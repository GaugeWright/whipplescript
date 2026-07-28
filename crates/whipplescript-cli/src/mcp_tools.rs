//! Host side of MCP client support for the built-in harness
//! (`spec/mcp-support-design-note.md`).
//!
//! The kernel's `whipplescript_kernel::mcp` owns the wire shapes and the
//! admission function; this module owns everything that touches the world:
//!
//! - the **server registry** — the operator's `mcp.json`, which holds the
//!   *evidence* a server has attained (its pin, its attestation, its role
//!   file). The matching *requirement* lives in the signed governance envelope,
//!   never here (design note §6);
//! - the two **transports** — streamable HTTP (portable; the DO can drive the
//!   same request shape through `NeedsHttp`) and stdio (native-only, because a
//!   wasm isolate cannot `fork`/`exec`);
//! - **turn resolution** — connecting granted servers, detecting drift,
//!   admitting tools, and turning survivors into `ToolSpec`s the model sees.
//!
//! Two properties this module is responsible for holding:
//!
//! **Environment hygiene.** A stdio server is a child process, and by default a
//! child inherits whip's entire environment — every API key in it. The official
//! MCP reference server ships a tool called `get-env`, annotated read-only and
//! non-destructive, that returns exactly that. So stdio children get a CLEANED
//! environment: `PATH` and `HOME` (which `npx`/`node` genuinely need) plus the
//! server's own declared variables, and nothing else. This is the same
//! discipline `exec_server.rs` applies to script capabilities.
//!
//! **Fail-closed setup.** A granted server that cannot be reached, that fails
//! its handshake, that advertises a refused sub-protocol, or whose pin has
//! drifted fails the TURN at setup. It never degrades into a quietly smaller
//! tool surface, because a model that silently loses a tool produces a
//! plausible wrong answer instead of an error.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Map, Value};

use whipplescript_kernel::harness_loop::ToolSpec;
use whipplescript_kernel::mcp::{
    admit_tools, initialize_request, initialized_notification, jsonrpc_result, manifest_drift,
    model_facing_description, namespaced_tool_name, parse_tool_call_result, parse_tools_list,
    refuse_unsupported_capabilities, tools_call_request, tools_list_next_cursor,
    tools_list_page_request, tools_list_request, McpAdmissionInput, McpRung, McpToolDescriptor,
};

/// How long one MCP request may take before the turn gives up on it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Cap on a single tool result before the harness's own capture/truncation.
const MAX_RESULT_BYTES: usize = 512 * 1024;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Where the MCP server registry lives: `$WHIPPLESCRIPT_MCP_CONFIG`, else
/// `$WHIPPLESCRIPT_CONFIG_DIR/mcp.json`, else `$XDG_CONFIG_HOME/whipplescript/
/// mcp.json`, else `~/.config/whipplescript/mcp.json`. Mirrors `auth.rs`.
pub fn mcp_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("WHIPPLESCRIPT_MCP_CONFIG") {
        if !path.trim().is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    if let Ok(dir) = std::env::var("WHIPPLESCRIPT_CONFIG_DIR") {
        if !dir.trim().is_empty() {
            return Some(PathBuf::from(dir).join("mcp.json"));
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return Some(PathBuf::from(xdg).join("whipplescript").join("mcp.json"));
        }
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("whipplescript")
            .join("mcp.json"),
    )
}

/// How whip reaches a server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum McpTransport {
    /// A child process speaking newline-delimited JSON-RPC on stdio. Native
    /// only: a wasm isolate has no `fork`/`exec`.
    Stdio {
        command: String,
        args: Vec<String>,
        /// Declared environment for the child. Values of the form `env:NAME`
        /// resolve from whip's environment at spawn; anything else is literal.
        env: BTreeMap<String, String>,
    },
    /// Streamable HTTP JSON-RPC. Portable across the native host and the DO.
    Http {
        url: String,
        /// Extra request headers, same `env:NAME` resolution as above. This is
        /// where a bearer token goes.
        headers: BTreeMap<String, String>,
    },
}

/// One registered server: how to reach it, plus the evidence it has accrued.
#[derive(Clone, Debug)]
pub struct McpServerConfig {
    pub name: String,
    pub transport: McpTransport,
    /// Frozen `name -> digest` manifest. Presence is what makes the server
    /// *pinned*.
    pub pin: Option<Map<String, Value>>,
    /// Someone attested that this server's self-reported annotations may be
    /// believed. Meaningless without a pin, and `attest` enforces that.
    pub trust_annotations: bool,
    /// Admin-authored `role -> [tool]` classification.
    pub roles: BTreeMap<String, Vec<String>>,
}

impl McpServerConfig {
    /// The server's rung is DERIVED from the evidence present, never stored as
    /// a free-standing claim — a stored rung could lie about the evidence
    /// backing it, and the whole ladder rests on the evidence being the rung.
    pub fn rung(&self) -> McpRung {
        if self.pin.is_none() {
            return McpRung::Unattested;
        }
        if !self.roles.is_empty() {
            return McpRung::Classified;
        }
        if self.trust_annotations {
            return McpRung::Attested;
        }
        McpRung::Pinned
    }

    /// The tools a role covers. At [`McpRung::Attested`] a role may also be
    /// satisfied by the server's own annotations; that resolution happens in
    /// [`classified_tools`] where the live manifest is in hand.
    pub fn role_tools(&self, role: &str) -> Option<&[String]> {
        self.roles.get(role).map(Vec::as_slice)
    }
}

/// Parse the registry document. Unknown keys are ignored; a malformed server
/// entry is an error rather than a skipped row, because a server that silently
/// vanishes from the registry looks to a program exactly like a server that was
/// never granted.
pub fn parse_registry(value: &Value) -> Result<BTreeMap<String, McpServerConfig>, String> {
    let mut servers = BTreeMap::new();
    let Some(entries) = value.get("servers").and_then(Value::as_object) else {
        return Ok(servers);
    };
    for (name, entry) in entries {
        servers.insert(name.clone(), parse_server(name, entry)?);
    }
    Ok(servers)
}

fn string_map(value: Option<&Value>) -> BTreeMap<String, String> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_server(name: &str, entry: &Value) -> Result<McpServerConfig, String> {
    let transport = match entry.get("url").and_then(Value::as_str) {
        Some(url) => McpTransport::Http {
            url: url.to_owned(),
            headers: string_map(entry.get("headers")),
        },
        None => {
            let command = entry
                .get("command")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("MCP server `{name}` has neither `url` nor `command`"))?;
            McpTransport::Stdio {
                command: command.to_owned(),
                args: entry
                    .get("args")
                    .and_then(Value::as_array)
                    .map(|args| {
                        args.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
                env: string_map(entry.get("env")),
            }
        }
    };
    let roles = entry
        .get("roles")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .map(|(role, tools)| {
                    let tools = tools
                        .as_array()
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned)
                                .collect()
                        })
                        .unwrap_or_default();
                    (role.clone(), tools)
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(McpServerConfig {
        name: name.to_owned(),
        transport,
        pin: entry.get("pin").and_then(Value::as_object).cloned(),
        trust_annotations: entry
            .get("trust_annotations")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        roles,
    })
}

/// Load the registry from disk. A missing file is an empty registry (nobody has
/// added a server yet), but an unreadable or malformed one is an error.
pub fn load_registry() -> Result<BTreeMap<String, McpServerConfig>, String> {
    let Some(path) = mcp_config_path() else {
        return Ok(BTreeMap::new());
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(format!("could not read {}: {error}", path.display())),
    };
    let value: Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not valid JSON: {error}", path.display()))?;
    parse_registry(&value)
}

/// Serialize one server back to its registry shape.
pub fn server_to_json(server: &McpServerConfig) -> Value {
    let mut entry = Map::new();
    match &server.transport {
        McpTransport::Stdio { command, args, env } => {
            entry.insert("command".into(), json!(command));
            if !args.is_empty() {
                entry.insert("args".into(), json!(args));
            }
            if !env.is_empty() {
                entry.insert("env".into(), json!(env));
            }
        }
        McpTransport::Http { url, headers } => {
            entry.insert("url".into(), json!(url));
            if !headers.is_empty() {
                entry.insert("headers".into(), json!(headers));
            }
        }
    }
    if let Some(pin) = &server.pin {
        entry.insert("pin".into(), Value::Object(pin.clone()));
    }
    if server.trust_annotations {
        entry.insert("trust_annotations".into(), json!(true));
    }
    if !server.roles.is_empty() {
        entry.insert("roles".into(), json!(server.roles));
    }
    Value::Object(entry)
}

/// Write the whole registry back, preserving unrelated top-level keys.
pub fn save_registry(servers: &BTreeMap<String, McpServerConfig>) -> Result<PathBuf, String> {
    let path = mcp_config_path().ok_or_else(|| "no MCP config path available".to_owned())?;
    let mut document = std::fs::read_to_string(&path)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let entries: Map<String, Value> = servers
        .iter()
        .map(|(name, server)| (name.clone(), server_to_json(server)))
        .collect();
    document.insert("servers".into(), Value::Object(entries));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("could not create config directory: {error}"))?;
    }
    let text = serde_json::to_string_pretty(&Value::Object(document))
        .map_err(|error| format!("could not serialize MCP config: {error}"))?;
    std::fs::write(&path, text)
        .map_err(|error| format!("could not write {}: {error}", path.display()))?;
    // The registry can carry literal tokens in `env`/`headers`, so it gets the
    // same owner-only treatment as the credential store.
    restrict_permissions(&path)?;
    Ok(path)
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|error| format!("could not restrict MCP config permissions: {error}"))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> Result<(), String> {
    Ok(())
}

/// Import servers from a Claude Code / Cursor style `mcpServers` block, so the
/// zero-setup path is "point whip at the config you already have".
pub fn servers_from_mcp_servers_block(value: &Value) -> Result<Vec<McpServerConfig>, String> {
    let entries = value
        .get("mcpServers")
        .and_then(Value::as_object)
        .ok_or_else(|| "no `mcpServers` object found in that file".to_owned())?;
    let mut servers = Vec::new();
    for (name, entry) in entries {
        servers.push(parse_server(name, entry)?);
    }
    Ok(servers)
}

/// Resolve an `env:NAME` indirection against whip's own environment. A literal
/// value passes through. A missing variable is an error, not an empty string —
/// a server silently launched without its credential fails in confusing ways
/// much later.
fn resolve_secret(raw: &str, context: &str) -> Result<String, String> {
    match raw.strip_prefix("env:") {
        Some(name) => std::env::var(name)
            .ok()
            // An exported-but-empty variable is not a credential. Treating it as
            // one launches the server unauthenticated and fails much later, in a
            // place that does not name the cause.
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                format!("{context} refers to environment variable `{name}`, which is not set")
            }),
        None => Ok(raw.to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

trait McpTransportConn: Send {
    /// Send one JSON-RPC request and wait for its response.
    fn request(&mut self, message: &Value) -> Result<Value, String>;
    /// Send one notification (no response expected).
    fn notify(&mut self, message: &Value) -> Result<(), String>;
}

struct StdioConn {
    child: Child,
    stdin: ChildStdin,
    /// Reads are served by a reader thread so a request can time out. A raw
    /// `read_line` on the child's stdout blocks forever if the server never
    /// answers, which would hang the whole turn with no way out — the HTTP path
    /// had a deadline and this one did not.
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl StdioConn {
    fn spawn(
        server: &str,
        command: &str,
        args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<Self, String> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // Environment hygiene (module docs): the child does NOT inherit whip's
        // environment. It gets PATH and HOME — which `npx`/`node` need to
        // resolve and cache — plus exactly the variables the server declared.
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        if let Ok(home) = std::env::var("HOME") {
            cmd.env("HOME", home);
        }
        for (key, raw) in env {
            let value = resolve_secret(raw, &format!("MCP server `{server}` env `{key}`"))?;
            cmd.env(key, value);
        }
        let mut child = cmd
            .spawn()
            .map_err(|error| format!("could not start MCP server `{server}`: {error}"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| format!("MCP server `{server}` has no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| format!("MCP server `{server}` has no stdout"))?;
        let (sender, lines) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            // A byte ceiling on ONE JSON-RPC line. `read_line` grows without
            // bound, so a server that never sends a newline could otherwise
            // exhaust memory before any result-size cap applies.
            const MAX_LINE_BYTES: u64 = 8 * 1024 * 1024;
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                let mut bounded = std::io::Read::take(&mut reader, MAX_LINE_BYTES);
                let outcome = bounded.read_line(&mut line).and_then(|read| {
                    if read as u64 == MAX_LINE_BYTES && !line.ends_with('\n') {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "MCP server sent a single line over 8 MiB",
                        ))
                    } else {
                        Ok(read)
                    }
                });
                match outcome {
                    // EOF: the server closed. Drop the sender so the receiver
                    // sees a disconnect rather than waiting out the deadline.
                    Ok(0) => return,
                    Ok(_) => {
                        if sender.send(Ok(line)).is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        return;
                    }
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            lines,
            reader: Some(reader),
        })
    }
}

impl Drop for StdioConn {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        // The reader thread ends on EOF once the child is gone.
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl McpTransportConn for StdioConn {
    fn request(&mut self, message: &Value) -> Result<Value, String> {
        self.notify(message)?;
        let want = message.get("id").cloned();
        let deadline = std::time::Instant::now() + REQUEST_TIMEOUT;
        // Skip server-initiated traffic (logging notifications, progress) until
        // the response to THIS id arrives — but never past the deadline.
        loop {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or_else(|| {
                    format!(
                        "MCP server did not answer within {}s",
                        REQUEST_TIMEOUT.as_secs()
                    )
                })?;
            let line = match self.lines.recv_timeout(remaining) {
                Ok(Ok(line)) => line,
                Ok(Err(error)) => return Err(format!("MCP stdio read failed: {error}")),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "MCP server did not answer within {}s",
                        REQUEST_TIMEOUT.as_secs()
                    ))
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err("MCP server closed its stdout before responding".to_owned())
                }
            };
            let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            if value.get("id").cloned() == want {
                return Ok(value);
            }
        }
    }

    fn notify(&mut self, message: &Value) -> Result<(), String> {
        writeln!(self.stdin, "{message}")
            .and_then(|()| self.stdin.flush())
            .map_err(|error| format!("MCP stdio write failed: {error}"))
    }
}

struct HttpConn {
    agent: ureq::Agent,
    url: String,
    headers: Vec<(String, String)>,
    /// `Mcp-Session-Id` handed out by the server at initialize, echoed back on
    /// every later request.
    session: Option<String>,
}

/// Refuse a plaintext endpoint. The configured headers carry the server's
/// bearer token, so `http://` would put a credential on the wire in clear —
/// and the design's whole claim about MCP is that whip governs the door it
/// controls. Loopback is exempt because a local server has no wire to sniff,
/// which is the same rule the model broker applies
/// (`crates/whipplescript-host-do/worker/src/model-broker.ts:96`).
pub fn refuse_plaintext_endpoint(server: &str, url: &str) -> Result<(), String> {
    let parsed = url::Url::parse(url)
        .map_err(|error| format!("MCP server `{server}` has an unparseable url: {error}"))?;
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback) {
        return Ok(());
    }
    Err(format!(
        "MCP server `{server}` uses `{}://`, which whip refuses: the request carries this \
         server's credentials, so the endpoint must be HTTPS (plain HTTP is allowed only for \
         loopback)",
        parsed.scheme()
    ))
}

impl HttpConn {
    fn new(server: &str, url: &str, headers: &BTreeMap<String, String>) -> Result<Self, String> {
        refuse_plaintext_endpoint(server, url)?;
        let mut resolved = Vec::new();
        for (key, raw) in headers {
            let value = resolve_secret(raw, &format!("MCP server `{server}` header `{key}`"))?;
            resolved.push((key.clone(), value));
        }
        Ok(Self {
            // No redirects. Headers carry the server's bearer token, and ureq
            // replays headers on redirect — a server (or a hijacked DNS answer)
            // could bounce the request to another host and collect the
            // credential. An MCP endpoint that redirects is a misconfiguration
            // the operator should see, not something to follow silently.
            agent: ureq::AgentBuilder::new()
                .timeout(REQUEST_TIMEOUT)
                .redirects(0)
                .build(),
            url: url.to_owned(),
            headers: resolved,
            session: None,
        })
    }

    fn post(&mut self, message: &Value) -> Result<Option<Value>, String> {
        let mut builder = self
            .agent
            .post(&self.url)
            .set("content-type", "application/json")
            // Streamable HTTP servers may answer either way; whip does not hold
            // an SSE stream open, but a single SSE-framed reply is unwrapped.
            .set("accept", "application/json, text/event-stream");
        for (key, value) in &self.headers {
            builder = builder.set(key, value);
        }
        if let Some(session) = &self.session {
            builder = builder.set("mcp-session-id", session);
        }
        let response = match builder.send_json(message.clone()) {
            Ok(response) => response,
            Err(ureq::Error::Status(status, response)) => {
                let body = response.into_string().unwrap_or_default();
                return Err(format!("MCP server returned HTTP {status}: {body}"));
            }
            Err(ureq::Error::Transport(transport)) => {
                return Err(format!("MCP transport error: {transport}"));
            }
        };
        if let Some(session) = response.header("mcp-session-id") {
            self.session = Some(session.to_owned());
        }
        let body = response
            .into_string()
            .map_err(|error| format!("MCP response was not readable: {error}"))?;
        if body.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(parse_http_body(&body)?))
    }
}

/// Accept both a plain JSON body and a single SSE-framed reply (`data:` lines),
/// which streamable-HTTP servers use even for one-shot responses.
fn parse_http_body(body: &str) -> Result<Value, String> {
    if let Ok(value) = serde_json::from_str::<Value>(body.trim()) {
        return Ok(value);
    }
    let mut payload = String::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("data:") {
            payload.push_str(rest.trim());
        }
    }
    serde_json::from_str::<Value>(&payload)
        .map_err(|error| format!("MCP response was not JSON or SSE-framed JSON: {error}"))
}

impl McpTransportConn for HttpConn {
    fn request(&mut self, message: &Value) -> Result<Value, String> {
        self.post(message)?
            .ok_or_else(|| "MCP server returned an empty body for a request".to_owned())
    }

    fn notify(&mut self, message: &Value) -> Result<(), String> {
        self.post(message).map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A connected MCP server, past its handshake.
pub struct McpClient {
    server: String,
    conn: Box<dyn McpTransportConn>,
    next_id: u64,
}

impl McpClient {
    /// Connect and complete the handshake, refusing sub-protocols whip will not
    /// host before any tool is listed.
    pub fn connect(config: &McpServerConfig) -> Result<Self, String> {
        let conn: Box<dyn McpTransportConn> = match &config.transport {
            McpTransport::Stdio { command, args, env } => {
                Box::new(StdioConn::spawn(&config.name, command, args, env)?)
            }
            McpTransport::Http { url, headers } => {
                Box::new(HttpConn::new(&config.name, url, headers)?)
            }
        };
        let mut client = Self {
            server: config.name.clone(),
            conn,
            next_id: 1,
        };
        let id = client.take_id();
        let response = client.conn.request(&initialize_request(id))?;
        let result = jsonrpc_result(&response).map_err(|error| client.context(&error))?;
        refuse_unsupported_capabilities(&result).map_err(|error| client.context(&error))?;
        client.conn.notify(&initialized_notification())?;
        Ok(client)
    }

    fn take_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn context(&self, message: &str) -> String {
        format!("MCP server `{}`: {message}", self.server)
    }

    /// The server's live tool manifest, following pagination to the end.
    ///
    /// `tools/list` is a paginated method: a server may answer with a partial
    /// list plus a `nextCursor`. Reading only the first page would look exactly
    /// like a server that does not offer the rest — a granted tool would fail
    /// setup for no visible reason, and a pin would cover only page one.
    pub fn list_tools(&mut self) -> Result<Vec<McpToolDescriptor>, String> {
        // A server that keeps handing back cursors must not spin the turn
        // forever; 64 pages is far past any real manifest.
        const MAX_PAGES: usize = 64;
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_PAGES {
            let id = self.take_id();
            let request = match &cursor {
                Some(cursor) => tools_list_page_request(id, cursor),
                None => tools_list_request(id),
            };
            let response = self.conn.request(&request)?;
            let result = jsonrpc_result(&response).map_err(|error| self.context(&error))?;
            tools.extend(parse_tools_list(&result).map_err(|error| self.context(&error))?);
            match tools_list_next_cursor(&result) {
                Some(next) => cursor = Some(next),
                None => return Ok(tools),
            }
        }
        Err(self.context("tools/list did not terminate within 64 pages"))
    }

    /// Call one tool. A server-signalled tool error comes back as `Err` so the
    /// harness surfaces it to the model as a tool error it can retry against —
    /// never as a silent success.
    pub fn call_tool(&mut self, tool: &str, arguments: &Value) -> Result<String, String> {
        let id = self.take_id();
        let response = self
            .conn
            .request(&tools_call_request(id, tool, arguments))?;
        let result = jsonrpc_result(&response).map_err(|error| self.context(&error))?;
        let (mut text, is_error) = parse_tool_call_result(&result);
        if text.len() > MAX_RESULT_BYTES {
            // `String::truncate` PANICS when the byte index is not a char
            // boundary, and this text is server-supplied — a multi-byte
            // character straddling byte 524288 would crash the turn. Walk back
            // to the nearest boundary instead.
            let mut cut = MAX_RESULT_BYTES;
            while cut > 0 && !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
            text.push_str("\n[truncated by whip]");
        }
        if is_error {
            return Err(text);
        }
        Ok(text)
    }
}

// ---------------------------------------------------------------------------
// Turn resolution
// ---------------------------------------------------------------------------

/// What one `with access to <server> { ... }` grant asked for, as written.
///
/// The operations stay RAW here because tool-vs-role cannot be decided without
/// the live manifest, and the rule is **tool-first**: an operation that names an
/// offered tool is that tool, and only a name the server does not offer is
/// looked up as a role. Tool-first is the narrower reading, and it matters —
/// the reference filesystem server offers a tool literally called `read`, so
/// `with access to files { read }` must mean that one tool, never "every tool
/// something classified as readable".
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct McpServerGrant {
    pub operations: Vec<String>,
}

impl McpServerGrant {
    /// Split the grant against a live manifest into (tool names, role names).
    fn split(&self, live: &[McpToolDescriptor]) -> (Vec<String>, Vec<String>) {
        let mut tools = Vec::new();
        let mut roles = Vec::new();
        for operation in &self.operations {
            if live.iter().any(|tool| &tool.name == operation) {
                tools.push(operation.clone());
            } else {
                roles.push(operation.clone());
            }
        }
        (tools, roles)
    }
}

/// The per-turn MCP authority: server name -> what the grant asked for.
pub type McpTurnAccess = BTreeMap<String, McpServerGrant>;

/// Which tools carry an admitted classification, given the rung. At
/// [`McpRung::Classified`] the admin's role file is the authority. At
/// [`McpRung::Attested`] the server's own annotations are admissible too,
/// because someone signed off on believing them.
fn classified_tools(config: &McpServerConfig, live: &[McpToolDescriptor]) -> Vec<String> {
    let mut classified: Vec<String> = config.roles.values().flatten().cloned().collect();
    if config.rung() == McpRung::Attested {
        for tool in live {
            if tool.annotations.is_some() {
                classified.push(tool.name.clone());
            }
        }
    }
    classified.sort();
    classified.dedup();
    classified
}

/// Resolve a role name to its tools. An admin role file wins; at rung 2 with no
/// role file, the conventional `read` role falls back to the tools the server
/// annotates read-only.
fn role_tools(
    config: &McpServerConfig,
    role: &str,
    live: &[McpToolDescriptor],
) -> Result<Vec<String>, String> {
    if let Some(tools) = config.role_tools(role) {
        return Ok(tools.to_vec());
    }
    if config.rung() == McpRung::Attested && role == "read" {
        return Ok(live
            .iter()
            .filter(|tool| tool.claims_read_only())
            .map(|tool| tool.name.clone())
            .collect());
    }
    Err(format!(
        "MCP server `{}` defines no role `{role}` (roles: {})",
        config.name,
        if config.roles.is_empty() {
            "none declared".to_owned()
        } else {
            config.roles.keys().cloned().collect::<Vec<_>>().join(", ")
        }
    ))
}

/// One live server for the duration of a turn: its client plus the tool names
/// admission approved.
pub struct McpServerRuntime {
    pub name: String,
    pub rung: McpRung,
    client: Mutex<McpClient>,
    admitted: Vec<String>,
}

impl McpServerRuntime {
    /// Execute a tool call, re-checking admission at execution time. The tool
    /// list the model saw and the tool list whip will run must be the same set:
    /// exposure is not authority, so a name that was never admitted is refused
    /// here even if it somehow reached the model.
    pub fn call(&self, tool: &str, arguments: &Value) -> Result<String, String> {
        if !self.admitted.iter().any(|name| name == tool) {
            return Err(format!(
                "tool `{tool}` is not granted for this turn on MCP server `{}`",
                self.name
            ));
        }
        let mut client = self
            .client
            .lock()
            .map_err(|_| format!("MCP server `{}` connection is poisoned", self.name))?;
        client.call_tool(tool, arguments)
    }
}

/// Everything a turn needs to run MCP tools, keyed by server name.
#[derive(Default)]
pub struct McpTurnRuntime {
    servers: Vec<McpServerRuntime>,
}

impl McpTurnRuntime {
    /// Dispatch a namespaced `mcp__<server>__<tool>` call.
    pub fn call(&self, server: &str, tool: &str, arguments: &Value) -> Result<String, String> {
        let runtime = self
            .servers
            .iter()
            .find(|candidate| candidate.name == server)
            .ok_or_else(|| format!("MCP server `{server}` is not available for this turn"))?;
        runtime.call(tool, arguments)
    }

    /// Every server this turn drew tools from, with the rung it ran at and the
    /// tools admission approved. This becomes a recorded context bundle, so the
    /// turn's durable provenance answers "which third parties could this turn
    /// reach, and how much had anyone vouched for them?" — the tagging half of
    /// progressive rigor, which is what makes rung 0 honest rather than silent.
    pub fn trust_summary(&self) -> Vec<(String, McpRung, Vec<String>)> {
        self.servers
            .iter()
            .map(|runtime| (runtime.name.clone(), runtime.rung, runtime.admitted.clone()))
            .collect()
    }
}

/// Connect every granted server, admit its tools, and build the model-facing
/// specs. Any failure fails the turn — see the module docs on fail-closed setup.
///
/// `min_rung` is the signed envelope's requirement (design note §6), passed in
/// by the caller so this function stays testable without an envelope on disk.
pub fn resolve_turn_mcp_tools(
    access: &McpTurnAccess,
    registry: &BTreeMap<String, McpServerConfig>,
    min_rung: Option<McpRung>,
) -> Result<(Vec<ToolSpec>, McpTurnRuntime), String> {
    let mut specs = Vec::new();
    let mut runtime = McpTurnRuntime::default();
    for (server_name, grant) in access {
        let config = registry.get(server_name).ok_or_else(|| {
            format!(
                "turn grants MCP server `{server_name}`, which is not registered \
                 (add it with `whip mcp add {server_name} ...`)"
            )
        })?;
        let rung = config.rung();
        // The envelope gate runs BEFORE any contact. Admission would catch this
        // anyway, but only after we had spawned the process or made the request
        // — a below-bar server should not be executed at all, and for stdio that
        // means not running its command.
        if let Some(required) = min_rung {
            if rung < required {
                return Err(whipplescript_kernel::mcp::McpDenial::EnvelopeRung {
                    required,
                    actual: rung,
                }
                .message(server_name));
            }
        }
        let mut client = McpClient::connect(config)?;
        let live = client.list_tools()?;
        let (granted_names, granted_role_names) = grant.split(&live);

        let drifted = match &config.pin {
            Some(pin) => manifest_drift(pin, &live),
            None => Vec::new(),
        };
        let mut granted_roles = Vec::new();
        if rung.classification_admitted() {
            // At rung 2/3 a role must actually resolve. An unresolvable name is
            // neither a tool the server offers nor a role anyone defined, so it
            // is a typo or a server that moved on — a setup error, said out loud,
            // rather than a silently smaller tool surface.
            for role in &granted_role_names {
                granted_roles.push((role.clone(), role_tools(config, role, &live)?));
            }
        } else if !granted_role_names.is_empty() {
            // Below rung 2 the names are carried through unresolved so the
            // admission function produces its own RoleUnavailable denial, which
            // is the message that tells the operator what to do about it.
            for role in &granted_role_names {
                granted_roles.push((role.clone(), Vec::new()));
            }
        }

        let input = McpAdmissionInput {
            offered: live.iter().map(|tool| tool.name.clone()).collect(),
            drifted,
            granted_names,
            granted_roles,
            classified: classified_tools(config, &live),
            profile_permitted: None,
        };
        let admitted =
            admit_tools(rung, min_rung, &input).map_err(|denial| denial.message(server_name))?;

        for tool in &live {
            if !admitted.iter().any(|name| name == &tool.name) {
                continue;
            }
            // Providers enforce `^[a-zA-Z0-9_-]{1,64}$` on tool names, and the
            // model-facing name goes verbatim into the request. A name that
            // cannot be represented is REFUSED, not mangled: a rewritten name
            // would no longer match the grant or the pin that admitted it.
            let Some(name) = namespaced_tool_name(server_name, &tool.name) else {
                return Err(format!(
                    "MCP server `{server_name}` offers granted tool `{}`, whose namespaced name \
                     is not representable to the model provider (names must match \
                     [A-Za-z0-9_-] and the composed `mcp__server__tool` must be at most 64 \
                     characters). Rename the server with a shorter id, or drop the tool from \
                     the grant.",
                    tool.name
                ));
            };
            specs.push(ToolSpec {
                name,
                description: model_facing_description(server_name, rung, &tool.description),
                input_schema: tool.input_schema.clone(),
            });
        }
        runtime.servers.push(McpServerRuntime {
            name: server_name.clone(),
            rung,
            client: Mutex::new(client),
            admitted,
        });
    }
    Ok((specs, runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(name: &str, read_only: bool) -> McpToolDescriptor {
        McpToolDescriptor {
            name: name.to_owned(),
            description: format!("does {name}"),
            input_schema: json!({ "type": "object" }),
            annotations: Some(json!({ "readOnlyHint": read_only })),
        }
    }

    fn config(pin: bool, trust: bool, roles: &[(&str, &[&str])]) -> McpServerConfig {
        McpServerConfig {
            name: "github".into(),
            transport: McpTransport::Http {
                url: "https://example.invalid/mcp".into(),
                headers: BTreeMap::new(),
            },
            pin: pin.then(Map::new),
            trust_annotations: trust,
            roles: roles
                .iter()
                .map(|(role, tools)| {
                    (
                        (*role).to_owned(),
                        tools.iter().map(|t| (*t).to_owned()).collect(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn rung_is_derived_from_evidence_not_asserted() {
        assert_eq!(config(false, false, &[]).rung(), McpRung::Unattested);
        assert_eq!(config(true, false, &[]).rung(), McpRung::Pinned);
        assert_eq!(config(true, true, &[]).rung(), McpRung::Attested);
        assert_eq!(
            config(true, true, &[("read", &["get_issue"])]).rung(),
            McpRung::Classified
        );
        // Attestation without a pin cannot climb: there is no frozen manifest
        // for the attestation to be about.
        assert_eq!(config(false, true, &[]).rung(), McpRung::Unattested);
    }

    #[test]
    fn parses_a_claude_code_style_mcp_servers_block() {
        let block = json!({
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-github"],
                    "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "env:GH_PAT" }
                },
                "linear": { "url": "https://mcp.linear.app/sse" }
            }
        });
        let mut servers = servers_from_mcp_servers_block(&block).expect("parsed");
        servers.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "github");
        match &servers[0].transport {
            McpTransport::Stdio { command, args, env } => {
                assert_eq!(command, "npx");
                assert_eq!(args.len(), 2);
                assert_eq!(
                    env.get("GITHUB_PERSONAL_ACCESS_TOKEN").map(String::as_str),
                    Some("env:GH_PAT")
                );
            }
            other => panic!("expected stdio, got {other:?}"),
        }
        assert!(matches!(servers[1].transport, McpTransport::Http { .. }));
        // Every imported server starts unattested — importing is not trusting.
        assert!(servers.iter().all(|s| s.rung() == McpRung::Unattested));
    }

    #[test]
    fn a_server_with_neither_url_nor_command_is_an_error() {
        let block = json!({ "mcpServers": { "broken": { "note": "nothing here" } } });
        assert!(servers_from_mcp_servers_block(&block).is_err());
    }

    #[test]
    fn registry_round_trips_through_json() {
        let server = config(true, true, &[("read", &["get_issue"])]);
        let document = json!({ "servers": { "github": server_to_json(&server) } });
        let parsed = parse_registry(&document).expect("parsed");
        let round_tripped = parsed.get("github").expect("present");
        assert_eq!(round_tripped.rung(), McpRung::Classified);
        assert_eq!(
            round_tripped.role_tools("read"),
            Some(["get_issue".to_owned()].as_slice())
        );
    }

    #[test]
    fn env_indirection_resolves_and_a_missing_variable_is_loud() {
        std::env::set_var("WHIP_TEST_MCP_TOKEN", "s3cret");
        assert_eq!(
            resolve_secret("env:WHIP_TEST_MCP_TOKEN", "ctx").expect("resolved"),
            "s3cret"
        );
        assert_eq!(
            resolve_secret("literal", "ctx").expect("literal"),
            "literal"
        );
        let error = resolve_secret("env:WHIP_TEST_MCP_ABSENT", "server `x` header `A`")
            .expect_err("missing variable is an error");
        assert!(error.contains("WHIP_TEST_MCP_ABSENT"), "{error}");
        std::env::remove_var("WHIP_TEST_MCP_TOKEN");
    }

    #[test]
    fn attested_annotations_classify_but_unannotated_tools_stay_out() {
        let attested = config(true, true, &[]);
        let live = vec![
            descriptor("get_issue", true),
            McpToolDescriptor {
                annotations: None,
                ..descriptor("merge_pull_request", false)
            },
        ];
        let classified = classified_tools(&attested, &live);
        assert_eq!(classified, vec!["get_issue".to_owned()]);

        // The conventional `read` role at rung 2 is the annotated read-only set.
        assert_eq!(
            role_tools(&attested, "read", &live).expect("resolved"),
            vec!["get_issue".to_owned()]
        );
        // Any other role name still needs an admin role file.
        assert!(role_tools(&attested, "write", &live).is_err());
    }

    #[test]
    fn a_pinned_but_unattested_server_classifies_nothing() {
        // Rung 1 has a frozen manifest but nobody has vouched for the
        // annotations, so `readOnlyHint` buys the server nothing.
        let pinned = config(true, false, &[]);
        let live = vec![descriptor("get_issue", true)];
        assert!(classified_tools(&pinned, &live).is_empty());
        assert!(role_tools(&pinned, "read", &live).is_err());
    }

    #[test]
    fn admin_roles_beat_annotations() {
        // The `get-env` shape: the server annotates it read-only, but the admin's
        // role file is the authority at rung 3 and does not list it.
        let classified_server = config(true, true, &[("read", &["get_issue"])]);
        let live = vec![descriptor("get_issue", true), descriptor("get_env", true)];
        assert_eq!(
            role_tools(&classified_server, "read", &live).expect("resolved"),
            vec!["get_issue".to_owned()]
        );
        assert_eq!(
            classified_tools(&classified_server, &live),
            vec!["get_issue".to_owned()]
        );
    }

    #[test]
    fn runtime_refuses_a_tool_admission_never_approved() {
        // Exposure is not authority: even if a name reached the model, the
        // executor re-checks it.
        let runtime = McpTurnRuntime::default();
        let error = runtime
            .call("github", "merge_pull_request", &json!({}))
            .expect_err("no such server this turn");
        assert!(error.contains("not available for this turn"), "{error}");
    }

    #[test]
    fn a_grant_reads_tool_first_then_role() {
        // The filesystem-server hazard: the server offers a tool named `read`,
        // and a role named `read` may also exist. The tool wins, because it is
        // the narrower reading of what the author wrote.
        let live = vec![descriptor("read", true), descriptor("write", false)];
        let grant = McpServerGrant {
            operations: vec!["read".into(), "reader".into()],
        };
        let (tools, roles) = grant.split(&live);
        assert_eq!(tools, vec!["read".to_owned()]);
        assert_eq!(roles, vec!["reader".to_owned()]);
    }

    /// A self-contained stdio MCP server: enough of the protocol to handshake,
    /// list two tools, and answer a call. Written to a temp file so the test
    /// exercises the REAL transport — spawn, newline-delimited JSON-RPC, the
    /// handshake, and the cleaned environment — rather than a stubbed client.
    fn fake_server_script(dir: &std::path::Path, annotate: bool) -> PathBuf {
        let annotations = if annotate {
            r#", "annotations": {"readOnlyHint": True}"#
        } else {
            ""
        };
        let script = format!(
            r#"
import json, sys, os

def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method = msg.get("method")
    if method == "initialize":
        send({{"jsonrpc": "2.0", "id": msg["id"], "result": {{
            "protocolVersion": "2025-06-18",
            "capabilities": {{"tools": {{}}}},
            "serverInfo": {{"name": "fake", "version": "1.0"}}}}}})
    elif method == "tools/list":
        send({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"tools": [
            {{"name": "get_issue", "description": "Get an issue",
              "inputSchema": {{"type": "object"}}{annotations}}},
            {{"name": "merge_pr", "description": "Merge a pull request",
              "inputSchema": {{"type": "object"}}}}
        ]}}}})
    elif method == "tools/call":
        name = msg["params"]["name"]
        # Echo back what the child can see of the environment, so the test can
        # prove whip did not hand it every secret in its own process.
        leaked = [k for k in os.environ if k.startswith("WHIP_TEST_SECRET")]
        send({{"jsonrpc": "2.0", "id": msg["id"], "result": {{"content": [
            {{"type": "text", "text": json.dumps({{
                "called": name,
                "declared": os.environ.get("DECLARED_TOKEN"),
                "leaked": leaked}})}}]}}}})
"#
        );
        let path = dir.join("fake_mcp_server.py");
        std::fs::write(&path, script).expect("write fake server");
        path
    }

    fn have_python() -> bool {
        Command::new("python3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// Each real-transport test gets its OWN environment variable. They share a
    /// process, so a single `WHIP_TEST_DECLARED` let one test's cleanup remove
    /// the variable another test was still relying on — a genuine race under a
    /// parallel runner.
    fn declared_var(name: &str) -> String {
        format!("WHIP_TEST_DECLARED_{}", name.to_uppercase())
    }

    fn stdio_config(name: &str, script: &std::path::Path) -> McpServerConfig {
        let mut env = BTreeMap::new();
        env.insert(
            "DECLARED_TOKEN".to_owned(),
            format!("env:{}", declared_var(name)),
        );
        McpServerConfig {
            name: name.to_owned(),
            transport: McpTransport::Stdio {
                command: "python3".into(),
                args: vec![script.display().to_string()],
                env,
            },
            pin: None,
            trust_annotations: false,
            roles: BTreeMap::new(),
        }
    }

    /// End-to-end over a real child process: handshake, `tools/list`, admission,
    /// and a `tools/call` — plus the two properties this module owns.
    #[test]
    fn stdio_server_round_trips_and_gets_a_cleaned_environment() {
        if !have_python() {
            eprintln!("skipping: python3 not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("whip-mcp-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let script = fake_server_script(&dir, false);

        // A secret in whip's own environment that the server never declared.
        std::env::set_var("WHIP_TEST_SECRET_KEY", "sk-must-not-leak");
        std::env::set_var(declared_var("fake"), "declared-value");

        let mut registry = BTreeMap::new();
        registry.insert("fake".to_owned(), stdio_config("fake", &script));
        let mut access = McpTurnAccess::new();
        access.insert(
            "fake".to_owned(),
            McpServerGrant {
                operations: vec!["get_issue".to_owned()],
            },
        );

        let (specs, runtime) = resolve_turn_mcp_tools(&access, &registry, None).expect("resolved");

        // Only the granted tool is exposed, and it is namespaced.
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "mcp__fake__get_issue");
        // The description is fenced and marked untrusted at rung 0.
        assert!(
            specs[0].description.contains("UNATTESTED"),
            "{}",
            specs[0].description
        );

        // The ungranted tool is not callable even though the server offers it.
        let refused = runtime
            .call("fake", "merge_pr", &json!({}))
            .expect_err("ungranted");
        assert!(refused.contains("not granted"), "{refused}");

        // The granted one works, and the child saw its declared variable...
        let result = runtime
            .call("fake", "get_issue", &json!({ "id": 1 }))
            .expect("called");
        let parsed: Value = serde_json::from_str(&result).expect("json result");
        assert_eq!(parsed["called"], json!("get_issue"));
        assert_eq!(parsed["declared"], json!("declared-value"));
        // ... and NOT whip's own secret. This is the `get-env` defense.
        assert_eq!(
            parsed["leaked"],
            json!([]),
            "child inherited whip's environment"
        );

        std::env::remove_var("WHIP_TEST_SECRET_KEY");
        std::env::remove_var(declared_var("fake"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pinned server whose manifest has changed fails the TURN, and the
    /// failure names the drifted tool.
    #[test]
    fn drift_against_a_real_server_fails_turn_setup() {
        if !have_python() {
            eprintln!("skipping: python3 not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("whip-mcp-drift-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let script = fake_server_script(&dir, false);
        std::env::set_var(declared_var("drift"), "declared-value");

        let mut config = stdio_config("drift", &script);
        // Pin a manifest that does not match what the server will serve.
        let mut pin = Map::new();
        pin.insert("get_issue".to_owned(), Value::String("stale-digest".into()));
        config.pin = Some(pin);
        assert_eq!(config.rung(), McpRung::Pinned);

        let mut registry = BTreeMap::new();
        registry.insert("drift".to_owned(), config);
        let mut access = McpTurnAccess::new();
        access.insert(
            "drift".to_owned(),
            McpServerGrant {
                operations: vec!["get_issue".to_owned()],
            },
        );

        let error = match resolve_turn_mcp_tools(&access, &registry, None) {
            Err(error) => error,
            Ok(_) => panic!("a drifted pin must fail turn setup"),
        };
        assert!(
            error.contains("pinned manifest no longer matches"),
            "{error}"
        );
        assert!(error.contains("get_issue (changed)"), "{error}");
        assert!(error.contains("whip mcp sync"), "{error}");

        std::env::remove_var(declared_var("drift"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The envelope's minimum rung denies before any tool is considered, and the
    /// message tells the operator which lever to pull.
    #[test]
    fn envelope_minimum_rung_denies_a_live_server() {
        if !have_python() {
            eprintln!("skipping: python3 not available");
            return;
        }
        let dir = std::env::temp_dir().join(format!("whip-mcp-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let script = fake_server_script(&dir, false);
        std::env::set_var(declared_var("envbar"), "declared-value");

        let mut registry = BTreeMap::new();
        registry.insert("envbar".to_owned(), stdio_config("envbar", &script));
        let mut access = McpTurnAccess::new();
        access.insert(
            "envbar".to_owned(),
            McpServerGrant {
                operations: vec!["get_issue".to_owned()],
            },
        );

        let error = match resolve_turn_mcp_tools(&access, &registry, Some(McpRung::Attested)) {
            Err(error) => error,
            Ok(_) => panic!("a server below the envelope bar must be denied"),
        };
        assert!(error.contains("requires trust rung `attested`"), "{error}");

        std::env::remove_var(declared_var("envbar"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A loopback HTTP server that answers MCP JSON-RPC, for testing the
    /// transport the design calls primary. `sse` makes it answer `tools/call`
    /// with an SSE-framed body, exercising the other parse path.
    ///
    /// Detached on purpose: the accept loop parks after the client is done, so
    /// joining it would block. It is defensive by construction too — one bad
    /// request must not kill it, because a dead server does not fail a test
    /// quickly, it makes the client wait out its per-request timeout, which
    /// reads as a hang rather than a failure.
    fn spawn_http_mcp_server(sse: bool) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            for stream in listener.incoming().take(16) {
                let Ok(mut stream) = stream else { continue };
                let Ok(peer) = stream.try_clone() else {
                    continue;
                };
                let mut reader = BufReader::new(peer);
                let mut length = 0usize;
                let mut saw_blank = false;
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                    if line == "\r\n" || line == "\n" {
                        saw_blank = true;
                        break;
                    }
                }
                if !saw_blank {
                    continue;
                }
                let mut body = vec![0u8; length];
                if std::io::Read::read_exact(&mut reader, &mut body).is_err() {
                    continue;
                }
                let Ok(request) = serde_json::from_slice::<Value>(&body) else {
                    continue;
                };
                let method = request.get("method").and_then(Value::as_str).unwrap_or("");
                let result = match method {
                    "initialize" => json!({
                        "protocolVersion": "2025-06-18",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "http-fake", "version": "1.0" }
                    }),
                    "tools/list" => json!({ "tools": [
                        { "name": "get_issue", "description": "Get an issue",
                          "inputSchema": { "type": "object" } }
                    ] }),
                    "tools/call" => json!({ "content": [
                        { "type": "text", "text": "issue #1" }
                    ] }),
                    _ => Value::Null,
                };
                // A notification carries no id and expects no JSON-RPC reply.
                let (payload, content_type) = match request.get("id") {
                    None => (String::new(), "application/json"),
                    Some(id) => {
                        let envelope = json!({ "jsonrpc": "2.0", "id": id, "result": result });
                        if sse && method == "tools/call" {
                            (
                                format!("event: message\ndata: {envelope}\n\n"),
                                "text/event-stream",
                            )
                        } else {
                            (envelope.to_string(), "application/json")
                        }
                    }
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nMcp-Session-Id: s-1\r\n\
                     Connection: close\r\nContent-Length: {}\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
                let _ = stream.shutdown(std::net::Shutdown::Both);
            }
        });
        format!("http://127.0.0.1:{}/mcp", addr.port())
    }

    fn http_config(name: &str, url: &str) -> McpServerConfig {
        McpServerConfig {
            name: name.to_owned(),
            transport: McpTransport::Http {
                url: url.to_owned(),
                headers: BTreeMap::new(),
            },
            pin: None,
            trust_annotations: false,
            roles: BTreeMap::new(),
        }
    }

    /// The HTTP transport is the one that is portable across placements, and it
    /// had no test beyond body parsing. This drives a real socket end to end:
    /// handshake, tools/list, admission, and a tools/call.
    #[test]
    fn http_transport_round_trips_over_a_real_socket() {
        let url = spawn_http_mcp_server(false);
        let mut registry = BTreeMap::new();
        registry.insert("web".to_owned(), http_config("web", &url));
        let mut access = McpTurnAccess::new();
        access.insert(
            "web".to_owned(),
            McpServerGrant {
                operations: vec!["get_issue".to_owned()],
            },
        );

        let (specs, runtime) = resolve_turn_mcp_tools(&access, &registry, None).expect("resolved");
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "mcp__web__get_issue");

        let result = runtime
            .call("web", "get_issue", &json!({ "id": 1 }))
            .expect("called");
        assert_eq!(result, "issue #1");
    }

    /// The same path when the server answers SSE-framed, which streamable-HTTP
    /// servers do even for one-shot replies.
    #[test]
    fn http_transport_reads_an_sse_framed_reply() {
        let url = spawn_http_mcp_server(true);
        let mut registry = BTreeMap::new();
        registry.insert("web".to_owned(), http_config("web", &url));
        let mut access = McpTurnAccess::new();
        access.insert(
            "web".to_owned(),
            McpServerGrant {
                operations: vec!["get_issue".to_owned()],
            },
        );
        let (_, runtime) = resolve_turn_mcp_tools(&access, &registry, None).expect("resolved");
        assert_eq!(
            runtime
                .call("web", "get_issue", &json!({}))
                .expect("called"),
            "issue #1"
        );
    }

    /// Credentials ride in headers, so a plaintext endpoint is refused — except
    /// loopback, which is what the tests above rely on.
    #[test]
    fn plaintext_endpoints_are_refused_unless_they_are_loopback() {
        assert!(refuse_plaintext_endpoint("s", "https://mcp.example.com/x").is_ok());
        assert!(refuse_plaintext_endpoint("s", "http://127.0.0.1:8080/x").is_ok());
        assert!(refuse_plaintext_endpoint("s", "http://localhost:8080/x").is_ok());
        let error = refuse_plaintext_endpoint("s", "http://mcp.example.com/x")
            .expect_err("plaintext to a remote host must be refused");
        assert!(error.contains("HTTPS"), "{error}");
        assert!(refuse_plaintext_endpoint("s", "not a url").is_err());
    }

    #[test]
    fn http_bodies_parse_as_plain_json_or_sse_frames() {
        let plain = parse_http_body(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).expect("json");
        assert_eq!(plain.get("id").and_then(Value::as_u64), Some(1));
        let sse = parse_http_body("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2}\n\n")
            .expect("sse");
        assert_eq!(sse.get("id").and_then(Value::as_u64), Some(2));
        assert!(parse_http_body("not json at all").is_err());
    }
}
