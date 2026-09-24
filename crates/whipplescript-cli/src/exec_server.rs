//! Class-A executor sidecar (compute plane P8): a stateless HTTP server that
//! runs sha-pinned scripts on behalf of a workflow host that cannot spawn
//! processes (the DO isolate raises `NeedsHttp`; its shell fetches here).
//!
//! v1 protocol (`whip-executor/1`, one request-response per exec — §4 of
//! spec/compute-plane-design-note.md): the request carries the script bytes
//! inline (verified against the pinned sha256 before running — same TOCTOU
//! discipline as native script capabilities), the argv with a script-slot
//! index, resolved env values, and the JSON stdin. Manifest-ref + pull-
//! missing-blobs materialization joins when the object tier lands.
//!
//! Hermeticity is enforced harder than native exec: the child gets a CLEANED
//! environment (only the declared env plus PATH) — the sidecar is stronger
//! than native, per the design note's IFC-span section. Network egress denial
//! is a container property, not enforced here.
//!
//! Server style matches the repo's execution model: hand-rolled HTTP/1.1 over
//! `TcpListener`, thread per connection, threads not async.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

pub use whipplescript_kernel::exec_http::EXECUTOR_PROTOCOL;
use whipplescript_kernel::exec_http::{base64_decode, sha256_hex};

/// Per-stream response cap. Bounded so a runaway script cannot balloon the
/// response; the flag tells the caller truncation happened.
const STREAM_CAP_BYTES: usize = 512 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Cap on concurrently-handled connections. Each connection parses its
/// request line + headers BEFORE authentication, so without a bound an
/// unauthenticated peer could open connections faster than they complete
/// and pin unbounded OS threads / FDs / memory (slowloris-class
/// thread-exhaustion DoS). Accept blocks when the cap is reached.
const MAX_CONNECTIONS: usize = 256;

/// Wall-clock budget for the pre-auth read of the request line + headers.
/// A peer that opens a connection and never completes the header block —
/// or dribbles it a byte at a time — is dropped rather than holding a
/// thread forever. The turn WebSocket clears this before streaming.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Cap on total header bytes accepted before the blank-line terminator,
/// so an endless header stream cannot grow the buffer without bound.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Default and ceiling for the per-exec timeout.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 300_000;

/// Bounded exec slots per executor process (the pool's per-instance
/// concurrency; pool size × this = workspace Class-A parallelism).
const EXEC_SLOTS: usize = 4;

/// Priority classes, best first: production > working > counterfactual —
/// the compute-plane scheduling discipline (design note §6): mass
/// regeneration must not starve live traffic of executor slots.
const PRIORITY_CLASSES: usize = 3;

fn priority_class(name: &str) -> usize {
    match name {
        "working" => 1,
        "counterfactual" => 2,
        // Unlabeled requests are live traffic.
        _ => 0,
    }
}

/// The admission gate implementing the verified priority discipline
/// (models/maude/compute-priority-queue.maude): a freed slot is granted to a
/// waiter only when no strictly higher-priority waiter exists — the [serve]
/// rule's guard, transcribed.
struct AdmissionGate {
    state: std::sync::Mutex<GateState>,
    freed: std::sync::Condvar,
}

struct GateState {
    free_slots: usize,
    waiting: [usize; PRIORITY_CLASSES],
}

impl AdmissionGate {
    fn new(slots: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(GateState {
                free_slots: slots,
                waiting: [0; PRIORITY_CLASSES],
            }),
            freed: std::sync::Condvar::new(),
        }
    }

    /// Block until a slot is granted at `priority` (0 best). Mirrors the
    /// model's guard: grant only when no higher-priority request waits.
    fn acquire(&self, priority: usize) {
        let mut state = self.state.lock().expect("admission gate lock");
        state.waiting[priority] += 1;
        loop {
            let higher_waiting = state.waiting[..priority].iter().any(|&count| count > 0);
            if state.free_slots > 0 && !higher_waiting {
                state.free_slots -= 1;
                state.waiting[priority] -= 1;
                return;
            }
            state = self.freed.wait(state).expect("admission gate wait");
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("admission gate lock");
        state.free_slots += 1;
        drop(state);
        self.freed.notify_all();
    }

    #[cfg(test)]
    fn waiting_total(&self) -> usize {
        let state = self.state.lock().expect("admission gate lock");
        state.waiting.iter().sum()
    }
}

/// The process-wide gate for `/exec` (Class-A) requests.
fn exec_gate() -> &'static AdmissionGate {
    static GATE: std::sync::OnceLock<AdmissionGate> = std::sync::OnceLock::new();
    GATE.get_or_init(|| AdmissionGate::new(EXEC_SLOTS))
}

/// A minimal counting semaphore bounding the number of connection-handler
/// threads alive at once (the pre-auth DoS backstop; see [MAX_CONNECTIONS]).
/// A permit is held for the whole connection and released on drop.
struct ConnLimiter {
    available: std::sync::Mutex<usize>,
    freed: std::sync::Condvar,
}

impl ConnLimiter {
    fn new(permits: usize) -> Self {
        Self {
            available: std::sync::Mutex::new(permits),
            freed: std::sync::Condvar::new(),
        }
    }

    /// Block until a permit is free, then take one. The returned guard
    /// returns the permit when dropped.
    fn acquire(self: &std::sync::Arc<Self>) -> ConnPermit {
        let mut available = self.available.lock().expect("conn limiter lock");
        while *available == 0 {
            available = self.freed.wait(available).expect("conn limiter wait");
        }
        *available -= 1;
        ConnPermit {
            limiter: std::sync::Arc::clone(self),
        }
    }
}

struct ConnPermit {
    limiter: std::sync::Arc<ConnLimiter>,
}

impl Drop for ConnPermit {
    fn drop(&mut self) {
        let mut available = self.limiter.available.lock().expect("conn limiter lock");
        *available += 1;
        drop(available);
        self.limiter.freed.notify_one();
    }
}

/// Native managed receivers have one pinned dispatch and one delivery slot.
/// The external controller owns durability; this gate prevents a script from
/// reentering the local sidecar after its own invocation has started.
struct ManagedDispatch {
    digest: String,
    consumed: std::sync::atomic::AtomicBool,
}
impl ManagedDispatch {
    fn new(digest: String) -> std::io::Result<Self> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(std::io::Error::other(
                "managed executor dispatch digest is invalid",
            ));
        }
        Ok(Self {
            digest,
            consumed: std::sync::atomic::AtomicBool::new(false),
        })
    }
    fn admit(&self, dispatch: &Value) -> Result<(), String> {
        if sha256_hex(dispatch.to_string().as_bytes()) != self.digest {
            return Err("managed executor dispatch differs from its pinned invocation".into());
        }
        self.consumed
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .map_err(|_| "managed executor delivery was already consumed".to_owned())?;
        Ok(())
    }
}

/// Serve forever on `bind` (e.g. `127.0.0.1:8080`).
pub fn serve(bind: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    serve_on(listener)
}

/// Serve forever on an already-bound listener (tests bind `:0` first).
pub fn serve_on(listener: TcpListener) -> std::io::Result<()> {
    let runtime = std::env::var("WHIP_NORM_RUNTIME")
        .map(Some)
        .or_else(|error| match error {
            std::env::VarError::NotPresent => Ok(None),
            // A runtime profile that is SET but unreadable is not an absent
            // one. Serving without it would run unverified against a
            // configuration the operator did mean to supply.
            // Spelled with the error type, because with both arms yielding
            // `Ok` there is nothing left for `or_else` to infer it from.
            // MUTATION-SUCCESS-EXPR: Ok::<_, std::io::Error>(None)
            _ => Err(std::io::Error::other(error)),
        })?
        .map(|configuration| {
            let runtime = whipplescript_kernel::norm_runtime::parse(&configuration)
                .map_err(std::io::Error::other)?;
            crate::norm_observer::verify_runtime_profile(&runtime)
                .map_err(std::io::Error::other)?;
            Ok::<_, std::io::Error>(runtime)
        })
        .transpose()?;
    let managed = match std::env::var("WHIP_EXECUTOR_DISPATCH_SHA256") {
        Ok(digest) => Some(ManagedDispatch::new(digest)?),
        Err(std::env::VarError::NotPresent) => None,
        // Same, and it matters more here: falling through to `None` would mean
        // an executor whose pinned dispatch digest was SUPPLIED but unreadable
        // serves UNMANAGED -- every bypass the gate exists to refuse, admitted.
        // MUTATION-SUCCESS-EXPR: None
        Err(error) => return Err(std::io::Error::other(error)),
    };
    serve_on_with_runtime(listener, managed, runtime)
}

#[cfg(test)]
fn serve_on_with_profile(
    listener: TcpListener,
    managed: Option<ManagedDispatch>,
) -> std::io::Result<()> {
    serve_on_with_runtime(listener, managed, None)
}

fn serve_on_with_runtime(
    listener: TcpListener,
    managed: Option<ManagedDispatch>,
    runtime: Option<whipplescript_kernel::norm_runner::PythonRuntime>,
) -> std::io::Result<()> {
    let runtime = std::sync::Arc::new(runtime);
    let managed = std::sync::Arc::new(managed);
    use ring::rand::SecureRandom as _;
    let mut entropy = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut entropy)
        .map_err(|_| std::io::Error::other("executor incarnation entropy unavailable"))?;
    let incarnation = std::sync::Arc::new(sha256_hex(&entropy));
    eprintln!(
        "whip executor listening on {} ({EXECUTOR_PROTOCOL})",
        listener.local_addr()?
    );
    let limiter = std::sync::Arc::new(ConnLimiter::new(MAX_CONNECTIONS));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // Acquire BEFORE spawning: at the cap the accept loop blocks
                // (new peers queue in the OS backlog) instead of spawning an
                // unbounded number of handler threads.
                let permit = limiter.acquire();
                let incarnation = std::sync::Arc::clone(&incarnation);
                let managed = std::sync::Arc::clone(&managed);
                let runtime = std::sync::Arc::clone(&runtime);
                std::thread::spawn(move || {
                    let _permit = permit; // released when the handler returns
                    let _ = handle_connection(
                        stream,
                        &incarnation,
                        managed.as_ref().as_ref(),
                        runtime.as_ref().as_ref(),
                    );
                });
            }
            Err(error) => eprintln!("executor: accept failed: {error}"),
        }
    }
    Ok(())
}

/// Read one line of the PRE-AUTH header phase under the phase's wall-clock
/// budget.
///
/// `set_read_timeout` bounds each `recv`, not the phase, so a peer dribbling
/// one byte per timeout would hold the thread forever with the option set:
/// shrink the socket timeout toward the phase deadline before every read, and
/// refuse to read at all once the budget is spent.
fn read_header_line(
    stream: &TcpStream,
    deadline: Instant,
    reader: &mut impl BufRead,
    line: &mut String,
) -> std::io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "pre-auth header read exceeded its budget",
        ));
    }
    stream.set_read_timeout(Some(remaining))?;
    reader.read_line(line)?;
    Ok(())
}

fn handle_connection(
    stream: TcpStream,
    incarnation: &str,
    managed: Option<&ManagedDispatch>,
    runtime: Option<&whipplescript_kernel::norm_runner::PythonRuntime>,
) -> std::io::Result<()> {
    let local_addr = stream.local_addr().ok();
    // Bound the PRE-AUTH header read: a peer that opens a connection and
    // never finishes (or dribbles) the header block is dropped when the
    // budget is spent instead of pinning this thread forever. The socket
    // option is shared with the try_clone below.
    let header_deadline = Instant::now() + HEADER_READ_TIMEOUT;
    stream.set_read_timeout(Some(HEADER_READ_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    // `read_line` grows its buffer until a newline arrives, so the byte cap
    // has to bound the READ rather than be checked once the line has landed —
    // otherwise a peer sending a header line it never terminates is buffered
    // in full before it authenticates. One `take` spans the whole header
    // phase, the request line included.
    let mut headers = (&mut reader).take(MAX_HEADER_BYTES as u64 + 1);
    let mut request_line = String::new();
    read_header_line(&stream, header_deadline, &mut headers, &mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let path = parts.next().unwrap_or_default().to_owned();

    let mut content_length = 0usize;
    let mut websocket_key = None;
    let mut wants_upgrade = false;
    let mut authorization = None;
    let mut executor_token_header = None;
    loop {
        let mut line = String::new();
        read_header_line(&stream, header_deadline, &mut headers, &mut line)?;
        if headers.limit() == 0 {
            return write_json_response(stream, 431, json!({"error": "request headers too large"}));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            } else if name.eq_ignore_ascii_case("sec-websocket-key") {
                websocket_key = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("upgrade")
                && value.trim().eq_ignore_ascii_case("websocket")
            {
                wants_upgrade = true;
            } else if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().to_owned());
            } else if name.eq_ignore_ascii_case("x-whip-executor-token") {
                executor_token_header = Some(value.trim().to_owned());
            }
        }
    }

    // The pre-auth phase is over: the byte cap ends with the last read
    // through `headers`, and the body read gets back the plain per-read
    // budget that the header deadline had been shrinking.
    stream.set_read_timeout(Some(HEADER_READ_TIMEOUT))?;

    // A build action's blobs travel in bodies the script routes never need;
    // only those routes get the larger cap.
    let body_cap = if is_action_route(&path) {
        whipplescript_remote_execution::sidecar::MAX_ACTION_BODY_BYTES
    } else {
        MAX_REQUEST_BODY_BYTES
    };
    if content_length > body_cap {
        return write_json_response(stream, 413, json!({"error": "request body too large"}));
    }

    if managed.is_some()
        && !matches!(
            (method.as_str(), path.as_str()),
            ("GET", "/healthz")
                | ("GET", "/exec/incarnation")
                | ("GET", "/exec/norm-runtime")
                | ("POST", "/exec/bound")
        )
    {
        // Drain the declared body FIRST. `write_json_response` closes the
        // socket, and closing one whose receive queue still holds unread bytes
        // makes the kernel send RST rather than FIN -- which discards the
        // response the peer has not read yet. The caller then sees a connection
        // reset where a 409 was sent, and cannot tell a refusal from a crashed
        // executor. It is a race, so it shows up as a flaky test on a loaded
        // machine rather than as a bug: `managed_executor_http_refuses_bypass_
        // and_concurrent_replay` lost it on the hosted runner, which is what
        // the mutation sweep's self test refused to run against.
        //
        // Best-effort, and the two refusals above deliberately do NOT do this:
        // theirs is a header block or a body just declared too large to read,
        // and abandoning it unread is the refusal. Here the body is within the
        // cap and merely unwanted.
        let _ = std::io::copy(
            &mut (&mut reader).take(content_length as u64),
            &mut std::io::sink(),
        );
        return write_json_response(
            stream,
            409,
            json!({"error":"managed executor requires its pinned bound delivery"}),
        );
    }

    // Class-B turn channel (whip-turn/1): hand the raw socket to the
    // WebSocket handler. Safe because an upgrade request has no body and the
    // client sends no frames until it sees the 101 — the buffered reader has
    // consumed exactly through the header terminator.
    if method == "GET" && path == "/turn" && wants_upgrade {
        if let Err((status, message)) = check_executor_auth(
            local_addr.map(|addr| addr.ip()),
            &authorization,
            &executor_token_header,
        ) {
            return write_json_response(stream, status, json!({"error": message}));
        }
        if let Some(key) = websocket_key {
            drop(reader);
            // The turn channel is long-lived and client-paced; clear the
            // header-phase read timeout so streaming frames don't expire
            // mid-turn.
            stream.set_read_timeout(None)?;
            return crate::turn_server::handle_turn_websocket(stream, &key);
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let (status, response_body) = match (method.as_str(), path.as_str()) {
        ("GET", "/healthz") => (200, json!({"protocol": EXECUTOR_PROTOCOL, "ok": true})),
        ("GET", "/exec/incarnation") | ("GET", "/exec/norm-runtime") | ("POST", "/exec/bound") => {
            match check_executor_auth(
                local_addr.map(|addr| addr.ip()),
                &authorization,
                &executor_token_header,
            ) {
                Err((status, message)) => (status, json!({"error": message})),
                Ok(()) => {
                    use whipplescript_kernel::exec_incarnation;
                    let encoded = if path == "/exec/norm-runtime" {
                        runtime
                            .ok_or_else(|| "executor has no verified norm runtime".to_owned())
                            .and_then(|runtime| {
                                whipplescript_kernel::norm_runtime::process_receipt(
                                    incarnation,
                                    runtime,
                                )
                            })
                    } else if method == "GET" {
                        exec_incarnation::handshake(incarnation)
                    } else {
                        std::str::from_utf8(&body)
                            .map_err(|e| e.to_string())
                            .and_then(|body| exec_incarnation::read_delivery(body, incarnation))
                            .and_then(|request| {
                                if let Some(managed) = managed {
                                    managed.admit(&request)?;
                                }
                                let (status, response) = match handle_exec_request(&request) {
                                    Ok(response) => (200, response),
                                    Err((status, message)) => (status, json!({"error":message})),
                                };
                                exec_incarnation::completion(incarnation, status, response)
                            })
                    };
                    match encoded {
                        Ok(body) => (
                            200,
                            serde_json::from_str(&body).map_err(std::io::Error::other)?,
                        ),
                        Err(message) => (409, json!({"error":message})),
                    }
                }
            }
        }
        ("POST", "/exec") => {
            match check_executor_auth(
                local_addr.map(|addr| addr.ip()),
                &authorization,
                &executor_token_header,
            ) {
                Ok(()) => match serde_json::from_slice::<Value>(&body) {
                    Ok(request) => match handle_exec_request(&request) {
                        Ok(response) => (200, response),
                        Err((status, message)) => (status, json!({"error": message})),
                    },
                    Err(error) => (400, json!({"error": format!("invalid JSON body: {error}")})),
                },
                Err((status, message)) => (status, json!({"error": message})),
            }
        }
        // Build actions an endpoint hands to this executor
        // (`whipplescript.build.action/v1`): the sidecar tier as the
        // endpoint's runner, confined exactly as the endpoint's own runner is.
        ("POST", route) if is_action_route(route) => {
            match check_executor_auth(
                local_addr.map(|addr| addr.ip()),
                &authorization,
                &executor_token_header,
            ) {
                Ok(()) => action_sidecar()
                    .handle(route, &body)
                    .unwrap_or_else(|| (404, json!({"error": "unknown action route"}))),
                Err((status, message)) => (status, json!({"error": message})),
            }
        }
        // Class-B blocking form: run (or re-attach to) a whole agent turn and
        // answer with its final outcome. The WS form on GET /turn streams.
        ("POST", "/turn") => {
            match check_executor_auth(
                local_addr.map(|addr| addr.ip()),
                &authorization,
                &executor_token_header,
            ) {
                Ok(()) => match serde_json::from_slice::<Value>(&body) {
                    Ok(request) => match crate::turn_server::handle_turn_http(&request) {
                        Ok(response) => (200, response),
                        Err((status, message)) => (status, json!({"error": message})),
                    },
                    Err(error) => (400, json!({"error": format!("invalid JSON body: {error}")})),
                },
                Err((status, message)) => (status, json!({"error": message})),
            }
        }
        _ => (
            404,
            json!({"error": "unknown route; POST /exec, POST /action or GET /healthz"}),
        ),
    };

    write_json_response(stream, status, response_body)
}

fn is_action_route(path: &str) -> bool {
    path == "/action" || path.starts_with("/action/")
}

/// The executor's build-action half: one blob cache and scratch root per
/// process, under `WHIP_EXECUTOR_ACTIONS` or the system's temporary directory.
fn action_sidecar() -> &'static whipplescript_remote_execution::sidecar::ActionSidecar {
    static SIDECAR: std::sync::OnceLock<whipplescript_remote_execution::sidecar::ActionSidecar> =
        std::sync::OnceLock::new();
    SIDECAR.get_or_init(|| {
        whipplescript_remote_execution::sidecar::ActionSidecar::new(
            whipplescript_remote_execution::sidecar::default_sidecar_root(),
        )
    })
}

fn write_json_response(
    mut stream: TcpStream,
    status: u16,
    response_body: Value,
) -> std::io::Result<()> {
    let payload = response_body.to_string();
    write!(
        stream,
        "HTTP/1.1 {status} {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
        match status {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            409 => "Conflict",
            401 => "Unauthorized",
            413 => "Payload Too Large",
            422 => "Unprocessable Content",
            431 => "Request Header Fields Too Large",
            _ => "Internal Server Error",
        },
        payload.len(),
    )?;
    stream.flush()
}

fn check_executor_auth(
    local_ip: Option<IpAddr>,
    authorization: &Option<String>,
    token_header: &Option<String>,
) -> Result<(), (u16, String)> {
    let configured = std::env::var("WHIP_EXECUTOR_TOKEN")
        .ok()
        .map(|token| token.trim().to_owned())
        .filter(|token| !token.is_empty());
    let requires_auth =
        configured.is_some() || !local_ip.map(|ip| ip.is_loopback()).unwrap_or(false);
    let Some(expected) = configured else {
        return if requires_auth {
            Err((
                503,
                "WHIP_EXECUTOR_TOKEN is required for non-loopback executor binds".to_owned(),
            ))
        } else {
            Ok(())
        };
    };
    let actual = authorization
        .as_deref()
        .and_then(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
        })
        .map(str::trim)
        .or(token_header.as_deref())
        .unwrap_or_default();
    if constant_time_equal(actual, &expected) {
        Ok(())
    } else {
        Err((401, "unauthorized".to_owned()))
    }
}

fn constant_time_equal(left: &str, right: &str) -> bool {
    let mut diff = left.len() ^ right.len();
    let max = left.len().max(right.len());
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    for i in 0..max {
        diff |= usize::from(*left_bytes.get(i).unwrap_or(&0) ^ *right_bytes.get(i).unwrap_or(&0));
    }
    diff == 0
}

/// Validate + run one exec request. Pure with respect to the transport, so
/// it is testable without sockets.
pub fn handle_exec_request(request: &Value) -> Result<Value, (u16, String)> {
    let protocol = request
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if protocol != EXECUTOR_PROTOCOL {
        return Err((
            400,
            format!("unsupported protocol `{protocol}`; expected `{EXECUTOR_PROTOCOL}`"),
        ));
    }
    let effect_id = request
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let expected_sha = request
        .get("script_sha256")
        .and_then(Value::as_str)
        .ok_or((400, "script_sha256 is required".to_owned()))?
        .to_ascii_lowercase();
    let script_b64 = request
        .get("script_b64")
        .and_then(Value::as_str)
        .ok_or((400, "script_b64 is required".to_owned()))?;
    let script_bytes =
        base64_decode(script_b64).ok_or((400, "script_b64 is not valid base64".to_owned()))?;
    let actual_sha = sha256_hex(&script_bytes);
    if actual_sha != expected_sha {
        return Err((
            400,
            format!("script hash mismatch: expected {expected_sha}, got {actual_sha}"),
        ));
    }
    let argv = request
        .get("argv")
        .and_then(Value::as_array)
        .ok_or((400, "argv array is required".to_owned()))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or((400, "argv values must be strings".to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if argv.is_empty() {
        return Err((400, "argv must not be empty".to_owned()));
    }
    let script_index = request
        .get("script_index")
        .and_then(Value::as_u64)
        .ok_or((400, "script_index is required".to_owned()))? as usize;
    if script_index >= argv.len() {
        return Err((400, "script_index is out of range".to_owned()));
    }
    let env = match request.get("env") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Object(entries)) => entries
            .iter()
            .map(|(name, value)| {
                value
                    .as_str()
                    .map(|value| (name.clone(), value.to_owned()))
                    .ok_or((400, "env values must be strings".to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err((400, "env must be an object".to_owned())),
    };
    let stdin_json = request
        .get("stdin")
        .cloned()
        .unwrap_or(Value::Null)
        .to_string();
    let script_ext = request
        .get("script_ext")
        .and_then(Value::as_str)
        .unwrap_or("");
    let timeout_ms = request
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_TIMEOUT_MS)
        .min(MAX_TIMEOUT_MS);

    let staged = stage_verified_script(&actual_sha, &script_bytes, script_ext)
        .map_err(|error| (500, format!("failed to stage script: {error}")))?;
    let mut argv = argv;
    argv[script_index] = staged.path.display().to_string();

    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    // Cleaned environment: only the declared values plus PATH. The sidecar is
    // deliberately stronger than native exec here.
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    for (name, value) in &env {
        command.env(name, value);
    }
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    // Bounded slots with priority admission (production > working >
    // counterfactual), per the verified compute-priority-queue model —
    // postures ride the protocol via the request's `priority` field.
    let priority = priority_class(
        request
            .get("priority")
            .and_then(Value::as_str)
            .unwrap_or("production"),
    );
    let gate = exec_gate();
    gate.acquire(priority);
    let outcome = run_with_timeout(command, &stdin_json, Duration::from_millis(timeout_ms));
    gate.release();
    drop(staged);
    let output = outcome.map_err(|error| (500, format!("exec failed: {error}")))?;
    Ok(json!({
        "protocol": EXECUTOR_PROTOCOL,
        "effect_id": effect_id,
        "exit_code": output.exit_code,
        "timed_out": output.timed_out,
        "stdout": output.stdout,
        "stdout_truncated": output.stdout_truncated,
        "stderr": output.stderr,
        "stderr_truncated": output.stderr_truncated,
    }))
}

/// Spawn, hand off stdin (EPIPE-tolerant: a script that never reads stdin is
/// normal), and wait with a kill-on-timeout loop.
/// Captured streams retain their observed prefix even when a timeout kills the child.
fn run_with_timeout(
    mut command: Command,
    stdin_json: &str,
    timeout: Duration,
) -> Result<ExecProcessOutput, String> {
    let start = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to spawn: {error}"))?;
    // Input may exceed pipe capacity while an interpreter is stalled before
    // reading. Hand it off independently so that backpressure cannot prevent
    // the execution timer from starting or the parent from killing the child.
    let stdin_handle = child.stdin.take().map(|stdin| {
        let input = stdin_json.to_owned();
        std::thread::spawn(move || write_exec_stdin(stdin, &input))
    });

    // Drain pipes on threads so a chatty child cannot deadlock on a full pipe
    // while we poll for exit.
    let stdout_handle = child.stdout.take().map(spawn_drain);
    let stderr_handle = child.stderr.take().map(spawn_drain);

    let (exit_code, timed_out) = loop {
        // The wait FAILING and the child's state are two different questions.
        // Relabel and propagate the first -- nothing is decided here, the OS
        // already did -- and match only on the second, which is the decision.
        match child
            .try_wait()
            .map_err(|error| format!("failed to wait: {error}"))?
        {
            Some(status) => break (i64::from(status.code().unwrap_or(-1)), false),
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (-1, true);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };
    // A grandchild may still hold the pipes after the direct child is killed.
    // Snapshot already captured bytes instead of joining indefinitely or erasing
    // the prefix. Capture threads retain bounded buffers until their pipes close.
    let deadline = start + timeout;
    let stdin_open = if let Some(writer) = stdin_handle {
        while !writer.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        if writer.is_finished() {
            writer
                .join()
                .map_err(|_| "executor stdin writer panicked".to_owned())?
                .map_err(|error| format!("failed to write stdin: {error}"))?;
            false
        } else {
            true
        }
    } else {
        false
    };
    let (stdout, stdout_truncated, stdout_open) = stdout_handle
        .map(|drain| drain.finish(deadline))
        .unwrap_or_default();
    let (stderr, stderr_truncated, stderr_open) = stderr_handle
        .map(|drain| drain.finish(deadline))
        .unwrap_or_default();
    let timed_out = timed_out || stdin_open || stdout_open || stderr_open;

    Ok(ExecProcessOutput {
        exit_code,
        timed_out,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    })
}

fn write_exec_stdin<W: Write>(mut stdin: W, input: &str) -> std::io::Result<()> {
    match stdin.write_all(input.as_bytes()) {
        // A command deliberately ignoring its input is ordinary exec behavior.
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

struct ExecProcessOutput {
    exit_code: i64,
    timed_out: bool,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[derive(Default)]
struct StreamCapture {
    bytes: Vec<u8>,
    truncated: bool,
}

struct StreamDrain {
    thread: std::thread::JoinHandle<()>,
    capture: std::sync::Arc<std::sync::Mutex<StreamCapture>>,
}

impl StreamDrain {
    fn finish(self, deadline: Instant) -> (String, bool, bool) {
        while !self.thread.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let still_open = !self.thread.is_finished();
        if !still_open {
            let _ = self.thread.join();
        }
        let capture = self.capture.lock().expect("executor stream capture");
        let (text, capped) = cap_stream(String::from_utf8_lossy(&capture.bytes).into_owned());
        (text, capped || capture.truncated || still_open, still_open)
    }
}

fn spawn_drain<R: Read + Send + 'static>(mut source: R) -> StreamDrain {
    let capture = std::sync::Arc::new(std::sync::Mutex::new(StreamCapture::default()));
    let writer = std::sync::Arc::clone(&capture);
    let thread = std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match source.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => {
                    let mut capture = writer.lock().expect("executor stream capture");
                    let keep = count.min(STREAM_CAP_BYTES - capture.bytes.len());
                    capture.bytes.extend_from_slice(&chunk[..keep]);
                    capture.truncated |= keep < count;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    writer.lock().expect("executor stream capture").truncated = true;
                    break;
                }
            }
        }
    });
    StreamDrain { thread, capture }
}

fn cap_stream(stream: String) -> (String, bool) {
    if stream.len() <= STREAM_CAP_BYTES {
        return (stream, false);
    }
    let mut end = STREAM_CAP_BYTES;
    while !stream.is_char_boundary(end) {
        end -= 1;
    }
    (stream[..end].to_owned(), true)
}

/// Own the staged path for exactly one invocation. Cleanup of identical script
/// bytes in another invocation cannot remove this one's still-live executable.
struct StagedScript {
    path: PathBuf,
    directory: PathBuf,
}

impl Drop for StagedScript {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Stage the verified bytes under a temp path private to THIS request and
/// make the file executable (argv may invoke it directly).
///
/// The name carries the verified sha for legibility but must not be the sha
/// alone: identical scripts run concurrently as a matter of course (mass
/// regeneration, design note §6), and a shared path lets one request truncate
/// a file another is reading, or remove — after its own run — the script a
/// request still parked at the admission gate is about to spawn. The private
/// staging directory supplies that separation, and `StagedScript` removes it.
fn stage_verified_script(
    sha256: &str,
    bytes: &[u8],
    extension: &str,
) -> std::io::Result<StagedScript> {
    if extension.len() > 32
        || !extension
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "script extension must be a filename suffix",
        ));
    }
    let suffix = if extension.is_empty() {
        String::new()
    } else {
        format!(".{extension}")
    };
    let directory = super::private_staging_dir("whip-executor")?;
    let staged = StagedScript {
        path: directory.join(format!("{sha256}{suffix}")),
        directory,
    };
    std::fs::write(&staged.path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged.path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(staged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_kernel::exec_http::base64_encode;

    fn exec_request(script: &str, stdin: Value) -> Value {
        json!({
            "protocol": EXECUTOR_PROTOCOL,
            "effect_id": "effect-1",
            "script_sha256": sha256_hex(script.as_bytes()),
            "script_b64": base64_encode(script.as_bytes()),
            "script_ext": "sh",
            "argv": ["sh", "{script}"],
            "script_index": 1,
            "stdin": stdin,
        })
    }

    // The admission gate serves production before counterfactual when a slot
    // frees — the [serve] guard from compute-priority-queue.maude, live.
    #[test]
    fn admission_gate_grants_higher_priority_first() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let gate = Arc::new(AdmissionGate::new(1));
        // Occupy the single slot.
        gate.acquire(0);

        let order = Arc::new(std::sync::Mutex::new(Vec::new()));
        let started = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        // A counterfactual waiter first, then a production waiter.
        for &priority in &[2usize, 0usize] {
            let waiter_gate = Arc::clone(&gate);
            let waiter_order = Arc::clone(&order);
            let waiter_started = Arc::clone(&started);
            handles.push(std::thread::spawn(move || {
                waiter_started.fetch_add(1, Ordering::SeqCst);
                waiter_gate.acquire(priority);
                waiter_order.lock().expect("order lock").push(priority);
                waiter_gate.release();
            }));
            // Ensure registration order: the waiter must be queued inside
            // acquire before the next one spawns.
            while gate.waiting_total() < handles.len() {
                std::thread::yield_now();
            }
        }
        let _ = started;

        // Free the slot: the production waiter must win despite arriving
        // second; the counterfactual runs after it releases.
        gate.release();
        for handle in handles {
            handle.join().expect("waiter joins");
        }
        assert_eq!(*order.lock().expect("order lock"), vec![0, 2]);
    }

    #[test]
    fn managed_dispatch_requires_a_valid_digest_and_one_exact_admission() {
        for invalid in [
            "".to_owned(),
            "a".repeat(63),
            "A".repeat(64),
            "g".repeat(64),
        ] {
            assert!(ManagedDispatch::new(invalid).is_err());
        }
        let request = json!({"original":true});
        let gate = ManagedDispatch::new(sha256_hex(request.to_string().as_bytes())).expect("gate");
        assert!(gate.admit(&json!({"replacement":true})).is_err());
        assert!(gate.admit(&request).is_ok());
        assert!(gate.admit(&request).is_err());
    }

    /// A configuration variable that is SET but unreadable is not an absent
    /// one, and both arms that say so are load-bearing in opposite directions.
    /// `WHIP_NORM_RUNTIME` falling through to `Ok(None)` would serve without
    /// the verified profile the operator supplied; `WHIP_EXECUTOR_DISPATCH_SHA256`
    /// falling through to `None` would serve UNMANAGED, admitting every bypass
    /// the managed gate exists to refuse. `serve_on` reads both before it
    /// accepts anything, so each refusal is observable as a startup error.
    #[test]
    fn unreadable_executor_configuration_refuses_to_serve() {
        use std::os::unix::ffi::OsStringExt;

        let _guard = crate::env_lock();
        // Not valid UTF-8, so `env::var` yields `VarError::NotUnicode` rather
        // than `NotPresent` -- the distinction both arms turn on.
        let unreadable = std::ffi::OsString::from_vec(vec![0x66, 0xff, 0x6f]);
        for key in ["WHIP_NORM_RUNTIME", "WHIP_EXECUTOR_DISPATCH_SHA256"] {
            let restore = std::env::var_os(key);
            std::env::set_var(key, &unreadable);
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            // On ANOTHER thread, with a deadline. Without the refusal
            // `serve_on` does not return an error -- it goes on to serve, and
            // a call on this thread would then block forever. A test that
            // hangs when the guard it measures is removed reports nothing:
            // this one wedged a mutation sweep for three hours before it was
            // written this way, and would have spent the hosted job's whole
            // timeout saying so.
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = sender.send(serve_on(listener).is_err());
            });
            let refused = receiver.recv_timeout(Duration::from_secs(10));
            match restore {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
            assert_eq!(
                refused.ok(),
                Some(true),
                "{key} is set but unreadable; `serve_on` must refuse, not serve"
            );
        }
    }

    #[test]
    fn managed_executor_http_refuses_bypass_and_concurrent_replay() {
        use whipplescript_kernel::exec_incarnation;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind executor");
        let address = listener.local_addr().expect("address");
        let marker = std::env::temp_dir().join(format!(
            "whip-managed-{}-{}",
            std::process::id(),
            address.port()
        ));
        let mut dispatch = exec_request("printf x >> \"$MARKER\"\n", Value::Null);
        dispatch["env"] = json!({"MARKER":marker.to_string_lossy()});
        let gate = ManagedDispatch::new(sha256_hex(dispatch.to_string().as_bytes())).expect("gate");
        std::thread::spawn(move || {
            let _ = serve_on_with_profile(listener, Some(gate));
        });
        let base = format!("http://{address}");
        let handshake = ureq::get(&format!("{base}/exec/incarnation"))
            .call()
            .expect("handshake")
            .into_string()
            .expect("body");
        let incarnation = exec_incarnation::read_handshake(&handshake).expect("incarnation");
        for route in ["/exec", "/turn", "/exec/controller/deliver"] {
            let response = ureq::post(&format!("{base}{route}")).send_json(&dispatch);
            assert!(
                matches!(response, Err(ureq::Error::Status(409, _))),
                "{route}: {response:?}"
            );
        }
        assert!(matches!(
            ureq::get(&format!("{base}/turn"))
                .set("Upgrade", "websocket")
                .set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .call(),
            Err(ureq::Error::Status(409, _))
        ));
        let mut replaced = dispatch.clone();
        replaced["stdin"] = json!({"replacement":true});
        for (incarnation, request) in [("stale", &dispatch), (incarnation.as_str(), &replaced)] {
            let delivery =
                exec_incarnation::delivery(incarnation, request.clone()).expect("delivery");
            assert!(matches!(
                ureq::post(&format!("{base}/exec/bound")).send_string(&delivery),
                Err(ureq::Error::Status(409, _))
            ));
        }
        assert!(!marker.exists(), "refused deliveries executed");
        let delivery = exec_incarnation::delivery(&incarnation, dispatch).expect("delivery");
        let barrier = std::sync::Barrier::new(8);
        std::thread::scope(|scope| {
            let mut requests = Vec::new();
            for _ in 0..8 {
                requests.push(scope.spawn(|| {
                    barrier.wait();
                    match ureq::post(&format!("{base}/exec/bound")).send_string(&delivery) {
                        Ok(response) => {
                            let completion = response.into_string().expect("completion");
                            let (status, body) =
                                exec_incarnation::read_completion(&completion, &incarnation)
                                    .expect("bound completion");
                            assert_eq!(status, 200);
                            assert_eq!(body["exit_code"], 0);
                            1
                        }
                        Err(ureq::Error::Status(409, _)) => 0,
                        Err(error) => panic!("unexpected delivery error: {error}"),
                    }
                }));
            }
            assert_eq!(
                requests
                    .into_iter()
                    .map(|request| request.join().expect("request thread"))
                    .sum::<usize>(),
                1
            );
        });
        assert_eq!(std::fs::read(&marker).expect("script effect"), b"x");
        assert!(matches!(
            ureq::post(&format!("{base}/exec/bound")).send_string(&delivery),
            Err(ureq::Error::Status(409, _))
        ));
        std::fs::remove_file(marker).expect("remove marker");
    }

    #[test]
    fn base64_roundtrip() {
        for sample in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"echo hello # \xff\x00 binary"[..],
        ] {
            let encoded = base64_encode(sample);
            assert_eq!(base64_decode(&encoded).expect("decodes"), sample);
        }
        assert!(base64_decode("not!!base64").is_none());
    }

    #[test]
    fn exec_request_runs_script_with_stdin_and_env() {
        let script = "read line\necho \"got:$line:$JUDGE_MODE\"\necho oops >&2\nexit 3\n";
        let mut request = exec_request(script, json!({"n": 1}));
        request["env"] = json!({"JUDGE_MODE": "strict"});
        let response = handle_exec_request(&request).expect("executes");
        assert_eq!(response["exit_code"], json!(3));
        assert_eq!(response["timed_out"], json!(false));
        assert_eq!(response["stdout"], json!("got:{\"n\":1}:strict\n"));
        assert_eq!(response["stderr"], json!("oops\n"));
        assert_eq!(response["effect_id"], json!("effect-1"));
    }

    #[test]
    fn exec_request_cleans_the_environment() {
        let _guard = crate::env_lock();
        // A host env var not declared in the request must not leak through.
        std::env::set_var("WHIP_EXECUTOR_LEAK_PROBE", "leaked");
        let response = handle_exec_request(&exec_request(
            "echo \"probe:${WHIP_EXECUTOR_LEAK_PROBE:-clean}\"\n",
            Value::Null,
        ))
        .expect("executes");
        assert_eq!(response["stdout"], json!("probe:clean\n"));
    }

    #[test]
    fn exec_request_rejects_hash_mismatch_and_bad_shapes() {
        let mut tampered = exec_request("echo hi\n", Value::Null);
        tampered["script_b64"] = json!(base64_encode(b"echo tampered\n"));
        let (status, message) = handle_exec_request(&tampered).expect_err("hash mismatch");
        assert_eq!(status, 400);
        assert!(message.contains("hash mismatch"), "{message}");

        let mut wrong_protocol = exec_request("echo hi\n", Value::Null);
        wrong_protocol["protocol"] = json!("bogus/9");
        let (status, message) =
            handle_exec_request(&wrong_protocol).expect_err("protocol rejected");
        assert_eq!(status, 400);
        assert!(message.contains("unsupported protocol"), "{message}");

        let mut bad_index = exec_request("echo hi\n", Value::Null);
        bad_index["script_index"] = json!(9);
        let (status, message) = handle_exec_request(&bad_index).expect_err("index rejected");
        assert_eq!(status, 400);
        assert!(message.contains("out of range"), "{message}");
    }

    #[test]
    fn exec_request_kills_on_timeout() {
        let mut request = exec_request("sleep 5\n", Value::Null);
        request["timeout_ms"] = json!(150);
        let started = Instant::now();
        let response = handle_exec_request(&request).expect("timeout is a response");
        assert!(started.elapsed() < Duration::from_secs(4), "killed early");
        assert_eq!(response["timed_out"], json!(true));
        assert_eq!(response["exit_code"], json!(-1));
    }

    #[test]
    fn server_answers_exec_and_health_over_http() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let address = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            let _ = serve_on(listener);
        });

        let health: Value = ureq::get(&format!("http://{address}/healthz"))
            .call()
            .expect("healthz")
            .into_json()
            .expect("health json");
        assert_eq!(health["ok"], json!(true));

        let response: Value = ureq::post(&format!("http://{address}/exec"))
            .send_json(exec_request("echo over-http\n", Value::Null))
            .expect("exec call")
            .into_json()
            .expect("exec json");
        assert_eq!(response["exit_code"], json!(0));
        assert_eq!(response["stdout"], json!("over-http\n"));

        let error = ureq::post(&format!("http://{address}/exec"))
            .send_json(json!({"protocol": "bogus"}))
            .expect_err("bad request errors");
        match error {
            ureq::Error::Status(status, _) => assert_eq!(status, 400),
            other => panic!("unexpected transport error: {other}"),
        }
    }

    #[test]
    fn exec_incarnation_http_refuses_stale_delivery_before_running_script() {
        use whipplescript_kernel::exec_incarnation;
        let start = || {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind executor");
            let address = listener.local_addr().expect("executor address");
            std::thread::spawn(move || {
                let _ = serve_on(listener);
            });
            format!("http://{address}")
        };
        let first = start();
        let second = start();
        let inspect = |server: &str| {
            let body = ureq::get(&format!("{server}/exec/incarnation"))
                .call()
                .expect("incarnation query")
                .into_string()
                .expect("incarnation body");
            exec_incarnation::read_handshake(&body).expect("valid handshake")
        };
        let original = inspect(&first);
        assert_eq!(original.len(), 64);
        assert_eq!(
            inspect(&first),
            original,
            "connections share server identity"
        );
        let replacement = inspect(&second);
        assert_ne!(original, replacement, "server starts mint fresh identities");
        let marker = std::env::temp_dir().join(format!("whip-incarnation-{original}"));
        let mut dispatch = exec_request("printf x >> \"$MARKER\"\n", Value::Null);
        dispatch["env"] = json!({"MARKER":marker.to_string_lossy()});
        let stale = exec_incarnation::delivery(&original, dispatch.clone()).expect("delivery");
        let error = ureq::post(&format!("{second}/exec/bound"))
            .send_string(&stale)
            .expect_err("stale incarnation refused");
        assert!(matches!(error, ureq::Error::Status(409, _)));
        assert!(!marker.exists(), "stale delivery must not execute");
        let legacy = ureq::post(&format!("{second}/exec/bound"))
            .send_json(&dispatch)
            .expect_err("bound route refuses an unbound request");
        assert!(matches!(legacy, ureq::Error::Status(409, _)));
        assert!(!marker.exists());
        let bound = exec_incarnation::delivery(&replacement, dispatch).expect("bound delivery");
        let response = ureq::post(&format!("{second}/exec/bound"))
            .send_string(&bound)
            .expect("bound execution")
            .into_string()
            .expect("completion body");
        let (status, body) =
            exec_incarnation::read_completion(&response, &replacement).expect("bound completion");
        assert_eq!(status, 200);
        assert_eq!(body["exit_code"], 0);
        assert_eq!(std::fs::read(&marker).expect("script effect"), b"x");
        std::fs::remove_file(&marker).expect("remove marker");
        assert!(exec_incarnation::read_completion(&response, &original).is_err());
        let invalid = exec_incarnation::delivery(&replacement, json!({"protocol":"wrong"}))
            .expect("invalid dispatch wrapped");
        let response = ureq::post(&format!("{second}/exec/bound"))
            .send_string(&invalid)
            .expect("bound refusal response")
            .into_string()
            .expect("refusal body");
        assert_eq!(
            exec_incarnation::read_completion(&response, &replacement)
                .expect("bound refusal")
                .0,
            400
        );
    }

    // The connection limiter bounds concurrent handler threads: at the cap a
    // further acquire blocks until a permit is released, so an unauthenticated
    // peer cannot spawn unbounded threads (pre-auth DoS backstop).
    #[test]
    fn conn_limiter_blocks_at_cap_and_frees_on_drop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let limiter = Arc::new(ConnLimiter::new(1));
        let held = limiter.acquire();
        let done = Arc::new(AtomicBool::new(false));
        let (l2, d2) = (Arc::clone(&limiter), Arc::clone(&done));
        let waiter = std::thread::spawn(move || {
            let _permit = l2.acquire(); // cannot proceed while `held` lives
            d2.store(true, Ordering::SeqCst);
        });
        // The only permit is held, so the waiter cannot have acquired one no
        // matter how the threads interleave.
        assert!(!done.load(Ordering::SeqCst), "waiter must block at the cap");
        drop(held);
        waiter.join().expect("waiter acquires after release");
        assert!(done.load(Ordering::SeqCst));
    }

    // A header block larger than MAX_HEADER_BYTES is rejected with 431 rather
    // than buffered unboundedly — the slowloris/oversized-header DoS guard.
    #[test]
    fn oversized_header_block_is_rejected() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let address = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            let _ = serve_on(listener);
        });

        let mut stream = std::net::TcpStream::connect(address).expect("connect");
        let request_line = b"GET /healthz HTTP/1.1\r\n";
        stream.write_all(request_line).expect("request line");
        // Many COMPLETE header lines -- the block, not one long line, is what
        // this test is about -- cut off at exactly the first refused byte.
        //
        // The cut is the same precaution `an_unterminated_header_line_is_cut_off_at_the_cap`
        // takes below and for the same reason: a tail the server never reads
        // is still sitting in its receive buffer when it closes, which makes
        // the close an RST, and an RST discards the 431 the client has already
        // been sent. This test used to write MAX_HEADER_BYTES + 64 bytes and a
        // terminator past the cap, so it carried about 64 KiB of exactly that
        // tail. The Linux runner drained it in time and the assertion passed;
        // elsewhere the client read `"HTTP/1.1 "` and the gate reported a
        // truncated response as a missing refusal. Nothing about the cap
        // needs the tail -- the server has refused by then and stopped
        // reading -- so it is not sent.
        let mut headers = Vec::new();
        while headers.len() < MAX_HEADER_BYTES + 1 - request_line.len() {
            let mut line = b"X-Pad: ".to_vec();
            line.resize(1024 - 2, b'a');
            line.extend_from_slice(b"\r\n");
            headers.extend_from_slice(&line);
        }
        headers.truncate(MAX_HEADER_BYTES + 1 - request_line.len());
        stream.write_all(&headers).expect("oversized header block");
        stream.flush().ok();

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("complete refusal response");
        assert!(
            response.contains(" 431 ") && response.contains("request headers too large"),
            "oversized headers must be rejected with 431: {response:?}"
        );
    }

    // The byte cap has to bound the READ, not be checked once the line has
    // landed: a peer that never sends the terminator would otherwise have its
    // whole line buffered before it authenticates.
    #[test]
    fn an_unterminated_header_line_is_cut_off_at_the_cap() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let address = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            let _ = serve_on(listener);
        });

        let mut stream = std::net::TcpStream::connect(address).expect("connect");
        let request_line = b"GET /healthz HTTP/1.1\r\n";
        stream.write_all(request_line).expect("request line");
        let mut headers = b"X-Pad: ".to_vec();
        // Exactly the first refused byte, with no unread tail that could
        // reset the socket on close and discard part of the 431 response.
        headers.resize(MAX_HEADER_BYTES + 1 - request_line.len(), b'a');
        // No terminator, and the peer keeps the connection open: the 431 has
        // to arrive while the line is still unfinished.
        stream.write_all(&headers).expect("unterminated header");
        stream.flush().ok();

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("complete refusal response");
        assert!(
            response.contains(" 431 ") && response.contains("request headers too large"),
            "an unterminated header line must be cut off at the cap: {response:?}"
        );
    }

    // The cap covers the request line as well as the header lines: it is read
    // pre-auth too, and it is the first thing an attacking peer can grow.
    #[test]
    fn an_oversized_request_line_is_cut_off_at_the_cap() {
        use std::io::{Read, Write};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let address = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            let _ = serve_on(listener);
        });

        let mut stream = std::net::TcpStream::connect(address).expect("connect");
        let mut request_line = b"GET /".to_vec();
        // Avoid unread bytes after the bounded read: closing over such a
        // tail may reset the connection before the refusal body is received.
        request_line.resize(MAX_HEADER_BYTES + 1, b'a');
        stream
            .write_all(&request_line)
            .expect("oversized request line");
        stream.flush().ok();

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("complete refusal response");
        assert!(
            response.contains(" 431 ") && response.contains("request headers too large"),
            "an oversized request line must be rejected with 431: {response:?}"
        );
    }

    // The pre-auth budget is wall-clock for the whole header phase, not a
    // fresh allowance per recv: once it is spent, a peer still dribbling
    // bytes gets no further read.
    #[test]
    fn the_header_budget_belongs_to_the_phase_not_to_each_read() {
        use std::io::Write;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let address = listener.local_addr().expect("local addr");
        let mut client = std::net::TcpStream::connect(address).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        client
            .write_all(b"X-Dribble: a\r\n")
            .expect("the peer is still sending");
        client.flush().ok();

        let mut reader = BufReader::new(server.try_clone().expect("clone"));
        let mut line = String::new();
        let error = read_header_line(&server, Instant::now(), &mut reader, &mut line)
            .expect_err("a spent budget ends the header phase");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            line.is_empty(),
            "no further bytes are read once the budget is spent"
        );
    }

    /// A staged script lives INSIDE a per-request private directory
    /// (`whip-executor-<pid>-<nanos>-<n>/<sha><suffix>`), so discovery scans one
    /// level down. A flat match on the temp directory finds the directories,
    /// never the scripts.
    fn staged_paths_for_sha(sha: &str) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("whip-executor-"))
            })
            .filter_map(|dir| std::fs::read_dir(dir).ok())
            .flat_map(|inner| inner.flatten().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(sha))
            })
            .collect()
    }

    // Two in-flight requests for the SAME script must not share one staged
    // file: each request removes its staged script when it finishes, and a
    // request still waiting for an exec slot would then spawn on a path that
    // no longer exists.
    #[test]
    fn a_duplicate_request_cannot_unstage_a_waiting_request() {
        struct HeldSlots(usize);
        impl Drop for HeldSlots {
            fn drop(&mut self) {
                for _ in 0..self.0 {
                    exec_gate().release();
                }
            }
        }

        let script = "echo not-unstaged\n";
        let sha = sha256_hex(script.as_bytes());
        // A crashed earlier run can leave a file under this prefix behind.
        for stale in staged_paths_for_sha(&sha) {
            let _ = std::fs::remove_file(stale);
        }

        // Hold every exec slot so the request below parks between staging its
        // script and spawning it.
        let gate = exec_gate();
        for _ in 0..EXEC_SLOTS {
            gate.acquire(0);
        }
        let held = HeldSlots(EXEC_SLOTS);

        let parked =
            std::thread::spawn(move || handle_exec_request(&exec_request(script, Value::Null)));
        // Staging happens before the slot is requested, so the staged file
        // appearing means the request is parked at the gate.
        let deadline = Instant::now() + Duration::from_secs(10);
        while staged_paths_for_sha(&sha).is_empty() {
            assert!(Instant::now() < deadline, "the parked request never staged");
            std::thread::sleep(Duration::from_millis(5));
        }

        // A second request for the same script stages it, runs, and removes
        // its own staged file while the first request is still parked.
        let duplicate =
            stage_verified_script(&sha, script.as_bytes(), "sh").expect("stage duplicate");
        std::fs::remove_file(&duplicate.path).expect("the duplicate removes its own staged script");

        drop(held);
        let response = parked
            .join()
            .expect("parked request joins")
            .expect("parked request runs");
        assert_eq!(response["exit_code"], json!(0));
        assert_eq!(response["stdout"], json!("not-unstaged\n"));
    }

    #[test]
    fn the_action_route_runs_a_build_action_for_the_endpoints_sidecar_runner() {
        use whipplescript_remote_execution::runner::{ActionRunner, Output, PreparedAction};
        use whipplescript_remote_execution::sidecar::SidecarRunner;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind executor");
        let address = listener.local_addr().expect("address");
        std::thread::spawn(move || {
            let _ = serve_on(listener);
        });
        let base = format!("http://{address}");
        // An input larger than the script routes accept: the action routes
        // carry blobs, so only they take the larger body.
        let input = vec![b'q'; MAX_REQUEST_BODY_BYTES + 1024];
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let outcome = runtime
            .block_on(
                SidecarRunner::new(&base, None)
                    .expect("an http address")
                    .run(PreparedAction {
                        arguments: vec!["sh".into(), "-c".into(), "wc -c < in.bin > count".into()],
                        environment: vec![],
                        working_directory: String::new(),
                        inputs: [("in.bin".to_owned(), (input.clone(), false))]
                            .into_iter()
                            .collect(),
                        output_paths: vec!["count".into()],
                        timeout: Some(Duration::from_secs(60)),
                    }),
            )
            .expect("the executor ran the action");
        assert_eq!(outcome.exit_code, 0);
        match &outcome.outputs["count"] {
            Output::File { bytes, .. } => assert_eq!(
                String::from_utf8_lossy(bytes).trim(),
                input.len().to_string()
            ),
            other => panic!("not a file: {other:?}"),
        }
        match ureq::post(&format!("{base}/action/elsewhere")).send_json(json!({})) {
            Err(ureq::Error::Status(404, response)) => assert_eq!(
                response.into_json::<Value>().expect("json")["error"],
                "unknown action route"
            ),
            other => panic!("expected a 404, got {other:?}"),
        }
    }
}
