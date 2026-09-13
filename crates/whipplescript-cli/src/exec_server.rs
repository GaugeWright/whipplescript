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

/// Serve forever on `bind` (e.g. `127.0.0.1:8080`).
pub fn serve(bind: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind)?;
    serve_on(listener)
}

/// Serve forever on an already-bound listener (tests bind `:0` first).
pub fn serve_on(listener: TcpListener) -> std::io::Result<()> {
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
                std::thread::spawn(move || {
                    let _permit = permit; // released when the handler returns
                    let _ = handle_connection(stream);
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

fn handle_connection(stream: TcpStream) -> std::io::Result<()> {
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

    if content_length > MAX_REQUEST_BODY_BYTES {
        return write_json_response(stream, 413, json!({"error": "request body too large"}));
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
            json!({"error": "unknown route; POST /exec or GET /healthz"}),
        ),
    };

    write_json_response(stream, status, response_body)
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
            413 => "Payload Too Large",
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
    argv[script_index] = staged.display().to_string();

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
    let _ = std::fs::remove_file(&staged);
    let (exit_code, timed_out, stdout, stderr) =
        outcome.map_err(|error| (500, format!("exec failed: {error}")))?;

    let (stdout, stdout_truncated) = cap_stream(stdout);
    let (stderr, stderr_truncated) = cap_stream(stderr);
    Ok(json!({
        "protocol": EXECUTOR_PROTOCOL,
        "effect_id": effect_id,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "stdout": stdout,
        "stdout_truncated": stdout_truncated,
        "stderr": stderr,
        "stderr_truncated": stderr_truncated,
    }))
}

/// Spawn, hand off stdin (EPIPE-tolerant: a script that never reads stdin is
/// normal), and wait with a kill-on-timeout loop. Returns
/// `(exit_code, timed_out, stdout, stderr)`.
fn run_with_timeout(
    mut command: Command,
    stdin_json: &str,
    timeout: Duration,
) -> Result<(i64, bool, String, String), String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to spawn: {error}"))?;
    if let Some(stdin) = child.stdin.as_mut() {
        if let Err(error) = stdin.write_all(stdin_json.as_bytes()) {
            if error.kind() != std::io::ErrorKind::BrokenPipe {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("failed to write stdin: {error}"));
            }
        }
    }
    drop(child.stdin.take());

    // Drain pipes on threads so a chatty child cannot deadlock on a full pipe
    // while we poll for exit.
    let stdout_handle = child.stdout.take().map(spawn_drain);
    let stderr_handle = child.stderr.take().map(spawn_drain);

    let start = Instant::now();
    let (exit_code, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (i64::from(status.code().unwrap_or(-1)), false),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    break (-1, true);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("failed to wait: {error}")),
        }
    };
    if timed_out {
        // Grandchildren of the killed process may still hold the pipes (kill
        // reaches the direct child only); joining the drain threads would
        // block until they exit. Abandon the drains — the threads end when
        // the pipes close — and report empty streams for the killed run.
        return Ok((exit_code, timed_out, String::new(), String::new()));
    }
    let stdout = stdout_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    Ok((exit_code, timed_out, stdout, stderr))
}

fn spawn_drain<R: Read + Send + 'static>(mut source: R) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = source.read_to_end(&mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    })
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

/// Stage the verified bytes under a temp path private to THIS request and
/// make the file executable (argv may invoke it directly).
///
/// The name carries the verified sha for legibility but must not be the sha
/// alone: identical scripts run concurrently as a matter of course (mass
/// regeneration, design note §6), and a shared path lets one request truncate
/// a file another is reading, or remove — after its own run — the script a
/// request still parked at the admission gate is about to spawn.
fn stage_verified_script(sha256: &str, bytes: &[u8], extension: &str) -> std::io::Result<PathBuf> {
    static STAGE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let suffix = if extension.is_empty() {
        String::new()
    } else {
        format!(".{extension}")
    };
    let unique = STAGE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "whip-executor-{sha256}-{}-{unique}{suffix}",
        std::process::id()
    ));
    std::fs::write(&path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755));
    }
    Ok(path)
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
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\n")
            .expect("request line");
        // One header line past the cap, then the terminator.
        let mut headers = b"X-Pad: ".to_vec();
        headers.resize(headers.len() + MAX_HEADER_BYTES + 64, b'a');
        headers.extend_from_slice(b"\r\n\r\n");
        stream.write_all(&headers).expect("oversized headers");
        stream.flush().ok();

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        assert!(
            response.contains(" 431 "),
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
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\n")
            .expect("request line");
        let mut headers = b"X-Pad: ".to_vec();
        headers.resize(headers.len() + MAX_HEADER_BYTES + 64, b'a');
        // No terminator, and the peer keeps the connection open: the 431 has
        // to arrive while the line is still unfinished.
        stream.write_all(&headers).expect("unterminated header");
        stream.flush().ok();

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
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
        request_line.resize(request_line.len() + MAX_HEADER_BYTES + 64, b'a');
        stream
            .write_all(&request_line)
            .expect("oversized request line");
        stream.flush().ok();

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
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

    fn staged_paths_with_prefix(prefix: &str) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return Vec::new();
        };
        entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(prefix))
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
        let prefix = format!("whip-executor-{sha}");
        // A crashed earlier run can leave a file under this prefix behind.
        for stale in staged_paths_with_prefix(&prefix) {
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
        while staged_paths_with_prefix(&prefix).is_empty() {
            assert!(Instant::now() < deadline, "the parked request never staged");
            std::thread::sleep(Duration::from_millis(5));
        }

        // A second request for the same script stages it, runs, and removes
        // its own staged file while the first request is still parked.
        let duplicate =
            stage_verified_script(&sha, script.as_bytes(), "sh").expect("stage duplicate");
        std::fs::remove_file(&duplicate).expect("the duplicate removes its own staged script");

        drop(held);
        let response = parked
            .join()
            .expect("parked request joins")
            .expect("parked request runs");
        assert_eq!(response["exit_code"], json!(0));
        assert_eq!(response["stdout"], json!("not-unstaged\n"));
    }
}
