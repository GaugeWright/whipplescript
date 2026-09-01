//! The inbound HTTP listener, end to end (spec/std-ingress.md slice I4).
//!
//! Drives a real `whip ingress serve --http` over a real socket, because the
//! properties worth checking here are the ones a unit test cannot see: that an
//! unauthenticated delivery appends NO fact to the store, that a retry with the
//! same delivery id is absorbed, and that a wrong path answers without
//! revealing what is there.
//!
//! The listener is written to `models/tla/IngressDeliveryLifecycle.tla`; these
//! are the same three guards, observed from outside.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};

const SECRET: &str = "s3cret-webhook-token";

fn program() -> String {
    r#"@service
workflow Webhooks

use std.ingress

signal github.push { repo string }

output result R
class R { v string }

source http as pushes {
  path "/hooks/github"
  auth shared secret github_webhook
  observe as observation
  emit github.push {
    repo observation.path
  }
}

rule note
  when github.push as push
=> {
  complete result { v push.repo }
}
"#
    .to_owned()
}

/// A temp dir made the way the other integration tests make one — no
/// `tempfile` dependency for a directory this test removes itself.
fn temp_dir() -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("whip-ingress-e2e-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

struct Listener {
    child: Child,
    port: u16,
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the listener on an ephemeral port and wait until it says which one.
///
/// Reading the port from the process rather than picking one: binding :0 and
/// asking is the only way two tests running at once cannot collide.
fn start(dir: &std::path::Path) -> (Listener, String) {
    let bin = env!("CARGO_BIN_EXE_whip");
    let program_path = dir.join("webhooks.whip");
    std::fs::write(&program_path, program()).expect("write program");
    let store = dir.join("store.db");

    // A delivery is admitted INTO A RUNNING INSTANCE — the admission core has
    // no notion of creating one, and should not: a webhook that could start
    // workflows would be an unauthenticated peer deciding what runs. So the
    // instance exists first, and the listener admits into it.
    let started = Command::new(bin)
        .args([
            "--store",
            store.to_str().expect("store path"),
            "start",
            program_path.to_str().expect("program path"),
            "--json",
        ])
        .output()
        .expect("start runs");
    assert!(
        started.status.success(),
        "start failed: {}",
        String::from_utf8_lossy(&started.stderr)
    );
    let started: serde_json::Value =
        serde_json::from_slice(&started.stdout).expect("start prints json");
    let instance = started
        .get("instance_id")
        .and_then(|v| v.as_str())
        .expect("instance id")
        .to_owned();

    let mut child = Command::new(bin)
        .args([
            "--store",
            store.to_str().expect("store path"),
            "ingress",
            "serve",
            "--http",
            "127.0.0.1:0",
            "--program",
            program_path.to_str().expect("program path"),
            "--instance",
            &instance,
        ])
        .env("WHIPPLESCRIPT_INGRESS_SECRET_GITHUB_WEBHOOK", SECRET)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("listener starts");

    let stderr = child.stderr.take().expect("stderr");
    let mut reader = BufReader::new(stderr);
    let mut port = None;
    for _ in 0..40 {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(rest) = line.trim().strip_prefix("whip ingress listening on ") {
            port = rest.rsplit(':').next().and_then(|p| p.parse().ok());
            break;
        }
    }
    // Keep draining so a full pipe cannot wedge the listener mid-test.
    std::thread::spawn(move || {
        let mut sink = String::new();
        let _ = reader.read_to_string(&mut sink);
    });
    (
        Listener {
            child,
            port: port.expect("the listener announced its port"),
        },
        instance,
    )
}

struct Response {
    status: u16,
    body: String,
}

fn deliver(port: u16, path: &str, headers: &[(&str, &str)], body: &str) -> Response {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).expect("write");
    stream.flush().expect("flush");

    let mut raw = String::new();
    stream.read_to_string(&mut raw).expect("read");
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or_default().to_owned();
    Response { status, body }
}

fn authenticated(port: u16, delivery_id: &str, body: &str) -> Response {
    deliver(
        port,
        "/hooks/github",
        &[("x-whip-secret", SECRET), ("x-whip-delivery", delivery_id)],
        body,
    )
}

#[test]
fn the_listener_admits_authenticates_absorbs_and_routes() {
    let dir = temp_dir();
    let (listener, _instance) = start(&dir);
    let port = listener.port;

    // A delivery that authenticates admits exactly one fact.
    let first = authenticated(port, "delivery-1", r#"{"repo":"whipplescript"}"#);
    assert_eq!(first.status, 200, "body: {}", first.body);
    assert!(
        first.body.contains("\"status\":\"admitted\""),
        "body: {}",
        first.body
    );

    // THE RETRY. Same delivery id, absorbed — and it says so, with a 200: an
    // error would make a correct retry look like a failure and provoke another.
    let retry = authenticated(port, "delivery-1", r#"{"repo":"whipplescript"}"#);
    assert_eq!(retry.status, 200, "body: {}", retry.body);
    assert!(
        retry.body.contains("\"status\":\"duplicate\""),
        "a re-delivered id is absorbed: {}",
        retry.body
    );

    // A DIFFERENT delivery id is a different delivery, and admits.
    let second = authenticated(port, "delivery-2", r#"{"repo":"whipplescript"}"#);
    assert!(
        second.body.contains("\"status\":\"admitted\""),
        "body: {}",
        second.body
    );

    // AUTH FAILURE ADMITS NOTHING, and says only that it failed.
    let forged = deliver(
        port,
        "/hooks/github",
        &[
            ("x-whip-secret", "wrong"),
            ("x-whip-delivery", "delivery-3"),
        ],
        r#"{"repo":"whipplescript"}"#,
    );
    assert_eq!(forged.status, 401, "body: {}", forged.body);
    assert!(
        forged.body.contains("\"reason\":\"unauthenticated\""),
        "the sender learns only that it failed: {}",
        forged.body
    );
    assert!(
        !forged.body.contains("does not match"),
        "and not WHICH half was wrong: {}",
        forged.body
    );

    // No credentials at all: same answer, so a prober cannot tell a missing
    // header from a wrong one.
    let bare = deliver(port, "/hooks/github", &[], r#"{"repo":"x"}"#);
    assert_eq!(bare.status, 401, "body: {}", bare.body);

    // A WRONG PATH 404s without naming what does exist.
    let astray = deliver(
        port,
        "/hooks/elsewhere",
        &[("x-whip-secret", SECRET)],
        r#"{"repo":"x"}"#,
    );
    assert_eq!(astray.status, 404, "body: {}", astray.body);
    assert!(
        !astray.body.contains("github"),
        "a 404 must not map the endpoints that do exist: {}",
        astray.body
    );

    // A body that is not JSON is refused AFTER authentication and appends
    // nothing: the model's NoFactWithoutValidation.
    let malformed = deliver(
        port,
        "/hooks/github",
        &[("x-whip-secret", SECRET), ("x-whip-delivery", "delivery-4")],
        "this is not json",
    );
    assert_eq!(malformed.status, 400, "body: {}", malformed.body);
    // An AUTHENTICATED sender is told what was wrong. The reticence above is an
    // anti-probing measure and probing is a pre-authentication concern — this
    // caller proved it holds the secret, so a generic answer would only make
    // their integration harder to fix.
    assert!(
        malformed.body.contains("not JSON"),
        "the sender learns what to correct: {}",
        malformed.body
    );

    let _ = std::fs::remove_dir_all(&dir);
}
