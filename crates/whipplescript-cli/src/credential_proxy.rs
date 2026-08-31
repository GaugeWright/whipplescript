//! A localhost HTTP front-end for `CustodyOp::Request`, so a provider sidecar
//! can make authenticated calls without ever holding a key.
//!
//! **What this retires.** `CONTROL_PLANE_SECRET_ENV` strips whip's own secrets
//! from every provider spawn, and each sidecar's spawn strips the OTHER
//! families' API keys — but a sidecar still inherits its own family's key,
//! because the `codex` and `claude` CLIs are third-party binaries that do not
//! know whip exists and cannot be handed a sentinel to resolve.
//!
//! They do accept a BASE URL. So the sidecar is pointed here, given no key at
//! all, and this translates its plain HTTP into the custody protocol: an
//! `EgressRequest` carrying a SENTINEL where the credential belongs. The
//! custodian substitutes at the marked slot, egresses under its own
//! deny-by-default allow-list, and returns the response.
//!
//! The key therefore enters neither the sidecar's address space nor whip's.
//! That is the whole point, and it is why this is a front-end for an existing
//! operation rather than a proxy that holds a credential: a proxy holding one
//! would move the key from the child to the parent, which §2 forbids just as
//! firmly.
//!
//! **What it does not claim.** A sidecar that still has network access can
//! reach the upstream directly — it simply has nothing to authenticate with.
//! Denying that reach is a container property, as it is for the executor
//! sidecar. What this removes is the key, and with it exfiltration: a
//! compromised sidecar can spend the credential only through here, where the
//! allow-list bounds it.
//!
//! Server style matches `exec_server`: hand-rolled HTTP/1.1 over
//! `TcpListener`, thread per connection, threads not async.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use whipplescript_custody::{CredentialName, EgressRequest, PresentationForm, Sentinel};

/// How a sidecar's request is turned into a custody egress, or why it is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Translation {
    /// Send this to the custodian. The Authorization header carries a
    /// sentinel, never material.
    Egress(Box<EgressRequest>),
    /// Refuse, with a reason the operator reads in whip's log rather than the
    /// model reading it in a response body.
    Refuse(String),
}

/// What one proxy instance is authorized to do: reach exactly one upstream
/// origin, under exactly one credential.
///
/// Deliberately not a list. A proxy that fronted several credentials would let
/// a sidecar choose which one it spent by varying its request, and the choice
/// belongs to the spawn rather than to the child.
#[derive(Debug, Clone)]
pub struct ProxyBinding {
    /// The upstream origin, `https://host` with no trailing slash. A request's
    /// path is appended to it; the sidecar cannot name a different host.
    pub upstream: String,
    pub credential: CredentialName,
    pub form: PresentationForm,
}

/// Cap on a proxied request body. The provider protocols this fronts carry
/// prompts, not uploads, and an unbounded body would let a sidecar use whip's
/// memory as scratch space.
pub const MAX_PROXIED_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Headers a sidecar may not set, because the proxy owns them.
///
/// `authorization` is the point: the sentinel goes there, and a request that
/// set its own would either be overwritten silently or would race the
/// substitution. Refusing is the honest answer — it says the sidecar tried to
/// authenticate itself, which is exactly the posture this removes.
///
/// `host` follows the upstream, not the client. The hop-by-hop headers are
/// meaningless across a proxy boundary and a forwarded `connection` would
/// confuse the upstream about a connection it never saw.
const RESERVED_HEADERS: [&str; 6] = [
    "authorization",
    "host",
    "connection",
    "proxy-authorization",
    "transfer-encoding",
    "upgrade",
];

/// Translate one sidecar request into a custody egress.
///
/// Pure, and separated from the socket for the reason every other decision in
/// this build was: a refusal reachable only by standing up a listener and a
/// custodian is a refusal nothing gates.
pub fn translate(
    binding: &ProxyBinding,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Translation {
    if !path.starts_with('/') {
        return Translation::Refuse(format!(
            "proxied path must be origin-form and begin with `/`: {path:?}"
        ));
    }
    // An absolute-form request line (`GET https://elsewhere/...`) is how a
    // client asks a forward proxy to pick the host. This is not one: the
    // upstream is the spawn's choice, so naming another host is refused rather
    // than quietly rewritten to the bound one.
    if path.starts_with("//") || path.contains("://") {
        return Translation::Refuse(format!(
            "proxied path names a host; this proxy reaches only {}: {path:?}",
            binding.upstream
        ));
    }
    if body.len() > MAX_PROXIED_BODY_BYTES {
        return Translation::Refuse(format!(
            "proxied body is {} bytes, over the {MAX_PROXIED_BODY_BYTES} cap",
            body.len()
        ));
    }
    for (name, _) in headers {
        let lowered = name.to_ascii_lowercase();
        if RESERVED_HEADERS.contains(&lowered.as_str()) {
            return Translation::Refuse(format!(
                "proxied request sets `{name}`, which the proxy owns"
            ));
        }
    }

    let sentinel = Sentinel::new(binding.credential.clone(), binding.form);
    let mut forwarded: Vec<(String, String)> = headers.to_vec();
    forwarded.push(("Authorization".to_owned(), sentinel.render()));

    Translation::Egress(Box::new(EgressRequest {
        method: method.to_ascii_uppercase(),
        url: format!("{}{path}", binding.upstream),
        headers: forwarded,
        body_b64: if body.is_empty() {
            None
        } else {
            Some(whipplescript_kernel::exec_http::base64_encode(body))
        },
    }))
}

/// One request line plus headers, as read off a sidecar connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxiedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Parse an HTTP/1.1 request the sidecar sent.
///
/// Hand-rolled, matching `exec_server`: this repo's execution model is threads
/// and hand-written HTTP rather than an async stack, and a second style here
/// would be a second thing to audit.
///
/// Separated from the socket so a malformed request is testable as a value.
/// Every refusal below is one a sidecar can provoke, and reaching them only
/// through a live listener would put them beyond the suite.
pub fn parse_request(head: &str, body: Vec<u8>) -> Result<ProxiedRequest, String> {
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(path), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(format!("malformed request line: {request_line:?}"));
    };
    if !version.starts_with("HTTP/1.") {
        return Err(format!("unsupported protocol version: {version:?}"));
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(format!("malformed header line: {line:?}"));
        };
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }
    Ok(ProxiedRequest {
        method: method.to_owned(),
        path: path.to_owned(),
        headers,
        body,
    })
}

/// Whether a request carries the per-spawn token this proxy was started with.
///
/// The proxy listens on loopback, which is NOT an authorization boundary:
/// every process on the box can reach it, and one of them is the model's tool
/// loop. The token is what makes it the sidecar's proxy rather than the
/// machine's.
///
/// Compared in constant time for the usual reason — a byte-at-a-time compare
/// on a value an attacker can retry is a value an attacker can learn.
pub fn token_admitted(expected: &str, headers: &[(String, String)]) -> bool {
    let presented = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("x-whip-proxy-token"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    if presented.len() != expected.len() {
        return false;
    }
    presented
        .bytes()
        .zip(expected.bytes())
        .fold(0u8, |differing, (a, b)| differing | (a ^ b))
        == 0
}

/// Cap on concurrently-handled connections, and on the pre-auth header read.
/// Both for `exec_server`'s reasons: without them an unauthenticated peer can
/// open connections faster than they complete and pin unbounded threads.
const MAX_CONNECTIONS: usize = 64;
const HEADER_READ_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

/// Serve until killed, translating sidecar HTTP into custody egress.
pub fn serve(listener: TcpListener, binding: ProxyBinding, token: String) -> std::io::Result<()> {
    eprintln!(
        "whip credential proxy listening on {} -> {} as {}",
        listener.local_addr()?,
        binding.upstream,
        binding.credential
    );
    let shared = std::sync::Arc::new((binding, token));
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if live.load(std::sync::atomic::Ordering::SeqCst) >= MAX_CONNECTIONS {
            // Dropped rather than queued: a sidecar makes one call at a time,
            // so a backlog this deep is not the sidecar.
            continue;
        }
        live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let shared = std::sync::Arc::clone(&shared);
        let live = std::sync::Arc::clone(&live);
        std::thread::spawn(move || {
            let _ = handle(stream, &shared.0, &shared.1);
            live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        });
    }
    Ok(())
}

fn handle(mut stream: TcpStream, binding: &ProxyBinding, token: &str) -> std::io::Result<()> {
    stream.set_read_timeout(Some(HEADER_READ_BUDGET))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        head.push_str(line.trim_end_matches('\n').trim_end_matches('\r'));
        head.push_str("\r\n");
    }
    let head = head.trim_end_matches("\r\n").to_owned();

    let parsed = match parse_request(&head, Vec::new()) {
        Ok(parsed) => parsed,
        Err(reason) => return respond(&mut stream, 400, &reason),
    };
    // Authenticated BEFORE the body is read, so an unauthorized peer cannot
    // make this process buffer megabytes on its say-so.
    if !token_admitted(token, &parsed.headers) {
        return respond(&mut stream, 401, "proxy token missing or wrong");
    }
    let length: usize = parsed
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    if length > MAX_PROXIED_BODY_BYTES {
        return respond(&mut stream, 413, "body over the proxy cap");
    }
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;

    let request = match translate(
        binding,
        &parsed.method,
        &parsed.path,
        &parsed.headers,
        &body,
    ) {
        Translation::Egress(request) => *request,
        Translation::Refuse(reason) => return respond(&mut stream, 403, &reason),
    };
    match send_to_custodian(binding, request) {
        Ok((status, bytes)) => {
            let mut out = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .into_bytes();
            out.extend_from_slice(&bytes);
            stream.write_all(&out)
        }
        Err(reason) => respond(&mut stream, 502, &reason),
    }
}

/// Hand one translated request to the custodian and return its answer.
fn send_to_custodian(
    binding: &ProxyBinding,
    request: EgressRequest,
) -> Result<(u16, Vec<u8>), String> {
    send_via(crate::custody_egress_transport()?, binding, request)
}

/// The same, with the transport already resolved.
///
/// Split so the absent-transport refusal is reachable with a value rather than
/// by unsetting an env var mid-suite, which races every other test in the
/// binary. Resolving and using are two decisions, and only one of them needs a
/// custodian to exercise.
fn send_via(
    transport: Option<Box<dyn whipplescript_custody::CustodyTransport>>,
    binding: &ProxyBinding,
    request: EgressRequest,
) -> Result<(u16, Vec<u8>), String> {
    let Some(transport) = transport else {
        return Err("no custodian socket (WHIPPLESCRIPT_CUSTODIAN_SOCKET)".to_owned());
    };
    let call = whipplescript_custody::CustodyCall::new(
        whipplescript_custody::UseAttribution {
            run_id: "credential-proxy".to_owned(),
            actor: None,
            effect_key: None,
        },
        whipplescript_custody::CustodyOp::Request {
            credential: binding.credential.clone(),
            request,
            slots: 1,
        },
    );
    let reply = transport
        .call(call)
        .map_err(|error| format!("custodian unreachable: {error:?}"))?;
    requested_reply(reply.outcome)
}

/// What a custody reply means to the proxy, as a pure function.
///
/// Extracted for the reason `generated_reply` and `vault_encode` were: these
/// two refusal arms are otherwise reachable only through a live custodian
/// socket, and a refusal reachable only from an environment the suite does not
/// have is a refusal nothing gates.
pub fn requested_reply(
    outcome: Result<whipplescript_custody::CustodyOk, whipplescript_custody::CustodyError>,
) -> Result<(u16, Vec<u8>), String> {
    match outcome {
        Ok(whipplescript_custody::CustodyOk::Requested { response }) => {
            let bytes = response
                .body_b64
                .as_deref()
                .map(whipplescript_custody::decode_body_b64)
                .transpose()?
                .unwrap_or_default();
            Ok((response.status, bytes))
        }
        Ok(other) => Err(format!("custodian answered a request with {other:?}")),
        Err(refusal) => Err(format!("custodian refused: {refusal:?}")),
    }
}

/// A status line and a plain-text reason.
///
/// The reason reaches the SIDECAR, which means it reaches the model. That is
/// acceptable for these: each says the request was malformed or unauthorized,
/// which the caller already knows, and none names a credential or a policy.
fn respond(stream: &mut TcpStream, status: u16, reason: &str) -> std::io::Result<()> {
    let body = reason.as_bytes();
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ProxyBinding {
        ProxyBinding {
            upstream: "https://api.anthropic.com".to_owned(),
            credential: CredentialName::new("providers/anthropic").expect("name"),
            form: PresentationForm::Bearer,
        }
    }

    fn egress(t: Translation) -> EgressRequest {
        match t {
            Translation::Egress(request) => *request,
            Translation::Refuse(reason) => panic!("expected an egress: {reason}"),
        }
    }

    fn refusal(t: Translation) -> String {
        match t {
            Translation::Refuse(reason) => reason,
            Translation::Egress(_) => panic!("expected a refusal"),
        }
    }

    /// The property the whole design rests on: what leaves here carries a
    /// SENTINEL, never material. Whip has no key to put in, and that is why
    /// this is a front-end for `CustodyOp::Request` rather than a proxy that
    /// holds one.
    #[test]
    fn a_translated_request_carries_a_sentinel_and_no_material() {
        let request = egress(translate(
            &binding(),
            "post",
            "/v1/messages",
            &[("content-type".to_owned(), "application/json".to_owned())],
            br#"{"model":"claude"}"#,
        ));
        assert_eq!(request.method, "POST", "the method is normalised");
        assert_eq!(request.url, "https://api.anthropic.com/v1/messages");

        let auth = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .expect("the proxy supplies the Authorization header");
        assert_eq!(
            auth,
            Sentinel::new(
                CredentialName::new("providers/anthropic").expect("name"),
                PresentationForm::Bearer
            )
            .render()
        );
        // The sidecar's own headers survive; only the reserved ones are ours.
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "content-type" && value == "application/json"));
    }

    /// The upstream is the spawn's choice. A request naming another host is
    /// refused rather than quietly rewritten, because a silent rewrite would
    /// make a sidecar's attempt to reach elsewhere look like it succeeded.
    #[test]
    fn a_request_naming_another_host_is_refused() {
        for path in [
            "https://evil.example/v1/messages",
            "//evil.example/v1/messages",
            "v1/messages",
        ] {
            let reason = refusal(translate(&binding(), "GET", path, &[], b""));
            assert!(
                reason.contains("names a host") || reason.contains("origin-form"),
                "`{path}`: {reason}"
            );
        }
    }

    /// A sidecar that sets its own `Authorization` is trying to authenticate
    /// itself. Overwriting it silently would hide that; refusing says so.
    #[test]
    fn a_request_setting_a_reserved_header_is_refused() {
        for header in ["Authorization", "authorization", "Host", "Connection"] {
            let reason = refusal(translate(
                &binding(),
                "GET",
                "/v1/models",
                &[(header.to_owned(), "whatever".to_owned())],
                b"",
            ));
            assert!(reason.contains(header), "{header}: {reason}");
        }
    }

    #[test]
    fn an_oversized_body_is_refused() {
        let body = vec![b'x'; MAX_PROXIED_BODY_BYTES + 1];
        let reason = refusal(translate(&binding(), "POST", "/v1/messages", &[], &body));
        assert!(reason.contains("over the"), "{reason}");

        // The cap admits what it should: one byte under passes, so the refusal
        // is about the size rather than about bodies existing.
        let ok = vec![b'x'; MAX_PROXIED_BODY_BYTES];
        assert!(matches!(
            translate(&binding(), "POST", "/v1/messages", &[], &ok),
            Translation::Egress(_)
        ));
    }

    /// A bodiless request carries no `body_b64` rather than an empty one: the
    /// custodian scans bodies for sentinels, and an empty string is a body it
    /// would have to reason about.
    /// Loopback is not an authorization boundary: every process on the box can
    /// reach this port, and one of them is the model's tool loop. The token is
    /// what makes it the sidecar's proxy rather than the machine's.
    #[test]
    fn only_a_request_carrying_the_spawn_token_is_admitted() {
        let expected = "s3cret-per-spawn-token";
        let header = |value: &str| vec![("X-Whip-Proxy-Token".to_owned(), value.to_owned())];

        assert!(token_admitted(expected, &header(expected)));
        // Case-insensitive on the NAME, exact on the value.
        assert!(token_admitted(
            expected,
            &[("x-whip-proxy-token".to_owned(), expected.to_owned())]
        ));

        assert!(!token_admitted(expected, &[]), "an absent token is refused");
        assert!(!token_admitted(expected, &header("")));
        assert!(!token_admitted(expected, &header("wrong")));
        // A prefix must not pass: a compare that stopped at the shorter length
        // would admit anyone who guessed the first byte.
        assert!(!token_admitted(expected, &header("s3cret")));
        assert!(!token_admitted(
            expected,
            &header("s3cret-per-spawn-token-and-more")
        ));
    }

    /// A malformed request is a value, not a socket event. Every case here is
    /// one a sidecar can provoke.
    #[test]
    fn a_malformed_request_is_refused_by_reason() {
        for (head, expected) in [
            ("", "malformed request line"),
            ("GET", "malformed request line"),
            ("GET /v1/models", "malformed request line"),
            ("GET /v1/models HTTP/2", "unsupported protocol version"),
            (
                "GET /v1/models HTTP/1.1\r\nnot-a-header",
                "malformed header line",
            ),
        ] {
            let reason = parse_request(head, Vec::new())
                .err()
                .unwrap_or_else(|| panic!("`{head}` must not parse"));
            assert!(reason.contains(expected), "`{head}`: {reason}");
        }
    }

    #[test]
    fn a_well_formed_request_parses_to_its_parts() {
        let parsed = parse_request(
            "POST /v1/messages HTTP/1.1\r\nContent-Type: application/json\r\nX-Whip-Proxy-Token: t",
            b"{}".to_vec(),
        )
        .expect("parses");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/v1/messages");
        assert_eq!(parsed.body, b"{}");
        assert!(parsed
            .headers
            .iter()
            .any(|(n, v)| n == "Content-Type" && v == "application/json"));
    }

    /// A proxy with no custodian behind it refuses by name rather than
    /// failing obscurely: the sidecar is pointed here INSTEAD of holding a
    /// key, so "no custodian" is the difference between a working deployment
    /// and one that cannot authenticate at all.
    #[test]
    fn a_proxy_with_no_custodian_refuses_by_name() {
        let reason = send_via(
            None,
            &binding(),
            EgressRequest {
                method: "GET".to_owned(),
                url: "https://api.anthropic.com/v1/models".to_owned(),
                headers: Vec::new(),
                body_b64: None,
            },
        )
        .expect_err("no transport must refuse");
        assert!(reason.contains("no custodian socket"), "{reason}");
    }

    /// The custody reply's three shapes. Its two refusal arms are otherwise
    /// reachable only through a live custodian socket.
    #[test]
    fn a_custody_reply_is_a_response_or_a_named_refusal() {
        let (status, bytes) = requested_reply(Ok(whipplescript_custody::CustodyOk::Requested {
            response: whipplescript_custody::EgressResponse {
                status: 200,
                headers: Vec::new(),
                body_b64: Some(whipplescript_custody::encode_body_b64(b"{\"ok\":true}")),
            },
        }))
        .expect("a Requested reply maps to a response");
        assert_eq!(status, 200);
        assert_eq!(bytes, b"{\"ok\":true}");

        let wrong = requested_reply(Ok(whipplescript_custody::CustodyOk::Revoked {
            existed: true,
        }))
        .expect_err("another success shape is not a request reply");
        assert!(wrong.contains("answered a request with"), "{wrong}");

        let refused = requested_reply(Err(whipplescript_custody::CustodyError::Revoked {
            credential: CredentialName::new("providers/anthropic").expect("name"),
        }))
        .expect_err("a custodian refusal must surface");
        assert!(refused.contains("custodian refused"), "{refused}");
    }

    #[test]
    fn a_bodiless_request_carries_no_body() {
        let request = egress(translate(&binding(), "GET", "/v1/models", &[], b""));
        assert_eq!(request.body_b64, None);
    }
}

// ---------------------------------------------------------------------------
// Turn lifecycle
// ---------------------------------------------------------------------------

/// A proxy whip runs for the duration of ONE turn.
///
/// The tracker left three questions when the proxy itself landed, and they are
/// answered here rather than left to an operator's shell.
///
/// **Minted per turn, never shared.** The token is the only thing standing
/// between this listener and every other process on the box — loopback is not
/// an authorization boundary, and one of the processes on that box is the
/// model's own tool loop. A token that outlived its turn would be a standing
/// capability to spend the credential; one that dies with the turn is a
/// capability bounded by the work it was minted for. Sharing across turns
/// would buy a few milliseconds of setup and pay for it in blast radius.
///
/// **Started lazily and stopped on drop.** A turn that never spawns a sidecar
/// never opens a socket. Dropping the handle stops the listener, so the
/// lifetime is the scope rather than a cleanup step someone can forget on an
/// early return.
///
/// **A proxy that cannot serve fails the turn.** See `base_url`.
pub struct TurnProxy {
    base_url: String,
    stopping: std::sync::Arc<std::sync::atomic::AtomicBool>,
    serving: Option<std::thread::JoinHandle<()>>,
    port: u16,
}

impl TurnProxy {
    /// Bind a listener on an ephemeral loopback port and start serving.
    ///
    /// `127.0.0.1` explicitly, never `0.0.0.0`: this is reachable by design
    /// only from the box whip runs on, and binding a wildcard would put a
    /// credential-spending endpoint on the network for the sake of a default.
    pub fn start(binding: ProxyBinding, token: String) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&stopping);
        let serving = std::thread::spawn(move || {
            serve_until_stopped(listener, binding, token, &flag);
        });
        Ok(Self {
            base_url: format!("http://127.0.0.1:{port}"),
            stopping,
            serving: Some(serving),
            port,
        })
    }

    /// The base URL to hand a sidecar, or an error if the proxy is not serving.
    ///
    /// **This is the trap the tracker named.** The tempting failure behaviour
    /// is to fall back to the inherited key so the turn keeps running. That
    /// would make the guarantee conditional on nothing having gone wrong — the
    /// property would hold on every day it was not tested and lapse silently on
    /// the day it mattered, with no record that it had. So a dead proxy is an
    /// error the caller must handle, and the caller's only correct handling is
    /// to fail the turn.
    ///
    /// The distinction that survives: a turn that asks for NO proxy still
    /// inherits the key, which is the documented concession and unchanged. A
    /// turn that asked for one and cannot have it does not quietly become that
    /// turn.
    pub fn base_url(&self) -> Result<&str, String> {
        if !self.is_live() {
            return Err(format!(
                "the credential proxy for this turn is not serving on port {} — refusing to spawn \
                 a sidecar with its own key instead, because that would silently drop the \
                 property the proxy exists to provide",
                self.port
            ));
        }
        Ok(&self.base_url)
    }

    /// Whether the serving thread is still up.
    ///
    /// A panicked thread is indistinguishable from a stopped one here, and
    /// deliberately so: both mean nothing is answering, and the answer to
    /// "nothing is answering" is the same either way.
    pub fn is_live(&self) -> bool {
        !self.stopping.load(std::sync::atomic::Ordering::SeqCst)
            && self
                .serving
                .as_ref()
                .map(|handle| !handle.is_finished())
                .unwrap_or(false)
    }

    fn stop(&mut self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.serving.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for TurnProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

/// How long the accept loop sleeps between polls when no connection is waiting.
///
/// A non-blocking accept with a short sleep, rather than a blocking accept woken
/// by a self-connection: the wake-up trick needs the shutdown path to make a
/// TCP connection to itself, which fails in exactly the circumstances shutdown
/// matters. This costs one wake per interval on an idle turn and cannot wedge.
const ACCEPT_POLL: std::time::Duration = std::time::Duration::from_millis(10);

fn serve_until_stopped(
    listener: TcpListener,
    binding: ProxyBinding,
    token: String,
    stopping: &std::sync::atomic::AtomicBool,
) {
    let live = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    while !stopping.load(std::sync::atomic::Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                if live.load(std::sync::atomic::Ordering::SeqCst) >= MAX_CONNECTIONS {
                    continue;
                }
                live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let binding = binding.clone();
                let token = token.clone();
                let live = std::sync::Arc::clone(&live);
                std::thread::spawn(move || {
                    // Blocking reads inside the handler, so the connection is
                    // served the same way the long-running server serves it.
                    let _ = stream.set_nonblocking(false);
                    let _ = handle(stream, &binding, &token);
                    live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod turn_lifecycle_tests {
    use super::*;
    use std::io::Write;

    fn binding() -> ProxyBinding {
        ProxyBinding {
            upstream: "https://api.anthropic.com".to_owned(),
            credential: CredentialName::new("providers/anthropic").expect("name"),
            form: PresentationForm::Bearer,
        }
    }

    #[test]
    fn a_turn_proxy_listens_on_loopback_only() {
        let proxy = TurnProxy::start(binding(), "tok".to_owned()).expect("starts");
        let url = proxy
            .base_url()
            .expect("a fresh proxy is serving")
            .to_owned();
        assert!(
            url.starts_with("http://127.0.0.1:"),
            "a credential-spending endpoint must not be bound to a wildcard: {url}"
        );
        // It really accepts: binding a port is not the same as serving one.
        let port: u16 = url.rsplit(':').next().expect("port").parse().expect("u16");
        std::net::TcpStream::connect(("127.0.0.1", port)).expect("the proxy accepts");
    }

    #[test]
    fn stopping_the_turn_stops_the_listener() {
        let port = {
            let proxy = TurnProxy::start(binding(), "tok".to_owned()).expect("starts");
            let url = proxy.base_url().expect("serving").to_owned();
            url.rsplit(':')
                .next()
                .expect("port")
                .parse::<u16>()
                .expect("u16")
            // dropped here: the turn is over
        };
        // The socket is released with the turn rather than left for the next
        // one. Retried briefly because the close is another thread's work.
        let mut refused = false;
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
                refused = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(refused, "the listener outlived the turn that minted it");
    }

    #[test]
    fn a_dead_proxy_refuses_instead_of_letting_the_turn_continue() {
        // THE trap. A fallback to the inherited key here would make the
        // property hold on every day it was not tested and lapse on the day it
        // mattered, with no record that it had.
        let mut proxy = TurnProxy::start(binding(), "tok".to_owned()).expect("starts");
        proxy.stop();
        let error = proxy
            .base_url()
            .expect_err("a stopped proxy must not hand out a base URL");
        assert!(
            error.contains("refusing to spawn"),
            "the refusal must say what it is protecting: {error}"
        );
        assert!(!proxy.is_live());
    }

    #[test]
    fn a_family_with_no_known_upstream_is_refused() {
        // The proxy exists so the sidecar cannot choose where the credential is
        // spent. A family whose origin nobody decided has no safe default, and
        // guessing one would spend a credential at an address no one chose.
        let error = crate::proxy_upstream_for("wolfram")
            .expect_err("an unknown family has no upstream to proxy to");
        assert_eq!(error, "no credential proxy upstream is known for `wolfram`");

        // The control: the family that IS known resolves, so the refusal is
        // about the family rather than about the function refusing everything.
        assert_eq!(
            crate::proxy_upstream_for("anthropic"),
            Ok("https://api.anthropic.com")
        );
    }

    #[test]
    fn two_turns_get_different_tokens() {
        // The token is what stops every other process on the box from spending
        // the credential; reusing one across turns would make it a standing
        // capability rather than one bounded by the work it was minted for.
        let first = crate::proxy_turn_token();
        let second = crate::proxy_turn_token();
        assert_ne!(first, second);
        assert_eq!(first.len(), 64, "a full sha256, not a truncated one");
    }

    #[test]
    fn each_turn_gets_its_own_port_so_a_token_cannot_outlive_its_turn() {
        let first = TurnProxy::start(binding(), "tok-1".to_owned()).expect("starts");
        let second = TurnProxy::start(binding(), "tok-2".to_owned()).expect("starts");
        assert_ne!(
            first.base_url().expect("serving"),
            second.base_url().expect("serving"),
            "two turns sharing a listener would share a token"
        );
    }

    #[test]
    fn a_request_without_the_turns_token_is_refused_by_the_running_proxy() {
        // End to end through the real listener: authentication is not something
        // the translation layer does on its own behalf, it is what stops every
        // other process on this box from spending the credential.
        let proxy = TurnProxy::start(binding(), "the-turn-token".to_owned()).expect("starts");
        let url = proxy.base_url().expect("serving").to_owned();
        let port: u16 = url.rsplit(':').next().expect("port").parse().expect("u16");
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connects");
        stream
            .write_all(b"GET /v1/messages HTTP/1.1\r\nhost: x\r\nx-whip-proxy-token: wrong\r\n\r\n")
            .expect("writes");
        let mut response = String::new();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .expect("timeout");
        use std::io::Read;
        let _ = stream.read_to_string(&mut response);
        assert!(
            response.starts_with("HTTP/1.1 401"),
            "an unauthorized peer must be turned away: {response}"
        );
    }
}
