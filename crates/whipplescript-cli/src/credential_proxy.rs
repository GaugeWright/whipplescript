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
