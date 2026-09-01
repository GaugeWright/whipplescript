//! The inbound HTTP delivery path (spec/std-ingress.md slice I4).
//!
//! Written to `models/tla/IngressDeliveryLifecycle.tla`, which came first by
//! house discipline. The model's three guards are the three refusals here —
//! authenticate before the admission core, never admit a settled key twice,
//! never append a fact for a payload that failed validation — and the model
//! proves each is load-bearing by removing it.
//!
//! **The decisions are separated from the socket.** Routing, authentication,
//! the delivery key and the correlation are functions over values, so every
//! refusal an operator can meet is checked without binding a port. What is left
//! in `serve_on` is the accept loop and the byte plumbing, in the style
//! `exec_server` already sets: hand-rolled HTTP/1.1, thread per connection,
//! threads not async.

use std::collections::BTreeMap;

use serde_json::Value;
use whipplescript_parser::IrSource;

/// Header carrying an HMAC signature over the body, `sha256=<hex>`.
pub const SIGNATURE_HEADER: &str = "x-whip-signature";
/// Header carrying a shared secret verbatim.
pub const SHARED_HEADER: &str = "x-whip-secret";
/// Header carrying the sender's delivery id.
pub const DELIVERY_HEADER: &str = "x-whip-delivery";

/// Where an inbound source's secret is read from.
///
/// An env var named after the reference, never the reference's own text: the
/// declaration names WHICH secret, and the environment holds it. That is the
/// same shape the MCP shim uses, and it is why a source may not carry a
/// literal.
pub fn secret_env_var(reference: &str) -> String {
    format!(
        "WHIPPLESCRIPT_INGRESS_SECRET_{}",
        reference.to_uppercase().replace(['-', '.'], "_")
    )
}

/// The sources this listener serves, by endpoint path.
///
/// Built once from the IR. A duplicate endpoint is refused rather than
/// resolved: two sources on one path means the path does not say which signal a
/// delivery becomes, and picking the first would make that depend on
/// declaration order.
pub fn routes(sources: &[IrSource]) -> Result<BTreeMap<String, &IrSource>, String> {
    let mut routes: BTreeMap<String, &IrSource> = BTreeMap::new();
    for source in sources {
        let Some(endpoint) = &source.endpoint else {
            continue;
        };
        if let Some(existing) = routes.get(endpoint.as_str()) {
            return Err(format!(
                "sources `{}` and `{}` both serve `{endpoint}`, so a delivery there names no \
                 single signal",
                existing.name, source.name
            ));
        }
        routes.insert(endpoint.clone(), source);
    }
    Ok(routes)
}

/// Why a delivery was refused before it reached the admission core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryRefusal {
    /// No source serves this path. 404: saying more would let a prober map the
    /// endpoints that do exist.
    UnknownPath,
    /// Authentication failed. 401, and the reason stays in whip's log rather
    /// than the response body — a sender that is not the sender learns only
    /// that it failed.
    Unauthenticated(String),
    /// The body was not the JSON the signal's contract requires. 400.
    Malformed(String),
    /// The delivery authenticated and named a target that is not there: an
    /// instance that finished, never started, or was never this sender's.
    ///
    /// SPECIFIC on purpose. The reticence above is an anti-probing measure, and
    /// probing is a PRE-authentication concern: a caller that proved it holds
    /// the secret is the sender, and telling them "no such instance" costs
    /// nothing while withholding it makes a legitimate integration undebuggable.
    NoSuchTarget(String),
    /// The signal exists but may not be sourced from outside (DR-0027 H8: an
    /// internal channel carries its emitter's integrity). 403 rather than 400 —
    /// the delivery is well formed and the answer is that it is not allowed.
    Forbidden(String),
    /// The store could not take the fact. Not the sender's fault, so telling
    /// them their delivery was bad would send them looking in the wrong place:
    /// they are told to retry, which their delivery key makes safe.
    Unavailable(String),
}

impl DeliveryRefusal {
    pub fn status(&self) -> u16 {
        match self {
            DeliveryRefusal::UnknownPath => 404,
            DeliveryRefusal::Unauthenticated(_) => 401,
            DeliveryRefusal::Malformed(_) => 400,
            DeliveryRefusal::NoSuchTarget(_) => 404,
            DeliveryRefusal::Forbidden(_) => 403,
            DeliveryRefusal::Unavailable(_) => 503,
        }
    }

    /// What the SENDER is told. Deliberately less than what the operator reads:
    /// an authentication detail in the response body is a probing oracle.
    pub fn public_reason(&self) -> String {
        match self {
            DeliveryRefusal::UnknownPath => "no such endpoint".to_owned(),
            DeliveryRefusal::Unauthenticated(_) => "unauthenticated".to_owned(),
            // Everything below happens AFTER authentication, so the detail goes
            // to the sender: they are the sender, and a generic answer here
            // only makes their integration harder to fix.
            DeliveryRefusal::Malformed(detail)
            | DeliveryRefusal::NoSuchTarget(detail)
            | DeliveryRefusal::Forbidden(detail) => detail.clone(),
            // The sender is told to retry, and NOT what broke: an internal
            // failure's detail is the operator's, and it is in their log.
            DeliveryRefusal::Unavailable(_) => "temporarily unavailable, retry".to_owned(),
        }
    }
}

impl DeliveryRefusal {
    /// How an admission refusal reaches the sender.
    ///
    /// A TOTAL mapping rather than a refusal of its own: every admission
    /// refusal becomes some delivery refusal, and the only judgement here is
    /// which one. They answer differently because they are different problems
    /// for whoever has to fix them.
    pub fn from_admission(
        refusal: &whipplescript_kernel::ingress_pass::SignalRefusal,
    ) -> DeliveryRefusal {
        use whipplescript_kernel::ingress_pass::{refusal_reason, SignalRefusal};
        match refusal {
            SignalRefusal::InstanceNotFound => {
                DeliveryRefusal::NoSuchTarget(refusal_reason(refusal))
            }
            // Well formed and not allowed, which is not the same as malformed.
            SignalRefusal::InternalChannel => DeliveryRefusal::Forbidden(refusal_reason(refusal)),
            SignalRefusal::UndeclaredSignal { .. } | SignalRefusal::PayloadInvalid { .. } => {
                DeliveryRefusal::Malformed(refusal_reason(refusal))
            }
        }
    }
}

/// Constant-time equality, the same XOR-accumulate the credential proxy's token
/// check uses: every byte is read and only the accumulator decides. A compare
/// that returned early would leak how much of a forged token was right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Authenticate a delivery under the source's declared mode.
///
/// FAIL-CLOSED at every branch: a missing header, an unparsable one, a mode the
/// source did not declare, and a wrong secret all refuse. There is no path
/// through this function that admits without a match, which is the property the
/// model's `AuthenticatedBeforeAdmitted` states.
pub fn authenticate(
    mode: &str,
    secret: &str,
    headers: &BTreeMap<String, String>,
    body: &[u8],
) -> Result<(), DeliveryRefusal> {
    let unauthenticated = |detail: &str| Err(DeliveryRefusal::Unauthenticated(detail.to_owned()));
    match mode {
        // The only mode that binds the CONTENT: a replayed signature does not
        // carry over to different bytes.
        "hmac" => {
            let Some(presented) = headers.get(SIGNATURE_HEADER) else {
                return unauthenticated("no signature header");
            };
            let Some(hex) = presented.strip_prefix("sha256=") else {
                return unauthenticated("signature is not `sha256=<hex>`");
            };
            let Ok(presented) = decode_hex(hex) else {
                return unauthenticated("signature is not hex");
            };
            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
            let expected = ring::hmac::sign(&key, body);
            if !constant_time_eq(expected.as_ref(), &presented) {
                return unauthenticated("signature does not match the body");
            }
            Ok(())
        }
        "bearer" => {
            let Some(header) = headers.get("authorization") else {
                return unauthenticated("no authorization header");
            };
            let Some(token) = header.strip_prefix("Bearer ") else {
                return unauthenticated("authorization is not a bearer token");
            };
            if !constant_time_eq(token.as_bytes(), secret.as_bytes()) {
                return unauthenticated("bearer token does not match");
            }
            Ok(())
        }
        "shared" => {
            let Some(presented) = headers.get(SHARED_HEADER) else {
                return unauthenticated("no shared-secret header");
            };
            if !constant_time_eq(presented.as_bytes(), secret.as_bytes()) {
                return unauthenticated("shared secret does not match");
            }
            Ok(())
        }
        // A source cannot declare an unknown mode — the parser refuses it — so
        // reaching here means the IR and this table disagree. Refusing is the
        // only safe reading: admitting on a mode nobody implemented would be
        // authentication in name only.
        other => unauthenticated(&format!("unimplemented auth mode `{other}`")),
    }
}

fn decode_hex(text: &str) -> Result<Vec<u8>, ()> {
    if !text.len().is_multiple_of(2) {
        return Err(());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// The observation record an inbound delivery produces: `{body, path, delivery}`.
///
/// This is what `emit`, `dedup` and `correlate` read, and it is the shape the
/// parser type-checks against.
pub fn observation(body: &Value, path: &str, delivery: &str) -> Value {
    serde_json::json!({
        "body": body,
        "path": path,
        "delivery": delivery,
    })
}

/// The delivery id: the sender's if it gave one, otherwise a hash of the body.
///
/// A sender that retries with its own id is absorbed by that id; one that does
/// not is absorbed by content. The fallback is what makes "at most once per
/// key" hold for senders that do not participate.
pub fn delivery_id(headers: &BTreeMap<String, String>, body: &[u8]) -> String {
    if let Some(given) = headers.get(DELIVERY_HEADER) {
        if !given.trim().is_empty() {
            return given.trim().to_owned();
        }
    }
    let digest = ring::digest::digest(&ring::digest::SHA256, body);
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The instance a delivery belongs to, read from the path `correlate` names.
///
/// `None` when the source declares no correlation — the caller then uses the
/// instance it was started for, which is the single-instance case.
pub fn correlated_instance(
    source: &IrSource,
    observation: &Value,
) -> Result<Option<String>, DeliveryRefusal> {
    let Some(path) = &source.correlate_field else {
        return Ok(None);
    };
    let mut cursor = observation;
    for segment in path.split('.') {
        match cursor.get(segment) {
            Some(next) => cursor = next,
            None => {
                return Err(DeliveryRefusal::Malformed(format!(
                    "the delivery carries no `{path}` to correlate on"
                )))
            }
        }
    }
    match cursor {
        Value::String(instance) if !instance.is_empty() => Ok(Some(instance.clone())),
        // A correlation that is not a string names no instance. Refused rather
        // than stringified: `{"id": 7}` and `{"id": "7"}` would otherwise be
        // the same instance, and a sender could reach another tenant's run by
        // changing a JSON type.
        other => Err(DeliveryRefusal::Malformed(format!(
            "`{path}` is {}, which names no instance",
            match other {
                Value::Null => "absent".to_owned(),
                Value::String(_) => "empty".to_owned(),
                _ => format!("a {}", json_kind(other)),
            }
        ))),
    }
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// The socket
// ---------------------------------------------------------------------------

/// Cap on concurrently-handled connections. Every connection reads its request
/// line and headers BEFORE authenticating, so without a bound an unauthenticated
/// peer could open connections faster than they complete and pin unbounded
/// threads — the same slowloris-class reasoning `exec_server` states.
const MAX_CONNECTIONS: usize = 128;
/// Wall-clock budget for that pre-auth read.
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_HEADER_BYTES: usize = 64 * 1024;
/// A webhook body is small. Bounded so an unauthenticated peer cannot make this
/// process buffer megabytes on its say-so — and the length is checked BEFORE
/// the body is read, not after.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// What one delivery did, for the operator's log and the sender's status.
#[derive(Debug)]
pub enum DeliveryOutcome {
    Admitted {
        instance: String,
        fact: String,
    },
    /// The key was already admitted. Absorbed, and SAID so: an observable
    /// duplicate is the difference between idempotency and silence.
    Duplicate {
        instance: String,
        existing: String,
    },
    Refused(DeliveryRefusal),
}

impl DeliveryOutcome {
    pub fn status(&self) -> u16 {
        match self {
            // A duplicate is 200: the sender did its job, and the delivery is
            // accounted for. Answering an error would make a correct retry look
            // like a failure and provoke another one.
            DeliveryOutcome::Admitted { .. } | DeliveryOutcome::Duplicate { .. } => 200,
            DeliveryOutcome::Refused(refusal) => refusal.status(),
        }
    }

    pub fn body(&self) -> Value {
        match self {
            DeliveryOutcome::Admitted { instance, fact } => {
                serde_json::json!({"status": "admitted", "instance": instance, "fact": fact})
            }
            DeliveryOutcome::Duplicate { instance, existing } => serde_json::json!({
                "status": "duplicate", "instance": instance, "existing": existing
            }),
            DeliveryOutcome::Refused(refusal) => {
                serde_json::json!({"status": "refused", "reason": refusal.public_reason()})
            }
        }
    }
}

/// One parsed request, before anything is decided about it.
pub struct RawDelivery {
    pub method: String,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

/// Read one HTTP/1.1 request off a stream.
///
/// Header names are lowercased on the way in, because HTTP header names are
/// case-insensitive and a sender that writes `X-Whip-Signature` must not be a
/// different sender from one that writes `x-whip-signature`.
pub fn read_request(stream: &std::net::TcpStream) -> std::io::Result<Option<RawDelivery>> {
    use std::io::{BufRead, BufReader, Read};

    stream.set_read_timeout(Some(HEADER_READ_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(None);
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    // The query string is not part of the route: a sender that appends
    // `?retry=3` is delivering to the same endpoint.
    let path = target.split('?').next().unwrap_or_default().to_owned();

    let mut headers = BTreeMap::new();
    let mut header_bytes = request_line.len();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > MAX_HEADER_BYTES {
            return Ok(None);
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
        }
    }

    let length: usize = headers
        .get("content-length")
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Ok(None);
    }
    let mut body = vec![0u8; length];
    if length > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Some(RawDelivery {
        method,
        path,
        headers,
        body,
    }))
}

/// Write one JSON response and close.
pub fn write_response(
    mut stream: std::net::TcpStream,
    status: u16,
    body: &Value,
) -> std::io::Result<()> {
    use std::io::Write;
    let payload = body.to_string();
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
        payload.len()
    )?;
    stream.flush()
}

/// Decide what a delivery becomes, in the order the model fixes.
///
/// Route, then AUTHENTICATE, then validate, then admit — and each stage refuses
/// rather than falling through to the next. `admit` is the caller's closure so
/// this stays a decision over values: the store, the kernel and the IR live on
/// the other side of it, and every refusal above it is testable without any of
/// them.
pub fn decide<F>(
    routes: &BTreeMap<String, &IrSource>,
    secret_for: &dyn Fn(&str) -> Option<String>,
    delivery: &RawDelivery,
    default_instance: &str,
    mut admit: F,
) -> DeliveryOutcome
where
    F: FnMut(&IrSource, &str, &Value, &str) -> Result<AdmitOutcome, DeliveryRefusal>,
{
    // Only POST delivers. A GET on a webhook endpoint is a prober or a health
    // check, and neither should reach authentication.
    if delivery.method != "POST" {
        return DeliveryOutcome::Refused(DeliveryRefusal::UnknownPath);
    }
    let Some(source) = routes.get(delivery.path.as_str()) else {
        return DeliveryOutcome::Refused(DeliveryRefusal::UnknownPath);
    };
    let (Some(mode), Some(reference)) = (&source.auth_mode, &source.auth_secret) else {
        // The parser requires `auth` on an endpoint, so an inbound source
        // without one means the IR and that check disagree. Refusing is the
        // only safe reading.
        return DeliveryOutcome::Refused(DeliveryRefusal::Unauthenticated(
            "the source declares no auth".to_owned(),
        ));
    };
    let Some(secret) = secret_for(reference) else {
        // A configured secret that is absent is NOT an open door: the operator
        // meant to authenticate and the environment does not let them, so the
        // delivery is refused and the log says which variable is missing.
        return DeliveryOutcome::Refused(DeliveryRefusal::Unauthenticated(format!(
            "{} is not set, so `{reference}` resolves to nothing",
            secret_env_var(reference)
        )));
    };
    if let Err(refusal) = authenticate(mode, &secret, &delivery.headers, &delivery.body) {
        return DeliveryOutcome::Refused(refusal);
    }

    // Only now is the body parsed. An unauthenticated peer never reaches the
    // JSON parser, let alone the store.
    let body: Value = match serde_json::from_slice(&delivery.body) {
        Ok(body) => body,
        Err(error) => {
            return DeliveryOutcome::Refused(DeliveryRefusal::Malformed(format!(
                "body is not JSON: {error}"
            )))
        }
    };
    let key = delivery_id(&delivery.headers, &delivery.body);
    let observed = observation(&body, &delivery.path, &key);
    let instance = match correlated_instance(source, &observed) {
        Ok(Some(instance)) => instance,
        Ok(None) => default_instance.to_owned(),
        Err(refusal) => return DeliveryOutcome::Refused(refusal),
    };

    match admit(source, &instance, &observed, &key) {
        Ok(AdmitOutcome::Admitted { fact }) => DeliveryOutcome::Admitted { instance, fact },
        Ok(AdmitOutcome::Duplicate { existing }) => {
            DeliveryOutcome::Duplicate { instance, existing }
        }
        Err(refusal) => DeliveryOutcome::Refused(refusal),
    }
}

/// What the admission core did, in the terms this module cares about.
#[derive(Debug)]
pub enum AdmitOutcome {
    Admitted { fact: String },
    Duplicate { existing: String },
}

/// Bound the number of connections handled at once.
struct ConnLimiter {
    live: std::sync::Mutex<usize>,
    room: std::sync::Condvar,
    cap: usize,
}

impl ConnLimiter {
    fn new(cap: usize) -> Self {
        Self {
            live: std::sync::Mutex::new(0),
            room: std::sync::Condvar::new(),
            cap,
        }
    }

    /// Blocks while at the cap, so new peers queue in the OS backlog instead of
    /// spawning an unbounded number of handler threads.
    fn acquire(self: &std::sync::Arc<Self>) -> ConnPermit {
        let mut live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        while *live >= self.cap {
            live = self.room.wait(live).unwrap_or_else(|e| e.into_inner());
        }
        *live += 1;
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
        let mut live = self.limiter.live.lock().unwrap_or_else(|e| e.into_inner());
        *live = live.saturating_sub(1);
        self.limiter.room.notify_one();
    }
}

/// Serve deliveries on an already-bound listener until killed.
///
/// `handle` is the caller's: it owns the kernel and the store, which are not
/// `Sync`, so deliveries are handled ONE AT A TIME on the accept thread. That is
/// the honest shape for an admission path whose whole job is a serialized
/// append — concurrency here would buy nothing and would need a lock around the
/// store anyway. The connection cap still applies: it bounds peers waiting, not
/// work in flight.
pub fn serve_on<F>(listener: std::net::TcpListener, mut handle: F) -> std::io::Result<()>
where
    F: FnMut(&RawDelivery) -> DeliveryOutcome,
{
    eprintln!("whip ingress listening on {}", listener.local_addr()?);
    let limiter = std::sync::Arc::new(ConnLimiter::new(MAX_CONNECTIONS));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("ingress: accept failed: {error}");
                continue;
            }
        };
        let _permit = limiter.acquire();
        let delivery = match read_request(&stream) {
            Ok(Some(delivery)) => delivery,
            // A request whose head could not be read at all: closed early, over
            // the header cap, or over the body cap. Nothing to answer, and
            // nothing reached the store.
            Ok(None) => {
                let _ = write_response(
                    stream,
                    413,
                    &serde_json::json!({"status": "refused", "reason": "delivery too large"}),
                );
                continue;
            }
            Err(error) => {
                eprintln!("ingress: reading a delivery failed: {error}");
                continue;
            }
        };
        let outcome = handle(&delivery);
        // The operator's log carries the DETAIL the response withholds.
        match &outcome {
            DeliveryOutcome::Refused(refusal) => match refusal {
                DeliveryRefusal::Unauthenticated(detail) => {
                    eprintln!("ingress: {} refused: {detail}", delivery.path)
                }
                DeliveryRefusal::Malformed(detail) => {
                    eprintln!("ingress: {} rejected: {detail}", delivery.path)
                }
                DeliveryRefusal::UnknownPath => {
                    eprintln!("ingress: no source serves {}", delivery.path)
                }
                DeliveryRefusal::NoSuchTarget(detail) => {
                    eprintln!("ingress: {} has no target: {detail}", delivery.path)
                }
                DeliveryRefusal::Forbidden(detail) => {
                    eprintln!("ingress: {} forbidden: {detail}", delivery.path)
                }
                // The operator's log carries what the sender is not told.
                DeliveryRefusal::Unavailable(detail) => {
                    eprintln!("ingress: {} could not be recorded: {detail}", delivery.path)
                }
            },
            DeliveryOutcome::Duplicate { existing, .. } => {
                eprintln!(
                    "ingress: {} absorbed a duplicate of {existing}",
                    delivery.path
                )
            }
            DeliveryOutcome::Admitted { fact, .. } => {
                eprintln!("ingress: {} admitted {fact}", delivery.path)
            }
        }
        let _ = write_response(stream, outcome.status(), &outcome.body());
    }
    Ok(())
}

/// Turn what the admission core did into what the sender is told.
///
/// Here rather than inline at the call site because both arms are refusals the
/// mutation sweep must be able to measure, and neither is reachable through a
/// socket: an admission refusal needs a store in a particular state, and a
/// store FAILURE needs one that is broken. Over values, both are ordinary
/// tests.
pub fn map_admission(
    admission: Result<whipplescript_kernel::ingress_pass::SignalAdmission, String>,
) -> Result<AdmitOutcome, DeliveryRefusal> {
    use whipplescript_kernel::ingress_pass::SignalAdmission;
    match admission {
        Ok(SignalAdmission::Admitted { fact_event_id, .. }) => Ok(AdmitOutcome::Admitted {
            fact: fact_event_id,
        }),
        Ok(SignalAdmission::Duplicate { existing_event_id }) => Ok(AdmitOutcome::Duplicate {
            existing: existing_event_id,
        }),
        // The four admission refusals answer differently, because they are
        // different problems for whoever has to fix them: a target that is not
        // there, a signal that may not come from outside, and two shapes of
        // "your payload does not match the contract".
        Ok(SignalAdmission::Refused(refusal)) => {
            // Bound rather than constructed inline: `from_admission` is a TOTAL
            // mapping, so this line forwards a value someone else decided
            // instead of being a refusal of its own — which is also what makes
            // the mapping measurable, arm by arm, in its own tests.
            let refusal = DeliveryRefusal::from_admission(&refusal);
            Err(refusal)
        }
        // A store failure is NOT the sender's fault and saying otherwise would
        // send them looking at their payload. It is a 500-shaped problem, and
        // the only honest thing to tell them is to retry — which their delivery
        // key makes safe.
        Err(detail) => {
            let refusal = DeliveryRefusal::Unavailable(detail);
            Err(refusal)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn hmac_header(secret: &str, body: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let tag = ring::hmac::sign(&key, body);
        format!(
            "sha256={}",
            tag.as_ref()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        )
    }

    #[test]
    fn hmac_binds_the_body_it_signed() {
        let body = br#"{"repo":"whipplescript"}"#;
        let signed = headers(&[(SIGNATURE_HEADER, &hmac_header("s3cret", body))]);
        assert_eq!(authenticate("hmac", "s3cret", &signed, body), Ok(()));

        // The same signature over DIFFERENT bytes: this is the property hmac
        // has and the other two modes do not, so it is the one worth pinning.
        let tampered = br#"{"repo":"somewhere-else"}"#;
        assert!(authenticate("hmac", "s3cret", &signed, tampered).is_err());
    }

    #[test]
    fn every_auth_mode_fails_closed_on_a_missing_header() {
        let body = b"{}";
        for (mode, detail) in [
            ("hmac", "no signature header"),
            ("bearer", "no authorization header"),
            ("shared", "no shared-secret header"),
        ] {
            let refused = authenticate(mode, "s3cret", &headers(&[]), body)
                .expect_err("a delivery with no credentials is not authenticated");
            assert_eq!(
                refused,
                DeliveryRefusal::Unauthenticated(detail.to_owned()),
                "{mode} must refuse by name"
            );
            assert_eq!(refused.status(), 401);
        }
    }

    #[test]
    fn a_wrong_secret_is_refused_in_every_mode() {
        let body = b"{}";
        assert!(authenticate(
            "hmac",
            "s3cret",
            &headers(&[(SIGNATURE_HEADER, &hmac_header("wrong", body))]),
            body
        )
        .is_err());
        assert!(authenticate(
            "bearer",
            "s3cret",
            &headers(&[("authorization", "Bearer wrong")]),
            body
        )
        .is_err());
        assert!(authenticate(
            "shared",
            "s3cret",
            &headers(&[(SHARED_HEADER, "wrong")]),
            body
        )
        .is_err());
    }

    #[test]
    fn a_malformed_signature_is_refused_rather_than_ignored() {
        let body = b"{}";
        for (header, detail) in [
            ("md5=abcd", "signature is not `sha256=<hex>`"),
            ("sha256=nothex", "signature is not hex"),
            ("sha256=abc", "signature is not hex"),
        ] {
            let refused = authenticate(
                "hmac",
                "s3cret",
                &headers(&[(SIGNATURE_HEADER, header)]),
                body,
            )
            .expect_err("a signature that cannot be read is not a signature");
            assert_eq!(refused, DeliveryRefusal::Unauthenticated(detail.to_owned()));
        }
    }

    #[test]
    fn a_bearer_prefix_is_required_so_a_bare_token_is_not_admitted() {
        let body = b"{}";
        let refused = authenticate(
            "bearer",
            "s3cret",
            &headers(&[("authorization", "s3cret")]),
            body,
        )
        .expect_err("the scheme is part of the header");
        assert_eq!(
            refused,
            DeliveryRefusal::Unauthenticated("authorization is not a bearer token".to_owned())
        );
    }

    #[test]
    fn an_unimplemented_mode_refuses_rather_than_admits() {
        // The parser refuses an unknown mode, so reaching this means the IR and
        // this table disagree. Admitting would be authentication in name only.
        let refused = authenticate("magic", "s3cret", &headers(&[]), b"{}")
            .expect_err("a mode nobody implemented authenticates nothing");
        assert!(matches!(refused, DeliveryRefusal::Unauthenticated(_)));
    }

    #[test]
    fn a_senders_delivery_id_wins_and_the_body_hash_is_the_fallback() {
        let body = br#"{"a":1}"#;
        assert_eq!(
            delivery_id(&headers(&[(DELIVERY_HEADER, " abc-123 ")]), body),
            "abc-123",
            "trimmed, so a stray space is not a different delivery"
        );
        // A sender that gives no id is still absorbed, by content.
        let hashed = delivery_id(&headers(&[]), body);
        assert_eq!(hashed.len(), 64);
        assert_eq!(
            hashed,
            delivery_id(&headers(&[]), body),
            "same body, same key"
        );
        assert_ne!(hashed, delivery_id(&headers(&[]), br#"{"a":2}"#));
        // An empty header is not an id: it would collapse every such delivery
        // onto one key and absorb them all after the first.
        assert_eq!(
            delivery_id(&headers(&[(DELIVERY_HEADER, "  ")]), body),
            hashed
        );
    }

    /// A real lowered source rather than a hand-built one, so these tests
    /// cannot drift from what the lowering actually produces — the clause
    /// grammar and the listener have to agree, and compiling is how that is
    /// checked rather than asserted.
    fn inbound_source_with(extra_clauses: &str) -> IrSource {
        let program = format!(
            "@service\nworkflow W\n\nuse std.ingress\n\nsignal github.push {{ repo string }}\n\noutput result R\nclass R {{ v string }}\n\nsource http as pushes {{\n  path \"/hooks/github\"\n  auth shared secret github_webhook\n{extra_clauses}  observe as observation\n  emit github.push {{ repo observation.path }}\n}}\n\nrule r\n  when github.push as p\n=> {{\n  complete result {{ v p.repo }}\n}}\n"
        );
        let compiled = whipplescript_parser::compile_program(&program);
        assert!(
            compiled.diagnostics.is_empty(),
            "fixture must compile: {:#?}",
            compiled
                .diagnostics
                .iter()
                .map(|d| &d.message)
                .collect::<Vec<_>>()
        );
        compiled
            .ir
            .expect("ir")
            .sources
            .into_iter()
            .next()
            .expect("one source")
    }

    fn inbound_source() -> IrSource {
        inbound_source_with("")
    }

    fn post(path: &str, headers: &[(&str, &str)], body: &str) -> RawDelivery {
        RawDelivery {
            method: "POST".to_owned(),
            path: path.to_owned(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn secret_is(value: &'static str) -> impl Fn(&str) -> Option<String> {
        move |_| Some(value.to_owned())
    }

    #[test]
    fn a_delivery_that_authenticates_reaches_the_admission_core() {
        let source = inbound_source();
        let routes = routes(std::slice::from_ref(&source)).expect("routes");
        let mut reached = 0;
        let outcome = decide(
            &routes,
            &secret_is("s3cret"),
            &post(
                "/hooks/github",
                &[(SHARED_HEADER, "s3cret")],
                r#"{"repo":"w"}"#,
            ),
            "inst-1",
            |_source, instance, observed, key| {
                reached += 1;
                assert_eq!(
                    instance, "inst-1",
                    "no correlation declared, so the default"
                );
                assert_eq!(observed["body"]["repo"], "w");
                assert_eq!(observed["path"], "/hooks/github");
                assert_eq!(observed["delivery"], key);
                Ok(AdmitOutcome::Admitted {
                    fact: "fact-1".to_owned(),
                })
            },
        );
        assert_eq!(reached, 1);
        assert_eq!(outcome.status(), 200);
        assert_eq!(outcome.body()["status"], "admitted");
    }

    #[test]
    fn nothing_unauthenticated_reaches_the_admission_core() {
        // The model's `AuthenticatedBeforeAdmitted`, in code: the closure is
        // the admission core, and a forged delivery must not call it.
        let source = inbound_source();
        let routes = routes(std::slice::from_ref(&source)).expect("routes");
        let mut reached = 0;
        let outcome = decide(
            &routes,
            &secret_is("s3cret"),
            &post(
                "/hooks/github",
                &[(SHARED_HEADER, "wrong")],
                r#"{"repo":"w"}"#,
            ),
            "inst-1",
            |_, _, _, _| {
                reached += 1;
                Ok(AdmitOutcome::Admitted {
                    fact: "fact-1".to_owned(),
                })
            },
        );
        assert_eq!(reached, 0, "a forged delivery never reached admission");
        assert_eq!(outcome.status(), 401);
        assert_eq!(outcome.body()["reason"], "unauthenticated");
    }

    #[test]
    fn a_missing_secret_is_a_closed_door_rather_than_an_open_one() {
        // The operator MEANT to authenticate and the environment does not let
        // them. Treating that as "no auth configured" would turn a deployment
        // mistake into an open endpoint.
        let source = inbound_source();
        let routes = routes(std::slice::from_ref(&source)).expect("routes");
        let mut reached = 0;
        let outcome = decide(
            &routes,
            &|_| None,
            &post("/hooks/github", &[(SHARED_HEADER, "s3cret")], "{}"),
            "inst-1",
            |_, _, _, _| {
                reached += 1;
                Ok(AdmitOutcome::Admitted {
                    fact: "f".to_owned(),
                })
            },
        );
        assert_eq!(reached, 0);
        assert_eq!(outcome.status(), 401);
    }

    #[test]
    fn an_unknown_path_and_a_get_are_both_refused_before_auth() {
        let source = inbound_source();
        let routes = routes(std::slice::from_ref(&source)).expect("routes");
        let refuse = |delivery: RawDelivery| {
            decide(
                &routes,
                &secret_is("s3cret"),
                &delivery,
                "inst-1",
                |_, _, _, _| panic!("must not reach admission"),
            )
        };
        assert_eq!(refuse(post("/hooks/other", &[], "{}")).status(), 404);
        let mut get = post("/hooks/github", &[(SHARED_HEADER, "s3cret")], "{}");
        get.method = "GET".to_owned();
        // A GET on a webhook endpoint is a prober or a health check, and the
        // 404 tells it nothing about what is there.
        assert_eq!(refuse(get).status(), 404);
    }

    #[test]
    fn a_correlated_delivery_names_the_instance_it_belongs_to() {
        let source = inbound_source_with("  correlate observation.body.instance\n");
        let routes = routes(std::slice::from_ref(&source)).expect("routes");
        let outcome = decide(
            &routes,
            &secret_is("s3cret"),
            &post(
                "/hooks/github",
                &[(SHARED_HEADER, "s3cret")],
                r#"{"instance":"inst-42"}"#,
            ),
            "inst-default",
            |_, instance, _, _| {
                assert_eq!(instance, "inst-42", "the delivery said which run it is for");
                Ok(AdmitOutcome::Admitted {
                    fact: "f".to_owned(),
                })
            },
        );
        assert_eq!(outcome.body()["instance"], "inst-42");
    }

    #[test]
    fn a_correlation_of_the_wrong_type_is_refused_rather_than_stringified() {
        // `{"instance": 7}` and `{"instance": "7"}` must not be the same run:
        // a sender could otherwise reach another tenant by changing a JSON type.
        let source = inbound_source_with("  correlate observation.body.instance\n");
        let routes = routes(std::slice::from_ref(&source)).expect("routes");
        let outcome = decide(
            &routes,
            &secret_is("s3cret"),
            &post(
                "/hooks/github",
                &[(SHARED_HEADER, "s3cret")],
                r#"{"instance":7}"#,
            ),
            "inst-default",
            |_, _, _, _| panic!("must not reach admission"),
        );
        assert_eq!(outcome.status(), 400);
    }

    #[test]
    fn a_duplicate_is_absorbed_and_says_so_with_a_200() {
        // Answering an error would make a CORRECT retry look like a failure and
        // provoke another one; answering nothing would make idempotency
        // indistinguishable from silence.
        let source = inbound_source();
        let routes = routes(std::slice::from_ref(&source)).expect("routes");
        let outcome = decide(
            &routes,
            &secret_is("s3cret"),
            &post("/hooks/github", &[(SHARED_HEADER, "s3cret")], "{}"),
            "inst-1",
            |_, _, _, _| {
                Ok(AdmitOutcome::Duplicate {
                    existing: "event-1".to_owned(),
                })
            },
        );
        assert_eq!(outcome.status(), 200);
        assert_eq!(outcome.body()["status"], "duplicate");
        assert_eq!(outcome.body()["existing"], "event-1");
    }

    #[test]
    fn two_sources_on_one_endpoint_are_refused_at_startup() {
        // Picking the first would make which signal a delivery becomes depend
        // on declaration order.
        let first = inbound_source();
        let mut second = inbound_source();
        second.name = "other".to_owned();
        let refused = routes(&[first, second]).expect_err("one path, one source");
        assert!(refused.contains("both serve `/hooks/github`"), "{refused}");
        assert!(refused.contains("no single signal"), "{refused}");
    }

    #[test]
    fn each_admission_refusal_answers_differently() {
        use whipplescript_kernel::ingress_pass::{SignalAdmission, SignalRefusal};
        // They are different problems for whoever has to fix them, so they get
        // different answers rather than one 400 that means four things.
        let target = map_admission(Ok(SignalAdmission::Refused(
            SignalRefusal::InstanceNotFound,
        )))
        .expect_err("no such instance");
        assert_eq!(target.status(), 404);
        assert!(target.public_reason().contains("instance not found"));

        let internal = map_admission(Ok(SignalAdmission::Refused(SignalRefusal::InternalChannel)))
            .expect_err("not from outside");
        assert_eq!(
            internal.status(),
            403,
            "well formed and not allowed is not the same as malformed"
        );

        let invalid = map_admission(Ok(SignalAdmission::Refused(
            SignalRefusal::PayloadInvalid {
                errors: vec!["repo: expected string".to_owned()],
            },
        )))
        .expect_err("bad payload");
        assert_eq!(invalid.status(), 400);
        assert!(
            invalid.public_reason().contains("repo"),
            "an authenticated sender is told WHICH field: {}",
            invalid.public_reason()
        );
    }

    #[test]
    fn a_store_failure_is_not_reported_as_the_senders_mistake() {
        // Telling a sender their delivery was bad when the STORE broke sends
        // them looking at their payload. They are told to retry, which their
        // delivery key makes safe.
        let refusal = map_admission(Err("disk is full".to_owned())).expect_err("store failed");
        assert_eq!(refusal.status(), 503);
        assert_eq!(refusal.public_reason(), "temporarily unavailable, retry");
        assert!(
            !refusal.public_reason().contains("disk"),
            "what broke is the operator's, and it is in their log"
        );
    }

    #[test]
    fn an_admitted_or_duplicate_admission_maps_straight_through() {
        use whipplescript_kernel::ingress_pass::SignalAdmission;
        // The control: a mapping that refused everything would satisfy the two
        // tests above.
        assert!(matches!(
            map_admission(Ok(SignalAdmission::Admitted {
                event_id: "e".to_owned(),
                fact_event_id: "f".to_owned(),
                sequence: 1,
            })),
            Ok(AdmitOutcome::Admitted { .. })
        ));
        assert!(matches!(
            map_admission(Ok(SignalAdmission::Duplicate {
                existing_event_id: "e".to_owned(),
            })),
            Ok(AdmitOutcome::Duplicate { .. })
        ));
    }

    #[test]
    fn a_correlation_that_is_absent_or_the_wrong_type_says_which() {
        let source = inbound_source_with("  correlate observation.body.instance\n");
        let refusal = |body: &str| {
            let observed = observation(
                &serde_json::from_str(body).expect("json"),
                "/hooks/github",
                "d1",
            );
            correlated_instance(&source, &observed).expect_err("no instance")
        };
        // Absent: the path is not there at all.
        let missing = refusal("{}");
        assert!(
            missing
                .public_reason()
                .contains("carries no `body.instance`"),
            "{}",
            missing.public_reason()
        );
        // Present and the wrong type. Refused rather than stringified, so
        // `{"instance": 7}` cannot reach the run `{"instance": "7"}` names.
        let numeric = refusal(r#"{"instance":7}"#);
        // The PROSE as well as the interpolated kind: `mutate_message` keeps a
        // message's placeholders, so asserting only "a number" would survive
        // the text being rewritten to anything at all.
        assert!(
            numeric.public_reason().contains("which names no instance"),
            "{}",
            numeric.public_reason()
        );
        assert!(
            numeric.public_reason().contains("a number"),
            "and names what it found: {}",
            numeric.public_reason()
        );
        let empty = refusal(r#"{"instance":""}"#);
        assert!(
            empty.public_reason().contains("empty"),
            "{}",
            empty.public_reason()
        );
    }

    #[test]
    fn the_public_reason_says_less_than_the_log_does() {
        // An authentication detail in the response body is a probing oracle:
        // "no signature header" and "signature does not match" tell a forger
        // which half to work on.
        let refused =
            DeliveryRefusal::Unauthenticated("signature does not match the body".to_owned());
        assert_eq!(refused.public_reason(), "unauthenticated");
        assert_eq!(
            DeliveryRefusal::UnknownPath.public_reason(),
            "no such endpoint"
        );
        assert_eq!(DeliveryRefusal::UnknownPath.status(), 404);
    }
}
