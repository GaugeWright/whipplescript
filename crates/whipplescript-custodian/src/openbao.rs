//! The r3 `remote` backend: a small sync client for the OpenBao HTTP API
//! (DR-0053 §4, §8).
//!
//! At r3 the material never exists on this box — the key lives in an OpenBao
//! transit engine and the custodian forwards keyed operations to it. The
//! custodian stays semantically dumb either way: transit signs bytes and
//! verifies bytes; everything above that is whip's.
//!
//! Config comes from the environment at daemon start: `BAO_ADDR` (falling
//! back to `VAULT_ADDR`) and `BAO_TOKEN` (falling back to `VAULT_TOKEN`) —
//! the names the `bao`/`vault` CLIs already use, so one shell serves both.

use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use zeroize::Zeroizing;

use whipplescript_custody::CredentialKind;

/// Per-request timeout. Transit calls are small; anything slower than this is
/// an outage, not a slow sign.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// Renew at half the remaining lease, so a single failed attempt still leaves
/// as much time again to retry in.
const MIN_RENEW_INTERVAL_SECS: u64 = 5;
const MAX_RENEW_INTERVAL_SECS: u64 = 3600;

pub struct Client {
    /// Base address, no trailing slash.
    addr: String,
    /// The OpenBao token, sent as `X-Vault-Token`. Zeroizes on drop — it is
    /// itself a credential.
    token: Zeroizing<String>,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(addr: &str, token: &str) -> Self {
        Self {
            addr: addr.trim_end_matches('/').to_string(),
            token: Zeroizing::new(token.to_string()),
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
                .build(),
        }
    }

    /// Build a client from the environment: `BAO_ADDR`/`VAULT_ADDR` and
    /// `BAO_TOKEN`/`VAULT_TOKEN`. `Ok(None)` when no address is configured
    /// (the daemon simply has no r3 backend); an address without a token is
    /// an error — a half-configured remote backend must not look like an
    /// unconfigured one.
    pub fn from_env() -> Result<Option<Self>, String> {
        let addr = std::env::var("BAO_ADDR")
            .or_else(|_| std::env::var("VAULT_ADDR"))
            .ok()
            .filter(|a| !a.is_empty());
        let Some(addr) = addr else {
            return Ok(None);
        };
        let token = std::env::var("BAO_TOKEN")
            .or_else(|_| std::env::var("VAULT_TOKEN"))
            .ok()
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                "BAO_ADDR is set but no token: set BAO_TOKEN (or VAULT_TOKEN)".to_string()
            })?;
        Ok(Some(Self::new(&addr, &token)))
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    // -- transit ------------------------------------------------------------

    /// Sign (or MAC) `input` under the transit key. HMAC-SHA-256 kinds go
    /// through `/v1/transit/hmac/{key}` with `sha2-256`; Ed25519 kinds
    /// through `/v1/transit/sign/{key}`. Returns the KEY VERSION and the raw
    /// signature/MAC bytes, parsed out of OpenBao's `vault:vN:<base64>` format.
    ///
    /// The version is returned rather than dropped because verification needs
    /// it: transit resolves which key version to check from the prefix, so a
    /// caller that forgets it can only guess.
    pub fn transit_sign(
        &self,
        key: &str,
        input: &[u8],
        kind: CredentialKind,
    ) -> Result<(u32, Vec<u8>), String> {
        let value = match kind {
            CredentialKind::HmacSha256 => self.post_json(
                &format!("/v1/transit/hmac/{key}"),
                &serde_json::json!({
                    "algorithm": "sha2-256",
                    "input": B64.encode(input),
                }),
            )?,
            CredentialKind::Ed25519 => self.post_json(
                &format!("/v1/transit/sign/{key}"),
                &serde_json::json!({ "input": B64.encode(input) }),
            )?,
            other => return Err(format!("r3 transit does not sign for kind {other}")),
        };
        let field = if kind == CredentialKind::HmacSha256 {
            "hmac"
        } else {
            "signature"
        };
        let encoded = value["data"][field]
            .as_str()
            .ok_or_else(|| format!("openbao response carries no data.{field}"))?;
        parse_vault_encoded(encoded)
    }

    /// Verify `sig_or_mac` (raw bytes) over `input` under the transit key via
    /// `/v1/transit/verify/{key}`. `Ok(false)` is a *successful* call whose
    /// answer is "invalid".
    ///
    /// `key_version` is the version the signature was MADE under, carried back
    /// from `transit_sign`. It used to be hard-coded to 1, which pinned r3 to a
    /// key that had never rotated; a caller that does not know the version
    /// passes 1 and gets the old behaviour explicitly rather than silently.
    pub fn transit_verify(
        &self,
        key: &str,
        input: &[u8],
        sig_or_mac: &[u8],
        kind: CredentialKind,
        key_version: u32,
    ) -> Result<bool, String> {
        let field = match kind {
            CredentialKind::HmacSha256 => "hmac",
            CredentialKind::Ed25519 => "signature",
            other => return Err(format!("r3 transit does not verify for kind {other}")),
        };
        let value = self.post_json(
            &format!("/v1/transit/verify/{key}"),
            &serde_json::json!({
                "input": B64.encode(input),
                field: vault_encode(key_version, sig_or_mac),
            }),
        )?;
        value["data"]["valid"]
            .as_bool()
            .ok_or_else(|| "openbao response carries no data.valid".to_string())
    }

    /// `POST /v1/transit/keys/{key}/rotate` — mint a new key version.
    ///
    /// Transit keeps every prior version, so this IS the dual validity §12
    /// asks for: signatures made before the rotation keep verifying under the
    /// version they carry, and new ones are made under the latest. That only
    /// holds because the version now travels with the signature — before the
    /// unpin, rotating would have broken every outstanding signature at once.
    ///
    /// Returns the version the key is at afterwards.
    pub fn transit_rotate(&self, key: &str) -> Result<u32, String> {
        self.post_json(
            &format!("/v1/transit/keys/{key}/rotate"),
            &serde_json::json!({}),
        )?;
        let value = self.get_json(&format!("/v1/transit/keys/{key}"))?;
        value["data"]["latest_version"]
            .as_u64()
            .map(|v| v as u32)
            .ok_or_else(|| "openbao response carries no data.latest_version".to_string())
    }

    // -- token lifecycle ----------------------------------------------------

    /// `GET /v1/auth/token/lookup-self` — the daemon-start liveness and
    /// posture probe.
    pub fn token_lookup_self(&self) -> Result<serde_json::Value, String> {
        self.get_json("/v1/auth/token/lookup-self")
    }

    /// `POST /v1/auth/token/renew-self` — keeps a renewable token alive
    /// across a long-running daemon. Returns the *new* posture so the caller
    /// can time the next renewal off the lease OpenBao actually granted
    /// rather than the one it asked for; OpenBao is free to grant less.
    pub fn token_renew_self(&self) -> Result<TokenPosture, String> {
        let value = self.post_json("/v1/auth/token/renew-self", &serde_json::json!({}))?;
        Ok(TokenPosture::from_renew(&value))
    }

    // -- plumbing -----------------------------------------------------------

    fn post_json(&self, path: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
        let request = self
            .agent
            .post(&format!("{}{path}", self.addr))
            .set("X-Vault-Token", &self.token);
        read_response(request.send_json(body.clone()))
    }

    fn get_json(&self, path: &str) -> Result<serde_json::Value, String> {
        let request = self
            .agent
            .get(&format!("{}{path}", self.addr))
            .set("X-Vault-Token", &self.token);
        read_response(request.call())
    }
}

// -- token renewal ----------------------------------------------------------

/// What OpenBao says about the daemon's own token: whether the lease can be
/// extended, and how much of it is left. Both the lookup and the renew reply
/// carry this, under different field names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenPosture {
    pub renewable: bool,
    pub ttl_secs: u64,
}

impl TokenPosture {
    /// Read the posture out of a `lookup-self` reply (`data.renewable`,
    /// `data.ttl`). A reply missing either field reads as *not renewable*,
    /// which costs an operator a renewal thread they can see is absent —
    /// the alternative is a thread renewing a token on a guess.
    pub fn from_lookup(value: &serde_json::Value) -> Self {
        Self::read(&value["data"], "ttl")
    }

    /// Read the posture out of a `renew-self` reply, which reports the fresh
    /// lease under `auth.lease_duration` rather than `data.ttl`.
    pub fn from_renew(value: &serde_json::Value) -> Self {
        Self::read(&value["auth"], "lease_duration")
    }

    fn read(section: &serde_json::Value, ttl_field: &str) -> Self {
        Self {
            renewable: section["renewable"].as_bool().unwrap_or(false),
            ttl_secs: section[ttl_field].as_u64().unwrap_or(0),
        }
    }
}

/// How long to wait before the next renewal attempt, given the lease left.
/// Half the remaining lease, floored so a short-TTL token cannot spin and
/// capped so a multi-day lease still checks in daily.
fn renew_interval(remaining_ttl_secs: u64) -> Duration {
    Duration::from_secs(
        (remaining_ttl_secs / 2).clamp(MIN_RENEW_INTERVAL_SECS, MAX_RENEW_INTERVAL_SECS),
    )
}

/// Keep the daemon's token alive for as long as the process runs.
///
/// `None` when there is nothing to renew — a non-renewable token, or one with
/// no expiry at all (a dev root token). That is not a failure, but the caller
/// should say so out loud: an operator who provisioned a renewable token and
/// gets no renewal thread needs to see why.
///
/// The thread is detached in practice; the handle is returned so a test can
/// hold one. Failures go to stderr, the daemon's one status channel, and are
/// logged per attempt rather than only at the end — a token that renews again
/// after a blip should leave a trace that the blip happened.
pub fn spawn_token_renewal(
    client: Arc<Client>,
    posture: TokenPosture,
) -> Option<std::thread::JoinHandle<()>> {
    if !posture.renewable || posture.ttl_secs == 0 {
        return None;
    }
    Some(std::thread::spawn(move || renewal_loop(&client, posture)))
}

fn renewal_loop(client: &Client, initial: TokenPosture) {
    let mut posture = initial;
    let mut renewed_at = Instant::now();
    let mut failures: u32 = 0;
    loop {
        let remaining = posture
            .ttl_secs
            .saturating_sub(renewed_at.elapsed().as_secs());
        if remaining == 0 {
            eprintln!(
                "openbao token renewal: the {}s lease on {} has run out after {failures} \
                 consecutive failures — every r3 credential operation fails from here until this \
                 daemon restarts with a live token",
                posture.ttl_secs,
                client.addr()
            );
            return;
        }
        std::thread::sleep(renew_interval(remaining));
        match client.token_renew_self() {
            Ok(next) => {
                if failures > 0 {
                    eprintln!(
                        "openbao token renewal: recovered after {failures} failed attempts \
                         (lease now {}s)",
                        next.ttl_secs
                    );
                    failures = 0;
                }
                // OpenBao can hand back a lease it will not extend again —
                // an explicit max TTL reached, or a token whose role changed.
                // Renewing on a loop past that point is noise; say so once.
                if !next.renewable || next.ttl_secs == 0 {
                    eprintln!(
                        "openbao token renewal: token is no longer renewable (renewable={}, \
                         lease={}s) — stopping; r3 stops working when this lease ends",
                        next.renewable, next.ttl_secs
                    );
                    return;
                }
                posture = next;
                renewed_at = Instant::now();
            }
            Err(detail) => {
                failures += 1;
                let left = posture
                    .ttl_secs
                    .saturating_sub(renewed_at.elapsed().as_secs());
                eprintln!(
                    "openbao token renewal FAILED (attempt {failures}, ~{left}s of lease left): \
                     {detail}"
                );
            }
        }
    }
}

// -- response plumbing ------------------------------------------------------

fn read_response(result: Result<ureq::Response, ureq::Error>) -> Result<serde_json::Value, String> {
    match result {
        Ok(response) => {
            let body = response
                .into_string()
                .map_err(|e| format!("openbao response read failed: {e}"))?;
            if body.trim().is_empty() {
                return Ok(serde_json::Value::Null);
            }
            serde_json::from_str(&body).map_err(|e| format!("openbao response is not JSON: {e}"))
        }
        // Non-2xx: surface OpenBao's `errors` array when the body carries one.
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            let errors = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v.get("errors").cloned())
                .filter(|e| e.as_array().is_some_and(|a| !a.is_empty()))
                .map(|e| e.to_string());
            match errors {
                Some(errors) => Err(format!("openbao returned {status}: {errors}")),
                None => Err(format!("openbao returned {status}")),
            }
        }
        Err(err) => Err(format!("openbao request failed: {err}")),
    }
}

/// Parse OpenBao's `vault:v<N>:<base64>` result format into raw bytes.
/// Render raw bytes back into transit's `vault:vN:<base64>` framing.
///
/// A one-line format, extracted because the line matters more than its size:
/// this is where the version reaches the wire, and it was a hard-coded `v1`
/// until 2026-08-30. Inlined, the only thing that could catch a regression is
/// the live smoke, which needs a real server and so runs on its own schedule —
/// a mutation sweep found exactly that hole. As a function it is unit-testable
/// against `parse_vault_encoded`, its own inverse.
fn vault_encode(version: u32, bytes: &[u8]) -> String {
    format!("vault:v{version}:{}", B64.encode(bytes))
}

/// Split `vault:vN:<base64>` into its KEY VERSION and raw bytes.
///
/// The version used to be discarded here while `transit_verify` re-added a
/// hard-coded `v1`, which is why r3 v1 scoped rotation out: a signature made
/// under key version 2 would have been verified against version 1 — a rotation
/// that succeeds and a verification that silently checks the wrong key. Keeping
/// the version is what unpins it.
fn parse_vault_encoded(s: &str) -> Result<(u32, Vec<u8>), String> {
    let rest = s
        .strip_prefix("vault:")
        .ok_or_else(|| format!("not a vault-encoded value: {s:?}"))?;
    let (version, b64) = rest
        .split_once(':')
        .ok_or_else(|| format!("malformed vault-encoded value: {s:?}"))?;
    let version = version
        .strip_prefix('v')
        .and_then(|digits| digits.parse::<u32>().ok())
        .ok_or_else(|| format!("malformed key version in vault-encoded value: {s:?}"))?;
    let bytes = B64
        .decode(b64)
        .map_err(|e| format!("bad base64 in vault-encoded value: {e}"))?;
    Ok((version, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Put a synthesized HTTP reply through `read_response`, in the same two
    /// shapes ureq hands it one: `Ok` for a 2xx, `Error::Status` otherwise.
    fn read(status: u16, body: &str) -> Result<serde_json::Value, String> {
        let response = ureq::Response::new(status, "test", body).expect("build response");
        read_response(if (200..300).contains(&status) {
            Ok(response)
        } else {
            Err(ureq::Error::Status(status, response))
        })
    }

    // -- parse_vault_encoded -------------------------------------------------

    #[test]
    fn parses_a_vault_encoded_value() {
        // The HMAC an OpenBao dev server actually returns for `hello`.
        let (version, raw) = parse_vault_encoded("vault:v1:aGVsbG8gd29ybGQ=").expect("parse");
        assert_eq!(version, 1);
        assert_eq!(raw, b"hello world");
    }

    /// The version is now RETURNED rather than discarded, which is what unpins
    /// r3 from key version 1. `transit_verify` used to re-add a hard-coded
    /// `vault:v1:` on the way out, so a v2 signature parsed on the way in and
    /// then verified against the wrong key.
    #[test]
    fn a_rotated_key_version_survives_the_parse() {
        let (version, raw) = parse_vault_encoded("vault:v2:aGVsbG8=").expect("parse");
        assert_eq!(version, 2, "the version must reach the verifier");
        assert_eq!(raw, b"hello");
    }

    /// `vault_encode` is `parse_vault_encoded`'s inverse, and the version has to
    /// survive BOTH directions. Verification resolves which key version to
    /// check from the framing this produces, so an encoder that dropped the
    /// version — as the inlined `format!` did with its hard-coded `v1` — sends
    /// a v2 signature to be checked against v1.
    #[test]
    fn the_encoder_carries_the_version_its_parser_reads() {
        for version in [1u32, 2, 17] {
            let framed = vault_encode(version, b"payload");
            assert_eq!(framed, format!("vault:v{version}:cGF5bG9hZA=="));
            let (parsed, bytes) = parse_vault_encoded(&framed).expect("round trips");
            assert_eq!(parsed, version, "the version must survive the round trip");
            assert_eq!(bytes, b"payload");
        }
    }

    /// Transit signs and verifies for two kinds. A third reaching this client
    /// is a mistake worth naming rather than sending to OpenBao to reject,
    /// and the refusal happens before any request — so it is testable without
    /// a server.
    #[test]
    fn transit_refuses_a_kind_it_cannot_verify() {
        let client = Client::new("http://127.0.0.1:1", "token");
        for kind in [
            CredentialKind::Bearer,
            CredentialKind::Raw,
            CredentialKind::AwsSigv4,
            CredentialKind::JwtRs256,
        ] {
            let err = client
                .transit_verify("k", b"payload", b"sig", kind, 1)
                .expect_err("must refuse before reaching the network");
            assert!(
                err.contains("does not verify for kind"),
                "{kind:?} must be refused by name: {err}"
            );
        }
    }

    /// An unreachable server is a transport failure, and the message says so
    /// rather than surfacing as a parse error about a body that never arrived.
    /// Port 1 is reserved and refuses immediately, so this needs no fixture.
    #[test]
    fn an_unreachable_server_is_reported_as_a_failed_request() {
        let client = Client::new("http://127.0.0.1:1", "token");
        let err = client
            .transit_sign("k", b"payload", CredentialKind::HmacSha256)
            .expect_err("an unreachable server must fail");
        assert!(
            err.contains("openbao request failed"),
            "a transport failure must say so: {err}"
        );
    }

    #[test]
    fn rejects_a_malformed_key_version() {
        // `vN` is the only shape transit emits; anything else would have to be
        // guessed at, and guessing a version is how the wrong key gets checked.
        for bad in ["vault:1:aGVsbG8=", "vault:vx:aGVsbG8=", "vault::aGVsbG8="] {
            assert!(
                parse_vault_encoded(bad).is_err(),
                "`{bad}` must not parse to a version"
            );
        }
    }

    #[test]
    fn empty_payload_parses_to_empty_bytes() {
        let (version, raw) = parse_vault_encoded("vault:v1:").expect("parse");
        assert_eq!(version, 1);
        assert!(raw.is_empty());
    }

    #[test]
    fn rejects_a_missing_vault_prefix() {
        // Bare base64 is the shape a caller gets from a non-transit endpoint,
        // so it must not decode by accident.
        let err = parse_vault_encoded("aGVsbG8=").expect_err("must reject");
        assert!(err.contains("not a vault-encoded value"), "{err}");
        let err = parse_vault_encoded("v1:aGVsbG8=").expect_err("must reject");
        assert!(err.contains("not a vault-encoded value"), "{err}");
    }

    #[test]
    fn rejects_a_missing_version_separator() {
        let err = parse_vault_encoded("vault:v1aGVsbG8=").expect_err("must reject");
        assert!(err.contains("malformed vault-encoded value"), "{err}");
    }

    #[test]
    fn rejects_bad_base64() {
        let err = parse_vault_encoded("vault:v1:not base64!").expect_err("must reject");
        assert!(err.contains("bad base64"), "{err}");
    }

    // -- read_response -------------------------------------------------------

    #[test]
    fn reads_a_json_body() {
        let value = read(200, r#"{"data":{"valid":true}}"#).expect("read");
        assert_eq!(value["data"]["valid"], serde_json::json!(true));
    }

    #[test]
    fn an_empty_2xx_body_is_null_not_an_error() {
        // 204 is what `renew-self` style endpoints return when they have
        // nothing to say; it is a success, not a parse failure.
        assert_eq!(read(204, "").expect("read"), serde_json::Value::Null);
    }

    #[test]
    fn a_non_json_2xx_body_is_an_error() {
        let err = read(200, "<html>proxy</html>").expect_err("must reject");
        assert!(err.contains("openbao response is not JSON"), "{err}");
    }

    #[test]
    fn surfaces_the_errors_array_on_a_non_2xx() {
        // The shape a real OpenBao 403 carries. Losing this text is what
        // makes a permissions problem look like an outage.
        let err = read(403, r#"{"errors":["permission denied"]}"#).expect_err("must reject");
        assert!(err.contains("403"), "{err}");
        assert!(err.contains("permission denied"), "{err}");
    }

    #[test]
    fn an_empty_errors_array_falls_back_to_the_bare_status() {
        // OpenBao returns `{"errors":[]}` for a 404 on an unmounted path.
        // Reporting `openbao returned 404: []` would be worse than nothing.
        let err = read(404, r#"{"errors":[]}"#).expect_err("must reject");
        assert_eq!(err, "openbao returned 404");
    }

    #[test]
    fn a_non_json_error_body_falls_back_to_the_bare_status() {
        let err = read(502, "<html>bad gateway</html>").expect_err("must reject");
        assert_eq!(err, "openbao returned 502");
    }

    // -- token posture and renewal timing ------------------------------------

    #[test]
    fn reads_the_posture_out_of_a_lookup_reply() {
        let posture = TokenPosture::from_lookup(&serde_json::json!({
            "data": { "renewable": true, "ttl": 60, "policies": ["whip-smoke"] }
        }));
        assert_eq!(
            posture,
            TokenPosture {
                renewable: true,
                ttl_secs: 60
            }
        );
    }

    #[test]
    fn reads_the_posture_out_of_a_renew_reply() {
        // `renew-self` reports the fresh lease under a different key than
        // `lookup-self` does; reading the wrong one silently yields ttl 0.
        let posture = TokenPosture::from_renew(&serde_json::json!({
            "auth": { "renewable": true, "lease_duration": 60 }
        }));
        assert_eq!(
            posture,
            TokenPosture {
                renewable: true,
                ttl_secs: 60
            }
        );
    }

    #[test]
    fn a_dev_root_token_reads_as_nothing_to_renew() {
        // ttl 0, renewable false — the posture that must not start a thread.
        let posture = TokenPosture::from_lookup(&serde_json::json!({
            "data": { "renewable": false, "ttl": 0, "policies": ["root"] }
        }));
        assert_eq!(posture.ttl_secs, 0);
        assert!(
            spawn_token_renewal(Arc::new(Client::new("http://127.0.0.1:1", "t")), posture)
                .is_none()
        );
    }

    #[test]
    fn a_reply_missing_the_fields_reads_as_not_renewable() {
        let posture = TokenPosture::from_lookup(&serde_json::json!({ "data": {} }));
        assert_eq!(
            posture,
            TokenPosture {
                renewable: false,
                ttl_secs: 0
            }
        );
        assert_eq!(TokenPosture::from_renew(&serde_json::Value::Null), posture);
    }

    #[test]
    fn a_renewable_token_with_no_lease_left_starts_no_thread() {
        let posture = TokenPosture {
            renewable: true,
            ttl_secs: 0,
        };
        assert!(
            spawn_token_renewal(Arc::new(Client::new("http://127.0.0.1:1", "t")), posture)
                .is_none()
        );
    }

    #[test]
    fn renews_at_half_the_remaining_lease_within_bounds() {
        assert_eq!(renew_interval(3600), Duration::from_secs(1800));
        // Floored: a 6-second lease must not spin the loop.
        assert_eq!(
            renew_interval(6),
            Duration::from_secs(MIN_RENEW_INTERVAL_SECS)
        );
        assert_eq!(
            renew_interval(0),
            Duration::from_secs(MIN_RENEW_INTERVAL_SECS)
        );
        // Capped: a 30-day lease still checks in hourly.
        assert_eq!(
            renew_interval(30 * 24 * 3600),
            Duration::from_secs(MAX_RENEW_INTERVAL_SECS)
        );
    }
}
