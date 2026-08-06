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

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use zeroize::Zeroizing;

use whipplescript_custody::CredentialKind;

/// Per-request timeout. Transit calls are small; anything slower than this is
/// an outage, not a slow sign.
const REQUEST_TIMEOUT_SECS: u64 = 30;

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
    /// through `/v1/transit/sign/{key}`. Returns the raw signature/MAC bytes
    /// parsed out of OpenBao's `vault:v1:<base64>` format.
    pub fn transit_sign(
        &self,
        key: &str,
        input: &[u8],
        kind: CredentialKind,
    ) -> Result<Vec<u8>, String> {
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
    /// answer is "invalid". The raw bytes are re-encoded as `vault:v1:…`, so
    /// verification is pinned to key version 1 — key rotation support is not
    /// part of r3 v1.
    pub fn transit_verify(
        &self,
        key: &str,
        input: &[u8],
        sig_or_mac: &[u8],
        kind: CredentialKind,
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
                field: format!("vault:v1:{}", B64.encode(sig_or_mac)),
            }),
        )?;
        value["data"]["valid"]
            .as_bool()
            .ok_or_else(|| "openbao response carries no data.valid".to_string())
    }

    // -- token lifecycle ----------------------------------------------------

    /// `GET /v1/auth/token/lookup-self` — the daemon-start liveness and
    /// posture probe.
    pub fn token_lookup_self(&self) -> Result<serde_json::Value, String> {
        self.get_json("/v1/auth/token/lookup-self")
    }

    /// `POST /v1/auth/token/renew-self` — keeps a renewable token alive
    /// across a long-running daemon.
    pub fn token_renew_self(&self) -> Result<(), String> {
        self.post_json("/v1/auth/token/renew-self", &serde_json::json!({}))?;
        Ok(())
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
fn parse_vault_encoded(s: &str) -> Result<Vec<u8>, String> {
    let rest = s
        .strip_prefix("vault:")
        .ok_or_else(|| format!("not a vault-encoded value: {s:?}"))?;
    let (_version, b64) = rest
        .split_once(':')
        .ok_or_else(|| format!("malformed vault-encoded value: {s:?}"))?;
    B64.decode(b64)
        .map_err(|e| format!("bad base64 in vault-encoded value: {e}"))
}
