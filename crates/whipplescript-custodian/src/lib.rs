//! The WhippleScript credential custodian (DR-0053).
//!
//! A second security principal: it holds sealed material and performs the
//! closed operation vocabulary — substitute at marked slots, sign through a
//! derivation chain, verify in constant time, derive, wrap/unwrap, mint. It
//! is deliberately semantically dumb (§3): it never parses payloads, chooses
//! endpoints, or knows what an API is. whip constructs everything; the
//! custodian substitutes where the sentinel marks and refuses everything
//! else.
//!
//! There is no `get(handle)` here and no function that returns entry
//! material across the protocol boundary. `Unwrap` is the one operation that
//! returns plaintext, and what it returns is *application data* whip wrapped
//! earlier — never credential material (§13).

pub mod egress;
pub mod serve;
pub mod store;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use whipplescript_custody::{
    CredentialKind, CredentialName, CustodyCall, CustodyError, CustodyOk, CustodyOp, CustodyReply,
    CustodyTransport, EgressRequest, EgressResponse, Envelope, MintExtraction, Operation,
    PresentationForm, Rung, Sentinel, SignatureAlg, TransportError, UseAttribution,
    CUSTODY_PROTOCOL,
};

use store::{SealedStore, StoreError};

// ---------------------------------------------------------------------------
// Egress
// ---------------------------------------------------------------------------

/// Network egress the custodian performs after substitution (`request`) or
/// for a credential exchange (`mint`). A trait so the custody engine tests
/// against a double and the real HTTP client arrives with the `call`
/// construct build.
pub trait Egress: Send + Sync {
    fn perform(&self, request: &EgressRequest) -> Result<EgressResponse, String>;
}

impl<T: Egress + ?Sized> Egress for std::sync::Arc<T> {
    fn perform(&self, request: &EgressRequest) -> Result<EgressResponse, String> {
        (**self).perform(request)
    }
}

/// Default egress until a real client is wired: refuses everything. Refusing
/// loudly beats a mock quietly succeeding — an unwired custodian must not
/// look like a working one.
pub struct DeniedEgress;

impl Egress for DeniedEgress {
    fn perform(&self, _request: &EgressRequest) -> Result<EgressResponse, String> {
        Err("egress is not enabled in this custodian".to_string())
    }
}

// ---------------------------------------------------------------------------
// Use records
// ---------------------------------------------------------------------------

/// Every call — refusals included — is recorded (§1: attributable;
/// `UsesAreRecorded` in `CredentialCustody.tla`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UseRecord {
    pub use_id: String,
    pub credential: String,
    pub operation: Operation,
    pub attribution: UseAttribution,
    pub rung: Rung,
    pub degraded: bool,
    /// `"ok"` or the refusal's kebab-case tag.
    pub outcome: String,
    pub at_epoch_s: u64,
}

// ---------------------------------------------------------------------------
// The custodian
// ---------------------------------------------------------------------------

pub struct Custodian {
    store: Mutex<SealedStore>,
    uses: Mutex<Vec<UseRecord>>,
    use_counts: Mutex<BTreeMap<CredentialName, u64>>,
    egress: Box<dyn Egress>,
    rng: SystemRandom,
}

fn now_epoch_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Custodian {
    pub fn new(store: SealedStore, egress: Box<dyn Egress>) -> Self {
        Self {
            store: Mutex::new(store),
            uses: Mutex::new(Vec::new()),
            use_counts: Mutex::new(BTreeMap::new()),
            egress,
            rng: SystemRandom::new(),
        }
    }

    /// The rung this custodian's backend seals at, with the degraded tag. r0
    /// is always degraded (DR-0053 §4: dev only, tagged) — the tag is derived
    /// from what the backend *is*, never from configuration
    /// (`credential-rung-evidence.maude`: configuration is not evidence).
    pub fn rung(&self) -> (Rung, bool) {
        (Rung::Process, true)
    }

    /// Admin surface, reachable only in-process by the principal holding the
    /// store passphrase — never over the custody protocol.
    pub fn register(
        &self,
        name: CredentialName,
        kind: CredentialKind,
        material: Zeroizing<Vec<u8>>,
        budget: Option<u64>,
    ) -> Result<(), StoreError> {
        lock(&self.store).register(name, kind, material, budget)
    }

    pub fn revoke(&self, name: &CredentialName) -> Result<bool, StoreError> {
        lock(&self.store).revoke(name)
    }

    pub fn list(&self) -> Vec<(CredentialName, CredentialKind, bool)> {
        lock(&self.store)
            .entries()
            .iter()
            .map(|(n, e)| (n.clone(), e.kind, e.revoked))
            .collect()
    }

    pub fn uses(&self) -> Vec<UseRecord> {
        lock(&self.uses).clone()
    }

    fn fresh_id(&self, prefix: &str) -> String {
        let mut bytes = [0u8; 8];
        // rng.fill only fails on catastrophic platform RNG loss; a
        // non-unique id is preferable to refusing all service.
        let _ = self.rng.fill(&mut bytes);
        let mut s = String::with_capacity(prefix.len() + 1 + 16);
        s.push_str(prefix);
        s.push('-');
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// Handle one protocol call. Always replies; every reply is recorded.
    pub fn handle(&self, call: &CustodyCall) -> CustodyReply {
        let (rung, degraded) = self.rung();
        let use_id = self.fresh_id("use");
        let outcome = if call.protocol == CUSTODY_PROTOCOL {
            self.dispatch(&call.op)
        } else {
            Err(CustodyError::Backend {
                detail: format!("unsupported protocol {:?}", call.protocol),
            })
        };
        let record = UseRecord {
            use_id: use_id.clone(),
            credential: call.op.credential().as_str().to_string(),
            operation: call.op.operation(),
            attribution: call.attribution.clone(),
            rung,
            degraded,
            outcome: match &outcome {
                Ok(_) => "ok".to_string(),
                Err(e) => error_tag(e).to_string(),
            },
            at_epoch_s: now_epoch_s(),
        };
        lock(&self.uses).push(record);
        CustodyReply {
            use_id,
            rung,
            degraded,
            outcome,
        }
    }

    fn dispatch(&self, op: &CustodyOp) -> Result<CustodyOk, CustodyError> {
        let name = op.credential().clone();
        let operation = op.operation();

        // Admission: existence, revocation, kind support, budget — checked
        // under the store lock, then material is cloned out (zeroizing) so
        // crypto work does not hold the lock.
        let (kind, material, budget) = {
            let store = lock(&self.store);
            let entry = store
                .get(&name)
                .ok_or_else(|| CustodyError::UnknownCredential {
                    credential: name.clone(),
                })?;
            if entry.revoked {
                return Err(CustodyError::Revoked { credential: name });
            }
            if !entry.kind.supports(operation) {
                return Err(CustodyError::KindMismatch {
                    credential: name,
                    kind: entry.kind,
                    operation,
                });
            }
            (
                entry.kind,
                Zeroizing::new(entry.material.to_vec()),
                entry.budget,
            )
        };
        if let Some(budget) = budget {
            let mut counts = lock(&self.use_counts);
            let count = counts.entry(name.clone()).or_insert(0);
            if *count >= budget {
                return Err(CustodyError::BudgetExhausted { credential: name });
            }
            *count += 1;
        }

        match op {
            CustodyOp::Request { request, .. } => self.op_request(&name, kind, &material, request),
            CustodyOp::Sign {
                alg,
                derivation,
                payload_b64,
                ..
            } => op_sign(kind, &material, *alg, derivation, payload_b64),
            CustodyOp::Verify {
                alg,
                payload_b64,
                signature_b64,
                ..
            } => op_verify(kind, &material, *alg, payload_b64, signature_b64),
            CustodyOp::Derive { context, .. } => self.op_derive(&name, kind, &material, context),
            CustodyOp::Wrap {
                plaintext_b64,
                label,
                context,
                ..
            } => self.op_wrap(&name, &material, plaintext_b64, label, context),
            CustodyOp::Unwrap {
                envelope, context, ..
            } => op_unwrap(&name, &material, envelope, context),
            CustodyOp::Mint {
                scope,
                ttl_secs,
                exchange,
                extraction,
                ..
            } => self.op_mint(&name, &material, scope, *ttl_secs, exchange, extraction),
        }
    }

    // -- request ------------------------------------------------------------

    fn op_request(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
        material: &[u8],
        request: &EgressRequest,
    ) -> Result<CustodyOk, CustodyError> {
        let substituted = substitute_request(name, kind, material, request)?;
        let response = self
            .egress
            .perform(&substituted)
            .map_err(|detail| CustodyError::EgressFailed { detail })?;
        Ok(CustodyOk::Requested { response })
    }

    // -- derive -------------------------------------------------------------

    fn op_derive(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
        material: &[u8],
        context: &str,
    ) -> Result<CustodyOk, CustodyError> {
        let sub = hkdf_expand(material, context.as_bytes())?;
        let digest = ring::digest::digest(&ring::digest::SHA256, context.as_bytes());
        let tag: String = digest.as_ref()[..4]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let derived_name = CredentialName::new(&format!("{}/hkdf-{tag}", name.as_str()))
            .map_err(|detail| CustodyError::Backend { detail })?;
        // The derived subkey signs; it does not present. Parent kinds that
        // sign keep signing, everything else derives a raw subkey.
        let derived_kind = match kind {
            CredentialKind::HmacSha256 | CredentialKind::AwsSigv4 => CredentialKind::HmacSha256,
            _ => CredentialKind::Raw,
        };
        lock(&self.store)
            .register(derived_name.clone(), derived_kind, sub, None)
            .map_err(|e| CustodyError::Backend {
                detail: e.to_string(),
            })?;
        Ok(CustodyOk::Derived {
            credential: derived_name,
        })
    }

    // -- wrap ---------------------------------------------------------------

    fn op_wrap(
        &self,
        name: &CredentialName,
        material: &[u8],
        plaintext_b64: &str,
        label: &serde_json::Value,
        context: &str,
    ) -> Result<CustodyOk, CustodyError> {
        let mut buf = decode_b64(plaintext_b64)?;
        let key = wrapping_key(material)?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        self.rng
            .fill(&mut nonce_bytes)
            .map_err(|_| CustodyError::Backend {
                detail: "rng failure".into(),
            })?;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(wrap_aad(name, context, label)),
            &mut buf,
        )
        .map_err(|_| CustodyError::Backend {
            detail: "seal failure".into(),
        })?;
        Ok(CustodyOk::Wrapped {
            envelope: Envelope {
                credential: name.clone(),
                context: context.to_string(),
                label: label.clone(),
                nonce_b64: B64.encode(nonce_bytes),
                ciphertext_b64: B64.encode(&buf),
            },
        })
    }

    // -- mint ---------------------------------------------------------------

    fn op_mint(
        &self,
        name: &CredentialName,
        material: &[u8],
        _scope: &[String],
        ttl_secs: u64,
        exchange: &EgressRequest,
        extraction: &MintExtraction,
    ) -> Result<CustodyOk, CustodyError> {
        // The exchange request is whip's, with sentinels for the parent
        // credential; the custodian substitutes and executes it so the token
        // never appears in whip's address space (DR-0053 *Open*: OAuth
        // response capture).
        let parent_kind = CredentialKind::Bearer;
        let substituted = substitute_request(name, parent_kind, material, exchange)?;
        let response = self
            .egress
            .perform(&substituted)
            .map_err(|detail| CustodyError::EgressFailed { detail })?;
        let body = response
            .body_b64
            .as_deref()
            .map(decode_b64)
            .transpose()?
            .unwrap_or_default();
        let body: serde_json::Value =
            serde_json::from_slice(&body).map_err(|e| CustodyError::EgressFailed {
                detail: format!("exchange response is not JSON: {e}"),
            })?;

        let token = dotted_path(&body, &extraction.token_path)
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or_else(|| CustodyError::EgressFailed {
                detail: format!(
                    "exchange response has no string at {:?}",
                    extraction.token_path
                ),
            })?;
        let digest = ring::digest::digest(&ring::digest::SHA256, token.as_bytes());
        let fingerprint: String = digest.as_ref()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let minted_name = CredentialName::new(&format!("{}/mint-{fingerprint}", name.as_str()))
            .map_err(|detail| CustodyError::Backend { detail })?;
        lock(&self.store)
            .register(
                minted_name.clone(),
                CredentialKind::Bearer,
                Zeroizing::new(token.into_bytes()),
                None,
            )
            .map_err(|e| CustodyError::Backend {
                detail: e.to_string(),
            })?;
        let _ = ttl_secs; // r0 records no expiry; lease enforcement arrives with lifecycle verbs.

        let mut public = serde_json::Map::new();
        for path in &extraction.public_paths {
            if let Some(v) = dotted_path(&body, path) {
                public.insert(path.clone(), v.clone());
            }
        }
        Ok(CustodyOk::Minted {
            credential: minted_name,
            fingerprint,
            public: serde_json::Value::Object(public),
        })
    }
}

// ---------------------------------------------------------------------------
// Pure operation helpers
// ---------------------------------------------------------------------------

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn error_tag(e: &CustodyError) -> &'static str {
    match e {
        CustodyError::UnknownCredential { .. } => "unknown-credential",
        CustodyError::KindMismatch { .. } => "kind-mismatch",
        CustodyError::OperationNotGranted { .. } => "operation-not-granted",
        CustodyError::ScopeRefused { .. } => "scope-refused",
        CustodyError::RungBelowFloor { .. } => "rung-below-floor",
        CustodyError::Revoked { .. } => "revoked",
        CustodyError::BudgetExhausted { .. } => "budget-exhausted",
        CustodyError::EnvelopeRefused => "envelope-refused",
        CustodyError::EgressFailed { .. } => "egress-failed",
        CustodyError::Backend { .. } => "backend",
    }
}

fn decode_b64(s: &str) -> Result<Vec<u8>, CustodyError> {
    B64.decode(s).map_err(|e| CustodyError::Backend {
        detail: format!("bad base64: {e}"),
    })
}

/// Presentation of material at a marked slot (DR-0053 §5).
fn present(form: PresentationForm, material: &[u8]) -> Result<String, CustodyError> {
    let as_text = || {
        std::str::from_utf8(material)
            .map(str::to_string)
            .map_err(|_| CustodyError::Backend {
                detail: "material is not textual".into(),
            })
    };
    match form {
        PresentationForm::Bearer => Ok(format!("Bearer {}", as_text()?)),
        PresentationForm::Basic => Ok(format!("Basic {}", B64.encode(material))),
        PresentationForm::Raw => as_text(),
    }
}

/// Substitute this credential's sentinels throughout the request. A sentinel
/// naming a *different* credential is a refusal (one call, one handle); a
/// request with *no* marked slot is a refusal too — a request that does not
/// use the credential has no business spending a use of it. This is the
/// dynamic edge of the static `unmarked` check
/// (`credential-no-eliminator.maude`).
fn substitute_request(
    name: &CredentialName,
    _kind: CredentialKind,
    material: &[u8],
    request: &EgressRequest,
) -> Result<EgressRequest, CustodyError> {
    let mut marked = 0usize;
    let mut substitute_text = |text: &str| -> Result<String, CustodyError> {
        let found = Sentinel::find_all(text).map_err(|detail| CustodyError::ScopeRefused {
            credential: name.clone(),
            detail,
        })?;
        let mut out = String::with_capacity(text.len());
        let mut at = 0usize;
        for (range, sentinel) in found {
            if sentinel.credential != *name {
                return Err(CustodyError::ScopeRefused {
                    credential: name.clone(),
                    detail: format!(
                        "request carries a slot for a different credential ({})",
                        sentinel.credential
                    ),
                });
            }
            out.push_str(&text[at..range.start]);
            out.push_str(&present(sentinel.form, material)?);
            at = range.end;
            marked += 1;
        }
        out.push_str(&text[at..]);
        Ok(out)
    };

    let mut headers = Vec::with_capacity(request.headers.len());
    for (k, v) in &request.headers {
        headers.push((k.clone(), substitute_text(v)?));
    }
    let url = substitute_text(&request.url)?;
    let body_b64 = match &request.body_b64 {
        None => None,
        Some(b64) => {
            let bytes = decode_b64(b64)?;
            match std::str::from_utf8(&bytes) {
                Ok(text) => Some(B64.encode(substitute_text(text)?)),
                // A binary body cannot carry a textual sentinel; pass through.
                Err(_) => Some(b64.clone()),
            }
        }
    };
    if marked == 0 {
        return Err(CustodyError::ScopeRefused {
            credential: name.clone(),
            detail: "request has no marked slot for this credential".into(),
        });
    }
    Ok(EgressRequest {
        method: request.method.clone(),
        url,
        headers,
        body_b64,
    })
}

/// AWS SigV4's initial key is `"AWS4" || secret` (§7). That prefix is keyed
/// key-preparation, not protocol knowledge, so it lives here with the kind.
fn initial_hmac_key(kind: CredentialKind, material: &[u8]) -> Vec<u8> {
    match kind {
        CredentialKind::AwsSigv4 => {
            let mut k = Vec::with_capacity(4 + material.len());
            k.extend_from_slice(b"AWS4");
            k.extend_from_slice(material);
            k
        }
        _ => material.to_vec(),
    }
}

fn op_sign(
    kind: CredentialKind,
    material: &[u8],
    alg: SignatureAlg,
    derivation: &[String],
    payload_b64: &str,
) -> Result<CustodyOk, CustodyError> {
    let payload = decode_b64(payload_b64)?;
    let signature =
        match alg {
            SignatureAlg::HmacSha256 => {
                let mut key = Zeroizing::new(initial_hmac_key(kind, material));
                for step in derivation {
                    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
                    key = Zeroizing::new(ring::hmac::sign(&k, step.as_bytes()).as_ref().to_vec());
                }
                let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key);
                ring::hmac::sign(&k, &payload).as_ref().to_vec()
            }
            SignatureAlg::Ed25519 => {
                if !derivation.is_empty() {
                    return Err(CustodyError::Backend {
                        detail: "ed25519 does not take a derivation chain".into(),
                    });
                }
                let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(material)
                    .map_err(|_| CustodyError::Backend {
                        detail: "material is not an ed25519 seed".into(),
                    })?;
                keypair.sign(&payload).as_ref().to_vec()
            }
            SignatureAlg::RsaSha256 => {
                let keypair = ring::signature::RsaKeyPair::from_pkcs8(material).map_err(|_| {
                    CustodyError::Backend {
                        detail: "material is not a pkcs8 rsa key".into(),
                    }
                })?;
                let rng = SystemRandom::new();
                let mut sig = vec![0u8; keypair.public().modulus_len()];
                keypair
                    .sign(&ring::signature::RSA_PKCS1_SHA256, &rng, &payload, &mut sig)
                    .map_err(|_| CustodyError::Backend {
                        detail: "rsa signing failed".into(),
                    })?;
                sig
            }
        };
    Ok(CustodyOk::Signed {
        signature_b64: B64.encode(signature),
    })
}

fn op_verify(
    kind: CredentialKind,
    material: &[u8],
    alg: SignatureAlg,
    payload_b64: &str,
    signature_b64: &str,
) -> Result<CustodyOk, CustodyError> {
    let payload = decode_b64(payload_b64)?;
    let signature = decode_b64(signature_b64)?;
    let valid = match alg {
        SignatureAlg::HmacSha256 => {
            // ring's hmac::verify is the constant-time comparison DR-0053 §6
            // requires to live in the custodian.
            let key = ring::hmac::Key::new(
                ring::hmac::HMAC_SHA256,
                &Zeroizing::new(initial_hmac_key(kind, material)),
            );
            ring::hmac::verify(&key, &payload, &signature).is_ok()
        }
        SignatureAlg::Ed25519 => {
            let keypair =
                ring::signature::Ed25519KeyPair::from_seed_unchecked(material).map_err(|_| {
                    CustodyError::Backend {
                        detail: "material is not an ed25519 seed".into(),
                    }
                })?;
            use ring::signature::KeyPair as _;
            let public = ring::signature::UnparsedPublicKey::new(
                &ring::signature::ED25519,
                keypair.public_key().as_ref(),
            );
            public.verify(&payload, &signature).is_ok()
        }
        SignatureAlg::RsaSha256 => {
            return Err(CustodyError::Backend {
                detail: "rsa verification is done against the public key in whip, not here".into(),
            })
        }
    };
    Ok(CustodyOk::Verified { valid })
}

fn hkdf_expand(material: &[u8], info: &[u8]) -> Result<Zeroizing<Vec<u8>>, CustodyError> {
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &[]);
    let prk = salt.extract(material);
    let info_parts = [info];
    let okm = prk
        .expand(&info_parts, ring::hkdf::HKDF_SHA256)
        .map_err(|_| CustodyError::Backend {
            detail: "hkdf expand failed".into(),
        })?;
    let mut out = Zeroizing::new(vec![0u8; 32]);
    okm.fill(out.as_mut()).map_err(|_| CustodyError::Backend {
        detail: "hkdf fill failed".into(),
    })?;
    Ok(out)
}

/// The wrapping key is an HKDF subkey of the credential, so wrap/unwrap
/// never uses raw material directly as an AEAD key.
fn wrapping_key(material: &[u8]) -> Result<LessSafeKey, CustodyError> {
    let sub = hkdf_expand(material, b"whipplescript-custody-wrap-v1")?;
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &sub).map_err(|_| CustodyError::Backend {
        detail: "bad wrap key".into(),
    })?;
    Ok(LessSafeKey::new(unbound))
}

/// AEAD associated data for an envelope: credential identity, the caller's
/// context, and the carried label. Binding all three means a ciphertext
/// produced for one context never opens in another even with every label
/// intact (§13; `credential-wrap-carriage.maude` `-UNBOUND`).
fn wrap_aad(name: &CredentialName, context: &str, label: &serde_json::Value) -> Vec<u8> {
    // serde_json maps are BTreeMap-backed here (preserve_order is off), so
    // this serialization is canonical for equal labels.
    format!(
        "{}\n{}\n{}",
        name.resource_id(),
        context,
        serde_json::to_string(label).unwrap_or_default()
    )
    .into_bytes()
}

fn op_unwrap(
    name: &CredentialName,
    material: &[u8],
    envelope: &Envelope,
    context: &str,
) -> Result<CustodyOk, CustodyError> {
    if envelope.credential != *name {
        // A different credential does not open the envelope; saying so by
        // name is fine — which credential a caller *asked for* is not secret.
        return Err(CustodyError::EnvelopeRefused);
    }
    let key = wrapping_key(material)?;
    let nonce_bytes: [u8; NONCE_LEN] = decode_b64(&envelope.nonce_b64)?
        .try_into()
        .map_err(|_| CustodyError::EnvelopeRefused)?;
    let mut buf = decode_b64(&envelope.ciphertext_b64)?;
    // The associated data is rebuilt from the *caller's* context and the
    // envelope's recorded label: a cross-context unwrap fails AEAD rather
    // than a string comparison.
    let plain_len = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(wrap_aad(name, context, &envelope.label)),
            &mut buf,
        )
        .map_err(|_| CustodyError::EnvelopeRefused)?
        .len();
    buf.truncate(plain_len);
    Ok(CustodyOk::Unwrapped {
        plaintext_b64: B64.encode(&buf),
        label: envelope.label.clone(),
    })
}

fn dotted_path<'v>(value: &'v serde_json::Value, path: &str) -> Option<&'v serde_json::Value> {
    let mut at = value;
    for seg in path.split('.') {
        at = at.get(seg)?;
    }
    Some(at)
}

// ---------------------------------------------------------------------------
// In-process transport
// ---------------------------------------------------------------------------

/// The r0 transport: in-process, but it still speaks the wire protocol —
/// calls and replies make a full JSON roundtrip, so the seam r1+ swaps in
/// behind is exercised on every call rather than bypassed by direct function
/// calls (tracker slice 1: principal separation, not encryption, is what
/// makes custody real).
pub struct InProcessTransport {
    custodian: std::sync::Arc<Custodian>,
}

impl InProcessTransport {
    pub fn new(custodian: std::sync::Arc<Custodian>) -> Self {
        Self { custodian }
    }
}

impl CustodyTransport for InProcessTransport {
    fn call(&self, call: CustodyCall) -> Result<CustodyReply, TransportError> {
        let wire = serde_json::to_string(&call)
            .map_err(|e| TransportError::Protocol(format!("unserializable call: {e}")))?;
        let call: CustodyCall = serde_json::from_str(&wire)
            .map_err(|e| TransportError::Protocol(format!("malformed call: {e}")))?;
        if call.protocol != CUSTODY_PROTOCOL {
            return Err(TransportError::Protocol(format!(
                "unsupported protocol {:?}",
                call.protocol
            )));
        }
        let reply = self.custodian.handle(&call);
        let wire = serde_json::to_string(&reply)
            .map_err(|e| TransportError::Protocol(format!("unserializable reply: {e}")))?;
        serde_json::from_str(&wire)
            .map_err(|e| TransportError::Protocol(format!("malformed reply: {e}")))
    }
}
