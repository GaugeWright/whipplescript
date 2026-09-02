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
pub mod openbao;
// The daemon's listener is a Unix domain socket by construction — the 0o600
// socket *is* the authority boundary (§4), not an implementation detail — so
// it compiles only where that transport exists, exactly as the protocol
// crate's client half does. Sealing, the operation vocabulary, and the store
// are portable and stay compiled everywhere.
pub mod pkcs11;
#[cfg(feature = "pkcs11")]
pub mod pkcs11_device;
#[cfg(target_family = "unix")]
pub mod serve;
pub mod store;
pub mod tpm;
#[cfg(feature = "tpm")]
pub mod tpm_device;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
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

use store::{Material, SealedStore, StoreError};

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
    /// The r3 remote backend, when the daemon configured one from
    /// `BAO_ADDR`/`BAO_TOKEN`. A remote entry used without a client is a
    /// loud refusal, never a silent local fallback.
    /// Shared because the daemon's token-renewal thread holds the same
    /// client: renewal is a property of the connection, not of any one call.
    openbao: Option<Arc<openbao::Client>>,
    /// Per-credential signing bounds; see `with_sign_prefixes`.
    sign_prefixes: BTreeMap<CredentialName, Vec<Vec<u8>>>,
    rng: SystemRandom,
}

pub fn now_epoch_s() -> u64 {
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
            openbao: None,
            sign_prefixes: BTreeMap::new(),
            rng: SystemRandom::new(),
        }
    }

    /// Bound what a credential may SIGN, by literal payload prefix (DR-0053 §14
    /// Amendment 2026-08-29).
    ///
    /// Configured at the daemon rather than read from whip's governance, for
    /// the same reason the egress allow-list is: the bound has to hold against
    /// a fully compromised whip, and a bound whip supplies is one whip can
    /// choose. The two are the same shape — governance checks at compile time,
    /// the custodian enforces at use time, and neither is the other's backup.
    ///
    /// Absent means UNBOUND, matching the egress allow-list's shape only in
    /// spelling: there, absence denies everything. Here it admits, because
    /// every existing deployment signs without prefixes and a custodian that
    /// refused them on upgrade would take the tree down rather than tighten it.
    /// Naming a credential is what opts it in.
    pub fn with_sign_prefixes(mut self, prefixes: BTreeMap<CredentialName, Vec<Vec<u8>>>) -> Self {
        self.sign_prefixes = prefixes;
        self
    }

    /// Attach an r3 OpenBao transit client (built by the daemon from
    /// `BAO_ADDR`/`BAO_TOKEN`). Only remote entries route through it; local
    /// entries keep the in-process path.
    pub fn with_openbao(mut self, client: Arc<openbao::Client>) -> Self {
        self.openbao = Some(client);
        self
    }

    /// The rung this custodian's *local* sealing sits at, with the degraded
    /// tag. r0 is always degraded (DR-0053 §4: dev only, tagged) — the tag is
    /// derived from what the backend *is*, never from configuration
    /// (`credential-rung-evidence.maude`: configuration is not evidence).
    /// Per-call replies derive the rung from the entry actually touched
    /// ([`Self::entry_rung`]): remote entries report r3, not this floor.
    pub fn rung(&self) -> (Rung, bool) {
        (Rung::Process, true)
    }

    /// The rung/degraded pair for the entry a call touches — evidence is
    /// where the *material* is, so it is per-entry, not per-custodian: an
    /// OpenBao transit entry's material never exists on this box (r3, not
    /// degraded), while a local entry stays r0 degraded. An unknown entry
    /// reports the local floor; the refusal in the outcome says the rest.
    fn entry_rung(&self, name: &CredentialName) -> (Rung, bool) {
        match lock(&self.store).get(name).map(|e| &e.material) {
            Some(Material::OpenBaoTransit { .. }) => (Rung::Remote, false),
            // r2, and NOT degraded: the key was generated inside the chip and
            // cannot leave it. Freshness is judged at the use rather than here,
            // because this answers "what rung is this entry" and a moved
            // platform makes the operation refuse, not the rung shrink.
            Some(Material::TpmHmac { .. }) => (Rung::Hardware, false),
            // r2 as well, and for the same reason the TPM entry is: nothing was
            // admitted here that the token did not say never left. Registration
            // refuses a key whose attributes fall short, so an entry that
            // exists has already cleared the bar — and every use re-asks, in
            // case the token's answer changed.
            Some(Material::Pkcs11 { .. }) => (Rung::Hardware, false),
            _ => self.rung(),
        }
    }

    /// r2 over PKCS#11: route a keyed operation to the token, re-checking that
    /// its key still evidences the rung.
    ///
    /// The attributes are re-read at every use rather than trusted from
    /// registration. A token can be re-provisioned under a custodian that is
    /// still running, and an entry recorded when the key was resident should
    /// not keep claiming r2 for a key that has since been made extractable.
    /// That is the same question the TPM path asks of the platform state, in
    /// the terms this backend has.
    fn dispatch_pkcs11(
        &self,
        name: &CredentialName,
        reference: &crate::store::Pkcs11Ref,
        admitted: &crate::pkcs11::KeyAttributes,
        op: &CustodyOp,
    ) -> Result<CustodyOk, CustodyError> {
        match op {
            CustodyOp::Sign { payload_b64, .. } => {
                self.admits_sign(name, payload_b64)?;
                let mac = self.pkcs11_mac(name, reference, admitted, payload_b64)?;
                Ok(CustodyOk::Signed {
                    signature_b64: B64.encode(mac),
                    key_version: None,
                })
            }
            CustodyOp::Verify {
                alg,
                payload_b64,
                signature_b64,
                ..
            } => {
                crate::tpm::verifiable_alg(*alg)
                    .map_err(|detail| CustodyError::Backend { detail })?;
                // The MAC helper returns BYTES rather than an outcome, so
                // verification has no "the token answered a sign with something
                // else" branch to write — an error nothing can produce is a
                // refusal nothing gates.
                let computed = self.pkcs11_mac(name, reference, admitted, payload_b64)?;
                let presented = decode_b64(signature_b64)?;
                Ok(CustodyOk::Verified {
                    valid: crate::tpm::mac_matches(&computed, &presented),
                })
            }
            other => Err(CustodyError::Backend {
                detail: format!(
                    "credential {name} is held on a PKCS#11 token, which performs `sign` and `verify` and nothing else here: `{}` needs material this box does not have",
                    other.operation().as_str()
                ),
            }),
        }
    }

    #[cfg(feature = "pkcs11")]
    fn pkcs11_mac(
        &self,
        name: &CredentialName,
        reference: &crate::store::Pkcs11Ref,
        admitted: &crate::pkcs11::KeyAttributes,
        payload_b64: &str,
    ) -> Result<Vec<u8>, CustodyError> {
        let payload = decode_b64(payload_b64)?;
        let backend = |detail: String| CustodyError::Backend { detail };
        let module = crate::pkcs11_device::module(&reference.module).map_err(backend)?;
        let slot =
            crate::pkcs11_device::slot_with_token(&module, &reference.token).map_err(backend)?;
        let pin = std::env::var(crate::pkcs11::PIN_ENV).map_err(|_| CustodyError::Backend {
            detail: format!(
                "credential {name} is on a PKCS#11 token and {} is not set, so the custodian cannot log in",
                crate::pkcs11::PIN_ENV
            ),
        })?;
        let session = crate::pkcs11_device::session(&module, slot, &pin).map_err(backend)?;
        let (key, current) =
            crate::pkcs11_device::admitted_key(&session, &reference.key).map_err(backend)?;
        crate::pkcs11::still_admitted(name.as_str(), admitted, &current).map_err(backend)?;
        crate::pkcs11_device::hmac_sha256(&session, key, &payload).map_err(backend)
    }

    #[cfg(not(feature = "pkcs11"))]
    fn pkcs11_mac(
        &self,
        name: &CredentialName,
        _reference: &crate::store::Pkcs11Ref,
        _admitted: &crate::pkcs11::KeyAttributes,
        _payload_b64: &str,
    ) -> Result<Vec<u8>, CustodyError> {
        Err(CustodyError::Backend {
            detail: format!(
                "credential {name} is held on a PKCS#11 token, and this custodian was built without the `pkcs11` feature: rebuild with `--features pkcs11` on a host that has the vendor module"
            ),
        })
    }

    /// r2: route a keyed operation to the TPM, after checking the rung still
    /// holds.
    ///
    /// **Freshness is checked HERE, at the use**, not at registration. A
    /// binding taken at registration says what the platform was then; the
    /// question every signature asks is what it is NOW. Checking once at
    /// registration would make r2 a claim about the past.
    ///
    /// A stale binding REFUSES rather than falling back to a lower rung. The
    /// key is unreachable anyway — the material for this credential exists only
    /// inside the chip — so a "downgrade" would be inventing a credential that
    /// does not exist, and silence about a moved platform is exactly what §4
    /// says a rung must not do.
    fn dispatch_tpm(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
        binding: &crate::tpm::PcrBinding,
        op: &CustodyOp,
    ) -> Result<CustodyOk, CustodyError> {
        let _ = kind;
        match op {
            CustodyOp::Sign { payload_b64, .. } => {
                self.admits_sign(name, payload_b64)?;
                self.tpm_sign(name, binding, payload_b64)
            }
            // Verification recomputes the MAC with the SAME key, which is in
            // the chip, so it belongs here rather than on the local path — the
            // local path has no material to verify against. No signing bound is
            // consulted: `grant sign ... for prefix` limits what a key may
            // PRODUCE, and checking a signature produces nothing.
            CustodyOp::Verify {
                alg,
                payload_b64,
                signature_b64,
                ..
            } => {
                crate::tpm::verifiable_alg(*alg)
                    .map_err(|detail| CustodyError::Backend { detail })?;
                self.tpm_verify(name, binding, payload_b64, signature_b64)
            }
            other => Err(CustodyError::Backend {
                detail: format!(
                    "credential {name} is held in a TPM, which performs `sign` and `verify` and nothing else here: `{}` needs material this box does not have",
                    other.operation().as_str()
                ),
            }),
        }
    }

    #[cfg(feature = "tpm")]
    fn tpm_sign(
        &self,
        name: &CredentialName,
        binding: &crate::tpm::PcrBinding,
        payload_b64: &str,
    ) -> Result<CustodyOk, CustodyError> {
        let payload = decode_b64(payload_b64)?;
        let mut context =
            crate::tpm_device::context().map_err(|detail| CustodyError::Backend { detail })?;
        let current = crate::tpm_device::read_binding(&mut context, &binding.slots)
            .map_err(|detail| CustodyError::Backend { detail })?;
        crate::tpm::ensure_fresh(name.as_str(), binding, &current)
            .map_err(|detail| CustodyError::Backend { detail })?;
        let signature = crate::tpm_device::hmac_sha256(&mut context, name.as_str(), &payload)
            .map_err(|detail| CustodyError::Backend { detail })?;
        Ok(CustodyOk::Signed {
            signature_b64: B64.encode(signature),
            key_version: None,
        })
    }

    #[cfg(feature = "tpm")]
    fn tpm_verify(
        &self,
        name: &CredentialName,
        binding: &crate::tpm::PcrBinding,
        payload_b64: &str,
        signature_b64: &str,
    ) -> Result<CustodyOk, CustodyError> {
        let payload = decode_b64(payload_b64)?;
        let presented = decode_b64(signature_b64)?;
        let mut context =
            crate::tpm_device::context().map_err(|detail| CustodyError::Backend { detail })?;
        let current = crate::tpm_device::read_binding(&mut context, &binding.slots)
            .map_err(|detail| CustodyError::Backend { detail })?;
        // Freshness gates verification too. A platform that moved cannot
        // recompute the same MAC anyway — the key derives from a seed bound to
        // it — so reporting `valid: false` would blame the signature for a
        // platform change, which is the most misleading answer available.
        crate::tpm::ensure_fresh(name.as_str(), binding, &current)
            .map_err(|detail| CustodyError::Backend { detail })?;
        let computed = crate::tpm_device::hmac_sha256(&mut context, name.as_str(), &payload)
            .map_err(|detail| CustodyError::Backend { detail })?;
        Ok(CustodyOk::Verified {
            valid: crate::tpm::mac_matches(&computed, &presented),
        })
    }

    #[cfg(not(feature = "tpm"))]
    fn tpm_verify(
        &self,
        name: &CredentialName,
        _binding: &crate::tpm::PcrBinding,
        _payload_b64: &str,
        _signature_b64: &str,
    ) -> Result<CustodyOk, CustodyError> {
        Err(CustodyError::Backend {
            detail: format!(
                "credential {name} is held in a TPM, and this custodian was built without the `tpm` feature: rebuild with `--features tpm` on a host that has the tss2 stack"
            ),
        })
    }

    /// The same entry point in a custodian built without the `tpm` feature.
    ///
    /// A store is portable: an entry registered by a TPM-enabled custodian can
    /// be opened by one built without it. Refusing by name beats a panic or a
    /// "no such credential" — the credential exists, this binary simply cannot
    /// reach the chip that holds it.
    #[cfg(not(feature = "tpm"))]
    fn tpm_sign(
        &self,
        name: &CredentialName,
        _binding: &crate::tpm::PcrBinding,
        _payload_b64: &str,
    ) -> Result<CustodyOk, CustodyError> {
        Err(CustodyError::Backend {
            detail: format!(
                "credential {name} is held in a TPM, and this custodian was built without the `tpm` feature: rebuild with `--features tpm` on a host that has the tss2 stack"
            ),
        })
    }

    /// Admin surface, reachable only in-process by the principal holding the
    /// store passphrase — never over the custody protocol.
    pub fn register(
        &self,
        name: CredentialName,
        kind: CredentialKind,
        material: Zeroizing<Vec<u8>>,
        budget: Option<u64>,
        lease_expires_at: Option<u64>,
    ) -> Result<(), StoreError> {
        lock(&self.store).register(name, kind, material, budget, lease_expires_at)
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
        let (rung, degraded) = self.entry_rung(call.op.credential());
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

        // Container operations act on a vault rather than on an existing
        // credential, so they run BEFORE the admission block below: a
        // `Generate` has no entry to look up, and a `Revoke` ends an entry
        // whatever kind it holds. Running them through the member path would
        // fail `UnknownCredential` on the one operation whose whole purpose is
        // that the credential does not exist yet.
        // Matched STRUCTURALLY rather than through `is_container()`, so the
        // compiler enforces the split instead of a runtime arm asserting it. A
        // classifier here would need an impossible-state branch, which is a
        // refusal no test can reach and so a refusal nothing gates.
        match op {
            CustodyOp::Generate {
                credential: _,
                kind,
            } => return self.op_generate(&name, *kind),
            CustodyOp::Register {
                kind, material_b64, ..
            } => return self.op_register(&name, *kind, material_b64),
            CustodyOp::Revoke { .. } => return self.op_revoke(&name),
            // `Rotate` deliberately does NOT return here. It needs an entry
            // that exists and is not revoked — exactly the two admissions
            // below — so routing it through them means one implementation of
            // those refusals rather than a second copy inside a handler.
            CustodyOp::Rotate { .. }
            | CustodyOp::Deliver { .. }
            | CustodyOp::Request { .. }
            | CustodyOp::Sign { .. }
            | CustodyOp::Verify { .. }
            | CustodyOp::Derive { .. }
            | CustodyOp::Wrap { .. }
            | CustodyOp::Unwrap { .. }
            | CustodyOp::Mint { .. } => {}
        }

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
            // The lease, checked beside revocation because it IS revocation —
            // the kind nobody had to perform. Before the kind check, so an
            // expired credential says so rather than complaining about an
            // operation it would refuse anyway.
            if let Some(expired_at) = entry.lease_expires_at {
                if now_epoch_s() >= expired_at {
                    return Err(CustodyError::LeaseExpired {
                        credential: name,
                        expired_at,
                    });
                }
            }
            // A container operation acts on the entry's identity rather than
            // exercising its key, so no kind performs it and asking would
            // refuse every rotation. Existence and revocation still apply.
            if !operation.is_container() && !entry.kind.supports(operation) {
                return Err(CustodyError::KindMismatch {
                    credential: name,
                    kind: entry.kind,
                    operation,
                });
            }
            (entry.kind, entry.material.clone(), entry.budget)
        };
        if let Some(budget) = budget {
            let mut counts = lock(&self.use_counts);
            let count = counts.entry(name.clone()).or_insert(0);
            if *count >= budget {
                return Err(CustodyError::BudgetExhausted { credential: name });
            }
            *count += 1;
        }

        // r3 remote entries route keyed operations to the OpenBao transit
        // engine; the material never exists in this process.
        let material = match &material {
            Material::OpenBaoTransit { key_name } => {
                return self.dispatch_remote(&name, kind, key_name, op)
            }
            // r2: the key is in the TPM and signs there. Routed before the
            // local path for the same reason r3 is — there is no material in
            // this process to hand the local operations.
            Material::TpmHmac { binding } => return self.dispatch_tpm(&name, kind, binding, op),
            Material::Pkcs11 {
                reference,
                admitted,
            } => return self.dispatch_pkcs11(&name, reference, admitted, op),
            Material::Local(material) => Zeroizing::new(material.to_vec()),
        };

        match op {
            CustodyOp::Request { request, slots, .. } => {
                self.op_request(&name, kind, &material, request, *slots)
            }
            CustodyOp::Deliver { request, slots, .. } => {
                self.op_deliver(&name, kind, &material, request, *slots)
            }
            CustodyOp::Sign {
                alg,
                derivation,
                payload_b64,
                ..
            } => {
                self.admits_sign(&name, payload_b64)?;
                op_sign(kind, &material, *alg, derivation, payload_b64)
            }
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
            // Returned above, before admission — a container operation has no
            // entry to load material from. Listed rather than wildcarded so a
            // future container op is a compile error here rather than a silent
            // fall-through, and `unreachable!` rather than an `Err` because an
            // error nothing can produce is a refusal nothing gates.
            // A local entry holds exactly one material, so a successor would
            // REPLACE its predecessor and break every outstanding signature —
            // the opposite of the dual validity §12 asks for. Refused by name
            // rather than silently replacing.
            CustodyOp::Rotate { .. } => Err(CustodyError::Backend {
                detail: format!(
                    "credential {name} is sealed locally and cannot rotate: a local entry holds \
                     one material, so a successor would replace its predecessor rather than sit \
                     beside it. rotation needs the r3 remote rung"
                ),
            }),
            // Returned above, before admission. Listed rather than wildcarded
            // so a future container op is a compile error here, and
            // `unreachable!` rather than an `Err` because an error nothing can
            // produce is a refusal nothing gates.
            CustodyOp::Generate { .. } | CustodyOp::Register { .. } | CustodyOp::Revoke { .. } => {
                unreachable!("generate and revoke return before member admission")
            }
            CustodyOp::Mint {
                exchange,
                extraction,
                exchange_slots,
                ..
            } => self.op_mint(&name, &material, exchange, extraction, *exchange_slots),
        }
    }

    // -- r3 remote (OpenBao transit) ----------------------------------------

    /// Dispatch for an entry whose material lives in an OpenBao transit
    /// engine. Transit performs keyed signing and verification; everything
    /// else in the vocabulary would need the material here, which is exactly
    /// what r3 exists to prevent — so the rest refuses, by name.
    fn dispatch_remote(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
        key_name: &str,
        op: &CustodyOp,
    ) -> Result<CustodyOk, CustodyError> {
        let client = self.openbao.as_ref().ok_or_else(|| CustodyError::Backend {
            detail: "no OpenBao connection configured (BAO_ADDR/BAO_TOKEN)".into(),
        })?;
        match op {
            // Transit keeps every prior key version, so a rotation here IS the
            // dual validity §12 asks for — which holds only because a
            // signature now carries the version it was made under.
            CustodyOp::Rotate { .. } => {
                let version = client
                    .transit_rotate(key_name)
                    .map_err(|detail| CustodyError::Backend { detail })?;
                Ok(CustodyOk::Rotated {
                    credential: name.clone(),
                    version,
                })
            }
            CustodyOp::Sign {
                alg,
                derivation,
                payload_b64,
                ..
            } => {
                remote_alg_admitted(name, kind, *alg, op.operation())?;
                if !derivation.is_empty() {
                    return Err(CustodyError::Backend {
                        detail: "r3 transit does not support derivation chains: the chain folds \
                                 HMAC over the raw key, which never leaves the transit engine"
                            .into(),
                    });
                }
                self.admits_sign(name, payload_b64)?;
                let payload = decode_b64(payload_b64)?;
                let (key_version, signature) = client
                    .transit_sign(key_name, &payload, kind)
                    .map_err(|detail| CustodyError::Backend { detail })?;
                Ok(CustodyOk::Signed {
                    signature_b64: B64.encode(signature),
                    // Reported so the verifier can name the same version. A
                    // signature that does not say which key made it can only be
                    // checked against a guess.
                    key_version: Some(key_version),
                })
            }
            CustodyOp::Verify {
                alg,
                payload_b64,
                signature_b64,
                key_version,
                ..
            } => {
                remote_alg_admitted(name, kind, *alg, op.operation())?;
                let payload = decode_b64(payload_b64)?;
                let signature = decode_b64(signature_b64)?;
                let valid = client
                    .transit_verify(
                        key_name,
                        &payload,
                        &signature,
                        kind,
                        // Absent means "the version this key started at",
                        // which is the pre-rotation behaviour made explicit
                        // rather than hard-coded a layer down.
                        key_version.unwrap_or(1),
                    )
                    .map_err(|detail| CustodyError::Backend { detail })?;
                Ok(CustodyOk::Verified { valid })
            }
            _ => Err(CustodyError::Backend {
                detail: format!(
                    "{} on a remote credential is not supported at r3 transit yet",
                    op.operation()
                ),
            }),
        }
    }

    // -- request ------------------------------------------------------------

    fn op_request(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
        material: &[u8],
        request: &EgressRequest,
        declared_slots: usize,
    ) -> Result<CustodyOk, CustodyError> {
        let (substituted, secrets) =
            substitute_request(name, kind, material, request, declared_slots)?;
        let response = self
            .egress
            .perform(&substituted)
            .map_err(|detail| CustodyError::EgressFailed { detail })?;
        // Redact on the way back. The caller cannot: whip is designed never to
        // know the material, so it cannot recognise it, and this is the only
        // place that holds both the material and the response.
        Ok(CustodyOk::Requested {
            response: secrets.scrub_response(response, name),
        })
    }

    /// Hand the credential to a recipient, and RECORD that it happened.
    ///
    /// Mechanically `op_request`: the same substitution, the same allow-list,
    /// the same sentinel-count defence. Two things differ, and both are the
    /// reason this is its own operation.
    ///
    /// The GRANT is separate — spending a credential and giving it away are
    /// different authorities, and one grant covering both would have made every
    /// existing `request` grant a handoff grant retroactively.
    ///
    /// The RECORD is the point. DR-0053 §5 states the reaping rule as "reap
    /// what was never handed off" and deliberately did not build it, because
    /// until something performs a handoff there is nothing for the rule to
    /// read. This writes that fact, so `retain instance` can stop reaping a key
    /// that already reached CI.
    ///
    /// The response is scrubbed like any other, and here that is not belt and
    /// braces: an endpoint that echoes its request body would otherwise hand
    /// the credential straight back into whip's run record, and for `deliver`
    /// the body IS the credential.
    fn op_deliver(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
        material: &[u8],
        request: &EgressRequest,
        declared_slots: usize,
    ) -> Result<CustodyOk, CustodyError> {
        let (substituted, secrets) =
            substitute_request(name, kind, material, request, declared_slots)?;
        let response = self
            .egress
            .perform(&substituted)
            .map_err(|detail| CustodyError::EgressFailed { detail })?;
        // Recorded only on a response the recipient actually gave: a handoff
        // that failed to egress did not happen, and marking it would tell the
        // reaper to spare a credential nobody received.
        let handed_off_at = now_epoch_s();
        // A handoff that the store could not record is a handoff nobody can
        // prove: the credential HAS reached the recipient, and reporting
        // success while the reaper still believes it never left would revoke a
        // live key. Failing loudly is the honest answer — the operator can see
        // that the delivery happened and the record did not.
        if let Err(error) = lock(&self.store).mark_delivered(name, handed_off_at) {
            // Bound rather than constructed inline: `unrecordable_handoff` is
            // where the decision and its words live and where they are tested,
            // so this line FORWARDS a refusal rather than being one. That also
            // keeps the sweep's account of this file honest — a call inside
            // `Err(...)` is a site it cannot mutate.
            let refusal = unrecordable_handoff(name, &error.to_string());
            return Err(refusal);
        }
        Ok(CustodyOk::Delivered {
            response: secrets.scrub_response(response, name),
            handed_off_at,
        })
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
            .register(derived_name.clone(), derived_kind, sub, None, None)
            .map_err(|e| CustodyError::Backend {
                detail: e.to_string(),
            })?;
        Ok(CustodyOk::Derived {
            credential: derived_name,
        })
    }

    /// Refuse a payload that begins with none of a credential's granted
    /// prefixes (DR-0053 §14 Amendment 2026-08-29).
    ///
    /// Enforced on BOTH signing paths — local and r3 remote — because a bound
    /// that held only on one would be a bound an operator could not reason
    /// about, and the remote rung is the production one.
    ///
    /// A credential the configuration does not name is unbounded. Naming one is
    /// what opts it in, which is what keeps this from breaking every deployment
    /// that signs today.
    fn admits_sign(&self, name: &CredentialName, payload_b64: &str) -> Result<(), CustodyError> {
        let Some(prefixes) = self.sign_prefixes.get(name) else {
            return Ok(());
        };
        let payload = decode_b64(payload_b64)?;
        if whipplescript_custody::sign_prefix::admits(prefixes, &payload) {
            return Ok(());
        }
        Err(CustodyError::Backend {
            detail: format!(
                "credential {name} may not sign this payload: it begins with none of the \
                 configured prefixes. a signing oracle bounded to one protocol cannot produce \
                 another's"
            ),
        })
    }

    // -- container operations -------------------------------------------------

    /// Create sealed material and register it in one act (DR-0053 §2/§5
    /// Amendments). Returns the handle, never the material.
    ///
    /// **Refuses an existing name.** `Store::register` is an upsert, which is
    /// right for the admin surface an operator drives deliberately — and wrong
    /// here, where a generated name arrives from a running program. A silent
    /// overwrite would destroy a live credential and hand back a handle that
    /// looks identical, so the collision is an error.
    fn op_generate(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
    ) -> Result<CustodyOk, CustodyError> {
        // Not `KindMismatch`: that variant says a CREDENTIAL's kind cannot
        // perform an operation, and here the credential does not exist yet —
        // naming one that is not there would be a misuse of the shape. The
        // refusal is about the kind alone, and saying so in words also makes it
        // measurable: the mutation sweep perturbs a refusal's message, so a
        // message-less typed variant is a refusal no sweep can reach.
        let Some(bytes) = generatable_key_len(kind) else {
            return Err(CustodyError::Backend {
                detail: format!(
                    "credential kind {kind} cannot be generated: its material is issued by a \
                     third party, so `obtain credential` is its path rather than `generate`"
                ),
            });
        };
        let mut material = Zeroizing::new(vec![0u8; bytes]);
        self.rng
            .fill(material.as_mut_slice())
            .map_err(|_| CustodyError::Backend {
                detail: "rng failure".into(),
            })?;
        let mut store = lock(&self.store);
        if store.get(name).is_some() {
            return Err(CustodyError::Backend {
                detail: format!("credential {name} already exists"),
            });
        }
        store
            .register(name.clone(), kind, material, None, None)
            .map_err(|e| CustodyError::Backend {
                detail: e.to_string(),
            })?;
        Ok(CustodyOk::Generated {
            credential: name.clone(),
            kind,
        })
    }

    /// Take material whip already holds into custody (DR-0053 §15 Amendment).
    ///
    /// Refuses an existing name for the same reason `generate` does:
    /// `Store::register` is an upsert, which is right for an operator driving
    /// the admin surface and wrong for a name arriving from a running program.
    /// Silently replacing a live credential with an ingressed one would be
    /// worse here than for generate, because the replacement is material a
    /// third party supplied.
    ///
    /// Empty material is refused. A registration that took custody of nothing
    /// would hand back a handle that signs and verifies as though it meant
    /// something.
    fn op_register(
        &self,
        name: &CredentialName,
        kind: CredentialKind,
        material_b64: &str,
    ) -> Result<CustodyOk, CustodyError> {
        let material = Zeroizing::new(decode_b64(material_b64)?);
        if material.is_empty() {
            return Err(CustodyError::Backend {
                detail: format!(
                    "credential {name} was registered with no material: a handle to nothing \
                     would sign and verify as though it meant something"
                ),
            });
        }
        let mut store = lock(&self.store);
        if store.get(name).is_some() {
            return Err(CustodyError::Backend {
                detail: format!("credential {name} already exists"),
            });
        }
        store
            .register(name.clone(), kind, material, None, None)
            .map_err(|e| CustodyError::Backend {
                detail: e.to_string(),
            })?;
        Ok(CustodyOk::Registered {
            credential: name.clone(),
        })
    }

    /// End a credential. `existed: false` is a successful call whose answer is
    /// "there was nothing to revoke".
    fn op_revoke(&self, name: &CredentialName) -> Result<CustodyOk, CustodyError> {
        let existed = lock(&self.store)
            .revoke(name)
            .map_err(|e| CustodyError::Backend {
                detail: e.to_string(),
            })?;
        Ok(CustodyOk::Revoked { existed })
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

    // The parameters are the wire op's fields, one for one; bundling them into a
    // struct here would only re-describe `CustodyOp::Mint`.
    #[allow(clippy::too_many_arguments)]
    fn op_mint(
        &self,
        name: &CredentialName,
        material: &[u8],
        exchange: &EgressRequest,
        extraction: &MintExtraction,
        exchange_slots: usize,
    ) -> Result<CustodyOk, CustodyError> {
        // The exchange request is whip's, with sentinels for the parent
        // credential; the custodian substitutes and executes it so the token
        // never appears in whip's address space (DR-0053 *Open*: OAuth
        // response capture).
        let parent_kind = CredentialKind::Bearer;
        // Deliberately unscrubbed: this response is parsed for the minted
        // token and never handed back to whip, and scrubbing could corrupt a
        // token that happens to contain the parent's text.
        let (substituted, _secrets) =
            substitute_request(name, parent_kind, material, exchange, exchange_slots)?;
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
                // A minted token often carries its own expiry in the exchange
                // response, which §5's amendment deliberately does NOT model:
                // whip gives up policing a vendor scope it cannot verify. A
                // lease invented here would be whip asserting a lifetime the
                // vendor never agreed to.
                None,
            )
            .map_err(|e| CustodyError::Backend {
                detail: e.to_string(),
            })?;

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
        CustodyError::LeaseExpired { .. } => "lease-expired",
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

/// Admission for a keyed operation on an r3 transit entry: only
/// HMAC-SHA-256 keys with alg `hmac-sha256` and Ed25519 keys with alg
/// `ed25519` are supported remotely. Anything else — RSA, AWS SigV4 key
/// preparation, or an alg that does not match the key — refuses with a
/// message naming r3 transit, not a generic crypto error.
fn remote_alg_admitted(
    name: &CredentialName,
    kind: CredentialKind,
    alg: SignatureAlg,
    operation: Operation,
) -> Result<(), CustodyError> {
    match (kind, alg) {
        (CredentialKind::HmacSha256, SignatureAlg::HmacSha256)
        | (CredentialKind::Ed25519, SignatureAlg::Ed25519) => Ok(()),
        (CredentialKind::HmacSha256, _) | (CredentialKind::Ed25519, _) => {
            // The key could serve, but this call's alg does not match it.
            Err(CustodyError::KindMismatch {
                credential: name.clone(),
                kind,
                operation,
            })
        }
        _ => Err(CustodyError::Backend {
            detail: format!(
                "r3 transit does not support {operation} for kind {kind}: only hmac-sha256 and \
                 ed25519 keys operate remotely"
            ),
        }),
    }
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
///
/// `declared_slots` is how many slots the constructing program says it placed,
/// and a disagreement with what is found here is a refusal. Slots are located
/// by scanning finished request text, which cannot distinguish one the author
/// wrote from one that arrived inside an interpolated value; without the
/// declaration, data that reached a header, URL or body could mint a slot and
/// have real material substituted into a position the author never designated
/// — with `PresentationForm::Raw` placing the bare secret there. The count is
/// the authority on how many slots are legitimate, not the text. It detects
/// rather than prevents: data can add an occurrence but cannot remove the
/// author's, so any injection makes the totals disagree and the call refuses.
/// The strings a substitution put on the wire, so they can be taken back out of
/// the response.
///
/// This exists because whip cannot do it. whip is designed never to know the
/// material, so it cannot recognise it in order to redact it — the custodian is
/// the only party that holds the material AND sees the response. Found
/// 2026-08-26 by pointing a `request` at an endpoint that echoes the
/// `Authorization` header: the request whip built was clean, and the material
/// came back from OUTSIDE and landed in whip's run record.
#[derive(Debug, Default)]
struct WireSecrets {
    /// Longest first, so `Bearer <material>` is replaced before `<material>`
    /// and a redaction cannot leave a dangling fragment of a longer match.
    fragments: Vec<String>,
}

impl WireSecrets {
    fn add(&mut self, fragment: String) {
        if fragment.is_empty() || self.fragments.contains(&fragment) {
            return;
        }
        self.fragments.push(fragment);
        self.fragments.sort_by_key(|value| usize::MAX - value.len());
    }

    /// Redact every known fragment from `text`.
    fn scrub(&self, text: &str, name: &CredentialName) -> String {
        let mut out = text.to_owned();
        for fragment in &self.fragments {
            if out.contains(fragment.as_str()) {
                out = out.replace(fragment.as_str(), &format!("[redacted {}]", name.as_str()));
            }
        }
        out
    }

    /// Redact from a whole response: header values and a textual body.
    ///
    /// Header NAMES are not scrubbed — a name is not material, and rewriting
    /// one would corrupt the response shape for no gain. A binary body passes
    /// through: it cannot carry the textual form that was substituted in, and
    /// re-encoding it would be a lie about what arrived.
    fn scrub_response(&self, response: EgressResponse, name: &CredentialName) -> EgressResponse {
        if self.fragments.is_empty() {
            return response;
        }
        EgressResponse {
            status: response.status,
            headers: response
                .headers
                .into_iter()
                .map(|(key, value)| (key, self.scrub(&value, name)))
                .collect(),
            body_b64: response.body_b64.map(|encoded| {
                match decode_b64(&encoded)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok())
                {
                    Some(text) => B64.encode(self.scrub(&text, name)),
                    None => encoded,
                }
            }),
        }
    }
}

fn substitute_request(
    name: &CredentialName,
    _kind: CredentialKind,
    material: &[u8],
    request: &EgressRequest,
    declared_slots: usize,
) -> Result<(EgressRequest, WireSecrets), CustodyError> {
    let mut marked = 0usize;
    let mut secrets = WireSecrets::default();
    // The material itself, in the encodings a presentation can put it in. An
    // endpoint may echo the whole header (`Bearer sk_…`) or just the token, so
    // both are recorded and the longest is replaced first.
    if let Ok(text) = std::str::from_utf8(material) {
        secrets.add(text.to_owned());
    }
    secrets.add(B64.encode(material));
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
            let presented = present(sentinel.form, material)?;
            secrets.add(presented.clone());
            out.push_str(&presented);
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
    if marked != declared_slots {
        return Err(CustodyError::ScopeRefused {
            credential: name.clone(),
            detail: format!(
                "request carries {marked} credential slot(s) but the caller declared \
                 {declared_slots} — a slot the program did not place may have arrived \
                 in interpolated data"
            ),
        });
    }
    Ok((
        EgressRequest {
            method: request.method.clone(),
            url,
            headers,
            body_b64,
        },
        secrets,
    ))
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
        // A local key has one version and no way to name others, so there is
        // nothing honest to report. `None` says exactly that, rather than
        // claiming a version number the backend does not have.
        key_version: None,
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
/// How many random bytes a kind's material is, or `None` if the kind cannot be
/// generated at all (DR-0053 §5 Amendment 2026-08-29).
///
/// The split is not a judgement call — it follows from who issues the material.
/// `bearer` is an opaque token a third party issues TO us and `aws-sigv4`'s
/// secret comes from IAM, so neither can be conjured here; §11's
/// `obtain credential` is the path for those.
///
/// `basic` is deliberately absent from v1. We could generate the password half,
/// but a `basic` credential is a PAIR and the username is not ours to invent,
/// so generating one would produce a credential that authenticates to nothing.
/// What an operator is told when a delivery succeeded and its record did not.
///
/// A function rather than a `map_err` closure, and not for tidiness: a refusal
/// built inside `map_err` is not an `Err(` construction, so the mutation sweep
/// does not see it AT ALL — it is not reported as unmeasured, it is simply not
/// a site. The gate passes and the refusal is unpinned, which is worse than
/// being told it is unpinned.
///
/// The message has to carry the asymmetry: the credential HAS reached the
/// recipient and cannot be recalled, so the failure is the record's. Reporting
/// success would leave a reaper believing the key never left, and it would
/// revoke a live one.
pub fn unrecordable_handoff_detail(name: &CredentialName, error: &str) -> String {
    match unrecordable_handoff(name, error) {
        CustodyError::Backend { detail } => detail,
        other => other.to_string(),
    }
}

fn unrecordable_handoff(name: &CredentialName, error: &str) -> CustodyError {
    CustodyError::Backend {
        detail: format!(
            "credential {name} reached its recipient but the handoff could not be recorded \
             ({error}), so a reaper would still treat it as never delivered"
        ),
    }
}

fn generatable_key_len(kind: CredentialKind) -> Option<usize> {
    // WHICH kinds can be generated is `CredentialKind::is_generatable`, in the
    // vocabulary crate, because the language asks the same question when it
    // admits a `generate` grant. Only HOW MANY BYTES is decided here: that is
    // the custodian's business and nothing else needs to know it.
    //
    // Ed25519 seeds are 32 bytes and the public half is derived from them;
    // `raw` and `hmac-sha256` are random bytes with both ends ours.
    kind.is_generatable().then_some(32)
}

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
