//! The two-agent privilege separation (DR-0028 D5).
//!
//! The **governance agent** is the only path that may SIGN a governance envelope,
//! and it is gated by admin/sudo privilege (G1, G4). The **whip agent** — the rest
//! of the CLI — is unprivileged and may only *verify* a signed envelope, never
//! produce one via `SignedEnvelope::sign` (which refuses without governance
//! privilege).
//!
//! ## Trust model (be honest about which path is cryptographic)
//!
//! The legacy attestation here is a **keyless SHA-256 integrity checksum of the
//! canonical envelope content**, NOT a cryptographic signature. It detects
//! *tampering* (mutating the content breaks the hash), but it authenticates no
//! author: anyone who can WRITE the envelope file can recompute the same hash and
//! produce a byte-valid attestation, and the `signer` field is outside the hashed
//! bytes. So on the native path the "single-signer" guarantee rests on **OS file
//! permissions of `WHIPPLESCRIPT_IFC_ENVELOPE`** (only the privileged operator can
//! write it) — a documented local-trust assumption, not a keyed proof. The policy
//! epoch is likewise not covered by this checksum.
//!
//! The **authenticated** path — the one that resists a compromised host / an
//! untrusted envelope — is the external **P-256** signature verified in
//! `whipplescript-host-do::governance`, which binds signer + key + algorithm +
//! content hash cryptographically (and the epoch, on that path). Any consumer
//! crossing a real trust boundary must use that verifier, not the checksum.
//! (v0.1 documents this posture; folding signer+epoch into the native hashed
//! bytes and persisting an epoch floor are deferred hardening — see
//! spec/information-flow-governance.md.)

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::ifc::Envelope;

/// Whether the current process holds governance (admin) privilege (G1) — the
/// **degraded** dev shim.
///
/// DR-0053 §10: an environment variable is not an authority boundary once
/// escape is in the threat model — an escaped agent can set it and grant
/// itself the credentials custody protects. The authority path is therefore
/// the **custodian**: governance signing keys are custodian-held and admin is
/// the `sign` capability on the governance credential
/// ([`SignedEnvelope::sign_with_custodian`] /
/// [`CustodianEnvelopeVerifier`]), bounded by the custodian socket's OS
/// permissions and the custodian's own grants. This env-token gate remains
/// only for CI and dev sandboxes where no custodian runs; every path through
/// it produces the keyless checksum attestation, which trusts the local
/// filesystem and must be labelled degraded, never presented as the custody
/// claim.
pub fn has_governance_privilege() -> bool {
    std::env::var_os("WHIPPLESCRIPT_GOV_ADMIN").is_some()
}

/// The conventional custodian entry for governance signing. Admin = whoever
/// the custodian lets `sign` with this credential; the resource identity is
/// stable across sealing backends (DR-0053 §5).
pub const GOVERNANCE_SIGNING_CREDENTIAL: &str = "whip/governance-signing";

/// The attestation algorithm tag for custodian-held governance keys.
pub const GOVERNANCE_CUSTODIAN_ALGORITHM: &str = "ed25519-custodian";

pub(crate) fn hash_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Canonicalize a governance config (DSL or JSON) to the stable signed-artifact
/// JSON, so its hash is deterministic.
pub fn canonicalize(config_text: &str) -> Result<String, String> {
    let envelope = if config_text.trim_start().starts_with('{') {
        Envelope::from_json(config_text)?
    } else {
        Envelope::from_dsl(config_text)?
    };
    let canonical = envelope.to_canonical_json();
    debug_assert_lossless(&envelope, &canonical);
    Ok(canonical)
}

/// The canonical form is what a governance signature covers, so anything this
/// function drops is silently outside the signature: the field parses, the
/// envelope behaves correctly in memory, and the check that rests on it passes
/// vacuously once the document is signed and reloaded.
///
/// That is not hypothetical. It has taken four arms of DR-0063 — `authority`,
/// `requires_authority`, §8's `exposes`/`attachments`, and `policy_lifetime` —
/// each of which parsed correctly and then vanished at signing, taking its check
/// with it. A hand-maintained list of arms is no defence, because forgetting to
/// extend the list is exactly as easy as forgetting to extend the emitter.
///
/// So the property is total and mechanical: reparsing the canonical form must
/// reproduce the envelope it came from. Any field the emitter does not write
/// fails here, including fields nobody has thought of yet. Envelopes are
/// normalized at parse rather than at emit, which is what makes the comparison
/// exact instead of modulo ordering.
///
/// Debug-only: the cost is one reparse per canonicalization, and every test that
/// signs, verifies, or composes anything exercises it for free.
#[cfg(debug_assertions)]
fn debug_assert_lossless(envelope: &Envelope, canonical: &str) {
    match Envelope::from_json(canonical) {
        Ok(reparsed) => assert!(
            reparsed == *envelope,
            "canonicalization is LOSSY: reparsing the canonical form does not \
             reproduce the envelope. A field is parsed but not emitted, so it is \
             outside what the signature covers. Add it to \
             `Envelope::to_canonical_json` and to the reader on both parse paths."
        ),
        Err(error) => panic!("the canonical form does not reparse: {error}"),
    }
}

#[cfg(not(debug_assertions))]
fn debug_assert_lossless(_envelope: &Envelope, _canonical: &str) {}

/// A signed governance envelope: the canonical content + an attestation binding
/// its hash to the signer.
pub struct SignedEnvelope {
    pub canonical: String,
    pub envelope_hash: String,
    pub signer: String,
    external: Option<ExternalAttestation>,
}

/// The identity proven by a successfully verified envelope attestation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAttestation {
    pub envelope_hash: String,
    pub signer: String,
    /// The external governance key that signed the envelope. `None` only for
    /// the legacy root-only CLI governance agent.
    pub key_id: Option<String>,
    /// The policy epoch the signature COVERS, present only under the `:v2`
    /// preimage. `None` means the epoch is not authenticated by this envelope,
    /// so nothing may rest on it (DR-0063 §5).
    pub epoch: Option<u64>,
    /// The authority the envelope speaks for, present only under `:v2`.
    pub authority: Option<String>,
}

/// A cryptographic attestation supplied by an embedding governance authority.
///
/// `epoch` and `authority` are the `:v2` preimage's additions (DR-0063 §5).
/// Both present selects `:v2`; both absent selects `:v1`, which stays valid on
/// the single-envelope path. Exactly one present is malformed and refused
/// rather than silently downgraded — a half-stated v2 is how an epoch would
/// come to look signed without being.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalAttestation {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
    pub epoch: Option<u64>,
    pub authority: Option<String>,
}

/// Cryptographic agility seam for embedding governance authorities.
///
/// WhippleScript defines the canonical bytes and refuses an externally signed
/// envelope unless this verifier accepts them. GaugeDesk implements this with
/// its existing P-256 governance root; another host may use a KMS/HSM without
/// changing WhippleScript's envelope or IFC semantics.
pub trait GovernanceAttestationVerifier {
    fn verify(&self, signing_bytes: &[u8], attestation: &ExternalAttestation)
        -> Result<(), String>;
}

impl SignedEnvelope {
    /// Sign a governance config. PRIVILEGED (G1/G4): fails without governance
    /// privilege, so only the governance agent reaches a successful sign.
    pub fn sign(config_text: &str, signer: &str) -> Result<Self, String> {
        Self::sign_with_privilege(config_text, signer, has_governance_privilege())
    }

    /// Sign with the privilege decision injected (so the gate is testable without
    /// mutating process env). `whip` always passes `has_governance_privilege()`.
    fn sign_with_privilege(
        config_text: &str,
        signer: &str,
        privileged: bool,
    ) -> Result<Self, String> {
        if !privileged {
            return Err(
                "signing a governance envelope requires admin/governance privilege \
                 — run via the governance agent (sudo)"
                    .to_owned(),
            );
        }
        let canonical = canonicalize(config_text)?;
        let envelope_hash = hash_hex(&canonical);
        Ok(Self {
            canonical,
            envelope_hash,
            signer: signer.to_owned(),
            external: None,
        })
    }

    /// Assemble an envelope signed by an external governance authority. This
    /// does not itself confer trust: consumers must use
    /// [`verify_attestation_with`](Self::verify_attestation_with), which invokes
    /// their pinned verifier. The signature must cover
    /// [`external_signing_bytes`].
    pub fn from_external_signature(
        config_text: &str,
        signer: &str,
        algorithm: &str,
        key_id: &str,
        signature: &str,
    ) -> Result<Self, String> {
        if signer.trim().is_empty()
            || algorithm.trim().is_empty()
            || key_id.trim().is_empty()
            || signature.trim().is_empty()
        {
            return Err("external governance attestation is incomplete".to_owned());
        }
        let canonical = canonicalize(config_text)?;
        let envelope_hash = hash_hex(&canonical);
        Ok(Self {
            canonical,
            envelope_hash,
            signer: signer.to_owned(),
            external: Some(ExternalAttestation {
                algorithm: algorithm.to_owned(),
                key_id: key_id.to_owned(),
                signature: signature.to_owned(),
                epoch: None,
                authority: None,
            }),
        })
    }

    /// Assemble an envelope signed under the `:v2` preimage (DR-0063 §5), which
    /// also covers the policy `epoch` and the `authority` the envelope speaks
    /// for. The signature must cover [`external_signing_bytes_v2`]. A composed
    /// set admits only this form; `from_external_signature` remains the
    /// single-envelope path.
    pub fn from_external_signature_v2(
        config_text: &str,
        signer: &str,
        algorithm: &str,
        key_id: &str,
        signature: &str,
        epoch: u64,
        authority: &str,
    ) -> Result<Self, String> {
        if authority.trim().is_empty() {
            return Err("a :v2 governance attestation requires an authority".to_owned());
        }
        let mut envelope =
            Self::from_external_signature(config_text, signer, algorithm, key_id, signature)?;
        if let Some(external) = envelope.external.as_mut() {
            external.epoch = Some(epoch);
            external.authority = Some(authority.to_owned());
        }
        Ok(envelope)
    }

    /// Sign through the custodian (DR-0053 §10): the governance signing key
    /// is custodian-held, so holding admin means the custodian's policy lets
    /// this caller `sign` with the governance credential — an authority
    /// bounded by the custodian socket's OS permissions rather than an
    /// environment variable. Produces an external-attestation envelope whose
    /// `key_id` is the credential's stable resource identity; verify it with
    /// [`CustodianEnvelopeVerifier`].
    pub fn sign_with_custodian(
        config_text: &str,
        signer: &str,
        transport: &dyn whipplescript_custody::CustodyTransport,
        credential: &whipplescript_custody::CredentialName,
    ) -> Result<Self, String> {
        let canonical = canonicalize(config_text)?;
        let envelope_hash = hash_hex(&canonical);
        let key_id = credential.resource_id();
        let signing_bytes = signing_bytes_from_hash(
            &envelope_hash,
            signer,
            GOVERNANCE_CUSTODIAN_ALGORITHM,
            &key_id,
        );
        let call = whipplescript_custody::CustodyCall::new(
            whipplescript_custody::UseAttribution {
                run_id: "governance-sign".to_owned(),
                actor: Some(signer.to_owned()),
                effect_key: None,
            },
            whipplescript_custody::CustodyOp::Sign {
                credential: credential.clone(),
                alg: whipplescript_custody::SignatureAlg::Ed25519,
                derivation: Vec::new(),
                payload_b64: crate::exec_http::base64_encode(&signing_bytes),
            },
        );
        let reply = transport
            .call(call)
            .map_err(|err| format!("custodian unreachable: {err}"))?;
        let signature_b64 = match reply.outcome {
            // `key_version` is deliberately dropped rather than stored.
            // `ExternalAttestation` is canonicalized and signed, so adding a
            // field to it changes the signing domain of every existing
            // envelope. Governance keys therefore stay pinned to their first
            // version until that envelope change is made deliberately — the
            // same limitation r3 had everywhere before this commit, now scoped
            // to one place and written down.
            Ok(whipplescript_custody::CustodyOk::Signed { signature_b64, .. }) => signature_b64,
            Ok(other) => return Err(format!("custodian returned a non-signature: {other:?}")),
            Err(refusal) => {
                return Err(format!(
                    "governance sign refused by the custodian: {refusal} — admin is the `sign` \
                     capability on {key_id}"
                ))
            }
        };
        Ok(Self {
            canonical,
            envelope_hash,
            signer: signer.to_owned(),
            external: Some(ExternalAttestation {
                algorithm: GOVERNANCE_CUSTODIAN_ALGORITHM.to_owned(),
                key_id,
                signature: signature_b64,
                epoch: None,
                authority: None,
            }),
        })
    }

    /// Sign with privilege forced on — for tests only (the crate forbids the
    /// `set_var` that would drive the env-gated path).
    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn sign_for_test(config_text: &str, signer: &str) -> Self {
        Self::sign_with_privilege(config_text, signer, true).expect("privileged test sign")
    }

    /// The on-disk signed-envelope JSON: the FULL canonical content (resources,
    /// bindings, delegations, declassifications, endorsements) with an `attestation`
    /// block. The whole content is what the hash covers, so every field must survive
    /// the round-trip — not just `resources`.
    pub fn to_json(&self) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&self.canonical).unwrap_or_else(|_| serde_json::json!({}));
        if let Some(obj) = value.as_object_mut() {
            let mut attestation = serde_json::json!({
                "envelope_hash": self.envelope_hash,
                "signer": self.signer,
            });
            if let Some(external) = &self.external {
                attestation["algorithm"] = serde_json::json!(external.algorithm);
                attestation["key_id"] = serde_json::json!(external.key_id);
                attestation["signature"] = serde_json::json!(external.signature);
                // Emitted only under `:v2`, so a v1 envelope round-trips
                // byte-identically and keeps verifying against v1 bytes.
                if let (Some(epoch), Some(authority)) = (external.epoch, &external.authority) {
                    attestation["epoch"] = serde_json::json!(epoch);
                    attestation["authority"] = serde_json::json!(authority);
                }
            }
            obj.insert("attestation".to_owned(), attestation);
        }
        value.to_string()
    }

    /// Verify a loaded signed-envelope JSON: the attested hash must match the hash
    /// of its canonical content. UNPRIVILEGED — the whip agent does this; a tamper
    /// breaks the hash. Returns the signer on success.
    pub fn verify(signed_json: &str) -> Result<String, String> {
        Self::verify_attestation(signed_json).map(|attestation| attestation.signer)
    }

    /// Verify a loaded signed envelope and return the stable identity a host binds
    /// to its policy epoch. This is the programmatic trust-boundary surface used by
    /// embedding hosts; it proves both signer and canonical envelope hash.
    pub fn verify_attestation(signed_json: &str) -> Result<VerifiedAttestation, String> {
        let parsed = parse_attestation(signed_json)?;
        if parsed.external.is_some() {
            return Err(
                "externally signed governance envelope requires its pinned attestation verifier"
                    .to_owned(),
            );
        }
        Ok(VerifiedAttestation {
            envelope_hash: parsed.envelope_hash,
            signer: parsed.signer,
            key_id: None,
            epoch: None,
            authority: None,
        })
    }

    /// Verify an externally signed envelope under the embedding host's pinned
    /// governance verifier. Hash-only legacy envelopes are refused on this path.
    pub fn verify_attestation_with<V: GovernanceAttestationVerifier + ?Sized>(
        signed_json: &str,
        verifier: &V,
    ) -> Result<VerifiedAttestation, String> {
        let parsed = parse_attestation(signed_json)?;
        let external = parsed.external.ok_or_else(|| {
            "trusted embedding requires an external cryptographic attestation".to_owned()
        })?;
        // The preimage is selected by what the attestation states, never by a
        // caller preference: a `:v1` attestation cannot be verified against
        // `:v2` bytes or the reverse, because the domain tag differs and the
        // signature simply fails.
        let signing_bytes = match (external.epoch, external.authority.as_deref()) {
            (Some(epoch), Some(authority)) => signing_bytes_from_hash_v2(
                &parsed.envelope_hash,
                &parsed.signer,
                &external.algorithm,
                &external.key_id,
                epoch,
                authority,
            ),
            _ => signing_bytes_from_hash(
                &parsed.envelope_hash,
                &parsed.signer,
                &external.algorithm,
                &external.key_id,
            ),
        };
        verifier.verify(&signing_bytes, &external)?;
        Ok(VerifiedAttestation {
            envelope_hash: parsed.envelope_hash,
            signer: parsed.signer,
            key_id: Some(external.key_id),
            epoch: external.epoch,
            authority: external.authority,
        })
    }
}

/// Verifies custodian-signed governance envelopes: the whip agent asks the
/// custodian — which holds the governance key and never releases it — whether
/// the attestation's signature covers the signing bytes. Constant-time,
/// custodian-side (DR-0053 §6). This is [`GovernanceAttestationVerifier`]'s
/// custody realization, so `verify_attestation_with` works unchanged.
pub struct CustodianEnvelopeVerifier<'a> {
    transport: &'a dyn whipplescript_custody::CustodyTransport,
}

impl<'a> CustodianEnvelopeVerifier<'a> {
    pub fn new(transport: &'a dyn whipplescript_custody::CustodyTransport) -> Self {
        Self { transport }
    }
}

impl GovernanceAttestationVerifier for CustodianEnvelopeVerifier<'_> {
    fn verify(
        &self,
        signing_bytes: &[u8],
        attestation: &ExternalAttestation,
    ) -> Result<(), String> {
        if attestation.algorithm != GOVERNANCE_CUSTODIAN_ALGORITHM {
            return Err(format!(
                "not a custodian-held governance attestation (algorithm {:?})",
                attestation.algorithm
            ));
        }
        let credential =
            whipplescript_custody::CredentialName::from_resource_id(&attestation.key_id)
                .map_err(|err| format!("attestation key_id is not a credential: {err}"))?;
        let call = whipplescript_custody::CustodyCall::new(
            whipplescript_custody::UseAttribution {
                run_id: "governance-verify".to_owned(),
                actor: None,
                effect_key: None,
            },
            whipplescript_custody::CustodyOp::Verify {
                credential,
                alg: whipplescript_custody::SignatureAlg::Ed25519,
                payload_b64: crate::exec_http::base64_encode(signing_bytes),
                signature_b64: attestation.signature.clone(),
                // See the sign site: the attestation envelope carries no
                // version, so this asks for the key's first version, which is
                // what governance signed under.
                key_version: None,
            },
        );
        let reply = self
            .transport
            .call(call)
            .map_err(|err| format!("custodian unreachable: {err}"))?;
        match reply.outcome {
            Ok(whipplescript_custody::CustodyOk::Verified { valid: true }) => Ok(()),
            Ok(whipplescript_custody::CustodyOk::Verified { valid: false }) => {
                Err("governance envelope signature is invalid".to_owned())
            }
            Ok(other) => Err(format!("custodian returned a non-verification: {other:?}")),
            Err(refusal) => Err(format!("governance verify refused: {refusal}")),
        }
    }
}

struct ParsedAttestation {
    envelope_hash: String,
    signer: String,
    external: Option<ExternalAttestation>,
}

fn parse_attestation(signed_json: &str) -> Result<ParsedAttestation, String> {
    let mut value: serde_json::Value = serde_json::from_str(signed_json)
        .map_err(|err| format!("invalid signed envelope: {err}"))?;
    let attestation = value
        .get("attestation")
        .ok_or_else(|| "envelope is not signed (no attestation)".to_owned())?;
    let attested_hash = attestation
        .get("envelope_hash")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "attestation has no envelope_hash".to_owned())?;
    let signer = attestation
        .get("signer")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    let external_fields = (
        attestation
            .get("algorithm")
            .and_then(serde_json::Value::as_str),
        attestation
            .get("key_id")
            .and_then(serde_json::Value::as_str),
        attestation
            .get("signature")
            .and_then(serde_json::Value::as_str),
    );
    let external = match external_fields {
        (None, None, None) => None,
        (Some(algorithm), Some(key_id), Some(signature))
            if !algorithm.is_empty() && !key_id.is_empty() && !signature.is_empty() =>
        {
            let epoch = attestation.get("epoch").and_then(serde_json::Value::as_u64);
            let authority = attestation
                .get("authority")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            // Half a v2 attestation is refused rather than downgraded to v1.
            // Downgrading would verify a signature that never covered the epoch
            // while the envelope carries one, which is the exact confusion the
            // domain tag exists to prevent.
            if epoch.is_some() != authority.is_some() {
                return Err(
                    "governance attestation states one of epoch/authority; :v2 requires both"
                        .to_owned(),
                );
            }
            Some(ExternalAttestation {
                algorithm: algorithm.to_owned(),
                key_id: key_id.to_owned(),
                signature: signature.to_owned(),
                epoch,
                authority,
            })
        }
        _ => return Err("external governance attestation is incomplete".to_owned()),
    };
    // recompute the canonical content hash from the FULL content (everything
    // except the attestation), re-canonicalized through the envelope so ordering
    // matches signing. A tamper to any covered field breaks the hash. The
    // attested hash is owned off first so the parsed document itself can shed
    // its attestation in place — nothing below reads it again.
    let attested_hash = attested_hash.to_owned();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("attestation");
    }
    let recanonical = canonicalize(&value.to_string())?;
    if hash_hex(&recanonical) == attested_hash {
        Ok(ParsedAttestation {
            envelope_hash: attested_hash,
            signer,
            external,
        })
    } else {
        Err(
            "signed envelope failed verification — content does not match its \
                 attestation (tampered or re-edited without re-signing)"
                .to_owned(),
        )
    }
}

/// The exact bytes an embedding governance authority signs. Length-prefixing
/// makes the tuple unambiguous; the domain tag prevents cross-protocol reuse.
pub fn external_signing_bytes(
    config_text: &str,
    signer: &str,
    algorithm: &str,
    key_id: &str,
) -> Result<Vec<u8>, String> {
    let canonical = canonicalize(config_text)?;
    let envelope_hash = hash_hex(&canonical);
    Ok(signing_bytes_from_hash(
        &envelope_hash,
        signer,
        algorithm,
        key_id,
    ))
}

/// The exact bytes an embedding governance authority signs under `:v2`
/// (DR-0063 §5). A composed set admits only this form; `:v1` remains valid on
/// the single-envelope path.
pub fn external_signing_bytes_v2(
    config_text: &str,
    signer: &str,
    algorithm: &str,
    key_id: &str,
    epoch: u64,
    authority: &str,
) -> Result<Vec<u8>, String> {
    let canonical = canonicalize(config_text)?;
    let envelope_hash = hash_hex(&canonical);
    Ok(signing_bytes_from_hash_v2(
        &envelope_hash,
        signer,
        algorithm,
        key_id,
        epoch,
        authority,
    ))
}

fn signing_bytes_from_hash(
    envelope_hash: &str,
    signer: &str,
    algorithm: &str,
    key_id: &str,
) -> Vec<u8> {
    tagged_signing_bytes(
        b"whipplescript-governance-envelope:v1;",
        &[envelope_hash, signer, algorithm, key_id],
    )
}

/// The `:v2` preimage (DR-0063 §5): everything `:v1` covers, plus the policy
/// **epoch** and the **authority** the envelope speaks for.
///
/// The epoch matters because a composition record cites
/// `(authority, envelope_hash, epoch)` per constituent, and
/// under `:v1` the same valid signature verifies under whatever epoch a caller
/// names — so a constituent can be presented as a different, including an
/// earlier, policy version. That is exactly the non-retroactivity claim the
/// record is meant to carry. The authority matters because a composed set is
/// keyed by it, and a signature that does not cover it authenticates the
/// signer without authenticating whose policy this is.
fn signing_bytes_from_hash_v2(
    envelope_hash: &str,
    signer: &str,
    algorithm: &str,
    key_id: &str,
    epoch: u64,
    authority: &str,
) -> Vec<u8> {
    let epoch_text = epoch.to_string();
    tagged_signing_bytes(
        b"whipplescript-governance-envelope:v2;",
        &[
            envelope_hash,
            signer,
            algorithm,
            key_id,
            &epoch_text,
            authority,
        ],
    )
}

/// Length-prefixed concatenation under a domain tag. The prefixes make the
/// tuple unambiguous, so no two distinct field lists produce one preimage.
fn tagged_signing_bytes(tag: &[u8], values: &[&str]) -> Vec<u8> {
    let mut bytes = tag.to_vec();
    for value in values {
        bytes.extend_from_slice(value.len().to_string().as_bytes());
        bytes.push(b':');
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(b';');
    }
    bytes
}

/// An escalation request: the whip side asks the admin for a governance change
/// (e.g. a missing declassify grant). It crosses to the governance side as
/// LOW-INTEGRITY data (DR-0028 D5, the one whip->gov flow): the governance agent
/// never auto-acts on it; the admin reviews and signs.
pub struct Escalation {
    pub request: String,
    pub from: String,
}

/// File an escalation request — UNPRIVILEGED (the whip side files it). Appends a
/// low-integrity request to the escalation log; it is data, never an action.
pub fn file_escalation(log: &Path, request: &str, from: &str) -> Result<(), String> {
    let line = serde_json::json!({ "request": request, "from": from }).to_string();
    let mut contents = std::fs::read_to_string(log).unwrap_or_default();
    if !contents.is_empty() && !contents.ends_with('\n') {
        contents.push('\n');
    }
    contents.push_str(&line);
    contents.push('\n');
    std::fs::write(log, contents)
        .map_err(|err| format!("cannot write escalation log {}: {err}", log.display()))
}

/// Review pending escalations — PRIVILEGED (only the governance agent, G1). The
/// requests are surfaced for the admin to decide on; reviewing them never applies
/// them (the admin signs a new envelope separately).
pub fn list_escalations(log: &Path) -> Result<Vec<Escalation>, String> {
    list_escalations_with_privilege(log, has_governance_privilege())
}

fn list_escalations_with_privilege(
    log: &Path,
    privileged: bool,
) -> Result<Vec<Escalation>, String> {
    if !privileged {
        return Err(
            "reviewing escalations requires governance privilege (run via the governance agent)"
                .to_owned(),
        );
    }
    let text = std::fs::read_to_string(log).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| format!("invalid escalation entry: {err}"))?;
        out.push(Escalation {
            request: value
                .get("request")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_owned(),
            from: value
                .get("from")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown")
                .to_owned(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transport that answers every call with one canned outcome, so the two
    /// ways `sign_with_custodian` can be told "no" are reachable without a
    /// custodian process.
    struct CannedTransport(
        std::sync::Mutex<
            Option<Result<whipplescript_custody::CustodyOk, whipplescript_custody::CustodyError>>,
        >,
    );

    impl whipplescript_custody::CustodyTransport for CannedTransport {
        fn call(
            &self,
            _call: whipplescript_custody::CustodyCall,
        ) -> Result<whipplescript_custody::CustodyReply, whipplescript_custody::TransportError>
        {
            Ok(whipplescript_custody::CustodyReply {
                use_id: "use-test".to_owned(),
                rung: whipplescript_custody::Rung::Process,
                degraded: false,
                outcome: self
                    .0
                    .lock()
                    .expect("lock")
                    .take()
                    .expect("one call per canned transport"),
            })
        }
    }

    /// Governance signing reads exactly one reply shape. The other two are
    /// refusals, and both were unpinned: a custodian that answers with some
    /// other success, and one that refuses outright.
    ///
    /// The second message carries the key id on purpose — an operator reading
    /// "governance sign refused" needs to know WHICH credential the `sign`
    /// capability is missing on.
    #[test]
    fn governance_signing_refuses_a_non_signature_and_reports_a_custodian_refusal() {
        let credential =
            whipplescript_custody::CredentialName::new("gov/root").expect("valid name");

        let wrong_shape = CannedTransport(std::sync::Mutex::new(Some(Ok(
            whipplescript_custody::CustodyOk::Verified { valid: true },
        ))));
        let err = SignedEnvelope::sign_with_custodian(
            "authority acme\n",
            "acme",
            &wrong_shape,
            &credential,
        )
        .err()
        .unwrap_or_else(|| panic!("a non-signature reply must refuse"));
        assert!(
            err.contains("custodian returned a non-signature"),
            "the refusal must name the shape mismatch: {err}"
        );

        let refused = CannedTransport(std::sync::Mutex::new(Some(Err(
            whipplescript_custody::CustodyError::UnknownCredential {
                credential: credential.clone(),
            },
        ))));
        let err =
            SignedEnvelope::sign_with_custodian("authority acme\n", "acme", &refused, &credential)
                .err()
                .unwrap_or_else(|| panic!("a custodian refusal must surface"));
        assert!(
            err.contains("governance sign refused by the custodian"),
            "the refusal must say the custodian refused: {err}"
        );
        assert!(
            err.contains(&credential.resource_id()),
            "the refusal must name the credential the `sign` capability is missing on: {err}"
        );
    }

    struct ExactVerifier {
        expected: Vec<u8>,
    }

    impl GovernanceAttestationVerifier for ExactVerifier {
        fn verify(
            &self,
            signing_bytes: &[u8],
            attestation: &ExternalAttestation,
        ) -> Result<(), String> {
            if signing_bytes == self.expected
                && attestation.algorithm == "p256-sha256"
                && attestation.key_id == "key-1"
                && attestation.signature == "valid-signature"
            {
                Ok(())
            } else {
                Err("external signature rejected".to_owned())
            }
        }
    }

    const CONFIG: &str = "\
grant file_store ledger -> file:/srv/ledger.db readable by Operator\n\
grant file_store outbox -> file:/srv/outbox public\n";

    /// The whip agent (no governance privilege) cannot sign — the single-signer
    /// rule G4, enforced structurally.
    #[test]
    fn unprivileged_cannot_sign() {
        assert!(SignedEnvelope::sign_with_privilege(CONFIG, "admin", false).is_err());
    }

    #[test]
    fn governance_agent_signs_and_whip_agent_verifies() {
        let signed =
            SignedEnvelope::sign_with_privilege(CONFIG, "alice@admin", true).expect("privileged");
        let json = signed.to_json();
        // the whip agent (unprivileged) can still VERIFY
        assert_eq!(
            SignedEnvelope::verify(&json).expect("verifies"),
            "alice@admin"
        );
        let attestation = SignedEnvelope::verify_attestation(&json).expect("identity verifies");
        assert_eq!(attestation.signer, "alice@admin");
        assert_eq!(attestation.envelope_hash, signed.envelope_hash);
        assert_eq!(attestation.key_id, None);
    }

    #[test]
    fn a_half_stated_v2_attestation_is_refused_rather_than_downgraded() {
        // DR-0063 §5. An attestation naming an epoch but no authority (or the
        // reverse) is malformed. Treating it as `:v1` would verify a signature
        // that never covered the epoch while the envelope carries one — the
        // exact confusion the domain tag exists to prevent, arrived at by
        // omission rather than by forgery.
        let signed = SignedEnvelope::from_external_signature(
            CONFIG,
            "gaugedesk-root",
            "p256-sha256",
            "key-1",
            "valid-signature",
        )
        .expect("artifact")
        .to_json();
        let half = signed.replace(
            "\"signature\":\"valid-signature\"",
            "\"signature\":\"valid-signature\",\"epoch\":12",
        );
        let error = SignedEnvelope::verify_attestation_with(
            &half,
            &ExactVerifier {
                expected: Vec::new(),
            },
        )
        .expect_err("half a v2 attestation is not a v1 attestation");
        assert!(
            error.contains("epoch/authority"),
            "the refusal says which half is missing: {error}"
        );
    }

    #[test]
    fn the_v2_preimage_covers_the_epoch_and_the_authority() {
        // Changing either input changes the bytes a signature must cover, which
        // is the whole mechanism: an epoch outside the preimage is an epoch a
        // caller may choose.
        let base =
            external_signing_bytes_v2(CONFIG, "gaugedesk-root", "p256-sha256", "key-1", 12, "acme")
                .expect("bytes");
        let other_epoch =
            external_signing_bytes_v2(CONFIG, "gaugedesk-root", "p256-sha256", "key-1", 13, "acme")
                .expect("bytes");
        let other_authority =
            external_signing_bytes_v2(CONFIG, "gaugedesk-root", "p256-sha256", "key-1", 12, "beta")
                .expect("bytes");
        assert_ne!(base, other_epoch, "the epoch is inside the preimage");
        assert_ne!(
            base, other_authority,
            "the authority is inside the preimage"
        );

        let v1 = external_signing_bytes(CONFIG, "gaugedesk-root", "p256-sha256", "key-1")
            .expect("bytes");
        assert_ne!(base, v1, "the two preimages are domain-separated");
    }

    #[test]
    fn external_attestation_requires_and_binds_the_pinned_verifier() {
        let signing_bytes =
            external_signing_bytes(CONFIG, "gaugedesk-root", "p256-sha256", "key-1")
                .expect("canonical signing bytes");
        let signed = SignedEnvelope::from_external_signature(
            CONFIG,
            "gaugedesk-root",
            "p256-sha256",
            "key-1",
            "valid-signature",
        )
        .expect("artifact")
        .to_json();

        assert!(SignedEnvelope::verify_attestation(&signed).is_err());
        let verified = SignedEnvelope::verify_attestation_with(
            &signed,
            &ExactVerifier {
                expected: signing_bytes,
            },
        )
        .expect("external signature");
        assert_eq!(verified.signer, "gaugedesk-root");
        assert_eq!(verified.key_id.as_deref(), Some("key-1"));

        let forged = signed.replace("valid-signature", "forged-signature");
        assert!(SignedEnvelope::verify_attestation_with(
            &forged,
            &ExactVerifier {
                expected: external_signing_bytes(CONFIG, "gaugedesk-root", "p256-sha256", "key-1")
                    .expect("bytes"),
            }
        )
        .is_err());
    }

    #[test]
    fn escalation_channel_files_low_integrity_and_only_gov_reviews() {
        let log = std::env::temp_dir().join(format!(
            "whip-gov-escalation-{}-{}.jsonl",
            std::process::id(),
            CONFIG.len()
        ));
        let _ = std::fs::remove_file(&log);
        file_escalation(&log, "need declassify ledger to Auditor", "bob").expect("filed");
        file_escalation(&log, "need endorse intake to Operator", "carol").expect("filed");
        // the whip side (unprivileged) cannot review escalations (G1).
        assert!(list_escalations_with_privilege(&log, false).is_err());
        // the governance agent reviews them.
        let items = list_escalations_with_privilege(&log, true).expect("review");
        assert_eq!(items.len(), 2);
        assert!(items[0].request.contains("declassify"));
        assert_eq!(items[0].from, "bob");
        let _ = std::fs::remove_file(&log);
    }

    /// DR-0053 §10: the governance key is custodian-held; admin is the
    /// `sign` capability. Sign through the custodian, verify through the
    /// custodian, and confirm no path yields the key or accepts a forgery.
    #[test]
    fn custodian_holds_the_governance_key() {
        use std::sync::Arc;
        use whipplescript_custodian::store::SealedStore;
        use whipplescript_custodian::{Custodian, DeniedEgress, InProcessTransport};
        use whipplescript_custody::CredentialName;
        use zeroize_seed::seed;

        mod zeroize_seed {
            /// RFC 8032 test seed — a published constant, secures nothing.
            pub fn seed() -> Vec<u8> {
                let hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                    .collect()
            }
        }

        let mut store = SealedStore::create(None, "pw").expect("store");
        let credential = CredentialName::new(GOVERNANCE_SIGNING_CREDENTIAL).expect("name");
        store
            .register(
                credential.clone(),
                whipplescript_custody::CredentialKind::Ed25519,
                zeroize::Zeroizing::new(seed()),
                None,
                None,
            )
            .expect("register");
        let custodian = Arc::new(Custodian::new(store, Box::new(DeniedEgress)));
        let transport = InProcessTransport::new(Arc::clone(&custodian));

        let signed =
            SignedEnvelope::sign_with_custodian(CONFIG, "root-admin", &transport, &credential)
                .expect("custodian signs");
        let json = signed.to_json();

        // The keyless checksum path refuses custodian envelopes: they demand
        // their pinned verifier.
        assert!(SignedEnvelope::verify_attestation(&json).is_err());

        let verified = SignedEnvelope::verify_attestation_with(
            &json,
            &CustodianEnvelopeVerifier::new(&transport),
        )
        .expect("custodian verifies");
        assert_eq!(verified.signer, "root-admin");
        assert_eq!(
            verified.key_id.as_deref(),
            Some("credential:whip/governance-signing")
        );

        // A forged signature is rejected — by the custodian, in constant time.
        let signature = signed.to_json();
        let original_sig = serde_json::from_str::<serde_json::Value>(&signature).expect("json")
            ["attestation"]["signature"]
            .as_str()
            .expect("sig")
            .to_owned();
        let forged = json.replace(&original_sig, &"A".repeat(original_sig.len()));
        assert_ne!(forged, json);
        assert!(SignedEnvelope::verify_attestation_with(
            &forged,
            &CustodianEnvelopeVerifier::new(&transport)
        )
        .is_err());

        // Signing with an unknown credential is a custodian refusal — there
        // is no environment variable to set around it.
        let missing = CredentialName::new("whip/not-registered").expect("name");
        assert!(
            SignedEnvelope::sign_with_custodian(CONFIG, "root-admin", &transport, &missing)
                .is_err()
        );

        // Both uses were recorded and attributed (§1).
        let uses = custodian.uses();
        assert!(uses
            .iter()
            .any(|record| record.attribution.run_id == "governance-sign"));
        assert!(uses
            .iter()
            .any(|record| record.attribution.run_id == "governance-verify"));
    }

    #[test]
    fn tampered_envelope_fails_verification() {
        let signed =
            SignedEnvelope::sign_with_privilege(CONFIG, "alice@admin", true).expect("privileged");
        let json = signed.to_json();
        // flip ledger's reader authority to public without re-signing
        let tampered = json.replace("\"reader\":[\"Operator\"]", "\"reader\":[]");
        assert_ne!(tampered, json, "test should actually modify the content");
        assert!(SignedEnvelope::verify(&tampered).is_err());
    }
}
