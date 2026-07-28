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

/// Whether the current process holds governance (admin) privilege (G1).
///
/// Production binds this to the OS: `whip gov` is installed root-only / behind
/// sudo, so being able to run the privileged path *is* the gate. Where requiring
/// root is impractical (CI, dev sandboxes), the explicit `WHIPPLESCRIPT_GOV_ADMIN`
/// token stands in. Otherwise the process is unprivileged — the whip agent.
pub fn has_governance_privilege() -> bool {
    std::env::var_os("WHIPPLESCRIPT_GOV_ADMIN").is_some()
}

fn hash_hex(content: &str) -> String {
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
    Ok(envelope.to_canonical_json())
}

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
}

/// A cryptographic attestation supplied by an embedding governance authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExternalAttestation {
    pub algorithm: String,
    pub key_id: String,
    pub signature: String,
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
        let signing_bytes = signing_bytes_from_hash(
            &parsed.envelope_hash,
            &parsed.signer,
            &external.algorithm,
            &external.key_id,
        );
        verifier.verify(&signing_bytes, &external)?;
        Ok(VerifiedAttestation {
            envelope_hash: parsed.envelope_hash,
            signer: parsed.signer,
            key_id: Some(external.key_id),
        })
    }
}

struct ParsedAttestation {
    envelope_hash: String,
    signer: String,
    external: Option<ExternalAttestation>,
}

fn parse_attestation(signed_json: &str) -> Result<ParsedAttestation, String> {
    let value: serde_json::Value = serde_json::from_str(signed_json)
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
            Some(ExternalAttestation {
                algorithm: algorithm.to_owned(),
                key_id: key_id.to_owned(),
                signature: signature.to_owned(),
            })
        }
        _ => return Err("external governance attestation is incomplete".to_owned()),
    };
    // recompute the canonical content hash from the FULL content (everything
    // except the attestation), re-canonicalized through the envelope so ordering
    // matches signing. A tamper to any covered field breaks the hash.
    let mut content = value.clone();
    if let Some(obj) = content.as_object_mut() {
        obj.remove("attestation");
    }
    let recanonical = canonicalize(&content.to_string())?;
    if hash_hex(&recanonical) == attested_hash {
        Ok(ParsedAttestation {
            envelope_hash: attested_hash.to_owned(),
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

fn signing_bytes_from_hash(
    envelope_hash: &str,
    signer: &str,
    algorithm: &str,
    key_id: &str,
) -> Vec<u8> {
    let mut bytes = b"whipplescript-governance-envelope:v1;".to_vec();
    for value in [envelope_hash, signer, algorithm, key_id] {
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
