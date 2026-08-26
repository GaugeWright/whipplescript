//! Governance verification at the hosted placement boundary.
//!
//! GaugeDesk authenticates people and signs an immutable WhippleScript policy
//! epoch with its P-256 governance root. A Durable Object must verify that
//! signature itself before it admits a package or turn; trusting only the
//! Worker bearer token would move runtime enforcement out of WhippleScript.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use whipplescript_kernel::gov::GovernanceAttestationVerifier;
use whipplescript_kernel::host_protocol::PolicyEpochRef;
use whipplescript_kernel::ifc::VerifiedEnvelope;

/// The external-attestation algorithm emitted by GaugeDesk.
pub const GAUGEDESK_ATTESTATION_ALGORITHM: &str = "p256-sha256";

/// A pinned GaugeDesk governance root. The public key is the exact
/// SEC1-encoded, hex-encoded GaugeDesk `PublicKey` wire representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GaugeDeskGovernanceRoot {
    expected_signer: String,
    public_key_hex: String,
}

impl GaugeDeskGovernanceRoot {
    pub fn new(expected_signer: impl Into<String>, public_key_hex: impl Into<String>) -> Self {
        Self {
            expected_signer: expected_signer.into(),
            public_key_hex: public_key_hex.into(),
        }
    }

    /// Verify the signed policy and bind it to an immutable epoch reference.
    /// Signer, key, and now the **epoch** are all pinned by the signature;
    /// none may be selected by the request being verified (DR-0063 §5).
    ///
    /// The epoch is read from the attestation rather than taken as an argument,
    /// so the hosted path requires a `:v2` envelope. A `:v1` signature does not
    /// reach the epoch, and this path is exactly where an unauthenticated one
    /// would matter: a composition record cites the epoch per constituent, and
    /// a caller that can name it can present a policy as a version it is not.
    pub fn verify(&self, signed_envelope: &str) -> Result<VerifiedHostedPolicy, String> {
        if self.expected_signer.trim().is_empty() || self.public_key_hex.trim().is_empty() {
            return Err("hosted placement has no pinned GaugeDesk governance root".to_owned());
        }
        let envelope = VerifiedEnvelope::verify_signed_text_with(signed_envelope, self)?;
        let attestation = envelope
            .attestation()
            .ok_or("hosted policy requires an external governance attestation")?;
        if attestation.signer != self.expected_signer {
            return Err(
                "governance signer does not match the placement's pinned authority".to_owned(),
            );
        }
        if attestation.key_id.as_deref() != Some(self.public_key_hex.as_str()) {
            return Err(
                "governance key does not match the placement's pinned authority".to_owned(),
            );
        }
        let epoch = attestation.epoch.ok_or(
            "hosted policy requires a :v2 governance attestation, whose signature covers the epoch",
        )?;
        let policy =
            PolicyEpochRef::from_verified(epoch, &envelope).map_err(|error| error.to_string())?;
        Ok(VerifiedHostedPolicy { policy, envelope })
    }
}

impl GovernanceAttestationVerifier for GaugeDeskGovernanceRoot {
    fn verify(
        &self,
        signing_bytes: &[u8],
        attestation: &whipplescript_kernel::gov::ExternalAttestation,
    ) -> Result<(), String> {
        if attestation.algorithm != GAUGEDESK_ATTESTATION_ALGORITHM {
            return Err("unsupported GaugeDesk governance signature algorithm".to_owned());
        }
        if attestation.key_id != self.public_key_hex {
            return Err("governance attestation key does not match the pinned root".to_owned());
        }
        let key_bytes = hex::decode(&self.public_key_hex)
            .map_err(|_| "pinned governance key is not valid hex".to_owned())?;
        let verifying = VerifyingKey::from_sec1_bytes(&key_bytes)
            .map_err(|_| "pinned governance key is not a valid P-256 point".to_owned())?;
        let signature_bytes = hex::decode(&attestation.signature)
            .map_err(|_| "governance signature is not valid hex".to_owned())?;
        let signature = Signature::from_slice(&signature_bytes)
            .map_err(|_| "governance signature is not a raw P-256 signature".to_owned())?;
        verifying
            .verify(signing_bytes, &signature)
            .map_err(|_| "governance signature does not verify".to_owned())
    }
}

/// Verified enforcement material retained by the Durable Object. The envelope
/// stays WhippleScript-owned; callers receive only its stable epoch reference.
pub struct VerifiedHostedPolicy {
    pub policy: PolicyEpochRef,
    pub envelope: VerifiedEnvelope,
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToSec1Point;
    use whipplescript_kernel::gov::{
        external_signing_bytes, external_signing_bytes_v2, SignedEnvelope,
    };

    fn signed_policy(seed: u8, signer: &str) -> (String, String) {
        let (key, public_key, policy) = policy_material(seed);
        let signing_bytes = external_signing_bytes(
            &policy,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
        )
        .expect("canonical bytes");
        let signature: Signature = key.sign(&signing_bytes);
        let signed = SignedEnvelope::from_external_signature(
            &policy,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
            &hex::encode(signature.to_bytes()),
        )
        .expect("signed")
        .to_json();
        (public_key, signed)
    }

    /// The signing key, its pinned public form, and the policy text every test
    /// in this module signs. Shared so a `:v1` and a `:v2` attestation cover
    /// byte-identical content and differ only in their preimage.
    fn policy_material(seed: u8) -> (SigningKey, String, String) {
        let key = SigningKey::from_slice(&[seed; 32]).expect("test key");
        let public_key = hex::encode(
            key.verifying_key()
                .as_affine()
                .to_sec1_point(true)
                .as_bytes(),
        );
        let policy = serde_json::json!({
            "resources": {
                "placement:do": { "principal": true },
                "provider:openai": { "principal": true }
            },
            "bindings": {
                "do": "placement:do",
                "model": "provider:openai"
            },
            "capabilities": ["workspace.read"],
            "provider_bindings": {
                "model": {
                    "provider": "openai",
                    "model": "gpt-5",
                    "base_url": "https://api.openai.com/v1/responses",
                    "credential_ref": "credential:account:openai"
                }
            },
            "placements": {
                "do": {
                    "kind": "durable_object",
                    "provider_bindings": ["model"],
                    "command_network": false
                }
            }
        })
        .to_string();
        (key, public_key, policy)
    }

    /// The same policy signed under the `:v2` preimage, which covers the epoch
    /// and the authority as well (DR-0063 §5).
    fn signed_policy_v2(seed: u8, signer: &str, epoch: u64, authority: &str) -> (String, String) {
        let (key, public_key, policy) = policy_material(seed);
        let signing_bytes = external_signing_bytes_v2(
            &policy,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
            epoch,
            authority,
        )
        .expect("canonical bytes");
        let signature: Signature = key.sign(&signing_bytes);
        let signed = SignedEnvelope::from_external_signature_v2(
            &policy,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
            &hex::encode(signature.to_bytes()),
            epoch,
            authority,
        )
        .expect("signed")
        .to_json();
        (public_key, signed)
    }

    #[test]
    fn the_hosted_epoch_comes_from_the_signature() {
        let (key, signed) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let verified = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key)
            .verify(&signed)
            .expect("verified");
        assert_eq!(
            verified.policy.epoch, 12,
            "the epoch is read from the attestation, not supplied by the caller"
        );
        assert_eq!(verified.policy.signer, "authority:gaugedesk");
        assert_eq!(
            verified
                .envelope
                .attestation()
                .and_then(|a| a.authority.as_deref()),
            Some("acme"),
        );
    }

    #[test]
    fn two_epochs_are_two_signatures() {
        // The headline of DR-0063 §5, restated now that the argument is gone:
        // there is no call that presents one signature as two policy versions,
        // because the version is inside what was signed. Signing epoch 13
        // produces different bytes and therefore a different envelope.
        let (key, twelve) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let (_, thirteen) = signed_policy_v2(7, "authority:gaugedesk", 13, "acme");
        assert_ne!(twelve, thirteen);
        let root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key);
        assert_eq!(root.verify(&twelve).expect("verified").policy.epoch, 12);
        assert_eq!(root.verify(&thirteen).expect("verified").policy.epoch, 13);
    }

    #[test]
    fn the_hosted_path_refuses_a_v1_envelope() {
        // The production consequence of reading the epoch from the signature:
        // a `:v1` attestation does not reach the epoch, so there is nothing to
        // read and the hosted path fails closed rather than inventing one.
        // `:v1` stays valid where an epoch is not load-bearing — that is the
        // single-envelope path, not this one.
        let (key, signed) = signed_policy(7, "authority:gaugedesk");
        let error = match GaugeDeskGovernanceRoot::new("authority:gaugedesk", key).verify(&signed) {
            Ok(_) => panic!("a v1 envelope carries no signed epoch"),
            Err(error) => error,
        };
        assert!(
            error.contains(":v2"),
            "the refusal says what the hosted path requires: {error}"
        );
    }

    #[test]
    fn a_v2_signature_does_not_verify_as_v1() {
        // Domain separation. The tag differs, so bytes signed under one
        // preimage cannot be replayed as the other — which is what lets both
        // live in one verifier with no downgrade path between them. Stripping
        // the v2 fields does not yield a valid v1 envelope; it yields nothing.
        let (key, signed) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let stripped = signed
            .replace(",\"epoch\":12", "")
            .replace(",\"authority\":\"acme\"", "");
        assert!(!stripped.contains("\"epoch\""), "v2 fields removed");
        let root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key);
        assert!(root.verify(&stripped).is_err());
    }

    #[test]
    fn hosted_policy_rejects_a_different_signer_or_key() {
        let (key, signed) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let wrong_signer = GaugeDeskGovernanceRoot::new("authority:attacker", key.clone());
        assert!(wrong_signer.verify(&signed).is_err());

        let (wrong_key, _) = signed_policy_v2(9, "authority:gaugedesk", 12, "acme");
        let wrong_root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", wrong_key);
        assert!(wrong_root.verify(&signed).is_err());
    }

    /// A policy carrying DR-0074 §2's type-narrowed unwrap grant, signed the
    /// same way every other policy in this module is. Separate from
    /// `policy_material` so the existing tests keep signing byte-identical
    /// content and go on covering what they were written to cover.
    fn custody_policy_material(seed: u8) -> (SigningKey, String, String) {
        let key = SigningKey::from_slice(&[seed; 32]).expect("test key");
        let public_key = hex::encode(
            key.verifying_key()
                .as_affine()
                .to_sec1_point(true)
                .as_bytes(),
        );
        let policy = serde_json::json!({
            "authority": "acme",
            "resources": { "credential:acme/phi-key": {} },
            "bindings": { "PHIKey": "credential:acme/phi-key" },
            "unwrap_grants": [
                {
                    "credential": "PHIKey",
                    "type": "PatientRecord",
                    "role": "acme::Clinician"
                }
            ]
        })
        .to_string();
        (key, public_key, policy)
    }

    fn signed_custody_policy(seed: u8, signer: &str, epoch: u64) -> (String, String) {
        let (key, public_key, policy) = custody_policy_material(seed);
        let signing_bytes = external_signing_bytes_v2(
            &policy,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
            epoch,
            "acme",
        )
        .expect("canonical bytes");
        let signature: Signature = key.sign(&signing_bytes);
        let signed = SignedEnvelope::from_external_signature_v2(
            &policy,
            signer,
            GAUGEDESK_ATTESTATION_ALGORITHM,
            &public_key,
            &hex::encode(signature.to_bytes()),
            epoch,
            "acme",
        )
        .expect("signed")
        .to_json();
        (public_key, signed)
    }

    #[test]
    fn the_hosted_path_carries_a_type_narrowed_unwrap_grant() {
        // DR-0074 §2 parity. The hosted path parses envelopes with the same
        // kernel code the native one does, so parity holds by construction —
        // but the last parity claim made by inspection on this host hid a
        // fail-open, so it is asserted here instead of assumed.
        let (key, signed) = signed_custody_policy(7, "authority:gaugedesk", 12);
        let verified = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key)
            .verify(&signed)
            .expect("verified");
        assert!(verified
            .envelope
            .may_unwrap("PHIKey", "PatientRecord", "acme::Clinician"));
        // The narrowing survives the hosted trip intact: another type under the
        // same credential is refused here exactly as it is natively.
        assert!(!verified
            .envelope
            .may_unwrap("PHIKey", "BillingRecord", "acme::Clinician"));
        assert!(!verified
            .envelope
            .may_unwrap("PHIKey", "PatientRecord", "acme::Billing"));
    }

    #[test]
    fn a_hosted_unwrap_grant_is_inside_the_signature() {
        // The grant is an authorization, so it must be signature-covered on the
        // hosted path too. Widening the type it narrows to breaks verification
        // rather than yielding a policy that opens more than acme signed for.
        let (key, signed) = signed_custody_policy(7, "authority:gaugedesk", 12);
        let widened = signed.replace("PatientRecord", "BillingRecord");
        assert_ne!(widened, signed, "the grant is in the signed document");
        let root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key);
        assert!(root.verify(&widened).is_err());
    }

    #[test]
    fn hosted_policy_rejects_tampering() {
        let (key, signed) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let tampered = signed.replace("gpt-5", "gpt-5-mini");
        let root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key);
        assert!(root.verify(&tampered).is_err());
    }
}
