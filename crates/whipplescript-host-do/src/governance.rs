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
    /// Both signer identity and key are pinned; neither may be selected by the
    /// request being verified.
    pub fn verify_epoch(
        &self,
        epoch: u64,
        signed_envelope: &str,
    ) -> Result<VerifiedHostedPolicy, String> {
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
        // DR-0063 §5. Under `:v2` the signature covers the epoch, so the epoch
        // this call names must be the one that was signed — the caller stops
        // being able to choose which policy version a valid signature stands
        // for. Under `:v1` the signature does not reach the epoch at all, and
        // this call keeps its historic behaviour on the single-envelope path;
        // `attestation.epoch` being `None` is what a consumer checks before
        // resting anything on it.
        if let Some(signed_epoch) = attestation.epoch {
            if signed_epoch != epoch {
                return Err(format!(
                    "governance attestation is signed for epoch {signed_epoch}, not {epoch}"
                ));
            }
        }
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
    fn a_v2_policy_verifies_at_the_epoch_it_was_signed_for() {
        let (key, signed) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let verified = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key)
            .verify_epoch(12, &signed)
            .expect("verified");
        assert_eq!(verified.policy.epoch, 12);
        assert_eq!(
            verified.envelope.attestation().and_then(|a| a.epoch),
            Some(12),
            "the epoch is authenticated, so a consumer may rest on it"
        );
        assert_eq!(
            verified
                .envelope
                .attestation()
                .and_then(|a| a.authority.as_deref()),
            Some("acme"),
        );
    }

    #[test]
    fn a_v2_policy_is_refused_at_any_other_epoch() {
        // The headline of DR-0063 §5. Under `:v1` this same call succeeds
        // (below), which is how a constituent could be replayed as a different
        // — including an earlier — policy version while its signature stayed
        // valid. The composition record cites the epoch, so an unauthenticated
        // one makes the record's non-retroactivity claim untrue.
        let (key, signed) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key);
        let error = match root.verify_epoch(11, &signed) {
            Ok(_) => panic!("a v2 signature must not verify at an epoch it does not name"),
            Err(error) => error,
        };
        assert!(
            error.contains("signed for epoch 12"),
            "the refusal names the epoch actually signed: {error}"
        );
        assert!(root.verify_epoch(13, &signed).is_err());
    }

    #[test]
    fn a_v1_policy_still_verifies_and_authenticates_no_epoch() {
        // The single-envelope path, unchanged and deliberately so. What changes
        // is that `epoch: None` now SAYS the epoch is unauthenticated, instead
        // of the caller's argument looking like a verified fact.
        let (key, signed) = signed_policy(7, "authority:gaugedesk");
        let verified = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key)
            .verify_epoch(12, &signed)
            .expect("verified");
        assert_eq!(
            verified.envelope.attestation().and_then(|a| a.epoch),
            None,
            "a v1 signature does not reach the epoch, and says so"
        );
    }

    #[test]
    fn a_v2_signature_does_not_verify_as_v1() {
        // Domain separation. The tag differs, so bytes signed under one
        // preimage cannot be replayed as the other — which is what lets both
        // live in one verifier without a downgrade path between them.
        let (key, signed) = signed_policy_v2(7, "authority:gaugedesk", 12, "acme");
        let stripped = signed
            .replace(",\"epoch\":12", "")
            .replace(",\"authority\":\"acme\"", "");
        assert!(!stripped.contains("\"epoch\""), "v2 fields removed");
        let root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key);
        assert!(
            root.verify_epoch(12, &stripped).is_err(),
            "stripping the v2 fields must not downgrade the envelope into a valid v1 one"
        );
    }

    #[test]
    fn hosted_policy_verifies_under_the_pinned_gaugedesk_root() {
        let (key, signed) = signed_policy(7, "authority:gaugedesk");
        let verified = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key)
            .verify_epoch(12, &signed)
            .expect("verified");
        assert_eq!(verified.policy.epoch, 12);
        assert_eq!(verified.policy.signer, "authority:gaugedesk");
    }

    #[test]
    fn hosted_policy_rejects_a_different_signer_or_key() {
        let (key, signed) = signed_policy(7, "authority:gaugedesk");
        let wrong_signer = GaugeDeskGovernanceRoot::new("authority:attacker", key.clone());
        assert!(wrong_signer.verify_epoch(12, &signed).is_err());

        let (wrong_key, _) = signed_policy(9, "authority:gaugedesk");
        let wrong_root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", wrong_key);
        assert!(wrong_root.verify_epoch(12, &signed).is_err());
    }

    #[test]
    fn hosted_policy_rejects_tampering() {
        let (key, signed) = signed_policy(7, "authority:gaugedesk");
        let tampered = signed.replace("gpt-5", "gpt-5-mini");
        let root = GaugeDeskGovernanceRoot::new("authority:gaugedesk", key);
        assert!(root.verify_epoch(12, &tampered).is_err());
    }
}
