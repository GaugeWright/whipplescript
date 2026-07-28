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

/// A pinned GaugeDesk governance root. The public key is SEC1-compressed and
/// hex encoded, matching GaugeDesk's `PublicKey` wire representation.
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
    use whipplescript_kernel::gov::{external_signing_bytes, SignedEnvelope};

    fn signed_policy(seed: u8, signer: &str) -> (String, String) {
        let key = SigningKey::from_slice(&[seed; 32]).expect("test key");
        let public_key = hex::encode(key.verifying_key().to_encoded_point(true).as_bytes());
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
