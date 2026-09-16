//! Host-supplied public verification material for portable norm history.
//! A signed event never supplies its own principal binding or public-key trust.

use serde::{Deserialize, Serialize};
use whipplescript_store::norm::NormActor;

use crate::gov::{ExternalAttestation, GovernanceAttestationVerifier};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormPublicKeyBinding {
    pub actor: NormActor,
    /// SEC1-encoded P-256 or a 32-byte Ed25519 verifying key, both in hex.
    /// This is independent of the actor's opaque, immutable key identity.
    pub public_key_hex: String,
}

enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

pub struct NormPublicKeyVerifier {
    actor: NormActor,
    key: PublicKey,
}
impl NormPublicKeyVerifier {
    pub fn new(binding: NormPublicKeyBinding) -> Result<Self, String> {
        let bytes =
            hex::decode(&binding.public_key_hex).map_err(|_| "norm public key is not valid hex")?;
        let key = match binding.actor.algorithm.as_str() {
            "p256-sha256" => PublicKey::P256(
                p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
                    .map_err(|_| "norm public key is not a P-256 point")?,
            ),
            crate::gov::GOVERNANCE_CUSTODIAN_ALGORITHM => {
                let bytes: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| "norm Ed25519 key must have 32 bytes")?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
                    .map_err(|_| "norm public key is not an Ed25519 point")?;
                if key.is_weak() {
                    return Err("norm Ed25519 key has small order".into());
                }
                PublicKey::Ed25519(key)
            }
            _ => {
                // MUTATION-SUCCESS-EXPR: Ok(Self { actor: binding.actor, key: PublicKey::P256(p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).expect("valid mutation fixture key")) })
                return Err("unsupported norm public-key algorithm".into());
            }
        };
        Ok(Self {
            actor: binding.actor,
            key,
        })
    }

    pub fn actor(&self) -> &NormActor {
        &self.actor
    }
}

impl GovernanceAttestationVerifier for NormPublicKeyVerifier {
    fn verify(&self, bytes: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
        if attestation.algorithm != self.actor.algorithm || attestation.key_id != self.actor.key_id
        {
            return Err("norm signature differs from its trusted public-key binding".into());
        }
        if !bytes.starts_with(b"whipplescript.norm.event.v1\0") {
            return Err("norm public-key verification requires its signing domain".into());
        }
        match &self.key {
            PublicKey::P256(key) => {
                use p256::ecdsa::signature::Verifier as _;
                let encoded = hex::decode(&attestation.signature)
                    .map_err(|_| "norm P-256 signature is not hex")?;
                let signature = p256::ecdsa::Signature::from_slice(&encoded)
                    .map_err(|_| "norm P-256 signature is not raw fixed-width ECDSA")?;
                key.verify(bytes, &signature)
                    .map_err(|_| "norm P-256 signature does not verify".into())
            }
            PublicKey::Ed25519(key) => {
                let encoded = crate::exec_http::base64_decode(&attestation.signature)
                    .ok_or("norm Ed25519 signature is not base64")?;
                let signature = ed25519_dalek::Signature::from_slice(&encoded)
                    .map_err(|_| "norm Ed25519 signature has invalid length")?;
                key.verify_strict(bytes, &signature)
                    .map_err(|_| "norm Ed25519 signature does not verify".into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
    use ed25519_dalek::Signer as _;
    use p256::ecdsa::signature::Signer as _;
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    use whipplescript_store::norm::NormVerifier;

    fn actor(algorithm: &str) -> NormActor {
        NormActor {
            principal: "owner".into(),
            algorithm: algorithm.into(),
            key_id: "immutable-key-version".into(),
        }
    }
    fn attestation(actor: &NormActor, signature: String) -> ExternalAttestation {
        ExternalAttestation {
            algorithm: actor.algorithm.clone(),
            key_id: actor.key_id.clone(),
            signature,
            epoch: None,
            authority: None,
        }
    }

    #[test]
    fn norm_public_keys_verify_both_host_encodings_without_granting_principal_trust() {
        let bytes = b"whipplescript.norm.event.v1\0exact statement bytes";
        let ed = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let p256 = p256::ecdsa::SigningKey::from_slice(&[9; 32]).expect("fixture key");
        let p256_signature: p256::ecdsa::Signature = p256.sign(bytes);
        for (actor, public_key_hex, signature) in [
            (
                actor(crate::gov::GOVERNANCE_CUSTODIAN_ALGORITHM),
                hex::encode(ed.verifying_key().as_bytes()),
                crate::exec_http::base64_encode(&ed.sign(bytes).to_bytes()),
            ),
            (
                actor("p256-sha256"),
                hex::encode(
                    p256.verifying_key()
                        .as_affine()
                        .to_sec1_point(true)
                        .as_bytes(),
                ),
                hex::encode(p256_signature.to_bytes()),
            ),
        ] {
            let verifier = NormPublicKeyVerifier::new(NormPublicKeyBinding {
                actor: actor.clone(),
                public_key_hex,
            })
            .expect("trusted key");
            let signed = attestation(&actor, signature.clone());
            assert!(verifier.verify(bytes, &signed).is_ok());
            assert!(verifier
                .verify(b"whipplescript.norm.event.v1\0altered", &signed)
                .is_err());
            assert!(verifier
                .verify(bytes, &attestation(&actor, "invalid".into()))
                .is_err());
            let mut wrong = signed.clone();
            wrong.key_id = "replacement".into();
            assert!(verifier.verify(bytes, &wrong).is_err());
            wrong = signed.clone();
            wrong.algorithm = "another algorithm".into();
            assert!(verifier.verify(bytes, &wrong).is_err());
            let bound = NormGovernanceVerifier::new(
                vec![NormPrincipalBinding {
                    actor: actor.clone(),
                    verifier: &verifier,
                }],
                Default::default(),
            )
            .expect("binding");
            assert!(bound.verify(&actor, bytes, &signature).is_ok());
            let mut impersonator = actor.clone();
            impersonator.principal = "another owner".into();
            assert!(bound.verify(&impersonator, bytes, &signature).is_err());
            assert!(bound.authorize_creation("worker", &actor).is_err());
        }
    }

    #[test]
    fn norm_public_keys_refuse_other_domains_even_with_valid_signatures() {
        let bytes = b"another signing protocol";
        let key = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
        let actor = actor(crate::gov::GOVERNANCE_CUSTODIAN_ALGORITHM);
        let verifier = NormPublicKeyVerifier::new(NormPublicKeyBinding {
            actor: actor.clone(),
            public_key_hex: hex::encode(key.verifying_key().as_bytes()),
        })
        .expect("key");
        assert!(verifier
            .verify(
                bytes,
                &attestation(
                    &actor,
                    crate::exec_http::base64_encode(&key.sign(bytes).to_bytes())
                )
            )
            .is_err());
    }

    #[test]
    fn norm_public_keys_refuse_invalid_or_weak_configuration() {
        let p256 = p256::ecdsa::SigningKey::from_slice(&[9; 32]).expect("fixture key");
        let valid_p256 = hex::encode(
            p256.verifying_key()
                .as_affine()
                .to_sec1_point(true)
                .as_bytes(),
        );
        for (algorithm, key) in [
            ("p256-sha256", "not-hex".into()),
            ("p256-sha256", "00".into()),
            (crate::gov::GOVERNANCE_CUSTODIAN_ALGORITHM, "00".into()),
            (crate::gov::GOVERNANCE_CUSTODIAN_ALGORITHM, "00".repeat(32)),
            ("unknown", valid_p256),
        ] {
            assert!(NormPublicKeyVerifier::new(NormPublicKeyBinding {
                actor: actor(algorithm),
                public_key_hex: key
            })
            .is_err());
        }
    }
}
