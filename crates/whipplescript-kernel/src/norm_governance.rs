//! Norm-ledger authentication through the existing cryptographic verifier seam.
//! Bindings and creation grants come from authenticated host configuration;
//! they are deliberately not deserializable request fields.

use std::collections::{BTreeMap, BTreeSet};

use crate::gov::{ExternalAttestation, GovernanceAttestationVerifier};
use whipplescript_store::norm::{NormActor, NormVerifier};

pub struct NormPrincipalBinding<'a> {
    pub actor: NormActor,
    pub verifier: &'a dyn GovernanceAttestationVerifier,
}

pub struct NormGovernanceVerifier<'a> {
    bindings: BTreeMap<NormActor, NormPrincipalBinding<'a>>,
    creation_grants: BTreeSet<(String, String)>,
}

impl<'a> NormGovernanceVerifier<'a> {
    pub fn new(
        bindings: Vec<NormPrincipalBinding<'a>>,
        creation_grants: BTreeSet<(String, String)>,
    ) -> Result<Self, String> {
        let mut indexed = BTreeMap::new();
        for binding in bindings {
            let repeated = indexed.insert(binding.actor.clone(), binding).is_some();
            if repeated {
                return Err("norm host configuration repeats a principal/key binding".into());
            }
        }
        Ok(Self {
            bindings: indexed,
            creation_grants,
        })
    }
}

impl NormVerifier for NormGovernanceVerifier<'_> {
    fn verify(
        &self,
        actor: &NormActor,
        signing_bytes: &[u8],
        signature: &str,
    ) -> Result<(), String> {
        let binding = self
            .bindings
            .get(actor)
            .ok_or("norm signer/key has no authenticated host binding")?;
        binding.verifier.verify(
            signing_bytes,
            &ExternalAttestation {
                algorithm: actor.algorithm.clone(),
                key_id: actor.key_id.clone(),
                signature: signature.into(),
                epoch: None,
                authority: None,
            },
        )
    }

    fn authorize_creation(&self, creator: &str, owner: &NormActor) -> Result<(), String> {
        if !self
            .creation_grants
            .contains(&(creator.into(), owner.principal.clone()))
        {
            // MUTATION-SUCCESS-EXPR: Ok(())
            return Err("no host grant to create for norm owner".into());
        }
        if !self.bindings.contains_key(owner) {
            return Err("norm genesis root has no authenticated owner/key binding".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct VerificationBoundary;
    impl GovernanceAttestationVerifier for VerificationBoundary {
        fn verify(&self, bytes: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
            if bytes == b"exact signed bytes" && attestation.signature == "verified" {
                Ok(())
            } else {
                Err("verification boundary refused".into())
            }
        }
    }
    fn owner() -> NormActor {
        NormActor {
            principal: "owner".into(),
            algorithm: "test-boundary".into(),
            key_id: "owner-key".into(),
        }
    }

    #[test]
    fn norm_binding_and_creation_permission_remain_independent() {
        let boundary = VerificationBoundary;
        let actor = owner();
        let bindings = || {
            vec![NormPrincipalBinding {
                actor: actor.clone(),
                verifier: &boundary,
            }]
        };
        assert!(NormGovernanceVerifier::new(
            vec![
                NormPrincipalBinding {
                    actor: actor.clone(),
                    verifier: &boundary
                },
                NormPrincipalBinding {
                    actor: actor.clone(),
                    verifier: &boundary
                }
            ],
            BTreeSet::new()
        )
        .is_err());
        let verifier = NormGovernanceVerifier::new(bindings(), BTreeSet::new()).unwrap();
        assert!(verifier
            .verify(&actor, b"exact signed bytes", "verified")
            .is_ok());
        assert!(verifier.verify(&actor, b"tampered", "verified").is_err());
        assert!(verifier.authorize_creation("worker", &actor).is_err());
        let verifier = NormGovernanceVerifier::new(
            bindings(),
            BTreeSet::from([("worker".into(), "owner".into())]),
        )
        .unwrap();
        assert!(verifier.authorize_creation("worker", &actor).is_ok());
        let mut unknown = actor.clone();
        unknown.key_id = "replacement".into();
        assert!(verifier
            .verify(&unknown, b"exact signed bytes", "verified")
            .is_err());
        assert!(verifier.authorize_creation("worker", &unknown).is_err());
    }
}
