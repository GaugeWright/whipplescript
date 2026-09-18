//! Custody signing for norm commands. Configuration is supplied by the trusted
//! host, never deserialized from an act. Possession of this signer does not
//! supply a creation grant or bypass norm admission.

use std::num::NonZeroU32;

use whipplescript_custody::{
    CredentialName, CustodyCall, CustodyOk, CustodyOp, CustodyTransport, SignatureAlg,
    UseAttribution,
};
use whipplescript_store::norm::{NormAct, NormActor, NormStatement};

use crate::gov::{
    ExternalAttestation, GovernanceAttestationVerifier, GOVERNANCE_CUSTODIAN_ALGORITHM,
};

/// Local keys require immutable, distinct credential names. Versioned backends
/// always name a concrete version; there is deliberately no `Latest` variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormCustodyVersion {
    ImmutableLocal,
    Version(NonZeroU32),
}

impl NormCustodyVersion {
    fn number(self) -> Option<u32> {
        match self {
            Self::ImmutableLocal => None,
            Self::Version(version) => Some(version.get()),
        }
    }
}

pub struct NormCustodyKey<'a> {
    actor: NormActor,
    credential: CredentialName,
    version: NormCustodyVersion,
    transport: &'a dyn CustodyTransport,
}

impl<'a> NormCustodyKey<'a> {
    pub fn new(
        principal: String,
        credential: CredentialName,
        version: NormCustodyVersion,
        transport: &'a dyn CustodyTransport,
    ) -> Result<Self, String> {
        if principal.trim().is_empty() {
            return Err("norm custody binding needs an authenticated principal".into());
        }
        // CredentialName's serde representation is transparent; validate even
        // when the embedding loaded a name from its own configuration.
        let credential = CredentialName::new(credential.as_str())?;
        let suffix = match version {
            NormCustodyVersion::ImmutableLocal => "local".into(),
            NormCustodyVersion::Version(version) => format!("v{version}"),
        };
        let actor = NormActor {
            principal,
            algorithm: GOVERNANCE_CUSTODIAN_ALGORITHM.into(),
            key_id: format!("{}#{suffix}", credential.resource_id()),
        };
        Ok(Self {
            actor,
            credential,
            version,
            transport,
        })
    }

    pub fn actor(&self) -> &NormActor {
        &self.actor
    }

    pub fn sign(&self, statement: &NormStatement) -> Result<String, String> {
        if statement.actor != self.actor {
            return Err("norm primary signer differs from its host binding".into());
        }
        self.sign_bytes(statement)
    }

    pub fn cosign_rotation(&self, statement: &NormStatement) -> Result<String, String> {
        let named_successor = matches!(
            &statement.action,
            NormAct::Rotate { successor, .. } if successor == &self.actor
        );
        if !named_successor {
            return Err("norm co-signer is not the named rotation successor".into());
        }
        self.sign_bytes(statement)
    }

    fn sign_bytes(&self, statement: &NormStatement) -> Result<String, String> {
        let bytes = statement
            .signing_bytes()
            .map_err(|error| format!("{error:?}"))?;
        let reply = self
            .transport
            .call(CustodyCall::new(
                UseAttribution {
                    run_id: "norm-sign".into(),
                    actor: Some(self.actor.principal.clone()),
                    // No runtime effect is established by an authoring nonce.
                    effect_key: None,
                },
                CustodyOp::Sign {
                    credential: self.credential.clone(),
                    alg: SignatureAlg::Ed25519,
                    derivation: Vec::new(),
                    payload_b64: crate::exec_http::base64_encode(&bytes),
                },
            ))
            .map_err(|error| format!("norm custodian unreachable: {error}"))?;
        let (signature_b64, key_version) = match reply.outcome {
            Ok(CustodyOk::Signed {
                signature_b64,
                key_version,
            }) => (signature_b64, key_version),
            Ok(_) => {
                // MUTATION-SUCCESS-EXPR: Ok(String::new())
                return Err("norm custodian returned a non-signature".into());
            }
            Err(error) => {
                // MUTATION-SUCCESS-EXPR: Ok(String::new())
                return Err(format!("norm custodian refused signing: {error}"));
            }
        };
        if key_version != self.version.number() {
            return Err("norm signing key version changed; prepare again".into());
        }
        Ok(signature_b64)
    }
}

impl GovernanceAttestationVerifier for NormCustodyKey<'_> {
    fn verify(&self, bytes: &[u8], attestation: &ExternalAttestation) -> Result<(), String> {
        if attestation.algorithm != self.actor.algorithm || attestation.key_id != self.actor.key_id
        {
            return Err("norm attestation differs from its pinned custody key".into());
        }
        if !bytes.starts_with(b"whipplescript.norm.event.v1\0") {
            return Err("norm custody verification requires its signing domain".into());
        }
        let reply = self
            .transport
            .call(CustodyCall::new(
                UseAttribution {
                    run_id: "norm-verify".into(),
                    actor: Some(self.actor.principal.clone()),
                    effect_key: None,
                },
                CustodyOp::Verify {
                    credential: self.credential.clone(),
                    alg: SignatureAlg::Ed25519,
                    payload_b64: crate::exec_http::base64_encode(bytes),
                    signature_b64: attestation.signature.clone(),
                    key_version: self.version.number(),
                },
            ))
            .map_err(|error| format!("norm custodian unreachable: {error}"))?;
        let valid = match reply.outcome {
            Ok(CustodyOk::Verified { valid }) => valid,
            Ok(_) => {
                // MUTATION-SUCCESS-EXPR: Ok(())
                return Err("norm custodian returned a non-verification".into());
            }
            Err(error) => {
                // MUTATION-SUCCESS-EXPR: Ok(())
                return Err(format!("norm custodian refused verification: {error}"));
            }
        };
        if !valid {
            return Err("norm custody signature is invalid".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::norm_governance::{NormGovernanceVerifier, NormPrincipalBinding};
    use std::collections::BTreeSet;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    };
    use whipplescript_custody::{CustodyReply, Rung, TransportError};
    use whipplescript_store::norm::{NormCharter, SignedNormEvent};

    fn statement(actor: &NormActor, nonce: &str) -> NormStatement {
        NormStatement {
            premises: None,
            protocol: "whipplescript.norm/v1".into(),
            actor: actor.clone(),
            nonce: nonce.into(),
            created_at: "2026-09-05T00:00:00Z".into(),
            action: NormAct::Bootstrap {
                creator: "worker".into(),
                charter: NormCharter::bundled().expect("defaults"),
            },
        }
    }
    fn attestation(key: &NormCustodyKey<'_>, signature: String) -> ExternalAttestation {
        ExternalAttestation {
            algorithm: key.actor.algorithm.clone(),
            key_id: key.actor.key_id.clone(),
            signature,
            epoch: None,
            authority: None,
        }
    }
    fn version(n: u32) -> NormCustodyVersion {
        NormCustodyVersion::Version(NonZeroU32::new(n).expect("nonzero fixture"))
    }
    fn credential() -> CredentialName {
        CredentialName::new("norm/owner").expect("name")
    }

    // A version-routing fixture, not a cryptographic implementation. It models
    // the backend default moving while historical versions remain verifiable.
    struct VersionedTransport {
        current: AtomicU32,
        calls: Mutex<Vec<CustodyCall>>,
    }
    impl CustodyTransport for VersionedTransport {
        fn call(&self, call: CustodyCall) -> Result<CustodyReply, TransportError> {
            self.calls.lock().expect("calls").push(call.clone());
            let outcome = match call.op {
                CustodyOp::Sign { payload_b64, .. } => {
                    let v = self.current.load(Ordering::SeqCst);
                    CustodyOk::Signed {
                        signature_b64: format!("{v}:{payload_b64}"),
                        key_version: Some(v),
                    }
                }
                CustodyOp::Verify {
                    payload_b64,
                    signature_b64,
                    key_version,
                    ..
                } => {
                    let v = key_version.unwrap_or(self.current.load(Ordering::SeqCst));
                    CustodyOk::Verified {
                        valid: signature_b64 == format!("{v}:{payload_b64}"),
                    }
                }
                _ => panic!("unexpected custody operation"),
            };
            Ok(CustodyReply {
                use_id: "fixture".into(),
                rung: Rung::Process,
                degraded: false,
                outcome: Ok(outcome),
            })
        }
    }

    #[test]
    fn norm_custody_pins_versions_across_signing_races_and_historical_verification() {
        let transport = VersionedTransport {
            current: AtomicU32::new(1),
            calls: Mutex::new(Vec::new()),
        };
        let old =
            NormCustodyKey::new("owner".into(), credential(), version(1), &transport).unwrap();
        let new =
            NormCustodyKey::new("owner".into(), credential(), version(2), &transport).unwrap();
        assert_ne!(old.actor(), new.actor());
        let original = statement(old.actor(), "bootstrap");
        let signature = old.sign(&original).unwrap();
        let bytes = original.signing_bytes().unwrap();
        transport.current.store(2, Ordering::SeqCst);
        assert!(old.sign(&original).is_err());
        old.verify(&bytes, &attestation(&old, signature.clone()))
            .unwrap();
        assert!(old
            .verify(
                &bytes,
                &attestation(
                    &old,
                    format!("2:{}", crate::exec_http::base64_encode(&bytes))
                )
            )
            .is_err());
        let local = NormCustodyKey::new(
            "owner".into(),
            credential(),
            NormCustodyVersion::ImmutableLocal,
            &transport,
        )
        .unwrap();
        assert!(local.sign(&statement(local.actor(), "no-default")).is_err());
        assert!(new.sign(&original).is_err());
        assert!(new.cosign_rotation(&original).is_err());
        let mut rotation = original.clone();
        rotation.action = NormAct::Rotate {
            ledger: "ledger".into(),
            previous: "previous".into(),
            successor: new.actor().clone(),
            frontier: vec![],
        };
        let co_signature = new.cosign_rotation(&rotation).unwrap();
        new.verify(
            &rotation.signing_bytes().unwrap(),
            &attestation(&new, co_signature),
        )
        .unwrap();
        assert!(old.cosign_rotation(&rotation).is_err());
        let unrelated =
            NormCustodyKey::new("worker".into(), credential(), version(2), &transport).unwrap();
        assert!(unrelated.cosign_rotation(&rotation).is_err());
        let calls = transport.calls.lock().unwrap();
        assert!(calls
            .iter()
            .all(|call| call.attribution.effect_key.is_none()));
        assert!(calls.iter().any(|call| matches!(
            call.op,
            CustodyOp::Verify {
                key_version: Some(1),
                ..
            }
        )));
        assert!(calls.iter().any(|call| matches!(
            call.op,
            CustodyOp::Verify {
                key_version: Some(2),
                ..
            }
        )));
    }

    #[test]
    fn norm_custody_binding_and_domain_are_checked_before_transport() {
        let transport = VersionedTransport {
            current: AtomicU32::new(1),
            calls: Mutex::new(Vec::new()),
        };
        assert!(NormCustodyKey::new(" ".into(), credential(), version(1), &transport).is_err());
        let bad: CredentialName = serde_json::from_str("\"BAD\"").unwrap();
        assert!(NormCustodyKey::new("owner".into(), bad, version(1), &transport).is_err());
        let key =
            NormCustodyKey::new("owner".into(), credential(), version(1), &transport).unwrap();
        let stmt = statement(key.actor(), "one");
        let bytes = stmt.signing_bytes().unwrap();
        let sig = key.sign(&stmt).unwrap();
        let mut proof = attestation(&key, sig);
        proof.algorithm = "checksum".into();
        assert!(key.verify(&bytes, &proof).is_err());
        proof.algorithm = key.actor().algorithm.clone();
        proof.key_id = "another-key".into();
        assert!(key.verify(&bytes, &proof).is_err());
        let foreign = b"another signing domain";
        let proof = attestation(
            &key,
            format!("1:{}", crate::exec_http::base64_encode(foreign)),
        );
        assert!(key.verify(foreign, &proof).is_err());
        let mut impostor = stmt;
        impostor.actor.principal = "worker".into();
        assert!(key.sign(&impostor).is_err());
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }

    struct BrokenTransport(Result<CustodyReply, TransportError>);
    impl CustodyTransport for BrokenTransport {
        fn call(&self, _: CustodyCall) -> Result<CustodyReply, TransportError> {
            self.0.clone()
        }
    }
    #[test]
    fn norm_custody_does_not_substitute_success_for_transport_or_reply_failures() {
        for outcome in [
            Err(TransportError::Unavailable("offline".into())),
            Ok(CustodyReply {
                use_id: "denied".into(),
                rung: Rung::Process,
                degraded: false,
                outcome: Err(whipplescript_custody::CustodyError::Revoked {
                    credential: credential(),
                }),
            }),
            Ok(CustodyReply {
                use_id: "wrong".into(),
                rung: Rung::Process,
                degraded: false,
                outcome: Ok(CustodyOk::Verified { valid: false }),
            }),
            Ok(CustodyReply {
                use_id: "wrong".into(),
                rung: Rung::Process,
                degraded: false,
                outcome: Ok(CustodyOk::Signed {
                    signature_b64: "sig".into(),
                    key_version: Some(2),
                }),
            }),
        ] {
            let transport = BrokenTransport(outcome);
            let key =
                NormCustodyKey::new("owner".into(), credential(), version(1), &transport).unwrap();
            let stmt = statement(key.actor(), "one");
            assert!(key.sign(&stmt).is_err());
            assert!(key
                .verify(
                    &stmt.signing_bytes().unwrap(),
                    &attestation(&key, "sig".into())
                )
                .is_err());
        }
    }

    #[cfg(feature = "native")]
    #[test]
    fn norm_custody_real_signatures_admit_genesis_and_dual_signed_succession() {
        use whipplescript_custodian::store::SealedStore;
        use whipplescript_custodian::{Custodian, DeniedEgress, InProcessTransport};
        let mut sealed = SealedStore::create(None, "fixture-password").unwrap();
        let first = credential();
        let second = CredentialName::new("norm/successor").unwrap();
        for (name, byte) in [(first.clone(), 1), (second.clone(), 2)] {
            sealed
                .register(
                    name,
                    whipplescript_custody::CredentialKind::Ed25519,
                    zeroize::Zeroizing::new(vec![byte; 32]),
                    None,
                    None,
                )
                .unwrap();
        }
        let custodian = Arc::new(Custodian::new(sealed, Box::new(DeniedEgress)));
        let transport = InProcessTransport::new(custodian);
        let old = NormCustodyKey::new(
            "owner".into(),
            first,
            NormCustodyVersion::ImmutableLocal,
            &transport,
        )
        .unwrap();
        let next = NormCustodyKey::new(
            "owner".into(),
            second,
            NormCustodyVersion::ImmutableLocal,
            &transport,
        )
        .unwrap();
        let bindings = || {
            vec![
                NormPrincipalBinding {
                    actor: old.actor().clone(),
                    verifier: &old,
                },
                NormPrincipalBinding {
                    actor: next.actor().clone(),
                    verifier: &next,
                },
            ]
        };
        let no_grants = NormGovernanceVerifier::new(bindings(), BTreeSet::new()).unwrap();
        let verifier = NormGovernanceVerifier::new(
            bindings(),
            BTreeSet::from([("worker".into(), "owner".into())]),
        )
        .unwrap();
        let stmt = statement(old.actor(), "bootstrap");
        let genesis = SignedNormEvent {
            signature: old.sign(&stmt).unwrap(),
            statement: stmt,
            successor_signature: None,
        };
        let mut store = whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
        assert!(store.append_norm_event(&genesis, &no_grants).is_err());
        let ledger = store.append_norm_event(&genesis, &verifier).unwrap();
        let definition = NormCharter::bundled()
            .unwrap()
            .vocabularies
            .into_iter()
            .find(|entry| entry.definition.name == "decision")
            .unwrap()
            .definition;
        let vocabulary = whipplescript_core::vocabulary::Vocabulary::new(definition)
            .unwrap()
            .reference()
            .clone();
        let creation = NormStatement {
            action: NormAct::Create {
                ledger: ledger.clone(),
                authority: None,
                vocabulary: vocabulary.clone(),
                fields_json:
                    r#"{"title":"repair","intent":"deny worker","subjects":["src/auth.py"]}"#.into(),
            },
            ..statement(old.actor(), "create")
        };
        let event = SignedNormEvent {
            signature: old.sign(&creation).unwrap(),
            statement: creation,
            successor_signature: None,
        };
        let record = store.append_norm_event(&event, &verifier).unwrap();
        let view = store.norm_view(&verifier).unwrap();
        let rotation = NormStatement {
            action: NormAct::Rotate {
                ledger: ledger.clone(),
                previous: view.authority_head,
                successor: next.actor().clone(),
                frontier: view.frontier.into_iter().collect(),
            },
            ..statement(old.actor(), "rotate")
        };
        let rotated = SignedNormEvent {
            signature: old.sign(&rotation).unwrap(),
            successor_signature: Some(next.cosign_rotation(&rotation).unwrap()),
            statement: rotation,
        };
        let mut forged = rotated.clone();
        forged.successor_signature = Some(genesis.signature.clone());
        assert!(store.append_norm_event(&forged, &verifier).is_err());
        store.append_norm_event(&rotated, &verifier).unwrap();
        assert_eq!(store.norm_view(&verifier).unwrap().owner, *next.actor());
        let authority = store.norm_checkpoint().unwrap().unwrap().authority_head;
        let mut acceptance = NormStatement {
            action: NormAct::Transition {
                ledger,
                authority: Some(authority),
                vocabulary,
                record: record.clone(),
                previous: record.clone(),
                status: "accepted".into(),
            },
            ..statement(old.actor(), "accept")
        };
        let denied = SignedNormEvent {
            signature: old.sign(&acceptance).unwrap(),
            statement: acceptance.clone(),
            successor_signature: None,
        };
        assert!(store.append_norm_event(&denied, &verifier).is_err());
        acceptance.actor = next.actor().clone();
        let accepted = SignedNormEvent {
            signature: next.sign(&acceptance).unwrap(),
            statement: acceptance,
            successor_signature: None,
        };
        store.append_norm_event(&accepted, &verifier).unwrap();
        assert_eq!(
            store.norm_view(&verifier).unwrap().records[&record].status,
            "accepted"
        );
        let mut restored = whipplescript_store::items::WorkItemStore::open_in_memory().unwrap();
        restored
            .pin_norm_checkpoint(&store.norm_checkpoint().unwrap().unwrap())
            .unwrap();
        restored
            .import_norm_events(&store.export_events().unwrap(), &no_grants)
            .unwrap();
        let recovered = restored.norm_view(&no_grants).unwrap();
        assert_eq!(recovered.owner, *next.actor());
        assert_eq!(
            recovered.checkpoint(),
            store.norm_view(&verifier).unwrap().checkpoint()
        );
        assert_eq!(
            restored.export_events().unwrap(),
            store.export_events().unwrap()
        );
    }
}
