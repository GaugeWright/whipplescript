#[path = "support/scratch.rs"]
mod scratch;
#[cfg(all(test, feature = "native"))]
mod tests {
    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::ecdsa::{Signature, SigningKey};
    use p256::elliptic_curve::sec1::ToSec1Point;
    use serde_json::json;
    use std::collections::BTreeMap;
    use whipplescript_core::vocabulary::{AdmissionPredicate, Vocabulary, VocabularyDefinition};
    use whipplescript_store::items::WorkItemStore;
    use whipplescript_store::norm::*;
    use whipplescript_store::StoreError;

    struct Keys {
        keys: BTreeMap<String, SigningKey>,
        permit_creation: bool,
    }
    impl Keys {
        fn new() -> Self {
            Self {
                keys: BTreeMap::from([
                    (
                        "owner".into(),
                        SigningKey::from_slice(&[1; 32]).expect("test key"),
                    ),
                    (
                        "owner2".into(),
                        SigningKey::from_slice(&[3; 32]).expect("test key"),
                    ),
                    (
                        "owner3".into(),
                        SigningKey::from_slice(&[4; 32]).expect("test key"),
                    ),
                    (
                        "worker".into(),
                        SigningKey::from_slice(&[2; 32]).expect("test key"),
                    ),
                ]),
                permit_creation: true,
            }
        }
        fn actor(&self, principal: &str) -> NormActor {
            NormActor {
                principal: if principal.starts_with("owner") {
                    "owner"
                } else {
                    principal
                }
                .into(),
                algorithm: "p256-sha256".into(),
                key_id: hex::encode(
                    self.keys[principal]
                        .verifying_key()
                        .as_affine()
                        .to_sec1_point(true)
                        .as_bytes(),
                ),
            }
        }
        fn sign(&self, principal: &str, nonce: &str, action: NormAct) -> SignedNormEvent {
            self.sign_with(principal, nonce, action, None)
        }
        fn sign_with(
            &self,
            principal: &str,
            nonce: &str,
            action: NormAct,
            premises: Option<NormPremises>,
        ) -> SignedNormEvent {
            let statement = NormStatement {
                protocol: "whipplescript.norm/v1".into(),
                actor: self.actor(principal),
                nonce: nonce.into(),
                created_at: "2026-09-05T00:00:00Z".into(),
                action,
                premises,
            };
            let signature: Signature =
                self.keys[principal].sign(&statement.signing_bytes().expect("bytes"));
            SignedNormEvent {
                successor_signature: None,
                statement,
                signature: hex::encode(signature.to_bytes()),
            }
        }
        fn bootstrap(&self) -> SignedNormEvent {
            self.sign(
                "owner",
                "genesis",
                NormAct::Bootstrap {
                    creator: "worker".into(),
                    charter: charter(),
                },
            )
        }
        fn create(&self, ledger: &str, nonce: &str) -> SignedNormEvent {
            self.sign(
                "worker",
                nonce,
                NormAct::Create {
                    authority: None,
                    ledger: ledger.into(),
                    vocabulary: Vocabulary::new(definition())
                        .expect("definition")
                        .reference()
                        .clone(),
                    fields_json: r#"{"title":"repair authorization"}"#.into(),
                },
            )
        }
        fn change(
            &self,
            actor: &str,
            nonce: &str,
            ledger: &str,
            record: &str,
            status: &str,
        ) -> SignedNormEvent {
            self.sign(
                actor,
                nonce,
                NormAct::Transition {
                    authority: None,
                    ledger: ledger.into(),
                    vocabulary: Vocabulary::new(definition())
                        .expect("definition")
                        .reference()
                        .clone(),
                    record: record.into(),
                    previous: record.into(),
                    status: status.into(),
                },
            )
        }
    }
    impl Keys {
        fn rotate(&self, view: &NormView, from: &str, to: &str, nonce: &str) -> SignedNormEvent {
            let event = self.sign(
                from,
                nonce,
                NormAct::Rotate {
                    ledger: view.ledger.clone(),
                    previous: view.authority_head.clone(),
                    successor: self.actor(to),
                    frontier: view.frontier.iter().cloned().collect(),
                },
            );
            self.cosign(event, to)
        }
        fn cosign(&self, mut event: SignedNormEvent, to: &str) -> SignedNormEvent {
            let signature: Signature = self.keys[to].sign(
                &event
                    .statement
                    .signing_bytes()
                    .expect("rotation signing bytes"),
            );
            event.successor_signature = Some(hex::encode(signature.to_bytes()));
            event
        }
        fn edit(
            &self,
            view: &NormView,
            record: &str,
            fields: &str,
            key: &str,
            nonce: &str,
        ) -> SignedNormEvent {
            let current = &view.records[record];
            self.sign(
                key,
                nonce,
                NormAct::Edit {
                    ledger: view.ledger.clone(),
                    authority: Some(view.authority_head.clone()),
                    vocabulary: current.vocabulary.clone(),
                    record: record.into(),
                    previous: current.head.clone(),
                    fields_json: fields.into(),
                },
            )
        }
        fn at_epoch(
            &self,
            key: &str,
            nonce: &str,
            view: &NormView,
            mut action: NormAct,
        ) -> SignedNormEvent {
            match &mut action {
                NormAct::Create { authority, .. }
                | NormAct::Transition { authority, .. }
                | NormAct::Edit { authority, .. } => *authority = Some(view.authority_head.clone()),
                _ => panic!("record fixture expected"),
            }
            self.sign(key, nonce, action)
        }
    }
    impl NormVerifier for Keys {
        fn verify(&self, actor: &NormActor, bytes: &[u8], signature: &str) -> Result<(), String> {
            let (_, key) = self
                .keys
                .iter()
                .find(|(name, _)| actor == &self.actor(name))
                .ok_or("unbound principal/key")?;
            let signature = hex::decode(signature).map_err(|e| e.to_string())?;
            let signature = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
            key.verifying_key()
                .verify(bytes, &signature)
                .map_err(|e| e.to_string())
        }
        fn authorize_creation(&self, creator: &str, owner: &NormActor) -> Result<(), String> {
            if self.permit_creation && creator == "worker" && owner == &self.actor("owner") {
                Ok(())
            } else {
                Err("creation not authorized".into())
            }
        }
    }
    fn definition() -> VocabularyDefinition {
        serde_json::from_value(json!({"name":"decision","version":"1","fields":[{"name":"title","required":true,"value_type":{"type":"text"}}],"status":{"values":["proposed","accepted","withdrawn"],"initial":"proposed","transitions":[{"from":"proposed","to":"accepted","admission":{"requires":"authority","scope":"accept"}},{"from":"proposed","to":"withdrawn","admission":{"requires":"public"}}]}})).expect("fixture")
    }
    fn charter() -> NormCharter {
        NormCharter {
            resource_domains: None,
            vocabularies: vec![NormVocabulary {
                relation: None,
                manifest: None,
                correspondence: None,
                editing: None,
                effectiveness: None,
                inventory_role: None,
                definition: definition(),
                creation: AdmissionPredicate::Public {},
            }],
            owner_scopes: vec!["accept".into()],
        }
    }

    #[test]
    fn norm_native_signed_creation_authority_retry_and_replay() {
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let bootstrap = keys.bootstrap();
        let ledger = store.append_norm_event(&bootstrap, &keys).unwrap();
        assert_eq!(store.append_norm_event(&bootstrap, &keys).unwrap(), ledger);
        let record = store
            .append_norm_event(&keys.create(&ledger, "D0"), &keys)
            .unwrap();
        let before = store.export_events().unwrap();
        assert!(store
            .append_norm_event(
                &keys.change("worker", "denied", &ledger, &record, "accepted"),
                &keys
            )
            .is_err());
        assert_eq!(store.export_events().unwrap(), before);
        assert_eq!(
            store.norm_view(&keys).unwrap().records[&record].status,
            "proposed"
        );
        let accepted = keys.change("owner", "accept", &ledger, &record, "accepted");
        let head = store.append_norm_event(&accepted, &keys).unwrap();
        assert_eq!(store.append_norm_event(&accepted, &keys).unwrap(), head);
        store.rebuild_projection().unwrap();
        let view = store.norm_view(&keys).unwrap();
        assert_eq!(view.owner, keys.actor("owner"));
        assert_eq!(view.records[&record].head, head);
        assert_eq!(view.records[&record].status, "accepted");
        assert_eq!(view.records[&record].id, record);
        assert_eq!(
            view.records[&record].fields,
            json!({"title":"repair authorization"})
        );
        assert_eq!(store.export_events().unwrap().len(), 3);
        let mut revoked_creation = Keys::new();
        revoked_creation.permit_creation = false;
        assert_eq!(
            store.norm_view(&revoked_creation).unwrap().records,
            view.records
        );
    }
    #[test]
    fn norm_native_import_restores_only_original_pinned_genesis() {
        let keys = Keys::new();
        let mut source = WorkItemStore::open_in_memory().unwrap();
        let ledger = source.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        source
            .append_norm_event(&keys.create(&ledger, "D0"), &keys)
            .unwrap();
        let exported = source.export_events().unwrap();
        let mut dest = WorkItemStore::open_in_memory().unwrap();
        assert!(dest.import_norm_events(&exported, &keys).is_err());
        assert!(dest.export_events().unwrap().is_empty());
        dest.pin_norm_ledger(&ledger).unwrap();
        assert!(dest.norm_view(&keys).is_err());
        assert!(matches!(dest.import_norm_events(&exported[1..], &keys),
            Err(StoreError::Conflict(message)) if message.contains("pinned norm genesis is missing")));
        assert_eq!(dest.norm_ledger_id().unwrap(), Some(ledger.clone()));
        assert!(dest.export_events().unwrap().is_empty());
        let other = keys.sign(
            "owner",
            "other",
            NormAct::Bootstrap {
                creator: "worker".into(),
                charter: charter(),
            },
        );
        assert!(dest.append_norm_event(&other, &keys).is_err());
        assert!(dest
            .pin_norm_ledger(&other.tracker_event().unwrap().event_id)
            .is_err());
        let mut reversed = exported.clone();
        reversed.reverse();
        assert_eq!(dest.import_norm_events(&reversed, &keys).unwrap(), 2);
        assert_eq!(dest.import_norm_events(&reversed, &keys).unwrap(), 0);
        assert_eq!(
            dest.norm_view(&keys).unwrap().records,
            source.norm_view(&keys).unwrap().records
        );
        let mut legacy = WorkItemStore::open_in_memory().unwrap();
        assert_eq!(legacy.import_events(&exported).unwrap().rejected, 2);
        assert!(legacy.export_events().unwrap().is_empty());
        let mut forged = keys.create(&ledger, "forged");
        forged.signature = "00".repeat(64);
        assert!(dest.append_norm_event(&forged, &keys).is_err());
        assert_eq!(dest.export_events().unwrap().len(), 2);
    }
    #[test]
    fn norm_native_refuses_missing_rules_wrong_versions_and_invalid_shapes() {
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let record = store
            .append_norm_event(&keys.create(&ledger, "D0"), &keys)
            .unwrap();
        for (nonce, status) in [("missing-rule", "proposed"), ("bad-status", "imagined")] {
            assert!(store
                .append_norm_event(
                    &keys.change("owner", nonce, &ledger, &record, status),
                    &keys
                )
                .is_err());
        }
        let mut d = definition();
        d.version = "2".into();
        let reference = Vocabulary::new(d).unwrap().reference().clone();
        let wrong = keys.sign(
            "owner",
            "wrong-version",
            NormAct::Transition {
                authority: None,
                ledger: ledger.clone(),
                vocabulary: reference,
                record: record.clone(),
                previous: record.clone(),
                status: "accepted".into(),
            },
        );
        assert!(store.append_norm_event(&wrong, &keys).is_err());
        let missing = keys.change("owner", "missing-record", &ledger, &ledger, "accepted");
        assert!(store.append_norm_event(&missing, &keys).is_err());
        for (nonce, fields_json) in [
            ("empty", "{}"),
            ("duplicate", r#"{"title":"one","title":"two"}"#),
        ] {
            let bad = keys.sign(
                "worker",
                nonce,
                NormAct::Create {
                    authority: None,
                    ledger: ledger.clone(),
                    vocabulary: Vocabulary::new(definition()).unwrap().reference().clone(),
                    fields_json: fields_json.into(),
                },
            );
            assert!(store.append_norm_event(&bad, &keys).is_err());
        }
        store
            .append_norm_event(
                &keys.change("worker", "withdraw", &ledger, &record, "withdrawn"),
                &keys,
            )
            .unwrap();
        assert_eq!(
            store.norm_view(&keys).unwrap().records[&record].status,
            "withdrawn"
        );
    }
    #[test]
    fn norm_native_pin_persists_and_failed_write_rolls_back_bootstrap() {
        let path = crate::scratch::file("whip-norm", "sqlite");
        let keys = Keys::new();
        let ledger;
        {
            let mut store = WorkItemStore::open(&path).unwrap();
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection.execute_batch("CREATE TRIGGER fail_norm BEFORE INSERT ON tracker_events WHEN NEW.kind LIKE 'norm.%' BEGIN SELECT RAISE(ABORT, 'injected failure'); END;").unwrap();
            assert!(store.append_norm_event(&keys.bootstrap(), &keys).is_err());
            assert_eq!(store.norm_ledger_id().unwrap(), None);
            assert!(store.export_events().unwrap().is_empty());
            connection.execute_batch("DROP TRIGGER fail_norm").unwrap();
            ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        }
        {
            let store = WorkItemStore::open(&path).unwrap();
            assert_eq!(store.norm_ledger_id().unwrap(), Some(ledger.clone()));
            assert_eq!(store.norm_view(&keys).unwrap().ledger, ledger);
        }
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn norm_native_rejects_forged_metadata_nonce_reuse_and_invalid_charters() {
        let keys = Keys::new();
        for mutate in 0..4 {
            let mut c = charter();
            match mutate {
                0 => c.owner_scopes.push("accept".into()),
                1 => c.owner_scopes = vec!["".into()],
                2 => c.vocabularies.push(c.vocabularies[0].clone()),
                _ => c.owner_scopes.clear(),
            }
            let event = keys.sign(
                "owner",
                "bad-charter",
                NormAct::Bootstrap {
                    creator: "worker".into(),
                    charter: c,
                },
            );
            let mut store = WorkItemStore::open_in_memory().unwrap();
            assert!(store.append_norm_event(&event, &keys).is_err());
            assert_eq!(store.norm_ledger_id().unwrap(), None);
            assert!(store.export_events().unwrap().is_empty());
        }
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let mut denied_keys = Keys::new();
        denied_keys.permit_creation = false;
        assert!(store
            .append_norm_event(&denied_keys.bootstrap(), &denied_keys)
            .is_err());
        assert_eq!(store.norm_ledger_id().unwrap(), None);
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let replacement = keys.sign(
            "owner",
            "replacement-genesis",
            NormAct::Bootstrap {
                creator: "worker".into(),
                charter: charter(),
            },
        );
        assert!(store.append_norm_event(&replacement, &keys).is_err());
        let creation = keys.create(&ledger, "D0");
        let record = store.append_norm_event(&creation, &keys).unwrap();
        let mut collision = creation.tracker_event().unwrap();
        collision.actor = Some("forged".into());
        assert!(store
            .import_norm_events(&[collision, creation.tracker_event().unwrap()], &keys)
            .is_err());
        let mut metadata = keys.create(&ledger, "metadata").tracker_event().unwrap();
        metadata.actor = Some("forged".into());
        assert!(store.import_norm_events(&[metadata], &keys).is_err());
        let mut statement = keys.create(&ledger, "bad-protocol").statement;
        statement.protocol = "whipplescript.norm/v0".into();
        let sig: Signature = keys.keys["worker"].sign(&statement.signing_bytes().unwrap());
        assert!(store
            .append_norm_event(
                &SignedNormEvent {
                    successor_signature: None,
                    statement,
                    signature: hex::encode(sig.to_bytes())
                },
                &keys
            )
            .is_err());
        let reused = keys.sign(
            "worker",
            "D0",
            NormAct::Create {
                authority: None,
                ledger: ledger.clone(),
                vocabulary: Vocabulary::new(definition()).unwrap().reference().clone(),
                fields_json: r#"{"title":"another invocation"}"#.into(),
            },
        );
        assert!(store.append_norm_event(&reused, &keys).is_err());
        let stale = keys.sign(
            "owner",
            "stale",
            NormAct::Transition {
                authority: None,
                ledger: ledger.clone(),
                vocabulary: Vocabulary::new(definition()).unwrap().reference().clone(),
                record: record.clone(),
                previous: ledger.clone(),
                status: "accepted".into(),
            },
        );
        assert!(store.append_norm_event(&stale, &keys).is_err());
        let wrong_root = keys.at_epoch(
            "worker",
            "wrong-root",
            &store.norm_view(&keys).unwrap(),
            keys.create(&record, "ignored").statement.action,
        );
        assert!(store.append_norm_event(&wrong_root, &keys).is_err());
        let foreign = keys.create(&"f".repeat(64), "foreign");
        assert!(store.append_norm_event(&foreign, &keys).is_err());
        assert!(store.pin_norm_ledger("invalid").is_err());
        let mut not_norm = creation.tracker_event().unwrap();
        not_norm.kind = "issue.created".into();
        assert!(store.import_norm_events(&[not_norm], &keys).is_err());
        assert_eq!(store.export_events().unwrap().len(), 2);
    }
    #[test]
    fn norm_native_creation_permission_is_explicit_and_scoped() {
        let keys = Keys::new();
        let missing = serde_json::json!({"definition":definition()});
        assert!(serde_json::from_value::<NormVocabulary>(missing).is_err());
        let mut store = WorkItemStore::open_in_memory().unwrap();
        assert!(matches!(store.norm_view(&keys),
            Err(StoreError::Conflict(message)) if message.contains("norm ledger is not bootstrapped or pinned")));
        assert!(
            matches!(store.append_norm_event(&keys.create(&"a".repeat(64), "no-genesis"), &keys),
            Err(StoreError::Conflict(message)) if message.contains("norm genesis must be a bootstrap act"))
        );
        let mut policy = charter();
        policy.vocabularies[0].creation = AdmissionPredicate::Authority {
            scope: "accept".into(),
        };
        let bootstrap = keys.sign(
            "owner",
            "private-genesis",
            NormAct::Bootstrap {
                creator: "worker".into(),
                charter: policy,
            },
        );
        let ledger = store.append_norm_event(&bootstrap, &keys).unwrap();
        assert!(store
            .append_norm_event(&keys.create(&ledger, "worker-create"), &keys)
            .is_err());
        let owner_create = keys.sign(
            "owner",
            "owner-create",
            keys.create(&ledger, "ignored").statement.action,
        );
        store.append_norm_event(&owner_create, &keys).unwrap();
        let mut unknown = definition();
        unknown.version = "absent".into();
        let unknown = keys.sign(
            "owner",
            "unknown-vocabulary",
            NormAct::Create {
                authority: None,
                ledger,
                vocabulary: Vocabulary::new(unknown).unwrap().reference().clone(),
                fields_json: r#"{"title":"unknown vocabulary"}"#.into(),
            },
        );
        assert!(store.append_norm_event(&unknown, &keys).is_err());
        assert_eq!(store.export_events().unwrap().len(), 2);
    }
    #[test]
    fn norm_native_succession_pins_frontier_and_restores_in_reverse_order() {
        let keys = Keys::new();
        let mut source = WorkItemStore::open_in_memory().unwrap();
        let ledger = source.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let first = source
            .append_norm_event(&keys.create(&ledger, "old-record"), &keys)
            .unwrap();
        let accepted = keys.change("owner", "old-accept", &ledger, &first, "accepted");
        source.append_norm_event(&accepted, &keys).unwrap();
        let before = source.norm_view(&keys).unwrap();
        let rotation = keys.rotate(&before, "owner", "owner2", "rotate-one");
        let r1 = source.append_norm_event(&rotation, &keys).unwrap();
        assert_eq!(source.append_norm_event(&rotation, &keys).unwrap(), r1);
        let view = source.norm_view(&keys).unwrap();
        assert_eq!(view.ledger, ledger);
        assert_eq!(view.owner, keys.actor("owner2"));
        assert_eq!(view.records[&first], before.records[&first]);
        assert_eq!(source.norm_checkpoint().unwrap(), Some(view.checkpoint()));
        // Public creation still authenticates the worker, with its authority
        // epoch explicit; retaining an old binding grants no current owner vote.
        let new_record = keys.at_epoch(
            "worker",
            "new-record",
            &view,
            keys.create(&ledger, "ignored").statement.action,
        );
        let second = source.append_norm_event(&new_record, &keys).unwrap();
        let act = keys
            .change("owner2", "ignored", &ledger, &second, "accepted")
            .statement
            .action;
        let denied = keys.at_epoch("owner", "old-key-new-epoch", &view, act.clone());
        assert!(source.append_norm_event(&denied, &keys).is_err());
        let accepted = keys.at_epoch("owner2", "new-accept", &view, act);
        source.append_norm_event(&accepted, &keys).unwrap();
        let view = source.norm_view(&keys).unwrap();
        let r2 = source
            .append_norm_event(&keys.rotate(&view, "owner2", "owner3", "rotate-two"), &keys)
            .unwrap();
        let checkpoint = source.norm_checkpoint().unwrap().unwrap();
        assert_eq!(
            checkpoint,
            NormCheckpoint {
                ledger: ledger.clone(),
                authority_head: r2
            }
        );
        let mut events = source.export_events().unwrap();
        let mut pinned = WorkItemStore::open_in_memory().unwrap();
        assert!(pinned
            .pin_norm_checkpoint(&NormCheckpoint {
                ledger: ledger.clone(),
                authority_head: "untrusted-key-label".into(),
            })
            .is_err());
        assert_eq!(pinned.norm_checkpoint().unwrap(), None);
        pinned.pin_norm_checkpoint(&checkpoint).unwrap();
        assert!(pinned.import_norm_events(&events[..3], &keys).is_err());
        assert!(pinned.export_events().unwrap().is_empty());
        assert!(pinned
            .append_norm_event(&keys.create(&ledger, "missing-chain"), &keys)
            .is_err());
        assert_eq!(pinned.norm_checkpoint().unwrap(), Some(checkpoint.clone()));
        events.reverse();
        assert_eq!(pinned.import_norm_events(&events, &keys).unwrap(), 7);
        assert_eq!(pinned.import_norm_events(&events, &keys).unwrap(), 0);
        assert_eq!(pinned.norm_checkpoint().unwrap(), Some(checkpoint.clone()));
        assert_eq!(pinned.norm_view(&keys).unwrap().owner, keys.actor("owner3"));
        assert_eq!(
            pinned.norm_view(&keys).unwrap().records,
            source.norm_view(&keys).unwrap().records
        );
        let mut advancing = WorkItemStore::open_in_memory().unwrap();
        advancing.pin_norm_ledger(&ledger).unwrap();
        advancing.import_norm_events(&events, &keys).unwrap();
        assert_eq!(advancing.norm_checkpoint().unwrap(), Some(checkpoint));
        assert!(advancing.pin_norm_ledger(&ledger).is_err());
    }

    #[test]
    fn norm_native_rotation_refuses_unbound_signers_and_concurrent_old_epoch_acts() {
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        let rotation = keys.rotate(&view, "owner", "owner2", "rotate");
        let before = store.export_events().unwrap();
        let mut missing = rotation.clone();
        missing.successor_signature = None;
        assert!(store.append_norm_event(&missing, &keys).is_err());
        let mut forged = rotation.clone();
        forged.successor_signature = Some("00".repeat(64));
        assert!(store.append_norm_event(&forged, &keys).is_err());
        for (from, to, nonce) in [
            ("worker", "owner2", "worker-rotation"),
            ("owner", "worker", "other-owner"),
            ("owner", "owner", "same-key"),
        ] {
            assert!(store
                .append_norm_event(&keys.rotate(&view, from, to, nonce), &keys)
                .is_err());
        }
        let extra = keys.cosign(keys.create(&ledger, "unexpected-cosignature"), "owner2");
        assert!(store.append_norm_event(&extra, &keys).is_err());
        assert_eq!(store.export_events().unwrap(), before);
        let r1 = store.append_norm_event(&rotation, &keys).unwrap();
        // Exercise both possible canonical orders of a concurrent old-epoch
        // create against the fixed rotation commitment, not only one guard.
        for before_rotation in [true, false] {
            let concurrent = (0..1024)
                .map(|n| keys.create(&ledger, &format!("concurrent-{n}")))
                .find(|event| (event.tracker_event().unwrap().event_id < r1) == before_rotation)
                .unwrap();
            let original = store.export_events().unwrap();
            assert!(store
                .import_norm_events(&[concurrent.tracker_event().unwrap()], &keys)
                .is_err());
            assert_eq!(store.export_events().unwrap(), original);
        }
        assert_eq!(store.norm_checkpoint().unwrap().unwrap().authority_head, r1);
        // Even a public transition cannot silently resolve its omitted epoch
        // to the latest root; omission remains the original genesis.
        assert!(store
            .append_norm_event(&keys.create(&ledger, "stale-public"), &keys)
            .is_err());
    }

    #[test]
    fn norm_native_checkpoint_survives_missing_succession_and_rotation_write_failure() {
        let path = crate::scratch::file("norm-rotation", "sqlite");
        let keys = Keys::new();
        let mut store = WorkItemStore::open(&path).unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let first = keys.rotate(
            &store.norm_view(&keys).unwrap(),
            "owner",
            "owner2",
            "rotation-one",
        );
        let r1 = store.append_norm_event(&first, &keys).unwrap();
        let second = keys.rotate(
            &store.norm_view(&keys).unwrap(),
            "owner2",
            "owner3",
            "rotation-two",
        );
        let connection = rusqlite::Connection::open(&path).unwrap();
        // Pre-succession readers must refuse this checkpoint schema, and what
        // makes them refuse is that the stamp is compared for EXACT equality:
        // a build carrying any other generation declines the file rather than
        // reading a checkpoint it cannot interpret. The generation's VALUE is
        // derived and belongs to `items.rs`, not here -- this line pinned it
        // at 3 while the work-item store had stamped 5 since before this
        // branch began, so it recorded a guess and not an observation. The
        // owner is what this test can honestly assert.
        let owner: String = connection
            .query_row(
                "SELECT name FROM schema_migrations ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(owner, "work-item", "the checkpoint schema's owner");
        connection.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE UPDATE ON tracker_norm_checkpoint BEGIN SELECT RAISE(ABORT, 'injected checkpoint failure'); END;").unwrap();
        let prior = store.export_events().unwrap();
        assert!(store.append_norm_event(&second, &keys).is_err());
        assert_eq!(store.export_events().unwrap(), prior);
        assert_eq!(store.norm_checkpoint().unwrap().unwrap().authority_head, r1);
        connection
            .execute_batch("DROP TRIGGER fail_checkpoint")
            .unwrap();
        let r2 = store.append_norm_event(&second, &keys).unwrap();
        connection
            .execute("DELETE FROM tracker_events WHERE event_id = ?1", [&r1])
            .unwrap();
        drop(store);
        let mut store = WorkItemStore::open(&path).unwrap();
        assert!(store.norm_view(&keys).is_err());
        assert_eq!(store.norm_checkpoint().unwrap().unwrap().authority_head, r2);
        assert!(store
            .append_norm_event(&keys.create(&ledger, "missing-rotation"), &keys)
            .is_err());
        assert_eq!(
            store
                .import_norm_events(&[first.tracker_event().unwrap()], &keys)
                .unwrap(),
            1
        );
        assert_eq!(store.norm_checkpoint().unwrap().unwrap().authority_head, r2);
        assert_eq!(store.norm_view(&keys).unwrap().owner, keys.actor("owner3"));
        drop(store);
        drop(connection);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn norm_native_edits_pin_content_revisions_and_preserve_old_approval_history() {
        let keys = Keys::new();
        let mut c = charter();
        c.vocabularies[0].editing = Some(AdmissionPredicate::Public {});
        c.vocabularies[0].effectiveness = Some(vec![EffectivenessRule {
            status: "accepted".into(),
            effect: RevisionEffect::Activate,
        }]);
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let genesis = keys.sign(
            "owner",
            "editable",
            NormAct::Bootstrap {
                creator: "worker".into(),
                charter: c,
            },
        );
        let ledger = store.append_norm_event(&genesis, &keys).unwrap();
        let record = store
            .append_norm_event(&keys.create(&ledger, "D0"), &keys)
            .unwrap();
        let accepted = keys.change("owner", "accept-initial", &ledger, &record, "accepted");
        store.append_norm_event(&accepted, &keys).unwrap();
        assert_eq!(store.norm_aliases().unwrap()[&record], "N-1");
        let view = store.norm_view(&keys).unwrap();
        let noop = keys.edit(
            &view,
            &record,
            r#" { "title" : "repair authorization" } "#,
            "worker",
            "noop",
        );
        let noop_id = store.append_norm_event(&noop, &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        assert_eq!(view.records[&record].status, "accepted");
        assert_eq!(view.records[&record].content_head, record);
        assert_eq!(view.records[&record].head, noop_id);
        assert_eq!(
            view.effective_records[&record].head,
            accepted.tracker_event().unwrap().event_id
        );
        assert_eq!(view.effective_records[&record].content_head, record);
        let approved_history = store.export_events().unwrap();
        let change = keys.edit(
            &view,
            &record,
            r#"{"title":"a different decision"}"#,
            "worker",
            "change",
        );
        let changed = store.append_norm_event(&change, &keys).unwrap();
        let current = store.norm_view(&keys).unwrap();
        assert_eq!(current.records[&record].id, record);
        assert_eq!(current.records[&record].status, "proposed");
        assert_eq!(current.records[&record].content_head, changed);
        assert_eq!(
            current.records[&record].fields,
            json!({"title":"a different decision"})
        );
        assert_eq!(current.effective_records[&record].content_head, record);
        assert_eq!(
            current.effective_records[&record].fields,
            json!({"title":"repair authorization"})
        );
        assert!(
            matches!(current.effective_revision(&current.records[&record]),
            EffectiveRevision::Active { record: active, .. } if active.content_head == record && active.status == "accepted")
        );
        let mut restored = WorkItemStore::open_in_memory().unwrap();
        restored.pin_norm_checkpoint(&current.checkpoint()).unwrap();
        let mut events = store.export_events().unwrap();
        events.reverse();
        restored.import_norm_events(&events, &keys).unwrap();
        assert_eq!(
            restored.norm_view(&keys).unwrap().effective_records,
            current.effective_records
        );
        let historical = replay_norm(&approved_history, &view.checkpoint(), &keys).unwrap();
        assert_eq!(historical.records[&record].status, "accepted");
        assert_eq!(historical.records[&record].content_head, record);
        assert_eq!(
            historical.records[&record].fields,
            json!({"title":"repair authorization"})
        );
        let mut accept_new = accepted.statement.action.clone();
        if let NormAct::Transition { previous, .. } = &mut accept_new {
            *previous = changed.clone();
        }
        let accept_new = keys.at_epoch("owner", "accept-new", &current, accept_new);
        let accepted_head = store.append_norm_event(&accept_new, &keys).unwrap();
        assert_eq!(store.append_norm_event(&change, &keys).unwrap(), changed);
        let current = store.norm_view(&keys).unwrap();
        assert_eq!(current.records[&record].status, "accepted");
        assert_eq!(current.records[&record].content_head, changed);
        assert_eq!(current.records[&record].head, accepted_head);
        assert_eq!(current.effective_records[&record].content_head, changed);
        assert_eq!(current.effective_records[&record].head, accepted_head);
        assert_eq!(
            store.resolve_norm_record("N-1").unwrap(),
            Some(record.clone())
        );
        assert_eq!(store.resolve_norm_record(&record).unwrap(), Some(record));
        assert_eq!(store.resolve_norm_record("N-999").unwrap(), None);
        assert_eq!(store.norm_aliases().unwrap().len(), 1);
    }

    #[test]
    fn norm_native_edits_refuse_missing_policies_authority_stale_heads_and_bad_fields() {
        let keys = Keys::new();
        let mut immutable = WorkItemStore::open_in_memory().unwrap();
        let ledger = immutable
            .append_norm_event(&keys.bootstrap(), &keys)
            .unwrap();
        let record = immutable
            .append_norm_event(&keys.create(&ledger, "D0"), &keys)
            .unwrap();
        let edit = keys.edit(
            &immutable.norm_view(&keys).unwrap(),
            &record,
            r#"{"title":"changed"}"#,
            "owner",
            "denied-edit",
        );
        assert!(immutable.append_norm_event(&edit, &keys).is_err());
        let mut c = charter();
        c.vocabularies[0].editing = Some(AdmissionPredicate::Authority {
            scope: "accept".into(),
        });
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "private-edit",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let record = store
            .append_norm_event(&keys.create(&ledger, "D0"), &keys)
            .unwrap();
        let before = store.norm_view(&keys).unwrap();
        assert!(store
            .append_norm_event(
                &keys.edit(
                    &before,
                    &record,
                    r#"{"title":"changed"}"#,
                    "worker",
                    "worker-edit"
                ),
                &keys
            )
            .is_err());
        let good = keys.edit(
            &before,
            &record,
            r#"{"title":"changed"}"#,
            "owner",
            "owner-edit",
        );
        store.append_norm_event(&good, &keys).unwrap();
        assert!(store
            .append_norm_event(
                &keys.edit(
                    &before,
                    &record,
                    r#"{"title":"stale"}"#,
                    "owner",
                    "stale-edit"
                ),
                &keys
            )
            .is_err());
        let current = store.norm_view(&keys).unwrap();
        let original = store.export_events().unwrap();
        for (n, fields) in [
            "{}",
            r#"{"title":"one","title":"two"}"#,
            r#"{"title":5}"#,
            r#"{"title":"ok","extra":true}"#,
        ]
        .iter()
        .enumerate()
        {
            assert!(store
                .append_norm_event(
                    &keys.edit(&current, &record, fields, "owner", &format!("bad-{n}")),
                    &keys
                )
                .is_err());
        }
        let mut wrong = good.statement.action.clone();
        if let NormAct::Edit {
            vocabulary,
            previous,
            ..
        } = &mut wrong
        {
            vocabulary.version = "other".into();
            *previous = current.records[&record].head.clone();
        }
        assert!(store
            .append_norm_event(
                &keys.at_epoch("owner", "wrong-version-edit", &current, wrong),
                &keys
            )
            .is_err());
        assert_eq!(store.export_events().unwrap(), original);
        let rotation = keys.rotate(&current, "owner", "owner2", "rotate-editor");
        store.append_norm_event(&rotation, &keys).unwrap();
        let rotated = store.norm_view(&keys).unwrap();
        assert!(store
            .append_norm_event(
                &keys.edit(
                    &rotated,
                    &record,
                    r#"{"title":"next"}"#,
                    "owner",
                    "old-editor"
                ),
                &keys
            )
            .is_err());
        store
            .append_norm_event(
                &keys.edit(
                    &rotated,
                    &record,
                    r#"{"title":"next"}"#,
                    "owner2",
                    "new-editor",
                ),
                &keys,
            )
            .unwrap();
        // Edit scopes pass through charter validation just like transition scopes.
        c.vocabularies[0].editing = Some(AdmissionPredicate::Authority {
            scope: "invented".into(),
        });
        let mut other = WorkItemStore::open_in_memory().unwrap();
        assert!(other
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "unknown-edit-scope",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c,
                    }
                ),
                &keys
            )
            .is_err());
    }

    #[test]
    fn norm_native_aliases_are_local_idempotent_and_survive_rebuild() {
        let keys = Keys::new();
        let mut source = WorkItemStore::open_in_memory().unwrap();
        let ledger = source.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let source_record = source
            .append_norm_event(&keys.create(&ledger, "source"), &keys)
            .unwrap();
        let mut dest = WorkItemStore::open_in_memory().unwrap();
        dest.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let local = dest
            .append_norm_event(&keys.create(&ledger, "local"), &keys)
            .unwrap();
        dest.import_norm_events(&source.export_events().unwrap(), &keys)
            .unwrap();
        assert_eq!(source.norm_aliases().unwrap()[&source_record], "N-1");
        assert_eq!(dest.norm_aliases().unwrap()[&source_record], "N-2");
        assert_eq!(dest.resolve_norm_record("N-1").unwrap(), Some(local));
        let aliases = dest.norm_aliases().unwrap();
        dest.rebuild_projection().unwrap();
        assert_eq!(dest.norm_aliases().unwrap(), aliases);
        assert_eq!(
            dest.import_norm_events(&source.export_events().unwrap(), &keys)
                .unwrap(),
            0
        );
        let third = dest
            .append_norm_event(&keys.create(&ledger, "next"), &keys)
            .unwrap();
        assert_eq!(dest.norm_aliases().unwrap()[&third], "N-3");
        assert_eq!(
            dest.norm_view(&keys).unwrap().records[&source_record],
            source.norm_view(&keys).unwrap().records[&source_record]
        );
    }

    #[test]
    fn norm_native_upgrades_pre_alias_history_in_local_admission_order() {
        let path = crate::scratch::file("norm-alias-upgrade", "sqlite");
        let keys = Keys::new();
        let mut store = WorkItemStore::open(&path).unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "DROP TRIGGER tracker_norm_creation_alias; DROP TABLE tracker_norm_aliases;",
            )
            .unwrap();
        let mut creations = [
            keys.create(&ledger, "first"),
            keys.create(&ledger, "second"),
        ];
        // Reverse content order to ensure the migration uses admission sequence.
        creations.sort_by_key(|event| std::cmp::Reverse(event.tracker_event().unwrap().event_id));
        let first = store.append_norm_event(&creations[0], &keys).unwrap();
        let second = store.append_norm_event(&creations[1], &keys).unwrap();
        let history = store.export_events().unwrap();
        let checkpoint = store.norm_checkpoint().unwrap();
        drop(store);
        drop(connection);
        let expected = BTreeMap::from([(first.clone(), "N-1".into()), (second, "N-2".into())]);
        for _ in 0..2 {
            let mut reopened = WorkItemStore::open(&path).unwrap();
            assert_eq!(reopened.norm_aliases().unwrap(), expected);
            assert_eq!(reopened.export_events().unwrap(), history);
            assert_eq!(reopened.norm_checkpoint().unwrap(), checkpoint);
            assert_eq!(reopened.import_norm_events(&history, &keys).unwrap(), 0);
            assert_eq!(
                reopened.resolve_norm_record("N-1").unwrap(),
                Some(first.clone())
            );
        }
        let mut reopened = WorkItemStore::open(&path).unwrap();
        let third = reopened
            .append_norm_event(&keys.create(&ledger, "third"), &keys)
            .unwrap();
        assert_eq!(reopened.norm_aliases().unwrap()[&third], "N-3");
        drop(reopened);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn norm_native_alias_failure_and_missing_evidence_preserve_allocations() {
        let path = crate::scratch::file("norm-alias", "sqlite");
        let keys = Keys::new();
        let mut store = WorkItemStore::open(&path).unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let first = keys.create(&ledger, "first");
        let record = store.append_norm_event(&first, &keys).unwrap();
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("CREATE TRIGGER fail_alias BEFORE INSERT ON tracker_norm_aliases BEGIN SELECT RAISE(ABORT, 'injected alias failure'); END;").unwrap();
        let second = keys.create(&ledger, "second");
        let before = store.export_events().unwrap();
        assert!(store.append_norm_event(&second, &keys).is_err());
        assert_eq!(store.export_events().unwrap(), before);
        assert_eq!(store.norm_aliases().unwrap().len(), 1);
        connection.execute_batch("DROP TRIGGER fail_alias").unwrap();
        let batch_tail = keys.create(&ledger, "batch-tail");
        connection.execute_batch("CREATE TRIGGER fail_batch_alias BEFORE INSERT ON tracker_norm_aliases WHEN (SELECT count(*) FROM tracker_norm_aliases) >= 2 BEGIN SELECT RAISE(ABORT, 'injected batch failure'); END;").unwrap();
        assert!(store
            .import_norm_events(
                &[
                    second.tracker_event().unwrap(),
                    batch_tail.tracker_event().unwrap()
                ],
                &keys
            )
            .is_err());
        assert_eq!(store.export_events().unwrap(), before);
        assert_eq!(store.norm_aliases().unwrap().len(), 1);
        connection
            .execute_batch("DROP TRIGGER fail_batch_alias")
            .unwrap();
        let other = store.append_norm_event(&second, &keys).unwrap();
        assert_eq!(store.norm_aliases().unwrap()[&other], "N-2");
        connection
            .execute("DELETE FROM tracker_events WHERE event_id = ?1", [&record])
            .unwrap();
        drop(store);
        let mut store = WorkItemStore::open(&path).unwrap();
        assert_eq!(
            store.resolve_norm_record("N-1").unwrap(),
            Some(record.clone())
        );
        store
            .import_norm_events(&[first.tracker_event().unwrap()], &keys)
            .unwrap();
        assert_eq!(store.norm_aliases().unwrap()[&record], "N-1");
        let next = store
            .append_norm_event(&keys.create(&ledger, "third"), &keys)
            .unwrap();
        assert_eq!(store.norm_aliases().unwrap()[&next], "N-3");
        drop(store);
        drop(connection);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn norm_bundled_vocabularies_use_data_and_refuse_unimplemented_semantic_steps() {
        let c = NormCharter::bundled().unwrap();
        assert_eq!(
            c.vocabularies
                .iter()
                .map(|v| v.definition.name.as_str())
                .collect::<Vec<_>>(),
            [
                "issue",
                "assertion",
                "obligation",
                "decision",
                "reservation",
                "refines",
                "derives",
                "supersedes",
                "derived_from",
                "manifest",
                "correspondence",
                "artifact"
            ]
        );
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "bundled",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let mut ids = BTreeMap::new();
        for entry in &c.vocabularies {
            // Relations and manifests need resolvable references and bound
            // premises, and an artifact the owner's `build.publish` scope;
            // their own fixtures exercise them.
            if entry.relation.is_some()
                || entry.manifest.is_some()
                || entry.correspondence.is_some()
                || entry.definition.name == "artifact"
            {
                continue;
            }
            let fields = match entry.definition.name.as_str() {
                "issue" => json!({"title":"repair","labels":["norm"]}),
                "assertion" => json!({"title":"claim","statement":"the parser denies the worker"}),
                "obligation" => {
                    json!({"name":"custody-authorization","proposition":"worker is denied","domain":"src/","subject":"src/auth.py"})
                }
                "decision" => {
                    json!({"title":"enforce","intent":"deny the worker","subjects":["src/auth.py"]})
                }
                "reservation" => {
                    json!({"purpose":"repair","selectors":["src/future.py"],"mode":"speculative"})
                }
                _ => panic!("uncovered bundled declaration"),
            };
            let vocabulary = Vocabulary::new(entry.definition.clone())
                .unwrap()
                .reference()
                .clone();
            let event = keys.sign(
                "worker",
                &entry.definition.name,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: vocabulary.clone(),
                    fields_json: fields.to_string(),
                },
            );
            let id = store.append_norm_event(&event, &keys).unwrap();
            ids.insert(entry.definition.name.clone(), (id, vocabulary));
        }
        let (decision, vocabulary) = &ids["decision"];
        let accepted = keys.sign(
            "owner",
            "accept-bundled",
            NormAct::Transition {
                ledger: ledger.clone(),
                authority: None,
                vocabulary: vocabulary.clone(),
                record: decision.clone(),
                previous: decision.clone(),
                status: "accepted".into(),
            },
        );
        let head = store.append_norm_event(&accepted, &keys).unwrap();
        let folded = keys.sign(
            "owner",
            "no-fake-fold",
            NormAct::Transition {
                ledger: ledger.clone(),
                authority: None,
                vocabulary: vocabulary.clone(),
                record: decision.clone(),
                previous: head,
                status: "folded".into(),
            },
        );
        assert!(store.append_norm_event(&folded, &keys).is_err());
        let (reservation, vocabulary) = &ids["reservation"];
        let granted = keys.sign(
            "owner",
            "no-fake-grant",
            NormAct::Transition {
                ledger,
                authority: None,
                vocabulary: vocabulary.clone(),
                record: reservation.clone(),
                previous: reservation.clone(),
                status: "granted".into(),
            },
        );
        assert!(store.append_norm_event(&granted, &keys).is_err());
        assert_eq!(store.norm_aliases().unwrap().len(), 5);
    }
    /// DR-0122 §13.2 and §13.4, the runtime half of
    /// `models/maude/relation-validation-scope.maude`: an act that makes an
    /// edge live binds the family basis it was validated against, a moved
    /// basis is refused for re-evaluation, and the family stays acyclic and
    /// within its declared kinds and cardinality.
    #[test]
    fn norm_relations_bind_the_family_basis_and_keep_the_family_acyclic() {
        use whipplescript_store::norm_commands::NormCommandStore;
        let c = NormCharter::bundled().unwrap();
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "relations",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let reference = |name: &str| {
            Vocabulary::new(
                c.vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == name)
                    .unwrap()
                    .definition
                    .clone(),
            )
            .unwrap()
            .reference()
            .clone()
        };
        let create = |nonce: &str, kind: &str, fields: serde_json::Value| {
            keys.sign(
                "worker",
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference(kind),
                    fields_json: fields.to_string(),
                },
            )
        };
        let obligation = |name: &str| {
            create(
                name,
                "obligation",
                json!({"name": name, "proposition": "holds", "domain": "src/", "subject": "src/x.py"}),
            )
        };
        let relate = |nonce: &str, kind: &str, source: &str, target: &str, basis: Option<&str>| {
            keys.sign_with(
                "worker",
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference(kind),
                    fields_json: json!({"source": source, "target": target}).to_string(),
                },
                basis.map(|basis| NormPremises {
                    family_basis: Some(basis.into()),
                    references: vec![source.into(), target.into()],
                    inventory_frontier: Vec::new(),
                }),
            )
        };
        let a = store.append_norm_event(&obligation("a"), &keys).unwrap();
        let b = store.append_norm_event(&obligation("b"), &keys).unwrap();
        let c_ = store.append_norm_event(&obligation("c"), &keys).unwrap();
        let d = store.append_norm_event(&obligation("d"), &keys).unwrap();
        let refused = |result: Result<String, StoreError>, needle: &str| {
            let message = format!("{:?}", result.expect_err("refusal expected"));
            assert!(message.contains(needle), "{message}");
        };
        let basis = |store: &WorkItemStore, family: &str| {
            store
                .norm_state(&keys)
                .unwrap()
                .relation_family(family)
                .unwrap()
                .basis
        };
        assert!(store
            .norm_state(&keys)
            .unwrap()
            .relation_family("undeclared")
            .is_err());
        let empty = basis(&store, "refinement");
        // An empty family still has a basis, and a live edge is admitted on it.
        let ab = store
            .append_norm_event(&relate("ab", "refines", &a, &b, Some(&empty)), &keys)
            .unwrap();
        // The basis moved; a candidate captured against the old one is refused
        // for re-evaluation, never admitted on a substituted token.
        refused(
            store.append_norm_event(&relate("bc-stale", "refines", &b, &c_, Some(&empty)), &keys),
            "moved since it was captured",
        );
        let after_ab = basis(&store, "refinement");
        assert_ne!(after_ab, empty);
        store
            .append_norm_event(&relate("bc", "refines", &b, &c_, Some(&after_ab)), &keys)
            .unwrap();
        // A cycle through the longer path a -> b -> c is refused on the whole
        // family, not on the immediate reverse edge.
        let after_bc = basis(&store, "refinement");
        refused(
            store.append_norm_event(&relate("ca", "refines", &c_, &a, Some(&after_bc)), &keys),
            "close a cycle in family refinement",
        );
        // Both families are checked as one: derives shares the refinement family.
        refused(
            store.append_norm_event(
                &relate("ca-derives", "derives", &c_, &a, Some(&after_bc)),
                &keys,
            ),
            "close a cycle",
        );
        refused(
            store.append_norm_event(&relate("no-basis", "refines", &c_, &d, None), &keys),
            "must bind the family basis",
        );
        refused(
            store.append_norm_event(&relate("self", "refines", &d, &d, Some(&after_bc)), &keys),
            "relate a record to itself",
        );
        // A non-relation act binds no basis.
        refused(
            store.append_norm_event(
                &keys.sign_with(
                    "worker",
                    "e",
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("obligation"),
                        fields_json: json!({"name": "e", "proposition": "holds", "domain": "src/", "subject": "src/e.py"}).to_string(),
                    },
                    Some(NormPremises {
                        family_basis: Some(after_bc.clone()),
                        references: Vec::new(),
                        inventory_frontier: Vec::new(),
                    }),
                ),
                &keys,
            ),
            "only an act on a relation binds",
        );
        // Two candidates captured against the same basis, one edge of a
        // two-cycle each: the first lands, the second is refused as moved, and
        // re-evaluated it is refused as a cycle.
        let p = store.append_norm_event(&obligation("p"), &keys).unwrap();
        let q = store.append_norm_event(&obligation("q"), &keys).unwrap();
        let shared = basis(&store, "refinement");
        store
            .append_norm_event(&relate("pq", "refines", &p, &q, Some(&shared)), &keys)
            .unwrap();
        refused(
            store.append_norm_event(&relate("qp", "refines", &q, &p, Some(&shared)), &keys),
            "moved since it was captured",
        );
        let after_pq = basis(&store, "refinement");
        refused(
            store.append_norm_event(
                &relate("qp-again", "refines", &q, &p, Some(&after_pq)),
                &keys,
            ),
            "close a cycle",
        );
        // An independent candidate captured against the stale basis pays a
        // re-evaluation, not the work: recaptured, it lands.
        let r = store.append_norm_event(&obligation("r"), &keys).unwrap();
        let s_ = store.append_norm_event(&obligation("s"), &keys).unwrap();
        refused(
            store.append_norm_event(
                &relate("rs-stale", "refines", &r, &s_, Some(&shared)),
                &keys,
            ),
            "moved since it was captured",
        );
        let current = basis(&store, "refinement");
        store
            .append_norm_event(&relate("rs", "refines", &r, &s_, Some(&current)), &keys)
            .unwrap();
        // Endpoints resolve to declared kinds, and a dangling reference resolves to nothing.
        let issue = store
            .append_norm_event(
                &create("issue", "issue", json!({"title": "not an obligation"})),
                &keys,
            )
            .unwrap();
        let current = basis(&store, "refinement");
        refused(
            store.append_norm_event(
                &relate("kind", "refines", &issue, &a, Some(&current)),
                &keys,
            ),
            "undeclared kind",
        );
        // A reference to an event that is not a record resolves to nothing,
        // and one to no event at all is a missing parent before it is anything.
        refused(
            store.append_norm_event(
                &relate("not-a-record", "refines", &ledger, &a, Some(&current)),
                &keys,
            ),
            "does not resolve",
        );
        refused(
            store.append_norm_event(
                &relate("dangling", "refines", &"f".repeat(64), &a, Some(&current)),
                &keys,
            ),
            "missing parents",
        );
        // The references an act names are premises: unbound, the act is refused
        // even when they resolve, because a replay could apply it before them.
        refused(
            store.append_norm_event(
                &keys.sign_with(
                    "worker",
                    "unbound-refs",
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("refines"),
                        fields_json: json!({"source": a, "target": d}).to_string(),
                    },
                    Some(NormPremises {
                        family_basis: Some(current.clone()),
                        references: vec![a.clone()],
                        inventory_frontier: Vec::new(),
                    }),
                ),
                &keys,
            ),
            "bind the references it names",
        );
        // Cardinality: at most one live successor per predecessor in succession.
        let d1 = store
            .append_norm_event(
                &create(
                    "d1",
                    "decision",
                    json!({"title": "one", "intent": "i", "subjects": []}),
                ),
                &keys,
            )
            .unwrap();
        let d2 = store
            .append_norm_event(
                &create(
                    "d2",
                    "decision",
                    json!({"title": "two", "intent": "i", "subjects": []}),
                ),
                &keys,
            )
            .unwrap();
        let d3 = store
            .append_norm_event(
                &create(
                    "d3",
                    "decision",
                    json!({"title": "three", "intent": "i", "subjects": []}),
                ),
                &keys,
            )
            .unwrap();
        let succession = basis(&store, "succession");
        store
            .append_norm_event(
                &relate("d1d2", "supersedes", &d1, &d2, Some(&succession)),
                &keys,
            )
            .unwrap();
        let succession = basis(&store, "succession");
        refused(
            store.append_norm_event(
                &relate("d3d2", "supersedes", &d3, &d2, Some(&succession)),
                &keys,
            ),
            "at most one live relation per target",
        );
        // Withdrawing an edge binds the family basis like every family act,
        // because it moves the family, but it is not checked structurally: it
        // leaves the live family. What the withdrawal made admissible then is,
        // and re-asserting the edge is an act that makes it live again, checked
        // on the family as it stands.
        let refines = reference("refines");
        refused(
            store.append_norm_event(
                &keys.sign(
                    "worker",
                    "withdraw-ab-unbound",
                    NormAct::Transition {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: refines.clone(),
                        record: ab.clone(),
                        previous: ab.clone(),
                        status: "withdrawn".into(),
                    },
                ),
                &keys,
            ),
            "must bind the family basis",
        );
        let current = basis(&store, "refinement");
        let withdrawn = store
            .append_norm_event(
                &keys.sign_with(
                    "worker",
                    "withdraw-ab",
                    NormAct::Transition {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: refines.clone(),
                        record: ab.clone(),
                        previous: ab.clone(),
                        status: "withdrawn".into(),
                    },
                    Some(NormPremises {
                        family_basis: Some(current),
                        references: Vec::new(),
                        inventory_frontier: Vec::new(),
                    }),
                ),
                &keys,
            )
            .unwrap();
        let current = basis(&store, "refinement");
        store
            .append_norm_event(&relate("ca-now", "refines", &c_, &a, Some(&current)), &keys)
            .unwrap();
        let reassert = |nonce: &str, previous: &str, basis: Option<&str>| {
            keys.sign_with(
                "worker",
                nonce,
                NormAct::Transition {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: refines.clone(),
                    record: ab.clone(),
                    previous: previous.into(),
                    status: "asserted".into(),
                },
                basis.map(|basis| NormPremises {
                    family_basis: Some(basis.into()),
                    references: vec![a.clone(), b.clone()],
                    inventory_frontier: Vec::new(),
                }),
            )
        };
        refused(
            store.append_norm_event(&reassert("reassert-unbound", &withdrawn, None), &keys),
            "must bind the family basis",
        );
        let current = basis(&store, "refinement");
        refused(
            store.append_norm_event(&reassert("reassert", &withdrawn, Some(&current)), &keys),
            "close a cycle",
        );
        // A revision reference resolves to its record after later edits moved
        // the head, so lineage from an exact revision keeps resolving.
        let d_revision = store.norm_state(&keys).unwrap().records[&d]
            .content_head
            .clone();
        store
            .append_norm_event(
                &keys.sign(
                    "worker",
                    "edit-d",
                    NormAct::Edit {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("obligation"),
                        record: d.clone(),
                        previous: d.clone(),
                        fields_json: json!({"name": "d", "proposition": "holds more", "domain": "src/", "subject": "src/x.py"}).to_string(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let lineage = basis(&store, "lineage");
        store
            .append_norm_event(
                &relate("fork", "derived_from", &a, &d_revision, Some(&lineage)),
                &keys,
            )
            .unwrap();
        // The snapshot exposes every family with its live edges and basis.
        let view = store.norm_state(&keys).unwrap();
        let families = view.relation_families().unwrap();
        assert_eq!(
            families.keys().cloned().collect::<Vec<_>>(),
            ["lineage", "refinement", "succession"]
        );
        let refinement = &families["refinement"];
        assert_eq!(refinement.basis, basis(&store, "refinement"));
        let edges: Vec<(&str, &str, &str)> = refinement
            .edges
            .iter()
            .map(|edge| {
                (
                    edge.relation.as_str(),
                    edge.source.as_str(),
                    edge.target.as_str(),
                )
            })
            .collect();
        assert!(edges.contains(&("refines", b.as_str(), c_.as_str())));
        assert!(edges.contains(&("refines", c_.as_str(), a.as_str())));
        assert!(!edges
            .iter()
            .any(|(_, source, target)| *source == a && *target == b));
        assert_eq!(families["lineage"].edges[0].target, d);
        let mut host = whipplescript_store::norm_commands::NormCommandHost::new(&mut store, &keys);
        let response = host
            .execute(whipplescript_store::norm_commands::NormCommandRequest::new(
                whipplescript_store::norm_commands::NormCommand::Snapshot {},
            ))
            .unwrap();
        let whipplescript_store::norm_commands::NormCommandResult::Snapshot { snapshot } =
            response.result
        else {
            panic!("snapshot expected");
        };
        assert_eq!(snapshot.families, families);
    }

    /// DR-0122 §13.1, the runtime half of `models/maude/manifest-completeness.maude`:
    /// members are bound and resolve or the act is refused, an exhaustive claim
    /// binds the inventory frontier it was judged against or is refused, a
    /// bounded claim is never total, and completeness is a judgment derived at
    /// the bound frontier that a later requirement does not rewrite.
    #[test]
    fn norm_manifests_bind_the_inventory_frontier_and_judge_completeness_there() {
        use whipplescript_store::norm_commands::*;
        use whipplescript_store::norm_manifests::ManifestCompleteness;
        let c = NormCharter::bundled().unwrap();
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "manifests",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let reference = |name: &str| {
            Vocabulary::new(
                c.vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == name)
                    .unwrap()
                    .definition
                    .clone(),
            )
            .unwrap()
            .reference()
            .clone()
        };
        let refused = |result: Result<String, StoreError>, needle: &str| {
            let message = format!("{:?}", result.expect_err("refusal expected"));
            assert!(message.contains(needle), "{message}");
        };
        let requirement = |nonce: &str, name: &str| {
            keys.sign(
                "worker",
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("obligation"),
                    fields_json: json!({"name": name, "proposition": "holds", "domain": "src/", "subject": "src/x.py"}).to_string(),
                },
            )
        };
        let accept = |nonce: &str, record: &str| {
            keys.sign(
                "owner",
                nonce,
                NormAct::Transition {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("obligation"),
                    record: record.into(),
                    previous: record.into(),
                    status: "accepted".into(),
                },
            )
        };
        // Two accepted requirements form the applicable inventory.
        let r1 = store
            .append_norm_event(&requirement("r1", "r1"), &keys)
            .unwrap();
        store
            .append_norm_event(&accept("accept-r1", &r1), &keys)
            .unwrap();
        let r2 = store
            .append_norm_event(&requirement("r2", "r2"), &keys)
            .unwrap();
        store
            .append_norm_event(&accept("accept-r2", &r2), &keys)
            .unwrap();
        let revision = |store: &WorkItemStore, id: &str| -> String {
            store.norm_state(&keys).unwrap().effective_records[id]
                .content_head
                .clone()
        };
        let frontier = |store: &WorkItemStore| -> Vec<String> {
            store
                .norm_state(&keys)
                .unwrap()
                .frontier
                .iter()
                .cloned()
                .collect()
        };
        let manifest = |nonce: &str,
                        members: &[String],
                        claim: &str,
                        frontier: Vec<String>,
                        bind: bool| {
            keys.sign_with(
                "worker",
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("manifest"),
                    fields_json: json!({"title": nonce, "selection": "all accepted obligations", "members": members, "claim": claim, "scope": "src/"}).to_string(),
                },
                Some(NormPremises {
                    family_basis: None,
                    references: if bind { members.to_vec() } else { Vec::new() },
                    inventory_frontier: frontier,
                }),
            )
        };
        let both = vec![revision(&store, &r1), revision(&store, &r2)];
        let now = frontier(&store);
        // Complete at its basis.
        let complete = store
            .append_norm_event(
                &manifest("complete", &both, "exhaustive", now.clone(), true),
                &keys,
            )
            .unwrap();
        // Structurally valid and incomplete: admitted, judged incomplete, the
        // missing revision named.
        let partial = store
            .append_norm_event(
                &manifest("partial", &both[..1], "exhaustive", frontier(&store), true),
                &keys,
            )
            .unwrap();
        // An exhaustive claim without a basis is refused; a bounded claim binds none.
        refused(
            store.append_norm_event(
                &manifest("unbased", &both, "exhaustive", Vec::new(), true),
                &keys,
            ),
            "must bind the inventory frontier",
        );
        refused(
            store.append_norm_event(
                &manifest("bounded-based", &both, "bounded", frontier(&store), true),
                &keys,
            ),
            "bounded manifest claim binds no inventory frontier",
        );
        let bounded = store
            .append_norm_event(
                &manifest("bounded", &both[..1], "bounded", Vec::new(), true),
                &keys,
            )
            .unwrap();
        // Members are premises: unbound, or unresolvable, the act is refused;
        // an alias is not even a reference; an unknown frontier is a missing parent.
        refused(
            store.append_norm_event(
                &manifest("unbound", &both, "exhaustive", frontier(&store), false),
                &keys,
            ),
            "must bind the members it names",
        );
        refused(
            store.append_norm_event(
                &manifest(
                    "not-a-revision",
                    std::slice::from_ref(&ledger),
                    "exhaustive",
                    frontier(&store),
                    true,
                ),
                &keys,
            ),
            "does not resolve to an admitted revision",
        );
        // An alias is not a reference at all: bound, it would be a missing
        // parent; unbound, the interpreter refuses its shape.
        refused(
            store.append_norm_event(
                &manifest(
                    "alias",
                    &["N-1".to_owned()],
                    "exhaustive",
                    frontier(&store),
                    false,
                ),
                &keys,
            ),
            "revision reference",
        );
        refused(
            store.append_norm_event(
                &manifest(
                    "unknown-frontier",
                    &both,
                    "exhaustive",
                    vec!["f".repeat(64)],
                    true,
                ),
                &keys,
            ),
            "missing parents",
        );
        // A bound frontier names each admitted event once.
        let dup = frontier(&store);
        refused(
            store.append_norm_event(
                &manifest(
                    "dup-frontier",
                    &both,
                    "exhaustive",
                    vec![dup[0].clone(), dup[0].clone()],
                    true,
                ),
                &keys,
            ),
            "names each admitted event once",
        );
        // A non-manifest act binds no inventory frontier.
        refused(
            store.append_norm_event(
                &keys.sign_with(
                    "worker",
                    "r3-with-frontier",
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("obligation"),
                        fields_json: json!({"name": "r3", "proposition": "holds", "domain": "src/", "subject": "src/x.py"}).to_string(),
                    },
                    Some(NormPremises {
                        family_basis: None,
                        references: Vec::new(),
                        inventory_frontier: frontier(&store),
                    }),
                ),
                &keys,
            ),
            "only an act on a manifest binds",
        );
        let judgments = |store: &mut WorkItemStore| {
            let mut host = NormCommandHost::new(store, &keys);
            let response = host
                .execute(NormCommandRequest::new(NormCommand::Snapshot {}))
                .unwrap();
            let NormCommandResult::Snapshot { snapshot } = response.result else {
                panic!("snapshot expected");
            };
            snapshot.manifests
        };
        let judged = judgments(&mut store);
        assert_eq!(
            judged[&complete].completeness,
            ManifestCompleteness::Complete { basis: now.clone() }
        );
        let ManifestCompleteness::Incomplete { missing, .. } = &judged[&partial].completeness
        else {
            panic!(
                "partial manifest must be judged incomplete: {:?}",
                judged[&partial]
            );
        };
        assert_eq!(missing, &vec![both[1].clone()]);
        assert_eq!(
            judged[&bounded].completeness,
            ManifestCompleteness::Bounded {
                scope: Some("src/".into())
            }
        );
        // A requirement accepted afterwards does not rewrite the judgment at
        // the basis: complete then is complete then, and a fresh exhaustive
        // manifest with the same members is incomplete now.
        let r3 = store
            .append_norm_event(&requirement("r3", "r3"), &keys)
            .unwrap();
        store
            .append_norm_event(&accept("accept-r3", &r3), &keys)
            .unwrap();
        let later = store
            .append_norm_event(
                &manifest("later", &both, "exhaustive", frontier(&store), true),
                &keys,
            )
            .unwrap();
        let judged = judgments(&mut store);
        assert_eq!(
            judged[&complete].completeness,
            ManifestCompleteness::Complete { basis: now }
        );
        let ManifestCompleteness::Incomplete { missing, .. } = &judged[&later].completeness else {
            panic!(
                "later manifest must be judged incomplete: {:?}",
                judged[&later]
            );
        };
        assert_eq!(missing, &vec![revision(&store, &r3)]);
    }

    /// DR-0122 §13.3, the runtime half of `models/maude/correspondence-reuse.maude`:
    /// a correspondence binds both sides as premises and resolves them, and it
    /// activates nothing; a successor becomes active only through an admitted
    /// act on that successor by the authority the transition names.
    #[test]
    fn norm_correspondence_binds_both_sides_and_activates_nothing() {
        use whipplescript_store::norm_commands::NormCommandStore;
        let c = NormCharter::bundled().unwrap();
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "correspondence",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let reference = |name: &str| {
            Vocabulary::new(
                c.vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == name)
                    .unwrap()
                    .definition
                    .clone(),
            )
            .unwrap()
            .reference()
            .clone()
        };
        let refused = |result: Result<String, StoreError>, needle: &str| {
            let message = format!("{:?}", result.expect_err("refusal expected"));
            assert!(message.contains(needle), "{message}");
        };
        let requirement = |nonce: &str| {
            keys.sign(
                "worker",
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("obligation"),
                    fields_json: json!({"name": nonce, "proposition": "holds", "domain": "src/", "subject": "src/x.py"}).to_string(),
                },
            )
        };
        let transition = |actor: &str, nonce: &str, record: &str, status: &str| {
            keys.sign(
                actor,
                nonce,
                NormAct::Transition {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("obligation"),
                    record: record.into(),
                    previous: record.into(),
                    status: status.into(),
                },
            )
        };
        let r = store.append_norm_event(&requirement("r"), &keys).unwrap();
        store
            .append_norm_event(&transition("owner", "accept-r", &r, "accepted"), &keys)
            .unwrap();
        let r1 = store.append_norm_event(&requirement("r1"), &keys).unwrap();
        let r2 = store.append_norm_event(&requirement("r2"), &keys).unwrap();
        let revision = |store: &WorkItemStore, id: &str| -> String {
            store.norm_state(&keys).unwrap().records[id]
                .content_head
                .clone()
        };
        let correspond = |nonce: &str, sources: &[String], targets: &[String], bind: bool| {
            keys.sign_with(
                "worker",
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("correspondence"),
                    fields_json: json!({
                        "sources": sources, "targets": targets, "claim": "split",
                        "property": "the conjunction of the successors preserves the original",
                        "direction": "forward", "witness": "review of 2026-09-18", "mode": "attested",
                        "reliance": "norm.accept"
                    })
                    .to_string(),
                },
                Some(NormPremises {
                    family_basis: None,
                    references: if bind {
                        sources.iter().chain(targets).cloned().collect()
                    } else {
                        Vec::new()
                    },
                    inventory_frontier: Vec::new(),
                }),
            )
        };
        let original = vec![revision(&store, &r)];
        let successors = vec![revision(&store, &r1), revision(&store, &r2)];
        // Bound and resolving, the split is admitted; the successors are
        // untouched by it.
        let split = store
            .append_norm_event(&correspond("split", &original, &successors, true), &keys)
            .unwrap();
        let view = store.norm_state(&keys).unwrap();
        assert_eq!(view.records[&split].status, "proposed");
        assert_eq!(view.records[&r1].status, "proposed");
        assert_eq!(view.records[&r2].status, "proposed");
        assert!(!view.effective_records.contains_key(&r1));
        // Unbound, unresolvable, empty or self-related sides are refused.
        refused(
            store.append_norm_event(&correspond("unbound", &original, &successors, false), &keys),
            "must bind the revisions it names",
        );
        refused(
            store.append_norm_event(
                &correspond(
                    "not-a-revision",
                    &original,
                    std::slice::from_ref(&ledger),
                    true,
                ),
                &keys,
            ),
            "does not resolve to an admitted revision",
        );
        refused(
            store.append_norm_event(&correspond("empty", &original, &[], true), &keys),
            "at least one revision on each side",
        );
        refused(
            store.append_norm_event(&correspond("self", &original, &original, true), &keys),
            "not to itself",
        );
        // Attesting the correspondence is the authority's act, and it still
        // activates no successor. Activation is an act on the successor, by
        // the authority the successor's own transition names.
        let attest = |actor: &str, nonce: &str, previous: &str| {
            keys.sign(
                actor,
                nonce,
                NormAct::Transition {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("correspondence"),
                    record: split.clone(),
                    previous: previous.into(),
                    status: "attested".into(),
                },
            )
        };
        refused(
            store.append_norm_event(&attest("worker", "attest-by-worker", &split), &keys),
            "authenticated governance authority",
        );
        store
            .append_norm_event(&attest("owner", "attest", &split), &keys)
            .unwrap();
        let view = store.norm_state(&keys).unwrap();
        assert_eq!(view.records[&split].status, "attested");
        assert_eq!(view.records[&r1].status, "proposed");
        refused(
            store.append_norm_event(
                &transition("worker", "activate-r1-by-worker", &r1, "accepted"),
                &keys,
            ),
            "authenticated governance authority",
        );
        store
            .append_norm_event(&transition("owner", "activate-r1", &r1, "accepted"), &keys)
            .unwrap();
        let view = store.norm_state(&keys).unwrap();
        assert!(view.effective_records.contains_key(&r1));
        assert_eq!(view.records[&r2].status, "proposed");
        // Lineage to a revision a later edit moved past still resolves.
        store
            .append_norm_event(
                &keys.sign(
                    "worker",
                    "edit-r",
                    NormAct::Edit {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("obligation"),
                        record: r.clone(),
                        previous: view.records[&r].head.clone(),
                        fields_json: json!({"name": "r", "proposition": "holds more", "domain": "src/", "subject": "src/x.py"}).to_string(),
                    },
                ),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &correspond("equivalence", &original, &[revision(&store, &r)], true),
                &keys,
            )
            .unwrap();
    }

    /// DR-0122: a relation, manifest or correspondence declaration is
    /// validated with its charter at bootstrap; a malformed one is not a charter.
    #[test]
    fn norm_typed_declarations_are_validated_with_the_charter() {
        let keys = Keys::new();
        let refuses = |mutate: &dyn Fn(&mut NormCharter), needle: &str| {
            let mut charter = NormCharter::bundled().unwrap();
            mutate(&mut charter);
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let result = store.append_norm_event(
                &keys.sign(
                    "owner",
                    "malformed",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter,
                    },
                ),
                &keys,
            );
            let message = format!(
                "{:?}",
                result.expect_err("malformed declaration must refuse")
            );
            assert!(message.contains(needle), "{message}");
        };
        fn relation(
            charter: &mut NormCharter,
        ) -> &mut whipplescript_store::norm_relations::RelationDeclaration {
            charter
                .vocabularies
                .iter_mut()
                .find(|entry| entry.definition.name == "refines")
                .unwrap()
                .relation
                .as_mut()
                .unwrap()
        }
        refuses(
            &|charter| relation(charter).source = "note".into(),
            "relation source must name a required reference field",
        );
        refuses(
            &|charter| relation(charter).target = "source".into(),
            "relation source and target must be distinct fields",
        );
        refuses(
            &|charter| relation(charter).family = " ".into(),
            "relation family must be named",
        );
        refuses(
            &|charter| relation(charter).live_statuses = vec!["nonexistent".into()],
            "relation live statuses must be nonempty and from the vocabulary",
        );
        refuses(
            &|charter| relation(charter).source_kinds = vec!["nonexistent".into()],
            "relation endpoint kinds must name vocabularies the charter declares",
        );
        fn manifest(
            charter: &mut NormCharter,
        ) -> &mut whipplescript_store::norm_manifests::ManifestDeclaration {
            charter
                .vocabularies
                .iter_mut()
                .find(|entry| entry.definition.name == "manifest")
                .unwrap()
                .manifest
                .as_mut()
                .unwrap()
        }
        refuses(
            &|charter| manifest(charter).members = "title".into(),
            "manifest members must be a required list of revision references",
        );
        refuses(
            &|charter| manifest(charter).claim = "selection".into(),
            "manifest claim must be a required enum field containing the exhaustive literal",
        );
        refuses(
            &|charter| manifest(charter).scope = Some("members".into()),
            "manifest scope must name a text field",
        );
        fn correspondence(
            charter: &mut NormCharter,
        ) -> &mut whipplescript_store::norm_correspondence::CorrespondenceDeclaration {
            charter
                .vocabularies
                .iter_mut()
                .find(|entry| entry.definition.name == "correspondence")
                .unwrap()
                .correspondence
                .as_mut()
                .unwrap()
        }
        refuses(
            &|charter| correspondence(charter).sources = "claim".into(),
            "correspondence sources must be a required list of revision references",
        );
        refuses(
            &|charter| correspondence(charter).targets = "sources".into(),
            "correspondence sources and targets must be distinct fields",
        );
        refuses(
            &|charter| correspondence(charter).claim = "witness".into(),
            "correspondence claim must be a required enum field",
        );
    }

    /// A creation preview refuses a nonce this ledger already admitted and
    /// accepts a fresh one; the preview is not admission.
    #[test]
    fn norm_preview_refuses_an_admitted_nonce() {
        use whipplescript_store::norm_commands::NormCommandStore;
        use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let admitted = keys.create(&ledger, "once");
        store.append_norm_event(&admitted, &keys).unwrap();
        let history = CapturedNormHistory::capture(
            &store.norm_state(&keys).unwrap(),
            &store.tracker_history().unwrap(),
            &keys,
            NormHistoryLimits::default(),
        )
        .unwrap();
        let message = format!(
            "{:?}",
            history
                .preview_creation(&admitted.statement)
                .expect_err("an admitted nonce cannot be previewed again")
        );
        assert!(message.contains("nonce was already admitted"), "{message}");
        history
            .preview_creation(&keys.create(&ledger, "fresh").statement)
            .unwrap();
    }

    /// DR-0123: the engineering vocabulary is a charter document, installed
    /// through the ordinary bootstrap path with no kernel change, and the
    /// loop it describes closes on the store as it is: requirement, decision
    /// and its attested incorporation, initiative and task, observation,
    /// specification judged at its frontier and reproduced there, release
    /// bound to baseline and evidence, and a requirement revision after which
    /// the task's target is obsolete while every historical judgment stands.
    #[test]
    fn norm_engineering_charter_installs_as_declarations_and_closes_the_loop() {
        use whipplescript_store::norm_commands::*;
        use whipplescript_store::norm_manifests::ManifestCompleteness;
        let charter: NormCharter =
            serde_json::from_str(include_str!("../../../examples/engineering/charter.json"))
                .expect("the engineering charter is a charter");
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "engineering",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: charter.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let reference = |name: &str| {
            Vocabulary::new(
                charter
                    .vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == name)
                    .unwrap_or_else(|| panic!("charter declares {name}"))
                    .definition
                    .clone(),
            )
            .unwrap()
            .reference()
            .clone()
        };
        let refused = |result: Result<String, StoreError>, needle: &str| {
            let message = format!("{:?}", result.expect_err("refusal expected"));
            assert!(message.contains(needle), "{message}");
        };
        let create = |actor: &str, nonce: &str, kind: &str, fields: serde_json::Value| {
            keys.sign(
                actor,
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference(kind),
                    fields_json: fields.to_string(),
                },
            )
        };
        let transition =
            |actor: &str, nonce: &str, kind: &str, record: &str, previous: &str, status: &str| {
                keys.sign(
                    actor,
                    nonce,
                    NormAct::Transition {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference(kind),
                        record: record.into(),
                        previous: previous.into(),
                        status: status.into(),
                    },
                )
            };
        let view = |store: &WorkItemStore| store.norm_state(&keys).unwrap();
        let head = |store: &WorkItemStore, id: &str| view(store).records[id].head.clone();
        let revision =
            |store: &WorkItemStore, id: &str| view(store).records[id].content_head.clone();
        let effective = |store: &WorkItemStore, id: &str| {
            view(store).effective_records[id].content_head.clone()
        };
        let basis = |store: &WorkItemStore, family: &str| {
            view(store).relation_family(family).unwrap().basis
        };
        let relate =
            |actor: &str, nonce: &str, kind: &str, source: &str, target: &str, basis: &str| {
                keys.sign_with(
                    actor,
                    nonce,
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference(kind),
                        fields_json: json!({"source": source, "target": target}).to_string(),
                    },
                    Some(NormPremises {
                        family_basis: Some(basis.into()),
                        references: vec![source.into(), target.into()],
                        inventory_frontier: Vec::new(),
                    }),
                )
            };
        let snapshot = |store: &mut WorkItemStore, frontier: Option<Vec<String>>| {
            let mut host = NormCommandHost::new(store, &keys);
            let command = match frontier {
                None => NormCommand::Snapshot {},
                Some(frontier) => NormCommand::SnapshotAt { frontier },
            };
            match host
                .execute(NormCommandRequest::new(command))
                .unwrap()
                .result
            {
                NormCommandResult::Snapshot { snapshot } => *snapshot,
                NormCommandResult::HistoricalSnapshot { snapshot, .. } => *snapshot,
                other => panic!("snapshot expected, got {other:?}"),
            }
        };

        // A requirement, accepted by the authority, forms the inventory.
        let r = store
            .append_norm_event(
                &create("worker", "R", "requirement", json!({
                    "name": "custody-authorization", "proposition": "role == owner or grant == allow",
                    "domain": "src/", "subject": "src/auth.py",
                    "applicability": "every mainline candidate", "owner": "owner"
                })),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &transition("owner", "accept-R", "requirement", &r, &r, "accepted"),
                &keys,
            )
            .unwrap();
        let r0 = effective(&store, &r);
        assert_eq!(
            view(&store)
                .requirement_inventory()
                .unwrap()
                .requirements
                .len(),
            1
        );

        // A decision, accepted on its exact content by the authority alone.
        let d = store
            .append_norm_event(
                &create("worker", "D", "decision", json!({
                    "title": "Authorize by role or grant", "question": "who may act",
                    "course": "owners always, workers when granted", "rationale": "least authority",
                    "alternatives": ["grants only"], "scope": "src/auth.py",
                    "consequences": "the parser interprets grants", "subjects": ["src/auth.py"]
                })),
                &keys,
            )
            .unwrap();
        refused(
            store.append_norm_event(
                &transition("worker", "accept-D-worker", "decision", &d, &d, "accepted"),
                &keys,
            ),
            "authenticated governance authority",
        );
        store
            .append_norm_event(
                &transition("owner", "accept-D", "decision", &d, &d, "accepted"),
                &keys,
            )
            .unwrap();
        // Incorporation is the authority's attestation, not the worker's.
        let incorporation = basis(&store, "incorporation");
        refused(
            store.append_norm_event(
                &relate(
                    "worker",
                    "inc-worker",
                    "incorporates",
                    &d,
                    &r0,
                    &incorporation,
                ),
                &keys,
            ),
            "authenticated governance authority",
        );
        store
            .append_norm_event(
                &relate("owner", "inc", "incorporates", &d, &r0, &incorporation),
                &keys,
            )
            .unwrap();

        // An initiative committed by its authority, and a task targeting the
        // requirement's exact revision.
        let i = store
            .append_norm_event(
                &create("worker", "I", "initiative", json!({
                    "title": "Ship authorization", "problem": "no authorization",
                    "outcome": "owners and granted workers act", "owner": "owner", "scope": "src/"
                })),
                &keys,
            )
            .unwrap();
        refused(
            store.append_norm_event(
                &transition(
                    "worker",
                    "commit-I-worker",
                    "initiative",
                    &i,
                    &i,
                    "committed",
                ),
                &keys,
            ),
            "authenticated governance authority",
        );
        store
            .append_norm_event(
                &transition("owner", "commit-I", "initiative", &i, &i, "committed"),
                &keys,
            )
            .unwrap();
        let t = store
            .append_norm_event(
                &create(
                    "worker",
                    "T",
                    "task",
                    json!({"title": "implement custody authorization", "labels": ["norm"]}),
                ),
                &keys,
            )
            .unwrap();
        let work = basis(&store, "work");
        store
            .append_norm_event(
                &relate("worker", "T-targets", "targets", &t, &r0, &work),
                &keys,
            )
            .unwrap();

        // An observation of the checked artifact, offered as support.
        let o = store
            .append_norm_event(
                &create("worker", "O", "observation", json!({
                    "title": "Q0 on A0", "statement": "all four cases pass", "subject": "src/auth.py",
                    "artifact": "cut-a0", "method": "Q0", "outcome": "pass"
                })),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &transition("owner", "activate-O", "observation", &o, &o, "active"),
                &keys,
            )
            .unwrap();
        let o0 = revision(&store, &o);
        let support = basis(&store, "support");
        store
            .append_norm_event(
                &relate("worker", "O-supports", "supports", &o, &r0, &support),
                &keys,
            )
            .unwrap();

        // A specification: an exhaustive claim judged at its bound frontier,
        // published by the authority, and reproduced by the historical
        // snapshot at that frontier.
        let baseline_frontier: Vec<String> = view(&store).frontier.iter().cloned().collect();
        let s = store
            .append_norm_event(
                &keys.sign_with(
                    "worker",
                    "S",
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("specification"),
                        fields_json: json!({
                            "title": "Authorization 1.0", "purpose": "what mainline must satisfy",
                            "selection": "every accepted requirement in src/", "members": [r0],
                            "claim": "exhaustive", "scope": "src/", "definitions": "grant: a recorded allowance"
                        })
                        .to_string(),
                    },
                    Some(NormPremises {
                        family_basis: None,
                        references: vec![r0.clone()],
                        inventory_frontier: baseline_frontier.clone(),
                    }),
                ),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &transition("owner", "publish-S", "specification", &s, &s, "published"),
                &keys,
            )
            .unwrap();
        let s0 = revision(&store, &s);
        let judged = snapshot(&mut store, None).manifests;
        assert_eq!(
            judged[&s].completeness,
            ManifestCompleteness::Complete {
                basis: baseline_frontier.clone()
            }
        );
        let published_frontier: Vec<String> = view(&store).frontier.iter().cloned().collect();
        let historical = snapshot(&mut store, Some(published_frontier.clone()));
        assert_eq!(
            historical.manifests[&s].completeness,
            judged[&s].completeness
        );

        // A release bound to its baseline and its evidence, admitted by the
        // release authority alone.
        let l = store
            .append_norm_event(
                &create("worker", "L", "release", json!({
                    "title": "1.0", "artifacts": ["cut-a0"], "policy": "mainline gated by Authorization 1.0", "exceptions": []
                })),
                &keys,
            )
            .unwrap();
        let binding = basis(&store, "release-binding");
        store
            .append_norm_event(
                &relate("worker", "L-baseline", "baselined_on", &l, &s0, &binding),
                &keys,
            )
            .unwrap();
        let binding = basis(&store, "release-binding");
        store
            .append_norm_event(
                &relate("worker", "L-evidence", "supported_by", &l, &o0, &binding),
                &keys,
            )
            .unwrap();
        refused(
            store.append_norm_event(
                &transition("worker", "admit-L-worker", "release", &l, &l, "admitted"),
                &keys,
            ),
            "authenticated governance authority",
        );
        store
            .append_norm_event(
                &transition("owner", "admit-L", "release", &l, &l, "admitted"),
                &keys,
            )
            .unwrap();

        // The requirement is revised: a draft edit leaves the accepted
        // revision effective; acceptance of the new revision moves it.
        let edited = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "edit-R",
                    NormAct::Edit {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("requirement"),
                        record: r.clone(),
                        previous: head(&store, &r),
                        fields_json: json!({
                            "name": "custody-authorization", "proposition": "role == owner or (grant == allow and grant is fresh)",
                            "domain": "src/", "subject": "src/auth.py",
                            "applicability": "every mainline candidate", "owner": "owner"
                        })
                        .to_string(),
                    },
                ),
                &keys,
            )
            .unwrap();
        assert_eq!(effective(&store, &r), r0);
        store
            .append_norm_event(
                &transition("owner", "accept-R1", "requirement", &r, &edited, "accepted"),
                &keys,
            )
            .unwrap();
        let r1 = effective(&store, &r);
        assert_ne!(r1, r0);

        // Reconciliation is derived from the snapshot, never performed: the
        // task still targets r0, and r0 is no longer effective.
        let current = snapshot(&mut store, None);
        let target = &current.families["work"].edges[0];
        assert_eq!(
            (target.source.as_str(), target.target.as_str()),
            (t.as_str(), r.as_str())
        );
        let targeted_revision = view(&store).records[&t].id.clone();
        let _ = targeted_revision;
        let targets_obsolete = view(&store)
            .records
            .values()
            .filter(|record| record.vocabulary.name == "targets")
            .any(|edge| edge.fields["target"] == json!(r0) && effective(&store, &r) != r0);
        assert!(
            targets_obsolete,
            "the task's targeted revision is no longer effective"
        );
        assert_eq!(view(&store).records[&t].status, "open");
        // The specification's judgment at its basis is unchanged; a fresh
        // exhaustive claim is judged at its own frontier and finds r1 missing.
        assert_eq!(
            current.manifests[&s].completeness,
            ManifestCompleteness::Complete {
                basis: baseline_frontier.clone()
            }
        );
        let now: Vec<String> = view(&store).frontier.iter().cloned().collect();
        let s2 = store
            .append_norm_event(
                &keys.sign_with(
                    "worker",
                    "S2",
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("specification"),
                        fields_json: json!({
                            "title": "Authorization 1.0 again", "purpose": "p", "selection": "s",
                            "members": [r0], "claim": "exhaustive"
                        })
                        .to_string(),
                    },
                    Some(NormPremises {
                        family_basis: None,
                        references: vec![r0.clone()],
                        inventory_frontier: now,
                    }),
                ),
                &keys,
            )
            .unwrap();
        let current = snapshot(&mut store, None);
        let ManifestCompleteness::Incomplete { missing, .. } = &current.manifests[&s2].completeness
        else {
            panic!(
                "a fresh exhaustive claim is incomplete now: {:?}",
                current.manifests[&s2]
            );
        };
        assert_eq!(missing, &vec![r1.clone()]);
        // The release's claim stands as made: admitted, bound to s0 and o0.
        assert_eq!(view(&store).records[&l].status, "admitted");
        let bindings: Vec<(String, String)> = current.families["release-binding"]
            .edges
            .iter()
            .map(|edge| (edge.relation.clone(), edge.target.clone()))
            .collect();
        assert!(bindings.contains(&("baselined_on".into(), s.clone())));
        assert!(bindings.contains(&("supported_by".into(), o.clone())));
        // And the historical snapshot at publication still shows r0 effective.
        let then = snapshot(&mut store, Some(published_frontier));
        let then_r = then
            .records
            .iter()
            .find(|named| named.record.id == r)
            .unwrap();
        let EffectiveRevision::Active { record, .. } = &then_r.effectiveness else {
            panic!("r was effective at publication");
        };
        assert_eq!(record.content_head, r0);
    }

    /// Stage 3 of the operating-model note (norm-plane §8.1, the Q1 subset):
    /// rendering, the diff of meaning and explanation are pure projections at
    /// a named frontier. A rendering carries the derived completeness
    /// judgment and nothing derived from the members it lists, so a bounded
    /// or incomplete manifest whose every member is visible is still not
    /// complete. The diff classifies a revision by the declaration's field
    /// classification. Every explanation node is one of five kinds and names
    /// its basis.
    #[test]
    fn norm_views_render_diff_and_explain_at_named_frontiers() {
        use whipplescript_store::norm_commands::*;
        use whipplescript_store::norm_manifests::ManifestCompleteness;
        use whipplescript_store::norm_views::*;
        let charter: NormCharter =
            serde_json::from_str(include_str!("../../../examples/engineering/charter.json"))
                .expect("the engineering charter is a charter");
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "engineering",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: charter.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let reference = |name: &str| {
            Vocabulary::new(
                charter
                    .vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == name)
                    .unwrap_or_else(|| panic!("charter declares {name}"))
                    .definition
                    .clone(),
            )
            .unwrap()
            .reference()
            .clone()
        };
        let create = |actor: &str, nonce: &str, kind: &str, fields: serde_json::Value| {
            keys.sign(
                actor,
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference(kind),
                    fields_json: fields.to_string(),
                },
            )
        };
        let transition =
            |actor: &str, nonce: &str, kind: &str, record: &str, previous: &str, status: &str| {
                keys.sign(
                    actor,
                    nonce,
                    NormAct::Transition {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference(kind),
                        record: record.into(),
                        previous: previous.into(),
                        status: status.into(),
                    },
                )
            };
        let relate =
            |actor: &str, nonce: &str, kind: &str, source: &str, target: &str, basis: &str| {
                keys.sign_with(
                    actor,
                    nonce,
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference(kind),
                        fields_json: json!({"source": source, "target": target}).to_string(),
                    },
                    Some(NormPremises {
                        family_basis: Some(basis.into()),
                        references: vec![source.into(), target.into()],
                        inventory_frontier: Vec::new(),
                    }),
                )
            };
        let manifest = |actor: &str,
                        nonce: &str,
                        fields: serde_json::Value,
                        members: Vec<String>,
                        frontier: Vec<String>| {
            keys.sign_with(
                actor,
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("specification"),
                    fields_json: fields.to_string(),
                },
                Some(NormPremises {
                    family_basis: None,
                    references: members,
                    inventory_frontier: frontier,
                }),
            )
        };
        let view = |store: &WorkItemStore| store.norm_state(&keys).unwrap();
        let head = |store: &WorkItemStore, id: &str| view(store).records[id].head.clone();
        let effective = |store: &WorkItemStore, id: &str| {
            view(store).effective_records[id].content_head.clone()
        };
        let basis = |store: &WorkItemStore, family: &str| {
            view(store).relation_family(family).unwrap().basis
        };
        let frontier = |store: &WorkItemStore| -> Vec<String> {
            view(store).frontier.iter().cloned().collect()
        };
        fn run(
            store: &mut WorkItemStore,
            keys: &Keys,
            command: NormCommand,
        ) -> Result<NormCommandResult, StoreError> {
            NormCommandHost::new(store, keys)
                .execute(NormCommandRequest::new(command))
                .map(|response| response.result)
        }
        let render =
            |store: &mut WorkItemStore, manifest: &str, frontier: Option<Vec<String>>| match run(
                store,
                &keys,
                NormCommand::Render {
                    manifest: manifest.into(),
                    frontier,
                },
            )
            .unwrap()
            {
                NormCommandResult::Rendered { rendering, .. } => *rendering,
                other => panic!("rendering expected, got {other:?}"),
            };
        let diff =
            |store: &mut WorkItemStore, before: Vec<String>, after: Option<Vec<String>>| match run(
                store,
                &keys,
                NormCommand::Diff { before, after },
            )
            .unwrap()
            {
                NormCommandResult::Differed { diff, .. } => *diff,
                other => panic!("diff expected, got {other:?}"),
            };
        let explain =
            |store: &mut WorkItemStore, record: &str, frontier: Option<Vec<String>>| match run(
                store,
                &keys,
                NormCommand::Explain {
                    record: record.into(),
                    frontier,
                },
            )
            .unwrap()
            {
                NormCommandResult::Explained { explanation, .. } => *explanation,
                other => panic!("explanation expected, got {other:?}"),
            };
        let refused = |result: Result<NormCommandResult, StoreError>, needle: &str| {
            let message = format!("{:?}", result.expect_err("refusal expected"));
            assert!(message.contains(needle), "{message}");
        };

        // A requirement accepted, a task targeting its revision, an
        // observation supporting it, an exhaustive specification judged at
        // the frontier it bound, and a bounded one over the same member.
        let r = store
            .append_norm_event(
                &create("worker", "R", "requirement", json!({
                    "name": "custody-authorization", "proposition": "role == owner or grant == allow",
                    "domain": "src/", "subject": "src/auth.py",
                    "applicability": "every mainline candidate", "owner": "owner"
                })),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &transition("owner", "accept-R", "requirement", &r, &r, "accepted"),
                &keys,
            )
            .unwrap();
        let r0 = effective(&store, &r);
        let t = store
            .append_norm_event(
                &create(
                    "worker",
                    "T",
                    "task",
                    json!({"title": "implement custody authorization", "labels": ["norm"]}),
                ),
                &keys,
            )
            .unwrap();
        let work = basis(&store, "work");
        store
            .append_norm_event(
                &relate("worker", "T-targets", "targets", &t, &r0, &work),
                &keys,
            )
            .unwrap();
        let o = store
            .append_norm_event(
                &create("worker", "O", "observation", json!({
                    "title": "Q0 on A0", "statement": "all four cases pass", "subject": "src/auth.py",
                    "artifact": "cut-a0", "method": "Q0", "outcome": "pass"
                })),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &transition("owner", "activate-O", "observation", &o, &o, "active"),
                &keys,
            )
            .unwrap();
        let support = basis(&store, "support");
        store
            .append_norm_event(
                &relate("worker", "O-supports", "supports", &o, &r0, &support),
                &keys,
            )
            .unwrap();
        let baseline_frontier = frontier(&store);
        let s = store
            .append_norm_event(
                &manifest(
                    "worker",
                    "S",
                    json!({
                        "title": "Authorization 1.0", "purpose": "what mainline must satisfy",
                        "selection": "every accepted requirement in src/", "members": [r0],
                        "claim": "exhaustive", "scope": "src/", "definitions": "grant: a recorded allowance"
                    }),
                    vec![r0.clone()],
                    baseline_frontier.clone(),
                ),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &transition("owner", "publish-S", "specification", &s, &s, "published"),
                &keys,
            )
            .unwrap();
        let b = store
            .append_norm_event(
                &manifest(
                    "worker",
                    "B",
                    json!({
                        "title": "Authorization, src only", "purpose": "a bounded view",
                        "selection": "what the author could see", "members": [r0],
                        "claim": "bounded", "scope": "src/"
                    }),
                    vec![r0.clone()],
                    Vec::new(),
                ),
                &keys,
            )
            .unwrap();
        let published_frontier = frontier(&store);

        // Rendering: the member at its exact revision, effective here; the
        // document is the manifest's own fields without the member list; the
        // judgment is the derived one at the bound basis.
        let rendered = render(&mut store, &s, Some(published_frontier.clone()));
        assert_eq!(rendered.frontier, published_frontier);
        assert_eq!(rendered.manifest.id, s);
        assert!(
            rendered.manifest.alias.is_some(),
            "aliases are local and present"
        );
        assert!(rendered.document.get("members").is_none());
        assert_eq!(rendered.document["title"], json!("Authorization 1.0"));
        assert_eq!(
            rendered.document["definitions"],
            json!("grant: a recorded allowance")
        );
        assert_eq!(rendered.members.len(), 1);
        assert_eq!(rendered.members[0].reference, r0);
        assert_eq!(rendered.members[0].record.id, r);
        assert_eq!(rendered.members[0].record.revision, r0);
        assert_eq!(
            rendered.members[0].fields["proposition"],
            json!("role == owner or grant == allow")
        );
        assert_eq!(rendered.members[0].standing, MemberStanding::Effective);
        assert_eq!(
            rendered.completeness.completeness,
            ManifestCompleteness::Complete {
                basis: baseline_frontier.clone()
            }
        );
        // The bounded manifest lists every applicable revision there is, and
        // the rendering still says only what was judged: bounded to a scope.
        let bounded = render(&mut store, &b, None);
        assert_eq!(bounded.members.len(), rendered.members.len());
        assert_eq!(
            bounded.completeness.completeness,
            ManifestCompleteness::Bounded {
                scope: Some("src/".into())
            }
        );
        // Only a manifest renders.
        refused(
            run(
                &mut store,
                &keys,
                NormCommand::Render {
                    manifest: r.clone(),
                    frontier: None,
                },
            ),
            "not a manifest",
        );
        refused(
            run(
                &mut store,
                &keys,
                NormCommand::Render {
                    manifest: "0".repeat(64),
                    frontier: None,
                },
            ),
            "no norm record",
        );

        // The requirement is revised in meaning and accepted; the task is
        // reworded in an editorial field only.
        let edited = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "edit-R",
                    NormAct::Edit {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("requirement"),
                        record: r.clone(),
                        previous: head(&store, &r),
                        fields_json: json!({
                            "name": "custody-authorization", "proposition": "role == owner or (grant == allow and grant is fresh)",
                            "domain": "src/", "subject": "src/auth.py",
                            "applicability": "every mainline candidate", "owner": "owner"
                        })
                        .to_string(),
                    },
                ),
                &keys,
            )
            .unwrap();
        store
            .append_norm_event(
                &transition("owner", "accept-R1", "requirement", &r, &edited, "accepted"),
                &keys,
            )
            .unwrap();
        let r1 = effective(&store, &r);
        assert_ne!(r1, r0);
        store
            .append_norm_event(
                &keys.sign(
                    "worker",
                    "edit-T",
                    NormAct::Edit {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: reference("task"),
                        record: t.clone(),
                        previous: head(&store, &t),
                        fields_json: json!({
                            "title": "implement custody authorization",
                            "labels": ["norm", "authorization"], "queue": "now"
                        })
                        .to_string(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let now = frontier(&store);
        let s3 = store
            .append_norm_event(
                &manifest(
                    "worker",
                    "S3",
                    json!({
                        "title": "Authorization 1.0 again", "purpose": "p", "selection": "s",
                        "members": [r0], "claim": "exhaustive"
                    }),
                    vec![r0.clone()],
                    now.clone(),
                ),
                &keys,
            )
            .unwrap();

        // The old member renders at its exact revision, superseded now; the
        // historical judgment is unchanged; the fresh claim is incomplete
        // while its one member renders in full.
        let rendered = render(&mut store, &s, None);
        assert_eq!(
            rendered.members[0].fields["proposition"],
            json!("role == owner or grant == allow")
        );
        assert_eq!(
            rendered.members[0].standing,
            MemberStanding::Superseded {
                effective: r1.clone()
            }
        );
        assert_eq!(
            rendered.completeness.completeness,
            ManifestCompleteness::Complete {
                basis: baseline_frontier.clone()
            }
        );
        let fresh = render(&mut store, &s3, None);
        assert_eq!(fresh.members.len(), 1);
        assert_eq!(
            fresh.completeness.completeness,
            ManifestCompleteness::Incomplete {
                basis: now.clone(),
                missing: vec![r1.clone()]
            }
        );

        // The diff of meaning from publication to now.
        let latest = frontier(&store);
        let changes = diff(&mut store, published_frontier.clone(), None);
        assert_eq!(changes.before, published_frontier);
        assert_eq!(changes.after, latest);
        assert!(changes.inventory.before_classification_complete);
        assert!(changes.inventory.after_classification_complete);
        let of = |changes: &MeaningDiff, id: &str| -> Vec<RecordChangeKind> {
            changes
                .records
                .iter()
                .find(|change| change.record == id)
                .map(|change| change.changes.clone())
                .unwrap_or_default()
        };
        let r_changes = of(&changes, &r);
        assert!(
            r_changes.iter().any(|change| matches!(
                change,
                RecordChangeKind::Revised { from, to, classification: ChangeClass::Meaning, fields }
                    if *from == r0 && *to == r1
                        && fields == &vec![FieldChange {
                            field: "proposition".into(),
                            change: FieldChangeKind::Changed,
                            classification: ChangeClass::Meaning,
                        }]
            )),
            "{r_changes:?}"
        );
        assert!(
            r_changes.iter().any(|change| matches!(
                change,
                RecordChangeKind::Effect {
                    from: EffectSummary::Active { revision: from, .. },
                    to: EffectSummary::Active { revision: to, .. },
                } if *from == r0 && *to == r1
            )),
            "{r_changes:?}"
        );
        let t_changes = of(&changes, &t);
        assert!(
            t_changes.iter().any(|change| matches!(
                change,
                RecordChangeKind::Revised { classification: ChangeClass::Editorial, fields, .. }
                    if fields.len() == 2
                        && fields.iter().all(|field| field.classification == ChangeClass::Editorial)
                        && fields.iter().any(|field| field.field == "labels" && field.change == FieldChangeKind::Changed)
                        && fields.iter().any(|field| field.field == "queue" && field.change == FieldChangeKind::Added)
            )),
            "{t_changes:?}"
        );
        assert_eq!(
            of(&changes, &s3),
            vec![RecordChangeKind::Created {
                revision: s3.clone()
            }]
        );
        assert!(of(&changes, &s).is_empty());
        assert!(
            changes.edges.is_empty(),
            "no live edge moved: {:?}",
            changes.edges
        );
        let s3_change = changes
            .manifests
            .iter()
            .find(|change| change.record == s3)
            .expect("the fresh claim is a manifest change");
        assert!(s3_change.before.is_none());
        assert!(matches!(
            s3_change
                .after
                .as_ref()
                .map(|judgment| &judgment.completeness),
            Some(ManifestCompleteness::Incomplete { .. })
        ));
        assert!(changes.manifests.iter().all(|change| change.record != s));
        // The reverse diff names what the earlier frontier does not reach.
        let latest = frontier(&store);
        let reverse = diff(&mut store, latest, Some(published_frontier.clone()));
        assert_eq!(
            of(&reverse, &s3),
            vec![RecordChangeKind::Unreached {
                revision: s3.clone()
            }]
        );
        assert!(of(&reverse, &r).iter().any(|change| matches!(
            change,
            RecordChangeKind::Revised { from, to, .. } if *from == r1 && *to == r0
        )));
        // Both ends are named frontiers of the history.
        refused(
            run(
                &mut store,
                &keys,
                NormCommand::Diff {
                    before: vec!["0".repeat(64)],
                    after: None,
                },
            ),
            "frontier",
        );

        // Explanations: every node is one of five kinds and names its basis.
        let five = ["obligation", "revision", "evidence", "premise", "authority"];
        let check_shape = |explanation: &Explanation| {
            assert!(!explanation.nodes.is_empty());
            for node in &explanation.nodes {
                let json = serde_json::to_value(node).unwrap();
                assert!(five.contains(&json["kind"].as_str().unwrap()), "{json}");
                let basis = &json["basis"];
                let named = match basis["kind"].as_str().unwrap() {
                    "frontier" | "inventory" => !basis["frontier"].as_array().unwrap().is_empty(),
                    "family" => !basis["basis"].as_str().unwrap().is_empty(),
                    "act" => !basis["event"].as_str().unwrap().is_empty(),
                    other => panic!("unknown basis {other}"),
                };
                assert!(named, "every node names its basis: {json}");
            }
        };
        let kinds = |explanation: &Explanation, kind: ExplanationKind| -> Vec<ExplanationNode> {
            explanation
                .nodes
                .iter()
                .filter(|node| node.kind == kind)
                .cloned()
                .collect()
        };
        // The task: its obligation is named at r0, whose effective revision is r1.
        let task = explain(&mut store, &t, None);
        check_shape(&task);
        assert_eq!(task.subject.id, t);
        let obligations = kinds(&task, ExplanationKind::Obligation);
        assert!(
            obligations
                .iter()
                .any(|node| node.detail["requirement"] == json!(r)
                    && node.detail["named"] == json!(r0)
                    && node.detail["effective"] == json!(r1)
                    && node.statement.contains("its effective revision here is")),
            "{obligations:?}"
        );
        assert!(kinds(&task, ExplanationKind::Evidence)
            .iter()
            .any(|node| node.detail["edge"]["relation"] == json!("targets")));
        assert!(kinds(&task, ExplanationKind::Authority)
            .iter()
            .any(|node| node.statement == "created by worker"));
        assert!(kinds(&task, ExplanationKind::Premise)
            .iter()
            .any(|node| node.detail["premises"].is_null() && node.detail["parents"].is_array()));
        // The requirement: an applicable obligation; supported, targeted, and
        // a member of two manifests; effective at r1 by the owner's act.
        let requirement = explain(&mut store, &r, None);
        check_shape(&requirement);
        assert!(kinds(&requirement, ExplanationKind::Obligation)
            .iter()
            .any(|node| node
                .statement
                .starts_with("applicable requirement custody-authorization")));
        let evidence = kinds(&requirement, ExplanationKind::Evidence);
        assert!(evidence
            .iter()
            .any(|node| node.detail["edge"]["relation"] == json!("supports")));
        assert!(evidence
            .iter()
            .any(|node| node.detail["edge"]["relation"] == json!("targets")));
        let memberships: Vec<&ExplanationNode> = evidence
            .iter()
            .filter(|node| node.detail["member"] == json!(r0))
            .collect();
        assert_eq!(memberships.len(), 3, "S, B and S3 list r0: {memberships:?}");
        let revisions = kinds(&requirement, ExplanationKind::Revision);
        assert!(revisions
            .iter()
            .any(|node| node.detail["revision"] == json!(r1)
                && node.detail["status"] == json!("accepted")));
        assert!(kinds(&requirement, ExplanationKind::Authority)
            .iter()
            .any(|node| {
                node.statement.starts_with("activated by owner")
                    && node.detail["rules"]
                        .as_array()
                        .is_some_and(|rules| !rules.is_empty())
            }));
        // At the published frontier the same record was effective at r0.
        let then = explain(&mut store, &r, Some(published_frontier.clone()));
        check_shape(&then);
        assert_eq!(then.frontier, published_frontier);
        assert!(kinds(&then, ExplanationKind::Revision)
            .iter()
            .any(|node| node.detail["revision"] == json!(r0)
                && node.detail["activation"].is_string()));
        assert!(!kinds(&then, ExplanationKind::Revision)
            .iter()
            .any(|node| node.detail["revision"] == json!(r1)));
        // The specification: its premise is the inventory frontier it bound,
        // and its evidence is the judgment there.
        let specification = explain(&mut store, &s, None);
        check_shape(&specification);
        assert!(kinds(&specification, ExplanationKind::Premise)
            .iter()
            .any(|node| {
                node.basis
                    == ExplanationBasis::Inventory {
                        frontier: baseline_frontier.clone(),
                    }
                    && node.statement.contains("judged against the inventory")
            }));
        assert!(kinds(&specification, ExplanationKind::Evidence)
            .iter()
            .any(|node| {
                node.statement == "the exhaustive claim is complete at its basis"
                    && node.basis
                        == ExplanationBasis::Inventory {
                            frontier: baseline_frontier.clone(),
                        }
            }));
        let bounded = explain(&mut store, &b, None);
        assert!(kinds(&bounded, ExplanationKind::Evidence)
            .iter()
            .any(|node| node.statement.contains("bounded to scope src/")));
        // A record the frontier does not reach cannot be explained there.
        refused(
            run(
                &mut store,
                &keys,
                NormCommand::Explain {
                    record: s3.clone(),
                    frontier: Some(published_frontier),
                },
            ),
            "no norm record",
        );
    }

    /// DR-0124 §14.6: an artifact is a record of the bundled `artifact`
    /// vocabulary, admitted only under the `build.publish` scope and never
    /// edited; in the engineering charter a task's `implements` edge to its
    /// revision is an ordinary relation, and a requirement cannot implement.
    #[test]
    fn norm_artifacts_are_bundled_records_under_build_publish_and_implements_is_an_edge() {
        use whipplescript_store::norm_commands::NormCommandStore;
        let refused = |result: Result<String, StoreError>, needle: &str| {
            let message = format!("{:?}", result.expect_err("refusal expected"));
            assert!(message.contains(needle), "{message}");
        };
        let artifact_fields = json!({
            "cut": "cut-a0", "label": "root//parser:parser", "configuration": "cfg:linux-x86_64",
            "outputs": ["0a"], "classification": "low", "encoding": "whipplescript.build.input-root/v1"
        });
        // The bundled charter.
        {
            let keys = Keys::new();
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let bundled = NormCharter::bundled().unwrap();
            assert!(bundled.owner_scopes.contains(&"build.publish".to_string()));
            let ledger = store
                .append_norm_event(
                    &keys.sign(
                        "owner",
                        "bundled",
                        NormAct::Bootstrap {
                            creator: "worker".into(),
                            charter: bundled.clone(),
                        },
                    ),
                    &keys,
                )
                .unwrap();
            let artifact = Vocabulary::new(
                bundled
                    .vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == "artifact")
                    .expect("the bundled defaults declare artifact")
                    .definition
                    .clone(),
            )
            .unwrap()
            .reference()
            .clone();
            let create = |actor: &str, nonce: &str| {
                keys.sign(
                    actor,
                    nonce,
                    NormAct::Create {
                        ledger: ledger.clone(),
                        authority: None,
                        vocabulary: artifact.clone(),
                        fields_json: artifact_fields.to_string(),
                    },
                )
            };
            refused(
                store.append_norm_event(&create("worker", "A-worker"), &keys),
                "authenticated governance authority",
            );
            let a = store
                .append_norm_event(&create("owner", "A"), &keys)
                .unwrap();
            let view = store.norm_state(&keys).unwrap();
            assert_eq!(view.records[&a].status, "recorded");
            assert_eq!(view.records[&a].fields, artifact_fields);
            refused(
                store.append_norm_event(
                    &keys.sign(
                        "owner",
                        "edit-A",
                        NormAct::Edit {
                            ledger: ledger.clone(),
                            authority: None,
                            vocabulary: artifact.clone(),
                            record: a.clone(),
                            previous: a.clone(),
                            fields_json: artifact_fields.to_string(),
                        },
                    ),
                    &keys,
                ),
                "no edit rule",
            );
        }
        // The engineering charter.
        let charter: NormCharter =
            serde_json::from_str(include_str!("../../../examples/engineering/charter.json"))
                .expect("the engineering charter is a charter");
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "engineering",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: charter.clone(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let reference = |name: &str| {
            Vocabulary::new(
                charter
                    .vocabularies
                    .iter()
                    .find(|entry| entry.definition.name == name)
                    .unwrap_or_else(|| panic!("charter declares {name}"))
                    .definition
                    .clone(),
            )
            .unwrap()
            .reference()
            .clone()
        };
        let create = |actor: &str, nonce: &str, kind: &str, fields: serde_json::Value| {
            keys.sign(
                actor,
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference(kind),
                    fields_json: fields.to_string(),
                },
            )
        };
        let view = |store: &WorkItemStore| store.norm_state(&keys).unwrap();
        let relate = |actor: &str, nonce: &str, source: &str, target: &str, basis: &str| {
            keys.sign_with(
                actor,
                nonce,
                NormAct::Create {
                    ledger: ledger.clone(),
                    authority: None,
                    vocabulary: reference("implements"),
                    fields_json: json!({"source": source, "target": target}).to_string(),
                },
                Some(NormPremises {
                    family_basis: Some(basis.into()),
                    references: vec![source.into(), target.into()],
                    inventory_frontier: Vec::new(),
                }),
            )
        };
        let t = store
            .append_norm_event(
                &create("worker", "T", "task", json!({"title": "ship the parser"})),
                &keys,
            )
            .unwrap();
        let r = store
            .append_norm_event(
                &create("worker", "R", "requirement", json!({
                    "name": "parses", "proposition": "the parser accepts every fixture",
                    "domain": "src/", "subject": "src/parser.rs", "applicability": "every candidate", "owner": "owner"
                })),
                &keys,
            )
            .unwrap();
        refused(
            store.append_norm_event(
                &create("worker", "A-worker", "artifact", artifact_fields.clone()),
                &keys,
            ),
            "authenticated governance authority",
        );
        let a = store
            .append_norm_event(
                &create("owner", "A", "artifact", artifact_fields.clone()),
                &keys,
            )
            .unwrap();
        let basis = view(&store)
            .relation_family("implementation")
            .unwrap()
            .basis;
        refused(
            store.append_norm_event(&relate("worker", "R-implements", &r, &a, &basis), &keys),
            "undeclared kind",
        );
        store
            .append_norm_event(&relate("worker", "T-implements", &t, &a, &basis), &keys)
            .unwrap();
        let family = view(&store).relation_family("implementation").unwrap();
        assert_eq!(family.edges.len(), 1);
        assert_eq!(
            (
                family.edges[0].source.as_str(),
                family.edges[0].target.as_str()
            ),
            (t.as_str(), a.as_str())
        );
        // The artifact has no effectiveness rule: it is a record, not a duty.
        assert_eq!(
            view(&store).effective_revision(&view(&store).records[&a]),
            EffectiveRevision::Unspecified
        );
    }

    /// DR-0124 §14.6: a retention names the durable fact it rests on. A
    /// candidate resting on a durable record is refused until that record
    /// exists under the slot's instance with the candidate's invocation as
    /// its payload, and a later candidate for the same slot with a different
    /// basis has different immutable bindings.
    #[test]
    fn norm_publication_retention_rests_on_the_durable_record_it_names() {
        use whipplescript_store::norm_publication::{
            NormPublicationJournal, PublicationBasis, PublicationCandidate, PublicationSlot,
        };
        let keys = Keys::new();
        let journal = whipplescript_store::SqliteStore::open_in_memory().unwrap();
        let ledger = "1".repeat(64);
        let slot = PublicationSlot {
            ledger: ledger.clone(),
            instance: "build:cut-a0".into(),
            effect: "root//parser:parser#cfg".into(),
            run: "artifact".into(),
        };
        let invocation = json!({"cut": "cut-a0", "label": "root//parser:parser"});
        let event = keys.sign(
            "owner",
            "artifact",
            NormAct::Create {
                ledger: ledger.clone(),
                authority: None,
                vocabulary: Vocabulary::new(definition()).unwrap().reference().clone(),
                fields_json: json!({"title": "artifact"}).to_string(),
            },
        );
        let candidate = |basis: PublicationBasis| PublicationCandidate {
            slot: slot.clone(),
            invocation: invocation.clone(),
            observation: invocation.clone(),
            event: event.clone(),
            basis,
        };
        let refused = |result: Result<_, StoreError>, needle: &str| {
            let message = format!("{:?}", result.expect_err("refusal expected"));
            assert!(message.contains(needle), "{message}");
        };
        let named = PublicationBasis::Event {
            event_id: "0".repeat(64),
        };
        refused(
            journal.prepare_publication(&candidate(named.clone())),
            "durable record it names",
        );
        // A record with another payload under the instance does not serve.
        journal
            .append_event(whipplescript_store::NewEvent {
                instance_id: &slot.instance,
                event_type: "build.recorded",
                payload_json: &json!({"cut": "cut-b1"}).to_string(),
                source: "wrapper",
                causation_id: None,
                correlation_id: None,
                idempotency_key: None,
            })
            .unwrap();
        let other = journal
            .append_event(whipplescript_store::NewEvent {
                instance_id: &slot.instance,
                event_type: "build.recorded",
                payload_json: &json!({"cut": "cut-b1"}).to_string(),
                source: "wrapper",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("other"),
            })
            .unwrap()
            .event_id;
        refused(
            journal.prepare_publication(&candidate(PublicationBasis::Event { event_id: other })),
            "durable record it names",
        );
        let record = journal
            .append_event(whipplescript_store::NewEvent {
                instance_id: &slot.instance,
                event_type: "build.recorded",
                payload_json: &invocation.to_string(),
                source: "wrapper",
                causation_id: None,
                correlation_id: None,
                idempotency_key: None,
            })
            .unwrap()
            .event_id;
        let basis = PublicationBasis::Event { event_id: record };
        let retained = journal
            .prepare_publication(&candidate(basis.clone()))
            .unwrap();
        assert_eq!(retained.candidate.basis, basis);
        assert_eq!(
            journal
                .retained_publication(&slot)
                .unwrap()
                .unwrap()
                .candidate,
            retained.candidate
        );
        // The same slot under another basis is another binding.
        refused(
            journal.prepare_publication(&candidate(PublicationBasis::Run {})),
            "different immutable bindings",
        );
        // A run-based candidate on an instance with no settled run is refused as before.
        let run_slot = PublicationSlot {
            instance: "instance".into(),
            ..slot.clone()
        };
        refused(
            journal.prepare_publication(&PublicationCandidate {
                slot: run_slot,
                invocation: invocation.clone(),
                observation: invocation.clone(),
                event: event.clone(),
                basis: PublicationBasis::Run {},
            }),
            "durable terminal run",
        );
    }

    #[test]
    fn norm_commands_decode_raw_json_before_any_admission() {
        use whipplescript_store::norm_commands::*;
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let request = serde_json::to_string(&NormCommandRequest::new(NormCommand::append(
            keys.bootstrap(),
        )))
        .unwrap();
        // Every malformed request retains an otherwise valid, signed bootstrap.
        // A transport that normalizes JSON would erase the repeated members and
        // admit it, so an empty store makes this a behavioral refusal test.
        let duplicate_protocol =
            request.replacen("{", r#"{"protocol":"whipplescript.norm.commands/v1","#, 1);
        let duplicate_kind = request.replacen(
            r#""kind":"append""#,
            r#""kind":"append","kind":"append""#,
            1,
        );
        let duplicate_actor = request.replacen(
            r#""principal":"owner""#,
            r#""principal":"owner","principal":"owner""#,
            1,
        );
        let extra_trust = request.replacen("{", r#"{"bindings":[],"#, 1);
        for malformed in [
            duplicate_protocol,
            duplicate_kind,
            duplicate_actor,
            extra_trust,
            format!("{request} {{}}"),
        ] {
            assert_ne!(malformed, request);
            assert!(NormCommandHost::new(&mut store, &keys)
                .execute_json(&malformed)
                .is_err());
            assert!(store.export_events().unwrap().is_empty());
            assert!(store.norm_aliases().unwrap().is_empty());
        }
        let response = NormCommandHost::new(&mut store, &keys)
            .execute_json(&request)
            .unwrap();
        let response: NormCommandResponse = serde_json::from_str(&response).unwrap();
        assert!(matches!(
            response.result,
            NormCommandResult::Appended { .. }
        ));
        assert_eq!(store.export_events().unwrap().len(), 1);
    }

    #[test]
    fn norm_native_commands_roundtrip_without_request_supplied_authority() {
        use whipplescript_store::norm_commands::*;
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let run = |store: &mut WorkItemStore, command| {
            let encoded = serde_json::to_string(&NormCommandRequest::new(command)).unwrap();
            NormCommandHost::new(store, &keys)
                .execute_json(&encoded)
                .map(|response| serde_json::from_str::<NormCommandResponse>(&response).unwrap())
        };
        assert!(run(&mut store, NormCommand::Snapshot {}).is_err());
        let bootstrap = keys.bootstrap();
        let ledger = bootstrap.tracker_event().unwrap().event_id;
        let result = run(&mut store, NormCommand::append(bootstrap)).unwrap();
        assert!(
            matches!(result.result, NormCommandResult::Appended { event_id } if event_id == ledger)
        );
        let creation = keys.create(&ledger, "command-record");
        let record = creation.tracker_event().unwrap().event_id;
        run(&mut store, NormCommand::append(creation.clone())).unwrap();
        run(&mut store, NormCommand::append(creation)).unwrap();
        let snapshot = run(&mut store, NormCommand::Snapshot {}).unwrap();
        let NormCommandResult::Snapshot { snapshot } = snapshot.result else {
            panic!("snapshot")
        };
        assert_eq!(snapshot.records.len(), 1);
        assert_eq!(snapshot.records[0].alias, "N-1");
        assert_eq!(snapshot.records[0].record.id, record);
        assert_eq!(snapshot.frontier, vec![record.clone()]);
        assert!(NormCommandHost::new(&mut store, &keys)
            .execute(NormCommandRequest {
                protocol: "unsupported".into(),
                command: NormCommand::Snapshot {}
            })
            .is_err());
        for request in [
            json!({"protocol":NORM_COMMAND_PROTOCOL,"command":{"kind":"snapshot"},"bindings":[]}),
            json!({"protocol":NORM_COMMAND_PROTOCOL,"command":{"kind":"snapshot","creation_grants":[]}}),
            json!({"protocol":NORM_COMMAND_PROTOCOL,"command":{"kind":"pin_checkpoint","checkpoint":snapshot.checkpoint}}),
            json!({"protocol":NORM_COMMAND_PROTOCOL,"command":{"kind":"import","events":[],"checkpoint":snapshot.checkpoint}}),
        ] {
            assert!(serde_json::from_value::<NormCommandRequest>(request).is_err());
        }
        let before = store.export_events().unwrap();
        assert!(run(
            &mut store,
            NormCommand::append(keys.change(
                "worker",
                "unauthorized",
                &ledger,
                &record,
                "accepted"
            ))
        )
        .is_err());
        assert_eq!(store.export_events().unwrap(), before);
        let exported = run(&mut store, NormCommand::Export {}).unwrap();
        let NormCommandResult::Exported {
            checkpoint,
            frontier,
            events,
        } = exported.result
        else {
            panic!("export")
        };
        assert_eq!(frontier, snapshot.frontier);
        assert_eq!(events, before);
        let mut restored = WorkItemStore::open_in_memory().unwrap();
        assert!(run(
            &mut restored,
            NormCommand::Import {
                events: events.clone()
            }
        )
        .is_err());
        // Destination trust is established outside the request protocol.
        restored.pin_norm_checkpoint(&checkpoint).unwrap();
        let imported = run(
            &mut restored,
            NormCommand::Import {
                events: events.clone(),
            },
        )
        .unwrap();
        assert!(matches!(
            imported.result,
            NormCommandResult::Imported { inserted: 2 }
        ));
        let repeated = run(&mut restored, NormCommand::Import { events }).unwrap();
        assert!(matches!(
            repeated.result,
            NormCommandResult::Imported { inserted: 0 }
        ));
        let restored = run(&mut restored, NormCommand::Snapshot {}).unwrap();
        assert_eq!(
            serde_json::to_value(restored.result).unwrap(),
            json!({"kind":"snapshot","snapshot":snapshot})
        );
    }

    struct ReadBoundary {
        inner: std::cell::RefCell<WorkItemStore>,
        keys: Keys,
        next: std::cell::RefCell<Option<SignedNormEvent>>,
        missing_alias: bool,
        missing_history: bool,
    }
    impl whipplescript_store::norm_commands::NormCommandStore for ReadBoundary {
        fn norm_state(
            &self,
            verifier: &dyn NormVerifier,
        ) -> whipplescript_store::StoreResult<NormView> {
            self.inner.borrow().norm_view(verifier)
        }
        fn local_norm_aliases(&self) -> whipplescript_store::StoreResult<BTreeMap<String, String>> {
            if self.missing_alias {
                Ok(BTreeMap::new())
            } else {
                self.inner.borrow().norm_aliases()
            }
        }
        fn tracker_history(
            &self,
        ) -> whipplescript_store::StoreResult<Vec<whipplescript_store::items::TrackerEvent>>
        {
            if let Some(event) = self.next.borrow_mut().take() {
                self.inner
                    .borrow_mut()
                    .append_norm_event(&event, &self.keys)?;
            }
            let mut history = self.inner.borrow().export_events()?;
            if self.missing_history {
                history.pop();
            }
            Ok(history)
        }
        fn append_norm(
            &mut self,
            event: &SignedNormEvent,
            verifier: &dyn NormVerifier,
        ) -> whipplescript_store::StoreResult<String> {
            self.inner.borrow_mut().append_norm_event(event, verifier)
        }
        fn import_norm(
            &mut self,
            events: &[whipplescript_store::items::TrackerEvent],
            verifier: &dyn NormVerifier,
        ) -> whipplescript_store::StoreResult<usize> {
            self.inner.borrow_mut().import_norm_events(events, verifier)
        }
    }
    #[test]
    fn norm_commands_refuse_incomplete_reads_and_export_the_captured_frontier() {
        use whipplescript_store::norm_commands::*;
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let first = store
            .append_norm_event(&keys.create(&ledger, "first"), &keys)
            .unwrap();
        let initial = store.export_events().unwrap();
        let next = keys.create(&ledger, "later");
        let later = next.tracker_event().unwrap().event_id;
        let mut boundary = ReadBoundary {
            inner: std::cell::RefCell::new(store),
            keys: Keys::new(),
            next: std::cell::RefCell::new(None),
            missing_alias: true,
            missing_history: false,
        };
        let error = NormCommandHost::new(&mut boundary, &keys)
            .execute(NormCommandRequest::new(NormCommand::Snapshot {}))
            .unwrap_err();
        assert!(
            matches!(error, StoreError::Conflict(message) if message.contains("missing its durable local alias"))
        );
        boundary.missing_alias = false;
        boundary.missing_history = true;
        let error = NormCommandHost::new(&mut boundary, &keys)
            .execute(NormCommandRequest::new(NormCommand::Export {}))
            .unwrap_err();
        assert!(
            matches!(error, StoreError::Conflict(message) if message.contains("history disappeared"))
        );
        boundary.missing_history = false;
        *boundary.next.borrow_mut() = Some(next);
        let result = NormCommandHost::new(&mut boundary, &keys)
            .execute(NormCommandRequest::new(NormCommand::Export {}))
            .unwrap();
        let NormCommandResult::Exported {
            frontier, events, ..
        } = result.result
        else {
            panic!("export")
        };
        assert_eq!(frontier, vec![first]);
        assert_eq!(events, initial);
        assert!(!events.iter().any(|event| event.event_id == later));
        assert_eq!(
            boundary
                .inner
                .borrow()
                .norm_view(&keys)
                .unwrap()
                .records
                .len(),
            2
        );
    }
    fn transition_current(
        keys: &Keys,
        store: &WorkItemStore,
        record: &str,
        status: &str,
        who: &str,
        nonce: &str,
    ) -> SignedNormEvent {
        let view = store
            .norm_view(keys)
            .expect("verified transition fixture view");
        let current = &view.records[record];
        keys.sign(
            who,
            nonce,
            NormAct::Transition {
                ledger: view.ledger.clone(),
                authority: Some(view.authority_head.clone()),
                vocabulary: current.vocabulary.clone(),
                record: record.into(),
                previous: current.head.clone(),
                status: status.into(),
            },
        )
    }

    #[test]
    fn norm_effective_draft_retirement_cannot_withdraw_an_accepted_revision() {
        let keys = Keys::new();
        let mut c = charter();
        c.vocabularies[0].editing = Some(AdmissionPredicate::Public {});
        c.vocabularies[0].effectiveness = Some(vec![
            EffectivenessRule {
                status: "accepted".into(),
                effect: RevisionEffect::Activate,
            },
            EffectivenessRule {
                status: "withdrawn".into(),
                effect: RevisionEffect::Retire,
            },
        ]);
        c.vocabularies[0].definition.status.transitions.push(
            whipplescript_core::vocabulary::TransitionRule {
                from: "accepted".into(),
                to: "withdrawn".into(),
                admission: AdmissionPredicate::Authority {
                    scope: "accept".into(),
                },
            },
        );
        let vocabulary = Vocabulary::new(c.vocabularies[0].definition.clone())
            .unwrap()
            .reference()
            .clone();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "effective-root",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c,
                    },
                ),
                &keys,
            )
            .unwrap();
        let record = store
            .append_norm_event(
                &keys.sign(
                    "worker",
                    "effective-record",
                    NormAct::Create {
                        ledger,
                        authority: None,
                        vocabulary,
                        fields_json: r#"{"title":"accepted original"}"#.into(),
                    },
                ),
                &keys,
            )
            .unwrap();
        let activation =
            transition_current(&keys, &store, &record, "accepted", "owner", "activate-a");
        let activated = store.append_norm_event(&activation, &keys).unwrap();
        let edit = keys.edit(
            &store.norm_view(&keys).unwrap(),
            &record,
            r#"{"title":"draft replacement"}"#,
            "worker",
            "draft-b",
        );
        store.append_norm_event(&edit, &keys).unwrap();
        // Equal fields do not make a later draft the earlier accepted revision.
        let view = store.norm_view(&keys).unwrap();
        let back = keys.edit(
            &view,
            &record,
            r#"{"title":"accepted original"}"#,
            "worker",
            "draft-back-to-original",
        );
        store.append_norm_event(&back, &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        assert_eq!(
            view.records[&record].fields,
            view.effective_records[&record].fields
        );
        assert_ne!(
            view.records[&record].content_head,
            view.effective_records[&record].content_head
        );
        let withdrawn = transition_current(
            &keys,
            &store,
            &record,
            "withdrawn",
            "worker",
            "withdraw-draft",
        );
        store.append_norm_event(&withdrawn, &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        assert_eq!(view.records[&record].status, "withdrawn");
        assert_eq!(view.effective_records[&record].head, activated);
        assert_eq!(
            view.effective_records[&record].fields["title"],
            "accepted original"
        );
        let edit = keys.edit(
            &view,
            &record,
            r#"{"title":"replacement for acceptance"}"#,
            "worker",
            "draft-c",
        );
        let revision = store.append_norm_event(&edit, &keys).unwrap();
        let unauthorized =
            transition_current(&keys, &store, &record, "accepted", "worker", "self-accept");
        assert!(store.append_norm_event(&unauthorized, &keys).is_err());
        assert_eq!(
            store.norm_view(&keys).unwrap().effective_records[&record].content_head,
            record
        );
        let accepted =
            transition_current(&keys, &store, &record, "accepted", "owner", "activate-c");
        let accepted_id = store.append_norm_event(&accepted, &keys).unwrap();
        assert_eq!(
            store.norm_view(&keys).unwrap().effective_records[&record].content_head,
            revision
        );
        let unauthorized =
            transition_current(&keys, &store, &record, "withdrawn", "worker", "self-retire");
        assert!(store.append_norm_event(&unauthorized, &keys).is_err());
        let retired = transition_current(&keys, &store, &record, "withdrawn", "owner", "retire-c");
        store.append_norm_event(&retired, &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        assert_eq!(
            view.effective_revision(&view.records[&record]),
            EffectiveRevision::Inactive
        );
        assert!(view.effective_records.is_empty());
        let history = store.export_events().unwrap();
        assert!(history.iter().any(|e| e.event_id == activated));
        assert!(history.iter().any(|e| e.event_id == accepted_id));
        let replay = replay_norm(&history, &view.checkpoint(), &keys).unwrap();
        assert!(replay.effective_records.is_empty());
    }

    #[test]
    fn norm_effective_policy_is_explicit_and_validated_in_the_pinned_charter() {
        let keys = Keys::new();
        for declared in [false, true] {
            let mut c = charter();
            if declared {
                c.vocabularies[0].effectiveness = Some(vec![]);
            } else {
                assert!(!serde_json::to_string(&c).unwrap().contains("effectiveness"));
            }
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let ledger = store
                .append_norm_event(
                    &keys.sign(
                        "owner",
                        "policy-root",
                        NormAct::Bootstrap {
                            creator: "worker".into(),
                            charter: c,
                        },
                    ),
                    &keys,
                )
                .unwrap();
            let record = store
                .append_norm_event(&keys.create(&ledger, "record"), &keys)
                .unwrap();
            let accepted = keys.change("owner", "accept", &ledger, &record, "accepted");
            store.append_norm_event(&accepted, &keys).unwrap();
            let view = store.norm_view(&keys).unwrap();
            assert_eq!(
                view.effective_revision(&view.records[&record]),
                if declared {
                    EffectiveRevision::Inactive
                } else {
                    EffectiveRevision::Unspecified
                }
            );
        }
        for unknown in [false, true] {
            let mut c = charter();
            let rule = EffectivenessRule {
                status: if unknown { "missing" } else { "accepted" }.into(),
                effect: RevisionEffect::Activate,
            };
            c.vocabularies[0].effectiveness = Some(if unknown {
                vec![rule]
            } else {
                vec![rule.clone(), rule]
            });
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let event = keys.sign(
                "owner",
                "bad-policy",
                NormAct::Bootstrap {
                    creator: "worker".into(),
                    charter: c,
                },
            );
            assert!(store.append_norm_event(&event, &keys).is_err());
            assert!(store.norm_checkpoint().unwrap().is_none());
        }
    }

    #[test]
    fn norm_effective_initial_activation_uses_the_declared_creation_authority() {
        let keys = Keys::new();
        let mut c = charter();
        c.vocabularies[0].definition.status.initial = "accepted".into();
        c.vocabularies[0].creation = AdmissionPredicate::Authority {
            scope: "accept".into(),
        };
        c.vocabularies[0].effectiveness = Some(vec![EffectivenessRule {
            status: "accepted".into(),
            effect: RevisionEffect::Activate,
        }]);
        let vocabulary = Vocabulary::new(c.vocabularies[0].definition.clone())
            .unwrap()
            .reference()
            .clone();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "initial-root",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c,
                    },
                ),
                &keys,
            )
            .unwrap();
        let create = NormAct::Create {
            ledger,
            authority: None,
            vocabulary,
            fields_json: r#"{"title":"active at creation"}"#.into(),
        };
        assert!(store
            .append_norm_event(&keys.sign("worker", "worker-create", create.clone()), &keys)
            .is_err());
        let record = store
            .append_norm_event(&keys.sign("owner", "owner-create", create), &keys)
            .unwrap();
        let view = store.norm_view(&keys).unwrap();
        assert_eq!(view.effective_records[&record], view.records[&record]);
        assert!(matches!(
            view.effective_revision(&view.records[&record]),
            EffectiveRevision::Active { .. }
        ));
    }
    fn retirement_fixture(
        include_retirement_rule: bool,
        permit_sealed_retirement: bool,
    ) -> (Keys, WorkItemStore, String) {
        let keys = Keys::new();
        let mut c = charter();
        c.vocabularies[0].editing = Some(AdmissionPredicate::Public {});
        c.vocabularies[0].effectiveness = Some(vec![
            EffectivenessRule {
                status: "accepted".into(),
                effect: RevisionEffect::Activate,
            },
            EffectivenessRule {
                status: "withdrawn".into(),
                effect: RevisionEffect::Retire,
            },
        ]);
        // A valid lifecycle transition without a retiring effect isolates the
        // role check from transition permission in the refusal control.
        c.vocabularies[0].definition.status.transitions.push(
            whipplescript_core::vocabulary::TransitionRule {
                from: "accepted".into(),
                to: "accepted".into(),
                admission: AdmissionPredicate::Authority {
                    scope: "accept".into(),
                },
            },
        );
        c.vocabularies[0]
            .definition
            .status
            .values
            .push("sealed".into());
        c.vocabularies[0].definition.status.transitions.push(
            whipplescript_core::vocabulary::TransitionRule {
                from: "accepted".into(),
                to: "sealed".into(),
                admission: AdmissionPredicate::Authority {
                    scope: "accept".into(),
                },
            },
        );
        if include_retirement_rule {
            c.vocabularies[0].definition.status.transitions.push(
                whipplescript_core::vocabulary::TransitionRule {
                    from: "accepted".into(),
                    to: "withdrawn".into(),
                    admission: AdmissionPredicate::Authority {
                        scope: "accept".into(),
                    },
                },
            );
        }
        if permit_sealed_retirement {
            c.vocabularies[0].definition.status.transitions.push(
                whipplescript_core::vocabulary::TransitionRule {
                    from: "sealed".into(),
                    to: "withdrawn".into(),
                    admission: AdmissionPredicate::Public {},
                },
            );
        }
        let vocabulary = Vocabulary::new(c.vocabularies[0].definition.clone())
            .expect("vocabulary")
            .reference()
            .clone();
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let ledger = store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "root",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter: c,
                    },
                ),
                &keys,
            )
            .expect("bootstrap");
        let record = store
            .append_norm_event(
                &keys.sign(
                    "worker",
                    "record",
                    NormAct::Create {
                        ledger,
                        authority: None,
                        vocabulary,
                        fields_json: r#"{"title":"accepted"}"#.into(),
                    },
                ),
                &keys,
            )
            .expect("create");
        let act = transition_current(&keys, &store, &record, "accepted", "owner", "approve");
        store.append_norm_event(&act, &keys).expect("accept");
        (keys, store, record)
    }

    fn retirement_action(view: &NormView, record: &str) -> NormAct {
        let current = &view.records[record];
        let effective = &view.effective_records[record];
        NormAct::Retire {
            ledger: view.ledger.clone(),
            authority: Some(view.authority_head.clone()),
            vocabulary: current.vocabulary.clone(),
            record: record.into(),
            previous: current.head.clone(),
            revision: effective.content_head.clone(),
            activation: effective.head.clone(),
            status: "withdrawn".into(),
        }
    }

    #[test]
    fn norm_retirement_targets_acceptance_and_preserves_the_newer_draft() {
        let (keys, mut store, record) = retirement_fixture(true, false);
        let accepted = store.norm_view(&keys).unwrap().effective_records[&record].clone();
        let edit = keys.edit(
            &store.norm_view(&keys).unwrap(),
            &record,
            r#"{"title":"new draft"}"#,
            "worker",
            "draft",
        );
        store.append_norm_event(&edit, &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        let draft = view.records[&record].clone();
        let action = retirement_action(&view, &record);
        let history = store.export_events().unwrap();
        // Each changed premise is signed by a real authorized key: signatures
        // alone do not establish freshness, the target, or the policy role.
        for (field, value) in [
            ("revision", draft.content_head.clone()),
            ("activation", record.clone()),
            ("previous", accepted.head.clone()),
            ("ledger", record.clone()),
            ("status", "accepted".into()),
        ] {
            let mut altered = serde_json::to_value(&action).unwrap();
            altered[field] = json!(value);
            let signed = keys.sign(
                "owner",
                &format!("bad-{field}"),
                serde_json::from_value(altered).unwrap(),
            );
            assert!(store.append_norm_event(&signed, &keys).is_err(), "{field}");
            assert_eq!(store.export_events().unwrap(), history);
        }
        // Draft withdrawal is public; acceptance retirement is owner-only.
        let worker = keys.sign("worker", "self-retirement", action.clone());
        assert!(store.append_norm_event(&worker, &keys).is_err());
        let act = keys.sign("owner", "retire", action.clone());
        let event = act.tracker_event().unwrap();
        assert!(event.parents.contains(&accepted.head));
        assert!(event.parents.contains(&accepted.content_head));
        assert!(event.parents.contains(&draft.head));
        let retired = store.append_norm_event(&act, &keys).unwrap();
        assert_eq!(store.append_norm_event(&act, &keys).unwrap(), retired);
        let after = store.norm_view(&keys).unwrap();
        assert_eq!(
            after.effective_revision(&after.records[&record]),
            EffectiveRevision::Inactive
        );
        assert_eq!(after.records[&record].fields, draft.fields);
        assert_eq!(after.records[&record].content_head, draft.content_head);
        assert_eq!(after.records[&record].status, draft.status);
        assert_eq!(after.records[&record].head, retired);
        assert!(after.event_order().contains(&accepted.head));
        // A new invocation cannot retire an already inactive acceptance.
        let mut inactive = action;
        if let NormAct::Retire { previous, .. } = &mut inactive {
            *previous = retired;
        }
        assert!(store
            .append_norm_event(&keys.sign("owner", "retire-again", inactive), &keys)
            .is_err());
        let mut restored = WorkItemStore::open_in_memory().unwrap();
        restored.pin_norm_checkpoint(&after.checkpoint()).unwrap();
        let mut history = store.export_events().unwrap();
        history.reverse();
        restored.import_norm_events(&history, &keys).unwrap();
        assert_eq!(restored.norm_view(&keys).unwrap().records, after.records);
        assert_eq!(
            restored.norm_view(&keys).unwrap().effective_records,
            after.effective_records
        );
        // The retained draft can subsequently become effective under fresh authority.
        let accept =
            transition_current(&keys, &store, &record, "accepted", "owner", "approve-draft");
        store.append_norm_event(&accept, &keys).unwrap();
        assert_eq!(
            store.norm_view(&keys).unwrap().effective_records[&record].content_head,
            draft.content_head
        );
    }

    #[test]
    fn norm_retirement_serializes_with_reapproval_edits_and_root_succession() {
        let (keys, mut store, record) = retirement_fixture(true, false);
        let original = store.norm_view(&keys).unwrap();
        let action = retirement_action(&original, &record);
        let edit = keys.edit(
            &original,
            &record,
            r#"{"title":"new draft"}"#,
            "worker",
            "draft",
        );
        store.append_norm_event(&edit, &keys).unwrap();
        assert!(store
            .append_norm_event(&keys.sign("owner", "before-edit", action.clone()), &keys)
            .is_err());
        let accept = transition_current(&keys, &store, &record, "accepted", "owner", "approve-new");
        store.append_norm_event(&accept, &keys).unwrap();
        let mut stale = action;
        if let NormAct::Retire { previous, .. } = &mut stale {
            *previous = store.norm_view(&keys).unwrap().records[&record]
                .head
                .clone();
        }
        assert!(store
            .append_norm_event(&keys.sign("owner", "old-acceptance", stale), &keys)
            .is_err());
        let before_rotation = store.norm_view(&keys).unwrap();
        let fresh = retirement_action(&before_rotation, &record);
        // Naming the newer activation forces the edit/reapproval to precede
        // this act, isolating a stale current-head check from branch conflicts.
        let mut stale_head = fresh.clone();
        if let NormAct::Retire { previous, .. } = &mut stale_head {
            *previous = original.records[&record].head.clone();
        }
        assert!(store
            .append_norm_event(
                &keys.sign("owner", "causally-stale-head", stale_head),
                &keys
            )
            .is_err());
        let rotation = keys.rotate(&before_rotation, "owner", "owner2", "rotate");
        store.append_norm_event(&rotation, &keys).unwrap();
        assert!(store
            .append_norm_event(&keys.sign("owner2", "old-epoch", fresh.clone()), &keys)
            .is_err());
        let after_rotation = store.norm_view(&keys).unwrap();
        // Force retirement to be causally after rotation; otherwise a stale
        // epoch can be refused by old-owner binding before the epoch guard runs.
        let noop = keys.edit(
            &after_rotation,
            &record,
            &after_rotation.records[&record].fields.to_string(),
            "worker",
            "post-rotation-noop",
        );
        store.append_norm_event(&noop, &keys).unwrap();
        let after_rotation = store.norm_view(&keys).unwrap();
        let mut stale_epoch = fresh;
        if let NormAct::Retire { previous, .. } = &mut stale_epoch {
            *previous = after_rotation.records[&record].head.clone();
        }
        assert!(store
            .append_norm_event(
                &keys.sign("owner2", "causally-stale-epoch", stale_epoch),
                &keys
            )
            .is_err());
        let updated = retirement_action(&after_rotation, &record);
        assert!(store
            .append_norm_event(&keys.sign("owner", "old-key", updated.clone()), &keys)
            .is_err());
        store
            .append_norm_event(&keys.sign("owner2", "retire-new", updated), &keys)
            .unwrap();
        let final_view = store.norm_view(&keys).unwrap();
        assert!(final_view.effective_records.is_empty());
        assert_eq!(final_view.records[&record].status, "withdrawn");
        assert_eq!(
            final_view.records[&record].content_head,
            before_rotation.records[&record].content_head
        );
    }
    #[test]
    fn norm_retirement_effect_mapping_does_not_grant_a_transition() {
        let (keys, mut store, record) = retirement_fixture(false, false);
        let view = store.norm_view(&keys).unwrap();
        let action = retirement_action(&view, &record);
        let before = store.export_events().unwrap();
        assert!(store
            .append_norm_event(&keys.sign("owner", "no-rule", action), &keys)
            .is_err());
        assert_eq!(store.export_events().unwrap(), before);
        assert_eq!(
            store.norm_view(&keys).unwrap().effective_records,
            view.effective_records
        );
    }
    #[test]
    fn norm_retirement_cannot_reuse_a_superseded_lifecycle_permission() {
        let (keys, mut store, record) = retirement_fixture(true, false);
        let original = store.norm_view(&keys).unwrap().effective_records[&record].clone();
        let seal = transition_current(&keys, &store, &record, "sealed", "owner", "seal");
        let sealed = store.append_norm_event(&seal, &keys).unwrap();
        for draft in [false, true] {
            if draft {
                let view = store.norm_view(&keys).unwrap();
                let edit = keys.edit(
                    &view,
                    &record,
                    r#"{"title":"after sealing"}"#,
                    "worker",
                    "draft-after-seal",
                );
                store.append_norm_event(&edit, &keys).unwrap();
            }
            let view = store.norm_view(&keys).unwrap();
            let EffectiveRevision::Active {
                record: accepted,
                lifecycle,
            } = view.effective_revision(&view.records[&record])
            else {
                panic!("still active");
            };
            assert_eq!(*accepted, original);
            assert_eq!(lifecycle.status, "sealed");
            assert_eq!(lifecycle.head, sealed);
            let action = retirement_action(&view, &record);
            let before = store.export_events().unwrap();
            assert!(store
                .append_norm_event(
                    &keys.sign("owner", &format!("retire-sealed-{draft}"), action),
                    &keys
                )
                .is_err());
            assert_eq!(store.export_events().unwrap(), before);
        }
        let view = store.norm_view(&keys).unwrap();
        let mut restored = WorkItemStore::open_in_memory().unwrap();
        restored.pin_norm_checkpoint(&view.checkpoint()).unwrap();
        let mut history = store.export_events().unwrap();
        history.reverse();
        restored.import_norm_events(&history, &keys).unwrap();
        let replay = restored.norm_view(&keys).unwrap();
        assert_eq!(
            replay.effective_revision(&replay.records[&record]),
            view.effective_revision(&view.records[&record])
        );
    }
    #[test]
    fn norm_retirement_uses_the_latest_explicit_lifecycle_grant() {
        let (keys, mut store, record) = retirement_fixture(true, true);
        let seal = transition_current(&keys, &store, &record, "sealed", "owner", "seal");
        store.append_norm_event(&seal, &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        let edit = keys.edit(
            &view,
            &record,
            r#"{"title":"draft after public release"}"#,
            "worker",
            "draft",
        );
        store.append_norm_event(&edit, &keys).unwrap();
        let view = store.norm_view(&keys).unwrap();
        // Public release is explicit in this charter's sealed state; the
        // activation state's owner-only rule is no longer the applicable rule.
        let action = retirement_action(&view, &record);
        store
            .append_norm_event(&keys.sign("worker", "public-release", action), &keys)
            .unwrap();
        assert!(store.norm_view(&keys).unwrap().effective_records.is_empty());
        assert_eq!(
            store.norm_view(&keys).unwrap().records[&record].status,
            "proposed"
        );
    }
    fn inventory_store(charter: NormCharter) -> (Keys, WorkItemStore) {
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().expect("inventory store");
        store
            .append_norm_event(
                &keys.sign(
                    "owner",
                    "inventory-root",
                    NormAct::Bootstrap {
                        creator: "worker".into(),
                        charter,
                    },
                ),
                &keys,
            )
            .expect("inventory charter");
        (keys, store)
    }
    fn inventory_create(
        keys: &Keys,
        store: &mut WorkItemStore,
        vocabulary_name: &str,
        nonce: &str,
        fields: serde_json::Value,
    ) -> String {
        let view = store.norm_view(keys).expect("inventory view");
        let entry = view
            .charter
            .vocabularies
            .iter()
            .find(|entry| entry.definition.name == vocabulary_name)
            .expect("fixture vocabulary");
        let vocabulary = Vocabulary::new(entry.definition.clone())
            .expect("vocabulary")
            .reference()
            .clone();
        store
            .append_norm_event(
                &keys.sign(
                    "worker",
                    nonce,
                    NormAct::Create {
                        ledger: view.ledger.clone(),
                        authority: Some(view.authority_head.clone()),
                        vocabulary,
                        fields_json: fields.to_string(),
                    },
                ),
                keys,
            )
            .expect("inventory creation")
    }
    fn requirement_fields() -> serde_json::Value {
        json!({"name":"authorize","proposition":"deny unknown","domain":"src/","subject":"src/auth.py"})
    }
    #[test]
    fn norm_inventory_keeps_all_effective_requirements_and_ignores_draft_aliases() {
        use whipplescript_store::norm_commands::*;
        let (keys, mut store) = inventory_store(NormCharter::bundled().unwrap());
        let first = inventory_create(
            &keys,
            &mut store,
            "obligation",
            "first",
            requirement_fields(),
        );
        let second = inventory_create(
            &keys,
            &mut store,
            "obligation",
            "same-name",
            requirement_fields(),
        );
        let issue = inventory_create(
            &keys,
            &mut store,
            "issue",
            "issue",
            json!({"title":"work item"}),
        );
        let inactive = store
            .norm_view(&keys)
            .unwrap()
            .requirement_inventory()
            .unwrap();
        assert!(inactive.classification_complete);
        assert_eq!(
            inactive.inactive,
            std::collections::BTreeSet::from([first.clone(), second.clone()])
        );
        assert_eq!(
            inactive.non_requirements,
            std::collections::BTreeSet::from([issue])
        );
        for (nonce, id) in [("accept-first", &first), ("accept-second", &second)] {
            let act = transition_current(&keys, &store, id, "accepted", "owner", nonce);
            store.append_norm_event(&act, &keys).unwrap();
        }
        let before = store
            .norm_view(&keys)
            .unwrap()
            .requirement_inventory()
            .unwrap();
        assert_eq!(
            before.requirements.len(),
            2,
            "duplicate display names do not collapse identities"
        );
        let original = before.requirements[&first].clone();
        let mut changed = requirement_fields();
        changed["proposition"] = json!("allow unknown");
        let edit = keys.edit(
            &store.norm_view(&keys).unwrap(),
            &first,
            &changed.to_string(),
            "worker",
            "draft",
        );
        store.append_norm_event(&edit, &keys).unwrap();
        let current = store.norm_view(&keys).unwrap();
        let inventory = current.requirement_inventory().unwrap();
        assert_eq!(inventory.requirements[&first], original);
        assert_eq!(
            inventory.requirements[&first]
                .declaration
                .as_ref()
                .unwrap()
                .proposition,
            "deny unknown"
        );
        assert_eq!(
            inventory.requirements[&first]
                .requirement
                .as_ref()
                .unwrap()
                .name,
            first
        );
        assert_eq!(
            inventory.requirements[&first]
                .requirement
                .as_ref()
                .unwrap()
                .version,
            first
        );
        assert_eq!(inventory.checkpoint, current.checkpoint());
        assert_eq!(inventory.frontier, current.frontier);
        let events = store.export_events().unwrap();
        let aliases = store.norm_aliases().unwrap();
        let standalone = NormCommandHost::new(&mut store, &keys)
            .execute(NormCommandRequest::new(NormCommand::Inventory {}))
            .unwrap();
        let snapshot = NormCommandHost::new(&mut store, &keys)
            .execute(NormCommandRequest::new(NormCommand::Snapshot {}))
            .unwrap();
        let NormCommandResult::Snapshot { snapshot } = snapshot.result else {
            panic!("snapshot")
        };
        let NormCommandResult::Inventory {
            inventory: standalone,
        } = standalone.result
        else {
            panic!("inventory")
        };
        assert_eq!(standalone, inventory);
        assert_eq!(snapshot.inventory, inventory);
        assert_eq!(
            store.export_events().unwrap(),
            events,
            "queries do not append effects"
        );
        assert_eq!(store.norm_aliases().unwrap(), aliases);
        let mut restored = WorkItemStore::open_in_memory().unwrap();
        restored.pin_norm_checkpoint(&current.checkpoint()).unwrap();
        let mut reversed = events;
        reversed.reverse();
        restored.import_norm_events(&reversed, &keys).unwrap();
        assert_eq!(
            restored
                .norm_view(&keys)
                .unwrap()
                .requirement_inventory()
                .unwrap(),
            inventory
        );
        let rotation = keys.rotate(
            &store.norm_view(&keys).unwrap(),
            "owner",
            "owner2",
            "inventory-rotation",
        );
        store.append_norm_event(&rotation, &keys).unwrap();
        let rotated_view = store.norm_view(&keys).unwrap();
        let rotated = rotated_view.requirement_inventory().unwrap();
        assert_eq!(
            rotated.requirements, inventory.requirements,
            "root rotation does not rewrite property meaning"
        );
        assert_eq!(rotated.checkpoint, rotated_view.checkpoint());
        assert_eq!(rotated.frontier, rotated_view.frontier);
        assert_ne!(rotated.checkpoint, inventory.checkpoint);
        assert_ne!(rotated.frontier, inventory.frontier);
        let accept = transition_current(&keys, &store, &first, "accepted", "owner2", "replace");
        store.append_norm_event(&accept, &keys).unwrap();
        let updated = store
            .norm_view(&keys)
            .unwrap()
            .requirement_inventory()
            .unwrap();
        assert_ne!(
            updated.requirements[&first].requirement,
            original.requirement
        );
        assert_ne!(
            updated.requirements[&first]
                .requirement
                .as_ref()
                .unwrap()
                .digest,
            original.requirement.as_ref().unwrap().digest
        );
        let mut retire = retirement_action(&store.norm_view(&keys).unwrap(), &first);
        if let NormAct::Retire { status, .. } = &mut retire {
            *status = "retired".into();
        }
        store
            .append_norm_event(&keys.sign("owner2", "retire-inventory", retire), &keys)
            .unwrap();
        let retired = store
            .norm_view(&keys)
            .unwrap()
            .requirement_inventory()
            .unwrap();
        assert!(retired.classification_complete);
        assert!(!retired.requirements.contains_key(&first));
        assert!(retired.inactive.contains(&first));
        assert!(retired.requirements.contains_key(&second));
    }

    #[test]
    fn norm_inventory_unknown_charter_roles_and_effects_are_gaps_even_without_records() {
        use whipplescript_store::norm_inventory::*;
        for omitted_role in [true, false] {
            let mut charter = NormCharter::bundled().unwrap();
            let entry = charter
                .vocabularies
                .iter_mut()
                .find(|entry| entry.definition.name == "obligation")
                .unwrap();
            if omitted_role {
                entry.inventory_role = None;
            } else {
                entry.effectiveness = None;
            }
            let legacy = serde_json::to_value(&entry).unwrap();
            if omitted_role {
                assert!(legacy.get("inventory_role").is_none());
            }
            let (keys, mut store) = inventory_store(charter);
            let empty = store
                .norm_view(&keys)
                .unwrap()
                .requirement_inventory()
                .unwrap();
            assert!(!empty.classification_complete);
            assert!(empty.requirements.is_empty());
            assert_eq!(empty.gaps.len(), 1);
            assert_eq!(empty.gaps[0].record, None);
            assert_eq!(
                empty.gaps[0].reason,
                if omitted_role {
                    InventoryGapKind::UnspecifiedRole
                } else {
                    InventoryGapKind::UnspecifiedEffectiveness
                }
            );
            let record = inventory_create(
                &keys,
                &mut store,
                "obligation",
                "unknown",
                requirement_fields(),
            );
            let accept = transition_current(
                &keys,
                &store,
                &record,
                "accepted",
                "owner",
                "accept-unknown",
            );
            store.append_norm_event(&accept, &keys).unwrap();
            let inventory = store
                .norm_view(&keys)
                .unwrap()
                .requirement_inventory()
                .unwrap();
            assert!(!inventory.classification_complete);
            assert!(inventory.unclassified.contains(&record));
            assert!(inventory.inactive.is_empty());
            assert!(inventory.non_requirements.is_empty());
        }
        let (keys, store) = inventory_store(NormCharter::bundled().unwrap());
        let empty = store
            .norm_view(&keys)
            .unwrap()
            .requirement_inventory()
            .unwrap();
        assert!(empty.classification_complete);
        assert!(empty.requirements.is_empty());
        assert!(empty.gaps.is_empty());
    }

    #[test]
    fn norm_inventory_validates_binding_schema_and_retains_malformed_active_meaning() {
        use whipplescript_store::norm_inventory::*;
        for mode in 0..5 {
            let keys = Keys::new();
            let mut charter = NormCharter::bundled().unwrap();
            let entry = charter
                .vocabularies
                .iter_mut()
                .find(|entry| entry.definition.name == "obligation")
                .unwrap();
            let Some(InventoryRole::Requirement { fields }) = &mut entry.inventory_role else {
                panic!("role")
            };
            match mode {
                0 => fields.proposition = fields.name.clone(),
                1 => fields.domain = "absent".into(),
                2 => {
                    entry.definition.fields[0].value_type =
                        whipplescript_core::vocabulary::ValueType::Boolean {}
                }
                3 => entry.definition.fields[0].required = false,
                _ => fields.support_contract = Some("absent".into()),
            }
            let mut store = WorkItemStore::open_in_memory().unwrap();
            assert!(
                store
                    .append_norm_event(
                        &keys.sign(
                            "owner",
                            "bad-schema",
                            NormAct::Bootstrap {
                                creator: "worker".into(),
                                charter
                            }
                        ),
                        &keys
                    )
                    .is_err(),
                "mode {mode}"
            );
            assert_eq!(store.norm_checkpoint().unwrap(), None);
        }
        for field in ["proposition", "support_contract"] {
            let (keys, mut store) = inventory_store(NormCharter::bundled().unwrap());
            let mut fields = requirement_fields();
            fields[field] = json!("  ");
            let id = inventory_create(&keys, &mut store, "obligation", "blank", fields);
            let accept =
                transition_current(&keys, &store, &id, "accepted", "owner", "accept-blank");
            store.append_norm_event(&accept, &keys).unwrap();
            let inventory = store
                .norm_view(&keys)
                .unwrap()
                .requirement_inventory()
                .unwrap();
            assert!(!inventory.classification_complete);
            assert!(
                inventory.requirements.contains_key(&id),
                "bad meaning is not absence of a duty"
            );
            assert_eq!(inventory.requirements[&id].declaration, None);
            assert_eq!(inventory.requirements[&id].requirement, None);
            assert_eq!(inventory.gaps[0].record.as_deref(), Some(id.as_str()));
            assert_eq!(
                inventory.gaps[0].reason,
                InventoryGapKind::InvalidText {
                    field: field.into()
                }
            );
        }
    }

    #[test]
    fn norm_inventory_roles_and_field_bindings_are_data_for_another_vocabulary() {
        use whipplescript_store::norm_inventory::*;
        let mut charter = NormCharter::bundled().unwrap();
        let mut alternative = charter
            .vocabularies
            .iter()
            .find(|entry| entry.definition.name == "obligation")
            .unwrap()
            .clone();
        alternative.definition.name = "promise".into();
        for (field, name) in alternative
            .definition
            .fields
            .iter_mut()
            .zip(["label", "claim", "universe", "anchor", "method"])
        {
            field.name = name.into();
        }
        alternative.definition.fields[2].value_type =
            whipplescript_core::vocabulary::ValueType::Enum {
                values: vec!["src/".into()],
            };
        alternative.inventory_role = Some(InventoryRole::Requirement {
            fields: RequirementFields {
                name: "label".into(),
                proposition: "claim".into(),
                domain: "universe".into(),
                subject: "anchor".into(),
                support_contract: Some("method".into()),
            },
        });
        charter.vocabularies.push(alternative);
        let (keys, mut store) = inventory_store(charter);
        let id = inventory_create(
            &keys,
            &mut store,
            "promise",
            "promise",
            json!({"label":"different noun","claim":"deny unknown","universe":"src/","anchor":"src/auth.py","method":"Q0"}),
        );
        let accept = transition_current(&keys, &store, &id, "accepted", "owner", "accept-promise");
        store.append_norm_event(&accept, &keys).unwrap();
        let inventory = store
            .norm_view(&keys)
            .unwrap()
            .requirement_inventory()
            .unwrap();
        assert!(inventory.classification_complete);
        let requirement = &inventory.requirements[&id];
        assert_eq!(requirement.source.vocabulary.name, "promise");
        let declaration = requirement.declaration.as_ref().unwrap();
        assert_eq!(declaration.name, "different noun");
        assert_eq!(declaration.proposition, "deny unknown");
        assert_eq!(declaration.domain, "src/");
        assert_eq!(declaration.subject, "src/auth.py");
        assert_eq!(declaration.support_contract.as_deref(), Some("Q0"));
    }
    fn resource_artifact(
        cut_id: &str,
        files: &[(&str, &str)],
    ) -> whipplescript_store::norm_artifact::CapturedArtifact {
        use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
        use whipplescript_store::content::ContentStore;
        use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};
        let content = ContentStore::open(":memory:").expect("resource content");
        let mut branches = BranchStore::open(":memory:").expect("resource branches");
        branches.ensure_mainline("t0").expect("mainline");
        let manifest = files
            .iter()
            .map(|(path, body)| {
                (
                    path.to_string(),
                    content.put(body.as_bytes()).expect("body"),
                )
            })
            .collect();
        let root =
            whipplescript_store::manifest_tree::build(&content, &manifest).expect("manifest");
        branches
            .record_cut(CutRecord {
                cut_id,
                change_id: cut_id,
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: &root,
                parent_cut_id: None,
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t1",
            })
            .expect("stored cut");
        capture_cut(&branches, &content, cut_id, ArtifactLimits::default())
            .expect("captured resource files")
    }
    fn resource_requirement(
        keys: &Keys,
        store: &mut WorkItemStore,
        nonce: &str,
        domain: &str,
        subject: &str,
    ) -> String {
        let id = inventory_create(
            keys,
            store,
            "obligation",
            nonce,
            json!({"name":nonce,"proposition":"deny unknown","domain":domain,"subject":subject}),
        );
        let act = transition_current(
            keys,
            store,
            &id,
            "accepted",
            "owner",
            &format!("accept-{nonce}"),
        );
        store
            .append_norm_event(&act, keys)
            .expect("effective resource requirement");
        id
    }
    #[test]
    fn norm_resources_bind_explicit_domains_and_preserve_deleted_and_retired_requirements() {
        use whipplescript_store::norm_resources::*;
        let mut charter = NormCharter::bundled().unwrap();
        charter.resource_domains = Some(BTreeMap::from([
            (
                "authorization".into(),
                ResourceDomain {
                    include: vec![
                        ResourceSelector::Subtree { root: "src".into() },
                        ResourceSelector::File {
                            path: "runner.json".into(),
                        },
                    ],
                },
            ),
            (
                "checks".into(),
                ResourceDomain {
                    include: vec![ResourceSelector::Subtree {
                        root: "checks".into(),
                    }],
                },
            ),
        ]));
        let (keys, mut store) = inventory_store(charter);
        let id = resource_requirement(&keys, &mut store, "auth", "authorization", "src/auth.py");
        let before_view = store.norm_view(&keys).unwrap();
        let before = resource_artifact(
            "before",
            &[
                ("src/auth.py", "ok"),
                ("src/parser.py", "old"),
                ("src2/no.py", "outside"),
                ("runner.json", "{}"),
                ("checks/test.py", "test"),
            ],
        );
        let after = resource_artifact(
            "after",
            &[
                ("src/parser.py", "changed"),
                ("src/new.py", "new"),
                ("src2/no.py", "outside"),
                ("runner.json", "{}"),
                ("checks/test.py", "test"),
            ],
        );
        let pair = compare_resources(
            &before_view,
            &before,
            &before_view,
            &after,
            ResourceLimits::default(),
        )
        .unwrap();
        assert!(pair.before.binding_complete);
        assert!(!pair.after.binding_complete);
        assert!(pair.before.bindings[&id].subject_present);
        assert!(!pair.after.bindings[&id].subject_present);
        assert_eq!(
            pair.after.gaps,
            vec![ResourceGap {
                requirement: Some(id.clone()),
                reason: ResourceGapKind::MissingSubject {}
            }]
        );
        assert_eq!(
            pair.before.bindings[&id].resources,
            ["src/auth.py", "src/parser.py", "runner.json"]
                .map(str::to_owned)
                .into()
        );
        assert!(pair.after.bindings[&id].resources.contains("src/new.py"));
        assert!(pair.before.unmanaged.contains("src2/no.py"));
        assert_eq!(pair.before.uncovered, ["checks/test.py".to_owned()].into());
        assert_eq!(
            pair.changes,
            BTreeMap::from([
                ("src/auth.py".into(), ResourceChange::Deleted),
                ("src/parser.py".into(), ResourceChange::Modified),
                ("src/new.py".into(), ResourceChange::Created)
            ])
        );
        assert_eq!(pair.before.artifact, *before.basis());
        assert_eq!(pair.after.artifact, *after.basis());
        assert_eq!(pair.requirements, [id.clone()].into());
        let mut retire = retirement_action(&before_view, &id);
        if let NormAct::Retire { status, .. } = &mut retire {
            *status = "retired".into();
        }
        store
            .append_norm_event(&keys.sign("owner", "resource-retirement", retire), &keys)
            .unwrap();
        let after_view = store.norm_view(&keys).unwrap();
        let retired = compare_resources(
            &before_view,
            &before,
            &after_view,
            &after,
            ResourceLimits::default(),
        )
        .unwrap();
        assert!(retired.after.inventory.requirements.is_empty());
        assert_eq!(retired.requirements, [id].into());
        assert!(retired.after.binding_complete);
        assert!(retired.after.uncovered.contains("src/parser.py"));
        assert!(compare_resources(
            &after_view,
            &after,
            &before_view,
            &before,
            ResourceLimits::default()
        )
        .is_err());
    }
    #[test]
    fn norm_resources_missing_and_empty_policies_are_distinct_even_without_records() {
        use whipplescript_store::norm_resources::*;
        let artifact = resource_artifact("empty-policy", &[("src/a.py", "a")]);
        let mut charter = NormCharter::bundled().unwrap();
        charter.resource_domains = None;
        let encoded = serde_json::to_value(&charter).unwrap();
        assert!(encoded.get("resource_domains").is_none());
        let (keys, store) = inventory_store(charter.clone());
        let view = store.norm_view(&keys).unwrap();
        let unknown = view
            .resource_inventory(&artifact, ResourceLimits::default())
            .unwrap();
        assert!(!unknown.binding_complete);
        assert_eq!(
            unknown.gaps,
            vec![ResourceGap {
                requirement: None,
                reason: ResourceGapKind::MissingPolicy {}
            }]
        );
        assert!(unknown.unmanaged.is_empty());
        assert!(unknown.uncovered.is_empty());
        assert_eq!(unknown.unresolved, ["src/a.py".to_owned()].into());
        charter.resource_domains = Some(BTreeMap::new());
        let (other_keys, other_store) = inventory_store(charter);
        let other = other_store.norm_view(&other_keys).unwrap();
        let empty = other
            .resource_inventory(&artifact, ResourceLimits::default())
            .unwrap();
        assert!(empty.binding_complete);
        assert_eq!(empty.unmanaged, ["src/a.py".to_owned()].into());
        assert!(compare_resources(
            &view,
            &artifact,
            &other,
            &artifact,
            ResourceLimits::default()
        )
        .is_err());
        for max_work in [0, 1] {
            assert!(other
                .resource_inventory(&artifact, ResourceLimits { max_work })
                .is_err());
        }
        let mut incomplete = NormCharter::bundled().unwrap();
        incomplete.vocabularies[0].inventory_role = None;
        let (keys, store) = inventory_store(incomplete);
        let inventory = store
            .norm_view(&keys)
            .unwrap()
            .resource_inventory(&artifact, ResourceLimits::default())
            .unwrap();
        assert!(!inventory.binding_complete);
        assert!(!inventory.inventory.classification_complete);
        assert!(inventory.uncovered.is_empty());
        assert_eq!(inventory.unresolved, ["src/a.py".to_owned()].into());
    }
    #[test]
    fn norm_resources_never_drop_uninterpretable_active_requirements() {
        use whipplescript_store::norm_resources::*;
        let mut charter = NormCharter::bundled().unwrap();
        charter.resource_domains.as_mut().unwrap().insert(
            "src".into(),
            ResourceDomain {
                include: vec![ResourceSelector::Subtree { root: "src".into() }],
            },
        );
        let (keys, mut store) = inventory_store(charter);
        let unknown = resource_requirement(&keys, &mut store, "unknown", "uninstalled", "src/a.py");
        let invalid = resource_requirement(&keys, &mut store, "invalid", "workspace", "../a.py");
        let outside = resource_requirement(&keys, &mut store, "outside", "src", "docs/a.py");
        let absent = resource_requirement(&keys, &mut store, "absent", "workspace", "future/a.py");
        let malformed = resource_requirement(&keys, &mut store, "malformed", "workspace", " ");
        let artifact = resource_artifact("candidate", &[("src/a.py", "a")]);
        let result = store
            .norm_view(&keys)
            .unwrap()
            .resource_inventory(&artifact, ResourceLimits::default())
            .unwrap();
        assert_eq!(result.inventory.requirements.len(), 5);
        assert!(!result.binding_complete);
        assert_eq!(
            result.bindings.keys().cloned().collect::<Vec<_>>(),
            vec![absent.clone()]
        );
        for (id, reason) in [
            (
                unknown,
                ResourceGapKind::UnknownDomain {
                    domain: "uninstalled".into(),
                },
            ),
            (
                invalid,
                ResourceGapKind::InvalidSubject {
                    subject: "../a.py".into(),
                },
            ),
            (outside, ResourceGapKind::SubjectOutsideDomain {}),
            (absent, ResourceGapKind::MissingSubject {}),
            (malformed, ResourceGapKind::UninterpretedRequirement {}),
        ] {
            assert!(result.gaps.contains(&ResourceGap {
                requirement: Some(id),
                reason
            }));
        }
    }
    #[test]
    fn norm_resources_c0_refuses_ambiguous_or_noncanonical_definitions() {
        use whipplescript_store::norm_resources::*;
        let mut charter = NormCharter::bundled().unwrap();
        for (name, selectors) in [
            (" ", vec![]),
            (" padded", vec![]),
            (
                "scope",
                vec![ResourceSelector::File {
                    path: "../a".into(),
                }],
            ),
            (
                "scope",
                vec![ResourceSelector::Subtree {
                    root: "src/".into(),
                }],
            ),
            (
                "scope",
                vec![
                    ResourceSelector::WorkspaceFiles {},
                    ResourceSelector::WorkspaceFiles {},
                ],
            ),
        ] {
            charter.resource_domains = Some(BTreeMap::from([(
                name.into(),
                ResourceDomain { include: selectors },
            )]));
            let keys = Keys::new();
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let event = keys.sign(
                "owner",
                "invalid-resource-policy",
                NormAct::Bootstrap {
                    creator: "worker".into(),
                    charter: charter.clone(),
                },
            );
            assert!(store.append_norm_event(&event, &keys).is_err());
        }
        let duplicate = r#"{"vocabularies":[],"owner_scopes":[],"resource_domains":{"same":{"include":[]},"same":{"include":[]}}}"#;
        assert!(serde_json::from_str::<NormCharter>(duplicate).is_err());
        let unknown = r#"{"vocabularies":[],"owner_scopes":[],"resource_domains":{"same":{"include":[{"kind":"guessed_glob","pattern":"**"}]}}}"#;
        assert!(serde_json::from_str::<NormCharter>(unknown).is_err());
    }
    #[test]
    fn norm_resources_selector_codec_refuses_extra_fields() {
        use whipplescript_store::norm_resources::ResourceSelector;
        let wire = json!({"kind":"workspace_files"});
        let selector: ResourceSelector = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(selector).unwrap(), wire);
        for value in [
            json!({"kind":"workspace_files","exclude":["private"]}),
            json!({"kind":"file","path":"a","ignored":true}),
            json!({"kind":"subtree","root":"src","ignored":true}),
        ] {
            assert!(
                serde_json::from_value::<ResourceSelector>(value.clone()).is_err(),
                "{value}"
            );
        }
    }

    #[test]
    fn norm_resources_non_requirement_codec_refuses_hidden_fields() {
        use whipplescript_store::norm_inventory::InventoryRole;
        let wire = json!({"kind":"non_requirement"});
        let role: InventoryRole = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(role).unwrap(), wire);
        assert!(serde_json::from_value::<InventoryRole>(
            json!({"kind":"non_requirement","fields":{"proposition":"must not disappear"}})
        )
        .is_err());
    }
    #[test]
    fn norm_query_projects_history_without_rolling_back_authority() {
        use whipplescript_store::norm_commands::*;
        use whipplescript_store::norm_history::*;
        let (keys, mut store) = inventory_store(NormCharter::bundled().unwrap());
        let id = resource_requirement(&keys, &mut store, "auth", "workspace", "src/auth.py");
        let old = store.norm_view(&keys).unwrap();
        let old_frontier: Vec<_> = old.frontier.iter().cloned().collect();
        let rotation = keys.rotate(&old, "owner", "owner2", "query-rotation");
        store.append_norm_event(&rotation, &keys).unwrap();
        let rotated = store.norm_view(&keys).unwrap();
        let current = &rotated.records[&id];
        let edit=keys.sign("worker","query-edit",NormAct::Edit {
            ledger:rotated.ledger.clone(),authority:Some(rotated.authority_head.clone()),vocabulary:current.vocabulary.clone(),record:id.clone(),previous:current.head.clone(),fields_json:json!({"name":"changed","proposition":"deny unknown","domain":"workspace","subject":"src/auth.py"}).to_string(),
        });
        store.append_norm_event(&edit, &keys).unwrap();
        let accept = transition_current(&keys, &store, &id, "accepted", "owner2", "query-reaccept");
        store.append_norm_event(&accept, &keys).unwrap();
        let current = store.norm_view(&keys).unwrap();
        let events = store.export_events().unwrap();
        let mut reversed = events.clone();
        reversed.reverse();
        reversed.push(events[0].clone());
        let history =
            CapturedNormHistory::capture(&current, &reversed, &keys, NormHistoryLimits::default())
                .unwrap();
        let projected = history.project(Some(&old_frontier), &keys).unwrap();
        assert_eq!(projected.records, old.records);
        assert_eq!(projected.owner, old.owner);
        assert_eq!(projected.frontier, old.frontier);
        assert_eq!(history.anchor().checkpoint, current.checkpoint());
        assert_eq!(
            history.project(None, &keys).unwrap().records,
            current.records
        );
        assert_eq!(
            history
                .project(Some(std::slice::from_ref(&old.ledger)), &keys)
                .unwrap()
                .records
                .len(),
            0
        );
        let response = NormCommandHost::new(&mut store, &keys)
            .execute(NormCommandRequest::new(NormCommand::SnapshotAt {
                frontier: old_frontier.clone(),
            }))
            .unwrap();
        let NormCommandResult::HistoricalSnapshot { captured, snapshot } = response.result else {
            panic!("historical snapshot")
        };
        assert_eq!(captured.checkpoint, current.checkpoint());
        assert_eq!(captured.frontier, current.frontier);
        assert_eq!(snapshot.checkpoint, old.checkpoint());
        assert_eq!(snapshot.records[0].record.fields["name"], "auth");
        assert_eq!(snapshot.records[0].alias, "N-1");
        let response = NormCommandHost::new(&mut store, &keys)
            .execute(NormCommandRequest::new(NormCommand::InventoryAt {
                frontier: old_frontier.clone(),
            }))
            .unwrap();
        let NormCommandResult::HistoricalInventory { inventory, .. } = response.result else {
            panic!("historical inventory")
        };
        assert_eq!(inventory, old.requirement_inventory().unwrap());
        assert_eq!(store.norm_checkpoint().unwrap(), Some(current.checkpoint()));
        assert_eq!(store.export_events().unwrap(), events);
        let denied = transition_current(&keys, &store, &id, "accepted", "owner", "query-old-owner");
        assert!(store.append_norm_event(&denied, &keys).is_err());
        let prefix: Vec<_> = events
            .iter()
            .filter(|event| old.event_order().contains(&event.event_id))
            .cloned()
            .collect();
        let mut restored = WorkItemStore::open_in_memory().unwrap();
        restored.pin_norm_checkpoint(&current.checkpoint()).unwrap();
        assert!(restored.import_norm_events(&prefix, &keys).is_err());
        let before =
            resource_artifact("before", &[("src/auth.py", "ok"), ("src/parser.py", "old")]);
        let after = resource_artifact("after", &[("src/parser.py", "new")]);
        let artifacts = |cut: &str| match cut {
            "before" => Ok(before.clone()),
            "after" => Ok(after.clone()),
            _ => Err(StoreError::Conflict("fixture missing cut".into())),
        };
        let request = NormCommandRequest::new(NormCommand::CompareResources {
            before: NormResourcePoint {
                cut: "before".into(),
                frontier: Some(old_frontier.clone()),
            },
            after: NormResourcePoint {
                cut: "after".into(),
                frontier: None,
            },
        });
        let response = NormCommandHost::new(&mut store, &keys)
            .with_artifacts(&artifacts)
            .execute(request)
            .unwrap();
        let NormCommandResult::ResourceComparison {
            captured,
            comparison,
        } = response.result
        else {
            panic!("comparison")
        };
        assert_eq!(captured.checkpoint, current.checkpoint());
        assert_eq!(comparison.before.inventory.checkpoint, old.checkpoint());
        assert_eq!(comparison.after.inventory.checkpoint, current.checkpoint());
        assert_eq!(
            comparison.before.inventory.requirements[&id]
                .declaration
                .as_ref()
                .unwrap()
                .name,
            "auth"
        );
        assert_eq!(
            comparison.after.inventory.requirements[&id]
                .declaration
                .as_ref()
                .unwrap()
                .name,
            "changed"
        );
        assert!(comparison.before.binding_complete);
        assert!(!comparison.after.binding_complete);
        assert_eq!(comparison.requirements, [id].into());
        assert_eq!(comparison.changes.len(), 2);
        let request = NormCommandRequest::new(NormCommand::Resources {
            point: NormResourcePoint {
                cut: "before".into(),
                frontier: Some(old_frontier),
            },
        });
        let response = NormCommandHost::new(&mut store, &keys)
            .with_artifacts(&artifacts)
            .execute(request.clone())
            .unwrap();
        let NormCommandResult::Resources { resources, .. } = response.result else {
            panic!("resources")
        };
        assert!(resources.binding_complete);
        let error = NormCommandHost::new(&mut store, &keys)
            .execute(request)
            .unwrap_err();
        assert!(
            matches!(error,StoreError::Conflict(message) if message=="norm resource queries require a host-owned artifact source")
        );
        let wrong = |_: &str| Ok(before.clone());
        assert!(NormCommandHost::new(&mut store, &keys)
            .with_artifacts(&wrong)
            .execute(NormCommandRequest::new(NormCommand::Resources {
                point: NormResourcePoint {
                    cut: "after".into(),
                    frontier: None
                }
            }))
            .is_err());
        assert_eq!(store.export_events().unwrap(), events);
    }

    #[test]
    fn norm_query_refuses_incomplete_corrupt_or_mixed_current_history() {
        use whipplescript_store::norm_history::*;
        let (keys, mut store) = inventory_store(NormCharter::bundled().unwrap());
        let id = resource_requirement(&keys, &mut store, "auth", "workspace", "src/auth.py");
        let current = store.norm_view(&keys).unwrap();
        let events = store.export_events().unwrap();
        for max_events in [0, 1] {
            assert!(CapturedNormHistory::capture(
                &current,
                &events,
                &keys,
                NormHistoryLimits { max_events }
            )
            .is_err());
        }
        let history =
            CapturedNormHistory::capture(&current, &events, &keys, NormHistoryLimits::default())
                .unwrap();
        let head = current.records[&id].head.clone();
        for frontier in [
            vec![],
            vec![head.clone(), head.clone()],
            vec![current.ledger.clone(), head.clone()],
            vec!["f".repeat(64)],
        ] {
            assert!(
                history.project(Some(&frontier), &keys).is_err(),
                "{frontier:?}"
            );
        }
        let mut missing = events.clone();
        missing.pop();
        assert!(CapturedNormHistory::capture(
            &current,
            &missing,
            &keys,
            NormHistoryLimits::default()
        )
        .is_err());
        let mut corrupt = events.clone();
        corrupt.last_mut().unwrap().payload_json.push(' ');
        assert!(CapturedNormHistory::capture(
            &current,
            &corrupt,
            &keys,
            NormHistoryLimits::default()
        )
        .is_err());
        let mut conflicting = events.clone();
        let mut duplicate = events[0].clone();
        duplicate.actor = Some("other".into());
        conflicting.push(duplicate);
        assert!(CapturedNormHistory::capture(
            &current,
            &conflicting,
            &keys,
            NormHistoryLimits::default()
        )
        .is_err());
        let _new = resource_requirement(&keys, &mut store, "later", "workspace", "other.py");
        assert!(CapturedNormHistory::capture(
            &current,
            &store.export_events().unwrap(),
            &keys,
            NormHistoryLimits::default()
        )
        .is_err());
        let newer = store.norm_view(&keys).unwrap();
        assert!(
            CapturedNormHistory::capture(&newer, &events, &keys, NormHistoryLimits::default())
                .is_err()
        );
    }

    #[test]
    fn norm_query_commands_refuse_racing_reads_and_request_owned_trust_or_artifacts() {
        use whipplescript_store::norm_commands::*;
        let keys = Keys::new();
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let ledger = store.append_norm_event(&keys.bootstrap(), &keys).unwrap();
        let first = store
            .append_norm_event(&keys.create(&ledger, "first"), &keys)
            .unwrap();
        let next = keys.create(&ledger, "query-race");
        let mut boundary = ReadBoundary {
            inner: std::cell::RefCell::new(store),
            keys: Keys::new(),
            next: std::cell::RefCell::new(Some(next)),
            missing_alias: false,
            missing_history: false,
        };
        let request = NormCommandRequest::new(NormCommand::SnapshotAt {
            frontier: vec![first.clone()],
        });
        assert!(NormCommandHost::new(&mut boundary, &keys)
            .execute(request.clone())
            .is_err());
        assert!(NormCommandHost::new(&mut boundary, &keys)
            .execute(request)
            .is_ok());
        assert!(serde_json::from_value::<NormCommand>(
            json!({"kind":"resources","point":{"cut":"cut"}})
        )
        .is_ok());
        for command in [
            json!({"kind":"snapshot_at","frontier":[first],"checkpoint":{"ledger":ledger,"authority_head":ledger}}),
            json!({"kind":"resources","point":{"cut":"cut","files":{"x":"body"}}}),
            json!({"kind":"resources","point":{"cut":"cut"},"limits":{"max_events":999999999}}),
            json!({"kind":"resources","point":{"cut":"cut"},"store":"other.sqlite"}),
            json!({"kind":"resources","point":{"cut":"cut","frontier":[]},"artifact":{"manifest":"fake"}}),
        ] {
            // Refusal must occur at decoding; a later missing artifact source
            // must not mask silently accepted request-owned fields.
            assert!(serde_json::from_value::<NormCommand>(command.clone()).is_err());
            assert!(NormCommandHost::new(&mut boundary, &keys)
                .execute_json(
                    &json!({"protocol":NORM_COMMAND_PROTOCOL,"command":command}).to_string()
                )
                .is_err());
        }
        let duplicate = format!(
            r#"{{"protocol":"{NORM_COMMAND_PROTOCOL}","command":{{"kind":"resources","point":{{"cut":"a","cut":"b"}}}}}}"#
        );
        assert!(NormCommandHost::new(&mut boundary, &keys)
            .execute_json(&duplicate)
            .is_err());
    }
}
