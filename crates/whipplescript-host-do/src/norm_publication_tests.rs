//! Storage-contract fixtures; synthetic envelopes do not claim signing authority
//! or verified execution. The kernel publication bridge supplies those premises.
use whipplescript_store::norm::{NormAct, NormActor, NormStatement, SignedNormEvent};
use whipplescript_store::norm_publication::*;
use whipplescript_store::*;

fn candidate(instance: &str) -> PublicationCandidate {
    PublicationCandidate {
        slot: PublicationSlot {
            ledger: "ledger".into(),
            instance: instance.into(),
            effect: "observe".into(),
            run: "run".into(),
        },
        invocation: serde_json::json!({"requirement":"captured"}),
        observation: serde_json::json!({"outcome":"fail","counterexample":"retained"}),
        event: SignedNormEvent {
            statement: NormStatement {
                premises: None,
                protocol: "whipplescript.norm.event/v1".into(),
                actor: NormActor {
                    principal: "publisher".into(),
                    algorithm: "fixture".into(),
                    key_id: "key".into(),
                },
                nonce: "one".into(),
                created_at: "first".into(),
                action: NormAct::Create {
                    ledger: "ledger".into(),
                    authority: None,
                    vocabulary: whipplescript_core::vocabulary::VocabularyRef {
                        name: "observation".into(),
                        version: "1".into(),
                        digest: "fixture".into(),
                    },
                    fields_json: "{}".into(),
                },
            },
            signature: "first-signature".into(),
            successor_signature: None,
        },
    }
}

fn journal_contract<S: RuntimeStore + NormPublicationJournal>(mut store: S) {
    let (instance, _) = crate::rule_commit_recovery_tests::seed_retry_rebuild(&mut store);
    let first = candidate(&instance);
    let before = store.list_events(&instance).unwrap();
    assert!(store
        .acknowledge_publication(&first.slot, "missing")
        .is_err());
    let mut absent = first.clone();
    absent.slot.run = "not-terminal".into();
    assert!(store.prepare_publication(&absent).is_err());
    let mut wrong_ledger = first.clone();
    wrong_ledger.slot.ledger = "other".into();
    assert!(store.prepare_publication(&wrong_ledger).is_err());
    assert_eq!(store.list_events(&instance).unwrap(), before);
    assert_eq!(store.retained_publication(&first.slot).unwrap(), None);
    let retained = store.prepare_publication(&first).unwrap();
    assert_eq!(
        store.retained_publication(&first.slot).unwrap(),
        Some(retained.clone())
    );
    assert_eq!(retained.candidate, first);
    let prepared = store.list_events(&instance).unwrap();
    let mut competitor = first.clone();
    competitor.event.signature = "second-signature".into();
    competitor.event.statement.created_at = "later".into();
    competitor.event.statement.nonce = "two".into();
    competitor.event.statement.actor.key_id = "successor-key".into();
    if let NormAct::Create { authority, .. } = &mut competitor.event.statement.action {
        *authority = Some("successor-authority".into());
    }
    assert_eq!(store.prepare_publication(&competitor).unwrap(), retained);
    for field in 0..6 {
        let mut changed = competitor.clone();
        match field {
            0 => changed.invocation = serde_json::json!({"requirement":"changed"}),
            1 => changed.observation = serde_json::json!({"outcome":"pass"}),
            2 => changed.event.statement.actor.principal = "substitute".into(),
            3 => changed.event.statement.protocol = "other".into(),
            4 => {
                if let NormAct::Create { fields_json, .. } = &mut changed.event.statement.action {
                    *fields_json = "{\"changed\":true}".into();
                }
            }
            _ => {
                if let NormAct::Create { vocabulary, .. } = &mut changed.event.statement.action {
                    vocabulary.version = "different-version".into();
                }
            }
        }
        assert!(store.prepare_publication(&changed).is_err());
    }
    let winner_id = first.event.tracker_event().unwrap().event_id;
    let loser_id = competitor.event.tracker_event().unwrap().event_id;
    assert_ne!(winner_id, loser_id);
    assert!(store
        .acknowledge_publication(&first.slot, &loser_id)
        .is_err());
    assert_eq!(store.list_events(&instance).unwrap(), prepared);
    let acknowledgment = store
        .acknowledge_publication(&first.slot, &winner_id)
        .unwrap();
    let acknowledged = store.list_events(&instance).unwrap();
    assert_eq!(
        store
            .acknowledge_publication(&first.slot, &winner_id)
            .unwrap(),
        acknowledgment
    );
    store.rebuild_projections(&instance).unwrap();
    assert_eq!(store.prepare_publication(&competitor).unwrap(), retained);
    assert_eq!(
        store
            .acknowledge_publication(&first.slot, &winner_id)
            .unwrap(),
        acknowledgment
    );
    assert_eq!(store.list_events(&instance).unwrap(), acknowledged);
}

#[test]
fn norm_publication_journal_native() {
    journal_contract(SqliteStore::open_in_memory().unwrap());
}
#[test]
fn norm_publication_journal_hosted() {
    journal_contract(crate::do_store::test_support::store());
}

#[test]
fn norm_publication_journal_concurrent_native_writers_recover_one_envelope() {
    let dir = std::env::temp_dir().join(format!(
        "norm-publication-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("runtime.sqlite");
    let mut seed = SqliteStore::open(&path).unwrap();
    let (instance, _) = crate::rule_commit_recovery_tests::seed_retry_rebuild(&mut seed);
    let first = candidate(&instance);
    drop(seed);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
    let joins: Vec<_> = (0..4)
        .map(|index| {
            let barrier = barrier.clone();
            let path = path.clone();
            let mut candidate = first.clone();
            candidate.event.signature = format!("signature-{index}");
            candidate.event.statement.nonce = format!("nonce-{index}");
            std::thread::spawn(move || {
                let store = SqliteStore::open(path).unwrap();
                barrier.wait();
                store.prepare_publication(&candidate).unwrap()
            })
        })
        .collect();
    let winners: Vec<_> = joins.into_iter().map(|join| join.join().unwrap()).collect();
    assert!(winners.iter().all(|winner| winner == &winners[0]));
    // Simulate process loss after preparation and a supplied receipt: each
    // reopen must recover the complete envelope and original acknowledgment.
    let winner = &winners[0];
    let event_id = winner.candidate.event.tracker_event().unwrap().event_id;
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(
        store.retained_publication(&first.slot).unwrap(),
        Some(winner.clone())
    );
    assert_eq!(store.prepare_publication(&first).unwrap(), *winner);
    let acknowledgment = store
        .acknowledge_publication(&first.slot, &event_id)
        .unwrap();
    drop(store);
    let store = SqliteStore::open(&path).unwrap();
    assert_eq!(
        store
            .acknowledge_publication(&first.slot, &event_id)
            .unwrap(),
        acknowledgment
    );
    assert_eq!(
        store
            .list_events(&instance)
            .unwrap()
            .iter()
            .filter(|event| event.event_type.starts_with("norm.publication."))
            .count(),
        2
    );
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn norm_publication_journal_hosted_rolls_back_every_statement_failure() {
    use crate::do_store::{test_support::store, tests::FaultySql, DoSqliteStore};
    for acknowledge in [false, true] {
        let mut exercised = 0;
        for fail_at in 1..100 {
            let mut original = store();
            let (instance, _) =
                crate::rule_commit_recovery_tests::seed_retry_rebuild(&mut original);
            let candidate = candidate(&instance);
            if acknowledge {
                original.prepare_publication(&candidate).unwrap();
            }
            let before = original.list_events(&instance).unwrap();
            let head = original.chain_head(&instance).unwrap();
            let faulty = DoSqliteStore::new(FaultySql::new(original.sql, fail_at));
            let event_id = candidate.event.tracker_event().unwrap().event_id;
            let result = if acknowledge {
                faulty
                    .acknowledge_publication(&candidate.slot, &event_id)
                    .map(|_| ())
            } else {
                faulty.prepare_publication(&candidate).map(|_| ())
            };
            faulty.sql.disarm();
            if result.is_ok() {
                break;
            }
            exercised += 1;
            assert_eq!(
                faulty.list_events(&instance).unwrap(),
                before,
                "statement {fail_at}"
            );
            assert_eq!(
                faulty.chain_head(&instance).unwrap(),
                head,
                "statement {fail_at}"
            );
            faulty.prepare_publication(&candidate).unwrap();
            faulty
                .acknowledge_publication(&candidate.slot, &event_id)
                .unwrap();
        }
        assert!(
            exercised > 3 && exercised < 99,
            "all statements must be reached: {exercised}"
        );
    }
}

fn attempts_and_restore<S: RuntimeStore + NormPublicationJournal>(mut store: S) {
    let (instance, retry) = crate::rule_commit_recovery_tests::seed_retry_rebuild(&mut store);
    let failed = candidate(&instance);
    let first = store.prepare_publication(&failed).unwrap();
    let first_id = failed.event.tracker_event().unwrap().event_id;
    let first_ack = store
        .acknowledge_publication(&failed.slot, &first_id)
        .unwrap();
    let mut run = crate::run_reattach_tests::request(&instance);
    run.run_id = "successful-retry";
    run.lease_id = "retry-lease";
    store
        .start_run_for_admission(run, Some(&retry.event_id))
        .unwrap();
    let mut success = failed.clone();
    success.slot.run = run.run_id.into();
    success.observation = serde_json::json!({"outcome":"pass"});
    success.event.statement.nonce = "retry-observation".into();
    let before = store.list_events(&instance).unwrap();
    assert!(
        store.prepare_publication(&success).is_err(),
        "an active run is not publishable"
    );
    assert_eq!(store.list_events(&instance).unwrap(), before);
    store
        .complete_effect(EffectCompletion {
            instance_id: &instance,
            effect_id: "observe",
            run_id: run.run_id,
            provider: "exec",
            worker_id: "worker",
            status: "completed",
            exit_code: Some(0),
            summary: Some("passed"),
            metadata_json: "{}",
            idempotency_key: Some("second-terminal"),
        })
        .unwrap();
    let second = store.prepare_publication(&success).unwrap();
    let second_id = success.event.tracker_event().unwrap().event_id;
    let second_ack = store
        .acknowledge_publication(&success.slot, &second_id)
        .unwrap();
    assert_ne!(first.preparation, second.preparation);
    assert_ne!(first_id, second_id);
    // A context restore changes runtime projections, never a publication that
    // may already have reached the independently committed ledger.
    store
        .append_event(NewEvent {
            instance_id: &instance,
            event_type: "context.restored",
            payload_json: "{\"restored_to_sequence\":0}",
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("publication-restore"),
        })
        .unwrap();
    store.rebuild_projections(&instance).unwrap();
    let restored = store.list_events(&instance).unwrap();
    assert_eq!(
        store.retained_publication(&failed.slot).unwrap(),
        Some(first.clone())
    );
    assert_eq!(
        store.retained_publication(&success.slot).unwrap(),
        Some(second.clone())
    );
    assert_eq!(store.prepare_publication(&failed).unwrap(), first);
    assert_eq!(store.prepare_publication(&success).unwrap(), second);
    assert_eq!(
        store
            .acknowledge_publication(&failed.slot, &first_id)
            .unwrap(),
        first_ack
    );
    assert_eq!(
        store
            .acknowledge_publication(&success.slot, &second_id)
            .unwrap(),
        second_ack
    );
    let mut changed = failed;
    changed.observation = success.observation;
    assert!(store.prepare_publication(&changed).is_err());
    assert_eq!(store.list_events(&instance).unwrap(), restored);
}

#[test]
fn norm_publication_attempts_and_restore_native() {
    attempts_and_restore(SqliteStore::open_in_memory().unwrap());
}
#[test]
fn norm_publication_attempts_and_restore_hosted() {
    attempts_and_restore(crate::do_store::test_support::store());
}

fn inconsistent_acknowledgment<S: NormPublicationJournal>(mut store: S) {
    let (instance, _) = crate::rule_commit_recovery_tests::seed_retry_rebuild(&mut store);
    let candidate = candidate(&instance);
    store.prepare_publication(&candidate).unwrap();
    // Defensive read validation of an inconsistent retained journal, not a
    // receipt constructible through the publication bridge.
    let payload =
        serde_json::json!({"slot":candidate.slot,"event_id":"different-event"}).to_string();
    store
        .append_event(NewEvent {
            instance_id: &instance,
            event_type: "norm.publication.acknowledged",
            payload_json: &payload,
            source: "fixture",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("inconsistent-ack"),
        })
        .unwrap();
    let before = store.list_events(&instance).unwrap();
    let event_id = candidate.event.tracker_event().unwrap().event_id;
    assert!(store
        .acknowledge_publication(&candidate.slot, &event_id)
        .is_err());
    assert_eq!(store.list_events(&instance).unwrap(), before);
}
#[test]
fn norm_publication_inconsistent_acknowledgment_native() {
    inconsistent_acknowledgment(SqliteStore::open_in_memory().unwrap());
}
#[test]
fn norm_publication_inconsistent_acknowledgment_hosted() {
    inconsistent_acknowledgment(crate::do_store::test_support::store());
}

#[test]
fn norm_publication_hosted_lost_append_reply_rolls_back() {
    use crate::do_store::{test_support::store, DoSql, DoSqliteStore, SqlValue};
    struct LostAppendReply<S> {
        inner: S,
        armed: std::cell::Cell<bool>,
    }
    impl<S: DoSql> DoSql for LostAppendReply<S> {
        fn atomic(&self, body: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            self.inner.atomic(body)
        }
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.inner.execute(sql, params)
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            let rows = self.inner.query(sql, params)?;
            // The actual SQLite write has occurred, but the bridge loses its
            // reply. A pre-statement fault cannot expose this rollback boundary.
            if sql.starts_with("INSERT INTO events ") && self.armed.replace(false) {
                return Err("injected reply loss after event insertion".into());
            }
            Ok(rows)
        }
    }
    for acknowledge in [false, true] {
        let mut original = store();
        let (instance, _) = crate::rule_commit_recovery_tests::seed_retry_rebuild(&mut original);
        let candidate = candidate(&instance);
        if acknowledge {
            original.prepare_publication(&candidate).unwrap();
        }
        let before = original.list_events(&instance).unwrap();
        let head = original.chain_head(&instance).unwrap();
        let faulty = DoSqliteStore::new(LostAppendReply {
            inner: original.sql,
            armed: std::cell::Cell::new(true),
        });
        let event_id = candidate.event.tracker_event().unwrap().event_id;
        let result = if acknowledge {
            faulty
                .acknowledge_publication(&candidate.slot, &event_id)
                .map(|_| ())
        } else {
            faulty.prepare_publication(&candidate).map(|_| ())
        };
        assert!(result.is_err());
        assert!(
            !faulty.sql.armed.get(),
            "fault must occur after the actual insert"
        );
        assert_eq!(faulty.list_events(&instance).unwrap(), before);
        assert_eq!(faulty.chain_head(&instance).unwrap(), head);
        faulty.prepare_publication(&candidate).unwrap();
        faulty
            .acknowledge_publication(&candidate.slot, &event_id)
            .unwrap();
    }
}
