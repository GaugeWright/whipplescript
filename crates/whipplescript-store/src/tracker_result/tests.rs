use super::*;
use crate::SqliteStore;

#[test]
fn native_tracker_result_delivery_preserves_terminal_history_and_replays() {
    for status in ["running", "lease_expired", "failed"] {
        conformance::run_suite(&mut SqliteStore::open_in_memory().unwrap(), status);
    }
}

#[test]
fn native_tracker_result_publication_rolls_back_after_projection_or_terminal_faults() {
    for status in ["running", "lease_expired", "failed"] {
        for trigger in [
            "CREATE TRIGGER result_fault AFTER INSERT ON facts BEGIN SELECT RAISE(ABORT, 'fact fault'); END",
            "CREATE TRIGGER result_fault AFTER UPDATE ON effects BEGIN SELECT RAISE(ABORT, 'effect fault'); END",
            "CREATE TRIGGER result_fault AFTER INSERT ON events WHEN NEW.event_type='effect.terminal' BEGIN SELECT RAISE(ABORT, 'terminal fault'); END",
            "CREATE TRIGGER result_fault AFTER INSERT ON events WHEN NEW.event_type='effect.disposition.recorded' BEGIN SELECT RAISE(ABORT, 'evidence fault'); END",
        ] {
            if status != "running" && trigger.contains("terminal fault") { continue; }
            let mut store = SqliteStore::open_in_memory().unwrap();
            let delivery = conformance::setup(&mut store, status);
            let epoch = store.claim_instance_ownership(&delivery.instance_id).unwrap();
            let before = store.list_events(&delivery.instance_id).unwrap();
            let facts = store.list_facts(&delivery.instance_id).unwrap();
            let head = store.chain_head(&delivery.instance_id).unwrap();
            store.connection.execute_batch(trigger).unwrap();
            assert!(store.publish_tracker_result(epoch, &head.digest, &delivery).is_err());
            assert_eq!(store.list_events(&delivery.instance_id).unwrap(), before);
            assert_eq!(store.list_facts(&delivery.instance_id).unwrap(), facts);
            assert_eq!(store.list_runs(&delivery.instance_id).unwrap()[0].status, status);
            assert_eq!(store.chain_head(&delivery.instance_id).unwrap(), head);
            store.connection.execute_batch("DROP TRIGGER result_fault").unwrap();
            store.publish_tracker_result(epoch, &head.digest, &delivery).unwrap();
        }
    }
}

#[test]
fn native_tracker_result_refuses_stale_owner_head_and_mismatched_dispatch() {
    for change in [
        "owner",
        "head",
        "title",
        "fingerprint",
        "operation",
        "queue",
        "run",
        "effect",
    ] {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let mut delivery = conformance::setup(&mut store, "lease_expired");
        let epoch = store
            .claim_instance_ownership(&delivery.instance_id)
            .unwrap();
        let mut head = store.chain_head(&delivery.instance_id).unwrap();
        match change {
            "owner" => {
                store
                    .claim_instance_ownership(&delivery.instance_id)
                    .unwrap();
                head = store.chain_head(&delivery.instance_id).unwrap();
            }
            "head" => {
                store
                    .append_event(crate::NewEvent {
                        instance_id: &delivery.instance_id,
                        event_type: "test.append",
                        payload_json: "{}",
                        source: "kernel",
                        causation_id: None,
                        correlation_id: None,
                        idempotency_key: None,
                    })
                    .unwrap();
            }
            "title" => delivery.title = "Other title".into(),
            "fingerprint" => delivery.filing_receipt.fingerprint = "other".into(),
            "operation" => delivery.filing_receipt.operation_id = "other".into(),
            "queue" => delivery.queue = "other".into(),
            "run" => delivery.run_id = "other".into(),
            "effect" => delivery.effect_id = "other".into(),
            _ => unreachable!(),
        }
        let before = store.list_events(&delivery.instance_id).unwrap();
        assert!(
            store
                .publish_tracker_result(epoch, &head.digest, &delivery)
                .is_err(),
            "{change}"
        );
        assert_eq!(store.list_events(&delivery.instance_id).unwrap(), before);
        assert!(store.list_facts(&delivery.instance_id).unwrap().is_empty());
    }
}

#[test]
fn native_tracker_result_cannot_reopen_a_terminal_or_handled_workflow() {
    for case in ["paused", "cancelled", "failed", "observed", "consumed"] {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let delivery = conformance::setup(&mut store, "failed");
        let instance = &delivery.instance_id;
        if matches!(case, "paused" | "cancelled" | "failed") {
            store
                .transition_instance(crate::InstanceTransition {
                    instance_id: instance,
                    status: case,
                    reason: None,
                    idempotency_key: None,
                })
                .unwrap();
        } else {
            let consumed = if case == "consumed" {
                vec!["failed-fact"]
            } else {
                vec![]
            };
            store
                .commit_rule(crate::RuleCommit {
                    instance_id: instance,
                    rule: "handle_failure",
                    trigger_event_id: None,
                    facts: &[],
                    consumed_fact_ids: &consumed,
                    effects: &[],
                    dependencies: &[],
                    terminal: None,
                    idempotency_key: Some("failure-handler"),
                    marks: &[],
                    context_json: None,
                })
                .unwrap();
        }
        let epoch = store.claim_instance_ownership(instance).unwrap();
        let head = store.chain_head(instance).unwrap();
        let facts = store.list_facts(instance).unwrap();
        assert!(
            store
                .publish_tracker_result(epoch, &head.digest, &delivery)
                .is_err(),
            "{case}"
        );
        assert_eq!(store.chain_head(instance).unwrap(), head);
        assert_eq!(store.list_facts(instance).unwrap(), facts);
        assert_eq!(store.list_runs(instance).unwrap()[0].status, "failed");
    }
}

#[test]
fn native_tracker_result_refuses_an_external_redelivery_record() {
    conformance::refuse_external_redelivery(&mut SqliteStore::open_in_memory().unwrap());
}

#[test]
fn native_tracker_result_eligibility_ignores_external_event_names() {
    for scenario in ["attempt", "rule", "terminal"] {
        conformance::external_names_do_not_change_eligibility(
            &mut SqliteStore::open_in_memory().unwrap(),
            scenario,
        );
    }
}

#[test]
fn tracker_result_application_evidence_requires_the_exact_attempt_and_issuer() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let delivery = conformance::setup(&mut store, "lease_expired");
    let events = store.list_events(&delivery.instance_id).unwrap();
    let start: Value = serde_json::from_str(
        &events
            .iter()
            .find(|event| event.event_type == "effect.run_started")
            .unwrap()
            .payload_json,
    )
    .unwrap();
    let evidence = delivery.application_evidence(&start).unwrap();
    assert_eq!(evidence.disposition, EvidenceDisposition::Applied);
    assert_eq!(evidence.evidence_ref, delivery.filing_receipt.event_id);
    assert_eq!(evidence.authority_ref, "workspace:fixture");
    for field in [
        "protocol",
        "instance_id",
        "effect_id",
        "run_id",
        "kind",
        "provider",
        "target",
    ] {
        let mut altered = start.clone();
        altered["external_dispatch"]["frame"][field] = "different".into();
        assert!(
            matches!(delivery.application_evidence(&altered), Err(StoreError::Conflict(message))
            if message == "tracker result evidence differs from its dispatch"),
            "{field}"
        );
    }
    for issuer in [Value::Null, json!(""), json!("   "), json!(7)] {
        let mut altered = delivery.clone();
        altered.recovery["issuer"] = issuer;
        assert!(
            matches!(altered.application_evidence(&start), Err(StoreError::Conflict(message))
            if message == "tracker result recovery issuer is missing")
        );
    }
    for field in ["operation_id", "fingerprint", "item_id", "event_id"] {
        let mut receipt = serde_json::to_value(&delivery.filing_receipt).unwrap();
        receipt[field] = "another".into();
        let receipt = serde_json::from_value(receipt).unwrap();
        assert_ne!(
            receipt_evidence_digest(&receipt),
            evidence.evidence_digest,
            "{field}"
        );
    }
}

#[test]
fn native_tracker_result_enforces_each_publication_eligibility_condition() {
    for case in conformance::REFUSAL_CASES {
        conformance::refuse_ineligible(&mut SqliteStore::open_in_memory().unwrap(), case);
    }
}

#[test]
fn native_tracker_result_replay_refuses_a_foreign_instance_before_projection() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let delivery = conformance::setup(&mut store, "failed");
    let record = RecordedTrackerResult {
        delivery,
        consumed_failure_facts: vec![],
        complete_running_attempt: false,
    };
    let error = native::apply_result(
        &store.connection,
        "different-instance",
        "replay-event",
        &record.into_delivered(),
    )
    .unwrap_err();
    assert!(
        matches!(error, StoreError::Conflict(reason) if reason == "tracker result replay instance differs")
    );
}

#[test]
fn tracker_result_delivery_requires_complete_coordinates_and_object_provenance() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let delivery = conformance::setup(&mut store, "failed");
    delivery.validate().unwrap();
    for path in [
        "/instance_id",
        "/effect_id",
        "/run_id",
        "/queue",
        "/fact_id",
        "/filing_receipt/operation_id",
        "/filing_receipt/fingerprint",
        "/filing_receipt/item_id",
        "/filing_receipt/event_id",
    ] {
        for blank in ["", "   "] {
            let mut value = serde_json::to_value(&delivery).unwrap();
            *value.pointer_mut(path).unwrap() = blank.into();
            let changed: TrackerResultDelivery = serde_json::from_value(value).unwrap();
            assert!(
                matches!(changed.validate(), Err(StoreError::Conflict(message))
                if message == "tracker result delivery coordinates are incomplete"),
                "{path}"
            );
        }
    }
    for provenance in [Value::Null, json!([]), json!("authority"), json!(true)] {
        let mut changed = delivery.clone();
        changed.recovery = provenance;
        assert!(
            matches!(changed.validate(), Err(StoreError::Conflict(message))
            if message == "tracker result delivery coordinates are incomplete")
        );
    }
}

#[test]
fn native_tracker_closing_result_preserves_attempts_and_matches_original_dispatch() {
    for status in ["running", "lease_expired", "failed"] {
        closing_conformance::run_suite(&mut SqliteStore::open_in_memory().unwrap(), status);
    }
    for field in [
        "operation",
        "actor",
        "queue",
        "item",
        "subject",
        "summary",
        "holder",
    ] {
        closing_conformance::refuse_changed_dispatch(
            &mut SqliteStore::open_in_memory().unwrap(),
            field,
        );
    }
}

#[test]
fn native_tracker_closing_result_faults_leave_no_partial_publication() {
    for status in ["running", "lease_expired", "failed"] {
        for trigger in [
            "AFTER INSERT ON facts",
            "AFTER UPDATE ON effects",
            "AFTER INSERT ON events WHEN NEW.event_type='effect.disposition.recorded'",
            "AFTER INSERT ON events WHEN NEW.event_type='effect.terminal'",
            "AFTER INSERT ON events WHEN NEW.event_type='tracker.closing.result_delivered'",
        ] {
            if status != "running" && trigger.contains("effect.terminal") {
                continue;
            }
            let mut store = SqliteStore::open_in_memory().unwrap();
            let delivery = closing_conformance::setup(&mut store, status);
            let instance = &delivery.closure.instance_id;
            let owner = store.claim_instance_ownership(instance).unwrap();
            let before = store.list_events(instance).unwrap();
            let facts = store.list_facts(instance).unwrap();
            let runs = store.list_runs(instance).unwrap();
            let head = store.chain_head(instance).unwrap();
            store.connection.execute_batch(&format!("CREATE TRIGGER closing_result_fault {trigger} BEGIN SELECT RAISE(ABORT, 'closing result fault'); END")).unwrap();
            let error = store
                .publish_tracker_closure_result(owner, &head.digest, &delivery)
                .unwrap_err();
            assert!(format!("{error:?}").contains("closing result fault"));
            assert_eq!(store.list_events(instance).unwrap(), before);
            assert_eq!(store.list_facts(instance).unwrap(), facts);
            assert_eq!(store.list_runs(instance).unwrap(), runs);
            assert_eq!(store.chain_head(instance).unwrap(), head);
            store
                .connection
                .execute_batch("DROP TRIGGER closing_result_fault")
                .unwrap();
            store
                .publish_tracker_closure_result(owner, &head.digest, &delivery)
                .unwrap();
        }
    }
}

#[test]
fn tracker_closing_result_application_evidence_requires_the_exact_attempt_and_issuer() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let delivery = closing_conformance::setup(&mut store, "lease_expired");
    let events = store.list_events(&delivery.closure.instance_id).unwrap();
    let start: Value = serde_json::from_str(
        &events
            .iter()
            .find(|event| event.event_type == "effect.run_started")
            .unwrap()
            .payload_json,
    )
    .unwrap();
    let evidence = delivery.application_evidence(&start).unwrap();
    assert_eq!(evidence.disposition, EvidenceDisposition::Applied);
    assert_eq!(evidence.evidence_ref, delivery.closing_receipt.event_id);
    assert_eq!(evidence.authority_ref, "workspace:fixture");
    for field in [
        "protocol",
        "instance_id",
        "effect_id",
        "run_id",
        "kind",
        "provider",
        "target",
    ] {
        let mut altered = start.clone();
        altered["external_dispatch"]["frame"][field] = "different".into();
        assert!(
            matches!(delivery.application_evidence(&altered), Err(StoreError::Conflict(message))
            if message == "tracker closing result evidence differs from its dispatch"),
            "{field}"
        );
    }
    for issuer in [Value::Null, json!(""), json!("   "), json!(7)] {
        let mut altered = delivery.clone();
        altered.recovery["issuer"] = issuer;
        assert!(
            matches!(altered.application_evidence(&start), Err(StoreError::Conflict(message))
            if message == "tracker closing result recovery issuer is missing")
        );
    }
    for field in ["operation_id", "fingerprint", "item_id", "event_id"] {
        let mut receipt = serde_json::to_value(&delivery.closing_receipt).unwrap();
        receipt[field] = "another".into();
        let receipt = serde_json::from_value(receipt).unwrap();
        assert_ne!(
            closing_receipt_evidence_digest(&receipt),
            evidence.evidence_digest,
            "{field}"
        );
    }
}

#[test]
fn tracker_closing_result_requires_complete_publication_coordinates() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let delivery = closing_conformance::setup(&mut store, "running");
    for field in ["run_id", "fact_id"] {
        for blank in ["", "   "] {
            let mut value = serde_json::to_value(&delivery).unwrap();
            value[field] = json!(blank);
            let invalid: TrackerClosureResultDelivery = serde_json::from_value(value).unwrap();
            assert!(
                matches!(invalid.validate(), Err(StoreError::Conflict(message))
                if message == "tracker closing result coordinates are incomplete")
            );
        }
    }
    for recovery in [Value::Null, json!("issuer"), json!([])] {
        let invalid = TrackerClosureResultDelivery {
            recovery,
            ..delivery.clone()
        };
        assert!(
            matches!(invalid.validate(), Err(StoreError::Conflict(message))
            if message == "tracker closing result coordinates are incomplete")
        );
    }
}

#[test]
fn native_tracker_recovery_preserves_historical_run_timestamps() {
    for status in ["running", "failed", "lease_expired"] {
        closing_conformance::run_historical_timestamps(
            &mut SqliteStore::open_in_memory().unwrap(),
            status,
            |store, entry, previous, digest| {
                store.connection.execute(
                    "UPDATE events SET occurred_at=?1, prev_digest=?2, entry_digest=?3 WHERE event_id=?4",
                    rusqlite::params![entry.occurred_at, previous, digest, entry.event_id],
                ).unwrap();
            },
        );
    }
}
