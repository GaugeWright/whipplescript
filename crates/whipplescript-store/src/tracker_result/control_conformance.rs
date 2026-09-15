//! Shared publication checks. Receipts here are fixtures; the governed facade
//! separately qualifies the authenticated original dispatch and actual target.
use super::*;
use crate::{
    file_settlement::{conformance, LocalEffectSettlementFact},
    log_append::LogAppend,
    tracker_control::{
        TrackerControl, TrackerControlAction, TrackerControlOutcome, TrackerControlReceipt,
    },
    EffectCompletion, RuntimeStore,
};

pub fn setup(store: &mut impl RuntimeStore, status: &str) -> TrackerControlResultDelivery {
    let fixture = conformance::setup_profile_queued(
        store,
        "capability.call",
        "failed",
        CONTROL_PROVIDER,
        Some("tracker.claim"),
    );
    let control = TrackerControl {
        operation_id: "control:one".into(),
        instance_id: fixture.instance.clone(),
        effect_id: "settle-effect".into(),
        actor: "person:learner".into(),
        queue: "tutorials".into(),
        item_id: "WS-1".into(),
        subject_id: "subject:one".into(),
        action: TrackerControlAction::Claim {
            expires_at: "2999-01-01 00:00:00".into(),
        },
    };
    let receipt = TrackerControlReceipt {
        operation_id: control.operation_id.clone(),
        fingerprint: control.fingerprint().expect("fixture fingerprint"),
        queue: control.queue.clone(),
        item_id: control.item_id.clone(),
        subject_id: control.subject_id.clone(),
        actor: control.actor.clone(),
        outcome: TrackerControlOutcome::Claimed {
            expires_at: "2999-01-01 00:00:00".into(),
        },
        event_ids: vec!["control-event:one".into()],
        recorded_at: "2026-09-11 00:00:00".into(),
    };
    let metadata = json!({"tracker_control": {
        "request": control, "fingerprint": receipt.fingerprint,
        "binding": {"tracker": {"queue": control.queue}, "item_id": control.item_id, "subject_id": control.subject_id}
    }, "action_execution": {"request": {"provenance": {"executor": control.actor}}}}).to_string();
    let mut run = fixture.run();
    run.metadata_json = &metadata;
    store
        .start_dispatch(run)
        .expect("original control dispatch");
    match status {
        "running" => {}
        "lease_expired" => {
            assert_eq!(
                store
                    .expire_leases(&fixture.instance, "2099-01-01T00:00:00Z")
                    .expect("expire control attempt")
                    .len(),
                1
            );
        }
        "failed" => {
            let value = json!({"effect_id": "settle-effect", "run_id": "settle-run", "status": "failed", "value": {"reason": "interrupted"}}).to_string();
            store
                .settle_local_effect(
                    EffectCompletion {
                        metadata_json: r#"{"value":{"reason":"interrupted"}}"#,
                        ..fixture.completion()
                    },
                    None,
                    LocalEffectSettlementFact {
                        fact_id: "failed-fact",
                        event_key: "failed-fact-event",
                        name: "capability.call.failed",
                        value_json: &value,
                    },
                )
                .expect("unhandled control failure");
        }
        _ => panic!("unknown fixture state"),
    }
    TrackerControlResultDelivery {
        control,
        run_id: "settle-run".into(),
        control_receipt: receipt,
        fact_id: "recovered-fact".into(),
        recovery: json!({"issuer": "workspace:fixture", "investigator": "agent:recovery"}),
    }
}

pub fn run_suite(
    store: &mut (impl RuntimeStore + LogAppend + TrackerResultPublications),
    status: &str,
) {
    let delivery = setup(store, status);
    let instance = &delivery.control.instance_id;
    let owner = store
        .claim_instance_ownership(instance)
        .expect("own control recovery");
    let head = store.chain_head(instance).expect("original history");
    let published = store
        .publish_tracker_control_result(owner, &head.digest, &delivery)
        .expect("publish actual control result");
    let facts = store.list_facts(instance).expect("control continuation");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].name, "capability.call.succeeded");
    assert_eq!(facts[0].source_event_id, published.event_id);
    let fact: Value = serde_json::from_str(&facts[0].value_json).expect("ordinary outcome");
    assert_eq!(fact["value"], delivery.value());
    let runs = store.list_runs(instance).expect("retained attempt");
    assert_eq!(runs.len(), 1);
    assert_eq!(
        runs[0].status,
        if status == "running" {
            "completed"
        } else {
            status
        }
    );
    assert_eq!(
        store.list_effects(instance).expect("settled effect")[0].status,
        "completed"
    );
    let events = store.list_events(instance).expect("published evidence");
    let attempts =
        crate::effect_recovery::fold_attempts(instance, &delivery.control.effect_id, &events)
            .expect("standard disposition");
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].disposition,
        crate::effect_recovery::ExternalDisposition::Applied
    );
    assert!(!attempts[0].disputed);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == CONTROL_DELIVERY_EVENT)
            .count(),
        1
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == "effect.terminal")
            .count(),
        usize::from(status != "lease_expired")
    );
    for replay in [false, true] {
        if replay {
            store
                .rebuild_projections(instance)
                .expect("replay control publication");
        }
        let head = store.chain_head(instance).expect("retry history");
        assert_eq!(
            store
                .publish_tracker_control_result(owner, &head.digest, &delivery)
                .expect("exact control redelivery"),
            published
        );
        assert_eq!(
            store.chain_head(instance).expect("unchanged retry history"),
            head
        );
        assert_eq!(store.list_runs(instance).expect("retained attempts"), runs);
        assert_eq!(
            store.list_facts(instance).expect("retained continuation"),
            facts
        );
    }
    let mut changed = delivery.clone();
    changed.recovery["investigator"] = json!("person:another");
    let head = store
        .chain_head(instance)
        .expect("before changed redelivery");
    let error = store
        .publish_tracker_control_result(owner, &head.digest, &changed)
        .expect_err("changed recovery identity");
    assert!(
        matches!(error, StoreError::Conflict(ref message) if message == "tracker result identity already binds a different delivery"),
        "{error:?}"
    );
    assert_eq!(
        store
            .chain_head(instance)
            .expect("after changed redelivery"),
        head
    );

    // Explicit consumption is separate from an ordinary `then` observation.
    // An acknowledged result must never reactivate a fact consumed later.
    store
        .commit_rule(crate::RuleCommit {
            instance_id: instance,
            rule: "consume_control_result",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[&delivery.fact_id],
            effects: &[],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("consume-control-result"),
            marks: &[],
            context_json: None,
        })
        .expect("consume published control fact");
    for replay in [false, true] {
        if replay {
            store
                .rebuild_projections(instance)
                .expect("replay consumption");
        }
        let head = store.chain_head(instance).expect("consumed history");
        assert_eq!(
            store
                .publish_tracker_control_result(owner, &head.digest, &delivery)
                .expect("redelivery of consumed result"),
            published
        );
        assert_eq!(
            store.chain_head(instance).expect("same consumed history"),
            head
        );
        assert!(store
            .list_facts(instance)
            .expect("no reactivated result")
            .is_empty());
    }
}

pub fn refuse_changed_dispatch(
    store: &mut (impl RuntimeStore + LogAppend + TrackerResultPublications),
    field: &str,
) {
    let mut delivery = setup(store, "failed");
    let instance = delivery.control.instance_id.clone();
    let owner = store
        .claim_instance_ownership(&instance)
        .expect("own fixture");
    match field {
        "operation" => {
            delivery.control.operation_id = "control:other".into();
            delivery.control_receipt.operation_id = delivery.control.operation_id.clone();
        }
        "actor" => {
            delivery.control.actor = "agent:other".into();
            delivery.control_receipt.actor = delivery.control.actor.clone();
        }
        "queue" => {
            delivery.control.queue = "private".into();
            delivery.control_receipt.queue = delivery.control.queue.clone();
        }
        "item" => {
            delivery.control.item_id = "WS-2".into();
            delivery.control_receipt.item_id = delivery.control.item_id.clone();
        }
        "subject" => {
            delivery.control.subject_id = "subject:other".into();
            delivery.control_receipt.subject_id = delivery.control.subject_id.clone();
        }
        "deadline" => {
            delivery.control.action = TrackerControlAction::Claim {
                expires_at: "2999-02-01 00:00:00".into(),
            };
            delivery.control_receipt.outcome = TrackerControlOutcome::Claimed {
                expires_at: "2999-02-01 00:00:00".into(),
            };
        }
        _ => panic!("unknown changed coordinate"),
    }
    delivery.control_receipt.fingerprint = delivery
        .control
        .fingerprint()
        .expect("changed self-consistent request");
    delivery.validate().expect("well-formed but foreign result");
    let head = store
        .chain_head(&instance)
        .expect("original dispatch history");
    let error = store
        .publish_tracker_control_result(owner, &head.digest, &delivery)
        .expect_err("changed original request");
    assert!(
        matches!(error, StoreError::Conflict(ref message) if message == "tracker control result differs from its original dispatch"),
        "{field}: {error:?}"
    );
    assert_eq!(
        store
            .chain_head(&instance)
            .expect("unchanged refused history"),
        head
    );
    assert_eq!(
        store.list_runs(&instance).expect("unchanged attempt")[0].status,
        "failed"
    );
}
