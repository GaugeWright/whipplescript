//! Shared publication checks. Receipts here are fixtures; the governed facade
//! separately qualifies the authenticated original dispatch and actual target.
use super::*;
use crate::{
    file_settlement::{conformance, LocalEffectSettlementFact},
    log_append::LogAppend,
    tracker_closure::{TrackerClosure, TrackerClosureReceipt},
    EffectCompletion, RuntimeStore,
};

pub fn setup(store: &mut impl RuntimeStore, status: &str) -> TrackerClosureResultDelivery {
    let fixture =
        conformance::setup_profile_queued(store, "tracker.finish", "failed", "queue", None);
    let closure = TrackerClosure {
        operation_id: "closing:one".into(),
        instance_id: fixture.instance.clone(),
        effect_id: "settle-effect".into(),
        actor: "person:learner".into(),
        queue: "tutorials".into(),
        item_id: "WS-1".into(),
        subject_id: "subject:one".into(),
        summary: Some("Self-reported completion".into()),
        expected_holder: Some("workflow:holder".into()),
    };
    let receipt = TrackerClosureReceipt {
        operation_id: closure.operation_id.clone(),
        fingerprint: closure.fingerprint().expect("fixture fingerprint"),
        queue: closure.queue.clone(),
        item_id: closure.item_id.clone(),
        subject_id: closure.subject_id.clone(),
        actor: closure.actor.clone(),
        event_id: "closing-event:one".into(),
        closed_at: "2026-09-11T00:00:00Z".into(),
    };
    let metadata = json!({"tracker_closure": {
        "operation_id": closure.operation_id, "fingerprint": receipt.fingerprint, "summary": closure.summary,
        "binding": {"tracker": {"queue": closure.queue}, "item_id": closure.item_id, "subject_id": closure.subject_id, "expected_holder": closure.expected_holder}
    }, "action_execution": {"request": {"provenance": {"executor": closure.actor}}}}).to_string();
    let mut run = fixture.run();
    run.metadata_json = &metadata;
    store
        .start_dispatch(run)
        .expect("original closing dispatch");
    match status {
        "running" => {}
        "lease_expired" => {
            assert_eq!(
                store
                    .expire_leases(&fixture.instance, "2099-01-01T00:00:00Z")
                    .expect("expire closing attempt")
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
                        name: "tracker.finish.failed",
                        value_json: &value,
                    },
                )
                .expect("unhandled closing failure");
        }
        _ => panic!("unknown fixture state"),
    }
    TrackerClosureResultDelivery {
        closure,
        run_id: "settle-run".into(),
        closing_receipt: receipt,
        fact_id: "recovered-fact".into(),
        recovery: json!({"issuer": "workspace:fixture", "investigator": "agent:recovery"}),
    }
}

pub fn run_suite(
    store: &mut (impl RuntimeStore + LogAppend + TrackerResultPublications),
    status: &str,
) {
    let delivery = setup(store, status);
    let instance = &delivery.closure.instance_id;
    let owner = store
        .claim_instance_ownership(instance)
        .expect("own closing recovery");
    let head = store.chain_head(instance).expect("original history");
    let published = store
        .publish_tracker_closure_result(owner, &head.digest, &delivery)
        .expect("publish actual closing result");
    let facts = store.list_facts(instance).expect("closing continuation");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].name, "tracker.finish.completed");
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
        crate::effect_recovery::fold_attempts(instance, &delivery.closure.effect_id, &events)
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
            .filter(|event| event.event_type == CLOSING_DELIVERY_EVENT)
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
                .expect("replay closing publication");
        }
        let head = store.chain_head(instance).expect("retry history");
        assert_eq!(
            store
                .publish_tracker_closure_result(owner, &head.digest, &delivery)
                .expect("exact closing redelivery"),
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
        .publish_tracker_closure_result(owner, &head.digest, &changed)
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
            rule: "consume_closing_result",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[&delivery.fact_id],
            effects: &[],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("consume-closing-result"),
            marks: &[],
            context_json: None,
        })
        .expect("consume published closing fact");
    for replay in [false, true] {
        if replay {
            store
                .rebuild_projections(instance)
                .expect("replay consumption");
        }
        let head = store.chain_head(instance).expect("consumed history");
        assert_eq!(
            store
                .publish_tracker_closure_result(owner, &head.digest, &delivery)
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
    let instance = delivery.closure.instance_id.clone();
    let owner = store
        .claim_instance_ownership(&instance)
        .expect("own fixture");
    match field {
        "operation" => {
            delivery.closure.operation_id = "closing:other".into();
            delivery.closing_receipt.operation_id = delivery.closure.operation_id.clone();
        }
        "actor" => {
            delivery.closure.actor = "agent:other".into();
            delivery.closing_receipt.actor = delivery.closure.actor.clone();
        }
        "queue" => {
            delivery.closure.queue = "private".into();
            delivery.closing_receipt.queue = delivery.closure.queue.clone();
        }
        "item" => {
            delivery.closure.item_id = "WS-2".into();
            delivery.closing_receipt.item_id = delivery.closure.item_id.clone();
        }
        "subject" => {
            delivery.closure.subject_id = "subject:other".into();
            delivery.closing_receipt.subject_id = delivery.closure.subject_id.clone();
        }
        "summary" => delivery.closure.summary = Some("different closing".into()),
        "holder" => delivery.closure.expected_holder = None,
        _ => panic!("unknown changed coordinate"),
    }
    delivery.closing_receipt.fingerprint = delivery
        .closure
        .fingerprint()
        .expect("changed self-consistent request");
    delivery.validate().expect("well-formed but foreign result");
    let head = store
        .chain_head(&instance)
        .expect("original dispatch history");
    let error = store
        .publish_tracker_closure_result(owner, &head.digest, &delivery)
        .expect_err("changed original request");
    assert!(
        matches!(error, StoreError::Conflict(ref message) if message == "tracker closing result differs from its original dispatch"),
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

/// Replay a valid historical fixture, so a same-second wall-clock run cannot
/// hide a projection that substitutes today's time for the recorded time.
/// The callback installs fixture rows only; production history is append-only.
pub fn run_historical_timestamps<S: RuntimeStore + LogAppend + TrackerResultPublications>(
    store: &mut S,
    status: &str,
    mut install: impl FnMut(&mut S, &crate::event_chain::OwnedChainEntry, &str, &str),
) {
    let delivery = setup(store, status);
    let instance = &delivery.closure.instance_id;
    let mut entries = store.chain_prefix(instance).expect("fixture history");
    let mut previous = crate::event_chain::genesis_digest(instance);
    for entry in &mut entries {
        entry.occurred_at = format!("2001-01-01 00:{:02}:00", entry.sequence);
        let digest = crate::event_chain::entry_digest(&previous, &entry.as_entry(instance));
        install(store, entry, &previous, &digest);
        previous = digest;
    }
    let head = store.chain_head(instance).expect("historical head");
    assert_eq!(head, crate::event_chain::fold_owned(instance, &entries));
    store
        .rebuild_projections(instance)
        .expect("historical replay");
    let runs = store.list_runs(instance).expect("historical run");
    assert_eq!(runs.len(), 1);
    let start = entries
        .iter()
        .find(|e| e.event_type == "effect.run_started")
        .expect("start event");
    assert_eq!(runs[0].started_at, start.occurred_at);
    let ending = entries
        .iter()
        .find(|e| matches!(e.event_type.as_str(), "effect.terminal" | "lease.expired"));
    assert_eq!(
        runs[0].completed_at.as_deref(),
        ending.map(|e| e.occurred_at.as_str())
    );
    assert_eq!(runs[0].status, status);
    assert_eq!(store.chain_head(instance).expect("unchanged history"), head);
    let owner = store
        .claim_instance_ownership(instance)
        .expect("recovery owner");
    let head = store.chain_head(instance).expect("recovery head");
    let publication = store
        .publish_tracker_closure_result(owner, &head.digest, &delivery)
        .expect("recover historical attempt");
    let recovered = store.list_runs(instance).expect("recovered run");
    if status == "running" {
        assert_eq!(recovered[0].started_at, runs[0].started_at);
        let terminal = store
            .list_events(instance)
            .expect("terminal history")
            .into_iter()
            .find(|e| e.event_type == "effect.terminal")
            .expect("recovery terminal");
        assert_eq!(
            recovered[0].completed_at.as_deref(),
            Some(terminal.occurred_at.as_str())
        );
    } else {
        assert_eq!(recovered, runs, "recovery must preserve a stopped attempt");
    }
    store
        .rebuild_projections(instance)
        .expect("recovered historical replay");
    assert_eq!(store.list_runs(instance).expect("replayed run"), recovered);
    let head = store.chain_head(instance).expect("redelivery head");
    assert_eq!(
        store
            .publish_tracker_closure_result(owner, &head.digest, &delivery)
            .expect("historical redelivery"),
        publication
    );
    assert_eq!(store.list_runs(instance).expect("unchanged run"), recovered);
    assert_eq!(store.chain_head(instance).expect("unchanged head"), head);
}
