//! Shared backend checks. The receipt is a fixture; actual target verification
//! and current principal authority belong to the governed kernel entry point.
use super::*;
use crate::{
    file_settlement::{conformance, LocalEffectSettlementFact},
    log_append::LogAppend,
    EffectCompletion, RuntimeStore,
};

pub fn setup(store: &mut impl RuntimeStore, status: &str) -> TrackerResultDelivery {
    let filing_receipt = TrackerFilingReceipt {
        operation_id: "filing:one".into(),
        fingerprint: "exact-request".into(),
        item_id: "WS-1".into(),
        event_id: "creation:1".into(),
    };
    let metadata = json!({"tracker_filing": {"operation_id": filing_receipt.operation_id,
        "fingerprint": filing_receipt.fingerprint, "queue": "tutorials", "title": "Original title"}}).to_string();
    let fixture = conformance::setup_profile_metadata(
        store,
        "tracker.file",
        "failed",
        "queue",
        Some("tutorials"),
        &metadata,
    );
    if status == "lease_expired" {
        assert_eq!(
            store
                .expire_leases(&fixture.instance, "2099-01-01T00:00:00Z")
                .expect("expire attempt")
                .len(),
            1
        );
    } else if status == "failed" {
        let value =
            json!({"effect_id": "settle-effect", "run_id": "settle-run", "status": "failed",
            "value": {"reason": "interrupted"}})
            .to_string();
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
                    name: "tracker.file.failed",
                    value_json: &value,
                },
            )
            .expect("record unhandled failed attempt");
    } else {
        assert_eq!(status, "running");
    }
    TrackerResultDelivery {
        instance_id: fixture.instance,
        effect_id: "settle-effect".into(),
        run_id: "settle-run".into(),
        queue: "tutorials".into(),
        title: "Original title".into(),
        filing_receipt,
        fact_id: "recovered-fact".into(),
        recovery: json!({"issuer": "workspace:fixture", "investigator": "person:recovery"}),
    }
}

pub fn run_suite(
    store: &mut (impl RuntimeStore + LogAppend + TrackerResultPublications),
    status: &str,
) {
    let delivery = setup(store, status);
    let instance = &delivery.instance_id;
    let epoch = store
        .claim_instance_ownership(instance)
        .expect("own recovery");
    let head = store.chain_head(instance).expect("observed history");
    let event = store
        .publish_tracker_result(epoch, &head.digest, &delivery)
        .expect("deliver retained result");
    let facts = store.list_facts(instance).expect("ordinary facts");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].name, "tracker.file.completed");
    assert_eq!(facts[0].value_json, delivery.fact_value().to_string());
    assert_eq!(facts[0].source_event_id, event.event_id);
    let runs = store.list_runs(instance).expect("attempt history");
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
        store.list_effects(instance).expect("effect result")[0].status,
        "completed"
    );
    let events = store.list_events(instance).expect("recovery records");
    let attempts = crate::effect_recovery::fold_attempts(instance, &delivery.effect_id, &events)
        .expect("fold recovered target knowledge");
    assert_eq!(attempts.len(), 1);
    assert_eq!(
        attempts[0].disposition,
        crate::effect_recovery::ExternalDisposition::Applied
    );
    assert!(!attempts[0].disputed);
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == DELIVERY_EVENT)
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
    for rebuild in [false, true] {
        if rebuild {
            store
                .rebuild_projections(instance)
                .expect("replay recovery");
        }
        let head = store.chain_head(instance).expect("current history");
        assert_eq!(
            store
                .publish_tracker_result(epoch, &head.digest, &delivery)
                .expect("exact redelivery"),
            event
        );
        assert_eq!(
            store
                .list_events(instance)
                .expect("no duplicate publication"),
            events
        );
        assert_eq!(
            store.list_facts(instance).expect("same continuation"),
            facts
        );
        assert_eq!(
            store.list_runs(instance).expect("same original terminal")[0].status,
            runs[0].status
        );
    }
    let mut changed = delivery.clone();
    changed.title = "Edited current title".into();
    let head = store.chain_head(instance).expect("history");
    assert!(store
        .publish_tracker_result(epoch, &head.digest, &changed)
        .is_err());
    assert_eq!(
        store.list_events(instance).expect("no changed replay"),
        events
    );
}

pub fn refuse_external_redelivery(
    store: &mut (impl RuntimeStore + LogAppend + TrackerResultPublications),
) {
    let delivery = setup(store, "lease_expired");
    let instance = &delivery.instance_id;
    let record = RecordedTrackerResult {
        delivery: delivery.clone(),
        consumed_failure_facts: vec![],
        complete_running_attempt: false,
    };
    store
        .append_event(crate::NewEvent {
            instance_id: instance,
            event_type: DELIVERY_EVENT,
            payload_json: &serde_json::to_string(&record).expect("serialize forged delivery"),
            source: "external",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some(&delivery.event_key()),
        })
        .expect("record external lookalike");
    let epoch = store
        .claim_instance_ownership(instance)
        .expect("own fixture instance");
    let head = store.chain_head(instance).expect("observe fixture head");
    let error = store
        .publish_tracker_result(epoch, &head.digest, &delivery)
        .expect_err("external evidence cannot impersonate an acknowledged delivery");
    assert!(matches!(error, StoreError::Conflict(message)
        if message == "tracker result identity already binds a different delivery"));
    assert_eq!(store.chain_head(instance).expect("unchanged history"), head);
    assert!(store
        .list_facts(instance)
        .expect("no forged success fact")
        .is_empty());
    store
        .rebuild_projections(instance)
        .expect("replay ignores external delivery");
    assert!(store
        .list_facts(instance)
        .expect("no replayed success fact")
        .is_empty());
    assert_eq!(
        store.list_effects(instance).expect("effect remains failed")[0].status,
        "failed"
    );
}

/// Eligibility uses recorded kernel actions, not names supplied by an event
/// producer. This checks live publication; ordinary replay has its own suite.
pub fn external_names_do_not_change_eligibility(
    store: &mut (impl RuntimeStore + LogAppend + TrackerResultPublications),
    scenario: &str,
) {
    let status = if scenario == "terminal" {
        "running"
    } else {
        "failed"
    };
    let delivery = setup(store, status);
    let instance = &delivery.instance_id;
    let event_type = match scenario {
        "attempt" => "effect.run_started",
        "rule" => "rule.committed",
        "terminal" => "effect.terminal",
        _ => panic!("unknown eligibility scenario"),
    };
    store
        .append_event(crate::NewEvent {
            instance_id: instance,
            event_type,
            payload_json: &json!({"effect_id": delivery.effect_id, "run_id": delivery.run_id})
                .to_string(),
            source: "external",
            causation_id: None,
            correlation_id: None,
            idempotency_key: None,
        })
        .expect("append external lookalike");
    if scenario == "terminal" {
        store
            .commit_rule(crate::RuleCommit {
                instance_id: instance,
                rule: "unrelated_rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("unrelated-commit"),
                marks: &[],
                context_json: None,
            })
            .expect("commit a rule before any actual attempt terminal");
    }
    let epoch = store
        .claim_instance_ownership(instance)
        .expect("own fixture");
    let head = store.chain_head(instance).expect("observe eligibility");
    store
        .publish_tracker_result(epoch, &head.digest, &delivery)
        .expect("external lookalikes cannot fabricate a competing attempt or handled failure");
    let facts = store.list_facts(instance).expect("ordinary result");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].value_json, delivery.fact_value().to_string());
}

pub const REFUSAL_CASES: &[&str] = &[
    "owner",
    "head",
    "run",
    "effect",
    "paused",
    "cancelled",
    "failed",
    "observed",
    "consumed",
    "competing",
    "title",
    "fingerprint",
    "operation",
    "queue",
];

/// Exact errors distinguish an early eligibility refusal from a later guard
/// which happens to reject the same fixture. No refused publication changes any
/// projection or original attempt, including after its failure was handled.
pub fn refuse_ineligible(
    store: &mut (impl RuntimeStore + LogAppend + TrackerResultPublications),
    case: &str,
) {
    let mut delivery = setup(store, "failed");
    let instance = delivery.instance_id.clone();
    let epoch = store
        .claim_instance_ownership(&instance)
        .expect("own recovery");
    let initial_head = store.chain_head(&instance).expect("initial head");
    let expected = match case {
        "owner" => {
            store
                .claim_instance_ownership(&instance)
                .expect("new owner");
            "tracker result owner changed before publication"
        }
        "head" => {
            store
                .append_event(crate::NewEvent {
                    instance_id: &instance,
                    event_type: "fixture.changed",
                    payload_json: "{}",
                    source: "kernel",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                })
                .expect("change history");
            "tracker result history changed before publication"
        }
        "run" | "effect" => {
            if case == "run" {
                delivery.run_id = "missing-run".into();
            } else {
                delivery.effect_id = "missing-effect".into();
            }
            "tracker result original attempt is missing"
        }
        "paused" | "cancelled" | "failed" => {
            store
                .transition_instance(crate::InstanceTransition {
                    instance_id: &instance,
                    status: case,
                    reason: None,
                    idempotency_key: None,
                })
                .expect("stop workflow");
            "tracker result cannot advance this workflow or attempt"
        }
        "observed" | "consumed" => {
            let consumed: &[&str] = if case == "consumed" {
                &["failed-fact"]
            } else {
                &[]
            };
            store
                .commit_rule(crate::RuleCommit {
                    instance_id: &instance,
                    rule: "handle_failure",
                    trigger_event_id: None,
                    facts: &[],
                    consumed_fact_ids: consumed,
                    effects: &[],
                    dependencies: &[],
                    terminal: None,
                    idempotency_key: Some("failure-handler"),
                    marks: &[],
                    context_json: None,
                })
                .expect("handle failure");
            "tracker result failure may already have been handled"
        }
        "competing" => {
            // A retained later dispatch is disqualifying, even when its full
            // outcome is unavailable. This is adversarial history, not admission.
            store
                .append_event(crate::NewEvent {
                    instance_id: &instance,
                    event_type: "effect.run_started",
                    payload_json: &json!({"effect_id": delivery.effect_id, "run_id": "later-run"})
                        .to_string(),
                    source: "kernel",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                })
                .expect("later dispatch history");
            "tracker result has a later competing attempt"
        }
        "title" | "fingerprint" | "operation" => {
            match case {
                "title" => delivery.title = "altered".into(),
                "fingerprint" => delivery.filing_receipt.fingerprint = "altered".into(),
                "operation" => delivery.filing_receipt.operation_id = "altered".into(),
                _ => unreachable!(),
            }
            "tracker result differs from its original dispatch"
        }
        "queue" => {
            delivery.queue = "elsewhere".into();
            "tracker result cannot advance this workflow or attempt"
        }
        _ => unreachable!(),
    };
    let head = store.chain_head(&instance).expect("current head");
    let events = store.list_events(&instance).expect("current events");
    let facts = store.list_facts(&instance).expect("current facts");
    let effects = store.list_effects(&instance).expect("current effects");
    let runs = store.list_runs(&instance).expect("current runs");
    let expected_head = if case == "head" {
        &initial_head.digest
    } else {
        &head.digest
    };
    let error = store
        .publish_tracker_result(epoch, expected_head, &delivery)
        .expect_err("ineligible recovery must refuse");
    assert!(
        matches!(error, StoreError::Conflict(ref reason) if reason == expected),
        "{case}: {error:?}"
    );
    assert_eq!(store.chain_head(&instance).expect("unchanged head"), head);
    assert_eq!(
        store.list_events(&instance).expect("unchanged events"),
        events
    );
    assert_eq!(store.list_facts(&instance).expect("unchanged facts"), facts);
    assert_eq!(
        store.list_effects(&instance).expect("unchanged effects"),
        effects
    );
    assert_eq!(store.list_runs(&instance).expect("unchanged runs"), runs);
}
