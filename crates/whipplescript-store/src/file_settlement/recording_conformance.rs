//! Shared native/DO qualification of atomic recording settlement. These are
//! storage fixtures, not evidence of governed recording admission or execution.
use super::*;
use crate::{log_append::LogAppend, RuntimeStore};
use serde_json::{json, Value};

pub fn setup(store: &mut impl RuntimeStore, status: &str) -> conformance::Fixture {
    let mut fixture = conformance::setup_recording(
        store,
        status,
        RESOLUTION_RECORDING_PROVIDER,
        Some(RESOLUTION_RECORDING_CAPABILITY),
    );
    // The fixture's reference-only result is shared with terminal metadata below.
    fixture.value = json!({
        "effect_id": "settle-effect", "run_id": "settle-run", "status": status,
        "value": outcome(status),
    })
    .to_string();
    fixture
}

fn outcome(status: &str) -> Value {
    if status == "completed" {
        json!({"operation_id": "recording", "receipt_hash": "receipt-reference"})
    } else {
        json!({"reason": "resolution recording did not settle successfully"})
    }
}

pub fn metadata(status: &str) -> String {
    json!({"value": outcome(status), "failure": {"message": "recording failed"}}).to_string()
}

pub fn run_suite(store: &mut (impl RuntimeStore + LogAppend), status: &str) {
    let fixture = setup(store, status);
    let metadata = metadata(status);
    let completion = EffectCompletion {
        metadata_json: &metadata,
        ..fixture.completion()
    };
    let before = store
        .list_events(&fixture.instance)
        .expect("initial history");
    for changed in [
        "provider",
        "status",
        "name",
        "effect",
        "run",
        "value",
        "missing-value",
        "fact-status",
        "fact-id",
        "event-key",
        "terminal-key",
        "shared-key",
    ] {
        let mut terminal = completion;
        let mut fact = fixture.fact();
        let mut value: Value = serde_json::from_str(&fixture.value).expect("fact value");
        match changed {
            "provider" => terminal.provider = "files",
            "status" => terminal.status = "uncertain",
            "name" => fact.name = "file.write.completed",
            "effect" => value["effect_id"] = json!("other"),
            "run" => value["run_id"] = json!("other"),
            "value" => value["value"] = json!({"reason": "substituted"}),
            "missing-value" => {
                value.as_object_mut().expect("object").remove("value");
            }
            "fact-status" => value["status"] = json!("uncertain"),
            "fact-id" => fact.fact_id = " ",
            "event-key" => fact.event_key = " ",
            "terminal-key" => terminal.idempotency_key = None,
            "shared-key" => terminal.idempotency_key = Some(fact.event_key),
            _ => unreachable!(),
        }
        let wire = value.to_string();
        fact.value_json = &wire;
        let error = store
            .settle_local_effect(terminal, None, fact)
            .expect_err("mismatched terminal and continuation refuse");
        assert!(
            matches!(error, StoreError::Conflict(ref detail)
            if detail == "file settlement fact does not bind its terminal"),
            "{changed}: {error:?}"
        );
        assert_eq!(
            store
                .list_events(&fixture.instance)
                .expect("unchanged history"),
            before,
            "{changed}"
        );
    }

    // A spent continuation key must roll back a valid terminal and projections.
    store
        .append_event(crate::NewEvent {
            instance_id: &fixture.instance,
            event_type: "fixture.spent",
            payload_json: "{}",
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("spent-continuation"),
        })
        .expect("occupy key");
    assert!(store
        .settle_local_effect(
            completion,
            fixture.diagnostic(),
            LocalEffectSettlementFact {
                event_key: "spent-continuation",
                ..fixture.fact()
            }
        )
        .is_err());
    assert_eq!(
        store.list_runs(&fixture.instance).expect("run")[0].status,
        "running"
    );
    assert!(store
        .list_facts(&fixture.instance)
        .expect("facts")
        .is_empty());
    assert!(store
        .list_diagnostics(Some(&fixture.instance))
        .expect("diagnostics")
        .is_empty());

    let terminal = store
        .settle_local_effect(completion, fixture.diagnostic(), fixture.fact())
        .expect("atomic recording settlement");
    let prefix = store
        .chain_prefix(&fixture.instance)
        .expect("settled prefix");
    let continuation = prefix
        .iter()
        .find(|event| event.event_type == "fact.derived")
        .expect("continuation event");
    assert_eq!(continuation.sequence, terminal.sequence + 1);
    assert_eq!(
        continuation.causation_id.as_deref(),
        Some(terminal.event_id.as_str())
    );
    let facts = store.list_facts(&fixture.instance).expect("settled facts");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].name, fixture.name);
    assert_eq!(
        serde_json::from_str::<Value>(&facts[0].value_json).expect("fact"),
        serde_json::from_str::<Value>(&fixture.value).expect("expected fact")
    );
    assert_eq!(
        store.list_runs(&fixture.instance).expect("settled run")[0].status,
        status
    );
    assert_eq!(
        store
            .list_diagnostics(Some(&fixture.instance))
            .expect("diagnostics")
            .len(),
        usize::from(status == "failed")
    );
    assert!(store
        .settle_local_effect(completion, fixture.diagnostic(), fixture.fact())
        .is_err());
    let refused = store
        .chain_prefix(&fixture.instance)
        .expect("refused prefix");
    assert!(store
        .settle_local_effect(completion, fixture.diagnostic(), fixture.fact())
        .is_err());
    assert_eq!(
        store
            .chain_prefix(&fixture.instance)
            .expect("deduplicated refusal"),
        refused
    );
    store
        .rebuild_projections(&fixture.instance)
        .expect("rebuild");
    assert_eq!(
        store.list_facts(&fixture.instance).expect("rebuilt facts")[0].value_json,
        facts[0].value_json
    );
    assert_eq!(
        store.list_runs(&fixture.instance).expect("rebuilt run")[0].status,
        status
    );
    store
        .commit_rule(crate::RuleCommit {
            instance_id: &fixture.instance,
            rule: "consume-recording",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &["settle-fact"],
            effects: &[],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("consume-recording"),
            marks: &[],
            context_json: None,
        })
        .expect("consume continuation");
    store
        .rebuild_projections(&fixture.instance)
        .expect("rebuild consumed state");
    assert!(store
        .list_facts(&fixture.instance)
        .expect("consumed facts")
        .is_empty());
    assert!(store
        .settle_local_effect(completion, fixture.diagnostic(), fixture.fact())
        .is_err());
    assert!(store
        .list_facts(&fixture.instance)
        .expect("no resurrected fact")
        .is_empty());
}

pub fn refuse_foreign_profile(store: &mut impl RuntimeStore, case: &str) {
    let target = match case {
        "missing-target" => None,
        "foreign-target" => Some("vcs.promote"),
        _ => Some(RESOLUTION_RECORDING_CAPABILITY),
    };
    let provider = if case == "foreign-provider" {
        "other-provider"
    } else {
        RESOLUTION_RECORDING_PROVIDER
    };
    let fixture = conformance::setup_recording(store, "completed", provider, target);
    let completion = EffectCompletion {
        provider: RESOLUTION_RECORDING_PROVIDER,
        ..fixture.completion()
    };
    let error = store
        .settle_local_effect(completion, None, fixture.fact())
        .expect_err("a different recorded target or provider cannot claim recording settlement");
    assert!(
        matches!(error, StoreError::Conflict(ref detail)
        if detail == "local settlement differs from the recorded target or run provider"),
        "{case}: {error:?}"
    );
    assert_eq!(
        store.list_runs(&fixture.instance).expect("unsettled run")[0].status,
        "running"
    );
    assert!(store
        .list_facts(&fixture.instance)
        .expect("no continuation")
        .is_empty());
    assert!(!store
        .list_events(&fixture.instance)
        .expect("refusal history")
        .iter()
        .any(|event| matches!(
            event.event_type.as_str(),
            "effect.terminal" | "fact.derived"
        )));
}
