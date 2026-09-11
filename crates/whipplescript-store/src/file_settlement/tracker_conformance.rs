//! Tracker terminal/continuation storage checks shared by native and DO SQLite.
//! These checks grant no authority to file a task or recover a target receipt.
use super::*;
use crate::{log_append::LogAppend, NewEvent, RuntimeStore};
use serde_json::{json, Value};

pub fn run_suite(store: &mut (impl RuntimeStore + LogAppend), status: &str) {
    let mut fixture = conformance::setup_profile(
        store,
        "tracker.file",
        status,
        TRACKER_PROVIDER,
        Some("tutorials"),
    );
    let outcome = if status == "completed" {
        json!({"queue": "tutorials", "id": "WS-1", "title": "Create a chat"})
    } else {
        json!({"reason": "tracker filing did not settle successfully"})
    };
    fixture.value = json!({"effect_id": "settle-effect", "run_id": "settle-run",
        "status": status, "value": outcome})
    .to_string();
    run_fixture(store, fixture);
}

pub fn setup_wait(store: &mut impl RuntimeStore, status: &str) -> conformance::Fixture {
    let fixture = conformance::setup_profile(
        store,
        "capability.call",
        status,
        TRACKER_WAIT_PROVIDER,
        Some(TRACKER_WAIT_CAPABILITY),
    );
    configure_wait(fixture, status)
}

pub fn setup_wait_queued(store: &mut impl RuntimeStore, status: &str) -> conformance::Fixture {
    let fixture = conformance::setup_profile_queued(
        store,
        "capability.call",
        status,
        TRACKER_WAIT_PROVIDER,
        Some(TRACKER_WAIT_CAPABILITY),
    );
    configure_wait(fixture, status)
}

fn configure_wait(mut fixture: conformance::Fixture, status: &str) -> conformance::Fixture {
    let suffix = if status == "completed" {
        "succeeded"
    } else {
        "failed"
    };
    fixture.name = format!("capability.call.{suffix}");
    let outcome = if status == "completed" {
        json!({"id": "WS-1", "queue": "tutorials", "event": "closing-1", "closed_at": "2026-09-10T00:00:00Z"})
    } else {
        json!({"reason": "tracker.wait_closed requires nonempty id and queue"})
    };
    fixture.value = json!({"effect_id": "settle-effect", "run_id": "settle-run",
        "status": status, "value": outcome})
    .to_string();
    fixture
}

pub fn wait_metadata(fixture: &conformance::Fixture) -> String {
    let fact: Value = serde_json::from_str(&fixture.value).expect("wait fact");
    json!({"value": fact["value"], "failure": {"message": "failed"}}).to_string()
}

pub fn run_wait_suite(store: &mut (impl RuntimeStore + LogAppend), status: &str) {
    let fixture = setup_wait(store, status);
    run_fixture(store, fixture);
}

fn run_fixture(store: &mut (impl RuntimeStore + LogAppend), fixture: conformance::Fixture) {
    let status = fixture.status.as_str();
    let metadata = wait_metadata(&fixture);
    let completion = EffectCompletion {
        metadata_json: &metadata,
        ..fixture.completion()
    };
    let mut initial = store
        .list_events(&fixture.instance)
        .expect("initial events");
    let foreign_kind = if fixture.name.starts_with("tracker.finish.") {
        "tracker.file"
    } else {
        "tracker.finish"
    };
    let foreign_name = format!("{foreign_kind}.{status}");
    for change in [
        "provider",
        "kind",
        "status",
        "value",
        "missing-value",
        "suffix",
    ] {
        let mut terminal = completion;
        let mut fact = fixture.fact();
        let mut value: Value = serde_json::from_str(&fixture.value).expect("fact");
        match change {
            "provider" => terminal.provider = "files",
            "kind" => fact.name = &foreign_name,
            "status" => terminal.status = "uncertain",
            "value" => value["value"] = json!({"id": "substituted"}),
            "suffix" => fact.name = "capability.call.completed",
            "missing-value" => {
                value.as_object_mut().expect("object").remove("value");
            }
            _ => unreachable!(),
        }
        let wire = value.to_string();
        fact.value_json = &wire;
        let error = store
            .settle_local_effect(terminal, None, fact)
            .expect_err("invalid tracker settlement");
        if change == "kind" && completion.provider == TRACKER_PROVIDER {
            conformance::assert_refusal_evidence(store, &fixture, &initial, &error);
            initial = store
                .list_events(&fixture.instance)
                .expect("history with refusal");
        } else {
            assert_eq!(
                store.list_events(&fixture.instance).expect("events"),
                initial,
                "{change}"
            );
        }
    }

    // Force failure after the terminal would have been written. Both stores
    // must roll it back instead of leaving a terminal with no continuation.
    store
        .append_event(NewEvent {
            instance_id: &fixture.instance,
            event_type: "fixture.spent",
            payload_json: "{}",
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("spent-continuation"),
        })
        .expect("occupy continuation key");
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
        store.list_runs(&fixture.instance).expect("runs")[0].status,
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
        .expect("settle tracker outcome");
    let prefix = store.chain_prefix(&fixture.instance).expect("prefix");
    let fact = prefix
        .iter()
        .find(|event| event.idempotency_key.as_deref() == Some("settle-fact-event"))
        .expect("continuation event");
    assert_eq!(
        fact.causation_id.as_deref(),
        Some(terminal.event_id.as_str())
    );
    assert_eq!(fact.sequence, terminal.sequence + 1);
    assert_eq!(
        store.list_runs(&fixture.instance).expect("runs")[0].status,
        status
    );
    let facts = store.list_facts(&fixture.instance).expect("facts");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].name, fixture.name);
    assert_eq!(facts[0].value_json, fixture.value);
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
    store
        .rebuild_projections(&fixture.instance)
        .expect("rebuild");
    assert_eq!(
        store.list_runs(&fixture.instance).expect("runs")[0].status,
        status
    );
    assert_eq!(store.list_facts(&fixture.instance).expect("facts"), facts);
}

pub fn refuse_foreign_profile(store: &mut impl RuntimeStore, case: &str) {
    let (kind, provider, target) = match case {
        "kind" => ("tracker.finish", TRACKER_PROVIDER, Some("tutorials")),
        "provider" => ("tracker.file", "files", Some("tutorials")),
        "missing-queue" => ("tracker.file", TRACKER_PROVIDER, None),
        "empty-queue" => ("tracker.file", TRACKER_PROVIDER, Some(" ")),
        _ => unreachable!(),
    };
    let mut fixture = conformance::setup_profile(store, kind, "completed", provider, target);
    // Make the supplied terminal and fact claim the valid profile, while the
    // recorded dispatch still names the incompatible operation above.
    fixture.provider = TRACKER_PROVIDER.into();
    fixture.name = "tracker.file.completed".into();
    assert!(
        store
            .settle_local_effect(fixture.completion(), None, fixture.fact())
            .is_err(),
        "{case}"
    );
    assert_eq!(
        store.list_runs(&fixture.instance).expect("runs")[0].status,
        "running"
    );
    assert!(store
        .list_facts(&fixture.instance)
        .expect("facts")
        .is_empty());
}

/// The supplied outcome cannot turn another dispatched capability into a wait.
pub fn refuse_foreign_wait_profile(store: &mut impl RuntimeStore, case: &str) {
    let (kind, provider, target) = match case {
        "kind" => (
            "file.read",
            TRACKER_WAIT_PROVIDER,
            Some(TRACKER_WAIT_CAPABILITY),
        ),
        "provider" => ("capability.call", "files", Some(TRACKER_WAIT_CAPABILITY)),
        "missing-target" => ("capability.call", TRACKER_WAIT_PROVIDER, None),
        "foreign-target" => (
            "capability.call",
            TRACKER_WAIT_PROVIDER,
            Some("other.observe"),
        ),
        _ => unreachable!(),
    };
    let mut fixture = conformance::setup_profile(store, kind, "completed", provider, target);
    fixture.provider = TRACKER_WAIT_PROVIDER.into();
    fixture.name = "capability.call.succeeded".into();
    let error = store
        .settle_local_effect(fixture.completion(), None, fixture.fact())
        .expect_err("foreign wait profile must refuse");
    assert!(
        matches!(error, crate::StoreError::Conflict(_)),
        "{case}: {error:?}"
    );
    assert_eq!(
        store.list_runs(&fixture.instance).expect("runs")[0].status,
        "running"
    );
    assert!(store
        .list_facts(&fixture.instance)
        .expect("facts")
        .is_empty());
}

/// The ordinary finish lowering has no capability target; its subject is in
/// the resolved input and authenticated dispatch binding.
pub fn setup_closure(store: &mut impl RuntimeStore, status: &str) -> conformance::Fixture {
    let mut fixture =
        conformance::setup_profile(store, "tracker.finish", status, TRACKER_PROVIDER, None);
    let outcome = if status == "completed" {
        json!({"id": "WS-1", "status": "done", "summary": "Self-reported completion"})
    } else {
        json!({"reason": "tracker closure did not settle successfully"})
    };
    fixture.value = json!({"effect_id": "settle-effect", "run_id": "settle-run",
        "status": status, "value": outcome})
    .to_string();
    fixture
}

pub fn run_closure_suite(store: &mut (impl RuntimeStore + LogAppend), status: &str) {
    let fixture = setup_closure(store, status);
    run_fixture(store, fixture);
}

pub fn refuse_foreign_closure_profile(store: &mut impl RuntimeStore, case: &str) {
    let (kind, provider, target, expected) = match case {
        "kind" => (
            "tracker.file",
            TRACKER_PROVIDER,
            Some("tutorials"),
            "file settlement fact differs from the recorded effect kind",
        ),
        "provider" => (
            "tracker.finish",
            "files",
            None,
            "local settlement differs from the recorded target or run provider",
        ),
        "target" => (
            "tracker.finish",
            TRACKER_PROVIDER,
            Some("tutorials"),
            "local settlement differs from the recorded target or run provider",
        ),
        "empty-target" => (
            "tracker.finish",
            TRACKER_PROVIDER,
            Some(""),
            "local settlement differs from the recorded target or run provider",
        ),
        _ => unreachable!(),
    };
    let mut fixture = conformance::setup_profile(store, kind, "completed", provider, target);
    fixture.provider = TRACKER_PROVIDER.into();
    fixture.name = "tracker.finish.completed".into();
    let before = store
        .list_events(&fixture.instance)
        .expect("closure history");
    let error = store
        .settle_local_effect(fixture.completion(), None, fixture.fact())
        .expect_err("foreign closure profile must refuse");
    assert!(
        matches!(error, crate::StoreError::Conflict(ref message) if message == expected),
        "{case}: {error:?}"
    );
    conformance::assert_refusal_evidence(store, &fixture, &before, &error);
    assert_eq!(
        store.list_runs(&fixture.instance).expect("closure runs")[0].status,
        "running"
    );
    assert!(store
        .list_facts(&fixture.instance)
        .expect("closure facts")
        .is_empty());
}
