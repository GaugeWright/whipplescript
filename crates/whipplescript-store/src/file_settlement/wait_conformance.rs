//! The local wait transaction, exercised unchanged on native and DO storage.
//! This fixture qualifies storage composition, not authority or closure readiness.
use super::*;
use crate::{log_append::LogAppend, RuntimeStore};

pub fn run_suite(store: &mut (impl RuntimeStore + LogAppend), status: &str) {
    let fixture = tracker_conformance::setup_wait_queued(store, status);
    let expected = store
        .claimable_effects(&fixture.instance)
        .expect("queued effect")[0]
        .clone();
    let metadata = tracker_conformance::wait_metadata(&fixture);
    let completion = EffectCompletion {
        metadata_json: &metadata,
        ..fixture.completion()
    };
    let before = store.chain_prefix(&fixture.instance).expect("before wait");
    for case in [
        "kind", "target", "provider", "instance", "effect", "run", "worker",
    ] {
        let mut altered = expected.clone();
        let mut run = fixture.run();
        match case {
            "kind" => altered.kind = "file.read".into(),
            "target" => altered.target = Some("another.capability".into()),
            "provider" => run.provider = "files",
            "instance" => run.instance_id = "another-instance",
            "effect" => run.effect_id = "another-effect",
            "run" => run.run_id = "another-run",
            "worker" => run.worker_id = "another-worker",
            _ => unreachable!(),
        }
        let error = store
            .settle_tracker_wait(
                run,
                &altered,
                TrackerWaitSettlement {
                    completion,
                    diagnostic: fixture.diagnostic(),
                    fact: fixture.fact(),
                },
            )
            .expect_err("foreign wait dispatch must refuse");
        assert!(
            matches!(error, StoreError::Conflict(ref reason) if reason == "atomic tracker wait does not bind its dispatch"),
            "{case}: {error:?}"
        );
        assert_eq!(
            store.chain_prefix(&fixture.instance).expect("refused wait"),
            before
        );
    }
    let mut stale = expected.clone();
    stale.input_json = "{\"changed\":true}".into();
    assert!(store
        .settle_tracker_wait(
            fixture.run(),
            &stale,
            TrackerWaitSettlement {
                completion,
                diagnostic: fixture.diagnostic(),
                fact: fixture.fact(),
            }
        )
        .is_err());
    assert_eq!(
        store.chain_prefix(&fixture.instance).expect("stale wait"),
        before
    );
    let terminal = store
        .settle_tracker_wait(
            fixture.run(),
            &expected,
            TrackerWaitSettlement {
                completion,
                diagnostic: fixture.diagnostic(),
                fact: fixture.fact(),
            },
        )
        .expect("atomic local wait");
    let prefix = store
        .chain_prefix(&fixture.instance)
        .expect("committed wait");
    let start = prefix
        .iter()
        .find(|event| event.event_type == "effect.run_started")
        .expect("start");
    let fact = prefix
        .iter()
        .find(|event| event.idempotency_key.as_deref() == Some("settle-fact-event"))
        .expect("fact");
    assert_eq!(terminal.sequence, start.sequence + 1);
    assert_eq!(fact.sequence, terminal.sequence + 1);
    assert_eq!(
        fact.causation_id.as_deref(),
        Some(terminal.event_id.as_str())
    );
    assert_eq!(
        store.list_runs(&fixture.instance).expect("runs")[0].status,
        status
    );
    let facts = store.list_facts(&fixture.instance).expect("facts");
    assert_eq!(facts.len(), 1);
    assert_eq!(facts[0].name, fixture.name);
    assert_eq!(facts[0].value_json, fixture.value);
    store
        .rebuild_projections(&fixture.instance)
        .expect("rebuild wait");
    assert_eq!(
        store.list_facts(&fixture.instance).expect("replayed facts"),
        facts
    );
    assert!(store
        .settle_tracker_wait(
            fixture.run(),
            &expected,
            TrackerWaitSettlement {
                completion,
                diagnostic: fixture.diagnostic(),
                fact: fixture.fact(),
            }
        )
        .is_err());
    assert_eq!(
        store
            .chain_prefix(&fixture.instance)
            .expect("no redelivery"),
        prefix
    );
    assert_eq!(
        store.list_runs(&fixture.instance).expect("one run").len(),
        1
    );
}

/// Readiness does not override cancellation or a paused/cancelled instance.
pub fn refuse_stopped(store: &mut (impl RuntimeStore + LogAppend), state: &str) {
    let fixture = tracker_conformance::setup_wait_queued(store, "completed");
    let expected = store
        .claimable_effects(&fixture.instance)
        .expect("queued wait")[0]
        .clone();
    if state == "effect-cancelled" {
        store
            .cancel_effect(crate::EffectCancellation {
                instance_id: &fixture.instance,
                effect_id: "settle-effect",
                reason: Some("cancelled after observation"),
                idempotency_key: Some("cancel-wait"),
            })
            .expect("cancel wait");
    } else {
        store
            .transition_instance(crate::InstanceTransition {
                instance_id: &fixture.instance,
                status: state,
                reason: Some("stopped after observation"),
                idempotency_key: Some("stop-wait"),
            })
            .expect("stop workflow");
    }
    let before = store
        .chain_prefix(&fixture.instance)
        .expect("stopped history");
    let metadata = tracker_conformance::wait_metadata(&fixture);
    assert!(store
        .settle_tracker_wait(
            fixture.run(),
            &expected,
            TrackerWaitSettlement {
                completion: EffectCompletion {
                    metadata_json: &metadata,
                    ..fixture.completion()
                },
                diagnostic: None,
                fact: fixture.fact(),
            }
        )
        .is_err());
    assert_eq!(
        store
            .chain_prefix(&fixture.instance)
            .expect("refused history"),
        before
    );
    assert!(store
        .list_runs(&fixture.instance)
        .expect("no run")
        .is_empty());
    assert!(store
        .list_facts(&fixture.instance)
        .expect("no continuation")
        .is_empty());
}
