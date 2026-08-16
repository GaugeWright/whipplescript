//! Trace reconstruction from store events, conformance checks, and log/JSON rendering.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn reconstructs_trace_records_from_store_events() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [
                    {"effect_id": "prepare", "status": "queued"},
                    {"effect_id": "send", "status": "queued"}
                ],
                "dependencies": [
                    {
                        "dependency_id": "dep_1",
                        "upstream_effect_id": "prepare",
                        "downstream_effect_id": "send",
                        "predicate": "succeeds"
                    }
                ]
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "prepare", "run_id": "run_prepare"}),
        ),
        event_view(
            3,
            "effect.terminal",
            json!({
                "effect_id": "prepare",
                "run_id": "run_prepare",
                "status": "completed"
            }),
        ),
        event_view(
            4,
            "effect.run_started",
            json!({"effect_id": "send", "run_id": "run_send"}),
        ),
        event_view(
            5,
            "effect.terminal",
            json!({
                "effect_id": "send",
                "run_id": "run_send",
                "status": "completed"
            }),
        ),
    ];

    let records = reconstruct_trace_records(&events);

    assert_eq!(records.len(), 9);
    check_trace(&records).expect("reconstructed trace conforms");
    check_local_trace(&events, &records).expect("local trace conforms");
}

#[test]
fn reconstructs_and_conforms_capacity_block_then_claim() {
    // A capacity-contended effect: blocked, then claimed straight from blocked.
    // This is the store-event shape `whip trace --check` reconstructs for a
    // `capacity 1` agent's second turn; it must conform.
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "turn", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            2,
            "effect.blocked",
            json!({
                "effect_id": "turn",
                "status": "blocked_by_capacity",
                "reason": "agent capacity exhausted"
            }),
        ),
        event_view(
            3,
            "effect.run_started",
            json!({"effect_id": "turn", "run_id": "run_turn"}),
        ),
        event_view(
            4,
            "effect.terminal",
            json!({"effect_id": "turn", "run_id": "run_turn", "status": "completed"}),
        ),
    ];

    let records = reconstruct_trace_records(&events);
    check_trace(&records).expect("capacity-block-then-claim trace conforms");
    check_local_trace(&events, &records).expect("local trace conforms");
}

#[test]
fn reconstructs_and_conforms_retry_then_reclaim() {
    // A failed effect re-queued by `whip retry` (effect.retried) and re-run under
    // a fresh run id. This is the store-event shape `whip trace --check`
    // reconstructs after an operator retry; it must conform.
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "turn", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "turn", "run_id": "run_turn_1"}),
        ),
        event_view(
            3,
            "effect.terminal",
            json!({"effect_id": "turn", "run_id": "run_turn_1", "status": "failed"}),
        ),
        event_view(4, "effect.retried", json!({"effect_id": "turn"})),
        event_view(
            5,
            "effect.run_started",
            json!({"effect_id": "turn", "run_id": "run_turn_2"}),
        ),
        event_view(
            6,
            "effect.terminal",
            json!({"effect_id": "turn", "run_id": "run_turn_2", "status": "completed"}),
        ),
    ];

    let records = reconstruct_trace_records(&events);
    check_trace(&records).expect("retry-then-reclaim trace conforms");
    check_local_trace(&events, &records).expect("local trace conforms");
}

#[test]
fn local_trace_conformance_rejects_store_event_sequence_gap() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "prepare", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            3,
            "effect.run_started",
            json!({"effect_id": "prepare", "run_id": "run_prepare"}),
        ),
    ];
    let records = reconstruct_trace_records(&events);

    check_trace(&records).expect("abstract trace alone masks raw event sequence gaps");
    let violation = check_local_trace(&events, &records).expect_err("store event gap should fail");

    assert_eq!(violation.sequence, 3);
    assert!(violation.message.contains("store event sequence gap"));
}

#[test]
fn local_trace_conformance_rejects_reconstructed_bad_dependency_block() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [
                    {"effect_id": "prepare", "status": "queued"},
                    {"effect_id": "send", "status": "queued"}
                ],
                "dependencies": [
                    {
                        "dependency_id": "dep_1",
                        "upstream_effect_id": "prepare",
                        "downstream_effect_id": "send",
                        "predicate": "fails"
                    }
                ]
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "prepare", "run_id": "run_prepare"}),
        ),
        event_view(
            3,
            "effect.terminal",
            json!({
                "effect_id": "prepare",
                "run_id": "run_prepare",
                "status": "failed"
            }),
        ),
        event_view(
            4,
            "effect.blocked",
            json!({
                "effect_id": "send",
                "status": "blocked_by_dependency",
                "reason": "effect dependencies are not satisfied"
            }),
        ),
    ];
    let records = reconstruct_trace_records(&events);

    let violation = check_local_trace(&events, &records)
        .expect_err("satisfied failure dependency block should fail");

    assert_eq!(violation.sequence, 7);
    assert!(violation
        .message
        .contains("without an unsatisfied dependency"));
}

#[test]
fn reconstructs_revision_trace_records_from_store_events() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "running", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "running", "run_id": "run_running"}),
        ),
        event_view(
            3,
            "workflow.revision_activated",
            json!({
                "revision_id": "rev_1",
                "instance_id": "ins_1",
                "from_version_id": "ver_old",
                "to_version_id": "ver_new",
                "from_epoch": 0,
                "to_epoch": 1,
                "activation_policy": {},
                "cancellation_policy": "request_running",
                "terminal_cancel_effects": [],
                "request_cancel_effects": ["running"]
            }),
        ),
        event_view(
            4,
            "effect.cancellation_requested",
            json!({
                "request_id": "ecr_1",
                "effect_id": "running",
                "revision_id": "rev_1",
                "reason": "workflow revision",
                "requested_by": "workflow.revision"
            }),
        ),
        event_view(
            5,
            "effect.terminal",
            json!({
                "effect_id": "running",
                "run_id": "run_running",
                "status": "completed"
            }),
        ),
    ];

    let records = reconstruct_trace_records(&events);

    assert_eq!(records.len(), 6);
    check_trace(&records).expect("revision trace conforms");
    match &records[3].event {
        TraceEvent::RevisionActivated {
            revision_id,
            to_epoch,
            request_cancel_effects,
            ..
        } => {
            assert_eq!(revision_id, "rev_1");
            assert_eq!(*to_epoch, 1);
            assert_eq!(request_cancel_effects, &vec!["running".to_owned()]);
        }
        event => panic!("expected revision activation record, got {event:?}"),
    }

    let rendered = trace_record_to_json(&records[4]);
    let event = rendered.get("event").expect("event");
    assert_eq!(
        event.get("type").and_then(Value::as_str),
        Some("effect_cancellation_requested")
    );
    assert_eq!(
        event.get("requested_by").and_then(Value::as_str),
        Some("workflow.revision")
    );
}

#[test]
fn renders_revision_log_event_details() {
    let event = event_view(
        1,
        "workflow.revision_activated",
        json!({
            "revision_id": "rev_1",
            "from_version_id": "ver_old",
            "to_version_id": "ver_new",
            "from_epoch": 0,
            "to_epoch": 1,
            "cancellation_policy": "request_running",
            "terminal_cancel_effects": ["queued"],
            "request_cancel_effects": ["running"]
        }),
    );

    assert_eq!(
            log_event_details(&event).as_deref(),
            Some(
                "revision=rev_1 epoch=0->1 from=ver_old to=ver_new cancel=request_running terminal_cancel=1 request_cancel=1"
            )
        );
}

#[test]
fn renders_cancellation_request_log_event_details() {
    let event = event_view(
        2,
        "effect.cancellation_requested",
        json!({
            "request_id": "ecr_1",
            "effect_id": "running",
            "revision_id": "rev_1",
            "reason": "workflow revision",
            "requested_by": "workflow.revision"
        }),
    );

    assert_eq!(
        log_event_details(&event).as_deref(),
        Some("effect=running revision=rev_1 by=workflow.revision reason=workflow revision")
    );
}

#[test]
fn renders_run_cancellation_request_json() {
    let run = RunView {
        run_id: "run-1".to_owned(),
        effect_id: "effect-1".to_owned(),
        provider: "fixture".to_owned(),
        worker_id: "worker-1".to_owned(),
        status: "running".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        completed_at: None,
        metadata_json: "{}".to_owned(),
        cancel_requested: true,
    };

    let rendered = run_to_json(&run);
    assert_eq!(
        rendered.get("cancel_requested").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/provider_id")
            .and_then(Value::as_str),
        Some("fixture")
    );
}

#[test]
fn renders_run_provider_selection_metadata_json() {
    let run = RunView {
        run_id: "run-1".to_owned(),
        effect_id: "effect-1".to_owned(),
        provider: "runner".to_owned(),
        worker_id: "worker-1".to_owned(),
        status: "running".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        completed_at: None,
        metadata_json: json!({
            "provider_selection": {
                "provider_id": "runner",
                "provider_kind": "command",
                "source_harness_id": "runner",
                "surface": "command"
            }
        })
        .to_string(),
        cancel_requested: false,
    };

    let rendered = run_to_json(&run);
    assert_eq!(
        rendered
            .pointer("/provider_selection/provider_kind")
            .and_then(Value::as_str),
        Some("command")
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/source_harness_id")
            .and_then(Value::as_str),
        Some("runner")
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/surface")
            .and_then(Value::as_str),
        Some("command")
    );
}

#[test]
fn renders_effect_harness_provider_selection_json() {
    let effect = EffectView {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        input_json: r#"{"prompt":"go"}"#.to_owned(),
        status: "queued".to_owned(),
        created_by_rule: "start".to_owned(),
        program_version_id: Some("version-1".to_owned()),
        revision_epoch: 0,
        profile: Some("repo-writer".to_owned()),
        required_capabilities_json: r#"["agent.tell"]"#.to_owned(),
        declared_profiles_json: json!({
            "harnesses": [{"name": "coder", "kind": "codex"}],
            "agents": [{"name": "implementer", "harness": "coder"}]
        })
        .to_string(),
        policy_block_reason: None,
        policy_block_category: None,
        cancel_requested: false,
    };

    let rendered = effect_to_json(&effect);

    assert_eq!(
        rendered
            .pointer("/provider_selection/source_harness_id")
            .and_then(Value::as_str),
        Some("coder")
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/provider_kind")
            .and_then(Value::as_str),
        Some("codex")
    );
}
