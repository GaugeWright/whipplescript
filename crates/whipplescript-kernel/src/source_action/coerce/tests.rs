use super::*;
use crate::source_action::arguments::{Bindings, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
workflow CoerceValues
output result Done
class Done { ok bool }
class Answer { text string }
file store fs { root "./workspace" allow read ["**/*.md"] }
coerce classify(first string, second string?) -> Answer {
  prompt "{{ first }} {{ second }} {{ ctx.output_format }}"
}
coerce photograph(photo image?) -> Answer {
  prompt "{{ photo }} {{ ctx.output_format }}"
}
rule finish when started => { complete result { ok true } }
"#;
fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SOURCE);
    compiled.ir.expect("coerce declaration fixture compiles")
}
fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "finish".into(),
        identity: Some("ticket".into()),
        trigger_event: Some("admitted".into()),
    }
}
fn slots(a: Slot, b: Slot) -> Bindings {
    BTreeMap::from([(BindingId(0), a), (BindingId(1), b)])
}
fn ready(value: Value) -> Slot {
    Slot::Ready(value.into())
}
fn run(
    ir: &IrProgram,
    source: &str,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
    config: &str,
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    project(
        Statement {
            node: NodeId(0),
            root_rule: Some("finish"),
            admitted: bindings,
            identity: "operation".into(),
            body: &body.statements[0],
            environment: &Environment::from([
                ("a".into(), BindingId(0)),
                ("b".into(), BindingId(1)),
            ]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir,
            frame: &frame(),
            effects,
            events,
            coercion_config_fingerprint: config,
            source_path: None,
        },
    )
}
fn parts(leaf: Leaf) -> (Box<OwnedLowering>, Option<Argument>, OwnedWork) {
    let Leaf::Ready {
        lowering,
        value,
        work: Some(work),
    } = leaf
    else {
        panic!("ready leaf");
    };
    (lowering, value, work)
}
fn effect(status: &str) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(), kind: "schema.coerce".into(), target: None,
        input_json: json!({"function_name":"classify","output_type":"Answer","arguments":{"arg0":"captured","arg1":null}}).to_string(),
        status: status.into(), created_by_rule: "finish".into(), program_version_id: Some("v".into()), revision_epoch: 0,
        profile: None, cancel_requested: false,
    }
}
fn event(kind: &str, sequence: i64, payload: Value) -> EventView {
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: kind.into(),
        payload_json: payload.to_string(),
        source: "kernel".into(),
        occurred_at: "2026-09-09T00:00:00Z".into(),
    }
}
fn result_events(status: &str, value: Value) -> Vec<EventView> {
    vec![
        event(
            "effect.terminal",
            1,
            json!({"effect_id":"operation","run_id":"run","status":status,"metadata":{"value":{"redacted":true}}}),
        ),
        event(
            match status {
                "completed" => "schema.coerce.succeeded",
                "timed_out" => "schema.coerce.timed_out",
                _ => "schema.coerce.failed",
            },
            2,
            json!({"effect_id":"operation","run_id":"run","status":status,"function_name":"classify","output_type":"Answer","value":value}),
        ),
    ]
}
fn observe(status: &str, events: &[EventView]) -> Result<Leaf, String> {
    run(
        &ir(),
        "coerce classify(a, b) as answer",
        &Bindings::new(),
        &[effect(status)],
        events,
        "fixture",
    )
}

#[test]
fn managed_coerce_arguments_wait_strictly_and_preserve_captured_sources() {
    let ir = ir();
    let source = "coerce classify(a, b) as answer";
    let pending = slots(
        Slot::Pending,
        Slot::Failed(BTreeSet::from([CauseId("original".into())])),
    );
    let Leaf::Waiting(wait) = run(&ir, source, &pending, &[], &[], "fixture").unwrap() else {
        panic!("must wait");
    };
    assert!(
        matches!(wait.state, State::Blocked { waiting, causes } if waiting == BTreeSet::from([BindingId(0)]) && causes == BTreeSet::from([CauseId("original".into())]))
    );
    let bindings = slots(
        Slot::Ready(Argument {
            value: json!("captured"),
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: "input".into(),
                admission_event: "admission".into(),
            }]),
            subjects: Default::default(),
            validity: Default::default(),
        }),
        ready(Value::Null),
    );
    let (draft, value, work) = parts(run(&ir, source, &bindings, &[], &[], "fixture").unwrap());
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    assert_eq!(draft.effects.len(), 1);
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert_eq!(input["arguments"], json!({"arg0":"captured","arg1":null}));
    assert!(input.get("argument_exprs").is_none());
    assert!(input.get("after").is_none());
    assert_eq!(
        input["action_arguments"][0]["sources"][0]["fact_id"],
        "input"
    );
    assert_eq!(
        draft.effects[0].required_capabilities_json,
        r#"["schema.coerce"]"#
    );
    assert!(draft.effects[0].source_span_json.is_some());
    let (other, _, _) = parts(run(&ir, source, &bindings, &[], &[], "other-model").unwrap());
    assert_ne!(
        draft.effects[0].idempotency_key,
        other.effects[0].idempotency_key
    );
    let changed = slots(ready(json!("changed")), ready(Value::Null));
    let (same, _, _) = parts(run(&ir, source, &changed, &[], &[], "fixture").unwrap());
    assert_eq!(
        draft.effects[0].idempotency_key,
        same.effects[0].idempotency_key
    );
    let Leaf::Waiting(bad) = run(
        &ir,
        source,
        &slots(ready(json!(42)), ready(Value::Null)),
        &[],
        &[],
        "fixture",
    )
    .unwrap() else {
        panic!("invalid argument");
    };
    assert!(matches!(bad.state, State::Invalid(_)));
    let (image, _, _) = parts(
        run(
            &ir,
            "coerce photograph(a) as answer",
            &slots(
                ready(json!("data:image/png;base64,YQ==")),
                ready(Value::Null),
            ),
            &[],
            &[],
            "fixture",
        )
        .unwrap(),
    );
    let input: Value = serde_json::from_str(&image.effects[0].input_json).unwrap();
    assert_eq!(input["media"][0]["data_base64"], "YQ==");
    assert_eq!(input["media"][0]["media_type"], "image/png");
}

#[test]
fn managed_coerce_observes_actual_value_and_all_failure_evidence() {
    let events = result_events("completed", json!({"text":"actual"}));
    let (draft, value, work) = parts(observe("completed", &events).unwrap());
    assert!(draft.effects.is_empty());
    assert_eq!(value.unwrap().value, json!({"text":"actual"}));
    assert_eq!(work.state, WorkState::Succeeded);
    for status in ["failed", "timed_out"] {
        let events = result_events(status, json!({"reason":"safe cause"}));
        let (_, value, work) = parts(observe(status, &events).unwrap());
        assert!(value.is_none());
        assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
        let cause = &work.causes[&CauseId("operation".into())].cause;
        assert_eq!(cause.payload, json!({"reason":"safe cause"}));
        assert_eq!(
            cause.evidence,
            BTreeSet::from(["event-1".into(), "event-2".into()])
        );
    }
    let (_, value, work) = parts(observe("queued", &events).unwrap());
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    let uncertain = vec![event(
        "effect.terminal",
        3,
        json!({"effect_id":"operation","status":"failed","run_status":"uncertain"}),
    )];
    assert_eq!(
        parts(observe("failed", &uncertain).unwrap()).2.state,
        WorkState::Uncertain
    );
    let cancelled = vec![event(
        "effect.cancelled",
        3,
        json!({"effect_id":"operation"}),
    )];
    assert_eq!(
        parts(observe("cancelled", &cancelled).unwrap()).2.causes[&CauseId("operation".into())]
            .cause
            .kind,
        FailureKind::Cancelled
    );
}

#[test]
fn managed_coerce_refuses_malformed_or_rebound_settlement() {
    for changed in [
        "status",
        "missing-terminal",
        "missing-run",
        "missing-result",
        "duplicate-result",
        "wrong-run",
        "result-status",
        "result-kind",
        "result-before-terminal",
        "function",
        "schema",
        "missing-value",
        "bad-output",
        "unreadable-terminal",
        "unreadable-result",
    ] {
        let mut events = result_events("completed", json!({"text":"actual"}));
        let mut terminal: Value = serde_json::from_str(&events[0].payload_json).unwrap();
        let mut result: Value = serde_json::from_str(&events[1].payload_json).unwrap();
        match changed {
            "status" => terminal["status"] = "failed".into(),
            "missing-run" => {
                terminal.as_object_mut().unwrap().remove("run_id");
            }
            "wrong-run" => result["run_id"] = "old-run".into(),
            "result-status" => result["status"] = "failed".into(),
            "function" => result["function_name"] = "other".into(),
            "schema" => result["output_type"] = "Other".into(),
            "missing-value" => {
                result.as_object_mut().unwrap().remove("value");
            }
            "bad-output" => result["value"] = json!({"text":42}),
            _ => {}
        }
        events[0].payload_json = terminal.to_string();
        events[1].payload_json = result.to_string();
        match changed {
            "missing-terminal" => {
                events.remove(0);
            }
            "missing-result" => {
                events.pop();
            }
            "duplicate-result" => events.push(events[1].clone()),
            "result-kind" => events[1].event_type = "schema.coerce.failed".into(),
            "result-before-terminal" => events[1].sequence = 0,
            "unreadable-terminal" => events[0].payload_json = "{".into(),
            "unreadable-result" => events[1].payload_json = "{".into(),
            _ => {}
        }
        assert!(observe("completed", &events).is_err(), "{changed}");
    }
    assert!(observe("mysterious", &[]).is_err());
}

#[test]
fn managed_coerce_refuses_wrong_source_and_recorded_identity() {
    for source in [
        "return null",
        "timer 1s as t",
        "coerce missing(a, b) as answer",
        "coerce classify(a) as answer",
    ] {
        assert!(
            run(&ir(), source, &Bindings::new(), &[], &[], "fixture").is_err(),
            "{source}"
        );
    }
    let mut no_root = ir();
    no_root.rules.clear();
    assert!(run(
        &no_root,
        "coerce classify(a,b) as answer",
        &Bindings::new(),
        &[],
        &[],
        "fixture"
    )
    .is_err());
    for change in ["kind", "rule", "version", "input", "function", "output"] {
        let mut row = effect("queued");
        match change {
            "kind" => row.kind = "timer.wait".into(),
            "rule" => row.created_by_rule = "other".into(),
            "version" => row.program_version_id = Some("other".into()),
            "input" => row.input_json = "{".into(),
            "function" => {
                row.input_json = r#"{"function_name":"other","output_type":"Answer"}"#.into()
            }
            "output" => {
                row.input_json = r#"{"function_name":"classify","output_type":"Other"}"#.into()
            }
            _ => unreachable!(),
        }
        assert!(
            run(
                &ir(),
                "coerce classify(a,b) as answer",
                &Bindings::new(),
                &[row],
                &[],
                "fixture"
            )
            .is_err(),
            "{change}"
        );
    }
}

#[test]
fn managed_coerce_keeps_optional_media_absent_and_preserves_grant_policy() {
    let ir = ir();
    let bindings = slots(ready(Value::Null), ready(Value::Null));
    let (draft, _, _) = parts(
        run(
            &ir,
            "coerce photograph(a) as answer",
            &bindings,
            &[],
            &[],
            "fixture",
        )
        .unwrap(),
    );
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert_eq!(input["arguments"]["arg0"], Value::Null);
    assert_eq!(input["media"], json!([]));
    let bindings = slots(ready(json!("hello")), ready(Value::Null));
    let (draft, _, _) = parts(
        run(
            &ir,
            "coerce classify(a, b) with access to fs { read } as answer",
            &bindings,
            &[],
            &[],
            "fixture",
        )
        .unwrap(),
    );
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert_eq!(input["access_grants"][0]["resource"], "fs");
    assert_eq!(
        input["access_grants"][0]["operations"][0]["operation"],
        "read"
    );
    assert_eq!(
        input["access_grants"][0]["store_policy"],
        json!({"root":"./workspace","allow_read":["**/*.md"],"allow_write":[]})
    );
}
