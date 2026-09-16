use super::*;
use crate::source_action::arguments::{Bindings, QueryObservation, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
use std.script
workflow Scripted
output result Report
class Started { input Input }
class Input { name string }
class Report { ok bool text string }
rule finish when Started as started => { complete result { ok true text started.input.name } }
"#;

fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("exec fixture compiles")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "finish".into(),
        identity: Some("started".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn run(
    source: &str,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    run_with_root(source, Some("finish"), bindings, effects, events)
}

fn run_with_root(
    source: &str,
    root_rule: Option<&str>,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    project(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body: &body.statements[0],
            environment: &Environment::from([("input".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir(),
            frame: &frame(),
            frontier: 7,
            effects,
            events,
            source_path: None,
        },
    )
}

fn input() -> Bindings {
    Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            value: json!({"name":"Ada"}),
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: "input-fact".into(),
                admission_event: "admitted".into(),
            }]),
            subjects: Default::default(),
            validity: BTreeSet::from([QueryObservation {
                frontier: 4,
                kind: super::super::arguments::ObservationKind::Fact,
                head: "Started".into(),
                guard_json: None,
                members: Default::default(),
            }]),
        }),
    )])
}

fn ready(leaf: Leaf) -> (Box<OwnedLowering>, Option<Argument>, OwnedWork) {
    let Leaf::Ready {
        lowering,
        value,
        work: Some(work),
    } = leaf
    else {
        panic!("ready exec leaf")
    };
    (lowering, value, work)
}

fn projection_effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "exec.command".into(),
        target: Some("render".into()),
        input_json: input.to_string(),
        status: status.into(),
        created_by_rule: "finish".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        profile: None,
        cancel_requested: false,
    }
}

fn event(kind: &str, sequence: i64, payload: Value) -> EventView {
    EventView {
        event_id: format!("event-{sequence}"),
        sequence,
        event_type: kind.into(),
        payload_json: payload.to_string(),
        source: "kernel".into(),
        occurred_at: "2026-09-13T00:00:00Z".into(),
    }
}

fn result_event(name: &str, sequence: i64, value: Value) -> EventView {
    event(
        "fact.derived",
        sequence,
        json!({
            "fact_id": format!("fact-{name}"),
            "name": name,
            "key": "operation",
            "value": value,
            "schema_id": null,
            "provenance_class": "external",
            "correlation_id": null,
            "validity": null,
        }),
    )
}

#[test]
fn managed_exec_waits_then_captures_typed_stdin_and_contract() {
    let Leaf::Waiting(wait) = run(
        "exec render with input -> Report as report",
        &Bindings::new(),
        &[],
        &[],
    )
    .unwrap() else {
        panic!("missing stdin must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(
        run(
            "exec render with input -> Report as report timeout 5s requires [\"audit\"]",
            &input(),
            &[],
            &[],
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Pending);
    assert!(value.is_none());
    let [effect] = lowering.effects.as_slice() else {
        panic!("one exec effect")
    };
    assert_eq!(effect.kind, "exec.command");
    assert_eq!(effect.target.as_deref(), Some("render"));
    assert_eq!(effect.timeout_seconds, Some(5));
    assert_eq!(
        effect.required_capabilities_json,
        r#"["audit","script.render"]"#
    );
    let captured: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(captured["mode"], "capability");
    assert_eq!(captured["stdin"], json!({"name":"Ada"}));
    assert_eq!(captured["stdin_binding"], "input");
    assert_eq!(
        captured["action_argument"]["sources"][0]["fact_id"],
        "input-fact"
    );
    assert_eq!(captured["action_argument"]["validity"][0]["frontier"], 4);
    assert_eq!(captured["parse"]["schema"], "Report");
    assert_eq!(captured["parse"]["each"], false);
    assert_eq!(captured["parse"]["shape"]["class"], "Report");
}

#[test]
fn managed_exec_observes_only_the_exact_typed_result_and_failure() {
    let (draft, _, _) = ready(
        run(
            "exec render with input -> Report as report",
            &input(),
            &[],
            &[],
        )
        .unwrap(),
    );
    let recorded_input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let completed = projection_effect("completed", recorded_input.clone());
    let events = vec![
        event(
            "effect.terminal",
            1,
            json!({"effect_id":"operation","run_id":"run","status":"completed"}),
        ),
        result_event(
            "exec.command.completed",
            2,
            json!({
                "effect_id":"operation", "run_id":"run", "status":"completed",
                "mode":"capability", "capability":"render",
                "value":{"ok":true,"text":"rendered"}
            }),
        ),
    ];
    let (_, value, work) = ready(
        run(
            "exec render with input -> Report as report",
            &Bindings::new(),
            std::slice::from_ref(&completed),
            &events,
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(value.unwrap().value, json!({"ok":true,"text":"rendered"}));

    let mut wrong = events.clone();
    wrong[1].payload_json = json!({
        "fact_id":"wrong", "name":"exec.command.completed", "key":"operation",
        "value": {
        "effect_id":"operation", "run_id":"run", "status":"completed",
        "mode":"capability", "capability":"other",
        "value":{"ok":true,"text":"rendered"}
        }
    })
    .to_string();
    assert!(run(
        "exec render with input -> Report as report",
        &Bindings::new(),
        &[completed],
        &wrong,
    )
    .unwrap_err()
    .contains("source contract"));

    let failed = projection_effect("failed", recorded_input);
    let failure = json!({
        "error_kind":"exec_failed", "message":"exit 2", "summary":"exit 2",
        "effect_id":"operation", "run_id":"run"
    });
    let (_, value, work) = ready(
        run(
            "exec render with input -> Report as report",
            &Bindings::new(),
            &[failed],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"failed"}),
                ),
                result_event(
                    "exec.command.failed",
                    2,
                    json!({
                        "effect_id":"operation", "run_id":"run", "status":"failed",
                        "mode":"capability", "capability":"render", "value":failure
                    }),
                ),
            ],
        )
        .unwrap(),
    );
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Failed(Disposition::Propagate));
    assert_eq!(
        work.causes[&CauseId("operation".into())].cause.payload,
        failure
    );
}

#[test]
fn managed_exec_refuses_unmanaged_forms_and_tampered_replay() {
    for source in [
        "exec \"echo hi\" -> Report as report",
        "exec render with input -> each Report",
    ] {
        assert!(run(source, &input(), &[], &[])
            .unwrap_err()
            .contains("managed exec"));
    }
    let (draft, _, _) = ready(
        run(
            "exec render with input -> Report as report",
            &input(),
            &[],
            &[],
        )
        .unwrap(),
    );
    let original: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut incomplete = original.clone();
    incomplete["action_argument"]
        .as_object_mut()
        .unwrap()
        .remove("validity");
    assert!(run(
        "exec render with input -> Report as report",
        &Bindings::new(),
        &[projection_effect("queued", incomplete)],
        &[],
    )
    .unwrap_err()
    .contains("incomplete freshness"));

    let mut recorded = original;
    recorded["parse"]["schema"] = json!("Other");
    assert!(run(
        "exec render with input -> Report as report",
        &Bindings::new(),
        &[projection_effect("queued", recorded)],
        &[],
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_exec_refusal_boundaries_are_all_observable() {
    let source = "exec render with input -> Report as report";
    assert!(run("return input", &input(), &[], &[])
        .unwrap_err()
        .contains("requires an effect statement"));
    assert!(run_with_root(source, None, &input(), &[], &[])
        .unwrap_err()
        .contains("pinned root rule"));

    let (draft, _, _) = ready(run(source, &input(), &[], &[]).unwrap());
    let recorded_input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_effect = projection_effect("queued", recorded_input.clone());
    wrong_effect.kind = "other".into();
    assert!(run(source, &Bindings::new(), &[wrong_effect], &[])
        .unwrap_err()
        .contains("source operation"));

    let unknown = projection_effect("mystery", recorded_input.clone());
    assert!(run(source, &Bindings::new(), &[unknown], &[])
        .unwrap_err()
        .contains("unknown operation status"));

    let completed = projection_effect("completed", recorded_input.clone());
    assert!(run(
        source,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[],
    )
    .unwrap_err()
    .contains("exactly one terminal"));

    let wrong_terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"failed"}),
    );
    assert!(run(
        source,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        &[wrong_terminal],
    )
    .unwrap_err()
    .contains("recorded status"));

    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run(
        source,
        &Bindings::new(),
        std::slice::from_ref(&completed),
        std::slice::from_ref(&terminal),
    )
    .unwrap_err()
    .contains("exactly one result"));

    let invalid = result_event(
        "exec.command.completed",
        2,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "mode":"capability", "capability":"render",
            "value":{"ok":"not-bool","text":"rendered"}
        }),
    );
    assert!(run(
        source,
        &Bindings::new(),
        &[projection_effect("completed", recorded_input)],
        &[terminal, invalid],
    )
    .unwrap_err()
    .contains("violates its output type"));
}
