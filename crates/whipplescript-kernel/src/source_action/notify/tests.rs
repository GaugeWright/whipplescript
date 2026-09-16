use super::*;
use crate::source_action::arguments::{Bindings, QueryObservation, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
workflow Signals
signal task.done { id string note string }
class Ticket { peer string id string note string }
class Answer { text string }
output result Answer
rule finish when started => { complete result { text "done" } }
"#;

const EMIT: &str = "emit signal task.done to ticket.peer from ticket as sent";

fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("signal fixture compiles")
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

fn bindings() -> Bindings {
    Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            value: json!({"peer":"receiver","id":"T-1","note":"ready"}),
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: "ticket-fact".into(),
                admission_event: "ticket-admitted".into(),
            }]),
            subjects: Default::default(),
            validity: BTreeSet::from([QueryObservation {
                frontier: 4,
                kind: super::super::arguments::ObservationKind::Fact,
                head: "Ticket".into(),
                guard_json: None,
                members: Default::default(),
            }]),
        }),
    )])
}

fn run(
    source: &str,
    root_rule: Option<&str>,
    bindings: &Bindings,
    effects: &[ProjectionEffect],
    events: &[EventView],
    mutate: impl FnOnce(BodyStmt) -> BodyStmt,
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    let statement = mutate(body.statements[0].clone());
    project(
        Statement {
            node: NodeId(0),
            root_rule,
            admitted: bindings,
            identity: "operation".into(),
            body: &statement,
            environment: &Environment::from([("ticket".into(), BindingId(0))]),
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

fn ready(leaf: Leaf) -> (Box<OwnedLowering>, Option<Argument>, OwnedWork) {
    let Leaf::Ready {
        lowering,
        value,
        work: Some(work),
    } = leaf
    else {
        panic!("ready signal leaf")
    };
    (lowering, value, work)
}

fn effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "signal.emit".into(),
        target: None,
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
            "name": name,
            "key": "operation",
            "value": value,
        }),
    )
}

#[test]
fn managed_signal_captures_projected_payload_and_freshness() {
    let Leaf::Waiting(wait) = run(EMIT, Some("finish"), &Bindings::new(), &[], &[], |body| {
        body
    })
    .unwrap() else {
        panic!("missing signal input must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(
        run(
            "emit signal task.done to ticket.peer from ticket { note \"sent\" } as sent timeout 5s requires [\"delivery\"]",
            Some("finish"),
            &bindings(),
            &[],
            &[],
            |body| body,
        )
        .unwrap(),
    );
    assert!(value.is_none());
    assert_eq!(work.state, WorkState::Pending);
    let [effect] = lowering.effects.as_slice() else {
        panic!("one signal effect")
    };
    assert_eq!(effect.kind, "signal.emit");
    assert_eq!(effect.timeout_seconds, Some(5));
    assert_eq!(effect.required_capabilities_json, r#"["delivery"]"#);
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["target_instance"], "receiver");
    assert_eq!(input["event"], "task.done");
    assert_eq!(input["payload"], json!({"id":"T-1","note":"sent"}));
    assert_eq!(
        input["target_argument"]["sources"][0]["fact_id"],
        "ticket-fact"
    );
    assert_eq!(input["payload_argument"]["validity"][0]["frontier"], 4);
    assert_eq!(input["shape"]["fields"]["id"], "string");
}

#[test]
fn managed_signal_projects_exact_success_and_failure_receipts() {
    let (draft, _, _) =
        ready(run(EMIT, Some("finish"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let (_, value, work) = ready(
        run(
            EMIT,
            Some("finish"),
            &Bindings::new(),
            &[effect("completed", input.clone())],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"completed"}),
                ),
                result_event(
                    "signal.emit.completed",
                    2,
                    json!({
                        "effect_id":"operation", "run_id":"run", "status":"completed",
                        "value":{"target":"receiver","event":"task.done"}
                    }),
                ),
            ],
            |body| body,
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(
        value.unwrap().value,
        json!({"target":"receiver","event":"task.done"})
    );

    let failure = json!({
        "error_kind":"notify_rejected", "message":"missing receiver", "summary":"missing receiver",
        "effect_id":"operation", "run_id":"run", "kind":"signal.emit"
    });
    let (_, value, work) = ready(
        run(
            EMIT,
            Some("finish"),
            &Bindings::new(),
            &[effect("failed", input)],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"failed"}),
                ),
                result_event(
                    "signal.emit.failed",
                    2,
                    json!({
                        "effect_id":"operation", "run_id":"run", "status":"failed",
                        "value":failure
                    }),
                ),
            ],
            |body| body,
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
fn managed_signal_refuses_source_and_evidence_drift() {
    assert!(run(
        "return ticket",
        Some("finish"),
        &bindings(),
        &[],
        &[],
        |body| body
    )
    .unwrap_err()
    .contains("requires an effect statement"));
    assert!(run(
        "prompt \"hi\" as answer",
        Some("finish"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("requires an emit statement"));
    assert!(run(EMIT, None, &bindings(), &[], &[], |body| body)
        .unwrap_err()
        .contains("pinned root rule"));
    assert!(run(
        "emit signal missing.event to ticket.peer from ticket as sent",
        Some("finish"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("no declared event"));
    let non_string = Bindings::from([(
        BindingId(0),
        Slot::Ready(
            json!({
                "peer":42,"id":"T-1","note":"ready"
            })
            .into(),
        ),
    )]);
    assert!(
        run(EMIT, Some("finish"), &non_string, &[], &[], |body| body)
            .unwrap_err()
            .contains("target must be a string")
    );

    let (draft, _, _) =
        ready(run(EMIT, Some("finish"), &bindings(), &[], &[], |body| body).unwrap());
    let mut input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    input["event"] = json!("other.event");
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("queued", input)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_signal_refuses_every_malformed_contract_and_settlement() {
    for (source, expected) in [
        (
            "emit signal task.done to ticket.peer { id \"a\" id \"b\" note \"n\" } as sent",
            "duplicated",
        ),
        (
            "emit signal task.done to ticket.peer { id \"a\" note \"n\" extra \"x\" } as sent",
            "not declared",
        ),
    ] {
        assert!(
            run(source, Some("finish"), &bindings(), &[], &[], |body| body)
                .unwrap_err()
                .contains(expected)
        );
    }
    assert!(
        run(EMIT, Some("finish"), &bindings(), &[], &[], |mut body| {
            let BodyStmt::Effect(effect) = &mut body else {
                unreachable!()
            };
            effect.binding = None;
            body
        },)
        .unwrap_err()
        .contains("no result binding")
    );
    assert!(
        run(EMIT, Some("finish"), &bindings(), &[], &[], |mut body| {
            let BodyStmt::Effect(effect) = &mut body else {
                unreachable!()
            };
            effect.timeout_seconds = Some(u64::MAX);
            body
        },)
        .unwrap_err()
        .contains("timeout exceeds")
    );

    let (draft, _, _) =
        ready(run(EMIT, Some("finish"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_identity = effect("queued", input.clone());
    wrong_identity.kind = "file.read".into();
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[wrong_identity],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("differs from its source operation"));

    let mut incomplete = input.clone();
    incomplete["target_argument"]["validity"] = Value::Null;
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("queued", incomplete)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("incomplete freshness argument"));

    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("mystery", input.clone())],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("unknown operation status"));
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[event(
            "effect.terminal",
            1,
            json!({"effect_id":"operation","run_id":"run","status":"failed"}),
        )],
        |body| body,
    )
    .unwrap_err()
    .contains("recorded status"));
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        std::slice::from_ref(&terminal),
        |body| body,
    )
    .unwrap_err()
    .contains("exactly one result"));
    let early = result_event(
        "signal.emit.completed",
        1,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value":{"target":"receiver","event":"task.done"}
        }),
    );
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[terminal.clone(), early],
        |body| body,
    )
    .unwrap_err()
    .contains("differs from its terminal"));
    let wrong_receipt = result_event(
        "signal.emit.completed",
        2,
        json!({
            "effect_id":"operation", "run_id":"run", "status":"completed",
            "value":{"target":"other","event":"task.done"}
        }),
    );
    assert!(run(
        EMIT,
        Some("finish"),
        &Bindings::new(),
        &[effect("completed", input)],
        &[terminal, wrong_receipt],
        |body| body,
    )
    .unwrap_err()
    .contains("violates its source contract"));
}
