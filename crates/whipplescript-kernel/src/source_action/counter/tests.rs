use super::*;
use crate::source_action::arguments::{Bindings, QueryObservation, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
workflow Counters
class Customer { id string }
class Answer { value int }
counter budget { key Customer cap 10 reset daily timezone "UTC" }
output result Answer
rule spend when started => { complete result { value 0 } }
"#;

const CONSUME: &str = "consume budget for customer amount units as spent";

fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("counter fixture compiles")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "spend".into(),
        identity: Some("started".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn bindings() -> Bindings {
    let source = BTreeSet::from([ValueSource::Fact {
        fact_id: "customer-fact".into(),
        admission_event: "customer-admitted".into(),
    }]);
    let validity = BTreeSet::from([QueryObservation {
        frontier: 4,
        kind: super::super::arguments::ObservationKind::Fact,
        head: "Customer".into(),
        guard_json: None,
        members: Default::default(),
    }]);
    Bindings::from([
        (
            BindingId(0),
            Slot::Ready(Argument {
                value: json!({"id":"C-1"}),
                sources: source.clone(),
                subjects: Default::default(),
                validity: validity.clone(),
            }),
        ),
        (
            BindingId(1),
            Slot::Ready(Argument {
                value: json!(3),
                sources: source,
                subjects: Default::default(),
                validity,
            }),
        ),
    ])
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
            environment: &Environment::from([
                ("customer".into(), BindingId(0)),
                ("units".into(), BindingId(1)),
            ]),
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
        panic!("ready counter leaf")
    };
    (lowering, value, work)
}

fn effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "counter.consume".into(),
        target: Some("budget".into()),
        input_json: input.to_string(),
        status: status.into(),
        created_by_rule: "spend".into(),
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
        json!({"name":name,"key":"operation","value":value}),
    )
}

#[test]
fn managed_counter_captures_both_arguments_and_declaration() {
    let Leaf::Waiting(wait) = run(CONSUME, Some("spend"), &Bindings::new(), &[], &[], |body| {
        body
    })
    .unwrap() else {
        panic!("missing counter inputs must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(
        run(
            "consume budget for customer amount units as spent timeout 5s requires [\"coord\"]",
            Some("spend"),
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
        panic!("one counter effect")
    };
    assert_eq!(effect.kind, "counter.consume");
    assert_eq!(effect.target.as_deref(), Some("budget"));
    assert_eq!(effect.timeout_seconds, Some(5));
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(input["key"], json!(r#"{"id":"C-1"}"#));
    assert_eq!(input["amount"], 3);
    assert_eq!(input["cap"], 10);
    assert_eq!(input["reset"], "daily");
    assert_eq!(input["timezone"], "UTC");
    assert_eq!(input["key_argument"]["validity"][0]["frontier"], 4);
    assert_eq!(
        input["amount_argument"]["sources"][0]["fact_id"],
        "customer-fact"
    );
}

#[test]
fn managed_counter_projects_ok_and_over_as_successful_values() {
    let (draft, _, _) =
        ready(run(CONSUME, Some("spend"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    for (variant, remaining) in [("Ok", 7), ("Over", 2)] {
        let receipt = json!({
            "variant":variant,"counter":"budget","key":"{\"id\":\"C-1\"}",
            "remaining":remaining,"period":"2026-09-13"
        });
        let (_, value, work) = ready(
            run(
                CONSUME,
                Some("spend"),
                &Bindings::new(),
                &[effect("completed", input.clone())],
                &[
                    event(
                        "effect.terminal",
                        1,
                        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
                    ),
                    result_event(
                        "counter.consume.completed",
                        2,
                        json!({
                            "effect_id":"operation","run_id":"run","status":"completed",
                            "value":receipt
                        }),
                    ),
                ],
                |body| body,
            )
            .unwrap(),
        );
        assert_eq!(work.state, WorkState::Succeeded);
        assert_eq!(value.unwrap().value, receipt);
    }
}

#[test]
fn managed_counter_refuses_source_and_evidence_drift() {
    assert!(run(
        "return customer",
        Some("spend"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("requires an effect statement"));
    assert!(run(
        "prompt \"hi\" as answer",
        Some("spend"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("requires a consume statement"));
    assert!(run(CONSUME, None, &bindings(), &[], &[], |body| body)
        .unwrap_err()
        .contains("pinned root rule"));
    assert!(run(
        "consume missing for customer amount units as spent",
        Some("spend"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("no declared counter"));
    let non_integer = Bindings::from([
        (BindingId(0), Slot::Ready(json!({"id":"C-1"}).into())),
        (BindingId(1), Slot::Ready(json!("three").into())),
    ]);
    assert!(
        run(CONSUME, Some("spend"), &non_integer, &[], &[], |body| body,)
            .unwrap_err()
            .contains("amount must be an integer")
    );

    let (draft, _, _) =
        ready(run(CONSUME, Some("spend"), &bindings(), &[], &[], |body| body).unwrap());
    let mut input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_identity = effect("queued", input.clone());
    wrong_identity.kind = "ledger.append".into();
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[wrong_identity],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("differs from its source operation"));
    let mut incomplete = input.clone();
    incomplete["amount_argument"]["validity"] = Value::Null;
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[effect("queued", incomplete)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("incomplete freshness argument"));
    input["cap"] = json!(11);
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[effect("queued", input)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_counter_refuses_malformed_settlement() {
    let (draft, _, _) =
        ready(run(CONSUME, Some("spend"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[effect("mystery", input.clone())],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("unknown operation status"));
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("exactly one terminal"));
    let terminal = event(
        "effect.terminal",
        1,
        json!({"effect_id":"operation","run_id":"run","status":"completed"}),
    );
    assert!(run(
        CONSUME,
        Some("spend"),
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
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        std::slice::from_ref(&terminal),
        |body| body,
    )
    .unwrap_err()
    .contains("exactly one result"));
    let early = result_event(
        "counter.consume.completed",
        1,
        json!({
            "effect_id":"operation","run_id":"run","status":"completed",
            "value":{"variant":"Ok","counter":"budget","key":"{\"id\":\"C-1\"}","remaining":7,"period":"2026-09-13"}
        }),
    );
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[terminal.clone(), early],
        |body| body,
    )
    .unwrap_err()
    .contains("differs from its terminal"));
    let wrong = result_event(
        "counter.consume.completed",
        2,
        json!({
            "effect_id":"operation","run_id":"run","status":"completed",
            "value":{"variant":"Maybe","counter":"budget","key":"{\"id\":\"C-1\"}","remaining":7,"period":"2026-09-13"}
        }),
    );
    assert!(run(
        CONSUME,
        Some("spend"),
        &Bindings::new(),
        &[effect("completed", input)],
        &[terminal, wrong],
        |body| body,
    )
    .unwrap_err()
    .contains("violates its source contract"));
}
