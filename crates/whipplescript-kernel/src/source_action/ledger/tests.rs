use super::*;
use crate::source_action::arguments::{Bindings, QueryObservation, Slot, ValueSource};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SOURCE: &str = r#"
workflow Ledgers
class Decision { area string choice string }
class Answer { value int }
ledger decisions { entry Decision partition by area retain 90d }
output result Answer
rule record when started => { complete result { value 0 } }
"#;

const APPEND: &str =
    "append Decision { area decision.area choice decision.choice } to decisions as saved";

fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("ledger fixture compiles")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "record".into(),
        identity: Some("started".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn bindings() -> Bindings {
    Bindings::from([(
        BindingId(0),
        Slot::Ready(Argument {
            value: json!({"area":"api","choice":"typed values"}),
            sources: BTreeSet::from([ValueSource::Fact {
                fact_id: "decision-fact".into(),
                admission_event: "decision-admitted".into(),
            }]),
            subjects: Default::default(),
            validity: BTreeSet::from([QueryObservation {
                frontier: 4,
                kind: super::super::arguments::ObservationKind::Fact,
                head: "Decision".into(),
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
    run_with_ir(&ir(), source, root_rule, bindings, effects, events, mutate)
}

fn run_with_ir(
    ir: &IrProgram,
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
            environment: &Environment::from([("decision".into(), BindingId(0))]),
            bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir,
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
        panic!("ready ledger leaf")
    };
    (lowering, value, work)
}

fn effect(status: &str, input: Value) -> ProjectionEffect {
    ProjectionEffect {
        effect_id: "operation".into(),
        kind: "ledger.append".into(),
        target: Some("decisions".into()),
        input_json: input.to_string(),
        status: status.into(),
        created_by_rule: "record".into(),
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

fn receipt() -> Value {
    json!({
        "variant":"Appended",
        "ledger":"decisions",
        "partition":"api",
        "seq":1
    })
}

#[test]
fn managed_append_captures_one_typed_entry_and_the_full_ledger_contract() {
    let Leaf::Waiting(wait) = run(APPEND, Some("record"), &Bindings::new(), &[], &[], |body| {
        body
    })
    .unwrap() else {
        panic!("missing ledger entry input must wait")
    };
    assert!(matches!(wait.state, State::Blocked { .. }));

    let (lowering, value, work) = ready(
        run(
            "append Decision { area decision.area choice decision.choice } to decisions as saved timeout 5s requires [\"ledger\"]",
            Some("record"),
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
        panic!("one append effect")
    };
    assert_eq!(effect.kind, "ledger.append");
    assert_eq!(effect.target.as_deref(), Some("decisions"));
    assert_eq!(effect.timeout_seconds, Some(5));
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    assert_eq!(
        input["entry"],
        json!({"area":"api","choice":"typed values"})
    );
    assert_eq!(input["partition"], "api");
    assert_eq!(input["partition_field"], "area");
    assert_eq!(input["retain_seconds"], 7_776_000);
    assert_eq!(input["entry_argument"]["validity"][0]["frontier"], 4);
    assert_eq!(
        input["entry_argument"]["sources"][0]["fact_id"],
        "decision-fact"
    );
}

#[test]
fn managed_append_projects_the_stable_receipt_as_its_value() {
    let (draft, _, _) =
        ready(run(APPEND, Some("record"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let (_, value, work) = ready(
        run(
            APPEND,
            Some("record"),
            &Bindings::new(),
            &[effect("completed", input)],
            &[
                event(
                    "effect.terminal",
                    1,
                    json!({"effect_id":"operation","run_id":"run","status":"completed"}),
                ),
                result_event(
                    "ledger.append.completed",
                    2,
                    json!({
                        "effect_id":"operation","run_id":"run","status":"completed",
                        "value":receipt()
                    }),
                ),
            ],
            |body| body,
        )
        .unwrap(),
    );
    assert_eq!(work.state, WorkState::Succeeded);
    assert_eq!(value.unwrap().value, receipt());
}

#[test]
fn managed_append_refuses_source_and_freshness_drift() {
    assert!(run(
        "return decision",
        Some("record"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("requires an effect statement"));
    assert!(run(
        "prompt \"hi\" as answer",
        Some("record"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("requires an append statement"));
    assert!(run(APPEND, None, &bindings(), &[], &[], |body| body)
        .unwrap_err()
        .contains("pinned root rule"));
    assert!(run(
        "append Decision { area decision.area choice decision.choice } to missing as saved",
        Some("record"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("no declared ledger"));
    assert!(run(
        "append Answer { value 1 } to decisions as saved",
        Some("record"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("schema differs"));
    let mut missing_class = ir();
    missing_class
        .schemas
        .retain(|schema| !matches!(schema, IrSchema::Class(class) if class.name == "Decision"));
    assert!(run_with_ir(
        &missing_class,
        APPEND,
        Some("record"),
        &bindings(),
        &[],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("no declared entry class"));
    assert!(
        run(APPEND, Some("record"), &bindings(), &[], &[], |mut body| {
            let BodyStmt::Effect(effect) = &mut body else {
                unreachable!()
            };
            let BodyEffectKind::LedgerAppend { fields, .. } = &mut effect.kind else {
                unreachable!()
            };
            fields.push(fields[0].clone());
            body
        },)
        .unwrap_err()
        .contains("duplicate entry fields")
    );

    let mut invalid_entry = bindings();
    let Slot::Ready(argument) = invalid_entry.get_mut(&BindingId(0)).unwrap() else {
        unreachable!()
    };
    argument.value["choice"] = json!(7);
    let issue = run(APPEND, Some("record"), &invalid_entry, &[], &[], |body| {
        body
    })
    .unwrap_err();
    assert!(issue.contains("Decision.choice must be string"), "{issue}");

    let (draft, _, _) =
        ready(run(APPEND, Some("record"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    let mut wrong_identity = effect("queued", input.clone());
    wrong_identity.kind = "counter.consume".into();
    assert!(run(
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[wrong_identity],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("differs from its source operation"));
    let mut incomplete = input.clone();
    incomplete["entry_argument"]["validity"] = Value::Null;
    assert!(run(
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[effect("queued", incomplete)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("incomplete freshness argument"));
    let mut stale = input.clone();
    stale["entry_argument"]["validity"][0]["frontier"] = json!(8);
    assert!(run(
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[effect("queued", stale)],
        &[],
        |body| body,
    )
    .is_err());
    let mut drift = input;
    drift["retain_seconds"] = json!(1);
    assert!(run(
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[effect("queued", drift)],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("source contract"));
}

#[test]
fn managed_append_refuses_malformed_settlement() {
    let (draft, _, _) =
        ready(run(APPEND, Some("record"), &bindings(), &[], &[], |body| body).unwrap());
    let input: Value = serde_json::from_str(&draft.effects[0].input_json).unwrap();
    assert!(run(
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[effect("mystery", input.clone())],
        &[],
        |body| body,
    )
    .unwrap_err()
    .contains("unknown operation status"));
    assert!(run(
        APPEND,
        Some("record"),
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
        APPEND,
        Some("record"),
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
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        std::slice::from_ref(&terminal),
        |body| body,
    )
    .unwrap_err()
    .contains("exactly one result"));
    let early = result_event(
        "ledger.append.completed",
        1,
        json!({
            "effect_id":"operation","run_id":"run","status":"completed","value":receipt()
        }),
    );
    assert!(run(
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[effect("completed", input.clone())],
        &[terminal.clone(), early],
        |body| body,
    )
    .unwrap_err()
    .contains("differs from its terminal"));
    let wrong = result_event(
        "ledger.append.completed",
        2,
        json!({
            "effect_id":"operation","run_id":"run","status":"completed",
            "value":{"variant":"Appended","ledger":"other","partition":"api","seq":1}
        }),
    );
    assert!(run(
        APPEND,
        Some("record"),
        &Bindings::new(),
        &[effect("completed", input)],
        &[terminal, wrong],
        |body| body,
    )
    .unwrap_err()
    .contains("violates its source contract"));
}
