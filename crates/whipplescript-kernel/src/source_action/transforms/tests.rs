use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};
use whipplescript_parser::body::parse_action_body;
use whipplescript_parser::compile_program;

use super::*;
use crate::source_action::arguments::{
    Evaluation, FactSubject, ObservationKind, QueryObservation, Slot, ValueSource,
};

fn ir() -> IrProgram {
    compile_program(
        "workflow Transform\nclass Public { id string note string? }\nclass Required { id string note string }\nrule run when started => { record Public { id \"ok\" } }",
    )
    .ir
    .expect("fixture compiles")
}

fn run(source: &str, slot: Slot) -> Result<Leaf, String> {
    let (body, diagnostics) = parse_action_body(source, 0);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let environment = Environment::from([("input".into(), BindingId(0))]);
    let bindings = BTreeMap::from([(BindingId(0), slot)]);
    project(
        Statement {
            node: NodeId(0),
            root_rule: Some("run"),
            admitted: &bindings,
            identity: "transform".into(),
            body: &body.statements[0],
            environment: &environment,
            bindings: &bindings,
            queries: None,
            outcomes: None,
        },
        &ir(),
    )
}

fn ready(leaf: Leaf) -> Argument {
    let Leaf::Ready {
        lowering,
        value: Some(value),
        work: None,
    } = leaf
    else {
        panic!("expected a ready pure value")
    };
    assert_eq!(*lowering, OwnedLowering::default());
    value
}

fn observed() -> Slot {
    let source = ValueSource::Fact {
        fact_id: "fact-1".into(),
        admission_event: "event-1".into(),
    };
    Slot::Ready(Argument {
        value: json!({"id":"visible", "note":"private", "extra":true}),
        sources: BTreeSet::from([source.clone()]),
        subjects: BTreeMap::from([
            (
                "/id".into(),
                FactSubject {
                    fact_id: "fact-1".into(),
                    admission_event: "event-1".into(),
                },
            ),
            (
                "/note".into(),
                FactSubject {
                    fact_id: "fact-1".into(),
                    admission_event: "event-1".into(),
                },
            ),
        ]),
        validity: BTreeSet::from([QueryObservation {
            frontier: 4,
            kind: ObservationKind::Fact,
            head: "Input".into(),
            guard_json: None,
            members: BTreeSet::new(),
        }]),
    })
}

#[test]
fn redact_projects_fields_and_retains_only_surviving_subjects() {
    let value = ready(run("redact input keep [id] as public", observed()).unwrap());
    assert_eq!(value.value, json!({"id":"visible"}));
    assert_eq!(value.sources.len(), 1);
    assert_eq!(value.validity.len(), 1);
    assert_eq!(value.subjects.keys().collect::<Vec<_>>(), vec!["/id"]);
}

#[test]
fn declassify_projects_to_the_declared_bound_and_checks_runtime_shape() {
    let value = ready(run("declassify input into Public as public", observed()).unwrap());
    assert_eq!(value.value, json!({"id":"visible", "note":"private"}));
    assert!(!value.value.as_object().unwrap().contains_key("extra"));

    let error = run(
        "declassify input into Required as public",
        Slot::Ready(Value::Object(Default::default()).into()),
    )
    .unwrap_err();
    assert!(error.contains("Required.id"), "{error}");
}

#[test]
fn transformations_preserve_waiting_and_refuse_non_objects() {
    assert!(matches!(
        run("redact input keep [id] as public", Slot::Pending).unwrap(),
        Leaf::Waiting(Evaluation {
            state: State::Blocked { .. },
            ..
        })
    ));
    assert!(matches!(
        run(
            "declassify input into Public as public",
            Slot::Ready(Value::Null.into())
        )
        .unwrap(),
        Leaf::Waiting(Evaluation {
            state: State::Invalid(_),
            ..
        })
    ));
    assert!(run("declassify input into Missing as public", observed())
        .unwrap_err()
        .contains("declared target class"));

    let (body, diagnostics) = parse_action_body("timer 1s as timer", 0);
    assert!(diagnostics.is_empty());
    let environment = Environment::new();
    let bindings = BTreeMap::new();
    let error = project(
        Statement {
            node: NodeId(0),
            root_rule: Some("run"),
            admitted: &bindings,
            identity: "wrong-projector".into(),
            body: &body.statements[0],
            environment: &environment,
            bindings: &bindings,
            queries: None,
            outcomes: None,
        },
        &ir(),
    )
    .unwrap_err();
    assert!(error.contains("requires redact or declassify"));
}
