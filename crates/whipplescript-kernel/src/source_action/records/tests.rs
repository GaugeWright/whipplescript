use super::*;
use crate::source_action::arguments::{
    Argument, Bindings, FactSubject, ObservationKind, QueryObservation, Slot, ValueSource,
};
use crate::source_action::CauseId;
use serde_json::json;
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

const SCHEMAS: &str = r#"
workflow Records
output result Done
class Done { ok bool }
class Out { name string note string? }
class Nullable { name string | null }
class Pair { first string second string third string? }
class Family { kind "a" | "b" detail string when kind is "a" }
class Wrapper { family Family }
enum Choice {
  Empty
  Named { name string }
  Maybe { note string? }
}
class Sum { value Choice }
rule finish when started => { complete result { ok true } }
"#;
fn ir() -> IrProgram {
    let compiled = whipplescript_parser::compile_program(SCHEMAS);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.unwrap()
}
fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "finish".into(),
        identity: None,
        trigger_event: Some("admitted".into()),
    }
}
fn slots(values: &[(&str, Slot)]) -> (Environment, Bindings) {
    (
        values
            .iter()
            .enumerate()
            .map(|(i, (name, _))| (name.to_string(), BindingId(i)))
            .collect(),
        values
            .iter()
            .enumerate()
            .map(|(i, (_, slot))| (BindingId(i), slot.clone()))
            .collect(),
    )
}
fn ready(value: Value) -> Slot {
    Slot::Ready(value.into())
}

fn observed(value: Value) -> Slot {
    Slot::Ready(Argument {
        value,
        validity: [QueryObservation {
            frontier: 3,
            kind: ObservationKind::Fact,
            head: "Input".into(),
            guard_json: None,
            members: Default::default(),
        }]
        .into(),
        ..Value::Null.into()
    })
}
fn run(
    source: &str,
    values: &[(&str, Slot)],
    frame: &Frame,
    events: &[EventView],
    active: &[ProjectionFact],
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{source}: {errors:?}");
    let (environment, bindings) = slots(values);
    project(
        Statement {
            node: NodeId(0),
            root_rule: Some("finish"),
            admitted: &bindings,
            identity: "arbitrary-call-site".into(),
            body: &body.statements[0],
            environment: &environment,
            bindings: &bindings,
            queries: None,
            outcomes: None,
        },
        Context {
            ir: &ir(),
            instance: "instance",
            frame,
            events,
            active,
            source_path: None,
        },
    )
}
fn lowering(leaf: Leaf) -> OwnedLowering {
    let Leaf::Ready {
        lowering,
        value,
        work,
    } = leaf
    else {
        panic!("not ready: {leaf:?}")
    };
    assert!(value.is_none());
    assert!(work.is_none());
    *lowering
}
fn payload_of(leaf: Leaf) -> Value {
    let lowered = lowering(leaf);
    assert_eq!(lowered.facts.len(), 1);
    serde_json::from_str(&lowered.facts[0].value_json).unwrap()
}
fn receipt(frame: &Frame, fact: &str, object: bool) -> EventView {
    let context = crate::rule_lowering::RuleContext {
        identity: frame.identity.clone(),
        trigger_event_id: frame.trigger_event.clone(),
        ..Default::default()
    };
    EventView { event_id: "commit".into(), sequence: 1, event_type: "rule.committed".into(),
        payload_json: json!({"rule":frame.rule, "program_version_id":frame.version,
            "revision_epoch":0, "context":serde_json::from_str::<Value>(&crate::rule_lowering::context_record_json(&context)).unwrap(),
            "facts":[if object { json!({"fact_id":fact}) } else { json!(fact) }]}).to_string(),
        source: "kernel".into(), occurred_at: "now".into() }
}

#[test]
fn managed_record_projection_uses_lexical_shorthand_and_omission() {
    let values = [(
        "source",
        ready(json!({"name":"copied", "alternate":"renamed", "extra":false})),
    )];
    for (source, expected) in [
        ("record Out from source { }", "copied"),
        ("record Out from source { name }", "copied"),
        ("record Out from source { name alternate }", "renamed"),
        ("record Out from source { name \"explicit\" }", "explicit"),
    ] {
        assert_eq!(
            payload_of(run(source, &values, &frame(), &[], &[]).unwrap()),
            json!({"name":expected})
        );
    }
    assert_eq!(
        payload_of(
            run(
                "record Out from source { name alternate }",
                &[values[0].clone(), ("alternate", ready(json!("lexical")))],
                &frame(),
                &[],
                &[]
            )
            .unwrap()
        ),
        json!({"name":"lexical"})
    );
    assert_eq!(
        payload_of(
            run(
                "record Nullable { name source.note }",
                &values,
                &frame(),
                &[],
                &[]
            )
            .unwrap()
        ),
        json!({"name":null})
    );
    for value in [Value::Null, json!(3), json!("text")] {
        let leaf = run(
            "record Out from source { }",
            &[("source", ready(value))],
            &frame(),
            &[],
            &[],
        )
        .unwrap();
        assert!(
            matches!(
                leaf,
                Leaf::Waiting(Evaluation {
                    state: State::Invalid(_),
                    ..
                })
            ),
            "{leaf:?}"
        );
    }
}

#[test]
fn managed_record_publishes_composed_validity() {
    let lowered = lowering(
        run(
            "record Out { name source }",
            &[("source", observed(json!("alice")))],
            &frame(),
            &[],
            &[],
        )
        .unwrap(),
    );
    let validity: crate::source_action::arguments::Validity =
        serde_json::from_str(lowered.facts[0].validity_json.as_deref().unwrap()).unwrap();
    assert_eq!(validity.len(), 1);
    assert_eq!(validity.iter().next().unwrap().head, "Input");
}

#[test]
fn managed_record_full_override_does_not_wait_for_an_unused_projection() {
    assert_eq!(
        payload_of(
            run(
                "record Out from source { name \"ready\" note null }",
                &[("source", Slot::Pending)],
                &frame(),
                &[],
                &[]
            )
            .unwrap()
        ),
        json!({"name":"ready","note":null})
    );
    let leaf = run(
        "record Out from source { name alternate note null }",
        &[("source", Slot::Pending), ("alternate", Slot::Pending)],
        &frame(),
        &[],
        &[],
    )
    .unwrap();
    let Leaf::Waiting(value) = leaf else {
        panic!("{leaf:?}")
    };
    assert_eq!(value.reads, BTreeSet::from([BindingId(1)]));
}

#[test]
fn managed_record_waits_and_failures_retain_all_independent_causes() {
    let leaf = run(
        "record Pair { first a second b third c }",
        &[
            ("a", Slot::Pending),
            (
                "b",
                Slot::Failed(BTreeSet::from([CauseId("original".into())])),
            ),
            ("c", Slot::Pending),
        ],
        &frame(),
        &[],
        &[],
    )
    .unwrap();
    let Leaf::Waiting(value) = leaf else {
        panic!("{leaf:?}")
    };
    assert_eq!(
        value.reads,
        BTreeSet::from([BindingId(0), BindingId(1), BindingId(2)])
    );
    assert_eq!(
        value.state,
        State::Blocked {
            waiting: BTreeSet::from([BindingId(0), BindingId(2)]),
            causes: BTreeSet::from([CauseId("original".into())])
        }
    );
    let leaf = run(
        "record Pair from source { first a second b }",
        &[
            ("source", ready(json!(4))),
            ("a", Slot::Pending),
            (
                "b",
                Slot::Failed(BTreeSet::from([CauseId("origin".into())])),
            ),
        ],
        &frame(),
        &[],
        &[],
    )
    .unwrap();
    let Leaf::Waiting(Evaluation {
        state: State::Invalid(issue),
        ..
    }) = leaf
    else {
        panic!("{leaf:?}")
    };
    assert_eq!(issue.waiting, BTreeSet::from([BindingId(1)]));
    assert_eq!(issue.causes, BTreeSet::from([CauseId("origin".into())]));
}

#[test]
fn managed_record_actual_payload_gate_checks_fields_and_mixed_enums() {
    for (source, expected) in [
        ("record Out { }", "Out.name is required"),
        ("record Out { name 3 }", "Out.name must be string"),
        (
            "record Out { name \"x\" extra true }",
            "Out.extra is not declared",
        ),
        ("record Out { name \"x\" name \"y\" }", "duplicated"),
        ("record Family { kind \"a\" }", "Family.detail is required"),
        (
            "record Family { kind \"b\" detail 3 }",
            "Family.detail must be string",
        ),
        ("record Sum { value Named }", "requires a payload object"),
        ("record Sum { value Maybe }", "requires a payload object"),
        (
            "record Sum { value Named { name 3 } }",
            "Sum.value.name must be string",
        ),
        (
            "record Sum { value Named { } }",
            "Sum.value.name is required",
        ),
    ] {
        let issue = run(source, &[], &frame(), &[], &[]).unwrap_err();
        assert!(issue.contains(expected), "{source}: {issue}");
    }
    for (source, expected) in [
        ("record Sum { value Empty }", json!({"value":"Empty"})),
        (
            "record Sum { value Named { name \"nested\" } }",
            json!({"value":{"variant":"Named","name":"nested"}}),
        ),
        (
            "record Sum { value Maybe { } }",
            json!({"value":{"variant":"Maybe"}}),
        ),
        ("record Family { kind \"b\" }", json!({"kind":"b"})),
    ] {
        assert_eq!(
            payload_of(run(source, &[], &frame(), &[], &[]).unwrap()),
            expected
        );
    }
    // Existing nominal ingestion intentionally tolerates an inactive sibling.
    assert_eq!(
        payload_of(
            run(
                "record Wrapper { family f }",
                &[("f", ready(json!({"kind":"b","detail":3})))],
                &frame(),
                &[],
                &[]
            )
            .unwrap()
        ),
        json!({"family":{"kind":"b","detail":3}})
    );
}

#[test]
fn managed_record_nested_constructor_keeps_its_own_scope_and_reserved_tag() {
    let values = [("source", ready(json!({"value":"Empty","name":"outer"})))];
    assert_eq!(
        payload_of(
            run(
                "record Sum from source { value Named { name name } }",
                &values,
                &frame(),
                &[],
                &[]
            )
            .unwrap()
        ),
        json!({"value":{"variant":"Named","name":"name"}})
    );
    for source in [
        "record Sum { value Named { variant \"Maybe\" name \"x\" } }",
        "record Sum { value Named { name \"a\" name \"b\" } }",
    ] {
        let leaf = run(source, &[], &frame(), &[], &[]).unwrap();
        assert!(
            matches!(
                leaf,
                Leaf::Waiting(Evaluation {
                    state: State::Invalid(_),
                    ..
                })
            ),
            "{leaf:?}"
        );
    }
}

#[test]
fn managed_record_receipts_follow_firings_without_capture_envelopes() {
    let first = lowering(run("record Out { name \"x\" }", &[], &frame(), &[], &[]).unwrap());
    let fact = &first.facts[0];
    assert_eq!(fact.provenance_class, "rule");
    assert_eq!(fact.schema_id, Some("Out".into()));
    let span: Value = serde_json::from_str(fact.source_span_json.as_ref().unwrap()).unwrap();
    assert_eq!(span["construct"], "record");
    for object in [true, false] {
        let history = [receipt(&frame(), &fact.fact_id, object)];
        assert!(
            lowering(run("record Out { name \"x\" }", &[], &frame(), &history, &[]).unwrap())
                .facts
                .is_empty()
        );
        let carried = Frame {
            version: "carried".into(),
            revision: "9".into(),
            ..frame()
        };
        assert!(
            lowering(run("record Out { name \"x\" }", &[], &carried, &history, &[]).unwrap())
                .facts
                .is_empty()
        );
        let another = Frame {
            trigger_event: Some("new-admission".into()),
            ..frame()
        };
        let fresh =
            lowering(run("record Out { name \"x\" }", &[], &another, &history, &[]).unwrap());
        assert_eq!(fresh.facts[0].fact_id, fact.fact_id);
        let keyed = Frame {
            identity: Some("different".into()),
            ..frame()
        };
        assert_eq!(
            lowering(run("record Out { name \"x\" }", &[], &keyed, &history, &[]).unwrap())
                .facts
                .len(),
            1
        );
        let mut unrelated = history[0].clone();
        unrelated.event_type = "external.notice".into();
        assert_eq!(
            lowering(
                run(
                    "record Out { name \"x\" }",
                    &[],
                    &frame(),
                    &[unrelated],
                    &[]
                )
                .unwrap()
            )
            .facts
            .len(),
            1
        );
    }
}

fn subject() -> Argument {
    Argument {
        value: json!({"name":"old"}),
        subjects: [(
            "".into(),
            FactSubject {
                fact_id: "ticket".into(),
                admission_event: "admitted".into(),
            },
        )]
        .into(),
        sources: BTreeSet::from([ValueSource::Fact {
            fact_id: "ticket".into(),
            admission_event: "admitted".into(),
        }]),
        validity: Default::default(),
    }
}
fn active() -> ProjectionFact {
    ProjectionFact {
        fact_id: "ticket".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        name: "Out".into(),
        key: "ticket".into(),
        value_json: subject().value.to_string(),
        provenance_class: "external".into(),
        source_span_json: None,
        validity_json: None,
        source_event_id: "admitted".into(),
    }
}
#[test]
fn managed_record_replacement_waits_before_consuming_and_preserves_admission_identity() {
    let source = "done ticket -> record Out { name result }";
    let values = [
        ("ticket", Slot::Ready(subject())),
        ("result", Slot::Pending),
    ];
    let leaf = run(source, &values, &frame(), &[], &[active()]).unwrap();
    let Leaf::Waiting(value) = leaf else {
        panic!("{leaf:?}")
    };
    assert_eq!(value.reads, BTreeSet::from([BindingId(0), BindingId(1)]));
    let values = [
        ("ticket", Slot::Ready(subject())),
        ("result", ready(json!("new"))),
    ];
    let result = lowering(run(source, &values, &frame(), &[], &[active()]).unwrap());
    assert_eq!(result.consumed_fact_ids, vec!["ticket"]);
    assert_eq!(result.facts.len(), 1);
    for active in [
        vec![],
        vec![ProjectionFact {
            source_event_id: "revived".into(),
            ..active()
        }],
    ] {
        let result = lowering(run(source, &values, &frame(), &[], &active).unwrap());
        assert!(result.consumed_fact_ids.is_empty());
        assert_eq!(result.facts.len(), 1);
        let replay = lowering(
            run(
                source,
                &values,
                &frame(),
                &[receipt(&frame(), &result.facts[0].fact_id, true)],
                &active,
            )
            .unwrap(),
        );
        assert!(replay.facts.is_empty());
        assert!(replay.consumed_fact_ids.is_empty());
    }
    assert!(run(
        source,
        &[
            ("ticket", ready(subject().value)),
            ("result", ready(json!("new")))
        ],
        &frame(),
        &[],
        &[active()]
    )
    .unwrap_err()
    .contains("exact whole fact"));
}

#[test]
fn managed_record_projector_rejects_wrong_dispatch_root_and_target() {
    assert!(run("timer 1s as wait", &[], &frame(), &[], &[])
        .unwrap_err()
        .contains("requires a record"));
    assert!(run(
        "record Out { name \"x\" }",
        &[],
        &Frame {
            rule: "other".into(),
            ..frame()
        },
        &[],
        &[]
    )
    .unwrap_err()
    .contains("actual calling rule"));
    assert!(run("record Missing { }", &[], &frame(), &[], &[])
        .unwrap_err()
        .contains("declared class"));
}

#[test]
fn managed_record_identity_is_scoped_by_instance_and_root_rule() {
    let ir = ir();
    let (body, errors) =
        whipplescript_parser::body::parse_action_body("record Out { name \"same\" }", 0);
    assert!(errors.is_empty());
    let build = |instance: &str, rule: &str| {
        let frame = Frame {
            rule: rule.into(),
            ..frame()
        };
        lowering(
            project(
                Statement {
                    node: NodeId(0),
                    root_rule: Some(rule),
                    admitted: &Bindings::new(),
                    identity: "site".into(),
                    body: &body.statements[0],
                    environment: &Environment::new(),
                    bindings: &Bindings::new(),
                    queries: None,
                    outcomes: None,
                },
                Context {
                    ir: &ir,
                    instance,
                    frame: &frame,
                    events: &[],
                    active: &[],
                    source_path: None,
                },
            )
            .unwrap(),
        )
        .facts
        .remove(0)
    };
    let first = build("one", "finish");
    assert_ne!(first.fact_id, build("two", "finish").fact_id);
    assert_ne!(first.fact_id, build("one", "another").fact_id);
    let first = lowering(run("record Out { name \"same\" }", &[], &frame(), &[], &[]).unwrap())
        .facts
        .remove(0);
    let unrelated = receipt(
        &Frame {
            rule: "another".into(),
            ..frame()
        },
        &first.fact_id,
        true,
    );
    assert_eq!(
        lowering(
            run(
                "record Out { name \"same\" }",
                &[],
                &frame(),
                &[unrelated],
                &[]
            )
            .unwrap()
        )
        .facts
        .len(),
        1
    );
}

#[test]
fn managed_record_replacement_combines_subject_failure_and_payload_waits() {
    let leaf = run(
        "done ticket -> record Out { name result }",
        &[
            (
                "ticket",
                Slot::Failed(BTreeSet::from([CauseId("subject-origin".into())])),
            ),
            ("result", Slot::Pending),
        ],
        &frame(),
        &[],
        &[],
    )
    .unwrap();
    let Leaf::Waiting(value) = leaf else {
        panic!("{leaf:?}")
    };
    assert_eq!(value.reads, BTreeSet::from([BindingId(0), BindingId(1)]));
    assert_eq!(
        value.state,
        State::Blocked {
            waiting: BTreeSet::from([BindingId(1)]),
            causes: BTreeSet::from([CauseId("subject-origin".into())])
        }
    );
}
