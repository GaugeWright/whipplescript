use super::*;
use crate::source_action::arguments::{Argument, Bindings, FactSubject, ValueSource};
use serde_json::json;
use std::collections::BTreeSet;
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};

fn argument() -> Argument {
    Argument {
        value: json!({"title":"original"}),
        sources: BTreeSet::from([ValueSource::Fact {
            fact_id: "ticket".into(),
            admission_event: "admitted".into(),
        }]),
        validity: Default::default(),
        subjects: [(
            String::new(),
            FactSubject {
                fact_id: "ticket".into(),
                admission_event: "admitted".into(),
            },
        )]
        .into(),
    }
}
fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "finish".into(),
        identity: None,
        trigger_event: Some("another|admitted".into()),
    }
}
fn active() -> ProjectionFact {
    ProjectionFact {
        fact_id: "ticket".into(),
        program_version_id: Some("v".into()),
        revision_epoch: 0,
        name: "Ticket".into(),
        key: "ticket".into(),
        value_json: argument().value.to_string(),
        provenance_class: "external".into(),
        source_span_json: None,
        validity_json: None,
        source_event_id: "admitted".into(),
    }
}
fn run(
    source: &str,
    slot: Slot,
    admitted: &Bindings,
    root: Option<&str>,
    frame: &Frame,
    active: &[ProjectionFact],
) -> Result<Leaf, String> {
    let (body, errors) = whipplescript_parser::body::parse_action_body(source, 0);
    assert!(errors.is_empty(), "{errors:?}");
    project(
        Statement {
            node: NodeId(0),
            root_rule: root,
            admitted,
            identity: "done".into(),
            body: &body.statements[0],
            environment: &Environment::from([("ticket".into(), BindingId(1))]),
            bindings: &Bindings::from([(BindingId(1), slot)]),
            queries: None,
            outcomes: None,
        },
        frame,
        active,
    )
}
fn roots() -> Bindings {
    [(BindingId(0), Slot::Ready(argument()))].into()
}
fn consumed(result: Result<Leaf, String>) -> Vec<String> {
    let Leaf::Ready {
        lowering,
        value: None,
        work: None,
    } = result.unwrap()
    else {
        panic!("done must produce an immediate, valueless lowering");
    };
    lowering.consumed_fact_ids
}
#[test]
fn action_fact_subject_done_consumes_only_its_original_active_admission() {
    let project = |facts: &[ProjectionFact]| {
        run(
            "done ticket",
            Slot::Ready(argument()),
            &roots(),
            Some("finish"),
            &frame(),
            facts,
        )
    };
    assert_eq!(consumed(project(&[active()])), ["ticket"]);
    assert!(consumed(project(&[])).is_empty());
    let mut revived = active();
    revived.source_event_id = "revived".into();
    assert!(consumed(project(&[revived])).is_empty());
    let mut unrelated = active();
    unrelated.fact_id = "other".into();
    assert!(consumed(project(&[unrelated])).is_empty());
}
#[test]
fn action_fact_subject_done_never_promotes_provenance_or_nested_subjects() {
    let mut rebuilt = argument();
    rebuilt.subjects.clear();
    let mut container = argument();
    container.value = json!({"ticket":container.value});
    let subject = container.subjects.remove("").unwrap();
    container.subjects.insert("/ticket".into(), subject);
    for value in [rebuilt, container] {
        let error = run(
            "done ticket",
            Slot::Ready(value),
            &roots(),
            Some("finish"),
            &frame(),
            &[active()],
        )
        .unwrap_err();
        assert!(error.contains("exact whole fact subject"), "{error}");
    }
}
#[test]
fn action_fact_subject_done_requires_the_original_root_payload_and_firing() {
    let mut wrong_payload = argument();
    wrong_payload.value = json!({"title":"changed"});
    let mut wrong_subject = argument();
    wrong_subject.subjects.get_mut("").unwrap().admission_event = "other".into();
    wrong_subject.sources.insert(ValueSource::Fact {
        fact_id: "ticket".into(),
        admission_event: "other".into(),
    });
    for admitted in [
        Bindings::new(),
        [(BindingId(0), Slot::Ready(wrong_payload))].into(),
        [(BindingId(0), Slot::Ready(wrong_subject))].into(),
        [(BindingId(0), Slot::Pending)].into(),
    ] {
        assert!(run(
            "done ticket",
            Slot::Ready(argument()),
            &admitted,
            Some("finish"),
            &frame(),
            &[active()]
        )
        .unwrap_err()
        .contains("captured admitted fact"));
    }
    for events in [
        None,
        Some("admitted-suffix".into()),
        Some("prefix-admitted".into()),
    ] {
        let mut f = frame();
        f.trigger_event = events;
        assert!(run(
            "done ticket",
            Slot::Ready(argument()),
            &roots(),
            Some("finish"),
            &f,
            &[active()]
        )
        .unwrap_err()
        .contains("captured admitted fact"));
    }
    for root in [None, Some("different")] {
        assert!(run(
            "done ticket",
            Slot::Ready(argument()),
            &roots(),
            root,
            &frame(),
            &[active()]
        )
        .unwrap_err()
        .contains("actual calling rule root"));
    }
}
#[test]
fn action_fact_subject_done_refuses_corrupt_active_projection() {
    let mut effect = active();
    effect.provenance_class = "effect".into();
    let mut missing = active();
    missing.source_event_id.clear();
    let mut malformed = active();
    malformed.value_json = "{".into();
    let mut changed = active();
    changed.value_json = json!({"title":"changed"}).to_string();
    for (facts, message) in [
        (vec![active(), active()], "conflicting"),
        (vec![effect], "effect placeholder"),
        (vec![missing], "no admitting event"),
        (vec![malformed], "invalid JSON"),
        (vec![changed], "payload changed"),
    ] {
        assert!(
            run(
                "done ticket",
                Slot::Ready(argument()),
                &roots(),
                Some("finish"),
                &frame(),
                &facts
            )
            .unwrap_err()
            .contains(message),
            "{message}"
        );
    }
}
#[test]
fn action_fact_subject_done_preserves_waits_and_refuses_unsupported_statements() {
    let pending = run(
        "done ticket",
        Slot::Pending,
        &roots(),
        Some("finish"),
        &frame(),
        &[active()],
    )
    .unwrap();
    assert!(
        matches!(pending, Leaf::Waiting(value) if matches!(value.state, State::Blocked { .. }))
    );
    for (source, message) in [
        ("timer 1s as delay", "requires a done statement"),
        (
            "done ticket -> record Ticket { title \"next\" }",
            "replacement record",
        ),
        ("done unknown", "unknown managed binding"),
    ] {
        assert!(run(
            source,
            Slot::Ready(argument()),
            &roots(),
            Some("finish"),
            &frame(),
            &[active()]
        )
        .unwrap_err()
        .contains(message));
    }
}
