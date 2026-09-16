use std::collections::BTreeSet;

use serde_json::{json, Value};
use whipplescript_parser::action_plan::{BindingId, Environment, NodeId};
use whipplescript_parser::body::parse_action_body;
use whipplescript_store::EventView;

use super::*;
use crate::source_action::arguments::{
    Argument, Bindings, Evaluation, ObservationKind, QueryObservation, Slot,
};

fn ir() -> IrProgram {
    whipplescript_parser::compile_program(
        "workflow Milestones\nclass Progress { detail string note string? }\nrule run when started => { record Progress { detail \"ok\" } }",
    )
    .ir
    .expect("fixture compiles")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "run".into(),
        identity: Some("item-1".into()),
        trigger_event: Some("admitted".into()),
    }
}

fn run(
    source: &str,
    values: &[(&str, Slot)],
    frame: &Frame,
    events: &[EventView],
) -> Result<Leaf, String> {
    let (body, diagnostics) = parse_action_body(source, 0);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    let environment: Environment = values
        .iter()
        .enumerate()
        .map(|(index, (name, _))| (name.to_string(), BindingId(index)))
        .collect();
    let bindings: Bindings = values
        .iter()
        .enumerate()
        .map(|(index, (_, value))| (BindingId(index), value.clone()))
        .collect();
    project(
        Statement {
            node: NodeId(0),
            root_rule: Some("run"),
            admitted: &bindings,
            identity: "call-site".into(),
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
            source_path: None,
        },
    )
}

fn lowering(leaf: Leaf) -> OwnedLowering {
    let Leaf::Ready {
        lowering,
        value: None,
        work: None,
    } = leaf
    else {
        panic!("expected ready synchronous milestone: {leaf:?}")
    };
    *lowering
}

fn receipt(frame: &Frame, fact_id: &str) -> EventView {
    let context = crate::rule_lowering::RuleContext {
        identity: frame.identity.clone(),
        trigger_event_id: frame.trigger_event.clone(),
        ..Default::default()
    };
    EventView {
        event_id: "commit".into(),
        sequence: 1,
        event_type: "rule.committed".into(),
        payload_json: json!({
            "rule": frame.rule,
            "program_version_id": frame.version,
            "revision_epoch": 0,
            "context": serde_json::from_str::<Value>(&crate::rule_lowering::context_record_json(&context)).unwrap(),
            "facts": [{"fact_id": fact_id}],
        })
        .to_string(),
        source: "kernel".into(),
        occurred_at: "now".into(),
    }
}

#[test]
fn managed_milestone_projects_the_existing_wire_shape_and_validity() {
    let observed = Slot::Ready(Argument {
        value: json!("started"),
        validity: BTreeSet::from([QueryObservation {
            frontier: 4,
            kind: ObservationKind::Fact,
            head: "Ticket".into(),
            guard_json: None,
            members: BTreeSet::new(),
        }]),
        ..Value::Null.into()
    });
    let lowered = lowering(
        run(
            "emit milestone \"work_started\" of Progress { detail input }",
            &[("input", observed)],
            &frame(),
            &[],
        )
        .unwrap(),
    );
    assert!(lowered.effects.is_empty());
    assert_eq!(lowered.facts.len(), 1);
    let fact = &lowered.facts[0];
    assert_eq!(fact.name, "workflow.milestone:work_started");
    assert_eq!(fact.schema_id, None);
    assert_eq!(fact.provenance_class, "rule");
    assert_eq!(fact.correlation_id.as_deref(), Some("item-1"));
    assert_eq!(
        serde_json::from_str::<Value>(&fact.value_json).unwrap(),
        json!({
            "milestone": "work_started",
            "status": "completed",
            "value": {"detail": "started"},
        })
    );
    let validity: crate::source_action::arguments::Validity =
        serde_json::from_str(fact.validity_json.as_deref().unwrap()).unwrap();
    assert_eq!(validity.len(), 1);
}

#[test]
fn managed_milestone_waits_and_checks_the_actual_payload() {
    assert!(matches!(
        run(
            "emit milestone \"work_started\" of Progress { detail input }",
            &[("input", Slot::Pending)],
            &frame(),
            &[],
        )
        .unwrap(),
        Leaf::Waiting(Evaluation { .. })
    ));
    let issue = run(
        "emit milestone \"work_started\" of Progress { detail 3 }",
        &[],
        &frame(),
        &[],
    )
    .unwrap_err();
    assert!(issue.contains("Progress.detail must be string"), "{issue}");
    assert!(run(
        "emit milestone \"work_started\" of Missing { detail \"x\" }",
        &[],
        &frame(),
        &[],
    )
    .unwrap_err()
    .contains("declared payload class"));
    assert!(run(
        "emit milestone \"work_started\" { detail \"x\" }",
        &[],
        &frame(),
        &[],
    )
    .unwrap_err()
    .contains("payload-less"));
    assert!(run(
        "emit milestone \"work_started\" of Progress { detail \"x\" detail \"y\" }",
        &[],
        &frame(),
        &[],
    )
    .unwrap_err()
    .contains("duplicates a payload field"));
}

#[test]
fn managed_bare_milestone_is_idempotent_for_the_rule_firing() {
    let first = lowering(run("emit milestone \"ready\"", &[], &frame(), &[]).unwrap());
    assert_eq!(
        serde_json::from_str::<Value>(&first.facts[0].value_json).unwrap(),
        json!({"milestone":"ready", "status":"completed", "value":{}})
    );
    let repeated = lowering(
        run(
            "emit milestone \"ready\"",
            &[],
            &frame(),
            &[receipt(&frame(), &first.facts[0].fact_id)],
        )
        .unwrap(),
    );
    assert!(repeated.facts.is_empty());
}

#[test]
fn managed_milestone_refuses_wrong_dispatch_and_root() {
    assert!(run("timer 1s as wait", &[], &frame(), &[])
        .unwrap_err()
        .contains("requires a milestone"));
    assert!(run(
        "emit milestone \"ready\"",
        &[],
        &Frame {
            rule: "other".into(),
            ..frame()
        },
        &[],
    )
    .unwrap_err()
    .contains("pinned calling rule"));
}
