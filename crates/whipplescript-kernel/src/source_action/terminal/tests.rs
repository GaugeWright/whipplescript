use super::*;
use crate::source_action::{
    arguments::{Argument, Bindings, ObservationKind, QueryObservation, Slot},
    CauseId,
};
use serde_json::{json, Value};
use whipplescript_parser::{
    action_plan::{BindingId, Environment, NodeId},
    body::{parse_composed_rule_body, BodyStmt},
};

const SOURCE: &str = r#"workflow Terminals
output result Answer
failure rejected string
class Answer { text string note string? }
class Family { kind "a" | "b" detail string when kind is "a" }
rule finish when started => { complete result { text "done" } }
"#;
fn ir() -> IrProgram {
    whipplescript_parser::compile_program(SOURCE).ir.unwrap()
}
fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "finish".into(),
        identity: None,
        trigger_event: Some("start".into()),
    }
}
fn body(source: &str) -> BodyStmt {
    let (body, errors) = parse_composed_rule_body(source, 0);
    assert!(errors.is_empty(), "{source}: {errors:?}");
    body.statements.into_iter().next().unwrap()
}
fn project_body(
    body: &BodyStmt,
    ir: &IrProgram,
    values: &[(&str, Slot)],
    root: Option<&str>,
    identity: &str,
) -> Result<Leaf, String> {
    let env: Environment = values
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.to_string(), BindingId(i)))
        .collect();
    let bindings: Bindings = values
        .iter()
        .enumerate()
        .map(|(i, (_, slot))| (BindingId(i), slot.clone()))
        .collect();
    project(
        Statement {
            node: NodeId(0),
            root_rule: root,
            admitted: &bindings,
            identity: identity.into(),
            body,
            environment: &env,
            bindings: &bindings,
            queries: None,
            outcomes: None,
        },
        ir,
        &frame(),
    )
}
fn run(source: &str, ir: &IrProgram, values: &[(&str, Slot)]) -> Result<Leaf, String> {
    project_body(
        &body(source),
        ir,
        values,
        Some("finish"),
        "instance-frame-node",
    )
}
fn terminal(leaf: Leaf) -> OwnedWorkflowTerminal {
    let Leaf::Ready {
        lowering,
        value,
        work,
    } = leaf
    else {
        panic!("{leaf:?}")
    };
    assert!(value.is_none() && work.is_none());
    assert!(lowering.facts.is_empty() && lowering.effects.is_empty());
    lowering.terminal.unwrap()
}
fn ready(value: Value) -> Slot {
    Slot::Ready(value.into())
}

fn observed(value: Value) -> Slot {
    Slot::Ready(Argument {
        value,
        validity: [QueryObservation {
            frontier: 5,
            kind: ObservationKind::Effect,
            head: "kind evidence.check".into(),
            guard_json: None,
            members: Default::default(),
        }]
        .into(),
        ..Value::Null.into()
    })
}
#[test]
fn managed_terminal_consumes_whole_values_or_bounded_construction() {
    let ir = ir();
    let values = [("answer", ready(json!({"text":"answer"})))];
    for source in [
        "complete result answer",
        "complete result from answer {}",
        "complete result { text answer.text }",
    ] {
        let t = terminal(run(source, &ir, &values).unwrap());
        assert_eq!(t.kind, WorkflowTerminalKind::Completed);
        assert_eq!(t.name, "result");
        assert_eq!(
            serde_json::from_str::<Value>(&t.payload_json).unwrap(),
            json!({"text":"answer"})
        );
    }
    let t = terminal(
        run(
            "complete result from answer {}",
            &ir,
            &[("answer", ready(json!({"text":"answer", "extra":true})))],
        )
        .unwrap(),
    );
    assert_eq!(
        serde_json::from_str::<Value>(&t.payload_json).unwrap(),
        json!({"text":"answer"})
    );
    let t = terminal(
        run(
            "fail rejected reason",
            &ir,
            &[("reason", ready(json!("declined")))],
        )
        .unwrap(),
    );
    assert_eq!(t.kind, WorkflowTerminalKind::Failed);
    assert_eq!(t.payload_json, "\"declined\"");
}

#[test]
fn managed_terminal_publishes_composed_validity() {
    let terminal = terminal(
        run(
            "complete result answer",
            &ir(),
            &[("answer", observed(json!({"text":"done"})))],
        )
        .unwrap(),
    );
    let validity: crate::source_action::arguments::Validity =
        serde_json::from_str(terminal.validity_json.as_deref().unwrap()).unwrap();
    assert_eq!(validity.len(), 1);
    assert_eq!(validity.iter().next().unwrap().head, "kind evidence.check");
}
#[test]
fn managed_terminal_pending_or_failed_inputs_do_not_become_payloads() {
    for slot in [
        Slot::Pending,
        Slot::Failed([CauseId("failure".into())].into()),
    ] {
        let Leaf::Waiting(e) =
            run("complete result answer", &ir(), &[("answer", slot.clone())]).unwrap()
        else {
            panic!("terminal bypassed dependency")
        };
        let State::Blocked { waiting, causes } = e.state else {
            panic!("lost dependency")
        };
        match slot {
            Slot::Pending => assert_eq!(waiting, [BindingId(0)].into()),
            Slot::Failed(c) => assert_eq!(causes, c),
            _ => unreachable!(),
        }
    }
}
#[test]
fn managed_terminal_refuses_wrong_root_contract_and_invalid_construction() {
    let ir = ir();
    for root in [None, Some("other")] {
        assert!(project_body(
            &body("complete result { text \"yes\" }"),
            &ir,
            &[],
            root,
            "id"
        )
        .unwrap_err()
        .contains("pinned calling rule"));
    }
    let mut no_rule = ir.clone();
    no_rule.rules.clear();
    assert!(run("complete result { text \"yes\" }", &no_rule, &[])
        .unwrap_err()
        .contains("pinned calling rule"));
    assert!(run("timer 1s as t", &ir, &[])
        .unwrap_err()
        .contains("requires a workflow terminal"));
    for source in [
        "complete missing { text \"yes\" }",
        "fail result \"bad\"",
        "complete rejected \"bad\"",
    ] {
        assert!(run(source, &ir, &[])
            .unwrap_err()
            .contains("exactly one matching contract"));
    }
    let mut duplicate = ir.clone();
    duplicate
        .workflow_contracts
        .push(ir.workflow_contracts[0].clone());
    assert!(run("complete result { text \"yes\" }", &duplicate, &[])
        .unwrap_err()
        .contains("exactly one matching contract"));
    for source in [
        "complete result {}",
        "complete result { text 42 }",
        "fail rejected 42",
        "complete result { text \"ok\" extra 42 }",
    ] {
        assert!(
            run(source, &ir, &[])
                .unwrap_err()
                .contains("violates contract"),
            "{source}"
        );
    }
    assert!(run("complete result { text \"a\" text \"b\" }", &ir, &[])
        .unwrap_err()
        .contains("duplicates a field"));
    assert!(run("fail rejected {}", &ir, &[])
        .unwrap_err()
        .contains("requires a class contract"));
    let mut missing = ir.clone();
    missing.schemas.clear();
    assert!(run("complete result { text \"a\" }", &missing, &[])
        .unwrap_err()
        .contains("class is absent"));
    let mut malformed = body("complete result answer");
    let BodyStmt::Terminal(t) = &mut malformed else {
        unreachable!()
    };
    t.from = Some("answer".into());
    assert!(project_body(&malformed, &ir, &[], Some("finish"), "id")
        .unwrap_err()
        .contains("mixes a value"));
    let BodyStmt::Terminal(t) = &mut malformed else {
        unreachable!()
    };
    t.from = None;
    t.scalar = Some(FieldValue::Shorthand);
    assert!(project_body(&malformed, &ir, &[], Some("finish"), "id")
        .unwrap_err()
        .contains("managed expression"));
}
#[test]
fn managed_terminal_construction_checks_inactive_fields_and_identity_is_stable() {
    let mut ir = ir();
    ir.workflow_contracts[0].ty = IrType::Ref("Family".into());
    assert!(run("complete result { kind \"b\" detail 42 }", &ir, &[])
        .unwrap_err()
        .contains("violates contract"));
    let b = body("complete result { kind \"b\" }");
    let first = terminal(project_body(&b, &ir, &[], Some("finish"), "frame-node-a").unwrap());
    let replay = terminal(project_body(&b, &ir, &[], Some("finish"), "frame-node-a").unwrap());
    assert_eq!(first.idempotency_key, replay.idempotency_key);
    let other = terminal(project_body(&b, &ir, &[], Some("finish"), "frame-node-b").unwrap());
    assert_ne!(first.idempotency_key, other.idempotency_key);
    let other = terminal(
        project_body(
            &body("complete result { kind \"a\" detail \"x\" }"),
            &ir,
            &[],
            Some("finish"),
            "frame-node-a",
        )
        .unwrap(),
    );
    assert_ne!(first.idempotency_key, other.idempotency_key);
}

#[test]
fn managed_terminal_absent_optional_is_null_but_pending_stays_pending() {
    let mut ir = ir();
    let failure = ir
        .workflow_contracts
        .iter_mut()
        .find(|c| c.kind == IrWorkflowContractKind::Failure)
        .unwrap();
    failure.ty = IrType::Optional(Box::new(failure.ty.clone()));
    let source = "fail rejected answer.note";
    assert_eq!(
        terminal(run(source, &ir, &[("answer", ready(json!({"text":"ready"})))]).unwrap())
            .payload_json,
        "null"
    );
    let Leaf::Waiting(e) = run(source, &ir, &[("answer", Slot::Pending)]).unwrap() else {
        panic!("pending became absent")
    };
    assert!(matches!(e.state, State::Blocked { .. }));
    let original = self::ir();
    assert!(run(
        source,
        &original,
        &[("answer", ready(json!({"text":"ready"})))]
    )
    .unwrap_err()
    .contains("violates contract"));
}
