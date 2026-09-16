use std::collections::BTreeMap;

use whipplescript_parser::action_plan::resolved::{resolve_rule_types, TypedActionPlan};
use whipplescript_parser::action_plan::{BindingSource, Environment};
use whipplescript_parser::body::parse_action_body;
use whipplescript_parser::parse_program;

use super::*;
use crate::source_action::arguments::{Bindings, Slot};

const DECLARATIONS: &str =
    "workflow Cancel\noutput result Done\nclass Done { ok bool }\nclass Ticket { text string }\n";

fn typed(rule: &str) -> TypedActionPlan {
    let parsed = parse_program(&format!("{DECLARATIONS}{rule}"));
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    resolve_rule_types(&parsed.program, "run").expect("fixture resolves")
}

fn frame() -> Frame {
    Frame {
        version: "v".into(),
        revision: "0".into(),
        rule: "run".into(),
        identity: None,
        trigger_event: Some("started".into()),
    }
}

fn cancel_node(plan: &ActionPlan) -> NodeId {
    plan.nodes
        .iter()
        .enumerate()
        .find_map(|(index, node)| {
            matches!(
                node.kind,
                NodeKind::Statement(ref body) if matches!(body.as_ref(), BodyStmt::Cancel { .. })
            )
            .then_some(NodeId(index))
        })
        .expect("cancel node")
}

fn statement<'a>(
    node: NodeId,
    body: &'a BodyStmt,
    environment: &'a Environment,
    bindings: &'a Bindings,
) -> Statement<'a> {
    Statement {
        node,
        root_rule: Some("run"),
        admitted: bindings,
        identity: operation_identity("instance", &frame(), node),
        body,
        environment,
        bindings,
        queries: None,
        outcomes: None,
    }
}

#[test]
fn direct_cancel_uses_the_target_effect_identity_without_owning_work() {
    let typed = typed(
        "rule run when started => { timer 1s as wait\ncancel wait\ncomplete result { ok true } }",
    );
    let plan = &typed.plan;
    let node = cancel_node(plan);
    let environment = &plan.blocks[plan.nodes[node.0].block.0].environment;
    let body = plan.nodes[node.0].kind.as_statement().unwrap();
    let BodyStmt::Cancel { binding, .. } = body else {
        unreachable!()
    };
    let target_binding = environment[binding];
    let BindingSource::Node(target) = plan.bindings[target_binding.0].source else {
        unreachable!()
    };
    let leaf = project(
        statement(node, body, environment, &Bindings::new()),
        plan,
        "instance",
        &frame(),
        &BTreeMap::new(),
    )
    .unwrap();
    let Leaf::Ready {
        lowering,
        value: None,
        work: None,
    } = leaf
    else {
        panic!("{leaf:?}")
    };
    assert_eq!(
        lowering.cancels,
        vec![operation_identity("instance", &frame(), target)]
    );
}

#[test]
fn action_cancel_waits_for_selection_then_targets_only_its_actual_effect_leaves() {
    let typed = typed(
        "action child() -> null { timer 1s as inner\nreturn null }\nrule run when started => { child() as job\ncancel job\ncomplete result { ok true } }",
    );
    let plan = &typed.plan;
    let node = cancel_node(plan);
    let environment = &plan.blocks[plan.nodes[node.0].block.0].environment;
    let body = plan.nodes[node.0].kind.as_statement().unwrap();
    let job = environment["job"];
    let BindingSource::Node(call) = plan.bindings[job.0].source else {
        unreachable!()
    };
    let bindings = Bindings::from([(job, Slot::Pending)]);
    assert!(matches!(
        project(
            statement(node, body, environment, &bindings),
            plan,
            "instance",
            &frame(),
            &BTreeMap::new(),
        )
        .unwrap(),
        Leaf::Waiting(_)
    ));

    let leaf_node = plan
        .nodes
        .iter()
        .enumerate()
        .find_map(|(index, candidate)| {
            matches!(
                candidate.kind,
                NodeKind::Statement(ref statement)
                    if matches!(statement.as_ref(), BodyStmt::Effect(_))
            )
            .then_some(NodeId(index))
        })
        .unwrap();
    let pending = OwnedWork {
        state: WorkState::Pending,
        causes: BTreeMap::new(),
    };
    let owned = BTreeMap::from([(leaf_node, pending.clone()), (call, pending)]);
    let Leaf::Ready { lowering, .. } = project(
        statement(node, body, environment, &bindings),
        plan,
        "instance",
        &frame(),
        &owned,
    )
    .unwrap() else {
        unreachable!()
    };
    assert_eq!(
        lowering.cancels,
        vec![operation_identity("instance", &frame(), leaf_node)]
    );
}

#[test]
fn cancellation_refuses_unknown_non_operation_and_wrong_dispatch() {
    let typed = typed(
        "rule run when Ticket as ticket => { redact ticket keep [text] as selected\ntimer 1s as wait\ncancel wait\ncomplete result { ok true } }",
    );
    let plan = &typed.plan;
    let node = cancel_node(plan);
    let body = plan.nodes[node.0].kind.as_statement().unwrap();
    let environment = &plan.blocks[plan.nodes[node.0].block.0].environment;
    assert!(project(
        statement(node, body, &Environment::new(), &Bindings::new()),
        plan,
        "instance",
        &frame(),
        &BTreeMap::new(),
    )
    .unwrap_err()
    .contains("unknown managed binding"));

    let mut input_binding = body.clone();
    let BodyStmt::Cancel { binding, .. } = &mut input_binding else {
        unreachable!()
    };
    *binding = "ticket".into();
    assert!(project(
        statement(node, &input_binding, environment, &Bindings::new()),
        plan,
        "instance",
        &frame(),
        &BTreeMap::new(),
    )
    .unwrap_err()
    .contains("operation binding"));

    let mut pure_node = body.clone();
    let BodyStmt::Cancel { binding, .. } = &mut pure_node else {
        unreachable!()
    };
    *binding = "selected".into();
    assert!(project(
        statement(node, &pure_node, environment, &Bindings::new()),
        plan,
        "instance",
        &frame(),
        &BTreeMap::new(),
    )
    .unwrap_err()
    .contains("operation binding"));

    let (parsed, diagnostics) = parse_action_body("timer 1s as wait", 0);
    assert!(diagnostics.is_empty());
    assert!(project(
        statement(node, &parsed.statements[0], environment, &Bindings::new()),
        plan,
        "instance",
        &frame(),
        &BTreeMap::new(),
    )
    .unwrap_err()
    .contains("requires a cancel"));
}

trait StatementKind {
    fn as_statement(&self) -> Option<&BodyStmt>;
}

impl StatementKind for NodeKind {
    fn as_statement(&self) -> Option<&BodyStmt> {
        match self {
            NodeKind::Statement(statement) => Some(statement),
            _ => None,
        }
    }
}
