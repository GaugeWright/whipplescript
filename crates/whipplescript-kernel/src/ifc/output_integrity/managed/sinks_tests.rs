use super::super::tests::{check_local_sinks, compiled, context, policy, typed, HEADER};
use super::*;

#[test]
fn managed_sink_inventory_copies_only_unwritten_declared_fields() {
    let source = format!(
        r#"{HEADER}
class Extended {{ value string extra string }}
action produce() -> Extended {{ tell unsafe "draft" as raw
 return {{ value raw extra "extra" }} }}
action publish(value Extended) -> null {{ record Output from value {{}}
 return null }}
rule run when started => {{ produce() as result
 publish(result) as first
 publish(result) as second }}"#
    );
    let ir = compiled(&format!("{HEADER}class Extended {{ value string extra string }}\nrule run when started => {{ timer 1s as wait }}"));
    let plan = typed(&source);
    let sinks = inventory(&plan, &ir).unwrap();
    assert_eq!(sinks.local.len(), 2);
    assert_eq!(sinks.effects.len(), 1);
    assert!(sinks.package_terminals.is_empty());
    for sink in &sinks.local {
        assert_eq!(sink.resource, "fact:Output");
        assert_eq!(
            sink.payload,
            vec![Expr::Path(vec!["value".into(), "value".into()])]
        );
    }
    let errors = check_local_sinks(&plan, &ir, &policy(""));
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert_ne!(errors[0].related, errors[1].related);
    let overridden = typed(&source.replace("from value {}", "from value { value \"constant\" }"));
    assert!(check_local_sinks(&overridden, &ir, &policy("")).is_empty());
    let extra_only =
        typed(&source.replace("value raw extra \"extra\"", "value \"constant\" extra raw"));
    assert!(check_local_sinks(&extra_only, &ir, &policy("")).is_empty());
}

#[test]
fn managed_sink_inventory_covers_replacements_and_milestones() {
    let source = format!(
        r#"{HEADER}
rule run when Input as input => {{ tell unsafe "draft" as raw
 done input -> record Output {{ value raw }}
 emit milestone "drafted" of Output {{ value raw }} }}"#
    );
    let plan = typed(&source);
    let ir = context("Input as input");
    let sinks = inventory(&plan, &ir).unwrap();
    assert_eq!(
        sinks
            .local
            .iter()
            .map(|s| s.resource.as_str())
            .collect::<Vec<_>>(),
        vec!["fact:Output", "milestone:drafted"]
    );
    assert_eq!(sinks.effects.len(), 1);
    let untyped_milestone = typed(&source.replace(" of Output", ""));
    assert_eq!(inventory(&untyped_milestone, &ir).unwrap().local.len(), 2);
    let policy = policy("grant milestone drafted -> milestone:drafted from Operator");
    assert_eq!(check_local_sinks(&untyped_milestone, &ir, &policy).len(), 2);
    let errors = check_local_sinks(&plan, &ir, &policy);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(errors
        .iter()
        .all(|error| error.message.contains("executor `unvouched`")));
}

fn terminal_context() -> IrProgram {
    compiled(&format!("{HEADER}output result Output\nfailure rejected string\nrule run when started => {{ timer 1s as wait }}"))
}
fn terminal_plan(statement: &str) -> TypedActionPlan {
    typed(&format!(
        r#"{HEADER}
output result Output
failure rejected string
action produce() -> Output {{ tell unsafe "draft" as raw
 return {{ value raw }} }}
rule run when started => {{ produce() as result
 {statement} }}"#
    ))
}
#[test]
fn managed_sink_inventory_checks_whole_constructed_and_projected_terminals() {
    let ir = terminal_context();
    let policy = policy("grant output result -> result from Operator\ngrant failure rejected -> rejected from Operator");
    for (statement, destination) in [
        ("complete result result", "result"),
        ("complete result from result {}", "result"),
        ("complete result { value result.value }", "result"),
        ("fail rejected result.value", "rejected"),
    ] {
        let plan = terminal_plan(statement);
        let sinks = inventory(&plan, &ir).unwrap();
        assert_eq!(sinks.local.len(), 1);
        assert_eq!(sinks.local[0].resource, destination);
        let errors = check_local_sinks(&plan, &ir, &policy);
        assert_eq!(errors.len(), 1, "{statement}: {errors:?}");
        assert!(errors[0].message.contains("executor `unvouched`"));
    }
    let overridden = terminal_plan("complete result from result { value \"constant\" }");
    assert!(check_local_sinks(&overridden, &ir, &policy).is_empty());
}

#[test]
fn managed_sink_inventory_preserves_tool_boundary_and_empty_selection() {
    let plan = terminal_plan("complete result from result {}");
    let mut ir = terminal_context();
    let tool = compiled("@tool\nworkflow Tool\noutput result string\nrule run when started => { complete result \"done\" }");
    ir.source_tags = tool.source_tags;
    let sinks = inventory(&plan, &ir).unwrap();
    assert!(sinks.local.is_empty());
    assert_eq!(sinks.package_terminals.len(), 1);
    assert_eq!(
        sinks.package_terminals[0].payload,
        vec![Expr::Path(vec!["result".into(), "value".into()])]
    );
    assert_eq!(sinks.effects.len(), 1);
    let source = format!(
        r#"{HEADER}class Empty {{}}
rule run when started => {{ tell unsafe "draft" as raw
 case raw {{ "yes" => {{ record Empty {{}} }} _ => {{ timer 1s as wait }} }} }}"#
    );
    let plan = typed(&source);
    let ir = compiled(&format!(
        "{HEADER}class Empty {{}}\nrule run when started => {{ timer 1s as wait }}"
    ));
    let policy = policy("grant fact empty -> fact:Empty from Operator");
    let errors = check_local_sinks(&plan, &ir, &policy);
    assert_eq!(errors.len(), 1, "{errors:?}");
}

#[test]
fn managed_sink_inventory_refuses_missing_or_ambiguous_destination_context() {
    let plan = terminal_plan("complete result from result {}");
    let mut ir = terminal_context();
    let class = ir
        .schemas
        .iter()
        .find(|s| matches!(s, IrSchema::Class(c) if c.name == "Output"))
        .unwrap()
        .clone();
    ir.schemas.push(class);
    assert!(inventory(&plan, &ir)
        .unwrap_err()
        .message
        .contains("one class declaration"));
    ir.schemas
        .retain(|s| !matches!(s, IrSchema::Class(c) if c.name == "Output"));
    assert!(inventory(&plan, &ir)
        .unwrap_err()
        .message
        .contains("one class declaration"));
    ir = terminal_context();
    ir.workflow_contracts.push(
        ir.workflow_contracts
            .iter()
            .find(|contract| contract.kind == IrWorkflowContractKind::Output)
            .unwrap()
            .clone(),
    );
    assert!(inventory(&plan, &ir)
        .unwrap_err()
        .message
        .contains("one matching contract"));
    ir.workflow_contracts.clear();
    assert!(inventory(&plan, &ir)
        .unwrap_err()
        .message
        .contains("one matching contract"));
    ir = terminal_context();
    ir.rules.push(
        ir.rules
            .iter()
            .find(|rule| rule.name == "run")
            .unwrap()
            .clone(),
    );
    assert!(inventory(&plan, &ir)
        .unwrap_err()
        .message
        .contains("one matching rule"));
    ir.rules.clear();
    assert!(inventory(&plan, &ir)
        .unwrap_err()
        .message
        .contains("one matching rule"));
    let mut bad = plan.clone();
    bad.plan.nodes[0].block = whipplescript_parser::action_plan::BlockId(usize::MAX);
    assert!(inventory(&bad, &terminal_context()).is_err());
    let program = whipplescript_parser::parse_program(
        "workflow Demo\naction empty() -> string { return \"constant\" }",
    )
    .program;
    let actions = program
        .items
        .iter()
        .filter_map(|item| match item {
            whipplescript_parser::Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let plan = TypedActionPlan {
        plan: whipplescript_parser::action_plan::expand_syntax(&actions, "empty").unwrap(),
        case_types: BTreeMap::new(),
        effects: BTreeMap::new(),
        views: BTreeMap::new(),
    };
    assert!(inventory(&plan, &terminal_context())
        .unwrap_err()
        .message
        .contains("root rule"));
}

#[test]
fn managed_sink_inventory_reports_authored_missing_class_with_call_chain() {
    let source = format!(
        r#"{HEADER}
action publish() -> null {{ record Output {{ value "constant" }}
 return null }}
rule run when started => {{ publish() as result }}"#
    );
    let plan = typed(&source);
    let mut ir = context("started");
    ir.schemas
        .retain(|s| !matches!(s, IrSchema::Class(c) if c.name == "Output"));
    let error = inventory(&plan, &ir).unwrap_err();
    assert!(source[error.span.start..error.span.end].contains("record Output"));
    assert!(error
        .related
        .iter()
        .any(|r| r.message == "call to action `publish`"));
}

#[test]
fn managed_sink_inventory_refuses_malformed_terminal_payloads() {
    let env = whipplescript_parser::action_plan::Environment::new();
    let ir = terminal_context();
    let plan = terminal_plan("complete result from result {}");
    let terminal = plan
        .plan
        .nodes
        .iter()
        .find_map(|node| match &node.kind {
            NodeKind::Statement(body) => match body.as_ref() {
                BodyStmt::Terminal(t) => Some(t.clone()),
                _ => None,
            },
            _ => None,
        })
        .unwrap();
    let mut bad = terminal.clone();
    bad.scalar = Some(FieldValue::Expr {
        source: "null".into(),
        expr: Expr::Literal(ExprLiteral::Null),
    });
    assert!(terminal_payload(&bad, ProgramContext::Legacy(&ir), &env)
        .unwrap_err()
        .message
        .contains("mixes"));
    bad.from = None;
    bad.fields.push(whipplescript_parser::body::FieldAssign {
        name: "value".into(),
        value: FieldValue::Expr {
            source: "null".into(),
            expr: Expr::Literal(ExprLiteral::Null),
        },
        span: bad.span,
    });
    assert!(terminal_payload(&bad, ProgramContext::Legacy(&ir), &env)
        .unwrap_err()
        .message
        .contains("mixes"));
    bad.fields.clear();
    bad.scalar = Some(FieldValue::Shorthand);
    assert!(terminal_payload(&bad, ProgramContext::Legacy(&ir), &env)
        .unwrap_err()
        .message
        .contains("must be an expression"));
    bad = terminal;
    bad.kind = TerminalKind::Fail;
    bad.name = "rejected".into();
    assert!(terminal_payload(&bad, ProgramContext::Legacy(&ir), &env)
        .unwrap_err()
        .message
        .contains("requires a class contract"));
}
