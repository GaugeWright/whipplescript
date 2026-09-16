use super::*;
use crate::{parse_program, Item};

fn definitions(source: &str) -> Vec<ActionDecl> {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    parsed
        .program
        .items
        .into_iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action),
            _ => None,
        })
        .collect()
}
fn plan(source: &str, entry: &str) -> ActionPlan {
    let p = expand_syntax(&definitions(source), entry).expect("syntax plan expands");
    p.validate_structure()
        .expect("expanded graph is structurally valid");
    p
}
fn statements(plan: &ActionPlan, scope: usize) -> Vec<&Node> {
    plan.blocks[plan.scopes[scope].entry.0]
        .nodes
        .iter()
        .map(|id| &plan.nodes[id.0])
        .collect()
}

#[test]
fn repeated_calls_have_distinct_parameters_results_and_provenance() {
    let source = "workflow Demo\naction leaf(value string) -> string { return value }\naction root(value string) -> string { leaf(value) as first\nleaf(\"second\") as second\nreturn first }";
    let p = plan(source, "root");
    assert_eq!(p.scopes.len(), 3);
    let root = statements(&p, 0);
    let NodeKind::Call {
        scope: first,
        arguments,
    } = &root[0].kind
    else {
        panic!("call")
    };
    assert_eq!(arguments[0].value.source, "value");
    assert_eq!(arguments[0].environment["value"], p.scopes[0].parameters[0]);
    let NodeKind::Call {
        scope: second,
        arguments,
    } = &root[1].kind
    else {
        panic!("call")
    };
    assert_eq!(arguments[0].value.source, "\"second\"");
    assert_ne!(first, second);
    assert_ne!(p.scopes[first.0].parameters, p.scopes[second.0].parameters);
    assert_ne!(root[0].result, root[1].result);
    for child in [first, second] {
        let scope = &p.scopes[child.0];
        let definition = scope.definition_span;
        assert_eq!(&source[definition.start..definition.end], "leaf");
        let call = &p.nodes[scope.parent_call.unwrap().0];
        assert!(source[call.span.start..call.span.end].starts_with("leaf("));
        assert_eq!(
            p.blocks[scope.entry.0].environment["value"],
            scope.parameters[0]
        );
        assert!(!p.blocks[scope.entry.0].environment.contains_key("first"));
    }
    assert_eq!(p.scopes[0].operations.len(), 2);
    assert!(p.scopes[first.0].operations.is_empty());
    assert_eq!(p, plan(source, "root"));
}

#[test]
fn callee_globals_do_not_capture_caller_locals() {
    let source = "workflow Demo\nenum Status { ready }\naction root(ready string) -> Status { child() as result\nreturn result }\naction child() -> Status { return ready }";
    let p = plan(source, "root");
    assert!(p.blocks[p.scopes[0].entry.0]
        .environment
        .contains_key("ready"));
    assert!(p.blocks[p.scopes[1].entry.0].environment.is_empty());
    let NodeKind::Return(value) = &statements(&p, 1)[0].kind else {
        panic!("return")
    };
    assert_eq!(value.source, "ready");
    let output = crate::compile_program(source);
    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    assert!(output.ir.is_some());
    assert!(output.typed_actions.is_some());
}

#[test]
fn effect_payloads_field_keys_prose_and_interpolations_are_not_rewritten() {
    let source = "workflow Demo\naction leaf(provider string) -> string { tell reviewer as turn \"provider {{ provider }}\"\nrecord Note { provider provider }\nreturn provider }\naction root(provider string) -> string { leaf(provider) as result\nreturn result }";
    let actions = definitions(source);
    let p = expand_syntax(&actions, "root").unwrap();
    let (ast, errors) = body::parse_action_body(&actions[0].body.text, actions[0].body.body_base());
    assert!(errors.is_empty());
    for (node, original) in statements(&p, 1).into_iter().take(2).zip(&ast.statements) {
        assert_eq!(&node.kind, &NodeKind::Statement(Box::new(original.clone())));
    }
    let BodyStmt::Record(record) = &ast.statements[1] else {
        panic!("record")
    };
    assert_eq!(record.fields[0].name, "provider");
    assert_eq!(
        p.bindings[p.scopes[1].parameters[0].0].name.as_deref(),
        Some("provider")
    );
}

#[test]
fn then_adds_a_success_barrier_without_serializing_plain_bindings() {
    let source = "workflow Demo\naction leaf(value string) -> string { return value }\naction root() -> string { prompt \"a\" as a\nprompt \"b\" as b\nthen c <- leaf(a)\nprompt \"d\" as d\nthen e <- leaf(b)\nreturn c }";
    let p = plan(source, "root");
    let ids = &p.blocks[p.scopes[0].entry.0].nodes;
    let nodes = statements(&p, 0);
    assert_eq!(
        nodes.iter().map(|n| n.order_after).collect::<Vec<_>>(),
        [None, None, None, Some(ids[2]), Some(ids[2]), Some(ids[4])]
    );
    assert_eq!(p.scopes[0].operations, ids[..5]);
    assert_eq!(
        p.blocks[p.scopes[0].entry.0].environment["c"],
        nodes[2].result.unwrap()
    );
    assert!(statements(&p, 1)
        .iter()
        .all(|node| node.order_after.is_none()));
}

#[test]
fn sibling_continuation_aliases_shadow_only_their_own_blocks() {
    let source = "workflow Demo\naction root(value string) -> string { prompt \"go\" as turn\nafter turn succeeds as value { return value }\nafter turn fails as value { return \"fallback\" } }";
    let p = plan(source, "root");
    let nodes = statements(&p, 0);
    let NodeKind::After {
        observed: first_observed,
        alias: Some(first),
        body: first_body,
        ..
    } = nodes[1].kind
    else {
        panic!("after")
    };
    let NodeKind::After {
        observed: second_observed,
        alias: Some(second),
        body: second_body,
        ..
    } = nodes[2].kind
    else {
        panic!("after")
    };
    assert_eq!(first_observed, nodes[0].result.unwrap());
    assert_eq!(first_observed, second_observed);
    assert_ne!(first, second);
    assert_ne!(first, p.scopes[0].parameters[0]);
    assert_eq!(p.blocks[first_body.0].environment["value"], first);
    assert_eq!(p.blocks[second_body.0].environment["value"], second);
    assert_eq!(
        p.blocks[p.scopes[0].entry.0].environment["value"],
        p.scopes[0].parameters[0]
    );
    assert!(p.blocks[first_body.0]
        .nodes
        .iter()
        .all(|id| p.nodes[id.0].order_after.is_none()));
}

#[test]
fn case_guards_keep_pattern_scope_and_cannot_capture_body_locals() {
    let source = "workflow Demo\naction root(ticket Ticket, check bool) -> string { case ticket { Ticket as item where item.title == \"x\" and check => { prompt \"inside\" as check\nreturn item.title } _ => { return \"fallback\" } } }";
    let p = plan(source, "root");
    let NodeKind::Case {
        scrutinee,
        branches,
    } = &statements(&p, 0)[0].kind
    else {
        panic!("case")
    };
    assert_eq!(scrutinee, "ticket");
    assert_eq!(
        branches[0].guard.as_deref(),
        Some("item.title == \"x\" and check")
    );
    assert_eq!(
        branches[0].guard_environment["item"],
        branches[0].binding.unwrap()
    );
    assert_eq!(
        branches[0].guard_environment["check"],
        p.scopes[0].parameters[1]
    );
    assert_ne!(
        p.blocks[branches[0].body.0].environment["check"],
        branches[0].guard_environment["check"]
    );
    assert!(!branches[1].guard_environment.contains_key("item"));
    assert!(!p.blocks[branches[1].body.0]
        .environment
        .contains_key("item"));
}

#[test]
fn region_polarity_conditions_and_lapse_scopes_survive_expansion() {
    let source = "workflow Demo\naction root(gate bool) -> string { until gate { prompt \"held\" as held\nreturn held } on lapse as progress { return \"lapsed\" } }";
    let p = plan(source, "root");
    let NodeKind::Region {
        until,
        condition,
        body,
        lapse_binding,
        lapse_body,
    } = &statements(&p, 0)[0].kind
    else {
        panic!("region")
    };
    assert!(*until);
    assert_eq!(condition, "gate");
    assert!(!p.blocks[body.0].environment.contains_key("progress"));
    assert_eq!(
        p.blocks[lapse_body.0].environment["progress"],
        lapse_binding.unwrap()
    );
    assert!(!p.blocks[lapse_body.0].environment.contains_key("held"));
    assert_eq!(p.scopes[0].operations.len(), 1);
    // Preserving region structure is not evidence of runtime entry/lapse closure.
    let compiled = crate::compile_program(source);
    assert!(compiled.ir.is_none());
}

#[test]
fn identical_generated_spans_do_not_merge_scope_or_binding_sites() {
    let source = "workflow Demo\naction leaf(x string) -> string { return x }\naction root(x string) -> string { leaf(x) as a\nleaf(x) as b\nreturn a }";
    let mut actions = definitions(source);
    for action in &mut actions {
        let text = action.body.text.to_string();
        action.body.rewrite(format!("\n{text}"));
    }
    let p = expand_syntax(&actions, "root").unwrap();
    let nodes = statements(&p, 0);
    assert_eq!(nodes[0].span, nodes[1].span);
    assert_ne!(nodes[0].result, nodes[1].result);
    assert_ne!(p.scopes[1].parameters, p.scopes[2].parameters);
    assert_ne!(p.scopes[1].parent_call, p.scopes[2].parent_call);
}

#[test]
fn long_finite_nested_calls_expand_without_recursive_ownership() {
    let mut source = String::from("workflow Demo\n");
    for index in 0..2049 {
        source.push_str(&format!("action f{index}(value string) -> string {{\n"));
        if index == 2048 {
            source.push_str("return value\n");
        } else {
            source.push_str(&format!("f{}(value) as next\nreturn next\n", index + 1));
        }
        source.push_str("}\n");
    }
    let p = plan(&source, "f0");
    assert_eq!(p.scopes.len(), 2049);
    assert_eq!(
        p.scopes
            .iter()
            .filter(|scope| scope.parent_call.is_none())
            .count(),
        1
    );
    assert_eq!(
        p.scopes
            .iter()
            .map(|scope| scope.operations.len())
            .sum::<usize>(),
        2048
    );
}

#[test]
fn invalid_or_unused_definitions_cannot_hide_a_bad_expansion() {
    for (source, entry, message) in [
        ("action root() { return null }", "root", "needs a result contract"),
        ("action root() -> null { return null }", "missing", "unknown entry action"),
        ("action root() -> null { root()\nreturn null }", "root", "recursive"),
        ("action root() -> null { return null }\naction unused() -> null { absent()\nreturn null }", "root", "unknown action"),
        ("action root() -> null { return null }\naction unused() -> null { root(42)\nreturn null }", "root", "expects 0 argument"),
        ("action root() -> null { after missing succeeds { return null } }", "root", "unknown action binding"),
    ] {
        let errors = expand_syntax(&definitions(&format!("workflow Demo\n{source}")), entry).unwrap_err();
        assert!(errors.iter().any(|d| d.message.contains(message)), "{source}: {errors:?}");
    }
}

#[test]
fn duplicate_local_declarations_have_both_source_locations() {
    for body in [
        "prompt \"a\" as x\nprompt \"b\" as x\nreturn x",
        "then x <- prompt \"a\"\nthen x <- prompt \"b\"\nreturn x",
        "prompt \"a\" as work\nafter work succeeds as x { prompt \"b\" as x\nreturn x }",
        "case true { true as x => { prompt \"a\" as x\nreturn x } false => { return \"b\" } }",
    ] {
        let source = format!("workflow Demo\naction root() -> string {{ {body} }}");
        let errors = expand_syntax(&definitions(&source), "root").unwrap_err();
        let error = errors
            .iter()
            .find(|error| error.message.contains("duplicate binding"))
            .unwrap();
        assert_eq!(error.related.len(), 1);
        assert_ne!(error.span, error.related[0].span);
        let compiled = crate::compile_program(&source);
        assert!(compiled.ir.is_none());
        assert!(
            compiled
                .diagnostics
                .iter()
                .any(|d| d.message.contains("duplicate binding")),
            "{:?}",
            compiled.diagnostics
        );
    }
    let source = "workflow Demo\naction root(x string) -> string { prompt \"a\" as x\nreturn x }";
    let errors = expand_syntax(&definitions(source), "root").unwrap_err();
    assert!(errors
        .iter()
        .any(|error| error.message.contains("duplicate binding")));
}

fn calling_rule(source: &str) -> RuleDecl {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    parsed
        .program
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .expect("calling rule")
}

#[test]
fn calling_rule_remains_a_rule_with_its_own_inputs_and_workflow_terminal() {
    let source = "workflow Demo\naction leaf(value string) -> string { return value }\nrule run\nwhen Ticket as ticket\n=> { leaf(ticket.title) as first\nthen second <- leaf(first)\ncomplete result second }";
    let rule = calling_rule(source);
    let inputs = [Ident {
        name: "ticket".into(),
        span: rule.whens[0].span,
    }];
    let p = expand_rule_syntax(&definitions(source), &rule, &inputs).unwrap();
    assert_eq!(p.root_rule.as_ref(), Some(&rule.name));
    assert_eq!(p.scopes.len(), 2, "no synthetic action wraps the rule");
    let root = &p.blocks[p.root.0];
    assert_eq!(root.scope, None);
    assert_eq!(root.environment["ticket"], p.root_inputs[0]);
    assert!(matches!(
        p.bindings[p.root_inputs[0].0].source,
        BindingSource::RuleInput { index: 0 }
    ));
    let first = &p.nodes[root.nodes[0].0];
    let second = &p.nodes[root.nodes[1].0];
    let terminal = &p.nodes[root.nodes[2].0];
    let NodeKind::Call { scope, arguments } = &first.kind else {
        panic!("call")
    };
    assert_eq!(arguments[0].value.source, "ticket.title");
    assert_eq!(arguments[0].environment["ticket"], p.root_inputs[0]);
    assert!(!p.blocks[p.scopes[scope.0].entry.0]
        .environment
        .contains_key("ticket"));
    let NodeKind::Call { arguments, .. } = &second.kind else {
        panic!("call")
    };
    assert_eq!(arguments[0].environment["first"], first.result.unwrap());
    assert_eq!(
        second.order_after, None,
        "data use is not a whole-block barrier"
    );
    assert_eq!(terminal.order_after, Some(root.nodes[1]));
    let NodeKind::Statement(statement) = &terminal.kind else {
        panic!("workflow terminal")
    };
    assert!(matches!(statement.as_ref(), BodyStmt::Terminal(_)));
    assert!(p.scopes.iter().all(|scope| scope.parent_call.is_some()));
}

#[test]
fn calling_rule_plan_owns_one_scope_failure_handler() {
    let source = "workflow Demo\nrule run\nwhen started\n=> { timer 1s as primary\ntimer 2s as sibling\non failure as problem { timer 3s as cleanup } }";
    let rule = calling_rule(source);
    let p = expand_rule_syntax(&[], &rule, &[]).unwrap();
    assert_eq!(p.operation_nodes(None).len(), 3);
    let root = &p.blocks[p.root.0];
    let handler = &p.nodes[root.nodes[2].0];
    let NodeKind::OnFailure { alias, body } = handler.kind else {
        panic!("rule failure handler")
    };
    assert_eq!(p.blocks[body.0].scope, None);
    assert!(matches!(
        p.bindings[alias.0].source,
        BindingSource::FailureHandler { .. }
    ));
    p.validate_structure().unwrap();
}

#[test]
fn caller_continuation_aliases_are_available_to_arguments_but_not_callees() {
    let source = "workflow Demo\naction leaf(value string) -> string { return value }\nrule run\nwhen started\n=> { prompt \"start\" as task\nafter task succeeds as value { leaf(value) as result\ncomplete done result } }";
    let p = expand_rule_syntax(&definitions(source), &calling_rule(source), &[]).unwrap();
    let root = &p.blocks[p.root.0];
    let NodeKind::After {
        alias: Some(alias),
        body,
        ..
    } = p.nodes[root.nodes[1].0].kind
    else {
        panic!("continuation")
    };
    assert_eq!(p.blocks[body.0].scope, None);
    let NodeKind::Call { scope, arguments } = &p.nodes[p.blocks[body.0].nodes[0].0].kind else {
        panic!("call")
    };
    assert_eq!(arguments[0].environment["value"], alias);
    assert_ne!(
        p.blocks[p.scopes[scope.0].entry.0].environment["value"],
        alias
    );
}

#[test]
fn caller_body_and_input_errors_refuse_before_expansion() {
    for (body, expected) in [
        ("missing()", "unknown action"),
        ("leaf(1, 2)", "expects 1 argument"),
        ("return 42", "a rule cannot return an action result"),
        ("leaf(1) as result\nleaf(2) as result", "duplicate binding"),
    ] {
        let source = format!("workflow Demo\naction leaf(x int) -> int {{ return x }}\nrule run\nwhen started\n=> {{ {body} }}");
        let errors =
            expand_rule_syntax(&definitions(&source), &calling_rule(&source), &[]).unwrap_err();
        assert!(
            errors.iter().any(|d| d.message.contains(expected)),
            "{errors:?}"
        );
    }
    let source = "workflow Demo\nrule run\nwhen started\n=> {}";
    let rule = calling_rule(source);
    let input = Ident {
        name: "duplicate".into(),
        span: rule.whens[0].span,
    };
    let errors = expand_rule_syntax(&[], &rule, &[input.clone(), input]).unwrap_err();
    assert!(errors
        .iter()
        .any(|d| d.message.contains("duplicate rule input")));
    let source = "workflow Demo\nrule run\nwhen Ticket as ticket\n=> { prompt \"bad\" as ticket }";
    let rule = calling_rule(source);
    let input = Ident {
        name: "ticket".into(),
        span: rule.whens[0].span,
    };
    let errors = expand_rule_syntax(&[], &rule, &[input]).unwrap_err();
    assert!(errors
        .iter()
        .any(|d| d.message.contains("duplicate binding")));
}

#[test]
fn every_duplicate_points_back_to_the_first_local_declaration() {
    let source = "workflow Demo\naction root() -> string { prompt \"first\" as x\nprompt \"second\" as x\nprompt \"third\" as x\nreturn x }";
    let errors = expand_syntax(&definitions(source), "root").unwrap_err();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].related[0].span, errors[1].related[0].span);
    let first = errors[0].related[0].span;
    assert!(source[first.start..first.end].contains("first"));
}

#[test]
fn discarded_bindings_do_not_detach_calls_or_external_work() {
    let source = "workflow Demo\naction root() -> string { leaf()\nreturn \"candidate\" }\naction leaf() -> string { tell worker \"owned\"\nreturn \"leaf candidate\" }";
    let p = plan(source, "root");
    assert_eq!(p.scopes[0].operations.len(), 1);
    assert_eq!(p.scopes[1].operations.len(), 1);
    for scope in &p.scopes {
        let operation = &p.nodes[scope.operations[0].0];
        let binding = &p.bindings[operation.result.unwrap().0];
        assert_eq!(binding.name, None);
        assert!(matches!(binding.source, BindingSource::Node(_)));
        assert!(p.blocks[scope.entry.0].environment.is_empty());
    }
    assert_eq!(p.scopes[1].parent_call, Some(p.scopes[0].operations[0]));
}

#[test]
fn domain_failure_keeps_its_action_boundary_and_workflow_failure_stays_outside() {
    let source = "workflow Demo\naction leaf() -> null ! string { fail \"domain\" }\nrule run\nwhen started\n=> { leaf()\nfail error \"workflow\" }";
    let p = expand_rule_syntax(&definitions(source), &calling_rule(source), &[]).unwrap();
    assert!(p.scopes[0].result.failure.is_some());
    let domain = &p.nodes[p.blocks[p.scopes[0].entry.0].nodes[0].0];
    let NodeKind::Fail(value) = &domain.kind else {
        panic!("action failure")
    };
    assert_eq!(value.source, "\"domain\"");
    let workflow = &p.nodes[p.blocks[p.root.0].nodes[1].0];
    let NodeKind::Statement(statement) = &workflow.kind else {
        panic!("workflow failure")
    };
    assert!(matches!(statement.as_ref(), BodyStmt::Terminal(_)));
    assert_eq!(p.blocks[workflow.block.0].scope, None);
    assert_eq!(p.blocks[domain.block.0].scope, Some(ScopeId(0)));
}

#[test]
fn plan_artifact_structure_refuses_corrupt_ownership_bindings_and_order() {
    let p = plan(
        r#"workflow Demo
      action leaf(value string) -> string { return value }
      action root(value string, gate bool) -> string {
        leaf(value) as first
        then second <- leaf(first)
        after second fails as problem { leaf(problem) as recovered
          return recovered }
        case gate { true as choice => { return value } _ => { return first } }
        during gate { leaf(value) as held } on lapse as progress { return value }
        return second
      }"#,
        "root",
    );
    let root = p.root.0;
    let nodes = p.blocks[root].nodes.clone();
    let first = nodes[0].0;
    let second = nodes[1].0;
    let after = nodes[2].0;
    let case = nodes[3].0;
    let region = nodes[4].0;
    let ret = nodes[5].0;
    let parameter = p.root_inputs[0].0;
    let result = p.nodes[first].result.unwrap().0;
    let NodeKind::Call { scope: callee, .. } = p.nodes[first].kind else {
        panic!("call")
    };
    let child_block = p.scopes[callee.0].entry.0;
    let NodeKind::After {
        alias: Some(alias),
        body: after_body,
        ..
    } = p.nodes[after].kind
    else {
        panic!("after")
    };
    let NodeKind::Case { branches, .. } = &p.nodes[case].kind else {
        panic!("case")
    };
    let case_binding = branches[0].binding.unwrap().0;
    let NodeKind::Region {
        lapse_binding: Some(lapse),
        ..
    } = p.nodes[region].kind
    else {
        panic!("region")
    };
    let value = serde_json::to_value(&p).unwrap();
    let cases = [
        ("/root".into(), serde_json::json!(999)),
        ("/root_inputs".into(), serde_json::json!([])),
        (format!("/blocks/{root}/scope"), serde_json::json!(null)),
        (format!("/blocks/{root}/nodes/0"), serde_json::json!(999)),
        (format!("/blocks/{root}/nodes/1"), serde_json::json!(first)),
        (
            format!("/nodes/{first}/block"),
            serde_json::json!(child_block),
        ),
        (format!("/nodes/{first}/result"), serde_json::json!(null)),
        (
            format!("/nodes/{first}/span/start"),
            serde_json::json!(usize::MAX),
        ),
        (
            format!("/nodes/{first}/order_after"),
            serde_json::json!(second),
        ),
        (
            format!("/nodes/{ret}/order_after"),
            serde_json::json!(region),
        ),
        (format!("/nodes/{ret}/result"), serde_json::json!(result)),
        (
            format!("/nodes/{first}/kind/Call/scope"),
            serde_json::json!(999),
        ),
        (
            format!("/nodes/{first}/kind/Call/arguments"),
            serde_json::json!([]),
        ),
        (
            format!("/nodes/{first}/kind/Call/arguments/0/environment"),
            serde_json::json!({}),
        ),
        (
            format!("/scopes/{}/parent_call", callee.0),
            serde_json::json!(second),
        ),
        (
            format!("/scopes/{}/entry", callee.0),
            serde_json::json!(root),
        ),
        (
            format!("/scopes/{}/parameters/0", callee.0),
            serde_json::json!(parameter),
        ),
        ("/scopes/0/operations".into(), serde_json::json!([])),
        ("/scopes/0/action".into(), serde_json::json!("")),
        (
            format!("/bindings/{parameter}/source/Parameter/index"),
            serde_json::json!(99),
        ),
        (
            format!("/bindings/{parameter}/name"),
            serde_json::json!(null),
        ),
        (
            format!("/bindings/{result}/source/Node"),
            serde_json::json!(second),
        ),
        (
            format!("/bindings/{result}/name"),
            serde_json::json!("value"),
        ),
        (format!("/bindings/{result}/name"), serde_json::json!("")),
        (
            format!("/bindings/{}/source/After/node", alias.0),
            serde_json::json!(first),
        ),
        (
            format!("/bindings/{case_binding}/source/Case/branch"),
            serde_json::json!(1),
        ),
        (
            format!("/bindings/{}/source/Lapse/node", lapse.0),
            serde_json::json!(first),
        ),
        (format!("/blocks/{root}/environment"), serde_json::json!({})),
        (
            format!("/blocks/{child_block}/environment/value"),
            serde_json::json!(parameter),
        ),
        (
            format!("/blocks/{}/scope", after_body.0),
            serde_json::json!(callee.0),
        ),
        (
            format!("/nodes/{after}/kind/After/body"),
            serde_json::json!(root),
        ),
        (
            format!("/nodes/{after}/kind/After/observed"),
            serde_json::json!(p.scopes[callee.0].parameters[0].0),
        ),
        (
            format!("/nodes/{case}/kind/Case/branches/0/guard_environment"),
            serde_json::json!({}),
        ),
        (
            format!("/nodes/{region}/kind/Region/lapse_body"),
            serde_json::json!(root),
        ),
    ];
    for (path, replacement) in cases {
        let mut bad = value.clone();
        *bad.pointer_mut(&path)
            .unwrap_or_else(|| panic!("missing test path {path}")) = replacement;
        let bad: ActionPlan = serde_json::from_value(bad).unwrap();
        let error = bad.validate_structure().expect_err(&path);
        assert!(
            !error.path.is_empty() && !error.message.is_empty(),
            "{path}"
        );
    }
    for collection in ["blocks", "nodes", "bindings", "scopes"] {
        let mut bad = value.clone();
        let list = bad[collection].as_array_mut().unwrap();
        list.push(list[0].clone());
        assert!(
            serde_json::from_value::<ActionPlan>(bad)
                .unwrap()
                .validate_structure()
                .is_err(),
            "orphan {collection}"
        );
    }
    let mut bad = p.clone();
    let duplicate = bad.scopes[0].operations[0];
    bad.scopes[0].operations.push(duplicate);
    assert!(
        bad.validate_structure().is_err(),
        "duplicate owned operation"
    );
    let mut bad = p.clone();
    bad.nodes[ret].kind = NodeKind::Statement(Box::new(BodyStmt::Composition(
        CompositionStmt::Return(if let NodeKind::Return(value) = &p.nodes[ret].kind {
            value.clone()
        } else {
            panic!("return")
        }),
    )));
    assert!(bad
        .validate_structure()
        .unwrap_err()
        .message
        .contains("unexpanded"));
}

#[test]
fn plan_artifact_rule_root_preserves_exact_admission_and_terminal_boundary() {
    let source = "workflow Demo\naction leaf(value string) -> string { return value }\nrule run when Ticket as ticket => { leaf(ticket.title) as result\ncomplete result result }";
    let rule = calling_rule(source);
    let inputs = [Ident {
        name: "ticket".into(),
        span: rule.whens[0].span,
    }];
    let p = expand_rule_syntax(&definitions(source), &rule, &inputs).unwrap();
    p.validate_structure().unwrap();
    let mut bad = p.clone();
    bad.bindings[p.root_inputs[0].0].source = BindingSource::RuleInput { index: 1 };
    assert!(bad.validate_structure().is_err());
    let terminal = p.nodes.iter().find(|node| matches!(&node.kind, NodeKind::Statement(s) if matches!(s.as_ref(), BodyStmt::Terminal(_)))).unwrap().kind.clone();
    let child_node = p.blocks[p.scopes[0].entry.0].nodes[0];
    let mut bad = p.clone();
    bad.nodes[child_node.0].kind = terminal;
    assert!(bad
        .validate_structure()
        .unwrap_err()
        .message
        .contains("workflow terminal"));
    let mut bad = p.clone();
    bad.nodes[p.blocks[p.root.0].nodes[1].0].kind = p.nodes[child_node.0].kind.clone();
    assert!(bad
        .validate_structure()
        .unwrap_err()
        .message
        .contains("outside an action"));
}
