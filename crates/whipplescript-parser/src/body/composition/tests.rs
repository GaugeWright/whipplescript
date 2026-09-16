use super::*;
use crate::body::{parse_action_body, parse_composed_rule_body, parse_rule_body, BodyBase};

fn parse(source: &str) -> Vec<BodyStmt> {
    let (body, diagnostics) = parse_action_body(source, 100);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    body.statements
}

#[test]
fn return_and_domain_fail_are_distinct_from_workflow_terminals() {
    let statements = parse("return ticket.summary\nfail problem");
    let BodyStmt::Composition(CompositionStmt::Return(value)) = &statements[0] else {
        panic!("action return")
    };
    assert_eq!(value.source, "ticket.summary");
    assert_eq!(
        value.span,
        SourceSpan {
            start: 107,
            end: 121
        }
    );
    assert!(matches!(
        statements[1],
        BodyStmt::Composition(CompositionStmt::Fail(_))
    ));
    let (_, diagnostics) = parse_action_body("complete result { value 42 }", 0);
    assert!(diagnostics
        .iter()
        .any(|d| d.message == "an action cannot complete its containing workflow"));
}

#[test]
fn calls_keep_argument_expression_trees_and_locations() {
    let statements = parse("review(ticket, count([1, 2]), \"comma, inside\") as result");
    let BodyStmt::Composition(CompositionStmt::Call {
        name,
        arguments,
        binding,
        name_span,
        ..
    }) = &statements[0]
    else {
        panic!("call")
    };
    assert_eq!(name, "review");
    assert_eq!(
        name_span,
        &SourceSpan {
            start: 100,
            end: 106
        }
    );
    assert_eq!(
        arguments
            .iter()
            .map(|e| e.source.as_str())
            .collect::<Vec<_>>(),
        ["ticket", "count([1, 2])", "\"comma, inside\""]
    );
    assert_eq!(binding.as_deref(), Some("result"));
}

#[test]
fn then_preserves_its_operand_instead_of_becoming_source_order() {
    for source in ["then reviewed <- review(ticket)", "then waited <- timer 1s"] {
        let statements = parse(source);
        let BodyStmt::Composition(CompositionStmt::Then { operation, .. }) = &statements[0] else {
            panic!("then")
        };
        assert!(matches!(
            operation.as_ref(),
            BodyStmt::Effect(_) | BodyStmt::Composition(CompositionStmt::Call { .. })
        ));
    }
    for source in ["then x <- review(ticket) as y", "then x <- timer 1s as y"] {
        let (_, diagnostics) = parse_action_body(source, 0);
        assert!(
            diagnostics
                .iter()
                .any(|d| d.message.contains("already binds the result")),
            "{source}: {diagnostics:?}"
        );
    }
    let (_, diagnostics) = parse_action_body("then x <- return 42", 0);
    assert!(diagnostics
        .iter()
        .any(|d| d.message == "`then` must sequence an effect or action call"));
}

#[test]
fn then_satisfies_only_the_operand_binding_requirement() {
    for (source, message) in [
        ("then waited <- timer 0s", "invalid timer duration"),
        (
            "then waited <- timer until \"tomorrow\"",
            "invalid time literal",
        ),
        (
            "then items <- exec \"list.sh\" -> each WorkItem",
            "produces a stream of facts",
        ),
    ] {
        let (_, diagnostics) = parse_action_body(source, 0);
        assert!(
            diagnostics.iter().any(|d| d.message.contains(message)),
            "{source}: {diagnostics:?}"
        );
    }
    // The implicit binding ends with its operand; it cannot excuse the next
    // sibling's required binding.
    let (_, diagnostics) = parse_action_body("then first <- timer 1s\ntimer 2s", 0);
    assert!(diagnostics
        .iter()
        .any(|d| d.message == "`timer` requires an `as` binding"));
}

#[test]
fn ordinary_branches_and_after_blocks_contain_typed_action_nodes() {
    let statements = parse("after work succeeds as output {\n case output.status {\n ok => { then assessed <- assess(output)\n return assessed }\n bad => { fail output.problem }\n }\n}");
    let BodyStmt::After(after) = &statements[0] else {
        panic!("after")
    };
    let BodyStmt::Case(case) = &after.body[0] else {
        panic!("case")
    };
    assert!(matches!(
        case.branches[0].body[0],
        BodyStmt::Composition(CompositionStmt::Then { .. })
    ));
    assert!(matches!(
        case.branches[1].body[0],
        BodyStmt::Composition(CompositionStmt::Fail(_))
    ));
}

#[test]
fn lexical_failure_handlers_are_structured_and_round_trip() {
    let source = "timer 1s as work\non failure as problem {\n timer 2s as cleanup\n return problem.summary\n}\n";
    let statements = parse(source);
    let BodyStmt::Composition(CompositionStmt::OnFailure {
        alias, body, span, ..
    }) = &statements[1]
    else {
        panic!("failure handler")
    };
    assert_eq!(alias, "problem");
    assert_eq!(body.len(), 2);
    assert_eq!(
        &source[span.start - 100..span.end - 100],
        source.trim_end().split_once('\n').unwrap().1
    );
    let mut printed = String::new();
    for statement in &statements {
        crate::body_print::print_statement_rn(statement, 0, &str::to_owned, &mut printed);
    }
    let (again, diagnostics) = parse_action_body(&printed, 0);
    assert!(diagnostics.is_empty(), "{printed}: {diagnostics:?}");
    assert!(matches!(
        again.statements[1],
        BodyStmt::Composition(CompositionStmt::OnFailure { .. })
    ));
    for malformed in [
        "on failure { return 1 }",
        "on failure as { return 1 }",
        "on problem as failure { return 1 }",
    ] {
        assert!(!parse_action_body(malformed, 0).1.is_empty(), "{malformed}");
    }
}

#[test]
fn composed_rules_parse_scope_failure_handlers_with_sibling_work() {
    let source =
        "timer 1s as primary\ntimer 2s as sibling\non failure as problem { timer 3s as cleanup }";
    let (body, diagnostics) = parse_composed_rule_body(source, 0);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert_eq!(body.statements.len(), 3);
    assert!(matches!(
        body.statements[2],
        BodyStmt::Composition(CompositionStmt::OnFailure { .. })
    ));
}

#[test]
fn malformed_calls_and_arrows_have_errors_and_terminate() {
    for source in [
        "review(ticket other)",
        "review(ticket",
        "review(,)",
        "then x < review()",
        "then x - review()",
        "return",
        "fail",
    ] {
        let (_, diagnostics) = parse_action_body(source, 0);
        assert!(!diagnostics.is_empty(), "{source}");
    }
}

#[test]
fn legacy_rule_parser_does_not_reinterpret_actions_or_workflow_fail() {
    let (_, diagnostics) = parse_rule_body("return result", 0);
    assert!(!diagnostics.is_empty());
    let (_, diagnostics) = parse_rule_body("review(ticket)", 0);
    assert!(!diagnostics.is_empty());
    let (body, diagnostics) = parse_rule_body("fail problem { reason \"broken\" }", 0);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert!(matches!(body.statements[0], BodyStmt::Terminal(_)));
}

#[test]
fn composition_reprints_inside_shared_bodies_without_losing_semantics() {
    let source =
        "then reviewed <- review(ticket, 42)\nafter turn succeeds as output {\n return output\n}\n";
    let (body, diagnostics) = parse_action_body(source, 0);
    assert!(diagnostics.is_empty());
    let mut printed = String::new();
    for statement in &body.statements {
        crate::body_print::print_statement_rn(statement, 0, &str::to_owned, &mut printed);
    }
    let (reparsed, diagnostics) = parse_action_body(
        &printed,
        BodyBase::Generated(SourceSpan { start: 0, end: 0 }),
    );
    assert!(diagnostics.is_empty(), "{printed}: {diagnostics:?}");
    assert!(matches!(
        reparsed.statements[0],
        BodyStmt::Composition(CompositionStmt::Then { .. })
    ));
    let mut again = String::new();
    for statement in &reparsed.statements {
        crate::body_print::print_statement_rn(statement, 0, &str::to_owned, &mut again);
    }
    assert_eq!(printed, again);
}

#[test]
fn unexpanded_action_nodes_cannot_bypass_legacy_authority_checks() {
    use std::collections::{BTreeMap, BTreeSet};
    let parsed = crate::parse_program(
        "workflow Demo\nview observe when started => { record X { value 1 } }",
    );
    let crate::Item::Rule(rule) = &parsed.program.items[0] else {
        panic!("view")
    };
    let statements = parse("review(ticket)");
    let semantic = crate::SemanticContext::from_program(&parsed.program, BTreeMap::new());
    let mut diagnostics = Vec::new();
    crate::validate_view_body(rule, &statements, &mut diagnostics);
    crate::validate_confinement(
        rule,
        &statements,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &mut diagnostics,
    );
    crate::validate_conditioned_field_reads(
        rule,
        &statements,
        &semantic,
        &BTreeMap::new(),
        &BTreeSet::new(),
        &mut diagnostics,
    );
    assert_eq!(diagnostics.len(), 3);
    assert!(diagnostics
        .iter()
        .all(|d| d.message.contains("must be expanded before rule authority")));
}

#[test]
fn composed_rule_calls_preserve_workflow_terminals_and_refuse_action_returns() {
    let source = "then answer <- work(42)\ncomplete result answer\nfail error \"failure\"";
    let (ast, diagnostics) = crate::body::parse_composed_rule_body(source, 0);
    assert!(diagnostics.is_empty(), "{diagnostics:?}");
    assert!(matches!(
        ast.statements[0],
        BodyStmt::Composition(CompositionStmt::Then { .. })
    ));
    assert!(matches!(ast.statements[1], BodyStmt::Terminal(_)));
    assert!(matches!(ast.statements[2], BodyStmt::Terminal(_)));
    let (_, diagnostics) = crate::body::parse_composed_rule_body("return 42", 0);
    assert!(diagnostics
        .iter()
        .any(|d| d.message == "a rule cannot return an action result"));
    let (_, diagnostics) =
        crate::body::parse_composed_rule_body("then result <- complete output 42", 0);
    assert!(diagnostics
        .iter()
        .any(|d| d.message == "`then` must sequence an effect or action call"));
    let (_, diagnostics) = parse_rule_body("work(42)", 0);
    assert!(
        !diagnostics.is_empty(),
        "legacy executable parsing must still refuse unexpanded calls"
    );
}
