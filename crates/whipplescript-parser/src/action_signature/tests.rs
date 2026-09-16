use super::*;
use crate::{compile_program, format_program, parse_program, Item};

fn declarations(source: &str) -> Vec<ActionDecl> {
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

#[test]
fn typed_action_header_preserves_compound_types_and_source_spans() {
    let source = "workflow Demo\naction review(ticket Ticket, optional string?) -> Review[] | null ! Rejected | Unavailable { return null }";
    let actions = declarations(source);
    let result = actions[0].result.as_ref().expect("typed result");
    assert_eq!(result.success.to_source(), "Review[] | null");
    assert_eq!(
        result.failure.as_ref().unwrap().to_source(),
        "Rejected | Unavailable"
    );
    let span = result.success.span();
    assert_eq!(&source[span.start..span.end], "Review[] | null");
    let span = result.failure.as_ref().unwrap().span();
    assert_eq!(&source[span.start..span.end], "Rejected | Unavailable");
    assert_eq!(actions[0].params[1].ty.to_source(), "string?");
}

#[test]
fn formatting_cannot_erase_the_result_or_failure_contract() {
    let source =
        "workflow Demo\naction review(ticket Ticket)->Review?!Rejected {\n return ticket\n}";
    let formatted = format_program(source).formatted.expect("formats");
    assert!(
        formatted.contains("action review(ticket Ticket) -> Review? ! Rejected {"),
        "{formatted}"
    );
    let reparsed = declarations(&formatted);
    assert_eq!(
        reparsed[0].result.as_ref().unwrap().success.to_source(),
        "Review?"
    );
    assert_eq!(
        reparsed[0]
            .result
            .as_ref()
            .unwrap()
            .failure
            .as_ref()
            .unwrap()
            .to_source(),
        "Rejected"
    );
    assert_eq!(
        format_program(&formatted).formatted.as_deref(),
        Some(formatted.as_str())
    );
}

#[test]
fn resultless_legacy_declarations_remain_distinct_from_null_results() {
    let actions =
        declarations("workflow Demo\naction legacy() {}\naction current() -> null { return null }");
    assert!(actions[0].result.is_none());
    assert_eq!(
        actions[1].result.as_ref().unwrap().success.to_source(),
        "null"
    );
    assert!(actions[1].result.as_ref().unwrap().failure.is_none());
}

#[test]
fn malformed_contracts_do_not_become_resultless_actions() {
    for header in [
        "action broken() ->",
        "action broken() ! Problem",
        "action broken() -> string !",
    ] {
        let parsed = parse_program(&format!("workflow Demo\n{header} {{ return null }}"));
        assert!(!parsed.diagnostics.is_empty(), "{header}");
    }
}

#[test]
fn direct_cycle_reports_the_call_and_definition_even_when_unused() {
    let source = "@service\nworkflow Demo\n# é\naction review() -> null { review() }";
    let compiled = compile_program(source);
    let diagnostic = compiled
        .diagnostics
        .iter()
        .find(|d| d.message.contains("recursive action expansion"))
        .expect("recursion refusal, not the pending-lowering fallback");
    assert_eq!(
        diagnostic.message,
        "recursive action expansion: review -> review"
    );
    assert_eq!(
        &source[diagnostic.span.start..diagnostic.span.end],
        "review"
    );
    assert_eq!(diagnostic.span.start, source.rfind("review()").unwrap());
    assert_eq!(diagnostic.related.len(), 1);
    assert_eq!(
        diagnostic.related[0].span.start,
        source.find("review()").unwrap()
    );
    assert!(compiled.ir.is_none());
}

#[test]
fn indirect_cycle_inside_then_and_an_unselected_branch_reports_every_edge() {
    let source = "workflow Demo\r\naction review() -> null {\r\n then result <- investigate()\r\n return result\r\n}\r\naction investigate() -> null {\r\n case false {\r\n true => { review() }\r\n false => { return null }\r\n }\r\n}";
    let diagnostics = validate(&declarations(source));
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    let diagnostic = &diagnostics[0];
    assert_eq!(
        diagnostic.message,
        "recursive action expansion: review -> investigate -> review"
    );
    assert_eq!(
        &source[diagnostic.span.start..diagnostic.span.end],
        "review"
    );
    assert!(diagnostic
        .related
        .iter()
        .any(|r| r.message == "`review` calls `investigate` here"
            && &source[r.span.start..r.span.end] == "investigate"));
    assert_eq!(
        diagnostic
            .related
            .iter()
            .filter(|r| r.message.ends_with("is defined here"))
            .count(),
        2
    );
}

#[test]
fn diamond_and_repeated_calls_are_finite_even_with_forward_definitions() {
    let source = "workflow Demo\naction review() -> null {\n investigate()\n assess()\n assess()\n return null\n}\naction investigate() -> null { assess() }\naction assess() -> null { return null }";
    assert!(validate(&declarations(source)).is_empty());
}

#[test]
fn comments_prompts_and_non_action_calls_do_not_invent_cycles() {
    let source = r#"workflow Demo
action review() -> null {
  # review()
  // review()
  tell worker """markdown
  review()
  then result <- review()
  """
  tell worker "review()"
  coerce review("input") as result
  return null
}
"#;
    assert!(validate(&declarations(source)).is_empty());
}

#[test]
fn duplicate_definitions_and_parameters_keep_both_source_locations() {
    for (source, message, token) in [
        (
            "workflow Demo\naction review() -> null {}\naction review() -> null {}",
            "duplicate action `review`",
            "review",
        ),
        (
            "workflow Demo\naction review(ticket Ticket, ticket Ticket) -> null {}",
            "duplicate parameter `ticket` in action `review`",
            "ticket",
        ),
    ] {
        let diagnostics = validate(&declarations(source));
        assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
        let d = &diagnostics[0];
        assert_eq!(d.message, message);
        assert_eq!(&source[d.span.start..d.span.end], token);
        assert_eq!(
            &source[d.related[0].span.start..d.related[0].span.end],
            token
        );
        assert!(d.related[0].span.start < d.span.start);
    }
}

#[test]
fn a_long_finite_chain_uses_no_recursive_compiler_walk() {
    let mut source = "workflow Demo\n".to_owned();
    for index in 0..2048 {
        source.push_str(&format!(
            "action step{index}() -> null {{ step{}() }}\n",
            index + 1
        ));
    }
    source.push_str("action step2048() -> null { return null }");
    assert!(validate(&declarations(&source)).is_empty());
}

#[test]
fn typed_declarations_retain_their_result_in_managed_compiler_output() {
    for call in ["", "rule run when started => { review() }"] {
        let compiled = compile_program(&format!(
            "@service\nworkflow Demo\naction review() -> null {{ return null }}\n{call}"
        ));
        assert!(
            compiled.diagnostics.is_empty(),
            "{:?}",
            compiled.diagnostics
        );
        assert!(compiled.ir.is_some());
        assert!(compiled.typed_actions.is_some());
    }
}
