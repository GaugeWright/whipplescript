use super::*;

fn callers(source: &str) -> Vec<Diagnostic> {
    let parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rules: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .collect();
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    assert!(action_signature::validate(&actions).is_empty());
    let definitions = validate(&actions, &semantic);
    assert!(definitions.is_empty(), "{definitions:?}");
    validate_callers(&actions, &rules, &semantic)
}

#[test]
fn action_caller_uses_matched_nominal_and_field_types_at_each_call_site() {
    let header = "workflow Demo\nclass Ticket { title string }\nclass Review { title string }\naction title(ticket Ticket) -> string { return ticket.title }\naction text(value string) -> string { return value }\n";
    let valid = format!("{header}rule run when {{ Ticket as ticket\nReview as review }} => {{ title(ticket) as first\ntext(review.title) as second }}");
    assert!(callers(&valid).is_empty());
    let invalid = format!("{header}rule run when {{ Ticket as ticket\nReview as review }} => {{ title(ticket) as first\ntitle(review) as second }}");
    let errors = callers(&invalid);
    assert_eq!(errors.len(), 1);
    let error = &errors[0];
    assert_eq!(&invalid[error.span.start..error.span.end], "review");
    assert!(
        error.message.contains("expects Ticket"),
        "{}",
        error.message
    );
    assert_eq!(error.related.len(), 1);
    let contract = error.related[0].span;
    assert_eq!(&invalid[contract.start..contract.end], "Ticket");
}

#[test]
fn action_caller_preserves_optional_and_numeric_assignment_direction() {
    for (field, parameter, succeeds) in [
        ("int", "float", true),
        ("float", "int", false),
        ("string?", "string", false),
        ("string?", "string?", true),
        ("int | string", "int", false),
        ("int | string", "int | string", true),
    ] {
        let source = format!("workflow Demo\nclass Input {{ value {field} }}\naction take(value {parameter}) -> null {{ return null }}\nrule run when Input as input => {{ take(input.value) }}");
        let errors = callers(&source);
        assert_eq!(errors.is_empty(), succeeds, "{source}: {errors:?}");
    }
}

#[test]
fn action_caller_types_forward_results_and_then_bindings() {
    let source = "workflow Demo\nclass Input { count int }\naction number(value int) -> int { return value }\naction take(value int) -> null { return null }\nrule run when Input as input => { take(result)\nthen result <- number(input.count)\nafter result succeeds { take(result) } }";
    assert!(callers(source).is_empty());
    let invalid = source.replace("number(input.count)", "number(\"wrong\")");
    let errors = callers(&invalid);
    assert_eq!(errors.len(), 1);
    assert_eq!(
        &invalid[errors[0].span.start..errors[0].span.end],
        "\"wrong\""
    );
    let invalid = source.replace("succeeds { take(result)", "fails as alias { take(alias)");
    let errors = callers(&invalid);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("expects int"));
}

#[test]
fn action_caller_checks_unselected_branches_and_nominal_narrowing() {
    let prefix = "workflow Demo\nclass Ticket { title string }\nclass Review { title string }\naction take(value string) -> null { return null }\n";
    let source = format!("{prefix}rule run when Ticket as ticket => {{ case ticket {{ Ticket as selected => {{ take(selected.title) }} }} }}");
    assert!(callers(&source).is_empty());
    let wrong = source.replace("Ticket as selected", "Review as selected");
    let errors = callers(&wrong);
    assert_eq!(errors.len(), 1, "invalid branch binding must not cascade");
    assert!(errors
        .iter()
        .any(|error| error.message.contains("cannot bind")));
    let related = &errors
        .iter()
        .find(|error| error.message.contains("cannot bind"))
        .unwrap()
        .related[0];
    assert_eq!(related.message, "calling rule declared here");
    assert_eq!(&wrong[related.span.start..related.span.end], "run");
    let source = format!("{prefix}rule run when started => {{ case true {{ true => {{ take(\"ok\") }}\nfalse => {{ take(4) }} }} }}");
    let errors = callers(&source);
    assert_eq!(errors.len(), 1);
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "4");
}

#[test]
fn action_caller_unresolved_local_shadows_a_matched_fact() {
    let source = "workflow Demo\nclass Ticket { title string }\naction take(value Ticket) -> null { return null }\nrule run when Ticket as ticket => { timer 1s as wait\nafter wait succeeds { exec \"hello\" as ticket\ntake(ticket) } }";
    let errors = callers(source);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("cannot determine"));
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "ticket");
    let source = source.replace("exec \"hello\" as ticket\n", "");
    assert!(callers(&source).is_empty());
}

#[test]
fn action_caller_checks_region_lapse_body() {
    let source = "workflow Demo\nclass Ticket { title string }\naction take(value string) -> null { return null }\nrule run when Ticket as ticket => { during Ticket { take(ticket.title) } on lapse { take(4) } }";
    let errors = callers(source);
    assert_eq!(errors.len(), 1);
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "4");
}

#[test]
fn action_caller_lexical_errors_precede_types_and_keep_trigger_locations() {
    let source = "workflow Demo\nclass Ticket { title string }\naction take(value string) -> null { return null }\nrule run when { Ticket as ticket where ticket.title == \"a\"\nTicket as ticket } => { take(ticket) }";
    let errors = callers(source);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("duplicate rule input"));
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], "ticket");
    assert_eq!(
        &source[errors[0].related[0].span.start..errors[0].related[0].span.end],
        "ticket"
    );
    assert!(errors[0].related[0].span.start < errors[0].span.start);
    let source = "workflow Demo\naction take() -> null { return null }\nrule run when started => { take() as result\ntake() as result }";
    let errors = callers(source);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("duplicate"));
}

#[test]
fn action_caller_reports_unknown_names_and_arity_at_the_call() {
    for (call, expected) in [
        ("missing()", "unknown action"),
        ("take()", "expects 1 argument"),
        ("take(1, 2)", "expects 1 argument"),
    ] {
        let source = format!("workflow Demo\naction take(value int) -> null {{ return null }}\nrule run when started => {{ {call} }}");
        let errors = callers(&source);
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains(expected));
        assert_eq!(
            &source[errors[0].span.start..errors[0].span.end],
            call.split('(').next().unwrap()
        );
    }
}

#[test]
fn action_caller_compilation_stops_on_precise_errors_and_emits_managed_output() {
    let prefix = "workflow Demo\naction take(value int) -> null { return null }\n";
    let invalid = format!("{prefix}rule run when started => {{ take(\"wrong\") }}");
    let compiled = compile_program(&invalid);
    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 1, "{:?}", compiled.diagnostics);
    assert!(compiled.diagnostics[0]
        .message
        .contains("parameter `value`"));
    assert_eq!(
        &invalid[compiled.diagnostics[0].span.start..compiled.diagnostics[0].span.end],
        "\"wrong\""
    );
    let compiled = compile_program(&format!("{prefix}rule run when started => {{ take(1) }}"));
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
    assert!(compiled.typed_actions.is_some());
    let invalid = "workflow Demo\naction take(value int) -> int { return \"bad\" }\nrule run when started => { take(\"also bad\") }";
    let compiled = compile_program(invalid);
    assert!(compiled.ir.is_none());
    assert_eq!(compiled.diagnostics.len(), 1);
    assert!(compiled.diagnostics[0]
        .message
        .contains("return from action"));
    let invalid = format!("{prefix}rule run when started => {{ return 1 }}");
    let compiled = compile_program(&invalid);
    assert_eq!(compiled.diagnostics.len(), 1);
    assert!(compiled.diagnostics[0]
        .message
        .contains("rule cannot return"));
}

#[test]
fn rule_failure_handler_has_a_typed_aggregate_and_one_boundary() {
    let header =
        "workflow Demo\nclass Incident { summary string }\naction take() -> null { return null }\n";
    let valid = format!(
        "{header}rule run when started => {{ take() as work\non failure as problem {{ record Incident {{ summary problem.summary }} }} }}"
    );
    assert!(callers(&valid).is_empty(), "{:?}", callers(&valid));

    let wrong = format!(
        "{header}rule run when started => {{ take() as work\non failure as problem {{ record Incident {{ summary problem.causes }} }} }}"
    );
    assert!(callers(&wrong)
        .iter()
        .any(|diagnostic| diagnostic.message.contains("expects string")));

    let duplicate = format!(
        "{header}rule run when started => {{ take() as work\non failure as first {{ record Incident {{ summary first.summary }} }}\non failure as second {{ record Incident {{ summary second.summary }} }} }}"
    );
    let errors = callers(&duplicate);
    assert!(errors.iter().any(|diagnostic| diagnostic
        .message
        .contains("rule `run` has more than one lexical failure handler")));
}

#[test]
fn action_caller_generated_trigger_keeps_its_coarse_recorded_origin() {
    let source = "workflow Demo\nclass Ticket { title string }\naction take(value Ticket) -> null { return null }\nrule run when { Ticket as ticket\nTicket as ticket } => { take(ticket) }";
    let mut parsed = parse_program(source);
    assert!(parsed.diagnostics.is_empty());
    for item in &mut parsed.program.items {
        if let Item::Rule(rule) = item {
            for when in &mut rule.whens {
                // Equal-length generated text does not prove a file offset.
                when.text = SourceText::generated(when.text.to_string());
            }
        }
    }
    let actions: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Action(action) => Some(action.clone()),
            _ => None,
        })
        .collect();
    let rules: Vec<_> = parsed
        .program
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Rule(rule) => Some(rule),
            _ => None,
        })
        .collect();
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    let errors = validate_callers(&actions, &rules, &semantic);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].span, rules[0].whens[1].span);
    assert_eq!(errors[0].related[0].span, rules[0].whens[0].span);
}
