use super::*;

const HEADER: &str = "workflow Demo\nclass Input { value string }\nagent coder { provider fixture profile \"writer\" capacity 1 }\n";

fn program(action_body: &str, rule_body: &str) -> String {
    format!("{HEADER}action helper() -> null {{ {action_body}\nreturn null }}\nrule run when Input as input => {{ {rule_body} }}")
}

fn grants(source: &str) -> Vec<Diagnostic> {
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
    validate_composition(&actions, &rules)
}

fn tell(resource: &str, operations: &str) -> String {
    format!("tell coder with access to {resource} {{ {operations} }} \"Work\"")
}

#[test]
fn action_grants_unused_helper_and_repeated_calls_report_one_definition() {
    let effect = tell("project_memory", "");
    for calls in ["", "helper()\nhelper()"] {
        let source = program(&effect, calls);
        let errors = compile_program(&source).diagnostics;
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert_eq!(
            errors[0].code,
            diagnostic_code!("construct.missing_requirement")
        );
        assert_eq!(
            errors[0].message,
            "action `helper` has a `with access to project_memory` grant that grants no operations"
        );
        assert_eq!(&source[errors[0].span.start..errors[0].span.end], effect);
    }
}

#[test]
fn action_grants_callers_and_all_nested_statement_forms_are_checked() {
    let bad = tell("project_memory", "");
    let wrappers = [
        bad.clone(),
        format!("then work <- {bad}"),
        format!("timer 1s as pause\nafter pause succeeds {{ {bad} }}"),
        format!("case true {{ true => {{ }} false => {{ {bad} }} }}"),
        format!("during Input {{ {bad} }} on lapse {{ }}"),
        format!("during Input {{ }} on lapse {{ {bad} }}"),
    ];
    for wrapper in wrappers {
        for in_action in [true, false] {
            let wrapper = if in_action && wrapper.starts_with("during Input") {
                if wrapper.contains("on lapse { }") {
                    wrapper.replace("on lapse { }", "on lapse { return null }")
                } else {
                    format!(
                        "{}\nreturn null }}",
                        wrapper.strip_suffix(" }").expect("region wrapper")
                    )
                }
            } else {
                wrapper.clone()
            };
            let source = if in_action {
                program(&wrapper, "helper()")
            } else {
                program("", &wrapper)
            };
            let errors = grants(&source);
            let compiled = compile_program(&source).diagnostics;
            assert_eq!(compiled, errors);
            assert_eq!(errors.len(), 1, "{source}: {errors:?}");
            assert_eq!(
                errors[0].code,
                diagnostic_code!("construct.missing_requirement"),
                "{source}: {errors:?}"
            );
            let owner = if in_action {
                "action `helper`"
            } else {
                "rule `run`"
            };
            assert!(errors[0].message.starts_with(owner));
            assert_eq!(&source[errors[0].span.start..errors[0].span.end], bad);
        }
    }
}

#[test]
fn action_grants_duplicates_are_per_effect_and_other_vocabularies_stay_independent() {
    let one = tell("project_memory", "unwrap"); // Not a custody resource.
    let source = program(&format!("{one}\n{one}"), "helper()");
    assert!(grants(&source).is_empty());
    let duplicate = "tell coder with access to project_memory { recall } with access to project_memory { learn } \"Work\"";
    let errors = grants(&program(duplicate, "helper()"));
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].code,
        diagnostic_code!("capability.duplicate_grant")
    );
    let unknown = program(&tell("credential key", "future_operation"), "");
    assert!(
        grants(&unknown).is_empty(),
        "unknown operation belongs to the registry validator"
    );
}

#[test]
fn action_grants_custody_classes_share_existing_narrowing_rules() {
    for (operation, detail) in [
        ("request", Some("names no glob list")),
        ("request [\"host/*\"]", None),
        ("unwrap", Some("names no type")),
        ("unwrap for Input", None),
        (
            "unwrap for Input [\"records/*\"]",
            Some("carries a glob list as well as a type"),
        ),
        ("wrap", None),
        ("wrap for Input", Some("carries a narrowing clause")),
        ("sign [\"host/*\"]", Some("carries a narrowing clause")),
    ] {
        let source = program(&tell("credential key", operation), "helper()");
        let errors = grants(&source);
        if let Some(detail) = detail {
            assert_eq!(errors.len(), 1, "{source}: {errors:?}");
            assert_eq!(
                errors[0].code,
                diagnostic_code!("capability.invalid_narrowing")
            );
            assert!(errors[0].message.contains(detail), "{errors:?}");
        } else {
            assert!(errors.is_empty(), "{source}: {errors:?}");
        }
    }
}

#[test]
fn action_grants_type_errors_precede_grants_and_valid_grants_reach_managed_output() {
    let source =
        program(&tell("project_memory", ""), "helper()").replace("return null", "return 1");
    let errors = compile_program(&source).diagnostics;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(!errors[0].message.contains("grants no operations"));
    let source = program(&tell("project_memory", ""), "helper(1)");
    let errors = compile_program(&source).diagnostics;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(!errors[0].message.contains("grants no operations"));
    let source = program(&tell("credential key", "unwrap for Input"), "helper()");
    assert!(grants(&source).is_empty());
    let result = compile_program(&source);
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    assert!(result.ir.is_some());
    assert!(result.typed_actions.is_some());
}

#[test]
fn action_grants_direct_consumer_preserves_parse_failures() {
    for source in [program("then", ""), program("", "then")] {
        let errors = grants(&source);
        assert!(!errors.is_empty(), "{source}");
        assert!(errors.iter().all(|error| error.severity == Severity::Error));
    }
}

#[test]
fn action_grants_every_grant_bearing_effect_uses_the_shared_conversion() {
    for effect in [
        "tell coder with access to credential key { unwrap } \"Work\"",
        "invoke Child {} with access to credential key { unwrap } as child",
        "exec \"report.sh\" with access to credential key { unwrap } as job",
        "coerce assess(\"input\") with access to credential key { unwrap } as answer",
    ] {
        let source = program(effect, "helper()");
        let errors = grants(&source);
        assert_eq!(errors.len(), 1, "{source}: {errors:?}");
        assert_eq!(
            errors[0].code,
            diagnostic_code!("capability.invalid_narrowing"),
            "{errors:?}"
        );
        assert_eq!(&source[errors[0].span.start..errors[0].span.end], effect);
    }
}

#[test]
fn action_grants_inline_rule_keeps_legacy_diagnostic_contract() {
    let bad = tell("credential key", "unwrap");
    let typed = program("", &bad);
    let legacy = format!("{HEADER}rule run when Input as input => {{ {bad} }}");
    let error = grants(&typed).remove(0);
    let result = compile_program(&legacy);
    let inline = result
        .diagnostics
        .iter()
        .find(|d| d.code == error.code)
        .expect("legacy narrowing refusal");
    assert_eq!(inline.message, error.message);
    assert_eq!(inline.suggestion, error.suggestion);
    assert_eq!(inline.severity, error.severity);
    assert_eq!(
        &legacy[inline.span.start..inline.span.end],
        &typed[error.span.start..error.span.end]
    );
}

#[test]
fn action_grants_nested_call_reports_the_leaf_definition_once() {
    let bad = tell("project_memory", "");
    let source = format!("{HEADER}action leaf() -> null {{ {bad}\nreturn null }}\naction middle() -> null {{ leaf()\nreturn null }}\naction outer() -> null {{ middle()\nreturn null }}\nrule run when Input as input => {{ outer()\nouter() }}");
    let errors = compile_program(&source).diagnostics;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.starts_with("action `leaf`"));
    assert_eq!(&source[errors[0].span.start..errors[0].span.end], bad);
}
