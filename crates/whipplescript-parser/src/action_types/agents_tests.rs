use super::*;

const HEADER: &str = "workflow Agents\nagent writer { provider fixture profile \"writer\" capacity 1 capabilities [\"read\", \"write\"] }\nagent reader { provider fixture profile \"reader\" capacity 1 capabilities [\"read\"] }\nclass Input { target AgentRef<reader | writer> other AgentRef<reader | writer> flag bool }\n";

fn source(params: &str, body: &str, caller: &str) -> String {
    format!("{HEADER}action helper({params}) -> null {{ {body}\nreturn null }}\nrule run when Input as input => {{ {caller} }}")
}
fn tell(target: &str, capability: &str) -> String {
    format!("tell {target} requires [\"{capability}\"] \"Work\"")
}
fn authority(source: &str) -> Vec<Diagnostic> {
    let parsed = parse_program(source);
    assert!(
        parsed.diagnostics.is_empty(),
        "{source}: {:?}",
        parsed.diagnostics
    );
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
    let signatures = action_signature::validate(&actions);
    assert!(signatures.is_empty(), "{source}: {signatures:?}");
    let errors = validate(&actions, &semantic);
    assert!(errors.is_empty(), "{source}: {errors:?}");
    let errors = validate_callers(&actions, &rules, &semantic);
    assert!(errors.is_empty(), "{source}: {errors:?}");
    validate_authority(&actions, &rules, &semantic)
}
fn expects_capability(source: &str) {
    let errors = authority(source);
    assert_eq!(errors.len(), 1, "{source}: {errors:?}");
    assert_eq!(
        errors[0].code,
        diagnostic_code!("construct.capability_not_declared")
    );
    assert!(
        errors[0]
            .message
            .contains("agent `reader` requiring undeclared capability `write`"),
        "{errors:?}"
    );
    assert_eq!(compile_program(source).diagnostics, errors);
}

#[test]
fn action_agent_all_targets_require_all_capabilities_even_in_unused_helpers() {
    for caller in ["", "helper(writer)", "helper(input.target)"] {
        expects_capability(&source(
            "target AgentRef<reader | writer>",
            &tell("target", "write"),
            caller,
        ));
    }
    assert!(authority(&source(
        "target AgentRef<reader | writer>",
        &tell("target", "read"),
        "helper(input.target)"
    ))
    .is_empty());
}

#[test]
fn action_agent_nested_definitions_keep_one_source_refusal() {
    let leaf = tell("target", "write");
    let text = format!("{HEADER}action leaf(target AgentRef<reader | writer>) -> null {{ {leaf}\nreturn null }}\naction outer(target AgentRef<reader | writer>) -> null {{ leaf(target)\nreturn null }}\nrule run when Input as input => {{ outer(input.target)\nouter(input.target) }}");
    let errors = authority(&text);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.starts_with("action `leaf`"));
    assert_eq!(&text[errors[0].span.start..errors[0].span.end], leaf);
}

#[test]
fn action_agent_plain_strings_optional_unknown_and_shadowed_targets_refuse() {
    for (params, target) in [
        ("target string", "target"),
        ("target AgentRef<writer>?", "target"),
        ("target \"writer\"", "target"),
        ("", "missing"),
        ("record Input", "record.missing"),
        ("writer string", "writer"),
    ] {
        let text = source(params, &tell(target, "read"), "");
        let errors = authority(&text);
        assert_eq!(errors.len(), 1, "{text}: {errors:?}");
        if target == "record.missing" {
            assert_eq!(errors[0].code, diagnostic_code!("type.unknown_field"));
            assert!(errors[0].related.is_empty());
        } else {
            assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
            assert_eq!(errors[0].related.len(), 1);
        }
    }
    let text = source("", "", &tell("input.target", "read"))
        .replace("AgentRef<reader | writer>", "AgentRef<ghost>");
    let errors = authority(&text);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, diagnostic_code!("type.unknown_agent"));
}

#[test]
fn action_agent_case_refines_parameter_field_and_fallback_without_changing_nominal_type() {
    for (params, target) in [
        ("target AgentRef<reader | writer>", "target"),
        ("record Input", "record.target"),
    ] {
        for pattern in ["writer", "\"writer\""] {
            let body = format!(
                "case {target} {{ {pattern} => {{ {} }} reader => {{ }} }}",
                tell(target, "write")
            );
            assert!(authority(&source(params, &body, "")).is_empty());
        }
        let body = format!(
            "case {target} {{ reader => {{ }} _ => {{ {} }} }}",
            tell(target, "write")
        );
        assert!(authority(&source(params, &body, "")).is_empty());
    }
    let body = format!(
        "case record.target {{ writer => {{ {} }} _ => {{ }} }}",
        tell("record.other", "write")
    );
    expects_capability(&source("record Input", &body, ""));
    let text = format!("{HEADER}action keep(record Input) -> Input {{ case record.target {{ writer => {{ return record }} _ => {{ return record }} }} }}");
    assert!(authority(&text).is_empty());
}

#[test]
fn action_agent_guarded_predecessor_does_not_remove_a_possible_fallback_target() {
    let body = format!(
        "case target {{ reader where flag => {{ }} _ => {{ {} }} }}",
        tell("target", "write")
    );
    expects_capability(&source(
        "target AgentRef<reader | writer>, flag bool",
        &body,
        "",
    ));
}

#[test]
fn action_agent_boolean_guards_narrow_only_proven_candidates() {
    for (guard, valid) in [
        ("target == writer", true),
        ("writer == target", true),
        ("target != reader", true),
        ("!(target == reader)", true),
        ("target == \"writer\" && flag", true),
        ("target == writer || false", true),
        ("target == writer || flag", false),
        ("target == reader || target == writer", false),
        ("target == target", false),
        ("flag", false),
    ] {
        let body = format!(
            "case flag {{ _ where {guard} => {{ {} }} _ => {{ }} }}",
            tell("target", "write")
        );
        let text = source("target AgentRef<reader | writer>, flag bool", &body, "");
        if valid {
            assert!(authority(&text).is_empty(), "{text}");
        } else {
            expects_capability(&text);
        }
    }
    let body = format!(
        "case flag {{ _ where target == writer => {{ {} }} _ => {{ }} }}",
        tell("target", "write")
    );
    expects_capability(&source(
        "target AgentRef<reader | writer>, writer AgentRef<reader | writer>, flag bool",
        &body,
        "",
    ));
}

#[test]
fn action_agent_rule_admission_guards_refine_arguments_and_effects() {
    let text = source(
        "target AgentRef<writer>",
        &tell("target", "write"),
        "helper(input.target)",
    )
    .replace(
        "when Input as input =>",
        "when Input as input where input.target == writer =>",
    );
    assert!(authority(&text).is_empty());
    let text = source("", "", &tell("input.target", "write")).replace(
        "when Input as input =>",
        "when Input as input where input.target != reader =>",
    );
    assert!(authority(&text).is_empty());
    let text = text.replace(
        "input.target != reader",
        "input.target != reader || input.flag",
    );
    expects_capability(&text);
}

#[test]
fn action_agent_refined_values_cross_typed_calls_and_returns() {
    let text = format!("{HEADER}action write_to(target AgentRef<writer>) -> null {{ {}\nreturn null }}\naction choose(target AgentRef<reader | writer>) -> AgentRef<writer> {{ case target {{ writer => {{ return target }} _ => {{ return writer }} }} }}\naction forward(target AgentRef<reader | writer>) -> null {{ case target {{ writer => {{ write_to(target) }} _ => {{ }} }}\nreturn null }}\nrule run when Input as input => {{ choose(input.target) as selected\nafter selected succeeds {{ write_to(selected) }} }}", tell("target", "write"));
    assert!(authority(&text).is_empty());
    let quoted = text.replace("return writer", "return \"writer\"");
    assert!(authority(&quoted).is_empty());
    let invalid = text.replace("write_to(selected)", "write_to(input.target)");
    assert!(compile_program(&invalid)
        .diagnostics
        .iter()
        .any(|d| d.message.contains("expects AgentRef<writer>")));
}

#[test]
fn action_agent_shadowing_clears_scalar_and_field_refinements() {
    for (params, selector, shadow, target) in [
        (
            "target AgentRef<reader | writer>",
            "target",
            "target",
            "target",
        ),
        ("record Input", "record.target", "record", "record.target"),
    ] {
        let body = format!("case {selector} {{ writer => {{ tell writer as {shadow} \"new value\"\n{} }} _ => {{ }} }}", tell(target, "write"));
        let text = source(params, &body, "");
        let errors = authority(&text);
        assert_eq!(errors.len(), 1, "{text}: {errors:?}");
        assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
    }
}

#[test]
fn action_agent_all_calling_rule_children_and_unselected_branches_are_checked() {
    let bad = tell("input.target", "write");
    for body in [
        bad.clone(),
        format!("then work <- {bad}"),
        format!("timer 1s as pause\nafter pause succeeds {{ {bad} }}"),
        format!("case true {{ true => {{ }} false => {{ {bad} }} }}"),
        format!("during Input {{ {bad} }} on lapse {{ }}"),
        format!("during Input {{ }} on lapse {{ {bad} }}"),
    ] {
        expects_capability(&source("", "", &body));
    }
}

#[test]
fn action_agent_earlier_errors_keep_priority_and_valid_authority_keeps_execution_gate() {
    let text = source(
        "target AgentRef<reader | writer>",
        &tell("target", "write"),
        "helper(4)",
    );
    let errors = compile_program(&text).diagnostics;
    assert_eq!(errors.len(), 1);
    assert!(errors[0].message.contains("expects AgentRef"));
    let text = source(
        "",
        "tell reader with access to project_memory {} requires [\"write\"] \"Work\"",
        "",
    );
    let errors = compile_program(&text).diagnostics;
    assert_eq!(errors.len(), 1);
    assert_eq!(
        errors[0].code,
        diagnostic_code!("construct.missing_requirement")
    );
    let text = source(
        "target AgentRef<writer>",
        &tell("target", "write"),
        "helper(writer)",
    );
    assert!(authority(&text).is_empty());
    let compiled = compile_program(&text);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert!(compiled.ir.is_some());
    assert!(compiled.typed_actions.is_some());
}

#[test]
fn action_agent_operation_and_nominal_bindings_keep_only_their_sources_field_refinements() {
    let text = format!("{HEADER}action copy(record Input) -> Input {{ return record }}\nrule run when Input as input => {{ copy(input) as result\ncase result.target {{ writer => {{ after result succeeds {{ {} }} }} _ => {{ }} }} }}", tell("result.target", "write"));
    assert!(authority(&text).is_empty());
    let nominal = source("record Input", &format!("case record.target {{ writer => {{ case record {{ Input as alias => {{ {} }} }} }} _ => {{ }} }}", tell("alias.target", "write")), "");
    assert!(authority(&nominal).is_empty());
    let wrong_source = text
        .replace("after result succeeds", "after result fails as alias")
        .replace("tell result.target", "tell alias.target");
    let errors = authority(&wrong_source);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, diagnostic_code!("type.unknown_field"));
}

#[test]
fn action_agent_invalid_patterns_and_guards_report_the_entrance_error() {
    for (pattern, message) in [
        ("ghost", "not an alternative"),
        ("writer where missing", "known boolean expression"),
    ] {
        let text = source(
            "target AgentRef<reader | writer>",
            &format!(
                "case target {{ {pattern} => {{ {} }} _ => {{ }} }}",
                tell("target", "write")
            ),
            "",
        );
        let errors = compile_program(&text).diagnostics;
        assert_eq!(errors.len(), 1, "{text}: {errors:?}");
        assert!(errors[0].message.contains(message), "{errors:?}");
    }
}

#[test]
fn action_agent_branch_refinements_do_not_leak_to_siblings_or_containing_scope() {
    let text = source(
        "target AgentRef<reader | writer>",
        &format!(
            "case target {{ writer => {{ {} }} reader => {{ }} }}\n{}",
            tell("target", "write"),
            tell("target", "write")
        ),
        "",
    );
    expects_capability(&text);
    let text = source(
        "target AgentRef<reader | writer>",
        &format!(
            "case target {{ writer => {{ }} reader => {{ {} }} }}",
            tell("target", "write")
        ),
        "",
    );
    expects_capability(&text);
}

#[test]
fn action_agent_equivalent_union_domains_compose_but_mixed_unions_do_not() {
    let text = source(
        "target AgentRef<reader> | AgentRef<writer>",
        &tell("target", "read"),
        "helper(input.target)",
    );
    assert!(authority(&text).is_empty());
    expects_capability(&text.replace("[\"read\"] \"Work\"", "[\"write\"] \"Work\""));
    let body = format!(
        "case target {{ writer => {{ {} }} _ => {{ }} }}",
        tell("target", "write")
    );
    assert!(authority(&source(
        "target AgentRef<reader> | AgentRef<writer>",
        &body,
        ""
    ))
    .is_empty());
    let text = source(
        "target AgentRef<writer> | string",
        &tell("target", "write"),
        "",
    );
    let errors = authority(&text);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
}

#[test]
fn action_agent_inline_capability_diagnostics_keep_the_legacy_contract() {
    let bad = tell("reader", "write");
    let typed = source("", "", &bad);
    let error = authority(&typed).remove(0);
    let legacy = format!("{HEADER}rule run when Input as input => {{ {bad} }}");
    let result = compile_program(&legacy);
    let old = result
        .diagnostics
        .iter()
        .find(|d| d.code == error.code)
        .expect("legacy capability refusal");
    assert_eq!(old.message, error.message);
    assert_eq!(old.suggestion, error.suggestion);
    assert_eq!(
        &legacy[old.span.start..old.span.end],
        &typed[error.span.start..error.span.end]
    );
}

#[test]
fn action_agent_return_path_analysis_uses_guard_and_operation_refinements() {
    for body in [
        "case flag { _ where record.target == writer => { case record.target { writer => { return 1 } } } _ => { return 2 } }",
        "case flag { _ where record.target == writer => { case record { Input as alias => { case alias.target { writer => { return 1 } } } } } _ => { return 2 } }",
        "copy(record) as result\ncase flag { _ where result.target == writer => { after result succeeds { case result.target { writer => { return 1 } } } } _ => { return 2 } }",
    ] {
        let text = format!("{HEADER}action copy(record Input) -> Input {{ return record }}\naction select(record Input, flag bool) -> int {{ {body} }}");
        assert!(authority(&text).is_empty(), "{text}");
    }
}

#[test]
fn action_agent_literal_boundaries_check_membership_without_promoting_string_types() {
    let valid = source(
        "target AgentRef<writer>",
        &tell("target", "write"),
        "helper(\"writer\")",
    );
    assert!(authority(&valid).is_empty());
    let invalid = valid.replace("helper(\"writer\")", "helper(\"reader\")");
    let errors = compile_program(&invalid).diagnostics;
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].message.contains("expects AgentRef<writer>"));
}

#[test]
fn action_agent_one_operation_does_not_inherit_another_operations_refinements() {
    let text = format!("{HEADER}action copy(record Input) -> Input {{ return record }}\nrule run when Input as input => {{ copy(input) as result\ncopy(input) as other\ncase result.target {{ writer => {{ after other succeeds {{ {} }} }} _ => {{ }} }} }}", tell("other.target", "write"));
    expects_capability(&text);
}

#[test]
fn action_agent_synchronous_bindings_shadow_global_and_refined_agent_names() {
    for statement in [
        "redact record keep [target] as writer",
        "declassify record into Input as writer",
    ] {
        let text = source(
            "record Input",
            &format!("{statement}\n{}", tell("writer", "write")),
            "",
        );
        let errors = authority(&text);
        assert_eq!(errors.len(), 1, "{text}: {errors:?}");
        assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
        let body = format!(
            "case input.target {{ writer => {{ {}\n{} }} _ => {{ }} }}",
            statement
                .replace("record", "input")
                .replace("as writer", "as input"),
            tell("input.target", "write")
        );
        let text = source("", "", &body);
        let errors = if statement.starts_with("redact") {
            // This is a self-dependent local, not a read of the shadowed input.
            // Checked redaction now refuses it before authority analysis.
            let parsed = parse_program(&text);
            crate::action_plan::analysis::analyze_composition(&parsed.program).unwrap_err()
        } else {
            authority(&text)
        };
        assert_eq!(errors.len(), 1, "{body}: {errors:?}");
        if statement.starts_with("declassify") {
            // The result now has Input's declared domain. It must not recover
            // the shadowed binding's narrower `writer` refinement.
            assert_eq!(
                errors[0].code,
                diagnostic_code!("construct.capability_not_declared")
            );
            assert!(
                errors[0]
                    .message
                    .contains("agent `reader` requiring undeclared capability `write`"),
                "{errors:?}"
            );
        } else {
            assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
            assert!(errors[0].message.contains("must be a present record"));
            assert!(text[errors[0].span.start..errors[0].span.end].contains("redact input"));
        }
    }
    let body = "case input.target { writer => { redact input keep [target] as projected\ntell projected.target requires [\"write\"] \"Work\" } _ => {} }";
    assert!(authority(&source("", "", body)).is_empty());
}

#[test]
fn action_agent_invalid_case_entrances_do_not_cascade_into_bad_arguments() {
    for (pattern, message) in [
        ("ghost", "not an alternative"),
        ("writer where missing", "known boolean expression"),
    ] {
        let text = format!("{HEADER}action text(value string) -> null {{ return null }}\naction helper(target AgentRef<reader | writer>) -> null {{ case target {{ {pattern} => {{ text(1) }} _ => {{ }} }}\nreturn null }}");
        let errors = compile_program(&text).diagnostics;
        assert_eq!(errors.len(), 1, "{text}: {errors:?}");
        assert!(errors[0].message.contains(message), "{errors:?}");
    }
}
