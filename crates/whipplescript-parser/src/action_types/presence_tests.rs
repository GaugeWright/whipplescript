use super::*;

const HEADER: &str = "workflow Presence\nclass Item { kind \"ready\" | \"waiting\"\nvalue string when kind is \"ready\"\nflag bool }\nclass Pair { left Item right Item }\n";

fn check(body: &str) -> Vec<Diagnostic> {
    tests::check(&format!(
        "{HEADER}action read(item Item, other Item, pair Pair) -> string {{ {body} }}"
    ))
}

fn accepts(body: &str) {
    let errors = check(body);
    assert!(errors.is_empty(), "{body}: {errors:?}");
}
fn refuses(body: &str) {
    let errors = check(body);
    assert!(!errors.is_empty(), "{body}");
    assert!(
        errors
            .iter()
            .any(|d| d.code == diagnostic_code!("expr.conditional_without_presence")),
        "{errors:?}"
    );
}

#[test]
fn action_presence_exact_cases_and_unguarded_fallback_prove_reads() {
    accepts("case item.kind { \"ready\" => { return item.value } _ => { return \"later\" } }");
    accepts("case item.kind { \"waiting\" => { return \"later\" } _ => { return item.value } }");
    refuses("return item.value");
    refuses("case item.kind { \"waiting\" => { return item.value } _ => { return \"later\" } }");
    refuses("case item.kind { \"waiting\" where item.flag => { return \"later\" } _ => { return item.value } }");
}

#[test]
fn action_presence_guards_preserve_every_possible_literal() {
    for guard in [
        "item.kind == \"ready\"",
        "\"ready\" == item.kind",
        "item.kind != \"waiting\"",
        "!(item.kind == \"waiting\")",
        "item.kind == \"ready\" && item.flag",
        "item.kind == \"ready\" || false",
    ] {
        accepts(&format!("case item.flag {{ _ where {guard} => {{ return item.value }} _ => {{ return \"later\" }} }}"));
    }
    for guard in [
        "item.kind == \"ready\" || item.flag",
        "item.kind == item.kind",
        "other.kind == \"ready\"",
        "item.flag",
    ] {
        refuses(&format!("case item.flag {{ _ where {guard} => {{ return item.value }} _ => {{ return \"later\" }} }}"));
    }
}

#[test]
fn action_presence_nested_paths_remain_independent() {
    accepts(
        "case pair.left.kind { \"ready\" => { return pair.left.value } _ => { return \"later\" } }",
    );
    refuses("case pair.left.kind { \"ready\" => { return pair.right.value } _ => { return \"later\" } }");
    refuses("case item.kind { \"ready\" => { return other.value } _ => { return \"later\" } }");
}

#[test]
fn action_presence_aliases_keep_nominal_type_and_rebinding_clears_proofs() {
    accepts("case item.kind { \"ready\" => { case item { Item as alias => { return alias.value } } } _ => { return \"later\" } }");
    refuses("case item.kind { \"ready\" => { case other { Item as item => { return item.value } } } _ => { return \"later\" } }");
    let text = format!("{HEADER}action keep(item Item) -> Item {{ case item.kind {{ \"ready\" => {{ return item }} _ => {{ return item }} }} }}");
    assert!(tests::check(&text).is_empty());
}

#[test]
fn action_presence_literal_refinement_is_not_agent_authority() {
    let text = "workflow Presence\nagent writer { provider fixture profile \"writer\" capacity 1 capabilities [\"read\"] }\naction helper(target \"writer\" | \"reader\") -> null { case target { \"writer\" => { tell target requires [\"read\"] \"Work\" } _ => { } }\nreturn null }";
    assert!(tests::check(text).is_empty());
    assert!(compile_program(text)
        .diagnostics
        .iter()
        .any(|d| d.code == diagnostic_code!("type.mismatch") && d.message.contains("AgentRef")));
}

#[test]
fn action_presence_rule_guards_type_helper_arguments() {
    let text = format!("{HEADER}action take(value string) -> null {{ return null }}\nrule run when Item as item where item.kind == \"ready\" => {{ take(item.value) }}");
    let parsed = parse_program(&text);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    let actions = parsed
        .program
        .items
        .iter()
        .filter_map(|item| {
            if let Item::Action(a) = item {
                Some(a.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let rules = parsed
        .program
        .items
        .iter()
        .filter_map(|item| {
            if let Item::Rule(r) = item {
                Some(r)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    assert!(validate_callers(&actions, &rules, &semantic).is_empty());
    let unguarded = text.replace(" where item.kind == \"ready\"", "");
    assert!(compile_program(&unguarded)
        .diagnostics
        .iter()
        .any(|d| d.code == diagnostic_code!("expr.conditional_without_presence")));
}

#[test]
fn action_presence_singletons_unions_and_cycles_need_nonempty_evidence() {
    for (declarations, parameter, valid) in [
        ("class Fixed { kind \"ready\"\nvalue string when kind is \"ready\" }", "Fixed", true),
        ("class Fixed { kind \"ready\"\nvalue string when kind is \"ready\" }", "Fixed | Item", false),
        ("class Fixed { kind \"ready\"\nvalue string when kind is \"ready\" }", "Fixed?", false),
        ("class Cycle { kind \"ready\" when other is \"ready\"\nother \"ready\" when kind is \"ready\"\nvalue string when kind is \"ready\" }", "Cycle", false),
    ] {
        let text = format!("{HEADER}{declarations}\naction read(item {parameter}) -> string {{ return item.value }}");
        let errors = tests::check(&text);
        assert_eq!(errors.is_empty(), valid, "{text}: {errors:?}");
    }
    refuses("case item.kind { \"ready\" where item.kind == \"waiting\" => { return item.value } _ => { return \"later\" } }");
}

#[test]
fn action_presence_environment_clears_unresolved_shadow_and_checks_union_members() {
    let parsed = parse_program(HEADER);
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    let path = |s: &str| s.split('.').map(str::to_owned).collect::<Vec<_>>();
    let mut env = Environment::from_iter([("item".into(), Some(IrType::Ref("Item".into())))]);
    let guard = parse_expression("item.kind == \"ready\"").unwrap();
    env.narrow_guard(&guard, &semantic);
    assert_eq!(
        env.path_type(&path("item.value"), &semantic),
        Some(primitive(IrPrimitiveType::String))
    );
    env.insert("item".into(), None);
    assert_eq!(env.path_type(&path("item.value"), &semantic), None);
    env.insert(
        "item".into(),
        Some(IrType::Union(vec![
            IrType::Ref("Item".into()),
            primitive(IrPrimitiveType::Null),
        ])),
    );
    assert_eq!(env.path_type(&path("item.value"), &semantic), None);
    // An impossible finite branch leaves an empty type domain; it cannot
    // manufacture a field merely because there is no member to disprove it.
    for ty in [
        IrType::Union(vec![]),
        primitive(IrPrimitiveType::String),
        IrType::Optional(Box::new(IrType::Ref("Item".into()))),
    ] {
        env.insert("item".into(), Some(ty));
        assert_eq!(env.path_type(&path("item.value"), &semantic), None);
    }
}

#[test]
fn action_presence_diagnostic_names_condition_and_exact_read_without_cascade() {
    let text = format!("{HEADER}action read(pair Pair) -> string {{ return pair.left.value }}");
    let errors = tests::check(&text);
    assert_eq!(errors.len(), 1, "{errors:?}");
    let error = &errors[0];
    assert_eq!(
        error.code,
        diagnostic_code!("expr.conditional_without_presence")
    );
    assert_eq!(&text[error.span.start..error.span.end], "pair.left.value");
    assert!(error.message.contains("`pair.left.kind` is \"ready\""));
    assert_eq!(error.related.len(), 1);
    assert_eq!(
        &text[error.related[0].span.start..error.related[0].span.end],
        "string"
    );
    assert_eq!(compile_program(&text).diagnostics, errors);
}

#[test]
fn action_presence_operator_checks_use_proved_field_types() {
    for (expression, code) in [
        (
            "item.value + 1",
            diagnostic_code!("expr.non_numeric_operand"),
        ),
        (
            "item.value && true",
            diagnostic_code!("expr.non_boolean_operand"),
        ),
        (
            "item.value == 1",
            diagnostic_code!("expr.incomparable_types"),
        ),
    ] {
        let result = if expression.contains('+') {
            "int"
        } else {
            "bool"
        };
        let fallback = if result == "int" { "0" } else { "false" };
        let text = format!("{HEADER}action read(item Item) -> {result} {{ case item.kind {{ \"ready\" => {{ return {expression} }} _ => {{ return {fallback} }} }} }}");
        let errors = tests::check(&text);
        assert_eq!(errors.len(), 1, "{text}: {errors:?}");
        assert_eq!(errors[0].code, code, "{text}: {errors:?}");
    }
    let numeric = HEADER.replace("value string", "value int");
    let text = format!("{numeric}action read(item Item) -> int {{ case item.kind {{ \"ready\" => {{ return item.value + 1 }} _ => {{ return 0 }} }} }}");
    assert!(tests::check(&text).is_empty());
}
