use super::*;
use crate::action_types::tests::check;

fn body(source: &str) -> Vec<Diagnostic> {
    check(&format!(
        "workflow Demo\naction f(x bool) -> int ! string {{ {source} }}"
    ))
}

#[test]
fn every_successful_alternative_owes_a_real_return() {
    for source in [
        "return 1",
        "case x { true => { return 1 } false => { return 2 } }",
        "case x { true => { return 1 } false => { fail \"no\" } }",
        "fail \"no\"",
        "case true { true => { return 1 } }",
    ] {
        assert!(body(source).is_empty(), "{source}: {:?}", body(source));
    }
    for source in [
        "",
        "timer 1s as t",
        "case x { true => { return 1 } }",
        "case x { true => { record X { n 1 } } false => { return 2 } }",
    ] {
        assert!(
            body(source)
                .iter()
                .any(|d| d.message.contains("successful path without a return")),
            "{source}: {:?}",
            body(source)
        );
    }
}

#[test]
fn an_optional_result_does_not_manufacture_a_null_return() {
    let diagnostics = check("workflow Demo\naction f() -> string? { }");
    assert!(diagnostics
        .iter()
        .any(|d| d.message.contains("without a return")));
}

#[test]
fn independent_returns_conflict_but_same_selector_alternatives_do_not() {
    let source = "case x { true => { return 1 } }\ncase x { false => { return 2 } }";
    assert!(body(source).is_empty(), "{:?}", body(source));
    let source = "case x { true => { return 1 } false => { return 2 } }\ncase x { true => { return 3 } false => { return 4 } }";
    let diagnostics = body(source);
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("select two returns") && !d.related.is_empty()),
        "{diagnostics:?}"
    );
}

#[test]
fn independent_after_blocks_are_not_a_source_order_chain() {
    let source = "timer 1s as a\ntimer 1s as b\nafter a succeeds { return 1 }\nafter b succeeds { return 2 }";
    assert!(body(source)
        .iter()
        .any(|d| d.message.contains("select two returns")));
    let source = "timer 1s as a\nafter a succeeds { return 1 }\nafter a fails { return 2 }";
    assert!(body(source).is_empty(), "{:?}", body(source));
    let source = "timer 1s as a\nafter a succeeds { return 1 }\nafter a completes { return 2 }";
    assert!(body(source)
        .iter()
        .any(|d| d.message.contains("select two returns")));
}

#[test]
fn then_sequences_success_without_requiring_a_fake_failure_return() {
    assert!(body("then a <- timer 1s\nthen b <- timer 1s\nreturn 1").is_empty());
    assert!(body("then a <- timer 1s")
        .iter()
        .any(|d| d.message.contains("without a return")));
}

#[test]
fn direct_return_or_fail_makes_the_lexical_tail_unreachable() {
    for source in ["return 1\ntimer 1s as t", "fail \"bad\"\nreturn 1"] {
        assert!(
            body(source)
                .iter()
                .any(|d| d.message.contains("unreachable")),
            "{source}"
        );
    }
}

#[test]
fn enums_and_open_domains_keep_unmatched_alternatives() {
    let header = "workflow Demo\nenum Status { yes\nno }\n";
    assert!(check(&format!("{header}action f(x Status) -> int {{ case x {{ yes => {{ return 1 }} no => {{ return 2 }} }} }}")).is_empty());
    assert!(check(&format!(
        "{header}action f(x Status) -> int {{ case x {{ yes => {{ return 1 }} }} }}"
    ))
    .iter()
    .any(|d| d.message.contains("without a return")));
    for value in ["known", "<other>"] {
        let source = format!("workflow Demo\naction f(x string) -> int {{ case x {{ \"{value}\" => {{ return 1 }} }} }}");
        assert!(
            check(&source)
                .iter()
                .any(|d| d.message.contains("without a return")),
            "{source}"
        );
    }
    assert!(check("workflow Demo\naction f(x string) -> int { case x { \"known\" => { return 1 } _ => { return 2 } } }").is_empty());
}

#[test]
fn operation_value_selection_waits_for_success() {
    let source = "workflow Demo\naction inner() -> bool { return true }\naction f() -> int { inner() as result\ncase result { true => { return 1 } false => { return 2 } }\nafter result fails { return 3 } }";
    assert!(check(source).is_empty(), "{:?}", check(source));
}

#[test]
fn scalar_literal_selectors_do_not_invent_unreachable_paths() {
    let source = "case false { false => { return 1 } }";
    assert!(body(source).is_empty(), "{source}: {:?}", body(source));
}

#[test]
fn selector_keys_keep_operators_function_names_and_literals() {
    let bindings = Bindings::new();
    for (left, right) in [
        ("x == true", "x != true"),
        ("x == true", "x == false"),
        ("count(x)", "empty(x)"),
        ("\"one\"", "\"two\""),
    ] {
        assert_ne!(
            selector_key(&parse_expression(left).unwrap(), &bindings),
            selector_key(&parse_expression(right).unwrap(), &bindings)
        );
    }
}

#[test]
fn duplicate_operations_and_unavailable_after_sources_are_refused() {
    for source in [
        "timer 1s as a\ntimer 2s as a\nreturn 1",
        "after missing succeeds { return 1 }",
        "after x succeeds { return 1 }",
    ] {
        assert!(!body(source).is_empty(), "{source}");
    }
}

#[test]
fn generated_source_spans_do_not_merge_distinct_operations() {
    let parsed = parse_program("workflow Demo\naction f() -> int { timer 1s as a\ntimer 1s as b\nafter a fails { return 1 }\nafter b succeeds { return 2 } }");
    assert!(parsed.diagnostics.is_empty());
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    let Item::Action(mut action) = parsed.program.items[0].clone() else {
        panic!("action")
    };
    action.body = BlockSource::generated(action.body.text.to_string(), action.span);
    let diagnostics = super::super::validate(&[action], &semantic);
    assert!(
        diagnostics
            .iter()
            .any(|d| d.message.contains("select two returns")),
        "{diagnostics:?}"
    );
}

#[test]
fn patterns_preserve_scalar_types_and_open_domain_sentinels_are_not_values() {
    for source in [
        "workflow Demo\naction f(x string) -> int { case x { true => { return 1 } } }",
        "workflow Demo\naction f(x bool) -> int { case x { \"true\" => { return 1 } \"false\" => { return 2 } } }",
    ] { assert!(check(source).iter().any(|d| d.message.contains("does not match the type")), "{source}: {:?}", check(source)); }
}

#[test]
fn constant_selectors_may_keep_valid_unselected_branches() {
    let source = "case true { true => { return 1 } false => { return 2 } }";
    assert!(body(source).is_empty(), "{source}: {:?}", body(source));
}

#[test]
fn guards_must_be_boolean_and_do_not_erase_unmatched_paths() {
    for source in [
        "case x { true where 42 => { return 1 } false => { return 2 } }",
        "case x { true where missing => { return 1 } false => { return 2 } }",
    ] {
        assert!(
            body(source)
                .iter()
                .any(|d| d.message.contains("known boolean expression")),
            "{source}: {:?}",
            body(source)
        );
    }
    assert!(
        body("case x { true where false => { return 1 } false => { return 2 } }")
            .iter()
            .any(|d| d.message.contains("without a return"))
    );
    let good = "case x { true where x => { return 1 } false where !x => { return 2 } }";
    assert!(body(good).is_empty(), "{:?}", body(good));
}

#[test]
fn an_unavailable_guard_is_not_false_and_cannot_enable_fallback() {
    let source = "workflow Demo\naction inner() -> bool { return true }\naction f(x bool) -> int { inner() as result\ncase x { _ where !result => { return 1 } _ => { return 2 } }\nafter result fails { return 3 } }";
    assert!(check(source).is_empty(), "{:?}", check(source));
}

#[test]
fn unknown_case_alternatives_and_unlowered_control_contracts_refuse() {
    for (source, message) in [
        (
            "case missing { _ => { return 1 } }",
            "cannot determine the alternatives",
        ),
        (
            "timer 1s as t\nafter t ok { return 1 }",
            "does not yet lower this outcome predicate",
        ),
    ] {
        assert!(
            body(source).iter().any(|d| d.message.contains(message)),
            "{source}: {:?}",
            body(source)
        );
    }
    let source = "workflow Demo\nenum Status { yes\nno }\naction f(x Status) -> int { case x { other => { return 1 } } }";
    assert!(
        check(source)
            .iter()
            .any(|d| d.message.contains("not an alternative")),
        "{:?}",
        check(source)
    );
}

#[test]
fn region_return_paths_preserve_entry_lapse_and_clean_exit_history() {
    for source in [
        "during x { return 1 } on lapse { fail \"lapsed\" }",
        "during x { } on lapse as progress { return 2 }\nreturn 1",
        "until x { return 1 } on lapse { fail \"finished\" }",
    ] {
        assert!(body(source).is_empty(), "{source}: {:?}", body(source));
    }

    let missing = body("during x { return 1 } on lapse { }");
    assert!(
        missing.iter().any(|diagnostic| diagnostic
            .message
            .contains("successful path without a return")
            && diagnostic.message.contains("lapse at entry")),
        "{missing:?}"
    );
}

#[test]
fn a_held_result_survives_lapse_and_can_conflict_with_lapse_recovery() {
    let diagnostics = body("during x { return 1 } on lapse { return 2 }");
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains("select two returns")
                && diagnostic.message.contains("lapse after entry")
                && !diagnostic.related.is_empty()
        }),
        "{diagnostics:?}"
    );

    let diagnostics = body("during x { return 1 } on lapse { fail \"lapsed\" }\nreturn 2");
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.message.contains("select two returns")
                && diagnostic.message.contains("clean exit")
        }),
        "{diagnostics:?}"
    );
}

#[test]
fn a_direct_contract_check_never_treats_an_unparsed_body_as_valid() {
    let parsed =
        parse_program("workflow Demo\naction f(x int) -> int { case x { 1 => { return 1 } } }");
    assert!(parsed.diagnostics.is_empty());
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    let Item::Action(action) = parsed.program.items[0].clone() else {
        panic!("action")
    };
    assert!(!super::super::validate(&[action], &semantic).is_empty());
}

#[test]
fn independent_operation_continuations_do_not_share_a_value() {
    let source = "workflow Demo\naction inner() -> bool { return true }\naction f() -> int { inner() as a\ninner() as b\nafter a succeeds { case a { true => { return 1 } } }\nafter b succeeds { case b { false => { return 2 } } } }";
    assert!(
        check(source)
            .iter()
            .any(|d| d.message.contains("select two returns")),
        "{:?}",
        check(source)
    );
}
