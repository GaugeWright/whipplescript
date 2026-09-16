use super::*;
use tests::check;

fn accepts(source: &str) {
    let errors = check(source);
    assert!(errors.is_empty(), "{source}: {errors:?}");
}
fn refuses(source: &str) {
    let errors = check(source);
    assert!(!errors.is_empty(), "{source}");
}

#[test]
fn action_null_helper_result_composes_after_exhaustive_absence_handling() {
    accepts("workflow Demo\naction first(xs int[]) -> int? { return xs[0] }\naction required(xs int[]) -> int { first(xs) as x\ncase x { null => { return 0 } _ => { return x } } }");
    accepts("workflow Demo\naction f(x int?) -> int? { case x { null => { return x } _ => { return x + 1 } } }");
    accepts("workflow Demo\nclass Item { value int? }\naction f(item Item) -> int { case item.value { null => { return 0 } _ => { return item.value } } }");
}

#[test]
fn action_null_narrowing_preserves_union_alternatives_and_inner_optionality() {
    for ty in ["int?", "int | null", "null | int", "int? | null"] {
        accepts(&format!("workflow Demo\naction f(x {ty}) -> int {{ case x {{ null => {{ return 0 }} _ => {{ return x }} }} }}"));
    }
    accepts("workflow Demo\naction f(x int | string | null) -> int | string { case x { null => { return 0 } _ => { return x } } }");
    refuses("workflow Demo\naction f(x int | string | null) -> int { case x { null => { return 0 } _ => { return x } } }");
    accepts("workflow Demo\naction f(x int?[], flag bool) -> int?[] { case flag { _ where x != null => { return x } _ => { return x } } }");
    refuses("workflow Demo\naction f(x int?[], flag bool) -> int[] { case flag { _ where x != null => { return x } _ => { return [] } } }");
    accepts("workflow Demo\naction f(x string?) -> string { case x { \"null\" => { return x } null => { return \"absent\" } _ => { return x } } }");
}

#[test]
fn action_null_guarded_arms_cannot_remove_absence_from_fallback() {
    let text = "workflow Demo\naction f(x int?, flag bool) -> int { case x { null where flag => { return 0 } _ => { return x } } }";
    let errors = check(text);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, diagnostic_code!("type.mismatch"));
    assert_eq!(&text[errors[0].span.start..errors[0].span.end], "x");
    assert!(errors[0].message.contains("expects int, got int?"));
    assert!(!errors[0].related.is_empty());
    refuses("workflow Demo\naction f(x string?) -> string { case x { \"null\" => { return x } _ => { return x } } }");
}

#[test]
fn action_null_guards_refine_only_when_every_true_alternative_proves_presence() {
    for guard in [
        "x != null",
        "null != x",
        "!(x == null)",
        "x != null && flag",
        "x != null || false",
    ] {
        accepts(&format!("workflow Demo\naction f(x int?, flag bool) -> int {{ case flag {{ _ where {guard} => {{ return x }} _ => {{ return 0 }} }} }}"));
    }
    for guard in [
        "x != null || flag",
        "other != null",
        "x == x",
        "flag",
        "x == null",
    ] {
        refuses(&format!("workflow Demo\naction f(x int?, other int?, flag bool) -> int {{ case flag {{ _ where {guard} => {{ return x }} _ => {{ return 0 }} }} }}"));
    }
    accepts("workflow Demo\naction f(x int | string | null, flag bool) -> int | string { case flag { _ where x != null => { return x } _ => { return 0 } } }");
    refuses("workflow Demo\naction f(x int | string | null, flag bool) -> int { case flag { _ where x != null => { return x } _ => { return 0 } } }");
}

#[test]
fn action_null_short_circuit_operands_use_local_condition_types() {
    for expression in [
        "x != null && x > 0",
        "x == null || x > 0",
        "!(x == null) && x > 0",
        "null != x && x > 0",
    ] {
        accepts(&format!(
            "workflow Demo\naction f(x int?) -> bool {{ return {expression} }}"
        ));
    }
    for expression in [
        "x == null && x > 0",
        "x != null || x > 0",
        "x > 0 && x != null",
        "(x != null || flag) && x > 0",
        "(x != null && x > 0) || x > 0",
    ] {
        refuses(&format!(
            "workflow Demo\naction f(x int?, flag bool) -> bool {{ return {expression} }}"
        ));
    }
    accepts("workflow Demo\nclass Item { value int }\naction f(x Item?) -> bool { return x != null && x.value > 0 }");
    accepts("workflow Demo\naction f(x int | null) -> bool { return x != null && x > 0 }");
    for expression in [
        "unknown == null",
        "null != unknown",
        "unknown == null && true",
        "x + 1 == null",
    ] {
        refuses(&format!(
            "workflow Demo\naction f(x int?) -> bool {{ return {expression} }}"
        ));
    }
    accepts("workflow Demo\naction f(x int | string | null) -> bool { return x == null }");
}

#[test]
fn action_null_exact_paths_and_lexical_shadowing_do_not_donate_presence() {
    accepts("workflow Demo\nclass Item { value int? }\naction f(item Item, flag bool) -> int { case flag { _ where item.value != null => { return item.value } _ => { return 0 } } }");
    refuses("workflow Demo\nclass Item { value int? }\naction f(item Item, other Item, flag bool) -> int { case flag { _ where item.value != null => { return other.value } _ => { return 0 } } }");
    refuses("workflow Demo\naction absent() -> int? { return null }\naction f(x int?) -> int { case x { null => { return 0 } _ => { absent() as x\nreturn x } } }");
    refuses("workflow Demo\nclass Item { value int? }\naction f(item Item, other Item) -> int { case item.value { null => { return 0 } _ => { case other { Item as item => { return item.value } } } } }");
}

#[test]
fn action_null_partition_never_opens_containers_or_invents_an_empty_domain_value() {
    let parsed = parse_program("workflow Demo");
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    for ty in [IrType::Union(vec![]), primitive(IrPrimitiveType::Int)] {
        let mut env = Environment::from_iter([("x".into(), Some(ty))]);
        env.narrow_guard(&parse_expression("x == null").unwrap(), &semantic);
        assert_eq!(env.get("x"), Some(&Some(IrType::Union(vec![]))));
    }
    for ty in [
        IrType::Array(Box::new(IrType::Optional(Box::new(primitive(
            IrPrimitiveType::Int,
        ))))),
        IrType::Sealed(Box::new(IrType::Optional(Box::new(primitive(
            IrPrimitiveType::Int,
        ))))),
    ] {
        let mut env = Environment::from_iter([("x".into(), Some(ty.clone()))]);
        env.narrow_guard(&parse_expression("x != null").unwrap(), &semantic);
        assert_eq!(env.get("x"), Some(&Some(ty)));
        env.insert("x".into(), None);
        assert_eq!(env.get("x"), Some(&None));
    }
}

#[test]
fn action_null_optional_patterns_keep_scalar_alternatives_and_existing_presence_patterns() {
    for arms in [
        "true => { return 1 } false => { return 2 } null => { return 0 }",
        "Some => { return 1 } None => { return 0 }",
        "None => { return 0 } _ => { case x { true => { return 1 } false => { return 2 } } }",
    ] {
        accepts(&format!(
            "workflow Demo\naction f(x bool?) -> int {{ case x {{ {arms} }} }}"
        ));
    }
    for (ty, arms) in [
        ("bool?", "true => { return 1 } null => { return 0 }"),
        (
            "bool?",
            "Some where flag => { return 1 } None => { return 0 }",
        ),
        ("int?", "None where flag => { return 0 } _ => { return x }"),
    ] {
        refuses(&format!(
            "workflow Demo\naction f(x {ty}, flag bool) -> int {{ case x {{ {arms} }} }}"
        ));
    }
    accepts("workflow Demo\naction f(x int?) -> int? { case x { None => { return x } Some => { return x + 1 } } }");
    accepts("workflow Demo\naction f(x int?) -> null { case x { Some => { return null } _ => { return x } } }");
    refuses("workflow Demo\naction f(x \"ready\"?) -> int { case x { None => { return 0 } Some => { return x } } }");
    refuses("workflow Demo\naction f(x \"None\"? | \"ready\") -> \"ready\" { case x { None => { return \"ready\" } _ => { return x } } }");
    refuses("workflow Demo\naction f(x int?, flag bool) -> null { case x { Some where flag => { return null } _ => { return x } } }");
    refuses("workflow Demo\naction f(x int?) -> int { case x { None => { return x } Some => { return x + 1 } } }");
    accepts("workflow Demo\nclass Item { value string }\naction f(x Item?) -> string { case x { Item as item => { return item.value } null => { return \"missing\" } } }");
}

#[test]
fn action_null_nested_short_circuit_checks_prove_each_parent_and_child() {
    let header = "workflow Demo\nclass Item { value int? }\nclass Outer { inner Item? }\n";
    for guard in [
        "x != null && x.inner != null && x.inner.value != null",
        "!(x == null || x.inner == null || x.inner.value == null)",
    ] {
        accepts(&format!("{header}action f(x Outer?, flag bool) -> int {{ case flag {{ _ where {guard} => {{ return x.inner.value }} _ => {{ return 0 }} }} }}"));
    }
    for guard in [
        "x != null && x.inner != null",
        "x != null && x.inner != null && (x.inner.value != null || flag)",
    ] {
        refuses(&format!("{header}action f(x Outer?, flag bool) -> int {{ case flag {{ _ where {guard} => {{ return x.inner.value }} _ => {{ return 0 }} }} }}"));
    }
}
