use super::super::tests::check;
use super::*;
fn source(parameters: &str, result: &str, expression: &str) -> String {
    format!("workflow Demo\nclass Ticket {{ id string }}\naction lookup({parameters}) -> {result} {{ return {expression} }}")
}
#[test]
fn action_indexing_retains_possible_absence_for_collections_and_unions() {
    for (parameters, result, expression) in [
        ("xs int[]", "int?", "xs[0]"),
        ("xs map<string>", "string?", "xs[\"name\"]"),
        ("xs int[]?", "int?", "xs[0]"),
        ("xs map<string> | null", "string?", "xs[\"name\"]"),
        ("xs int[] | string[]", "int | string | null", "xs[0]"),
        ("xs int[]", "bool", "xs[0] == null"),
        ("xs map<string>", "bool", "xs[\"name\"] == null"),
        ("xs int[]", "bool", "exists(xs[0])"),
    ] {
        let text = source(parameters, result, expression);
        assert!(check(&text).is_empty(), "{text}: {:?}", check(&text));
    }
    for (parameters, result, expression) in [
        ("xs int[]", "int", "xs[0]"),
        ("xs map<string>", "string", "xs[\"name\"]"),
        ("xs int[] | string[]", "int?", "xs[0]"),
        ("xs int[]", "int", "xs[0] + 1"),
    ] {
        let text = source(parameters, result, expression);
        assert!(!check(&text).is_empty(), "{text}");
    }
}
#[test]
fn action_indexing_literal_presence_does_not_escape_through_helpers_or_dynamic_keys() {
    for (parameters, result, expression) in [
        ("", "int", "[1, \"other\"][0]"),
        ("", "string", "[1, \"other\"][1]"),
        ("", "null", "[1][2]"),
        ("", "int?", "[1][0 - 1]"),
        ("", "null", "[][0]"),
        ("item Ticket", "Ticket", "[item][0]"),
        ("", "Ticket", "[{ id \"literal\" }][0]"),
        ("", "int", "[1][0] + 1"),
        ("", "bool", "not [true][0]"),
        ("index int", "int?", "[1][index]"),
    ] {
        let text = source(parameters, result, expression);
        assert!(check(&text).is_empty(), "{text}: {:?}", check(&text));
    }
    for text in [
        source("index int","int","[1][index]"),
        source("","int","[1, unknown][0]"),
        source("","Ticket","[{ id \"valid\" }, { unknown \"untyped\" }][0]"),
        "workflow Demo\naction make() -> int[] { return [1] }\naction read() -> int { make() as xs\nreturn xs[0] }".into(),
    ] { assert!(!check(&text).is_empty(),"{text}"); }
}
#[test]
fn action_indexing_reports_invalid_key_and_target_types_without_unknown_fallback() {
    for (parameters, expression, message) in [
        ("xs int[]", "xs[\"0\"]", "array index requires int"),
        ("xs int[]", "xs[1.0]", "array index requires int"),
        ("xs map<int>", "xs[0]", "map index requires string"),
        (
            "xs int[], key int | string",
            "xs[key]",
            "array index requires int",
        ),
        ("xs int[] | string", "xs[0]", "cannot index string"),
        ("xs Ticket", "xs[\"id\"]", "cannot index Ticket"),
        ("xs null", "xs[0]", "no array or map value type"),
    ] {
        let text = source(parameters, "int?", expression);
        let errors = check(&text);
        assert_eq!(errors.len(), 1, "{text}: {errors:?}");
        assert!(errors[0].message.contains(message), "{errors:?}");
        assert_eq!(&text[errors[0].span.start..errors[0].span.end], expression);
    }
}
#[test]
fn action_indexing_empty_type_domain_is_not_a_present_element_proof() {
    let parsed = parse_program("workflow Demo");
    let semantic = SemanticContext::from_program(&parsed.program, BTreeMap::new());
    assert!(result(
        &IrType::Union(vec![]),
        &primitive(IrPrimitiveType::Int),
        &semantic
    )
    .is_err());
}
