//! Extracted verbatim from `main.rs` (module path `lowered_ir_field_refusal_tests` is unchanged).

use super::{
    validate_lowered_ir_enum_field, validate_lowered_ir_nonempty_string_field,
    validate_lowered_ir_span_field, validate_lowered_ir_string_ref_set_field,
};
use serde_json::{json, Value};

/// The `<field>_invalid` codes across the lowered-IR verifier all come from
/// four small field helpers, parameterised by owner kind and field name. The
/// sweep counted their instances separately, but there are four behaviours
/// here, not thirty: exercising the helpers covers every instance, and
/// exercising the instances would assert the same four branches repeatedly.
fn codes(run: impl FnOnce(&mut Vec<Value>)) -> Vec<String> {
    let mut diagnostics = Vec::new();
    run(&mut diagnostics);
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn refs() -> Value {
    json!({"nodes": ["n1"]})
}

#[test]
fn a_non_empty_string_field_rejects_empty_and_non_string() {
    for bad in [json!(""), json!(7), json!(null)] {
        let found = codes(|d| {
            validate_lowered_ir_nonempty_string_field(
                &json!({"name": bad}),
                "node",
                "n1",
                refs(),
                "name",
                d,
            )
        });
        assert!(
            found.contains(&"lowered_ir.node.name_invalid".to_owned()),
            "{bad} must be refused, got {found:?}"
        );
    }

    // Present and non-empty is accepted; absent is not this helper's business.
    assert_eq!(
        codes(|d| validate_lowered_ir_nonempty_string_field(
            &json!({"name": "n"}),
            "node",
            "n1",
            refs(),
            "name",
            d
        )),
        Vec::<String>::new()
    );
    assert_eq!(
        codes(|d| validate_lowered_ir_nonempty_string_field(
            &json!({}),
            "node",
            "n1",
            refs(),
            "name",
            d
        )),
        Vec::<String>::new()
    );
}

#[test]
fn an_enum_field_rejects_a_value_outside_its_domain() {
    let found = codes(|d| {
        validate_lowered_ir_enum_field(
            &json!({"kind": "mystery"}),
            "node",
            "n1",
            refs(),
            "kind",
            &["fact", "rule"],
            d,
        )
    });
    assert!(
        found.contains(&"lowered_ir.node.kind_invalid".to_owned()),
        "{found:?}"
    );

    for allowed in ["fact", "rule"] {
        assert_eq!(
            codes(|d| validate_lowered_ir_enum_field(
                &json!({"kind": allowed}),
                "node",
                "n1",
                refs(),
                "kind",
                &["fact", "rule"],
                d
            )),
            Vec::<String>::new(),
            "`{allowed}` is in the declared domain"
        );
    }
}

#[test]
fn a_span_field_rejects_a_malformed_span() {
    let found = codes(|d| {
        validate_lowered_ir_span_field(
            &json!({"span": "not a span"}),
            "node",
            "n1",
            refs(),
            "span",
            d,
        )
    });
    assert!(
        found.contains(&"lowered_ir.node.span_invalid".to_owned()),
        "{found:?}"
    );
}

#[test]
fn a_string_ref_set_field_rejects_a_non_set() {
    for bad in [json!("nope"), json!([1]), json!(["a", "a"])] {
        let found = codes(|d| {
            validate_lowered_ir_string_ref_set_field(
                &json!({"refs": bad}),
                "node",
                "n1",
                refs(),
                "refs",
                d,
            )
        });
        assert!(
            found.contains(&"lowered_ir.node.refs_invalid".to_owned()),
            "{bad} must be refused, got {found:?}"
        );
    }

    assert_eq!(
        codes(|d| validate_lowered_ir_string_ref_set_field(
            &json!({"refs": ["a", "b"]}),
            "node",
            "n1",
            refs(),
            "refs",
            d
        )),
        Vec::<String>::new()
    );
}
