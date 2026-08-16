//! Extracted verbatim from `main.rs` (module path `artifact_metadata_refusal_tests` is unchanged).

//! The metadata rules are the last unexercised corner of the artifact
//! validators, and they sit on the same trust boundary as the rest: `whip
//! verify` reads a report from a file and decides whether to believe
//! evidence produced elsewhere.
//!
//! Three small `Result`-returning validators carry the actual rules, and a
//! dozen call sites wrap each one in a diagnostic code. Testing the inner
//! validators covers every rule once; testing one wrapper per code proves
//! the reason reaches the report rather than being swallowed. Asserting on
//! the reason TEXT is deliberate — a wrapper that discards it still emits
//! the right code, so a code-only assertion cannot tell a useful diagnostic
//! from a useless one.

use super::{
    validate_artifact_derived_fact_metadata, validate_artifact_diagnostic_metadata,
    validate_artifact_string_ref_array_value, validate_construct_graph_interface_shapes,
    validate_lowered_ir_derived_fact_metadata, validate_lowered_ir_diagnostic_metadata,
    validate_lowered_ir_required_string_array_field, validate_lowered_ir_validator_shapes,
};
use serde_json::{json, Value};

fn reason(result: Result<(), String>) -> String {
    result.expect_err("expected a rejection")
}

fn codes(diagnostics: &[Value]) -> Vec<String> {
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn messages(diagnostics: &[Value]) -> Vec<String> {
    diagnostics
        .iter()
        .filter_map(|d| d.get("message").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

#[test]
fn diagnostic_metadata_rules_reject_and_accept() {
    // Accept first: a well-formed diagnostic must survive every rule below,
    // or the rejections prove nothing.
    assert!(validate_artifact_diagnostic_metadata(
        &json!({
            "code": "some.code",
            "severity": "error",
            "refs": {"nodes": ["n1", "n2"]},
        }),
        true,
    )
    .is_ok());

    assert_eq!(
        reason(validate_artifact_diagnostic_metadata(
            &json!("not an object"),
            false
        )),
        "diagnostic must be an object"
    );
    assert_eq!(
        reason(validate_artifact_diagnostic_metadata(
            &json!({"code": ""}),
            false
        )),
        "`code` must be a non-empty string"
    );
    assert_eq!(
        reason(validate_artifact_diagnostic_metadata(
            &json!({"severity": "catastrophe"}),
            false
        )),
        "`severity` must be `error`, `warning`, `info`, or `hint`"
    );
    assert_eq!(
        reason(validate_artifact_diagnostic_metadata(
            &json!({"refs": ["nodes"]}),
            false
        )),
        "`refs` must be an object"
    );
    // The `refs` values delegate to the string-ref-array rules, and the
    // label names which key failed.
    assert_eq!(
        reason(validate_artifact_diagnostic_metadata(
            &json!({"refs": {"nodes": ["n1", "n1"]}}),
            true
        )),
        "`refs.nodes` contains duplicate ref `n1`"
    );
    // ... and only when uniqueness is required of this artifact.
    assert!(validate_artifact_diagnostic_metadata(
        &json!({"refs": {"nodes": ["n1", "n1"]}}),
        false
    )
    .is_ok());
}

#[test]
fn derived_fact_metadata_rules_reject_and_accept() {
    assert!(validate_artifact_derived_fact_metadata(&json!({
        "predicate": "holds",
        "owner_subsystem": "kernel",
    }))
    .is_ok());

    assert_eq!(
        reason(validate_artifact_derived_fact_metadata(&json!([]))),
        "derived fact must be an object"
    );
    assert_eq!(
        reason(validate_artifact_derived_fact_metadata(
            &json!({"predicate": ""})
        )),
        "`predicate` must be a non-empty string"
    );
    assert_eq!(
        reason(validate_artifact_derived_fact_metadata(
            &json!({"owner_subsystem": 7})
        )),
        "`owner_subsystem` must be a non-empty string"
    );
}

#[test]
fn string_ref_array_rules_reject_and_accept() {
    assert!(
        validate_artifact_string_ref_array_value(&json!(["a", "b"]), "`refs.nodes`", true).is_ok()
    );

    assert_eq!(
        reason(validate_artifact_string_ref_array_value(
            &json!("a"),
            "`refs.nodes`",
            false
        )),
        "`refs.nodes` must be an array"
    );
    assert_eq!(
        reason(validate_artifact_string_ref_array_value(
            &json!(["a", ""]),
            "`refs.nodes`",
            false
        )),
        "`refs.nodes` must contain only non-empty strings"
    );
    assert_eq!(
        reason(validate_artifact_string_ref_array_value(
            &json!(["a", 1]),
            "`refs.nodes`",
            false
        )),
        "`refs.nodes` must contain only non-empty strings"
    );
    assert_eq!(
        reason(validate_artifact_string_ref_array_value(
            &json!(["a", "a"]),
            "`refs.nodes`",
            true
        )),
        "`refs.nodes` contains duplicate ref `a`"
    );
}

#[test]
fn lowered_ir_metadata_wrappers_carry_the_reason_into_the_report() {
    let mut diagnostics = Vec::new();
    validate_lowered_ir_diagnostic_metadata(
        &json!({"severity": "catastrophe"}),
        "some.code",
        &mut diagnostics,
    );
    assert_eq!(
        codes(&diagnostics),
        ["lowered_ir.diagnostic.metadata_invalid"]
    );
    assert_eq!(
            messages(&diagnostics),
            ["lowered IR diagnostic `some.code` has invalid metadata: `severity` must be `error`, `warning`, `info`, or `hint`"]
        );

    let mut diagnostics = Vec::new();
    validate_lowered_ir_derived_fact_metadata(&json!({"predicate": ""}), "holds", &mut diagnostics);
    assert_eq!(
        codes(&diagnostics),
        ["lowered_ir.derived_fact.metadata_invalid"]
    );
    assert_eq!(
            messages(&diagnostics),
            ["lowered IR derived fact `holds` has invalid metadata: `predicate` must be a non-empty string"]
        );

    // A non-object short-circuits before the metadata rules run, so the
    // shape validator owns that case and this one stays quiet.
    let mut diagnostics = Vec::new();
    validate_lowered_ir_diagnostic_metadata(&json!("nope"), "some.code", &mut diagnostics);
    assert!(diagnostics.is_empty());
}

#[test]
fn duplicate_derived_facts_are_refused_by_whole_value_not_predicate() {
    let mut diagnostics = Vec::new();
    validate_lowered_ir_validator_shapes(
        &json!({"derived_facts": [
            {"predicate": "holds", "owner_subsystem": "kernel"},
            {"predicate": "holds", "owner_subsystem": "kernel"},
        ]}),
        &mut diagnostics,
    );
    assert!(
        codes(&diagnostics).contains(&"lowered_ir.derived_fact.duplicate".to_owned()),
        "got {:?}",
        codes(&diagnostics)
    );
    // The message must name WHICH predicate is duplicated — a report that
    // says only "something is duplicated" cannot be acted on.
    assert!(
        messages(&diagnostics)
            .contains(&"lowered IR derived fact `holds` is duplicated".to_owned()),
        "got {:?}",
        messages(&diagnostics)
    );

    // Two facts sharing a predicate but differing elsewhere are distinct
    // evidence, not a duplicate — the check is on the canonical value.
    let mut diagnostics = Vec::new();
    validate_lowered_ir_validator_shapes(
        &json!({"derived_facts": [
            {"predicate": "holds", "owner_subsystem": "kernel"},
            {"predicate": "holds", "owner_subsystem": "parser"},
        ]}),
        &mut diagnostics,
    );
    assert!(
        !codes(&diagnostics).contains(&"lowered_ir.derived_fact.duplicate".to_owned()),
        "got {:?}",
        codes(&diagnostics)
    );
}

#[test]
fn preservation_field_rules_reject_and_accept() {
    fn check(value: Value) -> Vec<String> {
        let mut diagnostics = Vec::new();
        validate_lowered_ir_required_string_array_field(
            "rule",
            "r1",
            &value,
            "preserved",
            &mut diagnostics,
            json!({"rules": ["r1"]}),
        );
        codes(&diagnostics)
    }

    assert!(check(json!({"preserved": ["a", "b"]})).is_empty());
    assert_eq!(
        check(json!({})),
        ["lowered_ir.rule.preservation_field_missing"]
    );
    assert_eq!(
        check(json!({"preserved": "a"})),
        ["lowered_ir.rule.preservation_field_invalid"]
    );
    assert_eq!(
        check(json!({"preserved": ["a", ""]})),
        ["lowered_ir.rule.preservation_field_invalid"]
    );
    assert_eq!(
        check(json!({"preserved": ["a", "a"]})),
        ["lowered_ir.rule.preservation_field_duplicate"]
    );
}

#[test]
fn interface_collection_must_be_an_array() {
    let mut diagnostics = Vec::new();
    validate_construct_graph_interface_shapes(
        &json!({"provides": {"not": "an array"}}),
        "n1",
        "provides",
        &mut diagnostics,
    );
    assert_eq!(
        codes(&diagnostics),
        ["construct_graph.interface.collection_invalid"]
    );

    // An absent collection is not an invalid one.
    let mut diagnostics = Vec::new();
    validate_construct_graph_interface_shapes(&json!({}), "n1", "provides", &mut diagnostics);
    assert!(diagnostics.is_empty());
}
