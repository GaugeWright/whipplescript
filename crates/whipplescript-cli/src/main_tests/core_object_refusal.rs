//! Extracted verbatim from `main.rs` (module path `core_object_refusal_tests` is unchanged).

use super::validate_lowered_ir_core_object_kind_and_entrypoint;
use serde_json::{json, Value};

/// A lowered-IR core object declares what it is (`object_kind`) and which
/// runtime entrypoint lowers it. These refusals hold that pairing honest, on
/// the same trust boundary as the rest of the artifact verifier: a report can
/// arrive from elsewhere, and an object claiming a kind it does not lower to
/// would otherwise be believed.
///
/// The sweep found none of them exercised. Table-driven because the branches
/// are one decision — kind, then entrypoint, then the rules that pair them.
fn codes(object: Value) -> Vec<String> {
    let mut diagnostics = Vec::new();
    validate_lowered_ir_core_object_kind_and_entrypoint(&object, "o1", &mut diagnostics);
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn assert_code(object: Value, expected: &str) {
    let found = codes(object);
    assert!(
        found.iter().any(|c| c == expected),
        "expected `{expected}`, got {found:?}"
    );
}

/// The accept case, and the reason the rejections below mean something: a
/// validator refusing every object would satisfy all of them.
/// A `fact` object also has to name what it records. Writing the accept case
/// first surfaced this: the pairing alone is not enough, and a fact without
/// `entrypoint_refs` names no schema.
fn valid_fact() -> Value {
    json!({
        "object_kind": "fact",
        "runtime_entrypoint": "fact_record",
        "entrypoint_refs": {"fact": "f1", "schema": "S"},
    })
}

#[test]
fn a_well_paired_core_object_is_accepted() {
    assert_eq!(codes(valid_fact()), Vec::<String>::new());
}

#[test]
fn a_fact_object_must_name_what_it_records() {
    let mut object = valid_fact();
    object
        .as_object_mut()
        .expect("object")
        .remove("entrypoint_refs");
    assert_code(object, "lowered_ir.core_object.entrypoint_refs_missing");

    // Present but naming nothing is refused for each required ref.
    for key in ["fact", "schema"] {
        let mut object = valid_fact();
        object["entrypoint_refs"]
            .as_object_mut()
            .expect("refs")
            .insert(key.to_owned(), json!(""));
        let found = codes(object);
        assert!(
            found
                .iter()
                .any(|c| c.starts_with("lowered_ir.core_object.entrypoint_ref")),
            "an empty `{key}` ref must be refused, got {found:?}"
        );
    }
}

#[test]
fn an_object_must_declare_its_kind_and_entrypoint() {
    assert_code(json!({}), "lowered_ir.core_object.kind_missing");
    assert_code(
        json!({"object_kind": "fact"}),
        "lowered_ir.core_object.runtime_entrypoint_missing",
    );
}

#[test]
fn an_unknown_kind_is_refused() {
    assert_code(
        json!({"object_kind": "mystery", "runtime_entrypoint": "fact_record"}),
        "lowered_ir.core_object.kind_unknown",
    );
}

/// A kind and an entrypoint that do not belong together is the forgery this
/// pairing exists to catch.
#[test]
fn a_kind_paired_with_the_wrong_entrypoint_is_refused() {
    assert_code(
        json!({"object_kind": "fact", "runtime_entrypoint": "rule_template"}),
        "lowered_ir.core_object.runtime_entrypoint_mismatch",
    );
}

/// Runtime state must not be materialized into a lowered artifact: a `run`,
/// a `claim`, a `terminal` are things the runtime owns, and an artifact
/// declaring one is claiming authority over state it does not hold.
#[test]
fn a_materialized_runtime_object_is_refused() {
    for kind in ["run", "claim", "terminal"] {
        assert_code(
            json!({"object_kind": kind, "runtime_entrypoint": "fact_record"}),
            "lowered_ir.core_object.runtime_state_materialized",
        );
    }
}

#[test]
fn a_dependency_object_must_own_itself_as_a_dependency() {
    assert_code(
        json!({
            "object_kind": "dependency",
            "runtime_entrypoint": "effect_dependency_template",
            "owner_kind": "rule",
        }),
        "lowered_ir.core_object.dependency_owner_kind",
    );
}
