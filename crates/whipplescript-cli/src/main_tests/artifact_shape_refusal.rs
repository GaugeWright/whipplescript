//! Extracted verbatim from `main.rs` (module path `artifact_shape_refusal_tests` is unchanged).

use super::{
    validate_construct_graph_artifact, validate_construct_graph_object_shape,
    validate_lowered_ir_object_shape,
};
use serde_json::{json, Value};

/// These validators sit on a TRUST BOUNDARY. `whip verify` reads a report from
/// a file and decides whether to believe evidence produced elsewhere, so a
/// refusal that does not fire means a corrupt or forged artifact is accepted.
/// A mutation sweep found ~100 of their rejections unexercised.
///
/// The `object_expected` / `field_missing` / `field_unknown` families are
/// emitted by one shared helper per artifact, parameterised by owner kind, so
/// exercising the helper covers every kind at once. Testing a hundred
/// near-identical call sites separately would assert the same three branches
/// over and over while leaving the distinct consistency rules untouched.
fn graph_shape(value: &Value, required: &[&str], allowed: &[&str]) -> Vec<String> {
    let mut diagnostics = Vec::new();
    validate_construct_graph_object_shape(
        value,
        "node",
        "n1",
        "nodes",
        required,
        allowed,
        &mut diagnostics,
    );
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn lowered_shape(value: &Value, required: &[&str], allowed: &[&str]) -> Vec<String> {
    let mut diagnostics = Vec::new();
    validate_lowered_ir_object_shape(
        value,
        "node",
        "n1",
        json!({"nodes": ["n1"]}),
        required,
        allowed,
        &mut diagnostics,
    );
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

#[test]
fn a_construct_graph_object_must_be_an_object_with_exactly_the_declared_fields() {
    assert!(graph_shape(&json!("nope"), &["id"], &["id"])
        .contains(&"construct_graph.node.object_expected".to_owned()));
    assert!(graph_shape(&json!({}), &["id"], &["id"])
        .contains(&"construct_graph.node.field_missing".to_owned()));
    assert!(
        graph_shape(&json!({"id": "n1", "extra": 1}), &["id"], &["id"])
            .contains(&"construct_graph.node.field_unknown".to_owned())
    );
    // The accept case: a validator refusing every object would satisfy all three.
    assert_eq!(
        graph_shape(&json!({"id": "n1"}), &["id"], &["id"]),
        Vec::<String>::new()
    );
}

#[test]
fn a_lowered_ir_object_must_be_an_object_with_exactly_the_declared_fields() {
    assert!(lowered_shape(&json!("nope"), &["id"], &["id"])
        .contains(&"lowered_ir.node.object_expected".to_owned()));
    assert!(lowered_shape(&json!({}), &["id"], &["id"])
        .contains(&"lowered_ir.node.field_missing".to_owned()));
    assert!(
        lowered_shape(&json!({"id": "n1", "extra": 1}), &["id"], &["id"])
            .contains(&"lowered_ir.node.field_unknown".to_owned())
    );
    assert_eq!(
        lowered_shape(&json!({"id": "n1"}), &["id"], &["id"]),
        Vec::<String>::new()
    );
}

/// A construct graph missing a whole section is refused before any per-element
/// check runs, so each top-level key needs its own case.
#[test]
fn a_construct_graph_missing_a_section_is_refused() {
    // Every root field the graph declares, so the only diagnostics below come
    // from the section this case removes.
    let complete = json!({
        "schema": "whip.construct_graph/v0",
        "graph_id": "g1",
        "platform_version": "0",
        "package_lock_digest": "0",
        "package_contract_digest": "0",
        "source_digest": "0",
        "nodes": [],
        "ports": [],
        "edges": [],
        "effect_dependencies": [],
        "derived_facts": [],
        "diagnostics": [],
    });
    for (key, code) in [
        ("nodes", "construct_graph.nodes_missing"),
        ("ports", "construct_graph.ports_missing"),
        ("edges", "construct_graph.edges_missing"),
        (
            "effect_dependencies",
            "construct_graph.effect_dependencies_missing",
        ),
    ] {
        let mut graph = complete.clone();
        graph.as_object_mut().expect("object").remove(key);
        let codes: Vec<String> = validate_construct_graph_artifact(&graph)
            .diagnostics
            .iter()
            .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert!(
            codes.contains(&code.to_owned()),
            "dropping `{key}` must raise `{code}`, got {codes:?}"
        );
    }

    // A graph with every section present raises none of the four.
    let codes: Vec<String> = validate_construct_graph_artifact(&complete)
        .diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect();
    assert!(
        !codes.iter().any(|c| c.ends_with("_missing")),
        "a complete graph must raise no section-missing code, got {codes:?}"
    );
}
