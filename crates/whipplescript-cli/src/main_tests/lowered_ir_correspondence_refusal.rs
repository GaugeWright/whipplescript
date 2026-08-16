//! Extracted verbatim from `main.rs` (module path `lowered_ir_correspondence_refusal_tests` is unchanged).

use super::validate_lowered_ir_artifact;
use serde_json::{json, Value};

/// A lowered-IR report claims to be the lowering OF a particular construct
/// graph. These refusals hold that correspondence: every node, edge and
/// dependency the report lowers must exist in the graph, and every dependency
/// the graph declares must be lowered. `whip verify` reads both from files, so
/// a report naming work the graph never contained is exactly what a forged
/// pairing looks like — and the sweep found none of these exercised.
fn codes(report: Value, graph: Value) -> Vec<String> {
    validate_lowered_ir_artifact(&report, &graph)
        .diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn graph_with(dependency_refs: Vec<&str>) -> Value {
    json!({
        "nodes": [{"node_id": "n1"}],
        "edges": [{"required_port_id": "req", "provided_port_id": "prov"}],
        "effect_dependencies": dependency_refs
            .iter()
            .map(|r| json!({"dependency_ref": r}))
            .collect::<Vec<_>>(),
    })
}

#[test]
fn a_report_lowering_a_node_the_graph_does_not_have_is_refused() {
    assert!(codes(
        json!({"node_lowerings": [{"node_id": "ghost"}]}),
        graph_with(vec![]),
    )
    .contains(&"lowered_ir.node_unknown".to_owned()));
}

#[test]
fn a_node_lowering_without_an_id_is_refused() {
    assert!(codes(json!({"node_lowerings": [{}]}), graph_with(vec![]))
        .contains(&"lowered_ir.node_missing".to_owned()));
}

#[test]
fn a_report_lowering_an_edge_the_graph_does_not_have_is_refused() {
    assert!(codes(
        json!({"edge_lowerings": [
            {"required_port_id": "ghost", "provided_port_id": "other"}
        ]}),
        graph_with(vec![]),
    )
    .contains(&"lowered_ir.edge_unknown".to_owned()));
}

#[test]
fn a_report_lowering_a_dependency_the_graph_does_not_declare_is_refused() {
    assert!(codes(
        json!({"dependency_lowerings": [{"dependency_ref": "ghost"}]}),
        graph_with(vec![]),
    )
    .contains(&"lowered_ir.dependency_unknown".to_owned()));
}

#[test]
fn the_same_dependency_lowered_twice_is_refused() {
    assert!(codes(
        json!({"dependency_lowerings": [
            {"dependency_ref": "d1"},
            {"dependency_ref": "d1"}
        ]}),
        graph_with(vec!["d1"]),
    )
    .contains(&"lowered_ir.dependency_duplicate".to_owned()));
}

/// The correspondence runs both ways: a dependency the graph declares and the
/// report never lowers is work silently dropped, which a one-directional check
/// would not notice.
#[test]
fn a_dependency_the_report_never_lowers_is_refused() {
    assert!(
        codes(json!({"dependency_lowerings": []}), graph_with(vec!["d1"]))
            .contains(&"lowered_ir.dependency_unlowered".to_owned())
    );
}
