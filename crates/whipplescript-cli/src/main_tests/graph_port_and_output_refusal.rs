//! Extracted verbatim from `main.rs` (module path `graph_port_and_output_refusal_tests` is unchanged).

use super::{validate_construct_graph_node_outputs, validate_construct_graph_node_ports};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Ports tie a construct-graph node to what it requires and produces. If a
/// port names an owner that is not in the graph, or an owner that does not
/// list it back, the graph is internally inconsistent — and on a boundary
/// where reports arrive from elsewhere, that inconsistency is what a forged
/// graph looks like. The sweep found none of these exercised.
fn port_codes(nodes: Vec<Value>, ports: Vec<Value>) -> Vec<String> {
    let node_by_id: BTreeMap<String, &Value> = nodes
        .iter()
        .filter_map(|n| {
            n.get("node_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), n))
        })
        .collect();
    let port_by_id: BTreeMap<String, &Value> = ports
        .iter()
        .filter_map(|p| {
            p.get("port_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), p))
        })
        .collect();
    let mut diagnostics = Vec::new();
    validate_construct_graph_node_ports(&nodes, &node_by_id, &port_by_id, &mut diagnostics);
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn node(id: &str, required: Vec<&str>, produced: Vec<&str>) -> Value {
    json!({"node_id": id, "required_ports": required, "produced_ports": produced})
}

fn port(id: &str, owner: Option<&str>, direction: Option<&str>) -> Value {
    let mut value = json!({"port_id": id});
    if let Some(owner) = owner {
        value["owner_node_id"] = json!(owner);
    }
    if let Some(direction) = direction {
        value["direction"] = json!(direction);
    }
    value
}

/// The accept case: a node and a port that agree.
#[test]
fn a_port_its_owner_lists_is_accepted() {
    assert_eq!(
        port_codes(
            vec![node("n1", vec!["p1"], vec![])],
            vec![port("p1", Some("n1"), Some("required"))],
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_port_must_name_an_owner_that_exists_and_lists_it() {
    assert!(port_codes(vec![], vec![port("p1", None, Some("required"))])
        .contains(&"construct_graph.port.owner_missing".to_owned()));

    assert!(
        port_codes(vec![], vec![port("p1", Some("ghost"), Some("required"))])
            .contains(&"construct_graph.port.owner_unknown".to_owned())
    );

    // The owner exists but does not list the port back.
    assert!(port_codes(
        vec![node("n1", vec![], vec![])],
        vec![port("p1", Some("n1"), Some("required"))],
    )
    .contains(&"construct_graph.port.not_listed_by_owner".to_owned()));
}

#[test]
fn a_port_must_declare_a_known_direction() {
    assert!(port_codes(
        vec![node("n1", vec!["p1"], vec![])],
        vec![port("p1", Some("n1"), Some("sideways"))],
    )
    .contains(&"construct_graph.port.direction_unknown".to_owned()));
}

/// A node declares which core-object kinds and runtime entrypoints it may
/// emit. `output_runtime_state` is the authority check of the pair: a node
/// claiming it can emit a `run` or a `claim` is claiming to produce state the
/// runtime owns.
fn output_codes(node: Value) -> Vec<String> {
    let mut diagnostics = Vec::new();
    validate_construct_graph_node_outputs(&[node], &mut diagnostics);
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

#[test]
fn a_node_declaring_supported_outputs_is_accepted() {
    assert_eq!(
        output_codes(json!({
            "node_id": "n1",
            "allowed_core_object_kinds": ["fact"],
            "allowed_runtime_entrypoints": ["fact_record"],
        })),
        Vec::<String>::new()
    );
}

#[test]
fn a_node_cannot_declare_it_emits_runtime_state() {
    for kind in ["run", "claim", "terminal"] {
        assert!(
            output_codes(json!({
                "node_id": "n1",
                "allowed_core_object_kinds": [kind],
                "allowed_runtime_entrypoints": ["fact_record"],
            }))
            .contains(&"construct_graph.node.output_runtime_state".to_owned()),
            "a node must not claim it emits `{kind}`"
        );
    }
}

#[test]
fn a_node_cannot_declare_an_unknown_output_kind() {
    assert!(output_codes(json!({
        "node_id": "n1",
        "allowed_core_object_kinds": ["mystery"],
        "allowed_runtime_entrypoints": ["fact_record"],
    }))
    .contains(&"construct_graph.node.output_kind_unknown".to_owned()));
}
