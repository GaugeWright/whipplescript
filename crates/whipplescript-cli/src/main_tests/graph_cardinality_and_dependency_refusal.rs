//! Extracted verbatim from `main.rs` (module path `graph_cardinality_and_dependency_refusal_tests` is unchanged).

use super::{validate_construct_graph_cardinality, validate_construct_graph_effect_dependencies};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Cardinality says how many providers a required port may have. It is the
/// rule that stops a graph from quietly wiring two providers into a port that
/// admits one — an ambiguity the runtime would have to resolve arbitrarily.
/// The sweep found these unexercised.
fn cardinality_codes(ports: Vec<Value>, edges: Vec<Value>) -> Vec<String> {
    let port_by_id: BTreeMap<String, &Value> = ports
        .iter()
        .filter_map(|p| {
            p.get("port_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), p))
        })
        .collect();
    let mut diagnostics = Vec::new();
    validate_construct_graph_cardinality(&port_by_id, &edges, &mut diagnostics);
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn required_port(cardinality: &str) -> Value {
    json!({"port_id": "req", "direction": "required", "cardinality": cardinality})
}

fn edge_to_req() -> Value {
    json!({"required_port_id": "req", "provider_node_id": "p", "provided_port_id": "prov"})
}

#[test]
fn an_exactly_one_port_wired_once_is_accepted() {
    assert_eq!(
        cardinality_codes(vec![required_port("exactly-one")], vec![edge_to_req()]),
        Vec::<String>::new()
    );
}

#[test]
fn an_exactly_one_port_wired_twice_is_refused() {
    assert!(cardinality_codes(
        vec![required_port("exactly-one")],
        vec![edge_to_req(), edge_to_req()],
    )
    .contains(&"construct_graph.cardinality.exactly_one".to_owned()));
}

#[test]
fn an_optional_one_port_wired_twice_is_refused() {
    assert!(cardinality_codes(
        vec![required_port("optional-one")],
        vec![edge_to_req(), edge_to_req()],
    )
    .contains(&"construct_graph.cardinality.optional_one".to_owned()));
    // Optional means zero is fine.
    assert_eq!(
        cardinality_codes(vec![required_port("optional-one")], vec![]),
        Vec::<String>::new()
    );
}

#[test]
fn an_unknown_cardinality_is_refused() {
    assert!(
        cardinality_codes(vec![required_port("several")], vec![edge_to_req()])
            .contains(&"construct_graph.cardinality.unknown".to_owned())
    );
}

/// A scalar port takes no ordering metadata: an `order_index` on an edge into
/// a one-provider port is metadata the graph cannot mean.
#[test]
fn ordering_metadata_on_a_scalar_edge_is_refused() {
    let mut edge = edge_to_req();
    edge["order_index"] = json!(0);
    assert!(
        cardinality_codes(vec![required_port("exactly-one")], vec![edge])
            .contains(&"construct_graph.cardinality.scalar_edge_metadata".to_owned())
    );
}

/// An effect dependency names one effect waiting on another under a predicate.
/// An unknown predicate would make the wait condition unreadable.
fn dependency_codes(dependencies: Vec<Value>) -> Vec<String> {
    let node_by_id: BTreeMap<String, &Value> = BTreeMap::new();
    let mut diagnostics = Vec::new();
    validate_construct_graph_effect_dependencies(&dependencies, &node_by_id, &mut diagnostics);
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn dependency(reference: &str, predicate: Option<&str>) -> Value {
    let mut value = json!({"dependency_ref": reference, "evidence": []});
    if let Some(predicate) = predicate {
        value["predicate"] = json!(predicate);
    }
    value
}

#[test]
fn a_dependency_must_declare_a_known_predicate() {
    assert!(dependency_codes(vec![dependency("d1", Some("maybe"))])
        .contains(&"construct_graph.effect_dependency.predicate_unknown".to_owned()));
    assert!(dependency_codes(vec![dependency("d1", None)])
        .contains(&"construct_graph.effect_dependency.predicate_missing".to_owned()));
    for predicate in ["succeeds", "fails", "completes"] {
        assert!(
            !dependency_codes(vec![dependency("d1", Some(predicate))])
                .iter()
                .any(|c| c.starts_with("construct_graph.effect_dependency.predicate")),
            "`{predicate}` is a declared predicate"
        );
    }
}

#[test]
fn the_same_dependency_twice_is_refused() {
    assert!(dependency_codes(vec![
        dependency("d1", Some("succeeds")),
        dependency("d1", Some("succeeds")),
    ])
    .contains(&"construct_graph.effect_dependency.duplicate".to_owned()));
}
