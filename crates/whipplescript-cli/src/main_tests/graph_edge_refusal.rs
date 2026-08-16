//! Extracted verbatim from `main.rs` (module path `graph_edge_refusal_tests` is unchanged).

use super::validate_construct_graph_edges;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// An edge claims that one node's produced port satisfies another's required
/// port. Every refusal here is a way that claim can be false: the ports do not
/// exist, they face the wrong way, the provider does not own what it offers,
/// or the two sides disagree about what is being exchanged. The sweep found
/// none of them exercised, so a graph asserting an unsatisfiable wiring was
/// believed.
fn edge_codes(edges: Vec<Value>, nodes: Vec<Value>, ports: Vec<Value>) -> Vec<String> {
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
    validate_construct_graph_edges(&edges, &node_by_id, &port_by_id, &mut diagnostics);
    diagnostics
        .iter()
        .filter_map(|d| d.get("code").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn port(id: &str, owner: &str, direction: &str) -> Value {
    json!({
        "port_id": id,
        "owner_node_id": owner,
        "direction": direction,
        "kind": "fact",
        "type": "T",
        "contract_version": "1",
        "phase": "build",
    })
}

fn edge() -> Value {
    json!({
        "required_port_id": "req",
        "provider_node_id": "provider",
        "provided_port_id": "prov",
    })
}

fn wired() -> (Vec<Value>, Vec<Value>) {
    (
        vec![
            json!({"node_id": "consumer"}),
            json!({"node_id": "provider"}),
        ],
        vec![
            port("req", "consumer", "required"),
            port("prov", "provider", "produced"),
        ],
    )
}

/// The accept case: a consistent wiring draws nothing.
#[test]
fn a_consistent_edge_is_accepted() {
    let (nodes, ports) = wired();
    assert_eq!(edge_codes(vec![edge()], nodes, ports), Vec::<String>::new());
}

#[test]
fn an_edge_naming_something_absent_is_refused() {
    let (nodes, ports) = wired();
    assert!(
        edge_codes(vec![edge()], nodes.clone(), vec![ports[1].clone()])
            .contains(&"construct_graph.edge.required_port_missing".to_owned())
    );
    assert!(
        edge_codes(vec![edge()], nodes.clone(), vec![ports[0].clone()])
            .contains(&"construct_graph.edge.provided_port_missing".to_owned())
    );
    assert!(edge_codes(
        vec![edge()],
        vec![json!({"node_id": "consumer"})],
        ports.clone(),
    )
    .contains(&"construct_graph.edge.provider_node_missing".to_owned()));
}

#[test]
fn the_same_edge_twice_is_refused() {
    let (nodes, ports) = wired();
    assert!(edge_codes(vec![edge(), edge()], nodes, ports)
        .contains(&"construct_graph.edge.duplicate".to_owned()));
}

/// Direction is what makes an edge mean anything: a required port must be
/// required, and a provided port must be produced. Reversed, the graph claims
/// a wiring that cannot carry a value.
#[test]
fn ports_facing_the_wrong_way_are_refused() {
    let (nodes, _) = wired();
    assert!(edge_codes(
        vec![edge()],
        nodes.clone(),
        vec![
            port("req", "consumer", "produced"),
            port("prov", "provider", "produced")
        ],
    )
    .contains(&"construct_graph.edge.required_not_required".to_owned()));

    assert!(edge_codes(
        vec![edge()],
        nodes,
        vec![
            port("req", "consumer", "required"),
            port("prov", "provider", "required")
        ],
    )
    .contains(&"construct_graph.edge.provided_not_produced".to_owned()));
}

#[test]
fn a_provider_that_does_not_own_the_offered_port_is_refused() {
    let (nodes, _) = wired();
    assert!(edge_codes(
        vec![edge()],
        nodes,
        vec![
            port("req", "consumer", "required"),
            port("prov", "someone_else", "produced")
        ],
    )
    .contains(&"construct_graph.edge.provider_owner_mismatch".to_owned()));
}

/// The two sides must agree about what is exchanged. Each disagreement has its
/// own code so a reader learns which half to fix.
#[test]
fn the_two_sides_must_agree_on_what_is_exchanged() {
    let (nodes, _) = wired();
    for (field, value, code) in [
        ("kind", "effect", "construct_graph.edge.kind_mismatch"),
        ("type", "Other", "construct_graph.edge.type_mismatch"),
        (
            "contract_version",
            "2",
            "construct_graph.edge.version_mismatch",
        ),
    ] {
        let mut provided = port("prov", "provider", "produced");
        provided[field] = json!(value);
        let found = edge_codes(
            vec![edge()],
            nodes.clone(),
            vec![port("req", "consumer", "required"), provided],
        );
        assert!(
            found.contains(&code.to_owned()),
            "disagreeing `{field}` must raise `{code}`, got {found:?}"
        );
    }
}
