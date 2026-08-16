//! Construct-graph shape, ports, edges, and dependency structure.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn construct_graph_reports_package_capability_call_resolution() {
    let graph = package_memory_construct_graph_for_test();

    assert_eq!(
        graph.get("schema").and_then(Value::as_str),
        Some("whipplescript.construct_graph.v0")
    );
    assert_eq!(
        graph
            .get("source_digest")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    // The graph resolves via the embedded `std.memory` manifest with no lock
    // at all, so the lock digest is the all-zero no-lock sentinel.
    assert_eq!(
        graph.get("package_lock_digest").and_then(Value::as_str),
        Some("0000000000000000000000000000000000000000000000000000000000000000")
    );

    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .expect("nodes array");
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str)
            == Some("contract:std.memory:memory.query:0.1.0")
    }));
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str)
            == Some("contract:std.memory:memory.query:0.1.0")
            && node
                .get("required_capabilities")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
            && node.get("construct_id").and_then(Value::as_str) == Some("memory.recall")
            && node.get("lowering_class").and_then(Value::as_str) == Some("capability_call")
            && node.get("lifecycle_profile").and_then(Value::as_str) == Some("typed_effect_graph")
    }));
    let effect_node = construct_graph_node(&graph, "effect:start:context");
    assert_eq!(
        construct_graph_string_array(effect_node, "allowed_core_object_kinds"),
        vec!["effect".to_owned()]
    );
    assert_eq!(
        construct_graph_string_array(effect_node, "allowed_runtime_entrypoints"),
        vec!["effect_graph_template".to_owned()]
    );
    let required_interfaces = effect_node
        .get("declared_required_interfaces")
        .and_then(Value::as_array)
        .expect("required interfaces");
    assert!(required_interfaces.iter().any(|interface| {
        interface.get("kind").and_then(Value::as_str) == Some("Capability")
            && interface.get("name").and_then(Value::as_str) == Some("memory.query")
            && interface.get("phase").and_then(Value::as_str) == Some("compile/runtime")
            && interface.get("cardinality").and_then(Value::as_str) == Some("exactly-one")
    }));
    let provided_interfaces = effect_node
        .get("declared_provided_interfaces")
        .and_then(Value::as_array)
        .expect("provided interfaces");
    assert!(provided_interfaces.iter().any(|interface| {
        interface.get("kind").and_then(Value::as_str) == Some("EffectHandle")
            && interface.get("type").and_then(Value::as_str) == Some("memory.query.output")
            && interface.get("phase").and_then(Value::as_str) == Some("compile/runtime")
            && interface.get("cardinality").and_then(Value::as_str) == Some("exactly-one")
    }));

    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .expect("edges array");
    let memory_edge_ref = edges
        .iter()
        .find_map(|edge| {
            let required = edge.get("required_port_id").and_then(Value::as_str)?;
            let provided = edge.get("provided_port_id").and_then(Value::as_str)?;
            required
                .contains("memory.query")
                .then(|| format!("{required}->{provided}"))
        })
        .expect("memory capability edge ref");
    assert!(edges.iter().any(|edge| {
        edge.get("resolution_reason").and_then(Value::as_str) == Some("locked_effect_contract")
            && edge
                .get("required_port_id")
                .and_then(Value::as_str)
                .is_some_and(|port| port.contains("memory.query"))
    }));
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("validator.graph.accepted:")));
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with("validator.graph.adequacy.source_lock_deterministic:")
    }));
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with("validator.graph.adequacy.checker_facts_accounted:")
    }));
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with("validator.graph.adequacy.lifecycle_boundary_declared:")
    }));
    let graph_accepted_refs = construct_graph_fact_input_refs(&graph, "validator.graph.accepted:")
        .expect("graph accepted refs");
    assert!(graph_accepted_refs.contains(&memory_edge_ref));
    let source_lock_refs = construct_graph_fact_input_refs(
        &graph,
        "validator.graph.adequacy.source_lock_deterministic:",
    )
    .expect("source lock adequacy refs");
    assert!(source_lock_refs
        .iter()
        .any(|ref_| ref_.starts_with("construct_graph.root.source_digest:")));
    assert!(source_lock_refs
        .iter()
        .any(|ref_| ref_.starts_with("construct_graph.root.package_lock_digest:")));
    assert!(predicates.contains("validator.node.profile:effect:start:context"));
    assert!(predicates.contains("validator.node.interfaces:effect:start:context"));
    assert!(predicates.contains("validator.node.capabilities:effect:start:context"));
    assert!(predicates
        .contains("validator.node.output:effect:start:context:core.effect_graph_template"));
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("validator.cardinality.exactly-one.satisfied:")));
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("validator.edge.type_compatible:")));
    let memory_edge = edges
        .iter()
        .find(|edge| {
            edge.get("required_port_id")
                .and_then(Value::as_str)
                .is_some_and(|port| port.contains("memory.query"))
        })
        .expect("memory edge");
    let required_port_id = memory_edge
        .get("required_port_id")
        .and_then(Value::as_str)
        .expect("required port id");
    let provided_port_id = memory_edge
        .get("provided_port_id")
        .and_then(Value::as_str)
        .expect("provided port id");
    let required_port = construct_graph_port(&graph, required_port_id);
    let provided_port = construct_graph_port(&graph, provided_port_id);
    let required_port_profile_refs = construct_graph_fact_input_refs(
        &graph,
        &format!("validator.port.profile:{required_port_id}"),
    )
    .expect("required port profile refs");
    assert!(required_port_profile_refs.contains(required_port_id));
    assert!(required_port_profile_refs.contains(&format!(
        "{required_port_id}#kind:{}",
        required_port
            .get("kind")
            .and_then(Value::as_str)
            .expect("required port kind")
    )));
    assert!(required_port_profile_refs.contains(&format!(
        "{required_port_id}#cardinality:{}",
        required_port
            .get("cardinality")
            .and_then(Value::as_str)
            .expect("required port cardinality")
    )));
    let edge_type_refs = construct_graph_fact_input_refs(
        &graph,
        &format!("validator.edge.type_compatible:{memory_edge_ref}"),
    )
    .expect("edge type compatibility refs");
    for (role, port_id, port) in [
        ("required", required_port_id, required_port),
        ("provided", provided_port_id, provided_port),
    ] {
        assert!(edge_type_refs.contains(&format!(
            "{port_id}#{role}.type:{}",
            port.get("type").and_then(Value::as_str).expect("port type")
        )));
        assert!(edge_type_refs.contains(&format!(
            "{port_id}#{role}.contract_version:{}",
            port.get("contract_version")
                .and_then(Value::as_str)
                .expect("port contract version")
        )));
    }
}

#[test]
fn construct_graph_reports_package_effect_dependencies() {
    let (graph, _) = package_memory_dependency_construct_graph_and_lowered_report_for_test();

    let dependencies = graph
        .get("effect_dependencies")
        .and_then(Value::as_array)
        .expect("effect dependencies");
    assert!(dependencies.iter().any(|dependency| {
        dependency.get("dependency_ref").and_then(Value::as_str)
            == Some("dependency:start:first:succeeds:second")
            && dependency.get("upstream_node_id").and_then(Value::as_str)
                == Some("effect:start:first")
            && dependency.get("predicate").and_then(Value::as_str) == Some("succeeds")
            && dependency.get("downstream_node_id").and_then(Value::as_str)
                == Some("effect:start:second")
    }));
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with(
            "validator.effect_dependency.endpoints_valid:dependency:start:first:succeeds:second",
        )
    }));
    let graph_accepted_refs = construct_graph_fact_input_refs(&graph, "validator.graph.accepted:")
        .expect("graph accepted refs");
    assert!(graph_accepted_refs.contains("dependency:start:first:succeeds:second"));
}

#[test]
fn construct_graph_reports_core_effect_dependencies() {
    let (graph, _) = core_effect_dependency_construct_graph_and_lowered_report_for_test();

    let nodes = graph.get("nodes").and_then(Value::as_array).expect("nodes");
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str) == Some("effect:start:first")
            && node.get("construct_id").and_then(Value::as_str) == Some("core.effect.agent.tell")
            && node.get("lowering_class").and_then(Value::as_str)
                == Some(CORE_EFFECT_LOWERING_CLASS)
            && node.get("owner").and_then(Value::as_str) == Some("std.agent")
    }));
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str) == Some("effect:start:second")
            && node
                .get("required_capabilities")
                .and_then(Value::as_array)
                .is_some_and(|capabilities| {
                    capabilities
                        .iter()
                        .any(|value| value.as_str() == Some("agent.turn"))
                })
    }));

    let dependencies = graph
        .get("effect_dependencies")
        .and_then(Value::as_array)
        .expect("effect dependencies");
    assert!(dependencies.iter().any(|dependency| {
        dependency.get("dependency_ref").and_then(Value::as_str)
            == Some("dependency:start:first:succeeds:second")
            && dependency.get("upstream_node_id").and_then(Value::as_str)
                == Some("effect:start:first")
            && dependency.get("downstream_node_id").and_then(Value::as_str)
                == Some("effect:start:second")
    }));
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
}

#[test]
fn construct_graph_reports_signal_source_declarations() {
    let (graph, _) = signal_source_construct_graph_and_lowered_report_for_test();

    // The `signal {}` declaration itself produces no node; the `signal_source`
    // node comes from the generic `source` block.
    assert!(!graph
        .get("nodes")
        .and_then(Value::as_array)
        .expect("nodes array")
        .iter()
        .any(|node| node.get("node_id").and_then(Value::as_str)
            == Some("signal_source:deploy.finished")));

    let node = construct_graph_node(&graph, "source:deploy_events");
    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some("core.signal_source.deploy_events")
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some("source_declaration")
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some("signal_source")
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("signal_source_template")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.signal_source_template")
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains("lowering_output:deploy_events:core.signal_source_template"));
}

#[test]
fn construct_graph_reports_schedule_templates() {
    let (graph, _) = schedule_construct_graph_and_lowered_report_for_test();
    let node = construct_graph_node(&graph, "effect:wait_for_deadline:deadline");

    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some("core.effect.timer.wait")
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some(CONSTRUCT_FAMILY_EFFECT_OPERATION)
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some(SCHEDULE_LOWERING_CLASS)
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("schedule_template")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.schedule_template")
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_core_object_kinds"),
        vec!["schedule".to_owned()]
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_runtime_entrypoints"),
        vec!["schedule_template".to_owned()]
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains("lowering_output:deadline:core.schedule_template"));
    assert!(predicates.contains("validator.node.profile:effect:wait_for_deadline:deadline"));
    assert!(predicates.contains(
        "validator.node.output:effect:wait_for_deadline:deadline:core.schedule_template"
    ));
}

#[test]
fn construct_graph_reports_assertion_checks() {
    let (graph, _) = assertion_construct_graph_and_lowered_report_for_test();
    let assertion_id = stable_hash_hex("true");
    let node_id = format!("assertion:{assertion_id}");
    let construct_id = format!("core.assertion.{assertion_id}");
    let node = construct_graph_node(&graph, &node_id);

    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some(construct_id.as_str())
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some("assertion")
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some("assertion_check")
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("assertion_check")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.assertion_check")
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains(&format!(
        "lowering_output:{assertion_id}:core.assertion_check"
    )));
}

#[test]
fn construct_graph_reports_rule_templates() {
    let (graph, _) = rule_template_construct_graph_and_lowered_report_for_test();
    let node = construct_graph_node(&graph, "rule:observe_start:when0");

    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some("core.rule.observe_start:when0")
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some("rule")
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some("rule_template")
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("rule_template")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.rule_template")
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_core_object_kinds"),
        vec!["rule".to_owned(), "fact".to_owned()]
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_runtime_entrypoints"),
        vec!["rule_template".to_owned(), "fact_record".to_owned()]
    );
    assert_eq!(
        node.get("metadata")
            .and_then(|metadata| metadata.get("fact_writes"))
            .and_then(Value::as_array)
            .and_then(|facts| facts.first())
            .and_then(Value::as_str),
        Some("schema:StartupSeen")
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains("lowering_output:observe_start:when0:core.rule_template"));
}

#[test]
fn construct_graph_reports_projection_reads() {
    let (graph, _) = projection_read_construct_graph_and_lowered_report_for_test();
    let rule_node = construct_graph_node(&graph, "projection_read:rule:observe:read0");

    assert_eq!(
        rule_node.get("construct_family").and_then(Value::as_str),
        Some("projection_read")
    );
    assert_eq!(
        rule_node.get("lowering_class").and_then(Value::as_str),
        Some("metadata")
    );
    assert_eq!(
        rule_node
            .get("lowering_output_kind")
            .and_then(Value::as_str),
        Some("checker.projection_read")
    );
    assert_eq!(
        rule_node
            .get("metadata")
            .and_then(|metadata| metadata.get("owner_kind"))
            .and_then(Value::as_str),
        Some("rule")
    );
    assert_eq!(
        rule_node
            .get("metadata")
            .and_then(|metadata| metadata.get("read_kind"))
            .and_then(Value::as_str),
        Some("fact")
    );
    assert_eq!(
        rule_node
            .get("metadata")
            .and_then(|metadata| metadata.get("source"))
            .and_then(Value::as_str),
        Some("Item where status == \"done\"")
    );

    let assertion_id = stable_hash_hex("count(Item where status == \"done\") == 1");
    let assertion_node_id = format!("projection_read:assertion:{assertion_id}:read0");
    let assertion_node = construct_graph_node(&graph, &assertion_node_id);
    assert_eq!(
        assertion_node
            .get("metadata")
            .and_then(|metadata| metadata.get("owner_kind"))
            .and_then(Value::as_str),
        Some("assertion")
    );
    assert_eq!(
        assertion_node
            .get("metadata")
            .and_then(|metadata| metadata.get("owner_ref"))
            .and_then(Value::as_str),
        Some(assertion_id.as_str())
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.iter().any(|predicate| predicate
        .starts_with("projection_read:rule:observe:read0:Item where status == \"done\"")));
}

#[test]
fn construct_graph_validator_rejects_duplicate_exactly_one_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    let mut duplicate_edge = graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .cloned()
        .expect("graph has an edge");
    let provided_port_id = first_construct_graph_provided_port_id(&graph);
    let duplicate_port_id = format!("{provided_port_id}:duplicate");
    let mut duplicate_port = construct_graph_port(&graph, &provided_port_id).clone();
    duplicate_port
        .as_object_mut()
        .expect("port object")
        .insert("port_id".to_owned(), json!(duplicate_port_id.clone()));
    let provider_node_id = duplicate_edge
        .get("provider_node_id")
        .and_then(Value::as_str)
        .expect("edge has provider node")
        .to_owned();
    construct_graph_node_mut(&mut graph, &provider_node_id)
        .get_mut("produced_ports")
        .and_then(Value::as_array_mut)
        .expect("produced ports array")
        .push(json!(duplicate_port_id.clone()));
    graph
        .get_mut("ports")
        .and_then(Value::as_array_mut)
        .expect("ports array")
        .push(duplicate_port);
    duplicate_edge
        .as_object_mut()
        .expect("edge object")
        .insert("provided_port_id".to_owned(), json!(duplicate_port_id));
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .push(duplicate_edge);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.exactly_one"));
}

#[test]
fn construct_graph_validator_accepts_optional_one_without_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("optional-one"));
    sync_declared_required_interface_cardinality(&mut graph, &required_port_id, "optional-one");
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .clear();

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
    let refs = construct_graph_validation_fact_input_refs(
        &validation,
        "validator.cardinality.optional-one.satisfied:",
    )
    .expect("optional-one cardinality fact");
    assert_eq!(refs, BTreeSet::from([required_port_id]));
}

#[test]
fn construct_graph_validator_rejects_duplicate_optional_one_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("optional-one"));
    let mut duplicate_edge = graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .cloned()
        .expect("graph has an edge");
    let provided_port_id = first_construct_graph_provided_port_id(&graph);
    let duplicate_port_id = format!("{provided_port_id}:duplicate");
    let mut duplicate_port = construct_graph_port(&graph, &provided_port_id).clone();
    duplicate_port
        .as_object_mut()
        .expect("port object")
        .insert("port_id".to_owned(), json!(duplicate_port_id.clone()));
    let provider_node_id = duplicate_edge
        .get("provider_node_id")
        .and_then(Value::as_str)
        .expect("edge has provider node")
        .to_owned();
    construct_graph_node_mut(&mut graph, &provider_node_id)
        .get_mut("produced_ports")
        .and_then(Value::as_array_mut)
        .expect("produced ports array")
        .push(json!(duplicate_port_id.clone()));
    graph
        .get_mut("ports")
        .and_then(Value::as_array_mut)
        .expect("ports array")
        .push(duplicate_port);
    duplicate_edge
        .as_object_mut()
        .expect("edge object")
        .insert("provided_port_id".to_owned(), json!(duplicate_port_id));
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .push(duplicate_edge);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.optional_one"));
}

#[test]
fn construct_graph_validator_accepts_many_with_contiguous_order() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    let edge_ref = first_construct_graph_edge_ref(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("many"));
    sync_declared_required_interface_cardinality(&mut graph, &required_port_id, "many");
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object")
        .insert("order_index".to_owned(), json!(0));

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
    let refs = construct_graph_validation_fact_input_refs(
        &validation,
        "validator.cardinality.many.satisfied:",
    )
    .expect("many cardinality fact");
    assert!(refs.contains(&edge_ref));
    assert!(refs.contains(&format!("{edge_ref}#order_index:0")));
}

#[test]
fn construct_graph_validator_rejects_many_with_noncontiguous_order() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("many"));
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object")
        .insert("order_index".to_owned(), json!(1));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.order_not_contiguous"));
}

#[test]
fn construct_graph_validator_rejects_many_with_resource_key() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("many"));
    let edge = graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object");
    edge.insert("order_index".to_owned(), json!(0));
    edge.insert("resource_key".to_owned(), json!("issue-source"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.resource_key_unexpected"));
}

#[test]
fn construct_graph_validator_accepts_named_many_with_order_and_key() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    let edge_ref = first_construct_graph_edge_ref(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("named-many"));
    sync_declared_required_interface_cardinality(&mut graph, &required_port_id, "named-many");
    let edge = graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object");
    edge.insert("order_index".to_owned(), json!(0));
    edge.insert("resource_key".to_owned(), json!("issue-source"));

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
    let refs = construct_graph_validation_fact_input_refs(
        &validation,
        "validator.cardinality.named-many.satisfied:",
    )
    .expect("named-many cardinality fact");
    assert!(refs.contains(&edge_ref));
    assert!(refs.contains(&format!("{edge_ref}#order_index:0")));
    assert!(refs.contains(&format!("{edge_ref}#resource_key:issue-source")));
}

#[test]
fn construct_graph_validator_rejects_duplicate_edge_ref() {
    let mut graph = package_memory_construct_graph_for_test();
    let duplicate_edge = graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .cloned()
        .expect("graph has an edge");
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .push(duplicate_edge);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.edge.duplicate"));
}

#[test]
fn construct_graph_validator_rejects_missing_exactly_one_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .clear();

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.exactly_one"));
}

#[test]
fn construct_graph_validator_rejects_incompatible_edge_type() {
    let mut graph = package_memory_construct_graph_for_test();
    let provided_port_id = first_construct_graph_provided_port_id(&graph);
    let provided_port = construct_graph_port_mut(&mut graph, &provided_port_id);
    provided_port
        .as_object_mut()
        .expect("port object")
        .insert("type".to_owned(), json!("tracker.issue"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.edge.type_mismatch"));
}

#[test]
fn construct_graph_validator_rejects_missing_declared_lowering_interface() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut()
        .expect("node object")
        .insert("declared_provided_interfaces".to_owned(), json!([]));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.lowering_provided_missing"));
}

#[test]
fn construct_graph_validator_rejects_unknown_output_object_kind() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut().expect("node object").insert(
        "allowed_core_object_kinds".to_owned(),
        json!(["effect_object"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.output_kind_unknown"));
}

#[test]
fn construct_graph_validator_rejects_unknown_runtime_entrypoint() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut().expect("node object").insert(
        "allowed_runtime_entrypoints".to_owned(),
        json!(["kernel.graph_commit"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.runtime_entrypoint_unknown"));
    assert!(codes.contains("construct_graph.node.runtime_entrypoint_missing"));
}

#[test]
fn construct_graph_validator_accepts_runtime_handoff_output_vocabulary() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let object = node.as_object_mut().expect("node object");
    object.insert(
        "allowed_core_object_kinds".to_owned(),
        json!(["event", "projection", "diagnostic"]),
    );
    object.insert(
        "allowed_runtime_entrypoints".to_owned(),
        json!(["event_record", "event_projection", "diagnostic_record"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
}

#[test]
fn construct_graph_validator_rejects_unmatched_runtime_entrypoint() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut().expect("node object").insert(
        "allowed_runtime_entrypoints".to_owned(),
        json!(["effect_graph_template", "assertion_check"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.runtime_entrypoint_unmatched"));
}

#[test]
fn construct_graph_validator_rejects_lifecycle_profile_mismatch() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut()
        .expect("node object")
        .insert("lifecycle_profile".to_owned(), json!("event_projection"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.lifecycle_profile_mismatch"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_node_inventory_ref() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_ports = node
        .get_mut("required_ports")
        .and_then(Value::as_array_mut)
        .expect("required ports");
    let duplicate = required_ports.first().expect("required port").clone();
    required_ports.push(duplicate);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.string_array_duplicate"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_edge_evidence_ref() {
    let mut graph = package_memory_construct_graph_for_test();
    let edge = graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge");
    edge.as_object_mut().expect("edge object").insert(
        "evidence".to_owned(),
        json!(["edge:evidence", "edge:evidence"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.edge.string_array_duplicate"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_dependency_evidence_ref() {
    let (mut graph, _) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let dependency = graph
        .get_mut("effect_dependencies")
        .and_then(Value::as_array_mut)
        .and_then(|dependencies| dependencies.first_mut())
        .expect("effect dependency");
    dependency
        .as_object_mut()
        .expect("effect dependency object")
        .insert(
            "evidence".to_owned(),
            json!(["dependency:evidence", "dependency:evidence"]),
        );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.effect_dependency.string_array_duplicate"));
}

#[test]
fn construct_graph_validator_rejects_declared_interface_without_matching_port() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_interfaces = node
        .get_mut("declared_required_interfaces")
        .and_then(Value::as_array_mut)
        .expect("required interfaces");
    required_interfaces
        .first_mut()
        .expect("required interface")
        .as_object_mut()
        .expect("required interface object")
        .insert("name".to_owned(), json!("memory.write"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.unsatisfied"));
}

#[test]
fn construct_graph_validator_rejects_declared_interface_phase_mismatch() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_interfaces = node
        .get_mut("declared_required_interfaces")
        .and_then(Value::as_array_mut)
        .expect("required interfaces");
    required_interfaces
        .first_mut()
        .expect("required interface")
        .as_object_mut()
        .expect("required interface object")
        .insert("phase".to_owned(), json!("runtime"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.unsatisfied"));
}

#[test]
fn construct_graph_validator_rejects_declared_interface_cardinality_mismatch() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let provided_interfaces = node
        .get_mut("declared_provided_interfaces")
        .and_then(Value::as_array_mut)
        .expect("provided interfaces");
    provided_interfaces
        .first_mut()
        .expect("provided interface")
        .as_object_mut()
        .expect("provided interface object")
        .insert("cardinality".to_owned(), json!("optional-one"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.unsatisfied"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_declared_interface() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_interfaces = node
        .get_mut("declared_required_interfaces")
        .and_then(Value::as_array_mut)
        .expect("required interfaces");
    let duplicate = required_interfaces
        .first()
        .expect("required interface")
        .clone();
    required_interfaces.push(duplicate);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.duplicate"));
}

#[test]
fn construct_graph_validator_rejects_named_many_without_order_and_key() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    let required_port = construct_graph_port_mut(&mut graph, &required_port_id);
    required_port
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("named-many"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.order_missing"));
    assert!(codes.contains("construct_graph.cardinality.resource_key_missing"));
}
