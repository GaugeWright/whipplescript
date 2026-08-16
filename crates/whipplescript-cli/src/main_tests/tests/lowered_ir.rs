//! Lowered-IR artifact shape and its correspondence to the construct graph.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn lowered_ir_report_accounts_for_package_capability_call_outputs() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();

    assert_eq!(
        lowered.get("schema").and_then(Value::as_str),
        Some("whipplescript.lowered_ir_report.v0")
    );
    assert_eq!(
        lowered.get("graph_id").and_then(Value::as_str),
        graph.get("graph_id").and_then(Value::as_str)
    );
    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str)
            == Some("contract:std.memory:memory.query:0.1.0")
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
            && lowering.get("lowering_class").and_then(Value::as_str) == Some("capability_call")
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some("core:effect:effect:start:context"))
                })
    }));
    let effect_node_lowering = node_lowerings
        .iter()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering");
    assert_eq!(
        construct_graph_string_array(effect_node_lowering, "preserved_provenance_refs"),
        vec!["effect:start:context"]
    );
    assert_eq!(
        construct_graph_string_array(effect_node_lowering, "preserved_terminal_binding_refs"),
        vec!["effect:start:context:produces:effect_handle"]
    );

    let edge_lowerings = lowered
        .get("edge_lowerings")
        .and_then(Value::as_array)
        .expect("edge lowerings");
    assert!(edge_lowerings.iter().any(|lowering| {
        lowering
            .get("required_port_id")
            .and_then(Value::as_str)
            .is_some_and(|port| port.contains("memory.query"))
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some("core:effect:effect:start:context")
            && object.get("object_kind").and_then(Value::as_str) == Some("effect")
            && object.get("runtime_entrypoint").and_then(Value::as_str)
                == Some("effect_graph_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some("effect:start:context")
    }));
}

#[test]
fn lowered_ir_validator_rejects_artifact_identity_mismatch() {
    for (field, replacement, expected_code) in [
        (
            "graph_id",
            json!("construct_graph:stale"),
            "lowered_ir.graph_id_mismatch",
        ),
        (
            "source_digest",
            json!("1111111111111111111111111111111111111111111111111111111111111111"),
            "lowered_ir.source_digest_mismatch",
        ),
        (
            "package_lock_digest",
            json!("2222222222222222222222222222222222222222222222222222222222222222"),
            "lowered_ir.package_lock_digest_mismatch",
        ),
    ] {
        let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
        lowered
            .as_object_mut()
            .expect("lowered report object")
            .insert(field.to_owned(), replacement);

        let validation = validate_lowered_ir_artifact(&lowered, &graph);
        let codes = lowered_ir_diagnostic_codes(&validation.diagnostics);
        assert!(
            codes.contains(expected_code),
            "{field} mismatch should be diagnosed"
        );
        assert!(
            validation.derived_facts.is_empty(),
            "{field} mismatch must not receive validator facts"
        );
    }
}

#[test]
fn lowered_ir_report_derives_validator_facts() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let facts = lowered
        .get("derived_facts")
        .and_then(Value::as_array)
        .expect("lowered IR derived facts");
    assert!(facts.iter().all(|fact| {
        fact.get("owner_subsystem").and_then(Value::as_str) == Some("lowered_ir_validator")
    }));

    let predicates = lowered_ir_fact_predicates(&lowered);
    let graph_id = graph
        .get("graph_id")
        .and_then(Value::as_str)
        .expect("graph id");
    assert!(predicates.contains(&format!("lowered_ir.validator.graph.coverage:{graph_id}")));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.owner_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.runtime_boundary:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.deterministic:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.report_complete:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.no_runtime_inputs:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.node_lowerings_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.edge_lowerings_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.dependency_lowerings_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.core_object_ids_unique:{graph_id}"
    )));
    assert!(predicates.contains("lowered_ir.validator.node.lowered:effect:start:first"));
    assert!(predicates.contains("lowered_ir.validator.node.preservation:effect:start:first"));
    assert!(predicates
        .contains("lowered_ir.validator.node.preservation.lowering_class:effect:start:first"));
    assert!(predicates
        .contains("lowered_ir.validator.node.preservation.terminal_binding:effect:start:first"));
    let preservation_class_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.preservation.lowering_class:effect:start:first",
    )
    .expect("node lowering class preservation refs");
    assert!(preservation_class_refs.contains(graph_id));
    assert!(preservation_class_refs.contains("effect:start:first"));
    assert!(preservation_class_refs.contains("capability_call"));
    let preservation_terminal_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.preservation.terminal_binding:effect:start:first",
    )
    .expect("node terminal binding preservation refs");
    assert!(preservation_terminal_refs.contains(graph_id));
    assert!(preservation_terminal_refs.contains("effect:start:first"));
    assert!(preservation_terminal_refs.contains("effect:start:first:produces:effect_handle"));
    assert!(predicates
        .contains("lowered_ir.validator.node.lifecycle_inputs:effect:start:first:capability_call"));
    let lifecycle_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.lifecycle_inputs:effect:start:first:capability_call",
    )
    .expect("lifecycle input refs");
    assert!(lifecycle_refs.contains(graph_id));
    assert!(lifecycle_refs.contains("effect:start:first"));
    assert!(lifecycle_refs.contains("capability_call"));
    assert!(lifecycle_refs.contains(CONSTRUCT_FAMILY_EFFECT_OPERATION));
    assert!(lifecycle_refs.contains("typed_effect_graph"));
    assert!(lifecycle_refs.contains("core:effect:effect:start:first"));
    assert!(lifecycle_refs.contains("effect"));
    assert!(lifecycle_refs.contains("effect_graph_template"));
    assert!(predicates.contains(
            "lowered_ir.validator.node.lifecycle_inputs.construct_family:effect:start:first:capability_call"
        ));
    let lifecycle_family_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.node.lifecycle_inputs.construct_family:effect:start:first:capability_call",
        )
        .expect("lifecycle construct-family refs");
    assert!(lifecycle_family_refs.contains(graph_id));
    assert!(lifecycle_family_refs.contains("effect:start:first"));
    assert!(lifecycle_family_refs.contains(CONSTRUCT_FAMILY_EFFECT_OPERATION));
    assert!(predicates.contains(
            "lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:effect:start:first:capability_call"
        ));
    let lifecycle_entrypoint_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:effect:start:first:capability_call",
        )
        .expect("lifecycle runtime-entrypoint refs");
    assert!(lifecycle_entrypoint_refs.contains("core:effect:effect:start:first"));
    assert!(lifecycle_entrypoint_refs.contains("effect_graph_template"));
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("lowered_ir.validator.edge.preservation:")));
    let edge_required_predicate = predicates
        .iter()
        .find(|predicate| {
            predicate.starts_with("lowered_ir.validator.edge.preservation.required_port:")
        })
        .expect("edge required-port preservation component fact");
    let edge_required_refs = lowered_ir_fact_input_refs(&lowered, edge_required_predicate)
        .expect("edge required-port preservation refs");
    assert!(edge_required_refs.contains(graph_id));
    assert!(edge_required_refs
        .iter()
        .any(|reference| reference.contains("->")));
    assert!(edge_required_refs.len() >= 3);
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
        "lowered_ir.validator.dependency.lowered:dependency:start:first:succeeds:second"
    )));
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
        "lowered_ir.validator.dependency.preservation:dependency:start:first:succeeds:second"
    )));
    assert!(predicates.contains(
            "lowered_ir.validator.dependency.preservation.predicate:dependency:start:first:succeeds:second"
        ));
    let dependency_predicate_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.dependency.preservation.predicate:dependency:start:first:succeeds:second",
        )
        .expect("dependency predicate preservation refs");
    assert!(dependency_predicate_refs.contains(graph_id));
    assert!(dependency_predicate_refs.contains("dependency:start:first:succeeds:second"));
    assert!(dependency_predicate_refs.contains("succeeds"));
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
            "lowered_ir.validator.core_object.entrypoint:core:dependency:dependency:start:first:succeeds:second:dependency:effect_dependency_template"
        )));
    let dependency_entrypoint_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.core_object.entrypoint:core:dependency:dependency:start:first:succeeds:second:dependency:effect_dependency_template",
        )
        .expect("dependency entrypoint refs");
    assert!(dependency_entrypoint_refs.contains(
            "core:dependency:dependency:start:first:succeeds:second#entrypoint_refs.upstream_effect:effect:start:first"
        ));
    assert!(dependency_entrypoint_refs.contains(
        "core:dependency:dependency:start:first:succeeds:second#entrypoint_refs.predicate:succeeds"
    ));
    assert!(dependency_entrypoint_refs.contains(
            "core:dependency:dependency:start:first:succeeds:second#entrypoint_refs.downstream_effect:effect:start:second"
        ));
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
            "lowered_ir.validator.core_object.owner:core:dependency:dependency:start:first:succeeds:second:dependency:dependency:start:first:succeeds:second"
        )));
    let owner_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.owner_unique:{graph_id}"),
    )
    .expect("owner uniqueness refs");
    assert!(owner_refs.contains("core:dependency:dependency:start:first:succeeds:second"));
    assert!(owner_refs.contains("dependency"));
    assert!(owner_refs.contains("dependency:start:first:succeeds:second"));
    let determinism_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.deterministic:{graph_id}"),
    )
    .expect("determinism refs");
    assert!(determinism_refs
        .iter()
        .any(|ref_| { ref_.starts_with("lowered_ir.root.accepted_program_digest:") }));
    assert!(determinism_refs
        .iter()
        .any(|ref_| { ref_.starts_with("lowered_ir.root.lowerer_version:whipplescript:") }));
    let report_complete_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.report_complete:{graph_id}"),
    )
    .expect("report completeness refs");
    assert!(report_complete_refs.contains("lowered_ir.inventory.node_lowering:effect:start:first"));
    assert!(report_complete_refs.contains(
        "lowered_ir.inventory.dependency_lowering:dependency:start:first:succeeds:second"
    ));
    assert!(report_complete_refs.contains(
        "lowered_ir.inventory.core_object:core:dependency:dependency:start:first:succeeds:second"
    ));
    let no_runtime_input_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.no_runtime_inputs:{graph_id}"),
    )
    .expect("no runtime input refs");
    assert!(no_runtime_input_refs.contains(
            "lowered_ir.runtime_boundary.core:dependency:dependency:start:first:succeeds:second:dependency:effect_dependency_template"
        ));
}

#[test]
fn lowered_ir_report_derives_node_output_compatibility_facts() {
    let (_, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let predicates = lowered_ir_fact_predicates(&lowered);

    assert!(predicates.contains("lowered_ir.validator.node.output_compat:effect:start:context"));
    assert!(predicates.contains(
        "lowered_ir.validator.node.output_compat.allowed_core_object_kinds:effect:start:context"
    ));
    assert!(predicates.contains(
        "lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints:effect:start:context"
    ));
    assert!(predicates.contains(
        "lowered_ir.validator.node.output_compat.runtime_entrypoints:effect:start:context"
    ));
    let refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.output_compat:effect:start:context",
    )
    .expect("node output compatibility refs");
    assert!(refs.contains("effect:start:context"));
    assert!(refs.contains("core:effect:effect:start:context"));
    assert!(refs.contains("effect"));
    assert!(refs.contains("effect_graph_template"));
    let allowed_kind_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.output_compat.allowed_core_object_kinds:effect:start:context",
    )
    .expect("output allowed object-kind refs");
    assert!(allowed_kind_refs.contains("effect:start:context"));
    assert!(allowed_kind_refs.contains("effect"));
    let runtime_entrypoint_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.output_compat.runtime_entrypoints:effect:start:context",
    )
    .expect("output runtime-entrypoint refs");
    assert!(runtime_entrypoint_refs.contains("core:effect:effect:start:context"));
    assert!(runtime_entrypoint_refs.contains("effect_graph_template"));
}

#[test]
fn lowered_ir_report_emits_signal_source_template_objects() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some("source:deploy_events")
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter().any(|value| {
                        value.as_str() == Some("core:signal_source:source:deploy_events")
                    })
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str)
            == Some("core:signal_source:source:deploy_events")
            && object.get("object_kind").and_then(Value::as_str) == Some("signal_source")
            && object.get("runtime_entrypoint").and_then(Value::as_str)
                == Some("signal_source_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some("source:deploy_events")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("event"))
                .and_then(Value::as_str)
                == Some("deploy.finished")
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_schedule_template_objects() {
    let (graph, lowered) = schedule_construct_graph_and_lowered_report_for_test();
    let node_id = "effect:wait_for_deadline:deadline";
    let object_id = "core:schedule:effect:wait_for_deadline:deadline";

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(object_id)))
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(object_id)
            && object.get("object_kind").and_then(Value::as_str) == Some("schedule")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("schedule_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id)
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("schedule"))
                .and_then(Value::as_str)
                == Some(node_id)
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_assertion_check_objects() {
    let (graph, lowered) = assertion_construct_graph_and_lowered_report_for_test();
    let assertion_id = stable_hash_hex("true");
    let node_id = format!("assertion:{assertion_id}");
    let object_id = format!("core:assertion:{node_id}");

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id.as_str())
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(object_id.as_str()))
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(object_id.as_str())
            && object.get("object_kind").and_then(Value::as_str) == Some("assertion")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("assertion_check")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id.as_str())
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("assertion"))
                .and_then(Value::as_str)
                == Some(assertion_id.as_str())
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_rule_template_objects() {
    let (graph, lowered) = rule_template_construct_graph_and_lowered_report_for_test();
    let node_id = "rule:observe_start:when0";
    let object_id = "core:rule:rule:observe_start:when0";
    let fact_object_id = "core:fact:rule:observe_start:when0:schema:StartupSeen";

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(object_id)))
    }));
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(fact_object_id))
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(object_id)
            && object.get("object_kind").and_then(Value::as_str) == Some("rule")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("rule_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id)
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("rule"))
                .and_then(Value::as_str)
                == Some("observe_start")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("fact"))
                .and_then(Value::as_str)
                == Some("observe_start:when0:started")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("graph"))
                .and_then(Value::as_str)
                == Some("observe_start:when0:graph")
    }));
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(fact_object_id)
            && object.get("object_kind").and_then(Value::as_str) == Some("fact")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("fact_record")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id)
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("fact"))
                .and_then(Value::as_str)
                == Some("schema:StartupSeen")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("schema"))
                .and_then(Value::as_str)
                == Some("StartupSeen")
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_accounts_for_projection_reads_without_runtime_objects() {
    let (graph, lowered) = projection_read_construct_graph_and_lowered_report_for_test();
    let node_id = "projection_read:rule:observe:read0";

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(!core_objects
        .iter()
        .any(|object| { object.get("owner_ref").and_then(Value::as_str) == Some(node_id) }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_package_effect_dependency_objects() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let dependency_ref = first_construct_graph_effect_dependency_ref(&graph);

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let dependency_lowerings = lowered
        .get("dependency_lowerings")
        .and_then(Value::as_array)
        .expect("dependency lowerings");
    assert!(dependency_lowerings.iter().any(|lowering| {
        lowering.get("dependency_ref").and_then(Value::as_str) == Some(dependency_ref.as_str())
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter().any(|value| {
                        value.as_str()
                            == Some("core:dependency:dependency:start:first:succeeds:second")
                    })
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str)
            == Some("core:dependency:dependency:start:first:succeeds:second")
            && object.get("object_kind").and_then(Value::as_str) == Some("dependency")
            && object.get("owner_kind").and_then(Value::as_str) == Some("dependency")
            && object.get("owner_ref").and_then(Value::as_str) == Some(dependency_ref.as_str())
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("upstream_effect"))
                .and_then(Value::as_str)
                == Some("effect:start:first")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("downstream_effect"))
                .and_then(Value::as_str)
                == Some("effect:start:second")
    }));
}

#[test]
fn lowered_ir_report_emits_core_effect_dependency_objects() {
    let (graph, lowered) = core_effect_dependency_construct_graph_and_lowered_report_for_test();
    let dependency_ref = first_construct_graph_effect_dependency_ref(&graph);

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some("core:effect:effect:start:first")
            && object.get("owner_ref").and_then(Value::as_str) == Some("effect:start:first")
    }));
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some("core:effect:effect:start:second")
            && object.get("owner_ref").and_then(Value::as_str) == Some("effect:start:second")
    }));
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str)
            == Some("core:dependency:dependency:start:first:succeeds:second")
            && object.get("owner_kind").and_then(Value::as_str) == Some("dependency")
            && object.get("owner_ref").and_then(Value::as_str) == Some(dependency_ref.as_str())
    }));
}

#[test]
fn lowered_ir_validator_rejects_unlowered_graph_node() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowerings = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings");
    node_lowerings.retain(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) != Some("effect:start:context")
    });

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node_unlowered"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_graph_node_lowering() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowerings = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings");
    let duplicate = node_lowerings
        .iter()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering")
        .clone();
    node_lowerings.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_missing_node_preservation_evidence() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowering = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings")
        .iter_mut()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering");
    node_lowering
        .as_object_mut()
        .expect("node lowering object")
        .remove("preserved_terminal_binding_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.preservation_field_missing"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_node_preservation_ref() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowering = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings")
        .iter_mut()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering");
    let refs = node_lowering
        .get_mut("preserved_terminal_binding_refs")
        .and_then(Value::as_array_mut)
        .expect("terminal binding refs");
    let duplicate = refs.first().expect("terminal binding ref").clone();
    refs.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.preservation_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_node_output_kind_not_allowed_by_graph() {
    let (mut graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    construct_graph_node_mut(&mut graph, "effect:start:context")
        .as_object_mut()
        .expect("node object")
        .insert("allowed_core_object_kinds".to_owned(), json!(["rule"]));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.output_kind_unallowed"));
}

#[test]
fn lowered_ir_validator_rejects_node_runtime_entrypoint_not_allowed_by_graph() {
    let (mut graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    construct_graph_node_mut(&mut graph, "effect:start:context")
        .as_object_mut()
        .expect("node object")
        .insert(
            "allowed_runtime_entrypoints".to_owned(),
            json!(["rule_template"]),
        );

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.runtime_entrypoint_unallowed"));
}

#[test]
fn lowered_ir_validator_rejects_unlowered_graph_edge() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let edge_lowerings = lowered
        .get_mut("edge_lowerings")
        .and_then(Value::as_array_mut)
        .expect("edge lowerings");
    edge_lowerings.clear();

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.edge_unlowered"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_graph_edge_lowering() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let edge_lowerings = lowered
        .get_mut("edge_lowerings")
        .and_then(Value::as_array_mut)
        .expect("edge lowerings");
    let duplicate = edge_lowerings.first().expect("edge lowering").clone();
    edge_lowerings.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.edge_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_edge_preservation_ref() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let edge_lowering = lowered
        .get_mut("edge_lowerings")
        .and_then(Value::as_array_mut)
        .expect("edge lowerings")
        .first_mut()
        .expect("edge lowering");
    let refs = edge_lowering
        .get_mut("preserved_span_refs")
        .and_then(Value::as_array_mut)
        .expect("span refs");
    let duplicate = refs.first().expect("span ref").clone();
    refs.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.edge.preservation_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_dependency_preservation_ref() {
    let (graph, mut lowered) =
        package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let dependency_lowering = lowered
        .get_mut("dependency_lowerings")
        .and_then(Value::as_array_mut)
        .expect("dependency lowerings")
        .first_mut()
        .expect("dependency lowering");
    let refs = dependency_lowering
        .get_mut("preserved_effect_refs")
        .and_then(Value::as_array_mut)
        .expect("effect refs");
    let duplicate = refs.first().expect("effect ref").clone();
    refs.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.dependency.preservation_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_core_object_metadata_ref() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    core_object.as_object_mut().expect("core object").insert(
        "resource_refs".to_owned(),
        json!(["resource:db", "resource:db"]),
    );

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.metadata_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_node_core_object_owner() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let object_id = "core:effect:effect:start:context";
    let node_lowerings = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings");
    let contract_lowering = node_lowerings
        .iter_mut()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str)
                == Some("contract:std.memory:memory.query:0.1.0")
        })
        .expect("contract lowering");
    contract_lowering
        .get_mut("produced_core_object_refs")
        .and_then(Value::as_array_mut)
        .expect("produced refs")
        .push(json!(object_id));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.owner_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_core_object_declared_owner_mismatch() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    core_object.as_object_mut().expect("core object").insert(
        "owner_ref".to_owned(),
        json!("contract:std.memory:memory.query:0.1.0"),
    );

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.owner_unmatched"));
}

#[test]
fn lowered_ir_validator_rejects_dependency_object_owned_by_interface_edge() {
    let (graph, mut lowered) =
        package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let edge_ref = first_construct_graph_edge_ref(&graph);
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("dependency"))
        .expect("dependency core object");
    let object = core_object.as_object_mut().expect("core object");
    object.insert("owner_kind".to_owned(), json!("edge"));
    object.insert("owner_ref".to_owned(), json!(edge_ref));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.dependency_owner_kind"));
}

#[test]
fn lowered_ir_validator_rejects_dependency_object_without_entrypoint_refs() {
    let (graph, mut lowered) =
        package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("dependency"))
        .expect("dependency core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_bridge_emits_dependency_handoff_entrypoint() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("dependency-bridge.whip", &graph, &lowered);

    assert!(source.contains("dependencyLoweringPreserved("));
    assert!(source.contains("dependencyEntrypoint("));
    assert!(source.contains("coreObjectOwnedByDependency("));
}

#[test]
fn lowered_ir_validator_rejects_signal_source_object_without_entrypoint_refs() {
    let (graph, mut lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("signal_source"))
        .expect("event source core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_validator_rejects_schedule_object_without_entrypoint_refs() {
    let (graph, mut lowered) = schedule_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("schedule"))
        .expect("schedule core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_validator_rejects_assertion_object_without_entrypoint_refs() {
    let (graph, mut lowered) = assertion_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("assertion"))
        .expect("assertion core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_validator_rejects_rule_object_without_entrypoint_refs() {
    let (graph, mut lowered) = rule_template_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("rule"))
        .expect("rule core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_bridge_emits_signal_source_handoff_entrypoint() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("event-ingress.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("eventSourceEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_bridge_emits_schedule_handoff_entrypoint() {
    let (graph, lowered) = schedule_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("schedule-graph.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("scheduleEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_bridge_emits_assertion_handoff_entrypoint() {
    let (graph, lowered) = assertion_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("assertion-graph.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("assertionCheckLowering"));
    assert!(source.contains("assertionEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_bridge_emits_rule_handoff_entrypoint() {
    let (graph, lowered) = rule_template_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("rule-graph.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("ruleTemplateLowering"));
    assert!(source.contains("ruleEntrypoint("));
    assert!(source.contains("factEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_validator_rejects_runtime_state_materialization() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    let object = core_object.as_object_mut().expect("core object");
    object.insert("object_kind".to_owned(), json!("run"));
    object.insert("runtime_entrypoint".to_owned(), json!("run_record"));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.runtime_state_materialized"));
}

#[test]
fn lowered_ir_validator_rejects_core_object_entrypoint_mismatch() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .insert("runtime_entrypoint".to_owned(), json!("fact_record"));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.runtime_entrypoint_mismatch"));
}

#[test]
fn lowered_ir_validator_accepts_runtime_handoff_entrypoints() {
    for (object_kind, runtime_entrypoint, entrypoint_refs) in [
        (
            "event",
            "event_record",
            json!({
                "event": "deploy.finished",
            }),
        ),
        (
            "projection",
            "event_projection",
            json!({
                "event": "deploy.finished",
                "fact": "schema:DeployFinished",
            }),
        ),
        (
            "diagnostic",
            "diagnostic_record",
            json!({
                "rule": "observe",
            }),
        ),
    ] {
        let (mut graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
        let graph_node = construct_graph_node_mut(&mut graph, "effect:start:context")
            .as_object_mut()
            .expect("graph node");
        graph_node.insert("allowed_core_object_kinds".to_owned(), json!([object_kind]));
        graph_node.insert(
            "allowed_runtime_entrypoints".to_owned(),
            json!([runtime_entrypoint]),
        );
        let core_object = lowered
            .get_mut("core_objects")
            .and_then(Value::as_array_mut)
            .expect("core objects")
            .iter_mut()
            .find(|object| {
                object.get("object_id").and_then(Value::as_str)
                    == Some("core:effect:effect:start:context")
            })
            .expect("effect core object");
        let object = core_object.as_object_mut().expect("core object");
        object.insert("object_kind".to_owned(), json!(object_kind));
        object.insert("runtime_entrypoint".to_owned(), json!(runtime_entrypoint));
        object.insert("entrypoint_refs".to_owned(), entrypoint_refs);

        let diagnostics = validate_lowered_ir_report(&lowered, &graph);
        assert_eq!(diagnostics, Vec::<Value>::new(), "{object_kind}");
    }
}
