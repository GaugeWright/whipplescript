//! `verify-report`: the independent re-check of a serialized compile report.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn verify_report_accepts_generated_artifact_evidence() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);

    verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect("generated artifact evidence verifies");
}

#[test]
fn verify_report_accepts_compile_report_success_shape() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut report =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report_object = report.as_object_mut().expect("report object");
    report_object.insert(
        "schema".to_owned(),
        Value::String(COMPILE_REPORT_SCHEMA.to_owned()),
    );
    report_object.remove("status");

    verify_report_value(&report, "compile.json", None).expect("compile report verifies");
}

#[test]
fn verify_report_artifact_bundle_emits_selected_artifact() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report = Value::Array(vec![entry]);
    let entries = verify_report_value(&report, "check.json", None).expect("check report verifies");

    let bundle = verified_report_artifacts_json(&entries, VerifyReportEmit::ConstructGraph);
    assert_eq!(
        bundle.get("schema").and_then(Value::as_str),
        Some("whipplescript.verified_artifacts.v0")
    );
    assert_eq!(
        bundle.get("emit").and_then(Value::as_str),
        Some("construct-graph")
    );
    let first_entry = bundle
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .expect("bundle entry");
    assert!(first_entry.get("construct_graph").is_some());
    assert!(first_entry.get("lowered_ir_report").is_none());
    assert!(first_entry
        .get("snapshot")
        .and_then(Value::as_str)
        .is_some());
    assert_eq!(
        first_entry.get("label").and_then(Value::as_str),
        Some("check.json[0]")
    );
}

#[test]
fn verify_report_lowered_ir_bundle_carries_graph_dependency() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report = Value::Array(vec![entry]);
    let entries = verify_report_value(&report, "check.json", None).expect("check report verifies");

    let bundle = verified_report_artifacts_json(&entries, VerifyReportEmit::LoweredIrReport);
    assert_eq!(
        bundle.get("emit").and_then(Value::as_str),
        Some("lowered-ir")
    );
    let first_entry = bundle
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .expect("bundle entry");
    assert!(first_entry.get("construct_graph").is_some());
    assert!(first_entry.get("lowered_ir_report").is_some());

    verify_report_value(&bundle, "lowered-ir.json", None).expect("lowered-ir bundle revalidates");
}

#[test]
fn artifact_model_search_writer_emits_verified_bundle() {
    // Deliberately shares `event-ingress.whip` with the lowered-IR bridge test:
    // that pair is what caught the scratch-path collision, so leaving both on
    // one label keeps `temp_scratch_path`'s uniqueness under test.
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);

    let path = write_verified_artifact_model_search_bundle("event-ingress.whip", &entry)
        .expect("verified artifact bundle writes");
    let bundle = serde_json::from_str::<Value>(
        &fs::read_to_string(&path).expect("verified artifact bundle reads"),
    )
    .expect("verified artifact bundle parses");
    let _ = fs::remove_file(path);

    assert_eq!(
        bundle.get("schema").and_then(Value::as_str),
        Some("whipplescript.verified_artifacts.v0")
    );
    assert_eq!(
        bundle.get("emit").and_then(Value::as_str),
        Some("artifacts")
    );
    let first_entry = bundle
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .expect("bundle entry");
    assert!(first_entry.get("construct_graph").is_some());
    assert!(first_entry.get("lowered_ir_report").is_some());
    assert!(first_entry
        .get("snapshot")
        .and_then(Value::as_str)
        .is_some());
}

#[test]
fn verify_report_accepts_full_verified_artifact_bundle_input() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let bundle = verified_report_artifacts_json(&verified_entries, VerifyReportEmit::Artifacts);

    let entries = verify_report_value(&bundle, "artifacts.json", None)
        .expect("verified artifact bundle verifies");

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].report_schema.as_str(),
        "whipplescript.check_report.v0"
    );
    assert_eq!(entries[0].report_path.as_str(), "artifacts.json");
}

#[test]
fn verify_report_accepts_construct_graph_verified_artifact_bundle_input() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let bundle =
        verified_report_artifacts_json(&verified_entries, VerifyReportEmit::ConstructGraph);

    let entries = verify_report_value(&bundle, "construct-graph.json", None)
        .expect("construct graph bundle verifies");

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].report_schema.as_str(),
        "whipplescript.check_report.v0"
    );
    assert_eq!(entries[0].report_path.as_str(), "construct-graph.json");
    assert!(entries[0].lowered_ir_report.is_none());
}

#[test]
fn verify_report_rejects_verified_artifact_bundle_unknown_top_level_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let mut bundle =
        verified_report_artifacts_json(&verified_entries, VerifyReportEmit::ConstructGraph);
    bundle
        .as_object_mut()
        .expect("bundle object")
        .insert("unexpected".to_owned(), Value::Bool(true));

    let error = verify_report_value(&bundle, "construct-graph.json", None)
        .expect_err("unknown top-level bundle fields should reject");
    assert!(
        error.contains("construct-graph.json field `unexpected` is not allowed"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_verified_artifact_bundle_unknown_entry_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let mut bundle = verified_report_artifacts_json(&verified_entries, VerifyReportEmit::Artifacts);
    bundle
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .and_then(|entries| entries.first_mut())
        .and_then(Value::as_object_mut)
        .expect("bundle entry object")
        .insert("unexpected".to_owned(), Value::Bool(true));

    let error = verify_report_value(&bundle, "artifacts.json", None)
        .expect_err("unknown bundle entry fields should reject");
    assert!(
        error.contains("artifacts.json.entries[0] field `unexpected` is not allowed"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_construct_graph_bundle_with_lowered_ir_report() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let mut bundle =
        verified_report_artifacts_json(&verified_entries, VerifyReportEmit::ConstructGraph);
    bundle
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .and_then(|entries| entries.first_mut())
        .and_then(Value::as_object_mut)
        .expect("bundle entry object")
        .insert("lowered_ir_report".to_owned(), lowered);

    let error = verify_report_value(&bundle, "construct-graph.json", None)
        .expect_err("construct-graph bundles should not carry lowered IR reports");
    assert!(
            error.contains(
                "construct-graph.json.entries[0].lowered_ir_report is not allowed in construct-graph bundles"
            ),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_missing_check_report_schema() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .as_object_mut()
        .expect("report entry object")
        .remove("schema");
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None).expect_err("schema is required");
    assert!(
        error.contains("check.json[0].schema must be a string"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_malformed_skipped_check_report_entry() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let ok_entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let malformed_error_entry = json!({
        "schema": CHECK_REPORT_SCHEMA,
        "path": "bad.whip",
        "status": "error",
        "error": {
            "kind": "not-a-check-error-kind",
        },
    });
    let report = Value::Array(vec![ok_entry, malformed_error_entry]);

    let error = verify_report_value(&report, "check.json", None)
        .expect_err("malformed non-ok entry should reject the whole report envelope");
    assert!(
        error.contains("check.json[1].error.kind must be one of"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_ir_hash() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry.as_object_mut().expect("report entry object").insert(
        "ir_hash".to_owned(),
        Value::String("00000000000000000000000000000000".to_owned()),
    );
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None).expect_err("ir_hash is stale");
    assert!(
        error.contains("ir_hash must match the embedded snapshot hash"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_construct_graph_id_not_bound_to_source_digest() {
    let (mut graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    graph
        .as_object_mut()
        .expect("graph object")
        .insert("graph_id".to_owned(), json!("construct_graph:stale"));
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None)
        .expect_err("graph_id is not derived from source_digest");
    assert!(
        error.contains("construct_graph.graph_id must be"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_accepted_program_digest() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("lowered_ir_report")
        .and_then(Value::as_object_mut)
        .expect("lowered report object")
        .insert(
            "accepted_program_digest".to_owned(),
            Value::String("0".repeat(64)),
        );
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None)
        .expect_err("accepted_program_digest is stale");
    assert!(
        error.contains("accepted_program_digest does not match graph_id + snapshot"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_success_compile_report_status_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut report =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    report.as_object_mut().expect("report object").insert(
        "schema".to_owned(),
        Value::String(COMPILE_REPORT_SCHEMA.to_owned()),
    );

    let error = verify_report_value(&report, "compile.json", None).expect_err("status is reserved");
    assert!(
        error.contains("status must be omitted for successful compile reports"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_construct_graph_evidence() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    append_stale_validator_ref(
        entry
            .get_mut("construct_graph")
            .expect("construct graph artifact"),
        "construct_graph_validator",
    );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale construct evidence should fail");
    assert!(
        error.contains("construct graph validator predicate")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_construct_graph_port_profile_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("construct_graph")
        .expect("construct graph artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("graph derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| predicate.starts_with("validator.port.profile:"))
        })
        .expect("port profile fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("port profile input refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale port profile evidence should fail");
    assert!(
        error.contains("validator.port.profile")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_package_contract_digest() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(Value::as_object_mut)
        .expect("package contract")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String("0".repeat(64)),
        );

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("stale package contract digest should be rejected");
    assert!(
        error.contains("package_contract.package_contract_digest does not match"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_incomplete_contract_registry_spine() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("contract_registry")
        .and_then(Value::as_object_mut)
        .expect("report contract registry")
        .remove("libraries");
    entry
        .get_mut("package_contract")
        .and_then(|package_contract| package_contract.get_mut("contract_registry"))
        .and_then(Value::as_object_mut)
        .expect("embedded contract registry")
        .remove("libraries");
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("incomplete contract registry should be rejected");
    assert!(
        error.contains("check.json[0].contract_registry.libraries must be an array"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unsupported_contract_registry_schema_fragment() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "input_schema": "unsupported.custom",
    });
    fn add_test_package_contract(registry: &mut Value, contract: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(json!({
                "id": "memory",
                "version": "0.1.0",
                "standard": false,
            }));
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
    }
    add_test_package_contract(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &contract,
    );
    add_test_package_contract(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &contract,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("unsupported package schema fragment should be rejected");
    assert!(
            error.contains(
                "check.json[0].contract_registry.effect_contracts[0].input_schema uses unsupported package type `unsupported.custom`"
            ),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_construct_missing_required_input_schema_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
        "input_schema": "{\"query\":\"string\"}",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "expression", "required": false}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.query", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.query",
    });

    fn add_bad_construct_registry(
        registry: &mut Value,
        library: &Value,
        contract: &Value,
        construct: &Value,
    ) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_bad_construct_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_bad_construct_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("construct/input schema mismatch should be rejected");
    assert!(
        error.contains("check.json[0].contract_registry.constructs")
            && error
                .contains("target input_schema field `query` is optional in the construct fields"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unsupported_contract_registry_construct_vocabulary() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "synthetic.unsupported", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.query", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.query",
    });

    fn add_bad_construct_registry(
        registry: &mut Value,
        library: &Value,
        contract: &Value,
        construct: &Value,
    ) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_bad_construct_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_bad_construct_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("unsupported construct vocabulary should be rejected");
    assert!(
        error.contains("check.json[0].contract_registry.constructs")
            && error.contains(
                "fields[0].kind uses unsupported construct field kind `synthetic.unsupported`"
            ),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_construct_target_without_effect_contract() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "expression", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.missing", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.missing",
    });

    fn add_registry(registry: &mut Value, library: &Value, contract: &Value, construct: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("construct target without effect contract should be rejected");
    assert!(
            error.contains("target_capability `memory.missing` has no matching package `capability.call` effect contract"),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_effect_contract_required_capability_without_contract() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
        "required_capabilities": ["memory.missing"],
    });

    fn add_registry(registry: &mut Value, library: &Value, contract: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("required capability without effect contract should be rejected");
    assert!(
        error.contains("required_capabilities references `memory.missing`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_duplicate_package_construct_keyword() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "expression", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.query", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.query",
    });
    let mut duplicate = construct.clone();
    duplicate.as_object_mut().expect("construct object").insert(
        "id".to_owned(),
        Value::String("memory.recall.alt".to_owned()),
    );

    fn add_registry(
        registry: &mut Value,
        library: &Value,
        contract: &Value,
        construct: &Value,
        duplicate: &Value,
    ) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        let constructs = registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs");
        constructs.push(construct.clone());
        constructs.push(duplicate.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
        &duplicate,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
        &duplicate,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("duplicate construct keyword should be rejected");
    assert!(
        error.contains("duplicates package construct keyword `recall` in scope `rule_body`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unprivileged_reserved_construct_keyword() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.claim",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.claim",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "claim",
        "scope": "rule_body",
        "fields": [
            {"name": "issue", "kind": "expression", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.claim", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.claim.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.claim",
    });

    fn add_registry(registry: &mut Value, library: &Value, contract: &Value, construct: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("unprivileged reserved construct keyword should be rejected");
    assert!(
        error.contains("uses reserved construct keyword `claim`"),
        "{error}"
    );
    assert!(
        error.contains("platform catalog authorization for library `memory`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_incomplete_embedded_contract_registry_spine() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(|package_contract| package_contract.get_mut("contract_registry"))
        .and_then(Value::as_object_mut)
        .expect("embedded contract registry")
        .remove("libraries");
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("incomplete embedded contract registry should be rejected");
    assert!(
        error.contains(
            "check.json[0].package_contract.contract_registry.libraries must be an array"
        ),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_incomplete_package_contract_spine() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(Value::as_object_mut)
        .expect("package contract")
        .remove("manifests");
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("incomplete package contract should be rejected");
    assert!(
        error.contains("check.json[0].package_contract.manifests must be an array"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_invalid_package_lock_digest_shape() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(Value::as_object_mut)
        .expect("package contract")
        .insert(
            "package_lock_digest".to_owned(),
            Value::String("ABC".to_owned()),
        );
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert(
            "package_lock_digest".to_owned(),
            Value::String("ABC".to_owned()),
        );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("invalid package lock digest should be rejected");
    assert!(
            error.contains(
                "check.json[0].package_contract.package_lock_digest must be a 64-character lowercase hex digest"
            ),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_package_contract_diagnostics() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let package_contract = entry.get_mut("package_contract").expect("package contract");
    package_contract
        .get_mut("diagnostics")
        .and_then(Value::as_array_mut)
        .expect("package contract diagnostics")
        .push(json!({
            "code": "package_contract.synthetic",
            "message": "synthetic package contract diagnostic",
        }));
    let mut digest_body = package_contract.clone();
    digest_body
        .as_object_mut()
        .expect("package contract object")
        .remove("package_contract_digest");
    let digest = sha256_hex(canonical_json(&digest_body).as_bytes());
    package_contract
        .as_object_mut()
        .expect("package contract object")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(digest.clone()),
        );
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert("package_contract_digest".to_owned(), Value::String(digest));

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("package contract diagnostics should be rejected");
    assert!(
        error.contains("package_contract.diagnostics must be empty"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_platform_construct_catalog() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let package_contract = entry.get_mut("package_contract").expect("package contract");
    package_contract
        .get_mut("platform_construct_catalog")
        .and_then(|catalog| catalog.get_mut("interface_kinds"))
        .and_then(Value::as_array_mut)
        .expect("platform catalog interface kinds")
        .push(Value::String("BogusInterface".to_owned()));
    let mut digest_body = package_contract.clone();
    digest_body
        .as_object_mut()
        .expect("package contract object")
        .remove("package_contract_digest");
    let digest = sha256_hex(canonical_json(&digest_body).as_bytes());
    package_contract
        .as_object_mut()
        .expect("package contract object")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(digest.clone()),
        );
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert("package_contract_digest".to_owned(), Value::String(digest));

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("stale platform catalog should be rejected");
    assert!(
        error.contains("platform_construct_catalog must match verifier platform catalog"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_graph_package_contract_digest_mismatch() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String("0".repeat(64)),
        );

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("graph package contract digest mismatch should be rejected");
    assert!(
        error.contains("construct_graph.package_contract_digest does not match"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_evidence() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    append_stale_validator_ref(
        entry
            .get_mut("lowered_ir_report")
            .expect("lowered IR artifact"),
        "lowered_ir_validator",
    );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale lowered evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_lifecycle_input_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with("lowered_ir.validator.node.lifecycle_inputs:")
                })
        })
        .expect("lifecycle input fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("lifecycle input refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale lifecycle input evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.node.lifecycle_inputs")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_lifecycle_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with(
                        "lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:",
                    )
                })
        })
        .expect("lifecycle runtime-entrypoint component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("lifecycle runtime-entrypoint refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale lifecycle component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_output_compat_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with(
                        "lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints:",
                    )
                })
        })
        .expect("output allowed-runtime-entrypoint component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("output allowed-runtime-entrypoint refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale output compatibility component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error
                .contains("lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_node_preservation_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate
                        .starts_with("lowered_ir.validator.node.preservation.terminal_binding:")
                })
        })
        .expect("terminal binding preservation component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("terminal binding preservation refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale node preservation component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.node.preservation.terminal_binding")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_edge_preservation_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with("lowered_ir.validator.edge.preservation.core_relation:")
                })
        })
        .expect("edge core-relation preservation component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("core relation preservation refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale edge preservation component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.edge.preservation.core_relation")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_dependency_preservation_component_evidence() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with("lowered_ir.validator.dependency.preservation.predicate:")
                })
        })
        .expect("dependency predicate preservation component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("dependency predicate preservation refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale dependency preservation component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.dependency.preservation.predicate")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_core_object_entrypoint_evidence() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate
                        .starts_with("lowered_ir.validator.core_object.entrypoint:core:dependency:")
                })
        })
        .expect("dependency core object entrypoint fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("entrypoint input refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale core object entrypoint evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.core_object.entrypoint")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_accepts_model_search_artifact_ledger() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);

    verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect("generated model_search artifact ledger verifies");
}

#[test]
fn verify_report_rejects_stale_model_search_artifact_ledger() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.construct_graph")
        })
        .expect("artifact obligation");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "downstream".to_owned(),
            Value::String("stale-node".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale model_search artifact obligation should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_artifact_model_search_obligations_artifact() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("artifact_model_search_obligations")
        .and_then(|artifact| artifact.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("artifact_model_search_obligations rows");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.construct_graph")
        })
        .expect("artifact obligation artifact row");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "downstream".to_owned(),
            Value::String("stale-node".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale artifact_model_search_obligations row should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch")
            && error.contains("artifact.construct_graph"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_model_search_platform_catalog_ledger() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.platform_catalog")
        })
        .expect("platform catalog artifact obligation");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "downstream".to_owned(),
            Value::String("stale-lowering-class".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale platform catalog obligation should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch")
            && error.contains("artifact.platform_catalog"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_model_search_handoff_source_span() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.lowered_ir")
                && obligation.get("predicate").and_then(Value::as_str) == Some("handoffObjectOk")
        })
        .expect("handoff artifact obligation");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "source_span".to_owned(),
            json!({
                "start": 999_999,
                "end": 1_000_000,
            }),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale handoff source span should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch")
            && error.contains("artifact.lowered_ir")
            && error.contains("source_span"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unknown_ir_model_search_predicate() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    set_report_snapshot_for_test(
            &mut entry,
            "workflow SnapshotSupport\nrules\n  rule start\n    when Task as task\n    effects\n      first kind=agent.tell binding=- key=first\n      second kind=agent.tell binding=- key=second\n    dependencies\n      first --succeeds--> second\n    body_hash abc\n",
        );
    add_ir_model_search_ledger_from_snapshot_for_test(&mut entry);
    let model_search = entry.get_mut("model_search").expect("model_search");
    let model_search_object = model_search.as_object_mut().expect("model_search object");
    let obligations = model_search_object
        .get_mut("obligations")
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let ir_obligation = obligations
        .iter_mut()
        .find(|obligation| obligation.get("category").and_then(Value::as_str) == Some("ir"))
        .expect("IR obligation");
    ir_obligation
        .as_object_mut()
        .expect("IR obligation object")
        .insert(
            "predicate".to_owned(),
            Value::String("not-a-generated-predicate".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("unknown generated IR predicate should fail");
    assert!(
        error.contains("unknown generated predicate `not-a-generated-predicate`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unsupported_ir_model_search_obligation() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    set_report_snapshot_for_test(
            &mut entry,
            "workflow SnapshotSupport\nrules\n  rule start\n    when Task as task\n    effects\n      first kind=agent.tell binding=- key=first\n      second kind=agent.tell binding=- key=second\n    dependencies\n      first --succeeds--> second\n    body_hash abc\n",
        );
    add_ir_model_search_ledger_from_snapshot_for_test(&mut entry);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let ir_obligation = obligations
        .iter_mut()
        .find(|obligation| obligation.get("category").and_then(Value::as_str) == Some("ir"))
        .expect("IR obligation");
    ir_obligation
        .as_object_mut()
        .expect("IR obligation object")
        .insert(
            "upstream".to_owned(),
            Value::String("missing-upstream".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("unsupported generated IR obligation should fail");
    assert!(
        error.contains("not supported by the embedded snapshot"),
        "{error}"
    );
}
