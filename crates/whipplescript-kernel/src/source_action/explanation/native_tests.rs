use super::project_instance;
use crate::{ProgramVersionInput, RuntimeKernel};
use serde_json::json;
use std::collections::BTreeSet;
use whipplescript_store::{NewEvent, NewInstance, NewProgramVersion, SqliteStore, StoreError};

#[expect(clippy::unwrap_used, reason = "test fixture construction")]
fn append_managed_root(store: &SqliteStore, instance: &str, version: &str, rule: &str) {
    let payload = json!({
        "rule": rule,
        "context": {
            "identity": null,
            "trigger_event_id": null,
            "bindings": [],
            "action_root": {
                "schema": "whipplescript-action-root/v3",
                "frame": {
                    "version": version,
                    "revision": "0",
                    "rule": rule,
                    "identity": null,
                    "trigger_event": null
                },
                "root": { "inputs": [], "frontier": 1 }
            }
        },
        "facts": [],
        "consumed_facts": [],
        "effects": [],
        "dependencies": [],
        "terminal": null,
        "program_version_id": version,
        "revision_epoch": 0
    })
    .to_string();
    store
        .append_event(NewEvent {
            instance_id: instance,
            event_type: "rule.committed",
            payload_json: &payload,
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some("managed-root"),
        })
        .unwrap();
}

#[test]
fn instance_projection_refuses_an_unknown_instance() {
    let store = SqliteStore::open_in_memory().unwrap();
    let StoreError::Conflict(message) =
        project_instance(&store, "missing", "fixture", &BTreeSet::new()).unwrap_err()
    else {
        panic!("missing instance must be a projection conflict")
    };
    assert_eq!(message, "instance `missing` does not exist");
}

#[test]
fn instance_projection_refuses_an_unavailable_historical_executable() {
    let mut store = SqliteStore::open_in_memory().unwrap();
    let source_hash = store.put_content("workflow Missing").unwrap();
    let summary = json!({
        "execution_semantics": "dr0100-typed-actions-v1",
        "executable_program": {
            "format": crate::program_artifact::TYPED_FORMAT,
            "content_hash": "missing-executable"
        }
    })
    .to_string();
    let version = store
        .create_program_version(NewProgramVersion {
            program_name: "Missing",
            source_hash: &source_hash,
            ir_hash: "missing-ir",
            compiler_version: "test",
            ir_snapshot: None,
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: &summary,
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
        .unwrap();
    let instance = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .unwrap();
    append_managed_root(
        &store,
        &instance.instance_id,
        &version.version_id,
        "missing",
    );

    let StoreError::Conflict(message) =
        project_instance(&store, &instance.instance_id, "fixture", &BTreeSet::new()).unwrap_err()
    else {
        panic!("missing executable must be a projection conflict")
    };
    assert!(message.contains("cannot explain managed firing under program version"));
    assert!(message.contains("missing from the content store"));
}

#[test]
fn instance_projection_refuses_a_frame_not_owned_by_the_recorded_plan() {
    const SOURCE: &str = r#"workflow Exact
action answer() -> string { return "ok" }
rule real when started => { answer() as value }
"#;
    let compiled = whipplescript_parser::compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let program = compiled.ir.unwrap();
    let plans = compiled.typed_actions.unwrap();
    let identity = crate::program_artifact::typed_identity_projection(&program, &plans).unwrap();
    let mut kernel = RuntimeKernel::new(SqliteStore::open_in_memory().unwrap());
    let source_hash = kernel.store().put_content(SOURCE).unwrap();
    let version = kernel
        .create_program_version_for_typed_program(
            ProgramVersionInput {
                program_name: &program.workflow,
                source_hash: &source_hash,
                ir_hash: &crate::stable_hash_hex(&identity),
                compiler_version: "test",
                ir_snapshot: Some(&identity),
            },
            &program,
            &plans,
        )
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    append_managed_root(kernel.store(), &instance, &version.version_id, "ghost");

    let StoreError::Conflict(message) =
        project_instance(kernel.store(), &instance, "fixture", &BTreeSet::new()).unwrap_err()
    else {
        panic!("foreign frame must be a projection conflict")
    };
    assert!(message.contains("has no typed action plan for its rule"));
    assert!(message.contains("ghost"));
}
