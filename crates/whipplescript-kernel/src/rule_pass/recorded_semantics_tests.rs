use super::{
    load_version_ir, load_version_program, step_active_program_generic,
    step_executable_program_generic, step_instance_generic,
};
use crate::{program_analysis_summary_json, ProgramVersionInput, RuntimeKernel};
use serde_json::Value;
use whipplescript_parser::{
    compile_program, execution_semantics::compile_recorded_program_with_root, ExecutionSemantics,
};
use whipplescript_store::{
    NewProgramVersion, RevisionActivation, RuntimeStore, SqliteStore, StoreError,
};

const SOURCE: &str =
    include_str!("../../../whipplescript-parser/tests/fixtures/recorded-actions-v1.whip");
const SNAPSHOT: &str =
    include_str!("../../../whipplescript-parser/tests/fixtures/recorded-actions-v1.ir");

fn fixture(analysis: &str, source: &str) -> (RuntimeKernel, String, String) {
    let mut kernel = RuntimeKernel::new(SqliteStore::open_in_memory().expect("test store opens"));
    let current = kernel
        .create_program_version(ProgramVersionInput {
            program_name: "RecordedActions",
            source_hash: "current-source",
            ir_hash: "current-ir",
            compiler_version: "current",
            ir_snapshot: None,
        })
        .expect("current version is created");
    let instance = kernel
        .create_instance(&current, "{}")
        .expect("instance is created");
    let hash = kernel
        .store()
        .put_content(source)
        .expect("old source is stored");
    let old = kernel
        .store_mut()
        .create_program_version(NewProgramVersion {
            program_name: "RecordedActions",
            source_hash: &hash,
            ir_hash: "old-ir",
            ir_snapshot: None,
            compiler_version: "unrelated-package-version",
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: analysis,
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
        .expect("old version is created");
    (kernel, instance, old.version_id)
}

#[test]
fn recorded_legacy_program_metadata_names_its_actual_pipeline() {
    let ir =
        compile_recorded_program_with_root(SOURCE, None, ExecutionSemantics::LegacyActionChainsV1)
            .ir
            .unwrap();
    let summary: Value = serde_json::from_str(&program_analysis_summary_json(&ir)).unwrap();
    assert_eq!(summary["execution_semantics"], "dr0023-action-chains-v1");
    let mut kernel = RuntimeKernel::new(SqliteStore::open_in_memory().unwrap());
    let hash = kernel.store().put_content(SOURCE).unwrap();
    let version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &ir.workflow,
                source_hash: &hash,
                ir_hash: &whipplescript_parser::snapshot::identity_hash(SNAPSHOT),
                ir_snapshot: None,
                compiler_version: "test",
            },
            &ir,
        )
        .unwrap();
    let stored = kernel
        .store()
        .get_program_version(&version.version_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&stored.analysis_summary_json).unwrap(),
        summary
    );
    let instance = kernel.create_instance(&version, "{}").unwrap();
    let loaded = load_version_ir(&mut kernel, &instance, &version.version_id)
        .unwrap()
        .unwrap();
    assert_eq!(loaded.to_snapshot(), SNAPSHOT);
}

#[test]
fn recorded_semantics_untagged_and_explicit_legacy_versions_load_the_frozen_graph() {
    for analysis in ["{}", r#"{"execution_semantics":"dr0023-action-chains-v1"}"#] {
        let (mut kernel, instance, version) = fixture(analysis, SOURCE);
        for _ in 0..2 {
            let loaded = load_version_ir(&mut kernel, &instance, &version)
                .unwrap()
                .unwrap();
            assert_eq!(
                loaded.execution_semantics,
                ExecutionSemantics::LegacyActionChainsV1
            );
            assert_eq!(loaded.to_snapshot(), SNAPSHOT);
        }
        assert!(kernel
            .store()
            .list_diagnostics(Some(&instance))
            .unwrap()
            .is_empty());
        assert!(kernel.store().list_effects(&instance).unwrap().is_empty());
    }
}

#[test]
fn recorded_semantics_unsupported_or_corrupt_metadata_refuses_once_per_version() {
    for (analysis, detail) in [
        (
            r#"{"execution_semantics":"future-v99"}"#,
            "unsupported recorded execution semantics",
        ),
        (
            r#"{"execution_semantics":""}"#,
            "unsupported recorded execution semantics",
        ),
        (r#"{"execution_semantics":null}"#, "tag is not a string"),
        (r#"{"execution_semantics":false}"#, "tag is not a string"),
        (r#"{"execution_semantics":23}"#, "tag is not a string"),
        (r#"{"execution_semantics":{}}"#, "tag is not a string"),
        ("null", "metadata is not an object"),
        ("[]", "metadata is not an object"),
        ("{", "metadata is not valid JSON"),
    ] {
        let (mut kernel, instance, version) = fixture(analysis, SOURCE);
        let before = kernel.store().list_events(&instance).unwrap();
        for _ in 0..2 {
            assert!(
                load_version_ir(&mut kernel, &instance, &version)
                    .unwrap()
                    .is_none(),
                "{analysis}"
            );
        }
        let diagnostics = kernel.store().list_diagnostics(Some(&instance)).unwrap();
        assert_eq!(diagnostics.len(), 1, "{analysis}");
        assert_eq!(
            diagnostics[0].code.as_deref(),
            Some("progression.version_unavailable")
        );
        assert_eq!(
            diagnostics[0].program_version_id.as_deref(),
            Some(version.as_str())
        );
        assert!(
            diagnostics[0].message.contains(detail),
            "{}",
            diagnostics[0].message
        );
        let after = kernel.store().list_events(&instance).unwrap();
        assert_eq!(&after[..before.len()], before.as_slice());
        assert_eq!(after.len(), before.len() + 1);
        assert_eq!(after.last().unwrap().event_type, "diagnostic.recorded");
        assert!(kernel.store().list_effects(&instance).unwrap().is_empty());
        assert!(kernel.store().list_facts(&instance).unwrap().is_empty());
    }
}

#[test]
fn recorded_semantics_selection_precedes_source_compilation() {
    let (mut kernel, instance, version) = fixture(
        r#"{"execution_semantics":"future-v99"}"#,
        "not valid source",
    );
    assert!(load_version_ir(&mut kernel, &instance, &version)
        .unwrap()
        .is_none());
    let diagnostics = kernel.store().list_diagnostics(Some(&instance)).unwrap();
    assert!(diagnostics[0].message.contains("future-v99"));
    assert!(!diagnostics[0].message.contains("no longer compiles"));
}

#[test]
fn recorded_semantics_restores_a_complete_typed_capture_without_source_compilation() {
    const TYPED: &str = r#"workflow TypedRecorded
action label(value string) -> string { return value }
rule run when started => { label("ok") as answer }
"#;
    let compiled =
        compile_recorded_program_with_root(TYPED, None, ExecutionSemantics::TypedActionsV1);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let program = compiled.ir.unwrap();
    let plans = compiled.typed_actions.unwrap();
    let identity = crate::program_artifact::typed_identity_projection(&program, &plans).unwrap();
    let ir_hash = crate::stable_hash_hex(&identity);
    let mut kernel = RuntimeKernel::new(SqliteStore::open_in_memory().unwrap());
    let source_hash = kernel.store().put_content("not valid source").unwrap();
    let input = ProgramVersionInput {
        program_name: &program.workflow,
        source_hash: &source_hash,
        ir_hash: &ir_hash,
        compiler_version: "test",
        ir_snapshot: Some(&identity),
    };
    let summary =
        crate::program_artifact::capture_typed(kernel.store(), &input, &program, &plans).unwrap();
    let version = kernel
        .store_mut()
        .create_program_version(NewProgramVersion {
            program_name: &program.workflow,
            source_hash: &source_hash,
            ir_hash: &ir_hash,
            ir_snapshot: Some(&identity),
            compiler_version: "test",
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: &summary,
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    let loaded = load_version_program(&mut kernel, &instance, &version.version_id)
        .unwrap()
        .expect("typed executable artifact loads");
    assert_eq!(loaded.program, program);
    assert_eq!(loaded.typed_actions, plans);
    assert!(kernel
        .store()
        .list_diagnostics(Some(&instance))
        .unwrap()
        .is_empty());
    assert!(kernel.store().list_effects(&instance).unwrap().is_empty());
}

#[test]
fn verified_typed_executable_drives_nested_action_through_the_shared_rule_pass() {
    const SOURCE: &str = r#"workflow TypedDriven
output result Answer
class Answer { text string }
action answer() -> Answer { return { text "ready" } }
rule finish when started => { answer() as answer
complete result answer }
"#;
    let compiled =
        compile_recorded_program_with_root(SOURCE, None, ExecutionSemantics::TypedActionsV1);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let program = compiled.ir.unwrap();
    let plans = compiled.typed_actions.unwrap();
    let identity = crate::program_artifact::typed_identity_projection(&program, &plans).unwrap();
    let ir_hash = crate::stable_hash_hex(&identity);
    let path = std::env::temp_dir().join(format!(
        "typed-rule-pass-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let stores = whipplescript_store::native_stores::NativeStores {
        runtime: SqliteStore::open(&path).unwrap(),
        coord: whipplescript_store::coordination::CoordinationStore::open_in_memory().unwrap(),
        items: whipplescript_store::items::WorkItemStore::open_in_memory().unwrap(),
        frontier: None,
    };
    let mut kernel = RuntimeKernel::new(stores);
    let source_hash = kernel.store().put_content(SOURCE).unwrap();
    let version = kernel
        .create_program_version_for_typed_program(
            ProgramVersionInput {
                program_name: &program.workflow,
                source_hash: &source_hash,
                ir_hash: &ir_hash,
                compiler_version: "test",
                ir_snapshot: Some(&identity),
            },
            &program,
            &plans,
        )
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    kernel
        .ingest_external_event(&instance, "external.started", "{}", Some("started"))
        .unwrap();
    let executable = crate::program_artifact::ExecutableProgram {
        program: program.clone(),
        typed_actions: plans,
    };

    let StoreError::Conflict(message) =
        step_executable_program_generic(&mut kernel, "missing", &executable, None, None)
            .unwrap_err()
    else {
        panic!("missing instance must be a version conflict")
    };
    assert_eq!(message, "instance does not exist");
    let StoreError::Conflict(message) =
        step_active_program_generic(&mut kernel, "missing", None, None, None).unwrap_err()
    else {
        panic!("active-program loading must refuse a missing instance")
    };
    assert_eq!(message, "instance does not exist");

    let StoreError::Conflict(message) =
        step_instance_generic(&mut kernel, &instance, &program, None, None).unwrap_err()
    else {
        panic!("typed IR at the legacy entry point must be a version conflict")
    };
    assert!(message.contains("complete executable program"));
    assert!(kernel.store().list_facts(&instance).unwrap().is_empty());

    let StoreError::Conflict(message) = step_executable_program_generic(
        &mut kernel,
        &instance,
        &executable,
        None,
        Some("stale-version"),
    )
    .unwrap_err() else {
        panic!("stale active-version guard must be a version conflict")
    };
    assert!(message.contains("active version changed before executable dispatch"));
    assert!(kernel.store().list_facts(&instance).unwrap().is_empty());
    let StoreError::Conflict(message) =
        step_active_program_generic(&mut kernel, &instance, None, None, Some("stale-version"))
            .unwrap_err()
    else {
        panic!("active-program loading must refuse a stale version guard")
    };
    assert!(message.contains("active version changed before program load"));

    let mut wrong = executable.clone();
    wrong.typed_actions.get_mut("finish").unwrap().plan.nodes[0]
        .span
        .end += 1;
    let StoreError::Conflict(message) = step_executable_program_generic(
        &mut kernel,
        &instance,
        &wrong,
        None,
        Some(&version.version_id),
    )
    .unwrap_err() else {
        panic!("wrong executable identity must be a version conflict")
    };
    assert!(message.contains("does not match the active recorded version"));
    assert!(kernel.store().list_facts(&instance).unwrap().is_empty());

    let report = step_active_program_generic(
        &mut kernel,
        &instance,
        None,
        None,
        Some(&version.version_id),
    )
    .unwrap();
    assert!(report.committed_rules >= 1);
    let status = kernel.store().get_instance(&instance).unwrap().unwrap();
    assert_eq!(status.status, "completed");
    let completed = kernel
        .store()
        .list_events(&instance)
        .unwrap()
        .into_iter()
        .find(|event| event.event_type == "workflow.completed")
        .expect("managed terminal committed through the shared rule pass");
    let payload: Value = serde_json::from_str(&completed.payload_json).unwrap();
    assert_eq!(payload["payload"], serde_json::json!({"text":"ready"}));

    let legacy_ir = compile_program("@service workflow LegacyFallback\n")
        .ir
        .unwrap();
    let legacy_version = kernel
        .create_program_version(ProgramVersionInput {
            program_name: &legacy_ir.workflow,
            source_hash: "missing-legacy-source",
            ir_hash: "legacy-ir-before-capture",
            compiler_version: "test",
            ir_snapshot: None,
        })
        .unwrap();
    let legacy_instance = kernel.create_instance(&legacy_version, "{}").unwrap();
    let StoreError::Conflict(message) =
        step_active_program_generic(&mut kernel, &legacy_instance, None, None, None).unwrap_err()
    else {
        panic!("uncaptured legacy execution needs its historical caller IR")
    };
    assert!(message.contains("neither an executable capture, stored source nor caller fallback"));
    let StoreError::Conflict(message) =
        step_active_program_generic(&mut kernel, &legacy_instance, Some(&program), None, None)
            .unwrap_err()
    else {
        panic!("legacy fallback must never select typed semantics")
    };
    assert_eq!(
        message,
        "active legacy version cannot use a typed executable fallback"
    );
    assert_eq!(
        step_active_program_generic(&mut kernel, &legacy_instance, Some(&legacy_ir), None, None,)
            .unwrap()
            .committed_rules,
        0
    );

    let original_summary = kernel
        .store()
        .get_program_version(&version.version_id)
        .unwrap()
        .unwrap()
        .analysis_summary_json;
    let mut damaged: Value = serde_json::from_str(&original_summary).unwrap();
    damaged["executable_program"]["content_hash"] = serde_json::json!("missing-artifact");
    let corrupt = rusqlite::Connection::open(&path).unwrap();
    corrupt
        .execute(
            "UPDATE program_versions SET analysis_summary = ?1 WHERE version_id = ?2",
            rusqlite::params![damaged.to_string(), version.version_id],
        )
        .unwrap();
    drop(corrupt);
    let StoreError::Conflict(message) =
        step_active_program_generic(&mut kernel, &instance, None, None, None).unwrap_err()
    else {
        panic!("active loading must stop after a missing typed artifact")
    };
    assert!(message.contains("active executable program"));
    let restore = rusqlite::Connection::open(&path).unwrap();
    restore
        .execute(
            "UPDATE program_versions SET analysis_summary = ?1 WHERE version_id = ?2",
            rusqlite::params![original_summary, version.version_id],
        )
        .unwrap();
    drop(restore);

    let corrupt = rusqlite::Connection::open(&path).unwrap();
    corrupt.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
    corrupt
        .execute(
            "DELETE FROM program_versions WHERE version_id = ?1",
            rusqlite::params![version.version_id],
        )
        .unwrap();
    drop(corrupt);
    let StoreError::Conflict(message) =
        step_executable_program_generic(&mut kernel, &instance, &executable, None, None)
            .unwrap_err()
    else {
        panic!("missing active version must be a version conflict")
    };
    assert_eq!(message, "active program version does not exist");
    let StoreError::Conflict(message) =
        step_active_program_generic(&mut kernel, &instance, None, None, None).unwrap_err()
    else {
        panic!("active-program loading must refuse a missing version")
    };
    assert_eq!(message, "active program version does not exist");
    drop(kernel);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn verified_typed_region_lapses_and_cancels_through_the_shared_rule_pass() {
    const SOURCE: &str = r#"workflow TypedRegion
class Stop { id string }
rule finish when started => { during empty(Stop) { timer 1h as held } on lapse as progress { timer 2h as cleanup } }
"#;
    let compiled = compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let program = compiled.ir.unwrap();
    assert_eq!(
        program.execution_semantics,
        ExecutionSemantics::TypedActionsV1
    );
    let plans = compiled.typed_actions.unwrap();
    let identity = crate::program_artifact::typed_identity_projection(&program, &plans).unwrap();
    let stores = whipplescript_store::native_stores::NativeStores {
        runtime: SqliteStore::open_in_memory().unwrap(),
        coord: whipplescript_store::coordination::CoordinationStore::open_in_memory().unwrap(),
        items: whipplescript_store::items::WorkItemStore::open_in_memory().unwrap(),
        frontier: None,
    };
    let mut kernel = RuntimeKernel::new(stores);
    let version = kernel
        .create_program_version_for_typed_program(
            ProgramVersionInput {
                program_name: &program.workflow,
                source_hash: "typed-region-source",
                ir_hash: &crate::stable_hash_hex(&identity),
                compiler_version: "test",
                ir_snapshot: Some(&identity),
            },
            &program,
            &plans,
        )
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    kernel
        .ingest_external_event(&instance, "external.started", "{}", Some("started"))
        .unwrap();
    let executable = crate::program_artifact::ExecutableProgram {
        program,
        typed_actions: plans,
    };

    let holding = step_executable_program_generic(
        &mut kernel,
        &instance,
        &executable,
        None,
        Some(&version.version_id),
    )
    .unwrap();
    assert_eq!(holding.effects_created, 1);
    let held = kernel.store().list_effects(&instance).unwrap()[0].clone();
    assert_eq!(held.status, "queued");

    kernel
        .derive_fact(&instance, "Stop", "stop", r#"{"id":"stop"}"#, None, None)
        .unwrap();
    let lapsed = step_executable_program_generic(
        &mut kernel,
        &instance,
        &executable,
        None,
        Some(&version.version_id),
    )
    .unwrap();
    assert_eq!(
        lapsed.effects_created, 1,
        "the lapse cleanup is admitted once"
    );
    let effects = kernel.store().list_effects(&instance).unwrap();
    assert_eq!(effects.len(), 2);
    assert_eq!(
        effects
            .iter()
            .find(|effect| effect.effect_id == held.effect_id)
            .unwrap()
            .status,
        "cancelled"
    );
    assert_eq!(
        effects
            .iter()
            .filter(|effect| effect.status == "queued")
            .count(),
        1,
        "only the lapse cleanup remains pending"
    );
    let lapses = kernel
        .store()
        .list_facts(&instance)
        .unwrap()
        .into_iter()
        .filter(|fact| fact.name == "progression.region.lapsed")
        .collect::<Vec<_>>();
    assert_eq!(lapses.len(), 1);
    let lapse: serde_json::Value = serde_json::from_str(&lapses[0].value_json).unwrap();
    assert_eq!(lapse["steps"]["held"], "cancelled_by_lapse");

    let replay = step_executable_program_generic(
        &mut kernel,
        &instance,
        &executable,
        None,
        Some(&version.version_id),
    )
    .unwrap();
    assert_eq!(replay.effects_created, 0);
    assert_eq!(kernel.store().list_effects(&instance).unwrap().len(), 2);
    assert!(kernel
        .store()
        .list_diagnostics(Some(&instance))
        .unwrap()
        .is_empty());
}

#[test]
fn typed_region_advances_an_ordered_step_after_its_predecessor_settles() {
    const SOURCE: &str = r#"workflow OrderedRegion
rule finish when started => { during true { then first <- timer 1s
then second <- timer 300s } on lapse { } }
"#;
    let compiled = compile_program(SOURCE);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    let program = compiled.ir.unwrap();
    let plans = compiled.typed_actions.unwrap();
    let identity = crate::program_artifact::typed_identity_projection(&program, &plans).unwrap();
    let stores = whipplescript_store::native_stores::NativeStores {
        runtime: SqliteStore::open_in_memory().unwrap(),
        coord: whipplescript_store::coordination::CoordinationStore::open_in_memory().unwrap(),
        items: whipplescript_store::items::WorkItemStore::open_in_memory().unwrap(),
        frontier: None,
    };
    let mut kernel = RuntimeKernel::new(stores);
    let version = kernel
        .create_program_version_for_typed_program(
            ProgramVersionInput {
                program_name: &program.workflow,
                source_hash: "typed-ordered-region-source",
                ir_hash: &crate::stable_hash_hex(&identity),
                compiler_version: "test",
                ir_snapshot: Some(&identity),
            },
            &program,
            &plans,
        )
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    kernel
        .ingest_external_event(&instance, "external.started", "{}", Some("started"))
        .unwrap();
    let executable = crate::program_artifact::ExecutableProgram {
        program,
        typed_actions: plans,
    };

    let first = step_executable_program_generic(
        &mut kernel,
        &instance,
        &executable,
        None,
        Some(&version.version_id),
    )
    .unwrap();
    assert_eq!(first.effects_created, 1);
    crate::time_pass::resolve_due_time_effects(&mut kernel, &instance, "2099-01-01T00:00:00Z")
        .unwrap();
    let second = step_executable_program_generic(
        &mut kernel,
        &instance,
        &executable,
        None,
        Some(&version.version_id),
    )
    .unwrap();
    assert_eq!(second.effects_created, 1);
    assert_eq!(kernel.store().list_effects(&instance).unwrap().len(), 2);
}

#[test]
fn revised_instance_completes_a_pinned_typed_firing_from_its_captured_plan() {
    const OLD: &str = r#"workflow TypedPinned
output result Answer
class Answer { text string }
action answer() -> Answer { return { text "old" } }
rule finish when started => { timer 1s as delay
after delay succeeds { answer() as answer
complete result answer } }
"#;
    const NEW: &str = r#"workflow TypedPinned
output result Answer
class Answer { text string }
class Never { value string }
rule idle when Never => { complete result { text "new" } }
"#;
    let old = compile_recorded_program_with_root(OLD, None, ExecutionSemantics::TypedActionsV1);
    assert!(old.diagnostics.is_empty(), "{:?}", old.diagnostics);
    let old_program = old.ir.unwrap();
    let old_plans = old.typed_actions.unwrap();
    let old_identity =
        crate::program_artifact::typed_identity_projection(&old_program, &old_plans).unwrap();
    let stores = whipplescript_store::native_stores::NativeStores {
        runtime: SqliteStore::open_in_memory().unwrap(),
        coord: whipplescript_store::coordination::CoordinationStore::open_in_memory().unwrap(),
        items: whipplescript_store::items::WorkItemStore::open_in_memory().unwrap(),
        frontier: None,
    };
    let mut kernel = RuntimeKernel::new(stores);
    let old_version = kernel
        .create_program_version_for_typed_program(
            ProgramVersionInput {
                program_name: &old_program.workflow,
                source_hash: "old-typed-source",
                ir_hash: &crate::stable_hash_hex(&old_identity),
                compiler_version: "test",
                ir_snapshot: Some(&old_identity),
            },
            &old_program,
            &old_plans,
        )
        .unwrap();
    let instance = kernel.create_instance(&old_version, "{}").unwrap();
    kernel
        .ingest_external_event(&instance, "external.started", "{}", Some("started"))
        .unwrap();
    let old_executable = crate::program_artifact::ExecutableProgram {
        program: old_program,
        typed_actions: old_plans,
    };
    let started = step_executable_program_generic(
        &mut kernel,
        &instance,
        &old_executable,
        None,
        Some(&old_version.version_id),
    )
    .unwrap();
    assert_eq!(started.effects_created, 1);

    let new = compile_program(NEW);
    assert!(new.diagnostics.is_empty(), "{:?}", new.diagnostics);
    let new_program = new.ir.unwrap();
    let new_identity =
        whipplescript_parser::snapshot::identity_projection(&new_program.to_snapshot());
    let new_version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &new_program.workflow,
                source_hash: "new-legacy-source",
                ir_hash: &crate::stable_hash_hex(&new_identity),
                compiler_version: "test",
                ir_snapshot: Some(&new_identity),
            },
            &new_program,
        )
        .unwrap();
    kernel
        .store_mut()
        .activate_revision(RevisionActivation {
            instance_id: &instance,
            from_version_id: &old_version.version_id,
            to_version_id: &new_version.version_id,
            activation_policy_json: "{}",
            cancellation_policy: "keep",
            rule_carries_json: "[]",
            rule_correspondence_json: "null",
            idempotency_key: Some("typed-to-legacy"),
        })
        .unwrap();
    crate::time_pass::resolve_due_time_effects(&mut kernel, &instance, "2099-01-01T00:00:00Z")
        .unwrap();
    let completed = step_instance_generic(
        &mut kernel,
        &instance,
        &new_program,
        None,
        Some(&new_version.version_id),
    )
    .unwrap();
    assert_eq!(completed.committed_rules, 1);
    let event = kernel
        .store()
        .list_events(&instance)
        .unwrap()
        .into_iter()
        .find(|event| event.event_type == "workflow.completed")
        .expect("old managed continuation completes");
    let payload: Value = serde_json::from_str(&event.payload_json).unwrap();
    assert_eq!(payload["payload"], serde_json::json!({"text":"old"}));
    assert!(kernel
        .store()
        .list_diagnostics(Some(&instance))
        .unwrap()
        .is_empty());
}

#[test]
fn recorded_semantics_supported_path_still_refuses_invalid_source() {
    let (mut kernel, instance, version) = fixture("{}", "not valid source");
    assert!(load_version_ir(&mut kernel, &instance, &version)
        .unwrap()
        .is_none());
    let diagnostics = kernel.store().list_diagnostics(Some(&instance)).unwrap();
    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0]
        .message
        .contains("stored source no longer compiles"));
}

#[test]
fn executable_program_loader_refuses_damaged_capture_without_recompiling_valid_source() {
    use crate::program_artifact;
    use serde_json::json;
    for (case, detail) in [
        (0, "invalid program artifact reference"),
        (1, "reference format"),
        (2, "missing from the content store"),
        (3, "content hash does not match"),
        (4, "differs from its recorded version"),
        (5, "unsupported recorded execution semantics"),
        (6, "invalid program artifact reference"),
        (7, "executable program:"),
        (8, "unsupported executable program format"),
        (9, "canonical encoding"),
    ] {
        let path = std::env::temp_dir().join(format!(
            "executable-capture-{}-{case}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut kernel = RuntimeKernel::new(SqliteStore::open(&path).unwrap());
        let ir = compile_recorded_program_with_root(
            SOURCE,
            None,
            ExecutionSemantics::LegacyActionChainsV1,
        )
        .ir
        .unwrap();
        let source_hash = kernel.store().put_content(SOURCE).unwrap();
        let identity = whipplescript_parser::snapshot::identity_projection(&ir.to_snapshot());
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: &source_hash,
                    ir_hash: &crate::stable_hash_hex(&identity),
                    ir_snapshot: Some(&identity),
                    compiler_version: "test",
                },
                &ir,
            )
            .unwrap();
        let instance = kernel.create_instance(&version, "{}").unwrap();
        let view = kernel
            .store()
            .get_program_version(&version.version_id)
            .unwrap()
            .unwrap();
        let mut summary: Value = serde_json::from_str(&view.analysis_summary_json).unwrap();
        let content_hash = summary["executable_program"]["content_hash"]
            .as_str()
            .unwrap()
            .to_string();
        let sql = rusqlite::Connection::open(&path).unwrap();
        match case {
            0 => summary["executable_program"] = Value::Null,
            1 => summary["executable_program"]["format"] = json!("future"),
            2 => summary["executable_program"]["content_hash"] = json!("missing"),
            3 => {
                let mut altered = ir.clone();
                altered.rules[0]
                    .metadata
                    .carried_input_roots
                    .insert("forged".into(), ["premise".into()].into());
                assert_eq!(altered.to_snapshot(), ir.to_snapshot());
                let bytes = program_artifact::encode(&altered, &source_hash).unwrap();
                sql.execute(
                    "UPDATE content_blobs SET body = ?1 WHERE id = ?2",
                    rusqlite::params![bytes, content_hash],
                )
                .unwrap();
            }
            4 => {
                let bytes = program_artifact::encode(&ir, "wrong-source").unwrap();
                summary["executable_program"]["content_hash"] =
                    json!(kernel.store().put_content(&bytes).unwrap());
            }
            5 => summary["execution_semantics"] = json!("future"),
            6 => summary["executable_program"]["unknown_authority"] = json!(true),
            7 => {
                summary["executable_program"]["content_hash"] =
                    json!(kernel.store().put_content("{}").unwrap())
            }
            8 => {
                let bytes = kernel
                    .store()
                    .get_content(&content_hash)
                    .unwrap()
                    .unwrap()
                    .replace(program_artifact::FORMAT, "future-format");
                summary["executable_program"]["content_hash"] =
                    json!(kernel.store().put_content(&bytes).unwrap());
            }
            _ => {
                let bytes = kernel.store().get_content(&content_hash).unwrap().unwrap();
                let mut artifact: Value = serde_json::from_str(&bytes).unwrap();
                artifact["program"]["rules"][0]["metadata"]
                    .as_object_mut()
                    .unwrap()
                    .remove("region");
                summary["executable_program"]["content_hash"] =
                    json!(kernel.store().put_content(&artifact.to_string()).unwrap());
            }
        }
        sql.execute(
            "UPDATE program_versions SET analysis_summary = ?1 WHERE version_id = ?2",
            rusqlite::params![summary.to_string(), version.version_id],
        )
        .unwrap();
        drop(sql);
        for _ in 0..2 {
            assert!(
                load_version_ir(&mut kernel, &instance, &version.version_id)
                    .unwrap()
                    .is_none(),
                "case {case} silently recompiled valid source"
            );
        }
        let diagnostics = kernel.store().list_diagnostics(Some(&instance)).unwrap();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code.as_deref(),
            Some("progression.version_unavailable")
        );
        assert!(
            diagnostics[0].message.contains(detail),
            "case {case}: {}",
            diagnostics[0].message
        );
        assert!(kernel.store().list_effects(&instance).unwrap().is_empty());
        drop(kernel);
        std::fs::remove_file(path).unwrap();
    }
}
