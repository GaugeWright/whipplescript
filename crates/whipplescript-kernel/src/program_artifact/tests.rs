use super::*;
use serde_json::{json, Value};
use whipplescript_parser::{
    action_plan::{analysis::analyze_composition, resolved::TypedActionPlan},
    compile_program,
    execution_semantics::compile_recorded_program_with_root,
    parse_program,
};

fn program() -> IrProgram {
    let compiled = compile_recorded_program_with_root(
        super::conformance::SOURCE,
        None,
        ExecutionSemantics::LegacyActionChainsV1,
    );
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    compiled.ir.expect("artifact fixture compiles")
}

const TYPED_SOURCE: &str = r#"workflow TypedCaptured
class Ticket { title string }
action label(ticket Ticket) -> string { return ticket.title }
rule run when Ticket as ticket => { label(ticket) as answer }
"#;

fn typed_program() -> (IrProgram, BTreeMap<String, TypedActionPlan>) {
    let parsed = parse_program(TYPED_SOURCE);
    assert!(parsed.diagnostics.is_empty(), "{:?}", parsed.diagnostics);
    let analysis = analyze_composition(&parsed.program).unwrap();
    let plans = analysis
        .rules()
        .iter()
        .map(|rule| {
            (
                rule.typed
                    .plan
                    .root_rule
                    .as_ref()
                    .expect("rule plan")
                    .name
                    .clone(),
                rule.typed.clone(),
            )
        })
        .collect();
    let compiled =
        compile_recorded_program_with_root(TYPED_SOURCE, None, ExecutionSemantics::TypedActionsV1);
    assert!(
        compiled.diagnostics.is_empty(),
        "{:?}",
        compiled.diagnostics
    );
    assert_eq!(compiled.typed_actions.as_ref(), Some(&plans));
    (compiled.ir.expect("typed static IR"), plans)
}
fn decode_for(bytes: &str, program: &IrProgram) -> Result<IrProgram, String> {
    decode(
        bytes,
        Expected {
            source_hash: "source",
            ir_hash: &whipplescript_parser::snapshot::identity_hash(&program.to_snapshot()),
            workflow: &program.workflow,
            semantics: program.execution_semantics,
        },
    )
    .map(|executable| executable.program)
}
#[test]
fn executable_program_roundtrip_preserves_full_region_and_enforcement_metadata() {
    let mut ir = program();
    assert!(ir.rules[0].metadata.region.is_some());
    // These enforcement fields are deliberately absent from diagnostic IR.
    // Their bytes still belong to the immutable complete program capture.
    let snapshot = ir.to_snapshot();
    ir.rules[0]
        .metadata
        .carried_input_roots
        .insert("retained".into(), ["premise".into()].into());
    ir.rules[0]
        .metadata
        .egress_case_influence
        .insert("result".into(), ["condition".into()].into());
    assert_eq!(ir.to_snapshot(), snapshot);
    let bytes = encode(&ir, "source").unwrap();
    assert_eq!(decode_for(&bytes, &ir).unwrap(), ir);
    assert_ne!(bytes, encode(&program(), "source").unwrap());
    assert_eq!(
        encode(&decode_for(&bytes, &ir).unwrap(), "source").unwrap(),
        bytes
    );
}

#[test]
fn legacy_executable_program_keeps_the_singular_resource_wire_shape() {
    let mut ir = program();
    ir.rules[0].metadata.effects[0].resources = vec!["timer-pool".into()];
    let bytes = encode(&ir, "source").unwrap();
    assert!(bytes.contains("\"resource\":\"timer-pool\""));
    assert!(!bytes.contains("\"resources\":"));
    assert_eq!(decode_for(&bytes, &ir).unwrap(), ir);

    ir.rules[0].metadata.effects[0]
        .resources
        .push("other-pool".into());
    assert_eq!(
        encode(&ir, "source").unwrap_err(),
        "legacy executable program effect cannot carry multiple resources"
    );
}

#[test]
fn typed_executable_roundtrip_pins_every_rule_plan_into_identity() {
    let (program, plans) = typed_program();
    let identity = identity_projection(&program, Some(&plans)).unwrap();
    let hash = whipplescript_parser::snapshot::identity_hash(&identity);
    let bytes = encode_typed(&program, &plans, "typed-source").unwrap();
    let executable = decode(
        &bytes,
        Expected {
            source_hash: "typed-source",
            ir_hash: &hash,
            workflow: "TypedCaptured",
            semantics: ExecutionSemantics::TypedActionsV1,
        },
    )
    .unwrap();
    assert_eq!(executable.program, program);
    assert_eq!(executable.typed_actions, plans);
    assert!(bytes.contains(TYPED_FORMAT));
    assert!(identity.contains("whipplescript-executable-identity/v1"));

    let mut changed = executable.typed_actions.clone();
    changed.get_mut("run").unwrap().plan.nodes[0].span.end += 1;
    assert_ne!(
        typed_identity_projection(&program, &changed).unwrap(),
        identity,
        "checked plan provenance participates in executable identity"
    );
    assert_ne!(
        encode_typed(&program, &changed, "typed-source").unwrap(),
        bytes
    );
}

#[test]
fn compiler_output_identity_has_one_semantics_checked_choice_point() {
    let legacy = program();
    let legacy_identity = identity_projection(&legacy, None).unwrap();
    assert_eq!(
        legacy_identity,
        whipplescript_parser::snapshot::identity_projection(&legacy.to_snapshot())
    );

    let (typed, plans) = typed_program();
    assert_eq!(
        identity_projection(&typed, Some(&plans)).unwrap(),
        typed_identity_projection(&typed, &plans).unwrap()
    );
    assert!(identity_projection(&legacy, Some(&plans))
        .unwrap_err()
        .contains("legacy compiler output cannot carry typed action plans"));
    assert!(identity_projection(&typed, None)
        .unwrap_err()
        .contains("typed compiler output is missing its action plans"));
}

#[test]
fn typed_executable_refuses_incomplete_misowned_and_cross_semantics_plans() {
    let (typed_ir, plans) = typed_program();
    let identity = typed_identity_projection(&typed_ir, &plans).unwrap();
    let hash = whipplescript_parser::snapshot::identity_hash(&identity);
    let bytes = encode_typed(&typed_ir, &plans, "typed-source").unwrap();

    assert!(decode(
        &bytes,
        Expected {
            source_hash: "wrong-source",
            ir_hash: &hash,
            workflow: "TypedCaptured",
            semantics: ExecutionSemantics::TypedActionsV1,
        }
    )
    .unwrap_err()
    .contains("differs from its recorded version"));
    assert!(decode(
        &(bytes.clone() + "\n"),
        Expected {
            source_hash: "typed-source",
            ir_hash: &hash,
            workflow: "TypedCaptured",
            semantics: ExecutionSemantics::TypedActionsV1,
        }
    )
    .unwrap_err()
    .contains("canonical encoding"));

    let mut future: TypedArtifact = serde_json::from_str(&bytes).unwrap();
    future.format = "future".into();
    assert!(decode_typed(
        &serde_json::to_string(&future).unwrap(),
        Expected {
            source_hash: "typed-source",
            ir_hash: &hash,
            workflow: "TypedCaptured",
            semantics: ExecutionSemantics::TypedActionsV1,
        }
    )
    .unwrap_err()
    .contains("unsupported executable program format"));

    let typed_snapshot_hash =
        whipplescript_parser::snapshot::identity_hash(&typed_ir.to_snapshot());
    let typed_in_v1 = serde_json::to_string(&Artifact {
        format: FORMAT.into(),
        source_hash: "typed-source".into(),
        ir_hash: typed_snapshot_hash.clone(),
        program: typed_ir.clone(),
    })
    .unwrap();
    assert!(decode(
        &typed_in_v1,
        Expected {
            source_hash: "typed-source",
            ir_hash: &typed_snapshot_hash,
            workflow: "TypedCaptured",
            semantics: ExecutionSemantics::TypedActionsV1,
        }
    )
    .unwrap_err()
    .contains("format does not match"));

    let mut missing = plans.clone();
    missing.remove("run");
    assert!(encode_typed(&typed_ir, &missing, "typed-source")
        .unwrap_err()
        .contains("exactly one plan"));
    assert!(ExecutableProgram {
        program: typed_ir.clone(),
        typed_actions: missing,
    }
    .validate()
    .unwrap_err()
    .contains("exactly one plan"));

    let mut misowned = plans.clone();
    misowned
        .get_mut("run")
        .unwrap()
        .plan
        .root_rule
        .as_mut()
        .unwrap()
        .name = "other".into();
    assert!(encode_typed(&typed_ir, &misowned, "typed-source")
        .unwrap_err()
        .contains("owning rule"));

    let mut legacy = program();
    assert!(encode_typed(&legacy, &plans, "source")
        .unwrap_err()
        .contains("requires typed action semantics"));
    assert!(ExecutableProgram {
        program: legacy.clone(),
        typed_actions: plans.clone(),
    }
    .validate()
    .unwrap_err()
    .contains("legacy executable program cannot carry typed action plans"));
    legacy.execution_semantics = ExecutionSemantics::TypedActionsV1;
    assert!(encode(&legacy, "source")
        .unwrap_err()
        .contains("cannot carry typed action semantics"));

    let mut value: Value = serde_json::from_str(&bytes).unwrap();
    value["typed_actions"]
        .as_object_mut()
        .unwrap()
        .remove("run");
    assert!(decode(
        &value.to_string(),
        Expected {
            source_hash: "typed-source",
            ir_hash: &hash,
            workflow: "TypedCaptured",
            semantics: ExecutionSemantics::TypedActionsV1,
        }
    )
    .is_err());

    let legacy_bytes = encode(&program(), "source").unwrap();
    let crossed = legacy_bytes.replace(FORMAT, TYPED_FORMAT);
    assert!(decode(
        &crossed,
        Expected {
            source_hash: "source",
            ir_hash: "irrelevant",
            workflow: "Captured",
            semantics: ExecutionSemantics::LegacyActionChainsV1,
        }
    )
    .is_err());
}

#[cfg(feature = "native")]
#[test]
fn typed_executable_capture_requires_composite_identity_and_restores_plans() {
    let (program, plans) = typed_program();
    let identity = typed_identity_projection(&program, &plans).unwrap();
    let hash = crate::stable_hash_hex(&identity);
    let store = whipplescript_store::SqliteStore::open_in_memory().unwrap();
    let input = ProgramVersionInput {
        program_name: &program.workflow,
        source_hash: "typed-source",
        ir_hash: &hash,
        compiler_version: "test",
        ir_snapshot: Some(&identity),
    };
    let summary = capture_typed(&store, &input, &program, &plans).unwrap();
    let summary: Value = serde_json::from_str(&summary).unwrap();
    assert_eq!(summary["execution_semantics"], "dr0100-typed-actions-v1");
    assert_eq!(summary["executable_program"]["format"], TYPED_FORMAT);
    let loaded = load(
        &store,
        summary.get("executable_program"),
        Expected {
            source_hash: "typed-source",
            ir_hash: &hash,
            workflow: &program.workflow,
            semantics: ExecutionSemantics::TypedActionsV1,
        },
    )
    .unwrap();
    let Load::Ready(loaded) = loaded else {
        panic!("typed capture is ready")
    };
    assert_eq!(
        *loaded,
        ExecutableProgram {
            program: program.clone(),
            typed_actions: plans.clone(),
        }
    );

    let without_identity = ProgramVersionInput {
        ir_snapshot: None,
        ..input
    };
    let missing_identity = capture_typed(&store, &without_identity, &program, &plans).unwrap_err();
    let whipplescript_store::StoreError::Conflict(message) = missing_identity else {
        panic!("missing typed identity must be a version conflict")
    };
    assert!(message.contains("requires its verified identity snapshot"));

    let mut changed = plans.clone();
    changed.get_mut("run").unwrap().plan.nodes[0].span.end += 1;
    assert!(capture_typed(&store, &input, &program, &changed).is_err());

    let mut kernel = crate::RuntimeKernel::new(store);
    let version = kernel
        .create_program_version_for_compiled_program(
            crate::CompiledProgramVersionInput {
                program_name: &program.workflow,
                source_hash: "typed-source",
                compiler_version: "test",
            },
            &program,
            Some(&plans),
        )
        .unwrap();
    let stored = kernel
        .store()
        .get_program_version(&version.version_id)
        .unwrap()
        .unwrap();
    assert_eq!(stored.ir_hash, crate::stable_hash_hex(&identity));
    assert_eq!(
        kernel
            .store()
            .get_content(&stored.ir_hash)
            .unwrap()
            .as_deref(),
        Some(identity.as_str())
    );
    let stored_summary: Value = serde_json::from_str(&stored.analysis_summary_json).unwrap();
    assert_eq!(stored_summary["executable_program"]["format"], TYPED_FORMAT);
}
#[test]
fn executable_program_roundtrip_covers_the_compiling_example_corpus() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let mut pending = vec![root];
    let mut checked = 0;
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                pending.push(entry.path());
            } else if entry.path().extension().is_some_and(|e| e == "whip") {
                let source = std::fs::read_to_string(entry.path()).unwrap();
                let compiled = compile_program(&source);
                if let Some(ir) = compiled.ir {
                    if let Some(plans) = compiled.typed_actions {
                        let identity = identity_projection(&ir, Some(&plans)).unwrap();
                        let hash = whipplescript_parser::snapshot::identity_hash(&identity);
                        let bytes = encode_typed(&ir, &plans, "source")
                            .unwrap_or_else(|e| panic!("{}: {e}", entry.path().display()));
                        let executable = decode(
                            &bytes,
                            Expected {
                                source_hash: "source",
                                ir_hash: &hash,
                                workflow: &ir.workflow,
                                semantics: ir.execution_semantics,
                            },
                        )
                        .unwrap();
                        assert_eq!(executable.program, ir, "{}", entry.path().display());
                        assert_eq!(
                            executable.typed_actions,
                            plans,
                            "{}",
                            entry.path().display()
                        );
                    } else {
                        let bytes = encode(&ir, "source")
                            .unwrap_or_else(|e| panic!("{}: {e}", entry.path().display()));
                        assert_eq!(
                            decode_for(&bytes, &ir).unwrap(),
                            ir,
                            "{}",
                            entry.path().display()
                        );
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked >= 25, "only {checked} examples exercised the codec");
}
#[test]
fn executable_program_refuses_format_identity_missing_fields_and_noncanonical_bytes() {
    let ir = program();
    let bytes = encode(&ir, "source").unwrap();
    let mut a: Artifact = serde_json::from_str(&bytes).unwrap();
    a.format = "future".into();
    assert!(decode_for(&encode_legacy_artifact(&a).unwrap(), &ir)
        .unwrap_err()
        .contains("unsupported"));
    for which in 0..4 {
        let mut a: Artifact = serde_json::from_str(&bytes).unwrap();
        match which {
            0 => a.source_hash = "other".into(),
            1 => a.ir_hash = "other".into(),
            2 => a.program.workflow = "Other".into(),
            _ => a.program.rules[0].body.push_str(" changed"),
        }
        assert!(decode_for(&encode_legacy_artifact(&a).unwrap(), &ir)
            .unwrap_err()
            .contains("differs from its recorded version"));
    }
    assert!(decode_for(&(bytes.clone() + "\n"), &ir)
        .unwrap_err()
        .contains("canonical"));
    let mut value: Value = serde_json::from_str(&bytes).unwrap();
    value["program"]["rules"][0]["metadata"]
        .as_object_mut()
        .unwrap()
        .remove("region");
    assert!(
        decode_for(&value.to_string(), &ir).is_err(),
        "an omitted optional execution field is not a default"
    );
    let mut value: Value = serde_json::from_str(&bytes).unwrap();
    value["program"]["rules"][0]["metadata"]["future_authority"] = json!(true);
    assert!(decode_for(&value.to_string(), &ir)
        .unwrap_err()
        .contains("unknown field"));
    assert!(decode_for(&bytes.replace("dr0023-action-chains-v1", "future-v99"), &ir).is_err());
}
#[cfg(feature = "native")]
#[test]
fn executable_program_capture_requires_the_supplied_identity_and_preserves_absence() {
    let ir = program();
    let store = whipplescript_store::SqliteStore::open_in_memory().unwrap();
    let identity = whipplescript_parser::snapshot::identity_projection(&ir.to_snapshot());
    let hash = crate::stable_hash_hex(&identity);
    let mut input = ProgramVersionInput {
        program_name: &ir.workflow,
        source_hash: "source",
        ir_hash: &hash,
        compiler_version: "test",
        ir_snapshot: None,
    };
    assert_eq!(
        capture(&store, &input, &ir).unwrap(),
        crate::program_analysis_summary_json(&ir)
    );
    for which in 0..3 {
        input.program_name = if which == 0 { "Other" } else { &ir.workflow };
        input.ir_hash = if which == 1 { "wrong" } else { &hash };
        input.ir_snapshot = Some(if which == 2 { "wrong" } else { &identity });
        assert!(capture(&store, &input, &ir).is_err());
    }
}
#[cfg(feature = "native")]
#[test]
fn executable_program_native_revised_progression_uses_complete_capture() {
    let store = whipplescript_store::native_stores::NativeStores {
        runtime: whipplescript_store::SqliteStore::open_in_memory().unwrap(),
        coord: whipplescript_store::coordination::CoordinationStore::open_in_memory().unwrap(),
        items: whipplescript_store::items::WorkItemStore::open_in_memory().unwrap(),
        frontier: None,
    };
    super::conformance::revised_progression_uses_capture(store);
}

/// A captured artifact decodes into a runnable program with no source and no
/// compiler — the property the capture exists for.
///
/// The fixture is not a compatibility sample from an older writer, and cannot
/// be: `decode_legacy` requires the bytes to be their own canonical encoding,
/// which refuses a field that arrived by `serde(default)` exactly as it refuses
/// one serde discarded. So adding a field to `IrRuleMetadata` invalidates every
/// artifact already captured, and this fixture with them — regenerate it by
/// re-encoding, and know that stored captures of the old shape stop decoding
/// too (a legacy one falls back to recompiling from its source; a typed one has
/// no fallback).
#[test]
fn executable_program_frozen_v1_artifact_remains_readable_without_source_compilation() {
    let bytes = include_str!("fixtures/executable-program-v1.json");
    let executable = decode(
        bytes,
        Expected {
            source_hash: "source",
            ir_hash: "99383468ab76f690851fcf3aec39bcd5",
            workflow: "Captured",
            semantics: ExecutionSemantics::LegacyActionChainsV1,
        },
    )
    .unwrap();
    let program = executable.program;
    assert!(executable.typed_actions.is_empty());
    assert_eq!(
        program.rules[0]
            .metadata
            .region
            .as_ref()
            .unwrap()
            .body_lapsed,
        "complete result { note \"old lapsed\" } "
    );
    assert_eq!(program.rules[0].metadata.effects.len(), 1);
    assert_eq!(encode(&program, "source").unwrap(), bytes);
}

#[cfg(feature = "native")]
#[test]
fn executable_program_reopens_native_store_before_old_progression_completes() {
    use whipplescript_store::{native_stores::NativeStores, SqliteStore};
    let path = std::env::temp_dir().join(format!(
        "executable-reopen-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let open = || NativeStores {
        runtime: SqliteStore::open(&path).unwrap(),
        coord: whipplescript_store::coordination::CoordinationStore::open_in_memory().unwrap(),
        items: whipplescript_store::items::WorkItemStore::open_in_memory().unwrap(),
        frontier: None,
    };
    super::conformance::revised_progression_with_reopen(open(), |store| {
        drop(store);
        open()
    });
    std::fs::remove_file(path).unwrap();
}

#[cfg(feature = "native")]
#[test]
fn executable_program_capture_does_not_rewrite_an_existing_uncaptured_version() {
    let ir = program();
    let identity = whipplescript_parser::snapshot::identity_projection(&ir.to_snapshot());
    let hash = crate::stable_hash_hex(&identity);
    let mut kernel =
        crate::RuntimeKernel::new(whipplescript_store::SqliteStore::open_in_memory().unwrap());
    let mut input = ProgramVersionInput {
        program_name: &ir.workflow,
        source_hash: "source",
        ir_hash: &hash,
        compiler_version: "test",
        ir_snapshot: None,
    };
    let old = kernel
        .create_program_version_for_program(input, &ir)
        .unwrap();
    let before = kernel
        .store()
        .get_program_version(&old.version_id)
        .unwrap()
        .unwrap()
        .analysis_summary_json;
    input.ir_snapshot = Some(&identity);
    let repeated = kernel
        .create_program_version_for_program(input, &ir)
        .unwrap();
    assert_eq!(old.version_id, repeated.version_id);
    let after = kernel
        .store()
        .get_program_version(&old.version_id)
        .unwrap()
        .unwrap()
        .analysis_summary_json;
    assert_eq!(before, after);
    assert!(serde_json::from_str::<Value>(&after)
        .unwrap()
        .get("executable_program")
        .is_none());
}
