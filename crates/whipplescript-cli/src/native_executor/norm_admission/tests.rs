use super::*;
use std::collections::BTreeMap;
use whipplescript_core::norm_evidence::{
    EvidenceSubject, EvidenceVersion, ReportContract, RequiredCase,
};
use whipplescript_kernel::{
    norm_execution::NormDispatchBinding,
    norm_runner::{candidate_identity, PreparedNormRun, PythonCase, PythonEngine, PythonRuntime},
    ProgramVersionInput,
};
use whipplescript_store::{
    CapabilityBinding, CapabilitySchemaRegistration, NewEffect, RuleCommit,
    ScriptCapabilityRegistration,
};

#[test]
fn native_norm_admission_lease_is_bounded_and_never_renewed_by_replay() {
    let (mut kernel, instance, effect, _) =
        fixture_with_store("exact", SqliteStore::open_in_memory().unwrap());
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    let method: PythonCallMethod =
        serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap()).unwrap();
    let installed = binding(method.runtime);
    let before = kernel.store().list_events(&instance).unwrap().len();
    for now in [
        "now",
        "2030-01-01T00:00:00.001Z",
        "2030-01-01T01:00:00+01:00",
        "9999-12-31T23:59:59Z",
    ] {
        assert!(
            NativeNormAdmission::admit_at(&mut kernel, &instance, &effect, &installed, now)
                .is_err(),
            "{now}"
        );
        assert_eq!(kernel.store().list_events(&instance).unwrap().len(), before);
    }
    let admitted = NativeNormAdmission::admit_at(
        &mut kernel,
        &instance,
        &effect,
        &installed,
        "2030-01-01T00:00:00Z",
    )
    .unwrap();
    let count = kernel.store().list_events(&instance).unwrap().len();
    NativeNormAdmission::admit_at(
        &mut kernel,
        &instance,
        &effect,
        &installed,
        "2030-01-01T00:05:00Z",
    )
    .unwrap();
    assert_eq!(kernel.store().list_events(&instance).unwrap().len(), count);
    assert!(kernel
        .expire_leases(&instance, "2030-01-01T00:09:59Z")
        .unwrap()
        .is_empty());
    assert_eq!(
        kernel
            .expire_leases(&instance, "2030-01-01T00:10:00Z")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        kernel.store().list_runs(&instance).unwrap()[0].status,
        "running"
    );
    assert!(exec_lifetime::fences(kernel.store(), &instance)
        .unwrap()
        .contains_key(&admitted.handoff.run_id()));
    let replay = NativeNormAdmission::admit_at(
        &mut kernel,
        &instance,
        &effect,
        &installed,
        "2030-01-01T00:11:00Z",
    )
    .unwrap();
    assert!(replay.candidate.is_none());
}

#[test]
fn native_norm_admission_retains_original_binding_and_fence() {
    let (mut kernel, instance, effect, _) =
        fixture_with_store("exact", SqliteStore::open_in_memory().unwrap());
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    let method: PythonCallMethod =
        serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap()).unwrap();
    let installed = binding(method.runtime);
    let first = NativeNormAdmission::admit(&mut kernel, &instance, &effect, &installed).unwrap();
    let run = first.handoff.run_id();
    let candidate = first.candidate.unwrap();
    assert_eq!(candidate.daemon_id, installed.daemon_id);
    assert_eq!(candidate.image_id, installed.image_id);
    assert!(exec_lifetime::tracked(kernel.store(), &instance)
        .unwrap()
        .contains_key(&run));
    let events = kernel.store().list_events(&instance).unwrap().len();
    let mut changed = installed.clone();
    changed.daemon_id = "new-daemon".into();
    changed.image_id = format!("sha256:{}", "d".repeat(64));
    changed.runtime.environment = "new-epoch".into();
    kernel
        .store()
        .register_script_capability(ScriptCapabilityRegistration {
            name: "observer",
            argv_json: r#"["foreign","{script}"]"#,
            sha256: "different",
            body: "different",
            env_json: "{}",
            hermetic: false,
        })
        .unwrap();
    let replay = NativeNormAdmission::admit(&mut kernel, &instance, &effect, &changed).unwrap();
    assert_eq!(replay.binding, installed);
    assert_eq!(replay.candidate, Some(candidate));
    assert_eq!(replay.handoff.command(), first.handoff.command());
    assert_eq!(kernel.store().list_events(&instance).unwrap().len(), events);
    kernel
        .store_mut()
        .ensure_exec_fence(Fence {
            instance_id: &instance,
            run_id: &run,
            reason: FenceReason::Recovery,
        })
        .unwrap();
    let fenced = NativeNormAdmission::admit(&mut kernel, &instance, &effect, &changed).unwrap();
    assert!(fenced.candidate.is_none());
}

#[test]
fn native_norm_admission_refuses_before_run_and_never_upgrades_legacy() {
    for case in [
        "mode",
        "missing-pin",
        "body",
        "adapter",
        "env",
        "cache",
        "parse",
        "permission",
        "registration",
        "stale-input",
        "runtime",
        "protocol",
        "image",
        "daemon",
        "legacy",
    ] {
        let (mut kernel, instance, mut effect, _) =
            fixture_with_store(case, SqliteStore::open_in_memory().unwrap());
        let input: Value = serde_json::from_str(&effect.input_json).unwrap();
        let method: PythonCallMethod =
            serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap())
                .unwrap();
        let mut installed = binding(method.runtime);
        match case {
            "stale-input" => {
                let mut changed = input.clone();
                changed["norm_intent"] = json!({"different":"intent"});
                effect.input_json = changed.to_string();
            }
            "runtime" => installed.runtime.executable = "/opt/another".into(),
            "protocol" => installed.protocol = "unknown".into(),
            "image" => installed.image_id = "mutable:latest".into(),
            "daemon" => installed.daemon_id = "".into(),
            "legacy" => {
                let run = Invocation {
                    instance_id: instance.clone(),
                    effect_id: effect.effect_id.clone(),
                    attempt_admission_event_id: None,
                }
                .run_id();
                kernel
                    .start_run(RunStart {
                        instance_id: &instance,
                        effect_id: &effect.effect_id,
                        run_id: &run,
                        provider: "exec",
                        worker_id: "whip-exec",
                        lease_id: "legacy",
                        lease_expires_at: "2030-01-01T00:00:00Z",
                        metadata_json: "{}",
                    })
                    .unwrap();
            }
            _ => {}
        }
        let before = kernel.store().list_events(&instance).unwrap().len();
        assert!(
            NativeNormAdmission::admit(&mut kernel, &instance, &effect, &installed).is_err(),
            "{case}"
        );
        if case == "permission" {
            assert!(kernel.store().list_runs(&instance).unwrap().is_empty());
        } else {
            assert_eq!(
                kernel.store().list_events(&instance).unwrap().len(),
                before,
                "{case}"
            );
        }
        assert!(
            exec_lifetime::tracked(kernel.store(), &instance)
                .unwrap()
                .is_empty(),
            "{case}"
        );
    }
}

pub(crate) fn binding(runtime: PythonRuntime) -> NativeRuntimeImage {
    NativeRuntimeImage {
        protocol: "whipplescript.exec.native-runtime-image/v1".into(),
        daemon_id: "original-daemon".into(),
        base_image: format!("sha256:{}", "b".repeat(64)),
        image_id: format!("sha256:{}", "c".repeat(64)),
        runtime,
    }
}

#[test]
fn native_norm_admission_recovers_between_run_and_tracking() {
    let path = std::env::temp_dir().join(format!(
        "native-norm-admission-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let (mut kernel, instance, effect, _) =
        fixture_with_store("exact", SqliteStore::open(&path).unwrap());
    let input: Value = serde_json::from_str(&effect.input_json).unwrap();
    let method: PythonCallMethod =
        serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap()).unwrap();
    let installed = binding(method.runtime);
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TRIGGER stop_tracking BEFORE INSERT ON events WHEN NEW.event_type='exec.lifetime.tracked' BEGIN SELECT RAISE(ABORT,'tracking fault'); END;").unwrap();
    assert!(NativeNormAdmission::admit(&mut kernel, &instance, &effect, &installed).is_err());
    assert_eq!(kernel.store().list_runs(&instance).unwrap().len(), 1);
    assert!(exec_lifetime::tracked(kernel.store(), &instance)
        .unwrap()
        .is_empty());
    assert!(!kernel
        .store()
        .list_events(&instance)
        .unwrap()
        .iter()
        .any(|e| e.event_type == whipplescript_store::exec_native_owner::OWNER_EVENT));
    drop(kernel);
    connection
        .execute_batch("DROP TRIGGER stop_tracking")
        .unwrap();
    connection.execute_batch("UPDATE runs SET metadata_json=json_set(metadata_json,'$.executor_transport','in-process')").unwrap();
    let mut legacy = RuntimeKernel::new(SqliteStore::open(&path).unwrap());
    let run = legacy.store().list_runs(&instance).unwrap()[0]
        .run_id
        .clone();
    assert!(NativeNormAdmission::restore_tracking(&mut legacy, &instance, &run).is_err());
    assert!(NativeNormAdmission::admit(&mut legacy, &instance, &effect, &installed).is_err());
    assert!(exec_lifetime::tracked(legacy.store(), &instance)
        .unwrap()
        .is_empty());
    drop(legacy);
    connection.execute_batch("UPDATE runs SET metadata_json=json_set(metadata_json,'$.executor_transport','native-managed')").unwrap();
    let (event_id, original): (String, String) = connection
        .query_row(
            "SELECT event_id,payload_json FROM events WHERE idempotency_key=?1 AND instance_id=?2",
            rusqlite::params![&run, &instance],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let original: Value = serde_json::from_str(&original).unwrap();
    let mut validating = RuntimeKernel::new(SqliteStore::open(&path).unwrap());
    let count = validating.store().list_events(&instance).unwrap().len();
    for fault in ["source", "legacy", "mode", "runtime", "provider", "pin"] {
        let mut changed = original.clone();
        let mut changed_input: Value = serde_json::from_str(&effect.input_json).unwrap();
        match fault {
            "legacy" => changed["metadata"]["executor_transport"] = "in-process".into(),
            "mode" => changed_input["mode"] = "raw".into(),
            "runtime" => {
                changed["metadata"]["native_runtime"]["runtime"]["executable"] =
                    "/opt/changed/observer".into()
            }
            "provider" => {
                changed["metadata"]["executor_url"] = "https://foreign.invalid/exec".into();
                changed["metadata"]["executor_dispatch"]["request_sha256"] = sha256_hex(
                    json!([
                        changed["metadata"]["executor_url"],
                        changed["metadata"]["executor_invocation"]["dispatch"]
                    ])
                    .to_string()
                    .as_bytes(),
                )
                .into();
            }
            "pin" => changed_input["norm_dispatch"]["environment_epoch"] = "foreign".into(),
            _ => {}
        }
        changed["metadata"]["executor_dispatch"]["input_sha256"] =
            sha256_hex(changed_input.to_string().as_bytes()).into();
        connection
            .execute(
                "UPDATE events SET source=?1,payload_json=?2 WHERE event_id=?3",
                rusqlite::params![
                    if fault == "source" {
                        "foreign"
                    } else {
                        "kernel"
                    },
                    changed.to_string(),
                    &event_id
                ],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE runs SET metadata_json=?1 WHERE run_id=?2",
                rusqlite::params![changed["metadata"].to_string(), &run],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE effects SET input_json=?1 WHERE effect_id=?2 AND instance_id=?3",
                rusqlite::params![changed_input.to_string(), &effect.effect_id, &instance],
            )
            .unwrap();
        assert!(
            NativeNormAdmission::restore_tracking(&mut validating, &instance, &run).is_err(),
            "{fault}"
        );
        assert_eq!(
            validating.store().list_events(&instance).unwrap().len(),
            count,
            "{fault}"
        );
        assert!(
            exec_lifetime::tracked(validating.store(), &instance)
                .unwrap()
                .is_empty(),
            "{fault}"
        );
        connection
            .execute(
                "UPDATE events SET source='kernel',payload_json=?1 WHERE event_id=?2",
                rusqlite::params![original.to_string(), &event_id],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE runs SET metadata_json=?1 WHERE run_id=?2",
                rusqlite::params![original["metadata"].to_string(), &run],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE effects SET input_json=?1 WHERE effect_id=?2 AND instance_id=?3",
                rusqlite::params![&effect.input_json, &effect.effect_id, &instance],
            )
            .unwrap();
    }
    drop(validating);
    drop(connection);
    let mut cold = RuntimeKernel::new(SqliteStore::open(&path).unwrap());
    NativeNormAdmission::restore_tracking(&mut cold, &instance, &run).unwrap();
    assert!(exec_lifetime::tracked(cold.store(), &instance)
        .unwrap()
        .contains_key(&run));
    assert!(!cold
        .store()
        .list_events(&instance)
        .unwrap()
        .iter()
        .any(|e| e.event_type == whipplescript_store::exec_native_owner::OWNER_EVENT));
    let count = cold.store().list_events(&instance).unwrap().len();
    NativeNormAdmission::restore_tracking(&mut cold, &instance, &run).unwrap();
    assert_eq!(cold.store().list_events(&instance).unwrap().len(), count);
    let mut replacement = installed.clone();
    replacement.daemon_id = "replacement-daemon".into();
    let recovered =
        NativeNormAdmission::admit(&mut cold, &instance, &effect, &replacement).unwrap();
    assert_eq!(recovered.binding, installed);
    assert_eq!(recovered.candidate.unwrap().daemon_id, installed.daemon_id);
    assert_eq!(cold.store().list_runs(&instance).unwrap().len(), 1);
    drop(cold);
    std::fs::remove_file(path).unwrap();
}
pub(crate) fn fixture_with_runtime(
    case: &str,
    store: SqliteStore,
    runtime_override: Option<PythonRuntime>,
) -> (
    RuntimeKernel<SqliteStore>,
    String,
    ClaimableEffect,
    PreparedNormRun,
) {
    let epoch = runtime_override
        .as_ref()
        .map(|r| r.environment.clone())
        .unwrap_or_else(|| "native-test".into());
    let python = "/opt/norm/observer";
    let mut method = PythonCallMethod {
        runtime: PythonRuntime {
            engine: PythonEngine::Cpython3147Wasi {
                artifact_path: "/opt/norm/runtime.wasm".into(),
                artifact_sha256: "a".repeat(64),
            },
            executable: python.into(),
            python_version: "3.14.7".into(),
            environment: epoch.clone(),
        },
        module: "candidate".into(),
        function: "check".into(),
        cases: vec![PythonCase {
            id: "deny".into(),
            args: vec![],
            kwargs: BTreeMap::new(),
        }],
    };
    if let Some(runtime) = runtime_override {
        method.runtime = runtime;
    }
    let python = method.runtime.executable.as_str();
    let files = BTreeMap::from([(
        "candidate.py".into(),
        if case == "counter" {
            "def check(): return True"
        } else if matches!(case, "retry" | "worker-retry") {
            "def check():\n import os\n os._exit(7)\n"
        } else {
            "def check(): return False"
        }
        .into(),
    )]);
    let contract = ReportContract {
        subject: EvidenceSubject {
            requirement: EvidenceVersion {
                name: "deny".into(),
                version: "1".into(),
                digest: "fixture".into(),
            },
            method: method.reference(),
            artifact: candidate_identity(&files),
        },
        cases: vec![RequiredCase {
            id: "deny".into(),
            assertion: "deny".into(),
            expected: json!(false),
        }],
    };
    let prepared =
        PreparedNormRun::prepare(contract, method.clone(), files, "observe".into()).unwrap();
    let request = prepared.executor_request("whip-executor://native").unwrap();
    let registered_body = if case == "adapter" {
        "changed"
    } else {
        method.adapter()
    };
    let registered_digest = sha256_hex(registered_body.as_bytes());
    // A self-consistent supplied pin cannot authorize another adapter.
    let binding_request = build_executor_exec_request(
        "whip-executor://native",
        "observe",
        &registered_digest,
        registered_body,
        &[
            python.into(),
            "executor".into(),
            "observe-norm".into(),
            "{script}".into(),
        ],
        &[],
        &request.body["stdin"],
        Some(30_000),
    )
    .unwrap();
    let mut input = json!({"mode":"capability", "capability":"observer", "stdin":request.body["stdin"], "norm_intent":{"fixture":true}, "norm_dispatch":NormDispatchBinding::for_request(&binding_request, &epoch)});
    match case {
        "missing-pin" => {
            input.as_object_mut().unwrap().remove("norm_dispatch");
        }
        "body" => input["stdin"]["files"]["candidate.py"] = json!("def check(): return True"),
        "parse" => input["parse"] = Value::Null,
        "mode" => input["mode"] = json!("raw"),
        _ => {}
    }
    let mut kernel = RuntimeKernel::new(store);
    let version = kernel
        .create_program_version(ProgramVersionInput {
            program_name: "NativeNorm",
            source_hash: "source",
            ir_hash: "ir",
            compiler_version: "fixture",
            ir_snapshot: None,
        })
        .unwrap();
    let instance = kernel.create_instance(&version, "{}").unwrap();
    kernel
        .store()
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "script.observer",
            description: "observer",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    if case != "permission" {
        kernel
            .store()
            .bind_capability(CapabilityBinding {
                binding_id: "observer",
                program_id: Some(&version.program_id),
                capability: "script.observer",
                provider: "builtin-script",
                config_json: "{}",
            })
            .unwrap();
    }
    if case != "registration" {
        kernel
            .store()
            .register_script_capability(ScriptCapabilityRegistration {
                name: "observer",
                argv_json: &json!([python, "executor", "observe-norm", "{script}"]).to_string(),
                sha256: &registered_digest,
                body: registered_body,
                env_json: if case == "env" {
                    r#"{"PATH":"env:PATH"}"#
                } else {
                    "{}"
                },
                hermetic: case == "cache",
            })
            .unwrap();
    }
    let input_json = input.to_string();
    kernel
        .store_mut()
        .commit_rule(RuleCommit {
            instance_id: &instance,
            rule: "observe",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[NewEffect {
                effect_id: "observe",
                kind: "exec.command",
                target: None,
                input_json: &input_json,
                status: "queued",
                idempotency_key: "observe",
                required_capabilities_json: r#"["script.observer"]"#,
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            }],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("observe"),
            marks: &[],
            context_json: None,
        })
        .unwrap();
    (
        kernel,
        instance,
        ClaimableEffect {
            attempt_admission_event_id: None,
            effect_id: "observe".into(),
            kind: "exec.command".into(),
            target: None,
            profile: None,
            input_json,
            required_capabilities_json: r#"["script.observer"]"#.into(),
            declared_profiles_json: "[]".into(),
        },
        prepared,
    )
}

pub(crate) fn fixture_with_store(
    case: &str,
    store: SqliteStore,
) -> (
    RuntimeKernel<SqliteStore>,
    String,
    ClaimableEffect,
    PreparedNormRun,
) {
    fixture_with_runtime(case, store, None)
}

#[test]
fn native_norm_admission_refuses_legacy_already_requeued_by_old_expiry() {
    for tracked in [false, true] {
        let path = std::env::temp_dir().join(format!(
            "native-norm-old-expiry-{}-{tracked}.sqlite",
            std::process::id()
        ));
        let (mut kernel, instance, effect, _) =
            fixture_with_store("exact", SqliteStore::open(&path).unwrap());
        let input: Value = serde_json::from_str(&effect.input_json).unwrap();
        let method: PythonCallMethod =
            serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap())
                .unwrap();
        let installed = binding(method.runtime);
        let run = Invocation {
            instance_id: instance.clone(),
            effect_id: effect.effect_id.clone(),
            attempt_admission_event_id: None,
        }
        .run_id();
        if tracked {
            NativeNormAdmission::admit_at(
                &mut kernel,
                &instance,
                &effect,
                &installed,
                "2000-01-01T00:00:00Z",
            )
            .unwrap();
        } else {
            kernel
                .start_run(RunStart {
                    instance_id: &instance,
                    effect_id: &effect.effect_id,
                    run_id: &run,
                    provider: "exec",
                    worker_id: "whip-exec",
                    lease_id: "legacy",
                    lease_expires_at: "2000-01-01T00:00:00Z",
                    metadata_json: "{}",
                })
                .unwrap();
        }
        kernel
            .store()
            .append_event(whipplescript_store::NewEvent {
                instance_id: &instance,
                event_type: "lease.expired",
                payload_json:
                    &json!({"effect_id":effect.effect_id,"run_id":run,"lease_id":"legacy"})
                        .to_string(),
                source: "kernel",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("legacy-expiry"),
            })
            .unwrap();
        // Old versions persisted this projection before executor expiry became a
        // distinct event. Opening that database does not replay all projections.
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("UPDATE runs SET status='lease_expired'; UPDATE effects SET status='queued'; UPDATE leases SET status='expired';").unwrap();
        drop(connection);
        drop(kernel);
        let mut kernel = RuntimeKernel::new(SqliteStore::open(&path).unwrap());
        let selected = kernel
            .store()
            .claimable_effects(&instance)
            .unwrap()
            .pop()
            .unwrap();
        assert!(selected.attempt_admission_event_id.is_some());
        let before = kernel.store().list_events(&instance).unwrap().len();
        assert!(NativeNormAdmission::admit(&mut kernel, &instance, &selected, &installed).is_err());
        assert_eq!(kernel.store().list_runs(&instance).unwrap().len(), 1);
        assert_eq!(kernel.store().list_events(&instance).unwrap().len(), before);
        assert_eq!(
            exec_lifetime::tracked(kernel.store(), &instance)
                .unwrap()
                .len(),
            usize::from(tracked)
        );
        drop(kernel);
        std::fs::remove_file(path).unwrap();
    }
}
