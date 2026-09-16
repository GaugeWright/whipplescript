//! Native norm execution through the same bounded handler as the sidecar.
//! Local protocol framing is retained as in-process evidence, never HTTP origin.
use super::*;
use whipplescript_kernel::exec_http::{
    build_executor_exec_request, parse_executor_response_for_effect, settle_exec_http_result,
    ExecDispatchPlan, ExecSettleContext, ExecSettleOutcome,
};
use whipplescript_kernel::norm_execution::validate_norm_dispatch;
use whipplescript_kernel::norm_runner::{PythonCallMethod, PythonEngine};
use whipplescript_kernel::sansio::HttpResponse;

fn validate_observer_command(
    argv: &[String],
    engine: &PythonEngine,
    current_executable: &Path,
) -> Result<(), StoreError> {
    // A protected profile must name this executable even when its basename is
    // not `whip`; a differently named binary is not an equivalent observer.
    if matches!(engine, PythonEngine::Cpython3147Wasi { .. })
        || script_argv_denied_executable(argv).is_some()
    {
        let current = fs::canonicalize(current_executable)?;
        let selected = argv.first().map(fs::canonicalize).transpose()?;
        let protected = matches!(engine, PythonEngine::Cpython3147Wasi { .. })
            && argv.len() == 4
            && argv[1] == "executor"
            && argv[2] == "observe-norm"
            && argv[3] == "{script}"
            && selected.as_ref() == Some(&current);
        if !protected {
            return Err(StoreError::Conflict(
                "native norm cannot invoke another control-plane command".into(),
            ));
        }
    }
    Ok(())
}

pub(super) fn execute(
    kernel: &mut RuntimeKernel<SqliteStore>,
    instance_id: &str,
    effect: &ClaimableEffect,
    environment_epoch: &str,
) -> Result<whipplescript_store::StoredEvent, StoreError> {
    let input: Value = serde_json::from_str(&effect.input_json)?;
    if input["mode"] != "capability" {
        return Err(StoreError::Conflict(
            "native norm execution requires capability mode".into(),
        ));
    }
    if norm_exec_managed::protected(&input)? {
        return Err(StoreError::Conflict(
            "protected norm execution requires the managed native worker".into(),
        ));
    }
    let capability = input["capability"].as_str().unwrap_or_default();
    let script = kernel.store().get_script_capability(capability)?;
    if script.is_none() {
        return Err(StoreError::Conflict(
            "native norm observer is not registered".into(),
        ));
    }
    let script = script.expect("registration presence was checked");
    let method: PythonCallMethod = serde_json::from_str(
        input["stdin"]["method_definition_json"]
            .as_str()
            .unwrap_or_default(),
    )?;
    let argv: Vec<String> = serde_json::from_str(&script.argv_json)?;
    let expected_argv = match method.runtime.engine {
        PythonEngine::Cpython {} => vec![
            method.runtime.executable.clone(),
            "-I".into(),
            "{script}".into(),
        ],
        PythonEngine::Cpython3147Wasi { .. } => vec![
            method.runtime.executable.clone(),
            "executor".into(),
            "observe-norm".into(),
            "{script}".into(),
        ],
    };
    let registration_matches = script.body == method.adapter()
        && script.sha256 == sha256_hex(script.body.as_bytes())
        && argv == expected_argv;
    if !registration_matches {
        return Err(StoreError::Conflict(
            "native norm registration differs from its declared observer".into(),
        ));
    }
    validate_observer_command(&argv, &method.runtime.engine, &env::current_exe()?)?;
    let declared_env: BTreeMap<String, String> = serde_json::from_str(&script.env_json)?;
    if !declared_env.is_empty() {
        return Err(StoreError::Conflict(
            "native norm observer requires an empty declared environment".into(),
        ));
    }
    let request = build_executor_exec_request(
        "whip-executor://native",
        &effect.effect_id,
        &script.sha256,
        &script.body,
        &argv,
        &[],
        &input["stdin"],
        Some(30_000),
    )
    .map_err(StoreError::Conflict)?;
    let plan = ExecDispatchPlan::prepare(
        capability,
        &script.sha256,
        &input,
        &request,
        environment_epoch,
        script.hermetic.then(|| "norm-cache-forbidden".into()),
        input.get("parse").cloned(),
    );
    validate_norm_dispatch(&input, &plan).map_err(StoreError::Conflict)?;
    let run_id = whipplescript_kernel::execution_attempt_key(
        instance_id,
        &effect.effect_id,
        effect.attempt_admission_event_id.as_deref(),
        "exec-run",
    );
    let lease_id = whipplescript_kernel::execution_attempt_key(
        instance_id,
        &effect.effect_id,
        effect.attempt_admission_event_id.as_deref(),
        "exec-lease",
    );
    if kernel
        .store()
        .list_runs(instance_id)?
        .iter()
        .any(|run| run.run_id == run_id)
    {
        let original = ExecDispatchPlan::load(
            kernel.store(),
            instance_id,
            &effect.effect_id,
            &run_id,
            &input,
        )?;
        if original != plan {
            return Err(StoreError::Conflict(
                "native norm redispatch differs from its original plan".into(),
            ));
        }
    }
    kernel.start_run_for_admission(
        RunStart {
            instance_id,
            effect_id: &effect.effect_id,
            run_id: &run_id,
            provider: "exec",
            worker_id: "whip-exec",
            lease_id: &lease_id,
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: &json!({"mode":"capability", "capability":capability,
            "executor_dispatch":plan, "executor_transport":"in-process"})
            .to_string(),
        },
        effect.attempt_admission_event_id.as_deref(),
    )?;
    // No network request is made. These status codes frame the real local
    // handler result in the same executor protocol as the sidecar endpoint.
    let response = match exec_server::handle_exec_request(&request.body) {
        Ok(body) => HttpResponse { status: 200, body },
        Err((status, error)) => HttpResponse {
            status,
            body: json!({"error":error}),
        },
    };
    let outcome = classify_executor_result(&response, &effect.effect_id);
    settle_exec_http_result(
        kernel,
        &ExecSettleContext {
            resolution_event_id: None,
            input_json: &effect.input_json,
            instance_id,
            effect_id: &effect.effect_id,
            run_id: &run_id,
            capability,
            script_sha256: &script.sha256,
            cache: None,
            ingest_schema: "json",
            executor_response: Some(&response),
            executor_transport: "in-process",
            dispatch_plan: Some(&plan),
        },
        outcome,
    )
}

fn classify_executor_result(response: &HttpResponse, effect_id: &str) -> ExecSettleOutcome {
    let result =
        parse_executor_response_for_effect(response, effect_id).map_err(|error| (None, error))?;
    if result.timed_out {
        return Err((
            Some((result.exit_code, result.stdout, result.stderr)),
            "native norm executor timed out".into(),
        ));
    }
    if result.exit_code != 0 {
        return Err((
            Some((result.exit_code, result.stdout, result.stderr)),
            "native norm executor exited unsuccessfully".into(),
        ));
    }
    Ok((result.exit_code, result.stdout, result.stderr, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_core::norm_evidence::{
        EvidenceSubject, EvidenceVersion, ReportContract, RequiredCase, TestOutcome,
    };
    use whipplescript_kernel::norm_execution::NormDispatchBinding;
    use whipplescript_kernel::norm_runner::{
        candidate_identity, PreparedNormRun, PythonCase, PythonRuntime,
    };
    use whipplescript_store::{
        CapabilityBinding, CapabilitySchemaRegistration, NewEffect, RuleCommit,
        ScriptCapabilityRegistration,
    };

    fn fixture(
        case: &str,
    ) -> (
        RuntimeKernel<SqliteStore>,
        String,
        ClaimableEffect,
        PreparedNormRun,
    ) {
        fixture_with_store(case, SqliteStore::open_in_memory().unwrap())
    }

    fn fixture_with_store(
        case: &str,
        store: SqliteStore,
    ) -> (
        RuntimeKernel<SqliteStore>,
        String,
        ClaimableEffect,
        PreparedNormRun,
    ) {
        let epoch = if matches!(case, "worker" | "worker-retry") {
            compute_environment_hash()
        } else {
            "native-test".into()
        };
        let python = if cfg!(windows) { "python" } else { "python3" };
        let version = Command::new(python)
            .args(["-c", "import sys; print(sys.version.split()[0])"])
            .output()
            .expect("native Python fixture");
        assert!(version.status.success());
        let mut method = PythonCallMethod {
            runtime: PythonRuntime {
                engine: PythonEngine::Cpython {},
                executable: python.into(),
                python_version: String::from_utf8(version.stdout).unwrap().trim().into(),
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
        if case == "protected" {
            method.runtime.engine = PythonEngine::Cpython3147Wasi {
                artifact_path: "/runtime.wasm".into(),
                artifact_sha256: "a".repeat(64),
            };
            method.runtime.executable = env::current_exe().unwrap().to_string_lossy().into_owned();
            method.runtime.python_version = "3.14.7".into();
        }
        let argv = if case == "protected" {
            vec![
                method.runtime.executable.clone(),
                "executor".into(),
                "observe-norm".into(),
                "{script}".into(),
            ]
        } else {
            vec![python.into(), "-I".into(), "{script}".into()]
        };
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
            &argv,
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
                    argv_json: &json!(argv).to_string(),
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

    #[test]
    fn native_norm_worker_requires_managed_host_and_refuses_in_process_protected_execution() {
        let path = env::temp_dir().join(format!(
            "native-norm-protected-{}.sqlite",
            std::process::id()
        ));
        let (mut kernel, instance, effect, _) =
            fixture_with_store("protected", SqliteStore::open(&path).unwrap());
        let before = kernel.store().list_events(&instance).unwrap().len();
        assert!(execute(&mut kernel, &instance, &effect, "native-test").is_err());
        assert!(kernel.store().list_runs(&instance).unwrap().is_empty());
        let options = WorkerOptions::parse(std::slice::from_ref(&instance)).unwrap();
        let error = run_worker_once_with_native_host(&path, &options, None).unwrap_err();
        assert!(
            matches!(error, StoreError::Conflict(ref e) if e.contains("WHIPPLESCRIPT_NATIVE_NORM_RUNTIME"))
        );
        assert_eq!(kernel.store().list_events(&instance).unwrap().len(), before);
        assert!(kernel.store().list_runs(&instance).unwrap().is_empty());
        let input: Value = serde_json::from_str(&effect.input_json).unwrap();
        let method: PythonCallMethod =
            serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap())
                .unwrap();
        let mut host = whipplescript::native_executor::NativeNormHost {
            protocol: "whipplescript.exec.native-norm-host/v1".into(),
            endpoint: "unix:///fixture".into(),
            installed: whipplescript::native_executor::NativeRuntimeImage {
                protocol: "whipplescript.exec.native-runtime-image/v1".into(),
                daemon_id: "original-daemon".into(),
                base_image: format!("sha256:{}", "b".repeat(64)),
                image_id: format!("sha256:{}", "c".repeat(64)),
                runtime: method.runtime,
            },
        };
        assert!(norm_exec_managed::validate_enqueue(&input, None).is_err());
        norm_exec_managed::validate_enqueue(&input, Some(&host)).unwrap();
        host.installed.runtime.environment = "changed".into();
        assert!(norm_exec_managed::validate_enqueue(&input, Some(&host)).is_err());
        host.installed.runtime.environment = "native-test".into();
        whipplescript::native_executor::NativeNormAdmission::admit_at(
            &mut kernel,
            &instance,
            &effect,
            &host.installed,
            "2030-01-01T00:00:00Z",
        )
        .unwrap();
        let before_recovery = kernel.store().list_events(&instance).unwrap().len();
        // Running work has left the claimable query; recovery still requires
        // host configuration instead of reporting a successfully idle pass.
        assert!(kernel
            .store()
            .claimable_effects(&instance)
            .unwrap()
            .is_empty());
        assert!(run_worker_once_with_native_host(&path, &options, None).is_err());
        assert_eq!(
            kernel.store().list_events(&instance).unwrap().len(),
            before_recovery
        );
        drop(kernel);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_norm_dispatch_runs_three_admitted_attempts_without_settlement_collision() {
        let (mut kernel, instance, _, _) = fixture("retry");
        let mut identities = std::collections::BTreeSet::new();
        let mut terminals = std::collections::BTreeSet::new();
        for attempt in 0..3 {
            let snapshot = kernel
                .store()
                .claimable_effects(&instance)
                .unwrap()
                .into_iter()
                .find(|effect| effect.effect_id == "observe")
                .expect("retry is claimable");
            let run = whipplescript_kernel::execution_attempt_key(
                &instance,
                "observe",
                snapshot.attempt_admission_event_id.as_deref(),
                "exec-run",
            );
            assert!(identities.insert(run));
            let terminal = execute(&mut kernel, &instance, &snapshot, "native-test").unwrap();
            assert!(terminals.insert(terminal.event_id));
            assert_eq!(
                kernel.store().list_effects(&instance).unwrap()[0].status,
                "failed"
            );
            let runs = kernel.store().list_runs(&instance).unwrap();
            assert_eq!(runs.len(), attempt + 1);
            assert!(runs.iter().all(|run| run.status == "failed"));
            if attempt < 2 {
                kernel
                    .retry_effect(whipplescript_store::RetryEffect {
                        instance_id: &instance,
                        effect_id: "observe",
                        retry_after: None,
                        idempotency_key: Some(&format!("admit-retry-{attempt}")),
                    })
                    .unwrap();
                kernel.store_mut().rebuild_projections(&instance).unwrap();
            }
        }
        assert_eq!(
            kernel
                .store()
                .list_events(&instance)
                .unwrap()
                .iter()
                .filter(|event| event.event_type == "effect.terminal")
                .count(),
            3
        );
    }

    #[test]
    fn native_norm_dispatch_retains_real_in_process_executor_evidence() {
        for (case, status, outcome) in [
            ("exact", "completed", TestOutcome::Pass),
            ("counter", "failed", TestOutcome::Fail),
        ] {
            let (mut kernel, instance, effect, prepared) = fixture(case);
            execute(&mut kernel, &instance, &effect, "native-test").unwrap();
            let runs = kernel.store().list_runs(&instance).unwrap();
            assert_eq!(runs.len(), 1);
            assert_eq!(runs[0].status, status);
            let metadata: Value = serde_json::from_str(&runs[0].metadata_json).unwrap();
            assert_eq!(metadata["executor_transport"], "in-process");
            let response = HttpResponse {
                status: metadata["executor_response"]["status"].as_u64().unwrap() as u16,
                body: metadata["executor_response"]["body"].clone(),
            };
            assert_eq!(
                prepared.finish(&response).unwrap().judgment.outcome,
                outcome
            );
            assert_eq!(response.body["effect_id"], "observe");
        }
    }

    #[test]
    fn native_norm_dispatch_refuses_before_run_start() {
        for case in [
            "missing-pin",
            "body",
            "epoch",
            "parse",
            "mode",
            "registration",
            "adapter",
            "env",
            "cache",
            "permission",
        ] {
            let (mut kernel, instance, effect, _) = fixture(case);
            let before = kernel.store().list_events(&instance).unwrap();
            let result = execute(
                &mut kernel,
                &instance,
                &effect,
                if case == "epoch" {
                    "changed"
                } else {
                    "native-test"
                },
            );
            assert!(result.is_err(), "{case}: {result:?}");
            assert!(
                kernel.store().list_runs(&instance).unwrap().is_empty(),
                "{case}"
            );
            if case != "permission" {
                assert_eq!(
                    kernel.store().list_events(&instance).unwrap(),
                    before,
                    "{case}"
                );
            }
        }
    }
    #[test]
    fn native_norm_dispatch_protected_command_is_exact_and_current() {
        let dir = env::temp_dir().join(format!(
            "norm-command-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let current = dir.join("whip");
        let other = dir.join("renamed-observer");
        fs::write(&current, "fixture").unwrap();
        fs::write(&other, "different executable").unwrap();
        let engine = PythonEngine::Cpython3147Wasi {
            artifact_path: "fixture".into(),
            artifact_sha256: "0".repeat(64),
        };
        let argv = vec![
            current.to_string_lossy().into_owned(),
            "executor".into(),
            "observe-norm".into(),
            "{script}".into(),
        ];
        validate_observer_command(&argv, &engine, &current).unwrap();
        validate_observer_command(
            &["python3".into(), "-I".into(), "{script}".into()],
            &PythonEngine::Cpython {},
            &current,
        )
        .unwrap();
        for case in [
            "binary",
            "verb",
            "subcommand",
            "slot",
            "extra",
            "empty",
            "profile",
        ] {
            let mut changed = argv.clone();
            match case {
                "binary" => changed[0] = other.to_string_lossy().into_owned(),
                "verb" => changed[1] = "worker".into(),
                "subcommand" => changed[2] = "serve".into(),
                "slot" => changed[3] = "other".into(),
                "extra" => changed.push("extra".into()),
                "empty" => changed.clear(),
                _ => {}
            }
            assert!(
                validate_observer_command(
                    &changed,
                    if case == "profile" {
                        &PythonEngine::Cpython {}
                    } else {
                        &engine
                    },
                    &current
                )
                .is_err(),
                "{case}"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_norm_dispatch_requires_the_original_redispatch_plan() {
        for changed in [false, true] {
            let (mut kernel, instance, effect, prepared) = fixture("exact");
            let input: Value = serde_json::from_str(&effect.input_json).unwrap();
            let request = prepared.executor_request("whip-executor://native").unwrap();
            let script = kernel
                .store()
                .get_script_capability("observer")
                .unwrap()
                .unwrap();
            let mut plan = ExecDispatchPlan::prepare(
                "observer",
                &script.sha256,
                &input,
                &request,
                "native-test",
                None,
                None,
            );
            if changed {
                plan.request_sha256 = "another original endpoint".into();
            }
            let run_id = idempotency_key(&[&instance, "observe", "exec-run"]);
            let lease_id = idempotency_key(&[&instance, "observe", "exec-lease"]);
            kernel.start_run(RunStart {
                instance_id:&instance, effect_id:"observe", run_id:&run_id,
                provider:"exec", worker_id:"whip-exec", lease_id:&lease_id, lease_expires_at:"2030-01-01T00:00:00Z",
                metadata_json:&json!({"mode":"capability", "capability":"observer", "executor_dispatch":plan, "executor_transport":"in-process"}).to_string(),
            }).unwrap();
            let before = kernel.store().list_events(&instance).unwrap();
            let result = execute(&mut kernel, &instance, &effect, "native-test");
            if changed {
                assert!(
                    matches!(
                        result,
                        Err(StoreError::Conflict(ref message))
                            if message == "native norm redispatch differs from its original plan"
                    ),
                    "unexpected redispatch result: {result:?}"
                );
                assert_eq!(kernel.store().list_events(&instance).unwrap(), before);
                assert_eq!(
                    kernel.store().list_runs(&instance).unwrap()[0].status,
                    "running"
                );
            } else {
                result.unwrap();
                assert_eq!(kernel.store().list_runs(&instance).unwrap().len(), 1);
                assert_eq!(
                    kernel.store().list_runs(&instance).unwrap()[0].status,
                    "completed"
                );
            }
        }
    }
    #[test]
    fn native_norm_dispatch_worker_retries_through_the_cli_command() {
        let dir = env::temp_dir().join(format!(
            "norm-worker-retry-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("runtime.sqlite");
        let (kernel, instance, _, _) =
            fixture_with_store("worker-retry", SqliteStore::open(&path).unwrap());
        drop(kernel);
        let options = CliOptions {
            command: Some("retry".into()),
            args: vec![instance.clone(), "observe".into()],
            store_path: path.clone(),
            json: false,
            input_json: None,
        };
        for attempt in 0..3 {
            let effect = SqliteStore::open(&path)
                .unwrap()
                .queued_exec_command_effects(&instance)
                .unwrap()
                .into_iter()
                .find(|effect| effect.effect_id == "observe")
                .unwrap();
            run_exec_effect(&path, &instance, &effect, ExecProfile::Hosted, None).unwrap();
            let store = SqliteStore::open(&path).unwrap();
            assert_eq!(store.list_effects(&instance).unwrap()[0].status, "failed");
            assert_eq!(store.list_runs(&instance).unwrap().len(), attempt + 1);
            drop(store);
            if attempt < 2 {
                assert_eq!(retry(&options), ExitCode::SUCCESS);
                let events = SqliteStore::open(&path)
                    .unwrap()
                    .list_events(&instance)
                    .unwrap();
                assert_eq!(retry(&options), ExitCode::SUCCESS);
                assert_eq!(
                    SqliteStore::open(&path)
                        .unwrap()
                        .list_events(&instance)
                        .unwrap(),
                    events
                );
            }
        }
        let store = SqliteStore::open(&path).unwrap();
        let events = store.list_events(&instance).unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.retried")
                .count(),
            2
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.terminal")
                .count(),
            3
        );
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn native_norm_dispatch_worker_entry_keeps_the_protocol_receipt_after_reopen() {
        let dir = env::temp_dir().join(format!(
            "norm-worker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join("runtime.sqlite");
        let (kernel, instance, effect, prepared) =
            fixture_with_store("worker", SqliteStore::open(&path).unwrap());
        drop(kernel);
        run_exec_effect(&path, &instance, &effect, ExecProfile::Hosted, None).unwrap();
        let store = SqliteStore::open(&path).unwrap();
        let runs = store.list_runs(&instance).unwrap();
        assert_eq!(runs.len(), 1);
        let metadata: Value = serde_json::from_str(&runs[0].metadata_json).unwrap();
        assert_eq!(metadata["executor_transport"], "in-process");
        let response = HttpResponse {
            status: metadata["executor_response"]["status"].as_u64().unwrap() as u16,
            body: metadata["executor_response"]["body"].clone(),
        };
        assert_eq!(
            prepared.finish(&response).unwrap().judgment.outcome,
            TestOutcome::Pass
        );
        drop(store);
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn native_norm_dispatch_timeout_cannot_be_classified_as_success() {
        let response = HttpResponse {
            status: 200,
            body: json!({"protocol":"whip-executor/1", "effect_id":"observe", "exit_code":0, "timed_out":true, "stdout":"retained", "stderr":"diagnostic"}),
        };
        let (detail, _) = classify_executor_result(&response, "observe")
            .expect_err("timeout dominates even a zero exit code");
        assert_eq!(detail, Some((0, "retained".into(), "diagnostic".into())));
        let mut success = response;
        success.body["timed_out"] = json!(false);
        assert!(classify_executor_result(&success, "observe").is_ok());
    }
}
