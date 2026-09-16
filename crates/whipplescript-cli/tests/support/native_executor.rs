use whipplescript_store::*;

pub fn setup() -> (SqliteStore, String, String, std::path::PathBuf) {
    setup_with_dispatch(serde_json::json!({"protocol":"whip-executor/1","effect_id":"exec"}))
}
pub fn setup_with_dispatch(
    dispatch: serde_json::Value,
) -> (SqliteStore, String, String, std::path::PathBuf) {
    setup_with_executor(dispatch, "whip-executor://native/exec")
}
pub fn setup_with_executor(
    dispatch: serde_json::Value,
    executor_url: &str,
) -> (SqliteStore, String, String, std::path::PathBuf) {
    let tracked = true;
    let path = std::env::temp_dir().join(format!(
        "whip-native-docker-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("recovery fixture operation succeeds")
            .as_nanos()
    ));
    let mut store = SqliteStore::open(&path).expect("recovery fixture operation succeeds");
    let version = store.create_program_version(NewProgramVersion {
        program_name: "exec-recovery", source_hash: "fixture", ir_hash: "fixture",
        ir_snapshot: None, compiler_version: "fixture", declared_capabilities_json: "[]",
        declared_profiles_json: "[]", declared_skills_json: "[]", declared_schemas_json: "[]",
        analysis_summary_json: r#"{"workflow":"exec-recovery","workflow_contracts":[],"schemas":[]}"#,
        generated_artifacts_json: "[]", artifact_root: None,
    }).expect("recovery fixture operation succeeds");
    let instance = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("recovery fixture operation succeeds")
        .instance_id;
    store
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "script.recovery",
            description: "fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .expect("recovery fixture operation succeeds");
    store
        .bind_capability(CapabilityBinding {
            binding_id: "recovery",
            program_id: Some(&version.program_id),
            capability: "script.recovery",
            provider: "builtin-script",
            config_json: "{}",
        })
        .expect("recovery fixture operation succeeds");
    store
        .commit_rule(RuleCommit {
            instance_id: &instance,
            rule: "start",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[NewEffect {
                effect_id: "exec",
                kind: "exec.command",
                target: None,
                input_json: "{}",
                status: "queued",
                idempotency_key: "exec",
                required_capabilities_json: r#"["script.recovery"]"#,
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            }],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("start"),
            marks: &[],
            context_json: None,
        })
        .expect("recovery fixture operation succeeds");
    let selected = whipplescript_kernel::exec_invocation::Invocation {
        instance_id: instance.clone(),
        effect_id: "exec".into(),
        attempt_admission_event_id: None,
    };
    let envelope = whipplescript_kernel::exec_invocation::Envelope::new(selected.clone(), dispatch)
        .expect("recovery fixture operation succeeds");
    let run = if tracked {
        selected.run_id()
    } else {
        "original".into()
    };
    let request = whipplescript_kernel::sansio::HttpRequest {
        url: executor_url.into(),
        headers: vec![],
        body: envelope
            .dispatch(&selected)
            .expect("recovery fixture operation succeeds")
            .clone(),
    };
    let plan = whipplescript_kernel::exec_http::ExecDispatchPlan::prepare(
        "script.recovery",
        "hash",
        &serde_json::json!({}),
        &request,
        "fixture",
        None,
        None,
    );
    let metadata = if tracked {
        serde_json::json!({"executor_invocation":envelope,"executor_dispatch":plan,"executor_url":request.url}).to_string()
    } else {
        "{}".into()
    };
    store
        .start_run(RunStart {
            instance_id: &instance,
            effect_id: "exec",
            run_id: &run,
            provider: "exec",
            worker_id: "whip-exec",
            lease_id: "original-lease",
            lease_expires_at: "2099-01-01T00:00:00Z",
            metadata_json: &metadata,
        })
        .expect("recovery fixture operation succeeds");
    if tracked {
        store
            .track_exec_lifetime(exec_lifetime::Track {
                instance_id: &instance,
                effect_id: "exec",
                run_id: &run,
                input_json: "{}",
                invocation_json: &serde_json::to_string(&envelope)
                    .expect("recovery fixture operation succeeds"),
                executor_url: &request.url,
            })
            .expect("recovery fixture operation succeeds");
    }
    (store, instance, run, path)
}
