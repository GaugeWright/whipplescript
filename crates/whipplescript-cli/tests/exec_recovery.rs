//! The public recovery command must not manufacture executor lifetime evidence.
use std::process::Command;
use whipplescript_store::*;

#[test]
fn recover_keeps_unresolved_executor_attempt_running() {
    check_recovery(false);
    check_recovery(true);
}

fn check_recovery(tracked: bool) {
    let path = std::env::temp_dir().join(format!(
        "whip-exec-recover-{}-{}.sqlite",
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
    let envelope = whipplescript_kernel::exec_invocation::Envelope::new(
        selected.clone(),
        serde_json::json!({"protocol":"whip-executor/1","effect_id":"exec"}),
    )
    .expect("recovery fixture operation succeeds");
    let run = if tracked {
        selected.run_id()
    } else {
        "original".into()
    };
    let request = whipplescript_kernel::sansio::HttpRequest {
        model_provenance: None,
        url: "http://executor/exec".into(),
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
    let mut events = store
        .list_events(&instance)
        .expect("recovery fixture operation succeeds");
    let effects = store
        .list_effects(&instance)
        .expect("recovery fixture operation succeeds");
    let runs = store
        .list_runs(&instance)
        .expect("recovery fixture operation succeeds");
    assert_eq!(runs[0].status, "running");
    drop(store);
    for attempt in 0..2 {
        let result = Command::new(env!("CARGO_BIN_EXE_whip"))
            .args(["recover", &instance, "--json", "--store"])
            .arg(&path)
            .output()
            .expect("recovery fixture operation succeeds");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("recovery fixture operation succeeds");
        assert_eq!(report["recovered_count"], 0);
        let store = SqliteStore::open(&path).expect("recovery fixture operation succeeds");
        if tracked && attempt == 0 {
            let fences = whipplescript_kernel::exec_lifetime::fences(&store, &instance)
                .expect("recovery fixture operation succeeds");
            assert_eq!(fences.len(), 1);
            assert!(matches!(
                fences[&run].reason,
                exec_lifetime::FenceReason::Recovery
            ));
            let updated = store
                .list_events(&instance)
                .expect("recovery fixture operation succeeds");
            assert_eq!(updated.len(), events.len() + 1);
            events = updated;
        }
        assert_eq!(
            store
                .list_events(&instance)
                .expect("recovery fixture operation succeeds"),
            events
        );
        assert_eq!(
            store
                .list_effects(&instance)
                .expect("recovery fixture operation succeeds"),
            effects
        );
        assert_eq!(
            store
                .list_runs(&instance)
                .expect("recovery fixture operation succeeds"),
            runs
        );
    }
    if tracked {
        let mut store = SqliteStore::open(&path).expect("recovery fixture operation succeeds");
        let envelope_json =
            serde_json::to_value(&envelope).expect("recovery fixture operation succeeds");
        let view = serde_json::json!({"protocol":"whipplescript.exec.resolution/v1","selected":selected,
            "placement":{"protocol":"whipplescript.exec.placement/v2","selected":envelope_json["invocation"],"envelope":envelope_json,"container_id":"owner","dispatch_id":"dispatch"},
            "lifetime":{"state":"not_admitted","fence_id":"f"},"outcome":{"state":"not_executed"}});
        assert!(whipplescript_kernel::exec_lifetime::observe(
            &mut store,
            &instance,
            &run,
            &view.to_string()
        )
        .expect("recovery fixture operation succeeds"));
        assert!(store
            .list_events(&instance)
            .expect("recovery fixture operation succeeds")
            .iter()
            .all(|event| event.event_type != "exec.settlement.retained"));
        drop(store);
        for _ in 0..2 {
            let result = Command::new(env!("CARGO_BIN_EXE_whip"))
                .env_clear()
                .env("WHIPPLESCRIPT_STORE", &path)
                .args(["--json", "worker", &instance, "--once"])
                .output()
                .expect("recovery fixture operation succeeds");
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            let store = SqliteStore::open(&path).expect("recovery fixture operation succeeds");
            assert_eq!(
                store
                    .list_runs(&instance)
                    .expect("recovery fixture operation succeeds")[0]
                    .status,
                "failed"
            );
            assert_eq!(
                store
                    .list_effects(&instance)
                    .expect("recovery fixture operation succeeds")[0]
                    .status,
                "failed"
            );
            assert_eq!(
                store
                    .list_events(&instance)
                    .expect("recovery fixture operation succeeds")
                    .iter()
                    .filter(|event| event.event_type == "effect.terminal")
                    .count(),
                1
            );
            assert_eq!(
                store
                    .list_events(&instance)
                    .expect("recovery fixture operation succeeds")
                    .iter()
                    .filter(|event| event.event_type == "exec.settlement.retained")
                    .count(),
                1
            );
        }
    }
    std::fs::remove_file(path).expect("recovery fixture operation succeeds");
}
