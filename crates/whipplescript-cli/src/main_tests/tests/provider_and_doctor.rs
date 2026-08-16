//! Provider selection/config resolution and the `whip doctor` surface.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn finds_first_matching_tool_on_path() {
    let directory =
        std::env::temp_dir().join(format!("whipplescript-doctor-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(&directory).expect("temp directory creates");
    let executable = directory.join("tool-b");
    fs::write(&executable, "").expect("tool file creates");

    let found = find_executable_in_path(
        &["tool-a", "tool-b"],
        directory.to_str().expect("path is utf-8"),
    );

    assert_eq!(found, Some(executable.display().to_string()));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn doctor_reports_python_jsonschema_bridge_dependency() {
    let tools = doctor_tool_checks();
    let jsonschema = tools
        .iter()
        .find(|tool| tool.id == "python-jsonschema")
        .expect("doctor reports jsonschema bridge dependency");

    assert_eq!(jsonschema.category, "formal");
    assert_eq!(jsonschema.command, "python3 -c 'import jsonschema'");
    assert!(
        jsonschema.note.contains("generated construct graph"),
        "{}",
        jsonschema.note
    );
}

#[test]
fn parses_doctor_provider_config_option() {
    let options = DoctorOptions::parse(&[
        "--providers".to_owned(),
        "--provider-config".to_owned(),
        "providers.json".to_owned(),
        "--record-provider-evidence".to_owned(),
        "ins_123".to_owned(),
    ])
    .expect("doctor options parse");

    assert_eq!(
        options.provider_config_paths,
        vec![PathBuf::from("providers.json")]
    );
    assert_eq!(
        options.record_provider_evidence_instance_id.as_deref(),
        Some("ins_123")
    );
    assert!(options.providers);
}

#[test]
fn parses_worker_and_dev_provider_config_options() {
    let worker = WorkerOptions::parse(&[
        "ins_123".to_owned(),
        "--provider".to_owned(),
        "fixture".to_owned(),
        "--provider-config".to_owned(),
        "providers-a.json".to_owned(),
        "--provider-config".to_owned(),
        "providers-b.json".to_owned(),
        "--once".to_owned(),
    ])
    .expect("worker options parse");

    assert_eq!(worker.instance_id, "ins_123");
    assert_eq!(
        worker.provider_config_paths,
        vec![
            PathBuf::from("providers-a.json"),
            PathBuf::from("providers-b.json")
        ]
    );

    let dev = DevOptions::parse(&[
        "workflow.whip".to_owned(),
        "--provider-config".to_owned(),
        "providers.json".to_owned(),
        "--until".to_owned(),
        "idle".to_owned(),
        "--stream".to_owned(),
        "ndjson".to_owned(),
    ])
    .expect("dev options parse");

    assert_eq!(dev.program_path, "workflow.whip");
    assert_eq!(
        dev.provider_config_paths,
        vec![PathBuf::from("providers.json")]
    );
    assert_eq!(dev.stream, Some(DevStreamFormat::Ndjson));
}

// Feature-gated: validates codex/claude provider-config rows against the
// registered capability catalog, which only carries those rows when the
// adapter features are compiled in (std.agent slice 7 build matrix).
#[cfg(all(feature = "codex", feature = "claude"))]
#[test]
fn doctor_provider_config_validation_redacts_extra_values() {
    let results = validate_doctor_provider_config_json(
        r#"{
              "providers": [
                {
                  "provider_id": "codex-main",
                  "provider_kind": "codex",
                  "surface": "codex_app_server",
                  "credentials_ref": "secret:codex",
                  "cancellation_depth": "native_stop",
                  "api_key": "sk-should-not-appear"
                },
                {
                  "provider_id": "reviewer",
                  "provider_kind": "claude",
                  "surface": "claude_agent_sdk",
                  "credentials_ref": "secret:claude",
                  "cancellation_depth": "cooperative_request"
                }
              ]
            }"#,
    );

    assert!(results.iter().any(|result| {
        result.status == whipplescript_kernel::provider::ProviderValidationStatus::Pass
            && result.provider == "codex-main"
            && result.code == "surface_supported"
    }));
    // DR-0017: Claude advertises no validated cancellation depth, so a
    // binding claiming cooperative_request is refused, not rubber-stamped.
    assert!(results.iter().any(|result| {
        result.status == whipplescript_kernel::provider::ProviderValidationStatus::Fail
            && result.provider == "reviewer"
            && result.code == "unsupported_cancellation_depth"
    }));
    assert!(!json!(results
        .iter()
        .map(ProviderValidationResult::to_json)
        .collect::<Vec<_>>())
    .to_string()
    .contains("sk-should-not-appear"));
}

#[test]
fn doctor_provider_config_validation_rejects_command_without_executable() {
    let results = validate_doctor_provider_config_json(
        r#"{
              "providers": [
                {
                  "provider_id": "runner",
                  "provider_kind": "command",
                  "surface": "command",
                  "workspace_policy": "read_only",
                  "cancellation_depth": "none",
                  "artifact_policy": "metadata"
                }
              ]
            }"#,
    );

    assert!(results.iter().any(|result| {
        result.status == whipplescript_kernel::provider::ProviderValidationStatus::Fail
            && result.provider == "runner"
            && result.code == "invalid_command_config"
            && result
                .message
                .contains("missing required command field `executable`")
    }));
}

#[test]
fn native_lifecycle_summary_exposes_redacted_status_for_runs() {
    let events = vec![
        event_view(
            1,
            "agent.turn.streamed",
            json!({
                "run_id": "run-1",
                "effect_id": "tell",
                "provider": "codex-main",
                "status": "streamed",
                "terminal": false,
                "provider_event_type": "item/completed",
                "provider_payload_shape": {"type":"object","keys":2},
                "evidence_id": "evd_stream",
            }),
        ),
        event_view(
            2,
            "agent.turn.cancelled",
            json!({
                "run_id": "run-1",
                "effect_id": "tell",
                "provider": "codex-main",
                "status": "cancelled",
                "terminal": true,
                "provider_event_type": "turn/completed",
                "provider_payload_shape": {"type":"object","keys":3},
                "evidence_id": "evd_cancel",
            }),
        ),
        event_view(3, "workflow.completed", json!({"status":"completed"})),
    ];
    let lifecycle = native_lifecycle_events(&events);
    assert_eq!(lifecycle.as_array().expect("array").len(), 2);
    assert_eq!(
        lifecycle
            .pointer("/1/provider_event_type")
            .and_then(Value::as_str),
        Some("turn/completed")
    );
    assert!(lifecycle.to_string().contains("evd_cancel"));
    assert!(!lifecycle.to_string().contains("provider_payload_shape"));

    let run = RunView {
        run_id: "run-1".to_owned(),
        effect_id: "tell".to_owned(),
        provider: "codex-main".to_owned(),
        worker_id: "worker-1".to_owned(),
        status: "running".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        completed_at: None,
        metadata_json: json!({
            "native_provider": {
                "provider_id": "codex-main",
                "provider_kind": "codex",
                "surface": "codex_app_server"
            }
        })
        .to_string(),
        cancel_requested: true,
    };
    let run_json = run_to_json_with_lifecycle_and_artifacts(&run, &events, &BTreeMap::new());
    assert_eq!(
        run_json
            .pointer("/native_lifecycle/status")
            .and_then(Value::as_str),
        Some("cancelled")
    );
    assert_eq!(
        run_json
            .pointer("/native_lifecycle/evidence_id")
            .and_then(Value::as_str),
        Some("evd_cancel")
    );
    assert_eq!(
        run_json
            .pointer("/provider_selection/surface")
            .and_then(Value::as_str),
        Some("codex_app_server")
    );
}

#[test]
fn provider_cancellation_policy_tracks_validated_native_shapes() {
    assert_eq!(
        provider_cancellation_policy("codex-main"),
        ProviderCancellationPolicy::NativeStop {
            acknowledgement_order: CancellationAcknowledgementOrder::BeforeTerminal,
        }
    );
    assert_eq!(
        provider_cancellation_policy("fixture-cancellable"),
        ProviderCancellationPolicy::NativeStop {
            acknowledgement_order: CancellationAcknowledgementOrder::BeforeTerminal,
        }
    );
    assert_eq!(
        provider_cancellation_policy("claude-main"),
        ProviderCancellationPolicy::Unsupported
    );
}

#[test]
fn agent_provider_selection_uses_bound_harness_metadata() {
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        profile: Some("repo-writer".to_owned()),
        input_json: "{}".to_owned(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: json!({
            "harnesses": [
                {"name": "coder", "kind": "codex"},
                {"name": "reviewer", "kind": "claude"}
            ],
            "agents": [
                {"name": "implementer", "harness": "coder", "profile": "repo-writer"},
                {"name": "critic", "harness": "reviewer", "profile": "repo-reader"}
            ]
        })
        .to_string(),
    };

    let selection =
        agent_provider_selection_with_config_paths(&effect, "fixture", &[]).expect("selection");

    assert_eq!(selection.provider_id, "coder");
    assert_eq!(selection.kind, "fixture");
    assert_eq!(selection.source_harness_id.as_deref(), Some("coder"));
    assert_eq!(selection.surface, None);
    assert!(selection.provider_config.is_none());
    assert!(selection.command_plan.is_none());
    assert!(
        selection.selection_reason.contains("harness `coder`"),
        "{}",
        selection.selection_reason
    );
}

#[test]
fn provider_selection_metadata_surfaces_the_explainable_reason() {
    // The recorded provider_selection metadata carries the human-readable reason
    // for the choice, so provider routing is explainable in status/effects.
    let selection = fallback_provider_selection_for_agent("fixture", Some("worker"));
    assert!(selection
        .selection_reason
        .contains("agent `worker` declares no harness or provider"));
    let metadata = agent_provider_selection_metadata_json(&selection);
    let value: Value = serde_json::from_str(&metadata).expect("metadata JSON");
    let reason = value
        .get("provider_selection")
        .and_then(|sel| sel.get("reason"))
        .and_then(Value::as_str)
        .expect("reason in metadata");
    assert_eq!(reason, selection.selection_reason);
}

#[test]
fn agent_provider_selection_supports_map_shaped_harness_metadata() {
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        profile: Some("repo-writer".to_owned()),
        input_json: "{}".to_owned(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: json!({
            "harnesses": {
                "coder": {"kind": "codex"}
            },
            "agents": {
                "implementer": {"harness": "coder", "profile": "repo-writer"}
            }
        })
        .to_string(),
    };

    let selection =
        agent_provider_selection_with_config_paths(&effect, "fixture", &[]).expect("selection");

    assert_eq!(selection.provider_id, "coder");
    assert_eq!(selection.kind, "fixture");
    assert_eq!(selection.source_harness_id.as_deref(), Some("coder"));
}

#[test]
fn agent_provider_selection_uses_direct_provider_metadata() {
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        profile: Some("repo-writer".to_owned()),
        input_json: "{}".to_owned(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: json!({
            "agents": [
                {"name": "implementer", "provider": "codex", "profile": "repo-writer"}
            ]
        })
        .to_string(),
    };

    let selection =
        agent_provider_selection_with_config_paths(&effect, "fixture", &[]).expect("selection");

    assert_eq!(selection.provider_id, "codex");
    assert_eq!(selection.kind, "fixture");
    assert_eq!(selection.source_harness_id, None);
    assert_eq!(selection.surface, None);
    assert!(selection.provider_config.is_none());
    assert!(selection.command_plan.is_none());
    assert!(
        selection.selection_reason.contains("provider `codex`"),
        "{}",
        selection.selection_reason
    );
}

// Feature-gated: binds a `codex` harness surface, which needs the codex
// capability row (std.agent slice 7 build matrix).
#[cfg(feature = "codex")]
#[test]
fn agent_provider_selection_uses_provider_config_for_harness_surface() {
    let config_path = std::env::temp_dir().join(format!(
        "whipplescript-harness-provider-config-{}.json",
        std::process::id()
    ));
    fs::write(
        &config_path,
        json!({
            "providers": [
                {
                    "provider_id": "coder",
                    "provider_kind": "codex",
                    "surface": "codex_app_server",
                    "credentials_ref": "env:OPENAI_API_KEY",
                    "profile_ids": ["repo-writer"],
                    "workspace_policy": "read_only",
                    "cancellation_depth": "native_stop",
                    "artifact_policy": "metadata"
                }
            ]
        })
        .to_string(),
    )
    .expect("config writes");
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        profile: Some("repo-writer".to_owned()),
        input_json: "{}".to_owned(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: json!({
            "harnesses": [
                {"name": "coder", "kind": "codex"}
            ],
            "agents": [
                {"name": "implementer", "harness": "coder", "profile": "repo-writer"}
            ]
        })
        .to_string(),
    };

    let selection = agent_provider_selection_with_config_paths(
        &effect,
        "fixture",
        std::slice::from_ref(&config_path),
    )
    .expect("selection");

    assert_eq!(selection.provider_id, "coder");
    assert_eq!(selection.kind, "codex");
    assert_eq!(selection.source_harness_id.as_deref(), Some("coder"));
    assert_eq!(selection.surface.as_deref(), Some("codex_app_server"));
    assert!(selection.command_plan.is_none());
    let config = selection
        .provider_config
        .as_ref()
        .expect("provider config selected");
    assert_eq!(config.provider_kind, "codex".to_owned());
    assert_eq!(config.surface, "codex_app_server".to_owned());
    assert_eq!(config.workspace_policy, "read_only");
    assert_eq!(
        config.credentials_ref.as_deref(),
        Some("env:OPENAI_API_KEY")
    );
    let _ = fs::remove_file(config_path);
}

#[test]
fn provider_profile_allowlist_blocks_mismatched_effect_profile() {
    let config = ProviderBindingConfig::from_value(&json!({
        "provider_id": "coder",
        "provider_kind": "codex",
        "surface": "codex_app_server",
        "profile_ids": ["repo-writer"]
    }))
    .expect("provider config parses");
    let selection = AgentProviderSelection {
        provider_id: "coder".to_owned(),
        kind: "codex".to_owned(),
        source_harness_id: Some("coder".to_owned()),
        surface: Some("codex_app_server".to_owned()),
        provider_config: Some(config),
        command_plan: None,
        selection_reason: "test".to_owned(),
    };

    assert!(provider_profile_allowlist_block(&selection, Some("repo-writer")).is_none());
    assert!(
        provider_profile_allowlist_block(&selection, Some("repo-reader"))
            .expect("profile mismatch blocks")
            .contains("does not allow profile `repo-reader`")
    );
    assert!(provider_profile_allowlist_block(&selection, None)
        .expect("missing profile blocks")
        .contains("effect has no profile"));
}

#[test]
fn agent_provider_selection_uses_command_provider_config_plan() {
    let config_path = std::env::temp_dir().join(format!(
        "whipplescript-command-harness-provider-config-{}.json",
        std::process::id()
    ));
    fs::write(
        &config_path,
        json!({
            "providers": [
                {
                    "provider_id": "runner",
                    "provider_kind": "command",
                    "surface": "command",
                    "workspace_policy": "read_only",
                    "cancellation_depth": "none",
                    "artifact_policy": "metadata",
                    "executable": "sh",
                    "args": ["-c", "cat >/dev/null; echo command completed"],
                    "env": {"MODE": "test"},
                    "required_env": ["PATH"],
                    "required_commands": ["sh"],
                    "timeout_ms": 2500,
                    "require_stdout_json": true
                }
            ]
        })
        .to_string(),
    )
    .expect("config writes");
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("worker".to_owned()),
        profile: Some("repo-reader".to_owned()),
        input_json: "{}".to_owned(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: json!({
            "harnesses": [
                {"name": "runner", "kind": "command"}
            ],
            "agents": [
                {"name": "worker", "harness": "runner", "profile": "repo-reader"}
            ]
        })
        .to_string(),
    };

    let selection = agent_provider_selection_with_config_paths(
        &effect,
        "fixture",
        std::slice::from_ref(&config_path),
    )
    .expect("selection");

    let expected_plan = CommandLaunchPlan::new("runner", "sh")
        .arg("-c")
        .arg("cat >/dev/null; echo command completed")
        .env("MODE", "test")
        .require_env("PATH")
        .require_command("sh")
        .timeout(Duration::from_millis(2500))
        .require_stdout_json();
    assert_eq!(selection.provider_id, "runner");
    assert_eq!(selection.kind, "command");
    assert_eq!(selection.source_harness_id.as_deref(), Some("runner"));
    assert_eq!(selection.surface.as_deref(), Some("command"));
    assert_eq!(selection.command_plan.as_ref(), Some(&expected_plan));
    let config = selection
        .provider_config
        .as_ref()
        .expect("provider config selected");
    assert_eq!(config.provider_kind, "command".to_owned());
    assert_eq!(config.timeout_ms, Some(2500));
    let _ = fs::remove_file(config_path);
}

#[test]
fn command_provider_config_requires_executable() {
    let config_path = std::env::temp_dir().join(format!(
        "whipplescript-command-harness-missing-executable-{}.json",
        std::process::id()
    ));
    fs::write(
        &config_path,
        json!({
            "providers": [
                {
                    "provider_id": "runner",
                    "provider_kind": "command",
                    "surface": "command",
                    "workspace_policy": "read_only",
                    "cancellation_depth": "none"
                }
            ]
        })
        .to_string(),
    )
    .expect("config writes");
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("worker".to_owned()),
        profile: Some("repo-reader".to_owned()),
        input_json: "{}".to_owned(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: json!({
            "harnesses": [
                {"name": "runner", "kind": "command"}
            ],
            "agents": [
                {"name": "worker", "harness": "runner", "profile": "repo-reader"}
            ]
        })
        .to_string(),
    };

    let error = agent_provider_selection_with_config_paths(
        &effect,
        "fixture",
        std::slice::from_ref(&config_path),
    )
    .expect_err("missing executable rejects command config");

    match error {
        StoreError::Conflict(message) => {
            assert!(message.contains("missing required command field `executable`"));
        }
        error => panic!("expected command config conflict, got {error:?}"),
    }
    let _ = fs::remove_file(config_path);
}

#[test]
fn agent_provider_selection_falls_back_without_harness_binding() {
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("worker".to_owned()),
        profile: Some("repo-writer".to_owned()),
        input_json: "{}".to_owned(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: json!({
            "agents": [
                {"name": "worker", "profile": "repo-writer"}
            ]
        })
        .to_string(),
    };

    let selection =
        agent_provider_selection_with_config_paths(&effect, "claude-main", &[]).expect("selection");

    assert_eq!(selection.provider_id, "claude-main");
    assert_eq!(selection.kind, "claude");
    assert_eq!(selection.source_harness_id, None);
    assert_eq!(selection.surface, None);
    assert!(selection.provider_config.is_none());
    assert!(selection.command_plan.is_none());
    assert!(
        selection
            .selection_reason
            .contains("fallback provider `claude-main`"),
        "{}",
        selection.selection_reason
    );
}

// Feature-gated: the codex/claude native-turn request builders exist only
// when their adapter features are compiled in (spec/std-agent.md slice 7
// build matrix: the features-off test target must also compile).
#[cfg(all(feature = "codex", feature = "claude"))]
#[test]
fn native_turn_request_applies_provider_config_fields() {
    let config_json = json!({
        "provider_id": "coder",
        "provider_kind": "codex",
        "surface": "codex_app_server",
        "credentials_ref": "env:OPENAI_API_KEY",
        "profile_ids": ["repo-writer"],
        "default_model": "gpt-5.4",
        "workspace_policy": "shared",
        "timeout_ms": 60000,
        "cancellation_depth": "hard_process_stop",
        "artifact_policy": "required",
        "health_checks": ["codex_cli"],
        "cwd": "/tmp/whip-coder"
    });
    let config = ProviderBindingConfig::from_value(&config_json).expect("provider config parses");
    let effect = ClaimableEffect {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        profile: Some("repo-writer".to_owned()),
        input_json: r#"{"prompt":"go"}"#.to_owned(),
        required_capabilities_json: r#"["agent.tell"]"#.to_owned(),
        declared_profiles_json: "{}".to_owned(),
    };
    let execution = AgentTurnExecution {
        instance_id: "ins-1",
        effect_id: "eff-1",
        run_id: "run-1",
        provider: "coder",
        worker_id: "worker-1",
        lease_id: "lease-1",
        lease_expires_at: "2030-01-01T00:00:00Z",
        agent: "implementer",
        profile: Some("repo-writer"),
        input_json: r#"{"prompt":"go"}"#,
        skill_names: &[],
    };

    let request =
        codex_native_turn_request(execution, &effect, r#"{"prompt":"go"}"#, Some(&config))
            .expect("request builds");

    assert_eq!(request.provider_id, "coder");
    assert_eq!(request.workspace_policy, "shared");
    assert_eq!(
        request.cancellation_depth,
        CancellationDepth::HardProcessStop
    );
    assert_eq!(request.artifact_policy, "required");
    assert_eq!(
        request.credential_ref.as_deref(),
        Some("env:OPENAI_API_KEY")
    );
    assert_eq!(
        request.provider_options.get("cwd").and_then(Value::as_str),
        Some("/tmp/whip-coder")
    );
    assert_eq!(
        request
            .provider_options
            .get("model")
            .and_then(Value::as_str),
        Some("gpt-5.4")
    );
    assert_eq!(
        request
            .provider_options
            .get("timeout_ms")
            .and_then(Value::as_u64),
        Some(60000)
    );
    assert_eq!(
        request
            .provider_options
            .get("profile_ids")
            .and_then(Value::as_array)
            .and_then(|values| values.first())
            .and_then(Value::as_str),
        Some("repo-writer")
    );

    let claude_config_json = json!({
        "provider_id": "reviewer",
        "provider_kind": "claude",
        "surface": "claude_agent_sdk",
        "credentials_ref": "env:ANTHROPIC_API_KEY",
        "default_model": "sonnet-4",
        "workspace_policy": "per_effect_worktree",
        "cancellation_depth": "cooperative_request",
        "artifact_policy": "metadata",
        "timeout_ms": 45000,
        "cwd": "/tmp/whip-reviewer"
    });
    let claude_config =
        ProviderBindingConfig::from_value(&claude_config_json).expect("claude config parses");
    let claude_request = claude_native_turn_request(
        AgentTurnExecution {
            provider: "reviewer",
            agent: "critic",
            profile: None,
            ..execution
        },
        &effect,
        r#"{"prompt":"review"}"#,
        Some(&claude_config),
        Some("project"),
    )
    .expect("claude request builds");

    assert_eq!(claude_request.provider_id, "reviewer");
    assert_eq!(claude_request.workspace_policy, "per_effect_worktree");
    assert_eq!(
        claude_request.cancellation_depth,
        CancellationDepth::CooperativeRequest
    );
    assert_eq!(
        claude_request.credential_ref.as_deref(),
        Some("env:ANTHROPIC_API_KEY")
    );
    assert_eq!(
        claude_request
            .provider_options
            .get("model")
            .and_then(Value::as_str),
        Some("sonnet-4")
    );
    assert_eq!(
        claude_request
            .provider_options
            .get("cwd")
            .and_then(Value::as_str),
        Some("/tmp/whip-reviewer")
    );
    // The declared `settings` knob rides provider_options (DR-0034 Decision 4).
    assert_eq!(
        claude_request
            .provider_options
            .get("settings")
            .and_then(Value::as_str),
        Some("project")
    );
}
