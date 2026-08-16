//! Deploy planning, script manifests, hosted exec, and the exec result cache.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn deploy_plan_resolves_worker_dir_and_flags() {
    // Explicit flag wins; unknown args are rejected; a directory with no
    // wrangler configuration is rejected. Use the real in-repo worker dir
    // as the valid target.
    let repo_worker = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .join("whipplescript-host-do/worker");
    let args = vec![
        "--worker-dir".to_owned(),
        repo_worker.display().to_string(),
        "--config".to_owned(),
        "wrangler.harness.toml".to_owned(),
        "--name".to_owned(),
        "staging".to_owned(),
        "--dry-run".to_owned(),
        "--skip-build".to_owned(),
    ];
    let plan = parse_deploy_args(&args, None, Path::new("/nowhere")).expect("plan resolves");
    assert_eq!(plan.worker_dir, repo_worker);
    assert_eq!(plan.config.as_deref(), Some("wrangler.harness.toml"));
    assert_eq!(plan.name.as_deref(), Some("staging"));
    assert!(plan.dry_run);
    assert!(plan.skip_build);
    assert!(!plan.set_secrets);

    let error = parse_deploy_args(&["--bogus".to_owned()], None, Path::new("/nowhere"))
        .expect_err("unknown arg rejected");
    assert!(error.contains("unknown deploy argument"), "{error}");

    let error = parse_deploy_args(
        &["--worker-dir".to_owned(), "/nowhere".to_owned()],
        None,
        Path::new("/nowhere"),
    )
    .expect_err("non-worker dir rejected");
    assert!(error.contains("no wrangler configuration"), "{error}");

    // The in-repo shell publishes one `src/index.ts` under several worker
    // names, so it has no default: omitting --config must refuse and name
    // the alternatives rather than pick one.
    let error = parse_deploy_args(
        &["--worker-dir".to_owned(), repo_worker.display().to_string()],
        None,
        Path::new("/nowhere"),
    )
    .expect_err("ambiguous worker dir rejected");
    assert!(error.contains("--config"), "{error}");
    assert!(error.contains("wrangler.public.toml"), "{error}");

    // A configuration that is not in the directory is rejected by name.
    let error = parse_deploy_args(
        &[
            "--worker-dir".to_owned(),
            repo_worker.display().to_string(),
            "--config".to_owned(),
            "wrangler.toml".to_owned(),
        ],
        None,
        Path::new("/nowhere"),
    )
    .expect_err("absent config rejected");
    assert!(error.contains("wrangler.toml"), "{error}");

    // An ordinary single-config worker directory still needs no flag, and
    // the conventional name stays implicit so wrangler's own default holds.
    let solo = unique_test_path("deploy-solo-config", "dir");
    fs::create_dir_all(&solo.path).expect("create solo worker dir");
    fs::write(solo.path.join("wrangler.toml"), "name = \"solo\"\n").expect("write config");
    let plan = parse_deploy_args(
        &["--worker-dir".to_owned(), solo.path.display().to_string()],
        None,
        Path::new("/nowhere"),
    )
    .expect("single-config dir resolves");
    assert_eq!(plan.config, None);

    // Repo discovery: walking up from inside the repo finds the shell.
    let discovered = discover_worker_dir(Path::new(env!("CARGO_MANIFEST_DIR")))
        .expect("worker dir discovered from repo");
    assert_eq!(discovered, repo_worker);
}

#[test]
fn deploy_steps_sequence_matches_plan() {
    let plan = DeployPlan {
        worker_dir: PathBuf::from("/w"),
        config: Some("wrangler.public.toml".to_owned()),
        name: Some("staging".to_owned()),
        dry_run: false,
        skip_build: false,
        set_secrets: true,
    };
    let secrets = vec![("ANTHROPIC_API_KEY", "sk-test".to_owned())];
    let steps = deploy_steps(&plan, false, &secrets, true);
    let labels = steps.iter().map(|step| step.label).collect::<Vec<_>>();
    assert_eq!(
        labels,
        vec![
            "install worker dependencies",
            "build wasm kernel",
            "stage executor binary",
            "set provider secret",
            "deploy to Cloudflare",
        ]
    );
    let secret_step = &steps[3];
    assert_eq!(secret_step.program, "wrangler");
    assert_eq!(
        secret_step.args,
        vec![
            "secret",
            "put",
            "ANTHROPIC_API_KEY",
            "--config",
            "wrangler.public.toml",
            "--name",
            "staging"
        ],
        "a secret belongs to one worker, so it is set against that worker's config"
    );
    assert_eq!(secret_step.stdin_value.as_deref(), Some("sk-test"));
    assert_eq!(
        steps[4].args,
        vec![
            "deploy",
            "--config",
            "wrangler.public.toml",
            "--name",
            "staging"
        ],
        "secret value must never appear in deploy argv"
    );

    // Dry run: no install (node_modules present), no secrets pushed, and
    // wrangler validates without publishing.
    let dry = DeployPlan {
        worker_dir: PathBuf::from("/w"),
        config: None,
        name: None,
        dry_run: true,
        skip_build: false,
        set_secrets: true,
    };
    let steps = deploy_steps(&dry, true, &secrets, false);
    let labels = steps.iter().map(|step| step.label).collect::<Vec<_>>();
    assert_eq!(
        labels,
        vec!["build wasm kernel", "validate deploy (dry run)"]
    );
    assert_eq!(steps[1].args, vec!["deploy", "--dry-run"]);

    // Skip-build: straight to deploy.
    let quick = DeployPlan {
        worker_dir: PathBuf::from("/w"),
        config: None,
        name: None,
        dry_run: false,
        skip_build: true,
        set_secrets: false,
    };
    let steps = deploy_steps(&quick, false, &[], true);
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].args, vec!["deploy"]);
}

#[test]
fn script_manifest_parses_hermetic_flag() {
    let manifest_path = unique_test_path("manifest-hermetic", "json");
    let sha = "a".repeat(64);
    fs::write(
        &manifest_path,
        json!({
            "cached": {"argv": ["sh", "judge.sh"], "sha256": sha, "hermetic": true},
            "plain": {"argv": ["sh", "other.sh"], "sha256": sha},
        })
        .to_string(),
    )
    .expect("write manifest");
    let manifest = ScriptManifest::load(&manifest_path).expect("manifest loads");
    assert!(manifest.get("cached").expect("cached entry").hermetic);
    assert!(!manifest.get("plain").expect("plain entry").hermetic);

    fs::write(
        &manifest_path,
        json!({"bad": {"argv": ["sh", "x.sh"], "sha256": sha, "hermetic": "yes"}}).to_string(),
    )
    .expect("rewrite manifest");
    let error = ScriptManifest::load(&manifest_path).expect_err("non-bool hermetic rejected");
    assert!(error.contains("hermetic must be a boolean"), "{error}");
    let _ = fs::remove_file(&manifest_path);
}

#[test]
fn script_manifest_rejects_reserved_and_invalid_keys() {
    // spec/std-script.md "Capability ids": operator keys must match
    // [a-z_][a-z0-9_]* and `raw` is reserved for the demoted raw form's
    // `script.raw` capability id — both are manifest LOAD errors.
    let manifest_path = unique_test_path("manifest-keys", "json");
    let sha = "a".repeat(64);

    fs::write(
        &manifest_path,
        json!({"raw": {"argv": ["sh", "x.sh"], "sha256": sha}}).to_string(),
    )
    .expect("write manifest");
    let error = ScriptManifest::load(&manifest_path).expect_err("reserved `raw` key rejected");
    assert!(
        error.contains("script manifest key `raw` is reserved"),
        "{error}"
    );

    fs::write(
        &manifest_path,
        json!({"My-Script": {"argv": ["sh", "x.sh"], "sha256": sha}}).to_string(),
    )
    .expect("rewrite manifest");
    let error = ScriptManifest::load(&manifest_path).expect_err("invalid key rejected");
    assert!(
        error.contains("script manifest key `My-Script` is invalid")
            && error.contains("[a-z_][a-z0-9_]*"),
        "{error}"
    );

    fs::write(
        &manifest_path,
        json!({
            "backup_repo": {"argv": ["sh", "x.sh"], "sha256": sha},
            "_v2": {"argv": ["sh", "y.sh"], "sha256": sha},
            "raw_report9": {"argv": ["sh", "z.sh"], "sha256": sha},
        })
        .to_string(),
    )
    .expect("rewrite manifest");
    let manifest = ScriptManifest::load(&manifest_path).expect("valid keys load");
    assert_eq!(manifest.names(), ["_v2", "backup_repo", "raw_report9"]);
    let _ = fs::remove_file(&manifest_path);
}

#[test]
fn script_manifest_rejects_whip_control_plane_argv_at_load() {
    // spec/std-script.md "Static checks" item 5: the runtime refusal of
    // whip-as-executable is mirrored at manifest load/pin time (same
    // deny-list source), so operators learn early. Basename logic matches
    // the runtime site: any argv element, path forms included.
    let manifest_path = unique_test_path("manifest-whip", "json");
    let sha = "a".repeat(64);
    for argv in [
        json!(["whip", "signal"]),
        json!(["/usr/bin/whip", "revise"]),
        json!(["bash", "-c", "whip"]),
    ] {
        fs::write(
            &manifest_path,
            json!({"deploy": {"argv": argv, "sha256": sha}}).to_string(),
        )
        .expect("write manifest");
        let error = ScriptManifest::load(&manifest_path).expect_err("whip argv rejected");
        assert!(
                error.contains(
                    "script manifest entry `deploy` argv may not execute the `whip` control-plane binary"
                ),
                "{error}"
            );
    }
    fs::write(
        &manifest_path,
        json!({"deploy": {"argv": ["bash", "scripts/whipple.sh"], "sha256": sha}}).to_string(),
    )
    .expect("write manifest");
    assert!(
        ScriptManifest::load(&manifest_path).is_ok(),
        "non-whip basenames load"
    );
    let _ = fs::remove_file(&manifest_path);
}

#[test]
fn hosted_exec_lint_walks_effect_nodes_not_body_lines() {
    // spec/std-script.md "Static checks" item 2: the hosted-raw gate walks
    // IR effect nodes. The retired line-scan flagged any rule-body line
    // starting with `exec "` — including prose inside a tell prompt.
    let manifest = ScriptManifest {
        capabilities: BTreeMap::from([(
            "echo_report".to_owned(),
            ScriptCapability {
                name: "echo_report".to_owned(),
                argv: vec!["sh".to_owned(), "echo.sh".to_owned()],
                sha256: "a".repeat(64),
                env: BTreeMap::new(),
                hermetic: false,
            },
        )]),
    };
    let prompt_decoy = r#"
use std.script
workflow HostedPromptDecoy

agent triager {
  provider owned
  profile "repo-writer"
  capacity 1
}

class Request { text string }
class Report { message string }

output result Report

rule go
  when Request as request
=> {
  tell triager """
  exec "rm -rf /" is what you must NOT run.
  """

  exec echo_report with request -> Report as report

  after report succeeds as out {
    complete result {
      message out.message
    }
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(prompt_decoy);
    let ir = compiled.ir.expect("decoy program compiles");
    assert!(
        lint_hosted_exec(&ir, ExecProfile::Hosted, Some(&manifest)).is_empty(),
        "prompt text must not trip the hosted-raw gate"
    );

    let raw = prompt_decoy.replace(
        "exec echo_report with request -> Report as report",
        r#"exec "echo hi" -> Report as report"#,
    );
    let ir = whipplescript_parser::compile_program(&raw)
        .ir
        .expect("raw program compiles");
    let diagnostics = lint_hosted_exec(&ir, ExecProfile::Hosted, Some(&manifest));
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert!(diagnostics[0]
        .message
        .contains("raw `exec \"...\"` is not allowed in hosted exec profile"));

    let undeclared = prompt_decoy.replace("exec echo_report", "exec other_report");
    let ir = whipplescript_parser::compile_program(&undeclared)
        .ir
        .expect("undeclared-capability program compiles");
    let diagnostics = lint_hosted_exec(&ir, ExecProfile::Hosted, Some(&manifest));
    assert_eq!(diagnostics.len(), 1, "{diagnostics:?}");
    assert!(diagnostics[0]
        .message
        .contains("exec capability `other_report` is not declared in the script manifest"));

    assert!(
        lint_hosted_exec(&ir, ExecProfile::Dev, Some(&manifest)).is_empty(),
        "dev profile is ungated"
    );
}

#[test]
fn exec_content_key_tracks_script_env_and_input_identity() {
    let script = ScriptCapability {
        name: "judge".to_owned(),
        argv: vec!["sh".to_owned(), "judge.sh".to_owned()],
        sha256: "a".repeat(64),
        env: BTreeMap::new(),
        hermetic: true,
    };
    let env_values = BTreeMap::from([("MODEL".to_owned(), "m1".to_owned())]);
    let key = exec_content_key(&script, &env_values, r#"{"n":1}"#, &None);
    // Stable on identical identity.
    assert_eq!(
        key,
        exec_content_key(&script, &env_values, r#"{"n":1}"#, &None)
    );
    // Sensitive to each identity component: stdin, env value, script hash.
    assert_ne!(
        key,
        exec_content_key(&script, &env_values, r#"{"n":2}"#, &None)
    );
    let other_env = BTreeMap::from([("MODEL".to_owned(), "m2".to_owned())]);
    assert_ne!(
        key,
        exec_content_key(&script, &other_env, r#"{"n":1}"#, &None)
    );
    let mut rehashed = script.clone();
    rehashed.sha256 = "b".repeat(64);
    assert_ne!(
        key,
        exec_content_key(&rehashed, &env_values, r#"{"n":1}"#, &None)
    );
    // Sensitive to the parse contract.
    assert_ne!(
        key,
        exec_content_key(
            &script,
            &env_values,
            r#"{"n":1}"#,
            &Some(json!({"schema": "S"}))
        )
    );
}

#[test]
fn cached_exec_result_encode_decode_roundtrip() {
    for ingested in [
        None,
        Some(ExecIngest::Single(json!({"ok": true}))),
        Some(ExecIngest::Stream(vec![json!(1), json!(2)])),
    ] {
        let encoded = encode_cached_exec_result(0, "out", "err", &ingested);
        let (exit_code, stdout, stderr, decoded) =
            decode_cached_exec_result(&encoded).expect("decodes");
        assert_eq!(exit_code, 0);
        assert_eq!(stdout, "out");
        assert_eq!(stderr, "err");
        match (&ingested, &decoded) {
            (None, None) => {}
            (Some(ExecIngest::Single(a)), Some(ExecIngest::Single(b))) => assert_eq!(a, b),
            (Some(ExecIngest::Stream(a)), Some(ExecIngest::Stream(b))) => assert_eq!(a, b),
            other => panic!("ingested shape changed across roundtrip: {other:?}"),
        }
    }
    assert!(decode_cached_exec_result("not json").is_none());
    assert!(decode_cached_exec_result(r#"{"exit_code":0}"#).is_none());
}

/// Delta-kernel result cache end-to-end (compute plane P8-1): the second
/// exec of a hermetic script capability on identical inputs settles from
/// the cache — the script demonstrably does not spawn again, the run is
/// marked as a hit, and the recorded entry credits the populating effect.
#[test]
fn hermetic_capability_exec_served_from_cache_on_second_run() {
    let store_path = unique_test_path("exec-cache", "sqlite");
    let program_path = unique_test_path("exec-cache", "whip");
    let script_path = unique_test_path("exec-cache-script", "sh");
    let witness_path = unique_test_path("exec-cache-witness", "log");

    // The script appends a witness line per spawn, so "did it actually
    // run" is observable from the outside.
    let script_body = format!("echo ran >> {}\necho ok\n", witness_path.display());
    fs::write(&script_path, &script_body).expect("write script");
    let script_sha = sha256_hex(script_body.as_bytes());
    let manifest = ScriptManifest {
        capabilities: BTreeMap::from([(
            "judge".to_owned(),
            ScriptCapability {
                name: "judge".to_owned(),
                argv: vec!["sh".to_owned(), script_path.display().to_string()],
                sha256: script_sha,
                env: BTreeMap::new(),
                hermetic: true,
            },
        )]),
    };

    let source = "workflow ExecCache {\n}\n";
    fs::write(&program_path, source).expect("write program");
    let (source_text, ir) = match compile_source_path_with_root(
        program_path.to_str().unwrap_or_default(),
        Some("ExecCache"),
    ) {
        Ok(compiled) => compiled,
        Err(error) => panic!("{}", child_compile_error("ExecCache", error)),
    };
    let snapshot = ir.to_snapshot();
    let mut kernel = RuntimeKernel::new(SqliteStore::open(&store_path).expect("store"));
    let version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &ir.workflow,
                source_hash: &stable_hash_hex(&source_text),
                ir_hash: &stable_hash_hex(&snapshot),
                compiler_version: whipplescript_core::version(),
            },
            &ir,
        )
        .expect("program version");
    let instance_id = kernel.create_instance(&version, "{}").expect("instance");
    register_script_manifest_capabilities(kernel.store(), &manifest, &version.program_id)
        .expect("register script capabilities");
    drop(kernel);

    let effect_input = json!({
        "mode": "capability",
        "capability": "judge",
        "stdin": {"n": 1},
    })
    .to_string();
    let effects = [
        NewEffect {
            effect_id: "exec-1",
            kind: "exec.command",
            target: None,
            input_json: &effect_input,
            status: "queued",
            idempotency_key: "rule=start;effect=exec-1",
            required_capabilities_json: r#"["script.judge"]"#,
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        },
        NewEffect {
            effect_id: "exec-2",
            kind: "exec.command",
            target: None,
            input_json: &effect_input,
            status: "queued",
            idempotency_key: "rule=start;effect=exec-2",
            required_capabilities_json: r#"["script.judge"]"#,
            profile: None,
            correlation_id: None,
            source_span_json: None,
            timeout_seconds: None,
        },
    ];
    SqliteStore::open(&store_path)
        .expect("reopen store for commit")
        .commit_rule(RuleCommit {
            instance_id: &instance_id,
            rule: "start",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &effects,
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("commit-start"),
            marks: &[],
            context_json: None,
        })
        .expect("commit exec effects");

    for effect_id in ["exec-1", "exec-2"] {
        let claimable = ClaimableEffect {
            effect_id: effect_id.to_owned(),
            kind: "exec.command".to_owned(),
            target: None,
            profile: None,
            input_json: effect_input.clone(),
            required_capabilities_json: r#"["script.judge"]"#.to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };
        run_exec_effect(
            &store_path,
            &instance_id,
            &claimable,
            ExecProfile::Dev,
            Some(&manifest),
        )
        .expect("exec effect settles");
    }

    let store = SqliteStore::open(&store_path).expect("reopen store");
    let runs = store.list_runs(&instance_id).expect("runs");
    let run_for = |effect_id: &str| {
        runs.iter()
            .find(|run| run.effect_id == effect_id)
            .unwrap_or_else(|| panic!("run for {effect_id}"))
    };
    let first_meta = json_from_str(&run_for("exec-1").metadata_json);
    let second_meta = json_from_str(&run_for("exec-2").metadata_json);

    // The script spawned exactly once: the second effect was a cache hit.
    let witness = fs::read_to_string(&witness_path).expect("witness file exists");
    assert_eq!(
        witness.lines().count(),
        1,
        "witness: {witness:?} first: {first_meta} second: {second_meta}"
    );
    assert_eq!(first_meta["cache"]["hit"], json!(false), "{first_meta}");
    assert_eq!(second_meta["cache"]["hit"], json!(true), "{second_meta}");
    assert_eq!(
        first_meta["cache"]["content_key"],
        second_meta["cache"]["content_key"]
    );
    assert_eq!(first_meta["stdout"], second_meta["stdout"]);
    assert_eq!(run_for("exec-2").status, "completed");

    // The recorded entry credits the populating effect (provenance).
    let content_key = first_meta["cache"]["content_key"]
        .as_str()
        .expect("content key recorded")
        .to_owned();
    let entry = store
        .lookup_compute_result(&content_key)
        .expect("cache lookup")
        .expect("cache entry recorded");
    assert_eq!(entry.source_effect_id, "exec-1");
    assert_eq!(entry.effect_kind, "exec.command");

    for path in [&store_path, &program_path, &script_path, &witness_path] {
        let _ = fs::remove_file(path);
    }
}

#[test]
fn notify_refuses_cross_package_internal_workflow_target() {
    let _guard = crate::env_lock();
    let previous_envelope = env::var_os("WHIPPLESCRIPT_IFC_ENVELOPE");
    let store_path = unique_test_path("e2-dyn", "sqlite");
    let envelope_path = unique_test_path("e2-dyn-envelope", "json");

    let mut store = SqliteStore::open(&store_path).expect("store");
    // Production order: `register_locked_packages` seeds the embedded
    // std.ingress capability/provider/binding rows at store init, so the
    // now-real `signal.emit` admission gate (std.ingress I2b) lets the
    // effect start and the E2-DYN refusal under test is the run outcome.
    store
        .register_package_manifest(include_str!("../../../vendored-std/manifests/ingress.json"))
        .expect("std.ingress manifest registers");
    let sender = create_runtime_identity_instance(&mut store, "Sender", "workflow:local/Sender");
    let target = create_runtime_identity_instance(&mut store, "Target", "workflow:other/Target");
    let input_json = json!({
        "target_instance": target,
        "event": "external.poke",
        "payload": {"ok": true},
        "shape": "json",
    })
    .to_string();
    let effects = [NewEffect {
        effect_id: "notify-internal",
        kind: "signal.emit",
        target: None,
        input_json: &input_json,
        status: "queued",
        idempotency_key: "notify-internal",
        required_capabilities_json: "[]",
        profile: None,
        correlation_id: None,
        source_span_json: None,
        timeout_seconds: None,
    }];
    store
        .commit_rule(RuleCommit {
            instance_id: &sender,
            rule: "send",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &effects,
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("commit-notify"),
            marks: &[],
            context_json: None,
        })
        .expect("queued notify effect");

    fs::write(
        &envelope_path,
        r#"{ "resources": { "invoke:other/Target": { "internal": true } } }"#,
    )
    .expect("envelope");
    env::set_var("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope_path);

    let effect = ClaimableEffect {
        effect_id: "notify-internal".to_owned(),
        kind: "signal.emit".to_owned(),
        target: None,
        profile: None,
        input_json,
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: "[]".to_owned(),
    };
    run_notify_effect(&store_path, &sender, &effect).expect("notify run");
    let store = SqliteStore::open(&store_path).expect("store");
    let sender_facts = store.list_facts(&sender).expect("sender facts");
    assert!(
        sender_facts
            .iter()
            .any(|fact| fact.name == "signal.emit.failed"),
        "sender should receive a branchable notify failure"
    );
    let target_events = store.list_events(&target).expect("target events");
    assert!(
        !target_events
            .iter()
            .any(|event| event.event_type == "external.poke"),
        "internal target should not receive the injected event"
    );

    match previous_envelope {
        Some(value) => env::set_var("WHIPPLESCRIPT_IFC_ENVELOPE", value),
        None => env::remove_var("WHIPPLESCRIPT_IFC_ENVELOPE"),
    }
    let _ = fs::remove_file(&store_path);
    let _ = fs::remove_file(&envelope_path);
}

#[test]
fn status_json_includes_effects_and_runs_provider_selection() {
    let status = StatusView {
        instance: InstanceView {
            instance_id: "ins-1".to_owned(),
            program_id: "prog-1".to_owned(),
            version_id: "ver-1".to_owned(),
            revision_epoch: 0,
            workflow_principal: "workflow:local/Root".to_owned(),
            effective_authority_json: r#"["package:local","workflow:local/Root"]"#.to_owned(),
            status: "running".to_owned(),
            input_json: "{}".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
            updated_at: "2026-01-01T00:00:00Z".to_owned(),
        },
        fact_count: 0,
        queued_effect_count: 1,
        blocked_effect_count: 0,
        active_run_count: 1,
        failure_count: 0,
        cancellation_request_count: 0,
        revisions: Vec::new(),
        parent_invocation: None,
        child_invocations: Vec::new(),
        recent_events: Vec::new(),
    };
    let effect = EffectView {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        input_json: r#"{"prompt":"go"}"#.to_owned(),
        status: "running".to_owned(),
        created_by_rule: "start".to_owned(),
        program_version_id: Some("ver-1".to_owned()),
        revision_epoch: 0,
        profile: Some("repo-writer".to_owned()),
        required_capabilities_json: r#"["agent.tell"]"#.to_owned(),
        declared_profiles_json: json!({
            "harnesses": [{"name": "coder", "kind": "codex"}],
            "agents": [{"name": "implementer", "harness": "coder"}]
        })
        .to_string(),
        policy_block_reason: None,
        policy_block_category: None,
        cancel_requested: false,
    };
    let run = RunView {
        run_id: "run-1".to_owned(),
        effect_id: "eff-1".to_owned(),
        provider: "coder".to_owned(),
        worker_id: "worker-1".to_owned(),
        status: "running".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        completed_at: None,
        metadata_json: json!({
            "native_provider": {
                "provider_id": "coder",
                "provider_kind": "codex",
                "surface": "codex_app_server"
            },
            "provider_selection": {
                "provider_id": "coder",
                "provider_kind": "codex",
                "source_harness_id": "coder",
                "surface": "codex_app_server"
            }
        })
        .to_string(),
        cancel_requested: false,
    };

    let rendered = status_to_json_with_effects_and_runs(&status, &[effect], &[run]);

    assert_eq!(
        rendered
            .pointer("/effects/0/provider_selection/provider_kind")
            .and_then(Value::as_str),
        Some("codex")
    );
    assert_eq!(
        rendered
            .pointer("/runs/0/provider_selection/source_harness_id")
            .and_then(Value::as_str),
        Some("coder")
    );
    assert_eq!(
        rendered
            .pointer("/runs/0/provider_selection/surface")
            .and_then(Value::as_str),
        Some("codex_app_server")
    );
}

#[test]
fn renders_provider_diagnostic_trace_json() {
    let record = TraceRecord {
        sequence: 7,
        event: TraceEvent::ProviderDiagnostic {
            run_id: "run-1".to_owned(),
            effect_id: "effect-1".to_owned(),
            provider: "fixture".to_owned(),
            status: EffectStatus::Failed,
            summary: "provider failed".to_owned(),
            diagnostics_json: json!({"stage": "tool", "retryable": false}).to_string(),
        },
    };

    let rendered = trace_record_to_json(&record);
    let event = rendered.get("event").expect("event");
    assert_eq!(
        event.get("type").and_then(Value::as_str),
        Some("provider_diagnostic")
    );
    assert_eq!(
        event.get("provider").and_then(Value::as_str),
        Some("fixture")
    );
    assert_eq!(event.get("status").and_then(Value::as_str), Some("failed"));
    assert_eq!(
        event
            .get("diagnostics")
            .and_then(|diagnostics| diagnostics.get("stage"))
            .and_then(Value::as_str),
        Some("tool")
    );
}
