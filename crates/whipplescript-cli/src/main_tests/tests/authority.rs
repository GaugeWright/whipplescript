//! Workflow authority derivation, start grants, and delegated-child narrowing.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
#[test]
fn workflow_authority_mints_package_and_workflow_principals() {
    let mut ir = empty_ir_program();
    ir.workflow = "Review".to_owned();
    let (principal, authority_json) = authority_for_ir(&ir);

    assert_eq!(principal, "workflow:local/Review");
    assert_eq!(
        json_from_str(&authority_json),
        json!(["package:local", "workflow:local/Review"])
    );
}

#[test]
fn package_child_start_persists_package_workflow_principal() {
    let store_path = unique_test_path("package-child-authority", "sqlite");
    let program_path = unique_test_path("package-child-authority", "whip");
    let source = r#"
workflow Tool {
  file store project_files {
    root "."
    allow read ["**"]
  }
}
"#;

    fs::write(&program_path, source).expect("write program");
    let (started, _ir) = start_child_workflow_instance_in_package(
        &store_path,
        &program_path,
        "Tool",
        "{}",
        "pkg-tools",
        ChildStartAuthority::non_delegating(),
    )
    .expect("child starts");
    let store = SqliteStore::open(&store_path).expect("reopen store");
    let child_instance = store
        .get_instance(&started.instance_id)
        .expect("get child")
        .expect("child row");

    assert_eq!(child_instance.workflow_principal, "workflow:pkg-tools/Tool");
    assert_eq!(
        json_from_str(&child_instance.effective_authority_json),
        json!([
            "package:pkg-tools",
            "resource:project_files/export",
            "resource:project_files/import",
            "resource:project_files/read",
            "resource:project_files/write",
            "workflow:pkg-tools/Tool",
        ])
    );

    let _ = fs::remove_file(&program_path);
    let _ = fs::remove_file(&store_path);
}

#[test]
fn package_tool_ifc_surface_includes_package_invoke_door() {
    let tool_ir = whipplescript_parser::compile_program(
        r#"@tool
workflow EchoText
input request Q
output result R
class Q { text string }
class R { text string }
rule go
  when Q as request
=> {
  complete result { text request.text }
}
"#,
    )
    .ir
    .expect("tool compiles");

    let surface = package_tool_ifc_surface("toolkit", "EchoText", &tool_ir);

    assert!(surface.contains(&"invoke:toolkit/EchoText".to_owned()));
}

#[test]
fn workflow_authority_includes_declared_file_store_operations() {
    let mut ir = empty_ir_program();
    ir.workflow = "Review".to_owned();
    ir.file_stores.push(whipplescript_parser::IrFileStore {
        name: "project_files".to_owned(),
        root: ".".to_owned(),
        read_globs: vec!["src/**".to_owned()],
        write_globs: vec!["src/**".to_owned()],
        provider: None,
    });

    let (_principal, authority_json) = authority_for_ir(&ir);

    assert_eq!(
        json_from_str(&authority_json),
        json!([
            "package:local",
            "resource:project_files/export",
            "resource:project_files/import",
            "resource:project_files/read",
            "resource:project_files/write",
            "workflow:local/Review",
        ])
    );
}

#[test]
fn attenuated_authority_uses_package_ancestor_for_workflows() {
    let declared = json!(["package:local", "workflow:local/Child"]).to_string();
    let same_package_parent = json!(["package:local", "workflow:local/Parent"]).to_string();
    assert_eq!(
        json_from_str(&attenuated_authority_json(&declared, &same_package_parent)),
        json!(["package:local", "workflow:local/Child"])
    );

    let different_package_parent = json!(["package:other", "workflow:other/Parent"]).to_string();
    assert_eq!(
        json_from_str(&attenuated_authority_json(
            &declared,
            &different_package_parent
        )),
        json!([])
    );
}

#[test]
fn start_grant_narrows_authority_below_the_automatic_cap() {
    let declared = json!([
        "package:local",
        "resource:project_files/read",
        "resource:project_files/write",
        "workflow:local/Child",
    ])
    .to_string();
    let parent_effective = json!([
        "package:local",
        "resource:project_files/read",
        "resource:project_files/write",
        "workflow:local/Parent",
    ])
    .to_string();
    let grant = BTreeSet::from(["resource:project_files/read".to_owned()]);

    let narrowed = attenuated_authority_json_with_grant(&declared, &parent_effective, Some(&grant))
        .expect("grant is within cap");

    assert_eq!(
        json_from_str(&narrowed),
        json!(["resource:project_files/read"])
    );
}

#[test]
fn start_grant_rejects_never_widen_violation() {
    let declared = json!([
        "resource:project_files/read",
        "resource:project_files/write"
    ])
    .to_string();
    let parent_effective = json!(["resource:project_files/read"]).to_string();
    let grant = BTreeSet::from([
        "resource:project_files/read".to_owned(),
        "resource:project_files/write".to_owned(),
    ]);

    let error = attenuated_authority_json_with_grant(&declared, &parent_effective, Some(&grant))
        .expect_err("grant must not widen");

    assert_eq!(error, vec!["resource:project_files/write"]);
}

#[test]
fn no_start_grant_uses_the_automatic_authority_cap() {
    let declared = json!([
        "package:local",
        "resource:project_files/read",
        "resource:project_files/write",
        "workflow:local/Child",
    ])
    .to_string();
    let parent_effective =
        json!(["resource:project_files/read", "workflow:local/Parent",]).to_string();

    let automatic_cap = attenuated_authority_json_with_grant(&declared, &parent_effective, None)
        .expect("automatic cap is well-formed");

    assert_eq!(
        json_from_str(&automatic_cap),
        json!(["resource:project_files/read"])
    );
}

#[test]
fn start_grant_authority_uses_operation_principals() {
    let grants = json!([
        {
            "resource": "project_files",
            "operations": [
                {"operation": "read", "target": null, "globs": ["src/**"]},
                {"operation": "write", "target": null, "globs": ["src/generated/**"]},
            ]
        }
    ]);

    let authority = start_grant_authority_from_value(Some(&grants))
        .expect("well-formed grants")
        .expect("non-empty grants");

    assert_eq!(
        authority,
        BTreeSet::from([
            "resource:project_files/read".to_owned(),
            "resource:project_files/write".to_owned(),
        ])
    );
}

#[test]
fn delegating_child_start_persists_start_grant_narrowed_authority() {
    let store_path = unique_test_path("start-grant-authority", "sqlite");
    let program_path = unique_test_path("start-grant-authority", "whip");
    let source = r#"
workflow Parent {
  file store project_files {
    root "."
    allow read ["**"]
    allow write ["**"]
  }
}

workflow Child {
  file store project_files {
    root "."
    allow read ["**"]
    allow write ["**"]
  }
}
"#;

    fs::write(&program_path, source).expect("write program");
    let (source_text, parent_ir) = match compile_source_path_with_root(
        program_path.to_str().unwrap_or_default(),
        Some("Parent"),
    ) {
        Ok(compiled) => compiled,
        Err(error) => panic!("{}", child_compile_error("Parent", error)),
    };
    let snapshot = parent_ir.to_snapshot();
    let mut kernel = RuntimeKernel::new(SqliteStore::open(&store_path).expect("store"));
    let parent_version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &parent_ir.workflow,
                source_hash: &stable_hash_hex(&source_text),
                ir_hash: &stable_hash_hex(&snapshot),
                compiler_version: whipplescript_core::version(),
            },
            &parent_ir,
        )
        .expect("parent version");
    let (parent_principal, parent_authority) = authority_for_ir(&parent_ir);
    let parent_instance_id = kernel
        .create_instance_with_authority(
            &parent_version,
            "{}",
            NewInstanceAuthority {
                workflow_principal: &parent_principal,
                effective_authority_json: &parent_authority,
            },
        )
        .expect("parent instance");
    let grant = BTreeSet::from(["resource:project_files/read".to_owned()]);
    let (child, _child_ir) = start_child_workflow_instance(
        &store_path,
        &program_path,
        "Child",
        "{}",
        ChildStartAuthority::delegating(&parent_instance_id, Some(grant)),
    )
    .expect("child starts");
    let store = SqliteStore::open(&store_path).expect("reopen store");
    let child_instance = store
        .get_instance(&child.instance_id)
        .expect("get child")
        .expect("child row");

    assert_eq!(
        json_from_str(&child_instance.effective_authority_json),
        json!(["resource:project_files/read"])
    );

    let _ = fs::remove_file(&program_path);
    let _ = fs::remove_file(&store_path);
}

#[test]
fn delegating_child_start_without_grant_persists_automatic_cap() {
    let store_path = unique_test_path("automatic-cap-authority", "sqlite");
    let program_path = unique_test_path("automatic-cap-authority", "whip");
    let source = r#"
workflow Parent {
  file store project_files {
    root "."
    allow read ["**"]
  }
}

workflow Child {
  file store project_files {
    root "."
    allow read ["**"]
    allow write ["**"]
  }
}
"#;

    fs::write(&program_path, source).expect("write program");
    let (source_text, parent_ir) = match compile_source_path_with_root(
        program_path.to_str().unwrap_or_default(),
        Some("Parent"),
    ) {
        Ok(compiled) => compiled,
        Err(error) => panic!("{}", child_compile_error("Parent", error)),
    };
    let snapshot = parent_ir.to_snapshot();
    let mut kernel = RuntimeKernel::new(SqliteStore::open(&store_path).expect("store"));
    let parent_version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &parent_ir.workflow,
                source_hash: &stable_hash_hex(&source_text),
                ir_hash: &stable_hash_hex(&snapshot),
                compiler_version: whipplescript_core::version(),
            },
            &parent_ir,
        )
        .expect("parent version");
    let (parent_principal, _parent_authority) = authority_for_ir(&parent_ir);
    let narrowed_parent_authority =
        json!(["resource:project_files/read", "workflow:local/Parent"]).to_string();
    let parent_instance_id = kernel
        .create_instance_with_authority(
            &parent_version,
            "{}",
            NewInstanceAuthority {
                workflow_principal: &parent_principal,
                effective_authority_json: &narrowed_parent_authority,
            },
        )
        .expect("parent instance");
    let (child, _child_ir) = start_child_workflow_instance(
        &store_path,
        &program_path,
        "Child",
        "{}",
        ChildStartAuthority::delegating(&parent_instance_id, None),
    )
    .expect("child starts");
    let store = SqliteStore::open(&store_path).expect("reopen store");
    let child_instance = store
        .get_instance(&child.instance_id)
        .expect("get child")
        .expect("child row");

    assert_eq!(
        json_from_str(&child_instance.effective_authority_json),
        json!(["resource:project_files/read"])
    );

    let _ = fs::remove_file(&program_path);
    let _ = fs::remove_file(&store_path);
}

/// Commit the queued `workflow.invoke` effect the delegated-invoke tests share,
/// and hand back the claim and the worker options a worker would run it with.
/// Takes the kernel by value because the commit reopens the store: the kernel's
/// own connection has to be gone first, which the `drop` below makes the
/// compiler's business rather than each caller's.
fn queued_invoke_child(
    kernel: RuntimeKernel<SqliteStore>,
    store_path: &Path,
    program_path: &Path,
    parent_instance_id: &str,
) -> (ClaimableEffect, WorkerOptions) {
    let effect_input = json!({
        "target_workflow": "Child",
        "input": {}
    })
    .to_string();
    let effects = [NewEffect {
        effect_id: "invoke-child",
        kind: "workflow.invoke",
        target: Some("Child"),
        input_json: &effect_input,
        status: "queued",
        idempotency_key: "rule=start;effect=invoke-child",
        required_capabilities_json: r#"["workflow.invoke"]"#,
        profile: None,
        correlation_id: None,
        source_span_json: None,
        timeout_seconds: None,
    }];
    drop(kernel);
    SqliteStore::open(store_path)
        .expect("reopen store for commit")
        .commit_rule(RuleCommit {
            instance_id: parent_instance_id,
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
        .expect("commit invoke effect");

    let claimable = ClaimableEffect {
        effect_id: "invoke-child".to_owned(),
        kind: "workflow.invoke".to_owned(),
        target: Some("Child".to_owned()),
        profile: None,
        input_json: effect_input,
        required_capabilities_json: r#"["workflow.invoke"]"#.to_owned(),
        declared_profiles_json: "[]".to_owned(),
    };
    let options = WorkerOptions {
        instance_id: parent_instance_id.to_owned(),
        provider: "fixture".to_owned(),
        exec_profile: ExecProfile::from_env(),
        script_manifest_path: None,
        package_lock_path: None,
        outcome: FixtureOutcome::Completed,
        variant: None,
        program_path: Some(program_path.to_path_buf()),
        root: Some("Parent".to_owned()),
        provider_config_paths: Vec::new(),
        max_child_iterations: 0,
        agent_outcomes: BTreeMap::new(),
        coerce_outputs: BTreeMap::new(),
        virtual_now: None,
        work_unit_root: None,
        side_stores: None,
    };

    (claimable, options)
}

#[test]
fn workflow_invoke_without_grant_starts_child_under_automatic_cap() {
    let store_path = unique_test_path("invoke-automatic-cap-authority", "sqlite");
    let program_path = unique_test_path("invoke-automatic-cap-authority", "whip");
    let source = r#"
workflow Parent {
  file store project_files {
    root "."
    allow read ["**"]
  }
}

workflow Child {
  file store project_files {
    root "."
    allow read ["**"]
    allow write ["**"]
  }
}
"#;

    fs::write(&program_path, source).expect("write program");
    let (source_text, parent_ir) = match compile_source_path_with_root(
        program_path.to_str().unwrap_or_default(),
        Some("Parent"),
    ) {
        Ok(compiled) => compiled,
        Err(error) => panic!("{}", child_compile_error("Parent", error)),
    };
    let snapshot = parent_ir.to_snapshot();
    let mut kernel = RuntimeKernel::new(SqliteStore::open(&store_path).expect("store"));
    let parent_version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &parent_ir.workflow,
                source_hash: &stable_hash_hex(&source_text),
                ir_hash: &stable_hash_hex(&snapshot),
                compiler_version: whipplescript_core::version(),
            },
            &parent_ir,
        )
        .expect("parent version");
    let (parent_principal, _parent_authority) = authority_for_ir(&parent_ir);
    let narrowed_parent_authority =
        json!(["resource:project_files/read", "workflow:local/Parent"]).to_string();
    let parent_instance_id = kernel
        .create_instance_with_authority(
            &parent_version,
            "{}",
            NewInstanceAuthority {
                workflow_principal: &parent_principal,
                effective_authority_json: &narrowed_parent_authority,
            },
        )
        .expect("parent instance");
    let (claimable, options) =
        queued_invoke_child(kernel, &store_path, &program_path, &parent_instance_id);

    run_workflow_invoke_effect(&store_path, &parent_instance_id, &claimable, &options)
        .expect("invoke effect starts child");

    let store = SqliteStore::open(&store_path).expect("reopen store");
    let invocation = store
        .get_workflow_invocation(&parent_instance_id, "invoke-child")
        .expect("get invocation")
        .expect("invocation row");
    let child_instance = store
        .get_instance(&invocation.child_instance_id)
        .expect("get child")
        .expect("child row");

    assert_eq!(
        json_from_str(&child_instance.effective_authority_json),
        json!(["resource:project_files/read"])
    );

    let _ = fs::remove_file(&program_path);
    let _ = fs::remove_file(&store_path);
}

#[test]
fn workflow_invoke_preserves_parent_package_identity_for_child_start() {
    let store_path = unique_test_path("invoke-package-authority", "sqlite");
    let program_path = unique_test_path("invoke-package-authority", "whip");
    let source = r#"
workflow Parent {
  file store project_files {
    root "."
    allow read ["**"]
  }
}

workflow Child {
  file store project_files {
    root "."
    allow read ["**"]
    allow write ["**"]
  }
}
"#;

    fs::write(&program_path, source).expect("write program");
    let (source_text, parent_ir) = match compile_source_path_with_root(
        program_path.to_str().unwrap_or_default(),
        Some("Parent"),
    ) {
        Ok(compiled) => compiled,
        Err(error) => panic!("{}", child_compile_error("Parent", error)),
    };
    let snapshot = parent_ir.to_snapshot();
    let mut kernel = RuntimeKernel::new(SqliteStore::open(&store_path).expect("store"));
    let parent_version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &parent_ir.workflow,
                source_hash: &stable_hash_hex(&source_text),
                ir_hash: &stable_hash_hex(&snapshot),
                compiler_version: whipplescript_core::version(),
            },
            &parent_ir,
        )
        .expect("parent version");
    let parent_instance_id = kernel
        .create_instance_with_authority(
            &parent_version,
            "{}",
            NewInstanceAuthority {
                workflow_principal: "workflow:pkg-suite/Parent",
                effective_authority_json: &json!([
                    "package:pkg-suite",
                    "resource:project_files/read",
                    "workflow:pkg-suite/Parent",
                ])
                .to_string(),
            },
        )
        .expect("parent instance");
    let (claimable, options) =
        queued_invoke_child(kernel, &store_path, &program_path, &parent_instance_id);

    run_workflow_invoke_effect(&store_path, &parent_instance_id, &claimable, &options)
        .expect("invoke effect starts child");

    let store = SqliteStore::open(&store_path).expect("reopen store");
    let invocation = store
        .get_workflow_invocation(&parent_instance_id, "invoke-child")
        .expect("get invocation")
        .expect("invocation row");
    let child_instance = store
        .get_instance(&invocation.child_instance_id)
        .expect("get child")
        .expect("child row");

    assert_eq!(
        child_instance.workflow_principal,
        "workflow:pkg-suite/Child"
    );
    assert_eq!(
        json_from_str(&child_instance.effective_authority_json),
        json!([
            "package:pkg-suite",
            "resource:project_files/read",
            "workflow:pkg-suite/Child",
        ])
    );

    let _ = fs::remove_file(&program_path);
    let _ = fs::remove_file(&store_path);
}

#[test]
fn delegating_workflow_invoke_refuses_child_ifc_violation() {
    let _guard = crate::env_lock();
    let previous_envelope = env::var_os("WHIPPLESCRIPT_IFC_ENVELOPE");
    let store_path = unique_test_path("invoke-child-ifc-admission", "sqlite");
    let program_path = unique_test_path("invoke-child-ifc-admission", "whip");
    let envelope_path = unique_test_path("invoke-child-ifc-admission-envelope", "json");
    let source = r#"
workflow Parent {
}

@service
workflow Child {
  output result R
  class R { ok bool }
  class Ticket { id string  status "open" }

  agent coder { provider fixture  profile "repo-reader"  capacity 1 }
  file store ledger { root "./ledger"  allow read ["**"] }

  table seed as Ticket [ { id "T1"  status "open" } ]

  rule work
    when Ticket as ticket where ticket.status == "open"
    when coder is available
  => {
    tell coder as turn
      with access to ledger {
        read ["**"]
      }
    "go"

    after turn succeeds as outcome {
      complete result { ok true }
    }
  }
}
"#;

    fs::write(&program_path, source).expect("write program");
    fs::write(
        &envelope_path,
        r#"{ "resources": { "ledger": { "confidential": true } } }"#,
    )
    .expect("write envelope");
    env::set_var("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope_path);

    let (source_text, parent_ir) = match compile_source_path_with_root(
        program_path.to_str().unwrap_or_default(),
        Some("Parent"),
    ) {
        Ok(compiled) => compiled,
        Err(error) => panic!("{}", child_compile_error("Parent", error)),
    };
    let snapshot = parent_ir.to_snapshot();
    let mut kernel = RuntimeKernel::new(SqliteStore::open(&store_path).expect("store"));
    let parent_version = kernel
        .create_program_version_for_program(
            ProgramVersionInput {
                program_name: &parent_ir.workflow,
                source_hash: &stable_hash_hex(&source_text),
                ir_hash: &stable_hash_hex(&snapshot),
                compiler_version: whipplescript_core::version(),
            },
            &parent_ir,
        )
        .expect("parent version");
    let (parent_principal, parent_authority) = authority_for_ir(&parent_ir);
    let parent_instance_id = kernel
        .create_instance_with_authority(
            &parent_version,
            "{}",
            NewInstanceAuthority {
                workflow_principal: &parent_principal,
                effective_authority_json: &parent_authority,
            },
        )
        .expect("parent instance");
    let (claimable, options) =
        queued_invoke_child(kernel, &store_path, &program_path, &parent_instance_id);

    let _terminal =
        run_workflow_invoke_effect(&store_path, &parent_instance_id, &claimable, &options)
            .expect("invoke effect records a recoverable failure");

    let store = SqliteStore::open(&store_path).expect("reopen store");
    assert!(
        store
            .get_workflow_invocation(&parent_instance_id, "invoke-child")
            .expect("get invocation")
            .is_none(),
        "a child refused at IFC admission must not persist an invocation link"
    );
    let invoke = store
        .list_effects(&parent_instance_id)
        .expect("list effects")
        .into_iter()
        .find(|effect| effect.effect_id == "invoke-child")
        .expect("invoke effect exists");
    assert_eq!(invoke.status, "failed");

    match previous_envelope {
        Some(value) => env::set_var("WHIPPLESCRIPT_IFC_ENVELOPE", value),
        None => env::remove_var("WHIPPLESCRIPT_IFC_ENVELOPE"),
    }
    let _ = fs::remove_file(&program_path);
    let _ = fs::remove_file(&store_path);
    let _ = fs::remove_file(&envelope_path);
}

#[test]
fn coordination_owner_strips_workflow_principal_prefix() {
    assert_eq!(
        coordination_owner_from_principal("workflow:local/Review").as_deref(),
        Some("local/Review")
    );
    assert_eq!(coordination_owner_from_principal(""), None);
}
