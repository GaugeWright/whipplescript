//! Extracted verbatim from `main.rs` (module path `tests` is unchanged).

/// The `whip mcp` subcommands are the only writers of trust evidence — the
/// pin, the attestation, the role file — so they are exactly the surface
/// that should not be hand-validated only. Driven sequentially in one test
/// because they share the process-global `WHIPPLESCRIPT_MCP_CONFIG`.
#[test]
fn whip_mcp_subcommands_write_and_gate_trust_evidence() {
    let _guard = crate::env_lock();
    let dir = std::env::temp_dir().join(format!("whip-mcp-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let config = dir.join("mcp.json");
    std::env::set_var("WHIPPLESCRIPT_MCP_CONFIG", &config);

    let opts = |args: &[&str]| CliOptions {
        command: Some("mcp".to_owned()),
        args: args.iter().map(|a| (*a).to_string()).collect(),
        store_path: dir.join("store.sqlite"),
        json: false,
        input_json: None,
    };

    // A plaintext remote endpoint is refused at `add`, before it is stored.
    assert_eq!(
        format!(
            "{:?}",
            mcp_command(&opts(&["add", "bad", "--url", "http://mcp.example.com/x"]))
        ),
        format!("{:?}", ExitCode::FAILURE)
    );
    assert!(mcp_tools::load_registry().expect("registry").is_empty());

    // A stdio server is stored, and lands at rung 0 — adding is not trusting.
    assert_eq!(
        format!(
            "{:?}",
            mcp_command(&opts(&["add", "srv", "--command", "true"]))
        ),
        format!("{:?}", ExitCode::SUCCESS)
    );
    let registry = mcp_tools::load_registry().expect("registry");
    let stored = registry.get("srv").expect("stored");
    assert_eq!(
        stored.rung(),
        whipplescript_kernel::mcp::McpRung::Unattested
    );

    // Attestation without a pin is refused: there is no frozen manifest for
    // the attestation to be about.
    assert_eq!(
        format!(
            "{:?}",
            mcp_command(&opts(&["attest", "srv", "--trust-annotations"]))
        ),
        format!("{:?}", ExitCode::FAILURE)
    );
    assert!(
        !mcp_tools::load_registry()
            .expect("registry")
            .get("srv")
            .expect("stored")
            .trust_annotations
    );

    // Attestation needs the flag spelled out; the bare verb is a usage error.
    assert_eq!(
        format!("{:?}", mcp_command(&opts(&["attest", "srv"]))),
        format!("{:?}", ExitCode::from(2))
    );

    // An unknown server is an error, not a silent no-op.
    assert_eq!(
        format!("{:?}", mcp_command(&opts(&["status", "nope"]))),
        format!("{:?}", ExitCode::FAILURE)
    );

    // `forget` removes it.
    assert_eq!(
        format!("{:?}", mcp_command(&opts(&["forget", "srv"]))),
        format!("{:?}", ExitCode::SUCCESS)
    );
    assert!(mcp_tools::load_registry().expect("registry").is_empty());

    std::env::remove_var("WHIPPLESCRIPT_MCP_CONFIG");
    let _ = std::fs::remove_dir_all(&dir);
}

use super::*;
// `NewEffect`/`IrRedaction` are exercised only by tests here (their production
// users — the lowering `as_*` converters and the rule-lowering closure — moved
// to `whipplescript_kernel::lowering` / `::rule_lowering`).
use whipplescript_parser::IrRedaction;
// `RuleCommit` is exercised only by tests here (production commits moved to
// `whipplescript_kernel::rule_pass::step_instance_generic`).
use whipplescript_store::{NewEffect, RuleCommit};

/// DR-0052 R3: the repair scope RETARGETS the selective provider at
/// the incident's branch (no instance binding needed) and REFUSES a
/// selection exceeding the derived slice; the repair cut is
/// intent-stamped with the scope's source reference.
#[test]
fn repair_scope_retargets_and_refuses_excess() {
    use whipplescript_kernel::effect_handlers::{CapabilityOutcome, CapabilityProvider};
    let _guard = crate::env_lock();
    let root = std::env::temp_dir().join(format!(
        "whip-repair-scope-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
    ));
    std::fs::create_dir_all(&root).expect("mkdir");
    let previous: Vec<(&str, Option<std::ffi::OsString>)> = [
        "WHIPPLESCRIPT_BRANCH_STORE",
        "WHIPPLESCRIPT_VCS_CONTENT_STORE",
    ]
    .into_iter()
    .map(|key| (key, std::env::var_os(key)))
    .collect();
    std::env::set_var("WHIPPLESCRIPT_BRANCH_STORE", root.join("branches.sqlite"));
    std::env::set_var(
        "WHIPPLESCRIPT_VCS_CONTENT_STORE",
        root.join("content.sqlite"),
    );

    // The incident's branch carries two writes; the derived slice
    // covers only one of them.
    let mut vcs = open_vcs().expect("vcs");
    vcs.init("t0").expect("init");
    vcs.create_branch("stalled-line", None, "main", "t1")
        .expect("branch");
    vcs.set_actor(Some("s:sess-9".to_owned()));
    vcs.write("stalled-line", "contested.md", Some("v1"), "cut_1", "t2")
        .expect("write");
    vcs.write("stalled-line", "unrelated.md", Some("v1"), "cut_2", "t3")
        .expect("write");
    drop(vcs);

    let store_path = root.join("store.sqlite");
    let mut store = SqliteStore::open(&store_path).expect("store");
    store
        .record_repair_scope(
            "ins-repair",
            "stalled-line",
            "path(contested.md)",
            "inc-test",
        )
        .expect("scope");
    drop(store);

    let provider = VcsSelectiveCapabilityProvider {
        store_path: store_path.clone(),
        instance_id: "ins-repair".to_owned(),
    };
    let effect = |id: &str, selection: &str| ClaimableEffect {
        effect_id: id.to_owned(),
        kind: "capability.call".to_owned(),
        target: Some("vcs.undo".to_owned()),
        profile: None,
        input_json: json!({ "selection": selection }).to_string(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: "[]".to_owned(),
    };
    let config = EffectConfig::default();

    // Exceeding the slice refuses (never-widen, refusal not narrowing).
    let outcome = provider.produce(&effect("e-wide", "in-branch(stalled-line)"), &config);
    let CapabilityOutcome::Failed { message, .. } = outcome else {
        panic!("expected refusal");
    };
    assert!(message.contains("exceeds the repair grant"));
    // unrelated.md is untouched by the refusal.
    let vcs = open_vcs().expect("vcs");
    assert_eq!(
        vcs.read("stalled-line", "unrelated.md")
            .expect("read")
            .as_deref(),
        Some("v1")
    );
    drop(vcs);

    // Within the slice: retargeted apply on a branch this instance
    // was never bound to, intent-stamped with the scope's source.
    let outcome = provider.produce(&effect("e-ok", "path(contested.md)"), &config);
    let CapabilityOutcome::Produced(value) = outcome else {
        panic!("expected produced");
    };
    assert_eq!(value["variant"], "Applied");
    let vcs = open_vcs().expect("vcs");
    assert!(vcs
        .read("stalled-line", "contested.md")
        .expect("read")
        .is_none());
    let units = vcs.change_units("stalled-line", 10).expect("units");
    let repair_unit = units
        .iter()
        .find(|unit| unit.origin.as_deref() == Some("undo-selection"))
        .expect("repair cut");
    assert_eq!(repair_unit.intent.as_deref(), Some("inc-test"));
    assert_eq!(repair_unit.actor.as_deref(), Some("instance:ins-repair"));
    drop(vcs);

    for (key, value) in previous {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn http_source_guard_refuses_internal_targets_and_screens_dns() {
    let _guard = crate::env_lock();
    std::env::remove_var("WHIPPLESCRIPT_HTTP_SOURCE_ALLOW_PRIVATE");
    std::env::remove_var("WHIPPLESCRIPT_HTTP_SOURCE_ALLOW");

    // Literal internal / link-local / RFC1918 addresses are refused.
    for url in [
        "http://127.0.0.1/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/x",
        "http://192.168.1.1/x",
        "https://[::1]/x",
        // IPv4-mapped / -compatible IPv6 must screen as their IPv4:
        "http://[::ffff:169.254.169.254]/latest/meta-data/",
        "http://[::ffff:127.0.0.1]/x",
        "http://[::ffff:10.0.0.5]/x",
        "http://100.64.0.1/x",
        "http://0.0.0.0/x",
    ] {
        assert!(
            http_source_url_policy_error(url).is_some(),
            "internal target must be refused: {url}"
        );
    }
    // Local namespaces are refused before any lookup.
    assert!(http_source_url_policy_error("http://localhost/x").is_some());
    assert!(http_source_url_policy_error("http://svc.local/x").is_some());
    // Non-http schemes and hostless URLs are refused.
    assert!(http_source_url_policy_error("file:///etc/passwd").is_some());
    // A public literal address is allowed when no allowlist is configured.
    assert!(http_source_url_policy_error("http://1.1.1.1/x").is_none());
    // A DNS NAME is now screened (not just literal IPs): a name that does
    // not resolve is refused fail-closed rather than passing through — the
    // branch that also refuses names resolving to internal addresses.
    assert!(
        http_source_url_policy_error("http://nonexistent-host.invalid/x").is_some(),
        "an unresolvable DNS name must be refused, not passed through"
    );
}

#[test]
fn screen_public_addrs_rejects_internal_resolutions() {
    // Literal addresses parse without DNS, so this is deterministic. The
    // connection-time resolver refuses any netloc that resolves to an
    // internal target, closing the DNS-rebind gap for HTTP-source ingress.
    assert!(screen_public_addrs("127.0.0.1:80").is_err());
    assert!(screen_public_addrs("169.254.169.254:80").is_err());
    assert!(screen_public_addrs("10.0.0.5:443").is_err());
    assert!(screen_public_addrs("[::1]:80").is_err());
    // A public literal address resolves through.
    assert!(screen_public_addrs("1.1.1.1:443").is_ok());
}

#[cfg(feature = "claude")]
#[test]
fn claude_sidecar_default_resolves_from_executable_not_cwd() {
    // Resolved relative to the test binary, walking up to the repo's
    // `scripts/` — never the current working directory.
    let path = default_claude_sidecar_path().expect("bundled sidecar found from exe dir");
    assert!(path.is_absolute(), "resolved sidecar path must be absolute");
    assert!(path.ends_with("scripts/claude-agent-sdk-sidecar.mjs"));
    assert!(path.is_file(), "resolved sidecar must be a real file");
}

#[cfg(unix)]
#[test]
fn lsp_scan_skips_symlinks_and_terminates_on_cycles() {
    use std::os::unix::fs::symlink;
    let root = std::env::temp_dir().join(format!("whip-lsp-scan-{}", std::process::id()));
    let outside = std::env::temp_dir().join(format!("whip-lsp-outside-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
    std::fs::create_dir_all(root.join("sub")).expect("mkdir sub");
    std::fs::write(root.join("a.whip"), "workflow A").expect("a");
    std::fs::write(root.join("sub/b.whip"), "workflow B").expect("b");
    // A `.whip` outside the tree that a symlink would otherwise expose.
    std::fs::create_dir_all(&outside).expect("mkdir outside");
    std::fs::write(outside.join("secret.whip"), "workflow Secret").expect("secret");
    // A directory-symlink CYCLE (`loop -> .`) and an out-of-tree ESCAPE.
    symlink(&root, root.join("loop")).expect("loop symlink");
    symlink(&outside, root.join("escape")).expect("escape symlink");

    // Must terminate (the test completing at all proves no infinite loop /
    // stack overflow from the cycle).
    let mut files = Vec::new();
    lsp_collect_whip_files(&root, &mut files, 0);

    let names: Vec<String> = files
        .iter()
        .map(|p| {
            p.file_name()
                .expect("file name")
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        names.contains(&"a.whip".to_owned()),
        "found a.whip: {names:?}"
    );
    assert!(
        names.contains(&"b.whip".to_owned()),
        "found b.whip: {names:?}"
    );
    assert!(
        !names.contains(&"secret.whip".to_owned()),
        "must not escape the tree via a symlink: {names:?}"
    );
    assert_eq!(
        files.len(),
        2,
        "exactly the two real files, no cycle dups: {names:?}"
    );

    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn retired_effect_kinds_are_flagged_but_current_kinds_are_not() {
    // The S1 rename retired event.notify -> signal.emit; a store still holding
    // an event.notify effect must be flagged, while every current kind
    // (including runtime kinds with no IrEffectKind variant, e.g. lease.release)
    // must pass.
    assert!(is_retired_effect_kind("event.notify"));
    assert!(is_retired_effect_kind("queue.file"));
    assert!(is_retired_effect_kind("queue.claim"));
    assert!(is_retired_effect_kind("queue.release"));
    assert!(is_retired_effect_kind("queue.finish"));
    assert!(!is_retired_effect_kind("signal.emit"));
    assert!(!is_retired_effect_kind("lease.release"));
    assert!(is_retired_effect_kind("coerce"));
    assert!(!is_retired_effect_kind("schema.coerce"));
    assert!(!is_retired_effect_kind("tracker.claim"));
}

#[test]
fn lint_flags_tool_grant_on_non_owned_agent_only() {
    // DR-0025: a `tools [...]` grant only works under the owned harness. A
    // non-owned agent's grant is dead → warn; an owned agent's grant is fine.
    let owned = whipplescript_parser::compile_program(
            "workflow W\nagent a {\n  provider owned\n  profile \"p\"\n  capacity 1\n  tools [Foo]\n}\n",
        )
        .ir
        .expect("owned ir");
    assert!(
        lint_tool_grant_requires_owned_harness(&owned).is_empty(),
        "owned agent grant should not warn"
    );

    let fixture = whipplescript_parser::compile_program(
            "workflow W\nagent a {\n  provider fixture\n  profile \"p\"\n  capacity 1\n  tools [Foo]\n}\n",
        )
        .ir
        .expect("fixture ir");
    let findings = lint_tool_grant_requires_owned_harness(&fixture);
    assert_eq!(
        findings.len(),
        1,
        "non-owned grant should warn: {findings:?}"
    );
    assert_eq!(findings[0].code, "lint.tool_grant_requires_owned_harness");

    // No grant → no finding regardless of provider.
    let no_grant = whipplescript_parser::compile_program(
        "workflow W\nagent a {\n  provider fixture\n  profile \"p\"\n  capacity 1\n}\n",
    )
    .ir
    .expect("no-grant ir");
    assert!(lint_tool_grant_requires_owned_harness(&no_grant).is_empty());
}

#[test]
fn lsp_tracks_agent_tool_grant_as_a_workflow_reference() {
    // DR-0025: a workflow named in an agent `tools [...]` grant is a plain
    // identifier reference, so the LSP's symbol-table + token-occurrence
    // machinery (document_symbols + lsp_find_occurrences) resolves it for
    // free — definition/references/rename/highlight all cover the grant. This
    // pins that: the workflow is a document symbol, and find_occurrences over
    // its name catches BOTH the `workflow EchoText` decl and `tools [EchoText]`.
    let source = "\
workflow Host {
  agent worker {
    provider owned
    profile \"p\"
    tools [EchoText]
  }
}

@tool
workflow EchoText {
  input request R
  output result Res
  class R { text string }
  class Res { echoed string }
  rule echo
    when R as request
  => {
    done request
    complete result { echoed request.text }
  }
}
";
    let symbols = whipplescript_parser::document_symbols(source);
    assert!(
        symbols
            .iter()
            .any(|symbol| symbol.name == "EchoText" && symbol.kind == "workflow"),
        "EchoText workflow should be a document symbol: {symbols:?}"
    );
    let occurrences = lsp_find_occurrences(source, "EchoText");
    assert_eq!(
        occurrences.len(),
        2,
        "expected the workflow decl and the tools grant to both match: {occurrences:?}"
    );
    // One occurrence is inside the `tools [EchoText]` grant.
    let grant_offset = source.find("tools [EchoText]").expect("grant present") + "tools [".len();
    assert!(
        occurrences
            .iter()
            .any(|(start, end)| *start == grant_offset && &source[*start..*end] == "EchoText"),
        "the grant occurrence should be tracked: {occurrences:?}"
    );
}

#[test]
fn lsp_completes_access_grant_surface_keywords() {
    for keyword in [
        "with", "access", "to", "read", "write", "import", "export", "recall", "learn",
    ] {
        assert!(
            LSP_KEYWORDS.contains(&keyword),
            "missing LSP completion keyword `{keyword}`"
        );
    }
}

#[test]
fn case_pattern_matches_bool_scrutinee_values() {
    // The runtime case matcher already compares a bool scrutinee against the
    // `true`/`false` literal patterns (parse_guard_literal -> Value::Bool),
    // so `case` over a `bool` selects the correct branch at runtime.
    let mut context = RuleContext::default();
    assert!(case_pattern_matches("true", &json!(true), &mut context));
    assert!(!case_pattern_matches("false", &json!(true), &mut context));
    assert!(case_pattern_matches("false", &json!(false), &mut context));
    assert!(!case_pattern_matches("true", &json!(false), &mut context));
}

#[test]
fn after_succeeds_predicate_excludes_failed_terminal_markers() {
    // Regression: a failed `invoke` emits BOTH `workflow.invoke.failed` and a
    // `workflow.invoke.completed` terminal marker (status=failed, so that
    // `after x completes` can fire). The `succeeds` predicate must NOT match
    // that `.completed` marker, or a failed child would wrongly trigger the
    // `after x succeeds` branch and bind its success value to the failure
    // payload (parent then stuck on an unresolvable `r.value`).
    let failed = json!({"status": "failed", "value": {"reason": "boom"}});
    assert!(!fact_matches_after_predicate(
        "workflow.invoke.completed",
        &failed,
        "succeeds"
    ));
    assert!(fact_matches_after_predicate(
        "workflow.invoke.failed",
        &failed,
        "fails"
    ));
    // Both terminal markers still satisfy `completes`.
    assert!(fact_matches_after_predicate(
        "workflow.invoke.completed",
        &failed,
        "completes"
    ));

    // The success terminal still satisfies `succeeds` (and not `fails`).
    let completed = json!({"status": "completed", "value": {"value": "ok"}});
    assert!(fact_matches_after_predicate(
        "workflow.invoke.completed",
        &completed,
        "succeeds"
    ));
    assert!(!fact_matches_after_predicate(
        "workflow.invoke.completed",
        &completed,
        "fails"
    ));
    // A `.succeeded`/`.completed` fact with no status counts as success.
    let no_status = json!({"value": {"value": "ok"}});
    assert!(fact_matches_after_predicate(
        "exec.command.completed",
        &no_status,
        "succeeds"
    ));
}

#[test]
fn redact_projects_to_kept_fields_at_runtime() {
    let value = json!({"id": "c1", "ssn": "secret", "status": "active"});
    let projected = project_record_value(&value, &["id".to_owned(), "status".to_owned()]);
    assert_eq!(projected, json!({"id": "c1", "status": "active"}));
    // The dropped field is physically gone — it cannot leave through any sink.
    assert!(projected.get("ssn").is_none());
    // A non-object value has no fields to drop.
    assert_eq!(
        project_record_value(&json!("x"), &["id".to_owned()]),
        json!("x")
    );
}

#[test]
fn materialize_redactions_binds_the_projection() {
    let mut context = RuleContext {
        trigger_event_id: None,
        identity: None,
        bindings: vec![(
            "cust".to_owned(),
            FactView {
                fact_id: "f1".to_owned(),
                program_version_id: None,
                revision_epoch: 0,
                name: "cust".to_owned(),
                key: "f1".to_owned(),
                value_json: json!({"id": "c1", "ssn": "secret", "status": "active"}).to_string(),
                provenance_class: "effect".to_owned(),
                source_span_json: None,
                source_event_id: String::new(),
            },
        )],
    };
    let redactions = vec![IrRedaction {
        source: "cust".to_owned(),
        keep: vec!["id".to_owned(), "status".to_owned()],
        binding: "safe".to_owned(),
        source_schema: Some("Customer".to_owned()),
    }];
    materialize_redactions(&mut context, &redactions);
    let safe = context
        .bindings
        .iter()
        .find(|(binding, _)| binding == "safe")
        .map(|(_, fact)| json_from_str(&fact.value_json))
        .expect("redact output `safe` should be bound");
    assert_eq!(safe, json!({"id": "c1", "status": "active"}));
    // A redaction whose source is absent is skipped (it materializes where bound).
    let mut empty = RuleContext {
        trigger_event_id: None,
        identity: None,
        bindings: Vec::new(),
    };
    materialize_redactions(&mut empty, &redactions);
    assert!(empty.bindings.is_empty());
}

#[test]
fn inline_after_block_and_terminal_are_detected() {
    // Regression: an `after x succeeds { complete result { … } }` written on a
    // single line was missed by both the liveness lint (terminal detection)
    // and the runtime after-block extractor (the block opens+closes on one
    // line, brace-delta 0).
    assert!(line_reaches_terminal(
        "  after f succeeds { complete result { status \"ok\" } }"
    ));
    assert!(line_reaches_terminal("  complete result {"));
    assert!(line_reaches_terminal("  fail error { reason \"x\" }"));
    // Not a terminal: an identifier that merely starts with the keyword.
    assert!(!line_reaches_terminal("  record R { complete_count 1 }"));
    assert!(!line_reaches_terminal("  read text from fs at \"x\" as f"));

    // The runtime after-block extractor captures the single-line body.
    let blocks = after_blocks("  after f succeeds { complete result { status \"ok\" } }");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].binding, "f");
    assert!(
        blocks[0].body.contains("complete result"),
        "single-line after body captured: {:?}",
        blocks[0].body
    );
}

#[test]
fn decode_import_rows_handles_jsonl_json_and_quoted_csv() {
    // jsonl: one object per non-blank line.
    let jsonl = decode_import_rows("jsonl", "{\"a\":1}\n\n{\"a\":2}\n").expect("jsonl");
    assert_eq!(jsonl.len(), 2);
    assert_eq!(jsonl[1].pointer("/a").and_then(Value::as_i64), Some(2));

    // json: a top-level array; a non-array is rejected.
    let json = decode_import_rows("json", "[{\"a\":1},{\"a\":2}]").expect("json");
    assert_eq!(json.len(), 2);
    assert!(decode_import_rows("json", "{\"a\":1}").is_err());

    // csv: header mapping, quoted field with an embedded comma, "" escape.
    let csv = decode_import_rows(
        "csv",
        "title,note\nCrash,short\n\"Typo, minor\",\"say \"\"hi\"\"\"\n",
    )
    .expect("csv");
    assert_eq!(csv.len(), 2);
    assert_eq!(
        csv[1].pointer("/title").and_then(Value::as_str),
        Some("Typo, minor")
    );
    assert_eq!(
        csv[1].pointer("/note").and_then(Value::as_str),
        Some("say \"hi\"")
    );

    // csv: a row whose field count disagrees with the header is rejected.
    assert!(decode_import_rows("csv", "a,b\n1\n").is_err());
}

#[test]
fn renders_source_span_diagnostic() {
    let source = "agent worker {\n  profile 42\n}\n";
    let diagnostic = Diagnostic {
        related: Vec::new(),
        span: SourceSpan { start: 25, end: 27 },
        message: "expected profile string, found number literal".to_owned(),
        suggestion: Some("write `profile \"profile-name\"`".to_owned()),
    };

    let expected = concat!(
        "error: expected profile string, found number literal\n",
        "  --> example.whip:2:11\n",
        "  |\n",
        "2 |   profile 42\n",
        "  |           ^^\n",
        "  = help: write `profile \"profile-name\"`\n",
    );

    assert_eq!(
        render_diagnostic("example.whip", source, &diagnostic),
        expected
    );
}

#[test]
fn resolve_span_file_maps_offset_to_originating_file() {
    // Mirror the concatenation order used by the resolver: the included
    // file's text comes first, then a separator newline, then the root.
    let lib = "agent helper {\n  profile 7\n}\n";
    let root = "workflow Root\nagent worker {\n  profile 42\n}\n";
    let combined = format!("{lib}\n{root}");
    let root_base = lib.len() + 1;
    let segments = vec![
        SourceSegment {
            start: 0,
            path: "lib.whip".to_owned(),
        },
        SourceSegment {
            start: root_base,
            path: "root.whip".to_owned(),
        },
    ];

    // A span inside the included file resolves to lib.whip with its own
    // in-file line/column.
    let lib_seven = combined.find("profile 7").expect("profile 7 present") + "profile ".len();
    let lib_diag = Diagnostic {
        span: SourceSpan {
            start: lib_seven,
            end: lib_seven + 1,
        },
        message: "expected profile string, found number literal".to_owned(),
        suggestion: None,
        related: Vec::new(),
    };
    let rendered = render_bundle_diagnostic("root.whip", &combined, &segments, &lib_diag, "error");
    assert!(rendered.contains("--> lib.whip:2:11"), "{rendered}");

    // A span inside the root file resolves to root.whip using the ROOT's
    // own line numbering (line 3), not the inflated combined-text line.
    let root_forty_two =
        combined.find("profile 42").expect("profile 42 present") + "profile ".len();
    let root_diag = Diagnostic {
        span: SourceSpan {
            start: root_forty_two,
            end: root_forty_two + 2,
        },
        message: "expected profile string, found number literal".to_owned(),
        suggestion: None,
        related: Vec::new(),
    };
    let rendered = render_bundle_diagnostic("root.whip", &combined, &segments, &root_diag, "error");
    assert!(rendered.contains("--> root.whip:3:11"), "{rendered}");
}

#[test]
fn included_file_diagnostic_names_the_included_file() {
    let dir = std::env::temp_dir().join(format!(
        "whipplescript-bundle-span-included-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    let lib = "class Widget {\n  id string\n}\n\nrule lib_rule\n  when Ghost as g\n=> {\n  record Widget { id \"x\" }\n}\n";
    let root = "include \"lib.whip\"\n\nworkflow Root\n\noutput result Done\n\nclass Done {\n  ok int\n}\n\nrule finish\n  when Widget as w\n=> {\n  complete result { ok 1 }\n}\n";
    fs::write(dir.join("lib.whip"), lib).expect("write lib");
    let root_path = dir.join("root.whip");
    fs::write(&root_path, root).expect("write root");

    let root_str = root_path.to_str().expect("utf8 path");
    let error = match compile_source_path_with_root(root_str, None) {
        Ok(_) => panic!("compilation should fail"),
        Err(error) => error,
    };
    let CompileFailure::Diagnostics {
        source,
        segments,
        diagnostics,
    } = error
    else {
        panic!("expected diagnostics failure");
    };
    let rendered: String = diagnostics
        .iter()
        .map(|diagnostic| {
            render_bundle_diagnostic(root_str, &source, &segments, diagnostic, "error")
        })
        .collect();
    let _ = fs::remove_dir_all(&dir);

    // The rule error originates in the INCLUDED file and must name it.
    assert!(
        rendered.contains("--> lib.whip:6:8"),
        "cross-file diagnostic should name the included file:\n{rendered}"
    );
}

#[test]
fn parses_global_cli_options() {
    let options = CliOptions::parse(vec![
        "--store".to_owned(),
        "state.sqlite".to_owned(),
        "--json".to_owned(),
        "status".to_owned(),
        "ins_1".to_owned(),
    ])
    .expect("options parse");

    assert_eq!(options.command.as_deref(), Some("status"));
    assert_eq!(options.args, vec!["ins_1"]);
    assert_eq!(options.store_path, PathBuf::from("state.sqlite"));
    assert!(options.json);
}

// End-to-end proof that the instance step machine + its native binding drive a
// real started workflow to its terminal — the same terminal the `dev` loop
// reaches — over the `NativeInstanceDriver` (DR-0033 chunk 4).
#[test]
fn instance_step_machine_drives_a_started_workflow_to_its_terminal() {
    use whipplescript_kernel::instance_machine::InstanceOutcome;
    let store_path = unique_test_path("instance-machine", "sqlite");
    let program_path = unique_test_path("instance-machine", "whip");
    let source = "workflow ScoreTicket(ticket: Ticket) -> float ! string\n\n\
             class Ticket {\n  id string\n  title string\n}\n\n\
             rule score\n  when Ticket as ticket\n=> {\n  complete result 0.9\n}\n";
    fs::write(&program_path, source).expect("write program");
    let options = CliOptions::parse(vec![
        "--store".to_owned(),
        store_path.to_string_lossy().into_owned(),
        "dev".to_owned(),
        program_path.to_string_lossy().into_owned(),
    ])
    .expect("options parse");
    let program_str = program_path.to_str().expect("utf8 path");
    let started = match start_workflow_instance(
        program_str,
        None,
        None,
        Some(r#"{"ticket":{"id":"t1","title":"x"}}"#),
        &options,
    ) {
        Ok(started) => started,
        Err(_) => panic!("workflow should start"),
    };
    let (_source, ir) = match compile_source_path_with_root(program_str, None) {
        Ok(compiled) => compiled,
        Err(_) => panic!("program should compile"),
    };

    // Drive the whole instance through the InstanceStepMachine (native binding).
    let outcome = run_instance_via_machine(&store_path, &started.instance_id, &ir)
        .expect("machine drives the instance");
    assert!(
        matches!(outcome, InstanceOutcome::Terminal),
        "the instance reaches a workflow terminal via the step machine: {outcome:?}"
    );

    // ...and the durable state agrees: the instance actually completed.
    let store = SqliteStore::open(&store_path).expect("reopen store");
    let status = store
        .status(&started.instance_id)
        .expect("status")
        .expect("instance row");
    assert_eq!(status.instance.status, "completed");

    let _ = fs::remove_file(&program_path);
    let _ = fs::remove_file(&store_path);
}

#[test]
fn parses_check_model_search_option() {
    let options = CheckOptions::parse(&[
        "--model-search".to_owned(),
        "examples/ralph.whip".to_owned(),
    ])
    .expect("check options parse");

    assert!(options.model_search);
    assert_eq!(options.root, None);
    assert_eq!(options.paths, vec!["examples/ralph.whip"]);
}

#[test]
fn parses_compile_model_search_option() {
    let options = CompileOptions::parse(&[
        "--model-search".to_owned(),
        "--package-lock".to_owned(),
        "whip.lock".to_owned(),
        "examples/package-memory.whip".to_owned(),
    ])
    .expect("compile options parse");

    assert!(options.model_search);
    assert_eq!(options.package_lock_path, Some(PathBuf::from("whip.lock")));
    assert_eq!(options.program_path, "examples/package-memory.whip");
}

#[test]
fn parses_verify_report_entry_index_option() {
    let options = VerifyReportOptions::parse(&[
        "--entry-index".to_owned(),
        "2".to_owned(),
        "check.json".to_owned(),
    ])
    .expect("verify report options parse");

    assert_eq!(options.entry_index, Some(2));
    assert_eq!(options.emit, VerifyReportEmit::Summary);
    assert_eq!(options.paths, vec!["check.json"]);
}

#[test]
fn parses_verify_report_emit_option() {
    let options = VerifyReportOptions::parse(&[
        "--emit".to_owned(),
        "lowered-ir".to_owned(),
        "check.json".to_owned(),
    ])
    .expect("verify report options parse");

    assert_eq!(options.entry_index, None);
    assert_eq!(options.emit, VerifyReportEmit::LoweredIrReport);
    assert_eq!(options.paths, vec!["check.json"]);
}

#[test]
fn parses_check_root_option() {
    let options = CheckOptions::parse(&[
        "--root".to_owned(),
        "Review".to_owned(),
        "examples/phase-review.whip".to_owned(),
    ])
    .expect("check options parse");

    assert_eq!(options.root.as_deref(), Some("Review"));
    assert_eq!(options.paths, vec!["examples/phase-review.whip"]);
}

#[test]
fn renders_contract_registry_json() {
    let source = r#"
workflow RegistryJson

class Review {
  accepted bool
}

coerce review() -> Review {
  prompt """
  Review it.
  """
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = contract_registry_json(&ir);

    assert_eq!(
        registry.get("schema").and_then(Value::as_str),
        Some("whipplescript.contract_registry.v0")
    );
    assert!(registry
        .get("libraries")
        .and_then(Value::as_array)
        .expect("libraries")
        .iter()
        .any(|library| library.get("id").and_then(Value::as_str) == Some("std.coercion")));
    assert!(registry
        .get("effect_contracts")
        .and_then(Value::as_array)
        .expect("effect contracts")
        .iter()
        .any(|contract| {
            contract.get("id").and_then(Value::as_str) == Some("schema.coerce")
                && contract.get("validation").and_then(Value::as_str) == Some("runtime_boundary")
        }));
    assert_eq!(
        registry
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
}

#[test]
fn package_manifest_rejects_old_manifest_without_package_schema() {
    let error = package_manifest_from_json(
        Path::new("memory.json"),
        include_str!("../../../../examples/legacy-plugin-manifests/memory.json").to_owned(),
    )
    .expect_err("old manifest shape should be rejected");

    assert!(
        error.contains("must have non-empty `schema` string"),
        "{error}"
    );
}

#[test]
fn package_manifest_accepts_first_class_library_shape() {
    let manifest = package_manifest_from_json(
        Path::new("memory.json"),
        include_str!("../../vendored-std/manifests/memory.json").to_owned(),
    )
    .expect("manifest parses");

    assert_eq!(manifest.package_id, "std.memory");
    assert!(manifest
        .registry
        .libraries
        .iter()
        .any(|library| library.id == "std.memory" && library.version == "0.1.0"));
    let query_contract = manifest
        .registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "memory.query")
        .expect("memory query contract");
    assert_eq!(query_contract.effect_kind, "capability.call");
    assert_eq!(
        query_contract.validation,
        TypedOutputValidation::RuntimeBoundary
    );
    let write_contract = manifest
        .registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "memory.write")
        .expect("memory write contract");
    assert_eq!(write_contract.effect_kind, "capability.call");
    assert_eq!(
        write_contract.validation,
        TypedOutputValidation::RuntimeBoundary
    );
    let recall_form = manifest
        .registry
        .constructs
        .iter()
        .find(|form| form.id == "memory.recall")
        .expect("memory recall construct");
    assert_eq!(recall_form.library_id, "std.memory");
    assert_eq!(recall_form.construct_family, "effect_operation");
    assert_eq!(recall_form.keyword, "recall");
    assert_eq!(recall_form.scope, "rule_body");
    assert_eq!(recall_form.lowering_target, "capability_call");
    assert_eq!(
        recall_form.target_capability.as_deref(),
        Some("memory.query")
    );
    assert_eq!(recall_form.fields.len(), 3);
    assert!(recall_form.requires.iter().any(|interface| {
        interface.kind == CONSTRUCT_INTERFACE_CAPABILITY
            && interface.name.as_deref() == Some("memory.query")
    }));
    assert!(recall_form
        .provides
        .iter()
        .any(|interface| interface.kind == "EffectHandle"
            && interface.type_ref.as_deref() == Some("memory.query.output")));
    assert_eq!(manifest.registry.validate(), Vec::new());
}

#[test]
fn package_manifest_rejects_unknown_closed_schema_fields() {
    let error = package_manifest_from_json(
        Path::new("unknown-fields.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "unexpected_top": true,
  "libraries": [
    {
      "id": "memory",
      "unexpected_library": true,
      "effect_contracts": [
        {
          "id": "memory.query",
          "unexpected_effect": true
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "unexpected_construct": true,
          "fields": [
            {
              "name": "pool",
              "kind": "identifier",
              "unexpected_field": true
            }
          ],
          "requires": [
            {
              "kind": "Capability",
              "name": "memory.query",
              "unexpected_interface": true
            }
          ]
        }
      ]
    }
  ],
  "capabilities": [
    {
      "id": "memory.query",
      "unexpected_capability": true
    }
  ],
  "providers": [
    {
      "id": "provider-memory-query",
      "provider_kind": "memory-provider",
      "capability": "memory.query",
      "unexpected_provider": true
    }
  ],
  "profiles": [
    {
      "id": "profile-memory-user",
      "name": "memory-user",
      "allowed_capabilities": ["memory.query"],
      "unexpected_profile": true
    }
  ],
  "bindings": [
    {
      "id": "binding-memory-query-global",
      "capability": "memory.query",
      "provider": "memory-provider",
      "unexpected_binding": true
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unknown schema fields");

    for expected in [
            "package manifest field `unexpected_top` is not allowed",
            "package manifest.libraries[0] field `unexpected_library` is not allowed",
            "package manifest.libraries[0].effect_contracts[0] field `unexpected_effect` is not allowed",
            "package manifest.libraries[0].constructs[0] field `unexpected_construct` is not allowed",
            "package manifest.libraries[0].constructs[0].fields[0] field `unexpected_field` is not allowed",
            "package manifest.libraries[0].constructs[0].requires[0] field `unexpected_interface` is not allowed",
            "package manifest.capabilities[0] field `unexpected_capability` is not allowed",
            "package manifest.providers[0] field `unexpected_provider` is not allowed",
            "package manifest.profiles[0] field `unexpected_profile` is not allowed",
            "package manifest.bindings[0] field `unexpected_binding` is not allowed",
        ] {
            assert!(error.contains(expected), "missing `{expected}` in {error}");
        }
}

#[test]
fn package_manifest_rejects_missing_required_nested_fields() {
    let error = package_manifest_from_json(
        Path::new("missing-required-fields.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "effect_contracts": [
        {
          "effect_kind": "capability.call"
        }
      ],
      "constructs": [
        {
          "scope": "rule_body",
          "fields": [
            {
              "name": "pool"
            }
          ],
          "requires": [
            {
              "name": "memory.query"
            }
          ]
        }
      ]
    }
  ],
  "capabilities": [
    {
      "description": "Query package memory."
    }
  ],
  "providers": [
    {
      "provider_kind": "memory-provider",
      "capability": "memory.query"
    }
  ],
  "profiles": [
    {
      "id": "profile-memory-user"
    }
  ],
  "bindings": [
    {
      "capability": "memory.query",
      "provider": "memory-provider"
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing required schema fields");

    for expected in [
        "package manifest.libraries[0] missing required field `id`",
        "package manifest.libraries[0].effect_contracts[0] missing required field `id`",
        "package manifest.libraries[0].constructs[0] missing required field `id`",
        "package manifest.libraries[0].constructs[0] missing required field `construct_family`",
        "package manifest.libraries[0].constructs[0] missing required field `keyword`",
        "package manifest.libraries[0].constructs[0].fields[0] missing required field `kind`",
        "package manifest.libraries[0].constructs[0].requires[0] missing required field `kind`",
        "package manifest.capabilities[0] missing required field `id`",
        "package manifest.providers[0] missing required field `id`",
        "package manifest.profiles[0] missing required field `name`",
        "package manifest.profiles[0] missing required field `allowed_capabilities`",
        "package manifest.bindings[0] missing required field `id`",
    ] {
        assert!(error.contains(expected), "missing `{expected}` in {error}");
    }
}

#[test]
fn package_manifest_rejects_schema_invalid_field_types() {
    let error = package_manifest_from_json(
        Path::new("invalid-field-types.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": null,
      "standard": "yes",
      "effect_contracts": [
        {
          "id": null,
          "source_forms": ["call memory.query", 42],
          "required_capabilities": "memory.query"
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": 42,
          "keyword": "recall",
          "fields": [
            {
              "name": "pool",
              "kind": "identifier",
              "required": "yes"
            }
          ],
          "requires": [
            {
              "kind": null
            }
          ]
        }
      ]
    }
  ],
  "capabilities": [
    {
      "id": null
    }
  ],
  "providers": [
    {
      "id": null,
      "provider_kind": "memory-provider",
      "capability": "memory.query"
    }
  ],
  "profiles": [
    {
      "id": "profile-memory-user",
      "name": null,
      "allowed_capabilities": "memory.query"
    }
  ],
  "bindings": [
    {
      "id": null,
      "program_id": 42,
      "capability": "memory.query",
      "provider": "memory-provider"
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject schema-invalid field types");

    for expected in [
            "package manifest.libraries[0] field `id` must be a non-empty string",
            "package manifest.libraries[0] field `standard` must be a boolean",
            "package manifest.libraries[0].effect_contracts[0] field `id` must be a non-empty string",
            "package manifest.libraries[0].effect_contracts[0].source_forms[1] must be a non-empty string",
            "package manifest.libraries[0].effect_contracts[0] field `required_capabilities` must be an array",
            "package manifest.libraries[0].constructs[0] field `construct_family` must be a non-empty string",
            "package manifest.libraries[0].constructs[0].fields[0] field `required` must be a boolean",
            "package manifest.libraries[0].constructs[0].requires[0] field `kind` must be a non-empty string",
            "package manifest.capabilities[0] field `id` must be a non-empty string",
            "package manifest.providers[0] field `id` must be a non-empty string",
            "package manifest.profiles[0] field `name` must be a non-empty string",
            "package manifest.profiles[0] field `allowed_capabilities` must be an array",
            "package manifest.bindings[0] field `id` must be a non-empty string",
            "package manifest.bindings[0] field `program_id` must be a string or null",
        ] {
            assert!(error.contains(expected), "missing `{expected}` in {error}");
        }
}

#[test]
fn package_manifest_rejects_duplicate_package_identity_declarations() {
    let error = package_manifest_from_json(
            Path::new("duplicate-identities.json"),
            r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "required_capabilities": ["memory.query", "memory.query"],
          "provider_kinds": ["memory-provider", "memory-provider"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall"
        }
      ]
    },
    {
      "id": "memory",
      "effect_contracts": [
        {"id": "memory.query"}
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "remember"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"},
    {"id": "memory.query"}
  ],
  "providers": [
    {"id": "provider-memory", "provider_kind": "memory-provider", "capability": "memory.query"},
    {"id": "provider-memory", "provider_kind": "memory-provider", "capability": "memory.query"}
  ],
  "profiles": [
    {"id": "profile-memory", "name": "Memory", "allowed_capabilities": ["memory.query", "memory.query"]},
    {"id": "profile-memory", "name": "Memory again", "allowed_capabilities": ["memory.query"]}
  ],
  "bindings": [
    {"id": "binding-memory", "capability": "memory.query", "provider": "memory-provider"},
    {"id": "binding-memory", "capability": "memory.query", "provider": "memory-provider"}
  ]
}
"#
            .to_owned(),
        )
        .expect_err("manifest should reject duplicate package identities");

    assert!(
        error.contains("library `memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("capability `memory.query` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("provider `provider-memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("profile `profile-memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("binding `binding-memory` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("effect contract `memory.query` is declared more than once"),
        "{error}"
    );
    assert!(
        error.contains("construct `memory.recall` is declared more than once"),
        "{error}"
    );
    assert!(error.contains("effect contract `memory.query` declares `required_capabilities` value `memory.query` more than once"), "{error}");
    assert!(error.contains("profile `profile-memory` declares `allowed_capabilities` value `memory.query` more than once"), "{error}");
}

#[test]
fn package_manifest_rejects_effect_contract_alias_conflict() {
    let error = package_manifest_from_json(
        Path::new("effect-alias-conflict.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [{"id": "memory.query"}],
      "effects": [{"id": "memory.write"}]
    }
  ],
  "capabilities": [
    {"id": "memory.query"},
    {"id": "memory.write"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject ambiguous effect aliases");

    assert!(
        error.contains("declares both `effect_contracts` and `effects`; use `effect_contracts`"),
        "{error}"
    );
}

#[test]
fn typed_effect_call_is_package_authorable_and_forbids_target_capability() {
    // std.files prerequisite (DR-0019/DR-0020 chain): `typed_effect_call` is
    // promoted to package-authorable, and — unlike `capability_call` — a
    // package construct using it must NOT name a generic `target_capability`.
    let lowering = PLATFORM_CONSTRUCT_CATALOG
        .lowering("typed_effect_call")
        .expect("typed_effect_call lowering");
    assert!(
        lowering.package_authorable,
        "typed_effect_call is package-authorable for std.files"
    );
    let ids = std::collections::BTreeSet::new();
    // Golden: requires Capability + provides EffectHandle, no target_capability.
    let ok = json!({
        "requires": [{"kind": "Capability", "name": "files.read"}],
        "provides": [{"kind": "EffectHandle"}],
    });
    assert!(
        verify_contract_registry_construct_lowering_interfaces(&ok, lowering, &ids, "files.read")
            .is_ok(),
        "a well-formed typed_effect_call construct is accepted"
    );
    // Negative: naming a target_capability is rejected (Forbidden policy).
    let bad = json!({
        "requires": [{"kind": "Capability", "name": "files.read"}],
        "provides": [{"kind": "EffectHandle"}],
        "target_capability": "files.read",
    });
    let err =
        verify_contract_registry_construct_lowering_interfaces(&bad, lowering, &ids, "files.read")
            .expect_err("target_capability on typed_effect_call is rejected");
    assert!(
        err.contains("forbids"),
        "error explains the forbidden target_capability: {err}"
    );
}

#[test]
fn package_manifest_schema_construct_vocabulary_matches_platform_catalog() {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../spec/report-schemas/package_manifest_v0.schema.json"
    ))
    .expect("package manifest schema parses");

    assert_eq!(
        schema_string_enum(
            &schema,
            &[
                "$defs",
                "construct",
                "properties",
                "construct_family",
                "enum"
            ]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .family_ids()
            .filter(|family_id| {
                PLATFORM_CONSTRUCT_CATALOG
                    .lowerings_for_family(family_id)
                    .any(|lowering| lowering.package_authorable)
            })
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &[
                "$defs",
                "construct",
                "properties",
                "lowering_target",
                "enum"
            ]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .lowerings
            .iter()
            .filter(|lowering| lowering.package_authorable)
            .map(|lowering| lowering.id)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "construct", "properties", "scope", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .scopes
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "constructField", "properties", "kind", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .field_kinds
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "constructInterface", "properties", "kind", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .interface_kinds
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &["$defs", "constructInterface", "properties", "phase", "enum"]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .interface_phases
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        schema_string_enum(
            &schema,
            &[
                "$defs",
                "constructInterface",
                "properties",
                "cardinality",
                "enum"
            ]
        ),
        PLATFORM_CONSTRUCT_CATALOG
            .interface_cardinalities
            .iter()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
}

fn schema_string_enum(schema: &Value, path: &[&str]) -> Vec<String> {
    let mut current = schema;
    for segment in path {
        current = current
            .get(*segment)
            .unwrap_or_else(|| panic!("schema path segment `{segment}` exists"));
    }
    current
        .as_array()
        .expect("schema enum is an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("schema enum value is a string")
                .to_owned()
        })
        .collect()
}

#[test]
fn package_manifest_rejects_unsupported_package_effect_kind() {
    let error = package_manifest_from_json(
        Path::new("bad-effect-kind.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "schema.coerce",
          "required_capabilities": ["memory.query"]
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported effect kind");
    assert!(
        error.contains("packages currently support only `capability.call`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_undeclared_required_capability() {
    let error = package_manifest_from_json(
        Path::new("missing-capability.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.missing"]
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing required capability");
    assert!(
        error.contains("references undeclared capability `memory.missing`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_capability_input_schema() {
    let error = package_manifest_from_json(
        Path::new("bad-input-schema.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "capabilities": [
    {
      "id": "memory.query",
      "schema": {
        "input": {
          "query": true
        }
      }
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported input schema fragments");
    assert!(
        error.contains("capability `memory.query`")
            && error.contains("invalid input_schema")
            && error.contains("input_schema.query uses unsupported package schema fragment"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_effect_output_schema() {
    let error = package_manifest_from_json(
        Path::new("bad-output-schema.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "output_schema": ["string", "integer"],
          "required_capabilities": ["memory.query"]
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported output schema fragments");
    assert!(
        error.contains("effect contract `memory.query`")
            && error.contains("invalid output_schema")
            && error.contains("output_schema uses unsupported package tuple schema"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_construct_missing_required_input_schema_field() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-input-fields.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "input_schema": {
            "query": "string"
          },
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "fields": [
            {"name": "pool", "kind": "identifier", "required": true},
            {"name": "binding", "kind": "identifier", "required": true}
          ],
          "requires": [
            {"kind": "Capability", "name": "memory.query"}
          ],
          "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output"}
          ],
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject construct fields that cannot supply target input");
    assert!(
        error.contains("construct `memory.recall` lowers to `memory.query`")
            && error.contains(
                "target input_schema field `query` has no matching required construct field"
            ),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_binding_without_matching_provider() {
    let error = package_manifest_from_json(
        Path::new("bad-binding.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "capabilities": [
    {"id": "memory.query"}
  ],
  "providers": [
    {
      "id": "provider-memory-query",
      "provider_kind": "memory-provider",
      "capability": "memory.query",
      "config": {}
    }
  ],
  "bindings": [
    {
      "id": "binding-memory-query-global",
      "capability": "memory.query",
      "provider": "other-provider",
      "config": {}
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject provider mismatch");
    assert!(
        error.contains("references provider `other-provider`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_construct_lowering_target() {
    let error = package_manifest_from_json(
        Path::new("bad-construct.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "core_rule"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject executable construct lowering");
    assert!(
        error.contains("expected one of `metadata_only`, `capability_call`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_platform_internal_construct_lowering_target() {
    let error = package_manifest_from_json(
        Path::new("bad-internal-construct.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.wait",
          "construct_family": "effect_operation",
          "keyword": "wait",
          "scope": "rule_body",
          "lowering_target": "core_effect"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject platform-internal construct lowering");
    assert!(
        error.contains("platform-internal lowering_target `core_effect`"),
        "{error}"
    );
}

/// A synthetic std manifest declaring a construct in a real
/// `package_authorable: false` lowering class (`signal_source`,
/// `source_declaration` family, no grammar/interfaces required) — otherwise
/// fully valid, so the only failure under test is the authorability door.
const INTERNAL_LOWERING_STD_MANIFEST: &str = r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "std.pulse",
  "name": "std.pulse",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "std.pulse",
      "version": "0.1.0",
      "constructs": [
        {
          "id": "pulse.source",
          "construct_family": "source_declaration",
          "keyword": "pulse",
          "scope": "top_level",
          "lowering_target": "signal_source"
        }
      ]
    }
  ]
}
"#;

#[test]
fn package_manifest_rejects_internal_lowering_without_embedded_privilege() {
    // The normal (vendor/lock/file) path: the manifest is not the platform's
    // embedded copy, so the flat rejection stands.
    let error = package_manifest_from_json(
        Path::new("std-pulse.json"),
        INTERNAL_LOWERING_STD_MANIFEST.to_owned(),
    )
    .expect_err("a non-embedded manifest must not author an internal lowering");
    assert!(
        error.contains("platform-internal lowering_target `signal_source`")
            && error.contains("only platform-embedded std manifests"),
        "{error}"
    );
}

#[test]
fn package_manifest_admits_internal_lowering_for_embedded_copy() {
    // The authorability door: the same bytes validated as an entry of the
    // embedded manifest set are the platform copy and may use internal
    // lowerings.
    let manifest = package_manifest_from_json_with_embedded(
        Path::new("<embedded:std.pulse>"),
        INTERNAL_LOWERING_STD_MANIFEST.to_owned(),
        &[("std.pulse", INTERNAL_LOWERING_STD_MANIFEST)],
    )
    .expect("the platform's own embedded copy may use internal lowerings");
    assert_eq!(manifest.name, "std.pulse");
    assert_eq!(manifest.registry.constructs.len(), 1);
    assert_eq!(
        manifest.registry.constructs[0].lowering_target,
        "signal_source"
    );
}

#[test]
fn package_manifest_std_name_grants_no_internal_lowering_privilege() {
    // Name alone grants nothing: a `std.evil` manifest with an internal
    // lowering is rejected through the normal path, and stays rejected even
    // against an embedded set whose entries have different bytes — only
    // byte-identity with the embedded copy is the privilege key.
    let evil = INTERNAL_LOWERING_STD_MANIFEST.replace("std.pulse", "std.evil");
    let error = package_manifest_from_json(Path::new("std-evil.json"), evil.clone())
        .expect_err("a std.*-named manifest file must not author an internal lowering");
    assert!(
        error.contains("platform-internal lowering_target `signal_source`"),
        "{error}"
    );
    let error = package_manifest_from_json_with_embedded(
        Path::new("std-evil.json"),
        evil,
        &[("std.pulse", INTERNAL_LOWERING_STD_MANIFEST)],
    )
    .expect_err("different bytes must not inherit embedded privilege");
    assert!(
        error.contains("platform-internal lowering_target `signal_source`"),
        "{error}"
    );
}

/// A minimal manifest whose one construct is a `resource_effect` row —
/// the non-authorable class whose only producers are platform-catalog
/// privilege tuples (std.coord slice 4). `{LIB}` / `{KW}` are substituted
/// per test.
const RESOURCE_EFFECT_MANIFEST_TEMPLATE: &str = r#"{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "{LIB}",
  "name": "{LIB}",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "{LIB}",
      "version": "0.1.0",
      "constructs": [
        {
          "id": "lease.acquire",
          "construct_family": "effect_operation",
          "keyword": "{KW}",
          "scope": "rule_body",
          "requires": [{ "kind": "Resource" }],
          "provides": [{ "kind": "EffectHandle" }],
          "lowering_target": "resource_effect"
        }
      ]
    }
  ]
}
"#;

/// std.coord slice 4 privilege acceptance (std-tracker.json claim-keyword
/// precedent, extended through the authorability wall): a manifest whose
/// (library, keyword, family, scope, lowering) tuple is in the platform
/// catalog may author a `resource_effect` construct WITHOUT being the
/// embedded byte-identical copy — the privilege-tuple leg of the door.
/// The embedded set is explicitly EMPTY so byte-identity cannot be the
/// key that admitted it.
#[test]
fn package_manifest_privilege_tuple_admits_resource_effect_construct() {
    let manifest = RESOURCE_EFFECT_MANIFEST_TEMPLATE
        .replace("{LIB}", "std.coord")
        .replace("{KW}", "acquire");
    let manifest = package_manifest_from_json_with_embedded(Path::new("coord.json"), manifest, &[])
        .expect("the catalog privilege tuple authorizes the resource_effect class");
    assert_eq!(manifest.registry.constructs.len(), 1);
    assert_eq!(
        manifest.registry.constructs[0].lowering_target,
        "resource_effect"
    );
}

/// Negative fixture (slice 4 gate): a NON-privileged manifest cannot
/// author a `resource_effect` construct — no catalog tuple, no row. Both
/// coordinates bite: a vendor library with the same keyword, and the
/// privileged library with a keyword outside its tuples.
#[test]
fn package_manifest_without_privilege_tuple_cannot_author_resource_effect() {
    let vendor = RESOURCE_EFFECT_MANIFEST_TEMPLATE
        .replace("{LIB}", "acme.coord")
        .replace("{KW}", "acquire");
    let error = package_manifest_from_json_with_embedded(Path::new("acme-coord.json"), vendor, &[])
        .expect_err("a vendor library holds no resource_effect tuple");
    assert!(
        error.contains("platform-internal lowering_target `resource_effect`"),
        "{error}"
    );

    let wrong_keyword = RESOURCE_EFFECT_MANIFEST_TEMPLATE
        .replace("{LIB}", "std.coord")
        .replace("{KW}", "seize");
    let error =
        package_manifest_from_json_with_embedded(Path::new("coord-seize.json"), wrong_keyword, &[])
            .expect_err("std.coord holds no tuple for an un-cataloged keyword");
    assert!(
        error.contains("platform-internal lowering_target `resource_effect`"),
        "{error}"
    );
}

/// std.ingress I2b manifest template: the two reserved-keyword construct
/// rows (`signal` declaration_block + `emit` signal_emit) parameterized on
/// the library id, so both privilege coordinates can bite.
const INGRESS_KEYWORD_MANIFEST_TEMPLATE: &str = r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "{LIB}",
  "name": "{LIB}",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "{LIB}",
      "constructs": [
        {
          "id": "ingress.signal",
          "construct_family": "declaration_block",
          "keyword": "signal",
          "scope": "top_level",
          "lowering_target": "metadata_only"
        },
        {
          "id": "signal.emit",
          "construct_family": "effect_operation",
          "keyword": "emit",
          "scope": "rule_body",
          "requires": [{ "kind": "Event" }],
          "lowering_target": "signal_emit"
        }
      ]
    }
  ]
}
"#;

/// std.ingress I2b, privilege-tuple leg (spec/std-ingress.md "Catalog
/// privilege additions"): the catalog tuples (`signal`, std.ingress,
/// declaration_block, metadata_only) and (`emit`, std.ingress,
/// effect_operation, signal_emit) admit the construct rows WITHOUT the
/// embedded-copy key (empty embedded set), the same door std.coord's
/// resource_effect rows ride.
#[test]
fn package_manifest_privilege_tuples_admit_ingress_signal_and_emit() {
    let manifest = INGRESS_KEYWORD_MANIFEST_TEMPLATE.replace("{LIB}", "std.ingress");
    let manifest =
        package_manifest_from_json_with_embedded(Path::new("ingress.json"), manifest, &[])
            .expect("the catalog tuples authorize the signal/emit rows");
    assert_eq!(manifest.registry.constructs.len(), 2);
    assert!(manifest
        .registry
        .constructs
        .iter()
        .any(|form| form.keyword == "emit" && form.lowering_target == "signal_emit"));
}

/// Negative fixture (I2b gate): a NON-privileged manifest cannot author
/// the `signal`/`emit` keywords or the `signal_emit` lowering — the tuples
/// are exact, so a vendor library with the same rows is refused.
#[test]
fn package_manifest_without_ingress_tuples_cannot_author_signal_or_emit() {
    let vendor = INGRESS_KEYWORD_MANIFEST_TEMPLATE.replace("{LIB}", "acme.ingress");
    let error =
        package_manifest_from_json_with_embedded(Path::new("acme-ingress.json"), vendor, &[])
            .expect_err("a vendor library holds neither ingress tuple");
    assert!(
        error.contains("reserved construct keyword")
            || error.contains("platform-internal lowering_target `signal_emit`"),
        "{error}"
    );
}

/// std.coord slice 4 drift test, contracts leg: the manifest's four
/// coordination effect contracts must FOLD against the parser-compiled
/// ones (same id/version/library/kind/schemas/validation), so a shape
/// drift between manifest and compiler surfaces as
/// `effect_contract_duplicate` and fails here.
#[test]
fn coord_manifest_contracts_fold_against_the_parser_compiled_ones() {
    let source = r#"use std.coord

workflow CoordImport

output result Done
failure error Busy

class Ticket { id string }
class Done { note string }
class Busy { reason string }
class Note { text string }
class AuditEntry { area string text string }

lease deploy_slot {
  key Ticket
  slots 1
  ttl 60s
}

ledger audit_log {
  entry AuditEntry
  partition by area
  retain 7d
}

counter request_budget {
  key Ticket
  cap 5
  reset daily
  timezone "UTC"
}

rule seed
  when started
=> {
  record Ticket { id "prod" }
}

rule audit
  when Ticket as t
=> {
  consume request_budget for t.id amount 1 as spend
  append AuditEntry { area t.id text "went" } to audit_log as entry

  after spend ok {
    record Note { text "ok" }
  }

  after spend over {
    record Note { text "over" }
  }
}

rule go
  when Ticket as t
=> {
  acquire deploy_slot for t.id until ttl as slot

  after slot held {
    release slot
    complete result { note "ok" }
  }

  after slot contended {
    fail error { reason "busy" }
  }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compiles");
    let registry = contract_registry_for_ir(None, &ir).expect("registry resolves");
    assert_eq!(registry.validate(), Vec::new());
    for (kind, source_form) in [
        ("lease.acquire", "acquire"),
        ("ledger.append", "append"),
        ("counter.consume", "consume"),
    ] {
        let contracts: Vec<_> = registry
            .effect_contracts
            .iter()
            .filter(|contract| contract.id == kind)
            .collect();
        assert_eq!(
            contracts.len(),
            1,
            "manifest and parser `{kind}` contracts must fold into one: {contracts:?}"
        );
        let contract = contracts[0];
        assert_eq!(contract.library_id, "std.coord");
        assert_eq!(contract.effect_kind, kind);
        assert_eq!(
            contract.required_capabilities,
            [kind],
            "the manifest contributes the id==kind capability row (M3)"
        );
        assert!(
            contract.source_forms.iter().any(|form| form == source_form),
            "{contract:?}"
        );
    }
    // The lease.release contract has no parser-compiled partner (the
    // release verb has no IrEffectKind); the manifest copy stands alone.
    assert_eq!(
        registry
            .effect_contracts
            .iter()
            .filter(|contract| contract.id == "lease.release")
            .count(),
        1
    );
    // The seven construct rows arrive from the embedded manifest merge.
    let coord_constructs: Vec<_> = registry
        .constructs
        .iter()
        .filter(|form| form.library_id == "std.coord")
        .collect();
    assert_eq!(coord_constructs.len(), 7, "{coord_constructs:?}");
    for keyword in ["acquire", "release", "append", "consume"] {
        assert!(
            coord_constructs.iter().any(|form| form.keyword == keyword
                && form.lowering_target == "resource_effect"
                && form.scope == "rule_body"),
            "missing resource_effect row for `{keyword}`: {coord_constructs:?}"
        );
    }
    for keyword in ["lease", "ledger", "counter"] {
        assert!(
            coord_constructs.iter().any(|form| form.keyword == keyword
                && form.lowering_target == "metadata_only"
                && form.scope == "top_level"),
            "missing metadata_only row for `{keyword}`: {coord_constructs:?}"
        );
    }
}

/// std.coord slice 4 drift test, declarations leg: the runtime manifest's
/// `declaration_block` rows must name exactly the decl constructs the
/// grammar-only manifest (std/grammars/coord.json, build.rs-read) parses —
/// two spellings of one surface, kept in lockstep.
#[test]
fn coord_manifest_decl_rows_agree_with_the_grammar_manifest() {
    let runtime: Value =
        serde_json::from_str(include_str!("../../vendored-std/manifests/coord.json"))
            .expect("valid json");
    let grammar: Value = serde_json::from_str(include_str!("../../../../std/grammars/coord.json"))
        .expect("valid json");
    let decl_rows = |manifest: &Value, family_filter: bool| -> BTreeSet<(String, String)> {
        manifest["libraries"]
            .as_array()
            .expect("libraries")
            .iter()
            .flat_map(|library| {
                library
                    .get("constructs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter(|construct| {
                !family_filter
                    || construct["construct_family"].as_str() == Some("declaration_block")
            })
            .map(|construct| {
                (
                    construct["id"].as_str().expect("id").to_owned(),
                    construct["keyword"].as_str().expect("keyword").to_owned(),
                )
            })
            .collect()
    };
    assert_eq!(
        decl_rows(&runtime, true),
        decl_rows(&grammar, false),
        "runtime manifest decl rows and std/grammars/coord.json must agree"
    );
}

/// std.files slice F5 drift test, contracts leg: the manifest's four
/// `file.*` effect contracts must FOLD against the parser-compiled ones
/// (same id/version/library/kind/schemas/validation), so a shape drift
/// between manifest and compiler surfaces as `effect_contract_duplicate`
/// and fails here.
#[test]
fn files_manifest_contracts_fold_against_the_parser_compiled_ones() {
    let source = r#"use std.files

workflow FilesImport

output result Done
failure error Broken

class Done { note string }
class Broken { reason string }
class Row { id string }

file store docs {
  root "fixtures"
  allow read ["**/*"]
  allow write ["out/**"]
}

rule go
  when started
=> {
  read text from docs at "note.md" as loaded
  import jsonl Row from docs at "rows.jsonl" as rows
  export jsonl Row to docs at "out/rows.jsonl" { mode upsert } as dumped
  write text to docs at "out/copy.md" { body "hi" mode upsert } as copied

  after copied succeeds {
    complete result { note "ok" }
  }

  after copied fails as oops {
    fail error { reason oops.reason }
  }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compiles");
    let registry = contract_registry_for_ir(None, &ir).expect("registry resolves");
    assert_eq!(registry.validate(), Vec::new());
    for (kind, source_form, output_schema) in [
        ("file.read", "read", "FileReadResult"),
        ("file.write", "write", "FileWriteResult"),
        ("file.import", "import", "FileImportResult"),
        ("file.export", "export", "FileExportResult"),
    ] {
        let contracts: Vec<_> = registry
            .effect_contracts
            .iter()
            .filter(|contract| contract.id == kind)
            .collect();
        assert_eq!(
            contracts.len(),
            1,
            "manifest and parser `{kind}` contracts must fold into one: {contracts:?}"
        );
        let contract = contracts[0];
        assert_eq!(contract.library_id, "std.files");
        assert_eq!(contract.effect_kind, kind);
        assert_eq!(
            contract.required_capabilities,
            [kind],
            "capability id == effect kind (M3)"
        );
        assert_eq!(contract.output_schema.as_deref(), Some(output_schema));
        assert_eq!(
            contract.validation,
            whipplescript_core::TypedOutputValidation::RuntimeBoundary
        );
        assert!(
            contract.source_forms.iter().any(|form| form == source_form),
            "{contract:?}"
        );
        assert_eq!(
            contract.provider_kinds,
            ["local"],
            "the manifest contributes the `local` FileStore-seam provider kind"
        );
    }
    // The five construct rows arrive from the embedded manifest merge —
    // the catalog-honesty gate (E4): typed_effect_call's "promoted for
    // std.files" claim is now TRUE via registered rows, keeping the
    // `file.*` kind strings (attribution + admission, no rekey).
    let files_constructs: Vec<_> = registry
        .constructs
        .iter()
        .filter(|form| form.library_id == "std.files")
        .collect();
    assert_eq!(files_constructs.len(), 5, "{files_constructs:?}");
    for keyword in ["read", "write", "import", "export"] {
        assert!(
            files_constructs.iter().any(|form| {
                form.keyword == keyword
                    && form.lowering_target == "typed_effect_call"
                    && form.scope == "rule_body"
                    && form.target_capability.is_none()
            }),
            "missing typed_effect_call row for `{keyword}`: {files_constructs:?}"
        );
    }
    assert!(
        files_constructs.iter().any(|form| {
            form.keyword == "file store"
                && form.lowering_target == "metadata_only"
                && form.scope == "top_level"
        }),
        "missing metadata_only row for `file store`: {files_constructs:?}"
    );
}

/// std.files slice F5 drift test, declarations leg: the runtime manifest's
/// `declaration_block` rows must name exactly the decl constructs the
/// grammar-only manifest (std/grammars/files.json, build.rs-read) parses —
/// two spellings of one surface, kept in lockstep.
#[test]
fn files_manifest_decl_rows_agree_with_the_grammar_manifest() {
    let runtime: Value =
        serde_json::from_str(include_str!("../../vendored-std/manifests/files.json"))
            .expect("valid json");
    let grammar: Value = serde_json::from_str(include_str!("../../../../std/grammars/files.json"))
        .expect("valid json");
    let decl_rows = |manifest: &Value, family_filter: bool| -> BTreeSet<(String, String)> {
        manifest["libraries"]
            .as_array()
            .expect("libraries")
            .iter()
            .flat_map(|library| {
                library
                    .get("constructs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter(|construct| {
                !family_filter
                    || construct["construct_family"].as_str() == Some("declaration_block")
            })
            .map(|construct| {
                (
                    construct["id"].as_str().expect("id").to_owned(),
                    construct["keyword"].as_str().expect("keyword").to_owned(),
                )
            })
            .collect()
    };
    assert_eq!(
        decl_rows(&runtime, true),
        decl_rows(&grammar, false),
        "runtime manifest decl rows and std/grammars/files.json must agree"
    );
}

/// std.tracker slice T4 drift test, contracts leg: the manifest's five
/// tracker effect contracts must FOLD against the parser-compiled ones
/// (same id/version/library/kind/schemas/validation), so a shape drift
/// between manifest and compiler surfaces as `effect_contract_duplicate`
/// and fails here. `tracker.renew` now has a full contract too (T3 landed
/// the effect kind, spec/std-tracker.md "Renew/TTL semantics"): the rule
/// below renews its claim, so the parser emits the `tracker.renew`
/// contract and the manifest row folds against it.
#[test]
fn tracker_manifest_contracts_fold_against_the_parser_compiled_ones() {
    let source = r#"use std.tracker

workflow TrackerImport

output result Done
failure error Busy

class Done { note string }
class Busy { reason string }

tracker backlog {
  provider builtin
}

rule file_ticket
  when started
=> {
  file issue into backlog {
    title "Add retry telemetry"
    body "Record retry count and final outcome."
  }
}

rule work_ready_item
  when backlog has ready issue as issue
=> {
  claim issue as active_claim

  after active_claim succeeds {
    renew active_claim as renewed
    finish issue {
      summary "done"
    }
    complete result { note "ok" }
  }

  after active_claim fails {
    release issue
    fail error { reason "busy" }
  }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compiles");
    let registry = contract_registry_for_ir(None, &ir).expect("registry resolves");
    assert_eq!(registry.validate(), Vec::new());
    for (kind, source_form) in [
        ("tracker.file", "file"),
        ("tracker.claim", "claim"),
        ("tracker.renew", "renew"),
        ("tracker.release", "release"),
        ("tracker.finish", "finish"),
    ] {
        let contracts: Vec<_> = registry
            .effect_contracts
            .iter()
            .filter(|contract| contract.id == kind)
            .collect();
        assert_eq!(
            contracts.len(),
            1,
            "manifest and parser `{kind}` contracts must fold into one: {contracts:?}"
        );
        let contract = contracts[0];
        assert_eq!(contract.library_id, "std.tracker");
        assert_eq!(contract.effect_kind, kind);
        assert_eq!(
            contract.required_capabilities,
            [kind],
            "contract carries the id==kind capability row (M3, slice T2)"
        );
        assert!(
            contract.source_forms.iter().any(|form| form == source_form),
            "{contract:?}"
        );
        assert!(
            contract
                .provider_kinds
                .iter()
                .any(|provider| provider == "builtin-tracker"),
            "the manifest contributes the admission-honesty provider kind: {contract:?}"
        );
    }
    // T3 landed the `tracker.renew` effect kind: the manifest contract row
    // now merge-folds against the parser-compiled contract (the loop above
    // already asserted the single folded row), so a contract WITHOUT its
    // parser partner is no longer the pretense — the fold is honest.
    // The six construct rows arrive from the embedded manifest merge; the
    // claim/renew/release rows are the reserved-keyword privilege tuples'
    // first real exercisers (typed_effect_call, corrected by T4).
    let tracker_constructs: Vec<_> = registry
        .constructs
        .iter()
        .filter(|form| form.library_id == "std.tracker")
        .collect();
    assert_eq!(tracker_constructs.len(), 6, "{tracker_constructs:?}");
    for keyword in ["file", "claim", "renew", "release", "finish"] {
        assert!(
            tracker_constructs.iter().any(|form| form.keyword == keyword
                && form.lowering_target == "typed_effect_call"
                && form.scope == "rule_body"),
            "missing typed_effect_call row for `{keyword}`: {tracker_constructs:?}"
        );
    }
    assert!(
        tracker_constructs
            .iter()
            .any(|form| form.keyword == "tracker"
                && form.lowering_target == "metadata_only"
                && form.scope == "top_level"),
        "missing metadata_only row for the `tracker` declaration: {tracker_constructs:?}"
    );
}

/// std.tracker slice T4 drift test, declarations leg: the runtime
/// manifest's `declaration_block` rows must name exactly the decl
/// constructs the grammar-only manifest (std/grammars/tracker.json,
/// build.rs-read) parses — two spellings of one surface, kept in lockstep.
#[test]
fn tracker_manifest_decl_rows_agree_with_the_grammar_manifest() {
    let runtime: Value =
        serde_json::from_str(include_str!("../../vendored-std/manifests/tracker.json"))
            .expect("valid json");
    let grammar: Value =
        serde_json::from_str(include_str!("../../../../std/grammars/tracker.json"))
            .expect("valid json");
    let decl_rows = |manifest: &Value, family_filter: bool| -> BTreeSet<(String, String)> {
        manifest["libraries"]
            .as_array()
            .expect("libraries")
            .iter()
            .flat_map(|library| {
                library
                    .get("constructs")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter(|construct| {
                !family_filter
                    || construct["construct_family"].as_str() == Some("declaration_block")
            })
            .map(|construct| {
                (
                    construct["id"].as_str().expect("id").to_owned(),
                    construct["keyword"].as_str().expect("keyword").to_owned(),
                )
            })
            .collect()
    };
    assert_eq!(
        decl_rows(&runtime, true),
        decl_rows(&grammar, false),
        "runtime manifest decl rows and std/grammars/tracker.json must agree"
    );
}

#[test]
fn embedded_std_manifests_parse() {
    // Guard: every real embedded manifest validates clean through the full
    // manifest validation (`embedded_std_manifests` panics otherwise).
    // std.coord's four `resource_effect` construct rows exercise the
    // authorability door for real (both legs: byte-identity when loaded
    // through `package_manifest_from_json`, and the catalog privilege
    // tuples — see the slice-4 tests above).
    let manifests = embedded_std_manifests();
    assert_eq!(
        manifests.len(),
        whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS.len()
    );
    for ((name, _), manifest) in whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS
        .iter()
        .zip(&manifests)
    {
        assert_eq!(&manifest.name, name);
    }
}

/// Manifest/adapter drift (spec/std-agent.md "Static checks" 4, slice 7):
/// the thin provider packages' embedded manifests are present iff their
/// adapter cargo feature is compiled in — a binary without feature `codex`
/// genuinely does not know provider kind `codex`.
#[test]
fn agent_provider_manifests_track_adapter_features() {
    assert!(is_embedded_std_manifest("std.agent"));
    assert_eq!(
        is_embedded_std_manifest("std.agent.codex"),
        cfg!(feature = "codex"),
        "std.agent.codex manifest presence must equal the codex feature"
    );
    assert_eq!(
        is_embedded_std_manifest("std.agent.claude"),
        cfg!(feature = "claude"),
        "std.agent.claude manifest presence must equal the claude feature"
    );
    // Kind resolution flips with the feature set.
    let kinds = known_agent_provider_kinds(None);
    for kind in ["owned", "fixture", "native-fixture", "command"] {
        assert!(
            kinds.contains_key(kind),
            "std.agent must contribute `{kind}`"
        );
    }
    assert_eq!(kinds.contains_key("codex"), cfg!(feature = "codex"));
    assert_eq!(kinds.contains_key("claude"), cfg!(feature = "claude"));
    // And the compiled feature reports track the same features.
    use whipplescript_kernel::agent_profile::agent_feature_report;
    assert_eq!(
        agent_feature_report("codex").is_some(),
        cfg!(feature = "codex")
    );
    assert_eq!(
        agent_feature_report("claude").is_some(),
        cfg!(feature = "claude")
    );
}

/// Manifest-vs-compiled drift (spec/std-agent.md slices 4/5/7): every
/// embedded agent-provider row's `config.feature_report` matches the
/// compiled report for that kind exactly, and the `std.agent` manifest's
/// `profiles` section mirrors the compiled preset table row for row.
#[test]
fn agent_manifest_reports_and_profiles_match_compiled_data() {
    use whipplescript_kernel::agent_profile::{
        agent_feature_report, agent_profile_preset, AGENT_PROFILE_PRESETS,
    };
    let mut kinds_with_manifest_reports = BTreeSet::new();
    for (package, json) in whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS {
        if *package != "std.agent" && !package.starts_with("std.agent.") {
            continue;
        }
        let value: Value = serde_json::from_str(json).expect("embedded manifest json");
        for row in value
            .get("providers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let config = row.get("config").expect("provider config");
            if config.get("agent_provider").and_then(Value::as_bool) != Some(true) {
                continue;
            }
            let kind = row
                .get("provider_kind")
                .and_then(Value::as_str)
                .expect("provider_kind");
            let compiled = agent_feature_report(kind)
                .unwrap_or_else(|| panic!("no compiled report for manifest kind `{kind}`"));
            let entries = config
                .get("feature_report")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("kind `{kind}` manifest row carries no report"));
            assert_eq!(
                entries.len(),
                compiled.entries.len(),
                "kind `{kind}` report length drifted"
            );
            for (entry, compiled_entry) in entries.iter().zip(compiled.entries) {
                assert_eq!(
                    entry.get("class").and_then(Value::as_str),
                    Some(compiled_entry.class),
                    "kind `{kind}` report class order drifted"
                );
                assert_eq!(
                    entry.get("support").and_then(Value::as_str),
                    Some(compiled_entry.support.as_str()),
                    "kind `{kind}` class `{}` support drifted",
                    compiled_entry.class
                );
                assert_eq!(
                    entry.get("source").and_then(Value::as_str),
                    Some(compiled_entry.source.as_str()),
                    "kind `{kind}` class `{}` source drifted",
                    compiled_entry.class
                );
                assert_eq!(
                    entry.get("native_name").and_then(Value::as_str),
                    compiled_entry.native_name,
                    "kind `{kind}` class `{}` native_name drifted",
                    compiled_entry.class
                );
                assert_eq!(
                    entry.get("dispatch").and_then(Value::as_str),
                    compiled_entry.dispatch,
                    "kind `{kind}` class `{}` dispatch drifted",
                    compiled_entry.class
                );
            }
            kinds_with_manifest_reports.insert(kind.to_owned());
        }
    }
    // Every compiled report has a manifest home (feature-conditional on
    // both sides, so the sets agree under any feature combination).
    for report in whipplescript_kernel::agent_profile::AGENT_FEATURE_REPORTS {
        assert!(
            kinds_with_manifest_reports.contains(report.provider_kind),
            "compiled report `{}` has no embedded manifest row",
            report.provider_kind
        );
    }

    // Profile table fold (slice 4's manifest home): std.agent `profiles`
    // rows mirror the compiled preset table exactly.
    let (_, agent_json) = whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS
        .iter()
        .find(|(name, _)| *name == "std.agent")
        .expect("std.agent embedded");
    let value: Value = serde_json::from_str(agent_json).expect("agent manifest json");
    let profiles = value
        .get("profiles")
        .and_then(Value::as_array)
        .expect("std.agent profiles");
    assert_eq!(profiles.len(), AGENT_PROFILE_PRESETS.len());
    for row in profiles {
        let name = row.get("name").and_then(Value::as_str).expect("name");
        let preset = agent_profile_preset(name)
            .unwrap_or_else(|| panic!("manifest profile `{name}` is not a compiled preset"));
        // Enforcement flows through the compiled preset leg; the manifest
        // row is audit/visibility data so registered-policy seeding can
        // never narrow (or widen) the preset expansion.
        assert_eq!(
            row.get("enforcement_mode").and_then(Value::as_str),
            Some("audit"),
            "profile `{name}` must be audit-mode data"
        );
        let config = row.get("config").expect("profile config");
        assert_eq!(
            config.get("canonical").and_then(Value::as_bool),
            Some(preset.canonical)
        );
        assert_eq!(
            config.get("codex_mapped").and_then(Value::as_bool),
            Some(preset.codex_mapped)
        );
        let claude_tools: Option<Vec<&str>> = config
            .get("claude_allowed_tools")
            .and_then(Value::as_array)
            .map(|tools| tools.iter().filter_map(Value::as_str).collect());
        assert_eq!(
            claude_tools,
            preset.claude_allowed_tools.map(|tools| tools.to_vec()),
            "profile `{name}` claude translation drifted"
        );
        let capabilities: Vec<&str> = config
            .get("capabilities")
            .and_then(Value::as_array)
            .map(|caps| caps.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        assert_eq!(
            capabilities,
            preset.capabilities.to_vec(),
            "profile `{name}` capability list drifted"
        );
        let owned = config.get("owned_tools").expect("owned_tools");
        let flag = |key: &str| owned.get(key).and_then(Value::as_bool).unwrap_or(false);
        assert_eq!(
            (
                flag("read_files"),
                flag("write_files"),
                flag("bash"),
                flag("tracker_file"),
                flag("tracker_claim"),
                flag("tracker_finish"),
                flag("tracker_release"),
                flag("workflow_invoke"),
            ),
            (
                preset.owned.read_files,
                preset.owned.write_files,
                preset.owned.bash,
                preset.owned.tracker_file,
                preset.owned.tracker_claim,
                preset.owned.tracker_finish,
                preset.owned.tracker_release,
                preset.owned.workflow_invoke,
            ),
            "profile `{name}` owned expansion drifted"
        );
    }
}

#[test]
fn telemetry_operator_provider_is_admission_inert_and_readable() {
    // std-telemetry.md T3, machine-checkable Non-Goals: the package's
    // `otlp` row is operator-plane — readable as a registry default,
    // invisible to every admission-plane surface.
    assert_eq!(
        embedded_operator_provider_default("std.telemetry", "otlp", "endpoint").as_deref(),
        Some("http://127.0.0.1:4318/v1/traces"),
    );
    assert_eq!(
        embedded_operator_provider_default("std.telemetry", "otlp", "protocol").as_deref(),
        Some("http/json"),
    );
    let (_, json) = whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS
        .iter()
        .find(|(name, _)| *name == "std.telemetry")
        .expect("std.telemetry is embedded");
    let value: Value = serde_json::from_str(json).expect("valid json");
    let label = Path::new("<embedded:std.telemetry>");
    // Registration writes no admission-plane row: zero effect providers,
    // zero effect contracts, zero capabilities.
    let providers = package_provider_contracts(label, &value).expect("effect-provider parse");
    assert!(
        providers.is_empty(),
        "operator-plane rows must never become effect providers: {providers:?}"
    );
    let manifest = package_manifest_from_json(
        &PathBuf::from("<embedded:std.telemetry>"),
        (*json).to_owned(),
    )
    .expect("telemetry manifest validates");
    assert!(manifest.registry.effect_contracts.is_empty());
    // …while the operator surface sees exactly the one row.
    let operator = package_operator_providers(label, &value).expect("operator parse");
    assert_eq!(operator.len(), 1);
    assert_eq!(operator[0].id, "otlp");
    assert_eq!(operator[0].provider_kind, "otlp-exporter");
}

/// spec/std-coercion.md slice 4 gate: the std.coercion manifest's
/// capability/provider/binding rows must AGREE with migration 0001's
/// seeded `schema.coerce` rows — the manifest supersedes the seeds, so a
/// drift between them is a lie one side tells operators. Agreement is
/// semantic where the names differ historically: the seeded binding
/// provider `builtin-coerce` and the manifest default `fixture` must both
/// select the FIXTURE path through the same resolver predicate.
#[test]
fn coercion_manifest_agrees_with_migration_seeded_rows() {
    let migration = include_str!("../../../whipplescript-store/migrations/0001_runtime_store.sql");
    let manifest: Value = serde_json::from_str(
        whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS
            .iter()
            .find(|(name, _)| *name == "std.coercion")
            .expect("std.coercion is embedded")
            .1,
    )
    .expect("valid json");
    // Capability row: both sides declare `schema.coerce`.
    assert!(
        migration.contains("('schema.coerce', 'Coerce unstructured data"),
        "migration 0001 seeds the schema.coerce capability"
    );
    let capability_ids: Vec<&str> = manifest["capabilities"]
        .as_array()
        .expect("capabilities")
        .iter()
        .filter_map(|capability| capability["id"].as_str())
        .collect();
    assert_eq!(capability_ids, ["schema.coerce"]);
    // Provider row: the seed registers ONE schema.coerce effect provider;
    // extract its provider name and require it to be the fixture path —
    // the same path the manifest's default binding selects.
    let seeded_provider_line = migration
        .lines()
        .find(|line| line.contains("'provider_coerce_builtin'"))
        .expect("migration 0001 seeds the schema.coerce effect provider");
    let seeded_provider = seeded_provider_line
        .split(',')
        .nth(2)
        .expect("provider column")
        .trim()
        .trim_matches(|c| c == '\'' || c == ' ');
    assert!(
        coerce_runtime::is_fixture_provider_name(seeded_provider),
        "the seeded default provider `{seeded_provider}` must select the fixture path"
    );
    let provider_ids: Vec<&str> = manifest["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .filter_map(|provider| provider["id"].as_str())
        .collect();
    assert_eq!(provider_ids, ["fixture", "native"]);
    for provider in manifest["providers"].as_array().expect("providers") {
        assert_eq!(provider["provider_kind"], "schema_coercer");
        assert_eq!(provider["capability"], "schema.coerce");
    }
    // Binding row: the seed binds schema.coerce globally to the fixture
    // path; the manifest's default binding selects provider `fixture`.
    let seeded_binding_line = migration
        .lines()
        .find(|line| line.contains("'binding_coerce_builtin'"))
        .expect("migration 0001 seeds the schema.coerce binding");
    let seeded_binding_provider = seeded_binding_line
        .split(',')
        .nth(3)
        .expect("binding provider column")
        .trim()
        .trim_matches(|c| c == '\'' || c == ')' || c == ' ');
    assert!(
        coerce_runtime::is_fixture_provider_name(seeded_binding_provider),
        "the seeded binding provider `{seeded_binding_provider}` must select the fixture path"
    );
    let bindings = manifest["bindings"].as_array().expect("bindings");
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0]["capability"], "schema.coerce");
    assert!(
        coerce_runtime::is_fixture_provider_name(
            bindings[0]["config"]["provider_id"]
                .as_str()
                .expect("default provider id")
        ),
        "the manifest default binding must select the fixture path"
    );
    // Profile row: both sides allow schema.coerce in a default profile.
    assert!(
        migration.contains(r#""schema.coerce""#),
        "migration 0001 profiles allow schema.coerce"
    );
    let profiles = manifest["profiles"].as_array().expect("profiles");
    assert!(profiles.iter().any(|profile| {
        profile["allowed_capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|cap| cap == "schema.coerce"))
    }));
}

/// The std.coercion manifest's `schema.coerce` contract mirrors the
/// parser-compiled one, so merging both (a coerce-using program that
/// imports std.coercion) FOLDS into one contract — a shape drift between
/// manifest and parser would instead surface as `effect_contract_duplicate`.
#[test]
fn coercion_manifest_contract_folds_against_the_parser_compiled_one() {
    let source = r#"use std.coercion

@service
workflow CoercionImport

enum Verdict {
  Yes
  No
}
coerce judge(summary string) -> Verdict {
  prompt """markdown
  Decide: {{ summary }}
  {{ ctx.output_format }}
  """
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compiles");
    let registry = contract_registry_for_ir(None, &ir).expect("registry resolves");
    assert_eq!(registry.validate(), Vec::new());
    let coerce_contracts: Vec<_> = registry
        .effect_contracts
        .iter()
        .filter(|contract| contract.id == "schema.coerce")
        .collect();
    assert_eq!(
        coerce_contracts.len(),
        1,
        "manifest and parser contracts must fold into one: {coerce_contracts:?}"
    );
    let contract = coerce_contracts[0];
    assert_eq!(contract.effect_kind, "schema.coerce");
    assert_eq!(contract.required_capabilities, ["schema.coerce"]);
    assert_eq!(contract.provider_kinds, ["schema_coercer"]);
    assert_eq!(
        contract.source_forms,
        ["coerce", "decide", "prompt"],
        "source forms merge-unique across the two copies"
    );
}

#[test]
fn operator_plane_provider_rows_are_shape_checked() {
    // The two dishonest shapes the T3 validator amendment refuses: an
    // operator row that ALSO claims a capability, and an unknown plane.
    let with_capability = r#"{
            "schema": "whipplescript.package_manifest.v0",
            "package_id": "p", "name": "p", "version": "0.1.0",
            "providers": [{"id": "x", "provider_kind": "k", "plane": "operator", "capability": "a.b"}]
        }"#;
    let error = package_manifest_from_json(Path::new("p.json"), with_capability.to_owned())
        .expect_err("operator rows are capability-free by definition");
    assert!(error.contains("capability-free"), "{error}");
    let unknown_plane = r#"{
            "schema": "whipplescript.package_manifest.v0",
            "package_id": "p", "name": "p", "version": "0.1.0",
            "providers": [{"id": "x", "provider_kind": "k", "plane": "orbital", "capability": "a.b"}]
        }"#;
    let error = package_manifest_from_json(Path::new("p.json"), unknown_plane.to_owned())
        .expect_err("unknown plane values are refused");
    assert!(error.contains("unknown plane"), "{error}");
}

#[test]
fn std_manifests_all_embedded() {
    // Blocker B1 door mirror: `scripts/artifact_admission.py`
    // (`embedded_std_construct_identities`) globs `std/manifests/*.json`
    // indiscriminately and treats every construct it finds as embedded-std
    // (door-privileged). The Rust authority instead reads only
    // `whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS`. If a construct-bearing manifest that is NOT
    // embedded ever lands under `std/manifests/`, Python would privilege it
    // (fail-open) while Rust would not — re-opening the gap the
    // grammar-only-manifests-live-in-std/grammars decision closed. This
    // test fails the build the moment such a manifest appears, forcing it
    // into `std/grammars/` (build.rs-only, un-globbed) or into the embedded
    // set. Keep the two sources in lockstep.
    let manifests_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../std/manifests");
    let entries = std::fs::read_dir(&manifests_dir)
        .expect("std/manifests directory must exist and be readable");
    let embedded_names: std::collections::HashSet<&str> =
        whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS
            .iter()
            .map(|(name, _)| *name)
            .collect();
    let mut checked = 0usize;
    for entry in entries {
        let path = entry.expect("std/manifests entry must be readable").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("could not read `{}`: {error}", path.display()));
        let manifest: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("`{}` is not valid JSON: {error}", path.display()));
        let has_construct = manifest
            .get("libraries")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|library| {
                library
                    .get("constructs")
                    .and_then(serde_json::Value::as_array)
            })
            .any(|constructs| !constructs.is_empty());
        if !has_construct {
            continue;
        }
        let name = manifest
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_else(|| panic!("`{}` is missing a top-level `name`", path.display()));
        assert!(
                embedded_names.contains(name),
                "construct-bearing std manifest `{}` (name `{name}`) is under std/manifests/ but not in \
                 whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS; either embed it (and update the parser build.rs list + the \
                 Python door) or move it to std/grammars/ (grammar-only, build.rs-read, un-globbed by the door)",
                path.display()
            );
        checked += 1;
    }
    assert!(
        checked > 0,
        "expected at least one construct-bearing manifest under std/manifests/"
    );
}

#[test]
fn registry_construct_embedded_std_copy_requires_full_identity() {
    // The report-registry layer keys on registration identity with an
    // embedded std construct; any drifted field breaks the match.
    let recall = json!({
        "id": "memory.recall",
        "library_id": "std.memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "lowering_target": "capability_call",
        "target_capability": "memory.query",
    });
    let embedded = embedded_std_manifests();
    assert!(registry_construct_is_embedded_std_copy(&recall, &embedded));
    let mut forged = recall.clone();
    forged["lowering_target"] = json!("core_effect");
    assert!(!registry_construct_is_embedded_std_copy(&forged, &embedded));
    let mut renamed = recall;
    renamed["library_id"] = json!("std.evil");
    assert!(!registry_construct_is_embedded_std_copy(
        &renamed, &embedded
    ));
}

#[test]
fn report_registry_rejects_internal_lowering_for_non_embedded_construct() {
    // The report-registry enforcement site: a package-library construct
    // with an internal lowering that is not the platform's embedded copy is
    // rejected (a reserved-looking library name grants nothing).
    let registry = json!({
        "libraries": [{ "id": "std.evil", "version": "0.1.0", "standard": false }],
        "constructs": [{
            "id": "evil.source",
            "library_id": "std.evil",
            "version": "0.1.0",
            "construct_family": "source_declaration",
            "keyword": "pulse",
            "scope": "top_level",
            "lowering_target": "signal_source",
        }],
        "effect_contracts": [],
    });
    let error = verify_contract_registry_platform_vocabulary(
        &registry,
        "report",
        &embedded_std_manifests(),
    )
    .expect_err("a non-embedded internal-lowering construct must be rejected");
    assert!(
        error.contains("platform-internal")
            && error.contains("only platform-embedded std manifests"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_construct_family() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-family.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "macro",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "metadata_only"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported construct family");
    assert!(
        error.contains("unsupported construct_family `macro`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_family_mismatch() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-family.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "declaration_block",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject capability_call family mismatch");
    assert!(
        error.contains("uses capability_call lowering but construct_family is `declaration_block`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_form_without_target() {
    let error = package_manifest_from_json(
        Path::new("bad-construct.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "lowering_target": "capability_call"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject capability_call without target");
    assert!(
        error.contains("uses capability_call lowering but has no target_capability"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_without_required_capability_interface() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-interface.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "provides": [{"kind": "EffectHandle"}],
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing Capability interface");
    assert!(
        error.contains("declares no required `Capability` interface"),
        "{error}"
    );
    assert!(
        error.contains("declares no required Capability interface named `memory.query`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_capability_call_without_effect_handle_interface() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-interface.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.query",
          "effect_kind": "capability.call",
          "required_capabilities": ["memory.query"]
        }
      ],
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "effect_operation",
          "keyword": "recall",
          "scope": "rule_body",
          "requires": [{"kind": "Capability", "name": "memory.query"}],
          "lowering_target": "capability_call",
          "target_capability": "memory.query"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.query"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject missing EffectHandle interface");
    assert!(
        error.contains("declares no provided `EffectHandle` interface"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_unsupported_construct_interface_kind() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-interface.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.pool",
          "construct_family": "declaration_block",
          "keyword": "memory",
          "provides": [{"kind": "Magic"}],
          "lowering_target": "metadata_only"
        }
      ]
    }
  ],
  "capabilities": []
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported interface kind");
    assert!(
        error.contains("provides interface uses unsupported kind `Magic`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_reserved_construct_keyword() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-keyword.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.call.form",
          "construct_family": "declaration_block",
          "keyword": "call",
          "scope": "rule_body",
          "lowering_target": "metadata_only"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject reserved construct keyword");
    assert!(
        error.contains("uses reserved construct keyword `call`"),
        "{error}"
    );
}

#[test]
fn package_manifest_accepts_authorized_reserved_construct_keyword() {
    let manifest = package_manifest_from_json(
        Path::new("std-tracker.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "std-tracker",
  "name": "tracker",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "std.tracker",
      "standard": true,
      "effect_contracts": [
        {
          "id": "tracker.claim",
          "effect_kind": "capability.call",
          "input_schema": {"issue": "string"},
          "required_capabilities": ["tracker.claim"]
        }
      ],
      "constructs": [
        {
          "id": "tracker.claim",
          "construct_family": "effect_operation",
          "keyword": "claim",
          "scope": "rule_body",
          "fields": [
            {"name": "issue", "kind": "expression", "required": true}
          ],
          "requires": [
            {"kind": "Capability", "name": "tracker.claim"}
          ],
          "provides": [
            {"kind": "EffectHandle"}
          ],
          "lowering_target": "typed_effect_call"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "tracker.claim"}
  ]
}
"#
        .to_owned(),
    )
    .expect("std.tracker claim keyword privilege should be accepted");

    assert!(manifest.registry.constructs.iter().any(|form| {
        form.library_id == "std.tracker"
            && form.keyword == "claim"
            && form.lowering_target == "typed_effect_call"
    }));
}

#[test]
fn package_manifest_rejects_unprivileged_reserved_construct_keyword() {
    let error = package_manifest_from_json(
        Path::new("bad-memory-claim.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "effect_contracts": [
        {
          "id": "memory.claim",
          "effect_kind": "capability.call",
          "input_schema": {"issue": "string"},
          "required_capabilities": ["memory.claim"]
        }
      ],
      "constructs": [
        {
          "id": "memory.claim",
          "construct_family": "effect_operation",
          "keyword": "claim",
          "scope": "rule_body",
          "fields": [
            {"name": "issue", "kind": "expression", "required": true}
          ],
          "requires": [
            {"kind": "Capability", "name": "memory.claim"}
          ],
          "provides": [
            {"kind": "EffectHandle"}
          ],
          "lowering_target": "capability_call",
          "target_capability": "memory.claim"
        }
      ]
    }
  ],
  "capabilities": [
    {"id": "memory.claim"}
  ]
}
"#
        .to_owned(),
    )
    .expect_err("unprivileged package should not own claim keyword");

    assert!(
        error.contains("uses reserved construct keyword `claim`"),
        "{error}"
    );
    assert!(
        error.contains("platform catalog authorization for library `memory`"),
        "{error}"
    );
}

/// A `declaration_block` grammar-only manifest with a single clause, for the
/// decl-grammar validator tests. `clause` is the raw JSON of one clause; the
/// library uses the non-reserved keyword `widget` so no privilege is needed.
fn declaration_grammar_manifest(clause: &str) -> String {
    format!(
        r#"{{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "gadget",
  "name": "gadget",
  "version": "0.1.0",
  "libraries": [
    {{
      "id": "gadget",
      "constructs": [
        {{
          "id": "gadget.widget",
          "construct_family": "declaration_block",
          "keyword": "widget",
          "scope": "top_level",
          "grammar": {{
            "shape": "declaration_block",
            "keyword": "widget",
            "clauses": [{clause}]
          }}
        }}
      ]
    }}
  ]
}}"#
    )
}

#[test]
fn package_manifest_accepts_declaration_block_grammar() {
    // A flag clause, a connective-introduced value clause, and a list
    // clause. The default `metadata_only` lowering is declaration_block-
    // compatible, so no capabilities or effect contracts are required.
    let manifest = package_manifest_from_json(
            Path::new("gadget-grammar.json"),
            declaration_grammar_manifest(
                r#"
              {"name": "shared", "kind": "flag", "required": false, "list": false,
               "unknown_hint": "no such field", "missing_summary": "add a field"},
              {"name": "partition", "kind": "identifier", "required": true, "list": false,
               "connective": "by", "unknown_hint": "no such field", "missing_summary": "add a field"},
              {"name": "allow read", "kind": "glob", "required": false, "list": true,
               "unknown_hint": "no such field", "missing_summary": "add a field"}
            "#,
            ),
        )
        .expect("declaration_block grammar manifest should validate");

    let form = manifest
        .registry
        .constructs
        .iter()
        .find(|form| form.id == "gadget.widget")
        .expect("gadget.widget construct");
    assert_eq!(form.construct_family, "declaration_block");
    let grammar = form
        .grammar
        .as_ref()
        .expect("grammar carried on the registration");
    assert_eq!(
        grammar.shape,
        whipplescript_core::CONSTRUCT_GRAMMAR_SHAPE_DECLARATION_BLOCK
    );
    let clauses = grammar
        .clauses
        .as_ref()
        .expect("declaration_block grammar carries clauses");
    assert_eq!(clauses.len(), 3);
    assert_eq!(clauses[1].connective.as_deref(), Some("by"));
    // The derived flat `fields[]` view: flag -> optional boolean, value
    // clause -> its own kind, list clause -> the `list` field kind.
    assert_eq!(
        form.fields,
        vec![
            ConstructField {
                name: "shared".to_owned(),
                kind: "boolean".to_owned(),
                required: false,
            },
            ConstructField {
                name: "partition".to_owned(),
                kind: "identifier".to_owned(),
                required: true,
            },
            ConstructField {
                name: "allow read".to_owned(),
                kind: "list".to_owned(),
                required: false,
            },
        ]
    );
}

#[test]
fn package_manifest_rejects_declaration_flag_with_list() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "shared", "kind": "flag", "required": false, "list": true,
                    "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("a flag clause cannot be a list");
    assert!(
        error.contains("is a `flag` and cannot set `list: true`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_declaration_flag_with_connective() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "shared", "kind": "flag", "required": false, "list": false,
                    "connective": "by", "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("a flag clause cannot carry a connective");
    assert!(
        error.contains("is a `flag` and cannot carry a connective"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_declaration_unknown_clause_kind() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "x", "kind": "mystery", "required": true, "list": false,
                    "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("an unknown clause kind is rejected");
    assert!(error.contains("uses unsupported kind `mystery`"), "{error}");
}

#[test]
fn package_manifest_rejects_declaration_unknown_connective() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "x", "kind": "identifier", "required": true, "list": false,
                    "connective": "beside", "unknown_hint": "h", "missing_summary": "s"}"#,
        ),
    )
    .expect_err("an unknown connective is rejected");
    assert!(
        error.contains("uses unsupported connective `beside`"),
        "{error}"
    );
}

#[test]
fn package_manifest_rejects_declaration_unknown_clause_key() {
    let error = package_manifest_from_json(
        Path::new("gadget-grammar.json"),
        declaration_grammar_manifest(
            r#"{"name": "x", "kind": "identifier", "required": true, "list": false,
                    "unknown_hint": "h", "missing_summary": "s", "extra": true}"#,
        ),
    )
    .expect_err("an unknown clause key is rejected");
    assert!(error.contains("field `extra` is not allowed"), "{error}");
}

#[test]
fn package_check_accepts_std_grammar_manifests() {
    // The five grammar-only std manifests (read by `build.rs` for the parse
    // table) are now fully-checkable first-class package manifests: each
    // passes `whip package check` (parse + consistency + registry
    // diagnostics) now that `declaration_block` is a supported shape.
    let sources = [
        (
            "std/grammars/tracker.json",
            include_str!("../../../../std/grammars/tracker.json"),
        ),
        (
            "std/grammars/coord.json",
            include_str!("../../../../std/grammars/coord.json"),
        ),
        (
            "std/grammars/files.json",
            include_str!("../../../../std/grammars/files.json"),
        ),
        (
            "std/grammars/messaging-grammar.json",
            include_str!("../../../../std/grammars/messaging-grammar.json"),
        ),
        (
            "std/grammars/memory-grammar.json",
            include_str!("../../../../std/grammars/memory-grammar.json"),
        ),
    ];
    for (label, json) in sources {
        let manifest = package_manifest_from_json(Path::new(label), json.to_owned())
            .unwrap_or_else(|error| {
                panic!("std grammar manifest `{label}` must validate: {error}")
            });
        let registry = package_registry(std::slice::from_ref(&manifest));
        let diagnostics = registry.validate();
        assert!(
            diagnostics.is_empty(),
            "std grammar manifest `{label}` must pass package check: {diagnostics:?}"
        );
    }
}

#[test]
fn package_manifest_rejects_unsupported_construct_field_kind() {
    let error = package_manifest_from_json(
        Path::new("bad-construct-field-kind.json"),
        r#"
{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-memory",
  "name": "memory",
  "version": "0.1.0",
  "libraries": [
    {
      "id": "memory",
      "constructs": [
        {
          "id": "memory.recall",
          "construct_family": "declaration_block",
          "keyword": "recall",
          "scope": "rule_body",
          "fields": [
            {"name": "pool", "kind": "macro"}
          ],
          "lowering_target": "metadata_only"
        }
      ]
    }
  ]
}
"#
        .to_owned(),
    )
    .expect_err("manifest should reject unsupported construct field kind");
    assert!(
        error.contains("field `pool` uses unsupported kind `macro`"),
        "{error}"
    );
}

#[test]
fn package_lock_json_emits_portable_source_shape_no_absolute_path() {
    let manifest_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/packages/notes.json");
    let manifest = load_package_manifest(&manifest_path).expect("manifest loads");
    let base_dir = manifest_path
        .parent()
        .expect("manifest parent")
        .to_path_buf();
    let lock_json = package_lock_json(&[manifest], &base_dir);

    let entry = &lock_json["packages"][0];
    // No absolute manifest_path field; only a portable relative source.
    assert!(entry.get("manifest_path").is_none(), "{lock_json}");
    assert_eq!(entry["source"]["type"], "path");
    let source_path = entry["source"]["path"].as_str().expect("source path");
    assert_eq!(source_path, "notes.json");
    assert!(
        is_portable_relative_path(source_path),
        "source path must be portable: {source_path}"
    );
    // The serialized lock must not contain any absolute path or the old key.
    let serialized = canonical_lock_text(&lock_json);
    assert!(!serialized.contains("manifest_path"), "{serialized}");
    assert!(
        !serialized.contains(&base_dir.display().to_string()),
        "lock must not embed the absolute base dir: {serialized}"
    );
}

#[test]
fn canonical_lock_text_is_sorted_indented_and_lf_terminated() {
    let value = json!({
        "schema": PACKAGE_LOCK_SCHEMA,
        "packages": [
            {"name": "z", "package_id": "p", "version": "1", "source": {"type": "path", "path": "a"}}
        ],
    });
    let text = canonical_lock_text(&value);
    // Exactly one trailing LF newline, no CR.
    assert!(text.ends_with("}\n"), "{text:?}");
    assert!(!text.ends_with("}\n\n"), "{text:?}");
    assert!(!text.contains('\r'), "{text:?}");
    // Top-level keys sorted: packages before schema.
    let packages_at = text.find("\"packages\"").expect("packages key");
    let schema_at = text.find("\"schema\"").expect("schema key");
    assert!(packages_at < schema_at, "{text}");
    // 2-space indentation for the first nested key.
    assert!(text.contains("\n  \"packages\""), "{text}");
    // Deterministic: serializing twice produces identical bytes.
    assert_eq!(text, canonical_lock_text(&value));
}

#[test]
fn package_lock_json_sorts_packages_by_name_then_package_id() {
    fn manifest(name: &str, id: &str) -> PackageManifest {
        PackageManifest {
            path: PathBuf::from(format!("{name}.json")),
            manifest_json: String::new(),
            manifest_sha256: "0".repeat(64),
            package_id: id.to_owned(),
            name: name.to_owned(),
            version: "0.1.0".to_owned(),
            registry: ContractRegistry::default(),
            workflow_tools: Vec::new(),
        }
    }
    let manifests = vec![
        manifest("beta", "pkg-beta"),
        manifest("alpha", "pkg-alpha-2"),
        manifest("alpha", "pkg-alpha-1"),
    ];
    let lock = package_lock_json(&manifests, Path::new("."));
    let names = lock["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .map(|entry| {
            (
                entry["name"].as_str().expect("present").to_owned(),
                entry["package_id"].as_str().expect("present").to_owned(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            ("alpha".to_owned(), "pkg-alpha-1".to_owned()),
            ("alpha".to_owned(), "pkg-alpha-2".to_owned()),
            ("beta".to_owned(), "pkg-beta".to_owned()),
        ]
    );
}

/// Set up a temp project containing the notes manifest and a `whip.packages.json`.
/// Returns (temp_dir, package_set_path).
fn write_notes_package_set(slug: &str) -> (PathBuf, PathBuf) {
    let manifest_src =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/packages/notes.json");
    let temp_dir = env::temp_dir().join(format!(
        "whipplescript-sync-{slug}-{}",
        stable_hash_hex(&manifest_src.display().to_string())
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(temp_dir.join("packages")).expect("packages dir");
    fs::copy(&manifest_src, temp_dir.join("packages/notes.json")).expect("manifest copies");
    let set = json!({
        "schema": PACKAGE_SET_SCHEMA,
        "packages": [
            {"name": "notes", "source": {"type": "path", "path": "packages/notes.json"}}
        ],
    });
    let set_path = temp_dir.join("whip.packages.json");
    fs::write(&set_path, canonical_lock_text(&set)).expect("set writes");
    (temp_dir, set_path)
}

#[test]
fn package_sync_resolution_is_byte_identical_across_runs() {
    let (temp_dir, set_path) = write_notes_package_set("deterministic");
    let lock_path = temp_dir.join("whip.lock");

    let first = resolve_package_sync(Some(set_path.clone()), Some(lock_path.clone()))
        .expect("first sync resolves");
    let second = resolve_package_sync(Some(set_path.clone()), Some(lock_path.clone()))
        .expect("second sync resolves");

    // Deterministic on-disk bytes and digest -> --check-only is stable.
    assert_eq!(first.lock_text, second.lock_text);
    assert_eq!(first.package_lock_digest, second.package_lock_digest);
    // Portable source, no absolute manifest path.
    assert!(
        !first.lock_text.contains("manifest_path"),
        "{}",
        first.lock_text
    );
    assert!(
        first.lock_text.contains("packages/notes.json"),
        "{}",
        first.lock_text
    );

    // Writing then re-resolving yields bytes identical to what was written.
    write_lock_atomically(&lock_path, &first.lock_text).expect("lock writes");
    let written = fs::read_to_string(&lock_path).expect("lock reads");
    assert_eq!(written, first.lock_text);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn package_sync_rejects_nonportable_source_path() {
    let manifest_src =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/packages/notes.json");
    let temp_dir = env::temp_dir().join(format!(
        "whipplescript-sync-escape-{}",
        stable_hash_hex(&manifest_src.display().to_string())
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("temp dir");
    let set = json!({
        "schema": PACKAGE_SET_SCHEMA,
        "packages": [
            {"name": "notes", "source": {"type": "path", "path": "../escape.json"}}
        ],
    });
    let set_path = temp_dir.join("whip.packages.json");
    fs::write(&set_path, canonical_lock_text(&set)).expect("set writes");

    let diagnostics = resolve_package_sync(Some(set_path), Some(temp_dir.join("whip.lock")))
        .expect_err("nonportable path must fail");
    assert!(
        diagnostics
            .iter()
            .any(|d| d.code == "package_source.nonportable_path"),
        "{:?}",
        diagnostics.iter().map(|d| d.code).collect::<Vec<_>>()
    );
    let _ = fs::remove_dir_all(&temp_dir);
}

/// Copy the `notes` example manifest into a fresh temp directory and write
/// a portable lock alongside it. Returns the temp directory (caller cleans
/// up), the lock path, and the parsed lock JSON so tests can mutate it.
fn write_portable_notes_lock(slug: &str) -> (PathBuf, PathBuf, Value) {
    let manifest_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/packages/notes.json");
    let temp_dir = env::temp_dir().join(format!(
        "whipplescript-lock-{slug}-{}",
        stable_hash_hex(&manifest_path.display().to_string())
    ));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("temp dir");
    let copied_manifest = temp_dir.join("notes.json");
    fs::copy(&manifest_path, &copied_manifest).expect("manifest copies");
    let manifest = load_package_manifest(&copied_manifest).expect("manifest loads");
    let lock_json = package_lock_json(&[manifest], &temp_dir);
    let lock_path = temp_dir.join("whip.lock");
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    (temp_dir, lock_path, lock_json)
}

#[test]
fn package_lock_supplies_package_import_registry() {
    let (temp_dir, lock_path, lock_json) = write_portable_notes_lock("import-registry");
    // The portable lock must record a relative source, never an absolute path.
    let source_path = lock_json["packages"][0]["source"]["path"]
        .as_str()
        .expect("source path");
    assert_eq!(source_path, "notes.json");
    assert!(lock_json["packages"][0].get("manifest_path").is_none());
    let lock = load_package_lock_file(&lock_path).expect("lock loads");
    let _ = fs::remove_dir_all(&temp_dir);

    let source = r#"
workflow PackageLockRegistry

use notes

class Task {
  title string
}

rule start
  when Task as task
=> {
  call notes.query for task as context
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    // `memory` ships as the embedded `std.memory` manifest (M5), so
    // `use std.memory` + `recall` resolves with no lock at all — no supply
    // chain required.
    let embedded_ir = whipplescript_parser::compile_program(
        r#"
workflow EmbeddedMemory

use std.memory

memory pool project_memory {
  context limit 8
}

class Task {
  title string
}

rule start
  when Task as task
=> {
  recall project_memory for task as context
}
"#,
    )
    .ir
    .expect("embedded source compiles");
    let embedded = contract_registry_for_ir(None, &embedded_ir)
        .expect("embedded `std.memory` manifest resolves without a lock");
    assert!(
        embedded.constructs.iter().any(|form| {
            form.keyword == "recall" && form.target_capability.as_deref() == Some("memory.query")
        }),
        "embedded resolution authorizes the `recall` construct"
    );
    // A genuinely-unlocked (non-embedded) import still trips the no-lock guard.
    let unlocked_ir = whipplescript_parser::compile_program(
        r#"
workflow Unlocked

use notebook

class Task {
  title string
}

rule start
  when Task as task
=> {
  record Task {
    title "keep"
  }
}
"#,
    )
    .ir
    .expect("unlocked source compiles");
    let no_lock_error = contract_registry_for_ir(None, &unlocked_ir)
        .expect_err("a non-embedded import requires a package lock");
    assert!(
        no_lock_error.contains("requires a package lock")
            && no_lock_error.contains("whip package sync")
            && no_lock_error.contains("import `notebook`"),
        "{no_lock_error}"
    );
    let registry = lock.registry_for_ir(&ir).expect("registry resolves");

    assert!(registry
        .libraries
        .iter()
        .any(|library| library.id == "notes" && library.version == "0.1.0"));
    assert!(registry
        .effect_contracts
        .iter()
        .any(|contract| contract.id == "notes.query" && contract.effect_kind == "capability.call"));
    assert_eq!(registry.validate(), Vec::new());
}

#[test]
fn package_lock_rejects_reserved_std_namespace_entries() {
    // A supply-chain lock can never provide a `std.*` package: std packages
    // ship embedded in the platform, and embedded always wins.
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("reserved-std");
    let manifest_path = temp_dir.join("std.memory.json");
    let manifest_json = fs::read_to_string(temp_dir.join("notes.json"))
        .expect("read notes manifest")
        .replace("\"name\": \"notes\"", "\"name\": \"std.memory\"");
    fs::write(&manifest_path, &manifest_json).expect("write std-named manifest");
    let entry = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object");
    entry.insert("name".to_owned(), Value::String("std.memory".to_owned()));
    entry.insert(
        "source".to_owned(),
        json!({"type": "path", "path": "std.memory.json"}),
    );
    entry.insert(
        "manifest_sha256".to_owned(),
        Value::String(sha256_hex(manifest_json.as_bytes())),
    );
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path)
        .expect_err("a reserved std.* lock entry must be rejected");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("entry `std.memory` claims the reserved std namespace")
            && error.contains("cannot be provided by a package lock"),
        "{error}"
    );
}

#[test]
fn embedded_messaging_manifest_matches_core_reference_data() {
    // The embedded `std.messaging` manifest must transcribe the core
    // reference data (`std_messaging_send_construct` /
    // `std_messaging_send_effect_contract`) field-for-field, so the two can
    // never drift while both exist. Both now share the `0.1.0` package
    // version, so the comparison is a full field-for-field equality.
    let manifest = embedded_std_manifests()
        .into_iter()
        .find(|manifest| manifest.name == "std.messaging")
        .expect("std.messaging ships as an embedded manifest");

    let construct = manifest
        .registry
        .constructs
        .iter()
        .find(|form| form.keyword == "send")
        .expect("manifest registers the send construct");
    let expected_construct = whipplescript_core::std_messaging_send_construct();
    assert_eq!(construct, &expected_construct);

    let contract = manifest
        .registry
        .effect_contracts
        .iter()
        .find(|contract| contract.id == "messaging.send")
        .expect("manifest registers the messaging.send effect contract");
    let expected_contract = whipplescript_core::std_messaging_send_effect_contract();
    assert_eq!(contract, &expected_contract);
}

/// The embedded std.messaging manifest's `bindings[]` rows are the M2
/// load-bearing selection rows (spec/std-messaging.md "Manifest"): one per
/// v1 provider, each carrying that provider's capability report in the
/// binding config — mirroring the parser's compiled
/// `CHANNEL_PROVIDER_REPORTS` constants (reports are DATA in two mirrored
/// homes; this test is the drift gate between them).
#[test]
fn messaging_manifest_bindings_mirror_parser_capability_reports() {
    let (_, json) = whipplescript::std_manifests::EMBEDDED_STD_MANIFESTS
        .iter()
        .find(|(name, _)| *name == "std.messaging")
        .expect("std.messaging embedded manifest");
    let manifest: Value = serde_json::from_str(json).expect("valid json");
    let bindings = manifest["bindings"].as_array().expect("bindings");
    let reports = whipplescript_parser::CHANNEL_PROVIDER_REPORTS;
    assert_eq!(
        bindings.len(),
        reports.len(),
        "one binding row per v1 provider"
    );
    for report in reports {
        let binding = bindings
            .iter()
            .find(|binding| binding["provider"] == report.provider_id)
            .unwrap_or_else(|| panic!("binding for provider `{}`", report.provider_id));
        assert_eq!(binding["capability"], "messaging.send");
        assert_eq!(
            binding["program_id"],
            Value::Null,
            "v1 messaging bindings are global"
        );
        let manifest_report = &binding["config"]["report"];
        assert_eq!(
            manifest_report["direction"], report.direction,
            "direction mirrors the parser report for `{}`",
            report.short_name
        );
        assert_eq!(manifest_report["identity"], report.identity);
        let interactions: Vec<&str> = manifest_report["interactions"]
            .as_array()
            .expect("interactions")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(interactions, report.interactions);
        let receipts: Vec<&str> = manifest_report["delivery_receipts"]
            .as_array()
            .expect("delivery_receipts")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert_eq!(receipts, report.delivery_receipts);
    }
    // Every binding's provider has a matching providers[] row (the
    // manifest-consistency validator's cross-check), and the default
    // profile allows messaging.send.
    let provider_kinds: Vec<&str> = manifest["providers"]
        .as_array()
        .expect("providers")
        .iter()
        .filter_map(|provider| provider["provider_kind"].as_str())
        .collect();
    for report in reports {
        assert!(provider_kinds.contains(&report.provider_id));
    }
    let profiles = manifest["profiles"].as_array().expect("profiles");
    assert!(profiles.iter().any(|profile| {
        profile["allowed_capabilities"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|cap| cap == "messaging.send"))
    }));
    // The contract's output schema is exactly the 8-field receipt.
    let output_schema = manifest
        .pointer("/libraries/0/effect_contracts/0/output_schema")
        .and_then(Value::as_object)
        .expect("output schema");
    let fields: Vec<&str> = output_schema.keys().map(String::as_str).collect();
    assert_eq!(
        fields,
        [
            "accepted_at",
            "channel",
            "destination",
            "message_id",
            "provider",
            "provider_message_id",
            "status",
            "thread_id",
        ]
    );
}

/// Channel→binding provider resolution (spec/std-messaging.md
/// "Channel→binding provider selection"): short names resolve to exactly
/// one bound provider id; unknown and ambiguous identifiers fail with the
/// bound set named; a missing provider field resolves as `fixture`.
#[test]
fn resolve_messaging_binding_selects_exactly_one_provider() {
    let binding = |id: &str, provider: &str| whipplescript_store::CapabilityBindingView {
        binding_id: id.to_owned(),
        program_id: None,
        capability: "messaging.send".to_owned(),
        provider: Some(provider.to_owned()),
        config_json: "{}".to_owned(),
    };
    let bindings = vec![
        // A stray binding naming a provider no channel declares stays inert.
        binding("stray", "builtin-messaging"),
        binding("b-fixture", "fixture"),
        binding("b-local", "std.messaging.local"),
        binding("b-desktop", "std.messaging.desktop"),
        binding("b-stdio", "std.messaging.stdio"),
    ];
    // Short names resolve to the qualified binding provider id.
    assert_eq!(
        resolve_messaging_binding(&bindings, Some("local")).as_deref(),
        Ok("std.messaging.local")
    );
    assert_eq!(
        resolve_messaging_binding(&bindings, Some("desktop")).as_deref(),
        Ok("std.messaging.desktop")
    );
    // Exact provider ids resolve as themselves.
    assert_eq!(
        resolve_messaging_binding(&bindings, Some("std.messaging.stdio")).as_deref(),
        Ok("std.messaging.stdio")
    );
    assert_eq!(
        resolve_messaging_binding(&bindings, Some("fixture")).as_deref(),
        Ok("fixture")
    );
    // Pre-selection programs (no threaded provider) keep the fixture.
    assert_eq!(
        resolve_messaging_binding(&bindings, None).as_deref(),
        Ok("fixture")
    );
    // Unknown identifiers fail, naming the bound set.
    let unknown = resolve_messaging_binding(&bindings, Some("slack"))
        .expect_err("unknown provider is a dispatch failure");
    assert!(
        unknown.contains("`slack`") && unknown.contains("std.messaging.local"),
        "{unknown}"
    );
    // A short name matching BOTH a bare and a qualified binding is
    // ambiguous (exactly-one rule).
    let mut ambiguous = bindings.clone();
    ambiguous.push(binding("b-local-bare", "local"));
    let error = resolve_messaging_binding(&ambiguous, Some("local"))
        .expect_err("two distinct matches are ambiguous");
    assert!(error.contains("ambiguous"), "{error}");
    // Duplicate rows naming the SAME provider id (program-scoped + global)
    // are not ambiguous.
    let mut duplicated = bindings.clone();
    duplicated.push(binding("b-local-program", "std.messaging.local"));
    assert_eq!(
        resolve_messaging_binding(&duplicated, Some("local")).as_deref(),
        Ok("std.messaging.local")
    );
}

/// Desktop notifier command construction is PURE and platform-shaped
/// (spec/std-messaging.md slice 4): notify-send argument order, osascript
/// AppleScript embedding with quote-safe escaping.
#[test]
fn desktop_notify_command_builds_platform_invocations() {
    let (program, args) = desktop_notify_command("notify-send", "Ops", "disk almost full");
    assert_eq!(program, "notify-send");
    assert_eq!(args, ["Ops", "disk almost full"]);

    let (program, args) =
        desktop_notify_command("/usr/bin/osascript", "Ops \"quoted\"", "body \\ slash");
    assert_eq!(program, "/usr/bin/osascript");
    assert_eq!(args[0], "-e");
    assert_eq!(
        args[1], r#"display notification "body \\ slash" with title "Ops \"quoted\"""#,
        "arguments embed as JSON-escaped AppleScript string literals"
    );

    // A fake notifier override keeps the notify-send shape.
    let (program, args) = desktop_notify_command("/tmp/fake-notifier.sh", "t", "b");
    assert_eq!(program, "/tmp/fake-notifier.sh");
    assert_eq!(args, ["t", "b"]);
}

/// Markdown strips to notification text (desktop report content ⊆ {text}).
#[test]
fn markdown_strips_to_plain_text() {
    assert_eq!(
        markdown_to_text("# Alert\n\n**disk** is `90%` _full_ — see [runbook](https://x.y/z)"),
        "Alert\n\ndisk is 90% full — see runbook"
    );
    assert_eq!(markdown_to_text("> quoted *emphasis*"), "quoted emphasis");
    // A bare `[` without a link tail survives.
    assert_eq!(markdown_to_text("array[0] stays"), "array[0] stays");
    assert_eq!(markdown_to_text(""), "");
}

#[test]
fn send_requires_std_messaging_import_and_validates_lock_free_with_it() {
    // `send` migrated from an ambient parser builtin to the embedded
    // `std.messaging` manifest (the import ladder): without
    // `use std.messaging` it is rejected with the import hint; with the
    // import it validates with no package lock at all.
    let source = |uses: &str| {
        format!(
            r##"
@service
workflow Notify
{uses}
class Trigger {{
  id string
}}

channel alerts {{
  provider fixture
  destination "#ops"
}}

rule notify
  when Trigger as t
=> {{
  send via alerts {{
    text "hello"
  }} as sent
}}
"##
        )
    };
    let without_import = whipplescript_parser::compile_program(&source(""))
        .ir
        .expect("source compiles");
    let error = contract_registry_for_ir(None, &without_import)
        .expect_err("send without `use std.messaging` must be rejected");
    assert!(
        error.contains("construct `send`")
            && error.contains("embedded std package `std.messaging`")
            && error.contains("add `use std.messaging`"),
        "{error}"
    );

    // A package lock does not change the fix: `send` is embedded-owned, so
    // the lock path emits the same import hint instead of blaming the lock.
    let (temp_dir, lock_path, _) = write_portable_notes_lock("send-import-hint");
    let lock = load_package_lock_file(&lock_path).expect("lock loads");
    let _ = fs::remove_dir_all(&temp_dir);
    let locked_error = lock
        .registry_for_ir(&without_import)
        .expect_err("send without `use std.messaging` is rejected under a lock too");
    assert!(
        locked_error.contains("add `use std.messaging`"),
        "{locked_error}"
    );

    let with_import = whipplescript_parser::compile_program(&source("\nuse std.messaging\n"))
        .ir
        .expect("source compiles");
    let registry = contract_registry_for_ir(None, &with_import)
        .expect("`use std.messaging` authorizes send with no lock");
    assert!(
        registry.constructs.iter().any(|form| {
            form.keyword == "send"
                && form.library_id == "std.messaging"
                && form.target_capability.as_deref() == Some("messaging.send")
        }),
        "embedded resolution authorizes the `send` construct"
    );
    assert!(
        registry.effect_contracts.iter().any(|contract| {
            contract.id == "messaging.send" && contract.effect_kind == "capability.call"
        }),
        "embedded resolution registers the messaging.send contract"
    );
    assert_eq!(registry.validate(), Vec::new());
}

#[test]
fn package_sync_refuses_reserved_std_manifest_names() {
    let (temp_dir, set_path) = write_notes_package_set("reserved-std");
    // Point the package set at a manifest claiming the reserved namespace.
    let manifest_path = temp_dir.join("packages/notes.json");
    let manifest_json = fs::read_to_string(&manifest_path)
        .expect("read notes manifest")
        .replace("\"name\": \"notes\"", "\"name\": \"std.notes\"");
    fs::write(&manifest_path, manifest_json).expect("write std-named manifest");
    let set = json!({
        "schema": PACKAGE_SET_SCHEMA,
        "packages": [
            {"name": "std.notes", "source": {"type": "path", "path": "packages/notes.json"}}
        ],
    });
    fs::write(&set_path, canonical_lock_text(&set)).expect("set writes");

    let diagnostics = resolve_package_sync(Some(set_path), Some(temp_dir.join("whip.lock")))
        .expect_err("a reserved std.* manifest name must refuse to sync");
    let _ = fs::remove_dir_all(&temp_dir);
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "package_manifest.reserved_std_name"
                && diagnostic.message.contains("reserved std namespace")
        }),
        "{:?}",
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.message.as_str()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn package_lock_rejects_duplicate_package_entries() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("duplicate-entries");
    let packages = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .expect("packages array");
    packages.push(packages[0].clone());
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path)
        .expect_err("duplicate package entries should be rejected");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package_id `package-notes` more than once"),
        "{error}"
    );
    assert!(
        error.contains("package name `notes` more than once"),
        "{error}"
    );
}

#[test]
fn package_lock_rejects_unknown_closed_schema_fields() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("unknown-fields");
    lock_json
        .as_object_mut()
        .expect("lock object")
        .insert("unexpected_top".to_owned(), Value::Bool(true));
    lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object")
        .insert("unexpected_entry".to_owned(), Value::Bool(true));
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path).expect_err("unknown lock fields should reject");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package lock field `unexpected_top` is not allowed"),
        "{error}"
    );
    assert!(
        error.contains("package lock.packages[0] field `unexpected_entry` is not allowed"),
        "{error}"
    );
}

#[test]
fn package_lock_rejects_missing_required_fields() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("missing-fields");
    let package = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object");
    package.remove("source");
    package.remove("manifest_sha256");
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path).expect_err("missing lock fields should reject");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package lock.packages[0] missing required field `source`"),
        "{error}"
    );
    assert!(
        error.contains("package lock.packages[0] missing required field `manifest_sha256`"),
        "{error}"
    );
}

#[test]
fn package_lock_rejects_invalid_field_types_and_hash_shape() {
    let (temp_dir, lock_path, mut lock_json) = write_portable_notes_lock("invalid-fields");
    let package = lock_json
        .get_mut("packages")
        .and_then(Value::as_array_mut)
        .and_then(|packages| packages.first_mut())
        .and_then(Value::as_object_mut)
        .expect("package entry object");
    package.insert("package_id".to_owned(), Value::Null);
    package.insert(
        "source".to_owned(),
        json!({"type": "path", "path": "/etc/passwd"}),
    );
    package.insert(
        "manifest_sha256".to_owned(),
        Value::String("ABC".to_owned()),
    );
    fs::write(&lock_path, canonical_lock_text(&lock_json)).expect("lock writes");
    let error = load_package_lock_file(&lock_path).expect_err("invalid lock fields should reject");
    let _ = fs::remove_dir_all(&temp_dir);

    assert!(
        error.contains("package lock.packages[0] field `package_id` must be a non-empty string"),
        "{error}"
    );
    assert!(
        error.contains(
            "package lock.packages[0].source.path must be a portable project-relative path"
        ),
        "{error}"
    );
    assert!(
            error.contains(
                "package lock.packages[0] field `manifest_sha256` must be a 64-character lowercase hex digest"
            ),
            "{error}"
        );
}

fn package_memory_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    // `std.memory` ships embedded (M5), so the package-backed graph resolves
    // with no lock at all.
    let source = r#"
workflow PackageGraph

use std.memory

memory pool project_memory {
  context limit 8
}

class Task {
  title string
}

rule start
  when Task as task
=> {
  recall project_memory for task as context
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry =
        contract_registry_for_ir(None, &ir).expect("embedded std.memory registry resolves");
    let graph = construct_graph_json("package-graph.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("package-graph.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn package_memory_dependency_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    let source = r#"
workflow PackageGraph

use std.memory

memory pool project_memory {
  context limit 8
}

class Task {
  title string
}

rule start
  when Task as task
=> {
  recall project_memory for task as first

  after first succeeds {
    recall project_memory for task as second
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry =
        contract_registry_for_ir(None, &ir).expect("embedded std.memory registry resolves");
    let graph = construct_graph_json("package-graph.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("package-graph.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn core_effect_dependency_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    let source = r#"
workflow CoreGraph

class Task {
  title string
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule start
  when Task as task
=> {
  tell worker as first """
  Write a plan for {{ task.title }}.
  """

  after first succeeds {
    tell worker as second """
    Review the plan for {{ task.title }}.
    """
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = ir.contract_registry();
    let graph = construct_graph_json("core-graph.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("core-graph.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn signal_source_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    // A `signal {}` declaration is a typed schema with no construct-graph node;
    // the `signal_source` node comes from a generic (non-clock) `source` block.
    let source = r#"
@service
workflow EventIngress

signal deploy.finished {
  service string
  status "ok" | "failed"
}

source webhook as deploy_events {
  observe as obs
  emit deploy.finished {
    service obs.service
    status obs.status
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = ir.contract_registry();
    let graph = construct_graph_json("event-ingress.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("event-ingress.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn clock_source_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    let source = r#"
@service
workflow ClockIngress

signal triage.tick {
  scheduled_at time
}

source clock as daily_triage {
  every weekday at 09:00
  timezone "America/New_York"
  missed coalesce

  observe as tick
  emit triage.tick {
    scheduled_at tick.scheduled_at
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = ir.contract_registry();
    let graph = construct_graph_json("clock-ingress.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("clock-ingress.whip", source, &ir, &graph, None);
    (graph, lowered)
}

#[test]
fn construct_graph_and_lowered_report_emit_clock_source() {
    let (graph, lowered) = clock_source_construct_graph_and_lowered_report_for_test();

    let node = construct_graph_node(&graph, "source:daily_triage");
    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some("core.clock_source.daily_triage")
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some("source_declaration")
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some("clock_source")
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("clock_source_template")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.clock_source_template")
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    let clock_object = core_objects
        .iter()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("clock_source"))
        .expect("clock_source core object");
    assert_eq!(
        clock_object
            .get("runtime_entrypoint")
            .and_then(Value::as_str),
        Some("clock_source_template")
    );
    assert_eq!(
        clock_object.get("owner_ref").and_then(Value::as_str),
        Some("source:daily_triage")
    );
    // The emitted signal is decoupled from the source's own name.
    assert_eq!(
        clock_object
            .pointer("/entrypoint_refs/event")
            .and_then(Value::as_str),
        Some("triage.tick")
    );
}

fn schedule_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    let source = r#"
workflow ScheduleGraph

class Task {
  title string
}

rule wait_for_deadline
  when Task as task
=> {
  timer until "2026-06-15T09:00:00Z" as deadline
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = ir.contract_registry();
    let graph = construct_graph_json("schedule-graph.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("schedule-graph.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn assertion_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    let source = r#"
@service
workflow AssertionGraph

assert true
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = ir.contract_registry();
    let graph = construct_graph_json("assertion-graph.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("assertion-graph.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn rule_template_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    let source = r#"
workflow RuleGraph

class StartupSeen {
  source string
}

rule observe_start
  when started
=> {
  record StartupSeen {
    source "external.started"
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = ir.contract_registry();
    let graph = construct_graph_json("rule-graph.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("rule-graph.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn projection_read_construct_graph_and_lowered_report_for_test() -> (Value, Value) {
    let source = r#"
workflow ProjectionReads

class Item {
  status string
}

rule observe
  when Item as item where count(Item where status == "done") == 0
=> {
  record Item {
    status "done"
  }
}

assert count(Item where status == "done") == 1
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let registry = ir.contract_registry();
    let graph = construct_graph_json("projection-reads.whip", source, &ir, &registry, None);
    let lowered = lowered_ir_report_json("projection-reads.whip", source, &ir, &graph, None);
    (graph, lowered)
}

fn package_memory_construct_graph_for_test() -> Value {
    package_memory_construct_graph_and_lowered_report_for_test().0
}

fn artifact_model_search_check_report_entry(path: &str, graph: &Value, lowered: &Value) -> Value {
    let snapshot = "";
    let contract_registry = json!({
        "schema": "whipplescript.contract_registry.v0",
        "libraries": [],
        "constructs": [],
        "effect_contracts": [],
        "diagnostics": [],
    });
    let package_lock_digest = graph
        .get("package_lock_digest")
        .and_then(Value::as_str)
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    let mut package_contract = json!({
        "schema": PACKAGE_CONTRACT_SCHEMA,
        "package_lock_digest": package_lock_digest,
        "platform_version": whipplescript_core::version(),
        "manifests": [],
        "platform_construct_catalog": platform_construct_catalog_json(),
        "contract_registry": contract_registry,
        "diagnostics": [],
    });
    let package_contract_digest = sha256_hex(canonical_json(&package_contract).as_bytes());
    package_contract
        .as_object_mut()
        .expect("package contract object")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(package_contract_digest.clone()),
        );
    let mut graph = graph.clone();
    graph
        .as_object_mut()
        .expect("construct graph object")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(package_contract_digest),
        );
    let graph_validation = validate_construct_graph_artifact(&graph);
    assert!(
        graph_validation.diagnostics.is_empty(),
        "artifact model-search graph fixture should validate: {:?}",
        graph_validation.diagnostics
    );
    graph
        .as_object_mut()
        .expect("construct graph object")
        .insert(
            "derived_facts".to_owned(),
            Value::Array(graph_validation.derived_facts),
        );
    graph
        .as_object_mut()
        .expect("construct graph object")
        .insert(
            "diagnostics".to_owned(),
            Value::Array(graph_validation.diagnostics),
        );
    let mut lowered = lowered.clone();
    let graph_id = graph
        .get("graph_id")
        .and_then(Value::as_str)
        .expect("graph id");
    lowered
        .as_object_mut()
        .expect("lowered report object")
        .insert("graph_id".to_owned(), Value::String(graph_id.to_owned()));
    lowered
        .as_object_mut()
        .expect("lowered report object")
        .insert(
            "accepted_program_digest".to_owned(),
            Value::String(sha256_hex(format!("{graph_id}\n{snapshot}").as_bytes())),
        );
    let lowered_validation = validate_lowered_ir_artifact(&lowered, &graph);
    assert!(
        lowered_validation.diagnostics.is_empty(),
        "artifact model-search lowered fixture should validate: {:?}",
        lowered_validation.diagnostics
    );
    lowered
        .as_object_mut()
        .expect("lowered report object")
        .insert(
            "derived_facts".to_owned(),
            Value::Array(lowered_validation.derived_facts),
        );
    lowered
        .as_object_mut()
        .expect("lowered report object")
        .insert(
            "diagnostics".to_owned(),
            Value::Array(lowered_validation.diagnostics),
        );
    json!({
        "schema": "whipplescript.check_report.v0",
        "path": display_path(path),
        "status": "ok",
        "workflow": "ArtifactModelSearchTest",
        "source_hash": stable_hash_hex(path),
        "ir_hash": stable_hash_hex(snapshot),
        "snapshot": snapshot,
        "source_metadata": {
            "tags": [],
            "descriptions": [],
            "targets": {},
        },
        "contract_registry": package_contract
            .get("contract_registry")
            .expect("package contract registry")
            .clone(),
        "package_contract": package_contract,
        "construct_graph": graph,
        "lowered_ir_report": lowered,
    })
}

fn refresh_report_package_contract_digest(entry: &mut Value) -> String {
    let digest = {
        let package_contract = entry
            .get("package_contract")
            .expect("package contract")
            .clone();
        let mut digest_body = package_contract;
        digest_body
            .as_object_mut()
            .expect("package contract object")
            .remove("package_contract_digest");
        sha256_hex(canonical_json(&digest_body).as_bytes())
    };
    entry
        .get_mut("package_contract")
        .and_then(Value::as_object_mut)
        .expect("package contract")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(digest.clone()),
        );
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(digest.clone()),
        );
    digest
}

fn run_lowered_ir_bridge_for_test(path: &str, graph: &Value, lowered: &Value) -> String {
    let report_entry = artifact_model_search_check_report_entry(path, graph, lowered);
    let report_path = write_verified_artifact_model_search_bundle(path, &report_entry)
        .expect("verified artifact bundle writes");
    let platform_catalog_path =
        write_artifact_bridge_platform_catalog(path).expect("platform catalog writes");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repo root");
    let python =
        find_executable_in_path(&["python3", "python"], &path_value()).expect("python on PATH");
    let output = Command::new(python)
        .arg(repo_root.join("scripts/lowered-ir-to-maude.py"))
        .arg("--root")
        .arg(repo_root)
        .arg("--platform-catalog")
        .arg(&platform_catalog_path)
        .arg(&report_path)
        .output()
        .expect("bridge runs");
    let _ = fs::remove_file(report_path);
    let _ = fs::remove_file(platform_catalog_path);
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn append_stale_validator_ref(artifact: &mut Value, owner_subsystem: &str) {
    let facts = artifact
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("derived facts");
    for fact in facts {
        if fact.get("owner_subsystem").and_then(Value::as_str) == Some(owner_subsystem) {
            fact.get_mut("input_refs")
                .and_then(Value::as_array_mut)
                .expect("input refs")
                .push(Value::String("stale-report-ref".to_owned()));
            return;
        }
    }
    panic!("missing validator-owned fact for {owner_subsystem}");
}

fn add_artifact_model_search_ledger(entry: &mut Value, graph: &Value, lowered: &Value) {
    let mut obligations = Vec::new();
    obligations.extend(model_search_obligations_for_test(
        "artifact.construct_graph",
        construct_graph_artifact_expected_searches(graph),
    ));
    obligations.extend(model_search_obligations_for_test(
        "artifact.lowered_ir",
        lowered_ir_artifact_expected_searches(graph, lowered),
    ));
    obligations.extend(model_search_obligations_for_test(
        "artifact.platform_catalog",
        platform_catalog_artifact_expected_searches(graph, &platform_construct_catalog_json()),
    ));
    let searches = obligations.len();
    let artifact_obligations = obligations
        .iter()
        .map(|obligation| {
            json!({
                "category": obligation.get("category").expect("category").clone(),
                "index": obligation.get("index").expect("index").clone(),
                "description": obligation.get("description").expect("description").clone(),
                "upstream": obligation.get("upstream").expect("upstream").clone(),
                "predicate": obligation.get("predicate").expect("predicate").clone(),
                "downstream": obligation.get("downstream").expect("downstream").clone(),
                "expected": obligation.get("expected").expect("expected").clone(),
                "source_span": obligation.get("source_span").expect("source_span").clone(),
            })
        })
        .collect::<Vec<_>>();
    let package_contract_digest = entry
        .get("package_contract")
        .and_then(|contract| contract.get("package_contract_digest"))
        .and_then(Value::as_str)
        .expect("package contract digest")
        .to_owned();
    let graph_id = entry
        .get("construct_graph")
        .and_then(|graph| graph.get("graph_id"))
        .and_then(Value::as_str)
        .expect("graph id")
        .to_owned();
    let accepted_program_digest = entry
        .get("lowered_ir_report")
        .and_then(|report| report.get("accepted_program_digest"))
        .and_then(Value::as_str)
        .expect("accepted program digest")
        .to_owned();
    let source_hash = entry
        .get("source_hash")
        .and_then(Value::as_str)
        .expect("source hash")
        .to_owned();
    let ir_hash = entry
        .get("ir_hash")
        .and_then(Value::as_str)
        .expect("ir hash")
        .to_owned();
    entry.as_object_mut().expect("report entry object").insert(
        "model_search".to_owned(),
        json!({
            "status": "ok",
            "searches": searches,
            "solutions": searches,
            "no_solutions": 0,
            "ir_searches": 0,
            "artifact_searches": searches,
            "obligations": obligations,
        }),
    );
    entry.as_object_mut().expect("report entry object").insert(
        "artifact_model_search_obligations".to_owned(),
        json!({
            "schema": "whipplescript.artifact_model_search_obligations.v0",
            "source_hash": source_hash,
            "ir_hash": ir_hash,
            "package_contract_digest": package_contract_digest,
            "construct_graph_id": graph_id,
            "accepted_program_digest": accepted_program_digest,
            "generator": "unit-test",
            "obligations": artifact_obligations,
        }),
    );
}

fn add_ir_model_search_ledger_from_snapshot_for_test(entry: &mut Value) {
    let snapshot = entry
        .get("snapshot")
        .and_then(Value::as_str)
        .expect("snapshot")
        .to_owned();
    let rows = IrSnapshotFacts::parse(&snapshot).expected_ir_rows();
    assert!(
        !rows.is_empty(),
        "test snapshot should imply generated IR searches"
    );

    let source_hash = entry
        .get("source_hash")
        .and_then(Value::as_str)
        .expect("source_hash")
        .to_owned();
    let ir_hash = entry
        .get("ir_hash")
        .and_then(Value::as_str)
        .expect("ir_hash")
        .to_owned();

    let mut ir_obligations = Vec::new();
    let mut solution_count = 0u64;
    let mut no_solution_count = 0u64;
    for (index, (description, upstream, predicate, downstream, outcome)) in rows.iter().enumerate()
    {
        match outcome.as_str() {
            "solution" => solution_count += 1,
            "no_solution" => no_solution_count += 1,
            other => panic!("unexpected generated outcome {other}"),
        }
        ir_obligations.push(json!({
            "category": "ir",
            "index": index + 1,
            "description": description,
            "upstream": upstream,
            "predicate": predicate,
            "downstream": downstream,
            "expected": outcome,
            "actual": outcome,
            "status": "ok",
            "source_span": {"start": 0, "end": 0},
        }));
    }

    let model_search_object = entry
        .get_mut("model_search")
        .and_then(Value::as_object_mut)
        .expect("model_search object");
    let obligations = model_search_object
        .get_mut("obligations")
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    obligations.extend(ir_obligations.clone());
    let ir_count = rows.len() as u64;
    for (field, increment) in [
        ("searches", ir_count),
        ("ir_searches", ir_count),
        ("solutions", solution_count),
        ("no_solutions", no_solution_count),
    ] {
        let value = model_search_object
            .get(field)
            .and_then(Value::as_u64)
            .expect("counter");
        model_search_object.insert(field.to_owned(), json!(value + increment));
    }

    let artifact_obligations = ir_obligations
        .into_iter()
        .enumerate()
        .map(|(index, obligation)| {
            json!({
                "index": index + 1,
                "description": obligation.get("description").expect("description").clone(),
                "upstream": obligation.get("upstream").expect("upstream").clone(),
                "predicate": obligation.get("predicate").expect("predicate").clone(),
                "downstream": obligation.get("downstream").expect("downstream").clone(),
                "expected": obligation.get("expected").expect("expected").clone(),
                "source_span": obligation.get("source_span").expect("source_span").clone(),
            })
        })
        .collect::<Vec<_>>();
    entry.as_object_mut().expect("report entry object").insert(
        "ir_model_search_obligations".to_owned(),
        json!({
            "schema": "whipplescript.ir_model_search_obligations.v0",
            "source_hash": source_hash,
            "ir_hash": ir_hash,
            "generator": "unit-test",
            "obligations": artifact_obligations,
        }),
    );
}

fn set_report_snapshot_for_test(entry: &mut Value, snapshot: &str) {
    let graph_id = entry
        .get("construct_graph")
        .and_then(|graph| graph.get("graph_id"))
        .and_then(Value::as_str)
        .expect("graph id")
        .to_owned();
    let construct_graph = entry
        .get("construct_graph")
        .expect("construct graph")
        .clone();
    entry
        .as_object_mut()
        .expect("report entry object")
        .insert("snapshot".to_owned(), Value::String(snapshot.to_owned()));
    entry.as_object_mut().expect("report entry object").insert(
        "ir_hash".to_owned(),
        Value::String(stable_hash_hex(snapshot)),
    );
    let accepted_program_digest = sha256_hex(format!("{graph_id}\n{snapshot}").as_bytes());
    entry
        .get_mut("lowered_ir_report")
        .and_then(Value::as_object_mut)
        .expect("lowered report object")
        .insert(
            "accepted_program_digest".to_owned(),
            Value::String(accepted_program_digest),
        );
    let validation = {
        let lowered_ir_report = entry.get("lowered_ir_report").expect("lowered report");
        validate_lowered_ir_artifact(lowered_ir_report, &construct_graph)
    };
    assert_eq!(
        validation.diagnostics,
        Vec::<Value>::new(),
        "synthetic snapshot should keep lowered IR valid"
    );
    entry
        .get_mut("lowered_ir_report")
        .and_then(Value::as_object_mut)
        .expect("lowered report object")
        .insert(
            "derived_facts".to_owned(),
            Value::Array(validation.derived_facts),
        );
}

fn model_search_obligations_for_test(category: &str, expected: Vec<ExpectedSearch>) -> Vec<Value> {
    expected
        .into_iter()
        .enumerate()
        .map(|(index, expected)| {
            json!({
                "category": category,
                "index": index + 1,
                "description": expected.description,
                "upstream": expected.upstream,
                "predicate": expected.predicate,
                "downstream": expected.downstream,
                "expected": expected.outcome.json_label(),
                "actual": expected.outcome.json_label(),
                "status": "ok",
                "source_span": source_span_to_json(expected.span),
            })
        })
        .collect()
}

#[test]
fn verify_report_accepts_generated_artifact_evidence() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);

    verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect("generated artifact evidence verifies");
}

#[test]
fn verify_report_accepts_compile_report_success_shape() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut report =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report_object = report.as_object_mut().expect("report object");
    report_object.insert(
        "schema".to_owned(),
        Value::String(COMPILE_REPORT_SCHEMA.to_owned()),
    );
    report_object.remove("status");

    verify_report_value(&report, "compile.json", None).expect("compile report verifies");
}

#[test]
fn verify_report_artifact_bundle_emits_selected_artifact() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report = Value::Array(vec![entry]);
    let entries = verify_report_value(&report, "check.json", None).expect("check report verifies");

    let bundle = verified_report_artifacts_json(&entries, VerifyReportEmit::ConstructGraph);
    assert_eq!(
        bundle.get("schema").and_then(Value::as_str),
        Some("whipplescript.verified_artifacts.v0")
    );
    assert_eq!(
        bundle.get("emit").and_then(Value::as_str),
        Some("construct-graph")
    );
    let first_entry = bundle
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .expect("bundle entry");
    assert!(first_entry.get("construct_graph").is_some());
    assert!(first_entry.get("lowered_ir_report").is_none());
    assert!(first_entry
        .get("snapshot")
        .and_then(Value::as_str)
        .is_some());
    assert_eq!(
        first_entry.get("label").and_then(Value::as_str),
        Some("check.json[0]")
    );
}

#[test]
fn verify_report_lowered_ir_bundle_carries_graph_dependency() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report = Value::Array(vec![entry]);
    let entries = verify_report_value(&report, "check.json", None).expect("check report verifies");

    let bundle = verified_report_artifacts_json(&entries, VerifyReportEmit::LoweredIrReport);
    assert_eq!(
        bundle.get("emit").and_then(Value::as_str),
        Some("lowered-ir")
    );
    let first_entry = bundle
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .expect("bundle entry");
    assert!(first_entry.get("construct_graph").is_some());
    assert!(first_entry.get("lowered_ir_report").is_some());

    verify_report_value(&bundle, "lowered-ir.json", None).expect("lowered-ir bundle revalidates");
}

#[test]
fn artifact_model_search_writer_emits_verified_bundle() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);

    let path = write_verified_artifact_model_search_bundle("event-ingress.whip", &entry)
        .expect("verified artifact bundle writes");
    let bundle = serde_json::from_str::<Value>(
        &fs::read_to_string(&path).expect("verified artifact bundle reads"),
    )
    .expect("verified artifact bundle parses");
    let _ = fs::remove_file(path);

    assert_eq!(
        bundle.get("schema").and_then(Value::as_str),
        Some("whipplescript.verified_artifacts.v0")
    );
    assert_eq!(
        bundle.get("emit").and_then(Value::as_str),
        Some("artifacts")
    );
    let first_entry = bundle
        .get("entries")
        .and_then(Value::as_array)
        .and_then(|entries| entries.first())
        .expect("bundle entry");
    assert!(first_entry.get("construct_graph").is_some());
    assert!(first_entry.get("lowered_ir_report").is_some());
    assert!(first_entry
        .get("snapshot")
        .and_then(Value::as_str)
        .is_some());
}

#[test]
fn verify_report_accepts_full_verified_artifact_bundle_input() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let bundle = verified_report_artifacts_json(&verified_entries, VerifyReportEmit::Artifacts);

    let entries = verify_report_value(&bundle, "artifacts.json", None)
        .expect("verified artifact bundle verifies");

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].report_schema.as_str(),
        "whipplescript.check_report.v0"
    );
    assert_eq!(entries[0].report_path.as_str(), "artifacts.json");
}

#[test]
fn verify_report_accepts_construct_graph_verified_artifact_bundle_input() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let bundle =
        verified_report_artifacts_json(&verified_entries, VerifyReportEmit::ConstructGraph);

    let entries = verify_report_value(&bundle, "construct-graph.json", None)
        .expect("construct graph bundle verifies");

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].report_schema.as_str(),
        "whipplescript.check_report.v0"
    );
    assert_eq!(entries[0].report_path.as_str(), "construct-graph.json");
    assert!(entries[0].lowered_ir_report.is_none());
}

#[test]
fn verify_report_rejects_verified_artifact_bundle_unknown_top_level_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let mut bundle =
        verified_report_artifacts_json(&verified_entries, VerifyReportEmit::ConstructGraph);
    bundle
        .as_object_mut()
        .expect("bundle object")
        .insert("unexpected".to_owned(), Value::Bool(true));

    let error = verify_report_value(&bundle, "construct-graph.json", None)
        .expect_err("unknown top-level bundle fields should reject");
    assert!(
        error.contains("construct-graph.json field `unexpected` is not allowed"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_verified_artifact_bundle_unknown_entry_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let mut bundle = verified_report_artifacts_json(&verified_entries, VerifyReportEmit::Artifacts);
    bundle
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .and_then(|entries| entries.first_mut())
        .and_then(Value::as_object_mut)
        .expect("bundle entry object")
        .insert("unexpected".to_owned(), Value::Bool(true));

    let error = verify_report_value(&bundle, "artifacts.json", None)
        .expect_err("unknown bundle entry fields should reject");
    assert!(
        error.contains("artifacts.json.entries[0] field `unexpected` is not allowed"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_construct_graph_bundle_with_lowered_ir_report() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let verified_entries = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect("check report verifies");
    let mut bundle =
        verified_report_artifacts_json(&verified_entries, VerifyReportEmit::ConstructGraph);
    bundle
        .get_mut("entries")
        .and_then(Value::as_array_mut)
        .and_then(|entries| entries.first_mut())
        .and_then(Value::as_object_mut)
        .expect("bundle entry object")
        .insert("lowered_ir_report".to_owned(), lowered);

    let error = verify_report_value(&bundle, "construct-graph.json", None)
        .expect_err("construct-graph bundles should not carry lowered IR reports");
    assert!(
            error.contains(
                "construct-graph.json.entries[0].lowered_ir_report is not allowed in construct-graph bundles"
            ),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_missing_check_report_schema() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .as_object_mut()
        .expect("report entry object")
        .remove("schema");
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None).expect_err("schema is required");
    assert!(
        error.contains("check.json[0].schema must be a string"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_malformed_skipped_check_report_entry() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let ok_entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let malformed_error_entry = json!({
        "schema": CHECK_REPORT_SCHEMA,
        "path": "bad.whip",
        "status": "error",
        "error": {
            "kind": "not-a-check-error-kind",
        },
    });
    let report = Value::Array(vec![ok_entry, malformed_error_entry]);

    let error = verify_report_value(&report, "check.json", None)
        .expect_err("malformed non-ok entry should reject the whole report envelope");
    assert!(
        error.contains("check.json[1].error.kind must be one of"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_ir_hash() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry.as_object_mut().expect("report entry object").insert(
        "ir_hash".to_owned(),
        Value::String("00000000000000000000000000000000".to_owned()),
    );
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None).expect_err("ir_hash is stale");
    assert!(
        error.contains("ir_hash must match the embedded snapshot hash"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_construct_graph_id_not_bound_to_source_digest() {
    let (mut graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    graph
        .as_object_mut()
        .expect("graph object")
        .insert("graph_id".to_owned(), json!("construct_graph:stale"));
    let entry = artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None)
        .expect_err("graph_id is not derived from source_digest");
    assert!(
        error.contains("construct_graph.graph_id must be"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_accepted_program_digest() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("lowered_ir_report")
        .and_then(Value::as_object_mut)
        .expect("lowered report object")
        .insert(
            "accepted_program_digest".to_owned(),
            Value::String("0".repeat(64)),
        );
    let report = Value::Array(vec![entry]);

    let error = verify_report_value(&report, "check.json", None)
        .expect_err("accepted_program_digest is stale");
    assert!(
        error.contains("accepted_program_digest does not match graph_id + snapshot"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_success_compile_report_status_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut report =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    report.as_object_mut().expect("report object").insert(
        "schema".to_owned(),
        Value::String(COMPILE_REPORT_SCHEMA.to_owned()),
    );

    let error = verify_report_value(&report, "compile.json", None).expect_err("status is reserved");
    assert!(
        error.contains("status must be omitted for successful compile reports"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_construct_graph_evidence() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    append_stale_validator_ref(
        entry
            .get_mut("construct_graph")
            .expect("construct graph artifact"),
        "construct_graph_validator",
    );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale construct evidence should fail");
    assert!(
        error.contains("construct graph validator predicate")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_construct_graph_port_profile_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("construct_graph")
        .expect("construct graph artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("graph derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| predicate.starts_with("validator.port.profile:"))
        })
        .expect("port profile fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("port profile input refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale port profile evidence should fail");
    assert!(
        error.contains("validator.port.profile")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_package_contract_digest() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(Value::as_object_mut)
        .expect("package contract")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String("0".repeat(64)),
        );

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("stale package contract digest should be rejected");
    assert!(
        error.contains("package_contract.package_contract_digest does not match"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_incomplete_contract_registry_spine() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("contract_registry")
        .and_then(Value::as_object_mut)
        .expect("report contract registry")
        .remove("libraries");
    entry
        .get_mut("package_contract")
        .and_then(|package_contract| package_contract.get_mut("contract_registry"))
        .and_then(Value::as_object_mut)
        .expect("embedded contract registry")
        .remove("libraries");
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("incomplete contract registry should be rejected");
    assert!(
        error.contains("check.json[0].contract_registry.libraries must be an array"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unsupported_contract_registry_schema_fragment() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "input_schema": "unsupported.custom",
    });
    fn add_test_package_contract(registry: &mut Value, contract: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(json!({
                "id": "memory",
                "version": "0.1.0",
                "standard": false,
            }));
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
    }
    add_test_package_contract(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &contract,
    );
    add_test_package_contract(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &contract,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("unsupported package schema fragment should be rejected");
    assert!(
            error.contains(
                "check.json[0].contract_registry.effect_contracts[0].input_schema uses unsupported package type `unsupported.custom`"
            ),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_construct_missing_required_input_schema_field() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
        "input_schema": "{\"query\":\"string\"}",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "expression", "required": false}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.query", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.query",
    });

    fn add_bad_construct_registry(
        registry: &mut Value,
        library: &Value,
        contract: &Value,
        construct: &Value,
    ) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_bad_construct_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_bad_construct_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("construct/input schema mismatch should be rejected");
    assert!(
        error.contains("check.json[0].contract_registry.constructs")
            && error
                .contains("target input_schema field `query` is optional in the construct fields"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unsupported_contract_registry_construct_vocabulary() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "synthetic.unsupported", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.query", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.query",
    });

    fn add_bad_construct_registry(
        registry: &mut Value,
        library: &Value,
        contract: &Value,
        construct: &Value,
    ) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_bad_construct_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_bad_construct_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("unsupported construct vocabulary should be rejected");
    assert!(
        error.contains("check.json[0].contract_registry.constructs")
            && error.contains(
                "fields[0].kind uses unsupported construct field kind `synthetic.unsupported`"
            ),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_construct_target_without_effect_contract() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "expression", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.missing", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.missing",
    });

    fn add_registry(registry: &mut Value, library: &Value, contract: &Value, construct: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("construct target without effect contract should be rejected");
    assert!(
            error.contains("target_capability `memory.missing` has no matching package `capability.call` effect contract"),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_effect_contract_required_capability_without_contract() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
        "required_capabilities": ["memory.missing"],
    });

    fn add_registry(registry: &mut Value, library: &Value, contract: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("required capability without effect contract should be rejected");
    assert!(
        error.contains("required_capabilities references `memory.missing`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_duplicate_package_construct_keyword() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.query",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.recall",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "recall",
        "scope": "rule_body",
        "fields": [
            {"name": "query", "kind": "expression", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.query", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.query.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.query",
    });
    let mut duplicate = construct.clone();
    duplicate.as_object_mut().expect("construct object").insert(
        "id".to_owned(),
        Value::String("memory.recall.alt".to_owned()),
    );

    fn add_registry(
        registry: &mut Value,
        library: &Value,
        contract: &Value,
        construct: &Value,
        duplicate: &Value,
    ) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        let constructs = registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs");
        constructs.push(construct.clone());
        constructs.push(duplicate.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
        &duplicate,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
        &duplicate,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("duplicate construct keyword should be rejected");
    assert!(
        error.contains("duplicates package construct keyword `recall` in scope `rule_body`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unprivileged_reserved_construct_keyword() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let library = json!({
        "id": "memory",
        "version": "0.1.0",
        "standard": false,
    });
    let contract = json!({
        "id": "memory.claim",
        "library_id": "memory",
        "version": "0.1.0",
        "effect_kind": "capability.call",
    });
    let construct = json!({
        "id": "memory.claim",
        "library_id": "memory",
        "version": "0.1.0",
        "construct_family": "effect_operation",
        "keyword": "claim",
        "scope": "rule_body",
        "fields": [
            {"name": "issue", "kind": "expression", "required": true}
        ],
        "requires": [
            {"kind": "Capability", "name": "memory.claim", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "provides": [
            {"kind": "EffectHandle", "type": "memory.claim.output", "phase": "compile/runtime", "cardinality": "exactly-one"}
        ],
        "lowering_target": "capability_call",
        "target_capability": "memory.claim",
    });

    fn add_registry(registry: &mut Value, library: &Value, contract: &Value, construct: &Value) {
        registry
            .get_mut("libraries")
            .and_then(Value::as_array_mut)
            .expect("contract registry libraries")
            .push(library.clone());
        registry
            .get_mut("effect_contracts")
            .and_then(Value::as_array_mut)
            .expect("contract registry effect contracts")
            .push(contract.clone());
        registry
            .get_mut("constructs")
            .and_then(Value::as_array_mut)
            .expect("contract registry constructs")
            .push(construct.clone());
    }

    add_registry(
        entry
            .get_mut("contract_registry")
            .expect("report contract registry"),
        &library,
        &contract,
        &construct,
    );
    add_registry(
        entry
            .get_mut("package_contract")
            .and_then(|package_contract| package_contract.get_mut("contract_registry"))
            .expect("embedded contract registry"),
        &library,
        &contract,
        &construct,
    );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("unprivileged reserved construct keyword should be rejected");
    assert!(
        error.contains("uses reserved construct keyword `claim`"),
        "{error}"
    );
    assert!(
        error.contains("platform catalog authorization for library `memory`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_incomplete_embedded_contract_registry_spine() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(|package_contract| package_contract.get_mut("contract_registry"))
        .and_then(Value::as_object_mut)
        .expect("embedded contract registry")
        .remove("libraries");
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("incomplete embedded contract registry should be rejected");
    assert!(
        error.contains(
            "check.json[0].package_contract.contract_registry.libraries must be an array"
        ),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_incomplete_package_contract_spine() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(Value::as_object_mut)
        .expect("package contract")
        .remove("manifests");
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("incomplete package contract should be rejected");
    assert!(
        error.contains("check.json[0].package_contract.manifests must be an array"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_invalid_package_lock_digest_shape() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("package_contract")
        .and_then(Value::as_object_mut)
        .expect("package contract")
        .insert(
            "package_lock_digest".to_owned(),
            Value::String("ABC".to_owned()),
        );
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert(
            "package_lock_digest".to_owned(),
            Value::String("ABC".to_owned()),
        );
    refresh_report_package_contract_digest(&mut entry);

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("invalid package lock digest should be rejected");
    assert!(
            error.contains(
                "check.json[0].package_contract.package_lock_digest must be a 64-character lowercase hex digest"
            ),
            "{error}"
        );
}

#[test]
fn verify_report_rejects_package_contract_diagnostics() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let package_contract = entry.get_mut("package_contract").expect("package contract");
    package_contract
        .get_mut("diagnostics")
        .and_then(Value::as_array_mut)
        .expect("package contract diagnostics")
        .push(json!({
            "code": "package_contract.synthetic",
            "message": "synthetic package contract diagnostic",
        }));
    let mut digest_body = package_contract.clone();
    digest_body
        .as_object_mut()
        .expect("package contract object")
        .remove("package_contract_digest");
    let digest = sha256_hex(canonical_json(&digest_body).as_bytes());
    package_contract
        .as_object_mut()
        .expect("package contract object")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(digest.clone()),
        );
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert("package_contract_digest".to_owned(), Value::String(digest));

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("package contract diagnostics should be rejected");
    assert!(
        error.contains("package_contract.diagnostics must be empty"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_platform_construct_catalog() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let package_contract = entry.get_mut("package_contract").expect("package contract");
    package_contract
        .get_mut("platform_construct_catalog")
        .and_then(|catalog| catalog.get_mut("interface_kinds"))
        .and_then(Value::as_array_mut)
        .expect("platform catalog interface kinds")
        .push(Value::String("BogusInterface".to_owned()));
    let mut digest_body = package_contract.clone();
    digest_body
        .as_object_mut()
        .expect("package contract object")
        .remove("package_contract_digest");
    let digest = sha256_hex(canonical_json(&digest_body).as_bytes());
    package_contract
        .as_object_mut()
        .expect("package contract object")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String(digest.clone()),
        );
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert("package_contract_digest".to_owned(), Value::String(digest));

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("stale platform catalog should be rejected");
    assert!(
        error.contains("platform_construct_catalog must match verifier platform catalog"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_graph_package_contract_digest_mismatch() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    entry
        .get_mut("construct_graph")
        .and_then(Value::as_object_mut)
        .expect("construct graph")
        .insert(
            "package_contract_digest".to_owned(),
            Value::String("0".repeat(64)),
        );

    let error = verify_report_value(&Value::Array(vec![entry]), "check.json", None)
        .expect_err("graph package contract digest mismatch should be rejected");
    assert!(
        error.contains("construct_graph.package_contract_digest does not match"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_evidence() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    append_stale_validator_ref(
        entry
            .get_mut("lowered_ir_report")
            .expect("lowered IR artifact"),
        "lowered_ir_validator",
    );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale lowered evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_lifecycle_input_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with("lowered_ir.validator.node.lifecycle_inputs:")
                })
        })
        .expect("lifecycle input fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("lifecycle input refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale lifecycle input evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.node.lifecycle_inputs")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_lifecycle_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with(
                        "lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:",
                    )
                })
        })
        .expect("lifecycle runtime-entrypoint component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("lifecycle runtime-entrypoint refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale lifecycle component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_output_compat_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with(
                        "lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints:",
                    )
                })
        })
        .expect("output allowed-runtime-entrypoint component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("output allowed-runtime-entrypoint refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale output compatibility component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error
                .contains("lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_node_preservation_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate
                        .starts_with("lowered_ir.validator.node.preservation.terminal_binding:")
                })
        })
        .expect("terminal binding preservation component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("terminal binding preservation refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale node preservation component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.node.preservation.terminal_binding")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_edge_preservation_component_evidence() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with("lowered_ir.validator.edge.preservation.core_relation:")
                })
        })
        .expect("edge core-relation preservation component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("core relation preservation refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale edge preservation component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.edge.preservation.core_relation")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_dependency_preservation_component_evidence() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate.starts_with("lowered_ir.validator.dependency.preservation.predicate:")
                })
        })
        .expect("dependency predicate preservation component fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("dependency predicate preservation refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale dependency preservation component evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.dependency.preservation.predicate")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_lowered_ir_core_object_entrypoint_evidence() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    let fact = entry
        .get_mut("lowered_ir_report")
        .expect("lowered IR artifact")
        .get_mut("derived_facts")
        .and_then(Value::as_array_mut)
        .expect("lowered IR derived facts")
        .iter_mut()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| {
                    predicate
                        .starts_with("lowered_ir.validator.core_object.entrypoint:core:dependency:")
                })
        })
        .expect("dependency core object entrypoint fact");
    fact.get_mut("input_refs")
        .and_then(Value::as_array_mut)
        .expect("entrypoint input refs")
        .pop();

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale core object entrypoint evidence should fail");
    assert!(
        error.contains("lowered IR report validator predicate")
            && error.contains("lowered_ir.validator.core_object.entrypoint")
            && error.contains("does not match recomputed evidence"),
        "{error}"
    );
}

#[test]
fn verify_report_accepts_model_search_artifact_ledger() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);

    verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect("generated model_search artifact ledger verifies");
}

#[test]
fn verify_report_rejects_stale_model_search_artifact_ledger() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.construct_graph")
        })
        .expect("artifact obligation");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "downstream".to_owned(),
            Value::String("stale-node".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale model_search artifact obligation should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_artifact_model_search_obligations_artifact() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("artifact_model_search_obligations")
        .and_then(|artifact| artifact.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("artifact_model_search_obligations rows");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.construct_graph")
        })
        .expect("artifact obligation artifact row");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "downstream".to_owned(),
            Value::String("stale-node".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale artifact_model_search_obligations row should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch")
            && error.contains("artifact.construct_graph"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_model_search_platform_catalog_ledger() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.platform_catalog")
        })
        .expect("platform catalog artifact obligation");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "downstream".to_owned(),
            Value::String("stale-lowering-class".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale platform catalog obligation should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch")
            && error.contains("artifact.platform_catalog"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_stale_model_search_handoff_source_span() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let artifact_obligation = obligations
        .iter_mut()
        .find(|obligation| {
            obligation.get("category").and_then(Value::as_str) == Some("artifact.lowered_ir")
                && obligation.get("predicate").and_then(Value::as_str) == Some("handoffObjectOk")
        })
        .expect("handoff artifact obligation");
    artifact_obligation
        .as_object_mut()
        .expect("obligation object")
        .insert(
            "source_span".to_owned(),
            json!({
                "start": 999_999,
                "end": 1_000_000,
            }),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("stale handoff source span should fail");
    assert!(
        error.contains("model_search artifact obligation mismatch")
            && error.contains("artifact.lowered_ir")
            && error.contains("source_span"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unknown_ir_model_search_predicate() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    set_report_snapshot_for_test(
            &mut entry,
            "workflow SnapshotSupport\nrules\n  rule start\n    when Task as task\n    effects\n      first kind=agent.tell binding=- key=first\n      second kind=agent.tell binding=- key=second\n    dependencies\n      first --succeeds--> second\n    body_hash abc\n",
        );
    add_ir_model_search_ledger_from_snapshot_for_test(&mut entry);
    let model_search = entry.get_mut("model_search").expect("model_search");
    let model_search_object = model_search.as_object_mut().expect("model_search object");
    let obligations = model_search_object
        .get_mut("obligations")
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let ir_obligation = obligations
        .iter_mut()
        .find(|obligation| obligation.get("category").and_then(Value::as_str) == Some("ir"))
        .expect("IR obligation");
    ir_obligation
        .as_object_mut()
        .expect("IR obligation object")
        .insert(
            "predicate".to_owned(),
            Value::String("not-a-generated-predicate".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("unknown generated IR predicate should fail");
    assert!(
        error.contains("unknown generated predicate `not-a-generated-predicate`"),
        "{error}"
    );
}

#[test]
fn verify_report_rejects_unsupported_ir_model_search_obligation() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let mut entry =
        artifact_model_search_check_report_entry("event-ingress.whip", &graph, &lowered);
    add_artifact_model_search_ledger(&mut entry, &graph, &lowered);
    set_report_snapshot_for_test(
            &mut entry,
            "workflow SnapshotSupport\nrules\n  rule start\n    when Task as task\n    effects\n      first kind=agent.tell binding=- key=first\n      second kind=agent.tell binding=- key=second\n    dependencies\n      first --succeeds--> second\n    body_hash abc\n",
        );
    add_ir_model_search_ledger_from_snapshot_for_test(&mut entry);
    let obligations = entry
        .get_mut("model_search")
        .and_then(|model_search| model_search.get_mut("obligations"))
        .and_then(Value::as_array_mut)
        .expect("model_search obligations");
    let ir_obligation = obligations
        .iter_mut()
        .find(|obligation| obligation.get("category").and_then(Value::as_str) == Some("ir"))
        .expect("IR obligation");
    ir_obligation
        .as_object_mut()
        .expect("IR obligation object")
        .insert(
            "upstream".to_owned(),
            Value::String("missing-upstream".to_owned()),
        );

    let error = verify_report_entry_artifacts(&entry, "event-ingress.whip")
        .expect_err("unsupported generated IR obligation should fail");
    assert!(
        error.contains("not supported by the embedded snapshot"),
        "{error}"
    );
}

fn construct_graph_diagnostic_codes(diagnostics: &[Value]) -> BTreeSet<String> {
    diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.get("code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn lowered_ir_diagnostic_codes(diagnostics: &[Value]) -> BTreeSet<String> {
    diagnostics
        .iter()
        .filter_map(|diagnostic| diagnostic.get("code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn construct_graph_fact_predicates(graph: &Value) -> BTreeSet<String> {
    graph
        .get("derived_facts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|fact| fact.get("predicate").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn construct_graph_fact_input_refs(
    graph: &Value,
    predicate_prefix: &str,
) -> Option<BTreeSet<String>> {
    graph
        .get("derived_facts")
        .and_then(Value::as_array)?
        .iter()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| predicate.starts_with(predicate_prefix))
        })
        .and_then(|fact| fact.get("input_refs").and_then(Value::as_array))
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

fn construct_graph_validation_fact_input_refs(
    validation: &ConstructGraphValidation,
    predicate_prefix: &str,
) -> Option<BTreeSet<String>> {
    validation
        .derived_facts
        .iter()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| predicate.starts_with(predicate_prefix))
        })
        .and_then(|fact| fact.get("input_refs").and_then(Value::as_array))
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

fn lowered_ir_fact_predicates(report: &Value) -> BTreeSet<String> {
    report
        .get("derived_facts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|fact| fact.get("predicate").and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn lowered_ir_fact_input_refs(report: &Value, predicate_prefix: &str) -> Option<BTreeSet<String>> {
    report
        .get("derived_facts")
        .and_then(Value::as_array)?
        .iter()
        .find(|fact| {
            fact.get("predicate")
                .and_then(Value::as_str)
                .is_some_and(|predicate| predicate.starts_with(predicate_prefix))
        })
        .and_then(|fact| fact.get("input_refs").and_then(Value::as_array))
        .map(|refs| {
            refs.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
}

fn first_construct_graph_required_port_id(graph: &Value) -> String {
    graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .and_then(|edge| edge.get("required_port_id"))
        .and_then(Value::as_str)
        .expect("edge has required port")
        .to_owned()
}

fn first_construct_graph_provided_port_id(graph: &Value) -> String {
    graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .and_then(|edge| edge.get("provided_port_id"))
        .and_then(Value::as_str)
        .expect("edge has provided port")
        .to_owned()
}

fn first_construct_graph_edge_ref(graph: &Value) -> String {
    graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .map(construct_graph_edge_ref)
        .expect("graph has an edge")
}

fn first_construct_graph_effect_dependency_ref(graph: &Value) -> String {
    graph
        .get("effect_dependencies")
        .and_then(Value::as_array)
        .and_then(|dependencies| dependencies.first())
        .and_then(|dependency| dependency.get("dependency_ref"))
        .and_then(Value::as_str)
        .expect("graph has an effect dependency")
        .to_owned()
}

fn construct_graph_port_mut<'a>(graph: &'a mut Value, port_id: &str) -> &'a mut Value {
    graph
        .get_mut("ports")
        .and_then(Value::as_array_mut)
        .expect("ports array")
        .iter_mut()
        .find(|port| port.get("port_id").and_then(Value::as_str) == Some(port_id))
        .expect("port exists")
}

fn construct_graph_port<'a>(graph: &'a Value, port_id: &str) -> &'a Value {
    graph
        .get("ports")
        .and_then(Value::as_array)
        .expect("ports array")
        .iter()
        .find(|port| port.get("port_id").and_then(Value::as_str) == Some(port_id))
        .expect("port exists")
}

fn construct_graph_node<'a>(graph: &'a Value, node_id: &str) -> &'a Value {
    graph
        .get("nodes")
        .and_then(Value::as_array)
        .expect("nodes array")
        .iter()
        .find(|node| node.get("node_id").and_then(Value::as_str) == Some(node_id))
        .expect("node exists")
}

fn construct_graph_node_mut<'a>(graph: &'a mut Value, node_id: &str) -> &'a mut Value {
    graph
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .expect("nodes array")
        .iter_mut()
        .find(|node| node.get("node_id").and_then(Value::as_str) == Some(node_id))
        .expect("node exists")
}

fn sync_declared_required_interface_cardinality(
    graph: &mut Value,
    required_port_id: &str,
    cardinality: &str,
) {
    let port = construct_graph_port(graph, required_port_id);
    let owner_node_id = port
        .get("owner_node_id")
        .and_then(Value::as_str)
        .expect("required port has owner")
        .to_owned();
    let port_kind = port.get("kind").and_then(Value::as_str).map(str::to_owned);
    let port_type = port.get("type").and_then(Value::as_str).map(str::to_owned);
    let node = construct_graph_node_mut(graph, &owner_node_id);
    let interfaces = node
        .get_mut("declared_required_interfaces")
        .and_then(Value::as_array_mut)
        .expect("declared required interfaces");
    let interface = interfaces
        .iter_mut()
        .find(|interface| {
            interface.get("kind").and_then(Value::as_str) == port_kind.as_deref()
                && (interface.get("name").and_then(Value::as_str) == port_type.as_deref()
                    || interface.get("type").and_then(Value::as_str) == port_type.as_deref())
        })
        .expect("declared required interface for port");
    interface
        .as_object_mut()
        .expect("declared required interface object")
        .insert("cardinality".to_owned(), json!(cardinality));
}

#[test]
fn construct_graph_reports_package_capability_call_resolution() {
    let graph = package_memory_construct_graph_for_test();

    assert_eq!(
        graph.get("schema").and_then(Value::as_str),
        Some("whipplescript.construct_graph.v0")
    );
    assert_eq!(
        graph
            .get("source_digest")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    // The graph resolves via the embedded `std.memory` manifest with no lock
    // at all, so the lock digest is the all-zero no-lock sentinel.
    assert_eq!(
        graph.get("package_lock_digest").and_then(Value::as_str),
        Some("0000000000000000000000000000000000000000000000000000000000000000")
    );

    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .expect("nodes array");
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str)
            == Some("contract:std.memory:memory.query:0.1.0")
    }));
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str)
            == Some("contract:std.memory:memory.query:0.1.0")
            && node
                .get("required_capabilities")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
            && node.get("construct_id").and_then(Value::as_str) == Some("memory.recall")
            && node.get("lowering_class").and_then(Value::as_str) == Some("capability_call")
            && node.get("lifecycle_profile").and_then(Value::as_str) == Some("typed_effect_graph")
    }));
    let effect_node = construct_graph_node(&graph, "effect:start:context");
    assert_eq!(
        construct_graph_string_array(effect_node, "allowed_core_object_kinds"),
        vec!["effect".to_owned()]
    );
    assert_eq!(
        construct_graph_string_array(effect_node, "allowed_runtime_entrypoints"),
        vec!["effect_graph_template".to_owned()]
    );
    let required_interfaces = effect_node
        .get("declared_required_interfaces")
        .and_then(Value::as_array)
        .expect("required interfaces");
    assert!(required_interfaces.iter().any(|interface| {
        interface.get("kind").and_then(Value::as_str) == Some("Capability")
            && interface.get("name").and_then(Value::as_str) == Some("memory.query")
            && interface.get("phase").and_then(Value::as_str) == Some("compile/runtime")
            && interface.get("cardinality").and_then(Value::as_str) == Some("exactly-one")
    }));
    let provided_interfaces = effect_node
        .get("declared_provided_interfaces")
        .and_then(Value::as_array)
        .expect("provided interfaces");
    assert!(provided_interfaces.iter().any(|interface| {
        interface.get("kind").and_then(Value::as_str) == Some("EffectHandle")
            && interface.get("type").and_then(Value::as_str) == Some("memory.query.output")
            && interface.get("phase").and_then(Value::as_str) == Some("compile/runtime")
            && interface.get("cardinality").and_then(Value::as_str) == Some("exactly-one")
    }));

    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .expect("edges array");
    let memory_edge_ref = edges
        .iter()
        .find_map(|edge| {
            let required = edge.get("required_port_id").and_then(Value::as_str)?;
            let provided = edge.get("provided_port_id").and_then(Value::as_str)?;
            required
                .contains("memory.query")
                .then(|| format!("{required}->{provided}"))
        })
        .expect("memory capability edge ref");
    assert!(edges.iter().any(|edge| {
        edge.get("resolution_reason").and_then(Value::as_str) == Some("locked_effect_contract")
            && edge
                .get("required_port_id")
                .and_then(Value::as_str)
                .is_some_and(|port| port.contains("memory.query"))
    }));
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("validator.graph.accepted:")));
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with("validator.graph.adequacy.source_lock_deterministic:")
    }));
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with("validator.graph.adequacy.checker_facts_accounted:")
    }));
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with("validator.graph.adequacy.lifecycle_boundary_declared:")
    }));
    let graph_accepted_refs = construct_graph_fact_input_refs(&graph, "validator.graph.accepted:")
        .expect("graph accepted refs");
    assert!(graph_accepted_refs.contains(&memory_edge_ref));
    let source_lock_refs = construct_graph_fact_input_refs(
        &graph,
        "validator.graph.adequacy.source_lock_deterministic:",
    )
    .expect("source lock adequacy refs");
    assert!(source_lock_refs
        .iter()
        .any(|ref_| ref_.starts_with("construct_graph.root.source_digest:")));
    assert!(source_lock_refs
        .iter()
        .any(|ref_| ref_.starts_with("construct_graph.root.package_lock_digest:")));
    assert!(predicates.contains("validator.node.profile:effect:start:context"));
    assert!(predicates.contains("validator.node.interfaces:effect:start:context"));
    assert!(predicates.contains("validator.node.capabilities:effect:start:context"));
    assert!(predicates
        .contains("validator.node.output:effect:start:context:core.effect_graph_template"));
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("validator.cardinality.exactly-one.satisfied:")));
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("validator.edge.type_compatible:")));
    let memory_edge = edges
        .iter()
        .find(|edge| {
            edge.get("required_port_id")
                .and_then(Value::as_str)
                .is_some_and(|port| port.contains("memory.query"))
        })
        .expect("memory edge");
    let required_port_id = memory_edge
        .get("required_port_id")
        .and_then(Value::as_str)
        .expect("required port id");
    let provided_port_id = memory_edge
        .get("provided_port_id")
        .and_then(Value::as_str)
        .expect("provided port id");
    let required_port = construct_graph_port(&graph, required_port_id);
    let provided_port = construct_graph_port(&graph, provided_port_id);
    let required_port_profile_refs = construct_graph_fact_input_refs(
        &graph,
        &format!("validator.port.profile:{required_port_id}"),
    )
    .expect("required port profile refs");
    assert!(required_port_profile_refs.contains(required_port_id));
    assert!(required_port_profile_refs.contains(&format!(
        "{required_port_id}#kind:{}",
        required_port
            .get("kind")
            .and_then(Value::as_str)
            .expect("required port kind")
    )));
    assert!(required_port_profile_refs.contains(&format!(
        "{required_port_id}#cardinality:{}",
        required_port
            .get("cardinality")
            .and_then(Value::as_str)
            .expect("required port cardinality")
    )));
    let edge_type_refs = construct_graph_fact_input_refs(
        &graph,
        &format!("validator.edge.type_compatible:{memory_edge_ref}"),
    )
    .expect("edge type compatibility refs");
    for (role, port_id, port) in [
        ("required", required_port_id, required_port),
        ("provided", provided_port_id, provided_port),
    ] {
        assert!(edge_type_refs.contains(&format!(
            "{port_id}#{role}.type:{}",
            port.get("type").and_then(Value::as_str).expect("port type")
        )));
        assert!(edge_type_refs.contains(&format!(
            "{port_id}#{role}.contract_version:{}",
            port.get("contract_version")
                .and_then(Value::as_str)
                .expect("port contract version")
        )));
    }
}

#[test]
fn construct_graph_reports_package_effect_dependencies() {
    let (graph, _) = package_memory_dependency_construct_graph_and_lowered_report_for_test();

    let dependencies = graph
        .get("effect_dependencies")
        .and_then(Value::as_array)
        .expect("effect dependencies");
    assert!(dependencies.iter().any(|dependency| {
        dependency.get("dependency_ref").and_then(Value::as_str)
            == Some("dependency:start:first:succeeds:second")
            && dependency.get("upstream_node_id").and_then(Value::as_str)
                == Some("effect:start:first")
            && dependency.get("predicate").and_then(Value::as_str) == Some("succeeds")
            && dependency.get("downstream_node_id").and_then(Value::as_str)
                == Some("effect:start:second")
    }));
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.iter().any(|predicate| {
        predicate.starts_with(
            "validator.effect_dependency.endpoints_valid:dependency:start:first:succeeds:second",
        )
    }));
    let graph_accepted_refs = construct_graph_fact_input_refs(&graph, "validator.graph.accepted:")
        .expect("graph accepted refs");
    assert!(graph_accepted_refs.contains("dependency:start:first:succeeds:second"));
}

#[test]
fn construct_graph_reports_core_effect_dependencies() {
    let (graph, _) = core_effect_dependency_construct_graph_and_lowered_report_for_test();

    let nodes = graph.get("nodes").and_then(Value::as_array).expect("nodes");
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str) == Some("effect:start:first")
            && node.get("construct_id").and_then(Value::as_str) == Some("core.effect.agent.tell")
            && node.get("lowering_class").and_then(Value::as_str)
                == Some(CORE_EFFECT_LOWERING_CLASS)
            && node.get("owner").and_then(Value::as_str) == Some("std.agent")
    }));
    assert!(nodes.iter().any(|node| {
        node.get("node_id").and_then(Value::as_str) == Some("effect:start:second")
            && node
                .get("required_capabilities")
                .and_then(Value::as_array)
                .is_some_and(|capabilities| {
                    capabilities
                        .iter()
                        .any(|value| value.as_str() == Some("agent.turn"))
                })
    }));

    let dependencies = graph
        .get("effect_dependencies")
        .and_then(Value::as_array)
        .expect("effect dependencies");
    assert!(dependencies.iter().any(|dependency| {
        dependency.get("dependency_ref").and_then(Value::as_str)
            == Some("dependency:start:first:succeeds:second")
            && dependency.get("upstream_node_id").and_then(Value::as_str)
                == Some("effect:start:first")
            && dependency.get("downstream_node_id").and_then(Value::as_str)
                == Some("effect:start:second")
    }));
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
}

#[test]
fn construct_graph_reports_signal_source_declarations() {
    let (graph, _) = signal_source_construct_graph_and_lowered_report_for_test();

    // The `signal {}` declaration itself produces no node; the `signal_source`
    // node comes from the generic `source` block.
    assert!(!graph
        .get("nodes")
        .and_then(Value::as_array)
        .expect("nodes array")
        .iter()
        .any(|node| node.get("node_id").and_then(Value::as_str)
            == Some("signal_source:deploy.finished")));

    let node = construct_graph_node(&graph, "source:deploy_events");
    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some("core.signal_source.deploy_events")
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some("source_declaration")
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some("signal_source")
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("signal_source_template")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.signal_source_template")
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains("lowering_output:deploy_events:core.signal_source_template"));
}

#[test]
fn construct_graph_reports_schedule_templates() {
    let (graph, _) = schedule_construct_graph_and_lowered_report_for_test();
    let node = construct_graph_node(&graph, "effect:wait_for_deadline:deadline");

    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some("core.effect.timer.wait")
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some(CONSTRUCT_FAMILY_EFFECT_OPERATION)
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some(SCHEDULE_LOWERING_CLASS)
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("schedule_template")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.schedule_template")
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_core_object_kinds"),
        vec!["schedule".to_owned()]
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_runtime_entrypoints"),
        vec!["schedule_template".to_owned()]
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains("lowering_output:deadline:core.schedule_template"));
    assert!(predicates.contains("validator.node.profile:effect:wait_for_deadline:deadline"));
    assert!(predicates.contains(
        "validator.node.output:effect:wait_for_deadline:deadline:core.schedule_template"
    ));
}

#[test]
fn construct_graph_reports_assertion_checks() {
    let (graph, _) = assertion_construct_graph_and_lowered_report_for_test();
    let assertion_id = stable_hash_hex("true");
    let node_id = format!("assertion:{assertion_id}");
    let construct_id = format!("core.assertion.{assertion_id}");
    let node = construct_graph_node(&graph, &node_id);

    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some(construct_id.as_str())
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some("assertion")
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some("assertion_check")
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("assertion_check")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.assertion_check")
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains(&format!(
        "lowering_output:{assertion_id}:core.assertion_check"
    )));
}

#[test]
fn construct_graph_reports_rule_templates() {
    let (graph, _) = rule_template_construct_graph_and_lowered_report_for_test();
    let node = construct_graph_node(&graph, "rule:observe_start:when0");

    assert_eq!(
        node.get("construct_id").and_then(Value::as_str),
        Some("core.rule.observe_start:when0")
    );
    assert_eq!(
        node.get("construct_family").and_then(Value::as_str),
        Some("rule")
    );
    assert_eq!(
        node.get("lowering_class").and_then(Value::as_str),
        Some("rule_template")
    );
    assert_eq!(
        node.get("lifecycle_profile").and_then(Value::as_str),
        Some("rule_template")
    );
    assert_eq!(
        node.get("lowering_output_kind").and_then(Value::as_str),
        Some("core.rule_template")
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_core_object_kinds"),
        vec!["rule".to_owned(), "fact".to_owned()]
    );
    assert_eq!(
        construct_graph_string_array(node, "allowed_runtime_entrypoints"),
        vec!["rule_template".to_owned(), "fact_record".to_owned()]
    );
    assert_eq!(
        node.get("metadata")
            .and_then(|metadata| metadata.get("fact_writes"))
            .and_then(Value::as_array)
            .and_then(|facts| facts.first())
            .and_then(Value::as_str),
        Some("schema:StartupSeen")
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.contains("lowering_output:observe_start:when0:core.rule_template"));
}

#[test]
fn construct_graph_reports_projection_reads() {
    let (graph, _) = projection_read_construct_graph_and_lowered_report_for_test();
    let rule_node = construct_graph_node(&graph, "projection_read:rule:observe:read0");

    assert_eq!(
        rule_node.get("construct_family").and_then(Value::as_str),
        Some("projection_read")
    );
    assert_eq!(
        rule_node.get("lowering_class").and_then(Value::as_str),
        Some("metadata")
    );
    assert_eq!(
        rule_node
            .get("lowering_output_kind")
            .and_then(Value::as_str),
        Some("checker.projection_read")
    );
    assert_eq!(
        rule_node
            .get("metadata")
            .and_then(|metadata| metadata.get("owner_kind"))
            .and_then(Value::as_str),
        Some("rule")
    );
    assert_eq!(
        rule_node
            .get("metadata")
            .and_then(|metadata| metadata.get("read_kind"))
            .and_then(Value::as_str),
        Some("fact")
    );
    assert_eq!(
        rule_node
            .get("metadata")
            .and_then(|metadata| metadata.get("source"))
            .and_then(Value::as_str),
        Some("Item where status == \"done\"")
    );

    let assertion_id = stable_hash_hex("count(Item where status == \"done\") == 1");
    let assertion_node_id = format!("projection_read:assertion:{assertion_id}:read0");
    let assertion_node = construct_graph_node(&graph, &assertion_node_id);
    assert_eq!(
        assertion_node
            .get("metadata")
            .and_then(|metadata| metadata.get("owner_kind"))
            .and_then(Value::as_str),
        Some("assertion")
    );
    assert_eq!(
        assertion_node
            .get("metadata")
            .and_then(|metadata| metadata.get("owner_ref"))
            .and_then(Value::as_str),
        Some(assertion_id.as_str())
    );
    assert_eq!(
        graph
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    let predicates = construct_graph_fact_predicates(&graph);
    assert!(predicates.iter().any(|predicate| predicate
        .starts_with("projection_read:rule:observe:read0:Item where status == \"done\"")));
}

#[test]
fn lowered_ir_report_accounts_for_package_capability_call_outputs() {
    let (graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();

    assert_eq!(
        lowered.get("schema").and_then(Value::as_str),
        Some("whipplescript.lowered_ir_report.v0")
    );
    assert_eq!(
        lowered.get("graph_id").and_then(Value::as_str),
        graph.get("graph_id").and_then(Value::as_str)
    );
    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str)
            == Some("contract:std.memory:memory.query:0.1.0")
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
            && lowering.get("lowering_class").and_then(Value::as_str) == Some("capability_call")
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some("core:effect:effect:start:context"))
                })
    }));
    let effect_node_lowering = node_lowerings
        .iter()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering");
    assert_eq!(
        construct_graph_string_array(effect_node_lowering, "preserved_provenance_refs"),
        vec!["effect:start:context"]
    );
    assert_eq!(
        construct_graph_string_array(effect_node_lowering, "preserved_terminal_binding_refs"),
        vec!["effect:start:context:produces:effect_handle"]
    );

    let edge_lowerings = lowered
        .get("edge_lowerings")
        .and_then(Value::as_array)
        .expect("edge lowerings");
    assert!(edge_lowerings.iter().any(|lowering| {
        lowering
            .get("required_port_id")
            .and_then(Value::as_str)
            .is_some_and(|port| port.contains("memory.query"))
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some("core:effect:effect:start:context")
            && object.get("object_kind").and_then(Value::as_str) == Some("effect")
            && object.get("runtime_entrypoint").and_then(Value::as_str)
                == Some("effect_graph_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some("effect:start:context")
    }));
}

#[test]
fn lowered_ir_validator_rejects_artifact_identity_mismatch() {
    for (field, replacement, expected_code) in [
        (
            "graph_id",
            json!("construct_graph:stale"),
            "lowered_ir.graph_id_mismatch",
        ),
        (
            "source_digest",
            json!("1111111111111111111111111111111111111111111111111111111111111111"),
            "lowered_ir.source_digest_mismatch",
        ),
        (
            "package_lock_digest",
            json!("2222222222222222222222222222222222222222222222222222222222222222"),
            "lowered_ir.package_lock_digest_mismatch",
        ),
    ] {
        let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
        lowered
            .as_object_mut()
            .expect("lowered report object")
            .insert(field.to_owned(), replacement);

        let validation = validate_lowered_ir_artifact(&lowered, &graph);
        let codes = lowered_ir_diagnostic_codes(&validation.diagnostics);
        assert!(
            codes.contains(expected_code),
            "{field} mismatch should be diagnosed"
        );
        assert!(
            validation.derived_facts.is_empty(),
            "{field} mismatch must not receive validator facts"
        );
    }
}

#[test]
fn lowered_ir_report_derives_validator_facts() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let facts = lowered
        .get("derived_facts")
        .and_then(Value::as_array)
        .expect("lowered IR derived facts");
    assert!(facts.iter().all(|fact| {
        fact.get("owner_subsystem").and_then(Value::as_str) == Some("lowered_ir_validator")
    }));

    let predicates = lowered_ir_fact_predicates(&lowered);
    let graph_id = graph
        .get("graph_id")
        .and_then(Value::as_str)
        .expect("graph id");
    assert!(predicates.contains(&format!("lowered_ir.validator.graph.coverage:{graph_id}")));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.owner_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.runtime_boundary:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.deterministic:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.report_complete:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.no_runtime_inputs:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.node_lowerings_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.edge_lowerings_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.dependency_lowerings_unique:{graph_id}"
    )));
    assert!(predicates.contains(&format!(
        "lowered_ir.validator.graph.core_object_ids_unique:{graph_id}"
    )));
    assert!(predicates.contains("lowered_ir.validator.node.lowered:effect:start:first"));
    assert!(predicates.contains("lowered_ir.validator.node.preservation:effect:start:first"));
    assert!(predicates
        .contains("lowered_ir.validator.node.preservation.lowering_class:effect:start:first"));
    assert!(predicates
        .contains("lowered_ir.validator.node.preservation.terminal_binding:effect:start:first"));
    let preservation_class_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.preservation.lowering_class:effect:start:first",
    )
    .expect("node lowering class preservation refs");
    assert!(preservation_class_refs.contains(graph_id));
    assert!(preservation_class_refs.contains("effect:start:first"));
    assert!(preservation_class_refs.contains("capability_call"));
    let preservation_terminal_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.preservation.terminal_binding:effect:start:first",
    )
    .expect("node terminal binding preservation refs");
    assert!(preservation_terminal_refs.contains(graph_id));
    assert!(preservation_terminal_refs.contains("effect:start:first"));
    assert!(preservation_terminal_refs.contains("effect:start:first:produces:effect_handle"));
    assert!(predicates
        .contains("lowered_ir.validator.node.lifecycle_inputs:effect:start:first:capability_call"));
    let lifecycle_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.lifecycle_inputs:effect:start:first:capability_call",
    )
    .expect("lifecycle input refs");
    assert!(lifecycle_refs.contains(graph_id));
    assert!(lifecycle_refs.contains("effect:start:first"));
    assert!(lifecycle_refs.contains("capability_call"));
    assert!(lifecycle_refs.contains(CONSTRUCT_FAMILY_EFFECT_OPERATION));
    assert!(lifecycle_refs.contains("typed_effect_graph"));
    assert!(lifecycle_refs.contains("core:effect:effect:start:first"));
    assert!(lifecycle_refs.contains("effect"));
    assert!(lifecycle_refs.contains("effect_graph_template"));
    assert!(predicates.contains(
            "lowered_ir.validator.node.lifecycle_inputs.construct_family:effect:start:first:capability_call"
        ));
    let lifecycle_family_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.node.lifecycle_inputs.construct_family:effect:start:first:capability_call",
        )
        .expect("lifecycle construct-family refs");
    assert!(lifecycle_family_refs.contains(graph_id));
    assert!(lifecycle_family_refs.contains("effect:start:first"));
    assert!(lifecycle_family_refs.contains(CONSTRUCT_FAMILY_EFFECT_OPERATION));
    assert!(predicates.contains(
            "lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:effect:start:first:capability_call"
        ));
    let lifecycle_entrypoint_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.node.lifecycle_inputs.runtime_entrypoints:effect:start:first:capability_call",
        )
        .expect("lifecycle runtime-entrypoint refs");
    assert!(lifecycle_entrypoint_refs.contains("core:effect:effect:start:first"));
    assert!(lifecycle_entrypoint_refs.contains("effect_graph_template"));
    assert!(predicates
        .iter()
        .any(|predicate| predicate.starts_with("lowered_ir.validator.edge.preservation:")));
    let edge_required_predicate = predicates
        .iter()
        .find(|predicate| {
            predicate.starts_with("lowered_ir.validator.edge.preservation.required_port:")
        })
        .expect("edge required-port preservation component fact");
    let edge_required_refs = lowered_ir_fact_input_refs(&lowered, edge_required_predicate)
        .expect("edge required-port preservation refs");
    assert!(edge_required_refs.contains(graph_id));
    assert!(edge_required_refs
        .iter()
        .any(|reference| reference.contains("->")));
    assert!(edge_required_refs.len() >= 3);
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
        "lowered_ir.validator.dependency.lowered:dependency:start:first:succeeds:second"
    )));
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
        "lowered_ir.validator.dependency.preservation:dependency:start:first:succeeds:second"
    )));
    assert!(predicates.contains(
            "lowered_ir.validator.dependency.preservation.predicate:dependency:start:first:succeeds:second"
        ));
    let dependency_predicate_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.dependency.preservation.predicate:dependency:start:first:succeeds:second",
        )
        .expect("dependency predicate preservation refs");
    assert!(dependency_predicate_refs.contains(graph_id));
    assert!(dependency_predicate_refs.contains("dependency:start:first:succeeds:second"));
    assert!(dependency_predicate_refs.contains("succeeds"));
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
            "lowered_ir.validator.core_object.entrypoint:core:dependency:dependency:start:first:succeeds:second:dependency:effect_dependency_template"
        )));
    let dependency_entrypoint_refs = lowered_ir_fact_input_refs(
            &lowered,
            "lowered_ir.validator.core_object.entrypoint:core:dependency:dependency:start:first:succeeds:second:dependency:effect_dependency_template",
        )
        .expect("dependency entrypoint refs");
    assert!(dependency_entrypoint_refs.contains(
            "core:dependency:dependency:start:first:succeeds:second#entrypoint_refs.upstream_effect:effect:start:first"
        ));
    assert!(dependency_entrypoint_refs.contains(
        "core:dependency:dependency:start:first:succeeds:second#entrypoint_refs.predicate:succeeds"
    ));
    assert!(dependency_entrypoint_refs.contains(
            "core:dependency:dependency:start:first:succeeds:second#entrypoint_refs.downstream_effect:effect:start:second"
        ));
    assert!(predicates.iter().any(|predicate| predicate.starts_with(
            "lowered_ir.validator.core_object.owner:core:dependency:dependency:start:first:succeeds:second:dependency:dependency:start:first:succeeds:second"
        )));
    let owner_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.owner_unique:{graph_id}"),
    )
    .expect("owner uniqueness refs");
    assert!(owner_refs.contains("core:dependency:dependency:start:first:succeeds:second"));
    assert!(owner_refs.contains("dependency"));
    assert!(owner_refs.contains("dependency:start:first:succeeds:second"));
    let determinism_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.deterministic:{graph_id}"),
    )
    .expect("determinism refs");
    assert!(determinism_refs
        .iter()
        .any(|ref_| { ref_.starts_with("lowered_ir.root.accepted_program_digest:") }));
    assert!(determinism_refs
        .iter()
        .any(|ref_| { ref_.starts_with("lowered_ir.root.lowerer_version:whipplescript:") }));
    let report_complete_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.report_complete:{graph_id}"),
    )
    .expect("report completeness refs");
    assert!(report_complete_refs.contains("lowered_ir.inventory.node_lowering:effect:start:first"));
    assert!(report_complete_refs.contains(
        "lowered_ir.inventory.dependency_lowering:dependency:start:first:succeeds:second"
    ));
    assert!(report_complete_refs.contains(
        "lowered_ir.inventory.core_object:core:dependency:dependency:start:first:succeeds:second"
    ));
    let no_runtime_input_refs = lowered_ir_fact_input_refs(
        &lowered,
        &format!("lowered_ir.validator.graph.no_runtime_inputs:{graph_id}"),
    )
    .expect("no runtime input refs");
    assert!(no_runtime_input_refs.contains(
            "lowered_ir.runtime_boundary.core:dependency:dependency:start:first:succeeds:second:dependency:effect_dependency_template"
        ));
}

#[test]
fn lowered_ir_report_derives_node_output_compatibility_facts() {
    let (_, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let predicates = lowered_ir_fact_predicates(&lowered);

    assert!(predicates.contains("lowered_ir.validator.node.output_compat:effect:start:context"));
    assert!(predicates.contains(
        "lowered_ir.validator.node.output_compat.allowed_core_object_kinds:effect:start:context"
    ));
    assert!(predicates.contains(
        "lowered_ir.validator.node.output_compat.allowed_runtime_entrypoints:effect:start:context"
    ));
    assert!(predicates.contains(
        "lowered_ir.validator.node.output_compat.runtime_entrypoints:effect:start:context"
    ));
    let refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.output_compat:effect:start:context",
    )
    .expect("node output compatibility refs");
    assert!(refs.contains("effect:start:context"));
    assert!(refs.contains("core:effect:effect:start:context"));
    assert!(refs.contains("effect"));
    assert!(refs.contains("effect_graph_template"));
    let allowed_kind_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.output_compat.allowed_core_object_kinds:effect:start:context",
    )
    .expect("output allowed object-kind refs");
    assert!(allowed_kind_refs.contains("effect:start:context"));
    assert!(allowed_kind_refs.contains("effect"));
    let runtime_entrypoint_refs = lowered_ir_fact_input_refs(
        &lowered,
        "lowered_ir.validator.node.output_compat.runtime_entrypoints:effect:start:context",
    )
    .expect("output runtime-entrypoint refs");
    assert!(runtime_entrypoint_refs.contains("core:effect:effect:start:context"));
    assert!(runtime_entrypoint_refs.contains("effect_graph_template"));
}

#[test]
fn lowered_ir_report_emits_signal_source_template_objects() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some("source:deploy_events")
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter().any(|value| {
                        value.as_str() == Some("core:signal_source:source:deploy_events")
                    })
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str)
            == Some("core:signal_source:source:deploy_events")
            && object.get("object_kind").and_then(Value::as_str) == Some("signal_source")
            && object.get("runtime_entrypoint").and_then(Value::as_str)
                == Some("signal_source_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some("source:deploy_events")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("event"))
                .and_then(Value::as_str)
                == Some("deploy.finished")
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_schedule_template_objects() {
    let (graph, lowered) = schedule_construct_graph_and_lowered_report_for_test();
    let node_id = "effect:wait_for_deadline:deadline";
    let object_id = "core:schedule:effect:wait_for_deadline:deadline";

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(object_id)))
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(object_id)
            && object.get("object_kind").and_then(Value::as_str) == Some("schedule")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("schedule_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id)
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("schedule"))
                .and_then(Value::as_str)
                == Some(node_id)
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_assertion_check_objects() {
    let (graph, lowered) = assertion_construct_graph_and_lowered_report_for_test();
    let assertion_id = stable_hash_hex("true");
    let node_id = format!("assertion:{assertion_id}");
    let object_id = format!("core:assertion:{node_id}");

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id.as_str())
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(object_id.as_str()))
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(object_id.as_str())
            && object.get("object_kind").and_then(Value::as_str) == Some("assertion")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("assertion_check")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id.as_str())
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("assertion"))
                .and_then(Value::as_str)
                == Some(assertion_id.as_str())
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_rule_template_objects() {
    let (graph, lowered) = rule_template_construct_graph_and_lowered_report_for_test();
    let node_id = "rule:observe_start:when0";
    let object_id = "core:rule:rule:observe_start:when0";
    let fact_object_id = "core:fact:rule:observe_start:when0:schema:StartupSeen";

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| refs.iter().any(|value| value.as_str() == Some(object_id)))
    }));
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter()
                        .any(|value| value.as_str() == Some(fact_object_id))
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(object_id)
            && object.get("object_kind").and_then(Value::as_str) == Some("rule")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("rule_template")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id)
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("rule"))
                .and_then(Value::as_str)
                == Some("observe_start")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("fact"))
                .and_then(Value::as_str)
                == Some("observe_start:when0:started")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("graph"))
                .and_then(Value::as_str)
                == Some("observe_start:when0:graph")
    }));
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some(fact_object_id)
            && object.get("object_kind").and_then(Value::as_str) == Some("fact")
            && object.get("runtime_entrypoint").and_then(Value::as_str) == Some("fact_record")
            && object.get("owner_kind").and_then(Value::as_str) == Some("node")
            && object.get("owner_ref").and_then(Value::as_str) == Some(node_id)
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("fact"))
                .and_then(Value::as_str)
                == Some("schema:StartupSeen")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("schema"))
                .and_then(Value::as_str)
                == Some("StartupSeen")
    }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_accounts_for_projection_reads_without_runtime_objects() {
    let (graph, lowered) = projection_read_construct_graph_and_lowered_report_for_test();
    let node_id = "projection_read:rule:observe:read0";

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let node_lowerings = lowered
        .get("node_lowerings")
        .and_then(Value::as_array)
        .expect("node lowerings");
    assert!(node_lowerings.iter().any(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) == Some(node_id)
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(!core_objects
        .iter()
        .any(|object| { object.get("owner_ref").and_then(Value::as_str) == Some(node_id) }));
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );
}

#[test]
fn lowered_ir_report_emits_package_effect_dependency_objects() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let dependency_ref = first_construct_graph_effect_dependency_ref(&graph);

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let dependency_lowerings = lowered
        .get("dependency_lowerings")
        .and_then(Value::as_array)
        .expect("dependency lowerings");
    assert!(dependency_lowerings.iter().any(|lowering| {
        lowering.get("dependency_ref").and_then(Value::as_str) == Some(dependency_ref.as_str())
            && lowering
                .get("produced_core_object_refs")
                .and_then(Value::as_array)
                .is_some_and(|refs| {
                    refs.iter().any(|value| {
                        value.as_str()
                            == Some("core:dependency:dependency:start:first:succeeds:second")
                    })
                })
    }));

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str)
            == Some("core:dependency:dependency:start:first:succeeds:second")
            && object.get("object_kind").and_then(Value::as_str) == Some("dependency")
            && object.get("owner_kind").and_then(Value::as_str) == Some("dependency")
            && object.get("owner_ref").and_then(Value::as_str) == Some(dependency_ref.as_str())
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("upstream_effect"))
                .and_then(Value::as_str)
                == Some("effect:start:first")
            && object
                .get("entrypoint_refs")
                .and_then(|refs| refs.get("downstream_effect"))
                .and_then(Value::as_str)
                == Some("effect:start:second")
    }));
}

#[test]
fn lowered_ir_report_emits_core_effect_dependency_objects() {
    let (graph, lowered) = core_effect_dependency_construct_graph_and_lowered_report_for_test();
    let dependency_ref = first_construct_graph_effect_dependency_ref(&graph);

    assert_eq!(
        lowered
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let core_objects = lowered
        .get("core_objects")
        .and_then(Value::as_array)
        .expect("core objects");
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some("core:effect:effect:start:first")
            && object.get("owner_ref").and_then(Value::as_str) == Some("effect:start:first")
    }));
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str) == Some("core:effect:effect:start:second")
            && object.get("owner_ref").and_then(Value::as_str) == Some("effect:start:second")
    }));
    assert!(core_objects.iter().any(|object| {
        object.get("object_id").and_then(Value::as_str)
            == Some("core:dependency:dependency:start:first:succeeds:second")
            && object.get("owner_kind").and_then(Value::as_str) == Some("dependency")
            && object.get("owner_ref").and_then(Value::as_str) == Some(dependency_ref.as_str())
    }));
}

#[test]
fn lowered_ir_validator_rejects_unlowered_graph_node() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowerings = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings");
    node_lowerings.retain(|lowering| {
        lowering.get("node_id").and_then(Value::as_str) != Some("effect:start:context")
    });

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node_unlowered"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_graph_node_lowering() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowerings = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings");
    let duplicate = node_lowerings
        .iter()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering")
        .clone();
    node_lowerings.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_missing_node_preservation_evidence() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowering = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings")
        .iter_mut()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering");
    node_lowering
        .as_object_mut()
        .expect("node lowering object")
        .remove("preserved_terminal_binding_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.preservation_field_missing"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_node_preservation_ref() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let node_lowering = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings")
        .iter_mut()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str) == Some("effect:start:context")
        })
        .expect("effect node lowering");
    let refs = node_lowering
        .get_mut("preserved_terminal_binding_refs")
        .and_then(Value::as_array_mut)
        .expect("terminal binding refs");
    let duplicate = refs.first().expect("terminal binding ref").clone();
    refs.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.preservation_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_node_output_kind_not_allowed_by_graph() {
    let (mut graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    construct_graph_node_mut(&mut graph, "effect:start:context")
        .as_object_mut()
        .expect("node object")
        .insert("allowed_core_object_kinds".to_owned(), json!(["rule"]));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.output_kind_unallowed"));
}

#[test]
fn lowered_ir_validator_rejects_node_runtime_entrypoint_not_allowed_by_graph() {
    let (mut graph, lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    construct_graph_node_mut(&mut graph, "effect:start:context")
        .as_object_mut()
        .expect("node object")
        .insert(
            "allowed_runtime_entrypoints".to_owned(),
            json!(["rule_template"]),
        );

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.node.runtime_entrypoint_unallowed"));
}

#[test]
fn lowered_ir_validator_rejects_unlowered_graph_edge() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let edge_lowerings = lowered
        .get_mut("edge_lowerings")
        .and_then(Value::as_array_mut)
        .expect("edge lowerings");
    edge_lowerings.clear();

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.edge_unlowered"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_graph_edge_lowering() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let edge_lowerings = lowered
        .get_mut("edge_lowerings")
        .and_then(Value::as_array_mut)
        .expect("edge lowerings");
    let duplicate = edge_lowerings.first().expect("edge lowering").clone();
    edge_lowerings.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.edge_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_edge_preservation_ref() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let edge_lowering = lowered
        .get_mut("edge_lowerings")
        .and_then(Value::as_array_mut)
        .expect("edge lowerings")
        .first_mut()
        .expect("edge lowering");
    let refs = edge_lowering
        .get_mut("preserved_span_refs")
        .and_then(Value::as_array_mut)
        .expect("span refs");
    let duplicate = refs.first().expect("span ref").clone();
    refs.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.edge.preservation_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_dependency_preservation_ref() {
    let (graph, mut lowered) =
        package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let dependency_lowering = lowered
        .get_mut("dependency_lowerings")
        .and_then(Value::as_array_mut)
        .expect("dependency lowerings")
        .first_mut()
        .expect("dependency lowering");
    let refs = dependency_lowering
        .get_mut("preserved_effect_refs")
        .and_then(Value::as_array_mut)
        .expect("effect refs");
    let duplicate = refs.first().expect("effect ref").clone();
    refs.push(duplicate);

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.dependency.preservation_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_core_object_metadata_ref() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    core_object.as_object_mut().expect("core object").insert(
        "resource_refs".to_owned(),
        json!(["resource:db", "resource:db"]),
    );

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.metadata_field_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_duplicate_node_core_object_owner() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let object_id = "core:effect:effect:start:context";
    let node_lowerings = lowered
        .get_mut("node_lowerings")
        .and_then(Value::as_array_mut)
        .expect("node lowerings");
    let contract_lowering = node_lowerings
        .iter_mut()
        .find(|lowering| {
            lowering.get("node_id").and_then(Value::as_str)
                == Some("contract:std.memory:memory.query:0.1.0")
        })
        .expect("contract lowering");
    contract_lowering
        .get_mut("produced_core_object_refs")
        .and_then(Value::as_array_mut)
        .expect("produced refs")
        .push(json!(object_id));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.owner_duplicate"));
}

#[test]
fn lowered_ir_validator_rejects_core_object_declared_owner_mismatch() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    core_object.as_object_mut().expect("core object").insert(
        "owner_ref".to_owned(),
        json!("contract:std.memory:memory.query:0.1.0"),
    );

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.owner_unmatched"));
}

#[test]
fn lowered_ir_validator_rejects_dependency_object_owned_by_interface_edge() {
    let (graph, mut lowered) =
        package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let edge_ref = first_construct_graph_edge_ref(&graph);
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("dependency"))
        .expect("dependency core object");
    let object = core_object.as_object_mut().expect("core object");
    object.insert("owner_kind".to_owned(), json!("edge"));
    object.insert("owner_ref".to_owned(), json!(edge_ref));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.dependency_owner_kind"));
}

#[test]
fn lowered_ir_validator_rejects_dependency_object_without_entrypoint_refs() {
    let (graph, mut lowered) =
        package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("dependency"))
        .expect("dependency core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_bridge_emits_dependency_handoff_entrypoint() {
    let (graph, lowered) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("dependency-bridge.whip", &graph, &lowered);

    assert!(source.contains("dependencyLoweringPreserved("));
    assert!(source.contains("dependencyEntrypoint("));
    assert!(source.contains("coreObjectOwnedByDependency("));
}

#[test]
fn lowered_ir_validator_rejects_signal_source_object_without_entrypoint_refs() {
    let (graph, mut lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("signal_source"))
        .expect("event source core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_validator_rejects_schedule_object_without_entrypoint_refs() {
    let (graph, mut lowered) = schedule_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("schedule"))
        .expect("schedule core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_validator_rejects_assertion_object_without_entrypoint_refs() {
    let (graph, mut lowered) = assertion_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("assertion"))
        .expect("assertion core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_validator_rejects_rule_object_without_entrypoint_refs() {
    let (graph, mut lowered) = rule_template_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| object.get("object_kind").and_then(Value::as_str) == Some("rule"))
        .expect("rule core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .remove("entrypoint_refs");

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.entrypoint_refs_missing"));
}

#[test]
fn lowered_ir_bridge_emits_signal_source_handoff_entrypoint() {
    let (graph, lowered) = signal_source_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("event-ingress.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("eventSourceEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_bridge_emits_schedule_handoff_entrypoint() {
    let (graph, lowered) = schedule_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("schedule-graph.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("scheduleEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_bridge_emits_assertion_handoff_entrypoint() {
    let (graph, lowered) = assertion_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("assertion-graph.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("assertionCheckLowering"));
    assert!(source.contains("assertionEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_bridge_emits_rule_handoff_entrypoint() {
    let (graph, lowered) = rule_template_construct_graph_and_lowered_report_for_test();
    assert_eq!(
        validate_lowered_ir_report(&lowered, &graph),
        Vec::<Value>::new()
    );

    let source = run_lowered_ir_bridge_for_test("rule-graph.whip", &graph, &lowered);

    assert!(source.contains("loweringPreservedNode("));
    assert!(source.contains("ruleTemplateLowering"));
    assert!(source.contains("ruleEntrypoint("));
    assert!(source.contains("factEntrypoint("));
    assert!(source.contains("coreObjectOwnedByNode("));
}

#[test]
fn lowered_ir_validator_rejects_runtime_state_materialization() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    let object = core_object.as_object_mut().expect("core object");
    object.insert("object_kind".to_owned(), json!("run"));
    object.insert("runtime_entrypoint".to_owned(), json!("run_record"));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.runtime_state_materialized"));
}

#[test]
fn lowered_ir_validator_rejects_core_object_entrypoint_mismatch() {
    let (graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
    let core_object = lowered
        .get_mut("core_objects")
        .and_then(Value::as_array_mut)
        .expect("core objects")
        .iter_mut()
        .find(|object| {
            object.get("object_id").and_then(Value::as_str)
                == Some("core:effect:effect:start:context")
        })
        .expect("effect core object");
    core_object
        .as_object_mut()
        .expect("core object")
        .insert("runtime_entrypoint".to_owned(), json!("fact_record"));

    let diagnostics = validate_lowered_ir_report(&lowered, &graph);
    let codes = lowered_ir_diagnostic_codes(&diagnostics);
    assert!(codes.contains("lowered_ir.core_object.runtime_entrypoint_mismatch"));
}

#[test]
fn lowered_ir_validator_accepts_runtime_handoff_entrypoints() {
    for (object_kind, runtime_entrypoint, entrypoint_refs) in [
        (
            "event",
            "event_record",
            json!({
                "event": "deploy.finished",
            }),
        ),
        (
            "projection",
            "event_projection",
            json!({
                "event": "deploy.finished",
                "fact": "schema:DeployFinished",
            }),
        ),
        (
            "diagnostic",
            "diagnostic_record",
            json!({
                "rule": "observe",
            }),
        ),
    ] {
        let (mut graph, mut lowered) = package_memory_construct_graph_and_lowered_report_for_test();
        let graph_node = construct_graph_node_mut(&mut graph, "effect:start:context")
            .as_object_mut()
            .expect("graph node");
        graph_node.insert("allowed_core_object_kinds".to_owned(), json!([object_kind]));
        graph_node.insert(
            "allowed_runtime_entrypoints".to_owned(),
            json!([runtime_entrypoint]),
        );
        let core_object = lowered
            .get_mut("core_objects")
            .and_then(Value::as_array_mut)
            .expect("core objects")
            .iter_mut()
            .find(|object| {
                object.get("object_id").and_then(Value::as_str)
                    == Some("core:effect:effect:start:context")
            })
            .expect("effect core object");
        let object = core_object.as_object_mut().expect("core object");
        object.insert("object_kind".to_owned(), json!(object_kind));
        object.insert("runtime_entrypoint".to_owned(), json!(runtime_entrypoint));
        object.insert("entrypoint_refs".to_owned(), entrypoint_refs);

        let diagnostics = validate_lowered_ir_report(&lowered, &graph);
        assert_eq!(diagnostics, Vec::<Value>::new(), "{object_kind}");
    }
}

#[test]
fn construct_graph_validator_rejects_duplicate_exactly_one_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    let mut duplicate_edge = graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .cloned()
        .expect("graph has an edge");
    let provided_port_id = first_construct_graph_provided_port_id(&graph);
    let duplicate_port_id = format!("{provided_port_id}:duplicate");
    let mut duplicate_port = construct_graph_port(&graph, &provided_port_id).clone();
    duplicate_port
        .as_object_mut()
        .expect("port object")
        .insert("port_id".to_owned(), json!(duplicate_port_id.clone()));
    let provider_node_id = duplicate_edge
        .get("provider_node_id")
        .and_then(Value::as_str)
        .expect("edge has provider node")
        .to_owned();
    construct_graph_node_mut(&mut graph, &provider_node_id)
        .get_mut("produced_ports")
        .and_then(Value::as_array_mut)
        .expect("produced ports array")
        .push(json!(duplicate_port_id.clone()));
    graph
        .get_mut("ports")
        .and_then(Value::as_array_mut)
        .expect("ports array")
        .push(duplicate_port);
    duplicate_edge
        .as_object_mut()
        .expect("edge object")
        .insert("provided_port_id".to_owned(), json!(duplicate_port_id));
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .push(duplicate_edge);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.exactly_one"));
}

#[test]
fn construct_graph_validator_accepts_optional_one_without_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("optional-one"));
    sync_declared_required_interface_cardinality(&mut graph, &required_port_id, "optional-one");
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .clear();

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
    let refs = construct_graph_validation_fact_input_refs(
        &validation,
        "validator.cardinality.optional-one.satisfied:",
    )
    .expect("optional-one cardinality fact");
    assert_eq!(refs, BTreeSet::from([required_port_id]));
}

#[test]
fn construct_graph_validator_rejects_duplicate_optional_one_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("optional-one"));
    let mut duplicate_edge = graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .cloned()
        .expect("graph has an edge");
    let provided_port_id = first_construct_graph_provided_port_id(&graph);
    let duplicate_port_id = format!("{provided_port_id}:duplicate");
    let mut duplicate_port = construct_graph_port(&graph, &provided_port_id).clone();
    duplicate_port
        .as_object_mut()
        .expect("port object")
        .insert("port_id".to_owned(), json!(duplicate_port_id.clone()));
    let provider_node_id = duplicate_edge
        .get("provider_node_id")
        .and_then(Value::as_str)
        .expect("edge has provider node")
        .to_owned();
    construct_graph_node_mut(&mut graph, &provider_node_id)
        .get_mut("produced_ports")
        .and_then(Value::as_array_mut)
        .expect("produced ports array")
        .push(json!(duplicate_port_id.clone()));
    graph
        .get_mut("ports")
        .and_then(Value::as_array_mut)
        .expect("ports array")
        .push(duplicate_port);
    duplicate_edge
        .as_object_mut()
        .expect("edge object")
        .insert("provided_port_id".to_owned(), json!(duplicate_port_id));
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .push(duplicate_edge);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.optional_one"));
}

#[test]
fn construct_graph_validator_accepts_many_with_contiguous_order() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    let edge_ref = first_construct_graph_edge_ref(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("many"));
    sync_declared_required_interface_cardinality(&mut graph, &required_port_id, "many");
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object")
        .insert("order_index".to_owned(), json!(0));

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
    let refs = construct_graph_validation_fact_input_refs(
        &validation,
        "validator.cardinality.many.satisfied:",
    )
    .expect("many cardinality fact");
    assert!(refs.contains(&edge_ref));
    assert!(refs.contains(&format!("{edge_ref}#order_index:0")));
}

#[test]
fn construct_graph_validator_rejects_many_with_noncontiguous_order() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("many"));
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object")
        .insert("order_index".to_owned(), json!(1));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.order_not_contiguous"));
}

#[test]
fn construct_graph_validator_rejects_many_with_resource_key() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("many"));
    let edge = graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object");
    edge.insert("order_index".to_owned(), json!(0));
    edge.insert("resource_key".to_owned(), json!("issue-source"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.resource_key_unexpected"));
}

#[test]
fn construct_graph_validator_accepts_named_many_with_order_and_key() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    let edge_ref = first_construct_graph_edge_ref(&graph);
    construct_graph_port_mut(&mut graph, &required_port_id)
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("named-many"));
    sync_declared_required_interface_cardinality(&mut graph, &required_port_id, "named-many");
    let edge = graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge")
        .as_object_mut()
        .expect("edge object");
    edge.insert("order_index".to_owned(), json!(0));
    edge.insert("resource_key".to_owned(), json!("issue-source"));

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
    let refs = construct_graph_validation_fact_input_refs(
        &validation,
        "validator.cardinality.named-many.satisfied:",
    )
    .expect("named-many cardinality fact");
    assert!(refs.contains(&edge_ref));
    assert!(refs.contains(&format!("{edge_ref}#order_index:0")));
    assert!(refs.contains(&format!("{edge_ref}#resource_key:issue-source")));
}

#[test]
fn construct_graph_validator_rejects_duplicate_edge_ref() {
    let mut graph = package_memory_construct_graph_for_test();
    let duplicate_edge = graph
        .get("edges")
        .and_then(Value::as_array)
        .and_then(|edges| edges.first())
        .cloned()
        .expect("graph has an edge");
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .push(duplicate_edge);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.edge.duplicate"));
}

#[test]
fn construct_graph_validator_rejects_missing_exactly_one_resolution() {
    let mut graph = package_memory_construct_graph_for_test();
    graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .expect("edges array")
        .clear();

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.exactly_one"));
}

#[test]
fn construct_graph_validator_rejects_incompatible_edge_type() {
    let mut graph = package_memory_construct_graph_for_test();
    let provided_port_id = first_construct_graph_provided_port_id(&graph);
    let provided_port = construct_graph_port_mut(&mut graph, &provided_port_id);
    provided_port
        .as_object_mut()
        .expect("port object")
        .insert("type".to_owned(), json!("tracker.issue"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.edge.type_mismatch"));
}

#[test]
fn construct_graph_validator_rejects_missing_declared_lowering_interface() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut()
        .expect("node object")
        .insert("declared_provided_interfaces".to_owned(), json!([]));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.lowering_provided_missing"));
}

#[test]
fn construct_graph_validator_rejects_unknown_output_object_kind() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut().expect("node object").insert(
        "allowed_core_object_kinds".to_owned(),
        json!(["effect_object"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.output_kind_unknown"));
}

#[test]
fn construct_graph_validator_rejects_unknown_runtime_entrypoint() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut().expect("node object").insert(
        "allowed_runtime_entrypoints".to_owned(),
        json!(["kernel.graph_commit"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.runtime_entrypoint_unknown"));
    assert!(codes.contains("construct_graph.node.runtime_entrypoint_missing"));
}

#[test]
fn construct_graph_validator_accepts_runtime_handoff_output_vocabulary() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let object = node.as_object_mut().expect("node object");
    object.insert(
        "allowed_core_object_kinds".to_owned(),
        json!(["event", "projection", "diagnostic"]),
    );
    object.insert(
        "allowed_runtime_entrypoints".to_owned(),
        json!(["event_record", "event_projection", "diagnostic_record"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    assert_eq!(validation.diagnostics, Vec::<Value>::new());
}

#[test]
fn construct_graph_validator_rejects_unmatched_runtime_entrypoint() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut().expect("node object").insert(
        "allowed_runtime_entrypoints".to_owned(),
        json!(["effect_graph_template", "assertion_check"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.runtime_entrypoint_unmatched"));
}

#[test]
fn construct_graph_validator_rejects_lifecycle_profile_mismatch() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    node.as_object_mut()
        .expect("node object")
        .insert("lifecycle_profile".to_owned(), json!("event_projection"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.lifecycle_profile_mismatch"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_node_inventory_ref() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_ports = node
        .get_mut("required_ports")
        .and_then(Value::as_array_mut)
        .expect("required ports");
    let duplicate = required_ports.first().expect("required port").clone();
    required_ports.push(duplicate);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.node.string_array_duplicate"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_edge_evidence_ref() {
    let mut graph = package_memory_construct_graph_for_test();
    let edge = graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .and_then(|edges| edges.first_mut())
        .expect("edge");
    edge.as_object_mut().expect("edge object").insert(
        "evidence".to_owned(),
        json!(["edge:evidence", "edge:evidence"]),
    );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.edge.string_array_duplicate"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_dependency_evidence_ref() {
    let (mut graph, _) = package_memory_dependency_construct_graph_and_lowered_report_for_test();
    let dependency = graph
        .get_mut("effect_dependencies")
        .and_then(Value::as_array_mut)
        .and_then(|dependencies| dependencies.first_mut())
        .expect("effect dependency");
    dependency
        .as_object_mut()
        .expect("effect dependency object")
        .insert(
            "evidence".to_owned(),
            json!(["dependency:evidence", "dependency:evidence"]),
        );

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.effect_dependency.string_array_duplicate"));
}

#[test]
fn construct_graph_validator_rejects_declared_interface_without_matching_port() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_interfaces = node
        .get_mut("declared_required_interfaces")
        .and_then(Value::as_array_mut)
        .expect("required interfaces");
    required_interfaces
        .first_mut()
        .expect("required interface")
        .as_object_mut()
        .expect("required interface object")
        .insert("name".to_owned(), json!("memory.write"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.unsatisfied"));
}

#[test]
fn construct_graph_validator_rejects_declared_interface_phase_mismatch() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_interfaces = node
        .get_mut("declared_required_interfaces")
        .and_then(Value::as_array_mut)
        .expect("required interfaces");
    required_interfaces
        .first_mut()
        .expect("required interface")
        .as_object_mut()
        .expect("required interface object")
        .insert("phase".to_owned(), json!("runtime"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.unsatisfied"));
}

#[test]
fn construct_graph_validator_rejects_declared_interface_cardinality_mismatch() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let provided_interfaces = node
        .get_mut("declared_provided_interfaces")
        .and_then(Value::as_array_mut)
        .expect("provided interfaces");
    provided_interfaces
        .first_mut()
        .expect("provided interface")
        .as_object_mut()
        .expect("provided interface object")
        .insert("cardinality".to_owned(), json!("optional-one"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.unsatisfied"));
}

#[test]
fn construct_graph_validator_rejects_duplicate_declared_interface() {
    let mut graph = package_memory_construct_graph_for_test();
    let node = construct_graph_node_mut(&mut graph, "effect:start:context");
    let required_interfaces = node
        .get_mut("declared_required_interfaces")
        .and_then(Value::as_array_mut)
        .expect("required interfaces");
    let duplicate = required_interfaces
        .first()
        .expect("required interface")
        .clone();
    required_interfaces.push(duplicate);

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.interface.duplicate"));
}

#[test]
fn construct_graph_validator_rejects_named_many_without_order_and_key() {
    let mut graph = package_memory_construct_graph_for_test();
    let required_port_id = first_construct_graph_required_port_id(&graph);
    let required_port = construct_graph_port_mut(&mut graph, &required_port_id);
    required_port
        .as_object_mut()
        .expect("port object")
        .insert("cardinality".to_owned(), json!("named-many"));

    let validation = validate_construct_graph_artifact(&graph);
    let codes = construct_graph_diagnostic_codes(&validation.diagnostics);
    assert!(codes.contains("construct_graph.cardinality.order_missing"));
    assert!(codes.contains("construct_graph.cardinality.resource_key_missing"));
}

#[test]
fn capability_call_lowering_requires_target_capability() {
    let effects = parse_effect_statements(
        "call memory.query for task as context",
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );

    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].kind, "capability.call");
    assert_eq!(effects[0].target.as_deref(), Some("memory.query"));
    assert_eq!(
        effects[0].required_capabilities_json(),
        r#"["memory.query"]"#
    );
}

#[test]
fn recall_form_lowers_to_memory_query_capability_call() {
    let effects = parse_effect_statements(
        "recall project_memory for task as context",
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );

    assert_eq!(effects.len(), 1);
    assert_eq!(effects[0].kind, "capability.call");
    assert_eq!(effects[0].name.as_deref(), Some("recall"));
    assert_eq!(effects[0].target.as_deref(), Some("memory.query"));
    assert_eq!(
        effects[0].args,
        vec!["project_memory".to_owned(), "task".to_owned()]
    );
    assert_eq!(
        effects[0].required_capabilities_json(),
        r#"["memory.query"]"#
    );
}

#[test]
fn parse_effect_statements_skips_record_block_fields() {
    // A record field named like an effect keyword (`prompt`, `release`, ...)
    // must not be scanned as an effect statement — six same-shaped rows in a
    // fixture table produced colliding effect idempotency keys (the
    // provider-language e2e regression).
    let body = r#"
record LanguageTask {
  provider codex
  prompt "Write a four-line original poem about rain."
  release "not-an-effect"
  status "queued"
}
record LanguageTask {
  provider claude
  prompt "Write a four-line original poem about snow."
  status "queued"
}
done task -> record Archived {
  prompt "still not an effect"
}
prompt "Summarize {{ ticket.title }}" as summary
"#;
    let effects = parse_effect_statements(
        body,
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );
    assert_eq!(effects.len(), 1, "only the real prompt effect: {effects:?}");
    assert_eq!(effects[0].kind, "schema.coerce");
    assert_eq!(effects[0].name.as_deref(), Some("prompt"));
    assert_eq!(effects[0].binding.as_deref(), Some("summary"));
}

#[test]
fn parse_effect_statements_covers_accepted_body_surface() {
    let body = r#"
tell worker as turn "go"
coerce classify(ticket.title) as review
prompt "Summarize {{ ticket.title }}" using fixture as summary
decide "fixed?" -> { fixed bool } as verdict
call memory.query for ticket as called
recall project_memory for ticket.title as memories
send via ops_room { text ticket.title } as sent
invoke Child { item ticket.title } as child
timer 5m as wait
timer until ticket.due_at as deadline
exec "echo hi" as run
file issue into backlog { title ticket.title body "body" } as filed
claim item as lease
release item
finish item { summary ticket.title }
acquire workspace_slot for workspace until ttl as slot
append LedgerEntry { area ticket.id text ticket.title } to review_log as entry
consume request_budget for ticket amount ticket.amount as spend
emit signal deploy.finished to ticket.id { service ticket.title status "ok" } as signal_sent
read text from docs at "note.md" as file_read
write text to docs at "out.md" { body ticket.title mode create } as file_write
import json Row from docs at "rows.json" as imported
export json Row to docs at "rows.json" { mode create } as exported
"#;

    let effects = parse_effect_statements(
        body,
        &RuleContext::default(),
        &[],
        &[],
        &whipplescript_kernel::rule_lowering::empty_ir_program(),
    );
    let expected = [
        ("agent.tell", Some("turn")),
        ("schema.coerce", Some("review")),
        ("schema.coerce", Some("summary")),
        ("schema.coerce", Some("verdict")),
        ("capability.call", Some("called")),
        ("capability.call", Some("memories")),
        ("capability.call", Some("sent")),
        ("workflow.invoke", Some("child")),
        ("timer.wait", Some("wait")),
        ("timer.wait", Some("deadline")),
        ("exec.command", Some("run")),
        ("tracker.file", Some("filed")),
        ("tracker.claim", Some("lease")),
        ("tracker.release", None),
        ("tracker.finish", None),
        ("lease.acquire", Some("slot")),
        ("ledger.append", Some("entry")),
        ("counter.consume", Some("spend")),
        ("signal.emit", Some("signal_sent")),
        ("file.read", Some("file_read")),
        ("file.write", Some("file_write")),
        ("file.import", Some("imported")),
        ("file.export", Some("exported")),
    ];

    assert_eq!(effects.len(), expected.len(), "{effects:?}");
    for (kind, binding) in expected {
        assert!(
            effects
                .iter()
                .any(|effect| effect.kind == kind && effect.binding.as_deref() == binding),
            "missing {kind} / {binding:?} in {effects:?}"
        );
    }

    let prompt = effects
        .iter()
        .find(|effect| effect.binding.as_deref() == Some("summary"))
        .expect("prompt effect");
    assert_eq!(prompt.name.as_deref(), Some("prompt"));
    assert_eq!(prompt.target.as_deref(), Some("fixture"));
    assert_eq!(
        prompt.prompt.as_deref(),
        Some("Summarize {{ ticket.title }}")
    );
}

#[test]
fn whipplescript_author_skill_has_discovery_frontmatter() {
    let source = include_str!("../../../../skills/whipplescript-author/SKILL.md");
    let metadata = parse_skill_frontmatter(source).expect("skill frontmatter parses");

    assert_eq!(metadata.name.as_deref(), Some("whipplescript-author"));

    let description = metadata.description.expect("description is present");
    assert!(
        (1..=1024).contains(&description.len()),
        "description must be 1..=1024 chars, got {}",
        description.len()
    );

    for term in [
        "durable orchestration",
        "parallelizable",
        "long-running",
        "recurring",
        "scheduled",
        "timers",
        "queues",
        "retries",
        "human approvals",
        "multi-agent",
        "fan-out/fan-in",
        "plugin",
        "child workflows",
        "typed model decisions",
        "atomically commit",
        "durable effects",
    ] {
        assert!(
            description.contains(term),
            "description should route on `{term}`"
        );
    }
}

#[derive(Debug, Default)]
struct SkillFrontmatter {
    name: Option<String>,
    description: Option<String>,
}

fn parse_skill_frontmatter(source: &str) -> Result<SkillFrontmatter, String> {
    let source = source
        .strip_prefix("---\n")
        .ok_or_else(|| "missing opening frontmatter fence".to_owned())?;
    let (frontmatter, _) = source
        .split_once("\n---\n")
        .ok_or_else(|| "missing closing frontmatter fence".to_owned())?;

    let mut metadata = SkillFrontmatter::default();
    let mut lines = frontmatter.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            continue;
        }
        if line.starts_with(' ') {
            return Err(format!("unexpected indented field line `{line}`"));
        }

        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("malformed frontmatter line `{line}`"))?;
        let value = value.trim();
        let value = if value == ">-" {
            let mut block = Vec::new();
            while let Some(next) = lines.peek().copied() {
                if let Some(stripped) = next.strip_prefix("  ") {
                    block.push(stripped);
                    lines.next();
                } else {
                    break;
                }
            }
            block
                .join(" ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        } else {
            value.to_owned()
        };

        match key {
            "name" => metadata.name = Some(value),
            "description" => metadata.description = Some(value),
            other => return Err(format!("unknown frontmatter field `{other}`")),
        }
    }

    Ok(metadata)
}

#[test]
fn parses_trace_check_option() {
    let options =
        TraceOptions::parse(&["ins_123".to_owned(), "--check".to_owned()]).expect("parse");

    assert_eq!(options.instance_id, "ins_123");
    assert!(options.check);
}

#[test]
fn assertion_reports_typed_error_for_invalid_external_duration_value() {
    let source = r#"
workflow DurationAssertionExternalInvalid

class Window {
  elapsed duration
  limit duration
}

assert exists(Window where elapsed < limit)
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let facts = vec![FactView {
        fact_id: "fact-invalid-duration".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "Window".to_owned(),
        key: "fact-invalid-duration".to_owned(),
        value_json: r#"{"elapsed":"bad-duration","limit":"PT1H"}"#.to_owned(),
        provenance_class: "external".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    }];

    let assertions = eval_assertions(&ir, &facts, &[], None, &AssertionTagFilter::default());

    assert_eq!(assertions.len(), 1);
    assert_eq!(assertions[0].status, AssertionStatus::Error);
    assert!(assertions[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("invalid duration value `bad-duration`")));
    assert!(assertions[0]
        .failure_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("invalid duration value `bad-duration`")));
}

#[test]
fn lowering_consumes_matched_fact_binding() {
    let source = r#"
workflow ConsumeTask

class Task {
  status "queued"
}

class Done {
  status "done"
}

rule finish
  when Task as task where task.status == "queued"
=> {
  done task
  record Done {
    status "done"
  }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let fact = FactView {
        fact_id: "fact-task".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "Task".to_owned(),
        key: "Task:queued".to_owned(),
        value_json: r#"{"status":"queued"}"#.to_owned(),
        provenance_class: "rule".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let facts = vec![fact];
    let effects = Vec::new();
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &effects, None);
    assert_eq!(ready.contexts.len(), 1);

    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &ready.contexts[0],
        &facts,
        &effects,
        None,
    );

    assert_eq!(lowering.consumed_fact_ids, vec!["fact-task"]);
    assert_eq!(lowering.facts.len(), 1);
}

/// DR-0014 amendment (modeled in models/maude/effect-key.maude): the
/// `schema.coerce` admission key commits to the coercion name, declared
/// prompt template, synthesized output schema, and the host-supplied
/// config fingerprint — and ONLY schema.coerce keys see the fingerprint.
#[test]
fn schema_coerce_admission_key_commits_to_template_and_config_fingerprint() {
    let source_template_a = r#"
workflow CoerceKeyCommitments

class Review {
  accepted bool
}

output result Review

coerce reviewArtifact() -> Review {
  prompt """
  Review the artifact.
  """
}

agent scribe {
  provider fixture
  profile "issue-triager"
  capacity 1
}

rule start
  when started
=> {
  coerce reviewArtifact() as review
  tell scribe as note """
  Note the review.
  """

  after review succeeds as r {
    complete result { accepted r.accepted }
  }
}
"#;
    let source_template_b =
        source_template_a.replace("Review the artifact.", "Audit the artifact.");
    let lower = |source: &str, fingerprint: &str| {
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("compile");
        let lowering = lower_rule(
            "ins_test",
            "ver_test",
            "0",
            fingerprint,
            &ir,
            &ir.rules[0],
            &RuleContext::default(),
            &[],
            &[],
            None,
        );
        let key_of = |kind: &str| {
            lowering
                .effects
                .iter()
                .find(|effect| effect.kind == kind)
                .map(|effect| effect.idempotency_key.clone())
                .expect(kind)
        };
        (key_of("schema.coerce"), key_of("agent.tell"))
    };

    let (coerce_a1, tell_a1) = lower(source_template_a, "fixture");
    let (coerce_a2, tell_a2) = lower(source_template_a, "fixture");
    // Unchanged program + config dedups (same key both lowerings).
    assert_eq!(coerce_a1, coerce_a2);
    assert_eq!(tell_a1, tell_a2);

    // A changed prompt template is a distinct coercion even under the SAME
    // pinned program version literal (the prefix-replay hazard).
    let (coerce_b, _) = lower(&source_template_b, "fixture");
    assert_ne!(coerce_a1, coerce_b);

    // A changed coercion config re-keys schema.coerce — and nothing else.
    let (coerce_c, tell_c) = lower(source_template_a, "key_anthropic_sonnet");
    assert_ne!(coerce_a1, coerce_c);
    assert_eq!(tell_a1, tell_c);
}

#[test]
fn effect_id_carries_program_version_for_cross_revision_distinctness() {
    // The effect idempotency key is fixed at creation from the commit
    // identity, which includes program_version + revision_epoch
    // (spec/execution-contract.md). So the same rule firing under one version
    // dedups to the same effect key, but a re-fire under a NEW program_version
    // is a DISTINCT effect — a revised effect is never deduped against the
    // stale one. (Modeled in models/maude/effect-key.maude.)
    let source = r#"
workflow EffectKey

output result R

class R {
  x string
}

rule run
  when started
=> {
  exec "echo hi" as e

  after e succeeds as ran {
    complete result {
      x "ok"
    }
  }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let facts: Vec<FactView> = Vec::new();
    let effects: Vec<EffectView> = Vec::new();
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &effects, Some("evt-started"));
    assert_eq!(ready.contexts.len(), 1);
    let context = &ready.contexts[0];

    let effect_ids = |version: &str, epoch: &str| {
        lower_rule(
            "ins_test",
            version,
            epoch,
            "fixture",
            &ir,
            &ir.rules[0],
            context,
            &facts,
            &effects,
            None,
        )
        .effects
        .into_iter()
        .map(|effect| effect.effect_id)
        .collect::<Vec<_>>()
    };

    let v1 = effect_ids("ver_a", "0");
    assert!(!v1.is_empty(), "rule should lower an exec effect");
    assert_eq!(
        v1,
        effect_ids("ver_a", "0"),
        "same program version + epoch yields the same effect key (dedup holds)"
    );
    assert_ne!(
        v1,
        effect_ids("ver_b", "0"),
        "a new program version yields a distinct effect key"
    );
    assert_ne!(
        v1,
        effect_ids("ver_a", "1"),
        "a new revision epoch yields a distinct effect key"
    );
}

#[test]
fn coerce_json_schema_maps_types_to_strict_structured_output() {
    let source = r#"
@service
workflow SchemaShape

class Pick {
  kind "a" | "b"
  note string
  score int
  tag string?
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compiles");
    let schema = whipplescript_kernel::coerce_native::json_schema_for_type(
        &IrType::Ref("Pick".to_owned()),
        &ir.schemas,
    );
    assert_eq!(schema["type"], "object");
    assert_eq!(schema["additionalProperties"], json!(false));
    // string-literal union -> enum
    assert_eq!(
        schema["properties"]["kind"],
        json!({ "type": "string", "enum": ["a", "b"] })
    );
    assert_eq!(schema["properties"]["score"]["type"], "integer");
    // optional -> nullable
    assert_eq!(
        schema["properties"]["tag"],
        json!({ "anyOf": [{ "type": "string" }, { "type": "null" }] })
    );
    // strict: every field is required
    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("required array")
        .iter()
        .map(|value| value.as_str().expect("string"))
        .collect();
    for field in ["kind", "note", "score", "tag"] {
        assert!(required.contains(&field), "missing required {field}");
    }
}

#[test]
fn select_clock_occurrences_applies_missed_policy() {
    let due = vec!["t1".to_owned(), "t2".to_owned(), "t3".to_owned()];
    // Default (no declared policy) = coalesce: one fact at the latest instant,
    // missed_count folding the earlier ticks.
    assert_eq!(
        select_clock_occurrences(&due, None),
        vec![("t3".to_owned(), 2)]
    );
    assert_eq!(
        select_clock_occurrences(&due, Some(&MissedPolicy::Coalesce)),
        vec![("t3".to_owned(), 2)]
    );
    // skip: only the latest, missed ticks dropped (not folded).
    assert_eq!(
        select_clock_occurrences(&due, Some(&MissedPolicy::Skip)),
        vec![("t3".to_owned(), 0)]
    );
    // catch_up: one fact per occurrence, newest `limit` of them.
    assert_eq!(
        select_clock_occurrences(&due, Some(&MissedPolicy::CatchUp { limit: 2 })),
        vec![("t2".to_owned(), 0), ("t3".to_owned(), 0)]
    );
    // No due occurrences admits nothing.
    assert!(select_clock_occurrences(&[], None).is_empty());
}

fn time_of_day(hour: u8, minute: u8) -> TimeOfDay {
    TimeOfDay {
        hour,
        minute,
        span: SourceSpan { start: 0, end: 0 },
    }
}

#[test]
fn due_calendar_occurrences_enumerates_daily_in_window() {
    // `every day at 09:00` America/New_York; March 2026 is EDT (UTC-4), so
    // 09:00 local = 13:00Z. Window (10th 00:00Z, 13th 00:00Z] => 10th/11th/12th.
    let due = due_calendar_occurrences(
        "2026-03-10T00:00:00Z",
        "2026-03-13T00:00:00Z",
        "America/New_York",
        CalendarPattern::Day,
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-10T13:00:00Z".to_owned(),
            "2026-03-11T13:00:00Z".to_owned(),
            "2026-03-12T13:00:00Z".to_owned(),
        ]
    );
}

#[test]
fn due_calendar_occurrences_is_dst_correct_across_spring_forward() {
    // DST begins 2026-03-08 in America/New_York. 09:00 local is 14:00Z under EST
    // (UTC-5) before, and 13:00Z under EDT (UTC-4) after — the helper must shift.
    let due = due_calendar_occurrences(
        "2026-03-06T00:00:00Z",
        "2026-03-09T00:00:00Z",
        "America/New_York",
        CalendarPattern::Day,
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-06T14:00:00Z".to_owned(), // EST
            "2026-03-07T14:00:00Z".to_owned(), // EST
            "2026-03-08T13:00:00Z".to_owned(), // EDT (after spring-forward)
        ]
    );
}

#[test]
fn due_calendar_occurrences_weekday_skips_weekends() {
    // 2026-03-09 is a Monday; `every weekday at 09:00` over Mon..Sun yields Mon-Fri.
    let due = due_calendar_occurrences(
        "2026-03-09T00:00:00Z",
        "2026-03-14T00:00:00Z",
        "America/New_York",
        CalendarPattern::Weekday,
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-09T13:00:00Z".to_owned(),
            "2026-03-10T13:00:00Z".to_owned(),
            "2026-03-11T13:00:00Z".to_owned(),
            "2026-03-12T13:00:00Z".to_owned(),
            "2026-03-13T13:00:00Z".to_owned(),
        ]
    );
}

#[test]
fn due_calendar_occurrences_weekly_matches_only_that_weekday() {
    // `every monday at 09:00` over two weeks => the two Mondays (09th, 16th).
    let due = due_calendar_occurrences(
        "2026-03-08T00:00:00Z",
        "2026-03-23T00:00:00Z",
        "America/New_York",
        CalendarPattern::Weekly(Weekday::Monday),
        time_of_day(9, 0),
    );
    assert_eq!(
        due,
        vec![
            "2026-03-09T13:00:00Z".to_owned(),
            "2026-03-16T13:00:00Z".to_owned(),
        ]
    );
}

#[test]
fn due_calendar_occurrences_empty_when_now_not_after_cursor() {
    assert!(due_calendar_occurrences(
        "2026-03-10T00:00:00Z",
        "2026-03-10T00:00:00Z",
        "America/New_York",
        CalendarPattern::Day,
        time_of_day(9, 0),
    )
    .is_empty());
}

#[test]
fn lowering_preserves_multiline_prompt_content_type_metadata() {
    let source = r#"
workflow PromptContentType

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule start
  when started
=> {
  tell worker as turn """markdown
  Write a short report.
  """
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );

    assert_eq!(lowering.effects.len(), 1);
    let input = json_from_str(&lowering.effects[0].input_json);
    assert_eq!(
        input.get("prompt").and_then(Value::as_str),
        Some("Write a short report.")
    );
    assert_eq!(
        input.get("prompt_content_type").and_then(Value::as_str),
        Some("markdown")
    );
}

#[test]
fn lowering_preserves_coerce_prompt_content_type_metadata() {
    let source = r#"
workflow CoercePromptContentType

class Review {
  accepted bool
}

coerce reviewArtifact() -> Review {
  prompt """markdown
  Review the artifact.
  """
}

rule start
  when started
=> {
  coerce reviewArtifact() as review
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );

    assert_eq!(lowering.effects.len(), 1);
    let input = json_from_str(&lowering.effects[0].input_json);
    assert_eq!(
        input.get("prompt_template").and_then(Value::as_str),
        Some("Review the artifact.")
    );
    assert_eq!(
        input.get("prompt_content_type").and_then(Value::as_str),
        Some("markdown")
    );
}

#[test]
fn prompt_effect_input_json_uses_plain_string_shape() {
    let source = r#"
workflow PromptInput

class Done {
  ok bool
}

output result Done

rule start
  when started
=> {
  complete result { ok true }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let effect = ParsedEffect {
        kind: "schema.coerce".to_owned(),
        target: Some("fixture".to_owned()),
        name: Some("prompt".to_owned()),
        binding: Some("answer".to_owned()),
        args: Vec::new(),
        prompt: Some("Summarize this.".to_owned()),
        prompt_content_type: Some("markdown".to_owned()),
        prompt_template: Some("Summarize this.".to_owned()),
        required_capabilities: Vec::new(),
        after: None,
        timeout_seconds: None,
    };
    let mut errors = Vec::new();
    let input_json = parsed_effect_input_json(
        &ir,
        &ir.rules[0],
        &effect,
        &RuleContext::default(),
        &std::collections::BTreeMap::new(),
        &mut errors,
        &[],
        &[],
    );

    assert_eq!(errors, Vec::<String>::new());
    let input = json_from_str(&input_json);
    assert_eq!(
        input.get("function_name").and_then(Value::as_str),
        Some("prompt")
    );
    assert_eq!(
        input.get("output_type").and_then(Value::as_str),
        Some("string")
    );
    assert_eq!(
        input.get("prompt").and_then(Value::as_str),
        Some("Summarize this.")
    );
    assert_eq!(
        input.get("prompt_template").and_then(Value::as_str),
        Some("Summarize this.")
    );
    assert_eq!(
        input.get("provider").and_then(Value::as_str),
        Some("fixture")
    );
    assert_eq!(
        input.get("prompt_content_type").and_then(Value::as_str),
        Some("markdown")
    );
}

#[test]
fn agent_tell_input_json_carries_turn_access_grants() {
    let source = r#"
workflow OwnedGrantInput

agent coder {
  provider owned
  profile "repo-writer"
  capacity 1
}

file store project_files {
  root "."
  allow read ["src/**"]
}

rule start
  when started
=> {
  tell coder as turn
    with access to project_files {
      read ["src/**"]
    }
    with access to command {
      run
    }
    "work"
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );
    let tell = lowering
        .effects
        .iter()
        .find(|effect| effect.kind == "agent.tell")
        .expect("agent tell effect");
    let input = json_from_str(&tell.input_json);
    let grants = input
        .get("access_grants")
        .and_then(Value::as_array)
        .expect("access grants");

    assert_eq!(grants.len(), 2);
    assert_eq!(
        grants[0].get("resource").and_then(Value::as_str),
        Some("project_files")
    );
    assert_eq!(
        grants[0]
            .pointer("/operations/0/operation")
            .and_then(Value::as_str),
        Some("read")
    );
    assert_eq!(
        grants[0].pointer("/operations/0/globs"),
        Some(&json!(["src/**"]))
    );
    assert_eq!(
        grants[1].get("resource").and_then(Value::as_str),
        Some("command")
    );
    assert_eq!(
        grants[1]
            .pointer("/operations/0/operation")
            .and_then(Value::as_str),
        Some("run")
    );
    // Q3 fix: the file-store grant carries the store's own policy snapshot so
    // the harness can intersect the turn grant against the store's authority.
    assert_eq!(
        grants[0]
            .pointer("/store_policy/root")
            .and_then(Value::as_str),
        Some(".")
    );
    assert_eq!(
        grants[0].pointer("/store_policy/allow_read"),
        Some(&json!(["src/**"]))
    );
    assert_eq!(
        grants[0].pointer("/store_policy/allow_write"),
        Some(&json!([]))
    );
    // The non-file `command` grant carries no store policy.
    assert!(grants[1].get("store_policy").is_none());
}

#[test]
fn workflow_invoke_input_json_carries_start_access_grants() {
    let source = r#"
class Done { ok bool }

workflow Parent {
  output result Done
  rule start
    when started
  => {
    invoke Child { }
      with access to child_authority {
        invoke
      }
      as child
    complete result { ok true }
  }
}

workflow Child {
  output result Done
  rule start
    when started
  => {
    complete result { ok true }
  }
}
"#;
    let ir = whipplescript_parser::compile_program_with_root(source, Some("Parent"))
        .ir
        .expect("compile");
    let lowering = lower_rule(
        "ins_test",
        "ver_test",
        "0",
        "fixture",
        &ir,
        &ir.rules[0],
        &RuleContext::default(),
        &[],
        &[],
        None,
    );
    let invoke = lowering
        .effects
        .iter()
        .find(|effect| effect.kind == "workflow.invoke")
        .expect("workflow invoke effect");
    let input = json_from_str(&invoke.input_json);
    let grants = input
        .get("access_grants")
        .and_then(Value::as_array)
        .expect("access grants");
    assert_eq!(grants.len(), 1);
    assert_eq!(
        grants[0].get("resource").and_then(Value::as_str),
        Some("child_authority")
    );
    assert_eq!(
        grants[0]
            .pointer("/operations/0/operation")
            .and_then(Value::as_str),
        Some("invoke")
    );
}

#[test]
fn multiline_prompt_single_word_opening_tail_stays_prompt_text() {
    let lines = ["tell worker \"\"\"hello", "world", "\"\"\""];
    let (prompt, cursor) = parse_prompt_from_lines(&lines, 0, lines[0]);

    assert_eq!(cursor, 2);
    assert_eq!(
        prompt,
        ParsedPrompt {
            text: "hello\nworld".to_owned(),
            content_type: None,
        }
    );
}

#[test]
fn ready_contexts_match_queue_ready_item_alias_to_projected_fact() {
    let source = r#"
workflow QueueReadyAlias

tracker backlog {
  provider builtin
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule claim_ready
  when backlog has ready issue as item
  when worker is available
=> {
  claim item as lease
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let fact = FactView {
        fact_id: "fact-queue-item".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "tracker.issue.ready".to_owned(),
        key: "backlog:WS-1:gen".to_owned(),
        value_json: r#"{"queue":"backlog","id":"WS-1","title":"Ready item","body":"Do work"}"#
            .to_owned(),
        provenance_class: "queue".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let other_queue = FactView {
        fact_id: "fact-other-item".to_owned(),
        program_version_id: None,
        revision_epoch: 0,
        name: "tracker.issue.ready".to_owned(),
        key: "other:WS-2:gen".to_owned(),
        value_json: r#"{"queue":"other","id":"WS-2","title":"Other","body":""}"#.to_owned(),
        provenance_class: "queue".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let facts = vec![fact, other_queue];
    let effects = Vec::new();
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &effects, None);

    assert_eq!(ready.contexts.len(), 1);
    assert_eq!(ready.contexts[0].bindings[0].0, "item");
    assert_eq!(ready.contexts[0].bindings[0].1.key, "backlog:WS-1:gen");
}

/// DR-0052 grammar pass slice 2: the std.vcs readiness sugar — each
/// phrase lowers to its `vcs.*` fact; the stream guard filters by the
/// leading word; `by others` excludes exactly the matching instance's
/// own principal.
#[test]
fn vcs_readiness_sugar_lowers_guards_and_excludes_own_writes() {
    let source = r#"
@service
workflow VcsSugar

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

stream triage {
  members [worker]
}

class Note { body string }
rule on_change
  when line changed by others as c
=> {
  record Note { body c.path }
}
rule on_contention
  when triage has contention as x
=> {
  record Note { body x.slice }
}
"#;
    let ir = whipplescript_parser::compile_program(source)
        .ir
        .expect("compile");
    let cut_fact = |id: &str, by: &str| FactView {
        fact_id: format!("fact-{id}"),
        program_version_id: None,
        revision_epoch: 0,
        name: "vcs.cut.recorded".to_owned(),
        key: id.to_owned(),
        value_json: format!(r#"{{"branch":"line","cut":"{id}","path":"src/a.rs","by":"{by}"}}"#),
        provenance_class: "external".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let own = cut_fact("c-own", "instance:i-1");
    let other = cut_fact("c-other", "s:sess-9");
    let facts = vec![own, other];
    // `line changed by others`: with the instance's own principal in
    // scope, only the foreign cut matches.
    let ready = whipplescript_kernel::rule_lowering::ready_contexts_for(
        &ir,
        &ir.rules[0],
        &facts,
        &[],
        None,
        Some("instance:i-1"),
    );
    assert_eq!(ready.contexts.len(), 1);
    assert_eq!(ready.contexts[0].bindings[0].1.key, "c-other");
    // Without an own-principal (projection contexts) both match.
    let ready = ready_contexts(&ir, &ir.rules[0], &facts, &[], None);
    assert_eq!(ready.contexts.len(), 2);
    // Stream guard: `triage has contention` matches only facts whose
    // payload names triage.
    let contention = |id: &str, stream: &str| FactView {
        fact_id: format!("fact-{id}"),
        program_version_id: None,
        revision_epoch: 0,
        name: "vcs.contention.predicted".to_owned(),
        key: id.to_owned(),
        value_json: format!(r#"{{"branch":"line","stream":"{stream}","slice":["src/a.rs"]}}"#),
        provenance_class: "external".to_owned(),
        source_span_json: None,
        source_event_id: String::new(),
    };
    let facts = vec![contention("k-1", "triage"), contention("k-2", "hotfix")];
    let ready = ready_contexts(&ir, &ir.rules[1], &facts, &[], None);
    assert_eq!(ready.contexts.len(), 1);
    assert_eq!(ready.contexts[0].bindings[0].1.key, "k-1");
}

#[test]
fn selects_failed_terminal_case_branch_and_binds_payload() {
    let body = r#"
case classification {
  Completed as result => {
    record TerminalRoute {
      branch "completed"
      detail result.summary
    }
  }
  Failed as failure => {
    record TerminalRoute {
      branch "failed"
      detail failure.reason
    }
  }
}
"#;
    let mut context = RuleContext::default();
    push_effect_binding(
        &mut context,
        "classification",
        "effect",
        json!({
            "tag": "Failed",
            "status": "failed",
            "error": {
                "reason": "fixture coerce failure"
            }
        }),
    );

    let (selected, selected_context, reports) = selected_rule_body(body, &context);

    assert!(selected.contains("branch \"failed\""));
    assert!(!selected.contains("branch \"completed\""));
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].status, BranchStatus::Matched);
    assert_eq!(
        parse_field_value("failure.reason", &selected_context),
        Value::String("fixture coerce failure".to_owned())
    );
}

#[test]
fn terminal_case_guard_error_selects_no_sibling_branch() {
    let body = r#"
case classification {
  Completed as result where result.summary => {
    tell worker "should not commit"
  }
  Failed as failure => {
    tell worker "failed sibling"
  }
}
"#;
    let mut context = RuleContext::default();
    push_effect_binding(
        &mut context,
        "classification",
        "effect",
        json!({
            "tag": "Completed",
            "status": "completed",
            "value": {
                "summary": "Fixture classification"
            }
        }),
    );

    let (selected, _selected_context, reports) = selected_rule_body(body, &context);

    assert!(selected.is_empty() || !selected.contains("tell worker \"should not commit\""));
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].status, BranchStatus::Error);
    assert!(reports[0]
        .error
        .as_deref()
        .is_some_and(|error| error.contains("did not evaluate to bool")));
}

#[test]
fn reconstructs_trace_records_from_store_events() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [
                    {"effect_id": "prepare", "status": "queued"},
                    {"effect_id": "send", "status": "queued"}
                ],
                "dependencies": [
                    {
                        "dependency_id": "dep_1",
                        "upstream_effect_id": "prepare",
                        "downstream_effect_id": "send",
                        "predicate": "succeeds"
                    }
                ]
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "prepare", "run_id": "run_prepare"}),
        ),
        event_view(
            3,
            "effect.terminal",
            json!({
                "effect_id": "prepare",
                "run_id": "run_prepare",
                "status": "completed"
            }),
        ),
        event_view(
            4,
            "effect.run_started",
            json!({"effect_id": "send", "run_id": "run_send"}),
        ),
        event_view(
            5,
            "effect.terminal",
            json!({
                "effect_id": "send",
                "run_id": "run_send",
                "status": "completed"
            }),
        ),
    ];

    let records = reconstruct_trace_records(&events);

    assert_eq!(records.len(), 9);
    check_trace(&records).expect("reconstructed trace conforms");
    check_local_trace(&events, &records).expect("local trace conforms");
}

#[test]
fn reconstructs_and_conforms_capacity_block_then_claim() {
    // A capacity-contended effect: blocked, then claimed straight from blocked.
    // This is the store-event shape `whip trace --check` reconstructs for a
    // `capacity 1` agent's second turn; it must conform.
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "turn", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            2,
            "effect.blocked",
            json!({
                "effect_id": "turn",
                "status": "blocked_by_capacity",
                "reason": "agent capacity exhausted"
            }),
        ),
        event_view(
            3,
            "effect.run_started",
            json!({"effect_id": "turn", "run_id": "run_turn"}),
        ),
        event_view(
            4,
            "effect.terminal",
            json!({"effect_id": "turn", "run_id": "run_turn", "status": "completed"}),
        ),
    ];

    let records = reconstruct_trace_records(&events);
    check_trace(&records).expect("capacity-block-then-claim trace conforms");
    check_local_trace(&events, &records).expect("local trace conforms");
}

#[test]
fn reconstructs_and_conforms_retry_then_reclaim() {
    // A failed effect re-queued by `whip retry` (effect.retried) and re-run under
    // a fresh run id. This is the store-event shape `whip trace --check`
    // reconstructs after an operator retry; it must conform.
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "turn", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "turn", "run_id": "run_turn_1"}),
        ),
        event_view(
            3,
            "effect.terminal",
            json!({"effect_id": "turn", "run_id": "run_turn_1", "status": "failed"}),
        ),
        event_view(4, "effect.retried", json!({"effect_id": "turn"})),
        event_view(
            5,
            "effect.run_started",
            json!({"effect_id": "turn", "run_id": "run_turn_2"}),
        ),
        event_view(
            6,
            "effect.terminal",
            json!({"effect_id": "turn", "run_id": "run_turn_2", "status": "completed"}),
        ),
    ];

    let records = reconstruct_trace_records(&events);
    check_trace(&records).expect("retry-then-reclaim trace conforms");
    check_local_trace(&events, &records).expect("local trace conforms");
}

#[test]
fn local_trace_conformance_rejects_store_event_sequence_gap() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "prepare", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            3,
            "effect.run_started",
            json!({"effect_id": "prepare", "run_id": "run_prepare"}),
        ),
    ];
    let records = reconstruct_trace_records(&events);

    check_trace(&records).expect("abstract trace alone masks raw event sequence gaps");
    let violation = check_local_trace(&events, &records).expect_err("store event gap should fail");

    assert_eq!(violation.sequence, 3);
    assert!(violation.message.contains("store event sequence gap"));
}

#[test]
fn local_trace_conformance_rejects_reconstructed_bad_dependency_block() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [
                    {"effect_id": "prepare", "status": "queued"},
                    {"effect_id": "send", "status": "queued"}
                ],
                "dependencies": [
                    {
                        "dependency_id": "dep_1",
                        "upstream_effect_id": "prepare",
                        "downstream_effect_id": "send",
                        "predicate": "fails"
                    }
                ]
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "prepare", "run_id": "run_prepare"}),
        ),
        event_view(
            3,
            "effect.terminal",
            json!({
                "effect_id": "prepare",
                "run_id": "run_prepare",
                "status": "failed"
            }),
        ),
        event_view(
            4,
            "effect.blocked",
            json!({
                "effect_id": "send",
                "status": "blocked_by_dependency",
                "reason": "effect dependencies are not satisfied"
            }),
        ),
    ];
    let records = reconstruct_trace_records(&events);

    let violation = check_local_trace(&events, &records)
        .expect_err("satisfied failure dependency block should fail");

    assert_eq!(violation.sequence, 7);
    assert!(violation
        .message
        .contains("without an unsatisfied dependency"));
}

#[test]
fn reconstructs_revision_trace_records_from_store_events() {
    let events = vec![
        event_view(
            1,
            "rule.committed",
            json!({
                "rule": "dispatch",
                "facts": [],
                "effects": [{"effect_id": "running", "status": "queued"}],
                "dependencies": []
            }),
        ),
        event_view(
            2,
            "effect.run_started",
            json!({"effect_id": "running", "run_id": "run_running"}),
        ),
        event_view(
            3,
            "workflow.revision_activated",
            json!({
                "revision_id": "rev_1",
                "instance_id": "ins_1",
                "from_version_id": "ver_old",
                "to_version_id": "ver_new",
                "from_epoch": 0,
                "to_epoch": 1,
                "activation_policy": {},
                "cancellation_policy": "request_running",
                "terminal_cancel_effects": [],
                "request_cancel_effects": ["running"]
            }),
        ),
        event_view(
            4,
            "effect.cancellation_requested",
            json!({
                "request_id": "ecr_1",
                "effect_id": "running",
                "revision_id": "rev_1",
                "reason": "workflow revision",
                "requested_by": "workflow.revision"
            }),
        ),
        event_view(
            5,
            "effect.terminal",
            json!({
                "effect_id": "running",
                "run_id": "run_running",
                "status": "completed"
            }),
        ),
    ];

    let records = reconstruct_trace_records(&events);

    assert_eq!(records.len(), 6);
    check_trace(&records).expect("revision trace conforms");
    match &records[3].event {
        TraceEvent::RevisionActivated {
            revision_id,
            to_epoch,
            request_cancel_effects,
            ..
        } => {
            assert_eq!(revision_id, "rev_1");
            assert_eq!(*to_epoch, 1);
            assert_eq!(request_cancel_effects, &vec!["running".to_owned()]);
        }
        event => panic!("expected revision activation record, got {event:?}"),
    }

    let rendered = trace_record_to_json(&records[4]);
    let event = rendered.get("event").expect("event");
    assert_eq!(
        event.get("type").and_then(Value::as_str),
        Some("effect_cancellation_requested")
    );
    assert_eq!(
        event.get("requested_by").and_then(Value::as_str),
        Some("workflow.revision")
    );
}

#[test]
fn renders_revision_log_event_details() {
    let event = event_view(
        1,
        "workflow.revision_activated",
        json!({
            "revision_id": "rev_1",
            "from_version_id": "ver_old",
            "to_version_id": "ver_new",
            "from_epoch": 0,
            "to_epoch": 1,
            "cancellation_policy": "request_running",
            "terminal_cancel_effects": ["queued"],
            "request_cancel_effects": ["running"]
        }),
    );

    assert_eq!(
            log_event_details(&event).as_deref(),
            Some(
                "revision=rev_1 epoch=0->1 from=ver_old to=ver_new cancel=request_running terminal_cancel=1 request_cancel=1"
            )
        );
}

#[test]
fn renders_cancellation_request_log_event_details() {
    let event = event_view(
        2,
        "effect.cancellation_requested",
        json!({
            "request_id": "ecr_1",
            "effect_id": "running",
            "revision_id": "rev_1",
            "reason": "workflow revision",
            "requested_by": "workflow.revision"
        }),
    );

    assert_eq!(
        log_event_details(&event).as_deref(),
        Some("effect=running revision=rev_1 by=workflow.revision reason=workflow revision")
    );
}

#[test]
fn renders_run_cancellation_request_json() {
    let run = RunView {
        run_id: "run-1".to_owned(),
        effect_id: "effect-1".to_owned(),
        provider: "fixture".to_owned(),
        worker_id: "worker-1".to_owned(),
        status: "running".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        completed_at: None,
        metadata_json: "{}".to_owned(),
        cancel_requested: true,
    };

    let rendered = run_to_json(&run);
    assert_eq!(
        rendered.get("cancel_requested").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/provider_id")
            .and_then(Value::as_str),
        Some("fixture")
    );
}

#[test]
fn renders_run_provider_selection_metadata_json() {
    let run = RunView {
        run_id: "run-1".to_owned(),
        effect_id: "effect-1".to_owned(),
        provider: "runner".to_owned(),
        worker_id: "worker-1".to_owned(),
        status: "running".to_owned(),
        started_at: "2026-01-01T00:00:00Z".to_owned(),
        completed_at: None,
        metadata_json: json!({
            "provider_selection": {
                "provider_id": "runner",
                "provider_kind": "command",
                "source_harness_id": "runner",
                "surface": "command"
            }
        })
        .to_string(),
        cancel_requested: false,
    };

    let rendered = run_to_json(&run);
    assert_eq!(
        rendered
            .pointer("/provider_selection/provider_kind")
            .and_then(Value::as_str),
        Some("command")
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/source_harness_id")
            .and_then(Value::as_str),
        Some("runner")
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/surface")
            .and_then(Value::as_str),
        Some("command")
    );
}

#[test]
fn renders_effect_harness_provider_selection_json() {
    let effect = EffectView {
        effect_id: "eff-1".to_owned(),
        kind: "agent.tell".to_owned(),
        target: Some("implementer".to_owned()),
        input_json: r#"{"prompt":"go"}"#.to_owned(),
        status: "queued".to_owned(),
        created_by_rule: "start".to_owned(),
        program_version_id: Some("version-1".to_owned()),
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

    let rendered = effect_to_json(&effect);

    assert_eq!(
        rendered
            .pointer("/provider_selection/source_harness_id")
            .and_then(Value::as_str),
        Some("coder")
    );
    assert_eq!(
        rendered
            .pointer("/provider_selection/provider_kind")
            .and_then(Value::as_str),
        Some("codex")
    );
}

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
    SqliteStore::open(&store_path)
        .expect("reopen store for commit")
        .commit_rule(RuleCommit {
            instance_id: &parent_instance_id,
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
        instance_id: parent_instance_id.clone(),
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
    SqliteStore::open(&store_path)
        .expect("reopen store for commit")
        .commit_rule(RuleCommit {
            instance_id: &parent_instance_id,
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
        instance_id: parent_instance_id.clone(),
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
    SqliteStore::open(&store_path)
        .expect("reopen store for commit")
        .commit_rule(RuleCommit {
            instance_id: &parent_instance_id,
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
        instance_id: parent_instance_id.clone(),
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

/// A unique temp path whose containing directory is removed when the
/// binding drops, panic included.
///
/// The directory is the unit rather than the file: a `.sqlite` path handed
/// to the store grows `-shm`/`-wal` sidecars, which owning only the file
/// would leave behind. `Deref`/`AsRef` keep the 25 call sites unchanged.
/// Bind it — never use it inline, which would drop the directory at the
/// end of the statement.
struct TempPath {
    dir: PathBuf,
    path: PathBuf,
}

impl std::ops::Deref for TempPath {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for TempPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<std::ffi::OsStr> for TempPath {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.path.as_os_str()
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn unique_test_path(label: &str, ext: &str) -> TempPath {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = env::temp_dir().join(format!(
        "whipplescript-{label}-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create unique test dir");
    let path = dir.join(format!("subject.{ext}"));
    TempPath { dir, path }
}

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

fn create_runtime_identity_instance(
    store: &mut SqliteStore,
    workflow: &str,
    principal: &str,
) -> String {
    let version = store
        .create_program_version(whipplescript_store::NewProgramVersion {
            program_name: workflow,
            source_hash: &format!("{workflow}-source"),
            ir_hash: &format!("{workflow}-ir"),
            compiler_version: "test",
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
        .expect("program version");
    store
        .create_instance_with_authority(
            whipplescript_store::NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            },
            NewInstanceAuthority {
                workflow_principal: principal,
                effective_authority_json: "[]",
            },
        )
        .expect("instance")
        .instance_id
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
        .register_package_manifest(include_str!("../../vendored-std/manifests/ingress.json"))
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

fn revision_generated_checks_source() -> &'static str {
    r#"
workflow RevisionGeneratedChecks

class Task {
  title string
}

class Classification {
  summary string
}

coerce classify(title string) -> Classification {
  prompt "Classify"
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule classify
  when Task as task
=> {
  coerce classify(task.title) as classification

  after classification completes {
    tell worker "summarize" as notify
  }
}
"#
}

#[test]
fn generates_model_searches_for_effect_dependencies() {
    let source = include_str!("../../../../examples/queue-worker-with-review.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("example compiles");
    let (_maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert_eq!(expected.len(), 15);
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.outcome == ExpectedSearchResult::Solution)
            .count(),
        5
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "succeeds")
            .count(),
        9
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "fails")
            .count(),
        3
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "revision-active-rule")
            .count(),
        1
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "revision-stale-rule")
            .count(),
        1
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "revision-effect-attribution")
            .count(),
        1
    );
}

#[test]
fn generates_revision_model_searches_for_effects_and_completes_dependencies() {
    let source = revision_generated_checks_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("scopedRuleV("));
    assert!(maude.contains("activeRevision("));
    assert!(maude.contains("effectVersion("));
    assert!(maude.contains("revisionCancellationPolicy("));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-active-rule"
            && result.outcome == ExpectedSearchResult::Solution
    }));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-stale-rule"
            && result.outcome == ExpectedSearchResult::NoSolution
    }));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-effect-attribution"
            && result.outcome == ExpectedSearchResult::NoSolution
    }));
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-completes-cancelled"
            && result.outcome == ExpectedSearchResult::Solution
    }));
}

#[test]
fn generated_ne_false_case_compares_left_and_right_operands() {
    let left = Expr::Literal(ExprLiteral::String("left".to_owned()));
    let right = Expr::Literal(ExprLiteral::String("right".to_owned()));
    let left_key = left.to_snapshot();
    let right_key = right.to_snapshot();
    let expr = Expr::Binary {
        op: BinaryOp::Ne,
        left: Box::new(left),
        right: Box::new(right),
    };
    let mut context = MaudeExprContext::default();

    let cases = maude_bool_cases(&expr, &mut context);

    let left_symbol = context
        .scalar_symbols
        .get(&left_key)
        .expect("left symbol exists");
    let right_symbol = context
        .scalar_symbols
        .get(&right_key)
        .expect("right symbol exists");
    assert_ne!(left_symbol, right_symbol);
    assert_eq!(
        cases.false_expr,
        format!("neExpr(scalar({left_symbol}), scalar({right_symbol}))")
    );
}

#[test]
fn generates_model_searches_for_guards_and_assertions() {
    let source = r#"
workflow GeneratedChecks

class Task {
  priority int
  status string
  labels string[]
  metadata map<string>
}

class Result {
  status string
  metadata map<string>
}

assert count(Result) == 0
assert count(Result) == 0
assert count(Result where status == "accepted") >= 0
assert count(Result where status not in ["accepted", "queued"]) == 0
assert "urgent" in ["urgent", "later"]

rule accept
  when Task as task where task.status == "queued" && task.priority >= 1 && "urgent" in task.labels && task.metadata["phase"] == "kernel" && count(Result where metadata["phase"] == "done") == 0
=> {
  record Result {
    status "accepted"
    metadata { phase task.metadata["phase"] }
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert_eq!(expected.len(), 19);
    assert!(maude.contains("guardExpr("));
    assert!(maude.contains("assertionExpr("));
    assert!(maude.contains("andExpr("));
    assert!(maude.contains("eqExpr("));
    assert!(maude.contains("geExpr("));
    assert!(maude.contains("inExpr("));
    assert!(maude.contains("indexExpr("));
    assert!(maude.contains("arrayHas("));
    assert!(maude.contains("mapHas("));
    assert!(maude.contains("queryFilter("));
    assert!(maude.contains("countExpr(query("));
    assert!(expected.iter().any(|result| {
        result.description == "accept true guard commits rule"
            && result.outcome == ExpectedSearchResult::Solution
    }));
    assert!(expected.iter().any(|result| {
        result.description == "accept false guard cannot commit rule"
            && result.outcome == ExpectedSearchResult::NoSolution
    }));
    assert!(expected.iter().any(|result| {
        result.description == "accept guard error emits diagnostic"
            && result.outcome == ExpectedSearchResult::Solution
    }));
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "assertion-read-only"
                && result.outcome == ExpectedSearchResult::NoSolution)
            .count(),
        15
    );
}

#[test]
fn generates_model_searches_for_terminal_branches() {
    let source = include_str!("../../../../examples/terminal-output-union.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("example compiles");
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("terminalBranch("));
    assert!(maude.contains("exhaustiveTerminal("));
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-branch-match")
            .count(),
        4
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-branch-miss")
            .count(),
        4
    );
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-exhaustive-miss")
            .count(),
        4
    );
}

#[test]
fn generates_model_searches_for_guarded_terminal_branch_misses() {
    let source = include_str!("../../../../examples/terminal-output-union.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let mut ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let branch = ir.rules[0]
        .metadata
        .terminal_branches
        .first_mut()
        .expect("terminal branch");
    branch.guard = Some(whipplescript_parser::IrExpression {
        source: "true".to_owned(),
        expr: parse_expression("true").expect("guard parses"),
        span: branch.pattern_span,
    });
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("terminalBranchGuard("));
    assert_eq!(
        expected
            .iter()
            .filter(|result| result.predicate == "terminal-branch-guard-false")
            .count(),
        1
    );
}

#[test]
fn generated_model_search_detects_unsafe_dependency_release_fixture() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = include_str!("../../../../examples/queue-worker-with-review.whip");
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("example compiles");
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let module_end = maude
        .find("endm\n\n")
        .expect("generated module has an end marker");
    let unsafe_rule = concat!(
        "  vars U D : EffectId .\n",
        "  rl [unsafe-generated-fixture-release] :\n",
        "    effect(U, queued) dep(U, succeeds, D) effect(D, blocked)\n",
        "    => effect(U, queued) dep(U, succeeds, D) effect(D, queued) .\n",
    );
    let unsafe_maude = format!(
        "{}{}{}",
        &maude[..module_end],
        unsafe_rule,
        &maude[module_end..]
    );

    let output = run_maude_source("unsafe-generated-check-fixture", &unsafe_maude)
        .expect("unsafe generated Maude fixture runs");
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(actual.len(), expected.len(), "{}", output.stdout);
    assert!(
        expected
            .iter()
            .zip(actual.iter())
            .any(|(expected, actual)| {
                expected.description.contains("cannot run before")
                    && expected.outcome == ExpectedSearchResult::NoSolution
                    && *actual == ExpectedSearchResult::Solution
            }),
        "unsafe fixture did not produce a generated-check counterexample\n{}",
        output.stdout
    );
}

#[test]
fn generated_model_search_runs_lowered_expression_fixture() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = r#"
workflow GeneratedExpressionChecks

class Task {
  status string
}

class Result {
  status string
}

assert count(Result) == 0
assert count(Result) == 0

rule accept
  when Task as task where task.status == "queued" && count(Result) == 0
=> {
  record Result {
    status "accepted"
  }
}
"#;
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("source compiles");
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let output = run_maude_source("generated-expression-check-fixture", &maude)
        .expect("generated expression Maude fixture runs");
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

#[test]
fn generated_model_search_runs_revision_fixture() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = revision_generated_checks_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(expected.iter().any(|result| {
        result.predicate == "revision-completes-cancelled"
            && result.outcome == ExpectedSearchResult::Solution
    }));

    let output = run_maude_source("generated-revision-check-fixture", &maude).expect("runs Maude");
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

fn composition_invoke_source() -> &'static str {
    // Block-form parent/child: exercises workflow completion + failure
    // (declared output/failure contracts) and workflow invocation. Patterns
    // cannot appear in block-form workflow bodies, so pattern elaboration is
    // covered by `composition_pattern_source` instead.
    r#"
workflow CompositionModelCheck {
  input request ReviewRequest
  output result ReviewSummary
  failure error ReviewFailure

  class ReviewRequest {
    id string
    title string
  }

  class ReviewSummary {
    reviewed int
  }

  class ReviewFailure {
    reason string
  }

  class ChildTask {
    title string
  }

  rule dispatch
    when ReviewRequest as request
  => {
    invoke ChildReviewWorkflow { task { title request.title } } as child

    after child succeeds as childResult {
      done request

      complete result {
        reviewed 1
      }
    }

    after child fails as childFailure {
      done request

      fail error {
        reason childFailure.reason
      }
    }
  }
}

workflow ChildReviewWorkflow {
  input task ChildTask
  output result ChildResult

  class ChildTask {
    title string
  }

  class ChildResult {
    summary string
  }

  rule do_work
    when ChildTask as task
  => {
    complete result {
      summary task.title
    }
  }
}
"#
}

fn composition_pattern_source() -> &'static str {
    // Flat-form program: exercises pattern elaboration (`apply`) alongside a
    // declared output contract (`complete result`).
    r#"
workflow CompositionPatternCheck

output result ReviewSummary

class ReviewRequest {
  id string
  title string
  status "queued"
}

class ReviewedItem {
  id string
  summary string
  status "reviewed"
}

class ReviewSummary {
  reviewed int
}

agent reviewer {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table requests as ReviewRequest [
  {
    id "R-1"
    title "Tune retries"
    status "queued"
  }
]

pattern AgentReview<Input, Output> {
  rule review
    when Input as item
    when reviewer is available
  => {
    tell reviewer as turn """markdown
    Review {{ item.title }}.
    """

    after turn succeeds as reviewed {
      done item -> record Output {
        id item.id
        summary reviewed.summary
        status "reviewed"
      }
    }
  }
}

apply AgentReview<ReviewRequest, ReviewedItem> as itemReview {
}

rule finish_batch
  when ReviewedItem as reviewed where reviewed.status == "reviewed"
=> {
  complete result {
    reviewed 1
  }
}
"#
}

#[test]
fn generates_composition_model_searches_from_ir() {
    let source = composition_invoke_source();
    let compiled =
        whipplescript_parser::compile_program_with_root(source, Some("CompositionModelCheck"));
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    // Workflow completion + failure kernel rules are driven by the declared
    // output/failure contracts.
    assert!(maude.contains("completeWorkflow("));
    assert!(maude.contains("event(workflowCompletedEvt)"));
    assert!(maude.contains("failWorkflow("));
    assert!(maude.contains("event(workflowFailedEvt)"));
    // Workflow invocation kernel rules are driven by the `workflow.invoke`
    // effect.
    assert!(maude.contains("invokeWorkflow("));
    assert!(maude.contains("invocationOutput("));
    assert!(maude.contains("invocationFailure("));

    for predicate in [
        "workflow-complete",
        "workflow-fail",
        "invoke-starts-child",
        "invoke-completes",
        "invoke-fails",
    ] {
        assert!(
            expected.iter().any(|search| {
                search.predicate == predicate && search.outcome == ExpectedSearchResult::Solution
            }),
            "missing solution search for {predicate}"
        );
    }
    for predicate in [
        "workflow-complete-requires-action",
        "workflow-fail-requires-action",
        "invoke-blocks-until-terminal",
    ] {
        assert!(
            expected.iter().any(|search| {
                search.predicate == predicate && search.outcome == ExpectedSearchResult::NoSolution
            }),
            "missing no-solution search for {predicate}"
        );
    }
}

#[test]
fn generates_pattern_elaboration_model_searches_from_ir() {
    let source = composition_pattern_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) =
        generate_maude_model_search(source, &ir, Path::new("/tmp/kernel.maude"));

    assert!(maude.contains("patternApp("));
    assert!(maude.contains("ruleProvenance("));
    assert!(expected.iter().any(|search| {
        search.predicate == "pattern-elaborates" && search.outcome == ExpectedSearchResult::Solution
    }));
    assert!(expected.iter().any(|search| {
        search.predicate == "pattern-provenance-requires-elaboration"
            && search.outcome == ExpectedSearchResult::NoSolution
    }));
}

#[test]
fn generated_composition_model_search_runs_clean_in_maude() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = composition_invoke_source();
    let compiled =
        whipplescript_parser::compile_program_with_root(source, Some("CompositionModelCheck"));
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let output = run_maude_source("generated-composition-check-fixture", &maude)
        .expect("generated composition Maude fixture runs");
    assert!(
        output.stderr.is_empty(),
        "generated composition Maude emitted warnings:\n{}",
        output.stderr
    );
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

#[test]
fn generated_pattern_model_search_runs_clean_in_maude() {
    if find_executable_in_path(&["maude"], &path_value()).is_none() {
        return;
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let kernel_path =
        fs::canonicalize(root.join("models/maude/kernel.maude")).expect("kernel path resolves");
    let source = composition_pattern_source();
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled
        .ir
        .unwrap_or_else(|| panic!("source compiles: {:?}", compiled.diagnostics));
    let (maude, expected) = generate_maude_model_search(source, &ir, &kernel_path);
    assert!(!expected.is_empty());

    let output = run_maude_source("generated-pattern-check-fixture", &maude)
        .expect("generated pattern Maude fixture runs");
    assert!(
        output.stderr.is_empty(),
        "generated pattern Maude emitted warnings:\n{}",
        output.stderr
    );
    let actual = extract_maude_search_results(&output.stdout);
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|expected| expected.outcome)
            .collect::<Vec<_>>(),
        "{}",
        output.stdout
    );
}

#[test]
fn extracts_maude_search_results_in_order() {
    let output = concat!(
        "search 1\nNo solution.\n",
        "search 2\nSolution 1 (state 1)\n",
        "search 3\nNo solution.\n",
    );

    assert_eq!(
        extract_maude_search_results(output),
        vec![
            ExpectedSearchResult::NoSolution,
            ExpectedSearchResult::Solution,
            ExpectedSearchResult::NoSolution,
        ]
    );
}

#[test]
fn locates_dependency_source_span() {
    let source =
        "rule work {\n  after prepare succeeds {\n    agent.tell \"send\" as notify\n  }\n}\n";
    let span = dependency_source_span(source, "prepare", "succeeds");

    assert_eq!(&source[span.start..span.end], "after prepare succeeds");
}

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

fn event_view(sequence: i64, event_type: &str, payload: Value) -> EventView {
    EventView {
        event_id: format!("evt_{sequence}"),
        sequence,
        event_type: event_type.to_owned(),
        payload_json: payload.to_string(),
        source: "kernel".to_owned(),
        occurred_at: "2026-01-01T00:00:00Z".to_owned(),
    }
}
