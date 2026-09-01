//! CLI option parsing, diagnostics rendering, and the guards on the outer command surface.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
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
    // DR-0084 O1: the receipt carries the staleness-delta advisory (empty
    // here — no anchored evidence in this fixture — but always present on
    // an applied proposal).
    assert!(value["staleness"].is_array(), "{value}");
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

/// DR-0084 K2: the anchor door refuses change-set atoms — and the refusal
/// has TEETH: were it removed, the anchor would be recorded, so the
/// empty-anchors assertion fails without it.
#[test]
fn anchor_door_refuses_change_set_atoms() {
    let _guard = crate::env_lock();
    let root = std::env::temp_dir().join(format!(
        "whip-anchor-refusal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
    ));
    std::fs::create_dir_all(&root).expect("mkdir");
    let previous = std::env::var_os("WHIPPLESCRIPT_ITEMS_STORE");
    std::env::set_var("WHIPPLESCRIPT_ITEMS_STORE", root.join("items.sqlite"));

    let mut store =
        whipplescript_store::items::WorkItemStore::open(items_store_path()).expect("items");
    let issue = store
        .file_item("q", "anchored", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    let options = CliOptions {
        command: Some("issue".to_owned()),
        args: vec![
            "anchor".to_owned(),
            issue.id.clone(),
            "path(src/**) & since(t1)".to_owned(),
        ],
        store_path: root.join("store.sqlite"),
        json: false,
        input_json: None,
    };
    let code = knowledge_subject_verbs(&mut store, &options, "usage");
    assert_eq!(code, std::process::ExitCode::from(2));
    assert!(
        store.anchors(&issue.id).expect("anchors").is_empty(),
        "the change-set anchor must be refused, not recorded"
    );
    // The refusal's TEXT is the contract the door speaks; pin it (this is
    // what the mutation sweep's message-mutation fallback measures).
    let error = validated_region("path(src/**) & since(t1)").expect_err("refused");
    assert!(
        error.contains("may not appear in an anchor/basis"),
        "{error}"
    );
    assert!(error.contains("`since`"), "{error}");
    // And the guard's OTHER side has teeth too: a world-denoting region
    // passes the same door and IS recorded (a falsified guard that refuses
    // everything fails here).
    assert!(validated_region("path(src/**) | decl(rule *)").is_ok());
    let ok_options = CliOptions {
        command: Some("issue".to_owned()),
        args: vec![
            "anchor".to_owned(),
            issue.id.clone(),
            "path(src/**) | decl(rule *)".to_owned(),
        ],
        store_path: root.join("store.sqlite"),
        json: false,
        input_json: None,
    };
    let code = knowledge_subject_verbs(&mut store, &ok_options, "usage");
    assert_eq!(code, std::process::ExitCode::SUCCESS);
    assert_eq!(store.anchors(&issue.id).expect("anchors").len(), 1);

    match previous {
        Some(value) => std::env::set_var("WHIPPLESCRIPT_ITEMS_STORE", value),
        None => std::env::remove_var("WHIPPLESCRIPT_ITEMS_STORE"),
    }
    std::fs::remove_dir_all(&root).ok();
}

/// DR-0086 F3: the effect door's finish auto-attest, at the kernel level —
/// the same generic fn the tracker.finish handler calls. A claimed issue
/// with a subject anchor mints KEYED cut-trail evidence against the
/// facade's frontier (real canonicalizer entries); an unclaimed issue
/// mints nothing.
#[test]
fn kernel_finish_auto_attests_keyed_on_the_native_facade() {
    use whipplescript_store::items::WorkItems;
    let _guard = crate::env_lock();
    let root = std::env::temp_dir().join(format!(
        "whip-f3-native-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
    ));
    std::fs::create_dir_all(&root).expect("mkdir");

    let mut vcs = whipplescript_store::vcs::WorkspaceVcs::open(
        root.join("branches.sqlite"),
        root.join("content.sqlite"),
    )
    .expect("vcs");
    vcs.set_decl_canonicalizer(Box::new(
        whipplescript_kernel::source_merge::WhipDeclCanonicalizer,
    ));
    vcs.init("t0").expect("init");
    vcs.write(
        whipplescript_store::branches::MAINLINE_BRANCH_ID,
        "src/close.whip",
        Some("workflow K\noutput result R\nclass R { ok bool }\nrule close\n  when started\n=> { complete result { ok true } }\n"),
        "cut_f3",
        "t1",
    )
    .expect("write");

    let mut stores = whipplescript_store::native_stores::NativeStores::open(
        root.join("runtime.sqlite"),
        root.join("coord.sqlite"),
        root.join("items.sqlite"),
    )
    .expect("stores")
    .with_frontier(vcs);

    let claimed = stores
        .items
        .file_item("q", "worked", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    stores
        .items
        .add_anchor(&claimed.id, "decl(rule close)", "subject", Some("s:a"))
        .expect("anchor")
        .expect("known");
    stores
        .items
        .claim_item(&claimed.id, "ins-f3", None)
        .expect("claim");
    let unclaimed = stores
        .items
        .file_item("q", "untouched", "", &[], &json!({}), Some("s:a"))
        .expect("file");

    whipplescript_kernel::effect_handlers::auto_attest_finish_generic(
        &mut stores,
        &claimed.id,
        Some("ins-f3"),
    );
    whipplescript_kernel::effect_handlers::auto_attest_finish_generic(
        &mut stores,
        &unclaimed.id,
        Some("ins-f3"),
    );

    let trail = stores.items.evidence(&claimed.id).expect("evidence");
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].kind.as_deref(), Some("cuts"));
    assert!(trail[0].at_cut.is_some(), "keyed: the frontier was live");
    let fingerprint: std::collections::BTreeMap<String, String> =
        serde_json::from_str(trail[0].basis_fingerprint_json.as_deref().expect("keyed"))
            .expect("fingerprint json");
    assert!(
        fingerprint.contains_key("decl:rule close"),
        "{fingerprint:?}"
    );
    let content_id = WorkItems::subject_content_id(&stores, &claimed.id)
        .expect("content id")
        .expect("known");
    assert_eq!(
        trail[0].reference.as_deref(),
        Some(format!("intent({content_id})").as_str())
    );
    assert!(stores
        .items
        .evidence(&unclaimed.id)
        .expect("evidence")
        .is_empty());

    std::fs::remove_dir_all(&root).ok();
}

/// The agent-door claim join: the harness todo tool holds claims as
/// `agent:<instance id>` (live turns pass the instance as the holder), and
/// the intent stamp unions that spelling with the kernel door's bare
/// instance id — so turn-claimed work mints intent-stamped cuts. Two
/// claims across the doors is ambiguous and stamps nothing.
#[test]
fn agent_door_claims_stamp_cut_intent() {
    let _guard = crate::env_lock();
    let root = std::env::temp_dir().join(format!(
        "whip-claim-join-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
    ));
    std::fs::create_dir_all(&root).expect("mkdir");
    let previous: Vec<(&str, Option<std::ffi::OsString>)> = [
        "WHIPPLESCRIPT_ITEMS_STORE",
        "WHIPPLESCRIPT_BRANCH_STORE",
        "WHIPPLESCRIPT_VCS_CONTENT_STORE",
    ]
    .into_iter()
    .map(|key| (key, std::env::var_os(key)))
    .collect();
    std::env::set_var("WHIPPLESCRIPT_ITEMS_STORE", root.join("items.sqlite"));
    std::env::set_var("WHIPPLESCRIPT_BRANCH_STORE", root.join("branches.sqlite"));
    std::env::set_var(
        "WHIPPLESCRIPT_VCS_CONTENT_STORE",
        root.join("content.sqlite"),
    );

    let mut items =
        whipplescript_store::items::WorkItemStore::open(items_store_path()).expect("items");
    let issue = items
        .file_item("q", "turn work", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    // The AGENT door's holder spelling, exactly as update_todo claims.
    items
        .claim_item(&issue.id, "agent:ins-join", None)
        .expect("claim");
    let content_id = items
        .subject_content_id(&issue.id)
        .expect("content id")
        .expect("known");
    drop(items);

    let mut vcs = open_vcs().expect("vcs");
    vcs.init("t0").expect("init");
    stamp_claim_intent(&mut vcs, "ins-join");
    vcs.write(
        whipplescript_store::branches::MAINLINE_BRANCH_ID,
        "src/a.rs",
        Some("v1"),
        "cut_join_1",
        "t1",
    )
    .expect("write");
    let units = vcs
        .change_units(whipplescript_store::branches::MAINLINE_BRANCH_ID, 10)
        .expect("units");
    assert_eq!(units.len(), 1);
    assert_eq!(
        units[0].intent.as_deref(),
        Some(content_id.as_str()),
        "the todo-claimed issue's content id rides the cut"
    );

    // A second claim through the KERNEL door makes intent ambiguous:
    // a fresh handle stamps nothing.
    let mut items =
        whipplescript_store::items::WorkItemStore::open(items_store_path()).expect("items");
    let second = items
        .file_item("q", "second", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    items
        .claim_item(&second.id, "ins-join", None)
        .expect("claim");
    drop(items);
    let mut vcs = open_vcs().expect("vcs");
    stamp_claim_intent(&mut vcs, "ins-join");
    vcs.write(
        whipplescript_store::branches::MAINLINE_BRANCH_ID,
        "src/b.rs",
        Some("v1"),
        "cut_join_2",
        "t2",
    )
    .expect("write");
    let units = vcs
        .change_units(whipplescript_store::branches::MAINLINE_BRANCH_ID, 10)
        .expect("units");
    let second_cut = units
        .iter()
        .find(|unit| unit.cut_id == "cut_join_2")
        .expect("cut");
    assert_eq!(second_cut.intent, None, "two held claims stamp nothing");

    for (key, value) in previous {
        match value {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
    std::fs::remove_dir_all(&root).ok();
}

/// DR-0084 I1: finishing a subject that was worked under a claim
/// auto-attests its cut trail — `kind: "cuts"` referencing the
/// `intent(<content-id>)` selection. With no VCS frontier the evidence is
/// UNKEYED (degraded and tagged); an unclaimed finish records nothing.
#[test]
fn finish_auto_attests_the_cut_trail() {
    let _guard = crate::env_lock();
    let root = std::env::temp_dir().join(format!(
        "whip-auto-attest-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
    ));
    std::fs::create_dir_all(&root).expect("mkdir");
    let previous = std::env::var_os("WHIPPLESCRIPT_ITEMS_STORE");
    std::env::set_var("WHIPPLESCRIPT_ITEMS_STORE", root.join("items.sqlite"));

    let mut store =
        whipplescript_store::items::WorkItemStore::open(items_store_path()).expect("items");
    let claimed = store
        .file_item("q", "worked", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    let unclaimed = store
        .file_item("q", "untouched", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    store.claim_item(&claimed.id, "ins-9", None).expect("claim");
    store.finish_item(&claimed.id, None, None).expect("finish");
    auto_attest_finish(&mut store, &claimed.id, Some("ins-9"));
    auto_attest_finish(&mut store, &unclaimed.id, Some("ins-9"));

    let trail = store.evidence(&claimed.id).expect("evidence");
    assert_eq!(trail.len(), 1);
    assert_eq!(trail[0].kind.as_deref(), Some("cuts"));
    let content_id = store
        .subject_content_id(&claimed.id)
        .expect("content id")
        .expect("known");
    assert_eq!(
        trail[0].reference.as_deref(),
        Some(format!("intent({content_id})").as_str())
    );
    assert_eq!(trail[0].at_cut, None, "no frontier -> unkeyed");
    assert!(store.evidence(&unclaimed.id).expect("evidence").is_empty());

    match previous {
        Some(value) => std::env::set_var("WHIPPLESCRIPT_ITEMS_STORE", value),
        None => std::env::remove_var("WHIPPLESCRIPT_ITEMS_STORE"),
    }
    std::fs::remove_dir_all(&root).ok();
}

/// DR-0084 O1: the mediator's classification emits one edge fact per stale
/// subject — issues under their name, assertions under theirs — with the
/// mainline branch key and NO volatile fields (the edge key is the payload
/// content). Fresh and unverified subjects emit nothing.
#[test]
fn staleness_facts_classify_stale_subjects_only() {
    use std::collections::BTreeMap;
    let mut items = whipplescript_store::items::WorkItemStore::open_in_memory().expect("items");
    let stale_issue = items
        .file_item("q", "stale one", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    let fresh_issue = items
        .file_item("q", "fresh one", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    let unkeyed_issue = items
        .file_item("q", "unverified one", "", &[], &json!({}), Some("s:a"))
        .expect("file");
    let assertion = items
        .create_assertion("stale claim", "", Some("s:a"))
        .expect("assert");
    let fingerprint_stale = r#"{"decl:rule close":"old-hash"}"#;
    let fingerprint_fresh = r#"{"decl:rule close":"h1"}"#;
    items
        .attest(
            &stale_issue.id,
            Some("t"),
            None,
            None,
            Some("s:a"),
            Some("cut_1"),
            Some("decl(rule close)"),
            Some(fingerprint_stale),
        )
        .expect("attest")
        .expect("known");
    items
        .attest(
            &fresh_issue.id,
            Some("t"),
            None,
            None,
            Some("s:a"),
            Some("cut_1"),
            Some("decl(rule close)"),
            Some(fingerprint_fresh),
        )
        .expect("attest")
        .expect("known");
    items
        .add_evidence(&unkeyed_issue.id, Some("t"), None, None, Some("s:a"))
        .expect("evidence");
    items
        .attest(
            &assertion.id,
            Some("t"),
            None,
            None,
            Some("s:a"),
            Some("cut_1"),
            Some("decl(rule close)"),
            Some(fingerprint_stale),
        )
        .expect("attest")
        .expect("known");

    let frontier = whipplescript_store::freshness::FrontierContent {
        decls: BTreeMap::from([("rule close".to_owned(), "h1".to_owned())]),
        decl_renames: BTreeMap::new(),
        paths: BTreeMap::new(),
    };
    let facts = staleness_facts(&items, &(frontier, Vec::new()));
    let names: Vec<(&str, &str)> = facts
        .iter()
        .map(|(name, payload)| {
            (
                name.as_str(),
                payload.get("subject").and_then(Value::as_str).unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(
        names,
        vec![
            ("tracker.issue.stale", stale_issue.id.as_str()),
            ("tracker.assertion.stale", assertion.id.as_str()),
        ]
    );
    // The payload is edge-stable: branch key + no timestamps.
    let payload = &facts[0].1;
    assert_eq!(payload["branch"], "main");
    assert!(payload.get("at").is_none());
    assert_eq!(payload["verification"]["status"], "stale");
}

/// DR-0084: an unresolved `region(<name>)` atom reaching the selective-verb
/// provider is refused BY NAME before any store is opened — literals expand
/// at effect-input build, so only a dynamic selection naming an undeclared
/// region gets here, and "matched nothing" must never be the answer.
#[test]
fn vcs_selective_provider_refuses_unresolved_region_atoms() {
    let provider = VcsSelectiveCapabilityProvider {
        store_path: std::path::PathBuf::from("/nonexistent/store.sqlite"),
        instance_id: "ins-region".to_owned(),
    };
    let effect = ClaimableEffect {
        effect_id: "e-region".to_owned(),
        kind: "capability.call".to_owned(),
        target: Some("vcs.undo".to_owned()),
        profile: None,
        input_json: json!({ "selection": "region(ghost) & by(s:)" }).to_string(),
        required_capabilities_json: "[]".to_owned(),
        declared_profiles_json: "[]".to_owned(),
    };
    let outcome = provider.produce(&effect, &EffectConfig::default());
    let CapabilityOutcome::Failed { message, .. } = outcome else {
        panic!("expected refusal");
    };
    assert!(
        message.contains("`region(ghost)` did not resolve"),
        "{message}"
    );
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
        code: diagnostic_code!("parse.unexpected_token"),
        severity: Severity::Error,
        related: Vec::new(),
        span: SourceSpan { start: 25, end: 27 },
        message: "expected profile string, found number literal".to_owned(),
        suggestion: Some("write `profile \"profile-name\"`".to_owned()),
    };

    let expected = concat!(
        "error[parse.unexpected_token]: expected profile string, found number literal\n",
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
fn a_span_inside_a_character_degrades_instead_of_panicking() {
    // Spans are byte offsets and not every producer's arithmetic lands on a
    // character boundary. The producer that first showed this — a whole-program
    // check re-parsing a rule body at base `0`, so its offsets were essentially
    // arbitrary positions in the file — now carries the body's origin (tracker
    // D2c), but the rendering hazard is not the producer's to own: rendering
    // used to slice `line_text` by raw offsets and panic outright, and a
    // diagnostic that crashes the compiler is the worst possible diagnostic.
    // Every multi-byte width has to survive, so this walks EVERY interior byte
    // of a 2-, 3-, and 4-byte character and both ends of the span.
    for filler in ["é", "日", "🚀"] {
        let source = format!("# {filler}{filler}{filler} header\nworkflow Widths\n");
        let header = source.lines().next().expect("header").len();
        for start in 0..header {
            for end in start..header {
                let diagnostic = Diagnostic {
                    code: diagnostic_code!("parse.unexpected_token"),
                    severity: Severity::Error,
                    related: Vec::new(),
                    span: SourceSpan { start, end },
                    message: "boundary probe".to_owned(),
                    suggestion: None,
                };
                let rendered = render_diagnostic("example.whip", &source, &diagnostic);
                assert!(
                    rendered.contains('^'),
                    "{filler} {start}..{end} rendered no caret:\n{rendered}"
                );
            }
        }
    }
}

#[test]
fn renders_a_character_column_for_a_multibyte_rule_body() {
    // Spans are byte offsets; the rendered column is a CHARACTER count. A body
    // carrying multi-byte text before the fault must render the caret under the
    // offending token, not shifted right by the extra bytes (tracker D2a).
    let source = "workflow Multibyte\noutput result Done\n\nclass Order {\n  id string\n}\n\nclass Done {\n  id string\n}\n\nrule act\n  when Order as order\n=> {\n  record Done { id \"caf\u{e9} \u{65e5}\u{672c}\u{8a9e}\" }\n  frobnicate order\n}\n";
    let compiled = whipplescript_parser::compile_program(source);
    let diagnostic = compiled
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.message.contains("`frobnicate`"))
        .expect("statement diagnostic");

    let expected = concat!(
        "error[construct.unknown_clause]: unknown rule body statement `frobnicate`\n",
        "   --> example.whip:16:3\n",
        "   |\n",
        "16 |   frobnicate order\n",
        "   |   ^^^^^^^^^^\n",
    );

    let rendered = render_diagnostic("example.whip", source, diagnostic);
    assert!(
        rendered.starts_with(expected),
        "unexpected rendering:\n{rendered}"
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
        code: diagnostic_code!("parse.unexpected_token"),
        severity: Severity::Error,
        span: SourceSpan {
            start: lib_seven,
            end: lib_seven + 1,
        },
        message: "expected profile string, found number literal".to_owned(),
        suggestion: None,
        related: Vec::new(),
    };
    let rendered = render_bundle_diagnostic("root.whip", &combined, &segments, &lib_diag);
    assert!(rendered.contains("--> lib.whip:2:11"), "{rendered}");

    // A span inside the root file resolves to root.whip using the ROOT's
    // own line numbering (line 3), not the inflated combined-text line.
    let root_forty_two =
        combined.find("profile 42").expect("profile 42 present") + "profile ".len();
    let root_diag = Diagnostic {
        code: diagnostic_code!("parse.unexpected_token"),
        severity: Severity::Error,
        span: SourceSpan {
            start: root_forty_two,
            end: root_forty_two + 2,
        },
        message: "expected profile string, found number literal".to_owned(),
        suggestion: None,
        related: Vec::new(),
    };
    let rendered = render_bundle_diagnostic("root.whip", &combined, &segments, &root_diag);
    assert!(rendered.contains("--> root.whip:3:11"), "{rendered}");
}

/// A `= note:` in a BUNDLE has to be rebased the same way the caret is.
///
/// The renderer used to rebase the primary span into the origin file's
/// coordinates and hand the related spans through untouched, so one diagnostic
/// carried a right caret and a wrong note, shifted by the length of the included
/// prefix. And a related span that belongs to a DIFFERENT file of the bundle has
/// to be resolved against THAT file: printing its line number under the primary
/// file's path is a coordinate that looks authoritative and points nowhere.
#[test]
fn a_bundle_note_is_rebased_into_the_file_it_points_at() {
    let lib = "class Widget {\n  id string\n}\n";
    let root = "workflow Root\nclass Other {\n  id string\n}\n";
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

    // Primary in the ROOT file, related in the INCLUDED one — the shape the
    // `class … is declared here` note takes whenever the class came from an
    // include.
    let primary = combined.find("class Other").expect("root class present");
    let related = combined.find("class Widget").expect("lib class present") + "class ".len();
    let diagnostic = Diagnostic {
        code: diagnostic_code!("type.unknown_field"),
        severity: Severity::Error,
        span: SourceSpan {
            start: primary,
            end: primary + "class".len(),
        },
        message: "class `Widget` has no field `nmae`".to_owned(),
        suggestion: None,
        related: vec![whipplescript_parser::RelatedInfo {
            span: SourceSpan {
                start: related,
                end: related + "Widget".len(),
            },
            message: "`Widget` is declared here".to_owned(),
        }],
    };
    let rendered = render_bundle_diagnostic("root.whip", &combined, &segments, &diagnostic);
    assert!(rendered.contains("--> root.whip:2:1"), "{rendered}");
    assert!(
        rendered.contains("= note: `Widget` is declared here (lib.whip:1:7)"),
        "the note was not resolved to the file it points at:\n{rendered}"
    );

    // Same-file notes stay same-file, and are rebased with the caret rather than
    // left in bundle coordinates.
    let same_file = combined.rfind("id string").expect("root field present");
    let diagnostic = Diagnostic {
        code: diagnostic_code!("type.unknown_field"),
        severity: Severity::Error,
        span: SourceSpan {
            start: primary,
            end: primary + "class".len(),
        },
        message: "class `Other` has no field `nmae`".to_owned(),
        suggestion: None,
        related: vec![whipplescript_parser::RelatedInfo {
            span: SourceSpan {
                start: same_file,
                end: same_file + 2,
            },
            message: "`id` is declared `string` here".to_owned(),
        }],
    };
    let rendered = render_bundle_diagnostic("root.whip", &combined, &segments, &diagnostic);
    assert!(
        rendered.contains("= note: `id` is declared `string` here (root.whip:3:3)"),
        "a same-file note was not rebased with its caret:\n{rendered}"
    );
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
        .map(|diagnostic| render_bundle_diagnostic(root_str, &source, &segments, diagnostic))
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
