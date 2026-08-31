//! The embedded std grammar/manifest set and its agreement with parser-compiled data.
//!
//! Split out of `main_tests/tests.rs`; `use super::*` keeps the shared
//! fixtures and the crate-root imports in scope.

use super::*;
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
        serde_json::from_str(include_str!("../../../vendored-std/manifests/coord.json"))
            .expect("valid json");
    let grammar: Value =
        serde_json::from_str(include_str!("../../../../../std/grammars/coord.json"))
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
        serde_json::from_str(include_str!("../../../vendored-std/manifests/files.json"))
            .expect("valid json");
    let grammar: Value =
        serde_json::from_str(include_str!("../../../../../std/grammars/files.json"))
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
        serde_json::from_str(include_str!("../../../vendored-std/manifests/tracker.json"))
            .expect("valid json");
    let grammar: Value =
        serde_json::from_str(include_str!("../../../../../std/grammars/tracker.json"))
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

/// The agent-provider kinds are a CLOSED vocabulary, and one of the two places
/// that fact is written down lives in another crate.
///
/// `construct.unknown_provider_kind` names a candidate through
/// `suggest_then_keyword`, so the kind set is a closed vocabulary in the sense
/// `Vocabulary::Language` means, and
/// `whipplescript-parser`'s `closed_vocabularies_do_not_suggest_for_common_english`
/// sweeps every such vocabulary against 184 ordinary English words to prove none
/// of them produces a confident suggestion of an unrelated word. That sweep lives
/// in the parser and cannot call this function, so it carries the list as a
/// literal. THIS test is what stops the two drifting: add a provider kind to a
/// manifest without adding it there and the sweep silently stops covering it.
#[test]
fn agent_provider_kinds_match_the_parser_sweep_mirror() {
    // The full set with every adapter feature compiled in, which is what the
    // parser's mirror lists. Under a reduced feature set the mirror is a
    // superset, which costs the sweep nothing.
    // The parser's own list, not a third hand-written copy. Comparing the real
    // set against a local array would have compared two hand-written arrays and
    // stayed green while the sweep stopped covering a kind.
    let mirror = whipplescript_parser::SWEPT_AGENT_PROVIDER_KINDS;
    let kinds = known_agent_provider_kinds(None);
    for kind in kinds.keys() {
        assert!(
            mirror.contains(&kind.as_str()),
            "provider kind `{kind}` is contributed by an embedded manifest but is \
             missing from the mirror in whipplescript-parser's \
             `closed_vocabularies()`, so the English sweep does not cover it"
        );
    }
    #[cfg(all(feature = "codex", feature = "claude"))]
    assert_eq!(
        kinds.keys().map(String::as_str).collect::<Vec<_>>(),
        mirror,
        "the mirror in whipplescript-parser's `closed_vocabularies()` must be \
         exactly the embedded kind set"
    );
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
    let migration =
        include_str!("../../../../whipplescript-store/migrations/0001_runtime_store.sql");
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
