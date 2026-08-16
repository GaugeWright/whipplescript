//! Extracted verbatim from `main.rs` (module path `tests` is unchanged).

use super::*;
// `NewEffect`/`IrRedaction` are exercised only by tests here (their production
// users — the lowering `as_*` converters and the rule-lowering closure — moved
// to `whipplescript_kernel::lowering` / `::rule_lowering`).
use whipplescript_parser::IrRedaction;
// `RuleCommit` is exercised only by tests here (production commits moved to
// `whipplescript_kernel::rule_pass::step_instance_generic`).
use whipplescript_store::{NewEffect, RuleCommit};

// Test bodies live in sibling files; this module keeps the shared fixtures
// they are written against.
#[path = "tests/authority.rs"]
mod authority;
#[path = "tests/cli_surface.rs"]
mod cli_surface;
#[path = "tests/construct_graph.rs"]
mod construct_graph;
#[path = "tests/exec_and_deploy.rs"]
mod exec_and_deploy;
#[path = "tests/lowered_ir.rs"]
mod lowered_ir;
#[path = "tests/lowering_semantics.rs"]
mod lowering_semantics;
#[path = "tests/model_search.rs"]
mod model_search;
#[path = "tests/packages.rs"]
mod packages;
#[path = "tests/provider_and_doctor.rs"]
mod provider_and_doctor;
#[path = "tests/std_manifests.rs"]
mod std_manifests;
#[path = "tests/trace_and_log.rs"]
mod trace_and_log;
#[path = "tests/verify_report.rs"]
mod verify_report;

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

fn time_of_day(hour: u8, minute: u8) -> TimeOfDay {
    TimeOfDay {
        hour,
        minute,
        span: SourceSpan { start: 0, end: 0 },
    }
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
