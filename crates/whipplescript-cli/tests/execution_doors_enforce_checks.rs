//! An execution door enforces what the check door refuses.
//!
//! `whip check` and `whip run` compiled through different functions, and only
//! the check door ran the authority battery. So a program `whip check` rejected
//! with `security.package_import_required` -- a `file store` declaration with no
//! `use std.files` -- ran to completion under `whip run` and wrote its file. The
//! import is the program's explicit opt-in to file authority, and it was
//! optional for anyone who never typed `check`.
//!
//! Script's hard-off survived that gap: its Layer-2 seeding leaves `exec.command`
//! blocked at the store admission gate, so a forged program gets a blocked
//! effect rather than a process. The files, messaging and ingress imports have
//! no such runtime backstop, which is exactly why the check-time refusal had to
//! BE the enforcement rather than a preview of it.
//!
//! This pins the property as a difference the two doors must not have: whatever
//! `check` refuses, `run` refuses.

#[path = "support/isolated_whip.rs"]
mod isolated_whip;
use isolated_whip::whip_command;

use std::fs;
use std::path::PathBuf;

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "whip-doors-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn whip(dir: &PathBuf, args: &[&str]) -> (bool, String) {
    let output = whip_command(env!("CARGO_BIN_EXE_whip"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|error| panic!("run whip {args:?}: {error}"));
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// The shipped `examples/file-store-demo.whip`, minus its `use std.files` line
/// and pointed at a scratch root. Taken from the example rather than written by
/// hand so the program is known-good and the ONLY thing under test is the
/// missing import.
const NO_IMPORT: &str = r#"workflow FileStoreDemo

output result Saved

failure error FileError

# std.files: a `file store` is a policy boundary over a provider-backed document
# root. `write text`/`read text` are durable effects validated against the
# store's `allow write`/`allow read` globs. This example writes a note then reads
# it back, completing with the round-tripped content.
class Saved {
  content string
}

class FileError {
  reason string
}

class Wrote {
  path string
}

file store notes_store {
  root "./notes-root"
  allow read ["notes/**"]
  allow write ["notes/**"]
}

rule write_note
  when started
=> {
  write text to notes_store at "notes/hello.txt" {
    body "hello from the file store"
    mode upsert
  } as written

  after written succeeds {
    record Wrote {
      path "notes/hello.txt"
    }
  }

  after written fails as write_error {
    fail error {
      reason write_error.reason
    }
  }
}

rule read_note
  when Wrote as wrote
=> {
  read text from notes_store at "notes/hello.txt" as loaded

  after loaded succeeds as file {
    complete result {
      content file.content
    }
  }

  after loaded fails as read_error {
    fail error {
      reason read_error.reason
    }
  }
}
"#;

#[test]
fn what_check_refuses_run_and_start_refuse_too() {
    let dir = temp_dir("no-import");
    let program = dir.join("no_import.whip");
    fs::write(&program, NO_IMPORT).expect("write program");
    let path = program.to_str().expect("path");

    let (check_ok, check_out) = whip(&dir, &["check", path]);
    assert!(!check_ok, "check must refuse the program: {check_out}");
    assert!(
        check_out.contains("security.package_import_required"),
        "check refuses for the authority import: {check_out}"
    );

    // The door under test. Before this, `run` compiled past the battery and
    // completed the instance, writing the file.
    let (run_ok, run_out) = whip(&dir, &["--store", "run.db", "run", path, "--until", "idle"]);
    assert!(!run_ok, "run must refuse what check refused: {run_out}");
    assert!(
        run_out.contains("security.package_import_required"),
        "run gives the same refusal as check: {run_out}"
    );

    // The refusal has to land BEFORE the authority is exercised, not as a
    // report afterwards.
    assert!(
        !dir.join("notes-root/notes/hello.txt").exists(),
        "the file authority must not have been exercised"
    );

    let (start_ok, start_out) = whip(&dir, &["--store", "start.db", "start", path]);
    assert!(
        !start_ok,
        "start must refuse what check refused: {start_out}"
    );

    fs::remove_dir_all(&dir).ok();
}

/// The same battery must not refuse a program that declares its import: this
/// fails if the door is closed by refusing everything.
#[test]
fn a_program_that_declares_its_authority_still_runs() {
    let dir = temp_dir("with-import");
    let program = dir.join("with_import.whip");
    fs::write(&program, format!("use std.files\n\n{NO_IMPORT}")).expect("write program");
    let path = program.to_str().expect("path");

    let (check_ok, check_out) = whip(&dir, &["check", path]);
    assert!(check_ok, "the declared program checks: {check_out}");

    let (run_ok, run_out) = whip(&dir, &["--store", "run.db", "run", path, "--until", "idle"]);
    assert!(run_ok, "the declared program runs: {run_out}");
    assert!(
        dir.join("notes-root/notes/hello.txt").exists(),
        "and actually exercises the authority it declared: {run_out}"
    );

    fs::remove_dir_all(&dir).ok();
}

const SIGNAL_SOURCE: &str = r#"@service
workflow LegacyIngress
signal go.now { x string }
class Seen { x string }
rule observe when go.now as event => { record Seen { x event.x } }
"#;

/// Deliberately models the ordinary pre-hard-check publication door. It uses
/// actual raw compiler IR and ordinary public store publication/instance APIs;
/// it grants no authority, injects no facts/effects and retains exact source.
fn legacy_instance(dir: &std::path::Path, source: &str) -> String {
    use whipplescript_store::{stable_hash_hex, NewInstance, NewProgramVersion, SqliteStore};
    let compiled = whipplescript_parser::compile_program(source);
    let ir = compiled.ir.expect("real legacy raw compilation");
    let snapshot = whipplescript_parser::snapshot::identity_projection(&ir.to_snapshot());
    let mut store = SqliteStore::open(dir.join("legacy.db")).expect("own legacy store");
    let source_hash = stable_hash_hex(source);
    assert_eq!(
        store
            .put_content(source)
            .expect("retain original authored source"),
        source_hash
    );
    let ir_hash = stable_hash_hex(&snapshot);
    let version = store
        .create_program_version(NewProgramVersion {
            program_name: "LegacyIngress",
            source_hash: &source_hash,
            ir_hash: &ir_hash,
            compiler_version: "disclosed-pre-authority-check-fixture",
            ir_snapshot: Some(&snapshot),
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
        .expect("ordinary retained legacy program");
    store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("ordinary legacy instance")
        .instance_id
}

fn history(dir: &std::path::Path, instance: &str) -> Vec<whipplescript_store::EventView> {
    whipplescript_store::SqliteStore::open(dir.join("legacy.db"))
        .expect("own store")
        .list_events(instance)
        .expect("history")
}

fn stream(dir: &PathBuf, program: &str, envelopes: &str) -> std::process::Output {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = whip_command(env!("CARGO_BIN_EXE_whip"))
        .args([
            "--store",
            "legacy.db",
            "ingress",
            "serve",
            "--stdio",
            "--program",
            program,
        ])
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("actual resident driver");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(envelopes.as_bytes())
        .expect("envelopes");
    child.wait_with_output().expect("resident terminal")
}

#[test]
fn signal_and_resident_refuse_legacy_missing_authority_before_append() {
    for (package, declaration) in [
        ("ingress", ""),
        (
            "files",
            "file store notes { root \"./notes\" allow read [\"**\"] }\n",
        ),
        ("messaging", "channel updates\n"),
    ] {
        let dir = temp_dir(&format!("legacy-{package}"));
        let source = if package == "ingress" {
            SIGNAL_SOURCE.to_owned()
        } else {
            format!("use std.ingress\n{declaration}{SIGNAL_SOURCE}")
        };
        let instance = legacy_instance(&dir, &source);
        let program = dir.join("legacy.whip");
        fs::write(&program, &source).expect("source");
        let before = history(&dir, &instance);
        let args = [
            "--store",
            "legacy.db",
            "signal",
            &instance,
            "--name",
            "go.now",
            "--data",
            r#"{"x":"owned"}"#,
            "--delivery-id",
            "once",
            "--program",
            program.to_str().expect("path"),
        ];
        let (ok, diagnostic) = whip(&dir, &args);
        assert!(
            !ok && diagnostic.contains("security.package_import_required"),
            "actual signal missing {package}: {diagnostic}"
        );
        assert_eq!(history(&dir, &instance), before, "signal no append");
        let envelope = format!(
            "{}\n",
            serde_json::json!({"instance":instance,"signal":"go.now","payload":{"x":"owned"},"delivery_id":"once"})
        );
        let output = stream(&dir, program.to_str().expect("path"), &envelope);
        assert!(
            !output.status.success()
                && String::from_utf8_lossy(&output.stderr)
                    .contains("security.package_import_required"),
            "resident missing {package}: {output:?}"
        );
        assert_eq!(history(&dir, &instance), before, "resident no append");
        // HTTP shares this exact compiler gate and must refuse before binding.
        let (ok, diagnostic) = whip(
            &dir,
            &[
                "--store",
                "legacy.db",
                "ingress",
                "serve",
                "--http",
                "not-a-valid-bind",
                "--program",
                program.to_str().expect("path"),
            ],
        );
        assert!(
            !ok && diagnostic.contains("security.package_import_required"),
            "HTTP before bind: {diagnostic}"
        );
        assert_eq!(history(&dir, &instance), before);
        fs::remove_dir_all(dir).expect("own cleanup");
    }
}

#[test]
fn imported_signal_resident_replay_payload_and_source_guards_remain() {
    let dir = temp_dir("legacy-imported");
    let source = format!("use std.ingress\n{SIGNAL_SOURCE}");
    let instance = legacy_instance(&dir, &source);
    let program = dir.join("legacy.whip");
    fs::write(&program, &source).expect("source");
    let path = program.to_str().expect("path");
    let signal = [
        "--store",
        "legacy.db",
        "--json",
        "signal",
        &instance,
        "--name",
        "go.now",
        "--data",
        r#"{"x":"owned"}"#,
        "--delivery-id",
        "once",
        "--program",
        path,
    ];
    let (ok, output) = whip(&dir, &signal);
    assert!(ok, "{output}");
    let before = history(&dir, &instance);
    let (ok, output) = whip(&dir, &signal);
    assert!(ok, "{output}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).expect("json")["duplicate"],
        true
    );
    assert_eq!(history(&dir, &instance), before);
    for (name, data, diagnostic) in [
        ("go.now", r#"{"x":42}"#, "does not conform"),
        ("unknown", "{}", "not declared"),
    ] {
        let (ok, output) = whip(
            &dir,
            &[
                "--store",
                "legacy.db",
                "signal",
                &instance,
                "--name",
                name,
                "--data",
                data,
                "--program",
                path,
            ],
        );
        assert!(!ok && output.contains(diagnostic), "{output}");
        assert_eq!(history(&dir, &instance), before);
    }
    let envelopes = format!(
        "{}\n{}\nnot-json\n",
        serde_json::json!({"instance":instance,"signal":"go.now","payload":{"x":"resident"},"delivery_id":"resident"}),
        serde_json::json!({"instance":instance,"signal":"go.now","payload":{"x":"resident"},"delivery_id":"resident"})
    );
    let output = stream(&dir, path, &envelopes);
    assert!(output.status.success(), "{output:?}");
    let rows: Vec<serde_json::Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|s| serde_json::from_str(s).expect("JSON row"))
        .collect();
    assert_eq!(
        rows.iter()
            .map(|r| r["status"].as_str().expect("status"))
            .collect::<Vec<_>>(),
        ["admitted", "duplicate", "rejected"]
    );
    let before = history(&dir, &instance);
    fs::write(
        &program,
        format!("{source}\n# substituted authored source\n"),
    )
    .expect("different source");
    let (ok, output) = whip(&dir, &signal);
    assert!(!ok && output.contains("does not match"), "{output}");
    assert_eq!(history(&dir, &instance), before);
    let output = stream(&dir, path, &envelopes);
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("does not match"),
        "{output:?}"
    );
    assert_eq!(history(&dir, &instance), before);
    let store = whipplescript_store::SqliteStore::open(dir.join("legacy.db")).expect("store");
    assert!(
        store.list_effects(&instance).expect("effects").is_empty(),
        "admission does not dispatch"
    );
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn legacy_message_refuses_missing_import_and_declared_channel_still_admits() {
    for imported in [false, true] {
        let dir = temp_dir("legacy-message");
        let source = format!(
            "{}@service\nworkflow LegacyMessage\nchannel updates\n",
            if imported { "use std.messaging\n" } else { "" }
        );
        let instance = legacy_instance(&dir, &source);
        let program = dir.join("legacy.whip");
        fs::write(&program, &source).expect("source");
        let before = history(&dir, &instance);
        let (ok, output) = whip(
            &dir,
            &[
                "--store",
                "legacy.db",
                "message",
                &instance,
                "--channel",
                "updates",
                "--text",
                "owned",
                "--program",
                program.to_str().expect("path"),
            ],
        );
        if imported {
            assert!(ok, "{output}");
            assert!(history(&dir, &instance).len() > before.len());
        } else {
            assert!(
                !ok && output.contains("security.package_import_required"),
                "{output}"
            );
            assert_eq!(history(&dir, &instance), before);
        }
        fs::remove_dir_all(dir).expect("cleanup");
    }
}

#[test]
fn authority_only_execution_preserves_check_time_liveness() {
    let dir = temp_dir("shape");
    let program = dir.join("shape.whip");
    fs::write(&program, "workflow Shape\nclass Seen { x string }\nrule observe when started => { record Seen { x \"owned\" } }\n").expect("source");
    let path = program.to_str().expect("path");
    let (ok, output) = whip(&dir, &["check", path]);
    assert!(!ok, "check should keep liveness: {output}");
    let (ok, output) = whip(&dir, &["--store", "shape.db", "start", path]);
    assert!(ok, "start must retain authority-only compile: {output}");
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn every_authority_package_refuses_start_run_and_legacy_step() {
    for (package, declaration) in [
        ("ingress", "signal go.now { x string }"),
        (
            "files",
            "file store notes { root \"./notes\" allow read [\"**\"] }",
        ),
        ("messaging", "channel updates"),
    ] {
        let dir = temp_dir(&format!("execution-{package}"));
        let source = format!("@service\nworkflow Gate\n{declaration}\nclass Seen {{ x string }}\nrule go when started => {{ record Seen {{ x \"owned\" }} }}\n");
        let instance = legacy_instance(&dir, &source);
        let program = dir.join("legacy.whip");
        fs::write(&program, &source).expect("source");
        let before = history(&dir, &instance);
        for door in ["start", "run"] {
            let (ok, output) = whip(
                &dir,
                &[
                    "--store",
                    "legacy.db",
                    door,
                    program.to_str().expect("path"),
                ],
            );
            assert!(
                !ok && output.contains("security.package_import_required"),
                "{door}/{package}: {output}"
            );
            assert_eq!(history(&dir, &instance), before);
        }
        let (ok, output) = whip(
            &dir,
            &[
                "--store",
                "legacy.db",
                "step",
                &instance,
                "--program",
                program.to_str().expect("path"),
            ],
        );
        assert!(
            !ok && output.contains("security.package_import_required"),
            "step/{package}: {output}"
        );
        assert_eq!(history(&dir, &instance), before);
        fs::remove_dir_all(dir).expect("cleanup");
    }
}

#[test]
fn script_hard_off_still_reaches_the_runtime_backstop() {
    let dir = temp_dir("script-runtime");
    let program = dir.join("script.whip");
    fs::write(&program, "workflow ScriptGate\noutput result Done\nclass Done { note string }\nrule go when started => { exec \"echo ws326\" as work after work succeeds { complete result { note \"ok\" } } }\n").expect("source");
    let output = whip_command(env!("CARGO_BIN_EXE_whip"))
        .env("WHIPPLESCRIPT_EXEC_ALLOW", "echo *")
        .args([
            "--store",
            "script.db",
            "--json",
            "run",
            program.to_str().expect("path"),
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .current_dir(&dir)
        .output()
        .expect("actual exec runtime door");
    assert!(output.status.success(), "{output:?}");
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("run JSON");
    let instance = result["instance_id"].as_str().expect("instance");
    let (ok, output) = whip(
        &dir,
        &["--store", "script.db", "--json", "effects", instance],
    );
    assert!(ok, "{output}");
    let effects: serde_json::Value = serde_json::from_str(&output).expect("effects JSON");
    let effect = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|e| e["kind"] == "exec.command")
        .expect("actual admitted exec");
    assert_eq!(effect["status"], "blocked_by_capability");
    assert!(effect["policy_block_reason"]
        .as_str()
        .expect("reason")
        .contains("security.script_disabled"));
    let (ok, output) = whip(&dir, &["--store", "script.db", "--json", "runs", instance]);
    assert!(ok, "{output}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&output).expect("runs"),
        serde_json::json!([])
    );
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn actual_invoke_refuses_child_authority_before_a_child_exists() {
    let dir = temp_dir("invoke-authority");
    let program = dir.join("invoke.whip");
    fs::write(
        &program,
        r#"
workflow Parent {
  output result Done
  failure error Failed
  class Done { note string }
  class Failed { reason string }
  rule go when started => {
    invoke Child {} as child
    after child succeeds as result { complete result { note result.note } }
    after child fails as error { fail error { reason error.reason } }
  }
}
workflow Child {
  output result Done
  class Done { note string }
  file store notes { root "./notes" allow read ["**"] }
  rule go when started => { complete result { note "child" } }
}
"#,
    )
    .expect("source");
    let (ok, output) = whip(
        &dir,
        &[
            "--store",
            "invoke.db",
            "--json",
            "run",
            program.to_str().expect("path"),
            "--root",
            "Parent",
            "--provider",
            "fixture",
            "--until",
            "idle",
        ],
    );
    assert!(
        ok,
        "parent runs and records ordinary child failure: {output}"
    );
    let result: serde_json::Value = serde_json::from_str(&output).expect("run JSON");
    let instance = result["instance_id"].as_str().expect("parent");
    let connection = rusqlite::Connection::open(dir.join("invoke.db")).expect("own runtime");
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM instances", [], |r| r.get(0))
        .expect("instances");
    assert_eq!(count, 1, "authority refusal must not admit a child");
    let (ok, output) = whip(&dir, &["--store", "invoke.db", "--json", "runs", instance]);
    assert!(ok, "{output}");
    let retained = whipplescript_store::SqliteStore::open(dir.join("invoke.db"))
        .expect("own retained runtime")
        .list_events(instance)
        .expect("retained events");
    assert!(
        retained
            .iter()
            .any(|event| event.event_type == "effect.terminal"
                && event.payload_json.contains("requires `use std.files`")),
        "actual invocation refusal provenance: {retained:?}"
    );
    fs::remove_dir_all(dir).expect("cleanup");
}
