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

use std::fs;
use std::path::PathBuf;
use std::process::Command;

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
    let output = Command::new(env!("CARGO_BIN_EXE_whip"))
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
