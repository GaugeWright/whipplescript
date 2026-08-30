//! `whip check` applies its per-workflow battery to the WHOLE bundle.
//!
//! The parser lowers every workflow, so a sibling's lowering errors always
//! surfaced. Everything after lowering did not: `select_root_workflow` empties
//! `Program::workflows`, so the liveness lint, the script hard-off, the
//! authority-import gate, the provider checks, the tool-grant resolution and the
//! information-flow checker only ever saw the workflow named by `--root`.
//!
//! The consequence was not a missing warning but an evasion: the same file that
//! `--root Child` rejected for writing confidential data to a public channel
//! passed under `--root Parent`, whose only statement was `invoke Child`.

use super::{check_sibling_workflows, ExecProfile};
use std::fs;

fn bundle(label: &str, source: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "whip-sibling-{label}-{}-{:?}.whip",
        std::process::id(),
        std::thread::current().id()
    ));
    fs::write(&path, source).expect("write bundle");
    path
}

/// A dead rule in a sibling: refused under its own root before this change, and
/// silent under any other root.
#[test]
fn a_siblings_dead_rule_is_reported_under_another_root() {
    let path = bundle(
        "dead-rule",
        r#"
class R { ok bool }
class Q { id string }
class Ghost { x string }

workflow Parent {
  output result R
  rule go
    when started
  => { complete result { ok true } }
}

workflow Child {
  input ask Q
  output outcome R
  rule dead
    when Ghost as g
  => { complete outcome { ok true } }
}
"#,
    );
    let source = fs::read_to_string(&path).expect("read bundle");
    let found = check_sibling_workflows(
        path.to_str().expect("path"),
        "Parent",
        None,
        None,
        ExecProfile::Dev,
        None,
        &source,
    );
    let _ = fs::remove_file(&path);

    assert!(
        found.iter().any(|diagnostic| {
            diagnostic.message.contains("in workflow `Child`")
                && diagnostic
                    .message
                    .contains("rule `dead` can never fire: nothing produces `Ghost`")
        }),
        "{:?}",
        found.iter().map(|d| d.message.as_str()).collect::<Vec<_>>()
    );
}

/// The authority gate is one of the refusals that was escapable this way: a
/// sibling could declare a `file store` without the `use std.files` opt-in and
/// no root but its own would say so.
#[test]
fn a_siblings_ungoverned_authority_declaration_is_reported() {
    let path = bundle(
        "authority",
        r#"
class R { ok bool }
class Q { id string }

workflow Parent {
  output result R
  rule go
    when started
  => { complete result { ok true } }
}

workflow Child {
  input ask Q
  output outcome R

  file store crm {
    root "."
    allow read ["**"]
  }

  rule go
    when Q as q
  => { complete outcome { ok true } }
}
"#,
    );
    let source = fs::read_to_string(&path).expect("read bundle");
    let found = check_sibling_workflows(
        path.to_str().expect("path"),
        "Parent",
        None,
        None,
        ExecProfile::Dev,
        None,
        &source,
    );
    let _ = fs::remove_file(&path);

    assert!(
        found.iter().any(|diagnostic| {
            diagnostic.message.contains("in workflow `Child`")
                && diagnostic
                    .message
                    .contains("security.package_import_required")
        }),
        "{:?}",
        found.iter().map(|d| d.message.as_str()).collect::<Vec<_>>()
    );
}

/// The root itself is never double-reported: it has already been through the
/// same battery in `check`.
#[test]
fn the_selected_root_is_not_checked_twice() {
    let path = bundle(
        "root-skipped",
        r#"
class R { ok bool }
class Ghost { x string }

workflow Parent {
  output result R
  rule dead
    when Ghost as g
  => { complete result { ok true } }
}

workflow Child {
  output outcome R
  rule go
    when started
  => { complete outcome { ok true } }
}
"#,
    );
    let source = fs::read_to_string(&path).expect("read bundle");
    let found = check_sibling_workflows(
        path.to_str().expect("path"),
        "Parent",
        None,
        None,
        ExecProfile::Dev,
        None,
        &source,
    );
    let _ = fs::remove_file(&path);

    assert!(
        found.is_empty(),
        "the root's own diagnostics belong to `check`, not to the sibling pass: {:?}",
        found.iter().map(|d| d.message.as_str()).collect::<Vec<_>>()
    );
}
