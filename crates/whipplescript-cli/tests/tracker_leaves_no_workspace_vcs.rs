//! A tracker verb must not create a workspace VCS store as a side effect
//! (WS-117). The branch and content stores resolve from the current
//! directory, so `whip issue finish` run from a checkout used to leave an
//! empty `.whipplescript/branches.sqlite` and `vcs-content.sqlite` there,
//! untracked, in every repository a session closed an item from.
//!
//! The process runs the way an agent runs it: in a directory of its own,
//! with only the tracker store named. No branch or content store variable is
//! set, because setting one is exactly what would hide the default.

use std::path::Path;
use std::process::{Command, Output};

const STORE_VARS: &[&str] = &[
    "WHIPPLESCRIPT_BRANCH_STORE",
    "WHIPPLESCRIPT_VCS_CONTENT_STORE",
    "WHIPPLESCRIPT_WORKSTREAM_STORE",
    "WHIPPLESCRIPT_COORDINATION_STORE",
];

fn whip(cwd: &Path, items: &Path, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_whip"));
    command
        .current_dir(cwd)
        .env("WHIPPLESCRIPT_ITEMS_STORE", items)
        .args(args);
    for name in STORE_VARS {
        command.env_remove(name);
    }
    let output = command.output().expect("whip runs");
    assert!(
        output.status.success(),
        "whip {args:?} failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

#[test]
fn closing_an_item_from_a_checkout_leaves_no_workspace_vcs_there() {
    let root = tempfile::tempdir().expect("temp dir");
    let checkout = root.path().join("checkout");
    let tracker = root.path().join("tracker");
    std::fs::create_dir_all(&checkout).expect("checkout dir");
    std::fs::create_dir_all(&tracker).expect("tracker dir");
    let items = tracker.join("items.sqlite");

    let filed = whip(
        &checkout,
        &items,
        &[
            "--json",
            "issue",
            "new",
            "--tracker",
            "t",
            "--title",
            "x",
            "--body",
            "y",
        ],
    );
    let filed: serde_json::Value = serde_json::from_slice(&filed.stdout).expect("json");
    let id = filed["id"].as_str().expect("issue id").to_owned();

    whip(
        &checkout,
        &items,
        &["issue", "claim", &id, "--actor", "a", "--ttl", "1h"],
    );
    whip(&checkout, &items, &["issue", "note", &id, "n"]);
    whip(&checkout, &items, &["--json", "issue", "show", &id]);
    whip(
        &checkout,
        &items,
        &["issue", "finish", &id, "--summary", "s", "--actor", "a"],
    );
    whip(&checkout, &items, &["--json", "issue", "show", &id]);

    let stray = checkout.join(".whipplescript");
    assert!(
        !stray.exists(),
        "a tracker verb created {}: {:?}",
        stray.display(),
        std::fs::read_dir(&stray)
            .map(|entries| entries.flatten().map(|e| e.file_name()).collect::<Vec<_>>())
            .unwrap_or_default()
    );
}
