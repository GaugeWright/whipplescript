//! Initiative CLI round trip: one shared task, two group identities, independent
//! task execution, derived inspection and explained group closure.
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_whip"))
        .current_dir(root)
        .env("WHIPPLESCRIPT_ITEMS_STORE", root.join("items.sqlite"))
        .args(["--json", "issue"])
        .args(args)
        .output()
        .expect("whip runs")
}

fn good(root: &Path, args: &[&str]) -> Value {
    let out = run(root, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("valid JSON")
}

#[test]
fn initiative_cli_keeps_shared_members_and_outcome_state_independent() {
    let root = tempfile::tempdir().expect("temp directory");
    let a = good(
        root.path(),
        &[
            "new",
            "--tracker",
            "company",
            "--kind",
            "initiative",
            "--title",
            "A",
        ],
    );
    let b = good(
        root.path(),
        &[
            "new",
            "--tracker",
            "company",
            "--kind",
            "initiative",
            "--title",
            "B",
        ],
    );
    let task = good(
        root.path(),
        &["new", "--tracker", "product", "--title", "shared task"],
    );
    assert_eq!(a["kind"], "initiative");
    assert_eq!(task["kind"], "task");
    let a_id = a["id"].as_str().expect("ID");
    let b_id = b["id"].as_str().expect("ID");
    let task_id = task["id"].as_str().expect("ID");
    for id in [a_id, b_id] {
        good(root.path(), &["link", task_id, "belongs-to", id]);
        let shown = good(root.path(), &["show", id]);
        assert_eq!(shown["progress"]["total"], 1);
        assert_eq!(shown["progress"]["states"]["open"], 1);
        assert_eq!(shown["progress"]["members"][0]["id"], task_id);
        assert_eq!(shown["readiness"]["ready"], false);
    }
    assert_eq!(
        good(root.path(), &["list", "--kind", "initiative"])
            .as_array()
            .expect("array")
            .len(),
        2
    );
    assert!(!run(
        root.path(),
        &["new", "--tracker", "q", "--kind", "epic", "--title", "bad"]
    )
    .status
    .success());
    assert!(!run(root.path(), &["list", "--kind", "epic"])
        .status
        .success());
    assert!(!run(root.path(), &["list", "--kind"]).status.success());
    assert!(!run(
        root.path(),
        &["new", "--tracker", "q", "--title", "bad", "--kind"]
    )
    .status
    .success());
    assert!(!run(root.path(), &["claim", a_id, "--override", "try it"])
        .status
        .success());
    assert!(!run(root.path(), &["link", a_id, "belongs-to", b_id])
        .status
        .success());
    assert!(!run(root.path(), &["finish", a_id]).status.success());
    good(
        root.path(),
        &[
            "finish",
            a_id,
            "--summary",
            "Outcome A verified; shared task retained for B",
        ],
    );
    assert_eq!(good(root.path(), &["show", task_id])["status"], "open");
    good(
        root.path(),
        &["claim", task_id, "--actor", "worker", "--ttl", "2h"],
    );
    good(root.path(), &["finish", task_id, "--summary", "proof"]);
    let b_shown = good(root.path(), &["show", b_id]);
    assert_eq!(b_shown["status"], "open");
    assert_eq!(b_shown["progress"]["states"]["closed"], 1);
    good(root.path(), &["unlink", task_id, "belongs-to", a_id]);
    assert_eq!(good(root.path(), &["show", a_id])["progress"]["total"], 0);
    assert_eq!(good(root.path(), &["show", b_id])["progress"]["total"], 1);
}

#[test]
fn initiative_files_are_enrolled_automatically_and_follow_cli_edits() {
    let root = tempfile::tempdir().expect("root");
    assert!(Command::new("git")
        .arg("init")
        .arg(root.path())
        .output()
        .expect("git")
        .status
        .success());
    let group = good(
        root.path(),
        &[
            "new",
            "--tracker",
            "q",
            "--kind",
            "initiative",
            "--title",
            "discovery initiative",
        ],
    );
    let task = good(
        root.path(),
        &[
            "new",
            "--tracker",
            "q",
            "--title",
            "searchable ungrouped task",
        ],
    );
    let group_id = group["id"].as_str().expect("group");
    let task_id = task["id"].as_str().expect("task");
    let path = root
        .path()
        .join(format!("tracker/initiatives/{group_id}.hjson"));
    let task_path = root.path().join(format!("tracker/tasks/{task_id}.hjson"));
    assert!(task_path.exists());
    good(root.path(), &["link", task_id, "belongs-to", group_id]);
    good(root.path(), &["set", task_id, "body", "fresh body marker"]);
    let data: Value =
        serde_json::from_slice(&std::fs::read(&path).expect("file")).expect("JSON HJSON subset");
    assert_eq!(data["members"][0]["body"], "fresh body marker");
    let rg = Command::new("rg")
        .current_dir(root.path())
        .args(["-l", "fresh body marker"])
        .output()
        .expect("rg");
    assert!(rg.status.success());
    assert!(String::from_utf8_lossy(&rg.stdout)
        .contains(&format!("tracker/initiatives/{group_id}.hjson")));
    good(root.path(), &["unlink", task_id, "belongs-to", group_id]);
    let data: Value = serde_json::from_slice(&std::fs::read(&path).expect("file")).expect("JSON");
    assert_eq!(data["progress"]["total"], 0);
    assert!(task_path.exists());
}

#[test]
fn tracker_commands_still_work_without_git_installed() {
    let root = tempfile::tempdir().expect("root");
    let out = Command::new(env!("CARGO_BIN_EXE_whip"))
        .current_dir(root.path())
        .env("PATH", "")
        .env(
            "WHIPPLESCRIPT_ITEMS_STORE",
            root.path().join("items.sqlite"),
        )
        .args([
            "--json",
            "issue",
            "new",
            "--tracker",
            "q",
            "--title",
            "standalone",
        ])
        .output()
        .expect("whip");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!root.path().join("tracker").exists());
}

#[test]
fn durable_export_does_not_depend_on_a_writable_discovery_view() {
    let root = tempfile::tempdir().expect("root");
    assert!(Command::new("git")
        .arg("init")
        .arg(root.path())
        .output()
        .expect("git")
        .status
        .success());
    let task = good(
        root.path(),
        &["new", "--tracker", "q", "--title", "backup-marker"],
    );
    std::fs::write(
        root.path().join("tracker/.whipplescript-discovery-owner"),
        "foreign owner",
    )
    .expect("simulate unavailable view");
    assert!(
        !run(root.path(), &["show", task["id"].as_str().expect("id")])
            .status
            .success()
    );
    let events = good(root.path(), &["export"]);
    assert!(!events.as_array().expect("events").is_empty());
    assert!(events.to_string().contains("backup-marker"));
    assert_eq!(
        std::fs::read_to_string(root.path().join("tracker/.whipplescript-discovery-owner"))
            .expect("preserved"),
        "foreign owner"
    );
}
