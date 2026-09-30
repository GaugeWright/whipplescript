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
