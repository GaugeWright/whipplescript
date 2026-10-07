//! WS-242: ordinary runtime admission, CLI and editor explanations share
//! exact retained identities. No obstruction rows are fabricated by this test.
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

const PROFILE_SOURCE: &str = r#"
use std.agent
workflow ProfileExplanation
class Ran { out string }
agent helper { provider native-fixture profile "unknown-explanation-profile" capacity 1 }
action review() -> Ran {
  tell helper "ws242-private-provider-input" as operation
  after operation succeeds {
    return { out "done" }
  }
}
rule work
  when started
=> {
  review() as answer
  after answer succeeds {
    record Ran { out answer.out }
  }
}
"#;

struct Fixture {
    dir: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempfile::tempdir().expect("fixture operation succeeds"),
        };
        fs::write(fixture.dir.path().join("program.whip"), PROFILE_SOURCE)
            .expect("fixture operation succeeds");
        fixture
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_whip"));
        command
            .current_dir(self.dir.path())
            .args(["--store", "runtime.sqlite"]);
        for (name, file) in [
            ("WHIPPLESCRIPT_ITEMS_STORE", "items.sqlite"),
            ("WHIPPLESCRIPT_WORKSTREAMS_STORE", "streams.sqlite"),
            ("WHIPPLESCRIPT_VCS_STORE", "vcs.sqlite"),
            ("WHIPPLESCRIPT_MEMORY_STORE", "memory.sqlite"),
            ("WHIPPLESCRIPT_CONTENT_STORE", "content.sqlite"),
        ] {
            command.env(name, self.dir.path().join(file));
        }
        command.env_remove("WHIPPLESCRIPT_EXEC_ALLOW");
        command
    }
    fn json(&self, args: &[&str]) -> Value {
        let output = self
            .command()
            .arg("--json")
            .args(args)
            .output()
            .expect("fixture operation succeeds");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("fixture operation succeeds")
    }
    fn explain_in_editor(&self, instance: &str, result: &str) -> Value {
        let mut child = self
            .command()
            .arg("lsp")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("fixture operation succeeds");
        let messages = [
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"workspace/executeCommand","params":{
                "command":"whip.explainResult","arguments":[{"instance":instance,"result":result}]
            }}),
            json!({"jsonrpc":"2.0","id":3,"method":"shutdown","params":null}),
            json!({"jsonrpc":"2.0","method":"exit","params":null}),
        ];
        let mut input = child.stdin.take().expect("fixture operation succeeds");
        for message in messages {
            let body = message.to_string();
            write!(input, "Content-Length: {}\r\n\r\n{}", body.len(), body)
                .expect("fixture operation succeeds");
        }
        drop(input);
        let output = child
            .wait_with_output()
            .expect("fixture operation succeeds");
        assert!(output.status.success());
        let mut remaining = output.stdout.as_slice();
        while !remaining.is_empty() {
            let header_end = remaining
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("fixture operation succeeds");
            let header =
                std::str::from_utf8(&remaining[..header_end]).expect("fixture operation succeeds");
            let size: usize = header
                .lines()
                .find_map(|line| line.strip_prefix("Content-Length:"))
                .expect("fixture operation succeeds")
                .trim()
                .parse()
                .expect("fixture operation succeeds");
            let start = header_end + 4;
            let message: Value = serde_json::from_slice(&remaining[start..start + size])
                .expect("fixture operation succeeds");
            remaining = &remaining[start + size..];
            if message["id"] == 2 {
                return message["result"].clone();
            }
        }
        panic!("editor returned no selected explanation");
    }
}

// Configuration is changed through its public owning API. Effects, firings,
// terminal events and explanation rows are produced only by ordinary CLI doors.
fn profile_repair_case(revise_pending: bool) {
    let fixture = Fixture::new();
    let started = fixture.json(&[
        "run",
        "program.whip",
        "--provider",
        "native-fixture",
        "--until",
        "idle",
    ]);
    let instance = started["instance_id"]
        .as_str()
        .expect("fixture operation succeeds");
    let effects = fixture.json(&["effects", instance]);
    let operation = effects
        .as_array()
        .expect("fixture operation succeeds")
        .iter()
        .find(|effect| effect["kind"] == "agent.tell")
        .expect("fixture operation succeeds");
    assert_eq!(operation["status"], "blocked_by_profile");
    let explanation = fixture.json(&["explain", instance, "operation"]);
    let before = &explanation["outcome"]["selection"];
    assert_eq!(
        before["program_version_id"],
        operation["program_version_id"]
    );
    assert_eq!(before["result"]["operation_id"], operation["effect_id"]);
    assert_eq!(
        before["result"]["reasons"],
        json!(["missing_configuration"])
    );
    assert_eq!(before["result"]["status"], "waiting");
    let source = before["result"]["source"]
        .as_array()
        .expect("fixture operation succeeds");
    assert_eq!(
        source
            .iter()
            .map(|item| item["role"].as_str().expect("fixture operation succeeds"))
            .collect::<Vec<_>>(),
        ["call_site", "definition", "result"]
    );
    for (reference, expected) in source
        .iter()
        .zip(["review() as answer", "review", "tell helper"])
    {
        let start = reference["span"]["start"]
            .as_u64()
            .expect("fixture operation succeeds") as usize;
        let end = reference["span"]["end"]
            .as_u64()
            .expect("fixture operation succeeds") as usize;
        assert!(PROFILE_SOURCE[start..end].contains(expected));
    }
    assert_eq!(before["next_action"]["code"], "inspect_operation_block");
    assert_eq!(
        before["next_action"]["operation_id"],
        operation["effect_id"]
    );
    assert_eq!(before["next_action"]["authorizes_work"], false);
    assert_eq!(before["next_action"]["retry_permitted"], false);
    assert_eq!(
        fixture.explain_in_editor(instance, "operation"),
        explanation
    );
    assert!(!explanation
        .to_string()
        .contains("ws242-private-provider-input"));
    assert_eq!(fixture.json(&["effects", instance]), effects);
    assert_eq!(
        fixture.json(&["explain", instance, "operation"]),
        explanation
    );
    assert_eq!(fixture.json(&["runs", instance]), json!([]));
    if revise_pending {
        let revised_source = format!(
            "// Current source has different positions and a different completion.\n{}",
            PROFILE_SOURCE.replace("out \"done\"", "out \"new-body\"")
        );
        fs::write(fixture.dir.path().join("program.whip"), revised_source)
            .expect("fixture operation succeeds");
        let revised = fixture.json(&["revise", instance, "program.whip", "--cancel", "keep"]);
        assert_ne!(
            revised["revision"]["to_version_id"],
            before["program_version_id"]
        );
        assert_eq!(
            revised["revision"]["from_version_id"],
            before["program_version_id"]
        );
        let still_blocked = fixture.json(&["explain", instance, "operation"]);
        assert_eq!(
            still_blocked["outcome"]["selection"]["program_version_id"],
            before["program_version_id"]
        );
        assert_eq!(
            still_blocked["outcome"]["selection"]["result"],
            before["result"]
        );
        assert_eq!(
            fixture.explain_in_editor(instance, "operation"),
            still_blocked
        );
    }
    let store =
        whipplescript_store::SqliteStore::open_existing(fixture.dir.path().join("runtime.sqlite"))
            .expect("fixture operation succeeds");
    store
        .register_profile(whipplescript_store::ProfileRegistration {
            profile_id: "ws242-profile",
            name: "unknown-explanation-profile",
            description: "Explicit configuration repair through the supported store API",
            enforcement_mode: "enforce",
            allowed_capabilities_json: "[\"agent.tell\"]",
            config_json: "{}",
        })
        .expect("fixture operation succeeds");
    drop(store);
    // Registration and explanation reads never dispatch the pending operation.
    assert_eq!(
        fixture.json(&["effects", instance])[0]["status"],
        "blocked_by_profile"
    );
    assert_eq!(fixture.json(&["runs", instance]), json!([]));
    let worker = fixture.json(&[
        "worker",
        instance,
        "--program",
        "program.whip",
        "--provider",
        "native-fixture",
    ]);
    assert_eq!(worker["ran_effects"], 1);
    fixture.json(&["step", instance, "--program", "program.whip"]);
    let repaired = fixture.json(&["explain", instance, "operation"]);
    let after = &repaired["outcome"]["selection"];
    for field in [
        "program_version_id",
        "revision",
        "revision_epoch",
        "rule",
        "firing",
    ] {
        assert_eq!(after[field], before[field], "retained {field}");
    }
    for field in ["result_id", "operation_id", "binding", "source"] {
        assert_eq!(
            after["result"][field], before["result"][field],
            "retained {field}"
        );
    }
    assert!(
        after["evaluated_frontier"]
            .as_i64()
            .expect("fixture operation succeeds")
            > before["evaluated_frontier"]
                .as_i64()
                .expect("fixture operation succeeds")
    );
    assert_eq!(after["result"]["reasons"], json!(["value_available"]));
    assert_eq!(after["result"]["status"], "ready");
    assert_eq!(after["next_action"], Value::Null);
    assert_eq!(fixture.explain_in_editor(instance, "operation"), repaired);
    assert!(!repaired
        .to_string()
        .contains("ws242-private-provider-input"));
    let runs = fixture.json(&["runs", instance]);
    assert_eq!(
        runs.as_array().expect("fixture operation succeeds").len(),
        1
    );
    assert_eq!(runs[0]["effect_id"], operation["effect_id"]);
    assert_eq!(runs[0]["provider"], "native-fixture");
    assert_eq!(runs[0]["status"], "completed");
    assert_eq!(runs[0]["artifact_count"], 1);
    assert_eq!(runs[0]["native_lifecycle"]["status"], "completed");
    let completed = fixture.json(&["effects", instance]);
    assert_eq!(
        completed
            .as_array()
            .expect("fixture operation succeeds")
            .len(),
        1
    );
    assert_eq!(completed[0]["effect_id"], operation["effect_id"]);
    assert_eq!(completed[0]["status"], "completed");
    let facts = fixture.json(&["facts", instance]);
    assert!(facts
        .as_array()
        .expect("fixture operation succeeds")
        .iter()
        .any(|fact| fact["name"] == "Ran" && fact["value"]["out"] == "done"));
    assert_eq!(
        fixture.json(&[
            "worker",
            instance,
            "--program",
            "program.whip",
            "--provider",
            "native-fixture"
        ])["ran_effects"],
        0
    );
    assert_eq!(fixture.json(&["runs", instance]), runs);
    assert_eq!(fixture.json(&["effects", instance]), completed);
    assert_eq!(fixture.json(&["explain", instance, "operation"]), repaired);
}

#[test]
fn runtime_profile_obstruction_repairs_through_supported_configuration_and_native_execution() {
    profile_repair_case(false);
}

#[test]
fn pending_profile_obstruction_retains_source_and_firing_across_keep_revision_and_repair() {
    profile_repair_case(true);
}
