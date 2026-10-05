//! End-to-end `whip improve` loop: pin a scenario from a real dev run,
//! campaign with the fixture proposer, dominance verdicts on real
//! regenerated evaluations, campaign record, and adoption — all through the
//! built binary with deterministic exec judges (no live provider).

#[path = "support/isolated_whip.rs"]
mod isolated_whip;
use isolated_whip::whip_command;

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "whip-improve-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

struct Env {
    dir: PathBuf,
    store: String,
    improve_store: String,
}

/// Reclaim the scenario's temp tree when the test ends — including when it
/// ends by panicking, since `Drop` runs during unwind. Without this each of
/// the 19 tests here left its directory behind on every run; they had
/// accumulated ~2,676 of them in the tmpfs before this was added.
impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl Env {
    fn new(label: &str) -> Self {
        let dir = temp_dir(label);
        let store = dir.join("store.sqlite").to_string_lossy().into_owned();
        let improve_store = dir.join("improve.sqlite").to_string_lossy().into_owned();
        Self {
            dir,
            store,
            improve_store,
        }
    }

    fn command(&self) -> Command {
        let mut command = whip_command(env!("CARGO_BIN_EXE_whip"));
        command
            .env("WHIPPLESCRIPT_EXEC_ALLOW", "python3 *")
            .env("WHIPPLESCRIPT_IMPROVE_STORE", &self.improve_store)
            .current_dir(&self.dir);
        command
    }

    fn run_json(&self, args: &[&str], extra_env: &[(&str, &str)]) -> Value {
        let mut command = self.command();
        command.args(args);
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let output = command.output().expect("spawn whip");
        assert!(
            output.status.success(),
            "whip {args:?} failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let start = stdout.find('{').unwrap_or_else(|| {
            panic!("no JSON in output of whip {args:?}:\n{stdout}");
        });
        serde_json::from_str(&stdout[start..]).expect("parse JSON output")
    }

    fn run_expect_failure(&self, args: &[&str]) -> String {
        let mut command = self.command();
        command.args(args);
        let output = command.output().expect("spawn whip");
        assert!(
            !output.status.success(),
            "whip {args:?} unexpectedly succeeded"
        );
        String::from_utf8_lossy(&output.stderr).into_owned()
    }
}

const PRIORITY_JUDGE: &str = r#"
import json, sys
record = json.load(sys.stdin)
priority = None
for fact in record.get("facts", []):
    if fact.get("name") == "Assessment":
        priority = fact.get("value", {}).get("priority")
print(json.dumps({"ok": priority == "high"}))
"#;

const ECHO_JUDGE: &str = r#"
import json, sys
record = json.load(sys.stdin)
ticket_in = (record.get("input") or {}).get("ticket", {}).get("id")
echoed = None
for fact in record.get("facts", []):
    if fact.get("name") == "Assessment":
        echoed = fact.get("value", {}).get("ticket")
print(json.dumps({"passed": echoed == ticket_in}))
"#;

fn program(priority: &str, ticket_expr: &str, judge_dir: &std::path::Path) -> String {
    let priority_judge = judge_dir.join("judge_priority.py");
    let echo_judge = judge_dir.join("judge_echo.py");
    format!(
        r#"workflow Triage

input ticket Ticket

class Ticket {{
  id string
  title string
}}

class Assessment {{
  ticket string
  priority string
}}

gauge priority_correct {{
  judge via exec "python3 {priority_judge}"
  expect P(ok) at least 0.5
}}

gauge ticket_echoed {{
  judge via exec "python3 {echo_judge}"
}}

rule triage
  when Ticket as ticket
=> {{
  record Assessment {{
    ticket {ticket_expr}
    priority "{priority}"
  }}
}}
"#,
        priority_judge = priority_judge.display(),
        echo_judge = echo_judge.display(),
    )
}

fn write_judges(dir: &std::path::Path) {
    fs::write(dir.join("judge_priority.py"), PRIORITY_JUDGE).expect("write judge");
    fs::write(dir.join("judge_echo.py"), ECHO_JUDGE).expect("write judge");
}

fn dev_and_pin(env: &Env, program_path: &str) -> String {
    let dev = env.run_json(
        &[
            "--store",
            &env.store,
            "--input",
            r#"{"ticket":{"id":"T-1","title":"Fix login"}}"#,
            "--json",
            "run",
            program_path,
            "--provider",
            "fixture",
        ],
        &[],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();
    let pinned = env.run_json(
        &[
            "--store", &env.store, "--json", "pin", &instance, "--as", "case-1",
        ],
        &[],
    );
    assert_eq!(pinned["scenario"].as_str(), Some("case-1"));
    instance
}

#[test]
fn improve_exec_judge_receives_workflow_terminal_payload() {
    let env = Env::new("terminal-judge");
    let judge = env.dir.join("judge_terminal.py");
    fs::write(
        &judge,
        "import json,sys\nr=json.load(sys.stdin)\nprint(json.dumps({'ok': r.get('status') == 'completed' and (r.get('terminal') or {}).get('route') == 'BILLING'}))\n",
    )
    .expect("judge");
    let source = |route: &str| {
        format!(
            r#"workflow TerminalRoute
input ticket Ticket
output result Reply
class Ticket {{ id string }}
class Reply {{ route string }}
gauge terminal_correct {{
  judge via exec "python3 {}"
  expect P(ok) at least 0.9
}}
rule route
  when Ticket as ticket
=> {{ complete result {{ route "{route}" }} }}
"#,
            judge.display()
        )
    };
    let program_path = env.dir.join("route.whip");
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&program_path, source("GENERAL")).expect("baseline");
    fs::write(&candidate_path, source("BILLING")).expect("candidate");
    let program_str = program_path.to_string_lossy().into_owned();
    let run = env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "--input",
            r#"{"ticket":{"id":"T-1"}}"#,
            "run",
            &program_str,
            "--provider",
            "fixture",
        ],
        &[],
    );
    env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "pin",
            run["instance_id"].as_str().unwrap(),
            "--as",
            "terminal-1",
        ],
        &[],
    );
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "terminal_correct",
            "--program",
            &program_str,
            "--provider",
            "fixture",
            "--proposer",
            "fixture",
        ],
        &[(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            &candidate_path.to_string_lossy(),
        )],
    );
    assert_eq!(report["proposed"], true, "{report}");
    assert_eq!(report["cards"][0]["proposable"], true, "{report}");
}

#[test]
fn improve_regeneration_uses_the_content_pinned_script_manifest() {
    let env = Env::new("script-manifest-regeneration");
    let script = env.dir.join("echo.py");
    let script_source = "import json,sys\nrequest=json.load(sys.stdin)\nprint(json.dumps({'value':request['id']}))\n";
    fs::write(&script, script_source).expect("write script");
    let manifest = env.dir.join("scripts.json");
    fs::write(
        &manifest,
        serde_json::json!({"echo_ticket": {
            "argv": ["python3", script.to_string_lossy()],
            "sha256": Sha256::digest(script_source.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        }})
        .to_string(),
    )
    .expect("write script manifest");
    let judge = env.dir.join("judge.py");
    fs::write(
        &judge,
        "import json,sys\nr=json.load(sys.stdin)\nt=r.get('terminal') or {}\nprint(json.dumps({'ok':r.get('status')=='completed' and t.get('value')=='T-1' and t.get('route')=='right'}))\n",
    )
    .expect("write judge");
    let source = |route: &str| {
        format!(
            r#"use std.script
workflow ScriptEval
input ticket Ticket
output result Reply
class Ticket {{ id string }}
class ScriptReply {{ value string }}
class Reply {{ value string route string }}
gauge script_quality {{
  judge via exec "python3 {}"
  expect P(ok) at least 0.5
}}
rule evaluate
  when Ticket as ticket
=> {{
  exec echo_ticket with ticket -> ScriptReply as called
  after called succeeds as answer {{
    complete result {{ value answer.value route "{route}" }}
  }}
}}
"#,
            judge.display()
        )
    };
    let baseline = env.dir.join("baseline.whip");
    let candidate = env.dir.join("candidate.whip");
    fs::write(&baseline, source("wrong")).expect("write baseline");
    fs::write(&candidate, source("right")).expect("write candidate");
    let baseline = baseline.to_string_lossy().into_owned();
    let candidate = candidate.to_string_lossy().into_owned();
    let manifest = manifest.to_string_lossy().into_owned();
    let script_env = [
        ("WHIPPLESCRIPT_SCRIPT_MANIFEST", manifest.as_str()),
        ("WHIPPLESCRIPT_EXEC_PROFILE", "hosted"),
    ];
    let run = env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "--input",
            r#"{"ticket":{"id":"T-1"}}"#,
            "run",
            &baseline,
            "--provider",
            "fixture",
        ],
        &script_env,
    );
    env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "pin",
            run["instance_id"].as_str().expect("instance id"),
            "--as",
            "script-case",
        ],
        &script_env,
    );
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "script_quality",
            "--program",
            &baseline,
            "--provider",
            "fixture",
            "--proposer",
            "fixture",
        ],
        &[
            script_env[0],
            script_env[1],
            ("WHIPPLESCRIPT_IMPROVE_PROPOSALS", candidate.as_str()),
        ],
    );
    assert_eq!(report["proposed"], true, "{report}");
    assert_eq!(report["cards"][0]["proposable"], true, "{report}");
}

#[test]
fn improve_stops_when_a_declared_baseline_judge_is_unscored() {
    let env = Env::new("unscored-baseline-judge");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("high", "ticket.id", &env.dir)).expect("write program");
    let program_path = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_path);
    let output = env
        .command()
        .env("WHIPPLESCRIPT_EXEC_ALLOW", "")
        .args([
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_path,
            "--provider",
            "fixture",
            "--proposer",
            "fixture",
        ])
        .output()
        .expect("run improve");
    assert!(!output.status.success(), "unscored judge was accepted");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("baseline gauge unscored")
            && stderr.contains("exec judge")
            && stderr.contains("not granted"),
        "{stderr}"
    );
}

#[test]
fn candidate_that_fails_runtime_lowering_is_recorded_and_next_proposal_runs() {
    let env = Env::new("candidate-lowering");
    let judge = env.dir.join("judge.py");
    fs::write(
        &judge,
        "import json,sys\nr=json.load(sys.stdin)\nprint(json.dumps({'ok': any(f.get('name') == 'Reply' and f.get('value', {}).get('route') == 'owned completed' for f in r.get('facts', []))}))\n",
    )
    .expect("judge");
    let baseline = format!(
        r#"use std.agent
workflow Route
input ticket Ticket
class Ticket {{ id string }}
class Reply {{ route string }}
gauge route_correct {{
  judge via exec "python3 {}"
  expect P(ok) at least 0.5
}}
agent router {{ provider owned profile "repo-reader" capacity 1 }}
rule route
  when Ticket as ticket
  when router is available
=> {{
  tell router as turn """markdown
  Route {{{{ ticket.id }}}}.
  """
  after turn succeeds {{
    record Reply {{ route "GENERAL" }}
  }}
}}
"#,
        judge.display()
    );
    let program_path = env.dir.join("route.whip");
    fs::write(&program_path, &baseline).expect("baseline");
    let program_str = program_path.to_string_lossy().into_owned();
    let input = r#"{"ticket":{"id":"T-1"}}"#;
    let run = env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "--input",
            input,
            "run",
            &program_str,
            "--provider",
            "fixture",
        ],
        &[],
    );
    env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "pin",
            run["instance_id"].as_str().unwrap(),
            "--as",
            "route-1",
        ],
        &[],
    );
    let bad = env.dir.join("bad.whip");
    fs::write(
        &bad,
        baseline.replace("route \"GENERAL\"", "route turn.text"),
    )
    .expect("bad candidate");
    let good = env.dir.join("good.whip");
    fs::write(
        &good,
        baseline.replace("route \"GENERAL\"", "route turn.summary"),
    )
    .expect("good candidate");
    let proposals = format!("{}:{}", bad.display(), good.display());
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "route_correct",
            "--program",
            &program_str,
            "--provider",
            "fixture",
            "--proposer",
            "fixture",
        ],
        &[("WHIPPLESCRIPT_IMPROVE_PROPOSALS", &proposals)],
    );
    assert_eq!(report["proposed"], true, "{report}");
    let campaign = env.run_json(
        &["--json", "campaign", report["campaign"].as_str().unwrap()],
        &[],
    );
    assert!(
        campaign["events"].as_array().unwrap().iter().any(|event| {
            event["type"] == "candidate.rejected"
                && event["payload"]["candidate"] == "K-1"
                && event["payload"]["reason"]
                    .as_str()
                    .is_some_and(|r| r.contains("lowering failed:"))
        }),
        "{campaign}"
    );
    assert!(
        campaign["events"].as_array().unwrap().iter().any(|event| {
            event["type"] == "candidate.open_assessed"
                && event["payload"]["candidate"] == "K-1"
                && event["payload"]["reasons"][0]
                    .as_str()
                    .is_some_and(|reason| reason.contains("could not resolve `turn.text`"))
        }),
        "the next proposer must receive the actionable open-case diagnostic: {campaign}"
    );
    assert!(
        campaign["events"].as_array().unwrap().iter().any(|event| {
            event["type"] == "campaign.spend"
                && event["payload"]["what"] == "workflow turns (K-1, failed evaluation)"
                && event["payload"]["runs"]
                    .as_u64()
                    .is_some_and(|runs| runs > 0)
        }),
        "provider work before the lowering failure must enter the ledger: {campaign}"
    );
    assert_eq!(report["cards"][0]["candidate"], "K-2", "{report}");

    let capped = env
        .command()
        .args([
            "--json",
            "improve",
            "route_correct",
            "--program",
            &program_str,
            "--provider",
            "fixture",
            "--proposer",
            "fixture",
            "--spend-cap",
            "$1",
        ])
        .env("WHIPPLESCRIPT_IMPROVE_PROPOSALS", &proposals)
        .output()
        .expect("capped improve");
    assert!(!capped.status.success(), "capped campaign must stop");
    assert!(
        String::from_utf8_lossy(&capped.stderr).contains("unaccounted provider use"),
        "{}",
        String::from_utf8_lossy(&capped.stderr)
    );
    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let failed = campaigns["campaigns"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["status"] == "failed")
        .expect("capped campaign is recorded as failed");
    let detail = env.run_json(
        &["--json", "campaign", failed["campaign"].as_str().unwrap()],
        &[],
    );
    assert!(
        detail["events"].as_array().unwrap().iter().any(|event| {
            event["type"] == "campaign.spend"
                && event["payload"]["what"] == "workflow turns (K-1, failed evaluation)"
                && event["payload"]["priced"] == false
        }),
        "unaccounted provider use must remain visible in failed campaign: {detail}"
    );
}

#[test]
fn improve_skips_repeated_canonical_candidate_before_regeneration() {
    let env = Env::new("repeat-guard");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    let baseline = program("low", "ticket.id", &env.dir);
    fs::write(&program_path, &baseline).expect("write baseline");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);
    let repeated_path = env.dir.join("repeated.whip");
    fs::write(&repeated_path, &baseline).expect("write repeated candidate");
    let improved_path = env.dir.join("improved.whip");
    fs::write(&improved_path, program("high", "ticket.id", &env.dir))
        .expect("write improved candidate");
    let proposals = format!(
        "{}:{}:{}",
        repeated_path.display(),
        repeated_path.display(),
        improved_path.display()
    );
    let result = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[("WHIPPLESCRIPT_IMPROVE_PROPOSALS", &proposals)],
    );
    assert_eq!(result["proposed"], true);
    let campaign_id = result["campaign"].as_str().expect("campaign id");
    let campaign = env.run_json(&["--json", "campaign", campaign_id], &[]);
    let events = campaign["events"].as_array().expect("events");
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "candidate.recorded")
            .count(),
        2,
        "the duplicate must not run a second regeneration"
    );
    assert!(events.iter().any(|event| {
        event["type"] == "candidate.rejected"
            && event["payload"]["candidate"] == "K-2"
            && event["payload"]["tags"] == serde_json::json!(["exact-retry"])
    }));
    assert!(events.iter().any(|event| {
        event["type"] == "candidate.open_assessed" && event["payload"]["candidate"] == "K-1"
    }));
    assert!(events.iter().any(|event| {
        event["type"] == "candidate.proposed" && event["payload"]["candidate"] == "K-3"
    }));
}

#[test]
fn native_shortcut_critic_generalizes_a_planted_case_answer() {
    let env = Env::new("shortcut-generalization");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write baseline");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let planted = program("high", "\"T-1\"", &env.dir);
    let generalized = program("high", "ticket.id", &env.dir);
    let account = serde_json::json!({
        "mechanism": "raise priority while preserving ticket identity",
        "declarations": ["rule triage"],
        "expected_gauges": ["priority_correct"],
    });
    let replies = vec![
        serde_json::json!({"rationale": "repair priority", "source": planted,
            "edit_account": account})
        .to_string(),
        serde_json::json!({"classification": "clear", "source_quote": "ticket \"T-1\"",
            "reason": "the output copies the pinned case id instead of its input"})
        .to_string(),
        serde_json::json!({"rationale": "read the ticket id from input", "source": generalized,
            "edit_account": account})
        .to_string(),
        serde_json::json!({"classification": "none", "source_quote": "", "reason": ""}).to_string(),
    ];
    let (base_url, bodies) = mock_coerce_sequence_endpoint(replies);
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "native",
        ],
        &[
            ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
            ("OPENAI_API_KEY", "test-key"),
            ("WHIPPLESCRIPT_COERCE_BASE_URL", &base_url),
            ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
        ],
    );
    assert_eq!(report["proposed"], true, "{report}");
    let card = &report["cards"][0];
    assert_eq!(card["shortcut"]["original"]["classification"], "clear");
    assert_eq!(card["shortcut"]["original"]["status"], "source-verified");
    assert_eq!(card["shortcut"]["selected"]["classification"], "none");
    assert_eq!(card["shortcut"]["excerpt_removed_by_revision"], true);
    assert!(card["tags"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("shortcut-revised")));

    let campaign = env.run_json(
        &["--json", "campaign", report["campaign"].as_str().unwrap()],
        &[],
    );
    let events = campaign["events"].as_array().unwrap();
    assert!(events.iter().any(|event| {
        event["type"] == "candidate.refinement"
            && event["payload"]["kind"] == "shortcut-generalization"
            && event["payload"]["status"] == "selected"
    }));
    assert!(events.iter().any(|event| {
        event["type"] == "candidate.recorded"
            && event["payload"]["source"].as_str() == Some(generalized.as_str())
    }));
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "candidate.shortcut_assessed")
            .count(),
        2,
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event["type"] == "campaign.spend"
                && event["payload"]["what"] == "shortcut critic turn")
            .count(),
        2,
    );
    let bodies = bodies.lock().unwrap();
    assert_eq!(bodies.len(), 4, "proposal, critic, revision, critic");
    let proposal_request: Value = serde_json::from_str(&bodies[0]).expect("proposal request");
    assert_eq!(
        proposal_request["response_format"]["json_schema"]["strict"],
        true
    );
    let proposal_schema = &proposal_request["response_format"]["json_schema"]["schema"];
    assert!(proposal_schema["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("context_edits")));
    assert!(proposal_schema["properties"]["edit_account"]["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("resources")));
    let critic_request: Value = serde_json::from_str(&bodies[1]).expect("critic request");
    assert_eq!(
        critic_request["response_format"]["json_schema"]["strict"],
        true
    );
    let critic_schema = &critic_request["response_format"]["json_schema"]["schema"];
    assert!(critic_schema["required"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("source_path")));
}

#[test]
fn native_resource_refinement_keeps_a_dominating_deletion_draft() {
    let env = Env::new("resource-deletion-refinement");
    let judge = env.dir.join("judge_copy.py");
    fs::write(
        &judge,
        r#"import json, sys
record = json.load(sys.stdin)
expected = record["input"]["item"]["code"]
actual = [fact["value"]["code"] for fact in record["facts"] if fact["name"] == "Reply"]
print(json.dumps({"ok": bool(actual) and actual[-1] == expected}))
"#,
    )
    .expect("judge");
    let baseline = r#"use std.coercion

workflow CopyCode

input item Item
output result Reply

class Item {
  code string
}

class Reply {
  code string
}

class AuditResult {
  checked bool
}

coerce Copy(value string) -> Reply {
  prompt """markdown
  Copy {{ value }} into code.
  {{ ctx.output_format }}
  """
}

coerce Audit(value string) -> AuditResult {
  prompt """markdown
  Return checked true for {{ value }}.
  {{ ctx.output_format }}
  """
}

gauge copy_correct {
  judge via exec "python3 __JUDGE__"
  expect P(ok) at least 0.9
}

rule copy
  when Item as item
=> {
  then first <- coerce Copy(item.code)
  then redundant <- coerce Audit(item.code)
  record Reply { code first.code }
  complete result { code first.code }
}
"#
    .replace("__JUDGE__", &judge.to_string_lossy());
    let narrow = baseline
        .replace("class AuditResult {\n  checked bool\n}\n\n", "")
        .replace(
            "coerce Audit(value string) -> AuditResult {\n  prompt \"\"\"markdown\n  Return checked true for {{ value }}.\n  {{ ctx.output_format }}\n  \"\"\"\n}\n\n",
            "",
        )
        .replace("  then redundant <- coerce Audit(item.code)\n", "");
    let broad = narrow
        .replace("use std.coercion\n\n", "")
        .replace(
            "coerce Copy(value string) -> Reply {\n  prompt \"\"\"markdown\n  Copy {{ value }} into code.\n  {{ ctx.output_format }}\n  \"\"\"\n}\n\n",
            "",
        )
        .replace("  then first <- coerce Copy(item.code)\n", "")
        .replace("first.code", "item.code");
    assert!(!broad.contains("coerce"), "broad draft removes both calls");
    let program_path = env.dir.join("copy.whip");
    fs::write(&program_path, &baseline).expect("baseline program");
    let program_str = program_path.to_string_lossy().into_owned();
    let proposal = serde_json::json!({
        "rationale": "copy the already available input without model calls",
        "source": broad,
        "edit_account": {"mechanism": "remove redundant model work",
            "declarations": ["use std.coercion", "class AuditResult", "coerce Copy(value string) -> Reply", "coerce Audit(value string) -> AuditResult", "rule copy"],
            "resources": [], "expected_gauges": ["std.tokens"]},
        "context_edits": []
    });
    let refinement = serde_json::json!({
        "rationale": "remove only the unused audit",
        "source": narrow,
        "edit_account": {"mechanism": "remove redundant audit",
            "declarations": ["class AuditResult", "coerce Audit(value string) -> AuditResult", "rule copy"],
            "resources": [], "expected_gauges": ["std.tokens"]},
        "context_edits": []
    });
    let no_shortcut = serde_json::json!({
        "classification": "none", "source_path": "program", "source_quote": "", "reason": ""
    });
    let replies = vec![
        r#"{"code":"CODE"}"#.to_owned(),
        r#"{"checked":true}"#.to_owned(),
        r#"{"code":"CODE"}"#.to_owned(),
        r#"{"checked":true}"#.to_owned(),
        proposal.to_string(),
        no_shortcut.to_string(),
        refinement.to_string(),
        no_shortcut.to_string(),
        r#"{"code":"CODE"}"#.to_owned(),
    ];
    let (base_url, bodies) = mock_coerce_sequence_endpoint(replies);
    let provider_env = [
        ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
        ("OPENAI_API_KEY", "test-key"),
        ("WHIPPLESCRIPT_COERCE_BASE_URL", base_url.as_str()),
        ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
    ];
    let dev = env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "--input",
            r#"{"item":{"code":"CODE"}}"#,
            "run",
            &program_str,
            "--provider",
            "owned",
        ],
        &provider_env,
    );
    env.run_json(
        &[
            "--json",
            "--store",
            &env.store,
            "pin",
            dev["instance_id"].as_str().unwrap(),
            "--as",
            "copy-case",
        ],
        &[],
    );
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "std.tokens",
            "--program",
            &program_str,
            "--provider",
            "owned",
            "--proposer",
            "native",
        ],
        &provider_env,
    );
    assert_eq!(report["proposed"], true, "{report}");
    let card = &report["cards"][0];
    assert!(card["tags"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("scope-refinement-outperformed")));
    assert_eq!(
        card["gauges"]
            .as_array()
            .unwrap()
            .iter()
            .find(|gauge| gauge["gauge"] == "std.tokens")
            .unwrap()["candidate"],
        0.0
    );
    let campaign = env.run_json(
        &["--json", "campaign", report["campaign"].as_str().unwrap()],
        &[],
    );
    let events = campaign["events"].as_array().unwrap();
    assert!(events
        .iter()
        .any(|event| event["type"] == "candidate.refinement"
            && event["payload"]["status"] == "retained-original"
            && event["payload"]["comparison"]["status"] == "retained-original"));
    assert!(events
        .iter()
        .any(|event| event["type"] == "candidate.recorded"
            && event["payload"]["source"] == proposal["source"]));
    assert_eq!(
        bodies.lock().unwrap().len(),
        9,
        "two baseline calls twice, three model turns, a refinement critic, and one refined call"
    );
}

#[test]
fn ambiguous_shortcut_finding_remains_reviewable_and_testable() {
    let env = Env::new("shortcut-ambiguous");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write baseline");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);
    let candidate = program("high", "ticket.id", &env.dir);
    let replies = vec![
        serde_json::json!({
            "rationale": "raise urgent priority", "source": candidate,
            "edit_account": {"mechanism": "raise priority", "declarations": ["rule triage"],
                "expected_gauges": ["priority_correct"]},
        })
        .to_string(),
        serde_json::json!({
            "classification": "ambiguous", "source_quote": "priority \"high\"",
            "reason": "a constant may be legitimate domain routing",
        })
        .to_string(),
    ];
    let (base_url, bodies) = mock_coerce_sequence_endpoint(replies);
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "native",
        ],
        &[
            ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
            ("OPENAI_API_KEY", "test-key"),
            ("WHIPPLESCRIPT_COERCE_BASE_URL", &base_url),
            ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
        ],
    );
    assert_eq!(report["proposed"], true, "{report}");
    let card = &report["cards"][0];
    assert_eq!(card["shortcut"]["selected"]["classification"], "ambiguous");
    assert!(card["tags"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("shortcut-ambiguous")));
    assert_eq!(card["shortcut"]["excerpt_removed_by_revision"], false);
    let campaign = env.run_json(
        &["--json", "campaign", report["campaign"].as_str().unwrap()],
        &[],
    );
    assert!(!campaign["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|event| { event["type"] == "candidate.refinement" }));
    assert_eq!(bodies.lock().unwrap().len(), 2, "proposal and critic only");
}

#[test]
fn external_context_only_candidate_is_evaluated_and_adopted_against_exact_baseline() {
    exercise_external_context_candidate(false);
}

#[test]
fn native_patches_to_large_context_are_evaluated_recorded_and_adopted_exactly() {
    exercise_external_context_candidate(true);
}

fn exercise_external_context_candidate(native: bool) {
    let env = Env::new(if native {
        "native-context-patches"
    } else {
        "external-context"
    });
    let context_root = env.dir.join("context");
    fs::create_dir_all(&context_root).expect("context root");
    let context_file = context_root.join("AGENTS.md");
    let padding = if native {
        format!("\n{}", "Catalog reference text.\n".repeat(1700))
    } else {
        String::new()
    };
    let baseline_context = format!("Use long answers.{padding}");
    let candidate_context = format!("Use short answers.{padding}");
    fs::write(&context_file, &baseline_context).expect("baseline context");
    let skill_dir = context_root.join("skills/demo");
    fs::create_dir_all(&skill_dir).expect("skill directory");
    let skill_file = skill_dir.join("SKILL.md");
    let baseline_skill =
        "---\nname: demo\ndescription: Context skill marker baseline.\n---\n# demo\nRead project guidance.\n";
    let candidate_skill =
        "---\nname: demo\ndescription: Context skill marker candidate.\n---\n# demo\nRead project guidance.\n";
    fs::write(&skill_file, baseline_skill).expect("baseline skill");
    let judge = env.dir.join("always.py");
    fs::write(&judge, "import json\nprint(json.dumps({'ok': True}))\n").expect("judge");
    let program_path = env.dir.join("context.whip");
    let source = format!(
        r#"use std.files

workflow Context
input ticket Ticket

class Ticket {{ id string title string }}
class Done {{ ok bool }}

gauge quality {{
  judge via exec "python3 {}"
  expect P(ok) at least 0.5
}}

file store context_docs {{
  root "."
  allow read ["**"]
}}

agent helper {{
  provider owned
  profile "repo-reader"
  capacity 1
}}

rule begin
  when Ticket as ticket
  when helper is available
=> {{
  tell helper as turn
    with access to context_docs {{
      read ["**"]
    }}
  """markdown
  Classify {{ ticket.title }}.
  """
  after turn succeeds {{ record Done {{ ok true }} }}
}}
"#,
        judge.display()
    );
    fs::write(&program_path, &source).expect("program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let proposal_path = env.dir.join("candidate.whip");
    fs::write(&proposal_path, &source).expect("context-only proposal");
    let edits = serde_json::json!([
        {"path":"AGENTS.md","content":candidate_context},
        {"path":"skills/demo/SKILL.md","content":candidate_skill}
    ])
    .to_string();
    let account = serde_json::json!({"mechanism":"shorter project guidance",
        "declarations":[],"resources":["AGENTS.md","skills/demo/SKILL.md"],"expected_gauges":["std.tokens"]})
    .to_string();
    let (base_url, requests) = mock_harness_context_endpoint();
    let proposal_str = proposal_path.to_string_lossy().into_owned();
    let root_str = context_root.to_string_lossy().into_owned();
    let proposal = serde_json::json!({
        "rationale": "shorter project guidance",
        "source": source,
        "edit_account": serde_json::from_str::<Value>(&account).expect("fixture account"),
        "context_edits": [],
        "context_patches": [
            {"path":"AGENTS.md","find":"Use long answers.","replace":"Use short answers."},
            {"path":"skills/demo/SKILL.md","find":"Context skill marker baseline.","replace":"Context skill marker candidate."}
        ]
    }).to_string();
    let critic =
        serde_json::json!({"classification":"none", "source_path":"AGENTS.md", "source_quote":null,
        "reason":"general response length instruction"})
        .to_string();
    let (coerce_url, coerce_requests) =
        mock_coerce_sequence_endpoint(vec![proposal.clone(), critic, proposal]);
    let mut envs = vec![
        ("WHIPPLESCRIPT_IMPROVE_PROPOSALS", proposal_str.as_str()),
        ("WHIPPLESCRIPT_IMPROVE_CONTEXT_EDITS", edits.as_str()),
        ("WHIPPLESCRIPT_IMPROVE_EDIT_ACCOUNT", account.as_str()),
        ("WHIPPLESCRIPT_HARNESS_PROVIDER", "openai-generic"),
        ("WHIPPLESCRIPT_HARNESS_MODEL", "test-model"),
        ("WHIPPLESCRIPT_HARNESS_BASE_URL", base_url.as_str()),
        ("OPENAI_API_KEY", "test-key"),
    ];
    if native {
        envs.extend([
            ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
            ("WHIPPLESCRIPT_COERCE_BASE_URL", coerce_url.as_str()),
            ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
        ]);
    }
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "std.tokens",
            "--program",
            &program_str,
            "--context-root",
            &root_str,
            "--proposer",
            if native { "native" } else { "fixture" },
            "--provider",
            "owned",
        ],
        &envs,
    );
    assert_eq!(report["proposed"], true, "context-only gain: {report}");
    let card = &report["cards"][0];
    assert_eq!(card["edit"]["changed_resources"][0]["path"], "AGENTS.md");
    assert_eq!(
        card["edit"]["changed_resources"][1]["path"],
        "skills/demo/SKILL.md"
    );
    assert!(card["edit"]["changed_declarations"]
        .as_array()
        .expect("declaration changes")
        .is_empty());
    assert_eq!(
        fs::read_to_string(&context_file).expect("live context"),
        baseline_context,
        "evaluation must not change the live context"
    );
    assert_eq!(
        fs::read_to_string(&skill_file).expect("live skill"),
        baseline_skill
    );
    let seen = requests.lock().expect("harness requests");
    assert!(
        seen.iter().any(|body| body.contains("Use long answers.")),
        "baseline request lacked context"
    );
    assert!(
        seen.iter().any(|body| body.contains("Use short answers.")),
        "candidate request lacked context"
    );
    assert!(seen
        .iter()
        .any(|body| body.contains("Context skill marker baseline.")));
    assert!(seen
        .iter()
        .any(|body| body.contains("Context skill marker candidate.")));
    drop(seen);

    let target = format!("{}:K-1", report["campaign"].as_str().expect("campaign id"));
    fs::write(&context_file, "Human edit after campaign.").expect("human edit");
    let refusal = env.run_expect_failure(&["adopt", &target, "--program", &program_str]);
    assert!(
        refusal.contains("program or admitted context changed"),
        "{refusal}"
    );
    fs::write(&context_file, &baseline_context).expect("restore baseline");
    let adopted = env.run_json(
        &["--json", "adopt", &target, "--program", &program_str],
        &[],
    );
    assert_eq!(adopted["changed_resources"][0], "AGENTS.md");
    assert_eq!(adopted["changed_resources"][1], "skills/demo/SKILL.md");
    assert_eq!(
        fs::read_to_string(&context_file).expect("adopted context"),
        candidate_context
    );
    assert_eq!(
        fs::read_to_string(&skill_file).expect("adopted skill"),
        candidate_skill
    );
    if native {
        let detail = env.run_json(
            &[
                "--json",
                "campaign",
                report["campaign"].as_str().expect("campaign id"),
            ],
            &[],
        );
        let recorded = detail["events"]
            .as_array()
            .expect("campaign events")
            .iter()
            .find(|event| event["type"] == "candidate.recorded")
            .expect("recorded candidate");
        assert_eq!(
            recorded["payload"]["context_edits"][0]["content"],
            candidate_context
        );
        assert!(recorded["payload"].get("context_patches").is_none());
        let sent = coerce_requests.lock().expect("coerce requests");
        assert!(sent[0].contains("context_patches"));
        assert!(sent[0].contains("Canonical declaration identities"));
    }
}

#[test]
fn improve_campaign_proposes_dominant_candidate_and_adopts() {
    let env = Env::new("dominant");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    let baseline_source = program("low", "ticket.id", &env.dir);
    fs::write(&program_path, &baseline_source).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    dev_and_pin(&env, &program_str);

    // Ambient scoring landed live evidence rows from the dev run.
    let gauges = env.run_json(&["--json", "gauges"], &[]);
    let ambient: Vec<&str> = gauges["gauges"]
        .as_array()
        .expect("gauges array")
        .iter()
        .filter_map(|gauge| gauge["gauge"].as_str())
        .collect();
    assert!(
        ambient.contains(&"priority_correct"),
        "ambient scoring records declared exec gauges: {ambient:?}"
    );

    // The fixture proposer offers the fixed program (priority high).
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&candidate_path, program("high", "ticket.id", &env.dir)).expect("write candidate");

    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[
            (
                "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
                &candidate_path.to_string_lossy(),
            ),
            (
                "WHIPPLESCRIPT_IMPROVE_EDIT_ACCOUNT",
                r#"{"mechanism":"Raise ticket priority","declarations":["rule other"],"expected_gauges":["priority_correct"]}"#,
            ),
        ],
    );
    assert_eq!(report["schema"].as_str(), Some("whipplescript.improve.v0"));
    assert_eq!(report["proposed"].as_bool(), Some(true));
    assert_eq!(
        report["unheld_out"].as_bool(),
        Some(true),
        "one pinned scenario is below the sealing floor — tagged, never blocked"
    );
    let cards = report["cards"].as_array().expect("cards");
    assert_eq!(cards.len(), 1);
    let card = &cards[0];
    assert_eq!(card["proposable"].as_bool(), Some(true));
    assert_eq!(
        card["edit"]["status"].as_str(),
        Some("declarations-unaccounted")
    );
    assert_eq!(card["edit"]["unaccounted_declarations"][0], "rule triage");
    assert!(card["edit"]["changed_declarations"]
        .as_array()
        .expect("changed declarations")
        .iter()
        .any(|change| change["identity"].as_str() == Some("rule triage")));
    assert!(card["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .any(|tag| tag.as_str() == Some("edit-account-mismatch")));
    assert!(card["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .any(|tag| tag.as_str() == Some("unheld-out")));
    let focus_line = card["gauges"]
        .as_array()
        .expect("gauge lines")
        .iter()
        .find(|line| line["gauge"].as_str() == Some("priority_correct"))
        .expect("focus gauge line");
    assert_eq!(focus_line["role"].as_str(), Some("ascend"));
    assert_eq!(focus_line["delta"].as_str(), Some("better"));
    assert_eq!(focus_line["bar_met"].as_bool(), Some(true));

    // The campaign record folded.
    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let head = &campaigns["campaigns"].as_array().expect("campaigns")[0];
    assert_eq!(head["candidates"].as_i64(), Some(1));
    assert_eq!(head["proposed"].as_i64(), Some(1));
    let campaign_id = head["campaign"].as_str().expect("campaign id").to_owned();
    let campaign = env.run_json(&["--json", "campaign", &campaign_id], &[]);
    assert!(campaign["events"]
        .as_array()
        .expect("events")
        .iter()
        .any(|event| event["type"] == "candidate.recorded"
            && event["payload"]["edit"] == card["edit"]));

    // Propose-don't-apply: the program on disk is untouched until adoption.
    assert_eq!(
        fs::read_to_string(&program_path).expect("read program"),
        baseline_source
    );
    let target = format!("{campaign_id}:K-1");
    let adopted = env.run_json(
        &["--json", "adopt", &target, "--program", &program_str],
        &[],
    );
    assert_eq!(adopted["candidate"].as_str(), Some("K-1"));
    let after = fs::read_to_string(&program_path).expect("read program");
    assert!(after.contains("priority \"high\""), "candidate adopted");

    // Adoption refuses when mainline moved under the campaign — the file
    // now holds the adopted candidate, which no longer matches the
    // campaign's baseline hash.
    let stderr = env.run_expect_failure(&["adopt", &target, "--program", &program_str]);
    assert!(
        stderr.contains("changed since campaign"),
        "stale adoption refused honestly: {stderr}"
    );
}

#[test]
fn improve_refuses_dominated_candidate_as_tradeoff() {
    let env = Env::new("dominated");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    dev_and_pin(&env, &program_str);

    // The candidate improves the focus gauge but breaks the guarded gauge
    // (drops the ticket echo) — dominated, must not be proposed.
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&candidate_path, program("high", "\"wrong\"", &env.dir)).expect("write candidate");

    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            &candidate_path.to_string_lossy(),
        )],
    );
    assert_eq!(report["proposed"].as_bool(), Some(false));
    let cards = report["cards"].as_array().expect("cards");
    assert_eq!(cards.len(), 1);
    let card = &cards[0];
    assert_eq!(card["proposable"].as_bool(), Some(false));
    assert_eq!(
        card["tradeoff"].as_bool(),
        Some(true),
        "focus up + guard broken is a decision for the human, never an acceptance"
    );
    assert!(card["reasons"]
        .as_array()
        .expect("reasons")
        .iter()
        .any(|reason| reason.as_str().is_some_and(|r| r.contains("ticket_echoed"))));

    // The dominated candidate must not be adoptable as a proposal, but its
    // record exists for archaeology.
    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let head = &campaigns["campaigns"].as_array().expect("campaigns")[0];
    assert_eq!(head["candidates"].as_i64(), Some(1));
    assert_eq!(head["proposed"].as_i64(), Some(0));
    let campaign_id = head["campaign"].as_str().expect("campaign id").to_owned();

    // Adoption is reserved for proposed candidates: the dominated candidate
    // is recorded but never adoptable (the acceptance model's invariant has
    // no side door).
    let target = format!("{campaign_id}:K-1");
    let stderr = env.run_expect_failure(&["adopt", &target, "--program", &program_str]);
    assert!(
        stderr.contains("was not proposed"),
        "dominated candidate adoption must be refused: {stderr}"
    );
}

#[test]
fn answered_tradeoff_becomes_precedent_and_auto_resolves() {
    let env = Env::new("precedent");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    dev_and_pin(&env, &program_str);

    // The tradeoff candidate: improves the focus gauge, breaks the guard.
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&candidate_path, program("high", "\"wrong\"", &env.dir)).expect("write candidate");
    let candidate_env: (&str, &str) = (
        "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
        &candidate_path.to_string_lossy(),
    );

    // Campaign 1: surfaced as a tradeoff, not proposed.
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[candidate_env],
    );
    assert_eq!(report["proposed"].as_bool(), Some(false));
    let campaign_1 = report["campaign"].as_str().expect("campaign id").to_owned();
    let target_1 = format!("{campaign_1}:K-1");

    // A proposed candidate is not answerable; a tradeoff is.
    let answered = env.run_json(&["--json", "answer", &target_1, "--accept"], &[]);
    assert_eq!(answered["verdict"].as_str(), Some("accepted"));
    assert_eq!(answered["adoptable"].as_bool(), Some(true));

    // Double answers are refused until revoked.
    let stderr = env.run_expect_failure(&["answer", &target_1, "--reject"]);
    assert!(stderr.contains("already answered"), "{stderr}");

    // Campaign 2: the identical tradeoff now auto-resolves by precedent —
    // proposed, tagged, citing the human's answer.
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[candidate_env],
    );
    assert_eq!(
        report["proposed"].as_bool(),
        Some(true),
        "the Pareto-safe closure of an answered ask auto-accepts: {report}"
    );
    let card = &report["cards"].as_array().expect("cards")[0];
    assert!(card["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .any(|tag| tag.as_str() == Some("auto-resolved:precedent")));
    assert!(card["precedent"]
        .as_str()
        .expect("citation")
        .contains(&target_1));

    // The accepted tradeoff itself became adoptable via the answer.
    let adopted = env.run_json(
        &["--json", "adopt", &target_1, "--program", &program_str],
        &[],
    );
    assert_eq!(adopted["candidate"].as_str(), Some("K-1"));

    // Revoke the precedent; restore the baseline program; the same
    // tradeoff surfaces again — authority is gone.
    let revoked = env.run_json(&["--json", "answer", &target_1, "--revoke"], &[]);
    assert_eq!(revoked["verdict"].as_str(), Some("revoked"));
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("restore baseline");
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[candidate_env],
    );
    assert_eq!(
        report["proposed"].as_bool(),
        Some(false),
        "a revoked precedent grants nothing: {report}"
    );
    let card = &report["cards"].as_array().expect("cards")[0];
    assert_eq!(card["tradeoff"].as_bool(), Some(true));
}

const PREFIX_JUDGE: &str = r#"
import json, sys
record = json.load(sys.stdin)
priority = None
classified = False
for fact in record.get("facts", []):
    if fact.get("name") == "Assessment":
        priority = fact.get("value", {}).get("priority")
    if fact.get("name") == "Classified":
        classified = True
print(json.dumps({"ok": classified and priority == "high"}))
"#;

fn chained_program(priority: &str, judge_dir: &std::path::Path) -> String {
    let judge = judge_dir.join("judge_chain.py");
    format!(
        r#"workflow Triage

input ticket Ticket

class Ticket {{
  id string
  title string
}}

class Classified {{
  ticket string
  kind string
}}

class Assessment {{
  ticket string
  priority string
}}

mark "classified" after classify

gauge priority_correct {{
  judge via exec "python3 {judge}"
  expect P(ok) at least 0.5
}}

rule classify
  when Ticket as ticket
=> {{
  record Classified {{
    ticket ticket.id
    kind "bug"
  }}
}}

rule triage
  when Classified as c
=> {{
  record Assessment {{
    ticket c.ticket
    priority "{priority}"
  }}
}}
"#,
        judge = judge.display(),
    )
}

#[test]
fn mark_pinned_scenario_replays_prefix_and_regenerates_suffix() {
    let env = Env::new("mark-replay");
    fs::write(env.dir.join("judge_chain.py"), PREFIX_JUDGE).expect("write judge");
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, chained_program("low", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    // Baseline dev run stamps the mark when `classify` commits.
    let dev = env.run_json(
        &[
            "--store",
            &env.store,
            "--input",
            r#"{"ticket":{"id":"T-1","title":"Fix login"}}"#,
            "--json",
            "run",
            &program_str,
            "--provider",
            "fixture",
        ],
        &[],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();

    // Pin the frozen prefix at the mark.
    let pinned = env.run_json(
        &[
            "--store",
            &env.store,
            "--json",
            "pin",
            &instance,
            "at",
            "classified",
            "--as",
            "case-m",
        ],
        &[],
    );
    assert_eq!(pinned["mark"].as_str(), Some("classified"));
    assert!(
        pinned["cut_sequence"].as_i64().is_some(),
        "the mark event's sequence is the cut: {pinned}"
    );

    // Pinning at an unknown mark is refused with the stamped set.
    let stderr = env.run_expect_failure(&[
        "--store", &env.store, "pin", &instance, "at", "missing", "--as", "x",
    ]);
    assert!(stderr.contains("never reached mark"), "{stderr}");

    // Suppose under a candidate that fixes the suffix: the prefix replays,
    // only the suffix re-executes, and the gauge flips.
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&candidate_path, chained_program("high", &env.dir)).expect("write candidate");
    let supposed = env.run_json(
        &[
            "--json",
            "suppose",
            "case-m",
            "--program",
            &candidate_path.to_string_lossy(),
        ],
        &[],
    );
    assert_eq!(
        supposed["mode"].as_str(),
        Some("prefix-replay"),
        "mark pins regenerate from the frozen prefix: {supposed}"
    );
    let gauge = supposed["gauges"]
        .as_array()
        .expect("gauges")
        .iter()
        .find(|line| line["gauge"].as_str() == Some("priority_correct"))
        .expect("gauge line");
    assert_eq!(gauge["regenerated_passed"].as_bool(), Some(true));
    assert_eq!(
        gauge["recorded_passed"].as_bool(),
        Some(false),
        "the recorded run is the paired control"
    );
    assert!(gauge["tags"]
        .as_array()
        .expect("tags")
        .iter()
        .any(|tag| tag.as_str() == Some("prefix-replay")));
    let replay_note = supposed["skipped"]
        .as_array()
        .expect("skipped")
        .iter()
        .find(|entry| entry["gauge"].as_str() == Some("replay"))
        .expect("replay accounting note");
    assert!(
        replay_note["reason"]
            .as_str()
            .expect("reason")
            .contains("0 refires"),
        "the fact-recording prefix must not refire: {replay_note}"
    );

    // A campaign over the mark-pinned scenario: both arms regenerate from
    // the cut (paired), and the dominant candidate is proposed.
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            &candidate_path.to_string_lossy(),
        )],
    );
    assert_eq!(
        report["proposed"].as_bool(),
        Some(true),
        "prefix-paired evaluation proposes the dominant candidate: {report}"
    );
}

#[test]
fn settle_races_pinned_scenarios_and_stops_at_the_crossing() {
    let env = Env::new("settle-cross");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    // priority "high": every regeneration clears the P(ok) >= 0.5 bar.
    fs::write(&program_path, program("high", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let settled = env.run_json(
        &[
            "--json",
            "settle",
            "priority_correct",
            "--threshold",
            "2",
            "--certify",
            "--program",
            &program_str,
        ],
        &[],
    );
    assert_eq!(settled["schema"].as_str(), Some("whipplescript.settle.v0"));
    assert_eq!(settled["outcome"].as_str(), Some("certified"));
    assert_eq!(settled["reason"].as_str(), Some("threshold-crossed"));
    // The system chose N: two strong regenerations of the one pinned
    // scenario cross K=2 — the crossing needs no further exhaustion.
    assert_eq!(settled["n"].as_i64(), Some(2));
    assert_eq!(settled["level"].as_i64(), Some(2));
    assert!(
        settled["certificate"]
            .as_str()
            .is_some_and(|certificate| certificate.starts_with("ct-")),
        "--certify mints a certificate at the crossing: {settled}"
    );

    // Every settle regeneration landed in the evidence ledger.
    let gauges = env.run_json(&["--json", "gauges", "priority_correct"], &[]);
    let row = &gauges["gauges"].as_array().expect("gauges")[0];
    assert!(
        row["regen"].as_i64().unwrap_or(0) >= 2,
        "settle observations are ledger evidence: {gauges}"
    );
}

#[test]
fn settle_exhausts_to_an_honest_undetermined() {
    let env = Env::new("settle-dry");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    // priority "low": every regeneration is contrary, so a full pass over
    // the pinned pool adds no net evidence and settle stops itself.
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let settled = env.run_json(
        &[
            "--json",
            "settle",
            "priority_correct",
            "--certify",
            "--program",
            &program_str,
        ],
        &[],
    );
    assert_eq!(
        settled["outcome"].as_str(),
        Some("undetermined"),
        "exhaustion below the threshold never certifies: {settled}"
    );
    assert_eq!(settled["reason"].as_str(), Some("evidence-exhausted"));
    assert_eq!(settled["level"].as_i64(), Some(0));
    assert!(
        settled["certificate"].is_null(),
        "no certificate without a crossing: {settled}"
    );
}

#[test]
fn settle_refuses_a_gauge_without_a_bar() {
    let env = Env::new("settle-nobar");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("high", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    // ticket_echoed declares no `expect` bar: there is no decision to
    // settle, and the refusal says so instead of inventing one.
    let stderr = env.run_expect_failure(&["settle", "ticket_echoed", "--program", &program_str]);
    assert!(
        stderr.contains("has no bar"),
        "refusal names the missing bar: {stderr}"
    );
}

const CLASSIFY_EXEC: &str = r#"
import json
print(json.dumps({"kind": "bug"}))
"#;

/// A program whose PREFIX contains a settled exec effect created by a
/// non-consuming rule (`classify` reads Ticket without consuming it): the
/// refire shape from DR-0038 — after a candidate activation, the pre-cut
/// site re-derives the effect under a fresh id.
fn effectful_program(note: &str, judge_dir: &std::path::Path) -> String {
    let judge = judge_dir.join("judge_chain.py");
    let classify = judge_dir.join("classify_exec.py");
    format!(
        r#"use std.script
workflow Triage

input ticket Ticket

class Ticket {{
  id string
  title string
}}

class CheckOut {{
  kind string
}}

class Classified {{
  ticket string
  kind string
}}

class Assessment {{
  ticket string
  priority string
}}

class Final {{
  ticket string
  note string
}}

mark "assessed" after triage

gauge priority_correct {{
  judge via exec "python3 {judge}"
  expect P(ok) at least 0.5
}}

rule classify
  when Ticket as ticket
=> {{
  exec "python3 {classify}" -> CheckOut as chk

  after chk succeeds as c {{
    record Classified {{
      ticket ticket.id
      kind c.kind
    }}
  }}
}}

rule triage
  when Classified as c
=> {{
  record Assessment {{
    ticket c.ticket
    priority "high"
  }}
}}

rule finalize
  when Assessment as a
=> {{
  record Final {{
    ticket a.ticket
    note "{note}"
  }}
}}
"#,
        judge = judge.display(),
        classify = classify.display(),
    )
}

#[test]
fn refire_shaped_candidate_is_refused_pre_flight() {
    let env = Env::new("refire-preflight");
    fs::write(env.dir.join("judge_chain.py"), PREFIX_JUDGE).expect("write judge");
    fs::write(env.dir.join("classify_exec.py"), CLASSIFY_EXEC).expect("write classifier");
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, effectful_program("recorded", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    let dev = env.run_json(
        &[
            "--store",
            &env.store,
            "--input",
            r#"{"ticket":{"id":"T-1","title":"Fix login"}}"#,
            "--json",
            "run",
            &program_str,
            "--provider",
            "fixture",
        ],
        &[],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();
    let pinned = env.run_json(
        &[
            "--store", &env.store, "--json", "pin", &instance, "at", "assessed", "--as", "case-r",
        ],
        &[],
    );
    assert_eq!(pinned["scenario"].as_str(), Some("case-r"));

    // Control: the identical program needs no activation, so the prefix
    // replays and the settled exec effect dedupes exactly (no refire).
    let same = env.run_json(
        &["--json", "suppose", "case-r", "--program", &program_str],
        &[],
    );
    assert_eq!(
        same["mode"].as_str(),
        Some("prefix-replay"),
        "the identical program replays the frozen prefix: {same}"
    );

    // A textually-different candidate would activate a revision, and the
    // pre-cut `classify` site (non-consuming, Ticket still live) would
    // re-derive its settled exec effect — refused BEFORE any suffix work,
    // degrading honestly to input replay.
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&candidate_path, effectful_program("changed", &env.dir)).expect("write candidate");
    let supposed = env.run_json(
        &[
            "--json",
            "suppose",
            "case-r",
            "--program",
            &candidate_path.to_string_lossy(),
        ],
        &[],
    );
    assert_eq!(
        supposed["mode"].as_str(),
        Some("input-replay"),
        "refire-shaped candidates fall back to input replay: {supposed}"
    );
    let tagged = supposed["gauges"]
        .as_array()
        .expect("gauges")
        .iter()
        .any(|line| {
            line["tags"].as_array().is_some_and(|tags| {
                tags.iter()
                    .any(|tag| tag.as_str() == Some("replay-fallback"))
            })
        });
    assert!(
        tagged,
        "the fallback is honesty-tagged on the readings: {supposed}"
    );
}

#[test]
fn then_stage_ratchets_and_executes_when_its_target_is_met() {
    let env = Env::new("ratchet-stage");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    // Baseline: the echo is already correct (stage-1 target met at
    // baseline) while priority is low (stage 2 has room to ascend).
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    // Candidate A fixes priority but breaks the completed stage's echo:
    // refused by the stage-ratchet floor. Candidate B fixes priority and
    // holds the floor: proposed.
    let bad = env.dir.join("bad.whip");
    fs::write(&bad, program("high", "\"WRONG\"", &env.dir)).expect("write bad candidate");
    let good = env.dir.join("good.whip");
    fs::write(&good, program("high", "ticket.id", &env.dir)).expect("write good candidate");

    let report = env.run_json(
        &[
            "--json",
            "improve",
            "ticket_echoed>=0.5",
            "then",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            &format!("{}:{}", bad.display(), good.display()),
        )],
    );
    assert_eq!(
        report["stages_advanced"].as_i64(),
        Some(1),
        "the met stage-1 target advances the campaign: {report}"
    );
    assert_eq!(report["proposed"].as_bool(), Some(true));
    let cards = report["cards"].as_array().expect("cards");
    assert_eq!(cards.len(), 2, "both candidates carded: {report}");
    assert_eq!(cards[0]["proposable"].as_bool(), Some(false));
    assert!(
        cards[0]["reasons"]
            .as_array()
            .expect("reasons")
            .iter()
            .any(|reason| reason
                .as_str()
                .is_some_and(|reason| reason.contains("stage-ratchet floor"))),
        "the refusal cites the completed stage's floor: {}",
        cards[0]
    );
    assert_eq!(cards[1]["proposable"].as_bool(), Some(true));
    let lines = cards[1]["gauges"].as_array().expect("gauge lines");
    let priority = lines
        .iter()
        .find(|line| line["gauge"].as_str() == Some("priority_correct"))
        .expect("stage-2 focus line");
    assert_eq!(
        priority["role"].as_str(),
        Some("ascend"),
        "stage 2's gauge is the active focus: {report}"
    );
    assert_eq!(priority["delta"].as_str(), Some("better"));
    let echoed = lines
        .iter()
        .find(|line| line["gauge"].as_str() == Some("ticket_echoed"))
        .expect("completed-stage line");
    assert_eq!(
        echoed["role"].as_str(),
        Some("guard"),
        "the completed stage's gauge is guarded, not focus: {report}"
    );

    // The advancement is a campaign-record event.
    let campaign_id = report["campaign"].as_str().expect("campaign id");
    let detail = env.run_json(&["--json", "campaign", campaign_id], &[]);
    let advanced = detail["events"]
        .as_array()
        .map(|events| {
            events.iter().any(|event| {
                event["type"].as_str() == Some("stage.advanced")
                    || event["event_type"].as_str() == Some("stage.advanced")
            })
        })
        .unwrap_or(false);
    assert!(advanced, "stage.advanced recorded: {detail}");
}

#[test]
fn spend_cap_parks_and_resume_continues_the_campaign() {
    let env = Env::new("park-resume");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    // A configured price table (config-only by design): $1 per input
    // token, so the fixture proposer's synthetic 2-token turn costs $2
    // against a $1 cap.
    let prices_path = env.dir.join("providers.json");
    fs::write(
        &prices_path,
        r#"{"providers": [], "prices": [
            {"provider": "fixture-llm", "model": "m1",
             "input_micros_per_mtok": 1000000000000, "output_micros_per_mtok": 0}
        ]}"#,
    )
    .expect("write prices");
    let prices_str = prices_path.to_string_lossy().into_owned();
    let usage_env = ("WHIPPLESCRIPT_IMPROVE_PROPOSAL_USAGE", "fixture-llm/m1/2/0");

    // The first candidate is rejected (regressed echo, bar still unmet),
    // so the loop reaches the next round's cap check and PARKS: priced
    // spend made the cap bind.
    let bad = env.dir.join("bad.whip");
    fs::write(&bad, program("low", "\"WRONG\"", &env.dir)).expect("write bad");
    let bad_str = bad.to_string_lossy().into_owned();
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
            "--spend-cap",
            "$1",
            "--provider-config",
            &prices_str,
        ],
        &[("WHIPPLESCRIPT_IMPROVE_PROPOSALS", &bad_str), usage_env],
    );
    assert_eq!(
        report["parked"].as_bool(),
        Some(true),
        "priced spend crossed the cap: {report}"
    );
    assert_eq!(report["proposed"].as_bool(), Some(false));
    let campaign_id = report["campaign"].as_str().expect("campaign id").to_owned();
    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let row = campaigns["campaigns"]
        .as_array()
        .expect("campaigns")
        .iter()
        .find(|row| row["campaign"].as_str() == Some(campaign_id.as_str()))
        .expect("campaign row");
    assert_eq!(row["status"].as_str(), Some("parked"), "{campaigns}");
    assert_eq!(
        row["spent_micros"].as_i64(),
        Some(2_000_000),
        "record-time pricing recorded the turn's cost: {campaigns}"
    );

    // Resume with a fresh per-invocation allowance. The first proposal
    // repeats the prior candidate and is skipped before regeneration; the
    // next one is evaluated under a new candidate id.
    let good = env.dir.join("good.whip");
    fs::write(&good, program("high", "ticket.id", &env.dir)).expect("write good");
    let resumed_proposals = format!("{}:{}", bad.display(), good.display());
    let resumed = env.run_json(
        &[
            "--json",
            "improve",
            "--resume",
            &campaign_id,
            "--spend-cap",
            "$5",
            "--provider-config",
            &prices_str,
        ],
        &[
            ("WHIPPLESCRIPT_IMPROVE_PROPOSALS", &resumed_proposals),
            usage_env,
        ],
    );
    assert_eq!(
        resumed["campaign"].as_str(),
        Some(campaign_id.as_str()),
        "resume continues the SAME campaign: {resumed}"
    );
    assert_eq!(resumed["proposed"].as_bool(), Some(true), "{resumed}");
    let cards = resumed["cards"].as_array().expect("cards");
    assert_eq!(
        cards[0]["candidate"].as_str(),
        Some("K-3"),
        "candidate numbering continues across the park: {resumed}"
    );

    // The record tells the story: parked, resumed, then closed.
    let detail = env.run_json(&["--json", "campaign", &campaign_id], &[]);
    let event_types: Vec<String> = detail["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter_map(|event| {
            event["type"]
                .as_str()
                .or_else(|| event["event_type"].as_str())
                .map(str::to_owned)
        })
        .collect();
    assert!(detail["events"].as_array().unwrap().iter().any(|event| {
        event["type"] == "candidate.rejected"
            && event["payload"]["candidate"] == "K-2"
            && event["payload"]["tags"] == serde_json::json!(["exact-retry"])
    }));
    for expected in ["campaign.parked", "campaign.resumed", "campaign.closed"] {
        assert!(
            event_types.iter().any(|event| event == expected),
            "missing {expected}: {event_types:?}"
        );
    }

    // A closed campaign is not resumable — the refusal says why.
    let stderr = env.run_expect_failure(&["improve", "--resume", &campaign_id]);
    assert!(
        stderr.contains("not parked"),
        "refusal names the status: {stderr}"
    );
}

#[test]
fn settle_spend_cap_cannot_bind_on_unpriced_usage() {
    // The guardrail is currency: fixture regenerations record no provider
    // usage, so a tiny cap has nothing priced to bind on and settle still
    // reaches its verdict — the honest unpriced posture, never a phantom
    // stop.
    let env = Env::new("settle-cap");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("high", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let settled = env.run_json(
        &[
            "--json",
            "settle",
            "priority_correct",
            "--threshold",
            "2",
            "--spend-cap",
            "$0.01",
            "--program",
            &program_str,
        ],
        &[],
    );
    assert_eq!(
        settled["outcome"].as_str(),
        Some("bar-cleared"),
        "{settled}"
    );
    assert_eq!(settled["spent_micros"].as_i64(), Some(0));
}

#[test]
fn suppose_reads_out_p_better_from_the_paired_sign_test() {
    let env = Env::new("suppose-estimator");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    // Regenerate under a candidate that flips the failing bar: one
    // discordant pair, Jeffreys ⇒ P(better) ≈ 0.818.
    let candidate = env.dir.join("candidate.whip");
    fs::write(&candidate, program("high", "ticket.id", &env.dir)).expect("write candidate");
    let supposed = env.run_json(
        &[
            "--store",
            &env.store,
            "--json",
            "suppose",
            "case-1",
            "--program",
            &candidate.to_string_lossy(),
        ],
        &[],
    );
    let lines = supposed["gauges"].as_array().expect("gauges");
    let priority = lines
        .iter()
        .find(|line| line["gauge"].as_str() == Some("priority_correct"))
        .expect("focus line");
    let p_better = priority["p_better"].as_f64().expect("readout present");
    assert!(
        (p_better - 0.8183).abs() < 1e-3,
        "one discordant win under Jeffreys: {supposed}"
    );
    let echoed = lines
        .iter()
        .find(|line| line["gauge"].as_str() == Some("ticket_echoed"))
        .expect("guard line");
    assert!(
        (echoed["p_better"].as_f64().expect("readout") - 0.5).abs() < 1e-9,
        "a concordant pair is dead even: {supposed}"
    );
}

#[test]
fn settle_reads_out_p_bar_met_alongside_the_walk() {
    let env = Env::new("settle-estimator");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("high", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let settled = env.run_json(
        &[
            "--json",
            "settle",
            "priority_correct",
            "--threshold",
            "2",
            "--program",
            &program_str,
        ],
        &[],
    );
    assert_eq!(settled["outcome"].as_str(), Some("bar-cleared"));
    let p_bar_met = settled["p_bar_met"].as_f64().expect("readout present");
    assert!(
        p_bar_met > 0.8,
        "two strong observations against the 0.5 chance bar: {settled}"
    );
}

#[test]
fn sustained_live_contradiction_reopens_an_answered_call() {
    let env = Env::new("reopener");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    // Surface a tradeoff and ACCEPT it: the answered call the ledger will
    // later contradict.
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&candidate_path, program("high", "\"wrong\"", &env.dir)).expect("write candidate");
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            &candidate_path.to_string_lossy(),
        )],
    );
    let campaign_id = report["campaign"].as_str().expect("campaign id").to_owned();
    let target = format!("{campaign_id}:K-1");
    let answered = env.run_json(&["--json", "answer", &target, "--accept"], &[]);
    assert_eq!(answered["verdict"].as_str(), Some("accepted"));

    // No flag yet: the answer just weighed all the evidence there is.
    let gauges = env.run_json(&["--json", "gauges"], &[]);
    assert_eq!(
        gauges["contradictions"].as_array().map(Vec::len),
        Some(0),
        "{gauges}"
    );

    // The world drifts: the judge starts failing what the answer accepted
    // (second-granularity timestamps need the answer strictly behind the
    // ambient rows).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fs::write(
        env.dir.join("judge_priority.py"),
        "import json\nprint(json.dumps({\"ok\": False}))\n",
    )
    .expect("drift judge");

    // Three live runs of the accepted program: each ambient row tightens
    // the contradiction posterior against the answer-time operating point.
    for _ in 0..3 {
        env.run_json(
            &[
                "--store",
                &env.store,
                "--input",
                r#"{"ticket":{"id":"T-1","title":"Fix login"}}"#,
                "--json",
                "run",
                &candidate_path.to_string_lossy(),
                "--provider",
                "fixture",
            ],
            &[],
        );
    }

    let gauges = env.run_json(&["--json", "gauges"], &[]);
    let flags = gauges["contradictions"].as_array().expect("contradictions");
    let flag = flags
        .iter()
        .find(|flag| flag["gauge"].as_str() == Some("priority_correct"))
        .unwrap_or_else(|| panic!("sustained live failures raise the flag: {gauges}"));
    assert!(
        flag["p_worse"].as_f64().expect("posterior") > 0.9,
        "{gauges}"
    );
    assert!(
        flag["precedent"]
            .as_str()
            .expect("citation")
            .contains(&target),
        "the flag cites the answered call: {gauges}"
    );

    // Advisory only: the precedent still stands until the human revokes.
    let revoked = env.run_json(&["--json", "answer", &target, "--revoke"], &[]);
    assert_eq!(revoked["verdict"].as_str(), Some("revoked"));
}

/// A minimal OpenAI-compatible chat-completions endpoint: answers every
/// request with the given verdict JSON and collects request bodies so the
/// test can assert what the judge actually asked.
fn mock_coerce_endpoint(
    verdict: &'static str,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    mock_coerce_sequence_endpoint(vec![verdict.to_owned()])
}

fn mock_harness_context_endpoint() -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind harness endpoint");
    let url = format!("http://{}", listener.local_addr().expect("address"));
    let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let collected = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut raw = Vec::new();
            let mut buffer = [0u8; 4096];
            let header_end = loop {
                let Ok(n) = stream.read(&mut buffer) else {
                    break 0;
                };
                if n == 0 {
                    break 0;
                }
                raw.extend_from_slice(&buffer[..n]);
                if let Some(pos) = raw.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            if header_end == 0 {
                continue;
            }
            let header = String::from_utf8_lossy(&raw[..header_end]);
            let length: usize = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse().ok())
                })
                .unwrap_or(0);
            while raw.len() < header_end + length {
                let Ok(n) = stream.read(&mut buffer) else {
                    break;
                };
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..n]);
            }
            let body = String::from_utf8_lossy(&raw[header_end..]).into_owned();
            let candidate = body.contains("Use short answers.");
            collected.lock().expect("requests").push(body);
            let prompt_tokens = if candidate { 5 } else { 80 };
            let reply = serde_json::json!({
                "choices": [{"message": {"role": "assistant", "content": "finished"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": 1,
                    "total_tokens": prompt_tokens + 1},
            }).to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                reply.len(), reply,
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (url, requests)
}

fn mock_coerce_sequence_endpoint(
    verdicts: Vec<String>,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    mock_coerce_response_sequence_endpoint(
        verdicts
            .into_iter()
            .map(|content| {
                serde_json::json!({
                    "choices": [{"message": {"content": content}}],
                    "usage": {"input_tokens": 3, "output_tokens": 2}
                })
            })
            .collect(),
    )
}

fn mock_coerce_response_sequence_endpoint(
    replies: Vec<Value>,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock endpoint");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let collected = bodies.clone();
    std::thread::spawn(move || {
        let mut response_index = 0usize;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut raw = Vec::new();
            let mut buffer = [0u8; 4096];
            let body_start = loop {
                let Ok(n) = stream.read(&mut buffer) else {
                    break 0;
                };
                if n == 0 {
                    break 0;
                }
                raw.extend_from_slice(&buffer[..n]);
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            if body_start == 0 {
                continue;
            }
            let header = String::from_utf8_lossy(&raw[..body_start]).into_owned();
            let content_length: usize = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap_or(0))
                })
                .unwrap_or(0);
            while raw.len() < body_start + content_length {
                let Ok(n) = stream.read(&mut buffer) else {
                    break;
                };
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..n]);
            }
            let body = String::from_utf8_lossy(&raw[body_start..]).into_owned();
            collected.lock().expect("bodies lock").push(body);
            let reply = replies
                .get(response_index)
                .or_else(|| replies.last())
                .expect("mock endpoint has a response");
            response_index += 1;
            let reply = serde_json::to_string(reply).expect("encode response");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                reply.len(),
                reply
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (base_url, bodies)
}

#[test]
fn native_context_patches_without_admitted_snapshot_are_refused() {
    let proposal = serde_json::json!({
        "source": "", "rationale": "PRIVATE_PARTIAL_MODEL_OUTPUT",
        "context_edits": [], "context_patches": [{"path":"AGENTS.md","find":"old","replace":"new"}],
        "edit_account": {"mechanism":"edit guidance", "declarations":[], "resources":["AGENTS.md"], "expected_gauges":["priority_correct"]}
    });
    assert_failed_native_proposal_retains_usage(
        serde_json::json!({
            "status":"completed", "output_text":proposal.to_string(),
            "usage":{"input_tokens":12,"output_tokens":4}
        }),
        "context patches without --context-root",
        "native-context-without-snapshot",
    );
}

#[test]
fn native_proposer_output_limit_preserves_failure_and_priced_usage() {
    assert_failed_native_proposal_retains_usage(
        serde_json::json!({
            "status": "incomplete",
            "incomplete_details": {"reason": "max_output_tokens"},
            "output_text": "PRIVATE_PARTIAL_MODEL_OUTPUT",
            "usage": {"input_tokens": 12, "output_tokens": 4}
        }),
        "WHIPPLESCRIPT_COERCE_MAX_TOKENS",
        "native-proposal-output-limit",
    );
}

#[test]
fn native_proposer_missing_source_retains_priced_usage() {
    assert_failed_native_proposal_retains_usage(
        serde_json::json!({
            "status": "completed",
            "output_text": "{\"rationale\":\"PRIVATE_PARTIAL_MODEL_OUTPUT\"}",
            "usage": {"input_tokens": 12, "output_tokens": 4}
        }),
        "proposer returned no source",
        "native-proposal-missing-source",
    );
}

fn assert_failed_native_proposal_retains_usage(response: Value, diagnostic: &str, label: &str) {
    let env = Env::new(label);
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("high", "ticket.id", &env.dir)).expect("program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);
    let (base_url, _) = mock_coerce_response_sequence_endpoint(vec![response]);
    let prices_path = env.dir.join("providers.json");
    fs::write(
        &prices_path,
        r#"{"providers": [], "prices": [
        {"provider":"openai", "model":"test-model",
         "input_micros_per_mtok":1000000000000,
         "output_micros_per_mtok":1000000000000}
    ]}"#,
    )
    .expect("prices");
    let output = env
        .command()
        .args([
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "native",
            "--provider",
            "fixture",
            "--provider-config",
            &prices_path.to_string_lossy(),
        ])
        .env("WHIPPLESCRIPT_COERCE_PROVIDER", "openai")
        .env("OPENAI_API_KEY", "test-key")
        .env("WHIPPLESCRIPT_COERCE_BASE_URL", base_url)
        .env("WHIPPLESCRIPT_COERCE_MODEL", "test-model")
        .output()
        .expect("improve");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(diagnostic), "{stderr}");
    assert!(!stderr.contains("PRIVATE_PARTIAL_MODEL_OUTPUT"));
    let campaign = env.run_json(&["--json", "campaign", "C-1"], &[]);
    let events = campaign["events"].as_array().expect("events");
    let spend = events
        .iter()
        .find(|event| {
            event["type"] == "campaign.spend"
                && event["payload"]["what"] == "proposer turn (failed)"
        })
        .expect("failed turn usage");
    assert_eq!(spend["payload"]["tokens"], 16);
    assert_eq!(spend["payload"]["cost_micros"], 16_000_000);
    assert_eq!(spend["payload"]["priced"], true);
    assert!(events
        .iter()
        .any(|event| event["type"] == "campaign.failed"));
    assert!(!campaign
        .to_string()
        .contains("PRIVATE_PARTIAL_MODEL_OUTPUT"));
    assert!(!events
        .iter()
        .any(|event| event["type"] == "candidate.recorded"));
}

#[test]
fn failed_native_critic_retains_priced_usage_without_vetoing_candidate() {
    assert_failed_auxiliary_turn(false, false, false, false);
}

#[test]
fn failed_native_generalization_retains_priced_usage_and_original_candidate() {
    assert_failed_auxiliary_turn(true, false, false, false);
}

#[test]
fn capped_campaign_stops_after_unpriced_failed_critic() {
    assert_failed_auxiliary_turn(false, true, false, true);
}

#[test]
fn capped_campaign_stops_after_revision_failure_without_usage() {
    assert_failed_auxiliary_turn(true, true, true, true);
}

#[test]
fn uncapped_campaign_keeps_unknown_failed_critic_cost_visible() {
    assert_failed_auxiliary_turn(false, true, false, false);
}

fn assert_failed_auxiliary_turn(
    generalization: bool,
    unknown_cost: bool,
    missing_usage: bool,
    capped: bool,
) {
    let stopped = capped && unknown_cost;
    let env = Env::new(if generalization {
        "failed-generalization"
    } else {
        "failed-critic"
    });
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir))
        .expect("failed native turn fixture");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);
    let candidate = program(
        "high",
        if generalization {
            "\"T-1\""
        } else {
            "ticket.id"
        },
        &env.dir,
    );
    let proposal = serde_json::json!({"rationale":"repair priority", "source":candidate,
        "edit_account":{"mechanism":"repair priority", "declarations":["rule triage"],
                        "expected_gauges":["priority_correct"]}});
    let envelope = |content: String| {
        serde_json::json!({
            "output":[{"type":"message","content":[{"type":"output_text","text":content}]}],
            "usage":{"input_tokens":11,"output_tokens":5,"total_tokens":16}
        })
    };
    let mut replies = vec![envelope(proposal.to_string())];
    if generalization {
        replies.push(envelope(
            serde_json::json!({"classification":"clear",
            "source_quote":"ticket \"T-1\"", "reason":"copies one pinned case id"})
            .to_string(),
        ));
    }
    let mut failed = envelope("PRIVATE_PARTIAL_MODEL_OUTPUT".to_owned());
    failed["status"] = serde_json::json!("incomplete");
    failed["incomplete_details"] = serde_json::json!({"reason":"max_output_tokens"});
    if missing_usage {
        failed
            .as_object_mut()
            .expect("response object")
            .remove("usage");
    }
    replies.push(failed);
    let expected_calls = replies.len();
    let (base_url, bodies) = mock_coerce_response_sequence_endpoint(replies);
    let prices_path = env.dir.join("providers.json");
    fs::write(
        &prices_path,
        if unknown_cost {
            r#"{"providers":[],"prices":[]}"#
        } else {
            r#"{"providers":[],"prices":[{"provider":"openai","model":"test-model",
        "input_micros_per_mtok":1000000000000,"output_micros_per_mtok":1000000000000}]}"#
        },
    )
    .expect("failed native turn fixture");
    let mut command = env.command();
    command
        .args([
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "native",
            "--provider-config",
            &prices_path.to_string_lossy(),
        ])
        .env("WHIPPLESCRIPT_COERCE_PROVIDER", "openai")
        .env("OPENAI_API_KEY", "test-key")
        .env("WHIPPLESCRIPT_COERCE_BASE_URL", base_url)
        .env("WHIPPLESCRIPT_COERCE_MODEL", "test-model");
    if capped {
        command.args(["--spend-cap", "$100"]);
    }
    let output = command.output().expect("failed native turn fixture");
    if stopped {
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("unaccounted provider use"));
    } else {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value =
            serde_json::from_slice(&output.stdout).expect("failed native turn fixture");
        assert_eq!(report["proposed"], true, "{report}");
    }
    let campaign = env.run_json(&["--json", "campaign", "C-1"], &[]);
    let events = campaign["events"]
        .as_array()
        .expect("failed native turn fixture");
    let what = if generalization {
        "shortcut generalization turn (failed)"
    } else {
        "shortcut critic turn (failed)"
    };
    let failed_spend = events
        .iter()
        .find(|event| event["type"] == "campaign.spend" && event["payload"]["what"] == what)
        .expect("failed native turn fixture");
    assert_eq!(
        failed_spend["payload"]["tokens"],
        if missing_usage {
            Value::Null
        } else {
            serde_json::json!(16)
        }
    );
    assert_eq!(failed_spend["payload"]["priced"], !unknown_cost);
    assert_eq!(failed_spend["payload"]["unaccounted"], unknown_cost);
    assert_eq!(
        failed_spend["payload"]["cost_micros"],
        if unknown_cost { 0 } else { 16_000_000 }
    );
    assert!(!campaign
        .to_string()
        .contains("PRIVATE_PARTIAL_MODEL_OUTPUT"));
    if generalization {
        assert!(events
            .iter()
            .any(|event| event["type"] == "candidate.refinement"
                && event["payload"]["status"] == "turn-failed"));
    } else {
        assert!(events
            .iter()
            .any(|event| event["type"] == "candidate.shortcut_assessed"
                && event["payload"]["status"] == "failed"));
    }
    assert_eq!(
        events
            .iter()
            .any(|event| event["type"] == "campaign.failed"),
        stopped
    );
    if !stopped {
        assert!(events
            .iter()
            .any(|event| event["type"] == "candidate.recorded"
                && event["payload"]["source"] == candidate));
    }
    assert_eq!(
        bodies.lock().expect("failed native turn fixture").len(),
        expected_calls
    );
}

fn coerce_judge_program(judge_dir: &std::path::Path) -> String {
    let echo_judge = judge_dir.join("judge_echo.py");
    format!(
        r#"workflow Triage

input ticket Ticket

class Ticket {{
  id string
  title string
}}

class Verdict {{
  ok bool
}}

class Assessment {{
  ticket string
  priority string
}}

coerce AssessQuality(title string, priority string) -> Verdict {{
  prompt """markdown
  Was "{{{{ title }}}}" triaged well at priority {{{{ priority }}}}?

  {{{{ ctx.output_format }}}}
  """
}}

gauge quality {{
  judge via coerce AssessQuality(input.ticket.title, facts.Assessment.priority)
  expect P(ok) at least 0.5
}}

gauge ticket_echoed {{
  judge via exec "python3 {echo_judge}"
}}

rule triage
  when Ticket as ticket
=> {{
  record Assessment {{
    ticket ticket.id
    priority "high"
  }}
}}
"#,
        echo_judge = echo_judge.display(),
    )
}

#[test]
fn coerce_judge_scores_with_explicitly_bound_arguments() {
    let env = Env::new("coerce-judge");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, coerce_judge_program(&env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let (base_url, bodies) = mock_coerce_endpoint(r#"{"ok": true}"#);
    let settled = env.run_json(
        &[
            "--json",
            "settle",
            "quality",
            "--threshold",
            "2",
            "--program",
            &program_str,
        ],
        &[
            ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
            ("OPENAI_API_KEY", "test-key"),
            ("WHIPPLESCRIPT_COERCE_BASE_URL", &base_url),
            ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
        ],
    );
    assert_eq!(
        settled["outcome"].as_str(),
        Some("bar-cleared"),
        "the coerce judge scored the regenerations: {settled}"
    );
    assert_eq!(settled["n"].as_i64(), Some(2));

    // The judge asked with the RESOLVED bindings: the input title and the
    // recorded fact's field, rendered through the coerce's own prompt.
    let bodies = bodies.lock().expect("bodies");
    assert!(!bodies.is_empty(), "the mock endpoint was called");
    assert!(
        bodies[0].contains("Fix login") && bodies[0].contains("high"),
        "resolved argument values reach the prompt: {}",
        bodies[0]
    );
}

#[test]
fn evidence_verb_routes_to_the_gauge_view_and_instance_subcommand() {
    let env = Env::new("evidence-routing");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("high", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    let instance = dev_and_pin(&env, &program_str);

    // Bare `whip evidence` = the gauge evidence view (naming settled
    // 2026-07-14: subcommand split, the estimate view owns the verb).
    let view = env.run_json(&["--json", "evidence"], &[]);
    assert_eq!(view["schema"].as_str(), Some("whipplescript.gauges.v0"));

    // `whip evidence instance <id>` = the runtime evidence chain.
    let chain = env.run_json(
        &[
            "--store", &env.store, "--json", "evidence", "instance", &instance,
        ],
        &[],
    );
    assert!(
        chain.get("evidence").is_some() || chain.get("instance_id").is_some(),
        "instance evidence chain renders: {chain}"
    );
}

#[test]
fn judge_turns_are_priced_spend_and_bind_the_settle_cap() {
    let env = Env::new("judge-spend");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, coerce_judge_program(&env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    // $1 per token: each judged regeneration costs $5 (3 in + 2 out).
    let prices_path = env.dir.join("providers.json");
    fs::write(
        &prices_path,
        r#"{"providers": [], "prices": [
            {"provider": "openai-generic", "model": "test-model",
             "input_micros_per_mtok": 1000000000000,
             "output_micros_per_mtok": 1000000000000}
        ]}"#,
    )
    .expect("write prices");

    let (base_url, _bodies) = mock_coerce_endpoint(r#"{"ok": true}"#);
    let settled = env.run_json(
        &[
            "--json",
            "settle",
            "quality",
            "--threshold",
            "5",
            "--spend-cap",
            "$4",
            "--provider-config",
            &prices_path.to_string_lossy(),
            "--program",
            &program_str,
        ],
        &[
            ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
            ("OPENAI_API_KEY", "test-key"),
            ("WHIPPLESCRIPT_COERCE_BASE_URL", &base_url),
            ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
        ],
    );
    assert_eq!(
        settled["outcome"].as_str(),
        Some("undetermined"),
        "the judge turn's priced cost binds the cap: {settled}"
    );
    assert_eq!(settled["reason"].as_str(), Some("spend-cap-reached"));
    assert_eq!(
        settled["spent_micros"].as_i64(),
        Some(5_000_000),
        "one $5 judged regeneration before the cap check: {settled}"
    );
}

/// The improve `--spend-cap` must bound the candidate/baseline programs' OWN
/// provider spend (their body `coerce`/agent effects), not only judge +
/// proposer turns. Regression for the guardrail silently failing to bind when
/// the dominant cost is the workflow itself (a free exec gauge + a zero-usage
/// fixture proposer leave workflow spend the ONLY thing that can cross the cap).
#[test]
fn improve_spend_cap_binds_on_the_workflows_own_coerce_spend() {
    let env = Env::new("workflow-spend-cap");
    write_judges(&env.dir);
    let priority_judge = env.dir.join("judge_priority.py");
    // A program whose RULE BODY runs a coerce (priced provider spend), scored
    // by a FREE exec gauge — so nothing but the body coerce can bind the cap.
    let program_src = format!(
        r#"workflow Triage

input ticket Ticket

class Ticket {{
  id string
  title string
}}

class Verdict {{
  ok bool
}}

class Assessment {{
  ticket string
  priority string
}}

coerce Classify(title string) -> Verdict {{
  prompt """markdown
  Is "{{{{ title }}}}" ok?

  {{{{ ctx.output_format }}}}
  """
}}

gauge priority_correct {{
  judge via exec "python3 {priority_judge}"
  expect P(ok) at least 0.5
}}

rule triage
  when Ticket as ticket
=> {{
  coerce Classify(ticket.title) as verdict
  after verdict succeeds as v {{
    record Assessment {{
      ticket ticket.id
      priority "low"
    }}
  }}
}}
"#,
        priority_judge = priority_judge.display(),
    );
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, &program_src).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    // $1 per token — 1e12 micros per Mtok: the mock coerce returns 3 in + 2
    // out = $5 per body call.
    // The coerce RUN records the worker's agent provider (`fixture`) and the
    // model it resolved, so std.spend prices it under (fixture, test-model).
    //
    // This entry used to be keyed on an EMPTY model, because a settled coercion
    // recorded none — and an empty key is not something a real price table has.
    // A table written from a provider's list would have failed to price every
    // coercion, and an unpriced reading is skipped rather than reported, so the
    // cap could not bind on coerce spend at all. The run records its model now.
    let prices_path = env.dir.join("providers.json");
    fs::write(
        &prices_path,
        r#"{"providers": [], "prices": [
            {"provider": "fixture", "model": "test-model",
             "input_micros_per_mtok": 1000000000000,
             "output_micros_per_mtok": 1000000000000}
        ]}"#,
    )
    .expect("write prices");
    let prices_str = prices_path.to_string_lossy().into_owned();

    let (base_url, _bodies) = mock_coerce_endpoint(r#"{"ok": true}"#);
    let coerce_env: [(&str, &str); 4] = [
        ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
        ("OPENAI_API_KEY", "test-key"),
        ("WHIPPLESCRIPT_COERCE_BASE_URL", &base_url),
        ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
    ];

    // Pin a scenario (the body coerce runs via the mock endpoint here too).
    let dev = env.run_json(
        &[
            "--store",
            &env.store,
            "--input",
            r#"{"ticket":{"id":"T-1","title":"Fix login"}}"#,
            "--json",
            "run",
            &program_str,
            "--provider",
            "fixture",
        ],
        &coerce_env,
    );
    let instance = dev["instance_id"].as_str().expect("instance id").to_owned();
    env.run_json(
        &[
            "--store", &env.store, "--json", "pin", &instance, "--as", "case-1",
        ],
        &[],
    );

    // A fixture proposer with NO usage env => zero proposer spend. The exec
    // gauge is free => zero judge spend. Only the baseline body coerce ($5)
    // accrues, and it must cross the $4 cap and park BEFORE any proposal.
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
            "--spend-cap",
            "$4",
            "--provider-config",
            &prices_str,
        ],
        &coerce_env,
    );
    assert_eq!(
        report["parked"].as_bool(),
        Some(true),
        "the workflow's own coerce spend must bind the cap: {report}"
    );
    assert_eq!(
        report["proposed"].as_bool(),
        Some(false),
        "parked before proposing anything: {report}"
    );
    // The campaign record shows the recorded workflow spend crossed the $4 cap.
    let campaign_id = report["campaign"].as_str().expect("campaign id").to_owned();
    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let row = campaigns["campaigns"]
        .as_array()
        .expect("campaigns")
        .iter()
        .find(|row| row["campaign"].as_str() == Some(campaign_id.as_str()))
        .expect("campaign row");
    assert_eq!(row["status"].as_str(), Some("parked"), "{campaigns}");
    assert!(
        row["spent_micros"].as_i64().unwrap_or(0) >= 4_000_000,
        "workflow coerce spend recorded against the cap: {campaigns}"
    );
}

#[test]
fn parallel_evaluation_pairs_scenarios_and_records_judge_spend() {
    let env = Env::new("parallel-eval");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    let baseline_source = coerce_judge_program(&env.dir);
    fs::write(&program_path, &baseline_source).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();

    // Four pinned scenarios: enough to engage sealing (2 open / 2 sealed)
    // and to put more than one evaluation on the pool at once.
    for index in 1..=4 {
        let dev = env.run_json(
            &[
                "--store",
                &env.store,
                "--input",
                &format!(r#"{{"ticket":{{"id":"T-{index}","title":"Fix login"}}}}"#),
                "--json",
                "run",
                &program_str,
                "--provider",
                "fixture",
            ],
            &[],
        );
        let instance = dev["instance_id"].as_str().expect("instance id").to_owned();
        env.run_json(
            &[
                "--store",
                &env.store,
                "--json",
                "pin",
                &instance,
                "--as",
                &format!("case-{index}"),
            ],
            &[],
        );
    }

    let prices_path = env.dir.join("providers.json");
    fs::write(
        &prices_path,
        r#"{"providers": [], "prices": [
            {"provider": "openai-generic", "model": "test-model",
             "input_micros_per_mtok": 1000000000000,
             "output_micros_per_mtok": 1000000000000}
        ]}"#,
    )
    .expect("write prices");
    let (base_url, _bodies) = mock_coerce_endpoint(r#"{"ok": true}"#);

    // A textually-different candidate (no behavioral change to the focus):
    // it evaluates, spends judge turns, and is refused — the spend record
    // is the point.
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(
        &candidate_path,
        baseline_source.replace("\"high\"", "\"low\""),
    )
    .expect("write candidate");

    let report = env.run_json(
        &[
            "--json",
            "improve",
            "ticket_echoed",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
            "--provider-config",
            &prices_path.to_string_lossy(),
        ],
        &[
            (
                "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
                &candidate_path.to_string_lossy(),
            ),
            ("WHIPPLESCRIPT_EVAL_CONCURRENCY", "4"),
            ("WHIPPLESCRIPT_COERCE_PROVIDER", "openai-generic"),
            ("OPENAI_API_KEY", "test-key"),
            ("WHIPPLESCRIPT_COERCE_BASE_URL", &base_url),
            ("WHIPPLESCRIPT_COERCE_MODEL", "test-model"),
        ],
    );
    assert_eq!(
        report["unheld_out"].as_bool(),
        Some(false),
        "four scenarios engage sealing: {report}"
    );
    // Pairing survives the pool: every gauge line compares per-scenario
    // pairs, and the echo gauge (unchanged by the candidate) reads even.
    let card = &report["cards"].as_array().expect("cards")[0];
    let echoed = card["gauges"]
        .as_array()
        .expect("gauge lines")
        .iter()
        .find(|line| line["gauge"].as_str() == Some("ticket_echoed"))
        .expect("echo line");
    assert_eq!(
        echoed["delta"].as_str(),
        Some("in-band"),
        "index-aligned pairing under parallel evaluation: {report}"
    );

    // Judge turns were recorded as priced campaign spend: baseline open
    // (2) + baseline sealed (2) + candidate open (2) coerce turns at $5
    // each = $30 total.
    let campaign_id = report["campaign"].as_str().expect("campaign id");
    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let row = campaigns["campaigns"]
        .as_array()
        .expect("campaigns")
        .iter()
        .find(|row| row["campaign"].as_str() == Some(campaign_id))
        .expect("campaign row");
    assert_eq!(
        row["spent_micros"].as_i64(),
        Some(30_000_000),
        "judge turns are priced spend: {campaigns}"
    );
    let detail = env.run_json(&["--json", "campaign", campaign_id], &[]);
    let spend_whats: Vec<String> = detail["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter(|event| {
            event["type"].as_str().or(event["event_type"].as_str()) == Some("campaign.spend")
        })
        .filter_map(|event| {
            event["payload"]["what"]
                .as_str()
                .or(event["what"].as_str())
                .map(str::to_owned)
        })
        .collect();
    assert!(
        spend_whats.iter().any(|what| what.contains("baseline")),
        "baseline judge spend recorded: {spend_whats:?} {detail}"
    );
}

#[test]
fn a_crashed_campaign_reads_failed_and_is_not_resumable() {
    // The evaluation closure's Err path appends `campaign.failed` so a
    // crashed campaign never lingers `open`; the listing and the resume
    // refusal must project that record, not contradict it.
    let env = Env::new("crashed");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    // A fixture proposal path that does not exist crashes the campaign
    // after it opened and evaluated the baseline.
    let missing = env.dir.join("no-such-proposal.whip");
    let mut command = env.command();
    command
        .args([
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ])
        .env(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            missing.to_string_lossy().as_ref(),
        );
    let output = command.output().expect("spawn whip");
    assert!(
        !output.status.success(),
        "a crashed campaign exits non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fixture proposal"),
        "the crash names its cause: {stderr}"
    );

    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let rows = campaigns["campaigns"].as_array().expect("campaigns");
    assert_eq!(rows.len(), 1, "{campaigns}");
    assert_eq!(
        rows[0]["status"].as_str(),
        Some("failed"),
        "a crashed campaign reads `failed`, not `open`: {campaigns}"
    );
    let campaign_id = rows[0]["campaign"].as_str().expect("id").to_owned();

    // A failed campaign is not parked; the refusal names the status.
    let stderr = env.run_expect_failure(&["improve", "--resume", &campaign_id]);
    assert!(
        stderr.contains("not parked (status: failed)"),
        "refusal names the folded status: {stderr}"
    );
}

#[test]
fn an_unknown_gauge_is_refused_before_a_campaign_is_minted() {
    // The refusal must come before any store write: a typo in the gauge
    // name is not a campaign, and must not mint a C-id that sits `open`
    // with one event and no closing record.
    let env = Env::new("unknown-gauge");
    write_judges(&env.dir);
    let program_path = env.dir.join("triage.whip");
    fs::write(&program_path, program("low", "ticket.id", &env.dir)).expect("write program");
    let program_str = program_path.to_string_lossy().into_owned();
    dev_and_pin(&env, &program_str);

    let stderr = env.run_expect_failure(&[
        "improve",
        "priority_corect",
        "--program",
        &program_str,
        "--proposer",
        "fixture",
    ]);
    assert!(
        stderr.contains("unknown gauge `priority_corect`"),
        "the refusal names the typo: {stderr}"
    );
    assert!(
        stderr.contains("declared gauges: priority_correct, ticket_echoed"),
        "the refusal lists what is declared: {stderr}"
    );

    let campaigns = env.run_json(&["--json", "campaigns"], &[]);
    let rows = campaigns["campaigns"].as_array().expect("campaigns");
    assert!(
        rows.is_empty(),
        "a refused gauge name mints no campaign: {campaigns}"
    );

    // The accepting side: the declared name opens a campaign as before.
    let candidate_path = env.dir.join("candidate.whip");
    fs::write(&candidate_path, program("high", "ticket.id", &env.dir)).expect("write candidate");
    let report = env.run_json(
        &[
            "--json",
            "improve",
            "priority_correct",
            "--program",
            &program_str,
            "--proposer",
            "fixture",
        ],
        &[(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            &candidate_path.to_string_lossy(),
        )],
    );
    assert_eq!(
        report["campaign"].as_str(),
        Some("C-1"),
        "the first accepted campaign takes the first id: {report}"
    );
}
