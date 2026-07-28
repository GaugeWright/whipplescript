//! End-to-end `whip improve` loop: pin a scenario from a real dev run,
//! campaign with the fixture proposer, dominance verdicts on real
//! regenerated evaluations, campaign record, and adoption — all through the
//! built binary with deterministic exec judges (no live provider).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

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
        let mut command = Command::new(env!("CARGO_BIN_EXE_whip"));
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
        &[(
            "WHIPPLESCRIPT_IMPROVE_PROPOSALS",
            &candidate_path.to_string_lossy(),
        )],
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
             "input_per_mtok_usd": 1000000.0, "output_per_mtok_usd": 0.0}
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

    // Resume: a fresh per-invocation allowance under the same recorded
    // cap; the spec comes from the record, candidate numbering continues.
    let good = env.dir.join("good.whip");
    fs::write(&good, program("high", "ticket.id", &env.dir)).expect("write good");
    let good_str = good.to_string_lossy().into_owned();
    let resumed = env.run_json(
        &[
            "--json",
            "improve",
            "--resume",
            &campaign_id,
            "--provider-config",
            &prices_str,
        ],
        &[("WHIPPLESCRIPT_IMPROVE_PROPOSALS", &good_str), usage_env],
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
        Some("K-2"),
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
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock endpoint");
    let base_url = format!("http://{}", listener.local_addr().expect("addr"));
    let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let collected = bodies.clone();
    std::thread::spawn(move || {
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
            let content = serde_json::to_string(verdict).expect("encode content");
            let reply = format!(
                r#"{{"choices":[{{"message":{{"content":{content}}}}}],"usage":{{"input_tokens":3,"output_tokens":2}}}}"#
            );
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
             "input_per_mtok_usd": 1000000.0, "output_per_mtok_usd": 1000000.0}
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

    // $1 per token: the mock coerce returns 3 in + 2 out = $5 per body call.
    // The coerce RUN records the worker's agent provider (`fixture`) and leaves
    // the model unrecorded, so std.spend prices it under (fixture, "").
    let prices_path = env.dir.join("providers.json");
    fs::write(
        &prices_path,
        r#"{"providers": [], "prices": [
            {"provider": "fixture", "model": "",
             "input_per_mtok_usd": 1000000.0, "output_per_mtok_usd": 1000000.0}
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
             "input_per_mtok_usd": 1000000.0, "output_per_mtok_usd": 1000000.0}
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
