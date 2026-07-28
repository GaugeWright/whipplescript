//! B1 "soft middle" regression suite: anything `check` accepts must execute
//! faithfully. Each test here pins a failure mode where bodies previously
//! compiled and then silently did the wrong thing at runtime.

use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;

fn run_json(bin: &str, args: &[&str]) -> Value {
    let output = Command::new(bin).args(args).output().expect("command runs");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    let json_start = stdout.find(['{', '[']).expect("json output");
    serde_json::from_str(&stdout[json_start..]).expect("valid json")
}

fn temp_path(label: &str, extension: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "whipplescript-soft-middle-{label}-{}-{nanos}.{extension}",
        std::process::id()
    ))
}

fn dev_until_idle(bin: &str, store: &str, source: &str, extra: &[&str]) -> Value {
    let mut args = vec!["--store", store, "--json", "run", source];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--provider", "fixture", "--until", "idle"]);
    run_json(bin, &args)
}

fn instance_status(bin: &str, store: &str, instance: &str) -> String {
    let status = run_json(bin, &["--store", store, "--json", "status", instance]);
    status
        .pointer("/instance/status")
        .and_then(Value::as_str)
        .expect("instance status")
        .to_owned()
}

/// Filtered fact queries behave identically in guards and assertions, and
/// single-line table rows seed exactly like multi-line rows.
#[test]
fn filtered_query_guards_match_assertions_over_single_line_rows() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("guard-assert", "sqlite");
    let source = temp_path("guard-assert", "whip");
    fs::write(
        &source,
        r#"
workflow GuardAssertEquivalence

output result Report

class Item {
  id string
  status string
}

class Report {
  total int
}

table items as Item [
  { id "a" status "done" }
  { id "b" status "done" }
  {
    id "c"
    status "open"
  }
]

rule finish
  when Item as item where count(Item where status == "done") == 2 and exists(Item where status == "open")
=> {
  complete result {
    total count(Item where status == "done")
  }
}

assert count(Item where status == "done") == 2
assert exists(Item where status == "open")
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    for assertion in dev
        .get("assertions")
        .and_then(Value::as_array)
        .expect("assertions")
    {
        assert_eq!(
            assertion.get("status").and_then(Value::as_str),
            Some("passed"),
            "{assertion}"
        );
    }
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// A `where` guard on a bindingless trigger (`when started`) is enforced at
/// runtime, not silently dropped. Bindingless triggers previously skipped guard
/// evaluation entirely, so a false guard still fired the rule — the exact
/// silent-no-op class this suite pins. The same `count(... where ...)` guard is
/// exercised to keep it aligned with the bound-trigger B1c coverage above.
#[test]
fn started_trigger_guard_is_enforced() {
    let bin = env!("CARGO_BIN_EXE_whip");

    // True guard (exactly two "done") fires the started rule and completes;
    // false guard (not three) must NOT fire, so the instance never completes.
    for (label, guard, expected_completed) in [
        (
            "true-guard",
            r#"count(Item where status == "done") == 2"#,
            true,
        ),
        (
            "false-guard",
            r#"count(Item where status == "done") == 3"#,
            false,
        ),
    ] {
        let store = temp_path(&format!("started-guard-{label}"), "sqlite");
        let source = temp_path(&format!("started-guard-{label}"), "whip");
        fs::write(&source, started_guard_program(guard)).expect("write source");
        let store_str = store.to_str().expect("utf-8");
        let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
        let instance = dev
            .get("instance_id")
            .and_then(Value::as_str)
            .expect("instance id");
        let completed = instance_status(bin, store_str, instance) == "completed";
        assert_eq!(
            completed, expected_completed,
            "{label}: started-guard enforcement wrong (completed={completed})"
        );
        let _ = fs::remove_file(store);
        let _ = fs::remove_file(source);
    }
}

fn started_guard_program(guard: &str) -> String {
    format!(
        r#"
workflow StartedGuard

output result Report

class Item {{
  id string
  status string
}}

class Report {{
  ok int
}}

table items as Item [
  {{ id "a" status "done" }}
  {{ id "b" status "done" }}
  {{ id "c" status "open" }}
]

rule finish
  when started
  where {guard}
=> {{
  complete result {{
    ok 1
  }}
}}
"#
    )
}

/// Templates in record/payload string fields render against bindings.
#[test]
fn templates_in_payload_fields_render() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("templates", "sqlite");
    let source = temp_path("templates", "whip");
    fs::write(
        &source,
        r#"
workflow Templates

output result Out

class In {
  a string
  b string
}

class Out {
  joined string
}

table seeds as In [
  { a "x" b "y" }
]

rule go
  when In as i
=> {
  complete result {
    joined "{{ i.a }}-{{ i.b }}"
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let completed = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.completed"))
        .expect("completed event");
    assert_eq!(
        completed
            .pointer("/payload/payload/joined")
            .and_then(Value::as_str),
        Some("x-y")
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Arithmetic in field values evaluates (retry-counter idiom).
#[test]
fn arithmetic_in_field_values_evaluates_on_failure_path() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("arith", "sqlite");
    let source = temp_path("arith", "whip");
    fs::write(
        &source,
        r#"
workflow Arithmetic

failure error GaveUp

class Job {
  id string
  attempts int
}

class GaveUp {
  attempts int
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

table jobs as Job [
  { id "j" attempts 0 }
]

rule attempt
  when Job as job where job.attempts < 1
  when worker is available
=> {
  tell worker as turn "do it"

  after turn fails as failed {
    done job -> record Job {
      id job.id
      attempts job.attempts + 1
    }
  }
}

rule give_up
  when Job as job where job.attempts >= 1
=> {
  fail error {
    attempts job.attempts * 10
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let failed = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.failed"))
        .expect("failed event");
    assert_eq!(
        failed
            .pointer("/payload/payload/attempts")
            .and_then(Value::as_i64),
        Some(10)
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// DR-0032: a failed effect's `.failed` fact carries the EffectError base under
/// `value`, so `after <effect> fails as f` binds `f.reason` to the actual failure
/// text — not `null` (the prior value-shadow bug, where facts with `value: null`
/// resolved the binding to null and shadowed the error). `--fail` forces the
/// fixture turn to fail; the rule writes `f.reason` into the workflow failure.
#[test]
fn failed_effect_binds_effecterror_base_reason() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("effecterror-reason", "sqlite");
    let source = temp_path("effecterror-reason", "whip");
    fs::write(
        &source,
        r#"
workflow W

failure error E

class Trigger {
  id string
}

class E {
  detail string
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

table triggers as Trigger [
  { id "t" }
]

rule go
  when Trigger as trig
  when worker is available
=> {
  tell worker as turn "do it"

  after turn fails as f {
    fail error {
      detail f.reason
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let failed = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.failed"))
        .expect("failed event");
    let detail = failed
        .pointer("/payload/payload/detail")
        .and_then(Value::as_str)
        .unwrap_or("");
    assert!(
        !detail.is_empty(),
        "f.reason must bind the failure text (the EffectError base), not null; failed event: {failed:#?}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Nested `after` blocks fire (the recursion in lower_rule): a hand-written
/// two-deep pipeline — effect, `after` requesting a second effect, nested
/// `after` reaching the terminal — completes with both bindings resolved.
/// Before the fix this checked clean and silently stalled forever.
#[test]
fn nested_after_blocks_fire_to_the_terminal() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("nested-after", "sqlite");
    let source = temp_path("nested-after", "whip");
    fs::write(
        &source,
        r#"
workflow NestedAfter

output result Done

class Done {
  first string
  second string
}

class Trigger {
  id string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table seed as Trigger [
  { id "t" }
]

rule pipeline
  when Trigger as t
=> {
  tell worker as a "one"

  after a succeeds {
    tell worker as b "two"

    after b succeeds {
      complete result {
        first a.summary
        second b.summary
      }
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// `then` sugar (R2): a chained pipeline completes end to end, with each
/// binding carrying the success payload of its step.
#[test]
fn then_chain_pipeline_completes() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("then-chain", "sqlite");
    let source = temp_path("then-chain", "whip");
    fs::write(
        &source,
        r#"
workflow ThenChain

output result Done

class Done {
  first string
  second string
}

class Trigger {
  id string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table seed as Trigger [
  { id "t" }
]

rule pipeline
  when Trigger as t
=> {
  then a <- tell worker "one"
  then b <- tell worker "two"
  complete result {
    first a.summary
    second b.summary
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let completed = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.completed"))
        .expect("workflow.completed event");
    assert!(
        completed
            .pointer("/payload/payload/first")
            .and_then(Value::as_str)
            .is_some(),
        "the chained binding resolves to the success payload: {completed}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// `then` sugar (R2 + R1): a failing chained step auto-fails the instance with
/// the AUTHOR's binding name in the reason (never the synthetic `__then_*`
/// handle), and `whip check` stays quiet — the sugar is an explicit opt-in to
/// auto-fail, so R1a's unhandled-failure warning must not fire.
#[test]
fn then_chain_failure_auto_fails_with_author_binding() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("then-fail", "sqlite");
    let source = temp_path("then-fail", "whip");
    fs::write(
        &source,
        r#"
workflow ThenFail

output result Done

class Done {
  note string
}

class Trigger {
  id string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table seed as Trigger [
  { id "t" }
]

rule pipeline
  when Trigger as t
=> {
  then a <- tell worker "one"
  complete result {
    note a.summary
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let check = Command::new(bin)
        .args([
            "--store",
            store_str,
            "check",
            source.to_str().expect("utf-8"),
        ])
        .output()
        .expect("check runs");
    let check_output = format!(
        "{}{}",
        String::from_utf8_lossy(&check.stdout),
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(
        !check_output.contains("failure is unhandled"),
        "a then-chain opts into auto-fail; R1a must stay quiet:\n{check_output}"
    );

    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let transitioned = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("instance.transitioned")
                && event.pointer("/payload/status").and_then(Value::as_str) == Some("failed")
        })
        .expect("instance.transitioned failed event");
    assert_eq!(
        transitioned
            .pointer("/payload/reason")
            .and_then(Value::as_str),
        Some("unhandled failure of `a` in rule `pipeline`"),
        "the reason names the author binding, not the synthetic handle"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Auto-fail (R1) at RULE level: an effect whose failure has no observing
/// `after` block in a plain rule of a self-terminating workflow drives the
/// instance to `failed` with the generic reason, instead of stalling forever.
#[test]
fn unhandled_rule_effect_failure_auto_fails_the_workflow() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("rule-autofail", "sqlite");
    let source = temp_path("rule-autofail", "whip");
    fs::write(
        &source,
        r#"
workflow RuleAutoFail

output result Decision
failure error Blocked

class Trigger {
  id string
}

class Decision {
  ok string
}

class Blocked {
  reason string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  tell worker as turn "do it"

  after turn succeeds {
    complete result {
      ok "done"
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let transitioned = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("instance.transitioned")
                && event.pointer("/payload/status").and_then(Value::as_str) == Some("failed")
        })
        .expect("instance.transitioned failed event");
    let reason = transitioned
        .pointer("/payload/reason")
        .and_then(Value::as_str)
        .unwrap_or_default();
    assert_eq!(
        reason, "unhandled failure of `turn` in rule `r`",
        "the R1 generic reason names the binding and rule"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Auto-fail (R1): an `after <binding> fails` observer keeps the rule-level net
/// out — the failure routes through the author's typed terminal.
#[test]
fn handled_rule_effect_failure_does_not_auto_fail() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("rule-handledfail", "sqlite");
    let source = temp_path("rule-handledfail", "whip");
    fs::write(
        &source,
        r#"
workflow RuleHandledFail

output result Decision
failure error Blocked

class Trigger {
  id string
}

class Decision {
  ok string
}

class Blocked {
  reason string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  tell worker as turn "do it"

  after turn succeeds {
    complete result {
      ok "done"
    }
  }

  after turn fails {
    fail error {
      reason "handled"
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let failed = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.failed"))
        .expect("workflow.failed event");
    assert_eq!(
        failed
            .pointer("/payload/payload/reason")
            .and_then(Value::as_str),
        Some("handled"),
        "the author after-fails handler payload must fire: {failed}"
    );
    assert!(
        !log.as_array().expect("log").iter().any(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("instance.transitioned")
                && event
                    .pointer("/payload/reason")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .contains("unhandled failure")
        }),
        "a handled failure must not also auto-fail: {log}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Auto-fail (R1): `after <binding> completes` observes every terminal, so it
/// counts as an observer — the case arm decides, and the net stays out.
#[test]
fn completes_observer_prevents_rule_auto_fail() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("rule-completes", "sqlite");
    let source = temp_path("rule-completes", "whip");
    fs::write(
        &source,
        r#"
workflow RuleCompletes

output result Decision

class Trigger {
  id string
}

class Decision {
  ok string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  tell worker as turn "do it"

  after turn completes {
    complete result {
      ok "observed"
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    // The tell failed, but `after turn completes` fired and completed the
    // workflow — the net must not override the author's observer.
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Auto-fail (R1): a `@service` workflow can never auto-fail — an unhandled
/// effect failure records ONE durable diagnostic (idempotent per effect across
/// worker passes) and the service keeps running.
#[test]
fn service_unhandled_failure_records_diagnostic_and_keeps_running() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("service-diag", "sqlite");
    let source = temp_path("service-diag", "whip");
    fs::write(
        &source,
        r#"
@service
workflow ServiceDiag

class Trigger {
  id string
}

class Seen {
  note string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  tell worker as turn "do it"

  after turn succeeds {
    record Seen { note "ok" }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "running");
    let count_diagnostics = || {
        run_json(
            bin,
            &["--store", store_str, "--json", "diagnostics", instance],
        )
        .as_array()
        .expect("diagnostics")
        .iter()
        .filter(|diagnostic| {
            diagnostic.get("code").and_then(Value::as_str) == Some("workflow.unhandled_failure")
        })
        .count()
    };
    assert_eq!(count_diagnostics(), 1, "one durable diagnostic per failure");
    // Another worker pass re-observes the same failure; the diagnostic must not
    // duplicate (idempotent per effect).
    let _ = run_json(
        bin,
        &[
            "--store",
            store_str,
            "--json",
            "step",
            instance,
            "--program",
            source.to_str().expect("utf-8"),
        ],
    );
    assert_eq!(instance_status(bin, store_str, instance), "running");
    assert_eq!(count_diagnostics(), 1, "re-observation must not duplicate");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Auto-fail (R1): `cancelled` is exempt — effect-level cancel is deliberate
/// (the watchdog pattern depends on it), so a cancelled effect never trips the
/// net even with no observer on its binding. (Coerce settlement is the fixture
/// path that emits a real cancelled terminal.)
#[test]
fn cancelled_effect_is_exempt_from_rule_auto_fail() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("rule-cancel-exempt", "sqlite");
    let source = temp_path("rule-cancel-exempt", "whip");
    fs::write(
        &source,
        r#"
use std.coercion

workflow CancelExempt

output result Decision

class Trigger {
  id string
}

class Decision {
  ok string
}

class Verdict {
  priority string
}

coerce judge(id string) -> Verdict {
  prompt "Classify {{ id }}"
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  coerce judge(t.id) as verdict

  after verdict succeeds {
    complete result {
      ok "done"
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(
        bin,
        store_str,
        source.to_str().expect("utf-8"),
        &["--cancel"],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    // The cancelled tell leaves the instance running (no observer fires), but
    // it must NOT auto-fail — cancellation is deliberate.
    assert_eq!(instance_status(bin, store_str, instance), "running");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    assert!(
        !log.as_array().expect("log").iter().any(|event| {
            event
                .pointer("/payload/reason")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .contains("unhandled failure")
        }),
        "a cancelled effect must not trip the auto-fail net: {log}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Auto-fail (R1): a timed-out effect with no observer trips the net the same
/// as a failed one — `timed_out` is a terminal failure for the net's purposes.
/// (Coerce settlement is the fixture path that emits a real timed-out terminal.)
#[test]
fn timed_out_effect_auto_fails_without_observer() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("rule-timeout-autofail", "sqlite");
    let source = temp_path("rule-timeout-autofail", "whip");
    fs::write(
        &source,
        r#"
use std.coercion

workflow TimeoutAutoFail

output result Decision

class Trigger {
  id string
}

class Decision {
  ok string
}

class Verdict {
  priority string
}

coerce judge(id string) -> Verdict {
  prompt "Classify {{ id }}"
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  coerce judge(t.id) as verdict

  after verdict succeeds {
    complete result {
      ok "done"
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(
        bin,
        store_str,
        source.to_str().expect("utf-8"),
        &["--timeout"],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// `send via <channel>` (std.messaging) compiles with NO package lock — the
/// embedded `std.messaging` manifest authorizes it via `use std.messaging` —
/// runs as a `messaging.send` capability.call under the fixture provider, and
/// the workflow completes on `after sent succeeds`.
#[test]
fn send_via_channel_runs_under_fixture_and_completes() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("send", "sqlite");
    let source = temp_path("send", "whip");
    fs::write(
        &source,
        r##"
@service
workflow Notify

use std.messaging

output result Done

class Trigger {
  id string
}

class Done {
  ok string
}

agent worker {
  provider fixture
  profile "repo-reader"
  capacity 1
}

channel alerts {
  provider fixture
  destination "#ops"
}

table seed as Trigger [
  { id "t" }
]

rule notify
  when Trigger as t
=> {
  send via alerts {
    text "hello"
  } as sent

  after sent succeeds {
    complete result {
      ok "sent"
    }
  }
}
"##,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    // No `--package-lock`: the embedded `std.messaging` manifest must let
    // `send` compile + run.
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");
    let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
    let send = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|effect| effect.get("target").and_then(Value::as_str) == Some("messaging.send"))
        .expect("messaging.send effect");
    assert_eq!(
        send.get("status").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        send.pointer("/input/message/channel")
            .and_then(Value::as_str),
        Some("alerts")
    );

    // The named `fixture` provider returns the FULL typed MessageSendReceipt
    // (spec/std-messaging.md "MessageSendReceipt"), not the generic fixture
    // `{summary, target}` stand-in: the succeeded fact's value carries every
    // receipt field, deterministically (fixture accepted_at stays empty).
    let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
    let receipt = facts
        .as_array()
        .expect("facts")
        .iter()
        .find(|fact| fact.get("name").and_then(Value::as_str) == Some("capability.call.succeeded"))
        .and_then(|fact| fact.pointer("/value/value"))
        .expect("send receipt value")
        .clone();
    assert_eq!(
        receipt.get("channel").and_then(Value::as_str),
        Some("alerts")
    );
    assert_eq!(
        receipt.get("provider").and_then(Value::as_str),
        Some("fixture")
    );
    assert_eq!(
        receipt.get("status").and_then(Value::as_str),
        Some("accepted")
    );
    assert_eq!(
        receipt.get("destination").and_then(Value::as_str),
        Some("#ops"),
        "the channel's fixed destination is echoed in the receipt"
    );
    let message_id = receipt
        .get("message_id")
        .and_then(Value::as_str)
        .expect("message_id");
    let provider_message_id = receipt
        .get("provider_message_id")
        .and_then(Value::as_str)
        .expect("provider_message_id");
    assert!(!message_id.is_empty());
    assert!(!provider_message_id.is_empty());
    assert_ne!(
        message_id, provider_message_id,
        "the provider correlation handle is minted distinct from the durable id"
    );
    assert_eq!(
        receipt.get("accepted_at").and_then(Value::as_str),
        Some(""),
        "the fixture acknowledges nothing; accepted_at stays deterministic-empty"
    );
    assert!(receipt.get("thread_id").is_some());

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// S5 first real provider: a `send via <channel>` on a channel declaring
/// `provider local` is delivered by the native, file-backed local mailbox
/// provider (not the fixture). The workflow completes and the mailbox file
/// (derived from the store path) carries the delivered message.
#[test]
fn send_via_local_channel_delivers_to_local_mailbox() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("send-local", "sqlite");
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/messaging-local-demo.whip");

    let store_str = store.to_str().expect("utf-8");
    // No `--package-lock`: the embedded `std.messaging` manifest lets `send`
    // compile + run.
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    // The messaging.send effect completed under the local provider.
    let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
    let send = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|effect| effect.get("target").and_then(Value::as_str) == Some("messaging.send"))
        .expect("messaging.send effect");
    assert_eq!(
        send.get("status").and_then(Value::as_str),
        Some("completed")
    );

    // The local mailbox file (store path with a `.mailbox.jsonl` extension)
    // carries exactly the delivered message.
    let mailbox = store.with_extension("mailbox.jsonl");
    let contents = fs::read_to_string(&mailbox).expect("mailbox file");
    let line = contents.lines().next().expect("one mailbox line");
    let record: Value = serde_json::from_str(line).expect("mailbox json line");
    assert_eq!(
        record.get("channel").and_then(Value::as_str),
        Some("alerts")
    );
    assert_eq!(record.get("text").and_then(Value::as_str), Some("hello"));
    assert_eq!(
        record.get("provider").and_then(Value::as_str),
        Some("local")
    );

    // The local receipt is the full MessageSendReceipt: binding-resolved
    // provider id, real provider-acknowledged instant, correlation handle
    // distinct from the durable message id (spec/std-messaging.md).
    let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
    let receipt = facts
        .as_array()
        .expect("facts")
        .iter()
        .find(|fact| fact.get("name").and_then(Value::as_str) == Some("capability.call.succeeded"))
        .and_then(|fact| fact.pointer("/value/value"))
        .expect("send receipt value")
        .clone();
    assert_eq!(
        receipt.get("provider").and_then(Value::as_str),
        Some("std.messaging.local")
    );
    assert_eq!(
        receipt.get("status").and_then(Value::as_str),
        Some("accepted")
    );
    let accepted_at = receipt
        .get("accepted_at")
        .and_then(Value::as_str)
        .expect("accepted_at");
    assert!(
        !accepted_at.is_empty(),
        "the local provider reports a real provider-acknowledged instant"
    );
    assert_ne!(
        receipt.get("message_id").and_then(Value::as_str),
        receipt.get("provider_message_id").and_then(Value::as_str),
    );
    // The mailbox row mirrors the receipt correlation.
    assert_eq!(
        record.get("provider_message_id").and_then(Value::as_str),
        receipt.get("provider_message_id").and_then(Value::as_str),
    );
    assert_eq!(
        record.get("accepted_at").and_then(Value::as_str),
        Some(accepted_at)
    );

    // `whip mailbox outbound` lists the delivered row (the operator door,
    // spec/std-messaging.md open question 1).
    let listed = run_json(
        bin,
        &["--store", store_str, "--json", "mailbox", "outbound"],
    );
    let messages = listed
        .get("messages")
        .and_then(Value::as_array)
        .expect("mailbox messages");
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].get("message_id").and_then(Value::as_str),
        record.get("message_id").and_then(Value::as_str),
    );
    // Channel filtering: a non-matching filter lists nothing.
    let filtered = run_json(
        bin,
        &[
            "--store",
            store_str,
            "--json",
            "mailbox",
            "outbound",
            "--channel",
            "nope",
        ],
    );
    assert_eq!(
        filtered
            .get("messages")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(mailbox);
}

/// Autonomous inbound RECEIVE for a `local` channel (spec/messaging.md): the
/// SOURCE side that complements outbound `send` and the `whip message`
/// injection. A worker pass polls the per-channel inbox at
/// `<store>.inbox.<channel>.jsonl` and admits each JSON line as a `Message` on
/// `message.<channel>` — the same fact `whip message` injects, so a
/// `when message from <channel>` rule fires autonomously, once per received
/// message. Admission is idempotent by (channel, line ordinal): a second worker
/// pass over the same inbox re-admits nothing. Mirrors the file-ingress source
/// (`dev_file_source_admits_one_signal_per_line_idempotently`), inbound.
#[test]
fn inbound_local_channel_admits_messages_from_inbox_idempotently() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("inbound-local", "sqlite");
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/messaging-inbound-local.whip");
    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");

    // The per-channel inbox: `<store>.inbox.<channel>.jsonl` (channel `inbox`).
    // Two received messages, each a JSON object carrying at least `text`.
    let inbox = store.with_extension("inbox.inbox.jsonl");
    fs::write(
        &inbox,
        "{\"text\":\"first message\",\"sender\":\"alice\"}\n\
         {\"text\":\"second message\",\"thread_id\":\"t7\"}\n",
    )
    .expect("seed inbox");

    // A worker-boundary poll admits both inbox lines and the reacting rule fires
    // once per message, recording a `Received` fact.
    let dev = dev_until_idle(bin, store_str, source_str, &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();

    // Both messages were admitted (summed across the worker passes).
    let admitted: u64 = dev
        .get("workers")
        .and_then(Value::as_array)
        .expect("workers")
        .iter()
        .filter_map(|w| w.get("inbound_messages_admitted").and_then(Value::as_u64))
        .sum();
    assert_eq!(admitted, 2, "both inbox lines were admitted: {dev}");

    // One `message.inbox` fact per received message, in file order, each a
    // well-formed local `Message` envelope carrying that line's text.
    let inbox_texts = |instance: &str| -> Vec<String> {
        let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
        let mut rows: Vec<(String, String)> = facts
            .as_array()
            .expect("facts array")
            .iter()
            .filter(|fact| fact.get("name").and_then(Value::as_str) == Some("message.inbox"))
            .map(|fact| {
                assert_eq!(
                    fact.pointer("/value/provider").and_then(Value::as_str),
                    Some("local"),
                    "the admitted Message declares the local provider"
                );
                let message_id = fact
                    .pointer("/value/message_id")
                    .and_then(Value::as_str)
                    .expect("message carries an id")
                    .to_owned();
                let text = fact
                    .pointer("/value/text")
                    .and_then(Value::as_str)
                    .expect("message carries text")
                    .to_owned();
                (message_id, text)
            })
            .collect();
        rows.sort_by(|a, b| a.1.cmp(&b.1));
        rows.into_iter().map(|(_, text)| text).collect()
    };
    assert_eq!(
        inbox_texts(&instance),
        vec!["first message".to_owned(), "second message".to_owned()],
        "one `message.inbox` Message fact per inbox line"
    );

    // The `when message from inbox` rule fired once per message: an unresolved
    // `msg.text` would have failed rather than record. Two `Received` facts.
    let received_count = |instance: &str| -> usize {
        let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
        facts
            .as_array()
            .expect("facts array")
            .iter()
            .filter(|fact| fact.get("name").and_then(Value::as_str) == Some("Received"))
            .count()
    };
    assert_eq!(
        received_count(&instance),
        2,
        "the reacting rule fired once per admitted message"
    );

    // Idempotency: a second worker pass over the *same* instance and the *same*
    // inbox re-admits nothing. Without the (channel, line ordinal) cursor this
    // would hit the event log's UNIQUE(idempotency_key) constraint or double the
    // facts; instead the counts are unchanged.
    let worker = run_json(
        bin,
        &[
            "--store",
            store_str,
            "--json",
            "worker",
            &instance,
            "--program",
            source_str,
            "--provider",
            "fixture",
        ],
    );
    assert_eq!(
        worker
            .get("inbound_messages_admitted")
            .and_then(Value::as_u64),
        Some(0),
        "a re-poll of an unchanged inbox admits no new messages: {worker}"
    );
    assert_eq!(
        inbox_texts(&instance),
        vec!["first message".to_owned(), "second message".to_owned()],
        "re-polling admits no duplicate Message facts (idempotent by line ordinal)"
    );
    assert_eq!(
        received_count(&instance),
        2,
        "no duplicate Received facts after the idempotent re-poll"
    );

    // `whip mailbox inbound <channel>` lists the received rows with their
    // admission ordinals (the operator read door over the local inbox).
    let listed = run_json(
        bin,
        &[
            "--store", store_str, "--json", "mailbox", "inbound", "inbox",
        ],
    );
    let messages = listed
        .get("messages")
        .and_then(Value::as_array)
        .expect("inbound messages");
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].get("ordinal").and_then(Value::as_u64), Some(0));
    assert_eq!(
        messages[0].get("text").and_then(Value::as_str),
        Some("first message")
    );
    assert_eq!(
        messages[1].get("thread_id").and_then(Value::as_str),
        Some("t7")
    );

    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(&inbox);
}

/// `send via <channel>` where the channel declares `provider stdio` is delivered
/// by the native stdio provider: the workflow completes and a
/// `[messaging.stdio] channel=… text=…` marker line is written to stdout. The
/// second real messaging provider behind the S5 seam (local mailbox was first);
/// non-local/non-stdio channels keep the fixture.
#[test]
fn send_via_stdio_channel_writes_marker_to_stdout() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("send-stdio", "sqlite");
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/messaging-stdio-demo.whip");
    let store_str = store.to_str().expect("utf-8");

    let output = Command::new(bin)
        .args([
            "--store",
            store_str,
            "run",
            source.to_str().expect("utf-8"),
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .output()
        .expect("dev runs");
    assert!(
        output.status.success(),
        "dev failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("[messaging.stdio] channel=console text=hello-stdio"),
        "expected the stdio delivery marker on stdout, got:\n{stdout}"
    );
    assert!(
        stdout.contains("status completed"),
        "workflow did not complete, got:\n{stdout}"
    );

    let _ = fs::remove_file(store);
}

/// A desktop-channel workflow source shared by the desktop provider tests:
/// outbound-only `send via` with `after … succeeds` and `fails as` branches.
fn desktop_workflow_source() -> String {
    r##"
@service
workflow DesktopNotify

use std.messaging

output result Done
failure error NotifyFailed

class Trigger { id string }
class Done { ok string }
class NotifyFailed { why string }

channel alerts {
  provider desktop
  destination "Ops Alerts"
}

table seed as Trigger [
  { id "t" }
]

rule notify
  when Trigger as t
=> {
  send via alerts {
    text "disk almost full"
  } as sent

  after sent succeeds {
    complete result {
      ok "notified"
    }
  }
  after sent fails as f {
    fail error {
      why f.reason
    }
  }
}
"##
    .to_owned()
}

/// std.messaging.desktop (spec/std-messaging.md slice 4): a `send via` on a
/// channel declaring `provider desktop` spawns the notifier subprocess
/// (`WHIPPLESCRIPT_DESKTOP_NOTIFIER` resolves it — here a fake that records
/// its argv), the workflow completes, and the receipt names the desktop
/// provider with no correlation handle. Outbound-only is enforced at CHECK
/// time (`when message from` a desktop channel is a check error — covered by
/// the parser suite), so this test is pure send.
#[test]
fn send_via_desktop_channel_spawns_notifier_and_completes() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("send-desktop", "sqlite");
    let source = temp_path("send-desktop", "whip");
    let notifier = temp_path("fake-notifier", "sh");
    let argv_log = temp_path("fake-notifier-argv", "log");
    fs::write(&source, desktop_workflow_source()).expect("write source");
    fs::write(
        &notifier,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 0\n",
            argv_log.display()
        ),
    )
    .expect("write notifier");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&notifier, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let store_str = store.to_str().expect("utf-8");
    let output = Command::new(bin)
        .env("WHIPPLESCRIPT_DESKTOP_NOTIFIER", &notifier)
        .args([
            "--store",
            store_str,
            "--json",
            "run",
            source.to_str().expect("utf-8"),
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .output()
        .expect("dev runs");
    assert!(
        output.status.success(),
        "dev failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let dev: Value =
        serde_json::from_str(&stdout[stdout.find(['{']).expect("json")..]).expect("dev json");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    // The fake notifier ran with the notify-send argument shape:
    // `<title> <body>` — title = the channel's fixed destination, body = text.
    let argv = fs::read_to_string(&argv_log).expect("notifier argv recorded");
    assert_eq!(argv, "Ops Alerts\ndisk almost full\n");

    // Receipt: desktop provider id, accepted, no correlation handle.
    let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
    let receipt = facts
        .as_array()
        .expect("facts")
        .iter()
        .find(|fact| fact.get("name").and_then(Value::as_str) == Some("capability.call.succeeded"))
        .and_then(|fact| fact.pointer("/value/value"))
        .expect("send receipt value")
        .clone();
    assert_eq!(
        receipt.get("provider").and_then(Value::as_str),
        Some("std.messaging.desktop")
    );
    assert_eq!(
        receipt.get("status").and_then(Value::as_str),
        Some("accepted")
    );
    assert_eq!(
        receipt.get("provider_message_id").and_then(Value::as_str),
        Some(""),
        "desktop has no provider correlation handle"
    );
    assert_eq!(
        receipt.get("destination").and_then(Value::as_str),
        Some("Ops Alerts")
    );
    assert!(receipt
        .get("accepted_at")
        .and_then(Value::as_str)
        .is_some_and(|at| !at.is_empty()));

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(notifier);
    let _ = fs::remove_file(argv_log);
}

/// A nonzero notifier exit settles `capability.call.failed` with the DR-0032
/// EffectError base and routes to `fails as` (spec/std-messaging.md slice 4:
/// failure is not a receipt).
#[test]
fn desktop_notifier_failure_settles_capability_call_failed() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("desktop-fail", "sqlite");
    let source = temp_path("desktop-fail", "whip");
    let notifier = temp_path("fake-notifier-fail", "sh");
    fs::write(&source, desktop_workflow_source()).expect("write source");
    fs::write(
        &notifier,
        "#!/bin/sh\necho 'no notification daemon' >&2\nexit 3\n",
    )
    .expect("write notifier");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&notifier, fs::Permissions::from_mode(0o755)).expect("chmod");
    }

    let store_str = store.to_str().expect("utf-8");
    let output = Command::new(bin)
        .env("WHIPPLESCRIPT_DESKTOP_NOTIFIER", &notifier)
        .args([
            "--store",
            store_str,
            "--json",
            "run",
            source.to_str().expect("utf-8"),
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .output()
        .expect("dev runs");
    assert!(
        output.status.success(),
        "dev failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let dev: Value =
        serde_json::from_str(&stdout[stdout.find(['{']).expect("json")..]).expect("dev json");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    // The `fails as` branch drove the typed failure terminal.
    assert_eq!(instance_status(bin, store_str, instance), "failed");

    let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
    let failed = facts
        .as_array()
        .expect("facts")
        .iter()
        .find(|fact| fact.get("name").and_then(Value::as_str) == Some("capability.call.failed"))
        .expect("capability.call.failed fact")
        .clone();
    // DR-0032 EffectError base rides `value`; the notifier's stderr and exit
    // status are in the reason.
    assert_eq!(
        failed.pointer("/value/value/kind").and_then(Value::as_str),
        Some("capability.call")
    );
    let reason = failed
        .pointer("/value/value/reason")
        .and_then(Value::as_str)
        .expect("failure reason");
    assert!(
        reason.contains("no notification daemon") && reason.contains("3"),
        "failure carries the notifier stderr + exit status: {reason}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(notifier);
}

/// `whip message` slice-3 upgrades (spec/std-messaging.md local provider
/// notes): `--by` records the claimed-actor identity, `received_at` is a real
/// instant (it was `""`), and the message id is minted per DELIVERY — sending
/// identical text twice is TWO distinct messages (the old content-keyed id
/// silently deduped the second).
#[test]
fn whip_message_mints_distinct_ids_per_delivery() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("message-mint", "sqlite");
    let source = temp_path("message-mint", "whip");
    fs::write(
        &source,
        r#"
@service
workflow Minted

use std.messaging

channel room {
  provider fixture
}

output result Done
class Done { n string }

rule react
  when message from room as msg
=> {
  record Seen {
    text msg.text
  }
}

class Seen { text string }
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source_str, &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();

    // The SAME text, twice.
    for _ in 0..2 {
        let output = Command::new(bin)
            .args([
                "--store",
                store_str,
                "message",
                &instance,
                "--channel",
                "room",
                "--text",
                "ship it",
                "--by",
                "alice",
                "--program",
                source_str,
            ])
            .output()
            .expect("message runs");
        assert!(
            output.status.success(),
            "whip message failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let facts = run_json(bin, &["--store", store_str, "--json", "facts", &instance]);
    let messages: Vec<&Value> = facts
        .as_array()
        .expect("facts")
        .iter()
        .filter(|fact| fact.get("name").and_then(Value::as_str) == Some("message.room"))
        .collect();
    assert_eq!(
        messages.len(),
        2,
        "identical text re-sent is a DISTINCT delivery: {facts}"
    );
    let ids: Vec<&str> = messages
        .iter()
        .filter_map(|fact| fact.pointer("/value/message_id").and_then(Value::as_str))
        .collect();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1], "delivery-ordinal-minted ids are distinct");
    for message in &messages {
        assert_eq!(
            message.pointer("/value/sender").and_then(Value::as_str),
            Some("alice"),
            "--by records the claimed-actor identity"
        );
        assert!(
            message
                .pointer("/value/received_at")
                .and_then(Value::as_str)
                .is_some_and(|at| !at.is_empty()),
            "received_at is a real instant"
        );
    }

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Inbound messaging (spec/messaging.md): `whip message` injects a `Message` on a
/// declared channel and a `when message from <channel> as msg` rule fires, binding
/// the envelope. The fixture-parity counterpart of outbound `send`; live providers
/// stay gated.
#[test]
fn inbound_message_fires_when_message_from_rule() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("inbound", "sqlite");
    let source = temp_path("inbound", "whip");
    fs::write(
        &source,
        r#"
@service
workflow Inbound

use std.messaging

channel release_room {
  provider fixture
}

output result Decision

class Decision {
  note string
}

rule react
  when message from release_room as msg
=> {
  complete result {
    note msg.text
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");
    // The instance starts running and waits — no message has arrived yet.
    let dev = dev_until_idle(bin, store_str, source_str, &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();
    assert_eq!(instance_status(bin, store_str, &instance), "running");

    // Inject an inbound message on the channel, then step the reactive rule.
    run_text(
        bin,
        &[
            "--store",
            store_str,
            "message",
            &instance,
            "--channel",
            "release_room",
            "--text",
            "ship it",
            "--program",
            source_str,
        ],
    );
    run_text(
        bin,
        &[
            "--store",
            store_str,
            "step",
            &instance,
            "--program",
            source_str,
        ],
    );
    // Completing proves the `msg` binding resolved (an unresolved `msg.text`
    // would fail the rule rather than complete).
    assert_eq!(instance_status(bin, store_str, &instance), "completed");

    // The injected envelope is a well-formed `Message` fact on the channel.
    let facts = run_json(bin, &["--store", store_str, "--json", "facts", &instance]);
    let message = facts
        .as_array()
        .expect("facts")
        .iter()
        .find(|fact| fact.get("name").and_then(Value::as_str) == Some("message.release_room"))
        .expect("message fact");
    assert_eq!(
        message.pointer("/value/text").and_then(Value::as_str),
        Some("ship it")
    );
    assert_eq!(
        message.pointer("/value/channel").and_then(Value::as_str),
        Some("release_room")
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// The general readiness form `when fact <dotted.name> as x` matches runtime
/// facts; the English sugar phrases are abbreviations of it.
#[test]
fn general_fact_match_fires_rule() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("general-fact", "sqlite");
    let source = temp_path("general-fact", "whip");
    fs::write(
        &source,
        r#"
workflow GeneralFact

output result Seen

class Seen {
  agent string
}

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
}

rule begin
  when started
  when worker is available
=> {
  tell worker "go"
}

rule observe
  when fact agent.turn.completed as turn where turn.agent == "worker"
=> {
  complete result {
    agent turn.agent
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

fn run_text(bin: &str, args: &[&str]) {
    let output = Command::new(bin).args(args).output().expect("command runs");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Rules fan out per matched fact: two tickets, two progressions.
#[test]
fn rule_fans_out_per_matched_fact() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("flow-fan", "sqlite");
    let source = temp_path("flow-fan", "whip");
    fs::write(
        &source,
        r#"
@service
workflow FanTriage

class Ticket {
  id string
  title string
}

class Plan {
  id string
  plan string
}

agent triager {
  provider fixture
  profile "repo-reader"
  capacity 2
}

table tickets as Ticket [
  {
    id "T-1"
    title "Bug one"
  }
  {
    id "T-2"
    title "Bug two"
  }
]

rule plan_ticket
  when Ticket as ticket
=> {
  tell triager as turn """markdown
  Plan {{ ticket.title }}.
  """

  after turn succeeds {
    record Plan {
      id ticket.id
      plan turn.summary
    }
  }
}
"#,
    )
    .expect("write source");
    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
    let plans = facts
        .as_array()
        .expect("facts")
        .iter()
        .filter(|fact| fact.get("name").and_then(Value::as_str) == Some("Plan"))
        .count();
    assert_eq!(plans, 2);

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

const EXEC_FLOW: &str = r#"
use std.script
workflow ExecDemo

output result Ran
failure error Blocked

class Ran {
  out string
}

class Blocked {
  reason string
}

rule go
  when started
=> {
  exec "echo hello-from-exec" as run

  after run succeeds as out {
    complete result {
      out out.stdout
    }
  }

  after run fails {
    fail error {
      reason "exec blocked or failed"
    }
  }
}
"#;

/// Ungranted exec commands fail closed at STORE ADMISSION (script hard-off
/// Layer 2, spec/std-script.md): without the allowlist authority `script.raw`
/// is never seeded, so the effect blocks as blocked_by_capability
/// (`security.script_disabled`) before any provider run. Granted ones seed,
/// admit, run, and expose exit_code/stdout to the success branch.
#[test]
fn exec_is_gated_by_operator_grants() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (grant, expected) in [(None, "running"), (Some("echo *"), "completed")] {
        let store = temp_path("exec-gate", "sqlite");
        let source = temp_path("exec-gate", "whip");
        fs::write(&source, EXEC_FLOW).expect("write source");
        let mut command = Command::new(bin);
        command.args([
            "--store",
            store.to_str().expect("utf-8"),
            "--json",
            "run",
            source.to_str().expect("utf-8"),
            "--provider",
            "fixture",
            "--until",
            "idle",
        ]);
        match grant {
            Some(value) => {
                command.env("WHIPPLESCRIPT_EXEC_ALLOW", value);
            }
            None => {
                command.env_remove("WHIPPLESCRIPT_EXEC_ALLOW");
            }
        }
        let output = command.output().expect("command runs");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let dev: Value =
            serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("dev json");
        let instance = dev
            .get("instance_id")
            .and_then(Value::as_str)
            .expect("instance id");
        let store_str = store.to_str().expect("utf-8");
        assert_eq!(
            instance_status(bin, store_str, instance),
            expected,
            "grant={grant:?}"
        );
        if grant.is_none() {
            // The block is durable and pre-run: blocked_by_capability with the
            // hard-off diagnostic id, and the fails branch never fired (no
            // terminal — a disabled script crosses no exec boundary).
            let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
            let exec = effects
                .as_array()
                .expect("effects")
                .iter()
                .find(|effect| effect.get("kind").and_then(Value::as_str) == Some("exec.command"))
                .expect("exec effect")
                .clone();
            assert_eq!(
                exec.get("status").and_then(Value::as_str),
                Some("blocked_by_capability")
            );
            assert!(
                exec.get("policy_block_reason")
                    .and_then(Value::as_str)
                    .expect("policy block reason")
                    .contains("security.script_disabled"),
                "blocked exec carries the hard-off diagnostic id: {exec}"
            );
        }
        let _ = fs::remove_file(store);
        let _ = fs::remove_file(source);
    }
}

/// The other two-key negative (script hard-off Layer 2): operator authority
/// alone is not enough. A program that does NOT import std.script — the
/// forged-IR analog, since `dev` compiles without the check-time gate — never
/// gets `script.raw` seeded, so its raw exec blocks at store admission even
/// though the allowlist would have granted the command string.
#[test]
fn exec_without_import_blocks_even_with_allowlist() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("exec-noimport", "sqlite");
    let source = temp_path("exec-noimport", "whip");
    fs::write(&source, EXEC_FLOW.replace("use std.script\n", "")).expect("write source");
    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_exec_allow(bin, store_str, source.to_str().expect("utf-8"), "echo *");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "running");
    let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
    let exec = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|effect| effect.get("kind").and_then(Value::as_str) == Some("exec.command"))
        .expect("exec effect")
        .clone();
    assert_eq!(
        exec.get("status").and_then(Value::as_str),
        Some("blocked_by_capability")
    );
    assert!(
        exec.get("policy_block_reason")
            .and_then(Value::as_str)
            .expect("policy block reason")
            .contains("security.script_disabled"),
        "blocked exec carries the hard-off diagnostic id: {exec}"
    );
    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

#[test]
fn hosted_check_rejects_raw_exec() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let source = temp_path("hosted-raw-exec", "whip");
    fs::write(
        &source,
        r#"
use std.script
workflow HostedRawExec

output result Report

class Report {
  message string
}

rule go
  when started
=> {
  exec "echo hi" as run

  after run succeeds {
    complete result {
      message "done"
    }
  }
}
"#,
    )
    .expect("write source");
    let output = Command::new(bin)
        .args([
            "check",
            "--exec-profile",
            "hosted",
            source.to_str().expect("utf-8"),
        ])
        .output()
        .expect("command runs");
    assert!(
        !output.status.success(),
        "hosted raw exec check unexpectedly passed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("raw `exec \"...\"` is not allowed"));
    let _ = fs::remove_file(source);
}

/// DQ-1 authority-split namespace: the I/O-boundary packages hard-error at
/// check when their constructs appear without the `use std.<pkg>` import —
/// the import line is uniformly load-bearing, never decoration. (The ambient
/// packages — agent, coercion, coord, tracker, time, workflow, memory — need
/// no import; every non-`use` example in this suite already exercises that.)
#[test]
fn authority_packages_require_their_import() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, body, expected) in [
        (
            "signal-no-ingress",
            "signal go.now {\n  x string\n}\n\nrule j\n  when go.now as g\n=> {\n  complete result { note g.x }\n}",
            "requires `use std.ingress`",
        ),
        (
            "channel-no-messaging",
            "channel updates\n\nrule j\n  when started\n=> {\n  complete result { note \"ok\" }\n}",
            "requires `use std.messaging`",
        ),
        (
            "filestore-no-files",
            "file store docs {\n  root \"./docs\"\n  allow read [\"**\"]\n}\n\nrule j\n  when started\n=> {\n  complete result { note \"ok\" }\n}",
            "requires `use std.files`",
        ),
    ] {
        let source = temp_path(label, "whip");
        fs::write(
            &source,
            format!(
                "workflow Gate\n\noutput result Done\n\nclass Done {{\n  note string\n}}\n\n{body}\n"
            ),
        )
        .expect("write source");
        let output = Command::new(bin)
            .args(["check", source.to_str().expect("utf-8")])
            .output()
            .expect("check runs");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains(expected),
            "{label}: expected `{expected}`\nstderr:\n{stderr}"
        );
        let _ = fs::remove_file(source);
    }
}

#[test]
fn exec_is_hard_off_without_use_std_script() {
    // Script hard-off (M5 import ladder, Layer 1): exec is a check error unless
    // the program imports std.script. Adding the import clears it.
    let bin = env!("CARGO_BIN_EXE_whip");
    let body = |uses: &str| {
        format!(
            "{uses}workflow HardOff\n\
             output result R\n\
             class R {{ m string }}\n\
             rule go\n  when started\n=> {{\n  \
             exec \"echo hi\" as run\n  \
             after run succeeds {{ complete result {{ m \"ok\" }} }}\n}}\n"
        )
    };

    let without = temp_path("hardoff-without", "whip");
    fs::write(&without, body("")).expect("write");
    let out = Command::new(bin)
        .args(["check", without.to_str().expect("utf-8")])
        .output()
        .expect("runs");
    assert!(
        !out.status.success(),
        "exec without use std.script must fail"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("security.script_disabled"),
        "expected the hard-off diagnostic id"
    );
    let _ = fs::remove_file(&without);

    let with = temp_path("hardoff-with", "whip");
    fs::write(&with, body("use std.script\n")).expect("write");
    let out = Command::new(bin)
        .args(["check", with.to_str().expect("utf-8")])
        .output()
        .expect("runs");
    assert!(
        out.status.success(),
        "exec with use std.script must pass: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = fs::remove_file(&with);
}

#[test]
fn hosted_exec_runs_content_pinned_capability_with_json_stdin() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("hosted-exec", "sqlite");
    let source = temp_path("hosted-exec", "whip");
    let script = temp_path("hosted-exec-report", "py");
    let manifest = temp_path("hosted-exec-manifest", "json");
    let script_source = "#!/usr/bin/env python3\nimport json, sys\npayload = json.load(sys.stdin)\nprint(json.dumps({\"message\": payload[\"text\"]}))\n";
    fs::write(&script, script_source).expect("write script");
    fs::write(
        &manifest,
        serde_json::json!({
            "echo_report": {
                "argv": ["python3", script.to_str().expect("utf-8")],
                "sha256": "f62856dbf1183d28f7d8f8fe8cd3aec76e66b4659e2e5f6d4b687a2d64fd1d23"
            }
        })
        .to_string(),
    )
    .expect("write manifest");
    fs::write(
        &source,
        r#"
use std.script
workflow HostedExec

output result Report

class Request {
  text string
}

class Report {
  message string
}

table requests as Request [
  {
    text "hello-hosted"
  }
]

rule go
  when Request as request
=> {
  exec echo_report with request -> Report as report

  after report succeeds as out {
    complete result {
      message out.message
    }
  }
}
"#,
    )
    .expect("write source");

    let dev = dev_until_idle(
        bin,
        store.to_str().expect("utf-8"),
        source.to_str().expect("utf-8"),
        &[
            "--exec-profile",
            "hosted",
            "--script-manifest",
            manifest.to_str().expect("utf-8"),
        ],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(
        instance_status(bin, store.to_str().expect("utf-8"), instance),
        "completed"
    );
    let log = run_json(
        bin,
        &[
            "--store",
            store.to_str().expect("utf-8"),
            "--json",
            "log",
            instance,
        ],
    );
    let terminal = log
        .as_array()
        .expect("events")
        .iter()
        .find(|event| {
            event.get("event_type").and_then(Value::as_str) == Some("effect.terminal")
                && event.pointer("/payload/provider").and_then(Value::as_str) == Some("exec")
        })
        .expect("exec terminal event");
    assert_eq!(
        terminal.pointer("/payload/status").and_then(Value::as_str),
        Some("completed")
    );
    assert_eq!(
        terminal
            .pointer("/payload/metadata/sha256")
            .and_then(Value::as_str),
        Some("f62856dbf1183d28f7d8f8fe8cd3aec76e66b4659e2e5f6d4b687a2d64fd1d23")
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(script);
    let _ = fs::remove_file(manifest);
}

#[test]
fn hosted_exec_hash_mismatch_fails_before_spawn() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("hosted-exec-mismatch", "sqlite");
    let source = temp_path("hosted-exec-mismatch", "whip");
    let script = temp_path("hosted-exec-mismatch-report", "py");
    let marker = temp_path("hosted-exec-mismatch-marker", "txt");
    let manifest = temp_path("hosted-exec-mismatch-manifest", "json");
    let script_source = format!(
        "#!/usr/bin/env python3\nimport json, pathlib, sys\npathlib.Path({marker:?}).write_text('spawned')\npayload = json.load(sys.stdin)\nprint(json.dumps({{\"message\": payload[\"text\"]}}))\n",
        marker = marker.to_str().expect("utf-8")
    );
    fs::write(&script, script_source).expect("write script");
    fs::write(
        &manifest,
        serde_json::json!({
            "echo_report": {
                "argv": ["python3", script.to_str().expect("utf-8")],
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        })
        .to_string(),
    )
    .expect("write manifest");
    fs::write(
        &source,
        r#"
use std.script
workflow HostedExecMismatch

output result Report
failure error Failed

class Request {
  text string
}

class Report {
  message string
}

class Failed {
  reason string
}

table requests as Request [
  {
    text "hello-hosted"
  }
]

rule go
  when Request as request
=> {
  exec echo_report with request -> Report as report

  after report succeeds as out {
    complete result {
      message out.message
    }
  }

  after report fails {
    fail error {
      reason "hash mismatch"
    }
  }
}
"#,
    )
    .expect("write source");

    let dev = dev_until_idle(
        bin,
        store.to_str().expect("utf-8"),
        source.to_str().expect("utf-8"),
        &[
            "--exec-profile",
            "hosted",
            "--script-manifest",
            manifest.to_str().expect("utf-8"),
        ],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(
        instance_status(bin, store.to_str().expect("utf-8"), instance),
        "failed"
    );
    assert!(!marker.exists(), "script was spawned despite hash mismatch");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(script);
    let _ = fs::remove_file(marker);
    let _ = fs::remove_file(manifest);
}

/// Inline `decide` lowers to a coerce effect and the workflow continues from
/// its completion.
#[test]
fn inline_decide_completes() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("decide", "sqlite");
    let source = temp_path("decide", "whip");
    fs::write(
        &source,
        r#"
workflow DecideDemo

output result Verdict

class Verdict {
  summary string
}

rule go
  when started
=> {
  decide "Is this workflow worth running?" -> { worth bool, reason string } as verdict

  after verdict succeeds as v {
    complete result {
      summary "decided"
    }
  }
}
"#,
    )
    .expect("write source");
    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");
    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Unknown statements and malformed modifiers are check errors, not silent
/// no-ops.
#[test]
fn unknown_statements_and_modifiers_are_rejected() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, body, expected) in [
        (
            "unknown-stmt",
            "frobnicate task",
            "unknown rule body statement `frobnicate`",
        ),
        (
            "bad-timeout",
            "tell worker as turn timeout banana \"go\"",
            "expected a duration after `timeout`",
        ),
        (
            "flow-only",
            "on fails {\n    record Seen {\n      id \"x\"\n    }\n  }",
            "not rule body statements",
        ),
    ] {
        let source = temp_path(label, "whip");
        fs::write(
            &source,
            format!(
                r#"
workflow Gate

class Seen {{
  id string
}}

agent worker {{
  provider fixture
  profile "x"
  capacity 1
}}

@external
rule go
  when Seen as task
=> {{
  {body}
}}
"#
            ),
        )
        .expect("write source");
        let output = Command::new(bin)
            .args(["check", source.to_str().expect("utf-8")])
            .output()
            .expect("command runs");
        assert!(!output.status.success(), "{label} should fail check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
        let _ = fs::remove_file(source);
    }
}

const TIMER_UNTIL_SOURCE: &str = r#"
workflow TimerUntil

output result Done

class Done {
  note string
}

class Job {
  id string
  fireAt time
}

rule seed
  when started
=> {
  record Job {
    id "J-1"
    fireAt "DEADLINE"
  }
}

rule wait_for_deadline
  when Job as j
=> {
  timer until OPERAND as deadline

  after deadline succeeds {
    complete result {
      note "deadline reached"
    }
  }
}
"#;

fn timer_until_source(deadline: &str, operand: &str) -> String {
    TIMER_UNTIL_SOURCE
        .replace("DEADLINE", deadline)
        .replace("OPERAND", operand)
}

/// An absolute `timer until` literal in the past fires on the worker pass and
/// the `after ... succeeds` terminal completes the instance — from a fact
/// trigger, the case where the deadline comparison and NULL duration mapping
/// previously broke the time pass.
#[test]
fn timer_until_past_literal_completes_from_fact_trigger() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("until-past", "sqlite");
    let source = temp_path("until-past", "whip");
    fs::write(
        &source,
        timer_until_source("2020-01-01T00:00:00Z", "\"2020-01-01T00:00:00Z\""),
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
    let timer = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|effect| effect.get("kind").and_then(Value::as_str) == Some("timer.wait"))
        .expect("timer effect");
    assert_eq!(
        timer.get("status").and_then(Value::as_str),
        Some("completed")
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// `timer until <path>` resolves a `time`-typed fact field into the effect's
/// absolute deadline and fires identically to the literal form.
#[test]
fn timer_until_fact_path_resolves_and_completes() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("until-path", "sqlite");
    let source = temp_path("until-path", "whip");
    fs::write(
        &source,
        timer_until_source("2020-01-01T00:00:00Z", "j.fireAt"),
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
    let timer = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|effect| effect.get("kind").and_then(Value::as_str) == Some("timer.wait"))
        .expect("timer effect");
    assert_eq!(
        timer.pointer("/input/deadline_at").and_then(Value::as_str),
        Some("2020-01-01T00:00:00Z"),
        "path operand resolves to the recorded instant, not the path text"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// A future absolute deadline pends: the timer stays queued and the instance
/// stays running until the clock reaches the target.
#[test]
fn timer_until_future_deadline_stays_queued() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("until-future", "sqlite");
    let source = temp_path("until-future", "whip");
    fs::write(
        &source,
        timer_until_source("2099-01-01T00:00:00Z", "j.fireAt"),
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "running");

    let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
    let timer = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|effect| effect.get("kind").and_then(Value::as_str) == Some("timer.wait"))
        .expect("timer effect");
    assert_eq!(timer.get("status").and_then(Value::as_str), Some("queued"));

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// DR-0032 P3 (per-kind failure extras): an exec failure binding exposes
/// `f.exit_code`, and the value is the command's real exit status.
#[test]
fn exec_failure_binding_exposes_exit_code() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("exec-exit-code", "sqlite");
    let source = temp_path("exec-exit-code", "whip");
    fs::write(
        &source,
        r#"
use std.script

workflow ExecExit

output result Done
failure error Broken

class Done {
  note string
}

class Broken {
  reason string
  code int
}

class Trigger {
  id string
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  exec "false" as x

  after x succeeds {
    complete result { note "ok" }
  }

  after x fails as f {
    fail error {
      reason f.reason
      code f.exit_code
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_exec_allow(bin, store_str, source.to_str().expect("utf-8"), "false");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let failed = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.failed"))
        .expect("workflow.failed event");
    assert_eq!(
        failed
            .pointer("/payload/payload/code")
            .and_then(Value::as_i64),
        Some(1),
        "f.exit_code binds the real exit status: {failed}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// DR-0032 P3: coerce and tell failure bindings expose `f.error_class` (a
/// coarse, redaction-safe classification).
#[test]
fn coerce_and_tell_failure_bindings_expose_error_class() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("error-class", "sqlite");
    let source = temp_path("error-class", "whip");
    fs::write(
        &source,
        r#"
use std.coercion

workflow ErrorClass

output result Done
failure error Broken

class Done {
  note string
}

class Broken {
  reason string
  klass string
}

class Trigger {
  id string
}

class Verdict {
  priority string
}

coerce judge(id string) -> Verdict {
  prompt "Classify {{ id }}"
}

table seed as Trigger [
  { id "t" }
]

rule r
  when Trigger as t
=> {
  coerce judge(t.id) as v

  after v succeeds {
    complete result { note "ok" }
  }

  after v fails as f {
    fail error {
      reason f.reason
      klass f.error_class
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &["--fail"]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let failed = log
        .as_array()
        .expect("log")
        .iter()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.failed"))
        .expect("workflow.failed event");
    assert_eq!(
        failed
            .pointer("/payload/payload/klass")
            .and_then(Value::as_str),
        Some("provider_error"),
        "f.error_class binds the classification: {failed}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// DR-0032 P3 (typed invoke failure at runtime): when the child declares a
/// sole shared failure contract, the parent's `after child fails as f` binds
/// the child's typed failure fields (merged under the EffectError base), so
/// `f.<child field>` resolves at runtime, matching the static typing.
#[test]
fn invoke_failure_binding_carries_child_typed_fields() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("invoke-child-fail", "sqlite");
    let source = temp_path("invoke-child-fail", "whip");
    fs::write(
        &source,
        r#"
class ChildBroken {
  reason string
  code string
}

workflow Parent {
  input task ParentTask
  output result Done
  failure error Broken

  class ParentTask {
    id string
  }

  class Done {
    note string
  }

  class Broken {
    reason string
    child_code string
  }

  rule r
    when ParentTask as t
  => {
    invoke Child {
      task { id t.id }
    } as child

    after child succeeds {
      complete result { note "ok" }
    }

    after child fails as f {
      fail error {
        reason f.reason
        child_code f.code
      }
    }
  }
}

workflow Child {
  input task ChildTask
  output result ChildDone
  failure error ChildBroken

  class ChildTask {
    id string
  }

  class ChildDone {
    note string
  }

  rule go
    when ChildTask as task
  => {
    fail error {
      reason "child says no"
      code "E42"
    }
  }
}
"#,
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let output = Command::new(bin)
        .args([
            "--store",
            store_str,
            "--input",
            r#"{"task":{"id":"t1"}}"#,
            "--json",
            "run",
            source.to_str().expect("utf-8"),
            "--root",
            "Parent",
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .output()
        .expect("run");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let dev: Value =
        serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("dev json");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");
    let log = run_json(bin, &["--store", store_str, "--json", "log", instance]);
    let failed = log
        .as_array()
        .expect("log")
        .iter()
        .rev()
        .find(|event| event.get("event_type").and_then(Value::as_str) == Some("workflow.failed"))
        .expect("workflow.failed event");
    assert_eq!(
        failed
            .pointer("/payload/payload/child_code")
            .and_then(Value::as_str),
        Some("E42"),
        "f.code binds the child's typed failure field: {failed}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

fn dev_with_exec_allow(bin: &str, store: &str, source: &str, allow: &str) -> Value {
    let mut command = Command::new(bin);
    command
        .args([
            "--store",
            store,
            "--json",
            "run",
            source,
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .env("WHIPPLESCRIPT_EXEC_ALLOW", allow);
    let output = command.output().expect("command runs");
    assert!(
        output.status.success(),
        "dev failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("dev json")
}

const EXEC_PARSE_SINGLE: &str = r#"
use std.script
workflow ExecParseSingle

output result Done
failure error Failed

class Done {
  total int
}

class Failed {
  reason string
}

class Report {
  count int
  label string
}

rule run_report
  when started
=> {
  exec "COMMAND" -> Report as x

  after x succeeds as r {
    complete result {
      total r.count
    }
  }
  after x fails {
    fail error {
      reason "report did not parse"
    }
  }
}
"#;

/// `exec ... -> Report as x` parses stdout at the result boundary and binds
/// the typed value in the success branch — including escaped quotes in the
/// command string.
#[test]
fn exec_parse_single_binds_typed_value() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("exec-parse", "sqlite");
    let source = temp_path("exec-parse", "whip");
    fs::write(
        &source,
        EXEC_PARSE_SINGLE.replace(
            "COMMAND",
            "echo '{\\\"count\\\": 7, \\\"label\\\": \\\"ok\\\"}'",
        ),
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_exec_allow(bin, store_str, source.to_str().expect("utf-8"), "echo *");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let trace = run_json(bin, &["--store", store_str, "--json", "status", instance]);
    assert_eq!(
        trace
            .pointer("/workflow_terminal/payload/total")
            .and_then(Value::as_i64),
        Some(7),
        "{trace}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Parse or schema-validation failure makes the effect fail even on exit 0,
/// routing to `after x fails`.
#[test]
fn exec_parse_failure_routes_to_fails_branch() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("exec-parse-bad", "sqlite");
    let source = temp_path("exec-parse-bad", "whip");
    fs::write(
        &source,
        EXEC_PARSE_SINGLE.replace("COMMAND", "echo not-json"),
    )
    .expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_exec_allow(bin, store_str, source.to_str().expect("utf-8"), "echo *");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

const EXEC_PARSE_EACH: &str = r#"
use std.script
workflow ExecParseEach

output result Done

class Done {
  total int
}

class WorkItem {
  id string
  title string
}

rule list_items
  when started
=> {
  exec "COMMAND" -> each WorkItem
}

rule finish
  when WorkItem as item where count(WorkItem) == 3
=> {
  complete result {
    total count(WorkItem)
  }
}
"#;

/// `-> each` records one typed `ingest` fact per JSONL line and ordinary
/// per-fact rule fan-out reacts to them.
#[test]
fn exec_parse_each_fans_out_ingest_facts() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("exec-each", "sqlite");
    let source = temp_path("exec-each", "whip");
    let script = temp_path("exec-each", "sh");
    fs::write(
        &script,
        "#!/bin/sh\necho '{\"id\": \"W-1\", \"title\": \"first\"}'\necho '{\"id\": \"W-2\", \"title\": \"second\"}'\necho '{\"id\": \"W-3\", \"title\": \"third\"}'\n",
    )
    .expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let script_str = script.to_str().expect("utf-8");
    fs::write(&source, EXEC_PARSE_EACH.replace("COMMAND", script_str)).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_exec_allow(bin, store_str, source.to_str().expect("utf-8"), script_str);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
    let items = facts
        .as_array()
        .expect("facts")
        .iter()
        .filter(|fact| fact.get("name").and_then(Value::as_str) == Some("WorkItem"))
        .collect::<Vec<_>>();
    assert_eq!(items.len(), 3, "{facts}");
    for item in items {
        assert_eq!(
            item.get("provenance_class").and_then(Value::as_str),
            Some("ingest"),
            "{item}"
        );
    }

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(script);
}

/// A malformed line fails the whole stream: the effect lands `failed` and no
/// partial facts commit.
#[test]
fn exec_parse_stream_is_all_or_nothing() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("exec-atomic", "sqlite");
    let source = temp_path("exec-atomic", "whip");
    let script = temp_path("exec-atomic", "sh");
    fs::write(
        &script,
        "#!/bin/sh\necho '{\"id\": \"W-1\", \"title\": \"first\"}'\necho 'not json at all'\necho '{\"id\": \"W-3\", \"title\": \"third\"}'\n",
    )
    .expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    let script_str = script.to_str().expect("utf-8");
    fs::write(&source, EXEC_PARSE_EACH.replace("COMMAND", script_str)).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_exec_allow(bin, store_str, source.to_str().expect("utf-8"), script_str);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");

    let effects = run_json(bin, &["--store", store_str, "--json", "effects", instance]);
    let exec = effects
        .as_array()
        .expect("effects")
        .iter()
        .find(|effect| effect.get("kind").and_then(Value::as_str) == Some("exec.command"))
        .expect("exec effect");
    assert_eq!(exec.get("status").and_then(Value::as_str), Some("failed"));

    let facts = run_json(bin, &["--store", store_str, "--json", "facts", instance]);
    let items = facts
        .as_array()
        .expect("facts")
        .iter()
        .filter(|fact| fact.get("name").and_then(Value::as_str) == Some("WorkItem"))
        .count();
    assert_eq!(items, 0, "partial stream must not commit");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(script);
}

/// `->` parse targets are statically checked: schema must exist, single needs
/// a binding, `each` rejects one.
#[test]
fn exec_parse_static_checks_reject_bad_targets() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, source_text, expected) in [
        (
            "unknown-schema",
            EXEC_PARSE_SINGLE
                .replace("COMMAND", "echo x")
                .replace("-> Report as x", "-> Mystery as x"),
            "unknown schema `Mystery`",
        ),
        (
            "single-without-binding",
            EXEC_PARSE_SINGLE
                .replace("COMMAND", "echo x")
                .replace("-> Report as x", "-> Report"),
            "needs an `as` binding",
        ),
        (
            "each-with-binding",
            EXEC_PARSE_EACH
                .replace("COMMAND", "echo x")
                .replace("-> each WorkItem", "-> each WorkItem as items"),
            "stream of facts, not a single binding",
        ),
    ] {
        let source = temp_path(label, "whip");
        fs::write(&source, source_text).expect("write source");
        let output = Command::new(bin)
            .args(["check", source.to_str().expect("utf-8")])
            .output()
            .expect("command runs");
        assert!(!output.status.success(), "{label} should fail check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
        let _ = fs::remove_file(source);
    }
}

const LEASE_SOURCE: &str = r#"
workflow LeaseDemo

output result Done
failure error Failed

class Done {
  note string
}

class Failed {
  reason string
}

class Environment {
  name string
}

class ReadyToShip {
  env string
}

lease deploy_slot {
  key Environment
  slots 1
  ttl 10m
}

rule seed
  when started
=> {
  record ReadyToShip {
    env "prod"
  }
}

rule ship
  when ReadyToShip as r
=> {
  acquire deploy_slot for r.env as slot

  after slot held {
    release slot
    complete result {
      note "deployed {{ r.env }}"
    }
  }
  after slot contended {
    fail error {
      reason "deploy slot busy"
    }
  }
}
"#;

const PARTITIONED_LEASE_SOURCE: &str = r#"
workflow __WORKFLOW__

output result Held
failure error Failed

class Held {
  tag string
}

class Failed {
  reason string
}

class Key {
  id string
}

lease slot {
  key Key
  slots 1
  ttl 1h
}

rule seed
  when started
=> {
  record Key {
    id "same"
  }
}

rule grab
  when Key as k
=> {
  acquire slot for k.id until ttl as lease

  after lease held {
    record Held {
      tag k.id
    }
  }
  after lease contended {
    fail error {
      reason "busy"
    }
  }
}
"#;

fn dev_with_coordination(bin: &str, store: &str, source: &str, coordination: &str) -> Value {
    let mut command = Command::new(bin);
    command
        .args([
            "--store",
            store,
            "--json",
            "run",
            source,
            "--provider",
            "fixture",
            "--until",
            "idle",
        ])
        .env("WHIPPLESCRIPT_COORDINATION_STORE", coordination);
    let output = command.output().expect("command runs");
    assert!(
        output.status.success(),
        "dev failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("dev json")
}

/// Acquire wins a free slot, the `held` arm runs, and explicit release plus
/// terminal auto-release leave no lease behind.
#[test]
fn lease_acquire_held_release_completes() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("lease-held", "sqlite");
    let source = temp_path("lease-held", "whip");
    let coordination = temp_path("lease-held-coord", "sqlite");
    fs::write(&source, LEASE_SOURCE).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let coordination_str = coordination.to_str().expect("utf-8");
    let dev = dev_with_coordination(
        bin,
        store_str,
        source.to_str().expect("utf-8"),
        coordination_str,
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "completed");

    let leases = {
        let output = Command::new(bin)
            .args(["--json", "leases"])
            .env("WHIPPLESCRIPT_COORDINATION_STORE", coordination_str)
            .output()
            .expect("command runs");
        let stdout = String::from_utf8_lossy(&output.stdout);
        serde_json::from_str::<Value>(&stdout[stdout.find('[').expect("json")..]).expect("json")
    };
    assert_eq!(leases.as_array().map(Vec::len), Some(0), "{leases}");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// A held slot contends: the second instance routes to the `contended` arm —
/// a normal branchable outcome, not an error.
#[test]
fn lease_contention_routes_to_contended_arm() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("lease-contended", "sqlite");
    let source = temp_path("lease-contended", "whip");
    let coordination = temp_path("lease-contended-coord", "sqlite");
    fs::write(&source, LEASE_SOURCE).expect("write source");

    // Seed a foreign holder so the acquire contends.
    {
        let mut seeded = whipplescript_store::coordination::CoordinationStore::open(&coordination)
            .expect("open coordination store");
        assert_eq!(
            seeded
                .try_acquire_for_owner(
                    "local/LeaseDemo",
                    "deploy_slot",
                    "prod",
                    1,
                    600,
                    "ins_other"
                )
                .expect("seed holder"),
            whipplescript_store::coordination::AcquireOutcome::Held
        );
    }

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_coordination(
        bin,
        store_str,
        source.to_str().expect("utf-8"),
        coordination.to_str().expect("utf-8"),
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    assert_eq!(instance_status(bin, store_str, instance), "failed");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

#[test]
fn coordination_leases_are_partitioned_by_workflow_owner() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("lease-partition", "sqlite");
    let source_a = temp_path("lease-partition-a", "whip");
    let source_b = temp_path("lease-partition-b", "whip");
    let coordination = temp_path("lease-partition-coord", "sqlite");
    fs::write(
        &source_a,
        PARTITIONED_LEASE_SOURCE.replace("__WORKFLOW__", "PartitionAlpha"),
    )
    .expect("write source a");
    fs::write(
        &source_b,
        PARTITIONED_LEASE_SOURCE.replace("__WORKFLOW__", "PartitionBeta"),
    )
    .expect("write source b");

    let store_str = store.to_str().expect("utf-8");
    let coordination_str = coordination.to_str().expect("utf-8");
    let first = dev_with_coordination(
        bin,
        store_str,
        source_a.to_str().expect("utf-8"),
        coordination_str,
    );
    let first_instance = first
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("first instance");
    assert_eq!(instance_status(bin, store_str, first_instance), "running");

    let second = dev_with_coordination(
        bin,
        store_str,
        source_b.to_str().expect("utf-8"),
        coordination_str,
    );
    let second_instance = second
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("second instance");
    assert_eq!(instance_status(bin, store_str, second_instance), "running");

    let output = Command::new(bin)
        .args(["--json", "leases"])
        .env("WHIPPLESCRIPT_COORDINATION_STORE", coordination_str)
        .output()
        .expect("leases runs");
    assert!(
        output.status.success(),
        "leases failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let leases: Value =
        serde_json::from_str(&stdout[stdout.find('[').expect("json")..]).expect("leases json");
    let owners: Vec<_> = leases
        .as_array()
        .expect("lease array")
        .iter()
        .filter_map(|lease| lease.get("owner").and_then(Value::as_str))
        .collect();
    assert_eq!(owners.len(), 2, "{leases}");
    assert!(owners.contains(&"local/PartitionAlpha"), "{leases}");
    assert!(owners.contains(&"local/PartitionBeta"), "{leases}");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source_a);
    let _ = fs::remove_file(source_b);
    let _ = fs::remove_file(coordination);
}

#[test]
fn shared_coordination_lease_opts_into_cross_workflow_contention() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("lease-shared", "sqlite");
    let source_a = temp_path("lease-shared-a", "whip");
    let source_b = temp_path("lease-shared-b", "whip");
    let coordination = temp_path("lease-shared-coord", "sqlite");
    let shared_source =
        PARTITIONED_LEASE_SOURCE.replace("lease slot {\n  key", "lease slot {\n  shared\n  key");
    fs::write(
        &source_a,
        shared_source.replace("__WORKFLOW__", "SharedAlpha"),
    )
    .expect("write source a");
    fs::write(
        &source_b,
        shared_source.replace("__WORKFLOW__", "SharedBeta"),
    )
    .expect("write source b");

    let store_str = store.to_str().expect("utf-8");
    let coordination_str = coordination.to_str().expect("utf-8");
    let first = dev_with_coordination(
        bin,
        store_str,
        source_a.to_str().expect("utf-8"),
        coordination_str,
    );
    let first_instance = first
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("first instance");
    assert_eq!(instance_status(bin, store_str, first_instance), "running");

    let second = dev_with_coordination(
        bin,
        store_str,
        source_b.to_str().expect("utf-8"),
        coordination_str,
    );
    let second_instance = second
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("second instance");
    assert_eq!(instance_status(bin, store_str, second_instance), "failed");

    let output = Command::new(bin)
        .args(["--json", "leases"])
        .env("WHIPPLESCRIPT_COORDINATION_STORE", coordination_str)
        .output()
        .expect("leases runs");
    assert!(
        output.status.success(),
        "leases failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let leases: Value =
        serde_json::from_str(&stdout[stdout.find('[').expect("json")..]).expect("leases json");
    let rows = leases.as_array().expect("lease array");
    assert_eq!(rows.len(), 1, "{leases}");
    assert_eq!(
        rows[0].get("owner").and_then(Value::as_str),
        Some("shared"),
        "{leases}"
    );
    assert_eq!(
        rows[0].get("holder").and_then(Value::as_str),
        Some(first_instance),
        "{leases}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source_a);
    let _ = fs::remove_file(source_b);
    let _ = fs::remove_file(coordination);
}

const COUNTER_SOURCE: &str = r#"
workflow CounterDemo

output result Done
failure error Failed

class Done {
  note string
}

class Failed {
  reason string
}

class Customer {
  id string
}

class ReviewTask {
  customer string
  estTokens int
}

counter model_budget {
  key Customer
  cap 1000
  reset daily
}

rule seed
  when started
=> {
  record ReviewTask {
    customer "cust-1"
    estTokens 600
  }
}

rule review
  when ReviewTask as t
=> {
  consume model_budget for t.customer amount t.estTokens as spend

  after spend ok {
    complete result {
      note "within budget"
    }
  }
  after spend over {
    fail error {
      reason "over budget"
    }
  }
}
"#;

/// Cap invariant across instances: the first consume fits, the second
/// (sharing the workspace counter) is over budget and downgrades.
#[test]
fn counter_consume_ok_then_over() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let coordination = temp_path("counter-coord", "sqlite");
    let coordination_str = coordination.to_str().expect("utf-8");
    let source = temp_path("counter", "whip");
    fs::write(&source, COUNTER_SOURCE).expect("write source");

    for (label, expected) in [("first", "completed"), ("second", "failed")] {
        let store = temp_path(&format!("counter-{label}"), "sqlite");
        let store_str = store.to_str().expect("utf-8");
        let dev = dev_with_coordination(
            bin,
            store_str,
            source.to_str().expect("utf-8"),
            coordination_str,
        );
        let instance = dev
            .get("instance_id")
            .and_then(Value::as_str)
            .expect("instance id");
        assert_eq!(
            instance_status(bin, store_str, instance),
            expected,
            "{label}"
        );
        let _ = fs::remove_file(store);
    }

    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// The coordination safety model is enforced statically: undeclared
/// resources, unhandled outcomes, leak-prone held branches, and multi-lease
/// progressions are check errors.
#[test]
fn coordination_static_checks() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, source_text, expected) in [
        (
            "undeclared-lease",
            LEASE_SOURCE.replace("lease deploy_slot", "lease other_slot"),
            "acquires undeclared lease `deploy_slot`",
        ),
        (
            "missing-contended",
            LEASE_SOURCE.replace(
                "  after slot contended {\n    fail error {\n      reason \"deploy slot busy\"\n    }\n  }\n",
                "",
            ),
            "does not handle the `contended` outcome",
        ),
        (
            "held-forever",
            LEASE_SOURCE.replace(
                "  after slot held {\n    release slot\n    complete result {\n      note \"deployed {{ r.env }}\"\n    }\n  }\n",
                "  after slot held {\n    record ReadyToShip {\n      env \"staging\"\n    }\n  }\n",
            ),
            "can hold lease `slot` forever",
        ),
        (
            "two-leases",
            LEASE_SOURCE.replace(
                "  acquire deploy_slot for r.env as slot\n",
                "  acquire deploy_slot for r.env as slot\n  acquire deploy_slot for r.env as slot2\n",
            ),
            "acquires more than one lease in a single progression",
        ),
        (
            "missing-over",
            COUNTER_SOURCE.replace(
                "  after spend over {\n    fail error {\n      reason \"over budget\"\n    }\n  }\n",
                "",
            ),
            "does not handle the `over` outcome",
        ),
    ] {
        let source = temp_path(label, "whip");
        fs::write(&source, source_text).expect("write source");
        let output = Command::new(bin)
            .args(["check", source.to_str().expect("utf-8")])
            .output()
            .expect("command runs");
        assert!(!output.status.success(), "{label} should fail check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
        let _ = fs::remove_file(source);
    }
}

/// The OTel ambassador (spec/observability.md C8): `whip otel-export` builds
/// OTLP-JSON from the durable log; `--dry-run` prints it, and structural
/// attributes (never content) ride each span.
#[test]
fn otel_export_dry_run_emits_structural_spans() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("otel", "sqlite");
    let source = temp_path("otel", "whip");
    let coordination = temp_path("otel-coord", "sqlite");
    fs::write(&source, LEASE_SOURCE).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let dev = dev_with_coordination(
        bin,
        store_str,
        source.to_str().expect("utf-8"),
        coordination.to_str().expect("utf-8"),
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");

    let payload = run_json(
        bin,
        &["--store", store_str, "otel-export", instance, "--dry-run"],
    );
    let spans = payload
        .pointer("/resourceSpans/0/scopeSpans/0/spans")
        .and_then(Value::as_array)
        .expect("spans");
    assert!(!spans.is_empty(), "{payload}");
    let span = &spans[0];
    assert!(
        span.get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.contains("lease.acquire")),
        "{span}"
    );
    let attributes = span
        .get("attributes")
        .and_then(Value::as_array)
        .expect("attrs");
    assert!(attributes.iter().any(|attr| {
        attr.get("key").and_then(Value::as_str) == Some("whipplescript.instance_id")
    }));

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// `whip otel-export` POSTs OTLP/HTTP+JSON to a real endpoint (validated here by
/// an in-process collector — no external backend needed), then `whip telemetry
/// status` reflects the emit-once cursor and `whip telemetry reset-cursor` clears
/// it (spec/std-telemetry.md export-cursor management).
#[test]
fn otel_export_posts_to_collector_then_status_and_reset() {
    use std::io::{Read, Write};

    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("otel-post", "sqlite");
    let source = temp_path("otel-post", "whip");
    let coordination = temp_path("otel-post-coord", "sqlite");
    fs::write(&source, LEASE_SOURCE).expect("write source");
    let store_str = store.to_str().expect("utf-8").to_owned();
    let dev = dev_with_coordination(
        bin,
        &store_str,
        source.to_str().expect("utf-8"),
        coordination.to_str().expect("utf-8"),
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();

    // In-process OTLP collector: accept one POST, capture its body, reply 200.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind collector");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let collector = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                    let content_length = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = pos + 4;
                    while buf.len() < body_start + content_length {
                        let read = stream.read(&mut chunk).unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..read]);
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    let body = String::from_utf8_lossy(&buf[body_start..]).to_string();
                    let _ = tx.send(body);
                    break;
                }
            }
        }
    });

    let export = Command::new(bin)
        .args(["--store", &store_str, "otel-export", &instance])
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://127.0.0.1:{port}"),
        )
        .env("OTEL_SERVICE_NAME", "whip-test")
        .output()
        .expect("otel-export runs");
    assert!(
        export.status.success(),
        "otel-export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );

    let body = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("collector received the OTLP POST");
    collector.join().ok();
    let received: Value = serde_json::from_str(&body).expect("collector body is OTLP JSON");
    assert!(
        received
            .pointer("/resourceSpans/0/scopeSpans/0/spans")
            .and_then(Value::as_array)
            .is_some_and(|spans| !spans.is_empty()),
        "expected exported spans in the OTLP payload: {body}"
    );

    // `telemetry status` reflects the emit-once cursor.
    let status = run_json(
        bin,
        &["--store", &store_str, "--json", "telemetry", "status"],
    );
    assert!(
        status
            .pointer("/instances/0/exported_runs")
            .and_then(Value::as_u64)
            .is_some_and(|count| count >= 1),
        "status should show exported runs: {status}"
    );

    // `telemetry reset-cursor` clears it; a follow-up status shows nothing.
    let reset = run_json(
        bin,
        &["--store", &store_str, "--json", "telemetry", "reset-cursor"],
    );
    assert_eq!(
        reset.get("cleared").and_then(Value::as_bool),
        Some(true),
        "{reset}"
    );
    let status_after = run_json(
        bin,
        &["--store", &store_str, "--json", "telemetry", "status"],
    );
    assert!(
        status_after
            .pointer("/instances")
            .and_then(Value::as_array)
            .is_some_and(|instances| instances.is_empty()),
        "cursor should be cleared after reset: {status_after}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// Stand up an exportable instance (one terminal lease run) and return its
/// store path + instance id, for the Q2 env-surface tests below.
fn otel_export_fixture(bin: &str, label: &str) -> (PathBuf, PathBuf, PathBuf, String) {
    let store = temp_path(label, "sqlite");
    let source = temp_path(label, "whip");
    let coordination = temp_path(&format!("{label}-coord"), "sqlite");
    fs::write(&source, LEASE_SOURCE).expect("write source");
    let dev = dev_with_coordination(
        bin,
        store.to_str().expect("utf-8"),
        source.to_str().expect("utf-8"),
        coordination.to_str().expect("utf-8"),
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();
    (store, source, coordination, instance)
}

/// A one-shot in-process collector that captures the full raw request (request
/// line + headers + body) and replies 200. Returns (port, receiver, handle).
#[allow(clippy::type_complexity)]
fn spawn_otel_collector() -> (
    u16,
    std::sync::mpsc::Receiver<String>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind collector");
    let port = listener.local_addr().expect("addr").port();
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..read]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
                    let content_length = headers
                        .to_lowercase()
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length:"))
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = pos + 4;
                    while buf.len() < body_start + content_length {
                        let read = stream.read(&mut chunk).unwrap_or(0);
                        if read == 0 {
                            break;
                        }
                        buf.extend_from_slice(&chunk[..read]);
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                    let _ = tx.send(String::from_utf8_lossy(&buf).to_string());
                    break;
                }
            }
        }
    });
    (port, rx, handle)
}

/// Q2: `OTEL_EXPORTER_OTLP_PROTOCOL` validates before any socket — only the
/// shipped `http/json` encoding is accepted; anything else is a config error.
#[test]
fn otel_export_rejects_unsupported_protocol() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, coordination, instance) = otel_export_fixture(bin, "otel-proto");
    let store_str = store.to_str().expect("utf-8");

    // `--dry-run` runs the same config validation, so no endpoint is needed.
    let out = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
        .output()
        .expect("otel-export runs");
    assert!(
        !out.status.success(),
        "unsupported protocol must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("OTEL_EXPORTER_OTLP_PROTOCOL") && stderr.contains("http/json"),
        "expected a protocol config error: {stderr}"
    );

    // The shipped protocol is accepted.
    let ok = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env("OTEL_EXPORTER_OTLP_PROTOCOL", "http/json")
        .output()
        .expect("otel-export runs");
    assert!(ok.status.success(), "http/json must be accepted");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// Q2: auth headers over a plaintext, non-loopback endpoint are refused (the
/// cleartext-credential hazard) unless the operator sets the documented opt-in;
/// header values never leak into the dry-run output either way.
#[test]
fn otel_export_refuses_headers_over_plaintext_without_optin() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, coordination, instance) = otel_export_fixture(bin, "otel-plain");
    let store_str = store.to_str().expect("utf-8");
    let secret = "Bearer super-secret-token";

    let refused = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://collector.example.com:4318",
        )
        .env(
            "OTEL_EXPORTER_OTLP_HEADERS",
            format!("authorization={secret}"),
        )
        .output()
        .expect("otel-export runs");
    assert!(
        !refused.status.success(),
        "headers over plaintext non-loopback must be refused"
    );
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("refusing"), "expected a refusal: {stderr}");
    assert!(
        !stderr.contains("super-secret-token"),
        "the header value must never be printed: {stderr}"
    );

    // The documented opt-in re-enables plaintext headers; dry-run then succeeds
    // and still never prints the secret value.
    let allowed = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "http://collector.example.com:4318",
        )
        .env(
            "OTEL_EXPORTER_OTLP_HEADERS",
            format!("authorization={secret}"),
        )
        .env("WHIPPLESCRIPT_OTEL_ALLOW_INSECURE_HEADERS", "1")
        .output()
        .expect("otel-export runs");
    assert!(
        allowed.status.success(),
        "opt-in must permit plaintext headers: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&allowed.stdout),
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(
        !combined.contains("super-secret-token"),
        "the header value must never appear in dry-run output: {combined}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// Q2: `OTEL_RESOURCE_ATTRIBUTES` are parsed (percent-decoded) and merged onto
/// the OTLP resource alongside `service.name`.
#[test]
fn otel_export_merges_resource_attributes() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, coordination, instance) = otel_export_fixture(bin, "otel-res");
    let store_str = store.to_str().expect("utf-8");

    let out = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env("OTEL_SERVICE_NAME", "checkout")
        .env(
            "OTEL_RESOURCE_ATTRIBUTES",
            "deployment.environment=prod,service.version=1.2.3,note=hello%20world",
        )
        .output()
        .expect("otel-export runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let payload: Value =
        serde_json::from_str(&stdout[stdout.find('{').expect("json")..]).expect("payload json");
    let attributes = payload
        .pointer("/resourceSpans/0/resource/attributes")
        .and_then(Value::as_array)
        .expect("resource attributes");
    let attr = |key: &str| -> Option<String> {
        attributes.iter().find_map(|entry| {
            (entry.get("key").and_then(Value::as_str) == Some(key)).then(|| {
                entry
                    .pointer("/value/stringValue")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            })
        })
    };
    assert_eq!(attr("service.name").as_deref(), Some("checkout"));
    assert_eq!(attr("deployment.environment").as_deref(), Some("prod"));
    assert_eq!(attr("service.version").as_deref(), Some("1.2.3"));
    // Percent-decoding of the OTel value.
    assert_eq!(attr("note").as_deref(), Some("hello world"));

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// Q2: `OTEL_EXPORTER_OTLP_HEADERS` are parsed, percent-decoded, and attached to
/// the POST (verified over a loopback endpoint, where plaintext headers are
/// allowed without the opt-in).
#[test]
fn otel_export_attaches_parsed_headers_to_post() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, coordination, instance) = otel_export_fixture(bin, "otel-hdr");
    let store_str = store.to_str().expect("utf-8");
    let (port, rx, collector) = spawn_otel_collector();

    let export = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance])
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://127.0.0.1:{port}"),
        )
        .env(
            "OTEL_EXPORTER_OTLP_HEADERS",
            "authorization=Bearer%20xyz,x-tenant=acme",
        )
        .output()
        .expect("otel-export runs");
    assert!(
        export.status.success(),
        "otel-export failed: {}",
        String::from_utf8_lossy(&export.stderr)
    );
    let raw = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("collector received the POST");
    collector.join().ok();
    let lower = raw.to_lowercase();
    assert!(
        lower.contains("authorization: bearer xyz"),
        "percent-decoded auth header must ride the POST: {raw}"
    );
    assert!(
        lower.contains("x-tenant: acme"),
        "second header must ride the POST: {raw}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// Q2 cursor scoping: changing the endpoint re-keys the cursor, so the new scope
/// re-exports the full history exactly once without disturbing the old scope.
#[test]
fn otel_export_rekeys_cursor_per_endpoint() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, coordination, instance) = otel_export_fixture(bin, "otel-scope");
    let store_str = store.to_str().expect("utf-8");

    // First endpoint exports the history.
    let (port_a, rx_a, collector_a) = spawn_otel_collector();
    let export_a = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance])
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://127.0.0.1:{port_a}"),
        )
        .output()
        .expect("otel-export runs");
    assert!(
        export_a.status.success(),
        "{}",
        String::from_utf8_lossy(&export_a.stderr)
    );
    let body_a = rx_a
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("collector A received the POST");
    collector_a.join().ok();
    assert!(body_a.contains("resourceSpans"), "A got spans");

    // A second endpoint is a new scope: full history re-exports exactly once.
    let (port_b, rx_b, collector_b) = spawn_otel_collector();
    let export_b = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance])
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://127.0.0.1:{port_b}"),
        )
        .output()
        .expect("otel-export runs");
    assert!(
        export_b.status.success(),
        "{}",
        String::from_utf8_lossy(&export_b.stderr)
    );
    let body_b = rx_b
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("collector B re-exports under the new scope");
    collector_b.join().ok();
    assert!(
        body_b.contains("resourceSpans"),
        "B got spans under its own scope"
    );

    // Status now lists two scopes.
    let status = run_json(
        bin,
        &["--store", store_str, "--json", "telemetry", "status"],
    );
    let scopes = status
        .pointer("/scopes")
        .and_then(Value::as_array)
        .expect("scopes");
    assert_eq!(scopes.len(), 2, "two endpoints => two scopes: {status}");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(coordination);
}

/// A workflow with a schema-typed effect run: the coerce output (`Verdict`)
/// is the effect-run output content the T4 allowlist can declassify.
const COERCE_OTEL_SOURCE: &str = r#"
workflow CoerceOtel

output result Done
failure error Failed

class Done {
  note string
}

class Failed {
  reason string
}

class Verdict {
  label string
  score float
}

coerce judge(text string) -> Verdict {
  prompt """markdown
  Judge this text: {{ text }}

  {{ ctx.output_format }}
  """
}

rule seed
  when started
=> {
  coerce judge("hello world") as v

  after v succeeds {
    complete result {
      note v.label
    }
  }
  after v fails {
    fail error {
      reason "could not judge"
    }
  }
}
"#;

/// Stand up an instance with one completed schema-typed (coerce) run, for the
/// T4 content-allowlist tests below.
fn otel_allowlist_fixture(bin: &str, label: &str) -> (PathBuf, PathBuf, String) {
    let store = temp_path(label, "sqlite");
    let source = temp_path(label, "whip");
    fs::write(&source, COERCE_OTEL_SOURCE).expect("write source");
    let dev = dev_until_idle(
        bin,
        store.to_str().expect("utf-8"),
        source.to_str().expect("utf-8"),
        &[],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();
    (store, source, instance)
}

/// Run `otel-export --dry-run` and parse the printed OTLP payload.
fn otel_dry_run_payload(output: &std::process::Output) -> Value {
    assert!(
        output.status.success(),
        "otel-export --dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout[stdout.find('{').expect("payload json")..])
        .expect("payload parses")
}

/// Collect every `whipplescript.field.*` attribute key/value across the
/// payload's spans.
fn otel_field_attributes(payload: &Value) -> Vec<(String, String)> {
    payload
        .pointer("/resourceSpans/0/scopeSpans/0/spans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|span| span.get("attributes").and_then(Value::as_array))
        .flatten()
        .filter_map(|attr| {
            let key = attr.get("key").and_then(Value::as_str)?;
            key.starts_with("whipplescript.field.").then(|| {
                (
                    key.to_owned(),
                    attr.pointer("/value/stringValue")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                )
            })
        })
        .collect()
}

/// T4: an allowlisted `<Schema>.<field>` exports as span attribute
/// `whipplescript.field.<Schema>.<field>` on the producing run's span; the
/// env carrier works too, and the flag wins over the env.
#[test]
fn otel_export_allowlisted_field_exports_as_attribute() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, instance) = otel_allowlist_fixture(bin, "otel-allow");
    let store_str = store.to_str().expect("utf-8");

    let flagged = Command::new(bin)
        .args([
            "--store",
            store_str,
            "otel-export",
            &instance,
            "--dry-run",
            "--telemetry-allowlist",
            "Verdict.label",
        ])
        .env_remove("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST")
        .output()
        .expect("otel-export runs");
    let fields = otel_field_attributes(&otel_dry_run_payload(&flagged));
    assert_eq!(
        fields.len(),
        1,
        "exactly the allowlisted field exports: {fields:?}"
    );
    assert_eq!(fields[0].0, "whipplescript.field.Verdict.label");
    assert!(
        !fields[0].1.is_empty(),
        "the coerce output value rides the attribute"
    );

    // The env variable is the second carrier.
    let from_env = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST", "Verdict.score")
        .output()
        .expect("otel-export runs");
    let fields = otel_field_attributes(&otel_dry_run_payload(&from_env));
    assert_eq!(fields.len(), 1, "{fields:?}");
    assert_eq!(fields[0].0, "whipplescript.field.Verdict.score");

    // The flag wins over the env.
    let both = Command::new(bin)
        .args([
            "--store",
            store_str,
            "otel-export",
            &instance,
            "--dry-run",
            "--telemetry-allowlist",
            "Verdict.score",
        ])
        .env("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST", "Verdict.label")
        .output()
        .expect("otel-export runs");
    let fields = otel_field_attributes(&otel_dry_run_payload(&both));
    assert_eq!(fields.len(), 1, "flag replaces env entirely: {fields:?}");
    assert_eq!(fields[0].0, "whipplescript.field.Verdict.score");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// T4: a field that is NOT on the allowlist never exports, and with no
/// allowlist at all no content attribute exists anywhere in the payload.
#[test]
fn otel_export_non_allowlisted_field_never_exports() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, instance) = otel_allowlist_fixture(bin, "otel-deny");
    let store_str = store.to_str().expect("utf-8");

    let partial = Command::new(bin)
        .args([
            "--store",
            store_str,
            "otel-export",
            &instance,
            "--dry-run",
            "--telemetry-allowlist",
            "Verdict.label",
        ])
        .env_remove("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST")
        .output()
        .expect("otel-export runs");
    let keys = otel_field_attributes(&otel_dry_run_payload(&partial))
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    assert!(
        !keys.iter().any(|key| key.contains("score")),
        "non-allowlisted `Verdict.score` must never export: {keys:?}"
    );
    assert_eq!(keys, ["whipplescript.field.Verdict.label"]);

    let structural = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env_remove("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST")
        .output()
        .expect("otel-export runs");
    let stdout = String::from_utf8_lossy(&structural.stdout);
    assert!(
        !stdout.contains("whipplescript.field."),
        "no allowlist => no content attributes at all"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// T4: an unknown schema/field or a malformed entry is a config error (exit 2,
/// no payload), and an allowlist whose program schemas are unreachable is
/// refused (fail closed).
#[test]
fn otel_export_rejects_bad_allowlist_entries() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, instance) = otel_allowlist_fixture(bin, "otel-badlist");
    let store_str = store.to_str().expect("utf-8");

    let cases: [(&str, &str, &str); 4] = [
        ("Nope.field", &instance, "does not name a declared schema"),
        ("Verdict.nope", &instance, "does not name a declared schema"),
        ("Verdictlabel", &instance, "malformed"),
        // Valid shape, but no reachable program/schema info: fail closed.
        ("Verdict.label", "no-such-instance", "refused"),
    ];
    for (entry, target, expected) in cases {
        let out = Command::new(bin)
            .args([
                "--store",
                store_str,
                "otel-export",
                target,
                "--dry-run",
                "--telemetry-allowlist",
                entry,
            ])
            .env_remove("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST")
            .output()
            .expect("otel-export runs");
        assert_eq!(
            out.status.code(),
            Some(2),
            "`{entry}` against `{target}` must be a config error"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(expected),
            "`{entry}`: expected `{expected}` in: {stderr}"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.contains("resourceSpans"),
            "a config error must abort before emitting any payload: {stdout}"
        );
    }

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// T4: with no allowlist the export is byte-identical to the structural
/// export — an allowlisted run differs ONLY by the added content attributes.
#[test]
fn otel_export_no_allowlist_is_byte_identical_structural() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let (store, source, instance) = otel_allowlist_fixture(bin, "otel-ident");
    let store_str = store.to_str().expect("utf-8");

    let structural = Command::new(bin)
        .args(["--store", store_str, "otel-export", &instance, "--dry-run"])
        .env_remove("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST")
        .output()
        .expect("otel-export runs");
    let structural_payload = otel_dry_run_payload(&structural);

    let allowlisted = Command::new(bin)
        .args([
            "--store",
            store_str,
            "otel-export",
            &instance,
            "--dry-run",
            "--telemetry-allowlist",
            "Verdict.label,Verdict.score",
        ])
        .env_remove("WHIPPLESCRIPT_TELEMETRY_ALLOWLIST")
        .output()
        .expect("otel-export runs");
    let mut stripped = otel_dry_run_payload(&allowlisted);
    assert_eq!(
        otel_field_attributes(&stripped).len(),
        2,
        "the allowlisted run carries both content attributes before stripping"
    );

    // Dropping the content attributes from the allowlisted payload must give
    // back the structural payload byte-for-byte.
    if let Some(spans) = stripped
        .pointer_mut("/resourceSpans/0/scopeSpans/0/spans")
        .and_then(Value::as_array_mut)
    {
        for span in spans {
            if let Some(attributes) = span.get_mut("attributes").and_then(Value::as_array_mut) {
                attributes.retain(|attr| {
                    !attr
                        .get("key")
                        .and_then(Value::as_str)
                        .is_some_and(|key| key.starts_with("whipplescript.field."))
                });
            }
        }
    }
    assert_eq!(
        structural_payload.to_string(),
        stripped.to_string(),
        "no-allowlist spans must be byte-identical to the structural export"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

const EVENT_SOURCE: &str = r#"
workflow EventDemo

output result Done

class Done {
  note string
}

signal deploy.finished {
  service string
  status string
}

rule on_deploy
  when deploy.finished as d
=> {
  complete result {
    note "deploy of {{ d.service }}: {{ d.status }}"
  }
}
"#;

/// `whip signal` validates the payload against the declared `signal` schema,
/// lands a typed durable fact, and the bare `when <signal> as d` reaction
/// fires — no `@external` tag needed.
#[test]
fn signal_lands_typed_fact_and_rule_fires() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("signal", "sqlite");
    let source = temp_path("signal", "whip");
    fs::write(&source, EVENT_SOURCE).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source_str, &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();
    assert_eq!(instance_status(bin, store_str, &instance), "running");

    let signaled = run_json(
        bin,
        &[
            "--store",
            store_str,
            "--json",
            "signal",
            &instance,
            "--name",
            "deploy.finished",
            "--data",
            r#"{"service":"api","status":"ok"}"#,
            "--program",
            source_str,
        ],
    );
    assert_eq!(
        signaled.get("signal").and_then(Value::as_str),
        Some("deploy.finished")
    );
    run_text(
        bin,
        &[
            "--store",
            store_str,
            "step",
            &instance,
            "--program",
            source_str,
        ],
    );
    assert_eq!(instance_status(bin, store_str, &instance), "completed");

    let status = run_json(bin, &["--store", store_str, "--json", "status", &instance]);
    assert_eq!(
        status
            .pointer("/workflow_terminal/payload/note")
            .and_then(Value::as_str),
        Some("deploy of api: ok")
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// No laundering (H8 stage b): under a governed envelope that marks the signal an
/// INTERNAL channel, an external `whip signal` injection is refused — an internal
/// signal carries its emitter's integrity and may not be sourced from outside.
/// Ungoverned (no envelope) still delivers (the gradual model).
#[test]
fn whip_signal_refuses_external_injection_of_an_internal_signal() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let source = temp_path("signal-internal", "whip");
    let policy = temp_path("signal-internal", "policy");
    fs::write(&source, EVENT_SOURCE).expect("write source");
    fs::write(
        &policy,
        "grant signal deploy.finished -> signal:deploy.finished internal\n",
    )
    .expect("write policy");
    let source_str = source.to_str().expect("utf-8");

    // Governed + internal: the external injection is refused.
    let refused = Command::new(bin)
        .args([
            "signal",
            "inst-x",
            "--name",
            "deploy.finished",
            "--data",
            r#"{"service":"api","status":"ok"}"#,
            "--program",
            source_str,
        ])
        .env(
            "WHIPPLESCRIPT_IFC_ENVELOPE",
            policy.to_str().expect("utf-8"),
        )
        .output()
        .expect("command runs");
    assert!(
        !refused.status.success(),
        "external injection of an internal signal must be refused"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("INTERNAL channel"),
        "stderr: {}",
        String::from_utf8_lossy(&refused.stderr)
    );

    // Ungoverned (no envelope): the same delivery is NOT refused for being internal.
    let dev = Command::new(bin)
        .args([
            "signal",
            "inst-x",
            "--name",
            "deploy.finished",
            "--data",
            r#"{"service":"api","status":"ok"}"#,
            "--program",
            source_str,
        ])
        .output()
        .expect("command runs");
    assert!(
        !String::from_utf8_lossy(&dev.stderr).contains("INTERNAL channel"),
        "dev mode must not refuse for internal: {}",
        String::from_utf8_lossy(&dev.stderr)
    );

    let _ = fs::remove_file(source);
    let _ = fs::remove_file(policy);
}

/// A malformed payload or undeclared signal is rejected at the CLI boundary;
/// no ill-typed fact can land.
#[test]
fn signal_rejects_bad_payload_and_unknown_signal() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("signal-reject", "sqlite");
    let source = temp_path("signal-reject", "whip");
    fs::write(&source, EVENT_SOURCE).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source_str, &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();

    for (label, signal, data, expected) in [
        (
            "bad-payload",
            "deploy.finished",
            r#"{"service":"api","bogus":1}"#,
            "does not conform to signal",
        ),
        ("unknown-signal", "deploy.nope", "{}", "is not declared"),
    ] {
        let output = Command::new(bin)
            .args([
                "--store",
                store_str,
                "signal",
                &instance,
                "--name",
                signal,
                "--data",
                data,
                "--program",
                source_str,
            ])
            .output()
            .expect("command runs");
        assert!(!output.status.success(), "{label} should be rejected");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
    }
    assert_eq!(instance_status(bin, store_str, &instance), "running");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// I5 (spec/std-ingress.md): `whip signal --delivery-id` — the operator's
/// delivery id WINS over the derived payload hash, and the same id twice
/// admits once ACROSS PROCESS RUNS: the second invocation is a fresh process
/// against the same store, and the duplicate is absorbed with an observable
/// diagnostic instead of a second fact (or a store conflict).
#[test]
fn signal_delivery_id_admits_once_across_process_runs() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("signal-delivery", "sqlite");
    let source = temp_path("signal-delivery", "whip");
    fs::write(&source, EVENT_SOURCE).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source_str, &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();

    let deliver = |payload: &str| -> Value {
        run_json(
            bin,
            &[
                "--store",
                store_str,
                "--json",
                "signal",
                &instance,
                "--name",
                "deploy.finished",
                "--data",
                payload,
                "--program",
                source_str,
                "--delivery-id",
                "provider-evt-42",
            ],
        )
    };

    let first = deliver(r#"{"service":"api","status":"ok"}"#);
    assert!(first.get("event_id").and_then(Value::as_str).is_some());
    assert_eq!(first.get("duplicate"), None, "{first}");

    // Same delivery id, DIFFERENT payload bytes: the delivery id wins over the
    // derived payload hash, so this is the same delivery — absorbed once.
    let second = deliver(r#"{"service":"api","status":"retried"}"#);
    assert_eq!(second.get("duplicate").and_then(Value::as_bool), Some(true));
    assert_eq!(
        second.get("event_id").and_then(Value::as_str),
        first.get("event_id").and_then(Value::as_str),
        "the duplicate names the original admission: {second}"
    );

    // Exactly one durable signal fact landed.
    let facts = run_json(bin, &["--store", store_str, "--json", "facts", &instance]);
    let admitted = facts
        .as_array()
        .expect("facts array")
        .iter()
        .filter(|fact| fact.get("name").and_then(Value::as_str) == Some("deploy.finished"))
        .count();
    assert_eq!(admitted, 1, "same delivery id twice admits once: {facts}");

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

const FAMILY_B_SIGNAL_SOURCE: &str = r#"
workflow FamilyBSignal

output result Done

class Done {
  note string
}

signal deploy.finished {
  kind "deploy" | "rollback"
  region string when kind is "deploy"
}

rule on_deploy
  when deploy.finished as d
=> {
  complete result {
    note "{{ d.kind }}"
  }
}
"#;

/// Family B conditional required-presence at admission
/// (discriminated-families-design.md §5.7): a `when <disc> is "<lit>"` field is
/// required only when the discriminant equals the literal; an inapplicable present
/// sibling is accepted (the all-keys-present webhook shape — positive presence only).
#[test]
fn signal_enforces_conditional_field_presence() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("signal-familyb", "sqlite");
    let source = temp_path("signal-familyb", "whip");
    fs::write(&source, FAMILY_B_SIGNAL_SOURCE).expect("write source");

    let store_str = store.to_str().expect("utf-8");
    let source_str = source.to_str().expect("utf-8");
    let dev = dev_until_idle(bin, store_str, source_str, &[]);
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id")
        .to_owned();

    // Applicable but missing: kind == "deploy" requires `region`; rejected at the
    // boundary so no ill-typed fact lands and the instance keeps running.
    let rejected = Command::new(bin)
        .args([
            "--store",
            store_str,
            "signal",
            &instance,
            "--name",
            "deploy.finished",
            "--data",
            r#"{"kind":"deploy"}"#,
            "--program",
            source_str,
        ])
        .output()
        .expect("command runs");
    assert!(
        !rejected.status.success(),
        "kind==deploy with no region must be rejected"
    );
    assert_eq!(instance_status(bin, store_str, &instance), "running");

    // Inapplicable present: kind == "rollback", so `region` (a deploy-only field) is
    // neither required nor rejected when present — accepted.
    let accepted = run_json(
        bin,
        &[
            "--store",
            store_str,
            "--json",
            "signal",
            &instance,
            "--name",
            "deploy.finished",
            "--data",
            r#"{"kind":"rollback","region":"x"}"#,
            "--program",
            source_str,
        ],
    );
    assert_eq!(
        accepted.get("signal").and_then(Value::as_str),
        Some("deploy.finished")
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(source);
}

/// Signal reactions are statically checked: the bare `when` form requires a
/// declared signal, and field access on the binding is typed against the
/// signal schema.
#[test]
fn signal_static_checks() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, source_text, expected) in [
        (
            "undeclared-signal",
            EVENT_SOURCE.replace("when deploy.finished as d", "when deploy.unknown as d"),
            "reacts to undeclared signal `deploy.unknown`",
        ),
        (
            "bad-event-field",
            EVENT_SOURCE.replace("{{ d.status }}", "{{ d.bogus }}"),
            "schema `deploy.finished` has no field `bogus`",
        ),
    ] {
        let source = temp_path(label, "whip");
        fs::write(&source, source_text).expect("write source");
        let output = Command::new(bin)
            .args(["check", source.to_str().expect("utf-8")])
            .output()
            .expect("command runs");
        assert!(!output.status.success(), "{label} should fail check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
        let _ = fs::remove_file(source);
    }
}

const SUM_TYPE_TABLE: &str = r#"
workflow SumTable

output result Done
failure error Failed

class Done {
  note string
}

class Failed {
  reason string
}

enum ReviewOutcome {
  Approved {
    score float
  }
  Rejected {
    reason string
  }
  Blocked
}

class Review {
  id string
  outcome ReviewOutcome
}

table reviews as Review [
  { id "R-1" outcome SEED }
]

rule judge
  when Review as r
=> {
  case r.outcome {
    Approved as a => {
      complete result {
        note "approved with {{ a.score }}"
      }
    }
    Rejected as rej => {
      fail error {
        reason rej.reason
      }
    }
    Blocked => {
      fail error {
        reason "blocked"
      }
    }
  }
}
"#;

/// A data-carrying variant constructed in a table row lands as an
/// internally-tagged record; `case` dispatches on the synthesized `variant`
/// discriminant and `as` binds the payload.
#[test]
fn sum_type_case_dispatches_and_binds_payload() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, seed, expected_status, expected_payload) in [
        (
            "approved",
            "Approved { score 0.9 }",
            "completed",
            r#""note":"approved with 0.9""#,
        ),
        (
            "rejected",
            r#"Rejected { reason "too vague" }"#,
            "failed",
            r#""reason":"too vague""#,
        ),
        ("bare", "Blocked", "failed", r#""reason":"blocked""#),
    ] {
        let store = temp_path(&format!("sum-{label}"), "sqlite");
        let source = temp_path(&format!("sum-{label}"), "whip");
        fs::write(&source, SUM_TYPE_TABLE.replace("SEED", seed)).expect("write source");

        let store_str = store.to_str().expect("utf-8");
        let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), &[]);
        let instance = dev
            .get("instance_id")
            .and_then(Value::as_str)
            .expect("instance id");
        assert_eq!(
            instance_status(bin, store_str, instance),
            expected_status,
            "{label}"
        );
        let status = run_json(bin, &["--store", store_str, "--json", "status", instance]);
        let payload = status
            .pointer("/workflow_terminal/payload")
            .map(Value::to_string)
            .unwrap_or_default();
        assert!(payload.contains(expected_payload), "{label}: {payload}");

        let _ = fs::remove_file(store);
        let _ = fs::remove_file(source);
    }
}

const SUM_TYPE_COERCE: &str = r#"
workflow SumCoerce

output result Done
failure error Failed

class Done {
  note string
}

class Failed {
  reason string
}

enum ReviewOutcome {
  Approved {
    score float
  }
  Rejected {
    reason string
  }
}

class Draft {
  body string
}

coerce reviewDraft(draft string) -> ReviewOutcome {
  prompt """
  Review this draft: {{ draft }}
  """
}

rule seed
  when started
=> {
  record Draft {
    body "the draft"
  }
}

rule review
  when Draft as d
=> {
  coerce reviewDraft(d.body) as outcome

  after outcome succeeds as o {
    case o {
      Approved as a => {
        complete result {
          note "score {{ a.score }}"
        }
      }
      Rejected as rej => {
        fail error {
          reason rej.reason
        }
      }
    }
  }
}
"#;

/// A fixture coerce over a sum type returns the first declared variant as a
/// tagged record by default; `--variant` selects another arm to exercise its
/// case branch without a real provider.
#[test]
fn sum_type_coerce_fixture_selects_variants() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (extra, expected_status) in [
        (None, "completed"),
        (Some(["--variant", "Rejected"]), "failed"),
    ] {
        let store = temp_path("sum-coerce", "sqlite");
        let source = temp_path("sum-coerce", "whip");
        fs::write(&source, SUM_TYPE_COERCE).expect("write source");

        let store_str = store.to_str().expect("utf-8");
        let extra_args = extra.as_ref().map(|args| &args[..]).unwrap_or(&[]);
        let dev = dev_until_idle(bin, store_str, source.to_str().expect("utf-8"), extra_args);
        let instance = dev
            .get("instance_id")
            .and_then(Value::as_str)
            .expect("instance id");
        assert_eq!(
            instance_status(bin, store_str, instance),
            expected_status,
            "extra={extra:?}"
        );

        let _ = fs::remove_file(store);
        let _ = fs::remove_file(source);
    }
}

/// Sum-type declarations and case blocks are statically checked: the
/// discriminant name is reserved, bare variants take no binding, and case
/// stays exhaustive over the variant set.
#[test]
fn sum_type_static_checks() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, source_text, expected) in [
        (
            "reserved-variant-field",
            SUM_TYPE_TABLE
                .replace("SEED", "Blocked")
                .replace("score float", "variant string"),
            "declares reserved field `variant`",
        ),
        (
            "binding-on-bare-variant",
            SUM_TYPE_TABLE
                .replace("SEED", "Blocked")
                .replace("Blocked => {", "Blocked as b => {"),
            "carries no payload to bind",
        ),
        (
            "non-exhaustive",
            SUM_TYPE_TABLE.replace("SEED", "Blocked").replace(
                "    Blocked => {\n      fail error {\n        reason \"blocked\"\n      }\n    }\n",
                "",
            ),
            "non-exhaustive case; missing Blocked",
        ),
    ] {
        let source = temp_path(label, "whip");
        fs::write(&source, source_text).expect("write source");
        let output = Command::new(bin)
            .args(["check", source.to_str().expect("utf-8")])
            .output()
            .expect("command runs");
        assert!(!output.status.success(), "{label} should fail check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
        let _ = fs::remove_file(source);
    }
}

/// `timer until` operands are statically checked: literals must be ISO-8601
/// instants and paths must resolve to `time`-typed fields.
#[test]
fn timer_until_static_checks_reject_bad_operands() {
    let bin = env!("CARGO_BIN_EXE_whip");
    for (label, deadline, operand, expected) in [
        (
            "bad-literal",
            "2020-01-01T00:00:00Z",
            "\"next tuesday\"",
            "invalid time literal `next tuesday`",
        ),
        (
            "non-time-path",
            "2020-01-01T00:00:00Z",
            "j.id",
            "non-time operand `j.id` in `timer until`",
        ),
        (
            "unknown-binding",
            "2020-01-01T00:00:00Z",
            "ghost.fireAt",
            "unknown binding `ghost` in `timer until ghost.fireAt`",
        ),
    ] {
        let source = temp_path(label, "whip");
        fs::write(&source, timer_until_source(deadline, operand)).expect("write source");
        let output = Command::new(bin)
            .args(["check", source.to_str().expect("utf-8")])
            .output()
            .expect("command runs");
        assert!(!output.status.success(), "{label} should fail check");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{label}: {stderr}");
        let _ = fs::remove_file(source);
    }
}

/// DR-0025 cross-package `@tool`: an owned-harness agent granted a workflow tool
/// exported by a `use`d package resolves it from the package attestation, drives
/// the package's shipped source synchronously, and the parent turn completes. The
/// example program/lock/package are the committed fixtures. The parent's
/// `after turn succeeds` only fires if the granted tool resolved and the turn
/// succeeded, so a completed parent proves the cross-package grant ran end to end.
#[test]
fn cross_package_tool_grant_resolves_and_runs() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let examples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let consumer = examples.join("subworkflow-tool-consumer.whip");
    let lock = examples.join("subworkflow-tool-consumer.lock.json");
    let store = temp_path("xpkg-tool", "sqlite");
    let workspace = temp_path("xpkg-tool-ws", "dir");
    let coordination = temp_path("xpkg-tool-coord", "sqlite");
    fs::create_dir_all(&workspace).expect("workspace dir");

    let output = Command::new(bin)
        .args([
            "--store",
            store.to_str().expect("utf-8"),
            "--json",
            "run",
            consumer.to_str().expect("utf-8"),
            "--package-lock",
            lock.to_str().expect("utf-8"),
            "--root",
            "ConsumerFlow",
            "--provider",
            "owned",
            "--input",
            r#"{"request":{"task":"echo it"}}"#,
            "--until",
            "idle",
        ])
        .env(
            "WHIPPLESCRIPT_OWNED_FIXTURE_TOOL",
            r#"EchoText:{"request":{"text":"cross-package regression"}}"#,
        )
        .env("WHIPPLESCRIPT_HARNESS_WORKSPACE", &workspace)
        .env("WHIPPLESCRIPT_COORDINATION_STORE", &coordination)
        .output()
        .expect("command runs");
    assert!(
        output.status.success(),
        "dev failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8");
    let json_start = stdout.find(['{', '[']).expect("json output");
    let dev: Value = serde_json::from_str(&stdout[json_start..]).expect("valid json");
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    let store_str = store.to_str().expect("utf-8");
    assert_eq!(
        instance_status(bin, store_str, instance),
        "completed",
        "consumer flow did not complete: {dev}"
    );
    // The brokered turn requested and received a result for the granted package
    // tool — the cross-package invoke path actually ran, not just type-checked.
    let evidence_kinds = dev
        .pointer("/provider_evidence/groups")
        .and_then(Value::as_array)
        .map(|groups| {
            groups
                .iter()
                .filter_map(|group| group.get("kind").and_then(Value::as_str))
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    assert!(
        evidence_kinds
            .iter()
            .any(|kind| kind == "agent.turn.brokered.tool_result"),
        "expected a brokered tool result from the package tool: {evidence_kinds:?}"
    );

    let _ = fs::remove_file(store);
    let _ = fs::remove_file(coordination);
    let _ = fs::remove_dir_all(workspace);
}

const IFC_BAD_WHIP: &str = r#"use std.files

@service
workflow IfcCheck

output result R
class R { ok bool }
class Ticket { id string  status "open" }

agent coder { provider fixture  profile "repo-writer"  capacity 1 }

file store ledger { root "./ledger"  allow read ["**"] }
file store outbox { root "./outbox"  allow write ["**"] }

table seed as Ticket [ { id "T1"  status "open" } ]

rule work
  when Ticket as ticket where ticket.status == "open"
  when coder is available
=> {
  tell coder as turn
    with access to ledger {
      read ["**"]
    }
    with access to outbox {
      write ["**"]
    }
  "go"

  after turn succeeds as outcome {
    complete result { ok true }
  }
}
"#;

const IFC_ENVELOPE: &str = r#"{ "resources": {
  "ledger": { "confidential": true },
  "outbox": { "confidential": false }
} }"#;

const XPKG_TOOL: &str = r#"use std.files

@tool
workflow LeakyTool
output result R
class R { ok bool }
input request Q
class Q { path string }
file store secretz { root "./s"  allow read ["**"] }
rule go
  when started
=> {
  read text from secretz at "x" as loaded
  after loaded succeeds as f { complete result { ok true } }
}
"#;

const XPKG_MANIFEST: &str = r#"{
  "schema": "whipplescript.package_manifest.v0",
  "package_id": "package-leaky",
  "name": "leaky",
  "version": "0.1.0",
  "workflow_tools": [ { "name": "LeakyTool", "source": "leaky-tool.whip" } ]
}
"#;

const XPKG_CONSUMER: &str = r#"use leaky

workflow ConsumerFlow {
  input request ConsumerRequest
  output result ConsumerResult
  class ConsumerRequest { task string }
  class ConsumerResult { summary string }

  agent worker {
    provider fixture
    profile "p"
    capacity 1
    tools [LeakyTool]
  }

  rule dispatch
    when ConsumerRequest as request
    when worker is available
  => {
    tell worker as turn "Do: {{ request.task }}"
    after turn succeeds {
      done request
      complete result { summary turn.summary }
    }
  }
}
"#;

const IFC_CEILING_WHIP: &str = r#"use std.files

@service
workflow CeilingDemo
output result R
class R { ok bool }
class Ticket { id string  status "open" }
file store crm { root "./crm"  allow read ["**"] }
table seed as Ticket [ { id "T1"  status "open" } ]
rule review
  when Ticket as ticket where ticket.status == "open"
=> {
  read text from crm at "c.json" as rec
  after rec succeeds as r { complete result { ok true } }
}
"#;

const IFC_CEILING_POLICY: &str = "\
grant file_store crm -> file:/srv/crm.db readable by Operator from Operator\n\
party alice@acme.com : Operator\n\
party bob@acme.com : Requester\n";

/// Identity boundary (DR-0031 / D3): the agent acts-for the principal the
/// environment asserts (`WHIPPLESCRIPT_PRINCIPAL`, the launcher backend) and no
/// further — a low-clearance principal is refused a read it is not cleared for; a
/// cleared principal is allowed.
#[test]
fn ifc_principal_ceiling_caps_an_agent_to_the_users_clearance() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let whip = temp_path("ifc-prin-whip", "whip");
    let envelope = temp_path("ifc-prin-env", "policy");
    fs::write(&whip, IFC_CEILING_WHIP).expect("write whip");
    fs::write(&envelope, IFC_CEILING_POLICY).expect("write envelope");

    // a low-clearance principal (Requester) reading Operator data is refused.
    let bob = Command::new(bin)
        .args(["check", whip.to_str().expect("utf-8")])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope)
        .env("WHIPPLESCRIPT_PRINCIPAL", "bob@acme.com")
        .output()
        .expect("command runs");
    let bob_err = String::from_utf8_lossy(&bob.stderr);
    assert!(
        !bob.status.success() && bob_err.contains("denied read in rule"),
        "a Requester principal should be capped below Operator data\nstderr:\n{bob_err}"
    );

    // the cleared principal (Operator) is allowed.
    let alice = Command::new(bin)
        .args(["check", whip.to_str().expect("utf-8")])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope)
        .env("WHIPPLESCRIPT_PRINCIPAL", "alice@acme.com")
        .output()
        .expect("command runs");
    let alice_err = String::from_utf8_lossy(&alice.stderr);
    assert!(
        !alice_err.contains("denied read in rule"),
        "an Operator principal should be cleared\nstderr:\n{alice_err}"
    );

    let _ = fs::remove_file(&whip);
    let _ = fs::remove_file(&envelope);
}

/// Runtime IFC admission (E3): `whip run` refuses to RUN a whip that violates
/// information flow under a governed envelope, before any side effect — enforcement
/// at run time, not only at `whip check` time.
#[test]
fn ifc_runtime_admission_refuses_a_violating_whip() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let whip = temp_path("ifc-rt-whip", "whip");
    let envelope = temp_path("ifc-rt-env", "json");
    let store = temp_path("ifc-rt-store", "db");
    fs::write(&whip, IFC_BAD_WHIP).expect("write whip");
    fs::write(&envelope, IFC_ENVELOPE).expect("write envelope");

    let governed = Command::new(bin)
        .args([
            "--store",
            store.to_str().expect("utf-8"),
            "run",
            whip.to_str().expect("utf-8"),
            "--root",
            "IfcCheck",
        ])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope)
        .output()
        .expect("command runs");
    let stderr = String::from_utf8_lossy(&governed.stderr);
    assert!(
        !governed.status.success()
            && stderr.contains("refusing to run")
            && stderr.contains("denied flow in rule"),
        "expected runtime admission to refuse the violating whip\nstderr:\n{stderr}"
    );

    let _ = fs::remove_file(&whip);
    let _ = fs::remove_file(&envelope);
    let _ = fs::remove_file(&store);
}

/// End-to-end cross-package IFC (DR-0029, Wave 3): a consuming whip imports a
/// `@tool` whose surface opens doors (`secretz` and the package invoke membrane)
/// the consumer's governance does not cover, so `whip check` rejects the import
/// fail-closed (X1/X8/E1); governing those doors clears it.
#[test]
fn ifc_cross_package_rejects_imported_tool_with_ungoverned_surface() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let dir = std::env::temp_dir().join(format!(
        "whip-xpkg-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    fs::create_dir_all(&dir).expect("mkdir");
    let tool = dir.join("leaky-tool.whip");
    let manifest = dir.join("leaky-toolkit.json");
    let consumer = dir.join("consumer.whip");
    let lock = dir.join("lock.json");
    let envelope = dir.join("env.policy");
    fs::write(&tool, XPKG_TOOL).expect("tool");
    fs::write(&manifest, XPKG_MANIFEST).expect("manifest");
    fs::write(&consumer, XPKG_CONSUMER).expect("consumer");
    fs::write(
        &envelope,
        "grant file_store crm -> file:/srv/crm readable by Operator\n",
    )
    .expect("env");

    let lock_out = Command::new(bin)
        .args([
            "package",
            "lock",
            "--output",
            lock.to_str().expect("utf-8"),
            manifest.to_str().expect("utf-8"),
        ])
        .output()
        .expect("lock runs");
    assert!(
        lock_out.status.success(),
        "lock failed:\n{}",
        String::from_utf8_lossy(&lock_out.stderr)
    );

    // governed, but `secretz` is uncovered -> cross-package violation.
    let governed = Command::new(bin)
        .args([
            "check",
            consumer.to_str().expect("utf-8"),
            "--package-lock",
            lock.to_str().expect("utf-8"),
        ])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope)
        .output()
        .expect("check runs");
    let stderr = String::from_utf8_lossy(&governed.stderr);
    assert!(
        !governed.status.success()
            && stderr.contains("denied import of tool")
            && stderr.contains("secretz")
            && stderr.contains("invoke:package-leaky/LeakyTool"),
        "expected a cross-package violation naming secretz and the invoke door\nstderr:\n{stderr}"
    );

    // govern `secretz` but not the cross-package invoke door -> E1 still fails.
    fs::write(
        &envelope,
        "grant file_store crm -> file:/srv/crm readable by Operator\n\
         grant file_store secretz -> file:/srv/s readable by Operator\n",
    )
    .expect("env2");
    let missing_invoke = Command::new(bin)
        .args([
            "check",
            consumer.to_str().expect("utf-8"),
            "--package-lock",
            lock.to_str().expect("utf-8"),
        ])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope)
        .output()
        .expect("check runs");
    let missing_invoke_stderr = String::from_utf8_lossy(&missing_invoke.stderr);
    assert!(
        !missing_invoke.status.success()
            && missing_invoke_stderr.contains("denied import of tool")
            && missing_invoke_stderr.contains("invoke:package-leaky/LeakyTool"),
        "missing package invoke grant should still fail\nstderr:\n{missing_invoke_stderr}"
    );

    // Govern both the tool surface and the package invoke door -> the import clears.
    fs::write(
        &envelope,
        "grant file_store crm -> file:/srv/crm readable by Operator\n\
         grant file_store secretz -> file:/srv/s readable by Operator\n\
         grant invoke LeakyTool -> invoke:package-leaky/LeakyTool public\n",
    )
    .expect("env3");
    let cleared = Command::new(bin)
        .args([
            "check",
            consumer.to_str().expect("utf-8"),
            "--package-lock",
            lock.to_str().expect("utf-8"),
        ])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope)
        .output()
        .expect("check runs");
    let cleared_stderr = String::from_utf8_lossy(&cleared.stderr);
    assert!(
        !cleared_stderr.contains("cross-package"),
        "governing secretz should clear the cross-package violation\nstderr:\n{cleared_stderr}"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// End-to-end: with a governance envelope a turn that reads a confidential
/// resource and writes an un-cleared one is rejected by `whip check`; without the
/// envelope the same whip passes (the gradual / dev mode).
#[test]
fn ifc_check_rejects_confidential_to_uncleared_flow_under_envelope() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let whip = temp_path("ifc-whip", "whip");
    let envelope = temp_path("ifc-env", "json");
    fs::write(&whip, IFC_BAD_WHIP).expect("write whip");
    fs::write(&envelope, IFC_ENVELOPE).expect("write envelope");

    let governed = Command::new(bin)
        .args(["check", whip.to_str().expect("utf-8 path")])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &envelope)
        .output()
        .expect("command runs");
    let governed_stderr = String::from_utf8_lossy(&governed.stderr);
    assert!(
        !governed.status.success(),
        "expected check to fail under governance\nstderr:\n{governed_stderr}"
    );
    assert!(
        governed_stderr.contains("denied flow in rule"),
        "expected an IFC violation\nstderr:\n{governed_stderr}"
    );

    let dev = Command::new(bin)
        .args(["check", whip.to_str().expect("utf-8 path")])
        .env_remove("WHIPPLESCRIPT_IFC_ENVELOPE")
        .output()
        .expect("command runs");
    assert!(
        dev.status.success(),
        "expected dev-mode check to pass (no envelope)\nstderr:\n{}",
        String::from_utf8_lossy(&dev.stderr)
    );

    let _ = fs::remove_file(&whip);
    let _ = fs::remove_file(&envelope);
}

/// End-to-end two-agent separation (DR-0028 D5): `whip gov sign` is refused
/// without governance privilege (the whip agent) and succeeds with it (the
/// governance agent); the resulting signed envelope verifies unprivileged.
#[test]
fn ifc_two_agent_sign_requires_governance_privilege() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let config = temp_path("gov-config", "gov");
    fs::write(
        &config,
        "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n",
    )
    .expect("write config");
    let config_arg = config.to_str().expect("utf-8 path");

    // whip agent (no privilege): sign refused (G4)
    let unprivileged = Command::new(bin)
        .args(["gov", "sign", config_arg])
        .env_remove("WHIPPLESCRIPT_GOV_ADMIN")
        .output()
        .expect("command runs");
    assert!(
        !unprivileged.status.success(),
        "unprivileged sign must be refused"
    );
    assert!(
        String::from_utf8_lossy(&unprivileged.stderr).contains("privilege"),
        "stderr: {}",
        String::from_utf8_lossy(&unprivileged.stderr)
    );

    // governance agent (privileged, sudo proxy): sign succeeds
    let signed = Command::new(bin)
        .args(["gov", "sign", config_arg])
        .env("WHIPPLESCRIPT_GOV_ADMIN", "1")
        .output()
        .expect("command runs");
    assert!(
        signed.status.success(),
        "privileged sign must succeed\nstderr:\n{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let signed_json = String::from_utf8_lossy(&signed.stdout).to_string();
    assert!(signed_json.contains("attestation"), "got: {signed_json}");

    // whip agent (unprivileged) verifies the signed envelope
    let signed_file = temp_path("gov-signed", "json");
    fs::write(&signed_file, &signed_json).expect("write signed");
    let verify = Command::new(bin)
        .args(["gov", "verify", signed_file.to_str().expect("utf-8 path")])
        .env_remove("WHIPPLESCRIPT_GOV_ADMIN")
        .output()
        .expect("command runs");
    assert!(
        verify.status.success(),
        "verify must succeed\nstderr:\n{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let _ = fs::remove_file(&config);
    let _ = fs::remove_file(&signed_file);
}

/// End-to-end trust root: a SIGNED envelope drives `whip check` enforcement, and a
/// tampered signed envelope is rejected (the whip agent refuses a tampered policy).
#[test]
fn ifc_check_enforces_and_rejects_tampered_signed_envelope() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let config = temp_path("gov-cfg2", "gov");
    fs::write(
        &config,
        "grant file_store ledger -> file:/srv/ledger.db readable by Operator\n\
         grant file_store outbox -> file:/srv/outbox public\n",
    )
    .expect("write config");

    // governance agent signs
    let signed = Command::new(bin)
        .args(["gov", "sign", config.to_str().expect("utf-8 path")])
        .env("WHIPPLESCRIPT_GOV_ADMIN", "1")
        .output()
        .expect("command runs");
    assert!(signed.status.success(), "sign should succeed");
    let signed_json = String::from_utf8_lossy(&signed.stdout).to_string();
    let signed_file = temp_path("gov-signed2", "json");
    fs::write(&signed_file, &signed_json).expect("write signed");

    let whip = temp_path("ifc-whip2", "whip");
    fs::write(&whip, IFC_BAD_WHIP).expect("write whip");

    // a verified signed envelope enforces: the bad flow is rejected
    let enforced = Command::new(bin)
        .args(["check", whip.to_str().expect("utf-8 path")])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &signed_file)
        .output()
        .expect("command runs");
    assert!(!enforced.status.success(), "signed envelope should enforce");
    assert!(
        String::from_utf8_lossy(&enforced.stderr).contains("denied flow in rule"),
        "stderr: {}",
        String::from_utf8_lossy(&enforced.stderr)
    );

    // tamper the signed envelope: flip ledger's reader to public without re-signing
    let tampered = signed_json.replace("\"reader\":[\"Operator\"]", "\"reader\":[]");
    assert_ne!(tampered, signed_json, "tamper must change the content");
    fs::write(&signed_file, &tampered).expect("write tampered");
    let rejected = Command::new(bin)
        .args(["check", whip.to_str().expect("utf-8 path")])
        .env("WHIPPLESCRIPT_IFC_ENVELOPE", &signed_file)
        .output()
        .expect("command runs");
    assert!(
        !rejected.status.success(),
        "tampered envelope must be rejected"
    );
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("governance envelope rejected"),
        "stderr: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );

    let _ = fs::remove_file(&config);
    let _ = fs::remove_file(&signed_file);
    let _ = fs::remove_file(&whip);
}

/// End-to-end escalation channel (DR-0028 D5): the whip side files an escalation
/// (unprivileged); only the governance agent (privileged) may review it.
#[test]
fn ifc_escalation_channel_whip_files_gov_reviews() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let log = temp_path("gov-escalations", "jsonl");
    let _ = fs::remove_file(&log);
    let log_arg = log.to_str().expect("utf-8 path");

    // whip side (unprivileged) files a request
    let filed = Command::new(bin)
        .args(["gov", "escalate", "need declassify ledger to Auditor"])
        .env("WHIPPLESCRIPT_GOV_ESCALATIONS", log_arg)
        .env_remove("WHIPPLESCRIPT_GOV_ADMIN")
        .output()
        .expect("command runs");
    assert!(
        filed.status.success(),
        "filing an escalation should succeed\nstderr:\n{}",
        String::from_utf8_lossy(&filed.stderr)
    );

    // whip side (unprivileged) cannot review
    let denied = Command::new(bin)
        .args(["gov", "escalations"])
        .env("WHIPPLESCRIPT_GOV_ESCALATIONS", log_arg)
        .env_remove("WHIPPLESCRIPT_GOV_ADMIN")
        .output()
        .expect("command runs");
    assert!(
        !denied.status.success(),
        "unprivileged review must be refused"
    );

    // governance agent (privileged) reviews the pending request
    let reviewed = Command::new(bin)
        .args(["gov", "escalations"])
        .env("WHIPPLESCRIPT_GOV_ESCALATIONS", log_arg)
        .env("WHIPPLESCRIPT_GOV_ADMIN", "1")
        .output()
        .expect("command runs");
    assert!(
        reviewed.status.success(),
        "privileged review should succeed"
    );
    assert!(
        String::from_utf8_lossy(&reviewed.stdout).contains("declassify ledger to Auditor"),
        "stdout: {}",
        String::from_utf8_lossy(&reviewed.stdout)
    );

    let _ = fs::remove_file(&log);
}

/// End-to-end governance agent loop (DR-0028 D5): privileged, it reads commands
/// from stdin, drafts a config, and signs; unprivileged, it refuses to start.
#[test]
fn ifc_governance_agent_loop_drafts_and_signs() {
    use std::io::Write;
    let bin = env!("CARGO_BIN_EXE_whip");
    let out = temp_path("gov-agent-out", "json");
    let _ = fs::remove_file(&out);
    let out_arg = out.to_str().expect("utf-8 path");
    let script =
        format!("grant file_store ledger -> file:/x readable by Operator\nsign {out_arg}\nquit\n");

    // privileged: the agent loop drafts and signs
    let mut child = Command::new(bin)
        .args(["gov", "agent"])
        .env("WHIPPLESCRIPT_GOV_ADMIN", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("write script");
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success(), "gov agent loop should succeed");
    let signed = fs::read_to_string(&out).expect("signed envelope written");
    assert!(signed.contains("attestation"), "got: {signed}");

    // unprivileged: the agent refuses to start
    let denied = Command::new(bin)
        .args(["gov", "agent"])
        .env_remove("WHIPPLESCRIPT_GOV_ADMIN")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("command runs");
    assert!(
        !denied.status.success(),
        "unprivileged gov agent must refuse"
    );

    let _ = fs::remove_file(&out);
}

/// End-to-end whip infoflow loop (DR-0026/0028; renamed from `whip agent`,
/// spec/std-agent.md "Operator CLI"): the unprivileged whip agent can
/// `check` a whip but is refused if it tries to `sign` governance.
#[test]
fn ifc_whip_infoflow_loop_checks_and_refuses_to_sign() {
    use std::io::Write;
    let bin = env!("CARGO_BIN_EXE_whip");
    let whip = temp_path("whip-agent-whip", "whip");
    fs::write(&whip, IFC_BAD_WHIP).expect("write whip");
    let whip_arg = whip.to_str().expect("utf-8 path");
    let script = format!("check {whip_arg}\nsign anything\nquit\n");

    let mut child = Command::new(bin)
        .args(["infoflow"])
        .env_remove("WHIPPLESCRIPT_IFC_ENVELOPE")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(script.as_bytes())
        .expect("write script");
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success(), "whip infoflow loop should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("no information-flow violations"),
        "dev-mode check should pass: {stdout}"
    );
    assert!(
        stdout.contains("cannot sign governance"),
        "whip infoflow must refuse to sign: {stdout}"
    );

    let _ = fs::remove_file(&whip);
}

/// `whip agent` is a one-way rename to `whip infoflow` (spec/std-agent.md
/// "Operator CLI"): no alias — the old name errors with a pointer, freeing the
/// `whip agent` namespace for std.agent.
#[test]
fn whip_agent_errors_with_infoflow_pointer() {
    let bin = env!("CARGO_BIN_EXE_whip");
    let output = Command::new(bin).args(["agent"]).output().expect("run");
    assert!(
        !output.status.success(),
        "`whip agent` must fail after the infoflow rename"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("whip infoflow"),
        "`whip agent` must point at `whip infoflow`: {stderr}"
    );
}

#[test]
fn whip_script_list_and_verify_recheck_manifest_pins() {
    // SC6 (spec/std-script.md "operator surface polish"): read-only views
    // over the pinned script manifest. `verify` re-hashes each entry with
    // structured expected/actual fields and exits 1 on any mismatch; `list`
    // shows the pins. Bootstrap trick: pin a wrong hash first and re-pin
    // from the reported actual_sha256 so the test hardcodes no digest.
    let bin = env!("CARGO_BIN_EXE_whip");
    let script = temp_path("sc6-script", "py");
    let manifest = temp_path("sc6-manifest", "json");
    fs::write(&script, "#!/usr/bin/env python3\nprint(\"{}\")\n").expect("write script");
    let manifest_with = |sha: &str| {
        serde_json::json!({
            "sc6_probe": {
                "argv": ["python3", script.to_str().expect("utf-8")],
                "sha256": sha
            }
        })
        .to_string()
    };
    fs::write(&manifest, manifest_with(&"0".repeat(64))).expect("write manifest");

    let mismatch = Command::new(bin)
        .args([
            "--json",
            "script",
            "verify",
            "--script-manifest",
            manifest.to_str().expect("utf-8"),
        ])
        .output()
        .expect("runs");
    assert!(
        !mismatch.status.success(),
        "a wrong pin must fail verify: {}",
        String::from_utf8_lossy(&mismatch.stdout)
    );
    let report: Value = serde_json::from_slice(&mismatch.stdout).expect("verify emits json");
    let row = &report
        .get("scripts")
        .and_then(Value::as_array)
        .expect("rows")[0];
    assert_eq!(row.get("status").and_then(Value::as_str), Some("mismatch"));
    assert_eq!(
        row.get("expected_sha256").and_then(Value::as_str),
        Some("0".repeat(64).as_str()),
        "structured expected field"
    );
    let actual = row
        .get("actual_sha256")
        .and_then(Value::as_str)
        .expect("structured actual field")
        .to_owned();
    assert_eq!(actual.len(), 64);

    fs::write(&manifest, manifest_with(&actual)).expect("re-pin manifest");
    let verified = Command::new(bin)
        .args([
            "--json",
            "script",
            "verify",
            "--script-manifest",
            manifest.to_str().expect("utf-8"),
        ])
        .output()
        .expect("runs");
    assert!(
        verified.status.success(),
        "a correct pin must verify: {}",
        String::from_utf8_lossy(&verified.stdout)
    );

    let listed = Command::new(bin)
        .args([
            "--json",
            "script",
            "list",
            "--script-manifest",
            manifest.to_str().expect("utf-8"),
        ])
        .output()
        .expect("runs");
    assert!(listed.status.success());
    let rows: Value = serde_json::from_slice(&listed.stdout).expect("list emits json");
    assert_eq!(
        rows.as_array().expect("rows")[0]
            .get("sha256")
            .and_then(Value::as_str),
        Some(actual.as_str())
    );

    let _ = fs::remove_file(&script);
    let _ = fs::remove_file(&manifest);
}

#[test]
fn tampered_script_capability_fails_with_structured_hash_evidence() {
    // SC6's evidence half: the runtime hash-mismatch refusal records
    // machine-readable expected_sha256/actual_sha256 on the failed fact and
    // terminal, replacing message-text-only evidence.
    let bin = env!("CARGO_BIN_EXE_whip");
    let store = temp_path("sc6-evidence", "sqlite");
    let source = temp_path("sc6-evidence", "whip");
    let script = temp_path("sc6-evidence-script", "py");
    let manifest = temp_path("sc6-evidence-manifest", "json");
    fs::write(&script, "#!/usr/bin/env python3\nprint(\"{}\")\n").expect("write script");
    fs::write(
        &manifest,
        serde_json::json!({
            "sc6_judge": {
                "argv": ["python3", script.to_str().expect("utf-8")],
                "sha256": "1".repeat(64)
            }
        })
        .to_string(),
    )
    .expect("write manifest");
    fs::write(
        &source,
        r#"
use std.script
workflow Sc6Evidence

output result Report
failure trouble Report

class Request {
  text string
}

class Report {
  message string
}

table requests as Request [
  {
    text "tampered"
  }
]

rule go
  when Request as request
=> {
  exec sc6_judge with request -> Report as report

  after report succeeds as out {
    complete result {
      message out.message
    }
  }
  after report fails as f {
    fail trouble {
      message f.reason
    }
  }
}
"#,
    )
    .expect("write source");

    let dev = dev_until_idle(
        bin,
        store.to_str().expect("utf-8"),
        source.to_str().expect("utf-8"),
        &[
            "--exec-profile",
            "hosted",
            "--script-manifest",
            manifest.to_str().expect("utf-8"),
        ],
    );
    let instance = dev
        .get("instance_id")
        .and_then(Value::as_str)
        .expect("instance id");
    let facts = run_json(
        bin,
        &[
            "--store",
            store.to_str().expect("utf-8"),
            "--json",
            "facts",
            instance,
        ],
    );
    let failed = facts
        .as_array()
        .expect("facts array")
        .iter()
        .find(|fact| fact.get("name").and_then(Value::as_str) == Some("exec.command.failed"))
        .expect("hash mismatch fails the exec effect");
    let evidence = failed
        .pointer("/value/error/evidence")
        .expect("structured evidence on the failed fact");
    assert_eq!(
        evidence.get("kind").and_then(Value::as_str),
        Some("script.hash_mismatch")
    );
    assert_eq!(
        evidence.get("expected_sha256").and_then(Value::as_str),
        Some("1".repeat(64).as_str())
    );
    assert_eq!(
        evidence
            .get("actual_sha256")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );

    let _ = fs::remove_file(&store);
    let _ = fs::remove_file(&source);
    let _ = fs::remove_file(&script);
    let _ = fs::remove_file(&manifest);
}
