//! Actual pinned Python executions through the existing executor handler.
use std::collections::BTreeMap;
use std::process::Command;

use serde_json::{json, Value};
use whipplescript_core::norm_evidence::{
    EvidenceSubject, EvidenceVersion, ReportContract, RequiredCase, TestOutcome,
};
use whipplescript_kernel::norm_runner::{
    candidate_identity, PreparedNormRun, PythonCallMethod, PythonCase, PythonRuntime,
};
use whipplescript_kernel::sansio::HttpResponse;

use super::handle_exec_request;

fn fixture(broken: bool) -> (ReportContract, PythonCallMethod, BTreeMap<String, String>) {
    let version = Command::new("python3")
        .args(["-I", "-c", "import sys; print(sys.version.split()[0])"])
        .output()
        .expect("Python fixture runtime");
    assert!(version.status.success());
    let files = BTreeMap::from([
        ("src/auth.py".into(), "from src import parser\ndef authorize(role, grant):\n    return role == 'owner' or parser.allowed(grant)\n".into()),
        ("src/parser.py".into(), if broken { "def allowed(grant):\n    return True\n" } else { "def allowed(grant):\n    return grant == 'allow'\n" }.into()),
        ("config/description.txt".into(), "Unicode café, quote \" and newline\n".into()),
    ]);
    let pairs = [
        ("owner", "allow", true),
        ("owner", "deny", true),
        ("worker", "allow", true),
        ("worker", "deny", false),
    ];
    let method = PythonCallMethod {
        runtime: PythonRuntime {
            engine: Default::default(),
            executable: "python3".into(),
            python_version: String::from_utf8(version.stdout)
                .expect("version text")
                .trim()
                .into(),
            environment: "test-executor-profile".into(),
        },
        module: "src.auth".into(),
        function: "authorize".into(),
        cases: pairs
            .iter()
            .map(|(role, grant, _)| PythonCase {
                id: format!("{role}-{grant}"),
                args: vec![json!(role), json!(grant)],
                kwargs: BTreeMap::new(),
            })
            .collect(),
    };
    let contract = ReportContract {
        subject: EvidenceSubject {
            requirement: EvidenceVersion {
                name: "custody-authorization".into(),
                version: "1".into(),
                digest: "four-role-grant-proposition".into(),
            },
            method: method.reference(),
            artifact: candidate_identity(&files),
        },
        cases: pairs
            .iter()
            .map(|(role, grant, expected)| RequiredCase {
                id: format!("{role}-{grant}"),
                assertion: format!("authorize:{role}:{grant}"),
                expected: json!(expected),
            })
            .collect(),
    };
    (contract, method, files)
}

fn plan(broken: bool) -> PreparedNormRun {
    let (contract, method, files) = fixture(broken);
    PreparedNormRun::prepare(contract, method, files, "norm-fixture-run".into())
        .expect("prepared actual run")
}

fn execute(plan: &PreparedNormRun) -> HttpResponse {
    let request = plan
        .executor_request("http://executor")
        .expect("executor request");
    HttpResponse {
        status: 200,
        body: handle_exec_request(&request.body).expect("actual executor run"),
    }
}

#[test]
fn norm_runner_executes_the_candidate_and_locates_the_parser_counterexample() {
    for (broken, expected) in [(false, TestOutcome::Pass), (true, TestOutcome::Fail)] {
        let plan = plan(broken);
        let result = plan.finish(&execute(&plan)).expect("bound result");
        assert_eq!(result.judgment.outcome, expected, "{result:?}");
        assert_eq!(result.judgment.exercised.len(), 4);
        assert_eq!(
            result.judgment.subject.artifact,
            result.report.subject.artifact
        );
        if broken {
            assert_eq!(result.judgment.counterexamples.len(), 1);
            assert_eq!(result.judgment.counterexamples[0].case, "worker-deny");
            assert_eq!(result.judgment.counterexamples[0].actual, json!(true));
        }
    }
}

#[test]
fn norm_runner_retains_actual_failure_through_timeout_truncation_and_swallowed_exit() {
    let plan = plan(true);
    let response = execute(&plan);
    let counter = plan
        .finish(&response)
        .expect("baseline failure")
        .judgment
        .counterexamples;
    for (field, value) in [
        ("timed_out", json!(true)),
        ("stdout_truncated", json!(true)),
        ("stderr_truncated", json!(true)),
        ("exit_code", json!(0)),
    ] {
        let mut changed = response.clone();
        changed.body[field] = value;
        let result = plan.finish(&changed).expect("damaged run still observed");
        assert_eq!(
            result.judgment.outcome,
            TestOutcome::HarnessFailed,
            "{field}: {result:?}"
        );
        assert_eq!(result.judgment.counterexamples, counter);
    }
    let mut incomplete = response.clone();
    let lines: Vec<_> = response.body["stdout"]
        .as_str()
        .expect("stdout")
        .lines()
        .filter(|line| !line.contains("\"kind\":\"complete\""))
        .collect();
    incomplete.body["stdout"] = json!(lines.join("\n"));
    let result = plan.finish(&incomplete).expect("partial report");
    assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
    assert_eq!(result.judgment.counterexamples, counter);
}

#[test]
fn norm_runner_derives_actual_source_and_method_identity_in_the_executed_adapter() {
    let plan = plan(false);
    for change_source in [true, false] {
        let mut request = plan.executor_request("http://executor").expect("request");
        if change_source {
            request.body["stdin"]["files"]["src/parser.py"] =
                json!("def allowed(grant):\n    return True\n");
        } else {
            let text = request.body["stdin"]["method_definition_json"]
                .as_str()
                .expect("definition");
            let mut definition: Value = serde_json::from_str(text).expect("method JSON");
            definition["cases"][3]["args"][1] = json!("allow");
            request.body["stdin"]["method_definition_json"] = json!(definition.to_string());
        }
        let response = HttpResponse {
            status: 200,
            body: handle_exec_request(&request.body).expect("tampered invocation executes"),
        };
        let result = plan.finish(&response).expect("mismatch observed");
        assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
        assert!(result.judgment.counterexamples.is_empty());
        assert!(result.judgment.exercised.is_empty());
    }
}

#[test]
fn norm_runner_refuses_wrong_receipts_and_unbound_adapter_headers() {
    let plan = plan(false);
    let response = execute(&plan);
    let mut wrong_status = response.clone();
    wrong_status.status = 503;
    assert!(plan.finish(&wrong_status).is_err());
    for field in ["protocol", "effect_id"] {
        let mut changed = response.clone();
        changed.body[field] = json!("another");
        assert!(plan.finish(&changed).is_err());
    }
    for field in [
        "stdout",
        "stderr",
        "stdout_truncated",
        "stderr_truncated",
        "timed_out",
        "exit_code",
    ] {
        let mut changed = response.clone();
        changed
            .body
            .as_object_mut()
            .expect("receipt object")
            .remove(field);
        let result = plan
            .finish(&changed)
            .expect("incomplete receipt is a harness observation");
        assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d == &format!("missing or invalid executor field {field}")));
    }
    for field in [
        "protocol",
        "run_id",
        "artifact",
        "environment",
        "adapter_digest",
        "python_version",
        "method",
        "contract_digest",
        "requirement",
    ] {
        let mut lines: Vec<Value> = response.body["stdout"]
            .as_str()
            .expect("stdout")
            .lines()
            .map(|line| serde_json::from_str(line).expect("event"))
            .collect();
        if matches!(field, "method" | "requirement") {
            lines[0][field]["digest"] = json!("other");
        } else {
            lines[0][field] = json!("other");
        }
        let mut changed = response.clone();
        changed.body["stdout"] = json!(lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"));
        let result = plan.finish(&changed).expect("header mismatch");
        assert_eq!(
            result.judgment.outcome,
            TestOutcome::HarnessFailed,
            "{field}"
        );
        assert!(result.judgment.exercised.is_empty());
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d == "adapter header differs from the prepared run or runtime"));
        let header = result.observed_header.expect("retain the actual header");
        assert_eq!(result.report.subject.requirement, header.requirement);
        assert_eq!(result.report.subject.method, header.method);
        assert_eq!(result.report.subject.artifact, header.artifact);
    }
}

#[test]
fn norm_runner_missing_malformed_and_out_of_order_reports_never_pass() {
    let plan = plan(false);
    let response = execute(&plan);
    let lines: Vec<_> = response.body["stdout"]
        .as_str()
        .expect("stdout")
        .lines()
        .map(str::to_owned)
        .collect();
    let variants = [
        String::new(),
        "not a structured report".into(),
        lines[1..].join("\n"),
        format!("{}\n{}", lines[0], lines.join("\n")),
        format!("{}\n{}", lines.join("\n"), lines[1]),
        format!(
            "{}\n{}",
            lines.join("\n"),
            lines.last().expect("completion")
        ),
        format!("{}\n{}", lines[1], lines.join("\n")),
        format!(
            "{}\n{}",
            lines.last().expect("completion"),
            lines.join("\n")
        ),
        format!(
            "{}\n{{\"kind\":\"error\",\"case\":null,\"message\":\"crash\"}}",
            lines.join("\n")
        ),
    ];
    for stdout in variants {
        let mut changed = response.clone();
        changed.body["stdout"] = json!(stdout);
        assert_eq!(
            plan.finish(&changed)
                .expect("diagnostic report")
                .judgment
                .outcome,
            TestOutcome::HarnessFailed
        );
    }
}

#[test]
fn norm_runner_preparation_pins_paths_runtime_and_the_entire_case_inventory() {
    let (contract, method, files) = fixture(false);
    assert!(
        PreparedNormRun::prepare(contract.clone(), method.clone(), files.clone(), " ".into())
            .is_err()
    );
    let mut stale = contract.clone();
    stale.subject.method.digest = "stale".into();
    assert!(PreparedNormRun::prepare(stale, method.clone(), files.clone(), "run".into()).is_err());
    let mut stale = contract.clone();
    stale.subject.artifact = "stale".into();
    assert!(PreparedNormRun::prepare(stale, method.clone(), files.clone(), "run".into()).is_err());
    for which in 0..8 {
        let mut method = method.clone();
        match which {
            0 => method.runtime.executable.clear(),
            1 => method.runtime.python_version.clear(),
            2 => method.runtime.environment.clear(),
            3 => method.module = "../escape".into(),
            4 => method.function = "not-a-name".into(),
            5 => {
                method.cases.pop();
            }
            6 => method.cases.push(method.cases[0].clone()),
            _ => method.cases[0].id = "outside".into(),
        }
        let mut contract = contract.clone();
        contract.subject.method = method.reference();
        assert!(
            PreparedNormRun::prepare(contract, method, files.clone(), "run".into()).is_err(),
            "case {which}"
        );
    }
    for name in [
        "../escape.py",
        "/absolute.py",
        "src//bad.py",
        "./dot.py",
        "C:drive.py",
        "src\\bad.py",
    ] {
        let mut files = files.clone();
        files.insert(name.into(), "".into());
        let mut contract = contract.clone();
        contract.subject.artifact = candidate_identity(&files);
        assert!(PreparedNormRun::prepare(contract, method.clone(), files, "run".into()).is_err());
    }
    for which in 0..3 {
        let mut contract = contract.clone();
        let mut method = method.clone();
        match which {
            0 => contract.cases.push(contract.cases[0].clone()),
            1 => contract.cases[0].assertion.clear(),
            _ => {
                contract.cases[0].id.clear();
                method.cases[0].id.clear();
                contract.subject.method = method.reference();
            }
        }
        assert!(PreparedNormRun::prepare(contract, method, files.clone(), "run".into()).is_err());
    }
}

#[test]
fn norm_runner_real_case_errors_and_early_exit_keep_prior_counterexamples() {
    for body in [
        "def authorize(role, grant):\n    if role == 'worker' and grant == 'deny': raise RuntimeError('adapter-fixture-error')\n    return role == 'owner'\n",
        "import os\ndef authorize(role, grant):\n    if grant == 'deny': os._exit(0)\n    return False\n",
    ] {
        let (mut contract, method, mut files) = fixture(false);
        files.insert("src/auth.py".into(), body.into());
        contract.subject.artifact = candidate_identity(&files);
        let plan = PreparedNormRun::prepare(contract, method, files, "error-run".into()).expect("error fixture");
        let result = plan.finish(&execute(&plan)).expect("real damaged run");
        assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
        assert_eq!(result.judgment.counterexamples.len(), 1, "{result:?}");
        if body.contains("RuntimeError") {
            assert!(result.diagnostics.iter().any(|d| d == "adapter case Some(\"worker-deny\"): RuntimeError: adapter-fixture-error"));
        } else {
            assert!(result.diagnostics.iter().any(|d| d == "missing adapter completion"));
        }
    }
    let (mut contract, mut method, files) = fixture(false);
    contract.cases.clear();
    method.cases.clear();
    contract.subject.method = method.reference();
    let plan = PreparedNormRun::prepare(contract, method, files, "empty-family".into())
        .expect("empty family is observed");
    let result = plan.finish(&execute(&plan)).expect("empty run");
    assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
    assert!(result.judgment.exercised.is_empty());
}

#[test]
fn norm_runner_diagnostics_are_retained_even_when_other_guards_also_refuse() {
    let plan = plan(false);
    let response = execute(&plan);
    for field in ["stdout_truncated", "stderr_truncated"] {
        let mut changed = response.clone();
        changed.body[field] = json!(true);
        assert!(plan
            .finish(&changed)
            .expect("truncated")
            .diagnostics
            .iter()
            .any(|d| d == "executor stream truncated"));
    }
    let mut empty = response.clone();
    empty.body["stdout"] = json!("");
    let result = plan.finish(&empty).expect("missing report");
    assert!(result
        .diagnostics
        .iter()
        .any(|d| d == "missing adapter header"));
    assert!(result
        .diagnostics
        .iter()
        .any(|d| d == "missing adapter completion"));
    let mut invalid = response.clone();
    invalid.body["stdout"] = json!("{");
    assert!(plan
        .finish(&invalid)
        .expect("invalid JSON")
        .diagnostics
        .iter()
        .any(|d| d.starts_with("invalid adapter event:")));
    let lines: Vec<_> = response.body["stdout"]
        .as_str()
        .expect("stdout")
        .lines()
        .map(str::to_owned)
        .collect();
    // A case moved across the header/completion cannot become coverage merely
    // by removing the sequence guard; no duplicate case masks that bypass.
    for stdout in [
        format!("{}\n{}\n{}", lines[1], lines[0], lines[2..].join("\n")),
        format!("{}\n{}\n{}", lines[0], lines[2..].join("\n"), lines[1]),
    ] {
        let mut changed = response.clone();
        changed.body["stdout"] = json!(stdout);
        let result = plan.finish(&changed).expect("outside-case");
        assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d == "case observation outside the adapter run"));
    }
}

#[test]
fn norm_runner_identical_scripts_have_independently_owned_staging_paths() {
    let bytes = b"echo same-script\n";
    let hash = whipplescript_kernel::exec_http::sha256_hex(bytes);
    let first = super::stage_verified_script(&hash, bytes, "sh").expect("first stage");
    let second = super::stage_verified_script(&hash, bytes, "sh").expect("second stage");
    assert_ne!(first.path, second.path);
    let first_path = first.path.clone();
    let second_path = second.path.clone();
    drop(first);
    assert!(!first_path.exists());
    assert_eq!(
        std::fs::read(&second_path).expect("other invocation remains live"),
        bytes
    );
    drop(second);
    assert!(!second_path.exists());
    for extension in ["space ext", "../escape", "a/b", "C:drive"] {
        assert!(super::stage_verified_script(&hash, bytes, extension).is_err());
    }
}

#[test]
fn norm_runner_cannot_substitute_a_cached_runtime_module_for_the_candidate() {
    let (mut contract, mut method, mut files) = fixture(false);
    method.module = "json".into();
    method.function = "loads".into();
    for (input, case) in method.cases.iter_mut().zip(&contract.cases) {
        input.args = vec![json!(case.expected.to_string())];
    }
    // The adapter itself loaded stdlib json before adding the candidate path.
    // Without the origin guard, cached json.loads makes every case pass while
    // this candidate's deliberately wrong function is never exercised.
    files.insert(
        "json.py".into(),
        "def loads(value):\n    return None\n".into(),
    );
    contract.subject.artifact = candidate_identity(&files);
    contract.subject.method = method.reference();
    let plan = PreparedNormRun::prepare(contract, method, files, "module-shadow".into())
        .expect("candidate module declared");
    let result = plan
        .finish(&execute(&plan))
        .expect("module resolution observed");
    assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
    assert!(result.judgment.exercised.is_empty());
    assert!(result
        .diagnostics
        .iter()
        .any(|d| d.contains("entry point resolved outside its exact candidate module")));

    let (contract, method, mut files) = fixture(false);
    files.remove("src/auth.py");
    let mut missing = contract.clone();
    missing.subject.artifact = candidate_identity(&files);
    assert!(
        PreparedNormRun::prepare(missing, method.clone(), files, "missing-module".into()).is_err()
    );
    let (mut contract, method, mut files) = fixture(false);
    files.insert("src/auth/__init__.py".into(), "".into());
    contract.subject.artifact = candidate_identity(&files);
    assert!(PreparedNormRun::prepare(contract, method, files, "ambiguous-module".into()).is_err());
}

#[test]
fn norm_runner_missing_metadata_preserves_an_independently_bound_counterexample() {
    let plan = plan(true);
    let response = execute(&plan);
    let counter = plan
        .finish(&response)
        .expect("baseline failure")
        .judgment
        .counterexamples;
    for field in [
        "stderr",
        "stdout_truncated",
        "stderr_truncated",
        "timed_out",
        "exit_code",
    ] {
        for wrong_type in [false, true] {
            let mut changed = response.clone();
            if wrong_type {
                changed.body[field] = json!([]);
            } else {
                changed.body.as_object_mut().expect("receipt").remove(field);
            }
            let result = plan.finish(&changed).expect("partial metadata");
            assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
            assert_eq!(result.judgment.counterexamples, counter);
        }
    }
}

#[test]
fn norm_runner_real_timeout_keeps_capture_without_waiting_for_a_grandchild() {
    let (mut contract, method, mut files) = fixture(false);
    files.insert("src/auth.py".into(), "import subprocess, sys, time\ndef authorize(role, grant):\n    if grant == 'deny':\n        subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])\n        time.sleep(5)\n    return False\n".into());
    contract.subject.artifact = candidate_identity(&files);
    let plan = PreparedNormRun::prepare(contract, method, files, "real-timeout".into())
        .expect("timeout plan");
    let mut request = plan
        .executor_request("http://executor")
        .expect("timeout request");
    request.body["timeout_ms"] = json!(1500);
    let start = std::time::Instant::now();
    let response = HttpResponse {
        status: 200,
        body: handle_exec_request(&request.body).expect("timed out execution"),
    };
    assert!(
        start.elapsed() < std::time::Duration::from_secs(4),
        "held pipes must not extend the executor deadline"
    );
    assert_eq!(response.body["timed_out"], json!(true));
    let result = plan.finish(&response).expect("timeout observed");
    assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
    assert_eq!(result.judgment.counterexamples.len(), 1, "{result:?}");
    assert_eq!(result.judgment.counterexamples[0].case, "owner-allow");
}

#[test]
fn norm_runner_capture_is_bounded_and_does_not_hide_an_observed_failure() {
    let (mut contract, method, mut files) = fixture(false);
    files.insert(
        "src/auth.py".into(),
        "def authorize(role, grant):\n    print('x' * 600000)\n    return False\n".into(),
    );
    contract.subject.artifact = candidate_identity(&files);
    let plan = PreparedNormRun::prepare(contract, method, files, "bounded-capture".into())
        .expect("chatty plan");
    let response = execute(&plan);
    assert_eq!(response.body["stderr_truncated"], json!(true));
    assert!(response.body["stderr"].as_str().expect("stderr").len() <= super::STREAM_CAP_BYTES);
    let result = plan.finish(&response).expect("bounded capture");
    assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
    assert_eq!(result.judgment.counterexamples.len(), 3);
}

#[test]
fn norm_runner_a_child_exit_does_not_remove_the_deadline_for_held_pipes() {
    let script = "import subprocess, sys\nsubprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])\nprint('observed-before-exit', flush=True)\n";
    let request = whipplescript_kernel::exec_http::build_executor_exec_request(
        "http://executor",
        "held-pipes",
        &whipplescript_kernel::exec_http::sha256_hex(script.as_bytes()),
        script,
        &["python3".into(), "-I".into(), "{script}".into()],
        &[],
        &json!(null),
        Some(1500),
    )
    .expect("held-pipe request");
    let start = std::time::Instant::now();
    let response = handle_exec_request(&request.body).expect("child exited with a live grandchild");
    assert!(start.elapsed() < std::time::Duration::from_secs(4));
    assert_eq!(response["exit_code"], json!(0));
    assert_eq!(response["timed_out"], json!(true));
    assert_eq!(response["stdout"], json!("observed-before-exit\n"));
}

#[test]
fn norm_runner_capture_bounds_memory_while_draining_the_entire_stream() {
    let drain = super::spawn_drain(std::io::Cursor::new(vec![
        b'x';
        super::STREAM_CAP_BYTES * 3
    ]));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !drain.thread.is_finished() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    assert!(drain.thread.is_finished());
    assert!(drain.capture.lock().expect("capture").bytes.len() <= super::STREAM_CAP_BYTES);
    let (text, truncated, open) = drain.finish(deadline);
    assert!(truncated);
    assert!(!open);
    assert_eq!(text.len(), super::STREAM_CAP_BYTES);
}

#[test]
fn norm_runner_a_response_cannot_be_relabelled_under_a_changed_contract() {
    let (contract, method, files) = fixture(false);
    let original = PreparedNormRun::prepare(
        contract.clone(),
        method.clone(),
        files.clone(),
        "same-invocation".into(),
    )
    .expect("original contract");
    let response = execute(&original);
    assert_eq!(
        original
            .finish(&response)
            .expect("original report")
            .judgment
            .outcome,
        TestOutcome::Pass
    );
    for which in 0..4 {
        let mut changed = contract.clone();
        match which {
            0 => changed.subject.requirement.version = "2".into(),
            1 => changed.subject.requirement.digest = "new-meaning".into(),
            2 => changed.cases[0].expected = json!(false),
            // The exact contract is a premise even when a correspondence might
            // later establish this reordered inventory is semantically equal.
            _ => changed.cases.reverse(),
        }
        let new = PreparedNormRun::prepare(
            changed,
            method.clone(),
            files.clone(),
            "same-invocation".into(),
        )
        .expect("changed contract");
        let result = new
            .finish(&response)
            .expect("old report is retained as unbound");
        assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
        assert!(result.judgment.exercised.is_empty());
        assert!(result.judgment.counterexamples.is_empty());
    }
}

#[test]
fn norm_runner_witnesses_bind_observed_scope_and_survive_re_evaluation() {
    let (contract, method, files) = fixture(false);
    let first = PreparedNormRun::prepare(
        contract.clone(),
        method.clone(),
        files.clone(),
        "witness-run".into(),
    )
    .expect("first contract");
    let response = execute(&first);
    let original = first.finish(&response).expect("first observation");
    assert_eq!(original.judgment.outcome, TestOutcome::Pass);
    let mut changed = contract;
    changed.subject.requirement.version = "2".into();
    let second = PreparedNormRun::prepare(changed, method, files, "witness-run".into())
        .expect("second contract");
    let fresh = second
        .finish(&execute(&second))
        .expect("fresh second observation");
    assert_eq!(fresh.judgment.outcome, TestOutcome::Pass);
    assert_ne!(
        original.report.observations[0].witness,
        fresh.report.observations[0].witness
    );
    let re_evaluated = second
        .finish(&response)
        .expect("old observation under another target");
    assert_eq!(re_evaluated.judgment.outcome, TestOutcome::HarnessFailed);
    assert_eq!(
        original.report.observations,
        re_evaluated.report.observations
    );
}

#[test]
fn norm_runner_stdin_backpressure_cannot_prevent_the_execution_deadline() {
    // The child sleeps far longer than any plausible spawn cost, so the two
    // outcomes this guard separates are not neighbours: bounded by the 250ms
    // deadline is a fraction of a second, and blocked on the 512KB stdin write
    // until the child exits is half a minute. A margin that sat beside the
    // child's own sleep measured machine load as much as backpressure, and
    // failed at 2.02s under a loaded test binary while the deadline itself had
    // fired correctly.
    let script = "import time\ntime.sleep(30)\n";
    let request = whipplescript_kernel::exec_http::build_executor_exec_request(
        "http://executor",
        "blocked-stdin",
        &whipplescript_kernel::exec_http::sha256_hex(script.as_bytes()),
        script,
        &["python3".into(), "-I".into(), "{script}".into()],
        &[],
        &json!({"large": "x".repeat(512 * 1024)}),
        Some(250),
    )
    .expect("blocked-stdin request");
    let start = std::time::Instant::now();
    let response =
        handle_exec_request(&request.body).expect("stdin is bounded by the execution deadline");
    let elapsed = start.elapsed();
    assert_eq!(response["timed_out"], json!(true));
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "stdin blocked past the deadline: {elapsed:?}"
    );
}

#[test]
fn norm_runner_stdin_ignores_only_broken_pipe_errors() {
    struct Fails(std::io::ErrorKind);
    impl std::io::Write for Fails {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(self.0))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    assert!(super::write_exec_stdin(Fails(std::io::ErrorKind::BrokenPipe), "input").is_ok());
    assert!(super::write_exec_stdin(Fails(std::io::ErrorKind::PermissionDenied), "input").is_err());
    let mut bytes = Vec::new();
    super::write_exec_stdin(&mut bytes, "complete input").expect("ordinary input");
    assert_eq!(bytes, b"complete input");
}

#[test]
fn norm_runner_executes_owned_stored_cut_after_source_erasure() {
    use whipplescript_store::branches::{BranchStore, Branches, CutRecord, MAINLINE_BRANCH_ID};
    use whipplescript_store::content::{ContentBlobs, ContentStore};
    use whipplescript_store::norm_artifact::{capture_cut, ArtifactLimits};

    let (contract, method, files) = fixture(false);
    let content = ContentStore::open(":memory:").expect("artifact capture fixture");
    let mut branches = BranchStore::open(":memory:").expect("artifact capture fixture");
    branches
        .ensure_mainline("t0")
        .expect("artifact capture fixture");
    let manifest: BTreeMap<_, _> = files
        .iter()
        .map(|(path, body)| {
            (
                path.clone(),
                content
                    .put(body.as_bytes())
                    .expect("artifact capture fixture"),
            )
        })
        .collect();
    let root = whipplescript_store::manifest_tree::build(&content, &manifest)
        .expect("artifact capture fixture");
    branches
        .record_cut(CutRecord {
            cut_id: "source-cut",
            change_id: "source-change",
            branch_id: MAINLINE_BRANCH_ID,
            manifest_hash: &root,
            parent_cut_id: None,
            origin: None,
            actor: None,
            intent: None,
            recorded_at: "t1",
        })
        .expect("artifact capture fixture");
    let artifact = capture_cut(&branches, &content, "source-cut", ArtifactLimits::default())
        .expect("artifact capture fixture");
    let plan = PreparedNormRun::prepare_from_artifact(
        contract.clone(),
        method.clone(),
        &artifact,
        "stored-cut-run".into(),
    )
    .expect("artifact capture fixture");
    let mut wrong_contract = contract;
    wrong_contract.subject.artifact = "different-artifact".into();
    assert!(PreparedNormRun::prepare_from_artifact(
        wrong_contract,
        method,
        &artifact,
        "wrong-cut-run".into()
    )
    .is_err());
    for id in manifest.values() {
        content.erase(id, "t2").expect("artifact capture fixture");
    }
    assert!(capture_cut(&branches, &content, "source-cut", ArtifactLimits::default()).is_err());
    let result = plan
        .finish(&execute(&plan))
        .expect("artifact capture fixture");
    assert_eq!(result.judgment.outcome, TestOutcome::Pass);
    assert_eq!(result.judgment.exercised.len(), 4);
    assert_eq!(plan.source(), Some(artifact.basis()));
    assert_eq!(result.source.as_ref(), Some(artifact.basis()));
}

fn embedded_method(method: &mut PythonCallMethod, contract: &mut ReportContract) -> bool {
    let Some(artifact) = whipplescript::norm_reactor::prepared_reactor() else {
        return false;
    };
    let bytes = std::fs::read(&artifact).expect("read the prepared norm reactor");
    method.runtime.engine = whipplescript_kernel::norm_runner::PythonEngine::Cpython3147Wasi {
        artifact_path: artifact.to_string_lossy().into_owned(),
        artifact_sha256: whipplescript_kernel::exec_http::sha256_hex(&bytes),
    };
    method.runtime.executable = "whip".into();
    method.runtime.python_version = "3.14.7".into();
    contract.subject.method = method.reference();
    true
}

fn execute_embedded(plan: &PreparedNormRun) -> HttpResponse {
    let request = plan.executor_request("http://executor").unwrap();
    let mut events = Vec::new();
    let status = crate::norm_observer::execute(&request.body["stdin"].to_string(), &mut |event| {
        events.push(event.to_string());
        Ok(())
    })
    .unwrap_or(2);
    HttpResponse {
        status: 200,
        body: json!({
            "protocol":super::EXECUTOR_PROTOCOL,"effect_id":request.body["effect_id"],
            "stdout":events.join("\n"),"stderr":"","stdout_truncated":false,
            "stderr_truncated":false,"timed_out":false,"exit_code":status
        }),
    }
}

#[test]
fn norm_runner_candidate_cannot_forge_case_observations_before_calls() {
    let (mut contract, mut method, mut files) = fixture(false);
    if !embedded_method(&mut method, &mut contract) {
        return;
    }
    files.insert(
        "src/auth.py".into(),
        r#"
import json
import os
import sys
frame = sys._getframe()
while frame is not None and "contract" not in frame.f_locals:
    frame = frame.f_back
assert frame is not None
for case in frame.f_locals["contract"]["cases"]:
    sys.__stdout__.write(json.dumps({"kind": "case", "case": case["id"],
        "assertion": case["assertion"], "actual": case["expected"]}) + "\n")
sys.__stdout__.write('{"kind":"complete"}\n')
sys.__stdout__.flush()
os._exit(0)
def authorize(role, grant):
    raise AssertionError("the attacker never invokes this function")
"#
        .into(),
    );
    contract.subject.artifact = candidate_identity(&files);
    let plan = PreparedNormRun::prepare(contract, method, files, "norm-forged-observer".into())
        .expect("prepared adversarial run");
    let result = plan
        .finish(&execute_embedded(&plan))
        .expect("bound adversarial execution");
    assert_ne!(
        result.judgment.outcome,
        TestOutcome::Pass,
        "candidate-authored protocol events must not certify calls: {result:?}"
    );
}

#[test]
fn norm_observer_executes_cross_file_calls_and_ignores_candidate_protocol_text() {
    for broken in [false, true] {
        let (mut contract, mut method, mut files) = fixture(broken);
        if !embedded_method(&mut method, &mut contract) {
            return;
        }
        files.insert("src/auth.py".into(), r#"
from src import parser
import sys
def authorize(role, grant):
    frame = sys._getframe()
    while frame is not None:
        assert 'contract' not in frame.f_locals
        frame = frame.f_back
    for finder in sys.meta_path:
        if type(finder).__name__ == 'CapturedLoader':
            assert 'contract' not in finder.exec_module.__globals__
    sys.__stdout__.write('{"kind":"case","case":"worker-deny","assertion":"authorize:worker:deny","actual":false}\n')
    print('{"kind":"complete"}')
    return role == 'owner' or parser.allowed(grant)
"#.into());
        contract.subject.artifact = candidate_identity(&files);
        let plan =
            PreparedNormRun::prepare(contract, method, files, "embedded-observer".into()).unwrap();
        let result = plan.finish(&execute_embedded(&plan)).unwrap();
        assert_eq!(
            result.judgment.outcome,
            if broken {
                TestOutcome::Fail
            } else {
                TestOutcome::Pass
            },
            "{result:?}"
        );
        assert_eq!(
            result.observation_integrity,
            whipplescript_kernel::norm_runner::ObserverIntegrity::ProtectedInterpreter {}
        );
        assert_eq!(result.judgment.exercised.len(), 4);
        assert_eq!(result.judgment.counterexamples.len(), usize::from(broken));
        if broken {
            assert_eq!(result.judgment.counterexamples[0].actual, json!(true));
        }
    }
}

#[test]
fn norm_observer_refuses_unbounded_or_non_json_return_values() {
    for body in [
        "value=[]; value.append(value); return value",
        "return float('nan')",
        "return 'x' * 300000",
        "return list(range(10001))",
        "return {1: True}",
        "raise SystemExit(0)",
    ] {
        let (mut contract, mut method, mut files) = fixture(false);
        if !embedded_method(&mut method, &mut contract) {
            return;
        }
        files.insert(
            "src/auth.py".into(),
            format!("def authorize(role, grant):\n    {body}\n"),
        );
        contract.subject.artifact = candidate_identity(&files);
        let plan =
            PreparedNormRun::prepare(contract, method, files, "embedded-invalid-return".into())
                .unwrap();
        let result = plan.finish(&execute_embedded(&plan)).unwrap();
        assert_eq!(
            result.judgment.outcome,
            TestOutcome::HarnessFailed,
            "{body}: {result:?}"
        );
        assert!(result.judgment.exercised.is_empty());
    }
}

#[test]
fn norm_observer_engine_codec_preserves_explicit_profile_identity() {
    use whipplescript_kernel::norm_runner::PythonEngine;
    let (_, method, _) = fixture(false);
    assert!(serde_json::to_value(&method.runtime)
        .unwrap()
        .get("engine")
        .is_none());
    assert_eq!(method.reference().version, "1");
    for wire in [
        json!({"kind":"rustpython050"}),
        json!({"kind":"rustpython050","host_env":true}),
        json!({"kind":"cpython","stdio":false}),
        json!({"kind":"unknown"}),
    ] {
        assert!(serde_json::from_value::<PythonEngine>(wire).is_err());
    }
    let mut protected = method.clone();
    protected.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/runtime/norm.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    assert_eq!(protected.reference().version, "2");
    assert_ne!(protected.reference(), method.reference());
    assert_ne!(protected.adapter(), method.adapter());
}

#[test]
fn norm_wasi_profile_pins_artifact_and_refuses_incomplete_identity() {
    use whipplescript_kernel::norm_runner::PythonEngine;
    let (mut contract, mut method, files) = fixture(false);
    method.runtime.executable = "whip".into();
    method.runtime.python_version = "3.14.7".into();
    method.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/runtime/norm.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    contract.subject.method = method.reference();
    assert!(PreparedNormRun::prepare(
        contract.clone(),
        method.clone(),
        files.clone(),
        "wasi-run".into()
    )
    .is_ok());
    assert_eq!(method.reference().version, "2");
    for (path, digest, version) in [
        ("", "a".repeat(64), "3.14.7"),
        ("bad\0path", "a".repeat(64), "3.14.7"),
        ("/runtime/norm.wasm", "a".repeat(63), "3.14.7"),
        ("/runtime/norm.wasm", "A".repeat(64), "3.14.7"),
        ("/runtime/norm.wasm", "g".repeat(64), "3.14.7"),
        ("/runtime/norm.wasm", "a".repeat(64), "3.14.8"),
    ] {
        let mut changed = method.clone();
        changed.runtime.engine = PythonEngine::Cpython3147Wasi {
            artifact_path: path.into(),
            artifact_sha256: digest,
        };
        changed.runtime.python_version = version.into();
        let mut rebound = contract.clone();
        rebound.subject.method = changed.reference();
        assert_eq!(
            PreparedNormRun::prepare(rebound, changed, files.clone(), "bad-profile".into())
                .unwrap_err(),
            "norm WASI runtime requires an artifact path, SHA-256 and Python 3.14.7"
        );
    }
    for (path, digest) in [
        ("/runtime/other.wasm", "a".repeat(64)),
        ("/runtime/norm.wasm", "b".repeat(64)),
    ] {
        let mut changed = method.clone();
        changed.runtime.engine = PythonEngine::Cpython3147Wasi {
            artifact_path: path.into(),
            artifact_sha256: digest,
        };
        assert_ne!(changed.reference(), method.reference());
        assert!(PreparedNormRun::prepare(
            contract.clone(),
            changed,
            files.clone(),
            "changed-runtime".into()
        )
        .is_err());
    }
    for wire in [
        json!({"kind":"cpython3147_wasi","artifact_path":"/runtime/norm.wasm"}),
        json!({"kind":"cpython3147_wasi","artifact_path":"/runtime/norm.wasm","artifact_sha256":"a".repeat(64),"host_env":true}),
    ] {
        assert!(serde_json::from_value::<PythonEngine>(wire).is_err());
    }
}

#[test]
fn norm_wasi_observer_refuses_unverified_artifacts_before_emitting_events() {
    use whipplescript_kernel::norm_runner::PythonEngine;
    let path = std::env::temp_dir().join(format!(
        "norm-wasi-artifact-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, b"not a WebAssembly module").unwrap();
    let (mut contract, mut method, files) = fixture(false);
    method.runtime.python_version = "3.14.7".into();
    method.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: path.to_string_lossy().into_owned(),
        artifact_sha256: "0".repeat(64),
    };
    contract.subject.method = method.reference();
    let plan = PreparedNormRun::prepare(contract, method, files, "invalid-runtime".into()).unwrap();
    let request = plan.executor_request("http://executor").unwrap();
    let mut events = Vec::new();
    let error = crate::norm_observer::execute(&request.body["stdin"].to_string(), &mut |event| {
        events.push(event);
        Ok(())
    })
    .unwrap_err();
    assert_eq!(error, "runtime artifact digest mismatch");
    assert!(events.is_empty());
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let error = crate::norm_observer::execute(&request.body["stdin"].to_string(), &mut |event| {
        events.push(event);
        Ok(())
    })
    .unwrap_err();
    std::fs::remove_file(path).unwrap();
    assert_eq!(error, "norm runtime artifact exceeds its byte budget");
    assert!(events.is_empty());
}

#[test]
fn norm_wasi_reactor_version_is_measured_before_initialization() {
    let bytes = include_bytes!("../tests/fixtures/norm-wasi-wrong-version.wasm");
    let digest = whipplescript_kernel::exec_http::sha256_hex(bytes);
    let runtime = crate::norm_wasi::Runtime::new(bytes, &digest).unwrap();
    let error = match runtime.instantiate() {
        Ok(_) => panic!("wrong Python version accepted"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "reactor was not compiled with CPython 3.14.7 final"
    );
}
