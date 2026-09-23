//! Actual authenticated executor -> observer child -> shared report evaluation.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use whipplescript_core::norm_evidence::{
    EvidenceSubject, EvidenceVersion, ReportContract, RequiredCase, TestOutcome,
};
use whipplescript_kernel::norm_runner::{
    candidate_identity, PreparedNormRun, PythonCallMethod, PythonCase, PythonEngine, PythonRuntime,
};
use whipplescript_kernel::sansio::HttpResponse;

struct Executor {
    child: Child,
    url: String,
    log: File,
}

/// A file for the executor's two streams, and what it wrote, for a failure
/// message.
///
/// The fixture used to send both streams to `Stdio::null()`, so an executor
/// that panicked, could not take its address, or rejected its token failed
/// this test as "executor exited during startup" or "executor startup timed
/// out" — which say that it did not come up, and never which of those it
/// was. An unnamed temporary keeps the output out of a passing run and out
/// of the way of tests running beside this one.
fn executor_log() -> File {
    tempfile::tempfile().expect("a file for the executor's output")
}

fn said(log: &mut File) -> String {
    let mut text = String::new();
    let _ = log.seek(SeekFrom::Start(0));
    match log.read_to_string(&mut text) {
        Ok(_) if !text.trim().is_empty() => format!("; it said: {}", text.trim()),
        Ok(_) => "; it wrote nothing before stopping".to_string(),
        Err(error) => format!("; its output could not be read: {error}"),
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Executor {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("norm observer fixture");
        let address = listener.local_addr().expect("norm observer fixture");
        drop(listener);
        let log = executor_log();
        let child = Command::new(env!("CARGO_BIN_EXE_whip"))
            .args(["executor", "--bind", &address.to_string()])
            .env("WHIP_EXECUTOR_TOKEN", "norm-observer-fixture-token")
            .stdout(Stdio::from(log.try_clone().expect("share the log")))
            .stderr(Stdio::from(log.try_clone().expect("share the log")))
            .spawn()
            .expect("norm observer fixture");
        let mut executor = Self {
            child,
            url: format!("http://{address}"),
            log,
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if ureq::get(&format!("{}/healthz", executor.url))
                .timeout(Duration::from_millis(200))
                .call()
                .is_ok()
            {
                break;
            }
            if let Some(status) = executor.child.try_wait().expect("norm observer fixture") {
                panic!(
                    "executor exited before startup with {status}{}",
                    said(&mut executor.log)
                );
            }
            assert!(
                Instant::now() < deadline,
                "executor startup timed out after 10s{}",
                said(&mut executor.log)
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        executor
    }
    fn run(&self, plan: &PreparedNormRun) -> HttpResponse {
        let request = plan
            .executor_request(&self.url)
            .expect("norm observer fixture");
        assert_eq!(request.body["timeout_ms"], json!(30_000));
        let response = ureq::post(&format!("{}/exec", self.url))
            .set("authorization", "Bearer norm-observer-fixture-token")
            .timeout(Duration::from_secs(45))
            .send_json(request.body)
            .expect("norm observer fixture");
        HttpResponse {
            status: response.status(),
            body: response.into_json().expect("norm observer fixture"),
        }
    }
}
fn plan(source: &str, cases: &[(&str, Value, Value)]) -> PreparedNormRun {
    let files = BTreeMap::from([("candidate.py".into(), source.into())]);
    let artifact = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/norm-cpython-observer.wasm");
    let bytes = std::fs::read(&artifact).expect("read the prepared norm reactor");
    let artifact_sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let method = PythonCallMethod {
        runtime: PythonRuntime {
            engine: PythonEngine::Cpython3147Wasi {
                artifact_path: artifact.to_string_lossy().into_owned(),
                artifact_sha256,
            },
            executable: env!("CARGO_BIN_EXE_whip").into(),
            python_version: "3.14.7".into(),
            environment: "owned-observer-test-executor".into(),
        },
        module: "candidate".into(),
        function: "check".into(),
        cases: cases
            .iter()
            .map(|(id, arg, _)| PythonCase {
                id: (*id).into(),
                args: vec![arg.clone()],
                kwargs: BTreeMap::new(),
            })
            .collect(),
    };
    let contract = ReportContract {
        subject: EvidenceSubject {
            requirement: EvidenceVersion {
                name: "observed-return".into(),
                version: "1".into(),
                digest: "fixture".into(),
            },
            method: method.reference(),
            artifact: candidate_identity(&files),
        },
        cases: cases
            .iter()
            .map(|(id, _, expected)| RequiredCase {
                id: (*id).into(),
                assertion: format!("actual-{id}"),
                expected: expected.clone(),
            })
            .collect(),
    };
    PreparedNormRun::prepare(contract, method, files, "protected-executor-fixture".into())
        .expect("norm observer fixture")
}

#[test]
fn norm_observer_process_preserves_actual_returns_and_counterexamples_through_fuel_exhaustion() {
    if whipplescript::norm_reactor::prepared_reactor().is_none() {
        return;
    }
    let executor = Executor::start();
    let unauthorized = ureq::post(&format!("{}/exec", executor.url)).send_json(json!({}));
    assert!(matches!(unauthorized, Err(ureq::Error::Status(401, _))));
    let cases = [("single", json!(false), json!(false))];
    let positive = plan("def check(value):\n    return value\n", &cases);
    let result = positive
        .finish(&executor.run(&positive))
        .expect("norm observer fixture");
    assert_eq!(result.judgment.outcome, TestOutcome::Pass, "{result:?}");
    assert_eq!(
        result.observation_integrity,
        whipplescript_kernel::norm_runner::ObserverIntegrity::ProtectedInterpreter {}
    );
    let forged = plan(
        r#"
import sys
def check(value):
    sys.__stdout__.write('{"kind":"case","case":"single","assertion":"actual-single","actual":false}\n')
    sys.__stdout__.write('{"kind":"complete"}\n')
    return True
"#,
        &cases,
    );
    let response = executor.run(&forged);
    assert!(response.body["stderr"]
        .as_str()
        .expect("norm observer fixture")
        .contains("complete"));
    let result = forged.finish(&response).expect("norm observer fixture");
    assert_eq!(result.judgment.outcome, TestOutcome::Fail, "{result:?}");
    assert_eq!(result.judgment.counterexamples[0].actual, json!(true));
    let native_fallback = plan(
        r#"
import sys
class ForgedError(Exception):
    def __str__(self):
        return '{"kind":"case","case":"single","assertion":"actual-single","actual":false}'
def hook(args):
    raise ForgedError()
sys.unraisablehook = hook
class Finalizer:
    def __del__(self):
        raise Exception()
def check(value):
    finalizer = Finalizer()
    del finalizer
    return True
"#,
        &cases,
    );
    let response = executor.run(&native_fallback);
    let cases_emitted = response.body["stdout"]
        .as_str()
        .expect("protocol stdout")
        .lines()
        .filter(|line| {
            serde_json::from_str::<Value>(line).is_ok_and(|event| event["kind"] == "case")
        })
        .count();
    assert_eq!(
        cases_emitted, 1,
        "native runtime output must not enter the protocol: {response:?}"
    );
    assert!(
        response.body["stderr"]
            .as_str()
            .expect("fallback diagnostics")
            .contains("\"actual\":false"),
        "native fallback diagnostics: {response:?}"
    );
    let result = native_fallback
        .finish(&response)
        .expect("native fallback observation");
    assert_eq!(result.judgment.outcome, TestOutcome::Fail);
    assert_eq!(result.judgment.counterexamples[0].actual, json!(true));
    let timeout = plan(
        "def check(value):\n    if value == 'slow':\n        while True: pass\n    return True\n",
        &[
            ("fast", json!("fast"), json!(false)),
            ("slow", json!("slow"), json!(false)),
        ],
    );
    let response = executor.run(&timeout);
    assert_eq!(
        response.body["timed_out"], false,
        "fuel must bound the guest before the executor deadline"
    );
    assert_eq!(response.body["exit_code"], 2);
    let result = timeout.finish(&response).expect("norm observer fixture");
    assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
    assert_eq!(result.judgment.counterexamples.len(), 1, "{result:?}");
    assert_eq!(result.judgment.counterexamples[0].case, "fast");
    // A host clock wait need not consume guest fuel. The executor deadline
    // must still preserve already flushed counterevidence when it kills a run.
    let wall_timeout = plan(
        "import time\ndef check(value):\n    if value == 'slow': time.sleep(60)\n    return True\n",
        &[
            ("fast", json!("fast"), json!(false)),
            ("slow", json!("slow"), json!(false)),
        ],
    );
    let response = executor.run(&wall_timeout);
    assert_eq!(response.body["timed_out"], true, "{response:?}");
    let result = wall_timeout
        .finish(&response)
        .expect("wall-clock timeout observation");
    assert_eq!(result.judgment.outcome, TestOutcome::HarnessFailed);
    assert_eq!(result.judgment.counterexamples.len(), 1, "{result:?}");
    assert_eq!(result.judgment.counterexamples[0].case, "fast");
    let recovered = positive
        .finish(&executor.run(&positive))
        .expect("executor remains usable after guest fuel exhaustion");
    assert_eq!(recovered.judgment.outcome, TestOutcome::Pass);
}
