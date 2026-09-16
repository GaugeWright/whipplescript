use super::*;
use crate::norm_execution::{fixtures::*, PreparedNormExecution, PythonCallSupport};
use crate::norm_runner::PythonEngine;
use whipplescript_core::norm_evidence::RequiredCase;

fn recovered(actual: bool, timeout: bool) -> VerifiedNormExecution {
    let mut method = method();
    method.runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: "/runtime/python.wasm".into(),
        artifact_sha256: "a".repeat(64),
    };
    method.runtime.executable = "whip".into();
    let support = PythonCallSupport::V1 {
        method: method.clone(),
        cases: vec![RequiredCase {
            id: "deny".into(),
            assertion: "unknown denied".into(),
            expected: serde_json::json!(false),
        }],
    };
    let (ledger, requirement) = fixture(
        Some(serde_json::to_value(support).expect("serializable policy support fixture")),
        true,
    );
    let history = history(&ledger);
    let source = artifact("def allow(user): return False");
    let mut installed = script();
    installed.body = method.adapter().into();
    installed.sha256 = sha256_hex(installed.body.as_bytes());
    installed.argv_json =
        serde_json::json!(["whip", "executor", "observe-norm", "{script}"]).to_string();
    let prepared = PreparedNormExecution::prepare(
        &history,
        &Boundary,
        &source,
        &installed,
        selection(&history.anchor().checkpoint.ledger, &requirement),
    )
    .expect("prepare policy fixture execution");
    let kernel = journal_execution(
        whipplescript_store::SqliteStore::open_in_memory().expect("policy fixture journal"),
        &prepared,
        &receipt(&prepared, actual, timeout),
        actual || timeout,
    );
    drop(prepared);
    let recovered = PreparedNormExecution::recover_settled(
        &history,
        &Boundary,
        &source,
        kernel.store(),
        "instance",
        "run",
    )
    .expect("recover policy fixture execution");
    assert_eq!(recovered.method(), &method);
    recovered
}
fn query(policy: &ProtectedPythonPolicy, execution: &VerifiedNormExecution) -> SelectionQuery {
    SelectionQuery {
        requirement: execution.contract().subject.requirement.clone(),
        artifact: execution.contract().subject.artifact.clone(),
        policy: policy.identity().clone(),
        time_basis: policy.time_basis().into(),
        frontier: execution.intent().anchor.frontier.clone(),
    }
}
#[test]
fn protected_policy_binds_runtime_requirement_and_query_without_erasing_failures() {
    for (actual, timeout) in [(false, false), (true, false), (true, true)] {
        let execution = recovered(actual, timeout);
        let configuration = serde_json::to_string(&execution.method().runtime).unwrap();
        let policy = ProtectedPythonPolicy::new(&configuration, "captured-at-host").unwrap();
        let query = query(&policy, &execution);
        assert!(policy.accepts(&query, &execution));
        let same = ProtectedPythonPolicy::new(&configuration, "captured-at-host").unwrap();
        assert_eq!(same.identity(), policy.identity());
        for fault in [
            "policy-name",
            "policy-version",
            "policy-digest",
            "requirement-name",
            "requirement-version",
            "requirement-digest",
            "time",
        ] {
            let mut changed = query.clone();
            match fault {
                "policy-name" => changed.policy.name.push('x'),
                "policy-version" => changed.policy.version.push('x'),
                "policy-digest" => changed.policy.digest.push('x'),
                "requirement-name" => changed.requirement.name.push('x'),
                "requirement-version" => changed.requirement.version.push('x'),
                "requirement-digest" => changed.requirement.digest.push('x'),
                _ => changed.time_basis.push('x'),
            }
            assert!(!policy.accepts(&changed, &execution), "{fault}");
        }
        let mut stale = query.clone();
        stale.artifact.push_str("-different");
        assert!(
            policy.accepts(&stale, &execution),
            "selection must retain stale evidence"
        );
        for fault in [
            "executable",
            "environment",
            "artifact-path",
            "artifact-digest",
        ] {
            let mut runtime = execution.method().runtime.clone();
            match fault {
                "executable" => runtime.executable.push('x'),
                "environment" => runtime.environment.push('x'),
                "artifact-path" => {
                    if let PythonEngine::Cpython3147Wasi { artifact_path, .. } = &mut runtime.engine
                    {
                        artifact_path.push('x');
                    }
                }
                _ => {
                    if let PythonEngine::Cpython3147Wasi {
                        artifact_sha256, ..
                    } = &mut runtime.engine
                    {
                        *artifact_sha256 = "b".repeat(64);
                    }
                }
            }
            let other = ProtectedPythonPolicy::new(
                &serde_json::to_string(&runtime).unwrap(),
                policy.time_basis(),
            )
            .unwrap();
            assert_ne!(other.identity(), policy.identity(), "{fault}");
            let mut changed = query.clone();
            changed.policy = other.identity().clone();
            assert!(!other.accepts(&changed, &execution), "{fault}");
        }
    }
}
#[test]
fn protected_policy_requires_supported_configuration_and_explicit_time() {
    let execution = recovered(false, false);
    let configuration = serde_json::to_string(&execution.method().runtime).unwrap();
    assert!(ProtectedPythonPolicy::new(&configuration, " ").is_err());
    assert!(ProtectedPythonPolicy::new("{}", "host-time").is_err());
    assert!(ProtectedPythonPolicy::new(
        &serde_json::to_string(&method().runtime).unwrap(),
        "host-time"
    )
    .is_err());
    let mut runtime = execution.method().runtime.clone();
    runtime.python_version = "3.14.8".into();
    assert!(
        ProtectedPythonPolicy::new(&serde_json::to_string(&runtime).unwrap(), "host-time").is_err()
    );
}
