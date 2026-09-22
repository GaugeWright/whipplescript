//! The executor against a real Buck2 over the fixture project (admission
//! fixtures BE-02). Ignored by default: it needs `buck2` on the PATH and is
//! run by the bar's `buck2-test-executor` section, which names the remedy
//! when the host has no Buck2.

use std::path::{Path, PathBuf};
use std::process::Command;

use whipplescript_core::norm_buck2_report::{
    Buck2TestReport, CaseStatus, Listing, BUCK2_TEST_SUPPORT_PROTOCOL,
};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("buck2-tests")
        .canonicalize()
        .expect("the fixture project")
}

fn buck2(isolation: &Path, project: &Path) -> Command {
    let mut command = Command::new("buck2");
    command
        .arg("--isolation-dir")
        .arg(isolation.file_name().expect("an isolation dir name"))
        .current_dir(project)
        // The daemon this test starts speaks the TCP launch to its executor.
        .env("BUCK2_TEST_TPX_USE_TCP", "1");
    command
}

#[test]
#[ignore = "needs buck2 on the PATH; the bar's buck2-test-executor section runs it"]
fn buck2_runs_the_fixture_through_the_executor_and_the_report_says_what_it_saw() {
    let project = fixture();
    let executor = env!("CARGO_BIN_EXE_whip-test-executor");
    let scratch = tempfile::tempdir().expect("a scratch directory");
    let report_path = scratch.path().join("report.json");
    let isolation = scratch.path().join("whip-test-executor-fixture");
    let output = buck2(&isolation, &project)
        .arg("test")
        .arg("//...")
        .arg("-c")
        .arg(format!("test.v2_test_executor={executor}"))
        .arg("--")
        .arg("--report")
        .arg(&report_path)
        .arg("--cut")
        .arg("cut-fixture")
        .arg("--timeout")
        .arg("60")
        .output()
        .expect("buck2 runs");
    let _ = buck2(&isolation, &project).arg("kill").output();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Buck2TestReport =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap_or_else(|error| {
            panic!("no report: {error}\nstdout:\n{stdout}\nstderr:\n{stderr}")
        }))
        .expect("the report parses");
    assert_eq!(report.protocol, BUCK2_TEST_SUPPORT_PROTOCOL);
    assert_eq!(report.cut.as_deref(), Some("cut-fixture"));
    // The run as a whole failed, and Buck2 says so.
    assert!(
        !output.status.success(),
        "buck2 test reported success:\n{stdout}\n{stderr}"
    );
    assert_eq!(report.exit_code, 32);
    let suite = |name: &str| {
        report
            .suites
            .iter()
            .find(|suite| suite.target.target == name)
            .unwrap_or_else(|| panic!("suite {name} in {report:?}"))
    };
    let passing = suite("passing");
    assert_eq!(passing.test_type, "whip");
    assert!(
        matches!(&passing.listing, Listing::Listed { cases, .. } if cases == &["parses_empty", "parses_nested"]),
        "{:?}",
        passing.listing
    );
    assert_eq!(passing.executions.len(), 2);
    assert!(passing
        .executions
        .iter()
        .all(|execution| execution.status == CaseStatus::Pass && execution.verdict_line));
    let swallowed = suite("swallowed");
    let stale = swallowed
        .executions
        .iter()
        .find(|execution| execution.case == "rejects_stale_grant")
        .expect("the swallowed case ran");
    assert_eq!(stale.status, CaseStatus::Fail);
    assert!(stale.verdict_line);
    assert_eq!(
        stale.exit_code,
        Some(0),
        "the wrapper exited 0 and the verdict still says fail"
    );
    let silent = suite("silent");
    assert_eq!(silent.executions.len(), 1);
    assert_eq!(silent.executions[0].status, CaseStatus::Unknown);
    assert!(!silent.executions[0].verdict_line);
    // Every execution names how Buck2 ran it and what it read.
    for suite in &report.suites {
        for execution in &suite.executions {
            assert_eq!(execution.stdout_sha256.len(), 64);
            assert_ne!(
                execution.execution_kind,
                whipplescript_core::norm_buck2_report::ExecutionKind::Unknown,
                "{execution:?}"
            );
        }
    }
    // Buck2's own output carries each case as its own result.
    assert!(
        stderr.contains("rejects_stale_grant") || stdout.contains("rejects_stale_grant"),
        "Buck2 did not print the per-case result:\n{stdout}\n{stderr}"
    );
}
