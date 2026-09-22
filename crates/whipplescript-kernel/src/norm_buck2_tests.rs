//! The norm plane's adapter for the Buck2 test executor's report (DR-0124
//! §14.5): a peer of the Python-call adapter, turning
//! `whipplescript.norm.buck2-test-support/v1` into the `TestReport` that
//! `norm_evidence::evaluate_report` judges.
//!
//! The executor reports what it observed; this adapter decides nothing it did
//! not. A case's verdict line is its actual value. A case the executor ran
//! without a verdict line is not exercised, so the report is truncated and
//! the judgment is a harness failure that names the case; a suite whose
//! listing failed or whose test type has no adapter is the same. A case that
//! printed `fail` while its process exited 0 is a counterexample, and the
//! termination it implies is failure, so the swallowed failure never becomes
//! a pass. A report that is not there is missing.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use whipplescript_core::norm_buck2_report::{
    Buck2TestReport, CaseStatus, Listing, SuiteReport, BUCK2_TEST_SUPPORT_PROTOCOL,
};
use whipplescript_core::norm_evidence::{
    evaluate_report, ArtifactProvenance, AssertionObservation, ProcessTermination,
    ReportCompletion, ReportContract, ReportVerifier, TestJudgment, TestReport,
};

use crate::exec_http::sha256_hex;

/// The assertion every Buck2 case makes: its verdict.
pub const VERDICT_ASSERTION: &str = "verdict";

/// The case id the contract names for one case of one suite.
pub fn case_id(suite: &SuiteReport, case: &str) -> String {
    format!("{}::{case}", suite.target.label())
}

/// The build the report was produced against: the pinned Buck2 the wrapper
/// ran, and the toolchain it pinned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Buck2Build {
    pub buck2_version: String,
    pub toolchain: String,
    pub environment: String,
}

/// Turn the executor's report into the evidence report for `contract`.
/// `report` is `None` when the executor left no report at all.
pub fn test_report(
    contract: &ReportContract,
    build: &Buck2Build,
    report: Option<&Buck2TestReport>,
) -> TestReport {
    let subject = contract.subject.clone();
    let Some(report) = report else {
        return TestReport {
            subject,
            provenance: None,
            completion: ReportCompletion::Missing,
            termination: ProcessTermination::Unknown,
            observations: Vec::new(),
        };
    };
    let bound = report.protocol == BUCK2_TEST_SUPPORT_PROTOCOL
        && report.cut.as_deref() == Some(contract.subject.artifact.as_str());
    let mut observations = Vec::new();
    let mut truncated = false;
    let mut failed = false;
    let mut crashed = false;
    for suite in &report.suites {
        match &suite.listing {
            Listing::Listed { .. } => {}
            Listing::ListingFailed { .. } | Listing::MissingAdapter { .. } => truncated = true,
        }
        for execution in &suite.executions {
            match execution.status {
                CaseStatus::Pass | CaseStatus::Fail if execution.verdict_line => {
                    let actual = json!(match execution.status {
                        CaseStatus::Pass => "pass",
                        _ => "fail",
                    });
                    if execution.status == CaseStatus::Fail {
                        failed = true;
                    }
                    let witness = sha256_hex(
                        json!([
                            BUCK2_TEST_SUPPORT_PROTOCOL,
                            report.cut,
                            suite.target.label(),
                            suite.target.configuration,
                            execution.case,
                            execution.start_time_ms,
                            execution.stdout_sha256,
                            execution.stderr_sha256,
                        ])
                        .to_string()
                        .as_bytes(),
                    );
                    observations.push(AssertionObservation {
                        case: case_id(suite, &execution.case),
                        assertion: VERDICT_ASSERTION.into(),
                        actual,
                        witness,
                    });
                }
                // An exit status without a verdict line is not an exercise of
                // the case; the report is truncated at that case.
                CaseStatus::Pass | CaseStatus::Fail | CaseStatus::Unknown => truncated = true,
                CaseStatus::Timeout | CaseStatus::Omitted => {
                    truncated = true;
                    crashed = true;
                }
            }
            if execution.exit_code.is_some_and(|code| code < 0) {
                crashed = true;
            }
        }
    }
    let completion = if truncated {
        ReportCompletion::Truncated
    } else {
        ReportCompletion::Complete
    };
    let termination = if crashed {
        ProcessTermination::Crashed
    } else if failed {
        ProcessTermination::Failure
    } else if truncated {
        ProcessTermination::Unknown
    } else {
        ProcessTermination::Success
    };
    TestReport {
        subject,
        provenance: bound.then(|| ArtifactProvenance::Built {
            source_frontier: contract.subject.artifact.clone(),
            build: format!("buck2 {}", build.buck2_version),
            toolchain: build.toolchain.clone(),
            environment: build.environment.clone(),
        }),
        completion,
        termination,
        observations,
    }
}

struct BoundReport<'a> {
    report: &'a TestReport,
    bound: bool,
}

impl ReportVerifier for BoundReport<'_> {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        self.bound && report == self.report
    }
    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        report == self.report && report.observations.contains(observation)
    }
}

/// Judge the executor's report against the contract.
pub fn judge(
    contract: &ReportContract,
    build: &Buck2Build,
    report: Option<&Buck2TestReport>,
) -> TestJudgment {
    let test_report = test_report(contract, build, report);
    let verifier = BoundReport {
        report: &test_report,
        bound: test_report.provenance.is_some(),
    };
    evaluate_report(contract, &test_report, &verifier)
}

/// The contract's required case ids, for a caller checking coverage.
pub fn required_cases(contract: &ReportContract) -> BTreeSet<String> {
    contract.cases.iter().map(|case| case.id.clone()).collect()
}

pub fn expected_pass() -> Value {
    json!("pass")
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_core::norm_buck2_report::{CaseExecution, ExecutionKind, SuiteTarget};
    use whipplescript_core::norm_evidence::{
        EvidenceDiagnostic, EvidenceSubject, EvidenceVersion, RequiredCase, TestOutcome,
    };

    fn version(name: &str) -> EvidenceVersion {
        EvidenceVersion {
            name: name.into(),
            version: "1".into(),
            digest: sha256_hex(name.as_bytes()),
        }
    }

    fn contract(cases: &[&str]) -> ReportContract {
        ReportContract {
            subject: EvidenceSubject {
                requirement: version("parses"),
                method: version(BUCK2_TEST_SUPPORT_PROTOCOL),
                artifact: "cut-a0".into(),
            },
            cases: cases
                .iter()
                .map(|id| RequiredCase {
                    id: (*id).into(),
                    assertion: VERDICT_ASSERTION.into(),
                    expected: expected_pass(),
                })
                .collect(),
        }
    }

    fn build() -> Buck2Build {
        Buck2Build {
            buck2_version: "2026-09-15".into(),
            toolchain: "sh".into(),
            environment: "fixture".into(),
        }
    }

    fn execution(
        case: &str,
        status: CaseStatus,
        exit_code: Option<i32>,
        verdict_line: bool,
    ) -> CaseExecution {
        CaseExecution {
            case: case.into(),
            status,
            exit_code,
            verdict_line,
            start_time_ms: 10,
            duration_ms: 5,
            execution_kind: ExecutionKind::Local,
            stdout_sha256: sha256_hex(case.as_bytes()),
            stderr_sha256: sha256_hex(b""),
            max_memory_used_bytes: None,
        }
    }

    fn suite(name: &str, listing: Listing, executions: Vec<CaseExecution>) -> SuiteReport {
        SuiteReport {
            target: SuiteTarget {
                cell: "root".into(),
                package: "".into(),
                target: name.into(),
                configuration: "cfg".into(),
            },
            test_type: "whip".into(),
            labels: Vec::new(),
            listing,
            executions,
        }
    }

    fn report(suites: Vec<SuiteReport>) -> Buck2TestReport {
        Buck2TestReport {
            protocol: BUCK2_TEST_SUPPORT_PROTOCOL.into(),
            cut: Some("cut-a0".into()),
            executor_user: None,
            trace_id: None,
            config_entries: Vec::new(),
            suites,
            exit_code: 0,
        }
    }

    fn listed(cases: &[&str]) -> Listing {
        Listing::Listed {
            cases: cases.iter().map(|c| (*c).into()).collect(),
            cacheable: true,
        }
    }

    #[test]
    fn a_complete_report_with_every_case_passing_is_tested_support() {
        let judgment = judge(
            &contract(&["root//:passing::a", "root//:passing::b"]),
            &build(),
            Some(&report(vec![suite(
                "passing",
                listed(&["a", "b"]),
                vec![
                    execution("a", CaseStatus::Pass, Some(0), true),
                    execution("b", CaseStatus::Pass, Some(0), true),
                ],
            )])),
        );
        assert_eq!(judgment.outcome, TestOutcome::Pass, "{judgment:?}");
        assert_eq!(judgment.exercised.len(), 2);
        assert!(judgment.diagnostics.is_empty());
    }

    #[test]
    fn a_swallowed_failure_is_retained_as_counterevidence() {
        let judgment = judge(
            &contract(&["root//:swallowed::a", "root//:swallowed::b"]),
            &build(),
            Some(&report(vec![suite(
                "swallowed",
                listed(&["a", "b"]),
                vec![
                    execution("a", CaseStatus::Pass, Some(0), true),
                    // The verdict says fail; the process exited 0.
                    execution("b", CaseStatus::Fail, Some(0), true),
                ],
            )])),
        );
        assert_eq!(judgment.outcome, TestOutcome::Fail, "{judgment:?}");
        assert_eq!(judgment.counterexamples.len(), 1);
        assert_eq!(judgment.counterexamples[0].case, "root//:swallowed::b");
        assert_eq!(judgment.counterexamples[0].actual, json!("fail"));
        assert!(
            judgment.diagnostics.is_empty(),
            "{:?}",
            judgment.diagnostics
        );
    }

    #[test]
    fn a_case_without_a_verdict_and_a_missing_report_are_named_harness_failures() {
        let silent = judge(
            &contract(&["root//:silent::a"]),
            &build(),
            Some(&report(vec![suite(
                "silent",
                listed(&["a"]),
                vec![execution("a", CaseStatus::Unknown, Some(0), false)],
            )])),
        );
        assert_eq!(silent.outcome, TestOutcome::HarnessFailed);
        assert!(silent
            .diagnostics
            .contains(&EvidenceDiagnostic::MissingCase("root//:silent::a".into())));
        assert!(silent
            .diagnostics
            .contains(&EvidenceDiagnostic::TruncatedReport));
        assert!(silent.exercised.is_empty());

        let missing = judge(&contract(&["root//:silent::a"]), &build(), None);
        assert_eq!(missing.outcome, TestOutcome::HarnessFailed);
        assert!(missing
            .diagnostics
            .contains(&EvidenceDiagnostic::MissingReport));
        assert!(missing
            .diagnostics
            .contains(&EvidenceDiagnostic::MissingProvenance));

        // No adapter for the test type: the suite ran once and no case is exercised.
        let unadapted = judge(
            &contract(&["root//:other::a"]),
            &build(),
            Some(&report(vec![suite(
                "other",
                Listing::MissingAdapter {
                    test_type: "rust".into(),
                },
                vec![execution("root//:other", CaseStatus::Pass, Some(0), false)],
            )])),
        );
        assert_eq!(unadapted.outcome, TestOutcome::HarnessFailed);
        assert!(unadapted
            .diagnostics
            .contains(&EvidenceDiagnostic::TruncatedReport));
    }

    #[test]
    fn a_report_for_another_cut_is_unbound() {
        let mut other = report(vec![suite(
            "passing",
            listed(&["a"]),
            vec![execution("a", CaseStatus::Pass, Some(0), true)],
        )]);
        other.cut = Some("cut-b1".into());
        let judgment = judge(&contract(&["root//:passing::a"]), &build(), Some(&other));
        assert_eq!(judgment.outcome, TestOutcome::HarnessFailed);
        assert!(judgment
            .diagnostics
            .contains(&EvidenceDiagnostic::UnboundReport));
        assert!(judgment
            .diagnostics
            .contains(&EvidenceDiagnostic::MissingProvenance));
    }
}
