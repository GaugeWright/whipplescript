use super::*;
use serde_json::json;

/// Test-only independent adapter records. A report cannot add a witness here.
struct Adapter {
    subject: EvidenceSubject,
    provenance: Option<ArtifactProvenance>,
    witnesses: Vec<AssertionObservation>,
    available: bool,
}
impl ReportVerifier for Adapter {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        self.available && report.subject == self.subject && report.provenance == self.provenance
    }
    fn verify_assertion_exercise(&self, _: &TestReport, obs: &AssertionObservation) -> bool {
        self.witnesses.contains(obs)
    }
}

fn fixture() -> (ReportContract, TestReport, Adapter) {
    let subject = EvidenceSubject {
        requirement: EvidenceVersion {
            name: "custody-authorization".into(),
            version: "1".into(),
            digest: "four-role-grant-proposition".into(),
        },
        method: EvidenceVersion {
            name: "authorization-adapter".into(),
            version: "1".into(),
            digest: "pinned-source-and-report-schema".into(),
        },
        artifact: "source-frontier-a0".into(),
    };
    let cases: Vec<_> = [
        ("owner-allow", true),
        ("owner-deny", true),
        ("worker-allow", true),
        ("worker-deny", false),
    ]
    .into_iter()
    .map(|(id, expected)| RequiredCase {
        id: id.into(),
        assertion: format!("authorize:{id}"),
        expected: json!(expected),
    })
    .collect();
    let observations: Vec<_> = cases
        .iter()
        .map(|c| AssertionObservation {
            case: c.id.clone(),
            assertion: c.assertion.clone(),
            actual: c.expected.clone(),
            witness: format!("execution-a0:{}", c.id),
        })
        .collect();
    let provenance = Some(ArtifactProvenance::Interpreted {
        source_frontier: "source-frontier-a0".into(),
        interpreter: "pinned-python".into(),
        environment: "pinned-environment".into(),
    });
    let contract = ReportContract {
        subject: subject.clone(),
        cases,
    };
    let report = TestReport {
        subject: subject.clone(),
        provenance: provenance.clone(),
        completion: ReportCompletion::Complete,
        termination: ProcessTermination::Success,
        observations: observations.clone(),
    };
    let adapter = Adapter {
        subject,
        provenance,
        witnesses: observations,
        available: true,
    };
    (contract, report, adapter)
}

fn failing_fixture() -> (ReportContract, TestReport, Adapter) {
    let (contract, mut report, mut adapter) = fixture();
    // The parser mutation interprets deny as allow, and the real adapter
    // records that assertion's observed value independently of the contract.
    report.observations[3].actual = json!(true);
    adapter.witnesses = report.observations.clone();
    report.termination = ProcessTermination::Failure;
    (contract, report, adapter)
}

#[test]
fn norm_evidence_requires_meaningful_complete_coverage() {
    let (contract, report, adapter) = fixture();
    let result = evaluate_report(&contract, &report, &adapter);
    assert_eq!(result.outcome, TestOutcome::Pass);
    assert_eq!(result.required.len(), 4);
    assert_eq!(result.required, result.exercised);
    assert!(result.diagnostics.is_empty());
    assert!(result.counterexamples.is_empty());

    let mut empty = contract.clone();
    empty.cases.clear();
    let mut no_observations = report.clone();
    no_observations.observations.clear();
    let empty_result = evaluate_report(&empty, &no_observations, &adapter);
    assert_eq!(empty_result.outcome, TestOutcome::HarnessFailed);
    assert!(empty_result
        .diagnostics
        .contains(&EvidenceDiagnostic::EmptyFamily));
    let zero = evaluate_report(&contract, &no_observations, &adapter);
    assert_eq!(zero.outcome, TestOutcome::HarnessFailed);
    assert_eq!(zero.exercised.len(), 0);
    let mut partial = report.clone();
    partial.observations.pop();
    let result = evaluate_report(&contract, &partial, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result
        .diagnostics
        .contains(&EvidenceDiagnostic::MissingCase("worker-deny".into())));

    let mut names_only = report.clone();
    for obs in &mut names_only.observations {
        obs.witness = "claimed-but-unobserved".into();
    }
    let result = evaluate_report(&contract, &names_only, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result.exercised.is_empty());
    assert!(result.counterexamples.is_empty());
}

#[test]
fn norm_evidence_keeps_counterexamples_when_the_harness_fails() {
    let (contract, report, adapter) = failing_fixture();
    let result = evaluate_report(&contract, &report, &adapter);
    assert_eq!(result.outcome, TestOutcome::Fail);
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.counterexamples.len(), 1);
    assert_eq!(result.counterexamples[0].case, "worker-deny");
    assert_eq!(result.counterexamples[0].expected, json!(false));
    assert_eq!(result.counterexamples[0].actual, json!(true));
    for completion in [
        ReportCompletion::Complete,
        ReportCompletion::Truncated,
        ReportCompletion::Missing,
    ] {
        for termination in [
            ProcessTermination::Success,
            ProcessTermination::Crashed,
            ProcessTermination::Unknown,
        ] {
            let mut damaged = report.clone();
            damaged.completion = completion;
            damaged.termination = termination;
            let judged = evaluate_report(&contract, &damaged, &adapter);
            assert_eq!(judged.outcome, TestOutcome::HarnessFailed);
            assert_eq!(judged.counterexamples, result.counterexamples);
            assert!(judged
                .diagnostics
                .contains(&EvidenceDiagnostic::InconsistentTermination));
        }
    }
    let mut incomplete = report.clone();
    incomplete.observations.remove(0);
    let judged = evaluate_report(&contract, &incomplete, &adapter);
    assert_eq!(judged.outcome, TestOutcome::HarnessFailed);
    assert_eq!(judged.counterexamples, result.counterexamples);
}

#[test]
fn norm_evidence_refuses_incomplete_reports_and_inconsistent_success() {
    let (contract, report, adapter) = fixture();
    for (completion, diagnostic) in [
        (ReportCompletion::Missing, EvidenceDiagnostic::MissingReport),
        (
            ReportCompletion::Truncated,
            EvidenceDiagnostic::TruncatedReport,
        ),
    ] {
        let mut changed = report.clone();
        changed.completion = completion;
        let judged = evaluate_report(&contract, &changed, &adapter);
        assert_eq!(judged.outcome, TestOutcome::HarnessFailed);
        assert!(judged.diagnostics.contains(&diagnostic));
        assert!(judged.counterexamples.is_empty());
    }
    for termination in [
        ProcessTermination::Failure,
        ProcessTermination::Crashed,
        ProcessTermination::Unknown,
    ] {
        let mut changed = report.clone();
        changed.termination = termination;
        let judged = evaluate_report(&contract, &changed, &adapter);
        assert_eq!(judged.outcome, TestOutcome::HarnessFailed);
        assert!(judged.counterexamples.is_empty());
    }
}

#[test]
fn norm_evidence_pins_all_identities_and_independent_provenance() {
    let (contract, report, mut adapter) = failing_fixture();
    let mut subjects = Vec::new();
    for which in 0..7 {
        let mut subject = report.subject.clone();
        match which {
            0 => subject.requirement.name.push_str("-other"),
            1 => subject.requirement.version.push('2'),
            2 => subject.requirement.digest.push_str("-other"),
            3 => subject.method.name.push_str("-other"),
            4 => subject.method.version.push('2'),
            5 => subject.method.digest.push_str("-other"),
            _ => subject.artifact.push_str("-other"),
        }
        subjects.push(subject);
    }
    for subject in subjects {
        let mut changed = report.clone();
        changed.subject = subject.clone();
        adapter.subject = subject;
        // Validly bound evidence of a DIFFERENT premise cannot satisfy this one.
        let result = evaluate_report(&contract, &changed, &adapter);
        assert_eq!(result.outcome, TestOutcome::HarnessFailed);
        assert!(result.counterexamples.is_empty());
        assert!(result.exercised.is_empty());
    }
    adapter.subject = report.subject.clone();
    adapter.available = false;
    let result = evaluate_report(&contract, &report, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result.counterexamples.is_empty());
    adapter.available = true;
    let mut missing = report.clone();
    missing.provenance = None;
    adapter.provenance = None;
    let result = evaluate_report(&contract, &missing, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result.counterexamples.is_empty());
}

#[test]
fn norm_evidence_cached_build_provenance_does_not_require_source_reads() {
    let (contract, mut report, mut adapter) = fixture();
    report.provenance = Some(ArtifactProvenance::Built {
        source_frontier: contract.subject.artifact.clone(),
        build: "cached-build-with-source-correspondence".into(),
        toolchain: "pinned-toolchain".into(),
        environment: "pinned-environment".into(),
    });
    adapter.provenance = report.provenance.clone();
    assert_eq!(
        evaluate_report(&contract, &report, &adapter).outcome,
        TestOutcome::Pass
    );
    report.provenance = None;
    assert_eq!(
        evaluate_report(&contract, &report, &adapter).outcome,
        TestOutcome::HarnessFailed
    );
}

#[test]
fn norm_evidence_ambiguous_or_forged_cases_cannot_supply_coverage() {
    let (contract, report, mut adapter) = failing_fixture();
    let mut duplicate = contract.clone();
    duplicate.cases.push(contract.cases[3].clone());
    let result = evaluate_report(&duplicate, &report, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result.counterexamples.is_empty());
    let mut unknown = report.clone();
    unknown.observations[3].case = "outside-domain".into();
    adapter.witnesses = unknown.observations.clone();
    let result = evaluate_report(&contract, &unknown, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result.counterexamples.is_empty());
    let mut wrong_assertion = report.clone();
    wrong_assertion.observations[3].assertion = "unrelated-assertion".into();
    adapter.witnesses = wrong_assertion.observations.clone();
    let result = evaluate_report(&contract, &wrong_assertion, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result.counterexamples.is_empty());
    adapter.witnesses = report.observations.clone();
    let mut repeated = report.clone();
    repeated.observations.push(report.observations[0].clone());
    let result = evaluate_report(&contract, &repeated, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert_eq!(result.counterexamples.len(), 1);
    let mut forged = report.clone();
    forged.observations[3].witness.clear();
    adapter.witnesses = forged.observations.clone();
    let result = evaluate_report(&contract, &forged, &adapter);
    assert_eq!(result.outcome, TestOutcome::HarnessFailed);
    assert!(result.counterexamples.is_empty());
}

#[test]
fn norm_evidence_blank_contract_identity_cannot_certify_or_refute() {
    let (contract, report, _) = failing_fixture();
    for which in 0..7 {
        let mut contract = contract.clone();
        let mut report = report.clone();
        match which {
            0 => contract.subject.artifact = " ".into(),
            1 => contract.subject.requirement.name.clear(),
            2 => contract.subject.requirement.version.clear(),
            3 => contract.subject.requirement.digest.clear(),
            4 => contract.subject.method.name.clear(),
            5 => contract.subject.method.version.clear(),
            _ => contract.subject.method.digest.clear(),
        }
        report.subject = contract.subject.clone();
        let adapter = Adapter {
            subject: report.subject.clone(),
            provenance: report.provenance.clone(),
            witnesses: report.observations.clone(),
            available: true,
        };
        let result = evaluate_report(&contract, &report, &adapter);
        assert_eq!(result.outcome, TestOutcome::HarnessFailed);
        assert!(result.counterexamples.is_empty());
    }
    for which in 0..2 {
        let mut contract = contract.clone();
        let mut report = report.clone();
        if which == 0 {
            contract.cases[3].id.clear();
            report.observations[3].case.clear();
        } else {
            contract.cases[3].assertion.clear();
            report.observations[3].assertion.clear();
        }
        let adapter = Adapter {
            subject: report.subject.clone(),
            provenance: report.provenance.clone(),
            witnesses: report.observations.clone(),
            available: true,
        };
        let result = evaluate_report(&contract, &report, &adapter);
        assert_eq!(result.outcome, TestOutcome::HarnessFailed);
        assert!(result.counterexamples.is_empty());
    }
}

#[test]
fn norm_evidence_finite_proof_requires_nonempty_universal_support() {
    let model = BTreeMap::from([("good".into(), true), ("bad".into(), false)]);
    let good = BTreeSet::from(["good".into()]);
    let bad = BTreeSet::from(["bad".into()]);
    let universe = BTreeSet::from(["good".into(), "bad".into()]);
    let proved = evaluate_finite_proof(&model, &[good.clone(), universe.clone()]);
    assert!(proved.established);
    assert_eq!(proved.admitted_interpretations, good);
    let mixed = evaluate_finite_proof(&model, &[]);
    assert!(!mixed.established);
    assert_eq!(mixed.countermodels, bad);
    let inconsistent = evaluate_finite_proof(&model, &[good.clone(), bad]);
    assert!(!inconsistent.established);
    assert!(inconsistent.admitted_interpretations.is_empty());
    assert!(!evaluate_finite_proof(&BTreeMap::new(), &[]).established);
    let empty = evaluate_finite_proof(&model, &[BTreeSet::new()]);
    assert!(!empty.established);
    let unknown =
        evaluate_finite_proof(&model, &[BTreeSet::from(["good".into(), "unknown".into()])]);
    assert!(!unknown.established);
    assert_eq!(
        unknown.unknown_interpretations,
        BTreeSet::from(["unknown".into()])
    );
    assert_eq!(unknown.admitted_interpretations, good);
}
