//! Pure report adequacy and bounded proof evaluation (DR-0098, N1).
//!
//! This module consumes an independently trusted adapter verifier. Neither a
//! self-reported case name nor a signature alone establishes assertion exercise.
//! It performs no ledger admission, evidence selection, reuse, or workflow effects.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceVersion {
    pub name: String,
    pub version: String,
    /// Commits to the complete meaning, including proposition/domain or adapter.
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSubject {
    pub requirement: EvidenceVersion,
    pub method: EvidenceVersion,
    pub artifact: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredCase {
    pub id: String,
    pub assertion: String,
    pub expected: Value,
}

/// Installed under the requirement's authority, not taken from a run's report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportContract {
    pub subject: EvidenceSubject,
    pub cases: Vec<RequiredCase>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactProvenance {
    Interpreted {
        source_frontier: String,
        interpreter: String,
        environment: String,
    },
    Built {
        source_frontier: String,
        build: String,
        toolchain: String,
        environment: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportCompletion {
    Complete,
    Truncated,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessTermination {
    Success,
    Failure,
    Crashed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssertionObservation {
    pub case: String,
    pub assertion: String,
    pub actual: Value,
    /// Identity of the adapter's exercise witness, not just a case label.
    pub witness: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestReport {
    pub subject: EvidenceSubject,
    pub provenance: Option<ArtifactProvenance>,
    pub completion: ReportCompletion,
    pub termination: ProcessTermination,
    pub observations: Vec<AssertionObservation>,
}

/// A host-owned adapter boundary, never configured by the report itself.
///
/// The first operation binds the entire report to a real run of the named
/// method/artifact and validates its build/interpreter provenance and termination
/// observation. The second validates that the named assertion actually executed
/// and produced the claimed value. An adapter must not implement these by merely
/// trusting a report's flags or counting names. Neither operation establishes
/// a dependency closure for reusing evidence on another artifact.
pub trait ReportVerifier {
    fn verify_report_binding(&self, report: &TestReport) -> bool;
    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum EvidenceDiagnostic {
    InvalidIdentity,
    EmptyFamily,
    InvalidCase(String),
    DuplicateRequiredCase(String),
    RequirementMismatch,
    MethodMismatch,
    ArtifactMismatch,
    MissingProvenance,
    UnboundReport,
    MissingReport,
    TruncatedReport,
    UnknownCase(String),
    DuplicateObservation(String),
    AssertionMismatch(String),
    UnverifiedExercise(String),
    MissingCase(String),
    InconsistentTermination,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counterexample {
    pub case: String,
    pub witness: String,
    pub expected: Value,
    pub actual: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestOutcome {
    Pass,
    Fail,
    HarnessFailed,
}

/// Tested support only. Even Pass is not an admission certificate or proof mode.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestJudgment {
    pub subject: EvidenceSubject,
    pub reported_subject: EvidenceSubject,
    pub outcome: TestOutcome,
    pub required: BTreeSet<String>,
    pub exercised: BTreeSet<String>,
    pub counterexamples: Vec<Counterexample>,
    pub diagnostics: BTreeSet<EvidenceDiagnostic>,
}

fn nonempty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn valid_subject(subject: &EvidenceSubject) -> bool {
    nonempty(&subject.artifact)
        && [&subject.requirement, &subject.method]
            .into_iter()
            .all(|v| nonempty(&v.name) && nonempty(&v.version) && nonempty(&v.digest))
}

/// Evaluate one report against its independently installed contract. Missing or
/// malformed coverage blocks positive support without deleting valid failures.
pub fn evaluate_report(
    contract: &ReportContract,
    report: &TestReport,
    verifier: &dyn ReportVerifier,
) -> TestJudgment {
    use EvidenceDiagnostic as D;
    let mut diagnostics = BTreeSet::new();
    let identities_valid = valid_subject(&contract.subject) && valid_subject(&report.subject);
    if !identities_valid {
        diagnostics.insert(D::InvalidIdentity);
    }
    if contract.cases.is_empty() {
        diagnostics.insert(D::EmptyFamily);
    }
    let mut cases = BTreeMap::new();
    let mut ambiguous = BTreeSet::new();
    for case in &contract.cases {
        if !nonempty(&case.id) || !nonempty(&case.assertion) {
            diagnostics.insert(D::InvalidCase(case.id.clone()));
            ambiguous.insert(case.id.clone());
        }
        let repeated = cases.insert(case.id.clone(), case).is_some();
        if repeated {
            diagnostics.insert(D::DuplicateRequiredCase(case.id.clone()));
            ambiguous.insert(case.id.clone());
        }
    }
    let requirement_matches = contract.subject.requirement == report.subject.requirement;
    let method_matches = contract.subject.method == report.subject.method;
    let artifact_matches = contract.subject.artifact == report.subject.artifact;
    if !requirement_matches {
        diagnostics.insert(D::RequirementMismatch);
    }
    if !method_matches {
        diagnostics.insert(D::MethodMismatch);
    }
    if !artifact_matches {
        diagnostics.insert(D::ArtifactMismatch);
    }
    let has_provenance = report.provenance.is_some();
    if !has_provenance {
        diagnostics.insert(D::MissingProvenance);
    }
    let authenticated = verifier.verify_report_binding(report);
    if !authenticated {
        diagnostics.insert(D::UnboundReport);
    }
    let bound = identities_valid
        && requirement_matches
        && method_matches
        && artifact_matches
        && has_provenance
        && authenticated;
    match report.completion {
        ReportCompletion::Complete => {}
        ReportCompletion::Truncated => {
            diagnostics.insert(D::TruncatedReport);
        }
        ReportCompletion::Missing => {
            diagnostics.insert(D::MissingReport);
        }
    }
    let mut seen = BTreeSet::new();
    let mut exercised = BTreeSet::new();
    let mut counterexamples = Vec::new();
    for observation in &report.observations {
        let repeated_observation = !seen.insert(&observation.case);
        if repeated_observation {
            diagnostics.insert(D::DuplicateObservation(observation.case.clone()));
        }
        let Some(case) = cases.get(&observation.case) else {
            diagnostics.insert(D::UnknownCase(observation.case.clone()));
            continue;
        };
        let assertion_matches = case.assertion == observation.assertion;
        if !assertion_matches {
            diagnostics.insert(D::AssertionMismatch(observation.case.clone()));
        }
        let verified = nonempty(&observation.witness)
            && verifier.verify_assertion_exercise(report, observation);
        if !verified {
            diagnostics.insert(D::UnverifiedExercise(observation.case.clone()));
        }
        if bound && assertion_matches && verified && !ambiguous.contains(&observation.case) {
            exercised.insert(observation.case.clone());
            if observation.actual != case.expected {
                counterexamples.push(Counterexample {
                    case: observation.case.clone(),
                    witness: observation.witness.clone(),
                    expected: case.expected.clone(),
                    actual: observation.actual.clone(),
                });
            }
        }
    }
    let required: BTreeSet<_> = cases.keys().cloned().collect();
    for case in required.difference(&exercised) {
        diagnostics.insert(D::MissingCase(case.clone()));
    }
    // Evaluate termination independently: a swallowed failure never becomes pass.
    let consistent = match report.termination {
        ProcessTermination::Success => counterexamples.is_empty(),
        ProcessTermination::Failure => !counterexamples.is_empty(),
        ProcessTermination::Crashed | ProcessTermination::Unknown => false,
    };
    if !consistent {
        diagnostics.insert(D::InconsistentTermination);
    }
    let outcome = if !diagnostics.is_empty() {
        // MUTATION-SUCCESS: TestOutcome::Pass
        TestOutcome::HarnessFailed
    } else if counterexamples.is_empty() {
        TestOutcome::Pass
    } else {
        TestOutcome::Fail
    };
    TestJudgment {
        subject: contract.subject.clone(),
        reported_subject: report.subject.clone(),
        outcome,
        required,
        exercised,
        counterexamples,
        diagnostics,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FiniteProofJudgment {
    pub admitted_interpretations: BTreeSet<String>,
    pub countermodels: BTreeSet<String>,
    pub unknown_interpretations: BTreeSet<String>,
    pub established: bool,
}

/// Evaluate a supplied finite model's proposition table under intersected
/// premises. The table's truth assignments and completeness are assumptions of
/// this bounded result, not discovered facts or a general-purpose proof solver.
pub fn evaluate_finite_proof(
    proposition: &BTreeMap<String, bool>,
    premises: &[BTreeSet<String>],
) -> FiniteProofJudgment {
    let universe: BTreeSet<_> = proposition.keys().cloned().collect();
    let mut admitted = universe.clone();
    let mut unknown = BTreeSet::new();
    for premise in premises {
        unknown.extend(premise.difference(&universe).cloned());
        admitted = admitted.intersection(premise).cloned().collect();
    }
    let countermodels: BTreeSet<_> = admitted
        .iter()
        .filter(|world| !proposition[*world])
        .cloned()
        .collect();
    let established = !admitted.is_empty() && unknown.is_empty() && countermodels.is_empty();
    FiniteProofJudgment {
        admitted_interpretations: admitted,
        countermodels,
        unknown_interpretations: unknown,
        established,
    }
}

#[cfg(test)]
#[path = "norm_evidence_tests.rs"]
mod tests;
