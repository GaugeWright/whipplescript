//! Deterministic preservation under an independently verified observation basis.
//! This compares premises; it does not discover dependencies or create evidence.
use crate::norm_evidence::EvidenceVersion;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreservationContext {
    pub requirement: EvidenceVersion,
    pub method: EvidenceVersion,
    pub policy: EvidenceVersion,
    pub source_artifact: String,
    pub target_artifact: String,
    pub boundary: EvidenceVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationAspect {
    Content,
    Metadata,
    Presence,
    Membership,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationKey {
    pub resource: String,
    pub aspect: ObservationAspect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "digest",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObservationValue {
    Absent,
    Present(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyObservation {
    pub key: ObservationKey,
    pub value: ObservationValue,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationBasis {
    CompleteExact,
    EnforcedCeiling,
    PartialTrace,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationMode {
    Deterministic,
    Sampled,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreservationWitness {
    pub id: String,
    pub context: PreservationContext,
    pub basis: PreservationBasis,
    pub mode: PreservationMode,
    pub source: Vec<DependencyObservation>,
    pub target: Vec<DependencyObservation>,
    pub gaps: BTreeSet<String>,
}

/// Host-owned verification of the complete witness: authentic observations at
/// both artifacts, complete boundary/ceiling, and valid method assumptions.
/// An enum value, signature alone, or equality of a declared path set is not
/// enough. The current Python adapter cannot supply this verification.
pub trait PreservationVerifier {
    fn verify_preservation_basis(&self, witness: &PreservationWitness) -> bool;
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum PreservationDiagnostic {
    InvalidIdentity,
    ContextMismatch,
    UnverifiedBasis,
    IncompleteBasis,
    Nondeterministic,
    Gap(String),
    InvalidObservation(ObservationKey),
    DuplicateSource(ObservationKey),
    DuplicateTarget(ObservationKey),
    MissingTarget(ObservationKey),
    UnexpectedTarget(ObservationKey),
    Changed(ObservationKey),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PreservationJudgment {
    pub context: PreservationContext,
    pub witness: String,
    pub preserved: bool,
    pub diagnostics: BTreeSet<PreservationDiagnostic>,
}
fn named(v: &EvidenceVersion) -> bool {
    [&v.name, &v.version, &v.digest]
        .iter()
        .all(|s| !s.trim().is_empty())
}
fn valid_context(c: &PreservationContext) -> bool {
    [&c.requirement, &c.method, &c.policy, &c.boundary]
        .iter()
        .all(|v| named(v))
        && !c.source_artifact.trim().is_empty()
        && !c.target_artifact.trim().is_empty()
}
fn observations<'a>(
    items: &'a [DependencyObservation],
    source: bool,
    diagnostics: &mut BTreeSet<PreservationDiagnostic>,
) -> BTreeMap<ObservationKey, &'a ObservationValue> {
    let mut map = BTreeMap::new();
    for item in items {
        let valid = !item.key.resource.trim().is_empty()
            && !matches!(&item.value, ObservationValue::Present(digest) if digest.trim().is_empty());
        if !valid {
            diagnostics.insert(PreservationDiagnostic::InvalidObservation(item.key.clone()));
        }
        if map.insert(item.key.clone(), &item.value).is_some() {
            diagnostics.insert(if source {
                PreservationDiagnostic::DuplicateSource(item.key.clone())
            } else {
                PreservationDiagnostic::DuplicateTarget(item.key.clone())
            });
        }
    }
    map
}

/// No support-mode upgrade: this only establishes preservation of a previously
/// supported judgment. Report adequacy and temporal/statistical policy are separate.
pub fn evaluate_preservation(
    expected: &PreservationContext,
    witness: &PreservationWitness,
    verifier: &dyn PreservationVerifier,
) -> PreservationJudgment {
    use PreservationDiagnostic as D;
    let mut diagnostics = BTreeSet::new();
    if !valid_context(expected) || !valid_context(&witness.context) || witness.id.trim().is_empty()
    {
        diagnostics.insert(D::InvalidIdentity);
    }
    if &witness.context != expected {
        diagnostics.insert(D::ContextMismatch);
    }
    if !verifier.verify_preservation_basis(witness) {
        diagnostics.insert(D::UnverifiedBasis);
    }
    if !matches!(
        witness.basis,
        PreservationBasis::CompleteExact | PreservationBasis::EnforcedCeiling
    ) {
        diagnostics.insert(D::IncompleteBasis);
    }
    if witness.mode != PreservationMode::Deterministic {
        diagnostics.insert(D::Nondeterministic);
    }
    diagnostics.extend(witness.gaps.iter().cloned().map(D::Gap));
    let source = observations(&witness.source, true, &mut diagnostics);
    let target = observations(&witness.target, false, &mut diagnostics);
    for (key, value) in &source {
        match target.get(key) {
            None => {
                diagnostics.insert(D::MissingTarget(key.clone()));
            }
            Some(current) if current != value => {
                diagnostics.insert(D::Changed(key.clone()));
            }
            _ => {}
        }
    }
    for key in target.keys().filter(|key| !source.contains_key(*key)) {
        diagnostics.insert(D::UnexpectedTarget(key.clone()));
    }
    PreservationJudgment {
        context: expected.clone(),
        witness: witness.id.clone(),
        preserved: diagnostics.is_empty(),
        diagnostics,
    }
}

#[cfg(test)]
#[path = "norm_preservation_tests.rs"]
mod tests;
