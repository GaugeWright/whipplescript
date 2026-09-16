//! Complete pure impact planning. No job execution or ref admission authority.
use crate::norm_projection::{EvidenceProjection, ExecutionSelectionPolicy, ProjectionGap};
use crate::norm_runner::candidate_identity;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_core::norm_selection::{
    select_evidence, Conformance, EvidenceSelection, SelectionEvent, SelectionQuery,
    SelectionVerifier,
};
use whipplescript_store::norm::NormView;
use whipplescript_store::norm_artifact::CapturedArtifact;
use whipplescript_store::norm_inventory::InventoryRequirement;
use whipplescript_store::norm_resources::{
    compare_resources, ResourceInventory, ResourceInventoryPair, ResourceLimits,
};
use whipplescript_store::{StoreError, StoreResult};

/// A trusted host binding, not caller-supplied flags. Selection verification
/// must authenticate the typed events against the captured norm history.
pub trait ImpactVerifier: SelectionVerifier {
    /// Identify an actually installed automatic method for the complete pinned
    /// requirement and candidate. A declaration alone does not establish this.
    fn automatic_method(
        &self,
        requirement: &InventoryRequirement,
        candidate: &CapturedArtifact,
    ) -> Option<EvidenceVersion>;
}

pub struct ImpactInput<'a> {
    pub before: &'a NormView,
    pub before_artifact: &'a CapturedArtifact,
    pub after: &'a NormView,
    pub candidate: &'a CapturedArtifact,
    pub policy: &'a EvidenceVersion,
    pub time_basis: &'a str,
    pub evidence: &'a [SelectionEvent],
}
#[derive(Clone, Copy)]
pub struct ImpactLimits {
    pub resources: ResourceLimits,
    pub max_evaluations: usize,
    pub max_events: usize,
}
impl Default for ImpactLimits {
    fn default() -> Self {
        Self {
            resources: ResourceLimits::default(),
            max_evaluations: 1_000,
            max_events: 10_000,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactBasis {
    Before,
    After,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImpactWork {
    Supported,
    Check { method: EvidenceVersion },
    Repair,
    ResolveEvidence,
    ObservationGap,
    VerifyEvidence,
    ResourceGap,
}
#[derive(Clone, Debug, Serialize)]
pub struct RequirementImpact {
    pub bases: BTreeSet<ImpactBasis>,
    pub requirement: Option<EvidenceVersion>,
    pub selection: Option<EvidenceSelection>,
    pub work: ImpactWork,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(tag = "kind", content = "record", rename_all = "snake_case")]
pub enum ImpactAuthorityAction {
    RequirementChanged(String),
    CharterChanged,
    AuthorityChanged,
}
#[derive(Clone, Debug, Serialize)]
pub struct ImpactPlan {
    pub evidence_gaps: BTreeMap<String, ProjectionGap>,
    pub policy: EvidenceVersion,
    pub time_basis: String,
    pub resources: ResourceInventoryPair,
    /// Prior duties interpreted under the prior charter at the candidate.
    pub prior_at_candidate: ResourceInventory,
    pub requirements: BTreeMap<String, Vec<RequirementImpact>>,
    pub authority_actions: BTreeSet<ImpactAuthorityAction>,
}

pub fn plan(
    input: ImpactInput<'_>,
    verifier: &dyn ImpactVerifier,
    limits: ImpactLimits,
) -> StoreResult<ImpactPlan> {
    plan_with_selection(
        input,
        limits,
        BTreeMap::new(),
        |query, evidence| select_evidence(query, evidence, verifier),
        |requirement, candidate| verifier.automatic_method(requirement, candidate),
    )
}

/// The host supplies captured views/artifacts and installed method discovery;
/// published evidence always comes from the authenticated projection.
pub struct ProjectedImpactInput<'a> {
    pub before: &'a NormView,
    pub before_artifact: &'a CapturedArtifact,
    pub after: &'a NormView,
    pub candidate: &'a CapturedArtifact,
    pub policy: &'a EvidenceVersion,
    pub time_basis: &'a str,
}
pub fn plan_projected(
    input: ProjectedImpactInput<'_>,
    projection: &EvidenceProjection,
    policy: &dyn ExecutionSelectionPolicy,
    automatic_method: impl Fn(&InventoryRequirement, &CapturedArtifact) -> Option<EvidenceVersion>,
    limits: ImpactLimits,
) -> StoreResult<ImpactPlan> {
    if projection.events().len() > limits.max_events {
        return Err(StoreError::Conflict(
            "impact evidence exceeds its event budget".into(),
        ));
    }
    let gaps = projection
        .gaps_for_view(input.after)
        .map_err(StoreError::Conflict)?;
    plan_with_selection(
        ImpactInput {
            before: input.before,
            before_artifact: input.before_artifact,
            after: input.after,
            candidate: input.candidate,
            policy: input.policy,
            time_basis: input.time_basis,
            evidence: projection.events(),
        },
        limits,
        gaps,
        |query, _| {
            projection
                .select(query, policy)
                .map(|selected| selected.selection)
        },
        automatic_method,
    )
}
fn plan_with_selection(
    input: ImpactInput<'_>,
    limits: ImpactLimits,
    evidence_gaps: BTreeMap<String, ProjectionGap>,
    select: impl Fn(&SelectionQuery, &[SelectionEvent]) -> Result<EvidenceSelection, String>,
    automatic_method: impl Fn(&InventoryRequirement, &CapturedArtifact) -> Option<EvidenceVersion>,
) -> StoreResult<ImpactPlan> {
    if [
        &input.policy.name,
        &input.policy.version,
        &input.policy.digest,
        input.time_basis,
    ]
    .iter()
    .any(|s| s.trim().is_empty())
    {
        return Err(StoreError::Conflict(
            "impact planning requires policy and time identities".into(),
        ));
    }
    if input.evidence.len() > limits.max_events {
        return Err(StoreError::Conflict(
            "impact evidence exceeds its event budget".into(),
        ));
    }
    let resources = compare_resources(
        input.before,
        input.before_artifact,
        input.after,
        input.candidate,
        limits.resources,
    )?;
    let prior_at_candidate = input
        .before
        .resource_inventory(input.candidate, limits.resources)?;
    let mut result = ImpactPlan {
        evidence_gaps,
        policy: input.policy.clone(),
        time_basis: input.time_basis.into(),
        resources,
        prior_at_candidate,
        requirements: BTreeMap::new(),
        authority_actions: BTreeSet::new(),
    };
    if input.before.charter != input.after.charter {
        result
            .authority_actions
            .insert(ImpactAuthorityAction::CharterChanged);
    }
    if input.before.checkpoint() != input.after.checkpoint() {
        result
            .authority_actions
            .insert(ImpactAuthorityAction::AuthorityChanged);
    }
    let artifact = candidate_identity(input.candidate.files());
    let mut evaluated = 0usize;
    for id in &result.resources.requirements {
        let before = result.resources.before.inventory.requirements.get(id);
        let after = result.resources.after.inventory.requirements.get(id);
        if before.is_some() && before.map(|r| &r.requirement) != after.map(|r| &r.requirement) {
            result
                .authority_actions
                .insert(ImpactAuthorityAction::RequirementChanged(id.clone()));
        }
        let mut entries: Vec<RequirementImpact> = Vec::new();
        for (basis, record, inventory) in [
            (ImpactBasis::Before, before, &result.prior_at_candidate),
            (ImpactBasis::After, after, &result.resources.after),
        ] {
            let Some(record) = record else {
                continue;
            };
            let bound = inventory
                .bindings
                .get(id)
                .is_some_and(|b| b.subject_present);
            // Equal interpreted properties share a selection. An uninterpreted
            // record cannot deduplicate by the absence of an evidence identity.
            if let Some(entry) = entries.iter_mut().find(|entry| {
                record.requirement.is_some() && entry.requirement == record.requirement
            }) {
                entry.bases.insert(basis);
                if !bound {
                    entry.work = ImpactWork::ResourceGap;
                }
                continue;
            }
            evaluated += 1;
            if evaluated > limits.max_evaluations {
                return Err(StoreError::Conflict(
                    "impact planning exceeds its evaluation budget".into(),
                ));
            }
            let selection = record
                .requirement
                .as_ref()
                .map(|requirement| {
                    select(
                        &SelectionQuery {
                            requirement: requirement.clone(),
                            artifact: artifact.clone(),
                            policy: input.policy.clone(),
                            time_basis: input.time_basis.into(),
                            frontier: input.after.frontier.clone(),
                        },
                        input.evidence,
                    )
                })
                .transpose()
                .map_err(StoreError::Conflict)?;
            let work = match (&selection, bound) {
                (Some(selected), true) => match selected.conformance {
                    Conformance::Satisfied if !result.evidence_gaps.is_empty() => {
                        ImpactWork::VerifyEvidence
                    }
                    Conformance::Satisfied => ImpactWork::Supported,
                    Conformance::Violated => ImpactWork::Repair,
                    Conformance::Conflicted => ImpactWork::ResolveEvidence,
                    Conformance::Stale | Conformance::Unresolved
                        if !result.evidence_gaps.is_empty() =>
                    {
                        ImpactWork::VerifyEvidence
                    }
                    Conformance::Stale | Conformance::Unresolved => {
                        match automatic_method(record, input.candidate) {
                            Some(method)
                                if [&method.name, &method.version, &method.digest]
                                    .iter()
                                    .all(|v| !v.trim().is_empty()) =>
                            {
                                ImpactWork::Check { method }
                            }
                            _ => ImpactWork::ObservationGap,
                        }
                    }
                },
                _ => ImpactWork::ResourceGap,
            };
            entries.push(RequirementImpact {
                bases: [basis].into(),
                requirement: record.requirement.clone(),
                selection,
                work,
            });
        }
        result.requirements.insert(id.clone(), entries);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "norm_impact_tests.rs"]
mod tests;
