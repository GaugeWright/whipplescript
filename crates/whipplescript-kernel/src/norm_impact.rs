//! Complete pure impact planning. No job execution or ref admission authority.
use crate::norm_projection::{EvidenceProjection, ExecutionSelectionPolicy, ProjectionGap};
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
    Check {
        method: EvidenceVersion,
    },
    Repair,
    ResolveEvidence,
    ObservationGap,
    VerifyEvidence,
    ResourceGap,
    /// The only positive support comes from a quarantined method, and no
    /// policy window over it has accepted (norm-plane §3.5, N1).
    Quarantined(Box<crate::norm_reliability::QuarantinedSupport>),
}
#[derive(Clone, Debug, Serialize)]
pub struct RequirementImpact {
    pub bases: BTreeSet<ImpactBasis>,
    pub requirement: Option<EvidenceVersion>,
    pub selection: Option<EvidenceSelection>,
    pub work: ImpactWork,
    /// For a protected run staged its requirement's domain, that domain and
    /// every change outside it: the witness that support carried across
    /// those changes (norm-plane §3.4).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<crate::norm_staging::SupportCeiling>,
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
    // What each requirement's run is staged at the candidate: its domain for
    // a protected method, the whole cut otherwise (norm_staging).
    let staging = |record: &InventoryRequirement, inventory: &ResourceInventory, id: &str| {
        let method = crate::norm_execution::PreparedNormExecution::requirement_method(record).ok();
        match method {
            Some(method) => crate::norm_staging::stage(
                &method.runtime.engine,
                inventory.bindings.get(id),
                input.candidate.files(),
            ),
            None => crate::norm_staging::Staging {
                files: input.candidate.files().clone(),
                ceiling: None,
            },
        }
    };
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
            let staged = staging(record, inventory, id);
            let selection = record
                .requirement
                .as_ref()
                .map(|requirement| {
                    select(
                        &SelectionQuery {
                            requirement: requirement.clone(),
                            artifact: staged.identity(),
                            policy: input.policy.clone(),
                            time_basis: input.time_basis.into(),
                            frontier: input.after.frontier.clone(),
                        },
                        input.evidence,
                    )
                })
                .transpose()
                .map_err(StoreError::Conflict)?;
            // Only a gap that could hide this requirement's evidence doubts it.
            let in_doubt = record.requirement.as_ref().is_some_and(|requirement| {
                result
                    .evidence_gaps
                    .values()
                    .any(|gap| gap.applies_to(&requirement.name))
            });
            let work = match (&selection, bound) {
                (Some(selected), true) => match selected.conformance {
                    Conformance::Satisfied if in_doubt => ImpactWork::VerifyEvidence,
                    Conformance::Satisfied => ImpactWork::Supported,
                    Conformance::Violated => ImpactWork::Repair,
                    Conformance::Conflicted => ImpactWork::ResolveEvidence,
                    Conformance::Stale | Conformance::Unresolved if in_doubt => {
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
            // Every change outside what the run is staged, which is what a
            // supported requirement's support carried across.
            let ceiling = staged
                .ceiling
                .map(|domain| crate::norm_staging::SupportCeiling {
                    domain,
                    outside: result
                        .resources
                        .changes
                        .keys()
                        .filter(|path| {
                            !staged.files.contains_key(*path)
                                && !result
                                    .resources
                                    .before
                                    .bindings
                                    .get(id)
                                    .is_some_and(|before| before.resources.contains(*path))
                        })
                        .cloned()
                        .collect(),
                });
            entries.push(RequirementImpact {
                bases: [basis].into(),
                requirement: record.requirement.clone(),
                selection,
                work,
                ceiling,
            });
        }
        result.requirements.insert(id.clone(), entries);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "norm_impact_tests.rs"]
mod tests;
