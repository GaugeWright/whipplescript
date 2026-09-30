//! Source-process composition (DR-0152), not another norm or ref authority.
//!
//! Read-only native derivation uses the owning VCS and authenticated norm
//! readers. Local reference observations never establish a Home population.
//! This result deliberately has no certificate conversion: coverage authority,
//! isolated execution and the final publication fence must be bound separately.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_core::norm_selection::EvidenceSelection;
use whipplescript_store::branches::flowing_admission::FlowingCandidateWitness;
use whipplescript_store::branches::flowing_fence::FlowingFenceState;
use whipplescript_store::norm_artifact::ArtifactLimits;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::norm_reference_inventory::{
    inventory_at, observed_acts_at, observed_edges_at, NormReferenceMeaning,
};
use whipplescript_store::norm_resources::RequirementResources;
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::RuntimeStore;

use crate::norm_admission::{AdmissionHost, AdmissionLedger};
use crate::norm_impact::{ImpactBasis, ImpactWork};
use crate::norm_planning::{ImpactQuery, Planned};

#[derive(Clone, Debug, Serialize)]
pub struct SourceAdmissionSubject {
    pub witness_digest: String,
    pub witness: FlowingCandidateWitness,
    pub source_fence: FlowingFenceState,
}

/// Located gaps are part of the judgment, including gaps outside the locally
/// observed ledger. An empty local reference set cannot remove them.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct LocatedBlocker {
    pub scope: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceObligation {
    pub record: String,
    pub requirement: Option<EvidenceVersion>,
    pub bases: BTreeSet<ImpactBasis>,
    /// Prior obligations are interpreted at the candidate under prior policy.
    pub applicability: BTreeMap<ImpactBasis, RequirementResources>,
    pub work: ImpactWork,
    pub support: Option<EvidenceSelection>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReferenceClassObservation {
    pub vocabulary: String,
    pub version: String,
    pub field: String,
    pub meaning: Option<NormReferenceMeaning>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReferenceEdgeObservation {
    pub consumer: String,
    pub consumer_revision: String,
    pub vocabulary: String,
    pub vocabulary_version: String,
    pub field: String,
    pub occurrence: String,
    pub provider: String,
    pub resolved_revision: Option<String>,
    pub meaning: Option<NormReferenceMeaning>,
}

/// A truthful local observation. It is not a serializable authority token or
/// an input that can be replayed to supply Home coverage.
#[derive(Clone, Debug, Serialize)]
pub struct LocalReferenceObservation {
    pub ledger: String,
    pub authority_head: String,
    pub frontier: Vec<String>,
    pub charter_digest: String,
    pub charter_events: Vec<String>,
    pub required_classes: Vec<ReferenceClassObservation>,
    pub observed_acts: BTreeSet<String>,
    pub edges: Vec<ReferenceEdgeObservation>,
    pub historical_population_unknown: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SourceAdmissionJudgment {
    pub protocol: &'static str,
    pub process: EvidenceVersion,
    pub subject: SourceAdmissionSubject,
    pub interpretation: EvidenceVersion,
    /// The complete typed norm result, including its read anchors, requirement
    /// inventories, selected evidence, resource and discovery gaps.
    pub norm: serde_json::Value,
    pub obligations: BTreeMap<String, SourceObligation>,
    pub references: LocalReferenceObservation,
    pub blockers: BTreeSet<LocatedBlocker>,
}

/// No deserializer or public constructor. Only derivation from owning readers
/// creates this immutable result. A plan identity is not admission authority.
#[derive(Clone, Debug)]
pub struct SourceAdmissionPlan {
    identity: String,
    judgment: SourceAdmissionJudgment,
}

impl SourceAdmissionPlan {
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn judgment(&self) -> &SourceAdmissionJudgment {
        &self.judgment
    }
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"identity": self.identity, "judgment": self.judgment})
    }
}

fn identity(value: &impl Serialize) -> Result<String, String> {
    // Value canonicalizes object key order; vectors must be canonically ordered
    // by their owning derivation. Operational queue order is never an input.
    let canonical = serde_json::to_value(value).map_err(|error| format!("{error:?}"))?;
    let bytes = serde_json::to_vec(&canonical).map_err(|error| format!("{error:?}"))?;
    Ok(format!(
        "sha256:{}",
        whipplescript_store::stable_hash_bytes_hex(&bytes)
    ))
}

fn obligations(
    witness_digest: &str,
    planned: &Planned,
) -> Result<BTreeMap<String, SourceObligation>, String> {
    let mut result = BTreeMap::new();
    for (record, impacts) in &planned.plan.requirements {
        for impact in impacts {
            let mut applicability = BTreeMap::new();
            for basis in &impact.bases {
                let inventory = match basis {
                    ImpactBasis::Before => &planned.plan.prior_at_candidate,
                    ImpactBasis::After => &planned.plan.resources.after,
                };
                if let Some(binding) = inventory.bindings.get(record) {
                    applicability.insert(*basis, binding.clone());
                }
            }
            let id = identity(&(
                "source-obligation-v1",
                witness_digest,
                record,
                &impact.requirement,
                &impact.bases,
                &applicability,
            ))?;
            let obligation = SourceObligation {
                record: record.clone(),
                requirement: impact.requirement.clone(),
                bases: impact.bases.clone(),
                applicability,
                work: impact.work.clone(),
                support: impact.selection.clone(),
            };
            // Equal interpreted requirements share one norm selection;
            // distinct versions or uninterpreted bases remain distinct here.
            result.insert(id, obligation);
        }
    }
    Ok(result)
}

/// Derive the candidate's full local norm obligations. No requirement is
/// filtered by a partial reverse-dependency query. The Home's authoritative
/// population/cut is still owed and remains an explicit blocking scope.
///
/// The caller selects only a retained witness and attempt; policy, methods,
/// artifacts and evidence come from the embedding's owning readers. This
/// function creates no issue, claim, execution, certificate or publication.
pub fn plan_native<L: AdmissionLedger, S: RuntimeStore>(
    vcs: &NativeWorkspaceVcs,
    ledger: &L,
    host: AdmissionHost<'_, S>,
    witness_digest: &str,
    attempt_id: &str,
) -> Result<SourceAdmissionPlan, String> {
    let captured = vcs
        .capture_native_gate_subject(witness_digest, attempt_id)
        .map_err(|error| format!("{error:?}"))?;
    if !ledger
        .bootstrapped()
        .map_err(|error| format!("{error:?}"))?
    {
        return Err("source admission has no admitted norm policy".into());
    }
    let (view, events) = ledger
        .capture(host.verifier)
        .map_err(|error| format!("{error:?}"))?;
    let history =
        CapturedNormHistory::capture(&view, &events, host.verifier, NormHistoryLimits::default())
            .map_err(|error| format!("{error:?}"))?;
    let witness = captured.witness();
    let capture = |cut: &str| vcs.capture_norm_artifact(cut, ArtifactLimits::default());
    let planned = crate::norm_planning::plan(
        ImpactQuery {
            configuration: host.configuration,
            history: &history,
            verifier: host.verifier,
            runtime: host.runtime,
            artifacts: &capture,
            before_cut: witness
                .expected_trunk_cut_id
                .as_deref()
                .unwrap_or(&witness.candidate_cut_id),
            after_cut: &witness.candidate_cut_id,
            before_frontier: None,
            after_frontier: None,
            policy: host.policy,
        },
        host.verify_runtime,
    )?;
    // Both the retained witness and the artifacts are read from this VCS's
    // authority at the exact witness cuts; no caller supplies a manifest.
    let inventory = inventory_at(&view).map_err(|error| format!("{error:?}"))?;
    let edges = observed_edges_at(&view).map_err(|error| format!("{error:?}"))?;
    let acts = observed_acts_at(&view);
    let references = LocalReferenceObservation {
        ledger: inventory.ledger,
        authority_head: inventory.authority_head,
        frontier: inventory.frontier,
        charter_digest: inventory.charter_digest,
        charter_events: inventory.charter_events,
        required_classes: inventory
            .fields
            .iter()
            .map(|field| ReferenceClassObservation {
                vocabulary: field.vocabulary.clone(),
                version: field.vocabulary_version.clone(),
                field: field.path.clone(),
                meaning: field.meaning,
            })
            .collect(),
        observed_acts: acts
            .admissions
            .iter()
            .map(|act| act.event.clone())
            .collect(),
        edges: edges
            .references
            .iter()
            .map(|edge| ReferenceEdgeObservation {
                consumer: edge.consumer.clone(),
                consumer_revision: edge.consumer_revision.clone(),
                vocabulary: edge.vocabulary.name.clone(),
                vocabulary_version: edge.vocabulary.version.clone(),
                field: edge.field.clone(),
                occurrence: edge.occurrence.clone(),
                provider: edge.provider.clone(),
                resolved_revision: edge.resolved_revision.clone(),
                meaning: edge.meaning,
            })
            .collect(),
        historical_population_unknown: inventory.historical_population_unknown,
    };
    let mut blockers = BTreeSet::from([LocatedBlocker {
        scope: "home/reference-population".into(),
        reason: "no authoritative Home operation population, sealed cut or enforced scope boundary was captured".into(),
    }]);
    for class in &references.required_classes {
        if class.meaning.is_none() {
            blockers.insert(LocatedBlocker {
                scope: format!(
                    "norm/{}/{}/{}/{}",
                    references.ledger, class.vocabulary, class.version, class.field
                ),
                reason: "reference-capable field has no admitted meaning".into(),
            });
        }
    }
    if references.historical_population_unknown {
        blockers.insert(LocatedBlocker {
            scope: format!("norm/{}/historical-population", references.ledger),
            reason: "current charter declarations do not close earlier accepting paths".into(),
        });
    }
    if let Err(refusal) = crate::norm_admission::judge(&planned) {
        blockers.insert(LocatedBlocker {
            scope: "norm/admission".into(),
            reason: refusal.reason(),
        });
    }
    for conflict in &planned.reservation_conflicts {
        blockers.insert(LocatedBlocker {
            scope: "norm/reservations".into(),
            reason: serde_json::to_string(conflict).map_err(|error| format!("{error:?}"))?,
        });
    }
    let judgment = SourceAdmissionJudgment {
        protocol: "whipplescript.source-admission/v1",
        process: EvidenceVersion {
            name: "whipplescript.source-admission.full-norm".into(),
            version: "1".into(),
            digest: format!(
                "sha256:{}",
                whipplescript_store::stable_hash_bytes_hex(include_bytes!("source_admission.rs"))
            ),
        },
        subject: SourceAdmissionSubject {
            witness_digest: witness_digest.into(),
            witness: witness.clone(),
            source_fence: captured.fence().clone(),
        },
        interpretation: host.configuration.identity().clone(),
        norm: planned.to_json(),
        obligations: obligations(witness_digest, &planned)?,
        references,
        blockers,
    };
    // Detect change during derivation. This is not the final publication fence.
    let current = vcs
        .capture_native_gate_subject(witness_digest, attempt_id)
        .map_err(|error| format!("{error:?}"))?;
    let (current_view, current_events) = ledger
        .capture(host.verifier)
        .map_err(|error| format!("{error:?}"))?;
    let current_history = CapturedNormHistory::capture(
        &current_view,
        &current_events,
        host.verifier,
        NormHistoryLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    if current != captured || current_history.anchor() != planned.anchor {
        return Err("source-admission premises changed during derivation".into());
    }
    Ok(SourceAdmissionPlan {
        identity: identity(&judgment)?,
        judgment,
    })
}

#[cfg(test)]
#[path = "source_admission_tests.rs"]
mod tests;
