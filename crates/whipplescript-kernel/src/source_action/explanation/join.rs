//! Readiness and validity joins over one captured action explanation.
//!
//! The base projection (`super::project`) reads only the managed progression.
//! Two owning records refine why a result stands as it does, and both are
//! joined here rather than inferred:
//!
//! - the effect store's recorded row for a pending operation says whether it
//!   is held by capacity, a recorded retry gate, missing configuration or a
//!   refused grant;
//! - the norm evaluator's evidence selection, taken at the explanation's own
//!   frontier, says whether a result's support is stale, inadequate or
//!   conflicted.
//!
//! Both joins are reads. They change reason codes, never a status, start no
//! work and grant no authority. An assessment taken at another frontier, or
//! naming a result the explanation does not hold, is refused rather than
//! attached to the wrong judgment.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use whipplescript_core::norm_evidence::{EvidenceVersion, TestOutcome};
use whipplescript_core::norm_selection::{Conformance, EvidenceSelection};
use whipplescript_store::projection_prefix::ProjectionEffect;
use whipplescript_store::EventView;

use super::{Explanation, ReasonCode, ResultStatus};

/// What keeps a recorded, still-pending operation from running.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationObstruction {
    Capacity,
    Backoff,
    Configuration,
    Authority,
}

impl OperationObstruction {
    pub fn reason(self) -> ReasonCode {
        match self {
            Self::Capacity => ReasonCode::WaitingCapacity,
            Self::Backoff => ReasonCode::WaitingBackoff,
            Self::Configuration => ReasonCode::MissingConfiguration,
            Self::Authority => ReasonCode::MissingAuthority,
        }
    }
}

/// Classify each pending effect row by the status its owning store recorded.
/// A managed operation's effect identity is its operation identity, so the
/// result map is keyed by the same id an explanation result carries.
///
/// `blocked` (no provider could be bound) and `blocked_by_profile` are missing
/// configuration; `blocked_by_admission` and `blocked_by_capability` are a
/// refused gate or grant. A `queued` row whose latest retry recorded a
/// `retry_after` gate is in backoff. The projection reads no clock, so the
/// reason names the recorded gate, not whether it has lapsed.
pub fn operation_obstructions(
    effects: &[ProjectionEffect],
    events: &[EventView],
) -> BTreeMap<String, OperationObstruction> {
    let mut gated = BTreeMap::<String, bool>::new();
    for event in events
        .iter()
        .filter(|event| event.event_type == "effect.retried")
    {
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&event.payload_json) else {
            continue;
        };
        let Some(effect) = payload.get("effect_id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let gate = payload
            .get("retry_after")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|after| !after.trim().is_empty());
        gated.insert(effect.to_owned(), gate);
    }
    effects
        .iter()
        .filter(|effect| !effect.cancel_requested)
        .filter_map(|effect| {
            let obstruction = match effect.status.as_str() {
                "blocked_by_capacity" => OperationObstruction::Capacity,
                "blocked" | "blocked_by_profile" => OperationObstruction::Configuration,
                "blocked_by_admission" | "blocked_by_capability" => OperationObstruction::Authority,
                "queued" if gated.get(&effect.effect_id) == Some(&true) => {
                    OperationObstruction::Backoff
                }
                _ => return None,
            };
            Some((effect.effect_id.clone(), obstruction))
        })
        .collect()
}

/// Replace the generic pending-operation reason with the recorded obstruction.
/// Only a result that is still waiting on its own operation is refined;
/// cancellation, uncertainty and recovery keep their own reasons.
pub fn join_operations(
    explanation: &mut Explanation,
    obstructions: &BTreeMap<String, OperationObstruction>,
) {
    for result in &mut explanation.results {
        let Some(obstruction) = result
            .operation_id
            .as_ref()
            .and_then(|operation| obstructions.get(operation))
        else {
            continue;
        };
        if result.status != ResultStatus::Waiting
            || !result.reasons.contains(&ReasonCode::WaitingOperation)
        {
            continue;
        }
        result
            .reasons
            .retain(|reason| *reason != ReasonCode::WaitingOperation);
        result.reasons.push(obstruction.reason());
        result.reasons.sort();
        result.reasons.dedup();
    }
}

/// One norm evaluator assessment of one result's support, bound to the
/// execution frontier the explanation was evaluated at.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportAssessment {
    pub result_id: String,
    pub evaluated_frontier: i64,
    pub requirement: EvidenceVersion,
    pub artifact: String,
    /// Applicable evidence judged against another artifact.
    pub stale: BTreeSet<String>,
    /// Eligible reports the evaluator could not count as support.
    pub inadequate: BTreeSet<String>,
    /// Positive and negative evidence that both still apply.
    pub conflicted: BTreeSet<String>,
}

impl SupportAssessment {
    /// Read the three support dimensions from the evaluator's own selection.
    /// A retired observation contributes to none of them; an excluded one was
    /// never about this requirement.
    pub fn from_selection(
        result_id: impl Into<String>,
        evaluated_frontier: i64,
        selection: &EvidenceSelection,
    ) -> Self {
        let live = |id: &String| {
            !selection.retired_by.contains_key(id) && !selection.excluded.contains(id)
        };
        let stale = selection
            .stale
            .iter()
            .filter(|id| live(id))
            .cloned()
            .collect();
        let inadequate = selection
            .judgments
            .iter()
            .filter(|(id, _)| live(id) && !selection.stale.contains(*id))
            .filter(|(_, judgment)| {
                judgment.outcome == TestOutcome::HarnessFailed || !judgment.diagnostics.is_empty()
            })
            .map(|(id, _)| id.clone())
            .collect();
        let conflicted = if selection.conformance == Conformance::Conflicted {
            selection
                .positive
                .union(&selection.counterevidence)
                .cloned()
                .collect()
        } else {
            BTreeSet::new()
        };
        Self {
            result_id: result_id.into(),
            evaluated_frontier,
            requirement: selection.query.requirement.clone(),
            artifact: selection.query.artifact.clone(),
            stale,
            inadequate,
            conflicted,
        }
    }

    fn reasons(&self) -> Vec<ReasonCode> {
        [
            (!self.stale.is_empty()).then_some(ReasonCode::StaleSupport),
            (!self.inadequate.is_empty()).then_some(ReasonCode::InadequateSupport),
            (!self.conflicted.is_empty()).then_some(ReasonCode::ConflictedSupport),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

/// The joined assessment as a result carries it. Evidence identities are
/// filtered at this boundary exactly like cause witnesses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportReference {
    pub requirement: EvidenceVersion,
    pub artifact: String,
    pub reasons: Vec<ReasonCode>,
    pub evidence_refs: Vec<String>,
    pub evidence_complete: bool,
}

/// Attach each assessment to its result and add its support reasons.
pub fn join_support(
    explanation: &mut Explanation,
    assessments: &[SupportAssessment],
    visible_evidence: &BTreeSet<String>,
) -> Result<(), String> {
    // Applied to a copy so a refused assessment attaches nothing at all.
    let mut joined = explanation.clone();
    for assessment in assessments {
        if assessment.evaluated_frontier != joined.evaluated_frontier {
            return Err(format!(
                "support assessment for result `{}` was taken at frontier {}, not the explanation's frontier {}",
                assessment.result_id, assessment.evaluated_frontier, joined.evaluated_frontier
            ));
        }
        let Some(result) = joined
            .results
            .iter_mut()
            .find(|result| result.result_id == assessment.result_id)
        else {
            return Err(format!(
                "support assessment names result `{}` that this explanation does not hold",
                assessment.result_id
            ));
        };
        if result.support.iter().any(|existing| {
            existing.requirement == assessment.requirement
                && existing.artifact == assessment.artifact
        }) {
            return Err(format!(
                "result `{}` has more than one support assessment for requirement `{}`",
                assessment.result_id, assessment.requirement.name
            ));
        }
        let evidence: BTreeSet<&String> = assessment
            .stale
            .iter()
            .chain(&assessment.inadequate)
            .chain(&assessment.conflicted)
            .collect();
        let reasons = assessment.reasons();
        result.reasons.extend(reasons.iter().copied());
        result.reasons.sort();
        result.reasons.dedup();
        result.support.push(SupportReference {
            requirement: assessment.requirement.clone(),
            artifact: assessment.artifact.clone(),
            reasons,
            evidence_refs: evidence
                .iter()
                .filter(|id| visible_evidence.contains(**id))
                .map(|id| (*id).clone())
                .collect(),
            evidence_complete: evidence.iter().all(|id| visible_evidence.contains(*id)),
        });
    }
    *explanation = joined;
    Ok(())
}

#[cfg(test)]
mod tests;
