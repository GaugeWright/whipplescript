//! Pure causal selection and verified preservation of test evidence. No execution or admission.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::norm_evidence::{
    evaluate_report, EvidenceVersion, ReportContract, ReportVerifier, TestJudgment, TestOutcome,
    TestReport,
};

use crate::norm_preservation::{
    evaluate_preservation, PreservationContext, PreservationJudgment, PreservationVerifier,
    PreservationWitness,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionQuery {
    pub requirement: EvidenceVersion,
    pub artifact: String,
    pub policy: EvidenceVersion,
    pub time_basis: String,
    pub frontier: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceResolution {
    pub predecessor: String,
    pub replacement: String,
    pub requirement: EvidenceVersion,
    pub artifact: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SelectionPayload {
    Context,
    Observation {
        contract: ReportContract,
        report: Box<TestReport>,
    },
    Resolution(EvidenceResolution),
    Preservation {
        observation: String,
        witness: Box<PreservationWitness>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionEvent {
    pub id: String,
    pub parents: BTreeSet<String>,
    pub payload: SelectionPayload,
}

/// Installed host policy, never constructed from event-supplied authority flags.
/// Event verification binds identity, parents and the entire payload to admitted
/// history. Contract verification checks installed requirement/method policy.
/// Resolution verification checks the complete act, scoped authority, policy
/// and time premises. ReportVerifier still independently establishes exercise.
pub trait SelectionVerifier: ReportVerifier + PreservationVerifier {
    fn verify_event(&self, event: &SelectionEvent) -> bool;
    fn accepts_contract(&self, query: &SelectionQuery, contract: &ReportContract) -> bool;
    fn authorize_resolution(&self, query: &SelectionQuery, event: &SelectionEvent) -> bool;
    /// Accept this authenticated boundary and its method assumptions under the
    /// exact query policy and time basis. This must not merely read witness flags.
    fn accepts_preservation(&self, query: &SelectionQuery, witness: &PreservationWitness) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Conformance {
    Satisfied,
    Violated,
    Conflicted,
    Stale,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReuseDiagnostic {
    UnknownObservation,
    UnsupportedObservation,
    WitnessIdentityMismatch,
    MissingObservationAncestry,
    PolicyRejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReuseEvaluation {
    pub observation: String,
    pub preservation: Option<PreservationJudgment>,
    pub diagnostics: BTreeSet<ReuseDiagnostic>,
    pub applied: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceSelection {
    pub query: SelectionQuery,
    pub history: BTreeMap<String, SelectionEvent>,
    pub judgments: BTreeMap<String, TestJudgment>,
    pub positive: BTreeSet<String>,
    pub counterevidence: BTreeSet<String>,
    pub stale: BTreeSet<String>,
    pub unresolved: BTreeSet<String>,
    pub excluded: BTreeSet<String>,
    pub retired_by: BTreeMap<String, BTreeSet<String>>,
    pub reused_by: BTreeMap<String, BTreeSet<String>>,
    pub reuse_evaluations: BTreeMap<String, ReuseEvaluation>,
    pub resolution_diagnostics: BTreeMap<String, String>,
    pub conformance: Conformance,
}

impl EvidenceSelection {
    fn empty(query: &SelectionQuery) -> Self {
        Self {
            query: query.clone(),
            history: BTreeMap::new(),
            judgments: BTreeMap::new(),
            positive: BTreeSet::new(),
            counterevidence: BTreeSet::new(),
            stale: BTreeSet::new(),
            unresolved: BTreeSet::new(),
            excluded: BTreeSet::new(),
            retired_by: BTreeMap::new(),
            reused_by: BTreeMap::new(),
            reuse_evaluations: BTreeMap::new(),
            resolution_diagnostics: BTreeMap::new(),
            conformance: Conformance::Unresolved,
        }
    }
}

fn version_named(v: &EvidenceVersion) -> bool {
    [&v.name, &v.version, &v.digest]
        .iter()
        .all(|s| !s.trim().is_empty())
}

/// Select only ancestors of the requested frontier. Reject ambiguity and gaps;
/// input order and unrelated future events confer no selection priority.
pub fn select_evidence(
    query: &SelectionQuery,
    events: &[SelectionEvent],
    verifier: &dyn SelectionVerifier,
) -> Result<EvidenceSelection, String> {
    let valid_query = version_named(&query.requirement)
        && version_named(&query.policy)
        && !query.artifact.trim().is_empty()
        && !query.time_basis.trim().is_empty();
    if !valid_query {
        return Err("selection query has an empty identity".to_owned());
    }
    let mut all = BTreeMap::new();
    for event in events {
        let ambiguous = event.id.trim().is_empty() || all.insert(event.id.clone(), event).is_some();
        if ambiguous {
            return Err("selection history has empty or duplicate event identities".to_owned());
        }
    }
    let mut history = BTreeMap::new();
    let mut pending: Vec<_> = query.frontier.iter().cloned().collect();
    while let Some(id) = pending.pop() {
        if history.contains_key(&id) {
            continue;
        }
        let Some(event) = all.get(&id) else {
            // MUTATION-SUCCESS-EXPR: Ok(EvidenceSelection::empty(query))
            return Err(format!("selection history is missing {id}"));
        };
        if !verifier.verify_event(event) {
            return Err(format!("selection event {id} is unauthenticated"));
        }
        pending.extend(event.parents.iter().cloned());
        history.insert(id, (*event).clone());
    }
    let mut ancestors: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for _ in 0..history.len() {
        let ready: Vec<_> = history
            .values()
            .filter(|event| {
                !ancestors.contains_key(&event.id)
                    && event.parents.iter().all(|p| ancestors.contains_key(p))
            })
            .collect();
        if ready.is_empty() {
            break;
        }
        for event in ready {
            let mut closure = event.parents.clone();
            for parent in &event.parents {
                closure.extend(ancestors[parent].iter().cloned());
            }
            ancestors.insert(event.id.clone(), closure);
        }
    }
    if ancestors.len() != history.len() {
        return Err("selection history contains a causal cycle".to_owned());
    }
    let mut result = EvidenceSelection::empty(query);
    result.history = history;
    let mut eligible = BTreeSet::new();
    for event in result.history.values() {
        let SelectionPayload::Observation { contract, report } = &event.payload else {
            continue;
        };
        let judgment = evaluate_report(contract, report, verifier);
        if contract.subject.requirement != query.requirement {
            result.excluded.insert(event.id.clone());
        } else if !verifier.accepts_contract(query, contract) {
            result.unresolved.insert(event.id.clone());
        } else {
            eligible.insert(event.id.clone());
            let positive = judgment.outcome == TestOutcome::Pass;
            let negative = !judgment.counterexamples.is_empty();
            if contract.subject.artifact != query.artifact {
                if positive || negative {
                    result.stale.insert(event.id.clone());
                } else {
                    result.unresolved.insert(event.id.clone());
                }
            } else {
                if positive {
                    result.positive.insert(event.id.clone());
                }
                if negative {
                    result.counterevidence.insert(event.id.clone());
                }
                if !judgment.diagnostics.is_empty() {
                    result.unresolved.insert(event.id.clone());
                }
            }
        }
        result.judgments.insert(event.id.clone(), judgment);
    }
    // A preservation act is itself captured authenticated history. Its input
    // report stays bound to the source; only applicability is transported.
    for event in result.history.values() {
        let SelectionPayload::Preservation {
            observation,
            witness,
        } = &event.payload
        else {
            continue;
        };
        let mut diagnostics = BTreeSet::new();
        if witness.id != event.id {
            diagnostics.insert(ReuseDiagnostic::WitnessIdentityMismatch);
        }
        if !ancestors[&event.id].contains(observation) {
            diagnostics.insert(ReuseDiagnostic::MissingObservationAncestry);
        }
        if !verifier.accepts_preservation(query, witness) {
            diagnostics.insert(ReuseDiagnostic::PolicyRejected);
        }
        let preservation = if let Some(judgment) = result.judgments.get(observation) {
            let supported =
                judgment.outcome == TestOutcome::Pass || !judgment.counterexamples.is_empty();
            if !eligible.contains(observation) || !supported {
                diagnostics.insert(ReuseDiagnostic::UnsupportedObservation);
            }
            let expected = PreservationContext {
                requirement: query.requirement.clone(),
                method: judgment.subject.method.clone(),
                policy: query.policy.clone(),
                source_artifact: judgment.subject.artifact.clone(),
                target_artifact: query.artifact.clone(),
                boundary: witness.context.boundary.clone(),
            };
            Some(evaluate_preservation(&expected, witness, verifier))
        } else {
            diagnostics.insert(ReuseDiagnostic::UnknownObservation);
            None
        };
        let applied = diagnostics.is_empty() && preservation.as_ref().is_some_and(|p| p.preserved);
        if applied {
            let judgment = &result.judgments[observation];
            if judgment.outcome == TestOutcome::Pass {
                result.positive.insert(observation.clone());
            }
            if !judgment.counterexamples.is_empty() {
                result.counterevidence.insert(observation.clone());
            }
            if !judgment.diagnostics.is_empty() {
                result.unresolved.insert(observation.clone());
            }
            result.stale.remove(observation);
            result
                .reused_by
                .entry(observation.clone())
                .or_default()
                .insert(event.id.clone());
        }
        result.reuse_evaluations.insert(
            event.id.clone(),
            ReuseEvaluation {
                observation: observation.clone(),
                preservation,
                diagnostics,
                applied,
            },
        );
    }
    // Evaluate every act against immutable evidence, before applying any retirement.
    for event in result.history.values() {
        let SelectionPayload::Resolution(resolution) = &event.payload else {
            continue;
        };
        let applicable =
            |id: &String| result.positive.contains(id) || result.counterevidence.contains(id);
        let scoped =
            resolution.requirement == query.requirement && resolution.artifact == query.artifact;
        let support_precedes = |id: &String| {
            ancestors[&event.id].contains(id)
                && result.judgments.get(id).is_some_and(|judgment| {
                    judgment.subject.artifact == query.artifact
                        || result.reused_by.get(id).is_some_and(|witnesses| {
                            witnesses.iter().any(|w| ancestors[&event.id].contains(w))
                        })
                })
        };
        let causal =
            support_precedes(&resolution.predecessor) && support_precedes(&resolution.replacement);
        let grounded = resolution.predecessor != resolution.replacement
            && applicable(&resolution.predecessor)
            && applicable(&resolution.replacement)
            && !resolution.reason.trim().is_empty();
        let authorized = verifier.authorize_resolution(query, event);
        if scoped && causal && grounded && authorized {
            result
                .retired_by
                .entry(resolution.predecessor.clone())
                .or_default()
                .insert(event.id.clone());
        } else {
            result.resolution_diagnostics.insert(event.id.clone(), format!(
                "resolution rejected: scope={scoped}, causal={causal}, grounded={grounded}, authorized={authorized}"));
        }
    }
    for id in result.retired_by.keys() {
        result.positive.remove(id);
        result.counterevidence.remove(id);
    }
    result.conformance = match (
        result.positive.is_empty(),
        result.counterevidence.is_empty(),
    ) {
        (false, false) => Conformance::Conflicted,
        (false, true) => Conformance::Satisfied,
        (true, false) => Conformance::Violated,
        (true, true) if !result.stale.is_empty() => Conformance::Stale,
        _ => Conformance::Unresolved,
    };
    Ok(result)
}

#[cfg(test)]
#[path = "norm_selection_tests.rs"]
mod tests;
