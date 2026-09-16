//! Binding and firing selection over audience-filtered action explanations.
//!
//! Consumers use this projection instead of choosing a latest firing or
//! rebuilding recovery guidance. It remains a read: every suggested step is
//! observational, grants no authority, starts no work, and never recommends a
//! retry without the owning recovery contract.

use serde::{Deserialize, Serialize};

use super::{
    CauseExplanation, Explanation, Firing, ReasonCode, ResultExplanation, ResultStatus,
    SourceReference,
};

pub const SCHEMA: &str = "whipplescript.action-explanation-query.v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultQuery {
    pub result: String,
    pub firing: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub schema: String,
    pub instance_id: String,
    pub query: ResultQuery,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    Selected { selection: Box<SelectedResult> },
    Ambiguous { candidates: Vec<ResultCandidate> },
    NotFound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedResult {
    pub program_version_id: String,
    pub revision: String,
    pub revision_epoch: i64,
    pub rule: String,
    pub firing: Firing,
    pub evaluated_frontier: i64,
    pub result: ResultExplanation,
    /// Only causes referenced by `result`, still carrying the visibility and
    /// completeness decision made by the owning projection boundary.
    pub causes: Vec<CauseExplanation>,
    pub next_action: Option<NextAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultCandidate {
    pub result_id: String,
    pub name: String,
    pub status: ResultStatus,
    pub program_version_id: String,
    pub revision: String,
    pub revision_epoch: i64,
    pub rule: String,
    pub firing: Firing,
    pub evaluated_frontier: i64,
    /// Caller-first source chain. This lets a consumer present a useful choice
    /// without resolving the old source or exposing result payload bytes.
    pub source: Vec<SourceReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NextActionCode {
    InspectResult,
    InspectBinding,
    AwaitOperation,
    AwaitCancellationAcknowledgement,
    ObserveRecovery,
    ReconcileUncertainOperation,
    InspectCause,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextAction {
    pub code: NextActionCode,
    pub result_id: Option<String>,
    pub operation_id: Option<String>,
    pub binding: Option<u64>,
    pub cause_id: Option<String>,
    /// Explicit invariants for renderers and automation consumers. A later
    /// action that starts work needs a separately authorized contract.
    pub authorizes_work: bool,
    pub retry_permitted: bool,
}

#[derive(Clone, Copy)]
struct Match<'a> {
    explanation: &'a Explanation,
    result: &'a ResultExplanation,
}

/// Resolve an exact result identity or an authored binding name within an
/// instance. A name with multiple candidates is returned as an explicit choice;
/// source order, revision order and arrival order never select one implicitly.
pub fn resolve(
    explanations: &[Explanation],
    instance_id: &str,
    result: &str,
    firing: Option<&str>,
) -> Result<Response, String> {
    if result.trim().is_empty() {
        return Err("action explanation result selector is empty".into());
    }
    if firing.is_some_and(|identity| identity.trim().is_empty()) {
        return Err("action explanation firing selector is empty".into());
    }
    for explanation in explanations {
        if explanation.schema != super::SCHEMA {
            return Err(format!(
                "unsupported action explanation schema `{}`",
                explanation.schema
            ));
        }
    }

    let eligible = explanations
        .iter()
        .filter(|explanation| explanation.instance_id == instance_id)
        .filter(|explanation| {
            firing.is_none_or(|identity| explanation.firing.identity.as_deref() == Some(identity))
        })
        .flat_map(|explanation| {
            explanation.results.iter().map(move |result| Match {
                explanation,
                result,
            })
        })
        .collect::<Vec<_>>();
    let exact = eligible
        .iter()
        .filter(|candidate| candidate.result.result_id == result)
        .copied()
        .collect::<Vec<_>>();
    if exact.len() > 1 {
        return Err(format!(
            "action explanation result identity `{result}` occurs more than once"
        ));
    }
    let mut matches = if exact.is_empty() {
        eligible
            .into_iter()
            .filter(|candidate| candidate.result.name == result)
            .collect::<Vec<_>>()
    } else {
        exact
    };
    matches.sort_by_key(|candidate| candidate_key(candidate));

    let outcome = match matches.as_slice() {
        [] => Outcome::NotFound,
        [selected] => Outcome::Selected {
            selection: Box::new(select(selected)?),
        },
        _ => Outcome::Ambiguous {
            candidates: matches.iter().map(candidate).collect(),
        },
    };
    Ok(Response {
        schema: SCHEMA.into(),
        instance_id: instance_id.into(),
        query: ResultQuery {
            result: result.into(),
            firing: firing.map(str::to_owned),
        },
        outcome,
    })
}

fn candidate_key(candidate: &Match<'_>) -> (String, i64, String, String, String) {
    (
        candidate.explanation.program_version_id.clone(),
        candidate.explanation.revision_epoch,
        candidate.explanation.rule.clone(),
        candidate
            .explanation
            .firing
            .identity
            .clone()
            .unwrap_or_default(),
        candidate.result.result_id.clone(),
    )
}

fn candidate(found: &Match<'_>) -> ResultCandidate {
    ResultCandidate {
        result_id: found.result.result_id.clone(),
        name: found.result.name.clone(),
        status: found.result.status,
        program_version_id: found.explanation.program_version_id.clone(),
        revision: found.explanation.revision.clone(),
        revision_epoch: found.explanation.revision_epoch,
        rule: found.explanation.rule.clone(),
        firing: found.explanation.firing.clone(),
        evaluated_frontier: found.explanation.evaluated_frontier,
        source: found.result.source.clone(),
    }
}

fn select(found: &Match<'_>) -> Result<SelectedResult, String> {
    let mut causes = Vec::new();
    for id in &found.result.cause_ids {
        let mut matches = found
            .explanation
            .causes
            .iter()
            .filter(|cause| &cause.cause_id == id);
        let Some(cause) = matches.next() else {
            return Err(format!(
                "action result `{}` references missing cause `{id}`",
                found.result.result_id
            ));
        };
        if matches.next().is_some() {
            return Err(format!(
                "action explanation cause identity `{id}` occurs more than once"
            ));
        }
        if !cause.dependents.contains(&found.result.result_id) {
            return Err(format!(
                "action cause `{id}` does not name dependent result `{}`",
                found.result.result_id
            ));
        }
        causes.push(cause.clone());
    }
    Ok(SelectedResult {
        program_version_id: found.explanation.program_version_id.clone(),
        revision: found.explanation.revision.clone(),
        revision_epoch: found.explanation.revision_epoch,
        rule: found.explanation.rule.clone(),
        firing: found.explanation.firing.clone(),
        evaluated_frontier: found.explanation.evaluated_frontier,
        result: found.result.clone(),
        causes,
        next_action: next_action(found.result),
    })
}

fn next_action(result: &ResultExplanation) -> Option<NextAction> {
    let mut action = NextAction {
        code: NextActionCode::InspectBinding,
        result_id: None,
        operation_id: None,
        binding: None,
        cause_id: None,
        authorizes_work: false,
        retry_permitted: false,
    };
    if result.reasons.contains(&ReasonCode::UncertainOutcome) {
        action.code = NextActionCode::ReconcileUncertainOperation;
        action.operation_id = result.operation_id.clone();
        return action.operation_id.is_some().then_some(action);
    }
    if result
        .reasons
        .contains(&ReasonCode::CancellationAcknowledgement)
    {
        action.code = NextActionCode::AwaitCancellationAcknowledgement;
        action.operation_id = result.operation_id.clone();
        return action.operation_id.is_some().then_some(action);
    }
    if result.reasons.contains(&ReasonCode::Recovery) {
        action.code = NextActionCode::ObserveRecovery;
        action.operation_id = result.operation_id.clone();
        return action.operation_id.is_some().then_some(action);
    }
    if result.reasons.contains(&ReasonCode::WaitingInput) {
        let dependency = result.waiting_on.first()?;
        if let Some(id) = &dependency.result_id {
            action.code = NextActionCode::InspectResult;
            action.result_id = Some(id.clone());
        } else {
            action.binding = Some(dependency.binding);
        }
        return Some(action);
    }
    if result.reasons.contains(&ReasonCode::WaitingOperation) {
        if let Some(dependency) = result.waiting_on.first() {
            if let Some(id) = &dependency.result_id {
                action.code = NextActionCode::InspectResult;
                action.result_id = Some(id.clone());
            } else {
                action.binding = Some(dependency.binding);
            }
            return Some(action);
        }
        action.code = NextActionCode::AwaitOperation;
        action.operation_id = result.operation_id.clone();
        return action.operation_id.is_some().then_some(action);
    }
    if result.reasons.contains(&ReasonCode::ExecutionFailure) {
        action.code = NextActionCode::InspectCause;
        action.cause_id = result.cause_ids.first().cloned();
        return action.cause_id.is_some().then_some(action);
    }
    None
}

#[cfg(test)]
mod tests;
