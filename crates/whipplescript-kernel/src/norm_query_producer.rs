//! The projection producer (norm-plane §8; DR-0098 §6; ecosystem-shape E4).
//!
//! A projection is the typed ledger query evaluated at a named frontier and
//! handed to a consumer as a value: the `projection_view` lowering class
//! has had a consumer since DR-0098 and no producer; this is the producer.
//! It asks the shared dispatcher, so the native and hosted stores project
//! identically, and it adds nothing to what the query said: the frontier it
//! was read at, the members it found, and whether the answer may be read as
//! complete. A projection is pure — reading one runs no check, admits
//! nothing, and files nothing — and it is never itself a fact: a rule that
//! consumes it observes the members at that frontier, under the
//! completeness it states, and a frontier that has moved is a new
//! projection, not an edit of this one. Lowering a construct to it is the
//! composition tracker's work; the value it lowers to is fixed here.

use serde::{Deserialize, Serialize};
use whipplescript_store::norm::NormVerifier;
use whipplescript_store::norm_commands::{
    NormArtifactCapture, NormCommand, NormCommandHost, NormCommandRequest, NormCommandResult,
    NormCommandStore,
};
use whipplescript_store::norm_query::{QueryCompleteness, QueryMembers};

pub const PROJECTION_PROTOCOL: &str = "whipplescript.norm.projection/v1";

/// One member of a record projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedRecord {
    pub record: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub vocabulary: String,
    pub version: String,
    pub revision: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProjectedMembers {
    Records { records: Vec<ProjectedRecord> },
    Regions { cut: String, paths: Vec<String> },
}

/// The value a `projection_view` consumer receives.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedView {
    pub protocol: String,
    /// The query, in its canonical spelling.
    pub expression: String,
    /// The frontier the projection was read at; a consumer keys on it.
    pub frontier: Vec<String>,
    /// The cut a region projection, or an anchored one, was read at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cut: Option<String>,
    pub members: ProjectedMembers,
    pub completeness: QueryCompleteness,
}

impl ProjectedView {
    /// A stable key for the projection: its expression at its frontier.
    pub fn key(&self) -> String {
        let mut parts = vec![self.expression.clone()];
        parts.extend(self.frontier.iter().cloned());
        if let Some(cut) = &self.cut {
            parts.push(format!("cut={cut}"));
        }
        crate::idempotency_key(&parts.iter().map(String::as_str).collect::<Vec<_>>())
    }
}

/// Produce a projection through the shared dispatcher.
pub fn project<S: NormCommandStore>(
    store: &mut S,
    verifier: &dyn NormVerifier,
    artifacts: Option<&NormArtifactCapture<'_>>,
    expression: &str,
    frontier: Option<Vec<String>>,
    cut: Option<&str>,
) -> Result<ProjectedView, String> {
    let mut host = NormCommandHost::new(store, verifier);
    if let Some(artifacts) = artifacts {
        host = host.with_artifacts(artifacts);
    }
    let response = host
        .execute(NormCommandRequest::new(NormCommand::Query {
            expression: expression.to_owned(),
            frontier,
            cut: cut.map(str::to_owned),
        }))
        .map_err(|error| format!("{error:?}"))?;
    projected(response.result, cut)
}

/// The projection a dispatcher answer is, or the refusal it is not one.
fn projected(answer: NormCommandResult, cut: Option<&str>) -> Result<ProjectedView, String> {
    let NormCommandResult::Queried { result, .. } = answer else {
        return Err("the dispatcher answered a query with something other than a result".into());
    };
    let members = match result.members {
        QueryMembers::Records { heads } => ProjectedMembers::Records {
            records: heads
                .into_iter()
                .map(|head| ProjectedRecord {
                    record: head.id,
                    alias: head.alias,
                    vocabulary: head.vocabulary.name,
                    version: head.vocabulary.version,
                    revision: head.revision,
                    status: head.status,
                })
                .collect(),
        },
        QueryMembers::Regions { cut, paths } => ProjectedMembers::Regions { cut, paths },
    };
    Ok(ProjectedView {
        protocol: PROJECTION_PROTOCOL.into(),
        expression: result.expression,
        frontier: result.frontier,
        cut: cut.map(str::to_owned),
        members,
        completeness: result.completeness,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_query_result_projects() {
        assert_eq!(
            projected(
                NormCommandResult::Appended {
                    event_id: "not a query".into()
                },
                None
            )
            .unwrap_err(),
            "the dispatcher answered a query with something other than a result"
        );
    }
}
