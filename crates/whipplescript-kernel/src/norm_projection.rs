//! Authenticated observation history plus independently recovered execution.
//! Policy, automatic method discovery and ref admission remain host operations.
use std::collections::{BTreeMap, BTreeSet};

use crate::norm_execution::VerifiedNormExecution;
use serde::Serialize;
use whipplescript_core::norm_evidence::{
    AssertionObservation, ReportContract, ReportVerifier, TestReport,
};
use whipplescript_core::norm_preservation::{PreservationVerifier, PreservationWitness};
use whipplescript_core::norm_selection::{
    select_evidence, EvidenceSelection, SelectionEvent, SelectionPayload, SelectionQuery,
    SelectionVerifier,
};
use whipplescript_core::vocabulary::VocabularyRef;
use whipplescript_store::norm::{NormAct, SignedNormEvent};
use whipplescript_store::norm_history::CapturedNormHistory;

/// Installed interpretation keyed by the complete vocabulary identity.
#[derive(Clone, Copy)]
pub enum ProjectionRole {
    Context,
    PublishedExecution,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProjectionGap {
    UnknownVocabulary { vocabulary: VocabularyRef },
    MalformedPublication,
    ExecutionUnavailable { reason: String },
    PublicationMismatch,
}

/// No deserializer: creation requires authenticated history and recovered runs.
pub struct EvidenceProjection {
    ledger: String,
    events: Vec<SelectionEvent>,
    executions: BTreeMap<String, VerifiedNormExecution>,
    gaps: BTreeMap<String, ProjectionGap>,
}
/// Installed policy must verify exact policy/time, requirement/method and
/// observer integrity. It is not taken from an observation's serialized flags.
pub trait ExecutionSelectionPolicy {
    fn accepts(&self, query: &SelectionQuery, execution: &VerifiedNormExecution) -> bool;
}

impl EvidenceProjection {
    /// `recover` resolves coordinates through host-owned runtime/artifact stores,
    /// normally using PreparedNormExecution::recover_with_artifacts. Failure is
    /// retained as a gap; it is never interpreted as passing evidence.
    pub fn capture(
        history: &CapturedNormHistory,
        roles: &BTreeMap<VocabularyRef, ProjectionRole>,
        max_events: usize,
        mut recover: impl FnMut(&str, &str) -> Result<VerifiedNormExecution, String>,
    ) -> Result<Self, String> {
        if history.events().count() > max_events {
            return Err("evidence projection exceeds its event budget".into());
        }
        let mut result = Self {
            ledger: history.anchor().checkpoint.ledger,
            events: Vec::new(),
            executions: BTreeMap::new(),
            gaps: BTreeMap::new(),
        };
        for event in history.events() {
            let signed: SignedNormEvent =
                serde_json::from_str(&event.payload_json).map_err(|e| e.to_string())?;
            let mut payload = SelectionPayload::Context;
            if let NormAct::Create {
                vocabulary,
                fields_json,
                ledger,
                ..
            } = &signed.statement.action
            {
                match roles.get(vocabulary) {
                    None => {
                        result.gaps.insert(
                            event.event_id.clone(),
                            ProjectionGap::UnknownVocabulary {
                                vocabulary: vocabulary.clone(),
                            },
                        );
                    }
                    Some(ProjectionRole::Context) => {}
                    Some(ProjectionRole::PublishedExecution) => {
                        let fields: serde_json::Value =
                            serde_json::from_str(fields_json).map_err(|e| e.to_string())?;
                        let verified = match (fields["instance"].as_str(), fields["run"].as_str()) {
                            (Some(instance), Some(run))
                                if !instance.is_empty() && !run.is_empty() =>
                            {
                                recover(instance, run).map_err(|reason| {
                                    ProjectionGap::ExecutionUnavailable { reason }
                                })
                            }
                            _ => Err(ProjectionGap::MalformedPublication),
                        };
                        match verified {
                            Ok(execution) => {
                                if crate::norm_publication::fields(&execution)? != fields
                                    || execution.intent().publisher
                                        != signed.statement.actor.principal
                                    || execution.intent().anchor.checkpoint.ledger != *ledger
                                {
                                    result.gaps.insert(
                                        event.event_id.clone(),
                                        ProjectionGap::PublicationMismatch,
                                    );
                                } else {
                                    payload = SelectionPayload::Observation {
                                        contract: execution.contract().clone(),
                                        report: Box::new(execution.observation().report.clone()),
                                    };
                                    result.executions.insert(event.event_id.clone(), execution);
                                }
                            }
                            Err(gap) => {
                                result.gaps.insert(event.event_id.clone(), gap);
                            }
                        }
                    }
                }
            }
            result.events.push(SelectionEvent {
                id: event.event_id.clone(),
                parents: event.parents.iter().cloned().collect(),
                payload,
            });
        }
        Ok(result)
    }

    /// Bind a host-captured view to this projection even when no requirement
    /// selection will run. Unknown or mixed causal histories refuse as a whole.
    pub(crate) fn gaps_for_view(
        &self,
        view: &whipplescript_store::norm::NormView,
    ) -> Result<BTreeMap<String, ProjectionGap>, String> {
        if view.ledger != self.ledger || view.frontier.is_empty() {
            return Err(
                "impact projection requires the same ledger and a nonempty frontier".into(),
            );
        }
        let events: BTreeMap<_, _> = self.events.iter().map(|e| (&e.id, e)).collect();
        let mut pending: Vec<_> = view.frontier.iter().cloned().collect();
        let mut closure = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !closure.insert(id.clone()) {
                continue;
            }
            let event = events
                .get(&id)
                .ok_or("impact projection has an unknown frontier ancestor")?;
            pending.extend(event.parents.iter().cloned());
        }
        if closure != view.event_order().iter().cloned().collect() {
            return Err("impact view differs from the projected causal closure".into());
        }
        Ok(self
            .gaps
            .iter()
            .filter(|(id, _)| closure.contains(*id))
            .map(|(id, gap)| (id.clone(), gap.clone()))
            .collect())
    }

    pub fn events(&self) -> &[SelectionEvent] {
        &self.events
    }
    pub fn gaps(&self) -> &BTreeMap<String, ProjectionGap> {
        &self.gaps
    }

    /// Gaps are scoped to the same causal history as the evidence selection.
    /// A result with gaps is not a complete conformance or admission decision.
    pub fn select(
        &self,
        query: &SelectionQuery,
        policy: &dyn ExecutionSelectionPolicy,
    ) -> Result<ProjectedSelection, String> {
        let selection = select_evidence(
            query,
            &self.events,
            &ProjectionVerifier {
                projection: self,
                policy,
                query,
            },
        )?;
        let gaps = self
            .gaps
            .iter()
            .filter(|(id, _)| selection.history.contains_key(*id))
            .map(|(id, gap)| (id.clone(), gap.clone()))
            .collect();
        Ok(ProjectedSelection { selection, gaps })
    }
}
#[derive(Debug, Serialize)]
pub struct ProjectedSelection {
    pub selection: EvidenceSelection,
    pub gaps: BTreeMap<String, ProjectionGap>,
}
struct ProjectionVerifier<'a> {
    projection: &'a EvidenceProjection,
    policy: &'a dyn ExecutionSelectionPolicy,
    query: &'a SelectionQuery,
}
impl ReportVerifier for ProjectionVerifier<'_> {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        self.projection
            .executions
            .values()
            .any(|e| self.policy.accepts(self.query, e) && e.verify_report_binding(report))
    }
    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        self.projection.executions.values().any(|e| {
            self.policy.accepts(self.query, e) && e.verify_assertion_exercise(report, observation)
        })
    }
}
impl PreservationVerifier for ProjectionVerifier<'_> {
    fn verify_preservation_basis(&self, _: &PreservationWitness) -> bool {
        false
    }
}
impl SelectionVerifier for ProjectionVerifier<'_> {
    fn verify_event(&self, event: &SelectionEvent) -> bool {
        self.projection.events.contains(event)
    }
    fn accepts_contract(&self, query: &SelectionQuery, contract: &ReportContract) -> bool {
        self.projection
            .executions
            .values()
            .any(|e| e.contract() == contract && self.policy.accepts(query, e))
    }
    fn authorize_resolution(&self, _: &SelectionQuery, _: &SelectionEvent) -> bool {
        false
    }
    fn accepts_preservation(&self, _: &SelectionQuery, _: &PreservationWitness) -> bool {
        false
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "norm_projection_tests.rs"]
mod tests;
