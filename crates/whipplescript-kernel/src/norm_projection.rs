//! Authenticated observation history plus independently recovered execution.
//! Policy, automatic method discovery and ref admission remain host operations.
use std::collections::{BTreeMap, BTreeSet};

use crate::norm_buck2_execution::VerifiedBuck2Execution;
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
    UnknownVocabulary {
        vocabulary: VocabularyRef,
    },
    MalformedPublication,
    /// A publication whose run this host cannot recover. Its signed
    /// invocation names the one requirement it could ever support, so the
    /// gap is that requirement's alone; one whose invocation names none is
    /// every requirement's.
    ExecutionUnavailable {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        requirement: Option<String>,
    },
    PublicationMismatch,
}
impl ProjectionGap {
    /// Whether this gap leaves the named requirement's evidence in doubt.
    pub fn applies_to(&self, requirement: &str) -> bool {
        match self {
            Self::ExecutionUnavailable {
                requirement: Some(scope),
                ..
            } => scope == requirement,
            _ => true,
        }
    }
    /// Whether this gap is every requirement's rather than one's.
    pub fn is_unscoped(&self) -> bool {
        !matches!(
            self,
            Self::ExecutionUnavailable {
                requirement: Some(_),
                ..
            }
        )
    }
}

/// The requirement a publication's signed invocation names. A recovered run
/// must reproduce that invocation exactly (`fields` is compared whole), so a
/// publication can only ever count for this requirement.
fn invoked_requirement(instance: &str, fields: &serde_json::Value) -> Option<String> {
    let invocation = fields["invocation_json"].as_str()?;
    if crate::norm_buck2_execution::is_run_instance(instance) {
        serde_json::from_str::<crate::norm_buck2_execution::Buck2RunRecord>(invocation)
            .ok()
            .map(|record| record.intent.requirement.name)
    } else {
        serde_json::from_str::<crate::norm_execution::NormRunIntent>(invocation)
            .ok()
            .map(|intent| intent.requirement.name)
    }
}

/// One recovered execution of either kind: a Python-call run settled by the
/// executor, or a Buck2 test run re-judged from its durable record. Only
/// recovery constructs either; neither deserializes.
#[derive(Clone, Debug)]
pub enum VerifiedExecution {
    PythonCalls(Box<VerifiedNormExecution>),
    Buck2Tests(Box<VerifiedBuck2Execution>),
}
impl From<VerifiedNormExecution> for VerifiedExecution {
    fn from(execution: VerifiedNormExecution) -> Self {
        Self::PythonCalls(Box::new(execution))
    }
}
impl From<VerifiedBuck2Execution> for VerifiedExecution {
    fn from(execution: VerifiedBuck2Execution) -> Self {
        Self::Buck2Tests(Box::new(execution))
    }
}
impl VerifiedExecution {
    /// Rebuilt from verified history and the captured artifact.
    pub fn contract(&self) -> &ReportContract {
        match self {
            Self::PythonCalls(execution) => execution.contract(),
            Self::Buck2Tests(execution) => execution.contract(),
        }
    }
    /// The adapter's report of what the run observed.
    pub fn report(&self) -> &TestReport {
        match self {
            Self::PythonCalls(execution) => &execution.observation().report,
            Self::Buck2Tests(execution) => execution.report(),
        }
    }
    /// The ledger state the run was prepared against.
    pub fn anchor(&self) -> &whipplescript_store::norm_history::NormReadAnchor {
        match self {
            Self::PythonCalls(execution) => &execution.intent().anchor,
            Self::Buck2Tests(execution) => &execution.intent().anchor,
        }
    }
    fn accepted_by(&self, policy: &dyn ExecutionSelectionPolicy, query: &SelectionQuery) -> bool {
        match self {
            Self::PythonCalls(execution) => policy.accepts(query, execution.as_ref()),
            Self::Buck2Tests(execution) => policy.accepts_buck2_tests(query, execution.as_ref()),
        }
    }
}
impl ReportVerifier for VerifiedExecution {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        match self {
            Self::PythonCalls(execution) => execution.verify_report_binding(report),
            Self::Buck2Tests(execution) => execution.verify_report_binding(report),
        }
    }
    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        match self {
            Self::PythonCalls(execution) => {
                execution.verify_assertion_exercise(report, observation)
            }
            Self::Buck2Tests(execution) => execution.verify_assertion_exercise(report, observation),
        }
    }
}

/// No deserializer: creation requires authenticated history and recovered runs.
pub struct EvidenceProjection {
    ledger: String,
    events: Vec<SelectionEvent>,
    executions: BTreeMap<String, VerifiedExecution>,
    gaps: BTreeMap<String, ProjectionGap>,
}
/// Installed policy must verify exact policy/time, requirement/method and
/// observer integrity. It is not taken from an observation's serialized flags.
pub trait ExecutionSelectionPolicy {
    fn accepts(&self, query: &SelectionQuery, execution: &VerifiedNormExecution) -> bool;
    /// A Buck2 test run is a separate named kind; a policy that does not
    /// name it accepts none.
    fn accepts_buck2_tests(&self, _: &SelectionQuery, _: &VerifiedBuck2Execution) -> bool {
        false
    }
}

impl EvidenceProjection {
    /// `recover` resolves coordinates through host-owned runtime/artifact stores,
    /// normally using PreparedNormExecution::recover_with_artifacts, or
    /// VerifiedBuck2Execution::recover on a host that runs Buck2. Failure is
    /// retained as a gap; it is never interpreted as passing evidence.
    pub fn capture<E: Into<VerifiedExecution>>(
        history: &CapturedNormHistory,
        roles: &BTreeMap<VocabularyRef, ProjectionRole>,
        max_events: usize,
        mut recover: impl FnMut(&str, &str) -> Result<E, String>,
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
                                recover(instance, run).map(Into::into).map_err(|reason| {
                                    ProjectionGap::ExecutionUnavailable {
                                        reason,
                                        requirement: invoked_requirement(instance, &fields),
                                    }
                                })
                            }
                            // MUTATION-SUCCESS-EXPR: recover(fields["instance"].as_str().unwrap_or_default(), fields["run"].as_str().unwrap_or_default()).map(Into::into).map_err(|reason| ProjectionGap::ExecutionUnavailable { reason, requirement: None })
                            _ => Err(ProjectionGap::MalformedPublication),
                        };
                        match verified {
                            Ok(execution) => {
                                use crate::norm_publication::PublishableExecution;
                                if crate::norm_publication::fields(&execution)? != fields
                                    || execution.publisher() != signed.statement.actor.principal
                                    || execution.ledger() != ledger
                                {
                                    result.gaps.insert(
                                        event.event_id.clone(),
                                        ProjectionGap::PublicationMismatch,
                                    );
                                } else {
                                    payload = SelectionPayload::Observation {
                                        contract: execution.contract().clone(),
                                        report: Box::new(execution.report().clone()),
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
    /// The verified execution behind one published observation.
    pub fn execution(&self, event: &str) -> Option<&VerifiedExecution> {
        self.executions.get(event)
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
            .filter(|(id, gap)| {
                selection.history.contains_key(*id) && gap.applies_to(&query.requirement.name)
            })
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
            .any(|e| e.accepted_by(self.policy, self.query) && e.verify_report_binding(report))
    }
    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        self.projection.executions.values().any(|e| {
            e.accepted_by(self.policy, self.query)
                && e.verify_assertion_exercise(report, observation)
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
            .any(|e| e.contract() == contract && e.accepted_by(self.policy, query))
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
