//! Source-addressable explanations for one captured managed progression.
//!
//! This is a pure projection over the same plan and [`Progression`] that drive
//! managed work. It creates no work, reads no current store state and does not
//! infer branch selection from a missing runtime row. Failure payloads never
//! cross this boundary. Witness identities cross only when the caller supplies
//! an audience-filtered allow-list.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use whipplescript_parser::action_plan::{
    ActionPlan, BindingId, BindingSource, BlockId, NodeId, NodeKind,
};
use whipplescript_parser::body::BodyStmt;
use whipplescript_parser::SourceSpan;
use whipplescript_store::{RuntimeStore, StoreError, StoreResult};

use super::arguments::{Slot, State};
use super::journal::Frame;
use super::progression::Progression;
use super::{Cause, CauseId, Disposition, FailureKind, ObservedCause, WorkState};

pub mod query;

pub const SCHEMA: &str = "whipplescript.action-explanation.v1";

/// Project every managed firing retained by an instance at its current log
/// frontier. Each firing uses its own immutable executable version and the
/// exact root/context journaled when it was admitted. This is a read: it does
/// not advance the instance, publish a phase cut, or authorize any work.
pub fn project_instance<S: RuntimeStore>(
    store: &S,
    instance_id: &str,
    coercion_fingerprint: &str,
    visible_witnesses: &BTreeSet<String>,
) -> StoreResult<Vec<Explanation>> {
    if store.get_instance(instance_id)?.is_none() {
        return Err(StoreError::Conflict(format!(
            "instance `{instance_id}` does not exist"
        )));
    }
    let events = store.list_events(instance_id)?;
    let frontier = events.last().map_or(0, |event| event.sequence);
    let prefix = store.projection_prefix(instance_id, frontier)?;
    let mut journal = super::journal::Journal::default();
    for event in &prefix.events {
        journal
            .apply(event)
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
    }

    let admissions = prefix
        .events
        .iter()
        .filter(|event| event.event_type == "rule.committed")
        .filter_map(|event| {
            let payload: serde_json::Value = serde_json::from_str(&event.payload_json).ok()?;
            let rule = payload.get("rule")?.as_str()?.to_owned();
            let version = payload.get("program_version_id")?.as_str()?.to_owned();
            let epoch = payload
                .get("revision_epoch")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or_default();
            let context = payload
                .get("context")
                .and_then(crate::rule_lowering::context_from_record)?;
            Some((version, rule, epoch, context))
        })
        .collect::<Vec<_>>();

    let frames = journal.admitted_frames().cloned().collect::<Vec<_>>();
    let mut programs = BTreeMap::new();
    for frame in &frames {
        if programs.contains_key(&frame.version) {
            continue;
        }
        match crate::program_artifact::load_recorded_version(store, &frame.version)? {
            crate::program_artifact::RecordedLoad::Ready(program) => {
                programs.insert(frame.version.clone(), program);
            }
            crate::program_artifact::RecordedLoad::Unavailable(detail) => {
                return Err(StoreError::Conflict(format!(
                    "cannot explain managed firing under program version `{}`: {detail}",
                    frame.version
                )));
            }
        }
    }

    let mut explanations = Vec::new();
    for frame in &frames {
        let executable = programs
            .get(&frame.version)
            .expect("every admitted frame version was loaded");
        let Some(typed) = executable.typed_actions().get(&frame.rule) else {
            return Err(StoreError::Conflict(format!(
                "cannot explain managed firing `{}`: program version `{}` has no typed action plan for its rule",
                frame.rule, frame.version
            )));
        };
        let (_, _, epoch, admission) = admissions
            .iter()
            .find(|(version, rule, _, context)| {
                version == &frame.version
                    && rule == &frame.rule
                    && context.identity == frame.identity
                    && context.trigger_event_id == frame.trigger_event
            })
            .expect("an admitted journal frame came from a commit with the same pinned context");
        let progression = super::rule::project_regions_from_store(
            store,
            super::rule::StoredContext {
                ir: executable.program(),
                typed,
                instance: instance_id,
                frame,
                admission,
                journal: &journal,
                coercion_fingerprint,
                source_path: None,
            },
            frontier,
        )
        .map_err(|error| StoreError::Conflict(error.to_string()))?;
        explanations.push(
            project(
                &typed.plan,
                &progression,
                instance_id,
                frame,
                *epoch,
                visible_witnesses,
            )
            .map_err(StoreError::Conflict)?,
        );
    }
    Ok(explanations)
}

#[cfg(all(test, feature = "native"))]
mod native_tests;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Explanation {
    pub schema: String,
    pub instance_id: String,
    pub program_version_id: String,
    pub revision: String,
    pub revision_epoch: i64,
    pub rule: String,
    pub firing: Firing,
    pub evaluated_frontier: i64,
    pub results: Vec<ResultExplanation>,
    pub causes: Vec<CauseExplanation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Firing {
    pub identity: Option<String>,
    pub trigger_event: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultStatus {
    Ready,
    Waiting,
    Failed,
    Uncertain,
    NotSelected,
    NotReached,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    ValueAvailable,
    WaitingInput,
    WaitingOperation,
    CancellationAcknowledgement,
    UncertainOutcome,
    Recovery,
    ExecutionFailure,
    NotSelected,
    NotReached,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceRole {
    CallSite,
    Definition,
    Result,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReference {
    pub role: SourceRole,
    pub action: Option<String>,
    pub node: Option<u64>,
    pub span: SourceSpan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyReference {
    pub binding: u64,
    pub result_id: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultExplanation {
    pub result_id: String,
    pub name: String,
    pub binding: u64,
    pub operation_id: Option<String>,
    pub status: ResultStatus,
    pub reasons: Vec<ReasonCode>,
    pub waiting_on: Vec<DependencyReference>,
    pub cause_ids: Vec<String>,
    pub validity_observations: usize,
    /// Call sites are ordered outermost first, followed by the definition and
    /// the result site. Consumers can lead with the authored call and defer
    /// internal detail without reconstructing a stack from spans.
    pub source: Vec<SourceReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CauseKind {
    Failed,
    TimedOut,
    Cancelled,
    Domain,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CauseExplanation {
    pub cause_id: String,
    pub kind: CauseKind,
    pub recovered: bool,
    pub dependents: Vec<String>,
    pub witness_refs: Vec<String>,
    pub witnesses_complete: bool,
}

#[derive(Clone, Copy)]
struct ParentBlock {
    controller: NodeId,
    parent: BlockId,
}

struct ResultDraft {
    explanation: ResultExplanation,
    cause_ids: BTreeSet<CauseId>,
}

struct Projector<'a> {
    plan: &'a ActionPlan,
    progression: &'a Progression,
    parent_blocks: &'a BTreeMap<BlockId, ParentBlock>,
    result_ids: &'a BTreeMap<BindingId, String>,
    instance_id: &'a str,
    frame: &'a Frame,
}

/// Project every authored result binding in one firing. Repeated helper calls
/// remain distinct because result and operation identities include the expanded
/// structural node and the full firing frame.
pub fn project(
    plan: &ActionPlan,
    progression: &Progression,
    instance_id: &str,
    frame: &Frame,
    revision_epoch: i64,
    visible_witnesses: &BTreeSet<String>,
) -> Result<Explanation, String> {
    plan.validate_structure()
        .map_err(|issue| format!("invalid action plan for explanation: {issue}"))?;

    let parent_blocks = parent_blocks(plan);
    let result_ids: BTreeMap<BindingId, String> = plan
        .bindings
        .iter()
        .enumerate()
        .filter_map(|(index, binding)| {
            let id = BindingId(index);
            binding
                .name
                .as_ref()
                .filter(|_| matches!(binding.source, BindingSource::Node(_)))
                .map(|_| (id, result_identity(instance_id, frame, id)))
        })
        .collect();

    let known_causes = known_causes(progression);
    let mut dependents = BTreeMap::<CauseId, BTreeSet<String>>::new();
    let mut results = Vec::new();
    let projector = Projector {
        plan,
        progression,
        parent_blocks: &parent_blocks,
        result_ids: &result_ids,
        instance_id,
        frame,
    };
    for (&binding, result_id) in &result_ids {
        let Some(name) = plan.bindings[binding.0].name.clone() else {
            continue;
        };
        let BindingSource::Node(node) = plan.bindings[binding.0].source else {
            continue;
        };
        let draft = projector.explain_result(binding, node, result_id.clone(), name);
        for cause in &draft.cause_ids {
            dependents
                .entry(cause.clone())
                .or_default()
                .insert(result_id.clone());
        }
        results.push(draft.explanation);
    }

    let causes = dependents
        .into_iter()
        .map(|(id, dependents)| {
            let observed = known_causes.get(&id);
            let evidence = observed
                .map(|observed| &observed.cause.evidence)
                .into_iter()
                .flatten();
            let witness_refs: Vec<_> = evidence
                .clone()
                .filter(|witness| visible_witnesses.contains(*witness))
                .cloned()
                .collect();
            let witnesses_complete = observed.is_some_and(|observed| {
                observed
                    .cause
                    .evidence
                    .iter()
                    .all(|witness| visible_witnesses.contains(witness))
            });
            CauseExplanation {
                cause_id: id.0,
                kind: observed.map_or(CauseKind::Unknown, |observed| cause_kind(&observed.cause)),
                recovered: observed.is_some_and(|observed| observed.recovered),
                dependents: dependents.into_iter().collect(),
                witness_refs,
                witnesses_complete,
            }
        })
        .collect();

    Ok(Explanation {
        schema: SCHEMA.into(),
        instance_id: instance_id.into(),
        program_version_id: frame.version.clone(),
        revision: frame.revision.clone(),
        revision_epoch,
        rule: frame.rule.clone(),
        firing: Firing {
            identity: frame.identity.clone(),
            trigger_event: frame.trigger_event.clone(),
        },
        evaluated_frontier: progression.frontier,
        results,
        causes,
    })
}

impl Projector<'_> {
    fn explain_result(
        &self,
        binding: BindingId,
        node: NodeId,
        result_id: String,
        name: String,
    ) -> ResultDraft {
        let plan = self.plan;
        let progression = self.progression;
        let mut reasons = BTreeSet::new();
        let mut causes = BTreeSet::new();
        let mut waiting = BTreeSet::new();
        let mut validity_observations = 0;

        let status = if !progression
            .active_blocks
            .contains(&plan.nodes[node.0].block)
        {
            let status = inactive_status(plan, progression, self.parent_blocks, node);
            reasons.insert(if status == ResultStatus::NotSelected {
                ReasonCode::NotSelected
            } else {
                ReasonCode::NotReached
            });
            status
        } else if let Some(slot) = progression.bindings.get(&binding) {
            match slot {
                Slot::Ready(argument) => {
                    if let Some(work) = progression.owned.get(&node) {
                        causes.extend(work.causes.keys().cloned());
                    }
                    reasons.insert(ReasonCode::ValueAvailable);
                    validity_observations = argument.validity.len();
                    ResultStatus::Ready
                }
                Slot::Failed(found) => {
                    causes.extend(found.iter().cloned());
                    reasons.insert(ReasonCode::ExecutionFailure);
                    ResultStatus::Failed
                }
                Slot::Pending => {
                    operation_status(progression, node, &mut reasons, &mut causes, &mut waiting)
                }
            }
        } else {
            operation_status(progression, node, &mut reasons, &mut causes, &mut waiting)
        };

        let mut waiting_on = waiting
            .into_iter()
            .map(|dependency| DependencyReference {
                binding: dependency.0 as u64,
                result_id: self.result_ids.get(&dependency).cloned(),
                name: plan
                    .bindings
                    .get(dependency.0)
                    .and_then(|binding| binding.name.clone()),
            })
            .chain(self.owned_work_waits(node))
            .collect::<Vec<_>>();
        waiting_on.sort_by_key(|dependency| dependency.binding);
        waiting_on.dedup_by_key(|dependency| dependency.binding);
        let is_operation = match &plan.nodes[node.0].kind {
            NodeKind::Call { .. } => true,
            NodeKind::Statement(body) => matches!(body.as_ref(), BodyStmt::Effect(_)),
            _ => false,
        };
        let operation_id = is_operation
            .then(|| super::progression::operation_identity(self.instance_id, self.frame, node));

        ResultDraft {
            explanation: ResultExplanation {
                result_id,
                name,
                binding: binding.0 as u64,
                operation_id,
                status,
                reasons: reasons.into_iter().collect(),
                waiting_on,
                cause_ids: causes.iter().map(|cause| cause.0.clone()).collect(),
                validity_observations,
                source: source_references(plan, binding, node),
            },
            cause_ids: causes,
        }
    }

    /// A call result can have its value ready while its action boundary still
    /// waits for work the action started. Surface those direct children as
    /// dependencies of the call result so a consumer can point at the actual
    /// operation instead of stopping at the generated action boundary.
    fn owned_work_waits(&self, node: NodeId) -> Vec<DependencyReference> {
        let NodeKind::Call { scope, .. } = self.plan.nodes[node.0].kind else {
            return Vec::new();
        };
        self.plan.scopes[scope.0]
            .operations
            .iter()
            .filter_map(|operation| {
                let work = self.progression.owned.get(operation)?;
                if !matches!(
                    work.state,
                    WorkState::Pending
                        | WorkState::CancellationRequested
                        | WorkState::Uncertain
                        | WorkState::Failed(Disposition::Recovering)
                ) {
                    return None;
                }
                let binding = self.plan.nodes[operation.0].result?;
                Some(DependencyReference {
                    binding: binding.0 as u64,
                    result_id: self.result_ids.get(&binding).cloned(),
                    name: self.plan.bindings[binding.0].name.clone(),
                })
            })
            .collect()
    }
}

fn operation_status(
    progression: &Progression,
    node: NodeId,
    reasons: &mut BTreeSet<ReasonCode>,
    causes: &mut BTreeSet<CauseId>,
    waiting: &mut BTreeSet<BindingId>,
) -> ResultStatus {
    if let Some(work) = progression.owned.get(&node) {
        causes.extend(work.causes.keys().cloned());
        return match work.state {
            WorkState::Pending => {
                reasons.insert(ReasonCode::WaitingOperation);
                ResultStatus::Waiting
            }
            WorkState::CancellationRequested => {
                reasons.insert(ReasonCode::CancellationAcknowledgement);
                ResultStatus::Waiting
            }
            WorkState::Uncertain => {
                reasons.insert(ReasonCode::UncertainOutcome);
                ResultStatus::Uncertain
            }
            WorkState::Succeeded | WorkState::Failed(Disposition::Recovered) => {
                reasons.insert(ReasonCode::NotReached);
                ResultStatus::NotReached
            }
            WorkState::Failed(Disposition::Recovering) => {
                reasons.insert(ReasonCode::Recovery);
                ResultStatus::Waiting
            }
            WorkState::Failed(Disposition::Propagate) => {
                reasons.insert(ReasonCode::ExecutionFailure);
                ResultStatus::Failed
            }
        };
    }
    if let Some(evaluation) = progression.waiting.get(&node) {
        match &evaluation.state {
            State::Blocked {
                waiting: blocked,
                causes: failed,
            } => {
                waiting.extend(blocked.iter().copied());
                causes.extend(failed.iter().cloned());
                if blocked.is_empty() {
                    reasons.insert(ReasonCode::ExecutionFailure);
                    return ResultStatus::Failed;
                }
                reasons.insert(ReasonCode::WaitingInput);
                return ResultStatus::Waiting;
            }
            State::Ready(_) | State::Absent | State::Invalid(_) => {}
        }
    }
    reasons.insert(ReasonCode::NotReached);
    ResultStatus::NotReached
}

fn inactive_status(
    plan: &ActionPlan,
    progression: &Progression,
    parents: &BTreeMap<BlockId, ParentBlock>,
    node: NodeId,
) -> ResultStatus {
    let mut block = plan.nodes[node.0].block;
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(block) {
            return ResultStatus::NotReached;
        }
        if let Some(parent) = parents.get(&block) {
            if let Some(selected) = progression.selected_blocks.get(&parent.controller) {
                if *selected != Some(block) {
                    return ResultStatus::NotSelected;
                }
            }
            block = parent.parent;
            continue;
        }
        let Some(scope) = plan.blocks.get(block.0).and_then(|block| block.scope) else {
            return ResultStatus::NotReached;
        };
        let Some(call) = plan.scopes.get(scope.0).and_then(|scope| scope.parent_call) else {
            return ResultStatus::NotReached;
        };
        block = plan.nodes[call.0].block;
    }
}

fn parent_blocks(plan: &ActionPlan) -> BTreeMap<BlockId, ParentBlock> {
    let mut parents = BTreeMap::new();
    for (index, node) in plan.nodes.iter().enumerate() {
        let controller = NodeId(index);
        let mut add = |child| {
            parents.insert(
                child,
                ParentBlock {
                    controller,
                    parent: node.block,
                },
            );
        };
        match &node.kind {
            NodeKind::After { body, .. } => add(*body),
            NodeKind::OnFailure { body, .. } => add(*body),
            NodeKind::Case { branches, .. } => {
                for branch in branches {
                    add(branch.body);
                }
            }
            NodeKind::Region {
                body, lapse_body, ..
            } => {
                add(*body);
                add(*lapse_body);
            }
            NodeKind::Statement(_)
            | NodeKind::Call { .. }
            | NodeKind::Return(_)
            | NodeKind::Fail(_) => {}
        }
    }
    parents
}

fn source_references(plan: &ActionPlan, binding: BindingId, node: NodeId) -> Vec<SourceReference> {
    let mut calls = Vec::new();
    let mut scope = plan.blocks[plan.nodes[node.0].block.0].scope;
    let current_scope = scope;
    while let Some(id) = scope {
        let Some(call) = plan.scopes[id.0].parent_call else {
            break;
        };
        let action = match &plan.nodes[call.0].kind {
            NodeKind::Call { scope, .. } => Some(plan.scopes[scope.0].action.clone()),
            _ => None,
        };
        calls.push(SourceReference {
            role: SourceRole::CallSite,
            action,
            node: Some(call.0 as u64),
            span: plan.nodes[call.0].span,
        });
        scope = plan.blocks[plan.nodes[call.0].block.0].scope;
    }
    calls.reverse();
    if let Some(scope) = current_scope {
        calls.push(SourceReference {
            role: SourceRole::Definition,
            action: Some(plan.scopes[scope.0].action.clone()),
            node: None,
            span: plan.scopes[scope.0].definition_span,
        });
    }
    calls.push(SourceReference {
        role: SourceRole::Result,
        action: current_scope.map(|scope| plan.scopes[scope.0].action.clone()),
        node: Some(node.0 as u64),
        span: plan.bindings[binding.0].span,
    });
    calls
}

fn known_causes(progression: &Progression) -> BTreeMap<CauseId, ObservedCause> {
    let mut causes = BTreeMap::new();
    for observed in progression
        .owned
        .values()
        .flat_map(|work| work.causes.iter())
        .chain(
            progression
                .scopes
                .values()
                .flat_map(|scope| scope.causes.iter()),
        )
        .chain(progression.root.causes.iter())
    {
        let (id, observed) = observed;
        causes
            .entry(id.clone())
            .and_modify(|known: &mut ObservedCause| known.recovered &= observed.recovered)
            .or_insert_with(|| observed.clone());
    }
    causes
}

fn cause_kind(cause: &Cause) -> CauseKind {
    match cause.kind {
        FailureKind::Failed => CauseKind::Failed,
        FailureKind::TimedOut => CauseKind::TimedOut,
        FailureKind::Cancelled => CauseKind::Cancelled,
        FailureKind::Domain => CauseKind::Domain,
    }
}

fn result_identity(instance_id: &str, frame: &Frame, binding: BindingId) -> String {
    crate::idempotency_key(&[
        instance_id,
        "source-result-v1",
        &serde_json::to_string(frame).unwrap_or_default(),
        &binding.0.to_string(),
    ])
}

#[cfg(test)]
mod tests;
