//! Traversal of one captured source progression. Ordinary statement projection
//! remains supplied by the owning lowerer; it must be pure over this same
//! prefix. No provider, independent scheduler, or action-status store lives here.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use whipplescript_parser::action_plan::{
    ActionPlan, BindingId, BlockId, Environment, NodeId, NodeKind, ScopeId,
};
use whipplescript_parser::body::{AfterPredicate, BodyStmt};
use whipplescript_parser::{parse_expression, SourceSpan};

use super::arguments::{
    evaluate_with_context, prepare_call_with_queries, read_binding, Argument, Bindings, Evaluation,
    OutcomeContext, QueryContext, Slot, State, ValueSource,
};
use super::journal::{Frame, Journal};
use super::{
    project, Boundary, Cause, CauseId, ChosenResult, Disposition, FailureKind, OwnedWork,
    Projection, WorkState,
};
use crate::lowering::OwnedLowering;

mod cases;
mod recovery;

/// A projection/draft from the ordinary statement lowerer. Ready means payload
/// evaluation is complete, not that external work succeeded. A new effect has
/// pending owned work; an existing effect carries its actual observed work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Leaf {
    Waiting(Evaluation),
    Ready {
        lowering: Box<OwnedLowering>,
        value: Option<Argument>,
        work: Option<OwnedWork>,
    },
}

pub struct Statement<'a> {
    pub node: NodeId,
    pub root_rule: Option<&'a str>,
    pub admitted: &'a Bindings,
    pub identity: String,
    pub body: &'a BodyStmt,
    pub environment: &'a Environment,
    pub bindings: &'a Bindings,
    pub queries: Option<QueryContext<'a>>,
    pub outcomes: Option<OutcomeContext<'a>>,
}

impl Statement<'_> {
    pub fn evaluate(&self, expr: &whipplescript_parser::Expr) -> Evaluation {
        evaluate_with_context(
            expr,
            self.environment,
            self.bindings,
            self.queries,
            self.outcomes,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgressionError {
    pub node: NodeId,
    pub span: SourceSpan,
    pub message: String,
    pub evaluation: Option<Box<Evaluation>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Progression {
    /// Commit this lowering at this frontier with evaluated_frontier set,
    /// including passes that add no new call capture.
    pub frontier: i64,
    pub lowering: OwnedLowering,
    pub bindings: Bindings,
    pub scopes: BTreeMap<ScopeId, Projection<Argument>>,
    pub root: Projection<()>,
    /// Actual selected operations, including nested call boundaries and their
    /// leaf work. Leaves retain original observations; call boundaries carry their
    /// scope projections. Region selection does not apply lexical recovery.
    pub owned: BTreeMap<NodeId, OwnedWork>,
    /// The exact return/fail node selected in each active action scope. This
    /// remains visible even while owned work keeps the scope from settling.
    pub chosen_results: BTreeMap<ScopeId, (NodeId, ChosenResult<Argument>)>,
    pub active_blocks: BTreeSet<BlockId>,
    pub selected_blocks: BTreeMap<NodeId, Option<BlockId>>,
    /// Current pure condition observations for reached unentered or holding
    /// regions. The phase driver consumes these observations when deciding an
    /// atomic holding, exit, or lapse cut; captured read projection never does.
    pub region_conditions: BTreeMap<NodeId, Evaluation>,
    /// Reached holding regions whose selected held graph is closed and whose
    /// actual owned children all have terminal evidence at this frontier.
    pub region_complete: BTreeSet<NodeId>,
    pub waiting: BTreeMap<NodeId, Evaluation>,
}

/// Exact held-prefix selections retained while projecting a later lapse. Work
/// states may be refreshed from today's ledger, but membership and result
/// candidates come only from the recorded held frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetainedRegion {
    pub owned: BTreeMap<NodeId, OwnedWork>,
    pub results: BTreeMap<ScopeId, (NodeId, ChosenResult<Argument>)>,
    pub progress: Argument,
}

pub fn operation_identity(instance: &str, frame: &Frame, node: NodeId) -> String {
    crate::idempotency_key(&[
        instance,
        "source-operation-v1",
        &serde_json::json!(frame).to_string(),
        &node.0.to_string(),
    ])
}

fn error(plan: &ActionPlan, node: NodeId, message: impl Into<String>) -> ProgressionError {
    ProgressionError {
        node,
        span: plan
            .nodes
            .get(node.0)
            .map_or(SourceSpan { start: 0, end: 0 }, |node| node.span),
        message: message.into(),
        evaluation: None,
    }
}

fn evaluated(
    plan: &ActionPlan,
    node: NodeId,
    value: Evaluation,
) -> Result<Evaluation, ProgressionError> {
    if let State::Invalid(issue) = &value.state {
        return Err(ProgressionError {
            evaluation: Some(Box::new(value.clone())),
            ..error(plan, node, issue.message.clone())
        });
    }
    Ok(value)
}

fn expression(
    plan: &ActionPlan,
    node: NodeId,
    source: &str,
    environment: &Environment,
    bindings: &Bindings,
    queries: Option<QueryContext<'_>>,
    outcomes: Option<OutcomeContext<'_>>,
) -> Result<Evaluation, ProgressionError> {
    let expr = parse_expression(source).map_err(|message| error(plan, node, message))?;
    let value = evaluate_with_context(&expr, environment, bindings, queries, outcomes);
    evaluated(plan, node, value)
}

fn argument(value: &Evaluation) -> Option<Argument> {
    match &value.state {
        State::Ready(value_json) => Some(Argument {
            value: value_json.clone(),
            sources: value.sources.clone(),
            subjects: value.subjects.clone(),
            validity: value.validity.clone(),
        }),
        State::Absent => Some(Argument {
            value: Value::Null,
            sources: value.sources.clone(),
            subjects: Default::default(),
            validity: value.validity.clone(),
        }),
        _ => None,
    }
}

/// Failure suppresses a dependent success path. An unresolved input keeps it
/// open, even when another input has already failed; both remain explainable.
fn resolved_obstruction(value: &Evaluation) -> bool {
    matches!(&value.state, State::Blocked { waiting, causes } if waiting.is_empty() && !causes.is_empty())
}

/// Suppressed work has an unavailable value, not an invented operation terminal.
fn suppress_result(bindings: &mut Bindings, binding: Option<BindingId>, value: &Evaluation) {
    if let (Some(binding), State::Blocked { causes, .. }) = (binding, &value.state) {
        bindings.insert(binding, Slot::Failed(causes.clone()));
    }
}

fn bind_result(
    bindings: &mut Bindings,
    binding: Option<BindingId>,
    value: Option<&Argument>,
    work: &OwnedWork,
    identity: &str,
) -> Result<(), &'static str> {
    let Some(binding) = binding else {
        return Ok(());
    };
    let slot = match work.state {
        WorkState::Succeeded | WorkState::Failed(Disposition::Recovered) => {
            let Some(value) = value else {
                // MUTATION-SUCCESS-EXPR: Ok(())
                return Err("successful operation has no result value");
            };
            let mut value = value.clone();
            value.sources.insert(ValueSource::Operation {
                operation_id: identity.into(),
            });
            Slot::Ready(value)
        }
        WorkState::Failed(Disposition::Propagate) => Slot::Failed(
            work.causes
                .iter()
                .filter(|(_, cause)| !cause.recovered)
                .map(|(id, _)| id.clone())
                .collect(),
        ),
        WorkState::Pending
        | WorkState::CancellationRequested
        | WorkState::Uncertain
        | WorkState::Failed(Disposition::Recovering) => Slot::Pending,
    };
    bindings.insert(binding, slot);
    Ok(())
}

/// Returns the selected pattern payload without introducing a synthetic fact.
/// Nominal record selection needs the compiler's type metadata; the
/// current source gate stays closed while that integration is unfinished.
fn pattern_value(pattern: &str, value: &Argument) -> Result<Option<Argument>, &'static str> {
    if matches!(pattern, "_" | "default") {
        return Ok(Some(value.clone()));
    }
    if pattern == "None" {
        return Ok(value.value.is_null().then(|| value.clone()));
    }
    if pattern == "Some" {
        return Ok((!value.value.is_null()).then(|| value.clone()));
    }
    if let Some(tag) = value.value.get("tag").and_then(Value::as_str) {
        return Ok((tag == pattern).then(|| {
            let mut payload = value.clone();
            payload.value = crate::rule_lowering::terminal_payload_for_tag(&value.value, tag);
            payload
        }));
    }
    if value.value.is_object() {
        return Err("managed class patterns require resolved type metadata");
    }
    Ok((crate::rule_lowering::parse_guard_literal(pattern) == value.value).then(|| value.clone()))
}

fn merge(
    plan: &ActionPlan,
    node: NodeId,
    target: &mut OwnedLowering,
    mut source: OwnedLowering,
    allow_terminal: bool,
) -> Result<(), ProgressionError> {
    if source.action_root.is_some()
        || !source.action_captures.is_empty()
        || !source.action_regions.is_empty()
        || source.internal_fail.is_some()
        || !source.unhandled_failures.is_empty()
    {
        return Err(error(
            plan,
            node,
            "statement lowering cannot own action captures or scope failure propagation",
        ));
    }
    if allow_terminal && source.terminal.is_some() {
        if target.terminal.is_some() {
            return Err(error(plan, node, "two selected workflow terminals"));
        }
        target.terminal = source.terminal.take();
    }
    for fact in source.facts {
        if let Some(previous) = target
            .facts
            .iter()
            .find(|known| known.fact_id == fact.fact_id)
        {
            let mut comparable = fact.clone();
            comparable
                .source_span_json
                .clone_from(&previous.source_span_json);
            if previous != &comparable {
                return Err(error(
                    plan,
                    node,
                    "conflicting assertions under one fact identity",
                ));
            }
        } else {
            target.facts.push(fact);
        }
    }
    for fact in source.consumed_fact_ids {
        if !target.consumed_fact_ids.contains(&fact) {
            target.consumed_fact_ids.push(fact);
        }
    }
    target.effects.extend(source.effects);
    target.dependencies.extend(source.dependencies);
    target.branch_reports.extend(source.branch_reports);
    target.errors.extend(source.errors);
    target.cancels.extend(source.cancels);
    Ok(())
}

/// The plan must have passed source type/authority checks. `project_statement`
/// projects/drafts ordinary statements at this prefix; it performs no I/O and
/// never commits. The returned lowering still passes the shared guarded door.
pub fn advance(
    plan: &ActionPlan,
    instance: &str,
    frame: &Frame,
    frontier: i64,
    inputs: &Bindings,
    journal: &Journal,
    project_statement: impl Fn(Statement<'_>) -> Result<Leaf, String>,
) -> Result<Progression, ProgressionError> {
    advance_resolved(
        plan,
        None,
        instance,
        frame,
        frontier,
        inputs,
        journal,
        None,
        false,
        &BTreeMap::new(),
        project_statement,
    )
}

/// Untyped structural counterpart used by source-plan tests and consumers
/// that do not evaluate typed cases. It has the same read-only region contract
/// as `advance_typed_with_regions` when captured regions are enabled.
#[cfg(test)]
pub(crate) fn advance_captured_regions(
    plan: &ActionPlan,
    instance: &str,
    frame: &Frame,
    frontier: i64,
    inputs: &Bindings,
    journal: &Journal,
    project_statement: impl Fn(Statement<'_>) -> Result<Leaf, String>,
) -> Result<Progression, ProgressionError> {
    advance_resolved(
        plan,
        None,
        instance,
        frame,
        frontier,
        inputs,
        journal,
        None,
        true,
        &BTreeMap::new(),
        project_statement,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_captured_regions_with_retained(
    plan: &ActionPlan,
    instance: &str,
    frame: &Frame,
    frontier: i64,
    inputs: &Bindings,
    journal: &Journal,
    retained_regions: &BTreeMap<NodeId, RetainedRegion>,
    project_statement: impl Fn(Statement<'_>) -> Result<Leaf, String>,
) -> Result<Progression, ProgressionError> {
    advance_resolved(
        plan,
        None,
        instance,
        frame,
        frontier,
        inputs,
        journal,
        None,
        true,
        retained_regions,
        project_statement,
    )
}

/// Consumes compiler-resolved case types with the pinned program schemas.
#[allow(clippy::too_many_arguments)]
pub fn advance_typed(
    typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
    ir: &whipplescript_parser::IrProgram,
    instance: &str,
    frame: &Frame,
    frontier: i64,
    inputs: &Bindings,
    journal: &Journal,
    project_statement: impl Fn(Statement<'_>) -> Result<Leaf, String>,
) -> Result<Progression, ProgressionError> {
    advance_typed_with_regions(
        typed,
        ir,
        instance,
        frame,
        frontier,
        inputs,
        journal,
        None,
        false,
        project_statement,
    )
}

/// Read-only reconstruction for a captured region frontier. The caller must
/// have selected a journal and fact/effect prefix from that same frontier.
/// This admits no phase transition and produces no permission to commit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_typed_with_regions(
    typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
    ir: &whipplescript_parser::IrProgram,
    instance: &str,
    frame: &Frame,
    frontier: i64,
    inputs: &Bindings,
    journal: &Journal,
    queries: Option<QueryContext<'_>>,
    captured_regions: bool,
    project_statement: impl Fn(Statement<'_>) -> Result<Leaf, String>,
) -> Result<Progression, ProgressionError> {
    advance_typed_with_retained_regions(
        typed,
        ir,
        instance,
        frame,
        frontier,
        inputs,
        journal,
        queries,
        captured_regions,
        &BTreeMap::new(),
        project_statement,
    )
}

/// Captured region projection with exact held-prefix selections supplied by
/// the store-backed phase driver for any later lapse at this frontier.
#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_typed_with_retained_regions(
    typed: &whipplescript_parser::action_plan::resolved::TypedActionPlan,
    ir: &whipplescript_parser::IrProgram,
    instance: &str,
    frame: &Frame,
    frontier: i64,
    inputs: &Bindings,
    journal: &Journal,
    queries: Option<QueryContext<'_>>,
    captured_regions: bool,
    retained_regions: &BTreeMap<NodeId, RetainedRegion>,
    project_statement: impl Fn(Statement<'_>) -> Result<Leaf, String>,
) -> Result<Progression, ProgressionError> {
    typed
        .validate_structure()
        .map_err(|message| error(&typed.plan, NodeId(0), message))?;
    advance_resolved(
        &typed.plan,
        Some((ir, &typed.case_types)),
        instance,
        frame,
        frontier,
        inputs,
        journal,
        queries,
        captured_regions,
        retained_regions,
        project_statement,
    )
}

#[allow(clippy::too_many_arguments)]
fn advance_resolved(
    plan: &ActionPlan,
    types: Option<(
        &whipplescript_parser::IrProgram,
        &BTreeMap<NodeId, whipplescript_parser::IrType>,
    )>,
    instance: &str,
    frame: &Frame,
    frontier: i64,
    inputs: &Bindings,
    journal: &Journal,
    queries: Option<QueryContext<'_>>,
    captured_regions: bool,
    retained_regions: &BTreeMap<NodeId, RetainedRegion>,
    project_statement: impl Fn(Statement<'_>) -> Result<Leaf, String>,
) -> Result<Progression, ProgressionError> {
    let (mut bindings, root_capture) =
        super::journal::root::prepare(plan, inputs, journal.root(frame), frontier)
            .map_err(|issue| error(plan, NodeId(0), issue.0))?;
    let admitted = bindings.clone();
    let regions = super::regions::Layout::build(plan)
        .map_err(|issue| error(plan, NodeId(0), format!("invalid region layout: {issue}")))?;
    for region in journal
        .regions(frame)
        .into_iter()
        .flat_map(|regions| regions.keys())
    {
        let node = NodeId(usize::try_from(*region).unwrap_or(usize::MAX));
        if regions.region(node).is_none() {
            return Err(error(
                plan,
                node,
                "recorded region is absent from its source plan",
            ));
        }
    }
    for (index, node) in plan.nodes.iter().enumerate() {
        match &node.kind {
            NodeKind::Region { .. } if !captured_regions => {
                return Err(error(
                    plan,
                    NodeId(index),
                    "managed region entry/lapse history is not implemented",
                ))
            }
            NodeKind::After {
                observed,
                predicate,
                alias,
                ..
            } => {
                recovery::preflight(plan, NodeId(index), *observed, *predicate, *alias)?;
            }
            _ => {}
        }
    }
    if let Some(calls) = journal.calls(frame) {
        for capture in calls.values() {
            if capture.call >= plan.nodes.len() as u64
                || !matches!(
                    plan.nodes.get(capture.call as usize).map(|node| &node.kind),
                    Some(NodeKind::Call { .. })
                )
                || capture
                    .reads
                    .iter()
                    .any(|read| *read >= plan.bindings.len() as u64)
            {
                return Err(error(
                    plan,
                    NodeId(usize::try_from(capture.call).unwrap_or(usize::MAX)),
                    "recorded call or read is absent from its source plan",
                ));
            }
        }
    }
    if journal.root(frame).is_none() && journal.calls(frame).is_some() {
        return Err(error(
            plan,
            NodeId(0),
            "recorded action calls have no admitted root capture",
        ));
    }
    let parents = recovery::block_parents(plan);
    let mut active_blocks = BTreeSet::from([plan.root]);
    let mut calls = BTreeMap::new();
    let mut scopes = BTreeMap::<ScopeId, Projection<Argument>>::new();
    let mut waiting = BTreeMap::new();
    let mut leaves = BTreeMap::new();
    let mut resolved = BTreeSet::new();
    let mut selected = BTreeMap::new();
    let mut region_conditions = BTreeMap::new();
    let mut chosen = BTreeMap::<ScopeId, (NodeId, ChosenResult<Argument>)>::new();
    let mut owned = BTreeMap::<NodeId, OwnedWork>::new();
    let mut retained_applied = BTreeSet::new();

    // Activation and immutable value availability are monotone. Each pass
    // either activates a node or carries a child's result toward its parent.
    for round in 0..=plan.nodes.len() + plan.scopes.len() + 1 {
        let before = (
            bindings.clone(),
            active_blocks.clone(),
            scopes.clone(),
            resolved.clone(),
            owned.clone(),
            leaves.clone(),
            waiting.clone(),
        );
        for (index, node) in plan.nodes.iter().enumerate() {
            let id = NodeId(index);
            if !active_blocks.contains(&node.block) {
                continue;
            }
            if captured_regions {
                if let Some(predecessor) = regions.exit_before(id) {
                    let exited = journal
                        .region(frame, predecessor.0 as u64)
                        .and_then(|history| history.latest())
                        .is_some_and(|cut| cut.phase == super::journal::regions::Phase::Exited);
                    if !exited {
                        continue;
                    }
                }
            }
            let environment = &plan.blocks[node.block.0].environment;
            if let Some(before) = node.order_after {
                if !calls.contains_key(&id)
                    && !journal
                        .calls(frame)
                        .is_some_and(|recorded| recorded.contains_key(&(id.0 as u64)))
                {
                    let binding = plan.nodes[before.0]
                        .result
                        .ok_or_else(|| error(plan, id, "success barrier has no result slot"))?;
                    let value = evaluated(plan, id, read_binding(binding, &bindings))?;
                    if argument(&value).is_none() {
                        if resolved_obstruction(&value) {
                            resolved.insert(id);
                            suppress_result(&mut bindings, node.result, &value);
                        }
                        waiting.insert(id, value);
                        continue;
                    }
                }
            }
            waiting.remove(&id);
            match &node.kind {
                NodeKind::Call { scope, .. } => {
                    if let std::collections::btree_map::Entry::Vacant(entry) = calls.entry(id) {
                        let observe = |binding| {
                            recovery::observe_outcome(
                                plan, binding, &owned, &bindings, instance, frame,
                            )
                        };
                        match prepare_call_with_queries(
                            plan,
                            id,
                            &bindings,
                            journal,
                            frame,
                            frontier,
                            (queries, Some(&observe)),
                        ) {
                            Ok(prepared) => {
                                bindings.extend(prepared.parameters.clone());
                                active_blocks.insert(plan.scopes[scope.0].entry);
                                entry.insert(prepared);
                            }
                            Err(obstruction) => {
                                let value = evaluated(plan, id, obstruction.evaluation).map_err(
                                    |mut issue| {
                                        issue.span = obstruction.span;
                                        issue
                                    },
                                )?;
                                if resolved_obstruction(&value) {
                                    resolved.insert(id);
                                    suppress_result(&mut bindings, node.result, &value);
                                }
                                waiting.insert(id, value);
                                continue;
                            }
                        }
                    }
                    resolved.insert(id);
                }
                NodeKind::Return(value) | NodeKind::Fail(value) => {
                    let observe = |binding| {
                        recovery::observe_outcome(plan, binding, &owned, &bindings, instance, frame)
                    };
                    let evaluation = evaluated(
                        plan,
                        id,
                        evaluate_with_context(
                            &value.expr,
                            environment,
                            &bindings,
                            queries,
                            Some(&observe),
                        ),
                    )?;
                    let Some(value) = argument(&evaluation) else {
                        if resolved_obstruction(&evaluation) {
                            resolved.insert(id);
                        }
                        waiting.insert(id, evaluation);
                        continue;
                    };
                    let scope = plan.blocks[node.block.0]
                        .scope
                        .ok_or_else(|| error(plan, id, "action result outside an action scope"))?;
                    let result = if matches!(node.kind, NodeKind::Return(_)) {
                        ChosenResult::Return(value)
                    } else {
                        let evidence = value
                            .sources
                            .into_iter()
                            .flat_map(|source| match source {
                                ValueSource::Fact {
                                    fact_id,
                                    admission_event,
                                } => vec![fact_id, admission_event],
                                ValueSource::Operation { operation_id } => vec![operation_id],
                            })
                            .collect();
                        ChosenResult::Fail {
                            origin: CauseId(operation_identity(instance, frame, id)),
                            cause: Cause {
                                kind: FailureKind::Domain,
                                payload: value.value,
                                evidence,
                            },
                        }
                    };
                    let mut retain_handler_result = false;
                    if let Some((previous, _)) = chosen.get(&scope) {
                        if *previous != id {
                            let current_handler =
                                recovery::failure_handler_ancestor(plan, &parents, node.block);
                            let previous_handler = recovery::failure_handler_ancestor(
                                plan,
                                &parents,
                                plan.nodes[previous.0].block,
                            );
                            match (current_handler, previous_handler) {
                                (Some(_), None) => {}
                                (None, Some(_)) => retain_handler_result = true,
                                _ => {
                                    return Err(error(
                                        plan,
                                        id,
                                        "two selected results in one action",
                                    ));
                                }
                            }
                        }
                    }
                    if !retain_handler_result {
                        chosen.insert(scope, (id, result));
                    }
                    resolved.insert(id);
                }
                NodeKind::Statement(body) => {
                    let observe = |binding| {
                        recovery::observe_outcome(plan, binding, &owned, &bindings, instance, frame)
                    };
                    let statement = Statement {
                        root_rule: plan.root_rule.as_ref().map(|rule| rule.name.as_str()),
                        admitted: &admitted,
                        node: id,
                        identity: operation_identity(instance, frame, id),
                        body,
                        environment,
                        bindings: &bindings,
                        queries,
                        outcomes: Some(&observe),
                    };
                    let leaf = if matches!(body.as_ref(), BodyStmt::Cancel { .. }) {
                        super::cancellation::project(statement, plan, instance, frame, &owned)
                    } else {
                        project_statement(statement)
                    }
                    .map_err(|message| error(plan, id, message))?;
                    match &leaf {
                        Leaf::Waiting(value) => {
                            let value = evaluated(plan, id, value.clone())?;
                            if resolved_obstruction(&value) {
                                resolved.insert(id);
                                suppress_result(&mut bindings, node.result, &value);
                            }
                            waiting.insert(id, value);
                        }
                        Leaf::Ready {
                            lowering,
                            value,
                            work,
                        } => {
                            if !lowering.errors.is_empty() {
                                return Err(error(plan, id, lowering.errors.join("; ")));
                            }
                            if plan.blocks[node.block.0].scope.is_some()
                                && lowering.terminal.is_some()
                            {
                                return Err(error(
                                    plan,
                                    id,
                                    "action statement cannot terminate its workflow",
                                ));
                            }
                            if matches!(body.as_ref(), BodyStmt::Effect(_)) != work.is_some() {
                                return Err(error(
                                    plan,
                                    id,
                                    "statement operation ownership differs from its source",
                                ));
                            }
                            if let Some(work) = work {
                                bind_result(
                                    &mut bindings,
                                    node.result,
                                    value.as_ref(),
                                    work,
                                    &operation_identity(instance, frame, id),
                                )
                                .map_err(|message| error(plan, id, message))?;
                                owned.insert(id, work.clone());
                            } else if let Some(binding) = node.result {
                                let value = value.as_ref().ok_or_else(|| {
                                    error(plan, id, "pure statement has no bound value")
                                })?;
                                bindings.insert(binding, Slot::Ready(value.clone()));
                            }
                            resolved.insert(id);
                        }
                    }
                    leaves.insert(id, leaf);
                }
                NodeKind::After {
                    observed,
                    predicate,
                    alias,
                    body,
                    ..
                } => {
                    let choice = if *predicate == AfterPredicate::Succeeds {
                        match bindings.get(observed) {
                            Some(Slot::Ready(value)) => {
                                if let Some(alias) = alias {
                                    bindings.insert(*alias, Slot::Ready(value.clone()));
                                }
                                Some(true)
                            }
                            Some(Slot::Failed(_)) => Some(false),
                            Some(Slot::Pending) | None => None,
                        }
                    } else {
                        recovery::selection(plan, *observed, *predicate, &owned, &bindings)
                    };
                    if let Some(selected_body) = choice {
                        if selected_body {
                            if *predicate != AfterPredicate::Succeeds {
                                if let Some(alias) = alias {
                                    let value = recovery::alias(
                                        plan, *observed, *predicate, &owned, &bindings, instance,
                                        frame,
                                    )
                                    .map_err(|message| error(plan, id, message))?;
                                    bindings.insert(*alias, Slot::Ready(value));
                                }
                            }
                            active_blocks.insert(*body);
                        }
                        selected.insert(id, selected_body.then_some(*body));
                        resolved.insert(id);
                    } else {
                        waiting.insert(id, read_binding(*observed, &bindings));
                    }
                }
                NodeKind::OnFailure { alias, body } => {
                    if selected.contains_key(&id) {
                        resolved.insert(id);
                        continue;
                    }
                    let scope = plan.blocks[node.block.0].scope;
                    match recovery::select_handler(
                        plan,
                        id,
                        scope,
                        *body,
                        scope.and_then(|scope| chosen.get(&scope)),
                        &owned,
                        &active_blocks,
                        &resolved,
                        &parents,
                        instance,
                        frame,
                    )? {
                        recovery::HandlerSelection::Waiting => {}
                        recovery::HandlerSelection::Unselected => {
                            selected.insert(id, None);
                            resolved.insert(id);
                        }
                        recovery::HandlerSelection::Selected { failure, caught } => {
                            if let Some((failure_node, work)) = caught {
                                owned.insert(failure_node, work);
                            }
                            bindings.insert(*alias, Slot::Ready(failure));
                            active_blocks.insert(*body);
                            selected.insert(id, Some(*body));
                            resolved.insert(id);
                        }
                    }
                }
                NodeKind::Case {
                    scrutinee,
                    branches,
                } => {
                    if selected.contains_key(&id) {
                        resolved.insert(id);
                        continue;
                    }
                    let observe = |binding| {
                        recovery::observe_outcome(plan, binding, &owned, &bindings, instance, frame)
                    };
                    let value = expression(
                        plan,
                        id,
                        scrutinee,
                        environment,
                        &bindings,
                        queries,
                        Some(&observe),
                    )?;
                    let Some(value) = argument(&value) else {
                        if resolved_obstruction(&value) {
                            resolved.insert(id);
                            suppress_result(&mut bindings, node.result, &value);
                        }
                        waiting.insert(id, value);
                        continue;
                    };
                    let case_type = types.map(|(ir, types)| (ir, &types[&id]));
                    if let Some((ir, ty)) = case_type {
                        cases::validate(ir, ty, &value.value)
                            .map_err(|message| error(plan, id, message))?;
                    }
                    let mut choice = None;
                    let mut deferred = false;
                    // Fallback comes after concrete alternatives regardless of
                    // source position. Its guard is still a real dependency.
                    for branch in branches
                        .iter()
                        .filter(|b| !matches!(b.pattern.as_str(), "_" | "default"))
                        .chain(
                            branches
                                .iter()
                                .filter(|b| matches!(b.pattern.as_str(), "_" | "default")),
                        )
                    {
                        let matched = match case_type {
                            Some((ir, ty)) => cases::matches(ir, ty, &branch.pattern, &value.value)
                                .map(|matched| {
                                    matched.then(|| {
                                        let mut payload = value.clone();
                                        if cases::is_terminal_outcome(ty) {
                                            payload.value = cases::terminal_payload(
                                                &branch.pattern,
                                                &value.value,
                                            );
                                        }
                                        payload
                                    })
                                }),
                            None => pattern_value(&branch.pattern, &value).map_err(str::to_owned),
                        };
                        let Some(payload) = matched.map_err(|message| error(plan, id, message))?
                        else {
                            continue;
                        };
                        let mut candidate = bindings.clone();
                        if let Some(binding) = branch.binding {
                            candidate.insert(binding, Slot::Ready(payload.clone()));
                        }
                        if let Some(guard) = &branch.guard {
                            let evaluation = expression(
                                plan,
                                id,
                                guard,
                                &branch.guard_environment,
                                &candidate,
                                queries,
                                Some(&observe),
                            )?;
                            match evaluation.state {
                                State::Ready(Value::Bool(false)) => continue,
                                State::Ready(Value::Bool(true)) => {}
                                State::Blocked { .. } => {
                                    if resolved_obstruction(&evaluation) {
                                        resolved.insert(id);
                                    }
                                    waiting.insert(id, evaluation);
                                    deferred = true;
                                    break;
                                }
                                _ => {
                                    return Err(error(
                                        plan,
                                        id,
                                        "managed case guard requires a boolean",
                                    ))
                                }
                            }
                        }
                        if let Some(binding) = branch.binding {
                            bindings.insert(binding, candidate[&binding].clone());
                        }
                        choice = Some(branch.body);
                        break;
                    }
                    if !deferred {
                        if let Some(body) = choice {
                            active_blocks.insert(body);
                        }
                        selected.insert(id, choice);
                        resolved.insert(id);
                    }
                }
                NodeKind::Region {
                    until,
                    condition,
                    body,
                    lapse_binding,
                    lapse_body,
                } => {
                    if !captured_regions {
                        unreachable!("region preflight");
                    }
                    let history = journal.region(frame, id.0 as u64);
                    let cut = history.and_then(|history| history.latest());
                    if cut.is_none()
                        || cut
                            .is_some_and(|cut| cut.phase == super::journal::regions::Phase::Holding)
                    {
                        let observe = |binding| {
                            recovery::observe_outcome(
                                plan, binding, &owned, &bindings, instance, frame,
                            )
                        };
                        let mut observed = expression(
                            plan,
                            id,
                            condition,
                            environment,
                            &bindings,
                            queries,
                            Some(&observe),
                        )?;
                        match &mut observed.state {
                            State::Ready(Value::Bool(holds)) => {
                                if *until {
                                    *holds = !*holds;
                                }
                            }
                            State::Blocked { .. } => {}
                            _ => {
                                return Err(error(
                                    plan,
                                    id,
                                    "managed region condition requires a boolean",
                                ))
                            }
                        }
                        region_conditions.insert(id, observed);
                    }
                    let Some(cut) = cut else { continue };
                    match cut.phase {
                        super::journal::regions::Phase::Holding => {
                            active_blocks.insert(*body);
                            selected.insert(id, Some(*body));
                        }
                        super::journal::regions::Phase::Exited => {
                            active_blocks.insert(*body);
                            selected.insert(id, Some(*body));
                            resolved.insert(id);
                        }
                        super::journal::regions::Phase::Lapsed => {
                            let retained = if history
                                .is_some_and(|history| history.held_frontier().is_some())
                            {
                                Some(retained_regions.get(&id).ok_or_else(|| {
                                    error(
                                        plan,
                                        id,
                                        "captured held projection through a lapsed region is not implemented",
                                    )
                                })?)
                            } else {
                                None
                            };
                            if let Some(retained) = retained {
                                if retained_applied.insert(id) {
                                    for (node, work) in &retained.owned {
                                        if let Some(known) = owned.insert(*node, work.clone()) {
                                            debug_assert_eq!(
                                                known, *work,
                                                "held region membership overlaps a differently observed active node"
                                            );
                                        }
                                    }
                                    for (scope, result) in &retained.results {
                                        if chosen
                                            .insert(*scope, result.clone())
                                            .is_some_and(|known| known != *result)
                                        {
                                            return Err(error(
                                                plan,
                                                id,
                                                "two selected results in one action",
                                            ));
                                        }
                                    }
                                }
                            }
                            if let Some(binding) = lapse_binding {
                                bindings.insert(
                                    *binding,
                                    Slot::Ready(retained.map_or_else(
                                        || {
                                            regions
                                                .region(id)
                                                .expect("validated source region")
                                                .held
                                                .empty_progress(plan)
                                        },
                                        |retained| retained.progress.clone(),
                                    )),
                                );
                            }
                            active_blocks.insert(*lapse_body);
                            selected.insert(id, Some(*lapse_body));
                            resolved.insert(id);
                        }
                    }
                }
            }
        }
        for index in (0..plan.scopes.len()).rev() {
            let scope_id = ScopeId(index);
            let scope = &plan.scopes[index];
            if !active_blocks.contains(&scope.entry) {
                continue;
            }
            let closed = graph_closed(plan, Some(scope_id), &active_blocks, &resolved);
            let scope_owned = recovery::scope_work(
                plan,
                scope_id,
                chosen.get(&scope_id),
                &owned,
                &active_blocks,
                &resolved,
                &parents,
            )?
            .into_iter()
            .map(|(node, work)| (operation_identity(instance, frame, node), work))
            .collect();
            let result = chosen
                .get(&scope_id)
                .map_or(&ChosenResult::Pending, |(_, result)| result);
            let projection = project(result, closed, &scope_owned).map_err(|issue| {
                error(
                    plan,
                    scope.parent_call.unwrap_or(NodeId(0)),
                    format!("invalid owned action work: {issue:?}"),
                )
            })?;
            if closed
                && matches!(projection.boundary, Boundary::Waiting(ref waits) if waits == &BTreeSet::from([super::WaitReason::Return]))
            {
                return Err(error(
                    plan,
                    scope.parent_call.unwrap_or(NodeId(0)),
                    "closed action has no successful result",
                ));
            }
            if let Some(call) = scope.parent_call {
                let value = match &projection.boundary {
                    Boundary::Succeeded(value) => Some(value),
                    _ => None,
                };
                let work = projection.clone().into_owned_work();
                bind_result(
                    &mut bindings,
                    plan.nodes[call.0].result,
                    value,
                    &work,
                    &operation_identity(instance, frame, call),
                )
                .map_err(|message| error(plan, call, message))?;
                owned.insert(call, work);
            }
            scopes.insert(scope_id, projection);
        }
        if before
            == (
                bindings.clone(),
                active_blocks.clone(),
                scopes.clone(),
                resolved.clone(),
                owned.clone(),
                leaves.clone(),
                waiting.clone(),
            )
        {
            break;
        }
        if round == plan.nodes.len() + plan.scopes.len() + 1 {
            return Err(error(
                plan,
                NodeId(0),
                "source progression did not reach a stable projection",
            ));
        }
    }
    if journal.calls(frame).is_some_and(|recorded| {
        recorded
            .keys()
            .any(|call| !calls.contains_key(&NodeId(*call as usize)))
    }) {
        return Err(error(
            plan,
            NodeId(0),
            "recorded action call is unreachable from its admitted root",
        ));
    }
    let root_owned = recovery::root_work(plan, &owned, &active_blocks, &resolved, &parents, true)?
        .into_iter()
        .map(|(node, work)| (operation_identity(instance, frame, node), work))
        .collect();
    let root = if let Some(scope) = plan.blocks[plan.root.0].scope {
        let projection = &scopes[&scope];
        Projection {
            boundary: match &projection.boundary {
                Boundary::Succeeded(_) => Boundary::Succeeded(()),
                Boundary::Failed => Boundary::Failed,
                Boundary::Waiting(waits) => Boundary::Waiting(waits.clone()),
            },
            causes: projection.causes.clone(),
        }
    } else {
        project(
            &ChosenResult::Return(()),
            graph_closed(plan, None, &active_blocks, &resolved),
            &root_owned,
        )
        .map_err(|issue| {
            error(
                plan,
                NodeId(0),
                format!("invalid root owned work: {issue:?}"),
            )
        })?
    };
    let mut lowering = OwnedLowering {
        action_root: root_capture,
        ..Default::default()
    };
    lowering.action_captures.extend(
        calls
            .into_values()
            .filter(|call| call.fresh)
            .map(|call| call.capture),
    );
    for (node, leaf) in leaves {
        if let Leaf::Ready {
            lowering: draft, ..
        } = leaf
        {
            merge(
                plan,
                node,
                &mut lowering,
                *draft,
                matches!(root.boundary, Boundary::Succeeded(_)),
            )?;
        }
    }
    let region_complete = region_conditions
        .keys()
        .filter(|region| {
            regions.region(**region).is_some_and(|layout| {
                layout
                    .held
                    .complete(plan, **region, &active_blocks, &resolved, &owned)
            })
        })
        .copied()
        .collect();
    Ok(Progression {
        frontier,
        lowering,
        bindings,
        scopes,
        root,
        owned,
        chosen_results: chosen,
        active_blocks,
        selected_blocks: selected,
        region_conditions,
        region_complete,
        waiting,
    })
}

fn graph_closed(
    plan: &ActionPlan,
    scope: Option<ScopeId>,
    active: &BTreeSet<BlockId>,
    resolved: &BTreeSet<NodeId>,
) -> bool {
    active
        .iter()
        .filter(|block| plan.blocks[block.0].scope == scope)
        .all(|block| {
            plan.blocks[block.0]
                .nodes
                .iter()
                .all(|node| resolved.contains(node))
        })
}

#[cfg(test)]
mod tests;
