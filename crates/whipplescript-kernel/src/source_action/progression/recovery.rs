//! Non-success selection reads actual operations. Recovery is a lexical scope
//! disposition computed over a copy; original terminals and value slots persist.
use super::*;
use whipplescript_parser::action_plan::BindingSource;
use whipplescript_parser::{body::BodyEffectKind, Expr};

pub(super) fn operation_node(plan: &ActionPlan, observed: BindingId) -> Option<NodeId> {
    match plan.bindings[observed.0].source {
        BindingSource::Node(node) => match &plan.nodes[node.0].kind {
            NodeKind::Call { .. } => Some(node),
            NodeKind::Statement(body) if matches!(body.as_ref(), BodyStmt::Effect(_)) => Some(node),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn preflight(
    plan: &ActionPlan,
    node: NodeId,
    observed: BindingId,
    predicate: AfterPredicate,
    _alias: Option<BindingId>,
) -> Result<(), ProgressionError> {
    if predicate == AfterPredicate::Succeeds {
        return Ok(());
    }
    let op = operation_node(plan, observed);
    let supported_operation = op.is_some_and(|op| match &plan.nodes[op.0].kind {
        NodeKind::Call { .. } => {
            matches!(predicate, AfterPredicate::Fails | AfterPredicate::Completes)
        }
        NodeKind::Statement(body) => match body.as_ref() {
            BodyStmt::Effect(effect) => {
                matches!(
                    predicate,
                    AfterPredicate::Fails
                        | AfterPredicate::TimedOut
                        | AfterPredicate::Cancelled
                        | AfterPredicate::Completes
                ) || matches!(effect.kind, BodyEffectKind::CounterConsume { .. })
                    && matches!(predicate, AfterPredicate::Ok | AfterPredicate::Over)
            }
            _ => false,
        },
        _ => false,
    });
    if !supported_operation {
        return Err(error(
            plan,
            node,
            "managed continuation predicate, alias or operation is not implemented",
        ));
    }
    Ok(())
}

pub(super) fn alias(
    plan: &ActionPlan,
    observed: BindingId,
    predicate: AfterPredicate,
    owned: &BTreeMap<NodeId, OwnedWork>,
    bindings: &Bindings,
    instance: &str,
    frame: &Frame,
) -> Result<Argument, &'static str> {
    let op = operation_node(plan, observed).ok_or("managed failure alias has no operation")?;
    let work = owned
        .get(&op)
        .ok_or("managed failure alias has no observed work")?;
    let child_scope = match &plan.nodes[op.0].kind {
        NodeKind::Call { scope, .. } => Some(*scope),
        _ => None,
    };
    let context = OperationContext {
        plan,
        instance,
        frame,
    };
    if matches!(
        predicate,
        AfterPredicate::Completes | AfterPredicate::Ok | AfterPredicate::Over
    ) {
        if matches!(predicate, AfterPredicate::Ok | AfterPredicate::Over) {
            let Slot::Ready(value) = bindings
                .get(&observed)
                .ok_or("managed counter alias has no successful value")?
            else {
                return Err("managed counter alias has no successful value");
            };
            return Ok(value.clone());
        }
        return if let Some(scope) = child_scope {
            child_terminal_outcome(context, op, scope, observed, work, bindings)
        } else {
            terminal_outcome(
                observed,
                work,
                bindings,
                &operation_identity(instance, frame, op),
            )
        };
    }
    if let Some(scope) = child_scope {
        return Ok(child_failure(context, op, scope, work));
    }
    let mut matching = work.causes.iter().filter(|(_, observed)| {
        !observed.recovered
            && matches!(
                (predicate, &observed.cause.kind),
                (AfterPredicate::Fails, FailureKind::Failed)
                    | (AfterPredicate::TimedOut, FailureKind::TimedOut)
                    | (AfterPredicate::Cancelled, FailureKind::Cancelled)
            )
    });
    let (origin, observed) = matching
        .next()
        .ok_or("managed failure alias has no matching terminal cause")?;
    if matching.next().is_some() {
        return Err("managed failure alias has more than one matching terminal cause");
    }
    Ok(Argument {
        value: observed.cause.payload.clone(),
        sources: BTreeSet::from([ValueSource::Operation {
            operation_id: origin.0.clone(),
        }]),
        subjects: Default::default(),
        validity: Default::default(),
    })
}

pub(super) fn terminal_outcome(
    observed: BindingId,
    work: &OwnedWork,
    bindings: &Bindings,
    identity: &str,
) -> Result<Argument, &'static str> {
    if work.state == WorkState::Succeeded {
        let Slot::Ready(value) = bindings
            .get(&observed)
            .ok_or("managed outcome alias has no successful value")?
        else {
            return Err("managed outcome alias has no successful value");
        };
        let mut outcome = value.clone();
        outcome.value = serde_json::json!({
            "tag": "Completed",
            "status": "completed",
            "value": value.value,
            "error": Value::Null,
            "summary": Value::Null,
            "effect_id": identity,
            "run_id": Value::Null,
        });
        return Ok(outcome);
    }
    let mut causes = work.causes.iter().filter(|(_, cause)| !cause.recovered);
    let (origin, observed) = causes
        .next()
        .ok_or("managed outcome alias has no terminal cause")?;
    if causes.next().is_some() {
        return Err("managed outcome alias has more than one terminal cause");
    }
    let (tag, status) = match observed.cause.kind {
        FailureKind::Failed | FailureKind::Domain => ("Failed", "failed"),
        FailureKind::TimedOut => ("TimedOut", "timed_out"),
        FailureKind::Cancelled => ("Cancelled", "cancelled"),
    };
    let payload = &observed.cause.payload;
    Ok(Argument {
        value: serde_json::json!({
            "tag": tag,
            "status": status,
            "value": Value::Null,
            "error": payload,
            "summary": payload.get("summary").or_else(|| payload.get("reason")).cloned().unwrap_or(Value::Null),
            "effect_id": payload.get("effect_id").cloned().unwrap_or_else(|| Value::String(origin.0.clone())),
            "run_id": payload.get("run_id").cloned().unwrap_or(Value::Null),
        }),
        sources: BTreeSet::from([ValueSource::Operation {
            operation_id: origin.0.clone(),
        }]),
        subjects: Default::default(),
        validity: Default::default(),
    })
}

fn cause_summary(cause: &Cause) -> String {
    cause
        .payload
        .get("summary")
        .or_else(|| cause.payload.get("reason"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| cause.payload.as_str().map(str::to_owned))
        .unwrap_or_else(|| cause.payload.to_string())
}

#[derive(Clone, Copy)]
struct OperationContext<'a> {
    plan: &'a ActionPlan,
    instance: &'a str,
    frame: &'a Frame,
}

fn child_failure(
    context: OperationContext<'_>,
    call: NodeId,
    scope: ScopeId,
    work: &OwnedWork,
) -> Argument {
    debug_assert!(matches!(work.state, WorkState::Failed(_)));
    let unrecovered = work
        .causes
        .values()
        .filter(|cause| !cause.recovered)
        .count();
    debug_assert!(unrecovered > 0);
    let direct_failures: BTreeSet<_> = context
        .plan
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| {
            context.plan.blocks[node.block.0].scope == Some(scope)
                && matches!(node.kind, NodeKind::Fail(_))
        })
        .map(|(node, _)| operation_identity(context.instance, context.frame, NodeId(node)))
        .collect();
    let mut domains = work.causes.iter().filter(|(origin, cause)| {
        !cause.recovered
            && cause.cause.kind == FailureKind::Domain
            && direct_failures.contains(&origin.0)
    });
    let domain = domains
        .next()
        .map_or(Value::Null, |(_, cause)| cause.cause.payload.clone());
    debug_assert!(domains.next().is_none());
    let causes: Vec<_> = work
        .causes
        .iter()
        .map(|(origin, observed)| {
            let kind = match observed.cause.kind {
                FailureKind::Failed => "Failed",
                FailureKind::TimedOut => "TimedOut",
                FailureKind::Cancelled => "Cancelled",
                FailureKind::Domain => "Domain",
            };
            serde_json::json!({
                "origin": origin.0.clone(),
                "kind": kind,
                "summary": cause_summary(&observed.cause),
                "recovered": observed.recovered,
                "evidence": observed.cause.evidence.clone(),
            })
        })
        .collect();
    let identity = operation_identity(context.instance, context.frame, call);
    Argument {
        value: serde_json::json!({
            "summary": format!("child action failed with {unrecovered} unrecovered cause{}", if unrecovered == 1 { "" } else { "s" }),
            "operation_id": identity,
            "domain": domain,
            "causes": causes,
        }),
        sources: work
            .causes
            .keys()
            .map(|origin| ValueSource::Operation {
                operation_id: origin.0.clone(),
            })
            .collect(),
        subjects: Default::default(),
        validity: Default::default(),
    }
}

fn child_terminal_outcome(
    context: OperationContext<'_>,
    call: NodeId,
    scope: ScopeId,
    observed: BindingId,
    work: &OwnedWork,
    bindings: &Bindings,
) -> Result<Argument, &'static str> {
    let identity = operation_identity(context.instance, context.frame, call);
    if work.state == WorkState::Succeeded {
        return terminal_outcome(observed, work, bindings, &identity);
    }
    let failure = child_failure(context, call, scope, work);
    let summary = failure.value.get("summary").cloned().unwrap_or(Value::Null);
    Ok(Argument {
        value: serde_json::json!({
            "tag": "Failed",
            "status": "failed",
            "value": Value::Null,
            "error": failure.value,
            "summary": summary,
            "effect_id": identity,
            "run_id": Value::Null,
        }),
        sources: failure.sources,
        subjects: failure.subjects,
        validity: failure.validity,
    })
}

pub(super) fn observe_outcome(
    plan: &ActionPlan,
    observed: BindingId,
    owned: &BTreeMap<NodeId, OwnedWork>,
    bindings: &Bindings,
    instance: &str,
    frame: &Frame,
) -> Evaluation {
    let Some(op) = operation_node(plan, observed) else {
        return Evaluation::invalid("managed outcome has no operation identity");
    };
    let Some(work) = owned.get(&op) else {
        // Suppressed work has no terminal observation. Preserve the original
        // wait or cause rather than manufacturing an outcome envelope.
        return read_binding(observed, bindings);
    };
    if matches!(
        work.state,
        WorkState::Pending | WorkState::CancellationRequested | WorkState::Uncertain
    ) {
        return Evaluation {
            state: State::Blocked {
                waiting: BTreeSet::from([observed]),
                causes: BTreeSet::new(),
            },
            reads: BTreeSet::from([observed]),
            sources: BTreeSet::new(),
            subjects: Default::default(),
            validity: Default::default(),
        };
    }
    let outcome = match &plan.nodes[op.0].kind {
        NodeKind::Call { scope, .. } => child_terminal_outcome(
            OperationContext {
                plan,
                instance,
                frame,
            },
            op,
            *scope,
            observed,
            work,
            bindings,
        ),
        NodeKind::Statement(statement) if matches!(statement.as_ref(), BodyStmt::Effect(_)) => {
            terminal_outcome(
                observed,
                work,
                bindings,
                &operation_identity(instance, frame, op),
            )
        }
        _ => unreachable!("operation_node returned a non-operation"),
    };
    match outcome {
        Ok(argument) => Evaluation {
            state: State::Ready(argument.value),
            reads: BTreeSet::from([observed]),
            sources: argument.sources,
            subjects: argument.subjects,
            validity: argument.validity,
        },
        Err(message) => Evaluation::invalid(message),
    }
}

pub(super) fn selection(
    plan: &ActionPlan,
    observed: BindingId,
    predicate: AfterPredicate,
    owned: &BTreeMap<NodeId, OwnedWork>,
    bindings: &Bindings,
) -> Option<bool> {
    let op = operation_node(plan, observed).expect("preflight checked operation");
    match owned.get(&op) {
        Some(work) => match work.state {
            WorkState::Pending | WorkState::CancellationRequested | WorkState::Uncertain => None,
            WorkState::Succeeded => Some(match predicate {
                AfterPredicate::Completes => true,
                AfterPredicate::Ok | AfterPredicate::Over => bindings
                    .get(&observed)
                    .and_then(|slot| match slot {
                        Slot::Ready(value) => value.value.get("variant")?.as_str(),
                        _ => None,
                    })
                    .is_some_and(|variant| {
                        matches!(
                            (predicate, variant),
                            (AfterPredicate::Ok, "Ok") | (AfterPredicate::Over, "Over")
                        )
                    }),
                _ => false,
            }),
            WorkState::Failed(_) => Some(
                predicate == AfterPredicate::Completes
                    || matches!(plan.nodes[op.0].kind, NodeKind::Call { .. })
                    || work.causes.values().any(|observed| {
                        !observed.recovered
                            && matches!(
                                (predicate, &observed.cause.kind),
                                (AfterPredicate::Fails, FailureKind::Failed)
                                    | (AfterPredicate::TimedOut, FailureKind::TimedOut)
                                    | (AfterPredicate::Cancelled, FailureKind::Cancelled)
                            )
                    }),
            ),
        },
        // Suppressed before admission: the value carries causes, but there is
        // no terminal here to select a recovery continuation.
        None => matches!(bindings.get(&observed), Some(Slot::Failed(_))).then_some(false),
    }
}

pub(super) fn block_parents(plan: &ActionPlan) -> BTreeMap<BlockId, NodeId> {
    let mut parents = BTreeMap::new();
    for (index, node) in plan.nodes.iter().enumerate() {
        let id = NodeId(index);
        match &node.kind {
            NodeKind::After { body, .. } => {
                parents.insert(*body, id);
            }
            NodeKind::Case { branches, .. } => {
                parents.extend(branches.iter().map(|branch| (branch.body, id)));
            }
            NodeKind::OnFailure { body, .. } => {
                parents.insert(*body, id);
            }
            NodeKind::Region {
                body, lapse_body, ..
            } => {
                parents.insert(*body, id);
                parents.insert(*lapse_body, id);
            }
            _ => {}
        }
    }
    parents
}

pub(super) fn failure_handler_ancestor(
    plan: &ActionPlan,
    parents: &BTreeMap<BlockId, NodeId>,
    mut block: BlockId,
) -> Option<NodeId> {
    while let Some(parent) = parents.get(&block) {
        if matches!(plan.nodes[parent.0].kind, NodeKind::OnFailure { .. }) {
            return Some(*parent);
        }
        block = plan.nodes[parent.0].block;
    }
    None
}

fn within(
    plan: &ActionPlan,
    parents: &BTreeMap<BlockId, NodeId>,
    mut block: BlockId,
    root: BlockId,
) -> bool {
    loop {
        if block == root {
            return true;
        }
        let Some(parent) = parents.get(&block) else {
            return false;
        };
        block = plan.nodes[parent.0].block;
    }
}

pub(super) enum HandlerSelection {
    Waiting,
    Unselected,
    Selected {
        failure: Argument,
        caught: Option<(NodeId, OwnedWork)>,
    },
}

#[allow(clippy::too_many_arguments)]
pub(super) fn select_handler(
    plan: &ActionPlan,
    handler: NodeId,
    scope: Option<ScopeId>,
    body: BlockId,
    chosen: Option<&(NodeId, ChosenResult<Argument>)>,
    owned: &BTreeMap<NodeId, OwnedWork>,
    active: &BTreeSet<BlockId>,
    resolved: &BTreeSet<NodeId>,
    parents: &BTreeMap<BlockId, NodeId>,
    instance: &str,
    frame: &Frame,
) -> Result<HandlerSelection, ProgressionError> {
    let protected_root = plan.nodes[handler.0].block;
    let protected_blocks: BTreeSet<_> = active
        .iter()
        .copied()
        .filter(|block| {
            plan.blocks[block.0].scope == scope
                && within(plan, parents, *block, protected_root)
                && !within(plan, parents, *block, body)
        })
        .collect();
    let closed = protected_blocks.iter().all(|block| {
        plan.blocks[block.0]
            .nodes
            .iter()
            .all(|node| *node == handler || resolved.contains(node))
    });
    if !closed {
        return Ok(HandlerSelection::Waiting);
    }
    let preliminary = match scope {
        Some(scope) => scope_work(plan, scope, chosen, owned, active, resolved, parents)?,
        None => root_work(plan, owned, active, resolved, parents, false)?,
    };
    let mut work: BTreeMap<_, _> = preliminary
        .into_iter()
        .filter(|(node, _)| protected_blocks.contains(&plan.nodes[node.0].block))
        .collect();
    let caught = chosen.and_then(|(node, result)| {
        let ChosenResult::Fail { origin, cause } = result else {
            return None;
        };
        let block = plan.nodes[node.0].block;
        (protected_blocks.contains(&block) && !within(plan, parents, block, body)).then(|| {
            (
                *node,
                OwnedWork {
                    state: WorkState::Failed(Disposition::Propagate),
                    causes: BTreeMap::from([(
                        origin.clone(),
                        crate::source_action::ObservedCause {
                            cause: cause.clone(),
                            recovered: false,
                        },
                    )]),
                },
            )
        })
    });
    if let Some((node, caught)) = &caught {
        work.insert(*node, caught.clone());
    }
    if work.values().any(|work| {
        matches!(
            work.state,
            WorkState::Pending
                | WorkState::CancellationRequested
                | WorkState::Uncertain
                | WorkState::Failed(Disposition::Recovering)
        )
    }) {
        return Ok(HandlerSelection::Waiting);
    }
    if !work.values().any(|work| {
        matches!(work.state, WorkState::Failed(Disposition::Propagate))
            && work.causes.values().any(|cause| !cause.recovered)
    }) {
        return Ok(HandlerSelection::Unselected);
    }
    let domain = caught
        .as_ref()
        .and_then(|(_, work)| work.causes.values().next())
        .map_or(Value::Null, |cause| cause.cause.payload.clone());
    Ok(HandlerSelection::Selected {
        failure: handler_failure(plan, handler, scope, &work, domain, instance, frame)?,
        caught,
    })
}

fn handler_failure(
    plan: &ActionPlan,
    handler: NodeId,
    scope: Option<ScopeId>,
    work: &BTreeMap<NodeId, OwnedWork>,
    domain: Value,
    instance: &str,
    frame: &Frame,
) -> Result<Argument, ProgressionError> {
    let mut causes = BTreeMap::new();
    for (origin, observed) in work.values().flat_map(|work| &work.causes) {
        if let Some(known) = causes.insert(origin.clone(), observed.clone()) {
            if known != *observed {
                return Err(error(
                    plan,
                    handler,
                    "failure handler observed conflicting evidence for one cause origin",
                ));
            }
        }
    }
    let unrecovered = causes.values().filter(|cause| !cause.recovered).count();
    debug_assert!(unrecovered > 0);
    let values: Vec<_> = causes
        .iter()
        .map(|(origin, observed)| {
            let kind = match observed.cause.kind {
                FailureKind::Failed => "Failed",
                FailureKind::TimedOut => "TimedOut",
                FailureKind::Cancelled => "Cancelled",
                FailureKind::Domain => "Domain",
            };
            serde_json::json!({
                "origin": origin.0.clone(),
                "kind": kind,
                "summary": cause_summary(&observed.cause),
                "recovered": observed.recovered,
                "evidence": observed.cause.evidence.clone(),
            })
        })
        .collect();
    let owner = if scope.is_some() {
        "action scope"
    } else {
        "rule progression"
    };
    Ok(Argument {
        value: serde_json::json!({
            "summary": format!("{owner} failed with {unrecovered} unrecovered cause{}", if unrecovered == 1 { "" } else { "s" }),
            "operation_id": operation_identity(instance, frame, handler),
            "domain": domain,
            "causes": values,
        }),
        sources: causes
            .keys()
            .map(|origin| ValueSource::Operation {
                operation_id: origin.0.clone(),
            })
            .collect(),
        subjects: Default::default(),
        validity: Default::default(),
    })
}

fn case_observation(plan: &ActionPlan, node: NodeId) -> Option<BindingId> {
    let NodeKind::Case { scrutinee, .. } = &plan.nodes[node.0].kind else {
        return None;
    };
    let expr = parse_expression(scrutinee).ok()?;
    let Expr::Call { name, args } = expr else {
        return None;
    };
    if name != "outcome" {
        return None;
    }
    let [argument] = args.as_slice() else {
        return None;
    };
    let name = match argument {
        Expr::Literal(whipplescript_parser::ExprLiteral::Ident(name)) => name,
        Expr::Path(path) if path.len() == 1 => &path[0],
        _ => return None,
    };
    plan.blocks[plan.nodes[node.0].block.0]
        .environment
        .get(name)
        .copied()
}

#[derive(Clone, Copy)]
struct RecoveryGraph<'a> {
    active: &'a BTreeSet<BlockId>,
    resolved: &'a BTreeSet<NodeId>,
    parents: &'a BTreeMap<BlockId, NodeId>,
}

fn handler_disposition(
    plan: &ActionPlan,
    scope: Option<ScopeId>,
    parent: NodeId,
    body: BlockId,
    work: &BTreeMap<NodeId, OwnedWork>,
    graph: RecoveryGraph<'_>,
) -> Result<Disposition, ProgressionError> {
    let handler_blocks: BTreeSet<_> = graph
        .active
        .iter()
        .copied()
        .filter(|block| {
            plan.blocks[block.0].scope == scope && within(plan, graph.parents, *block, body)
        })
        .collect();
    let closed = graph_closed(plan, scope, &handler_blocks, graph.resolved);
    let handler_work = work
        .iter()
        .filter(|(node, _)| handler_blocks.contains(&plan.nodes[node.0].block))
        .map(|(node, work)| (node.0.to_string(), work.clone()))
        .collect();
    let handler = project(&ChosenResult::Return(()), closed, &handler_work)
        .map_err(|issue| error(plan, parent, format!("invalid recovery work: {issue:?}")))?;
    Ok(match handler.boundary {
        Boundary::Succeeded(()) => Disposition::Recovered,
        Boundary::Waiting(_) => Disposition::Recovering,
        Boundary::Failed => Disposition::Propagate,
    })
}

pub(super) fn scope_work(
    plan: &ActionPlan,
    scope: ScopeId,
    chosen: Option<&(NodeId, ChosenResult<Argument>)>,
    owned: &BTreeMap<NodeId, OwnedWork>,
    active: &BTreeSet<BlockId>,
    resolved: &BTreeSet<NodeId>,
    parents: &BTreeMap<BlockId, NodeId>,
) -> Result<BTreeMap<NodeId, OwnedWork>, ProgressionError> {
    let mut operation_nodes: BTreeSet<_> =
        plan.scopes[scope.0].operations.iter().copied().collect();
    operation_nodes.extend(owned.keys().copied().filter(|node| {
        plan.blocks[plan.nodes[node.0].block.0].scope == Some(scope)
            && matches!(plan.nodes[node.0].kind, NodeKind::Fail(_))
    }));
    let mut work: BTreeMap<_, _> = operation_nodes
        .iter()
        .filter_map(|node| owned.get(node).map(|work| (*node, work.clone())))
        .collect();
    let Some((returned, ChosenResult::Return(_))) = chosen else {
        return Ok(work);
    };
    let mut block = plan.nodes[returned.0].block;
    // Walk the selected return's lexical ancestors from the inside out. A
    // sibling observation or an outer return cannot excuse a failed operation.
    while let Some(parent) = parents.get(&block) {
        let node = &plan.nodes[parent.0];
        enum Recovery {
            Operation(NodeId, BlockId),
            Scope(BlockId, BlockId),
        }
        let recovery = match &node.kind {
            NodeKind::After {
                observed,
                predicate,
                body,
                ..
            } if *predicate != AfterPredicate::Succeeds => {
                operation_node(plan, *observed).map(|op| Recovery::Operation(op, *body))
            }
            NodeKind::Case { branches, .. } => {
                case_observation(plan, *parent).and_then(|observed| {
                    let op = operation_node(plan, observed)?;
                    let body = branches
                        .iter()
                        .find(|branch| within(plan, parents, block, branch.body))?
                        .body;
                    Some(Recovery::Operation(op, body))
                })
            }
            NodeKind::OnFailure { body, .. } => Some(Recovery::Scope(node.block, *body)),
            _ => None,
        };
        if let Some(recovery) = recovery {
            let body = match recovery {
                Recovery::Operation(_, body) | Recovery::Scope(_, body) => body,
            };
            let disposition = handler_disposition(
                plan,
                Some(scope),
                *parent,
                body,
                &work,
                RecoveryGraph {
                    active,
                    resolved,
                    parents,
                },
            )?;
            match recovery {
                Recovery::Operation(op, _) => {
                    if let Some(observed_work) = work.get_mut(&op) {
                        if matches!(observed_work.state, WorkState::Failed(_)) {
                            observed_work.state = WorkState::Failed(disposition);
                        }
                    }
                }
                Recovery::Scope(root, handler_body) => {
                    for (operation, observed_work) in &mut work {
                        let operation_block = plan.nodes[operation.0].block;
                        if within(plan, parents, operation_block, root)
                            && !within(plan, parents, operation_block, handler_body)
                            && matches!(observed_work.state, WorkState::Failed(_))
                        {
                            observed_work.state = WorkState::Failed(disposition);
                        }
                    }
                }
            }
        }
        block = node.block;
    }
    Ok(work)
}

fn block_depth(
    plan: &ActionPlan,
    parents: &BTreeMap<BlockId, NodeId>,
    mut block: BlockId,
) -> usize {
    let mut depth = 0;
    while let Some(parent) = parents.get(&block) {
        depth += 1;
        block = plan.nodes[parent.0].block;
    }
    depth
}

pub(super) fn root_work(
    plan: &ActionPlan,
    owned: &BTreeMap<NodeId, OwnedWork>,
    active: &BTreeSet<BlockId>,
    resolved: &BTreeSet<NodeId>,
    parents: &BTreeMap<BlockId, NodeId>,
    include_failure_handler: bool,
) -> Result<BTreeMap<NodeId, OwnedWork>, ProgressionError> {
    let mut work: BTreeMap<_, _> = plan
        .operation_nodes(None)
        .into_iter()
        .filter_map(|node| owned.get(&node).map(|work| (node, work.clone())))
        .collect();
    let graph = RecoveryGraph {
        active,
        resolved,
        parents,
    };
    let mut local = Vec::new();
    let mut scope_handler = None;
    for (index, node) in plan.nodes.iter().enumerate() {
        if plan.blocks[node.block.0].scope.is_some() || !resolved.contains(&NodeId(index)) {
            continue;
        }
        match &node.kind {
            NodeKind::After {
                observed,
                predicate,
                body,
                ..
            } if *predicate != AfterPredicate::Succeeds && active.contains(body) => {
                if let Some(operation) = operation_node(plan, *observed) {
                    local.push((
                        block_depth(plan, parents, *body),
                        operation,
                        NodeId(index),
                        *body,
                    ));
                }
            }
            NodeKind::Case { branches, .. } => {
                let selected = branches.iter().find(|branch| active.contains(&branch.body));
                if let (Some(observed), Some(branch)) =
                    (case_observation(plan, NodeId(index)), selected)
                {
                    if let Some(operation) = operation_node(plan, observed) {
                        local.push((
                            block_depth(plan, parents, branch.body),
                            operation,
                            NodeId(index),
                            branch.body,
                        ));
                    }
                }
            }
            NodeKind::OnFailure { body, .. }
                if include_failure_handler && active.contains(body) =>
            {
                scope_handler = Some((NodeId(index), node.block, *body));
            }
            _ => {}
        }
    }
    local.sort_by_key(|(depth, _, _, _)| std::cmp::Reverse(*depth));
    for (_, operation, parent, body) in local {
        let disposition = handler_disposition(plan, None, parent, body, &work, graph)?;
        if let Some(observed) = work.get_mut(&operation) {
            if matches!(observed.state, WorkState::Failed(_)) {
                observed.state = WorkState::Failed(disposition);
            }
        }
    }
    if let Some((parent, root, body)) = scope_handler {
        let disposition = handler_disposition(plan, None, parent, body, &work, graph)?;
        for (operation, observed) in &mut work {
            let operation_block = plan.nodes[operation.0].block;
            if within(plan, parents, operation_block, root)
                && !within(plan, parents, operation_block, body)
                && matches!(observed.state, WorkState::Failed(_))
            {
                observed.state = WorkState::Failed(disposition);
            }
        }
    }
    Ok(work)
}
