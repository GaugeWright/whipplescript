//! Cancellation addresses operation identities already present in the typed
//! graph. It drafts requests for the ordinary rule commit; settlement remains
//! owned by the targeted effects and their terminal evidence.
use std::collections::BTreeMap;

use whipplescript_parser::action_plan::{ActionPlan, BindingSource, NodeId, NodeKind, ScopeId};
use whipplescript_parser::body::BodyStmt;

use super::arguments::read_binding;
use super::journal::Frame;
use super::progression::{operation_identity, Leaf, Statement};
use super::{OwnedWork, WorkState};
use crate::lowering::OwnedLowering;

fn ready(cancels: Vec<String>) -> Leaf {
    Leaf::Ready {
        lowering: Box::new(OwnedLowering {
            cancels,
            ..Default::default()
        }),
        value: None,
        work: None,
    }
}

fn inside_call(plan: &ActionPlan, mut scope: ScopeId, call: NodeId) -> bool {
    loop {
        let Some(parent) = plan.scopes[scope.0].parent_call else {
            return false;
        };
        if parent == call {
            return true;
        }
        let Some(parent_scope) = plan.blocks[plan.nodes[parent.0].block.0].scope else {
            return false;
        };
        scope = parent_scope;
    }
}

pub fn project(
    statement: Statement<'_>,
    plan: &ActionPlan,
    instance: &str,
    frame: &Frame,
    owned: &BTreeMap<NodeId, OwnedWork>,
) -> Result<Leaf, String> {
    let BodyStmt::Cancel { binding, .. } = statement.body else {
        // MUTATION-SUCCESS-EXPR: Ok(ready(Vec::new()))
        return Err("cancellation projector requires a cancel statement".into());
    };
    let binding_id = statement
        .environment
        .get(binding)
        .copied()
        .ok_or("cancel names an unknown managed binding")?;
    let target = match plan
        .bindings
        .get(binding_id.0)
        .map(|binding| &binding.source)
    {
        Some(BindingSource::Node(node)) => *node,
        _ => {
            // MUTATION-SUCCESS-EXPR: Ok(ready(Vec::new()))
            return Err("cancel requires an operation binding".into());
        }
    };
    let leaf = match &plan.nodes[target.0].kind {
        NodeKind::Statement(body) if matches!(body.as_ref(), BodyStmt::Effect(_)) => {
            ready(vec![operation_identity(instance, frame, target)])
        }
        NodeKind::Call { .. } => {
            let targets = owned
                .keys()
                .copied()
                .filter(|node| {
                    matches!(
                        plan.nodes[node.0].kind,
                        NodeKind::Statement(ref body)
                            if matches!(body.as_ref(), BodyStmt::Effect(_))
                    )
                })
                .filter(|node| {
                    plan.blocks[plan.nodes[node.0].block.0]
                        .scope
                        .is_some_and(|scope| inside_call(plan, scope, target))
                })
                .map(|node| operation_identity(instance, frame, node))
                .collect::<Vec<_>>();
            if !targets.is_empty()
                || owned.get(&target).is_some_and(|work| {
                    matches!(work.state, WorkState::Succeeded | WorkState::Failed(_))
                })
            {
                ready(targets)
            } else {
                return Ok(Leaf::Waiting(read_binding(binding_id, statement.bindings)));
            }
        }
        _ => {
            // MUTATION-SUCCESS-EXPR: Ok(ready(Vec::new()))
            return Err("cancel requires an operation binding".into());
        }
    };
    Ok(leaf)
}

#[cfg(test)]
mod tests;
