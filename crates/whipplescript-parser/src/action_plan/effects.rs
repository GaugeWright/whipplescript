//! Checked per-effect metadata attached through structural source sites. The
//! complete executable program owner must authenticate these compiler results.
use super::*;
use crate::effect_contract::{Contract, Resource};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Effect {
    pub contract: Contract,
    pub resource_subject: Option<BindingId>,
    /// None for non-tell effects; Some(empty) proves an unreachable tell.
    pub agent_targets: Option<Vec<String>>,
}

pub(super) fn collect(
    plan: &ActionPlan,
    sites: &BTreeMap<NodeId, SourceSite>,
    targets: &BTreeMap<SourceSite, Vec<String>>,
) -> Result<BTreeMap<NodeId, Effect>, Vec<Diagnostic>> {
    let mut effects = BTreeMap::new();
    for (index, node) in plan.nodes.iter().enumerate() {
        let NodeKind::Statement(body) = &node.kind else {
            continue;
        };
        let BodyStmt::Effect(effect) = body.as_ref() else {
            continue;
        };
        let contract = Contract::from_statement(effect);
        let resource_subject = match &contract.resource {
            Resource::Binding(name) => {
                let Some(binding) = plan.blocks[node.block.0].environment.get(name) else {
                    let issue = error(
                        node.span,
                        format!("effect resource binding `{name}` has no lexical subject"),
                    );
                    // MUTATION-SUCCESS-EXPR: Ok(effects)
                    return Err(vec![issue]);
                };
                Some(*binding)
            }
            _ => None,
        };
        let agent_targets = if contract.agent.is_some() {
            let Some(agents) = sites.get(&NodeId(index)).and_then(|site| targets.get(site)) else {
                let issue = error(node.span, "tell has no checked agent domain".into());
                // MUTATION-SUCCESS-EXPR: Ok(effects)
                return Err(vec![issue]);
            };
            Some(agents.clone())
        } else {
            None
        };
        effects.insert(
            NodeId(index),
            Effect {
                contract,
                resource_subject,
                agent_targets,
            },
        );
    }
    Ok(effects)
}

pub(super) fn validate(
    plan: &ActionPlan,
    effects: &BTreeMap<NodeId, Effect>,
) -> Result<(), String> {
    let mut expected = Vec::new();
    for (index, node) in plan.nodes.iter().enumerate() {
        let NodeKind::Statement(body) = &node.kind else {
            continue;
        };
        let BodyStmt::Effect(effect) = body.as_ref() else {
            continue;
        };
        expected.push(NodeId(index));
        let Some(checked) = effects.get(&NodeId(index)) else {
            // MUTATION-SUCCESS-EXPR: Ok(())
            return Err("typed plan is missing an effect contract".into());
        };
        if checked.contract != Contract::from_statement(effect) {
            // MUTATION-SUCCESS-EXPR: Ok(())
            return Err("effect contract differs from its source statement".into());
        }
        let subject = match &checked.contract.resource {
            Resource::Binding(name) => plan.blocks[node.block.0].environment.get(name).copied(),
            _ => None,
        };
        if checked.resource_subject != subject
            || (matches!(checked.contract.resource, Resource::Binding(_)) && subject.is_none())
        {
            // MUTATION-SUCCESS-EXPR: Ok(())
            return Err("effect contract has no matching resource subject".into());
        }
        if checked.contract.agent.is_some() != checked.agent_targets.is_some()
            || checked.agent_targets.as_ref().is_some_and(|agents| {
                agents.windows(2).any(|pair| pair[0] >= pair[1])
                    || agents.iter().any(String::is_empty)
            })
        {
            // MUTATION-SUCCESS-EXPR: Ok(())
            return Err("effect contract requires a canonical checked tell domain".into());
        }
    }
    if effects.keys().copied().collect::<Vec<_>>() != expected {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("typed plan has an effect contract for a non-effect node".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
