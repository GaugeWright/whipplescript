//! Read sites retained independently of their rule-wide source join.
use super::program_context::ProgramContext;
use super::*;
use whipplescript_parser::{action_plan::NodeId, SourceSpan};

pub(super) struct ReadSite {
    pub source: String,
    pub span: SourceSpan,
    pub node: Option<NodeId>,
}

pub(super) fn own(context: ProgramContext<'_>, body: &RuleBodyAnalysis<'_>) -> Vec<ReadSite> {
    let shared = shared_coordination_resources_in(context);
    let declared = declared_resources_in(context);
    let signals: BTreeSet<_> = context
        .events()
        .iter()
        .map(|event| event.name.as_str())
        .collect();
    let mut own = Vec::new();
    for (id, effect) in &body.inventory.effects {
        if effect_flow(&effect.kind).reads_resource {
            for resource in &effect.resources {
                if let Some(resource) = resource_for_ifc(&effect.kind, resource, &shared) {
                    own.push(ReadSite {
                        source: resource.into(),
                        span: body.rule.typed.plan.nodes[id.0].span,
                        node: Some(*id),
                    });
                }
            }
        }
        for grant in &body.rule.typed.effects[id].contract.access_grants {
            if grant
                .operations
                .iter()
                .any(|op| classify_op(&op.operation, declared.contains(grant.resource.as_str())).0)
            {
                own.push(ReadSite {
                    source: grant.resource.clone(),
                    span: body.rule.typed.plan.nodes[id.0].span,
                    node: Some(*id),
                });
            }
        }
    }
    for when in &body.rule.root.whens {
        let pattern = when.pattern.trim_start();
        if let Some(channel) = pattern
            .strip_prefix("message from ")
            .and_then(|rest| rest.split_whitespace().next())
        {
            own.push(ReadSite {
                source: channel.into(),
                span: when.span,
                node: None,
            });
        }
        if let Some(name) = pattern
            .split_whitespace()
            .next()
            .filter(|name| signals.contains(name))
        {
            own.push(ReadSite {
                source: format!("signal:{name}"),
                span: when.span,
                node: None,
            });
        }
    }
    let trackers = context
        .trackers()
        .iter()
        .map(|tracker| tracker.name.as_str())
        .collect();
    for resource in &body.rule.root.resource_reads {
        if let Some(tracker) = resource.strip_prefix("tracker:") {
            let span = body
                .rule
                .root
                .whens
                .iter()
                .find(|when| tracker_trigger_handle(&when.pattern, &trackers) == Some(tracker))
                .map(|when| when.span)
                .unwrap_or(body.rule.root.name.span);
            own.push(ReadSite {
                source: tracker.into(),
                span,
                node: None,
            });
        }
    }
    own
}
