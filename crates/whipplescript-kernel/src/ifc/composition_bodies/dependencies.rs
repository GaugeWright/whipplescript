//! The actual activation footprint; no synthetic legacy rule metadata.
use super::*;
use whipplescript_parser::{rule_dependencies, IrRuleDependency};

pub(super) fn build(
    source: &CompositionAnalysis,
    rules: &[RuleBodyAnalysis<'_>],
) -> Vec<IrRuleDependency> {
    let declarations = source.declarations();
    let footprints: Vec<_> = rules
        .iter()
        .map(|body| {
            let mut writes: BTreeSet<_> = body
                .rule
                .fact_flow
                .writes
                .iter()
                .map(|write| write.fact.clone())
                .collect();
            for (node, effect) in &body.inventory.effects {
                let contract = &body.rule.typed.effects[node].contract;
                let prefix = match effect.kind {
                    IrEffectKind::TrackerFile | IrEffectKind::TrackerRelease => Some("tracker"),
                    IrEffectKind::CapabilityCall
                        if contract
                            .construct_use
                            .as_ref()
                            .is_some_and(|usage| usage.target_capability == "messaging.send") =>
                    {
                        Some("channel")
                    }
                    _ => None,
                };
                if let Some(prefix) = prefix {
                    for resource in &effect.resources {
                        let declared = if prefix == "tracker" {
                            declarations
                                .trackers()
                                .iter()
                                .any(|tracker| &tracker.name == resource)
                        } else {
                            declarations
                                .channels()
                                .iter()
                                .any(|channel| &channel.name == resource)
                        };
                        if declared {
                            writes.insert(format!("{prefix}:{resource}"));
                        }
                    }
                }
            }
            rule_dependencies::Footprint {
                name: &body.rule.root.name.name,
                reads: body
                    .rule
                    .root
                    .fact_reads
                    .iter()
                    .chain(&body.rule.root.resource_reads)
                    .cloned()
                    .collect(),
                writes: writes.into_iter().collect(),
            }
        })
        .collect();
    rule_dependencies::build(&footprints)
}
