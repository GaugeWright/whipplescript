//! Structural region membership over the compiler's expanded plan. This is a
//! derived view, not admission, continuation closure, or cancellation policy.
use std::collections::{BTreeMap, BTreeSet};

use whipplescript_parser::action_plan::{
    ActionPlan, BlockId, NodeId, NodeKind, PlanError, ScopeId,
};
use whipplescript_parser::body::BodyStmt;

use super::{
    arguments::{subjects, Argument, Slot, State},
    journal::{regions::Cut, regions::Phase, Frame, Journal},
    progression::Progression,
    ChosenResult, OwnedWork, WorkState,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Arm {
    pub entry: BlockId,
    nodes: BTreeSet<NodeId>,
    children: BTreeSet<NodeId>,
    effects: BTreeSet<NodeId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Region {
    pub held: Arm,
    pub lapse: Arm,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Layout {
    regions: BTreeMap<NodeId, Region>,
    exit_before: BTreeMap<NodeId, NodeId>,
}

/// References to this projection's actual work. Observed states and cause
/// identities are retained; a cancellation request cannot become an outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selected<'a> {
    pub children: BTreeMap<NodeId, &'a OwnedWork>,
    pub effects: BTreeMap<NodeId, &'a OwnedWork>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeldSelection {
    pub children: BTreeMap<NodeId, OwnedWork>,
    pub effects: BTreeMap<NodeId, OwnedWork>,
    pub results: BTreeMap<ScopeId, (NodeId, ChosenResult<Argument>)>,
}

impl Arm {
    pub fn contains(&self, node: NodeId) -> bool {
        self.nodes.contains(&node)
    }

    pub(super) fn empty_progress(&self, plan: &ActionPlan) -> Argument {
        let steps = self
            .children
            .iter()
            .filter_map(|node| plan.nodes[node.0].result)
            .filter_map(|binding| plan.bindings[binding.0].name.as_deref())
            .map(|name| {
                (
                    name.to_owned(),
                    serde_json::Value::String("not_requested".into()),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        Argument::from(serde_json::json!({"steps": steps}))
    }

    pub(super) fn progress(
        &self,
        plan: &ActionPlan,
        selected: &BTreeMap<NodeId, OwnedWork>,
        current: &Progression,
    ) -> Argument {
        let mut values = serde_json::Map::new();
        let mut steps = serde_json::Map::new();
        let mut sources = BTreeSet::new();
        let mut validity = BTreeSet::new();
        let mut fact_subjects = BTreeMap::new();
        for node in &self.children {
            let Some(binding) = plan.nodes[node.0].result else {
                continue;
            };
            let Some(name) = plan.bindings[binding.0].name.as_deref() else {
                continue;
            };
            let status = match selected.get(node) {
                None => "not_requested",
                Some(work) => match work.state {
                    WorkState::Pending
                    | WorkState::CancellationRequested
                    | WorkState::Uncertain => "cancelled_by_lapse",
                    WorkState::Succeeded => "completed",
                    WorkState::Failed(_) => {
                        if !work.causes.is_empty()
                            && work
                                .causes
                                .values()
                                .all(|cause| cause.cause.kind == super::FailureKind::TimedOut)
                        {
                            "timed_out"
                        } else if !work.causes.is_empty()
                            && work
                                .causes
                                .values()
                                .all(|cause| cause.cause.kind == super::FailureKind::Cancelled)
                        {
                            "cancelled"
                        } else {
                            "failed"
                        }
                    }
                },
            };
            steps.insert(name.to_owned(), serde_json::Value::String(status.into()));
            if status == "completed" {
                if let Some(Slot::Ready(value)) = current.bindings.get(&binding) {
                    values.insert(name.to_owned(), value.value.clone());
                    sources.extend(value.sources.iter().cloned());
                    validity.extend(value.validity.iter().cloned());
                    fact_subjects.extend(subjects::nested(&value.subjects, name));
                }
            }
        }
        values.insert("steps".into(), serde_json::Value::Object(steps));
        Argument {
            value: serde_json::Value::Object(values),
            sources,
            subjects: fact_subjects,
            validity,
        }
    }

    pub fn select<'a>(&self, owned: &'a BTreeMap<NodeId, OwnedWork>) -> Selected<'a> {
        let actual = |members: &BTreeSet<NodeId>| {
            members
                .iter()
                .filter_map(|node| owned.get(node).map(|work| (*node, work)))
                .collect()
        };
        Selected {
            children: actual(&self.children),
            effects: actual(&self.effects),
        }
    }

    pub(super) fn complete(
        &self,
        plan: &ActionPlan,
        region: NodeId,
        active: &BTreeSet<BlockId>,
        resolved: &BTreeSet<NodeId>,
        owned: &BTreeMap<NodeId, OwnedWork>,
    ) -> bool {
        if !active.contains(&self.entry)
            || plan.nodes.get(region.0).is_none_or(
                |node| !matches!(node.kind, NodeKind::Region { body, .. } if body == self.entry),
            )
        {
            return false;
        }
        let graph_closed = active.iter().all(|block| {
            plan.blocks[block.0]
                .nodes
                .iter()
                .filter(|node| self.contains(**node))
                .all(|node| resolved.contains(node))
        });
        graph_closed
            && self
                .select(owned)
                .children
                .values()
                .all(|work| matches!(work.state, WorkState::Succeeded | WorkState::Failed(_)))
    }

    pub fn selected_held(
        &self,
        region: NodeId,
        progression: &Progression,
    ) -> Result<HeldSelection, &'static str> {
        if progression.selected_blocks.get(&region) != Some(&Some(self.entry)) {
            return Err("recorded held region is unreachable from its captured root");
        }
        let selected = self.select(&progression.owned);
        Ok(HeldSelection {
            children: selected
                .children
                .into_iter()
                .map(|(node, work)| (node, work.clone()))
                .collect(),
            effects: selected
                .effects
                .into_iter()
                .map(|(node, work)| (node, work.clone()))
                .collect(),
            results: progression
                .chosen_results
                .iter()
                .filter(|(_, (node, _))| self.contains(*node))
                .map(|(scope, result)| (*scope, result.clone()))
                .collect(),
        })
    }
}

impl Layout {
    pub fn build(plan: &ActionPlan) -> Result<Self, PlanError> {
        plan.validate_structure()?;
        let mut result = Self::default();
        for block in &plan.blocks {
            let mut previous = None;
            for node in &block.nodes {
                if let Some(region) = previous {
                    result.exit_before.insert(*node, region);
                }
                if let NodeKind::Region {
                    body, lapse_body, ..
                } = &plan.nodes[node.0].kind
                {
                    result.regions.insert(
                        *node,
                        Region {
                            held: arm(plan, *body),
                            lapse: arm(plan, *lapse_body),
                        },
                    );
                    previous = Some(*node);
                }
            }
        }
        Ok(result)
    }

    pub fn region(&self, node: NodeId) -> Option<&Region> {
        self.regions.get(&node)
    }

    /// Immediate lexical predecessor; successive regions form a chain.
    /// The containing control/call supplies activation to its child blocks.
    pub fn exit_before(&self, node: NodeId) -> Option<NodeId> {
        self.exit_before.get(&node).copied()
    }
}

/// Derive the one next durable phase transition for each reached region from
/// a pure progression. A first holding cut admits the held graph. Once held,
/// completed work exits even if the condition changes at that same frontier;
/// otherwise a false observation lapses. Blocked observations do not guess.
pub fn phase_cuts(
    plan: &ActionPlan,
    journal: &Journal,
    frame: &Frame,
    progression: &Progression,
) -> Vec<Cut> {
    let candidates = progression
        .region_conditions
        .iter()
        .filter_map(|(region, observed)| {
            let State::Ready(serde_json::Value::Bool(holds)) = &observed.state else {
                return None;
            };
            let phase = match journal
                .region(frame, region.0 as u64)
                .and_then(|history| history.latest())
                .map(|cut| cut.phase)
            {
                None => Some(if *holds {
                    Phase::Holding
                } else {
                    Phase::Lapsed
                }),
                Some(Phase::Holding) if progression.region_complete.contains(region) => {
                    Some(Phase::Exited)
                }
                Some(Phase::Holding) if !holds => Some(Phase::Lapsed),
                // A held prefix grows when this projection admits more work.
                // Checkpoint that same commit so a later lapse reconstructs
                // the latest admitted membership rather than the entry cut.
                Some(Phase::Holding) if progression.lowering.has_commit_work() => {
                    Some(Phase::Holding)
                }
                Some(Phase::Holding | Phase::Exited | Phase::Lapsed) => None,
            }?;
            Some(Cut {
                region: region.0 as u64,
                frontier: progression.frontier,
                phase,
            })
        })
        .collect::<Vec<_>>();
    let layout = Layout::build(plan).expect("progression already validated its region layout");
    candidates
        .iter()
        .filter(|candidate| {
            !candidates.iter().any(|ancestor| {
                ancestor.region != candidate.region
                    && ancestor.phase == Phase::Lapsed
                    && layout
                        .region(NodeId(ancestor.region as usize))
                        .is_some_and(|region| {
                            region.held.contains(NodeId(candidate.region as usize))
                        })
            })
        })
        .cloned()
        .collect()
}

fn arm(plan: &ActionPlan, entry: BlockId) -> Arm {
    let owner = plan.blocks[entry.0].scope;
    let mut result = Arm {
        entry,
        nodes: BTreeSet::new(),
        children: BTreeSet::new(),
        effects: BTreeSet::new(),
    };
    let mut blocks = vec![entry];
    while let Some(block) = blocks.pop() {
        for id in &plan.blocks[block.0].nodes {
            let node = &plan.nodes[id.0];
            result.nodes.insert(*id);
            let effect = matches!(&node.kind, NodeKind::Statement(body) if matches!(body.as_ref(), BodyStmt::Effect(_)));
            if effect {
                result.effects.insert(*id);
            }
            if (effect || matches!(node.kind, NodeKind::Call { .. }))
                && plan.blocks[block.0].scope == owner
            {
                result.children.insert(*id);
            }
            match &node.kind {
                NodeKind::Call { scope, .. } => blocks.push(plan.scopes[scope.0].entry),
                NodeKind::After { body, .. } => blocks.push(*body),
                NodeKind::Case { branches, .. } => {
                    blocks.extend(branches.iter().map(|branch| branch.body))
                }
                NodeKind::Region {
                    body, lapse_body, ..
                } => blocks.extend([*body, *lapse_body]),
                _ => {}
            }
        }
    }
    result
}

#[cfg(test)]
mod tests;
