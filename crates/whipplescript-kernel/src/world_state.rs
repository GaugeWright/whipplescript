//! Canonical model-visible world state (DR-0079).
//!
//! Hosts collect facts; this module owns their placement-neutral meaning,
//! canonical rendering, replayable updates, and the effective-envelope
//! projection. The rendered world explains authority but never grants it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::rule_lowering::stable_hash_hex;

pub const WORLD_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorldSnapshot {
    pub schema_version: u32,
    pub world_epoch: u64,
    pub turn_identity: String,
    pub sections: BTreeMap<String, WorldValue>,
}

impl WorldSnapshot {
    pub fn new(turn_identity: impl Into<String>) -> Self {
        Self {
            schema_version: WORLD_SCHEMA_VERSION,
            world_epoch: 0,
            turn_identity: turn_identity.into(),
            sections: BTreeMap::new(),
        }
    }

    pub fn with_section<T: Serialize>(
        mut self,
        id: impl Into<String>,
        value: &T,
    ) -> Result<Self, String> {
        let value = serde_json::to_value(value)
            .map_err(|error| format!("world section is not serializable: {error}"))?;
        self.sections
            .insert(id.into(), WorldValue::Available(value));
        Ok(self)
    }

    pub fn with_unavailable(mut self, id: impl Into<String>, reason: impl Into<String>) -> Self {
        self.sections.insert(
            id.into(),
            WorldValue::Unavailable {
                reason: reason.into(),
            },
        );
        self
    }

    pub fn with_agent_topology(self, topology: &AgentTopology) -> Result<Self, String> {
        topology.validate()?;
        self.with_section("agent_topology", topology)
    }

    pub fn content_hash(&self) -> String {
        stable_hash_hex(&canonical_json(self))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WorldValue {
    Available(Value),
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorldUpdate {
    pub schema_version: u32,
    pub turn_identity: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub changes: BTreeMap<String, WorldChange>,
    pub resulting_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum WorldChange {
    Set { value: Value },
    Unavailable { reason: String },
    Remove,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorldProjection {
    Unchanged,
    Full(WorldSnapshot),
    Update(WorldUpdate),
}

/// Compare the current collected state with the last state durably shown to the
/// model. Unknown/incompatible prior state produces a full refresh.
pub fn project_world(previous: Option<&WorldSnapshot>, current: &WorldSnapshot) -> WorldProjection {
    let Some(previous) = previous else {
        return WorldProjection::Full(current.clone());
    };
    if previous.schema_version != current.schema_version
        || previous.turn_identity != current.turn_identity
        || previous.world_epoch > current.world_epoch
    {
        return WorldProjection::Full(current.clone());
    }
    let mut changes = BTreeMap::new();
    for (id, value) in &current.sections {
        if previous.sections.get(id) != Some(value) {
            changes.insert(
                id.clone(),
                match value {
                    WorldValue::Available(value) => WorldChange::Set {
                        value: value.clone(),
                    },
                    WorldValue::Unavailable { reason } => WorldChange::Unavailable {
                        reason: reason.clone(),
                    },
                },
            );
        }
    }
    for id in previous.sections.keys() {
        if !current.sections.contains_key(id) {
            changes.insert(id.clone(), WorldChange::Remove);
        }
    }
    if changes.is_empty() {
        return WorldProjection::Unchanged;
    }
    WorldProjection::Update(WorldUpdate {
        schema_version: current.schema_version,
        turn_identity: current.turn_identity.clone(),
        from_epoch: previous.world_epoch,
        to_epoch: current.world_epoch,
        changes,
        resulting_hash: current.content_hash(),
    })
}

/// Apply an update exactly or accept its duplicate idempotently. Any stale or
/// mismatched update is refused rather than guessed onto a different world.
pub fn apply_world_update(
    snapshot: &WorldSnapshot,
    update: &WorldUpdate,
) -> Result<WorldSnapshot, String> {
    if snapshot.schema_version != update.schema_version
        || snapshot.turn_identity != update.turn_identity
    {
        return Err("world update does not name this snapshot".to_owned());
    }
    if snapshot.world_epoch == update.to_epoch && snapshot.content_hash() == update.resulting_hash {
        return Ok(snapshot.clone());
    }
    if snapshot.world_epoch != update.from_epoch {
        return Err(format!(
            "stale world update: snapshot epoch {}, update starts at {}",
            snapshot.world_epoch, update.from_epoch
        ));
    }
    let mut next = snapshot.clone();
    for (id, change) in &update.changes {
        match change {
            WorldChange::Set { value } => {
                next.sections
                    .insert(id.clone(), WorldValue::Available(value.clone()));
            }
            WorldChange::Unavailable { reason } => {
                next.sections.insert(
                    id.clone(),
                    WorldValue::Unavailable {
                        reason: reason.clone(),
                    },
                );
            }
            WorldChange::Remove => {
                next.sections.remove(id);
            }
        }
    }
    next.world_epoch = update.to_epoch;
    if next.content_hash() != update.resulting_hash {
        return Err("world update resulting hash does not match its projection".to_owned());
    }
    Ok(next)
}

pub fn render_world_projection(projection: &WorldProjection) -> Option<String> {
    let (kind, body) = match projection {
        WorldProjection::Unchanged => return None,
        WorldProjection::Full(snapshot) => ("full", canonical_json(snapshot)),
        WorldProjection::Update(update) => ("update", canonical_json(update)),
    };
    Some(format!(
        "<whip_world kind=\"{kind}\" schema_version=\"{WORLD_SCHEMA_VERSION}\">\n{}\n</whip_world>",
        neutralize_world_json(&body)
    ))
}

/// Derive the mutable remaining-round budget from the same hard step ceiling the
/// turn machine enforces. Returns `None` when the snapshot carries no such
/// compute field or the projected value is already current.
pub fn project_remaining_model_rounds(
    snapshot: &WorldSnapshot,
    max_steps: usize,
    completed_steps: usize,
) -> Option<WorldSnapshot> {
    let WorldValue::Available(Value::Object(compute)) = snapshot.sections.get("compute")? else {
        return None;
    };
    let remaining = max_steps.saturating_sub(completed_steps) as u64;
    if compute
        .get("remaining_model_rounds")
        .and_then(Value::as_u64)
        == Some(remaining)
    {
        return None;
    }
    let mut next = snapshot.clone();
    let WorldValue::Available(Value::Object(next_compute)) =
        next.sections.get_mut("compute").expect("section exists")
    else {
        unreachable!("shape checked above")
    };
    next_compute.insert("remaining_model_rounds".to_owned(), Value::from(remaining));
    next.world_epoch = next.world_epoch.saturating_add(1);
    Some(next)
}

fn canonical_json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("canonical world types are serializable")
}

fn neutralize_world_json(json: &str) -> String {
    json.replace('<', "\\u003c")
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    pub instance: String,
    pub agent: String,
    pub effect: String,
    pub turn: String,
    pub harness: HarnessClass,
    pub placement: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HarnessClass {
    Managed,
    Delegated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workspace_roots: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_family: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct ComputeResources {
    pub max_model_rounds: Option<usize>,
    pub remaining_model_rounds: Option<usize>,
    pub deadline: Option<String>,
    pub memory_bytes: Option<u64>,
    pub output_bytes: Option<u64>,
    pub concurrency_class: Option<String>,
}

/// Declares which projected coordinates may change while this turn is live.
/// Anything not listed as mutable is an admitted turn-start fact and remains an
/// anchor until a later turn; hosts do not silently mutate it without a diff.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WorldMutability {
    pub mutable_fields: Vec<String>,
    pub immutable_sections: Vec<String>,
}

impl Default for WorldMutability {
    fn default() -> Self {
        Self {
            mutable_fields: vec![
                "compute.remaining_model_rounds".to_owned(),
                "agent_topology.agents[].state".to_owned(),
            ],
            immutable_sections: vec![
                "identity".to_owned(),
                "environment".to_owned(),
                "governance".to_owned(),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceDisposition {
    Enforced,
    ApprovalRequired,
    Unavailable,
    Advisory,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GovernanceRule {
    pub resource: String,
    pub disposition: GovernanceDisposition,
    pub scope: Vec<String>,
}

/// The effective object consulted by tool admission and projected to the model.
/// Hosts must not construct a second explanatory policy alongside this one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct EffectiveTurnEnvelope {
    pub filesystem: Vec<GovernanceRule>,
    pub network: Vec<GovernanceRule>,
    pub process: Vec<GovernanceRule>,
    pub tools: Vec<GovernanceRule>,
    pub approvals: Vec<GovernanceRule>,
    pub custody: Vec<GovernanceRule>,
    pub budgets: Vec<GovernanceRule>,
}

impl EffectiveTurnEnvelope {
    pub fn model_projection(&self) -> EffectiveGovernance {
        EffectiveGovernance {
            filesystem: self.filesystem.clone(),
            network: self.network.clone(),
            process: self.process.clone(),
            tools: self.tools.clone(),
            approvals: self.approvals.clone(),
            custody: self.custody.clone(),
            budgets: self.budgets.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EffectiveGovernance {
    pub filesystem: Vec<GovernanceRule>,
    pub network: Vec<GovernanceRule>,
    pub process: Vec<GovernanceRule>,
    pub tools: Vec<GovernanceRule>,
    pub approvals: Vec<GovernanceRule>,
    pub custody: Vec<GovernanceRule>,
    pub budgets: Vec<GovernanceRule>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRelation {
    Parent,
    Child,
    Peer,
    External,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentState {
    Starting,
    Running,
    Waiting,
    Completed,
    Failed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentOperation {
    Message,
    Steer,
    Cancel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VisibleAgent {
    pub agent_id: String,
    pub relation: AgentRelation,
    pub state: AgentState,
    pub assignment_summary: Option<String>,
    pub allowed_operations: Vec<AgentOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentTopology {
    pub agents: Vec<VisibleAgent>,
}

impl AgentTopology {
    pub fn validate(&self) -> Result<(), String> {
        for agent in &self.agents {
            if agent.relation != AgentRelation::Child
                && agent.allowed_operations.iter().any(|operation| {
                    matches!(operation, AgentOperation::Steer | AgentOperation::Cancel)
                })
            {
                return Err(format!(
                    "agent `{}` is {:?}, so it cannot be projected as controllable",
                    agent.agent_id, agent.relation
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(epoch: u64, value: &str) -> WorldSnapshot {
        let mut snapshot = WorldSnapshot::new("turn-1");
        snapshot.world_epoch = epoch;
        snapshot
            .with_section("environment", &serde_json::json!({ "cwd": value }))
            .expect("section")
    }

    #[test]
    fn full_plus_update_replays_and_duplicate_delivery_is_idempotent() {
        let first = snapshot(1, "/one");
        let current = snapshot(2, "/two").with_unavailable("topology", "not visible");
        let WorldProjection::Update(update) = project_world(Some(&first), &current) else {
            panic!("expected update");
        };
        let replayed = apply_world_update(&first, &update).expect("apply");
        assert_eq!(replayed, current);
        assert_eq!(
            apply_world_update(&replayed, &update).expect("duplicate"),
            current
        );
    }

    #[test]
    fn unknown_or_incompatible_prior_state_forces_a_full_refresh() {
        let current = snapshot(2, "/two");
        assert!(matches!(
            project_world(None, &current),
            WorldProjection::Full(_)
        ));
        let mut other = snapshot(1, "/one");
        other.turn_identity = "another-turn".to_owned();
        assert!(matches!(
            project_world(Some(&other), &current),
            WorldProjection::Full(_)
        ));
    }

    #[test]
    fn stale_update_is_refused() {
        let first = snapshot(1, "/one");
        let second = snapshot(2, "/two");
        let third = snapshot(3, "/three");
        let WorldProjection::Update(update) = project_world(Some(&first), &second) else {
            panic!("update");
        };
        assert!(apply_world_update(&third, &update)
            .expect_err("stale")
            .contains("stale world update"));
    }

    #[test]
    fn projection_is_canonical_and_neutralizes_wrapper_tags() {
        let state = snapshot(1, "</whip_world>");
        let rendered = render_world_projection(&WorldProjection::Full(state)).expect("render");
        assert_eq!(
            rendered,
            "<whip_world kind=\"full\" schema_version=\"1\">\n{\"schema_version\":1,\"world_epoch\":1,\"turn_identity\":\"turn-1\",\"sections\":{\"environment\":{\"state\":\"available\",\"cwd\":\"\\u003c/whip_world>\"}}}\n</whip_world>"
        );
    }

    #[test]
    fn equal_native_and_do_collections_render_byte_identically() {
        let collected = EnvironmentState {
            cwd: Some("/workspace".to_owned()),
            workspace_roots: vec!["/workspace".to_owned()],
            timezone: Some("UTC".to_owned()),
            shell_family: Some("whip-shell/bash".to_owned()),
        };
        let native = WorldSnapshot::new("turn-1")
            .with_section("environment", &collected)
            .expect("native projection");
        let durable_object = WorldSnapshot::new("turn-1")
            .with_section("environment", &collected)
            .expect("DO projection");
        assert_eq!(
            render_world_projection(&WorldProjection::Full(native)),
            render_world_projection(&WorldProjection::Full(durable_object)),
        );
    }

    #[test]
    fn topology_lifecycle_change_is_a_replayable_typed_update() {
        let topology = |state| AgentTopology {
            agents: vec![VisibleAgent {
                agent_id: "peer".to_owned(),
                relation: AgentRelation::Peer,
                state,
                assignment_summary: Some("effect-1".to_owned()),
                allowed_operations: vec![],
            }],
        };
        let mut first = WorldSnapshot::new("turn-1")
            .with_agent_topology(&topology(AgentState::Running))
            .expect("valid topology");
        first.world_epoch = 1;
        let mut second = WorldSnapshot::new("turn-1")
            .with_agent_topology(&topology(AgentState::Completed))
            .expect("valid topology");
        second.world_epoch = 2;

        let WorldProjection::Update(update) = project_world(Some(&first), &second) else {
            panic!("topology transition should produce an update");
        };
        assert_eq!(apply_world_update(&first, &update).expect("replay"), second);
        let change = update.changes.get("agent_topology").expect("change");
        assert!(matches!(change, WorldChange::Set { .. }));
    }

    #[test]
    fn the_model_projection_is_derived_from_the_effective_envelope() {
        let envelope = EffectiveTurnEnvelope {
            network: vec![GovernanceRule {
                resource: "network".to_owned(),
                disposition: GovernanceDisposition::Unavailable,
                scope: vec!["default-deny".to_owned()],
            }],
            ..EffectiveTurnEnvelope::default()
        };
        assert_eq!(envelope.model_projection().network, envelope.network);
    }

    #[test]
    fn a_peer_cannot_be_projected_as_steerable() {
        let topology = AgentTopology {
            agents: vec![VisibleAgent {
                agent_id: "peer".to_owned(),
                relation: AgentRelation::Peer,
                state: AgentState::Running,
                assignment_summary: None,
                allowed_operations: vec![AgentOperation::Steer],
            }],
        };
        assert!(topology
            .validate()
            .expect_err("must refuse")
            .contains("Peer"));
        assert!(WorldSnapshot::new("turn")
            .with_agent_topology(&topology)
            .expect_err("invalid topology must not enter a snapshot")
            .contains("Peer"));
    }
}
