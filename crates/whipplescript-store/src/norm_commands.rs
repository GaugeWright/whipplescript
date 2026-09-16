//! Shared norm command protocol. A host constructs this dispatcher only after
//! granting full-ledger access. Request data cannot install a verifier, creation
//! grant, or restoration checkpoint. IFC-filtered queries are a separate surface.

use crate::items::TrackerEvent;
use crate::norm::{
    EffectiveRevision, NormActor, NormCharter, NormCheckpoint, NormRecord, NormVerifier, NormView,
    SignedNormEvent,
};
use crate::norm_artifact::CapturedArtifact;
use crate::norm_history::{CapturedNormHistory, NormHistoryLimits, NormReadAnchor};
use crate::norm_resources::{
    compare_resources, ResourceInventory, ResourceInventoryPair, ResourceLimits,
};
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const NORM_COMMAND_PROTOCOL: &str = "whipplescript.norm.commands/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormCommandRequest {
    pub protocol: String,
    pub command: NormCommand,
}
impl NormCommandRequest {
    pub fn new(command: NormCommand) -> Self {
        Self {
            protocol: NORM_COMMAND_PROTOCOL.into(),
            command,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormCommand {
    Append {
        event: Box<SignedNormEvent>,
    },
    Import {
        events: Vec<TrackerEvent>,
    },
    Snapshot {},
    Inventory {},
    SnapshotAt {
        frontier: Vec<String>,
    },
    InventoryAt {
        frontier: Vec<String>,
    },
    Resources {
        point: NormResourcePoint,
    },
    CompareResources {
        before: NormResourcePoint,
        after: NormResourcePoint,
    },
    Export {},
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormResourcePoint {
    pub cut: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontier: Option<Vec<String>>,
}

/// Configured only by a host with whole-workspace read authority. The request
/// cannot supply file bytes, store paths, a trusted cut row, or larger limits.
pub type NormArtifactCapture<'a> = dyn Fn(&str) -> StoreResult<CapturedArtifact> + 'a;

impl NormCommand {
    pub fn append(event: SignedNormEvent) -> Self {
        Self::Append {
            event: Box::new(event),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormCommandResponse {
    pub protocol: String,
    pub result: NormCommandResult,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NormCommandResult {
    Appended {
        event_id: String,
    },
    Imported {
        inserted: usize,
    },
    Snapshot {
        snapshot: Box<NormSnapshot>,
    },
    Inventory {
        inventory: crate::norm_inventory::RequirementInventory,
    },
    HistoricalSnapshot {
        captured: NormReadAnchor,
        snapshot: Box<NormSnapshot>,
    },
    HistoricalInventory {
        captured: NormReadAnchor,
        inventory: crate::norm_inventory::RequirementInventory,
    },
    Resources {
        captured: NormReadAnchor,
        resources: Box<ResourceInventory>,
    },
    ResourceComparison {
        captured: NormReadAnchor,
        comparison: Box<ResourceInventoryPair>,
    },
    Exported {
        checkpoint: NormCheckpoint,
        frontier: Vec<String>,
        events: Vec<TrackerEvent>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormSnapshot {
    pub checkpoint: NormCheckpoint,
    pub frontier: Vec<String>,
    pub owner: NormActor,
    pub charter: NormCharter,
    pub records: Vec<NamedNormRecord>,
    pub inventory: crate::norm_inventory::RequirementInventory,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedNormRecord {
    pub alias: String,
    pub record: NormRecord,
    pub effectiveness: EffectiveRevision,
}

/// Store adapters retain their atomic admission implementations. This trait
/// deliberately has no method for installing trusted configuration from commands.
pub trait NormCommandStore {
    fn norm_state(&self, verifier: &dyn NormVerifier) -> StoreResult<NormView>;
    fn local_norm_aliases(&self) -> StoreResult<BTreeMap<String, String>>;
    fn tracker_history(&self) -> StoreResult<Vec<TrackerEvent>>;
    fn append_norm(
        &mut self,
        event: &SignedNormEvent,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<String>;
    fn import_norm(
        &mut self,
        events: &[TrackerEvent],
        verifier: &dyn NormVerifier,
    ) -> StoreResult<usize>;
}

pub struct NormCommandHost<'a, S: NormCommandStore> {
    store: &'a mut S,
    verifier: &'a dyn NormVerifier,
    artifacts: Option<&'a NormArtifactCapture<'a>>,
}
impl<'a, S: NormCommandStore> NormCommandHost<'a, S> {
    pub fn new(store: &'a mut S, verifier: &'a dyn NormVerifier) -> Self {
        Self {
            store,
            verifier,
            artifacts: None,
        }
    }

    pub fn with_artifacts(mut self, artifacts: &'a NormArtifactCapture<'a>) -> Self {
        self.artifacts = Some(artifacts);
        self
    }

    fn history(&self) -> StoreResult<CapturedNormHistory> {
        let current = self.store.norm_state(self.verifier)?;
        CapturedNormHistory::capture(
            &current,
            &self.store.tracker_history()?,
            self.verifier,
            NormHistoryLimits::default(),
        )
    }

    fn snapshot(&self, view: NormView) -> StoreResult<NormSnapshot> {
        let aliases = self.store.local_norm_aliases()?;
        let mut records = Vec::with_capacity(view.records.len());
        for record in view.records.values() {
            let alias = aliases.get(&record.id).ok_or_else(|| {
                StoreError::Conflict(
                    "verified norm record is missing its durable local alias".into(),
                )
            })?;
            records.push(NamedNormRecord {
                alias: alias.clone(),
                record: record.clone(),
                effectiveness: view.effective_revision(record),
            });
        }
        Ok(NormSnapshot {
            inventory: view.requirement_inventory()?,
            checkpoint: view.checkpoint(),
            frontier: view.frontier.into_iter().collect(),
            owner: view.owner,
            charter: view.charter,
            records,
        })
    }

    fn capture_artifact(&self, cut: &str) -> StoreResult<CapturedArtifact> {
        let Some(capture) = self.artifacts else {
            return Err(StoreError::Conflict(
                "norm resource queries require a host-owned artifact source".into(),
            ));
        };
        let artifact = capture(cut)?;
        if artifact.basis().cut != cut {
            return Err(StoreError::Conflict(
                "host returned a different norm artifact cut".into(),
            ));
        }
        Ok(artifact)
    }

    /// Decode the original transport body before dispatch. Embeddings must not
    /// parse and reserialize it first: that can erase duplicate fields before
    /// the typed decoder has a chance to refuse them.
    pub fn execute_json(&mut self, request: &str) -> StoreResult<String> {
        let request = serde_json::from_str(request)?;
        let response = self.execute(request)?;
        Ok(serde_json::to_string(&response)?)
    }

    pub fn execute(&mut self, request: NormCommandRequest) -> StoreResult<NormCommandResponse> {
        if request.protocol != NORM_COMMAND_PROTOCOL {
            return Err(StoreError::Conflict(
                "unsupported norm command protocol".into(),
            ));
        }
        let result = match request.command {
            NormCommand::Append { event } => NormCommandResult::Appended {
                event_id: self.store.append_norm(&event, self.verifier)?,
            },
            NormCommand::Import { events } => NormCommandResult::Imported {
                inserted: self.store.import_norm(&events, self.verifier)?,
            },
            NormCommand::Inventory {} => NormCommandResult::Inventory {
                inventory: self
                    .store
                    .norm_state(self.verifier)?
                    .requirement_inventory()?,
            },
            NormCommand::Snapshot {} => NormCommandResult::Snapshot {
                snapshot: Box::new(self.snapshot(self.store.norm_state(self.verifier)?)?),
            },
            NormCommand::SnapshotAt { frontier } => {
                let history = self.history()?;
                let view = history.project(Some(&frontier), self.verifier)?;
                NormCommandResult::HistoricalSnapshot {
                    captured: history.anchor(),
                    snapshot: Box::new(self.snapshot(view)?),
                }
            }
            NormCommand::InventoryAt { frontier } => {
                let history = self.history()?;
                let view = history.project(Some(&frontier), self.verifier)?;
                NormCommandResult::HistoricalInventory {
                    captured: history.anchor(),
                    inventory: view.requirement_inventory()?,
                }
            }
            NormCommand::Resources { point } => {
                let history = self.history()?;
                let view = history.project(point.frontier.as_deref(), self.verifier)?;
                let artifact = self.capture_artifact(&point.cut)?;
                NormCommandResult::Resources {
                    captured: history.anchor(),
                    resources: Box::new(
                        view.resource_inventory(&artifact, ResourceLimits::default())?,
                    ),
                }
            }
            NormCommand::CompareResources { before, after } => {
                let history = self.history()?;
                let before_view = history.project(before.frontier.as_deref(), self.verifier)?;
                let after_view = history.project(after.frontier.as_deref(), self.verifier)?;
                let before_artifact = self.capture_artifact(&before.cut)?;
                let after_artifact = self.capture_artifact(&after.cut)?;
                NormCommandResult::ResourceComparison {
                    captured: history.anchor(),
                    comparison: Box::new(compare_resources(
                        &before_view,
                        &before_artifact,
                        &after_view,
                        &after_artifact,
                        ResourceLimits::default(),
                    )?),
                }
            }
            NormCommand::Export {} => {
                let view = self.store.norm_state(self.verifier)?;
                let mut history: BTreeMap<_, _> = self
                    .store
                    .tracker_history()?
                    .into_iter()
                    .map(|event| (event.event_id.clone(), event))
                    .collect();
                let mut events = Vec::with_capacity(view.event_order().len());
                // Capture only the verified view's causal frontier, even if a
                // concurrent writer appends between the two monotonic reads.
                for id in view.event_order() {
                    let event = history.remove(id).ok_or_else(|| {
                        StoreError::Conflict(
                            "verified norm history disappeared during export".into(),
                        )
                    })?;
                    events.push(event);
                }
                NormCommandResult::Exported {
                    checkpoint: view.checkpoint(),
                    frontier: view.frontier.into_iter().collect(),
                    events,
                }
            }
        };
        Ok(NormCommandResponse {
            protocol: NORM_COMMAND_PROTOCOL.into(),
            result,
        })
    }
}

#[cfg(feature = "native")]
impl NormCommandStore for crate::items::WorkItemStore {
    fn norm_state(&self, verifier: &dyn NormVerifier) -> StoreResult<NormView> {
        self.norm_view(verifier)
    }
    fn local_norm_aliases(&self) -> StoreResult<BTreeMap<String, String>> {
        self.norm_aliases()
    }
    fn tracker_history(&self) -> StoreResult<Vec<TrackerEvent>> {
        self.export_events()
    }
    fn append_norm(
        &mut self,
        event: &SignedNormEvent,
        verifier: &dyn NormVerifier,
    ) -> StoreResult<String> {
        self.append_norm_event(event, verifier)
    }
    fn import_norm(
        &mut self,
        events: &[TrackerEvent],
        verifier: &dyn NormVerifier,
    ) -> StoreResult<usize> {
        self.import_norm_events(events, verifier)
    }
}
