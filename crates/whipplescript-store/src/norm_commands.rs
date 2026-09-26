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
    /// Render one manifest as a document at a frontier (§8.1).
    Render {
        manifest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frontier: Option<Vec<String>>,
    },
    /// The diff of meaning from one frontier to another; `after` omitted is
    /// the captured current frontier, named in the result.
    Diff {
        before: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<Vec<String>>,
    },
    /// Explain one record at a frontier.
    Explain {
        record: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frontier: Option<Vec<String>>,
    },
    /// Evaluate a typed query (§8, `norm_query`) at a frontier; a query that
    /// reaches the artifact names the cut it is read at.
    Query {
        expression: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        frontier: Option<Vec<String>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cut: Option<String>,
    },
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
    Rendered {
        captured: NormReadAnchor,
        rendering: Box<crate::norm_views::ManifestRendering>,
    },
    Differed {
        captured: NormReadAnchor,
        diff: Box<crate::norm_views::MeaningDiff>,
    },
    Explained {
        captured: NormReadAnchor,
        explanation: Box<crate::norm_views::Explanation>,
    },
    Queried {
        captured: NormReadAnchor,
        result: Box<crate::norm_query::QueryResult>,
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
    /// Every declared relation family with its live edges and the basis an
    /// act binds (DR-0122); a family with no edges still has a basis.
    #[serde(default)]
    pub families: BTreeMap<String, crate::norm_relations::RelationFamilyView>,
    /// Every manifest record's derived completeness judgment (DR-0122): an
    /// exhaustive claim judged at the frontier it bound, a bounded claim
    /// within its scope. Never inferred from the members.
    #[serde(default)]
    pub manifests: BTreeMap<String, crate::norm_manifests::ManifestJudgment>,
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
    gated_refs: Option<&'a mut dyn FnMut() -> StoreResult<()>>,
}
impl<'a, S: NormCommandStore> NormCommandHost<'a, S> {
    pub fn new(store: &'a mut S, verifier: &'a dyn NormVerifier) -> Self {
        Self {
            store,
            verifier,
            artifacts: None,
            gated_refs: None,
        }
    }

    /// The host's way to lease its gated refs (norm-plane §5). A ledger's
    /// first event — a bootstrap, or an import that may carry one — leases
    /// them before it lands, so a governed workspace's mainline never exists
    /// unleased; an append that then fails leaves the lease, which only
    /// over-protects, and the ungoverned gate still admits through it.
    pub fn with_gated_refs(mut self, lease: &'a mut dyn FnMut() -> StoreResult<()>) -> Self {
        self.gated_refs = Some(lease);
        self
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
            manifests: self.manifest_judgments(&view, None)?,
            families: view.relation_families()?,
            inventory: view.requirement_inventory()?,
            checkpoint: view.checkpoint(),
            frontier: view.frontier.into_iter().collect(),
            owner: view.owner,
            charter: view.charter,
            records,
        })
    }

    /// An exhaustive claim is judged by projecting the verified history at the
    /// frontier the act bound, so the judgment is the same in every replay and
    /// stays a historical one when the inventory moves afterwards.
    fn manifest_judgments(
        &self,
        view: &NormView,
        captured: Option<&CapturedNormHistory>,
    ) -> StoreResult<BTreeMap<String, crate::norm_manifests::ManifestJudgment>> {
        use crate::norm_manifests::{judge, ManifestCompleteness, ManifestJudgment};
        let mut judgments = BTreeMap::new();
        let mut history = None;
        for record in view.records.values() {
            let Some((_, manifest)) = view.manifest_of(&record.vocabulary) else {
                continue;
            };
            let members: Vec<String> = record
                .fields
                .get(&manifest.members)
                .and_then(serde_json::Value::as_array)
                .map(|members| {
                    members
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let claim = record
                .fields
                .get(&manifest.claim)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let completeness = if claim == manifest.exhaustive {
                let basis: Vec<String> = view.manifest_basis(&record.id).unwrap_or(&[]).to_vec();
                let history = match captured {
                    Some(captured) => captured,
                    None => {
                        if history.is_none() {
                            history = Some(self.history()?);
                        }
                        history.as_ref().expect("captured above")
                    }
                };
                match history.project(Some(&basis), self.verifier) {
                    Ok(at_basis) => judge(&members, &at_basis.requirement_inventory()?, basis),
                    Err(error) => ManifestCompleteness::Unresolved {
                        basis,
                        reason: format!(
                            "the bound basis is not a frontier of this history: {error:?}"
                        ),
                    },
                }
            } else {
                ManifestCompleteness::Bounded {
                    scope: manifest
                        .scope
                        .as_ref()
                        .and_then(|field| record.fields.get(field))
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                }
            };
            judgments.insert(
                record.id.clone(),
                ManifestJudgment {
                    revision: record.content_head.clone(),
                    claim,
                    completeness,
                },
            );
        }
        Ok(judgments)
    }

    /// Every act of a projected view as an explanation cites it: causal
    /// parents from the transport and the statement it carries. The history
    /// was verified at capture; this reads it, it does not authenticate again.
    fn acts_of(
        &self,
        history: &CapturedNormHistory,
        view: &NormView,
    ) -> StoreResult<BTreeMap<String, crate::norm_views::ExplainedAct>> {
        let events: BTreeMap<&str, &TrackerEvent> = history
            .events()
            .map(|event| (event.event_id.as_str(), event))
            .collect();
        let mut acts = BTreeMap::new();
        for id in view.event_order() {
            let Some(event) = events.get(id.as_str()) else {
                continue;
            };
            let signed: SignedNormEvent = serde_json::from_str(&event.payload_json)?;
            acts.insert(
                id.clone(),
                crate::norm_views::ExplainedAct {
                    parents: event.parents.clone(),
                    statement: signed.statement,
                },
            );
        }
        Ok(acts)
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
        let governs = match &request.command {
            NormCommand::Append { event } => {
                matches!(
                    event.statement.action,
                    crate::norm::NormAct::Bootstrap { .. }
                )
            }
            NormCommand::Import { .. } => true,
            _ => false,
        };
        if governs {
            if let Some(lease) = self.gated_refs.as_mut() {
                lease()?;
            }
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
            NormCommand::Render { manifest, frontier } => {
                let history = self.history()?;
                let view = history.project(frontier.as_deref(), self.verifier)?;
                let manifests = self.manifest_judgments(&view, Some(&history))?;
                let aliases = self.store.local_norm_aliases()?;
                let context = crate::norm_views::ViewContext {
                    view: &view,
                    aliases: &aliases,
                    manifests: &manifests,
                };
                NormCommandResult::Rendered {
                    captured: history.anchor(),
                    rendering: Box::new(crate::norm_views::render_manifest(&context, &manifest)?),
                }
            }
            NormCommand::Query {
                expression,
                frontier,
                cut,
            } => {
                let query = crate::norm_query::parse(&expression)?;
                let history = self.history()?;
                let view = history.project(frontier.as_deref(), self.verifier)?;
                let manifests = self.manifest_judgments(&view, Some(&history))?;
                let aliases = self.store.local_norm_aliases()?;
                let context = crate::norm_views::ViewContext {
                    view: &view,
                    aliases: &aliases,
                    manifests: &manifests,
                };
                let captured_artifact = match &cut {
                    Some(cut) => Some(self.capture_artifact(cut)?),
                    None => None,
                };
                let resources = match &captured_artifact {
                    Some(artifact) => {
                        Some(view.resource_inventory(artifact, ResourceLimits::default())?)
                    }
                    None => None,
                };
                let artifact_paths: Option<std::collections::BTreeSet<String>> = captured_artifact
                    .as_ref()
                    .map(|artifact| artifact.files().keys().cloned().collect());
                let result = crate::norm_query::evaluate(
                    &query,
                    &crate::norm_query::QueryInput {
                        context: &context,
                        resources: resources.as_ref(),
                        artifact_paths: artifact_paths.as_ref(),
                        redacted: 0,
                    },
                )?;
                NormCommandResult::Queried {
                    captured: history.anchor(),
                    result: Box::new(result),
                }
            }
            NormCommand::Diff { before, after } => {
                let history = self.history()?;
                let before_view = history.project(Some(&before), self.verifier)?;
                let after_view = history.project(after.as_deref(), self.verifier)?;
                let before_manifests = self.manifest_judgments(&before_view, Some(&history))?;
                let after_manifests = self.manifest_judgments(&after_view, Some(&history))?;
                let aliases = self.store.local_norm_aliases()?;
                let diff = crate::norm_views::diff_meaning(
                    &crate::norm_views::ViewContext {
                        view: &before_view,
                        aliases: &aliases,
                        manifests: &before_manifests,
                    },
                    &crate::norm_views::ViewContext {
                        view: &after_view,
                        aliases: &aliases,
                        manifests: &after_manifests,
                    },
                )?;
                NormCommandResult::Differed {
                    captured: history.anchor(),
                    diff: Box::new(diff),
                }
            }
            NormCommand::Explain { record, frontier } => {
                let history = self.history()?;
                let view = history.project(frontier.as_deref(), self.verifier)?;
                let manifests = self.manifest_judgments(&view, Some(&history))?;
                let aliases = self.store.local_norm_aliases()?;
                let acts = self.acts_of(&history, &view)?;
                let context = crate::norm_views::ViewContext {
                    view: &view,
                    aliases: &aliases,
                    manifests: &manifests,
                };
                NormCommandResult::Explained {
                    captured: history.anchor(),
                    explanation: Box::new(crate::norm_views::explain_record(
                        &context, &acts, &record,
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
