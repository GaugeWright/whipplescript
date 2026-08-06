//! Durable SQLite store for event logs, facts, effects, and evidence.

pub mod branches;
pub mod bundle;
pub mod chunking;
pub mod content;
pub mod coordination;
pub mod diff;
pub mod files;
pub mod improve;
pub mod incidents;
pub mod items;
pub mod materialize;
pub mod memory;
pub mod merge;
#[cfg(feature = "native")]
pub mod native_stores;
pub mod reconcile;
/// Relocated to `whipplescript-core` (DR-0052 R4.2: one selection
/// grammar validates statically in the parser and dynamically at the
/// seams — no mirror to drift). Re-exported here so every existing
/// `whipplescript_store::selection::…` path keeps working.
pub use whipplescript_core::selection;
pub mod skill_frontmatter;
pub mod stat_cache;
pub mod text_merge;
pub mod vcs;
pub mod working_set;
pub mod workspace_api;
pub mod workstreams;

use std::result;
#[cfg(feature = "native")]
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
// Re-exported so store-trait hosts built without the native backend (the DO
// host) can construct `DiagnosticRecord`s without a direct core dependency.
pub use whipplescript_core::Severity;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};
#[cfg(feature = "native")]
use serde_json::{json, Value};

pub type StoreResult<T> = result::Result<T, StoreError>;

/// DR-0054 Phase B: the highest `schema_migrations` version this build
/// understands. Must stay equal to the highest version in `MIGRATIONS`
/// (asserted by test); `apply_migrations` refuses to open a store stamped
/// beyond it instead of silently misreading a newer layout.
pub const SUPPORTED_SCHEMA_VERSION: i64 = 1;

/// DR-0054 Phase B: the `events.format_version` this build stamps on every
/// new row and the highest it will fold. Legacy rows carry NULL and read as
/// version 1; a row stamped beyond this fails the fold closed with its row
/// identity instead of misparsing.
pub const SUPPORTED_EVENT_FORMAT_VERSION: i64 = 1;

/// DR-0054 Phase B: the crate version recorded in `store_meta.writer_version`
/// on every open, so a store on disk can always be diagnosed ("which build
/// last wrote this?") without guessing from its contents.
pub const WRITER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    #[cfg(feature = "native")]
    Sqlite(rusqlite::Error),
    Json(serde_json::Error),
    Conflict(String),
    PolicyBlocked {
        effect_id: String,
        reason: String,
    },
    CapacityBlocked {
        effect_id: String,
        reason: String,
    },
    /// DR-0054 Phase B: persisted state is stamped with a version newer than
    /// this build supports (a rolled-back binary over a newer store). Fail
    /// closed — never open or fold it silently. The remediation is a build
    /// that understands `found`, never deleting the store.
    UnsupportedVersion {
        /// What carries the version stamp (e.g. "store schema", an event row).
        subject: String,
        found: i64,
        supported: i64,
    },
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(feature = "native")]
impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sqlite(error)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[cfg(feature = "native")]
pub struct SqliteStore {
    connection: Connection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredEvent {
    pub event_id: String,
    pub sequence: i64,
}

/// Restorable-context RC-3: a request to capture a consistent-cut checkpoint of
/// an instance at a quiescent point. The three planes the cut binds are the
/// agent transcript position (`transcript_ref`), the instance event-log
/// sequence (captured as the checkpoint event's own sequence), and the
/// file-store manifest hash (folded from `file.write.completed` facts at the
/// cut). Models `checkpointReq(cutId)` in models/maude/restorable-context.maude.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointCapture<'a> {
    pub instance_id: &'a str,
    /// Caller-supplied stable identifier for this cut (surfaces to `whip
    /// restore <cut_id>`).
    pub cut_id: &'a str,
    /// The transcript position at the cut — the owned-harness `checkpoint`
    /// callback's step marker (Plane 1). `None` when the instance has no
    /// brokered transcript yet.
    pub transcript_ref: Option<&'a str>,
    /// Idempotency key so a re-requested capture of the same cut is absorbed
    /// rather than duplicated.
    pub idempotency_key: Option<&'a str>,
}

/// Restorable-context RC-3: the recorded consistent cut. `sequence` is the
/// checkpoint event's own event-log index — the single cut coordinate that
/// `rebuild_projections_to` (Plane 2) and `load_brokered_transcript_at`
/// (Plane 1) key off. Models `cut(cutId, tPos, seqN, mHash)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedCheckpoint {
    pub cut_id: String,
    pub event_id: String,
    pub sequence: i64,
    pub manifest_hash: String,
    pub file_count: usize,
}

/// Restorable-context RC-4c: the outcome of PLANNING a restore. `plan_restore`
/// is read-only and performs the whole coherence check up front (models the
/// `restore-apply` vs `restore-refuse` split in
/// models/maude/restorable-context.maude): either every referenced content hash
/// is present and a `Ready` plan is returned, or a required hash is missing /
/// the cut is unknown and the restore is `Refused` with no mutation. The caller
/// applies the file ops through the file store, then calls `commit_restore`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreDecision {
    Ready(RestorePlan),
    Refused { reason: String },
}

/// The file + coordinate plan for a coherent restore. `writes` and `removes`
/// are the FULL reconcile of the mediated file plane to the cut manifest:
/// every manifest path is rewritten to its cut content, and every mediated path
/// present now but absent from the cut is removed. `restored_to_sequence` is the
/// cut coordinate the `context.restored` marker will carry (RC-4b), rewinding
/// the instance and transcript planes to the same point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePlan {
    pub cut_id: String,
    pub restored_to_sequence: i64,
    pub transcript_ref: Option<String>,
    pub writes: std::collections::BTreeMap<String, String>,
    pub removes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewEvent<'a> {
    pub instance_id: &'a str,
    pub event_type: &'a str,
    pub payload_json: &'a str,
    pub source: &'a str,
    pub causation_id: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewProgramVersion<'a> {
    pub program_name: &'a str,
    pub source_hash: &'a str,
    pub ir_hash: &'a str,
    pub compiler_version: &'a str,
    pub declared_capabilities_json: &'a str,
    pub declared_profiles_json: &'a str,
    pub declared_skills_json: &'a str,
    pub declared_schemas_json: &'a str,
    pub analysis_summary_json: &'a str,
    pub generated_artifacts_json: &'a str,
    pub artifact_root: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramVersionRecord {
    pub program_id: String,
    pub version_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramVersionView {
    pub program_id: String,
    pub program_name: String,
    pub version_id: String,
    pub source_hash: String,
    pub ir_hash: String,
    pub compiler_version: String,
    pub analysis_summary_json: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewInstance<'a> {
    pub program_id: &'a str,
    pub version_id: &'a str,
    pub input_json: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewInstanceAuthority<'a> {
    pub workflow_principal: &'a str,
    pub effective_authority_json: &'a str,
}

impl<'a> NewInstanceAuthority<'a> {
    pub fn empty() -> Self {
        Self {
            workflow_principal: "",
            effective_authority_json: "[]",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceRecord {
    pub instance_id: String,
    pub status: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceView {
    pub instance_id: String,
    pub program_id: String,
    pub version_id: String,
    pub revision_epoch: i64,
    pub workflow_principal: String,
    pub effective_authority_json: String,
    pub status: String,
    pub input_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleCommit<'a> {
    pub instance_id: &'a str,
    pub rule: &'a str,
    pub trigger_event_id: Option<&'a str>,
    pub facts: &'a [NewFact<'a>],
    pub consumed_fact_ids: &'a [&'a str],
    pub effects: &'a [NewEffect<'a>],
    pub dependencies: &'a [NewEffectDependency<'a>],
    pub terminal: Option<WorkflowTerminal<'a>>,
    pub idempotency_key: Option<&'a str>,
    /// Declared `mark` names riding this committing site: a `mark.reached`
    /// event per name is appended IN the commit transaction, so a cut
    /// coordinate can never be lost between a durable commit and a
    /// separate append (the experimentation surface's named cut points).
    pub marks: &'a [&'a str],
    /// DR-0043 slice 1: the firing's pinned context — identity plus the bound
    /// trigger values — serialized by the kernel and embedded verbatim in the
    /// `rule.committed` payload, making every firing record self-contained
    /// (pinned re-lowering reads the record, replay is byte-exact). `None`
    /// for callers that predate the pinning surface.
    pub context_json: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuleCommitRevisionGuard<'a> {
    pub program_version_id: &'a str,
    pub revision_epoch: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkflowTerminal<'a> {
    pub kind: WorkflowTerminalKind,
    pub name: &'a str,
    pub payload_json: &'a str,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowTerminalKind {
    Completed,
    Failed,
}

impl WorkflowTerminalKind {
    pub fn event_type(self) -> &'static str {
        match self {
            Self::Completed => "workflow.completed",
            Self::Failed => "workflow.failed",
        }
    }

    pub fn instance_status(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }

    pub fn action(self) -> &'static str {
        match self {
            Self::Completed => "complete",
            Self::Failed => "fail",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewFact<'a> {
    pub fact_id: &'a str,
    pub name: &'a str,
    pub key: &'a str,
    pub value_json: &'a str,
    pub schema_id: Option<&'a str>,
    pub provenance_class: &'a str,
    pub correlation_id: Option<&'a str>,
    pub source_span_json: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DerivedFact<'a> {
    pub instance_id: &'a str,
    pub fact: NewFact<'a>,
    pub source: &'a str,
    pub causation_id: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

/// One row of a typed fact batch (spec/admission-and-idempotency.md). `fact_id`
/// is the row's derived per-row admission key (the caller computes
/// `H(effect_key, row_index)` or `H(effect_key, natural_key)`); `key` is the
/// fact's natural key/index recorded on the fact row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactBatchRow<'a> {
    pub fact_id: &'a str,
    pub key: &'a str,
    pub value_json: &'a str,
}

/// A typed fact batch admitted atomically from one validated effect outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactBatch<'a> {
    pub instance_id: &'a str,
    pub source: &'a str,
    pub causation_id: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    /// The imported row schema name; each admitted fact carries it as its name.
    pub schema_name: &'a str,
    pub schema_id: Option<&'a str>,
    pub rows: &'a [FactBatchRow<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FactBatchOutcome {
    pub admitted: usize,
    pub skipped: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewEffect<'a> {
    pub effect_id: &'a str,
    pub kind: &'a str,
    pub target: Option<&'a str>,
    pub input_json: &'a str,
    pub status: &'a str,
    pub idempotency_key: &'a str,
    pub required_capabilities_json: &'a str,
    pub profile: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    pub source_span_json: Option<&'a str>,
    /// Creation-anchored deadline in seconds; for `timer.wait` effects this
    /// is the timer duration.
    pub timeout_seconds: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitySchemaRegistration<'a> {
    pub capability: &'a str,
    pub description: &'a str,
    pub schema_json: &'a str,
    pub registered_by_package_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectProviderRegistration<'a> {
    pub provider_id: &'a str,
    pub effect_kind: &'a str,
    pub provider: &'a str,
    pub capability: &'a str,
    pub config_json: &'a str,
    pub registered_by_package_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProfileRegistration<'a> {
    pub profile_id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub enforcement_mode: &'a str,
    pub allowed_capabilities_json: &'a str,
    pub config_json: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredProfilePolicy {
    pub enforcement_mode: String,
    pub allowed_capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackageRegistration<'a> {
    pub package_id: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub manifest_json: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityBinding<'a> {
    pub binding_id: &'a str,
    pub program_id: Option<&'a str>,
    pub capability: &'a str,
    pub provider: &'a str,
    pub config_json: &'a str,
}

/// One `capability_bindings` row as READ back for provider selection
/// (spec/std-messaging.md "Channel→binding provider selection"): where
/// `capability_bound_provider` collapses to a single name, this view carries
/// every binding bound for a capability — provider id plus the binding's
/// `config_json` (the capability report for messaging bindings) — so a
/// channel-scoped selection step can resolve its declared provider against
/// the full bound set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityBindingView {
    pub binding_id: String,
    pub program_id: Option<String>,
    pub capability: String,
    pub provider: Option<String>,
    pub config_json: String,
}

/// One project-instruction document (AGENTS.md / CLAUDE.md) registered for the
/// durable object's store-backed context resolution (context-assembly Phase 3
/// item 4). `position` is the injection order (root-most first, nearest-cwd
/// last); `content_hash` is the body's hash so it is content-addressed and
/// replay-stable, mirroring skills.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectContextDoc {
    pub position: i64,
    pub path: String,
    pub content_hash: String,
    pub body: String,
}

/// One recorded delta-kernel result (compute plane P8-1): the cached outcome
/// of a hermetic Class-A invocation, keyed by its content key (script hash +
/// environment hash + input hashes). Workspace-wide — not instance-scoped —
/// so a validator/judge on untouched inputs never runs twice. The source ids
/// record provenance (which run populated the entry).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComputeCachedResult {
    pub content_key: String,
    pub effect_kind: String,
    pub result_json: String,
    pub source_instance_id: String,
    pub source_effect_id: String,
    pub created_at: String,
}

/// Registration input for one delta-kernel cache entry. Insertion is
/// first-writer-wins (`INSERT OR IGNORE`): a content key is immutable once
/// recorded, which is what makes served-from-cache results canonical.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComputeResultRegistration<'a> {
    pub content_key: &'a str,
    pub effect_kind: &'a str,
    pub result_json: &'a str,
    pub source_instance_id: &'a str,
    pub source_effect_id: &'a str,
}

/// One operator-pinned script capability registered in the store (compute
/// plane P8): the store-backed mirror of the native filesystem script
/// manifest, for hosts with no filesystem (the DO builds `whip-executor/1`
/// requests from these rows). `body` is the full script text; `sha256` is
/// the operator's pin — the host layer verifies body-vs-pin at registration
/// and the executor re-verifies before running (the TOCTOU discipline).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScriptCapabilityRecord {
    pub name: String,
    pub argv_json: String,
    pub sha256: String,
    pub env_json: String,
    pub hermetic: bool,
    pub body: String,
}

/// Registration input for one script capability (`INSERT OR REPLACE`: a
/// re-pin is an explicit operator act, same as the native manifest).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptCapabilityRegistration<'a> {
    pub name: &'a str,
    pub argv_json: &'a str,
    pub sha256: &'a str,
    pub env_json: &'a str,
    pub hermetic: bool,
    pub body: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SkillRegistration<'a> {
    pub skill_id: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    pub source: &'a str,
    pub source_path: &'a str,
    /// The full SKILL.md bytes the model reads on activation. `content_hash` is
    /// this body's hash (Decision 3), so it is content-addressed and replay-stable.
    pub body: &'a str,
    pub description: &'a str,
    pub required_capabilities_json: &'a str,
    pub metadata_json: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SkillAttachment<'a> {
    pub attachment_id: &'a str,
    pub scope_type: &'a str,
    pub scope_id: &'a str,
    pub skill_name: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SkillEvidence<'a> {
    pub instance_id: &'a str,
    pub run_id: &'a str,
    pub effect_id: &'a str,
    pub skill_names: &'a [&'a str],
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillView {
    pub skill_id: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_path: String,
    pub content_hash: String,
    pub description: String,
    pub required_capabilities_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillAttachmentView {
    pub attachment_id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub skill: SkillView,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceRecord<'a> {
    pub instance_id: &'a str,
    pub kind: &'a str,
    pub subject_type: &'a str,
    pub subject_id: &'a str,
    pub causation_id: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    pub summary: Option<&'a str>,
    pub metadata_json: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceView {
    pub evidence_id: String,
    pub instance_id: String,
    pub kind: String,
    pub subject_type: String,
    pub subject_id: String,
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub summary: Option<String>,
    pub metadata_json: String,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvidenceLink<'a> {
    pub evidence_id: &'a str,
    pub instance_id: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub relation: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceLinkView {
    pub evidence_id: String,
    pub target_type: String,
    pub target_id: String,
    pub relation: String,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderValidationEvidence<'a> {
    pub instance_id: &'a str,
    pub provider_id: &'a str,
    pub provider_kind: &'a str,
    pub surface: &'a str,
    pub status: &'a str,
    pub config_json: &'a str,
    pub capability_json: &'a str,
    pub validation_results_json: &'a str,
    pub source_path: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodexAppServerEvidence<'a> {
    pub instance_id: &'a str,
    pub provider_id: &'a str,
    pub thread_id: &'a str,
    pub turn_id: &'a str,
    pub metadata_json: &'a str,
    pub correlation_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaudeAgentSdkEvidence<'a> {
    pub instance_id: &'a str,
    pub provider_id: &'a str,
    pub session_id: &'a str,
    pub run_id: &'a str,
    pub metadata_json: &'a str,
    pub correlation_id: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactRecord<'a> {
    pub run_id: &'a str,
    pub kind: &'a str,
    pub path: &'a str,
    pub content_hash: Option<&'a str>,
    pub mime_type: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactView {
    pub artifact_id: String,
    pub run_id: String,
    pub kind: String,
    pub path: String,
    pub content_hash: Option<String>,
    pub mime_type: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WorkspaceRecord<'a> {
    pub instance_id: Option<&'a str>,
    pub effect_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub provider: Option<&'a str>,
    pub policy: &'a str,
    pub uri: &'a str,
    pub status: &'a str,
    pub metadata_json: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceView {
    pub workspace_id: String,
    pub instance_id: Option<String>,
    pub effect_id: Option<String>,
    pub run_id: Option<String>,
    pub provider: Option<String>,
    pub policy: String,
    pub uri: String,
    pub status: String,
    pub metadata_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticRecord<'a> {
    pub instance_id: Option<&'a str>,
    pub program_id: Option<&'a str>,
    pub program_version_id: Option<&'a str>,
    pub severity: Severity,
    pub code: Option<&'a str>,
    pub message: &'a str,
    pub source_span_json: Option<&'a str>,
    pub subject_type: Option<&'a str>,
    pub subject_id: Option<&'a str>,
    pub event_id: Option<&'a str>,
    pub effect_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    pub assertion_id: Option<&'a str>,
    pub evidence_ids_json: &'a str,
    pub artifact_ids_json: &'a str,
    pub causation_id: Option<&'a str>,
    pub correlation_id: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalDiagnosticRecord {
    pub program_id: Option<String>,
    pub program_version_id: Option<String>,
    pub severity: Severity,
    pub code: Option<String>,
    pub message: String,
    pub source_span_json: Option<String>,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub assertion_id: Option<String>,
    pub evidence_ids_json: String,
    pub artifact_ids_json: String,
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub idempotency_key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticView {
    pub diagnostic_id: String,
    pub instance_id: Option<String>,
    pub program_id: Option<String>,
    pub program_version_id: Option<String>,
    pub severity: String,
    pub code: Option<String>,
    pub message: String,
    pub source_span_json: Option<String>,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub event_id: Option<String>,
    pub effect_id: Option<String>,
    pub run_id: Option<String>,
    pub assertion_id: Option<String>,
    pub evidence_ids_json: String,
    pub artifact_ids_json: String,
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub created_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewEffectDependency<'a> {
    pub dependency_id: &'a str,
    pub upstream_effect_id: &'a str,
    pub downstream_effect_id: &'a str,
    pub predicate: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NewWorkflowInvocation<'a> {
    pub invocation_id: &'a str,
    pub parent_instance_id: &'a str,
    pub parent_effect_id: &'a str,
    pub child_instance_id: &'a str,
    pub target_workflow: &'a str,
    pub input_json: &'a str,
    pub source_span_json: Option<&'a str>,
    pub idempotency_key: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowInvocationView {
    pub invocation_id: String,
    pub parent_instance_id: String,
    pub parent_effect_id: String,
    pub parent_program_version_id: Option<String>,
    pub parent_revision_epoch: i64,
    pub parent_active_program_version_id: Option<String>,
    pub parent_active_revision_epoch: Option<i64>,
    pub child_instance_id: String,
    pub child_program_version_id: Option<String>,
    pub child_revision_epoch: Option<i64>,
    pub child_active_program_version_id: Option<String>,
    pub child_active_revision_epoch: Option<i64>,
    pub target_workflow: String,
    pub input_json: String,
    pub status: String,
    pub terminal_event_id: Option<String>,
    pub source_span_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectCompletion<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub provider: &'a str,
    pub worker_id: &'a str,
    pub status: &'a str,
    pub exit_code: Option<i64>,
    pub summary: Option<&'a str>,
    pub metadata_json: &'a str,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimableEffect {
    pub effect_id: String,
    pub kind: String,
    pub target: Option<String>,
    pub profile: Option<String>,
    pub input_json: String,
    pub required_capabilities_json: String,
    pub declared_profiles_json: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventView {
    pub event_id: String,
    pub sequence: i64,
    pub event_type: String,
    pub payload_json: String,
    pub source: String,
    pub occurred_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactView {
    pub fact_id: String,
    pub program_version_id: Option<String>,
    pub revision_epoch: i64,
    pub name: String,
    pub key: String,
    pub value_json: String,
    pub provenance_class: String,
    pub source_span_json: Option<String>,
    /// The event that ADMITTED this fact (its current liveness generation).
    /// A consumed-then-re-recorded fact keeps its content identity but gains
    /// a fresh admitting event; the stepper folds this into a firing's
    /// trigger_event_id so re-admissions commit under distinct keys. Empty
    /// when reconstructed from contexts that predate the field.
    pub source_event_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectView {
    pub effect_id: String,
    pub kind: String,
    pub target: Option<String>,
    pub input_json: String,
    pub status: String,
    pub created_by_rule: String,
    pub program_version_id: Option<String>,
    pub revision_epoch: i64,
    pub profile: Option<String>,
    pub required_capabilities_json: String,
    pub declared_profiles_json: String,
    pub policy_block_reason: Option<String>,
    /// For binding-time blocks (status `blocked`), the categorized reason
    /// (`provider_config`/`credentials`/`enforcement`/`provider_health`). Scheduling
    /// blocks encode their category in the `blocked_by_*` status string instead.
    pub policy_block_category: Option<String>,
    pub cancel_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DueTimeEffect {
    pub effect_id: String,
    pub kind: String,
    pub status: String,
    pub timeout_seconds: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunView {
    pub run_id: String,
    pub effect_id: String,
    pub provider: String,
    pub worker_id: String,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub metadata_json: String,
    pub cancel_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatusView {
    pub instance: InstanceView,
    pub fact_count: i64,
    pub queued_effect_count: i64,
    pub blocked_effect_count: i64,
    pub active_run_count: i64,
    pub failure_count: i64,
    pub cancellation_request_count: i64,
    pub revisions: Vec<WorkflowRevisionView>,
    pub parent_invocation: Option<WorkflowInvocationView>,
    pub child_invocations: Vec<WorkflowInvocationView>,
    pub recent_events: Vec<EventView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevisionActivation<'a> {
    pub instance_id: &'a str,
    pub from_version_id: &'a str,
    pub to_version_id: &'a str,
    pub activation_policy_json: &'a str,
    pub cancellation_policy: &'a str,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowRevisionView {
    pub revision_id: String,
    pub instance_id: String,
    pub epoch: i64,
    pub from_version_id: String,
    pub to_version_id: String,
    pub activated_by_event_id: String,
    pub activation_policy_json: String,
    pub cancellation_policy: String,
    pub status: String,
    pub idempotency_key: Option<String>,
    pub created_at: String,
    pub activated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionCancellationImpact {
    pub instance_id: String,
    pub active_version_id: String,
    pub active_revision_epoch: i64,
    pub cancellation_policy: String,
    pub terminal_cancel_effects: Vec<String>,
    pub request_cancel_effects: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionCompatibilityReport {
    pub instance_id: String,
    pub active_version_id: String,
    pub candidate_version_id: String,
    pub compatible: bool,
    pub diagnostics: Vec<RevisionCompatibilityDiagnostic>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevisionCandidate<'a> {
    pub candidate_version_id: &'a str,
    pub program_name: &'a str,
    pub analysis_summary_json: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevisionCompatibilityDiagnostic {
    pub code: String,
    pub message: String,
    pub subject: Option<String>,
    pub source_span_json: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectCancellationRequest<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub revision_id: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub requested_by: &'a str,
    pub causation_event_id: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectCancellationRequestView {
    pub request_id: String,
    pub instance_id: String,
    pub effect_id: String,
    pub revision_id: Option<String>,
    pub reason: Option<String>,
    pub requested_by: String,
    pub causation_event_id: Option<String>,
    pub status: String,
    pub idempotency_key: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub resolved_by_event_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunStart<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub provider: &'a str,
    pub worker_id: &'a str,
    pub lease_id: &'a str,
    pub lease_expires_at: &'a str,
    pub metadata_json: &'a str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InstanceTransition<'a> {
    pub instance_id: &'a str,
    pub status: &'a str,
    pub reason: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectCancellation<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub reason: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseRenewal<'a> {
    pub instance_id: &'a str,
    pub lease_id: &'a str,
    pub run_id: &'a str,
    pub new_expires_at: &'a str,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredLease {
    pub lease_id: String,
    pub run_id: String,
    pub effect_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryEffect<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub retry_after: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
}

#[cfg(feature = "native")]
struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

#[cfg(feature = "native")]
const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "runtime-store-schema",
    sql: include_str!("../migrations/0001_runtime_store.sql"),
}];

/// Stage marker retained for the CLI/kernel scaffold.
pub fn store_stage() -> &'static str {
    whipplescript_core::IMPLEMENTATION_STAGE
}

#[cfg(feature = "native")]
impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let path = path.as_ref();
        let mut connection = Connection::open(path)?;
        // A whip worker executes the ready set of effects concurrently (a bounded
        // thread pool), and several worker processes may run against one store.
        // WAL lets a writer and readers coexist; `busy_timeout` makes a contended
        // write wait briefly instead of failing with SQLITE_BUSY. The durable
        // lease + per-row idempotency machinery is what makes the concurrent
        // execution itself safe (see models/tla AtMostOneRunExecutingEffect).
        establish_wal(&connection)?;
        apply_migrations(&mut connection)?;
        if path.to_string_lossy() != ":memory:" {
            harden_store_file_permissions(path)?;
        }
        Ok(Self { connection })
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        let mut connection = Connection::open_in_memory()?;
        // WAL does not apply to an in-memory database; busy_timeout is harmless
        // and keeps behavior uniform with the file-backed store.
        connection.busy_timeout(STORE_BUSY_TIMEOUT)?;
        apply_migrations(&mut connection)?;
        Ok(Self { connection })
    }

    pub fn schema_version(&self) -> StoreResult<i64> {
        self.connection
            .query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )
            .map_err(Into::into)
    }

    pub fn append_event(&self, event: NewEvent<'_>) -> StoreResult<StoredEvent> {
        append_event_on(&self.connection, event)
    }

    pub fn create_program_version(
        &mut self,
        version: NewProgramVersion<'_>,
    ) -> StoreResult<ProgramVersionRecord> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            r#"
            INSERT INTO programs (program_id, name)
            VALUES ('prg_' || lower(hex(randomblob(16))), ?1)
            ON CONFLICT(name) DO NOTHING
            "#,
            [version.program_name],
        )?;
        let program_id = tx.query_row(
            "SELECT program_id FROM programs WHERE name = ?1",
            [version.program_name],
            |row| row.get::<_, String>(0),
        )?;
        tx.execute(
            r#"
            INSERT INTO program_versions (
                version_id,
                program_id,
                source_hash,
                ir_hash,
                compiler_version,
                declared_capabilities,
                declared_profiles,
                declared_skills,
                declared_schemas,
                analysis_summary,
                generated_artifacts,
                artifact_root
            )
            VALUES (
                'ver_' || lower(hex(randomblob(16))),
                ?1,
                ?2,
                ?3,
                ?4,
                ?5,
                ?6,
                ?7,
                ?8,
                ?9,
                ?10,
                ?11
            )
            ON CONFLICT(program_id, source_hash, ir_hash) DO NOTHING
            "#,
            params![
                &program_id,
                version.source_hash,
                version.ir_hash,
                version.compiler_version,
                version.declared_capabilities_json,
                version.declared_profiles_json,
                version.declared_skills_json,
                version.declared_schemas_json,
                version.analysis_summary_json,
                version.generated_artifacts_json,
                version.artifact_root,
            ],
        )?;
        let version_id = tx.query_row(
            r#"
            SELECT version_id
            FROM program_versions
            WHERE program_id = ?1
              AND source_hash = ?2
              AND ir_hash = ?3
            "#,
            params![&program_id, version.source_hash, version.ir_hash],
            |row| row.get::<_, String>(0),
        )?;
        tx.commit()?;

        Ok(ProgramVersionRecord {
            program_id,
            version_id,
        })
    }

    pub fn get_program_version(&self, version_id: &str) -> StoreResult<Option<ProgramVersionView>> {
        self.connection
            .query_row(
                r#"
                SELECT
                    program_versions.program_id,
                    programs.name,
                    program_versions.version_id,
                    program_versions.source_hash,
                    program_versions.ir_hash,
                    program_versions.compiler_version,
                    program_versions.analysis_summary
                FROM program_versions
                JOIN programs ON programs.program_id = program_versions.program_id
                WHERE program_versions.version_id = ?1
                "#,
                [version_id],
                |row| {
                    Ok(ProgramVersionView {
                        program_id: row.get(0)?,
                        program_name: row.get(1)?,
                        version_id: row.get(2)?,
                        source_hash: row.get(3)?,
                        ir_hash: row.get(4)?,
                        compiler_version: row.get(5)?,
                        analysis_summary_json: row.get(6)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn create_instance(&self, instance: NewInstance<'_>) -> StoreResult<InstanceRecord> {
        self.create_instance_with_authority(instance, NewInstanceAuthority::empty())
    }

    pub fn create_instance_with_authority(
        &self,
        instance: NewInstance<'_>,
        authority: NewInstanceAuthority<'_>,
    ) -> StoreResult<InstanceRecord> {
        self.connection
            .query_row(
                r#"
                INSERT INTO instances (
                    instance_id,
                    program_id,
                    version_id,
                    workflow_principal,
                    effective_authority,
                    status,
                    input_json,
                    started_at
                )
                VALUES (
                    'ins_' || lower(hex(randomblob(16))),
                    ?1,
                    ?2,
                    ?3,
                    ?4,
                    'running',
                    ?5,
                    CURRENT_TIMESTAMP
                )
                RETURNING instance_id, status
                "#,
                params![
                    instance.program_id,
                    instance.version_id,
                    authority.workflow_principal,
                    authority.effective_authority_json,
                    instance.input_json,
                ],
                |row| {
                    Ok(InstanceRecord {
                        instance_id: row.get(0)?,
                        status: row.get(1)?,
                    })
                },
            )
            .map_err(Into::into)
    }

    pub fn list_instance_revisions(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<WorkflowRevisionView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                revision_id,
                instance_id,
                epoch,
                from_version_id,
                to_version_id,
                activated_by_event_id,
                activation_policy_json,
                cancellation_policy,
                status,
                idempotency_key,
                created_at,
                activated_at
            FROM instance_revisions
            WHERE instance_id = ?1
            ORDER BY epoch
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], workflow_revision_from_row)?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn revision_cancellation_impact(
        &self,
        instance_id: &str,
        cancellation_policy: &str,
    ) -> StoreResult<RevisionCancellationImpact> {
        let cancellation_policy = normalize_cancellation_policy(cancellation_policy)?;
        let (active_version_id, active_revision_epoch, status) = self
            .connection
            .query_row(
                r#"
                SELECT version_id, revision_epoch, status
                FROM instances
                WHERE instance_id = ?1
                "#,
                [instance_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return Err(StoreError::Conflict(format!(
                "instance is {status}; revision impact requires a non-terminal instance"
            )));
        }
        let terminal_cancel_effects = if cancellation_policy == "keep" {
            Vec::new()
        } else {
            revision_policy_effects_on(&self.connection, instance_id, false)?
        };
        let request_cancel_effects = if cancellation_policy == "request_running" {
            revision_policy_effects_on(&self.connection, instance_id, true)?
        } else {
            Vec::new()
        };

        Ok(RevisionCancellationImpact {
            instance_id: instance_id.to_owned(),
            active_version_id,
            active_revision_epoch,
            cancellation_policy: cancellation_policy.to_owned(),
            terminal_cancel_effects,
            request_cancel_effects,
        })
    }

    pub fn analyze_revision_compatibility(
        &self,
        instance_id: &str,
        candidate_version_id: &str,
    ) -> StoreResult<RevisionCompatibilityReport> {
        let context = revision_instance_context_on(&self.connection, instance_id)?;
        let (active_program_id, active_summary) =
            program_version_analysis_on(&self.connection, &context.active_version_id)?;
        let (candidate_program_id, candidate_summary) =
            program_version_analysis_on(&self.connection, candidate_version_id)?;

        let mut diagnostics = Vec::new();
        add_instance_revision_diagnostics(&context, &mut diagnostics);
        if active_program_id != context.program_id || candidate_program_id != context.program_id {
            diagnostics.push(revision_compatibility_diagnostic(
                "revision.program_mismatch",
                "candidate version belongs to a different program".to_owned(),
                Some(candidate_version_id),
            ));
        }
        compare_revision_summaries(&active_summary, &candidate_summary, &mut diagnostics);
        add_active_fact_schema_diagnostics(
            &self.connection,
            instance_id,
            &active_summary,
            &candidate_summary,
            &mut diagnostics,
        )?;

        Ok(RevisionCompatibilityReport {
            instance_id: instance_id.to_owned(),
            active_version_id: context.active_version_id,
            candidate_version_id: candidate_version_id.to_owned(),
            compatible: diagnostics.is_empty(),
            diagnostics,
        })
    }

    pub fn analyze_revision_candidate(
        &self,
        instance_id: &str,
        candidate: RevisionCandidate<'_>,
    ) -> StoreResult<RevisionCompatibilityReport> {
        let context = revision_instance_context_on(&self.connection, instance_id)?;
        let (_active_program_id, active_summary) =
            program_version_analysis_on(&self.connection, &context.active_version_id)?;
        let candidate_summary = serde_json::from_str::<Value>(candidate.analysis_summary_json)?;

        let mut diagnostics = Vec::new();
        add_instance_revision_diagnostics(&context, &mut diagnostics);
        if candidate.program_name != context.program_name {
            diagnostics.push(revision_compatibility_diagnostic(
                "revision.program_mismatch",
                format!(
                    "candidate program `{}` does not match active program `{}`",
                    candidate.program_name, context.program_name
                ),
                Some(candidate.program_name),
            ));
        }
        compare_revision_summaries(&active_summary, &candidate_summary, &mut diagnostics);
        add_active_fact_schema_diagnostics(
            &self.connection,
            instance_id,
            &active_summary,
            &candidate_summary,
            &mut diagnostics,
        )?;

        Ok(RevisionCompatibilityReport {
            instance_id: instance_id.to_owned(),
            active_version_id: context.active_version_id,
            candidate_version_id: candidate.candidate_version_id.to_owned(),
            compatible: diagnostics.is_empty(),
            diagnostics,
        })
    }

    pub fn activate_revision(
        &mut self,
        activation: RevisionActivation<'_>,
    ) -> StoreResult<WorkflowRevisionView> {
        let cancellation_policy = normalize_cancellation_policy(activation.cancellation_policy)?;
        let activation_policy: Value = serde_json::from_str(activation.activation_policy_json)?;

        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(idempotency_key) = activation.idempotency_key {
            if let Some(existing) =
                revision_by_idempotency_on(&tx, activation.instance_id, idempotency_key)?
            {
                ensure_revision_idempotency_matches(
                    &existing,
                    &activation,
                    &activation_policy,
                    cancellation_policy,
                )?;
                return Ok(existing);
            }
        }

        let (program_id, program_name, current_version_id, current_epoch, status) = tx
            .query_row(
                r#"
                SELECT instances.program_id, programs.name, instances.version_id, instances.revision_epoch, instances.status
                FROM instances
                JOIN programs ON programs.program_id = instances.program_id
                WHERE instances.instance_id = ?1
                "#,
                [activation.instance_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return Err(StoreError::Conflict(format!(
                "instance is {status}; revisions require a non-terminal instance"
            )));
        }
        if current_version_id != activation.from_version_id {
            return Err(StoreError::Conflict(format!(
                "active version is {}; expected {}",
                current_version_id, activation.from_version_id
            )));
        }
        let to_program_id = tx
            .query_row(
                "SELECT program_id FROM program_versions WHERE version_id = ?1",
                [activation.to_version_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::Conflict("target program version does not exist".to_owned())
            })?;
        if to_program_id != program_id {
            return Err(StoreError::Conflict(
                "target version belongs to a different program".to_owned(),
            ));
        }
        let (_active_program_id, active_summary) =
            program_version_analysis_on(&tx, &current_version_id)?;
        let (_candidate_program_id, candidate_summary) =
            program_version_analysis_on(&tx, activation.to_version_id)?;
        let mut compatibility_diagnostics = Vec::new();
        let context = RevisionInstanceContext {
            program_id: program_id.clone(),
            program_name,
            active_version_id: current_version_id.clone(),
            status: status.clone(),
        };
        add_instance_revision_diagnostics(&context, &mut compatibility_diagnostics);
        compare_revision_summaries(
            &active_summary,
            &candidate_summary,
            &mut compatibility_diagnostics,
        );
        add_active_fact_schema_diagnostics(
            &tx,
            activation.instance_id,
            &active_summary,
            &candidate_summary,
            &mut compatibility_diagnostics,
        )?;
        if !compatibility_diagnostics.is_empty() {
            let codes = compatibility_diagnostics
                .iter()
                .map(|diagnostic| diagnostic.code.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(StoreError::Conflict(format!(
                "revision candidate is incompatible: {codes}"
            )));
        }

        let next_epoch = current_epoch + 1;
        let revision_id = random_id_on(&tx, "rev")?;
        let queued_effects = revision_policy_effects_on(&tx, activation.instance_id, false)?;
        let running_effects = revision_policy_effects_on(&tx, activation.instance_id, true)?;
        let queued_effects_for_policy = if cancellation_policy == "keep" {
            Vec::new()
        } else {
            queued_effects
        };
        let running_effects_for_policy = if cancellation_policy == "request_running" {
            running_effects
        } else {
            Vec::new()
        };
        let payload = json!({
            "revision_id": &revision_id,
            "instance_id": activation.instance_id,
            "from_version_id": activation.from_version_id,
            "to_version_id": activation.to_version_id,
            "from_epoch": current_epoch,
            "to_epoch": next_epoch,
            "activation_policy": activation_policy,
            "cancellation_policy": cancellation_policy,
            "terminal_cancel_effects": &queued_effects_for_policy,
            "request_cancel_effects": &running_effects_for_policy,
        })
        .to_string();
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: activation.instance_id,
                event_type: "workflow.revision_activated",
                payload_json: &payload,
                source: "kernel",
                causation_id: None,
                correlation_id: Some(&revision_id),
                idempotency_key: activation.idempotency_key,
            },
        )?;

        tx.execute(
            r#"
            INSERT INTO instance_revisions (
                revision_id,
                instance_id,
                epoch,
                from_version_id,
                to_version_id,
                activated_by_event_id,
                activation_policy_json,
                cancellation_policy,
                status,
                idempotency_key
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9)
            "#,
            params![
                &revision_id,
                activation.instance_id,
                next_epoch,
                activation.from_version_id,
                activation.to_version_id,
                event.event_id,
                activation.activation_policy_json,
                cancellation_policy,
                activation.idempotency_key,
            ],
        )?;
        tx.execute(
            r#"
            UPDATE instances
            SET version_id = ?1,
                revision_epoch = ?2,
                last_event_id = ?3,
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?4
            "#,
            params![
                activation.to_version_id,
                next_epoch,
                event.event_id,
                activation.instance_id,
            ],
        )?;

        for effect_id in &queued_effects_for_policy {
            let cancel_payload = json!({
                "effect_id": effect_id,
                "status": "cancelled",
                "revision_id": &revision_id,
                "reason": "workflow revision",
            })
            .to_string();
            let cancel_idempotency_key = format!("revision-cancel:{revision_id}:{effect_id}");
            let cancel_event = append_event_on(
                &tx,
                NewEvent {
                    instance_id: activation.instance_id,
                    event_type: "effect.terminal",
                    payload_json: &cancel_payload,
                    source: "kernel",
                    causation_id: Some(&event.event_id),
                    correlation_id: Some(&revision_id),
                    idempotency_key: Some(&cancel_idempotency_key),
                },
            )?;
            tx.execute(
                r#"
                UPDATE effects
                SET status = 'cancelled',
                    updated_at = CURRENT_TIMESTAMP
                WHERE instance_id = ?1
                  AND effect_id = ?2
                  AND status IN (
                      'queued',
                      'blocked',
                      'blocked_by_dependency',
                      'blocked_by_capacity',
                      'blocked_by_capability',
                      'blocked_by_profile'
                  )
                "#,
                params![activation.instance_id, effect_id],
            )?;
            mark_cancellation_requests_terminal_on(
                &tx,
                activation.instance_id,
                effect_id,
                &cancel_event.event_id,
            )?;
        }
        if !queued_effects_for_policy.is_empty() {
            satisfy_dependencies_on(&tx, activation.instance_id)?;
        }
        let mut cancellation_request_ids = Vec::new();
        for effect_id in &running_effects_for_policy {
            let request_idempotency_key =
                format!("revision-request-cancel:{revision_id}:{effect_id}");
            let request = insert_effect_cancellation_request_on(
                &tx,
                EffectCancellationRequest {
                    instance_id: activation.instance_id,
                    effect_id,
                    revision_id: Some(&revision_id),
                    reason: Some("workflow revision"),
                    requested_by: "workflow.revision",
                    causation_event_id: Some(&event.event_id),
                    idempotency_key: Some(&request_idempotency_key),
                },
            )?;
            cancellation_request_ids.push((effect_id.clone(), request.request_id));
        }
        if !queued_effects_for_policy.is_empty() {
            satisfy_dependencies_on(&tx, activation.instance_id)?;
        }
        let revision_evidence_metadata = json!({
            "revision_id": &revision_id,
            "event_id": event.event_id,
            "from_version_id": activation.from_version_id,
            "to_version_id": activation.to_version_id,
            "from_epoch": current_epoch,
            "to_epoch": next_epoch,
            "cancellation_policy": cancellation_policy,
            "terminal_cancel_effects": &queued_effects_for_policy,
            "request_cancel_effects": &running_effects_for_policy,
            "cancellation_request_ids": cancellation_request_ids
                .iter()
                .map(|(_, request_id)| request_id.as_str())
                .collect::<Vec<_>>(),
        })
        .to_string();
        let revision_evidence_id = insert_evidence_on(
            &tx,
            EvidenceRecord {
                instance_id: activation.instance_id,
                kind: "workflow.revision.activated",
                subject_type: "workflow_revision",
                subject_id: &revision_id,
                causation_id: Some(&event.event_id),
                correlation_id: Some(&revision_id),
                summary: Some("workflow revision activated"),
                metadata_json: &revision_evidence_metadata,
            },
        )?;
        insert_evidence_link_on(
            &tx,
            EvidenceLink {
                evidence_id: &revision_evidence_id,
                instance_id: activation.instance_id,
                target_type: "event",
                target_id: &event.event_id,
                relation: "activated",
            },
        )?;
        insert_evidence_link_on(
            &tx,
            EvidenceLink {
                evidence_id: &revision_evidence_id,
                instance_id: activation.instance_id,
                target_type: "program_version",
                target_id: activation.from_version_id,
                relation: "from_version",
            },
        )?;
        insert_evidence_link_on(
            &tx,
            EvidenceLink {
                evidence_id: &revision_evidence_id,
                instance_id: activation.instance_id,
                target_type: "program_version",
                target_id: activation.to_version_id,
                relation: "to_version",
            },
        )?;
        for effect_id in &queued_effects_for_policy {
            insert_evidence_link_on(
                &tx,
                EvidenceLink {
                    evidence_id: &revision_evidence_id,
                    instance_id: activation.instance_id,
                    target_type: "effect",
                    target_id: effect_id,
                    relation: "terminal_cancelled",
                },
            )?;
        }
        for (effect_id, request_id) in &cancellation_request_ids {
            insert_evidence_link_on(
                &tx,
                EvidenceLink {
                    evidence_id: &revision_evidence_id,
                    instance_id: activation.instance_id,
                    target_type: "effect",
                    target_id: effect_id,
                    relation: "cancellation_requested",
                },
            )?;
            insert_evidence_link_on(
                &tx,
                EvidenceLink {
                    evidence_id: &revision_evidence_id,
                    instance_id: activation.instance_id,
                    target_type: "effect_cancellation_request",
                    target_id: request_id,
                    relation: "created",
                },
            )?;
        }
        let view = revision_by_id_on(&tx, &revision_id)?
            .ok_or_else(|| StoreError::Conflict("revision was not recorded".to_owned()))?;
        tx.commit()?;
        Ok(view)
    }

    pub fn request_effect_cancellation(
        &mut self,
        request: EffectCancellationRequest<'_>,
    ) -> StoreResult<EffectCancellationRequestView> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let status = tx
            .query_row(
                "SELECT status FROM effects WHERE instance_id = ?1 AND effect_id = ?2",
                params![request.instance_id, request.effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| StoreError::Conflict("effect does not exist".to_owned()))?;
        if status != "running" {
            return Err(StoreError::Conflict(format!(
                "effect is {status}; cancellation requests require running work"
            )));
        }
        let view = insert_effect_cancellation_request_on(&tx, request)?;
        tx.commit()?;
        Ok(view)
    }

    pub fn effect_has_open_cancellation_request(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<bool> {
        effect_has_open_cancellation_request_on(&self.connection, instance_id, effect_id)
    }

    pub fn list_effect_cancellation_requests(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<EffectCancellationRequestView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                request_id,
                instance_id,
                effect_id,
                revision_id,
                reason,
                requested_by,
                causation_event_id,
                status,
                idempotency_key,
                created_at,
                updated_at,
                resolved_by_event_id
            FROM effect_cancellation_requests
            WHERE instance_id = ?1
            ORDER BY created_at, request_id
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], effect_cancellation_request_from_row)?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn record_workflow_invocation(
        &self,
        invocation: NewWorkflowInvocation<'_>,
    ) -> StoreResult<()> {
        serde_json::from_str::<Value>(invocation.input_json)?;
        let (parent_program_version_id, parent_revision_epoch) = self
            .connection
            .query_row(
                r#"
                SELECT program_version_id, revision_epoch
                FROM effects
                WHERE instance_id = ?1
                  AND effect_id = ?2
                "#,
                params![invocation.parent_instance_id, invocation.parent_effect_id],
                |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::Conflict("parent workflow invoke effect does not exist".to_owned())
            })?;
        let (child_program_version_id, child_revision_epoch) = self
            .connection
            .query_row(
                r#"
                SELECT version_id, revision_epoch
                FROM instances
                WHERE instance_id = ?1
                "#,
                [invocation.child_instance_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::Conflict("child workflow instance does not exist".to_owned())
            })?;
        self.connection.execute(
            r#"
            INSERT INTO workflow_invocations (
                invocation_id,
                parent_instance_id,
                parent_effect_id,
                parent_program_version_id,
                parent_revision_epoch,
                child_instance_id,
                child_program_version_id,
                child_revision_epoch,
                target_workflow,
                input_json,
                source_span_json,
                idempotency_key
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            ON CONFLICT(idempotency_key) DO NOTHING
            "#,
            params![
                invocation.invocation_id,
                invocation.parent_instance_id,
                invocation.parent_effect_id,
                parent_program_version_id,
                parent_revision_epoch,
                invocation.child_instance_id,
                child_program_version_id,
                child_revision_epoch,
                invocation.target_workflow,
                invocation.input_json,
                invocation.source_span_json,
                invocation.idempotency_key,
            ],
        )?;
        Ok(())
    }

    pub fn get_workflow_invocation(
        &self,
        parent_instance_id: &str,
        parent_effect_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        self.connection
            .query_row(
                r#"
                SELECT
                    invocation_id,
                    parent_instance_id,
                    parent_effect_id,
                    parent_program_version_id,
                    parent_revision_epoch,
                    parent_instance.version_id,
                    parent_instance.revision_epoch,
                    child_instance_id,
                    child_program_version_id,
                    child_revision_epoch,
                    child_instance.version_id,
                    child_instance.revision_epoch,
                    workflow_invocations.target_workflow,
                    workflow_invocations.input_json,
                    CASE
                        WHEN parent_effect.status IN ('completed', 'failed', 'timed_out', 'cancelled')
                        THEN parent_effect.status
                        ELSE workflow_invocations.status
                    END,
                    workflow_invocations.terminal_event_id,
                    workflow_invocations.source_span_json,
                    workflow_invocations.created_at,
                    COALESCE(workflow_invocations.updated_at, workflow_invocations.created_at)
                FROM workflow_invocations
                LEFT JOIN instances AS parent_instance
                  ON parent_instance.instance_id = workflow_invocations.parent_instance_id
                LEFT JOIN instances AS child_instance
                  ON child_instance.instance_id = workflow_invocations.child_instance_id
                LEFT JOIN effects AS parent_effect
                  ON parent_effect.instance_id = workflow_invocations.parent_instance_id
                 AND parent_effect.effect_id = workflow_invocations.parent_effect_id
                WHERE workflow_invocations.parent_instance_id = ?1
                  AND workflow_invocations.parent_effect_id = ?2
                ORDER BY workflow_invocations.created_at DESC, invocation_id DESC
                LIMIT 1
                "#,
                params![parent_instance_id, parent_effect_id],
                workflow_invocation_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_child_workflow_invocations(
        &self,
        parent_instance_id: &str,
    ) -> StoreResult<Vec<WorkflowInvocationView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                invocation_id,
                parent_instance_id,
                parent_effect_id,
                parent_program_version_id,
                parent_revision_epoch,
                parent_instance.version_id,
                parent_instance.revision_epoch,
                child_instance_id,
                child_program_version_id,
                child_revision_epoch,
                child_instance.version_id,
                child_instance.revision_epoch,
                workflow_invocations.target_workflow,
                workflow_invocations.input_json,
                CASE
                    WHEN parent_effect.status IN ('completed', 'failed', 'timed_out', 'cancelled')
                    THEN parent_effect.status
                    ELSE workflow_invocations.status
                END,
                workflow_invocations.terminal_event_id,
                workflow_invocations.source_span_json,
                workflow_invocations.created_at,
                COALESCE(workflow_invocations.updated_at, workflow_invocations.created_at)
            FROM workflow_invocations
            LEFT JOIN instances AS parent_instance
              ON parent_instance.instance_id = workflow_invocations.parent_instance_id
            LEFT JOIN instances AS child_instance
              ON child_instance.instance_id = workflow_invocations.child_instance_id
            LEFT JOIN effects AS parent_effect
              ON parent_effect.instance_id = workflow_invocations.parent_instance_id
             AND parent_effect.effect_id = workflow_invocations.parent_effect_id
            WHERE workflow_invocations.parent_instance_id = ?1
            ORDER BY workflow_invocations.created_at, invocation_id
            "#,
        )?;
        let rows = statement
            .query_map([parent_instance_id], workflow_invocation_from_row)?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn get_parent_workflow_invocation(
        &self,
        child_instance_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        self.connection
            .query_row(
                r#"
                SELECT
                    invocation_id,
                    parent_instance_id,
                    parent_effect_id,
                    parent_program_version_id,
                    parent_revision_epoch,
                    parent_instance.version_id,
                    parent_instance.revision_epoch,
                    child_instance_id,
                    child_program_version_id,
                    child_revision_epoch,
                    child_instance.version_id,
                    child_instance.revision_epoch,
                    workflow_invocations.target_workflow,
                    workflow_invocations.input_json,
                    CASE
                        WHEN parent_effect.status IN ('completed', 'failed', 'timed_out', 'cancelled')
                        THEN parent_effect.status
                        ELSE workflow_invocations.status
                    END,
                    workflow_invocations.terminal_event_id,
                    workflow_invocations.source_span_json,
                    workflow_invocations.created_at,
                    COALESCE(workflow_invocations.updated_at, workflow_invocations.created_at)
                FROM workflow_invocations
                LEFT JOIN instances AS parent_instance
                  ON parent_instance.instance_id = workflow_invocations.parent_instance_id
                LEFT JOIN instances AS child_instance
                  ON child_instance.instance_id = workflow_invocations.child_instance_id
                LEFT JOIN effects AS parent_effect
                  ON parent_effect.instance_id = workflow_invocations.parent_instance_id
                 AND parent_effect.effect_id = workflow_invocations.parent_effect_id
                WHERE workflow_invocations.child_instance_id = ?1
                ORDER BY workflow_invocations.created_at DESC, invocation_id DESC
                LIMIT 1
                "#,
                [child_instance_id],
                workflow_invocation_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn commit_rule(&mut self, commit: RuleCommit<'_>) -> StoreResult<StoredEvent> {
        self.commit_rule_inner(commit, None)
    }

    pub fn commit_rule_with_revision_guard(
        &mut self,
        commit: RuleCommit<'_>,
        guard: RuleCommitRevisionGuard<'_>,
    ) -> StoreResult<StoredEvent> {
        self.commit_rule_inner(commit, Some(guard))
    }

    fn commit_rule_inner(
        &mut self,
        commit: RuleCommit<'_>,
        guard: Option<RuleCommitRevisionGuard<'_>>,
    ) -> StoreResult<StoredEvent> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(status) = instance_status_on(&tx, commit.instance_id)? {
            if status != "running" {
                return Err(StoreError::Conflict(format!(
                    "instance is {status}; rule commits require a running instance"
                )));
            }
        }
        let (program_version_id, revision_epoch) = active_revision_on(&tx, commit.instance_id)?;
        if let Some(guard) = guard {
            if program_version_id.as_deref() != Some(guard.program_version_id)
                || revision_epoch != guard.revision_epoch
            {
                return Err(StoreError::Conflict(format!(
                    "active revision changed before rule commit (expected version {} epoch {}, got version {} epoch {})",
                    guard.program_version_id,
                    guard.revision_epoch,
                    program_version_id.as_deref().unwrap_or("<none>"),
                    revision_epoch
                )));
            }
        }
        let payload = rule_commit_payload(commit, program_version_id.as_deref(), revision_epoch)?;
        // Replays are idempotent, collisions are bugs: a pinned re-lowering
        // that reproduces a committed firing byte-for-byte (same idempotency
        // key, same payload) returns the stored commit and touches nothing —
        // while a DISTINCT commit landing on an existing key stays a loud
        // error (it means two different firings derived one key).
        if let Some(key) = commit.idempotency_key {
            if let Some((event_id, sequence, stored_payload)) = tx
                .query_row(
                    "SELECT event_id, sequence, payload_json FROM events \
                     WHERE instance_id = ?1 AND idempotency_key = ?2",
                    params![commit.instance_id, key],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()?
            {
                if stored_payload == payload {
                    return Ok(StoredEvent { event_id, sequence });
                }
                return Err(StoreError::Conflict(format!(
                    "rule commit idempotency key reused with a DIFFERENT payload \
                     (rule `{}`, key `{key}`): two distinct firings derived one \
                     commit key — this is a whip bug, please report it",
                    commit.rule
                )));
            }
        }
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: commit.instance_id,
                event_type: "rule.committed",
                payload_json: &payload,
                source: "kernel",
                causation_id: commit.trigger_event_id,
                correlation_id: None,
                idempotency_key: commit.idempotency_key,
            },
        )?;

        for mark in commit.marks {
            let mark_payload = serde_json::json!({
                "mark": mark,
                "site": commit.rule,
                "committed_event_id": event.event_id,
            })
            .to_string();
            // Length-prefixed so a mark name containing `:` cannot shift the
            // component boundary and alias another (mark, event) pair.
            let mark_key = format!("mark-reached:{}:{mark}:{}", mark.len(), event.event_id);
            append_event_on(
                &tx,
                NewEvent {
                    instance_id: commit.instance_id,
                    event_type: "mark.reached",
                    payload_json: &mark_payload,
                    source: "kernel",
                    causation_id: Some(&event.event_id),
                    correlation_id: None,
                    idempotency_key: Some(&mark_key),
                },
            )?;
        }
        for fact in commit.facts {
            insert_fact(
                &tx,
                commit.instance_id,
                commit.rule,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                fact,
            )?;
        }
        consume_facts(&tx, commit.instance_id, commit.consumed_fact_ids)?;
        for effect in commit.effects {
            insert_effect(
                &tx,
                commit.instance_id,
                commit.rule,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                effect,
            )?;
        }
        for dependency in commit.dependencies {
            insert_effect_dependency(&tx, commit.instance_id, commit.rule, dependency)?;
        }
        if let Some(terminal) = commit.terminal {
            let terminal_payload = workflow_terminal_payload(commit, terminal)?;
            let terminal_event = append_event_on(
                &tx,
                NewEvent {
                    instance_id: commit.instance_id,
                    event_type: terminal.kind.event_type(),
                    payload_json: &terminal_payload,
                    source: "kernel",
                    causation_id: Some(&event.event_id),
                    correlation_id: Some(commit.rule),
                    idempotency_key: terminal.idempotency_key,
                },
            )?;
            tx.execute(
                r#"
                UPDATE instances
                SET status = ?1,
                    last_event_id = ?2,
                    last_error = CASE WHEN ?1 = 'failed' THEN ?3 ELSE last_error END,
                    updated_at = CURRENT_TIMESTAMP,
                    completed_at = CURRENT_TIMESTAMP
                WHERE instance_id = ?4
                "#,
                params![
                    terminal.kind.instance_status(),
                    terminal_event.event_id,
                    terminal.name,
                    commit.instance_id,
                ],
            )?;
        }
        let evidence_metadata = json!({
            "rule": commit.rule,
            "trigger_event_id": commit.trigger_event_id,
            "event_id": event.event_id,
            "program_version_id": program_version_id,
            "revision_epoch": revision_epoch,
            "facts": commit.facts.iter().map(|fact| fact.fact_id).collect::<Vec<_>>(),
            "consumed_facts": commit.consumed_fact_ids,
            "effects": commit.effects.iter().map(|effect| effect.effect_id).collect::<Vec<_>>(),
            // DR-0054 Phase C: the terminal payload was already parsed with
            // `?` while building the terminal event above, so propagate here
            // too instead of silently recording `null` in the evidence trail.
            "terminal": commit.terminal.map(|terminal| -> StoreResult<Value> {
                Ok(json!({
                    "action": terminal.kind.action(),
                    "name": terminal.name,
                    "payload": serde_json::from_str::<Value>(terminal.payload_json)?,
                }))
            }).transpose()?,
            "dependencies": commit
                .dependencies
                .iter()
                .map(|dependency| dependency.dependency_id)
                .collect::<Vec<_>>(),
        })
        .to_string();
        let evidence_id = insert_evidence_on(
            &tx,
            EvidenceRecord {
                instance_id: commit.instance_id,
                kind: "rule.committed",
                subject_type: "rule_commit",
                subject_id: &event.event_id,
                causation_id: commit.trigger_event_id,
                correlation_id: Some(commit.rule),
                summary: Some("rule committed facts and effects"),
                metadata_json: &evidence_metadata,
            },
        )?;
        insert_evidence_link_on(
            &tx,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: commit.instance_id,
                target_type: "event",
                target_id: &event.event_id,
                relation: "emitted",
            },
        )?;
        insert_evidence_link_on(
            &tx,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: commit.instance_id,
                target_type: "rule",
                target_id: commit.rule,
                relation: "committed",
            },
        )?;
        for fact in commit.facts {
            insert_evidence_link_on(
                &tx,
                EvidenceLink {
                    evidence_id: &evidence_id,
                    instance_id: commit.instance_id,
                    target_type: "fact",
                    target_id: fact.fact_id,
                    relation: "recorded",
                },
            )?;
        }
        for fact_id in commit.consumed_fact_ids {
            insert_evidence_link_on(
                &tx,
                EvidenceLink {
                    evidence_id: &evidence_id,
                    instance_id: commit.instance_id,
                    target_type: "fact",
                    target_id: fact_id,
                    relation: "consumed",
                },
            )?;
        }
        for effect in commit.effects {
            insert_evidence_link_on(
                &tx,
                EvidenceLink {
                    evidence_id: &evidence_id,
                    instance_id: commit.instance_id,
                    target_type: "effect",
                    target_id: effect.effect_id,
                    relation: "queued",
                },
            )?;
        }
        for dependency in commit.dependencies {
            insert_evidence_link_on(
                &tx,
                EvidenceLink {
                    evidence_id: &evidence_id,
                    instance_id: commit.instance_id,
                    target_type: "effect_dependency",
                    target_id: dependency.dependency_id,
                    relation: "created",
                },
            )?;
        }

        tx.commit()?;
        Ok(event)
    }

    pub fn derive_fact(&mut self, derived: DerivedFact<'_>) -> StoreResult<StoredEvent> {
        let payload = json!({
            "fact_id": derived.fact.fact_id,
            "name": derived.fact.name,
            "key": derived.fact.key,
            "value": serde_json::from_str::<Value>(derived.fact.value_json)?,
            "schema_id": derived.fact.schema_id,
            "provenance_class": derived.fact.provenance_class,
            "correlation_id": derived.fact.correlation_id,
        })
        .to_string();
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        // Replay-tolerant: a re-derivation under an existing idempotency key is
        // a crash-window heal (the caller's projection re-ran), not an error.
        // On replay the fact row is inserted only if it is missing entirely —
        // NEVER revived from consumed — so a replayed projection cannot
        // resurrect a fact a rule legitimately consumed after the original
        // derivation.
        let existing_event = match derived.idempotency_key {
            Some(key) => tx
                .query_row(
                    "SELECT event_id, sequence FROM events \
                     WHERE instance_id = ?1 AND idempotency_key = ?2",
                    params![derived.instance_id, key],
                    |row| {
                        Ok(StoredEvent {
                            event_id: row.get(0)?,
                            sequence: row.get(1)?,
                        })
                    },
                )
                .optional()?,
            None => None,
        };
        let replayed = existing_event.is_some();
        let event = match existing_event {
            Some(event) => event,
            None => append_event_on(
                &tx,
                NewEvent {
                    instance_id: derived.instance_id,
                    event_type: "fact.derived",
                    payload_json: &payload,
                    source: derived.source,
                    causation_id: derived.causation_id,
                    correlation_id: derived.fact.correlation_id,
                    idempotency_key: derived.idempotency_key,
                },
            )?,
        };
        let fact_row_exists = replayed
            && tx
                .query_row(
                    "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 AND key = ?3",
                    params![derived.instance_id, derived.fact.name, derived.fact.key],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
        if !fact_row_exists {
            let (program_version_id, revision_epoch) =
                active_revision_on(&tx, derived.instance_id)?;
            insert_fact(
                &tx,
                derived.instance_id,
                derived.source,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                &derived.fact,
            )?;
        }
        tx.commit()?;
        Ok(event)
    }

    /// Admit a typed fact batch atomically (spec/admission-and-idempotency.md):
    /// from one validated effect outcome, record N facts in a single transaction.
    /// Each row carries its derived per-row admission key as `fact_id`
    /// (the caller computes `H(effect_key, row_index)` or `H(effect_key,
    /// natural_key)`); a row whose key already has a fact is skipped, so
    /// re-admission is idempotent. The whole batch commits or rolls back as a
    /// unit, so a mid-batch failure admits nothing. Realizes the Maude
    /// `importRow` admission model (models/maude/admission.maude).
    pub fn admit_fact_batch(&mut self, batch: FactBatch<'_>) -> StoreResult<FactBatchOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let (program_version_id, revision_epoch) = active_revision_on(&tx, batch.instance_id)?;
        let mut admitted = 0usize;
        let mut skipped = 0usize;
        for row in batch.rows {
            // Idempotent skip: a row whose derived key already produced a fact is
            // absorbed (the admitted-set membership guard in the model).
            let exists = tx
                .query_row(
                    "SELECT 1 FROM facts WHERE fact_id = ?1 AND instance_id = ?2",
                    params![row.fact_id, batch.instance_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if exists {
                skipped += 1;
                continue;
            }
            // A LIVE identical row from an earlier admission (different
            // fact_id, same (name, key)) makes this row a no-op re-assertion:
            // report it `skipped`, not `admitted` — the counters feed the
            // import completion fact, and an operator re-importing an
            // unchanged file used to read "admitted: N" when nothing changed.
            // A CONSUMED row falls through: re-admission via insert_fact's
            // revive clause is a fresh admission (DR-0044) and counts.
            let live_conflict = tx
                .query_row(
                    "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 \
                     AND key = ?3 AND consumed_at IS NULL",
                    params![batch.instance_id, batch.schema_name, row.key],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if live_conflict {
                skipped += 1;
                continue;
            }
            let value: Value = serde_json::from_str(row.value_json)?;
            let payload = json!({
                "fact_id": row.fact_id,
                "name": batch.schema_name,
                "key": row.key,
                "value": value,
                "schema_id": batch.schema_id,
                "provenance_class": "import",
                "correlation_id": batch.correlation_id,
            })
            .to_string();
            let event = append_event_on(
                &tx,
                NewEvent {
                    instance_id: batch.instance_id,
                    event_type: "fact.derived",
                    payload_json: &payload,
                    source: batch.source,
                    causation_id: batch.causation_id,
                    correlation_id: batch.correlation_id,
                    idempotency_key: Some(row.fact_id),
                },
            )?;
            insert_fact(
                &tx,
                batch.instance_id,
                batch.source,
                &event.event_id,
                program_version_id.as_deref(),
                revision_epoch,
                &NewFact {
                    fact_id: row.fact_id,
                    name: batch.schema_name,
                    key: row.key,
                    value_json: row.value_json,
                    schema_id: batch.schema_id,
                    provenance_class: "import",
                    correlation_id: batch.correlation_id,
                    source_span_json: None,
                },
            )?;
            admitted += 1;
        }
        tx.commit()?;
        Ok(FactBatchOutcome { admitted, skipped })
    }

    pub fn complete_effect(
        &mut self,
        completion: EffectCompletion<'_>,
    ) -> StoreResult<StoredEvent> {
        self.complete_effect_with_terminal_diagnostic(completion, None)
    }

    pub fn complete_effect_with_terminal_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        let run_status = completion.status;
        self.complete_effect_terminal_inner(completion, diagnostic, run_status)
    }

    /// Recovery resolution: record a distinct `uncertain` run status while the
    /// effect itself becomes `failed` (a Failed subkind). Realizes the TLA+
    /// `ResolveUncertainRun` action and the admission-and-idempotency.md
    /// exactly-once recovery rule (started-without-terminal, no idempotent
    /// re-query → one `uncertain` terminal, never re-executed).
    pub fn resolve_effect_uncertain(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        self.complete_effect_terminal_inner(completion, diagnostic, "uncertain")
    }

    fn complete_effect_terminal_inner(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
        run_status: &str,
    ) -> StoreResult<StoredEvent> {
        let payload = effect_completion_payload(completion, diagnostic.as_ref())?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: completion.instance_id,
                event_type: "effect.terminal",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(completion.effect_id),
                correlation_id: None,
                idempotency_key: completion.idempotency_key,
            },
        )?;

        let updated_run = tx.execute(
            r#"
            UPDATE runs
            SET status = ?1,
                completed_at = CURRENT_TIMESTAMP,
                exit_code = ?2,
                summary = ?3,
                metadata_json = ?4
            WHERE run_id = ?5
              AND effect_id = ?6
              AND instance_id = ?7
              AND status = 'running'
            "#,
            params![
                run_status,
                completion.exit_code,
                completion.summary,
                completion.metadata_json,
                completion.run_id,
                completion.effect_id,
                completion.instance_id,
            ],
        )?;
        if updated_run == 0 {
            let terminal_exists = tx
                .query_row(
                    r#"
                    SELECT 1
                    FROM runs
                    WHERE run_id = ?1
                      AND effect_id = ?2
                      AND instance_id = ?3
                      AND status IN ('completed', 'failed', 'timed_out', 'cancelled', 'uncertain')
                    "#,
                    params![
                        completion.run_id,
                        completion.effect_id,
                        completion.instance_id,
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if terminal_exists {
                return Err(StoreError::Conflict(
                    "run already has a terminal completion".to_owned(),
                ));
            }

            return Err(StoreError::Conflict("run is not running".to_owned()));
        }
        tx.execute(
            r#"
            UPDATE leases
            SET status = 'released',
                released_at = CURRENT_TIMESTAMP
            WHERE run_id = ?1
              AND effect_id = ?2
              AND instance_id = ?3
              AND status = 'active'
            "#,
            params![
                completion.run_id,
                completion.effect_id,
                completion.instance_id,
            ],
        )?;
        tx.execute(
            "UPDATE effects SET status = ?1, updated_at = CURRENT_TIMESTAMP WHERE effect_id = ?2 AND instance_id = ?3",
            params![completion.status, completion.effect_id, completion.instance_id],
        )?;
        mark_cancellation_requests_terminal_on(
            &tx,
            completion.instance_id,
            completion.effect_id,
            &event.event_id,
        )?;
        satisfy_dependencies_on(&tx, completion.instance_id)?;
        if let Some(diagnostic) = diagnostic {
            insert_diagnostic_on(
                &tx,
                DiagnosticRecord {
                    instance_id: Some(completion.instance_id),
                    program_id: diagnostic.program_id.as_deref(),
                    program_version_id: diagnostic.program_version_id.as_deref(),
                    severity: diagnostic.severity,
                    code: diagnostic.code.as_deref(),
                    message: &diagnostic.message,
                    source_span_json: diagnostic.source_span_json.as_deref(),
                    subject_type: diagnostic.subject_type.as_deref(),
                    subject_id: diagnostic.subject_id.as_deref(),
                    event_id: Some(&event.event_id),
                    effect_id: Some(completion.effect_id),
                    run_id: Some(completion.run_id),
                    assertion_id: diagnostic.assertion_id.as_deref(),
                    evidence_ids_json: &diagnostic.evidence_ids_json,
                    artifact_ids_json: &diagnostic.artifact_ids_json,
                    causation_id: diagnostic.causation_id.as_deref(),
                    correlation_id: diagnostic.correlation_id.as_deref(),
                    idempotency_key: diagnostic.idempotency_key.as_deref(),
                },
            )?;
        }

        tx.commit()?;
        Ok(event)
    }

    /// Distinct kinds of effects still awaiting resolution (any non-terminal
    /// status). Used by the store-open guard to detect effects left behind by a
    /// kind rename (M4): after a one-way rename a persisted effect keeps its old
    /// kind string, which no dispatcher matches, so it would loop forever. The
    /// guard turns that silent hang into a loud, actionable error.
    pub fn pending_effect_kinds(&self) -> StoreResult<Vec<String>> {
        let mut statement = self.connection.prepare(
            "SELECT DISTINCT kind FROM effects \
             WHERE status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')",
        )?;
        let kinds = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(kinds)
    }

    pub fn claimable_effects(&self, instance_id: &str) -> StoreResult<Vec<ClaimableEffect>> {
        if let Some(status) = instance_status_on(&self.connection, instance_id)? {
            if status != "running" {
                return Ok(Vec::new());
            }
        }
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                candidate.effect_id,
                candidate.kind,
                candidate.target,
                candidate.profile,
                candidate.input_json,
                candidate.required_capabilities,
                COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles, '[]'),
                candidate.created_by_event_id
            FROM effects AS candidate
            LEFT JOIN instances ON instances.instance_id = candidate.instance_id
            LEFT JOIN program_versions AS active_versions
              ON active_versions.version_id = instances.version_id
            LEFT JOIN program_versions AS effect_versions
              ON effect_versions.version_id = candidate.program_version_id
            WHERE candidate.instance_id = ?1
              AND candidate.kind != 'timer.wait'
              AND (
                  candidate.status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')
                  OR (candidate.kind = 'workflow.invoke' AND candidate.status = 'running')
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM effect_cancellation_requests AS request
                  WHERE request.instance_id = candidate.instance_id
                    AND request.effect_id = candidate.effect_id
                    AND request.status = 'requested'
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM effect_dependencies AS dependency
                  JOIN effects AS upstream
                    ON upstream.effect_id = dependency.upstream_effect_id
                   AND upstream.instance_id = dependency.instance_id
                  WHERE dependency.instance_id = candidate.instance_id
                    AND dependency.downstream_effect_id = candidate.effect_id
                    AND NOT (
                        (dependency.predicate = 'succeeds' AND upstream.status = 'completed')
                        OR (dependency.predicate = 'fails' AND upstream.status = 'failed')
                        OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out')
                        OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled')
                        OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled'))
                    )
              )
            ORDER BY candidate.created_at, candidate.effect_id
            "#,
        )?;
        let effects = statement
            .query_map([instance_id], |row| {
                Ok((
                    ClaimableEffect {
                        effect_id: row.get(0)?,
                        kind: row.get(1)?,
                        target: row.get(2)?,
                        profile: row.get(3)?,
                        input_json: row.get(4)?,
                        required_capabilities_json: row.get(5)?,
                        declared_profiles_json: row.get(6)?,
                    },
                    row.get::<_, Option<String>>(7)?,
                ))
            })?
            .collect::<result::Result<Vec<_>, _>>()
            .map_err(StoreError::from)?;
        // RC-4b on the effects plane: orphaned-segment PENDING effects are
        // never handed to a worker after a restore.
        let live = live_event_ids_on(&self.connection, instance_id)?;
        let effects: Vec<ClaimableEffect> = effects
            .into_iter()
            .filter(|(_, created_by)| match (&live, created_by) {
                (Some(live), Some(event_id)) => live.contains(event_id),
                _ => true,
            })
            .map(|(effect, _)| effect)
            .collect();
        let mut claimable = Vec::new();
        for effect in effects {
            if let Some(block) = policy_block_on(&self.connection, instance_id, &effect.effect_id)?
            {
                // Persist the block where it is observed: skipping silently
                // here left the effect reading `queued` with no reason forever
                // (the only other persist point, `start_run`, is exactly what
                // this filter prevents from running).
                persist_policy_block_on(&self.connection, instance_id, &effect.effect_id, &block)?;
                continue;
            }
            if capacity_block_on(&self.connection, instance_id, &effect.effect_id)?.is_some() {
                continue;
            }
            claimable.push(effect);
        }
        Ok(claimable)
    }

    pub fn fact_exists(&self, instance_id: &str, fact_name: &str) -> StoreResult<bool> {
        self.connection
            .query_row(
                "SELECT 1 FROM facts WHERE instance_id = ?1 AND name = ?2 LIMIT 1",
                params![instance_id, fact_name],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(Into::into)
    }

    pub fn register_package(&self, package: PackageRegistration<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(package.manifest_json)?;
        self.connection.execute(
            r#"
            INSERT INTO package_registrations (package_id, name, version, manifest_json)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(package_id) DO UPDATE SET
                name = excluded.name,
                version = excluded.version,
                manifest_json = excluded.manifest_json
            "#,
            params![
                package.package_id,
                package.name,
                package.version,
                package.manifest_json,
            ],
        )?;
        Ok(())
    }

    pub fn register_package_manifest(&self, manifest_json: &str) -> StoreResult<String> {
        let manifest: Value = serde_json::from_str(manifest_json)?;
        let package_id = required_manifest_string(&manifest, &["package_id", "plugin_id"])?;
        let name = required_manifest_string(&manifest, &["name"])?;
        let version = required_manifest_string(&manifest, &["version"])?;

        self.register_package(PackageRegistration {
            package_id: &package_id,
            name: &name,
            version: &version,
            manifest_json,
        })?;

        for capability in manifest
            .get("capabilities")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let schema_json = capability
                .get("schema")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            self.register_capability_schema(CapabilitySchemaRegistration {
                capability: &required_manifest_string(capability, &["capability", "id"])?,
                description: capability
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                schema_json: &schema_json,
                registered_by_package_id: Some(&package_id),
            })?;
        }

        for provider in manifest
            .get("providers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            // Operator-plane rows (`"plane": "operator"`, std-telemetry.md
            // T3) are capability-free configuration for operator CLI
            // surfaces: registering one here would mint exactly the
            // decorative admission-plane row the design forbids.
            if provider.get("plane").and_then(Value::as_str) == Some("operator") {
                continue;
            }
            let config_json = provider
                .get("config")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            self.register_effect_provider(EffectProviderRegistration {
                provider_id: &required_manifest_string(provider, &["provider_id", "id"])?,
                effect_kind: &manifest_effect_kind(provider),
                provider: &required_manifest_string(
                    provider,
                    &["provider", "provider_kind", "kind"],
                )?,
                capability: &required_manifest_string(
                    provider,
                    &["capability", "effect_contract", "effect_contract_id"],
                )?,
                config_json: &config_json,
                registered_by_package_id: Some(&package_id),
            })?;
        }

        for profile in manifest
            .get("profiles")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let config_json = profile
                .get("config")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            let allowed_json = profile
                .get("allowed_capabilities")
                .map(Value::to_string)
                .unwrap_or_else(|| "[]".to_owned());
            self.register_profile(ProfileRegistration {
                profile_id: &required_manifest_string(profile, &["profile_id", "id"])?,
                name: &required_string(profile, "name"),
                description: profile
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                enforcement_mode: profile
                    .get("enforcement_mode")
                    .and_then(Value::as_str)
                    .unwrap_or("enforce"),
                allowed_capabilities_json: &allowed_json,
                config_json: &config_json,
            })?;
        }

        for binding in manifest
            .get("bindings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let config_json = binding
                .get("config")
                .map(Value::to_string)
                .unwrap_or_else(|| "{}".to_owned());
            self.bind_capability(CapabilityBinding {
                binding_id: &required_manifest_string(binding, &["binding_id", "id"])?,
                program_id: binding.get("program_id").and_then(Value::as_str),
                capability: &required_manifest_string(binding, &["capability"])?,
                provider: &required_manifest_string(binding, &["provider", "provider_kind"])?,
                config_json: &config_json,
            })?;
        }

        Ok(package_id)
    }

    pub fn load_package_manifests_from_dir(
        &self,
        directory: impl AsRef<Path>,
    ) -> StoreResult<Vec<String>> {
        let mut loaded = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }

            let manifest_json = fs::read_to_string(&path)?;
            loaded.push(self.register_package_manifest(&manifest_json)?);
        }
        loaded.sort();
        Ok(loaded)
    }

    pub fn register_capability_schema(
        &self,
        capability: CapabilitySchemaRegistration<'_>,
    ) -> StoreResult<()> {
        serde_json::from_str::<Value>(capability.schema_json)?;
        self.connection.execute(
            r#"
            INSERT INTO capability_schemas (
                capability,
                description,
                schema_json,
                registered_by_package_id
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(capability) DO UPDATE SET
                description = excluded.description,
                schema_json = excluded.schema_json,
                registered_by_package_id = excluded.registered_by_package_id
            "#,
            params![
                capability.capability,
                capability.description,
                capability.schema_json,
                capability.registered_by_package_id,
            ],
        )?;
        Ok(())
    }

    pub fn register_effect_provider(
        &self,
        provider: EffectProviderRegistration<'_>,
    ) -> StoreResult<()> {
        serde_json::from_str::<Value>(provider.config_json)?;
        self.connection.execute(
            r#"
            INSERT INTO effect_providers (
                provider_id,
                effect_kind,
                provider,
                capability,
                config_json,
                registered_by_package_id
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(effect_kind, provider) DO UPDATE SET
                capability = excluded.capability,
                config_json = excluded.config_json,
                registered_by_package_id = excluded.registered_by_package_id
            "#,
            params![
                provider.provider_id,
                provider.effect_kind,
                provider.provider,
                provider.capability,
                provider.config_json,
                provider.registered_by_package_id,
            ],
        )?;
        Ok(())
    }

    pub fn register_profile(&self, profile: ProfileRegistration<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(profile.allowed_capabilities_json)?;
        serde_json::from_str::<Value>(profile.config_json)?;
        self.connection.execute(
            r#"
            INSERT INTO profiles (
                profile_id,
                name,
                description,
                enforcement_mode,
                allowed_capabilities,
                config_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(name) DO UPDATE SET
                description = excluded.description,
                enforcement_mode = excluded.enforcement_mode,
                allowed_capabilities = excluded.allowed_capabilities,
                config_json = excluded.config_json
            "#,
            params![
                profile.profile_id,
                profile.name,
                profile.description,
                profile.enforcement_mode,
                profile.allowed_capabilities_json,
                profile.config_json,
            ],
        )?;
        Ok(())
    }

    pub fn registered_profile_policy(
        &self,
        profile: &str,
    ) -> StoreResult<Option<RegisteredProfilePolicy>> {
        Ok(profile_policy(&self.connection, profile)?.map(
            |(enforcement_mode, allowed_capabilities)| RegisteredProfilePolicy {
                enforcement_mode,
                allowed_capabilities,
            },
        ))
    }

    /// The provider name bound to `capability` for the program running
    /// `instance_id`, mirroring `capability_bound`'s program-scoped-wins-over-global
    /// scoping. `None` when no binding row exists (or its `provider` column is NULL).
    /// This is the registry-driven `CapabilityProvider` selection seam (S5 → first
    /// real provider): the native worker maps the returned name to a concrete impl.
    pub fn capability_bound_provider(
        &self,
        instance_id: &str,
        capability: &str,
    ) -> StoreResult<Option<String>> {
        let program_id = self
            .connection
            .query_row(
                "SELECT program_id FROM instances WHERE instance_id = ?1",
                [instance_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        capability_bound_provider(&self.connection, &program_id, capability)
    }

    /// Every binding bound for `capability` visible to the program running
    /// `instance_id` (program-scoped rows first, then global `NULL` rows;
    /// stable `binding_id` order within each scope). This is the
    /// channel-scoped provider-selection read (spec/std-messaging.md
    /// "Channel→binding provider selection"): the `capability_bound` gate
    /// stays the program×capability policy check, and dispatch resolves a
    /// channel's declared provider against these rows' provider ids, taking
    /// the matching row's `config_json` capability report.
    pub fn capability_bindings_for(
        &self,
        instance_id: &str,
        capability: &str,
    ) -> StoreResult<Vec<CapabilityBindingView>> {
        let program_id = self
            .connection
            .query_row(
                "SELECT program_id FROM instances WHERE instance_id = ?1",
                [instance_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let mut statement = self.connection.prepare(
            r#"
            SELECT binding_id, program_id, capability, provider, config_json
            FROM capability_bindings
            WHERE capability = ?1
              AND (program_id = ?2 OR program_id IS NULL)
            ORDER BY (program_id IS NULL) ASC, binding_id ASC
            "#,
        )?;
        let rows = statement
            .query_map(params![capability, program_id], |row| {
                Ok(CapabilityBindingView {
                    binding_id: row.get(0)?,
                    program_id: row.get(1)?,
                    capability: row.get(2)?,
                    provider: row.get(3)?,
                    config_json: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The `effect_providers.config_json` for `(effect_kind, provider)` — the
    /// registry-default configuration half of the coerce selection ladder's
    /// rung 3 (spec/std-coercion.md "Backend selection and config precedence"):
    /// `capability_bound_provider` names the provider, this row carries its
    /// config. `None` when no such provider row exists.
    pub fn effect_provider_config(
        &self,
        effect_kind: &str,
        provider: &str,
    ) -> StoreResult<Option<String>> {
        self.connection
            .query_row(
                "SELECT config_json FROM effect_providers WHERE effect_kind = ?1 AND provider = ?2",
                params![effect_kind, provider],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn bind_capability(&self, binding: CapabilityBinding<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(binding.config_json)?;
        self.connection.execute(
            r#"
            INSERT INTO capability_bindings (
                binding_id,
                program_id,
                capability,
                provider,
                config_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(binding_id) DO UPDATE SET
                program_id = excluded.program_id,
                capability = excluded.capability,
                provider = excluded.provider,
                config_json = excluded.config_json
            "#,
            params![
                binding.binding_id,
                binding.program_id,
                binding.capability,
                binding.provider,
                binding.config_json,
            ],
        )?;
        Ok(())
    }

    pub fn register_skill(&self, skill: SkillRegistration<'_>) -> StoreResult<()> {
        serde_json::from_str::<Value>(skill.required_capabilities_json)?;
        serde_json::from_str::<Value>(skill.metadata_json)?;
        // Content-address the body (Decision 3): the hash tracks the exact bytes
        // the model reads, so it moves iff the SKILL.md body changes.
        let content_hash = stable_hash_hex(skill.body);
        self.connection.execute(
            r#"
            INSERT INTO skills (
                skill_id,
                name,
                version,
                source,
                source_path,
                content_hash,
                body,
                description,
                required_capabilities,
                metadata_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            ON CONFLICT(name) DO UPDATE SET
                version = excluded.version,
                source = excluded.source,
                source_path = excluded.source_path,
                content_hash = excluded.content_hash,
                body = excluded.body,
                description = excluded.description,
                required_capabilities = excluded.required_capabilities,
                metadata_json = excluded.metadata_json
            "#,
            params![
                skill.skill_id,
                skill.name,
                skill.version,
                skill.source,
                skill.source_path,
                content_hash,
                skill.body,
                skill.description,
                skill.required_capabilities_json,
                skill.metadata_json,
            ],
        )?;
        Ok(())
    }

    pub fn attach_skill(&self, attachment: SkillAttachment<'_>) -> StoreResult<()> {
        let skill_id = self.connection.query_row(
            "SELECT skill_id FROM skills WHERE name = ?1",
            [attachment.skill_name],
            |row| row.get::<_, String>(0),
        )?;
        self.connection.execute(
            r#"
            INSERT INTO skill_attachments (
                attachment_id,
                scope_type,
                scope_id,
                skill_id
            )
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(scope_type, scope_id, skill_id) DO NOTHING
            "#,
            params![
                attachment.attachment_id,
                attachment.scope_type,
                attachment.scope_id,
                skill_id,
            ],
        )?;
        Ok(())
    }

    /// The content-addressed body of the skill registered at `source_path`, or
    /// `None` if no skill is registered there (context-assembly Phase 2, activation
    /// read — Decision 3). Resolving through the registry means the model reads the
    /// exact registered bytes, identically on native and the durable object.
    pub fn skill_body(&self, source_path: &str) -> StoreResult<Option<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT body FROM skills WHERE source_path = ?1")?;
        let mut rows = statement.query(params![source_path])?;
        match rows.next()? {
            Some(row) => Ok(Some(row.get::<_, String>(0)?)),
            None => Ok(None),
        }
    }

    /// Register (or replace) one project-instruction document at `position`
    /// (context-assembly Phase 3 item 4). Content-addressed like skills: the
    /// stored hash is the body's hash.
    pub fn register_project_context_doc(
        &self,
        position: i64,
        path: &str,
        body: &str,
    ) -> StoreResult<()> {
        let content_hash = stable_hash_hex(body);
        self.connection.execute(
            "INSERT OR REPLACE INTO project_context_docs (position, path, content_hash, body) \
             VALUES (?1, ?2, ?3, ?4)",
            params![position, path, content_hash, body],
        )?;
        Ok(())
    }

    /// The registered project-instruction documents in injection order.
    pub fn list_project_context_docs(&self) -> StoreResult<Vec<ProjectContextDoc>> {
        let mut statement = self.connection.prepare(
            "SELECT position, path, content_hash, body FROM project_context_docs \
             ORDER BY position",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(ProjectContextDoc {
                position: row.get(0)?,
                path: row.get(1)?,
                content_hash: row.get(2)?,
                body: row.get(3)?,
            })
        })?;
        rows.collect::<result::Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    /// Register (or re-pin) one script capability (compute plane P8). The
    /// caller is responsible for verifying `body` hashes to `sha256` before
    /// registering; the store records what it is given.
    pub fn register_script_capability(
        &self,
        registration: ScriptCapabilityRegistration<'_>,
    ) -> StoreResult<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO script_capabilities \
             (name, argv_json, sha256, env_json, hermetic, body) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                registration.name,
                registration.argv_json,
                registration.sha256,
                registration.env_json,
                registration.hermetic,
                registration.body,
            ],
        )?;
        Ok(())
    }

    /// Look up one registered script capability by name (compute plane P8).
    pub fn get_script_capability(&self, name: &str) -> StoreResult<Option<ScriptCapabilityRecord>> {
        self.connection
            .query_row(
                "SELECT name, argv_json, sha256, env_json, hermetic, body \
                 FROM script_capabilities WHERE name = ?1",
                params![name],
                |row| {
                    Ok(ScriptCapabilityRecord {
                        name: row.get(0)?,
                        argv_json: row.get(1)?,
                        sha256: row.get(2)?,
                        env_json: row.get(3)?,
                        hermetic: row.get::<_, i64>(4)? != 0,
                        body: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Record one delta-kernel result under its content key (compute plane
    /// P8-1). First-writer-wins: returns `true` when this call inserted the
    /// entry, `false` when the key was already recorded (the existing entry is
    /// canonical and left untouched).
    pub fn record_compute_result(
        &self,
        registration: ComputeResultRegistration<'_>,
    ) -> StoreResult<bool> {
        let inserted = self.connection.execute(
            "INSERT OR IGNORE INTO compute_result_cache \
             (content_key, effect_kind, result_json, source_instance_id, source_effect_id) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                registration.content_key,
                registration.effect_kind,
                registration.result_json,
                registration.source_instance_id,
                registration.source_effect_id,
            ],
        )?;
        Ok(inserted > 0)
    }

    /// Look up a delta-kernel result by content key (compute plane P8-1).
    pub fn lookup_compute_result(
        &self,
        content_key: &str,
    ) -> StoreResult<Option<ComputeCachedResult>> {
        self.connection
            .query_row(
                "SELECT content_key, effect_kind, result_json, source_instance_id, \
                 source_effect_id, created_at FROM compute_result_cache WHERE content_key = ?1",
                params![content_key],
                |row| {
                    Ok(ComputeCachedResult {
                        content_key: row.get(0)?,
                        effect_kind: row.get(1)?,
                        result_json: row.get(2)?,
                        source_instance_id: row.get(3)?,
                        source_effect_id: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Capture `body` content-addressed into the file-history blob table
    /// (restorable-context RC-1), returning its content id — the SAME
    /// `stable_hash_hex` the `file.write.completed` fact records. Idempotent:
    /// identical bytes dedupe to one row (`INSERT OR IGNORE`), so overwriting a
    /// file with new bytes preserves BOTH the old and new versions by hash. The
    /// blob lives in the same database as the write's fact, and is captured
    /// before that fact commits, so no manifest hash is ever referenced without
    /// its bytes present (restorable-context INV-4 coherence).
    pub fn put_content(&self, body: &str) -> StoreResult<String> {
        let id = stable_hash_hex(body);
        self.connection.execute(
            "INSERT OR IGNORE INTO content_blobs (id, body, byte_len) VALUES (?1, ?2, ?3)",
            params![id, body, body.len() as i64],
        )?;
        Ok(id)
    }

    /// Read the full stored bytes for a file-history content id, or `None` if the
    /// blob store never held it. The restore write-back slice (RC-4) reads through
    /// this to reconstruct a superseded file body.
    pub fn get_content(&self, id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT body FROM content_blobs WHERE id = ?1",
                params![id],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    }

    pub fn list_skills(&self) -> StoreResult<Vec<SkillView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                skill_id,
                name,
                version,
                source,
                source_path,
                content_hash,
                description,
                required_capabilities
            FROM skills
            ORDER BY name
            "#,
        )?;
        let rows = statement
            .query_map([], skill_view_from_row)?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_skill_attachments(
        &self,
        scope_type: &str,
        scope_id: &str,
    ) -> StoreResult<Vec<SkillAttachmentView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                attachment.attachment_id,
                attachment.scope_type,
                attachment.scope_id,
                skill.skill_id,
                skill.name,
                skill.version,
                skill.source,
                skill.source_path,
                skill.content_hash,
                skill.description,
                skill.required_capabilities
            FROM skill_attachments AS attachment
            JOIN skills AS skill ON skill.skill_id = attachment.skill_id
            WHERE attachment.scope_type = ?1
              AND attachment.scope_id = ?2
            ORDER BY skill.name
            "#,
        )?;
        let rows = statement
            .query_map(params![scope_type, scope_id], |row| {
                Ok(SkillAttachmentView {
                    attachment_id: row.get(0)?,
                    scope_type: row.get(1)?,
                    scope_id: row.get(2)?,
                    skill: SkillView {
                        skill_id: row.get(3)?,
                        name: row.get(4)?,
                        version: row.get(5)?,
                        source: row.get(6)?,
                        source_path: row.get(7)?,
                        content_hash: row.get(8)?,
                        description: row.get(9)?,
                        required_capabilities_json: row.get(10)?,
                    },
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn record_evidence(&self, evidence: EvidenceRecord<'_>) -> StoreResult<String> {
        insert_evidence_on(&self.connection, evidence)
    }

    pub fn record_provider_validation_evidence(
        &self,
        evidence: ProviderValidationEvidence<'_>,
    ) -> StoreResult<String> {
        let config = serde_json::from_str::<Value>(evidence.config_json)?;
        let capability = serde_json::from_str::<Value>(evidence.capability_json)?;
        let validation_results = serde_json::from_str::<Value>(evidence.validation_results_json)?;
        let metadata = json!({
            "provider_id": evidence.provider_id,
            "provider_kind": evidence.provider_kind,
            "surface": evidence.surface,
            "status": evidence.status,
            "source_path": evidence.source_path,
            "config": config,
            "capability": capability,
            "validation_results": validation_results,
        })
        .to_string();
        let summary = format!(
            "provider `{}` validation {} on {}",
            evidence.provider_id, evidence.status, evidence.surface
        );
        let evidence_id = insert_evidence_on(
            &self.connection,
            EvidenceRecord {
                instance_id: evidence.instance_id,
                kind: "provider.validation",
                subject_type: "provider_config",
                subject_id: evidence.provider_id,
                causation_id: None,
                correlation_id: evidence.correlation_id,
                summary: Some(&summary),
                metadata_json: &metadata,
            },
        )?;
        insert_evidence_link_on(
            &self.connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider",
                target_id: evidence.provider_id,
                relation: "validates",
            },
        )?;
        insert_evidence_link_on(
            &self.connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider_capability",
                target_id: &format!("{}:{}", evidence.provider_kind, evidence.surface),
                relation: "uses",
            },
        )?;
        Ok(evidence_id)
    }

    pub fn record_codex_app_server_evidence(
        &self,
        evidence: CodexAppServerEvidence<'_>,
    ) -> StoreResult<String> {
        let metadata = serde_json::from_str::<Value>(evidence.metadata_json)?;
        let metadata = json!({
            "provider_id": evidence.provider_id,
            "thread_id": evidence.thread_id,
            "turn_id": evidence.turn_id,
            "evidence": metadata,
        })
        .to_string();
        let summary = format!(
            "Codex app-server evidence for provider `{}` turn `{}`",
            evidence.provider_id, evidence.turn_id
        );
        let evidence_id = insert_evidence_on(
            &self.connection,
            EvidenceRecord {
                instance_id: evidence.instance_id,
                kind: "codex.app_server.evidence",
                subject_type: "provider_turn",
                subject_id: evidence.turn_id,
                causation_id: None,
                correlation_id: evidence.correlation_id,
                summary: Some(&summary),
                metadata_json: &metadata,
            },
        )?;
        insert_evidence_link_on(
            &self.connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider",
                target_id: evidence.provider_id,
                relation: "observes",
            },
        )?;
        insert_evidence_link_on(
            &self.connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider_thread",
                target_id: evidence.thread_id,
                relation: "observes",
            },
        )?;
        Ok(evidence_id)
    }

    pub fn record_claude_agent_sdk_evidence(
        &self,
        evidence: ClaudeAgentSdkEvidence<'_>,
    ) -> StoreResult<String> {
        let metadata = serde_json::from_str::<Value>(evidence.metadata_json)?;
        let metadata = json!({
            "provider_id": evidence.provider_id,
            "session_id": evidence.session_id,
            "run_id": evidence.run_id,
            "evidence": metadata,
        })
        .to_string();
        let summary = format!(
            "Claude Agent SDK evidence for provider `{}` session `{}`",
            evidence.provider_id, evidence.session_id
        );
        let evidence_id = insert_evidence_on(
            &self.connection,
            EvidenceRecord {
                instance_id: evidence.instance_id,
                kind: "claude.agent_sdk.evidence",
                subject_type: "provider_session",
                subject_id: evidence.session_id,
                causation_id: Some(evidence.run_id),
                correlation_id: evidence.correlation_id,
                summary: Some(&summary),
                metadata_json: &metadata,
            },
        )?;
        insert_evidence_link_on(
            &self.connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider",
                target_id: evidence.provider_id,
                relation: "observes",
            },
        )?;
        insert_evidence_link_on(
            &self.connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "provider_run",
                target_id: evidence.run_id,
                relation: "observes",
            },
        )?;
        Ok(evidence_id)
    }

    pub fn link_evidence(&self, link: EvidenceLink<'_>) -> StoreResult<()> {
        insert_evidence_link_on(&self.connection, link)
    }

    pub fn record_artifact(&self, artifact: ArtifactRecord<'_>) -> StoreResult<String> {
        self.connection
            .query_row(
                r#"
                INSERT INTO artifacts (
                    artifact_id,
                    run_id,
                    kind,
                    path,
                    content_hash,
                    mime_type
                )
                VALUES (
                    'art_' || lower(hex(randomblob(16))),
                    ?1,
                    ?2,
                    ?3,
                    ?4,
                    ?5
                )
                RETURNING artifact_id
                "#,
                params![
                    artifact.run_id,
                    artifact.kind,
                    artifact.path,
                    artifact.content_hash,
                    artifact.mime_type,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(Into::into)
    }

    pub fn list_artifacts_for_run(&self, run_id: &str) -> StoreResult<Vec<ArtifactView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                artifact_id,
                run_id,
                kind,
                path,
                content_hash,
                mime_type,
                created_at
            FROM artifacts
            WHERE run_id = ?1
            ORDER BY created_at, artifact_id
            "#,
        )?;
        let rows = statement
            .query_map([run_id], |row| {
                Ok(ArtifactView {
                    artifact_id: row.get(0)?,
                    run_id: row.get(1)?,
                    kind: row.get(2)?,
                    path: row.get(3)?,
                    content_hash: row.get(4)?,
                    mime_type: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn record_workspace(&self, workspace: WorkspaceRecord<'_>) -> StoreResult<String> {
        validate_workspace_policy(workspace.policy)?;
        validate_workspace_status(workspace.status)?;
        serde_json::from_str::<Value>(workspace.metadata_json)?;
        self.connection
            .query_row(
                r#"
                INSERT INTO workspaces (
                    workspace_id,
                    instance_id,
                    effect_id,
                    run_id,
                    provider,
                    policy,
                    uri,
                    status,
                    metadata_json,
                    updated_at
                )
                VALUES (
                    'wsp_' || lower(hex(randomblob(16))),
                    ?1,
                    ?2,
                    ?3,
                    ?4,
                    ?5,
                    ?6,
                    ?7,
                    ?8,
                    CURRENT_TIMESTAMP
                )
                ON CONFLICT(instance_id, effect_id, run_id, policy)
                DO UPDATE SET
                    provider = excluded.provider,
                    uri = excluded.uri,
                    status = excluded.status,
                    metadata_json = excluded.metadata_json,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING workspace_id
                "#,
                params![
                    workspace.instance_id,
                    workspace.effect_id,
                    workspace.run_id,
                    workspace.provider,
                    workspace.policy,
                    workspace.uri,
                    workspace.status,
                    workspace.metadata_json,
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(Into::into)
    }

    pub fn get_workspace(&self, workspace_id: &str) -> StoreResult<Option<WorkspaceView>> {
        let sql = workspace_select_sql("WHERE workspace_id = ?1");
        self.connection
            .query_row(&sql, [workspace_id], workspace_from_row)
            .optional()
            .map_err(Into::into)
    }

    pub fn list_workspaces_for_instance(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<WorkspaceView>> {
        let sql = workspace_select_sql("WHERE instance_id = ?1 ORDER BY created_at, workspace_id");
        let mut statement = self.connection.prepare(&sql)?;
        let rows = statement
            .query_map([instance_id], workspace_from_row)?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn record_diagnostic(&self, diagnostic: DiagnosticRecord<'_>) -> StoreResult<String> {
        insert_diagnostic_on(&self.connection, diagnostic)
    }

    pub fn list_diagnostics(&self, instance_id: Option<&str>) -> StoreResult<Vec<DiagnosticView>> {
        let mut sql = r#"
            SELECT
                diagnostic_id,
                instance_id,
                program_id,
                program_version_id,
                severity,
                code,
                message,
                source_span_json,
                subject_type,
                subject_id,
                event_id,
                effect_id,
                run_id,
                assertion_id,
                evidence_ids_json,
                artifact_ids_json,
                causation_id,
                correlation_id,
                idempotency_key,
                created_at
            FROM diagnostics
        "#
        .to_owned();
        if instance_id.is_some() {
            sql.push_str(" WHERE instance_id = ?1");
        }
        sql.push_str(" ORDER BY created_at, diagnostic_id");

        let mut statement = self.connection.prepare(&sql)?;
        let map_row = |row: &rusqlite::Row<'_>| {
            Ok(DiagnosticView {
                diagnostic_id: row.get(0)?,
                instance_id: row.get(1)?,
                program_id: row.get(2)?,
                program_version_id: row.get(3)?,
                severity: row.get(4)?,
                code: row.get(5)?,
                message: row.get(6)?,
                source_span_json: row.get(7)?,
                subject_type: row.get(8)?,
                subject_id: row.get(9)?,
                event_id: row.get(10)?,
                effect_id: row.get(11)?,
                run_id: row.get(12)?,
                assertion_id: row.get(13)?,
                evidence_ids_json: row.get(14)?,
                artifact_ids_json: row.get(15)?,
                causation_id: row.get(16)?,
                correlation_id: row.get(17)?,
                idempotency_key: row.get(18)?,
                created_at: row.get(19)?,
            })
        };
        let rows = if let Some(instance_id) = instance_id {
            statement
                .query_map([instance_id], map_row)?
                .collect::<result::Result<Vec<_>, _>>()?
        } else {
            statement
                .query_map([], map_row)?
                .collect::<result::Result<Vec<_>, _>>()?
        };
        Ok(rows)
    }

    pub fn list_diagnostics_from_events(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<DiagnosticView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT event_id, payload_json, occurred_at
            FROM events
            WHERE instance_id = ?1
              AND event_type = 'effect.terminal'
            ORDER BY sequence
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                let event_id: String = row.get(0)?;
                let payload_json: String = row.get(1)?;
                let occurred_at: String = row.get(2)?;
                Ok((event_id, payload_json, occurred_at))
            })?
            .collect::<result::Result<Vec<_>, _>>()?;

        let mut diagnostics = Vec::new();
        for (event_id, payload_json, occurred_at) in rows {
            let payload = serde_json::from_str::<Value>(&payload_json)?;
            let Some(diagnostic) = payload.get("diagnostic").filter(|value| !value.is_null())
            else {
                continue;
            };
            diagnostics.push(DiagnosticView {
                diagnostic_id: format!("dia_event_{}", stable_hash_hex(&event_id)),
                instance_id: Some(instance_id.to_owned()),
                program_id: optional_string(diagnostic.get("program_id")),
                program_version_id: optional_string(diagnostic.get("program_version_id")),
                severity: optional_string(diagnostic.get("severity"))
                    .unwrap_or_else(|| "error".to_owned()),
                code: optional_string(diagnostic.get("code")),
                message: optional_string(diagnostic.get("message")).unwrap_or_default(),
                source_span_json: diagnostic.get("source_span").and_then(|value| {
                    if value.is_null() {
                        None
                    } else {
                        Some(value.to_string())
                    }
                }),
                subject_type: optional_string(diagnostic.get("subject_type")),
                subject_id: optional_string(diagnostic.get("subject_id")),
                event_id: Some(event_id.clone()),
                effect_id: optional_string(payload.get("effect_id")),
                run_id: optional_string(payload.get("run_id")),
                assertion_id: optional_string(diagnostic.get("assertion_id")),
                evidence_ids_json: diagnostic
                    .get("evidence_ids")
                    .cloned()
                    .unwrap_or_else(|| json!([]))
                    .to_string(),
                artifact_ids_json: diagnostic
                    .get("artifact_ids")
                    .cloned()
                    .unwrap_or_else(|| json!([]))
                    .to_string(),
                causation_id: optional_string(diagnostic.get("causation_id")),
                correlation_id: optional_string(diagnostic.get("correlation_id")),
                idempotency_key: optional_string(diagnostic.get("idempotency_key")),
                created_at: occurred_at,
            });
        }
        Ok(diagnostics)
    }

    pub fn effect_source_span_json(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<Option<String>> {
        let payload_json = self
            .connection
            .query_row(
                r#"
                SELECT events.payload_json
                FROM effects
                JOIN events ON events.event_id = effects.created_by_event_id
                WHERE effects.instance_id = ?1
                  AND effects.effect_id = ?2
                "#,
                params![instance_id, effect_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(payload_json) = payload_json else {
            return Ok(None);
        };
        let payload = serde_json::from_str::<Value>(&payload_json)?;
        let span = payload
            .get("effects")
            .and_then(Value::as_array)
            .and_then(|effects| {
                effects.iter().find_map(|effect| {
                    (effect.get("effect_id").and_then(Value::as_str) == Some(effect_id))
                        .then(|| effect.get("source_span"))
                        .flatten()
                        .filter(|value| !value.is_null())
                        .map(Value::to_string)
                })
            });
        Ok(span)
    }

    pub fn record_skill_evidence(&self, evidence: SkillEvidence<'_>) -> StoreResult<String> {
        let skills = self.skills_by_name(evidence.skill_names)?;
        let metadata = json!({
            "effect_id": evidence.effect_id,
            "skills": skills.iter().map(skill_to_json).collect::<StoreResult<Vec<_>>>()?,
        })
        .to_string();
        let summary = if skills.is_empty() {
            "no skills injected".to_owned()
        } else {
            format!(
                "injected skills: {}",
                skills
                    .iter()
                    .map(|skill| format!("{}@{}", skill.name, skill.version))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        self.record_evidence(EvidenceRecord {
            instance_id: evidence.instance_id,
            kind: "skills.injected",
            subject_type: "run",
            subject_id: evidence.run_id,
            causation_id: Some(evidence.effect_id),
            correlation_id: evidence.idempotency_key,
            summary: Some(&summary),
            metadata_json: &metadata,
        })
    }

    pub fn list_evidence(&self, instance_id: &str) -> StoreResult<Vec<EvidenceView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                evidence_id,
                instance_id,
                kind,
                subject_type,
                subject_id,
                causation_id,
                correlation_id,
                summary,
                metadata_json,
                created_at
            FROM evidence
            WHERE instance_id = ?1
            ORDER BY created_at, evidence_id
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok(EvidenceView {
                    evidence_id: row.get(0)?,
                    instance_id: row.get(1)?,
                    kind: row.get(2)?,
                    subject_type: row.get(3)?,
                    subject_id: row.get(4)?,
                    causation_id: row.get(5)?,
                    correlation_id: row.get(6)?,
                    summary: row.get(7)?,
                    metadata_json: row.get(8)?,
                    created_at: row.get(9)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_evidence_for_subject(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> StoreResult<Vec<EvidenceView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                evidence_id,
                instance_id,
                kind,
                subject_type,
                subject_id,
                causation_id,
                correlation_id,
                summary,
                metadata_json,
                created_at
            FROM evidence
            WHERE subject_type = ?1
              AND subject_id = ?2
            ORDER BY created_at, evidence_id
            "#,
        )?;
        let rows = statement
            .query_map(params![subject_type, subject_id], |row| {
                Ok(EvidenceView {
                    evidence_id: row.get(0)?,
                    instance_id: row.get(1)?,
                    kind: row.get(2)?,
                    subject_type: row.get(3)?,
                    subject_id: row.get(4)?,
                    causation_id: row.get(5)?,
                    correlation_id: row.get(6)?,
                    summary: row.get(7)?,
                    metadata_json: row.get(8)?,
                    created_at: row.get(9)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_evidence_links(&self, instance_id: &str) -> StoreResult<Vec<EvidenceLinkView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT evidence_id, target_type, target_id, relation, created_at
            FROM evidence_links
            WHERE instance_id = ?1
            ORDER BY created_at, evidence_id, target_type, target_id, relation
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok(EvidenceLinkView {
                    evidence_id: row.get(0)?,
                    target_type: row.get(1)?,
                    target_id: row.get(2)?,
                    relation: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn skills_by_name(&self, skill_names: &[&str]) -> StoreResult<Vec<SkillView>> {
        let mut skills = Vec::new();
        for name in skill_names {
            let skill = self.connection.query_row(
                r#"
                SELECT
                    skill_id,
                    name,
                    version,
                    source,
                    source_path,
                    content_hash,
                    description,
                    required_capabilities
                FROM skills
                WHERE name = ?1
                "#,
                [name],
                skill_view_from_row,
            )?;
            skills.push(skill);
        }
        skills.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(skills)
    }

    pub fn list_instances(&self) -> StoreResult<Vec<InstanceView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                instance_id,
                program_id,
                version_id,
                revision_epoch,
                workflow_principal,
                effective_authority,
                status,
                input_json,
                created_at,
                updated_at
            FROM instances
            ORDER BY created_at, instance_id
            "#,
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(InstanceView {
                    instance_id: row.get(0)?,
                    program_id: row.get(1)?,
                    version_id: row.get(2)?,
                    revision_epoch: row.get(3)?,
                    workflow_principal: row.get(4)?,
                    effective_authority_json: row.get(5)?,
                    status: row.get(6)?,
                    input_json: row.get(7)?,
                    created_at: row.get(8)?,
                    updated_at: row.get(9)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Record a child instance's repair scope (DR-0052 R3): the branch
    /// and mediator-derived slice a `with access to vcs { repair for
    /// <binding> }` start grant resolved to. Written by the invoke seam
    /// only; the vcs selective-verb providers read it to RETARGET their
    /// line and REFUSE any selection exceeding the slice. One scope per
    /// instance (a repair flow serves one incident).
    pub fn record_repair_scope(
        &mut self,
        instance_id: &str,
        branch_id: &str,
        slice_expr: &str,
        source_ref: &str,
    ) -> StoreResult<()> {
        self.connection.execute(
            "INSERT INTO repair_scopes (instance_id, branch_id, slice_expr, source_ref) \
             VALUES (?1, ?2, ?3, ?4) \
             ON CONFLICT(instance_id) DO UPDATE SET branch_id = ?2, slice_expr = ?3, \
             source_ref = ?4",
            rusqlite::params![instance_id, branch_id, slice_expr, source_ref],
        )?;
        Ok(())
    }

    /// The repair scope granted to an instance, if any:
    /// (branch, slice expression, source reference).
    pub fn repair_scope(&self, instance_id: &str) -> StoreResult<Option<(String, String, String)>> {
        use rusqlite::OptionalExtension;
        let row = self
            .connection
            .query_row(
                "SELECT branch_id, slice_expr, source_ref FROM repair_scopes \
                 WHERE instance_id = ?1",
                rusqlite::params![instance_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        Ok(row)
    }

    pub fn get_instance(&self, instance_id: &str) -> StoreResult<Option<InstanceView>> {
        self.connection
            .query_row(
                r#"
                SELECT
                    instance_id,
                    program_id,
                    version_id,
                    revision_epoch,
                    workflow_principal,
                    effective_authority,
                    status,
                    input_json,
                    created_at,
                    updated_at
                FROM instances
                WHERE instance_id = ?1
                "#,
                [instance_id],
                |row| {
                    Ok(InstanceView {
                        instance_id: row.get(0)?,
                        program_id: row.get(1)?,
                        version_id: row.get(2)?,
                        revision_epoch: row.get(3)?,
                        workflow_principal: row.get(4)?,
                        effective_authority_json: row.get(5)?,
                        status: row.get(6)?,
                        input_json: row.get(7)?,
                        created_at: row.get(8)?,
                        updated_at: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_events(&self, instance_id: &str) -> StoreResult<Vec<EventView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT event_id, sequence, event_type, payload_json, source, occurred_at
            FROM events
            WHERE instance_id = ?1
            ORDER BY sequence
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok(EventView {
                    event_id: row.get(0)?,
                    sequence: row.get(1)?,
                    event_type: row.get(2)?,
                    payload_json: row.get(3)?,
                    source: row.get(4)?,
                    occurred_at: row.get(5)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// The already-recorded event carrying this `(instance_id, idempotency_key)`
    /// pair, if any — the read side of the events unique index, so admission
    /// drivers can absorb a re-delivered key instead of tripping the index.
    pub fn event_by_idempotency_key(
        &self,
        instance_id: &str,
        idempotency_key: &str,
    ) -> StoreResult<Option<StoredEvent>> {
        self.connection
            .query_row(
                r#"
                SELECT event_id, sequence
                FROM events
                WHERE instance_id = ?1
                  AND idempotency_key = ?2
                "#,
                params![instance_id, idempotency_key],
                |row| {
                    Ok(StoredEvent {
                        event_id: row.get(0)?,
                        sequence: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_facts(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT fact_id, program_version_id, revision_epoch, name, key, value_json, provenance_class, source_span_json, source_event_id
            FROM facts
            WHERE instance_id = ?1
              AND consumed_at IS NULL
            ORDER BY name, key
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok(FactView {
                    fact_id: row.get(0)?,
                    program_version_id: row.get(1)?,
                    revision_epoch: row.get(2)?,
                    name: row.get(3)?,
                    key: row.get(4)?,
                    value_json: row.get(5)?,
                    provenance_class: row.get(6)?,
                    source_span_json: row.get(7)?,
                    source_event_id: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_facts_including_consumed(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT fact_id, program_version_id, revision_epoch, name, key, value_json, provenance_class, source_span_json, source_event_id
            FROM facts
            WHERE instance_id = ?1
            ORDER BY name, key
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok(FactView {
                    fact_id: row.get(0)?,
                    program_version_id: row.get(1)?,
                    revision_epoch: row.get(2)?,
                    name: row.get(3)?,
                    key: row.get(4)?,
                    value_json: row.get(5)?,
                    provenance_class: row.get(6)?,
                    source_span_json: row.get(7)?,
                    source_event_id: row.get::<_, Option<String>>(8)?.unwrap_or_default(),
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn list_effects(&self, instance_id: &str) -> StoreResult<Vec<EffectView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                effects.effect_id,
                effects.kind,
                effects.target,
                effects.input_json,
                effects.status,
                effects.created_by_rule,
                effects.program_version_id,
                effects.revision_epoch,
                effects.profile,
                effects.required_capabilities,
                effects.policy_block_reason,
                effects.policy_block_category,
                COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles, '[]'),
                EXISTS (
                    SELECT 1
                    FROM effect_cancellation_requests AS request
                    WHERE request.instance_id = effects.instance_id
                      AND request.effect_id = effects.effect_id
                      AND request.status = 'requested'
                ) AS cancel_requested,
                effects.created_by_event_id
            FROM effects
            LEFT JOIN instances ON instances.instance_id = effects.instance_id
            LEFT JOIN program_versions AS active_versions
              ON active_versions.version_id = instances.version_id
            LEFT JOIN program_versions AS effect_versions
              ON effect_versions.version_id = effects.program_version_id
            WHERE effects.instance_id = ?1
            ORDER BY effects.created_at, effects.effect_id
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok((
                    EffectView {
                        effect_id: row.get(0)?,
                        kind: row.get(1)?,
                        target: row.get(2)?,
                        input_json: row.get(3)?,
                        status: row.get(4)?,
                        created_by_rule: row.get(5)?,
                        program_version_id: row.get(6)?,
                        revision_epoch: row.get(7)?,
                        profile: row.get(8)?,
                        required_capabilities_json: row.get(9)?,
                        policy_block_reason: row.get(10)?,
                        policy_block_category: row.get(11)?,
                        declared_profiles_json: row.get(12)?,
                        cancel_requested: row.get(13)?,
                    },
                    row.get::<_, Option<String>>(14)?,
                ))
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        // RC-4b on the effects plane: after a restore, the orphaned
        // segment's effects are invisible — the restored timeline
        // re-offers the rules instead of adopting orphaned outcomes.
        let live = live_event_ids_on(&self.connection, instance_id)?;
        let rows = rows
            .into_iter()
            .filter(|(_, created_by)| match (&live, created_by) {
                (Some(live), Some(event_id)) => live.contains(event_id),
                _ => true,
            })
            .map(|(view, _)| view)
            .collect();
        Ok(rows)
    }

    pub fn list_runs(&self, instance_id: &str) -> StoreResult<Vec<RunView>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                run_id,
                effect_id,
                provider,
                worker_id,
                status,
                started_at,
                completed_at,
                metadata_json,
                EXISTS (
                    SELECT 1
                    FROM effect_cancellation_requests AS request
                    WHERE request.instance_id = runs.instance_id
                      AND request.effect_id = runs.effect_id
                      AND request.status = 'requested'
                ) AS cancel_requested
            FROM runs
            WHERE runs.instance_id = ?1
            ORDER BY started_at, run_id
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok(RunView {
                    run_id: row.get(0)?,
                    effect_id: row.get(1)?,
                    provider: row.get(2)?,
                    worker_id: row.get(3)?,
                    status: row.get(4)?,
                    started_at: row.get(5)?,
                    completed_at: row.get(6)?,
                    metadata_json: row.get(7)?,
                    cancel_requested: row.get(8)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn status(&self, instance_id: &str) -> StoreResult<Option<StatusView>> {
        let Some(instance) = self.get_instance(instance_id)? else {
            return Ok(None);
        };
        let fact_count = count_where(&self.connection, "facts", instance_id, None)?;
        let queued_effect_count = count_where(
            &self.connection,
            "effects",
            instance_id,
            Some("status IN ('queued', 'blocked_by_dependency')"),
        )?;
        let blocked_effect_count = count_where(
            &self.connection,
            "effects",
            instance_id,
            Some(
                "status IN ('blocked_by_capability', 'blocked_by_profile', 'blocked_by_capacity')",
            ),
        )?;
        let active_run_count = count_where(
            &self.connection,
            "runs",
            instance_id,
            Some("status = 'running'"),
        )?;
        let failure_count = count_where(
            &self.connection,
            "effects",
            instance_id,
            Some("status IN ('failed', 'timed_out')"),
        )?;
        let cancellation_request_count = count_where(
            &self.connection,
            "effect_cancellation_requests",
            instance_id,
            Some("status = 'requested'"),
        )?;
        let mut recent_events = self.list_events(instance_id)?;
        if recent_events.len() > 5 {
            recent_events = recent_events.split_off(recent_events.len() - 5);
        }
        let revisions = self.list_instance_revisions(instance_id)?;
        let parent_invocation = self.get_parent_workflow_invocation(instance_id)?;
        let child_invocations = self.list_child_workflow_invocations(instance_id)?;

        Ok(Some(StatusView {
            instance,
            fact_count,
            queued_effect_count,
            blocked_effect_count,
            active_run_count,
            failure_count,
            cancellation_request_count,
            revisions,
            parent_invocation,
            child_invocations,
            recent_events,
        }))
    }

    pub fn satisfy_dependencies(&self, instance_id: &str) -> StoreResult<usize> {
        satisfy_dependencies_on(&self.connection, instance_id)
    }

    pub fn start_run(&mut self, run: RunStart<'_>) -> StoreResult<StoredEvent> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(status) = instance_status_on(&tx, run.instance_id)? {
            if status != "running" {
                return Err(StoreError::Conflict(format!(
                    "instance is {status}; provider runs require a running instance"
                )));
            }
        }
        if let Some(block) = policy_block_on(&tx, run.instance_id, run.effect_id)? {
            let payload = json!({
                "effect_id": run.effect_id,
                "status": block.status,
                "reason": block.reason,
            })
            .to_string();
            append_event_idempotent_on(
                &tx,
                NewEvent {
                    instance_id: run.instance_id,
                    event_type: "effect.blocked",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: Some(run.effect_id),
                    correlation_id: None,
                    idempotency_key: Some(&format!(
                        "policy-block:{}:{}",
                        run.effect_id, run.run_id
                    )),
                },
            )?;
            tx.execute(
                r#"
                UPDATE effects
                SET status = ?1,
                    policy_block_reason = ?2,
                    updated_at = CURRENT_TIMESTAMP
                WHERE instance_id = ?3
                  AND effect_id = ?4
                  AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')
                "#,
                params![block.status, block.reason, run.instance_id, run.effect_id],
            )?;
            tx.commit()?;
            return Err(StoreError::PolicyBlocked {
                effect_id: run.effect_id.to_owned(),
                reason: block.reason,
            });
        }
        let claimable = tx.query_row(
            r#"
            SELECT NOT EXISTS (
                SELECT 1
                FROM effect_dependencies AS dependency
                JOIN effects AS upstream
                  ON upstream.effect_id = dependency.upstream_effect_id
                 AND upstream.instance_id = dependency.instance_id
                WHERE dependency.instance_id = ?1
                  AND dependency.downstream_effect_id = ?2
                  AND NOT (
                      (dependency.predicate = 'succeeds' AND upstream.status = 'completed')
                      OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out'))
                      OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out')
                      OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled')
                      OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled'))
                  )
            )
            "#,
            params![run.instance_id, run.effect_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !claimable {
            tx.execute(
                "UPDATE effects SET status = 'blocked_by_dependency', updated_at = CURRENT_TIMESTAMP WHERE instance_id = ?1 AND effect_id = ?2 AND status = 'queued'",
                params![run.instance_id, run.effect_id],
            )?;
            return Err(StoreError::Conflict(
                "effect dependencies are not satisfied".to_owned(),
            ));
        }
        if effect_has_open_cancellation_request_on(&tx, run.instance_id, run.effect_id)? {
            return Err(StoreError::Conflict(
                "effect cancellation has been requested".to_owned(),
            ));
        }
        if let Some(reason) = capacity_block_on(&tx, run.instance_id, run.effect_id)? {
            let payload = json!({
                "effect_id": run.effect_id,
                "status": "blocked_by_capacity",
                "reason": reason,
            })
            .to_string();
            // Idempotent: the same (effect, run) can be capacity-blocked again
            // on a later worker pass after an interleaved unblock — the same
            // durable statement, not a second event.
            append_event_idempotent_on(
                &tx,
                NewEvent {
                    instance_id: run.instance_id,
                    event_type: "effect.blocked",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: Some(run.effect_id),
                    correlation_id: None,
                    idempotency_key: Some(&format!(
                        "capacity-block:{}:{}",
                        run.effect_id, run.run_id
                    )),
                },
            )?;
            tx.execute(
                r#"
                UPDATE effects
                SET status = 'blocked_by_capacity',
                    policy_block_reason = ?1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE instance_id = ?2
                  AND effect_id = ?3
                  AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity')
                "#,
                params![reason, run.instance_id, run.effect_id],
            )?;
            tx.commit()?;
            return Err(StoreError::CapacityBlocked {
                effect_id: run.effect_id.to_owned(),
                reason,
            });
        }

        let fingerprint_salt = fingerprint_salt_from_metadata(run.metadata_json);
        let fingerprint = execution_fingerprint_on(
            &tx,
            run.instance_id,
            run.effect_id,
            fingerprint_salt.as_deref(),
        )?;
        let run_metadata = inject_execution_fingerprint(&run, run.metadata_json, &fingerprint)?;
        let payload = run_start_payload(run, &run_metadata)?;
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: run.instance_id,
                event_type: "effect.run_started",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(run.effect_id),
                correlation_id: None,
                idempotency_key: Some(run.run_id),
            },
        )?;
        let changed = tx.execute(
            r#"
            UPDATE effects
            SET status = 'running',
                policy_block_reason = NULL,
                policy_block_category = NULL,
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1
              AND effect_id = ?2
              AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')
            "#,
            params![run.instance_id, run.effect_id],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict("effect is not claimable".to_owned()));
        }
        tx.execute(
            r#"
            INSERT INTO runs (
                run_id,
                effect_id,
                instance_id,
                provider,
                worker_id,
                status,
                metadata_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6)
            "#,
            params![
                run.run_id,
                run.effect_id,
                run.instance_id,
                run.provider,
                run.worker_id,
                run_metadata,
            ],
        )?;
        tx.execute(
            r#"
            INSERT INTO leases (
                lease_id,
                run_id,
                effect_id,
                instance_id,
                worker_id,
                status,
                expires_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)
            "#,
            params![
                run.lease_id,
                run.run_id,
                run.effect_id,
                run.instance_id,
                run.worker_id,
                run.lease_expires_at,
            ],
        )?;

        tx.commit()?;
        Ok(event)
    }

    /// Block an effect at provider-binding time (DR-0020): the worker found the
    /// provider unbindable (missing config/credentials/enforcement/healthy
    /// binding) *before* provider execution. Transitions the effect to the
    /// recoverable, non-terminal `blocked` status with a categorized reason and
    /// returns the recorded `effect.blocked` event.
    ///
    /// Idempotent: if the effect is already `blocked` with the same category this
    /// is a no-op that returns the existing block event (no new event), so a
    /// re-claimed effect that stays unbindable does not grow the event log — the
    /// effect simply waits, blocked, until the binding becomes available and the
    /// next worker pass runs it.
    pub fn block_effect_binding(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        category: &str,
        detail: &str,
    ) -> StoreResult<StoredEvent> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current: Option<(String, Option<String>)> = tx
            .query_row(
                "SELECT status, policy_block_category FROM effects \
                 WHERE instance_id = ?1 AND effect_id = ?2",
                params![instance_id, effect_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let already_blocked = matches!(
            &current,
            Some((status, cat)) if status == "blocked" && cat.as_deref() == Some(category)
        );
        if already_blocked {
            // Return the existing block event without recording a new one.
            let event = tx.query_row(
                "SELECT event_id, sequence FROM events \
                 WHERE instance_id = ?1 AND event_type = 'effect.blocked' AND causation_id = ?2 \
                 ORDER BY sequence DESC LIMIT 1",
                params![instance_id, effect_id],
                |row| {
                    Ok(StoredEvent {
                        event_id: row.get(0)?,
                        sequence: row.get(1)?,
                    })
                },
            )?;
            tx.commit()?;
            return Ok(event);
        }
        let payload = json!({
            "effect_id": effect_id,
            "status": "blocked",
            "category": category,
            "reason": detail,
        })
        .to_string();
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id,
                event_type: "effect.blocked",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(effect_id),
                correlation_id: None,
                idempotency_key: Some(&format!(
                    "binding-block:{instance_id}:{effect_id}:{category}"
                )),
            },
        )?;
        tx.execute(
            r#"
            UPDATE effects
            SET status = 'blocked',
                policy_block_reason = ?1,
                policy_block_category = ?2,
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?3
              AND effect_id = ?4
              AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity')
            "#,
            params![detail, category, instance_id, effect_id],
        )?;
        tx.commit()?;
        Ok(event)
    }

    pub fn transition_instance(
        &mut self,
        transition: InstanceTransition<'_>,
    ) -> StoreResult<StoredEvent> {
        fn transition_allowed(current: &str, next: &str) -> bool {
            matches!(
                (current, next),
                ("running", "paused")
                    | ("paused", "running")
                    | ("running", "cancelled")
                    | ("paused", "cancelled")
                    | ("blocked", "cancelled")
                    // Generic internal failure terminal (flow auto-fail): an
                    // unhandled effect failure fails the instance directly,
                    // without an author-typed `failure` payload.
                    | ("running", "failed")
                    | ("paused", "failed")
                    | ("blocked", "failed")
            )
        }

        let payload = json!({
            "instance_id": transition.instance_id,
            "status": transition.status,
            "reason": transition.reason,
        })
        .to_string();
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let current_status = instance_status_on(&tx, transition.instance_id)?
            .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))?;
        if !transition_allowed(&current_status, transition.status) {
            return Err(StoreError::Conflict(format!(
                "cannot transition instance from {current_status} to {}",
                transition.status
            )));
        }
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: transition.instance_id,
                event_type: "instance.transitioned",
                payload_json: &payload,
                source: "kernel",
                causation_id: None,
                correlation_id: None,
                idempotency_key: transition.idempotency_key,
            },
        )?;
        tx.execute(
            r#"
            UPDATE instances
            SET status = ?1,
                last_event_id = ?2,
                last_error = ?3,
                updated_at = CURRENT_TIMESTAMP,
                completed_at = CASE
                    WHEN ?1 IN ('completed', 'cancelled', 'failed') THEN CURRENT_TIMESTAMP
                    ELSE completed_at
                END
            WHERE instance_id = ?4
            "#,
            params![
                transition.status,
                event.event_id,
                transition.reason,
                transition.instance_id,
            ],
        )?;
        tx.commit()?;
        Ok(event)
    }

    /// Effects whose creation-anchored time has arrived: due `timer.wait`
    /// effects (dependency-cleared) and effects whose `timeout` deadline has
    /// expired. Resolved on worker passes; rule evaluation never reads the
    /// clock.
    /// Seconds until the EARLIEST pending time deadline of this instance — a
    /// relative `timeout_seconds` or an absolute `deadline_at` — or `None` when
    /// no pending effect carries one. Negative when already due. Backs
    /// `whip run --wait` (R5): the loop sleeps this long instead of stopping
    /// idle on a pending timer.
    pub fn next_time_deadline_seconds(&self, instance_id: &str) -> StoreResult<Option<i64>> {
        let deadline: Option<i64> = self.connection.query_row(
            r#"
            SELECT MIN(due) - CAST(strftime('%s', 'now') AS INTEGER)
            FROM (
                SELECT CAST(strftime('%s', created_at) AS INTEGER) + timeout_seconds AS due
                FROM effects
                WHERE instance_id = ?1
                  AND timeout_seconds IS NOT NULL
                  AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
                UNION ALL
                SELECT CAST(strftime('%s', json_extract(input_json, '$.deadline_at')) AS INTEGER)
                FROM effects
                WHERE instance_id = ?1
                  AND json_extract(input_json, '$.deadline_at') IS NOT NULL
                  AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
            )
            "#,
            params![instance_id],
            |row| row.get(0),
        )?;
        Ok(deadline)
    }

    pub fn due_time_effects(
        &self,
        instance_id: &str,
        now: &str,
    ) -> StoreResult<Vec<DueTimeEffect>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT
                candidate.effect_id,
                candidate.kind,
                candidate.status,
                COALESCE(candidate.timeout_seconds, 0)
            FROM effects AS candidate
            WHERE candidate.instance_id = ?1
              AND candidate.status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
              AND (
                  -- relative deadline: created + timeout_seconds. `?2` is the
                  -- evaluation clock — `'now'` (wall clock) for dev/worker, or a
                  -- virtual timestamp a test injects via `given clock`.
                  (candidate.timeout_seconds IS NOT NULL
                   AND (strftime('%s', ?2) - strftime('%s', candidate.created_at)) >= candidate.timeout_seconds)
                  -- absolute deadline (timer until): input_json.deadline_at
                  -- (cast to integer: strftime returns text, and `>=` on text
                  -- compares lexicographically)
                  OR (json_extract(candidate.input_json, '$.deadline_at') IS NOT NULL
                      AND CAST(strftime('%s', ?2) AS INTEGER)
                          >= CAST(strftime('%s', json_extract(candidate.input_json, '$.deadline_at')) AS INTEGER))
              )
              AND (
                  candidate.kind != 'timer.wait'
                  OR NOT EXISTS (
                      SELECT 1
                      FROM effect_dependencies AS dependency
                      JOIN effects AS upstream
                        ON upstream.effect_id = dependency.upstream_effect_id
                       AND upstream.instance_id = dependency.instance_id
                      WHERE dependency.instance_id = candidate.instance_id
                        AND dependency.downstream_effect_id = candidate.effect_id
                        AND NOT (
                            (dependency.predicate = 'succeeds' AND upstream.status = 'completed')
                            OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out'))
                            OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out')
                            OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled')
                            OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled'))
                        )
                  )
              )
            ORDER BY candidate.created_at, candidate.effect_id
            "#,
        )?;
        let rows = statement
            .query_map([instance_id, now], |row| {
                Ok(DueTimeEffect {
                    effect_id: row.get(0)?,
                    kind: row.get(1)?,
                    status: row.get(2)?,
                    timeout_seconds: row.get(3)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Scheduled instants for an `every <interval_seconds>` clock source that are
    /// due at `now`, strictly after `after_scheduled` (the cursor — pass the source
    /// start when no occurrence has been admitted yet), in ascending ISO-8601
    /// order. Pure interval arithmetic via SQLite `strftime` (no timezone, no date
    /// library): the first occurrence is `cursor + interval`. `now` is the
    /// evaluation clock (`'now'` for dev/worker, or an injected virtual timestamp).
    /// Bounded to 100000 occurrences per pass as a runaway guard.
    pub fn due_interval_occurrences(
        &self,
        after_scheduled: &str,
        interval_seconds: i64,
        now: &str,
    ) -> StoreResult<Vec<String>> {
        if interval_seconds <= 0 {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            r#"
            WITH RECURSIVE occurrence(scheduled_epoch) AS (
                SELECT CAST(strftime('%s', ?1) AS INTEGER) + ?2
                UNION ALL
                SELECT scheduled_epoch + ?2 FROM occurrence
                WHERE scheduled_epoch + ?2 <= CAST(strftime('%s', ?3) AS INTEGER)
                  AND scheduled_epoch < CAST(strftime('%s', ?1) AS INTEGER) + (?2 * 100000)
            )
            SELECT strftime('%Y-%m-%dT%H:%M:%SZ', scheduled_epoch, 'unixepoch')
            FROM occurrence
            WHERE scheduled_epoch <= CAST(strftime('%s', ?3) AS INTEGER)
            ORDER BY scheduled_epoch
            "#,
        )?;
        let rows = statement
            .query_map(params![after_scheduled, interval_seconds, now], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Resolve an evaluation-clock token (`'now'` or an injected virtual
    /// timestamp) to a concrete ISO-8601 instant, so an admitted occurrence records
    /// a fixed `observed_at` (replay reads the recorded value rather than the clock).
    pub fn resolve_clock(&self, now: &str) -> StoreResult<String> {
        let resolved: Option<String> = self
            .connection
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%SZ', ?1)",
                params![now],
                |row| row.get(0),
            )
            .optional()?;
        resolved.ok_or_else(|| StoreError::Conflict(format!("unparseable clock instant `{now}`")))
    }

    /// The latest `scheduled_at` already admitted for a clock signal, read from the
    /// append-only event log (NOT active facts — a consumed occurrence must not let
    /// the cursor regress and re-admit). `None` when no occurrence has been admitted
    /// yet, so the caller seeds the cursor from the source start.
    pub fn last_clock_occurrence(
        &self,
        instance_id: &str,
        signal: &str,
    ) -> StoreResult<Option<String>> {
        let latest: Option<String> = self
            .connection
            .query_row(
                "SELECT MAX(json_extract(payload_json, '$.scheduled_at')) \
                 FROM events WHERE instance_id = ?1 AND event_type = ?2",
                params![instance_id, signal],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(latest)
    }

    /// Pending time obligations (queued timers, unexpired deadlines) for
    /// status reporting.
    pub fn pending_time_effects(&self, instance_id: &str) -> StoreResult<Vec<DueTimeEffect>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT effect_id, kind, status, timeout_seconds
            FROM effects
            WHERE instance_id = ?1
              AND timeout_seconds IS NOT NULL
              AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
            ORDER BY created_at, effect_id
            "#,
        )?;
        let rows = statement
            .query_map([instance_id], |row| {
                Ok(DueTimeEffect {
                    effect_id: row.get(0)?,
                    kind: row.get(1)?,
                    status: row.get(2)?,
                    timeout_seconds: row.get(3)?,
                })
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Marks a never-run effect `timed_out` when its creation-anchored
    /// deadline expires. Running effects go through run-level timeout plus a
    /// cancellation request instead.
    pub fn expire_effect(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let payload = json!({
            "effect_id": effect_id,
            "status": "timed_out",
            "reason": "deadline exceeded",
        })
        .to_string();
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id,
                event_type: "effect.terminal",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(effect_id),
                correlation_id: None,
                idempotency_key,
            },
        )?;
        let changed = tx.execute(
            r#"
            UPDATE effects
            SET status = 'timed_out',
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1
              AND effect_id = ?2
              AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
            "#,
            params![instance_id, effect_id],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict("effect cannot expire".to_owned()));
        }
        tx.commit()?;
        Ok(event)
    }

    /// Marks a projection fact consumed outside a rule commit (used when a
    /// projected work item stops being ready).
    ///
    /// DR-0044 ruling (P1 c, the `retire_fact` boundary): this retirement is a
    /// raw projection UPDATE and appends NO event — projection facts are a
    /// derived overlay (a `tracker.issue.ready` fact reflects live lease/blocks
    /// state), not durable rule truth, so their coming-and-going is not part of
    /// the event log. The ruling is DOCUMENTED BOUNDARY, not "make it an event":
    /// any event-log-based tooling (`whip trace`, `local_trace.v0`, a log-join
    /// staleness detector) is therefore BLIND to projection retirement. That is
    /// acceptable because the consumers that need to observe retirement read the
    /// live `facts` table instead — in particular DR-0044 P4's justification
    /// view checks whether a firing's pinned binding fact_ids are still live
    /// (a `facts` liveness read), which sees this UPDATE directly and needs no
    /// event. Do NOT add a log-join detector for this class; use liveness.
    pub fn retire_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.connection.execute(
            r#"
            UPDATE facts
            SET consumed_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1 AND fact_id = ?2 AND consumed_at IS NULL
            "#,
            params![instance_id, fact_id],
        )?;
        Ok(())
    }

    /// Undo a [`retire_fact`](Self::retire_fact): the projection's backing
    /// state is ready again under an unchanged generation. Same DR-0044
    /// ruling — a raw overlay UPDATE, no event.
    pub fn revive_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.connection.execute(
            r#"
            UPDATE facts
            SET consumed_at = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1 AND fact_id = ?2 AND consumed_at IS NOT NULL
            "#,
            params![instance_id, fact_id],
        )?;
        Ok(())
    }

    pub fn cancel_effect(
        &mut self,
        cancellation: EffectCancellation<'_>,
    ) -> StoreResult<StoredEvent> {
        let payload = json!({
            "effect_id": cancellation.effect_id,
            "status": "cancelled",
            "reason": cancellation.reason,
        })
        .to_string();
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: cancellation.instance_id,
                event_type: "effect.terminal",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(cancellation.effect_id),
                correlation_id: None,
                idempotency_key: cancellation.idempotency_key,
            },
        )?;
        let changed = tx.execute(
            r#"
            UPDATE effects
            SET status = 'cancelled',
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1
              AND effect_id = ?2
              AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
            "#,
            params![cancellation.instance_id, cancellation.effect_id],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(
                "effect cannot be cancelled".to_owned(),
            ));
        }
        mark_cancellation_requests_terminal_on(
            &tx,
            cancellation.instance_id,
            cancellation.effect_id,
            &event.event_id,
        )?;
        satisfy_dependencies_on(&tx, cancellation.instance_id)?;
        tx.commit()?;
        Ok(event)
    }

    pub fn renew_lease(&mut self, renewal: LeaseRenewal<'_>) -> StoreResult<StoredEvent> {
        let payload = json!({
            "lease_id": renewal.lease_id,
            "run_id": renewal.run_id,
            "new_expires_at": renewal.new_expires_at,
        })
        .to_string();
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: renewal.instance_id,
                event_type: "lease.renewed",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(renewal.run_id),
                correlation_id: None,
                idempotency_key: renewal.idempotency_key,
            },
        )?;
        let changed = tx.execute(
            r#"
            UPDATE leases
            SET expires_at = ?1
            WHERE instance_id = ?2
              AND lease_id = ?3
              AND run_id = ?4
              AND status = 'active'
            "#,
            params![
                renewal.new_expires_at,
                renewal.instance_id,
                renewal.lease_id,
                renewal.run_id,
            ],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict("lease cannot be renewed".to_owned()));
        }
        tx.commit()?;
        Ok(event)
    }

    pub fn expire_leases(
        &mut self,
        instance_id: &str,
        now: &str,
    ) -> StoreResult<Vec<ExpiredLease>> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let expired = {
            let mut statement = tx.prepare(
                r#"
                SELECT lease_id, run_id, effect_id
                FROM leases
                WHERE instance_id = ?1
                  AND status = 'active'
                  AND expires_at <= ?2
                ORDER BY expires_at, lease_id
                "#,
            )?;
            let rows = statement
                .query_map(params![instance_id, now], |row| {
                    Ok(ExpiredLease {
                        lease_id: row.get(0)?,
                        run_id: row.get(1)?,
                        effect_id: row.get(2)?,
                    })
                })?
                .collect::<result::Result<Vec<_>, _>>()?;
            rows
        };

        for lease in &expired {
            let payload = json!({
                "lease_id": lease.lease_id,
                "run_id": lease.run_id,
                "effect_id": lease.effect_id,
                "expired_at": now,
            })
            .to_string();
            append_event_on(
                &tx,
                NewEvent {
                    instance_id,
                    event_type: "lease.expired",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: Some(&lease.run_id),
                    correlation_id: None,
                    idempotency_key: Some(&format!("lease-expired:{}", lease.lease_id)),
                },
            )?;
            tx.execute(
                r#"
                UPDATE leases
                SET status = 'expired',
                    released_at = CURRENT_TIMESTAMP
                WHERE lease_id = ?1
                "#,
                [&lease.lease_id],
            )?;
            tx.execute(
                r#"
                UPDATE runs
                SET status = 'lease_expired',
                    completed_at = CURRENT_TIMESTAMP
                WHERE run_id = ?1
                  AND status = 'running'
                "#,
                [&lease.run_id],
            )?;
            tx.execute(
                r#"
                UPDATE effects
                SET status = 'queued',
                    updated_at = CURRENT_TIMESTAMP
                WHERE instance_id = ?1
                  AND effect_id = ?2
                  AND status = 'running'
                "#,
                params![instance_id, lease.effect_id],
            )?;
        }

        tx.commit()?;
        Ok(expired)
    }

    pub fn retry_effect(&mut self, retry: RetryEffect<'_>) -> StoreResult<StoredEvent> {
        let payload = json!({
            "effect_id": retry.effect_id,
            "retry_after": retry.retry_after,
        })
        .to_string();
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: retry.instance_id,
                event_type: "effect.retried",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(retry.effect_id),
                correlation_id: None,
                idempotency_key: retry.idempotency_key,
            },
        )?;
        let changed = tx.execute(
            r#"
            UPDATE effects
            SET status = 'queued',
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1
              AND effect_id = ?2
              AND status IN ('failed', 'timed_out')
            "#,
            params![retry.instance_id, retry.effect_id],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict("effect is not retryable".to_owned()));
        }
        tx.commit()?;
        Ok(event)
    }

    /// A transactionally-consistent snapshot of this store into a new file
    /// (`VACUUM INTO`): safe against live writers and WAL sidecars, unlike
    /// a file copy. The prefix-replay driver clones sources through this.
    pub fn snapshot_to(&self, target: &Path) -> StoreResult<()> {
        let target = target.to_string_lossy().replace('\'', "''");
        self.connection
            .execute_batch(&format!("VACUUM INTO '{target}'"))
            .map_err(StoreError::from)?;
        Ok(())
    }

    /// Prefix-replay support (`models/maude/prefix-replay.maude`): drop
    /// every event after the cut for one instance, so a subsequent
    /// `rebuild_projections` folds exactly the frozen prefix. FOR
    /// DISPOSABLE COUNTERFACTUAL STORES ONLY — the live store's log is
    /// append-only (a live rewind is `commit_restore`, which marks instead
    /// of deleting); the caller owns that discipline. Unlike a restore
    /// marker this does not bump the restore generation, so every pre-cut
    /// identity re-derives byte-identically and replayed work dedupes
    /// exactly (INV-P1 by exact dedup).
    pub fn truncate_instance_events_after(
        &mut self,
        instance_id: &str,
        cut_sequence: i64,
    ) -> StoreResult<u64> {
        let dropped = self
            .connection
            .execute(
                "DELETE FROM events WHERE instance_id = ?1 AND sequence > ?2",
                params![instance_id, cut_sequence],
            )
            .map_err(StoreError::from)?;
        // Interaction rows are not sequence-keyed and would otherwise
        // resurrect POST-cut recorded outcomes through byte-identical
        // re-derived effect ids: a re-claimed pre-cut invoke would harvest
        // the recorded child terminal, a re-asked human question would find
        // its recorded answer. Dropping them is safe for the prefix too —
        // effects settled pre-cut fold terminal and are never re-claimed,
        // so their rows are unread; queued ones must regenerate fresh.
        self.connection
            .execute(
                "DELETE FROM workflow_invocations WHERE parent_instance_id = ?1",
                params![instance_id],
            )
            .map_err(StoreError::from)?;
        Ok(dropped as u64)
    }

    /// Prefix-replay support: pin the instance row's version pointer to
    /// the given prefix-derived value — a live activation that happened
    /// AFTER the cut stamped the row with a version the truncated log no
    /// longer contains (only replayed activation events restore it).
    pub fn set_instance_version(
        &mut self,
        instance_id: &str,
        version_id: &str,
        revision_epoch: i64,
    ) -> StoreResult<()> {
        self.connection
            .execute(
                "UPDATE instances SET version_id = ?2, revision_epoch = ?3
                 WHERE instance_id = ?1",
                params![instance_id, version_id, revision_epoch],
            )
            .map_err(StoreError::from)?;
        Ok(())
    }

    /// Prefix-replay support: a truncated prefix may predate the source
    /// run's terminal, but `rebuild_projections` never resets the instance
    /// row's status (only replayed terminal/transition events move it) —
    /// reopen it so the suffix can drive.
    pub fn reset_instance_to_running(&mut self, instance_id: &str) -> StoreResult<()> {
        self.connection
            .execute(
                "UPDATE instances SET status = 'running', last_error = NULL,
                   completed_at = NULL WHERE instance_id = ?1",
                params![instance_id],
            )
            .map_err(StoreError::from)?;
        Ok(())
    }

    pub fn rebuild_projections(&mut self, instance_id: &str) -> StoreResult<()> {
        self.rebuild_projections_impl(instance_id, None)
    }

    /// RC-2 Delta A: bounded projection replay. Reconstructs the instance's
    /// projection tables AS OF event `up_to_sequence` — every persisted event
    /// with `sequence <= up_to_sequence` is applied, none after. `N` is
    /// INCLUSIVE (the event at the named sequence is itself replayed). Same
    /// single `Immediate` transaction as the unbounded rebuild; the only
    /// difference is the `WHERE sequence <= N` cut on the replayed event set.
    ///
    /// `up_to_sequence` is the single cut coordinate: the SAME per-instance
    /// event sequence that `load_brokered_transcript_at` (Plane 1) and the file
    /// manifest (`file.write.completed` facts ≤ N) key off, so one N names one
    /// consistent point across all three planes.
    pub fn rebuild_projections_to(
        &mut self,
        instance_id: &str,
        up_to_sequence: i64,
    ) -> StoreResult<()> {
        self.rebuild_projections_impl(instance_id, Some(up_to_sequence))
    }

    fn rebuild_projections_impl(
        &mut self,
        instance_id: &str,
        up_to_sequence: Option<i64>,
    ) -> StoreResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let artifact_run_links = {
            let mut statement = tx.prepare(
                r#"
                SELECT artifact_id, run_id
                FROM artifacts
                WHERE run_id IN (
                    SELECT run_id FROM runs WHERE instance_id = ?1
                )
                ORDER BY artifact_id
                "#,
            )?;
            let rows = statement
                .query_map([instance_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<result::Result<Vec<_>, _>>()?;
            rows
        };
        for (artifact_id, _) in &artifact_run_links {
            tx.execute(
                "UPDATE artifacts SET run_id = NULL WHERE artifact_id = ?1",
                [artifact_id],
            )?;
        }
        tx.execute(
            "DELETE FROM effect_cancellation_requests WHERE instance_id = ?1",
            [instance_id],
        )?;
        tx.execute("DELETE FROM leases WHERE instance_id = ?1", [instance_id])?;
        tx.execute("DELETE FROM runs WHERE instance_id = ?1", [instance_id])?;
        tx.execute(
            "DELETE FROM instance_revisions WHERE instance_id = ?1",
            [instance_id],
        )?;
        tx.execute(
            "DELETE FROM effect_dependencies WHERE instance_id = ?1",
            [instance_id],
        )?;
        tx.execute("DELETE FROM effects WHERE instance_id = ?1", [instance_id])?;
        tx.execute("DELETE FROM facts WHERE instance_id = ?1", [instance_id])?;

        let fetched = {
            // RC-2 Delta A: when a bound is present, cut the replayed event set
            // at `sequence <= N` (INCLUSIVE). `N` is an i64 so interpolation is
            // injection-safe; when unbounded the clause is empty, leaving the
            // full-replay query semantically identical to before.
            //
            // RC-4b: `context.restored` markers are fetched alongside the state
            // events (and `sequence` is selected) so the fold below can honor
            // them. A marker is not itself replayed; it rewinds the live set.
            let bound_clause = match up_to_sequence {
                Some(n) => format!("  AND sequence <= {n}\n"),
                None => String::new(),
            };
            let mut statement = tx.prepare(&format!(
                r#"
                SELECT event_id, event_type, payload_json, idempotency_key, causation_id, source, sequence, format_version
                FROM events
                WHERE instance_id = ?1
                  AND event_type IN (
                      'rule.committed',
                      'fact.derived',
                      'workflow.completed',
                      'workflow.failed',
                      'instance.transitioned',
                      'workflow.revision_activated',
                      'effect.run_started',
                      'effect.terminal',
                      'effect.cancelled',
                      'effect.cancellation_requested',
                      'lease.expired',
                      'context.restored'
                  )
                {bound_clause}ORDER BY sequence
                "#
            ))?;
            let rows = statement
                .query_map([instance_id], |row| {
                    Ok((
                        (
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, i64>(6)?,
                        ),
                        row.get::<_, Option<i64>>(7)?,
                    ))
                })?
                .collect::<result::Result<Vec<_>, _>>()?;
            // DR-0054 Phase B: fail the fold closed on an event row stamped
            // with a format this build does not understand — misparsing it
            // would poison every projection folded after it. Legacy NULL rows
            // read as version 1 and pass. The error names the row so the
            // diagnosis is "run the newer build", never "delete the store".
            let mut checked = Vec::with_capacity(rows.len());
            for (entry, format_version) in rows {
                if let Some(version) = format_version {
                    if version > SUPPORTED_EVENT_FORMAT_VERSION {
                        return Err(StoreError::UnsupportedVersion {
                            subject: format!(
                                "event `{}` (instance `{instance_id}`, sequence {})",
                                entry.0, entry.6
                            ),
                            found: version,
                            supported: SUPPORTED_EVENT_FORMAT_VERSION,
                        });
                    }
                }
                checked.push(entry);
            }
            checked
        };

        // RC-4b: the restore-marker replay fold (models/maude/restore-replay.maude).
        // Walk the log ascending; a `context.restored` marker rewinds the live
        // set to its target sequence, dropping every event that a later restore
        // orphaned so an abandoned branch is never re-applied. With no markers
        // present, `events` is exactly the ordered state-event set as before, so
        // the rebuild is byte-identical for instances that were never restored.
        let events = {
            let mut live: Vec<ReplayRow> = Vec::new();
            for entry in fetched {
                if entry.1 == "context.restored" {
                    if let Some(target) = restore_marker_target(&entry.2) {
                        live.retain(|folded| folded.6 <= target);
                    }
                } else {
                    live.push(entry);
                }
            }
            live
        };

        for (
            event_id,
            event_type,
            payload_json,
            idempotency_key,
            causation_id,
            source,
            _sequence,
        ) in events
        {
            match event_type.as_str() {
                "rule.committed" => replay_rule_commit(&tx, instance_id, &event_id, &payload_json)?,
                "fact.derived" => {
                    replay_fact_derived(&tx, instance_id, &event_id, &source, &payload_json)?
                }
                "workflow.completed" | "workflow.failed" => replay_workflow_terminal(
                    &tx,
                    instance_id,
                    &event_id,
                    &event_type,
                    &payload_json,
                )?,
                "instance.transitioned" => {
                    replay_instance_transition(&tx, instance_id, &event_id, &payload_json)?
                }
                "workflow.revision_activated" => replay_revision_activation(
                    &tx,
                    instance_id,
                    &event_id,
                    &payload_json,
                    idempotency_key.as_deref(),
                )?,
                "effect.run_started" => replay_run_started(&tx, instance_id, &payload_json)?,
                "effect.terminal" => {
                    replay_effect_terminal(&tx, instance_id, &event_id, &payload_json)?
                }
                "effect.cancelled" => {
                    replay_effect_cancelled(&tx, instance_id, &event_id, &payload_json)?
                }
                "effect.cancellation_requested" => replay_cancellation_request(
                    &tx,
                    instance_id,
                    &event_id,
                    &payload_json,
                    idempotency_key.as_deref(),
                    causation_id.as_deref(),
                )?,
                "lease.expired" => replay_lease_expired(&tx, instance_id, &payload_json)?,
                _ => {}
            }
        }

        for (artifact_id, run_id) in artifact_run_links {
            let run_exists = tx
                .query_row(
                    "SELECT 1 FROM runs WHERE run_id = ?1",
                    [&run_id],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if run_exists {
                tx.execute(
                    "UPDATE artifacts SET run_id = ?1 WHERE artifact_id = ?2",
                    params![run_id, artifact_id],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    }

    /// Restorable-context RC-3: capture a consistent-cut checkpoint at a
    /// quiescent point. In ONE `Immediate` transaction this (1) refuses unless
    /// the instance is quiescent — no effect mid-run (INV-2 no-in-flight
    /// straddle); (2) folds the file-store manifest from every
    /// `file.write.completed` fact so far, latest-write-wins per path; (3)
    /// stores that manifest content-addressed BEFORE the cut references its
    /// hash, in the same transaction, so no committed cut names a manifest hash
    /// absent from the blob store (INV-4 coherence); and (4) appends the
    /// `context.checkpoint` event as the cut carrier. The event's own `sequence`
    /// is the single cut coordinate that `rebuild_projections_to` (Plane 2) and
    /// `load_brokered_transcript_at` (Plane 1) key off, binding all three planes
    /// to one point. Models the `checkpoint` rule in
    /// models/maude/restorable-context.maude.
    pub fn capture_checkpoint(
        &mut self,
        capture: CheckpointCapture<'_>,
    ) -> StoreResult<CapturedCheckpoint> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let running: i64 = tx.query_row(
            "SELECT COUNT(*) FROM effects WHERE instance_id = ?1 AND status = 'running'",
            [capture.instance_id],
            |row| row.get(0),
        )?;
        if running > 0 {
            return Err(StoreError::Conflict(format!(
                "checkpoint requires a quiescent instance; {running} effect(s) still running"
            )));
        }
        // RC-4c: fold the manifest from the LIVE fact.derived payloads (the
        // restore-marker fold applied), so a checkpoint taken after a restore
        // reflects the reconciled file plane, never an abandoned-branch write.
        let fact_payloads = live_fact_payloads_on(&tx, capture.instance_id, None)?;
        let (manifest_json, manifest) = fold_file_manifest(&fact_payloads)?;
        let manifest_hash = stable_hash_hex(&manifest_json);
        tx.execute(
            "INSERT OR IGNORE INTO content_blobs (id, body, byte_len) VALUES (?1, ?2, ?3)",
            params![manifest_hash, manifest_json, manifest_json.len() as i64],
        )?;
        let payload = json!({
            "cut_id": capture.cut_id,
            "transcript_ref": capture.transcript_ref,
            "manifest_hash": manifest_hash,
            "manifest": manifest,
            "file_count": manifest.len(),
        })
        .to_string();
        let event = append_event_on(
            &tx,
            NewEvent {
                instance_id: capture.instance_id,
                event_type: "context.checkpoint",
                payload_json: &payload,
                source: "restorable-context",
                causation_id: None,
                correlation_id: None,
                idempotency_key: capture.idempotency_key,
            },
        )?;
        tx.commit()?;
        Ok(CapturedCheckpoint {
            cut_id: capture.cut_id.to_owned(),
            event_id: event.event_id,
            sequence: event.sequence,
            manifest_hash,
            file_count: manifest.len(),
        })
    }

    /// Restorable-context RC-4c: PLAN a restore to the cut `cut_id` (read-only).
    /// Resolves the checkpoint by cut id, reads its manifest, and performs the
    /// whole coherence check up front (model `restore-apply` vs `restore-refuse`):
    /// an unknown cut, a missing manifest blob, or ANY dangling content hash
    /// yields `Refused` with no mutation. Otherwise returns a `Ready` plan whose
    /// `writes` restore every manifest path to its cut content and whose
    /// `removes` are the mediated paths present now but absent from the cut (the
    /// full reconcile to the model's "file plane = exactly the manifest"). The
    /// caller applies the file ops through the file store, then `commit_restore`.
    /// Both the current file plane and the cut manifest are folded marker-aware
    /// (RC-4c), so a prior restore's abandoned writes never enter the diff.
    pub fn plan_restore(&self, instance_id: &str, cut_id: &str) -> StoreResult<RestoreDecision> {
        let checkpoint = {
            let mut statement = self.connection.prepare(
                r#"
                SELECT payload_json, sequence
                FROM events
                WHERE instance_id = ?1 AND event_type = 'context.checkpoint'
                ORDER BY sequence DESC
                "#,
            )?;
            let rows: Vec<(String, i64)> = statement
                .query_map([instance_id], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })?
                .collect::<result::Result<Vec<_>, _>>()?;
            // DR-0054 Phase C: an unreadable checkpoint payload used to be
            // silently skipped, so a corrupt row surfaced as "no checkpoint
            // with cut id X" — indistinguishable from the cut never existing,
            // and an invitation to treat the store as disposable. Surface the
            // corruption with the row identity instead.
            let mut found = None;
            for (payload_json, sequence) in rows {
                let payload: Value = serde_json::from_str(&payload_json).map_err(|error| {
                    StoreError::Conflict(format!(
                        "context.checkpoint event at sequence {sequence} of instance \
                         `{instance_id}` has an unreadable payload: {error}"
                    ))
                })?;
                if payload.get("cut_id").and_then(Value::as_str) == Some(cut_id) {
                    found = Some((payload, sequence));
                    break;
                }
            }
            found
        };
        let Some((payload, restored_to_sequence)) = checkpoint else {
            return Ok(RestoreDecision::Refused {
                reason: format!("no checkpoint with cut id `{cut_id}`"),
            });
        };
        let manifest_hash = payload
            .get("manifest_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let transcript_ref = payload
            .get("transcript_ref")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let Some(manifest_body) = self.get_content(&manifest_hash)? else {
            return Ok(RestoreDecision::Refused {
                reason: format!("manifest blob `{manifest_hash}` missing for cut `{cut_id}`"),
            });
        };
        let cut_manifest: BTreeMap<String, String> = serde_json::from_str(&manifest_body)?;
        // INV-4 coherence: every referenced content hash must be present, up
        // front, before any mutation. A single dangling hash refuses the whole
        // restore.
        let mut writes: BTreeMap<String, String> = BTreeMap::new();
        for (path, content_hash) in &cut_manifest {
            match self.get_content(content_hash)? {
                Some(body) => {
                    writes.insert(path.clone(), body);
                }
                None => {
                    return Ok(RestoreDecision::Refused {
                        reason: format!(
                            "content `{content_hash}` for `{path}` missing (dangling manifest)"
                        ),
                    });
                }
            }
        }
        // Full reconcile: mediated paths live now but absent from the cut are
        // removed so the file plane equals exactly the cut manifest.
        let current_payloads = live_fact_payloads_on(&self.connection, instance_id, None)?;
        let (_, current_manifest) = fold_file_manifest(&current_payloads)?;
        let removes: Vec<String> = current_manifest
            .keys()
            .filter(|path| !cut_manifest.contains_key(*path))
            .cloned()
            .collect();
        Ok(RestoreDecision::Ready(RestorePlan {
            cut_id: cut_id.to_owned(),
            restored_to_sequence,
            transcript_ref,
            writes,
            removes,
        }))
    }

    /// Restorable-context RC-4c: COMMIT a restore. Appends the `context.restored`
    /// marker carrying the cut coordinate, then rebuilds projections (marker-aware,
    /// RC-4b) so the instance plane lands exactly at the cut and every later read
    /// (rebuild, transcript, manifest) folds past the abandoned branch. Call
    /// AFTER the caller has applied the plan's file ops and auto-checkpointed the
    /// pre-restore head (so the restore is itself undoable). The marker is
    /// appended before the rebuild so the unbounded rebuild folds it immediately.
    pub fn commit_restore(
        &mut self,
        instance_id: &str,
        restored_to_sequence: i64,
        cut_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let payload = json!({
            "cut_id": cut_id,
            "restored_to_sequence": restored_to_sequence,
        })
        .to_string();
        let marker = self.append_event(NewEvent {
            instance_id,
            event_type: "context.restored",
            payload_json: &payload,
            source: "restorable-context",
            causation_id: None,
            correlation_id: None,
            idempotency_key,
        })?;
        self.rebuild_projections(instance_id)?;
        Ok(marker)
    }

    pub fn table_exists(&self, table: &str) -> StoreResult<bool> {
        self.connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
            .map_err(Into::into)
    }
}

/// The durable runtime store as a backend-agnostic, object-safe trait — the
/// sans-IO store seam (DR-0033 Phase 3). A durable-object SQLite backend
/// implements the same event / fact / effect / instance / registry operations
/// the native rusqlite `SqliteStore` provides, so the DO host can back the
/// runtime without the language changing. The native impl forwards to the
/// inherent methods (delegation via inherent-method precedence, guarded by
/// `unconditional_recursion`).
///
/// Excluded from the seam (kept inherent-only): constructors (`open`/
/// `open_in_memory`) and native-filesystem convenience methods that take an
/// `impl AsRef<Path>` and read the local FS — the DO host does not load from a
/// directory. Excluded: `load_package_manifests_from_dir`.
#[allow(clippy::too_many_arguments)]
pub trait RuntimeStore {
    fn schema_version(&self) -> StoreResult<i64>;
    fn append_event(&self, event: NewEvent<'_>) -> StoreResult<StoredEvent>;
    fn create_program_version(
        &mut self,
        version: NewProgramVersion<'_>,
    ) -> StoreResult<ProgramVersionRecord>;
    fn get_program_version(&self, version_id: &str) -> StoreResult<Option<ProgramVersionView>>;
    fn create_instance(&self, instance: NewInstance<'_>) -> StoreResult<InstanceRecord>;
    fn create_instance_with_authority(
        &self,
        instance: NewInstance<'_>,
        authority: NewInstanceAuthority<'_>,
    ) -> StoreResult<InstanceRecord>;
    fn list_instance_revisions(&self, instance_id: &str) -> StoreResult<Vec<WorkflowRevisionView>>;
    fn revision_cancellation_impact(
        &self,
        instance_id: &str,
        cancellation_policy: &str,
    ) -> StoreResult<RevisionCancellationImpact>;
    fn analyze_revision_compatibility(
        &self,
        instance_id: &str,
        candidate_version_id: &str,
    ) -> StoreResult<RevisionCompatibilityReport>;
    fn analyze_revision_candidate(
        &self,
        instance_id: &str,
        candidate: RevisionCandidate<'_>,
    ) -> StoreResult<RevisionCompatibilityReport>;
    fn activate_revision(
        &mut self,
        activation: RevisionActivation<'_>,
    ) -> StoreResult<WorkflowRevisionView>;
    fn request_effect_cancellation(
        &mut self,
        request: EffectCancellationRequest<'_>,
    ) -> StoreResult<EffectCancellationRequestView>;
    fn effect_has_open_cancellation_request(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<bool>;
    fn list_effect_cancellation_requests(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<EffectCancellationRequestView>>;
    fn record_workflow_invocation(&self, invocation: NewWorkflowInvocation<'_>) -> StoreResult<()>;
    fn get_workflow_invocation(
        &self,
        parent_instance_id: &str,
        parent_effect_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>>;
    fn list_child_workflow_invocations(
        &self,
        parent_instance_id: &str,
    ) -> StoreResult<Vec<WorkflowInvocationView>>;
    fn get_parent_workflow_invocation(
        &self,
        child_instance_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>>;
    fn commit_rule(&mut self, commit: RuleCommit<'_>) -> StoreResult<StoredEvent>;
    fn commit_rule_with_revision_guard(
        &mut self,
        commit: RuleCommit<'_>,
        guard: RuleCommitRevisionGuard<'_>,
    ) -> StoreResult<StoredEvent>;
    fn derive_fact(&mut self, derived: DerivedFact<'_>) -> StoreResult<StoredEvent>;
    fn admit_fact_batch(&mut self, batch: FactBatch<'_>) -> StoreResult<FactBatchOutcome>;
    fn complete_effect(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent>;
    fn complete_effect_with_terminal_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent>;
    fn resolve_effect_uncertain(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent>;
    fn claimable_effects(&self, instance_id: &str) -> StoreResult<Vec<ClaimableEffect>>;
    fn fact_exists(&self, instance_id: &str, fact_name: &str) -> StoreResult<bool>;
    fn register_package(&self, package: PackageRegistration<'_>) -> StoreResult<()>;
    fn register_package_manifest(&self, manifest_json: &str) -> StoreResult<String>;
    fn register_capability_schema(
        &self,
        capability: CapabilitySchemaRegistration<'_>,
    ) -> StoreResult<()>;
    fn register_effect_provider(&self, provider: EffectProviderRegistration<'_>)
        -> StoreResult<()>;
    fn register_profile(&self, profile: ProfileRegistration<'_>) -> StoreResult<()>;
    fn registered_profile_policy(
        &self,
        profile: &str,
    ) -> StoreResult<Option<RegisteredProfilePolicy>>;
    fn bind_capability(&self, binding: CapabilityBinding<'_>) -> StoreResult<()>;
    fn register_skill(&self, skill: SkillRegistration<'_>) -> StoreResult<()>;
    fn register_project_context_doc(
        &self,
        position: i64,
        path: &str,
        body: &str,
    ) -> StoreResult<()>;
    fn list_project_context_docs(&self) -> StoreResult<Vec<ProjectContextDoc>>;
    fn record_compute_result(
        &self,
        registration: ComputeResultRegistration<'_>,
    ) -> StoreResult<bool>;
    fn lookup_compute_result(&self, content_key: &str) -> StoreResult<Option<ComputeCachedResult>>;
    /// Capture a file body content-addressed into the file-history blob store
    /// (restorable-context RC-1), returning its content id (`stable_hash_hex`).
    /// Idempotent — identical bytes dedupe — so an overwrite preserves both the
    /// superseded and the new body by hash. Captured in the same store as the
    /// write's fact and before that fact commits (INV-4 coherence).
    fn put_content(&self, body: &str) -> StoreResult<String>;
    /// Read a captured file body back by content id, or `None` if never held.
    fn get_content(&self, id: &str) -> StoreResult<Option<String>>;
    /// Restorable-context RC-3: capture a consistent-cut checkpoint at a
    /// quiescent point, binding the three planes to one cut coordinate (the
    /// checkpoint event's sequence). Refuses if the instance is not quiescent
    /// (INV-2) and stores the file manifest content-addressed before the cut
    /// references it (INV-4). See the inherent method for the full contract.
    fn capture_checkpoint(
        &mut self,
        capture: CheckpointCapture<'_>,
    ) -> StoreResult<CapturedCheckpoint>;
    /// Restorable-context RC-4c: plan a restore to `cut_id` (read-only, coherence
    /// check up front; `Refused` on unknown cut / dangling manifest). See the
    /// inherent method for the full contract.
    fn plan_restore(&self, instance_id: &str, cut_id: &str) -> StoreResult<RestoreDecision>;
    /// Restorable-context RC-4c: commit a restore — append the `context.restored`
    /// marker and rebuild marker-aware so the instance plane lands at the cut.
    fn commit_restore(
        &mut self,
        instance_id: &str,
        restored_to_sequence: i64,
        cut_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent>;
    fn register_script_capability(
        &self,
        registration: ScriptCapabilityRegistration<'_>,
    ) -> StoreResult<()>;
    fn get_script_capability(&self, name: &str) -> StoreResult<Option<ScriptCapabilityRecord>>;
    fn attach_skill(&self, attachment: SkillAttachment<'_>) -> StoreResult<()>;
    fn list_skills(&self) -> StoreResult<Vec<SkillView>>;
    fn list_skill_attachments(
        &self,
        scope_type: &str,
        scope_id: &str,
    ) -> StoreResult<Vec<SkillAttachmentView>>;
    fn record_evidence(&self, evidence: EvidenceRecord<'_>) -> StoreResult<String>;
    fn record_provider_validation_evidence(
        &self,
        evidence: ProviderValidationEvidence<'_>,
    ) -> StoreResult<String>;
    fn record_codex_app_server_evidence(
        &self,
        evidence: CodexAppServerEvidence<'_>,
    ) -> StoreResult<String>;
    fn record_claude_agent_sdk_evidence(
        &self,
        evidence: ClaudeAgentSdkEvidence<'_>,
    ) -> StoreResult<String>;
    fn link_evidence(&self, link: EvidenceLink<'_>) -> StoreResult<()>;
    fn record_artifact(&self, artifact: ArtifactRecord<'_>) -> StoreResult<String>;
    fn list_artifacts_for_run(&self, run_id: &str) -> StoreResult<Vec<ArtifactView>>;
    fn record_workspace(&self, workspace: WorkspaceRecord<'_>) -> StoreResult<String>;
    fn get_workspace(&self, workspace_id: &str) -> StoreResult<Option<WorkspaceView>>;
    fn list_workspaces_for_instance(&self, instance_id: &str) -> StoreResult<Vec<WorkspaceView>>;
    fn record_diagnostic(&self, diagnostic: DiagnosticRecord<'_>) -> StoreResult<String>;
    fn list_diagnostics(&self, instance_id: Option<&str>) -> StoreResult<Vec<DiagnosticView>>;
    fn list_diagnostics_from_events(&self, instance_id: &str) -> StoreResult<Vec<DiagnosticView>>;
    fn effect_source_span_json(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<Option<String>>;
    fn record_skill_evidence(&self, evidence: SkillEvidence<'_>) -> StoreResult<String>;
    fn list_evidence(&self, instance_id: &str) -> StoreResult<Vec<EvidenceView>>;
    fn list_evidence_for_subject(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> StoreResult<Vec<EvidenceView>>;
    fn list_evidence_links(&self, instance_id: &str) -> StoreResult<Vec<EvidenceLinkView>>;
    fn list_instances(&self) -> StoreResult<Vec<InstanceView>>;
    fn get_instance(&self, instance_id: &str) -> StoreResult<Option<InstanceView>>;
    fn list_events(&self, instance_id: &str) -> StoreResult<Vec<EventView>>;
    /// The already-recorded event carrying this `(instance_id, idempotency_key)`
    /// pair, if any — the read side of the events unique index
    /// (migrations/0001), so an admission driver can absorb a re-delivered
    /// key instead of tripping the index (spec/std-ingress.md, one shared
    /// admission core for every driver).
    fn event_by_idempotency_key(
        &self,
        instance_id: &str,
        idempotency_key: &str,
    ) -> StoreResult<Option<StoredEvent>>;
    fn list_facts(&self, instance_id: &str) -> StoreResult<Vec<FactView>>;
    fn list_facts_including_consumed(&self, instance_id: &str) -> StoreResult<Vec<FactView>>;
    fn list_effects(&self, instance_id: &str) -> StoreResult<Vec<EffectView>>;
    fn list_runs(&self, instance_id: &str) -> StoreResult<Vec<RunView>>;
    fn status(&self, instance_id: &str) -> StoreResult<Option<StatusView>>;
    fn satisfy_dependencies(&self, instance_id: &str) -> StoreResult<usize>;
    fn start_run(&mut self, run: RunStart<'_>) -> StoreResult<StoredEvent>;
    fn block_effect_binding(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        category: &str,
        detail: &str,
    ) -> StoreResult<StoredEvent>;
    fn transition_instance(
        &mut self,
        transition: InstanceTransition<'_>,
    ) -> StoreResult<StoredEvent>;
    fn due_time_effects(&self, instance_id: &str, now: &str) -> StoreResult<Vec<DueTimeEffect>>;
    fn due_interval_occurrences(
        &self,
        after_scheduled: &str,
        interval_seconds: i64,
        now: &str,
    ) -> StoreResult<Vec<String>>;
    fn resolve_clock(&self, now: &str) -> StoreResult<String>;
    fn last_clock_occurrence(&self, instance_id: &str, signal: &str)
        -> StoreResult<Option<String>>;
    fn pending_time_effects(&self, instance_id: &str) -> StoreResult<Vec<DueTimeEffect>>;
    fn expire_effect(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent>;
    fn retire_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()>;
    /// Undo a [`retire_fact`](Self::retire_fact): a projection fact whose
    /// backing state is ready again (with an unchanged generation) comes back
    /// live. Same DR-0044 ruling — a raw overlay UPDATE, no event.
    fn revive_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()>;
    fn cancel_effect(&mut self, cancellation: EffectCancellation<'_>) -> StoreResult<StoredEvent>;
    fn renew_lease(&mut self, renewal: LeaseRenewal<'_>) -> StoreResult<StoredEvent>;
    fn expire_leases(&mut self, instance_id: &str, now: &str) -> StoreResult<Vec<ExpiredLease>>;
    fn retry_effect(&mut self, retry: RetryEffect<'_>) -> StoreResult<StoredEvent>;
    fn rebuild_projections(&mut self, instance_id: &str) -> StoreResult<()>;
    fn table_exists(&self, table: &str) -> StoreResult<bool>;
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "native")]
impl RuntimeStore for SqliteStore {
    fn schema_version(&self) -> StoreResult<i64> {
        self.schema_version()
    }
    fn append_event(&self, event: NewEvent<'_>) -> StoreResult<StoredEvent> {
        self.append_event(event)
    }
    fn create_program_version(
        &mut self,
        version: NewProgramVersion<'_>,
    ) -> StoreResult<ProgramVersionRecord> {
        self.create_program_version(version)
    }
    fn get_program_version(&self, version_id: &str) -> StoreResult<Option<ProgramVersionView>> {
        self.get_program_version(version_id)
    }
    fn create_instance(&self, instance: NewInstance<'_>) -> StoreResult<InstanceRecord> {
        self.create_instance(instance)
    }
    fn create_instance_with_authority(
        &self,
        instance: NewInstance<'_>,
        authority: NewInstanceAuthority<'_>,
    ) -> StoreResult<InstanceRecord> {
        self.create_instance_with_authority(instance, authority)
    }
    fn list_instance_revisions(&self, instance_id: &str) -> StoreResult<Vec<WorkflowRevisionView>> {
        self.list_instance_revisions(instance_id)
    }
    fn revision_cancellation_impact(
        &self,
        instance_id: &str,
        cancellation_policy: &str,
    ) -> StoreResult<RevisionCancellationImpact> {
        self.revision_cancellation_impact(instance_id, cancellation_policy)
    }
    fn analyze_revision_compatibility(
        &self,
        instance_id: &str,
        candidate_version_id: &str,
    ) -> StoreResult<RevisionCompatibilityReport> {
        self.analyze_revision_compatibility(instance_id, candidate_version_id)
    }
    fn analyze_revision_candidate(
        &self,
        instance_id: &str,
        candidate: RevisionCandidate<'_>,
    ) -> StoreResult<RevisionCompatibilityReport> {
        self.analyze_revision_candidate(instance_id, candidate)
    }
    fn activate_revision(
        &mut self,
        activation: RevisionActivation<'_>,
    ) -> StoreResult<WorkflowRevisionView> {
        self.activate_revision(activation)
    }
    fn request_effect_cancellation(
        &mut self,
        request: EffectCancellationRequest<'_>,
    ) -> StoreResult<EffectCancellationRequestView> {
        self.request_effect_cancellation(request)
    }
    fn effect_has_open_cancellation_request(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<bool> {
        self.effect_has_open_cancellation_request(instance_id, effect_id)
    }
    fn list_effect_cancellation_requests(
        &self,
        instance_id: &str,
    ) -> StoreResult<Vec<EffectCancellationRequestView>> {
        self.list_effect_cancellation_requests(instance_id)
    }
    fn record_workflow_invocation(&self, invocation: NewWorkflowInvocation<'_>) -> StoreResult<()> {
        self.record_workflow_invocation(invocation)
    }
    fn get_workflow_invocation(
        &self,
        parent_instance_id: &str,
        parent_effect_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        self.get_workflow_invocation(parent_instance_id, parent_effect_id)
    }
    fn list_child_workflow_invocations(
        &self,
        parent_instance_id: &str,
    ) -> StoreResult<Vec<WorkflowInvocationView>> {
        self.list_child_workflow_invocations(parent_instance_id)
    }
    fn get_parent_workflow_invocation(
        &self,
        child_instance_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        self.get_parent_workflow_invocation(child_instance_id)
    }
    fn commit_rule(&mut self, commit: RuleCommit<'_>) -> StoreResult<StoredEvent> {
        self.commit_rule(commit)
    }
    fn commit_rule_with_revision_guard(
        &mut self,
        commit: RuleCommit<'_>,
        guard: RuleCommitRevisionGuard<'_>,
    ) -> StoreResult<StoredEvent> {
        self.commit_rule_with_revision_guard(commit, guard)
    }
    fn derive_fact(&mut self, derived: DerivedFact<'_>) -> StoreResult<StoredEvent> {
        self.derive_fact(derived)
    }
    fn admit_fact_batch(&mut self, batch: FactBatch<'_>) -> StoreResult<FactBatchOutcome> {
        self.admit_fact_batch(batch)
    }
    fn complete_effect(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent> {
        self.complete_effect(completion)
    }
    fn complete_effect_with_terminal_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        self.complete_effect_with_terminal_diagnostic(completion, diagnostic)
    }
    fn resolve_effect_uncertain(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        self.resolve_effect_uncertain(completion, diagnostic)
    }
    fn claimable_effects(&self, instance_id: &str) -> StoreResult<Vec<ClaimableEffect>> {
        self.claimable_effects(instance_id)
    }
    fn fact_exists(&self, instance_id: &str, fact_name: &str) -> StoreResult<bool> {
        self.fact_exists(instance_id, fact_name)
    }
    fn register_package(&self, package: PackageRegistration<'_>) -> StoreResult<()> {
        self.register_package(package)
    }
    fn register_package_manifest(&self, manifest_json: &str) -> StoreResult<String> {
        self.register_package_manifest(manifest_json)
    }
    fn register_capability_schema(
        &self,
        capability: CapabilitySchemaRegistration<'_>,
    ) -> StoreResult<()> {
        self.register_capability_schema(capability)
    }
    fn register_effect_provider(
        &self,
        provider: EffectProviderRegistration<'_>,
    ) -> StoreResult<()> {
        self.register_effect_provider(provider)
    }
    fn register_profile(&self, profile: ProfileRegistration<'_>) -> StoreResult<()> {
        self.register_profile(profile)
    }
    fn registered_profile_policy(
        &self,
        profile: &str,
    ) -> StoreResult<Option<RegisteredProfilePolicy>> {
        self.registered_profile_policy(profile)
    }
    fn bind_capability(&self, binding: CapabilityBinding<'_>) -> StoreResult<()> {
        self.bind_capability(binding)
    }
    fn register_project_context_doc(
        &self,
        position: i64,
        path: &str,
        body: &str,
    ) -> StoreResult<()> {
        SqliteStore::register_project_context_doc(self, position, path, body)
    }

    fn list_project_context_docs(&self) -> StoreResult<Vec<ProjectContextDoc>> {
        SqliteStore::list_project_context_docs(self)
    }

    fn record_compute_result(
        &self,
        registration: ComputeResultRegistration<'_>,
    ) -> StoreResult<bool> {
        SqliteStore::record_compute_result(self, registration)
    }

    fn lookup_compute_result(&self, content_key: &str) -> StoreResult<Option<ComputeCachedResult>> {
        SqliteStore::lookup_compute_result(self, content_key)
    }

    fn put_content(&self, body: &str) -> StoreResult<String> {
        SqliteStore::put_content(self, body)
    }

    fn get_content(&self, id: &str) -> StoreResult<Option<String>> {
        SqliteStore::get_content(self, id)
    }

    fn capture_checkpoint(
        &mut self,
        capture: CheckpointCapture<'_>,
    ) -> StoreResult<CapturedCheckpoint> {
        SqliteStore::capture_checkpoint(self, capture)
    }

    fn plan_restore(&self, instance_id: &str, cut_id: &str) -> StoreResult<RestoreDecision> {
        SqliteStore::plan_restore(self, instance_id, cut_id)
    }

    fn commit_restore(
        &mut self,
        instance_id: &str,
        restored_to_sequence: i64,
        cut_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        SqliteStore::commit_restore(
            self,
            instance_id,
            restored_to_sequence,
            cut_id,
            idempotency_key,
        )
    }

    fn register_script_capability(
        &self,
        registration: ScriptCapabilityRegistration<'_>,
    ) -> StoreResult<()> {
        SqliteStore::register_script_capability(self, registration)
    }

    fn get_script_capability(&self, name: &str) -> StoreResult<Option<ScriptCapabilityRecord>> {
        SqliteStore::get_script_capability(self, name)
    }

    fn register_skill(&self, skill: SkillRegistration<'_>) -> StoreResult<()> {
        self.register_skill(skill)
    }
    fn attach_skill(&self, attachment: SkillAttachment<'_>) -> StoreResult<()> {
        self.attach_skill(attachment)
    }
    fn list_skills(&self) -> StoreResult<Vec<SkillView>> {
        self.list_skills()
    }
    fn list_skill_attachments(
        &self,
        scope_type: &str,
        scope_id: &str,
    ) -> StoreResult<Vec<SkillAttachmentView>> {
        self.list_skill_attachments(scope_type, scope_id)
    }
    fn record_evidence(&self, evidence: EvidenceRecord<'_>) -> StoreResult<String> {
        self.record_evidence(evidence)
    }
    fn record_provider_validation_evidence(
        &self,
        evidence: ProviderValidationEvidence<'_>,
    ) -> StoreResult<String> {
        self.record_provider_validation_evidence(evidence)
    }
    fn record_codex_app_server_evidence(
        &self,
        evidence: CodexAppServerEvidence<'_>,
    ) -> StoreResult<String> {
        self.record_codex_app_server_evidence(evidence)
    }
    fn record_claude_agent_sdk_evidence(
        &self,
        evidence: ClaudeAgentSdkEvidence<'_>,
    ) -> StoreResult<String> {
        self.record_claude_agent_sdk_evidence(evidence)
    }
    fn link_evidence(&self, link: EvidenceLink<'_>) -> StoreResult<()> {
        self.link_evidence(link)
    }
    fn record_artifact(&self, artifact: ArtifactRecord<'_>) -> StoreResult<String> {
        self.record_artifact(artifact)
    }
    fn list_artifacts_for_run(&self, run_id: &str) -> StoreResult<Vec<ArtifactView>> {
        self.list_artifacts_for_run(run_id)
    }
    fn record_workspace(&self, workspace: WorkspaceRecord<'_>) -> StoreResult<String> {
        self.record_workspace(workspace)
    }
    fn get_workspace(&self, workspace_id: &str) -> StoreResult<Option<WorkspaceView>> {
        self.get_workspace(workspace_id)
    }
    fn list_workspaces_for_instance(&self, instance_id: &str) -> StoreResult<Vec<WorkspaceView>> {
        self.list_workspaces_for_instance(instance_id)
    }
    fn record_diagnostic(&self, diagnostic: DiagnosticRecord<'_>) -> StoreResult<String> {
        self.record_diagnostic(diagnostic)
    }
    fn list_diagnostics(&self, instance_id: Option<&str>) -> StoreResult<Vec<DiagnosticView>> {
        self.list_diagnostics(instance_id)
    }
    fn list_diagnostics_from_events(&self, instance_id: &str) -> StoreResult<Vec<DiagnosticView>> {
        self.list_diagnostics_from_events(instance_id)
    }
    fn effect_source_span_json(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> StoreResult<Option<String>> {
        self.effect_source_span_json(instance_id, effect_id)
    }
    fn record_skill_evidence(&self, evidence: SkillEvidence<'_>) -> StoreResult<String> {
        self.record_skill_evidence(evidence)
    }
    fn list_evidence(&self, instance_id: &str) -> StoreResult<Vec<EvidenceView>> {
        self.list_evidence(instance_id)
    }
    fn list_evidence_for_subject(
        &self,
        subject_type: &str,
        subject_id: &str,
    ) -> StoreResult<Vec<EvidenceView>> {
        self.list_evidence_for_subject(subject_type, subject_id)
    }
    fn list_evidence_links(&self, instance_id: &str) -> StoreResult<Vec<EvidenceLinkView>> {
        self.list_evidence_links(instance_id)
    }
    fn list_instances(&self) -> StoreResult<Vec<InstanceView>> {
        self.list_instances()
    }
    fn get_instance(&self, instance_id: &str) -> StoreResult<Option<InstanceView>> {
        self.get_instance(instance_id)
    }
    fn list_events(&self, instance_id: &str) -> StoreResult<Vec<EventView>> {
        self.list_events(instance_id)
    }
    fn event_by_idempotency_key(
        &self,
        instance_id: &str,
        idempotency_key: &str,
    ) -> StoreResult<Option<StoredEvent>> {
        self.event_by_idempotency_key(instance_id, idempotency_key)
    }
    fn list_facts(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        self.list_facts(instance_id)
    }
    fn list_facts_including_consumed(&self, instance_id: &str) -> StoreResult<Vec<FactView>> {
        self.list_facts_including_consumed(instance_id)
    }
    fn list_effects(&self, instance_id: &str) -> StoreResult<Vec<EffectView>> {
        self.list_effects(instance_id)
    }
    fn list_runs(&self, instance_id: &str) -> StoreResult<Vec<RunView>> {
        self.list_runs(instance_id)
    }
    fn status(&self, instance_id: &str) -> StoreResult<Option<StatusView>> {
        self.status(instance_id)
    }
    fn satisfy_dependencies(&self, instance_id: &str) -> StoreResult<usize> {
        self.satisfy_dependencies(instance_id)
    }
    fn start_run(&mut self, run: RunStart<'_>) -> StoreResult<StoredEvent> {
        self.start_run(run)
    }
    fn block_effect_binding(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        category: &str,
        detail: &str,
    ) -> StoreResult<StoredEvent> {
        self.block_effect_binding(instance_id, effect_id, category, detail)
    }
    fn transition_instance(
        &mut self,
        transition: InstanceTransition<'_>,
    ) -> StoreResult<StoredEvent> {
        self.transition_instance(transition)
    }
    fn due_time_effects(&self, instance_id: &str, now: &str) -> StoreResult<Vec<DueTimeEffect>> {
        self.due_time_effects(instance_id, now)
    }
    fn due_interval_occurrences(
        &self,
        after_scheduled: &str,
        interval_seconds: i64,
        now: &str,
    ) -> StoreResult<Vec<String>> {
        self.due_interval_occurrences(after_scheduled, interval_seconds, now)
    }
    fn resolve_clock(&self, now: &str) -> StoreResult<String> {
        self.resolve_clock(now)
    }
    fn last_clock_occurrence(
        &self,
        instance_id: &str,
        signal: &str,
    ) -> StoreResult<Option<String>> {
        self.last_clock_occurrence(instance_id, signal)
    }
    fn pending_time_effects(&self, instance_id: &str) -> StoreResult<Vec<DueTimeEffect>> {
        self.pending_time_effects(instance_id)
    }
    fn expire_effect(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        self.expire_effect(instance_id, effect_id, idempotency_key)
    }
    fn retire_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.retire_fact(instance_id, fact_id)
    }
    fn revive_fact(&mut self, instance_id: &str, fact_id: &str) -> StoreResult<()> {
        self.revive_fact(instance_id, fact_id)
    }
    fn cancel_effect(&mut self, cancellation: EffectCancellation<'_>) -> StoreResult<StoredEvent> {
        self.cancel_effect(cancellation)
    }
    fn renew_lease(&mut self, renewal: LeaseRenewal<'_>) -> StoreResult<StoredEvent> {
        self.renew_lease(renewal)
    }
    fn expire_leases(&mut self, instance_id: &str, now: &str) -> StoreResult<Vec<ExpiredLease>> {
        self.expire_leases(instance_id, now)
    }
    fn retry_effect(&mut self, retry: RetryEffect<'_>) -> StoreResult<StoredEvent> {
        self.retry_effect(retry)
    }
    fn rebuild_projections(&mut self, instance_id: &str) -> StoreResult<()> {
        self.rebuild_projections(instance_id)
    }
    fn table_exists(&self, table: &str) -> StoreResult<bool> {
        self.table_exists(table)
    }
}

/// How long a contended write waits before it gives up with `SQLITE_BUSY`.
/// Every store in this crate shares the value so one contended path cannot
/// wait a different amount from another for no stated reason.
#[cfg(feature = "native")]
pub(crate) const STORE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Put a freshly opened connection into the mode every store in this crate
/// expects: a lock wait installed, and WAL established.
///
/// `busy_timeout` does not cover the WAL conversion. Switching a database out
/// of `delete` journal mode needs a brief exclusive lock, and SQLite does not
/// run the busy handler for that conversion — it returns `SQLITE_BUSY` at
/// once. So N workers opening one *fresh* store concurrently would each set
/// their timeout, race for the conversion, and all but one would fail
/// immediately no matter how long the timeout was. Only the first open of a
/// given file can hit this: once the database is in WAL the conversion is a
/// no-op that takes no exclusive lock.
///
/// A `SQLITE_BUSY` here therefore does not mean "cannot proceed", it means
/// "someone else is converting". Re-read the mode: if the winner has landed,
/// this connection wants exactly what it already has. Otherwise back off and
/// look again, and surface the real error if the contention never clears —
/// never open a store whose journal mode was not established.
///
/// An in-memory database reports `memory` and cannot be converted; that is a
/// success, not a failure to establish WAL.
#[cfg(feature = "native")]
pub(crate) fn establish_wal(connection: &Connection) -> StoreResult<()> {
    const ATTEMPTS: u32 = 50;

    connection.busy_timeout(STORE_BUSY_TIMEOUT)?;

    let established = |mode: &str| -> bool {
        let mode = mode.to_ascii_lowercase();
        mode == "wal" || mode == "memory"
    };
    let current: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if established(&current) {
        return Ok(());
    }

    for attempt in 0..ATTEMPTS {
        // `PRAGMA journal_mode = WAL` reports the resulting mode as a row, so
        // it is a query rather than a statement to execute and discard.
        let outcome = connection.query_row("PRAGMA journal_mode = WAL", [], |row| {
            row.get::<_, String>(0)
        });
        match outcome {
            Ok(mode) if established(&mode) => return Ok(()),
            // The conversion reported some other mode: it did not take, and no
            // error explains why. Treat it like contention and look again.
            Ok(_) => {}
            Err(error) if is_busy(&error) => {}
            Err(error) => return Err(StoreError::from(error)),
        }

        let settled: String = connection.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
        if established(&settled) {
            return Ok(());
        }
        if attempt + 1 == ATTEMPTS {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }

    Err(StoreError::Conflict(format!(
        "could not establish WAL journal mode after {ATTEMPTS} attempts: the database stayed locked by another connection",
    )))
}

#[cfg(feature = "native")]
fn is_busy(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    )
}

#[cfg(feature = "native")]
#[cfg(unix)]
fn harden_store_file_permissions(path: &Path) -> StoreResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    if permissions.mode() & 0o777 != 0o600 {
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions)?;
    }
    Ok(())
}

#[cfg(feature = "native")]
#[cfg(not(unix))]
fn harden_store_file_permissions(_path: &Path) -> StoreResult<()> {
    Ok(())
}

#[cfg(feature = "native")]
fn table_exists(connection: &Connection, table: &str) -> StoreResult<bool> {
    connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn validate_workspace_policy(policy: &str) -> StoreResult<()> {
    match policy {
        "shared"
        | "read_only"
        | "per_effect_worktree"
        | "per_issue_worktree"
        | "remote_sandbox" => Ok(()),
        _ => Err(StoreError::Conflict(format!(
            "unsupported workspace policy `{policy}`"
        ))),
    }
}

#[cfg(feature = "native")]
fn validate_workspace_status(status: &str) -> StoreResult<()> {
    match status {
        "prepared" | "active" | "released" | "failed" => Ok(()),
        _ => Err(StoreError::Conflict(format!(
            "unsupported workspace status `{status}`"
        ))),
    }
}

#[cfg(feature = "native")]
fn workspace_select_sql(predicate: &str) -> String {
    format!(
        r#"
        SELECT
            workspace_id,
            instance_id,
            effect_id,
            run_id,
            provider,
            policy,
            uri,
            status,
            metadata_json,
            created_at,
            updated_at
        FROM workspaces
        {predicate}
        "#
    )
}

#[cfg(feature = "native")]
fn workspace_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkspaceView> {
    Ok(WorkspaceView {
        workspace_id: row.get(0)?,
        instance_id: row.get(1)?,
        effect_id: row.get(2)?,
        run_id: row.get(3)?,
        provider: row.get(4)?,
        policy: row.get(5)?,
        uri: row.get(6)?,
        status: row.get(7)?,
        metadata_json: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

#[cfg(feature = "native")]
/// Restorable-context RC-3: fold the file-store manifest at a cut from the
/// sequence-ordered `fact.derived` event payloads of an instance. Only
/// `file.write.completed` facts contribute; the RC-1 write value they carry
/// lives at `payload.value.value` (the outer `value` is the fact body, the
/// inner is the write descriptor `{store, path, ..., content_hash}`). Later
/// writes to the same path supersede earlier ones (latest-wins), so the folded
/// map is the file-plane state as of the cut. Returned as a `BTreeMap` (sorted
/// by path) and its deterministic JSON serialization, so two cuts over the same
/// file state hash identically. Backend-agnostic — native and DO both fold the
/// same way after their own ordered SELECT.
fn fold_file_manifest(fact_payloads: &[String]) -> StoreResult<(String, BTreeMap<String, String>)> {
    let mut manifest: BTreeMap<String, String> = BTreeMap::new();
    for payload_json in fact_payloads {
        let payload: Value = serde_json::from_str(payload_json)?;
        if payload.get("name").and_then(Value::as_str) != Some("file.write.completed") {
            continue;
        }
        let descriptor = payload.get("value").and_then(|fact| fact.get("value"));
        // Prefer the full resolved path (RC-5) so restore is self-contained and
        // writes back to the exact location; fall back to the relative `path`
        // for facts recorded before RC-5 (and synthetic test facts).
        let path = descriptor
            .and_then(|value| value.get("full_path").or_else(|| value.get("path")))
            .and_then(Value::as_str);
        let content_hash = descriptor
            .and_then(|value| value.get("content_hash"))
            .and_then(Value::as_str);
        if let (Some(path), Some(content_hash)) = (path, content_hash) {
            manifest.insert(path.to_owned(), content_hash.to_owned());
        }
    }
    let manifest_json = serde_json::to_string(&manifest)?;
    Ok((manifest_json, manifest))
}

/// Restorable-context RC-4c: the LIVE `fact.derived` payloads for an instance,
/// with the restore-marker fold already applied (RC-4b) so abandoned-branch
/// facts are excluded. Used to fold the file manifest at a cut (`capture_checkpoint`)
/// and the current file plane (`plan_restore`) so both see the same
/// marker-aware file state. `up_to_sequence` bounds the read (INCLUSIVE) for a
/// point-in-time fold; `None` reads to the current head.
#[cfg(feature = "native")]
fn live_fact_payloads_on(
    connection: &Connection,
    instance_id: &str,
    up_to_sequence: Option<i64>,
) -> StoreResult<Vec<String>> {
    let bound_clause = match up_to_sequence {
        Some(n) => format!("  AND sequence <= {n}\n"),
        None => String::new(),
    };
    let mut statement = connection.prepare(&format!(
        r#"
        SELECT event_type, payload_json, sequence
        FROM events
        WHERE instance_id = ?1 AND event_type IN ('fact.derived', 'context.restored')
        {bound_clause}ORDER BY sequence
        "#
    ))?;
    let rows: Vec<(String, String, i64)> = {
        let mapped = statement
            .query_map([instance_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<result::Result<Vec<_>, _>>()?;
        mapped
    };
    let mut live: Vec<(String, i64)> = Vec::new();
    for (event_type, payload_json, sequence) in rows {
        if event_type == "context.restored" {
            if let Some(target) = restore_marker_target(&payload_json) {
                live.retain(|(_, seq)| *seq <= target);
            }
        } else {
            live.push((payload_json, sequence));
        }
    }
    Ok(live.into_iter().map(|(payload, _)| payload).collect())
}

/// A fetched replayable event row for the restore-marker fold (RC-4b):
/// (event_id, event_type, payload_json, idempotency_key, causation_id, source,
/// sequence).
#[cfg(feature = "native")]
type ReplayRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
    i64,
);

/// Restorable-context RC-4b: the target sequence a `context.restored` marker
/// rewinds the replay to (`restored_to_sequence`). `None` for a malformed
/// marker, in which case the fold applies no rewind (retains all live events)
/// rather than corrupting the projection.
#[cfg(feature = "native")]
/// The restore-marker fold over the EFFECTS plane: the set of event ids
/// that survive every `context.restored` marker (RC-4b applied to the
/// third plane — an effect is live iff its creating event is). `None`
/// when no marker exists, so the un-restored fast path filters nothing.
/// Closes the discovered gap where a re-executed suffix silently adopted
/// the orphaned segment's effect rows instead of re-offering the rules
/// (the visibility half; branch-distinct keys are the dedup half).
#[cfg(feature = "native")]
fn live_event_ids_on(
    connection: &Connection,
    instance_id: &str,
) -> StoreResult<Option<std::collections::BTreeSet<String>>> {
    let mut statement = connection.prepare(
        "SELECT event_id, sequence, event_type, payload_json FROM events \
         WHERE instance_id = ?1 ORDER BY sequence",
    )?;
    let rows = statement
        .query_map([instance_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?
        .collect::<result::Result<Vec<_>, _>>()?;
    let mut saw_marker = false;
    let mut live: Vec<(String, i64)> = Vec::new();
    for (event_id, sequence, event_type, payload_json) in rows {
        if event_type == "context.restored" {
            saw_marker = true;
            if let Some(target) = restore_marker_target(&payload_json) {
                live.retain(|(_, seq)| *seq <= target);
            }
        }
        live.push((event_id, sequence));
    }
    if !saw_marker {
        return Ok(None);
    }
    Ok(Some(
        live.into_iter().map(|(event_id, _)| event_id).collect(),
    ))
}

#[cfg(feature = "native")]
fn restore_marker_target(payload_json: &str) -> Option<i64> {
    serde_json::from_str::<Value>(payload_json)
        .ok()?
        .get("restored_to_sequence")
        .and_then(Value::as_i64)
}

#[cfg(feature = "native")]
fn append_event_on(connection: &Connection, event: NewEvent<'_>) -> StoreResult<StoredEvent> {
    connection
        .query_row(
            r#"
            INSERT INTO events (
                event_id,
                instance_id,
                sequence,
                event_type,
                payload_json,
                occurred_at,
                source,
                causation_id,
                correlation_id,
                idempotency_key,
                format_version
            )
            VALUES (
                'evt_' || lower(hex(randomblob(16))),
                ?1,
                (SELECT COALESCE(MAX(sequence), 0) + 1 FROM events WHERE instance_id = ?1),
                ?2,
                ?3,
                CURRENT_TIMESTAMP,
                ?4,
                ?5,
                ?6,
                ?7,
                ?8
            )
            RETURNING event_id, sequence
            "#,
            params![
                event.instance_id,
                event.event_type,
                event.payload_json,
                event.source,
                event.causation_id,
                event.correlation_id,
                event.idempotency_key,
                // DR-0054 Phase B: stamp the writer's event format so a future
                // reader can tell a row it must not misparse. Constant within a
                // build, so replay re-derivation stays byte-identical.
                SUPPORTED_EVENT_FORMAT_VERSION,
            ],
            |row| {
                Ok(StoredEvent {
                    event_id: row.get(0)?,
                    sequence: row.get(1)?,
                })
            },
        )
        .map_err(|error| {
            // Name the colliding event in the error: a UNIQUE hit on the
            // idempotency key is otherwise undebuggable from the generic
            // "internal store error" the CLI wraps around it.
            if let rusqlite::Error::SqliteFailure(f, _) = &error {
                if f.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE {
                    return StoreError::Conflict(format!(
                        "duplicate event idempotency key for `{}` (key {:?}): a second \
                         distinct commit produced an already-used key",
                        event.event_type, event.idempotency_key
                    ));
                }
            }
            error.into()
        })
}

/// `append_event_on`, tolerant of an idempotency-key replay: re-appending an
/// event that already exists (same instance, same idempotency key) returns the
/// stored row instead of a UNIQUE-constraint error. For observability events
/// that legitimately recur — a capacity block re-observed for the same
/// (effect, run) on a later worker pass is the same durable statement, not a
/// second one.
#[cfg(feature = "native")]
fn append_event_idempotent_on(
    connection: &Connection,
    event: NewEvent<'_>,
) -> StoreResult<StoredEvent> {
    if let Some(key) = event.idempotency_key {
        if let Some(existing) = connection
            .query_row(
                "SELECT event_id, sequence FROM events WHERE instance_id = ?1 AND idempotency_key = ?2",
                params![event.instance_id, key],
                |row| {
                    Ok(StoredEvent {
                        event_id: row.get(0)?,
                        sequence: row.get(1)?,
                    })
                },
            )
            .optional()?
        {
            return Ok(existing);
        }
    }
    append_event_on(connection, event)
}

#[cfg(feature = "native")]
/// Facts are set-like by (instance, name, key), and the record key is
/// content-derived (`record_fact_key`). A conflicting insert is either a
/// byte-identical fact already ACTIVE in the projection — a harmless no-op
/// re-assertion — or a CONSUMED row being re-recorded, which is a fresh
/// admission (DR-0044): the row revives, taking the new admission's
/// fact_id/source_event_id so the committing event and the live row agree.
fn insert_fact(
    connection: &Connection,
    instance_id: &str,
    rule: &str,
    event_id: &str,
    program_version_id: Option<&str>,
    revision_epoch: i64,
    fact: &NewFact<'_>,
) -> StoreResult<()> {
    if let Some(source_span_json) = fact.source_span_json {
        serde_json::from_str::<Value>(source_span_json)?;
    }
    connection.execute(
        r#"
        INSERT INTO facts (
            fact_id,
            instance_id,
            program_version_id,
            revision_epoch,
            name,
            key,
            value_json,
            source_event_id,
            source_rule,
            schema_id,
            provenance_class,
            correlation_id,
            source_span_json
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
        ON CONFLICT(instance_id, name, key) DO UPDATE SET
            consumed_at = NULL,
            fact_id = excluded.fact_id,
            value_json = excluded.value_json,
            source_event_id = excluded.source_event_id,
            source_rule = excluded.source_rule,
            program_version_id = excluded.program_version_id,
            revision_epoch = excluded.revision_epoch,
            updated_at = CURRENT_TIMESTAMP
        WHERE facts.consumed_at IS NOT NULL
        "#,
        params![
            fact.fact_id,
            instance_id,
            program_version_id,
            revision_epoch,
            fact.name,
            fact.key,
            fact.value_json,
            event_id,
            rule,
            fact.schema_id,
            fact.provenance_class,
            fact.correlation_id,
            fact.source_span_json,
        ],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn consume_facts(connection: &Connection, instance_id: &str, fact_ids: &[&str]) -> StoreResult<()> {
    for fact_id in fact_ids {
        let changed = connection.execute(
            r#"
            UPDATE facts
            SET consumed_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1
              AND fact_id = ?2
              AND consumed_at IS NULL
            "#,
            params![instance_id, fact_id],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(format!(
                "fact `{fact_id}` is not active and cannot be consumed"
            )));
        }
    }
    Ok(())
}

#[cfg(feature = "native")]
fn insert_effect(
    connection: &Connection,
    instance_id: &str,
    rule: &str,
    event_id: &str,
    program_version_id: Option<&str>,
    revision_epoch: i64,
    effect: &NewEffect<'_>,
) -> StoreResult<()> {
    connection.execute(
        r#"
        INSERT INTO effects (
            effect_id,
            instance_id,
            kind,
            target,
            input_json,
            status,
            created_by_rule,
            created_by_event_id,
            program_version_id,
            revision_epoch,
            correlation_id,
            idempotency_key,
            required_capabilities,
            profile,
            timeout_seconds
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
        "#,
        params![
            effect.effect_id,
            instance_id,
            effect.kind,
            effect.target,
            effect.input_json,
            effect.status,
            rule,
            event_id,
            program_version_id,
            revision_epoch,
            effect.correlation_id,
            effect.idempotency_key,
            effect.required_capabilities_json,
            effect.profile,
            effect.timeout_seconds,
        ],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn insert_effect_dependency(
    connection: &Connection,
    instance_id: &str,
    rule: &str,
    dependency: &NewEffectDependency<'_>,
) -> StoreResult<()> {
    connection.execute(
        r#"
        INSERT INTO effect_dependencies (
            dependency_id,
            instance_id,
            upstream_effect_id,
            downstream_effect_id,
            predicate,
            created_by_rule
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
        params![
            dependency.dependency_id,
            instance_id,
            dependency.upstream_effect_id,
            dependency.downstream_effect_id,
            dependency.predicate,
            rule,
        ],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn insert_evidence_on(
    connection: &Connection,
    evidence: EvidenceRecord<'_>,
) -> StoreResult<String> {
    serde_json::from_str::<Value>(evidence.metadata_json)?;
    let evidence_id = connection.query_row(
        r#"
        INSERT INTO evidence (
            evidence_id,
            instance_id,
            kind,
            subject_type,
            subject_id,
            causation_id,
            correlation_id,
            summary,
            metadata_json
        )
        VALUES (
            'evd_' || lower(hex(randomblob(16))),
            ?1,
            ?2,
            ?3,
            ?4,
            ?5,
            ?6,
            ?7,
            ?8
        )
        RETURNING evidence_id
        "#,
        params![
            evidence.instance_id,
            evidence.kind,
            evidence.subject_type,
            evidence.subject_id,
            evidence.causation_id,
            evidence.correlation_id,
            evidence.summary,
            evidence.metadata_json,
        ],
        |row| row.get::<_, String>(0),
    )?;
    insert_evidence_link_on(
        connection,
        EvidenceLink {
            evidence_id: &evidence_id,
            instance_id: evidence.instance_id,
            target_type: evidence.subject_type,
            target_id: evidence.subject_id,
            relation: "subject",
        },
    )?;
    if let Some(causation_id) = evidence.causation_id {
        insert_evidence_link_on(
            connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "causation",
                target_id: causation_id,
                relation: "caused_by",
            },
        )?;
    }
    if let Some(correlation_id) = evidence.correlation_id {
        insert_evidence_link_on(
            connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: evidence.instance_id,
                target_type: "correlation",
                target_id: correlation_id,
                relation: "correlates_with",
            },
        )?;
    }
    Ok(evidence_id)
}

#[cfg(feature = "native")]
fn insert_evidence_link_on(connection: &Connection, link: EvidenceLink<'_>) -> StoreResult<()> {
    connection.execute(
        r#"
        INSERT INTO evidence_links (
            link_id,
            evidence_id,
            instance_id,
            target_type,
            target_id,
            relation
        )
        VALUES (
            'evl_' || lower(hex(randomblob(16))),
            ?1,
            ?2,
            ?3,
            ?4,
            ?5
        )
        ON CONFLICT(evidence_id, target_type, target_id, relation) DO NOTHING
        "#,
        params![
            link.evidence_id,
            link.instance_id,
            link.target_type,
            link.target_id,
            link.relation,
        ],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn insert_diagnostic_on(
    connection: &Connection,
    diagnostic: DiagnosticRecord<'_>,
) -> StoreResult<String> {
    if let Some(source_span_json) = diagnostic.source_span_json {
        serde_json::from_str::<Value>(source_span_json)?;
    }
    parse_json_array(diagnostic.evidence_ids_json)?;
    parse_json_array(diagnostic.artifact_ids_json)?;

    if let Some(existing_id) = existing_diagnostic_id_on(connection, &diagnostic)? {
        return Ok(existing_id);
    }

    connection
        .query_row(
            r#"
            INSERT INTO diagnostics (
                diagnostic_id,
                instance_id,
                program_id,
                program_version_id,
                severity,
                code,
                message,
                source_span_json,
                subject_type,
                subject_id,
                event_id,
                effect_id,
                run_id,
                assertion_id,
                evidence_ids_json,
                artifact_ids_json,
                causation_id,
                correlation_id,
                idempotency_key
            )
            VALUES (
                'dia_' || lower(hex(randomblob(16))),
                ?1,
                ?2,
                ?3,
                ?4,
                ?5,
                ?6,
                ?7,
                ?8,
                ?9,
                ?10,
                ?11,
                ?12,
                ?13,
                ?14,
                ?15,
                ?16,
                ?17,
                ?18
            )
            RETURNING diagnostic_id
            "#,
            params![
                diagnostic.instance_id,
                diagnostic.program_id,
                diagnostic.program_version_id,
                diagnostic.severity.as_str(),
                diagnostic.code,
                diagnostic.message,
                diagnostic.source_span_json,
                diagnostic.subject_type,
                diagnostic.subject_id,
                diagnostic.event_id,
                diagnostic.effect_id,
                diagnostic.run_id,
                diagnostic.assertion_id,
                diagnostic.evidence_ids_json,
                diagnostic.artifact_ids_json,
                diagnostic.causation_id,
                diagnostic.correlation_id,
                diagnostic.idempotency_key,
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn optional_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}

#[cfg(feature = "native")]
fn existing_diagnostic_id_on(
    connection: &Connection,
    diagnostic: &DiagnosticRecord<'_>,
) -> StoreResult<Option<String>> {
    let Some(idempotency_key) = diagnostic.idempotency_key else {
        return Ok(None);
    };
    if let Some(instance_id) = diagnostic.instance_id {
        return connection
            .query_row(
                r#"
                SELECT diagnostic_id
                FROM diagnostics
                WHERE instance_id = ?1 AND idempotency_key = ?2
                "#,
                params![instance_id, idempotency_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into);
    }
    if let Some(program_version_id) = diagnostic.program_version_id {
        return connection
            .query_row(
                r#"
                SELECT diagnostic_id
                FROM diagnostics
                WHERE instance_id IS NULL
                  AND program_version_id = ?1
                  AND idempotency_key = ?2
                "#,
                params![program_version_id, idempotency_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into);
    }
    if let Some(program_id) = diagnostic.program_id {
        return connection
            .query_row(
                r#"
                SELECT diagnostic_id
                FROM diagnostics
                WHERE instance_id IS NULL
                  AND program_id = ?1
                  AND idempotency_key = ?2
                "#,
                params![program_id, idempotency_key],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into);
    }
    Ok(None)
}

#[cfg(feature = "native")]
fn parse_json_array(json: &str) -> StoreResult<()> {
    let value = serde_json::from_str::<Value>(json)?;
    if value.is_array() {
        Ok(())
    } else {
        Err(StoreError::Conflict("expected JSON array".to_owned()))
    }
}

#[cfg(feature = "native")]
fn satisfy_dependencies_on(connection: &Connection, instance_id: &str) -> StoreResult<usize> {
    connection
        .execute(
            r#"
            UPDATE effects
            SET status = 'queued',
                updated_at = CURRENT_TIMESTAMP
            WHERE instance_id = ?1
              AND status = 'blocked_by_dependency'
              AND effect_id IN (
                  SELECT candidate.effect_id
                  FROM effects AS candidate
                  WHERE candidate.instance_id = ?1
                    AND NOT EXISTS (
                        SELECT 1
                        FROM effect_dependencies AS dependency
                        JOIN effects AS upstream
                          ON upstream.effect_id = dependency.upstream_effect_id
                         AND upstream.instance_id = dependency.instance_id
                        WHERE dependency.instance_id = candidate.instance_id
                          AND dependency.downstream_effect_id = candidate.effect_id
                          AND NOT (
                              (dependency.predicate = 'succeeds' AND upstream.status = 'completed')
                              OR (dependency.predicate = 'fails' AND upstream.status IN ('failed', 'timed_out'))
                              OR (dependency.predicate = 'timed_out' AND upstream.status = 'timed_out')
                              OR (dependency.predicate = 'cancelled' AND upstream.status = 'cancelled')
                              OR (dependency.predicate = 'completes' AND upstream.status IN ('completed', 'failed', 'timed_out', 'cancelled'))
                          )
                    )
              )
            "#,
            [instance_id],
        )
        .map_err(Into::into)
}

#[cfg(feature = "native")]
struct PolicyBlock {
    status: &'static str,
    reason: String,
}

#[cfg(feature = "native")]
struct PolicyEffect {
    kind: String,
    target: Option<String>,
    status: String,
    required_capabilities_json: String,
    profile: Option<String>,
    program_id: String,
    declared_profiles_json: String,
}

#[cfg(feature = "native")]
fn policy_block_on(
    connection: &Connection,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<Option<PolicyBlock>> {
    let Some(effect) = connection
        .query_row(
            r#"
            SELECT
                effects.kind,
                effects.target,
                effects.status,
                effects.required_capabilities,
                effects.profile,
                COALESCE(effect_versions.program_id, instances.program_id),
                COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles)
            FROM effects
            JOIN instances ON instances.instance_id = effects.instance_id
            JOIN program_versions AS active_versions
              ON active_versions.version_id = instances.version_id
            LEFT JOIN program_versions AS effect_versions
              ON effect_versions.version_id = effects.program_version_id
            WHERE effects.instance_id = ?1
              AND effects.effect_id = ?2
            "#,
            params![instance_id, effect_id],
            |row| {
                Ok(PolicyEffect {
                    kind: row.get(0)?,
                    target: row.get(1)?,
                    status: row.get(2)?,
                    required_capabilities_json: row.get(3)?,
                    profile: row.get(4)?,
                    program_id: row.get(5)?,
                    declared_profiles_json: row.get(6)?,
                })
            },
        )
        .optional()?
    else {
        return Ok(None);
    };

    // A persisted policy block (`blocked_by_capability` / `blocked_by_profile`)
    // is re-evaluated here every pass: this is what makes it RECOVERABLE — the
    // moment the missing profile/capability is registered, the gate returns
    // None and the effect is claimable again.
    if !matches!(
        effect.status.as_str(),
        "queued"
            | "blocked_by_dependency"
            | "blocked_by_capacity"
            | "blocked_by_capability"
            | "blocked_by_profile"
    ) {
        return Ok(None);
    }

    if let Some(block) = agent_target_policy_block(&effect)? {
        return Ok(Some(block));
    }

    // Timers are resolved by the runtime itself on worker passes: no provider,
    // capability, or profile applies.
    //
    // Coordination kinds (`lease.*` / `ledger.*` / `counter.*`, std.coord
    // slice 4), file kinds (`file.*`, std.files slice F2), tracker kinds
    // (`tracker.*`, std.tracker slice T4), and the ingress kind
    // (`signal.emit`, std.ingress slice I2b) are NOT exempt here: the
    // embedded std.coord / std.files / std.tracker / std.ingress manifests
    // seed their capability/provider/binding rows at store init, so the
    // admission gate is REAL for them — an unbound kind blocks as
    // blocked_by_capability. INTENTIONAL DIVERGENCE from the DO mirror
    // (host-do/do_store.rs `do_policy_block_on`), which keeps the exemptions
    // until the DO tracker's package-registration row seeds the same rows in
    // the DO bootstrap (spec/std-coord.md / spec/std-files.md /
    // spec/std-tracker.md / spec/std-ingress.md "Deferred with cause").
    if effect.kind == "timer.wait" {
        return Ok(None);
    }

    if effect.kind == "exec.command" {
        // Script hard-off Layer 2 (spec/std-script.md "Hard-off semantics"):
        // EVERY exec.command effect requires a bound `script.*` capability.
        // The capability form carries its `script.<name>` requirement from
        // lowering; the raw form carries none and is held to `script.raw`.
        // The requirement is derived HERE, at the admission gate, so a forged
        // effect row that strips its requirements gains nothing — and the
        // rows only exist when both seeding keys turned (the program imports
        // std.script AND the operator-plane authority exists).
        let mut capabilities = explicit_required_capabilities(&effect)?;
        if !capabilities
            .iter()
            .any(|capability| capability.starts_with("script."))
        {
            capabilities.push("script.raw".to_owned());
        }
        let block = policy_block_for_capabilities(connection, &effect, &capabilities)?;
        // A script-capability block IS the "scripts are disabled" state:
        // surface the hard-off diagnostic id with the blocked reason, before
        // any provider run.
        return Ok(block.map(|block| match block.status {
            "blocked_by_capability" => PolicyBlock {
                status: block.status,
                reason: format!("security.script_disabled: {}", block.reason),
            },
            _ => block,
        }));
    }

    if effect.kind == "capability.call" {
        let mut capabilities = explicit_required_capabilities(&effect)?;
        if capabilities.is_empty() {
            match effect.target.as_deref().filter(|target| !target.is_empty()) {
                Some(target) => capabilities.push(target.to_owned()),
                None => {
                    return Ok(Some(PolicyBlock {
                        status: "blocked_by_capability",
                        reason: "capability.call effect has no target capability requirement"
                            .to_owned(),
                    }))
                }
            }
        }
        return policy_block_for_capabilities(connection, &effect, &capabilities);
    }

    let capabilities = required_capabilities(&effect)?;
    if !effect_provider_exists(connection, &effect.kind)? {
        return Ok(Some(PolicyBlock {
            status: "blocked_by_capability",
            reason: format!("no effect provider is registered for `{}`", effect.kind),
        }));
    }

    policy_block_for_capabilities(connection, &effect, &capabilities)
}

/// Persist a policy block observed by the claim-list filter, so the record
/// tells the truth: the effect flips to the block's status with its reason and
/// an `effect.blocked` event is appended — idempotent per (effect, reason), so
/// repeated passes with an unchanged verdict write nothing. Recovery is
/// automatic: `policy_block_on` re-evaluates persisted blocks each pass and
/// the effect rejoins the claimable set the moment the gate clears.
#[cfg(feature = "native")]
fn persist_policy_block_on(
    connection: &Connection,
    instance_id: &str,
    effect_id: &str,
    block: &PolicyBlock,
) -> StoreResult<()> {
    let changed = connection.execute(
        r#"
        UPDATE effects
        SET status = ?1,
            policy_block_reason = ?2,
            updated_at = CURRENT_TIMESTAMP
        WHERE instance_id = ?3
          AND effect_id = ?4
          AND (status != ?1 OR policy_block_reason IS NOT ?2)
          AND status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')
        "#,
        params![block.status, block.reason, instance_id, effect_id],
    )?;
    if changed == 1 {
        let payload = json!({
            "effect_id": effect_id,
            "status": block.status,
            "reason": block.reason,
        })
        .to_string();
        append_event_idempotent_on(
            connection,
            NewEvent {
                instance_id,
                event_type: "effect.blocked",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(effect_id),
                correlation_id: None,
                idempotency_key: Some(&format!("policy-block:{effect_id}:{}", block.reason)),
            },
        )?;
    }
    Ok(())
}

#[cfg(feature = "native")]
fn policy_block_for_capabilities(
    connection: &Connection,
    effect: &PolicyEffect,
    capabilities: &[String],
) -> StoreResult<Option<PolicyBlock>> {
    for capability in capabilities {
        if !capability_schema_exists(connection, capability)? {
            return Ok(Some(PolicyBlock {
                status: "blocked_by_capability",
                reason: format!("capability `{capability}` is not registered"),
            }));
        }
        if !capability_bound(connection, &effect.program_id, capability)? {
            return Ok(Some(PolicyBlock {
                status: "blocked_by_capability",
                reason: format!(
                    "capability `{capability}` is not bound for program {}",
                    effect.program_id
                ),
            }));
        }
    }

    if let Some(profile) = &effect.profile {
        let Some((enforcement_mode, allowed_capabilities)) = profile_policy(connection, profile)?
        else {
            return Ok(Some(PolicyBlock {
                status: "blocked_by_profile",
                reason: format!("profile `{profile}` is not registered"),
            }));
        };
        if enforcement_mode != "audit" {
            for capability in capabilities {
                if !capability_allowed(&allowed_capabilities, capability) {
                    return Ok(Some(PolicyBlock {
                        status: "blocked_by_profile",
                        reason: format!(
                            "profile `{profile}` does not allow capability `{capability}`"
                        ),
                    }));
                }
            }
        }
    }

    Ok(None)
}

#[cfg(feature = "native")]
fn agent_target_policy_block(effect: &PolicyEffect) -> StoreResult<Option<PolicyBlock>> {
    if effect.kind != "agent.tell" {
        return Ok(None);
    }
    let Some(target) = effect.target.as_deref() else {
        return Ok(None);
    };
    if !declared_agents_present(&effect.declared_profiles_json)? {
        return Ok(None);
    }
    let Some(declared_profile) = declared_agent_profile(&effect.declared_profiles_json, target)?
    else {
        return Ok(Some(PolicyBlock {
            status: "blocked_by_profile",
            reason: format!("agent `{target}` is not declared by the program"),
        }));
    };
    match (effect.profile.as_deref(), declared_profile.as_deref()) {
        (Some(actual), Some(expected)) if actual != expected => Ok(Some(PolicyBlock {
            status: "blocked_by_profile",
            reason: format!(
                "agent `{target}` uses profile `{actual}`, expected declared profile `{expected}`"
            ),
        })),
        (None, Some(expected)) => Ok(Some(PolicyBlock {
            status: "blocked_by_profile",
            reason: format!("agent `{target}` requires declared profile `{expected}`"),
        })),
        _ => {
            let declared_capabilities =
                declared_agent_capabilities(&effect.declared_profiles_json, target)?;
            let required_capabilities = explicit_required_capabilities(effect)?;
            for capability in required_capabilities {
                if !declared_capabilities.contains(&capability) {
                    return Ok(Some(PolicyBlock {
                        status: "blocked_by_capability",
                        reason: format!(
                            "agent `{target}` does not declare required capability `{capability}`"
                        ),
                    }));
                }
            }
            Ok(None)
        }
    }
}

#[cfg(feature = "native")]
fn capacity_block_on(
    connection: &Connection,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<Option<String>> {
    let Some((kind, target, declared_profiles)) = connection
        .query_row(
            r#"
            SELECT effects.kind,
                   effects.target,
                   COALESCE(effect_versions.declared_profiles, active_versions.declared_profiles)
            FROM effects
            JOIN instances ON instances.instance_id = effects.instance_id
            JOIN program_versions AS active_versions
              ON active_versions.version_id = instances.version_id
            LEFT JOIN program_versions AS effect_versions
              ON effect_versions.version_id = effects.program_version_id
            WHERE effects.instance_id = ?1
              AND effects.effect_id = ?2
            "#,
            params![instance_id, effect_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()?
    else {
        return Ok(None);
    };
    if kind != "agent.tell" {
        return Ok(None);
    }
    let Some(agent) = target else {
        return Ok(None);
    };
    let Some(capacity) = declared_agent_capacity(&declared_profiles, &agent)? else {
        return Ok(None);
    };
    let running = connection.query_row(
        r#"
        SELECT COUNT(*)
        FROM effects
        WHERE instance_id = ?1
          AND kind = 'agent.tell'
          AND target = ?2
          AND status = 'running'
        "#,
        params![instance_id, agent],
        |row| row.get::<_, i64>(0),
    )?;
    if running >= capacity {
        Ok(Some(format!(
            "agent `{agent}` capacity exhausted ({running}/{capacity} running)"
        )))
    } else {
        Ok(None)
    }
}

#[cfg(feature = "native")]
fn declared_agent_profile(
    declared_profiles_json: &str,
    agent: &str,
) -> StoreResult<Option<Option<String>>> {
    let parsed = serde_json::from_str::<Value>(declared_profiles_json)?;
    Ok(agent_profile_in_value(&parsed, agent))
}

#[cfg(feature = "native")]
fn declared_agents_present(declared_profiles_json: &str) -> StoreResult<bool> {
    let parsed = serde_json::from_str::<Value>(declared_profiles_json)?;
    Ok(match &parsed {
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => {
            object
                .get("agents")
                .and_then(Value::as_array)
                .is_some_and(|agents| !agents.is_empty())
                || object.iter().any(|(key, value)| {
                    if matches!(key.as_str(), "harnesses" | "workflow" | "schemas") {
                        return false;
                    }
                    value.as_object().is_some_and(|entry| {
                        entry.contains_key("profile")
                            || entry.contains_key("capacity")
                            || entry.contains_key("capabilities")
                            || entry.contains_key("harness")
                            || entry.contains_key("provider")
                    })
                })
        }
        _ => false,
    })
}

#[cfg(feature = "native")]
fn agent_profile_in_value(value: &Value, agent: &str) -> Option<Option<String>> {
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| agent_profile_in_value(item, agent)),
        Value::Object(object) => {
            if let Some(entry) = object.get(agent) {
                return Some(
                    entry
                        .get("profile")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                );
            }
            if let Some(profile) = object
                .get("agents")
                .and_then(|agents| agent_profile_in_value(agents, agent))
            {
                return Some(profile);
            }
            let declared_agent = object
                .get("name")
                .or_else(|| object.get("agent"))
                .or_else(|| object.get("agent_name"))
                .or_else(|| object.get("target"))
                .and_then(Value::as_str);
            if declared_agent == Some(agent) {
                Some(
                    object
                        .get("profile")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(feature = "native")]
fn declared_agent_capacity(declared_profiles_json: &str, agent: &str) -> StoreResult<Option<i64>> {
    let parsed = serde_json::from_str::<Value>(declared_profiles_json)?;
    Ok(agent_capacity_in_value(&parsed, agent))
}

#[cfg(feature = "native")]
fn declared_agent_capabilities(
    declared_profiles_json: &str,
    agent: &str,
) -> StoreResult<BTreeSet<String>> {
    let parsed = serde_json::from_str::<Value>(declared_profiles_json)?;
    Ok(agent_capabilities_in_value(&parsed, agent).unwrap_or_default())
}

#[cfg(feature = "native")]
fn agent_capabilities_in_value(value: &Value, agent: &str) -> Option<BTreeSet<String>> {
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| agent_capabilities_in_value(item, agent)),
        Value::Object(object) => {
            if let Some(entry) = object.get(agent) {
                return Some(capabilities_value(entry.get("capabilities")?));
            }
            if let Some(capabilities) = object
                .get("agents")
                .and_then(|agents| agent_capabilities_in_value(agents, agent))
            {
                return Some(capabilities);
            }
            let declared_agent = object
                .get("name")
                .or_else(|| object.get("agent"))
                .or_else(|| object.get("agent_name"))
                .or_else(|| object.get("target"))
                .and_then(Value::as_str);
            if declared_agent == Some(agent) {
                object.get("capabilities").map(capabilities_value)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(feature = "native")]
fn capabilities_value(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(feature = "native")]
fn agent_capacity_in_value(value: &Value, agent: &str) -> Option<i64> {
    match value {
        Value::Array(items) => items
            .iter()
            .find_map(|item| agent_capacity_in_value(item, agent)),
        Value::Object(object) => {
            if let Some(capacity) = object.get(agent).and_then(capacity_value) {
                return Some(capacity);
            }
            if let Some(capacity) = object
                .get(agent)
                .and_then(|entry| entry.get("capacity"))
                .and_then(capacity_value)
            {
                return Some(capacity);
            }
            if let Some(capacity) = object
                .get("agents")
                .and_then(|agents| agent_capacity_in_value(agents, agent))
            {
                return Some(capacity);
            }
            let declared_agent = object
                .get("name")
                .or_else(|| object.get("agent"))
                .or_else(|| object.get("agent_name"))
                .or_else(|| object.get("target"))
                .and_then(Value::as_str);
            if declared_agent == Some(agent) {
                object.get("capacity").and_then(capacity_value)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(feature = "native")]
fn capacity_value(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        value
            .as_u64()
            .and_then(|capacity| i64::try_from(capacity).ok())
    })
}

#[cfg(feature = "native")]
fn required_capabilities(effect: &PolicyEffect) -> StoreResult<Vec<String>> {
    let mut capabilities = explicit_required_capabilities(effect)?;
    if capabilities.is_empty() {
        capabilities.push(effect.kind.clone());
    }
    capabilities.sort();
    capabilities.dedup();
    Ok(capabilities)
}

#[cfg(feature = "native")]
fn explicit_required_capabilities(effect: &PolicyEffect) -> StoreResult<Vec<String>> {
    let parsed = serde_json::from_str::<Value>(&effect.required_capabilities_json)?;
    let mut capabilities = parsed
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    capabilities.sort();
    capabilities.dedup();
    Ok(capabilities)
}

#[cfg(feature = "native")]
fn effect_provider_exists(connection: &Connection, effect_kind: &str) -> StoreResult<bool> {
    connection
        .query_row(
            "SELECT 1 FROM effect_providers WHERE effect_kind = ?1 LIMIT 1",
            [effect_kind],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn capability_schema_exists(connection: &Connection, capability: &str) -> StoreResult<bool> {
    connection
        .query_row(
            "SELECT 1 FROM capability_schemas WHERE capability = ?1 LIMIT 1",
            [capability],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn capability_bound(
    connection: &Connection,
    program_id: &str,
    capability: &str,
) -> StoreResult<bool> {
    connection
        .query_row(
            r#"
            SELECT 1
            FROM capability_bindings
            WHERE capability = ?1
              AND (program_id = ?2 OR program_id IS NULL)
            LIMIT 1
            "#,
            params![capability, program_id],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(Into::into)
}

/// The provider name bound to `capability`, mirroring `capability_bound`'s
/// program-scoped-wins-over-global scoping (a program-scoped row beats a global
/// `NULL` one). `Ok(None)` when no binding row exists or its `provider` column is
/// NULL. This reads the `capability_bindings.provider` column that `capability_bound`
/// only tested for existence — the registry-driven `CapabilityProvider` selection
/// seam (S5) that lands with the first real per-capability provider.
#[cfg(feature = "native")]
fn capability_bound_provider(
    connection: &Connection,
    program_id: &str,
    capability: &str,
) -> StoreResult<Option<String>> {
    connection
        .query_row(
            r#"
            SELECT provider
            FROM capability_bindings
            WHERE capability = ?1
              AND (program_id = ?2 OR program_id IS NULL)
            ORDER BY (program_id IS NULL) ASC
            LIMIT 1
            "#,
            params![capability, program_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map(Option::flatten)
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn profile_policy(
    connection: &Connection,
    profile: &str,
) -> StoreResult<Option<(String, Vec<String>)>> {
    connection
        .query_row(
            "SELECT enforcement_mode, allowed_capabilities FROM profiles WHERE name = ?1",
            [profile],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .map(|(mode, allowed_json)| {
            let allowed = serde_json::from_str::<Value>(&allowed_json)?
                .as_array()
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            Ok((mode, allowed))
        })
        .transpose()
}

#[cfg(feature = "native")]
fn instance_status_on(connection: &Connection, instance_id: &str) -> StoreResult<Option<String>> {
    connection
        .query_row(
            "SELECT status FROM instances WHERE instance_id = ?1",
            [instance_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn active_revision_on(
    connection: &Connection,
    instance_id: &str,
) -> StoreResult<(Option<String>, i64)> {
    connection
        .query_row(
            "SELECT version_id, revision_epoch FROM instances WHERE instance_id = ?1",
            [instance_id],
            |row| Ok((Some(row.get::<_, String>(0)?), row.get::<_, i64>(1)?)),
        )
        .optional()
        .map(|row| row.unwrap_or((None, 0)))
        .map_err(Into::into)
}

#[cfg(feature = "native")]
struct RevisionInstanceContext {
    program_id: String,
    program_name: String,
    active_version_id: String,
    status: String,
}

#[cfg(feature = "native")]
fn revision_instance_context_on(
    connection: &Connection,
    instance_id: &str,
) -> StoreResult<RevisionInstanceContext> {
    connection
        .query_row(
            r#"
            SELECT instances.program_id, programs.name, instances.version_id, instances.status
            FROM instances
            JOIN programs ON programs.program_id = instances.program_id
            WHERE instances.instance_id = ?1
            "#,
            [instance_id],
            |row| {
                Ok(RevisionInstanceContext {
                    program_id: row.get(0)?,
                    program_name: row.get(1)?,
                    active_version_id: row.get(2)?,
                    status: row.get(3)?,
                })
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::Conflict("instance does not exist".to_owned()))
}

#[cfg(feature = "native")]
fn add_instance_revision_diagnostics(
    context: &RevisionInstanceContext,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) {
    if matches!(
        context.status.as_str(),
        "completed" | "failed" | "cancelled"
    ) {
        diagnostics.push(revision_compatibility_diagnostic(
            "revision.terminal_instance",
            format!(
                "instance is {}; revisions require a non-terminal instance",
                context.status
            ),
            None,
        ));
    }
}

#[cfg(feature = "native")]
fn program_version_analysis_on(
    connection: &Connection,
    version_id: &str,
) -> StoreResult<(String, Value)> {
    let (program_id, analysis_summary_json) = connection
        .query_row(
            r#"
            SELECT program_id, analysis_summary
            FROM program_versions
            WHERE version_id = ?1
            "#,
            [version_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?
        .ok_or_else(|| StoreError::Conflict("program version does not exist".to_owned()))?;
    let analysis_summary = serde_json::from_str::<Value>(&analysis_summary_json)?;
    Ok((program_id, analysis_summary))
}

#[cfg(feature = "native")]
fn compare_revision_summaries(
    active: &Value,
    candidate: &Value,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) {
    let active_workflow = active.get("workflow").and_then(Value::as_str);
    let candidate_workflow = candidate.get("workflow").and_then(Value::as_str);
    match (active_workflow, candidate_workflow) {
        (Some(active_workflow), Some(candidate_workflow))
            if active_workflow != candidate_workflow =>
        {
            diagnostics.push(revision_compatibility_diagnostic(
                "revision.root_workflow_changed",
                format!(
                    "candidate root workflow `{candidate_workflow}` does not match active root `{active_workflow}`"
                ),
                Some(candidate_workflow),
            ));
        }
        (None, _) => diagnostics.push(revision_compatibility_diagnostic(
            "revision.active_analysis_missing",
            "active version does not include revision analysis metadata".to_owned(),
            None,
        )),
        (_, None) => diagnostics.push(revision_compatibility_diagnostic(
            "revision.candidate_analysis_missing",
            "candidate version does not include revision analysis metadata".to_owned(),
            None,
        )),
        _ => {}
    }

    compare_contracts("input", true, active, candidate, diagnostics);
    compare_contracts("output", false, active, candidate, diagnostics);
    compare_contracts("failure", false, active, candidate, diagnostics);
}

#[cfg(feature = "native")]
fn compare_contracts(
    kind: &str,
    reject_candidate_additions: bool,
    active: &Value,
    candidate: &Value,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) {
    let active_contracts = contracts_by_name(active, kind);
    let candidate_contracts = contracts_by_name(candidate, kind);
    for (name, active_ty) in &active_contracts {
        match candidate_contracts.get(name) {
            Some(candidate_ty) if candidate_ty.ty == active_ty.ty => {}
            Some(candidate_ty) => diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.contract_changed",
                format!(
                    "{kind} contract `{name}` changed from `{}` to `{}`",
                    active_ty.ty, candidate_ty.ty
                ),
                Some(name.as_str()),
                candidate_ty.source_span_json.clone(),
            )),
            None => diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.contract_removed",
                format!("{kind} contract `{name}` is missing from the candidate version"),
                Some(name.as_str()),
                active_ty.source_span_json.clone(),
            )),
        }
    }
    if reject_candidate_additions {
        for (name, candidate_ty) in candidate_contracts {
            if !active_contracts.contains_key(&name) {
                diagnostics.push(revision_compatibility_diagnostic_with_span(
                    "revision.input_contract_added",
                    format!(
                        "candidate adds input contract `{name}` with type `{}` to an already-started instance",
                        candidate_ty.ty
                    ),
                    Some(name.as_str()),
                    candidate_ty.source_span_json,
                ));
            }
        }
    }
}

#[cfg(feature = "native")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ContractSummary {
    ty: String,
    source_span_json: Option<String>,
}

#[cfg(feature = "native")]
fn contracts_by_name(summary: &Value, kind: &str) -> BTreeMap<String, ContractSummary> {
    summary
        .get("workflow_contracts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|contract| contract.get("kind").and_then(Value::as_str) == Some(kind))
        .filter_map(|contract| {
            Some((
                contract.get("name")?.as_str()?.to_owned(),
                ContractSummary {
                    ty: contract.get("type")?.as_str()?.to_owned(),
                    source_span_json: summary_source_span_json(contract),
                },
            ))
        })
        .collect()
}

#[cfg(feature = "native")]
fn add_active_fact_schema_diagnostics(
    connection: &Connection,
    instance_id: &str,
    active_summary: &Value,
    candidate_summary: &Value,
    diagnostics: &mut Vec<RevisionCompatibilityDiagnostic>,
) -> StoreResult<()> {
    let active_schemas = schemas_by_name(active_summary);
    let candidate_schemas = schemas_by_name(candidate_summary);
    if active_schemas.is_empty() && candidate_schemas.is_empty() {
        return Ok(());
    }

    let mut statement = connection.prepare(
        r#"
        SELECT fact_id, name, schema_id, value_json
        FROM facts
        WHERE instance_id = ?1
          AND consumed_at IS NULL
        ORDER BY fact_id
        "#,
    )?;
    let rows = statement.query_map([instance_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;

    for row in rows {
        let (fact_id, name, schema_id, value_json) = row?;
        let schema_name = fact_schema_name(
            &name,
            schema_id.as_deref(),
            &active_schemas,
            &candidate_schemas,
        );
        let Some(schema_name) = schema_name else {
            continue;
        };
        let Some(candidate_schema) = candidate_schemas.get(schema_name) else {
            let source_span_json = active_schemas
                .get(schema_name)
                .and_then(summary_source_span_json);
            diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.active_fact_schema_removed",
                format!("active fact `{fact_id}` uses schema `{schema_name}` missing from candidate version"),
                Some(schema_name),
                source_span_json,
            ));
            continue;
        };

        let value = serde_json::from_str::<Value>(&value_json)?;
        let mut errors = Vec::new();
        validate_fact_value_against_schema(
            &value,
            candidate_schema,
            &candidate_schemas,
            "$",
            &mut errors,
            0,
        );
        if !errors.is_empty() {
            diagnostics.push(revision_compatibility_diagnostic_with_span(
                "revision.active_fact_incompatible",
                format!(
                    "active fact `{fact_id}` no longer typechecks as `{schema_name}`: {}",
                    errors.join("; ")
                ),
                Some(schema_name),
                summary_source_span_json(candidate_schema),
            ));
        }
    }

    Ok(())
}

#[cfg(feature = "native")]
fn schemas_by_name(summary: &Value) -> BTreeMap<String, Value> {
    summary
        .get("schemas")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|schema| Some((schema.get("name")?.as_str()?.to_owned(), schema.clone())))
        .collect()
}

#[cfg(feature = "native")]
fn summary_source_span_json(summary: &Value) -> Option<String> {
    summary.get("source_span").map(Value::to_string)
}

#[cfg(feature = "native")]
fn fact_schema_name<'a>(
    fact_name: &'a str,
    schema_id: Option<&'a str>,
    active_schemas: &BTreeMap<String, Value>,
    candidate_schemas: &BTreeMap<String, Value>,
) -> Option<&'a str> {
    if let Some(schema_id) = schema_id {
        if active_schemas.contains_key(schema_id) || candidate_schemas.contains_key(schema_id) {
            return Some(schema_id);
        }
    }
    if active_schemas.contains_key(fact_name) || candidate_schemas.contains_key(fact_name) {
        return Some(fact_name);
    }
    None
}

#[cfg(feature = "native")]
fn validate_fact_value_against_schema(
    value: &Value,
    schema: &Value,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        errors.push(format!("{path} exceeded schema recursion limit"));
        return;
    }
    match schema.get("kind").and_then(Value::as_str) {
        Some("class") => validate_value_against_fields(
            value,
            schema.get("fields").and_then(Value::as_array),
            schemas,
            path,
            errors,
            depth,
        ),
        Some("enum") => {
            let variants = schema
                .get("variants")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            match value.as_str() {
                Some(variant) if variants.contains(&variant) => {}
                Some(variant) => errors.push(format!(
                    "{path} has enum variant `{variant}` not declared by candidate"
                )),
                None => errors.push(format!("{path} must be a string enum variant")),
            }
        }
        Some(kind) => errors.push(format!("{path} uses unsupported schema kind `{kind}`")),
        None => errors.push(format!("{path} uses schema without a kind")),
    }
}

#[cfg(feature = "native")]
fn validate_value_against_fields(
    value: &Value,
    fields: Option<&Vec<Value>>,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    let Some(object) = value.as_object() else {
        errors.push(format!("{path} must be an object"));
        return;
    };
    let fields = fields.map(Vec::as_slice).unwrap_or(&[]);
    let declared = fields
        .iter()
        .filter_map(|field| Some((field.get("name")?.as_str()?, field.get("type")?.as_str()?)))
        .collect::<BTreeMap<_, _>>();
    for key in object.keys() {
        if !declared.contains_key(key.as_str()) {
            errors.push(format!("{path}.{key} is not declared by candidate"));
        }
    }
    for (name, signature) in declared {
        let field_path = format!("{path}.{name}");
        match object.get(name) {
            Some(value) => {
                validate_value_against_type_signature(
                    value,
                    signature,
                    schemas,
                    &field_path,
                    errors,
                    depth + 1,
                );
            }
            None if is_optional_signature(signature) => {}
            None => errors.push(format!("{field_path} is required by candidate")),
        }
    }
}

#[cfg(feature = "native")]
fn validate_value_against_type_signature(
    value: &Value,
    signature: &str,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    if depth > 32 {
        errors.push(format!("{path} exceeded schema recursion limit"));
        return;
    }
    match signature {
        "string" | "duration" | "time" | "image" | "audio" | "pdf" | "video" => {
            if !value.is_string() {
                errors.push(format!("{path} must be {signature}"));
            }
        }
        "int" => {
            if value.as_i64().is_none() {
                errors.push(format!("{path} must be int"));
            }
        }
        "float" => {
            if value.as_f64().is_none() {
                errors.push(format!("{path} must be float"));
            }
        }
        "bool" => {
            if !value.is_boolean() {
                errors.push(format!("{path} must be bool"));
            }
        }
        "null" => {
            if !value.is_null() {
                errors.push(format!("{path} must be null"));
            }
        }
        _ => {
            if let Some(expected) = signature_envelope(signature, "literal") {
                let expected = serde_json::from_str::<String>(expected)
                    .unwrap_or_else(|_| expected.to_owned());
                if value.as_str() != Some(expected.as_str()) {
                    errors.push(format!("{path} must be literal {expected:?}"));
                }
            } else if let Some(schema_name) = signature_envelope(signature, "ref") {
                match schemas.get(schema_name) {
                    Some(schema) => validate_fact_value_against_schema(
                        value,
                        schema,
                        schemas,
                        path,
                        errors,
                        depth + 1,
                    ),
                    None => errors.push(format!(
                        "{path} references schema `{schema_name}` missing from candidate"
                    )),
                }
            } else if let Some(inner) = signature_envelope(signature, "optional") {
                if !value.is_null() {
                    validate_value_against_type_signature(
                        value,
                        inner,
                        schemas,
                        path,
                        errors,
                        depth + 1,
                    );
                }
            } else if let Some(inner) = signature_envelope(signature, "array") {
                match value.as_array() {
                    Some(items) => {
                        for (index, item) in items.iter().enumerate() {
                            validate_value_against_type_signature(
                                item,
                                inner,
                                schemas,
                                &format!("{path}[{index}]"),
                                errors,
                                depth + 1,
                            );
                        }
                    }
                    None => errors.push(format!("{path} must be an array")),
                }
            } else if let Some(inner) = signature_envelope(signature, "map") {
                match value.as_object() {
                    Some(map) => {
                        for (key, item) in map {
                            validate_value_against_type_signature(
                                item,
                                inner,
                                schemas,
                                &format!("{path}.{key}"),
                                errors,
                                depth + 1,
                            );
                        }
                    }
                    None => errors.push(format!("{path} must be an object map")),
                }
            } else if let Some(inner) = signature_envelope(signature, "union") {
                let variants = split_top_level(inner, " | ");
                if !variants.iter().any(|variant| {
                    let mut candidate_errors = Vec::new();
                    validate_value_against_type_signature(
                        value,
                        variant,
                        schemas,
                        path,
                        &mut candidate_errors,
                        depth + 1,
                    );
                    candidate_errors.is_empty()
                }) {
                    errors.push(format!(
                        "{path} must match one of: {}",
                        variants.join(" | ")
                    ));
                }
            } else if let Some(inner) = signature_envelope(signature, "object") {
                validate_value_against_object_signature(value, inner, schemas, path, errors, depth);
            } else if let Some(inner) = signature_envelope(signature, "agentref") {
                let agents = split_top_level(inner, " | ");
                match value.as_str() {
                    Some(agent) if agents.iter().any(|candidate| candidate == agent) => {}
                    Some(_) => errors.push(format!(
                        "{path} must name one of these agents: {}",
                        agents.join(", ")
                    )),
                    None => errors.push(format!("{path} must be an agent name string")),
                }
            } else {
                errors.push(format!("{path} uses unsupported type `{signature}`"));
            }
        }
    }
}

#[cfg(feature = "native")]
fn validate_value_against_object_signature(
    value: &Value,
    inner: &str,
    schemas: &BTreeMap<String, Value>,
    path: &str,
    errors: &mut Vec<String>,
    depth: usize,
) {
    let Some(fields) = inner
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
    else {
        errors.push(format!("{path} uses malformed object type"));
        return;
    };
    let fields = split_top_level(fields, ", ")
        .into_iter()
        .filter_map(|field| {
            let (name, signature) = field.split_once(' ')?;
            Some(json!({ "name": name, "type": signature }))
        })
        .collect::<Vec<_>>();
    validate_value_against_fields(value, Some(&fields), schemas, path, errors, depth + 1);
}

#[cfg(feature = "native")]
fn is_optional_signature(signature: &str) -> bool {
    signature_envelope(signature, "optional").is_some()
}

#[cfg(feature = "native")]
fn signature_envelope<'a>(signature: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}<");
    signature
        .strip_prefix(&prefix)
        .and_then(|rest| rest.strip_suffix('>'))
}

#[cfg(feature = "native")]
fn split_top_level(input: &str, separator: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut index = 0usize;
    while index < input.len() {
        let rest = &input[index..];
        if depth == 0 && rest.starts_with(separator) {
            parts.push(input[start..index].trim().to_owned());
            index += separator.len();
            start = index;
            continue;
        }
        if let Some(ch) = rest.chars().next() {
            match ch {
                '<' => depth += 1,
                '>' => depth -= 1,
                _ => {}
            }
            index += ch.len_utf8();
        } else {
            break;
        }
    }
    parts.push(input[start..].trim().to_owned());
    parts.retain(|part| !part.is_empty());
    parts
}

#[cfg(feature = "native")]
fn revision_compatibility_diagnostic(
    code: &str,
    message: String,
    subject: Option<&str>,
) -> RevisionCompatibilityDiagnostic {
    revision_compatibility_diagnostic_with_span(code, message, subject, None)
}

#[cfg(feature = "native")]
fn revision_compatibility_diagnostic_with_span(
    code: &str,
    message: String,
    subject: Option<&str>,
    source_span_json: Option<String>,
) -> RevisionCompatibilityDiagnostic {
    RevisionCompatibilityDiagnostic {
        code: code.to_owned(),
        message,
        subject: subject.map(str::to_owned),
        source_span_json,
    }
}

#[cfg(feature = "native")]
fn normalize_cancellation_policy(policy: &str) -> StoreResult<&'static str> {
    match policy {
        "keep" => Ok("keep"),
        "cancel_queued" | "cancel queued" | "queued" => Ok("cancel_queued"),
        "request_running" | "request running" | "running" => Ok("request_running"),
        _ => Err(StoreError::Conflict(format!(
            "unsupported revision cancellation policy `{policy}`"
        ))),
    }
}

#[cfg(feature = "native")]
fn random_id_on(connection: &Connection, prefix: &str) -> StoreResult<String> {
    connection
        .query_row(
            "SELECT ?1 || '_' || lower(hex(randomblob(16)))",
            [prefix],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn workflow_revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkflowRevisionView> {
    Ok(WorkflowRevisionView {
        revision_id: row.get(0)?,
        instance_id: row.get(1)?,
        epoch: row.get(2)?,
        from_version_id: row.get(3)?,
        to_version_id: row.get(4)?,
        activated_by_event_id: row.get(5)?,
        activation_policy_json: row.get(6)?,
        cancellation_policy: row.get(7)?,
        status: row.get(8)?,
        idempotency_key: row.get(9)?,
        created_at: row.get(10)?,
        activated_at: row.get(11)?,
    })
}

#[cfg(feature = "native")]
fn revision_by_id_on(
    connection: &Connection,
    revision_id: &str,
) -> StoreResult<Option<WorkflowRevisionView>> {
    connection
        .query_row(
            r#"
            SELECT
                revision_id,
                instance_id,
                epoch,
                from_version_id,
                to_version_id,
                activated_by_event_id,
                activation_policy_json,
                cancellation_policy,
                status,
                idempotency_key,
                created_at,
                activated_at
            FROM instance_revisions
            WHERE revision_id = ?1
            "#,
            [revision_id],
            workflow_revision_from_row,
        )
        .optional()
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn revision_by_idempotency_on(
    connection: &Connection,
    instance_id: &str,
    idempotency_key: &str,
) -> StoreResult<Option<WorkflowRevisionView>> {
    connection
        .query_row(
            r#"
            SELECT
                revision_id,
                instance_id,
                epoch,
                from_version_id,
                to_version_id,
                activated_by_event_id,
                activation_policy_json,
                cancellation_policy,
                status,
                idempotency_key,
                created_at,
                activated_at
            FROM instance_revisions
            WHERE instance_id = ?1
              AND idempotency_key = ?2
            "#,
            params![instance_id, idempotency_key],
            workflow_revision_from_row,
        )
        .optional()
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn ensure_revision_idempotency_matches(
    existing: &WorkflowRevisionView,
    activation: &RevisionActivation<'_>,
    activation_policy: &Value,
    cancellation_policy: &str,
) -> StoreResult<()> {
    let existing_activation_policy: Value = serde_json::from_str(&existing.activation_policy_json)?;
    if existing.instance_id.as_str() == activation.instance_id
        && existing.from_version_id.as_str() == activation.from_version_id
        && existing.to_version_id.as_str() == activation.to_version_id
        && existing.cancellation_policy.as_str() == cancellation_policy
        && &existing_activation_policy == activation_policy
    {
        return Ok(());
    }
    Err(StoreError::Conflict(
        "revision idempotency key was reused with different activation input".to_owned(),
    ))
}

#[cfg(feature = "native")]
fn revision_policy_effects_on(
    connection: &Connection,
    instance_id: &str,
    running: bool,
) -> StoreResult<Vec<String>> {
    let predicate = if running {
        "status = 'running'"
    } else {
        "status IN ('queued', 'blocked', 'blocked_by_dependency', 'blocked_by_capacity', 'blocked_by_capability', 'blocked_by_profile')"
    };
    let mut statement = connection.prepare(&format!(
        r#"
        SELECT effect_id
        FROM effects
        WHERE instance_id = ?1
          AND {predicate}
        ORDER BY created_at, effect_id
        "#
    ))?;
    let rows = statement
        .query_map([instance_id], |row| row.get(0))?
        .collect::<result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(feature = "native")]
fn effect_has_open_cancellation_request_on(
    connection: &Connection,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<bool> {
    connection
        .query_row(
            r#"
            SELECT 1
            FROM effect_cancellation_requests
            WHERE instance_id = ?1
              AND effect_id = ?2
              AND status = 'requested'
            LIMIT 1
            "#,
            params![instance_id, effect_id],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn effect_cancellation_request_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<EffectCancellationRequestView> {
    Ok(EffectCancellationRequestView {
        request_id: row.get(0)?,
        instance_id: row.get(1)?,
        effect_id: row.get(2)?,
        revision_id: row.get(3)?,
        reason: row.get(4)?,
        requested_by: row.get(5)?,
        causation_event_id: row.get(6)?,
        status: row.get(7)?,
        idempotency_key: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
        resolved_by_event_id: row.get(11)?,
    })
}

#[cfg(feature = "native")]
fn cancellation_request_by_idempotency_on(
    connection: &Connection,
    instance_id: &str,
    idempotency_key: &str,
) -> StoreResult<Option<EffectCancellationRequestView>> {
    connection
        .query_row(
            r#"
            SELECT
                request_id,
                instance_id,
                effect_id,
                revision_id,
                reason,
                requested_by,
                causation_event_id,
                status,
                idempotency_key,
                created_at,
                updated_at,
                resolved_by_event_id
            FROM effect_cancellation_requests
            WHERE instance_id = ?1
              AND idempotency_key = ?2
            "#,
            params![instance_id, idempotency_key],
            effect_cancellation_request_from_row,
        )
        .optional()
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn cancellation_request_by_id_on(
    connection: &Connection,
    request_id: &str,
) -> StoreResult<Option<EffectCancellationRequestView>> {
    connection
        .query_row(
            r#"
            SELECT
                request_id,
                instance_id,
                effect_id,
                revision_id,
                reason,
                requested_by,
                causation_event_id,
                status,
                idempotency_key,
                created_at,
                updated_at,
                resolved_by_event_id
            FROM effect_cancellation_requests
            WHERE request_id = ?1
            "#,
            [request_id],
            effect_cancellation_request_from_row,
        )
        .optional()
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn insert_effect_cancellation_request_on(
    connection: &Connection,
    request: EffectCancellationRequest<'_>,
) -> StoreResult<EffectCancellationRequestView> {
    if let Some(idempotency_key) = request.idempotency_key {
        if let Some(existing) = cancellation_request_by_idempotency_on(
            connection,
            request.instance_id,
            idempotency_key,
        )? {
            return Ok(existing);
        }
    }
    if effect_has_open_cancellation_request_on(connection, request.instance_id, request.effect_id)?
    {
        return Err(StoreError::Conflict(
            "effect already has an open cancellation request".to_owned(),
        ));
    }

    let request_id = random_id_on(connection, "ecr")?;
    let payload = json!({
        "request_id": &request_id,
        "effect_id": request.effect_id,
        "revision_id": request.revision_id,
        "reason": request.reason,
        "requested_by": request.requested_by,
    })
    .to_string();
    let event = append_event_on(
        connection,
        NewEvent {
            instance_id: request.instance_id,
            event_type: "effect.cancellation_requested",
            payload_json: &payload,
            source: "kernel",
            causation_id: request.causation_event_id.or(Some(request.effect_id)),
            correlation_id: request.revision_id,
            idempotency_key: request.idempotency_key,
        },
    )?;
    connection.execute(
        r#"
        INSERT INTO effect_cancellation_requests (
            request_id,
            instance_id,
            effect_id,
            revision_id,
            reason,
            requested_by,
            causation_event_id,
            status,
            idempotency_key
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'requested', ?8)
        "#,
        params![
            request_id,
            request.instance_id,
            request.effect_id,
            request.revision_id,
            request.reason,
            request.requested_by,
            request.causation_event_id,
            request.idempotency_key,
        ],
    )?;
    let active_run_ids =
        running_run_ids_for_effect_on(connection, request.instance_id, request.effect_id)?;
    let evidence_metadata = json!({
        "request_id": &request_id,
        "effect_id": request.effect_id,
        "revision_id": request.revision_id,
        "reason": request.reason,
        "requested_by": request.requested_by,
        "event_id": event.event_id,
        "active_run_ids": &active_run_ids,
    })
    .to_string();
    let evidence_id = insert_evidence_on(
        connection,
        EvidenceRecord {
            instance_id: request.instance_id,
            kind: "effect.cancellation.requested",
            subject_type: "effect_cancellation_request",
            subject_id: &request_id,
            causation_id: Some(&event.event_id),
            correlation_id: request.revision_id,
            summary: Some("effect cancellation requested"),
            metadata_json: &evidence_metadata,
        },
    )?;
    insert_evidence_link_on(
        connection,
        EvidenceLink {
            evidence_id: &evidence_id,
            instance_id: request.instance_id,
            target_type: "event",
            target_id: &event.event_id,
            relation: "requested",
        },
    )?;
    insert_evidence_link_on(
        connection,
        EvidenceLink {
            evidence_id: &evidence_id,
            instance_id: request.instance_id,
            target_type: "effect",
            target_id: request.effect_id,
            relation: "requested_cancellation",
        },
    )?;
    if let Some(revision_id) = request.revision_id {
        insert_evidence_link_on(
            connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: request.instance_id,
                target_type: "workflow_revision",
                target_id: revision_id,
                relation: "requested_by",
            },
        )?;
    }
    for run_id in &active_run_ids {
        insert_evidence_link_on(
            connection,
            EvidenceLink {
                evidence_id: &evidence_id,
                instance_id: request.instance_id,
                target_type: "run",
                target_id: run_id,
                relation: "active_run",
            },
        )?;
    }
    cancellation_request_by_id_on(connection, &request_id)?
        .ok_or_else(|| StoreError::Conflict("cancellation request was not recorded".to_owned()))
}

#[cfg(feature = "native")]
fn running_run_ids_for_effect_on(
    connection: &Connection,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<Vec<String>> {
    let mut statement = connection.prepare(
        r#"
        SELECT run_id
        FROM runs
        WHERE instance_id = ?1
          AND effect_id = ?2
          AND status = 'running'
        ORDER BY started_at, run_id
        "#,
    )?;
    let run_ids = statement
        .query_map(params![instance_id, effect_id], |row| row.get(0))?
        .collect::<result::Result<Vec<_>, _>>()
        .map_err(StoreError::from)?;
    Ok(run_ids)
}

#[cfg(feature = "native")]
fn mark_cancellation_requests_terminal_on(
    connection: &Connection,
    instance_id: &str,
    effect_id: &str,
    event_id: &str,
) -> StoreResult<()> {
    connection.execute(
        r#"
        UPDATE effect_cancellation_requests
        SET status = 'terminal',
            resolved_by_event_id = ?1,
            updated_at = CURRENT_TIMESTAMP
        WHERE instance_id = ?2
          AND effect_id = ?3
          AND status = 'requested'
        "#,
        params![event_id, instance_id, effect_id],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn capability_allowed(allowed: &[String], capability: &str) -> bool {
    allowed.iter().any(|item| item == "*" || item == capability)
}

#[cfg(feature = "native")]
fn required_string(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

#[cfg(feature = "native")]
fn required_manifest_string(value: &Value, fields: &[&str]) -> StoreResult<String> {
    fields
        .iter()
        .find_map(|field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned)
        })
        .ok_or_else(|| {
            StoreError::Conflict(format!(
                "manifest entry must have one of these non-empty string fields: {}",
                fields
                    .iter()
                    .map(|field| format!("`{field}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

#[cfg(feature = "native")]
fn manifest_effect_kind(provider: &Value) -> String {
    provider
        .get("effect_kind")
        .or_else(|| provider.get("core_effect_kind"))
        .or_else(|| provider.get("capability"))
        .or_else(|| provider.get("effect_contract"))
        .or_else(|| provider.get("effect_contract_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("capability.call")
        .to_owned()
}

#[cfg(feature = "native")]
fn skill_view_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SkillView> {
    Ok(SkillView {
        skill_id: row.get(0)?,
        name: row.get(1)?,
        version: row.get(2)?,
        source: row.get(3)?,
        source_path: row.get(4)?,
        content_hash: row.get(5)?,
        description: row.get(6)?,
        required_capabilities_json: row.get(7)?,
    })
}

#[cfg(feature = "native")]
fn skill_to_json(skill: &SkillView) -> StoreResult<Value> {
    // DR-0054 Phase C: unreadable stored capabilities surface with the skill's
    // identity instead of silently projecting `null` (which would erase the
    // capability declaration from the evidence trail without a trace).
    let required_capabilities = serde_json::from_str::<Value>(&skill.required_capabilities_json)
        .map_err(|error| {
            StoreError::Conflict(format!(
                "skill `{}` ({}) has unreadable required_capabilities: {error}",
                skill.name, skill.skill_id
            ))
        })?;
    Ok(json!({
        "skill_id": skill.skill_id,
        "name": skill.name,
        "version": skill.version,
        "source": skill.source,
        "source_path": skill.source_path,
        "content_hash": skill.content_hash,
        "description": skill.description,
        "required_capabilities": required_capabilities,
    }))
}

#[cfg(feature = "native")]
pub(crate) fn stable_hash_hex(value: &str) -> String {
    let mut hex = String::with_capacity(32);
    for byte in stable_hash_bytes(value) {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Execution fingerprint for a run, per spec/execution-contract.md: the
/// materialized input plus the resolved dependency outputs, recorded with the run
/// for replay verification and model-backed change detection. It is deliberately
/// **distinct** from the effect idempotency key (the key is fixed at creation; the
/// fingerprint reflects what the run actually executed against). Downstream effects
/// bake their upstream outputs into `input_json` at lowering, so the materialized
/// input already carries the resolved dependency outputs; the sorted upstream
/// effect ids record the dependency structure that fed the run.
#[cfg(feature = "native")]
fn execution_fingerprint_on(
    connection: &Connection,
    instance_id: &str,
    effect_id: &str,
    salt: Option<&str>,
) -> StoreResult<String> {
    let input_json: String = connection
        .query_row(
            "SELECT input_json FROM effects WHERE instance_id = ?1 AND effect_id = ?2",
            params![instance_id, effect_id],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_else(|| "{}".to_owned());
    let mut upstream: Vec<String> = connection
        .prepare(
            "SELECT upstream_effect_id FROM effect_dependencies \
             WHERE instance_id = ?1 AND downstream_effect_id = ?2",
        )?
        .query_map(params![instance_id, effect_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<_, _>>()?;
    upstream.sort();
    let base = format!("{input_json}|{}", upstream.join(","));
    // A non-empty salt (the runtime-resolved model for `schema.coerce` runs,
    // carried in run metadata under `__fingerprint_model`; DR-0014 amendment)
    // makes the execution fingerprint model-sensitive, so a coercion whose only
    // change is the model re-runs instead of deduping a stale result. An
    // absent/empty salt keeps the fingerprint byte-identical to the pre-salt
    // behaviour for every other effect kind.
    let fingerprint_input = match salt {
        Some(salt) if !salt.is_empty() => format!("{base}|model={salt}"),
        _ => base,
    };
    Ok(stable_hash_hex(&fingerprint_input))
}

/// The reserved run-metadata key carrying the runtime-resolved model for a
/// `schema.coerce` run, folded into the execution fingerprint (DR-0014). A run
/// whose `metadata_json` sets this key gets a model-sensitive fingerprint.
pub const FINGERPRINT_MODEL_METADATA_KEY: &str = "__fingerprint_model";

/// Extract the fingerprint model salt from a run's metadata JSON, if present.
fn fingerprint_salt_from_metadata(metadata_json: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(metadata_json)
        .ok()?
        .get(FINGERPRINT_MODEL_METADATA_KEY)
        .and_then(|value| value.as_str())
        .filter(|model| !model.is_empty())
        .map(str::to_owned)
}

#[cfg(feature = "native")]
fn stable_hash_bytes(value: &str) -> [u8; 16] {
    // SHA-256/128 (the FNV-collision hardening swap): these digests cover
    // user-authored content — file bodies (`file.write.completed`
    // content_hash), skill bodies, manifests — where a crafted collision
    // aliases two contents. The DO mirror in do_store.rs must stay
    // byte-identical.
    use sha2::Digest;
    let digest = sha2::Sha256::digest(value.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(feature = "native")]
fn count_where(
    connection: &Connection,
    table: &str,
    instance_id: &str,
    extra_predicate: Option<&str>,
) -> StoreResult<i64> {
    let mut sql = format!("SELECT COUNT(*) FROM {table} WHERE instance_id = ?1");
    if let Some(predicate) = extra_predicate {
        sql.push_str(" AND ");
        sql.push_str(predicate);
    }

    connection
        .query_row(&sql, [instance_id], |row| row.get(0))
        .map_err(Into::into)
}

#[cfg(feature = "native")]
fn workflow_invocation_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<WorkflowInvocationView> {
    Ok(WorkflowInvocationView {
        invocation_id: row.get(0)?,
        parent_instance_id: row.get(1)?,
        parent_effect_id: row.get(2)?,
        parent_program_version_id: row.get(3)?,
        parent_revision_epoch: row.get(4)?,
        parent_active_program_version_id: row.get(5)?,
        parent_active_revision_epoch: row.get(6)?,
        child_instance_id: row.get(7)?,
        child_program_version_id: row.get(8)?,
        child_revision_epoch: row.get(9)?,
        child_active_program_version_id: row.get(10)?,
        child_active_revision_epoch: row.get(11)?,
        target_workflow: row.get(12)?,
        input_json: row.get(13)?,
        status: row.get(14)?,
        terminal_event_id: row.get(15)?,
        source_span_json: row.get(16)?,
        created_at: row.get(17)?,
        updated_at: row.get(18)?,
    })
}

#[cfg(feature = "native")]
fn rule_commit_payload(
    commit: RuleCommit<'_>,
    program_version_id: Option<&str>,
    revision_epoch: i64,
) -> StoreResult<String> {
    let facts = commit
        .facts
        .iter()
        .map(|fact| {
            if let Some(source_span_json) = fact.source_span_json {
                serde_json::from_str::<Value>(source_span_json)?;
            }
            Ok(json!({
                "fact_id": fact.fact_id,
                "name": fact.name,
                "key": fact.key,
                "value": serde_json::from_str::<Value>(fact.value_json)?,
                "program_version_id": program_version_id,
                "revision_epoch": revision_epoch,
                "schema_id": fact.schema_id,
                "provenance_class": fact.provenance_class,
                "correlation_id": fact.correlation_id,
                "source_span": fact.source_span_json
                    .map(serde_json::from_str::<Value>)
                    .transpose()?
                    .unwrap_or(Value::Null),
            }))
        })
        .collect::<StoreResult<Vec<_>>>()?;
    let consumed_facts = commit
        .consumed_fact_ids
        .iter()
        .map(|fact_id| json!({ "fact_id": fact_id }))
        .collect::<Vec<_>>();
    let effects = commit
        .effects
        .iter()
        .map(|effect| {
            if let Some(source_span_json) = effect.source_span_json {
                serde_json::from_str::<Value>(source_span_json)?;
            }
            Ok(json!({
                "effect_id": effect.effect_id,
                "kind": effect.kind,
                "target": effect.target,
                "input": serde_json::from_str::<Value>(effect.input_json)?,
                "status": effect.status,
                "program_version_id": program_version_id,
                "revision_epoch": revision_epoch,
                "idempotency_key": effect.idempotency_key,
                "required_capabilities": serde_json::from_str::<Value>(effect.required_capabilities_json)?,
                "profile": effect.profile,
                "correlation_id": effect.correlation_id,
                "source_span": effect
                    .source_span_json
                    .map(serde_json::from_str::<Value>)
                    .transpose()?
                    .unwrap_or(Value::Null),
            }))
        })
        .collect::<StoreResult<Vec<_>>>()?;
    let dependencies = commit
        .dependencies
        .iter()
        .map(|dependency| {
            json!({
                "dependency_id": dependency.dependency_id,
                "upstream_effect_id": dependency.upstream_effect_id,
                "downstream_effect_id": dependency.downstream_effect_id,
                "predicate": dependency.predicate,
            })
        })
        .collect::<Vec<_>>();

    let payload = json!({
        "rule": commit.rule,
        "program_version_id": program_version_id,
        "revision_epoch": revision_epoch,
        "facts": facts,
        "consumed_facts": consumed_facts,
        "effects": effects,
        "dependencies": dependencies,
        "terminal": match commit.terminal {
            Some(terminal) => Some(serde_json::from_str::<Value>(&workflow_terminal_payload(commit, terminal)?)?),
            None => None,
        },
        // DR-0043 slice 1: the firing's pinned context (identity + bound
        // trigger values), kernel-serialized; makes the firing record
        // self-contained for pinned re-lowering and `whip progressions`.
        "context": commit
            .context_json
            .map(serde_json::from_str::<Value>)
            .transpose()?
            .unwrap_or(Value::Null),
    });
    serde_json::to_string(&payload).map_err(Into::into)
}

#[cfg(feature = "native")]
fn workflow_terminal_payload(
    commit: RuleCommit<'_>,
    terminal: WorkflowTerminal<'_>,
) -> StoreResult<String> {
    let payload = json!({
        "workflow_action": terminal.kind.action(),
        "workflow_status": terminal.kind.instance_status(),
        "terminal_name": terminal.name,
        "payload": serde_json::from_str::<Value>(terminal.payload_json)?,
        "rule": commit.rule,
    });
    serde_json::to_string(&payload).map_err(Into::into)
}

#[cfg(feature = "native")]
fn effect_completion_payload(
    completion: EffectCompletion<'_>,
    diagnostic: Option<&TerminalDiagnosticRecord>,
) -> StoreResult<String> {
    // DR-0054 Phase C: unreadable completion metadata surfaces with the run
    // identity instead of writing `null` into the canonical `effect.terminal`
    // event (which would silently drop the completion's metadata forever).
    let metadata = serde_json::from_str::<Value>(completion.metadata_json).map_err(|error| {
        StoreError::Conflict(format!(
            "effect `{}` run `{}` completion has unreadable metadata: {error}",
            completion.effect_id, completion.run_id
        ))
    })?;
    Ok(json!({
        "effect_id": completion.effect_id,
        "run_id": completion.run_id,
        "provider": completion.provider,
        "worker_id": completion.worker_id,
        "status": completion.status,
        "exit_code": completion.exit_code,
        "summary": completion.summary,
        "metadata": metadata,
        "diagnostic": diagnostic.map(terminal_diagnostic_payload).transpose()?,
    })
    .to_string())
}

#[cfg(feature = "native")]
fn terminal_diagnostic_payload(diagnostic: &TerminalDiagnosticRecord) -> StoreResult<Value> {
    // DR-0054 Phase C: an absent span is genuinely optional (`None` → `null`),
    // but a PRESENT span/ids field this build cannot parse is corruption and
    // surfaces instead of silently degrading to `null` / `[]`.
    let context = |field: &str, error: serde_json::Error| {
        StoreError::Conflict(format!(
            "terminal diagnostic `{}` has unreadable {field}: {error}",
            diagnostic.message
        ))
    };
    Ok(json!({
        "program_id": diagnostic.program_id,
        "program_version_id": diagnostic.program_version_id,
        "severity": diagnostic.severity.as_str(),
        "code": diagnostic.code,
        "message": diagnostic.message,
        "source_span": diagnostic
            .source_span_json
            .as_deref()
            .map(serde_json::from_str::<Value>)
            .transpose()
            .map_err(|error| context("source_span", error))?,
        "subject_type": diagnostic.subject_type,
        "subject_id": diagnostic.subject_id,
        "assertion_id": diagnostic.assertion_id,
        "evidence_ids": serde_json::from_str::<Value>(&diagnostic.evidence_ids_json)
            .map_err(|error| context("evidence_ids", error))?,
        "artifact_ids": serde_json::from_str::<Value>(&diagnostic.artifact_ids_json)
            .map_err(|error| context("artifact_ids", error))?,
        "causation_id": diagnostic.causation_id,
        "correlation_id": diagnostic.correlation_id,
        "idempotency_key": diagnostic.idempotency_key,
    }))
}

#[cfg(feature = "native")]
fn run_start_payload(run: RunStart<'_>, metadata_json: &str) -> StoreResult<String> {
    // DR-0054 Phase C: unreadable run metadata surfaces with the run identity
    // instead of recording `null` in the canonical `effect.run_started` event.
    let metadata = serde_json::from_str::<Value>(metadata_json).map_err(|error| {
        StoreError::Conflict(format!(
            "effect `{}` run `{}` start has unreadable metadata: {error}",
            run.effect_id, run.run_id
        ))
    })?;
    Ok(json!({
        "effect_id": run.effect_id,
        "run_id": run.run_id,
        "provider": run.provider,
        "worker_id": run.worker_id,
        "lease_id": run.lease_id,
        "lease_expires_at": run.lease_expires_at,
        "metadata": metadata,
    })
    .to_string())
}

#[cfg(feature = "native")]
/// Merge the execution fingerprint into a run's metadata object so it is recorded
/// with the run (in the `run_started` event payload and the projected `runs` row)
/// and reconstructs on replay through the existing metadata flow. Non-object but
/// well-formed metadata (the historical `"null"`/scalar shapes) still normalizes
/// to an object; UNREADABLE metadata propagates instead of being silently
/// replaced with `{}`, which would drop the caller's metadata without a trace
/// (DR-0054 Phase C).
fn inject_execution_fingerprint(
    run: &RunStart<'_>,
    metadata_json: &str,
    fingerprint: &str,
) -> StoreResult<String> {
    let mut value: Value = serde_json::from_str(metadata_json).map_err(|error| {
        StoreError::Conflict(format!(
            "effect `{}` run `{}` has unreadable metadata: {error}",
            run.effect_id, run.run_id
        ))
    })?;
    if !value.is_object() {
        value = json!({});
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "execution_fingerprint".to_owned(),
            Value::String(fingerprint.to_owned()),
        );
    }
    Ok(value.to_string())
}

#[cfg(feature = "native")]
fn replay_rule_commit(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let rule = payload
        .get("rule")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    let commit_program_version_id = payload.get("program_version_id").and_then(Value::as_str);
    let commit_revision_epoch = payload
        .get("revision_epoch")
        .and_then(Value::as_i64)
        .unwrap_or(0);

    for fact in payload
        .get("facts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let fact_id = fact.get("fact_id").and_then(Value::as_str).unwrap_or("");
        let name = fact.get("name").and_then(Value::as_str).unwrap_or("");
        let key = fact.get("key").and_then(Value::as_str).unwrap_or("");
        let value_json = fact
            .get("value")
            .map(Value::to_string)
            .unwrap_or_else(|| "{}".to_owned());
        let source_span_json = fact.get("source_span").map(Value::to_string);
        let program_version_id = fact
            .get("program_version_id")
            .and_then(Value::as_str)
            .or(commit_program_version_id);
        let revision_epoch = fact
            .get("revision_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(commit_revision_epoch);
        let new_fact = NewFact {
            fact_id,
            name,
            key,
            value_json: &value_json,
            schema_id: fact.get("schema_id").and_then(Value::as_str),
            provenance_class: fact
                .get("provenance_class")
                .and_then(Value::as_str)
                .unwrap_or("replayed"),
            correlation_id: fact.get("correlation_id").and_then(Value::as_str),
            source_span_json: source_span_json.as_deref(),
        };
        insert_fact(
            connection,
            instance_id,
            rule,
            event_id,
            program_version_id,
            revision_epoch,
            &new_fact,
        )?;
    }

    let consumed_fact_ids = payload
        .get("consumed_facts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|fact| {
            fact.get("fact_id")
                .and_then(Value::as_str)
                .or_else(|| fact.as_str())
        })
        .collect::<Vec<_>>();
    consume_facts(connection, instance_id, &consumed_fact_ids)?;

    for effect in payload
        .get("effects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let effect_id = effect
            .get("effect_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let kind = effect.get("kind").and_then(Value::as_str).unwrap_or("");
        let input_json = effect
            .get("input")
            .map(Value::to_string)
            .unwrap_or_else(|| "{}".to_owned());
        let required_capabilities_json = effect
            .get("required_capabilities")
            .map(Value::to_string)
            .unwrap_or_else(|| "[]".to_owned());
        let source_span_json = effect.get("source_span").map(Value::to_string);
        let program_version_id = effect
            .get("program_version_id")
            .and_then(Value::as_str)
            .or(commit_program_version_id);
        let revision_epoch = effect
            .get("revision_epoch")
            .and_then(Value::as_i64)
            .unwrap_or(commit_revision_epoch);
        let new_effect = NewEffect {
            timeout_seconds: None,
            effect_id,
            kind,
            target: effect.get("target").and_then(Value::as_str),
            input_json: &input_json,
            status: effect
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("queued"),
            idempotency_key: effect
                .get("idempotency_key")
                .and_then(Value::as_str)
                .unwrap_or(""),
            required_capabilities_json: &required_capabilities_json,
            profile: effect.get("profile").and_then(Value::as_str),
            correlation_id: effect.get("correlation_id").and_then(Value::as_str),
            source_span_json: source_span_json.as_deref(),
        };
        insert_effect(
            connection,
            instance_id,
            rule,
            event_id,
            program_version_id,
            revision_epoch,
            &new_effect,
        )?;
    }

    for dependency in payload
        .get("dependencies")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let new_dependency = NewEffectDependency {
            dependency_id: dependency
                .get("dependency_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            upstream_effect_id: dependency
                .get("upstream_effect_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            downstream_effect_id: dependency
                .get("downstream_effect_id")
                .and_then(Value::as_str)
                .unwrap_or(""),
            predicate: dependency
                .get("predicate")
                .and_then(Value::as_str)
                .unwrap_or("succeeds"),
        };
        insert_effect_dependency(connection, instance_id, rule, &new_dependency)?;
    }

    Ok(())
}

#[cfg(feature = "native")]
fn replay_fact_derived(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    source: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let fact_id = payload.get("fact_id").and_then(Value::as_str).unwrap_or("");
    let name = payload.get("name").and_then(Value::as_str).unwrap_or("");
    let key = payload.get("key").and_then(Value::as_str).unwrap_or("");
    if fact_id.is_empty() || name.is_empty() || key.is_empty() {
        return Ok(());
    }

    let value_json = payload
        .get("value")
        .cloned()
        .unwrap_or(Value::Null)
        .to_string();
    let fact = NewFact {
        fact_id,
        name,
        key,
        value_json: &value_json,
        schema_id: payload.get("schema_id").and_then(Value::as_str),
        provenance_class: payload
            .get("provenance_class")
            .and_then(Value::as_str)
            .unwrap_or("derived"),
        correlation_id: payload.get("correlation_id").and_then(Value::as_str),
        source_span_json: None,
    };
    let (program_version_id, revision_epoch) = active_revision_on(connection, instance_id)?;
    insert_fact(
        connection,
        instance_id,
        source,
        event_id,
        program_version_id.as_deref(),
        revision_epoch,
        &fact,
    )
}

#[cfg(feature = "native")]
fn replay_workflow_terminal(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    event_type: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let status = payload
        .get("workflow_status")
        .and_then(Value::as_str)
        .unwrap_or_else(|| {
            if event_type == "workflow.failed" {
                "failed"
            } else {
                "completed"
            }
        });
    let terminal_name = payload
        .get("terminal_name")
        .and_then(Value::as_str)
        .unwrap_or(event_type);
    connection.execute(
        r#"
        UPDATE instances
        SET status = ?1,
            last_event_id = ?2,
            last_error = CASE WHEN ?1 = 'failed' THEN ?3 ELSE last_error END,
            updated_at = CURRENT_TIMESTAMP,
            completed_at = CURRENT_TIMESTAMP
        WHERE instance_id = ?4
        "#,
        params![status, event_id, terminal_name, instance_id],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn replay_instance_transition(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let status = payload.get("status").and_then(Value::as_str).unwrap_or("");
    if status.is_empty() {
        return Ok(());
    }
    connection.execute(
        r#"
        UPDATE instances
        SET status = ?1,
            last_event_id = ?2,
            last_error = ?3,
            updated_at = CURRENT_TIMESTAMP,
            completed_at = CASE
                WHEN ?1 IN ('completed', 'cancelled') THEN CURRENT_TIMESTAMP
                ELSE completed_at
            END
        WHERE instance_id = ?4
        "#,
        params![
            status,
            event_id,
            payload.get("reason").and_then(Value::as_str),
            instance_id,
        ],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn replay_revision_activation(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
    idempotency_key: Option<&str>,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let revision_id = payload
        .get("revision_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let from_version_id = payload
        .get("from_version_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let to_version_id = payload
        .get("to_version_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let epoch = payload
        .get("to_epoch")
        .and_then(Value::as_i64)
        .or_else(|| payload.get("revision_epoch").and_then(Value::as_i64))
        .unwrap_or(0);
    if revision_id.is_empty() || from_version_id.is_empty() || to_version_id.is_empty() {
        return Ok(());
    }
    let activation_policy_json = payload
        .get("activation_policy")
        .map(Value::to_string)
        .unwrap_or_else(|| "{}".to_owned());
    let cancellation_policy = payload
        .get("cancellation_policy")
        .and_then(Value::as_str)
        .unwrap_or("keep");
    connection.execute(
        r#"
        INSERT INTO instance_revisions (
            revision_id,
            instance_id,
            epoch,
            from_version_id,
            to_version_id,
            activated_by_event_id,
            activation_policy_json,
            cancellation_policy,
            status,
            idempotency_key
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9)
        ON CONFLICT(revision_id) DO NOTHING
        "#,
        params![
            revision_id,
            instance_id,
            epoch,
            from_version_id,
            to_version_id,
            event_id,
            activation_policy_json,
            cancellation_policy,
            idempotency_key,
        ],
    )?;
    connection.execute(
        r#"
        UPDATE instances
        SET version_id = ?1,
            revision_epoch = ?2,
            last_event_id = ?3,
            updated_at = CURRENT_TIMESTAMP
        WHERE instance_id = ?4
        "#,
        params![to_version_id, epoch, event_id, instance_id],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn replay_run_started(
    connection: &Connection,
    instance_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
    let lease_id = payload
        .get("lease_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if effect_id.is_empty() || run_id.is_empty() || lease_id.is_empty() {
        return Ok(());
    }
    let provider = payload
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let worker_id = payload
        .get("worker_id")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let lease_expires_at = payload
        .get("lease_expires_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    let metadata_json = payload
        .get("metadata")
        .map(Value::to_string)
        .unwrap_or_else(|| "{}".to_owned());

    connection.execute(
        r#"
        UPDATE effects
        SET status = 'running',
            policy_block_reason = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE instance_id = ?1
          AND effect_id = ?2
          AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
        "#,
        params![instance_id, effect_id],
    )?;
    connection.execute(
        r#"
        INSERT INTO runs (
            run_id,
            effect_id,
            instance_id,
            provider,
            worker_id,
            status,
            metadata_json
        )
        VALUES (?1, ?2, ?3, ?4, ?5, 'running', ?6)
        ON CONFLICT(run_id) DO UPDATE SET
            effect_id = excluded.effect_id,
            instance_id = excluded.instance_id,
            provider = excluded.provider,
            worker_id = excluded.worker_id,
            status = 'running',
            completed_at = NULL,
            exit_code = NULL,
            summary = NULL,
            metadata_json = excluded.metadata_json
        "#,
        params![
            run_id,
            effect_id,
            instance_id,
            provider,
            worker_id,
            metadata_json,
        ],
    )?;
    connection.execute(
        r#"
        INSERT INTO leases (
            lease_id,
            run_id,
            effect_id,
            instance_id,
            worker_id,
            status,
            expires_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, 'active', ?6)
        ON CONFLICT(lease_id) DO UPDATE SET
            run_id = excluded.run_id,
            effect_id = excluded.effect_id,
            instance_id = excluded.instance_id,
            worker_id = excluded.worker_id,
            status = 'active',
            expires_at = excluded.expires_at,
            released_at = NULL
        "#,
        params![
            lease_id,
            run_id,
            effect_id,
            instance_id,
            worker_id,
            lease_expires_at,
        ],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn replay_effect_terminal(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
    if effect_id.is_empty() {
        return Ok(());
    }
    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("completed");
    let provider = payload
        .get("provider")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let worker_id = payload
        .get("worker_id")
        .and_then(Value::as_str)
        .unwrap_or("replay");
    let metadata_json = payload
        .get("metadata")
        .map(Value::to_string)
        .unwrap_or_else(|| "{}".to_owned());
    if !run_id.is_empty() {
        connection.execute(
            r#"
            INSERT INTO runs (
                run_id,
                effect_id,
                instance_id,
                provider,
                worker_id,
                status,
                completed_at,
                exit_code,
                summary,
                metadata_json
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, CURRENT_TIMESTAMP, ?7, ?8, ?9)
            ON CONFLICT(run_id) DO UPDATE SET
                effect_id = excluded.effect_id,
                instance_id = excluded.instance_id,
                provider = excluded.provider,
                worker_id = excluded.worker_id,
                status = excluded.status,
                completed_at = CURRENT_TIMESTAMP,
                exit_code = excluded.exit_code,
                summary = excluded.summary,
                metadata_json = excluded.metadata_json
            "#,
            params![
                run_id,
                effect_id,
                instance_id,
                provider,
                worker_id,
                status,
                payload.get("exit_code").and_then(Value::as_i64),
                payload.get("summary").and_then(Value::as_str),
                metadata_json,
            ],
        )?;
        connection.execute(
            r#"
            UPDATE leases
            SET status = 'released',
                released_at = CURRENT_TIMESTAMP
            WHERE run_id = ?1
              AND effect_id = ?2
              AND instance_id = ?3
              AND status = 'active'
            "#,
            params![run_id, effect_id, instance_id],
        )?;
    }
    connection.execute(
        r#"
        UPDATE effects
        SET status = ?1,
            updated_at = CURRENT_TIMESTAMP
        WHERE effect_id = ?2
          AND instance_id = ?3
        "#,
        params![status, effect_id, instance_id],
    )?;
    mark_cancellation_requests_terminal_on(connection, instance_id, effect_id, event_id)?;
    satisfy_dependencies_on(connection, instance_id)?;
    Ok(())
}

#[cfg(feature = "native")]
fn replay_effect_cancelled(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if effect_id.is_empty() {
        return Ok(());
    }
    connection.execute(
        r#"
        UPDATE effects
        SET status = 'cancelled',
            updated_at = CURRENT_TIMESTAMP
        WHERE instance_id = ?1
          AND effect_id = ?2
          AND status NOT IN ('completed', 'failed', 'timed_out', 'cancelled')
        "#,
        params![instance_id, effect_id],
    )?;
    mark_cancellation_requests_terminal_on(connection, instance_id, effect_id, event_id)?;
    satisfy_dependencies_on(connection, instance_id)?;
    Ok(())
}

#[cfg(feature = "native")]
fn replay_lease_expired(
    connection: &Connection,
    instance_id: &str,
    payload_json: &str,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let lease_id = payload
        .get("lease_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let run_id = payload.get("run_id").and_then(Value::as_str).unwrap_or("");
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if lease_id.is_empty() || run_id.is_empty() || effect_id.is_empty() {
        return Ok(());
    }
    connection.execute(
        r#"
        UPDATE leases
        SET status = 'expired',
            released_at = CURRENT_TIMESTAMP
        WHERE lease_id = ?1
        "#,
        [lease_id],
    )?;
    connection.execute(
        r#"
        UPDATE runs
        SET status = 'lease_expired',
            completed_at = CURRENT_TIMESTAMP
        WHERE run_id = ?1
          AND status = 'running'
        "#,
        [run_id],
    )?;
    connection.execute(
        r#"
        UPDATE effects
        SET status = 'queued',
            updated_at = CURRENT_TIMESTAMP
        WHERE instance_id = ?1
          AND effect_id = ?2
          AND status = 'running'
        "#,
        params![instance_id, effect_id],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn replay_cancellation_request(
    connection: &Connection,
    instance_id: &str,
    event_id: &str,
    payload_json: &str,
    idempotency_key: Option<&str>,
    causation_event_id: Option<&str>,
) -> StoreResult<()> {
    let payload: Value = serde_json::from_str(payload_json)?;
    let request_id = payload
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let effect_id = payload
        .get("effect_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if request_id.is_empty() || effect_id.is_empty() {
        return Ok(());
    }
    let causation_event_id = match causation_event_id {
        Some(candidate)
            if connection
                .query_row(
                    "SELECT 1 FROM events WHERE instance_id = ?1 AND event_id = ?2",
                    params![instance_id, candidate],
                    |_| Ok(()),
                )
                .optional()?
                .is_some() =>
        {
            Some(candidate)
        }
        _ => Some(event_id),
    };
    connection.execute(
        r#"
        INSERT INTO effect_cancellation_requests (
            request_id,
            instance_id,
            effect_id,
            revision_id,
            reason,
            requested_by,
            causation_event_id,
            status,
            idempotency_key
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'requested', ?8)
        ON CONFLICT(request_id) DO NOTHING
        "#,
        params![
            request_id,
            instance_id,
            effect_id,
            payload.get("revision_id").and_then(Value::as_str),
            payload.get("reason").and_then(Value::as_str),
            payload
                .get("requested_by")
                .and_then(Value::as_str)
                .unwrap_or("replay"),
            causation_event_id,
            idempotency_key,
        ],
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn apply_migrations(connection: &mut Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )?;

    // DR-0054 Phase B downgrade guard: a store stamped past the highest
    // migration this build knows was written by a NEWER build. Opening it
    // anyway would silently misread (or "repair") a layout this code has never
    // seen, so refuse before any migration or ensure-* touches it. The error
    // names both versions; the fix is running the newer build — the store
    // itself is intact and must not be deleted.
    let stamped: i64 = connection.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get(0),
    )?;
    if stamped > SUPPORTED_SCHEMA_VERSION {
        return Err(StoreError::UnsupportedVersion {
            subject: "store schema (schema_migrations)".to_owned(),
            found: stamped,
            supported: SUPPORTED_SCHEMA_VERSION,
        });
    }

    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    for migration in MIGRATIONS {
        let applied = transaction
            .query_row(
                "SELECT 1 FROM schema_migrations WHERE version = ?1",
                [migration.version],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if applied {
            continue;
        }

        transaction.execute_batch(migration.sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations (version, name) VALUES (?1, ?2)",
            params![migration.version, migration.name],
        )?;
    }
    transaction.commit()?;
    ensure_fact_schema(connection)?;
    ensure_diagnostics_schema(connection)?;
    ensure_workflow_invocation_schema(connection)?;
    ensure_revision_schema(connection)?;
    ensure_instance_authority_schema(connection)?;
    ensure_workspace_schema(connection)?;
    ensure_effect_time_columns(connection)?;
    ensure_skill_body_column(connection)?;
    ensure_lookup_indexes(connection)?;
    ensure_event_format_column(connection)?;
    ensure_store_meta(connection)?;
    Ok(())
}

/// DR-0054 Phase B: give `events` a nullable `format_version` column via the
/// ensure-* additive pattern. Every new row is stamped with
/// [`SUPPORTED_EVENT_FORMAT_VERSION`]; legacy NULL rows read as version 1.
/// Additive only — no existing row is rewritten (the event log is canonical).
#[cfg(feature = "native")]
fn ensure_event_format_column(connection: &Connection) -> StoreResult<()> {
    let events_table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'events'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !events_table_exists {
        return Ok(());
    }
    if !column_exists(connection, "events", "format_version")? {
        connection.execute("ALTER TABLE events ADD COLUMN format_version INTEGER", [])?;
    }
    Ok(())
}

/// DR-0054 Phase B: record which build last opened this store. `store_meta`
/// carries `writer_version` (the crate version) and `format_version` (the
/// event format this build writes), upserted on every open, so a store found
/// on disk is always diagnosable — "written by whom, in what format" — without
/// inference from its contents.
#[cfg(feature = "native")]
fn ensure_store_meta(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS store_meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )?;
    for (key, value) in [
        ("writer_version", WRITER_VERSION.to_owned()),
        ("format_version", SUPPORTED_EVENT_FORMAT_VERSION.to_string()),
    ] {
        connection.execute(
            r#"
            INSERT INTO store_meta (key, value, updated_at)
            VALUES (?1, ?2, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE
            SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            "#,
            params![key, value],
        )?;
    }
    Ok(())
}

/// Idempotent patch (context-assembly Phase 2, Decision 3): give `skills` a `body`
/// column carrying the content-addressed SKILL.md bytes. Applied on every open, so
/// a store from before the column gains it; a no-op once present.
#[cfg(feature = "native")]
fn ensure_skill_body_column(connection: &Connection) -> StoreResult<()> {
    let skills_table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'skills'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !skills_table_exists {
        return Ok(());
    }
    if !column_exists(connection, "skills", "body")? {
        connection.execute(
            "ALTER TABLE skills ADD COLUMN body TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_effect_time_columns(connection: &Connection) -> StoreResult<()> {
    let effects_table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'effects'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !effects_table_exists {
        return Ok(());
    }
    if !column_exists(connection, "effects", "timeout_seconds")? {
        connection.execute("ALTER TABLE effects ADD COLUMN timeout_seconds INTEGER", [])?;
    }
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_lookup_indexes(connection: &Connection) -> StoreResult<()> {
    {
        let (table, statement) = (
            "facts",
            "CREATE INDEX IF NOT EXISTS idx_facts_instance_name ON facts(instance_id, name)",
        );
        let table_exists = connection
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if table_exists {
            connection.execute(statement, [])?;
        }
    }
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_instance_authority_schema(connection: &Connection) -> StoreResult<()> {
    if !table_exists(connection, "instances")? {
        return Ok(());
    }
    if !column_exists(connection, "instances", "workflow_principal")? {
        connection.execute(
            "ALTER TABLE instances ADD COLUMN workflow_principal TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    if !column_exists(connection, "instances", "effective_authority")? {
        connection.execute(
            "ALTER TABLE instances ADD COLUMN effective_authority TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_workspace_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS workspaces (
            workspace_id TEXT PRIMARY KEY,
            instance_id TEXT REFERENCES instances(instance_id),
            effect_id TEXT REFERENCES effects(effect_id),
            run_id TEXT REFERENCES runs(run_id),
            provider TEXT,
            policy TEXT NOT NULL,
            uri TEXT NOT NULL,
            status TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(instance_id, effect_id, run_id, policy)
        );
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_revision_schema(connection: &Connection) -> StoreResult<()> {
    if table_exists(connection, "instances")?
        && !column_exists(connection, "instances", "revision_epoch")?
    {
        connection.execute(
            "ALTER TABLE instances ADD COLUMN revision_epoch INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    if table_exists(connection, "effects")?
        && !column_exists(connection, "effects", "program_version_id")?
    {
        connection.execute("ALTER TABLE effects ADD COLUMN program_version_id TEXT", [])?;
    }
    if table_exists(connection, "effects")?
        && !column_exists(connection, "effects", "revision_epoch")?
    {
        connection.execute(
            "ALTER TABLE effects ADD COLUMN revision_epoch INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS instance_revisions (
            revision_id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(instance_id),
            epoch INTEGER NOT NULL,
            from_version_id TEXT NOT NULL REFERENCES program_versions(version_id),
            to_version_id TEXT NOT NULL REFERENCES program_versions(version_id),
            activated_by_event_id TEXT NOT NULL REFERENCES events(event_id),
            activation_policy_json TEXT NOT NULL DEFAULT '{}',
            cancellation_policy TEXT NOT NULL,
            status TEXT NOT NULL,
            idempotency_key TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            activated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(instance_id, epoch)
        );

        CREATE UNIQUE INDEX IF NOT EXISTS instance_revisions_instance_idempotency_key_idx
            ON instance_revisions(instance_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL;

        CREATE TABLE IF NOT EXISTS effect_cancellation_requests (
            request_id TEXT PRIMARY KEY,
            instance_id TEXT NOT NULL REFERENCES instances(instance_id),
            effect_id TEXT NOT NULL REFERENCES effects(effect_id),
            revision_id TEXT REFERENCES instance_revisions(revision_id),
            reason TEXT,
            requested_by TEXT NOT NULL,
            causation_event_id TEXT REFERENCES events(event_id),
            status TEXT NOT NULL,
            idempotency_key TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            resolved_by_event_id TEXT,
            UNIQUE(instance_id, effect_id, revision_id)
        );

        CREATE UNIQUE INDEX IF NOT EXISTS effect_cancellation_requests_instance_idempotency_key_idx
            ON effect_cancellation_requests(instance_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL;
        "#,
    )?;
    if table_exists(connection, "effects")? && table_exists(connection, "instances")? {
        connection.execute(
            r#"
            UPDATE effects
            SET program_version_id = (
                SELECT version_id
                FROM instances
                WHERE instances.instance_id = effects.instance_id
            )
            WHERE program_version_id IS NULL
            "#,
            [],
        )?;
    }
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_workflow_invocation_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS repair_scopes (
            instance_id TEXT PRIMARY KEY,
            branch_id TEXT NOT NULL,
            slice_expr TEXT NOT NULL,
            source_ref TEXT NOT NULL,
            granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS workflow_invocations (
            invocation_id TEXT PRIMARY KEY,
            parent_instance_id TEXT NOT NULL,
            parent_effect_id TEXT NOT NULL,
            parent_program_version_id TEXT,
            parent_revision_epoch INTEGER NOT NULL DEFAULT 0,
            child_instance_id TEXT NOT NULL,
            child_program_version_id TEXT,
            child_revision_epoch INTEGER,
            target_workflow TEXT NOT NULL,
            input_json TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'running',
            terminal_event_id TEXT,
            source_span_json TEXT,
            idempotency_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )?;
    for (column, definition) in [
        ("parent_program_version_id", "TEXT"),
        ("parent_revision_epoch", "INTEGER NOT NULL DEFAULT 0"),
        ("child_program_version_id", "TEXT"),
        ("child_revision_epoch", "INTEGER"),
        ("status", "TEXT NOT NULL DEFAULT 'running'"),
        ("terminal_event_id", "TEXT"),
        ("source_span_json", "TEXT"),
        ("updated_at", "TEXT"),
    ] {
        if !column_exists(connection, "workflow_invocations", column)? {
            connection.execute(
                &format!("ALTER TABLE workflow_invocations ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_fact_schema(connection: &Connection) -> StoreResult<()> {
    let facts_table_exists = connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'facts'",
            [],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !facts_table_exists {
        return Ok(());
    }
    if !column_exists(connection, "facts", "consumed_at")? {
        connection.execute("ALTER TABLE facts ADD COLUMN consumed_at TEXT", [])?;
    }
    for (column, definition) in [
        ("program_version_id", "TEXT"),
        ("revision_epoch", "INTEGER NOT NULL DEFAULT 0"),
        ("source_span_json", "TEXT"),
    ] {
        if !column_exists(connection, "facts", column)? {
            connection.execute(
                &format!("ALTER TABLE facts ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_diagnostics_schema(connection: &Connection) -> StoreResult<()> {
    for (column, definition) in [
        ("program_id", "TEXT"),
        ("program_version_id", "TEXT"),
        ("subject_type", "TEXT"),
        ("subject_id", "TEXT"),
        ("event_id", "TEXT"),
        ("effect_id", "TEXT"),
        ("run_id", "TEXT"),
        ("assertion_id", "TEXT"),
        ("evidence_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("artifact_ids_json", "TEXT NOT NULL DEFAULT '[]'"),
        ("causation_id", "TEXT"),
        ("correlation_id", "TEXT"),
        ("idempotency_key", "TEXT"),
    ] {
        if !column_exists(connection, "diagnostics", column)? {
            connection.execute(
                &format!("ALTER TABLE diagnostics ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }

    connection.execute_batch(
        r#"
        CREATE UNIQUE INDEX IF NOT EXISTS diagnostics_instance_idempotency_key_idx
            ON diagnostics(instance_id, idempotency_key)
            WHERE instance_id IS NOT NULL AND idempotency_key IS NOT NULL;

        CREATE UNIQUE INDEX IF NOT EXISTS diagnostics_program_idempotency_key_idx
            ON diagnostics(program_id, idempotency_key)
            WHERE instance_id IS NULL
              AND program_id IS NOT NULL
              AND program_version_id IS NULL
              AND idempotency_key IS NOT NULL;

        CREATE UNIQUE INDEX IF NOT EXISTS diagnostics_version_idempotency_key_idx
            ON diagnostics(program_version_id, idempotency_key)
            WHERE instance_id IS NULL AND program_version_id IS NOT NULL AND idempotency_key IS NOT NULL;
        "#,
    )?;
    Ok(())
}

#[cfg(feature = "native")]
fn column_exists(connection: &Connection, table: &str, column: &str) -> StoreResult<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<result::Result<Vec<_>, _>>()?;
    Ok(columns.iter().any(|name| name == column))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_scaffold_links_to_core() {
        assert_eq!(store_stage(), "release");
    }

    /// Drive the store through the `RuntimeStore` trait as a `&dyn` object:
    /// proves the trait is object-safe (a boxed durable-object backend is legal)
    /// and that its methods delegate to the inherent methods — the contract a
    /// DO-backed store satisfies. Spot-checks representative reads against known
    /// post-migration state.
    #[test]
    fn runtime_store_trait_seam_is_object_safe_and_faithful() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let runtime: &dyn RuntimeStore = &store;
        assert_eq!(runtime.schema_version().expect("version"), 1);
        assert!(runtime.table_exists("events").expect("table exists"));
        assert!(!runtime
            .fact_exists("no_such_instance", "no_such_fact")
            .expect("fact query"));
    }

    #[test]
    fn migrations_create_runtime_tables() {
        let store = SqliteStore::open_in_memory().expect("store opens");

        assert_eq!(store.schema_version().expect("version loads"), 1);
        for table in [
            "programs",
            "program_versions",
            "instances",
            "instance_revisions",
            "events",
            "facts",
            "effects",
            "effect_cancellation_requests",
            "effect_dependencies",
            "runs",
            "leases",
            "artifacts",
            "evidence",
            "evidence_links",
            "diagnostics",
            "package_registrations",
            "capability_schemas",
            "effect_providers",
            "profiles",
            "skills",
            "skill_attachments",
            "capability_bindings",
            "compute_result_cache",
            "content_blobs",
        ] {
            assert!(store.table_exists(table).expect("table lookup"), "{table}");
        }
    }

    /// DR-0054 Phase B: the supported-version constant and the migration list
    /// must move together — the downgrade guard compares against the constant,
    /// so a migration added without bumping it would refuse every fresh store.
    #[test]
    fn supported_schema_version_matches_the_highest_migration() {
        let highest = MIGRATIONS
            .iter()
            .map(|migration| migration.version)
            .max()
            .unwrap_or(0);
        assert_eq!(
            highest, SUPPORTED_SCHEMA_VERSION,
            "SUPPORTED_SCHEMA_VERSION must equal the highest MIGRATIONS version"
        );
    }

    /// DR-0054 Phase B downgrade guard: a store stamped with a migration
    /// version this build does not know refuses to open, naming both versions,
    /// and leaves the store untouched.
    #[test]
    fn store_stamped_by_a_newer_build_refuses_to_open() {
        let path = std::env::temp_dir().join(format!(
            "whipplescript-store-downgrade-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        drop(SqliteStore::open(&path).expect("fresh store opens"));
        {
            let connection = Connection::open(&path).expect("raw connection opens");
            connection
                .execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (99, 'from-the-future')",
                    [],
                )
                .expect("future stamp inserts");
        }

        let error = match SqliteStore::open(&path) {
            Err(error) => error,
            Ok(_) => panic!("newer-stamped store must refuse to open"),
        };
        match &error {
            StoreError::UnsupportedVersion {
                subject,
                found,
                supported,
            } => {
                assert_eq!(*found, 99);
                assert_eq!(*supported, SUPPORTED_SCHEMA_VERSION);
                assert!(
                    subject.contains("schema"),
                    "subject names what is versioned: {subject}"
                );
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }

        // Refusal mutated nothing: the future stamp (and the store) survive
        // for the build that understands them.
        let connection = Connection::open(&path).expect("store file still opens raw");
        let stamped: i64 = connection
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("stamp still present");
        assert_eq!(stamped, 99, "the refusing build must not rewrite the stamp");
        drop(connection);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    /// DR-0054 Phase B: every open records who wrote the store and in which
    /// event format, so a store found on disk is diagnosable without guessing.
    #[test]
    fn open_records_writer_and_format_version_in_store_meta() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let writer: String = store
            .connection
            .query_row(
                "SELECT value FROM store_meta WHERE key = 'writer_version'",
                [],
                |row| row.get(0),
            )
            .expect("writer_version recorded");
        assert_eq!(writer, WRITER_VERSION);
        let format: String = store
            .connection
            .query_row(
                "SELECT value FROM store_meta WHERE key = 'format_version'",
                [],
                |row| row.get(0),
            )
            .expect("format_version recorded");
        assert_eq!(format, SUPPORTED_EVENT_FORMAT_VERSION.to_string());
    }

    /// DR-0054 Phase B: new event rows carry the writer's format version; a
    /// row stamped beyond what this build supports fails the projection fold
    /// closed, naming the row, instead of misparsing it.
    #[test]
    fn future_event_format_version_fails_the_fold_with_row_identity() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("FormatGuard", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let event = store
            .append_event(NewEvent {
                instance_id: &instance.instance_id,
                event_type: "fact.derived",
                payload_json: r#"{"fact_id":"f1","name":"n","key":"k","value":{}}"#,
                source: "test",
                causation_id: None,
                correlation_id: None,
                idempotency_key: None,
            })
            .expect("event appends");

        // The writer stamped its format on the new row.
        let stamped: Option<i64> = store
            .connection
            .query_row(
                "SELECT format_version FROM events WHERE event_id = ?1",
                [&event.event_id],
                |row| row.get(0),
            )
            .expect("stamp readable");
        assert_eq!(stamped, Some(SUPPORTED_EVENT_FORMAT_VERSION));

        // A NULL (legacy) row folds fine...
        store
            .connection
            .execute(
                "UPDATE events SET format_version = NULL WHERE event_id = ?1",
                [&event.event_id],
            )
            .expect("regress to legacy NULL");
        store
            .rebuild_projections(&instance.instance_id)
            .expect("legacy NULL rows fold as version 1");

        // ...but a row from a newer format fails the fold closed with identity.
        store
            .connection
            .execute(
                "UPDATE events SET format_version = 99 WHERE event_id = ?1",
                [&event.event_id],
            )
            .expect("stamp future format");
        let error = store
            .rebuild_projections(&instance.instance_id)
            .expect_err("future-format row must fail the fold");
        match &error {
            StoreError::UnsupportedVersion {
                subject,
                found,
                supported,
            } => {
                assert_eq!(*found, 99);
                assert_eq!(*supported, SUPPORTED_EVENT_FORMAT_VERSION);
                assert!(
                    subject.contains(&event.event_id) && subject.contains(&instance.instance_id),
                    "subject carries the row identity: {subject}"
                );
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    /// Delta-kernel result cache (compute plane P8-1): a recorded content key
    /// is served back on lookup, and insertion is first-writer-wins — the
    /// existing entry stays canonical, mirroring the Maude model's
    /// at-most-one-run-per-key invariant (compute-result-cache.maude I1).
    #[test]
    fn compute_result_cache_roundtrip_and_first_writer_wins() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        assert_eq!(
            store
                .lookup_compute_result("key-1")
                .expect("lookup on empty cache"),
            None
        );

        let inserted = store
            .record_compute_result(ComputeResultRegistration {
                content_key: "key-1",
                effect_kind: "exec.command",
                result_json: r#"{"exit_code":0,"stdout":"first"}"#,
                source_instance_id: "instance-a",
                source_effect_id: "effect-1",
            })
            .expect("first record");
        assert!(inserted, "first writer inserts");

        let replay = store
            .record_compute_result(ComputeResultRegistration {
                content_key: "key-1",
                effect_kind: "exec.command",
                result_json: r#"{"exit_code":0,"stdout":"second"}"#,
                source_instance_id: "instance-b",
                source_effect_id: "effect-2",
            })
            .expect("second record");
        assert!(!replay, "second writer is ignored");

        let hit = store
            .lookup_compute_result("key-1")
            .expect("lookup")
            .expect("entry exists");
        assert_eq!(hit.result_json, r#"{"exit_code":0,"stdout":"first"}"#);
        assert_eq!(hit.source_instance_id, "instance-a");
        assert_eq!(hit.source_effect_id, "effect-1");
        assert_eq!(hit.effect_kind, "exec.command");
        assert_eq!(
            store.lookup_compute_result("key-2").expect("other key"),
            None
        );
    }

    /// Restorable-context RC-1: the file-history blob seam is content-addressed,
    /// dedups, and — the load-bearing property — a superseded body SURVIVES being
    /// overwritten. Capturing body Y after body X leaves BOTH retrievable by hash,
    /// which is exactly what a later restore slice reads through. The returned id
    /// is the same `stable_hash_hex` the `file.write.completed` fact records, so a
    /// manifest hash always resolves to its bytes (INV-4 coherence).
    #[test]
    fn content_blob_seam_dedups_and_preserves_superseded_bodies() {
        let store = SqliteStore::open_in_memory().expect("store opens");

        assert_eq!(
            store.get_content("deadbeef").expect("get on empty store"),
            None
        );

        // First write of a path: body X is captured, retrievable by its hash.
        let id_x = store.put_content("body X").expect("capture X");
        assert_eq!(id_x, stable_hash_hex("body X"), "id is the content hash");
        assert_eq!(
            store.get_content(&id_x).expect("get X").as_deref(),
            Some("body X")
        );

        // Overwriting the path with body Y captures Y WITHOUT losing X — history
        // survives the overwrite (the whole point of RC-1).
        let id_y = store.put_content("body Y").expect("capture Y");
        assert_ne!(id_x, id_y);
        assert_eq!(
            store.get_content(&id_x).expect("get X after Y").as_deref(),
            Some("body X")
        );
        assert_eq!(
            store.get_content(&id_y).expect("get Y").as_deref(),
            Some("body Y")
        );

        // Writing the same bytes again dedups to one row / one id.
        let id_x_again = store.put_content("body X").expect("recapture X");
        assert_eq!(id_x, id_x_again, "identical bytes dedupe to one id");
    }

    #[cfg(unix)]
    #[test]
    fn opening_file_store_hardens_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "whipplescript-store-permissions-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock is after epoch")
                .as_nanos()
        ));
        fs::write(&path, "").expect("precreated store file writes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("precreated permissions set");

        let store = SqliteStore::open(&path).expect("file store opens");
        let mode = fs::metadata(&path)
            .expect("store metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        drop(store);
        fs::remove_file(path).expect("store file removes");
    }

    #[test]
    fn append_events_assigns_per_instance_sequences() {
        let store = SqliteStore::open_in_memory().expect("store opens");

        let first = store
            .append_event(new_event("instance-a", "external.started", None))
            .expect("first event appends");
        let second = store
            .append_event(new_event("instance-a", "rule.fired", None))
            .expect("second event appends");
        let other = store
            .append_event(new_event("instance-b", "external.started", None))
            .expect("other instance event appends");

        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        assert_eq!(other.sequence, 1);
        assert_ne!(first.event_id, second.event_id);
    }

    #[test]
    fn duplicate_event_idempotency_key_is_rejected_per_instance() {
        let store = SqliteStore::open_in_memory().expect("store opens");

        store
            .append_event(new_event("instance-a", "external.started", Some("start")))
            .expect("first event appends");
        let duplicate =
            store.append_event(new_event("instance-a", "external.started", Some("start")));
        store
            .append_event(new_event("instance-b", "external.started", Some("start")))
            .expect("same key on another instance is allowed");

        assert!(duplicate.is_err());
    }

    #[test]
    fn derives_fact_atomically_from_event() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let event = store
            .derive_fact(DerivedFact {
                instance_id: "instance-a",
                fact: test_fact("fact-started", "pattern:started", "started"),
                source: "external",
                causation_id: None,
                idempotency_key: Some("derive-started"),
            })
            .expect("fact derives");

        assert_eq!(event.sequence, 1);
        assert!(store
            .fact_exists("instance-a", "pattern:started")
            .expect("fact query"));
        assert_eq!(row_count(&store, "facts"), 1);
    }

    #[test]
    fn admit_fact_batch_admits_atomically_and_is_per_row_idempotent() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let rows = [
            FactBatchRow {
                fact_id: "imp:row:0",
                key: "0",
                value_json: r#"{"title":"a"}"#,
            },
            FactBatchRow {
                fact_id: "imp:row:1",
                key: "1",
                value_json: r#"{"title":"b"}"#,
            },
        ];
        let batch = FactBatch {
            instance_id: "instance-a",
            source: "kernel",
            causation_id: None,
            correlation_id: Some("effect-1"),
            schema_name: "IssueRow",
            schema_id: Some("IssueRow"),
            rows: &rows,
        };

        let first = store.admit_fact_batch(batch).expect("batch admits");
        assert_eq!(first.admitted, 2);
        assert_eq!(first.skipped, 0);
        assert_eq!(row_count(&store, "facts"), 2);

        // Re-admitting the same batch admits nothing (each derived key is already
        // present) -- the idempotency the Maude importRow model proves.
        let second = store.admit_fact_batch(batch).expect("re-admit");
        assert_eq!(second.admitted, 0);
        assert_eq!(second.skipped, 2);
        assert_eq!(row_count(&store, "facts"), 2);

        // A batch overlapping the admitted set admits only the fresh rows.
        let overlap_rows = [
            rows[1],
            FactBatchRow {
                fact_id: "imp:row:2",
                key: "2",
                value_json: r#"{"title":"c"}"#,
            },
        ];
        let overlap = FactBatch {
            rows: &overlap_rows,
            ..batch
        };
        let third = store.admit_fact_batch(overlap).expect("overlap admits");
        assert_eq!(third.admitted, 1);
        assert_eq!(third.skipped, 1);
        assert_eq!(row_count(&store, "facts"), 3);

        let facts = store.list_facts("instance-a").expect("facts");
        assert_eq!(
            facts.iter().filter(|fact| fact.name == "IssueRow").count(),
            3
        );
    }

    /// The batch-admission ruling (Jack 2026-07-24, DR-0044 alignment): the
    /// per-row fact_id skip is REPLAY-scoped (same admission re-running never
    /// re-admits), while a NEW admission (fresh effect → fresh fact_ids) of a
    /// CONSUMED identical row revives it as a fresh admission via
    /// insert_fact's revive clause — and a LIVE identical row counts
    /// `skipped`, not `admitted` (a no-op re-assertion).
    #[test]
    fn admit_fact_batch_readmits_consumed_rows_under_a_new_admission() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let rows = [FactBatchRow {
            fact_id: "imp1:row:0",
            key: "0",
            value_json: r#"{"title":"a"}"#,
        }];
        let first_batch = FactBatch {
            instance_id: "instance-a",
            source: "kernel",
            causation_id: None,
            correlation_id: Some("effect-1"),
            schema_name: "IssueRow",
            schema_id: Some("IssueRow"),
            rows: &rows,
        };
        let first = store.admit_fact_batch(first_batch).expect("batch admits");
        assert_eq!((first.admitted, first.skipped), (1, 0));

        // A NEW admission while the row is LIVE: no-op re-assertion, skipped.
        let live_rows = [FactBatchRow {
            fact_id: "imp2:row:0",
            key: "0",
            value_json: r#"{"title":"a"}"#,
        }];
        let live_again = FactBatch {
            correlation_id: Some("effect-2"),
            rows: &live_rows,
            ..first_batch
        };
        let second = store.admit_fact_batch(live_again).expect("live re-import");
        assert_eq!((second.admitted, second.skipped), (0, 1));
        let live = store.list_facts("instance-a").expect("facts");
        assert_eq!(live[0].fact_id, "imp1:row:0", "live row untouched");

        // Consume the fact, then re-import via a THIRD admission: fresh
        // admission — the row revives carrying the new fact_id.
        store
            .retire_fact("instance-a", "imp1:row:0")
            .expect("consumes");
        assert!(store.list_facts("instance-a").expect("facts").is_empty());
        let readmit_rows = [FactBatchRow {
            fact_id: "imp3:row:0",
            key: "0",
            value_json: r#"{"title":"a"}"#,
        }];
        let readmit = FactBatch {
            correlation_id: Some("effect-3"),
            rows: &readmit_rows,
            ..first_batch
        };
        let third = store.admit_fact_batch(readmit).expect("re-admits");
        assert_eq!((third.admitted, third.skipped), (1, 0));
        let revived = store.list_facts("instance-a").expect("facts");
        assert_eq!(revived.len(), 1);
        assert_eq!(revived[0].fact_id, "imp3:row:0", "new admission identity");
    }

    #[test]
    fn creates_program_versions_and_instances() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");

        let version = store
            .create_program_version(test_program_version("Ralph", "source-1", "ir-1"))
            .expect("program version creates");
        let same_version = store
            .create_program_version(test_program_version("Ralph", "source-1", "ir-1"))
            .expect("matching program version reuses existing row");
        let next_version = store
            .create_program_version(test_program_version("Ralph", "source-2", "ir-2"))
            .expect("second program version creates");
        let instance = store
            .create_instance_with_authority(
                NewInstance {
                    program_id: &version.program_id,
                    version_id: &version.version_id,
                    input_json: r#"{"issue":"one"}"#,
                },
                NewInstanceAuthority {
                    workflow_principal: "workflow:local/Ralph",
                    effective_authority_json: r#"["workflow:local/Ralph"]"#,
                },
            )
            .expect("instance creates");

        assert_eq!(version.version_id, same_version.version_id);
        assert_eq!(version.program_id, next_version.program_id);
        assert_ne!(version.version_id, next_version.version_id);
        assert!(instance.instance_id.starts_with("ins_"));
        assert_eq!(instance.status, "running");
        assert_eq!(row_count(&store, "programs"), 1);
        assert_eq!(row_count(&store, "program_versions"), 2);
        assert_eq!(row_count(&store, "instances"), 1);
    }

    /// RC-4b on the EFFECTS plane: after a `context.restored` marker, the
    /// orphaned segment's effect rows vanish from both read paths — the
    /// restored timeline re-offers the rules instead of silently adopting
    /// orphaned outcomes, and the worker is never handed an orphaned
    /// pending effect. Work committed before the cut, and NEW work after
    /// the marker, stay live.
    #[test]
    fn restore_fold_hides_orphaned_effects_from_reads_and_claims() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        // Live segment: seq 1 commits eff-keep.
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "keep",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("eff-keep", "tracker.claim", "keep-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-keep"),
                marks: &[],
                context_json: None,
            })
            .expect("commit keep");
        // Orphaned-to-be segment: seq 2 commits eff-orphan.
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "orphan",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("eff-orphan", "tracker.claim", "orphan-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-orphan"),
                marks: &[],
                context_json: None,
            })
            .expect("commit orphan");
        assert_eq!(store.list_effects("instance-a").expect("list").len(), 2);

        // Restore to seq 1: the marker orphans the second commit.
        store
            .append_event(NewEvent {
                instance_id: "instance-a",
                event_type: "context.restored",
                payload_json: r#"{"cut_id":"cut-1","restored_to_sequence":1}"#,
                source: "test",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("restore-1"),
            })
            .expect("marker");
        let visible = store.list_effects("instance-a").expect("list");
        assert_eq!(
            visible
                .iter()
                .map(|effect| effect.effect_id.as_str())
                .collect::<Vec<_>>(),
            vec!["eff-keep"],
            "the orphaned segment's effect is invisible after the fold"
        );
        let claimable = store.claimable_effects("instance-a").expect("claimable");
        assert_eq!(
            claimable
                .iter()
                .map(|effect| effect.effect_id.as_str())
                .collect::<Vec<_>>(),
            vec!["eff-keep"],
            "the worker is never handed an orphaned pending effect"
        );

        // New work on the restored timeline stays live.
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "resume",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("eff-resume", "tracker.claim", "resume-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-resume"),
                marks: &[],
                context_json: None,
            })
            .expect("commit resume");
        let visible = store.list_effects("instance-a").expect("list");
        assert_eq!(
            visible
                .iter()
                .map(|effect| effect.effect_id.as_str())
                .collect::<Vec<_>>(),
            vec!["eff-keep", "eff-resume"],
            "post-restore work is live alongside the pre-cut segment"
        );
    }

    #[test]
    fn rule_commit_persists_event_fact_effect_and_dependency_atomically() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let facts = [test_fact("fact-ready", "issue", "issue-1")];
        let effects = [
            test_effect("claim", "tracker.claim", "rule=start;effect=claim"),
            test_effect("tell", "agent.tell", "rule=start;effect=tell"),
        ];
        let dependencies = [NewEffectDependency {
            dependency_id: "dep-claim-tell",
            upstream_effect_id: "claim",
            downstream_effect_id: "tell",
            predicate: "succeeds",
        }];

        let event = store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &facts,
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &dependencies,
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        assert_eq!(event.sequence, 1);
        assert_eq!(row_count(&store, "events"), 1);
        assert_eq!(row_count(&store, "facts"), 1);
        assert_eq!(row_count(&store, "effects"), 2);
        assert_eq!(row_count(&store, "effect_dependencies"), 1);
    }

    #[test]
    fn rule_commit_with_workflow_terminal_updates_instance_atomically() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Terminal", "source", "ir"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let event = store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "finish",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: Some(WorkflowTerminal {
                    kind: WorkflowTerminalKind::Completed,
                    name: "result",
                    payload_json: r#"{"status":"ok"}"#,
                    idempotency_key: Some("workflow-complete-result"),
                }),
                idempotency_key: Some("commit-finish"),
                marks: &[],
                context_json: None,
            })
            .expect("terminal commit succeeds");

        assert_eq!(event.sequence, 1);
        assert_eq!(instance_status(&store, &instance.instance_id), "completed");
        let event_type = store
            .connection
            .query_row(
                "SELECT event_type FROM events WHERE instance_id = ?1 AND sequence = 2",
                [&instance.instance_id],
                |row| row.get::<_, String>(0),
            )
            .expect("terminal event type");
        assert_eq!(event_type, "workflow.completed");

        let duplicate = store.commit_rule(RuleCommit {
            instance_id: &instance.instance_id,
            rule: "again",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &[],
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("commit-again"),
            marks: &[],
            context_json: None,
        });
        assert!(matches!(duplicate, Err(StoreError::Conflict(_))));
    }

    #[test]
    fn failed_rule_commit_rolls_back_partial_writes() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [
            test_effect("same-effect", "tracker.claim", "rule=bad;effect=one"),
            test_effect("same-effect", "agent.tell", "rule=bad;effect=two"),
        ];
        let result = store.commit_rule(RuleCommit {
            instance_id: "instance-a",
            rule: "bad",
            trigger_event_id: None,
            facts: &[],
            consumed_fact_ids: &[],
            effects: &effects,
            dependencies: &[],
            terminal: None,
            idempotency_key: Some("bad-commit"),
            marks: &[],
            context_json: None,
        });

        assert!(result.is_err());
        assert_eq!(row_count(&store, "events"), 0);
        assert_eq!(row_count(&store, "effects"), 0);
    }

    #[test]
    fn pending_effect_kinds_lists_nonterminal_and_excludes_settled() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[
                    test_effect("t", "agent.tell", "rule=start;effect=t"),
                    test_effect("s", "signal.emit", "rule=start;effect=s"),
                ],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        // Both queued effects are reported.
        let mut kinds = store.pending_effect_kinds().expect("pending kinds");
        kinds.sort();
        assert_eq!(
            kinds,
            vec!["agent.tell".to_owned(), "signal.emit".to_owned()]
        );

        // Settle one; a terminal effect drops out of the pending set.
        store
            .connection
            .execute(
                "UPDATE effects SET status = 'completed' WHERE effect_id = 't'",
                [],
            )
            .expect("settle effect");
        assert_eq!(
            store.pending_effect_kinds().expect("pending kinds"),
            vec!["signal.emit".to_owned()]
        );
    }

    #[test]
    fn block_effect_binding_is_idempotent_and_recoverable() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "rule=start;effect=tell")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        let effect = |store: &SqliteStore| {
            store
                .list_effects("instance-a")
                .expect("effects list")
                .into_iter()
                .find(|e| e.effect_id == "tell")
                .expect("tell effect")
        };
        let blocked_event_count = |store: &SqliteStore| -> i64 {
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE instance_id = 'instance-a' \
                     AND event_type = 'effect.blocked'",
                    [],
                    |row| row.get(0),
                )
                .expect("count")
        };
        assert_eq!(effect(&store).status, "queued");

        // First binding block: queued -> blocked, categorized, one event.
        let first = store
            .block_effect_binding(
                "instance-a",
                "tell",
                "credentials",
                "missing credentials_ref",
            )
            .expect("first block");
        let e = effect(&store);
        assert_eq!(e.status, "blocked");
        assert_eq!(e.policy_block_category.as_deref(), Some("credentials"));
        assert_eq!(
            e.policy_block_reason.as_deref(),
            Some("missing credentials_ref")
        );
        assert_eq!(blocked_event_count(&store), 1);

        // Idempotent re-block (same category): no new event, returns the same one.
        let second = store
            .block_effect_binding(
                "instance-a",
                "tell",
                "credentials",
                "missing credentials_ref",
            )
            .expect("re-block");
        assert_eq!(first.event_id, second.event_id, "re-block reuses the event");
        assert_eq!(blocked_event_count(&store), 1, "re-block adds no event");

        // Recoverable: a binding-blocked effect stays claimable so a later worker
        // pass retries once the binding is available.
        assert!(
            store
                .claimable_effects("instance-a")
                .expect("claimable")
                .iter()
                .any(|c| c.effect_id == "tell"),
            "blocked effect is re-claimable"
        );
    }

    #[test]
    fn replay_reconstructs_facts_effects_and_dependencies_from_events() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let facts = [test_fact("fact-ready", "issue", "issue-1")];
        let effects = [
            test_effect("claim", "tracker.claim", "rule=start;effect=claim"),
            test_effect("tell", "agent.tell", "rule=start;effect=tell"),
        ];
        let dependencies = [NewEffectDependency {
            dependency_id: "dep-claim-tell",
            upstream_effect_id: "claim",
            downstream_effect_id: "tell",
            predicate: "succeeds",
        }];

        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &facts,
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &dependencies,
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");
        store
            .derive_fact(DerivedFact {
                instance_id: "instance-a",
                fact: NewFact {
                    fact_id: "fact-derived",
                    name: "derived",
                    key: "derived-1",
                    value_json: r#"{"ok":true}"#,
                    schema_id: None,
                    provenance_class: "derived",
                    correlation_id: Some("claim"),
                    source_span_json: None,
                },
                source: "kernel",
                causation_id: None,
                idempotency_key: Some("derive-fact"),
            })
            .expect("derived fact succeeds");
        store
            .connection
            .execute("DELETE FROM effect_dependencies", [])
            .expect("dependencies clear");
        store
            .connection
            .execute("DELETE FROM effects", [])
            .expect("effects clear");
        store
            .connection
            .execute("DELETE FROM facts", [])
            .expect("facts clear");

        store
            .rebuild_projections("instance-a")
            .expect("projections rebuild");

        assert_eq!(row_count(&store, "events"), 2);
        assert_eq!(row_count(&store, "facts"), 2);
        assert_eq!(row_count(&store, "effects"), 2);
        assert_eq!(row_count(&store, "effect_dependencies"), 1);
        let rebuilt_facts = store.list_facts("instance-a").expect("facts list");
        assert!(rebuilt_facts.iter().any(|fact| {
            fact.fact_id == "fact-derived"
                && fact.name == "derived"
                && fact.value_json.contains(r#""ok":true"#)
        }));
    }

    #[test]
    fn rule_commit_consumes_facts_and_replay_preserves_consumption() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let facts = [test_fact("fact-task", "Task", "Task:queued")];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "seed",
                trigger_event_id: None,
                facts: &facts,
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-seed"),
                marks: &[],
                context_json: None,
            })
            .expect("seed commit succeeds");

        assert_eq!(
            store
                .list_facts("instance-a")
                .expect("active facts before consume")
                .len(),
            1
        );

        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "finish",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &["fact-task"],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-finish"),
                marks: &[],
                context_json: None,
            })
            .expect("consume commit succeeds");

        assert_eq!(
            store
                .list_facts("instance-a")
                .expect("active facts after consume")
                .len(),
            0
        );
        assert_eq!(row_count(&store, "facts"), 1);

        store
            .connection
            .execute("DELETE FROM facts", [])
            .expect("facts clear");
        store
            .rebuild_projections("instance-a")
            .expect("projections rebuild");

        assert_eq!(
            store
                .list_facts("instance-a")
                .expect("active replayed facts")
                .len(),
            0
        );
        assert_eq!(row_count(&store, "facts"), 1);
    }

    #[test]
    fn duplicate_terminal_completion_rolls_back_event() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [test_effect("tell", "agent.tell", "rule=start;effect=tell")];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        store
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-1",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-1",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .complete_effect(test_completion("run-1"))
            .expect("completion succeeds");
        let duplicate = store.complete_effect(test_completion("run-1"));

        assert!(duplicate.is_err());
        assert_eq!(row_count(&store, "events"), 3);
        assert_eq!(row_count(&store, "runs"), 1);
    }

    #[test]
    fn start_run_records_execution_fingerprint_distinct_from_effect_identity() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [
            test_effect("tell", "agent.tell", "rule=start;effect=tell"),
            NewEffect {
                input_json: r#"{"prompt":"different"}"#,
                ..test_effect("other", "agent.tell", "rule=start;effect=other")
            },
        ];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        store
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-1",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-1",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");

        // The run carries an execution fingerprint in its metadata (recorded with
        // the run for replay verification), distinct from the effect identity.
        let metadata: String = store
            .connection
            .query_row(
                "SELECT metadata_json FROM runs WHERE run_id = ?1",
                params!["run-1"],
                |row| row.get(0),
            )
            .expect("run row");
        let recorded: Value = serde_json::from_str(&metadata).expect("metadata json");
        let fingerprint = recorded
            .get("execution_fingerprint")
            .and_then(Value::as_str)
            .expect("execution_fingerprint recorded with the run");
        assert!(!fingerprint.is_empty());
        assert_ne!(
            fingerprint, "tell",
            "the fingerprint is not the effect id/idempotency key"
        );
        // It is the deterministic materialized-input fingerprint.
        assert_eq!(
            fingerprint,
            execution_fingerprint_on(&store.connection, "instance-a", "tell", None)
                .expect("recompute")
        );
        // A different materialized input is a different fingerprint.
        assert_ne!(
            execution_fingerprint_on(&store.connection, "instance-a", "tell", None)
                .expect("fp tell"),
            execution_fingerprint_on(&store.connection, "instance-a", "other", None)
                .expect("fp other"),
        );

        // DR-0014: the model salt makes the execution fingerprint model-sensitive
        // so a coercion whose only change is the model re-runs. An empty/absent
        // salt is byte-identical to the pre-salt fingerprint (every other effect).
        let base =
            execution_fingerprint_on(&store.connection, "instance-a", "tell", None).expect("base");
        assert_eq!(
            base,
            execution_fingerprint_on(&store.connection, "instance-a", "tell", Some(""))
                .expect("empty salt"),
            "an empty salt leaves the fingerprint unchanged",
        );
        assert_ne!(
            base,
            execution_fingerprint_on(&store.connection, "instance-a", "tell", Some("gpt-5"))
                .expect("salted"),
            "a model salt changes the fingerprint",
        );
        assert_ne!(
            execution_fingerprint_on(&store.connection, "instance-a", "tell", Some("gpt-5"))
                .expect("model a"),
            execution_fingerprint_on(&store.connection, "instance-a", "tell", Some("claude"))
                .expect("model b"),
            "different models produce different fingerprints",
        );
        // The salt is carried under the reserved run-metadata key.
        assert_eq!(
            fingerprint_salt_from_metadata(r#"{"__fingerprint_model":"gpt-5"}"#).as_deref(),
            Some("gpt-5"),
        );
        assert_eq!(fingerprint_salt_from_metadata("{}"), None);
        assert_eq!(
            fingerprint_salt_from_metadata(r#"{"__fingerprint_model":""}"#),
            None,
            "an empty model is treated as no salt",
        );
    }

    #[test]
    fn due_interval_occurrences_enumerates_each_due_tick_after_the_cursor() {
        let store = SqliteStore::open_in_memory().expect("store opens");

        // From the source start, every hour, three ticks are due by 12:00.
        let due = store
            .due_interval_occurrences("2026-06-18T09:00:00Z", 3600, "2026-06-18T12:00:00Z")
            .expect("due occurrences");
        assert_eq!(
            due,
            vec![
                "2026-06-18T10:00:00Z",
                "2026-06-18T11:00:00Z",
                "2026-06-18T12:00:00Z",
            ]
        );

        // From a cursor (last admitted tick), only later ticks are due.
        let after_cursor = store
            .due_interval_occurrences("2026-06-18T10:00:00Z", 3600, "2026-06-18T12:00:00Z")
            .expect("due after cursor");
        assert_eq!(
            after_cursor,
            vec!["2026-06-18T11:00:00Z", "2026-06-18T12:00:00Z"]
        );

        // Before the first tick is reached, nothing is due.
        let none_yet = store
            .due_interval_occurrences("2026-06-18T09:00:00Z", 3600, "2026-06-18T09:30:00Z")
            .expect("none yet");
        assert!(none_yet.is_empty());

        // A non-positive interval admits nothing (guard).
        assert!(store
            .due_interval_occurrences("2026-06-18T09:00:00Z", 0, "2026-06-18T12:00:00Z")
            .expect("zero interval")
            .is_empty());
    }

    #[test]
    fn contradictory_terminal_completion_rolls_back_event_even_with_distinct_key() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [test_effect("tell", "agent.tell", "rule=start;effect=tell")];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        store
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-1",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-1",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .complete_effect(EffectCompletion {
                idempotency_key: Some("provider-session-a:turn-a:terminal-hash-ok"),
                ..test_completion("run-1")
            })
            .expect("completion succeeds");
        let contradictory = store.complete_effect(EffectCompletion {
            status: "failed",
            exit_code: Some(1),
            summary: Some("provider reported a later failure"),
            metadata_json: r#"{"terminal_payload_hash":"different"}"#,
            idempotency_key: Some("provider-session-a:turn-a:terminal-hash-different"),
            ..test_completion("run-1")
        });

        assert!(contradictory.is_err());
        assert_eq!(row_count(&store, "events"), 3);
        let runs = store.list_runs("instance-a").expect("runs list");
        assert_eq!(runs[0].status, "completed");
        let terminal_events = store
            .list_events("instance-a")
            .expect("events list")
            .into_iter()
            .filter(|event| event.event_type == "effect.terminal")
            .collect::<Vec<_>>();
        assert_eq!(terminal_events.len(), 1);
        assert!(terminal_events[0]
            .payload_json
            .contains("\"summary\":\"done\""));
        assert!(!terminal_events[0]
            .payload_json
            .contains("provider reported a later failure"));
    }

    #[test]
    fn terminal_completion_requires_running_run() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [test_effect("tell", "agent.tell", "rule=start;effect=tell")];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        let completion = store.complete_effect(test_completion("run-1"));

        assert!(completion.is_err());
        assert_eq!(row_count(&store, "events"), 1);
        assert_eq!(row_count(&store, "runs"), 0);
        assert_eq!(effect_status(&store, "tell"), "queued");
    }

    #[test]
    fn scheduler_claims_only_dependency_satisfied_effects() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [
            test_effect("claim", "tracker.claim", "rule=start;effect=claim"),
            NewEffect {
                timeout_seconds: None,
                effect_id: "tell",
                kind: "agent.tell",
                target: Some("worker"),
                input_json: r#"{"prompt":"go"}"#,
                status: "blocked_by_dependency",
                idempotency_key: "rule=start;effect=tell",
                required_capabilities_json: "[]",
                profile: Some("repo-writer"),
                correlation_id: None,
                source_span_json: None,
            },
        ];
        let dependencies = [NewEffectDependency {
            dependency_id: "dep-claim-tell",
            upstream_effect_id: "claim",
            downstream_effect_id: "tell",
            predicate: "succeeds",
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &dependencies,
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        let claimable = store
            .claimable_effects("instance-a")
            .expect("claimable effects load");
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].effect_id, "claim");

        store
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "claim",
                run_id: "run-claim",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-claim",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("claim run starts");
        store
            .complete_effect(EffectCompletion {
                instance_id: "instance-a",
                effect_id: "claim",
                run_id: "run-claim",
                provider: "test",
                worker_id: "worker-1",
                status: "completed",
                exit_code: Some(0),
                summary: Some("claimed"),
                metadata_json: "{}",
                idempotency_key: Some("complete-claim"),
            })
            .expect("claim completes");

        assert_eq!(effect_status(&store, "tell"), "queued");
        let claimable = store
            .claimable_effects("instance-a")
            .expect("claimable effects reload");
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].effect_id, "tell");
        assert_eq!(lease_status(&store, "lease-claim"), "released");
    }

    #[test]
    fn timed_out_dependency_releases_only_on_timeout() {
        // A `timed_out` dependency predicate releases the downstream effect only
        // when the upstream reaches the `timed_out` terminal status, not on a
        // successful completion (terminal-union after-branch precision).
        for (instance, upstream_status, expect_claimable) in [
            ("ti-completed", "completed", false),
            ("ti-timedout", "timed_out", true),
        ] {
            let mut store = SqliteStore::open_in_memory().expect("store opens");
            let effects = [
                test_effect("up", "agent.tell", "rule=start;effect=up"),
                test_effect("down", "agent.tell", "rule=start;effect=down"),
            ];
            let dependencies = [NewEffectDependency {
                dependency_id: "dep-up-down",
                upstream_effect_id: "up",
                downstream_effect_id: "down",
                predicate: "timed_out",
            }];
            store
                .commit_rule(RuleCommit {
                    instance_id: instance,
                    rule: "start",
                    trigger_event_id: None,
                    facts: &[],
                    consumed_fact_ids: &[],
                    effects: &effects,
                    dependencies: &dependencies,
                    terminal: None,
                    idempotency_key: Some("commit-start"),
                    marks: &[],
                    context_json: None,
                })
                .expect("rule commit succeeds");
            store
                .start_run(RunStart {
                    instance_id: instance,
                    effect_id: "up",
                    run_id: "run-up",
                    provider: "test",
                    worker_id: "worker-1",
                    lease_id: "lease-up",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    metadata_json: "{}",
                })
                .expect("upstream run starts");
            store
                .complete_effect(EffectCompletion {
                    instance_id: instance,
                    effect_id: "up",
                    run_id: "run-up",
                    provider: "test",
                    worker_id: "worker-1",
                    status: upstream_status,
                    exit_code: None,
                    summary: None,
                    metadata_json: "{}",
                    idempotency_key: Some("complete-up"),
                })
                .expect("upstream reaches terminal");
            let claimable = store
                .claimable_effects(instance)
                .expect("claimable effects load");
            let down_claimable = claimable.iter().any(|e| e.effect_id == "down");
            assert_eq!(
                down_claimable, expect_claimable,
                "instance {instance}: upstream `{upstream_status}` should{} release the `timed_out` downstream",
                if expect_claimable { "" } else { " not" }
            );
        }
    }

    #[test]
    fn start_run_rejects_blocked_dependency_without_partial_event() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [
            test_effect("claim", "tracker.claim", "rule=start;effect=claim"),
            NewEffect {
                timeout_seconds: None,
                effect_id: "tell",
                kind: "agent.tell",
                target: Some("worker"),
                input_json: r#"{"prompt":"go"}"#,
                status: "blocked_by_dependency",
                idempotency_key: "rule=start;effect=tell",
                required_capabilities_json: "[]",
                profile: Some("repo-writer"),
                correlation_id: None,
                source_span_json: None,
            },
        ];
        let dependencies = [NewEffectDependency {
            dependency_id: "dep-claim-tell",
            upstream_effect_id: "claim",
            downstream_effect_id: "tell",
            predicate: "succeeds",
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &dependencies,
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        let result = store.start_run(RunStart {
            instance_id: "instance-a",
            effect_id: "tell",
            run_id: "run-tell",
            provider: "test",
            worker_id: "worker-1",
            lease_id: "lease-tell",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        });

        assert!(result.is_err());
        assert_eq!(row_count(&store, "events"), 1);
        assert_eq!(row_count(&store, "runs"), 0);
        assert_eq!(effect_status(&store, "tell"), "blocked_by_dependency");
    }

    #[test]
    fn transitions_instance_statuses_with_events() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Ralph", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        store
            .transition_instance(InstanceTransition {
                instance_id: &instance.instance_id,
                status: "paused",
                reason: Some("maintenance"),
                idempotency_key: Some("pause"),
            })
            .expect("instance pauses");
        store
            .transition_instance(InstanceTransition {
                instance_id: &instance.instance_id,
                status: "running",
                reason: None,
                idempotency_key: Some("resume"),
            })
            .expect("instance resumes");
        store
            .transition_instance(InstanceTransition {
                instance_id: &instance.instance_id,
                status: "cancelled",
                reason: Some("operator"),
                idempotency_key: Some("cancel-instance"),
            })
            .expect("instance cancels");

        assert_eq!(instance_status(&store, &instance.instance_id), "cancelled");
        assert_eq!(row_count(&store, "events"), 3);
    }

    #[test]
    fn start_run_rejects_non_running_instances() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Paused", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "rule=start;effect=tell")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .transition_instance(InstanceTransition {
                instance_id: &instance.instance_id,
                status: "paused",
                reason: Some("operator"),
                idempotency_key: Some("pause"),
            })
            .expect("instance pauses");

        let result = store.start_run(RunStart {
            instance_id: &instance.instance_id,
            effect_id: "tell",
            run_id: "run-tell",
            provider: "test",
            worker_id: "worker-1",
            lease_id: "lease-tell",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        });

        assert!(matches!(result, Err(StoreError::Conflict(message)) if message.contains("paused")));
        assert!(store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects")
            .is_empty());
    }

    #[test]
    fn terminal_instance_statuses_are_absorbing() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("TerminalGuard", "source-1", "ir-1"))
            .expect("program version creates");
        let completed = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        store
            .commit_rule(RuleCommit {
                instance_id: &completed.instance_id,
                rule: "finish",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: Some(WorkflowTerminal {
                    kind: WorkflowTerminalKind::Completed,
                    name: "result",
                    payload_json: "{}",
                    idempotency_key: Some("workflow-complete-terminal-guard"),
                }),
                idempotency_key: Some("commit-finish-terminal-guard"),
                marks: &[],
                context_json: None,
            })
            .expect("terminal commit succeeds");

        let cancel_completed = store.transition_instance(InstanceTransition {
            instance_id: &completed.instance_id,
            status: "cancelled",
            reason: Some("late cancel"),
            idempotency_key: Some("cancel-completed"),
        });

        assert!(matches!(
            cancel_completed,
            Err(StoreError::Conflict(message)) if message.contains("completed to cancelled")
        ));
        assert_eq!(instance_status(&store, &completed.instance_id), "completed");

        let cancelled = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .transition_instance(InstanceTransition {
                instance_id: &cancelled.instance_id,
                status: "cancelled",
                reason: Some("operator"),
                idempotency_key: Some("cancel-instance-terminal-guard"),
            })
            .expect("instance cancels");

        let resume_cancelled = store.transition_instance(InstanceTransition {
            instance_id: &cancelled.instance_id,
            status: "running",
            reason: None,
            idempotency_key: Some("resume-cancelled"),
        });

        assert!(matches!(
            resume_cancelled,
            Err(StoreError::Conflict(message)) if message.contains("cancelled to running")
        ));
        assert_eq!(instance_status(&store, &cancelled.instance_id), "cancelled");
    }

    #[test]
    fn activate_revision_updates_active_version_and_preserves_effect_attribution() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version("Revision", "source-1", "ir-1"))
            .expect("first program version creates");
        let version2 = store
            .create_program_version(test_program_version("Revision", "source-2", "ir-2"))
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "old-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("old-effect", "agent.tell", "old-effect-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-old"),
                marks: &[],
                context_json: None,
            })
            .expect("old rule commits");
        assert_eq!(
            effect_revision(&store, "old-effect"),
            (Some(version1.version_id.clone()), 0, false)
        );

        let revision = store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-keep"),
            })
            .expect("revision activates");
        assert_eq!(revision.epoch, 1);
        assert_eq!(revision.from_version_id, version1.version_id.as_str());
        assert_eq!(revision.to_version_id, version2.version_id.as_str());

        let active = store
            .get_instance(&instance.instance_id)
            .expect("instance loads")
            .expect("instance exists");
        assert_eq!(active.version_id, version2.version_id);
        assert_eq!(active.revision_epoch, 1);

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "new-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("new-effect", "agent.tell", "new-effect-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-new"),
                marks: &[],
                context_json: None,
            })
            .expect("new rule commits");

        assert_eq!(
            effect_revision(&store, "old-effect"),
            (Some(version1.version_id.clone()), 0, false)
        );
        assert_eq!(
            effect_revision(&store, "new-effect"),
            (Some(version2.version_id.clone()), 1, false)
        );
        let duplicate = store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-keep"),
            })
            .expect("idempotent revision returns existing row");
        assert_eq!(duplicate.revision_id, revision.revision_id);
        assert_eq!(row_count(&store, "instance_revisions"), 1);

        let reused_key = store.activate_revision(RevisionActivation {
            instance_id: &instance.instance_id,
            from_version_id: &version1.version_id,
            to_version_id: &version2.version_id,
            activation_policy_json: r#"{"changed":true}"#,
            cancellation_policy: "keep",
            idempotency_key: Some("revise-keep"),
        });
        assert!(matches!(
            reused_key,
            Err(StoreError::Conflict(message))
                if message.contains("idempotency key was reused")
        ));
        assert_eq!(row_count(&store, "instance_revisions"), 1);
    }

    #[test]
    fn guarded_rule_commit_rejects_stale_revision_epoch() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version("RevisionGuard", "source-1", "ir-1"))
            .expect("first program version creates");
        let version2 = store
            .create_program_version(test_program_version("RevisionGuard", "source-2", "ir-2"))
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-before-stale-commit"),
            })
            .expect("revision activates");

        let stale = store.commit_rule_with_revision_guard(
            RuleCommit {
                instance_id: &instance.instance_id,
                rule: "old-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect(
                    "stale-effect",
                    "agent.tell",
                    "stale-effect-key",
                )],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-stale"),
                marks: &[],
                context_json: None,
            },
            RuleCommitRevisionGuard {
                program_version_id: &version1.version_id,
                revision_epoch: 0,
            },
        );

        assert!(matches!(
            stale,
            Err(StoreError::Conflict(message))
                if message.contains("active revision changed before rule commit")
        ));
        assert_eq!(row_count(&store, "effects"), 0);
    }

    #[test]
    fn activate_revision_rechecks_compatibility_in_transaction() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version(
                "RevisionCompatTxn",
                "source-1",
                "ir-1",
            ))
            .expect("first program version creates");
        let incompatible_summary =
            r#"{"workflow":"OtherWorkflow","workflow_contracts":[],"schemas":[]}"#;
        let version2 = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: incompatible_summary,
                ..test_program_version("RevisionCompatTxn", "source-2", "ir-2")
            })
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let result = store.activate_revision(RevisionActivation {
            instance_id: &instance.instance_id,
            from_version_id: &version1.version_id,
            to_version_id: &version2.version_id,
            activation_policy_json: "{}",
            cancellation_policy: "keep",
            idempotency_key: Some("revise-incompatible-direct"),
        });

        assert!(matches!(
            result,
            Err(StoreError::Conflict(message))
                if message.contains("revision.root_workflow_changed")
        ));
        let active = store
            .get_instance(&instance.instance_id)
            .expect("instance loads")
            .expect("instance exists");
        assert_eq!(active.version_id, version1.version_id);
        assert_eq!(row_count(&store, "instance_revisions"), 0);
    }

    #[test]
    fn old_effect_policy_checks_use_effect_version_after_revision() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(NewProgramVersion {
                declared_profiles_json: r#"{"agents":[{"name":"worker","profile":"repo-writer","capacity":1,"capabilities":["agent.tell"]}]}"#,
                ..test_program_version("RevisionAgents", "source-1", "ir-1")
            })
            .expect("first program version creates");
        let version2 = store
            .create_program_version(NewProgramVersion {
                declared_profiles_json: r#"{"agents":[{"name":"other","profile":"repo-writer","capacity":1,"capabilities":["agent.tell"]}]}"#,
                ..test_program_version("RevisionAgents", "source-2", "ir-2")
            })
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "old-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("old-effect", "agent.tell", "old-effect-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-old"),
                marks: &[],
                context_json: None,
            })
            .expect("old rule commits");
        store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-agent-removal"),
            })
            .expect("revision activates");

        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "old-effect",
                run_id: "run-old",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-old",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("old effect uses old version declarations");
        store
            .complete_effect(EffectCompletion {
                instance_id: &instance.instance_id,
                effect_id: "old-effect",
                run_id: "run-old",
                provider: "test",
                worker_id: "worker-1",
                status: "completed",
                exit_code: Some(0),
                summary: Some("old done"),
                metadata_json: "{}",
                idempotency_key: Some("complete-old"),
            })
            .expect("old run completes");

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "new-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("new-effect", "agent.tell", "new-effect-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-new"),
                marks: &[],
                context_json: None,
            })
            .expect("new rule commits");
        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "new-effect",
                run_id: "run-new",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-new",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("new effect uses candidate declarations");

        assert!(
            matches!(blocked, StoreError::PolicyBlocked { reason, .. } if reason.contains("not declared"))
        );
        assert_eq!(effect_status(&store, "new-effect"), "blocked_by_profile");
    }

    #[test]
    fn revision_request_running_cancels_queued_and_requests_running_effects() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version("RevisionPolicy", "source-1", "ir-1"))
            .expect("first program version creates");
        let version2 = store
            .create_program_version(test_program_version("RevisionPolicy", "source-2", "ir-2"))
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effects = [
            test_effect("queued-effect", "agent.tell", "queued-effect-key"),
            test_effect("running-effect", "agent.tell", "running-effect-key"),
        ];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "old-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-policy-old"),
                marks: &[],
                context_json: None,
            })
            .expect("old rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "running-effect",
                run_id: "run-running",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-running",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");

        let impact = store
            .revision_cancellation_impact(&instance.instance_id, "running")
            .expect("revision impact reports");
        assert_eq!(impact.active_version_id, version1.version_id.as_str());
        assert_eq!(impact.active_revision_epoch, 0);
        assert_eq!(impact.cancellation_policy, "request_running");
        assert_eq!(impact.terminal_cancel_effects, vec!["queued-effect"]);
        assert_eq!(impact.request_cancel_effects, vec!["running-effect"]);

        let revision = store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "request_running",
                idempotency_key: Some("revise-request-running"),
            })
            .expect("revision activates");

        assert_eq!(revision.epoch, 1);
        assert_eq!(effect_status(&store, "queued-effect"), "cancelled");
        assert_eq!(effect_status(&store, "running-effect"), "running");
        let requests = store
            .list_effect_cancellation_requests(&instance.instance_id)
            .expect("requests list");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            effect_revision(&store, "running-effect"),
            (Some(version1.version_id.clone()), 0, true)
        );
        let runs = store
            .list_runs(&instance.instance_id)
            .expect("runs include request state");
        assert_eq!(runs.len(), 1);
        assert!(runs[0].cancel_requested);
        let evidence = store
            .list_evidence(&instance.instance_id)
            .expect("evidence lists");
        let revision_evidence = evidence
            .iter()
            .find(|evidence| evidence.kind == "workflow.revision.activated")
            .expect("revision evidence exists");
        let cancellation_evidence = evidence
            .iter()
            .find(|evidence| evidence.kind == "effect.cancellation.requested")
            .expect("cancellation request evidence exists");
        assert_eq!(revision_evidence.subject_id, revision.revision_id);
        assert_eq!(cancellation_evidence.subject_id, requests[0].request_id);
        let metadata =
            serde_json::from_str::<Value>(&revision_evidence.metadata_json).expect("metadata json");
        assert_eq!(
            metadata.get("from_version_id").and_then(Value::as_str),
            Some(version1.version_id.as_str())
        );
        assert_eq!(
            metadata.get("to_version_id").and_then(Value::as_str),
            Some(version2.version_id.as_str())
        );
        assert_eq!(
            metadata
                .get("terminal_cancel_effects")
                .and_then(Value::as_array)
                .and_then(|effects| effects.first())
                .and_then(Value::as_str),
            Some("queued-effect")
        );
        assert_eq!(
            metadata
                .get("cancellation_request_ids")
                .and_then(Value::as_array)
                .and_then(|requests| requests.first())
                .and_then(Value::as_str),
            Some(requests[0].request_id.as_str())
        );
        let cancellation_metadata =
            serde_json::from_str::<Value>(&cancellation_evidence.metadata_json)
                .expect("cancellation metadata json");
        assert_eq!(
            cancellation_metadata
                .get("active_run_ids")
                .and_then(Value::as_array)
                .and_then(|runs| runs.first())
                .and_then(Value::as_str),
            Some("run-running")
        );
        let links = store
            .list_evidence_links(&instance.instance_id)
            .expect("evidence links list");
        assert!(links.iter().any(|link| {
            link.evidence_id == revision_evidence.evidence_id
                && link.target_type == "program_version"
                && link.target_id == version1.version_id.as_str()
                && link.relation == "from_version"
        }));
        assert!(links.iter().any(|link| {
            link.evidence_id == revision_evidence.evidence_id
                && link.target_type == "program_version"
                && link.target_id == version2.version_id.as_str()
                && link.relation == "to_version"
        }));
        assert!(links.iter().any(|link| {
            link.evidence_id == revision_evidence.evidence_id
                && link.target_type == "effect"
                && link.target_id == "queued-effect"
                && link.relation == "terminal_cancelled"
        }));
        assert!(links.iter().any(|link| {
            link.evidence_id == revision_evidence.evidence_id
                && link.target_type == "effect"
                && link.target_id == "running-effect"
                && link.relation == "cancellation_requested"
        }));
        assert!(links.iter().any(|link| {
            link.evidence_id == revision_evidence.evidence_id
                && link.target_type == "effect_cancellation_request"
                && link.target_id == requests[0].request_id.as_str()
                && link.relation == "created"
        }));
        assert!(links.iter().any(|link| {
            link.evidence_id == cancellation_evidence.evidence_id
                && link.target_type == "effect"
                && link.target_id == "running-effect"
                && link.relation == "requested_cancellation"
        }));
        assert!(links.iter().any(|link| {
            link.evidence_id == cancellation_evidence.evidence_id
                && link.target_type == "run"
                && link.target_id == "run-running"
                && link.relation == "active_run"
        }));
        assert!(links.iter().any(|link| {
            link.evidence_id == cancellation_evidence.evidence_id
                && link.target_type == "workflow_revision"
                && link.target_id == revision.revision_id.as_str()
                && link.relation == "requested_by"
        }));

        store
            .expire_leases(&instance.instance_id, "2030-01-02T00:00:00Z")
            .expect("lease expires");
        assert_eq!(effect_status(&store, "running-effect"), "queued");
        assert!(
            store
                .claimable_effects(&instance.instance_id)
                .expect("claimable effects")
                .is_empty(),
            "cancel-requested effects must not become claimable after lease expiry"
        );
    }

    #[test]
    fn later_revision_policy_includes_effects_kept_across_prior_revisions() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version(
                "RevisionPolicyAll",
                "source-1",
                "ir-1",
            ))
            .expect("first program version creates");
        let version2 = store
            .create_program_version(test_program_version(
                "RevisionPolicyAll",
                "source-2",
                "ir-2",
            ))
            .expect("second program version creates");
        let version3 = store
            .create_program_version(test_program_version(
                "RevisionPolicyAll",
                "source-3",
                "ir-3",
            ))
            .expect("third program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effects = [
            test_effect("kept-queued", "agent.tell", "kept-queued-key"),
            test_effect("kept-running", "agent.tell", "kept-running-key"),
        ];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "old-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-kept-effects"),
                marks: &[],
                context_json: None,
            })
            .expect("old effects commit");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "kept-running",
                run_id: "run-kept-running",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-kept-running",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-keep-old-effects"),
            })
            .expect("first revision keeps existing work");

        let impact = store
            .revision_cancellation_impact(&instance.instance_id, "running")
            .expect("later revision impact reports");
        assert_eq!(impact.active_version_id, version2.version_id.as_str());
        assert_eq!(impact.terminal_cancel_effects, vec!["kept-queued"]);
        assert_eq!(impact.request_cancel_effects, vec!["kept-running"]);

        store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version2.version_id,
                to_version_id: &version3.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "running",
                idempotency_key: Some("revise-request-kept-effects"),
            })
            .expect("second revision applies policy to all existing old work");

        assert_eq!(effect_status(&store, "kept-queued"), "cancelled");
        assert_eq!(effect_status(&store, "kept-running"), "running");
        assert_eq!(
            effect_revision(&store, "kept-running"),
            (Some(version1.version_id.clone()), 0, true)
        );
    }

    #[test]
    fn cancellation_requests_are_idempotent_and_resolve_on_terminal_completion() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("RequestCancel", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "tell-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-request-cancel"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");

        let first = store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                revision_id: None,
                reason: Some("operator"),
                requested_by: "test",
                causation_event_id: None,
                idempotency_key: Some("request-cancel-tell"),
            })
            .expect("request records");
        let second = store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                revision_id: None,
                reason: Some("operator"),
                requested_by: "test",
                causation_event_id: None,
                idempotency_key: Some("request-cancel-tell"),
            })
            .expect("idempotent request returns existing row");

        assert_eq!(first.request_id, second.request_id);
        assert_eq!(row_count(&store, "effect_cancellation_requests"), 1);
        assert_eq!(
            effect_revision(&store, "tell"),
            (Some(version.version_id), 0, true)
        );

        store
            .complete_effect(EffectCompletion {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                status: "completed",
                exit_code: Some(0),
                summary: Some("done"),
                metadata_json: "{}",
                idempotency_key: Some("complete-requested-tell"),
            })
            .expect("completion succeeds");

        let requests = store
            .list_effect_cancellation_requests(&instance.instance_id)
            .expect("requests load");
        assert_eq!(requests[0].status, "terminal");
        assert_eq!(effect_status(&store, "tell"), "completed");
    }

    #[test]
    fn cancellation_request_after_terminal_completion_is_rejected() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version(
                "RequestCancelAfterTerminal",
                "source-1",
                "ir-1",
            ))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "tell-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-request-cancel-after-terminal"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .complete_effect(EffectCompletion {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                status: "completed",
                exit_code: Some(0),
                summary: Some("done"),
                metadata_json: "{}",
                idempotency_key: Some("complete-before-cancel-request"),
            })
            .expect("completion succeeds");

        let request = store.request_effect_cancellation(EffectCancellationRequest {
            instance_id: &instance.instance_id,
            effect_id: "tell",
            revision_id: None,
            reason: Some("too late"),
            requested_by: "test",
            causation_event_id: None,
            idempotency_key: Some("request-cancel-after-terminal"),
        });

        assert!(matches!(request, Err(StoreError::Conflict(_))));
        assert!(store
            .list_effect_cancellation_requests(&instance.instance_id)
            .expect("requests load")
            .is_empty());
        assert_eq!(effect_status(&store, "tell"), "completed");
    }

    #[test]
    fn cancellation_request_resolves_on_timeout_and_rejects_late_completion() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version(
                "RequestCancelThenTimeout",
                "source-1",
                "ir-1",
            ))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "tell-timeout-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-request-cancel-timeout"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell-timeout",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell-timeout",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                revision_id: None,
                reason: Some("operator"),
                requested_by: "operator",
                causation_event_id: None,
                idempotency_key: Some("request-cancel-before-timeout"),
            })
            .expect("cancellation requests");

        let timeout = store
            .complete_effect(EffectCompletion {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell-timeout",
                provider: "test",
                worker_id: "worker-1",
                status: "timed_out",
                exit_code: Some(124),
                summary: Some("provider timed out after cancellation request"),
                metadata_json: r#"{"cancellation":"timeout_after_request"}"#,
                idempotency_key: Some("timeout-after-cancel-request"),
            })
            .expect("timeout terminal succeeds");

        let requests = store
            .list_effect_cancellation_requests(&instance.instance_id)
            .expect("requests load");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].status, "terminal");
        assert_eq!(
            requests[0].resolved_by_event_id.as_deref(),
            Some(timeout.event_id.as_str())
        );
        assert_eq!(effect_status(&store, "tell"), "timed_out");
        assert_eq!(lease_status(&store, "lease-tell-timeout"), "released");

        let late_completion = store.complete_effect(EffectCompletion {
            instance_id: &instance.instance_id,
            effect_id: "tell",
            run_id: "run-tell-timeout",
            provider: "test",
            worker_id: "worker-1",
            status: "completed",
            exit_code: Some(0),
            summary: Some("late success"),
            metadata_json: "{}",
            idempotency_key: Some("late-success-after-timeout"),
        });
        assert!(matches!(
            late_completion,
            Err(StoreError::Conflict(message))
                if message == "run already has a terminal completion"
        ));
    }

    #[test]
    fn workflow_invocations_preserve_parent_and_child_revision_attribution() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let parent_version = store
            .create_program_version(test_program_version("InvokeRevision", "source-1", "ir-1"))
            .expect("parent program version creates");
        let child_version = store
            .create_program_version(test_program_version("InvokeRevision", "source-2", "ir-2"))
            .expect("child program version creates");
        let revised_parent_version = store
            .create_program_version(test_program_version("InvokeRevision", "source-3", "ir-3"))
            .expect("revised parent program version creates");
        let revised_child_version = store
            .create_program_version(test_program_version("InvokeRevision", "source-4", "ir-4"))
            .expect("revised child program version creates");
        let parent = store
            .create_instance(NewInstance {
                program_id: &parent_version.program_id,
                version_id: &parent_version.version_id,
                input_json: "{}",
            })
            .expect("parent instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &parent.instance_id,
                rule: "invoke-child",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect(
                    "invoke-child",
                    "workflow.invoke",
                    "invoke-child-key",
                )],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-invoke-child"),
                marks: &[],
                context_json: None,
            })
            .expect("parent invoke rule commits");
        let child = store
            .create_instance(NewInstance {
                program_id: &child_version.program_id,
                version_id: &child_version.version_id,
                input_json: r#"{"task":"child"}"#,
            })
            .expect("child instance creates");

        store
            .record_workflow_invocation(NewWorkflowInvocation {
                invocation_id: "inv-parent-child",
                parent_instance_id: &parent.instance_id,
                parent_effect_id: "invoke-child",
                child_instance_id: &child.instance_id,
                target_workflow: "Child",
                input_json: r#"{"task":"child"}"#,
                source_span_json: Some(r#"{"start":1,"end":6}"#),
                idempotency_key: "invoke-parent-child",
            })
            .expect("invocation records");

        let invocation = store
            .get_workflow_invocation(&parent.instance_id, "invoke-child")
            .expect("invocation loads")
            .expect("invocation exists");
        assert_eq!(
            invocation.parent_program_version_id.as_deref(),
            Some(parent_version.version_id.as_str())
        );
        assert_eq!(invocation.parent_revision_epoch, 0);
        assert_eq!(
            invocation.parent_active_program_version_id.as_deref(),
            Some(parent_version.version_id.as_str())
        );
        assert_eq!(invocation.parent_active_revision_epoch, Some(0));
        assert_eq!(
            invocation.child_program_version_id.as_deref(),
            Some(child_version.version_id.as_str())
        );
        assert_eq!(invocation.child_revision_epoch, Some(0));
        assert_eq!(
            invocation.child_active_program_version_id.as_deref(),
            Some(child_version.version_id.as_str())
        );
        assert_eq!(invocation.child_active_revision_epoch, Some(0));

        store
            .activate_revision(RevisionActivation {
                instance_id: &parent.instance_id,
                from_version_id: &parent_version.version_id,
                to_version_id: &revised_parent_version.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-parent-after-invoke"),
            })
            .expect("parent revision activates");
        let after_revision = store
            .get_workflow_invocation(&parent.instance_id, "invoke-child")
            .expect("invocation reloads")
            .expect("invocation still exists");
        assert_eq!(
            after_revision.parent_program_version_id.as_deref(),
            Some(parent_version.version_id.as_str())
        );
        assert_eq!(after_revision.parent_revision_epoch, 0);
        assert_eq!(
            after_revision.parent_active_program_version_id.as_deref(),
            Some(revised_parent_version.version_id.as_str())
        );
        assert_eq!(after_revision.parent_active_revision_epoch, Some(1));
        assert_eq!(
            after_revision.child_program_version_id.as_deref(),
            Some(child_version.version_id.as_str())
        );
        assert_eq!(after_revision.child_revision_epoch, Some(0));
        assert_eq!(
            after_revision.child_active_program_version_id.as_deref(),
            Some(child_version.version_id.as_str())
        );
        assert_eq!(after_revision.child_active_revision_epoch, Some(0));

        store
            .activate_revision(RevisionActivation {
                instance_id: &child.instance_id,
                from_version_id: &child_version.version_id,
                to_version_id: &revised_child_version.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-child-after-invoke"),
            })
            .expect("child revision activates");
        let after_child_revision = store
            .get_workflow_invocation(&parent.instance_id, "invoke-child")
            .expect("invocation reloads after child revision")
            .expect("invocation still exists after child revision");
        assert_eq!(
            after_child_revision.parent_program_version_id.as_deref(),
            Some(parent_version.version_id.as_str())
        );
        assert_eq!(after_child_revision.parent_revision_epoch, 0);
        assert_eq!(
            after_child_revision
                .parent_active_program_version_id
                .as_deref(),
            Some(revised_parent_version.version_id.as_str())
        );
        assert_eq!(after_child_revision.parent_active_revision_epoch, Some(1));
        assert_eq!(
            after_child_revision.child_program_version_id.as_deref(),
            Some(child_version.version_id.as_str())
        );
        assert_eq!(after_child_revision.child_revision_epoch, Some(0));
        assert_eq!(
            after_child_revision
                .child_active_program_version_id
                .as_deref(),
            Some(revised_child_version.version_id.as_str())
        );
        assert_eq!(after_child_revision.child_active_revision_epoch, Some(1));
    }

    #[test]
    fn revision_compatibility_accepts_same_root_and_additive_terminals() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let active_summary = json!({
            "workflow": "Compat",
            "workflow_contracts": [
                {"kind": "input", "name": "request", "type": "ref<Request>"},
                {"kind": "output", "name": "done", "type": "ref<Result>"},
                {"kind": "failure", "name": "failed", "type": "ref<Failure>"}
            ]
        })
        .to_string();
        let candidate_summary = json!({
            "workflow": "Compat",
            "workflow_contracts": [
                {"kind": "input", "name": "request", "type": "ref<Request>"},
                {"kind": "output", "name": "done", "type": "ref<Result>"},
                {"kind": "output", "name": "skipped", "type": "ref<Result>"},
                {"kind": "failure", "name": "failed", "type": "ref<Failure>"}
            ]
        })
        .to_string();
        let active_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &active_summary,
                ..test_program_version("Compat", "source-1", "ir-1")
            })
            .expect("active version creates");
        let candidate_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &candidate_summary,
                ..test_program_version("Compat", "source-2", "ir-2")
            })
            .expect("candidate version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &active_version.program_id,
                version_id: &active_version.version_id,
                input_json: r#"{"request":{"id":"1"}}"#,
            })
            .expect("instance creates");

        let report = store
            .analyze_revision_compatibility(&instance.instance_id, &candidate_version.version_id)
            .expect("compatibility report");
        assert!(report.compatible);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn revision_compatibility_reports_root_and_contract_breaks() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let active_summary = json!({
            "workflow": "Compat",
            "workflow_contracts": [
                {"kind": "input", "name": "request", "type": "ref<Request>", "source_span": {"start": 1, "end": 10, "construct": "workflow_contract"}},
                {"kind": "output", "name": "done", "type": "ref<Result>", "source_span": {"start": 11, "end": 20, "construct": "workflow_contract"}},
                {"kind": "failure", "name": "failed", "type": "ref<Failure>", "source_span": {"start": 21, "end": 30, "construct": "workflow_contract"}}
            ]
        })
        .to_string();
        let candidate_summary = json!({
            "workflow": "Other",
            "workflow_contracts": [
                {"kind": "input", "name": "request", "type": "ref<ChangedRequest>", "source_span": {"start": 31, "end": 40, "construct": "workflow_contract"}},
                {"kind": "input", "name": "extra", "type": "string", "source_span": {"start": 41, "end": 50, "construct": "workflow_contract"}},
                {"kind": "failure", "name": "failed", "type": "ref<Failure>", "source_span": {"start": 51, "end": 60, "construct": "workflow_contract"}}
            ]
        })
        .to_string();
        let active_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &active_summary,
                ..test_program_version("CompatBreak", "source-1", "ir-1")
            })
            .expect("active version creates");
        let candidate_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &candidate_summary,
                ..test_program_version("CompatBreak", "source-2", "ir-2")
            })
            .expect("candidate version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &active_version.program_id,
                version_id: &active_version.version_id,
                input_json: r#"{"request":{"id":"1"}}"#,
            })
            .expect("instance creates");

        let report = store
            .analyze_revision_compatibility(&instance.instance_id, &candidate_version.version_id)
            .expect("compatibility report");
        assert!(!report.compatible);
        let codes = report
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect::<BTreeSet<_>>();
        assert!(codes.contains("revision.root_workflow_changed"));
        assert!(codes.contains("revision.contract_changed"));
        assert!(codes.contains("revision.input_contract_added"));
        assert!(codes.contains("revision.contract_removed"));
        let changed = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "revision.contract_changed")
            .expect("contract change diagnostic");
        assert_eq!(
            changed
                .source_span_json
                .as_deref()
                .and_then(|span| serde_json::from_str::<Value>(span).ok())
                .and_then(|span| span.get("start").and_then(Value::as_u64)),
            Some(31)
        );
        let removed = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "revision.contract_removed")
            .expect("contract removed diagnostic");
        assert_eq!(
            removed
                .source_span_json
                .as_deref()
                .and_then(|span| serde_json::from_str::<Value>(span).ok())
                .and_then(|span| span.get("start").and_then(Value::as_u64)),
            Some(11)
        );
    }

    #[test]
    fn revision_compatibility_accepts_optional_schema_additions_for_active_facts() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let active_summary = json!({
            "workflow": "FactCompat",
            "schemas": [
                {
                    "kind": "class",
                    "name": "WorkItem",
                    "fields": [
                        {"name": "title", "type": "string"}
                    ]
                }
            ]
        })
        .to_string();
        let candidate_summary = json!({
            "workflow": "FactCompat",
            "schemas": [
                {
                    "kind": "class",
                    "name": "WorkItem",
                    "fields": [
                        {"name": "title", "type": "string"},
                        {"name": "notes", "type": "optional<string>"}
                    ]
                }
            ]
        })
        .to_string();
        let active_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &active_summary,
                ..test_program_version("FactCompat", "source-1", "ir-1")
            })
            .expect("active version creates");
        let candidate_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &candidate_summary,
                ..test_program_version("FactCompat", "source-2", "ir-2")
            })
            .expect("candidate version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &active_version.program_id,
                version_id: &active_version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "seed",
                trigger_event_id: None,
                facts: &[test_fact("fact-work", "WorkItem", "work-1")],
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-work"),
                marks: &[],
                context_json: None,
            })
            .expect("fact commits");

        let report = store
            .analyze_revision_compatibility(&instance.instance_id, &candidate_version.version_id)
            .expect("compatibility report");

        assert!(report.compatible, "{:#?}", report.diagnostics);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn revision_compatibility_reports_active_fact_schema_breaks() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let active_summary = json!({
            "workflow": "FactBreak",
            "schemas": [
                {
                    "kind": "class",
                    "name": "WorkItem",
                    "fields": [
                        {"name": "title", "type": "string"}
                    ]
                },
                {
                    "kind": "enum",
                    "name": "State",
                    "variants": ["open", "closed"]
                }
            ]
        })
        .to_string();
        let changed_summary = json!({
            "workflow": "FactBreak",
            "schemas": [
                {
                    "kind": "class",
                    "name": "WorkItem",
                    "fields": [
                        {"name": "title", "type": "int"},
                        {"name": "status", "type": "string"}
                    ]
                },
                {
                    "kind": "enum",
                    "name": "State",
                    "variants": ["closed"]
                }
            ]
        })
        .to_string();
        let removed_summary = json!({
            "workflow": "FactBreak",
            "schemas": []
        })
        .to_string();
        let active_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &active_summary,
                ..test_program_version("FactBreak", "source-1", "ir-1")
            })
            .expect("active version creates");
        let changed_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &changed_summary,
                ..test_program_version("FactBreak", "source-2", "ir-2")
            })
            .expect("changed candidate version creates");
        let removed_version = store
            .create_program_version(NewProgramVersion {
                analysis_summary_json: &removed_summary,
                ..test_program_version("FactBreak", "source-3", "ir-3")
            })
            .expect("removed candidate version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &active_version.program_id,
                version_id: &active_version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "seed",
                trigger_event_id: None,
                facts: &[
                    test_fact("fact-work", "WorkItem", "work-1"),
                    NewFact {
                        fact_id: "fact-state",
                        name: "State",
                        key: "state-1",
                        value_json: r#""open""#,
                        schema_id: Some("State"),
                        provenance_class: "derived",
                        correlation_id: None,
                        source_span_json: None,
                    },
                ],
                consumed_fact_ids: &[],
                effects: &[],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-work"),
                marks: &[],
                context_json: None,
            })
            .expect("fact commits");

        let changed_report = store
            .analyze_revision_compatibility(&instance.instance_id, &changed_version.version_id)
            .expect("changed compatibility report");
        assert!(!changed_report.compatible);
        let changed = changed_report
            .diagnostics
            .iter()
            .find(|diagnostic| {
                diagnostic.code == "revision.active_fact_incompatible"
                    && diagnostic.subject.as_deref() == Some("WorkItem")
            })
            .expect("active fact incompatibility diagnostic");
        assert_eq!(changed.subject.as_deref(), Some("WorkItem"));
        assert!(changed.message.contains("$.title must be int"));
        assert!(changed.message.contains("$.status is required"));
        assert!(changed_report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "revision.active_fact_incompatible"
                && diagnostic.subject.as_deref() == Some("State")
                && diagnostic
                    .message
                    .contains("enum variant `open` not declared")
        }));

        let removed_report = store
            .analyze_revision_compatibility(&instance.instance_id, &removed_version.version_id)
            .expect("removed compatibility report");
        assert!(!removed_report.compatible);
        assert!(removed_report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "revision.active_fact_schema_removed"
                && diagnostic.subject.as_deref() == Some("WorkItem")
        }));
    }

    #[test]
    fn terminal_instances_cannot_activate_revisions() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version("TerminalRevision", "source-1", "ir-1"))
            .expect("first program version creates");
        let version2 = store
            .create_program_version(test_program_version("TerminalRevision", "source-2", "ir-2"))
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .transition_instance(InstanceTransition {
                instance_id: &instance.instance_id,
                status: "cancelled",
                reason: Some("operator"),
                idempotency_key: Some("cancel-before-revision"),
            })
            .expect("instance cancels");

        let result = store.activate_revision(RevisionActivation {
            instance_id: &instance.instance_id,
            from_version_id: &version1.version_id,
            to_version_id: &version2.version_id,
            activation_policy_json: "{}",
            cancellation_policy: "keep",
            idempotency_key: Some("revise-terminal"),
        });

        assert!(matches!(
            result,
            Err(StoreError::Conflict(message)) if message.contains("cancelled")
        ));
        assert_eq!(row_count(&store, "instance_revisions"), 0);
    }

    #[test]
    fn replay_reconstructs_active_revision_cancelled_effects_and_requests() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version(
                "RevisionReplayFull",
                "source-1",
                "ir-1",
            ))
            .expect("first program version creates");
        let version2 = store
            .create_program_version(test_program_version(
                "RevisionReplayFull",
                "source-2",
                "ir-2",
            ))
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [
            test_effect("queued-effect", "agent.tell", "replay-queued-key"),
            test_effect("running-effect", "agent.tell", "replay-running-key"),
        ];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "old-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-replay-full-old"),
                marks: &[],
                context_json: None,
            })
            .expect("old rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "running-effect",
                run_id: "run-replay-running",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-replay-running",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "request_running",
                idempotency_key: Some("revise-replay-full"),
            })
            .expect("revision activates");

        store
            .connection
            .execute("DELETE FROM effect_cancellation_requests", [])
            .expect("requests clear");
        store
            .connection
            .execute("DELETE FROM instance_revisions", [])
            .expect("revisions clear");
        store
            .connection
            .execute("DELETE FROM leases", [])
            .expect("leases clear");
        store
            .connection
            .execute("DELETE FROM runs", [])
            .expect("runs clear");
        store
            .connection
            .execute("DELETE FROM effects", [])
            .expect("effects clear");
        store
            .connection
            .execute(
                "UPDATE instances SET version_id = ?1, revision_epoch = 0 WHERE instance_id = ?2",
                params![&version1.version_id, &instance.instance_id],
            )
            .expect("active revision cache corrupts");

        store
            .rebuild_projections(&instance.instance_id)
            .expect("projections rebuild");

        let active = store
            .get_instance(&instance.instance_id)
            .expect("instance loads")
            .expect("instance exists");
        assert_eq!(active.version_id, version2.version_id);
        assert_eq!(active.revision_epoch, 1);
        assert_eq!(
            store
                .list_instance_revisions(&instance.instance_id)
                .expect("revisions list")
                .len(),
            1
        );
        assert_eq!(effect_status(&store, "queued-effect"), "cancelled");
        assert_eq!(
            effect_revision(&store, "running-effect"),
            (Some(version1.version_id), 0, true)
        );
        assert_eq!(
            store
                .list_effect_cancellation_requests(&instance.instance_id)
                .expect("requests list")
                .len(),
            1
        );
        let runs = store
            .list_runs(&instance.instance_id)
            .expect("runs rebuild from run-start event");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "running");
        assert!(runs[0].cancel_requested);
        assert_eq!(lease_status(&store, "lease-replay-running"), "active");
    }

    #[test]
    fn rebuild_projections_to_reconstructs_instance_state_as_of_sequence() {
        // RC-2 Delta A: bounded replay reflects instance state AS OF event N —
        // an effect committed AFTER N is absent; one at/before N is present.
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("BoundedReplay", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effect_exists = |store: &SqliteStore, effect_id: &str| -> bool {
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM effects WHERE effect_id = ?1",
                    [effect_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("effect count")
                > 0
        };

        // Commit effect A, then effect B at a strictly later event sequence.
        let commit_a = store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "rule-a",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("effect-a", "agent.tell", "bounded-key-a")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-bounded-a"),
                marks: &[],
                context_json: None,
            })
            .expect("effect A commits");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "rule-b",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("effect-b", "agent.tell", "bounded-key-b")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-bounded-b"),
                marks: &[],
                context_json: None,
            })
            .expect("effect B commits");

        // Cut AT effect A's commit sequence: A is in, B (later) is out.
        store
            .rebuild_projections_to(&instance.instance_id, commit_a.sequence)
            .expect("bounded projections rebuild");
        assert!(
            effect_exists(&store, "effect-a"),
            "effect A (<= N) present after bounded rebuild"
        );
        assert!(
            !effect_exists(&store, "effect-b"),
            "effect B (> N) absent after bounded rebuild"
        );

        // Unbounded rebuild restores the full current state (both effects).
        store
            .rebuild_projections(&instance.instance_id)
            .expect("unbounded projections rebuild");
        assert!(
            effect_exists(&store, "effect-a"),
            "effect A present in full"
        );
        assert!(
            effect_exists(&store, "effect-b"),
            "effect B present in full"
        );
    }

    #[test]
    fn rebuild_projections_honors_restore_marker_excluding_the_abandoned_branch() {
        // RC-4b: an unbounded rebuild folds `context.restored` markers — an
        // effect committed AFTER the cut but BEFORE the marker is abandoned and
        // never re-applied, while post-restore work survives. This is the
        // append-only-log coherence the model proves
        // (models/maude/restore-replay.maude).
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("RestoreFold", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effect_exists = |store: &SqliteStore, effect_id: &str| -> bool {
            store
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM effects WHERE effect_id = ?1",
                    [effect_id],
                    |row| row.get::<_, i64>(0),
                )
                .expect("effect count")
                > 0
        };

        // Effect A at the cut, then effect B (the branch to abandon).
        let commit_a = store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "rule-a",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("effect-a", "agent.tell", "restore-key-a")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-restore-a"),
                marks: &[],
                context_json: None,
            })
            .expect("effect A commits");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "rule-b",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("effect-b", "agent.tell", "restore-key-b")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-restore-b"),
                marks: &[],
                context_json: None,
            })
            .expect("effect B commits");

        // A restore marker rewinding to A's sequence: B (later) is abandoned.
        let marker_payload = json!({ "restored_to_sequence": commit_a.sequence }).to_string();
        store
            .append_event(NewEvent {
                instance_id: &instance.instance_id,
                event_type: "context.restored",
                payload_json: &marker_payload,
                source: "restorable-context",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("restore-marker-1"),
            })
            .expect("restore marker appends");

        // Post-restore work: effect C, committed after the marker, stays live.
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "rule-c",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("effect-c", "agent.tell", "restore-key-c")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-restore-c"),
                marks: &[],
                context_json: None,
            })
            .expect("effect C commits");

        store
            .rebuild_projections(&instance.instance_id)
            .expect("marker-aware rebuild");
        assert!(
            effect_exists(&store, "effect-a"),
            "effect A (<= cut) survives the restore"
        );
        assert!(
            !effect_exists(&store, "effect-b"),
            "effect B (abandoned branch) is excluded by the marker"
        );
        assert!(
            effect_exists(&store, "effect-c"),
            "effect C (post-restore work) stays live"
        );
    }

    #[test]
    fn capture_checkpoint_folds_manifest_and_records_cut_at_quiescence() {
        // RC-3: at a quiescent point, capture folds the file manifest from the
        // file.write.completed facts (latest-write-wins per path), stores it
        // content-addressed (INV-4: hash present), and records the
        // context.checkpoint cut carrier whose sequence is the cut coordinate.
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Checkpoint", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        // Helper: derive a file.write.completed fact for `path` -> `content_hash`
        // in the RC-1 payload shape (write descriptor nested at value.value).
        let write_fact = |store: &mut SqliteStore, key: &str, path: &str, content_hash: &str| {
            let value_json = json!({
                "effect_id": key,
                "run_id": format!("run-{key}"),
                "status": "completed",
                "value": { "store": "workspace", "path": path, "content_hash": content_hash },
            })
            .to_string();
            store
                .derive_fact(DerivedFact {
                    instance_id: &instance.instance_id,
                    fact: NewFact {
                        fact_id: key,
                        name: "file.write.completed",
                        key,
                        value_json: &value_json,
                        schema_id: None,
                        provenance_class: "derived",
                        correlation_id: None,
                        source_span_json: None,
                    },
                    source: "kernel",
                    causation_id: None,
                    idempotency_key: Some(key),
                })
                .expect("file.write.completed fact derives")
        };

        write_fact(&mut store, "w-a1", "a.txt", "hash-a1");
        write_fact(&mut store, "w-b1", "b.txt", "hash-b1");
        // Overwrite a.txt: the later write must supersede the earlier hash.
        let last = write_fact(&mut store, "w-a2", "a.txt", "hash-a2");

        let checkpoint = store
            .capture_checkpoint(CheckpointCapture {
                instance_id: &instance.instance_id,
                cut_id: "cut-1",
                transcript_ref: Some("step-7"),
                idempotency_key: Some("checkpoint-cut-1"),
            })
            .expect("checkpoint captures at quiescence");

        assert_eq!(checkpoint.cut_id, "cut-1");
        assert_eq!(
            checkpoint.file_count, 2,
            "two distinct paths in the manifest"
        );
        assert!(
            checkpoint.sequence > last.sequence,
            "checkpoint event is the latest sequence (the cut coordinate)"
        );

        // INV-4: the manifest hash the cut names is present in the blob store,
        // and it is exactly the latest-wins path->hash map.
        let manifest_body = store
            .get_content(&checkpoint.manifest_hash)
            .expect("manifest blob read")
            .expect("manifest blob present");
        let manifest: BTreeMap<String, String> =
            serde_json::from_str(&manifest_body).expect("manifest parses");
        assert_eq!(manifest.get("a.txt").map(String::as_str), Some("hash-a2"));
        assert_eq!(manifest.get("b.txt").map(String::as_str), Some("hash-b1"));

        // The cut carrier is a context.checkpoint event at the returned sequence.
        let event_type: String = store
            .connection
            .query_row(
                "SELECT event_type FROM events WHERE instance_id = ?1 AND sequence = ?2",
                params![instance.instance_id, checkpoint.sequence],
                |row| row.get(0),
            )
            .expect("checkpoint event row");
        assert_eq!(event_type, "context.checkpoint");

        // The cut carrier is NOT a state-changing event: replaying to its own
        // sequence reproduces the same manifest fold (it is a no-op for the fold).
        store
            .rebuild_projections_to(&instance.instance_id, checkpoint.sequence)
            .expect("bounded replay to the cut");
        assert!(
            store
                .fact_exists(&instance.instance_id, "file.write.completed")
                .expect("fact exists check"),
            "file.write.completed facts survive replay to the cut"
        );
    }

    #[test]
    fn capture_checkpoint_refuses_when_an_effect_is_in_flight() {
        // RC-3 INV-2 (no-in-flight straddle): a checkpoint is only a consistent
        // cut at a quiescent point. With an effect mid-run, capture refuses.
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("CheckpointBusy", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "checkpoint-busy-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-checkpoint-busy"),
                marks: &[],
                context_json: None,
            })
            .expect("effect commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-busy",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-busy",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts (effect now running)");

        let refused = store.capture_checkpoint(CheckpointCapture {
            instance_id: &instance.instance_id,
            cut_id: "cut-busy",
            transcript_ref: None,
            idempotency_key: None,
        });
        assert!(
            matches!(refused, Err(StoreError::Conflict(_))),
            "checkpoint refuses while an effect is running, got {refused:?}"
        );
    }

    // RC-4c helper: record a mediated file write — put the body content-addressed
    // (so `plan_restore` can read it back) and derive the matching
    // file.write.completed fact with `content_hash = stable_hash_hex(body)`.
    #[cfg(test)]
    fn record_file_write(
        store: &mut SqliteStore,
        instance_id: &str,
        key: &str,
        path: &str,
        body: &str,
    ) {
        let content_hash = store.put_content(body).expect("blob captures");
        let value_json = json!({
            "effect_id": key,
            "run_id": format!("run-{key}"),
            "status": "completed",
            "value": { "store": "workspace", "path": path, "content_hash": content_hash },
        })
        .to_string();
        store
            .derive_fact(DerivedFact {
                instance_id,
                fact: NewFact {
                    fact_id: key,
                    name: "file.write.completed",
                    key,
                    value_json: &value_json,
                    schema_id: None,
                    provenance_class: "derived",
                    correlation_id: None,
                    source_span_json: None,
                },
                source: "kernel",
                causation_id: None,
                idempotency_key: Some(key),
            })
            .expect("file.write.completed fact derives");
    }

    #[test]
    fn plan_restore_reconciles_files_and_commit_restore_rewinds_the_planes() {
        // RC-4c: plan_restore returns the full reconcile (write manifest paths
        // to cut content, remove post-cut mediated files) and commit_restore's
        // marker rewinds the file plane so a later checkpoint hashes to the cut.
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("RestorePlan", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let id = &instance.instance_id;

        // File plane at the cut: a.txt=A1, b.txt=B1.
        record_file_write(&mut store, id, "w-a1", "a.txt", "A1");
        record_file_write(&mut store, id, "w-b1", "b.txt", "B1");
        let cut = store
            .capture_checkpoint(CheckpointCapture {
                instance_id: id,
                cut_id: "cut-1",
                transcript_ref: Some("step-3"),
                idempotency_key: Some("checkpoint-cut-1"),
            })
            .expect("checkpoint captures");

        // Post-cut work: overwrite a.txt, create c.txt.
        record_file_write(&mut store, id, "w-a2", "a.txt", "A2");
        record_file_write(&mut store, id, "w-c1", "c.txt", "C1");

        let plan = match store.plan_restore(id, "cut-1").expect("plan resolves") {
            RestoreDecision::Ready(plan) => plan,
            RestoreDecision::Refused { reason } => panic!("unexpected refusal: {reason}"),
        };
        assert_eq!(plan.restored_to_sequence, cut.sequence);
        assert_eq!(plan.transcript_ref.as_deref(), Some("step-3"));
        // writes restore every manifest path to its CUT content (a.txt back to A1).
        assert_eq!(plan.writes.get("a.txt").map(String::as_str), Some("A1"));
        assert_eq!(plan.writes.get("b.txt").map(String::as_str), Some("B1"));
        assert_eq!(plan.writes.len(), 2);
        // removes = mediated paths present now but absent from the cut (c.txt).
        assert_eq!(plan.removes, vec!["c.txt".to_owned()]);

        // Commit the restore: the marker rewinds the file plane so a fresh
        // checkpoint of the (marker-folded) manifest hashes to the cut manifest.
        store
            .commit_restore(id, plan.restored_to_sequence, "cut-1", Some("restore-1"))
            .expect("restore commits");
        let after = store
            .capture_checkpoint(CheckpointCapture {
                instance_id: id,
                cut_id: "cut-after",
                transcript_ref: None,
                idempotency_key: Some("checkpoint-after"),
            })
            .expect("post-restore checkpoint");
        assert_eq!(
            after.manifest_hash, cut.manifest_hash,
            "the file plane rewound to the cut (a.txt=A2 and c.txt abandoned)"
        );
        assert_eq!(after.file_count, 2);
    }

    #[test]
    fn plan_restore_refuses_unknown_cut_and_dangling_manifest() {
        // RC-4c INV-4: an unknown cut or a missing referenced blob refuses the
        // whole restore, with no mutation.
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("RestoreRefuse", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let id = &instance.instance_id;

        assert!(
            matches!(
                store.plan_restore(id, "nope").expect("plan resolves"),
                RestoreDecision::Refused { .. }
            ),
            "unknown cut refuses"
        );

        record_file_write(&mut store, id, "w-a1", "a.txt", "A1");
        let content_hash = stable_hash_hex("A1");
        store
            .capture_checkpoint(CheckpointCapture {
                instance_id: id,
                cut_id: "cut-1",
                transcript_ref: None,
                idempotency_key: Some("checkpoint-cut-1"),
            })
            .expect("checkpoint captures");
        // Evict the referenced content blob: the manifest is now dangling.
        store
            .connection
            .execute(
                "DELETE FROM content_blobs WHERE id = ?1",
                [content_hash.as_str()],
            )
            .expect("evict blob");
        assert!(
            matches!(
                store.plan_restore(id, "cut-1").expect("plan resolves"),
                RestoreDecision::Refused { .. }
            ),
            "dangling manifest refuses (INV-4 coherence)"
        );
    }

    #[test]
    fn replay_reconstructs_terminal_runs_leases_and_resolved_cancel_requests() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version(
                "RevisionReplayTerminal",
                "source-1",
                "ir-1",
            ))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "terminal-replay-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-terminal-replay"),
                marks: &[],
                context_json: None,
            })
            .expect("effect commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-terminal-replay",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-terminal-replay",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                revision_id: None,
                reason: Some("operator"),
                requested_by: "operator",
                causation_event_id: None,
                idempotency_key: Some("request-terminal-replay"),
            })
            .expect("cancellation requests");
        store
            .complete_effect(EffectCompletion {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-terminal-replay",
                provider: "test",
                worker_id: "worker-1",
                status: "completed",
                exit_code: Some(0),
                summary: Some("done"),
                metadata_json: r#"{"ok":true}"#,
                idempotency_key: Some("complete-terminal-replay"),
            })
            .expect("effect completes");

        store
            .rebuild_projections(&instance.instance_id)
            .expect("live projections rebuild");

        assert_eq!(effect_status(&store, "tell"), "completed");
        let runs = store
            .list_runs(&instance.instance_id)
            .expect("runs list after replay");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "completed");
        assert!(!runs[0].cancel_requested);
        assert_eq!(lease_status(&store, "lease-terminal-replay"), "released");
        let requests = store
            .list_effect_cancellation_requests(&instance.instance_id)
            .expect("requests replay");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].status, "terminal");
        assert!(requests[0].resolved_by_event_id.is_some());
    }

    #[test]
    fn replay_reconstructs_expired_leases_without_reclaiming_cancel_requested_effects() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version(
                "RevisionReplayLeaseExpired",
                "source-1",
                "ir-1",
            ))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "lease-replay-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-lease-replay"),
                marks: &[],
                context_json: None,
            })
            .expect("effect commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-lease-replay",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-lease-replay",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                revision_id: None,
                reason: Some("operator"),
                requested_by: "operator",
                causation_event_id: None,
                idempotency_key: Some("request-lease-replay"),
            })
            .expect("cancellation requests");
        store
            .expire_leases(&instance.instance_id, "2030-01-02T00:00:00Z")
            .expect("lease expires");

        store
            .rebuild_projections(&instance.instance_id)
            .expect("live projections rebuild");

        assert_eq!(effect_status(&store, "tell"), "queued");
        assert_eq!(lease_status(&store, "lease-lease-replay"), "expired");
        let runs = store
            .list_runs(&instance.instance_id)
            .expect("runs list after replay");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, "lease_expired");
        assert!(runs[0].cancel_requested);
        assert!(
            store
                .claimable_effects(&instance.instance_id)
                .expect("claimable effects")
                .is_empty(),
            "cancel-requested effects must not become claimable after replayed lease expiry"
        );
    }

    #[test]
    fn replay_preserves_rule_commit_revision_attribution() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version1 = store
            .create_program_version(test_program_version("RevisionReplay", "source-1", "ir-1"))
            .expect("first program version creates");
        let version2 = store
            .create_program_version(test_program_version("RevisionReplay", "source-2", "ir-2"))
            .expect("second program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version1.program_id,
                version_id: &version1.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "old-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("old-effect", "agent.tell", "old-effect-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-replay-old"),
                marks: &[],
                context_json: None,
            })
            .expect("old rule commits");
        store
            .activate_revision(RevisionActivation {
                instance_id: &instance.instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                idempotency_key: Some("revise-replay"),
            })
            .expect("revision activates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "new-rule",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("new-effect", "agent.tell", "new-effect-key")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-replay-new"),
                marks: &[],
                context_json: None,
            })
            .expect("new rule commits");

        store
            .connection
            .execute("DELETE FROM effects", [])
            .expect("effects clear");
        store
            .rebuild_projections(&instance.instance_id)
            .expect("projections rebuild");

        assert_eq!(
            effect_revision(&store, "old-effect"),
            (Some(version1.version_id), 0, false)
        );
        assert_eq!(
            effect_revision(&store, "new-effect"),
            (Some(version2.version_id), 1, false)
        );
    }

    #[test]
    fn cancel_effect_marks_non_terminal_effect_and_releases_completes_dependencies() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [
            test_effect("cleanup", "agent.tell", "rule=start;effect=cleanup"),
            NewEffect {
                timeout_seconds: None,
                effect_id: "notify",
                kind: "agent.tell",
                target: Some("worker"),
                input_json: r#"{"prompt":"notify"}"#,
                status: "blocked_by_dependency",
                idempotency_key: "rule=start;effect=notify",
                required_capabilities_json: "[]",
                profile: Some("repo-writer"),
                correlation_id: None,
                source_span_json: None,
            },
        ];
        let dependencies = [NewEffectDependency {
            dependency_id: "dep-cleanup-notify",
            upstream_effect_id: "cleanup",
            downstream_effect_id: "notify",
            predicate: "completes",
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &dependencies,
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");

        store
            .cancel_effect(EffectCancellation {
                instance_id: "instance-a",
                effect_id: "cleanup",
                reason: Some("operator"),
                idempotency_key: Some("cancel-cleanup"),
            })
            .expect("effect cancels");

        assert_eq!(effect_status(&store, "cleanup"), "cancelled");
        assert_eq!(effect_status(&store, "notify"), "queued");
    }

    #[test]
    fn renews_and_expires_leases_for_recovery() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [test_effect("tell", "agent.tell", "rule=start;effect=tell")];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");
        store
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");

        store
            .renew_lease(LeaseRenewal {
                instance_id: "instance-a",
                lease_id: "lease-tell",
                run_id: "run-tell",
                new_expires_at: "2030-01-02T00:00:00Z",
                idempotency_key: Some("renew-lease"),
            })
            .expect("lease renews");
        let not_expired = store
            .expire_leases("instance-a", "2030-01-01T12:00:00Z")
            .expect("expiry scans");
        assert!(not_expired.is_empty());

        let expired = store
            .expire_leases("instance-a", "2030-01-03T00:00:00Z")
            .expect("lease expires");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].run_id, "run-tell");
        assert_eq!(effect_status(&store, "tell"), "queued");
        assert_eq!(lease_status(&store, "lease-tell"), "expired");
    }

    #[test]
    fn retries_failed_effects_through_backoff_gate() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let effects = [test_effect("tell", "agent.tell", "rule=start;effect=tell")];
        store
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commit succeeds");
        store
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        store
            .complete_effect(EffectCompletion {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                status: "failed",
                exit_code: Some(1),
                summary: Some("failed"),
                metadata_json: "{}",
                idempotency_key: Some("fail-tell"),
            })
            .expect("effect fails");
        assert_eq!(effect_status(&store, "tell"), "failed");

        store
            .retry_effect(RetryEffect {
                instance_id: "instance-a",
                effect_id: "tell",
                retry_after: Some("2030-01-01T00:00:00Z"),
                idempotency_key: Some("retry-tell"),
            })
            .expect("effect retries");
        assert_eq!(effect_status(&store, "tell"), "queued");

        store
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell-2",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell-2",
                lease_expires_at: "2030-01-02T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("retry run starts");
        store
            .complete_effect(EffectCompletion {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell-2",
                provider: "test",
                worker_id: "worker-1",
                status: "completed",
                exit_code: Some(0),
                summary: Some("retry completed"),
                metadata_json: "{}",
                idempotency_key: Some("complete-tell-2"),
            })
            .expect("retry run completes");
        assert_eq!(effect_status(&store, "tell"), "completed");
    }

    #[test]
    fn inspection_views_report_instance_state() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let declared_profiles_json = r#"{"harnesses":[{"name":"coder","kind":"codex"}],"agents":[{"name":"worker","profile":"repo-writer","capacity":1,"harness":"coder","capabilities":["agent.tell"]}]}"#;
        let mut program_version = test_program_version("Ralph", "source-1", "ir-1");
        program_version.declared_profiles_json = declared_profiles_json;
        let version = store
            .create_program_version(program_version)
            .expect("program version creates");
        let instance = store
            .create_instance_with_authority(
                NewInstance {
                    program_id: &version.program_id,
                    version_id: &version.version_id,
                    input_json: r#"{"issue":"one"}"#,
                },
                NewInstanceAuthority {
                    workflow_principal: "workflow:local/Ralph",
                    effective_authority_json: r#"["workflow:local/Ralph"]"#,
                },
            )
            .expect("instance creates");
        let instance_id = instance.instance_id;

        store
            .derive_fact(DerivedFact {
                instance_id: &instance_id,
                fact: test_fact("fact-started", "pattern:started", "started"),
                source: "external",
                causation_id: None,
                idempotency_key: Some("derive-started"),
            })
            .expect("fact derives");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "rule=start;effect=tell")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let run_metadata_json = r#"{"native_provider":{"provider_id":"coder","provider_kind":"codex","surface":"codex.app_server"}}"#;
        store
            .start_run(RunStart {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: run_metadata_json,
            })
            .expect("run starts");

        let instances = store.list_instances().expect("instances list");
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].instance_id, instance_id);
        assert_eq!(instances[0].status, "running");
        assert_eq!(instances[0].workflow_principal, "workflow:local/Ralph");
        assert_eq!(
            instances[0].effective_authority_json,
            r#"["workflow:local/Ralph"]"#
        );

        let facts = store.list_facts(&instance_id).expect("facts list");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].name, "pattern:started");

        let effects = store.list_effects(&instance_id).expect("effects list");
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].effect_id, "tell");
        assert_eq!(effects[0].status, "running");
        assert_eq!(effects[0].declared_profiles_json, declared_profiles_json);

        let runs = store.list_runs(&instance_id).expect("runs list");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].run_id, "run-tell");
        assert_eq!(runs[0].status, "running");
        // The caller-provided run metadata is preserved, and the run additionally
        // records an execution fingerprint (see start_run / execution_fingerprint_on).
        let run_metadata: Value =
            serde_json::from_str(&runs[0].metadata_json).expect("run metadata json");
        let expected_metadata: Value =
            serde_json::from_str(run_metadata_json).expect("expected metadata json");
        assert_eq!(
            run_metadata.get("native_provider"),
            expected_metadata.get("native_provider")
        );
        assert!(run_metadata
            .get("execution_fingerprint")
            .and_then(Value::as_str)
            .is_some_and(|fingerprint| !fingerprint.is_empty()));
        assert!(!runs[0].cancel_requested);

        let events = store.list_events(&instance_id).expect("events list");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 1);

        let status = store
            .status(&instance_id)
            .expect("status loads")
            .expect("instance exists");
        assert_eq!(status.fact_count, 1);
        assert_eq!(status.queued_effect_count, 0);
        assert_eq!(status.blocked_effect_count, 0);
        assert_eq!(status.active_run_count, 1);
        assert_eq!(status.failure_count, 0);
        assert_eq!(status.recent_events.len(), 3);
    }

    #[test]
    fn records_lists_and_deduplicates_diagnostics_with_links() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Diagnostics", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "rule=start;effect=tell")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let run_event = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let artifact_id = store
            .record_artifact(ArtifactRecord {
                run_id: "run-tell",
                kind: "transcript",
                path: "artifacts/run-tell.txt",
                content_hash: Some("sha256:abc"),
                mime_type: Some("text/plain"),
            })
            .expect("artifact records");
        let evidence_id = store
            .record_evidence(EvidenceRecord {
                instance_id: &instance.instance_id,
                kind: "provider_failure",
                subject_type: "run",
                subject_id: "run-tell",
                causation_id: Some("tell"),
                correlation_id: Some("corr-tell"),
                summary: Some("provider failed"),
                metadata_json: r#"{"stderr":"boom"}"#,
            })
            .expect("evidence records");
        let evidence_ids_json = format!(r#"["{evidence_id}"]"#);
        let artifact_ids_json = format!(r#"["{artifact_id}"]"#);

        let diagnostic_id = store
            .record_diagnostic(DiagnosticRecord {
                instance_id: Some(&instance.instance_id),
                program_id: Some(&version.program_id),
                program_version_id: Some(&version.version_id),
                severity: Severity::Error,
                code: Some("provider.transport"),
                message: "provider transport failed",
                source_span_json: Some(
                    r#"{"path":"workflow.whip","start":{"line":3,"column":5},"end":{"line":3,"column":18},"construct":"effect"}"#,
                ),
                subject_type: Some("effect"),
                subject_id: Some("tell"),
                event_id: Some(&run_event.event_id),
                effect_id: Some("tell"),
                run_id: Some("run-tell"),
                assertion_id: None,
                evidence_ids_json: &evidence_ids_json,
                artifact_ids_json: &artifact_ids_json,
                causation_id: Some("tell"),
                correlation_id: Some("corr-tell"),
                idempotency_key: Some("diagnostic:run-tell"),
            })
            .expect("diagnostic records");
        let duplicate_id = store
            .record_diagnostic(DiagnosticRecord {
                message: "different retry message",
                ..DiagnosticRecord {
                    instance_id: Some(&instance.instance_id),
                    program_id: Some(&version.program_id),
                    program_version_id: Some(&version.version_id),
                    severity: Severity::Error,
                    code: Some("provider.transport"),
                    message: "provider transport failed",
                    source_span_json: None,
                    subject_type: Some("effect"),
                    subject_id: Some("tell"),
                    event_id: Some(&run_event.event_id),
                    effect_id: Some("tell"),
                    run_id: Some("run-tell"),
                    assertion_id: None,
                    evidence_ids_json: &evidence_ids_json,
                    artifact_ids_json: &artifact_ids_json,
                    causation_id: Some("tell"),
                    correlation_id: Some("corr-tell"),
                    idempotency_key: Some("diagnostic:run-tell"),
                }
            })
            .expect("duplicate diagnostic returns existing row");

        assert_eq!(diagnostic_id, duplicate_id);
        let diagnostics = store
            .list_diagnostics(Some(&instance.instance_id))
            .expect("diagnostics list");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].diagnostic_id, diagnostic_id);
        assert_eq!(diagnostics[0].severity, "error");
        assert_eq!(diagnostics[0].code.as_deref(), Some("provider.transport"));
        assert_eq!(diagnostics[0].subject_type.as_deref(), Some("effect"));
        assert_eq!(diagnostics[0].subject_id.as_deref(), Some("tell"));
        assert_eq!(
            diagnostics[0].event_id.as_deref(),
            Some(run_event.event_id.as_str())
        );
        assert_eq!(diagnostics[0].effect_id.as_deref(), Some("tell"));
        assert_eq!(diagnostics[0].run_id.as_deref(), Some("run-tell"));
        assert_eq!(diagnostics[0].evidence_ids_json, evidence_ids_json);
        assert_eq!(diagnostics[0].artifact_ids_json, artifact_ids_json);
        assert_eq!(diagnostics[0].correlation_id.as_deref(), Some("corr-tell"));
        assert!(diagnostics[0]
            .source_span_json
            .as_deref()
            .expect("source span")
            .contains("workflow.whip"));
    }

    #[test]
    fn reconstructs_terminal_diagnostics_from_event_payloads() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("DiagnosticReplay", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let source_span_json =
            r#"{"path":"workflow.whip","start":42,"end":73,"construct":"effect"}"#;
        let effects = [NewEffect {
            timeout_seconds: None,
            source_span_json: Some(source_span_json),
            ..test_effect("tell", "agent.tell", "rule=start;effect=tell")
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "fixture",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let event = store
            .complete_effect_with_terminal_diagnostic(
                EffectCompletion {
                    instance_id: &instance.instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "fixture",
                    worker_id: "worker-1",
                    status: "failed",
                    exit_code: Some(42),
                    summary: Some("fixture failed"),
                    metadata_json: r#"{"stderr":"boom"}"#,
                    idempotency_key: Some("terminal-run-tell"),
                },
                Some(TerminalDiagnosticRecord {
                    program_id: Some(version.program_id.clone()),
                    program_version_id: Some(version.version_id.clone()),
                    severity: Severity::Error,
                    code: Some("fixture.failed".to_owned()),
                    message: "fixture failed: boom".to_owned(),
                    source_span_json: Some(source_span_json.to_owned()),
                    subject_type: Some("effect".to_owned()),
                    subject_id: Some("tell".to_owned()),
                    assertion_id: None,
                    evidence_ids_json: "[]".to_owned(),
                    artifact_ids_json: "[]".to_owned(),
                    causation_id: Some("run-tell".to_owned()),
                    correlation_id: Some("tell".to_owned()),
                    idempotency_key: Some("diagnostic-run-tell".to_owned()),
                }),
            )
            .expect("terminal diagnostic completes");

        let replayed = store
            .list_diagnostics_from_events(&instance.instance_id)
            .expect("event diagnostics replay");
        assert_eq!(replayed.len(), 1);
        assert_eq!(
            replayed[0].event_id.as_deref(),
            Some(event.event_id.as_str())
        );
        assert_eq!(replayed[0].effect_id.as_deref(), Some("tell"));
        assert_eq!(replayed[0].run_id.as_deref(), Some("run-tell"));
        assert_eq!(replayed[0].code.as_deref(), Some("fixture.failed"));
        assert_eq!(
            serde_json::from_str::<Value>(
                replayed[0]
                    .source_span_json
                    .as_deref()
                    .expect("source span")
            )
            .expect("replayed source span json"),
            serde_json::from_str::<Value>(source_span_json).expect("expected source span json")
        );
    }

    #[test]
    fn opening_v1_store_adds_diagnostic_columns() {
        let path = std::env::temp_dir().join(format!(
            "whipplescript-store-v1-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        {
            let connection = Connection::open(&path).expect("v1 db opens");
            connection
                .execute_batch(
                    r#"
                    CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO schema_migrations (version, name)
                    VALUES (1, 'runtime-store-schema');
                    CREATE TABLE instances (
                        instance_id TEXT PRIMARY KEY,
                        version_id TEXT
                    );
                    CREATE TABLE effects (
                        effect_id TEXT PRIMARY KEY,
                        instance_id TEXT
                    );
                    CREATE TABLE runs (
                        run_id TEXT PRIMARY KEY
                    );
                    CREATE TABLE diagnostics (
                        diagnostic_id TEXT PRIMARY KEY,
                        instance_id TEXT,
                        severity TEXT NOT NULL,
                        code TEXT,
                        message TEXT NOT NULL,
                        source_span_json TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    "#,
                )
                .expect("v1 schema creates");
        }

        let store = SqliteStore::open(&path).expect("store opens v1 schema");
        let diagnostic_id = store
            .record_diagnostic(DiagnosticRecord {
                instance_id: None,
                program_id: Some("program-v1"),
                program_version_id: Some("version-v1"),
                severity: Severity::Warning,
                code: Some("compile.unused"),
                message: "unused binding",
                source_span_json: None,
                subject_type: Some("program_version"),
                subject_id: Some("version-v1"),
                event_id: None,
                effect_id: None,
                run_id: None,
                assertion_id: None,
                evidence_ids_json: "[]",
                artifact_ids_json: "[]",
                causation_id: None,
                correlation_id: Some("compile"),
                idempotency_key: Some("diag:compile:unused"),
            })
            .expect("diagnostic records on upgraded schema");

        let diagnostics = store.list_diagnostics(None).expect("diagnostics list");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].diagnostic_id, diagnostic_id);
        assert_eq!(diagnostics[0].program_id.as_deref(), Some("program-v1"));
        assert_eq!(
            diagnostics[0].program_version_id.as_deref(),
            Some("version-v1")
        );

        fs::remove_file(path).expect("v1 db removes");
    }

    #[test]
    fn records_and_updates_workspace_records_for_provider_runs() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("WorkspaceRecords", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[test_effect("tell", "agent.tell", "workspace-record-effect")],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-workspace-record"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-workspace",
                provider: "codex-main",
                worker_id: "worker-1",
                lease_id: "lease-workspace",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");

        let workspace_id = store
            .record_workspace(WorkspaceRecord {
                instance_id: Some(&instance.instance_id),
                effect_id: Some("tell"),
                run_id: Some("run-workspace"),
                provider: Some("codex-main"),
                policy: "per_effect_worktree",
                uri: "file:///tmp/whipplescript/worktrees/run-workspace",
                status: "prepared",
                metadata_json: r#"{"source":"test"}"#,
            })
            .expect("workspace records");
        let same_workspace_id = store
            .record_workspace(WorkspaceRecord {
                instance_id: Some(&instance.instance_id),
                effect_id: Some("tell"),
                run_id: Some("run-workspace"),
                provider: Some("codex-main"),
                policy: "per_effect_worktree",
                uri: "file:///tmp/whipplescript/worktrees/run-workspace",
                status: "active",
                metadata_json: r#"{"source":"test","updated":true}"#,
            })
            .expect("workspace upserts");

        assert_eq!(workspace_id, same_workspace_id);
        let workspace = store
            .get_workspace(&workspace_id)
            .expect("workspace loads")
            .expect("workspace exists");
        assert_eq!(workspace.policy, "per_effect_worktree");
        assert_eq!(workspace.status, "active");
        assert_eq!(workspace.run_id.as_deref(), Some("run-workspace"));
        assert!(workspace.metadata_json.contains("\"updated\":true"));
        let workspaces = store
            .list_workspaces_for_instance(&instance.instance_id)
            .expect("workspaces list");
        assert_eq!(workspaces.len(), 1);
        assert_eq!(workspaces[0].workspace_id, workspace_id);
    }

    #[test]
    fn workspace_records_reject_unknown_policy_status_and_invalid_metadata() {
        let store = SqliteStore::open_in_memory().expect("store opens");

        let bad_policy = store.record_workspace(WorkspaceRecord {
            instance_id: None,
            effect_id: None,
            run_id: None,
            provider: Some("codex-main"),
            policy: "host_everything",
            uri: "file:///tmp/workspace",
            status: "prepared",
            metadata_json: "{}",
        });
        assert!(
            matches!(bad_policy, Err(StoreError::Conflict(message)) if message.contains("unsupported workspace policy"))
        );

        let bad_status = store.record_workspace(WorkspaceRecord {
            instance_id: None,
            effect_id: None,
            run_id: None,
            provider: Some("codex-main"),
            policy: "shared",
            uri: "file:///tmp/workspace",
            status: "teleported",
            metadata_json: "{}",
        });
        assert!(
            matches!(bad_status, Err(StoreError::Conflict(message)) if message.contains("unsupported workspace status"))
        );

        let bad_metadata = store.record_workspace(WorkspaceRecord {
            instance_id: None,
            effect_id: None,
            run_id: None,
            provider: Some("codex-main"),
            policy: "shared",
            uri: "file:///tmp/workspace",
            status: "prepared",
            metadata_json: "{not json",
        });
        assert!(matches!(bad_metadata, Err(StoreError::Json(_))));
    }

    #[test]
    fn opening_v1_store_adds_workspace_table() {
        let path = std::env::temp_dir().join(format!(
            "whipplescript-store-workspace-v1-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        {
            let connection = Connection::open(&path).expect("v1 db opens");
            connection
                .execute_batch(
                    r#"
                    CREATE TABLE schema_migrations (
                        version INTEGER PRIMARY KEY,
                        name TEXT NOT NULL,
                        applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO schema_migrations (version, name)
                    VALUES (1, 'runtime-store-schema');
                    CREATE TABLE instances (
                        instance_id TEXT PRIMARY KEY,
                        version_id TEXT
                    );
                    CREATE TABLE effects (
                        effect_id TEXT PRIMARY KEY,
                        instance_id TEXT
                    );
                    CREATE TABLE runs (
                        run_id TEXT PRIMARY KEY
                    );
                    CREATE TABLE diagnostics (
                        diagnostic_id TEXT PRIMARY KEY,
                        instance_id TEXT,
                        severity TEXT NOT NULL,
                        code TEXT,
                        message TEXT NOT NULL,
                        source_span_json TEXT,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    );
                    "#,
                )
                .expect("v1 schema creates");
        }

        let store = SqliteStore::open(&path).expect("store opens v1 schema");
        assert!(store.table_exists("workspaces").expect("table check"));
        let workspace_id = store
            .record_workspace(WorkspaceRecord {
                instance_id: None,
                effect_id: None,
                run_id: None,
                provider: Some("fixture"),
                policy: "shared",
                uri: "file:///tmp/shared",
                status: "prepared",
                metadata_json: "{}",
            })
            .expect("workspace records on upgraded schema");
        assert!(store
            .get_workspace(&workspace_id)
            .expect("workspace loads")
            .is_some());

        fs::remove_file(path).expect("v1 db removes");
    }

    #[test]
    fn missing_capability_blocks_effect_before_provider_run() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Ralph", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            required_capabilities_json: r#"["plugin.memory"]"#,
            ..test_effect("memory", "agent.tell", "rule=start;effect=memory")
        }];

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "memory",
                run_id: "run-memory",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-memory",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("policy blocks run");

        assert!(matches!(blocked, StoreError::PolicyBlocked { .. }));
        assert_eq!(effect_status(&store, "memory"), "blocked_by_capability");
        assert_eq!(row_count(&store, "runs"), 0);
        let effects = store
            .list_effects(&instance.instance_id)
            .expect("effects list");
        assert!(effects[0]
            .policy_block_reason
            .as_deref()
            .expect("policy reason")
            .contains("plugin.memory"));
        let status = store
            .status(&instance.instance_id)
            .expect("status loads")
            .expect("instance exists");
        assert_eq!(status.blocked_effect_count, 1);
        assert_eq!(
            status
                .recent_events
                .last()
                .map(|event| event.event_type.as_str()),
            Some("effect.blocked")
        );
    }

    /// Script hard-off Layer 2, forged-IR fixture (spec/std-script.md,
    /// models/maude/script-capability-seeding.maude): a program registered
    /// DIRECTLY against the store — the path that bypasses the check-time
    /// gate, exactly what forged IR does — commits a raw exec.command effect
    /// carrying no capability requirement. The admission gate holds the raw
    /// form to `script.raw`; nothing seeded it (no import + no operator
    /// authority ever turned the two keys), so the effect blocks as
    /// blocked_by_capability with the `security.script_disabled` id, is never
    /// claimable, and no run row exists.
    #[test]
    fn raw_exec_without_seeded_script_capability_blocks_at_admission() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Forged", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            effect_id: "raw-exec",
            kind: "exec.command",
            target: None,
            input_json: r#"{"mode":"raw","command":"echo forged"}"#,
            profile: None,
            required_capabilities_json: "[]",
            ..test_effect("raw-exec", "exec.command", "rule=go;effect=raw-exec")
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "go",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-go"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        assert!(
            store
                .claimable_effects(&instance.instance_id)
                .expect("claimable list")
                .is_empty(),
            "an unseeded exec effect must not be claimable"
        );
        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "raw-exec",
                run_id: "run-raw-exec",
                provider: "exec",
                worker_id: "whip-exec",
                lease_id: "lease-raw-exec",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("admission blocks the run");
        assert!(
            matches!(&blocked, StoreError::PolicyBlocked { reason, .. }
                if reason.contains("security.script_disabled") && reason.contains("script.raw")),
            "got {blocked:?}"
        );
        assert_eq!(effect_status(&store, "raw-exec"), "blocked_by_capability");
        assert_eq!(row_count(&store, "runs"), 0, "no provider run was started");
    }

    /// The capability form of the same property: an exec.command effect
    /// carrying `script.<name>` blocks at admission when the row was never
    /// seeded (unregistered manifest entry, or seeding keys never turned).
    #[test]
    fn capability_exec_with_unseeded_script_capability_blocks_at_admission() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Forged", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            effect_id: "cap-exec",
            kind: "exec.command",
            target: None,
            input_json: r#"{"mode":"capability","capability":"judge"}"#,
            profile: None,
            required_capabilities_json: r#"["script.judge"]"#,
            ..test_effect("cap-exec", "exec.command", "rule=go;effect=cap-exec")
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "go",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-go"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "cap-exec",
                run_id: "run-cap-exec",
                provider: "exec",
                worker_id: "whip-exec",
                lease_id: "lease-cap-exec",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("admission blocks the run");
        assert!(
            matches!(&blocked, StoreError::PolicyBlocked { reason, .. }
                if reason.contains("security.script_disabled") && reason.contains("script.judge")),
            "got {blocked:?}"
        );
        assert_eq!(effect_status(&store, "cap-exec"), "blocked_by_capability");
        assert_eq!(row_count(&store, "runs"), 0, "no provider run was started");
    }

    /// The positive half: once the two-key seed happened (capability schema +
    /// per-program binding for `script.raw`), the same raw exec effect is
    /// admitted — the gate reads the seeded rows, nothing else.
    #[test]
    fn raw_exec_with_seeded_script_raw_capability_is_claimable() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Granted", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .register_capability_schema(CapabilitySchemaRegistration {
                capability: "script.raw",
                description: "raw exec behind the operator allowlist",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .expect("schema registers");
        store
            .bind_capability(CapabilityBinding {
                binding_id: "binding-script-raw",
                program_id: Some(&version.program_id),
                capability: "script.raw",
                provider: "builtin-script",
                config_json: "{}",
            })
            .expect("binding registers");
        let effects = [NewEffect {
            effect_id: "raw-exec",
            kind: "exec.command",
            target: None,
            input_json: r#"{"mode":"raw","command":"echo granted"}"#,
            profile: None,
            required_capabilities_json: "[]",
            ..test_effect("raw-exec", "exec.command", "rule=go;effect=raw-exec")
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "go",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-go"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable list");
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].effect_id, "raw-exec");
    }

    #[test]
    fn profile_mismatch_blocks_effect_before_provider_run() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Ralph", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "write",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"write"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=write",
            required_capabilities_json: r#"["agent.tell","repo.write"]"#,
            profile: Some("repo-reader"),
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "write",
                run_id: "run-write",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-write",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("profile blocks run");

        assert!(matches!(blocked, StoreError::PolicyBlocked { .. }));
        assert_eq!(effect_status(&store, "write"), "blocked_by_profile");
        let effect = store
            .list_effects(&instance.instance_id)
            .expect("effects list")
            .pop()
            .expect("effect exists");
        assert_eq!(effect.profile.as_deref(), Some("repo-reader"));
        assert!(effect
            .policy_block_reason
            .as_deref()
            .expect("policy reason")
            .contains("repo.write"));
    }

    #[test]
    fn policy_blocked_effects_are_not_claimable() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Ralph", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            required_capabilities_json: r#"["plugin.memory"]"#,
            ..test_effect("memory", "agent.tell", "rule=start;effect=memory")
        }];

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");

        assert!(claimable.is_empty());
        // The observed block is persisted, not silently skipped: the record
        // must say WHY the effect is going nowhere.
        assert_eq!(effect_status(&store, "memory"), "blocked_by_capability");
        let effect = store
            .list_effects(&instance.instance_id)
            .expect("effects list")
            .into_iter()
            .find(|effect| effect.effect_id == "memory")
            .expect("effect exists");
        assert_eq!(
            effect.policy_block_reason.as_deref(),
            Some("capability `plugin.memory` is not registered")
        );
    }

    #[test]
    fn declared_agents_present_supports_map_shaped_metadata() {
        assert!(declared_agents_present(
            r#"{"worker":{"profile":"repo-writer","capacity":1,"capabilities":["agent.tell"]}}"#
        )
        .expect("metadata parses"));
        assert!(
            !declared_agents_present(r#"{"harnesses":[{"name":"coder","kind":"codex"}]}"#)
                .expect("metadata parses")
        );
    }

    /// A capacity-blocked effect is retried by the worker on later passes with
    /// its SAME (effect, run) identity; each re-block re-records the
    /// `effect.blocked` event under the same `capacity-block:<effect>:<run>`
    /// idempotency key. That replay must be tolerated as the same durable
    /// statement — it used to surface as a raw UNIQUE-constraint store error
    /// that crashed `whip run` whenever the interleaving re-blocked a run
    /// (three fan-out tells against `capacity 1` hit it most passes).
    #[test]
    fn repeated_capacity_block_for_same_run_is_idempotent() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(NewProgramVersion {
                declared_profiles_json: r#"[{"name":"worker","profile":"repo-writer","capacity":1,"capabilities":["agent.tell"]}]"#,
                ..test_program_version("CapacityReplay", "source-1", "ir-1")
            })
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [
            test_effect("tell-one", "agent.tell", "rule=start;effect=tell-one"),
            test_effect("tell-two", "agent.tell", "rule=start;effect=tell-two"),
        ];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell-one",
                run_id: "run-one",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-one",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("first run starts");
        for attempt in 0..2 {
            let blocked = store
                .start_run(RunStart {
                    instance_id: &instance.instance_id,
                    effect_id: "tell-two",
                    run_id: "run-two",
                    provider: "test",
                    worker_id: "worker-1",
                    lease_id: "lease-two",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    metadata_json: "{}",
                })
                .expect_err("capacity blocks the run");
            assert!(
                matches!(blocked, StoreError::CapacityBlocked { .. }),
                "attempt {attempt} must report CapacityBlocked, not a raw store error: {blocked:?}"
            );
        }
        assert_eq!(effect_status(&store, "tell-two"), "blocked_by_capacity");
    }

    #[test]
    fn claim_list_persists_policy_block_and_registration_recovers_it() {
        // An effect whose profile is unregistered must not sit `queued` with no
        // reason forever: listing claimable effects persists the block (status
        // + reason + effect.blocked event), and registering the profile later
        // makes the same effect claimable again with the stale reason cleared.
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("GhostProfile", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            profile: Some("ghost"),
            ..test_effect("tell", "agent.tell", "rule=start;effect=tell")
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable listing works");
        assert!(claimable.is_empty(), "blocked effect must not be claimable");
        assert_eq!(effect_status(&store, "tell"), "blocked_by_profile");
        let effect = store
            .list_effects(&instance.instance_id)
            .expect("effects list")
            .into_iter()
            .find(|effect| effect.effect_id == "tell")
            .expect("effect exists");
        assert_eq!(
            effect.policy_block_reason.as_deref(),
            Some("profile `ghost` is not registered")
        );
        let blocked_events = store
            .list_events(&instance.instance_id)
            .expect("events list")
            .into_iter()
            .filter(|event| event.event_type == "effect.blocked")
            .count();
        assert_eq!(blocked_events, 1, "block is recorded as an event");

        // A second pass with an unchanged verdict writes nothing new.
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable listing works");
        assert!(claimable.is_empty());
        let blocked_events = store
            .list_events(&instance.instance_id)
            .expect("events list")
            .into_iter()
            .filter(|event| event.event_type == "effect.blocked")
            .count();
        assert_eq!(blocked_events, 1, "re-observation is idempotent");

        // Registering the profile recovers the effect without any requeue verb.
        store
            .register_profile(ProfileRegistration {
                profile_id: "profile-ghost",
                name: "ghost",
                description: "late-registered",
                enforcement_mode: "audit",
                allowed_capabilities_json: "[]",
                config_json: "{}",
            })
            .expect("profile registers");
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable listing works");
        assert_eq!(
            claimable
                .iter()
                .map(|e| e.effect_id.as_str())
                .collect::<Vec<_>>(),
            vec!["tell"],
            "registration makes the blocked effect claimable again"
        );
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell",
                run_id: "run-1",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-1",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("recovered effect starts");
        assert_eq!(effect_status(&store, "tell"), "running");
        let effect = store
            .list_effects(&instance.instance_id)
            .expect("effects list")
            .into_iter()
            .find(|effect| effect.effect_id == "tell")
            .expect("effect exists");
        assert!(
            effect.policy_block_reason.is_none(),
            "claiming clears the stale block reason"
        );
    }

    #[test]
    fn agent_capacity_limits_claimability_and_run_start() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(NewProgramVersion {
                declared_profiles_json: r#"[{"name":"worker","profile":"repo-writer","capacity":1,"capabilities":["agent.tell"]}]"#,
                ..test_program_version("Capacity", "source-1", "ir-1")
            })
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [
            test_effect("tell-one", "agent.tell", "rule=start;effect=tell-one"),
            test_effect("tell-two", "agent.tell", "rule=start;effect=tell-two"),
        ];

        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert_eq!(
            claimable
                .iter()
                .map(|effect| effect.effect_id.as_str())
                .collect::<Vec<_>>(),
            vec!["tell-one", "tell-two"]
        );

        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell-one",
                run_id: "run-one",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-one",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("first run starts");
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects reload");
        assert!(claimable.is_empty());

        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell-two",
                run_id: "run-two",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-two",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("capacity blocks second run");
        assert!(
            matches!(blocked, StoreError::CapacityBlocked { reason, .. } if reason.contains("capacity exhausted"))
        );
        assert_eq!(effect_status(&store, "tell-two"), "blocked_by_capacity");
        let status = store
            .status(&instance.instance_id)
            .expect("status loads")
            .expect("instance exists");
        assert_eq!(status.blocked_effect_count, 1);
        assert_eq!(
            status
                .recent_events
                .last()
                .map(|event| event.event_type.as_str()),
            Some("effect.blocked")
        );

        store
            .complete_effect(EffectCompletion {
                instance_id: &instance.instance_id,
                effect_id: "tell-one",
                run_id: "run-one",
                provider: "test",
                worker_id: "worker-1",
                status: "completed",
                exit_code: Some(0),
                summary: Some("done"),
                metadata_json: "{}",
                idempotency_key: Some("complete-one"),
            })
            .expect("first run completes");
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects after completion");
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].effect_id, "tell-two");
    }

    #[test]
    fn undeclared_agent_targets_are_durably_blocked() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(NewProgramVersion {
                declared_profiles_json: r#"{"agents":[{"name":"worker","profile":"repo-writer","capacity":1}]}"#,
                ..test_program_version("AgentRefs", "source-1", "ir-1")
            })
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            target: Some("rogue"),
            ..test_effect("tell-rogue", "agent.tell", "rule=start;effect=tell-rogue")
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell-rogue",
                run_id: "run-rogue",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-rogue",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("undeclared agent blocks run");

        assert!(
            matches!(blocked, StoreError::PolicyBlocked { reason, .. } if reason.contains("not declared"))
        );
        assert_eq!(effect_status(&store, "tell-rogue"), "blocked_by_profile");
        let effect = store
            .list_effects(&instance.instance_id)
            .expect("effects load")
            .pop()
            .expect("effect exists");
        assert!(effect
            .policy_block_reason
            .as_deref()
            .expect("block reason")
            .contains("not declared"));
    }

    #[test]
    fn agent_missing_declared_capability_is_durably_blocked() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(NewProgramVersion {
                declared_profiles_json: r#"{"agents":[{"name":"worker","profile":"repo-writer","capacity":1,"capabilities":["agent.tell"]}]}"#,
                ..test_program_version("AgentCapabilities", "source-1", "ir-1")
            })
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            required_capabilities_json: r#"["repo.write"]"#,
            ..test_effect("tell-write", "agent.tell", "rule=start;effect=tell-write")
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "tell-write",
                run_id: "run-write",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-write",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("agent capability blocks run");

        assert!(
            matches!(blocked, StoreError::PolicyBlocked { reason, .. } if reason.contains("does not declare required capability `repo.write`"))
        );
        assert_eq!(effect_status(&store, "tell-write"), "blocked_by_capability");
        let effect = store
            .list_effects(&instance.instance_id)
            .expect("effects load")
            .pop()
            .expect("effect exists");
        assert!(effect
            .policy_block_reason
            .as_deref()
            .expect("block reason")
            .contains("repo.write"));
    }

    #[test]
    fn legacy_manifest_registered_effect_contract_can_run_without_kernel_changes() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("MemoryWorkflow", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let package_id = store
            .register_package_manifest(include_str!(
                "../../../examples/legacy-plugin-manifests/memory.json"
            ))
            .expect("legacy manifest loads");
        assert_eq!(package_id, "legacy-memory-package");

        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "query",
            kind: "memory.query",
            target: None,
            input_json: r#"{"query":"context"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=query",
            required_capabilities_json: "[]",
            profile: Some("memory-user"),
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "query",
                run_id: "run-query",
                provider: "memory-legacy-provider",
                worker_id: "worker-1",
                lease_id: "lease-query",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("legacy manifest effect starts");

        assert_eq!(effect_status(&store, "query"), "running");
        assert_eq!(row_count(&store, "runs"), 1);
    }

    #[test]
    fn capability_call_uses_registered_target_capability_policy() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("MemoryWorkflow", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .register_package_manifest(include_str!(
                "../../../examples/legacy-plugin-manifests/memory.json"
            ))
            .expect("legacy manifest loads");

        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "query",
            kind: "capability.call",
            target: Some("memory.query"),
            input_json: r#"{"target":"memory.query"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=query",
            required_capabilities_json: r#"["memory.query"]"#,
            profile: Some("memory-user"),
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].effect_id, "query");
    }

    #[test]
    fn package_manifest_shape_registers_runtime_capability_policy() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("MemoryWorkflow", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let package_id = store
            .register_package_manifest(include_str!("../../../std/manifests/memory.json"))
            .expect("package manifest loads");
        assert_eq!(package_id, "std.memory");

        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "query",
            kind: "capability.call",
            target: Some("memory.query"),
            input_json: r#"{"target":"memory.query"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=query",
            required_capabilities_json: "[]",
            profile: Some("memory-user"),
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert_eq!(claimable.len(), 1);
        assert_eq!(claimable[0].effect_id, "query");
    }

    /// std.coord slice 4 gate: the NATIVE admission gate is real for
    /// coordination kinds. With the builtin exemption deleted from
    /// `policy_block_on`, an UNBOUND coordination kind blocks as
    /// blocked_by_capability (no effect provider registered), and the same
    /// kind becomes claimable once the embedded std.coord manifest's
    /// capability/provider/binding rows are registered — exactly what
    /// `register_locked_packages` seeds at store init in production.
    #[test]
    fn coordination_kind_blocks_unbound_and_claims_once_manifest_seeded() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("CoordGate", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "acquire-1",
            kind: "lease.acquire",
            target: None,
            input_json: r#"{"resource":"deploy_slot","key":"prod","slots":1,"ttl_seconds":60}"#,
            status: "queued",
            idempotency_key: "rule=grab;effect=acquire-1",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "grab",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-grab"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        // Unbound: no worker may claim it, and a forced start blocks durably.
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert!(
            claimable.is_empty(),
            "unbound coordination kind must not be claimable: {claimable:?}"
        );
        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "acquire-1",
                run_id: "run-acquire",
                provider: "coordination",
                worker_id: "worker-1",
                lease_id: "lease-acquire",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("unbound coordination kind blocks at admission");
        assert!(
            matches!(&blocked, StoreError::PolicyBlocked { reason, .. } if reason.contains("lease.acquire")),
            "{blocked:?}"
        );
        assert_eq!(effect_status(&store, "acquire-1"), "blocked_by_capability");

        // Seeded: on a store where the embedded std.coord manifest registered
        // first (production order — `register_locked_packages` runs at store
        // init, before any worker pass), the same effect is claimable.
        let mut seeded = SqliteStore::open_in_memory().expect("store opens");
        seeded
            .register_package_manifest(include_str!("../../../std/manifests/coord.json"))
            .expect("std.coord manifest registers");
        let version = seeded
            .create_program_version(test_program_version("CoordGateSeeded", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = seeded
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        seeded
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "grab",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-grab"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let claimable = seeded
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert_eq!(claimable.len(), 1, "{claimable:?}");
        assert_eq!(claimable[0].effect_id, "acquire-1");
    }

    /// std.files slice F2 gate: the NATIVE admission gate is real for
    /// `file.*` kinds. With the builtin exemption deleted from
    /// `policy_block_on`, an UNBOUND file kind blocks loudly as
    /// blocked_by_capability — the stale-store fixture (a workspace whose
    /// store lacks the std.files rows fails loud, never hangs) — and the
    /// same kind becomes claimable once the embedded std.files manifest's
    /// capability/provider/binding rows are registered, exactly what
    /// `register_locked_packages` seeds at store init in production.
    #[test]
    fn file_kind_blocks_unbound_and_claims_once_manifest_seeded() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("FilesGate", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "read-1",
            kind: "file.read",
            target: None,
            input_json: r#"{"store":"docs","root":".","path":"note.md","format":"text"}"#,
            status: "queued",
            idempotency_key: "rule=load;effect=read-1",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "load",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-load"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        // Unbound (stale store): no worker may claim it, and a forced start
        // blocks durably and loudly.
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert!(
            claimable.is_empty(),
            "unbound file kind must not be claimable: {claimable:?}"
        );
        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "read-1",
                run_id: "run-read",
                provider: "files",
                worker_id: "worker-1",
                lease_id: "lease-read",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("unbound file kind blocks at admission");
        assert!(
            matches!(&blocked, StoreError::PolicyBlocked { reason, .. } if reason.contains("file.read")),
            "{blocked:?}"
        );
        assert_eq!(effect_status(&store, "read-1"), "blocked_by_capability");

        // Seeded: on a store where the embedded std.files manifest registered
        // first (production order — `register_locked_packages` runs at store
        // init, before any worker pass), the same effect is claimable.
        let mut seeded = SqliteStore::open_in_memory().expect("store opens");
        seeded
            .register_package_manifest(include_str!("../../../std/manifests/files.json"))
            .expect("std.files manifest registers");
        let version = seeded
            .create_program_version(test_program_version("FilesGateSeeded", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = seeded
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        seeded
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "load",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-load"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let claimable = seeded
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert_eq!(claimable.len(), 1, "{claimable:?}");
        assert_eq!(claimable[0].effect_id, "read-1");
    }

    /// std.tracker slice T4 gate: the NATIVE admission gate is real for
    /// tracker kinds. With the builtin exemption deleted from
    /// `policy_block_on`, an UNBOUND tracker kind blocks as
    /// blocked_by_capability (no effect provider registered), and the same
    /// kind becomes claimable once the embedded std.tracker manifest's
    /// capability/provider/binding rows are registered — exactly what
    /// `register_locked_packages` seeds at store init in production.
    #[test]
    fn tracker_kind_blocks_unbound_and_claims_once_manifest_seeded() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("TrackerGate", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "claim-1",
            kind: "tracker.claim",
            target: None,
            input_json: r#"{"id":"WS-1"}"#,
            status: "queued",
            idempotency_key: "rule=work;effect=claim-1",
            required_capabilities_json: r#"["tracker.claim"]"#,
            profile: None,
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "work",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-work"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        // Unbound: no worker may claim it, and a forced start blocks durably.
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert!(
            claimable.is_empty(),
            "unbound tracker kind must not be claimable: {claimable:?}"
        );
        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "claim-1",
                run_id: "run-claim",
                provider: "queue",
                worker_id: "worker-1",
                lease_id: "lease-claim",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("unbound tracker kind blocks at admission");
        assert!(
            matches!(&blocked, StoreError::PolicyBlocked { reason, .. } if reason.contains("tracker.claim")),
            "{blocked:?}"
        );
        assert_eq!(effect_status(&store, "claim-1"), "blocked_by_capability");

        // Seeded: on a store where the embedded std.tracker manifest
        // registered first (production order — `register_locked_packages`
        // runs at store init, before any worker pass), the same effect is
        // claimable.
        let mut seeded = SqliteStore::open_in_memory().expect("store opens");
        seeded
            .register_package_manifest(include_str!("../../../std/manifests/tracker.json"))
            .expect("std.tracker manifest registers");
        let version = seeded
            .create_program_version(test_program_version(
                "TrackerGateSeeded",
                "source-1",
                "ir-1",
            ))
            .expect("program version creates");
        let instance = seeded
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        seeded
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "work",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-work"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let claimable = seeded
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert_eq!(claimable.len(), 1, "{claimable:?}");
        assert_eq!(claimable[0].effect_id, "claim-1");
    }

    /// std.ingress slice I2b gate: the NATIVE admission gate is real for
    /// `signal.emit`. With the builtin exemption deleted from
    /// `policy_block_on`, an UNBOUND `signal.emit` effect blocks as
    /// blocked_by_capability (no effect provider registered), and the same
    /// kind becomes claimable once the embedded std.ingress manifest's
    /// capability/provider/binding rows are registered — exactly what
    /// `register_locked_packages` seeds at store init in production.
    #[test]
    fn signal_emit_blocks_unbound_and_claims_once_manifest_seeded() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("IngressGate", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");

        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "emit-1",
            kind: "signal.emit",
            target: None,
            input_json: r#"{"target_instance":"peer","event":"deploy.finished","payload":{}}"#,
            status: "queued",
            idempotency_key: "rule=notify;effect=emit-1",
            required_capabilities_json: "[]",
            profile: None,
            correlation_id: None,
            source_span_json: None,
        }];
        store
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "notify",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-notify"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        // Unbound: no worker may claim it, and a forced start blocks durably.
        let claimable = store
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert!(
            claimable.is_empty(),
            "unbound signal.emit must not be claimable: {claimable:?}"
        );
        let blocked = store
            .start_run(RunStart {
                instance_id: &instance.instance_id,
                effect_id: "emit-1",
                run_id: "run-emit",
                provider: "notify",
                worker_id: "worker-1",
                lease_id: "lease-emit",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect_err("unbound signal.emit blocks at admission");
        assert!(
            matches!(&blocked, StoreError::PolicyBlocked { reason, .. } if reason.contains("signal.emit")),
            "{blocked:?}"
        );
        assert_eq!(effect_status(&store, "emit-1"), "blocked_by_capability");

        // Seeded: on a store where the embedded std.ingress manifest
        // registered first (production order — `register_locked_packages`
        // runs at store init, before any worker pass), the same effect is
        // claimable.
        let mut seeded = SqliteStore::open_in_memory().expect("store opens");
        seeded
            .register_package_manifest(include_str!("../../../std/manifests/ingress.json"))
            .expect("std.ingress manifest registers");
        let version = seeded
            .create_program_version(test_program_version(
                "IngressGateSeeded",
                "source-1",
                "ir-1",
            ))
            .expect("program version creates");
        let instance = seeded
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        seeded
            .commit_rule(RuleCommit {
                instance_id: &instance.instance_id,
                rule: "notify",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-notify"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let claimable = seeded
            .claimable_effects(&instance.instance_id)
            .expect("claimable effects load");
        assert_eq!(claimable.len(), 1, "{claimable:?}");
        assert_eq!(claimable[0].effect_id, "emit-1");
    }

    #[test]
    fn loads_legacy_manifests_from_directory() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let loaded = store
            .load_package_manifests_from_dir(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../examples/legacy-plugin-manifests"),
            )
            .expect("legacy manifests load");

        assert_eq!(
            loaded,
            vec![
                "legacy-external-notification-package".to_owned(),
                "legacy-memory-package".to_owned(),
            ]
        );
    }

    #[test]
    fn registers_attaches_and_records_skill_evidence() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(test_program_version("Ralph", "source-1", "ir-1"))
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        store
            .register_skill(SkillRegistration {
                skill_id: "skill-repo-user",
                name: "repo-user",
                version: "1.0.0",
                source: "# Repo User\nUse Repo carefully.\n",
                source_path: "skills/repo-user/SKILL.md",
                body: "# Repo User\nUse Repo carefully.\n",
                description: "Repo workflow instructions",
                required_capabilities_json: r#"["tracker.claim"]"#,
                metadata_json: r#"{"package":"core"}"#,
            })
            .expect("skill registers");
        store
            .attach_skill(SkillAttachment {
                attachment_id: "attach-program-repo",
                scope_type: "program",
                scope_id: &version.program_id,
                skill_name: "repo-user",
            })
            .expect("program skill attaches");
        store
            .attach_skill(SkillAttachment {
                attachment_id: "attach-agent-repo",
                scope_type: "agent",
                scope_id: "Ralph/worker",
                skill_name: "repo-user",
            })
            .expect("agent skill attaches");
        store
            .attach_skill(SkillAttachment {
                attachment_id: "attach-run-repo",
                scope_type: "run",
                scope_id: "run-tell",
                skill_name: "repo-user",
            })
            .expect("run skill attaches");

        let skills = store.list_skills().expect("skills list");
        assert_eq!(skills.len(), 1);
        assert_eq!(skills[0].name, "repo-user");
        assert_eq!(skills[0].version, "1.0.0");
        assert_eq!(skills[0].source_path, "skills/repo-user/SKILL.md");
        assert!(skills[0].content_hash.len() >= 16);

        let program_attachments = store
            .list_skill_attachments("program", &version.program_id)
            .expect("program attachments load");
        assert_eq!(program_attachments.len(), 1);
        assert_eq!(program_attachments[0].skill.name, "repo-user");
        let agent_attachments = store
            .list_skill_attachments("agent", "Ralph/worker")
            .expect("agent attachments load");
        assert_eq!(agent_attachments.len(), 1);
        let run_attachments = store
            .list_skill_attachments("run", "run-tell")
            .expect("run attachments load");
        assert_eq!(run_attachments.len(), 1);

        let evidence_id = store
            .record_skill_evidence(SkillEvidence {
                instance_id: &instance.instance_id,
                run_id: "run-tell",
                effect_id: "tell",
                skill_names: &["repo-user"],
                idempotency_key: Some("skills-run-tell"),
            })
            .expect("skill evidence records");
        assert!(evidence_id.starts_with("evd_"));
        let evidence = store
            .list_evidence(&instance.instance_id)
            .expect("evidence lists");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, "skills.injected");
        assert!(evidence[0]
            .metadata_json
            .contains("skills/repo-user/SKILL.md"));
        assert!(evidence[0].metadata_json.contains("content_hash"));
        assert!(evidence[0]
            .summary
            .as_deref()
            .expect("summary")
            .contains("repo-user@1.0.0"));
    }

    #[test]
    fn provider_validation_evidence_records_refs_and_reopens() {
        let path = std::env::temp_dir().join(format!(
            "whipplescript-provider-validation-evidence-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time after epoch")
                .as_nanos()
        ));
        {
            let mut store = SqliteStore::open(&path).expect("store opens");
            let version = store
                .create_program_version(test_program_version("ProviderEvidence", "source", "ir"))
                .expect("program version creates");
            let instance = store
                .create_instance(NewInstance {
                    program_id: &version.program_id,
                    version_id: &version.version_id,
                    input_json: "{}",
                })
                .expect("instance creates");
            let evidence_id = store
                .record_provider_validation_evidence(ProviderValidationEvidence {
                    instance_id: &instance.instance_id,
                    provider_id: "codex-main",
                    provider_kind: "codex",
                    surface: "codex_app_server",
                    status: "pass",
                    config_json: r#"{"provider_id":"codex-main","provider_kind":"codex","surface":"codex_app_server","credentials_ref":"secret:codex","extra_keys":["api_key"]}"#,
                    capability_json: r#"{"provider_kind":"codex","surface":"codex_app_server","cancellation_depths":["native_stop"]}"#,
                    validation_results_json: r#"[{"provider":"codex-main","surface":"codex_app_server","status":"pass","phase":"provider.surface.valid","code":"surface_supported","message":"ok","recoverable":false,"missing_config_refs":[]}]"#,
                    source_path: Some("providers/native.json"),
                    correlation_id: Some("provider-validation:codex-main"),
                })
                .expect("provider validation evidence records");
            assert!(evidence_id.starts_with("evd_"));
            let evidence = store
                .list_evidence(&instance.instance_id)
                .expect("evidence lists");
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].kind, "provider.validation");
            assert_eq!(evidence[0].subject_type, "provider_config");
            assert_eq!(evidence[0].subject_id, "codex-main");
            let metadata =
                serde_json::from_str::<Value>(&evidence[0].metadata_json).expect("metadata json");
            assert_eq!(
                metadata.get("provider_kind").and_then(Value::as_str),
                Some("codex")
            );
            assert_eq!(
                metadata
                    .pointer("/config/extra_keys/0")
                    .and_then(Value::as_str),
                Some("api_key")
            );
            assert_eq!(
                metadata
                    .pointer("/validation_results/0/code")
                    .and_then(Value::as_str),
                Some("surface_supported")
            );
            let links = store
                .list_evidence_links(&instance.instance_id)
                .expect("evidence links list");
            assert!(links.iter().any(|link| {
                link.evidence_id == evidence_id
                    && link.target_type == "provider_config"
                    && link.target_id == "codex-main"
                    && link.relation == "subject"
            }));
            assert!(links.iter().any(|link| {
                link.evidence_id == evidence_id
                    && link.target_type == "provider"
                    && link.target_id == "codex-main"
                    && link.relation == "validates"
            }));
            assert!(links.iter().any(|link| {
                link.evidence_id == evidence_id
                    && link.target_type == "provider_capability"
                    && link.target_id == "codex:codex_app_server"
                    && link.relation == "uses"
            }));
        }
        {
            let store = SqliteStore::open(&path).expect("store reopens");
            let evidence = store
                .list_evidence_for_subject("provider_config", "codex-main")
                .expect("subject evidence lists");
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].kind, "provider.validation");
            assert_eq!(
                evidence[0].correlation_id.as_deref(),
                Some("provider-validation:codex-main")
            );
        }
        fs::remove_file(path).expect("provider evidence db removes");
    }

    #[test]
    fn codex_app_server_evidence_records_refs_and_reopens() {
        let path = std::env::temp_dir().join(format!(
            "whipplescript-codex-app-server-evidence-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time after epoch")
                .as_nanos()
        ));
        {
            let mut store = SqliteStore::open(&path).expect("store opens");
            let version = store
                .create_program_version(test_program_version("CodexEvidence", "source", "ir"))
                .expect("program version creates");
            let instance = store
                .create_instance(NewInstance {
                    program_id: &version.program_id,
                    version_id: &version.version_id,
                    input_json: "{}",
                })
                .expect("instance creates");
            let evidence_id = store
                .record_codex_app_server_evidence(CodexAppServerEvidence {
                    instance_id: &instance.instance_id,
                    provider_id: "codex-main",
                    thread_id: "thread-1",
                    turn_id: "turn-1",
                    metadata_json: r#"{"approvalRequests":[{"method":"item/commandExecution/requestApproval","commandBytes":14}],"toolRequests":[],"diffNotifications":[{"method":"turn/diff/updated","diffBytes":42}],"itemNotifications":[]}"#,
                    correlation_id: Some("codex-app-server:turn-1"),
                })
                .expect("codex evidence records");
            assert!(evidence_id.starts_with("evd_"));
            let evidence = store
                .list_evidence(&instance.instance_id)
                .expect("evidence lists");
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].kind, "codex.app_server.evidence");
            assert_eq!(evidence[0].subject_type, "provider_turn");
            assert_eq!(evidence[0].subject_id, "turn-1");
            let metadata =
                serde_json::from_str::<Value>(&evidence[0].metadata_json).expect("metadata json");
            assert_eq!(
                metadata.get("provider_id").and_then(Value::as_str),
                Some("codex-main")
            );
            assert_eq!(
                metadata
                    .pointer("/evidence/diffNotifications/0/diffBytes")
                    .and_then(Value::as_i64),
                Some(42)
            );
            let links = store
                .list_evidence_links(&instance.instance_id)
                .expect("evidence links list");
            assert!(links.iter().any(|link| {
                link.evidence_id == evidence_id
                    && link.target_type == "provider"
                    && link.target_id == "codex-main"
                    && link.relation == "observes"
            }));
            assert!(links.iter().any(|link| {
                link.evidence_id == evidence_id
                    && link.target_type == "provider_thread"
                    && link.target_id == "thread-1"
                    && link.relation == "observes"
            }));
        }
        {
            let store = SqliteStore::open(&path).expect("store reopens");
            let evidence = store
                .list_evidence_for_subject("provider_turn", "turn-1")
                .expect("subject evidence lists");
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].kind, "codex.app_server.evidence");
            assert_eq!(
                evidence[0].correlation_id.as_deref(),
                Some("codex-app-server:turn-1")
            );
        }
        fs::remove_file(path).expect("codex evidence db removes");
    }

    #[test]
    fn claude_agent_sdk_evidence_records_refs_and_reopens() {
        let path = std::env::temp_dir().join(format!(
            "whipplescript-claude-agent-sdk-evidence-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time after epoch")
                .as_nanos()
        ));
        {
            let mut store = SqliteStore::open(&path).expect("store opens");
            let version = store
                .create_program_version(test_program_version("ClaudeEvidence", "source", "ir"))
                .expect("program version creates");
            let instance = store
                .create_instance(NewInstance {
                    program_id: &version.program_id,
                    version_id: &version.version_id,
                    input_json: "{}",
                })
                .expect("instance creates");
            let evidence_id = store
                .record_claude_agent_sdk_evidence(ClaudeAgentSdkEvidence {
                    instance_id: &instance.instance_id,
                    provider_id: "claude-main",
                    session_id: "session-1",
                    run_id: "run-1",
                    metadata_json: r#"{"session_id":"session-1","event_counts":{"claude.stream.message":2,"claude.turn.completed":1},"terminal_type":"claude.turn.completed","terminal_payload":{"subtype":"success","result_shape":{"type":"string","chars":12},"usage_shape":{"type":"object","keys":2}}}"#,
                    correlation_id: Some("claude-agent-sdk:run-1"),
                })
                .expect("claude evidence records");
            assert!(evidence_id.starts_with("evd_"));
            let evidence = store
                .list_evidence(&instance.instance_id)
                .expect("evidence lists");
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].kind, "claude.agent_sdk.evidence");
            assert_eq!(evidence[0].subject_type, "provider_session");
            assert_eq!(evidence[0].subject_id, "session-1");
            assert_eq!(evidence[0].causation_id.as_deref(), Some("run-1"));
            let metadata =
                serde_json::from_str::<Value>(&evidence[0].metadata_json).expect("metadata json");
            assert_eq!(
                metadata.get("provider_id").and_then(Value::as_str),
                Some("claude-main")
            );
            assert_eq!(
                metadata
                    .pointer("/evidence/event_counts/claude.turn.completed")
                    .and_then(Value::as_i64),
                Some(1)
            );
            let links = store
                .list_evidence_links(&instance.instance_id)
                .expect("evidence links list");
            assert!(links.iter().any(|link| {
                link.evidence_id == evidence_id
                    && link.target_type == "provider"
                    && link.target_id == "claude-main"
                    && link.relation == "observes"
            }));
            assert!(links.iter().any(|link| {
                link.evidence_id == evidence_id
                    && link.target_type == "provider_run"
                    && link.target_id == "run-1"
                    && link.relation == "observes"
            }));
        }
        {
            let store = SqliteStore::open(&path).expect("store reopens");
            let evidence = store
                .list_evidence_for_subject("provider_session", "session-1")
                .expect("subject evidence lists");
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].kind, "claude.agent_sdk.evidence");
            assert_eq!(
                evidence[0].correlation_id.as_deref(),
                Some("claude-agent-sdk:run-1")
            );
        }
        fs::remove_file(path).expect("claude evidence db removes");
    }

    fn new_event<'a>(
        instance_id: &'a str,
        event_type: &'a str,
        idempotency_key: Option<&'a str>,
    ) -> NewEvent<'a> {
        NewEvent {
            instance_id,
            event_type,
            payload_json: "{}",
            source: "test",
            causation_id: None,
            correlation_id: None,
            idempotency_key,
        }
    }

    fn test_fact<'a>(fact_id: &'a str, name: &'a str, key: &'a str) -> NewFact<'a> {
        NewFact {
            fact_id,
            name,
            key,
            value_json: r#"{"title":"Implement store"}"#,
            schema_id: Some("WorkItem"),
            provenance_class: "derived",
            correlation_id: None,
            source_span_json: None,
        }
    }

    fn test_program_version<'a>(
        program_name: &'a str,
        source_hash: &'a str,
        ir_hash: &'a str,
    ) -> NewProgramVersion<'a> {
        let analysis_summary_json = Box::leak(
            json!({
                "workflow": program_name,
                "workflow_contracts": [],
                "schemas": [],
            })
            .to_string()
            .into_boxed_str(),
        );
        NewProgramVersion {
            program_name,
            source_hash,
            ir_hash,
            compiler_version: "test",
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json,
            generated_artifacts_json: "[]",
            artifact_root: None,
        }
    }

    fn test_effect<'a>(
        effect_id: &'a str,
        kind: &'a str,
        idempotency_key: &'a str,
    ) -> NewEffect<'a> {
        NewEffect {
            timeout_seconds: None,
            effect_id,
            kind,
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key,
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }
    }

    fn test_completion(run_id: &str) -> EffectCompletion<'_> {
        EffectCompletion {
            instance_id: "instance-a",
            effect_id: "tell",
            run_id,
            provider: "test",
            worker_id: "worker-1",
            status: "completed",
            exit_code: Some(0),
            summary: Some("done"),
            metadata_json: "{}",
            idempotency_key: None,
        }
    }

    fn row_count(store: &SqliteStore, table: &str) -> i64 {
        store
            .connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .expect("row count")
    }

    fn effect_revision(store: &SqliteStore, effect_id: &str) -> (Option<String>, i64, bool) {
        store
            .connection
            .query_row(
                r#"
                SELECT
                    program_version_id,
                    revision_epoch,
                    EXISTS (
                        SELECT 1
                        FROM effect_cancellation_requests AS request
                        WHERE request.effect_id = effects.effect_id
                          AND request.instance_id = effects.instance_id
                          AND request.status = 'requested'
                    )
                FROM effects
                WHERE effect_id = ?1
                "#,
                [effect_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("effect revision")
    }

    fn effect_status(store: &SqliteStore, effect_id: &str) -> String {
        store
            .connection
            .query_row(
                "SELECT status FROM effects WHERE effect_id = ?1",
                [effect_id],
                |row| row.get(0),
            )
            .expect("effect status")
    }

    fn lease_status(store: &SqliteStore, lease_id: &str) -> String {
        store
            .connection
            .query_row(
                "SELECT status FROM leases WHERE lease_id = ?1",
                [lease_id],
                |row| row.get(0),
            )
            .expect("lease status")
    }

    fn instance_status(store: &SqliteStore, instance_id: &str) -> String {
        store
            .connection
            .query_row(
                "SELECT status FROM instances WHERE instance_id = ?1",
                [instance_id],
                |row| row.get(0),
            )
            .expect("instance status")
    }
}
