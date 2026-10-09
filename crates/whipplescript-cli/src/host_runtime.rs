//! Persistent native host facade for governed WhippleScript turns.
//!
//! The facade owns policy admission, instance identity, the brokered model/tool
//! loop, transcript persistence, and evidence projection. Embedding products
//! provide only opaque-reference resolvers. Secrets and resource bodies are
//! resolved after admission and never enter the host command or receipt.

#[path = "native_provider_transport.rs"]
mod native_provider_transport;
pub use native_provider_transport::NativeProviderTransport;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_kernel::coerce_native::CoerceProvider;
use whipplescript_kernel::construct_coverage::{
    embedded_std_registry_for_program, CheckedConstructBasis,
};
use whipplescript_kernel::context_assembly::SkillCatalogueEntry;
use whipplescript_kernel::file_view::{
    is_within, normalize_stored_path, FileView, RootRename, ViewResolution,
};
pub use whipplescript_kernel::harness_loop::ToolCall;
use whipplescript_kernel::harness_loop::{
    BrokeredTurnInput, ChatMessage, MediaInput, NoopCompactor, ToolExecutor, ToolOutcome, ToolSpec,
    ToolStatus,
};
use whipplescript_kernel::harness_model::MessagesApiClient;
use whipplescript_kernel::host_facade::{
    ForkInstanceHomeJournal, ForkInstanceOperationBasis, ForkInstanceOperationEvidence,
    ForkSourceHomeBasis, HostFacadeError, OpenInstanceHomeJournal, OpenInstanceOperationBasis,
    OpenInstanceOperationEvidence,
};
use whipplescript_kernel::import_coverage::{
    self, CheckedImportBasis, SelectedImportCoverage, NO_LOCK_DIGEST,
};
use whipplescript_kernel::sansio::{
    HostDriver, HttpResponse, IoRequest, IoResult, ModelContentProvenance, TransportError,
};
use whipplescript_kernel::whip_shell::{ShellFile, ShellRequest, WhipShell};
use whipplescript_kernel::world_state::{
    AgentTopology, ComputeResources, EffectiveTurnEnvelope, EnvironmentState, ExecutionIdentity,
    GovernanceDisposition, GovernanceRule, HarnessClass, WorldMutability, WorldSnapshot,
};
use whipplescript_kernel::{
    idempotency_key, AgentThreadSeed, BrokeredTurnContext, ProgramVersionInput, RuntimeKernel,
};
use whipplescript_store::{
    payload_protection::PayloadProtection, EffectCancellationRequest, EvidenceRecord, NewEffect,
    NewEvent, ProgramVersionView, RuleCommit, SkillView, SqliteStore, StoreError,
};

use crate::host_protocol::{
    AdoptionCut, EventPosition, ForkInstanceCommand, ForkedInstance, LabeledRuntimeEvent,
    OpenInstanceCommand, OpenedInstance, PinnedPosition, PolicyEpochRef, ProtocolError,
    ProviderBindingRef, ResourceRef, RuntimeEvidencePointer, StartTurnCommand, TurnReceipt,
    TurnStatus, HOST_PROTOCOL,
};
use crate::ifc::VerifiedEnvelope;
pub use whipplescript_kernel::host_package::{
    AuthoredAgentPackage, PackageResolver, ResolvedPackage, AGENT_PACKAGE_MANIFEST,
    AGENT_PACKAGE_SCHEMA,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelProvider {
    OpenAi,
    /// A generic OpenAI-compatible endpoint (Chat Completions API) at a caller-supplied
    /// base URL — OpenRouter, Together, Groq, vLLM, Ollama, LM Studio, etc.
    OpenAiCompat,
    Anthropic,
    Codex,
    /// xAI's Grok API (Chat Completions wire, first-class credential surface).
    Xai,
    /// A Grok/X Premium subscription OAuth bearer, admitted only at xAI's CLI
    /// proxy on the Responses wire.
    XaiSubscription,
}

impl ModelProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::OpenAiCompat => "openai-generic",
            Self::Anthropic => "anthropic",
            Self::Codex => "openai-codex",
            Self::Xai => "xai",
            Self::XaiSubscription => "xai-grok",
        }
    }
}

/// Ephemeral provider material. Its `Debug` implementation is deliberately
/// redacted and the value is never serialized by this module.
pub struct ResolvedProviderBinding {
    provider: ModelProvider,
    api_key: String,
    model: String,
    base_url: String,
    max_tokens: u64,
    timeout: Duration,
    codex_account_id: Option<String>,
    codex_session_id: Option<String>,
    transport: Option<NativeProviderTransport>,
}

impl ResolvedProviderBinding {
    pub fn new(
        provider: ModelProvider,
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: u64,
        timeout: Duration,
    ) -> Self {
        Self {
            provider,
            api_key: api_key.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens,
            timeout,
            codex_account_id: None,
            codex_session_id: None,
            transport: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_codex(
        access_token: impl Into<String>,
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: u64,
        timeout: Duration,
    ) -> Self {
        Self {
            provider: ModelProvider::Codex,
            api_key: access_token.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens,
            timeout,
            codex_account_id: Some(account_id.into()),
            codex_session_id: Some(session_id.into()),
            transport: None,
        }
    }

    /// Attach independently admitted transport custody. This is not a task grant.
    pub fn with_admitted_transport(mut self, transport: NativeProviderTransport) -> Self {
        self.transport = Some(transport);
        self
    }

    fn validate(&self) -> Result<(), HostRuntimeError> {
        if self.api_key.trim().is_empty()
            || self.model.trim().is_empty()
            || self.base_url.trim().is_empty()
            || self.max_tokens == 0
        {
            return Err(HostRuntimeError::Resolver(
                "provider binding is incomplete".to_owned(),
            ));
        }
        if self.provider == ModelProvider::Codex
            && (self.codex_account_id.as_deref().is_none_or(str::is_empty)
                || self.codex_session_id.as_deref().is_none_or(str::is_empty))
        {
            return Err(HostRuntimeError::Resolver(
                "Codex provider binding has no account/session identity".to_owned(),
            ));
        }
        Ok(())
    }

    fn policy_identity(&self) -> (&str, &str, &str) {
        (self.provider.as_str(), &self.model, &self.base_url)
    }
}

impl fmt::Debug for ResolvedProviderBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedProviderBinding")
            .field("provider", &self.provider)
            .field("api_key", &"[REDACTED]")
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("max_tokens", &self.max_tokens)
            .field("timeout", &self.timeout)
            .field("codex_account_id", &self.codex_account_id)
            .field(
                "codex_session_id",
                &self.codex_session_id.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Resolve credential bytes only after WhippleScript has admitted the policy,
/// provider binding, and placement ceiling. Resolver errors must not contain
/// secret material.
pub trait SecretResolver {
    fn resolve_provider(
        &self,
        binding: &ProviderBindingRef,
        placement_ceiling_ref: &str,
    ) -> Result<ResolvedProviderBinding, String>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedImage {
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// The host implementation behind package-declared resource tools.
///
/// Every call receives only the resource references admitted for this turn.
/// WhippleScript checks the tool name against the pinned package before invoking
/// the resolver, so neither model nor host can widen the tool surface in flight.
/// One witnessed workspace mutation (DR-0036 §1): the resolver performed the
/// operation itself, so this is the runtime's own claim of the delta — a
/// content reference, never an inline body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WitnessedWrite {
    pub path: String,
    /// `"add"`, `"modify"`, or `"delete"`.
    pub kind: String,
    pub content_hash: String,
    pub bytes: u64,
}

/// Exact proposed native bytes offered to embedding custody before a file
/// effect. This is preparation, not evidence that the write succeeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedWorkspaceWrite {
    pub path: String,
    pub kind: String,
    pub content_hash: String,
    pub bytes: u64,
}

type WorkspacePayloadRetention =
    dyn Fn(&PreparedWorkspaceWrite, &[u8]) -> Result<(), String> + Send + Sync;

/// The per-turn workspace witness a resolver hands back when the turn segment
/// ends (DR-0036 §1; turn-witness.maude). The receipt claims a workspace cut
/// only from a complete witness — a harness that cannot witness every
/// mutation declines honestly, and consumers treat absence as "unwitnessed",
/// never as "no changes".
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnWitness {
    /// The resolver mediates no workspace: nothing to witness or decline.
    Unavailable,
    /// Every mutation went through the resolver, so the delta is complete —
    /// possibly empty (the explicitly-empty cut, distinguishable from
    /// declining).
    Witnessed {
        writes: Vec<WitnessedWrite>,
        reads: Vec<String>,
    },
    /// An unmediated mutation channel ran (a native command): the delta
    /// cannot be claimed. Decline, never fabricate.
    Unwitnessed { reason: String },
}

/// Original recorded workspace evidence, observed under current product access.
/// This is evidence for the embedding product, never an execution grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedWorkspaceWitness {
    pub receipt: TurnReceipt,
    pub writes: Vec<WitnessedWrite>,
    pub reads: Vec<String>,
}

/// Borrowed correlation for the owner's actual native send, never a permission
/// or saved execution grant. Credential material and headers are not exposed.
pub struct NativeProviderRequest<'a> {
    pub command: &'a StartTurnCommand,
    pub ordinal: u64,
    pub url: &'a str,
    pub body: &'a Value,
    pub provenance: Option<&'a whipplescript_kernel::sansio::ModelRequestProvenance>,
    pub transport_pinned: bool,
    pub configured_timeout: Duration,
}

pub trait ResourceResolver {
    /// Additional current product access, independent of the pinned runtime
    /// policy. A refusal terminates this invocation; detail is not disclosed.
    fn check_live_access(&self) -> Result<(), String> {
        Ok(())
    }

    /// Let the embedding Home hold its short admission exclusion while the
    /// first turn effect is committed. The callback must invoke `start` once;
    /// the default keeps ordinary runtime callers on the same path. No model
    /// transport or tool work occurs inside this callback.
    fn with_turn_start_admission(
        &self,
        _command: &StartTurnCommand,
        start: &mut dyn FnMut() -> Result<(), HostRuntimeError>,
    ) -> Result<(), HostRuntimeError> {
        start()
    }

    /// Revalidate current embedding authority for an exact retry of a turn
    /// whose first effect already exists. The callback may finish retained
    /// target evidence, but model and tool work follows after it returns.
    fn with_turn_reuse_admission(
        &self,
        _command: &StartTurnCommand,
        reuse: &mut dyn FnMut() -> Result<(), HostRuntimeError>,
    ) -> Result<(), HostRuntimeError> {
        reuse()
    }

    /// Hold embedding-owned current approval through the borrowed, one-use
    /// native send. Clamp its positive duration to the remaining authority
    /// allowance. The owner retains the response; the hook cannot fabricate it.
    /// The send ends at response headers, before body/live-observation callbacks.
    /// This default preserves ordinary native sends and grants no office access.
    fn with_native_provider_request(
        &self,
        request: &NativeProviderRequest<'_>,
        send: &mut dyn FnMut(Duration) -> Result<(), String>,
    ) -> Result<(), String> {
        send(request.configured_timeout)
    }

    fn resolve_image(&self, image: &ResourceRef) -> Result<ResolvedImage, String>;

    /// Attest the exact skill catalogue this turn puts in the system prompt.
    /// The runtime reads one registry snapshot and verifies each body against
    /// that snapshot before asking the embedding host for source identities.
    /// A resolver that cannot classify those skills leaves provenance unknown.
    fn model_skill_catalogue_provenance(&self, _skills: &[SkillView]) -> ModelContentProvenance {
        ModelContentProvenance::default()
    }

    /// Files the governed virtual bash read since the last drain (G2 of the
    /// output-attribution note). Defaulted, so a resolver with no virtual
    /// workspace is unaffected.
    fn take_workspace_reads(&self) -> Vec<whipplescript_kernel::whip_shell::ShellRead> {
        Vec::new()
    }

    /// Sources entering a tool result beyond its model-authored arguments.
    /// An embedding host must opt in for tools it can account for completely.
    fn model_output_provenance(
        &self,
        _admitted_resources: &[ResourceRef],
        _call: &ToolCall,
    ) -> whipplescript_kernel::sansio::ModelContentProvenance {
        Default::default()
    }

    fn execute_tool(
        &self,
        admitted_resources: &[ResourceRef],
        call: &ToolCall,
    ) -> Result<String, String>;

    /// Take (and reset) the workspace witness accumulated since the last
    /// take — called once per turn segment. The default declines nothing and
    /// claims nothing: a resolver without a workspace has no witness.
    fn take_turn_witness(&self) -> TurnWitness {
        TurnWitness::Unavailable
    }

    /// Environment facts the resolver can attest for this turn. Opaque remote
    /// resolvers leave fields unavailable instead of letting the runtime infer
    /// ambient host state that the model cannot actually access.
    fn model_visible_environment(&self) -> EnvironmentState {
        EnvironmentState {
            cwd: None,
            workspace_roots: Vec::new(),
            timezone: None,
            shell_family: None,
        }
    }

    /// Live projection of the assistant's answer text while a turn is
    /// running: called once per provider `output_text` delta, in order, as
    /// the stream arrives. This is the native host's synchronous activity
    /// seam for `streaming_output` (spec/agent-harness.md "Live Turn
    /// Observation"): ephemeral by contract — never durable, never ordered
    /// evidence, and once the turn settles the durable assistant output
    /// replaces whatever was projected. Reasoning deltas are never offered.
    /// The default observes nothing.
    fn observe_text_delta(&self, _delta: &str) {}
}

fn attested_skill_catalogue_provenance<R: ResourceResolver + ?Sized>(
    store: &SqliteStore,
    resources: &R,
    skills: &[SkillView],
) -> ModelContentProvenance {
    if skills.is_empty() {
        return ModelContentProvenance {
            source_handles: Vec::new(),
            complete: true,
        };
    }
    for skill in skills {
        let Ok(Some(body)) = store.skill_body(&skill.source_path) else {
            return ModelContentProvenance::default();
        };
        let Ok(frontmatter) =
            whipplescript_store::skill_frontmatter::parse_skill_frontmatter(&body)
        else {
            return ModelContentProvenance::default();
        };
        if whipplescript_store::stable_hash_hex(&body) != skill.content_hash
            || frontmatter.name != skill.name
            || frontmatter.description != skill.description
        {
            return ModelContentProvenance::default();
        }
    }
    resources.model_skill_catalogue_provenance(skills)
}

fn hosted_model_visible_world<R: ResourceResolver + ?Sized>(
    command: &StartTurnCommand,
    package: &ResolvedPackage,
    resources: &R,
) -> Result<WorldSnapshot, String> {
    let identity = ExecutionIdentity {
        program: Some(package.program.workflow.clone()),
        revision: Some(command.package_version_ref.clone()),
        instance: command.instance_ref.clone(),
        agent: package.agent.clone(),
        effect: command.command_id.clone(),
        turn: command.command_id.clone(),
        harness: HarnessClass::Managed,
        placement: "native_host_facade".to_owned(),
    };
    let mut environment = resources.model_visible_environment();
    if package.tools.iter().any(|tool| tool.name == "bash") {
        environment.shell_family = Some("whip-shell/bash".to_owned());
    }
    let compute = ComputeResources {
        max_model_rounds: Some(package.max_steps),
        remaining_model_rounds: Some(package.max_steps),
        concurrency_class: Some("host-facade-owned-turn".to_owned()),
        ..ComputeResources::default()
    };
    let mut envelope = EffectiveTurnEnvelope::default();
    for capability in ["workspace.read", "workspace.write"] {
        let disposition = if package.capabilities.iter().any(|item| item == capability) {
            GovernanceDisposition::Enforced
        } else {
            GovernanceDisposition::Unavailable
        };
        envelope.filesystem.push(GovernanceRule {
            resource: capability.to_owned(),
            disposition,
            scope: command
                .resources
                .iter()
                .filter(|resource| resource.kind == "file_store")
                .map(|resource| resource.handle.clone())
                .collect(),
        });
    }
    envelope.network.push(GovernanceRule {
        resource: "network".to_owned(),
        disposition: GovernanceDisposition::Unavailable,
        scope: vec!["no model-facing network capability".to_owned()],
    });
    envelope.process.push(GovernanceRule {
        resource: "process:shell".to_owned(),
        disposition: if package
            .capabilities
            .iter()
            .any(|item| item == "command.run")
        {
            GovernanceDisposition::Enforced
        } else {
            GovernanceDisposition::Unavailable
        },
        scope: command
            .resources
            .iter()
            .filter(|resource| resource.kind == "command")
            .map(|resource| resource.handle.clone())
            .collect(),
    });
    envelope
        .tools
        .extend(package.tools.iter().map(|tool| GovernanceRule {
            resource: format!("tool:{}", tool.name),
            disposition: GovernanceDisposition::Enforced,
            scope: vec!["offered this turn".to_owned()],
        }));
    envelope.approvals.push(GovernanceRule {
        resource: "human_approval".to_owned(),
        disposition: GovernanceDisposition::Unavailable,
        scope: vec!["this Managed turn has no approval mechanism".to_owned()],
    });
    envelope.custody.push(GovernanceRule {
        resource: "provider_credentials".to_owned(),
        disposition: GovernanceDisposition::Unavailable,
        scope: vec!["resolved only at the host egress boundary".to_owned()],
    });
    envelope.budgets.push(GovernanceRule {
        resource: "model_rounds".to_owned(),
        disposition: GovernanceDisposition::Enforced,
        scope: vec![format!("maximum {}", package.max_steps)],
    });
    WorldSnapshot::new(&command.command_id)
        .with_section("identity", &identity)?
        .with_section("environment", &environment)?
        .with_section("compute", &compute)?
        .with_section("governance", &envelope.model_projection())?
        .with_agent_topology(&AgentTopology::default())?
        .with_section("mutability", &WorldMutability::default())
}

/// WhippleScript-owned native implementation of the workspace capability used
/// by embedding desktop hosts. GaugeDesk supplies only the root and any
/// read-only subtrees; WhippleScript parses tool arguments, confines paths,
/// rejects symlink traversal, and performs the operation.
pub struct NativeWorkspaceResolver {
    /// Files the governed virtual bash read, accumulated per tool call and
    /// drained by the harness loop. Behind a lock because the resolver surface
    /// takes `&self`.
    workspace_reads: std::sync::Mutex<Vec<whipplescript_kernel::whip_shell::ShellRead>>,
    /// The exact bytes successful single-file `read` and `grep` tools saw,
    /// keyed by their call IDs.
    /// A batch may execute several tools before the next model request.
    model_read_witnesses: std::sync::Mutex<HashMap<String, ModelReadWitness>>,
    /// A bounded directory search or listing's complete source set. Omitted
    /// when traversal cannot attest every searched or listed entry.
    model_scan_witnesses: std::sync::Mutex<HashMap<String, ModelScanWitness>>,
    root: PathBuf,
    read_only: Vec<PathBuf>,
    max_output_bytes: usize,
    /// The per-turn workspace witness (DR-0036 §1): every mutation this
    /// resolver performs is recorded. `taint` marks the segment *unwitnessed*
    /// so the turn declines the cut honestly if an unmediated channel ever
    /// mutates the workspace. No channel does today — `bash` runs in the
    /// in-isolate Bashkit shell and every effect is witnessed — so `witness_taint`
    /// is a reserved hook for a future native-OS command tool (see
    /// spec/native-command-tool-tracker.md).
    witness: std::sync::Mutex<WitnessState>,
    /// Renames of presented roots admitted this turn (DR-0148). Each applies
    /// to later calls while their references still present the old name.
    root_renames: std::sync::Mutex<Vec<RootRename>>,
    /// The embedding host's admission of a presented-root rename. Without
    /// one, every rename is refused.
    rename_admission: Option<Box<RenameAdmission>>,
    call_rename_admission: Option<Box<CallRenameAdmission>>,
    /// The embedding owns encrypted custody and original-command binding.
    payload_retention: Option<Box<WorkspacePayloadRetention>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelReadWitness {
    pub path: String,
    pub content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelScanWitness {
    pub root: String,
    pub files: Vec<ModelReadWitness>,
    pub directories: Vec<String>,
}

#[derive(Default)]
struct WitnessState {
    writes: Vec<WitnessedWrite>,
    reads: Vec<String>,
    taint: Option<String>,
}

/// What a model path names in the native workspace.
enum Target {
    Stored {
        absolute: PathBuf,
        stored: String,
    },
    /// A directory that exists only in the view (DR-0148).
    Synthetic,
}

/// What a walk covered.
enum Walked {
    Stored { stored: String, single_file: bool },
    Synthetic,
}

type RenameAdmission = dyn Fn(&RootRename) -> Result<(), String> + Send + Sync;
type CallRenameAdmission =
    dyn Fn(&ToolCall, usize, &RootRename) -> Result<(), String> + Send + Sync;

impl NativeWorkspaceResolver {
    pub fn take_model_read_witness(&self, call_id: &str) -> Option<ModelReadWitness> {
        self.model_read_witnesses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(call_id)
    }

    pub fn take_model_scan_witness(&self, call_id: &str) -> Option<ModelScanWitness> {
        self.model_scan_witnesses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(call_id)
    }

    fn witness_write(&self, path: &str, existed: bool, content: &[u8]) {
        let mut state = self.witness.lock().expect("witness lock");
        state.writes.push(WitnessedWrite {
            path: path.to_owned(),
            kind: if existed { "modify" } else { "add" }.to_owned(),
            content_hash: sha256_hex(content),
            bytes: content.len() as u64,
        });
    }

    fn witness_delete(&self, path: &str) {
        let mut state = self.witness.lock().expect("witness lock");
        state.writes.push(WitnessedWrite {
            path: path.to_owned(),
            kind: "delete".to_owned(),
            content_hash: sha256_hex(&[]),
            bytes: 0,
        });
    }

    fn witness_read(&self, path: &str) {
        let mut state = self.witness.lock().expect("witness lock");
        state.reads.push(path.to_owned());
    }

    /// Marks the current turn segment *unwitnessed* (DR-0036 honest-decline):
    /// `take_turn_witness` then reports `Unwitnessed` and the receipt omits the
    /// workspace-cut claim rather than fabricating one. RESERVED HOOK: no
    /// channel taints today (all mutations go through the mediated tool surface
    /// / Bashkit), so this has no caller. A future native-OS command tool must
    /// call it (or bring its own witnessing) — tracked in
    /// spec/native-command-tool-tracker.md.
    #[allow(dead_code)]
    fn witness_taint(&self, reason: &str) {
        let mut state = self.witness.lock().expect("witness lock");
        if state.taint.is_none() {
            state.taint = Some(reason.to_owned());
        }
    }
}

impl NativeWorkspaceResolver {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|error| format!("cannot open workspace capability: {error}"))?;
        if !root.is_dir() {
            return Err("workspace capability root is not a directory".to_owned());
        }
        Ok(Self {
            workspace_reads: std::sync::Mutex::new(Vec::new()),
            model_read_witnesses: std::sync::Mutex::new(HashMap::new()),
            model_scan_witnesses: std::sync::Mutex::new(HashMap::new()),
            root,
            read_only: Vec::new(),
            max_output_bytes: 50_000,
            witness: std::sync::Mutex::new(WitnessState::default()),
            root_renames: std::sync::Mutex::new(Vec::new()),
            rename_admission: None,
            call_rename_admission: None,
            payload_retention: None,
        })
    }

    /// Retain exact proposed bytes before applying native file mutations.
    /// A refusal prevents the file effect and is redacted. This callback grants
    /// no authority; saved successful workspace evidence remains necessary.
    pub fn with_payload_retention(
        mut self,
        retain: impl Fn(&PreparedWorkspaceWrite, &[u8]) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.payload_retention = Some(Box::new(retain));
        self
    }

    fn prepare_payload(&self, path: &str, kind: &str, body: &[u8]) -> Result<(), String> {
        if let Some(retain) = &self.payload_retention {
            let prepared = PreparedWorkspaceWrite {
                path: path.to_owned(),
                kind: kind.to_owned(),
                content_hash: sha256_hex(body),
                bytes: body.len() as u64,
            };
            retain(&prepared, body)
                .map_err(|_| "native workspace payload retention refused".to_owned())?;
        }
        Ok(())
    }

    /// Admit or refuse each rename of a presented root that a `bash` command
    /// makes (DR-0148). The host records an admitted rename as its own fact;
    /// a refusal refuses the whole command before any file changes.
    pub fn with_root_rename_admission(
        mut self,
        admit: impl Fn(&RootRename) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.rename_admission = Some(Box::new(admit));
        self.call_rename_admission = None;
        self
    }

    /// Exact original call and rename ordinal for embedding-owned phases.
    /// These values correlate intent; the embedding still supplies current
    /// authority, durable effect evidence and final publication checks.
    /// Selecting this boundary clears legacy admission, with no failure fallback.
    pub fn with_root_rename_call_admission(
        mut self,
        admit: impl Fn(&ToolCall, usize, &RootRename) -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        self.call_rename_admission = Some(Box::new(admit));
        self.rename_admission = None;
        self
    }

    pub fn read_only(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Result<Self, String> {
        self.read_only = paths
            .into_iter()
            .map(|path| normalize_relative(&path))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self)
    }

    fn resolve(&self, path: &str, write: bool) -> Result<PathBuf, String> {
        self.resolve_stored(path, path, write)
    }

    /// Resolve a stored workspace path to its file, naming `display` — the
    /// path as the model gave it — in every error.
    fn resolve_stored(&self, stored: &str, display: &str, write: bool) -> Result<PathBuf, String> {
        let relative = normalize_relative(Path::new(stored))
            .map_err(|_| format!("workspace path `{display}` escapes its capability"))?;
        if write
            && self
                .read_only
                .iter()
                .any(|protected| relative.starts_with(protected))
        {
            return Err(format!("workspace path `{display}` is read-only"));
        }
        let mut resolved = self.root.clone();
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(format!("workspace path `{display}` escapes its capability"));
            };
            resolved.push(segment);
            if let Ok(metadata) = fs::symlink_metadata(&resolved) {
                if metadata.file_type().is_symlink() {
                    return Err(format!("workspace path `{display}` traverses a symlink"));
                }
            }
        }
        Ok(resolved)
    }

    /// The model-visible namespace of this call: the admitted file stores,
    /// with every rename this resolver has admitted this turn (DR-0148).
    fn admitted_view(&self, resources: &[ResourceRef]) -> Result<FileView, String> {
        if !resources
            .iter()
            .any(|resource| resource.kind == "file_store")
        {
            return Err("turn has no admitted file-store capability".to_owned());
        }
        let mut view = FileView::from_resources(resources)?;
        view.apply_renames(
            &self
                .root_renames
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )?;
        Ok(view)
    }

    fn resolve_model(&self, path: &str, write: bool, view: &FileView) -> Result<Target, String> {
        match view.resolve(path)? {
            ViewResolution::Stored { stored, writable } => {
                if write && !writable {
                    return Err(format!("workspace path `{path}` is read-only"));
                }
                let absolute = self.resolve_stored(&stored, path, write)?;
                Ok(Target::Stored { absolute, stored })
            }
            ViewResolution::Synthetic if !write => Ok(Target::Synthetic),
            ViewResolution::Synthetic => Err(format!(
                "workspace path `{path}` is outside the admitted file-store selectors"
            )),
        }
    }

    fn resolve_admitted(
        &self,
        path: &str,
        write: bool,
        view: &FileView,
    ) -> Result<(PathBuf, String), String> {
        match self.resolve_model(path, write, view)? {
            Target::Stored { absolute, stored } => Ok((absolute, stored)),
            Target::Synthetic => Err(format!("workspace path `{path}` is a directory")),
        }
    }

    /// The path a record keeps for a model path: its selector once any root
    /// is presented, and the path as given otherwise, as before DR-0148.
    fn record_path(view: &FileView, model: &str, stored: &str) -> String {
        if view.presents() {
            stored.to_owned()
        } else {
            model.to_owned()
        }
    }

    /// Walk every file beneath a model path, handing `visit` each file's
    /// stored path, the path the model sees, its absolute path, and whether
    /// its name is valid UTF-8. A directory that exists only in the view
    /// walks each root beneath it. Returns what the path named.
    fn walk_model(
        &self,
        path: &str,
        view: &FileView,
        visit: &mut dyn FnMut(&str, &str, &Path, bool) -> bool,
    ) -> Result<Walked, String> {
        let mut continue_with = |stored: &str, absolute: &Path, valid: bool| {
            let presented = view.presented(stored).unwrap_or_else(|| stored.to_owned());
            visit(stored, &presented, absolute, valid)
        };
        match self.resolve_model(path, false, view)? {
            Target::Stored { absolute, stored } => {
                let single_file =
                    fs::symlink_metadata(&absolute).is_ok_and(|metadata| metadata.is_file());
                walk_workspace(&self.root, &absolute, &mut continue_with)?;
                Ok(Walked::Stored {
                    stored,
                    single_file,
                })
            }
            Target::Synthetic => {
                let directory = normalize_stored_path(path)?;
                let mut stopped = false;
                for root in view
                    .roots()
                    .iter()
                    .filter(|root| is_within(root.visible(), &directory))
                {
                    let absolute = self.resolve_stored(&root.stored, path, false)?;
                    if !absolute.exists() {
                        continue;
                    }
                    walk_workspace(&self.root, &absolute, &mut |stored, absolute, valid| {
                        stopped = !continue_with(stored, absolute, valid);
                        !stopped
                    })?;
                    if stopped {
                        break;
                    }
                }
                Ok(Walked::Synthetic)
            }
        }
    }

    fn cap(&self, text: String) -> String {
        if text.len() <= self.max_output_bytes {
            return text;
        }
        let mut boundary = self.max_output_bytes;
        while !text.is_char_boundary(boundary) {
            boundary -= 1;
        }
        format!(
            "{}\n… output truncated by WhippleScript …",
            &text[..boundary]
        )
    }

    fn read(&self, call_id: &str, arguments: &Value, view: &FileView) -> Result<String, String> {
        let path = string_argument(arguments, "path")?;
        let (resolved, stored) = self.resolve_admitted(path, false, view)?;
        let recorded = Self::record_path(view, path, &stored);
        self.witness_read(&recorded);
        let text = fs::read_to_string(&resolved)
            .map_err(|error| format!("cannot read workspace path `{path}`: {error}"))?;
        let offset = arguments
            .get("offset")
            .and_then(Value::as_u64)
            .unwrap_or(1)
            .max(1) as usize;
        let limit = arguments
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(2_000) as usize;
        let lines = text
            .lines()
            .skip(offset - 1)
            .take(limit)
            .enumerate()
            .map(|(index, line)| format!("{}: {line}", offset + index))
            .collect::<Vec<_>>()
            .join("\n");
        self.model_read_witnesses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                call_id.to_owned(),
                ModelReadWitness {
                    path: recorded,
                    content_hash: whipplescript_store::stable_hash_bytes_hex(text.as_bytes()),
                },
            );
        Ok(self.cap(lines))
    }

    fn write(&self, arguments: &Value, view: &FileView) -> Result<String, String> {
        let path = string_argument(arguments, "path")?;
        let content = string_argument(arguments, "content")?;
        let (resolved, stored) = self.resolve_admitted(path, true, view)?;
        let existed = resolved.exists();
        self.prepare_payload(
            &Self::record_path(view, path, &stored),
            if existed { "modify" } else { "add" },
            content.as_bytes(),
        )?;
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create parent for `{path}`: {error}"))?;
            reject_symlinks_between(&self.root, parent, path)?;
        }
        fs::write(&resolved, content)
            .map_err(|error| format!("cannot write workspace path `{path}`: {error}"))?;
        self.witness_write(
            &Self::record_path(view, path, &stored),
            existed,
            content.as_bytes(),
        );
        Ok(format!("wrote {} bytes to {path}", content.len()))
    }

    fn edit(&self, arguments: &Value, view: &FileView) -> Result<String, String> {
        let path = string_argument(arguments, "path")?;
        let (resolved, stored) = self.resolve_admitted(path, true, view)?;
        let text = fs::read_to_string(&resolved)
            .map_err(|error| format!("cannot edit workspace path `{path}`: {error}"))?;
        let edits = arguments
            .get("edits")
            .and_then(Value::as_array)
            .ok_or_else(|| "`edits` must be an array".to_owned())?;
        let (text, applied) = whipplescript_kernel::workspace_edit::apply_edits(text, path, edits)?;
        self.prepare_payload(
            &Self::record_path(view, path, &stored),
            "modify",
            text.as_bytes(),
        )?;
        fs::write(&resolved, &text)
            .map_err(|error| format!("cannot edit workspace path `{path}`: {error}"))?;
        self.witness_write(
            &Self::record_path(view, path, &stored),
            true,
            text.as_bytes(),
        );
        Ok(format!("applied {applied} edit(s) to {path}"))
    }

    fn list(&self, call_id: &str, arguments: &Value, view: &FileView) -> Result<String, String> {
        let path = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
        let (resolved, stored) = match self.resolve_model(path, false, view)? {
            Target::Stored { absolute, stored } => (absolute, stored),
            Target::Synthetic => {
                // A directory that exists only in the view lists the roots
                // beneath it. Its listing names no stored file, so it carries
                // no exact witness and keeps the coarse source.
                self.witness_read(&normalize_stored_path(path)?);
                let names = view
                    .children(path)
                    .into_iter()
                    .map(|entry| match entry.root {
                        Some(stored)
                            if !self
                                .resolve_stored(&stored, path, false)
                                .is_ok_and(|absolute| absolute.is_dir()) =>
                        {
                            entry.name
                        }
                        _ => format!("{}/", entry.name),
                    })
                    .collect::<Vec<_>>();
                return Ok(self.cap(names.join("\n")));
            }
        };
        self.witness_read(&Self::record_path(view, path, &stored));
        let mut names = Vec::new();
        let mut files = Vec::new();
        let mut directories = Vec::new();
        let mut complete = true;
        let mut total_bytes = 0u64;
        for row in fs::read_dir(&resolved)
            .map_err(|error| format!("cannot list workspace path `{path}`: {error}"))?
        {
            let Ok(entry) = row else {
                complete = false;
                continue;
            };
            let file_name = entry.file_name();
            if file_name.to_str().is_none() {
                complete = false;
            }
            let mut name = file_name.to_string_lossy().into_owned();
            let kind = entry.file_type();
            if kind.as_ref().is_ok_and(|kind| kind.is_dir()) {
                name.push('/');
            }
            names.push(name);
            if !complete || names.len() > 128 {
                complete = false;
                continue;
            }
            let Some(relative) = entry
                .path()
                .strip_prefix(&self.root)
                .ok()
                .and_then(|path| path.to_str().map(str::to_owned))
            else {
                complete = false;
                continue;
            };
            match kind {
                Ok(kind) if kind.is_dir() => directories.push(relative),
                Ok(kind) if kind.is_file() => {
                    let max_file = (16 * 1024 * 1024u64)
                        .saturating_sub(total_bytes)
                        .min(8 * 1024 * 1024);
                    let bytes = fs::File::open(entry.path()).and_then(|file| {
                        let mut bytes = Vec::new();
                        file.take(max_file + 1).read_to_end(&mut bytes)?;
                        Ok(bytes)
                    });
                    match bytes {
                        Ok(bytes) if bytes.len() as u64 <= max_file => {
                            total_bytes += bytes.len() as u64;
                            files.push(ModelReadWitness {
                                path: relative,
                                content_hash: whipplescript_store::stable_hash_bytes_hex(&bytes),
                            });
                        }
                        _ => complete = false,
                    }
                }
                _ => complete = false,
            }
        }
        names.sort();
        if complete && !names.is_empty() {
            self.model_scan_witnesses
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(
                    call_id.to_owned(),
                    ModelScanWitness {
                        root: Self::record_path(view, path, &stored),
                        files,
                        directories,
                    },
                );
        }
        Ok(self.cap(names.join("\n")))
    }

    fn find(&self, call_id: &str, arguments: &Value, view: &FileView) -> Result<String, String> {
        let path = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
        let pattern = string_argument(arguments, "pattern")?;
        let mut matches = Vec::new();
        // A negative name match still depends on every traversed file. Keep a
        // bounded exact witness for the whole search, including nonmatches;
        // an unreadable or larger scan remains coarse for model projection.
        let mut scan_files = Vec::new();
        let mut scan_complete = true;
        let mut scan_bytes = 0u64;
        let walked = self.walk_model(
            path,
            view,
            &mut |stored, presented, absolute, valid_path| {
                if !valid_path {
                    scan_complete = false;
                }
                if scan_files.len() < 128 {
                    // `find` needs filenames, not bodies. Bound the extra reads
                    // made only to attest current bytes for Raw context.
                    let remaining = (16 * 1024 * 1024u64).saturating_sub(scan_bytes);
                    let max_file = remaining.min(8 * 1024 * 1024);
                    let bytes = fs::File::open(absolute).and_then(|file| {
                        let mut bytes = Vec::new();
                        file.take(max_file + 1).read_to_end(&mut bytes)?;
                        Ok(bytes)
                    });
                    match bytes {
                        Ok(bytes) if bytes.len() as u64 <= max_file => {
                            scan_bytes += bytes.len() as u64;
                            scan_files.push(ModelReadWitness {
                                path: stored.to_owned(),
                                content_hash: whipplescript_store::stable_hash_bytes_hex(&bytes),
                            });
                        }
                        Ok(_) => scan_complete = false,
                        Err(_) => scan_complete = false,
                    }
                } else {
                    scan_complete = false;
                }
                if wildcard_matches(pattern, presented) {
                    matches.push(presented.to_owned());
                }
                if matches.len() >= 5_000 {
                    scan_complete = false;
                    false
                } else {
                    true
                }
            },
        )?;
        match walked {
            Walked::Stored {
                stored,
                single_file,
            } => {
                self.witness_read(&Self::record_path(view, path, &stored));
                if scan_complete && !scan_files.is_empty() {
                    if single_file {
                        self.model_read_witnesses
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .insert(call_id.to_owned(), scan_files.remove(0));
                    } else {
                        self.model_scan_witnesses
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .insert(
                                call_id.to_owned(),
                                ModelScanWitness {
                                    root: Self::record_path(view, path, &stored),
                                    files: scan_files,
                                    directories: Vec::new(),
                                },
                            );
                    }
                }
            }
            Walked::Synthetic => self.witness_read(&normalize_stored_path(path)?),
        }
        matches.sort();
        Ok(self.cap(matches.join("\n")))
    }

    fn grep(&self, call_id: &str, arguments: &Value, view: &FileView) -> Result<String, String> {
        let path = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
        let pattern = string_argument(arguments, "pattern")?;
        // `ignoreCase`, `context` and `limit` are all declared by the schema
        // this tool advertises, and this implementation read NONE of them: a
        // caller asking for a case-insensitive search got a case-sensitive one,
        // a context window got no context, and a limit of ten got up to five
        // thousand — each silently. The defaults below are the ones the schema
        // states and the ones the other implementation of this tool uses.
        let ignore_case = arguments
            .get("ignoreCase")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let limit = arguments
            .get("limit")
            .and_then(Value::as_u64)
            .map_or(100, |limit| limit as usize);
        let context = arguments
            .get("context")
            .and_then(Value::as_u64)
            .map_or(0, |context| context as usize);
        // Shared with the binary's copy of this tool via the library module;
        // a second implementation is what let these diverge.
        let matcher = crate::workspace_grep::GrepMatcher::new(pattern, ignore_case);
        let mut matches = Vec::new();
        let mut matches_found = 0usize;
        // A directory search also reveals negative matches. Its witness must
        // include every file searched, not just paths that produced matches.
        let mut exact_witness = None;
        let mut scan_files = Vec::new();
        let mut scan_complete = true;
        let target = self.resolve_model(path, false, view)?;
        let (single_file, resolved) = match &target {
            Target::Stored { absolute, .. } => (
                fs::symlink_metadata(absolute).is_ok_and(|metadata| metadata.is_file()),
                Some(absolute.clone()),
            ),
            Target::Synthetic => (false, None),
        };
        let walked = self.walk_model(
            path,
            view,
            &mut |stored, presented, absolute, valid_path| {
                if !valid_path {
                    scan_complete = false;
                }
                if matches_found >= limit {
                    return false;
                }
                let Ok(text) = fs::read_to_string(absolute) else {
                    scan_complete = false;
                    return true;
                };
                if !single_file {
                    // A scan over a very large tree still runs, but cannot be
                    // projected as a bounded current-access proof.
                    if scan_files.len() < 128 {
                        scan_files.push(ModelReadWitness {
                            path: stored.to_owned(),
                            content_hash: whipplescript_store::stable_hash_bytes_hex(
                                text.as_bytes(),
                            ),
                        });
                    } else {
                        scan_complete = false;
                    }
                }
                if single_file && resolved.as_deref() == Some(absolute) {
                    exact_witness = Some(ModelReadWitness {
                        path: stored.to_owned(),
                        content_hash: whipplescript_store::stable_hash_bytes_hex(text.as_bytes()),
                    });
                }
                crate::workspace_grep::grep_file_into(
                    presented,
                    &text,
                    &matcher,
                    context,
                    limit,
                    &mut matches_found,
                    &mut matches,
                );
                true
            },
        )?;
        match walked {
            Walked::Stored { stored, .. } => {
                self.witness_read(&Self::record_path(view, path, &stored));
                if let Some(witness) = exact_witness {
                    self.model_read_witnesses
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(call_id.to_owned(), witness);
                } else if !single_file && scan_complete && !scan_files.is_empty() {
                    self.model_scan_witnesses
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .insert(
                            call_id.to_owned(),
                            ModelScanWitness {
                                root: Self::record_path(view, path, &stored),
                                files: scan_files,
                                directories: Vec::new(),
                            },
                        );
                }
            }
            Walked::Synthetic => self.witness_read(&normalize_stored_path(path)?),
        }
        Ok(self.cap(matches.join("\n")))
    }

    #[cfg(test)]
    fn bash(&self, arguments: &Value, view: &FileView) -> Result<String, String> {
        self.bash_for_call(arguments, view, None)
    }

    fn bash_for_call(
        &self,
        arguments: &Value,
        view: &FileView,
        call: Option<&ToolCall>,
    ) -> Result<String, String> {
        let command = string_argument(arguments, "command")?.trim();
        if command.is_empty() {
            return Err("command must not be empty".to_owned());
        }
        let requested = Duration::from_secs(
            arguments
                .get("timeout")
                .and_then(Value::as_u64)
                .unwrap_or(30),
        );
        if requested.is_zero() || requested > Duration::from_secs(30) {
            return Err("command timeout must be between 1 and 30 seconds".to_owned());
        }

        // The shell sees every admitted file at the path the model sees; the
        // snapshot is keyed by that path.
        let mut before = BTreeMap::new();
        let mut load_error = None;
        let mut roots = view
            .roots()
            .iter()
            .map(|root| {
                if root.stored.is_empty() {
                    Ok(self.root.clone())
                } else {
                    self.resolve(&root.stored, false)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        roots.sort();
        roots.dedup();
        for root in roots {
            if !root.exists() {
                continue;
            }
            walk_workspace(&self.root, &root, &mut |relative, absolute, _valid_path| {
                if before.len() >= 5_000 {
                    load_error = Some("bash workspace contains more than 5000 files".to_owned());
                    return false;
                }
                let stored = relative.replace('\\', "/");
                let Some(presented) = view.presented(&stored) else {
                    return true;
                };
                match fs::read(absolute) {
                    Ok(content) => {
                        before.insert(presented, (stored, content));
                        true
                    }
                    Err(error) => {
                        load_error = Some(format!(
                            "cannot load bash workspace file `{}`: {error}",
                            view.presented(&stored).unwrap_or(stored)
                        ));
                        false
                    }
                }
            })?;
            if load_error.is_some() {
                break;
            }
        }
        if let Some(error) = load_error {
            return Err(error);
        }
        let files = before
            .iter()
            .map(|(presented, (stored, content))| ShellFile {
                path: presented.clone(),
                content: content.clone(),
                writable: view.writable_stored(stored)
                    && !self
                        .read_only
                        .iter()
                        .any(|protected| Path::new(stored).starts_with(protected)),
            })
            .collect();

        let mut output = WhipShell::default().execute(ShellRequest {
            command: command.to_owned(),
            timeout: requested,
            files,
            presented_roots: view.presented_roots(),
        })?;
        // Reads are recorded under the names the command started with, so
        // they resolve through the view the command was given; a record keeps
        // the selector of a presented root.
        if view.presents() {
            for read in &mut output.reads {
                if let Ok(ViewResolution::Stored { stored, .. }) = view.resolve(&read.path) {
                    read.path = stored;
                }
            }
        }
        self.workspace_reads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .append(&mut output.reads);

        // Validate the complete result before changing the real workspace:
        // each rename of a presented root, then every changed, added or
        // removed path, under the same capability and read-only ceilings as
        // the first-class file tools. Unchanged files are not writes.
        let mut after_view = view.clone();
        let mut renames = Vec::with_capacity(output.renames.len());
        for rename in &output.renames {
            let admitted = after_view.rename(&rename.from, &rename.to)?;
            after_view.apply_renames(std::slice::from_ref(&admitted))?;
            renames.push(admitted);
        }
        let before_stored = before
            .values()
            .map(|(stored, content)| (stored.clone(), content))
            .collect::<BTreeMap<_, _>>();
        let mut after = BTreeMap::new();
        for (path, content) in &output.files {
            let stored = match after_view.resolve(path) {
                Ok(ViewResolution::Stored { stored, .. }) => stored,
                Ok(ViewResolution::Synthetic) | Err(_) => {
                    return Err(format!(
                        "workspace path `{path}` is outside the admitted file-store selectors"
                    ))
                }
            };
            if before_stored.get(&stored).copied() != Some(content) {
                let (resolved, _) = self.resolve_admitted(path, true, &after_view)?;
                if let Some(parent) = resolved.parent() {
                    reject_symlinks_between(&self.root, parent, path)?;
                }
            }
            after.insert(stored, (path, content));
        }
        let removed = before
            .iter()
            .filter(|(_, (stored, _))| !after.contains_key(stored))
            .map(|(presented, (stored, _))| (presented.clone(), stored.clone()))
            .collect::<Vec<_>>();
        for (presented, _) in &removed {
            self.resolve_admitted(presented, true, view)?;
        }
        let call_bound = if let Some(admit) = self
            .call_rename_admission
            .as_ref()
            .filter(|_| !renames.is_empty())
        {
            let call = call.ok_or_else(|| "root rename has no original tool call".to_owned())?;
            if call.id.trim().is_empty() {
                return Err("root rename has no original tool call ID".to_owned());
            }
            Some((admit, call))
        } else {
            None
        };
        // Prepare the complete batch before any filesystem changes or retained
        // root rename. Earlier prepared payloads are not successful-write facts.
        let record = |presented: &str, stored: &str| Self::record_path(view, presented, stored);
        for (presented, stored) in &removed {
            self.prepare_payload(&record(presented, stored), "delete", &[])?;
        }
        for (stored, (path, content)) in &after {
            if before_stored.get(stored).copied() != Some(*content) {
                self.prepare_payload(
                    &record(path, stored),
                    if before_stored.contains_key(stored) {
                        "modify"
                    } else {
                        "add"
                    },
                    content,
                )?;
            }
        }
        for (ordinal, rename) in renames.iter().enumerate() {
            if let Some((admit, call)) = call_bound {
                admit(call, ordinal, rename)?;
                continue;
            }
            match &self.rename_admission {
                Some(admit) => admit(rename)?,
                None => {
                    return Err(format!(
                        "renaming `{}` is not supported by this workspace host",
                        rename.from
                    ))
                }
            }
        }
        self.root_renames
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend(renames);

        for (presented, stored) in &removed {
            let resolved = self.resolve_stored(stored, presented, true)?;
            fs::remove_file(&resolved).map_err(|error| {
                format!("cannot delete bash workspace path `{presented}`: {error}")
            })?;
            self.witness_delete(&record(presented, stored));
        }
        for (stored, (path, content)) in &after {
            if before_stored.get(stored).copied() == Some(*content) {
                continue;
            }
            let resolved = self.resolve_stored(stored, path, true)?;
            if let Some(parent) = resolved.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot create parent for `{path}`: {error}"))?;
                reject_symlinks_between(&self.root, parent, path)?;
            }
            let existed = before_stored.contains_key(stored);
            fs::write(&resolved, content)
                .map_err(|error| format!("cannot write bash workspace path `{path}`: {error}"))?;
            self.witness_write(&record(path, stored), existed, content);
        }

        let mut combined = output.stdout;
        combined.push_str(&output.stderr);
        let combined = self.cap(combined);
        match output.exit_code {
            0 => Ok(combined),
            code => Err(format!("command exited with status {code}\n{combined}")),
        }
    }
}

impl ResourceResolver for NativeWorkspaceResolver {
    fn take_workspace_reads(&self) -> Vec<whipplescript_kernel::whip_shell::ShellRead> {
        std::mem::take(
            &mut *self
                .workspace_reads
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        )
    }

    fn model_visible_environment(&self) -> EnvironmentState {
        let root = self.root.display().to_string();
        EnvironmentState {
            cwd: Some(root.clone()),
            workspace_roots: vec![root],
            timezone: Some("UTC".to_owned()),
            shell_family: None,
        }
    }

    fn resolve_image(&self, image: &ResourceRef) -> Result<ResolvedImage, String> {
        let locator = image.selector.as_deref().unwrap_or(&image.handle);
        let path = self.resolve(locator, false)?;
        let bytes =
            fs::read(&path).map_err(|error| format!("cannot read media `{locator}`: {error}"))?;
        let media_type = match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("webp") => "image/webp",
            Some("bmp") => "image/bmp",
            Some("tif" | "tiff") => "image/tiff",
            Some("ico") => "image/vnd.microsoft.icon",
            Some("pnm" | "pbm" | "pgm" | "ppm") => "image/x-portable-anymap",
            Some("tga") => "image/x-tga",
            Some("qoi") => "image/qoi",
            Some("pdf") => "application/pdf",
            Some("docx") => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
            Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            Some("pptx") => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            }
            Some("doc") => "application/msword",
            Some("xls") => "application/vnd.ms-excel",
            Some("ppt") => "application/vnd.ms-powerpoint",
            Some("wav") => "audio/wav",
            Some("mp3") => "audio/mpeg",
            Some("mp4") => "video/mp4",
            _ => return Err("unsupported media type".to_owned()),
        };
        Ok(ResolvedImage {
            media_type: media_type.to_owned(),
            bytes,
        })
    }

    fn execute_tool(
        &self,
        admitted_resources: &[ResourceRef],
        call: &ToolCall,
    ) -> Result<String, String> {
        // Reusing an ID cannot inherit a prior read, even if this call fails.
        self.take_model_read_witness(&call.id);
        self.take_model_scan_witness(&call.id);
        let view = self.admitted_view(admitted_resources)?;
        let view = &view;
        match call.name.as_str() {
            "read" => self.read(&call.id, &call.arguments, view),
            "write" => self.write(&call.arguments, view),
            "edit" => self.edit(&call.arguments, view),
            "ls" => self.list(&call.id, &call.arguments, view),
            "find" => self.find(&call.id, &call.arguments, view),
            "grep" => self.grep(&call.id, &call.arguments, view),
            "bash" => {
                if !admitted_resources
                    .iter()
                    .any(|resource| resource.kind == "command")
                {
                    return Err("turn has no admitted command capability".to_owned());
                }
                self.bash_for_call(&call.arguments, view, Some(call))
            }
            _ => Err("tool has no native workspace implementation".to_owned()),
        }
    }

    fn take_turn_witness(&self) -> TurnWitness {
        self.model_read_witnesses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        self.model_scan_witnesses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        let state = std::mem::take(&mut *self.witness.lock().expect("witness lock"));
        match state.taint {
            Some(reason) => TurnWitness::Unwitnessed { reason },
            None => TurnWitness::Witnessed {
                writes: state.writes,
                reads: state.reads,
            },
        }
    }
}

/// Compatibility names for existing native embedding consumers. The schemas
/// now come from the placement-neutral kernel module used by the DO host too.
pub use whipplescript_kernel::host_package::{
    workspace_tool_specs as native_workspace_tool_specs,
    workspace_tool_specs_from_registry as native_workspace_tool_specs_from_registry,
    workspace_tool_specs_with_capabilities as native_workspace_tool_specs_with_capabilities,
    workspace_tool_specs_with_command as native_workspace_tool_specs_with_command,
};

fn string_argument<'a>(arguments: &'a Value, name: &str) -> Result<&'a str, String> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing required string argument `{name}`"))
}

fn normalize_relative(path: &Path) -> Result<PathBuf, String> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => normalized.push(segment),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "workspace path `{}` escapes its capability",
                    path.display()
                ));
            }
        }
    }
    Ok(normalized)
}

fn reject_symlinks_between(root: &Path, target: &Path, display: &str) -> Result<(), String> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| format!("workspace path `{display}` escapes its capability"))?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component);
        if fs::symlink_metadata(&current)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(format!("workspace path `{display}` traverses a symlink"));
        }
    }
    Ok(())
}

fn walk_workspace(
    root: &Path,
    start: &Path,
    visit: &mut dyn FnMut(&str, &Path, bool) -> bool,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(start)
        .map_err(|error| format!("cannot inspect workspace path: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("workspace traversal reached a symlink".to_owned());
    }
    if metadata.is_file() {
        let relative = start
            .strip_prefix(root)
            .map_err(|_| "workspace traversal escaped its capability".to_owned())?;
        let valid_path = relative.to_str().is_some();
        let relative = relative.to_string_lossy();
        let _ = visit(&relative, start, valid_path);
        return Ok(());
    }
    let mut pending = vec![start.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries = fs::read_dir(&directory)
            .map_err(|error| format!("cannot walk workspace: {error}"))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let kind = entry
                .file_type()
                .map_err(|error| format!("cannot inspect workspace entry: {error}"))?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            if !kind.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "workspace traversal escaped its capability".to_owned())?;
            let valid_path = relative.to_str().is_some();
            let relative = relative.to_string_lossy();
            if !visit(&relative, &path, valid_path) {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn wildcard_matches(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let mut previous = vec![false; text.len() + 1];
    previous[0] = true;
    for &token in pattern {
        let mut current = vec![false; text.len() + 1];
        if token == b'*' {
            current[0] = previous[0];
        }
        for index in 1..=text.len() {
            current[index] = match token {
                b'*' => previous[index] || current[index - 1],
                b'?' => previous[index - 1],
                byte => previous[index - 1] && byte == text[index - 1],
            };
        }
        previous = current;
    }
    previous[text.len()]
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedToolCall {
    pub call_id: String,
    pub name: String,
    pub arguments: Value,
    pub result: Option<String>,
    pub ok: Option<bool>,
}

/// One ordered piece of a turn's host-visible content: a run of assistant prose,
/// or a tool call (carrying its result once the matching `ToolResults` message
/// correlates one in).
///
/// [`LabeledTurnOutput::assistant_text`] and [`LabeledTurnOutput::tool_calls`]
/// are the *folded* view of a turn — the final reply, and the flat set of calls
/// that ran. That fold answers "what did the turn conclude", but it discards the
/// order the turn produced its content in, and every intermediate line of prose
/// the model spoke alongside a tool call. A product shell that replays a turn as
/// a conversation — narration interleaved with the calls it introduced — needs
/// that order back. `segments` is the same admitted content under the same
/// turn-join label, in the sequence the turn produced it, so the shell replays
/// what happened rather than reconstructing it from the operational stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnContentSegment {
    /// A contiguous run of assistant prose — one `Assistant` message's text.
    Prose(String),
    /// A tool call the turn made, in the position it was called; `result`/`ok`
    /// fill in when its `ToolResults` correlate.
    Tool(ProjectedToolCall),
}

/// WhippleScript's certified dependency set for one field of the host-visible
/// turn projection.
///
/// Agent turns are intentionally opaque IFC boxes: every resource admitted to
/// the turn may influence both the assistant text and the tool-call transcript.
/// Publishing that conservative per-field signature lets an embedding product
/// derive provenance from WhippleScript's admitted resource set instead of
/// independently guessing which inputs influenced an output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertifiedOutputFieldFlow {
    pub field: String,
    pub reads: Vec<ResourceRef>,
}

/// The content projection WhippleScript has admitted for its embedding host.
///
/// The projection is derived from WhippleScript's durable transcript, carries
/// the same IFC join label as the evidence stream, and is the only supported
/// way for a product shell to obtain assistant/tool content. Embedding hosts do
/// not inspect the runtime store or recreate transcript-folding semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabeledTurnOutput {
    pub output_handle: Option<String>,
    pub label_ref: String,
    pub assistant_text: String,
    pub tool_calls: Vec<ProjectedToolCall>,
    /// The turn's content in the order it was produced — assistant prose runs
    /// interleaved with the tool calls they introduced (see
    /// [`TurnContentSegment`]). This is the same admitted content as
    /// `assistant_text` + `tool_calls`, so it shares their certified
    /// `flow_signature` (the conservative turn read-set); it is not a separate
    /// output field, only an ordered re-view carrying no read the folded fields
    /// do not already carry.
    pub segments: Vec<TurnContentSegment>,
    pub flow_signature: Vec<CertifiedOutputFieldFlow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnExecution {
    pub events: Vec<LabeledRuntimeEvent>,
    /// Present only after the turn reaches a runtime terminal. A suspended turn
    /// has no terminal receipt by construction.
    pub receipt: Option<TurnReceipt>,
    pub output: Option<LabeledTurnOutput>,
    /// The same deliberately narrow token projection the Durable Object host
    /// publishes (`HostedUsageObservation`): typed counts an embedding product
    /// may meter on, plus the settled context-window reading. The opaque
    /// `usage_ref` on the receipt remains the authoritative evidence pointer.
    /// `None` when the turn recorded no usage metadata.
    pub usage: Option<TurnUsageObservation>,
}

/// The local host's projection of one turn's usage metadata. `input_tokens` and
/// `output_tokens` sum the turn's model calls (a meter); `last_input_tokens` is
/// the final main call's prompt size (a gauge — how full the context window
/// was), 0 when the turn settled without one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnUsageObservation {
    pub usage_ref: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub last_input_tokens: u64,
}

impl TurnExecution {
    /// Publish only stable references to WhippleScript-owned evidence. Payload,
    /// label, usage, and guarantee bodies remain in the runtime store.
    pub fn evidence_pointers(&self) -> Vec<RuntimeEvidencePointer> {
        let mut pointers = self
            .events
            .iter()
            .cloned()
            .map(RuntimeEvidencePointer::Event)
            .collect::<Vec<_>>();
        if let Some(receipt) = &self.receipt {
            pointers.push(RuntimeEvidencePointer::TurnReceipt(receipt.clone()));
        }
        pointers
    }
}

/// A store-recorded instance identity, as [`GovernedHostRuntime::newest_recorded_instance`]
/// reports it: enough to name an adoption source, never enough to execute one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordedInstance {
    pub instance_ref: String,
    pub package_version_ref: String,
    /// The policy epoch the instance was recorded under. A host adopting it
    /// into a newer epoch opens the source runtime under this one, so the
    /// runtime can read the source's own verified envelope (DR-0293).
    pub policy: PolicyEpochRef,
}

/// How [`GovernedHostRuntime::newest_recorded_instance`] orders adoption
/// candidates: one lexicographic key, most significant field first.
///
/// Field ORDER is the rule — `derive(Ord)` compares in declaration order — so
/// moving a field up or down here changes which instance a host adopts. The
/// reasoning for this order, and for what is deliberately absent from it,
/// is on `newest_recorded_instance`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AdoptionRank {
    /// When this instance's log was last extended. The question being asked.
    last_activity_at: String,
    /// How far the log has got, which settles a same-second tie in favour of
    /// the instance actually being worked in.
    reach: i64,
    /// Creation order, for candidates with identical activity and reach.
    created_at: String,
    /// The last resort, so the pick is total and never depends on the order
    /// `list_instances` happened to return.
    instance_id: String,
}

/// Out-of-band cooperative cancellation capability for one admitted host
/// command. It opens an independent store connection, so an embedding UI can
/// request cancellation while the runtime-owning thread is blocked in provider
/// I/O. The owned loop observes it between model rounds.
#[derive(Clone)]
pub struct HostCancellationHandle {
    store_path: PathBuf,
    instance_ref: String,
    command_id: String,
    protection: Option<PayloadProtection>,
}
impl fmt::Debug for HostCancellationHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostCancellationHandle")
            .field("store_path", &self.store_path)
            .field("instance_ref", &self.instance_ref)
            .field("command_id", &self.command_id)
            .field("protected", &self.protection.is_some())
            .finish()
    }
}

fn open_cancellation_store(
    path: &Path,
    protection: Option<&PayloadProtection>,
) -> Result<SqliteStore, StoreError> {
    match protection {
        Some(protection) => SqliteStore::open_initialized_protected(path, protection.clone()),
        None => SqliteStore::open(path),
    }
}

/// The mid-stream companion to [`HostCancellationHandle`]: polls the same
/// durable cancellation surface from inside the transport's read loop, so an
/// in-flight provider stream is released at a complete-event boundary instead
/// of running to its end (spec/agent-harness.md "Cancellation").
///
/// Opens its own store connection for the same reason the handle does — the
/// runtime-owning thread is inside provider I/O while the embedding host
/// writes the request. Reads are throttled so a fast stream is never gated on
/// SQLite, and the first observation latches: the transport's release decision
/// and the machine's released-round settlement must agree about one stream.
/// Plain compatibility failures read as "not cancelled". Protected storage
/// failures release the stream rather than conceal unavailable authority.
struct StreamCancelProbe {
    store_path: PathBuf,
    instance_ref: String,
    command_id: String,
    clock: ProbeClock,
    protection: Option<PayloadProtection>,
    last_read: std::cell::Cell<Option<Duration>>,
    latched: std::cell::Cell<bool>,
    store: std::cell::RefCell<Option<SqliteStore>>,
}

/// The probe's source of now, as a reading on one monotonic scale. A turn
/// reads the machine's clock; a test holds the reading itself and advances it
/// explicitly, so an assertion about the throttle window states what the
/// window does rather than how much real time a loaded machine happened to
/// spend between two streamed lines.
#[derive(Clone, Debug)]
enum ProbeClock {
    Machine(std::time::Instant),
    #[cfg(test)]
    Held(std::rc::Rc<std::cell::Cell<Duration>>),
}

impl ProbeClock {
    fn now(&self) -> Duration {
        match self {
            Self::Machine(origin) => origin.elapsed(),
            #[cfg(test)]
            Self::Held(reading) => reading.get(),
        }
    }
}

impl StreamCancelProbe {
    const READ_INTERVAL: Duration = Duration::from_millis(250);

    fn new(
        store_path: PathBuf,
        instance_ref: String,
        command_id: String,
        protection: Option<PayloadProtection>,
    ) -> Self {
        Self::on_clock(
            store_path,
            instance_ref,
            command_id,
            ProbeClock::Machine(std::time::Instant::now()),
            protection,
        )
    }

    fn on_clock(
        store_path: PathBuf,
        instance_ref: String,
        command_id: String,
        clock: ProbeClock,
        protection: Option<PayloadProtection>,
    ) -> Self {
        Self {
            store_path,
            instance_ref,
            command_id,
            clock,
            protection,
            last_read: std::cell::Cell::new(None),
            latched: std::cell::Cell::new(false),
            store: std::cell::RefCell::new(None),
        }
    }

    /// Consulted by the transport between streamed lines: `true` = release.
    fn observed(&self) -> bool {
        if self.latched.get() {
            return true;
        }
        let now = self.clock.now();
        if self
            .last_read
            .get()
            .is_some_and(|at| now.saturating_sub(at) < Self::READ_INTERVAL)
        {
            return false;
        }
        self.last_read.set(Some(now));
        let mut slot = self.store.borrow_mut();
        if slot.is_none() {
            *slot = open_cancellation_store(&self.store_path, self.protection.as_ref()).ok();
        }
        let Some(store) = slot.as_mut() else {
            let release = self.protection.is_some();
            self.latched.set(release);
            return release;
        };
        let check =
            || store.effect_has_open_cancellation_request(&self.instance_ref, &self.command_id);
        let open = match &self.protection {
            Some(protection) => protection.retain(check),
            None => check(),
        }
        .unwrap_or(self.protection.is_some());
        if open {
            self.latched.set(true);
        }
        open
    }

    /// Whether this probe released a stream — the machine-side fact that the
    /// parsed reply is a truncation, never a natural terminal.
    fn released(&self) -> bool {
        self.latched.get()
    }
}

impl HostCancellationHandle {
    pub fn request(&self) -> Result<(), HostRuntimeError> {
        let mut store = open_cancellation_store(&self.store_path, self.protection.as_ref())
            .map_err(HostRuntimeError::Store)?;
        let idempotency = idempotency_key(&[
            &self.instance_ref,
            &self.command_id,
            "host-cancellation-request",
        ]);
        store
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: &self.instance_ref,
                effect_id: &self.command_id,
                revision_id: None,
                reason: Some("embedding host requested cancellation"),
                requested_by: "embedding-host",
                causation_event_id: None,
                idempotency_key: Some(&idempotency),
            })
            .map(|_| ())
            .map_err(HostRuntimeError::Store)
    }
}

/// A persistent, policy-bound native WhippleScript runtime.
pub struct GovernedHostRuntime {
    kernel: RuntimeKernel<SqliteStore>,
    store_path: PathBuf,
    policy: PolicyEpochRef,
    envelope: VerifiedEnvelope,
    protection: Option<PayloadProtection>,
}

/// Read-only original-runtime observation. No execution or writable-runtime
/// conversion is exposed; every observation needs current embedding access.
pub struct RecordedHostRuntime {
    runtime: GovernedHostRuntime,
}

impl RecordedHostRuntime {
    pub fn open<R: ResourceResolver + ?Sized>(
        path: impl AsRef<Path>,
        epoch: u64,
        signed_envelope: &str,
        resources: &R,
    ) -> Result<Self, HostRuntimeError> {
        Self::open_using(path, epoch, resources, None, || {
            VerifiedEnvelope::verify_signed_text(signed_envelope)
        })
    }

    pub fn open_with_verifier<
        V: crate::gov::GovernanceAttestationVerifier + ?Sized,
        R: ResourceResolver + ?Sized,
    >(
        path: impl AsRef<Path>,
        epoch: u64,
        signed_envelope: &str,
        verifier: &V,
        resources: &R,
    ) -> Result<Self, HostRuntimeError> {
        Self::open_using(path, epoch, resources, None, || {
            VerifiedEnvelope::verify_signed_text_with(signed_envelope, verifier)
        })
    }

    /// Inspect an existing protected original runtime without migration or execution.
    /// Protection custody and the governance verifier grant no resource access.
    pub fn open_existing_protected_with_verifier<
        V: crate::gov::GovernanceAttestationVerifier + ?Sized,
        R: ResourceResolver + ?Sized,
    >(
        path: impl AsRef<Path>,
        epoch: u64,
        signed_envelope: &str,
        verifier: &V,
        resources: &R,
        protection: PayloadProtection,
    ) -> Result<Self, HostRuntimeError> {
        Self::open_using(path, epoch, resources, Some(protection), || {
            VerifiedEnvelope::verify_signed_text_with(signed_envelope, verifier)
        })
    }

    fn open_using<R: ResourceResolver + ?Sized>(
        path: impl AsRef<Path>,
        epoch: u64,
        resources: &R,
        protection: Option<PayloadProtection>,
        verify: impl FnOnce() -> Result<VerifiedEnvelope, String>,
    ) -> Result<Self, HostRuntimeError> {
        let access = LiveTurnAccess::new(resources);
        access.check()?;
        let observed = (|| {
            let envelope = verify().map_err(HostRuntimeError::PolicyRejected)?;
            let policy = PolicyEpochRef::from_verified(epoch, &envelope)?;
            let path = path.as_ref().to_path_buf();
            let store = match protection.clone() {
                Some(protection) => SqliteStore::open_read_only_protected(&path, protection),
                None => SqliteStore::open_read_only(&path),
            }
            .map_err(HostRuntimeError::Store)?;
            require_recorded_schema(&store)?;
            Ok(Self {
                runtime: GovernedHostRuntime {
                    kernel: RuntimeKernel::new(store),
                    store_path: path,
                    policy,
                    envelope,
                    protection,
                },
            })
        })();
        access.check()?;
        observed
    }

    fn observe<R: ResourceResolver + ?Sized, T>(
        &self,
        command: &StartTurnCommand,
        start: &PinnedPosition,
        resources: &R,
        read: impl FnOnce(&GovernedHostRuntime) -> Result<T, HostRuntimeError>,
    ) -> Result<T, HostRuntimeError> {
        let access = LiveTurnAccess::new(resources);
        access.check()?;
        let observed = (|| {
            require_recorded_schema(self.runtime.kernel.store())?;
            if command.policy != self.runtime.policy || start.instance_ref != command.instance_ref {
                return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "original runtime policy or starting instance changed",
                )));
            }
            let store = self.runtime.kernel.store();
            if store
                .get_instance(&start.instance_ref)
                .map_err(HostRuntimeError::Store)?
                .is_none()
            {
                return Err(HostRuntimeError::UnknownInstance(
                    start.instance_ref.clone(),
                ));
            }
            let sequence = i64::try_from(start.sequence).map_err(|_| {
                HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "original runtime starting sequence is unsupported",
                ))
            })?;
            let pin = whipplescript_store::event_chain::ChainHead {
                sequence: if sequence == 0 { None } else { Some(sequence) },
                digest: start.head_digest.clone(),
            };
            store
                .list_events_pinned(&start.instance_ref, &pin)
                .map_err(HostRuntimeError::Store)?;
            let value = read(&self.runtime)?;
            require_recorded_schema(store)?;
            Ok(value)
        })();
        access.check()?;
        observed
    }

    pub fn recorded_turn_execution<R: ResourceResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        start: &PinnedPosition,
        resources: &R,
    ) -> Result<Option<TurnExecution>, HostRuntimeError> {
        self.observe(command, start, resources, |runtime| {
            let execution = runtime.recorded_turn_execution(command, resources)?;
            if execution
                .as_ref()
                .and_then(|value| value.receipt.as_ref())
                .is_some_and(|receipt| start.sequence > receipt.terminal_position.sequence)
            {
                return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "original runtime start follows its terminal receipt",
                )));
            }
            Ok(execution)
        })
    }

    pub fn turn_workspace_witness<R: ResourceResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        start: &PinnedPosition,
        resources: &R,
    ) -> Result<Option<RecordedWorkspaceWitness>, HostRuntimeError> {
        self.observe(command, start, resources, |runtime| {
            if self
                .recorded_turn_execution(command, start, resources)?
                .is_none()
            {
                return Ok(None);
            }
            runtime.turn_workspace_witness(command, resources)
        })
    }

    pub fn turn_guarantee_report<R: ResourceResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        start: &PinnedPosition,
        resources: &R,
    ) -> Result<Option<Value>, HostRuntimeError> {
        self.observe(command, start, resources, |runtime| {
            if self
                .recorded_turn_execution(command, start, resources)?
                .is_none()
            {
                return Ok(None);
            }
            runtime.turn_guarantee_report(command)
        })
    }
}

fn require_recorded_schema(store: &SqliteStore) -> Result<(), HostRuntimeError> {
    let version = store.schema_version().map_err(HostRuntimeError::Store)?;
    if version != whipplescript_store::SUPPORTED_SCHEMA_VERSION {
        return Err(HostRuntimeError::Store(
            whipplescript_store::StoreError::UnsupportedVersion {
                subject: "recorded runtime schema".into(),
                found: version,
                supported: whipplescript_store::SUPPORTED_SCHEMA_VERSION,
            },
        ));
    }
    Ok(())
}

impl GovernedHostRuntime {
    /// Open or reopen a native runtime store and bind this facade to one signed,
    /// immutable policy epoch.
    pub fn open(
        store_path: impl AsRef<Path>,
        epoch: u64,
        signed_envelope: &str,
    ) -> Result<Self, HostRuntimeError> {
        let envelope = VerifiedEnvelope::verify_signed_text(signed_envelope)
            .map_err(HostRuntimeError::PolicyRejected)?;
        Self::open_verified(store_path, epoch, envelope)
    }

    /// Open an embedding runtime under an externally signed governance
    /// envelope. The verifier is an explicit capability held by the governance
    /// authority; no process-global admin flag participates.
    pub fn open_with_verifier<V: crate::gov::GovernanceAttestationVerifier + ?Sized>(
        store_path: impl AsRef<Path>,
        epoch: u64,
        signed_envelope: &str,
        verifier: &V,
    ) -> Result<Self, HostRuntimeError> {
        let envelope = VerifiedEnvelope::verify_signed_text_with(signed_envelope, verifier)
            .map_err(HostRuntimeError::PolicyRejected)?;
        Self::open_verified(store_path, epoch, envelope)
    }

    /// Create a new protected native runtime; existing paths are never adopted.
    /// Policy verification occurs before the native store can create any file.
    pub fn create_protected_with_verifier<V: crate::gov::GovernanceAttestationVerifier + ?Sized>(
        store_path: impl AsRef<Path>,
        epoch: u64,
        signed_envelope: &str,
        verifier: &V,
        protection: PayloadProtection,
    ) -> Result<Self, HostRuntimeError> {
        let envelope = VerifiedEnvelope::verify_signed_text_with(signed_envelope, verifier)
            .map_err(HostRuntimeError::PolicyRejected)?;
        Self::open_verified_using(
            store_path,
            epoch,
            envelope,
            Some(protection.clone()),
            |path| SqliteStore::create_protected(path, protection),
        )
    }

    /// Reopen exact existing protected storage without conversion or initialization.
    pub fn open_existing_protected_with_verifier<
        V: crate::gov::GovernanceAttestationVerifier + ?Sized,
    >(
        store_path: impl AsRef<Path>,
        epoch: u64,
        signed_envelope: &str,
        verifier: &V,
        protection: PayloadProtection,
    ) -> Result<Self, HostRuntimeError> {
        let envelope = VerifiedEnvelope::verify_signed_text_with(signed_envelope, verifier)
            .map_err(HostRuntimeError::PolicyRejected)?;
        Self::open_verified_using(
            store_path,
            epoch,
            envelope,
            Some(protection.clone()),
            |path| SqliteStore::open_existing_protected(path, protection),
        )
    }

    fn open_verified(
        store_path: impl AsRef<Path>,
        epoch: u64,
        envelope: VerifiedEnvelope,
    ) -> Result<Self, HostRuntimeError> {
        Self::open_verified_using(store_path, epoch, envelope, None, |path| {
            SqliteStore::open(path)
        })
    }

    fn open_verified_using(
        store_path: impl AsRef<Path>,
        epoch: u64,
        envelope: VerifiedEnvelope,
        protection: Option<PayloadProtection>,
        open: impl FnOnce(&Path) -> whipplescript_store::StoreResult<SqliteStore>,
    ) -> Result<Self, HostRuntimeError> {
        let policy = PolicyEpochRef::from_verified(epoch, &envelope)?;
        let store_path = store_path.as_ref().to_path_buf();
        let store = open(&store_path).map_err(HostRuntimeError::Store)?;
        // DR-0062 §4: a delegation edge granting a model endpoint read-authority
        // for a role is admissible only if the endpoint's derived custody class
        // clears what the signed envelope demands of that role. This is the one
        // place both halves are in hand -- the envelope carries the demand, the
        // store carries the evidence -- so the refusal lands at policy-load
        // time rather than at the first turn that would have leaked.
        refuse_inadmissible_provider_delegations(&store, &envelope)?;
        Ok(Self {
            kernel: RuntimeKernel::new(store),
            store_path,
            policy,
            envelope,
            protection,
        })
    }

    pub fn policy_ref(&self) -> &PolicyEpochRef {
        &self.policy
    }

    /// The chat instance this store records that the host means to keep, with
    /// its recorded package reference — the adoption seam's source lookup for an
    /// embedding host whose authored package identity has drifted past what a
    /// replayed open can reproduce (see [`Self::adopt_instance_from`]). `None`
    /// for a store that has never opened a chat. Ordinary host actions have
    /// their own admitted command and are not candidates for chat adoption
    /// (DR-0099).
    ///
    /// The pick is the most recently ACTIVE instance, not the most recently
    /// created. `list_instances` orders by `(created_at, instance_id)`, so
    /// taking the last element picked the newest-created and, on a `created_at`
    /// tie, whichever id happened to sort highest — a migration shim opened in
    /// the same second as the real thread's instance could win, and an adoption
    /// seeded from it carries nothing.
    ///
    /// "Last active" is read off the LOG, not off `instances.updated_at`.
    /// Ranking on that column looked like the answer and was not: the
    /// projection stamps it on a status transition, a revision activation and a
    /// terminal event, and on nothing else, so a chat that has run twenty turns
    /// without changing status still carries the timestamp it was created with.
    /// Under that key a shim opened one second after the carrier outranked the
    /// carrier no matter how much work the carrier had since done, and kept
    /// outranking it forever — the exact failure DR-0099's pick exists to
    /// prevent, moved one second along. It read as a flaky test rather than as
    /// a defect because everything in an idle test lands in one second, where
    /// the column ties and the reach tiebreak below covers for it; a loaded
    /// machine straddles the second and the shim wins.
    ///
    /// The order is `(last activity, reach, created_at, instance_id)`, applied
    /// as one lexicographic key by [`AdoptionRank`]. Timestamps are
    /// `CURRENT_TIMESTAMP`, which has one-second resolution, so the later keys
    /// are load-bearing rather than decorative: within one second the instance
    /// whose log has got further is the one being worked in — a just-opened
    /// shim carries almost nothing, and a chat that has run a turn carries the
    /// turn — and `created_at` then `instance_id` make the pick total, so two
    /// candidates that are genuinely indistinguishable still resolve the same
    /// way on every run. Both the timestamp and the reach come off the chain
    /// head in one query, the way [`Self::current_position`] already reads a
    /// position, rather than by listing a whole log to look at its last row.
    pub fn newest_recorded_instance(&self) -> Result<Option<RecordedInstance>, HostRuntimeError> {
        let instances = self
            .kernel
            .store()
            .list_instances()
            .map_err(HostRuntimeError::Store)?;
        let mut newest: Option<(whipplescript_store::InstanceView, AdoptionRank)> = None;
        for instance in instances {
            if self
                .kernel
                .store()
                .event_by_idempotency_key(&instance.instance_id, "host-action-admission")
                .map_err(HostRuntimeError::Store)?
                .is_some()
            {
                continue;
            }
            let activity = self
                .kernel
                .store()
                .last_activity(&instance.instance_id)
                .map_err(HostRuntimeError::Store)?;
            let rank = AdoptionRank {
                // An instance with no log at all has never been active. The
                // empty string sorts below every recorded timestamp, which is
                // where "never" belongs.
                last_activity_at: activity
                    .as_ref()
                    .map(|activity| activity.occurred_at.clone())
                    .unwrap_or_default(),
                reach: activity.as_ref().map_or(0, |activity| activity.sequence),
                created_at: instance.created_at.clone(),
                instance_id: instance.instance_id.clone(),
            };
            if newest
                .as_ref()
                .is_none_or(|(_, incumbent)| rank > *incumbent)
            {
                newest = Some((instance, rank));
            }
        }
        let Some((instance, _)) = newest else {
            return Ok(None);
        };
        // Preserve the refusal for malformed legacy chat metadata. Only a
        // durably identified action is excluded from the chat lookup.
        let metadata: InstanceMetadata =
            serde_json::from_str(&instance.input_json).map_err(HostRuntimeError::Json)?;
        Ok(Some(RecordedInstance {
            instance_ref: instance.instance_id,
            package_version_ref: metadata.package_version_ref,
            policy: metadata.policy,
        }))
    }

    /// Where this instance's log currently is.
    ///
    /// Read off the chain head rather than by listing. This folded the WHOLE
    /// log — every row, payload included — to take one integer off its last
    /// element, which the durable-object host stopped doing and this did not.
    pub fn current_position(&self, instance_ref: &str) -> Result<EventPosition, HostRuntimeError> {
        let head = self
            .kernel
            .store()
            .chain_head(instance_ref)
            .map_err(HostRuntimeError::Store)?;
        // An instance with no events is not a position: the callers here are
        // quiescence checks before a fork, and "nowhere yet" is not somewhere
        // to fork from. Preserved from the listing form deliberately.
        let sequence = head
            .sequence
            .ok_or_else(|| HostRuntimeError::UnknownInstance(instance_ref.to_owned()))?;
        Ok(EventPosition {
            instance_ref: instance_ref.to_owned(),
            sequence: positive_sequence(sequence)?,
        })
    }

    /// The same coordinate **with the digest that makes it verifiable**
    /// (DR-0068 §3), for a reader that will hold it across a boundary.
    ///
    /// Native parity for `host_projection::pinned_position`. Unlike
    /// [`Self::current_position`] an empty log is a position here — sequence 0
    /// at the genesis digest — because a reader pinning before anything has
    /// happened is holding a real claim about the log, not an absence.
    ///
    /// # Errors
    /// Propagates store failures.
    pub fn pinned_position(&self, instance_ref: &str) -> Result<PinnedPosition, HostRuntimeError> {
        let head = self
            .kernel
            .store()
            .chain_head(instance_ref)
            .map_err(HostRuntimeError::Store)?;
        Ok(PinnedPosition {
            instance_ref: instance_ref.to_owned(),
            sequence: match head.sequence {
                Some(sequence) => positive_sequence(sequence)?,
                None => 0,
            },
            head_digest: head.digest,
        })
    }

    /// Observe an exact original terminal execution without admitting or
    /// resuming work, resolving a provider or refreshing runtime evidence.
    /// Absence supplies no execution grant. The embedding retains its original
    /// command, bindings and starting coordinate; this projection replaces none.
    pub fn recorded_turn_execution<R: ResourceResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        resources: &R,
    ) -> Result<Option<TurnExecution>, HostRuntimeError> {
        let access = LiveTurnAccess::new(resources);
        access.check()?;
        let observed = (|| {
            let saved = self.stored_execution(command)?;
            if let Some(receipt) = saved
                .as_ref()
                .and_then(|execution| execution.receipt.as_ref())
            {
                self.kernel
                    .store()
                    .chain_head_at(
                        &command.instance_ref,
                        receipt.terminal_position.sequence as i64,
                    )
                    .map_err(HostRuntimeError::Store)?;
            }
            Ok(saved)
        })();
        access.check()?;
        observed
    }

    /// The turn's guarantee report (DR-0036): the `host.turn.guarantee`
    /// evidence body for `command`'s run — the static admission set plus the
    /// dynamic per-turn section a host consumer matches **by name** (GaugeWright
    /// ADR 0082 §5; consumers never re-evaluate semantics). `Ok(None)` when the
    /// run has not produced a report (the turn has not finished here).
    pub fn turn_guarantee_report(
        &self,
        command: &StartTurnCommand,
    ) -> Result<Option<Value>, HostRuntimeError> {
        let run_id = idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
        let item = self
            .kernel
            .store()
            .list_evidence_for_subject("run", &run_id)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .find(|item| item.kind == "host.turn.guarantee");
        match item {
            Some(item) => Ok(Some(
                serde_json::from_str(&item.metadata_json).map_err(HostRuntimeError::Json)?,
            )),
            None => Ok(None),
        }
    }

    /// Read the original certified workspace witness without running a turn,
    /// resolving a provider, scanning a workspace or refreshing any evidence.
    /// Missing certified evidence supplies no witness; broken references refuse.
    pub fn turn_workspace_witness<R: ResourceResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        resources: &R,
    ) -> Result<Option<RecordedWorkspaceWitness>, HostRuntimeError> {
        let access = LiveTurnAccess::new(resources);
        access.check()?;
        let observed = (|| {
            let Some(receipt) = self.stored_turn_receipt(command)? else {
                return Ok(None);
            };
            let Some(reference) = &receipt.workspace_cut_ref else {
                return Ok(None);
            };
            let run_id =
                idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
            let Some(evidence) = self
                .kernel
                .store()
                .list_evidence_for_subject("run", &run_id)
                .map_err(HostRuntimeError::Store)?
                .into_iter()
                .find(|evidence| &evidence.evidence_id == reference)
            else {
                let reason = "recorded workspace witness is missing";
                // MUTATION-SUCCESS-EXPR: Ok(None)
                return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(reason)));
            };
            if evidence.instance_id != command.instance_ref
                || evidence.kind != "host.turn.workspace_cut"
                || evidence.subject_type != "run"
                || evidence.subject_id != run_id
                || evidence.correlation_id.as_deref() != Some(command.command_id.as_str())
                || evidence.causation_id.as_deref() != Some(command.command_id.as_str())
            {
                return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "recorded workspace witness identity differs",
                )));
            }
            #[derive(serde::Deserialize)]
            struct Body {
                complete: bool,
                writes: Vec<WitnessedWrite>,
                reads: Vec<String>,
            }
            let body: Body =
                serde_json::from_str(&evidence.metadata_json).map_err(HostRuntimeError::Json)?;
            if !body.complete {
                return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "recorded workspace witness is incomplete",
                )));
            }
            Ok(Some(RecordedWorkspaceWitness {
                receipt,
                writes: body.writes,
                reads: body.reads,
            }))
        })();
        access.check()?;
        observed
    }

    /// The recorded failure reason for this exact admitted turn. No provider
    /// request, credential or raw response body crosses this projection.
    pub fn turn_failure_summary(
        &self,
        command: &StartTurnCommand,
    ) -> Result<Option<String>, HostRuntimeError> {
        command.validate()?;
        let run_id = idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
        Ok(self
            .kernel
            .store()
            .list_runs(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .find(|run| run.run_id == run_id && run.status == "failed")
            .and_then(|run| run.summary))
    }

    /// Mint the out-of-band cancel capability for a command before driving it.
    /// The handle contains no provider secret or resource body.
    pub fn cancellation_handle(
        &self,
        instance_ref: impl Into<String>,
        command_id: impl Into<String>,
    ) -> HostCancellationHandle {
        HostCancellationHandle {
            store_path: self.store_path.clone(),
            instance_ref: instance_ref.into(),
            command_id: command_id.into(),
            protection: self.protection.clone(),
        }
    }

    /// Recheck one sealed selection against packages resolved now. The caller
    /// supplies each version's package reference from the authenticated Home
    /// journal, not from the stored import witness. The returned selection is
    /// still only one target-store read: the Home must bind its seal, account
    /// for outside operations, and recapture affected bases through ref CAS.
    pub fn revalidate_selected_imports<P, F>(
        &self,
        selected_ids: &[String],
        packages: &P,
        mut package_ref_for_version: F,
    ) -> Result<SelectedImportCoverage, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        F: FnMut(&ProgramVersionView) -> Option<String>,
    {
        import_coverage::revalidate_selected(self.kernel.store(), selected_ids, |view| {
            let package_ref = package_ref_for_version(view)?;
            let package = packages.resolve_package(&package_ref).ok()?;
            let compiler_artifact_digest = native_compiler_artifact_digest().ok()?;
            package
                .current_import_basis(
                    &package_ref,
                    view,
                    &compiler_artifact_digest,
                    crate::std_manifests::EMBEDDED_STD_MANIFESTS,
                )
                .ok()
        })
        .map_err(HostRuntimeError::Store)
    }

    /// Create the durable WhippleScript instance for a chat. The returned opaque
    /// instance reference is the value the host persists and uses on every turn.
    pub fn open_instance<P: PackageResolver + ?Sized>(
        &mut self,
        command: &OpenInstanceCommand,
        packages: &P,
    ) -> Result<OpenedInstance, HostRuntimeError> {
        self.open_instance_inner(command, packages, None)
    }

    /// Open through the authenticated Home's durable operation journal. The
    /// Home registers before a target write and completes the exact import
    /// operation before an instance can be returned or used on replay.
    pub fn open_instance_with_home_journal<P: PackageResolver + ?Sized>(
        &mut self,
        command: &OpenInstanceCommand,
        packages: &P,
        journal: &mut dyn OpenInstanceHomeJournal,
    ) -> Result<OpenedInstance, HostRuntimeError> {
        self.open_instance_inner(command, packages, Some(journal))
    }

    fn open_instance_inner<P: PackageResolver + ?Sized>(
        &mut self,
        command: &OpenInstanceCommand,
        packages: &P,
        mut journal: Option<&mut dyn OpenInstanceHomeJournal>,
    ) -> Result<OpenedInstance, HostRuntimeError> {
        let target_store_incarnation = journal
            .as_ref()
            .map(|_| require_home_store_incarnation(self.kernel.store()))
            .transpose()?;
        command.validate()?;
        self.require_policy(&command.policy)?;
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&package, &command.package_version_ref)?;
        let source_digest = package
            .checked_import_source_digest()
            .map_err(HostRuntimeError::Resolver)?;
        self.check_package_ifc(&package)?;
        if let Some((opened, version_id)) = self.replayed_open_instance(
            command,
            &package,
            &source_digest,
            target_store_incarnation.as_deref(),
            &mut journal,
        )? {
            if let Some(journal) = journal.as_mut() {
                journal
                    .allow_retained_use(
                        target_store_incarnation
                            .as_deref()
                            .expect("Home identity checked"),
                        &command.request_id,
                        &opened.instance_ref,
                        &version_id,
                    )
                    .map_err(home_journal_error)?;
            }
            return Ok(opened);
        }

        let compiler_artifact_digest =
            native_compiler_artifact_digest().map_err(HostRuntimeError::Resolver)?;
        let construct_registry = embedded_std_registry_for_program(
            &package.program,
            crate::std_manifests::EMBEDDED_STD_MANIFESTS,
        )
        .map_err(HostRuntimeError::Resolver)?;
        let construct_basis = CheckedConstructBasis {
            registry: &construct_registry,
            sources: &[],
        };
        let operation_id = journal
            .as_mut()
            .map(|journal| {
                journal.register(&OpenInstanceOperationBasis {
                    target_store_incarnation: target_store_incarnation
                        .as_deref()
                        .expect("Home identity checked"),
                    kind: "open",
                    instance_ref: None,
                    from_version_id: None,
                    request_id: &command.request_id,
                    package_version_ref: &command.package_version_ref,
                    program_name: &package.agent,
                    source_digest: &source_digest,
                    version_source_digest: &package.source_hash,
                    lock_digest: NO_LOCK_DIGEST,
                    ir_hash: &package.ir_hash,
                    compiler_artifact_digest: &compiler_artifact_digest,
                    policy: &command.policy,
                    construct_basis: Some(&construct_basis),
                })
            })
            .transpose()
            .map_err(home_journal_error)?;
        let input = ProgramVersionInput {
            program_name: &package.agent,
            source_hash: &package.source_hash,
            ir_hash: &package.ir_hash,
            compiler_version: HOST_PROTOCOL,
            ir_snapshot: None,
        };
        let import_basis = CheckedImportBasis {
            program_source_digest: &source_digest,
            version_source_digest: Some(&package.source_hash),
            lock_digest: NO_LOCK_DIGEST,
            compiler_artifact_digest: &compiler_artifact_digest,
            packages: &[],
        };
        let admission = if let Some(operation_id) = operation_id.as_deref() {
            self.kernel
                .create_program_version_with_imports_and_constructs_at_id(
                    input,
                    &package.program,
                    &import_basis,
                    &construct_basis,
                    operation_id,
                )
        } else {
            self.kernel
                .create_program_version_with_imports_and_constructs(
                    input,
                    &package.program,
                    &import_basis,
                    &construct_basis,
                )
        }
        .map_err(HostRuntimeError::Store)?;
        if let Some(journal) = journal.as_mut() {
            require_same_home_store_incarnation(
                self.kernel.store(),
                target_store_incarnation
                    .as_deref()
                    .expect("Home identity checked"),
            )?;
            journal
                .complete_for_use(&OpenInstanceOperationEvidence {
                    target_store_incarnation: target_store_incarnation
                        .as_deref()
                        .expect("Home identity checked"),
                    request_id: &command.request_id,
                    operation_id: &admission.operation_id,
                    instance_ref: None,
                    version_id: &admission.version_id,
                    witness_digest: &admission.witness_digest,
                })
                .map_err(home_journal_error)?;
        }
        let version = whipplescript_store::ProgramVersionRecord {
            program_id: admission.program_id,
            version_id: admission.version_id,
        };
        let metadata = InstanceMetadata {
            protocol: HOST_PROTOCOL.to_owned(),
            package_version_ref: command.package_version_ref.clone(),
            policy: command.policy.clone(),
        };
        let input_json = serde_json::to_string(&metadata).map_err(HostRuntimeError::Json)?;
        let instance_ref = self
            .kernel
            .create_instance(&version, &input_json)
            .map_err(HostRuntimeError::Store)?;
        let payload = json!({
            "request_id": command.request_id,
            "package_version_ref": command.package_version_ref,
            "policy": command.policy,
        })
        .to_string();
        let opened = self
            .kernel
            .store()
            .append_event(NewEvent {
                instance_id: &instance_ref,
                event_type: "host.instance.opened",
                payload_json: &payload,
                source: "host-runtime",
                causation_id: None,
                correlation_id: Some(&command.request_id),
                idempotency_key: Some(&idempotency_key(&[
                    &instance_ref,
                    &command.request_id,
                    "host-instance-opened",
                ])),
            })
            .map_err(HostRuntimeError::Store)?;
        let result = OpenedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            instance_ref: instance_ref.clone(),
            package_version_ref: command.package_version_ref.clone(),
            policy: command.policy.clone(),
            opened_at: EventPosition {
                instance_ref,
                sequence: positive_sequence(opened.sequence)?,
            },
        };
        result.validate_for(command)?;
        if let Some(journal) = journal.as_mut() {
            journal
                .allow_retained_use(
                    target_store_incarnation
                        .as_deref()
                        .expect("Home identity checked"),
                    &command.request_id,
                    &result.instance_ref,
                    &version.version_id,
                )
                .map_err(home_journal_error)?;
        }
        Ok(result)
    }

    /// Fork the source runtime's live agent thread into a distinct target
    /// instance. The source coordinate, each side's immutable package, and the
    /// shared policy are all validated. Source and target package versions may
    /// differ, making this the explicit thread-preserving package-upgrade seam;
    /// the target records an idempotent seed event rather than copying a store
    /// file or pretending to have executed the source effects.
    pub fn fork_instance_from<P: PackageResolver + ?Sized>(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
    ) -> Result<ForkedInstance, HostRuntimeError> {
        command.validate()?;
        self.require_policy(&command.policy)?;
        source_runtime.require_policy(&command.policy)?;

        let target_package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&target_package, &command.package_version_ref)?;
        self.check_package_ifc(&target_package)?;

        let seed = Self::fork_source(source_runtime, command)?;
        let source_package = packages
            .resolve_package(&seed.metadata.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&source_package, &seed.metadata.package_version_ref)?;
        source_runtime.check_package_ifc(&source_package)?;
        source_runtime.validate_instance_binding(
            &command.source.instance_ref,
            &seed.metadata.package_version_ref,
            &command.policy,
            packages,
        )?;

        self.fork_to_target(
            source_runtime,
            command,
            packages,
            &target_package,
            &source_package.agent,
            &seed,
        )
    }

    /// Fork a recorded instance to the current package **without requiring the
    /// source's authored package to be reproducible** — the adoption seam for
    /// an embedding host whose package authoring has evolved past what a
    /// replayed open can reproduce (spec/agent-harness.md "Program identity
    /// across toolchains"). The source is identified and its position checked
    /// exactly as an ordinary fork; source-content reproduction is waived.
    /// That is sound because an adopted source is never executed again: its
    /// thread is seeded into the target, and the target's package resolves and
    /// validates in full under the current authoring.
    ///
    /// Policy and quiescence differ from a fork's in two bounded ways
    /// (DR-0293). The source may have been recorded under an earlier epoch of
    /// this runtime's authority: `source_runtime` is then opened under the
    /// source's own recorded epoch, so its envelope is verified, and every
    /// resource the carried thread read must still be governed here and
    /// resolve to the same identity, or the adoption refuses rather than
    /// relabel it. And a source with an effect still running is cut at the
    /// newest position before that effect began; the effect is never settled,
    /// and [`ForkedInstance::cut`] says the turn after the cut is unresolved.
    pub fn adopt_instance_from<P: PackageResolver + ?Sized>(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
    ) -> Result<ForkedInstance, HostRuntimeError> {
        command.validate()?;
        self.require_policy(&command.policy)?;

        let target_package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&target_package, &command.package_version_ref)?;
        self.check_package_ifc(&target_package)?;

        // The recorded program name stands in for the unresolvable source
        // package's agent: it names whose thread is being carried.
        let (seed, source_agent) = self.adoption_source(source_runtime, command, || {
            HostRuntimeError::UnknownInstance(command.source.instance_ref.clone())
        })?;

        self.fork_to_target(
            source_runtime,
            command,
            packages,
            &target_package,
            &source_agent,
            &seed,
        )
    }

    /// Fork only through the authenticated Home's source pin, pending handoff,
    /// target import, exact seed, and completed handoff use door. A crash after
    /// any target step retries the same identities; an incomplete handoff is
    /// never returned as an admitted target.
    pub fn fork_instance_from_with_home_journal<
        P: PackageResolver + ?Sized,
        J: ForkInstanceHomeJournal,
    >(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
        journal: &mut J,
    ) -> Result<ForkedInstance, HostRuntimeError> {
        self.home_fork_or_adopt(source_runtime, command, packages, journal, false)
    }

    /// Adopt an unreproducible authored source through the same Home handoff.
    /// Only reproduction of the old source package is waived; its exact Home
    /// pin, event cut, policy, snapshot and target admission remain required.
    pub fn adopt_instance_from_with_home_journal<
        P: PackageResolver + ?Sized,
        J: ForkInstanceHomeJournal,
    >(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
        journal: &mut J,
    ) -> Result<ForkedInstance, HostRuntimeError> {
        self.home_fork_or_adopt(source_runtime, command, packages, journal, true)
    }

    fn home_fork_or_adopt<P: PackageResolver + ?Sized, J: ForkInstanceHomeJournal>(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
        journal: &mut J,
        adopt: bool,
    ) -> Result<ForkedInstance, HostRuntimeError> {
        command.validate()?;
        self.require_policy(&command.policy)?;
        if !adopt {
            source_runtime.require_policy(&command.policy)?;
        }
        let target_package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&target_package, &command.package_version_ref)?;
        self.check_package_ifc(&target_package)?;
        let (seed, source_agent) = if adopt {
            self.adoption_source(source_runtime, command, || {
                HostRuntimeError::Incomplete("Home adoption source version is missing".into())
            })?
        } else {
            let seed = Self::fork_source(source_runtime, command)?;
            let source_package = packages
                .resolve_package(&seed.metadata.package_version_ref)
                .map_err(HostRuntimeError::Resolver)?;
            validate_package(&source_package, &seed.metadata.package_version_ref)?;
            source_runtime.check_package_ifc(&source_package)?;
            source_runtime.validate_instance_binding(
                &command.source.instance_ref,
                &seed.metadata.package_version_ref,
                &command.policy,
                packages,
            )?;
            (seed, source_package.agent)
        };
        self.home_fork_to_target(
            source_runtime,
            command,
            packages,
            &target_package,
            &source_agent,
            &seed,
            journal,
            if adopt { "adopt" } else { "fork" },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn home_fork_to_target<P: PackageResolver + ?Sized, J: ForkInstanceHomeJournal>(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
        target_package: &ResolvedPackage,
        source_agent: &str,
        seed_source: &SeedSource,
        journal: &mut J,
        kind: &str,
    ) -> Result<ForkedInstance, HostRuntimeError> {
        let source_observed_version_id = seed_source.instance.version_id.as_str();
        let source_sequence = seed_source.position.sequence;
        let source_store_incarnation =
            require_home_store_incarnation(source_runtime.kernel.store())?;
        let target_store_incarnation = require_home_store_incarnation(self.kernel.store())?;
        let source_chain = source_runtime
            .kernel
            .store()
            .chain_head_at(&command.source.instance_ref, source_sequence as i64)
            .map_err(HostRuntimeError::Store)?;
        let messages = source_runtime
            .kernel
            .snapshot_agent_thread(
                &command.source.instance_ref,
                source_agent,
                Some(source_sequence as i64),
            )
            .map_err(HostRuntimeError::Store)?;
        let mut snapshot_bytes = b"whipplescript.home-fork-thread.v1\0".to_vec();
        snapshot_bytes.extend(
            serde_json::to_vec(&whipplescript_kernel::harness_loop::chat_messages_to_json(
                &messages,
            ))
            .map_err(HostRuntimeError::Json)?,
        );
        let source_thread_digest = sha256_hex(&snapshot_bytes);
        let source = ForkSourceHomeBasis {
            source_store_incarnation: &source_store_incarnation,
            source_instance_ref: &command.source.instance_ref,
            source_observed_version_id,
            source_sequence,
            source_chain_digest: &source_chain.digest,
            source_thread_digest: &source_thread_digest,
            policy: &seed_source.metadata.policy,
        };
        let source_home_operation_id = journal
            .pin_source_for_fork(&source)
            .map_err(home_journal_error)?;
        if source_home_operation_id.is_empty() {
            return Err(HostRuntimeError::HomeJournal(
                "Home fork source pin has no operation identity".into(),
            ));
        }
        let operation_id = journal
            .register_fork(&ForkInstanceOperationBasis {
                kind,
                request_id: &command.request_id,
                source: &source,
                source_home_operation_id: &source_home_operation_id,
                target_store_incarnation: &target_store_incarnation,
                target_request_id: &command.target_request_id,
                target_package_version_ref: &command.package_version_ref,
            })
            .map_err(home_journal_error)?;
        if operation_id.is_empty() {
            return Err(HostRuntimeError::HomeJournal(
                "Home fork registration has no operation identity".into(),
            ));
        }

        let target = self.open_instance_with_home_journal(
            &command.target_open_command(),
            packages,
            journal,
        )?;
        if target.instance_ref == command.source.instance_ref {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork target identity",
            )));
        }
        let target_instance = self
            .kernel
            .store()
            .get_instance(&target.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let Some(target_instance) = target_instance else {
            return Err(HostRuntimeError::Incomplete(
                "Home fork target disappeared after open".into(),
            ));
        };
        require_same_home_store_incarnation(
            source_runtime.kernel.store(),
            &source_store_incarnation,
        )?;
        require_same_home_store_incarnation(self.kernel.store(), &target_store_incarnation)?;
        let source_now = source_runtime
            .kernel
            .store()
            .get_instance(&command.source.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let Some(source_now) = source_now else {
            return Err(HostRuntimeError::Incomplete(
                "Home fork source disappeared after target open".into(),
            ));
        };
        if source_now.version_id != source_observed_version_id
            || source_runtime
                .kernel
                .store()
                .chain_head_at(&command.source.instance_ref, source_sequence as i64)
                .map_err(HostRuntimeError::Store)?
                != source_chain
        {
            return Err(HostRuntimeError::Incomplete(
                "Home fork source changed before target seed".into(),
            ));
        }
        let seed_key = idempotency_key(&[
            &target.instance_ref,
            &command.request_id,
            "host-instance-thread-seed",
        ]);
        let seed_payload = json!({
            "agent": target_package.agent,
            "messages": whipplescript_kernel::harness_loop::chat_messages_to_json(&messages),
            "source_instance_id": command.source.instance_ref,
            "source_sequence": source_sequence as i64,
        });
        let fork_key = idempotency_key(&[
            &target.instance_ref,
            &command.request_id,
            "host-instance-forked",
        ]);
        let mut fork_payload = json!({
            "request_id": command.request_id,
            "source": command.source,
            "target_request_id": command.target_request_id,
            "package_version_ref": command.package_version_ref,
            "policy": command.policy,
            "home_operation_id": operation_id,
            "source_home_operation_id": source_home_operation_id,
            "source_store_incarnation": source_store_incarnation,
            "source_observed_version_id": source_observed_version_id,
            "source_chain_digest": source_chain.digest,
            "source_thread_digest": source_thread_digest,
            "target_store_incarnation": target_store_incarnation,
            "target_version_id": target_instance.version_id,
            "kind": kind,
        });
        seed_source.record_on(&mut fork_payload, command);
        let existing_seed = self.exact_fork_event(
            &target.instance_ref,
            &seed_key,
            "agent.thread.seeded",
            &seed_payload,
            "kernel",
        )?;
        let existing_fork = self.exact_fork_event(
            &target.instance_ref,
            &fork_key,
            "host.instance.forked",
            &fork_payload,
            "host-runtime",
        )?;
        if existing_fork.is_some() && existing_seed.is_none() {
            return Err(HostRuntimeError::Incomplete(
                "recorded Home fork has no exact thread seed".into(),
            ));
        }
        let seed = if let Some(seed) = existing_seed {
            seed
        } else {
            self.kernel
                .seed_agent_thread(AgentThreadSeed {
                    instance_id: &target.instance_ref,
                    agent: &target_package.agent,
                    messages: &messages,
                    source_instance_id: &command.source.instance_ref,
                    source_sequence: source_sequence as i64,
                    idempotency_key: &seed_key,
                })
                .map_err(HostRuntimeError::Store)?
        };
        let fork = if let Some(fork) = existing_fork {
            fork
        } else {
            self.kernel
                .store()
                .append_event(NewEvent {
                    instance_id: &target.instance_ref,
                    event_type: "host.instance.forked",
                    payload_json: &fork_payload.to_string(),
                    source: "host-runtime",
                    causation_id: None,
                    correlation_id: Some(&command.request_id),
                    idempotency_key: Some(&fork_key),
                })
                .map_err(HostRuntimeError::Store)?
        };
        require_same_home_store_incarnation(
            source_runtime.kernel.store(),
            &source_store_incarnation,
        )?;
        require_same_home_store_incarnation(self.kernel.store(), &target_store_incarnation)?;
        let evidence = ForkInstanceOperationEvidence {
            request_id: &command.request_id,
            operation_id: &operation_id,
            source: &source,
            source_home_operation_id: &source_home_operation_id,
            target_store_incarnation: &target_store_incarnation,
            target_request_id: &command.target_request_id,
            target_instance_ref: &target.instance_ref,
            target_version_id: &target_instance.version_id,
            seed_event_id: &seed.event_id,
            seed_sequence: positive_sequence(seed.sequence)?,
            fork_event_id: &fork.event_id,
            fork_sequence: positive_sequence(fork.sequence)?,
        };
        journal
            .complete_fork_for_use(&evidence)
            .map_err(home_journal_error)?;
        journal
            .allow_retained_fork_use(&evidence)
            .map_err(home_journal_error)?;
        let target_instance_ref = target.instance_ref.clone();
        let fork_sequence = evidence.fork_sequence;
        let result = ForkedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            source: command.source.clone(),
            target,
            forked_at: EventPosition {
                instance_ref: target_instance_ref,
                sequence: fork_sequence,
            },
            cut: seed_source.cut.clone(),
        };
        result.validate_for(command)?;
        Ok(result)
    }

    /// The recorded instance a fork or adoption names, with the host metadata
    /// it was opened under.
    fn source_instance_metadata(
        source_runtime: &GovernedHostRuntime,
        instance_ref: &str,
    ) -> Result<(whipplescript_store::InstanceView, InstanceMetadata), HostRuntimeError> {
        let found = source_runtime
            .kernel
            .store()
            .get_instance(instance_ref)
            .map_err(HostRuntimeError::Store)?;
        if found.is_none() {
            return Err(HostRuntimeError::UnknownInstance(instance_ref.to_owned()));
        }
        let source_instance = found.expect("an unknown source instance was refused above");
        let source_metadata: InstanceMetadata =
            serde_json::from_str(&source_instance.input_json).map_err(HostRuntimeError::Json)?;
        if source_metadata.protocol != HOST_PROTOCOL {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork source package/policy binding",
            )));
        }
        Ok((source_instance, source_metadata))
    }

    /// An ordinary fork's source: recorded under exactly the fork's policy, at
    /// a position it has reached, with no effect running.
    fn fork_source(
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
    ) -> Result<SeedSource, HostRuntimeError> {
        let (instance, metadata) =
            Self::source_instance_metadata(source_runtime, &command.source.instance_ref)?;
        if metadata.policy != command.policy {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork source package/policy binding",
            )));
        }
        Self::check_source_fork_ready(source_runtime, command)?;
        Ok(SeedSource {
            instance,
            metadata,
            position: command.source.clone(),
            cut: None,
        })
    }

    /// An adoption's source and the agent whose thread it carries (DR-0293).
    /// `source_runtime` holds the policy the source was recorded under, which
    /// is this runtime's or an earlier epoch of the same authority; what the
    /// carried thread read is re-admitted here when the epochs differ; and a
    /// running effect cuts the thread instead of refusing it.
    fn adoption_source(
        &self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        missing_version: impl FnOnce() -> HostRuntimeError,
    ) -> Result<(SeedSource, String), HostRuntimeError> {
        let (instance, metadata) =
            Self::source_instance_metadata(source_runtime, &command.source.instance_ref)?;
        if source_runtime.policy != metadata.policy {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork source package/policy binding",
            )));
        }
        self.admit_policy_advance(source_runtime)?;
        let agent = source_runtime
            .kernel
            .store()
            .get_program_version(&instance.version_id)
            .map_err(HostRuntimeError::Store)?
            .ok_or_else(missing_version)?
            .program_name;
        let (position, cut) = Self::adoption_position(source_runtime, command)?;
        if source_runtime.policy != self.policy {
            self.readmit_carried_thread(source_runtime, &position, &agent)?;
        }
        Ok((
            SeedSource {
                instance,
                metadata,
                position,
                cut,
            },
            agent,
        ))
    }

    /// An adoption may carry a thread forward across policy epochs of one
    /// authority, never back and never across authorities (DR-0293 §1). The
    /// source runtime was opened under the source's own envelope, so both
    /// sides are verified; the host's epoch numbers order them.
    fn admit_policy_advance(
        &self,
        source_runtime: &GovernedHostRuntime,
    ) -> Result<(), HostRuntimeError> {
        let (source, target) = (&source_runtime.policy, &self.policy);
        if source == target {
            return Ok(());
        }
        if source.signer != target.signer
            || source_runtime.envelope.authority() != self.envelope.authority()
        {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "adoption source policy authority",
            )));
        }
        if source.epoch >= target.epoch {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "adoption source policy epoch",
            )));
        }
        Ok(())
    }

    /// Where an adoption reads its source (DR-0293 §3): the host's position,
    /// or, when an effect that began at or before it is still running, the
    /// newest position before the first such effect began. The effect is
    /// left exactly as it is.
    fn adoption_position(
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
    ) -> Result<(EventPosition, Option<AdoptionCut>), HostRuntimeError> {
        let instance_ref = &command.source.instance_ref;
        let current = source_runtime.current_position(instance_ref)?;
        if command.source.sequence > current.sequence {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork source position",
            )));
        }
        let running = source_runtime
            .kernel
            .store()
            .list_effects(instance_ref)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .filter(|effect| effect.status == "running")
            .map(|effect| effect.effect_id)
            .collect::<Vec<_>>();
        if running.is_empty() {
            return Ok((command.source.clone(), None));
        }
        let events = source_runtime
            .kernel
            .store()
            .list_events(instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let mut first_unresolved: Option<u64> = None;
        let mut unresolved = Vec::new();
        for effect_id in running {
            let began = events
                .iter()
                .find(|event| event_names_effect(&event.payload_json, &effect_id))
                .map(|event| event.sequence as u64);
            if began.is_none() {
                return Err(HostRuntimeError::Incomplete(format!(
                    "source instance {instance_ref} has running effect {effect_id} with no recorded start"
                )));
            }
            let began = began.expect("an effect with no recorded start was refused above");
            if began > command.source.sequence {
                continue;
            }
            first_unresolved = Some(first_unresolved.map_or(began, |first| first.min(began)));
            unresolved.push(effect_id);
        }
        let Some(began) = first_unresolved else {
            return Ok((command.source.clone(), None));
        };
        // An effect is never named by an instance's first event, so the cut is
        // a real position; `ForkedInstance::validate_for` refuses one that is not.
        let sequence = began.saturating_sub(1);
        unresolved.sort();
        Ok((
            EventPosition {
                instance_ref: instance_ref.clone(),
                sequence,
            },
            Some(AdoptionCut {
                sequence,
                unresolved_effects: unresolved,
            }),
        ))
    }

    /// Re-admit what a thread carried across an epoch read (DR-0293 §2). A
    /// turn's output is labeled by the join of the resources it read, so each
    /// resource every carried turn read — through the seed lineage too — must
    /// be governed by this epoch and resolve to the identity it had when it
    /// was read. Anything else would relabel recorded content, so it refuses
    /// visibly rather than widen a label or start an empty thread.
    fn readmit_carried_thread(
        &self,
        source_runtime: &GovernedHostRuntime,
        position: &EventPosition,
        agent: &str,
    ) -> Result<(), HostRuntimeError> {
        let refused = |what: String| {
            HostRuntimeError::PolicyRejected(format!(
                "the conversation cannot be carried from policy epoch {} into epoch {}: {what}",
                source_runtime.policy.epoch, self.policy.epoch
            ))
        };
        let store = source_runtime.kernel.store();
        let mut pending = vec![(
            position.instance_ref.clone(),
            Some(agent.to_owned()),
            position.sequence as i64,
        )];
        let mut answered = std::collections::BTreeSet::new();
        while let Some((instance_ref, agent, up_to)) = pending.pop() {
            if !answered.insert((instance_ref.clone(), up_to)) {
                continue;
            }
            if store
                .get_instance(&instance_ref)
                .map_err(HostRuntimeError::Store)?
                .is_none()
            {
                return Err(refused(format!(
                    "it was seeded from instance {instance_ref}, which this store does not hold"
                )));
            }
            let lineage = source_runtime
                .kernel
                .agent_thread_lineage(&instance_ref, agent.as_deref(), Some(up_to))
                .map_err(HostRuntimeError::Store)?;
            if !lineage.turn_effect_ids.is_empty() {
                let effects = store
                    .list_effects(&instance_ref)
                    .map_err(HostRuntimeError::Store)?;
                for effect_id in &lineage.turn_effect_ids {
                    let turn = effects
                        .iter()
                        .find(|effect| effect.effect_id == *effect_id)
                        .and_then(|effect| {
                            serde_json::from_str::<StartTurnCommand>(&effect.input_json).ok()
                        });
                    if turn.is_none() {
                        return Err(refused(format!(
                            "turn {effect_id} recorded no host command naming what it read"
                        )));
                    }
                    let turn = turn.expect("a turn with no recorded command was refused above");
                    for read in turn.resources.iter().chain(turn.input.images.iter()) {
                        let handle = read.handle.as_str();
                        if !self.envelope.governs(handle)
                            || self.envelope.resolve_handle(handle)
                                != source_runtime.envelope.resolve_handle(handle)
                        {
                            return Err(refused(format!(
                                "turn {effect_id} read `{handle}`, which the newer epoch does not admit as it was read"
                            )));
                        }
                    }
                }
            }
            if let Some(seed) = lineage.seed.filter(|seed| seed.carried_messages) {
                pending.push((seed.source_instance_id, None, seed.source_sequence));
            }
        }
        Ok(())
    }

    fn fork_to_target<P: PackageResolver + ?Sized>(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
        target_package: &ResolvedPackage,
        source_agent: &str,
        seed_source: &SeedSource,
    ) -> Result<ForkedInstance, HostRuntimeError> {
        let source_sequence = seed_source.position.sequence;
        let target_command = command.target_open_command();
        let target = self.open_instance(&target_command, packages)?;
        if target.instance_ref == command.source.instance_ref {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork target identity",
            )));
        }

        let messages = source_runtime
            .kernel
            .snapshot_agent_thread(
                &command.source.instance_ref,
                source_agent,
                Some(source_sequence as i64),
            )
            .map_err(HostRuntimeError::Store)?;
        let seed_key = idempotency_key(&[
            &target.instance_ref,
            &command.request_id,
            "host-instance-thread-seed",
        ]);
        let seed_payload = json!({
            "agent": target_package.agent,
            "messages": whipplescript_kernel::harness_loop::chat_messages_to_json(&messages),
            "source_instance_id": command.source.instance_ref,
            "source_sequence": source_sequence as i64,
        });
        let seed = self.exact_fork_event(
            &target.instance_ref,
            &seed_key,
            "agent.thread.seeded",
            &seed_payload,
            "kernel",
        )?;
        if let Some(replayed) = self.replayed_fork_instance(command, &target)? {
            if seed.is_none() {
                return Err(HostRuntimeError::Incomplete(
                    "recorded fork has no exact thread seed".into(),
                ));
            }
            return Ok(replayed);
        }
        if seed.is_none() {
            self.kernel
                .seed_agent_thread(AgentThreadSeed {
                    instance_id: &target.instance_ref,
                    agent: &target_package.agent,
                    messages: &messages,
                    source_instance_id: &command.source.instance_ref,
                    source_sequence: source_sequence as i64,
                    idempotency_key: &seed_key,
                })
                .map_err(HostRuntimeError::Store)?;
        }
        let mut payload = json!({
            "request_id": command.request_id,
            "source": command.source,
            "target_request_id": command.target_request_id,
            "package_version_ref": command.package_version_ref,
            "policy": command.policy,
        });
        seed_source.record_on(&mut payload, command);
        let payload = payload.to_string();
        let event = self
            .kernel
            .store()
            .append_event(NewEvent {
                instance_id: &target.instance_ref,
                event_type: "host.instance.forked",
                payload_json: &payload,
                source: "host-runtime",
                causation_id: None,
                correlation_id: Some(&command.request_id),
                idempotency_key: Some(&idempotency_key(&[
                    &target.instance_ref,
                    &command.request_id,
                    "host-instance-forked",
                ])),
            })
            .map_err(HostRuntimeError::Store)?;
        let target_instance_ref = target.instance_ref.clone();
        let result = ForkedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            source: command.source.clone(),
            target,
            forked_at: EventPosition {
                instance_ref: target_instance_ref,
                sequence: positive_sequence(event.sequence)?,
            },
            cut: seed_source.cut.clone(),
        };
        result.validate_for(command)?;
        Ok(result)
    }

    fn check_source_fork_ready(
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
    ) -> Result<(), HostRuntimeError> {
        let current = source_runtime.current_position(&command.source.instance_ref)?;
        if command.source.sequence > current.sequence {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork source position",
            )));
        }
        let running = source_runtime
            .kernel
            .store()
            .list_effects(&command.source.instance_ref)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .any(|effect| effect.status == "running");
        if running {
            return Err(HostRuntimeError::Incomplete(format!(
                "source instance {} is not quiescent",
                command.source.instance_ref
            )));
        }
        Ok(())
    }

    /// An idempotency key is only a locator. Verify the stored event's exact
    /// meaning before treating a crash retry as completion of the old step.
    fn exact_fork_event(
        &self,
        instance_ref: &str,
        key: &str,
        event_type: &str,
        expected_payload: &Value,
        source: &str,
    ) -> Result<Option<whipplescript_store::StoredEvent>, HostRuntimeError> {
        let Some(event) = self
            .kernel
            .store()
            .event_view_by_idempotency_key(instance_ref, key)
            .map_err(HostRuntimeError::Store)?
        else {
            return Ok(None);
        };
        if event.event_type != event_type
            || event.source != source
            || serde_json::from_str::<Value>(&event.payload_json).map_err(HostRuntimeError::Json)?
                != *expected_payload
        {
            return Err(HostRuntimeError::Incomplete(
                "fork event key names different evidence".into(),
            ));
        }
        Ok(Some(whipplescript_store::StoredEvent {
            event_id: event.event_id,
            sequence: event.sequence,
        }))
    }

    fn replayed_fork_instance(
        &self,
        command: &ForkInstanceCommand,
        target: &OpenedInstance,
    ) -> Result<Option<ForkedInstance>, HostRuntimeError> {
        let events = self
            .kernel
            .store()
            .list_events(&target.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let Some(event) = events.iter().find(|event| {
            event.event_type == "host.instance.forked"
                && serde_json::from_str::<Value>(&event.payload_json)
                    .ok()
                    .and_then(|payload| {
                        payload
                            .get("request_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(command.request_id.as_str())
        }) else {
            return Ok(None);
        };
        let payload: Value =
            serde_json::from_str(&event.payload_json).map_err(HostRuntimeError::Json)?;
        let result = ForkedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: required_string(&payload, "request_id")?,
            source: serde_json::from_value(payload["source"].clone())
                .map_err(HostRuntimeError::Json)?,
            target: target.clone(),
            forked_at: EventPosition {
                instance_ref: target.instance_ref.clone(),
                sequence: positive_sequence(event.sequence)?,
            },
            cut: match payload.get("cut") {
                Some(cut) => {
                    Some(serde_json::from_value(cut.clone()).map_err(HostRuntimeError::Json)?)
                }
                None => None,
            },
        };
        result.validate_for(command)?;
        Ok(Some(result))
    }

    fn replayed_open_instance(
        &mut self,
        command: &OpenInstanceCommand,
        package: &ResolvedPackage,
        source_digest: &str,
        target_store_incarnation: Option<&str>,
        journal: &mut Option<&mut dyn OpenInstanceHomeJournal>,
    ) -> Result<Option<(OpenedInstance, String)>, HostRuntimeError> {
        for instance in self
            .kernel
            .store()
            .list_instances()
            .map_err(HostRuntimeError::Store)?
        {
            // The opened event is appended under a key derived from exactly this
            // (instance, request) pair, so one indexed point lookup per instance
            // decides the replay question that a full event-log scan used to.
            let replay_key = idempotency_key(&[
                &instance.instance_id,
                &command.request_id,
                "host-instance-opened",
            ]);
            let Some(stored) = self
                .kernel
                .store()
                .event_by_idempotency_key(&instance.instance_id, &replay_key)
                .map_err(HostRuntimeError::Store)?
            else {
                continue;
            };
            let Some(event) = self
                .kernel
                .store()
                .list_events(&instance.instance_id)
                .map_err(HostRuntimeError::Store)?
                .into_iter()
                .find(|event| event.event_id == stored.event_id)
            else {
                continue;
            };
            if event.event_type != "host.instance.opened" {
                continue;
            }
            let payload: Value =
                serde_json::from_str(&event.payload_json).map_err(HostRuntimeError::Json)?;
            if payload.get("request_id").and_then(Value::as_str)
                != Some(command.request_id.as_str())
            {
                continue;
            }
            let opened = OpenedInstance {
                protocol: HOST_PROTOCOL.to_owned(),
                request_id: command.request_id.clone(),
                instance_ref: instance.instance_id.clone(),
                package_version_ref: required_string(&payload, "package_version_ref")?,
                policy: serde_json::from_value(payload["policy"].clone())
                    .map_err(HostRuntimeError::Json)?,
                opened_at: EventPosition {
                    instance_ref: instance.instance_id.clone(),
                    sequence: positive_sequence(event.sequence)?,
                },
            };
            opened.validate_for(command)?;
            let version = self
                .kernel
                .store()
                .get_program_version(&instance.version_id)
                .map_err(HostRuntimeError::Store)?
                .ok_or_else(|| HostRuntimeError::UnknownInstance(instance.instance_id.clone()))?;
            // Different authored content under a replayed request is the
            // integrity breach this guard exists for.
            if version.source_hash != package.source_hash {
                return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "replayed package content",
                )));
            }
            // Same authored program, different IR: the toolchain compiling
            // it has moved since the instance was opened. Refusing here
            // would strand every instance across every compiler-evolving
            // upgrade, which contradicts the store's durability — so the
            // current compile is re-attested (an auditable event plus a
            // version re-point, spec/agent-harness.md "Program identity
            // across toolchains").
            let current_version_id = if version.ir_hash != package.ir_hash {
                if let Some(journal) = journal.as_mut() {
                    journal
                        .allow_retained_use(
                            target_store_incarnation.expect("Home identity checked"),
                            &command.request_id,
                            &instance.instance_id,
                            &version.version_id,
                        )
                        .map_err(home_journal_error)?;
                }
                let compiler_artifact_digest =
                    native_compiler_artifact_digest().map_err(HostRuntimeError::Resolver)?;
                let construct_registry = embedded_std_registry_for_program(
                    &package.program,
                    crate::std_manifests::EMBEDDED_STD_MANIFESTS,
                )
                .map_err(HostRuntimeError::Resolver)?;
                let construct_basis = CheckedConstructBasis {
                    registry: &construct_registry,
                    sources: &[],
                };
                let operation_id = journal
                    .as_mut()
                    .map(|journal| {
                        journal.register(&OpenInstanceOperationBasis {
                            target_store_incarnation: target_store_incarnation
                                .expect("Home identity checked"),
                            kind: "reattest",
                            instance_ref: Some(&instance.instance_id),
                            from_version_id: Some(&version.version_id),
                            request_id: &command.request_id,
                            package_version_ref: &command.package_version_ref,
                            program_name: &package.agent,
                            source_digest,
                            version_source_digest: &package.source_hash,
                            lock_digest: NO_LOCK_DIGEST,
                            ir_hash: &package.ir_hash,
                            compiler_artifact_digest: &compiler_artifact_digest,
                            policy: &command.policy,
                            construct_basis: Some(&construct_basis),
                        })
                    })
                    .transpose()
                    .map_err(home_journal_error)?;
                let input = ProgramVersionInput {
                    program_name: &package.agent,
                    source_hash: &package.source_hash,
                    ir_hash: &package.ir_hash,
                    compiler_version: HOST_PROTOCOL,
                    ir_snapshot: None,
                };
                let import_basis = CheckedImportBasis {
                    program_source_digest: source_digest,
                    version_source_digest: Some(&package.source_hash),
                    lock_digest: NO_LOCK_DIGEST,
                    compiler_artifact_digest: &compiler_artifact_digest,
                    packages: &[],
                };
                let admission = if let Some(operation_id) = operation_id.as_deref() {
                    self.kernel
                        .reattest_instance_program_with_imports_and_constructs_at_id(
                            &instance.instance_id,
                            input,
                            &package.program,
                            &import_basis,
                            Some(&construct_basis),
                            operation_id,
                        )
                } else {
                    self.kernel
                        .reattest_instance_program_with_imports_and_constructs(
                            &instance.instance_id,
                            input,
                            &package.program,
                            &import_basis,
                            &construct_basis,
                        )
                }
                .map_err(HostRuntimeError::Store)?;
                if let Some(journal) = journal.as_mut() {
                    require_same_home_store_incarnation(
                        self.kernel.store(),
                        target_store_incarnation.expect("Home identity checked"),
                    )?;
                    journal
                        .complete_for_use(&OpenInstanceOperationEvidence {
                            target_store_incarnation: target_store_incarnation
                                .expect("Home identity checked"),
                            request_id: &command.request_id,
                            operation_id: &admission.operation_id,
                            instance_ref: Some(&instance.instance_id),
                            version_id: &admission.version_id,
                            witness_digest: &admission.witness_digest,
                        })
                        .map_err(home_journal_error)?;
                }
                admission.version_id
            } else {
                version.version_id
            };
            return Ok(Some((opened, current_version_id)));
        }
        Ok(None)
    }

    /// Run a turn through WhippleScript's owned brokered loop using the native
    /// HTTP transport.
    pub fn run_turn<P, S, R>(
        &mut self,
        command: &StartTurnCommand,
        packages: &P,
        secrets: &S,
        resources: &R,
    ) -> Result<TurnExecution, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        S: SecretResolver + ?Sized,
        R: ResourceResolver + ?Sized,
    {
        self.run_turn_observing_model_requests(command, packages, secrets, resources, &|_, _| {})
    }

    /// Drive a native turn while observing each provider-bound request body.
    /// The observer runs immediately before transport and is never written to
    /// the governed event stream. Callers must keep its capture ephemeral and
    /// authorize any reader separately.
    pub fn run_turn_observing_model_requests<P, S, R>(
        &mut self,
        command: &StartTurnCommand,
        packages: &P,
        secrets: &S,
        resources: &R,
        observe_request: &dyn Fn(
            &Value,
            Option<&whipplescript_kernel::sansio::ModelRequestProvenance>,
        ),
    ) -> Result<TurnExecution, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        S: SecretResolver + ?Sized,
        R: ResourceResolver + ?Sized,
    {
        self.run_turn_observing_model_requests_with_provenance(
            command,
            packages,
            secrets,
            resources,
            &Default::default(),
            observe_request,
        )
    }

    /// The owning product supplies source identities for the initial input
    /// planes. WhippleScript propagates them through the turn and marks any
    /// unaccounted content unknown; these labels do not authorize a reader.
    pub fn run_turn_observing_model_requests_with_provenance<P, S, R>(
        &mut self,
        command: &StartTurnCommand,
        packages: &P,
        secrets: &S,
        resources: &R,
        model_provenance: &whipplescript_kernel::sansio::InitialModelProvenance,
        observe_request: &dyn Fn(
            &Value,
            Option<&whipplescript_kernel::sansio::ModelRequestProvenance>,
        ),
    ) -> Result<TurnExecution, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        S: SecretResolver + ?Sized,
        R: ResourceResolver + ?Sized,
    {
        let access = LiveTurnAccess::new(resources);
        access.check()?;
        self.admit_command(command, packages)?;
        access.check()?;
        let binding = self.resolve_provider(command, secrets)?;
        let sink = |delta: &str| {
            if access.check().is_ok() {
                resources.observe_text_delta(delta);
            }
        };
        // Mid-stream cooperative cancel (spec/agent-harness.md "Cancellation"):
        // the transport polls the durable request surface between streamed
        // lines and releases the stream early; the machine converts that
        // released round to `Cancelled`, keeping the text that fully arrived.
        let probe = StreamCancelProbe::new(
            self.store_path.clone(),
            command.instance_ref.clone(),
            command.command_id.clone(),
            self.protection.clone(),
        );
        let observed = || access.check().is_err() || probe.observed();
        let released = || access.refused.get() || probe.released();
        let admit_request =
            |request: &NativeProviderRequest<'_>,
             send: &mut dyn FnMut(Duration) -> Result<(), String>| {
                access.check().map_err(|_| LIVE_ACCESS_REFUSED.to_owned())?;
                resources.with_native_provider_request(request, send)
            };
        let driver = NativeHttpDriver::for_binding(&binding)?
            .with_delta_sink(&sink)
            .with_cancel_probe(&observed)
            .with_request_observer(observe_request)
            .with_request_admission(command, &admit_request);
        self.run_admitted_turn(
            command,
            packages,
            &access,
            binding,
            &driver,
            TurnRunInspection {
                stream_released: Some(&released),
                model_provenance,
            },
        )
    }

    /// The same governed path with a caller-supplied sans-I/O driver. Native
    /// tests and remote hosts use this to drive the exact machine without a
    /// second turn implementation.
    pub fn run_turn_with_driver<P, S, R, H>(
        &mut self,
        command: &StartTurnCommand,
        packages: &P,
        secrets: &S,
        resources: &R,
        driver: &H,
    ) -> Result<TurnExecution, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        S: SecretResolver + ?Sized,
        R: ResourceResolver + ?Sized,
        H: HostDriver,
    {
        self.run_turn_with_driver_and_provenance(
            command,
            packages,
            secrets,
            resources,
            driver,
            &Default::default(),
        )
    }

    /// Drive the same admitted machine through a caller-supplied transport
    /// while carrying host-attested input sources into each HTTP request's
    /// transient model provenance. The driver may inspect the request body and
    /// labels before transport; neither enters durable runtime evidence.
    pub fn run_turn_with_driver_and_provenance<P, S, R, H>(
        &mut self,
        command: &StartTurnCommand,
        packages: &P,
        secrets: &S,
        resources: &R,
        driver: &H,
        model_provenance: &whipplescript_kernel::sansio::InitialModelProvenance,
    ) -> Result<TurnExecution, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        S: SecretResolver + ?Sized,
        R: ResourceResolver + ?Sized,
        H: HostDriver,
    {
        let access = LiveTurnAccess::new(resources);
        access.check()?;
        self.admit_command(command, packages)?;
        access.check()?;
        let binding = self.resolve_provider(command, secrets)?;
        self.run_admitted_turn(
            command,
            packages,
            &access,
            binding,
            driver,
            TurnRunInspection {
                stream_released: None,
                model_provenance,
            },
        )
    }

    fn admit_command<P>(
        &self,
        command: &StartTurnCommand,
        packages: &P,
    ) -> Result<(), HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
    {
        command.validate()?;
        self.require_policy(&command.policy)?;
        self.require_governed(&command.provider_binding.binding_id)?;
        self.require_governed(&command.placement_ceiling_ref)?;
        for resource in command.resources.iter().chain(command.input.images.iter()) {
            self.require_governed(&resource.handle)?;
        }
        self.validate_instance(command, packages)?;
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        self.check_principal_ceiling(&package, &command.actor_ref)?;
        Ok(())
    }

    fn resolve_provider<S>(
        &self,
        command: &StartTurnCommand,
        secrets: &S,
    ) -> Result<ResolvedProviderBinding, HostRuntimeError>
    where
        S: SecretResolver + ?Sized,
    {
        let binding = secrets
            .resolve_provider(&command.provider_binding, &command.placement_ceiling_ref)
            .map_err(HostRuntimeError::Resolver)?;
        binding.validate()?;
        let (provider, model, base_url) = binding.policy_identity();
        if !self.envelope.permits_provider_binding(
            &command.provider_binding.binding_id,
            &command.provider_binding.credential.credential_id,
            provider,
            model,
            base_url,
            &command.placement_ceiling_ref,
        ) {
            return Err(HostRuntimeError::PolicyRejected(
                "resolved provider, credential reference, or placement was not admitted by the policy epoch"
                    .to_owned(),
            ));
        }
        Ok(binding)
    }

    fn run_admitted_turn<P, R, H>(
        &mut self,
        command: &StartTurnCommand,
        packages: &P,
        access: &LiveTurnAccess<'_, R>,
        binding: ResolvedProviderBinding,
        driver: &H,
        inspection: TurnRunInspection<'_>,
    ) -> Result<TurnExecution, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        R: ResourceResolver + ?Sized,
        H: HostDriver,
    {
        let resources = access.resources;
        access.check()?;
        if let Some(execution) = self.stored_execution(command)? {
            admit_reused_turn(command, resources, &mut || access.check())?;
            access.check()?;
            return Ok(execution);
        }
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&package, &command.package_version_ref)?;
        if !self.envelope.permits_capabilities(&package.capabilities) {
            return Err(HostRuntimeError::PolicyRejected(format!(
                "package requests capabilities outside the policy epoch: {}",
                package.capabilities.join(", ")
            )));
        }
        self.check_package_ifc(&package)?;
        let command_json = serde_json::to_string(command).map_err(HostRuntimeError::Json)?;
        let effects = self
            .kernel
            .store()
            .list_effects(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let resumed_effect = match effects
            .iter()
            .find(|effect| effect.effect_id == command.command_id)
        {
            Some(effect) => {
                validate_recorded_turn_input(effect, command)?;
                if is_terminal_effect(&effect.status) {
                    let mut execution = None;
                    admit_reused_turn(command, resources, &mut || {
                        access.check()?;
                        execution = Some(self.finish_execution(command)?);
                        Ok(())
                    })?;
                    access.check()?;
                    return Ok(execution.expect("reuse callback completed"));
                }
                true
            }
            None => {
                access.check()?;
                let mut invoked = false;
                let mut committed = false;
                let mut duplicate = false;
                let mut start = || {
                    if invoked {
                        duplicate = true;
                        return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                            "turn start admission invoked twice",
                        )));
                    }
                    invoked = true;
                    access.check()?;
                    self.kernel
                        .commit_rule(RuleCommit {
                            instance_id: &command.instance_ref,
                            rule: "host.turn",
                            trigger_event_id: None,
                            facts: &[],
                            consumed_fact_ids: &[],
                            effects: &[NewEffect {
                                effect_id: &command.command_id,
                                kind: "agent.tell",
                                target: Some(&package.agent),
                                input_json: &command_json,
                                status: "queued",
                                idempotency_key: &idempotency_key(&[
                                    &command.instance_ref,
                                    &command.command_id,
                                    "host-turn-effect",
                                ]),
                                required_capabilities_json: "[]",
                                profile: None,
                                correlation_id: Some(&command.run_ref),
                                source_span_json: None,
                                timeout_seconds: None,
                            }],
                            dependencies: &[],
                            terminal: None,
                            idempotency_key: Some(&idempotency_key(&[
                                &command.instance_ref,
                                &command.command_id,
                                "host-turn-commit",
                            ])),
                            marks: &[],
                            context_json: None,
                        })
                        .map_err(HostRuntimeError::Store)?;
                    committed = true;
                    Ok(())
                };
                resources.with_turn_start_admission(command, &mut start)?;
                if !committed || duplicate {
                    return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                        "turn start admission omitted or repeated the durable effect",
                    )));
                }
                false
            }
        };

        // Message-scoped image handles are resolved only when the effect is
        // first committed. A suspended effect already has its exact brokered
        // transcript; resumption must not require the embedding host to retain
        // or replay the original ephemeral bytes.
        let media = if resumed_effect {
            Vec::new()
        } else {
            command
                .input
                .images
                .iter()
                .map(|image| {
                    access.check()?;
                    let resolved = resources.resolve_image(image);
                    access.check()?;
                    let resolved = resolved.map_err(HostRuntimeError::Resolver)?;
                    if resolved.media_type.trim().is_empty() {
                        return Err(HostRuntimeError::Resolver(
                            "resolved image has no media type".to_owned(),
                        ));
                    }
                    Ok(MediaInput {
                        artifact_ref: image
                            .selector
                            .clone()
                            .unwrap_or_else(|| image.handle.clone()),
                        media_type: resolved.media_type,
                        data_base64: Some(base64_encode(&resolved.bytes)),
                        metadata: BTreeMap::new(),
                    })
                })
                .collect::<Result<Vec<_>, HostRuntimeError>>()?
        };
        let executor = ResolverToolExecutor {
            offered: &package.tools,
            admitted_resources: &command.resources,
            resolver: resources,
            access,
        };
        let client = match binding.provider {
            ModelProvider::OpenAi => MessagesApiClient::new(
                CoerceProvider::OpenAi,
                binding.api_key,
                binding.model,
                binding.base_url,
                binding.max_tokens,
                Some(command.command_id.clone()),
            ),
            ModelProvider::OpenAiCompat => MessagesApiClient::new(
                CoerceProvider::OpenAiCompat,
                binding.api_key,
                binding.model,
                binding.base_url,
                binding.max_tokens,
                Some(command.command_id.clone()),
            ),
            ModelProvider::Xai => MessagesApiClient::new_xai(
                binding.api_key,
                binding.model,
                binding.base_url,
                binding.max_tokens,
                Some(command.command_id.clone()),
            ),
            ModelProvider::XaiSubscription => MessagesApiClient::new_xai_subscription(
                binding.api_key,
                binding.model,
                binding.base_url,
                binding.max_tokens,
                Some(command.command_id.clone()),
            ),
            ModelProvider::Anthropic => MessagesApiClient::new(
                CoerceProvider::Anthropic,
                binding.api_key,
                binding.model,
                binding.base_url,
                binding.max_tokens,
                Some(command.command_id.clone()),
            ),
            ModelProvider::Codex => MessagesApiClient::new_codex(
                binding.api_key,
                binding.codex_account_id.unwrap_or_default(),
                binding.codex_session_id.unwrap_or_default(),
                binding.model,
                binding.base_url,
                binding.max_tokens,
                Some(command.command_id.clone()),
            ),
        };
        let world = hosted_model_visible_world(command, &package, resources)
            .map_err(HostRuntimeError::Resolver)?;
        let registered_skills = self
            .kernel
            .store()
            .list_skills()
            .map_err(HostRuntimeError::Store)?;
        let skill_sources =
            attested_skill_catalogue_provenance(self.kernel.store(), resources, &registered_skills);
        let skills = registered_skills
            .into_iter()
            .map(|skill| SkillCatalogueEntry {
                name: skill.name,
                description: skill.description,
                location: skill.source_path,
            })
            .collect::<Vec<_>>();
        let context = package.context_for_model_with_skills(&skills);
        let mut model_provenance = inspection.model_provenance.clone();
        model_provenance.system =
            ModelContentProvenance::derived_from([&model_provenance.system, &skill_sources]);
        let input = BrokeredTurnInput {
            model_provenance,
            system: context.system_role,
            developer: context.developer_role,
            user: command.input.text.clone(),
            tools: package.tools.clone(),
            max_steps: package.max_steps,
            resume_from: Vec::new(),
            user_images: Vec::new(),
            // The authored agent-package manifest has no result contract of its
            // own; `returns` is declared on a `.whip` agent, which this hosted
            // path does not read.
            result_tool: None,
            user_media: media,
            world: Some(world),
            context_bundles: context.contributions,
            pinned_skills: Vec::new(),
        };
        let driver = LiveAccessDriver {
            inner: driver,
            access,
        };
        if resumed_effect {
            admit_reused_turn(command, resources, &mut || access.check())?;
        }
        self.kernel
            .run_brokered_agent_turn(
                &BrokeredTurnContext {
                    instance_id: &command.instance_ref,
                    effect_id: &command.command_id,
                    agent: &package.agent,
                    profile: None,
                    thread_continue: true,
                    stream_released: inspection.stream_released,
                },
                &client,
                &executor,
                &driver,
                &NoopCompactor,
                &input,
            )
            .map_err(HostRuntimeError::Store)?;
        // DR-0036 §1: persist this segment's workspace witness before the turn
        // suspends or finishes — a human-suspended turn resumes with a fresh
        // resolver, so the receipt aggregates the durable segments instead of
        // trusting any single resolver instance.
        self.record_witness_segment(command, resources)?;
        let execution = self.finish_execution(command)?;
        access.check()?;
        Ok(execution)
    }

    /// Record the turn segment's workspace witness as durable evidence
    /// (DR-0036 §1). `Unavailable` records nothing — a resolver with no
    /// workspace has nothing to claim or decline; the receipt will honestly
    /// omit `workspace_cut_ref`.
    fn record_witness_segment<R: ResourceResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        resources: &R,
    ) -> Result<(), HostRuntimeError> {
        let witness = resources.take_turn_witness();
        let metadata = match &witness {
            TurnWitness::Unavailable => return Ok(()),
            TurnWitness::Witnessed { writes, reads } => json!({
                "witness": "witnessed",
                "writes": writes,
                "reads": reads,
            }),
            TurnWitness::Unwitnessed { reason } => json!({
                "witness": "unwitnessed",
                "reason": reason,
            }),
        };
        let run_id = idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
        self.kernel
            .store()
            .record_evidence(EvidenceRecord {
                instance_id: &command.instance_ref,
                kind: "host.turn.workspace_cut.segment",
                subject_type: "run",
                subject_id: &run_id,
                causation_id: Some(&command.command_id),
                correlation_id: Some(&command.command_id),
                summary: None,
                metadata_json: &metadata.to_string(),
            })
            .map_err(HostRuntimeError::Store)?;
        Ok(())
    }

    /// Fold the turn's witness segments into one claim (DR-0036 §1;
    /// turn-witness.maude): any unwitnessed segment declines the whole turn
    /// (never fabricate); otherwise writes merge by path (a later segment's
    /// write to the same path supersedes) and reads union. No segments at
    /// all = no workspace surface = nothing to reference.
    fn aggregate_witness(
        &self,
        command: &StartTurnCommand,
        run_id: &str,
    ) -> Result<TurnWitness, HostRuntimeError> {
        let segments = self
            .kernel
            .store()
            .list_evidence_for_subject("run", run_id)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .filter(|item| {
                item.kind == "host.turn.workspace_cut.segment"
                    && item.correlation_id.as_deref() == Some(&command.command_id)
            })
            .collect::<Vec<_>>();
        if segments.is_empty() {
            return Ok(TurnWitness::Unavailable);
        }
        let mut writes: std::collections::BTreeMap<String, WitnessedWrite> =
            std::collections::BTreeMap::new();
        let mut reads: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for segment in segments {
            let value: Value =
                serde_json::from_str(&segment.metadata_json).map_err(HostRuntimeError::Json)?;
            match value.get("witness").and_then(Value::as_str) {
                Some("witnessed") => {
                    let segment_writes: Vec<WitnessedWrite> =
                        serde_json::from_value(value.get("writes").cloned().unwrap_or_default())
                            .map_err(HostRuntimeError::Json)?;
                    for write in segment_writes {
                        writes.insert(write.path.clone(), write);
                    }
                    if let Some(segment_reads) = value.get("reads").and_then(Value::as_array) {
                        reads.extend(
                            segment_reads
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_owned),
                        );
                    }
                }
                _ => {
                    return Ok(TurnWitness::Unwitnessed {
                        reason: value
                            .get("reason")
                            .and_then(Value::as_str)
                            .unwrap_or("a turn segment was unwitnessed")
                            .to_owned(),
                    });
                }
            }
        }
        Ok(TurnWitness::Witnessed {
            writes: writes.into_values().collect(),
            reads: reads.into_iter().collect(),
        })
    }

    /// Evaluate the envelope's declared dynamic guarantees for this turn
    /// (DR-0036 §2) under the cited policy epoch. Every declared guarantee
    /// appears in the report — held, violated, or not-evaluated, never
    /// silently omitted; consumers match names, never re-evaluate semantics.
    fn evaluate_dynamic_guarantees(&self, witness: &TurnWitness) -> Vec<Value> {
        self.envelope
            .declared_guarantees()
            .iter()
            .map(|(name, paths)| {
                if let Some(scope) = name.strip_prefix("writes_within:") {
                    return match witness {
                        TurnWitness::Witnessed { writes, .. } => {
                            let outside: Vec<&str> = writes
                                .iter()
                                .filter(|write| {
                                    !paths.iter().any(|glob| wildcard_matches(glob, &write.path))
                                })
                                .map(|write| write.path.as_str())
                                .collect();
                            if outside.is_empty() {
                                json!({ "name": name, "outcome": "held", "detail": format!("{} write(s) within scope `{scope}`", writes.len()) })
                            } else {
                                json!({ "name": name, "outcome": "violated", "detail": format!("write(s) outside scope `{scope}`: {}", outside.join(", ")) })
                            }
                        }
                        TurnWitness::Unwitnessed { reason } => json!({
                            "name": name, "outcome": "not_evaluated", "detail": reason,
                        }),
                        TurnWitness::Unavailable => json!({
                            "name": name, "outcome": "not_evaluated",
                            "detail": "the turn had no witnessed workspace surface",
                        }),
                    };
                }
                if name == "no_reads_beyond_grant" {
                    return match witness {
                        TurnWitness::Witnessed { reads, .. } => json!({
                            "name": name, "outcome": "held",
                            "detail": format!("{} read(s), all resolver-mediated within the turn's admitted capabilities", reads.len()),
                        }),
                        TurnWitness::Unwitnessed { reason } => json!({
                            "name": name, "outcome": "not_evaluated", "detail": reason,
                        }),
                        TurnWitness::Unavailable => json!({
                            "name": name, "outcome": "not_evaluated",
                            "detail": "the turn had no witnessed workspace surface",
                        }),
                    };
                }
                if name.starts_with("no_tainted_reads:") {
                    return json!({
                        "name": name, "outcome": "not_evaluated",
                        "detail": "label-class read tainting is not witnessed yet",
                    });
                }
                json!({
                    "name": name, "outcome": "not_evaluated",
                    "detail": "unknown guarantee name",
                })
            })
            .collect()
    }

    fn validate_instance<P: PackageResolver + ?Sized>(
        &self,
        command: &StartTurnCommand,
        packages: &P,
    ) -> Result<(), HostRuntimeError> {
        self.validate_instance_binding(
            &command.instance_ref,
            &command.package_version_ref,
            &command.policy,
            packages,
        )
    }

    fn validate_instance_binding<P: PackageResolver + ?Sized>(
        &self,
        instance_ref: &str,
        package_version_ref: &str,
        policy: &PolicyEpochRef,
        packages: &P,
    ) -> Result<(), HostRuntimeError> {
        let instance = self
            .kernel
            .store()
            .get_instance(instance_ref)
            .map_err(HostRuntimeError::Store)?
            .ok_or_else(|| HostRuntimeError::UnknownInstance(instance_ref.to_owned()))?;
        let metadata: InstanceMetadata =
            serde_json::from_str(&instance.input_json).map_err(HostRuntimeError::Json)?;
        if metadata.protocol != HOST_PROTOCOL
            || metadata.package_version_ref != package_version_ref
            || metadata.policy != *policy
        {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "instance package/policy binding",
            )));
        }
        let package = packages
            .resolve_package(package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&package, package_version_ref)?;
        self.check_package_ifc(&package)?;
        let version = self
            .kernel
            .store()
            .get_program_version(&instance.version_id)
            .map_err(HostRuntimeError::Store)?
            .ok_or_else(|| HostRuntimeError::UnknownInstance(instance_ref.to_owned()))?;
        if version.source_hash != package.source_hash || version.ir_hash != package.ir_hash {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "resolved package content",
            )));
        }
        Ok(())
    }

    fn finish_execution(
        &mut self,
        command: &StartTurnCommand,
    ) -> Result<TurnExecution, HostRuntimeError> {
        if let Some(execution) = self.stored_execution(command)? {
            return Ok(execution);
        }
        let run_id = idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
        let run = self
            .kernel
            .store()
            .list_runs(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .find(|run| run.run_id == run_id)
            .ok_or_else(|| HostRuntimeError::Incomplete(command.command_id.clone()))?;
        let status = turn_status(&run.status)?;
        let usage_ref =
            self.ensure_evidence(command, &run_id, "host.turn.usage", &run.metadata_json)?;
        // DR-0036 §1: the receipt's workspace cut is the aggregated witness —
        // a complete claim (possibly explicitly empty), or honestly absent
        // when any segment was unwitnessed or no workspace surface existed.
        let witness = self.aggregate_witness(command, &run_id)?;
        let workspace_cut_ref = match &witness {
            TurnWitness::Witnessed { writes, reads } => Some(
                self.ensure_evidence(
                    command,
                    &run_id,
                    "host.turn.workspace_cut",
                    &json!({
                        "complete": true,
                        "writes": writes,
                        "reads": reads,
                    })
                    .to_string(),
                )?,
            ),
            TurnWitness::Unwitnessed { .. } | TurnWitness::Unavailable => None,
        };
        // DR-0036 §2: the static admission set plus the dynamic per-turn
        // section, evaluated under the cited policy epoch.
        let dynamic = self.evaluate_dynamic_guarantees(&witness);
        let guarantee = json!({
            "protocol": HOST_PROTOCOL,
            "policy": command.policy,
            "actor_ref": command.actor_ref,
            "package_version_ref": command.package_version_ref,
            "resources": command.resources,
            "images": command.input.images,
            "provider_binding_ref": command.provider_binding,
            "placement_ceiling_ref": command.placement_ceiling_ref,
            "guarantees": [
                "signed_policy_identity_verified",
                "package_ifc_checked_under_verified_envelope",
                "instance_package_policy_binding_verified",
                "resource_provider_placement_handles_governed",
                "tool_surface_pinned_to_package",
                "resource_and_secret_bodies_resolved_after_admission"
            ],
            "dynamic": dynamic,
        })
        .to_string();
        let guarantee_report_ref =
            self.ensure_evidence(command, &run_id, "host.turn.guarantee", &guarantee)?;
        let events = self.project_events(command, &run_id)?;
        let output_handle =
            matches!(status, TurnStatus::Completed).then(|| format!("whip:run:{run_id}:output"));
        let marker_payload = json!({
            "command_id": command.command_id,
            "run_ref": command.run_ref,
            "status": status,
            "output_handle": output_handle,
            "usage_ref": usage_ref,
            "guarantee_report_ref": guarantee_report_ref,
            "workspace_cut_ref": workspace_cut_ref,
        })
        .to_string();
        let marker = self
            .kernel
            .store()
            .append_event(NewEvent {
                instance_id: &command.instance_ref,
                event_type: "host.turn.receipt",
                payload_json: &marker_payload,
                source: "host-runtime",
                causation_id: Some(&run_id),
                correlation_id: Some(&command.command_id),
                idempotency_key: Some(&idempotency_key(&[
                    &command.instance_ref,
                    &command.command_id,
                    "host-turn-receipt",
                ])),
            })
            .map_err(HostRuntimeError::Store)?;
        let receipt = TurnReceipt {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: command.command_id.clone(),
            run_ref: command.run_ref.clone(),
            instance_ref: command.instance_ref.clone(),
            policy: command.policy.clone(),
            terminal_position: EventPosition {
                instance_ref: command.instance_ref.clone(),
                sequence: positive_sequence(marker.sequence)?,
            },
            status,
            output_handle,
            usage_ref,
            guarantee_report_ref,
            workspace_cut_ref,
        };
        receipt.validate_for(command)?;
        let output = self.project_turn_output(command, receipt.output_handle.clone())?;
        let usage = self.project_turn_usage(command, &receipt.usage_ref)?;
        Ok(TurnExecution {
            events,
            receipt: Some(receipt),
            output,
            usage,
        })
    }

    /// Project the run's usage metadata into the typed observation. Total: a
    /// missing run or metadata without a usage object is an honest `None`, not
    /// an error — legacy runs recorded before the projection existed still
    /// reconstruct.
    fn project_turn_usage(
        &self,
        command: &StartTurnCommand,
        usage_ref: &str,
    ) -> Result<Option<TurnUsageObservation>, HostRuntimeError> {
        let run_id = idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
        let Some(run) = self
            .kernel
            .store()
            .list_runs(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .find(|run| run.run_id == run_id)
        else {
            return Ok(None);
        };
        let metadata: Value =
            serde_json::from_str(&run.metadata_json).map_err(HostRuntimeError::Json)?;
        let Some(usage) = metadata.get("usage").filter(|usage| usage.is_object()) else {
            return Ok(None);
        };
        let tokens = |primary: &str, alias: &str| {
            usage
                .get(primary)
                .or_else(|| usage.get(alias))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        };
        Ok(Some(TurnUsageObservation {
            usage_ref: usage_ref.to_owned(),
            input_tokens: tokens("input_tokens", "prompt_tokens"),
            output_tokens: tokens("output_tokens", "completion_tokens"),
            last_input_tokens: usage
                .get("last_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        }))
    }

    fn ensure_evidence(
        &self,
        command: &StartTurnCommand,
        run_id: &str,
        kind: &str,
        metadata_json: &str,
    ) -> Result<String, HostRuntimeError> {
        let existing = self
            .kernel
            .store()
            .list_evidence_for_subject("run", run_id)
            .map_err(HostRuntimeError::Store)?;
        if let Some(evidence) = existing.iter().find(|evidence| {
            evidence.kind == kind && evidence.correlation_id.as_deref() == Some(&command.command_id)
        }) {
            return Ok(evidence.evidence_id.clone());
        }
        self.kernel
            .store()
            .record_evidence(EvidenceRecord {
                instance_id: &command.instance_ref,
                kind,
                subject_type: "run",
                subject_id: run_id,
                causation_id: Some(&command.command_id),
                correlation_id: Some(&command.command_id),
                summary: None,
                metadata_json,
            })
            .map_err(HostRuntimeError::Store)
    }

    fn project_events(
        &self,
        command: &StartTurnCommand,
        run_id: &str,
    ) -> Result<Vec<LabeledRuntimeEvent>, HostRuntimeError> {
        let evidence = self
            .kernel
            .store()
            .list_evidence_for_subject("run", run_id)
            .map_err(HostRuntimeError::Store)?;
        let existing_events = self
            .kernel
            .store()
            .list_events(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        // One parse pass over the instance log instead of re-parsing every prior
        // `host.turn.evidence` payload once per evidence item. First writer wins,
        // matching the `find` this replaces; an unparseable payload is skipped
        // exactly as the old `.ok()` did.
        let mut projected_before: HashMap<String, i64> = HashMap::new();
        for event in &existing_events {
            if event.event_type != "host.turn.evidence" {
                continue;
            }
            let Ok(payload) = serde_json::from_str::<Value>(&event.payload_json) else {
                continue;
            };
            if payload.get("command_id").and_then(Value::as_str)
                != Some(command.command_id.as_str())
            {
                continue;
            }
            let Some(existing_ref) = payload.get("evidence_ref").and_then(Value::as_str) else {
                continue;
            };
            projected_before
                .entry(existing_ref.to_owned())
                .or_insert(event.sequence);
        }
        let mut projected = Vec::with_capacity(evidence.len());
        for item in evidence {
            let evidence_ref = format!("whip:evidence:{}", item.evidence_id);
            if let Some(existing) = projected_before.get(evidence_ref.as_str()).copied() {
                projected.push(LabeledRuntimeEvent {
                    protocol: HOST_PROTOCOL.to_owned(),
                    command_id: command.command_id.clone(),
                    position: EventPosition {
                        instance_ref: command.instance_ref.clone(),
                        sequence: positive_sequence(existing)?,
                    },
                    policy: command.policy.clone(),
                    kind: item.kind,
                    label_ref: self.label_ref(),
                    evidence_ref,
                    payload_ref: None,
                });
                continue;
            }
            let payload = json!({
                "command_id": command.command_id,
                "kind": item.kind,
                "label_ref": self.label_ref(),
                "evidence_ref": evidence_ref,
            })
            .to_string();
            let event = self
                .kernel
                .store()
                .append_event(NewEvent {
                    instance_id: &command.instance_ref,
                    event_type: "host.turn.evidence",
                    payload_json: &payload,
                    source: "host-runtime",
                    causation_id: Some(run_id),
                    correlation_id: Some(&command.command_id),
                    idempotency_key: Some(&idempotency_key(&[
                        &command.instance_ref,
                        &command.command_id,
                        &item.evidence_id,
                        "host-evidence-projection",
                    ])),
                })
                .map_err(HostRuntimeError::Store)?;
            projected.push(LabeledRuntimeEvent {
                protocol: HOST_PROTOCOL.to_owned(),
                command_id: command.command_id.clone(),
                position: EventPosition {
                    instance_ref: command.instance_ref.clone(),
                    sequence: positive_sequence(event.sequence)?,
                },
                policy: command.policy.clone(),
                kind: item.kind,
                label_ref: self.label_ref(),
                evidence_ref,
                payload_ref: None,
            });
        }
        Ok(projected)
    }

    fn stored_turn_receipt(
        &self,
        command: &StartTurnCommand,
    ) -> Result<Option<TurnReceipt>, HostRuntimeError> {
        command.validate()?;
        self.require_policy(&command.policy)?;
        let events = self
            .kernel
            .store()
            .list_events(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let Some(marker) = events.iter().rev().find(|event| {
            event.event_type == "host.turn.receipt"
                && serde_json::from_str::<Value>(&event.payload_json)
                    .ok()
                    .and_then(|value| {
                        value
                            .get("command_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(&command.command_id)
        }) else {
            return Ok(None);
        };
        let value: Value =
            serde_json::from_str(&marker.payload_json).map_err(HostRuntimeError::Json)?;
        let receipt = TurnReceipt {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: command.command_id.clone(),
            run_ref: required_string(&value, "run_ref")?,
            instance_ref: command.instance_ref.clone(),
            policy: command.policy.clone(),
            terminal_position: EventPosition {
                instance_ref: command.instance_ref.clone(),
                sequence: positive_sequence(marker.sequence)?,
            },
            status: serde_json::from_value(value["status"].clone())
                .map_err(HostRuntimeError::Json)?,
            output_handle: value
                .get("output_handle")
                .and_then(Value::as_str)
                .map(str::to_owned),
            usage_ref: required_string(&value, "usage_ref")?,
            guarantee_report_ref: required_string(&value, "guarantee_report_ref")?,
            workspace_cut_ref: value
                .get("workspace_cut_ref")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        receipt.validate_for(command)?;
        let Some(effect) = self
            .kernel
            .store()
            .list_effects(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?
            .into_iter()
            .find(|effect| effect.effect_id == command.command_id)
        else {
            let reason = "retained turn has no original command";
            // MUTATION-SUCCESS-EXPR: Ok(None)
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(reason)));
        };
        validate_recorded_turn_input(&effect, command)?;
        if !is_terminal_effect(&effect.status) {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "retained turn command is not terminal",
            )));
        }
        Ok(Some(receipt))
    }

    fn stored_execution(
        &self,
        command: &StartTurnCommand,
    ) -> Result<Option<TurnExecution>, HostRuntimeError> {
        let Some(receipt) = self.stored_turn_receipt(command)? else {
            return Ok(None);
        };
        let events = self
            .kernel
            .store()
            .list_events(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let mut projected = Vec::new();
        for event in events {
            if event.event_type != "host.turn.evidence" {
                continue;
            }
            let payload: Value =
                serde_json::from_str(&event.payload_json).map_err(HostRuntimeError::Json)?;
            if payload.get("command_id").and_then(Value::as_str)
                != Some(command.command_id.as_str())
            {
                continue;
            }
            projected.push(LabeledRuntimeEvent {
                protocol: HOST_PROTOCOL.to_owned(),
                command_id: command.command_id.clone(),
                position: EventPosition {
                    instance_ref: command.instance_ref.clone(),
                    sequence: positive_sequence(event.sequence)?,
                },
                policy: command.policy.clone(),
                kind: required_string(&payload, "kind")?,
                label_ref: required_string(&payload, "label_ref")?,
                evidence_ref: required_string(&payload, "evidence_ref")?,
                payload_ref: None,
            });
        }
        let output = self.project_turn_output(command, receipt.output_handle.clone())?;
        let usage = self.project_turn_usage(command, &receipt.usage_ref)?;
        Ok(Some(TurnExecution {
            events: projected,
            receipt: Some(receipt),
            output,
            usage,
        }))
    }

    fn project_turn_output(
        &self,
        command: &StartTurnCommand,
        output_handle: Option<String>,
    ) -> Result<Option<LabeledTurnOutput>, HostRuntimeError> {
        let events = self
            .kernel
            .store()
            .list_events(&command.instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let Some(checkpoint) = events.iter().rev().find(|event| {
            event.event_type == "agent.turn.brokered.transcript"
                && serde_json::from_str::<Value>(&event.payload_json)
                    .ok()
                    .and_then(|payload| {
                        payload
                            .get("effect_id")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(&command.command_id)
        }) else {
            return Ok(None);
        };
        let value: Value =
            serde_json::from_str(&checkpoint.payload_json).map_err(HostRuntimeError::Json)?;
        let messages = whipplescript_kernel::harness_loop::chat_messages_from_json(
            value.get("messages").unwrap_or(&Value::Null),
        );
        let turn_start = messages
            .iter()
            .rposition(|message| matches!(message, ChatMessage::User { .. }))
            .map_or(0, |index| index + 1);
        let mut assistant_text = String::new();
        // Answer text spoken alongside tool calls. A provider may put the
        // user-facing reply on the same message as its calls and close the
        // turn with an empty final message; dropping that text projected a
        // completed turn as a blank reply. A closing text-only message still
        // wins — this is only the projection's floor, never its override.
        let mut text_with_calls = String::new();
        let mut tool_calls: Vec<ProjectedToolCall> = Vec::new();
        // The same content, kept in the order the turn produced it. Every prose
        // run is retained here (the folded `assistant_text` keeps only the last),
        // each in the position it was spoken relative to the calls it introduced.
        let mut segments: Vec<TurnContentSegment> = Vec::new();
        for message in &messages[turn_start..] {
            match message {
                ChatMessage::Assistant {
                    text,
                    tool_calls: calls,
                } => {
                    if !text.is_empty() {
                        segments.push(TurnContentSegment::Prose(text.clone()));
                    }
                    if calls.is_empty() {
                        if !text.is_empty() {
                            assistant_text.clone_from(text);
                        }
                    } else {
                        if !text.is_empty() {
                            text_with_calls.clone_from(text);
                        }
                        for call in calls {
                            let projected = ProjectedToolCall {
                                call_id: call.id.clone(),
                                name: call.name.clone(),
                                arguments: call.arguments.clone(),
                                result: None,
                                ok: None,
                            };
                            tool_calls.push(projected.clone());
                            segments.push(TurnContentSegment::Tool(projected));
                        }
                    }
                }
                ChatMessage::ToolResults(results) => {
                    for result in results {
                        if let Some(projected) = tool_calls
                            .iter_mut()
                            .rev()
                            .find(|call| call.call_id == result.tool_call_id)
                        {
                            projected.result = Some(result.content.clone());
                            projected.ok = Some(!result.is_error);
                        }
                        // Correlate the same result into its ordered segment.
                        // Most-recent-match, exactly as the folded list above.
                        for segment in segments.iter_mut().rev() {
                            if let TurnContentSegment::Tool(call) = segment {
                                if call.call_id == result.tool_call_id {
                                    call.result = Some(result.content.clone());
                                    call.ok = Some(!result.is_error);
                                    break;
                                }
                            }
                        }
                    }
                }
                ChatMessage::System(_) | ChatMessage::Developer(_) | ChatMessage::User { .. } => {}
            }
        }
        if assistant_text.is_empty() {
            assistant_text = text_with_calls;
        }
        Ok(Some(LabeledTurnOutput {
            output_handle,
            label_ref: self.label_ref(),
            assistant_text,
            tool_calls,
            segments,
            flow_signature: certified_output_flow(command),
        }))
    }

    fn require_policy(&self, policy: &PolicyEpochRef) -> Result<(), HostRuntimeError> {
        if policy == &self.policy {
            Ok(())
        } else {
            Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "runtime policy epoch",
            )))
        }
    }

    fn require_governed(&self, handle: &str) -> Result<(), HostRuntimeError> {
        if self.envelope.governs(handle) {
            Ok(())
        } else {
            Err(HostRuntimeError::UngovernedHandle(handle.to_owned()))
        }
    }

    fn check_package_ifc(&self, package: &ResolvedPackage) -> Result<(), HostRuntimeError> {
        let diagnostics = crate::ifc::check_with_envelope(&package.program, &self.envelope);
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(HostRuntimeError::Ifc(
                diagnostics
                    .into_iter()
                    .map(|diagnostic| diagnostic.message)
                    .collect(),
            ))
        }
    }

    fn check_principal_ceiling(
        &self,
        package: &ResolvedPackage,
        actor_ref: &str,
    ) -> Result<(), HostRuntimeError> {
        let diagnostics = crate::ifc::check_principal_ceiling_for_identity(
            &package.program,
            &self.envelope,
            actor_ref,
        );
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(HostRuntimeError::Ifc(
                diagnostics
                    .into_iter()
                    .map(|diagnostic| diagnostic.message)
                    .collect(),
            ))
        }
    }

    fn label_ref(&self) -> String {
        format!("whip:label:{}:turn-join", self.policy.envelope_hash)
    }
}

fn certified_output_flow(command: &StartTurnCommand) -> Vec<CertifiedOutputFieldFlow> {
    let mut reads = command.resources.clone();
    reads.extend(command.input.images.iter().cloned());
    reads.sort_by(|left, right| {
        (&left.handle, &left.kind, &left.selector, &left.writable).cmp(&(
            &right.handle,
            &right.kind,
            &right.selector,
            &right.writable,
        ))
    });
    reads.dedup();
    ["assistant_text", "tool_calls"]
        .into_iter()
        .map(|field| CertifiedOutputFieldFlow {
            field: field.to_owned(),
            reads: reads.clone(),
        })
        .collect()
}

#[derive(Debug, Serialize, Deserialize)]
struct InstanceMetadata {
    protocol: String,
    package_version_ref: String,
    policy: PolicyEpochRef,
}

/// What a fork or an adoption seeds its target from, once the source's
/// identity, policy binding and quiescence have been answered.
struct SeedSource {
    instance: whipplescript_store::InstanceView,
    metadata: InstanceMetadata,
    /// The coordinate the thread is read at: the host's, or an adoption's cut.
    position: EventPosition,
    cut: Option<AdoptionCut>,
}

impl SeedSource {
    /// Name on the fork record what an adoption did beyond an ordinary fork:
    /// the earlier epoch it carried the thread from, and the cut it took. An
    /// ordinary fork's record is unchanged, so a replay of an older record
    /// still matches it exactly.
    fn record_on(&self, payload: &mut Value, command: &ForkInstanceCommand) {
        if self.metadata.policy != command.policy {
            payload["source_policy"] = json!(self.metadata.policy);
        }
        if let Some(cut) = &self.cut {
            payload["cut"] = json!(cut);
            payload["unresolved_outcome"] = json!("unknown");
        }
    }
}

/// Whether a recorded event's payload names `effect_id` as its own effect or
/// as one it commits.
fn event_names_effect(payload_json: &str, effect_id: &str) -> bool {
    let Ok(payload) = serde_json::from_str::<Value>(payload_json) else {
        return false;
    };
    payload.get("effect_id").and_then(Value::as_str) == Some(effect_id)
        || payload
            .get("effects")
            .and_then(Value::as_array)
            .is_some_and(|effects| {
                effects.iter().any(|effect| {
                    effect.get("effect_id").and_then(Value::as_str) == Some(effect_id)
                })
            })
}

fn validate_recorded_turn_input(
    effect: &whipplescript_store::EffectView,
    command: &StartTurnCommand,
) -> Result<(), HostRuntimeError> {
    let original = serde_json::to_string(command).map_err(HostRuntimeError::Json)?;
    if effect.kind != "agent.tell" || effect.input_json != original {
        return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
            "command id reused with different turn",
        )));
    }
    Ok(())
}

const LIVE_ACCESS_REFUSED: &str = "host turn access ended";

fn admit_reused_turn<R: ResourceResolver + ?Sized>(
    command: &StartTurnCommand,
    resources: &R,
    reuse: &mut dyn FnMut() -> Result<(), HostRuntimeError>,
) -> Result<(), HostRuntimeError> {
    let mut invoked = false;
    let mut succeeded = false;
    let mut duplicate = false;
    let mut once = || {
        if invoked {
            duplicate = true;
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "turn reuse admission invoked twice",
            )));
        }
        invoked = true;
        reuse()?;
        succeeded = true;
        Ok(())
    };
    resources.with_turn_reuse_admission(command, &mut once)?;
    if !succeeded || duplicate {
        return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
            "turn reuse admission omitted or repeated exact reuse",
        )));
    }
    Ok(())
}

struct LiveTurnAccess<'a, R: ResourceResolver + ?Sized> {
    resources: &'a R,
    refused: std::cell::Cell<bool>,
}
impl<'a, R: ResourceResolver + ?Sized> LiveTurnAccess<'a, R> {
    fn new(resources: &'a R) -> Self {
        Self {
            resources,
            refused: std::cell::Cell::new(false),
        }
    }
    fn check(&self) -> Result<(), HostRuntimeError> {
        if self.refused.get() || self.resources.check_live_access().is_err() {
            self.refused.set(true);
            return Err(HostRuntimeError::Resolver(LIVE_ACCESS_REFUSED.into()));
        }
        Ok(())
    }
}

struct LiveAccessDriver<'a, R: ResourceResolver + ?Sized, H: HostDriver> {
    inner: &'a H,
    access: &'a LiveTurnAccess<'a, R>,
}
impl<R: ResourceResolver + ?Sized, H: HostDriver> HostDriver for LiveAccessDriver<'_, R, H> {
    fn fulfill(&self, request: &IoRequest) -> IoResult {
        if self.access.check().is_err() {
            return IoResult::Http(Err(TransportError::Transport(LIVE_ACCESS_REFUSED.into())));
        }
        let result = self.inner.fulfill(request);
        if self.access.check().is_err() {
            return IoResult::Http(Err(TransportError::Transport(LIVE_ACCESS_REFUSED.into())));
        }
        result
    }
}

struct ResolverToolExecutor<'a, R: ResourceResolver + ?Sized> {
    offered: &'a [ToolSpec],
    admitted_resources: &'a [ResourceRef],
    resolver: &'a R,
    access: &'a LiveTurnAccess<'a, R>,
}

impl<R: ResourceResolver + ?Sized> ToolExecutor for ResolverToolExecutor<'_, R> {
    fn take_workspace_reads(&self) -> Vec<whipplescript_kernel::whip_shell::ShellRead> {
        self.resolver.take_workspace_reads()
    }

    fn model_output_provenance(
        &self,
        call: &ToolCall,
    ) -> whipplescript_kernel::sansio::ModelContentProvenance {
        self.resolver
            .model_output_provenance(self.admitted_resources, call)
    }

    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if !self.offered.iter().any(|tool| tool.name == call.name) {
            return ToolOutcome {
                status: ToolStatus::Error,
                content: "tool is not declared by the pinned package".to_owned(),
            };
        }
        if self.access.check().is_err() {
            return ToolOutcome {
                status: ToolStatus::Error,
                content: LIVE_ACCESS_REFUSED.into(),
            };
        }
        let result = self.resolver.execute_tool(self.admitted_resources, call);
        if self.access.check().is_err() {
            return ToolOutcome {
                status: ToolStatus::Error,
                content: LIVE_ACCESS_REFUSED.into(),
            };
        }
        match result {
            Ok(content) => ToolOutcome {
                status: ToolStatus::Ok,
                content,
            },
            Err(message) => ToolOutcome {
                status: ToolStatus::Error,
                content: message,
            },
        }
    }
}

type ModelRequestObserver<'a> =
    dyn Fn(&Value, Option<&whipplescript_kernel::sansio::ModelRequestProvenance>) + 'a;

type NativeRequestAdmission<'a> = dyn Fn(
        &NativeProviderRequest<'_>,
        &mut dyn FnMut(Duration) -> Result<(), String>,
    ) -> Result<(), String>
    + 'a;

struct TurnRunInspection<'a> {
    stream_released: Option<&'a dyn Fn() -> bool>,
    model_provenance: &'a whipplescript_kernel::sansio::InitialModelProvenance,
}

struct NativeHttpDriver<'a> {
    agent: ureq::Agent,
    admitted_request_url: Option<String>,
    /// Live `streaming_output` projection out of an active turn (the
    /// `ResourceResolver::observe_text_delta` seam). `None` observes nothing
    /// and reads the body exactly as before.
    delta_sink: Option<&'a dyn Fn(&str)>,
    /// Cooperative cancellation probe consulted between streamed lines
    /// (spec/agent-harness.md "Cancellation"). `true` releases the stream at a
    /// complete-line boundary: the lines that fully arrived feed the same
    /// assembly as a naturally ended body, and the machine settles the round
    /// cancelled through its paired release probe. `None` reads to the end
    /// exactly as before.
    cancel_probe: Option<&'a dyn Fn() -> bool>,
    request_observer: Option<&'a ModelRequestObserver<'a>>,
    request_admission: Option<(&'a StartTurnCommand, &'a NativeRequestAdmission<'a>)>,
    request_ordinal: std::cell::Cell<u64>,
    admission_ended: std::cell::Cell<bool>,
    timeout: Duration,
}

impl<'a> NativeHttpDriver<'a> {
    fn new(timeout: Duration) -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(timeout)
                // A governed provider binding names the exact egress endpoint.
                // Following a provider-controlled redirect would widen that
                // capability (and could replay prompt content to another host),
                // so redirects fail closed and must be resolved by the host.
                .redirects(0)
                .user_agent("whipplescript-host-runtime")
                .build(),
            admitted_request_url: None,
            delta_sink: None,
            cancel_probe: None,
            request_observer: None,
            request_admission: None,
            request_ordinal: std::cell::Cell::new(0),
            admission_ended: std::cell::Cell::new(false),
            timeout,
        }
    }

    fn for_binding(binding: &ResolvedProviderBinding) -> Result<Self, HostRuntimeError> {
        let mut driver = Self::new(binding.timeout);
        if let Some(transport) = &binding.transport {
            let (agent, request_url) =
                transport.agent(binding.provider, &binding.base_url, binding.timeout)?;
            driver.agent = agent;
            driver.admitted_request_url = Some(request_url);
        }
        Ok(driver)
    }

    fn with_delta_sink(mut self, sink: &'a dyn Fn(&str)) -> Self {
        self.delta_sink = Some(sink);
        self
    }

    fn with_cancel_probe(mut self, probe: &'a dyn Fn() -> bool) -> Self {
        self.cancel_probe = Some(probe);
        self
    }

    fn with_request_observer(
        mut self,
        observer: &'a dyn Fn(&Value, Option<&whipplescript_kernel::sansio::ModelRequestProvenance>),
    ) -> Self {
        self.request_observer = Some(observer);
        self
    }

    fn with_request_admission(
        mut self,
        command: &'a StartTurnCommand,
        admit: &'a NativeRequestAdmission<'a>,
    ) -> Self {
        self.request_admission = Some((command, admit));
        self
    }

    fn send_request(
        &self,
        request: &whipplescript_kernel::sansio::HttpRequest,
        timeout: Duration,
    ) -> Result<ureq::Response, TransportError> {
        let mut builder = self.agent.post(&request.url).timeout(timeout);
        for (name, value) in &request.headers {
            builder = builder.set(name, value);
        }
        match builder.send_json(&request.body) {
            Ok(response) | Err(ureq::Error::Status(_, response)) => Ok(response),
            Err(ureq::Error::Transport(error)) => {
                let message = error.to_string();
                Err(if message.to_ascii_lowercase().contains("timeout") {
                    TransportError::Timeout
                } else {
                    TransportError::Transport(message)
                })
            }
        }
    }

    fn admitted_send(
        &self,
        request: &whipplescript_kernel::sansio::HttpRequest,
    ) -> Result<ureq::Response, TransportError> {
        const REFUSED: &str = "native provider request admission refused";
        let Some((command, admit)) = self.request_admission else {
            return self.send_request(request, self.timeout);
        };
        let Some(ordinal) = self.request_ordinal.get().checked_add(1) else {
            self.admission_ended.set(true);
            return Err(TransportError::Transport(REFUSED.into()));
        };
        self.request_ordinal.set(ordinal);
        let metadata = NativeProviderRequest {
            command,
            ordinal,
            url: &request.url,
            body: &request.body,
            provenance: request.model_provenance.as_ref(),
            transport_pinned: self.admitted_request_url.is_some(),
            configured_timeout: self.timeout,
        };
        let mut attempted = false;
        let mut invalid = false;
        let mut outcome = None;
        let mut send = |timeout: Duration| {
            if attempted || timeout.is_zero() || timeout > self.timeout {
                invalid = true;
                return Err(REFUSED.to_owned());
            }
            attempted = true;
            outcome = Some(self.send_request(request, timeout));
            // The host controls admission, never the actual transport outcome.
            Ok(())
        };
        let admission = admit(&metadata, &mut send);
        if admission.is_err() || invalid || !attempted {
            self.admission_ended.set(true);
            return Err(TransportError::Transport(REFUSED.into()));
        }
        outcome.expect("a permitted one-use send retains its actual outcome")
    }

    /// Read an SSE body to its end, projecting each assistant answer-text
    /// delta into the live sink as its line arrives. The returned raw body
    /// feeds the same whole-body assembly as before — the sink observes the
    /// stream, it never interprets it, so the assembled result cannot differ
    /// from the unobserved read. Parity with `into_string`: a body past the
    /// same 10 MiB ceiling is dropped whole. A mid-stream transport failure
    /// keeps the lines that fully arrived — the assembler reads only complete
    /// `data:` lines, so a truncated tail cannot half-parse.
    fn read_sse_body(&self, response: ureq::Response) -> String {
        const BODY_LIMIT: usize = 10 * 1_024 * 1_024;
        let mut reader = std::io::BufReader::new(response.into_reader());
        let mut raw = String::new();
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::BufRead::read_line(&mut reader, &mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if raw.len() + line.len() > BODY_LIMIT {
                        return String::new();
                    }
                    if let Some(sink) = self.delta_sink {
                        if let Some(delta) = sse_output_text_delta(&line) {
                            sink(&delta);
                        }
                    }
                    raw.push_str(&line);
                    // Cooperative cancel: release the stream at this
                    // complete-line boundary. The truncated tail cannot
                    // half-parse (the assembler reads only complete `data:`
                    // lines), so what has arrived assembles exactly as a
                    // naturally ended body would. A stalled stream is not
                    // released here — `read_line` blocks until the agent's
                    // whole-call timeout bounds it.
                    if self.cancel_probe.is_some_and(|probe| probe()) {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        raw
    }
}

/// The one SSE event type whose payload is user-visible answer text.
/// Reasoning deltas arrive as different event types and are deliberately
/// never projected (spec/agent-harness.md "Live Turn Observation").
fn sse_output_text_delta(line: &str) -> Option<String> {
    let payload = line.trim().strip_prefix("data:")?.trim();
    if payload.is_empty() || payload == "[DONE]" {
        return None;
    }
    let event = serde_json::from_str::<Value>(payload).ok()?;
    match event.get("type").and_then(Value::as_str) {
        Some("response.output_text.delta") => event
            .get("delta")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Some("content_block_delta") if event["delta"]["type"] == "text_delta" => event
            .pointer("/delta/text")
            .and_then(Value::as_str)
            .map(str::to_owned),
        None => event
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

impl HostDriver for NativeHttpDriver<'_> {
    fn fulfill(&self, request: &IoRequest) -> IoResult {
        let IoRequest::Http(request) = request;
        if self.admission_ended.get() {
            return IoResult::Http(Err(TransportError::Transport(
                "native provider request admission refused".into(),
            )));
        }
        if self
            .admitted_request_url
            .as_ref()
            .is_some_and(|url| url != &request.url)
        {
            return IoResult::Http(Err(TransportError::Transport(
                "admitted provider request refused".into(),
            )));
        }
        if let Some(observer) = self.request_observer {
            observer(&request.body, request.model_provenance.as_ref());
        }
        let response = match self.admitted_send(request) {
            Ok(response) => response,
            Err(error) => return IoResult::Http(Err(error)),
        };
        let expects_sse = request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("accept") && value == "text/event-stream"
        });
        let status = response.status();
        let body = if expects_sse && (200..300).contains(&status) {
            assemble_native_sse(&request.url, &self.read_sse_body(response))
        } else {
            response.into_json::<Value>().unwrap_or(Value::Null)
        };
        IoResult::Http(Ok(HttpResponse { status, body }))
    }
}

/// The native transport receives three provider stream dialects. Choose the
/// assembler from the governed request URL so a Chat Completions or Messages
/// stream is not silently interpreted as an empty Responses reply.
fn assemble_native_sse(url: &str, raw: &str) -> Value {
    let path = url.split('?').next().unwrap_or(url);
    if path.ends_with("/chat/completions") {
        whipplescript_kernel::harness_model::assemble_openai_chat_sse(raw)
    } else if path.ends_with("/messages") {
        whipplescript_kernel::harness_model::assemble_anthropic_messages_sse(raw)
    } else {
        assemble_responses_sse(raw)
    }
}

fn assemble_responses_sse(raw: &str) -> Value {
    let mut completed: Option<Value> = None;
    let mut deltas = String::new();
    let mut done_items: Vec<Value> = Vec::new();
    for line in raw.lines() {
        let Some(payload) = line.trim().strip_prefix("data:") else {
            continue;
        };
        let payload = payload.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        let Ok(event) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        match event.get("type").and_then(Value::as_str) {
            Some("response.completed") => completed = event.get("response").cloned(),
            Some("response.output_text.delta") => {
                if let Some(delta) = event.get("delta").and_then(Value::as_str) {
                    deltas.push_str(delta);
                }
            }
            // The codex backend's `response.completed` payload often carries an
            // EMPTY `output[]`; the real items — function calls included — are
            // delivered only as per-item `response.output_item.done` events.
            // Collect them so a tool-calling turn survives assembly (verified
            // against the live backend 2026-07-10: a `write` call arrived
            // exclusively through these events).
            Some("response.output_item.done") => {
                if let Some(item) = event.get("item") {
                    done_items.push(item.clone());
                }
            }
            _ => {}
        }
    }
    let mut response = completed.unwrap_or_else(|| json!({}));
    let output_missing = response
        .get("output")
        .and_then(Value::as_array)
        .map(|output| output.is_empty())
        .unwrap_or(true);
    if output_missing && !done_items.is_empty() {
        response["output"] = Value::Array(done_items);
    }
    if !deltas.is_empty() {
        response["output_text"] = Value::String(deltas);
    }
    response
}

#[derive(Debug)]
pub enum HostRuntimeError {
    Protocol(ProtocolError),
    PolicyRejected(String),
    UngovernedHandle(String),
    Ifc(Vec<String>),
    UnknownInstance(String),
    Incomplete(String),
    HomeJournal(String),
    Resolver(String),
    Store(StoreError),
    Json(serde_json::Error),
}

fn home_journal_error(error: HostFacadeError) -> HostRuntimeError {
    HostRuntimeError::HomeJournal(error.to_string())
}

fn require_home_store_incarnation(store: &SqliteStore) -> Result<String, HostRuntimeError> {
    whipplescript_kernel::host_facade::require_home_store_incarnation(store)
        .map_err(home_journal_error)
}

fn require_same_home_store_incarnation(
    store: &SqliteStore,
    expected: &str,
) -> Result<(), HostRuntimeError> {
    whipplescript_kernel::host_facade::require_same_home_store_incarnation(store, expected)
        .map_err(home_journal_error)
}

impl fmt::Display for HostRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::PolicyRejected(message) => write!(formatter, "policy rejected: {message}"),
            Self::UngovernedHandle(handle) => {
                write!(formatter, "host handle is not governed: {handle}")
            }
            Self::Ifc(diagnostics) => write!(
                formatter,
                "package violates the admitted information-flow policy: {}",
                diagnostics.join("; ")
            ),
            Self::UnknownInstance(instance) => write!(formatter, "unknown instance: {instance}"),
            Self::Incomplete(command) => write!(formatter, "turn is not terminal: {command}"),
            Self::HomeJournal(message) => {
                write!(formatter, "Home reference journal refused: {message}")
            }
            Self::Resolver(message) => write!(formatter, "host resolver refused: {message}"),
            Self::Store(error) => write!(formatter, "runtime store error: {error:?}"),
            Self::Json(error) => write!(formatter, "runtime JSON error: {error}"),
        }
    }
}

impl std::error::Error for HostRuntimeError {}

impl From<ProtocolError> for HostRuntimeError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

fn validate_package(package: &ResolvedPackage, expected_ref: &str) -> Result<(), HostRuntimeError> {
    if package.version_ref != expected_ref {
        return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
            "resolved package ref",
        )));
    }
    if package.source_hash.trim().is_empty()
        || package.ir_hash.trim().is_empty()
        || package.agent.trim().is_empty()
        || package.max_steps == 0
        || !package
            .program
            .agents
            .iter()
            .any(|agent| agent.name == package.agent)
    {
        return Err(HostRuntimeError::Resolver(
            "resolved package is incomplete".to_owned(),
        ));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Hash the executable that contains the native compiler used by this host.
/// Linux keeps the running inode reachable through /proc/self/exe even if its
/// pathname is replaced while an admission is in progress.
pub fn native_compiler_artifact_digest() -> Result<String, String> {
    static DIGEST: OnceLock<Result<String, String>> = OnceLock::new();
    DIGEST
        .get_or_init(|| {
            #[cfg(target_os = "linux")]
            let path = PathBuf::from("/proc/self/exe");
            #[cfg(not(target_os = "linux"))]
            let path = std::env::current_exe()
                .map_err(|error| format!("locate native compiler artifact: {error}"))?;
            let bytes = fs::read(&path).map_err(|error| {
                format!(
                    "read native compiler artifact `{}`: {error}",
                    path.display()
                )
            })?;
            Ok(sha256_hex(&bytes))
        })
        .clone()
}

fn positive_sequence(sequence: i64) -> Result<u64, HostRuntimeError> {
    u64::try_from(sequence)
        .ok()
        .filter(|sequence| *sequence > 0)
        .ok_or(HostRuntimeError::Protocol(ProtocolError::Invalid(
            "runtime event sequence must be positive",
        )))
}

fn required_string(value: &Value, key: &'static str) -> Result<String, HostRuntimeError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
        .ok_or(HostRuntimeError::Protocol(ProtocolError::Invalid(key)))
}

fn is_terminal_effect(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "timed_out" | "cancelled")
}

fn turn_status(status: &str) -> Result<TurnStatus, HostRuntimeError> {
    match status {
        "completed" => Ok(TurnStatus::Completed),
        "failed" => Ok(TurnStatus::Failed),
        "timed_out" => Ok(TurnStatus::TimedOut),
        "cancelled" => Ok(TurnStatus::Cancelled),
        _ => Err(HostRuntimeError::Incomplete(status.to_owned())),
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        encoded.push(ALPHABET[(a >> 2) as usize] as char);
        encoded.push(ALPHABET[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        encoded.push(if chunk.len() > 1 {
            ALPHABET[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        encoded.push(if chunk.len() > 2 {
            ALPHABET[(c & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    encoded
}

/// The effect kinds that ship context to a model, and therefore the ones custody
/// evidence is keyed by (DR-0062 §6). Both are checked: an endpoint delegated
/// read-authority must clear the demand wherever it is used, and `schema.coerce`
/// is as real a door as `agent.tell`.
pub const MODEL_EGRESS_EFFECT_KINDS: [&str; 2] = ["agent.tell", "schema.coerce"];

/// The effect kind an unqualified `whip provider` command defaults to.
pub const AGENT_TURN_EFFECT_KIND: &str = "agent.tell";

/// What the registry currently supports for one model endpoint.
pub struct ResolvedProviderTrust {
    pub derived: whipplescript_kernel::provider_trust::DerivedTrust,
    pub row: whipplescript_store::ProviderTrustRow,
    /// The endpoint's digest as computed NOW. `None` when the registry has no
    /// config for it at all.
    pub live_digest: Option<String>,
}

/// Resolve an endpoint's rung and custody class from registry evidence.
///
/// Resolution, not storage, decides freshness: the live digest is recomputed
/// here from the endpoint's current `effect_providers` config, so a deployment
/// that moved under a pin is caught rather than vouched for by a stale row.
///
/// An endpoint the registry has never heard of resolves to no config and
/// therefore no live digest, which cannot match any pin -- it lands at the floor.
/// That is the fail-closed direction: a delegation naming an endpoint whip
/// cannot identify must not pass.
pub fn resolve_provider_trust(
    store: &SqliteStore,
    provider: &str,
    effect_kind: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<ResolvedProviderTrust, whipplescript_store::StoreError> {
    use whipplescript_kernel::provider_trust::{
        derive, endpoint_digest, evidence_from_registry, RegistryEvidence,
    };
    let live_digest = store
        .effect_provider_config(effect_kind, provider)?
        .map(|config| endpoint_digest(&config));
    let row = store
        .provider_trust_evidence(effect_kind, provider)?
        .unwrap_or_default();
    let evidence = evidence_from_registry(
        RegistryEvidence {
            pinned_digest: row.pinned_digest.as_deref(),
            claim_class: row.claim_class.as_deref(),
            claim_signer: row.claim_signer.as_deref(),
            claim_expires_at: row.claim_expires_at.as_deref(),
            operator_run: row.operator_run,
        },
        live_digest.as_deref(),
        now,
    );
    Ok(ResolvedProviderTrust {
        derived: derive(&evidence),
        row,
        live_digest,
    })
}

/// Refuse a policy whose model-endpoint delegations out-run their evidence
/// (DR-0062 §4). The envelope carries the demand and the store carries the
/// evidence, so the refusal lands at policy-load time rather than at the first
/// turn that would have leaked.
fn refuse_inadmissible_provider_delegations(
    store: &SqliteStore,
    envelope: &VerifiedEnvelope,
) -> Result<(), HostRuntimeError> {
    use whipplescript_kernel::provider_trust::delegation_admissible;

    let now = chrono::Utc::now();
    for (provider, role) in envelope.provider_delegations() {
        let Some(demand) = envelope.custody_demand_for(role) else {
            // No demand declared for this role: unconstrained, and an
            // unattested endpoint keeps working (public-only).
            continue;
        };
        // Every effect kind this endpoint serves must clear the demand. An
        // endpoint registered for both `agent.tell` and `schema.coerce` is two
        // registrations with their own config, so they can be different
        // deployments and each carries its own evidence.
        let mut kinds = store
            .list_provider_effect_kinds(provider)
            .map_err(HostRuntimeError::Store)?;
        kinds.retain(|kind| MODEL_EGRESS_EFFECT_KINDS.contains(&kind.as_str()));
        if kinds.is_empty() {
            // Registered for nothing whip can identify: the floor, and refused.
            // A delegation naming an endpoint that does not exist must not pass
            // merely because there was no row to judge.
            kinds.push(AGENT_TURN_EFFECT_KIND.to_owned());
        }
        for kind in kinds {
            let resolved = resolve_provider_trust(store, provider, &kind, now)
                .map_err(HostRuntimeError::Store)?;
            if let Err(denial) = delegation_admissible(&resolved.derived, Some(demand)) {
                return Err(HostRuntimeError::PolicyRejected(format!(
                    "{} (effect kind `{kind}`)",
                    denial.message(provider, role)
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod refusal_pin_tests {
    //! Refusals the workspace resolver carries that nothing exercised until the
    //! sweep's widened site matching (#309) attributed them to a change that
    //! threaded a parameter past them. True of the refusals, not of the change.

    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn scratch(label: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "whip-refusal-pin-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&path).expect("scratch dir");
        path
    }

    #[test]
    fn a_workspace_capability_root_that_is_a_file_is_refused() {
        // `canonicalize` succeeds on a file, so without this check the resolver
        // would hold a "root" that can never contain anything and would fail
        // later, somewhere less obvious.
        let base = scratch("root-is-file");
        let file = base.join("not-a-directory");
        fs::write(&file, "").expect("write");

        let error = match NativeWorkspaceResolver::new(&file) {
            Err(error) => error,
            Ok(_) => panic!("a file is not a workspace root"),
        };
        assert!(
            error.contains("workspace capability root is not a directory"),
            "got: {error}"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_command_that_exits_nonzero_is_an_error_carrying_its_status() {
        // The status has to reach the caller: a nonzero exit returned as `Ok`
        // would read to the model as a command that worked and said nothing.
        let root = scratch("nonzero-exit");
        let resolver = NativeWorkspaceResolver::new(&root).expect("resolver");
        let error = resolver
            .bash(
                &serde_json::json!({ "command": "echo out; exit 3" }),
                &FileView::default(),
            )
            .expect_err("a nonzero exit is an error");
        assert!(
            error.contains("command exited with status 3"),
            "names the status: {error}"
        );
        assert!(error.contains("out"), "carries the output: {error}");
        let _ = fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::{BTreeMap, BTreeSet, VecDeque};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use whipplescript_kernel::sansio::HttpRequest;

    use crate::gov::SignedEnvelope;
    use crate::host_policy::{
        HostGovernancePolicy, PlacementPolicy, ProviderBindingPolicy, ResourcePolicy,
    };
    use crate::host_protocol::{CredentialRef, TurnInput};

    struct Packages;

    const HOME_OPEN_OPERATION: &str = "imp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HOME_REATTEST_OPERATION: &str = "imp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[derive(Default)]
    struct TestHomeJournal {
        fail_at: Option<&'static str>,
        registered: Vec<String>,
        completed: Vec<String>,
        retained: Vec<String>,
    }

    impl OpenInstanceHomeJournal for TestHomeJournal {
        fn register(
            &mut self,
            basis: &OpenInstanceOperationBasis<'_>,
        ) -> Result<String, HostFacadeError> {
            assert_eq!(basis.target_store_incarnation.len(), 32);
            assert_eq!(basis.request_id, "home-chat-open");
            assert!(!basis.source_digest.is_empty());
            assert!(!basis.compiler_artifact_digest.is_empty());
            assert!(basis.construct_basis.is_some());
            self.registered.push(basis.kind.to_owned());
            if self.fail_at == Some("register") {
                return Err(HostFacadeError::Incomplete("Home register refused".into()));
            }
            Ok(match basis.kind {
                "open" => {
                    assert!(basis.instance_ref.is_none());
                    assert!(basis.from_version_id.is_none());
                    HOME_OPEN_OPERATION
                }
                "reattest" => {
                    assert!(basis.instance_ref.is_some());
                    assert!(basis.from_version_id.is_some());
                    HOME_REATTEST_OPERATION
                }
                other => panic!("unexpected Home operation: {other}"),
            }
            .to_owned())
        }

        fn complete_for_use(
            &mut self,
            evidence: &OpenInstanceOperationEvidence<'_>,
        ) -> Result<(), HostFacadeError> {
            assert_eq!(evidence.target_store_incarnation.len(), 32);
            assert_eq!(evidence.request_id, "home-chat-open");
            assert!(!evidence.version_id.is_empty());
            assert!(!evidence.witness_digest.is_empty());
            assert_eq!(
                evidence.instance_ref.is_some(),
                evidence.operation_id == HOME_REATTEST_OPERATION
            );
            if self.fail_at == Some("complete") {
                return Err(HostFacadeError::Incomplete("Home complete refused".into()));
            }
            self.completed.push(evidence.operation_id.to_owned());
            Ok(())
        }

        fn allow_retained_use(
            &mut self,
            target_store_incarnation: &str,
            request_id: &str,
            instance_ref: &str,
            version_id: &str,
        ) -> Result<(), HostFacadeError> {
            assert_eq!(target_store_incarnation.len(), 32);
            assert_eq!(request_id, "home-chat-open");
            assert!(!instance_ref.is_empty());
            assert!(!version_id.is_empty());
            self.retained.push(instance_ref.to_owned());
            if !self.completed.iter().any(|id| id == HOME_OPEN_OPERATION) {
                return Err(HostFacadeError::Incomplete(
                    "pending Home open has not been recovered".into(),
                ));
            }
            if self.registered.iter().any(|kind| kind == "reattest")
                && !self
                    .completed
                    .iter()
                    .any(|id| id == HOME_REATTEST_OPERATION)
            {
                return Err(HostFacadeError::Incomplete(
                    "pending Home re-attestation has not been recovered".into(),
                ));
            }
            if self.fail_at == Some("retained") {
                return Err(HostFacadeError::Incomplete(
                    "Home retained use refused".into(),
                ));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct TestForkJournal {
        fail_at: Option<&'static str>,
        mutate_source_version: Option<(PathBuf, String, String)>,
        remove_source_on_target_retained_use: Option<(PathBuf, String)>,
        remove_target_on_retained_use: Option<PathBuf>,
        completed_imports: BTreeSet<String>,
        source_binding: Option<(String, String, String)>,
        fork_registered: Option<(String, String, String)>,
        fork_completed: Option<(String, String, String, String)>,
        retained_forks: usize,
    }

    impl OpenInstanceHomeJournal for TestForkJournal {
        fn register(
            &mut self,
            basis: &OpenInstanceOperationBasis<'_>,
        ) -> Result<String, HostFacadeError> {
            assert_eq!(basis.kind, "open");
            assert_eq!(basis.target_store_incarnation.len(), 32);
            assert!(!basis.source_digest.is_empty());
            Ok(if basis.request_id == "home-fork-source" {
                HOME_OPEN_OPERATION
            } else {
                HOME_REATTEST_OPERATION
            }
            .to_owned())
        }

        fn complete_for_use(
            &mut self,
            evidence: &OpenInstanceOperationEvidence<'_>,
        ) -> Result<(), HostFacadeError> {
            assert!(!evidence.version_id.is_empty());
            assert!(!evidence.witness_digest.is_empty());
            self.completed_imports
                .insert(evidence.operation_id.to_owned());
            Ok(())
        }

        fn allow_retained_use(
            &mut self,
            target_store_incarnation: &str,
            request_id: &str,
            instance_ref: &str,
            version_id: &str,
        ) -> Result<(), HostFacadeError> {
            let operation = if request_id == "home-fork-source" {
                HOME_OPEN_OPERATION
            } else {
                HOME_REATTEST_OPERATION
            };
            if !self.completed_imports.contains(operation) {
                return Err(HostFacadeError::Incomplete(
                    "Home import is not complete".into(),
                ));
            }
            if request_id == "home-fork-source" {
                self.source_binding = Some((
                    target_store_incarnation.to_owned(),
                    instance_ref.to_owned(),
                    version_id.to_owned(),
                ));
            } else {
                if let Some((path, source_ref)) = self.remove_source_on_target_retained_use.take() {
                    rusqlite::Connection::open(path)
                        .expect("source database")
                        .execute("DELETE FROM instances WHERE instance_id = ?1", [source_ref])
                        .expect("source disappears after retained target open");
                }
                if let Some(path) = self.remove_target_on_retained_use.take() {
                    rusqlite::Connection::open(path)
                        .expect("target database")
                        .execute(
                            "DELETE FROM instances WHERE instance_id = ?1",
                            [instance_ref],
                        )
                        .expect("target disappears after retained open");
                }
            }
            Ok(())
        }
    }

    impl ForkInstanceHomeJournal for TestForkJournal {
        fn pin_source_for_fork(
            &mut self,
            source: &ForkSourceHomeBasis<'_>,
        ) -> Result<String, HostFacadeError> {
            if self.fail_at == Some("source") {
                return Err(HostFacadeError::Incomplete(
                    "Home source pin refused".into(),
                ));
            }
            if self.fail_at == Some("source_empty") {
                return Ok(String::new());
            }
            assert_eq!(
                self.source_binding.as_ref(),
                Some(&(
                    source.source_store_incarnation.to_owned(),
                    source.source_instance_ref.to_owned(),
                    source.source_observed_version_id.to_owned(),
                ))
            );
            assert!(source.source_sequence > 0);
            assert!(!source.source_chain_digest.is_empty());
            assert!(!source.source_thread_digest.is_empty());
            Ok(HOME_OPEN_OPERATION.to_owned())
        }

        fn register_fork(
            &mut self,
            basis: &ForkInstanceOperationBasis<'_>,
        ) -> Result<String, HostFacadeError> {
            if self.fail_at == Some("register") {
                return Err(HostFacadeError::Incomplete(
                    "Home fork register refused".into(),
                ));
            }
            if self.fail_at == Some("register_empty") {
                return Ok(String::new());
            }
            assert_eq!(basis.source_home_operation_id, HOME_OPEN_OPERATION);
            assert_eq!(basis.target_store_incarnation.len(), 32);
            assert_eq!(basis.target_package_version_ref, "package:v2");
            let observed = (
                basis.request_id.to_owned(),
                basis.target_store_incarnation.to_owned(),
                basis.source.source_chain_digest.to_owned(),
            );
            if let Some(existing) = &self.fork_registered {
                assert_eq!(existing, &observed, "retry keeps one Home basis");
            } else {
                self.fork_registered = Some(observed);
            }
            if let Some((path, instance_ref, version_id)) = self.mutate_source_version.take() {
                rusqlite::Connection::open(path)
                    .expect("source database")
                    .execute(
                        "UPDATE instances SET version_id = ?2 WHERE instance_id = ?1",
                        rusqlite::params![instance_ref, version_id],
                    )
                    .expect("source version changes after Home registration");
            }
            Ok("fork_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned())
        }

        fn complete_fork_for_use(
            &mut self,
            evidence: &ForkInstanceOperationEvidence<'_>,
        ) -> Result<(), HostFacadeError> {
            assert!(self.fork_registered.is_some());
            assert!(self.completed_imports.contains(HOME_REATTEST_OPERATION));
            assert_eq!(evidence.source_home_operation_id, HOME_OPEN_OPERATION);
            assert_eq!(
                evidence.operation_id,
                "fork_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            );
            assert!(evidence.seed_sequence < evidence.fork_sequence);
            assert!(!evidence.target_version_id.is_empty());
            if self.fail_at == Some("complete") {
                return Err(HostFacadeError::Incomplete(
                    "Home fork complete refused".into(),
                ));
            }
            let observed = (
                evidence.target_instance_ref.to_owned(),
                evidence.target_version_id.to_owned(),
                evidence.seed_event_id.to_owned(),
                evidence.fork_event_id.to_owned(),
            );
            if let Some(existing) = &self.fork_completed {
                assert_eq!(existing, &observed, "retry completes same evidence");
            } else {
                self.fork_completed = Some(observed);
            }
            Ok(())
        }

        fn allow_retained_fork_use(
            &mut self,
            evidence: &ForkInstanceOperationEvidence<'_>,
        ) -> Result<(), HostFacadeError> {
            if self.fork_completed.as_ref().map(|item| item.0.as_str())
                != Some(evidence.target_instance_ref)
            {
                return Err(HostFacadeError::Incomplete(
                    "Home fork pointer is not complete".into(),
                ));
            }
            self.retained_forks += 1;
            Ok(())
        }
    }

    impl PackageResolver for Packages {
        fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
            let system_prompt = if version_ref == "package:v2" {
                "Help through the governed resource tools (v2)."
            } else {
                "Help through the governed resource tools."
            };
            ResolvedPackage::compile(
                version_ref,
                r#"
file store project {
  root "."
  allow read ["**"]
  allow write ["**"]
}

workflow HostChat {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
  }

  rule converse
    when started
  => {
    tell assistant
      with access to project {
        read ["**"]
        write ["**"]
      }
      "host turn"
  }
}
"#,
                Some("HostChat"),
                "assistant",
                system_prompt,
                vec![ToolSpec {
                    name: "read".to_owned(),
                    description: "Read an admitted resource.".to_owned(),
                    input_schema: json!({
                        "type": "object",
                        "properties": { "path": { "type": "string" } },
                        "required": ["path"],
                        "additionalProperties": false
                    }),
                }],
                4,
            )
        }
    }

    struct ForgedLocalImportPackages;

    impl PackageResolver for ForgedLocalImportPackages {
        fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
            let mut package = Packages.resolve_package(version_ref)?;
            package.program.uses.push(whipplescript_parser::IrUse {
                kind: whipplescript_parser::IrUseKind::Package,
                name: "local.dep".to_owned(),
            });
            Ok(package)
        }
    }

    #[test]
    fn native_host_refuses_a_resolver_supplied_local_import_before_version_admission() {
        let path = temp_store();
        let policy = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-forged-local-import".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        assert!(runtime
            .open_instance(&open, &ForgedLocalImportPackages)
            .unwrap_err()
            .to_string()
            .contains("local import `local.dep` has no pinned package lock"));
        assert!(runtime
            .kernel
            .store()
            .program_import_operation_roster()
            .expect("admission operations")
            .operations
            .is_empty());
    }

    #[test]
    fn native_host_admits_std_only_package_with_exact_import_witness() {
        let path = temp_store();
        let policy = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy).expect("runtime");
        let package = Packages.resolve_package("package:v1").expect("package");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-checked-imports".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        runtime.open_instance(&open, &Packages).expect("opened");
        let roster = runtime
            .kernel
            .store()
            .program_import_operation_roster()
            .expect("admission operations");
        assert_eq!(roster.operations.len(), 1);
        assert_eq!(
            roster.operations[0].kind,
            whipplescript_store::program_imports::ProgramImportOperationKind::Checked
        );
        let witness = runtime
            .kernel
            .store()
            .program_import_witness(
                &roster.operations[0].version_id,
                roster.operations[0]
                    .witness_digest
                    .as_deref()
                    .expect("checked witness"),
            )
            .expect("witness lookup")
            .expect("stored witness");
        assert_eq!(
            witness.program_source_digest,
            package
                .checked_import_source_digest()
                .expect("source digest")
        );
        assert_eq!(
            witness.version_source_digest.as_deref(),
            Some(package.source_hash.as_str())
        );
        assert_eq!(
            witness.compiler_artifact_digest,
            native_compiler_artifact_digest().expect("compiler digest")
        );
        assert_eq!(witness.lock_digest, NO_LOCK_DIGEST);
        assert!(witness.examined.is_empty());
        assert!(witness
            .constructs
            .as_ref()
            .is_some_and(|capture| capture.examined.is_empty()));
        let declarations = witness.declarations.expect("checked declaration capture");
        assert_eq!(
            declarations
                .edges
                .iter()
                .map(|edge| edge.registration_id.as_str())
                .collect::<Vec<_>>(),
            ["files.file_store"]
        );
        assert!(declarations
            .edges
            .iter()
            .all(|edge| { edge.provider_source_digest == witness.compiler_artifact_digest }));
    }

    #[test]
    fn native_host_revalidates_a_sealed_selection_from_current_package_source() {
        use whipplescript_kernel::import_coverage::ImportCoverageGap;

        let path = temp_store();
        let policy = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy).expect("runtime");
        for request_id in ["first-checked", "second-checked"] {
            runtime
                .open_instance(
                    &OpenInstanceCommand {
                        protocol: HOST_PROTOCOL.to_owned(),
                        request_id: request_id.to_owned(),
                        package_version_ref: "package:v1".to_owned(),
                        policy: runtime.policy_ref().clone(),
                    },
                    &Packages,
                )
                .expect("checked admission");
        }
        let roster = runtime
            .kernel
            .store()
            .program_import_operation_roster()
            .expect("roster");
        assert_eq!(roster.operations.len(), 2);
        let selected_id = roster.operations[0].operation_id.clone();
        let selected = runtime
            .revalidate_selected_imports(std::slice::from_ref(&selected_id), &Packages, |_| {
                Some("package:v1".into())
            })
            .expect("selected coverage");
        assert_eq!(selected.selected.len(), 1);
        assert_eq!(selected.outside.len(), 1);
        assert!(selected.gaps.is_empty());

        for basis in [None, Some("package:v2".to_owned())] {
            let unknown = runtime
                .revalidate_selected_imports(std::slice::from_ref(&selected_id), &Packages, |_| {
                    basis.clone()
                })
                .expect("unknown basis is a gap");
            assert!(matches!(
                unknown.gaps.as_slice(),
                [ImportCoverageGap::NoCurrentBasis { operation_id, .. }]
                    if operation_id == &selected_id
            ));
        }
        let changed = runtime
            .revalidate_selected_imports(
                std::slice::from_ref(&selected_id),
                &UnsafePackages,
                |_| Some("package:v1".into()),
            )
            .expect("changed source is a gap");
        assert!(matches!(
            changed.gaps.as_slice(),
            [ImportCoverageGap::NoCurrentBasis { operation_id, .. }]
                if operation_id == &selected_id
        ));
        let missing = runtime
            .revalidate_selected_imports(&["absent-operation".into()], &Packages, |_| {
                panic!("a missing operation has no program basis")
            })
            .expect("missing selection is a gap");
        assert!(matches!(
            missing.gaps.as_slice(),
            [ImportCoverageGap::MissingOperation { .. }]
        ));
    }

    struct UnsafePackages;

    impl PackageResolver for UnsafePackages {
        fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
            ResolvedPackage::compile(
                version_ref,
                r#"
file store project {
  root "."
  allow read ["**"]
}

workflow UnsafeHostChat {
  agent assistant {
    provider fixture
    profile "repo-reader"
    capacity 1
  }

  rule leak
    when started
  => {
    tell assistant
      with access to project {
        read ["**"]
      }
      "leak the project"
  }
}
"#,
                Some("UnsafeHostChat"),
                "assistant",
                "unsafe",
                Vec::new(),
                1,
            )
        }
    }

    struct Secrets {
        calls: Cell<usize>,
    }

    impl SecretResolver for Secrets {
        fn resolve_provider(
            &self,
            binding: &ProviderBindingRef,
            placement_ceiling_ref: &str,
        ) -> Result<ResolvedProviderBinding, String> {
            assert_eq!(binding.binding_id, "model");
            assert_eq!(placement_ceiling_ref, "local");
            self.calls.set(self.calls.get() + 1);
            Ok(ResolvedProviderBinding::new(
                ModelProvider::OpenAi,
                "secret-that-must-not-be-persisted",
                "gpt-test",
                "https://provider.invalid",
                256,
                Duration::from_secs(1),
            ))
        }
    }

    struct Resources {
        calls: Cell<usize>,
    }

    impl ResourceResolver for Resources {
        fn resolve_image(&self, _image: &ResourceRef) -> Result<ResolvedImage, String> {
            Err("no images in this test".to_owned())
        }

        fn execute_tool(
            &self,
            admitted_resources: &[ResourceRef],
            call: &ToolCall,
        ) -> Result<String, String> {
            assert_eq!(call.name, "read");
            assert_eq!(admitted_resources.len(), 1);
            assert_eq!(admitted_resources[0].handle, "project");
            self.calls.set(self.calls.get() + 1);
            Ok("governed file body".to_owned())
        }
    }

    #[test]
    fn skill_catalogue_attestation_uses_the_exact_registry_snapshot() {
        struct SkillSource;
        impl ResourceResolver for SkillSource {
            fn resolve_image(&self, _image: &ResourceRef) -> Result<ResolvedImage, String> {
                Err("no image".into())
            }
            fn execute_tool(
                &self,
                _resources: &[ResourceRef],
                _call: &ToolCall,
            ) -> Result<String, String> {
                Err("no tool".into())
            }
            fn model_skill_catalogue_provenance(
                &self,
                skills: &[SkillView],
            ) -> ModelContentProvenance {
                ModelContentProvenance {
                    source_handles: skills
                        .iter()
                        .map(|skill| format!("skill:{}", skill.content_hash))
                        .collect(),
                    complete: true,
                }
            }
        }
        let store = SqliteStore::open(temp_store()).unwrap();
        let body = "---\nname: triage\ndescription: Inspect reports\n---\nRead the report.\n";
        let register = |body: &str, description: &str| {
            store
                .register_skill(whipplescript_store::SkillRegistration {
                    skill_id: "skill:triage",
                    name: "triage",
                    version: "1.0.0",
                    source: "gaugedesk-agent",
                    source_path: "agent/skills/triage/SKILL.md",
                    body,
                    description,
                    required_capabilities_json: "[]",
                    metadata_json: "{}",
                })
                .unwrap();
        };
        register(body, "Inspect reports");
        let snapshot = store.list_skills().unwrap();
        let known = attested_skill_catalogue_provenance(&store, &SkillSource, &snapshot);
        assert!(known.complete);
        assert_eq!(
            known.source_handles,
            [format!("skill:{}", snapshot[0].content_hash)]
        );
        assert!(
            !attested_skill_catalogue_provenance(
                &store,
                &Resources {
                    calls: Cell::new(0)
                },
                &snapshot
            )
            .complete
        );
        register(body, "forged description");
        assert!(
            !attested_skill_catalogue_provenance(
                &store,
                &SkillSource,
                &store.list_skills().unwrap()
            )
            .complete
        );
        register("changed body", "Inspect reports");
        assert!(!attested_skill_catalogue_provenance(&store, &SkillSource, &snapshot).complete);
    }

    struct ScriptedDriver {
        replies: RefCell<VecDeque<Value>>,
        requests: RefCell<Vec<Value>>,
        provenance: RefCell<Vec<Option<whipplescript_kernel::sansio::ModelRequestProvenance>>>,
    }

    impl ScriptedDriver {
        fn new(replies: Vec<Value>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
                requests: RefCell::new(Vec::new()),
                provenance: RefCell::new(Vec::new()),
            }
        }
    }

    impl HostDriver for ScriptedDriver {
        fn fulfill(&self, request: &IoRequest) -> IoResult {
            let IoRequest::Http(request) = request;
            self.requests.borrow_mut().push(request.body.clone());
            self.provenance
                .borrow_mut()
                .push(request.model_provenance.clone());
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: self
                    .replies
                    .borrow_mut()
                    .pop_front()
                    .expect("scripted reply"),
            }))
        }
    }

    #[test]
    fn custom_driver_receives_attested_model_sources() {
        use whipplescript_kernel::sansio::{InitialModelProvenance, ModelContentProvenance};

        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).expect("instance");
        let known = |source: &str| ModelContentProvenance {
            source_handles: vec![source.to_owned()],
            complete: true,
        };
        let sources = InitialModelProvenance {
            system: known("package:v1"),
            user: known("chat:one"),
            world: known("chat:one"),
            tools: known("package:v1"),
            workspace_content: ModelContentProvenance::default(),
        };
        let driver = ScriptedDriver::new(vec![json!({
            "output_text": "done",
            "usage": { "input_tokens": 10, "output_tokens": 2 }
        })]);
        runtime
            .run_turn_with_driver_and_provenance(
                &turn(&instance.instance_ref, &open.policy, 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &driver,
                &sources,
            )
            .expect("turn");
        let labels = driver.provenance.borrow();
        assert_eq!(labels.len(), 1);
        let labels = labels[0].as_ref().expect("transient model sources");
        assert_eq!(labels.messages[0], known("package:v1"));
        assert_eq!(labels.tools, known("package:v1"));
    }

    struct LiveResources {
        allowed: Cell<bool>,
        tool_calls: Cell<usize>,
        revoke_on_tool: bool,
    }
    impl ResourceResolver for LiveResources {
        fn check_live_access(&self) -> Result<(), String> {
            if self.allowed.get() {
                Ok(())
            } else {
                Err("private refusal detail".into())
            }
        }
        fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
            Err("unused image".into())
        }
        fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
            self.tool_calls.set(self.tool_calls.get() + 1);
            if self.revoke_on_tool {
                self.allowed.set(false);
            }
            Ok("private tool result".into())
        }
    }

    #[test]
    fn product_writer_encloses_first_durable_turn_effect_and_refusal_leaves_none() {
        struct StartAdmission {
            writer: rusqlite::Connection,
            product_path: std::path::PathBuf,
            expected_command: RefCell<String>,
            allowed: Cell<bool>,
            live_allowed: Cell<bool>,
            invoke_start: Cell<bool>,
            invoke_reuse: Cell<bool>,
            invoke_reuse_twice: Cell<bool>,
            invoke_twice: Cell<bool>,
            swallow_start_error: Cell<bool>,
            starts: Cell<usize>,
            reuses: Cell<usize>,
        }
        impl ResourceResolver for StartAdmission {
            fn check_live_access(&self) -> Result<(), String> {
                self.live_allowed
                    .get()
                    .then_some(())
                    .ok_or_else(|| "Home current access refused".into())
            }

            fn with_turn_start_admission(
                &self,
                command: &StartTurnCommand,
                start: &mut dyn FnMut() -> Result<(), HostRuntimeError>,
            ) -> Result<(), HostRuntimeError> {
                assert_eq!(command.command_id, *self.expected_command.borrow());
                if !self.allowed.get() {
                    return Err(HostRuntimeError::Resolver(
                        "Home current basis refused start".into(),
                    ));
                }
                if !self.invoke_start.get() {
                    return Ok(());
                }
                self.writer.execute_batch("BEGIN IMMEDIATE").unwrap();
                let competing = rusqlite::Connection::open(&self.product_path).unwrap();
                competing.busy_timeout(Duration::ZERO).unwrap();
                assert_eq!(
                    competing
                        .execute_batch("BEGIN IMMEDIATE")
                        .unwrap_err()
                        .sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
                self.starts.set(self.starts.get() + 1);
                let result = if self.swallow_start_error.get() {
                    self.live_allowed.set(false);
                    let _ = start();
                    Ok(())
                } else {
                    start().and_then(|()| {
                        if self.invoke_twice.get() {
                            start()
                        } else {
                            Ok(())
                        }
                    })
                };
                self.writer
                    .execute_batch(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                    .unwrap();
                result
            }
            fn with_turn_reuse_admission(
                &self,
                command: &StartTurnCommand,
                reuse: &mut dyn FnMut() -> Result<(), HostRuntimeError>,
            ) -> Result<(), HostRuntimeError> {
                assert_eq!(command.command_id, *self.expected_command.borrow());
                if !self.allowed.get() {
                    return Err(HostRuntimeError::Resolver(
                        "Home current basis refused reuse".into(),
                    ));
                }
                if !self.invoke_reuse.get() {
                    return Ok(());
                }
                self.writer.execute_batch("BEGIN IMMEDIATE").unwrap();
                let competing = rusqlite::Connection::open(&self.product_path).unwrap();
                competing.busy_timeout(Duration::ZERO).unwrap();
                assert_eq!(
                    competing
                        .execute_batch("BEGIN IMMEDIATE")
                        .unwrap_err()
                        .sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
                self.reuses.set(self.reuses.get() + 1);
                let result = reuse().and_then(|()| {
                    if self.invoke_reuse_twice.get() {
                        reuse()
                    } else {
                        Ok(())
                    }
                });
                self.writer
                    .execute_batch(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
                    .unwrap();
                result
            }
            fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
                unreachable!()
            }
            fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
                unreachable!()
            }
        }

        let path = temp_store();
        let product_path = path.with_extension("start-product.sqlite");
        let writer = rusqlite::Connection::open(&product_path).unwrap();
        writer
            .execute_batch("CREATE TABLE basis (version INTEGER)")
            .unwrap();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "start-admission-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let resources = StartAdmission {
            writer,
            product_path: product_path.clone(),
            expected_command: RefCell::new(command.command_id.clone()),
            allowed: Cell::new(false),
            live_allowed: Cell::new(true),
            invoke_start: Cell::new(false),
            invoke_reuse: Cell::new(false),
            invoke_reuse_twice: Cell::new(false),
            invoke_twice: Cell::new(false),
            swallow_start_error: Cell::new(false),
            starts: Cell::new(0),
            reuses: Cell::new(0),
        };
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let driver = ScriptedDriver::new(vec![
            json!({"output_text":"admitted"}),
            json!({"output_text":"resumed"}),
        ]);
        assert!(runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .is_err());
        assert!(runtime
            .kernel
            .store()
            .list_effects(&instance.instance_ref)
            .unwrap()
            .is_empty());
        assert!(driver.requests.borrow().is_empty());
        resources.allowed.set(true);
        let omitted = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(omitted
            .to_string()
            .contains("omitted or repeated the durable effect"));
        assert!(runtime
            .kernel
            .store()
            .list_effects(&instance.instance_ref)
            .unwrap()
            .is_empty());
        resources.invoke_start.set(true);
        resources.swallow_start_error.set(true);
        let swallowed = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(swallowed
            .to_string()
            .contains("omitted or repeated the durable effect"));
        assert!(runtime
            .kernel
            .store()
            .list_effects(&instance.instance_ref)
            .unwrap()
            .is_empty());
        resources.live_allowed.set(true);
        resources.swallow_start_error.set(false);
        runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap();
        assert_eq!(resources.starts.get(), 2);
        assert_eq!(driver.requests.borrow().len(), 1);
        resources.allowed.set(false);
        let refused = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(refused.to_string().contains("refused reuse"));
        resources.allowed.set(true);
        let omitted = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(omitted
            .to_string()
            .contains("omitted or repeated exact reuse"));
        resources.invoke_reuse.set(true);
        runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap();
        assert_eq!(resources.reuses.get(), 1);
        assert_eq!(driver.requests.borrow().len(), 1);
        resources.invoke_reuse_twice.set(true);
        let duplicate = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(duplicate
            .to_string()
            .contains("reuse admission invoked twice"));
        resources.invoke_reuse_twice.set(false);
        let second = turn(&instance.instance_ref, &open.policy, 2);
        resources
            .expected_command
            .replace(second.command_id.clone());
        resources.invoke_twice.set(true);
        let error = runtime
            .run_turn_with_driver(&second, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(error.to_string().contains("invoked twice"));
        assert_eq!(driver.requests.borrow().len(), 1);
        resources.invoke_twice.set(false);
        resources.allowed.set(false);
        let refused = runtime
            .run_turn_with_driver(&second, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(refused.to_string().contains("refused reuse"));
        assert_eq!(driver.requests.borrow().len(), 1);
        resources.allowed.set(true);
        runtime
            .run_turn_with_driver(&second, &Packages, &secrets, &resources, &driver)
            .unwrap();
        assert_eq!(resources.reuses.get(), 3);
        assert_eq!(driver.requests.borrow().len(), 2);
        drop(runtime);
        fs::remove_file(path).unwrap();
        fs::remove_file(product_path).unwrap();
    }

    #[test]
    fn live_access_denies_before_provider_and_denies_retained_result() {
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "live-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let resources = LiveResources {
            allowed: Cell::new(false),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let driver = ScriptedDriver::new(vec![json!({"output_text":"private answer"})]);
        let err = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(err.to_string().contains(LIVE_ACCESS_REFUSED), "{err:?}");
        assert!(!err.to_string().contains("private"));
        assert_eq!(secrets.calls.get(), 0);
        assert!(driver.requests.borrow().is_empty());
        resources.allowed.set(true);
        runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap();
        assert_eq!(driver.requests.borrow().len(), 1);
        resources.allowed.set(false);
        let err = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap_err();
        assert!(err.to_string().contains(LIVE_ACCESS_REFUSED), "{err:?}");
        assert_eq!(driver.requests.borrow().len(), 1);
        drop(runtime);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn recorded_turn_execution_preserves_original_after_later_work_and_restart() {
        let path = temp_store();
        let policy = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "saved-execution-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let original_start = runtime.pinned_position(&instance.instance_ref).unwrap();
        let before = runtime.current_position(&instance.instance_ref).unwrap();
        let effects = format!(
            "{:?}",
            runtime
                .kernel
                .store()
                .list_effects(&instance.instance_ref)
                .unwrap()
        );
        assert!(runtime
            .recorded_turn_execution(&command, &resources)
            .unwrap()
            .is_none());
        let absent_reader = RecordedHostRuntime::open(&path, 7, &policy, &resources).unwrap();
        assert!(absent_reader
            .recorded_turn_execution(&command, &original_start, &resources)
            .unwrap()
            .is_none());
        assert!(absent_reader
            .turn_workspace_witness(&command, &original_start, &resources)
            .unwrap()
            .is_none());
        assert!(absent_reader
            .turn_guarantee_report(&command, &original_start, &resources)
            .unwrap()
            .is_none());
        drop(absent_reader);

        assert_eq!(
            runtime.current_position(&instance.instance_ref).unwrap(),
            before
        );
        assert_eq!(
            format!(
                "{:?}",
                runtime
                    .kernel
                    .store()
                    .list_effects(&instance.instance_ref)
                    .unwrap()
            ),
            effects
        );
        assert_eq!(secrets.calls.get(), 0);

        let driver = ScriptedDriver::new(vec![json!({
            "output_text": "original private answer",
            "usage": { "input_tokens": 13, "output_tokens": 5 }
        })]);
        let original = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .unwrap();
        let later = turn(&instance.instance_ref, &open.policy, 2);
        runtime
            .run_turn_with_driver(
                &later,
                &Packages,
                &secrets,
                &resources,
                &ScriptedDriver::new(vec![json!({"output_text":"later private answer"})]),
            )
            .unwrap();
        assert!(
            runtime
                .current_position(&instance.instance_ref)
                .unwrap()
                .sequence
                > original
                    .receipt
                    .as_ref()
                    .unwrap()
                    .terminal_position
                    .sequence
        );
        let head = runtime.pinned_position(&instance.instance_ref).unwrap();
        let events = format!(
            "{:?}",
            runtime
                .kernel
                .store()
                .list_events(&instance.instance_ref)
                .unwrap()
        );
        let effects = format!(
            "{:?}",
            runtime
                .kernel
                .store()
                .list_effects(&instance.instance_ref)
                .unwrap()
        );
        let provider_calls = secrets.calls.get();
        let alternate = runtime
            .open_instance(
                &OpenInstanceCommand {
                    protocol: HOST_PROTOCOL.into(),
                    request_id: "another-existing-recorded-instance".into(),
                    package_version_ref: "package:v1".into(),
                    policy: open.policy.clone(),
                },
                &Packages,
            )
            .unwrap();
        let alternate_start = runtime.pinned_position(&alternate.instance_ref).unwrap();

        let journal_mode = || {
            rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .unwrap()
                .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
                .unwrap()
        };
        let journal_mode_before = journal_mode();
        let database_before = fs::read(&path).unwrap();
        let permissions_before = fs::metadata(&path).unwrap().permissions();
        let reader = RecordedHostRuntime::open(&path, 7, &policy, &resources).unwrap();
        let changed_policy_reader =
            RecordedHostRuntime::open(&path, 8, &policy, &resources).unwrap();
        assert!(changed_policy_reader
            .recorded_turn_execution(&command, &original_start, &resources)
            .is_err());
        drop(changed_policy_reader);

        assert_eq!(
            reader
                .recorded_turn_execution(&command, &original_start, &resources)
                .unwrap(),
            Some(original.clone())
        );
        assert!(reader
            .turn_workspace_witness(&command, &original_start, &resources)
            .unwrap()
            .is_none());
        assert_eq!(
            reader
                .turn_guarantee_report(&command, &original_start, &resources)
                .unwrap(),
            runtime.turn_guarantee_report(&command).unwrap()
        );
        for field in [
            "digest",
            "sequence",
            "overflow",
            "instance",
            "mismatched-instance",
            "policy",
            "after-terminal",
        ] {
            let mut changed_start = original_start.clone();
            let mut changed_command = command.clone();
            match field {
                "digest" => changed_start.head_digest.push('0'),
                "sequence" => changed_start.sequence += 1,
                "overflow" => changed_start.sequence = u64::MAX,
                "instance" => {
                    changed_start.instance_ref = "unknown-original-instance".into();
                    changed_command.instance_ref = changed_start.instance_ref.clone();
                    changed_start.sequence = 0;
                    changed_start.head_digest = whipplescript_store::event_chain::genesis_digest(
                        &changed_start.instance_ref,
                    );
                }
                "mismatched-instance" => changed_start = alternate_start.clone(),
                "policy" => changed_command.policy.epoch += 1,
                "after-terminal" => changed_start = head.clone(),
                _ => unreachable!(),
            }
            assert!(
                reader
                    .recorded_turn_execution(&changed_command, &changed_start, &resources)
                    .is_err(),
                "{field}"
            );
        }
        let mut unknown_command = command.clone();
        unknown_command.instance_ref = "unknown-original-instance".into();
        let unknown_start = PinnedPosition {
            instance_ref: unknown_command.instance_ref.clone(),
            sequence: 0,
            head_digest: whipplescript_store::event_chain::genesis_digest(
                &unknown_command.instance_ref,
            ),
        };
        let unknown_projection = Cell::new(false);
        assert!(reader
            .observe(&unknown_command, &unknown_start, &resources, |_| {
                unknown_projection.set(true);
                Ok("original projection")
            })
            .is_err());
        assert!(
            !unknown_projection.get(),
            "unknown runtime entered an original observation"
        );
        let genesis = PinnedPosition {
            instance_ref: instance.instance_ref.clone(),
            sequence: 0,
            head_digest: whipplescript_store::event_chain::genesis_digest(&instance.instance_ref),
        };
        assert_eq!(
            reader
                .recorded_turn_execution(&command, &genesis, &resources)
                .unwrap(),
            Some(original.clone())
        );
        assert!(
            reader
                .runtime
                .kernel
                .store()
                .append_event(NewEvent {
                    instance_id: &instance.instance_ref,
                    event_type: "host.synthetic.forbidden",
                    payload_json: "{}",
                    source: "qualification",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                })
                .is_err(),
            "recorded connection accepted a write"
        );
        assert_eq!(fs::read(&path).unwrap(), database_before);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions(),
            permissions_before
        );
        assert_eq!(journal_mode(), journal_mode_before);
        drop(reader);
        assert_eq!(journal_mode(), journal_mode_before);
        let missing = path.with_extension("missing-runtime");
        assert!(!missing.exists());
        assert!(RecordedHostRuntime::open(&missing, 7, &policy, &resources).is_err());
        assert!(
            !missing.exists(),
            "recorded open initialized a missing database"
        );
        let db = rusqlite::Connection::open(&path).unwrap();
        let schema_rows = db
            .prepare("SELECT version,name,applied_at FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let schema = schema_rows.last().unwrap().0;
        let existing_reader = RecordedHostRuntime::open(&path, 7, &policy, &resources).unwrap();
        for version in [0, schema - 1, schema + 1] {
            db.execute("DELETE FROM schema_migrations", []).unwrap();
            db.execute("INSERT INTO schema_migrations(version,name,applied_at) VALUES(?1,'synthetic-schema','synthetic-time')", [version]).unwrap();
            assert!(
                RecordedHostRuntime::open(&path, 7, &policy, &resources).is_err(),
                "schema {version}"
            );
            assert!(existing_reader
                .recorded_turn_execution(&command, &original_start, &resources)
                .is_err());
            assert_eq!(
                db.query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row
                    .get::<_, i64>(
                    0
                ))
                .unwrap(),
                version
            );
        }
        db.execute("DELETE FROM schema_migrations", []).unwrap();
        assert!(
            RecordedHostRuntime::open(&path, 7, &policy, &resources).is_err(),
            "missing schema stamp"
        );
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        for (version, name, applied_at) in &schema_rows {
            db.execute(
                "INSERT INTO schema_migrations(version,name,applied_at) VALUES(?1,?2,?3)",
                rusqlite::params![version, name, applied_at],
            )
            .unwrap();
        }

        let changed_during_read = existing_reader.observe(&command, &original_start, &resources, |_| {
            db.execute("INSERT INTO schema_migrations(version,name,applied_at) VALUES(?1,'synthetic-new-schema','synthetic-time')", [schema + 1]).unwrap();
            Ok("private original projection")
        });
        assert!(
            changed_during_read.is_err(),
            "reader released a result across schema replacement"
        );
        db.execute(
            "DELETE FROM schema_migrations WHERE version=?1",
            [schema + 1],
        )
        .unwrap();
        assert_eq!(
            existing_reader
                .recorded_turn_execution(&command, &original_start, &resources)
                .unwrap(),
            Some(original.clone())
        );
        drop(existing_reader);
        assert_eq!(
            runtime
                .recorded_turn_execution(&command, &resources)
                .unwrap(),
            Some(original.clone())
        );
        assert_eq!(
            runtime.pinned_position(&instance.instance_ref).unwrap(),
            head
        );
        assert_eq!(
            format!(
                "{:?}",
                runtime
                    .kernel
                    .store()
                    .list_events(&instance.instance_ref)
                    .unwrap()
            ),
            events
        );
        assert_eq!(
            format!(
                "{:?}",
                runtime
                    .kernel
                    .store()
                    .list_effects(&instance.instance_ref)
                    .unwrap()
            ),
            effects
        );
        assert_eq!(secrets.calls.get(), provider_calls);
        assert_eq!(driver.requests.borrow().len(), 1);
        assert_eq!(resources.tool_calls.get(), 0);

        for field in [
            "input",
            "actor",
            "run",
            "resources",
            "credential",
            "package",
            "placement",
        ] {
            let mut changed = command.clone();
            match field {
                "input" => changed.input.text.push_str("changed"),
                "actor" => changed.actor_ref.push_str("changed"),
                "run" => changed.run_ref.push_str("changed"),
                "resources" => changed.resources.clear(),
                "credential" => changed
                    .provider_binding
                    .credential
                    .credential_id
                    .push_str("changed"),
                "package" => changed.package_version_ref.push_str("changed"),
                "placement" => changed.placement_ceiling_ref.push_str("changed"),
                _ => unreachable!(),
            }
            assert!(
                runtime
                    .recorded_turn_execution(&changed, &resources)
                    .is_err(),
                "{field}"
            );
        }
        assert_eq!(
            runtime.pinned_position(&instance.instance_ref).unwrap(),
            head
        );
        let connection = rusqlite::Connection::open(&path).unwrap();
        let lost = connection.execute(
            "UPDATE events SET event_type='lost-original-checkpoint' WHERE event_type='agent.turn.brokered.transcript' AND json_extract(payload_json,'$.effect_id')=?1",
            [&command.command_id],
        ).unwrap();
        assert!(lost > 0);
        assert!(runtime
            .recorded_turn_execution(&command, &resources)
            .is_err());
        connection.execute(
            "UPDATE events SET event_type='agent.turn.brokered.transcript' WHERE event_type='lost-original-checkpoint' AND json_extract(payload_json,'$.effect_id')=?1",
            [&command.command_id],
        ).unwrap();
        assert_eq!(
            runtime
                .recorded_turn_execution(&command, &resources)
                .unwrap(),
            Some(original.clone())
        );
        for (column, bad) in [
            ("kind", "other"),
            ("status", "queued"),
            ("input_json", "{}"),
        ] {
            let old: String = connection
                .query_row(
                    &format!("SELECT {column} FROM effects WHERE effect_id=?1"),
                    [&command.command_id],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute(
                    &format!("UPDATE effects SET {column}=?1 WHERE effect_id=?2"),
                    rusqlite::params![bad, &command.command_id],
                )
                .unwrap();
            assert!(
                runtime
                    .recorded_turn_execution(&command, &resources)
                    .is_err(),
                "{column}"
            );
            connection
                .execute(
                    &format!("UPDATE effects SET {column}=?1 WHERE effect_id=?2"),
                    rusqlite::params![old, &command.command_id],
                )
                .unwrap();
        }
        let (marker_id, marker_payload): (String, String) = connection.query_row(
            "SELECT event_id,payload_json FROM events WHERE instance_id=?1 AND event_type='host.turn.receipt' AND correlation_id=?2",
            rusqlite::params![&instance.instance_ref, &command.command_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        let mut bad_receipt: Value = serde_json::from_str(&marker_payload).unwrap();
        bad_receipt["run_ref"] = json!("another-original-run");
        connection
            .execute(
                "UPDATE events SET payload_json=?1 WHERE event_id=?2",
                rusqlite::params![bad_receipt.to_string(), &marker_id],
            )
            .unwrap();
        assert!(runtime
            .recorded_turn_execution(&command, &resources)
            .is_err());
        connection
            .execute(
                "UPDATE events SET payload_json=?1 WHERE event_id=?2",
                rusqlite::params![marker_payload, &marker_id],
            )
            .unwrap();
        drop(connection);
        assert_eq!(
            runtime
                .recorded_turn_execution(&command, &resources)
                .unwrap(),
            Some(original.clone())
        );
        drop(runtime);
        let reopened = GovernedHostRuntime::open(&path, 7, &policy).unwrap();
        assert_eq!(
            reopened
                .recorded_turn_execution(&command, &resources)
                .unwrap(),
            Some(original)
        );
        assert_eq!(
            reopened.pinned_position(&instance.instance_ref).unwrap(),
            head
        );
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn protected_host_runtime_preserves_original_turn_and_refuses_plain_recovery() {
        use ring::{
            aead,
            rand::{SecureRandom, SystemRandom},
        };
        use std::sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        };
        use whipplescript_store::payload_protection::PayloadCodec;
        struct Codec {
            available: AtomicBool,
            key_byte: u8,
        }
        impl Codec {
            fn key(&self) -> Result<aead::LessSafeKey, StoreError> {
                if !self.available.load(Ordering::Acquire) {
                    return Err(StoreError::fault("fixture codec", "key unavailable"));
                }
                Ok(aead::LessSafeKey::new(
                    aead::UnboundKey::new(&aead::AES_256_GCM, &[self.key_byte; 32]).unwrap(),
                ))
            }
        }
        impl PayloadCodec for Codec {
            fn seal(&self, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, StoreError> {
                let key = self.key()?;
                let mut nonce = [0; 12];
                SystemRandom::new().fill(&mut nonce).unwrap();
                let mut body = plain.to_vec();
                key.seal_in_place_append_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(aad),
                    &mut body,
                )
                .map_err(|_| StoreError::fault("fixture codec", "seal failed"))?;
                Ok([nonce.to_vec(), body].concat())
            }
            fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, StoreError> {
                let key = self.key()?;
                let nonce: [u8; 12] = sealed
                    .get(..12)
                    .and_then(|v| v.try_into().ok())
                    .ok_or_else(|| StoreError::fault("fixture codec", "short envelope"))?;
                let mut body = sealed[12..].to_vec();
                let plain = key
                    .open_in_place(
                        aead::Nonce::assume_unique_for_key(nonce),
                        aead::Aad::from(aad),
                        &mut body,
                    )
                    .map_err(|_| StoreError::fault("fixture codec", "authentication failed"))?;
                Ok(plain.to_vec())
            }
            fn retain(
                &self,
                publish: &mut dyn FnMut() -> Result<(), StoreError>,
            ) -> Result<(), StoreError> {
                self.key()?;
                publish()
            }
        }
        struct Root(bool);
        impl crate::gov::GovernanceAttestationVerifier for Root {
            fn verify(&self, _: &[u8], _: &crate::gov::ExternalAttestation) -> Result<(), String> {
                if self.0 {
                    Ok(())
                } else {
                    Err("synthetic denied root".into())
                }
            }
        }
        let mut policy: Value = serde_json::from_str(&signed_policy()).unwrap();
        policy.as_object_mut().unwrap().remove("attestation");
        let signed = SignedEnvelope::from_external_signature_v2(
            &policy.to_string(),
            "office-root",
            "fixture",
            "fixture-key",
            "fixture-proof",
            7,
            "office",
        )
        .unwrap()
        .to_json();
        let codec = Arc::new(Codec {
            available: AtomicBool::new(true),
            key_byte: 7,
        });
        let protection = PayloadProtection::new("synthetic-office-chat", codec.clone()).unwrap();
        let path = temp_store();
        assert!(GovernedHostRuntime::create_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(false),
            protection.clone()
        )
        .is_err());
        assert!(!path.exists(), "denied policy created a database");
        assert!(GovernedHostRuntime::open_existing_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            protection.clone()
        )
        .is_err());
        assert!(
            !path.exists(),
            "existing-store reopen initialized a database"
        );
        let mut runtime = GovernedHostRuntime::create_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            protection.clone(),
        )
        .unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "protected-original-instance".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let mut command = turn(&instance.instance_ref, &open.policy, 1);
        command.input.text = "synthetic private clinical prompt".into();
        let start = runtime.pinned_position(&instance.instance_ref).unwrap();
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let execution = runtime
            .run_turn_with_driver(
                &command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &resources,
                &ScriptedDriver::new(vec![
                    json!({"output_text":"synthetic private clinical answer"}),
                ]),
            )
            .unwrap();
        let cancelled_command = turn(&instance.instance_ref, &open.policy, 2);
        let cancel_driver = CancellingDriver {
            handle: runtime.cancellation_handle(
                &cancelled_command.instance_ref,
                &cancelled_command.command_id,
            ),
            fired: Cell::new(false),
        };
        let cancelled = runtime
            .run_turn_with_driver(
                &cancelled_command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &resources,
                &cancel_driver,
            )
            .unwrap();
        assert_eq!(cancelled.receipt.unwrap().status, TurnStatus::Cancelled);
        assert!(cancel_driver.fired.get());
        let probe_command = turn(&instance.instance_ref, &open.policy, 3);
        let clock = std::rc::Rc::new(Cell::new(Duration::ZERO));
        let probe = StreamCancelProbe::on_clock(
            path.clone(),
            probe_command.instance_ref.clone(),
            probe_command.command_id.clone(),
            ProbeClock::Held(clock.clone()),
            runtime.protection.clone(),
        );
        let probe_driver = ProbeAssertingDriver {
            handle: runtime
                .cancellation_handle(&probe_command.instance_ref, &probe_command.command_id),
            probe: &probe,
            clock,
            checked: Cell::new(false),
        };
        let cancelled = runtime
            .run_turn_with_driver(
                &probe_command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &resources,
                &probe_driver,
            )
            .unwrap();
        assert!(probe_driver.checked.get());
        assert_eq!(cancelled.receipt.unwrap().status, TurnStatus::Cancelled);
        let unavailable_probe = StreamCancelProbe::new(
            path.clone(),
            command.instance_ref.clone(),
            command.command_id.clone(),
            Some(protection.clone()),
        );
        codec.available.store(false, Ordering::Release);
        assert!(
            unavailable_probe.observed(),
            "unavailable key concealed protected cancellation standing"
        );
        codec.available.store(true, Ordering::Release);
        assert!(
            unavailable_probe.observed(),
            "restored key revived a released protected stream"
        );
        drop(unavailable_probe);
        let missing_probe_path = temp_store();
        let missing_probe = StreamCancelProbe::new(
            missing_probe_path.clone(),
            command.instance_ref.clone(),
            command.command_id.clone(),
            Some(protection.clone()),
        );
        assert!(missing_probe.observed());
        assert!(
            !missing_probe_path.exists(),
            "protected probe initialized a missing runtime"
        );
        let head = runtime.pinned_position(&instance.instance_ref).unwrap();
        drop(runtime);
        for suffix in ["", "-wal"] {
            if let Ok(bytes) = fs::read(format!("{}{suffix}", path.display())) {
                for marker in [
                    "synthetic private clinical prompt",
                    "synthetic private clinical answer",
                ] {
                    assert!(
                        !bytes
                            .windows(marker.len())
                            .any(|part| part == marker.as_bytes()),
                        "native storage retained plaintext {marker}"
                    );
                }
            }
        }
        let before = fs::read(&path).unwrap();
        assert!(GovernedHostRuntime::open_with_verifier(&path, 7, &signed, &Root(true)).is_err());
        assert!(RecordedHostRuntime::open_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            &resources
        )
        .is_err());
        assert!(GovernedHostRuntime::create_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            protection.clone()
        )
        .is_err());
        let foreign = PayloadProtection::new("foreign-office-chat", codec.clone()).unwrap();
        assert!(RecordedHostRuntime::open_existing_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            &resources,
            foreign
        )
        .is_err());
        let wrong_key = PayloadProtection::new(
            "synthetic-office-chat",
            Arc::new(Codec {
                available: AtomicBool::new(true),
                key_byte: 8,
            }),
        )
        .unwrap();
        let wrong_reader = RecordedHostRuntime::open_existing_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            &resources,
            wrong_key,
        )
        .unwrap();
        assert!(
            wrong_reader
                .recorded_turn_execution(&command, &start, &resources)
                .is_err(),
            "matching domain admitted unauthenticated payloads from a wrong key"
        );
        drop(wrong_reader);
        let reader = RecordedHostRuntime::open_existing_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            &resources,
            protection.clone(),
        )
        .unwrap();
        assert_eq!(
            reader
                .recorded_turn_execution(&command, &start, &resources)
                .unwrap(),
            Some(execution)
        );
        codec.available.store(false, Ordering::Release);
        assert!(reader
            .recorded_turn_execution(&command, &start, &resources)
            .is_err());
        codec.available.store(true, Ordering::Release);
        resources.allowed.set(false);
        assert!(reader
            .recorded_turn_execution(&command, &start, &resources)
            .is_err());
        resources.allowed.set(true);
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "original recovery changed database bytes"
        );
        drop(reader);
        let reopened = GovernedHostRuntime::open_existing_protected_with_verifier(
            &path,
            7,
            &signed,
            &Root(true),
            protection,
        )
        .unwrap();
        assert_eq!(
            reopened.pinned_position(&instance.instance_ref).unwrap(),
            head
        );
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recorded_runtime_reopens_with_exact_external_policy_verifier() {
        struct Root {
            allow: bool,
            calls: Cell<usize>,
        }
        impl crate::gov::GovernanceAttestationVerifier for Root {
            fn verify(&self, _: &[u8], _: &crate::gov::ExternalAttestation) -> Result<(), String> {
                self.calls.set(self.calls.get() + 1);
                if self.allow {
                    Ok(())
                } else {
                    Err("synthetic untrusted policy root".into())
                }
            }
        }
        let mut policy: Value = serde_json::from_str(&signed_policy()).unwrap();
        policy.as_object_mut().unwrap().remove("attestation");
        let external = SignedEnvelope::from_external_signature_v2(
            &policy.to_string(),
            "office-policy-root",
            "fixture",
            "fixture-key",
            "fixture-proof",
            7,
            "office",
        )
        .unwrap()
        .to_json();
        let root = Root {
            allow: true,
            calls: Cell::new(0),
        };
        let path = temp_store();
        let mut runtime =
            GovernedHostRuntime::open_with_verifier(&path, 7, &external, &root).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "external-recorded-runtime".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let start = runtime.pinned_position(&instance.instance_ref).unwrap();
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let original = runtime
            .run_turn_with_driver(
                &command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &resources,
                &ScriptedDriver::new(vec![
                    json!({"output_text":"original external-policy answer"}),
                ]),
            )
            .unwrap();
        let head = runtime.pinned_position(&instance.instance_ref).unwrap();
        let before = fs::read(&path).unwrap();
        let calls = root.calls.get();
        let reader =
            RecordedHostRuntime::open_with_verifier(&path, 7, &external, &root, &resources)
                .unwrap();
        assert_eq!(root.calls.get(), calls + 1);
        assert_eq!(
            reader
                .recorded_turn_execution(&command, &start, &resources)
                .unwrap(),
            Some(original)
        );
        let denied = Root {
            allow: false,
            calls: Cell::new(0),
        };
        assert!(
            RecordedHostRuntime::open_with_verifier(&path, 7, &external, &denied, &resources)
                .is_err()
        );
        assert_eq!(denied.calls.get(), 1);
        resources.allowed.set(false);
        let calls = root.calls.get();
        assert!(
            RecordedHostRuntime::open_with_verifier(&path, 7, &external, &root, &resources)
                .is_err()
        );
        assert_eq!(
            root.calls.get(),
            calls,
            "revoked open reached signature verification"
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert_eq!(
            runtime.pinned_position(&instance.instance_ref).unwrap(),
            head
        );
        drop(reader);
        drop(runtime);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recorded_turn_execution_checks_access_before_and_after_observation() {
        struct ReadAccess {
            calls: Cell<usize>,
            deny_at: usize,
        }
        impl ResourceResolver for ReadAccess {
            fn check_live_access(&self) -> Result<(), String> {
                self.calls.set(self.calls.get() + 1);
                if self.calls.get() >= self.deny_at {
                    Err("private staff detail".into())
                } else {
                    Ok(())
                }
            }
            fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
                unreachable!()
            }
            fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
                unreachable!()
            }
        }
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "saved-access-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let original_start = runtime.pinned_position(&instance.instance_ref).unwrap();
        runtime
            .run_turn_with_driver(
                &command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &resources,
                &ScriptedDriver::new(vec![json!({"output_text":"saved private answer"})]),
            )
            .unwrap();
        let reader = RecordedHostRuntime::open(&path, 7, &signed_policy(), &resources).unwrap();
        for deny_at in [1, 2] {
            let access = ReadAccess {
                calls: Cell::new(0),
                deny_at,
            };
            let error = match RecordedHostRuntime::open(&path, 7, &signed_policy(), &access) {
                Err(error) => error,
                Ok(_) => panic!("recorded open ignored current access"),
            };
            assert!(error.to_string().contains(LIVE_ACCESS_REFUSED));
            assert!(!error.to_string().contains("private staff detail"));
            assert_eq!(access.calls.get(), deny_at);
        }
        for (operation, calls) in [("execution", 4), ("witness", 8), ("guarantee", 6)] {
            for deny_at in 1..=calls {
                let access = ReadAccess {
                    calls: Cell::new(0),
                    deny_at,
                };
                let error = match operation {
                    "execution" => reader
                        .recorded_turn_execution(&command, &original_start, &access)
                        .unwrap_err(),
                    "witness" => reader
                        .turn_workspace_witness(&command, &original_start, &access)
                        .unwrap_err(),
                    "guarantee" => reader
                        .turn_guarantee_report(&command, &original_start, &access)
                        .unwrap_err(),
                    _ => unreachable!(),
                };
                assert!(
                    error.to_string().contains(LIVE_ACCESS_REFUSED),
                    "{operation} {deny_at}: {error}"
                );
                assert!(!error.to_string().contains("private staff detail"));
                assert!(access.calls.get() >= deny_at);
            }
        }
        for deny_at in [1, 2] {
            let access = ReadAccess {
                calls: Cell::new(0),
                deny_at,
            };
            let observed = Cell::new(false);
            let error = reader
                .observe(&command, &original_start, &access, |_| {
                    observed.set(true);
                    Ok("private original projection")
                })
                .unwrap_err();
            assert!(error.to_string().contains(LIVE_ACCESS_REFUSED));
            assert_eq!(observed.get(), deny_at == 2);
            assert_eq!(access.calls.get(), deny_at);
        }
        drop(reader);
        let before = runtime.pinned_position(&instance.instance_ref).unwrap();
        for deny_at in [1, 2] {
            let access = ReadAccess {
                calls: Cell::new(0),
                deny_at,
            };
            let error = runtime
                .recorded_turn_execution(&command, &access)
                .unwrap_err();
            assert!(error.to_string().contains(LIVE_ACCESS_REFUSED));
            assert!(!error.to_string().contains("private staff detail"));
            assert_eq!(access.calls.get(), deny_at);
        }
        assert_eq!(
            runtime.pinned_position(&instance.instance_ref).unwrap(),
            before
        );
        drop(runtime);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_driver_discards_response_and_latches_refusal() {
        struct RevokingDriver<'a> {
            resources: &'a LiveResources,
            calls: Cell<usize>,
        }
        impl HostDriver for RevokingDriver<'_> {
            fn fulfill(&self, _: &IoRequest) -> IoResult {
                self.calls.set(self.calls.get() + 1);
                self.resources.allowed.set(false);
                IoResult::Http(Ok(HttpResponse {
                    status: 200,
                    body: json!({"private":"response"}),
                }))
            }
        }
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let access = LiveTurnAccess::new(&resources);
        let inner = RevokingDriver {
            resources: &resources,
            calls: Cell::new(0),
        };
        let driver = LiveAccessDriver {
            inner: &inner,
            access: &access,
        };
        let request = IoRequest::Http(HttpRequest {
            model_provenance: None,
            url: "https://example.invalid".into(),
            headers: vec![],
            body: json!({}),
        });
        for _ in 0..2 {
            let IoResult::Http(result) = driver.fulfill(&request);
            assert!(
                matches!(result, Err(TransportError::Transport(ref text)) if text == LIVE_ACCESS_REFUSED)
            );
            resources.allowed.set(true);
        }
        assert_eq!(inner.calls.get(), 1);
        let denied = LiveResources {
            allowed: Cell::new(false),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let denied_access = LiveTurnAccess::new(&denied);
        let denied_driver = LiveAccessDriver {
            inner: &inner,
            access: &denied_access,
        };
        let IoResult::Http(result) = denied_driver.fulfill(&request);
        assert!(result.is_err());
        assert_eq!(inner.calls.get(), 1);
    }

    #[test]
    fn live_tool_discards_result_and_refuses_new_calls() {
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: true,
        };
        let access = LiveTurnAccess::new(&resources);
        let offered = [ToolSpec {
            name: "read".into(),
            description: "read".into(),
            input_schema: json!({}),
        }];
        let executor = ResolverToolExecutor {
            offered: &offered,
            admitted_resources: &[],
            resolver: &resources,
            access: &access,
        };
        let call = ToolCall {
            id: "call".into(),
            name: "read".into(),
            arguments: json!({}),
        };
        let outcome = executor.execute(&call);
        assert_eq!(outcome.status, ToolStatus::Error);
        assert_eq!(outcome.content, LIVE_ACCESS_REFUSED);
        resources.allowed.set(true);
        assert_eq!(executor.execute(&call).content, LIVE_ACCESS_REFUSED);
        assert_eq!(resources.tool_calls.get(), 1);
        let denied = LiveResources {
            allowed: Cell::new(false),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let denied_access = LiveTurnAccess::new(&denied);
        let executor = ResolverToolExecutor {
            offered: &offered,
            admitted_resources: &[],
            resolver: &denied,
            access: &denied_access,
        };
        assert_eq!(executor.execute(&call).content, LIVE_ACCESS_REFUSED);
        assert_eq!(denied.tool_calls.get(), 0);
    }

    #[test]
    fn live_turn_stops_after_tool_revocation_before_next_model_request() {
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "live-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: true,
        };
        let driver = ScriptedDriver::new(vec![
            json!({"output":[{"type":"function_call","call_id":"c1","name":"read","arguments":"{}"}]}),
        ]);
        let err = runtime
            .run_turn_with_driver(
                &turn(&instance.instance_ref, &open.policy, 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &resources,
                &driver,
            )
            .unwrap_err();
        assert!(err.to_string().contains(LIVE_ACCESS_REFUSED), "{err:?}");
        assert_eq!(resources.tool_calls.get(), 1);
        assert_eq!(driver.requests.borrow().len(), 1);
        drop(runtime);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn live_image_revocation_suppresses_resolver_failure_and_model_dispatch() {
        struct Images(Cell<bool>);
        impl ResourceResolver for Images {
            fn check_live_access(&self) -> Result<(), String> {
                if self.0.get() {
                    Ok(())
                } else {
                    Err("private denial".into())
                }
            }
            fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
                self.0.set(false);
                Err("private image failure".into())
            }
            fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
                unreachable!()
            }
        }
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "image-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let mut command = turn(&instance.instance_ref, &open.policy, 1);
        command.input.images.push(command.resources[0].clone());
        let driver = ScriptedDriver::new(vec![]);
        let error = runtime
            .run_turn_with_driver(
                &command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Images(Cell::new(true)),
                &driver,
            )
            .unwrap_err();
        assert!(error.to_string().contains(LIVE_ACCESS_REFUSED));
        assert!(!error.to_string().contains("private"));
        assert!(driver.requests.borrow().is_empty());
        drop(runtime);
        fs::remove_file(path).unwrap();
    }

    fn read_admission_probe_request(socket: &mut std::net::TcpStream) -> Vec<u8> {
        use std::io::Read;
        socket.set_nonblocking(false).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut chunk = [0; 4096];
        let start = loop {
            let n = socket.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(i) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break i + 4;
            }
        };
        let length: usize = String::from_utf8_lossy(&bytes[..start])
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        while bytes.len() < start + length {
            let n = socket.read(&mut chunk).unwrap();
            assert!(n > 0);
            bytes.extend_from_slice(&chunk[..n]);
        }
        bytes
    }

    fn accept_admission_probe(listener: &std::net::TcpListener) -> std::net::TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(7);
        loop {
            match listener.accept() {
                Ok((socket, _)) => return socket,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < deadline, "receiver timed out");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("receiver: {e}"),
            }
        }
    }

    #[test]
    fn native_request_admission_holds_embedding_writer_through_actual_governed_send() {
        use std::io::Write;
        struct LocalSecrets(String, std::net::SocketAddr);
        impl SecretResolver for LocalSecrets {
            fn resolve_provider(
                &self,
                _: &ProviderBindingRef,
                _: &str,
            ) -> Result<ResolvedProviderBinding, String> {
                Ok(ResolvedProviderBinding::new(
                    ModelProvider::OpenAi,
                    "synthetic-admission-key",
                    "gpt-test",
                    &self.0,
                    256,
                    Duration::from_secs(5),
                )
                .with_admitted_transport(
                    NativeProviderTransport::loopback_http(&self.0, vec![self.1]).unwrap(),
                ))
            }
        }
        struct AdmittingResources {
            writer: rusqlite::Connection,
            expected: StartTurnCommand,
            calls: Cell<u64>,
        }
        impl ResourceResolver for AdmittingResources {
            fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
                unreachable!()
            }
            fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
                unreachable!()
            }
            fn with_native_provider_request(
                &self,
                request: &NativeProviderRequest<'_>,
                send: &mut dyn FnMut(Duration) -> Result<(), String>,
            ) -> Result<(), String> {
                assert_eq!(request.command, &self.expected);
                assert!(request
                    .body
                    .to_string()
                    .contains("synthetic-admitted-prompt"));
                assert!(request.url.ends_with("/v1/responses"));
                assert!(request.transport_pinned);
                assert!(request.provenance.is_some());
                assert_eq!(request.ordinal, self.calls.get() + 1);
                assert_eq!(request.configured_timeout, Duration::from_secs(5));
                self.calls.set(request.ordinal);
                self.writer.execute_batch("BEGIN IMMEDIATE").unwrap();
                let result = send(Duration::from_secs(2));
                self.writer.execute_batch("COMMIT").unwrap();
                result
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let path = temp_store();
        let fence_path = path.with_extension("admission.sqlite");
        let writer = rusqlite::Connection::open(&fence_path).unwrap();
        writer
            .execute_batch(
                "CREATE TABLE approval (version INTEGER); INSERT INTO approval VALUES (1)",
            )
            .unwrap();
        let server_fence = fence_path.clone();
        let server = std::thread::spawn(move || {
            let mut socket = accept_admission_probe(&listener);
            let request = read_admission_probe_request(&mut socket);
            let competing = rusqlite::Connection::open(server_fence).unwrap();
            competing.busy_timeout(Duration::ZERO).unwrap();
            let error = competing
                .execute_batch("BEGIN IMMEDIATE; UPDATE approval SET version=2")
                .unwrap_err();
            assert_eq!(
                error.sqlite_error_code(),
                Some(rusqlite::ErrorCode::DatabaseBusy)
            );
            let body = r#"{"error":{"message":"synthetic provider refusal"}}"#;
            write!(socket,"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            request
        });
        let endpoint = format!("http://{address}");
        let mut runtime =
            GovernedHostRuntime::open(&path, 7, &signed_policy_at(&endpoint)).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "admission-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let mut command = turn(&instance.instance_ref, &open.policy, 1);
        command.input.text = "synthetic-admitted-prompt".into();
        let resources = AdmittingResources {
            writer,
            expected: command.clone(),
            calls: Cell::new(0),
        };
        let result = runtime.run_turn(
            &command,
            &Packages,
            &LocalSecrets(endpoint, address),
            &resources,
        );
        assert_eq!(result.unwrap().receipt.unwrap().status, TurnStatus::Failed);
        assert_eq!(resources.calls.get(), 1);
        let received = String::from_utf8(server.join().unwrap()).unwrap();
        assert!(received.contains("synthetic-admitted-prompt"));
        assert!(received.contains("synthetic-admission-key"));
        resources
            .writer
            .execute_batch("BEGIN IMMEDIATE; UPDATE approval SET version=2; COMMIT")
            .unwrap();
        drop(resources);
        drop(runtime);
        fs::remove_file(path).unwrap();
        fs::remove_file(fence_path).unwrap();
    }

    #[test]
    fn native_request_admission_refuses_observer_removal_before_pinned_receiver() {
        struct LocalSecrets(String, std::net::SocketAddr);
        impl SecretResolver for LocalSecrets {
            fn resolve_provider(
                &self,
                _: &ProviderBindingRef,
                _: &str,
            ) -> Result<ResolvedProviderBinding, String> {
                Ok(ResolvedProviderBinding::new(
                    ModelProvider::OpenAi,
                    "synthetic",
                    "gpt-test",
                    &self.0,
                    256,
                    Duration::from_secs(1),
                )
                .with_admitted_transport(
                    NativeProviderTransport::loopback_http(&self.0, vec![self.1]).unwrap(),
                ))
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = format!("http://{address}");
        let path = temp_store();
        let mut runtime =
            GovernedHostRuntime::open(&path, 7, &signed_policy_at(&endpoint)).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "removal-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let resources = LiveResources {
            allowed: Cell::new(true),
            tool_calls: Cell::new(0),
            revoke_on_tool: false,
        };
        let observer_calls = Cell::new(0);
        let observer =
            |_: &Value, _: Option<&whipplescript_kernel::sansio::ModelRequestProvenance>| {
                observer_calls.set(observer_calls.get() + 1);
                resources.allowed.set(false);
            };
        let result = runtime.run_turn_observing_model_requests(
            &turn(&instance.instance_ref, &open.policy, 1),
            &Packages,
            &LocalSecrets(endpoint, address),
            &resources,
            &observer,
        );
        assert!(result.is_err());
        assert_eq!(observer_calls.get(), 1);
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(runtime);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_request_admission_refusal_and_invalid_send_end_driver_without_fallback() {
        use std::io::Write;
        for case in [
            "deny",
            "no-send",
            "zero",
            "widen",
            "duplicate",
            "after-send",
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let endpoint = format!("http://{address}");
            let server = if matches!(case, "duplicate" | "after-send") {
                let receiver = listener.try_clone().unwrap();
                Some(std::thread::spawn(move || {
                    let mut socket = accept_admission_probe(&receiver);
                    let received = read_admission_probe_request(&mut socket);
                    let body = r#"{"synthetic":"actual response"}"#;
                    write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
                    received
                }))
            } else {
                None
            };
            let command = turn(
                "synthetic-instance",
                &PolicyEpochRef {
                    epoch: 7,
                    envelope_hash: "synthetic".into(),
                    signer: "synthetic".into(),
                    key_id: None,
                },
                1,
            );
            let binding = ResolvedProviderBinding::new(
                ModelProvider::OpenAi,
                "synthetic",
                "gpt-test",
                &endpoint,
                256,
                Duration::from_millis(100),
            )
            .with_admitted_transport(
                NativeProviderTransport::loopback_http(&endpoint, vec![address]).unwrap(),
            );
            let admission_calls = Cell::new(0);
            let admit =
                |request: &NativeProviderRequest<'_>,
                 send: &mut dyn FnMut(Duration) -> Result<(), String>| {
                    admission_calls.set(admission_calls.get() + 1);
                    assert_eq!(request.ordinal, 1);
                    match case {
                        "deny" => Err("private approval detail".into()),
                        "no-send" => Ok(()),
                        "zero" => {
                            let _ = send(Duration::ZERO);
                            Ok(())
                        }
                        "widen" => {
                            let _ = send(Duration::from_secs(1));
                            Ok(())
                        }
                        "duplicate" => {
                            send(request.configured_timeout)?;
                            let _ = send(request.configured_timeout);
                            Ok(())
                        }
                        "after-send" => {
                            send(request.configured_timeout)?;
                            Err("private approval detail".into())
                        }
                        _ => unreachable!(),
                    }
                };
            let driver = NativeHttpDriver::for_binding(&binding)
                .unwrap()
                .with_request_admission(&command, &admit);
            let request = IoRequest::Http(whipplescript_kernel::sansio::HttpRequest {
                model_provenance: None,
                url: format!("{endpoint}/v1/responses"),
                headers: vec![],
                body: json!({"synthetic":"request"}),
            });
            for _ in 0..2 {
                let IoResult::Http(result) = driver.fulfill(&request);
                assert!(
                    matches!(result, Err(TransportError::Transport(ref text)) if text == "native provider request admission refused"),
                    "{case}: {result:?}"
                );
            }
            assert_eq!(admission_calls.get(), 1, "{case}");
            if let Some(server) = server {
                assert!(!server.join().unwrap().is_empty());
            }
            listener.set_nonblocking(true).unwrap();
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock,
                "{case}: extra send"
            );
        }
    }

    #[test]
    fn native_request_admission_correlates_each_send_and_preserves_actual_response() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for ordinal in 1..=2 {
                let mut socket = accept_admission_probe(&listener);
                let bytes = read_admission_probe_request(&mut socket);
                assert!(String::from_utf8_lossy(&bytes).contains(&format!("round-{ordinal}")));
                let body = format!("{{\"receiver_round\":{ordinal}}}");
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            }
        });
        let endpoint = format!("http://{address}");
        let command = turn(
            "synthetic-instance",
            &PolicyEpochRef {
                epoch: 7,
                envelope_hash: "synthetic".into(),
                signer: "synthetic".into(),
                key_id: None,
            },
            1,
        );
        let binding = ResolvedProviderBinding::new(
            ModelProvider::OpenAi,
            "synthetic",
            "gpt-test",
            &endpoint,
            256,
            Duration::from_secs(2),
        )
        .with_admitted_transport(
            NativeProviderTransport::loopback_http(&endpoint, vec![address]).unwrap(),
        );
        let calls = Cell::new(0);
        let admit = |request: &NativeProviderRequest<'_>,
                     send: &mut dyn FnMut(Duration) -> Result<(), String>| {
            assert_eq!(request.command, &command);
            assert_eq!(request.ordinal, calls.get() + 1);
            assert_eq!(
                request.body["synthetic"],
                format!("round-{}", request.ordinal)
            );
            calls.set(request.ordinal);
            send(Duration::from_secs(1))
        };
        let driver = NativeHttpDriver::for_binding(&binding)
            .unwrap()
            .with_request_admission(&command, &admit);
        for ordinal in 1..=2 {
            let request = IoRequest::Http(whipplescript_kernel::sansio::HttpRequest {
                model_provenance: None,
                url: format!("{endpoint}/v1/responses"),
                headers: vec![],
                body: json!({"synthetic":format!("round-{ordinal}")}),
            });
            let IoResult::Http(result) = driver.fulfill(&request);
            assert_eq!(result.unwrap().body["receiver_round"], ordinal);
        }
        assert_eq!(calls.get(), 2);
        server.join().unwrap();
    }

    #[test]
    fn native_request_admission_refuses_ordinal_overflow_before_receiver() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = format!("http://{address}");
        let command = turn(
            "synthetic-instance",
            &PolicyEpochRef {
                epoch: 7,
                envelope_hash: "synthetic".into(),
                signer: "synthetic".into(),
                key_id: None,
            },
            1,
        );
        let binding = ResolvedProviderBinding::new(
            ModelProvider::OpenAi,
            "synthetic",
            "gpt-test",
            &endpoint,
            256,
            Duration::from_millis(100),
        )
        .with_admitted_transport(
            NativeProviderTransport::loopback_http(&endpoint, vec![address]).unwrap(),
        );
        let calls = Cell::new(0);
        let admit = |_: &NativeProviderRequest<'_>,
                     _: &mut dyn FnMut(Duration) -> Result<(), String>| {
            calls.set(calls.get() + 1);
            Ok(())
        };
        let driver = NativeHttpDriver::for_binding(&binding)
            .unwrap()
            .with_request_admission(&command, &admit);
        driver.request_ordinal.set(u64::MAX);
        let request = IoRequest::Http(whipplescript_kernel::sansio::HttpRequest {
            model_provenance: None,
            url: format!("{endpoint}/v1/responses"),
            headers: vec![],
            body: json!({}),
        });
        for _ in 0..2 {
            let IoResult::Http(result) = driver.fulfill(&request);
            assert!(
                matches!(result, Err(TransportError::Transport(ref text)) if text == "native provider request admission refused")
            );
        }
        assert_eq!(calls.get(), 0);
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn native_request_admission_narrows_actual_transport_timeout() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut socket = accept_admission_probe(&listener);
            let received = read_admission_probe_request(&mut socket);
            std::thread::sleep(Duration::from_millis(300));
            let _ = write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}");
            received
        });
        let endpoint = format!("http://{address}");
        let command = turn(
            "synthetic-instance",
            &PolicyEpochRef {
                epoch: 7,
                envelope_hash: "synthetic".into(),
                signer: "synthetic".into(),
                key_id: None,
            },
            1,
        );
        let binding = ResolvedProviderBinding::new(
            ModelProvider::OpenAi,
            "synthetic",
            "gpt-test",
            &endpoint,
            256,
            Duration::from_secs(5),
        )
        .with_admitted_transport(
            NativeProviderTransport::loopback_http(&endpoint, vec![address]).unwrap(),
        );
        let admit = |_: &NativeProviderRequest<'_>,
                     send: &mut dyn FnMut(Duration) -> Result<(), String>| {
            send(Duration::from_millis(100))
        };
        let driver = NativeHttpDriver::for_binding(&binding)
            .unwrap()
            .with_request_admission(&command, &admit);
        let request = IoRequest::Http(whipplescript_kernel::sansio::HttpRequest {
            model_provenance: None,
            url: format!("{endpoint}/v1/responses"),
            headers: vec![],
            body: json!({"synthetic":"request"}),
        });
        let IoResult::Http(result) = driver.fulfill(&request);
        assert!(
            matches!(
                result,
                Err(TransportError::Timeout | TransportError::Transport(_))
            ),
            "{result:?}"
        );
        assert!(!server.join().unwrap().is_empty());
    }

    #[test]
    fn native_governed_turn_refuses_changed_admitted_transport_before_receiver() {
        struct ChangedTransport(String, std::net::SocketAddr);
        impl SecretResolver for ChangedTransport {
            fn resolve_provider(
                &self,
                _: &ProviderBindingRef,
                _: &str,
            ) -> Result<ResolvedProviderBinding, String> {
                let transport = NativeProviderTransport::loopback_http(
                    &format!("{}/changed", self.0),
                    vec![self.1],
                )
                .unwrap();
                Ok(ResolvedProviderBinding::new(
                    ModelProvider::OpenAi,
                    "synthetic",
                    "gpt-test",
                    &self.0,
                    256,
                    Duration::from_secs(1),
                )
                .with_admitted_transport(transport))
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let endpoint = format!("http://{address}");
        let path = temp_store();
        let mut runtime =
            GovernedHostRuntime::open(&path, 7, &signed_policy_at(&endpoint)).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "transport-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let error = runtime
            .run_turn(
                &turn(&instance.instance_ref, &open.policy, 1),
                &Packages,
                &ChangedTransport(endpoint, address),
                &Resources {
                    calls: Cell::new(0),
                },
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("admitted provider transport refused"));
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(runtime);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn live_native_turn_releases_stream_when_first_delta_revokes_access() {
        for pinned in [false, true] {
            use std::io::{Read, Write};
            struct LocalSecrets(String, bool);
            impl SecretResolver for LocalSecrets {
                fn resolve_provider(
                    &self,
                    _: &ProviderBindingRef,
                    _: &str,
                ) -> Result<ResolvedProviderBinding, String> {
                    let binding = ResolvedProviderBinding::new(
                        ModelProvider::OpenAi,
                        "synthetic",
                        "gpt-test",
                        &self.0,
                        256,
                        Duration::from_secs(5),
                    );
                    if self.1 {
                        let address = self.0.strip_prefix("http://").unwrap().parse().unwrap();
                        let transport =
                            NativeProviderTransport::loopback_http(&self.0, vec![address])
                                .map_err(|_| "synthetic transport refused".to_owned())?;
                        Ok(binding.with_admitted_transport(transport))
                    } else {
                        Ok(binding)
                    }
                }
            }
            struct StreamResources {
                live: LiveResources,
                deltas: RefCell<Vec<String>>,
            }
            impl ResourceResolver for StreamResources {
                fn check_live_access(&self) -> Result<(), String> {
                    self.live.check_live_access()
                }
                fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
                    unreachable!()
                }
                fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
                    unreachable!()
                }
                fn observe_text_delta(&self, delta: &str) {
                    self.deltas.borrow_mut().push(delta.into());
                    self.live.allowed.set(false);
                }
            }
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                let header_end = loop {
                    let n = socket.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(start) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        break start + 4;
                    }
                };
                let headers = std::str::from_utf8(&bytes[..header_end]).unwrap();
                let length: usize = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .expect("model request has a bounded JSON body");
                while bytes.len() < header_end + length {
                    let n = socket.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                }
                let body = concat!(
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"first\"}\n\n",
                "data: {\"type\":\"response.output_text.delta\",\"delta\":\"private later delta\"}\n\n",
                "data: [DONE]\n\n");
                write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            });
            let path = temp_store();
            let mut runtime = GovernedHostRuntime::open(
                &path,
                7,
                &signed_policy_at(&format!("http://{address}")),
            )
            .unwrap();
            let open = OpenInstanceCommand {
                protocol: HOST_PROTOCOL.into(),
                request_id: "stream-open".into(),
                package_version_ref: "package:v1".into(),
                policy: runtime.policy_ref().clone(),
            };
            let instance = runtime.open_instance(&open, &Packages).unwrap();
            let resources = StreamResources {
                live: LiveResources {
                    allowed: Cell::new(true),
                    tool_calls: Cell::new(0),
                    revoke_on_tool: false,
                },
                deltas: RefCell::new(vec![]),
            };
            let err = runtime
                .run_turn(
                    &turn(&instance.instance_ref, &open.policy, 1),
                    &Packages,
                    &LocalSecrets(format!("http://{address}"), pinned),
                    &resources,
                )
                .unwrap_err();
            assert!(err.to_string().contains(LIVE_ACCESS_REFUSED), "{err:?}");
            assert_eq!(&*resources.deltas.borrow(), &["first"]);
            server.join().unwrap();
            drop(runtime);
            fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn an_invalid_image_does_not_release_content_or_allow_changed_command_replay() {
        struct MissingMedia;
        impl ResourceResolver for MissingMedia {
            fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
                Ok(ResolvedImage {
                    media_type: " ".into(),
                    bytes: b"private image".to_vec(),
                })
            }
            fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
                unreachable!()
            }
        }
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "media-open".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let mut command = turn(&instance.instance_ref, &open.policy, 1);
        command.input.images.push(command.resources[0].clone());
        let driver = ScriptedDriver::new(vec![json!({"output_text":"must not be requested"})]);
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let err = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &MissingMedia, &driver)
            .unwrap_err();
        assert!(
            err.to_string().contains("resolved image has no media type"),
            "{err:?}"
        );
        assert!(driver.requests.borrow().is_empty());
        // Image resolution follows durable effect admission. A subsequent
        // invocation cannot use that command identity for different input.
        command.input.text = "changed task".into();
        let err = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &MissingMedia, &driver)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("command id reused with different turn"),
            "{err:?}"
        );
        assert!(driver.requests.borrow().is_empty());
        drop(runtime);
        fs::remove_file(path).unwrap();
    }

    struct CancellingDriver {
        handle: HostCancellationHandle,
        fired: Cell<bool>,
    }

    impl HostDriver for CancellingDriver {
        fn fulfill(&self, _request: &IoRequest) -> IoResult {
            assert!(
                !self.fired.replace(true),
                "cancelled before a second request"
            );
            self.handle.request().expect("cancel request records");
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: json!({
                    "output": [{
                        "type": "function_call",
                        "call_id": "call-before-cancel",
                        "name": "read",
                        "arguments": "{\"path\":\"README.md\"}"
                    }],
                    "usage": { "input_tokens": 10, "output_tokens": 2 }
                }),
            }))
        }
    }

    fn signed_policy() -> String {
        signed_policy_at("https://provider.invalid")
    }

    fn signed_policy_at(base_url: &str) -> String {
        SignedEnvelope::sign_for_test(
            &test_policy(base_url, "file:/workspace", &[])
                .to_json()
                .expect("policy"),
            "gaugedesk-admin",
        )
        .to_json()
    }

    /// The test policy with what an epoch advance may change named: the
    /// address `project` binds to, and further addresses governed beside it.
    fn test_policy(
        base_url: &str,
        project_address: &str,
        extra_addresses: &[&str],
    ) -> HostGovernancePolicy {
        let labeled = |principal| ResourcePolicy {
            reader: BTreeSet::from(["Operator".to_owned()]),
            writer: BTreeSet::from(["Operator".to_owned()]),
            principal,
            internal: false,
        };
        let mut resources = BTreeMap::from([
            (project_address.to_owned(), labeled(false)),
            ("provider:openai".to_owned(), labeled(true)),
            ("provider:owned".to_owned(), labeled(true)),
            ("placement:local".to_owned(), labeled(true)),
        ]);
        for address in extra_addresses {
            resources.insert((*address).to_owned(), labeled(false));
        }
        HostGovernancePolicy {
            resources,
            bindings: BTreeMap::from([
                ("project".to_owned(), project_address.to_owned()),
                ("model".to_owned(), "provider:openai".to_owned()),
                ("owned".to_owned(), "provider:owned".to_owned()),
                ("local".to_owned(), "placement:local".to_owned()),
            ]),
            capabilities: BTreeSet::from([
                "workspace.read".to_owned(),
                "workspace.write".to_owned(),
                "command.run".to_owned(),
            ]),
            provider_bindings: BTreeMap::from([(
                "model".to_owned(),
                ProviderBindingPolicy {
                    provider: "openai".to_owned(),
                    model: "gpt-test".to_owned(),
                    base_url: base_url.to_owned(),
                    credential_ref: "credential:model".to_owned(),
                    wire: None,
                },
            )]),
            placements: BTreeMap::from([(
                "local".to_owned(),
                PlacementPolicy {
                    kind: "local".to_owned(),
                    provider_bindings: BTreeSet::from(["model".to_owned()]),
                    command_network: false,
                },
            )]),
            parties: BTreeMap::from([("operator".to_owned(), "Operator".to_owned())]),
            ..HostGovernancePolicy::default()
        }
    }

    /// One epoch of the test policy, signed by `signer` and speaking for
    /// `authority` when it names one.
    fn epoch_policy(
        project_address: &str,
        extra_addresses: &[&str],
        signer: &str,
        authority: Option<&str>,
    ) -> String {
        let mut policy: Value = serde_json::from_str(
            &test_policy("https://provider.invalid", project_address, extra_addresses)
                .to_json()
                .expect("policy"),
        )
        .expect("policy json");
        if let Some(authority) = authority {
            policy["authority"] = json!(authority);
        }
        SignedEnvelope::sign_for_test(&policy.to_string(), signer).to_json()
    }

    /// DR-0062 §4: the refusal lands at policy-load time, not at the first turn
    /// that would have leaked. The endpoint here is registered but bare -- no
    /// pin, nothing filed -- so it sits at the floor while the envelope demands
    /// zero-retention of Operator data.
    #[test]
    fn a_policy_whose_endpoint_under_clears_its_role_is_refused_at_load() {
        let path = temp_store();
        let policy_text = SignedEnvelope::sign_for_test(
            "delegate provider:builtin-agent-harness acts-for Operator for confidentiality\n\
             require custody zero-retention for Operator\n",
            "admin",
        )
        .to_json();

        let error = GovernedHostRuntime::open(&path, 1, &policy_text)
            .err()
            .expect("an unattested endpoint must not carry Operator data");
        let message = format!("{error:?}");
        assert!(message.contains("pinned endpoint"), "{message}");

        // The same policy passes once the evidence actually supports it: pin the
        // endpoint, then record that the operator runs it.
        {
            let store = SqliteStore::open(&path).expect("store");
            let config = store
                .effect_provider_config(AGENT_TURN_EFFECT_KIND, "builtin-agent-harness")
                .expect("config")
                .expect("seeded provider");
            let digest = whipplescript_kernel::provider_trust::endpoint_digest(&config);
            store
                .pin_provider_endpoint(AGENT_TURN_EFFECT_KIND, "builtin-agent-harness", &digest)
                .expect("pin");
            store
                .set_provider_operator_run(AGENT_TURN_EFFECT_KIND, "builtin-agent-harness", true)
                .expect("operator run");
        }
        GovernedHostRuntime::open(&path, 1, &policy_text).expect("admissible now");
    }

    /// The same refusal under `authority acme`: the delegation edge then names
    /// `acme::Operator`, and the demand has to be found under that role. It
    /// was stored bare, so every authority-qualified policy loaded as if it
    /// had declared no demand at all.
    #[test]
    fn an_authority_qualified_policy_keeps_its_custody_demand() {
        let path = temp_store();
        let policy_text = SignedEnvelope::sign_for_test(
            "authority acme\n\
             delegate provider:builtin-agent-harness acts-for Operator for confidentiality\n\
             require custody zero-retention for Operator\n",
            "admin",
        )
        .to_json();

        let error = GovernedHostRuntime::open(&path, 1, &policy_text)
            .err()
            .expect("an unattested endpoint must not carry acme::Operator data");
        let message = format!("{error:?}");
        assert!(message.contains("pinned endpoint"), "{message}");
        assert!(message.contains("acme::Operator"), "{message}");
    }

    /// DR-0062: `schema.coerce` is as real a model-egress door as `agent.tell`,
    /// so custody is demanded of a coerce backend too. This endpoint is
    /// registered only under `schema.coerce`, and the check has to find it there
    /// rather than looking only at the turn kind.
    #[test]
    fn a_coerce_only_endpoint_must_clear_its_role_too() {
        let path = temp_store();
        let policy_text = SignedEnvelope::sign_for_test(
            "delegate provider:builtin-coerce acts-for Operator for confidentiality\n\
             require custody zero-retention for Operator\n",
            "admin",
        )
        .to_json();

        let error = GovernedHostRuntime::open(&path, 1, &policy_text)
            .err()
            .expect("an unattested coerce backend must not carry Operator data");
        let message = format!("{error:?}");
        assert!(message.contains("pinned endpoint"), "{message}");
        assert!(
            message.contains("schema.coerce"),
            "the refusal must name the effect kind it judged: {message}"
        );

        {
            let store = SqliteStore::open(&path).expect("store");
            let config = store
                .effect_provider_config("schema.coerce", "builtin-coerce")
                .expect("config")
                .expect("seeded provider");
            let digest = whipplescript_kernel::provider_trust::endpoint_digest(&config);
            store
                .pin_provider_endpoint("schema.coerce", "builtin-coerce", &digest)
                .expect("pin");
            store
                .set_provider_operator_run("schema.coerce", "builtin-coerce", true)
                .expect("operator run");
        }
        GovernedHostRuntime::open(&path, 1, &policy_text).expect("admissible now");
    }

    /// A role the envelope says nothing about places no demand, so zero setup
    /// keeps working -- the endpoint is simply public-only.
    #[test]
    fn a_policy_with_no_custody_demand_loads_against_a_bare_endpoint() {
        let path = temp_store();
        let policy_text = SignedEnvelope::sign_for_test(
            "delegate provider:builtin-agent-harness acts-for Operator for confidentiality\n",
            "admin",
        )
        .to_json();
        GovernedHostRuntime::open(&path, 1, &policy_text).expect("unconstrained");
    }

    /// Drift is caught at load: the pin was taken against one deployment and the
    /// endpoint now resolves to another, so the claim stops counting.
    #[test]
    fn a_drifted_endpoint_is_refused_even_with_a_current_claim() {
        let path = temp_store();
        {
            let store = SqliteStore::open(&path).expect("store");
            store
                .pin_provider_endpoint(
                    AGENT_TURN_EFFECT_KIND,
                    "builtin-agent-harness",
                    "sha256:a-deployment-this-no-longer-is",
                )
                .expect("pin");
            store
                .file_provider_custody_claim(whipplescript_store::ProviderCustodyClaim {
                    effect_kind: AGENT_TURN_EFFECT_KIND,
                    provider: "builtin-agent-harness",
                    class: "operator-held",
                    signer: "ops@acme.com",
                    filed_at: "2026-08-07T00:00:00Z",
                    expires_at: "2099-01-01T00:00:00Z",
                })
                .expect("claim");
        }
        let policy_text = SignedEnvelope::sign_for_test(
            "delegate provider:builtin-agent-harness acts-for Operator for confidentiality\n\
             require custody zero-retention for Operator\n",
            "admin",
        )
        .to_json();
        let error = GovernedHostRuntime::open(&path, 1, &policy_text)
            .err()
            .expect("testimony about a deployment this no longer is must not count");
        assert!(format!("{error:?}").contains("pinned endpoint"));
    }

    /// A turn where the model narrates *alongside* a tool call — one Assistant
    /// message carrying both text and a `read` — then closes with a text-only
    /// message. The folded `assistant_text` keeps only the closing line, but
    /// `segments` preserves every prose run in the order it was produced,
    /// interleaved with the call it introduced. Before segments existed, the
    /// mid-turn narration ("Let me check the file.") was dropped on the floor:
    /// a turn that narrated its work projected as if it had said nothing until
    /// the end.
    #[test]
    fn segments_preserve_prose_interleaved_with_the_calls_it_introduced() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).expect("instance");
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let resources = Resources {
            calls: Cell::new(0),
        };
        let driver = ScriptedDriver::new(vec![
            // One message: narration and a tool call, spoken together.
            json!({
                "output": [
                    { "type": "message", "content": [{ "text": "Let me check the file." }] },
                    {
                        "type": "function_call",
                        "call_id": "call-1",
                        "name": "read",
                        "arguments": "{\"path\":\"README.md\"}"
                    }
                ],
                "usage": { "input_tokens": 10, "output_tokens": 2 }
            }),
            // A closing text-only message.
            json!({
                "output_text": "Done — it reads clean.",
                "usage": { "input_tokens": 14, "output_tokens": 3 }
            }),
        ]);
        let execution = runtime
            .run_turn_with_driver(
                &turn(&instance.instance_ref, &open.policy, 1),
                &Packages,
                &secrets,
                &resources,
                &driver,
            )
            .expect("turn");
        let output = execution.output.expect("labeled output projection");

        // The fold still answers "what did it conclude": the closing line, and
        // the flat set of calls that ran.
        assert_eq!(output.assistant_text, "Done — it reads clean.");
        assert_eq!(output.tool_calls.len(), 1);
        assert_eq!(output.tool_calls[0].name, "read");

        // The ordered view keeps the mid-turn narration the fold discards, in
        // the position it was spoken: prose, the call it introduced, prose.
        assert_eq!(output.segments.len(), 3);
        assert_eq!(
            output.segments[0],
            TurnContentSegment::Prose("Let me check the file.".to_owned())
        );
        match &output.segments[1] {
            TurnContentSegment::Tool(call) => {
                assert_eq!(call.name, "read");
                assert_eq!(call.result.as_deref(), Some("governed file body"));
                assert_eq!(call.ok, Some(true));
            }
            other => panic!("expected the read call in position 1, got {other:?}"),
        }
        assert_eq!(
            output.segments[2],
            TurnContentSegment::Prose("Done — it reads clean.".to_owned())
        );
    }

    fn temp_store() -> std::path::PathBuf {
        static NEXT_STORE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let sequence = NEXT_STORE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "whip-host-runtime-{}-{nonce}-{sequence}.sqlite",
            std::process::id()
        ))
    }

    fn turn(instance_ref: &str, policy: &PolicyEpochRef, number: usize) -> StartTurnCommand {
        turn_with_package(instance_ref, policy, number, "package:v1")
    }

    fn turn_with_package(
        instance_ref: &str,
        policy: &PolicyEpochRef,
        number: usize,
        package_version_ref: &str,
    ) -> StartTurnCommand {
        StartTurnCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            command_id: format!("command-{number}"),
            run_ref: format!("gaugedesk:run:{number}"),
            instance_ref: instance_ref.to_owned(),
            package_version_ref: package_version_ref.to_owned(),
            policy: policy.clone(),
            actor_ref: "operator".to_owned(),
            input: TurnInput {
                text: format!("turn {number}"),
                images: Vec::new(),
            },
            resources: vec![ResourceRef {
                handle: "project".to_owned(),
                kind: "file_store".to_owned(),
                selector: None,
                writable: None,
                presented_as: None,
            }],
            provider_binding: ProviderBindingRef {
                binding_id: "model".to_owned(),
                credential: CredentialRef {
                    credential_id: "credential:model".to_owned(),
                },
            },
            placement_ceiling_ref: "local".to_owned(),
        }
    }

    #[test]
    fn host_action_instances_do_not_replace_the_latest_recoverable_chat() {
        use whipplescript_store::host_actions::conformance;
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let version = conformance::register(runtime.kernel.store_mut());
        let mut action = conformance::action(&version);
        // The deterministic suffix sorts after the chat when timestamps tie.
        action.instance_id = "ins_zz_action";
        runtime
            .kernel
            .store_mut()
            .admit_host_action(action)
            .unwrap();
        assert!(runtime.newest_recorded_instance().unwrap().is_none());
        let chat = runtime
            .open_instance(
                &OpenInstanceCommand {
                    protocol: HOST_PROTOCOL.into(),
                    request_id: "chat-after-action".into(),
                    package_version_ref: "package:v1".into(),
                    policy: runtime.policy_ref().clone(),
                },
                &Packages,
            )
            .unwrap();
        action.instance_id = "ins_zzz_later_action";
        action.input_facts = &[];
        runtime
            .kernel
            .store_mut()
            .admit_host_action(action)
            .unwrap();
        assert_eq!(
            runtime
                .newest_recorded_instance()
                .unwrap()
                .unwrap()
                .instance_ref,
            chat.instance_ref
        );
        drop(runtime);
        let reopened = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        assert_eq!(
            reopened
                .newest_recorded_instance()
                .unwrap()
                .unwrap()
                .instance_ref,
            chat.instance_ref
        );
        drop(reopened);
        fs::remove_file(path).unwrap();
    }

    fn rank(last_activity_at: &str, reach: i64, created_at: &str, id: &str) -> AdoptionRank {
        AdoptionRank {
            last_activity_at: last_activity_at.to_owned(),
            reach,
            created_at: created_at.to_owned(),
            instance_id: id.to_owned(),
        }
    }

    /// What the adoption order means, stated on the key itself: recency of
    /// ACTIVITY decides, and everything below it only settles what activity
    /// leaves tied.
    ///
    /// The first case is the one the store cannot state. A carrier created at
    /// `:00` and worked at `:02` outranks a shim created at `:01` and never
    /// touched since — but `instances.updated_at` reads `:00` for that carrier
    /// and `:01` for that shim, so an order keyed on the projection column
    /// inverts it. Pinning the rule here rather than only end-to-end keeps it
    /// stated in a form no wall clock participates in.
    #[test]
    fn adoption_rank_puts_activity_above_creation_and_stays_total() {
        let carrier = rank("2026-09-16 12:00:02", 4, "2026-09-16 12:00:00", "ins_a");
        let shim = rank("2026-09-16 12:00:01", 1, "2026-09-16 12:00:01", "ins_z");
        assert!(
            carrier > shim,
            "the worked-in instance outranks one created later and left alone"
        );

        let same_second = rank("2026-09-16 12:00:01", 4, "2026-09-16 12:00:00", "ins_a");
        assert!(
            same_second > shim,
            "within one second, the log that has got further is the live one"
        );

        let shallower_but_older = rank("2026-09-16 12:00:01", 1, "2026-09-16 12:00:00", "ins_z");
        assert!(
            shim > shallower_but_older,
            "activity and reach tied, creation order decides"
        );
        assert!(
            rank("2026-09-16 12:00:01", 1, "2026-09-16 12:00:01", "ins_z")
                > rank("2026-09-16 12:00:01", 1, "2026-09-16 12:00:01", "ins_a"),
            "identical candidates still resolve the same way on every run"
        );
    }

    /// Wait until the store's clock has entered a new second.
    ///
    /// `CURRENT_TIMESTAMP` has one-second resolution, so two writes in one
    /// second carry the same timestamp and a test that means to separate them
    /// has to say so. Sleeping a fixed span would only make the separation
    /// LIKELY; sleeping out the remainder of the current second makes it
    /// certain, and costs less than a second to do it.
    fn cross_a_store_second() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after the epoch");
        let into_the_second = Duration::from_nanos(u64::from(now.subsec_nanos()));
        std::thread::sleep(Duration::from_millis(1050) - into_the_second);
    }

    /// The adoption source is the instance whose thread the host means to keep —
    /// the most recently ACTIVE one, not the most recently created.
    ///
    /// A migration shim opened after the real thread's instance must not win the
    /// pick: an adoption seeded from it carries nothing. The shim is opened
    /// second here, so under the old `(created_at, instance_id)` order it was
    /// exactly what got picked.
    ///
    /// The second boundary between the two opens is the point of the test, not
    /// scaffolding around it. Without it both instances are created in the same
    /// second, every ordering that has ever been written here ties on its first
    /// key, and the reach tiebreak carries the pick regardless — so the test
    /// passed under an ordering keyed on `instances.updated_at`, which does not
    /// move when a turn runs and therefore ranked the shim above a carrier that
    /// had done all the work. That defect surfaced as one failure in a loaded
    /// `scripts/check.sh` run on 2026-09-16 and passed on the immediate re-run.
    /// Crossing the second deliberately makes the carrier's creation strictly
    /// older than the shim's, which is the only arrangement in which the pick
    /// has to consult activity at all.
    #[test]
    fn newest_recorded_instance_prefers_activity_over_creation() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 9, &policy_text).expect("runtime");
        let carrier = runtime
            .open_instance(
                &OpenInstanceCommand {
                    protocol: HOST_PROTOCOL.to_owned(),
                    request_id: "open-thread-carrier".to_owned(),
                    package_version_ref: "package:v1".to_owned(),
                    policy: runtime.policy_ref().clone(),
                },
                &Packages,
            )
            .expect("thread carrier");
        cross_a_store_second();
        let shim = runtime
            .open_instance(
                &OpenInstanceCommand {
                    protocol: HOST_PROTOCOL.to_owned(),
                    request_id: "open-migration-shim".to_owned(),
                    package_version_ref: "package:v1".to_owned(),
                    policy: runtime.policy_ref().clone(),
                },
                &Packages,
            )
            .expect("migration shim opened after the carrier");

        // The carrier is where activity happens.
        runtime
            .run_turn(
                &turn(&carrier.instance_ref, &runtime.policy_ref().clone(), 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
            )
            .expect("carrier turn");

        let picked = runtime
            .newest_recorded_instance()
            .expect("pick succeeds")
            .expect("store has instances")
            .instance_ref;
        assert_ne!(
            picked, shim.instance_ref,
            "the shim was created last, in a later second, and carries no work"
        );
        assert_eq!(
            picked, carrier.instance_ref,
            "activity outranks creation order"
        );
        drop(runtime);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn persistent_owned_turn_reopens_with_transcript_and_never_persists_secret() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).expect("instance");
        instance.validate_for(&open).expect("opened binding");

        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let resources = Resources {
            calls: Cell::new(0),
        };
        let mut unknown_actor = turn(&instance.instance_ref, &open.policy, 0);
        unknown_actor.actor_ref = "unknown".to_owned();
        let denied = runtime
            .run_turn_with_driver(
                &unknown_actor,
                &Packages,
                &secrets,
                &resources,
                &ScriptedDriver::new(Vec::new()),
            )
            .expect_err("unknown actor must not exceed the public ceiling");
        assert!(denied.to_string().contains("denied read in rule"));
        assert_eq!(secrets.calls.get(), 0, "denied actor resolves no secret");
        let first_driver = ScriptedDriver::new(vec![
            json!({
                "output": [{
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "read",
                    "arguments": "{\"path\":\"README.md\"}"
                }],
                "usage": { "input_tokens": 10, "output_tokens": 2 }
            }),
            json!({
                "output_text": "first answer",
                "usage": { "input_tokens": 14, "output_tokens": 3 }
            }),
        ]);
        let first = runtime
            .run_turn_with_driver(
                &turn(&instance.instance_ref, &open.policy, 1),
                &Packages,
                &secrets,
                &resources,
                &first_driver,
            )
            .expect("first turn");
        let first_receipt = first.receipt.as_ref().expect("terminal receipt");
        assert_eq!(first_receipt.status, TurnStatus::Completed);
        assert!(!first.events.is_empty());
        let first_output = first.output.expect("labeled output projection");
        assert_eq!(first_output.output_handle, first_receipt.output_handle);
        assert_eq!(first_output.assistant_text, "first answer");
        assert_eq!(first_output.tool_calls.len(), 1);
        assert_eq!(first_output.tool_calls[0].name, "read");
        assert_eq!(
            first_output.tool_calls[0].arguments,
            json!({ "path": "README.md" })
        );
        assert_eq!(
            first_output.tool_calls[0].result.as_deref(),
            Some("governed file body")
        );
        assert_eq!(first_output.tool_calls[0].ok, Some(true));
        assert_eq!(
            first_output.flow_signature,
            vec![
                CertifiedOutputFieldFlow {
                    field: "assistant_text".to_owned(),
                    reads: vec![ResourceRef {
                        handle: "project".to_owned(),
                        kind: "file_store".to_owned(),
                        selector: None,
                        writable: None,
                        presented_as: None,
                    }],
                },
                CertifiedOutputFieldFlow {
                    field: "tool_calls".to_owned(),
                    reads: vec![ResourceRef {
                        handle: "project".to_owned(),
                        kind: "file_store".to_owned(),
                        selector: None,
                        writable: None,
                        presented_as: None,
                    }],
                },
            ]
        );
        assert_eq!(resources.calls.get(), 1);
        drop(runtime);

        let mut reopened = GovernedHostRuntime::open(&path, 7, &policy_text).expect("reopen");
        let replayed = reopened
            .open_instance(&open, &Packages)
            .expect("open command replays");
        assert_eq!(replayed.instance_ref, instance.instance_ref);
        assert_eq!(replayed.opened_at, instance.opened_at);
        let second_driver = ScriptedDriver::new(vec![json!({
            "output_text": "second answer",
            "usage": { "input_tokens": 20, "output_tokens": 3 }
        })]);
        let second = reopened
            .run_turn_with_driver(
                &turn(&instance.instance_ref, &open.policy, 2),
                &Packages,
                &secrets,
                &resources,
                &second_driver,
            )
            .expect("second turn");
        assert_eq!(
            second.receipt.as_ref().expect("terminal receipt").status,
            TurnStatus::Completed
        );
        assert_eq!(
            second
                .output
                .as_ref()
                .map(|output| output.assistant_text.as_str()),
            Some("second answer")
        );
        let request = second_driver.requests.borrow();
        let serialized = request.first().expect("request").to_string();
        assert!(serialized.contains("first answer"));
        assert!(serialized.contains("turn 2"));
        drop(reopened);

        let bytes = fs::read(&path).expect("store bytes");
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-that-must-not-be-persisted"));
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn governed_instance_fork_seeds_a_distinct_continuing_thread() {
        let source_path = temp_store();
        let target_path = temp_store();
        let policy_text = signed_policy();
        let mut source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-source-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let source_instance = source
            .open_instance(&source_open, &Packages)
            .expect("source instance");
        source
            .run_turn_with_driver(
                &turn(&source_instance.instance_ref, &source_open.policy, 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &ScriptedDriver::new(vec![json!({
                    "output_text": "source answer",
                    "usage": { "input_tokens": 10, "output_tokens": 3 }
                })]),
            )
            .expect("source turn");
        let source_position = source
            .current_position(&source_instance.instance_ref)
            .expect("source position");

        let mut target =
            GovernedHostRuntime::open(&target_path, 9, &policy_text).expect("target runtime");
        let fork = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "fork-source-into-target".to_owned(),
            source: source_position,
            target_request_id: "open-target-chat".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        let forked = target
            .fork_instance_from(&source, &fork, &Packages)
            .expect("fork succeeds");
        forked.validate_for(&fork).expect("fork binding");
        assert_ne!(forked.target.instance_ref, source_instance.instance_ref);
        assert_eq!(forked.target.package_version_ref, "package:v2");
        let replayed = target
            .fork_instance_from(&source, &fork, &Packages)
            .expect("fork replays");
        assert_eq!(replayed, forked);

        let driver = ScriptedDriver::new(vec![json!({
            "output_text": "target answer",
            "usage": { "input_tokens": 20, "output_tokens": 3 }
        })]);
        target
            .run_turn_with_driver(
                &turn_with_package(&forked.target.instance_ref, &fork.policy, 2, "package:v2"),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &driver,
            )
            .expect("target turn");
        let serialized = driver
            .requests
            .borrow()
            .first()
            .expect("target request")
            .to_string();
        assert!(serialized.contains("source answer"));
        assert!(serialized.contains("turn 2"));
        // The carried thread answers under the target package's persona, not
        // the one it was seeded with.
        assert!(serialized.contains("Help through the governed resource tools (v2)."));
        assert!(!serialized.contains("Help through the governed resource tools."));

        drop(target);
        drop(source);
        for path in [&source_path, &target_path] {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    #[test]
    fn home_fork_registers_before_target_writes_and_recovers_exact_completion() {
        let source_path = temp_store();
        let target_path = temp_store();
        let policy_text = signed_policy();
        let mut journal = TestForkJournal::default();
        let mut source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-source".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let source_instance = source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source Home admission");
        source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("retained source Home use binds its exact instance");
        let source_position = source
            .current_position(&source_instance.instance_ref)
            .expect("source position");
        let mut target =
            GovernedHostRuntime::open(&target_path, 9, &policy_text).expect("target runtime");
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-transfer".to_owned(),
            source: source_position,
            target_request_id: "home-fork-target".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        let original_source_input = source
            .kernel
            .store()
            .get_instance(&source_instance.instance_ref)
            .expect("source row")
            .expect("source instance")
            .input_json;
        let mut changed_source: InstanceMetadata =
            serde_json::from_str(&original_source_input).expect("source metadata");
        changed_source.protocol = "different-host-protocol".to_owned();
        let source_connection = rusqlite::Connection::open(&source_path).expect("source database");
        source_connection
            .execute(
                "UPDATE instances SET input_json = ?2 WHERE instance_id = ?1",
                rusqlite::params![
                    source_instance.instance_ref,
                    serde_json::to_string(&changed_source).expect("changed source metadata")
                ],
            )
            .expect("change stored source binding");
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("a changed source binding cannot be admitted")
            .to_string()
            .contains("fork source package/policy binding"));
        source_connection
            .execute(
                "UPDATE instances SET input_json = ?2 WHERE instance_id = ?1",
                rusqlite::params![source_instance.instance_ref, original_source_input],
            )
            .expect("restore stored source binding");

        let mut future = command.clone();
        future.source.sequence += 1;
        assert!(target
            .fork_instance_from_with_home_journal(&source, &future, &Packages, &mut journal)
            .expect_err("source cannot fork from a future event")
            .to_string()
            .contains("fork source position"));
        assert!(target
            .kernel
            .store()
            .list_instances()
            .expect("targets")
            .is_empty());

        journal.fail_at = Some("source");
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("unpinned source is not forkable")
            .to_string()
            .contains("Home source pin refused"));
        assert!(target
            .kernel
            .store()
            .list_instances()
            .expect("targets")
            .is_empty());
        journal.fail_at = Some("source_empty");
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("source pin needs an operation identity")
            .to_string()
            .contains("Home fork source pin has no operation identity"));
        journal.fail_at = Some("register");
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("pending fork must register first")
            .to_string()
            .contains("Home fork register refused"));
        assert!(target
            .kernel
            .store()
            .list_instances()
            .expect("targets")
            .is_empty());
        journal.fail_at = Some("register_empty");
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("pending fork needs an operation identity")
            .to_string()
            .contains("Home fork registration has no operation identity"));
        assert!(target
            .kernel
            .store()
            .list_instances()
            .expect("targets")
            .is_empty());

        journal.fail_at = Some("complete");
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("incomplete Home pointer cannot expose target")
            .to_string()
            .contains("Home fork complete refused"));
        let pending_target = target
            .kernel
            .store()
            .list_instances()
            .expect("persisted target");
        assert_eq!(pending_target.len(), 1);
        assert!(journal.fork_completed.is_none());
        assert_eq!(journal.retained_forks, 0);

        journal.fail_at = None;
        let recovered = target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect("same operation recovers after crash");
        assert_eq!(recovered.target.instance_ref, pending_target[0].instance_id);
        assert!(journal.fork_completed.is_some());
        assert_eq!(journal.retained_forks, 1);
        assert_eq!(
            target
                .kernel
                .store()
                .list_events(&recovered.target.instance_ref)
                .expect("target events")
                .iter()
                .filter(|event| event.event_type == "agent.thread.seeded")
                .count(),
            1
        );
        assert_eq!(
            target
                .kernel
                .store()
                .list_events(&recovered.target.instance_ref)
                .expect("target events")
                .iter()
                .filter(|event| event.event_type == "host.instance.forked")
                .count(),
            1
        );
        let replayed = target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect("completed Home fork replays exactly");
        assert_eq!(replayed, recovered);
        assert_eq!(journal.retained_forks, 2);
        rusqlite::Connection::open(&target_path)
            .expect("target database")
            .execute(
                "DELETE FROM events WHERE instance_id = ?1 AND event_type = 'agent.thread.seeded'",
                [&recovered.target.instance_ref],
            )
            .expect("simulate missing retained seed");
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("a fork marker cannot replace the missing seed")
            .to_string()
            .contains("recorded Home fork has no exact thread seed"));
        journal.remove_target_on_retained_use = Some(target_path.clone());
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("target removed during Home admission cannot be seeded")
            .to_string()
            .contains("Home fork target disappeared after open"));

        drop(target);
        drop(source);
        for path in [&source_path, &target_path] {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    #[test]
    fn home_adoption_keeps_the_source_pin_when_old_authored_content_drifted() {
        let source_path = temp_store();
        let target_path = temp_store();
        let policy_text = signed_policy();
        let mut journal = TestForkJournal::default();
        let mut source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-source".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let opened = source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source admitted");
        source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source retained use bound");
        let position = source
            .current_position(&opened.instance_ref)
            .expect("source position");
        drop(source);
        rusqlite::Connection::open(&source_path)
            .expect("source store")
            .execute(
                "UPDATE program_versions SET source_hash = 'authored-by-an-older-build'",
                [],
            )
            .expect("age authored source identity");
        let source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("reopened source");
        let mut target =
            GovernedHostRuntime::open(&target_path, 9, &policy_text).expect("target runtime");
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-adoption".to_owned(),
            source: position,
            target_request_id: "home-fork-target".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .is_err());
        assert!(target
            .kernel
            .store()
            .list_instances()
            .expect("targets")
            .is_empty());
        let adopted = target
            .adopt_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect("Home-pinned adoption");
        assert_eq!(adopted.target.package_version_ref, "package:v2");
        assert!(journal.fork_completed.is_some());
        let marker = target
            .kernel
            .store()
            .list_events(&adopted.target.instance_ref)
            .expect("target events")
            .into_iter()
            .find(|event| event.event_type == "host.instance.forked")
            .expect("adoption marker");
        assert_eq!(
            serde_json::from_str::<Value>(&marker.payload_json).expect("payload")["kind"],
            "adopt"
        );
        let source_connection = rusqlite::Connection::open(&source_path).expect("source database");
        source_connection
            .pragma_update(None, "foreign_keys", false)
            .expect("allow a broken historical fixture");
        source_connection
            .execute(
                "UPDATE instances SET version_id = 'missing-home-source-version' WHERE instance_id = ?1",
                [&opened.instance_ref],
            )
            .expect("remove source version binding");
        assert!(target
            .adopt_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("adoption needs the source version")
            .to_string()
            .contains("Home adoption source version is missing"));

        drop(target);
        drop(source);
        for path in [&source_path, &target_path] {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    /// The Home-journalled adoption carries a thread across an epoch advance
    /// the same way (DR-0293), and records the epoch it carried it from.
    #[test]
    fn home_adoption_carries_a_thread_into_a_newer_epoch() {
        let source_path = temp_store();
        let target_path = temp_store();
        let first = epoch_policy("file:/workspace", &[], "gaugedesk-admin", None);
        let second = epoch_policy(
            "file:/workspace",
            &["tracker:tasks"],
            "gaugedesk-admin",
            None,
        );
        let mut journal = TestForkJournal::default();
        let mut source = GovernedHostRuntime::open(&source_path, 1, &first).expect("epoch 1");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            // The test journal binds the source pin under this request id.
            request_id: "home-fork-source".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let opened = source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source admitted");
        source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source retained use bound");
        source
            .run_turn_with_driver(
                &turn(&opened.instance_ref, &source_open.policy, 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &ScriptedDriver::new(vec![json!({
                    "output_text": "answer recorded under epoch 1",
                    "usage": { "input_tokens": 10, "output_tokens": 3 }
                })]),
            )
            .expect("source turn");
        let position = source
            .current_position(&opened.instance_ref)
            .expect("source position");
        let mut target = GovernedHostRuntime::open(&target_path, 2, &second).expect("epoch 2");
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-epoch-adoption".to_owned(),
            source: position,
            target_request_id: "home-epoch-target".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        let adopted = target
            .adopt_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect("Home adoption across epochs");
        assert!(journal.fork_completed.is_some());
        let record = fork_record(&target, &adopted.target.instance_ref);
        assert_eq!(record["kind"], "adopt");
        assert_eq!(record["source_policy"], json!(source.policy_ref()));
        let carried =
            serde_json::to_string(&whipplescript_kernel::harness_loop::chat_messages_to_json(
                &target
                    .kernel
                    .snapshot_agent_thread(&adopted.target.instance_ref, "assistant", None)
                    .expect("seeded thread"),
            ))
            .expect("thread json");
        assert!(
            carried.contains("answer recorded under epoch 1"),
            "{carried}"
        );

        drop((source, target));
        remove_stores(&[&source_path, &target_path]);
    }

    #[test]
    fn home_fork_refuses_a_source_version_move_after_pending_registration() {
        let source_path = temp_store();
        let target_path = temp_store();
        let policy_text = signed_policy();
        let mut journal = TestForkJournal::default();
        let mut source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-source".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let opened = source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source admitted");
        source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source retained use bound");
        let source_position = source
            .current_position(&opened.instance_ref)
            .expect("source position");
        let alternate = source
            .open_instance(
                &OpenInstanceCommand {
                    protocol: HOST_PROTOCOL.to_owned(),
                    request_id: "source-alternate-version".to_owned(),
                    package_version_ref: "package:v2".to_owned(),
                    policy: source.policy_ref().clone(),
                },
                &Packages,
            )
            .expect("alternate version exists");
        let alternate_version = source
            .kernel
            .store()
            .get_instance(&alternate.instance_ref)
            .expect("alternate instance read")
            .expect("alternate instance")
            .version_id;
        let original_version = source
            .kernel
            .store()
            .get_instance(&opened.instance_ref)
            .expect("original instance read")
            .expect("original instance")
            .version_id;
        journal.mutate_source_version = Some((
            source_path.clone(),
            opened.instance_ref.clone(),
            alternate_version,
        ));
        let mut target =
            GovernedHostRuntime::open(&target_path, 9, &policy_text).expect("target runtime");
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-moving-source".to_owned(),
            source: source_position,
            target_request_id: "home-fork-target".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        let failure = target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("source move after registration cannot seed target");
        assert!(
            failure
                .to_string()
                .contains("Home fork source changed before target seed"),
            "got: {failure:?}"
        );
        assert!(journal.fork_registered.is_some());
        assert!(journal.fork_completed.is_none());
        let pending = target.kernel.store().list_instances().expect("target rows");
        assert_eq!(pending.len(), 1);
        assert!(target
            .kernel
            .store()
            .list_events(&pending[0].instance_id)
            .expect("target events")
            .iter()
            .all(|event| event.event_type != "agent.thread.seeded"));
        rusqlite::Connection::open(&source_path)
            .expect("source database")
            .execute(
                "UPDATE instances SET version_id = ?2 WHERE instance_id = ?1",
                rusqlite::params![opened.instance_ref, original_version],
            )
            .expect("restore original source version");
        journal.remove_source_on_target_retained_use =
            Some((source_path.clone(), opened.instance_ref.clone()));
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("source removed during target admission cannot seed")
            .to_string()
            .contains("Home fork source disappeared after target open"));

        drop(target);
        drop(source);
        for path in [&source_path, &target_path] {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    #[test]
    fn home_fork_refuses_reusing_the_source_instance_as_its_target() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut journal = TestForkJournal::default();
        let mut source = GovernedHostRuntime::open(&path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-source".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let opened = source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source admitted");
        source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source pin bound");
        let position = source
            .current_position(&opened.instance_ref)
            .expect("source position");
        let mut target =
            GovernedHostRuntime::open(&path, 9, &policy_text).expect("same store target handle");
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-same-instance".to_owned(),
            source: position,
            target_request_id: source_open.request_id,
            package_version_ref: source_open.package_version_ref,
            policy: target.policy_ref().clone(),
        };
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("fork must create a distinct instance")
            .to_string()
            .contains("fork target identity"));
        assert!(journal.fork_registered.is_some());
        assert!(journal.fork_completed.is_none());

        drop(target);
        drop(source);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn home_fork_refuses_a_running_source_before_target_registration() {
        let source_path = temp_store();
        let target_path = temp_store();
        let policy_text = signed_policy();
        let mut journal = TestForkJournal::default();
        let mut source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-source".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let opened = source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source admitted");
        source
            .open_instance_with_home_journal(&source_open, &Packages, &mut journal)
            .expect("source pin bound");
        source
            .run_turn_with_driver(
                &turn(&opened.instance_ref, &source_open.policy, 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &ScriptedDriver::new(vec![json!({
                    "output_text": "source answer",
                    "usage": { "input_tokens": 10, "output_tokens": 3 }
                })]),
            )
            .expect("source has a turn effect");
        let changed = rusqlite::Connection::open(&source_path)
            .expect("source database")
            .execute(
                "UPDATE effects SET status = 'running' WHERE instance_id = ?1",
                [&opened.instance_ref],
            )
            .expect("simulate in-flight source effect");
        assert!(changed > 0);
        let position = source
            .current_position(&opened.instance_ref)
            .expect("source position");
        let mut target =
            GovernedHostRuntime::open(&target_path, 9, &policy_text).expect("target runtime");
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-fork-running-source".to_owned(),
            source: position,
            target_request_id: "home-fork-target".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        assert!(target
            .fork_instance_from_with_home_journal(&source, &command, &Packages, &mut journal)
            .expect_err("running source cannot be forked")
            .to_string()
            .contains("is not quiescent"));
        assert!(journal.fork_registered.is_none());
        assert!(target
            .kernel
            .store()
            .list_instances()
            .expect("targets")
            .is_empty());

        drop(target);
        drop(source);
        for path in [&source_path, &target_path] {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    #[test]
    fn fork_retry_recovers_exact_seed_and_refuses_a_conflicting_seed() {
        let source_path = temp_store();
        let target_path = temp_store();
        let policy_text = signed_policy();
        let mut source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "fork-retry-source".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let source_instance = source
            .open_instance(&source_open, &Packages)
            .expect("source instance");
        let position = source
            .current_position(&source_instance.instance_ref)
            .expect("source position");
        let mut target =
            GovernedHostRuntime::open(&target_path, 9, &policy_text).expect("target runtime");
        let command = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "fork-retry".to_owned(),
            source: position.clone(),
            target_request_id: "fork-retry-target".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        let opened = target
            .open_instance(&command.target_open_command(), &Packages)
            .expect("target import/open survived crash");
        let key = idempotency_key(&[
            &opened.instance_ref,
            &command.request_id,
            "host-instance-thread-seed",
        ]);
        target
            .kernel
            .seed_agent_thread(AgentThreadSeed {
                instance_id: &opened.instance_ref,
                agent: "assistant",
                messages: &[],
                source_instance_id: &position.instance_ref,
                source_sequence: position.sequence as i64,
                idempotency_key: &key,
            })
            .expect("seed survived crash");
        let recovered = target
            .fork_instance_from(&source, &command, &Packages)
            .expect("retry finishes fork from exact seed");
        assert_eq!(recovered.target, opened);
        assert_eq!(
            target
                .kernel
                .store()
                .list_events(&opened.instance_ref)
                .expect("target events")
                .iter()
                .filter(|event| event.event_type == "agent.thread.seeded")
                .count(),
            1
        );

        let missing_seed = ForkInstanceCommand {
            request_id: "fork-missing-seed".to_owned(),
            target_request_id: "fork-missing-seed-target".to_owned(),
            ..command.clone()
        };
        let unseeded_target = target
            .open_instance(&missing_seed.target_open_command(), &Packages)
            .expect("unseeded target");
        target
            .kernel
            .store()
            .append_event(NewEvent {
                instance_id: &unseeded_target.instance_ref,
                event_type: "host.instance.forked",
                payload_json: &json!({
                    "request_id": missing_seed.request_id,
                    "source": missing_seed.source,
                    "target_request_id": missing_seed.target_request_id,
                    "package_version_ref": missing_seed.package_version_ref,
                    "policy": missing_seed.policy,
                })
                .to_string(),
                source: "host-runtime",
                causation_id: None,
                correlation_id: Some(&missing_seed.request_id),
                idempotency_key: Some(&idempotency_key(&[
                    &unseeded_target.instance_ref,
                    &missing_seed.request_id,
                    "host-instance-forked",
                ])),
            })
            .expect("fork marker without seed");
        assert!(target
            .fork_instance_from(&source, &missing_seed, &Packages)
            .expect_err("a fork marker cannot stand in for its thread seed")
            .to_string()
            .contains("recorded fork has no exact thread seed"));

        let conflict = ForkInstanceCommand {
            request_id: "fork-conflicting-seed".to_owned(),
            target_request_id: "fork-conflicting-target".to_owned(),
            ..command.clone()
        };
        let conflicting_target = target
            .open_instance(&conflict.target_open_command(), &Packages)
            .expect("other target");
        let conflicting_key = idempotency_key(&[
            &conflicting_target.instance_ref,
            &conflict.request_id,
            "host-instance-thread-seed",
        ]);
        target
            .kernel
            .store()
            .append_event(NewEvent {
                instance_id: &conflicting_target.instance_ref,
                event_type: "agent.thread.seeded",
                payload_json: &json!({
                    "agent": "assistant",
                    "messages": [],
                    "source_instance_id": position.instance_ref,
                    "source_sequence": 999,
                })
                .to_string(),
                source: "kernel",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some(&conflicting_key),
            })
            .expect("conflicting seed exists");
        assert!(target
            .fork_instance_from(&source, &conflict, &Packages)
            .expect_err("a colliding key cannot settle a different source cut")
            .to_string()
            .contains("fork event key names different evidence"));

        drop(target);
        drop(source);
        for path in [&source_path, &target_path] {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    /// An embedding host whose package authoring drifted cannot reproduce the
    /// source's recorded content: an ordinary fork keeps refusing, and
    /// adoption carries the thread to the current, fully validated package
    /// (spec/agent-harness.md "Program identity across toolchains").
    #[test]
    fn adoption_forks_a_source_whose_authored_package_drifted() {
        let source_path = temp_store();
        let target_path = temp_store();
        let policy_text = signed_policy();
        let mut source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("source runtime");
        let source_open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-drifted-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: source.policy_ref().clone(),
        };
        let source_instance = source
            .open_instance(&source_open, &Packages)
            .expect("source instance");
        source
            .run_turn_with_driver(
                &turn(&source_instance.instance_ref, &source_open.policy, 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &ScriptedDriver::new(vec![json!({
                    "output_text": "answer from before the drift",
                    "usage": { "input_tokens": 10, "output_tokens": 3 }
                })]),
            )
            .expect("source turn");
        let source_position = source
            .current_position(&source_instance.instance_ref)
            .expect("source position");
        drop(source);
        // Today's host assembles different authored bytes under the same
        // reference — recorded by an older build, unreproducible now.
        {
            let connection = rusqlite::Connection::open(&source_path).expect("raw store");
            connection
                .execute(
                    "UPDATE program_versions SET source_hash = 'authored-by-an-older-build'",
                    [],
                )
                .expect("age the authored identity");
        }
        let source =
            GovernedHostRuntime::open(&source_path, 9, &policy_text).expect("reopen source");
        assert_eq!(
            source
                .newest_recorded_instance()
                .expect("recorded instance")
                .expect("store has one")
                .instance_ref,
            source_instance.instance_ref,
        );

        let mut target =
            GovernedHostRuntime::open(&target_path, 9, &policy_text).expect("target runtime");
        let fork = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "adopt-drifted-into-target".to_owned(),
            source: source_position,
            target_request_id: "open-adopted-chat".to_owned(),
            package_version_ref: "package:v2".to_owned(),
            policy: target.policy_ref().clone(),
        };
        assert!(
            target
                .fork_instance_from(&source, &fork, &Packages)
                .is_err(),
            "an ordinary fork must keep refusing an unreproducible source"
        );
        let adopted = target
            .adopt_instance_from(&source, &fork, &Packages)
            .expect("adoption succeeds");
        adopted.validate_for(&fork).expect("fork binding");
        assert_ne!(adopted.target.instance_ref, source_instance.instance_ref);
        let replayed = target
            .adopt_instance_from(&source, &fork, &Packages)
            .expect("adoption replays");
        assert_eq!(replayed, adopted);

        let driver = ScriptedDriver::new(vec![json!({
            "output_text": "answer after adoption",
            "usage": { "input_tokens": 20, "output_tokens": 3 }
        })]);
        target
            .run_turn_with_driver(
                &turn_with_package(&adopted.target.instance_ref, &fork.policy, 2, "package:v2"),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &driver,
            )
            .expect("target turn");
        let serialized = driver
            .requests
            .borrow()
            .first()
            .expect("target request")
            .to_string();
        assert!(
            serialized.contains("answer from before the drift"),
            "the adopted thread is carried"
        );

        drop(target);
        drop(source);
        for path in [&source_path, &target_path] {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    /// Open a chat under `runtime`'s epoch and run one turn per answer, the
    /// turns numbered from `first`, each reading `reads`.
    fn chat_with_turns(
        runtime: &mut GovernedHostRuntime,
        request_id: &str,
        first: usize,
        answers: &[&str],
        reads: &[ResourceRef],
    ) -> OpenedInstance {
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: request_id.to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let opened = runtime.open_instance(&open, &Packages).expect("chat opens");
        for (offset, answer) in answers.iter().enumerate() {
            let mut command = turn(&opened.instance_ref, &open.policy, first + offset);
            command.resources = reads.to_vec();
            runtime
                .run_turn_with_driver(
                    &command,
                    &Packages,
                    &Secrets {
                        calls: Cell::new(0),
                    },
                    &Resources {
                        calls: Cell::new(0),
                    },
                    &ScriptedDriver::new(vec![json!({
                        "output_text": answer,
                        "usage": { "input_tokens": 10, "output_tokens": 3 }
                    })]),
                )
                .expect("turn runs");
        }
        opened
    }

    fn read_of(handle: &str, kind: &str) -> ResourceRef {
        ResourceRef {
            handle: handle.to_owned(),
            kind: kind.to_owned(),
            selector: None,
            writable: None,
            presented_as: None,
        }
    }

    fn adoption_into(
        current: &GovernedHostRuntime,
        source: EventPosition,
        request_id: &str,
    ) -> ForkInstanceCommand {
        ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: request_id.to_owned(),
            source,
            target_request_id: format!("{request_id}:target"),
            package_version_ref: "package:v1".to_owned(),
            policy: current.policy_ref().clone(),
        }
    }

    fn fork_record(runtime: &GovernedHostRuntime, instance_ref: &str) -> Value {
        let event = runtime
            .kernel
            .store()
            .list_events(instance_ref)
            .expect("target events")
            .into_iter()
            .find(|event| event.event_type == "host.instance.forked")
            .expect("fork record");
        serde_json::from_str(&event.payload_json).expect("fork record json")
    }

    fn remove_stores(paths: &[&std::path::PathBuf]) {
        for path in paths {
            let _ = fs::remove_file(path);
            let _ = fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = fs::remove_file(path.with_extension("sqlite-shm"));
        }
    }

    /// DR-0293 §1 and GaugeDesk WS-660's acceptance: one turn under epoch 1,
    /// the chat reopens under epoch 2 of the same authority, and the second
    /// provider request contains the first turn.
    #[test]
    fn adoption_carries_a_thread_into_a_newer_epoch_of_the_same_authority() {
        let path = temp_store();
        let first = epoch_policy("file:/workspace", &[], "gaugedesk-admin", None);
        // The epoch advances because the chat gained a tracker.
        let second = epoch_policy(
            "file:/workspace",
            &["tracker:tasks"],
            "gaugedesk-admin",
            None,
        );
        let mut earlier = GovernedHostRuntime::open(&path, 1, &first).expect("epoch 1");
        let source = chat_with_turns(
            &mut earlier,
            "chat-under-epoch-1",
            1,
            &["answer under the first epoch"],
            &[read_of("project", "file_store")],
        );
        let position = earlier
            .current_position(&source.instance_ref)
            .expect("source position");
        let mut current = GovernedHostRuntime::open(&path, 2, &second).expect("epoch 2");
        let recorded = current
            .newest_recorded_instance()
            .expect("recorded instance")
            .expect("the chat");
        assert_eq!(recorded.instance_ref, source.instance_ref);
        assert_eq!(&recorded.policy, earlier.policy_ref());
        let command = adoption_into(&current, position, "adopt-into-epoch-2");

        assert!(
            current
                .fork_instance_from(&earlier, &command, &Packages)
                .is_err(),
            "an ordinary fork keeps exact policy equality"
        );
        let under_current = GovernedHostRuntime::open(&path, 2, &second).expect("epoch 2 again");
        assert!(current
            .fork_instance_from(&under_current, &command, &Packages)
            .expect_err("a fork refuses a source recorded under another epoch")
            .to_string()
            .contains("fork source package/policy binding"));
        let unknown = ForkInstanceCommand {
            source: EventPosition {
                instance_ref: "ins_never_opened".to_owned(),
                sequence: 1,
            },
            ..adoption_into(&current, command.source.clone(), "adopt-unknown-instance")
        };
        assert!(matches!(
            current.adopt_instance_from(&earlier, &unknown, &Packages),
            Err(HostRuntimeError::UnknownInstance(instance)) if instance == "ins_never_opened"
        ));
        let ahead = adoption_into(
            &current,
            EventPosition {
                instance_ref: source.instance_ref.clone(),
                sequence: command.source.sequence + 1,
            },
            "adopt-ahead-of-the-source",
        );
        assert!(current
            .adopt_instance_from(&earlier, &ahead, &Packages)
            .expect_err("a position the source has not reached")
            .to_string()
            .contains("fork source position"));
        assert!(current
            .adopt_instance_from(&under_current, &command, &Packages)
            .expect_err("a runtime under epoch 2 cannot vouch for epoch 1's envelope")
            .to_string()
            .contains("fork source package/policy binding"));

        let adopted = current
            .adopt_instance_from(&earlier, &command, &Packages)
            .expect("adoption across epochs");
        adopted.validate_for(&command).expect("fork binding");
        assert!(adopted.cut.is_none());
        assert_eq!(
            current
                .adopt_instance_from(&earlier, &command, &Packages)
                .expect("adoption replays"),
            adopted
        );
        let record = fork_record(&current, &adopted.target.instance_ref);
        assert_eq!(record["source_policy"], json!(earlier.policy_ref()));
        assert_eq!(record["policy"], json!(current.policy_ref()));

        let driver = ScriptedDriver::new(vec![json!({
            "output_text": "answer under the second epoch",
            "usage": { "input_tokens": 20, "output_tokens": 3 }
        })]);
        current
            .run_turn_with_driver(
                &turn(&adopted.target.instance_ref, &command.policy, 2),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &driver,
            )
            .expect("turn under epoch 2");
        let request = driver
            .requests
            .borrow()
            .first()
            .expect("second provider request")
            .to_string();
        assert!(request.contains("turn 1"), "{request}");
        assert!(
            request.contains("answer under the first epoch"),
            "{request}"
        );
        assert!(request.contains("turn 2"), "{request}");

        drop((earlier, under_current, current));
        remove_stores(&[&path]);
    }

    /// DR-0293 §1: a thread is carried forward within one authority only.
    /// Another signer, another declared authority, or an epoch that is not
    /// earlier refuses, and nothing is opened.
    #[test]
    fn adoption_refuses_another_authority_or_an_epoch_that_is_not_earlier() {
        let path = temp_store();
        let first = epoch_policy("file:/workspace", &[], "gaugedesk-admin", None);
        let mut earlier = GovernedHostRuntime::open(&path, 1, &first).expect("epoch 1");
        let source = chat_with_turns(
            &mut earlier,
            "chat-under-epoch-1",
            1,
            &["answer under the first epoch"],
            &[read_of("project", "file_store")],
        );
        let position = earlier
            .current_position(&source.instance_ref)
            .expect("source position");
        let refusal = |epoch: u64, policy: &str, request_id: &str| {
            let mut current = GovernedHostRuntime::open(&path, epoch, policy).expect("runtime");
            let command = adoption_into(&current, position.clone(), request_id);
            current
                .adopt_instance_from(&earlier, &command, &Packages)
                .expect_err("refused")
                .to_string()
        };
        let gained = ["tracker:tasks"];
        assert!(refusal(
            2,
            &epoch_policy("file:/workspace", &gained, "another-admin", None),
            "another-signer",
        )
        .contains("adoption source policy authority"));
        assert!(refusal(
            2,
            &epoch_policy(
                "file:/workspace",
                &gained,
                "gaugedesk-admin",
                Some("home:elsewhere")
            ),
            "another-authority",
        )
        .contains("adoption source policy authority"));
        assert!(refusal(
            1,
            &epoch_policy("file:/workspace", &gained, "gaugedesk-admin", None),
            "same-epoch-number",
        )
        .contains("adoption source policy epoch"));
        assert_eq!(
            earlier
                .kernel
                .store()
                .list_instances()
                .expect("instances")
                .len(),
            1,
            "a refused adoption opens no target"
        );

        drop(earlier);
        remove_stores(&[&path]);
    }

    /// DR-0293 §2: what the carried thread read is re-admitted under the newer
    /// epoch. A resource the epoch rebinds elsewhere, or one it no longer
    /// governs, refuses the adoption rather than relabel what was read.
    #[test]
    fn adoption_across_epochs_refuses_a_read_the_newer_epoch_does_not_admit() {
        let path = temp_store();
        let first = epoch_policy(
            "file:/workspace",
            &["tracker:tasks"],
            "gaugedesk-admin",
            None,
        );
        let mut earlier = GovernedHostRuntime::open(&path, 1, &first).expect("epoch 1");
        let source = chat_with_turns(
            &mut earlier,
            "chat-under-epoch-1",
            1,
            &["answer that read both"],
            &[
                read_of("project", "file_store"),
                read_of("tracker:tasks", "tracker"),
            ],
        );
        let position = earlier
            .current_position(&source.instance_ref)
            .expect("source position");
        let refusal = |epoch: u64, policy: &str, request_id: &str| {
            let mut current = GovernedHostRuntime::open(&path, epoch, policy).expect("runtime");
            let command = adoption_into(&current, position.clone(), request_id);
            current
                .adopt_instance_from(&earlier, &command, &Packages)
                .expect_err("refused")
                .to_string()
        };
        let rebound = refusal(
            2,
            &epoch_policy(
                "file:/elsewhere",
                &["tracker:tasks"],
                "gaugedesk-admin",
                None,
            ),
            "project-rebound",
        );
        assert!(
            rebound.contains("read `project`, which the newer epoch does not admit"),
            "{rebound}"
        );
        let dropped = refusal(
            3,
            &epoch_policy("file:/workspace", &[], "gaugedesk-admin", None),
            "tracker-dropped",
        );
        assert!(
            dropped.contains("read `tracker:tasks`, which the newer epoch does not admit"),
            "{dropped}"
        );

        drop(earlier);
        remove_stores(&[&path]);
    }

    /// DR-0293 §2 again: re-admission follows a seeded thread back to the
    /// turns it came from, and refuses when it cannot name what they read.
    #[test]
    fn adoption_across_epochs_refuses_history_whose_reads_it_cannot_name() {
        let elsewhere = temp_store();
        let here = temp_store();
        let first = epoch_policy("file:/workspace", &[], "gaugedesk-admin", None);
        let second = epoch_policy(
            "file:/workspace",
            &["tracker:tasks"],
            "gaugedesk-admin",
            None,
        );

        // A thread seeded from a store this one does not hold.
        let mut origin = GovernedHostRuntime::open(&elsewhere, 1, &first).expect("origin");
        let origin_chat = chat_with_turns(
            &mut origin,
            "chat-elsewhere",
            1,
            &["answer from another store"],
            &[read_of("project", "file_store")],
        );
        let mut earlier = GovernedHostRuntime::open(&here, 1, &first).expect("epoch 1 here");
        let fork = ForkInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "fork-from-elsewhere".to_owned(),
            source: origin
                .current_position(&origin_chat.instance_ref)
                .expect("origin position"),
            target_request_id: "chat-here".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: earlier.policy_ref().clone(),
        };
        let seeded = earlier
            .fork_instance_from(&origin, &fork, &Packages)
            .expect("cross-store fork under one epoch");
        let mut current = GovernedHostRuntime::open(&here, 2, &second).expect("epoch 2 here");
        let command = adoption_into(
            &current,
            earlier
                .current_position(&seeded.target.instance_ref)
                .expect("seeded position"),
            "adopt-seeded-from-elsewhere",
        );
        let refused = current
            .adopt_instance_from(&earlier, &command, &Packages)
            .expect_err("unknown lineage")
            .to_string();
        assert!(
            refused.contains("which this store does not hold"),
            "{refused}"
        );

        // A carried turn whose effect names no host command.
        let unnamed = chat_with_turns(
            &mut earlier,
            "chat-with-unnamed-reads",
            7,
            &["answer whose reads are lost"],
            &[read_of("project", "file_store")],
        );
        rusqlite::Connection::open(&here)
            .expect("store")
            .execute(
                "UPDATE effects SET input_json = '{}' WHERE effect_id = 'command-7'",
                [],
            )
            .expect("lose the recorded command");
        let command = adoption_into(
            &current,
            earlier
                .current_position(&unnamed.instance_ref)
                .expect("position"),
            "adopt-unnamed-reads",
        );
        let refused = current
            .adopt_instance_from(&earlier, &command, &Packages)
            .expect_err("unnamed reads")
            .to_string();
        assert!(refused.contains("recorded no host command"), "{refused}");

        drop((origin, earlier, current));
        remove_stores(&[&elsewhere, &here]);
    }

    /// DR-0293 §3: a source whose later turn never settled is adopted from
    /// the newest position before that turn began. The effect is left as it
    /// is, the result names the cut, and the carried thread does not contain
    /// the unresolved turn. A fork still refuses the same source.
    #[test]
    fn adoption_cuts_before_an_effect_that_never_settled() {
        let path = temp_store();
        let policy = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 9, &policy).expect("runtime");
        let source = chat_with_turns(
            &mut runtime,
            "chat-with-orphan",
            1,
            &["settled answer", "answer nobody saw"],
            &[read_of("project", "file_store")],
        );
        rusqlite::Connection::open(&path)
            .expect("store")
            .execute(
                "UPDATE effects SET status = 'running' WHERE effect_id = 'command-2'",
                [],
            )
            .expect("orphan the second turn");
        let source_runtime = GovernedHostRuntime::open(&path, 9, &policy).expect("source");
        let position = source_runtime
            .current_position(&source.instance_ref)
            .expect("position");
        let command = adoption_into(&runtime, position.clone(), "adopt-around-orphan");

        assert!(runtime
            .fork_instance_from(&source_runtime, &command, &Packages)
            .expect_err("a fork still needs a quiescent source")
            .to_string()
            .contains("is not quiescent"));
        let adopted = runtime
            .adopt_instance_from(&source_runtime, &command, &Packages)
            .expect("adoption cuts instead of refusing");
        let cut = adopted.cut.clone().expect("the cut is reported");
        assert_eq!(cut.unresolved_effects, ["command-2"]);
        assert!(cut.sequence < position.sequence);
        assert_eq!(
            runtime
                .adopt_instance_from(&source_runtime, &command, &Packages)
                .expect("adoption replays"),
            adopted
        );
        let effects = runtime
            .kernel
            .store()
            .list_effects(&source.instance_ref)
            .expect("source effects");
        assert_eq!(
            effects
                .iter()
                .find(|effect| effect.effect_id == "command-2")
                .expect("orphan")
                .status,
            "running",
            "the unresolved effect is never settled"
        );
        let carried =
            serde_json::to_string(&whipplescript_kernel::harness_loop::chat_messages_to_json(
                &runtime
                    .kernel
                    .snapshot_agent_thread(&adopted.target.instance_ref, "assistant", None)
                    .expect("seeded thread"),
            ))
            .expect("thread json");
        assert!(carried.contains("settled answer"), "{carried}");
        assert!(!carried.contains("answer nobody saw"), "{carried}");
        assert!(!carried.contains("turn 2"), "{carried}");
        let record = fork_record(&runtime, &adopted.target.instance_ref);
        assert_eq!(record["cut"], json!(cut));
        assert_eq!(record["unresolved_outcome"], "unknown");
        assert!(record.get("source_policy").is_none());

        // Asked for a position before the orphan began, there is nothing to cut.
        let before = adoption_into(
            &runtime,
            EventPosition {
                instance_ref: source.instance_ref.clone(),
                sequence: cut.sequence,
            },
            "adopt-before-orphan",
        );
        assert!(runtime
            .adopt_instance_from(&source_runtime, &before, &Packages)
            .expect("an earlier position is already quiescent")
            .cut
            .is_none());

        // A running effect with no recorded start has no position to cut at.
        rusqlite::Connection::open(&path)
            .expect("store")
            .execute(
                "INSERT INTO effects (effect_id, instance_id, kind, status, created_by_rule, idempotency_key) \
                 VALUES ('orphan-without-start', ?1, 'agent.tell', 'running', 'host.turn', 'orphan-without-start')",
                [&source.instance_ref],
            )
            .expect("an effect nothing recorded starting");
        let unknown_start = adoption_into(&runtime, position, "adopt-unknown-start");
        let refused = runtime
            .adopt_instance_from(&source_runtime, &unknown_start, &Packages)
            .expect_err("no start, no cut")
            .to_string();
        assert!(refused.contains("with no recorded start"), "{refused}");

        drop((runtime, source_runtime));
        remove_stores(&[&path]);
    }

    #[test]
    fn ungoverned_resource_is_rejected_before_secret_resolution() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 3, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).expect("instance");
        let mut command = turn(&instance.instance_ref, &open.policy, 1);
        command.resources[0].handle = "unlisted".to_owned();
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let resources = Resources {
            calls: Cell::new(0),
        };
        let driver = ScriptedDriver::new(Vec::new());
        let error = runtime
            .run_turn_with_driver(&command, &Packages, &secrets, &resources, &driver)
            .expect_err("ungoverned resource");
        assert!(matches!(error, HostRuntimeError::UngovernedHandle(_)));
        assert_eq!(secrets.calls.get(), 0);
        drop(runtime);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn out_of_band_handle_requests_cooperative_cancellation() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-cancel-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).expect("instance");
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let driver = CancellingDriver {
            handle: runtime.cancellation_handle(&command.instance_ref, &command.command_id),
            fired: Cell::new(false),
        };
        let execution = runtime
            .run_turn_with_driver(
                &command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &driver,
            )
            .expect("cancelled execution settles");
        let receipt = execution.receipt.as_ref().expect("terminal receipt");
        assert_eq!(receipt.status, TurnStatus::Cancelled);
        assert!(receipt.output_handle.is_none());
        assert!(driver.fired.get());
        drop(runtime);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn package_ifc_violation_is_rejected_before_an_instance_opens() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 4, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-unsafe-chat".to_owned(),
            package_version_ref: "package:unsafe".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let error = runtime
            .open_instance(&open, &UnsafePackages)
            .expect_err("IFC violation");
        assert!(matches!(error, HostRuntimeError::Ifc(_)));
        drop(runtime);
        let _ = fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_walk_refuses_a_symlink_start() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!(
            "whip-native-symlink-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("workspace");
        fs::write(root.join("target.txt"), "private").expect("target");
        symlink(root.join("target.txt"), root.join("shortcut.txt")).expect("symlink");
        let mut visited = false;
        let result = walk_workspace(&root, &root.join("shortcut.txt"), &mut |_, _, _| {
            visited = true;
            true
        });
        assert_eq!(
            result,
            Err("workspace traversal reached a symlink".to_owned())
        );
        assert!(!visited);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn native_scans_with_lossy_filenames_have_no_exact_model_witness() {
        use std::os::unix::ffi::OsStringExt;

        let root = std::env::temp_dir().join(format!(
            "whip-native-lossy-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("workspace");
        fs::write(root.join("bad\u{fffd}.txt"), "same contents").expect("UTF-8 alias");
        fs::write(
            root.join(std::ffi::OsString::from_vec(b"bad\xff.txt".to_vec())),
            "same contents",
        )
        .expect("non-UTF-8 filename");
        let resolver = NativeWorkspaceResolver::new(&root).expect("resolver");
        let resources = [ResourceRef {
            handle: "project".to_owned(),
            kind: "file_store".to_owned(),
            selector: None,
            writable: None,
            presented_as: None,
        }];
        for (name, arguments) in [
            ("ls", json!({ "path": "." })),
            ("find", json!({ "path": ".", "pattern": "*" })),
            ("grep", json!({ "path": ".", "pattern": "same" })),
        ] {
            let call = ToolCall {
                id: name.to_owned(),
                name: name.to_owned(),
                arguments,
            };
            resolver
                .execute_tool(&resources, &call)
                .expect("tool still returns its normal result");
            assert!(resolver.take_model_scan_witness(name).is_none(), "{name}");
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    fn payload_test_resources() -> [ResourceRef; 2] {
        [
            ResourceRef {
                handle: "project".into(),
                kind: "file_store".into(),
                selector: None,
                writable: None,
                presented_as: None,
            },
            ResourceRef {
                handle: "command".into(),
                kind: "command".into(),
                selector: None,
                writable: None,
                presented_as: None,
            },
        ]
    }

    fn payload_tool(name: &str, arguments: Value) -> ToolCall {
        ToolCall {
            id: "payload-fixture".into(),
            name: name.into(),
            arguments,
        }
    }

    #[test]
    fn native_call_bound_root_rename_carries_exact_call_and_order() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("targets/a")).unwrap();
        fs::write(root.path().join("targets/a/original.txt"), "preserved").unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = seen.clone();
        let resolver = NativeWorkspaceResolver::new(root.path())
            .unwrap()
            .with_root_rename_admission(|_| panic!("call-bound admission must clear legacy"))
            .with_root_rename_call_admission(move |call, ordinal, rename| {
                capture.lock().unwrap().push((
                    call.id.clone(),
                    call.name.clone(),
                    call.arguments.clone(),
                    ordinal,
                    rename.clone(),
                ));
                Ok(())
            });
        let mut resources = payload_test_resources();
        resources[0].selector = Some("targets/a".into());
        resources[0].presented_as = Some("api".into());
        resources[0].writable = Some(true);
        let mut call = payload_tool(
            "bash",
            json!({"command":"mv api backend && mv backend core && echo first > core/new.txt", "timeout_ms": 1000}),
        );
        call.id = "original-call-1".into();
        resolver.execute_tool(&resources, &call).unwrap();
        let records = seen.lock().unwrap().clone();
        assert_eq!(records.len(), 2);
        for (ordinal, record) in records.iter().enumerate() {
            assert_eq!(
                (&record.0, &record.1, &record.2, record.3),
                (&call.id, &call.name, &call.arguments, ordinal)
            );
            assert_eq!(record.4.selector, "targets/a");
        }
        assert_eq!(
            (&records[0].4.from, &records[0].4.to),
            (&"api".to_owned(), &"backend".to_owned())
        );
        assert_eq!(
            (&records[1].4.from, &records[1].4.to),
            (&"backend".to_owned(), &"core".to_owned())
        );
        assert_eq!(
            fs::read(root.path().join("targets/a/new.txt")).unwrap(),
            b"first\n"
        );
        assert!(
            resolver.execute_tool(&resources, &call).is_err(),
            "an old presented name cannot replay a mutable effect"
        );
        assert_eq!(seen.lock().unwrap().len(), 2);
        let mut later = payload_tool(
            "bash",
            json!({"command":"mv core final && echo later > final/next.txt"}),
        );
        later.id = "original-call-2".into();
        resolver.execute_tool(&resources, &later).unwrap();
        let records = seen.lock().unwrap();
        assert_eq!(
            (&records[2].0, &records[2].2, records[2].3),
            (&later.id, &later.arguments, 0)
        );
        assert_eq!(records[2].4.to, "final");
        assert_eq!(
            fs::read(root.path().join("targets/a/next.txt")).unwrap(),
            b"later\n"
        );
    }

    #[test]
    fn native_call_bound_root_rename_refuses_missing_identity_and_ended_host_before_effects() {
        for case in ["missing", "empty", "ended"] {
            let root = tempfile::tempdir().unwrap();
            fs::create_dir_all(root.path().join("targets/a")).unwrap();
            fs::write(root.path().join("targets/a/original.txt"), "preserved").unwrap();
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let capture = calls.clone();
            let resolver = NativeWorkspaceResolver::new(root.path())
                .unwrap()
                .with_root_rename_admission(|_| panic!("refusal must not fall back to legacy"))
                .with_root_rename_call_admission(move |_, _, _| {
                    capture.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if case == "ended" {
                        Err("original office authority ended".into())
                    } else {
                        Ok(())
                    }
                });
            let mut resources = payload_test_resources();
            resources[0].selector = Some("targets/a".into());
            resources[0].presented_as = Some("api".into());
            resources[0].writable = Some(true);
            let mut call = payload_tool(
                "bash",
                json!({"command":"mv api backend && echo changed > backend/original.txt && echo new > backend/new.txt"}),
            );
            if case == "empty" {
                call.id = " ".into();
            }
            let result = if case == "missing" {
                resolver.bash(
                    &call.arguments,
                    &resolver.admitted_view(&resources).unwrap(),
                )
            } else {
                resolver.execute_tool(&resources, &call)
            };
            let error = result.expect_err(case);
            assert_eq!(
                error,
                match case {
                    "missing" => "root rename has no original tool call",
                    "empty" => "root rename has no original tool call ID",
                    _ => "original office authority ended",
                }
            );
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                usize::from(case == "ended")
            );
            assert!(resolver.root_renames.lock().unwrap().is_empty());
            assert_eq!(
                fs::read(root.path().join("targets/a/original.txt")).unwrap(),
                b"preserved"
            );
            assert!(!root.path().join("targets/a/new.txt").exists());
            resolver
                .execute_tool(
                    &resources,
                    &payload_tool("read", json!({"path":"api/original.txt"})),
                )
                .unwrap();
            assert!(resolver
                .execute_tool(
                    &resources,
                    &payload_tool("read", json!({"path":"backend/original.txt"}))
                )
                .is_err());
        }
    }

    #[test]
    fn native_payload_retention_receives_original_bytes_before_effects() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("removed.txt"), "delete me").unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let retained = captured.clone();
        let location = root.path().to_owned();
        let resolver = NativeWorkspaceResolver::new(root.path())
            .unwrap()
            .with_payload_retention(move |prepared, body| {
                assert_eq!(prepared.content_hash, sha256_hex(body));
                assert_eq!(prepared.bytes, body.len() as u64);
                match (prepared.path.as_str(), prepared.kind.as_str()) {
                    ("nested/result.txt", "add") => assert!(!location.join("nested").exists()),
                    ("nested/result.txt", "modify") => assert_eq!(
                        fs::read(location.join(&prepared.path)).unwrap(),
                        b"original"
                    ),
                    ("removed.txt", "delete") => {
                        assert!(body.is_empty());
                        assert!(location.join(&prepared.path).exists());
                    }
                    ("binary.txt", "add") => assert!(!location.join(&prepared.path).exists()),
                    ("binary.txt", "modify") => {
                        assert_eq!(fs::read(location.join(&prepared.path)).unwrap(), b"a\0b")
                    }
                    _ => panic!("unexpected prepared native effect"),
                }
                retained
                    .lock()
                    .unwrap()
                    .push((prepared.clone(), body.to_vec()));
                Ok(())
            });
        let resources = payload_test_resources();
        resolver
            .execute_tool(
                &resources,
                &payload_tool(
                    "write",
                    json!({"path":"nested/result.txt", "content":"original"}),
                ),
            )
            .unwrap();
        resolver.execute_tool(&resources, &payload_tool("edit", json!({"path":"nested/result.txt", "edits":[{"oldText":"original", "newText":"edited"}]}))).unwrap();
        resolver
            .execute_tool(
                &resources,
                &payload_tool(
                    "bash",
                    json!({"command":"rm removed.txt; printf 'a\\000b' > binary.txt"}),
                ),
            )
            .unwrap();
        resolver
            .execute_tool(
                &resources,
                &payload_tool("bash", json!({"command":"printf 'c\\000d' > binary.txt"})),
            )
            .unwrap();
        let bodies = captured.lock().unwrap();
        assert_eq!(bodies.len(), 5);
        assert_eq!(bodies[0].1, b"original");
        assert_eq!(bodies[1].1, b"edited");
        let binary = bodies
            .iter()
            .find(|(prepared, _)| prepared.path == "binary.txt")
            .unwrap();
        assert_eq!(binary.1, b"a\0b");
        assert_eq!(fs::read(root.path().join("binary.txt")).unwrap(), b"c\0d");
        assert_eq!(bodies.last().unwrap().1, b"c\0d");
        fs::write(
            root.path().join("nested/result.txt"),
            "later pending replacement",
        )
        .unwrap();
        assert_eq!(bodies[0].1, b"original");
        assert_eq!(bodies[1].1, b"edited");
        let TurnWitness::Witnessed { writes, .. } = resolver.take_turn_witness() else {
            panic!("successful owner witness required")
        };
        assert_eq!(writes.len(), 5);
        for write in writes {
            assert!(bodies
                .iter()
                .any(|(prepared, _)| prepared.path == write.path
                    && prepared.kind == write.kind
                    && prepared.content_hash == write.content_hash
                    && prepared.bytes == write.bytes));
        }
    }

    #[test]
    fn native_payload_retention_refusal_prevents_write_edit_and_entire_bash_batch() {
        for name in ["write", "edit", "bash"] {
            let root = tempfile::tempdir().unwrap();
            fs::write(root.path().join("original.txt"), "original").unwrap();
            fs::write(root.path().join("removed.txt"), "preserve deletion target").unwrap();
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = calls.clone();
            let resolver = NativeWorkspaceResolver::new(root.path())
                .unwrap()
                .with_payload_retention(move |_, _| {
                    let count = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if name == "bash" && count == 0 {
                        Ok(())
                    } else {
                        Err("synthetic private storage diagnostic".into())
                    }
                });
            let arguments = match name {
                "write" => json!({"path":"nested/result.txt", "content":"refused"}),
                "edit" => {
                    json!({"path":"original.txt", "edits":[{"oldText":"original", "newText":"refused"}]})
                }
                _ => {
                    json!({"command":"rm removed.txt; printf refused > original.txt; mkdir nested; printf refused > nested/result.txt"})
                }
            };
            let error = resolver
                .execute_tool(&payload_test_resources(), &payload_tool(name, arguments))
                .unwrap_err();
            assert_eq!(error, "native workspace payload retention refused");
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                if name == "bash" { 2 } else { 1 }
            );
            assert_eq!(
                fs::read(root.path().join("original.txt")).unwrap(),
                b"original"
            );
            assert_eq!(
                fs::read(root.path().join("removed.txt")).unwrap(),
                b"preserve deletion target"
            );
            assert!(!root.path().join("nested").exists());
            let TurnWitness::Witnessed { writes, .. } = resolver.take_turn_witness() else {
                panic!("no unmediated effect")
            };
            assert!(writes.is_empty());
        }
    }

    #[test]
    fn native_payload_retention_refusal_preserves_presented_roots() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("targets/a")).unwrap();
        fs::write(root.path().join("targets/a/original.txt"), "preserved").unwrap();
        let resolver = NativeWorkspaceResolver::new(root.path())
            .unwrap()
            .with_root_rename_admission(|_| panic!("retention refusal precedes rename admission"))
            .with_payload_retention(|prepared, body| {
                assert_eq!(prepared.path, "targets/a/new.txt");
                assert_eq!(body, b"refused\n");
                Err("private storage diagnostic".into())
            });
        let mut resources = payload_test_resources();
        resources[0].selector = Some("targets/a".into());
        resources[0].presented_as = Some("api".into());
        resources[0].writable = Some(true);
        assert_eq!(
            resolver
                .execute_tool(
                    &resources,
                    &payload_tool(
                        "bash",
                        json!({"command":"mv api backend && echo refused > backend/new.txt"})
                    )
                )
                .unwrap_err(),
            "native workspace payload retention refused"
        );
        assert!(resolver.root_renames.lock().unwrap().is_empty());
        assert!(!root.path().join("targets/a/new.txt").exists());
        assert_eq!(
            fs::read(root.path().join("targets/a/original.txt")).unwrap(),
            b"preserved"
        );
        resolver
            .execute_tool(
                &resources,
                &payload_tool("read", json!({"path":"api/original.txt"})),
            )
            .unwrap();
        assert!(resolver
            .execute_tool(
                &resources,
                &payload_tool("read", json!({"path":"backend/original.txt"}))
            )
            .is_err());
    }

    #[test]
    fn native_payload_retention_preparation_is_not_a_successful_write_witness() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("directory.txt")).unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let retained = captured.clone();
        let resolver = NativeWorkspaceResolver::new(root.path())
            .unwrap()
            .with_payload_retention(move |prepared, body| {
                retained
                    .lock()
                    .unwrap()
                    .push((prepared.clone(), body.to_vec()));
                Ok(())
            });
        assert!(resolver
            .execute_tool(
                &payload_test_resources(),
                &payload_tool(
                    "write",
                    json!({"path":"directory.txt", "content":"prepared but never written"})
                )
            )
            .is_err());
        assert_eq!(captured.lock().unwrap().len(), 1);
        assert!(root.path().join("directory.txt").is_dir());
        let TurnWitness::Witnessed { writes, .. } = resolver.take_turn_witness() else {
            panic!("no unmediated effect")
        };
        assert!(writes.is_empty());
    }

    #[test]
    fn native_workspace_tools_are_confined_and_honor_read_only_subtrees() {
        let root = std::env::temp_dir().join(format!(
            "whip-native-workspace-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".method")).expect("dirs");
        fs::write(root.join("note.txt"), "alpha\nbeta\n").expect("note");
        fs::write(root.join("other.txt"), "separate\n").expect("other");
        fs::write(root.join(".method/SYSTEM.md"), "protected").expect("method");
        let resolver = NativeWorkspaceResolver::new(&root)
            .expect("resolver")
            .read_only([PathBuf::from(".method")])
            .expect("read-only path");
        let resources = [ResourceRef {
            handle: "project".to_owned(),
            kind: "file_store".to_owned(),
            selector: None,
            writable: None,
            presented_as: None,
        }];

        let read = resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "read-1".to_owned(),
                    name: "read".to_owned(),
                    arguments: json!({ "path": "note.txt" }),
                },
            )
            .expect("read");
        assert!(read.contains("1: alpha"));
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "read-2".to_owned(),
                    name: "read".to_owned(),
                    arguments: json!({ "path": "other.txt" }),
                },
            )
            .expect("read again");
        let grep = resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "grep-file".to_owned(),
                    name: "grep".to_owned(),
                    arguments: json!({ "path": "note.txt", "pattern": "alpha" }),
                },
            )
            .expect("single-file grep");
        assert!(grep.contains("alpha"));
        let no_matches = resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "grep-empty".to_owned(),
                    name: "grep".to_owned(),
                    arguments: json!({ "path": "other.txt", "pattern": "absent" }),
                },
            )
            .expect("single-file grep with no matches");
        assert!(no_matches.is_empty());
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "grep-directory".to_owned(),
                    name: "grep".to_owned(),
                    arguments: json!({ "path": ".", "pattern": "alpha" }),
                },
            )
            .expect("directory grep");
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "edit-1".to_owned(),
                    name: "edit".to_owned(),
                    arguments: json!({
                        "path": "note.txt",
                        "edits": [{ "oldText": "beta", "newText": "gamma" }]
                    }),
                },
            )
            .expect("edit");
        // An intervening edit does not discard a prior read in the same batch
        // or acquire its source identity under its own call ID.
        assert!(resolver.take_model_read_witness("edit-1").is_none());
        assert_eq!(
            resolver.take_model_read_witness("read-1"),
            Some(ModelReadWitness {
                path: "note.txt".to_owned(),
                content_hash: whipplescript_store::stable_hash_bytes_hex(b"alpha\nbeta\n"),
            })
        );
        assert_eq!(
            resolver.take_model_read_witness("read-2"),
            Some(ModelReadWitness {
                path: "other.txt".to_owned(),
                content_hash: whipplescript_store::stable_hash_bytes_hex(b"separate\n"),
            })
        );
        assert_eq!(
            resolver.take_model_read_witness("grep-file"),
            Some(ModelReadWitness {
                path: "note.txt".to_owned(),
                content_hash: whipplescript_store::stable_hash_bytes_hex(b"alpha\nbeta\n"),
            })
        );
        assert_eq!(
            resolver.take_model_read_witness("grep-empty"),
            Some(ModelReadWitness {
                path: "other.txt".to_owned(),
                content_hash: whipplescript_store::stable_hash_bytes_hex(b"separate\n"),
            })
        );
        assert!(resolver.take_model_read_witness("grep-directory").is_none());
        let scan = resolver
            .take_model_scan_witness("grep-directory")
            .expect("directory scan witness");
        assert_eq!(scan.root, ".");
        assert_eq!(scan.files.len(), 3);
        assert!(
            scan.files.iter().any(|file| {
                file.path == "other.txt"
                    && file.content_hash
                        == whipplescript_store::stable_hash_bytes_hex(b"separate\n")
            }),
            "a negative match still contributes its source"
        );
        assert!(resolver.take_model_scan_witness("grep-directory").is_none());
        let found = resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "find-directory".to_owned(),
                    name: "find".to_owned(),
                    arguments: json!({ "path": ".", "pattern": "note*" }),
                },
            )
            .expect("find filenames");
        assert_eq!(found, "note.txt");
        let find_scan = resolver
            .take_model_scan_witness("find-directory")
            .expect("bounded find witness");
        assert_eq!(find_scan.root, ".");
        assert_eq!(find_scan.files.len(), 3);
        assert!(find_scan.files.iter().any(|file| {
            file.path == "other.txt"
                && file.content_hash == whipplescript_store::stable_hash_bytes_hex(b"separate\n")
        }));
        assert!(resolver.take_model_scan_witness("find-directory").is_none());
        assert_eq!(
            resolver
                .execute_tool(
                    &resources,
                    &ToolCall {
                        id: "find-file".to_owned(),
                        name: "find".to_owned(),
                        arguments: json!({ "path": "other.txt", "pattern": "absent*" }),
                    },
                )
                .expect("single-file find"),
            ""
        );
        assert_eq!(
            resolver.take_model_read_witness("find-file"),
            Some(ModelReadWitness {
                path: "other.txt".to_owned(),
                content_hash: whipplescript_store::stable_hash_bytes_hex(b"separate\n"),
            })
        );
        assert!(resolver.take_model_read_witness("read-1").is_none());
        assert_eq!(
            resolver.execute_tool(
                &resources,
                &ToolCall {
                    id: "unknown-1".to_owned(),
                    name: "unknown".to_owned(),
                    arguments: json!({}),
                },
            ),
            Err("tool has no native workspace implementation".to_owned())
        );
        assert!(resolver.take_model_read_witness("unknown-1").is_none());
        assert_eq!(
            fs::read_to_string(root.join("note.txt")).expect("edited note"),
            "alpha\ngamma\n"
        );

        for path in ["../outside", ".method/SYSTEM.md"] {
            assert!(resolver
                .execute_tool(
                    &resources,
                    &ToolCall {
                        id: "write-denied".to_owned(),
                        name: "write".to_owned(),
                        arguments: json!({ "path": path, "content": "tampered" }),
                    },
                )
                .is_err());
        }
        assert_eq!(
            fs::read_to_string(root.join(".method/SYSTEM.md")).expect("protected method"),
            "protected"
        );
        assert!(native_workspace_tool_specs(false)
            .iter()
            .all(|tool| tool.name != "write" && tool.name != "edit"));
        assert!(native_workspace_tool_specs(true)
            .iter()
            .any(|tool| tool.name == "write"));
        fs::create_dir(root.join("empty")).expect("empty directory");
        let listing = resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "list-root".to_owned(),
                    name: "ls".to_owned(),
                    arguments: json!({ "path": "." }),
                },
            )
            .expect("directory listing");
        assert!(listing.contains("empty/"));
        let listed = resolver
            .take_model_scan_witness("list-root")
            .expect("bounded listing witness");
        assert_eq!(listed.root, ".");
        assert_eq!(listed.files.len(), 2);
        assert!(listed.directories.contains(&"empty".to_owned()));
        assert!(listed.directories.contains(&".method".to_owned()));
        assert!(listed.files.iter().any(|file| {
            file.path == "note.txt"
                && file.content_hash
                    == whipplescript_store::stable_hash_bytes_hex(b"alpha\ngamma\n")
        }));
        assert!(resolver.take_model_scan_witness("list-root").is_none());
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "empty-list".to_owned(),
                    name: "ls".to_owned(),
                    arguments: json!({ "path": "empty" }),
                },
            )
            .expect("empty listing");
        assert!(resolver.take_model_scan_witness("empty-list").is_none());
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "empty-scan".to_owned(),
                    name: "grep".to_owned(),
                    arguments: json!({ "path": "empty", "pattern": "absent" }),
                },
            )
            .expect("empty grep still runs");
        assert!(resolver.take_model_scan_witness("empty-scan").is_none());
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "empty-find".to_owned(),
                    name: "find".to_owned(),
                    arguments: json!({ "path": "empty", "pattern": "*" }),
                },
            )
            .expect("empty find still runs");
        assert!(resolver.take_model_scan_witness("empty-find").is_none());
        fs::write(root.join("invalid.txt"), [0xff]).expect("invalid UTF-8 file");
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "incomplete-scan".to_owned(),
                    name: "grep".to_owned(),
                    arguments: json!({ "path": ".", "pattern": "absent" }),
                },
            )
            .expect("grep ignores unreadable text");
        assert!(resolver
            .take_model_scan_witness("incomplete-scan")
            .is_none());
        fs::remove_file(root.join("invalid.txt")).expect("remove invalid text");
        for index in 0..125 {
            fs::write(root.join(format!("extra-{index}.txt")), "no match").expect("extra file");
        }
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "bounded-find".to_owned(),
                    name: "find".to_owned(),
                    arguments: json!({ "path": ".", "pattern": "absent*" }),
                },
            )
            .expect("bounded find still runs");
        assert_eq!(
            resolver
                .take_model_scan_witness("bounded-find")
                .expect("128 files are fully witnessed")
                .files
                .len(),
            128
        );
        fs::write(root.join("extra-125.txt"), "no match").expect("129th file");
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "oversized-scan".to_owned(),
                    name: "grep".to_owned(),
                    arguments: json!({ "path": ".", "pattern": "absent" }),
                },
            )
            .expect("large grep still runs");
        assert!(resolver.take_model_scan_witness("oversized-scan").is_none());
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "oversized-find".to_owned(),
                    name: "find".to_owned(),
                    arguments: json!({ "path": ".", "pattern": "absent*" }),
                },
            )
            .expect("large find still runs");
        assert!(resolver.take_model_scan_witness("oversized-find").is_none());
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "oversized-list".to_owned(),
                    name: "ls".to_owned(),
                    arguments: json!({ "path": "." }),
                },
            )
            .expect("large listing still runs");
        assert!(resolver.take_model_scan_witness("oversized-list").is_none());
        fs::create_dir(root.join("large")).expect("large directory");
        fs::File::create(root.join("large/one.bin"))
            .expect("large file")
            .set_len(8 * 1024 * 1024 + 1)
            .expect("sparse large file");
        resolver
            .execute_tool(
                &resources,
                &ToolCall {
                    id: "large-file-find".to_owned(),
                    name: "find".to_owned(),
                    arguments: json!({ "path": "large", "pattern": "absent*" }),
                },
            )
            .expect("large-file find still runs");
        assert!(resolver
            .take_model_scan_witness("large-file-find")
            .is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn native_workspace_tools_honor_every_file_store_selector() {
        let root = std::env::temp_dir().join(format!(
            "whip-native-selectors-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(root.join("targets/t-a")).expect("target a");
        fs::create_dir_all(root.join("targets/t-b")).expect("target b");
        fs::create_dir_all(root.join(".runtime")).expect("runtime");
        fs::write(root.join("targets/t-a/a.txt"), "a").expect("a");
        fs::write(root.join("targets/t-b/b.txt"), "b").expect("b");
        fs::write(root.join(".runtime/targets.json"), "{}").expect("manifest");
        fs::write(root.join("outside.txt"), "secret").expect("outside");
        let resolver = NativeWorkspaceResolver::new(&root).expect("resolver");
        let resources = [
            ResourceRef {
                handle: "target-a".to_owned(),
                kind: "file_store".to_owned(),
                selector: Some("targets/t-a".to_owned()),
                writable: Some(true),
                presented_as: None,
            },
            ResourceRef {
                handle: "target-b".to_owned(),
                kind: "file_store".to_owned(),
                selector: Some("targets/t-b".to_owned()),
                writable: Some(true),
                presented_as: None,
            },
            ResourceRef {
                handle: "target-manifest".to_owned(),
                kind: "file_store".to_owned(),
                selector: Some(".runtime/targets.json".to_owned()),
                writable: Some(false),
                presented_as: None,
            },
            ResourceRef {
                handle: "command".to_owned(),
                kind: "command".to_owned(),
                selector: None,
                writable: None,
                presented_as: None,
            },
        ];
        let call = |name: &str, arguments: Value| ToolCall {
            id: format!("{name}-selector-test"),
            name: name.to_owned(),
            arguments,
        };

        resolver
            .execute_tool(
                &resources,
                &call("read", json!({ "path": ".runtime/targets.json" })),
            )
            .expect("manifest is explicitly admitted");
        resolver
            .execute_tool(
                &resources,
                &call(
                    "write",
                    json!({ "path": "targets/t-b/new.txt", "content": "candidate" }),
                ),
            )
            .expect("selected target is writable");
        for call in [
            call("read", json!({ "path": "outside.txt" })),
            call("ls", json!({ "path": "." })),
            call(
                "write",
                json!({ "path": "outside-new.txt", "content": "escape" }),
            ),
            call(
                "bash",
                json!({ "command": "echo escape > outside-new.txt" }),
            ),
        ] {
            assert!(
                resolver.execute_tool(&resources, &call).is_err(),
                "{} must remain inside admitted selectors",
                call.name
            );
        }
        assert!(!root.join("outside-new.txt").exists());
        assert_eq!(
            fs::read_to_string(root.join("outside.txt")).expect("outside unchanged"),
            "secret"
        );
        let _ = fs::remove_dir_all(root);
    }

    /// The native workspace `grep` honours the schema it advertises.
    ///
    /// It read only `pattern` and `path`. `ignoreCase`, `context` and `limit`
    /// are all declared by its own tool spec and all three were ignored, so a
    /// caller asking for a case-insensitive search got a case-sensitive one, a
    /// context window got no context, and a limit of one got up to five
    /// thousand — each silently, because a tool that ignores an argument has no
    /// way to say so.
    #[test]
    fn presented_roots_are_what_the_model_sees_and_renames_need_admission() {
        let root = std::env::temp_dir().join(format!(
            "whip-native-presented-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(root.join("targets/t-a/src")).expect("target a");
        fs::create_dir_all(root.join("targets/t-b")).expect("target b");
        fs::create_dir_all(root.join(".runtime")).expect("runtime");
        fs::write(root.join("targets/t-a/src/main.rs"), "fn main() {}\n").expect("a");
        fs::write(root.join("targets/t-b/readme.md"), "fn in prose\n").expect("b");
        fs::write(root.join(".runtime/targets.json"), "{}").expect("manifest");
        let store =
            |handle: &str, selector: &str, presented: Option<&str>, writable: bool| ResourceRef {
                handle: handle.to_owned(),
                kind: "file_store".to_owned(),
                selector: Some(selector.to_owned()),
                writable: Some(writable),
                presented_as: presented.map(str::to_owned),
            };
        let resources = [
            store("target:a", "targets/t-a", Some("api"), true),
            store("target:b", "targets/t-b", Some("web"), false),
            store("manifest", ".runtime/targets.json", None, false),
            ResourceRef {
                handle: "command".to_owned(),
                kind: "command".to_owned(),
                selector: None,
                writable: None,
                presented_as: None,
            },
        ];
        let call = |name: &str, arguments: Value| ToolCall {
            id: format!("{name}-presented-test"),
            name: name.to_owned(),
            arguments,
        };
        let run = |resolver: &NativeWorkspaceResolver, name: &str, arguments: Value| {
            resolver.execute_tool(&resources, &call(name, arguments))
        };

        let resolver = NativeWorkspaceResolver::new(&root).expect("resolver");
        assert_eq!(
            run(&resolver, "ls", json!({})).expect("the root is listed"),
            ".runtime/\napi/\nweb/"
        );
        assert_eq!(
            run(&resolver, "ls", json!({ "path": "api" })).unwrap(),
            "src/"
        );
        assert_eq!(
            run(&resolver, "read", json!({ "path": "api/src/main.rs" })).unwrap(),
            "1: fn main() {}"
        );
        // Records keep the selector.
        assert_eq!(
            resolver
                .take_model_read_witness("read-presented-test")
                .expect("exact read")
                .path,
            "targets/t-a/src/main.rs"
        );
        let hidden = run(
            &resolver,
            "read",
            json!({ "path": "targets/t-a/src/main.rs" }),
        )
        .unwrap_err();
        assert!(hidden.contains("outside the admitted"), "{hidden}");
        assert_eq!(
            run(&resolver, "find", json!({ "pattern": "*.rs" })).unwrap(),
            "api/src/main.rs"
        );
        assert_eq!(
            run(&resolver, "grep", json!({ "pattern": "fn" })).unwrap(),
            "api/src/main.rs:1:fn main() {}\nweb/readme.md:1:fn in prose"
        );
        run(
            &resolver,
            "write",
            json!({ "path": "api/new.txt", "content": "n" }),
        )
        .expect("a writable root");
        assert_eq!(
            fs::read_to_string(root.join("targets/t-a/new.txt")).unwrap(),
            "n"
        );
        assert!(run(
            &resolver,
            "write",
            json!({ "path": "web/x", "content": "x" })
        )
        .is_err());
        let TurnWitness::Witnessed { writes, .. } = resolver.take_turn_witness() else {
            panic!("witnessed turn");
        };
        assert_eq!(writes[0].path, "targets/t-a/new.txt");

        // A command that changes nothing read-only runs beside read-only files.
        assert_eq!(
            run(
                &resolver,
                "bash",
                json!({ "command": "cat api/src/main.rs; ls" })
            )
            .unwrap(),
            "fn main() {}\napi\nweb\n"
        );
        assert!(run(
            &resolver,
            "bash",
            json!({ "command": "echo x > .runtime/targets.json" })
        )
        .is_err());
        let refused = run(&resolver, "bash", json!({ "command": "mv api backend" })).unwrap_err();
        assert!(refused.contains("not supported"), "{refused}");
        assert!(
            root.join("targets/t-a/src/main.rs").exists(),
            "nothing moved"
        );

        let admitted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = std::sync::Arc::clone(&admitted);
        let resolver = NativeWorkspaceResolver::new(&root)
            .expect("resolver")
            .with_root_rename_admission(move |rename| {
                seen.lock().unwrap().push(rename.clone());
                Ok(())
            });
        run(
            &resolver,
            "bash",
            json!({ "command": "mv api backend && echo b > backend/b.txt" }),
        )
        .expect("an admitted rename");
        assert_eq!(
            admitted.lock().unwrap().as_slice(),
            &[RootRename {
                handle: "target:a".into(),
                selector: "targets/t-a".into(),
                from: "api".into(),
                to: "backend".into(),
            }]
        );
        assert_eq!(
            fs::read_to_string(root.join("targets/t-a/b.txt")).unwrap(),
            "b\n"
        );
        assert!(
            root.join("targets/t-a/src/main.rs").exists(),
            "storage did not move"
        );
        // The rest of the turn sees the new name.
        run(&resolver, "read", json!({ "path": "backend/b.txt" })).expect("renamed");
        assert!(run(&resolver, "read", json!({ "path": "api/b.txt" })).is_err());
        let refusing = NativeWorkspaceResolver::new(&root)
            .expect("resolver")
            .with_root_rename_admission(|_| Err("names are frozen".to_owned()));
        let refused = run(
            &refusing,
            "bash",
            json!({ "command": "mv api backend && echo c > backend/c.txt" }),
        )
        .unwrap_err();
        assert!(refused.contains("names are frozen"), "{refused}");
        assert!(
            !root.join("targets/t-a/c.txt").exists(),
            "a refused result writes nothing"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ws331_edit_preserves_bom_refuses_overlap_and_shifts_disjoint_regions() {
        let root = std::env::temp_dir().join(format!(
            "whip-ws331-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let resolver = NativeWorkspaceResolver::new(&root).unwrap();
        let admitted = [ResourceRef {
            handle: "project".into(),
            kind: "file_store".into(),
            selector: None,
            writable: None,
            presented_as: None,
        }];
        let edit = |arguments| {
            resolver.execute_tool(
                &admitted,
                &ToolCall {
                    id: "edit-one".into(),
                    name: "edit".into(),
                    arguments,
                },
            )
        };
        let original = "\u{feff}α beta gamma";
        fs::write(root.join("e.txt"), original).unwrap();
        let bom =
            edit(json!({"path":"e.txt", "edits":[{"oldText":"α beta gamma", "newText":"δ"}]}));
        assert!(bom.is_ok(), "{bom:?}");
        assert_eq!(fs::read_to_string(root.join("e.txt")).unwrap(), "\u{feff}δ");
        fs::write(root.join("e.txt"), original).unwrap();
        let overlap = edit(
            json!({"path":"e.txt", "edits":[{"oldText":"α beta", "newText":"α beta"}, {"oldText":"beta gamma", "newText":"BETA gamma"}]}),
        );
        assert!(overlap.unwrap_err().contains("overlap"));
        assert_eq!(fs::read_to_string(root.join("e.txt")).unwrap(), original);
        let shifted = edit(
            json!({"path":"e.txt", "edits":[{"oldText":"gamma", "newText":"ΓΓΓ"}, {"oldText":"α", "newText":"longer-α"}, {"oldText":"beta", "newText":"β"}]}),
        );
        assert!(shifted.is_ok(), "{shifted:?}");
        assert_eq!(
            fs::read_to_string(root.join("e.txt")).unwrap(),
            "\u{feff}longer-α β ΓΓΓ"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn native_grep_honours_ignore_case_context_and_limit() {
        let root = std::env::temp_dir().join(format!(
            "whip-native-grep-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("dirs");
        fs::write(root.join("a.txt"), "alpha\nNEEDLE\nomega\nneedle\n").expect("fixture");
        let resolver = NativeWorkspaceResolver::new(&root).expect("resolver");
        let admitted = [ResourceRef {
            handle: "project".to_owned(),
            kind: "file_store".to_owned(),
            selector: None,
            writable: None,
            presented_as: None,
        }];
        let grep = |arguments: Value| {
            resolver
                .execute_tool(
                    &admitted,
                    &ToolCall {
                        id: "grep-1".to_owned(),
                        name: "grep".to_owned(),
                        arguments,
                    },
                )
                .expect("grep runs")
        };

        // Case sensitivity is the default, and `ignoreCase` changes it.
        assert_eq!(grep(json!({"pattern": "needle"})).lines().count(), 1);
        assert_eq!(
            grep(json!({"pattern": "needle", "ignoreCase": true}))
                .lines()
                .count(),
            2
        );

        // `limit` caps the MATCHES.
        assert_eq!(
            grep(json!({"pattern": "needle", "ignoreCase": true, "limit": 1}))
                .lines()
                .count(),
            1
        );

        // `context` brings neighbouring lines, marked `-` rather than `:`.
        let with_context = grep(json!({"pattern": "NEEDLE", "context": 1}));
        assert_eq!(with_context.lines().count(), 3, "{with_context}");
        assert!(
            with_context.contains("a.txt-1-alpha") && with_context.contains("a.txt:2:NEEDLE"),
            "a context line is `-`, the match is `:`: {with_context}"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn native_command_tool_is_governed_virtual_bash() {
        let root = std::env::temp_dir().join(format!(
            "whip-native-command-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(root.join(".method")).expect("dirs");
        let resolver = NativeWorkspaceResolver::new(&root)
            .expect("resolver")
            .read_only([PathBuf::from(".method")])
            .expect("read-only");
        let project_only = [ResourceRef {
            handle: "project".to_owned(),
            kind: "file_store".to_owned(),
            selector: None,
            writable: None,
            presented_as: None,
        }];
        let admitted = [
            project_only[0].clone(),
            ResourceRef {
                handle: "command".to_owned(),
                kind: "command".to_owned(),
                selector: None,
                writable: None,
                presented_as: None,
            },
        ];
        let call = |command: &str| ToolCall {
            id: "bash-1".to_owned(),
            name: "bash".to_owned(),
            arguments: json!({ "command": command, "timeout": 30 }),
        };

        assert!(resolver
            .execute_tool(&project_only, &call("date +%s"))
            .is_err());
        for command in ["", " \t\n "] {
            assert_eq!(
                resolver.execute_tool(&admitted, &call(command)),
                Err("command must not be empty".to_owned()),
            );
        }
        assert_eq!(
            resolver
                .execute_tool(&admitted, &call("date +%s"))
                .expect("admitted command"),
            "0\n"
        );
        resolver
            .execute_tool(&admitted, &call("printf hello | tr a-z A-Z > output.txt"))
            .expect("pipeline");
        assert_eq!(
            fs::read_to_string(root.join("output.txt")).expect("virtual bash delta"),
            "HELLO"
        );
        assert!(resolver
            .execute_tool(&admitted, &call("echo tampered > .method/SYSTEM.md"))
            .is_err());
        assert!(resolver
            .execute_tool(&admitted, &call("definitely-not-a-bashkit-command"))
            .is_err());
        // `bash` is served entirely by the in-isolate virtual shell (Bashkit):
        // there is no OS command executor to invoke — the seam was removed once
        // Bashkit became the only command path (DR-0039).
        assert!(native_workspace_tool_specs_with_command(true, true)
            .iter()
            .any(|tool| tool.name == "bash"));
        let _ = fs::remove_dir_all(root);
    }

    struct CutPackages;

    impl PackageResolver for CutPackages {
        fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
            ResolvedPackage::compile(
                version_ref,
                r#"
file store project {
  root "."
  allow read ["**"]
  allow write ["**"]
}

workflow HostChat {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
  }

  rule converse
    when started
  => {
    tell assistant
      with access to project {
        read ["**"]
        write ["**"]
      }
      "host turn"
  }
}
"#,
                Some("HostChat"),
                "assistant",
                "Help through the governed workspace tools.",
                vec![
                    ToolSpec {
                        name: "read".to_owned(),
                        description: "Read a workspace path.".to_owned(),
                        input_schema: json!({
                            "type": "object",
                            "properties": { "path": { "type": "string" } },
                            "required": ["path"],
                            "additionalProperties": false
                        }),
                    },
                    ToolSpec {
                        name: "write".to_owned(),
                        description: "Write a workspace path.".to_owned(),
                        input_schema: json!({
                            "type": "object",
                            "properties": {
                                "path": { "type": "string" },
                                "content": { "type": "string" }
                            },
                            "required": ["path", "content"],
                            "additionalProperties": false
                        }),
                    },
                    ToolSpec {
                        name: "bash".to_owned(),
                        description: "Run an admitted native command.".to_owned(),
                        input_schema: json!({
                            "type": "object",
                            "properties": {
                                "command": { "type": "string" },
                                "timeout": { "type": "integer" }
                            },
                            "required": ["command"],
                            "additionalProperties": false
                        }),
                    },
                ],
                6,
            )
        }
    }

    /// DR-0036: the terminal receipt references the turn's witnessed workspace
    /// cut and the guarantee report carries the envelope-declared dynamic
    /// section — held, violated, or not-evaluated, never silently omitted —
    /// and a turn whose workspace moved through an unmediated channel
    /// declines the cut instead of fabricating one.
    #[test]
    fn receipt_workspace_cut_and_dynamic_guarantees_from_witnessed_turn() {
        let path = temp_store();
        let workspace = std::env::temp_dir().join(format!(
            "whip-host-cut-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&workspace).expect("workspace");
        let policy_text = SignedEnvelope::sign_for_test(
            "grant file_store project -> file:/workspace readable by Operator\n\
             grant provider model -> provider:openai readable by Operator\n\
             grant provider owned -> provider:owned readable by Operator\n\
             grant command command -> command:local readable by Operator\n\
             grant placement local -> placement:local readable by Operator\n\
             guarantee writes_within:src src/*\n\
             guarantee no_reads_beyond_grant\n\
             guarantee no_tainted_reads:confidential\n",
            "gaugedesk-admin",
        )
        .to_json();
        let mut runtime = GovernedHostRuntime::open(&path, 21, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-cut-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime
            .open_instance(&open, &CutPackages)
            .expect("instance");
        let resources = NativeWorkspaceResolver::new(&workspace).expect("resolver");
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let dynamic_outcome = |guarantee: &Value, name: &str| -> (String, String) {
            let entry = guarantee
                .get("dynamic")
                .and_then(Value::as_array)
                .and_then(|entries| {
                    entries
                        .iter()
                        .find(|entry| entry.get("name").and_then(Value::as_str) == Some(name))
                })
                .unwrap_or_else(|| panic!("dynamic guarantee `{name}` missing: {guarantee}"));
            (
                entry
                    .get("outcome")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                entry
                    .get("detail")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            )
        };
        let evidence_metadata = |runtime: &GovernedHostRuntime,
                                 command: &StartTurnCommand,
                                 evidence_id: &str|
         -> Value {
            let run_id =
                idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
            let item = runtime
                .kernel
                .store()
                .list_evidence_for_subject("run", &run_id)
                .expect("evidence")
                .into_iter()
                .find(|item| item.evidence_id == evidence_id)
                .expect("referenced evidence exists");
            serde_json::from_str(&item.metadata_json).expect("evidence metadata")
        };
        let guarantee_metadata =
            |runtime: &GovernedHostRuntime, command: &StartTurnCommand| -> Value {
                let run_id =
                    idempotency_key(&[&command.instance_ref, &command.command_id, "brokered-run"]);
                let item = runtime
                    .kernel
                    .store()
                    .list_evidence_for_subject("run", &run_id)
                    .expect("evidence")
                    .into_iter()
                    .find(|item| item.kind == "host.turn.guarantee")
                    .expect("guarantee evidence");
                serde_json::from_str(&item.metadata_json).expect("guarantee metadata")
            };

        // Turn 1: one mediated write inside the declared scope. The receipt
        // references the complete witnessed cut; writes_within holds.
        let command1 = turn(&instance.instance_ref, &open.policy, 1);
        let original_start = runtime.pinned_position(&instance.instance_ref).unwrap();
        let turn1 = runtime
            .run_turn_with_driver(
                &command1,
                &CutPackages,
                &secrets,
                &resources,
                &ScriptedDriver::new(vec![
                    json!({
                        "output": [{
                            "type": "function_call",
                            "call_id": "write-1",
                            "name": "write",
                            "arguments": "{\"path\":\"src/out.md\",\"content\":\"cut body\"}"
                        }],
                        "usage": { "input_tokens": 10, "output_tokens": 2 }
                    }),
                    json!({
                        "output_text": "wrote the file",
                        "usage": { "input_tokens": 12, "output_tokens": 3 }
                    }),
                ]),
            )
            .expect("turn 1");
        let receipt1 = turn1.receipt.expect("terminal receipt");
        let cut_ref = receipt1
            .workspace_cut_ref
            .clone()
            .expect("witnessed turn references its workspace cut");
        let cut = evidence_metadata(&runtime, &command1, &cut_ref);
        let before_read = runtime.current_position(&command1.instance_ref).unwrap();
        let provider_reads = secrets.calls.get();
        let original = runtime
            .turn_workspace_witness(&command1, &resources)
            .unwrap()
            .unwrap();
        let reader = RecordedHostRuntime::open(&path, 21, &policy_text, &resources).unwrap();
        assert_eq!(
            reader
                .turn_workspace_witness(&command1, &original_start, &resources)
                .unwrap()
                .unwrap(),
            original
        );
        drop(reader);
        assert_eq!(original.receipt, receipt1);
        assert_eq!(original.writes.len(), 1);
        assert_eq!(original.writes[0].path, "src/out.md");
        assert_eq!(original.writes[0].content_hash, sha256_hex(b"cut body"));
        fs::write(workspace.join("src/out.md"), "later unimported work").unwrap();
        let restarted = GovernedHostRuntime::open(&path, 21, &policy_text).unwrap();
        assert_eq!(
            restarted
                .turn_workspace_witness(&command1, &resources)
                .unwrap()
                .unwrap(),
            original
        );
        assert_eq!(
            runtime.current_position(&command1.instance_ref).unwrap(),
            before_read
        );
        assert_eq!(secrets.calls.get(), provider_reads);
        fs::write(workspace.join("src/out.md"), "cut body").unwrap();
        struct ReadAccess {
            calls: Cell<usize>,
            deny_at: usize,
        }
        impl ResourceResolver for ReadAccess {
            fn check_live_access(&self) -> Result<(), String> {
                self.calls.set(self.calls.get() + 1);
                if self.calls.get() >= self.deny_at {
                    Err("private staff detail".into())
                } else {
                    Ok(())
                }
            }
            fn resolve_image(&self, _: &ResourceRef) -> Result<ResolvedImage, String> {
                unreachable!()
            }
            fn execute_tool(&self, _: &[ResourceRef], _: &ToolCall) -> Result<String, String> {
                unreachable!()
            }
        }
        for deny_at in [1, 2] {
            let access = ReadAccess {
                calls: Cell::new(0),
                deny_at,
            };
            let error = runtime
                .turn_workspace_witness(&command1, &access)
                .unwrap_err();
            assert!(error.to_string().contains(LIVE_ACCESS_REFUSED));
            assert!(!error.to_string().contains("private staff detail"));
            assert_eq!(access.calls.get(), deny_at);
        }
        let mut changed = command1.clone();
        changed.input.text = "different submitted input".into();
        assert!(runtime
            .turn_workspace_witness(&changed, &resources)
            .unwrap_err()
            .to_string()
            .contains("command id reused"));
        let replay_driver = ScriptedDriver::new(vec![]);
        assert!(runtime
            .run_turn_with_driver(&changed, &CutPackages, &secrets, &resources, &replay_driver)
            .unwrap_err()
            .to_string()
            .contains("command id reused"));
        assert!(replay_driver.requests.borrow().is_empty());
        // Corrupt authoritative records, one field at a time, then restore the
        // exact original. No live worktree or resolver scan can repair these.
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .unwrap();
        let original_input = serde_json::to_string(&command1).unwrap();
        for (column, bad) in [
            ("kind", "other"),
            ("status", "queued"),
            ("effect_id", "missing-original"),
            ("input_json", "{}"),
        ] {
            let old: String = connection
                .query_row(
                    &format!("SELECT {column} FROM effects WHERE effect_id=?1"),
                    [&command1.command_id],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute(
                    &format!("UPDATE effects SET {column}=?1 WHERE effect_id=?2"),
                    rusqlite::params![bad, &command1.command_id],
                )
                .unwrap();
            assert!(
                runtime
                    .turn_workspace_witness(&command1, &resources)
                    .is_err(),
                "{column}"
            );
            let key = if column == "effect_id" {
                bad
            } else {
                &command1.command_id
            };
            connection
                .execute(
                    &format!("UPDATE effects SET {column}=?1 WHERE effect_id=?2"),
                    rusqlite::params![old, key],
                )
                .unwrap();
        }
        assert_eq!(
            connection
                .query_row(
                    "SELECT input_json FROM effects WHERE effect_id=?1",
                    [&command1.command_id],
                    |row| row.get::<_, String>(0)
                )
                .unwrap(),
            original_input
        );
        for (column, bad) in [
            ("kind", "other"),
            ("correlation_id", "other-command"),
            ("causation_id", "other-command"),
            ("instance_id", "other-instance"),
            ("evidence_id", "missing-reference"),
            ("metadata_json", "{"),
            (
                "metadata_json",
                "{\"complete\":false,\"writes\":[],\"reads\":[]}",
            ),
        ] {
            let old: String = connection
                .query_row(
                    &format!("SELECT {column} FROM evidence WHERE evidence_id=?1"),
                    [&cut_ref],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute(
                    &format!("UPDATE evidence SET {column}=?1 WHERE evidence_id=?2"),
                    rusqlite::params![bad, &cut_ref],
                )
                .unwrap();
            assert!(
                runtime
                    .turn_workspace_witness(&command1, &resources)
                    .is_err(),
                "{column}"
            );
            let key = if column == "evidence_id" {
                bad
            } else {
                &cut_ref
            };
            connection
                .execute(
                    &format!("UPDATE evidence SET {column}=?1 WHERE evidence_id=?2"),
                    rusqlite::params![old, key],
                )
                .unwrap();
        }
        assert_eq!(
            runtime
                .turn_workspace_witness(&command1, &resources)
                .unwrap()
                .unwrap(),
            original
        );
        let mut absent = command1.clone();
        absent.command_id = "not-run".into();
        assert!(runtime
            .turn_workspace_witness(&absent, &resources)
            .unwrap()
            .is_none());

        assert_eq!(cut.get("complete"), Some(&Value::Bool(true)));
        let writes = cut.get("writes").and_then(Value::as_array).expect("writes");
        assert_eq!(writes.len(), 1);
        assert_eq!(
            writes[0].get("path").and_then(Value::as_str),
            Some("src/out.md")
        );
        assert_eq!(writes[0].get("kind").and_then(Value::as_str), Some("add"));
        assert!(writes[0]
            .get("content_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| !hash.is_empty()));
        let guarantee1 = guarantee_metadata(&runtime, &command1);
        // The public consumer path (GaugeWright ADR 0082 §5) resolves the same
        // report without reaching into the kernel.
        let via_accessor = runtime
            .turn_guarantee_report(&command1)
            .expect("report accessor")
            .expect("report present after a finished turn");
        assert_eq!(via_accessor, guarantee1, "accessor returns the report body");
        assert_eq!(
            dynamic_outcome(&guarantee1, "writes_within:src").0,
            "held",
            "in-scope write holds: {guarantee1}"
        );
        assert_eq!(
            dynamic_outcome(&guarantee1, "no_reads_beyond_grant").0,
            "held"
        );
        assert_eq!(
            dynamic_outcome(&guarantee1, "no_tainted_reads:confidential").0,
            "not_evaluated"
        );
        // Replay returns the same receipt, cut reference included.
        let replay = runtime
            .run_turn_with_driver(
                &command1,
                &CutPackages,
                &secrets,
                &resources,
                &ScriptedDriver::new(Vec::new()),
            )
            .expect("replay");
        assert_eq!(replay.receipt.expect("stored receipt"), receipt1);

        // Turn 2: a write outside the declared scope is reported violated —
        // certified fact for the host's advancement gate, not a refusal.
        let command2 = turn(&instance.instance_ref, &open.policy, 2);
        let turn2 = runtime
            .run_turn_with_driver(
                &command2,
                &CutPackages,
                &secrets,
                &resources,
                &ScriptedDriver::new(vec![
                    json!({
                        "output": [{
                            "type": "function_call",
                            "call_id": "write-2",
                            "name": "write",
                            "arguments": "{\"path\":\"elsewhere/oops.md\",\"content\":\"stray\"}"
                        }],
                        "usage": { "input_tokens": 10, "output_tokens": 2 }
                    }),
                    json!({
                        "output_text": "done",
                        "usage": { "input_tokens": 12, "output_tokens": 3 }
                    }),
                ]),
            )
            .expect("turn 2");
        assert!(turn2.receipt.expect("terminal").workspace_cut_ref.is_some());
        let guarantee2 = guarantee_metadata(&runtime, &command2);
        let (outcome2, detail2) = dynamic_outcome(&guarantee2, "writes_within:src");
        assert_eq!(outcome2, "violated");
        assert!(detail2.contains("elsewhere/oops.md"), "{detail2}");

        // Turn 3: no writes at all claims the explicitly-empty cut —
        // distinguishable from an unwitnessed decline.
        let command3 = turn(&instance.instance_ref, &open.policy, 3);
        let turn3 = runtime
            .run_turn_with_driver(
                &command3,
                &CutPackages,
                &secrets,
                &resources,
                &ScriptedDriver::new(vec![json!({
                    "output_text": "nothing to do",
                    "usage": { "input_tokens": 8, "output_tokens": 2 }
                })]),
            )
            .expect("turn 3");
        let cut3_ref = turn3
            .receipt
            .expect("terminal")
            .workspace_cut_ref
            .expect("explicitly-empty cut is still referenced");
        let cut3 = evidence_metadata(&runtime, &command3, &cut3_ref);
        assert_eq!(
            cut3.get("writes").and_then(Value::as_array).map(Vec::len),
            Some(0)
        );

        // Turn 4: bash remains inside the same witnessed virtual workspace.
        // Unsupported real-git behavior fails honestly as a tool result, but
        // it does not create an unmediated mutation channel or taint the cut.
        let mut command4 = turn(&instance.instance_ref, &open.policy, 4);
        command4.resources.push(ResourceRef {
            handle: "command".to_owned(),
            kind: "command".to_owned(),
            selector: None,
            writable: None,
            presented_as: None,
        });
        let turn4 = runtime
            .run_turn_with_driver(
                &command4,
                &CutPackages,
                &secrets,
                &resources,
                &ScriptedDriver::new(vec![
                    json!({
                        "output": [{
                            "type": "function_call",
                            "call_id": "bash-1",
                            "name": "bash",
                            "arguments": "{\"command\":\"git status\",\"timeout\":30}"
                        }],
                        "usage": { "input_tokens": 10, "output_tokens": 2 }
                    }),
                    json!({
                        "output_text": "ran the command",
                        "usage": { "input_tokens": 12, "output_tokens": 3 }
                    }),
                ]),
            )
            .expect("turn 4");
        assert!(
            turn4.receipt.expect("terminal").workspace_cut_ref.is_some(),
            "virtual bash preserves the complete workspace witness"
        );
        let guarantee4 = guarantee_metadata(&runtime, &command4);
        assert_eq!(dynamic_outcome(&guarantee4, "writes_within:src").0, "held");

        drop(runtime);
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn package_fingerprint_covers_behavior_outside_workflow_source() {
        let source = r#"
workflow Fingerprint {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
  }
  rule converse when started => { tell assistant "hello" }
}
"#;
        let compile = |prompt: &str, writable: bool| {
            ResolvedPackage::compile(
                "package:fingerprint",
                source,
                Some("Fingerprint"),
                "assistant",
                prompt,
                native_workspace_tool_specs(writable),
                4,
            )
            .expect("package compiles")
        };
        let original = compile("first prompt", false);
        assert_ne!(
            original.source_hash,
            compile("second prompt", false).source_hash
        );
        assert_ne!(
            original.source_hash,
            compile("first prompt", true).source_hash
        );
        let more_steps = ResolvedPackage::compile(
            "package:fingerprint",
            source,
            Some("Fingerprint"),
            "assistant",
            "first prompt",
            native_workspace_tool_specs(false),
            5,
        )
        .expect("package compiles");
        assert_ne!(original.source_hash, more_steps.source_hash);
    }

    #[test]
    fn authored_agent_package_owns_prompt_tools_and_identity() {
        let root = std::env::temp_dir().join(format!(
            "whip-authored-package-{}-{}",
            std::process::id(),
            idempotency_key(&["authored-package"])
        ));
        fs::create_dir_all(&root).expect("package dir");
        fs::write(
            root.join(AGENT_PACKAGE_MANIFEST),
            format!(
                r#"{{
  "schema": "{AGENT_PACKAGE_SCHEMA}",
  "source": "method.whip",
  "workflow": "Method",
  "agent": "assistant",
  "system_prompt": "persona.md",
  "capabilities": ["workspace.write", "workspace.read"],
  "agent_abilities": ["workspace.write", "workspace.read"],
  "max_steps": 8
}}"#
            ),
        )
        .expect("manifest");
        fs::write(
            root.join("method.whip"),
            r#"
file store project { root "." allow read ["**"] allow write ["**"] }
workflow Method {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read", "workspace.write"]
  }
  rule converse when started => {
    tell assistant requires ["workspace.read", "workspace.write"]
      with access to project { read ["**"] write ["**"] }
      "Run the method."
  }
}
"#,
        )
        .expect("source");
        fs::write(root.join("persona.md"), "Own the method.").expect("persona");

        let package = AuthoredAgentPackage::load(&root).expect("valid package");
        let first_ref = package.version_ref().to_owned();
        let resolved = package
            .resolve(&first_ref)
            .expect("pinned package resolves");
        assert!(resolved.tools.iter().any(|tool| tool.name == "read"));
        assert!(resolved.tools.iter().any(|tool| tool.name == "write"));
        assert!(!resolved.tools.iter().any(|tool| tool.name == "bash"));
        assert!(package.resolve("whip:agent-package:stale").is_err());

        fs::write(root.join("persona.md"), "Changed method.").expect("changed persona");
        let changed = AuthoredAgentPackage::load(&root).expect("changed package");
        assert_ne!(first_ref, changed.version_ref());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn authored_agent_package_rejects_manifest_source_capability_drift() {
        let manifest = json!({
            "schema": AGENT_PACKAGE_SCHEMA,
            "source": "method.whip",
            "workflow": "Method",
            "agent": "assistant",
            "system_prompt": "persona.md",
            "capabilities": ["workspace.read"],
            "agent_abilities": ["workspace.read"],
            "max_steps": 8,
        });
        let source = r#"
workflow Method {
  agent assistant {
    provider owned
    profile "repo-writer"
    capacity 1
    capabilities ["workspace.read", "workspace.write"]
  }
}
"#;
        let error = AuthoredAgentPackage::from_documents(manifest.to_string(), source, "persona")
            .expect_err("registry drift must fail");
        assert!(error.contains("capabilities do not match"));
    }

    #[test]
    fn authored_agent_package_can_offer_no_tools() {
        let package = AuthoredAgentPackage::from_documents(
            format!(
                r#"{{
  "schema":"{AGENT_PACKAGE_SCHEMA}",
  "source":"method.whip",
  "workflow":"Method",
  "agent":"assistant",
  "system_prompt":"persona.md",
  "capabilities":[],
  "agent_abilities":[],
  "max_steps":4
}}"#
            ),
            r#"
workflow Method {
  agent assistant {
    provider owned
    profile "plain"
    capacity 1
    capabilities []
  }
  rule converse when started => { tell assistant "Answer without tools." }
}
"#,
            "Be helpful.",
        )
        .expect("tool-free package");
        let resolved = package
            .resolve(package.version_ref())
            .expect("resolve tool-free package");
        assert!(resolved.tools.is_empty());
    }

    #[test]
    fn failed_turn_reason_is_recoverable_from_the_exact_runtime_run() {
        struct Refused;
        impl HostDriver for Refused {
            fn fulfill(&self, _: &IoRequest) -> IoResult {
                IoResult::Http(Ok(HttpResponse {
                    status: 400,
                    body: json!({"error":{"message":"invalid continuation"}}),
                }))
            }
        }
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.into(),
            request_id: "open-first-chat".into(),
            package_version_ref: "package:v1".into(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).unwrap();
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let execution = runtime
            .run_turn_with_driver(
                &command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &Refused,
            )
            .unwrap();
        assert_eq!(execution.receipt.unwrap().status, TurnStatus::Failed);
        assert!(runtime
            .turn_failure_summary(&command)
            .unwrap()
            .unwrap()
            .contains("invalid continuation"));
        assert!(runtime
            .turn_failure_summary(&turn(&instance.instance_ref, &open.policy, 2))
            .unwrap()
            .is_none());
        drop(runtime);
        let reopened = GovernedHostRuntime::open(&path, 7, &signed_policy()).unwrap();
        assert!(reopened
            .turn_failure_summary(&command)
            .unwrap()
            .unwrap()
            .contains("invalid continuation"));
    }

    // WS-590: a streamed model request can be refused with ordinary JSON.
    // The response status and actual reason must survive the native driver.
    #[test]
    fn native_stream_request_preserves_json_provider_refusal() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 4096];
            let start = loop {
                let count = socket.read(&mut chunk).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&chunk[..count]);
                if let Some(start) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break start + 4;
                }
            };
            let length = String::from_utf8_lossy(&request[..start])
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            while request.len() < start + length {
                let count = socket.read(&mut chunk).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&chunk[..count]);
            }
            let body = r#"{"error":{"message":"tool result has no matching call"}}"#;
            write!(socket, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let request = IoRequest::Http(HttpRequest {
            model_provenance: None,
            url: format!("http://{address}/v1/responses"),
            headers: vec![("accept".into(), "text/event-stream".into())],
            body: json!({"input": "a continuation after a refused tool"}),
        });
        let IoResult::Http(result) =
            NativeHttpDriver::new(Duration::from_secs(5)).fulfill(&request);
        let response = result.unwrap();
        assert_eq!(response.status, 400);
        assert_eq!(
            response.body["error"]["message"],
            "tool result has no matching call"
        );
        server.join().unwrap();
    }

    #[test]
    fn native_stream_assembly_uses_the_request_wire() {
        let chat = "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"}]}\n\n";
        let response = assemble_native_sse("https://example.test/v1/chat/completions", chat);
        assert_eq!(response["choices"][0]["message"]["content"], "hello");
        assert_eq!(
            sse_output_text_delta(chat.lines().next().unwrap()),
            Some("hello".to_owned())
        );

        let messages = "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n";
        let response = assemble_native_sse("https://example.test/v1/messages", messages);
        assert_eq!(response["content"][0]["text"], "hi");
        assert_eq!(
            sse_output_text_delta(messages.lines().next().unwrap()),
            Some("hi".to_owned())
        );
    }

    /// The delta sink observes the SSE stream as it arrives; it never
    /// interprets it. Served over a real socket so the read path under test
    /// is the one `run_turn` uses: sink order equals stream order, and the
    /// assembled body is identical to an unobserved read of the same bytes.
    #[test]
    fn native_driver_projects_each_answer_delta_and_assembles_identically() {
        use std::io::{Read, Write};
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Gauge\"}\n\n",
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Wright is live.\"}\n\n",
            "data: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"hidden\"}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":{\"input_tokens\":3}}}\n\n",
            "data: [DONE]\n\n",
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("loopback addr");
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            // Read until the blank line; the body length rides the headers.
            let body_start = loop {
                let n = socket.read(&mut chunk).expect("read request");
                if n == 0 {
                    break request.len();
                }
                request.extend_from_slice(&chunk[..n]);
                if let Some(pos) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            // Drain the body too. ureq writes headers and body in separate
            // syscalls, so stopping at the blank line can leave the body
            // unread — and closing a socket with unread inbound data sends
            // RST rather than FIN, which may discard the queued response
            // tail (a truncated stream) or reset the client mid-headers.
            let content_length: usize = String::from_utf8_lossy(&request[..body_start])
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap_or(0))
                })
                .unwrap_or(0);
            while request.len() < body_start + content_length {
                let n = socket.read(&mut chunk).expect("read body");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
                raw.len()
            )
            .expect("write head");
            // Two flushes so the client observably reads before the stream ends.
            let (first, rest) = raw.split_at(raw.len() / 2);
            socket
                .write_all(first.as_bytes())
                .expect("write first half");
            socket.flush().expect("flush first half");
            socket.write_all(rest.as_bytes()).expect("write rest");
        });
        let seen: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let sink = |delta: &str| seen.borrow_mut().push(delta.to_owned());
        let observed_body = RefCell::new(Vec::new());
        let observe = |body: &Value,
                       _provenance: Option<
            &whipplescript_kernel::sansio::ModelRequestProvenance,
        >| {
            observed_body.borrow_mut().push(body.clone());
        };
        let driver = NativeHttpDriver::new(Duration::from_secs(10))
            .with_delta_sink(&sink)
            .with_request_observer(&observe);
        let request = IoRequest::Http(HttpRequest {
            model_provenance: None,
            url: format!("http://{addr}/v1/responses"),
            headers: vec![("accept".to_owned(), "text/event-stream".to_owned())],
            body: json!({"input": "private model input"}),
        });
        let IoResult::Http(result) = driver.fulfill(&request);
        server.join().expect("server thread");
        let response = result.expect("http response");
        assert_eq!(response.status, 200);
        assert_eq!(
            seen.borrow().as_slice(),
            ["Gauge", "Wright is live."],
            "answer deltas project in stream order; reasoning deltas never do"
        );
        assert_eq!(response.body, assemble_responses_sse(raw));
        assert_eq!(response.body["output_text"], "GaugeWright is live.");
        assert_eq!(
            observed_body.borrow().as_slice(),
            &[json!({"input": "private model input"})]
        );
    }

    /// A cancellation observed mid-stream releases the read at a complete-line
    /// boundary: the transport returns promptly with the lines that fully
    /// arrived — assembled exactly as a naturally ended body — instead of
    /// waiting out the rest of the provider's stream.
    #[test]
    fn native_driver_releases_the_stream_on_an_observed_cancellation() {
        use std::io::{Read, Write};
        let first = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial \"}\n";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("loopback addr");
        // Detached on purpose: the server holds the stream open far longer than
        // the assertion tolerates, so a driver that ignores the probe fails on
        // elapsed time rather than passing by luck. Its writes after the client
        // hangs up are allowed to fail.
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut chunk).expect("read request");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..n]);
            }
            let _ = write!(
                socket,
                "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ncontent-length: {}\r\n\r\n",
                first.len() + 4096
            );
            let _ = socket.write_all(first.as_bytes());
            let _ = socket.flush();
            std::thread::sleep(Duration::from_secs(30));
        });
        let cancelled = std::cell::Cell::new(false);
        // The request "lands" the moment the first delta is observed — the
        // same mid-stream instant an embedding host's Stop would occupy.
        let sink = |_: &str| cancelled.set(true);
        let probe = || cancelled.get();
        let driver = NativeHttpDriver::new(Duration::from_secs(60))
            .with_delta_sink(&sink)
            .with_cancel_probe(&probe);
        let request = IoRequest::Http(HttpRequest {
            model_provenance: None,
            url: format!("http://{addr}/v1/responses"),
            headers: vec![("accept".to_owned(), "text/event-stream".to_owned())],
            body: json!({}),
        });
        let started = std::time::Instant::now();
        let IoResult::Http(result) = driver.fulfill(&request);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the release must not wait for the provider: {:?}",
            started.elapsed()
        );
        let response = result.expect("http response");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, assemble_responses_sse(first));
        assert_eq!(response.body["output_text"], "partial ");
    }

    /// The mid-stream probe reads the same durable surface the handle writes,
    /// throttles its store reads, and latches on first observation — the
    /// release decision and the machine's released-round settlement must agree
    /// about one stream. Asserted from inside a turn's provider round, which
    /// is the only moment the probe exists for (a cancellation request needs a
    /// committed effect to name).
    struct ProbeAssertingDriver<'a> {
        handle: HostCancellationHandle,
        probe: &'a StreamCancelProbe,
        /// The probe's now, held by the test: the window is left and re-entered
        /// by advancing this, never by spending real time. A machine under load
        /// can otherwise leave the window between two adjacent statements.
        clock: std::rc::Rc<Cell<Duration>>,
        checked: Cell<bool>,
    }

    impl HostDriver for ProbeAssertingDriver<'_> {
        fn fulfill(&self, _request: &IoRequest) -> IoResult {
            assert!(!self.probe.observed(), "no request yet");
            assert!(!self.probe.released());
            self.handle.request().expect("cancel request records");
            assert!(
                !self.probe.observed(),
                "a read inside the throttle answers from the last read"
            );
            // Exactly the window: the throttle admits the next read at the
            // interval, not one tick after it.
            self.clock
                .set(self.clock.get() + StreamCancelProbe::READ_INTERVAL);
            assert!(self.probe.observed(), "the durable request is observed");
            assert!(self.probe.released(), "the observation latches");
            assert!(
                self.probe.observed(),
                "latched answers need no further reads"
            );
            self.checked.set(true);
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: json!({
                    "output": [{
                        "type": "function_call",
                        "call_id": "call-before-cancel",
                        "name": "read",
                        "arguments": "{\"path\":\"README.md\"}"
                    }],
                    "usage": { "input_tokens": 10, "output_tokens": 2 }
                }),
            }))
        }
    }

    #[test]
    fn cli_home_open_recovers_exact_target_operation_before_instance_use() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-chat-open".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let mut journal = TestHomeJournal {
            fail_at: Some("register"),
            ..TestHomeJournal::default()
        };
        assert!(runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .is_err());
        assert!(runtime
            .kernel
            .store()
            .program_import_operation_roster()
            .unwrap()
            .operations
            .is_empty());
        journal.fail_at = Some("complete");
        assert!(runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .is_err());
        assert!(runtime.kernel.store().list_instances().unwrap().is_empty());
        let operation = runtime
            .kernel
            .store()
            .program_import_operation(HOME_OPEN_OPERATION)
            .unwrap()
            .expect("Home operation committed before completion");
        assert!(operation.witness_digest.is_some());

        journal.fail_at = Some("retained");
        let refused = runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .expect_err("fresh instance cannot return before its Home use check");
        assert!(format!("{refused:?}").contains("Home retained use refused"));
        assert_eq!(runtime.kernel.store().list_instances().unwrap().len(), 1);
        assert_eq!(journal.completed, [HOME_OPEN_OPERATION]);
        assert_eq!(journal.retained.len(), 1);
        journal.fail_at = None;
        let opened = runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .expect("exact retry recovers the withheld instance");
        assert_eq!(journal.completed, [HOME_OPEN_OPERATION]);
        assert_eq!(runtime.kernel.store().list_instances().unwrap().len(), 1);
        assert_eq!(journal.retained.len(), 2);
        let replayed = runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .expect("completed Home open can be reused");
        assert_eq!(replayed.instance_ref, opened.instance_ref);
        assert_eq!(journal.retained.len(), 3);
        assert_eq!(
            runtime
                .kernel
                .store()
                .program_import_operation_roster()
                .unwrap()
                .operations
                .len(),
            1,
        );
        journal.fail_at = Some("retained");
        assert!(runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .is_err());
        drop(runtime);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cli_home_completion_refuses_a_changed_target_store_incarnation() {
        let store = SqliteStore::open_in_memory().expect("store");
        let actual = require_home_store_incarnation(&store).expect("incarnation");
        require_same_home_store_incarnation(&store, &actual).expect("same target");
        let foreign = SqliteStore::open_in_memory().expect("foreign store");
        let foreign_id = require_home_store_incarnation(&foreign).expect("foreign incarnation");
        assert_ne!(actual, foreign_id);
        assert!(format!(
            "{:?}",
            require_same_home_store_incarnation(&store, &foreign_id)
        )
        .contains("incarnation changed"));
    }

    #[test]
    fn cli_home_open_refuses_a_target_without_store_incarnation_before_registration() {
        let path = temp_store();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &signed_policy()).expect("runtime");
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "DROP TRIGGER runtime_store_incarnation_no_delete; \
                 DELETE FROM runtime_store_incarnation WHERE id = 1;",
            )
            .unwrap();
        let command = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-chat-open".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let mut journal = TestHomeJournal::default();
        let refusal = runtime.open_instance_with_home_journal(&command, &Packages, &mut journal);
        assert!(format!("{refusal:?}").contains("Home target store has no incarnation"));
        assert!(journal.registered.is_empty());
        assert!(runtime
            .kernel
            .store()
            .program_import_operation_roster()
            .unwrap()
            .operations
            .is_empty());
        drop(runtime);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cli_home_replay_keeps_pending_reattest_unusable_until_recovery() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-chat-open".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let mut journal = TestHomeJournal::default();
        let first = runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .expect("first Home open");
        drop(runtime);
        {
            let connection = rusqlite::Connection::open(&path).expect("raw store");
            connection
                .execute(
                    "UPDATE program_versions SET ir_hash = 'ir-of-an-older-toolchain'",
                    [],
                )
                .expect("age recorded compiler IR");
        }
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("reopen");
        journal.fail_at = Some("complete");
        let refused = runtime.open_instance_with_home_journal(&open, &Packages, &mut journal);
        assert!(format!("{refused:?}").contains("Home complete refused"));
        let operation = runtime
            .kernel
            .store()
            .program_import_operation(HOME_REATTEST_OPERATION)
            .unwrap()
            .expect("exact re-attestation target operation");
        let correlated: i64 = rusqlite::Connection::open(&path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM events WHERE instance_id = ?1 \
                 AND event_type = 'instance.program.reattested' AND correlation_id = ?2",
                rusqlite::params![&first.instance_ref, HOME_REATTEST_OPERATION],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(correlated, 1);
        journal.fail_at = None;
        let pending = runtime.open_instance_with_home_journal(&open, &Packages, &mut journal);
        assert!(format!("{pending:?}").contains("pending Home re-attestation"));
        journal
            .complete_for_use(&OpenInstanceOperationEvidence {
                target_store_incarnation: &runtime
                    .kernel
                    .store()
                    .store_incarnation()
                    .unwrap()
                    .expect("runtime identity"),
                request_id: &open.request_id,
                operation_id: HOME_REATTEST_OPERATION,
                instance_ref: Some(&first.instance_ref),
                version_id: &operation.version_id,
                witness_digest: operation.witness_digest.as_deref().unwrap(),
            })
            .expect("Home recovers exact target operation");
        let replayed = runtime
            .open_instance_with_home_journal(&open, &Packages, &mut journal)
            .expect("recovered re-attestation can be reused");
        assert_eq!(replayed.instance_ref, first.instance_ref);
        assert_eq!(
            runtime
                .kernel
                .store()
                .program_import_operation_roster()
                .unwrap()
                .operations
                .len(),
            2,
        );
        drop(runtime);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn cli_home_replay_refuses_legacy_origin_before_reattest_write() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "home-chat-open".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        runtime
            .open_instance(&open, &Packages)
            .expect("legacy open");
        drop(runtime);
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE program_versions SET ir_hash = 'ir-of-an-older-toolchain'",
                [],
            )
            .unwrap();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("reopen");
        let before = runtime
            .kernel
            .store()
            .program_import_operation_roster()
            .unwrap();
        let mut journal = TestHomeJournal::default();
        let refusal = runtime.open_instance_with_home_journal(&open, &Packages, &mut journal);
        assert!(format!("{refusal:?}").contains("pending Home open"));
        assert!(journal.registered.is_empty());
        assert_eq!(
            runtime
                .kernel
                .store()
                .program_import_operation_roster()
                .unwrap(),
            before,
        );
        drop(runtime);
        let _ = fs::remove_file(&path);
    }

    /// A runtime upgrade changes the compiled identity of the same authored
    /// package. A replayed open re-attests the IR under the current compiler
    /// and the instance keeps running turns — it is not stranded
    /// (spec/agent-harness.md "Program identity across toolchains").
    #[test]
    fn replayed_open_reattests_an_older_toolchains_ir() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-reattest-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let first = runtime.open_instance(&open, &Packages).expect("instance");
        drop(runtime);
        // Stand in for an older toolchain: the recorded IR differs from what
        // the current compiler derives for the identical authored package.
        {
            let connection = rusqlite::Connection::open(&path).expect("raw store");
            connection
                .execute(
                    "UPDATE program_versions SET ir_hash = 'ir-of-an-older-toolchain'",
                    [],
                )
                .expect("age the recorded ir");
        }
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("reopen");
        let replayed = runtime
            .open_instance(&open, &Packages)
            .expect("the replayed open re-attests instead of refusing");
        assert_eq!(replayed.instance_ref, first.instance_ref);
        let roster = runtime
            .kernel
            .store()
            .program_import_operation_roster()
            .expect("import operations after replay");
        assert_eq!(roster.operations.len(), 2);
        let checked = roster.operations.last().expect("re-attestation operation");
        assert_eq!(
            checked.kind,
            whipplescript_store::program_imports::ProgramImportOperationKind::Checked
        );
        let witness = runtime
            .kernel
            .store()
            .program_import_witness(
                &checked.version_id,
                checked
                    .witness_digest
                    .as_deref()
                    .expect("checked witness digest"),
            )
            .expect("witness lookup")
            .expect("retained witness");
        let package = Packages.resolve_package("package:v1").expect("package");
        assert_eq!(
            witness.program_source_digest,
            package
                .checked_import_source_digest()
                .expect("checked source digest")
        );
        assert_eq!(
            witness.version_source_digest.as_deref(),
            Some(package.source_hash.as_str())
        );
        assert_eq!(witness.lock_digest, NO_LOCK_DIGEST);
        assert_eq!(
            witness.compiler_artifact_digest,
            native_compiler_artifact_digest().expect("compiler digest")
        );
        assert!(witness.examined.is_empty());
        assert!(witness
            .constructs
            .as_ref()
            .is_some_and(|capture| capture.examined.is_empty()));
        assert_eq!(
            witness
                .declarations
                .expect("re-attestation captures declarations")
                .edges
                .iter()
                .map(|edge| edge.registration_id.as_str())
                .collect::<Vec<_>>(),
            ["files.file_store"]
        );
        // The re-attestation is an auditable event, and the instance runs.
        {
            let connection = rusqlite::Connection::open(&path).expect("raw store");
            let reattested: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE event_type = 'instance.program.reattested'",
                    [],
                    |row| row.get(0),
                )
                .expect("count events");
            assert_eq!(reattested, 1, "one re-attestation event");
        }
        let driver = ScriptedDriver::new(vec![json!({
            "output_text": "still here",
            "usage": { "input_tokens": 4, "output_tokens": 2 }
        })]);
        let execution = runtime
            .run_turn_with_driver(
                &turn(&replayed.instance_ref, &open.policy, 1),
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &driver,
            )
            .expect("a turn runs on the re-attested instance");
        let receipt = execution.receipt.as_ref().expect("terminal receipt");
        assert_eq!(receipt.status, TurnStatus::Completed);
        drop(runtime);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    /// Different authored content under a replayed request stays refused — the
    /// re-attestation path never widens the guard for a changed source.
    #[test]
    fn replayed_open_still_refuses_changed_authored_content() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-changed-source-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        runtime.open_instance(&open, &Packages).expect("instance");
        drop(runtime);
        {
            let connection = rusqlite::Connection::open(&path).expect("raw store");
            connection
                .execute(
                    "UPDATE program_versions SET source_hash = 'someone-elses-program'",
                    [],
                )
                .expect("change the recorded authored identity");
        }
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("reopen");
        let refused = runtime.open_instance(&open, &Packages);
        assert!(
            matches!(
                refused,
                Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "replayed package content"
                )))
            ),
            "changed authored content is refused: {refused:?}"
        );
        drop(runtime);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn stream_cancel_probe_latches_on_the_durable_request() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 8, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-probe-chat".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).expect("instance");
        let command = turn(&instance.instance_ref, &open.policy, 1);
        let clock = std::rc::Rc::new(Cell::new(Duration::ZERO));
        let probe = StreamCancelProbe::on_clock(
            path.clone(),
            command.instance_ref.clone(),
            command.command_id.clone(),
            ProbeClock::Held(clock.clone()),
            runtime.protection.clone(),
        );
        let driver = ProbeAssertingDriver {
            handle: runtime.cancellation_handle(&command.instance_ref, &command.command_id),
            probe: &probe,
            clock,
            checked: Cell::new(false),
        };
        let execution = runtime
            .run_turn_with_driver(
                &command,
                &Packages,
                &Secrets {
                    calls: Cell::new(0),
                },
                &Resources {
                    calls: Cell::new(0),
                },
                &driver,
            )
            .expect("turn settles");
        assert!(driver.checked.get(), "the probe assertions ran mid-round");
        let receipt = execution.receipt.as_ref().expect("terminal receipt");
        assert_eq!(receipt.status, TurnStatus::Cancelled);
        drop(runtime);
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    }

    /// A provider may speak the user-facing reply on the same message as its
    /// tool calls and close the turn with an empty final message. The turn
    /// projection must keep that text rather than projecting a completed turn
    /// as a blank reply — while a closing text-only answer still wins.
    #[test]
    fn turn_projection_keeps_answer_text_spoken_with_tool_calls() {
        let path = temp_store();
        let policy_text = signed_policy();
        let mut runtime = GovernedHostRuntime::open(&path, 7, &policy_text).expect("runtime");
        let open = OpenInstanceCommand {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: "open-preamble".to_owned(),
            package_version_ref: "package:v1".to_owned(),
            policy: runtime.policy_ref().clone(),
        };
        let instance = runtime.open_instance(&open, &Packages).expect("instance");
        let secrets = Secrets {
            calls: Cell::new(0),
        };
        let resources = Resources {
            calls: Cell::new(0),
        };
        let driver = ScriptedDriver::new(vec![
            json!({
                "output_text": "Reading the register now.",
                "output": [{
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "read",
                    "arguments": "{\"path\":\"README.md\"}"
                }],
                "usage": { "input_tokens": 10, "output_tokens": 4 }
            }),
            json!({
                "output_text": "",
                "usage": { "input_tokens": 14, "output_tokens": 0 }
            }),
        ]);
        let execution = runtime
            .run_turn_with_driver(
                &turn(&instance.instance_ref, &open.policy, 1),
                &Packages,
                &secrets,
                &resources,
                &driver,
            )
            .expect("turn");
        let receipt = execution.receipt.as_ref().expect("terminal receipt");
        assert_eq!(receipt.status, TurnStatus::Completed);
        let output = execution.output.expect("labeled output projection");
        assert_eq!(output.assistant_text, "Reading the register now.");
        assert_eq!(output.tool_calls.len(), 1);
        // The typed usage projection: the meter sums both rounds (10 + 14),
        // the gauge reads only the final round's prompt — a tool-loop turn
        // must never report its summed input as the window reading.
        assert_eq!(
            execution.usage,
            Some(TurnUsageObservation {
                usage_ref: receipt.usage_ref.clone(),
                input_tokens: 24,
                output_tokens: 4,
                last_input_tokens: 14,
            })
        );
    }

    #[test]
    fn codex_sse_assembly_preserves_calls_and_text_deltas() {
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"done\"}\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"function_call\",\"call_id\":\"c1\",\"name\":\"read\",\"arguments\":\"{}\"}],\"usage\":{\"input_tokens\":3}}}\n",
            "data: [DONE]\n",
        );
        let response = assemble_responses_sse(raw);
        assert_eq!(response["output_text"], "done");
        assert_eq!(response["output"][0]["call_id"], "c1");
        assert_eq!(response["usage"]["input_tokens"], 3);
    }

    /// The live codex backend (verified 2026-07-10) sends `response.completed`
    /// with an EMPTY `output[]`; the reasoning and function-call items arrive
    /// only as `response.output_item.done` events. A tool-calling turn must
    /// survive assembly from those events, or the model's work is silently
    /// dropped (the empty-reply bug: 113 output tokens, no text, no calls).
    #[test]
    fn codex_sse_assembly_recovers_items_from_output_item_done_events() {
        let raw = concat!(
            "data: {\"type\":\"response.output_item.added\",\"item\":{\"type\":\"reasoning\"}}\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"reasoning\",\"summary\":[]}}\n",
            "data: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{\\\"path\\\"\"}\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"status\":\"completed\",\"arguments\":\"{\\\"path\\\":\\\"poem.md\\\",\\\"content\\\":\\\"ode\\\"}\",\"call_id\":\"call_1\",\"name\":\"write\"}}\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":{\"input_tokens\":503,\"output_tokens\":113}}}\n",
            "data: [DONE]\n",
        );
        let response = assemble_responses_sse(raw);
        let output = response["output"].as_array().expect("collected items");
        assert_eq!(output.len(), 2);
        assert_eq!(output[1]["type"], "function_call");
        assert_eq!(output[1]["name"], "write");
        assert_eq!(output[1]["call_id"], "call_1");
        assert_eq!(response["usage"]["output_tokens"], 113);
        // A completed payload that DOES carry output wins over the collected
        // items (no duplication).
        let raw_full = concat!(
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"dup\",\"name\":\"read\",\"arguments\":\"{}\"}}\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[{\"type\":\"function_call\",\"call_id\":\"real\",\"name\":\"read\",\"arguments\":\"{}\"}]}}\n",
        );
        let full = assemble_responses_sse(raw_full);
        let output = full["output"].as_array().expect("authoritative output");
        assert_eq!(output.len(), 1);
        assert_eq!(output[0]["call_id"], "real");
    }
}
