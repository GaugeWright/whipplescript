//! Persistent native host facade for governed WhippleScript turns.
//!
//! The facade owns policy admission, instance identity, the brokered model/tool
//! loop, transcript persistence, and evidence projection. Embedding products
//! provide only opaque-reference resolvers. Secrets and resource bodies are
//! resolved after admission and never enter the host command or receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_kernel::coerce_native::CoerceProvider;
pub use whipplescript_kernel::harness_loop::ToolCall;
use whipplescript_kernel::harness_loop::{
    BrokeredTurnInput, ChatMessage, ImageBlock, NoopCompactor, ToolExecutor, ToolOutcome, ToolSpec,
    ToolStatus,
};
use whipplescript_kernel::harness_model::MessagesApiClient;
use whipplescript_kernel::sansio::{HostDriver, HttpResponse, IoRequest, IoResult, TransportError};
use whipplescript_kernel::whip_shell::{ShellFile, ShellRequest, WhipShell};
use whipplescript_kernel::{
    idempotency_key, AgentThreadSeed, BrokeredTurnContext, ProgramVersionInput, RuntimeKernel,
};
use whipplescript_store::{
    EffectCancellationRequest, EvidenceRecord, NewEffect, NewEvent, RuleCommit, SqliteStore,
    StoreError,
};

use crate::host_protocol::{
    EventPosition, ForkInstanceCommand, ForkedInstance, LabeledRuntimeEvent, OpenInstanceCommand,
    OpenedInstance, PolicyEpochRef, ProtocolError, ProviderBindingRef, ResourceRef,
    RuntimeEvidencePointer, StartTurnCommand, TurnReceipt, TurnStatus, HOST_PROTOCOL,
};
use crate::ifc::VerifiedEnvelope;
pub use whipplescript_kernel::host_package::{
    AuthoredAgentPackage, PackageResolver, ResolvedPackage, AGENT_PACKAGE_MANIFEST,
    AGENT_PACKAGE_SCHEMA,
};

// Retained temporarily in source history while downstream code moves to the
// placement-neutral kernel package implementation above. This block is never
// compiled; keeping it isolated makes the extraction reviewable without
// changing the native facade and DO vertical in separate semantic steps.
#[cfg(any())]
#[rustfmt::skip]
mod retired_native_package_implementation {
use super::*;
/// Canonical manifest name for an authored agent package consumed by the
/// persistent host facade.
pub const AGENT_PACKAGE_MANIFEST: &str = "package.json";
pub const AGENT_PACKAGE_SCHEMA: &str = "whipplescript.agent_package.v0";

/// The authored, immutable input to an owned agent turn.
///
/// The package owns persona, executable WhippleScript source, and the exact
/// capability registry from which the model-facing tool surface is derived.
/// Embedding products may choose and pin a package version, but cannot bolt on
/// a prompt or tool after package resolution.
#[derive(Clone, Debug)]
pub struct AuthoredAgentPackage {
    version_ref: String,
    source: String,
    workflow: String,
    agent: String,
    system_prompt: String,
    capabilities: Vec<String>,
    max_steps: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredAgentPackageManifest {
    schema: String,
    source: String,
    workflow: String,
    agent: String,
    system_prompt: String,
    capabilities: Vec<String>,
    max_steps: usize,
}

impl AuthoredAgentPackage {
    /// Parse an authored package from already-resolved document bytes. This is
    /// the embedding seam for immutable built-in packages and content-addressed
    /// stores; [`Self::load`] is the filesystem convenience wrapper.
    pub fn from_documents(
        manifest_text: impl Into<String>,
        source: impl Into<String>,
        system_prompt: impl Into<String>,
    ) -> Result<Self, String> {
        let manifest_text = manifest_text.into();
        let manifest: AuthoredAgentPackageManifest = serde_json::from_str(&manifest_text)
            .map_err(|error| format!("invalid agent package manifest: {error}"))?;
        if manifest.schema != AGENT_PACKAGE_SCHEMA {
            return Err(format!(
                "unsupported agent package schema `{}`",
                manifest.schema
            ));
        }
        Self::from_parts(manifest_text, manifest, source.into(), system_prompt.into())
    }

    /// Load and validate the canonical three-file package rooted at `root`.
    /// Referenced files must be direct, non-symlink children of the package
    /// directory. Their exact bytes, plus the manifest, determine the immutable
    /// package version reference.
    pub fn load(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root
            .as_ref()
            .canonicalize()
            .map_err(|error| format!("cannot open agent package: {error}"))?;
        if !root.is_dir() {
            return Err("agent package root is not a directory".to_owned());
        }
        let manifest_text = read_package_child(&root, AGENT_PACKAGE_MANIFEST)?;
        let manifest: AuthoredAgentPackageManifest = serde_json::from_str(&manifest_text)
            .map_err(|error| format!("invalid agent package manifest: {error}"))?;
        let source = read_package_child(&root, &manifest.source)?;
        let system_prompt = read_package_child(&root, &manifest.system_prompt)?;
        Self::from_documents(manifest_text, source, system_prompt)
    }

    fn from_parts(
        manifest_text: String,
        manifest: AuthoredAgentPackageManifest,
        source: String,
        system_prompt: String,
    ) -> Result<Self, String> {
        if manifest.workflow.trim().is_empty()
            || manifest.agent.trim().is_empty()
            || system_prompt.trim().is_empty()
            || manifest.max_steps == 0
        {
            return Err(
                "agent package requires workflow, agent, persona, and positive max_steps"
                    .to_owned(),
            );
        }
        let mut capabilities = manifest.capabilities;
        capabilities.sort();
        capabilities.dedup();
        for capability in &capabilities {
            if !matches!(
                capability.as_str(),
                "workspace.read" | "workspace.write" | "command.run" | "human.ask"
            ) {
                return Err(format!(
                    "agent package declares unsupported capability `{capability}`"
                ));
            }
        }
        if capabilities.iter().any(|item| item == "workspace.write")
            && !capabilities.iter().any(|item| item == "workspace.read")
        {
            return Err("workspace.write requires workspace.read".to_owned());
        }

        let compiled = whipplescript_parser::compile_program_with_root(
            &source,
            Some(manifest.workflow.as_str()),
        );
        let program = compiled.ir.ok_or_else(|| {
            compiled
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        })?;
        let declared_agent = program
            .agents
            .iter()
            .find(|agent| agent.name == manifest.agent)
            .ok_or_else(|| format!("agent package has no agent `{}`", manifest.agent))?;
        let mut source_capabilities = declared_agent.capabilities.clone();
        source_capabilities.sort();
        source_capabilities.dedup();
        if source_capabilities != capabilities {
            return Err(format!(
                "agent `{}` capabilities do not match the package capability registry",
                manifest.agent
            ));
        }

        let identity = json!({
            "manifest": &manifest_text,
            "source": &source,
            "system_prompt": &system_prompt,
        });
        let version_ref = format!(
            "whip:agent-package:{}",
            sha256_hex(identity.to_string().as_bytes())
        );
        Ok(Self {
            version_ref,
            source,
            workflow: manifest.workflow,
            agent: manifest.agent,
            system_prompt,
            capabilities,
            max_steps: manifest.max_steps,
        })
    }

    pub fn version_ref(&self) -> &str {
        &self.version_ref
    }

    pub fn capabilities(&self) -> &[String] {
        &self.capabilities
    }

    /// Resolve this exact authored package. The caller must present the pinned
    /// reference; a mutable directory whose bytes changed therefore cannot
    /// impersonate an already-open package version.
    pub fn resolve(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
        if version_ref != self.version_ref {
            return Err("agent package bytes do not match the pinned version ref".to_owned());
        }
        let writable = self
            .capabilities
            .iter()
            .any(|capability| capability == "workspace.write");
        let command = self
            .capabilities
            .iter()
            .any(|capability| capability == "command.run");
        let human = self
            .capabilities
            .iter()
            .any(|capability| capability == "human.ask");
        ResolvedPackage::compile_with_capabilities(
            self.version_ref.clone(),
            &self.source,
            Some(&self.workflow),
            self.agent.clone(),
            self.system_prompt.clone(),
            native_workspace_tool_specs_from_registry(
                self.capabilities
                    .iter()
                    .any(|capability| capability == "workspace.read"),
                writable,
                command,
                human,
            ),
            self.max_steps,
            self.capabilities.clone(),
        )
    }
}

impl PackageResolver for AuthoredAgentPackage {
    fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String> {
        self.resolve(version_ref)
    }
}

fn read_package_child(root: &Path, relative: &str) -> Result<String, String> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.components().count() != 1
        || !matches!(relative.components().next(), Some(Component::Normal(_)))
    {
        return Err("agent package file references must name direct children".to_owned());
    }
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        format!(
            "cannot open agent package file `{}`: {error}",
            relative.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "agent package file `{}` must be a regular non-symlink file",
            relative.display()
        ));
    }
    fs::read_to_string(path).map_err(|error| {
        format!(
            "cannot read agent package file `{}`: {error}",
            relative.display()
        )
    })
}

/// A package version resolved from WhippleScript's package store.
///
/// Tool schemas come from the pinned package. The embedding host cannot add a
/// tool at turn time; it only implements the resource operations behind tools
/// the package already declares.
#[derive(Clone, Debug)]
pub struct ResolvedPackage {
    version_ref: String,
    source_hash: String,
    ir_hash: String,
    agent: String,
    system_prompt: String,
    tools: Vec<ToolSpec>,
    capabilities: Vec<String>,
    max_steps: usize,
    program: IrProgram,
}

impl ResolvedPackage {
    /// Compile the exact pinned WhippleScript source the host resolved. Package
    /// identity is derived from those bytes; the resulting IR is retained so
    /// runtime admission can execute WhippleScript's IFC checker under the
    /// verified governance envelope.
    #[allow(clippy::too_many_arguments)]
    pub fn compile(
        version_ref: impl Into<String>,
        source: &str,
        root: Option<&str>,
        agent: impl Into<String>,
        system_prompt: impl Into<String>,
        tools: Vec<ToolSpec>,
        max_steps: usize,
    ) -> Result<Self, String> {
        Self::compile_with_capabilities(
            version_ref,
            source,
            root,
            agent,
            system_prompt,
            tools,
            max_steps,
            Vec::new(),
        )
    }

    /// Compile a package while retaining its signed capability registry for
    /// policy-epoch admission. This is the authored-package path; the legacy
    /// `compile` constructor remains for compatibility fixtures with no registry.
    #[allow(clippy::too_many_arguments)]
    pub fn compile_with_capabilities(
        version_ref: impl Into<String>,
        source: &str,
        root: Option<&str>,
        agent: impl Into<String>,
        system_prompt: impl Into<String>,
        tools: Vec<ToolSpec>,
        max_steps: usize,
        mut capabilities: Vec<String>,
    ) -> Result<Self, String> {
        let compiled = whipplescript_parser::compile_program_with_root(source, root);
        let program = compiled.ir.ok_or_else(|| {
            compiled
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        })?;
        let agent = agent.into();
        let system_prompt = system_prompt.into();
        let tool_identity = tools
            .iter()
            .map(|tool| {
                json!({
                    "name": tool.name,
                    "description": tool.description,
                    "input_schema": tool.input_schema,
                })
            })
            .collect::<Vec<_>>();
        capabilities.sort();
        capabilities.dedup();
        let package_identity = json!({
            "source": source,
            "root": root,
            "agent": &agent,
            "system_prompt": &system_prompt,
            "tools": tool_identity,
            "max_steps": max_steps,
            "capabilities": &capabilities,
        });
        let source_hash = sha256_hex(package_identity.to_string().as_bytes());
        let ir_hash = sha256_hex(
            format!("{}:{}:{}", source_hash, program.workflow, HOST_PROTOCOL).as_bytes(),
        );
        Ok(Self {
            version_ref: version_ref.into(),
            source_hash,
            ir_hash,
            agent,
            system_prompt,
            tools,
            capabilities,
            max_steps,
            program,
        })
    }
}

/// Resolve an immutable WhippleScript package version by opaque reference.
pub trait PackageResolver {
    fn resolve_package(&self, version_ref: &str) -> Result<ResolvedPackage, String>;
}
}

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
        }
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

pub trait ResourceResolver {
    fn resolve_image(&self, image: &ResourceRef) -> Result<ResolvedImage, String>;

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

/// WhippleScript-owned native implementation of the workspace capability used
/// by embedding desktop hosts. GaugeDesk supplies only the root and any
/// read-only subtrees; WhippleScript parses tool arguments, confines paths,
/// rejects symlink traversal, and performs the operation.
pub struct NativeWorkspaceResolver {
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
}

#[derive(Default)]
struct WitnessState {
    writes: Vec<WitnessedWrite>,
    reads: Vec<String>,
    taint: Option<String>,
}

impl NativeWorkspaceResolver {
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
            root,
            read_only: Vec::new(),
            max_output_bytes: 50_000,
            witness: std::sync::Mutex::new(WitnessState::default()),
        })
    }

    pub fn read_only(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Result<Self, String> {
        self.read_only = paths
            .into_iter()
            .map(|path| normalize_relative(&path))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(self)
    }

    fn resolve(&self, path: &str, write: bool) -> Result<PathBuf, String> {
        let relative = normalize_relative(Path::new(path))?;
        if write
            && self
                .read_only
                .iter()
                .any(|protected| relative.starts_with(protected))
        {
            return Err(format!("workspace path `{path}` is read-only"));
        }
        let mut resolved = self.root.clone();
        for component in relative.components() {
            let Component::Normal(segment) = component else {
                return Err(format!("workspace path `{path}` escapes its capability"));
            };
            resolved.push(segment);
            if let Ok(metadata) = fs::symlink_metadata(&resolved) {
                if metadata.file_type().is_symlink() {
                    return Err(format!("workspace path `{path}` traverses a symlink"));
                }
            }
        }
        Ok(resolved)
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

    fn read(&self, arguments: &Value) -> Result<String, String> {
        let path = string_argument(arguments, "path")?;
        self.witness_read(path);
        let resolved = self.resolve(path, false)?;
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
        Ok(self.cap(lines))
    }

    fn write(&self, arguments: &Value) -> Result<String, String> {
        let path = string_argument(arguments, "path")?;
        let content = string_argument(arguments, "content")?;
        let resolved = self.resolve(path, true)?;
        if let Some(parent) = resolved.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create parent for `{path}`: {error}"))?;
            reject_symlinks_between(&self.root, parent, path)?;
        }
        let existed = resolved.exists();
        fs::write(&resolved, content)
            .map_err(|error| format!("cannot write workspace path `{path}`: {error}"))?;
        self.witness_write(path, existed, content.as_bytes());
        Ok(format!("wrote {} bytes to {path}", content.len()))
    }

    fn edit(&self, arguments: &Value) -> Result<String, String> {
        let path = string_argument(arguments, "path")?;
        let resolved = self.resolve(path, true)?;
        let mut text = fs::read_to_string(&resolved)
            .map_err(|error| format!("cannot edit workspace path `{path}`: {error}"))?;
        let edits = arguments
            .get("edits")
            .and_then(Value::as_array)
            .ok_or_else(|| "`edits` must be an array".to_owned())?;
        for edit in edits {
            let old = string_argument(edit, "oldText")?;
            let new = string_argument(edit, "newText")?;
            if old.is_empty() {
                return Err("edit oldText must not be empty".to_owned());
            }
            if text.matches(old).count() != 1 {
                return Err("edit oldText must match exactly once".to_owned());
            }
            text = text.replacen(old, new, 1);
        }
        fs::write(&resolved, &text)
            .map_err(|error| format!("cannot edit workspace path `{path}`: {error}"))?;
        self.witness_write(path, true, text.as_bytes());
        Ok(format!("applied {} edit(s) to {path}", edits.len()))
    }

    fn list(&self, arguments: &Value) -> Result<String, String> {
        let path = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
        self.witness_read(path);
        let resolved = self.resolve(path, false)?;
        let mut names = fs::read_dir(&resolved)
            .map_err(|error| format!("cannot list workspace path `{path}`: {error}"))?
            .filter_map(Result::ok)
            .map(|entry| {
                let mut name = entry.file_name().to_string_lossy().into_owned();
                if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                    name.push('/');
                }
                name
            })
            .collect::<Vec<_>>();
        names.sort();
        Ok(self.cap(names.join("\n")))
    }

    fn find(&self, arguments: &Value) -> Result<String, String> {
        let path = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
        self.witness_read(path);
        let pattern = string_argument(arguments, "pattern")?;
        let resolved = self.resolve(path, false)?;
        let mut matches = Vec::new();
        walk_workspace(&self.root, &resolved, &mut |relative, _| {
            if wildcard_matches(pattern, relative) {
                matches.push(relative.to_owned());
            }
            matches.len() < 5_000
        })?;
        matches.sort();
        Ok(self.cap(matches.join("\n")))
    }

    fn grep(&self, arguments: &Value) -> Result<String, String> {
        let path = arguments.get("path").and_then(Value::as_str).unwrap_or(".");
        self.witness_read(path);
        let pattern = string_argument(arguments, "pattern")?;
        let matcher = regex::Regex::new(pattern).ok();
        let resolved = self.resolve(path, false)?;
        let mut matches = Vec::new();
        walk_workspace(&self.root, &resolved, &mut |relative, absolute| {
            let Ok(text) = fs::read_to_string(absolute) else {
                return true;
            };
            for (line, content) in text.lines().enumerate() {
                let hit = matcher
                    .as_ref()
                    .map(|regex| regex.is_match(content))
                    .unwrap_or_else(|| content.contains(pattern));
                if hit {
                    matches.push(format!("{relative}:{}:{content}", line + 1));
                    if matches.len() >= 5_000 {
                        return false;
                    }
                }
            }
            true
        })?;
        Ok(self.cap(matches.join("\n")))
    }

    fn bash(&self, arguments: &Value) -> Result<String, String> {
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

        let mut before = BTreeMap::new();
        let mut files = Vec::new();
        let mut load_error = None;
        walk_workspace(&self.root, &self.root, &mut |relative, absolute| {
            if files.len() >= 5_000 {
                load_error = Some("bash workspace contains more than 5000 files".to_owned());
                return false;
            }
            match fs::read(absolute) {
                Ok(content) => {
                    let relative = relative.replace('\\', "/");
                    let path = Path::new(&relative);
                    let writable = !self
                        .read_only
                        .iter()
                        .any(|protected| path.starts_with(protected));
                    before.insert(relative.clone(), content.clone());
                    files.push(ShellFile {
                        path: relative,
                        content,
                        writable,
                    });
                    true
                }
                Err(error) => {
                    load_error = Some(format!(
                        "cannot load bash workspace file `{relative}`: {error}"
                    ));
                    false
                }
            }
        })?;
        if let Some(error) = load_error {
            return Err(error);
        }

        let output = WhipShell::default().execute(ShellRequest {
            command: command.to_owned(),
            timeout: requested,
            files,
        })?;
        // Validate every result path and mutation before changing the real
        // workspace. This preserves the same capability and read-only ceilings
        // as the first-class file tools.
        for (path, content) in &output.files {
            let resolved = self.resolve(path, true)?;
            if let Some(parent) = resolved.parent() {
                reject_symlinks_between(&self.root, parent, path)?;
            }
            let _ = content;
        }
        let after_paths = output.files.keys().cloned().collect::<BTreeSet<_>>();
        for removed in before.keys().filter(|path| !after_paths.contains(*path)) {
            let resolved = self.resolve(removed, true)?;
            fs::remove_file(&resolved).map_err(|error| {
                format!("cannot delete bash workspace path `{removed}`: {error}")
            })?;
            self.witness_delete(removed);
        }
        for (path, content) in &output.files {
            if before.get(path) == Some(content) {
                continue;
            }
            let resolved = self.resolve(path, true)?;
            if let Some(parent) = resolved.parent() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("cannot create parent for `{path}`: {error}"))?;
                reject_symlinks_between(&self.root, parent, path)?;
            }
            let existed = before.contains_key(path);
            fs::write(&resolved, content)
                .map_err(|error| format!("cannot write bash workspace path `{path}`: {error}"))?;
            self.witness_write(path, existed, content);
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
    fn resolve_image(&self, image: &ResourceRef) -> Result<ResolvedImage, String> {
        let locator = image.selector.as_deref().unwrap_or(&image.handle);
        let path = self.resolve(locator, false)?;
        let bytes =
            fs::read(&path).map_err(|error| format!("cannot read image `{locator}`: {error}"))?;
        let media_type = match path.extension().and_then(|extension| extension.to_str()) {
            Some("png") => "image/png",
            Some("jpg" | "jpeg") => "image/jpeg",
            Some("gif") => "image/gif",
            Some("webp") => "image/webp",
            _ => return Err("unsupported image media type".to_owned()),
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
        if !admitted_resources
            .iter()
            .any(|resource| resource.kind == "file_store")
        {
            return Err("turn has no admitted file-store capability".to_owned());
        }
        match call.name.as_str() {
            "read" => self.read(&call.arguments),
            "write" => self.write(&call.arguments),
            "edit" => self.edit(&call.arguments),
            "ls" => self.list(&call.arguments),
            "find" => self.find(&call.arguments),
            "grep" => self.grep(&call.arguments),
            "bash" => {
                if !admitted_resources
                    .iter()
                    .any(|resource| resource.kind == "command")
                {
                    return Err("turn has no admitted command capability".to_owned());
                }
                self.bash(&call.arguments)
            }
            _ => Err("tool has no native workspace implementation".to_owned()),
        }
    }

    fn take_turn_witness(&self) -> TurnWitness {
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

#[cfg(any())]
#[rustfmt::skip]
mod retired_native_tool_schema_implementation {
use super::*;
/// The model-facing workspace tools owned by WhippleScript. An embedding host
/// selects whether mutation is present; it cannot redefine their schemas or
/// execution semantics.
pub fn native_workspace_tool_specs(writable: bool) -> Vec<ToolSpec> {
    native_workspace_tool_specs_with_command(writable, false)
}

pub fn native_workspace_tool_specs_with_command(
    writable: bool,
    command_execution: bool,
) -> Vec<ToolSpec> {
    native_workspace_tool_specs_with_capabilities(writable, command_execution, false)
}

pub fn native_workspace_tool_specs_with_capabilities(
    writable: bool,
    command_execution: bool,
) -> Vec<ToolSpec> {
    native_workspace_tool_specs_from_registry(true, writable, command_execution)
}

pub fn native_workspace_tool_specs_from_registry(
    readable: bool,
    writable: bool,
    command_execution: bool,
) -> Vec<ToolSpec> {
    let mut tools = if readable {
        vec![
            tool_spec(
                "read",
                "Read a workspace text file.",
                json!({
                    "type": "object", "properties": {
                        "path": { "type": "string" }, "offset": { "type": "integer" },
                        "limit": { "type": "integer" }
                    }, "required": ["path"], "additionalProperties": false
                }),
            ),
            tool_spec(
                "grep",
                "Search text in workspace files.",
                json!({
                    "type": "object", "properties": {
                        "pattern": { "type": "string" }, "path": { "type": "string" }
                    }, "required": ["pattern"], "additionalProperties": false
                }),
            ),
            tool_spec(
                "find",
                "Find workspace paths by wildcard pattern.",
                json!({
                    "type": "object", "properties": {
                        "pattern": { "type": "string" }, "path": { "type": "string" }
                    }, "required": ["pattern"], "additionalProperties": false
                }),
            ),
            tool_spec(
                "ls",
                "List a workspace directory.",
                json!({
                    "type": "object", "properties": { "path": { "type": "string" } },
                    "additionalProperties": false
                }),
            ),
        ]
    } else {
        Vec::new()
    };
    if writable {
        tools.extend([
            tool_spec(
                "write",
                "Create or replace a workspace text file.",
                json!({
                    "type": "object", "properties": {
                        "path": { "type": "string" }, "content": { "type": "string" }
                    }, "required": ["path", "content"], "additionalProperties": false
                }),
            ),
            tool_spec(
                "edit",
                "Apply exact, unique string replacements.",
                json!({
                    "type": "object", "properties": {
                        "path": { "type": "string" }, "edits": { "type": "array", "items": {
                            "type": "object", "properties": {
                                "oldText": { "type": "string" }, "newText": { "type": "string" }
                            }, "required": ["oldText", "newText"], "additionalProperties": false
                        }}
                    }, "required": ["path", "edits"], "additionalProperties": false
                }),
            ),
        ]);
    }
    if command_execution {
        tools.push(tool_spec(
            "bash",
            "Run one admitted simple command in the governed workspace.",
            json!({
                "type": "object", "properties": {
                    "command": { "type": "string" },
                    "timeout": { "type": "integer", "minimum": 1 }
                }, "required": ["command"], "additionalProperties": false
            }),
        ));
    }
    tools
}

fn tool_spec(name: &str, description: &str, input_schema: Value) -> ToolSpec {
    ToolSpec {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema,
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
    visit: &mut dyn FnMut(&str, &Path) -> bool,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(start)
        .map_err(|error| format!("cannot inspect workspace path: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err("workspace traversal reached a symlink".to_owned());
    }
    if metadata.is_file() {
        let relative = start
            .strip_prefix(root)
            .map_err(|_| "workspace traversal escaped its capability".to_owned())?
            .to_string_lossy();
        let _ = visit(&relative, start);
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
                .map_err(|_| "workspace traversal escaped its capability".to_owned())?
                .to_string_lossy();
            if !visit(&relative, &path) {
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
}

/// Out-of-band cooperative cancellation capability for one admitted host
/// command. It opens an independent store connection, so an embedding UI can
/// request cancellation while the runtime-owning thread is blocked in provider
/// I/O. The owned loop observes it between model rounds.
#[derive(Clone, Debug)]
pub struct HostCancellationHandle {
    store_path: PathBuf,
    instance_ref: String,
    command_id: String,
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
/// Failures read as "not cancelled", matching the kernel's between-rounds
/// probe — a probe failure must not kill a healthy turn.
struct StreamCancelProbe {
    store_path: PathBuf,
    instance_ref: String,
    command_id: String,
    last_read: std::cell::Cell<Option<std::time::Instant>>,
    latched: std::cell::Cell<bool>,
    store: std::cell::RefCell<Option<SqliteStore>>,
}

impl StreamCancelProbe {
    const READ_INTERVAL: Duration = Duration::from_millis(250);

    fn new(store_path: PathBuf, instance_ref: String, command_id: String) -> Self {
        Self {
            store_path,
            instance_ref,
            command_id,
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
        if self
            .last_read
            .get()
            .is_some_and(|at| at.elapsed() < Self::READ_INTERVAL)
        {
            return false;
        }
        self.last_read.set(Some(std::time::Instant::now()));
        let mut slot = self.store.borrow_mut();
        if slot.is_none() {
            *slot = SqliteStore::open(&self.store_path).ok();
        }
        let Some(store) = slot.as_mut() else {
            return false;
        };
        let open = store
            .effect_has_open_cancellation_request(&self.instance_ref, &self.command_id)
            .unwrap_or(false);
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
        let mut store = SqliteStore::open(&self.store_path).map_err(HostRuntimeError::Store)?;
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

    fn open_verified(
        store_path: impl AsRef<Path>,
        epoch: u64,
        envelope: VerifiedEnvelope,
    ) -> Result<Self, HostRuntimeError> {
        let policy = PolicyEpochRef::from_verified(epoch, &envelope)?;
        let store_path = store_path.as_ref().to_path_buf();
        let store = SqliteStore::open(&store_path).map_err(HostRuntimeError::Store)?;
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
        })
    }

    pub fn policy_ref(&self) -> &PolicyEpochRef {
        &self.policy
    }

    /// The latest durable coordinate for an instance. Hosts use this to bind a
    /// fork to one explicit source point rather than an implicit moving head.
    /// The newest instance this store records, with its recorded package
    /// reference — the adoption seam's source lookup for an embedding host
    /// whose authored package identity has drifted past what a replayed open
    /// can reproduce (see [`Self::adopt_instance_from`]). `None` for a store
    /// that has never opened an instance.
    pub fn newest_recorded_instance(&self) -> Result<Option<RecordedInstance>, HostRuntimeError> {
        let mut instances = self
            .kernel
            .store()
            .list_instances()
            .map_err(HostRuntimeError::Store)?;
        let Some(instance) = instances.pop() else {
            return Ok(None);
        };
        let metadata: InstanceMetadata =
            serde_json::from_str(&instance.input_json).map_err(HostRuntimeError::Json)?;
        Ok(Some(RecordedInstance {
            instance_ref: instance.instance_id,
            package_version_ref: metadata.package_version_ref,
        }))
    }

    pub fn current_position(&self, instance_ref: &str) -> Result<EventPosition, HostRuntimeError> {
        let events = self
            .kernel
            .store()
            .list_events(instance_ref)
            .map_err(HostRuntimeError::Store)?;
        let latest = events
            .last()
            .ok_or_else(|| HostRuntimeError::UnknownInstance(instance_ref.to_owned()))?;
        Ok(EventPosition {
            instance_ref: instance_ref.to_owned(),
            sequence: positive_sequence(latest.sequence)?,
        })
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
        }
    }

    /// Create the durable WhippleScript instance for a chat. The returned opaque
    /// instance reference is the value the host persists and uses on every turn.
    pub fn open_instance<P: PackageResolver + ?Sized>(
        &mut self,
        command: &OpenInstanceCommand,
        packages: &P,
    ) -> Result<OpenedInstance, HostRuntimeError> {
        command.validate()?;
        self.require_policy(&command.policy)?;
        let package = packages
            .resolve_package(&command.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&package, &command.package_version_ref)?;
        self.check_package_ifc(&package)?;
        if let Some(opened) = self.replayed_open_instance(command, &package)? {
            return Ok(opened);
        }

        let version = self
            .kernel
            .create_program_version(ProgramVersionInput {
                program_name: &package.agent,
                source_hash: &package.source_hash,
                ir_hash: &package.ir_hash,
                compiler_version: HOST_PROTOCOL,
            })
            .map_err(HostRuntimeError::Store)?;
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

        let source_metadata =
            Self::fork_source_metadata(source_runtime, &command.source.instance_ref, command)?;
        let source_package = packages
            .resolve_package(&source_metadata.package_version_ref)
            .map_err(HostRuntimeError::Resolver)?;
        validate_package(&source_package, &source_metadata.package_version_ref)?;
        source_runtime.check_package_ifc(&source_package)?;
        source_runtime.validate_instance_binding(
            &command.source.instance_ref,
            &source_metadata.package_version_ref,
            &command.policy,
            packages,
        )?;

        self.fork_to_target(
            source_runtime,
            command,
            packages,
            &target_package,
            &source_package.agent,
        )
    }

    /// Fork a recorded instance to the current package **without requiring the
    /// source's authored package to be reproducible** — the adoption seam for
    /// an embedding host whose package authoring has evolved past what a
    /// replayed open can reproduce (spec/agent-harness.md "Program identity
    /// across toolchains"). The source is identified, protocol- and
    /// policy-checked, and required quiescent exactly as an ordinary fork;
    /// only source-content reproduction is waived. That is sound because an
    /// adopted source is never executed again: its thread is seeded into the
    /// target, and the target's package resolves and validates in full under
    /// the current authoring.
    pub fn adopt_instance_from<P: PackageResolver + ?Sized>(
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

        let source_metadata =
            Self::fork_source_metadata(source_runtime, &command.source.instance_ref, command)?;
        let _ = source_metadata; // identity + policy checked; content deliberately not re-derived
                                 // The recorded program name stands in for the unresolvable source
                                 // package's agent: it names whose thread is being carried.
        let source_instance = source_runtime
            .kernel
            .store()
            .get_instance(&command.source.instance_ref)
            .map_err(HostRuntimeError::Store)?
            .ok_or_else(|| {
                HostRuntimeError::UnknownInstance(command.source.instance_ref.clone())
            })?;
        let source_version = source_runtime
            .kernel
            .store()
            .get_program_version(&source_instance.version_id)
            .map_err(HostRuntimeError::Store)?
            .ok_or_else(|| {
                HostRuntimeError::UnknownInstance(command.source.instance_ref.clone())
            })?;

        self.fork_to_target(
            source_runtime,
            command,
            packages,
            &target_package,
            &source_version.program_name,
        )
    }

    /// The shared fork tail: source position and quiescence checks, target
    /// open (fully validated), replay short-circuit, thread seeding, and the
    /// `host.instance.forked` record.
    fn fork_source_metadata(
        source_runtime: &GovernedHostRuntime,
        instance_ref: &str,
        command: &ForkInstanceCommand,
    ) -> Result<InstanceMetadata, HostRuntimeError> {
        let source_instance = source_runtime
            .kernel
            .store()
            .get_instance(instance_ref)
            .map_err(HostRuntimeError::Store)?
            .ok_or_else(|| HostRuntimeError::UnknownInstance(instance_ref.to_owned()))?;
        let source_metadata: InstanceMetadata =
            serde_json::from_str(&source_instance.input_json).map_err(HostRuntimeError::Json)?;
        if source_metadata.protocol != HOST_PROTOCOL || source_metadata.policy != command.policy {
            return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                "fork source package/policy binding",
            )));
        }
        Ok(source_metadata)
    }

    fn fork_to_target<P: PackageResolver + ?Sized>(
        &mut self,
        source_runtime: &GovernedHostRuntime,
        command: &ForkInstanceCommand,
        packages: &P,
        target_package: &ResolvedPackage,
        source_agent: &str,
    ) -> Result<ForkedInstance, HostRuntimeError> {
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

        let target_command = command.target_open_command();
        let target = self.open_instance(&target_command, packages)?;
        if let Some(replayed) = self.replayed_fork_instance(command, &target)? {
            return Ok(replayed);
        }
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
                Some(command.source.sequence as i64),
            )
            .map_err(HostRuntimeError::Store)?;
        self.kernel
            .seed_agent_thread(AgentThreadSeed {
                instance_id: &target.instance_ref,
                agent: &target_package.agent,
                messages: &messages,
                source_instance_id: &command.source.instance_ref,
                source_sequence: command.source.sequence as i64,
                idempotency_key: &idempotency_key(&[
                    &target.instance_ref,
                    &command.request_id,
                    "host-instance-thread-seed",
                ]),
            })
            .map_err(HostRuntimeError::Store)?;
        let payload = json!({
            "request_id": command.request_id,
            "source": command.source,
            "target_request_id": command.target_request_id,
            "package_version_ref": command.package_version_ref,
            "policy": command.policy,
        })
        .to_string();
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
        };
        result.validate_for(command)?;
        Ok(result)
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
        };
        result.validate_for(command)?;
        Ok(Some(result))
    }

    fn replayed_open_instance(
        &mut self,
        command: &OpenInstanceCommand,
        package: &ResolvedPackage,
    ) -> Result<Option<OpenedInstance>, HostRuntimeError> {
        for instance in self
            .kernel
            .store()
            .list_instances()
            .map_err(HostRuntimeError::Store)?
        {
            let events = self
                .kernel
                .store()
                .list_events(&instance.instance_id)
                .map_err(HostRuntimeError::Store)?;
            for event in events {
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
                    .ok_or_else(|| {
                        HostRuntimeError::UnknownInstance(instance.instance_id.clone())
                    })?;
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
                if version.ir_hash != package.ir_hash {
                    self.kernel
                        .reattest_instance_program(
                            &instance.instance_id,
                            ProgramVersionInput {
                                program_name: &package.agent,
                                source_hash: &package.source_hash,
                                ir_hash: &package.ir_hash,
                                compiler_version: HOST_PROTOCOL,
                            },
                        )
                        .map_err(HostRuntimeError::Store)?;
                }
                return Ok(Some(opened));
            }
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
        self.admit_command(command, packages)?;
        let binding = self.resolve_provider(command, secrets)?;
        let sink = |delta: &str| resources.observe_text_delta(delta);
        // Mid-stream cooperative cancel (spec/agent-harness.md "Cancellation"):
        // the transport polls the durable request surface between streamed
        // lines and releases the stream early; the machine converts that
        // released round to `Cancelled`, keeping the text that fully arrived.
        let probe = StreamCancelProbe::new(
            self.store_path.clone(),
            command.instance_ref.clone(),
            command.command_id.clone(),
        );
        let observed = || probe.observed();
        let released = || probe.released();
        let driver = NativeHttpDriver::new(binding.timeout)
            .with_delta_sink(&sink)
            .with_cancel_probe(&observed);
        self.run_admitted_turn(
            command,
            packages,
            resources,
            binding,
            &driver,
            Some(&released),
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
        self.admit_command(command, packages)?;
        let binding = self.resolve_provider(command, secrets)?;
        self.run_admitted_turn(command, packages, resources, binding, driver, None)
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
        resources: &R,
        binding: ResolvedProviderBinding,
        driver: &H,
        stream_released: Option<&dyn Fn() -> bool>,
    ) -> Result<TurnExecution, HostRuntimeError>
    where
        P: PackageResolver + ?Sized,
        R: ResourceResolver + ?Sized,
        H: HostDriver,
    {
        if let Some(execution) = self.stored_execution(command)? {
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
            Some(effect) if effect.input_json != command_json => {
                return Err(HostRuntimeError::Protocol(ProtocolError::Mismatch(
                    "command id reused with different turn",
                )));
            }
            Some(effect) if is_terminal_effect(&effect.status) => {
                return self.finish_execution(command);
            }
            Some(_) => true,
            None => {
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
                false
            }
        };

        // Message-scoped image handles are resolved only when the effect is
        // first committed. A suspended effect already has its exact brokered
        // transcript; resumption must not require the embedding host to retain
        // or replay the original ephemeral bytes.
        let images = if resumed_effect {
            Vec::new()
        } else {
            command
                .input
                .images
                .iter()
                .map(|image| {
                    let resolved = resources
                        .resolve_image(image)
                        .map_err(HostRuntimeError::Resolver)?;
                    if resolved.media_type.trim().is_empty() {
                        return Err(HostRuntimeError::Resolver(
                            "resolved image has no media type".to_owned(),
                        ));
                    }
                    Ok(ImageBlock {
                        media_type: resolved.media_type,
                        data_base64: base64_encode(&resolved.bytes),
                    })
                })
                .collect::<Result<Vec<_>, HostRuntimeError>>()?
        };
        let executor = ResolverToolExecutor {
            offered: &package.tools,
            admitted_resources: &command.resources,
            resolver: resources,
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
        let input = BrokeredTurnInput {
            system: package.system_prompt,
            user: command.input.text.clone(),
            tools: package.tools.clone(),
            max_steps: package.max_steps,
            resume_from: Vec::new(),
            user_images: images,
            context_bundles: Vec::new(),
            pinned_skills: Vec::new(),
        };
        self.kernel
            .run_brokered_agent_turn(
                &BrokeredTurnContext {
                    instance_id: &command.instance_ref,
                    effect_id: &command.command_id,
                    agent: &package.agent,
                    profile: None,
                    thread_continue: true,
                    stream_released,
                },
                &client,
                &executor,
                driver,
                &NoopCompactor,
                &input,
            )
            .map_err(HostRuntimeError::Store)?;
        // DR-0036 §1: persist this segment's workspace witness before the turn
        // suspends or finishes — a human-suspended turn resumes with a fresh
        // resolver, so the receipt aggregates the durable segments instead of
        // trusting any single resolver instance.
        self.record_witness_segment(command, resources)?;
        self.finish_execution(command)
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
        let mut projected = Vec::with_capacity(evidence.len());
        for item in evidence {
            let evidence_ref = format!("whip:evidence:{}", item.evidence_id);
            if let Some(existing) = existing_events.iter().find(|event| {
                event.event_type == "host.turn.evidence"
                    && serde_json::from_str::<Value>(&event.payload_json)
                        .ok()
                        .is_some_and(|payload| {
                            payload.get("command_id").and_then(Value::as_str)
                                == Some(command.command_id.as_str())
                                && payload.get("evidence_ref").and_then(Value::as_str)
                                    == Some(evidence_ref.as_str())
                        })
            }) {
                projected.push(LabeledRuntimeEvent {
                    protocol: HOST_PROTOCOL.to_owned(),
                    command_id: command.command_id.clone(),
                    position: EventPosition {
                        instance_ref: command.instance_ref.clone(),
                        sequence: positive_sequence(existing.sequence)?,
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

    fn stored_execution(
        &self,
        command: &StartTurnCommand,
    ) -> Result<Option<TurnExecution>, HostRuntimeError> {
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
                ChatMessage::System(_) | ChatMessage::User { .. } => {}
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
        (&left.handle, &left.kind, &left.selector).cmp(&(
            &right.handle,
            &right.kind,
            &right.selector,
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

struct ResolverToolExecutor<'a, R: ResourceResolver + ?Sized> {
    offered: &'a [ToolSpec],
    admitted_resources: &'a [ResourceRef],
    resolver: &'a R,
}

impl<R: ResourceResolver + ?Sized> ToolExecutor for ResolverToolExecutor<'_, R> {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if !self.offered.iter().any(|tool| tool.name == call.name) {
            return ToolOutcome {
                status: ToolStatus::Error,
                content: "tool is not declared by the pinned package".to_owned(),
            };
        }
        match self.resolver.execute_tool(self.admitted_resources, call) {
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

struct NativeHttpDriver<'a> {
    agent: ureq::Agent,
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
            delta_sink: None,
            cancel_probe: None,
        }
    }

    fn with_delta_sink(mut self, sink: &'a dyn Fn(&str)) -> Self {
        self.delta_sink = Some(sink);
        self
    }

    fn with_cancel_probe(mut self, probe: &'a dyn Fn() -> bool) -> Self {
        self.cancel_probe = Some(probe);
        self
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
    if event.get("type").and_then(Value::as_str) != Some("response.output_text.delta") {
        return None;
    }
    event
        .get("delta")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

impl HostDriver for NativeHttpDriver<'_> {
    fn fulfill(&self, request: &IoRequest) -> IoResult {
        let IoRequest::Http(request) = request;
        let mut builder = self.agent.post(&request.url);
        for (name, value) in &request.headers {
            builder = builder.set(name, value);
        }
        let response = match builder.send_json(request.body.clone()) {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => {
                let message = error.to_string();
                let error = if message.to_ascii_lowercase().contains("timeout") {
                    TransportError::Timeout
                } else {
                    TransportError::Transport(message)
                };
                return IoResult::Http(Err(error));
            }
        };
        let expects_sse = request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("accept") && value == "text/event-stream"
        });
        let status = response.status();
        let body = if expects_sse {
            assemble_responses_sse(&self.read_sse_body(response))
        } else {
            response.into_json::<Value>().unwrap_or(Value::Null)
        };
        IoResult::Http(Ok(HttpResponse { status, body }))
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
    Resolver(String),
    Store(StoreError),
    Json(serde_json::Error),
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

    struct ScriptedDriver {
        replies: RefCell<VecDeque<Value>>,
        requests: RefCell<Vec<Value>>,
    }

    impl ScriptedDriver {
        fn new(replies: Vec<Value>) -> Self {
            Self {
                replies: RefCell::new(replies.into()),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl HostDriver for ScriptedDriver {
        fn fulfill(&self, request: &IoRequest) -> IoResult {
            let IoRequest::Http(request) = request;
            self.requests.borrow_mut().push(request.body.clone());
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
        let labeled = |principal| ResourcePolicy {
            reader: BTreeSet::from(["Operator".to_owned()]),
            writer: BTreeSet::from(["Operator".to_owned()]),
            principal,
            internal: false,
        };
        let policy = HostGovernancePolicy {
            resources: BTreeMap::from([
                ("file:/workspace".to_owned(), labeled(false)),
                ("provider:openai".to_owned(), labeled(true)),
                ("provider:owned".to_owned(), labeled(true)),
                ("placement:local".to_owned(), labeled(true)),
            ]),
            bindings: BTreeMap::from([
                ("project".to_owned(), "file:/workspace".to_owned()),
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
                    base_url: "https://provider.invalid".to_owned(),
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
        };
        SignedEnvelope::sign_for_test(&policy.to_json().expect("policy"), "gaugedesk-admin")
            .to_json()
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
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "whip-host-runtime-{}-{nonce}.sqlite",
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
                    }],
                },
                CertifiedOutputFieldFlow {
                    field: "tool_calls".to_owned(),
                    reads: vec![ResourceRef {
                        handle: "project".to_owned(),
                        kind: "file_store".to_owned(),
                        selector: None,
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
        fs::create_dir_all(root.join(".pi")).expect("dirs");
        fs::write(root.join("note.txt"), "alpha\nbeta\n").expect("note");
        fs::write(root.join(".pi/SYSTEM.md"), "protected").expect("method");
        let resolver = NativeWorkspaceResolver::new(&root)
            .expect("resolver")
            .read_only([PathBuf::from(".pi")])
            .expect("read-only path");
        let resources = [ResourceRef {
            handle: "project".to_owned(),
            kind: "file_store".to_owned(),
            selector: None,
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
                    id: "edit-1".to_owned(),
                    name: "edit".to_owned(),
                    arguments: json!({
                        "path": "note.txt",
                        "edits": [{ "oldText": "beta", "newText": "gamma" }]
                    }),
                },
            )
            .expect("edit");
        assert_eq!(
            fs::read_to_string(root.join("note.txt")).expect("edited note"),
            "alpha\ngamma\n"
        );

        for path in ["../outside", ".pi/SYSTEM.md"] {
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
            fs::read_to_string(root.join(".pi/SYSTEM.md")).expect("protected method"),
            "protected"
        );
        assert!(native_workspace_tool_specs(false)
            .iter()
            .all(|tool| tool.name != "write" && tool.name != "edit"));
        assert!(native_workspace_tool_specs(true)
            .iter()
            .any(|tool| tool.name == "write"));
        let _ = fs::remove_dir_all(root);
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
        fs::create_dir_all(root.join(".pi")).expect("dirs");
        let resolver = NativeWorkspaceResolver::new(&root)
            .expect("resolver")
            .read_only([PathBuf::from(".pi")])
            .expect("read-only");
        let project_only = [ResourceRef {
            handle: "project".to_owned(),
            kind: "file_store".to_owned(),
            selector: None,
        }];
        let admitted = [
            project_only[0].clone(),
            ResourceRef {
                handle: "command".to_owned(),
                kind: "command".to_owned(),
                selector: None,
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
            .execute_tool(&admitted, &call("echo tampered > .pi/SYSTEM.md"))
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
        let driver = NativeHttpDriver::new(Duration::from_secs(10)).with_delta_sink(&sink);
        let request = IoRequest::Http(HttpRequest {
            url: format!("http://{addr}/v1/responses"),
            headers: vec![("accept".to_owned(), "text/event-stream".to_owned())],
            body: json!({}),
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
            std::thread::sleep(StreamCancelProbe::READ_INTERVAL + Duration::from_millis(50));
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
        let probe = StreamCancelProbe::new(
            path.clone(),
            command.instance_ref.clone(),
            command.command_id.clone(),
        );
        let driver = ProbeAssertingDriver {
            handle: runtime.cancellation_handle(&command.instance_ref, &command.command_id),
            probe: &probe,
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
