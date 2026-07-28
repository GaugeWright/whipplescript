//! Codex App Server provider adapter for WhippleScript.
//!
//! An external, opt-in provider crate (DR-0024 provider-crate split): the kernel
//! has no compile-time knowledge of Codex. This crate owns the Codex protocol
//! (JSON-RPC transport, event normalization, policy mapping) and registers a
//! [`ProviderCapability`] into whatever catalog the host assembles via
//! [`capability`]. It depends on `whipplescript-kernel` for the shared provider
//! vocabulary and the kernel-side redaction boundary.

use std::{
    collections::{BTreeSet, VecDeque},
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

use serde_json::{json, Value};

use whipplescript_kernel::{
    native_lifecycle::{AgentTurnLifecycleKind, NativeAgentTurnObservation},
    provider::{
        CancellationDepth, NativeProviderAdapter, NativeProviderArtifactRef,
        NativeProviderBoundaryError, NativeProviderCancellation, NativeProviderEvent,
        NativeProviderEventKind, NativeProviderTurnRequest, ProviderCapability,
    },
};

/// The provider-kind identifier this crate registers under. Opaque to the kernel.
pub const PROVIDER_KIND: &str = "codex";
/// The adapter-surface identifier this crate speaks.
pub const SURFACE: &str = "codex_app_server";

/// The Codex capability entry. The host assembles this into the effective
/// provider catalog it passes to `validate_provider_binding` — the kernel does
/// not carry it (open registry).
pub fn capability() -> ProviderCapability {
    ProviderCapability {
        provider_kind: PROVIDER_KIND.to_owned(),
        surface: SURFACE.to_owned(),
        protocol_version: Some("codex-app-server-local-schema".to_owned()),
        session_identity_fields: ["thread_id", "turn_id", "item_id"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        stream_event_kinds: [
            "turn/started",
            "turn/completed",
            "turn/diff/updated",
            "approval/requested",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        tool_policy: "codex_approvals".to_owned(),
        cancellation_depths: vec![CancellationDepth::NativeStop],
        artifact_manifest: true,
        health_checks: ["codex_cli", "app_server_schema", "auth_status"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        auth_requirements: vec!["codex_login_or_openai_api_key".to_owned()],
    }
}

/// Normalize a raw Codex app-server JSON-RPC message into the kernel's
/// provider-agnostic lifecycle observation (shape-only payload; the kernel's
/// redaction boundary is applied via `payload_shape`). Event-shape knowledge
/// lives here with the adapter that speaks the protocol.
pub fn normalize_codex_app_server_event(message: &Value) -> Option<NativeAgentTurnObservation> {
    let method = message.get("method").and_then(Value::as_str)?;
    let params = message.get("params").unwrap_or(&Value::Null);
    let kind = match method {
        "turn/started" => AgentTurnLifecycleKind::Started,
        "turn/completed" => codex_terminal_kind(params),
        "turn/diff/updated" | "item/fileChange/patchUpdated" => {
            AgentTurnLifecycleKind::ArtifactCaptured
        }
        "item/tool/call" | "item/tool/requestUserInput" => AgentTurnLifecycleKind::ToolRequested,
        "item/started" | "item/completed" => AgentTurnLifecycleKind::Streamed,
        method if method.contains("/requestApproval") => AgentTurnLifecycleKind::ToolRequested,
        _ => return None,
    };
    Some(
        NativeAgentTurnObservation::new(kind, method)
            .session_id(
                params
                    .get("threadId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
            .turn_id(
                params
                    .get("turnId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
            .payload_shape(params)
            .provider_error(codex_terminal_error(params)),
    )
}

/// The Codex app-server reports a terminal failure reason under
/// `params.turn.error.message` (with `codexErrorInfo` as a machine code). This is
/// a control-plane error string, not model output.
fn codex_terminal_error(params: &Value) -> Option<String> {
    params
        .pointer("/turn/error/message")
        .or_else(|| params.pointer("/error/message"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn codex_terminal_kind(params: &Value) -> AgentTurnLifecycleKind {
    match params
        .get("status")
        .or_else(|| params.pointer("/turn/status"))
        .or_else(|| params.get("reason"))
        .and_then(Value::as_str)
    {
        Some("cancelled" | "interrupted" | "canceled") => AgentTurnLifecycleKind::Cancelled,
        Some("failed" | "error") => AgentTurnLifecycleKind::Failed,
        Some("timed_out" | "timeout") => AgentTurnLifecycleKind::TimedOut,
        _ => AgentTurnLifecycleKind::Completed,
    }
}

#[derive(Debug)]
pub enum CodexAppServerError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Protocol(String),
    Remote(Value),
    Timeout(String),
}

impl From<std::io::Error> for CodexAppServerError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for CodexAppServerError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub trait CodexAppServerTransport {
    fn write_line(&mut self, line: &str) -> Result<(), CodexAppServerError>;
    fn read_line(&mut self) -> Result<String, CodexAppServerError>;
    /// Wait up to `wait` for the next line; `Ok(None)` means the window
    /// elapsed with the peer still alive (DR-0035 Decision 4 inactivity
    /// clock). The default keeps blocking semantics for transports without a
    /// clock (test fakes).
    fn read_line_timeout(
        &mut self,
        wait: std::time::Duration,
    ) -> Result<Option<String>, CodexAppServerError> {
        let _ = wait;
        self.read_line().map(Some)
    }
}

pub struct CodexAppServerClient<T> {
    transport: T,
    next_id: u64,
    notifications: VecDeque<Value>,
    server_requests: VecDeque<Value>,
}

impl<T: CodexAppServerTransport> CodexAppServerClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: 1,
            notifications: VecDeque::new(),
            server_requests: VecDeque::new(),
        }
    }

    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, CodexAppServerError> {
        self.request_inner(method, params, None)
    }

    /// `request` bounded by a wait budget (DR-0035 Decision 4): a peer that
    /// never answers the JSON-RPC call yields a Timeout error instead of
    /// blocking the worker thread through turn start.
    pub fn request_timeout(
        &mut self,
        method: &str,
        params: Value,
        wait: std::time::Duration,
    ) -> Result<Value, CodexAppServerError> {
        self.request_inner(method, params, Some(wait))
    }

    fn request_inner(
        &mut self,
        method: &str,
        params: Value,
        wait: Option<std::time::Duration>,
    ) -> Result<Value, CodexAppServerError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        })
        .to_string();
        self.transport.write_line(&request)?;
        loop {
            let line = match wait {
                Some(window) => self.transport.read_line_timeout(window)?.ok_or_else(|| {
                    CodexAppServerError::Timeout(format!(
                        "no response to `{method}` within the start budget"
                    ))
                })?,
                None => self.transport.read_line()?,
            };
            if line.trim().is_empty() {
                continue;
            }
            let message: Value = serde_json::from_str(&line)?;
            if message.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(error) = message.get("error") {
                    return Err(CodexAppServerError::Remote(error.clone()));
                }
                return message.get("result").cloned().ok_or_else(|| {
                    CodexAppServerError::Protocol("response missing `result`".to_owned())
                });
            }
            if message.get("id").is_some()
                && message.get("method").and_then(Value::as_str).is_some()
            {
                self.server_requests.push_back(message);
                continue;
            }
            if message.get("method").and_then(Value::as_str).is_some() {
                self.notifications.push_back(message);
                continue;
            }
            return Err(CodexAppServerError::Protocol(
                "received response for unknown request id".to_owned(),
            ));
        }
    }

    pub fn pop_notification(&mut self) -> Option<Value> {
        self.notifications.pop_front()
    }

    pub fn pop_server_request(&mut self) -> Option<Value> {
        self.server_requests.pop_front()
    }

    pub fn respond(&mut self, id: Value, result: Value) -> Result<(), CodexAppServerError> {
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": result,
        })
        .to_string();
        self.transport.write_line(&response)
    }

    pub fn respond_error(&mut self, id: Value, message: &str) -> Result<(), CodexAppServerError> {
        let response = json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32000,
                "message": message,
            },
        })
        .to_string();
        self.transport.write_line(&response)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }

    pub fn read_message(&mut self) -> Result<Value, CodexAppServerError> {
        loop {
            let line = self.transport.read_line()?;
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(&line).map_err(CodexAppServerError::Json);
        }
    }

    /// `read_message` bounded by the inactivity clock: `Ok(None)` means the
    /// window elapsed without a frame (the peer is alive but silent).
    pub fn read_message_timeout(
        &mut self,
        wait: std::time::Duration,
    ) -> Result<Option<Value>, CodexAppServerError> {
        loop {
            let Some(line) = self.transport.read_line_timeout(wait)? else {
                return Ok(None);
            };
            if line.trim().is_empty() {
                continue;
            }
            return serde_json::from_str(&line)
                .map(Some)
                .map_err(CodexAppServerError::Json);
        }
    }
}

pub struct StdioCodexAppServerTransport {
    _child: Child,
    stdin: ChildStdin,
    // Lines arrive via a reader thread so reads can carry a timeout
    // (DR-0035 Decision 4): a blocked pipe no longer pins the worker thread.
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
}

impl StdioCodexAppServerTransport {
    pub fn spawn(command: &str, args: &[&str]) -> Result<Self, CodexAppServerError> {
        let mut builder = Command::new(command);
        builder
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        whipplescript_kernel::harness::strip_control_plane_secrets(&mut builder);
        // Codex is the OpenAI-family backend; it never needs an Anthropic key.
        whipplescript_kernel::harness::strip_env_vars(
            &mut builder,
            whipplescript_kernel::harness::ANTHROPIC_CREDENTIAL_ENV,
        );
        let mut child = builder.spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| {
            CodexAppServerError::Protocol("app-server process did not expose stdin".to_owned())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            CodexAppServerError::Protocol("app-server process did not expose stdout".to_owned())
        })?;
        Ok(Self {
            _child: child,
            stdin,
            lines: spawn_line_reader(stdout),
        })
    }

    fn closed_error() -> CodexAppServerError {
        CodexAppServerError::Timeout("app-server stdout closed before response".to_owned())
    }
}

fn spawn_line_reader(stdout: ChildStdout) -> std::sync::mpsc::Receiver<std::io::Result<String>> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if sender.send(Ok(line)).is_err() {
                        break;
                    }
                }
                Err(error) => {
                    let _ = sender.send(Err(error));
                    break;
                }
            }
        }
    });
    receiver
}

impl CodexAppServerTransport for StdioCodexAppServerTransport {
    fn write_line(&mut self, line: &str) -> Result<(), CodexAppServerError> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        Ok(())
    }

    fn read_line(&mut self) -> Result<String, CodexAppServerError> {
        match self.lines.recv() {
            Ok(Ok(line)) => Ok(line),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(Self::closed_error()),
        }
    }

    fn read_line_timeout(
        &mut self,
        wait: std::time::Duration,
    ) -> Result<Option<String>, CodexAppServerError> {
        match self.lines.recv_timeout(wait) {
            Ok(Ok(line)) => Ok(Some(line)),
            Ok(Err(error)) => Err(error.into()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(Self::closed_error()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAppServerPolicy {
    pub sandbox_mode: String,
    pub approval_policy: String,
    pub required_capabilities: Vec<String>,
}

impl CodexAppServerPolicy {
    pub fn to_config_args(&self) -> Vec<String> {
        vec![
            "-c".to_owned(),
            format!("sandbox_mode=\"{}\"", self.sandbox_mode),
            "-c".to_owned(),
            format!("approval_policy=\"{}\"", self.approval_policy),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexAppServerPolicyError {
    pub code: String,
    pub message: String,
}

pub fn build_codex_app_server_policy(
    profile: Option<&str>,
    required_capabilities: &[String],
    workspace_policy: &str,
    approval_mode: Option<&str>,
) -> Result<CodexAppServerPolicy, CodexAppServerPolicyError> {
    let profile = profile.ok_or_else(|| {
        codex_policy_error(
            "missing_profile",
            "Codex app-server policy requires an explicit profile",
        )
    })?;
    match approval_mode {
        Some("manual") | Some("never") | None => {}
        Some(other) => {
            return Err(codex_policy_error(
                "unsupported_approval_mode",
                format!("approval mode `{other}` is not supported for Codex"),
            ));
        }
    }

    let mut needs_workspace_write = false;
    let mut needs_approval = false;
    let mut capabilities = BTreeSet::new();
    for capability in required_capabilities {
        capabilities.insert(capability.clone());
        match capability.as_str() {
            "repo.read" => {}
            "repo.write" => {
                require_codex_writer(profile, workspace_policy, "repo.write")?;
                needs_workspace_write = true;
                needs_approval = true;
            }
            "command.run" => {
                require_codex_writer(profile, workspace_policy, "command.run")?;
                needs_workspace_write = true;
                needs_approval = true;
            }
            other => {
                return Err(codex_policy_error(
                    "unsupported_capability",
                    format!("capability `{other}` is not mapped to a Codex policy"),
                ));
            }
        }
    }

    // Table-driven (kernel/agent_profile.rs; spec/std-agent.md slice 4): a
    // preset maps to Codex only when its row says so; unknown names and
    // unmapped presets fail closed.
    match whipplescript_kernel::agent_profile::agent_profile_preset(profile) {
        Some(preset) if preset.codex_mapped => {}
        _ => {
            return Err(codex_policy_error(
                "profile_denied",
                format!("profile `{profile}` is not mapped to a Codex policy"),
            ));
        }
    }

    if needs_approval && approval_mode != Some("manual") {
        return Err(codex_policy_error(
            "missing_approval",
            "destructive Codex actions require manual approval mode",
        ));
    }

    Ok(CodexAppServerPolicy {
        sandbox_mode: if needs_workspace_write {
            "workspace-write".to_owned()
        } else {
            "read-only".to_owned()
        },
        approval_policy: if needs_approval {
            "on-request".to_owned()
        } else {
            "never".to_owned()
        },
        required_capabilities: capabilities.into_iter().collect(),
    })
}

fn require_codex_writer(
    profile: &str,
    workspace_policy: &str,
    capability: &str,
) -> Result<(), CodexAppServerPolicyError> {
    // A destructive capability is granted only when the preset's table row
    // carries it (spec/std-agent.md slice 4) — not by a hard-matched name.
    let grants = whipplescript_kernel::agent_profile::agent_profile_preset(profile)
        .is_some_and(|preset| preset.codex_mapped && preset.grants_capability(capability));
    if !grants {
        return Err(codex_policy_error(
            "profile_denied",
            format!("profile `{profile}` cannot use Codex capability `{capability}`"),
        ));
    }
    match workspace_policy {
        "shared" | "per_effect_worktree" | "per_issue_worktree" => Ok(()),
        "read_only" => Err(codex_policy_error(
            "workspace_denied",
            format!("workspace policy `{workspace_policy}` denies Codex capability `{capability}`"),
        )),
        other => Err(codex_policy_error(
            "unsupported_workspace_policy",
            format!("workspace policy `{other}` is not supported for Codex app-server writes"),
        )),
    }
}

fn codex_policy_error(
    code: impl Into<String>,
    message: impl Into<String>,
) -> CodexAppServerPolicyError {
    CodexAppServerPolicyError {
        code: code.into(),
        message: message.into(),
    }
}

pub struct CodexAppServerAdapter<T> {
    provider_id: String,
    capability: ProviderCapability,
    client: CodexAppServerClient<T>,
    initialized: bool,
    // The consumed `initialize` reply (DR-0035 Decision 7), shape-only;
    // attached to the first event's evidence then cleared.
    initialize_result_shape: Option<Value>,
    thread_id: Option<String>,
    turn_id: Option<String>,
    sequence: u64,
    // DR-0035 Decision 4: the inactivity wall clock. When no frame arrives
    // within this window, the adapter synthesizes the TimedOut terminal.
    inactivity_budget: std::time::Duration,
    // Idle time accumulated across empty poll slices; reset on every frame.
    idle_elapsed: std::time::Duration,
}

impl<T: CodexAppServerTransport> CodexAppServerAdapter<T> {
    pub fn new(
        provider_id: impl Into<String>,
        capability: ProviderCapability,
        client: CodexAppServerClient<T>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            capability,
            client,
            initialized: false,
            initialize_result_shape: None,
            thread_id: None,
            turn_id: None,
            sequence: 0,
            inactivity_budget: std::time::Duration::from_secs(300),
            idle_elapsed: std::time::Duration::ZERO,
        }
    }

    pub fn with_inactivity_budget(mut self, budget: std::time::Duration) -> Self {
        self.inactivity_budget = budget;
        self
    }

    pub fn into_client(self) -> CodexAppServerClient<T> {
        self.client
    }

    /// The synthesized inactivity terminal (DR-0035 Decision 4 T2): a silent
    /// or closed peer still yields exactly one terminal.
    fn inactivity_timeout_event(&mut self, run_id: &str, reason: &str) -> NativeProviderEvent {
        self.sequence += 1;
        NativeProviderEvent {
            provider_id: self.provider_id.clone(),
            run_id: run_id.to_owned(),
            event_kind: NativeProviderEventKind::TimedOut,
            provider_event_type: "whip.native.inactivity_timeout".to_owned(),
            provider_session_id: self.thread_id.clone(),
            provider_turn_id: self.turn_id.clone(),
            sequence: Some(self.sequence),
            evidence: json!({
                "reason": reason,
                "inactivity_budget_seconds": self.inactivity_budget.as_secs(),
            }),
            artifacts: Vec::new(),
        }
    }

    // Returns the shared, deliberately-rich `NativeProviderBoundaryError`; see
    // the kernel trait for why the large-Err variant is allowed at this seam.
    #[allow(clippy::result_large_err)]
    fn ensure_codex_request(
        &self,
        request: &NativeProviderTurnRequest,
    ) -> Result<(), NativeProviderBoundaryError> {
        if request.provider_id != self.provider_id {
            return Err(self.boundary_error(
                "provider_id_mismatch",
                "Codex adapter received a request for a different provider id",
                false,
                json!({
                    "request_provider_id": request.provider_id,
                    "adapter_provider_id": self.provider_id,
                }),
            ));
        }
        if request.provider_kind != "codex" || request.surface != "codex_app_server" {
            return Err(self.boundary_error(
                "surface_mismatch",
                "Codex adapter only accepts codex_app_server requests",
                false,
                request.to_json_redacted(),
            ));
        }
        Ok(())
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    fn boundary_error(
        &self,
        code: impl Into<String>,
        message: impl Into<String>,
        recoverable: bool,
        evidence: Value,
    ) -> NativeProviderBoundaryError {
        NativeProviderBoundaryError {
            provider_id: self.provider_id.clone(),
            surface: "codex_app_server".to_owned(),
            code: code.into(),
            message: message.into(),
            recoverable,
            evidence,
        }
    }

    fn map_error(
        &self,
        code: &'static str,
        error: CodexAppServerError,
    ) -> NativeProviderBoundaryError {
        let (message, recoverable, evidence) = match error {
            CodexAppServerError::Io(error) => (
                format!("Codex app-server I/O error: {error}"),
                true,
                json!({"kind": "io"}),
            ),
            CodexAppServerError::Json(error) => (
                format!("Codex app-server emitted invalid JSON: {error}"),
                true,
                json!({"kind": "json"}),
            ),
            CodexAppServerError::Protocol(message) => (message, true, json!({"kind": "protocol"})),
            CodexAppServerError::Remote(error) => (
                "Codex app-server returned a remote error".to_owned(),
                true,
                json!({
                    "kind": "remote",
                    "shape": json_shape(&error),
                    "code": error.get("code").cloned().unwrap_or(Value::Null),
                    "message": error
                        .get("message")
                        .and_then(Value::as_str)
                        .map(whipplescript_kernel::provider::redact_sensitive_metadata),
                }),
            ),
            CodexAppServerError::Timeout(message) => (message, true, json!({"kind": "timeout"})),
        };
        self.boundary_error(code, message, recoverable, evidence)
    }

    fn maybe_event_from_message(
        &mut self,
        run_id: &str,
        message: Value,
    ) -> Option<NativeProviderEvent> {
        let observation = normalize_codex_app_server_event(&message)?;
        let sequence = self.next_sequence();
        if let Some(session_id) = observation.provider_session_id.as_ref() {
            self.thread_id = Some(session_id.clone());
        }
        if let Some(turn_id) = observation.provider_turn_id.as_ref() {
            self.turn_id = Some(turn_id.clone());
        }
        Some(NativeProviderEvent {
            provider_id: self.provider_id.clone(),
            run_id: run_id.to_owned(),
            event_kind: native_event_kind(observation.kind),
            provider_event_type: observation.provider_event_type,
            provider_session_id: observation.provider_session_id,
            provider_turn_id: observation.provider_turn_id,
            sequence: Some(sequence),
            evidence: json!({
                "provider_payload_shape": observation.provider_payload_shape,
                "message_shape": json_shape(&message),
                "provider_error": observation.provider_error,
            }),
            artifacts: artifact_refs_from_codex_message(&message),
        })
    }

    fn respond_to_server_request(&mut self, message: &Value) -> Result<(), CodexAppServerError> {
        let Some(id) = message.get("id").cloned() else {
            return Ok(());
        };
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            return Ok(());
        };
        match method {
            "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                self.client.respond(id, json!({"decision": "decline"}))
            }
            "item/tool/requestUserInput" => self.client.respond(id, json!({"answers": {}})),
            "item/tool/call" => self
                .client
                .respond(id, json!({"success": false, "contentItems": []})),
            _ => self.client.respond_error(
                id,
                "unsupported Codex app-server request in WhippleScript native adapter",
            ),
        }
    }
}

impl<T: CodexAppServerTransport> NativeProviderAdapter for CodexAppServerAdapter<T> {
    fn provider_id(&self) -> &str {
        &self.provider_id
    }

    fn capability(&self) -> &ProviderCapability {
        &self.capability
    }

    fn start_turn(
        &mut self,
        request: NativeProviderTurnRequest,
    ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
        self.ensure_codex_request(&request)?;
        let policy = build_codex_app_server_policy(
            request.profile.as_deref(),
            &request.required_capabilities,
            &request.workspace_policy,
            request
                .provider_options
                .get("approval_mode")
                .and_then(Value::as_str),
        )
        .map_err(|error| {
            self.boundary_error(error.code, error.message, false, request.to_json_redacted())
        })?;

        // Turn-start RPCs are bounded by the inactivity budget (DR-0035
        // Decision 4): a hung app-server fails the start instead of pinning
        // the worker thread.
        let budget = self.inactivity_budget;
        if !self.initialized {
            let initialize_result = self
                .client
                .request_timeout(
                    "initialize",
                    json!({
                        "clientInfo": {
                            "name": "whipplescript-native-codex",
                            "version": "0.0.0",
                        },
                        "capabilities": {},
                    }),
                    budget,
                )
                .map_err(|error| self.map_error("codex_initialize_failed", error))?;
            // DR-0035 Decision 7: consume the handshake reply instead of
            // discarding it — the server's advertised info rides the started
            // event as evidence (shape-only across the redaction boundary).
            self.initialize_result_shape = Some(json_shape(&initialize_result));
            self.initialized = true;
        }

        let thread_start = self
            .client
            .request_timeout(
                "thread/start",
                codex_thread_start_params(&request, &policy),
                budget,
            )
            .map_err(|error| self.map_error("codex_thread_start_failed", error))?;
        let thread_id = thread_start
            .pointer("/thread/id")
            .or_else(|| thread_start.get("threadId"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                self.boundary_error(
                    "codex_thread_id_missing",
                    "Codex thread/start response did not include a thread id",
                    true,
                    json!({"response_shape": json_shape(&thread_start)}),
                )
            })?
            .to_owned();
        self.thread_id = Some(thread_id.clone());

        let turn_start = self
            .client
            .request_timeout(
                "turn/start",
                codex_turn_start_params(&request, &policy, &thread_id),
                budget,
            )
            .map_err(|error| self.map_error("codex_turn_start_failed", error))?;
        let turn_id = turn_start
            .pointer("/turn/id")
            .or_else(|| turn_start.get("turnId"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                self.boundary_error(
                    "codex_turn_id_missing",
                    "Codex turn/start response did not include a turn id",
                    true,
                    json!({"response_shape": json_shape(&turn_start)}),
                )
            })?
            .to_owned();
        self.turn_id = Some(turn_id.clone());

        Ok(NativeProviderEvent {
            provider_id: self.provider_id.clone(),
            run_id: request.run_id,
            event_kind: NativeProviderEventKind::Started,
            provider_event_type: "turn/start".to_owned(),
            provider_session_id: Some(thread_id),
            provider_turn_id: Some(turn_id),
            sequence: Some(self.next_sequence()),
            evidence: json!({
                // The consumed initialize reply (DR-0035 Decision 7) rides the
                // started event once, shape-only.
                "initialize_result_shape": self.initialize_result_shape.take(),
                "thread_start_response_shape": json_shape(&thread_start),
                "turn_start_response_shape": json_shape(&turn_start),
                "policy": {
                    "sandbox_mode": policy.sandbox_mode,
                    "approval_policy": policy.approval_policy,
                    "required_capabilities": policy.required_capabilities,
                },
            }),
            artifacts: vec![],
        })
    }

    fn next_event(
        &mut self,
        run_id: &str,
    ) -> Result<Option<NativeProviderEvent>, NativeProviderBoundaryError> {
        if let Some(message) = self.client.pop_server_request() {
            self.respond_to_server_request(&message)
                .map_err(|error| self.map_error("codex_server_request_response_failed", error))?;
            return Ok(self.maybe_event_from_message(run_id, message));
        }
        if let Some(message) = self.client.pop_notification() {
            return Ok(self.maybe_event_from_message(run_id, message));
        }
        // The wait is sliced (DR-0035 Decision 5) so the driver regains control
        // between slices to act on cancellation requests; the inactivity clock
        // accumulates across empty slices and fires at the full budget.
        let slice = self
            .inactivity_budget
            .min(std::time::Duration::from_secs(1));
        match self.client.read_message_timeout(slice) {
            Ok(Some(message)) => {
                self.idle_elapsed = std::time::Duration::ZERO;
                if message.get("id").is_some()
                    && message.get("method").and_then(Value::as_str).is_some()
                {
                    self.respond_to_server_request(&message).map_err(|error| {
                        self.map_error("codex_server_request_response_failed", error)
                    })?;
                }
                Ok(self.maybe_event_from_message(run_id, message))
            }
            Ok(None) => {
                self.idle_elapsed += slice;
                if self.idle_elapsed >= self.inactivity_budget {
                    self.idle_elapsed = std::time::Duration::ZERO;
                    // Window elapsed with no frame: the inactivity clock fires.
                    Ok(Some(self.inactivity_timeout_event(
                        run_id,
                        "inactivity_budget_exhausted",
                    )))
                } else {
                    Ok(None)
                }
            }
            // The stream closed with no terminal: same backstop, distinct reason.
            Err(CodexAppServerError::Timeout(_)) => {
                Ok(Some(self.inactivity_timeout_event(run_id, "stream_closed")))
            }
            Err(error) => Err(self.map_error("codex_event_read_failed", error)),
        }
    }

    fn cancel_turn(
        &mut self,
        cancellation: NativeProviderCancellation,
    ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
        if !CancellationDepth::NativeStop.allows(cancellation.requested_depth) {
            return Err(self.boundary_error(
                "unsupported_cancellation_depth",
                format!(
                    "Codex app-server cannot satisfy `{}` cancellation",
                    cancellation.requested_depth.as_str()
                ),
                false,
                json!({"requested_depth": cancellation.requested_depth.as_str()}),
            ));
        }
        let thread_id = cancellation
            .provider_session_id
            .clone()
            .or_else(|| self.thread_id.clone())
            .ok_or_else(|| {
                self.boundary_error(
                    "codex_cancel_thread_missing",
                    "Codex cancellation requires a thread id",
                    false,
                    json!({"run_id": cancellation.run_id}),
                )
            })?;
        let turn_id = cancellation
            .provider_turn_id
            .clone()
            .or_else(|| self.turn_id.clone())
            .ok_or_else(|| {
                self.boundary_error(
                    "codex_cancel_turn_missing",
                    "Codex cancellation requires a turn id",
                    false,
                    json!({"run_id": cancellation.run_id}),
                )
            })?;
        // Bound the interrupt RPC by the inactivity budget (DR-0035 Decision 4),
        // exactly like the turn-start RPCs: a wedged-but-alive app-server that
        // never answers `turn/interrupt` must not pin the worker thread forever
        // and defeat cancellation. On timeout, synthesize a refused-cancel
        // diagnostic (acknowledged=false) so the driver records it and keeps
        // draining toward the inactivity backstop instead of blocking.
        let interrupt = self.client.request_timeout(
            "turn/interrupt",
            json!({
                "threadId": thread_id,
                "turnId": turn_id,
            }),
            self.inactivity_budget,
        );
        let (acknowledged, interrupt_result_shape) = match interrupt {
            Ok(result) => (true, json_shape(&result)),
            Err(CodexAppServerError::Timeout(message)) => {
                (false, json_shape(&json!({ "timeout": message })))
            }
            Err(error) => return Err(self.map_error("codex_interrupt_failed", error)),
        };

        Ok(NativeProviderEvent {
            provider_id: self.provider_id.clone(),
            run_id: cancellation.run_id,
            event_kind: NativeProviderEventKind::Diagnostic,
            provider_event_type: "turn/interrupt".to_owned(),
            provider_session_id: Some(thread_id),
            provider_turn_id: Some(turn_id),
            sequence: Some(self.next_sequence()),
            evidence: json!({
                "acknowledged": acknowledged,
                "requested_depth": cancellation.requested_depth.as_str(),
                "reason_shape": json_shape(&Value::String(cancellation.reason)),
                "interrupt_result_shape": interrupt_result_shape,
            }),
            artifacts: vec![],
        })
    }
}

pub fn summarize_codex_app_server_evidence(
    server_requests: &[Value],
    notifications: &[Value],
) -> Value {
    let approval_requests = server_requests
        .iter()
        .filter(|message| {
            message
                .get("method")
                .and_then(Value::as_str)
                .is_some_and(|method| method.contains("/requestApproval"))
        })
        .map(summarize_approval_request)
        .collect::<Vec<_>>();
    let tool_requests = server_requests
        .iter()
        .filter(|message| {
            matches!(
                message.get("method").and_then(Value::as_str),
                Some("item/tool/call" | "item/tool/requestUserInput")
            )
        })
        .map(summarize_tool_request)
        .collect::<Vec<_>>();
    let diff_notifications = notifications
        .iter()
        .filter(|message| {
            matches!(
                message.get("method").and_then(Value::as_str),
                Some("turn/diff/updated" | "item/fileChange/patchUpdated")
            )
        })
        .map(summarize_diff_notification)
        .collect::<Vec<_>>();
    let item_notifications = notifications
        .iter()
        .filter(|message| {
            matches!(
                message.get("method").and_then(Value::as_str),
                Some("item/started" | "item/completed")
            )
        })
        .map(summarize_item_notification)
        .collect::<Vec<_>>();
    json!({
        "approvalRequests": approval_requests,
        "toolRequests": tool_requests,
        "diffNotifications": diff_notifications,
        "itemNotifications": item_notifications,
    })
}

fn codex_thread_start_params(
    request: &NativeProviderTurnRequest,
    policy: &CodexAppServerPolicy,
) -> Value {
    let mut params = serde_json::Map::new();
    if let Some(cwd) = request.provider_options.get("cwd").and_then(Value::as_str) {
        params.insert("cwd".to_owned(), json!(cwd));
    }
    if let Some(model) = request
        .provider_options
        .get("model")
        .and_then(Value::as_str)
    {
        params.insert("model".to_owned(), json!(model));
    }
    params.insert("sandbox".to_owned(), json!(policy.sandbox_mode));
    params.insert("approvalPolicy".to_owned(), json!(policy.approval_policy));
    params.insert("ephemeral".to_owned(), json!(true));
    params.insert("sessionStartSource".to_owned(), json!("startup"));
    Value::Object(params)
}

fn codex_turn_start_params(
    request: &NativeProviderTurnRequest,
    policy: &CodexAppServerPolicy,
    thread_id: &str,
) -> Value {
    let mut params = serde_json::Map::new();
    params.insert("threadId".to_owned(), json!(thread_id));
    params.insert(
        "input".to_owned(),
        codex_input_from_prompt(&request.prompt_json),
    );
    if let Some(cwd) = request.provider_options.get("cwd").and_then(Value::as_str) {
        params.insert("cwd".to_owned(), json!(cwd));
    }
    if let Some(model) = request
        .provider_options
        .get("model")
        .and_then(Value::as_str)
    {
        params.insert("model".to_owned(), json!(model));
    }
    params.insert("approvalPolicy".to_owned(), json!(policy.approval_policy));
    params.insert(
        "sandboxPolicy".to_owned(),
        json!({
            "type": if policy.sandbox_mode == "read-only" {
                "readOnly"
            } else {
                "workspaceWrite"
            },
            "networkAccess": false,
        }),
    );
    Value::Object(params)
}

fn codex_input_from_prompt(prompt: &Value) -> Value {
    if let Some(input) = prompt.get("input").and_then(Value::as_array) {
        return Value::Array(input.clone());
    }
    if let Some(text) = prompt.as_str() {
        return json!([{ "type": "text", "text": text }]);
    }
    json!([{ "type": "text", "text": prompt.to_string() }])
}

fn native_event_kind(kind: AgentTurnLifecycleKind) -> NativeProviderEventKind {
    match kind {
        AgentTurnLifecycleKind::Started => NativeProviderEventKind::Started,
        AgentTurnLifecycleKind::Streamed => NativeProviderEventKind::Streamed,
        AgentTurnLifecycleKind::ToolRequested => NativeProviderEventKind::ToolRequested,
        AgentTurnLifecycleKind::ArtifactCaptured => NativeProviderEventKind::ArtifactCaptured,
        AgentTurnLifecycleKind::Completed => NativeProviderEventKind::Completed,
        AgentTurnLifecycleKind::Failed => NativeProviderEventKind::Failed,
        AgentTurnLifecycleKind::TimedOut => NativeProviderEventKind::TimedOut,
        AgentTurnLifecycleKind::Cancelled => NativeProviderEventKind::Cancelled,
    }
}

fn artifact_refs_from_codex_message(message: &Value) -> Vec<NativeProviderArtifactRef> {
    let Some(method) = message.get("method").and_then(Value::as_str) else {
        return vec![];
    };
    if !matches!(method, "turn/diff/updated" | "item/fileChange/patchUpdated") {
        return vec![];
    }
    let params = message.get("params").unwrap_or(&Value::Null);
    summarize_changed_files(params)
        .into_iter()
        .filter_map(|file| {
            file.get("path")
                .and_then(Value::as_str)
                .map(|path| NativeProviderArtifactRef {
                    artifact_id: params
                        .get("itemId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    kind: "diff".to_owned(),
                    uri: format!("codex-diff://{path}"),
                    content_hash: None,
                    mime_type: Some("text/x-diff".to_owned()),
                    required: false,
                })
        })
        .collect()
}

fn summarize_approval_request(message: &Value) -> Value {
    let params = message.get("params").unwrap_or(&Value::Null);
    json!({
        "method": message.get("method").and_then(Value::as_str),
        "requestIdType": request_id_type(message.get("id")),
        "threadId": params.get("threadId").and_then(Value::as_str),
        "turnId": params.get("turnId").and_then(Value::as_str),
        "itemId": params.get("itemId").and_then(Value::as_str),
        "approvalId": params.get("approvalId").and_then(Value::as_str),
        "hasReason": params.get("reason").and_then(Value::as_str).is_some_and(|reason| !reason.is_empty()),
        "commandBytes": params.get("command").and_then(Value::as_str).map(str::len),
    })
}

fn summarize_tool_request(message: &Value) -> Value {
    let params = message.get("params").unwrap_or(&Value::Null);
    json!({
        "method": message.get("method").and_then(Value::as_str),
        "requestIdType": request_id_type(message.get("id")),
        "threadId": params.get("threadId").and_then(Value::as_str),
        "turnId": params.get("turnId").and_then(Value::as_str),
        "callId": params.get("callId").and_then(Value::as_str),
        "tool": params.get("tool").and_then(Value::as_str),
        "argumentsShape": params.get("arguments").map(json_shape),
    })
}

fn summarize_diff_notification(message: &Value) -> Value {
    let params = message.get("params").unwrap_or(&Value::Null);
    json!({
        "method": message.get("method").and_then(Value::as_str),
        "threadId": params.get("threadId").and_then(Value::as_str),
        "turnId": params.get("turnId").and_then(Value::as_str),
        "itemId": params.get("itemId").and_then(Value::as_str),
        "diffBytes": params.get("diff").and_then(Value::as_str).map(str::len),
        "changesCount": params.get("changes").and_then(Value::as_array).map(Vec::len),
        "changedFiles": summarize_changed_files(params),
    })
}

fn summarize_changed_files(params: &Value) -> Vec<Value> {
    let mut paths = BTreeSet::new();
    for field in ["path", "filePath", "relativePath"] {
        if let Some(path) = params.get(field).and_then(Value::as_str) {
            if !path.is_empty() {
                paths.insert(path.to_owned());
            }
        }
    }
    for change in params
        .get("changes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for field in ["path", "filePath", "relativePath", "oldPath", "newPath"] {
            if let Some(path) = change.get(field).and_then(Value::as_str) {
                if !path.is_empty() {
                    paths.insert(path.to_owned());
                }
            }
        }
    }
    paths
        .into_iter()
        .map(|path| {
            json!({
                "path": path,
            })
        })
        .collect()
}

fn summarize_item_notification(message: &Value) -> Value {
    let params = message.get("params").unwrap_or(&Value::Null);
    let item = params.get("item").unwrap_or(&Value::Null);
    json!({
        "method": message.get("method").and_then(Value::as_str),
        "threadId": params.get("threadId").and_then(Value::as_str),
        "turnId": params.get("turnId").and_then(Value::as_str),
        "itemId": item
            .get("id")
            .or_else(|| params.get("itemId"))
            .and_then(Value::as_str),
        "itemType": item.get("type").and_then(Value::as_str),
        "status": item.get("status").and_then(Value::as_str),
    })
}

fn request_id_type(id: Option<&Value>) -> Option<&'static str> {
    match id {
        Some(Value::String(_)) => Some("string"),
        Some(Value::Number(_)) => Some("number"),
        Some(Value::Null) => Some("null"),
        Some(Value::Bool(_)) => Some("bool"),
        Some(Value::Array(_)) => Some("array"),
        Some(Value::Object(_)) => Some("object"),
        None => None,
    }
}

fn json_shape(value: &Value) -> Value {
    match value {
        Value::Null => json!({ "type": "null" }),
        Value::Bool(_) => json!({ "type": "bool" }),
        Value::Number(_) => json!({ "type": "number" }),
        Value::String(value) => json!({ "type": "string", "chars": value.chars().count() }),
        Value::Array(items) => json!({ "type": "array", "items": items.len() }),
        Value::Object(object) => json!({ "type": "object", "keys": object.len() }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use whipplescript_kernel::provider::NativeProviderAdapter;

    #[derive(Default)]
    struct FakeTransport {
        writes: Vec<String>,
        reads: VecDeque<Result<String, String>>,
    }

    impl FakeTransport {
        fn with_reads(reads: &[&str]) -> Self {
            Self {
                writes: Vec::new(),
                reads: reads.iter().map(|line| Ok((*line).to_owned())).collect(),
            }
        }
    }

    fn codex_capability() -> ProviderCapability {
        super::capability()
    }

    #[test]
    fn normalizes_codex_started_diff_tool_and_cancelled_terminal() {
        let started = normalize_codex_app_server_event(&json!({
            "method": "turn/started",
            "params": {"threadId": "thread-1", "turnId": "turn-1"},
        }))
        .expect("started normalizes");
        assert_eq!(started.kind, AgentTurnLifecycleKind::Started);
        assert_eq!(started.provider_session_id.as_deref(), Some("thread-1"));
        assert_eq!(started.provider_turn_id.as_deref(), Some("turn-1"));

        let diff = normalize_codex_app_server_event(&json!({
            "method": "turn/diff/updated",
            "params": {"diff": "secret diff"},
        }))
        .expect("diff normalizes");
        assert_eq!(diff.kind, AgentTurnLifecycleKind::ArtifactCaptured);
        assert!(!diff
            .provider_payload_shape
            .to_string()
            .contains("secret diff"));

        let tool = normalize_codex_app_server_event(&json!({
            "method": "item/commandExecution/requestApproval",
            "params": {"command": "cat secret.txt"},
        }))
        .expect("tool normalizes");
        assert_eq!(tool.kind, AgentTurnLifecycleKind::ToolRequested);

        let terminal = normalize_codex_app_server_event(&json!({
            "method": "turn/completed",
            "params": {"status": "interrupted"},
        }))
        .expect("terminal normalizes");
        assert_eq!(terminal.kind, AgentTurnLifecycleKind::Cancelled);
        assert!(terminal.terminal);
    }

    #[test]
    fn capability_matches_the_registered_surface() {
        let capability = super::capability();
        assert_eq!(capability.provider_kind, super::PROVIDER_KIND);
        assert_eq!(capability.surface, super::SURFACE);
    }

    fn native_codex_request() -> NativeProviderTurnRequest {
        NativeProviderTurnRequest {
            provider_id: "codex-main".to_owned(),
            provider_kind: "codex".to_owned(),
            surface: "codex_app_server".to_owned(),
            run_id: "run-1".to_owned(),
            effect_id: "effect-1".to_owned(),
            agent: "codex".to_owned(),
            profile: Some("repo-writer".to_owned()),
            prompt_json: json!("edit README"),
            workspace_policy: "per_effect_worktree".to_owned(),
            required_capabilities: vec!["repo.write".to_owned()],
            cancellation_depth: CancellationDepth::NativeStop,
            artifact_policy: "manifest".to_owned(),
            credential_ref: Some("secret:codex".to_owned()),
            provider_options: BTreeMap::from([
                ("approval_mode".to_owned(), json!("manual")),
                ("cwd".to_owned(), json!("/workspace/effect-1")),
                ("model".to_owned(), json!("gpt-5.4-mini")),
            ]),
        }
    }

    impl CodexAppServerTransport for FakeTransport {
        fn write_line(&mut self, line: &str) -> Result<(), CodexAppServerError> {
            self.writes.push(line.to_owned());
            Ok(())
        }

        fn read_line(&mut self) -> Result<String, CodexAppServerError> {
            match self.reads.pop_front() {
                Some(Ok(line)) => Ok(line),
                Some(Err(message)) => Err(CodexAppServerError::Timeout(message)),
                None => Err(CodexAppServerError::Timeout("fake timeout".to_owned())),
            }
        }
    }

    #[test]
    fn client_sends_request_and_returns_matching_response() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{"threadId":"thr_1"}}"#,
        ]);
        let mut client = CodexAppServerClient::new(transport);

        let result = client
            .request("thread/start", json!({"workspace":"/tmp/ws"}))
            .expect("request succeeds");

        assert_eq!(
            result.get("threadId").and_then(Value::as_str),
            Some("thr_1")
        );
        let transport = client.into_transport();
        let request: Value = serde_json::from_str(&transport.writes[0]).expect("request json");
        assert_eq!(
            request.get("method").and_then(Value::as_str),
            Some("thread/start")
        );
        assert_eq!(request.get("id").and_then(Value::as_u64), Some(1));
        assert_eq!(
            request.pointer("/params/workspace").and_then(Value::as_str),
            Some("/tmp/ws")
        );
    }

    #[test]
    fn client_queues_notifications_before_matching_response() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","method":"turn/started","params":{"turnId":"turn_1"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"turnId":"turn_1"}}"#,
        ]);
        let mut client = CodexAppServerClient::new(transport);

        let result = client
            .request("turn/start", json!({"threadId":"thr_1"}))
            .expect("request succeeds");

        assert_eq!(result.get("turnId").and_then(Value::as_str), Some("turn_1"));
        let notification = client.pop_notification().expect("notification queued");
        assert_eq!(
            notification.get("method").and_then(Value::as_str),
            Some("turn/started")
        );
    }

    #[test]
    fn client_queues_server_requests_before_matching_response() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":"approval_1","method":"item/fileChange/requestApproval","params":{"itemId":"item_1"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":{"turnId":"turn_1"}}"#,
        ]);
        let mut client = CodexAppServerClient::new(transport);

        let result = client
            .request("turn/start", json!({"threadId":"thr_1"}))
            .expect("request succeeds");

        assert_eq!(result.get("turnId").and_then(Value::as_str), Some("turn_1"));
        let server_request = client.pop_server_request().expect("server request queued");
        assert_eq!(
            server_request.get("method").and_then(Value::as_str),
            Some("item/fileChange/requestApproval")
        );
    }

    #[test]
    fn client_sends_server_request_response() {
        let transport = FakeTransport::default();
        let mut client = CodexAppServerClient::new(transport);

        client
            .respond(json!("approval_1"), json!({"decision":"denied"}))
            .expect("response writes");

        let transport = client.into_transport();
        let response: Value = serde_json::from_str(&transport.writes[0]).expect("response json");
        assert_eq!(
            response.get("id").and_then(Value::as_str),
            Some("approval_1")
        );
        assert_eq!(
            response.pointer("/result/decision").and_then(Value::as_str),
            Some("denied")
        );
    }

    #[test]
    fn client_sends_server_request_error_response() {
        let transport = FakeTransport::default();
        let mut client = CodexAppServerClient::new(transport);

        client
            .respond_error(json!("request_1"), "unsupported request")
            .expect("error response writes");

        let transport = client.into_transport();
        let response: Value = serde_json::from_str(&transport.writes[0]).expect("response json");
        assert_eq!(
            response.get("id").and_then(Value::as_str),
            Some("request_1")
        );
        assert_eq!(
            response.pointer("/error/code").and_then(Value::as_i64),
            Some(-32000)
        );
    }

    #[test]
    fn client_reports_malformed_response() {
        let transport = FakeTransport::with_reads(&["not-json"]);
        let mut client = CodexAppServerClient::new(transport);

        let error = client
            .request("thread/start", json!({}))
            .expect_err("malformed response fails");

        assert!(matches!(error, CodexAppServerError::Json(_)));
    }

    #[test]
    fn client_reports_remote_error_response() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unknown method"}}"#,
        ]);
        let mut client = CodexAppServerClient::new(transport);

        let error = client
            .request("thread/start", json!({}))
            .expect_err("remote error fails");

        assert!(
            matches!(error, CodexAppServerError::Remote(error) if error.get("code").and_then(Value::as_i64) == Some(-32601))
        );
    }

    #[test]
    fn client_reports_transport_timeout() {
        let transport = FakeTransport::default();
        let mut client = CodexAppServerClient::new(transport);

        let error = client
            .request("thread/start", json!({}))
            .expect_err("timeout fails");

        assert!(matches!(error, CodexAppServerError::Timeout(_)));
    }

    #[test]
    fn policy_maps_reader_profile_to_read_only_never_approval() {
        let policy = build_codex_app_server_policy(
            Some("repo-reader"),
            &["repo.read".to_owned()],
            "read_only",
            None,
        )
        .expect("reader policy maps");

        assert_eq!(policy.sandbox_mode, "read-only");
        assert_eq!(policy.approval_policy, "never");
        assert_eq!(
            policy.to_config_args(),
            vec![
                "-c",
                "sandbox_mode=\"read-only\"",
                "-c",
                "approval_policy=\"never\""
            ]
        );
    }

    #[test]
    fn policy_maps_writer_profile_to_workspace_write_with_approval() {
        let policy = build_codex_app_server_policy(
            Some("repo-writer"),
            &["repo.write".to_owned(), "command.run".to_owned()],
            "per_effect_worktree",
            Some("manual"),
        )
        .expect("writer policy maps");

        assert_eq!(policy.sandbox_mode, "workspace-write");
        assert_eq!(policy.approval_policy, "on-request");
        assert_eq!(
            policy.required_capabilities,
            vec!["command.run".to_owned(), "repo.write".to_owned()]
        );
    }

    #[test]
    fn policy_rejects_forbidden_tool_for_reader_profile() {
        let error = build_codex_app_server_policy(
            Some("repo-reader"),
            &["repo.write".to_owned()],
            "shared",
            Some("manual"),
        )
        .expect_err("reader write denied");

        assert_eq!(error.code, "profile_denied");
    }

    #[test]
    fn policy_rejects_destructive_tool_without_approval() {
        let error = build_codex_app_server_policy(
            Some("repo-writer"),
            &["command.run".to_owned()],
            "shared",
            None,
        )
        .expect_err("approval required");

        assert_eq!(error.code, "missing_approval");
    }

    #[test]
    fn policy_rejects_write_in_read_only_workspace() {
        let error = build_codex_app_server_policy(
            Some("repo-writer"),
            &["repo.write".to_owned()],
            "read_only",
            Some("manual"),
        )
        .expect_err("read only workspace denied");

        assert_eq!(error.code, "workspace_denied");
    }

    #[test]
    fn policy_rejects_unsupported_workspace_policy() {
        let error = build_codex_app_server_policy(
            Some("repo-writer"),
            &["repo.write".to_owned()],
            "remote_sandbox",
            Some("manual"),
        )
        .expect_err("remote sandbox requires explicit workspace implementation");

        assert_eq!(error.code, "unsupported_workspace_policy");
    }

    #[test]
    fn policy_rejects_missing_profile() {
        let error = build_codex_app_server_policy(None, &["repo.read".to_owned()], "shared", None)
            .expect_err("profile required");

        assert_eq!(error.code, "missing_profile");
    }

    #[test]
    fn evidence_summary_redacts_approval_tool_and_diff_details() {
        let server_requests = vec![
            json!({
                "jsonrpc": "2.0",
                "id": "approval_1",
                "method": "item/commandExecution/requestApproval",
                "params": {
                    "threadId": "thr_1",
                    "turnId": "turn_1",
                    "itemId": "item_1",
                    "command": "cat secret.txt",
                    "reason": "needs a command",
                },
            }),
            json!({
                "jsonrpc": "2.0",
                "id": "tool_1",
                "method": "item/tool/call",
                "params": {
                    "threadId": "thr_1",
                    "turnId": "turn_1",
                    "callId": "call_1",
                    "tool": "lookup",
                    "arguments": {"token": "secret-token"},
                },
            }),
        ];
        let notifications = vec![
            json!({
                "jsonrpc": "2.0",
                "method": "turn/diff/updated",
                "params": {
                    "threadId": "thr_1",
                    "turnId": "turn_1",
                    "diff": "diff --git a/secret.txt b/secret.txt\n+secret",
                    "changes": [
                        {"path": "secret.txt"},
                        {"oldPath": "old.txt", "newPath": "new.txt"}
                    ],
                },
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "item/completed",
                "params": {
                    "threadId": "thr_1",
                    "turnId": "turn_1",
                    "item": {
                        "id": "item_2",
                        "type": "fileChange",
                        "status": "completed",
                    },
                },
            }),
        ];

        let summary = summarize_codex_app_server_evidence(&server_requests, &notifications);
        let summary_json = summary.to_string();

        assert_eq!(
            summary
                .pointer("/approvalRequests/0/commandBytes")
                .and_then(Value::as_u64),
            Some("cat secret.txt".len() as u64)
        );
        assert_eq!(
            summary
                .pointer("/toolRequests/0/argumentsShape/type")
                .and_then(Value::as_str),
            Some("object")
        );
        assert_eq!(
            summary
                .pointer("/diffNotifications/0/diffBytes")
                .and_then(Value::as_u64),
            Some("diff --git a/secret.txt b/secret.txt\n+secret".len() as u64)
        );
        assert_eq!(
            summary
                .pointer("/diffNotifications/0/changedFiles")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(3)
        );
        assert_eq!(
            summary
                .pointer("/diffNotifications/0/changedFiles/0/path")
                .and_then(Value::as_str),
            Some("new.txt")
        );
        assert_eq!(
            summary
                .pointer("/itemNotifications/0/itemType")
                .and_then(Value::as_str),
            Some("fileChange")
        );
        assert!(!summary_json.contains("cat secret.txt"));
        assert!(!summary_json.contains("secret-token"));
        assert!(!summary_json.contains("diff --git"));
    }

    #[test]
    fn native_adapter_starts_codex_thread_and_turn_with_policy_payloads() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{"userAgent":"codex-test"}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1"}}}"#,
        ]);
        let client = CodexAppServerClient::new(transport);
        let mut adapter = CodexAppServerAdapter::new("codex-main", codex_capability(), client);

        let event = adapter
            .start_turn(native_codex_request())
            .expect("turn starts");

        assert_eq!(event.event_kind, NativeProviderEventKind::Started);
        assert_eq!(event.provider_session_id.as_deref(), Some("thread-1"));
        assert_eq!(event.provider_turn_id.as_deref(), Some("turn-1"));
        // The consumed initialize reply rides the started event as a shape
        // (DR-0035 Decision 7) — advertised info recorded, content dropped.
        assert_eq!(
            event
                .evidence
                .pointer("/initialize_result_shape/type")
                .and_then(Value::as_str),
            Some("object")
        );
        assert!(!event.evidence.to_string().contains("codex-test"));

        let transport = adapter.into_client().into_transport();
        let initialize: Value =
            serde_json::from_str(&transport.writes[0]).expect("initialize json");
        let thread_start: Value =
            serde_json::from_str(&transport.writes[1]).expect("thread/start json");
        let turn_start: Value =
            serde_json::from_str(&transport.writes[2]).expect("turn/start json");

        assert_eq!(
            initialize.get("method").and_then(Value::as_str),
            Some("initialize")
        );
        assert_eq!(
            thread_start.get("method").and_then(Value::as_str),
            Some("thread/start")
        );
        assert_eq!(
            thread_start
                .pointer("/params/approvalPolicy")
                .and_then(Value::as_str),
            Some("on-request")
        );
        assert_eq!(
            turn_start.get("method").and_then(Value::as_str),
            Some("turn/start")
        );
        assert_eq!(
            turn_start
                .pointer("/params/input/0/text")
                .and_then(Value::as_str),
            Some("edit README")
        );
        assert_eq!(
            turn_start
                .pointer("/params/sandboxPolicy/type")
                .and_then(Value::as_str),
            Some("workspaceWrite")
        );
    }

    #[test]
    fn native_adapter_maps_codex_remote_start_error_without_raw_message() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32042,"message":"remote token sk-never-print leaked"}}"#,
        ]);
        let client = CodexAppServerClient::new(transport);
        let mut adapter = CodexAppServerAdapter::new("codex-main", codex_capability(), client);

        let error = adapter
            .start_turn(native_codex_request())
            .expect_err("remote thread/start error is mapped");

        assert_eq!(error.code, "codex_thread_start_failed");
        assert!(error.recoverable);
        assert_eq!(
            error.evidence.get("kind").and_then(Value::as_str),
            Some("remote")
        );
        assert_eq!(
            error.evidence.get("code").and_then(Value::as_i64),
            Some(-32042)
        );
        let redacted = error.to_json_redacted();
        assert_eq!(
            redacted.pointer("/surface").and_then(Value::as_str),
            Some("codex_app_server")
        );
        assert_eq!(
            redacted
                .pointer("/evidence_shape/type")
                .and_then(Value::as_str),
            Some("object")
        );
        let redacted_json = redacted.to_string();
        assert!(!redacted_json.contains("sk-never-print"));
        assert!(!redacted_json.contains("remote token"));
    }

    #[test]
    fn native_adapter_streams_codex_notifications_and_diff_artifacts() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"turn/diff/updated","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","diff":"secret diff","changes":[{"path":"src/lib.rs"}]}}"#,
            r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turnId":"turn-1","turn":{"id":"turn-1","status":"completed"}}}"#,
        ]);
        let client = CodexAppServerClient::new(transport);
        let mut adapter = CodexAppServerAdapter::new("codex-main", codex_capability(), client);
        adapter
            .start_turn(native_codex_request())
            .expect("turn starts");

        let diff = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("diff event");
        assert_eq!(diff.event_kind, NativeProviderEventKind::ArtifactCaptured);
        assert_eq!(diff.artifacts.len(), 1);
        assert_eq!(diff.artifacts[0].uri, "codex-diff://src/lib.rs");
        assert!(!diff.to_json_redacted().to_string().contains("secret diff"));

        let completed = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("terminal event");
        assert_eq!(completed.event_kind, NativeProviderEventKind::Completed);
        assert!(completed.event_kind.is_terminal());
    }

    #[test]
    fn native_adapter_surfaces_codex_usage_limit_error_on_failed_turn() {
        // Real shape from codex-cli 0.137.0: a failed turn carries the
        // control-plane reason under `params.turn.error.message`.
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1"}}}"#,
            r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-1","status":"failed","error":{"codexErrorInfo":"usageLimitExceeded","message":"You've hit your usage limit. Try again at 6:09 PM."}}}}"#,
        ]);
        let client = CodexAppServerClient::new(transport);
        let mut adapter = CodexAppServerAdapter::new("codex-main", codex_capability(), client);
        adapter
            .start_turn(native_codex_request())
            .expect("turn starts");

        let failed = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("terminal event");
        assert_eq!(failed.event_kind, NativeProviderEventKind::Failed);
        assert!(failed.event_kind.is_terminal());
        // The provider error reason crosses the redaction boundary (operational,
        // not model output) and is surfaced for the failure diagnostic.
        assert_eq!(
            failed.redacted_provider_error().as_str(),
            Some("You've hit your usage limit. Try again at 6:09 PM.")
        );
        assert!(failed
            .to_json_redacted()
            .to_string()
            .contains("usage limit"));
    }

    #[test]
    fn native_adapter_answers_codex_approval_requests_and_records_tool_event() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":"approval-1","method":"item/commandExecution/requestApproval","params":{"threadId":"thread-1","turnId":"turn-1","itemId":"item-1","command":"cat secret.txt","reason":"needs command"}}"#,
            r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turnId":"turn-1","turn":{"id":"turn-1","status":"completed"}}}"#,
        ]);
        let client = CodexAppServerClient::new(transport);
        let mut adapter = CodexAppServerAdapter::new("codex-main", codex_capability(), client);
        adapter
            .start_turn(native_codex_request())
            .expect("turn starts");

        let approval = adapter
            .next_event("run-1")
            .expect("approval reads")
            .expect("approval event");
        assert_eq!(approval.event_kind, NativeProviderEventKind::ToolRequested);
        assert_eq!(
            approval.provider_event_type,
            "item/commandExecution/requestApproval"
        );
        assert!(!approval
            .to_json_redacted()
            .to_string()
            .contains("secret.txt"));

        let completed = adapter
            .next_event("run-1")
            .expect("terminal reads")
            .expect("terminal event");
        assert_eq!(completed.event_kind, NativeProviderEventKind::Completed);

        let transport = adapter.into_client().into_transport();
        let response: Value =
            serde_json::from_str(&transport.writes[3]).expect("approval response json");
        assert_eq!(
            response.get("id").and_then(Value::as_str),
            Some("approval-1")
        );
        assert_eq!(
            response.pointer("/result/decision").and_then(Value::as_str),
            Some("decline")
        );
    }

    #[test]
    fn native_adapter_interrupt_is_acknowledgement_not_terminal_completion() {
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":4,"result":{"ok":true}}"#,
            r#"{"jsonrpc":"2.0","method":"turn/completed","params":{"threadId":"thread-1","turnId":"turn-1","turn":{"id":"turn-1","status":"interrupted"}}}"#,
        ]);
        let client = CodexAppServerClient::new(transport);
        let mut adapter = CodexAppServerAdapter::new("codex-main", codex_capability(), client);
        adapter
            .start_turn(native_codex_request())
            .expect("turn starts");

        let ack = adapter
            .cancel_turn(NativeProviderCancellation {
                run_id: "run-1".to_owned(),
                provider_session_id: None,
                provider_turn_id: None,
                requested_depth: CancellationDepth::NativeStop,
                reason: "revision changed".to_owned(),
            })
            .expect("interrupt acknowledged");
        assert_eq!(ack.event_kind, NativeProviderEventKind::Diagnostic);
        assert!(!ack.event_kind.is_terminal());

        let terminal = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("terminal event");
        assert_eq!(terminal.event_kind, NativeProviderEventKind::Cancelled);
        assert!(terminal.event_kind.is_terminal());

        let transport = adapter.into_client().into_transport();
        let interrupt: Value =
            serde_json::from_str(&transport.writes[3]).expect("interrupt request json");
        assert_eq!(
            interrupt.get("method").and_then(Value::as_str),
            Some("turn/interrupt")
        );
        assert_eq!(
            interrupt
                .pointer("/params/threadId")
                .and_then(Value::as_str),
            Some("thread-1")
        );
    }

    #[test]
    fn native_adapter_interrupt_that_never_answers_is_a_refused_cancel_not_a_hang() {
        // Only the three start RPCs answer; `turn/interrupt` gets no reply, so
        // the bounded read times out. cancel_turn must return a refused-cancel
        // diagnostic (acknowledged=false), NOT block forever or hard-error —
        // otherwise a wedged-but-alive app-server pins the worker thread and
        // defeats cancellation (ultracode #15).
        let transport = FakeTransport::with_reads(&[
            r#"{"jsonrpc":"2.0","id":1,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":2,"result":{"thread":{"id":"thread-1"}}}"#,
            r#"{"jsonrpc":"2.0","id":3,"result":{"turn":{"id":"turn-1"}}}"#,
        ]);
        let client = CodexAppServerClient::new(transport);
        let mut adapter = CodexAppServerAdapter::new("codex-main", codex_capability(), client)
            .with_inactivity_budget(std::time::Duration::from_millis(1));
        adapter
            .start_turn(native_codex_request())
            .expect("turn starts");

        let ack = adapter
            .cancel_turn(NativeProviderCancellation {
                run_id: "run-1".to_owned(),
                provider_session_id: None,
                provider_turn_id: None,
                requested_depth: CancellationDepth::NativeStop,
                reason: "revision changed".to_owned(),
            })
            .expect("a timed-out interrupt is still an Ok diagnostic, not an error");
        assert_eq!(ack.event_kind, NativeProviderEventKind::Diagnostic);
        assert!(!ack.event_kind.is_terminal());
        assert_eq!(
            ack.evidence.get("acknowledged").and_then(Value::as_bool),
            Some(false),
            "an unanswered interrupt is recorded as a refused cancel: {}",
            ack.evidence
        );
    }
}
