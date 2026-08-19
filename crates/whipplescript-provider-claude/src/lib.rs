//! Claude Agent SDK sidecar provider adapter for WhippleScript.
//!
//! An external, opt-in provider crate (DR-0024 provider-crate split): the kernel
//! has no compile-time knowledge of Claude. This crate owns the Claude sidecar
//! protocol (JSONL transport, event normalization, `ClaudeSidecarEvent`, policy
//! mapping) and registers a [`ProviderCapability`] into whatever catalog the host
//! assembles via [`capability`]. It depends on `whipplescript-kernel` for the
//! shared provider vocabulary and the kernel-side redaction boundary.

use std::{
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
pub const PROVIDER_KIND: &str = "claude";
/// The adapter-surface identifier this crate speaks.
pub const SURFACE: &str = "claude_agent_sdk";

/// The Claude capability entry. The host assembles this into the effective
/// provider catalog it passes to `validate_provider_binding` — the kernel does
/// not carry it (open registry).
pub fn capability() -> ProviderCapability {
    ProviderCapability {
        provider_kind: PROVIDER_KIND.to_owned(),
        surface: SURFACE.to_owned(),
        protocol_version: Some("anthropic-agent-sdk".to_owned()),
        session_identity_fields: vec!["session_id".to_owned()],
        stream_event_kinds: ["message", "tool_event", "hook_event", "result"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        tool_policy: "claude_tools_permissions_hooks".to_owned(),
        // DR-0017 ("Cancellation should remain conservative"): Claude interrupt
        // has never been live-validated, so the catalog advertises NO depth — a
        // binding requesting `cooperative_request` fails validation instead of
        // pretending.
        cancellation_depths: vec![CancellationDepth::None],
        artifact_manifest: true,
        health_checks: ["claude_sdk", "api_key", "tool_policy"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        auth_requirements: vec!["anthropic_api_key_or_provider_config_ref".to_owned()],
    }
}

/// Normalize a raw Claude sidecar event into the kernel's provider-agnostic
/// lifecycle observation (shape-only payload via the kernel's `payload_shape`
/// redaction). Moved out of the kernel with the adapter it belongs to (DR-0024).
pub fn normalize_claude_agent_sdk_event(
    event: &ClaudeSidecarEvent,
) -> Option<NativeAgentTurnObservation> {
    let kind = match event.event_type.as_str() {
        "claude.session.started" => AgentTurnLifecycleKind::Started,
        "claude.stream.message" => AgentTurnLifecycleKind::Streamed,
        "claude.tool.requested" | "claude.hook.event" => AgentTurnLifecycleKind::ToolRequested,
        "claude.artifact.captured" => AgentTurnLifecycleKind::ArtifactCaptured,
        "claude.turn.completed" => AgentTurnLifecycleKind::Completed,
        "claude.turn.failed" => AgentTurnLifecycleKind::Failed,
        "claude.turn.cancelled" => AgentTurnLifecycleKind::Cancelled,
        _ => return None,
    };
    Some(
        NativeAgentTurnObservation::new(kind, &event.event_type)
            .session_id(
                event
                    .payload
                    .get("session_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            )
            .turn_id(Some(event.run_id.clone()))
            .payload_shape(&event.payload)
            .provider_error(
                event
                    .payload
                    .pointer("/error/message")
                    .or_else(|| event.payload.get("error").filter(|e| e.is_string()))
                    .or_else(|| {
                        event
                            .payload
                            .get("message")
                            .filter(|_| event.event_type == "claude.turn.failed")
                    })
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            ),
    )
}

#[derive(Debug)]
pub enum ClaudeAgentSdkError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Protocol(String),
    Remote(Value),
    Timeout(String),
}

impl From<std::io::Error> for ClaudeAgentSdkError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ClaudeAgentSdkError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeSidecarEvent {
    pub event_type: String,
    pub run_id: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeAgentToolPolicy {
    pub allowed_tools: Vec<String>,
    pub disallowed_tools: Vec<String>,
    pub permission_mode: String,
    /// Ambient-config sources the delegate may read (DR-0034 Decision 4). `None`
    /// means the provider's own default — the key is omitted from the sidecar
    /// payload so the SDK applies its native behavior. `Some(vec![])` is the
    /// explicit `settings none` opt-out.
    pub setting_sources: Option<Vec<String>>,
    pub mcp_config_ref: Option<String>,
}

impl ClaudeAgentToolPolicy {
    pub fn to_sidecar_json(&self) -> Value {
        let mut value = json!({
            "allowed_tools": self.allowed_tools,
            "disallowed_tools": self.disallowed_tools,
            "permission_mode": self.permission_mode,
            "mcp_config_ref": self.mcp_config_ref,
        });
        if let Some(sources) = &self.setting_sources {
            value["setting_sources"] = json!(sources);
        }
        value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaudeAgentPolicyError {
    pub code: String,
    pub message: String,
}

pub fn build_claude_agent_tool_policy(
    profile: Option<&str>,
    required_capabilities: &[String],
    workspace_policy: &str,
    approval_mode: Option<&str>,
    mcp_config_ref: Option<&str>,
    settings: Option<&str>,
) -> Result<ClaudeAgentToolPolicy, ClaudeAgentPolicyError> {
    let Some(profile) = profile else {
        return Err(policy_error(
            "missing_profile",
            "Claude Agent SDK runs require a WhippleScript profile",
        ));
    };
    // The translation is COMPUTED from the std.agent profile table
    // (kernel/agent_profile.rs; spec/std-agent.md slice 4): the preset row
    // carries the base Claude tool set and the capability grants the preset
    // can truthfully expand to. A preset without a Claude translation — or a
    // name that is no preset at all — fails closed.
    let preset = whipplescript_kernel::agent_profile::agent_profile_preset(profile);
    let base_tools = preset.and_then(|preset| preset.claude_allowed_tools);
    let (Some(preset), Some(base_tools)) = (preset, base_tools) else {
        return Err(policy_error(
            "unsupported_profile",
            format!("profile `{profile}` is not mapped to a Claude tool policy"),
        ));
    };
    let mut allowed_tools = strings(base_tools);
    let mut needs_approval = false;
    for capability in required_capabilities {
        match capability.as_str() {
            "repo.read" | "agent.tell" => {}
            "repo.write" => {
                if !preset.grants_capability("repo.write") {
                    return Err(policy_error(
                        "profile_denied",
                        format!("profile `{profile}` cannot grant capability `repo.write`"),
                    ));
                }
                require_writable_workspace(workspace_policy, "repo.write")?;
                needs_approval = true;
                insert_unique(&mut allowed_tools, "Edit");
                insert_unique(&mut allowed_tools, "Write");
            }
            "command.run" => {
                if !preset.grants_capability("command.run") {
                    return Err(policy_error(
                        "profile_denied",
                        format!("profile `{profile}` cannot grant capability `command.run`"),
                    ));
                }
                require_writable_workspace(workspace_policy, "command.run")?;
                needs_approval = true;
                insert_unique(&mut allowed_tools, "Bash");
            }
            other => {
                return Err(policy_error(
                    "unsupported_capability",
                    format!("capability `{other}` is not mapped to a Claude tool policy"),
                ));
            }
        }
    }
    if needs_approval && approval_mode.is_none() {
        return Err(policy_error(
            "missing_approval",
            "destructive Claude tools require an explicit approval mode",
        ));
    }
    let disallowed_tools = ["Bash", "Edit", "Write"]
        .into_iter()
        .filter(|tool| !allowed_tools.iter().any(|allowed| allowed == tool))
        .map(str::to_owned)
        .collect();
    allowed_tools.sort();
    let permission_mode = match approval_mode {
        Some("auto") => "auto",
        Some("manual") => "default",
        Some("accept_edits") => "acceptEdits",
        Some(other) => {
            return Err(policy_error(
                "unsupported_approval_mode",
                format!("approval mode `{other}` is not supported for Claude"),
            ));
        }
        None => "default",
    }
    .to_owned();
    // DR-0034 Decision 4: the `settings` knob selects which ambient-config sources
    // the delegate may read. Unset means the provider default (None — no override),
    // NOT the crippled empty set. `none` is the explicit opt-out. The parser
    // validates the value; re-checking here keeps a raw provider_options bypass out.
    let setting_sources = match settings {
        None => None,
        Some("project") => Some(strings(&["project"])),
        Some("user") => Some(strings(&["user"])),
        Some("none") => Some(Vec::new()),
        Some(other) => {
            return Err(policy_error(
                "unsupported_settings_source",
                format!("settings source `{other}` is not supported for Claude"),
            ));
        }
    };
    Ok(ClaudeAgentToolPolicy {
        allowed_tools,
        disallowed_tools,
        permission_mode,
        setting_sources,
        mcp_config_ref: mcp_config_ref.map(str::to_owned),
    })
}

fn policy_error(code: impl Into<String>, message: impl Into<String>) -> ClaudeAgentPolicyError {
    ClaudeAgentPolicyError {
        code: code.into(),
        message: message.into(),
    }
}

fn require_writable_workspace(
    workspace_policy: &str,
    capability: &str,
) -> Result<(), ClaudeAgentPolicyError> {
    match workspace_policy {
        "shared" | "per_effect_worktree" | "per_issue_worktree" => Ok(()),
        "read_only" => Err(policy_error(
            "workspace_denied",
            format!("capability `{capability}` cannot run in a read-only workspace"),
        )),
        other => Err(policy_error(
            "unsupported_workspace_policy",
            format!("workspace policy `{other}` is not supported for Claude writes"),
        )),
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn insert_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|item| item == value) {
        values.push(value.to_owned());
    }
}

pub fn summarize_claude_agent_sdk_events(events: &[ClaudeSidecarEvent]) -> Value {
    let mut counts = serde_json::Map::new();
    let mut session_id = None;
    let mut terminal_type = None;
    let mut terminal_payload = Value::Null;
    for event in events {
        let count = counts
            .get(&event.event_type)
            .and_then(Value::as_u64)
            .unwrap_or(0)
            + 1;
        counts.insert(event.event_type.clone(), json!(count));
        if session_id.is_none() {
            session_id = event
                .payload
                .get("session_id")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        if matches!(
            event.event_type.as_str(),
            "claude.turn.completed" | "claude.turn.failed" | "claude.turn.cancelled"
        ) {
            terminal_type = Some(event.event_type.clone());
            terminal_payload = json!({
                "subtype": event.payload.get("subtype").and_then(Value::as_str),
                "result_shape": event.payload.get("result_shape"),
                "usage_shape": event.payload.get("usage_shape"),
                "error_shape": event.payload.get("error_shape"),
            });
        }
    }
    json!({
        "session_id": session_id,
        "event_counts": counts,
        "terminal_type": terminal_type,
        "terminal_payload": terminal_payload,
    })
}

pub trait ClaudeAgentSdkTransport {
    fn write_line(&mut self, line: &str) -> Result<(), ClaudeAgentSdkError>;
    fn read_line(&mut self) -> Result<String, ClaudeAgentSdkError>;
    /// Wait up to `wait` for the next line; `Ok(None)` means the window
    /// elapsed with the peer still alive (DR-0035 Decision 4 inactivity
    /// clock). The default keeps blocking semantics for transports without a
    /// clock (test fakes).
    fn read_line_timeout(
        &mut self,
        wait: std::time::Duration,
    ) -> Result<Option<String>, ClaudeAgentSdkError> {
        let _ = wait;
        self.read_line().map(Some)
    }
}

pub struct ClaudeAgentSdkClient<T> {
    transport: T,
    events: Vec<ClaudeSidecarEvent>,
}

impl<T: ClaudeAgentSdkTransport> ClaudeAgentSdkClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            events: Vec::new(),
        }
    }

    /// The `hello` handshake (DR-0035 Decision 7): returns the sidecar's
    /// protocol identifier, or `None` for a legacy sidecar that predates the
    /// verb (it answers `run/error unknown_command`; tolerated as `/1` for one
    /// release). Run before any turn so a mismatch blocks the binding rather
    /// than failing mid-turn.
    pub fn hello(&mut self) -> Result<Option<String>, ClaudeAgentSdkError> {
        self.transport
            .write_line(&json!({ "type": "hello" }).to_string())?;
        loop {
            // Bounded read: a sidecar that never answers the handshake is
            // treated as no-answer (liveness stays a start_turn concern), not
            // a construction hang.
            let Some(line) = self
                .transport
                .read_line_timeout(std::time::Duration::from_secs(10))?
            else {
                return Ok(None);
            };
            if line.trim().is_empty() {
                continue;
            }
            let message: Value = serde_json::from_str(&line)?;
            return match message.get("type").and_then(Value::as_str) {
                Some("hello") => Ok(message
                    .pointer("/payload/protocol")
                    .and_then(Value::as_str)
                    .map(str::to_owned)),
                Some("run/error")
                    if message.pointer("/payload/code").and_then(Value::as_str)
                        == Some("unknown_command") =>
                {
                    Ok(None)
                }
                _ => Err(ClaudeAgentSdkError::Protocol(
                    "unexpected reply to `hello` handshake".to_owned(),
                )),
            };
        }
    }

    pub fn start_run(
        &mut self,
        request: Value,
    ) -> Result<Vec<ClaudeSidecarEvent>, ClaudeAgentSdkError> {
        let run_id = request
            .get("run_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ClaudeAgentSdkError::Protocol("run/start missing `run_id`".to_owned()))?
            .to_owned();
        self.transport.write_line(
            &json!({
                "type": "run/start",
                "run_id": run_id,
                "protocol": WHIP_SIDECAR_PROTOCOL,
                "request": request,
            })
            .to_string(),
        )?;
        loop {
            let line = self.transport.read_line()?;
            if line.trim().is_empty() {
                continue;
            }
            let message: Value = serde_json::from_str(&line)?;
            match route_frame(message, &run_id)? {
                RoutedFrame::Event(event) | RoutedFrame::Misrouted(event) => {
                    let terminal = matches!(
                        event.event_type.as_str(),
                        "claude.turn.completed" | "claude.turn.failed" | "claude.turn.cancelled"
                    );
                    self.events.push(event);
                    if terminal {
                        return Ok(self.events.clone());
                    }
                }
            }
        }
    }

    pub fn begin_run(&mut self, request: Value) -> Result<String, ClaudeAgentSdkError> {
        let run_id = request
            .get("run_id")
            .and_then(Value::as_str)
            .ok_or_else(|| ClaudeAgentSdkError::Protocol("run/start missing `run_id`".to_owned()))?
            .to_owned();
        self.transport.write_line(
            &json!({
                "type": "run/start",
                "run_id": run_id,
                "protocol": WHIP_SIDECAR_PROTOCOL,
                "request": request,
            })
            .to_string(),
        )?;
        Ok(run_id)
    }

    pub fn read_event(
        &mut self,
        expected_run_id: &str,
    ) -> Result<ClaudeSidecarEvent, ClaudeAgentSdkError> {
        loop {
            let line = self.transport.read_line()?;
            if line.trim().is_empty() {
                continue;
            }
            let message: Value = serde_json::from_str(&line)?;
            return match route_frame(message, expected_run_id)? {
                RoutedFrame::Event(event) | RoutedFrame::Misrouted(event) => Ok(event),
            };
        }
    }

    /// `read_event` bounded by the inactivity clock: `Ok(None)` means the
    /// window elapsed without a frame (the peer is alive but silent).
    pub fn read_event_timeout(
        &mut self,
        expected_run_id: &str,
        wait: std::time::Duration,
    ) -> Result<Option<ClaudeSidecarEvent>, ClaudeAgentSdkError> {
        loop {
            let Some(line) = self.transport.read_line_timeout(wait)? else {
                return Ok(None);
            };
            if line.trim().is_empty() {
                continue;
            }
            let message: Value = serde_json::from_str(&line)?;
            return match route_frame(message, expected_run_id)? {
                RoutedFrame::Event(event) | RoutedFrame::Misrouted(event) => Ok(Some(event)),
            };
        }
    }

    pub fn cancel_run(&mut self, run_id: &str) -> Result<(), ClaudeAgentSdkError> {
        self.transport.write_line(
            &json!({
                "type": "run/cancel",
                "run_id": run_id,
            })
            .to_string(),
        )
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

/// The synthetic event type a misrouted frame surfaces as (DR-0035 Decision 3
/// T3). The kernel records `whip.protocol.*` events as protocol-violation
/// diagnostics, never as lifecycle events.
pub const MISROUTED_FRAME_EVENT_TYPE: &str = "whip.protocol.misrouted_frame";

/// The whip sidecar dialect version (DR-0035 Decision 7). Sent in `run/start`
/// and exchanged via the `hello` handshake; a mismatched sidecar blocks the
/// binding pre-turn (`provider_health`), never mid-turn.
pub const WHIP_SIDECAR_PROTOCOL: &str = "whip-sidecar/1";

enum RoutedFrame {
    Event(ClaudeSidecarEvent),
    Misrouted(ClaudeSidecarEvent),
}

/// DR-0035 Decision 3 T3 routing. A `run/error` with a null run id is a
/// channel-level sidecar failure and one with our run id is this run's error —
/// both surface as `Remote`. Any other frame whose run id does not match is
/// misrouted: it becomes a synthetic protocol-violation event (identifiers
/// only, no payload content) instead of aborting the turn.
fn route_frame(message: Value, expected_run_id: &str) -> Result<RoutedFrame, ClaudeAgentSdkError> {
    let frame_run_id = message.get("run_id").and_then(Value::as_str);
    let frame_type = message.get("type").and_then(Value::as_str);
    if frame_type == Some("run/error")
        && (frame_run_id.is_none() || frame_run_id == Some(expected_run_id))
    {
        return Err(ClaudeAgentSdkError::Remote(message));
    }
    if frame_run_id != Some(expected_run_id) {
        return Ok(RoutedFrame::Misrouted(ClaudeSidecarEvent {
            event_type: MISROUTED_FRAME_EVENT_TYPE.to_owned(),
            run_id: expected_run_id.to_owned(),
            payload: json!({
                "frame_type": frame_type,
                "frame_run_id": frame_run_id,
            }),
        }));
    }
    parse_event(message).map(RoutedFrame::Event)
}

fn parse_event(message: Value) -> Result<ClaudeSidecarEvent, ClaudeAgentSdkError> {
    let event_type = message
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| ClaudeAgentSdkError::Protocol("event missing `type`".to_owned()))?
        .to_owned();
    let run_id = message
        .get("run_id")
        .and_then(Value::as_str)
        .ok_or_else(|| ClaudeAgentSdkError::Protocol("event missing `run_id`".to_owned()))?
        .to_owned();
    let payload = message.get("payload").cloned().unwrap_or(Value::Null);
    Ok(ClaudeSidecarEvent {
        event_type,
        run_id,
        payload,
    })
}

pub struct ClaudeAgentSdkAdapter<T> {
    provider_id: String,
    capability: ProviderCapability,
    client: ClaudeAgentSdkClient<T>,
    active_run_id: Option<String>,
    provider_session_id: Option<String>,
    sequence: u64,
    // DR-0035 Decision 4: the inactivity wall clock. When no frame arrives
    // within this window, the adapter synthesizes the TimedOut terminal.
    inactivity_budget: std::time::Duration,
    // Idle time accumulated across empty poll slices; reset on every frame.
    idle_elapsed: std::time::Duration,
}

impl<T: ClaudeAgentSdkTransport> ClaudeAgentSdkAdapter<T> {
    pub fn new(
        provider_id: impl Into<String>,
        capability: ProviderCapability,
        client: ClaudeAgentSdkClient<T>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            capability,
            client,
            active_run_id: None,
            provider_session_id: None,
            sequence: 0,
            inactivity_budget: std::time::Duration::from_secs(300),
            idle_elapsed: std::time::Duration::ZERO,
        }
    }

    pub fn with_inactivity_budget(mut self, budget: std::time::Duration) -> Self {
        self.inactivity_budget = budget;
        self
    }

    pub fn into_client(self) -> ClaudeAgentSdkClient<T> {
        self.client
    }

    fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// The synthesized inactivity terminal (DR-0035 Decision 4 T2): a silent
    /// or closed peer still yields exactly one terminal.
    fn inactivity_timeout_event(&mut self, run_id: &str, reason: &str) -> NativeProviderEvent {
        NativeProviderEvent {
            provider_id: self.provider_id.clone(),
            run_id: run_id.to_owned(),
            event_kind: NativeProviderEventKind::TimedOut,
            provider_event_type: "whip.native.inactivity_timeout".to_owned(),
            provider_session_id: self.provider_session_id.clone(),
            provider_turn_id: None,
            sequence: Some(self.next_sequence()),
            evidence: json!({
                "reason": reason,
                "inactivity_budget_seconds": self.inactivity_budget.as_secs(),
            }),
            artifacts: Vec::new(),
        }
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
            surface: "claude_agent_sdk".to_owned(),
            code: code.into(),
            message: message.into(),
            recoverable,
            evidence,
        }
    }

    fn map_error(
        &self,
        code: &'static str,
        error: ClaudeAgentSdkError,
    ) -> NativeProviderBoundaryError {
        let (message, recoverable, evidence) = match error {
            ClaudeAgentSdkError::Io(error) => (
                format!("Claude Agent SDK sidecar I/O error: {error}"),
                true,
                json!({"kind": "io"}),
            ),
            ClaudeAgentSdkError::Json(error) => (
                format!("Claude Agent SDK sidecar emitted invalid JSON: {error}"),
                true,
                json!({"kind": "json"}),
            ),
            ClaudeAgentSdkError::Protocol(message) => (message, true, json!({"kind": "protocol"})),
            ClaudeAgentSdkError::Remote(error) => (
                "Claude Agent SDK sidecar returned a remote error".to_owned(),
                true,
                json!({"kind": "remote", "shape": json_shape(&error)}),
            ),
            ClaudeAgentSdkError::Timeout(message) => (message, true, json!({"kind": "timeout"})),
        };
        self.boundary_error(code, message, recoverable, evidence)
    }

    // Returns the shared, deliberately-rich `NativeProviderBoundaryError`; see
    // the kernel trait for why the large-Err variant is allowed at this seam.
    #[allow(clippy::result_large_err)]
    fn ensure_claude_request(
        &self,
        request: &NativeProviderTurnRequest,
    ) -> Result<(), NativeProviderBoundaryError> {
        if request.provider_id != self.provider_id {
            return Err(self.boundary_error(
                "provider_id_mismatch",
                "Claude adapter received a request for a different provider id",
                false,
                request.to_json_redacted(),
            ));
        }
        if request.provider_kind != "claude" || request.surface != "claude_agent_sdk" {
            return Err(self.boundary_error(
                "surface_mismatch",
                "Claude adapter only accepts claude_agent_sdk requests",
                false,
                request.to_json_redacted(),
            ));
        }
        Ok(())
    }

    fn event_from_sidecar(&mut self, event: ClaudeSidecarEvent) -> Option<NativeProviderEvent> {
        if event.event_type == MISROUTED_FRAME_EVENT_TYPE {
            // A misrouted frame surfaces as a non-terminal diagnostic; the
            // kernel records it as a protocol violation (DR-0035 Decision 3).
            let run_id = event.run_id.clone();
            return Some(NativeProviderEvent {
                provider_id: self.provider_id.clone(),
                run_id,
                event_kind: NativeProviderEventKind::Diagnostic,
                provider_event_type: event.event_type.clone(),
                provider_session_id: None,
                provider_turn_id: None,
                sequence: Some(self.next_sequence()),
                evidence: json!({ "violation": event.payload }),
                artifacts: Vec::new(),
            });
        }
        let observation = normalize_claude_agent_sdk_event(&event)?;
        let run_id = event.run_id.clone();
        if let Some(session_id) = observation.provider_session_id.as_ref() {
            self.provider_session_id = Some(session_id.clone());
        }
        let artifacts = artifact_refs_from_claude_event(&event);
        let sidecar_payload = summarize_claude_agent_sdk_events(std::slice::from_ref(&event));
        Some(NativeProviderEvent {
            provider_id: self.provider_id.clone(),
            run_id,
            event_kind: native_event_kind(observation.kind),
            provider_event_type: observation.provider_event_type,
            provider_session_id: observation.provider_session_id,
            provider_turn_id: observation.provider_turn_id,
            sequence: Some(self.next_sequence()),
            evidence: json!({
                "provider_payload_shape": observation.provider_payload_shape,
                "sidecar_payload": sidecar_payload,
                "provider_error": observation.provider_error,
            }),
            artifacts,
        })
    }
}

impl<T: ClaudeAgentSdkTransport> NativeProviderAdapter for ClaudeAgentSdkAdapter<T> {
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
        self.ensure_claude_request(&request)?;
        let policy = build_claude_agent_tool_policy(
            request.profile.as_deref(),
            &request.required_capabilities,
            &request.workspace_policy,
            request
                .provider_options
                .get("approval_mode")
                .and_then(Value::as_str),
            request
                .provider_options
                .get("mcp_config_ref")
                .and_then(Value::as_str),
            request
                .provider_options
                .get("settings")
                .and_then(Value::as_str),
        )
        .map_err(|error| {
            self.boundary_error(error.code, error.message, false, request.to_json_redacted())
        })?;
        let sidecar_request = claude_sidecar_request(&request, &policy);
        let run_id = self
            .client
            .begin_run(sidecar_request)
            .map_err(|error| self.map_error("claude_run_start_failed", error))?;
        self.active_run_id = Some(run_id.clone());
        let budget = self.inactivity_budget;
        loop {
            let event = match self.client.read_event_timeout(&run_id, budget) {
                Ok(Some(event)) => event,
                // A peer silent through the whole start window still yields
                // exactly one terminal (DR-0035 Decision 4 T2).
                Ok(None) => {
                    return Ok(self.inactivity_timeout_event(&run_id, "inactivity_budget_exhausted"))
                }
                Err(error) => {
                    return Err(self.map_error("claude_event_read_failed", error));
                }
            };
            if let Some(native) = self.event_from_sidecar(event) {
                return Ok(native);
            }
        }
    }

    fn next_event(
        &mut self,
        run_id: &str,
    ) -> Result<Option<NativeProviderEvent>, NativeProviderBoundaryError> {
        let active_run_id = self
            .active_run_id
            .clone()
            .unwrap_or_else(|| run_id.to_owned());
        // The wait is sliced (DR-0035 Decision 5) so the driver regains control
        // between slices to act on cancellation requests; the inactivity clock
        // accumulates across empty slices and fires at the full budget.
        let slice = self
            .inactivity_budget
            .min(std::time::Duration::from_secs(1));
        match self.client.read_event_timeout(&active_run_id, slice) {
            Ok(Some(event)) => {
                self.idle_elapsed = std::time::Duration::ZERO;
                Ok(self.event_from_sidecar(event))
            }
            Ok(None) => {
                self.idle_elapsed += slice;
                if self.idle_elapsed >= self.inactivity_budget {
                    self.idle_elapsed = std::time::Duration::ZERO;
                    // Window elapsed with no frame: the inactivity clock fires.
                    Ok(Some(self.inactivity_timeout_event(
                        &active_run_id,
                        "inactivity_budget_exhausted",
                    )))
                } else {
                    Ok(None)
                }
            }
            // The stream closed with no terminal: same backstop, distinct reason.
            Err(ClaudeAgentSdkError::Timeout(_)) => Ok(Some(
                self.inactivity_timeout_event(&active_run_id, "stream_closed"),
            )),
            Err(error) => Err(self.map_error("claude_event_read_failed", error)),
        }
    }

    fn cancel_turn(
        &mut self,
        cancellation: NativeProviderCancellation,
    ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
        if !CancellationDepth::CooperativeRequest.allows(cancellation.requested_depth) {
            return Err(self.boundary_error(
                "unsupported_cancellation_depth",
                format!(
                    "Claude Agent SDK adapter cannot satisfy `{}` cancellation until live interrupt validation is enabled",
                    cancellation.requested_depth.as_str()
                ),
                false,
                json!({"requested_depth": cancellation.requested_depth.as_str()}),
            ));
        }
        let run_id = self
            .active_run_id
            .clone()
            .unwrap_or_else(|| cancellation.run_id.clone());
        self.client
            .cancel_run(&run_id)
            .map_err(|error| self.map_error("claude_cancel_failed", error))?;
        Ok(NativeProviderEvent {
            provider_id: self.provider_id.clone(),
            run_id,
            event_kind: NativeProviderEventKind::Diagnostic,
            provider_event_type: "run/cancel".to_owned(),
            provider_session_id: cancellation
                .provider_session_id
                .or_else(|| self.provider_session_id.clone()),
            provider_turn_id: cancellation.provider_turn_id,
            sequence: Some(self.next_sequence()),
            evidence: json!({
                "acknowledged": true,
                "requested_depth": cancellation.requested_depth.as_str(),
                "reason_shape": json_shape(&Value::String(cancellation.reason)),
            }),
            artifacts: vec![],
        })
    }
}

fn claude_sidecar_request(
    request: &NativeProviderTurnRequest,
    policy: &ClaudeAgentToolPolicy,
) -> Value {
    let mut payload = serde_json::Map::new();
    payload.insert("run_id".to_owned(), json!(request.run_id));
    payload.insert(
        "prompt".to_owned(),
        json!(claude_prompt(&request.prompt_json)),
    );
    if let Some(cwd) = request.provider_options.get("cwd").and_then(Value::as_str) {
        payload.insert("cwd".to_owned(), json!(cwd));
    }
    if let Some(model) = request
        .provider_options
        .get("model")
        .and_then(Value::as_str)
    {
        payload.insert("model".to_owned(), json!(model));
    }
    payload.insert("allowed_tools".to_owned(), json!(policy.allowed_tools));
    payload.insert(
        "disallowed_tools".to_owned(),
        json!(policy.disallowed_tools),
    );
    payload.insert("permission_mode".to_owned(), json!(policy.permission_mode));
    // Omitted when None so the SDK keeps its own default setting sources
    // (DR-0034 Decision 4: unset means provider default, not the empty set).
    if let Some(sources) = policy.setting_sources.as_ref() {
        payload.insert("setting_sources".to_owned(), json!(sources));
    }
    if let Some(mcp_config_ref) = policy.mcp_config_ref.as_deref() {
        payload.insert("mcp_config_ref".to_owned(), json!(mcp_config_ref));
    }
    Value::Object(payload)
}

fn claude_prompt(prompt: &Value) -> String {
    prompt
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| prompt.to_string())
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

fn artifact_refs_from_claude_event(event: &ClaudeSidecarEvent) -> Vec<NativeProviderArtifactRef> {
    artifact_values(&event.payload)
        .into_iter()
        .filter_map(|artifact| {
            artifact_ref_from_value(
                artifact,
                "claude",
                &format!("provider://claude/runs/{}/artifacts", event.run_id),
            )
        })
        .collect()
}

fn artifact_values(payload: &Value) -> Vec<&Value> {
    ["artifacts", "artifact_refs"]
        .into_iter()
        .filter_map(|key| payload.get(key).and_then(Value::as_array))
        .flatten()
        .collect()
}

fn artifact_ref_from_value(
    artifact: &Value,
    provider: &str,
    fallback_base: &str,
) -> Option<NativeProviderArtifactRef> {
    let uri = string_field(artifact, &["uri", "ref", "artifact_ref"])
        .or_else(|| {
            string_field(artifact, &["path"]).map(|path| format!("{provider}-artifact://{path}"))
        })
        .or_else(|| {
            string_field(artifact, &["id", "artifact_id"]).map(|id| format!("{fallback_base}/{id}"))
        })?;
    Some(NativeProviderArtifactRef {
        artifact_id: string_field(artifact, &["artifact_id", "id"]),
        kind: string_field(artifact, &["kind"]).unwrap_or_else(|| "artifact".to_owned()),
        uri,
        content_hash: string_field(artifact, &["content_hash", "hash"]),
        mime_type: string_field(artifact, &["mime_type", "mime"]),
        required: artifact
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::to_owned)
}

fn json_shape(value: &Value) -> Value {
    match value {
        Value::Null => json!({"type":"null"}),
        Value::Bool(_) => json!({"type":"bool"}),
        Value::Number(_) => json!({"type":"number"}),
        Value::String(value) => json!({"type":"string","chars":value.chars().count()}),
        Value::Array(values) => json!({"type":"array","items":values.len()}),
        Value::Object(object) => json!({"type":"object","keys":object.len()}),
    }
}

pub struct StdioClaudeAgentSdkTransport {
    _child: Child,
    stdin: ChildStdin,
    // Lines arrive via a reader thread so reads can carry a timeout
    // (DR-0035 Decision 4): a blocked pipe no longer pins the worker thread.
    lines: std::sync::mpsc::Receiver<std::io::Result<String>>,
}

impl StdioClaudeAgentSdkTransport {
    pub fn spawn(command: &str, args: &[&str]) -> Result<Self, ClaudeAgentSdkError> {
        let mut builder = Command::new(command);
        builder
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        whipplescript_kernel::harness::strip_control_plane_secrets(&mut builder);
        // The Claude sidecar is the Anthropic-family backend; strip the other
        // families' keys (OpenAI, xAI).
        whipplescript_kernel::harness::strip_env_vars(
            &mut builder,
            whipplescript_kernel::harness::OPENAI_CREDENTIAL_ENV,
        );
        whipplescript_kernel::harness::strip_env_vars(
            &mut builder,
            whipplescript_kernel::harness::XAI_CREDENTIAL_ENV,
        );
        let mut child = builder.spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| {
            ClaudeAgentSdkError::Protocol("Claude sidecar did not expose stdin".to_owned())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            ClaudeAgentSdkError::Protocol("Claude sidecar did not expose stdout".to_owned())
        })?;
        Ok(Self {
            _child: child,
            stdin,
            lines: spawn_line_reader(stdout),
        })
    }

    fn closed_error() -> ClaudeAgentSdkError {
        ClaudeAgentSdkError::Timeout(
            "Claude sidecar stdout closed before terminal event".to_owned(),
        )
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

impl ClaudeAgentSdkTransport for StdioClaudeAgentSdkTransport {
    fn write_line(&mut self, line: &str) -> Result<(), ClaudeAgentSdkError> {
        self.stdin.write_all(line.as_bytes())?;
        self.stdin.write_all(b"\n")?;
        self.stdin.flush()?;
        Ok(())
    }

    fn read_line(&mut self) -> Result<String, ClaudeAgentSdkError> {
        match self.lines.recv() {
            Ok(Ok(line)) => Ok(line),
            Ok(Err(error)) => Err(error.into()),
            Err(_) => Err(Self::closed_error()),
        }
    }

    fn read_line_timeout(
        &mut self,
        wait: std::time::Duration,
    ) -> Result<Option<String>, ClaudeAgentSdkError> {
        match self.lines.recv_timeout(wait) {
            Ok(Ok(line)) => Ok(Some(line)),
            Ok(Err(error)) => Err(error.into()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(Self::closed_error()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

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

    impl ClaudeAgentSdkTransport for FakeTransport {
        fn write_line(&mut self, line: &str) -> Result<(), ClaudeAgentSdkError> {
            self.writes.push(line.to_owned());
            Ok(())
        }

        fn read_line(&mut self) -> Result<String, ClaudeAgentSdkError> {
            match self.reads.pop_front() {
                Some(Ok(line)) => Ok(line),
                Some(Err(message)) => Err(ClaudeAgentSdkError::Timeout(message)),
                None => Err(ClaudeAgentSdkError::Timeout("fake timeout".to_owned())),
            }
        }
    }

    fn claude_capability() -> ProviderCapability {
        super::capability()
    }

    #[test]
    fn capability_matches_the_registered_surface() {
        let capability = super::capability();
        assert_eq!(capability.provider_kind, super::PROVIDER_KIND);
        assert_eq!(capability.surface, super::SURFACE);
    }

    #[test]
    fn capability_advertises_no_cancellation_depth_per_dr0017() {
        // DR-0017: Claude interrupt was never live-validated, so the capability
        // must advertise NO cancellation depth (the validation-plane refusal is
        // covered kernel-side).
        assert_eq!(
            super::capability().cancellation_depths,
            vec![CancellationDepth::None]
        );
    }

    #[test]
    fn normalizes_claude_terminal_events() {
        let event = ClaudeSidecarEvent {
            event_type: "claude.turn.failed".to_owned(),
            run_id: "run-1".to_owned(),
            payload: json!({"session_id": "session-1", "error": "secret"}),
        };

        let observation = normalize_claude_agent_sdk_event(&event).expect("event normalizes");

        assert_eq!(observation.kind, AgentTurnLifecycleKind::Failed);
        assert_eq!(
            observation.provider_session_id.as_deref(),
            Some("session-1")
        );
        assert_eq!(observation.provider_turn_id.as_deref(), Some("run-1"));
        assert!(!observation
            .provider_payload_shape
            .to_string()
            .contains("secret"));
    }

    #[test]
    fn normalizes_claude_artifact_events() {
        let claude = normalize_claude_agent_sdk_event(&ClaudeSidecarEvent {
            event_type: "claude.artifact.captured".to_owned(),
            run_id: "run-1".to_owned(),
            payload: json!({"session_id": "session-1", "content": "secret"}),
        })
        .expect("claude artifact normalizes");
        assert_eq!(claude.kind, AgentTurnLifecycleKind::ArtifactCaptured);
        assert!(!claude.provider_payload_shape.to_string().contains("secret"));
    }

    fn native_claude_request() -> NativeProviderTurnRequest {
        NativeProviderTurnRequest {
            provider_id: "claude-main".to_owned(),
            provider_kind: "claude".to_owned(),
            surface: "claude_agent_sdk".to_owned(),
            run_id: "run-1".to_owned(),
            effect_id: "effect-1".to_owned(),
            agent: "claude".to_owned(),
            profile: Some("repo-writer".to_owned()),
            prompt_json: json!("inspect the repo"),
            workspace_policy: "shared".to_owned(),
            required_capabilities: vec!["repo.write".to_owned()],
            cancellation_depth: CancellationDepth::CooperativeRequest,
            artifact_policy: "manifest".to_owned(),
            credential_ref: Some("secret:claude".to_owned()),
            provider_options: std::collections::BTreeMap::from([
                ("approval_mode".to_owned(), json!("manual")),
                ("cwd".to_owned(), json!("/workspace")),
                ("model".to_owned(), json!("claude-sonnet-4-5")),
            ]),
        }
    }

    #[test]
    fn client_sends_start_and_collects_until_terminal() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"sess_1"}}"#,
            r#"{"type":"claude.stream.message","run_id":"run-1","payload":{"message_type":"assistant"}}"#,
            r#"{"type":"claude.turn.completed","run_id":"run-1","payload":{"subtype":"success"}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);

        let events = client
            .start_run(json!({"run_id":"run-1","prompt":"redacted"}))
            .expect("run succeeds");

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "claude.session.started");
        assert_eq!(events[2].event_type, "claude.turn.completed");
        let transport = client.into_transport();
        let request: Value = serde_json::from_str(&transport.writes[0]).expect("request json");
        assert_eq!(
            request.get("type").and_then(Value::as_str),
            Some("run/start")
        );
        assert_eq!(request.get("run_id").and_then(Value::as_str), Some("run-1"));
    }

    #[test]
    fn client_sends_cancel_command() {
        let transport = FakeTransport::default();
        let mut client = ClaudeAgentSdkClient::new(transport);

        client.cancel_run("run-1").expect("cancel writes");

        let transport = client.into_transport();
        let request: Value = serde_json::from_str(&transport.writes[0]).expect("request json");
        assert_eq!(
            request.get("type").and_then(Value::as_str),
            Some("run/cancel")
        );
        assert_eq!(request.get("run_id").and_then(Value::as_str), Some("run-1"));
    }

    #[test]
    fn client_reports_malformed_event() {
        let transport = FakeTransport::with_reads(&["not-json"]);
        let mut client = ClaudeAgentSdkClient::new(transport);

        let error = client
            .start_run(json!({"run_id":"run-1"}))
            .expect_err("malformed response fails");

        assert!(matches!(error, ClaudeAgentSdkError::Json(_)));
    }

    #[test]
    fn client_misrouted_terminal_never_completes_the_run() {
        // DR-0035 Decision 3: a terminal frame for ANOTHER run id is misrouted
        // — it must not terminate this run (it rides as a violation event and
        // the run keeps waiting for its own terminal).
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.turn.completed","run_id":"run-2","payload":{}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);

        let error = client
            .start_run(json!({"run_id":"run-1"}))
            .expect_err("no own terminal ever arrives");

        assert!(matches!(error, ClaudeAgentSdkError::Timeout(_)));
    }

    #[test]
    fn client_reports_remote_error() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"run/error","run_id":"run-1","payload":{"code":"auth_missing"}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);

        let error = client
            .start_run(json!({"run_id":"run-1"}))
            .expect_err("remote error fails");

        assert!(
            matches!(error, ClaudeAgentSdkError::Remote(error) if error.pointer("/payload/code").and_then(Value::as_str) == Some("auth_missing"))
        );
    }

    #[test]
    fn policy_maps_reader_profile_to_read_only_tools() {
        let policy = build_claude_agent_tool_policy(
            Some("repo-reader"),
            &["repo.read".to_owned()],
            "read_only",
            None,
            None,
            None,
        )
        .expect("reader policy maps");

        assert_eq!(policy.allowed_tools, strings(&["Glob", "Grep", "Read"]));
        assert_eq!(policy.disallowed_tools, strings(&["Bash", "Edit", "Write"]));
        assert_eq!(policy.permission_mode, "default");
    }

    #[test]
    fn policy_unset_settings_means_provider_default_and_omits_sidecar_key() {
        // DR-0034 Decision 4: unset must be the provider's own default, NOT the
        // crippled empty set — the key must be absent from the sidecar payload.
        let policy = build_claude_agent_tool_policy(
            Some("repo-reader"),
            &["repo.read".to_owned()],
            "read_only",
            None,
            None,
            None,
        )
        .expect("reader policy maps");

        assert_eq!(policy.setting_sources, None);
        assert!(policy.to_sidecar_json().get("setting_sources").is_none());
    }

    #[test]
    fn policy_maps_settings_sources_and_none_is_explicit_empty() {
        for (settings, expected) in [
            ("project", strings(&["project"])),
            ("user", strings(&["user"])),
            ("none", Vec::new()),
        ] {
            let policy = build_claude_agent_tool_policy(
                Some("repo-reader"),
                &["repo.read".to_owned()],
                "read_only",
                None,
                None,
                Some(settings),
            )
            .expect("reader policy maps");

            assert_eq!(policy.setting_sources.as_deref(), Some(expected.as_slice()));
            assert_eq!(
                policy.to_sidecar_json().get("setting_sources"),
                Some(&json!(expected))
            );
        }
    }

    #[test]
    fn policy_rejects_unknown_settings_source() {
        let error = build_claude_agent_tool_policy(
            Some("repo-reader"),
            &["repo.read".to_owned()],
            "read_only",
            None,
            None,
            Some("workspace"),
        )
        .expect_err("unknown settings source denied");

        assert_eq!(error.code, "unsupported_settings_source");
    }

    #[test]
    fn policy_maps_writer_profile_to_edit_tools_with_approval() {
        let policy = build_claude_agent_tool_policy(
            Some("repo-writer"),
            &["repo.write".to_owned(), "command.run".to_owned()],
            "shared",
            Some("manual"),
            Some("mcp/readonly.json"),
            None,
        )
        .expect("writer policy maps");

        assert_eq!(
            policy.allowed_tools,
            strings(&["Bash", "Edit", "Glob", "Grep", "Read", "Write"])
        );
        assert!(policy.disallowed_tools.is_empty());
        assert_eq!(policy.permission_mode, "default");
        assert_eq!(policy.mcp_config_ref.as_deref(), Some("mcp/readonly.json"));
    }

    #[test]
    fn policy_rejects_forbidden_tool_for_reader_profile() {
        let error = build_claude_agent_tool_policy(
            Some("repo-reader"),
            &["repo.write".to_owned()],
            "shared",
            Some("manual"),
            None,
            None,
        )
        .expect_err("reader write denied");

        assert_eq!(error.code, "profile_denied");
    }

    #[test]
    fn policy_rejects_destructive_tool_without_approval() {
        let error = build_claude_agent_tool_policy(
            Some("repo-writer"),
            &["repo.write".to_owned()],
            "shared",
            None,
            None,
            None,
        )
        .expect_err("approval required");

        assert_eq!(error.code, "missing_approval");
    }

    #[test]
    fn policy_rejects_write_in_read_only_workspace() {
        let error = build_claude_agent_tool_policy(
            Some("repo-writer"),
            &["repo.write".to_owned()],
            "read_only",
            Some("manual"),
            None,
            None,
        )
        .expect_err("read only workspace denied");

        assert_eq!(error.code, "workspace_denied");
    }

    #[test]
    fn policy_rejects_unsupported_workspace_policy() {
        let error = build_claude_agent_tool_policy(
            Some("repo-writer"),
            &["repo.write".to_owned()],
            "remote_sandbox",
            Some("manual"),
            None,
            None,
        )
        .expect_err("remote sandbox requires explicit workspace implementation");

        assert_eq!(error.code, "unsupported_workspace_policy");
    }

    #[test]
    fn policy_rejects_missing_profile() {
        let error = build_claude_agent_tool_policy(
            None,
            &["repo.read".to_owned()],
            "shared",
            None,
            None,
            None,
        )
        .expect_err("profile required");

        assert_eq!(error.code, "missing_profile");
    }

    #[test]
    fn event_summary_redacts_result_and_usage_payloads() {
        let events = vec![
            ClaudeSidecarEvent {
                event_type: "claude.session.started".to_owned(),
                run_id: "run-1".to_owned(),
                payload: json!({"session_id":"sess_1"}),
            },
            ClaudeSidecarEvent {
                event_type: "claude.stream.message".to_owned(),
                run_id: "run-1".to_owned(),
                payload: json!({
                    "message_type": "assistant",
                    "content_shape": {"type":"array","items":1},
                }),
            },
            ClaudeSidecarEvent {
                event_type: "claude.turn.completed".to_owned(),
                run_id: "run-1".to_owned(),
                payload: json!({
                    "subtype": "success",
                    "result_shape": {"type":"string","chars":42},
                    "usage_shape": {"type":"object","keys":2},
                }),
            },
        ];

        let summary = summarize_claude_agent_sdk_events(&events);

        assert_eq!(
            summary.get("session_id").and_then(Value::as_str),
            Some("sess_1")
        );
        assert_eq!(
            summary
                .pointer("/event_counts/claude.stream.message")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            summary.get("terminal_type").and_then(Value::as_str),
            Some("claude.turn.completed")
        );
        assert_eq!(
            summary
                .pointer("/terminal_payload/result_shape/chars")
                .and_then(Value::as_u64),
            Some(42)
        );
        assert!(!summary
            .to_string()
            .contains("WHIPPLESCRIPT_CLAUDE_SMOKE_OK"));
    }

    #[test]
    fn native_adapter_starts_sidecar_run_with_tool_policy_payload() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
        ]);
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client);

        let event = adapter
            .start_turn(native_claude_request())
            .expect("turn starts");

        assert_eq!(event.event_kind, NativeProviderEventKind::Started);
        assert_eq!(event.provider_session_id.as_deref(), Some("session-1"));
        let transport = adapter.into_client().into_transport();
        let request: Value = serde_json::from_str(&transport.writes[0]).expect("run/start json");
        assert_eq!(
            request.get("type").and_then(Value::as_str),
            Some("run/start")
        );
        assert_eq!(
            request.pointer("/request/prompt").and_then(Value::as_str),
            Some("inspect the repo")
        );
        assert_eq!(
            request
                .pointer("/request/allowed_tools")
                .and_then(Value::as_array)
                .expect("allowed tools")
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>(),
            vec!["Edit", "Glob", "Grep", "Read", "Write"]
        );
        assert_eq!(
            request
                .pointer("/request/permission_mode")
                .and_then(Value::as_str),
            Some("default")
        );
    }

    #[test]
    fn native_adapter_maps_claude_remote_start_error_without_raw_message() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"run/error","run_id":"run-1","payload":{"code":"auth_missing","message":"token sk-never-print leaked"}}"#,
        ]);
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client);

        let error = adapter
            .start_turn(native_claude_request())
            .expect_err("remote start error is mapped");

        assert_eq!(error.code, "claude_event_read_failed");
        assert!(error.recoverable);
        assert_eq!(
            error.evidence.get("kind").and_then(Value::as_str),
            Some("remote")
        );
        let redacted = error.to_json_redacted().to_string();
        assert!(!redacted.contains("sk-never-print"));
        assert!(!redacted.contains("auth_missing"));
    }

    #[test]
    fn native_adapter_streams_sidecar_events_without_raw_payload_content() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
            r#"{"type":"claude.stream.message","run_id":"run-1","payload":{"session_id":"session-1","content":"secret text"}}"#,
            r#"{"type":"claude.turn.completed","run_id":"run-1","payload":{"session_id":"session-1","subtype":"success","result_shape":{"type":"string","chars":18}}}"#,
        ]);
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client);
        adapter
            .start_turn(native_claude_request())
            .expect("turn starts");

        let streamed = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("stream event");
        assert_eq!(streamed.event_kind, NativeProviderEventKind::Streamed);
        assert!(!streamed
            .to_json_redacted()
            .to_string()
            .contains("secret text"));

        let terminal = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("terminal event");
        assert_eq!(terminal.event_kind, NativeProviderEventKind::Completed);
        assert!(terminal.event_kind.is_terminal());
    }

    /// A transport whose peer stays alive but silent once the scripted reads
    /// are exhausted: `read_line_timeout` reports an empty window instead of a
    /// closed stream.
    struct SilentAfterReadsTransport(FakeTransport);

    impl ClaudeAgentSdkTransport for SilentAfterReadsTransport {
        fn write_line(&mut self, line: &str) -> Result<(), ClaudeAgentSdkError> {
            self.0.write_line(line)
        }

        fn read_line(&mut self) -> Result<String, ClaudeAgentSdkError> {
            self.0.read_line()
        }

        fn read_line_timeout(
            &mut self,
            _wait: std::time::Duration,
        ) -> Result<Option<String>, ClaudeAgentSdkError> {
            match self.0.read_line() {
                Ok(line) => Ok(Some(line)),
                Err(_) => Ok(None),
            }
        }
    }

    #[test]
    fn native_adapter_inactivity_synthesizes_timed_out_terminal() {
        // DR-0035 Decision 4: a peer that stays silent past the inactivity
        // window yields exactly one synthesized TimedOut terminal.
        let transport = SilentAfterReadsTransport(FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
        ]));
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client)
            .with_inactivity_budget(std::time::Duration::from_millis(1));
        adapter
            .start_turn(native_claude_request())
            .expect("turn starts");

        let timed_out = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("inactivity terminal");
        assert_eq!(timed_out.event_kind, NativeProviderEventKind::TimedOut);
        assert!(timed_out.event_kind.is_terminal());
        assert_eq!(
            timed_out.provider_event_type,
            "whip.native.inactivity_timeout"
        );
        assert_eq!(
            timed_out.evidence.get("reason").and_then(Value::as_str),
            Some("inactivity_budget_exhausted")
        );
    }

    #[test]
    fn native_adapter_closed_stream_synthesizes_timed_out_terminal() {
        // A stream that closes with no terminal gets the same backstop with a
        // distinct reason.
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
        ]);
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client);
        adapter
            .start_turn(native_claude_request())
            .expect("turn starts");

        let timed_out = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("stream-closed terminal");
        assert_eq!(timed_out.event_kind, NativeProviderEventKind::TimedOut);
        assert_eq!(
            timed_out.evidence.get("reason").and_then(Value::as_str),
            Some("stream_closed")
        );
    }

    #[test]
    fn native_adapter_misrouted_frame_is_violation_diagnostic_not_abort() {
        // DR-0035 Decision 3 T3: a frame for another run id surfaces as a
        // non-terminal protocol-violation diagnostic; the turn keeps going and
        // the stray frame's payload never crosses (identifiers only).
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
            r#"{"type":"claude.stream.message","run_id":"run-2","payload":{"content":"stray secret text"}}"#,
            r#"{"type":"claude.turn.completed","run_id":"run-1","payload":{"session_id":"session-1","subtype":"success"}}"#,
        ]);
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client);
        adapter
            .start_turn(native_claude_request())
            .expect("turn starts");

        let violation = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("violation event");
        assert_eq!(violation.event_kind, NativeProviderEventKind::Diagnostic);
        assert!(!violation.event_kind.is_terminal());
        assert_eq!(violation.provider_event_type, MISROUTED_FRAME_EVENT_TYPE);
        assert_eq!(violation.run_id, "run-1");
        // The violation payload is whip-constructed from identifiers only —
        // the stray frame's content never crosses into it.
        assert_eq!(
            violation
                .evidence
                .pointer("/violation/frame_run_id")
                .and_then(Value::as_str),
            Some("run-2")
        );
        let raw = violation.evidence.to_string();
        assert!(!raw.contains("stray secret text"), "{raw}");
        let rendered = violation.to_json_redacted().to_string();
        assert!(!rendered.contains("stray secret text"), "{rendered}");

        let terminal = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("terminal event");
        assert_eq!(terminal.event_kind, NativeProviderEventKind::Completed);
    }

    #[test]
    fn client_hello_exchanges_protocol_and_tolerates_legacy_sidecars() {
        // DR-0035 Decision 7: the handshake returns the sidecar's protocol.
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"hello","run_id":null,"payload":{"protocol":"whip-sidecar/1"}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);
        assert_eq!(
            client.hello().expect("handshake"),
            Some(WHIP_SIDECAR_PROTOCOL.to_owned())
        );

        // A legacy sidecar answers unknown_command — tolerated as `/1`.
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"run/error","run_id":null,"payload":{"code":"unknown_command","message":"unknown command hello"}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);
        assert_eq!(client.hello().expect("legacy tolerated"), None);
    }

    #[test]
    fn client_run_start_carries_the_protocol_version() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.turn.completed","run_id":"run-1","payload":{}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);
        client
            .start_run(json!({"run_id":"run-1"}))
            .expect("run completes");
        let frame: Value =
            serde_json::from_str(&client.into_transport().writes[0]).expect("frame parses");
        assert_eq!(
            frame.get("protocol").and_then(Value::as_str),
            Some(WHIP_SIDECAR_PROTOCOL)
        );
    }

    #[test]
    fn client_routes_null_run_id_error_as_remote_not_protocol_abort() {
        // DR-0035 Decision 3 T3: the sidecar's pre-run failures carry
        // `run_id: null`; they must surface as the remote error they are, not
        // as an unexpected-run-id protocol abort.
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"run/error","run_id":null,"payload":{"code":"invalid_json","message":"bad frame"}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);
        let run_id = client
            .begin_run(json!({"run_id":"run-1"}))
            .expect("run begins");

        let error = client.read_event(&run_id).expect_err("remote error");
        assert!(
            matches!(error, ClaudeAgentSdkError::Remote(message) if message.pointer("/payload/code").and_then(Value::as_str) == Some("invalid_json"))
        );
    }

    #[test]
    fn client_start_run_carries_misrouted_frame_as_violation_event() {
        // The batch path applies the same tolerant routing: the stray frame
        // rides along as a violation event and the terminal still lands.
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
            r#"{"type":"claude.stream.message","run_id":"run-9","payload":{"content":"stray"}}"#,
            r#"{"type":"claude.turn.completed","run_id":"run-1","payload":{"session_id":"session-1","subtype":"success"}}"#,
        ]);
        let mut client = ClaudeAgentSdkClient::new(transport);

        let events = client
            .start_run(json!({"run_id":"run-1"}))
            .expect("run completes");
        assert_eq!(events.len(), 3);
        assert_eq!(events[1].event_type, MISROUTED_FRAME_EVENT_TYPE);
        assert_eq!(events[1].run_id, "run-1");
        assert_eq!(events[2].event_type, "claude.turn.completed");
    }

    #[test]
    fn native_adapter_captures_claude_artifact_refs_without_raw_content() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
            r#"{"type":"claude.artifact.captured","run_id":"run-1","payload":{"session_id":"session-1","artifacts":[{"id":"artifact-1","kind":"attachment","uri":"provider://claude/runs/run-1/artifacts/output.txt","mime_type":"text/plain","content_hash":"sha256:abc123","required":true,"content":"secret artifact bytes"}]}}"#,
        ]);
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client);
        adapter
            .start_turn(native_claude_request())
            .expect("turn starts");

        let artifact = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("artifact event");

        assert_eq!(
            artifact.event_kind,
            NativeProviderEventKind::ArtifactCaptured
        );
        assert_eq!(artifact.artifacts.len(), 1);
        assert_eq!(
            artifact.artifacts[0].artifact_id.as_deref(),
            Some("artifact-1")
        );
        assert_eq!(artifact.artifacts[0].kind, "attachment");
        assert_eq!(
            artifact.artifacts[0].uri,
            "provider://claude/runs/run-1/artifacts/output.txt"
        );
        assert!(artifact.artifacts[0].required);
        assert!(!artifact
            .to_json_redacted()
            .to_string()
            .contains("secret artifact bytes"));
    }

    #[test]
    fn native_adapter_cancel_ack_is_non_terminal_until_sidecar_cancel_event() {
        let transport = FakeTransport::with_reads(&[
            r#"{"type":"claude.session.started","run_id":"run-1","payload":{"session_id":"session-1"}}"#,
            r#"{"type":"claude.turn.cancelled","run_id":"run-1","payload":{"session_id":"session-1","acknowledgement":"fake-cancelled"}}"#,
        ]);
        let client = ClaudeAgentSdkClient::new(transport);
        let mut adapter = ClaudeAgentSdkAdapter::new("claude-main", claude_capability(), client);
        adapter
            .start_turn(native_claude_request())
            .expect("turn starts");

        let ack = adapter
            .cancel_turn(NativeProviderCancellation {
                run_id: "run-1".to_owned(),
                provider_session_id: None,
                provider_turn_id: None,
                requested_depth: CancellationDepth::CooperativeRequest,
                reason: "revision changed".to_owned(),
            })
            .expect("cancel request acknowledged");
        assert_eq!(ack.event_kind, NativeProviderEventKind::Diagnostic);
        assert!(!ack.event_kind.is_terminal());

        let terminal = adapter
            .next_event("run-1")
            .expect("event reads")
            .expect("terminal event");
        assert_eq!(terminal.event_kind, NativeProviderEventKind::Cancelled);

        let transport = adapter.into_client().into_transport();
        let cancel: Value = serde_json::from_str(&transport.writes[1]).expect("cancel json");
        assert_eq!(
            cancel.get("type").and_then(Value::as_str),
            Some("run/cancel")
        );
    }
}
