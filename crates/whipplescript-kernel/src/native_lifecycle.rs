//! Native provider lifecycle normalization.

use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTurnLifecycleKind {
    Started,
    Streamed,
    ToolRequested,
    ArtifactCaptured,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

impl AgentTurnLifecycleKind {
    pub fn event_type(self) -> &'static str {
        match self {
            Self::Started => "agent.turn.started",
            Self::Streamed => "agent.turn.streamed",
            Self::ToolRequested => "agent.turn.tool_requested",
            Self::ArtifactCaptured => "agent.turn.artifact_captured",
            Self::Completed => "agent.turn.completed",
            Self::Failed => "agent.turn.failed",
            Self::TimedOut => "agent.turn.timed_out",
            Self::Cancelled => "agent.turn.cancelled",
        }
    }

    pub fn status(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Streamed => "streamed",
            Self::ToolRequested => "tool_requested",
            Self::ArtifactCaptured => "artifact_captured",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::TimedOut | Self::Cancelled
        )
    }

    /// Per spec/agent-harness.md, the only durable, rule-matchable lifecycle
    /// facts are `agent.turn.started/completed/failed/timed_out/cancelled`. The
    /// in-turn observations `streamed`/`tool_requested`/`artifact_captured` are
    /// EVIDENCE only — turn-internal activity that is inspectable but never an
    /// event-sourced fact that later rules pattern-match (the compiler enforces
    /// the matching ban via `validate_evidence_fact_not_matched`; this keeps the
    /// storage side honest so they never inflate the fact set in the first place).
    pub fn derives_rule_matchable_fact(self) -> bool {
        !matches!(
            self,
            Self::Streamed | Self::ToolRequested | Self::ArtifactCaptured
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeAgentTurnObservation {
    pub kind: AgentTurnLifecycleKind,
    pub provider_event_type: String,
    pub provider_session_id: Option<String>,
    pub provider_turn_id: Option<String>,
    pub terminal: bool,
    pub provider_payload_shape: Value,
    /// A provider *control-plane* error reason for a terminal failure (e.g.
    /// "usage limit exceeded", auth failure, model-not-found) extracted from the
    /// terminal event's dedicated error field. This is operational, not model
    /// output content, so it is allowed to cross the shape-only redaction
    /// boundary (capped + secret-redacted at serialization). `None` for success
    /// and for non-error terminals.
    pub provider_error: Option<String>,
}

impl NativeAgentTurnObservation {
    pub fn fixture(
        kind: AgentTurnLifecycleKind,
        provider_event_type: impl Into<String>,
        provider_session_id: Option<String>,
        provider_turn_id: Option<String>,
        provider_payload_shape: Value,
    ) -> Self {
        Self {
            kind,
            provider_event_type: provider_event_type.into(),
            provider_session_id,
            provider_turn_id,
            terminal: kind.terminal(),
            provider_payload_shape,
            provider_error: None,
        }
    }

    // These builders are `pub` because provider *adapters* — now in their own
    // crates (whipplescript-provider-codex / -claude, DR-0024 split) — assemble
    // observations from raw provider events via `normalize_*` functions they own.
    // The shape-only redaction (`payload_shape` → `json_shape`) stays kernel-side
    // so every provider inherits the same egress boundary.
    pub fn new(kind: AgentTurnLifecycleKind, provider_event_type: impl Into<String>) -> Self {
        Self {
            kind,
            provider_event_type: provider_event_type.into(),
            provider_session_id: None,
            provider_turn_id: None,
            terminal: kind.terminal(),
            provider_payload_shape: Value::Null,
            provider_error: None,
        }
    }

    pub fn provider_error(mut self, provider_error: Option<String>) -> Self {
        self.provider_error = provider_error;
        self
    }

    pub fn session_id(mut self, session_id: Option<String>) -> Self {
        self.provider_session_id = session_id;
        self
    }

    pub fn turn_id(mut self, turn_id: Option<String>) -> Self {
        self.provider_turn_id = turn_id;
        self
    }

    pub fn payload_shape(mut self, payload: &Value) -> Self {
        self.provider_payload_shape = json_shape(payload);
        self
    }
}

// Provider event normalizers moved to their provider crates (DR-0024 split):
// `normalize_codex_app_server_event` (+ `codex_terminal_*`) to
// whipplescript-provider-codex, and `normalize_claude_agent_sdk_event` (+
// `ClaudeSidecarEvent`) to whipplescript-provider-claude. Event-shape knowledge
// belongs with the adapter that speaks the protocol; the kernel keeps only the
// provider-agnostic `AgentTurnLifecycleKind` / `NativeAgentTurnObservation`
// vocabulary and its shape-only redaction boundary (`payload_shape`).

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

// The codex/claude normalizer tests live with their crates now (DR-0024). The
// provider-agnostic kernel record path is covered by
// `native_provider_lifecycle_observation_records_event_and_fact` in lib.rs.
