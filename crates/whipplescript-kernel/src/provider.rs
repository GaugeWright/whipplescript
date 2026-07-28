//! Native provider capability and binding validation.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

// Provider-kind and adapter-surface identifiers. The registry is OPEN
// (DR-0024, provider-crate split): the kernel names only its own builtins as
// string constants here; external providers (codex, claude, and any third
// party) live in their own crates, own their identifier strings, and register a
// `ProviderCapability` into the effective catalog at the composition root. The
// kernel therefore has zero compile-time knowledge of any external provider —
// `provider_kind` / `surface` are opaque strings validated against whatever
// capability set the host assembles, not a closed enum.
pub const PROVIDER_FIXTURE: &str = "fixture";
pub const PROVIDER_COMMAND: &str = "command";
pub const PROVIDER_SCHEMA_COERCE: &str = "schema_coercer";

pub const SURFACE_FIXTURE: &str = "fixture";
pub const SURFACE_COMMAND: &str = "command";
pub const SURFACE_COERCE_HTTP: &str = "coerce_http";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CancellationDepth {
    None,
    CooperativeRequest,
    NativeStop,
    HardProcessStop,
    RemoteSessionCancel,
}

impl CancellationDepth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::CooperativeRequest => "cooperative_request",
            Self::NativeStop => "native_stop",
            Self::HardProcessStop => "hard_process_stop",
            Self::RemoteSessionCancel => "remote_session_cancel",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "cooperative_request" => Some(Self::CooperativeRequest),
            "native_stop" => Some(Self::NativeStop),
            "hard_process_stop" => Some(Self::HardProcessStop),
            "remote_session_cancel" => Some(Self::RemoteSessionCancel),
            _ => None,
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::CooperativeRequest => 1,
            Self::NativeStop => 2,
            Self::HardProcessStop => 3,
            Self::RemoteSessionCancel => 4,
        }
    }

    pub fn allows(self, requested: Self) -> bool {
        requested.rank() <= self.rank()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderValidationStatus {
    Pass,
    Fail,
    Skip,
}

impl ProviderValidationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderCapability {
    pub provider_kind: String,
    pub surface: String,
    pub protocol_version: Option<String>,
    pub session_identity_fields: Vec<String>,
    pub stream_event_kinds: Vec<String>,
    pub tool_policy: String,
    pub cancellation_depths: Vec<CancellationDepth>,
    pub artifact_manifest: bool,
    pub health_checks: Vec<String>,
    pub auth_requirements: Vec<String>,
}

impl ProviderCapability {
    pub fn supports_cancellation_depth(&self, depth: CancellationDepth) -> bool {
        self.cancellation_depths.contains(&depth)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "provider_kind": self.provider_kind.as_str(),
            "surface": self.surface.as_str(),
            "protocol_version": self.protocol_version,
            "session_identity_fields": self.session_identity_fields,
            "stream_event_kinds": self.stream_event_kinds,
            "tool_policy": self.tool_policy,
            "cancellation_depths": self
                .cancellation_depths
                .iter()
                .map(|depth| depth.as_str())
                .collect::<Vec<_>>(),
            "artifact_manifest": self.artifact_manifest,
            "health_checks": self.health_checks,
            "auth_requirements": self.auth_requirements,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderBindingConfig {
    pub provider_id: String,
    pub provider_kind: String,
    pub surface: String,
    pub credentials_ref: Option<String>,
    pub profile_ids: Vec<String>,
    pub default_model: Option<String>,
    pub workspace_policy: String,
    pub timeout_ms: Option<u64>,
    pub cancellation_depth: CancellationDepth,
    pub artifact_policy: String,
    pub health_checks: Vec<String>,
    pub extra: BTreeMap<String, Value>,
}

impl ProviderBindingConfig {
    pub fn from_json_str(config_json: &str) -> Result<Self, Vec<ProviderValidationResult>> {
        let value = match serde_json::from_str::<Value>(config_json) {
            Ok(value) => value,
            Err(error) => {
                return Err(vec![ProviderValidationResult::fail(
                    "",
                    "",
                    "provider.config.invalid",
                    "invalid_json",
                    format!("provider config is not valid JSON: {error}"),
                )])
            }
        };
        Self::from_value(&value)
    }

    pub fn from_value(value: &Value) -> Result<Self, Vec<ProviderValidationResult>> {
        let object = match value.as_object() {
            Some(object) => object,
            None => {
                return Err(vec![ProviderValidationResult::fail(
                    "",
                    "",
                    "provider.config.invalid",
                    "invalid_shape",
                    "provider config must be a JSON object",
                )])
            }
        };
        let provider_id = required_string(object, "provider_id");
        // Open registry: provider_kind / surface are free identifiers; an
        // unrecognized pair is rejected later by `validate_provider_binding`
        // against the assembled capability catalog, not here.
        let provider_kind = required_string(object, "provider_kind");
        let surface = required_string(object, "surface");
        let workspace_policy = optional_workspace_policy(object, "workspace_policy")
            .unwrap_or_else(|| Ok("shared".to_owned()));
        let artifact_policy =
            optional_string(object, "artifact_policy").unwrap_or_else(|| "optional".to_owned());
        let cancellation_depth =
            optional_enum_string(object, "cancellation_depth", CancellationDepth::from_str)
                .unwrap_or(Ok(CancellationDepth::None));
        let timeout_ms = optional_u64(object, "timeout_ms");
        let profile_ids = optional_string_array(object, "profile_ids");
        let health_checks = optional_string_array(object, "health_checks");

        let mut errors = Vec::new();
        let provider_id = match provider_id {
            Ok(provider_id) => provider_id,
            Err(error) => {
                errors.push(*error);
                String::new()
            }
        };
        let provider_kind = match provider_kind {
            Ok(provider_kind) => provider_kind,
            Err(error) => {
                errors.push(*error);
                String::new()
            }
        };
        let surface = match surface {
            Ok(surface) => surface,
            Err(error) => {
                errors.push(*error);
                String::new()
            }
        };
        let timeout_ms = match timeout_ms {
            Ok(timeout_ms) => timeout_ms,
            Err(error) => {
                errors.push(*error);
                None
            }
        };
        let workspace_policy = match workspace_policy {
            Ok(workspace_policy) => workspace_policy,
            Err(error) => {
                errors.push(*error);
                String::new()
            }
        };
        let cancellation_depth = match cancellation_depth {
            Ok(cancellation_depth) => cancellation_depth,
            Err(error) => {
                errors.push(*error);
                CancellationDepth::None
            }
        };
        let profile_ids = match profile_ids {
            Ok(profile_ids) => profile_ids,
            Err(error) => {
                errors.push(*error);
                Vec::new()
            }
        };
        let health_checks = match health_checks {
            Ok(health_checks) => health_checks,
            Err(error) => {
                errors.push(*error);
                Vec::new()
            }
        };
        if !errors.is_empty() {
            return Err(errors);
        }

        let known = [
            "provider_id",
            "provider_kind",
            "surface",
            "credentials_ref",
            "profile_ids",
            "default_model",
            "workspace_policy",
            "timeout_ms",
            "cancellation_depth",
            "artifact_policy",
            "health_checks",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let extra = object
            .iter()
            .filter(|(key, _)| !known.contains(key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();

        Ok(Self {
            provider_id,
            provider_kind,
            surface,
            credentials_ref: optional_string(object, "credentials_ref"),
            profile_ids,
            default_model: optional_string(object, "default_model"),
            workspace_policy,
            timeout_ms,
            cancellation_depth,
            artifact_policy,
            health_checks,
            extra,
        })
    }

    pub fn to_json_redacted(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "provider_kind": self.provider_kind.as_str(),
            "surface": self.surface.as_str(),
            "credentials_ref": self.credentials_ref,
            "profile_ids": self.profile_ids,
            "default_model": self.default_model,
            "workspace_policy": self.workspace_policy,
            "timeout_ms": self.timeout_ms,
            "cancellation_depth": self.cancellation_depth.as_str(),
            "artifact_policy": self.artifact_policy,
            "health_checks": self.health_checks,
            "extra_keys": self.extra.keys().cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderValidationResult {
    pub provider: String,
    pub surface: String,
    pub status: ProviderValidationStatus,
    pub phase: String,
    pub code: String,
    pub message: String,
    pub recoverable: bool,
    pub missing_config_refs: Vec<String>,
}

impl ProviderValidationResult {
    pub fn pass(
        provider: impl Into<String>,
        surface: impl Into<String>,
        phase: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            surface: surface.into(),
            status: ProviderValidationStatus::Pass,
            phase: phase.into(),
            code: code.into(),
            message: message.into(),
            recoverable: false,
            missing_config_refs: Vec::new(),
        }
    }

    pub fn fail(
        provider: impl Into<String>,
        surface: impl Into<String>,
        phase: impl Into<String>,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            surface: surface.into(),
            status: ProviderValidationStatus::Fail,
            phase: phase.into(),
            code: code.into(),
            message: message.into(),
            recoverable: true,
            missing_config_refs: Vec::new(),
        }
    }

    pub fn missing_ref(mut self, reference: impl Into<String>) -> Self {
        self.missing_config_refs.push(reference.into());
        self
    }

    pub fn to_json(&self) -> Value {
        json!({
            "provider": self.provider,
            "surface": self.surface,
            "status": self.status.as_str(),
            "phase": self.phase,
            "code": self.code,
            "message": self.message,
            "recoverable": self.recoverable,
            "missing_config_refs": self.missing_config_refs,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderTurnRequest {
    pub provider_id: String,
    pub provider_kind: String,
    pub surface: String,
    pub run_id: String,
    pub effect_id: String,
    pub agent: String,
    pub profile: Option<String>,
    pub prompt_json: Value,
    pub workspace_policy: String,
    pub required_capabilities: Vec<String>,
    pub cancellation_depth: CancellationDepth,
    pub artifact_policy: String,
    pub credential_ref: Option<String>,
    pub provider_options: BTreeMap<String, Value>,
}

impl NativeProviderTurnRequest {
    pub fn to_json_redacted(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "provider_kind": self.provider_kind.as_str(),
            "surface": self.surface.as_str(),
            "run_id": self.run_id,
            "effect_id": self.effect_id,
            "agent": self.agent,
            "profile": self.profile,
            "prompt_shape": json_shape(&self.prompt_json),
            "workspace_policy": self.workspace_policy,
            "required_capabilities": self.required_capabilities,
            "cancellation_depth": self.cancellation_depth.as_str(),
            "artifact_policy": self.artifact_policy,
            "credential_ref": self.credential_ref,
            "provider_option_keys": self.provider_options.keys().cloned().collect::<Vec<_>>(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProviderEventKind {
    Started,
    Streamed,
    ToolRequested,
    ArtifactCaptured,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Diagnostic,
}

impl NativeProviderEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Streamed => "streamed",
            Self::ToolRequested => "tool_requested",
            Self::ArtifactCaptured => "artifact_captured",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Diagnostic => "diagnostic",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::TimedOut | Self::Cancelled
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderArtifactRef {
    pub artifact_id: Option<String>,
    pub kind: String,
    pub uri: String,
    pub content_hash: Option<String>,
    pub mime_type: Option<String>,
    pub required: bool,
}

impl NativeProviderArtifactRef {
    pub fn to_json_redacted(&self) -> Value {
        json!({
            "artifact_id": self.artifact_id,
            "kind": self.kind,
            "uri": redact_sensitive_metadata(&self.uri),
            "content_hash": self
                .content_hash
                .as_deref()
                .map(redact_sensitive_metadata),
            "mime_type": self.mime_type,
            "required": self.required,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderEvent {
    pub provider_id: String,
    pub run_id: String,
    pub event_kind: NativeProviderEventKind,
    pub provider_event_type: String,
    pub provider_session_id: Option<String>,
    pub provider_turn_id: Option<String>,
    pub sequence: Option<u64>,
    pub evidence: Value,
    pub artifacts: Vec<NativeProviderArtifactRef>,
}

impl NativeProviderEvent {
    pub fn to_json_redacted(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "run_id": self.run_id,
            "event_kind": self.event_kind.as_str(),
            "terminal": self.event_kind.is_terminal(),
            "provider_event_type": self.provider_event_type,
            "provider_session_id": self.provider_session_id,
            "provider_turn_id": self.provider_turn_id,
            "sequence": self.sequence,
            "evidence_shape": json_shape(&self.evidence),
            "provider_error": self.redacted_provider_error(),
            "artifacts": self
                .artifacts
                .iter()
                .map(NativeProviderArtifactRef::to_json_redacted)
                .collect::<Vec<_>>(),
        })
    }

    /// The provider control-plane error reason carried on a terminal failure
    /// event's evidence, capped and secret-redacted before it crosses the
    /// shape-only redaction boundary. `Value::Null` when absent.
    pub fn redacted_provider_error(&self) -> Value {
        match self.evidence.get("provider_error").and_then(Value::as_str) {
            Some(message) => Value::String(redacted_provider_error_detail(message)),
            None => Value::Null,
        }
    }
}

/// Cap a provider control-plane error to a sane length and strip any secrets the
/// shared metadata redactor recognizes. Provider errors are operational strings
/// (usage limit, auth failure, model-not-found), not model output, but a cap +
/// secret scrub keeps a misbehaving provider from smuggling bulk content through.
pub fn redacted_provider_error_detail(message: &str) -> String {
    const MAX_PROVIDER_ERROR_CHARS: usize = 300;
    let redacted = redact_sensitive_metadata(message);
    if redacted.chars().count() > MAX_PROVIDER_ERROR_CHARS {
        let truncated: String = redacted.chars().take(MAX_PROVIDER_ERROR_CHARS).collect();
        format!("{truncated}…")
    } else {
        redacted
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderCancellation {
    pub run_id: String,
    pub provider_session_id: Option<String>,
    pub provider_turn_id: Option<String>,
    pub requested_depth: CancellationDepth,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProviderBoundaryError {
    pub provider_id: String,
    pub surface: String,
    pub code: String,
    pub message: String,
    pub recoverable: bool,
    pub evidence: Value,
}

impl NativeProviderBoundaryError {
    pub fn to_json_redacted(&self) -> Value {
        json!({
            "provider_id": self.provider_id,
            "surface": self.surface.as_str(),
            "code": self.code,
            "message": redact_sensitive_metadata(&self.message),
            "recoverable": self.recoverable,
            "evidence_shape": json_shape(&self.evidence),
        })
    }
}

// `NativeProviderBoundaryError` is a deliberately rich boundary-error value
// (provider id, surface, code, message, evidence) crossing the provider seam;
// boxing every `Result` here would churn every adapter impl for a micro-size
// win, so allow the large-Err variant on this trait and the validator below.
#[allow(clippy::result_large_err)]
pub trait NativeProviderAdapter {
    fn provider_id(&self) -> &str;
    fn capability(&self) -> &ProviderCapability;
    fn start_turn(
        &mut self,
        request: NativeProviderTurnRequest,
    ) -> Result<NativeProviderEvent, NativeProviderBoundaryError>;
    fn next_event(
        &mut self,
        run_id: &str,
    ) -> Result<Option<NativeProviderEvent>, NativeProviderBoundaryError>;
    fn cancel_turn(
        &mut self,
        cancellation: NativeProviderCancellation,
    ) -> Result<NativeProviderEvent, NativeProviderBoundaryError>;
}

#[allow(clippy::result_large_err)]
pub fn validate_native_cancellation_depth(
    config: &ProviderBindingConfig,
    capabilities: &[ProviderCapability],
    requested_depth: CancellationDepth,
) -> Result<(), NativeProviderBoundaryError> {
    let Some(capability) = capabilities.iter().find(|capability| {
        capability.provider_kind == config.provider_kind && capability.surface == config.surface
    }) else {
        return Err(native_boundary_error(
            config,
            "unsupported_surface",
            "provider kind and adapter surface do not match a registered capability",
            true,
            json!({}),
        ));
    };
    if !capability.supports_cancellation_depth(config.cancellation_depth) {
        return Err(native_boundary_error(
            config,
            "unsupported_configured_cancellation_depth",
            format!(
                "configured cancellation depth `{}` is not supported by provider capability",
                config.cancellation_depth.as_str()
            ),
            true,
            json!({
                "configured_depth": config.cancellation_depth.as_str(),
                "capability_depths": capability
                    .cancellation_depths
                    .iter()
                    .map(|depth| depth.as_str())
                    .collect::<Vec<_>>(),
            }),
        ));
    }
    if !config.cancellation_depth.allows(requested_depth) {
        return Err(native_boundary_error(
            config,
            "cancellation_depth_denied",
            format!(
                "requested cancellation depth `{}` exceeds configured depth `{}`",
                requested_depth.as_str(),
                config.cancellation_depth.as_str()
            ),
            false,
            json!({
                "requested_depth": requested_depth.as_str(),
                "configured_depth": config.cancellation_depth.as_str(),
            }),
        ));
    }
    Ok(())
}

fn native_boundary_error(
    config: &ProviderBindingConfig,
    code: impl Into<String>,
    message: impl Into<String>,
    recoverable: bool,
    evidence: Value,
) -> NativeProviderBoundaryError {
    NativeProviderBoundaryError {
        provider_id: config.provider_id.clone(),
        surface: config.surface.clone(),
        code: code.into(),
        message: message.into(),
        recoverable,
        evidence,
    }
}

pub fn builtin_provider_capabilities() -> Vec<ProviderCapability> {
    // Open registry (DR-0024): this returns only the kernel's OWN builtins
    // (the fixture and command surfaces). External providers — codex lives in
    // `whipplescript-provider-codex`, claude in `whipplescript-provider-claude`,
    // and any third party in its own crate — own their `ProviderCapability` and
    // the host extends this catalog with `capability()` from each crate it built.
    let caps: Vec<ProviderCapability> = vec![
        ProviderCapability {
            provider_kind: "fixture".to_owned(),
            surface: "fixture".to_owned(),
            protocol_version: Some("fixture".to_owned()),
            session_identity_fields: Vec::new(),
            stream_event_kinds: strings(&["completed", "failed", "timed_out", "cancelled"]),
            tool_policy: "none".to_owned(),
            cancellation_depths: vec![CancellationDepth::CooperativeRequest],
            artifact_manifest: false,
            health_checks: Vec::new(),
            auth_requirements: Vec::new(),
        },
        ProviderCapability {
            provider_kind: "command".to_owned(),
            surface: "command".to_owned(),
            protocol_version: Some("command-agent-harness".to_owned()),
            session_identity_fields: Vec::new(),
            stream_event_kinds: strings(&["completed", "failed", "timed_out"]),
            tool_policy: "adapter_defined".to_owned(),
            cancellation_depths: vec![CancellationDepth::None],
            artifact_manifest: true,
            health_checks: strings(&["executable"]),
            auth_requirements: Vec::new(),
        },
    ];
    caps
}

pub fn validate_provider_binding(
    config: &ProviderBindingConfig,
    capabilities: &[ProviderCapability],
) -> Vec<ProviderValidationResult> {
    let mut results = Vec::new();
    let provider = config.provider_id.clone();
    let surface = config.surface.as_str().to_owned();
    let capability = capabilities.iter().find(|capability| {
        capability.provider_kind == config.provider_kind && capability.surface == config.surface
    });

    let Some(capability) = capability else {
        return vec![ProviderValidationResult::fail(
            provider,
            surface,
            "provider.surface.unsupported",
            "unsupported_surface",
            "provider kind and adapter surface do not match a registered capability",
        )];
    };

    results.push(ProviderValidationResult::pass(
        provider.clone(),
        surface.clone(),
        "provider.surface.valid",
        "surface_supported",
        "provider kind and adapter surface are supported",
    ));

    if capability.supports_cancellation_depth(config.cancellation_depth) {
        results.push(ProviderValidationResult::pass(
            provider.clone(),
            surface.clone(),
            "provider.cancellation.valid",
            "cancellation_supported",
            "configured cancellation depth is supported by provider capability",
        ));
    } else {
        results.push(ProviderValidationResult::fail(
            provider.clone(),
            surface.clone(),
            "provider.cancellation.unsupported",
            "unsupported_cancellation_depth",
            format!(
                "configured cancellation depth `{}` is not supported by provider capability",
                config.cancellation_depth.as_str()
            ),
        ));
    }

    if capability.auth_requirements.is_empty() || config.credentials_ref.is_some() {
        results.push(ProviderValidationResult::pass(
            provider,
            surface,
            "provider.config.valid",
            "credentials_ref_available",
            "provider credential reference is available or not required",
        ));
    } else {
        results.push(
            ProviderValidationResult::fail(
                provider,
                surface,
                "provider.config.missing",
                "missing_credentials_ref",
                "provider credential reference is required for this native surface",
            )
            .missing_ref("credentials_ref"),
        );
    }

    results
}

pub fn validate_provider_binding_json(config_json: &str) -> Vec<ProviderValidationResult> {
    match ProviderBindingConfig::from_json_str(config_json) {
        Ok(config) => validate_provider_binding(&config, &builtin_provider_capabilities()),
        Err(results) => results,
    }
}

fn json_shape(value: &Value) -> Value {
    match value {
        Value::Null => json!({"type": "null"}),
        Value::Bool(_) => json!({"type": "bool"}),
        Value::Number(_) => json!({"type": "number"}),
        Value::String(value) => json!({"type": "string", "chars": value.chars().count()}),
        Value::Array(values) => json!({"type": "array", "items": values.len()}),
        Value::Object(object) => json!({
            "type": "object",
            "keys": object.keys().cloned().collect::<Vec<_>>(),
        }),
    }
}

pub fn redact_sensitive_metadata(value: &str) -> String {
    if value.contains("sk-")
        || value.contains("ANTHROPIC_API_KEY")
        || value.contains("OPENAI_API_KEY")
        || value.contains("token")
        || value.contains("secret")
    {
        "[REDACTED]".to_owned()
    } else {
        value.to_owned()
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn required_string(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<String, Box<ProviderValidationResult>> {
    match object.get(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value.to_owned()),
        _ => Err(Box::new(
            ProviderValidationResult::fail(
                "",
                "",
                "provider.config.invalid",
                "missing_required_field",
                format!("provider config missing required string `{key}`"),
            )
            .missing_ref(key),
        )),
    }
}

fn optional_string(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned)
}

fn optional_workspace_policy(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Option<Result<String, Box<ProviderValidationResult>>> {
    optional_string(object, key).map(|value| match value.as_str() {
        "shared"
        | "read_only"
        | "per_effect_worktree"
        | "per_issue_worktree"
        | "remote_sandbox" => Ok(value),
        _ => Err(Box::new(ProviderValidationResult::fail(
            "",
            "",
            "provider.config.invalid",
            "unsupported_workspace_policy",
            format!("provider config `{key}` has unsupported value `{value}`"),
        ))),
    })
}

fn optional_enum_string<T>(
    object: &serde_json::Map<String, Value>,
    key: &str,
    parse: impl FnOnce(&str) -> Option<T>,
) -> Option<Result<T, Box<ProviderValidationResult>>> {
    optional_string(object, key).map(|value| {
        parse(&value).ok_or_else(|| {
            Box::new(ProviderValidationResult::fail(
                "",
                "",
                "provider.config.invalid",
                "unknown_enum_value",
                format!("provider config `{key}` has unknown value `{value}`"),
            ))
        })
    })
}

fn optional_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, Box<ProviderValidationResult>> {
    match object.get(key) {
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            Box::new(ProviderValidationResult::fail(
                "",
                "",
                "provider.config.invalid",
                "invalid_integer",
                format!("provider config `{key}` must be an unsigned integer"),
            ))
        }),
        None => Ok(None),
    }
}

fn optional_string_array(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Vec<String>, Box<ProviderValidationResult>> {
    let Some(value) = object.get(key) else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(Box::new(ProviderValidationResult::fail(
            "",
            "",
            "provider.config.invalid",
            "invalid_array",
            format!("provider config `{key}` must be an array of strings"),
        )));
    };
    let mut output = Vec::new();
    for item in values {
        let Some(item) = item.as_str() else {
            return Err(Box::new(ProviderValidationResult::fail(
                "",
                "",
                "provider.config.invalid",
                "invalid_array_item",
                format!("provider config `{key}` must contain only strings"),
            )));
        };
        output.push(item.to_owned());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_capabilities_capture_distinct_native_surfaces() {
        // Open registry (DR-0024): the kernel builtin catalog holds ONLY the
        // kernel's own surfaces (fixture, command). Codex and claude moved to
        // their own crates; the host appends their `capability()`.
        let capabilities = builtin_provider_capabilities();

        assert!(capabilities
            .iter()
            .all(|capability| capability.provider_kind != "codex"
                && capability.provider_kind != "claude"));
        assert!(capabilities.iter().any(|capability| {
            capability.provider_kind == "fixture" && capability.surface == "fixture"
        }));
        assert!(capabilities.iter().any(|capability| {
            capability.provider_kind == "command"
                && capability.surface == "command"
                && capability.cancellation_depths == vec![CancellationDepth::None]
        }));
    }

    #[test]
    fn parses_valid_codex_provider_binding_config() {
        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "codex-main",
              "provider_kind": "codex",
              "surface": "codex_app_server",
              "credentials_ref": "secret:codex",
              "profile_ids": ["repo-writer"],
              "default_model": "gpt-5.5",
              "workspace_policy": "per_effect_worktree",
              "timeout_ms": 600000,
              "cancellation_depth": "native_stop",
              "artifact_policy": "required",
              "health_checks": ["schema", "auth"],
              "secret_value": "do-not-print"
            }"#,
        )
        .expect("config parses");

        assert_eq!(config.provider_id, "codex-main");
        assert_eq!(config.provider_kind, "codex".to_owned());
        assert_eq!(config.surface, "codex_app_server".to_owned());
        assert_eq!(config.cancellation_depth, CancellationDepth::NativeStop);
        assert_eq!(
            config.to_json_redacted()["extra_keys"],
            json!(["secret_value"])
        );
        assert!(!config
            .to_json_redacted()
            .to_string()
            .contains("do-not-print"));
    }

    #[test]
    fn rejects_mixed_provider_kind_and_surface() {
        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "bad-claude",
              "provider_kind": "claude",
              "surface": "codex_app_server",
              "credentials_ref": "secret:claude"
            }"#,
        )
        .expect("config shape parses");

        let results = validate_provider_binding(&config, &builtin_provider_capabilities());

        assert!(results.iter().any(|result| {
            result.status == ProviderValidationStatus::Fail && result.code == "unsupported_surface"
        }));
    }

    #[test]
    fn rejects_unknown_workspace_policy() {
        let results = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "codex-main",
              "provider_kind": "codex",
              "surface": "codex_app_server",
              "workspace_policy": "host_everything"
            }"#,
        )
        .expect_err("workspace policy is invalid");

        assert!(results.iter().any(|result| {
            result.status == ProviderValidationStatus::Fail
                && result.code == "unsupported_workspace_policy"
        }));
    }

    #[test]
    fn reports_missing_credentials_without_secret_values() {
        // No kernel builtin requires credentials, so validate against a
        // synthetic auth-requiring capability (open registry): the guard must
        // report the missing reference without echoing any secret value.
        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "claude-main",
              "provider_kind": "claude",
              "surface": "claude_agent_sdk"
            }"#,
        )
        .expect("config parses");
        let capabilities = vec![ProviderCapability {
            provider_kind: "claude".to_owned(),
            surface: "claude_agent_sdk".to_owned(),
            protocol_version: None,
            session_identity_fields: Vec::new(),
            stream_event_kinds: Vec::new(),
            tool_policy: "none".to_owned(),
            cancellation_depths: vec![CancellationDepth::None],
            artifact_manifest: true,
            health_checks: Vec::new(),
            auth_requirements: vec!["anthropic_api_key_or_provider_config_ref".to_owned()],
        }];

        let results = validate_provider_binding(&config, &capabilities);
        let missing = results
            .iter()
            .find(|result| result.code == "missing_credentials_ref")
            .expect("missing credentials reported");
        assert_eq!(missing.missing_config_refs, vec!["credentials_ref"]);
        assert!(!missing.to_json().to_string().contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn rejects_unrecognized_provider_surface_at_validation() {
        // Open registry (DR-0024): provider_kind / surface are free strings, so
        // an unrecognized surface now PARSES cleanly and is rejected by
        // `validate_provider_binding` against the assembled capability catalog —
        // no more parse-time `unknown_enum_value`.
        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "codex-main",
              "provider_kind": "codex",
              "surface": "plain_command"
            }"#,
        )
        .expect("free-string surface parses under the open registry");

        let results = validate_provider_binding(&config, &builtin_provider_capabilities());
        assert!(results.iter().any(|result| {
            result.status == ProviderValidationStatus::Fail && result.code == "unsupported_surface"
        }));
    }

    #[test]
    fn native_turn_request_redacts_prompt_and_provider_options() {
        let mut provider_options = BTreeMap::new();
        provider_options.insert("api_token".to_owned(), json!("sk-never-print"));
        let request = NativeProviderTurnRequest {
            provider_id: "codex-main".to_owned(),
            provider_kind: "codex".to_owned(),
            surface: "codex_app_server".to_owned(),
            run_id: "run-1".to_owned(),
            effect_id: "tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            prompt_json: json!({"prompt": "contains sk-never-print"}),
            workspace_policy: "per_effect_worktree".to_owned(),
            required_capabilities: vec!["repo.write".to_owned()],
            cancellation_depth: CancellationDepth::NativeStop,
            artifact_policy: "required".to_owned(),
            credential_ref: Some("secret:codex".to_owned()),
            provider_options,
        };

        let redacted = request.to_json_redacted();

        assert_eq!(
            redacted
                .pointer("/prompt_shape/type")
                .and_then(Value::as_str),
            Some("object")
        );
        assert_eq!(
            redacted
                .pointer("/provider_option_keys/0")
                .and_then(Value::as_str),
            Some("api_token")
        );
        assert!(!redacted.to_string().contains("sk-never-print"));
    }

    #[test]
    fn native_provider_event_preserves_shape_without_raw_payload() {
        let event = NativeProviderEvent {
            provider_id: "codex-main".to_owned(),
            run_id: "run-1".to_owned(),
            event_kind: NativeProviderEventKind::Cancelled,
            provider_event_type: "turn_end".to_owned(),
            provider_session_id: Some("session-1".to_owned()),
            provider_turn_id: None,
            sequence: Some(7),
            evidence: json!({
                "message": {
                    "content": "raw provider text with sk-never-print"
                }
            }),
            artifacts: vec![NativeProviderArtifactRef {
                artifact_id: Some("artifact-1".to_owned()),
                kind: "transcript".to_owned(),
                uri: "provider://codex/runs/run-1/secret/transcript".to_owned(),
                content_hash: Some("sha256:secret-token".to_owned()),
                mime_type: Some("text/plain".to_owned()),
                required: true,
            }],
        };

        let redacted = event.to_json_redacted();

        assert_eq!(
            redacted.get("terminal").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            redacted
                .pointer("/evidence_shape/type")
                .and_then(Value::as_str),
            Some("object")
        );
        assert_eq!(
            redacted.pointer("/artifacts/0/uri").and_then(Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            redacted
                .pointer("/artifacts/0/content_hash")
                .and_then(Value::as_str),
            Some("[REDACTED]")
        );
        assert!(!redacted.to_string().contains("sk-never-print"));
    }

    #[test]
    fn native_provider_boundary_error_redacts_message_and_evidence() {
        let error = NativeProviderBoundaryError {
            provider_id: "claude-main".to_owned(),
            surface: "claude_agent_sdk".to_owned(),
            code: "auth_failed".to_owned(),
            message: "ANTHROPIC_API_KEY sk-never-print failed".to_owned(),
            recoverable: true,
            evidence: json!({"headers": {"Authorization": "sk-never-print"}}),
        };

        let redacted = error.to_json_redacted();

        assert_eq!(
            redacted.get("message").and_then(Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            redacted
                .pointer("/evidence_shape/type")
                .and_then(Value::as_str),
            Some("object")
        );
        assert!(!redacted.to_string().contains("sk-never-print"));
    }

    #[test]
    fn native_adapter_trait_supports_distinct_start_stream_and_cancel_events() {
        struct FakeNativeAdapter {
            capability: ProviderCapability,
            started: bool,
        }

        impl NativeProviderAdapter for FakeNativeAdapter {
            fn provider_id(&self) -> &str {
                "fake-codex"
            }

            fn capability(&self) -> &ProviderCapability {
                &self.capability
            }

            fn start_turn(
                &mut self,
                request: NativeProviderTurnRequest,
            ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
                self.started = true;
                Ok(NativeProviderEvent {
                    provider_id: request.provider_id,
                    run_id: request.run_id,
                    event_kind: NativeProviderEventKind::Started,
                    provider_event_type: "turn_start".to_owned(),
                    provider_session_id: Some("session-1".to_owned()),
                    provider_turn_id: None,
                    sequence: Some(1),
                    evidence: json!({"codex_shape": "turn_start"}),
                    artifacts: Vec::new(),
                })
            }

            fn next_event(
                &mut self,
                run_id: &str,
            ) -> Result<Option<NativeProviderEvent>, NativeProviderBoundaryError> {
                assert!(self.started);
                Ok(Some(NativeProviderEvent {
                    provider_id: "fake-codex".to_owned(),
                    run_id: run_id.to_owned(),
                    event_kind: NativeProviderEventKind::Streamed,
                    provider_event_type: "message_end".to_owned(),
                    provider_session_id: Some("session-1".to_owned()),
                    provider_turn_id: None,
                    sequence: Some(2),
                    evidence: json!({"codex_shape": "message_end"}),
                    artifacts: Vec::new(),
                }))
            }

            fn cancel_turn(
                &mut self,
                cancellation: NativeProviderCancellation,
            ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
                Ok(NativeProviderEvent {
                    provider_id: "fake-codex".to_owned(),
                    run_id: cancellation.run_id,
                    event_kind: NativeProviderEventKind::Cancelled,
                    provider_event_type: "turn_end".to_owned(),
                    provider_session_id: cancellation.provider_session_id,
                    provider_turn_id: cancellation.provider_turn_id,
                    sequence: Some(3),
                    evidence: json!({"stopReason": "aborted"}),
                    artifacts: Vec::new(),
                })
            }
        }

        // Self-contained synthetic capability — this test exercises the
        // NativeProviderAdapter trait mechanics (start/stream/cancel), not the
        // catalog, so it does not depend on any provider being registered.
        let capability = ProviderCapability {
            provider_kind: "codex".to_owned(),
            surface: "codex_app_server".to_owned(),
            protocol_version: None,
            session_identity_fields: Vec::new(),
            stream_event_kinds: Vec::new(),
            tool_policy: "none".to_owned(),
            cancellation_depths: vec![CancellationDepth::NativeStop],
            artifact_manifest: false,
            health_checks: Vec::new(),
            auth_requirements: Vec::new(),
        };
        let mut adapter = FakeNativeAdapter {
            capability,
            started: false,
        };
        let request = NativeProviderTurnRequest {
            provider_id: "fake-codex".to_owned(),
            provider_kind: "codex".to_owned(),
            surface: "codex_app_server".to_owned(),
            run_id: "run-1".to_owned(),
            effect_id: "tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-reader".to_owned()),
            prompt_json: json!({"prompt": "go"}),
            workspace_policy: "read_only".to_owned(),
            required_capabilities: vec!["repo.read".to_owned()],
            cancellation_depth: CancellationDepth::NativeStop,
            artifact_policy: "optional".to_owned(),
            credential_ref: Some("secret:codex".to_owned()),
            provider_options: BTreeMap::new(),
        };

        let started = adapter.start_turn(request).expect("start event");
        let streamed = adapter
            .next_event("run-1")
            .expect("stream result")
            .expect("stream event");
        let cancelled = adapter
            .cancel_turn(NativeProviderCancellation {
                run_id: "run-1".to_owned(),
                provider_session_id: Some("session-1".to_owned()),
                provider_turn_id: None,
                requested_depth: CancellationDepth::NativeStop,
                reason: "operator".to_owned(),
            })
            .expect("cancel event");

        assert_eq!(adapter.provider_id(), "fake-codex");
        assert_eq!(adapter.capability().surface, "codex_app_server".to_owned());
        assert_eq!(started.event_kind, NativeProviderEventKind::Started);
        assert_eq!(streamed.provider_event_type, "message_end");
        assert_eq!(cancelled.event_kind, NativeProviderEventKind::Cancelled);
        assert!(cancelled.event_kind.is_terminal());
    }

    #[test]
    fn cancellation_depth_guard_allows_requests_within_configured_depth() {
        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "codex-main",
              "provider_kind": "codex",
              "surface": "codex_app_server",
              "credentials_ref": "secret:codex",
              "cancellation_depth": "native_stop"
            }"#,
        )
        .expect("config parses");

        // Synthetic catalog: a native_stop-capable surface. No kernel builtin
        // advertises native_stop anymore (codex moved to its own crate,
        // DR-0024), so the depth-guard logic is exercised against an assembled
        // capability rather than the builtin set.
        let capabilities = vec![ProviderCapability {
            provider_kind: "codex".to_owned(),
            surface: "codex_app_server".to_owned(),
            protocol_version: None,
            session_identity_fields: Vec::new(),
            stream_event_kinds: Vec::new(),
            tool_policy: "none".to_owned(),
            cancellation_depths: vec![CancellationDepth::NativeStop],
            artifact_manifest: false,
            health_checks: Vec::new(),
            auth_requirements: Vec::new(),
        }];

        validate_native_cancellation_depth(
            &config,
            &capabilities,
            CancellationDepth::CooperativeRequest,
        )
        .expect("cooperative request is within native-stop depth");
        validate_native_cancellation_depth(&config, &capabilities, CancellationDepth::NativeStop)
            .expect("native stop request matches configured depth");
    }

    #[test]
    fn cancellation_depth_guard_rejects_requests_deeper_than_configured_depth() {
        // Fixture advertises cooperative_request, so the configured depth is
        // capability-supported and the failure isolates requested > configured.
        // (Claude can no longer serve this case: its catalog depth is None per
        // DR-0017 — see claude_advertises_no_cancellation_depth_per_dr0017.)
        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "fixture-main",
              "provider_kind": "fixture",
              "surface": "fixture",
              "cancellation_depth": "cooperative_request"
            }"#,
        )
        .expect("config parses");

        let error = validate_native_cancellation_depth(
            &config,
            &builtin_provider_capabilities(),
            CancellationDepth::NativeStop,
        )
        .expect_err("native stop exceeds configured depth");

        assert_eq!(error.code, "cancellation_depth_denied");
        assert_eq!(error.provider_id, "fixture-main");
        assert_eq!(
            error
                .to_json_redacted()
                .pointer("/evidence_shape/type")
                .and_then(Value::as_str),
            Some("object")
        );
    }

    /// DR-0017 conformance (std-agent slice 2), validation-plane half: when a
    /// capability advertises NO cancellation depth, both validation planes must
    /// refuse a binding that claims `cooperative_request`. (The claude
    /// capability's own `None` advertisement is asserted in
    /// whipplescript-provider-claude.) Uses a synthetic no-depth capability so
    /// the kernel test is provider-agnostic.
    #[test]
    fn no_depth_capability_refuses_cooperative_request_per_dr0017() {
        let capabilities = vec![ProviderCapability {
            provider_kind: "claude".to_owned(),
            surface: "claude_agent_sdk".to_owned(),
            protocol_version: None,
            session_identity_fields: Vec::new(),
            stream_event_kinds: Vec::new(),
            tool_policy: "none".to_owned(),
            cancellation_depths: vec![CancellationDepth::None],
            artifact_manifest: true,
            health_checks: Vec::new(),
            auth_requirements: Vec::new(),
        }];

        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "claude-main",
              "provider_kind": "claude",
              "surface": "claude_agent_sdk",
              "credentials_ref": "secret:claude",
              "cancellation_depth": "cooperative_request"
            }"#,
        )
        .expect("config parses");

        let results = validate_provider_binding(&config, &capabilities);
        assert!(results.iter().any(|result| {
            result.status == ProviderValidationStatus::Fail
                && result.code == "unsupported_cancellation_depth"
        }));

        let error = validate_native_cancellation_depth(
            &config,
            &capabilities,
            CancellationDepth::CooperativeRequest,
        )
        .expect_err("configured cooperative_request is not capability-supported");
        assert_eq!(error.code, "unsupported_configured_cancellation_depth");
    }

    #[test]
    fn cancellation_depth_guard_rejects_configured_depth_not_supported_by_capability() {
        let config = ProviderBindingConfig::from_json_str(
            r#"{
              "provider_id": "fixture-main",
              "provider_kind": "fixture",
              "surface": "fixture",
              "cancellation_depth": "native_stop"
            }"#,
        )
        .expect("config parses");

        let error = validate_native_cancellation_depth(
            &config,
            &builtin_provider_capabilities(),
            CancellationDepth::NativeStop,
        )
        .expect_err("fixture does not support native stop");

        assert_eq!(error.code, "unsupported_configured_cancellation_depth");
    }
}
