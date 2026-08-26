//! Provider-native structured-output `coerce` client.
//!
//! This is the real LLM integration behind the `coerce` effect (the fixture
//! path stays in `coerce.rs`). It calls each provider's NATIVE structured-output
//! feature directly:
//!
//! - **OpenAI**: POST the Responses endpoint with a `text.format` JSON-schema
//!   constraint (`type: "json_schema"`).
//! - **Anthropic**: POST the Messages endpoint with a single tool whose
//!   `input_schema` is the output schema and a forced `tool_choice` (tool-use
//!   forces a structured argument object).
//!
//! Everything here is pure and unit/mock-testable: request construction and
//! response parsing are plain functions, and the only side effect — the socket
//! write — lives behind the [`CoerceTransport`] trait. The CLI supplies the real
//! `ureq`-backed transport (kernel stays network-free); tests inject a fake
//! transport. The live network call is credential-gated (see `whip auth`).

use crate::coerce::{CoerceClient, CoerceRequest, CoerceResult, CoerceStatus};
use serde_json::{json, Map, Value};
use whipplescript_parser::{IrClassField, IrPrimitiveType, IrProgram, IrSchema, IrType};

/// Which provider API the native client targets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoerceProvider {
    /// OpenAI's Responses API (`/v1/responses`).
    OpenAi,
    /// A generic OpenAI-**compatible** endpoint speaking the Chat Completions API
    /// (`/v1/chat/completions`) — OpenRouter, Together, Groq, vLLM, Ollama, LM Studio,
    /// etc. Same wire family as OpenAi but the older, near-universally-implemented API.
    OpenAiCompat,
    Anthropic,
    /// xAI's Grok API — the Chat Completions wire at `https://api.x.ai/v1`.
    /// Same wire family as [`CoerceProvider::OpenAiCompat`] but a first-class
    /// backend: its own credential surface (`XAI_API_KEY` / `whip auth set
    /// xai`), never the OpenAI one, and a known default base URL.
    Xai,
}

impl CoerceProvider {
    /// Default API base URL (overridable for the Codex backend or a mock).
    pub fn default_base_url(self) -> &'static str {
        match self {
            // The OpenAi (Responses) and Anthropic builders append the full
            // `/v1/...` path themselves, so their default base is the bare host.
            CoerceProvider::OpenAi => "https://api.openai.com",
            CoerceProvider::Anthropic => "https://api.anthropic.com",
            // The OpenAiCompat builder appends only `/chat/completions` (the
            // OpenAI-SDK `base_url` convention: the `/v1` version segment lives
            // in base_url), so the default MUST carry `/v1` — otherwise the
            // request 404s at `.../chat/completions`. Live-confirmed 2026-07-19.
            CoerceProvider::OpenAiCompat => "https://api.openai.com/v1",
            // Same `/v1`-in-base convention as OpenAiCompat: the builder
            // appends only `/chat/completions`.
            CoerceProvider::Xai => "https://api.x.ai/v1",
        }
    }
}

/// Default `max_tokens` for a coerce call — owned ONCE by std.coercion
/// (spec/std-coercion.md "Config-plane reconciliation"); both operator doors
/// (native env + `whip auth`, DO `coerce_config_json`) inherit it.
pub const DEFAULT_COERCE_MAX_TOKENS: u32 = 4096;
/// Default coerce timeout in seconds, owned once alongside
/// [`DEFAULT_COERCE_MAX_TOKENS`].
pub const DEFAULT_COERCE_TIMEOUT_SECS: u64 = 120;

/// The ONE canonical resolved coerce configuration record
/// (spec/std-coercion.md "Config-plane reconciliation"). Both operator doors
/// build exactly this: the native CLI resolver (env + `whip auth` + registry
/// default — `coerce_runtime`) and the DO secrets door (`coerce_config_json`,
/// `do_wasm::parse_coerce_config`). The kernel and both hosts see only the
/// record, never a plane.
pub struct ResolvedCoercionConfig {
    /// The selected `schema_coercer` provider id as recorded on runs/terminals
    /// and folded into the coercion-config fingerprint (e.g. `native`, or the
    /// backend name when the operator override selects one directly).
    pub provider_id: String,
    /// Which provider API the call targets (config, not a separate provider —
    /// spec/std-coercion.md "Providers").
    pub backend: CoerceProvider,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub max_tokens: u32,
    pub timeout_secs: u64,
    /// `Some(account_id)` when the OpenAI credential is the Codex OAuth token,
    /// so the call targets the codex backend (SSE) instead of `api.openai.com`.
    /// A native-door affordance: the DO secrets door carries explicit API keys
    /// only and always leaves this `None`.
    pub codex_account_id: Option<String>,
}

// Credentials are operator-plane secrets and never enter logs/facts/evidence:
// Debug redacts the key (only its presence is reported).
impl std::fmt::Debug for ResolvedCoercionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedCoercionConfig")
            .field("provider_id", &self.provider_id)
            .field("backend", &self.backend)
            .field("base_url", &self.base_url)
            .field(
                "api_key",
                &if self.api_key.is_empty() {
                    "<none>"
                } else {
                    "<redacted>"
                },
            )
            .field("model", &self.model)
            .field("max_tokens", &self.max_tokens)
            .field("timeout_secs", &self.timeout_secs)
            .field("codex_account_id", &self.codex_account_id)
            .finish()
    }
}

// The transport-agnostic HTTP types now live in the neutral `sansio` module
// (shared with agent turns and, later, file effects); re-exported here so the
// many `coerce_native::{HttpRequest, HttpResponse, CoerceTransportError}` paths
// keep resolving. `CoerceTransportError` is the coerce-facing name for the
// shared `sansio::TransportError`.
use crate::sansio::{run_to_completion, HostDriver, IoRequest, IoResult, Outcome, StepMachine};
pub use crate::sansio::{HttpRequest, HttpResponse, TransportError as CoerceTransportError};

/// The single side effect: POST a request and decode a JSON response. The real
/// impl lives in the CLI (`ureq`); tests inject a fake. Every `CoerceTransport`
/// is a sans-IO [`HostDriver`] (blanket impl below), so a coerce step machine
/// can be driven by any transport the codebase already has.
pub trait CoerceTransport {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, CoerceTransportError>;
}

/// Any HTTP transport is a host driver: fulfilling an [`IoRequest::Http`] is just
/// posting it. This bridges the existing `ureq`/fake transports into the sans-IO
/// [`HostDriver`] seam without changing them.
impl<T: CoerceTransport + ?Sized> HostDriver for T {
    fn fulfill(&self, request: &IoRequest) -> IoResult {
        match request {
            IoRequest::Http(http) => IoResult::Http(self.post(http)),
        }
    }
}

// -- JSON Schema synthesis ------------------------------------------------

/// Bound on schema recursion so a cyclic class ref (`class Node { child Node }`)
/// cannot infinitely recurse; beyond it the subtree is left unconstrained.
const MAX_SCHEMA_DEPTH: usize = 16;

/// Build a JSON Schema `Value` for a whip `IrType`, resolving `Ref`s against the
/// program's schema registry. Used to constrain the provider's structured output.
pub fn json_schema_for_type(ty: &IrType, schemas: &[IrSchema]) -> Value {
    schema_with_depth(ty, schemas, 0)
}

fn schema_with_depth(ty: &IrType, schemas: &[IrSchema], depth: usize) -> Value {
    if depth > MAX_SCHEMA_DEPTH {
        return json!({});
    }
    match ty {
        IrType::Primitive(primitive) => primitive_schema(primitive),
        IrType::LiteralString(literal) => json!({ "type": "string", "const": literal }),
        IrType::Ref(name) => schema_for_ref(name, schemas, depth),
        // An AgentRef is a string-named agent at the boundary.
        IrType::AgentRef(agents) => {
            json!({ "type": "string", "enum": agents.clone() })
        }
        IrType::Object(fields) => object_schema(fields, schemas, depth),
        // `Missing`/optional: allow the value to be null so absence validates
        // even though strict mode keeps the property `required`.
        IrType::Optional(inner) => nullable(schema_with_depth(inner, schemas, depth + 1)),
        IrType::Array(inner) => json!({
            "type": "array",
            "items": schema_with_depth(inner, schemas, depth + 1),
        }),
        // A map is an object with homogeneous additional properties.
        IrType::Map(value_ty) => json!({
            "type": "object",
            "additionalProperties": schema_with_depth(value_ty, schemas, depth + 1),
        }),
        // DR-0074 §10: a sealed value is ciphertext the custodian produced.
        // No model output can validate as one, so like `secret` (DR-0053 §5)
        // its schema is `false` — nothing satisfies it.
        IrType::Sealed(_) => json!(false),
        IrType::Union(variants) => union_schema(variants, schemas, depth),
    }
}

/// A union of only string literals collapses to a single `enum` (cleaner and
/// more widely supported than `anyOf` of `const`s); a mixed union stays `anyOf`.
fn union_schema(variants: &[IrType], schemas: &[IrSchema], depth: usize) -> Value {
    let literals: Option<Vec<&str>> = variants
        .iter()
        .map(|variant| match variant {
            IrType::LiteralString(literal) => Some(literal.as_str()),
            _ => None,
        })
        .collect();
    match literals {
        Some(values) if !values.is_empty() => json!({ "type": "string", "enum": values }),
        _ => json!({
            "anyOf": variants
                .iter()
                .map(|variant| schema_with_depth(variant, schemas, depth + 1))
                .collect::<Vec<_>>(),
        }),
    }
}

fn primitive_schema(primitive: &IrPrimitiveType) -> Value {
    match primitive {
        IrPrimitiveType::String => json!({ "type": "string" }),
        IrPrimitiveType::Int => json!({ "type": "integer" }),
        IrPrimitiveType::Float => json!({ "type": "number" }),
        IrPrimitiveType::Bool => json!({ "type": "boolean" }),
        IrPrimitiveType::Null => json!({ "type": "null" }),
        // Durations/times serialize as strings at the boundary; media types are
        // out-of-band references the model returns as strings.
        IrPrimitiveType::Duration
        | IrPrimitiveType::Time
        | IrPrimitiveType::Image
        | IrPrimitiveType::Audio
        | IrPrimitiveType::Pdf
        | IrPrimitiveType::Video => json!({ "type": "string" }),
        // The `false` schema matches nothing: a model can never produce a
        // secret (DR-0053 §5 — material enters only via the custodian).
        IrPrimitiveType::Secret => json!(false),
    }
}

fn schema_for_ref(name: &str, schemas: &[IrSchema], depth: usize) -> Value {
    for schema in schemas {
        match schema {
            IrSchema::Enum(enum_decl) if enum_decl.name == name => {
                // A payload-carrying (sum-type) enum lowers each data variant to a
                // generated class `<Enum>.<Variant>` (with a synthesized `variant`
                // const discriminant). Emit `anyOf` over the variants so the provider
                // can construct payloads, not just a bare variant name; a variant with
                // no generated class (a bare tag) stays a string `const`. A fully-bare
                // enum collapses to a single string `enum` (cleaner, widely supported).
                let mut alternatives = Vec::with_capacity(enum_decl.variants.len());
                let mut any_payload = false;
                for variant in &enum_decl.variants {
                    let class_name = format!("{}.{}", enum_decl.name, variant);
                    match find_class_fields(&class_name, schemas) {
                        Some(fields) => {
                            any_payload = true;
                            alternatives.push(object_schema(fields, schemas, depth + 1));
                        }
                        None => alternatives.push(json!({ "type": "string", "const": variant })),
                    }
                }
                return if any_payload {
                    json!({ "anyOf": alternatives })
                } else {
                    json!({ "type": "string", "enum": enum_decl.variants.clone() })
                };
            }
            IrSchema::Class(class_decl) if class_decl.name == name => {
                return object_schema(&class_decl.fields, schemas, depth);
            }
            _ => {}
        }
    }
    // Unknown ref (e.g. a built-in): leave unconstrained rather than reject — the
    // compiler already validates references, so this is a defensive fallback.
    json!({})
}

/// Look up a class declaration's fields by name (used to resolve a sum-type enum's
/// generated `<Enum>.<Variant>` payload classes).
fn find_class_fields<'a>(name: &str, schemas: &'a [IrSchema]) -> Option<&'a [IrClassField]> {
    schemas.iter().find_map(|schema| match schema {
        IrSchema::Class(class_decl) if class_decl.name == name => {
            Some(class_decl.fields.as_slice())
        }
        _ => None,
    })
}

fn object_schema(fields: &[IrClassField], schemas: &[IrSchema], depth: usize) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in fields {
        properties.insert(
            field.name.clone(),
            schema_with_depth(&field.ty, schemas, depth + 1),
        );
        // Strict structured-output mode (OpenAI `strict: true`) requires every
        // property in `required`; a genuinely-optional field expresses absence
        // through nullability (`anyOf [T, null]`, see the `Optional` arm), not by
        // omission from `required`.
        required.push(Value::String(field.name.clone()));
    }
    json!({
        "type": "object",
        "properties": Value::Object(properties),
        "required": required,
        "additionalProperties": false,
    })
}

fn nullable(schema: Value) -> Value {
    json!({ "anyOf": [schema, { "type": "null" }] })
}

/// The provider structured-output root must be a JSON object. For an output type
/// that is not object-shaped (enum, primitive, array, union), wrap it in a
/// single `value` property; the caller unwraps `.value` on parse.
///
/// Returns `(object_schema, wrapped)`.
pub fn output_schema_envelope(ty: &IrType, schemas: &[IrSchema]) -> (Value, bool) {
    let resolved_object = match ty {
        IrType::Object(_) => true,
        IrType::Ref(name) => schema_ref_is_class(name, schemas),
        _ => false,
    };
    if resolved_object {
        (json_schema_for_type(ty, schemas), false)
    } else {
        let inner = json_schema_for_type(ty, schemas);
        let wrapped = json!({
            "type": "object",
            "properties": { "value": inner },
            "required": ["value"],
            "additionalProperties": false,
        });
        (wrapped, true)
    }
}

fn schema_ref_is_class(name: &str, schemas: &[IrSchema]) -> bool {
    schemas.iter().any(|schema| match schema {
        IrSchema::Class(class_decl) => class_decl.name == name,
        IrSchema::Enum(_) => false,
    })
}

// -- Request construction (pure) -----------------------------------------

/// Codex-backend (ChatGPT-plan OAuth) parameters. When present on an OpenAI
/// call, the request targets `chatgpt.com/backend-api/codex/responses` with the
/// codex headers and an SSE-streamed Responses body, instead of the standard
/// `api.openai.com/v1/responses` JSON endpoint. Validated 2026-06-23: the codex
/// backend honors `text.format` json_schema structured outputs.
#[derive(Clone, Copy, Debug)]
pub struct CodexAuth<'a> {
    pub account_id: &'a str,
    pub session_id: &'a str,
}

/// Inputs needed to build a provider request, independent of transport/creds.
#[derive(Clone, Debug)]
pub struct CoerceCall<'a> {
    pub provider: CoerceProvider,
    pub base_url: &'a str,
    pub api_key: &'a str,
    pub model: &'a str,
    /// Fully interpolated prompt (arguments already substituted).
    pub prompt: &'a str,
    /// Object-rooted output schema (see [`output_schema_envelope`]).
    pub output_schema: &'a Value,
    /// A stable name for the schema/tool (the output type name).
    pub schema_name: &'a str,
    /// Upper bound on output tokens (Anthropic requires `max_tokens`).
    pub max_tokens: u32,
    /// When set (OpenAI + a ChatGPT-plan OAuth token), use the codex backend.
    pub codex: Option<CodexAuth<'a>>,
    /// Stable per-effect `Idempotency-Key` (DR-0033): the same value across a
    /// resume/retry of the same coerce effect, unique per distinct effect —
    /// derived from `(instance_id, effect_id)`. Sent as an `Idempotency-Key`
    /// request header so OpenAI/codex dedupe a duplicate call after a worker
    /// eviction (the fetch reached the provider but the response never recorded).
    /// Empty on the fixture/no-key path — then no header is emitted and the
    /// request stays byte-identical to before.
    pub idempotency_key: &'a str,
}

/// Build the HTTP request for a coerce call. Auth headers are included so the
/// transport stays a dumb pipe.
pub fn build_request(call: &CoerceCall<'_>) -> HttpRequest {
    match call.provider {
        CoerceProvider::OpenAi => match call.codex {
            Some(codex) => build_codex_request(call, codex),
            None => build_openai_request(call),
        },
        CoerceProvider::OpenAiCompat | CoerceProvider::Xai => build_openai_compat_request(call),
        CoerceProvider::Anthropic => build_anthropic_request(call),
    }
}

/// Structured-output request for a generic OpenAI-compatible endpoint: the Chat
/// Completions API with a `response_format` json-schema constraint (the widely
/// implemented equivalent of the Responses API's `text.format`). The base URL is
/// always the caller's configured endpoint.
fn build_openai_compat_request(call: &CoerceCall<'_>) -> HttpRequest {
    let body = json!({
        "model": call.model,
        "messages": [{ "role": "user", "content": call.prompt }],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": sanitize_name(call.schema_name),
                "schema": call.output_schema,
                "strict": is_strict_compatible(call.output_schema),
            }
        },
    });
    HttpRequest {
        // The configured endpoint is the OpenAI-compatible base URL as provider docs
        // give it (it already includes `/v1`), so append only `/chat/completions` —
        // matching the OpenAI SDK `base_url` convention every compat endpoint follows.
        url: format!("{}/chat/completions", call.base_url.trim_end_matches('/')),
        headers: with_idempotency_key(
            call,
            vec![
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", call.api_key),
                ),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
        ),
        body,
    }
}

/// Codex-backend request: the Responses-API body the codex CLI sends, with the
/// `text.format` structured-output constraint. Always streams (the endpoint is
/// SSE); the transport assembles the `response.completed` payload.
fn build_codex_request(call: &CoerceCall<'_>, codex: CodexAuth<'_>) -> HttpRequest {
    let body = json!({
        "model": call.model,
        "instructions": "Respond only with a value matching the required output schema.",
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{ "type": "input_text", "text": call.prompt }],
        }],
        "tools": [],
        "tool_choice": "auto",
        "parallel_tool_calls": false,
        "store": false,
        "stream": true,
        "text": {
            "format": {
                "type": "json_schema",
                "name": sanitize_name(call.schema_name),
                "schema": call.output_schema,
                "strict": is_strict_compatible(call.output_schema),
            }
        },
    });
    HttpRequest {
        url: format!(
            "{}/backend-api/codex/responses",
            call.base_url.trim_end_matches('/')
        ),
        headers: with_idempotency_key(
            call,
            vec![
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", call.api_key),
                ),
                ("chatgpt-account-id".to_owned(), codex.account_id.to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
                ("accept".to_owned(), "text/event-stream".to_owned()),
                (
                    "openai-beta".to_owned(),
                    "responses=experimental".to_owned(),
                ),
                ("originator".to_owned(), "codex_cli_rs".to_owned()),
                ("session_id".to_owned(), codex.session_id.to_owned()),
            ],
        ),
        body,
    }
}

/// Append the `Idempotency-Key` header when the call carries a non-empty key,
/// otherwise leave the header list untouched (the fixture/no-key path must stay
/// byte-identical). OpenAI/codex dedupe a resumed duplicate against this key;
/// providers that don't support it ignore the unknown request header.
fn with_idempotency_key(
    call: &CoerceCall<'_>,
    mut headers: Vec<(String, String)>,
) -> Vec<(String, String)> {
    if !call.idempotency_key.is_empty() {
        headers.push((
            "Idempotency-Key".to_owned(),
            call.idempotency_key.to_owned(),
        ));
    }
    headers
}

fn build_openai_request(call: &CoerceCall<'_>) -> HttpRequest {
    let body = json!({
        "model": call.model,
        "input": [{ "role": "user", "content": call.prompt }],
        "text": {
            "format": {
                "type": "json_schema",
                "name": sanitize_name(call.schema_name),
                "schema": call.output_schema,
                // Strict mode (guaranteed schema adherence) requires every object
                // to have `additionalProperties: false`; a whip `Map` lowers to a
                // schema-valued `additionalProperties`, which strict mode forbids,
                // so enable strict only when the schema is compatible.
                "strict": is_strict_compatible(call.output_schema),
            }
        },
    });
    HttpRequest {
        url: format!("{}/v1/responses", call.base_url.trim_end_matches('/')),
        headers: with_idempotency_key(
            call,
            vec![
                (
                    "authorization".to_owned(),
                    format!("Bearer {}", call.api_key),
                ),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
        ),
        body,
    }
}

fn build_anthropic_request(call: &CoerceCall<'_>) -> HttpRequest {
    let tool_name = format!("emit_{}", sanitize_name(call.schema_name));
    let body = json!({
        "model": call.model,
        "max_tokens": call.max_tokens,
        "tools": [{
            "name": tool_name,
            "description": "Return the coerced value as structured arguments.",
            "input_schema": call.output_schema,
        }],
        "tool_choice": { "type": "tool", "name": tool_name },
        "messages": [{ "role": "user", "content": call.prompt }],
    });
    // Anthropic coerce uses a console API key only (`x-api-key`). Reusing a
    // Claude Code OAuth token (`sk-ant-oat*`) for the API is a terms gray area
    // (decided 2026-06-23, Jack), so the credential resolver rejects those before
    // we get here — this path always carries a real key.
    HttpRequest {
        url: format!("{}/v1/messages", call.base_url.trim_end_matches('/')),
        headers: with_idempotency_key(
            call,
            vec![
                ("x-api-key".to_owned(), call.api_key.to_owned()),
                ("anthropic-version".to_owned(), "2023-06-01".to_owned()),
                ("content-type".to_owned(), "application/json".to_owned()),
            ],
        ),
        body,
    }
}

/// Whether a token is a Claude Code / `ant auth login` OAuth token (`sk-ant-oat*`)
/// rather than a console API key. Anthropic coerce requires a console key, so the
/// credential resolver uses this to reject OAuth tokens with a clear message.
pub fn is_anthropic_oauth_token(token: &str) -> bool {
    token.starts_with("sk-ant-oat")
}

/// Whether a JSON Schema satisfies OpenAI strict structured-output rules: every
/// object's `additionalProperties` must be `false` (never a sub-schema). A whip
/// `Map` produces a schema-valued `additionalProperties`, which is incompatible.
fn is_strict_compatible(schema: &Value) -> bool {
    match schema {
        Value::Object(object) => {
            if let Some(additional) = object.get("additionalProperties") {
                if !matches!(additional, Value::Bool(false)) {
                    return false;
                }
            }
            object
                .iter()
                .filter(|(key, _)| key.as_str() != "additionalProperties")
                .all(|(_, value)| is_strict_compatible(value))
        }
        Value::Array(items) => items.iter().all(is_strict_compatible),
        _ => true,
    }
}

/// Provider names/tool names allow only `[a-zA-Z0-9_-]`; whip type names already
/// satisfy this, but sanitize defensively.
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "value".to_owned()
    } else {
        cleaned
    }
}

// -- Response parsing (pure) ---------------------------------------------

/// Parse a provider response into a [`CoerceResult`]. `wrapped` indicates the
/// schema used the `value`-envelope and the structured payload must be unwrapped.
pub fn parse_response(
    provider: CoerceProvider,
    response: &HttpResponse,
    wrapped: bool,
) -> CoerceResult {
    if !(200..300).contains(&response.status) {
        return failed_result_classified(
            format!("provider returned HTTP {}", response.status),
            provider_error_excerpt(&response.body),
            "provider_error",
            Some(response.status),
        );
    }
    match provider {
        CoerceProvider::OpenAi => parse_openai_response(response, wrapped),
        CoerceProvider::OpenAiCompat | CoerceProvider::Xai => {
            parse_openai_compat_response(response, wrapped)
        }
        CoerceProvider::Anthropic => parse_anthropic_response(response, wrapped),
    }
}

fn parse_openai_compat_response(response: &HttpResponse, wrapped: bool) -> CoerceResult {
    // Chat Completions returns the structured payload as a JSON string in
    // `choices[0].message.content`.
    let text = openai_compat_message_content(&response.body);
    let Some(text) = text else {
        return failed_result(
            "provider response contained no message content".to_owned(),
            provider_error_excerpt(&response.body),
        );
    };
    finalize_structured(&text_to_value(&text), wrapped, openai_usage(&response.body))
}

/// The assistant message text of the first Chat Completions choice, if non-empty.
fn openai_compat_message_content(body: &Value) -> Option<String> {
    let content = body
        .get("choices")?
        .as_array()?
        .first()?
        .get("message")?
        .get("content")?
        .as_str()?;
    if content.is_empty() {
        None
    } else {
        Some(content.to_owned())
    }
}

fn parse_openai_response(response: &HttpResponse, wrapped: bool) -> CoerceResult {
    // The structured payload is a JSON string in the assistant message's output
    // text. Prefer the convenience `output_text`, then walk `output[].content[]`.
    let text = openai_output_text(&response.body);
    let Some(text) = text else {
        return failed_result(
            "provider response contained no output text".to_owned(),
            provider_error_excerpt(&response.body),
        );
    };
    finalize_structured(&text_to_value(&text), wrapped, openai_usage(&response.body))
}

fn parse_anthropic_response(response: &HttpResponse, wrapped: bool) -> CoerceResult {
    // The structured payload is the `input` of the forced tool_use content block.
    let tool_input = response
        .body
        .get("content")
        .and_then(Value::as_array)
        .and_then(|content| {
            content
                .iter()
                .find(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
        })
        .and_then(|block| block.get("input").cloned());
    let Some(tool_input) = tool_input else {
        return failed_result(
            "provider response contained no tool_use block".to_owned(),
            provider_error_excerpt(&response.body),
        );
    };
    finalize_structured(&tool_input, wrapped, anthropic_usage(&response.body))
}

/// Unwrap the `value` envelope when needed and emit a success result.
fn finalize_structured(structured: &Value, wrapped: bool, usage: Value) -> CoerceResult {
    let value = if wrapped {
        match structured.get("value") {
            Some(inner) => inner.clone(),
            None => {
                return failed_result(
                    "structured output missing wrapped `value`".to_owned(),
                    Some(structured.to_string()),
                );
            }
        }
    } else {
        structured.clone()
    };
    CoerceResult {
        status: CoerceStatus::Succeeded,
        value_json: Some(value.to_string()),
        error_json: None,
        summary: "coerce succeeded".to_owned(),
        transcript: format!("structured output:\n{}\n", value),
        usage_json: usage.to_string(),
    }
}

fn openai_output_text(body: &Value) -> Option<String> {
    if let Some(text) = body.get("output_text").and_then(Value::as_str) {
        if !text.is_empty() {
            return Some(text.to_owned());
        }
    }
    let output = body.get("output").and_then(Value::as_array)?;
    for item in output {
        if let Some(content) = item.get("content").and_then(Value::as_array) {
            for block in content {
                if let Some(text) = block.get("text").and_then(Value::as_str) {
                    return Some(text.to_owned());
                }
            }
        }
    }
    None
}

/// The structured text may itself be a JSON object string, or (rarely) already a
/// JSON value; parse leniently, falling back to a string scalar.
fn text_to_value(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::String(text.to_owned()))
}

fn openai_usage(body: &Value) -> Value {
    let usage = body.get("usage");
    let mut normalized = usage.cloned().unwrap_or_else(|| json!({}));
    let Some(object) = normalized.as_object_mut() else {
        return json!({ "input_tokens": 0, "output_tokens": 0 });
    };
    let input = object
        .get("input_tokens")
        .or_else(|| object.get("prompt_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output = object
        .get("output_tokens")
        .or_else(|| object.get("completion_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    object.insert("input_tokens".to_owned(), json!(input));
    object.insert("output_tokens".to_owned(), json!(output));
    normalized
}

fn anthropic_usage(body: &Value) -> Value {
    let usage = body.get("usage");
    json!({
        "input_tokens": usage.and_then(|u| u.get("input_tokens")).and_then(Value::as_u64).unwrap_or(0),
        "output_tokens": usage.and_then(|u| u.get("output_tokens")).and_then(Value::as_u64).unwrap_or(0),
    })
}

/// Pull a short, redactable error message from a provider error body without
/// leaking the whole payload.
fn provider_error_excerpt(body: &Value) -> Option<String> {
    body.get("error")
        .and_then(|error| {
            error
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| error.as_str())
        })
        .map(|message| message.chars().take(300).collect())
}

fn failed_result(reason: String, provider_error: Option<String>) -> CoerceResult {
    // Un-classified sites are response-shape/validation failures.
    failed_result_classified(reason, provider_error, "invalid_output", None)
}

/// DR-0032 P3 (per-kind failure extras): coerce failures carry a coarse
/// `error_class` — `provider_error` (non-2xx), `invalid_output` (unusable
/// response shape/schema), `network` (transport) — and, for provider errors,
/// the `http_status`. Both are redaction-safe (a classification and a number),
/// which is what lets them ride the bound failure value (Decision 4).
fn failed_result_classified(
    reason: String,
    provider_error: Option<String>,
    error_class: &str,
    http_status: Option<u16>,
) -> CoerceResult {
    let mut error = json!({
        "reason": reason,
        "recoverable": true,
        "error_class": error_class,
    });
    if let Some(status) = http_status {
        error["http_status"] = Value::from(status);
    }
    if let Some(provider_error) = provider_error {
        error["provider_error"] = Value::String(provider_error);
    }
    CoerceResult {
        status: CoerceStatus::Failed,
        value_json: None,
        error_json: Some(error.to_string()),
        summary: "coerce failed".to_owned(),
        transcript: "native coerce failure\n".to_owned(),
        usage_json: r#"{"input_tokens":0,"output_tokens":0}"#.to_owned(),
    }
}

// -- The native client ----------------------------------------------------

/// A real coerce client that talks to a provider's structured-output API over an
/// injected [`CoerceTransport`]. Holds the already-interpolated prompt and the
/// object-rooted output schema; `CoerceRequest` arguments are only used for the
/// transcript (the prompt already embeds them).
pub struct NativeCoerceClient<'a, T: CoerceTransport> {
    pub provider: CoerceProvider,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub prompt: String,
    pub output_schema: Value,
    pub wrapped: bool,
    pub schema_name: String,
    pub max_tokens: u32,
    /// `(account_id, session_id)` when using the codex backend (OpenAI only).
    pub codex: Option<(String, String)>,
    /// Stable per-effect `Idempotency-Key` (see [`CoerceCall::idempotency_key`]);
    /// empty for the fixture/no-key path.
    pub idempotency_key: String,
    pub transport: &'a T,
}

impl<T: CoerceTransport> CoerceClient for NativeCoerceClient<'_, T> {
    fn coerce(&self, _request: &CoerceRequest) -> CoerceResult {
        let call = CoerceCall {
            provider: self.provider,
            base_url: &self.base_url,
            api_key: &self.api_key,
            model: &self.model,
            prompt: &self.prompt,
            output_schema: &self.output_schema,
            schema_name: &self.schema_name,
            max_tokens: self.max_tokens,
            codex: self
                .codex
                .as_ref()
                .map(|(account_id, session_id)| CodexAuth {
                    account_id,
                    session_id,
                }),
            idempotency_key: &self.idempotency_key,
        };
        // Coerce is a one-round step machine (prepare → HTTP → finish). The
        // native host drives it to completion synchronously via its transport;
        // the behavior is identical to a straight build → post → parse.
        let mut machine = CoerceStepMachine {
            call,
            provider: self.provider,
            wrapped: self.wrapped,
        };
        run_to_completion(&mut machine, self.transport)
    }
}

/// The coerce effect as a sans-IO [`StepMachine`] (DR-0033 Decision 1): one HTTP
/// round, `build_request` as the prepare step and `parse_response`/the transport
/// error mapping as the finish step. Reusing those pure functions unchanged keeps
/// behavior byte-for-byte identical to the direct client.
struct CoerceStepMachine<'a> {
    call: CoerceCall<'a>,
    provider: CoerceProvider,
    wrapped: bool,
}

impl StepMachine for CoerceStepMachine<'_> {
    type Output = CoerceResult;

    fn step(&mut self, incoming: Option<IoResult>) -> Outcome<CoerceResult> {
        match incoming {
            // Prepare: build the provider request (pure) and hand it to the host.
            None => Outcome::NeedsIo(IoRequest::Http(build_request(&self.call))),
            // Finish: decode the response, or map a transport failure to a
            // terminal — the same three branches the direct client used.
            Some(IoResult::Http(Ok(response))) => {
                Outcome::Settle(parse_response(self.provider, &response, self.wrapped))
            }
            Some(IoResult::Http(Err(CoerceTransportError::Timeout))) => {
                Outcome::Settle(CoerceResult {
                    status: CoerceStatus::TimedOut,
                    value_json: None,
                    error_json: Some(
                        json!({ "reason": "coerce request timed out", "recoverable": true })
                            .to_string(),
                    ),
                    summary: "coerce timed out".to_owned(),
                    transcript: "native coerce timeout\n".to_owned(),
                    usage_json: r#"{"input_tokens":0,"output_tokens":0}"#.to_owned(),
                })
            }
            Some(IoResult::Http(Err(CoerceTransportError::Transport(message)))) => {
                Outcome::Settle(failed_result_classified(
                    format!("transport error: {message}"),
                    None,
                    "network",
                    None,
                ))
            }
        }
    }
}

// -- Coerce request-parts builder (prompt + schema from IR; DR-0033 chunk 5b) --
// Pure (IR + arguments -> prompt/schema): both hosts assemble the coerce HTTP
// request identically before their transports run it. Native builds it from the
// workspace program; the DO from its program metadata.

/// Build the prompt and output schema for a declared coerce function.
///
/// Returns `(rendered_prompt, output_schema, wrapped, schema_name)`.
pub fn build_coerce_call_parts(
    ir: &IrProgram,
    function_name: &str,
    arguments: &Value,
) -> Result<(String, Value, bool, String), String> {
    let coerce = ir
        .coerces
        .iter()
        .find(|coerce| coerce.name == function_name)
        .ok_or_else(|| {
            format!("coerce function `{function_name}` is not declared in the program")
        })?;
    let (schema, wrapped) = output_schema_envelope(&coerce.output, &ir.schemas);
    // Coerce-call arguments lower to positional keys (`arg0`, `arg1`, …); map
    // them to the declared parameter names so the prompt's `{{ <param> }}`
    // interpolations resolve. The positional keys are preserved too.
    let named = name_positional_arguments(coerce, arguments);
    // Render after building the schema so `{{ ctx.output_format }}` can embed it:
    // this makes the prompt self-describing and lets endpoints without native
    // structured output still return schema-shaped JSON (prompt-instructed mode).
    let prompt = render_coerce_prompt(&coerce.body, &named, Some(&schema));
    Ok((prompt, schema, wrapped, output_type_name(&coerce.output)))
}

/// Map positional argument keys (`arg0`, `arg1`, …) to the coerce function's
/// declared parameter names, keeping the originals so either form resolves.
fn name_positional_arguments(coerce: &whipplescript_parser::IrCoerce, arguments: &Value) -> Value {
    let Some(object) = arguments.as_object() else {
        return arguments.clone();
    };
    let mut named = object.clone();
    for (index, param) in coerce.params.iter().enumerate() {
        if let Some(value) = object.get(&format!("arg{index}")) {
            named
                .entry(param.name.clone())
                .or_insert_with(|| value.clone());
        }
    }
    Value::Object(named)
}

fn output_type_name(ty: &IrType) -> String {
    match ty {
        IrType::Ref(name) => name.clone(),
        _ => "CoerceResult".to_owned(),
    }
}

/// Render a coerce prompt template: substitute `{{ arg }}` from the arguments
/// object, replace the `{{ ctx.output_format }}` token with a structured-output
/// instruction (the API enforces the schema, so this is a textual reminder), and
/// leave any unrecognized interpolation untouched.
pub fn render_coerce_prompt(
    template: &str,
    arguments: &Value,
    output_schema: Option<&Value>,
) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            // No closing braces: emit the remainder verbatim.
            out.push_str("{{");
            rest = after;
            continue;
        };
        let key = after[..close].trim();
        match resolve_template_key(key, arguments, output_schema) {
            Some(value) => out.push_str(&value),
            None => {
                // Preserve unknown interpolation so nothing is silently dropped.
                out.push_str("{{ ");
                out.push_str(key);
                out.push_str(" }}");
            }
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

fn resolve_template_key(
    key: &str,
    arguments: &Value,
    output_schema: Option<&Value>,
) -> Option<String> {
    if key == "ctx.output_format" {
        return Some(match output_schema {
            Some(schema) => {
                format!("Respond with a single JSON value matching this JSON Schema:\n{schema}")
            }
            None => {
                "Respond with a single value that matches the required output schema.".to_owned()
            }
        });
    }
    // Support dotted access into the arguments object (`{{ item.summary }}`).
    let mut current = arguments;
    for segment in key.split('.') {
        current = current.get(segment)?;
    }
    Some(match current {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sansio::{IoRequest, IoResult, Outcome, StepMachine};
    use std::cell::RefCell;
    use whipplescript_parser::{IrClass, IrEnum};

    fn span() -> whipplescript_parser::SourceSpan {
        whipplescript_parser::SourceSpan { start: 0, end: 0 }
    }

    fn work_status_enum() -> IrSchema {
        IrSchema::Enum(IrEnum {
            name: "WorkStatus".to_owned(),
            variants: vec!["Accepted".to_owned(), "Rejected".to_owned()],
            span: span(),
        })
    }

    fn work_review_class() -> IrSchema {
        IrSchema::Class(IrClass {
            name: "WorkReview".to_owned(),
            fields: vec![
                IrClassField {
                    name: "status".to_owned(),
                    ty: IrType::Ref("WorkStatus".to_owned()),
                    is_key: false,
                    presence_condition: None,
                    span: span(),
                },
                IrClassField {
                    name: "reason".to_owned(),
                    ty: IrType::Primitive(IrPrimitiveType::String),
                    is_key: false,
                    presence_condition: None,
                    span: span(),
                },
                IrClassField {
                    name: "score".to_owned(),
                    ty: IrType::Optional(Box::new(IrType::Primitive(IrPrimitiveType::Int))),
                    is_key: false,
                    presence_condition: None,
                    span: span(),
                },
            ],
            span: span(),
        })
    }

    #[test]
    fn class_schema_is_strict_with_nullable_optionals() {
        let schemas = vec![work_status_enum(), work_review_class()];
        let (schema, wrapped) =
            output_schema_envelope(&IrType::Ref("WorkReview".to_owned()), &schemas);
        assert!(!wrapped, "a class output is already object-rooted");
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        let required: Vec<&str> = schema["required"]
            .as_array()
            .expect("present")
            .iter()
            .map(|v| v.as_str().expect("present"))
            .collect();
        // Strict mode: every property is required, including the optional one.
        assert!(required.contains(&"status"));
        assert!(required.contains(&"reason"));
        assert!(required.contains(&"score"));
        // The optional field expresses absence via nullability, not omission.
        assert!(
            schema["properties"]["score"]["anyOf"]
                .as_array()
                .expect("present")
                .iter()
                .any(|variant| variant["type"] == "null"),
            "optional field is nullable"
        );
        assert_eq!(schema["properties"]["status"]["enum"][0], "Accepted");
    }

    #[test]
    fn sum_type_enum_schema_is_anyof_of_variant_objects() {
        // A payload-carrying enum's generated `<Enum>.<Variant>` classes must drive an
        // anyOf of object schemas, not a string `enum` (which drops the payload — the
        // verified latent bug). A bare variant with no class stays a string const.
        let variant_field = |value: &str| IrClassField {
            name: "variant".to_owned(),
            ty: IrType::LiteralString(value.to_owned()),
            is_key: false,
            presence_condition: None,
            span: span(),
        };
        let payload_field = |name: &str, ty: IrType| IrClassField {
            name: name.to_owned(),
            ty,
            is_key: false,
            presence_condition: None,
            span: span(),
        };
        let schemas = vec![
            IrSchema::Enum(IrEnum {
                name: "ReviewOutcome".to_owned(),
                variants: vec![
                    "Approved".to_owned(),
                    "Rejected".to_owned(),
                    "Blocked".to_owned(),
                ],
                span: span(),
            }),
            IrSchema::Class(IrClass {
                name: "ReviewOutcome.Approved".to_owned(),
                fields: vec![
                    variant_field("Approved"),
                    payload_field("score", IrType::Primitive(IrPrimitiveType::Float)),
                ],
                span: span(),
            }),
            IrSchema::Class(IrClass {
                name: "ReviewOutcome.Rejected".to_owned(),
                fields: vec![
                    variant_field("Rejected"),
                    payload_field("reason", IrType::Primitive(IrPrimitiveType::String)),
                ],
                span: span(),
            }),
        ];
        let schema = json_schema_for_type(&IrType::Ref("ReviewOutcome".to_owned()), &schemas);
        let alts = schema["anyOf"].as_array().expect("anyOf present");
        assert_eq!(alts.len(), 3, "one alternative per variant");
        // The Approved payload field survives (the bug dropped it to a string enum).
        let approved = alts
            .iter()
            .find(|alt| alt["properties"]["variant"]["const"] == "Approved")
            .expect("Approved object alternative");
        assert_eq!(approved["type"], "object");
        assert_eq!(approved["additionalProperties"], false);
        assert_eq!(approved["properties"]["score"]["type"], "number");
        // The bare `Blocked` variant (no generated class) is a string const.
        assert!(
            alts.iter().any(|alt| alt["const"] == "Blocked"),
            "bare variant is a string const: {alts:?}"
        );

        // A fully-bare enum still collapses to a single string `enum`.
        let bare =
            json_schema_for_type(&IrType::Ref("WorkStatus".to_owned()), &[work_status_enum()]);
        assert_eq!(bare["type"], "string");
        assert_eq!(bare["enum"][0], "Accepted");
    }

    #[test]
    fn non_object_output_is_wrapped_in_a_value_envelope() {
        let schemas = vec![work_status_enum()];
        let (schema, wrapped) =
            output_schema_envelope(&IrType::Ref("WorkStatus".to_owned()), &schemas);
        assert!(wrapped, "an enum output must be wrapped");
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["properties"]["value"]["enum"][1], "Rejected");
    }

    #[test]
    fn openai_request_carries_json_schema_format_and_bearer() {
        let schema = json!({ "type": "object" });
        let call = CoerceCall {
            provider: CoerceProvider::OpenAi,
            base_url: "https://api.openai.com",
            api_key: "sk-test",
            model: "gpt-4o",
            prompt: "Classify this",
            output_schema: &schema,
            schema_name: "WorkReview",
            max_tokens: 1024,
            codex: None,
            idempotency_key: "key_openai_effect",
        };
        let request = build_request(&call);
        assert_eq!(request.url, "https://api.openai.com/v1/responses");
        assert_eq!(request.body["text"]["format"]["type"], "json_schema");
        assert_eq!(request.body["text"]["format"]["name"], "WorkReview");
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer sk-test"));
        // A non-empty per-effect key rides as an `Idempotency-Key` header.
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "Idempotency-Key" && v == "key_openai_effect"));
    }

    #[test]
    fn openai_compat_request_uses_chat_completions_with_response_format() {
        let schema = json!({ "type": "object" });
        let call = CoerceCall {
            provider: CoerceProvider::OpenAiCompat,
            base_url: "https://api.together.xyz/v1",
            api_key: "sk-test",
            model: "llama-3.3-70b",
            prompt: "Classify this",
            output_schema: &schema,
            schema_name: "WorkReview",
            max_tokens: 1024,
            codex: None,
            idempotency_key: "key_compat_effect",
        };
        let request = build_request(&call);
        // Chat Completions endpoint + `response_format` json-schema (not the
        // Responses API's `text.format`).
        assert_eq!(request.url, "https://api.together.xyz/v1/chat/completions");
        assert_eq!(
            request.body["response_format"]["type"],
            json!("json_schema")
        );
        assert_eq!(
            request.body["response_format"]["json_schema"]["name"],
            json!("WorkReview")
        );
        assert_eq!(request.body["messages"][0]["role"], json!("user"));
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer sk-test"));
    }

    #[test]
    fn openai_compat_default_base_url_carries_v1_so_the_default_is_usable() {
        // Regression (live-confirmed 2026-07-19 against Ollama): the OpenAiCompat
        // builder appends only `/chat/completions`, so its default base MUST
        // already include the `/v1` version segment — otherwise a caller relying
        // on the default (or pointing at real OpenAI without a manual `/v1`) 404s
        // at `.../chat/completions`. OpenAi/Anthropic keep the bare-host default
        // because their builders add `/v1/...` themselves.
        assert_eq!(
            CoerceProvider::OpenAiCompat.default_base_url(),
            "https://api.openai.com/v1"
        );
        assert_eq!(
            CoerceProvider::OpenAi.default_base_url(),
            "https://api.openai.com"
        );
        // Building with the default base must yield a valid `/v1/chat/completions`
        // URL, not the broken `.../chat/completions`.
        let schema = json!({ "type": "object" });
        let call = CoerceCall {
            provider: CoerceProvider::OpenAiCompat,
            base_url: CoerceProvider::OpenAiCompat.default_base_url(),
            api_key: "sk-test",
            model: "gpt-4o-mini",
            prompt: "Classify this",
            output_schema: &schema,
            schema_name: "WorkReview",
            max_tokens: 1024,
            codex: None,
            idempotency_key: "",
        };
        assert_eq!(
            build_request(&call).url,
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn xai_coerce_speaks_chat_completions_at_the_x_ai_default_base() {
        // xAI shares the OpenAiCompat wire (Chat Completions + `response_format`
        // json-schema) but is first-class: its default base URL is known, and —
        // same `/v1`-in-base convention — the builder appends only
        // `/chat/completions`, so the default MUST carry `/v1`.
        assert_eq!(
            CoerceProvider::Xai.default_base_url(),
            "https://api.x.ai/v1"
        );
        let schema = json!({ "type": "object" });
        let call = CoerceCall {
            provider: CoerceProvider::Xai,
            base_url: CoerceProvider::Xai.default_base_url(),
            api_key: "xai-test",
            model: "grok-4",
            prompt: "Classify this",
            output_schema: &schema,
            schema_name: "WorkReview",
            max_tokens: 1024,
            codex: None,
            idempotency_key: "key_xai_effect",
        };
        let request = build_request(&call);
        assert_eq!(request.url, "https://api.x.ai/v1/chat/completions");
        assert_eq!(
            request.body["response_format"]["type"],
            json!("json_schema")
        );
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer xai-test"));
        // And the reply parses through the same chat-completions reader.
        let response = HttpResponse {
            status: 200,
            body: json!({
                "choices": [{ "message": { "content": "{\"ok\":true}" } }],
                "usage": { "completion_tokens": 3 }
            }),
        };
        let result = parse_response(CoerceProvider::Xai, &response, false);
        assert_eq!(result.status, CoerceStatus::Succeeded);
        assert_eq!(result.value_json.as_deref(), Some("{\"ok\":true}"));
        let usage: Value = serde_json::from_str(&result.usage_json).unwrap();
        assert_eq!(usage["output_tokens"], json!(3));
    }

    #[test]
    fn chat_usage_is_normalized_without_erasing_cache_detail() {
        let usage = openai_usage(&json!({
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 4,
                "prompt_tokens_details": { "cached_tokens": 9 }
            }
        }));
        assert_eq!(usage["input_tokens"], json!(12));
        assert_eq!(usage["output_tokens"], json!(4));
        assert_eq!(usage["prompt_tokens_details"]["cached_tokens"], json!(9));
    }

    #[test]
    fn openai_compat_response_reads_message_content_as_structured_value() {
        let response = HttpResponse {
            status: 200,
            body: json!({
                "choices": [{ "message": { "content": "{\"ok\":true}" } }],
                "usage": { "completion_tokens": 3 }
            }),
        };
        let result = parse_response(CoerceProvider::OpenAiCompat, &response, false);
        assert_eq!(result.status, CoerceStatus::Succeeded);
        assert_eq!(result.value_json.as_deref(), Some("{\"ok\":true}"));
    }

    #[test]
    fn empty_idempotency_key_emits_no_header_on_every_builder() {
        // The fixture/no-key path must stay byte-identical to before: an empty
        // key produces no `Idempotency-Key` header on any of the three builders.
        let schema = json!({ "type": "object" });
        let has_key =
            |request: &HttpRequest| request.headers.iter().any(|(k, _)| k == "Idempotency-Key");
        let openai = CoerceCall {
            provider: CoerceProvider::OpenAi,
            base_url: "https://api.openai.com",
            api_key: "sk-test",
            model: "gpt-4o",
            prompt: "p",
            output_schema: &schema,
            schema_name: "WorkReview",
            max_tokens: 1024,
            codex: None,
            idempotency_key: "",
        };
        assert!(!has_key(&build_request(&openai)));

        let codex = CoerceCall {
            codex: Some(CodexAuth {
                account_id: "acct-1",
                session_id: "sess-1",
            }),
            ..openai.clone()
        };
        assert!(!has_key(&build_request(&codex)));

        let anthropic = CoerceCall {
            provider: CoerceProvider::Anthropic,
            base_url: "https://api.anthropic.com",
            api_key: "key",
            codex: None,
            ..openai
        };
        assert!(!has_key(&build_request(&anthropic)));
    }

    #[test]
    fn idempotency_key_is_resume_stable_per_effect() {
        // The whole correctness argument: the key must be identical across a
        // resume of the SAME effect (so the provider returns its cached response)
        // and differ for a distinct effect. The helper is a pure hash of
        // `(instance_id, effect_id, tag)`, so equal inputs → equal key.
        let same_1 = crate::idempotency_key(&["inst-A", "eff-1", "coerce"]);
        let same_2 = crate::idempotency_key(&["inst-A", "eff-1", "coerce"]);
        assert_eq!(same_1, same_2, "same effect must map to the same key");
        let other_effect = crate::idempotency_key(&["inst-A", "eff-2", "coerce"]);
        assert_ne!(same_1, other_effect, "a distinct effect must differ");
        let other_instance = crate::idempotency_key(&["inst-B", "eff-1", "coerce"]);
        assert_ne!(same_1, other_instance, "a distinct instance must differ");
    }

    #[test]
    fn codex_request_targets_backend_with_codex_headers_and_streams() {
        let schema = json!({ "type": "object" });
        let call = CoerceCall {
            provider: CoerceProvider::OpenAi,
            base_url: "https://chatgpt.com",
            api_key: "oauth-jwt",
            model: "gpt-5.5",
            prompt: "Classify this",
            output_schema: &schema,
            schema_name: "WorkReview",
            max_tokens: 1024,
            codex: Some(CodexAuth {
                account_id: "acct-1",
                session_id: "sess-1",
            }),
            idempotency_key: "key_codex_effect",
        };
        let request = build_request(&call);
        assert_eq!(
            request.url,
            "https://chatgpt.com/backend-api/codex/responses"
        );
        assert_eq!(request.body["stream"], true);
        assert_eq!(request.body["text"]["format"]["type"], "json_schema");
        // Codex input is message-shaped, not a bare string.
        assert_eq!(request.body["input"][0]["type"], "message");
        let header = |name: &str| {
            request
                .headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(header("authorization").as_deref(), Some("Bearer oauth-jwt"));
        assert_eq!(header("chatgpt-account-id").as_deref(), Some("acct-1"));
        assert_eq!(header("session_id").as_deref(), Some("sess-1"));
        assert_eq!(header("originator").as_deref(), Some("codex_cli_rs"));
        assert_eq!(header("accept").as_deref(), Some("text/event-stream"));
        assert_eq!(
            header("openai-beta").as_deref(),
            Some("responses=experimental")
        );
        // Codex honors `Idempotency-Key` — the resume-stable per-effect key.
        assert_eq!(
            header("Idempotency-Key").as_deref(),
            Some("key_codex_effect")
        );
    }

    #[test]
    fn anthropic_request_forces_a_single_tool() {
        let schema = json!({ "type": "object" });
        let call = CoerceCall {
            provider: CoerceProvider::Anthropic,
            base_url: "https://api.anthropic.com",
            api_key: "key",
            model: "claude-opus-4-8",
            prompt: "Classify this",
            output_schema: &schema,
            schema_name: "WorkReview",
            max_tokens: 1024,
            codex: None,
            idempotency_key: "key_anthropic_effect",
        };
        let request = build_request(&call);
        assert_eq!(request.url, "https://api.anthropic.com/v1/messages");
        assert_eq!(request.body["tool_choice"]["type"], "tool");
        assert_eq!(request.body["tool_choice"]["name"], "emit_WorkReview");
        assert_eq!(request.body["tools"][0]["name"], "emit_WorkReview");
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == "key"));
        // Anthropic coerce uses x-api-key only — never the OAuth bearer header.
        assert!(!request.headers.iter().any(|(k, _)| k == "authorization"));
        // The header is still sent to Anthropic (harmless — an unknown request
        // header is ignored); Anthropic simply does not dedupe on it.
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "Idempotency-Key" && v == "key_anthropic_effect"));
    }

    #[test]
    fn strict_disabled_for_map_valued_schema() {
        // A class with a Map field renders `additionalProperties` as a sub-schema.
        let schemas = vec![IrSchema::Class(IrClass {
            name: "Bag".to_owned(),
            fields: vec![IrClassField {
                name: "items".to_owned(),
                ty: IrType::Map(Box::new(IrType::Primitive(IrPrimitiveType::String))),
                is_key: false,
                presence_condition: None,
                span: span(),
            }],
            span: span(),
        })];
        let (schema, _) = output_schema_envelope(&IrType::Ref("Bag".to_owned()), &schemas);
        let call = CoerceCall {
            provider: CoerceProvider::OpenAi,
            base_url: "https://api.openai.com",
            api_key: "k",
            model: "gpt-4o",
            prompt: "p",
            output_schema: &schema,
            schema_name: "Bag",
            max_tokens: 256,
            codex: None,
            idempotency_key: "",
        };
        let request = build_request(&call);
        assert_eq!(
            request.body["text"]["format"]["strict"], false,
            "a Map-valued schema disables strict mode"
        );
        // A plain class stays strict.
        let plain = json!({ "type": "object", "additionalProperties": false });
        assert!(is_strict_compatible(&plain));
    }

    #[test]
    fn parse_openai_extracts_structured_output() {
        let response = HttpResponse {
            status: 200,
            body: json!({
                "output": [{
                    "content": [{ "type": "output_text", "text": "{\"status\":\"Accepted\",\"reason\":\"ok\"}" }]
                }],
                "usage": { "input_tokens": 12, "output_tokens": 5 }
            }),
        };
        let result = parse_response(CoerceProvider::OpenAi, &response, false);
        assert_eq!(result.status, CoerceStatus::Succeeded);
        let value: Value =
            serde_json::from_str(result.value_json.as_ref().expect("present")).expect("present");
        assert_eq!(value["status"], "Accepted");
        assert_eq!(
            result.usage_json,
            r#"{"input_tokens":12,"output_tokens":5}"#
        );
    }

    #[test]
    fn parse_anthropic_unwraps_value_envelope() {
        let response = HttpResponse {
            status: 200,
            body: json!({
                "content": [{ "type": "tool_use", "name": "emit_WorkStatus", "input": { "value": "Accepted" } }],
                "usage": { "input_tokens": 8, "output_tokens": 2 }
            }),
        };
        let result = parse_response(CoerceProvider::Anthropic, &response, true);
        assert_eq!(result.status, CoerceStatus::Succeeded);
        assert_eq!(result.value_json.as_deref(), Some("\"Accepted\""));
    }

    #[test]
    fn non_2xx_is_a_failure_with_provider_error() {
        let response = HttpResponse {
            status: 429,
            body: json!({ "error": { "message": "rate limited" } }),
        };
        let result = parse_response(CoerceProvider::OpenAi, &response, false);
        assert_eq!(result.status, CoerceStatus::Failed);
        let error: Value =
            serde_json::from_str(result.error_json.as_ref().expect("present")).expect("present");
        assert_eq!(error["provider_error"], "rate limited");
    }

    struct FakeTransport {
        response: Result<HttpResponse, CoerceTransportError>,
        seen: RefCell<Option<HttpRequest>>,
    }

    impl CoerceTransport for FakeTransport {
        fn post(&self, request: &HttpRequest) -> Result<HttpResponse, CoerceTransportError> {
            *self.seen.borrow_mut() = Some(request.clone());
            self.response.clone()
        }
    }

    #[test]
    fn native_client_drives_transport_and_parses() {
        let transport = FakeTransport {
            response: Ok(HttpResponse {
                status: 200,
                body: json!({
                    "content": [{ "type": "tool_use", "input": { "status": "Accepted", "reason": "ok" } }],
                    "usage": { "input_tokens": 1, "output_tokens": 1 }
                }),
            }),
            seen: RefCell::new(None),
        };
        let client = NativeCoerceClient {
            provider: CoerceProvider::Anthropic,
            base_url: "https://api.anthropic.com".to_owned(),
            api_key: "key".to_owned(),
            model: "claude-opus-4-8".to_owned(),
            prompt: "Classify this".to_owned(),
            output_schema: json!({ "type": "object" }),
            wrapped: false,
            schema_name: "WorkReview".to_owned(),
            max_tokens: 1024,
            codex: None,
            idempotency_key: String::new(),
            transport: &transport,
        };
        let request = CoerceRequest {
            function_name: "reviewWork".to_owned(),
            arguments_json: "{}".to_owned(),
            output_type: "WorkReview".to_owned(),
            generated_coerce_source_hash: "h".to_owned(),
            input_schema_hash: "i".to_owned(),
            output_schema_hash: "o".to_owned(),
        };
        let result = client.coerce(&request);
        assert_eq!(result.status, CoerceStatus::Succeeded);
        assert!(transport.seen.borrow().is_some(), "transport was invoked");
    }

    #[test]
    fn native_client_maps_timeout() {
        let transport = FakeTransport {
            response: Err(CoerceTransportError::Timeout),
            seen: RefCell::new(None),
        };
        let client = NativeCoerceClient {
            provider: CoerceProvider::OpenAi,
            base_url: "https://api.openai.com".to_owned(),
            api_key: "k".to_owned(),
            model: "gpt-4o".to_owned(),
            prompt: "p".to_owned(),
            output_schema: json!({ "type": "object" }),
            wrapped: false,
            schema_name: "X".to_owned(),
            max_tokens: 256,
            codex: None,
            idempotency_key: String::new(),
            transport: &transport,
        };
        let request = CoerceRequest {
            function_name: "f".to_owned(),
            arguments_json: "{}".to_owned(),
            output_type: "X".to_owned(),
            generated_coerce_source_hash: "h".to_owned(),
            input_schema_hash: "i".to_owned(),
            output_schema_hash: "o".to_owned(),
        };
        assert_eq!(client.coerce(&request).status, CoerceStatus::TimedOut);
    }

    // -- Coerce as a Phase-0 lifecycle instance ---------------------------
    // These assert the sans-IO shape directly (DR-0033 Decision 1;
    // models/tla/ResumableEffectLifecycle.tla): coerce is a one-round machine,
    // prepare -> NeedsIo(Http) -> settle, with transport failures mapped to
    // terminals in the finish step.

    fn one_round_machine(provider: CoerceProvider, schema: &Value) -> CoerceStepMachine<'_> {
        CoerceStepMachine {
            call: CoerceCall {
                provider,
                base_url: match provider {
                    CoerceProvider::Anthropic => "https://api.anthropic.com",
                    CoerceProvider::OpenAi | CoerceProvider::OpenAiCompat => {
                        "https://api.openai.com"
                    }
                    CoerceProvider::Xai => "https://api.x.ai/v1",
                },
                api_key: "key",
                model: "m",
                prompt: "Classify this",
                output_schema: schema,
                schema_name: "WorkReview",
                max_tokens: 1024,
                codex: None,
                idempotency_key: "",
            },
            provider,
            wrapped: false,
        }
    }

    #[test]
    fn coerce_step_machine_is_a_one_round_lifecycle_instance() {
        let schema = json!({ "type": "object" });
        let mut machine = one_round_machine(CoerceProvider::Anthropic, &schema);

        // First step (incoming = None) prepares the request and asks the host
        // for exactly one HTTP round.
        let request = match machine.step(None) {
            Outcome::NeedsIo(IoRequest::Http(request)) => request,
            _ => panic!("expected NeedsIo(Http) on the prepare step"),
        };
        assert!(
            request.url.contains("anthropic"),
            "the prepare step built the provider request"
        );

        // Feeding the response settles the machine in that one round.
        let response = HttpResponse {
            status: 200,
            body: json!({
                "content": [{ "type": "tool_use", "input": { "status": "Accepted", "reason": "ok" } }],
                "usage": { "input_tokens": 1, "output_tokens": 1 }
            }),
        };
        match machine.step(Some(IoResult::Http(Ok(response)))) {
            Outcome::Settle(result) => assert_eq!(result.status, CoerceStatus::Succeeded),
            _ => panic!("expected Settle on the finish step"),
        }
    }

    #[test]
    fn coerce_step_machine_maps_transport_failures_to_terminals() {
        let schema = json!({ "type": "object" });

        let mut timeout = one_round_machine(CoerceProvider::OpenAi, &schema);
        assert!(matches!(timeout.step(None), Outcome::NeedsIo(_)));
        let timed_out = match timeout.step(Some(IoResult::Http(Err(CoerceTransportError::Timeout))))
        {
            Outcome::Settle(result) => result.status,
            _ => panic!("expected Settle"),
        };
        assert_eq!(timed_out, CoerceStatus::TimedOut);

        let mut broken = one_round_machine(CoerceProvider::OpenAi, &schema);
        assert!(matches!(broken.step(None), Outcome::NeedsIo(_)));
        let failed = match broken.step(Some(IoResult::Http(Err(CoerceTransportError::Transport(
            "boom".to_owned(),
        ))))) {
            Outcome::Settle(result) => result.status,
            _ => panic!("expected Settle"),
        };
        assert_eq!(failed, CoerceStatus::Failed);
    }
}
