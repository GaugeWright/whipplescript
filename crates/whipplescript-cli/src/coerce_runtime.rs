//! CLI-side wiring for native (real-LLM) `coerce`: the registry-honest
//! backend-selection ladder (spec/std-coercion.md "Backend selection and
//! config precedence"), the `ureq` HTTP transport, and turning a declared
//! `coerce` function + its arguments into a rendered prompt and an output
//! JSON Schema.
//!
//! The pure request/response logic and JSON-Schema synthesis live in
//! `whipplescript_kernel::coerce_native`; the shared model-credential layer
//! lives in `crate::model_auth`; this module supplies selection + config
//! resolution and the network (`ureq`).
//!
//! Selection ladder (each rung an operator-visible choice, `whip coercion
//! status` reports which one fired):
//!
//! 1. per-effect `provider` in source (must name a registered schema_coercer)
//! 2. operator override — `WHIPPLESCRIPT_COERCE_*` env + `whip auth`
//! 3. registry default — the `schema.coerce` capability binding row's
//!    provider + its `effect_providers` row `config_json`
//! 4. fixture (when nothing selects native)
//!
//! Env variables are thereby operator-override-over-registry-default, not the
//! selection mechanism. Misconfiguration (unknown provider, provider set but
//! no credential) is a loud `Err` — never a silent fixture degrade.

use std::time::Duration;

use serde_json::Value;
use whipplescript_kernel::coerce_native::{
    CoerceProvider, CoerceTransport, CoerceTransportError, HttpRequest, HttpResponse,
    ResolvedCoercionConfig, DEFAULT_COERCE_MAX_TOKENS, DEFAULT_COERCE_TIMEOUT_SECS,
};

use crate::model_auth::{
    anthropic_oauth_rejection, codex_account_id, codex_config_model, env_nonempty,
    resolve_credential_with_source, CredentialSource,
};

/// Rung 3's input: the `schema.coerce` capability binding row's provider name
/// plus that provider's `effect_providers` row `config_json` — one indexed
/// SELECT at claim time, mirroring the `capability_bound` promotion.
pub struct CoerceRegistryDefault {
    /// `capability_bindings.provider` for `schema.coerce`.
    pub provider: String,
    /// `effect_providers.config_json` for that provider (backend/model/… as a
    /// JSON object; never credentials — those resolve through `model_auth`).
    pub config_json: Option<String>,
}

/// Which ladder rung selected the coerce configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoerceSelectionRung {
    /// Rung 1: per-effect `provider` in source.
    PerEffectProvider,
    /// Rung 2: operator override (`WHIPPLESCRIPT_COERCE_*` env + `whip auth`).
    OperatorOverride,
    /// Rung 3: the registry `schema.coerce` binding row.
    RegistryDefault,
    /// Rung 4: fixture — nothing selected native.
    Fixture,
}

impl CoerceSelectionRung {
    pub fn number(self) -> u8 {
        match self {
            CoerceSelectionRung::PerEffectProvider => 1,
            CoerceSelectionRung::OperatorOverride => 2,
            CoerceSelectionRung::RegistryDefault => 3,
            CoerceSelectionRung::Fixture => 4,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            CoerceSelectionRung::PerEffectProvider => "per-effect provider",
            CoerceSelectionRung::OperatorOverride => "operator override",
            CoerceSelectionRung::RegistryDefault => "registry default",
            CoerceSelectionRung::Fixture => "fixture",
        }
    }
}

/// A resolved coerce selection: the canonical config record (`None` = the
/// fixture path), the rung that chose it, and — for status surfaces — where
/// the credential came from (the label only; the key itself lives in
/// `config.api_key` and is never reported).
#[derive(Debug)]
pub struct CoerceSelection {
    pub config: Option<ResolvedCoercionConfig>,
    pub rung: CoerceSelectionRung,
    pub credential_source: Option<CredentialSource>,
}

/// Provider names that select the fixture path. `builtin-coerce` is the
/// migration-0001 seeded binding's provider name for the same deterministic
/// provider the manifest names `fixture`.
pub(crate) fn is_fixture_provider_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("fixture") || name == "builtin-coerce"
}

/// Snapshot of the operator-override environment (`WHIPPLESCRIPT_COERCE_*`),
/// separated from process env so the ladder itself is unit-testable.
struct OperatorEnv {
    provider: Option<String>,
    model: Option<String>,
    base_url: Option<String>,
    max_tokens: Option<u32>,
    timeout_secs: Option<u64>,
}

impl OperatorEnv {
    fn from_process() -> Self {
        Self {
            provider: env_nonempty("WHIPPLESCRIPT_COERCE_PROVIDER"),
            model: env_nonempty("WHIPPLESCRIPT_COERCE_MODEL"),
            base_url: env_nonempty("WHIPPLESCRIPT_COERCE_BASE_URL"),
            max_tokens: env_nonempty("WHIPPLESCRIPT_COERCE_MAX_TOKENS")
                .and_then(|value| value.parse().ok()),
            timeout_secs: env_nonempty("WHIPPLESCRIPT_COERCE_TIMEOUT_SECS")
                .and_then(|value| value.parse().ok()),
        }
    }

    #[cfg(test)]
    fn empty() -> Self {
        Self {
            provider: None,
            model: None,
            base_url: None,
            max_tokens: None,
            timeout_secs: None,
        }
    }
}

/// The credential/codex probes the resolution consults, injectable for tests
/// (the real set reads env, `whip auth`, and `~/.codex`).
struct CredentialProbes<'a> {
    credential: &'a dyn Fn(CoerceProvider) -> Option<(String, CredentialSource)>,
    codex_model: &'a dyn Fn() -> Option<String>,
    codex_account: &'a dyn Fn() -> Option<String>,
}

impl CredentialProbes<'_> {
    fn real() -> CredentialProbes<'static> {
        CredentialProbes {
            credential: &resolve_credential_with_source,
            codex_model: &codex_config_model,
            codex_account: &codex_account_id,
        }
    }
}

/// The coercion-config fingerprint the step machine folds into `schema.coerce`
/// effect admission keys (DR-0014 amendment): H(provider_kind, provider_id,
/// backend, model) over the same provider/model resolution the dispatch path
/// uses (ladder rungs 2-4 — rung 1 is per-effect and stays out of the
/// kernel-construction fingerprint), or the literal `"fixture"` when the
/// fixture path is selected — so switching backend or model re-runs future
/// coercions instead of replaying a stale terminal, while fixture runs stay
/// deterministic. Credential resolution is deliberately NOT consulted: a
/// missing or rotated key must fail at dispatch, never rekey admissions.
/// The rung-3 registry default is threaded in so the fingerprint resolves
/// provider/model through the SAME ladder the dispatch path uses.
pub fn coercion_config_fingerprint_with_registry(
    registry_default: Option<&CoerceRegistryDefault>,
) -> String {
    fingerprint_inner(
        &OperatorEnv::from_process(),
        registry_default,
        &codex_config_model,
    )
}

fn fingerprint_inner(
    env: &OperatorEnv,
    registry_default: Option<&CoerceRegistryDefault>,
    codex_model: &dyn Fn() -> Option<String>,
) -> String {
    // Rung 2: operator override.
    if let Some(provider_name) = &env.provider {
        if is_fixture_provider_name(provider_name) {
            return "fixture".to_owned();
        }
        let model = env.model.clone().or_else(codex_model).unwrap_or_default();
        return whipplescript_kernel::coerce::coercion_config_fingerprint(
            "schema_coercer",
            provider_name,
            provider_name,
            &model,
        );
    }
    // Rung 3: registry default.
    if let Some(default) = registry_default {
        if !is_fixture_provider_name(&default.provider) {
            let config = parsed_registry_config(default);
            let backend_name = registry_backend_name(default, &config)
                .unwrap_or_else(|_| default.provider.clone());
            let model = env
                .model
                .clone()
                .or_else(|| config_string(&config, "model"))
                .or_else(codex_model)
                .unwrap_or_default();
            return whipplescript_kernel::coerce::coercion_config_fingerprint(
                "schema_coercer",
                &default.provider,
                &backend_name,
                &model,
            );
        }
    }
    // Rung 4.
    "fixture".to_owned()
}

/// Resolve the coerce configuration through the full four-rung ladder.
/// `provider_override` is the per-effect `provider` from source (rung 1);
/// `registry_default` is the claim-time `schema.coerce` binding row (rung 3).
pub fn resolve_coercion_selection(
    provider_override: Option<&str>,
    registry_default: Option<&CoerceRegistryDefault>,
) -> Result<CoerceSelection, String> {
    resolve_selection_inner(
        provider_override,
        &OperatorEnv::from_process(),
        registry_default,
        &CredentialProbes::real(),
    )
}

/// Resolve native coerce configuration from the environment only (ladder
/// rungs 2 and 4 — no store in hand). `Ok(None)` selects the fixture path;
/// `Err` is a binding-time configuration/credential failure. Kept for
/// surfaces without a runtime store (the improve loop's judge/proposer
/// transport); store-backed call sites use [`resolve_coercion_selection`].
pub fn resolve_native_coerce_config() -> Result<Option<ResolvedCoercionConfig>, String> {
    Ok(resolve_coercion_selection(None, None)?.config)
}

fn resolve_selection_inner(
    provider_override: Option<&str>,
    env: &OperatorEnv,
    registry_default: Option<&CoerceRegistryDefault>,
    probes: &CredentialProbes<'_>,
) -> Result<CoerceSelection, String> {
    // Rung 1: per-effect `provider` in source.
    if let Some(name) = provider_override {
        if is_fixture_provider_name(name) {
            return Ok(fixture_selection(CoerceSelectionRung::PerEffectProvider));
        }
        let backend = parse_provider(name)?;
        return native_selection(
            CoerceSelectionRung::PerEffectProvider,
            name,
            backend,
            env,
            None,
            probes,
        );
    }
    // Rung 2: operator override (env + whip auth).
    if let Some(name) = &env.provider {
        if is_fixture_provider_name(name) {
            return Ok(fixture_selection(CoerceSelectionRung::OperatorOverride));
        }
        let backend = parse_provider(name)?;
        return native_selection(
            CoerceSelectionRung::OperatorOverride,
            name,
            backend,
            env,
            None,
            probes,
        );
    }
    // Rung 3: registry default (the schema.coerce binding row).
    if let Some(default) = registry_default {
        if !is_fixture_provider_name(&default.provider) {
            let config = parsed_registry_config(default);
            let backend_name = registry_backend_name(default, &config)?;
            let backend = parse_provider(&backend_name).map_err(|error| {
                format!("registry schema.coerce binding is misconfigured: {error}")
            })?;
            return native_selection(
                CoerceSelectionRung::RegistryDefault,
                &default.provider,
                backend,
                env,
                Some(&config),
                probes,
            );
        }
    }
    // Rung 4: fixture.
    Ok(fixture_selection(CoerceSelectionRung::Fixture))
}

fn fixture_selection(rung: CoerceSelectionRung) -> CoerceSelection {
    CoerceSelection {
        config: None,
        rung,
        credential_source: None,
    }
}

/// The registry row's parsed `config_json` (an object; anything else reads as
/// empty — the fields are optional refinements, never credentials).
fn parsed_registry_config(default: &CoerceRegistryDefault) -> Value {
    default
        .config_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<Value>(json).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
}

fn config_string(config: &Value, key: &str) -> Option<String> {
    config
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn config_u64(config: &Value, key: &str) -> Option<u64> {
    config.get(key).and_then(Value::as_u64)
}

/// The backend name a registry binding selects: the provider id `native`
/// carries its backend in `config_json` (`backend`, or `provider` matching the
/// DO secrets-door field name); a binding may also name a backend directly.
fn registry_backend_name(
    default: &CoerceRegistryDefault,
    config: &Value,
) -> Result<String, String> {
    if default.provider == "native" {
        return config_string(config, "backend")
            .or_else(|| config_string(config, "provider"))
            .ok_or_else(|| {
                "registry schema.coerce binding selects provider `native` but its \
                 effect_providers config_json names no `backend` (`openai`, `openai-generic`, \
                 or `anthropic`)"
                    .to_owned()
            });
    }
    Ok(default.provider.clone())
}

/// Resolve one native selection: credential (loud failure when missing — a
/// selected provider never silently degrades to a fixture), then the config
/// fields with env overriding the registry row overriding the package-owned
/// defaults (operator-override-over-registry-default).
fn native_selection(
    rung: CoerceSelectionRung,
    provider_id: &str,
    backend: CoerceProvider,
    env: &OperatorEnv,
    registry_config: Option<&Value>,
    probes: &CredentialProbes<'_>,
) -> Result<CoerceSelection, String> {
    let (api_key, source) =
        (probes.credential)(backend).ok_or_else(|| missing_credential_message(backend))?;
    if backend == CoerceProvider::Anthropic {
        // Anthropic coerce uses a console API key only (model_auth owns the rule).
        if let Some(rejection) = anthropic_oauth_rejection(&api_key) {
            return Err(rejection);
        }
    }
    // The OpenAI Codex OAuth token routes to the codex backend (SSE) with the
    // account id from `~/.codex/auth.json`.
    let codex_account_id = (backend == CoerceProvider::OpenAi
        && source == CredentialSource::CodexOAuth)
        .then(|| (probes.codex_account)())
        .flatten();
    let empty = Value::Object(serde_json::Map::new());
    let registry_config = registry_config.unwrap_or(&empty);
    let base_url = env
        .base_url
        .clone()
        .or_else(|| config_string(registry_config, "base_url"))
        .unwrap_or_else(|| {
            if codex_account_id.is_some() {
                "https://chatgpt.com".to_owned()
            } else {
                backend.default_base_url().to_owned()
            }
        });
    // Model is not hard-coded: `WHIPPLESCRIPT_COERCE_MODEL` wins, then the
    // registry row's `model`, then (codex path only) `~/.codex/config.toml`.
    let model = env
        .model
        .clone()
        .or_else(|| config_string(registry_config, "model"))
        .or_else(|| {
            codex_account_id
                .as_ref()
                .and_then(|_| (probes.codex_model)())
        })
        .ok_or_else(|| {
            if codex_account_id.is_some() {
                "no coerce model: set WHIPPLESCRIPT_COERCE_MODEL, or set `model` in \
                 ~/.codex/config.toml"
                    .to_owned()
            } else {
                "no coerce model: set WHIPPLESCRIPT_COERCE_MODEL (or the registry binding's \
                 `model`) to the provider model id"
                    .to_owned()
            }
        })?;
    let max_tokens = env
        .max_tokens
        .or_else(|| config_u64(registry_config, "max_tokens").map(|value| value as u32))
        .unwrap_or(DEFAULT_COERCE_MAX_TOKENS);
    let timeout_secs = env
        .timeout_secs
        .or_else(|| config_u64(registry_config, "timeout_secs"))
        .unwrap_or(DEFAULT_COERCE_TIMEOUT_SECS);
    Ok(CoerceSelection {
        config: Some(ResolvedCoercionConfig {
            provider_id: provider_id.to_owned(),
            backend,
            base_url,
            api_key,
            model,
            max_tokens,
            timeout_secs,
            codex_account_id,
        }),
        rung,
        credential_source: Some(source),
    })
}

fn missing_credential_message(provider: CoerceProvider) -> String {
    match provider {
        CoerceProvider::Anthropic => {
            "coerce provider `anthropic` needs a console API key: set ANTHROPIC_API_KEY or run \
             `whip auth set anthropic <key>`"
                .to_owned()
        }
        CoerceProvider::OpenAi | CoerceProvider::OpenAiCompat => {
            "coerce provider `openai` needs a credential: set OPENAI_API_KEY, run \
             `whip auth set openai <key>`, or sign in with `codex login`"
                .to_owned()
        }
    }
}

fn parse_provider(name: &str) -> Result<CoerceProvider, String> {
    match name {
        "openai" => Ok(CoerceProvider::OpenAi),
        "openai-generic" => Ok(CoerceProvider::OpenAiCompat),
        "anthropic" => Ok(CoerceProvider::Anthropic),
        other => Err(format!(
            "unknown coerce provider `{other}` \
             (expected `openai`, `openai-generic`, or `anthropic`)"
        )),
    }
}

/// The single network side effect, backed by `ureq` (synchronous — consistent
/// with how the worker drains effects serially; concurrency comes from running
/// effects on a worker thread pool, not async).
pub struct UreqCoerceTransport {
    agent: ureq::Agent,
    workspace_egress_token: Option<String>,
}

impl UreqCoerceTransport {
    pub fn new(timeout: Duration) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(timeout)
            .user_agent("whipplescript-coerce")
            .build();
        Self {
            agent,
            workspace_egress_token: None,
        }
    }

    pub fn with_workspace_egress_token(mut self, token: Option<String>) -> Self {
        self.workspace_egress_token = token;
        self
    }
}

impl CoerceTransport for UreqCoerceTransport {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, CoerceTransportError> {
        let mut builder = self.agent.post(&request.url);
        for (name, value) in &request.headers {
            builder = builder.set(name, value);
        }
        if let Some(token) = &self.workspace_egress_token {
            builder = builder.set("x-gaugewright-workspace-egress-token", token);
        }
        // We know the response is an SSE stream from the request's own Accept
        // header — don't rely on the server's (sometimes absent) content-type.
        let expect_sse = request
            .headers
            .iter()
            .any(|(name, value)| name == "accept" && value.contains("event-stream"));
        match builder.send_json(request.body.clone()) {
            Ok(response) => Ok(read_response(response, expect_sse)),
            // A non-2xx status is still a structured (JSON) response — parse it
            // for the provider error message, never as SSE.
            Err(ureq::Error::Status(_, response)) => Ok(read_response(response, false)),
            Err(ureq::Error::Transport(transport)) => {
                let message = transport.to_string();
                if message.to_ascii_lowercase().contains("timed out")
                    || message.to_ascii_lowercase().contains("timeout")
                {
                    Err(CoerceTransportError::Timeout)
                } else {
                    Err(CoerceTransportError::Transport(message))
                }
            }
        }
    }
}

fn read_response(response: ureq::Response, expect_sse: bool) -> HttpResponse {
    let status = response.status();
    if expect_sse {
        // Codex backend: assemble the SSE Responses stream into a `response`-shaped
        // object the kernel parser reads. (The server's content-type header is
        // unreliable here, so we key off the request's Accept instead.)
        let raw = response.into_string().unwrap_or_default();
        return HttpResponse {
            status,
            body: assemble_responses_sse(&raw),
        };
    }
    let body = response.into_json::<Value>().unwrap_or(Value::Null);
    HttpResponse { status, body }
}

/// Collapse a Responses-API SSE stream into a `response`-shaped object the
/// kernel's OpenAI parser can read. The structured output is carried by the
/// `response.output_text.delta` events (the codex `response.completed` payload's
/// `output[]` does not always include the assembled text), so prefer the
/// concatenated deltas and attach usage from the completed event.
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
            // Collect them so a tool-calling turn survives assembly.
            Some("response.output_item.done") => {
                if let Some(item) = event.get("item") {
                    done_items.push(item.clone());
                }
            }
            _ => {}
        }
    }
    let mut completed = completed.unwrap_or(Value::Null);
    let output_missing = completed
        .get("output")
        .and_then(Value::as_array)
        .map(|output| output.is_empty())
        .unwrap_or(true);
    if output_missing && !done_items.is_empty() {
        completed["output"] = Value::Array(done_items);
    }
    if !deltas.is_empty() {
        let usage = completed.get("usage").cloned().unwrap_or(Value::Null);
        let mut assembled = serde_json::json!({ "output_text": deltas, "usage": usage });
        // Keep any collected items alongside the text: a turn may carry both
        // an assistant message and tool calls.
        if let Some(output) = completed.get("output") {
            assembled["output"] = output.clone();
        }
        return assembled;
    }
    // No text deltas: fall back to the completed response object (the kernel
    // parser walks output[].content[].text).
    completed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use whipplescript_kernel::coerce_native::{build_coerce_call_parts, render_coerce_prompt};

    #[test]
    fn assemble_responses_sse_prefers_delta_text_and_keeps_usage() {
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"{\\\"v\\\":1}\"}\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":3,\"output_tokens\":2},\"output\":[]}}\n",
            "data: [DONE]\n",
        );
        let body = assemble_responses_sse(raw);
        assert_eq!(body["output_text"].as_str(), Some("{\"v\":1}"));
        assert_eq!(body["usage"]["input_tokens"], 3);
    }

    /// The live codex backend sends `response.completed` with an empty
    /// `output[]`; items arrive only as `response.output_item.done` events
    /// (same quirk the host runtime handles) — assembly must recover them.
    #[test]
    fn assemble_responses_sse_recovers_items_from_output_item_done_events() {
        let raw = concat!(
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"c9\",\"name\":\"write\",\"arguments\":\"{}\"}}\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":{\"input_tokens\":7}}}\n",
            "data: [DONE]\n",
        );
        let body = assemble_responses_sse(raw);
        assert_eq!(body["output"][0]["call_id"], "c9");
        assert_eq!(body["usage"]["input_tokens"], 7);
    }

    fn no_credential(_: CoerceProvider) -> Option<(String, CredentialSource)> {
        None
    }

    fn api_key_credential(_: CoerceProvider) -> Option<(String, CredentialSource)> {
        Some((
            "sk-test".to_owned(),
            CredentialSource::Env("OPENAI_API_KEY"),
        ))
    }

    fn no_codex_model() -> Option<String> {
        None
    }

    fn no_codex_account() -> Option<String> {
        None
    }

    fn test_probes(
        credential: &'static dyn Fn(CoerceProvider) -> Option<(String, CredentialSource)>,
    ) -> CredentialProbes<'static> {
        CredentialProbes {
            credential,
            codex_model: &no_codex_model,
            codex_account: &no_codex_account,
        }
    }

    fn env_with_model(model: &str) -> OperatorEnv {
        OperatorEnv {
            model: Some(model.to_owned()),
            ..OperatorEnv::empty()
        }
    }

    fn registry_native_openai(model: Option<&str>) -> CoerceRegistryDefault {
        let mut config = serde_json::Map::new();
        config.insert("backend".to_owned(), json!("openai"));
        if let Some(model) = model {
            config.insert("model".to_owned(), json!(model));
        }
        CoerceRegistryDefault {
            provider: "native".to_owned(),
            config_json: Some(Value::Object(config).to_string()),
        }
    }

    // ---- four-rung selection ladder (spec/std-coercion.md, slice 2 gate) ----

    #[test]
    fn rung1_per_effect_provider_beats_everything() {
        let selection = resolve_selection_inner(
            Some("openai"),
            &env_with_model("gpt-env"),
            Some(&registry_native_openai(Some("gpt-registry"))),
            &test_probes(&api_key_credential),
        )
        .expect("resolves");
        assert_eq!(selection.rung, CoerceSelectionRung::PerEffectProvider);
        let config = selection.config.expect("native config");
        assert_eq!(config.provider_id, "openai");
        assert!(matches!(config.backend, CoerceProvider::OpenAi));
        // A per-effect fixture override is also rung 1.
        let fixture = resolve_selection_inner(
            Some("fixture"),
            &env_with_model("gpt-env"),
            None,
            &test_probes(&api_key_credential),
        )
        .expect("resolves");
        assert_eq!(fixture.rung, CoerceSelectionRung::PerEffectProvider);
        assert!(fixture.config.is_none());
    }

    #[test]
    fn rung2_operator_override_beats_registry_default() {
        let env = OperatorEnv {
            provider: Some("anthropic".to_owned()),
            model: Some("claude-test".to_owned()),
            ..OperatorEnv::empty()
        };
        let credential = |_: CoerceProvider| {
            Some((
                "sk-ant-api03-x".to_owned(),
                CredentialSource::Env("ANTHROPIC_API_KEY"),
            ))
        };
        let selection = resolve_selection_inner(
            None,
            &env,
            Some(&registry_native_openai(Some("gpt-registry"))),
            &CredentialProbes {
                credential: &credential,
                codex_model: &no_codex_model,
                codex_account: &no_codex_account,
            },
        )
        .expect("resolves");
        assert_eq!(selection.rung, CoerceSelectionRung::OperatorOverride);
        let config = selection.config.expect("native config");
        assert_eq!(config.provider_id, "anthropic");
        assert!(matches!(config.backend, CoerceProvider::Anthropic));
        assert_eq!(config.model, "claude-test");
        // `WHIPPLESCRIPT_COERCE_PROVIDER=fixture` forces the fixture path even
        // over a native registry default — still the operator's rung.
        let forced_fixture = resolve_selection_inner(
            None,
            &OperatorEnv {
                provider: Some("fixture".to_owned()),
                ..OperatorEnv::empty()
            },
            Some(&registry_native_openai(Some("gpt-registry"))),
            &test_probes(&api_key_credential),
        )
        .expect("resolves");
        assert_eq!(forced_fixture.rung, CoerceSelectionRung::OperatorOverride);
        assert!(forced_fixture.config.is_none());
    }

    #[test]
    fn rung3_registry_default_selects_native_and_env_fields_override_it() {
        // Registry default alone selects native (registry-honest selection).
        let selection = resolve_selection_inner(
            None,
            &OperatorEnv::empty(),
            Some(&registry_native_openai(Some("gpt-registry"))),
            &test_probes(&api_key_credential),
        )
        .expect("resolves");
        assert_eq!(selection.rung, CoerceSelectionRung::RegistryDefault);
        let config = selection.config.expect("native config");
        assert_eq!(config.provider_id, "native");
        assert!(matches!(config.backend, CoerceProvider::OpenAi));
        assert_eq!(config.model, "gpt-registry");
        assert_eq!(config.max_tokens, DEFAULT_COERCE_MAX_TOKENS);
        assert_eq!(config.timeout_secs, DEFAULT_COERCE_TIMEOUT_SECS);
        // Field-level env vars are operator-override-over-registry-default:
        // the registry still SELECTS (rung 3), the env refines the fields.
        let refined = resolve_selection_inner(
            None,
            &env_with_model("gpt-env"),
            Some(&registry_native_openai(Some("gpt-registry"))),
            &test_probes(&api_key_credential),
        )
        .expect("resolves");
        assert_eq!(refined.rung, CoerceSelectionRung::RegistryDefault);
        assert_eq!(refined.config.expect("native config").model, "gpt-env");
    }

    #[test]
    fn rung4_fixture_when_nothing_selects_native() {
        // No override, no env, no registry row.
        let bare = resolve_selection_inner(
            None,
            &OperatorEnv::empty(),
            None,
            &test_probes(&no_credential),
        )
        .expect("resolves");
        assert_eq!(bare.rung, CoerceSelectionRung::Fixture);
        assert!(bare.config.is_none());
        // The migration-0001 seeded binding (`builtin-coerce`) IS the fixture
        // path: nothing selects native.
        let seeded = resolve_selection_inner(
            None,
            &OperatorEnv::empty(),
            Some(&CoerceRegistryDefault {
                provider: "builtin-coerce".to_owned(),
                config_json: Some("{}".to_owned()),
            }),
            &test_probes(&no_credential),
        )
        .expect("resolves");
        assert_eq!(seeded.rung, CoerceSelectionRung::Fixture);
        assert!(seeded.config.is_none());
    }

    #[test]
    fn misconfiguration_errors_loudly_instead_of_degrading_to_fixture() {
        // Provider selected (rung 2), no credential: a hard error.
        let env = OperatorEnv {
            provider: Some("openai".to_owned()),
            model: Some("gpt-test".to_owned()),
            ..OperatorEnv::empty()
        };
        let error = resolve_selection_inner(None, &env, None, &test_probes(&no_credential))
            .expect_err("missing credential is loud");
        assert!(error.contains("needs a credential"), "{error}");
        // Registry rung misconfigurations are equally loud.
        let no_backend = CoerceRegistryDefault {
            provider: "native".to_owned(),
            config_json: Some("{}".to_owned()),
        };
        let error = resolve_selection_inner(
            None,
            &OperatorEnv::empty(),
            Some(&no_backend),
            &test_probes(&api_key_credential),
        )
        .expect_err("native binding without a backend is loud");
        assert!(error.contains("names no `backend`"), "{error}");
        let unknown = CoerceRegistryDefault {
            provider: "gemini".to_owned(),
            config_json: None,
        };
        let error = resolve_selection_inner(
            None,
            &OperatorEnv::empty(),
            Some(&unknown),
            &test_probes(&api_key_credential),
        )
        .expect_err("unknown registry provider is loud");
        assert!(error.contains("misconfigured"), "{error}");
    }

    #[test]
    fn anthropic_oauth_rejection_regression_holds_through_the_ladder() {
        let env = OperatorEnv {
            provider: Some("anthropic".to_owned()),
            model: Some("claude-test".to_owned()),
            ..OperatorEnv::empty()
        };
        let oauth_credential =
            |_: CoerceProvider| Some(("sk-ant-oat01-abc".to_owned(), CredentialSource::Stored));
        let error = resolve_selection_inner(
            None,
            &env,
            None,
            &CredentialProbes {
                credential: &oauth_credential,
                codex_model: &no_codex_model,
                codex_account: &no_codex_account,
            },
        )
        .expect_err("oauth token rejected for anthropic");
        assert!(error.contains("console API key"), "{error}");
    }

    #[test]
    fn fingerprint_resolves_through_the_same_ladder_rungs_2_to_4() {
        // Rung 4: fixture literal.
        assert_eq!(
            fingerprint_inner(&OperatorEnv::empty(), None, &no_codex_model),
            "fixture"
        );
        // Registry fixture binding is still the fixture literal.
        assert_eq!(
            fingerprint_inner(
                &OperatorEnv::empty(),
                Some(&CoerceRegistryDefault {
                    provider: "builtin-coerce".to_owned(),
                    config_json: None,
                }),
                &no_codex_model
            ),
            "fixture"
        );
        // Rung 3: provider id + backend + model from the registry row — and it
        // matches the dispatch-path resolution for the same inputs.
        let registry = registry_native_openai(Some("gpt-registry"));
        let fingerprint =
            fingerprint_inner(&OperatorEnv::empty(), Some(&registry), &no_codex_model);
        assert_eq!(
            fingerprint,
            whipplescript_kernel::coerce::coercion_config_fingerprint(
                "schema_coercer",
                "native",
                "openai",
                "gpt-registry",
            )
        );
        let dispatch = resolve_selection_inner(
            None,
            &OperatorEnv::empty(),
            Some(&registry),
            &test_probes(&api_key_credential),
        )
        .expect("resolves")
        .config
        .expect("native config");
        assert_eq!(
            fingerprint,
            whipplescript_kernel::coerce::coercion_config_fingerprint(
                "schema_coercer",
                &dispatch.provider_id,
                "openai",
                &dispatch.model,
            ),
            "fingerprint and dispatch must resolve provider/model identically"
        );
        // Rung 2 beats rung 3 in the fingerprint exactly as in dispatch.
        let env = OperatorEnv {
            provider: Some("anthropic".to_owned()),
            model: Some("claude-test".to_owned()),
            ..OperatorEnv::empty()
        };
        assert_eq!(
            fingerprint_inner(&env, Some(&registry), &no_codex_model),
            whipplescript_kernel::coerce::coercion_config_fingerprint(
                "schema_coercer",
                "anthropic",
                "anthropic",
                "claude-test",
            )
        );
    }

    #[test]
    fn anthropic_oauth_token_is_recognized_for_rejection() {
        // Anthropic coerce requires a console key; the resolver uses this to
        // reject OAuth tokens (a terms gray area), not to route them.
        assert!(whipplescript_kernel::coerce_native::is_anthropic_oauth_token("sk-ant-oat01-abc"));
        assert!(
            !whipplescript_kernel::coerce_native::is_anthropic_oauth_token("sk-ant-api03-real")
        );
    }

    #[test]
    fn parse_provider_accepts_known_and_rejects_unknown() {
        assert!(matches!(
            parse_provider("openai"),
            Ok(CoerceProvider::OpenAi)
        ));
        assert!(matches!(
            parse_provider("anthropic"),
            Ok(CoerceProvider::Anthropic)
        ));
        assert!(parse_provider("gemini").is_err());
    }

    #[test]
    fn render_substitutes_arguments_and_output_format() {
        let arguments = json!({ "summary": "shipped the feature", "count": 3 });
        let schema = json!({ "type": "object" });
        let rendered = render_coerce_prompt(
            "Classify: {{ summary }} ({{ count }})\n{{ ctx.output_format }}",
            &arguments,
            Some(&schema),
        );
        assert!(rendered.contains("shipped the feature"));
        assert!(rendered.contains("(3)"));
        // The output-format token embeds the JSON Schema.
        assert!(rendered.contains("JSON Schema"));
    }

    #[test]
    fn render_preserves_unknown_interpolation() {
        let rendered = render_coerce_prompt("hi {{ missing }}", &json!({}), None);
        assert_eq!(rendered, "hi {{ missing }}");
    }

    #[test]
    fn render_supports_dotted_access() {
        let arguments = json!({ "item": { "title": "Bug" } });
        let rendered = render_coerce_prompt("Title: {{ item.title }}", &arguments, None);
        assert_eq!(rendered, "Title: Bug");
    }

    #[test]
    fn build_call_parts_resolves_prompt_and_schema() {
        let source = r#"
@service
workflow Coerce

enum Verdict {
  Yes
  No
}
coerce judge(summary string) -> Verdict {
  prompt """markdown
  Decide: {{ summary }}
  {{ ctx.output_format }}
  """
}

output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("compiles");
        // Positional args (`arg0`) are mapped to the declared parameter name so
        // `{{ summary }}` resolves — this is how a `coerce judge("…")` call lowers.
        let arguments = json!({ "arg0": "looks good" });
        let (prompt, schema, wrapped, name) =
            build_coerce_call_parts(&ir, "judge", &arguments).expect("parts");
        assert!(
            prompt.contains("looks good"),
            "positional arg0 should bind to `summary`: {prompt}"
        );
        assert!(wrapped, "an enum output is wrapped in a value envelope");
        assert_eq!(name, "Verdict");
        assert_eq!(schema["properties"]["value"]["enum"][0], "Yes");
    }

    #[test]
    fn build_call_parts_rejects_unknown_function() {
        let source = r#"
@service
workflow Coerce
output result R
class R { v string }
signal go.now { x string }
rule j
  when go.now as g
=> { complete result { v "ok" } }
"#;
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("compiles");
        assert!(build_coerce_call_parts(&ir, "missing", &json!({})).is_err());
    }
}
