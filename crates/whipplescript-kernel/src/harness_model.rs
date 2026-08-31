//! Live provider model client for the owned brokered harness (DR-0024).
//!
//! Generalizes the single-shot `coerce` client (`coerce_native`) into a
//! multi-turn tool-use client: it serializes the running conversation + the tool
//! specs into a provider request, posts it through the shared [`CoerceTransport`]
//! seam, and parses the reply into a normalized [`ModelReply`] (free text plus any
//! tool calls). The pure request-build / response-parse functions are
//! unit-testable with a fake transport; the CLI supplies the real `ureq`
//! transport and resolved credentials (live calls are credential-gated).
//!
//! Slice-1 scope: OpenAI Responses and Anthropic Messages (non-streaming). The
//! Codex OAuth SSE backend (function-call items over an event stream) rides the
//! same seam: [`assemble_codex_responses_sse`] collapses its stream into a
//! response-shaped value before the shared mapping runs.

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::coerce_native::{
    CoerceProvider, CoerceTransport, CoerceTransportError, HttpRequest, HttpResponse,
};
use crate::exec_http::sha256_hex;
use crate::harness_loop::{
    ChatMessage, HarnessModelClient, HarnessModelError, HttpModelClient, ModelCallMachine,
    ModelReply, ToolCall, ToolSpec,
};
use crate::idempotency_key;
use crate::sansio::run_to_completion;

/// Cap on a provider control-plane error string crossing into a turn failure
/// (matches the coerce path; DR-0024 lets operational errors cross redaction).
const PROVIDER_ERROR_CAP: usize = 300;
const OPENAI_PROMPT_CACHE_KEY_MAX_BYTES: usize = 64;

fn openai_request_key(cache_key: Option<&str>) -> Option<String> {
    cache_key.map(|key| {
        if key.len() <= OPENAI_PROMPT_CACHE_KEY_MAX_BYTES {
            key.to_owned()
        } else {
            sha256_hex(key.as_bytes())
        }
    })
}

/// The context window (tokens) of a provider model, for the conversation-compaction
/// trigger (context-assembly Phase 4). This is a **model capability**, derived from
/// the provider + model id — never an operator config knob. The numbers are the
/// window WhippleScript's requests actually get. Unknown models fall back to a
/// conservative family default.
pub fn model_context_window(wire: ModelWire, model: &str) -> u64 {
    let model = model.to_ascii_lowercase();
    // Match on the bare id. A metered-gateway name carries its provider
    // (`openai/gpt-5-mini`) because unified billing routes by that form, and the
    // capability belongs to the model rather than to the routing prefix.
    //
    // Live 400s on 2026-08-11/12: the o-series test below was `starts_with('o')`,
    // which every `openai/`-prefixed name satisfies. So `openai/gpt-5-mini` was
    // read as a reasoning model with a 200k window, and — because the output
    // limit reuses this number — the turn asked for 200,000 completion tokens
    // against that model's 128,000 ceiling and was refused outright.
    let bare = model.rsplit('/').next().unwrap_or(model.as_str());
    let is_claude = model.contains("claude") || model.starts_with("anthropic/");
    if is_claude {
        return if model.contains("opus-5")
            || model.contains("sonnet-5")
            || model.contains("opus-4-6")
            || model.contains("opus-4-7")
            || model.contains("opus-4-8")
            || model.contains("sonnet-4-6")
        {
            1_000_000
        } else {
            200_000
        };
    }
    // Claude models are 200k standard context.
    if wire == ModelWire::AnthropicMessages {
        return 200_000;
    }
    // xAI publishes few, stable windows: the fast variants carry 2M, the
    // grok-4 family and grok-code 256k, and everything earlier or unrecognized
    // falls back to grok-3's 131k (conservative default).
    //
    // Keyed on the model id rather than on the wire, because the wire no longer
    // distinguishes them: xAI speaks chat completions, and so do the dozen other
    // endpoints that can serve a grok model. A window is a property of the model
    // wherever it is served from — the same reason the Claude test above reads
    // the name.
    if bare.contains("grok") {
        return if bare.contains("grok-4-fast") || bare.contains("grok-4.1-fast") {
            2_000_000
        } else if bare.contains("grok-4") || bare.contains("grok-code") {
            256_000
        } else {
            131_072
        };
    }
    // Any remaining OpenAI-wire endpoint serves arbitrary models whose windows we
    // can't know; fall back to the OpenAI heuristic (conservative default for an
    // unrecognized id).
    if bare.contains("gpt-4.1") {
        1_000_000
    } else if bare.contains("gpt-4o") || bare.contains("gpt-4-turbo") {
        128_000
    } else if is_openai_reasoning_model(bare) {
        200_000
    } else {
        128_000
    }
}

/// An OpenAI o-series reasoning model (`o1`, `o3`, `o4`, and their variants).
///
/// Matched as a leading token rather than a leading letter. The letter form was
/// satisfied by the `openai/` routing prefix that every metered-gateway model
/// name carries, so it silently claimed the whole catalogue.
fn is_openai_reasoning_model(bare: &str) -> bool {
    ["o1", "o3", "o4"].iter().any(|series| {
        bare.strip_prefix(*series)
            // `o3` and `o3-mini` are the series; `o3x` would be some other model.
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('-'))
    })
}

/// The output ceiling of a Claude model, in tokens.
///
/// Anthropic's Messages API requires `max_tokens`, so this wire must name a
/// number even when nobody chose one. It can: the Claude ceilings are few and
/// published, unlike the OpenAI catalogue — see [`model_output_limit`].
fn anthropic_output_limit(model: &str) -> u64 {
    let model = model.to_ascii_lowercase();
    if model.contains("opus-5")
        || model.contains("sonnet-5")
        || model.contains("opus-4-6")
        || model.contains("opus-4-7")
        || model.contains("opus-4-8")
        || model.contains("sonnet-4-6")
    {
        128_000
    } else {
        64_000
    }
}

/// The output limit to request, or `None` to send none at all.
///
/// **Only Anthropic gets a number.** Its API requires the field, and Claude's
/// ceilings are known. Every OpenAI-family wire treats the field as optional,
/// and we do not know those ceilings — so naming one is a guess, and a wrong
/// guess is not clamped, it is refused:
///
/// ```text
/// 400  max_tokens is too large: 200000. This model supports at most
///      128000 completion tokens, whereas you provided 200000.
/// ```
///
/// That was live on the `gpt-5-mini` panel, from this function returning the
/// *context window* as if it were an output ceiling. They are different
/// capabilities and the window is the larger one, so the substitution failed in
/// the one direction the provider rejects. `gpt-4o` was equally broken and
/// simply had no traffic: a 128,000 window against a 16,384 output ceiling.
///
/// Omitting is not a fallback, it is the accurate answer. The provider then
/// applies its own true ceiling — which is precisely the capability the guess
/// was reaching for, sourced from the party that actually knows it. An operator
/// who wants a smaller budget still sets one explicitly, and that value is sent.
pub fn model_output_limit(wire: ModelWire, model: &str) -> Option<u64> {
    let lowered = model.to_ascii_lowercase();
    let is_claude = lowered.contains("claude") || lowered.starts_with("anthropic/");
    if is_claude || wire == ModelWire::AnthropicMessages {
        Some(anthropic_output_limit(&lowered))
    } else {
        None
    }
}

/// The request dialect one agent turn speaks to a model endpoint.
///
/// Distinct from [`CoerceProvider`], which answers *whose credential pays and
/// how it is resolved*. This answers *what bytes go on the wire*, and the two
/// are genuinely independent: the metered Cloudflare gateway is one provider
/// identity that fronts three dialects, and a single dialect (chat completions)
/// is spoken by a dozen provider identities.
///
/// Conflating them is what made models look swappable when they were not. The
/// dialect used to be recovered by inspecting a base URL for a suffix, so a
/// model whose family requires the Responses API was silently sent on the chat
/// completions wire and refused at the first turn that carried tools. A dialect
/// that is declared can be checked before anything is published.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelWire {
    /// Anthropic's Messages API (`/v1/messages`): `tool_use` content blocks.
    AnthropicMessages,
    /// OpenAI's Responses API (`/v1/responses`): `function_call` output items.
    /// The dialect OpenAI reasoning models require in order to carry tools —
    /// and, on that surface, to carry reasoning state between tool calls.
    OpenAiResponses,
    /// The Chat Completions API (`/chat/completions`): `tool_calls[]` on the
    /// assistant message. Near-universally implemented, and the older surface.
    OpenAiChatCompat,
    /// Chat Completions with **no native tool vocabulary**: the tool call is
    /// requested as structured output against a JSON schema, and WhippleScript
    /// reads it back out. The floor beneath every other dialect — a model that
    /// can honour a JSON schema can drive the loop, whether or not its endpoint
    /// implements function calling. See DR-0037.
    CoercedTools,
}

impl ModelWire {
    /// The dialect a provider identity speaks when nothing more specific is
    /// declared. Every arm is a deliberate statement rather than a default:
    /// an unrecognized surface has no honest fallback, so callers that cannot
    /// name a wire should refuse rather than guess.
    pub fn of_provider(provider: CoerceProvider) -> Self {
        match provider {
            CoerceProvider::Anthropic => ModelWire::AnthropicMessages,
            CoerceProvider::OpenAi => ModelWire::OpenAiResponses,
            CoerceProvider::OpenAiCompat | CoerceProvider::Xai => ModelWire::OpenAiChatCompat,
        }
    }

    /// Parse a declared wire name. Returns `None` for an unknown name so the
    /// caller can refuse rather than silently take a dialect the endpoint may
    /// not speak.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "anthropic-messages" => Some(ModelWire::AnthropicMessages),
            "openai-responses" => Some(ModelWire::OpenAiResponses),
            "openai-chat-compat" => Some(ModelWire::OpenAiChatCompat),
            "coerced-tools" => Some(ModelWire::CoercedTools),
            _ => None,
        }
    }

    /// The declared name, as it appears in a policy envelope or host config.
    pub fn as_str(self) -> &'static str {
        match self {
            ModelWire::AnthropicMessages => "anthropic-messages",
            ModelWire::OpenAiResponses => "openai-responses",
            ModelWire::OpenAiChatCompat => "openai-chat-compat",
            ModelWire::CoercedTools => "coerced-tools",
        }
    }

    /// Whether the dialect asks the endpoint for native function calling. The
    /// coerced dialect does not, which is exactly why it survives endpoints
    /// that refuse tools.
    pub fn uses_native_tools(self) -> bool {
        !matches!(self, ModelWire::CoercedTools)
    }
}

impl From<CoerceProvider> for ModelWire {
    fn from(provider: CoerceProvider) -> Self {
        ModelWire::of_provider(provider)
    }
}

/// A live model client over one provider API. The CLI builds this with a
/// `ureq`-backed transport and a resolved API key + model.
pub struct RealHarnessModelClient<'a, T: CoerceTransport + ?Sized> {
    transport: &'a T,
    wire: ModelWire,
    api_key: String,
    model: String,
    base_url: String,
    /// Absent means "send no output limit": the wire does not require one and
    /// no operator chose one. Only the Anthropic builder substitutes a value,
    /// because its API requires the field.
    max_tokens: Option<u64>,
    /// Stable cache key for this turn-thread (Decision 7): the run/effect id.
    /// Sent as `prompt_cache_key` on OpenAI; Anthropic caches by prefix hash
    /// (via `cache_control` breakpoints) and does not use it.
    cache_key: Option<String>,
    /// ChatGPT-plan Codex backend. When set, the turn targets
    /// `chatgpt.com/backend-api/codex/responses` rather than the OpenAI public
    /// API — the same routing `MessagesApiClient` already performs for coerce.
    /// A ChatGPT-plan OAuth token is not a public-API credential, so without
    /// this the owned harness presented one to `api.openai.com` and the
    /// provider refused it for want of `api.responses.write`.
    codex: Option<CodexBackend>,
    xai_api: bool,
    xai_subscription: bool,
}

impl<'a, T: CoerceTransport + ?Sized> RealHarnessModelClient<'a, T> {
    pub fn new(
        transport: &'a T,
        wire: impl Into<ModelWire>,
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        Self {
            transport,
            wire: wire.into(),
            api_key: api_key.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: max_tokens.into(),
            cache_key,
            codex: None,
            xai_api: false,
            xai_subscription: false,
        }
    }

    /// ChatGPT-plan Codex backend for the owned harness. Credential
    /// acquisition, refresh and storage stay host-owned; this client owns only
    /// the provider wire contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new_codex(
        transport: &'a T,
        access_token: impl Into<String>,
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        Self {
            transport,
            wire: ModelWire::OpenAiResponses,
            api_key: access_token.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: max_tokens.into(),
            cache_key,
            codex: Some(CodexBackend {
                account_id: account_id.into(),
                session_id: session_id.into(),
            }),
            xai_api: false,
            xai_subscription: false,
        }
    }

    /// xAI public API-key backend. It speaks Chat Completions and scopes xAI's
    /// automatic prompt cache with the `x-grok-conv-id` request header.
    pub fn new_xai(
        transport: &'a T,
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        let mut client = Self::new(
            transport,
            ModelWire::OpenAiChatCompat,
            api_key,
            model,
            base_url,
            max_tokens,
            cache_key,
        );
        client.xai_api = true;
        client
    }

    /// Grok subscription backend. The host owns OAuth acquisition and refresh;
    /// the runtime owns the fixed Responses wire and proxy request markers.
    pub fn new_xai_subscription(
        transport: &'a T,
        access_token: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        let mut client = Self::new(
            transport,
            ModelWire::OpenAiResponses,
            access_token,
            model,
            base_url,
            max_tokens,
            cache_key,
        );
        client.xai_subscription = true;
        client
    }
}

impl<T: CoerceTransport + ?Sized> HttpModelClient for RealHarnessModelClient<'_, T> {
    fn build_request(&self, messages: &[ChatMessage], tools: &[ToolSpec]) -> HttpRequest {
        if let Some(codex) = &self.codex {
            return build_codex_request(
                &self.base_url,
                &self.api_key,
                &self.model,
                self.cache_key.as_deref(),
                &codex.account_id,
                &codex.session_id,
                messages,
                tools,
            );
        }
        let mut request = build_request(
            self.wire,
            &self.base_url,
            &self.api_key,
            &self.model,
            self.max_tokens,
            self.cache_key.as_deref(),
            messages,
            tools,
        );
        if self.xai_api {
            apply_xai_api_cache_header(&mut request);
        }
        if self.xai_subscription {
            apply_xai_subscription_headers(&mut request, &self.model);
        }
        request
    }

    fn parse_response(
        &self,
        response: Result<HttpResponse, CoerceTransportError>,
    ) -> Result<ModelReply, HarnessModelError> {
        // The codex backend answers as an event stream even over the
        // synchronous transport, so its body is assembled before the shared
        // mapping. Every other surface on this client returns one JSON document.
        let response = response.map(|mut response| {
            if self.codex.is_some() {
                if let Some(raw) = response.body.as_str() {
                    response.body = assemble_codex_responses_sse(raw);
                }
            }
            response
        });
        map_transport_response(self.wire, response)
    }

    fn context_window(&self) -> u64 {
        model_context_window(self.wire, &self.model)
    }
}

impl<T: CoerceTransport + ?Sized> HarnessModelClient for RealHarnessModelClient<'_, T> {
    fn next(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ModelReply, HarnessModelError> {
        // One model call as a sans-IO step machine: prepare (`build_request`) →
        // `NeedsIo(Http)` → finish (`parse_response`), driven to completion
        // synchronously via the transport. Identical to a direct
        // build_request → post → parse_response.
        let mut machine = ModelCallMachine::new(self, messages, tools);
        run_to_completion(&mut machine, self.transport)
    }
}

/// A model client that owns only the provider config — no transport — so a host
/// that performs the HTTP itself drives it purely (DR-0033). This is the agent
/// counterpart to coerce's `build_coerce_call_parts`: the durable-object host
/// builds one from its secrets plane and drives it through the `HttpModelClient`
/// trait (`build_request` → its own `fetch` → `parse_response`) via the
/// `BrokeredTurnMachine`, never calling `next`/`run_to_completion`. It shares the
/// exact request-build / response-parse logic the native
/// [`RealHarnessModelClient`] uses, so the wire format is identical across hosts.
pub struct MessagesApiClient {
    wire: ModelWire,
    api_key: String,
    model: String,
    base_url: String,
    /// See [`RealHarnessModelClient::max_tokens`]: absent means send none.
    max_tokens: Option<u64>,
    /// Stable per-turn/effect cache scope (Decision 7). It remains the provider
    /// prompt-cache scope, while each distinct model round derives its own
    /// deterministic idempotency key from this scope and the exact model input.
    cache_key: Option<String>,
    codex: Option<CodexBackend>,
    xai_api: bool,
    xai_subscription: bool,
}

struct CodexBackend {
    account_id: String,
    session_id: String,
}

impl MessagesApiClient {
    pub fn new(
        wire: impl Into<ModelWire>,
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        Self {
            wire: wire.into(),
            api_key: api_key.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: max_tokens.into(),
            cache_key,
            codex: None,
            xai_api: false,
            xai_subscription: false,
        }
    }

    /// ChatGPT-plan Codex backend. Credential acquisition, refresh, and storage
    /// remain host-owned; this client owns only the provider wire contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new_codex(
        access_token: impl Into<String>,
        account_id: impl Into<String>,
        session_id: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        Self {
            wire: ModelWire::OpenAiResponses,
            api_key: access_token.into(),
            model: model.into(),
            base_url: base_url.into(),
            max_tokens: max_tokens.into(),
            cache_key,
            codex: Some(CodexBackend {
                account_id: account_id.into(),
                session_id: session_id.into(),
            }),
            xai_api: false,
            xai_subscription: false,
        }
    }

    pub fn new_xai(
        api_key: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        let mut client = Self::new(
            ModelWire::OpenAiChatCompat,
            api_key,
            model,
            base_url,
            max_tokens,
            cache_key,
        );
        client.xai_api = true;
        client
    }

    pub fn new_xai_subscription(
        access_token: impl Into<String>,
        model: impl Into<String>,
        base_url: impl Into<String>,
        max_tokens: impl Into<Option<u64>>,
        cache_key: Option<String>,
    ) -> Self {
        let mut client = Self::new(
            ModelWire::OpenAiResponses,
            access_token,
            model,
            base_url,
            max_tokens,
            cache_key,
        );
        client.xai_subscription = true;
        client
    }
}

impl HttpModelClient for MessagesApiClient {
    fn build_request(&self, messages: &[ChatMessage], tools: &[ToolSpec]) -> HttpRequest {
        if let Some(codex) = &self.codex {
            let mut request = build_codex_request(
                &self.base_url,
                &self.api_key,
                &self.model,
                self.cache_key.as_deref(),
                &codex.account_id,
                &codex.session_id,
                messages,
                tools,
            );
            set_round_idempotency_key(
                &mut request,
                round_idempotency_key(self.cache_key.as_deref(), messages, tools),
            );
            return request;
        }
        let mut request = build_request(
            self.wire,
            &self.base_url,
            &self.api_key,
            &self.model,
            self.max_tokens,
            self.cache_key.as_deref(),
            messages,
            tools,
        );
        if self.xai_api {
            apply_xai_api_cache_header(&mut request);
        }
        if self.xai_subscription {
            apply_xai_subscription_headers(&mut request, &self.model);
        }
        set_round_idempotency_key(
            &mut request,
            round_idempotency_key(self.cache_key.as_deref(), messages, tools),
        );
        // The Durable Object host owns incremental transport for every admitted
        // provider. The native client uses `RealHarnessModelClient`, so its
        // synchronous transport remains unchanged.
        request.body["stream"] = json!(true);
        request
            .headers
            .push(("accept".to_owned(), "text/event-stream".to_owned()));
        if matches!(
            self.wire,
            ModelWire::OpenAiChatCompat | ModelWire::CoercedTools
        ) {
            // A Chat Completions stream reports no usage at all unless the
            // request asks for it — the ordinary non-streamed response carries
            // `usage` unconditionally, so turning streaming on for this provider
            // silently removed the only token counts the turn ever produces. A
            // host that meters exact usage then has nothing to settle with and
            // must discard an answer the provider already gave. The Responses
            // and Messages streams always terminate with usage, so this is the
            // one wire that has to be asked.
            request.body["stream_options"] = json!({ "include_usage": true });
        }
        request
    }

    fn parse_response(
        &self,
        response: Result<HttpResponse, CoerceTransportError>,
    ) -> Result<ModelReply, HarnessModelError> {
        let response = response.map(|mut response| {
            if let Some(raw) = response.body.as_str() {
                response.body = match self.wire {
                    ModelWire::OpenAiResponses => assemble_codex_responses_sse(raw),
                    // The coerced dialect rides the chat-completions wire, so its
                    // stream assembles the same way; only the reply *shape* differs,
                    // and that is the parser's business rather than the stream's.
                    ModelWire::OpenAiChatCompat | ModelWire::CoercedTools => {
                        assemble_openai_chat_sse(raw)
                    }
                    ModelWire::AnthropicMessages => assemble_anthropic_messages_sse(raw),
                };
            }
            response
        });
        map_transport_response(self.wire, response)
    }

    fn context_window(&self) -> u64 {
        model_context_window(self.wire, &self.model)
    }
}

fn apply_xai_api_cache_header(request: &mut HttpRequest) {
    if let Some(key) = request
        .body
        .as_object_mut()
        .and_then(|body| body.remove("prompt_cache_key"))
        .and_then(|value| value.as_str().map(str::to_owned))
    {
        request.headers.push(("x-grok-conv-id".to_owned(), key));
    }
}

fn apply_xai_subscription_headers(request: &mut HttpRequest, model: &str) {
    request.headers.extend([
        ("X-XAI-Token-Auth".to_owned(), "xai-grok-cli".to_owned()),
        ("x-grok-model-override".to_owned(), model.to_owned()),
        (
            "user-agent".to_owned(),
            format!("whipplescript/{}", env!("CARGO_PKG_VERSION")),
        ),
    ]);
}

fn round_idempotency_key(
    scope: Option<&str>,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
) -> Option<String> {
    let scope = scope?.trim();
    if scope.is_empty() {
        return None;
    }
    let tools = tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            })
        })
        .collect::<Vec<_>>();
    let input = json!({ "messages": messages, "tools": tools }).to_string();
    Some(idempotency_key(&[scope, &input, "model-round"]))
}

fn set_round_idempotency_key(request: &mut HttpRequest, key: Option<String>) {
    let Some(key) = key else {
        return;
    };
    request
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case("idempotency-key"));
    request.headers.push(("Idempotency-Key".to_owned(), key));
}

#[allow(clippy::too_many_arguments)]
fn build_codex_request(
    base_url: &str,
    access_token: &str,
    model: &str,
    cache_key: Option<&str>,
    account_id: &str,
    session_id: &str,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
) -> HttpRequest {
    let mut request =
        build_openai_request(base_url, access_token, model, cache_key, messages, tools);
    request.url = format!(
        "{}/backend-api/codex/responses",
        base_url.trim_end_matches('/')
    );
    request.body["stream"] = json!(true);
    request.body["store"] = json!(false);
    request.body["parallel_tool_calls"] = json!(false);
    request.headers.extend([
        ("chatgpt-account-id".to_owned(), account_id.to_owned()),
        ("accept".to_owned(), "text/event-stream".to_owned()),
        (
            "openai-beta".to_owned(),
            "responses=experimental".to_owned(),
        ),
        ("originator".to_owned(), "gaugedesk".to_owned()),
        ("session_id".to_owned(), session_id.to_owned()),
    ]);
    request
}

/// Map a transport outcome to a model reply: parse a delivered response, or lift a
/// transport failure to the matching [`HarnessModelError`]. Shared by every
/// [`HttpModelClient`] so the timeout/transport mapping cannot drift between hosts.
fn map_transport_response(
    wire: ModelWire,
    response: Result<HttpResponse, CoerceTransportError>,
) -> Result<ModelReply, HarnessModelError> {
    match response {
        Ok(response) => parse_response(wire, response.status, &response.body),
        Err(CoerceTransportError::Timeout) => Err(HarnessModelError::Timeout),
        Err(CoerceTransportError::Transport(message)) => Err(HarnessModelError::Transport(message)),
    }
}

// -- request construction -------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_request(
    wire: ModelWire,
    base_url: &str,
    api_key: &str,
    model: &str,
    max_tokens: Option<u64>,
    cache_key: Option<&str>,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
) -> HttpRequest {
    match wire {
        ModelWire::AnthropicMessages => {
            // Anthropic caches by prefix hash via `cache_control` breakpoints, so
            // the stable-key intent (Decision 7) is carried by the breakpoint, not
            // an explicit key. The `cache_key` still rides as an `Idempotency-Key`
            // header (DR-0033) — harmless to Anthropic (an unknown request header
            // is ignored), and correct for any provider that dedupes on it.
            build_anthropic_request(
                base_url, api_key, model, max_tokens, cache_key, messages, tools,
            )
        }
        ModelWire::OpenAiResponses => {
            build_openai_request(base_url, api_key, model, cache_key, messages, tools)
        }
        ModelWire::OpenAiChatCompat => build_openai_compat_request(
            base_url, api_key, model, max_tokens, cache_key, messages, tools,
        ),
        ModelWire::CoercedTools => build_coerced_tools_request(
            base_url, api_key, model, max_tokens, cache_key, messages, tools,
        ),
    }
}

/// Agent-turn request for a generic OpenAI-compatible endpoint: the Chat Completions
/// API (`/v1/chat/completions`) — messages in the `(system|user|assistant|tool)`
/// shape, tools as `{type:"function", function:{…}}`, tool results as `role:"tool"`
/// messages. The near-universal OpenAI-wire surface, distinct from the Responses API
/// the [`build_openai_request`] path targets.
#[allow(clippy::too_many_arguments)]
fn build_openai_compat_request(
    base_url: &str,
    api_key: &str,
    model: &str,
    max_tokens: Option<u64>,
    cache_key: Option<&str>,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
) -> HttpRequest {
    let request_key = openai_request_key(cache_key);
    let msgs = openai_compat_messages(messages);
    let tool_defs: Vec<Value> = tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.input_schema,
                },
            })
        })
        .collect();
    let mut body = json!({
        "model": model,
        "messages": msgs,
    });
    // Optional on this wire, so send it only when an operator chose one.
    // Guessing was the defect: an over-large value is refused outright rather
    // than clamped, and omitting lets the provider apply its own true ceiling —
    // which is exactly the capability we were trying to name.
    if let Some(limit) = max_tokens {
        body["max_tokens"] = json!(limit);
    }
    if !tool_defs.is_empty() {
        body["tools"] = json!(tool_defs);
    }
    if let Some(key) = request_key.as_deref() {
        // Honored by OpenAI and ignored by endpoints that don't cache — harmless.
        body["prompt_cache_key"] = json!(key);
    }
    let mut headers = vec![
        ("authorization".into(), format!("Bearer {api_key}")),
        ("content-type".into(), "application/json".into()),
    ];
    if let Some(key) = request_key.as_deref() {
        headers.push(("Idempotency-Key".into(), key.to_owned()));
    }
    HttpRequest {
        // The configured endpoint is the OpenAI-compatible base URL as provider docs
        // give it (it already includes `/v1`), so append only `/chat/completions` —
        // the OpenAI SDK `base_url` convention every compat endpoint follows.
        url: format!("{}/chat/completions", base_url.trim_end_matches('/')),
        headers,
        body,
    }
}

/// Serialize the conversation into the Chat Completions `messages[]` shape: assistant
/// tool calls become `tool_calls[]` (arguments stringified) and results become one
/// `role:"tool"` message each (correlated by `tool_call_id`).
fn openai_compat_messages(messages: &[ChatMessage]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for message in messages {
        match message {
            ChatMessage::System(text) => {
                out.push(json!({ "role": "system", "content": text }));
            }
            ChatMessage::User { text, images } => {
                if images.is_empty() {
                    out.push(json!({ "role": "user", "content": text }));
                } else {
                    let mut content: Vec<Value> = vec![json!({ "type": "text", "text": text })];
                    for image in images {
                        content.push(json!({
                            "type": "image_url",
                            "image_url": {
                                "url": format!(
                                    "data:{};base64,{}",
                                    image.media_type, image.data_base64
                                ),
                            },
                        }));
                    }
                    out.push(json!({ "role": "user", "content": content }));
                }
            }
            ChatMessage::Assistant { text, tool_calls } => {
                let mut msg = Map::new();
                msg.insert("role".into(), json!("assistant"));
                // Chat Completions wants `content: null` when the turn is only tool
                // calls; a plain string otherwise.
                msg.insert(
                    "content".into(),
                    if text.is_empty() && !tool_calls.is_empty() {
                        Value::Null
                    } else {
                        json!(text)
                    },
                );
                if !tool_calls.is_empty() {
                    let calls: Vec<Value> = tool_calls
                        .iter()
                        .map(|call| {
                            json!({
                                "id": call.id,
                                "type": "function",
                                "function": {
                                    "name": call.name,
                                    "arguments": call.arguments.to_string(),
                                },
                            })
                        })
                        .collect();
                    msg.insert("tool_calls".into(), json!(calls));
                }
                out.push(Value::Object(msg));
            }
            ChatMessage::ToolResults(results) => {
                for result in results {
                    // Chat Completions `role:"tool"` has no error flag; mark a failure
                    // in-band so the model sees it (matches the Responses path).
                    let content = if result.is_error {
                        format!("error: {}", result.content)
                    } else {
                        result.content.clone()
                    };
                    out.push(json!({
                        "role": "tool",
                        "tool_call_id": result.tool_call_id,
                        "content": content,
                    }));
                }
            }
        }
    }
    out
}

/// The JSON schema one coerced step answers: free text plus zero or more tool
/// requests.
///
/// `arguments` is a JSON **string** rather than an object, which looks like a
/// wart and is not one: `strict` json-schema mode admits no free-form object,
/// and this is the same encoding native chat-completions already uses for tool
/// arguments — so the parse below is the ordinary one, not a second dialect of
/// argument decoding.
fn coerced_step_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "reply": {
                "type": "string",
                "description": "Text for the person. Empty while only calling tools.",
            },
            "tool_calls": {
                "type": "array",
                "description": "Tools to run before continuing. Empty when the reply is final.",
                "items": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "arguments": {
                            "type": "string",
                            "description": "A JSON object of arguments, encoded as a string.",
                        },
                    },
                    "required": ["name", "arguments"],
                    "additionalProperties": false,
                },
            },
        },
        "required": ["reply", "tool_calls"],
        "additionalProperties": false,
    })
}

/// The instruction that carries the tool vocabulary a native `tools[]` array
/// would have carried. Appended as a system message so it survives conversation
/// compaction the way the rest of the system prompt does.
fn coerced_tools_instruction(tools: &[ToolSpec]) -> String {
    let mut text = String::from(
        "You drive this turn by answering with a JSON object matching the required \
         schema. Put text for the person in `reply`. To use a tool, add an entry to \
         `tool_calls` whose `arguments` is a JSON object encoded as a string; the \
         results come back and you continue. Leave `tool_calls` empty when you are \
         done. The tools available to you are:\n",
    );
    for tool in tools {
        text.push_str(&format!(
            "\n- {}: {}\n  parameters: {}\n",
            tool.name, tool.description, tool.input_schema
        ));
    }
    text
}

/// Agent-turn request for an endpoint that will not, or cannot, take a native
/// tool vocabulary: the Chat Completions wire with `response_format` pinned to
/// [`coerced_step_schema`] and **no** `tools[]`.
///
/// This is the dialect that makes the model catalog swappable rather than a set
/// of models that happen to share a surface. Its cost is real and stated in
/// DR-0037: a tool request expressed as structured output is off the format the
/// model was trained on, so tool selection is measurably weaker than native
/// calling. It is the floor, not the preference.
#[allow(clippy::too_many_arguments)]
fn build_coerced_tools_request(
    base_url: &str,
    api_key: &str,
    model: &str,
    max_tokens: Option<u64>,
    cache_key: Option<&str>,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
) -> HttpRequest {
    let request_key = openai_request_key(cache_key);
    let mut msgs = coerced_tools_messages(messages);
    if !tools.is_empty() {
        msgs.push(json!({ "role": "system", "content": coerced_tools_instruction(tools) }));
    }
    let mut body = json!({
        "model": model,
        "messages": msgs,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "agent_step",
                "schema": coerced_step_schema(),
                "strict": true,
            },
        },
    });
    if let Some(limit) = max_tokens {
        body["max_tokens"] = json!(limit);
    }
    if let Some(key) = request_key.as_deref() {
        body["prompt_cache_key"] = json!(key);
    }
    let mut headers = vec![
        ("authorization".into(), format!("Bearer {api_key}")),
        ("content-type".into(), "application/json".into()),
    ];
    if let Some(key) = request_key.as_deref() {
        headers.push(("Idempotency-Key".into(), key.to_owned()));
    }
    HttpRequest {
        url: format!("{}/chat/completions", base_url.trim_end_matches('/')),
        headers,
        body,
    }
}

/// Serialize the conversation for the coerced dialect.
///
/// The difference from [`openai_compat_messages`] is forced by the wire: an
/// endpoint that was never sent a `tools[]` array has no tool-call ids to
/// correlate against, and a `role:"tool"` message referring to a `tool_call_id`
/// it never issued is rejected. So an assistant step replays as the JSON object
/// it was, and results return as an ordinary user message naming their call.
fn coerced_tools_messages(messages: &[ChatMessage]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for message in messages {
        match message {
            ChatMessage::System(text) => {
                out.push(json!({ "role": "system", "content": text }));
            }
            ChatMessage::User { text, images } => {
                if images.is_empty() {
                    out.push(json!({ "role": "user", "content": text }));
                } else {
                    let mut content: Vec<Value> = vec![json!({ "type": "text", "text": text })];
                    for image in images {
                        content.push(json!({
                            "type": "image_url",
                            "image_url": {
                                "url": format!(
                                    "data:{};base64,{}",
                                    image.media_type, image.data_base64
                                ),
                            },
                        }));
                    }
                    out.push(json!({ "role": "user", "content": content }));
                }
            }
            ChatMessage::Assistant { text, tool_calls } => {
                let calls: Vec<Value> = tool_calls
                    .iter()
                    .map(|call| {
                        json!({ "name": call.name, "arguments": call.arguments.to_string() })
                    })
                    .collect();
                let step = json!({ "reply": text, "tool_calls": calls });
                out.push(json!({ "role": "assistant", "content": step.to_string() }));
            }
            ChatMessage::ToolResults(results) => {
                for result in results {
                    let content = if result.is_error {
                        format!(
                            "Result of tool call {} (error): {}",
                            result.tool_call_id, result.content
                        )
                    } else {
                        format!(
                            "Result of tool call {}: {}",
                            result.tool_call_id, result.content
                        )
                    };
                    out.push(json!({ "role": "user", "content": content }));
                }
            }
        }
    }
    out
}

/// Parse a coerced step: the assistant message content is the schema-constrained
/// JSON document, not prose.
///
/// A model that answers with prose anyway has not called a tool, so its text is
/// taken as the reply. That keeps a weaker model's failure to honour the schema
/// a degraded answer rather than a failed turn.
fn parse_coerced_tools_response(body: &Value) -> ModelReply {
    let usage = body.get("usage").cloned().unwrap_or(Value::Null);
    let content = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(step) = serde_json::from_str::<Value>(content)
        .ok()
        .filter(Value::is_object)
    else {
        return ModelReply {
            text: content.to_owned(),
            tool_calls: Vec::new(),
            usage,
        };
    };
    let text = step
        .get("reply")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut tool_calls = Vec::new();
    for (index, call) in step
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let Some(name) = call.get("name").and_then(Value::as_str) else {
            continue;
        };
        let arguments = match call.get("arguments") {
            // The schema asks for a string, and a model that sends the object
            // directly has still said exactly what it meant.
            Some(Value::String(raw)) => serde_json::from_str::<Value>(raw).unwrap_or(Value::Null),
            Some(value) => value.clone(),
            None => Value::Null,
        };
        tool_calls.push(ToolCall {
            // No endpoint issued an id here, so the loop supplies one. It only
            // has to correlate a result with its call within this turn.
            id: format!("coerced-{index}"),
            name: name.to_owned(),
            arguments,
        });
    }
    ModelReply {
        text,
        tool_calls,
        usage,
    }
}

fn build_anthropic_request(
    base_url: &str,
    api_key: &str,
    model: &str,
    max_tokens: Option<u64>,
    cache_key: Option<&str>,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
) -> HttpRequest {
    let (system, msgs) = anthropic_messages(messages);
    let tool_defs: Vec<Value> = tools
        .iter()
        .map(|tool| {
            json!({
                "name": tool.name,
                "description": tool.description,
                "input_schema": tool.input_schema,
            })
        })
        .collect();
    let mut body = Map::new();
    body.insert("model".into(), json!(model));
    // Required by the Messages API, so an absent operator value is filled from
    // the model's own capability rather than omitted. Claude output ceilings are
    // known and few, which is why this wire can answer the question and the
    // OpenAI ones below cannot.
    body.insert(
        "max_tokens".into(),
        json!(max_tokens.unwrap_or_else(|| anthropic_output_limit(model))),
    );
    if let Some(system) = system {
        // Cache breakpoint at the end of the system prompt (Decision 7). The
        // deterministic assembler makes [tools, system] a byte-stable prefix, so
        // marking the system block `ephemeral` caches that prefix and lets it be
        // reused across the turn's model steps. Messages append after the
        // breakpoint and are not part of this cached prefix.
        body.insert(
            "system".into(),
            json!([{
                "type": "text",
                "text": system,
                "cache_control": { "type": "ephemeral" },
            }]),
        );
    }
    body.insert("messages".into(), json!(mark_conversation_cache(msgs)));
    body.insert("tools".into(), json!(tool_defs));
    let mut headers = vec![
        ("x-api-key".into(), api_key.to_owned()),
        ("anthropic-version".into(), "2023-06-01".into()),
        ("content-type".into(), "application/json".into()),
    ];
    if let Some(key) = cache_key {
        // The resume-stable per-effect run id as an `Idempotency-Key` header
        // (DR-0033): Anthropic ignores it today, but sending it costs nothing and
        // dedupes on any provider that honors it.
        headers.push(("Idempotency-Key".into(), key.to_owned()));
    }
    HttpRequest {
        url: format!("{base_url}/v1/messages"),
        headers,
        body: Value::Object(body),
    }
}

/// Put a cache breakpoint on the last content block of the last message.
///
/// The `[tools, system]` breakpoint caches the frozen prefix, which for a real
/// agent turn is the smaller half: measured on a live Theo round, 3,602 cached
/// tokens against 8,087 that were not, because everything the turn *accumulates*
/// — the conversation, tool results, files read into context — lands after that
/// breakpoint and was re-billed at full rate on every round.
///
/// Marking the newest message extends the cached span to the whole conversation
/// so far. Each round then reads the previous round's entry and writes a new one
/// covering what it appended, so the cached prefix grows with the turn instead of
/// staying frozen at the system prompt. Moving the mark is the documented
/// multi-turn shape and does not invalidate anything: the marker is a directive
/// about where to cut, not part of the content that is hashed.
///
/// Nothing is marked when the last message has no blocks — an assistant turn
/// with neither text nor tool calls — since there is no block to carry it.
///
/// One limit worth knowing: a breakpoint looks back a bounded number of blocks
/// for a prior entry, so a single round that appends a very large number of
/// blocks (many parallel tool calls and their results) can outrun the window and
/// simply write a fresh entry. That costs a write, not correctness.
fn mark_conversation_cache(mut messages: Vec<Value>) -> Vec<Value> {
    let Some(last) = messages.last_mut() else {
        return messages;
    };
    if let Some(blocks) = last.get_mut("content").and_then(Value::as_array_mut) {
        if let Some(block) = blocks.last_mut() {
            if let Some(object) = block.as_object_mut() {
                object.insert("cache_control".into(), json!({ "type": "ephemeral" }));
            }
        }
    }
    messages
}

/// Serialize the conversation into Anthropic's (system, messages[]) shape.
fn anthropic_messages(messages: &[ChatMessage]) -> (Option<String>, Vec<Value>) {
    let mut system_parts: Vec<String> = Vec::new();
    let mut out: Vec<Value> = Vec::new();
    for message in messages {
        match message {
            ChatMessage::System(text) => system_parts.push(text.clone()),
            ChatMessage::User { text, images } => {
                // Always content blocks, including the text-only case that used
                // to send a plain string. A cache breakpoint attaches to a
                // *block*, so the conversation breakpoint below can only mark a
                // message that has them — and a shape that depended on whether
                // the message happened to be last would rewrite the prefix on
                // the very next round, invalidating the cache it was added to
                // build. One stable shape costs a single miss when this ships
                // and is byte-identical forever after.
                if images.is_empty() {
                    out.push(json!({
                        "role": "user",
                        "content": [{ "type": "text", "text": text }],
                    }));
                } else {
                    let mut content: Vec<Value> = vec![json!({ "type": "text", "text": text })];
                    for image in images {
                        content.push(json!({
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": image.media_type,
                                "data": image.data_base64,
                            },
                        }));
                    }
                    out.push(json!({ "role": "user", "content": content }));
                }
            }
            ChatMessage::Assistant { text, tool_calls } => {
                let mut content: Vec<Value> = Vec::new();
                if !text.is_empty() {
                    content.push(json!({ "type": "text", "text": text }));
                }
                for call in tool_calls {
                    content.push(json!({
                        "type": "tool_use",
                        "id": call.id,
                        "name": call.name,
                        "input": call.arguments,
                    }));
                }
                out.push(json!({ "role": "assistant", "content": content }));
            }
            ChatMessage::ToolResults(results) => {
                let content: Vec<Value> = results
                    .iter()
                    .map(|result| {
                        json!({
                            "type": "tool_result",
                            "tool_use_id": result.tool_call_id,
                            "content": result.content,
                            "is_error": result.is_error,
                        })
                    })
                    .collect();
                out.push(json!({ "role": "user", "content": content }));
            }
        }
    }
    let system = if system_parts.is_empty() {
        None
    } else {
        Some(system_parts.join("\n\n"))
    };
    (system, out)
}

fn build_openai_request(
    base_url: &str,
    api_key: &str,
    model: &str,
    cache_key: Option<&str>,
    messages: &[ChatMessage],
    tools: &[ToolSpec],
) -> HttpRequest {
    let request_key = openai_request_key(cache_key);
    let input = openai_input(messages);
    let tool_defs: Vec<Value> = tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
            })
        })
        .collect();
    let mut body = json!({
        "model": model,
        "input": input,
        "tools": tool_defs,
    });
    if let Some(key) = request_key.as_deref() {
        // Stable per-turn-thread cache key (Decision 7): the run/effect id, held
        // constant across the turn's model steps so the server serves the growing
        // request prefix from cache instead of re-reading it each round.
        body["prompt_cache_key"] = json!(key);
    }
    let mut headers = vec![
        ("authorization".into(), format!("Bearer {api_key}")),
        ("content-type".into(), "application/json".into()),
    ];
    if let Some(key) = request_key.as_deref() {
        // Same run/effect id as an `Idempotency-Key` header (DR-0033): OpenAI
        // dedupes a resumed duplicate against it. This is idempotency, distinct
        // from `prompt_cache_key` above (caching) — both ride together.
        headers.push(("Idempotency-Key".into(), key.to_owned()));
    }
    HttpRequest {
        url: format!("{base_url}/v1/responses"),
        headers,
        body,
    }
}

/// Serialize the conversation into the OpenAI Responses `input[]` shape, mapping
/// assistant tool calls to `function_call` items and results to
/// `function_call_output` items (correlated by call id).
fn openai_input(messages: &[ChatMessage]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for message in messages {
        match message {
            ChatMessage::System(text) => {
                out.push(json!({ "role": "system", "content": text }));
            }
            ChatMessage::User { text, images } => {
                // Text-only stays a plain string (cache stability); images use
                // Responses content parts with data-URL `input_image` entries
                // (pi-conformance §6).
                if images.is_empty() {
                    out.push(json!({ "role": "user", "content": text }));
                } else {
                    let mut content: Vec<Value> = vec![json!({
                        "type": "input_text",
                        "text": text,
                    })];
                    for image in images {
                        content.push(json!({
                            "type": "input_image",
                            "image_url": format!(
                                "data:{};base64,{}",
                                image.media_type, image.data_base64
                            ),
                        }));
                    }
                    out.push(json!({ "role": "user", "content": content }));
                }
            }
            ChatMessage::Assistant { text, tool_calls } => {
                if !text.is_empty() {
                    out.push(json!({ "role": "assistant", "content": text }));
                }
                for call in tool_calls {
                    out.push(json!({
                        "type": "function_call",
                        "call_id": call.id,
                        "name": call.name,
                        "arguments": call.arguments.to_string(),
                    }));
                }
            }
            ChatMessage::ToolResults(results) => {
                for result in results {
                    // The Responses `function_call_output` item has no error flag
                    // (unlike Anthropic's `tool_result.is_error`), so a failed tool
                    // call is marked in-band: prefix the output text so the model
                    // sees the failure (pi-conformance §5).
                    let output = if result.is_error {
                        format!("error: {}", result.content)
                    } else {
                        result.content.clone()
                    };
                    out.push(json!({
                        "type": "function_call_output",
                        "call_id": result.tool_call_id,
                        "output": output,
                    }));
                }
            }
        }
    }
    out
}

// -- response parsing -----------------------------------------------------

fn parse_response(
    wire: ModelWire,
    status: u16,
    body: &Value,
) -> Result<ModelReply, HarnessModelError> {
    if !(200..300).contains(&status) {
        return Err(HarnessModelError::Provider(provider_error_excerpt(body)));
    }
    match wire {
        ModelWire::AnthropicMessages => Ok(parse_anthropic_response(body)),
        ModelWire::OpenAiResponses => Ok(parse_openai_response(body)),
        ModelWire::OpenAiChatCompat => Ok(parse_openai_compat_response(body)),
        ModelWire::CoercedTools => Ok(parse_coerced_tools_response(body)),
    }
}

/// Parse a Chat Completions reply: `choices[0].message` → free text (`content`) plus
/// `tool_calls[]` (function name + JSON-string arguments).
fn parse_openai_compat_response(body: &Value) -> ModelReply {
    let mut text = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    let message = body
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"));
    if let Some(message) = message {
        if let Some(content) = message.get("content").and_then(Value::as_str) {
            text.push_str(content);
        }
        if let Some(calls) = message.get("tool_calls").and_then(Value::as_array) {
            for call in calls {
                let function = call.get("function");
                tool_calls.push(ToolCall {
                    id: call
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    name: function
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    arguments: function
                        .and_then(|f| f.get("arguments"))
                        .and_then(Value::as_str)
                        .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                        .unwrap_or(Value::Null),
                });
            }
        }
    }
    ModelReply {
        text,
        tool_calls,
        usage: body.get("usage").cloned().unwrap_or(Value::Null),
    }
}

fn parse_anthropic_response(body: &Value) -> ModelReply {
    let mut text = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    if let Some(blocks) = body.get("content").and_then(Value::as_array) {
        for block in blocks {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(part) = block.get("text").and_then(Value::as_str) {
                        text.push_str(part);
                    }
                }
                Some("tool_use") => {
                    tool_calls.push(ToolCall {
                        id: block
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        name: block
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        arguments: block.get("input").cloned().unwrap_or(Value::Null),
                    });
                }
                _ => {}
            }
        }
    }
    ModelReply {
        text,
        tool_calls,
        usage: body.get("usage").cloned().unwrap_or(Value::Null),
    }
}

fn parse_openai_response(body: &Value) -> ModelReply {
    let mut text = String::new();
    let mut tool_calls: Vec<ToolCall> = Vec::new();
    if let Some(items) = body.get("output").and_then(Value::as_array) {
        for item in items {
            match item.get("type").and_then(Value::as_str) {
                Some("function_call") => {
                    tool_calls.push(ToolCall {
                        id: item
                            .get("call_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        name: item
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        arguments: item
                            .get("arguments")
                            .and_then(Value::as_str)
                            .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                            .unwrap_or(Value::Null),
                    });
                }
                Some("message") => {
                    if let Some(content) = item.get("content").and_then(Value::as_array) {
                        for part in content {
                            if let Some(t) = part.get("text").and_then(Value::as_str) {
                                text.push_str(t);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    // Convenience field some responses include.
    if text.is_empty() {
        if let Some(t) = body.get("output_text").and_then(Value::as_str) {
            text.push_str(t);
        }
    }
    ModelReply {
        text,
        tool_calls,
        usage: body.get("usage").cloned().unwrap_or(Value::Null),
    }
}

/// Collapse a Codex Responses-API SSE stream into the response-shaped value
/// consumed by the provider-neutral model loop. Hosts call this after transport;
/// credential brokers remain byte relays and do not take ownership of provider
/// response semantics.
pub fn assemble_codex_responses_sse(raw: &str) -> Value {
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
        if let Some(output) = completed.get("output") {
            assembled["output"] = output.clone();
        }
        return assembled;
    }
    completed
}

/// Collapse OpenAI-compatible chat-completion chunks into their ordinary
/// response shape. Tool argument fragments are joined by their stream index.
pub fn assemble_openai_chat_sse(raw: &str) -> Value {
    let mut text = String::new();
    let mut tools: Vec<Value> = Vec::new();
    let mut finish_reason = Value::Null;
    let mut usage = Value::Null;
    for payload in sse_payloads(raw) {
        let Ok(event) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        if !event.get("usage").unwrap_or(&Value::Null).is_null() {
            usage = event["usage"].clone();
        }
        let Some(choice) = event
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|v| v.first())
        else {
            continue;
        };
        if !choice
            .get("finish_reason")
            .unwrap_or(&Value::Null)
            .is_null()
        {
            finish_reason = choice["finish_reason"].clone();
        }
        let delta = &choice["delta"];
        if let Some(part) = delta.get("content").and_then(Value::as_str) {
            text.push_str(part);
        }
        for call in delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let index = call.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            while tools.len() <= index {
                tools
                    .push(json!({"id":"","type":"function","function":{"name":"","arguments":""}}));
            }
            if let Some(id) = call.get("id").and_then(Value::as_str) {
                tools[index]["id"] = json!(id);
            }
            if let Some(name) = call.pointer("/function/name").and_then(Value::as_str) {
                tools[index]["function"]["name"] = json!(name);
            }
            if let Some(args) = call.pointer("/function/arguments").and_then(Value::as_str) {
                // Append in place: rebuilding the whole accumulation per
                // fragment is quadratic in the argument blob's size.
                let slot = &mut tools[index]["function"]["arguments"];
                match slot {
                    Value::String(accumulated) => accumulated.push_str(args),
                    _ => *slot = json!(args),
                }
            }
        }
    }
    let mut message = json!({"role":"assistant","content":text});
    if !tools.is_empty() {
        message["tool_calls"] = Value::Array(tools);
    }
    json!({"choices":[{"message":message,"finish_reason":finish_reason}],"usage":usage})
}

/// Collapse Anthropic Messages events while deliberately ignoring thinking
/// deltas. Only answer text and tool input are user-visible model output.
pub fn assemble_anthropic_messages_sse(raw: &str) -> Value {
    let mut content: Vec<Value> = Vec::new();
    let mut usage = json!({"input_tokens":0,"output_tokens":0});
    let mut stop_reason = Value::Null;
    for payload in sse_payloads(raw) {
        let Ok(event) = serde_json::from_str::<Value>(payload) else {
            continue;
        };
        match event.get("type").and_then(Value::as_str) {
            Some("message_start") => {
                if let Some(value) = event.pointer("/message/usage") {
                    usage = value.clone();
                }
            }
            Some("content_block_start") => {
                let index = event
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(content.len() as u64) as usize;
                while content.len() <= index {
                    content.push(Value::Null);
                }
                content[index] = event.get("content_block").cloned().unwrap_or(Value::Null);
            }
            Some("content_block_delta") => {
                let index = event.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                while content.len() <= index {
                    content.push(Value::Null);
                }
                match event.pointer("/delta/type").and_then(Value::as_str) {
                    // Both arms append in place: rebuilding the whole
                    // accumulation per delta is quadratic in the block's size,
                    // and a streamed answer arrives as thousands of deltas.
                    Some("text_delta") => {
                        let delta = event
                            .pointer("/delta/text")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        // A delta can arrive before its content_block_start —
                        // a truncated or malformed stream, or a start event
                        // carrying no content_block. Seed the block as text so
                        // it is still recognised downstream: parse_anthropic_response
                        // dispatches on "type" and drops what it cannot name, so
                        // an untyped block silently discards answer text the
                        // model did send. Nothing else can it be — only a
                        // text_delta reaches here.
                        if content[index].is_null() {
                            content[index] = json!({"type":"text","text":""});
                        }
                        let slot = &mut content[index]["text"];
                        match slot {
                            Value::String(accumulated) => accumulated.push_str(delta),
                            _ => *slot = json!(delta),
                        }
                    }
                    Some("input_json_delta") => {
                        let delta = event
                            .pointer("/delta/partial_json")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let slot = &mut content[index]["input_json"];
                        match slot {
                            Value::String(accumulated) => accumulated.push_str(delta),
                            _ => *slot = json!(delta),
                        }
                    }
                    _ => {}
                }
            }
            Some("message_delta") => {
                if let Some(reason) = event.pointer("/delta/stop_reason") {
                    stop_reason = reason.clone();
                }
                if let Some(output) = event.pointer("/usage/output_tokens") {
                    usage["output_tokens"] = output.clone();
                }
            }
            _ => {}
        }
    }
    for block in &mut content {
        if block.get("type").and_then(Value::as_str) == Some("tool_use") {
            if let Some(raw_input) = block.get("input_json").and_then(Value::as_str) {
                block["input"] = serde_json::from_str(raw_input).unwrap_or(Value::Null);
            }
            block
                .as_object_mut()
                .map(|object| object.remove("input_json"));
        }
    }
    json!({"role":"assistant","content":content,"stop_reason":stop_reason,"usage":usage})
}

fn sse_payloads(raw: &str) -> impl Iterator<Item = &str> {
    raw.lines()
        .filter_map(|line| line.trim().strip_prefix("data:"))
        .map(str::trim)
        .filter(|payload| !payload.is_empty() && *payload != "[DONE]")
}

/// Pull a capped, single-line control-plane error message from a provider body.
fn provider_error_excerpt(body: &Value) -> String {
    let message = body
        .get("error")
        .and_then(|error| {
            error
                .get("message")
                .and_then(Value::as_str)
                .or_else(|| error.as_str())
        })
        .unwrap_or("provider returned a non-success status");
    let mut excerpt: String = message.chars().take(PROVIDER_ERROR_CAP).collect();
    if message.chars().count() > PROVIDER_ERROR_CAP {
        excerpt.push('…');
    }
    excerpt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness_loop::ToolResultMsg;
    use std::cell::RefCell;

    #[test]
    fn codex_sse_assembly_preserves_text_tools_and_usage() {
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"c1\",\"name\":\"read\",\"arguments\":\"{}\"}}\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n",
        );
        let body = assemble_codex_responses_sse(raw);
        assert_eq!(body["output_text"], "hello");
        assert_eq!(body["output"][0]["call_id"], "c1");
        assert_eq!(body["usage"]["input_tokens"], 3);
    }

    #[test]
    fn anthropic_sse_assembly_preserves_text_tools_and_usage() {
        let raw = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"secret\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n",
        );
        let body = assemble_anthropic_messages_sse(raw);
        assert_eq!(body["content"][0]["text"], "hello");
        assert_eq!(body["usage"]["input_tokens"], 4);
        assert_eq!(body["usage"]["output_tokens"], 2);
        assert!(!body.to_string().contains("secret"));
    }

    /// A stream can deliver a text delta with no content_block_start ahead of
    /// it. The block still has to reach the reply: parse_anthropic_response
    /// dispatches on "type", so an untyped block would drop answer text the
    /// model actually sent.
    #[test]
    fn anthropic_sse_assembly_keeps_text_whose_block_never_started() {
        let raw = concat!(
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"orph\"}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"aned\"}}\n\n",
        );
        let body = assemble_anthropic_messages_sse(raw);
        assert_eq!(body["content"][0]["type"], "text");
        assert_eq!(body["content"][0]["text"], "orphaned");
        assert_eq!(parse_anthropic_response(&body).text, "orphaned");
    }

    #[test]
    fn openai_chat_sse_assembly_joins_text() {
        let raw = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":1}}\n\n",
        );
        let body = assemble_openai_chat_sse(raw);
        assert_eq!(body["choices"][0]["message"]["content"], "hello");
        assert_eq!(body["usage"]["prompt_tokens"], 3);
    }

    /// The cached-token count is nested, and every stage between the provider
    /// and the meter had to be shown to carry it before a zero in production
    /// could be read as the provider's own answer. This pins the assembler's
    /// half: whatever `usage` the wire sends arrives intact, nesting included.
    /// `harness_loop::merge_usage_sums_nested_token_details` pins the summing
    /// across rounds, and `host_projection::usage_projection_reads_the_chat_
    /// completions_names` pins the read of exactly this shape.
    #[test]
    fn openai_chat_sse_assembly_preserves_nested_token_details() {
        let raw = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":9,\"completion_tokens\":2,",
            "\"prompt_tokens_details\":{\"cached_tokens\":7}}}\n\n",
        );
        let body = assemble_openai_chat_sse(raw);
        assert_eq!(
            body["usage"],
            json!({
                "prompt_tokens": 9,
                "completion_tokens": 2,
                "prompt_tokens_details": { "cached_tokens": 7 },
            }),
            "the assembler must not flatten away the only cached-token report"
        );
    }

    #[test]
    fn messages_client_settles_an_openai_sse_response() {
        let client = MessagesApiClient::new(
            CoerceProvider::OpenAi,
            "broker",
            "gpt-4.1",
            "https://api.openai.com",
            4096,
            None,
        );
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hello\"}\n\n",
            "data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"function_call\",\"call_id\":\"c1\",\"name\":\"read\",\"arguments\":\"{}\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n",
        );
        let reply = client
            .parse_response(Ok(HttpResponse {
                status: 200,
                body: Value::String(raw.to_owned()),
            }))
            .unwrap();

        assert_eq!(reply.text, "hello");
        assert_eq!(reply.tool_calls[0].id, "c1");
        assert_eq!(reply.usage["output_tokens"], 2);
    }

    #[test]
    fn context_window_is_derived_from_the_model_not_configured() {
        // Current Claude frontier models expose their full 1M window by default.
        assert_eq!(
            model_context_window(ModelWire::AnthropicMessages, "claude-opus-4-8"),
            1_000_000
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiChatCompat, "anthropic/claude-opus-5"),
            1_000_000
        );
        assert_eq!(
            model_output_limit(ModelWire::OpenAiChatCompat, "anthropic/claude-opus-5"),
            Some(128_000)
        );
        // OpenAI families map to their real windows.
        assert_eq!(
            model_context_window(ModelWire::OpenAiResponses, "gpt-4o"),
            128_000
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiResponses, "gpt-4.1"),
            1_000_000
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiResponses, "o3"),
            200_000
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiResponses, "o3-mini"),
            200_000
        );
        // An unrecognized OpenAI model takes the conservative family default.
        assert_eq!(
            model_context_window(ModelWire::OpenAiResponses, "some-future-model"),
            128_000
        );
        // A generic OpenAI-compatible endpoint reuses the OpenAI heuristic.
        assert_eq!(
            model_context_window(ModelWire::OpenAiChatCompat, "llama-3.3-70b"),
            128_000
        );
        // xAI: fast variants carry 2M, grok-4/grok-code 256k, and anything
        // unrecognized takes grok-3's conservative 131k. `grok-4-fast` must be
        // tested before the `grok-4` prefix claims it.
        assert_eq!(
            model_context_window(ModelWire::OpenAiChatCompat, "grok-4-fast"),
            2_000_000
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiChatCompat, "grok-4"),
            256_000
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiChatCompat, "grok-code-fast-1"),
            256_000
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiChatCompat, "grok-3"),
            131_072
        );
        assert_eq!(
            model_context_window(ModelWire::OpenAiChatCompat, "some-future-grok"),
            131_072
        );
        // The output limit stays provider-derived: only Anthropic names one.
        assert_eq!(
            model_output_limit(ModelWire::OpenAiChatCompat, "grok-4"),
            None
        );
    }

    /// The live 400: `openai/gpt-5-mini` satisfied a `starts_with('o')` test for
    /// o-series reasoning models, so it was read as a 200k-window model and the
    /// turn asked for 200,000 completion tokens against a 128,000 ceiling. Every
    /// round of that deployment was refused. The routing prefix is not part of
    /// the model's identity.
    #[test]
    fn a_routing_prefix_is_not_read_as_an_o_series_model() {
        for wire in [ModelWire::OpenAiResponses, ModelWire::OpenAiChatCompat] {
            assert_eq!(
                model_context_window(wire, "openai/gpt-5-mini"),
                128_000,
                "the `openai/` prefix must not claim the o-series window"
            );
            assert_eq!(
                model_output_limit(wire, "openai/gpt-5-mini"),
                None,
                "an OpenAI ceiling we do not know is not one we may invent"
            );
            // The prefix must not hide a capability either: a genuinely
            // prefixed o-series model keeps its own window.
            assert_eq!(model_context_window(wire, "openai/o3"), 200_000);
            // And a bare name is unaffected.
            assert_eq!(model_context_window(wire, "gpt-5-mini"), 128_000);
        }
    }

    /// The two wires answer the output-limit question differently, and the
    /// difference is the whole fix: Anthropic requires the field so an absent
    /// operator value is filled from a capability we actually know, while the
    /// OpenAI wire treats it as optional so an unknown ceiling is simply not
    /// named. Sending a guess there is refused, not clamped.
    #[test]
    fn an_unknown_output_ceiling_is_omitted_rather_than_guessed() {
        let compat = build_request(
            ModelWire::OpenAiChatCompat,
            "https://gateway.example/compat",
            "key",
            "openai/gpt-5-mini",
            None,
            None,
            &convo(),
            &[],
        );
        assert!(
            compat.body.get("max_tokens").is_none(),
            "an invented ceiling is refused outright by the provider"
        );

        // An operator who chose a budget still gets it.
        let chosen = build_request(
            ModelWire::OpenAiChatCompat,
            "https://gateway.example/compat",
            "key",
            "openai/gpt-5-mini",
            Some(4_096),
            None,
            &convo(),
            &[],
        );
        assert_eq!(chosen.body["max_tokens"], json!(4_096));

        // Anthropic must always name one, so the capability fills the gap.
        let anthropic = build_request(
            ModelWire::AnthropicMessages,
            "https://api.anthropic.com",
            "key",
            "claude-opus-5",
            None,
            None,
            &convo(),
            &[],
        );
        assert_eq!(anthropic.body["max_tokens"], json!(128_000));
    }

    #[test]
    fn the_o_series_test_matches_a_series_not_a_leading_letter() {
        assert!(is_openai_reasoning_model("o1"));
        assert!(is_openai_reasoning_model("o3-mini"));
        assert!(is_openai_reasoning_model("o4-mini-high"));
        // Any model that merely begins with the letter is not the series.
        assert!(!is_openai_reasoning_model("openai/gpt-5-mini"));
        assert!(!is_openai_reasoning_model("omni-moderation-latest"));
        assert!(!is_openai_reasoning_model("o3x-experimental"));
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

    fn convo() -> Vec<ChatMessage> {
        vec![
            ChatMessage::System("be helpful".into()),
            ChatMessage::user_text("read the file"),
            ChatMessage::Assistant {
                text: String::new(),
                tool_calls: vec![ToolCall {
                    id: "call_1".into(),
                    name: "read".into(),
                    arguments: json!({ "path": "a.txt" }),
                }],
            },
            ChatMessage::ToolResults(vec![ToolResultMsg {
                tool_call_id: "call_1".into(),
                tool_name: "read".into(),
                content: "hello".into(),
                is_error: false,
            }]),
        ]
    }

    fn tool_specs() -> Vec<ToolSpec> {
        vec![ToolSpec {
            name: "read".into(),
            description: "read a file".into(),
            input_schema: json!({ "type": "object" }),
        }]
    }

    /// The dialect a provider identity implies, and the round trip through its
    /// declared name. A name that does not round-trip is a name a host could
    /// write into a policy envelope and a runtime would then refuse to read.
    #[test]
    fn every_wire_round_trips_through_its_declared_name() {
        for wire in [
            ModelWire::AnthropicMessages,
            ModelWire::OpenAiResponses,
            ModelWire::OpenAiChatCompat,
            ModelWire::CoercedTools,
        ] {
            assert_eq!(ModelWire::parse(wire.as_str()), Some(wire));
        }
        assert_eq!(ModelWire::parse("openai-realtime"), None);
        assert_eq!(
            ModelWire::of_provider(CoerceProvider::OpenAi),
            ModelWire::OpenAiResponses
        );
        assert_eq!(
            ModelWire::of_provider(CoerceProvider::Anthropic),
            ModelWire::AnthropicMessages
        );
        // xAI and a generic compat endpoint are different provider identities
        // speaking one dialect — which is the whole reason the two concepts had
        // to stop being the same enum.
        assert_eq!(
            ModelWire::of_provider(CoerceProvider::Xai),
            ModelWire::OpenAiChatCompat
        );
        assert_eq!(
            ModelWire::of_provider(CoerceProvider::OpenAiCompat),
            ModelWire::OpenAiChatCompat
        );
        assert!(ModelWire::OpenAiChatCompat.uses_native_tools());
        assert!(!ModelWire::CoercedTools.uses_native_tools());
    }

    /// The live failure this dialect exists for, stated as the request that
    /// caused it. On 2026-08-19 a `gpt-5.6-terra` panel turn went out on chat
    /// completions carrying five function tools, and OpenAI refused it: that
    /// family carries tools only on the Responses API unless reasoning is
    /// switched off. The coerced dialect sends **no** `tools[]` at all, so the
    /// refusal has nothing to refuse.
    #[test]
    fn the_coerced_dialect_sends_a_schema_and_never_a_tool_array() {
        let req = build_coerced_tools_request(
            "https://gateway.ai.cloudflare.com/v1/acct/gw/compat",
            "gateway-key",
            "openai/gpt-5.6-terra",
            None,
            None,
            &convo(),
            &tool_specs(),
        );
        assert_eq!(
            req.url,
            "https://gateway.ai.cloudflare.com/v1/acct/gw/compat/chat/completions"
        );
        assert!(
            req.body.get("tools").is_none(),
            "the coerced dialect must not ask for a native tool vocabulary"
        );
        assert_eq!(req.body["response_format"]["type"], json!("json_schema"));
        assert_eq!(
            req.body["response_format"]["json_schema"]["strict"],
            json!(true)
        );
        // The tool vocabulary still reaches the model — as instruction rather
        // than as a wire feature.
        let text = req.body["messages"].to_string();
        assert!(
            text.contains("read a file"),
            "tool descriptions must survive"
        );
        // A prior assistant step replays as its JSON document, and a result
        // returns as an ordinary user message: there is no tool-call id for an
        // endpoint that was never given a tool array to correlate against.
        let roles: Vec<&str> = req.body["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|message| message["role"].as_str().unwrap())
            .collect();
        assert!(
            !roles.contains(&"tool"),
            "a role:tool message would name a tool_call_id no endpoint issued"
        );
    }

    /// A coerced step parses back into exactly the reply the loop would have
    /// read from native tool calls, so everything downstream is unchanged.
    #[test]
    fn a_coerced_step_parses_into_ordinary_tool_calls() {
        let step = json!({
            "reply": "Reading it now.",
            "tool_calls": [{ "name": "read", "arguments": "{\"path\":\"a.txt\"}" }],
        });
        let body = json!({
            "choices": [{ "message": { "content": step.to_string() } }],
            "usage": { "prompt_tokens": 11 },
        });
        let reply = parse_coerced_tools_response(&body);
        assert_eq!(reply.text, "Reading it now.");
        assert_eq!(reply.tool_calls.len(), 1);
        assert_eq!(reply.tool_calls[0].name, "read");
        assert_eq!(reply.tool_calls[0].arguments, json!({ "path": "a.txt" }));
        // The loop correlates results by id, so one is supplied where the
        // endpoint issued none.
        assert!(!reply.tool_calls[0].id.is_empty());
        assert_eq!(reply.usage, json!({ "prompt_tokens": 11 }));

        // A model that ignores the schema and answers in prose has still
        // answered. Degrading to a plain reply keeps a weaker model usable
        // rather than failing the turn outright.
        let prose = json!({ "choices": [{ "message": { "content": "just talking" } }] });
        let reply = parse_coerced_tools_response(&prose);
        assert_eq!(reply.text, "just talking");
        assert!(reply.tool_calls.is_empty());
    }

    /// Each dialect must reach its own builder. A wire that silently borrowed
    /// another's request shape is the defect this whole seam exists to prevent.
    #[test]
    fn each_wire_builds_its_own_surface() {
        let build = |wire| {
            build_request(
                wire,
                "https://api.example.invalid/v1",
                "key",
                "some-model",
                Some(1024),
                None,
                &convo(),
                &tool_specs(),
            )
        };
        assert!(build(ModelWire::AnthropicMessages)
            .url
            .ends_with("/v1/messages"));
        assert!(build(ModelWire::OpenAiResponses)
            .url
            .ends_with("/v1/responses"));
        let compat = build(ModelWire::OpenAiChatCompat);
        assert!(compat.url.ends_with("/chat/completions"));
        assert!(compat.body.get("tools").is_some());
        let coerced = build(ModelWire::CoercedTools);
        assert!(coerced.url.ends_with("/chat/completions"));
        assert!(coerced.body.get("tools").is_none());
    }

    #[test]
    fn anthropic_request_shape_serializes_conversation_and_tools() {
        let req = build_anthropic_request(
            "https://api.anthropic.com",
            "sk-ant-api-key",
            "claude-opus-4-8",
            Some(4096),
            None,
            &convo(),
            &tool_specs(),
        );
        assert_eq!(req.url, "https://api.anthropic.com/v1/messages");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == "sk-ant-api-key"));
        // System is a single text block carrying the end-of-prompt cache
        // breakpoint (Decision 7); the text the model sees is unchanged.
        assert_eq!(req.body["system"][0]["type"], json!("text"));
        assert_eq!(req.body["system"][0]["text"], json!("be helpful"));
        let msgs = req.body["messages"].as_array().expect("messages");
        // user, assistant(tool_use), user(tool_result)
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[1]["role"], json!("assistant"));
        assert_eq!(msgs[1]["content"][0]["type"], json!("tool_use"));
        assert_eq!(msgs[1]["content"][0]["id"], json!("call_1"));
        assert_eq!(msgs[2]["content"][0]["type"], json!("tool_result"));
        assert_eq!(msgs[2]["content"][0]["tool_use_id"], json!("call_1"));
        assert_eq!(req.body["tools"][0]["name"], json!("read"));
        // No forced tool_choice: the model chooses when to stop.
        assert!(req.body.get("tool_choice").is_none());
    }

    #[test]
    fn anthropic_parse_extracts_text_and_tool_calls() {
        let body = json!({
            "content": [
                { "type": "text", "text": "let me look" },
                { "type": "tool_use", "id": "tc1", "name": "read", "input": { "path": "x" } }
            ],
            "usage": { "output_tokens": 9 }
        });
        let reply = parse_anthropic_response(&body);
        assert_eq!(reply.text, "let me look");
        assert_eq!(reply.tool_calls.len(), 1);
        assert_eq!(reply.tool_calls[0].name, "read");
        assert_eq!(reply.tool_calls[0].arguments, json!({ "path": "x" }));
        assert!(!reply.is_final());
    }

    #[test]
    fn openai_request_maps_tool_calls_and_results() {
        let req = build_openai_request(
            "https://api.openai.com",
            "sk-key",
            "gpt-5.5",
            None,
            &convo(),
            &tool_specs(),
        );
        assert_eq!(req.url, "https://api.openai.com/v1/responses");
        let input = req.body["input"].as_array().expect("input");
        // system, user, function_call, function_call_output
        assert!(input
            .iter()
            .any(|i| i["type"] == json!("function_call") && i["call_id"] == json!("call_1")));
        assert!(
            input
                .iter()
                .any(|i| i["type"] == json!("function_call_output")
                    && i["call_id"] == json!("call_1"))
        );
        assert_eq!(req.body["tools"][0]["type"], json!("function"));
    }

    #[test]
    fn openai_compat_request_uses_chat_completions_with_tools_and_roles() {
        let req = build_openai_compat_request(
            "https://api.together.xyz/v1",
            "sk-key",
            "llama-3.3-70b",
            Some(8192),
            None,
            &convo(),
            &tool_specs(),
        );
        // Chat Completions endpoint (not the Responses API).
        assert_eq!(req.url, "https://api.together.xyz/v1/chat/completions");
        assert!(req
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer sk-key"));
        assert_eq!(req.body["max_tokens"], json!(8192));
        let msgs = req.body["messages"].as_array().expect("messages");
        // system, user, assistant(tool_calls), tool(result)
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[0]["role"], json!("system"));
        assert_eq!(msgs[1]["role"], json!("user"));
        // Assistant with only tool calls: content is null, tool_calls carry
        // stringified arguments in the chat-completions shape.
        assert_eq!(msgs[2]["role"], json!("assistant"));
        assert_eq!(msgs[2]["content"], Value::Null);
        assert_eq!(msgs[2]["tool_calls"][0]["type"], json!("function"));
        assert_eq!(msgs[2]["tool_calls"][0]["id"], json!("call_1"));
        assert_eq!(msgs[2]["tool_calls"][0]["function"]["name"], json!("read"));
        assert_eq!(
            msgs[2]["tool_calls"][0]["function"]["arguments"],
            json!("{\"path\":\"a.txt\"}")
        );
        // Tool result becomes a role:"tool" message correlated by id.
        assert_eq!(msgs[3]["role"], json!("tool"));
        assert_eq!(msgs[3]["tool_call_id"], json!("call_1"));
        assert_eq!(msgs[3]["content"], json!("hello"));
        // Tools are the chat-completions {type:function, function:{…}} shape.
        assert_eq!(req.body["tools"][0]["type"], json!("function"));
        assert_eq!(req.body["tools"][0]["function"]["name"], json!("read"));
    }

    /// A hosted Chat Completions round must still report token counts. This wire
    /// is the only one that drops usage when it is streamed, and a host that
    /// settles on exact usage has nothing to settle with — it releases the
    /// reservation and discards an answer the provider already produced.
    #[test]
    fn hosted_compat_stream_asks_for_usage_and_reports_it() {
        let compat = MessagesApiClient::new(
            CoerceProvider::OpenAiCompat,
            "sk-key",
            "gpt-test",
            "https://gateway.ai.cloudflare.com/v1/account/gw/compat",
            4096,
            None,
        );
        let request = compat.build_request(&convo(), &tool_specs());
        assert_eq!(request.body["stream"], json!(true));
        assert_eq!(
            request.body["stream_options"],
            json!({ "include_usage": true }),
            "a streamed chat-completions round must ask for its usage"
        );

        // What the flag buys: a terminal chunk carrying only the counts.
        let raw = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":3}}\n\n",
            "data: [DONE]\n\n",
        );
        let reply = compat
            .parse_response(Ok(HttpResponse {
                status: 200,
                body: json!(raw),
            }))
            .expect("reply");
        assert_eq!(reply.text, "hi");
        assert_eq!(reply.usage["prompt_tokens"], json!(11));
        assert_eq!(reply.usage["completion_tokens"], json!(3));

        // xAI speaks the same Chat Completions stream, so it must ask too.
        let xai =
            MessagesApiClient::new_xai("xai-key", "grok-4", "https://api.x.ai/v1", 4096, None);
        assert_eq!(
            xai.build_request(&convo(), &tool_specs()).body["stream_options"],
            json!({ "include_usage": true }),
        );

        // The Responses and Messages streams end with usage unasked, and neither
        // accepts this Chat Completions field.
        for provider in [CoerceProvider::OpenAi, CoerceProvider::Anthropic] {
            let client =
                MessagesApiClient::new(provider, "key", "model", "https://provider", 4096, None);
            assert!(
                client
                    .build_request(&convo(), &tool_specs())
                    .body
                    .get("stream_options")
                    .is_none(),
                "{provider:?} reports usage without being asked"
            );
        }
    }

    #[test]
    fn xai_backends_keep_payer_wire_cache_and_tool_authority_distinct() {
        let api = MessagesApiClient::new_xai(
            "xai-key",
            "grok-4.5",
            "https://api.x.ai/v1",
            4096,
            Some("turn-7".to_owned()),
        )
        .build_request(&convo(), &tool_specs());
        assert_eq!(api.url, "https://api.x.ai/v1/chat/completions");
        assert!(api.body.get("prompt_cache_key").is_none());
        assert!(api
            .headers
            .iter()
            .any(|(name, value)| name == "x-grok-conv-id" && value == "turn-7"));

        let subscription = MessagesApiClient::new_xai_subscription(
            "oauth-access",
            "grok-4.5",
            "https://cli-chat-proxy.grok.com",
            4096,
            Some("turn-7".to_owned()),
        )
        .build_request(&convo(), &tool_specs());
        assert_eq!(
            subscription.url,
            "https://cli-chat-proxy.grok.com/v1/responses"
        );
        assert_eq!(subscription.body["prompt_cache_key"], json!("turn-7"));
        assert!(subscription.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("X-XAI-Token-Auth") && value == "xai-grok-cli"
        }));
        assert!(subscription
            .headers
            .iter()
            .any(|(name, value)| { name == "x-grok-model-override" && value == "grok-4.5" }));
        // Only the brokered function declaration is serialized. Provider-hosted
        // search/code/MCP tools require a separately governed capability and are
        // absent by default.
        assert_eq!(subscription.body["tools"][0]["type"], json!("function"));
        assert!(subscription.body["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .all(|tool| tool["type"] == "function"));
    }

    #[test]
    fn openai_compat_response_parses_content_and_tool_calls() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "let me look",
                    "tool_calls": [{
                        "id": "call_9",
                        "type": "function",
                        "function": { "name": "read", "arguments": "{\"path\":\"x\"}" }
                    }]
                }
            }],
            "usage": { "completion_tokens": 7 }
        });
        let reply = parse_openai_compat_response(&body);
        assert_eq!(reply.text, "let me look");
        assert_eq!(reply.tool_calls.len(), 1);
        assert_eq!(reply.tool_calls[0].id, "call_9");
        assert_eq!(reply.tool_calls[0].name, "read");
        assert_eq!(reply.tool_calls[0].arguments, json!({ "path": "x" }));
        assert!(!reply.is_final());
    }

    #[test]
    fn openai_compat_tool_result_error_is_marked_in_band() {
        let messages = vec![ChatMessage::ToolResults(vec![ToolResultMsg {
            tool_call_id: "call_err".into(),
            tool_name: "read".into(),
            content: "read of `x` failed".into(),
            is_error: true,
        }])];
        let msgs = openai_compat_messages(&messages);
        assert_eq!(msgs[0]["role"], json!("tool"));
        assert_eq!(msgs[0]["content"], json!("error: read of `x` failed"));
    }

    #[test]
    fn openai_tool_result_error_is_marked_in_the_output_text() {
        // The Responses wire has no is_error field, so the failure marker rides
        // in-band; a successful result stays verbatim (pi-conformance §5).
        let messages = vec![ChatMessage::ToolResults(vec![
            ToolResultMsg {
                tool_call_id: "call_ok".into(),
                tool_name: "read".into(),
                content: "hello".into(),
                is_error: false,
            },
            ToolResultMsg {
                tool_call_id: "call_err".into(),
                tool_name: "read".into(),
                content: "read of `x` failed".into(),
                is_error: true,
            },
        ])];
        let input = openai_input(&messages);
        assert_eq!(input[0]["output"], json!("hello"));
        assert_eq!(input[1]["output"], json!("error: read of `x` failed"));
    }

    /// The conversation breakpoint is worthless if a message's bytes depend on
    /// whether it is currently last: the next round would rewrite the prefix and
    /// every read would miss, silently and while still paying the write. This is
    /// the regression that shape change exists to prevent, so assert the
    /// serialization of a message is identical in both positions.
    #[test]
    fn a_message_serializes_the_same_whether_or_not_it_is_last() {
        let first = ChatMessage::user_text("what changed?");
        let when_last = anthropic_messages(std::slice::from_ref(&first)).1;
        let when_not_last = anthropic_messages(&[
            first,
            ChatMessage::Assistant {
                text: "a lot".into(),
                tool_calls: Vec::new(),
            },
        ])
        .1;
        assert_eq!(
            when_last[0], when_not_last[0],
            "the cached prefix must not be rewritten as the turn grows"
        );
        // And the breakpoint itself rides on the *last* message, so it is not
        // part of what the earlier message contributes to the prefix.
        let marked = mark_conversation_cache(when_not_last);
        assert!(marked[0]["content"][0].get("cache_control").is_none());
        assert_eq!(
            marked[1]["content"][0]["cache_control"],
            json!({ "type": "ephemeral" })
        );
    }

    #[test]
    fn the_conversation_breakpoint_marks_the_newest_turn() {
        let messages = vec![
            ChatMessage::user_text("first"),
            ChatMessage::ToolResults(vec![crate::harness_loop::ToolResultMsg {
                tool_call_id: "call-1".into(),
                tool_name: "read".into(),
                content: "done".into(),
                is_error: false,
            }]),
        ];
        let (_, msgs) = anthropic_messages(&messages);
        let marked = mark_conversation_cache(msgs);
        assert_eq!(
            marked[1]["content"][0]["cache_control"],
            json!({ "type": "ephemeral" }),
            "a tool-result round extends the cached span"
        );
    }

    /// An assistant turn can carry neither text nor tool calls. There is no
    /// block to hold a breakpoint, and inventing one would change the prefix.
    #[test]
    fn an_empty_last_message_takes_no_breakpoint() {
        let messages = vec![ChatMessage::Assistant {
            text: String::new(),
            tool_calls: Vec::new(),
        }];
        let (_, msgs) = anthropic_messages(&messages);
        let marked = mark_conversation_cache(msgs);
        assert_eq!(marked[0]["content"], json!([]));
    }

    #[test]
    fn anthropic_user_images_emit_base64_source_blocks() {
        // pi-conformance §6: an image-bearing user message becomes content
        // blocks, and a text-only one now does too — see
        // `a_message_serializes_the_same_whether_or_not_it_is_last`.
        let messages = vec![
            ChatMessage::user_text("plain"),
            ChatMessage::User {
                text: "what is this?".into(),
                images: vec![crate::harness_loop::ImageBlock {
                    media_type: "image/png".into(),
                    data_base64: "aGVsbG8=".into(),
                }],
            },
        ];
        let (_, msgs) = anthropic_messages(&messages);
        assert_eq!(
            msgs[0]["content"],
            json!([{ "type": "text", "text": "plain" }])
        );
        assert_eq!(
            msgs[1]["content"][0],
            json!({ "type": "text", "text": "what is this?" })
        );
        assert_eq!(
            msgs[1]["content"][1],
            json!({
                "type": "image",
                "source": {
                    "type": "base64",
                    "media_type": "image/png",
                    "data": "aGVsbG8=",
                },
            })
        );
    }

    #[test]
    fn openai_user_images_emit_input_image_parts() {
        // pi-conformance §6: Responses content parts with a data-URL
        // `input_image`; a text-only user message stays a plain string.
        let messages = vec![
            ChatMessage::user_text("plain"),
            ChatMessage::User {
                text: "what is this?".into(),
                images: vec![crate::harness_loop::ImageBlock {
                    media_type: "image/png".into(),
                    data_base64: "aGVsbG8=".into(),
                }],
            },
        ];
        let input = openai_input(&messages);
        assert_eq!(input[0]["content"], json!("plain"));
        assert_eq!(
            input[1]["content"][0],
            json!({ "type": "input_text", "text": "what is this?" })
        );
        assert_eq!(
            input[1]["content"][1],
            json!({
                "type": "input_image",
                "image_url": "data:image/png;base64,aGVsbG8=",
            })
        );
    }

    #[test]
    fn cache_breakpoints_and_stable_key_follow_decision_7() {
        // Anthropic: the system prompt is sent as a content block carrying a
        // `cache_control` breakpoint at its end (the stable [tools, system] prefix).
        let anthropic = build_anthropic_request(
            "https://api.anthropic.com",
            "k",
            "m",
            Some(4096),
            Some("turn-42"),
            &convo(),
            &tool_specs(),
        );
        let system = anthropic.body["system"]
            .as_array()
            .expect("system rendered as cache-controllable blocks");
        assert_eq!(
            system.last().expect("a system block")["cache_control"]["type"],
            json!("ephemeral")
        );
        // The per-effect key rides as an `Idempotency-Key` header even on
        // Anthropic (DR-0033): sent, harmless, deduped only where honored.
        assert!(anthropic
            .headers
            .iter()
            .any(|(k, v)| k == "Idempotency-Key" && v == "turn-42"));
        // No cache_key => no idempotency header (byte-identical to before).
        let anthropic_nokey = build_anthropic_request(
            "https://api.anthropic.com",
            "k",
            "m",
            Some(4096),
            None,
            &convo(),
            &tool_specs(),
        );
        assert!(!anthropic_nokey
            .headers
            .iter()
            .any(|(k, _)| k == "Idempotency-Key"));

        // OpenAI: a stable per-turn-thread key rides as `prompt_cache_key` when
        // supplied, and is absent otherwise (no key => no field, not null).
        let with_key = build_openai_request(
            "https://api.openai.com",
            "k",
            "m",
            Some("turn-42"),
            &convo(),
            &tool_specs(),
        );
        assert_eq!(with_key.body["prompt_cache_key"], json!("turn-42"));
        // The same key is also the `Idempotency-Key` header (dedup, not caching);
        // both are present together.
        assert!(with_key
            .headers
            .iter()
            .any(|(k, v)| k == "Idempotency-Key" && v == "turn-42"));
        let without_key = build_openai_request(
            "https://api.openai.com",
            "k",
            "m",
            None,
            &convo(),
            &tool_specs(),
        );
        assert!(without_key.body.get("prompt_cache_key").is_none());
        assert!(!without_key
            .headers
            .iter()
            .any(|(k, _)| k == "Idempotency-Key"));

        let oversized =
            "public:sess_fc7e73f97ff14436be95709aca8246a9:edge-production-pre-cutover-1";
        assert!(oversized.len() > OPENAI_PROMPT_CACHE_KEY_MAX_BYTES);
        let bounded = build_openai_request(
            "https://api.openai.com",
            "k",
            "m",
            Some(oversized),
            &convo(),
            &tool_specs(),
        );
        let bounded_key = bounded.body["prompt_cache_key"]
            .as_str()
            .expect("bounded prompt cache key");
        assert_eq!(bounded_key.len(), OPENAI_PROMPT_CACHE_KEY_MAX_BYTES);
        assert_eq!(bounded_key, sha256_hex(oversized.as_bytes()));
        assert!(bounded
            .headers
            .iter()
            .any(|(k, v)| k == "Idempotency-Key" && v == bounded_key));
    }

    #[test]
    fn openai_parse_extracts_function_call() {
        let body = json!({
            "output": [
                { "type": "function_call", "call_id": "c9", "name": "ls", "arguments": "{\"path\":\".\"}" }
            ]
        });
        let reply = parse_openai_response(&body);
        assert_eq!(reply.tool_calls.len(), 1);
        assert_eq!(reply.tool_calls[0].id, "c9");
        assert_eq!(reply.tool_calls[0].arguments, json!({ "path": "." }));
    }

    #[test]
    fn non_success_status_is_a_provider_error() {
        let transport = FakeTransport {
            response: Ok(HttpResponse {
                status: 429,
                body: json!({ "error": { "message": "rate limit exceeded" } }),
            }),
            seen: RefCell::new(None),
        };
        let client = RealHarnessModelClient::new(
            &transport,
            CoerceProvider::Anthropic,
            "k",
            "m",
            "https://api.anthropic.com",
            4096,
            None,
        );
        let err = client
            .next(&convo(), &tool_specs())
            .expect_err("provider error");
        match err {
            HarnessModelError::Provider(message) => assert!(message.contains("rate limit")),
            other => panic!("expected provider error, got {other:?}"),
        }
    }

    #[test]
    fn timeout_maps_to_timeout() {
        let transport = FakeTransport {
            response: Err(CoerceTransportError::Timeout),
            seen: RefCell::new(None),
        };
        let client = RealHarnessModelClient::new(
            &transport,
            CoerceProvider::OpenAi,
            "k",
            "m",
            "https://api.openai.com",
            4096,
            None,
        );
        assert_eq!(
            client.next(&convo(), &tool_specs()),
            Err(HarnessModelError::Timeout)
        );
        // sanity: a request was actually built and sent
        assert!(transport.seen.borrow().is_some());
    }

    #[test]
    fn messages_api_client_builds_and_parses_without_a_transport() {
        // The durable-object path: no transport, the host does the fetch. The
        // config-only client must produce the same request and parse a reply.
        let client = MessagesApiClient::new(
            CoerceProvider::Anthropic,
            "sk-ant-key",
            "claude-opus-4-8",
            "https://api.anthropic.com",
            4096,
            None,
        );
        let request = client.build_request(&convo(), &tool_specs());
        assert_eq!(request.url, "https://api.anthropic.com/v1/messages");
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "x-api-key" && v == "sk-ant-key"));

        let reply = client
            .parse_response(Ok(HttpResponse {
                status: 200,
                body: json!({ "content": [ { "type": "text", "text": "final" } ] }),
            }))
            .expect("reply");
        assert_eq!(reply.text, "final");
        assert!(reply.is_final());

        assert_eq!(
            client.parse_response(Err(CoerceTransportError::Timeout)),
            Err(HarnessModelError::Timeout)
        );

        let openai = MessagesApiClient::new(
            CoerceProvider::OpenAi,
            "openai-key",
            "gpt-test",
            "https://api.openai.com",
            4096,
            None,
        );
        let request = openai.build_request(&convo(), &tool_specs());
        assert_eq!(request.body["stream"], json!(true));
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "accept" && value == "text/event-stream"));

        let scoped = MessagesApiClient::new(
            CoerceProvider::OpenAi,
            "whipplescript-model-broker",
            "gpt-test",
            "https://api.openai.com",
            4096,
            Some("effect-42".to_owned()),
        );
        let first = scoped.build_request(&convo(), &tool_specs());
        let replay = scoped.build_request(&convo(), &tool_specs());
        let mut next_messages = convo();
        next_messages.push(ChatMessage::user_text("next round"));
        let next = scoped.build_request(&next_messages, &tool_specs());
        let key = |request: &HttpRequest| {
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("idempotency-key"))
                .map(|(_, value)| value.clone())
                .expect("idempotency key")
        };
        assert_eq!(key(&first), key(&replay), "a replay keeps the round key");
        assert_ne!(
            key(&first),
            key(&next),
            "a distinct model round gets a distinct key"
        );
        assert_eq!(
            first.body["prompt_cache_key"],
            json!("effect-42"),
            "the turn cache scope remains stable across rounds"
        );
    }

    #[test]
    fn final_reply_has_no_tool_calls() {
        let transport = FakeTransport {
            response: Ok(HttpResponse {
                status: 200,
                body: json!({ "content": [ { "type": "text", "text": "done" } ] }),
            }),
            seen: RefCell::new(None),
        };
        let client = RealHarnessModelClient::new(
            &transport,
            CoerceProvider::Anthropic,
            "k",
            "m",
            "https://api.anthropic.com",
            4096,
            None,
        );
        let reply = client.next(&convo(), &tool_specs()).expect("reply");
        assert_eq!(reply.text, "done");
        assert!(reply.is_final());
    }

    /// The owned harness resolves ChatGPT-plan OAuth tokens, and those are not
    /// public-API credentials: presented to `api.openai.com` the provider
    /// refuses them for want of `api.responses.write`. The routing existed for
    /// coerce's client and this one had no way to reach it, so a subscription
    /// credential could be resolved and then spent on a request that could only
    /// fail. Both directions are pinned: a codex-backed client reaches the
    /// codex wire, and an ordinary one is untouched.
    #[test]
    fn owned_harness_client_reaches_the_codex_wire_when_host_material_is_present() {
        let transport = FakeTransport {
            response: Ok(HttpResponse {
                status: 200,
                body: Value::Null,
            }),
            seen: RefCell::new(None),
        };
        let client = RealHarnessModelClient::new_codex(
            &transport,
            "oauth-access",
            "account-1",
            "session-1",
            "gpt-5.5",
            "https://chatgpt.com",
            8_192,
            Some("effect-1".to_owned()),
        );
        let request = client.build_request(&convo(), &tool_specs());
        assert_eq!(
            request.url,
            "https://chatgpt.com/backend-api/codex/responses"
        );
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "chatgpt-account-id" && value == "account-1"));

        // and the codex wire answers as a stream even on this synchronous
        // transport, so the body is assembled before the shared mapping.
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"output\":[],",
            "\"usage\":{\"input_tokens\":3,\"output_tokens\":2}}}\n\n",
        );
        let reply = client
            .parse_response(Ok(HttpResponse {
                status: 200,
                body: Value::String(raw.to_owned()),
            }))
            .unwrap();
        assert_eq!(reply.text, "hi");
        assert_eq!(reply.usage["output_tokens"], 2);
    }

    #[test]
    fn owned_harness_client_without_host_material_keeps_the_public_api_wire() {
        let transport = FakeTransport {
            response: Ok(HttpResponse {
                status: 200,
                body: Value::Null,
            }),
            seen: RefCell::new(None),
        };
        let client = RealHarnessModelClient::new(
            &transport,
            CoerceProvider::OpenAi,
            "sk-key",
            "gpt-5.5",
            "https://api.openai.com",
            4096,
            None,
        );
        let request = client.build_request(&convo(), &tool_specs());
        assert!(!request.url.contains("backend-api/codex"));
        assert!(!request
            .headers
            .iter()
            .any(|(name, _)| name == "chatgpt-account-id"));
    }

    #[test]
    fn codex_client_uses_host_material_only_for_the_codex_wire() {
        let client = MessagesApiClient::new_codex(
            "oauth-access",
            "account-1",
            "session-1",
            "gpt-5.5",
            "https://chatgpt.com",
            8_192,
            Some("command-1".to_owned()),
        );
        let request = client.build_request(&convo(), &tool_specs());
        assert_eq!(
            request.url,
            "https://chatgpt.com/backend-api/codex/responses"
        );
        assert_eq!(request.body["stream"], true);
        assert_eq!(request.body["store"], false);
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "chatgpt-account-id" && value == "account-1"));
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "session_id" && value == "session-1"));
        assert!(request
            .headers
            .iter()
            .any(|(name, value)| name == "accept" && value == "text/event-stream"));
    }
}
