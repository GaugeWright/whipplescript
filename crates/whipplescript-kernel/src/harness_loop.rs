//! Owned brokered agent harness: the pure tool-use loop driver.
//!
//! Slice 1 of DR-0024 (see spec/owned-harness-loop-contract.md). This module is
//! the network-free, store-free *spine* of the brokered turn: it drives a model
//! through a tool-use loop where the KERNEL executes each requested tool (I1,
//! brokering) rather than delegating the whole turn to a provider harness.
//!
//! Two side effects are factored behind traits so this stays unit-testable:
//!   - [`HarnessModelClient`] makes one model call (the CLI supplies a real
//!     `ureq`-backed provider client; tests inject a fake).
//!   - [`ToolExecutor`] runs one tool request against the workspace (the CLI
//!     supplies the file-store-bounded executor; tests inject a fake).
//!
//! The driver returns a [`BrokeredTurnOutcome`] whose `observations` are the
//! in-turn stream events. Per the DR-0024 boundary corollary they are
//! evidence-grade only: the kernel runner records them as evidence and never
//! derives a rule-matchable fact from them (I2, leaf-ness). Only the single
//! terminal becomes a fact (layer 3).

use crate::harness::{ProviderFailure, ProviderRunResult, ProviderRunStatus};
use serde_json::{json, Value};

use crate::sansio::{
    run_to_completion, HostDriver, HttpRequest, HttpResponse, IoRequest, IoResult, Outcome,
    StepMachine, TransportError,
};
use crate::world_state::{
    project_remaining_model_rounds, project_world, render_world_projection, WorldProjection,
    WorldSnapshot,
};

/// A model-facing tool: its name, a one-line description, and the JSON Schema for
/// its arguments. Built from the file-tool set in slice 1.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// One tool invocation the model requested.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ToolCall {
    /// Provider-assigned call id, used to correlate the result back.
    pub id: String,
    pub name: String,
    pub arguments: Value,
}

/// Terminal status of a single tool execution. Anti-idempotence is intended: a
/// failed tool result is informative to the model (it retries), not a turn
/// failure (DR-0024 boundary corollary).
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ToolStatus {
    Ok,
    Error,
}

/// The result of executing one tool, fed back to the model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolOutcome {
    pub status: ToolStatus,
    /// The content returned to the model (already bounded/truncated by the
    /// executor; full output is recoverable by event reference in later slices).
    pub content: String,
}

/// The single tool side effect: run one requested tool against the workspace.
/// The real impl lives in the CLI (file-store bounded); tests inject a fake.
pub trait ToolExecutor {
    fn execute(&self, call: &ToolCall) -> ToolOutcome;

    /// Mid-turn delivery (DR-0052 Decision 7): information the host wants
    /// the running agent to see before its NEXT model call — raises
    /// addressed to this session, contention notices. Inbound only, so
    /// invariant I2 (interiors emit no facts) is untouched; the default
    /// delivers nothing (delegated harnesses, tests, the stepped DO
    /// machine — where the turn boundary remains the atom).
    fn poll_notices(&self) -> Vec<String> {
        Vec::new()
    }
}

/// One inline image attached to a user message (pi-conformance §6, v1 scope:
/// effect-input images only — the read-tool image path is deferred).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ImageBlock {
    /// The image MIME type, e.g. `image/png`.
    pub media_type: String,
    /// The raw image bytes, base64-encoded.
    pub data_base64: String,
}

/// Original typed user-media item before provider-capability normalization.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MediaInput {
    pub artifact_ref: String,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_base64: Option<String>,
    #[serde(default)]
    pub metadata: std::collections::BTreeMap<String, String>,
}

/// One message in the model conversation the driver maintains.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum ChatMessage {
    System(String),
    /// A user turn: text plus any inline images (pi-conformance §6).
    User {
        text: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        images: Vec<ImageBlock>,
    },
    /// An assistant turn: free text plus any tool calls it requested.
    Assistant {
        text: String,
        tool_calls: Vec<ToolCall>,
    },
    /// The results of the assistant's tool calls, correlated by call id.
    ToolResults(Vec<ToolResultMsg>),
}

impl ChatMessage {
    /// A text-only user message (the overwhelmingly common case).
    pub fn user_text(text: impl Into<String>) -> Self {
        ChatMessage::User {
            text: text.into(),
            images: Vec::new(),
        }
    }
}

/// A tool result as it appears back in the conversation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ToolResultMsg {
    pub tool_call_id: String,
    pub tool_name: String,
    pub content: String,
    pub is_error: bool,
}

/// One model reply: any text, any tool calls, and usage metadata. A reply with no
/// tool calls is final and ends the loop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelReply {
    pub text: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Value,
}

impl ModelReply {
    pub fn is_final(&self) -> bool {
        self.tool_calls.is_empty()
    }
}

/// Why a model call did not produce a reply.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HarnessModelError {
    Timeout,
    /// A control-plane / provider error (usage-limit, auth, model-not-found). The
    /// message is operational metadata and may cross the redaction boundary
    /// (capped + scrubbed by the caller), per DR-0024.
    Provider(String),
    /// Any other transport-level failure (connect/TLS/decode), redacted message.
    Transport(String),
}

/// The single model side effect: one model call given the conversation so far and
/// the available tools. The real impl lives in the CLI; tests inject a fake.
pub trait HarnessModelClient {
    fn next(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolSpec],
    ) -> Result<ModelReply, HarnessModelError>;
}

/// The HTTP half of an agent model client, split so a single model call is a
/// sans-IO step (DR-0033 Decisions 1–2): `build_request` is the prepare step and
/// `parse_response` the finish step, with the blocking POST performed by the host
/// in between. A `next` for an HTTP client is exactly `build_request` →
/// `NeedsIo(Http)` → `parse_response` driven by [`ModelCallMachine`]; the whole
/// tool-use turn lifts the same stepping to every model call
/// ([`BrokeredTurnMachine`]) so the durable-object host can suspend across each
/// provider `fetch`.
///
/// Non-HTTP model clients (fixtures, scripted tests, and the native-only stdio
/// sidecars — codex/claude, DR-0033 Decision 7) implement [`HarnessModelClient`]
/// directly and are never put on the step machine.
pub trait HttpModelClient {
    fn build_request(&self, messages: &[ChatMessage], tools: &[ToolSpec]) -> HttpRequest;

    fn parse_response(
        &self,
        response: Result<HttpResponse, TransportError>,
    ) -> Result<ModelReply, HarnessModelError>;

    /// The model's context window in tokens, for the conversation-compaction
    /// trigger (context-assembly Phase 4, Decision 7). The default suits the common
    /// 200k-token frontier models; a client with a known window (or a fixture that
    /// wants to force compaction cheaply) overrides it.
    fn context_window(&self) -> u64 {
        DEFAULT_CONTEXT_WINDOW
    }
}

/// One model call as a sans-IO [`StepMachine`]: prepare the provider request,
/// yield it as `NeedsIo(Http)`, then settle on the parsed reply. Any
/// [`HttpModelClient`] can be driven natively to completion via
/// [`run_to_completion`], which is how [`HttpModelClient`] satisfies
/// [`HarnessModelClient::next`] with identical behavior to a direct
/// build → post → parse.
pub struct ModelCallMachine<'a, M: HttpModelClient + ?Sized> {
    client: &'a M,
    request: HttpRequest,
}

impl<'a, M: HttpModelClient + ?Sized> ModelCallMachine<'a, M> {
    pub fn new(client: &'a M, messages: &[ChatMessage], tools: &[ToolSpec]) -> Self {
        Self {
            client,
            request: client.build_request(messages, tools),
        }
    }
}

impl<M: HttpModelClient + ?Sized> StepMachine for ModelCallMachine<'_, M> {
    type Output = Result<ModelReply, HarnessModelError>;

    fn step(&mut self, incoming: Option<IoResult>) -> Outcome<Self::Output> {
        match incoming {
            None => Outcome::NeedsIo(IoRequest::Http(self.request.clone())),
            Some(IoResult::Http(response)) => Outcome::Settle(self.client.parse_response(response)),
        }
    }
}

/// An in-turn stream event. Evidence-grade only (I2): the kernel runner records
/// each as evidence; none derives a rule-matchable fact.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum LoopObservation {
    /// A model call was made at this 0-based step.
    ModelRequest { step: usize },
    /// The model requested a tool.
    ToolRequested { call_id: String, name: String },
    /// The kernel executed the tool and got this status.
    ToolResult {
        call_id: String,
        name: String,
        status: ToolStatus,
    },
    ToolOutputTruncated {
        call_id: String,
        tool_name: String,
        policy: String,
        output_class: String,
        retention_direction: String,
        result_status: ToolStatus,
        experiment_label: String,
        original_bytes: usize,
        retained_bytes: usize,
        recall_id: Option<String>,
    },
    RecallRequested {
        call_id: String,
        content_id: String,
        offset: Option<u64>,
        limit: Option<u64>,
        experiment_label: String,
    },
    /// A conversation compaction was applied at this epoch (Phase 4 Layer B): the
    /// summary was recorded and the transcript folded to a fresh stable prefix. The
    /// kernel records this as a `context.compaction` evidence artifact (Decision 8).
    Compacted {
        epoch: u32,
        /// How many messages were folded into the summary.
        folded_messages: usize,
        /// Byte length of the recorded handoff summary (0 for a deterministic,
        /// no-model rewrite).
        summary_bytes: usize,
    },
    /// A durable user command was folded into the live turn at a model
    /// boundary. The command id makes replay/apply-once behavior auditable.
    UserCommandApplied {
        command_id: String,
        kind: TurnCommandKind,
    },
    /// A full model-visible world or an idempotent update was appended before a
    /// model round. The hash binds evidence to the exact canonical state.
    WorldProjected {
        epoch: u64,
        projection: String,
        content_hash: String,
    },
    /// One original media item was either admitted as a provider derivative or
    /// represented explicitly as unavailable. No item disappears silently.
    MediaNormalized {
        artifact_ref: String,
        media_type: String,
        normalization: String,
        derivative_hash: Option<String>,
    },
}

/// Runtime-owned user commands that can join an already-running agent turn.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnCommandKind {
    /// Redirect before the next main model call.
    Steer,
    /// Continue only after the model would otherwise finish.
    FollowUp,
    /// Request the selected existing compactor at the next coherent model
    /// boundary. Carries no user prose and is apply-once by command id.
    Compact,
}

/// One durable command supplied by the host. Command ids are stable across
/// retries and DO eviction; the machine snapshots which ids it has applied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingTurnCommand {
    pub command_id: String,
    pub text: String,
    pub images: Vec<ImageBlock>,
}

/// Host projection over its durable command queue. Reading does not consume a
/// row: the host marks ids applied only after the updated machine snapshot is
/// durable, closing the crash window between injection and acknowledgement.
pub trait TurnCommandSource {
    fn pending(&mut self, kind: TurnCommandKind) -> Result<Vec<PendingTurnCommand>, String>;
}

/// Host collector for mutable model-visible world state. It reads only already
/// admitted runtime state; returning a snapshot cannot grant authority.
pub trait WorldStateSource {
    fn current(&mut self, model_step: usize) -> Result<WorldSnapshot, String>;
}

/// Terminal status of a brokered turn (layer 3). Maps to the existing
/// agent.turn.* lifecycle terminal kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnStatus {
    Completed,
    Failed,
    TimedOut,
    /// A durable cancellation request was observed between model rounds
    /// (pi-conformance §3: cooperative abort; the partial transcript persists).
    Cancelled,
}

/// The outcome of a brokered turn: exactly one terminal, plus the in-turn stream
/// observations the runner records as evidence.
#[derive(Clone, Debug)]
pub struct BrokeredTurnOutcome {
    pub status: TurnStatus,
    /// Final model text on success; the error reason on failure/timeout.
    pub summary: String,
    /// Number of model calls made.
    pub steps: usize,
    pub observations: Vec<LoopObservation>,
    pub usage: Value,
    /// The last MAIN reply's `input_tokens` — the provider's own count of the
    /// whole prompt it just processed, the same reading the compaction trigger
    /// consumes. A point-in-time gauge, never a sum: `usage` answers "what did
    /// this turn cost", this answers "how full is the context window". 0 when
    /// no main reply reported it (an error before the first reply, or a settle
    /// straight after a compaction reset).
    pub last_input_tokens: u64,
}

/// Project a finished [`BrokeredTurnOutcome`] onto the [`ProviderRunResult`] the
/// kernel settles (via `settle_provider_run_result`). The durable-object agent
/// dispatch drives a [`BrokeredTurnMachine`] over `fetch`, then converts its outcome
/// here — the same terminal shape the native provider adapters produce.
pub fn provider_result_from_brokered_turn(outcome: &BrokeredTurnOutcome) -> ProviderRunResult {
    let (status, failure) = match outcome.status {
        TurnStatus::Completed => (ProviderRunStatus::Completed, None),
        TurnStatus::Failed | TurnStatus::TimedOut | TurnStatus::Cancelled => {
            let error_kind = if matches!(outcome.status, TurnStatus::Cancelled) {
                "cancelled"
            } else if matches!(outcome.status, TurnStatus::TimedOut) {
                "timeout"
            } else {
                "provider_error"
            };
            (
                match outcome.status {
                    TurnStatus::TimedOut => ProviderRunStatus::TimedOut,
                    // Was collapsed into Failed, which settled the effect
                    // `failed` on the DO placement — firing `fails` arms and
                    // stripping a deliberate watchdog cancel of its
                    // auto-fail exemption.
                    TurnStatus::Cancelled => ProviderRunStatus::Cancelled,
                    _ => ProviderRunStatus::Failed,
                },
                Some(ProviderFailure {
                    provider: "brokered".to_owned(),
                    adapter: "brokered-turn".to_owned(),
                    phase: "provider.agent.turn".to_owned(),
                    error_kind: error_kind.to_owned(),
                    message: outcome.summary.clone(),
                    recoverable: matches!(outcome.status, TurnStatus::TimedOut),
                    retry_after: None,
                    workspace_id: None,
                    provider_session_id: None,
                    provider_thread_id: None,
                    missing_config_keys: Vec::new(),
                    raw_json: None,
                }),
            )
        }
    };
    ProviderRunResult {
        status,
        summary: outcome.summary.clone(),
        stdout: outcome.summary.clone(),
        stderr: String::new(),
        transcript: serde_json::to_string(&outcome.observations)
            .unwrap_or_else(|_| "[]".to_owned()),
        exit_code: matches!(outcome.status, TurnStatus::Completed).then_some(0),
        usage_json: usage_with_context(&outcome.usage, outcome.last_input_tokens).to_string(),
        artifacts: Vec::new(),
        failure,
    }
}

/// The initial prompt for a brokered turn (slice 1 minimal projection: a system
/// prompt + the turn input as the first user message).
#[derive(Clone, Debug)]
pub struct BrokeredTurnInput {
    pub system: String,
    pub user: String,
    pub tools: Vec<ToolSpec>,
    /// Hard safety bound on model calls for slice 1. The governing budget
    /// (counter) is slice 2; this just prevents an unbounded loop.
    pub max_steps: usize,
    /// Resume-from-projection (slice 6): when non-empty, the loop continues from
    /// this persisted transcript instead of starting fresh from system+user. A
    /// dangling final tool-call (crash between request and result) is tolerated.
    pub resume_from: Vec<ChatMessage>,
    /// Inline images attached to the turn's user message (pi-conformance §6).
    /// Empty for text-only turns (the default); providers that lack vision error
    /// informatively in v1 (no omission-note degradation yet).
    pub user_images: Vec<ImageBlock>,
    /// Original typed media. The kernel normalizes these against the currently
    /// supported provider input boundary; `user_images` remains the resolved
    /// compatibility path for existing hosts and persisted commands.
    pub user_media: Vec<MediaInput>,
    /// Canonical initial world collected from the effective turn envelope.
    /// `None` is retained for delegated/test callers that do not own context.
    pub world: Option<WorldSnapshot>,
    /// Per-bundle provenance for the assembled system prompt (context-assembly
    /// Phase 1, Decision 5). The turn runner records one `context.bundle` evidence
    /// row per entry, before the turn, on a fresh start only (not on resume, so
    /// recovery does not duplicate). Empty when the host does not assemble context
    /// (e.g. the current DO agent stub).
    pub context_bundles: Vec<crate::context_assembly::ContributionProvenance>,
    /// Turn-scoped skills pinned by `tell … with skills [...]` (context-assembly
    /// Phase 7). Recorded once as `skills.pinned` provenance before the turn (fresh
    /// start only), like `context_bundles`. Provenance only — the discover-all
    /// catalogue is unchanged. Empty for turns with no pin.
    pub pinned_skills: Vec<String>,
}

fn execute_offered_tool<E: ToolExecutor + ?Sized>(
    executor: &E,
    offered: &[ToolSpec],
    call: &ToolCall,
) -> ToolOutcome {
    if !offered.iter().any(|tool| tool.name == call.name) {
        return ToolOutcome {
            status: ToolStatus::Error,
            content: format!("tool `{}` was not offered for this model round", call.name),
        };
    }
    executor.execute(call)
}

/// Drive a brokered tool-use loop to a single terminal.
///
/// The loop is the model's control flow (I2/I3): each iteration makes one model
/// call, and for every requested tool the KERNEL executes it via `executor` and
/// feeds the result back (I1, brokering). The conversation grows by an assistant
/// message then a tool-results message each round. The loop ends when the model
/// replies with no tool calls (Completed), a model call errors (Failed), or the
/// step bound is hit (TimedOut).
///
/// This is the imperative, no-compaction *reference* loop: production drives the
/// sans-IO [`BrokeredTurnMachine`] (which carries the [`Compactor`]) on both native
/// and the durable object. The loop is retained as the equivalence oracle the
/// stepped machine is proven byte-identical against (with a [`NoopCompactor`]).
pub fn run_brokered_loop<C, E>(
    client: &C,
    executor: &E,
    input: &BrokeredTurnInput,
    checkpoint: &mut dyn FnMut(&[ChatMessage]),
) -> BrokeredTurnOutcome
where
    C: HarnessModelClient + ?Sized,
    E: ToolExecutor + ?Sized,
{
    let mut messages = if input.resume_from.is_empty() {
        vec![
            ChatMessage::System(input.system.clone()),
            ChatMessage::User {
                text: input.user.clone(),
                images: input.user_images.clone(),
            },
        ]
    } else {
        // Resume-from-projection: continue from the persisted transcript, dropping
        // a dangling final tool-call (a crash between request and result) so the
        // model re-decides rather than the loop deadlocking on an unanswered call.
        sanitize_resume_messages(input.resume_from.clone())
    };
    // Persist the (possibly resumed) starting context so a crash before the first
    // model call still leaves a transcript to resume from.
    checkpoint(&messages);
    let mut observations: Vec<LoopObservation> = Vec::new();
    let mut usage = Value::Null;
    // Mirrors the stepped machine's field byte-for-byte: refreshed on every
    // main reply, so the settled value is the LAST reply's prompt size.
    let mut last_input_tokens = 0_u64;

    let mut provider_retries: u32 = 0;
    let mut step = 0;
    while step < input.max_steps {
        // Mid-turn delivery (DR-0052 Decision 7): notices arrive as
        // ordinary inbound context — one model call of latency instead
        // of a whole turn. Appended before the request and checkpointed,
        // so a resumed turn keeps what it was told.
        let notices = executor.poll_notices();
        if !notices.is_empty() {
            for notice in notices {
                messages.push(ChatMessage::User {
                    text: notice,
                    images: Vec::new(),
                });
            }
            checkpoint(&messages);
        }
        observations.push(LoopObservation::ModelRequest { step });
        let reply = match client.next(&messages, &input.tools) {
            Ok(reply) => reply,
            // Bounded auto-retry on transient provider errors (pi-conformance
            // §2), mirroring the stepped machine byte-for-byte.
            Err(error)
                if is_retryable_provider_error(&error)
                    && provider_retries < MAX_PROVIDER_RETRIES =>
            {
                provider_retries += 1;
                continue;
            }
            Err(error) => {
                return BrokeredTurnOutcome {
                    status: match error {
                        HarnessModelError::Timeout => TurnStatus::TimedOut,
                        _ => TurnStatus::Failed,
                    },
                    summary: model_error_summary(&error),
                    steps: step + 1,
                    observations,
                    usage,
                    last_input_tokens,
                };
            }
        };
        usage = merge_usage(usage, reply.usage.clone());
        last_input_tokens = input_tokens_of(&reply.usage);

        if reply.is_final() {
            // Mirror the stepped machine: the final assistant reply joins the
            // persisted transcript (pi-conformance §4).
            messages.push(ChatMessage::Assistant {
                text: reply.text.clone(),
                tool_calls: Vec::new(),
            });
            checkpoint(&messages);
            return BrokeredTurnOutcome {
                status: TurnStatus::Completed,
                summary: reply.text,
                steps: step + 1,
                observations,
                usage,
                last_input_tokens,
            };
        }

        // The model requested tools: record the assistant turn, then broker each
        // tool through the kernel executor and feed the results back.
        messages.push(ChatMessage::Assistant {
            text: reply.text.clone(),
            tool_calls: reply.tool_calls.clone(),
        });
        let mut results = Vec::with_capacity(reply.tool_calls.len());
        for call in &reply.tool_calls {
            observations.push(LoopObservation::ToolRequested {
                call_id: call.id.clone(),
                name: call.name.clone(),
            });
            if let Some(observation) = recall_request_observation(call) {
                observations.push(observation);
            }
            let outcome = execute_offered_tool(executor, &input.tools, call);
            observations.push(LoopObservation::ToolResult {
                call_id: call.id.clone(),
                name: call.name.clone(),
                status: outcome.status,
            });
            if let Some((original_bytes, recall_id)) = truncation_metadata(&outcome.content) {
                observations.push(LoopObservation::ToolOutputTruncated {
                    call_id: call.id.clone(),
                    tool_name: call.name.clone(),
                    policy: "class_aware_v1".to_owned(),
                    output_class: "text/plain".to_owned(),
                    retention_direction: tool_output_retention(&call.name).to_owned(),
                    result_status: outcome.status,
                    experiment_label: "pi_class_aware_v1".to_owned(),
                    original_bytes,
                    retained_bytes: outcome.content.len(),
                    recall_id,
                });
            }
            results.push(ToolResultMsg {
                tool_call_id: call.id.clone(),
                tool_name: call.name.clone(),
                content: outcome.content,
                is_error: matches!(outcome.status, ToolStatus::Error),
            });
        }
        messages.push(ChatMessage::ToolResults(results));
        // Persist the transcript after the step so a crash mid-turn leaves a
        // projection to resume from (DR-0024 resume-from-projection).
        checkpoint(&messages);
        step += 1;
    }

    BrokeredTurnOutcome {
        status: TurnStatus::TimedOut,
        summary: format!("brokered turn exceeded {} model steps", input.max_steps),
        steps: input.max_steps,
        observations,
        usage,
        last_input_tokens,
    }
}

/// The brokered tool-use loop as a sans-IO [`StepMachine`] (DR-0033 Decisions
/// 1–2): the exact control flow of [`run_brokered_loop`], but each model call is
/// surfaced as a `NeedsIo(Http)` the host performs, so a durable-object isolate
/// can suspend across every provider `fetch`. Tool calls remain nested effects
/// brokered synchronously by the [`ToolExecutor`] (a tool that itself needs I/O
/// becomes its own nested step machine in a later phase). Driven natively by
/// [`run_brokered_turn_http`]; proven equivalent to [`run_brokered_loop`] in tests.
/// The persistable mid-turn state of a [`BrokeredTurnMachine`] — everything that
/// varies as the turn progresses. The borrowed model/executor/input/checkpoint are
/// re-supplied on [`restore`](BrokeredTurnMachine::restore); this is only the state.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BrokeredTurnSnapshot {
    pub messages: Vec<ChatMessage>,
    pub observations: Vec<LoopObservation>,
    pub usage: Value,
    pub step: usize,
    pub started: bool,
    /// Which round the next Http response answers (Phase 4 Layer B). `Main` unless
    /// a summarization round is in flight.
    #[serde(default = "awaiting_main")]
    pub awaiting: Awaiting,
    /// The last MAIN reply's `input_tokens` — the compaction trigger signal. Reset
    /// to 0 after each compaction (hysteresis).
    #[serde(default)]
    pub last_input_tokens: u64,
    /// How many compactions have been applied this turn (apply-once bookkeeping /
    /// evidence key).
    #[serde(default)]
    pub compaction_epoch: u32,
    /// The summarization compaction awaiting its model reply; `Some` iff
    /// `awaiting == Summary`. Survives eviction so resume folds the same summary in.
    #[serde(default)]
    pub pending_compaction: Option<SummarizationRequest>,
    /// How many times this turn has front-trimmed after a provider context-window
    /// error (Lb-5 overflow fallback), bounded by `MAX_OVERFLOW_TRIMS`.
    #[serde(default)]
    pub overflow_trims: u32,
    /// User commands already folded into `messages`. This is the apply-once
    /// guard when a host crashes after saving the snapshot but before marking
    /// its queue rows applied.
    #[serde(default)]
    pub applied_command_ids: std::collections::BTreeSet<String>,
    /// Last state durably projected to the model, for replay-safe diffing after
    /// eviction. Old snapshots deserialize as unknown and force a full refresh.
    #[serde(default)]
    pub visible_world: Option<WorldSnapshot>,
}

/// `serde(default)` seed for [`BrokeredTurnSnapshot::awaiting`] on pre-Phase-4
/// snapshots (they were mid-main by construction).
fn awaiting_main() -> Awaiting {
    Awaiting::Main
}

pub struct BrokeredTurnMachine<'a, M, E>
where
    M: HttpModelClient + ?Sized,
    E: ToolExecutor + ?Sized,
{
    model: &'a M,
    executor: &'a E,
    input: &'a BrokeredTurnInput,
    checkpoint: &'a mut dyn FnMut(&[ChatMessage]),
    compactor: &'a dyn Compactor,
    messages: Vec<ChatMessage>,
    observations: Vec<LoopObservation>,
    usage: Value,
    step: usize,
    started: bool,
    awaiting: Awaiting,
    last_input_tokens: u64,
    compaction_epoch: u32,
    pending_compaction: Option<SummarizationRequest>,
    overflow_trims: u32,
    applied_command_ids: std::collections::BTreeSet<String>,
    /// Transient provider-error retries used so far this turn (bounded by
    /// [`MAX_PROVIDER_RETRIES`]).
    provider_retries: u32,
    /// Cooperative cancellation probe, consulted before each main model call
    /// (pi-conformance §3). `None` = not cancellable (tests, hosts without a
    /// cancellation surface). Probed between rounds only, so an in-flight tool
    /// settles before the check — the settle-before-release discipline.
    cancel_check: Option<&'a dyn Fn() -> bool>,
    /// Whether the host's transport released the just-fulfilled provider
    /// stream early because a cancellation request was observed mid-stream
    /// (spec/agent-harness.md "Cancellation"). Consulted once per parsed
    /// reply: a released round keeps the text that fully arrived — durably,
    /// as that round's assistant message — dispatches no tool batch, and
    /// settles `Cancelled`. `None`/`false` leaves every path exactly as
    /// before, including final-terminal-wins for a naturally completed
    /// stream that a request only raced.
    stream_released: Option<&'a dyn Fn() -> bool>,
    /// Durable steering/follow-up source. Hosts without interactive commands
    /// leave this absent and retain the ordinary one-shot lifecycle.
    command_source: Option<&'a mut dyn TurnCommandSource>,
    world_source: Option<&'a mut dyn WorldStateSource>,
    visible_world: Option<WorldSnapshot>,
}

impl<'a, M, E> BrokeredTurnMachine<'a, M, E>
where
    M: HttpModelClient + ?Sized,
    E: ToolExecutor + ?Sized,
{
    pub fn new(
        model: &'a M,
        executor: &'a E,
        input: &'a BrokeredTurnInput,
        checkpoint: &'a mut dyn FnMut(&[ChatMessage]),
        compactor: &'a dyn Compactor,
    ) -> Self {
        Self {
            model,
            executor,
            input,
            checkpoint,
            compactor,
            messages: Vec::new(),
            observations: Vec::new(),
            usage: Value::Null,
            step: 0,
            started: false,
            awaiting: Awaiting::Main,
            last_input_tokens: 0,
            compaction_epoch: 0,
            pending_compaction: None,
            overflow_trims: 0,
            applied_command_ids: std::collections::BTreeSet::new(),
            provider_retries: 0,
            cancel_check: None,
            stream_released: None,
            command_source: None,
            world_source: None,
            visible_world: None,
        }
    }

    /// Reconstruct a mid-turn machine from a persisted [`BrokeredTurnSnapshot`],
    /// re-supplying the borrowed model/executor/input/checkpoint. This is what makes
    /// a multi-round agent turn eviction-safe on the durable object (DR-0033
    /// Decision 3): each `run_effect` re-entry restores the exact machine state
    /// (conversation + observations + usage + step) from the store and continues,
    /// so an eviction between two provider `fetch`es loses nothing. Native runs the
    /// turn to completion in one pass and never needs it.
    pub fn restore(
        model: &'a M,
        executor: &'a E,
        input: &'a BrokeredTurnInput,
        checkpoint: &'a mut dyn FnMut(&[ChatMessage]),
        compactor: &'a dyn Compactor,
        snapshot: BrokeredTurnSnapshot,
    ) -> Self {
        Self {
            model,
            executor,
            input,
            checkpoint,
            compactor,
            messages: snapshot.messages,
            observations: snapshot.observations,
            usage: snapshot.usage,
            step: snapshot.step,
            started: snapshot.started,
            awaiting: snapshot.awaiting,
            last_input_tokens: snapshot.last_input_tokens,
            compaction_epoch: snapshot.compaction_epoch,
            pending_compaction: snapshot.pending_compaction,
            overflow_trims: snapshot.overflow_trims,
            applied_command_ids: snapshot.applied_command_ids,
            provider_retries: 0,
            cancel_check: None,
            stream_released: None,
            command_source: None,
            world_source: None,
            visible_world: snapshot.visible_world,
        }
    }

    /// Arm the cooperative cancellation probe (pi-conformance §3). The runner
    /// passes a closure over the durable `effect_cancellation_requests`
    /// surface; the machine consults it before each main model call.
    pub fn with_cancel_check(mut self, probe: &'a dyn Fn() -> bool) -> Self {
        self.cancel_check = Some(probe);
        self
    }

    /// Arm the stream-release probe: `true` says the transport released the
    /// round's provider stream early on an observed cancellation request, so
    /// the parsed reply is a truncation — never a natural terminal.
    pub fn with_stream_released(mut self, probe: &'a dyn Fn() -> bool) -> Self {
        self.stream_released = Some(probe);
        self
    }

    pub fn with_command_source(mut self, source: &'a mut dyn TurnCommandSource) -> Self {
        self.command_source = Some(source);
        self
    }

    pub fn with_world_source(mut self, source: &'a mut dyn WorldStateSource) -> Self {
        self.world_source = Some(source);
        self
    }

    /// Capture the machine's full mid-turn state so a host can persist it between
    /// provider rounds and later [`restore`](Self::restore) it byte-for-byte.
    pub fn snapshot(&self) -> BrokeredTurnSnapshot {
        BrokeredTurnSnapshot {
            messages: self.messages.clone(),
            observations: self.observations.clone(),
            usage: self.usage.clone(),
            step: self.step,
            started: self.started,
            awaiting: self.awaiting,
            last_input_tokens: self.last_input_tokens,
            compaction_epoch: self.compaction_epoch,
            pending_compaction: self.pending_compaction.clone(),
            overflow_trims: self.overflow_trims,
            applied_command_ids: self.applied_command_ids.clone(),
            visible_world: self.visible_world.clone(),
        }
    }

    fn project_current_world(&mut self) -> Result<bool, String> {
        let current = if let Some(source) = self.world_source.as_mut() {
            Some(source.current(self.step)?)
        } else if self.visible_world.is_none() {
            self.input.world.clone()
        } else {
            self.visible_world.as_ref().and_then(|visible| {
                project_remaining_model_rounds(visible, self.input.max_steps, self.step)
            })
        };
        let Some(current) = current else {
            return Ok(false);
        };
        let projection = project_world(self.visible_world.as_ref(), &current);
        let Some(rendered) = render_world_projection(&projection) else {
            return Ok(false);
        };
        let projection_kind = match projection {
            WorldProjection::Full(_) => "full",
            WorldProjection::Update(_) => "update",
            WorldProjection::Unchanged => unreachable!("renderer returned content"),
        };
        self.messages.push(ChatMessage::System(rendered));
        self.observations.push(LoopObservation::WorldProjected {
            epoch: current.world_epoch,
            projection: projection_kind.to_owned(),
            content_hash: current.content_hash(),
        });
        self.visible_world = Some(current);
        (self.checkpoint)(&self.messages);
        Ok(true)
    }

    fn inject_commands(
        &mut self,
        kind: TurnCommandKind,
        limit: Option<usize>,
    ) -> Result<bool, String> {
        let Some(source) = self.command_source.as_mut() else {
            return Ok(false);
        };
        let mut injected = false;
        for command in source
            .pending(kind)?
            .into_iter()
            .take(limit.unwrap_or(usize::MAX))
        {
            if !self.applied_command_ids.insert(command.command_id.clone()) {
                continue;
            }
            self.messages.push(ChatMessage::User {
                text: command.text,
                images: command.images,
            });
            self.observations.push(LoopObservation::UserCommandApplied {
                command_id: command.command_id,
                kind,
            });
            injected = true;
        }
        if injected {
            (self.checkpoint)(&self.messages);
        }
        Ok(injected)
    }

    /// Decide the next round: settle if the step bound is reached, else consult the
    /// compactor (Phase 4 Layer B) and either interleave a summarization round, apply
    /// a deterministic rewrite, or proceed straight to the main call. Replaces the old
    /// `prepare_model_call` (whose per-turn `compact_context` was cache-hostile).
    fn decide_next_call(&mut self) -> Outcome<BrokeredTurnOutcome> {
        if self.step >= self.input.max_steps {
            return Outcome::Settle(self.timed_out());
        }
        let stats = CompactionStats {
            last_input_tokens: self.last_input_tokens,
            context_window: self.model.context_window(),
            message_count: self.messages.len(),
        };
        let manual_compaction = match self.take_manual_compaction_request() {
            Ok(requested) => requested,
            Err(error) => {
                return Outcome::Settle(BrokeredTurnOutcome {
                    status: TurnStatus::Failed,
                    summary: format!("durable compaction command read failed: {error}"),
                    steps: self.step,
                    observations: std::mem::take(&mut self.observations),
                    usage: std::mem::take(&mut self.usage),
                    last_input_tokens: self.last_input_tokens,
                });
            }
        };
        if manual_compaction || self.compactor.should_compact(&stats) {
            match self.compactor.plan(&self.messages, &stats) {
                CompactionOutcome::Deterministic(rewritten) => {
                    // A pure rewrite (front-trim / hard-reset): install it, disarm,
                    // and persist the new prefix once (apply-once).
                    let folded_messages = self.messages.len().saturating_sub(rewritten.len());
                    self.messages = rewritten;
                    self.compaction_epoch += 1;
                    self.last_input_tokens = 0;
                    self.observations.push(LoopObservation::Compacted {
                        epoch: self.compaction_epoch,
                        folded_messages,
                        summary_bytes: 0,
                    });
                    self.anchor_current_world_after_compaction();
                    (self.checkpoint)(&self.messages);
                }
                CompactionOutcome::NeedsModel(request) => {
                    // Interleave one summarization round (Decision 8): yield its
                    // request as `NeedsIo(Http)`, remembering it so the reply folds
                    // in on re-entry. This is what makes the summarizer eviction-safe
                    // on the durable object.
                    self.awaiting = Awaiting::Summary;
                    let http = self.model.build_request(&request.request_messages, &[]);
                    self.pending_compaction = Some(request);
                    return Outcome::NeedsIo(IoRequest::Http(http));
                }
            }
        }
        self.main_call()
    }

    fn take_manual_compaction_request(&mut self) -> Result<bool, String> {
        let Some(source) = self.command_source.as_mut() else {
            return Ok(false);
        };
        for command in source.pending(TurnCommandKind::Compact)? {
            if !self.applied_command_ids.insert(command.command_id.clone()) {
                continue;
            }
            self.observations.push(LoopObservation::UserCommandApplied {
                command_id: command.command_id,
                kind: TurnCommandKind::Compact,
            });
            return Ok(true);
        }
        Ok(false)
    }

    fn anchor_current_world_after_compaction(&mut self) {
        let Some(world) = self.visible_world.clone() else {
            return;
        };
        let Some(rendered) = render_world_projection(&WorldProjection::Full(world.clone())) else {
            unreachable!("a full world projection always renders")
        };
        self.messages.push(ChatMessage::System(rendered));
        self.observations.push(LoopObservation::WorldProjected {
            epoch: world.world_epoch,
            projection: "full".to_owned(),
            content_hash: world.content_hash(),
        });
    }

    /// Prepare the main agent model call for the current step (observe + build).
    fn main_call(&mut self) -> Outcome<BrokeredTurnOutcome> {
        // Cooperative cancel (pi-conformance §3): every model round funnels
        // through here, so this is the between-rounds check. The transcript was
        // checkpointed after the last settle — the partial conversation
        // persists, mirroring pi's aborted-message-kept semantics.
        if self.cancel_check.is_some_and(|probe| probe()) {
            return Outcome::Settle(BrokeredTurnOutcome {
                status: TurnStatus::Cancelled,
                summary: "turn cancelled by request".to_owned(),
                steps: self.step,
                observations: std::mem::take(&mut self.observations),
                usage: std::mem::take(&mut self.usage),
                last_input_tokens: self.last_input_tokens,
            });
        }
        if let Err(error) = self.project_current_world() {
            return Outcome::Settle(BrokeredTurnOutcome {
                status: TurnStatus::Failed,
                summary: format!("model-visible world collection failed: {error}"),
                steps: self.step,
                observations: std::mem::take(&mut self.observations),
                usage: std::mem::take(&mut self.usage),
                last_input_tokens: self.last_input_tokens,
            });
        }
        // Pi-style steering joins the current run after the preceding
        // assistant/tool batch and before the next model request. Multiple
        // steering commands admitted before this boundary preserve FIFO order.
        if let Err(error) = self.inject_commands(TurnCommandKind::Steer, None) {
            return Outcome::Settle(BrokeredTurnOutcome {
                status: TurnStatus::Failed,
                summary: format!("durable turn command read failed: {error}"),
                steps: self.step,
                observations: std::mem::take(&mut self.observations),
                usage: std::mem::take(&mut self.usage),
                last_input_tokens: self.last_input_tokens,
            });
        }
        self.awaiting = Awaiting::Main;
        self.observations
            .push(LoopObservation::ModelRequest { step: self.step });
        Outcome::NeedsIo(IoRequest::Http(
            self.model.build_request(&self.messages, &self.input.tools),
        ))
    }

    /// The `TimedOut` terminal when the step bound is hit.
    fn timed_out(&mut self) -> BrokeredTurnOutcome {
        BrokeredTurnOutcome {
            status: TurnStatus::TimedOut,
            summary: format!(
                "brokered turn exceeded {} model steps",
                self.input.max_steps
            ),
            steps: self.input.max_steps,
            observations: std::mem::take(&mut self.observations),
            usage: std::mem::take(&mut self.usage),
            last_input_tokens: self.last_input_tokens,
        }
    }
}

impl<M, E> StepMachine for BrokeredTurnMachine<'_, M, E>
where
    M: HttpModelClient + ?Sized,
    E: ToolExecutor + ?Sized,
{
    type Output = BrokeredTurnOutcome;

    fn step(&mut self, incoming: Option<IoResult>) -> Outcome<BrokeredTurnOutcome> {
        // First entry: seed the conversation (or resume) and persist it, then
        // prepare the step-0 model call.
        if !self.started {
            self.started = true;
            self.messages = if self.input.resume_from.is_empty() {
                let (media_images, media_notices, media_observations) =
                    normalize_media_input(&self.input.user_media);
                self.observations.extend(media_observations);
                let mut messages = vec![ChatMessage::System(self.input.system.clone())];
                if let Some(world) = self.input.world.clone() {
                    let projection = WorldProjection::Full(world.clone());
                    if let Some(rendered) = render_world_projection(&projection) {
                        messages.push(ChatMessage::System(rendered));
                        self.observations.push(LoopObservation::WorldProjected {
                            epoch: world.world_epoch,
                            projection: "full".to_owned(),
                            content_hash: world.content_hash(),
                        });
                        self.visible_world = Some(world);
                    }
                }
                let mut text = self.input.user.clone();
                for notice in media_notices {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(&notice);
                }
                let mut images = self.input.user_images.clone();
                images.extend(media_images);
                messages.push(ChatMessage::User { text, images });
                messages
            } else {
                sanitize_resume_messages(self.input.resume_from.clone())
            };
            (self.checkpoint)(&self.messages);
            return self.decide_next_call();
        }

        let response = match incoming {
            Some(IoResult::Http(response)) => response,
            None => {
                // A fresh durable host handle has no transient `in_flight`
                // request, but the snapshot identifies exactly which call is
                // awaiting a response. Rebuild and re-emit that same request;
                // the model client derives its idempotency key from the stable
                // turn scope plus these exact messages/tool specs.
                let request = match self.awaiting {
                    Awaiting::Main => self.model.build_request(&self.messages, &self.input.tools),
                    Awaiting::Summary => {
                        let Some(compaction) = self.pending_compaction.as_ref() else {
                            return Outcome::Settle(BrokeredTurnOutcome {
                                status: TurnStatus::Failed,
                                summary: "persisted summarization round has no compaction request"
                                    .to_owned(),
                                steps: self.step,
                                observations: std::mem::take(&mut self.observations),
                                usage: std::mem::take(&mut self.usage),
                                last_input_tokens: self.last_input_tokens,
                            });
                        };
                        self.model.build_request(&compaction.request_messages, &[])
                    }
                };
                return Outcome::NeedsIo(IoRequest::Http(request));
            }
        };

        // A summarization round (Phase 4 Layer B): fold the summary into a fresh
        // stable prefix (apply-once), disarm, and issue the deferred main call. The
        // summarizer round is infrastructure — it does not advance `step`, and its
        // usage is not the trigger signal. On a summarizer failure, disarm and
        // proceed uncompacted (the Lb-5 overflow fallback covers the hard case).
        if self.awaiting == Awaiting::Summary {
            let folded = match (
                self.model.parse_response(response),
                self.pending_compaction.take(),
            ) {
                (Ok(reply), Some(request)) => Some((
                    self.compactor.assemble(&request, &reply.text),
                    request.request_messages.len(),
                    reply.text.len(),
                )),
                _ => None,
            };
            if let Some((messages, folded_messages, summary_bytes)) = folded {
                self.messages = messages;
                self.compaction_epoch += 1;
                self.observations.push(LoopObservation::Compacted {
                    epoch: self.compaction_epoch,
                    folded_messages,
                    summary_bytes,
                });
                self.anchor_current_world_after_compaction();
                (self.checkpoint)(&self.messages);
            }
            self.last_input_tokens = 0;
            return self.main_call();
        }

        let reply = match self.model.parse_response(response) {
            Ok(reply) => reply,
            Err(error) => {
                // Overflow fallback (Lb-5): a provider context-window error means the
                // prompt is too large even to send. Rather than fail, trim from the
                // FRONT — keep the anchors and a pairing-safe recent suffix byte-intact
                // (Codex's cache-preserving fallback, never a middle edit) — and retry
                // the same step. Bounded so a persistent overflow still terminates.
                if is_context_overflow(&error) && self.overflow_trims < MAX_OVERFLOW_TRIMS {
                    let trimmed = front_trim(&self.messages);
                    // Only retry if the trim actually made progress (dropped messages);
                    // otherwise fall through and fail rather than loop.
                    if trimmed.len() < self.messages.len() {
                        self.overflow_trims += 1;
                        let folded_messages = self.messages.len() - trimmed.len();
                        self.messages = trimmed;
                        self.compaction_epoch += 1;
                        self.observations.push(LoopObservation::Compacted {
                            epoch: self.compaction_epoch,
                            folded_messages,
                            summary_bytes: 0,
                        });
                        self.anchor_current_world_after_compaction();
                        (self.checkpoint)(&self.messages);
                        return self.main_call();
                    }
                }
                // Bounded auto-retry on transient provider errors
                // (pi-conformance §2): re-issue the same main call. The
                // transcript is untouched — the failed round produced nothing.
                if is_retryable_provider_error(&error)
                    && self.provider_retries < MAX_PROVIDER_RETRIES
                {
                    self.provider_retries += 1;
                    return self.main_call();
                }
                return Outcome::Settle(BrokeredTurnOutcome {
                    status: match error {
                        HarnessModelError::Timeout => TurnStatus::TimedOut,
                        _ => TurnStatus::Failed,
                    },
                    summary: model_error_summary(&error),
                    steps: self.step + 1,
                    observations: std::mem::take(&mut self.observations),
                    usage: std::mem::take(&mut self.usage),
                    last_input_tokens: self.last_input_tokens,
                });
            }
        };
        self.usage = merge_usage(std::mem::take(&mut self.usage), reply.usage.clone());
        // The real-usage compaction signal is the MAIN reply's input token count.
        self.last_input_tokens = input_tokens_of(&reply.usage);

        // A round whose stream the transport released early on an observed
        // cancellation request is a truncation, whatever shape it parsed to —
        // a text-only tail reads exactly like a final answer, and settling it
        // `Completed` would launder a stop into a normal terminal. Keep the
        // text that fully arrived (durably, as this round's assistant
        // message), start no offered tool, and settle cancelled. A naturally
        // completed stream never trips this: its release probe stays false,
        // so final-terminal-wins is untouched.
        if self.stream_released.is_some_and(|probe| probe()) {
            if !reply.text.is_empty() {
                self.messages.push(ChatMessage::Assistant {
                    text: reply.text.clone(),
                    tool_calls: Vec::new(),
                });
                (self.checkpoint)(&self.messages);
            }
            self.step += 1;
            return Outcome::Settle(BrokeredTurnOutcome {
                status: TurnStatus::Cancelled,
                summary: "turn cancelled by request".to_owned(),
                steps: self.step,
                observations: std::mem::take(&mut self.observations),
                usage: std::mem::take(&mut self.usage),
                last_input_tokens: self.last_input_tokens,
            });
        }

        if reply.is_final() {
            // Persist the final assistant reply into the transcript before
            // settling (pi-conformance §4): the completed conversation is what
            // a `thread continue` follow-up turn seeds from — without this the
            // thread would end on the last tool round, not the answer.
            self.messages.push(ChatMessage::Assistant {
                text: reply.text.clone(),
                tool_calls: Vec::new(),
            });
            (self.checkpoint)(&self.messages);
            self.step += 1;
            // Steering wins over ordinary follow-up. Follow-ups are consumed
            // one at a time, exactly when the agent would otherwise become
            // idle, matching Pi's one-at-a-time queue semantics.
            let continued = match self.inject_commands(TurnCommandKind::Steer, None) {
                Ok(true) => Ok(true),
                Ok(false) => self.inject_commands(TurnCommandKind::FollowUp, Some(1)),
                Err(error) => Err(error),
            };
            let continued = match continued {
                Ok(continued) => continued,
                Err(error) => {
                    return Outcome::Settle(BrokeredTurnOutcome {
                        status: TurnStatus::Failed,
                        summary: format!("durable turn command read failed: {error}"),
                        steps: self.step,
                        observations: std::mem::take(&mut self.observations),
                        usage: std::mem::take(&mut self.usage),
                        last_input_tokens: self.last_input_tokens,
                    });
                }
            };
            if continued {
                return self.decide_next_call();
            }
            return Outcome::Settle(BrokeredTurnOutcome {
                status: TurnStatus::Completed,
                summary: reply.text,
                steps: self.step,
                observations: std::mem::take(&mut self.observations),
                usage: std::mem::take(&mut self.usage),
                last_input_tokens: self.last_input_tokens,
            });
        }

        // The model requested tools: record the assistant turn, broker each tool
        // through the executor (nested effects), feed results back, then advance
        // to the next model call.
        self.messages.push(ChatMessage::Assistant {
            text: reply.text.clone(),
            tool_calls: reply.tool_calls.clone(),
        });
        let mut results = Vec::with_capacity(reply.tool_calls.len());
        for call in &reply.tool_calls {
            self.observations.push(LoopObservation::ToolRequested {
                call_id: call.id.clone(),
                name: call.name.clone(),
            });
            if let Some(observation) = recall_request_observation(call) {
                self.observations.push(observation);
            }
            let outcome = execute_offered_tool(self.executor, &self.input.tools, call);
            self.observations.push(LoopObservation::ToolResult {
                call_id: call.id.clone(),
                name: call.name.clone(),
                status: outcome.status,
            });
            if let Some((original_bytes, recall_id)) = truncation_metadata(&outcome.content) {
                self.observations
                    .push(LoopObservation::ToolOutputTruncated {
                        call_id: call.id.clone(),
                        tool_name: call.name.clone(),
                        policy: "class_aware_v1".to_owned(),
                        output_class: "text/plain".to_owned(),
                        retention_direction: tool_output_retention(&call.name).to_owned(),
                        result_status: outcome.status,
                        experiment_label: "pi_class_aware_v1".to_owned(),
                        original_bytes,
                        retained_bytes: outcome.content.len(),
                        recall_id,
                    });
            }
            results.push(ToolResultMsg {
                tool_call_id: call.id.clone(),
                tool_name: call.name.clone(),
                content: outcome.content,
                is_error: matches!(outcome.status, ToolStatus::Error),
            });
        }
        self.messages.push(ChatMessage::ToolResults(results));
        (self.checkpoint)(&self.messages);
        self.step += 1;
        self.decide_next_call()
    }
}

fn normalize_media_input(
    media: &[MediaInput],
) -> (Vec<ImageBlock>, Vec<String>, Vec<LoopObservation>) {
    let normalized = crate::media::normalize_provider_media(media);
    (
        normalized.images,
        normalized.text_parts,
        normalized.observations,
    )
}

fn recall_request_observation(call: &ToolCall) -> Option<LoopObservation> {
    if call.name != "recall" {
        return None;
    }
    let content_id = call
        .arguments
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())?;
    Some(LoopObservation::RecallRequested {
        call_id: call.id.clone(),
        content_id: content_id.to_owned(),
        offset: call.arguments.get("offset").and_then(Value::as_u64),
        limit: call.arguments.get("limit").and_then(Value::as_u64),
        experiment_label: "pi_class_aware_v1".to_owned(),
    })
}

fn truncation_metadata(content: &str) -> Option<(usize, Option<String>)> {
    if let Some(marker) = content.rfind("[full `") {
        let footer = &content[marker..];
        let bytes_at = footer.find(" output: ")? + " output: ".len();
        let bytes = footer[bytes_at..].split_whitespace().next()?.parse().ok()?;
        let recall_id = footer
            .find(", id ")
            .map(|start| &footer[start + ", id ".len()..])
            .and_then(|tail| tail.split_whitespace().next())
            .map(str::to_owned);
        return Some((bytes, recall_id));
    }
    let marker = content.find(" of ")?;
    let tail = &content[marker + " of ".len()..];
    let bytes = tail.split_whitespace().next()?.parse().ok()?;
    let recall_id = content
        .find("recall id=")
        .map(|start| &content[start + "recall id=".len()..])
        .and_then(|tail| tail.split_whitespace().next())
        .map(|id| {
            id.trim_end_matches(|ch: char| !ch.is_ascii_alphanumeric())
                .to_owned()
        });
    Some((bytes, recall_id))
}

/// Native driver for a brokered turn over an HTTP model client: run the
/// [`BrokeredTurnMachine`] to completion in one synchronous pass, fulfilling each
/// model call's `NeedsIo(Http)` via `host` (the `ureq` transport). Produces the
/// same [`BrokeredTurnOutcome`] as [`run_brokered_loop`] over an equivalent
/// client; the durable-object host (Phase 5) drives the same machine across
/// isolate wakes instead of in one pass.
#[allow(clippy::too_many_arguments)]
pub fn run_brokered_turn_http<M, E>(
    model: &M,
    executor: &E,
    input: &BrokeredTurnInput,
    checkpoint: &mut dyn FnMut(&[ChatMessage]),
    host: &impl HostDriver,
    compactor: &dyn Compactor,
    cancel_check: Option<&dyn Fn() -> bool>,
    stream_released: Option<&dyn Fn() -> bool>,
) -> BrokeredTurnOutcome
where
    M: HttpModelClient + ?Sized,
    E: ToolExecutor + ?Sized,
{
    let mut machine = BrokeredTurnMachine::new(model, executor, input, checkpoint, compactor);
    if let Some(probe) = cancel_check {
        machine = machine.with_cancel_check(probe);
    }
    if let Some(probe) = stream_released {
        machine = machine.with_stream_released(probe);
    }
    run_to_completion(&mut machine, host)
}

// ---------------------------------------------------------------------------
// Conversation compaction (context-assembly Phase 4, Layer B).
//
// The cache-hostile per-turn `compact_context` (which rewrote the middle of the
// prefix on every request) is gone. Compaction is now a pluggable, cache-aware
// strategy consulted ONCE per step before the main model call: it fires rarely
// and decisively (Decision 7), and when it needs a model — a turn-summarizing
// strategy — that summarization is an interleaved `NeedsHttp` round on the same
// step machine (Decision 8), so it suspends/resumes on the durable object like
// any other model call. The `owned-harness-compaction` /
// `compaction-epoch-lifecycle` Maude models lock the invariants.
// ---------------------------------------------------------------------------

/// The model's default context window (tokens) when a client does not report one.
pub const DEFAULT_CONTEXT_WINDOW: u64 = 200_000;

/// Real-usage statistics the compactor's trigger reads (Decision 7). Populated
/// from the last MAIN model reply's `input_tokens` — the provider's own count of
/// the whole prompt it just processed, a faithful `BodyAfterPrefix` proxy — and
/// the model's context window.
#[derive(Clone, Copy, Debug)]
pub struct CompactionStats {
    pub last_input_tokens: u64,
    pub context_window: u64,
    pub message_count: usize,
}

/// Which model round the machine's next Http response answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Awaiting {
    /// A normal agent model call.
    Main,
    /// The interleaved summarization round of a `NeedsModel` compaction.
    Summary,
}

/// What a [`Compactor`] decides when the trigger fires.
pub enum CompactionOutcome {
    /// Rewrite the transcript with no model call (front-trim, hard-reset).
    Deterministic(Vec<ChatMessage>),
    /// Run one summarization round, then rebuild via [`Compactor::assemble`].
    NeedsModel(SummarizationRequest),
}

/// A pending summarization compaction: the synthetic no-tools request that yields
/// the handoff summary, plus the verbatim anchors/tail to rebuild the transcript
/// around it. Serializable so it survives a durable-object eviction mid-round
/// (the machine snapshots it while `awaiting == Summary`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SummarizationRequest {
    /// The synthetic conversation sent to the model to produce the summary: a
    /// System instruction plus a User message carrying the folded transcript. No
    /// tools are offered.
    pub request_messages: Vec<ChatMessage>,
    /// Messages re-injected verbatim ahead of the summary (System + first User),
    /// preserving the stable cache prefix.
    pub anchors: Vec<ChatMessage>,
    /// The recent tail kept verbatim after the summary.
    pub keep_tail: Vec<ChatMessage>,
}

/// A conversation-compaction strategy (Decision 6), consulted once per step before
/// the main model call. Selected per agent/profile/config; v1 ships
/// [`TurnSummarizingCompactor`] and [`NoopCompactor`].
pub trait Compactor {
    /// Should a compaction fire before the next main call? Reads real usage vs the
    /// window (Decision 7); must be false until a fresh main reply re-measures, so
    /// the machine resets `last_input_tokens` to 0 after each compaction.
    fn should_compact(&self, stats: &CompactionStats) -> bool;

    /// Plan the compaction: a pure rewrite, or a summarization round.
    fn plan(&self, transcript: &[ChatMessage], stats: &CompactionStats) -> CompactionOutcome;

    /// Rebuild the transcript from a completed summary (the model's reply to a
    /// `NeedsModel` request) and the request's verbatim anchors/tail.
    fn assemble(&self, request: &SummarizationRequest, summary: &str) -> Vec<ChatMessage>;
}

/// A compactor that never compacts: the native default before a strategy is chosen,
/// and the reference the loop-equivalence tests drive so the stepped machine stays
/// byte-identical to the no-compaction reference loop.
pub struct NoopCompactor;

impl Compactor for NoopCompactor {
    fn should_compact(&self, _stats: &CompactionStats) -> bool {
        false
    }

    fn plan(&self, transcript: &[ChatMessage], _stats: &CompactionStats) -> CompactionOutcome {
        CompactionOutcome::Deterministic(transcript.to_vec())
    }

    fn assemble(&self, request: &SummarizationRequest, _summary: &str) -> Vec<ChatMessage> {
        let mut out = request.anchors.clone();
        out.extend(request.keep_tail.iter().cloned());
        out
    }
}

/// Resolve the authored owned-harness strategy through one shared policy seam.
/// Native and Durable Object hosts must not silently choose different context
/// behavior for the same agent declaration.
pub fn compactor_for_strategy(strategy: Option<&str>) -> Box<dyn Compactor> {
    match strategy {
        Some("hard_reset") => Box::new(HardResetCompactor::default()),
        Some("tool_results") => Box::new(ToolResultCompactor::default()),
        Some("none") => Box::new(NoopCompactor),
        _ => Box::new(TurnSummarizingCompactor::default()),
    }
}

/// Trigger threshold in context-window tenths: compact when real input usage reaches
/// this fraction of the window (Decision 7: ~90%).
const COMPACT_TRIGGER_TENTHS: u64 = 9;
/// Never compact a conversation shorter than this — there is nothing worth folding.
const COMPACT_MIN_MESSAGES: usize = 6;
/// Verbatim recent-tail budget in bytes (~20k tokens of recent turns kept intact).
const COMPACT_TAIL_BUDGET_BYTES: usize = 80_000;

/// The summarization instruction (Codex-shape structured handoff). Sent as the
/// System message of the interleaved summarization round.
const SUMMARIZE_INSTRUCTION: &str = "You are compacting an agent conversation that is approaching its context limit. \
Produce a dense, structured handoff summary a fresh agent could resume from with no other history: the task and goals, \
the decisions made and why, the current state, the concrete next steps, and every file path, identifier, and value \
referenced — verbatim. Do not omit specifics. Output only the summary.";

/// Strategy #1: turn-summarization (Decision 6, Codex-local shape). When real usage
/// crosses the trigger, fold the middle of the transcript into a recorded handoff
/// summary via one interleaved model round, keeping the System + first-User anchors
/// (the stable cache prefix) and a verbatim recent tail. The post-compaction prefix
/// is installed once and held stable (apply-once); subsequent turns only append.
pub struct TurnSummarizingCompactor {
    trigger_tenths: u64,
    min_messages: usize,
    tail_budget_bytes: usize,
}

impl Default for TurnSummarizingCompactor {
    fn default() -> Self {
        Self::new(
            COMPACT_TRIGGER_TENTHS,
            COMPACT_MIN_MESSAGES,
            COMPACT_TAIL_BUDGET_BYTES,
        )
    }
}

impl TurnSummarizingCompactor {
    /// Construct with explicit thresholds (for per-profile config and tests);
    /// [`Default`] uses the shipped constants.
    pub fn new(trigger_tenths: u64, min_messages: usize, tail_budget_bytes: usize) -> Self {
        Self {
            trigger_tenths,
            min_messages,
            tail_budget_bytes,
        }
    }
}

impl Compactor for TurnSummarizingCompactor {
    fn should_compact(&self, stats: &CompactionStats) -> bool {
        over_trigger(stats, self.trigger_tenths, self.min_messages)
    }

    fn plan(&self, transcript: &[ChatMessage], _stats: &CompactionStats) -> CompactionOutcome {
        // Anchors: the System message + the first User message (the seeded head, or
        // the held handoff after a prior compaction) — the stable cache prefix.
        let anchor_end = stable_anchor_end(transcript);
        let tail_start = recent_tail_start(transcript, self.tail_budget_bytes).max(anchor_end);
        // The fold region is everything between the anchors and the recent tail.
        // Nothing to fold → a no-op rewrite that disarms until the next reply.
        if tail_start <= anchor_end {
            return CompactionOutcome::Deterministic(transcript.to_vec());
        }
        let anchors = transcript[..anchor_end].to_vec();
        let fold = &transcript[anchor_end..tail_start];
        let keep_tail = transcript[tail_start..].to_vec();
        let folded_json = chat_messages_to_json(fold);
        let request_messages = vec![
            ChatMessage::System(SUMMARIZE_INSTRUCTION.to_string()),
            ChatMessage::user_text(format!(
                "Summarize this earlier portion of the conversation:\n{folded_json}"
            )),
        ];
        CompactionOutcome::NeedsModel(SummarizationRequest {
            request_messages,
            anchors,
            keep_tail,
        })
    }

    fn assemble(&self, request: &SummarizationRequest, summary: &str) -> Vec<ChatMessage> {
        let mut out = request.anchors.clone();
        out.push(ChatMessage::user_text(format!(
            "[Earlier conversation compacted to a handoff summary]\n{summary}"
        )));
        out.extend(request.keep_tail.iter().cloned());
        out
    }
}

/// The recall footer appended to a truncated tool output (context-assembly Phase 5).
/// The format is owned here — the CLI executor appends it at capture time and the
/// [`ToolResultCompactor`] parses it back — so the two sides agree on one contract.
/// `id` is the content-addressed recall id the model passes to the `recall` tool.
pub fn recall_footer(tool: &str, byte_len: usize, id: &str) -> String {
    format!(
        "\n[full `{tool}` output: {byte_len} bytes, id {id} — call `recall` with this id (and optional line offset/limit) to read the rest]"
    )
}

/// Semantic end retained for an oversized text result. Unknown tools default
/// to the head: the start normally carries schema, headings, or an explanation,
/// while only explicitly command/log-like streams make the latest tail the
/// useful end.
pub fn tool_output_retention(tool: &str) -> &'static str {
    let lower = tool.to_ascii_lowercase();
    if matches!(lower.as_str(), "bash" | "shell" | "exec" | "command.run")
        || lower.ends_with(".bash")
        || lower.ends_with(".exec")
        || lower.contains("log")
    {
        "tail"
    } else {
        "head"
    }
}

/// Apply DR-0080's Pi-style class-aware byte cap. Complete output recovery is
/// supplied by the caller's content store and named by `recall_id` when capture
/// succeeded. UTF-8 boundaries are preserved and a small result is unchanged.
pub fn truncate_tool_output(
    tool: &str,
    text: &str,
    max_bytes: usize,
    recall_id: Option<&str>,
) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let direction = tool_output_retention(tool);
    let keep = max_bytes.saturating_sub(256).max(1);
    let (retained, omitted_where) = if direction == "tail" {
        let mut start = text.len().saturating_sub(keep);
        while start < text.len() && !text.is_char_boundary(start) {
            start += 1;
        }
        (&text[start..], "beginning")
    } else {
        let mut end = keep.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        (&text[..end], "end")
    };
    let omitted = text.len().saturating_sub(retained.len());
    let marker = format!(
        "[... {omitted} of {} bytes omitted from the {omitted_where}; retained {direction} ...]",
        text.len()
    );
    let mut output = if direction == "tail" {
        format!("{marker}\n{retained}")
    } else {
        format!("{retained}\n{marker}")
    };
    if let Some(id) = recall_id {
        output.push_str(&recall_footer(tool, text.len(), id));
    }
    output
}

/// Marker preceding the recall id in a [`recall_footer`], used to parse it back.
const RECALL_ID_MARKER: &str = ", id ";

/// Extract the recall id from a tool-result content that carries a [`recall_footer`],
/// or `None` if it was not captured. The id is a single whitespace-delimited token.
fn recall_id_in(content: &str) -> Option<String> {
    let start = content.rfind(RECALL_ID_MARKER)? + RECALL_ID_MARKER.len();
    let rest = &content[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    let id = &rest[..end];
    (!id.is_empty()).then(|| id.to_string())
}

/// The shared compaction trigger (Decision 7): real usage has reached
/// `trigger_tenths`/10 of the window and the conversation clears the message floor.
fn over_trigger(stats: &CompactionStats, trigger_tenths: u64, min_messages: usize) -> bool {
    stats.message_count >= min_messages
        && stats.last_input_tokens.saturating_mul(10)
            >= stats.context_window.saturating_mul(trigger_tenths)
}

/// The index at which the recent tail begins: the suffix (nearest the end) whose
/// cumulative serialized size stays within `tail_budget_bytes`, always at least the
/// final message. Shared by the summarizing and hard-reset strategies.
fn recent_tail_start(messages: &[ChatMessage], tail_budget_bytes: usize) -> usize {
    let mut bytes = 0usize;
    let mut start = messages.len();
    for (index, message) in messages.iter().enumerate().rev() {
        bytes = bytes.saturating_add(message_size_bytes(message));
        if bytes > tail_budget_bytes && index + 1 < messages.len() {
            break;
        }
        start = index;
    }
    start
}

/// Stable anchors are every leading system-plane message plus the first user
/// message. This preserves the instruction plane and initial full world when a
/// turn has more than one system message, while retaining the legacy two-message
/// anchor for ordinary text-only turns.
fn stable_anchor_end(messages: &[ChatMessage]) -> usize {
    messages
        .iter()
        .position(|message| matches!(message, ChatMessage::User { .. }))
        .map_or(messages.len(), |index| index + 1)
}

/// Strategy #2: hard-reset (no-LLM, Codex's token-budget mode). When the trigger
/// fires, DISCARD the middle entirely — no summary, no model round — keeping only the
/// System + first-User anchors and a byte-budgeted recent tail. The cheapest strategy:
/// it loses the middle (unlike turn-summarization) but costs nothing and never stalls
/// the turn on a summarization round. A `Deterministic` compactor.
pub struct HardResetCompactor {
    trigger_tenths: u64,
    min_messages: usize,
    tail_budget_bytes: usize,
}

impl Default for HardResetCompactor {
    fn default() -> Self {
        Self::new(
            COMPACT_TRIGGER_TENTHS,
            COMPACT_MIN_MESSAGES,
            COMPACT_TAIL_BUDGET_BYTES,
        )
    }
}

impl HardResetCompactor {
    /// Construct with explicit thresholds (for config and tests); [`Default`] uses
    /// the shipped constants.
    pub fn new(trigger_tenths: u64, min_messages: usize, tail_budget_bytes: usize) -> Self {
        Self {
            trigger_tenths,
            min_messages,
            tail_budget_bytes,
        }
    }
}

impl Compactor for HardResetCompactor {
    fn should_compact(&self, stats: &CompactionStats) -> bool {
        over_trigger(stats, self.trigger_tenths, self.min_messages)
    }

    fn plan(&self, transcript: &[ChatMessage], _stats: &CompactionStats) -> CompactionOutcome {
        let anchor_end = stable_anchor_end(transcript);
        let tail_start = recent_tail_start(transcript, self.tail_budget_bytes).max(anchor_end);
        // Nothing between anchors and tail → a no-op rewrite that disarms.
        if tail_start <= anchor_end {
            return CompactionOutcome::Deterministic(transcript.to_vec());
        }
        // Drop the middle: anchors + recent tail, no summary.
        let mut out = transcript[..anchor_end].to_vec();
        out.extend_from_slice(&transcript[tail_start..]);
        CompactionOutcome::Deterministic(out)
    }

    fn assemble(&self, request: &SummarizationRequest, _summary: &str) -> Vec<ChatMessage> {
        // Never called (hard-reset is always `Deterministic`); rebuild anchors + tail.
        let mut out = request.anchors.clone();
        out.extend(request.keep_tail.iter().cloned());
        out
    }
}

/// Strategy #3: tool-result compaction (the WhippleScript edge — lossless where
/// Codex/pi are lossy). At a compaction boundary, rewrite the bodies of OLD captured
/// tool results (in the fold region between the anchors and the recent tail) down to
/// just their content-addressed recall ref, keeping the conversation STRUCTURE
/// (assistant turns, small results) intact. The bulk — large tool outputs already
/// truncated + captured — shrinks to ~100-byte refs the model can `recall` losslessly.
/// A `Deterministic` compactor (no model round). Best for read/grep/bash-heavy turns.
pub struct ToolResultCompactor {
    trigger_tenths: u64,
    min_messages: usize,
    tail_budget_bytes: usize,
}

impl Default for ToolResultCompactor {
    fn default() -> Self {
        Self::new(
            COMPACT_TRIGGER_TENTHS,
            COMPACT_MIN_MESSAGES,
            COMPACT_TAIL_BUDGET_BYTES,
        )
    }
}

impl ToolResultCompactor {
    /// Construct with explicit thresholds (for config and tests); [`Default`] uses
    /// the shipped constants.
    pub fn new(trigger_tenths: u64, min_messages: usize, tail_budget_bytes: usize) -> Self {
        Self {
            trigger_tenths,
            min_messages,
            tail_budget_bytes,
        }
    }
}

impl Compactor for ToolResultCompactor {
    fn should_compact(&self, stats: &CompactionStats) -> bool {
        over_trigger(stats, self.trigger_tenths, self.min_messages)
    }

    fn plan(&self, transcript: &[ChatMessage], _stats: &CompactionStats) -> CompactionOutcome {
        let anchor_end = stable_anchor_end(transcript);
        let tail_start = recent_tail_start(transcript, self.tail_budget_bytes).max(anchor_end);
        if tail_start <= anchor_end {
            return CompactionOutcome::Deterministic(transcript.to_vec());
        }
        let mut out = transcript[..anchor_end].to_vec();
        // Elide old captured tool results to their recall ref; keep structure.
        for message in &transcript[anchor_end..tail_start] {
            match message {
                ChatMessage::ToolResults(results) => {
                    let elided = results
                        .iter()
                        .map(|result| match recall_id_in(&result.content) {
                            Some(id) => ToolResultMsg {
                                content: format!(
                                    "[tool output elided at compaction — call `recall` with id {id} to read it]"
                                ),
                                ..result.clone()
                            },
                            None => result.clone(),
                        })
                        .collect();
                    out.push(ChatMessage::ToolResults(elided));
                }
                other => out.push(other.clone()),
            }
        }
        out.extend_from_slice(&transcript[tail_start..]);
        CompactionOutcome::Deterministic(out)
    }

    fn assemble(&self, request: &SummarizationRequest, _summary: &str) -> Vec<ChatMessage> {
        // Never called (always `Deterministic`); rebuild anchors + tail.
        let mut out = request.anchors.clone();
        out.extend(request.keep_tail.iter().cloned());
        out
    }
}

/// The input-token count from a model reply's usage (`input_tokens`, or the OpenAI
/// `prompt_tokens` alias), 0 when absent — the real-usage signal for the trigger.
fn input_tokens_of(usage: &Value) -> u64 {
    usage
        .get("input_tokens")
        .or_else(|| usage.get("prompt_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

/// The serialized size of one message, for the recent-tail byte budget.
fn message_size_bytes(message: &ChatMessage) -> usize {
    chat_message_to_json(message).to_string().len()
}

/// Bound on transient-provider-error retries per turn (pi-conformance §2:
/// pi's session auto-retry runs 3 attempts). The sans-IO machine re-issues the
/// same request immediately — backoff delay, if any, belongs to the host.
const MAX_PROVIDER_RETRIES: u32 = 3;

/// Whether a provider/transport error is transient (rate limit, overloaded,
/// server error, network blip) and worth re-issuing. Context overflow is
/// EXCLUDED — that is compaction's job (the Lb-5 fallback above).
fn is_retryable_provider_error(error: &HarnessModelError) -> bool {
    match error {
        HarnessModelError::Timeout => false,
        HarnessModelError::Transport(_) => true,
        HarnessModelError::Provider(message) => {
            if is_context_overflow(error) {
                return false;
            }
            let lower = message.to_ascii_lowercase();
            [
                "overloaded",
                "rate limit",
                "rate_limit",
                "429",
                "529",
                "500",
                "502",
                "503",
                "server error",
                "internal error",
            ]
            .iter()
            .any(|marker| lower.contains(marker))
        }
    }
}

/// How many times a single turn may front-trim on repeated context-window errors
/// before giving up and failing (Lb-5 overflow fallback).
const MAX_OVERFLOW_TRIMS: u32 = 3;

/// Whether a model error is a provider context-window overflow (the prompt is too
/// large to send) — the signal for the front-trim fallback. Matches the common
/// provider phrasings; anything else fails the turn normally.
fn is_context_overflow(error: &HarnessModelError) -> bool {
    let HarnessModelError::Provider(message) = error else {
        return false;
    };
    let message = message.to_lowercase();
    [
        "context length",
        "context_length_exceeded",
        "maximum context",
        "context window",
        "prompt is too long",
        "too many tokens",
        "input is too long",
    ]
    .iter()
    .any(|needle| message.contains(needle))
}

/// Front-trim the transcript for the overflow fallback: keep the System + first-User
/// anchors and a byte-intact recent suffix, dropping the OLDEST middle messages
/// (never editing the middle in place — Codex's cache-preserving shape). Drops in
/// pairing-safe units: the kept suffix never begins with an orphan `ToolResults`
/// whose assistant call was dropped, so the provider still accepts it. Aims to shed
/// roughly half the middle; always keeps at least the final message.
fn front_trim(messages: &[ChatMessage]) -> Vec<ChatMessage> {
    let anchor_end = stable_anchor_end(messages);
    if messages.len() <= anchor_end + 1 {
        return messages.to_vec(); // anchors + one tail message: no progress possible
    }
    let last = messages.len() - 1;
    // The furthest-back suffix start that still keeps the final message with its
    // pairing intact: a trailing `ToolResults` needs its preceding assistant kept.
    let last_safe = if matches!(messages[last], ChatMessage::ToolResults(_)) {
        last.saturating_sub(1).max(anchor_end)
    } else {
        last
    };
    let middle_total: usize = messages[anchor_end..].iter().map(message_size_bytes).sum();
    let target = middle_total / 2;
    let mut dropped = 0usize;
    let mut suffix_start = anchor_end;
    while suffix_start < last_safe {
        let safe_boundary = !matches!(messages[suffix_start], ChatMessage::ToolResults(_));
        if dropped >= target && safe_boundary {
            break;
        }
        dropped += message_size_bytes(&messages[suffix_start]);
        suffix_start += 1;
    }
    // Never begin the kept suffix on an orphan `ToolResults` (its assistant was
    // dropped) — advance past it.
    if matches!(
        messages.get(suffix_start),
        Some(ChatMessage::ToolResults(_))
    ) {
        suffix_start += 1;
    }
    let mut out = messages[..anchor_end].to_vec();
    out.extend_from_slice(&messages[suffix_start..]);
    out
}

/// Serialize a transcript to JSON for durable persistence (no serde derive dep).
pub fn chat_messages_to_json(messages: &[ChatMessage]) -> Value {
    Value::Array(messages.iter().map(chat_message_to_json).collect())
}

fn chat_message_to_json(message: &ChatMessage) -> Value {
    match message {
        ChatMessage::System(text) => json!({ "role": "system", "text": text }),
        ChatMessage::User { text, images } => {
            // Wire-format stability: a text-only user message keeps the exact
            // pre-images shape, so persisted transcripts round-trip unchanged.
            if images.is_empty() {
                json!({ "role": "user", "text": text })
            } else {
                json!({
                    "role": "user",
                    "text": text,
                    "images": images
                        .iter()
                        .map(|image| json!({
                            "media_type": image.media_type,
                            "data_base64": image.data_base64,
                        }))
                        .collect::<Vec<_>>(),
                })
            }
        }
        ChatMessage::Assistant { text, tool_calls } => json!({
            "role": "assistant",
            "text": text,
            "tool_calls": tool_calls
                .iter()
                .map(|call| json!({ "id": call.id, "name": call.name, "arguments": call.arguments }))
                .collect::<Vec<_>>(),
        }),
        ChatMessage::ToolResults(results) => json!({
            "role": "tool_results",
            "results": results
                .iter()
                .map(|result| json!({
                    "tool_call_id": result.tool_call_id,
                    "tool_name": result.tool_name,
                    "content": result.content,
                    "is_error": result.is_error,
                }))
                .collect::<Vec<_>>(),
        }),
    }
}

/// Parse a transcript persisted by [`chat_messages_to_json`]. Unknown shapes are
/// skipped (best-effort recovery).
pub fn chat_messages_from_json(value: &Value) -> Vec<ChatMessage> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(chat_message_from_json).collect())
        .unwrap_or_default()
}

fn chat_message_from_json(value: &Value) -> Option<ChatMessage> {
    let text = |v: &Value| {
        v.get("text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    match value.get("role").and_then(Value::as_str)? {
        "system" => Some(ChatMessage::System(text(value))),
        "user" => {
            // Old-format entries carry no `images` key → empty (compatibility).
            let images = value
                .get("images")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .map(|item| ImageBlock {
                            media_type: item
                                .get("media_type")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            data_base64: item
                                .get("data_base64")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(ChatMessage::User {
                text: text(value),
                images,
            })
        }
        "assistant" => {
            let tool_calls = value
                .get("tool_calls")
                .and_then(Value::as_array)
                .map(|calls| {
                    calls
                        .iter()
                        .map(|call| ToolCall {
                            id: call
                                .get("id")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            name: call
                                .get("name")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            arguments: call.get("arguments").cloned().unwrap_or(Value::Null),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(ChatMessage::Assistant {
                text: text(value),
                tool_calls,
            })
        }
        "tool_results" => {
            let results = value
                .get("results")
                .and_then(Value::as_array)
                .map(|rows| {
                    rows.iter()
                        .map(|row| ToolResultMsg {
                            tool_call_id: row
                                .get("tool_call_id")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            tool_name: row
                                .get("tool_name")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            content: row
                                .get("content")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                            is_error: row
                                .get("is_error")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        })
                        .collect()
                })
                .unwrap_or_default();
            Some(ChatMessage::ToolResults(results))
        }
        _ => None,
    }
}

/// Prepare a resumed transcript: drop a dangling final assistant tool-call that
/// has no following results (a crash between request and execution), so the model
/// re-decides on resume instead of the loop waiting on an unanswered call.
/// Anti-idempotence makes this safe: a re-issued edit that already applied is
/// just an informative error.
fn sanitize_resume_messages(mut messages: Vec<ChatMessage>) -> Vec<ChatMessage> {
    if let Some(ChatMessage::Assistant { tool_calls, .. }) = messages.last() {
        if !tool_calls.is_empty() {
            messages.pop();
        }
    }
    messages
}

fn model_error_summary(error: &HarnessModelError) -> String {
    match error {
        HarnessModelError::Timeout => "model call timed out".to_string(),
        HarnessModelError::Provider(message) => format!("provider error: {message}"),
        HarnessModelError::Transport(message) => format!("transport error: {message}"),
    }
}

/// Stamp the settled turn's context reading into its terminal usage object,
/// under a key no provider emits. Stamped once, at the terminal — never fed
/// back through [`merge_usage`], whose numeric summing is exactly what this
/// gauge must not receive. A reading of 0 (no main reply reported one) is
/// honest absence and stamps nothing.
pub fn usage_with_context(usage: &Value, last_input_tokens: u64) -> Value {
    if last_input_tokens == 0 {
        return usage.clone();
    }
    let mut map = match usage {
        Value::Object(map) => map.clone(),
        _ => serde_json::Map::new(),
    };
    map.insert("last_input_tokens".to_owned(), json!(last_input_tokens));
    Value::Object(map)
}

/// Accumulate usage objects across model calls by summing shared numeric keys.
/// Non-numeric or absent keys fall back to the latest value.
///
/// Nested objects are merged by the same rule rather than replaced. Both wires
/// report cached tokens inside a details object — `prompt_tokens_details` on
/// Chat Completions, `input_tokens_details` on Responses — so replacing meant a
/// turn's flat counts summed over every round while its cached count came from
/// the last round alone. That is the same under-count as pricing a whole turn
/// from its final round, in the one field whose whole purpose is to be cheaper.
fn merge_usage(acc: Value, next: Value) -> Value {
    match (acc, next) {
        (Value::Null, next) => next,
        (acc, Value::Null) => acc,
        (Value::Object(mut acc_map), Value::Object(next_map)) => {
            for (key, value) in next_map {
                let merged = match (acc_map.get(&key), &value) {
                    (Some(Value::Number(a)), Value::Number(b)) => match (a.as_i64(), b.as_i64()) {
                        (Some(a), Some(b)) => json!(a + b),
                        _ => value.clone(),
                    },
                    (Some(nested @ Value::Object(_)), Value::Object(_)) => {
                        merge_usage(nested.clone(), value.clone())
                    }
                    _ => value.clone(),
                };
                acc_map.insert(key, merged);
            }
            Value::Object(acc_map)
        }
        (_, next) => next,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A fake model client that replays a scripted sequence of replies/errors.
    struct ScriptedClient {
        replies: RefCell<std::collections::VecDeque<Result<ModelReply, HarnessModelError>>>,
        seen_tools: RefCell<bool>,
    }

    impl ScriptedClient {
        fn new(replies: Vec<Result<ModelReply, HarnessModelError>>) -> Self {
            Self {
                replies: RefCell::new(replies.into_iter().collect()),
                seen_tools: RefCell::new(false),
            }
        }
    }

    impl HarnessModelClient for ScriptedClient {
        fn next(
            &self,
            _messages: &[ChatMessage],
            tools: &[ToolSpec],
        ) -> Result<ModelReply, HarnessModelError> {
            if !tools.is_empty() {
                *self.seen_tools.borrow_mut() = true;
            }
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("scripted client ran out of replies")
        }
    }

    /// A fake executor recording every brokered call.
    struct RecordingExecutor {
        calls: RefCell<Vec<ToolCall>>,
        outcome: ToolOutcome,
    }

    impl RecordingExecutor {
        fn new(outcome: ToolOutcome) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                outcome,
            }
        }
    }

    impl ToolExecutor for RecordingExecutor {
        fn execute(&self, call: &ToolCall) -> ToolOutcome {
            self.calls.borrow_mut().push(call.clone());
            self.outcome.clone()
        }
    }

    fn final_reply(text: &str) -> ModelReply {
        ModelReply {
            text: text.to_string(),
            tool_calls: Vec::new(),
            usage: json!({ "output_tokens": 5 }),
        }
    }

    fn tool_reply(id: &str, name: &str) -> ModelReply {
        ModelReply {
            text: String::new(),
            tool_calls: vec![ToolCall {
                id: id.to_string(),
                name: name.to_string(),
                arguments: json!({ "path": "README.md" }),
            }],
            usage: json!({ "output_tokens": 3 }),
        }
    }

    fn input(max_steps: usize) -> BrokeredTurnInput {
        BrokeredTurnInput {
            system: "you are a coding agent".to_string(),
            user: "read the readme".to_string(),
            tools: vec![ToolSpec {
                name: "read".to_string(),
                description: "read a file".to_string(),
                input_schema: json!({ "type": "object" }),
            }],
            max_steps,
            resume_from: Vec::new(),
            user_images: Vec::new(),
            user_media: Vec::new(),
            world: None,
            context_bundles: Vec::new(),
            pinned_skills: Vec::new(),
        }
    }

    #[test]
    fn managed_turn_projects_a_full_world_then_budget_diffs() {
        let http = ScriptedHttpClient::new(vec![
            Ok(tool_reply("call-1", "read")),
            Ok(final_reply("done")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "read".to_owned(),
        });
        let mut turn = input(4);
        turn.world = Some(
            WorldSnapshot::new("turn-1")
                .with_section(
                    "compute",
                    &crate::world_state::ComputeResources {
                        max_model_rounds: Some(4),
                        remaining_model_rounds: Some(4),
                        ..crate::world_state::ComputeResources::default()
                    },
                )
                .expect("world"),
        );
        let checkpoints = RefCell::new(Vec::<Vec<ChatMessage>>::new());
        let outcome = run_brokered_turn_http(
            &http,
            &exec,
            &turn,
            &mut |messages| checkpoints.borrow_mut().push(messages.to_vec()),
            &DummyHost,
            &NoopCompactor,
            None,
            None,
        );
        assert_eq!(outcome.status, TurnStatus::Completed);
        let projections: Vec<_> = outcome
            .observations
            .iter()
            .filter_map(|observation| match observation {
                LoopObservation::WorldProjected {
                    epoch, projection, ..
                } => Some((*epoch, projection.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(projections, vec![(0, "full"), (1, "update")]);
        let final_messages = checkpoints.borrow();
        let final_messages = final_messages.last().expect("checkpoint");
        assert!(final_messages.iter().any(|message| matches!(
            message,
            ChatMessage::System(text) if text.contains("<whip_world kind=\"full\"")
        )));
        assert!(final_messages.iter().any(|message| matches!(
            message,
            ChatMessage::System(text) if text.contains("<whip_world kind=\"update\"")
        )));
    }

    /// A no-op checkpoint for tests that do not exercise persistence.
    fn no_checkpoint() -> impl FnMut(&[ChatMessage]) {
        |_messages: &[ChatMessage]| {}
    }

    /// The `HttpModelClient` twin of `ScriptedClient`: it replays the same
    /// scripted replies, but through the build/parse seam so it drives the
    /// `BrokeredTurnMachine`.
    struct ScriptedHttpClient {
        replies: RefCell<std::collections::VecDeque<Result<ModelReply, HarnessModelError>>>,
    }

    type SharedCommandQueue = std::rc::Rc<RefCell<Vec<(TurnCommandKind, PendingTurnCommand)>>>;

    #[derive(Clone)]
    struct SharedCommands {
        pending: SharedCommandQueue,
    }

    impl SharedCommands {
        fn new() -> (Self, SharedCommandQueue) {
            let pending = std::rc::Rc::new(RefCell::new(Vec::new()));
            (
                Self {
                    pending: pending.clone(),
                },
                pending,
            )
        }
    }

    impl TurnCommandSource for SharedCommands {
        fn pending(&mut self, kind: TurnCommandKind) -> Result<Vec<PendingTurnCommand>, String> {
            Ok(self
                .pending
                .borrow()
                .iter()
                .filter(|(candidate, _)| *candidate == kind)
                .map(|(_, command)| command.clone())
                .collect())
        }
    }

    fn user_command(id: &str, text: &str) -> PendingTurnCommand {
        PendingTurnCommand {
            command_id: id.to_owned(),
            text: text.to_owned(),
            images: Vec::new(),
        }
    }

    impl ScriptedHttpClient {
        fn new(replies: Vec<Result<ModelReply, HarnessModelError>>) -> Self {
            Self {
                replies: RefCell::new(replies.into_iter().collect()),
            }
        }
    }

    impl HttpModelClient for ScriptedHttpClient {
        fn build_request(&self, _messages: &[ChatMessage], _tools: &[ToolSpec]) -> HttpRequest {
            HttpRequest {
                url: "https://fake/model".to_string(),
                headers: Vec::new(),
                body: json!({}),
            }
        }

        fn parse_response(
            &self,
            _response: Result<HttpResponse, TransportError>,
        ) -> Result<ModelReply, HarnessModelError> {
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("scripted http client ran out of replies")
        }
    }

    /// A host that answers any model request with an ignored 200 — the scripted
    /// client's `parse_response` supplies the reply. Stands in for the ureq/fetch
    /// transport.
    struct DummyHost;

    impl HostDriver for DummyHost {
        fn fulfill(&self, _request: &IoRequest) -> IoResult {
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: json!({}),
            }))
        }
    }

    /// Transient provider errors auto-retry (bounded); a persistent one still
    /// fails the turn after the retry budget (pi-conformance §2).
    #[test]
    fn brokered_turn_retries_transient_provider_errors() {
        // One overloaded error, then success: the turn completes.
        let http = ScriptedHttpClient::new(vec![
            Err(HarnessModelError::Provider("Overloaded".to_string())),
            Ok(final_reply("ok after retry")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_string(),
        });
        let out = run_brokered_turn_http(
            &http,
            &exec,
            &input(5),
            &mut |_msgs: &[ChatMessage]| {},
            &DummyHost,
            &NoopCompactor,
            None,
            None,
        );
        assert!(matches!(out.status, TurnStatus::Completed), "{out:?}");
        assert_eq!(out.summary, "ok after retry");

        // Persistently overloaded: fails after MAX_PROVIDER_RETRIES + 1 calls.
        let errors: Vec<Result<ModelReply, HarnessModelError>> = (0..4)
            .map(|_| Err(HarnessModelError::Provider("Overloaded".to_string())))
            .collect();
        let http = ScriptedHttpClient::new(errors);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_string(),
        });
        let out = run_brokered_turn_http(
            &http,
            &exec,
            &input(5),
            &mut |_msgs: &[ChatMessage]| {},
            &DummyHost,
            &NoopCompactor,
            None,
            None,
        );
        assert!(matches!(out.status, TurnStatus::Failed), "{out:?}");
        assert_eq!(out.summary, "provider error: Overloaded");
    }

    /// The final checkpoint of a completed turn includes the final assistant
    /// reply (pi-conformance §4) — the persisted conversation a
    /// `thread continue` follow-up seeds from ends on the answer.
    #[test]
    fn completed_turn_checkpoints_the_final_assistant_reply() {
        let http = ScriptedHttpClient::new(vec![
            Ok(tool_reply("c1", "read")),
            Ok(final_reply("the answer")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_string(),
        });
        let mut checkpoints: Vec<Value> = Vec::new();
        let out = run_brokered_turn_http(
            &http,
            &exec,
            &input(5),
            &mut |messages: &[ChatMessage]| checkpoints.push(chat_messages_to_json(messages)),
            &DummyHost,
            &NoopCompactor,
            None,
            None,
        );
        assert!(matches!(out.status, TurnStatus::Completed));
        let last = checkpoints.last().expect("checkpoints recorded");
        let rebuilt = chat_messages_from_json(last);
        assert!(
            matches!(
                rebuilt.last(),
                Some(ChatMessage::Assistant { text, tool_calls })
                    if text == "the answer" && tool_calls.is_empty()
            ),
            "final message is the assistant answer: {rebuilt:?}"
        );
    }

    /// Cooperative cancel (pi-conformance §3): a cancellation request arriving
    /// after the first tool round settles the turn as `Cancelled` before the
    /// next model call; the partial transcript was already checkpointed.
    #[test]
    fn brokered_turn_cancels_between_model_rounds() {
        use std::cell::Cell;
        let http = ScriptedHttpClient::new(vec![
            Ok(tool_reply("c1", "read")),
            Ok(final_reply("never reached")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_string(),
        });
        let cancelled = Cell::new(false);
        let probe = || cancelled.get();
        let mut checkpoints: Vec<Value> = Vec::new();
        let mut record = |messages: &[ChatMessage]| {
            // The cancellation request lands while the first tool executes:
            // flip the probe at the checkpoint AFTER the tool results append.
            checkpoints.push(chat_messages_to_json(messages));
            if checkpoints.len() >= 2 {
                cancelled.set(true);
            }
        };
        let out = run_brokered_turn_http(
            &http,
            &exec,
            &input(5),
            &mut record,
            &DummyHost,
            &NoopCompactor,
            Some(&probe),
            None,
        );
        assert!(
            matches!(out.status, TurnStatus::Cancelled),
            "cancelled between rounds: {:?}",
            out.status
        );
        assert_eq!(out.summary, "turn cancelled by request");
        assert_eq!(
            exec.calls.borrow().len(),
            1,
            "the in-flight tool settled before the check"
        );
        assert!(
            checkpoints.len() >= 2,
            "the partial transcript persisted before cancellation"
        );
    }

    /// A round whose stream the transport released early settles cancelled —
    /// however final the truncation happens to look — keeping the text that
    /// fully arrived as this round's durable assistant message, and never
    /// running a tool the truncation offered.
    #[test]
    fn released_stream_settles_cancelled_keeping_arrived_text() {
        let truncated = ModelReply {
            text: "the first half of an ans".to_string(),
            tool_calls: vec![ToolCall {
                id: "c1".to_string(),
                name: "read".to_string(),
                arguments: json!({ "path": "README.md" }),
            }],
            usage: json!({ "output_tokens": 2 }),
        };
        let http = ScriptedHttpClient::new(vec![Ok(truncated)]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "never".to_string(),
        });
        let released = || true;
        let mut checkpoints: Vec<Value> = Vec::new();
        let mut record =
            |messages: &[ChatMessage]| checkpoints.push(chat_messages_to_json(messages));
        let out = run_brokered_turn_http(
            &http,
            &exec,
            &input(5),
            &mut record,
            &DummyHost,
            &NoopCompactor,
            None,
            Some(&released),
        );
        assert!(
            matches!(out.status, TurnStatus::Cancelled),
            "a released stream is a truncation, not a terminal: {:?}",
            out.status
        );
        assert_eq!(out.summary, "turn cancelled by request");
        assert!(
            exec.calls.borrow().is_empty(),
            "no offered tool starts after a release"
        );
        let last = checkpoints.last().expect("the arrived text checkpointed");
        let rebuilt = chat_messages_from_json(last);
        match rebuilt.last().expect("assistant message recorded") {
            ChatMessage::Assistant { text, tool_calls } => {
                assert_eq!(text, "the first half of an ans");
                assert!(
                    tool_calls.is_empty(),
                    "a truncated round's tool offers are not recorded as calls"
                );
            }
            other => panic!("expected the assistant's partial text, got {other:?}"),
        }
    }

    /// A stream that completed naturally is a real terminal even when a
    /// cancellation request raced it: the release probe stays false, so
    /// final-terminal-wins holds exactly as specified.
    #[test]
    fn natural_final_still_wins_over_a_racing_cancel_request() {
        use std::cell::Cell;
        let http = ScriptedHttpClient::new(vec![Ok(final_reply("the whole answer"))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let cancelled = Cell::new(false);
        let probe = || cancelled.get();
        let released = || false;
        let seen = Cell::new(0u32);
        let mut record = |_: &[ChatMessage]| {
            // The seed checkpoint precedes the first model call; the request
            // lands while the (only) round is in flight — at the checkpoint
            // that records its reply — and the stream completes naturally.
            seen.set(seen.get() + 1);
            if seen.get() >= 2 {
                cancelled.set(true);
            }
        };
        let out = run_brokered_turn_http(
            &http,
            &exec,
            &input(5),
            &mut record,
            &DummyHost,
            &NoopCompactor,
            Some(&probe),
            Some(&released),
        );
        assert!(
            matches!(out.status, TurnStatus::Completed),
            "an unreleased natural terminal wins: {:?}",
            out.status
        );
        assert_eq!(out.summary, "the whole answer");
    }

    /// Drive the same scenario through both the imperative `run_brokered_loop`
    /// and the stepped `run_brokered_turn_http`, and assert every observable is
    /// identical: terminal, summary, step count, the in-turn observation stream,
    /// merged usage, the brokered tool calls, and the checkpoint sequence.
    fn assert_loops_equivalent(
        build_replies: impl Fn() -> Vec<Result<ModelReply, HarnessModelError>>,
        max_steps: usize,
    ) {
        let tool_outcome = ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_string(),
        };

        let client = ScriptedClient::new(build_replies());
        let exec1 = RecordingExecutor::new(tool_outcome.clone());
        let mut cp1: Vec<Value> = Vec::new();
        let out1 = {
            let mut record = |messages: &[ChatMessage]| cp1.push(chat_messages_to_json(messages));
            run_brokered_loop(&client, &exec1, &input(max_steps), &mut record)
        };

        let http = ScriptedHttpClient::new(build_replies());
        let exec2 = RecordingExecutor::new(tool_outcome);
        let mut cp2: Vec<Value> = Vec::new();
        let out2 = {
            let mut record = |messages: &[ChatMessage]| cp2.push(chat_messages_to_json(messages));
            run_brokered_turn_http(
                &http,
                &exec2,
                &input(max_steps),
                &mut record,
                &DummyHost,
                &NoopCompactor,
                None,
                None,
            )
        };

        assert_eq!(out1.status, out2.status, "status");
        assert_eq!(out1.summary, out2.summary, "summary");
        assert_eq!(out1.steps, out2.steps, "steps");
        assert_eq!(out1.observations, out2.observations, "observations");
        assert_eq!(out1.usage, out2.usage, "usage");
        assert_eq!(
            out1.last_input_tokens, out2.last_input_tokens,
            "context reading"
        );
        assert_eq!(*exec1.calls.borrow(), *exec2.calls.borrow(), "tool calls");
        assert_eq!(cp1, cp2, "checkpoint sequence");
    }

    #[test]
    fn brokered_turn_machine_matches_loop_completing_immediately() {
        assert_loops_equivalent(|| vec![Ok(final_reply("done"))], 8);
    }

    /// The settled context reading is the LAST main reply's prompt size, while
    /// the usage meter sums every call — the two must not be conflated, in
    /// either loop. This is the property the whole gauge rests on: a tool-loop
    /// turn's summed input overcounts the window by the number of rounds.
    #[test]
    fn settled_context_reading_is_the_last_reply_not_the_sum() {
        let replies = || {
            vec![
                Ok(ModelReply {
                    text: String::new(),
                    tool_calls: vec![ToolCall {
                        id: "call-1".to_owned(),
                        name: "read".to_owned(),
                        arguments: json!({ "path": "README.md" }),
                    }],
                    usage: json!({ "input_tokens": 100, "output_tokens": 3 }),
                }),
                Ok(ModelReply {
                    text: "done".to_owned(),
                    tool_calls: Vec::new(),
                    usage: json!({ "input_tokens": 130, "output_tokens": 5 }),
                }),
            ]
        };
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_owned(),
        });
        for outcome in [
            run_brokered_loop(
                &ScriptedClient::new(replies()),
                &exec,
                &input(8),
                &mut no_checkpoint(),
            ),
            run_brokered_turn_http(
                &ScriptedHttpClient::new(replies()),
                &exec,
                &input(8),
                &mut no_checkpoint(),
                &DummyHost,
                &NoopCompactor,
                None,
                None,
            ),
        ] {
            assert_eq!(outcome.status, TurnStatus::Completed);
            assert_eq!(outcome.usage["input_tokens"], json!(230), "meter sums");
            assert_eq!(outcome.last_input_tokens, 130, "gauge reads the last");
        }
    }

    /// The terminal stamp: rides the usage object under a key no provider
    /// emits, and an unreported reading (0) stamps nothing rather than a lie.
    #[test]
    fn usage_with_context_stamps_only_a_real_reading() {
        let usage = json!({ "input_tokens": 230, "output_tokens": 8 });
        assert_eq!(
            usage_with_context(&usage, 130),
            json!({ "input_tokens": 230, "output_tokens": 8, "last_input_tokens": 130 })
        );
        assert_eq!(usage_with_context(&usage, 0), usage);
        assert_eq!(
            usage_with_context(&Value::Null, 130),
            json!({ "last_input_tokens": 130 })
        );
    }

    #[test]
    fn provider_cannot_dispatch_a_tool_that_was_not_offered() {
        let replies = vec![
            Ok(tool_reply("call-1", "write")),
            Ok(final_reply("write refused")),
        ];
        let client = ScriptedClient::new(replies);
        let executor = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "must not run".to_owned(),
        });
        let outcome = run_brokered_loop(&client, &executor, &input(8), &mut no_checkpoint());

        assert_eq!(outcome.status, TurnStatus::Completed);
        assert!(executor.calls.borrow().is_empty());
        assert!(outcome.observations.iter().any(|observation| matches!(
            observation,
            LoopObservation::ToolResult {
                name,
                status: ToolStatus::Error,
                ..
            } if name == "write"
        )));
    }

    /// The durable-object eviction test (DR-0033 Decision 3): drive a multi-round
    /// turn where the machine is snapshotted, JSON round-tripped (proving it fully
    /// serializes), and reconstructed from that snapshot before EVERY step — as if
    /// the DO were evicted between each provider `fetch`. The final outcome must be
    /// identical to an uninterrupted run: eviction mid-turn loses nothing.
    #[test]
    fn brokered_turn_survives_eviction_between_every_round() {
        let replies = || vec![Ok(tool_reply("c1", "read")), Ok(final_reply("done"))];
        let outcome_of = ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_string(),
        };

        // Reference: one uninterrupted stepped run.
        let http = ScriptedHttpClient::new(replies());
        let exec = RecordingExecutor::new(outcome_of.clone());
        let reference = {
            let mut record = |_: &[ChatMessage]| {};
            run_brokered_turn_http(
                &http,
                &exec,
                &input(8),
                &mut record,
                &DummyHost,
                &NoopCompactor,
                None,
                None,
            )
        };

        // Eviction-simulated: rebuild the machine from a serialized snapshot each
        // round. The scripted client/executor persist their queues across rebuilds
        // (the store would); only the machine is torn down and restored.
        let http2 = ScriptedHttpClient::new(replies());
        let exec2 = RecordingExecutor::new(outcome_of);
        let input2 = input(8);
        let host = DummyHost;
        let mut snapshot: Option<BrokeredTurnSnapshot> = None;
        let mut incoming: Option<IoResult> = None;
        let mut rebuilds = 0usize;
        let outcome = loop {
            let mut discard = |_: &[ChatMessage]| {};
            let mut machine = match snapshot.take() {
                None => {
                    BrokeredTurnMachine::new(&http2, &exec2, &input2, &mut discard, &NoopCompactor)
                }
                Some(snap) => {
                    let json = serde_json::to_string(&snap).expect("snapshot serializes");
                    let restored: BrokeredTurnSnapshot =
                        serde_json::from_str(&json).expect("snapshot deserializes");
                    rebuilds += 1;
                    BrokeredTurnMachine::restore(
                        &http2,
                        &exec2,
                        &input2,
                        &mut discard,
                        &NoopCompactor,
                        restored,
                    )
                }
            };
            match machine.step(incoming.take()) {
                Outcome::NeedsIo(request) => {
                    incoming = Some(host.fulfill(&request));
                    snapshot = Some(machine.snapshot());
                }
                Outcome::Settle(out) => break out,
            }
        };

        assert!(rebuilds >= 2, "the turn was rebuilt across multiple rounds");
        assert_eq!(outcome.status, reference.status, "status");
        assert_eq!(outcome.summary, reference.summary, "summary");
        assert_eq!(outcome.steps, reference.steps, "steps");
        assert_eq!(outcome.observations, reference.observations, "observations");
        assert_eq!(outcome.usage, reference.usage, "usage");
        assert_eq!(*exec.calls.borrow(), *exec2.calls.borrow(), "tool calls");
    }

    #[test]
    fn steering_joins_the_live_turn_after_the_current_tool_batch() {
        let http = ScriptedHttpClient::new(vec![
            Ok(tool_reply("c1", "read")),
            Ok(final_reply("redirected")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".to_owned(),
        });
        let turn_input = input(8);
        let mut checkpoint = |_: &[ChatMessage]| {};
        let (mut commands, control) = SharedCommands::new();
        let mut machine =
            BrokeredTurnMachine::new(&http, &exec, &turn_input, &mut checkpoint, &NoopCompactor)
                .with_command_source(&mut commands);

        assert!(matches!(machine.step(None), Outcome::NeedsIo(_)));
        control.borrow_mut().push((
            TurnCommandKind::Steer,
            user_command("steer-1", "change direction"),
        ));
        assert!(matches!(
            machine.step(Some(DummyHost.fulfill(&IoRequest::Http(HttpRequest {
                url: "https://fake/model".to_owned(),
                headers: Vec::new(),
                body: json!({}),
            })))),
            Outcome::NeedsIo(_)
        ));
        let snapshot = machine.snapshot();
        assert!(snapshot.applied_command_ids.contains("steer-1"));
        assert!(matches!(
            snapshot.messages.last(),
            Some(ChatMessage::User { text, .. }) if text == "change direction"
        ));
        assert!(matches!(
            machine.step(Some(DummyHost.fulfill(&IoRequest::Http(HttpRequest {
                url: "https://fake/model".to_owned(),
                headers: Vec::new(),
                body: json!({}),
            })))),
            Outcome::Settle(BrokeredTurnOutcome {
                status: TurnStatus::Completed,
                ..
            })
        ));
    }

    #[test]
    fn follow_up_continues_only_when_the_agent_would_finish() {
        let http = ScriptedHttpClient::new(vec![
            Ok(final_reply("first answer")),
            Ok(final_reply("second answer")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let turn_input = input(8);
        let mut checkpoint = |_: &[ChatMessage]| {};
        let (mut commands, control) = SharedCommands::new();
        let mut machine =
            BrokeredTurnMachine::new(&http, &exec, &turn_input, &mut checkpoint, &NoopCompactor)
                .with_command_source(&mut commands);

        assert!(matches!(machine.step(None), Outcome::NeedsIo(_)));
        control.borrow_mut().push((
            TurnCommandKind::FollowUp,
            user_command("follow-1", "one more thing"),
        ));
        assert!(matches!(
            machine.step(Some(DummyHost.fulfill(&IoRequest::Http(HttpRequest {
                url: "https://fake/model".to_owned(),
                headers: Vec::new(),
                body: json!({}),
            })))),
            Outcome::NeedsIo(_)
        ));
        let outcome = match machine.step(Some(DummyHost.fulfill(&IoRequest::Http(HttpRequest {
            url: "https://fake/model".to_owned(),
            headers: Vec::new(),
            body: json!({}),
        })))) {
            Outcome::Settle(outcome) => outcome,
            Outcome::NeedsIo(_) => panic!("follow-up should settle after its final answer"),
        };
        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(outcome.summary, "second answer");
        assert_eq!(outcome.steps, 2);
    }

    #[test]
    fn manual_compaction_uses_the_selected_compactor_once_at_a_boundary() {
        let http = ScriptedHttpClient::new(vec![Ok(final_reply("done"))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let mut turn_input = input(8);
        turn_input.resume_from = vec![
            ChatMessage::System("system".to_owned()),
            ChatMessage::user_text("task"),
            ChatMessage::Assistant {
                text: "old-a".repeat(20),
                tool_calls: Vec::new(),
            },
            ChatMessage::user_text("old-b".repeat(20)),
            ChatMessage::user_text("recent"),
        ];
        turn_input.world = Some(
            WorldSnapshot::new("turn-compact")
                .with_section("environment", &serde_json::json!({ "timezone": "UTC" }))
                .expect("world"),
        );
        let mut checkpoint = |_: &[ChatMessage]| {};
        let (mut commands, control) = SharedCommands::new();
        control
            .borrow_mut()
            .push((TurnCommandKind::Compact, user_command("compact-1", "")));
        let compactor = HardResetCompactor::new(9, 2, 10);
        let mut machine =
            BrokeredTurnMachine::new(&http, &exec, &turn_input, &mut checkpoint, &compactor)
                .with_command_source(&mut commands);

        assert!(matches!(machine.step(None), Outcome::NeedsIo(_)));
        let snapshot = machine.snapshot();
        assert!(snapshot.applied_command_ids.contains("compact-1"));
        assert_eq!(snapshot.compaction_epoch, 1);
        assert!(snapshot.messages.len() < turn_input.resume_from.len());
        assert!(snapshot.messages.iter().any(|message| matches!(
            message,
            ChatMessage::System(text)
                if text.contains("<whip_world kind=\"full\"")
                    && text.contains("turn-compact")
        )));
        let outcome = match machine.step(Some(DummyHost.fulfill(&IoRequest::Http(HttpRequest {
            url: "https://fake/model".to_owned(),
            headers: Vec::new(),
            body: json!({}),
        })))) {
            Outcome::Settle(outcome) => outcome,
            Outcome::NeedsIo(_) => panic!("final reply should settle"),
        };
        assert_eq!(
            outcome
                .observations
                .iter()
                .filter(|observation| matches!(observation, LoopObservation::Compacted { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn brokered_turn_machine_matches_loop_tool_then_final() {
        assert_loops_equivalent(
            || vec![Ok(tool_reply("c1", "read")), Ok(final_reply("done"))],
            8,
        );
    }

    #[test]
    fn brokered_turn_machine_matches_loop_on_model_error() {
        // Transport errors are retryable (pi-conformance §2): both loops burn
        // the full retry budget, then fail identically.
        assert_loops_equivalent(
            || {
                (0..4)
                    .map(|_| Err(HarnessModelError::Transport("boom".to_string())))
                    .collect()
            },
            8,
        );
    }

    #[test]
    fn brokered_turn_machine_matches_loop_on_timeout_error() {
        assert_loops_equivalent(
            || {
                vec![
                    Ok(tool_reply("c1", "read")),
                    Err(HarnessModelError::Timeout),
                ]
            },
            8,
        );
    }

    #[test]
    fn brokered_turn_machine_matches_loop_hitting_step_bound() {
        // Never final within the bound → TimedOut after max_steps model calls.
        assert_loops_equivalent(
            || vec![Ok(tool_reply("c1", "read")), Ok(tool_reply("c2", "read"))],
            2,
        );
    }

    #[test]
    fn completes_without_tools() {
        let client = ScriptedClient::new(vec![Ok(final_reply("done"))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let outcome = run_brokered_loop(&client, &exec, &input(8), &mut no_checkpoint());
        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(outcome.summary, "done");
        assert_eq!(outcome.steps, 1);
        assert!(exec.calls.borrow().is_empty());
        // One model_request observation, no tool observations.
        assert_eq!(
            outcome.observations,
            vec![LoopObservation::ModelRequest { step: 0 }]
        );
        // The model was offered the tools.
        assert!(*client.seen_tools.borrow());
    }

    #[test]
    fn brokers_a_tool_then_completes() {
        let client = ScriptedClient::new(vec![
            Ok(tool_reply("call_1", "read")),
            Ok(final_reply("the readme says hi")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "hi".to_string(),
        });
        let outcome = run_brokered_loop(&client, &exec, &input(8), &mut no_checkpoint());

        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(outcome.summary, "the readme says hi");
        assert_eq!(outcome.steps, 2);

        // Brokering (I1): the executor ran exactly the requested tool.
        let calls = exec.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "read");

        // The observation stream: a tool_result is always preceded by its
        // tool_requested, and both sit between model_requests.
        assert_eq!(
            outcome.observations,
            vec![
                LoopObservation::ModelRequest { step: 0 },
                LoopObservation::ToolRequested {
                    call_id: "call_1".to_string(),
                    name: "read".to_string(),
                },
                LoopObservation::ToolResult {
                    call_id: "call_1".to_string(),
                    name: "read".to_string(),
                    status: ToolStatus::Ok,
                },
                LoopObservation::ModelRequest { step: 1 },
            ]
        );
    }

    #[test]
    fn brokering_invariant_every_result_follows_a_request() {
        // Two tool calls in one reply, then finish: each result must be preceded
        // by its request, and every result corresponds to an executor call.
        let client = ScriptedClient::new(vec![
            Ok(ModelReply {
                text: String::new(),
                tool_calls: vec![
                    ToolCall {
                        id: "a".into(),
                        name: "read".into(),
                        arguments: json!({}),
                    },
                    ToolCall {
                        id: "b".into(),
                        name: "ls".into(),
                        arguments: json!({}),
                    },
                ],
                usage: Value::Null,
            }),
            Ok(final_reply("ok")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let mut turn = input(8);
        turn.tools.push(ToolSpec {
            name: "ls".to_owned(),
            description: "list files".to_owned(),
            input_schema: json!({"type": "object"}),
        });
        let outcome = run_brokered_loop(&client, &exec, &turn, &mut no_checkpoint());
        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(exec.calls.borrow().len(), 2);

        let mut pending: std::collections::HashSet<String> = std::collections::HashSet::new();
        for obs in &outcome.observations {
            match obs {
                LoopObservation::ToolRequested { call_id, .. } => {
                    pending.insert(call_id.clone());
                }
                LoopObservation::ToolResult { call_id, .. } => {
                    assert!(
                        pending.contains(call_id),
                        "tool_result for {call_id} had no preceding tool_requested"
                    );
                }
                LoopObservation::ModelRequest { .. }
                | LoopObservation::Compacted { .. }
                | LoopObservation::UserCommandApplied { .. }
                | LoopObservation::WorldProjected { .. }
                | LoopObservation::MediaNormalized { .. }
                | LoopObservation::ToolOutputTruncated { .. }
                | LoopObservation::RecallRequested { .. } => {}
            }
        }
    }

    #[test]
    fn provider_error_fails_the_turn() {
        let client =
            ScriptedClient::new(vec![Err(HarnessModelError::Provider("usage limit".into()))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let outcome = run_brokered_loop(&client, &exec, &input(8), &mut no_checkpoint());
        assert_eq!(outcome.status, TurnStatus::Failed);
        assert!(outcome.summary.contains("usage limit"));
    }

    #[test]
    fn timeout_error_times_out_the_turn() {
        let client = ScriptedClient::new(vec![Err(HarnessModelError::Timeout)]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let outcome = run_brokered_loop(&client, &exec, &input(8), &mut no_checkpoint());
        assert_eq!(outcome.status, TurnStatus::TimedOut);
    }

    #[test]
    fn exhausting_steps_times_out() {
        // The model keeps requesting tools forever; the step bound must stop it.
        let client = ScriptedClient::new(vec![
            Ok(tool_reply("c1", "read")),
            Ok(tool_reply("c2", "read")),
        ]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let outcome = run_brokered_loop(&client, &exec, &input(2), &mut no_checkpoint());
        assert_eq!(outcome.status, TurnStatus::TimedOut);
        assert_eq!(outcome.steps, 2);
    }

    #[test]
    fn resume_continues_from_persisted_transcript_without_rerunning_tools() {
        let client = ScriptedClient::new(vec![Ok(final_reply("resumed and done"))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let mut input = input(8);
        input.resume_from = vec![
            ChatMessage::System("s".into()),
            ChatMessage::user_text("u"),
            ChatMessage::Assistant {
                text: String::new(),
                tool_calls: vec![ToolCall {
                    id: "1".into(),
                    name: "read".into(),
                    arguments: json!({}),
                }],
            },
            ChatMessage::ToolResults(vec![ToolResultMsg {
                tool_call_id: "1".into(),
                tool_name: "read".into(),
                content: "x".into(),
                is_error: false,
            }]),
        ];
        let outcome = run_brokered_loop(&client, &exec, &input, &mut no_checkpoint());
        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(outcome.summary, "resumed and done");
        // The already-applied tool is NOT re-run on resume.
        assert!(exec.calls.borrow().is_empty());
    }

    #[test]
    fn resume_drops_a_dangling_tool_call() {
        let messages = vec![
            ChatMessage::System("s".into()),
            ChatMessage::Assistant {
                text: String::new(),
                tool_calls: vec![ToolCall {
                    id: "1".into(),
                    name: "read".into(),
                    arguments: json!({}),
                }],
            },
        ];
        let out = sanitize_resume_messages(messages);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], ChatMessage::System(_)));
    }

    #[test]
    fn transcript_json_round_trips() {
        let messages = vec![
            ChatMessage::System("s".into()),
            ChatMessage::user_text("u"),
            ChatMessage::Assistant {
                text: "t".into(),
                tool_calls: vec![ToolCall {
                    id: "1".into(),
                    name: "read".into(),
                    arguments: json!({ "path": "a" }),
                }],
            },
            ChatMessage::ToolResults(vec![ToolResultMsg {
                tool_call_id: "1".into(),
                tool_name: "read".into(),
                content: "c".into(),
                is_error: false,
            }]),
        ];
        let json = chat_messages_to_json(&messages);
        assert_eq!(chat_messages_from_json(&json), messages);
    }

    #[test]
    fn user_transcript_json_keeps_the_pre_images_wire_shape() {
        // Serde compatibility (pi-conformance §6): a text-only user entry
        // serializes exactly as it did before images existed...
        let json = chat_messages_to_json(&[ChatMessage::user_text("u")]);
        assert_eq!(json, json!([{ "role": "user", "text": "u" }]));
        // ...and an old-format persisted transcript (no `images` key) parses
        // with images empty, so pre-images transcripts round-trip.
        let old = json!([
            { "role": "system", "text": "s" },
            { "role": "user", "text": "hello" },
        ]);
        assert_eq!(
            chat_messages_from_json(&old),
            vec![
                ChatMessage::System("s".into()),
                ChatMessage::User {
                    text: "hello".into(),
                    images: Vec::new(),
                },
            ]
        );
    }

    #[test]
    fn transcript_json_round_trips_user_images() {
        let messages = vec![ChatMessage::User {
            text: "what is in this picture?".into(),
            images: vec![ImageBlock {
                media_type: "image/png".into(),
                data_base64: "aGVsbG8=".into(),
            }],
        }];
        let json = chat_messages_to_json(&messages);
        assert_eq!(json[0]["images"][0]["media_type"], json!("image/png"));
        assert_eq!(json[0]["images"][0]["data_base64"], json!("aGVsbG8="));
        assert_eq!(chat_messages_from_json(&json), messages);
    }

    #[test]
    fn turn_input_images_seed_the_first_user_message() {
        // pi-conformance §6: both the reference loop and the stepped machine
        // seed the turn's images into the first User message.
        let mut input = input(4);
        input.user_images = vec![ImageBlock {
            media_type: "image/jpeg".into(),
            data_base64: "QUJD".into(),
        }];
        let expected_seed = ChatMessage::User {
            text: input.user.clone(),
            images: input.user_images.clone(),
        };

        let client = ScriptedClient::new(vec![Ok(final_reply("done"))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "R".into(),
        });
        let mut loop_seed: Vec<ChatMessage> = Vec::new();
        let mut record_loop = |messages: &[ChatMessage]| {
            if loop_seed.is_empty() {
                loop_seed = messages.to_vec();
            }
        };
        run_brokered_loop(&client, &exec, &input, &mut record_loop);
        assert_eq!(loop_seed[1], expected_seed);

        let http = ScriptedHttpClient::new(vec![Ok(final_reply("done"))]);
        let mut machine_seed: Vec<ChatMessage> = Vec::new();
        let mut record_machine = |messages: &[ChatMessage]| {
            if machine_seed.is_empty() {
                machine_seed = messages.to_vec();
            }
        };
        run_brokered_turn_http(
            &http,
            &exec,
            &input,
            &mut record_machine,
            &DummyHost,
            &NoopCompactor,
            None,
            None,
        );
        assert_eq!(machine_seed[1], expected_seed);
    }

    #[test]
    fn unsupported_media_is_model_visible_and_evidenced_instead_of_dropped() {
        let mut turn = input(2);
        turn.user_media = vec![MediaInput {
            artifact_ref: "artifact:audio-1".to_owned(),
            media_type: "audio/wav".to_owned(),
            data_base64: Some("UklGRg==".to_owned()),
            metadata: std::collections::BTreeMap::new(),
        }];
        let http = ScriptedHttpClient::new(vec![Ok(final_reply("ack"))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let transcript = RefCell::new(Vec::new());
        let outcome = run_brokered_turn_http(
            &http,
            &exec,
            &turn,
            &mut |messages| *transcript.borrow_mut() = messages.to_vec(),
            &DummyHost,
            &NoopCompactor,
            None,
            None,
        );
        assert_eq!(outcome.status, TurnStatus::Completed);
        assert!(transcript.borrow().iter().any(|message| matches!(
            message,
            ChatMessage::User { text, .. }
                if text.contains("Unsupported media")
                    && text.contains("artifact:audio-1")
                    && text.contains("audio/wav")
        )));
        assert!(outcome.observations.iter().any(|observation| matches!(
            observation,
            LoopObservation::MediaNormalized { artifact_ref, normalization, .. }
                if artifact_ref == "artifact:audio-1" && normalization == "unsupported_explicit"
        )));
    }

    #[test]
    fn checkpoint_is_invoked_during_the_loop() {
        let client =
            ScriptedClient::new(vec![Ok(tool_reply("c1", "read")), Ok(final_reply("done"))]);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "r".into(),
        });
        let count = std::cell::Cell::new(0usize);
        let mut checkpoint = |_messages: &[ChatMessage]| count.set(count.get() + 1);
        let outcome = run_brokered_loop(&client, &exec, &input(8), &mut checkpoint);
        assert_eq!(outcome.status, TurnStatus::Completed);
        // Once for the initial context, once after the tool round.
        assert!(count.get() >= 2, "checkpoint should fire per step");
    }

    #[test]
    fn merge_usage_sums_shared_numeric_keys() {
        let merged = merge_usage(
            json!({ "input_tokens": 10, "output_tokens": 5 }),
            json!({ "input_tokens": 3, "output_tokens": 7 }),
        );
        assert_eq!(merged, json!({ "input_tokens": 13, "output_tokens": 12 }));
    }

    /// Cached tokens live one level down on both wires, so a turn priced from a
    /// replaced details object bills every round's input but only the last
    /// round's discount.
    #[test]
    fn merge_usage_sums_nested_token_details() {
        let merged = merge_usage(
            json!({
                "prompt_tokens": 10_000,
                "completion_tokens": 5,
                "prompt_tokens_details": { "cached_tokens": 8_000 },
            }),
            json!({
                "prompt_tokens": 12_000,
                "completion_tokens": 7,
                "prompt_tokens_details": { "cached_tokens": 11_000 },
            }),
        );
        assert_eq!(
            merged,
            json!({
                "prompt_tokens": 22_000,
                "completion_tokens": 12,
                "prompt_tokens_details": { "cached_tokens": 19_000 },
            })
        );
    }

    // --- Phase 4 Layer B: conversation compaction --------------------------

    fn stats(last_input_tokens: u64, window: u64, message_count: usize) -> CompactionStats {
        CompactionStats {
            last_input_tokens,
            context_window: window,
            message_count,
        }
    }

    #[test]
    fn trigger_fires_only_near_the_window_and_above_the_message_floor() {
        let c = TurnSummarizingCompactor::default(); // 90%, floor 6
                                                     // Below 90% real usage: no compaction.
        assert!(!c.should_compact(&stats(179_000, 200_000, 40)));
        // At/above 90% with enough messages: compaction.
        assert!(c.should_compact(&stats(181_000, 200_000, 40)));
        // At the threshold but too few messages: no compaction (nothing to fold).
        assert!(!c.should_compact(&stats(181_000, 200_000, 3)));
        // The 0-token starting/just-compacted signal never fires.
        assert!(!c.should_compact(&stats(0, 200_000, 40)));
    }

    #[test]
    fn truncation_and_recall_observations_capture_policy_and_ranges() {
        let native = "head\n[full `read` output: 90000 bytes, id sha256:abc — call `recall`]";
        assert_eq!(
            truncation_metadata(native),
            Some((90_000, Some("sha256:abc".to_owned())))
        );
        let hosted =
            "head\n[... 500 of 1000 bytes elided; recall id=blob123 for the full output ...]\ntail";
        assert_eq!(
            truncation_metadata(hosted),
            Some((1_000, Some("blob123".to_owned())))
        );
        assert!(matches!(
            recall_request_observation(&ToolCall {
                id: "call".to_owned(),
                name: "recall".to_owned(),
                arguments: json!({"id": "blob123", "offset": 20, "limit": 40}),
            }),
            Some(LoopObservation::RecallRequested {
                offset: Some(20),
                limit: Some(40),
                ..
            })
        ));
    }

    #[test]
    fn plan_folds_the_middle_keeping_anchors_and_a_verbatim_tail() {
        // A tiny tail budget forces a real fold region (only the last message fits
        // in the tail); the System + first User are anchors.
        let c = TurnSummarizingCompactor::new(9, 2, 10);
        let transcript = vec![
            ChatMessage::System("sys".into()),
            ChatMessage::user_text("task"),
            ChatMessage::Assistant {
                text: "middle-1".into(),
                tool_calls: Vec::new(),
            },
            ChatMessage::Assistant {
                text: "middle-2".into(),
                tool_calls: Vec::new(),
            },
            ChatMessage::user_text("recent"),
        ];
        match c.plan(&transcript, &stats(950, 1000, transcript.len())) {
            CompactionOutcome::NeedsModel(req) => {
                assert_eq!(req.anchors, transcript[..2].to_vec(), "System + first User");
                assert_eq!(req.keep_tail, vec![transcript[4].clone()], "verbatim tail");
                // The summarization request offers no tools and carries the fold region.
                assert_eq!(req.request_messages.len(), 2);
                assert!(matches!(req.request_messages[0], ChatMessage::System(_)));
                // assemble rebuilds anchors + handoff + tail.
                let rebuilt = c.assemble(&req, "HANDOFF");
                assert_eq!(rebuilt[0], transcript[0]);
                assert_eq!(rebuilt[1], transcript[1]);
                assert!(
                    matches!(&rebuilt[2], ChatMessage::User { text: t, .. } if t.contains("HANDOFF"))
                );
                assert_eq!(*rebuilt.last().expect("rebuilt tail"), transcript[4]);
            }
            CompactionOutcome::Deterministic(_) => panic!("expected a summarization round"),
        }
    }

    /// A scripted `HttpModelClient` with a small context window and a per-round
    /// record of whether tools were offered — so a test can force compaction and
    /// observe that the interleaved summarization round is a no-tools model call.
    struct CompactingHttpClient {
        replies: RefCell<std::collections::VecDeque<Result<ModelReply, HarnessModelError>>>,
        tools_seen: RefCell<Vec<bool>>,
        window: u64,
    }

    impl CompactingHttpClient {
        fn new(replies: Vec<Result<ModelReply, HarnessModelError>>, window: u64) -> Self {
            Self {
                replies: RefCell::new(replies.into_iter().collect()),
                tools_seen: RefCell::new(Vec::new()),
                window,
            }
        }
    }

    impl HttpModelClient for CompactingHttpClient {
        fn build_request(&self, _messages: &[ChatMessage], tools: &[ToolSpec]) -> HttpRequest {
            self.tools_seen.borrow_mut().push(!tools.is_empty());
            HttpRequest {
                url: "https://fake/model".to_string(),
                headers: Vec::new(),
                body: json!({}),
            }
        }
        fn parse_response(
            &self,
            _response: Result<HttpResponse, TransportError>,
        ) -> Result<ModelReply, HarnessModelError> {
            self.replies
                .borrow_mut()
                .pop_front()
                .expect("compacting client ran out of replies")
        }
        fn context_window(&self) -> u64 {
            self.window
        }
    }

    #[test]
    fn a_triggered_turn_interleaves_a_no_tools_summarization_round() {
        // Round 1 (main): a tool call whose input usage crosses 90% of the tiny
        // window → arms compaction. Round 2 (summary): the handoff text. Round 3
        // (main): the final answer.
        let replies = || {
            vec![
                Ok(ModelReply {
                    text: String::new(),
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "read".into(),
                        arguments: json!({ "path": "README.md" }),
                    }],
                    usage: json!({ "input_tokens": 950, "output_tokens": 1 }),
                }),
                Ok(final_reply("STRUCTURED HANDOFF")),
                Ok(final_reply("the answer")),
            ]
        };
        let client = CompactingHttpClient::new(replies(), 1000);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "file body".to_string(),
        });
        // Small message floor + tiny tail budget so the single tool round both
        // clears the floor and leaves a fold region.
        let compactor = TurnSummarizingCompactor::new(9, 2, 10);
        let mut folded_seen = false;
        let outcome = {
            let mut record = |messages: &[ChatMessage]| {
                if messages.iter().any(
                    |m| matches!(m, ChatMessage::User { text: t, .. } if t.contains("compacted to a handoff")),
                ) {
                    folded_seen = true;
                }
            };
            run_brokered_turn_http(
                &client,
                &exec,
                &input(8),
                &mut record,
                &DummyHost,
                &compactor,
                None,
                None,
            )
        };

        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(outcome.summary, "the answer");
        // The tool ran once (the main round), and the folded transcript was persisted.
        assert_eq!(exec.calls.borrow().len(), 1);
        assert!(
            folded_seen,
            "a checkpoint captured the folded handoff prefix"
        );
        // Three model rounds were built: main, summarization (no tools), main.
        assert_eq!(*client.tools_seen.borrow(), vec![true, false, true]);
        // The compaction is recorded once as evidence (the `context.compaction`
        // observation the kernel turns into an evidence artifact).
        let compactions: Vec<_> = outcome
            .observations
            .iter()
            .filter(|o| matches!(o, LoopObservation::Compacted { .. }))
            .collect();
        assert_eq!(compactions.len(), 1, "recorded exactly once");
        assert!(matches!(
            compactions[0],
            LoopObservation::Compacted { epoch: 1, .. }
        ));
    }

    #[test]
    fn a_compacted_transcript_is_reused_on_replay_not_resummarized() {
        // First: a turn that compacts, capturing the folded transcript from the
        // checkpoint (what the durable log would hold on a crash).
        let replies = vec![
            Ok(ModelReply {
                text: String::new(),
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "read".into(),
                    arguments: json!({ "path": "README.md" }),
                }],
                usage: json!({ "input_tokens": 950, "output_tokens": 1 }),
            }),
            Ok(final_reply("STRUCTURED HANDOFF")),
            Ok(final_reply("first answer")),
        ];
        let client = CompactingHttpClient::new(replies, 1000);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "file body".to_string(),
        });
        let compactor = TurnSummarizingCompactor::new(9, 2, 10);
        let mut folded: Option<Vec<ChatMessage>> = None;
        {
            let mut record = |messages: &[ChatMessage]| {
                if messages.iter().any(
                    |m| matches!(m, ChatMessage::User { text: t, .. } if t.contains("compacted to a handoff")),
                ) {
                    folded = Some(messages.to_vec());
                }
            };
            run_brokered_turn_http(
                &client,
                &exec,
                &input(8),
                &mut record,
                &DummyHost,
                &compactor,
                None,
                None,
            );
        }
        let folded = folded.expect("a compaction occurred");

        // Resume from the folded transcript. The handoff summary is already in it,
        // so a fresh turn must NOT re-summarize — only one MAIN round to finish. The
        // single-reply client would panic ("ran out of replies") if a second
        // (summarization) round were issued, so reaching the answer proves the
        // recorded summary is reused, never regenerated (Decision 7).
        let mut resumed_input = input(8);
        resumed_input.resume_from = folded;
        let resumed_client =
            CompactingHttpClient::new(vec![Ok(final_reply("resumed answer"))], 1000);
        let resumed_exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: String::new(),
        });
        let outcome = {
            let mut record = |_: &[ChatMessage]| {};
            run_brokered_turn_http(
                &resumed_client,
                &resumed_exec,
                &resumed_input,
                &mut record,
                &DummyHost,
                &compactor,
                None,
                None,
            )
        };
        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(outcome.summary, "resumed answer");
        // Exactly one model round, and it offered tools (a MAIN call) — no
        // summarization round was issued on replay.
        assert_eq!(*resumed_client.tools_seen.borrow(), vec![true]);
        assert!(
            !outcome
                .observations
                .iter()
                .any(|o| matches!(o, LoopObservation::Compacted { .. })),
            "resume does not re-compact"
        );
    }

    #[test]
    fn hard_reset_drops_the_middle_keeping_anchors_and_tail_with_no_model_round() {
        let c = HardResetCompactor::new(9, 2, 10);
        let transcript = vec![
            ChatMessage::System("sys".into()),
            ChatMessage::user_text("task"),
            ChatMessage::Assistant {
                text: "middle-1".into(),
                tool_calls: Vec::new(),
            },
            ChatMessage::Assistant {
                text: "middle-2".into(),
                tool_calls: Vec::new(),
            },
            ChatMessage::user_text("recent"),
        ];
        assert!(c.should_compact(&stats(950, 1000, transcript.len())));
        match c.plan(&transcript, &stats(950, 1000, transcript.len())) {
            CompactionOutcome::Deterministic(out) => {
                // Anchors + tail only; the middle is gone; no NeedsModel round.
                assert_eq!(out[0], transcript[0]);
                assert_eq!(out[1], transcript[1]);
                assert_eq!(*out.last().expect("tail"), transcript[4]);
                assert!(out.len() < transcript.len(), "middle dropped");
                assert!(
                    !out.iter().any(
                        |m| matches!(m, ChatMessage::Assistant { text, .. } if text == "middle-1")
                    ),
                    "the folded middle is discarded, not summarized"
                );
            }
            CompactionOutcome::NeedsModel(_) => panic!("hard-reset never needs a model"),
        }
    }

    #[test]
    fn tool_result_compactor_elides_captured_results_to_refs_keeping_structure() {
        let c = ToolResultCompactor::new(9, 2, 10);
        // A captured tool result carries a recall footer; the compactor elides its
        // body to a ref while keeping the assistant turn and a small result intact.
        let captured = ChatMessage::ToolResults(vec![ToolResultMsg {
            tool_call_id: "c1".into(),
            tool_name: "read".into(),
            content: format!("HEAD...TAIL{}", recall_footer("read", 90_000, "abc123")),
            is_error: false,
        }]);
        let small = ChatMessage::ToolResults(vec![ToolResultMsg {
            tool_call_id: "c2".into(),
            tool_name: "ls".into(),
            content: "a\nb\nc".into(),
            is_error: false,
        }]);
        let transcript = vec![
            ChatMessage::System("sys".into()),
            ChatMessage::user_text("task"),
            ChatMessage::Assistant {
                text: "reading".into(),
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "read".into(),
                    arguments: json!({}),
                }],
            },
            captured,
            small,
            ChatMessage::user_text("recent"),
        ];
        match c.plan(&transcript, &stats(950, 1000, transcript.len())) {
            CompactionOutcome::Deterministic(out) => {
                // Structure preserved: same message count, assistant turn intact.
                assert_eq!(out.len(), transcript.len());
                assert_eq!(out[2], transcript[2], "assistant turn kept");
                // The captured result is now a compact recall ref (no HEAD/TAIL body).
                if let ChatMessage::ToolResults(results) = &out[3] {
                    assert!(results[0].content.contains("recall` with id abc123"));
                    assert!(!results[0].content.contains("HEAD"));
                    assert!(results[0].content.len() < 200, "shrunk to a ref");
                } else {
                    panic!("expected tool results at index 3");
                }
                // The small (uncaptured) result is untouched.
                assert_eq!(out[4], transcript[4]);
            }
            CompactionOutcome::NeedsModel(_) => panic!("tool-result compaction needs no model"),
        }
    }

    // --- Phase 4 Layer B: overflow fallback (Lb-5) -------------------------

    fn assistant_tool_call(id: &str) -> ChatMessage {
        ChatMessage::Assistant {
            text: String::new(),
            tool_calls: vec![ToolCall {
                id: id.into(),
                name: "read".into(),
                arguments: json!({}),
            }],
        }
    }

    fn tool_results(id: &str) -> ChatMessage {
        ChatMessage::ToolResults(vec![ToolResultMsg {
            tool_call_id: id.into(),
            tool_name: "read".into(),
            content: "x".repeat(200),
            is_error: false,
        }])
    }

    #[test]
    fn overflow_detection_matches_provider_phrasings() {
        assert!(is_context_overflow(&HarnessModelError::Provider(
            "This model's maximum context length is 200000 tokens".into()
        )));
        assert!(is_context_overflow(&HarnessModelError::Provider(
            "prompt is too long: 250000 tokens".into()
        )));
        assert!(!is_context_overflow(&HarnessModelError::Provider(
            "invalid api key".into()
        )));
        assert!(!is_context_overflow(&HarnessModelError::Timeout));
    }

    #[test]
    fn front_trim_drops_oldest_pairs_keeping_anchors_and_a_paired_tail() {
        let messages = vec![
            ChatMessage::System("sys".into()),
            ChatMessage::user_text("task"),
            assistant_tool_call("a1"),
            tool_results("a1"),
            assistant_tool_call("a2"),
            tool_results("a2"),
        ];
        let trimmed = front_trim(&messages);
        // Progress was made, anchors survive, and the kept suffix does not begin
        // with an orphan ToolResults (its assistant would have been dropped).
        assert!(trimmed.len() < messages.len(), "made progress");
        assert_eq!(trimmed[0], messages[0]);
        assert_eq!(trimmed[1], messages[1]);
        assert!(
            !matches!(trimmed.get(2), Some(ChatMessage::ToolResults(_))),
            "suffix never starts with an orphan tool result"
        );
        // The final message is preserved with its pairing.
        assert_eq!(
            *trimmed.last().expect("tail"),
            *messages.last().expect("tail")
        );
    }

    #[test]
    fn a_context_overflow_front_trims_and_retries_instead_of_failing() {
        // Two tool rounds build up a transcript, then the third main call overflows;
        // the machine front-trims and retries, completing on the fourth call.
        let replies = vec![
            Ok(tool_reply("c1", "read")),
            Ok(tool_reply("c2", "read")),
            Err(HarnessModelError::Provider(
                "This model's maximum context length is 200000 tokens".into(),
            )),
            Ok(final_reply("done after trim")),
        ];
        let client = CompactingHttpClient::new(replies, 200_000);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "x".repeat(500),
        });
        let outcome = {
            let mut record = |_: &[ChatMessage]| {};
            run_brokered_turn_http(
                &client,
                &exec,
                &input(8),
                &mut record,
                &DummyHost,
                &NoopCompactor,
                None,
                None,
            )
        };
        // The turn recovered rather than failing on the overflow.
        assert_eq!(outcome.status, TurnStatus::Completed);
        assert_eq!(outcome.summary, "done after trim");
        // Exactly one front-trim was recorded as a compaction event.
        let trims: Vec<_> = outcome
            .observations
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    LoopObservation::Compacted {
                        summary_bytes: 0,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(trims.len(), 1, "one overflow front-trim recorded");
    }

    #[test]
    fn persistent_overflow_eventually_fails_after_bounded_trims() {
        // Every main call overflows; after MAX_OVERFLOW_TRIMS the turn fails rather
        // than looping forever. Enough tool rounds first so each trim makes progress.
        let mut replies = vec![
            Ok(tool_reply("c1", "read")),
            Ok(tool_reply("c2", "read")),
            Ok(tool_reply("c3", "read")),
            Ok(tool_reply("c4", "read")),
        ];
        for _ in 0..(MAX_OVERFLOW_TRIMS + 2) {
            replies.push(Err(HarnessModelError::Provider(
                "context window exceeded".into(),
            )));
        }
        let client = CompactingHttpClient::new(replies, 200_000);
        let exec = RecordingExecutor::new(ToolOutcome {
            status: ToolStatus::Ok,
            content: "y".repeat(300),
        });
        let outcome = {
            let mut record = |_: &[ChatMessage]| {};
            run_brokered_turn_http(
                &client,
                &exec,
                &input(8),
                &mut record,
                &DummyHost,
                &NoopCompactor,
                None,
                None,
            )
        };
        assert_eq!(outcome.status, TurnStatus::Failed);
        // The turn terminated (no infinite retry loop) and never front-trimmed more
        // than the bound, whether it hit the cap or ran out of droppable middle first.
        let trims = outcome
            .observations
            .iter()
            .filter(|o| matches!(o, LoopObservation::Compacted { .. }))
            .count() as u32;
        assert!(trims >= 1, "at least one recovery attempt");
        assert!(trims <= MAX_OVERFLOW_TRIMS, "trims are bounded");
    }
}
