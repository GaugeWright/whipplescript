//! Deterministic runtime kernel scaffold.

pub mod agent_profile;
pub mod artifact_manifest;
pub mod coerce;
pub mod coerce_native;
pub mod context_assembly;
pub mod effect_config;
pub mod effect_handlers;
pub mod exec_http;
pub mod gov;
pub mod harness;
pub mod harness_loop;
pub mod harness_model;
pub mod host_facade;
pub mod host_package;
pub mod host_policy;
pub mod host_protocol;
pub mod ifc;
pub mod ingress_pass;
pub mod instance_machine;
pub mod lowering;
pub mod mcp;
pub mod media;
pub mod native_lifecycle;
pub mod package_registry;
pub mod principal;
pub mod provider;
pub mod provider_trust;
pub mod rule_correspondence;
pub mod rule_lowering;
pub mod rule_pass;
pub mod sansio;
pub mod source_merge;
pub mod time_pass;
pub mod trace;
pub mod whip_shell;
pub mod world_state;

use artifact_manifest::{
    artifact_capture_failed_payload, provider_artifact_manifest, validate_artifact_manifest,
    ArtifactCaptureFailure,
};
use coerce::{CoerceClient, CoerceRequest, CoerceResult, CoerceStatus};
use effect_handlers::effect_failure_base;
use harness::{
    AgentHarness, AgentTurnRequest, ProviderFailure, ProviderRunResult, ProviderRunStatus,
};
use native_lifecycle::{AgentTurnLifecycleKind, NativeAgentTurnObservation};
use provider::{
    NativeProviderAdapter, NativeProviderArtifactRef, NativeProviderCancellation,
    NativeProviderEvent, NativeProviderEventKind, NativeProviderTurnRequest,
};
use rule_lowering::json_from_str;
use serde_json::{json, Value};
use trace::{DependencyEdge, EffectStatus, TraceEvent, TraceRecord};
use whipplescript_core::Severity;
use whipplescript_parser::{
    DependencyPredicate, IrPrimitiveType, IrProgram, IrSchema, IrType, IrWorkflowContractKind,
    SourceSpan,
};
use whipplescript_store::coordination::Coordination;
use whipplescript_store::items::WorkItems;
use whipplescript_store::{
    ArtifactRecord, ClaimableEffect, DerivedFact, DiagnosticRecord, DurableDiagnosticCode,
    EffectCancellation, EffectCompletion, EventView, EvidenceRecord, ExpiredLease, FactBatch,
    FactBatchOutcome, InstanceTransition, LeaseRenewal, NewEffectDependency, NewEvent, NewFact,
    NewInstance, NewInstanceAuthority, NewProgramVersion, NewWorkflowInvocation,
    ProgramVersionRecord, RetryEffect, RevisionActivation, RuleCommit, RuleCommitRevisionGuard,
    RunStart, RuntimeStore, SkillEvidence, StoreError, StoreResult, StoredEvent,
    TerminalDiagnosticRecord, WorkflowInvocationView, WorkflowRevisionView,
};
// `SqliteStore` (the rusqlite store) is the default backend for
// `RuntimeKernel` under the `native` feature and is used by tests; the kernel's
// non-test code is otherwise generic over `RuntimeStore`, so it builds on wasm
// (no-native) without it.
#[cfg(feature = "native")]
use whipplescript_store::SqliteStore;

/// The runtime kernel over a [`RuntimeStore`] backend. Native defaults the
/// backend to `SqliteStore` (so existing `RuntimeKernel` type references keep
/// working); the durable-object host (Phase 5) uses `RuntimeKernel<DoSqliteStore>`.
/// The kernel calls only trait methods, so it is decoupled from the concrete
/// rusqlite store and builds on wasm without it (DR-0033 Phase 5) — where there
/// is no default backend, so `S` is always explicit.
#[cfg(feature = "native")]
pub struct RuntimeKernel<S: RuntimeStore = SqliteStore> {
    store: S,
    trace: Vec<TraceRecord>,
    /// Folded into `schema.coerce` effect admission keys by the rule pass —
    /// see [`RuntimeKernel::with_coercion_config_fingerprint`].
    coercion_config_fingerprint: String,
    /// The host's door to the custodian, for reaping at instance terminal.
    /// `None` reaps nothing, which is what every host did before this existed.
    credential_reaper: Option<std::sync::Arc<dyn crate::rule_pass::CredentialReaper>>,
}

/// wasm / no-native form: no default backend (rusqlite `SqliteStore` is absent).
#[cfg(not(feature = "native"))]
pub struct RuntimeKernel<S: RuntimeStore> {
    store: S,
    trace: Vec<TraceRecord>,
    /// Folded into `schema.coerce` effect admission keys by the rule pass —
    /// see [`RuntimeKernel::with_coercion_config_fingerprint`].
    coercion_config_fingerprint: String,
    /// The host's door to the custodian, for reaping at instance terminal.
    /// `None` reaps nothing, which is what every host did before this existed.
    credential_reaper: Option<std::sync::Arc<dyn crate::rule_pass::CredentialReaper>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProgramVersionInput<'a> {
    pub program_name: &'a str,
    pub source_hash: &'a str,
    pub ir_hash: &'a str,
    pub compiler_version: &'a str,
    /// The `.ir` snapshot `ir_hash` is the hash of, supplied by whoever computed
    /// that hash — never derived here.
    ///
    /// Deriving it from the `IrProgram` looked tidier and was wrong: on the host
    /// protocol path `ir_hash` arrives from a REMOTE compiler while the program
    /// is compiled locally, and the two IRs legitimately differ across
    /// toolchains — that divergence is exactly what
    /// `reattest_instance_program` exists to absorb. A locally-derived snapshot
    /// would then be stored against a hash naming a different document.
    ///
    /// `None` means the caller has no snapshot it can vouch for, and nothing is
    /// stored. See `NewProgramVersion::ir_snapshot` for the store-side guard.
    pub ir_snapshot: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentTurnExecution<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub provider: &'a str,
    pub worker_id: &'a str,
    pub lease_id: &'a str,
    pub lease_expires_at: &'a str,
    pub agent: &'a str,
    pub profile: Option<&'a str>,
    pub input_json: &'a str,
    pub skill_names: &'a [&'a str],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoerceExecution<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub provider: &'a str,
    pub worker_id: &'a str,
    pub lease_id: &'a str,
    pub lease_expires_at: &'a str,
    pub request: &'a CoerceRequest,
    /// The runtime-resolved model, if any, folded into the run's execution
    /// fingerprint so a coercion whose only change is the model re-runs
    /// (DR-0014). `None` for the fixture path and any run without a resolved
    /// model — fingerprint stays model-insensitive, exactly as before.
    pub model: Option<&'a str>,
}

#[derive(Debug, Default)]
struct ProviderEvidence {
    evidence_id: Option<String>,
    artifact_ids: Vec<String>,
}

pub fn idempotency_key(parts: &[&str]) -> String {
    use std::fmt::Write;
    let mut input = String::with_capacity(parts.iter().map(|part| part.len() + 12).sum());
    for part in parts {
        let _ = write!(input, "{}:", part.len());
        input.push_str(part);
        input.push(';');
    }
    // SHA-256 truncated to 128 bits: user- and external-controlled bytes
    // (record payloads, ingress signal payloads, failure reasons) reach this
    // hash, and the old 64-bit FNV-1a was offline-collidable — a crafted
    // collision on a commit key permanently poisoned the instance with the
    // loud-conflict guard, and on a content key silently aliased two facts.
    // 128 bits puts a birthday search at 2^64. NOTE: changing this function
    // changes every derived id — in-flight stores from before the swap should
    // be retired, not resumed.
    use sha2::Digest;
    let digest = sha2::Sha256::digest(input.as_bytes());
    let mut hex = String::with_capacity(36);
    hex.push_str("key_");
    for byte in &digest[..16] {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Identifies the effect a brokered turn settles. The owned harness runner uses
/// it to open the run, attribute evidence, and key the terminal fact.
pub struct BrokeredTurnContext<'a> {
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub agent: &'a str,
    pub profile: Option<&'a str>,
    /// `agent { thread continue }` (pi-conformance §4): seed this turn from the
    /// agent's latest completed-turn transcript in this instance, appending the
    /// new user message — the chat-shaped continuation. `false` = fresh turn.
    pub thread_continue: bool,
    /// Whether the host's transport released this turn's in-flight provider
    /// stream early on an observed cancellation request
    /// (spec/agent-harness.md "Cancellation"). `None` = the transport cannot
    /// release a stream mid-flight; cancellation then remains a between-rounds
    /// observation exactly as before.
    pub stream_released: Option<&'a dyn Fn() -> bool>,
}

/// A host-governed seed for a newly forked agent thread. The seed is runtime
/// state, not a user message or a completed effect: it preserves the source
/// conversation while giving the target instance its own identity and future
/// event history.
pub struct AgentThreadSeed<'a> {
    pub instance_id: &'a str,
    pub agent: &'a str,
    pub messages: &'a [crate::harness_loop::ChatMessage],
    pub source_instance_id: &'a str,
    pub source_sequence: i64,
    pub idempotency_key: &'a str,
}

/// Evidence kind + shape-only metadata for one in-turn observation. Per DR-0024
/// these are evidence, never facts (I2): no tool args or results content is
/// recorded here, only the call shape (tool name, status, step).
fn brokered_observation_evidence(
    obs: &crate::harness_loop::LoopObservation,
) -> (&'static str, Value) {
    use crate::harness_loop::{LoopObservation, ToolStatus, TurnCommandKind};
    match obs {
        LoopObservation::ModelRequest { step } => {
            ("agent.turn.brokered.model_request", json!({ "step": step }))
        }
        LoopObservation::ToolRequested { call_id, name } => (
            "agent.turn.tool_requested",
            json!({ "call_id": call_id, "tool": name }),
        ),
        LoopObservation::ToolResult {
            call_id,
            name,
            status,
        } => (
            "agent.turn.brokered.tool_result",
            json!({
                "call_id": call_id,
                "tool": name,
                "status": match status {
                    ToolStatus::Ok => "ok",
                    ToolStatus::Error => "error",
                },
            }),
        ),
        LoopObservation::ToolOutputTruncated {
            call_id,
            tool_name,
            policy,
            output_class,
            retention_direction,
            result_status,
            experiment_label,
            original_bytes,
            retained_bytes,
            recall_id,
        } => (
            "context.tool_output_truncated",
            json!({
                "call_id": call_id,
                "tool": tool_name,
                "policy": policy,
                "output_class": output_class,
                "retention_direction": retention_direction,
                "result_status": match result_status {
                    ToolStatus::Ok => "ok",
                    ToolStatus::Error => "error",
                },
                "experiment_label": experiment_label,
                "original_bytes": original_bytes,
                "retained_bytes": retained_bytes,
                "recall_id": recall_id,
            }),
        ),
        // Shape, not content, so this stays inside the I2/DR-0024 line the
        // docstring above draws: a path, a digest, and a length say WHICH bytes
        // reached the model without recording any of them. It is the same class
        // of identifier as `RecallRequested`'s `content_id`, and the digest is
        // the one a `file.write.completed` fact carries, so a recorded read
        // joins the write that produced what it read.
        LoopObservation::WorkspaceRead {
            call_id,
            tool_name,
            reads,
        } => (
            "agent.turn.workspace_read",
            json!({
                "call_id": call_id,
                "tool": tool_name,
                "reads": reads
                    .iter()
                    .map(|read| json!({
                        "path": read.path,
                        "content_hash": read.content_hash,
                        "bytes": read.bytes,
                    }))
                    .collect::<Vec<_>>(),
            }),
        ),
        LoopObservation::RecallRequested {
            call_id,
            content_id,
            offset,
            limit,
            experiment_label,
        } => (
            "context.tool_output_recall",
            json!({
                "call_id": call_id,
                "content_id": content_id,
                "offset": offset,
                "limit": limit,
                "experiment_label": experiment_label,
            }),
        ),
        LoopObservation::Compacted {
            epoch,
            folded_messages,
            summary_bytes,
        } => (
            "context.compaction",
            json!({
                "epoch": epoch,
                "folded_messages": folded_messages,
                "summary_bytes": summary_bytes,
            }),
        ),
        LoopObservation::UserCommandApplied { command_id, kind } => (
            "agent.turn.user_command_applied",
            json!({
                "command_id": command_id,
                "kind": match kind {
                    TurnCommandKind::Steer => "steer",
                    TurnCommandKind::FollowUp => "follow_up",
                    TurnCommandKind::Compact => "compact",
                },
            }),
        ),
        LoopObservation::WorldProjected {
            epoch,
            projection,
            content_hash,
        } => (
            "context.world",
            json!({
                "epoch": epoch,
                "projection": projection,
                "content_hash": content_hash,
            }),
        ),
        LoopObservation::MediaNormalized {
            artifact_ref,
            media_type,
            normalization,
            derivative_hash,
        } => (
            "context.media_normalized",
            json!({
                "artifact_ref": artifact_ref,
                "media_type": media_type,
                "normalization": normalization,
                "derivative_hash": derivative_hash,
            }),
        ),
    }
}

fn merge_numeric_json(acc: Value, next: Value) -> Value {
    match (acc, next) {
        (Value::Null, next) => next,
        (acc, Value::Null) => acc,
        (Value::Object(mut acc), Value::Object(next)) => {
            for (key, value) in next {
                let merged = match (acc.get(&key), &value) {
                    (Some(Value::Number(left)), Value::Number(right)) => {
                        match (left.as_i64(), right.as_i64()) {
                            (Some(left), Some(right)) => json!(left + right),
                            _ => value.clone(),
                        }
                    }
                    _ => value.clone(),
                };
                acc.insert(key, merged);
            }
            Value::Object(acc)
        }
        (_, next) => next,
    }
}

/// Restorable-context RC-4c: the target sequence a `context.restored` marker
/// rewinds to (`restored_to_sequence`), for the marker-aware transcript fold.
/// Mirrors the store-side `restore_marker_target`; `None` for a malformed marker
/// so the fold applies no rewind rather than dropping live transcripts.
fn restore_marker_target_of(payload_json: &str) -> Option<i64> {
    serde_json::from_str::<Value>(payload_json)
        .ok()?
        .get("restored_to_sequence")
        .and_then(Value::as_i64)
}

impl<S: RuntimeStore> RuntimeKernel<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            trace: Vec::new(),
            coercion_config_fingerprint: "fixture".to_owned(),
            credential_reaper: None,
        }
    }

    /// Supply the coercion-config fingerprint the rule pass folds into
    /// `schema.coerce` effect admission keys (DR-0014 amendment):
    /// H(provider_kind, provider_id, backend, model) of the host's resolved
    /// coercion config — native derives it from the resolved coerce config,
    /// the durable object from `coerce_config_json`, and the fixture path
    /// keeps the constructor's literal `"fixture"` so tests stay
    /// deterministic. Switching backend/model re-runs future coercions
    /// instead of replaying a stale terminal.
    /// Install the host's door to the custodian, so an instance reaching
    /// terminal reaps what it made and never handed off.
    ///
    /// Opt-in: a host that installs none reaps nothing, which is what every
    /// host did before this existed. The kernel cannot reach a custodian on its
    /// own — it lives behind a socket the host owns.
    pub fn with_credential_reaper(
        mut self,
        reaper: std::sync::Arc<dyn crate::rule_pass::CredentialReaper>,
    ) -> Self {
        self.credential_reaper = Some(reaper);
        self
    }

    pub fn credential_reaper(
        &self,
    ) -> Option<std::sync::Arc<dyn crate::rule_pass::CredentialReaper>> {
        self.credential_reaper.clone()
    }

    pub fn with_coercion_config_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.coercion_config_fingerprint = fingerprint.into();
        self
    }

    pub fn coercion_config_fingerprint(&self) -> &str {
        &self.coercion_config_fingerprint
    }

    /// Borrow the underlying store. The lifted rule pass holds one kernel across a
    /// whole step and reaches the store directly for the reads (and, when `S` also
    /// implements `Coordination`/`WorkItems`, the coordination/queue operations) it
    /// interleaves with kernel-level commits (DR-0033 instance-scheduler lift).
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Mutably borrow the underlying store (see [`RuntimeKernel::store`]).
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// Run one owned/brokered agent turn (DR-0024 slice 1).
    ///
    /// Opens the run, drives the pure brokered loop (the kernel executes every
    /// requested tool via `executor` — I1), records each in-turn observation as
    /// EVIDENCE only (I2: no rule-matchable fact), then settles the single
    /// terminal and derives exactly one `agent.turn.<status>` fact (layer 3) so
    /// `after <turn> succeeds` matches it just like the delegating harness.
    pub fn run_brokered_agent_turn<M, E, H>(
        &mut self,
        ctx: &BrokeredTurnContext<'_>,
        client: &M,
        executor: &E,
        host: &H,
        compactor: &dyn crate::harness_loop::Compactor,
        input: &crate::harness_loop::BrokeredTurnInput,
    ) -> StoreResult<StoredEvent>
    where
        M: crate::harness_loop::HttpModelClient + ?Sized,
        E: crate::harness_loop::ToolExecutor + ?Sized,
        H: crate::sansio::HostDriver,
    {
        use crate::harness_loop::TurnStatus;

        let run_id = idempotency_key(&[ctx.instance_id, ctx.effect_id, "brokered-run"]);
        let lease_id = idempotency_key(&[ctx.instance_id, ctx.effect_id, "brokered-lease"]);
        let existing_run = self
            .store
            .list_runs(ctx.instance_id)?
            .into_iter()
            .find(|run| run.run_id == run_id);
        match existing_run.as_ref().map(|run| run.status.as_str()) {
            None => {
                self.start_run(RunStart {
                    instance_id: ctx.instance_id,
                    effect_id: ctx.effect_id,
                    run_id: &run_id,
                    provider: "owned-harness",
                    worker_id: "whip-owned-harness",
                    lease_id: &lease_id,
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    metadata_json: &json!({ "agent": ctx.agent }).to_string(),
                })?;
            }
            Some("running") => {}
            Some(status) => {
                return Err(StoreError::Conflict(format!(
                    "brokered run is already terminal ({status})"
                )));
            }
        }

        // Resume-from-projection (slice 6): if a prior interrupted run left a
        // persisted transcript for this effect, continue from it; otherwise start
        // fresh. The loop persists the transcript after each step via `checkpoint`.
        let mut resume_from = self.load_brokered_transcript(ctx.instance_id, ctx.effect_id);
        // Thread continuation (pi-conformance §4): a fresh tell on a
        // `thread continue` agent seeds from the agent's latest COMPLETED turn
        // in this instance and appends the new user message. Same-effect crash
        // recovery above takes priority (it already contains this turn).
        if resume_from.is_empty() && ctx.thread_continue {
            let mut thread = self.load_agent_thread_transcript(ctx.instance_id, ctx.agent);
            if !thread.is_empty() {
                thread.push(crate::harness_loop::ChatMessage::User {
                    text: input.user.clone(),
                    images: input.user_images.clone(),
                });
                resume_from = thread;
            }
        }

        // Context-assembly Phase 1 (Decision 5): record one `context.bundle`
        // evidence row per assembled bundle (source, version, hash) before the
        // turn. Guarded on a fresh start (no persisted transcript) so crash
        // recovery, which resumes from the transcript, does not duplicate the rows.
        if resume_from.is_empty() {
            for bundle in &input.context_bundles {
                self.store.record_evidence(EvidenceRecord {
                    instance_id: ctx.instance_id,
                    kind: "context.bundle",
                    subject_type: "run",
                    subject_id: &run_id,
                    causation_id: None,
                    correlation_id: Some(ctx.effect_id),
                    summary: Some(&bundle.contribution_id),
                    metadata_json: &json!({
                        "contribution_id": bundle.contribution_id,
                        "source": bundle.source,
                        "version": bundle.version,
                        "authority": bundle.authority,
                        "scope": bundle.scope,
                        "audience": bundle.audience,
                        "message_role": bundle.message_role,
                        "ordering_key": bundle.ordering_key,
                        "replacement_key": bundle.replacement_key,
                        "sequence": bundle.sequence,
                        "lifecycle": bundle.lifecycle,
                        "content_hash": bundle.content_hash,
                    })
                    .to_string(),
                })?;
            }
            // Turn-scoped skill pins (`tell … with skills [...]`, Phase 7): recorded
            // once as provenance. The discover-all catalogue is unchanged.
            if !input.pinned_skills.is_empty() {
                self.store.record_evidence(EvidenceRecord {
                    instance_id: ctx.instance_id,
                    kind: "skills.pinned",
                    subject_type: "run",
                    subject_id: &run_id,
                    causation_id: None,
                    correlation_id: Some(ctx.effect_id),
                    summary: Some("turn-scoped skills"),
                    metadata_json: &json!({ "skills": input.pinned_skills }).to_string(),
                })?;
            }
        }

        // Human-ask resume accounting is retired: a brokered turn now only
        // resumes from its own mid-turn transcript checkpoint, never from a
        // suspended human round, so there is no prior step/usage to carry.
        let prior_steps = 0_usize;
        let prior_usage = Value::Null;
        let resume_input;
        let run_input: &crate::harness_loop::BrokeredTurnInput =
            if resume_from.is_empty() && prior_steps == 0 {
                input
            } else {
                resume_input = crate::harness_loop::BrokeredTurnInput {
                    resume_from,
                    max_steps: input.max_steps.saturating_sub(prior_steps),
                    ..input.clone()
                };
                &resume_input
            };
        let checkpoint_step = self
            .store
            .list_events(ctx.instance_id)?
            .into_iter()
            .filter(|event| {
                event.event_type == "agent.turn.brokered.transcript"
                    && serde_json::from_str::<Value>(&event.payload_json)
                        .ok()
                        .and_then(|payload| {
                            payload
                                .get("effect_id")
                                .and_then(Value::as_str)
                                .map(|effect_id| effect_id == ctx.effect_id)
                        })
                        .unwrap_or(false)
            })
            .count();
        let outcome = {
            let store = &self.store;
            let mut step = checkpoint_step;
            let mut checkpoint = |messages: &[crate::harness_loop::ChatMessage]| {
                let key = idempotency_key(&[
                    ctx.instance_id,
                    ctx.effect_id,
                    "transcript",
                    &step.to_string(),
                ]);
                step += 1;
                let payload = json!({
                    "effect_id": ctx.effect_id,
                    "messages": crate::harness_loop::chat_messages_to_json(messages),
                })
                .to_string();
                let _ = store.append_event(NewEvent {
                    instance_id: ctx.instance_id,
                    event_type: "agent.turn.brokered.transcript",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: None,
                    correlation_id: Some(ctx.effect_id),
                    idempotency_key: Some(&key),
                });
            };
            // Cooperative cancel (pi-conformance §3): probe the durable
            // cancellation surface between model rounds. Errors read as "not
            // cancelled" — a probe failure must not kill a healthy turn.
            let cancel_probe = || {
                store
                    .effect_has_open_cancellation_request(ctx.instance_id, ctx.effect_id)
                    .unwrap_or(false)
            };
            crate::harness_loop::run_brokered_turn_http(
                client,
                executor,
                run_input,
                &mut checkpoint,
                host,
                compactor,
                Some(&cancel_probe),
                ctx.stream_released,
            )
        };

        // In-turn observations are evidence, never facts (leaf-ness, I2).
        for (index, obs) in outcome.observations.iter().enumerate() {
            let (kind, metadata) = brokered_observation_evidence(obs);
            self.store.record_evidence(EvidenceRecord {
                instance_id: ctx.instance_id,
                kind,
                subject_type: "run",
                subject_id: &run_id,
                causation_id: None,
                correlation_id: None,
                summary: None,
                metadata_json: &json!({ "index": index, "observation": metadata }).to_string(),
            })?;
        }

        let terminal_key = idempotency_key(&[ctx.instance_id, ctx.effect_id, "terminal"]);
        let total_steps = prior_steps + outcome.steps;
        let total_usage = merge_numeric_json(prior_usage, outcome.usage.clone());
        // The context reading is stamped after the merge: it is a point-in-time
        // gauge (the last main reply's prompt size), and running it through the
        // numeric merge would sum it into nonsense.
        let total_usage =
            crate::harness_loop::usage_with_context(&total_usage, outcome.last_input_tokens);
        let metadata_json = json!({
            "steps": total_steps,
            "usage": total_usage,
            "agent": ctx.agent,
        })
        .to_string();

        let (status, fact_name) = match outcome.status {
            TurnStatus::Completed => ("completed", "agent.turn.completed"),
            TurnStatus::Failed => ("failed", "agent.turn.failed"),
            TurnStatus::TimedOut => ("timed_out", "agent.turn.timed_out"),
            TurnStatus::Cancelled => ("cancelled", "agent.turn.cancelled"),
        };

        let completion = EffectCompletion {
            instance_id: ctx.instance_id,
            effect_id: ctx.effect_id,
            run_id: &run_id,
            provider: "owned-harness",
            worker_id: "whip-owned-harness",
            status,
            exit_code: Some(if matches!(outcome.status, TurnStatus::Completed) {
                0
            } else {
                1
            }),
            summary: Some(&outcome.summary),
            metadata_json: &metadata_json,
            idempotency_key: Some(&terminal_key),
        };
        let terminal = match outcome.status {
            TurnStatus::Completed => self.complete_run(completion)?,
            TurnStatus::Failed => self.fail_run(completion)?,
            TurnStatus::TimedOut => self.timeout_run(completion)?,
            TurnStatus::Cancelled => self.cancel_run(completion)?,
        };

        // The single terminal fact (layer 3) -- the only fact a brokered turn
        // derives. Byte-for-byte the same `agent.turn.<status>` convention the
        // delegating harness emits (fact keyed by run_id, correlated to the
        // effect, provenance `effect`) so `after <turn> succeeds` /
        // `when <agent> completed turn` resolve identically. Mirrors
        // append_agent_turn_event_and_fact.
        let mut fact_payload_value = json!({
            "id": run_id,
            "effect_id": ctx.effect_id,
            "run_id": run_id,
            "agent": ctx.agent,
            "provider": "owned-harness",
            "status": status,
            "summary": outcome.summary,
        });
        // DR-0032 parity with append_agent_turn_event_and_fact: a failed turn
        // carries the EffectError base under `value` (what `after turn fails
        // as f` binds — the checker approves f.reason/f.kind against it).
        if matches!(outcome.status, TurnStatus::Failed | TurnStatus::TimedOut) {
            if let Some(object) = fact_payload_value.as_object_mut() {
                let mut base = effect_failure_base(
                    "agent.tell",
                    &outcome.summary,
                    &outcome.summary,
                    ctx.effect_id,
                    &run_id,
                );
                if let Some(base_object) = base.as_object_mut() {
                    base_object.insert(
                        "error_class".to_owned(),
                        Value::String("provider_error".to_owned()),
                    );
                }
                object.insert("value".to_owned(), base);
            }
        }
        let fact_payload = fact_payload_value.to_string();
        let fact_id = idempotency_key(&[ctx.instance_id, "agent-turn", &run_id]);
        let fact_event_key = idempotency_key(&[ctx.instance_id, &run_id, "agent-turn-fact"]);
        self.store.append_event(NewEvent {
            instance_id: ctx.instance_id,
            event_type: fact_name,
            payload_json: &fact_payload,
            source: "kernel",
            causation_id: Some(&run_id),
            correlation_id: Some(ctx.effect_id),
            idempotency_key: Some(&idempotency_key(&[
                ctx.instance_id,
                &run_id,
                "agent-turn-event",
            ])),
        })?;
        self.store.derive_fact(DerivedFact {
            instance_id: ctx.instance_id,
            fact: NewFact {
                fact_id: &fact_id,
                name: fact_name,
                key: &run_id,
                value_json: &fact_payload,
                schema_id: None,
                provenance_class: "effect",
                correlation_id: Some(ctx.effect_id),
                source_span_json: None,
            },
            source: "kernel",
            causation_id: Some(&run_id),
            idempotency_key: Some(&fact_event_key),
        })?;

        Ok(terminal)
    }

    /// The agent's conversation thread: the final transcript of its latest
    /// COMPLETED turn in this instance (pi-conformance §4). The completed-turn
    /// fact carries the agent name and effect id; the transcript events carry
    /// the conversation — the last checkpoint of a completed turn includes the
    /// final assistant reply. Empty when the agent has no completed turn yet.
    fn load_agent_thread_transcript(
        &self,
        instance_id: &str,
        agent: &str,
    ) -> Vec<crate::harness_loop::ChatMessage> {
        self.snapshot_agent_thread(instance_id, agent, None)
            .unwrap_or_default()
    }

    /// Return the live conversation thread for `agent`, optionally bounded at
    /// one event-log coordinate. Restore markers are folded before selecting
    /// the latest completed turn or imported fork seed, so abandoned history
    /// never leaks into a fork or subsequent turn.
    pub fn snapshot_agent_thread(
        &self,
        instance_id: &str,
        agent: &str,
        up_to_sequence: Option<i64>,
    ) -> StoreResult<Vec<crate::harness_loop::ChatMessage>> {
        let events = self.store.list_events(instance_id)?;
        let mut live: Vec<&EventView> = Vec::new();
        for event in &events {
            if up_to_sequence.is_some_and(|sequence| event.sequence > sequence) {
                break;
            }
            if event.event_type == "context.restored" {
                if let Some(target) = restore_marker_target_of(&event.payload_json) {
                    live.retain(|folded| folded.sequence <= target);
                }
            } else {
                live.push(event);
            }
        }

        for event in live.iter().rev() {
            let payload = match serde_json::from_str::<Value>(&event.payload_json) {
                Ok(payload) => payload,
                Err(_) => continue,
            };
            if payload.get("agent").and_then(Value::as_str) != Some(agent) {
                continue;
            }
            if event.event_type == "agent.thread.seeded" {
                return Ok(crate::harness_loop::chat_messages_from_json(
                    payload.get("messages").unwrap_or(&Value::Null),
                ));
            }
            if event.event_type != "agent.turn.completed" {
                continue;
            }
            let Some(effect_id) = payload.get("effect_id").and_then(Value::as_str) else {
                continue;
            };
            let transcript = live.iter().rev().find(|candidate| {
                candidate.event_type == "agent.turn.brokered.transcript"
                    && serde_json::from_str::<Value>(&candidate.payload_json)
                        .ok()
                        .and_then(|checkpoint| {
                            checkpoint
                                .get("effect_id")
                                .and_then(Value::as_str)
                                .map(|candidate_id| candidate_id == effect_id)
                        })
                        .unwrap_or(false)
            });
            if let Some(transcript) = transcript {
                let checkpoint: Value = serde_json::from_str(&transcript.payload_json)?;
                return Ok(crate::harness_loop::chat_messages_from_json(
                    checkpoint.get("messages").unwrap_or(&Value::Null),
                ));
            }
        }
        Ok(Vec::new())
    }

    /// Seed a newly opened instance with an exported thread snapshot. The
    /// event is idempotent and records the exact source coordinate; later
    /// continuation treats it as the target's initial live thread without
    /// pretending that the target executed the source effects.
    pub fn seed_agent_thread(&mut self, seed: AgentThreadSeed<'_>) -> StoreResult<StoredEvent> {
        self.store.append_event(NewEvent {
            instance_id: seed.instance_id,
            event_type: "agent.thread.seeded",
            payload_json: &json!({
                "agent": seed.agent,
                "messages": crate::harness_loop::chat_messages_to_json(seed.messages),
                "source_instance_id": seed.source_instance_id,
                "source_sequence": seed.source_sequence,
            })
            .to_string(),
            source: "kernel",
            causation_id: None,
            correlation_id: None,
            idempotency_key: Some(seed.idempotency_key),
        })
    }

    /// Load the latest persisted brokered-turn transcript for an effect, for
    /// resume-from-projection. Empty when none was recorded (a fresh turn).
    fn load_brokered_transcript(
        &self,
        instance_id: &str,
        effect_id: &str,
    ) -> Vec<crate::harness_loop::ChatMessage> {
        self.load_brokered_transcript_bounded(instance_id, effect_id, None)
    }

    /// RC-2 Delta B: load the brokered-turn transcript for an effect as it was
    /// AT a prior cut — the latest transcript checkpoint whose event-log
    /// `sequence <= up_to_sequence` (INCLUSIVE), rather than the newest one.
    ///
    /// Keyed off the per-instance event-log `sequence` (NOT the per-effect
    /// `step` index) deliberately: `sequence` is the single monotonic
    /// per-instance coordinate that also cuts the instance projection plane
    /// (`rebuild_projections_to`) and the file manifest. `step` only orders
    /// transcripts within one effect and would not let a single cut coordinate
    /// N address all three planes at once. Because each transcript checkpoint is
    /// appended in step order and `sequence` is monotonic, "latest with
    /// `sequence <= N`" is exactly the transcript position that was current at
    /// the cut. Empty when no checkpoint exists at or before N.
    #[cfg_attr(not(test), allow(dead_code))]
    fn load_brokered_transcript_at(
        &self,
        instance_id: &str,
        effect_id: &str,
        up_to_sequence: i64,
    ) -> Vec<crate::harness_loop::ChatMessage> {
        self.load_brokered_transcript_bounded(instance_id, effect_id, Some(up_to_sequence))
    }

    fn load_brokered_transcript_bounded(
        &self,
        instance_id: &str,
        effect_id: &str,
        up_to_sequence: Option<i64>,
    ) -> Vec<crate::harness_loop::ChatMessage> {
        let Ok(events) = self.store.list_events(instance_id) else {
            return Vec::new();
        };
        // RC-4c: the transcript plane rewinds with the other two. Walk the log
        // ascending (`list_events` is ordered by `sequence`), folding
        // `context.restored` markers (models/maude/restore-replay.maude): a
        // marker drops every transcript checkpoint it orphaned, so after a
        // restore the newest LIVE transcript is the one that was current at the
        // cut, not an abandoned-branch turn. With no markers the live list is
        // every transcript in order, so latest/bounded reads are unchanged.
        //
        // RC-2 Delta B: `up_to_sequence` bounds the fold INCLUSIVE; because the
        // list is ascending we can stop at the first event past the bound.
        // `None` = unbounded (latest), the resume/crash-recovery behavior.
        let mut live: Vec<&EventView> = Vec::new();
        for event in &events {
            if let Some(n) = up_to_sequence {
                if event.sequence > n {
                    break;
                }
            }
            match event.event_type.as_str() {
                "context.restored" => {
                    if let Some(target) = restore_marker_target_of(&event.payload_json) {
                        live.retain(|folded| folded.sequence <= target);
                    }
                }
                "agent.turn.brokered.transcript" => live.push(event),
                _ => {}
            }
        }
        let latest = live.iter().rev().find(|event| {
            serde_json::from_str::<Value>(&event.payload_json)
                .ok()
                .and_then(|payload| {
                    payload
                        .get("effect_id")
                        .and_then(Value::as_str)
                        .map(|id| id == effect_id)
                })
                .unwrap_or(false)
        });
        match latest {
            Some(event) => serde_json::from_str::<Value>(&event.payload_json)
                .ok()
                .map(|payload| {
                    crate::harness_loop::chat_messages_from_json(
                        payload.get("messages").unwrap_or(&Value::Null),
                    )
                })
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    pub fn into_store(self) -> S {
        self.store
    }

    pub fn trace(&self) -> &[TraceRecord] {
        &self.trace
    }

    pub fn create_program_version(
        &mut self,
        input: ProgramVersionInput<'_>,
    ) -> StoreResult<ProgramVersionRecord> {
        self.store.create_program_version(NewProgramVersion {
            program_name: input.program_name,
            source_hash: input.source_hash,
            ir_hash: input.ir_hash,
            ir_snapshot: None,
            compiler_version: input.compiler_version,
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
    }

    pub fn create_program_version_for_program(
        &mut self,
        input: ProgramVersionInput<'_>,
        program: &IrProgram,
    ) -> StoreResult<ProgramVersionRecord> {
        let declared_profiles_json = declared_profiles_json(program);
        let declared_skills_json = declared_skills_json(program);
        let declared_schemas_json = declared_schemas_json(program);
        let analysis_summary_json = program_analysis_summary_json(program);
        self.store.create_program_version(NewProgramVersion {
            program_name: input.program_name,
            source_hash: input.source_hash,
            ir_hash: input.ir_hash,
            compiler_version: input.compiler_version,
            ir_snapshot: input.ir_snapshot,
            declared_capabilities_json: "[]",
            declared_profiles_json: &declared_profiles_json,
            declared_skills_json: &declared_skills_json,
            declared_schemas_json: &declared_schemas_json,
            analysis_summary_json: &analysis_summary_json,
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
    }

    /// Re-attest an instance's program under the current compiler: same
    /// authored identity (`source_hash`), new `ir_hash`. See
    /// `RuntimeStore::reattest_instance_program`.
    pub fn reattest_instance_program(
        &mut self,
        instance_id: &str,
        input: ProgramVersionInput<'_>,
    ) -> StoreResult<ProgramVersionRecord> {
        self.store.reattest_instance_program(
            instance_id,
            NewProgramVersion {
                program_name: input.program_name,
                source_hash: input.source_hash,
                ir_hash: input.ir_hash,
                ir_snapshot: None,
                compiler_version: input.compiler_version,
                declared_capabilities_json: "[]",
                declared_profiles_json: "[]",
                declared_skills_json: "[]",
                declared_schemas_json: "[]",
                analysis_summary_json: "{}",
                generated_artifacts_json: "[]",
                artifact_root: None,
            },
        )
    }

    pub fn create_instance(
        &self,
        version: &ProgramVersionRecord,
        input_json: &str,
    ) -> StoreResult<String> {
        self.create_instance_with_authority(version, input_json, NewInstanceAuthority::empty())
    }

    pub fn create_instance_with_authority(
        &self,
        version: &ProgramVersionRecord,
        input_json: &str,
        authority: NewInstanceAuthority<'_>,
    ) -> StoreResult<String> {
        self.store
            .create_instance_with_authority(
                NewInstance {
                    program_id: &version.program_id,
                    version_id: &version.version_id,
                    input_json,
                },
                authority,
            )
            .map(|instance| instance.instance_id)
    }

    pub fn ingest_external_event(
        &self,
        instance_id: &str,
        event_type: &str,
        payload_json: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        self.store.append_event(NewEvent {
            instance_id,
            event_type,
            payload_json,
            source: "external",
            causation_id: None,
            correlation_id: None,
            idempotency_key,
        })
    }

    pub fn derive_fact(
        &mut self,
        instance_id: &str,
        fact_name: &str,
        key: &str,
        value_json: &str,
        causation_id: Option<&str>,
        event_idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let fact_id = idempotency_key(&[instance_id, "fact", fact_name, key]);
        self.store.derive_fact(DerivedFact {
            instance_id,
            fact: NewFact {
                fact_id: &fact_id,
                name: fact_name,
                key,
                value_json,
                schema_id: None,
                provenance_class: "external",
                correlation_id: None,
                source_span_json: None,
            },
            source: "kernel",
            causation_id,
            idempotency_key: event_idempotency_key,
        })
    }

    /// Admit a typed fact batch atomically from one validated effect outcome
    /// (spec/admission-and-idempotency.md). Delegates to the store primitive.
    pub fn admit_fact_batch(&mut self, batch: FactBatch<'_>) -> StoreResult<FactBatchOutcome> {
        self.store.admit_fact_batch(batch)
    }

    /// Records a typed fact ingested from an effect's output bytes
    /// (spec/json-ingestion.md): provenance `ingest`, stamped with the schema
    /// it validated against.
    pub fn ingest_fact(
        &mut self,
        instance_id: &str,
        fact_name: &str,
        key: &str,
        value_json: &str,
        causation_id: Option<&str>,
        event_idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let fact_id = idempotency_key(&[instance_id, "fact", fact_name, key]);
        self.store.derive_fact(DerivedFact {
            instance_id,
            fact: NewFact {
                fact_id: &fact_id,
                name: fact_name,
                key,
                value_json,
                schema_id: Some(fact_name),
                provenance_class: "ingest",
                correlation_id: None,
                source_span_json: None,
            },
            source: "kernel",
            causation_id,
            idempotency_key: event_idempotency_key,
        })
    }

    pub fn evaluate_rules(
        &self,
        instance_id: &str,
        program: &IrProgram,
    ) -> StoreResult<Vec<String>> {
        let mut ready = Vec::new();
        for rule in &program.rules {
            let mut all_reads_available = true;
            for fact_read in &rule.metadata.fact_reads {
                if !self.store.fact_exists(instance_id, fact_read)? {
                    all_reads_available = false;
                    break;
                }
            }
            if all_reads_available {
                ready.push(rule.name.clone());
            }
        }
        Ok(ready)
    }

    pub fn commit_rule(&mut self, commit: RuleCommit<'_>) -> StoreResult<StoredEvent> {
        let event = self.store.commit_rule(commit)?;
        self.emit_rule_commit_trace(commit);
        Ok(event)
    }

    pub fn commit_rule_with_revision_guard(
        &mut self,
        commit: RuleCommit<'_>,
        guard: RuleCommitRevisionGuard<'_>,
    ) -> StoreResult<StoredEvent> {
        let event = self.store.commit_rule_with_revision_guard(commit, guard)?;
        self.emit_rule_commit_trace(commit);
        Ok(event)
    }

    fn emit_rule_commit_trace(&mut self, commit: RuleCommit<'_>) {
        for effect in commit.effects {
            self.emit(TraceEvent::EffectCreated {
                effect_id: effect.effect_id.to_owned(),
                status: effect_status(effect.status),
            });
        }
        for dependency in commit.dependencies {
            self.emit(TraceEvent::DependencyCreated(dependency_edge(dependency)));
        }
    }

    pub fn activate_revision(
        &mut self,
        activation: RevisionActivation<'_>,
    ) -> StoreResult<WorkflowRevisionView> {
        let revision = self.store.activate_revision(activation)?;
        self.emit_revision_activation_trace(&revision)?;
        Ok(revision)
    }

    fn emit_revision_activation_trace(
        &mut self,
        revision: &WorkflowRevisionView,
    ) -> StoreResult<()> {
        if self.trace.iter().any(|record| {
            matches!(
                &record.event,
                TraceEvent::RevisionActivated { revision_id, .. }
                    if revision_id == &revision.revision_id
            )
        }) {
            return Ok(());
        }
        let event = self
            .store
            .list_events(&revision.instance_id)?
            .into_iter()
            .find(|event| event.event_id == revision.activated_by_event_id)
            .ok_or_else(|| {
                StoreError::Conflict(format!(
                    "revision event {} was not found",
                    revision.activated_by_event_id
                ))
            })?;
        let payload: Value = serde_json::from_str(&event.payload_json)?;
        let terminal_cancel_effects =
            string_array_field(&payload, "terminal_cancel_effects").unwrap_or_default();
        let request_cancel_effects =
            string_array_field(&payload, "request_cancel_effects").unwrap_or_default();
        self.emit(TraceEvent::RevisionActivated {
            revision_id: revision.revision_id.clone(),
            from_version_id: revision.from_version_id.clone(),
            to_version_id: revision.to_version_id.clone(),
            from_epoch: payload
                .get("from_epoch")
                .and_then(Value::as_i64)
                .unwrap_or_else(|| revision.epoch.saturating_sub(1)),
            to_epoch: revision.epoch,
            cancellation_policy: payload
                .get("cancellation_policy")
                .and_then(Value::as_str)
                .unwrap_or(&revision.cancellation_policy)
                .to_owned(),
            terminal_cancel_effects: terminal_cancel_effects.clone(),
            request_cancel_effects: request_cancel_effects.clone(),
        });
        for effect_id in terminal_cancel_effects {
            self.emit(TraceEvent::EffectCancelled { effect_id });
        }
        for effect_id in request_cancel_effects {
            self.emit(TraceEvent::EffectCancellationRequested {
                effect_id,
                revision_id: Some(revision.revision_id.clone()),
                reason: Some("workflow revision".to_owned()),
                requested_by: "workflow.revision".to_owned(),
            });
        }
        Ok(())
    }

    pub fn record_workflow_invocation(
        &self,
        invocation: NewWorkflowInvocation<'_>,
    ) -> StoreResult<()> {
        self.store.record_workflow_invocation(invocation)
    }

    pub fn get_workflow_invocation(
        &self,
        parent_instance_id: &str,
        parent_effect_id: &str,
    ) -> StoreResult<Option<WorkflowInvocationView>> {
        self.store
            .get_workflow_invocation(parent_instance_id, parent_effect_id)
    }

    pub fn claimable_effects(&self, instance_id: &str) -> StoreResult<Vec<ClaimableEffect>> {
        self.store.claimable_effects(instance_id)
    }

    pub fn satisfy_dependencies(&self, instance_id: &str) -> StoreResult<usize> {
        self.store.satisfy_dependencies(instance_id)
    }

    pub fn start_run(&mut self, run: RunStart<'_>) -> StoreResult<StoredEvent> {
        let event = match self.store.start_run(run) {
            Ok(event) => event,
            Err(StoreError::PolicyBlocked { effect_id, reason })
            | Err(StoreError::CapacityBlocked { effect_id, reason }) => {
                self.emit(TraceEvent::EffectBlocked {
                    effect_id: effect_id.clone(),
                    status: None,
                    reason: reason.clone(),
                });
                return Err(StoreError::PolicyBlocked { effect_id, reason });
            }
            Err(error) => return Err(error),
        };
        self.emit(TraceEvent::EffectClaimed {
            effect_id: run.effect_id.to_owned(),
        });
        self.emit(TraceEvent::RunStarted {
            run_id: run.run_id.to_owned(),
            effect_id: run.effect_id.to_owned(),
        });
        Ok(event)
    }

    /// Block an effect at provider-binding time (DR-0020): the worker found the
    /// provider unbindable before provider execution. Delegates to the store's
    /// idempotent binding-block and emits the blocked trace.
    pub fn block_effect_binding(
        &mut self,
        instance_id: &str,
        effect_id: &str,
        category: &str,
        detail: &str,
    ) -> StoreResult<StoredEvent> {
        let event = self
            .store
            .block_effect_binding(instance_id, effect_id, category, detail)?;
        self.emit(TraceEvent::EffectBlocked {
            effect_id: effect_id.to_owned(),
            status: Some("blocked".to_owned()),
            reason: format!("{category}: {detail}"),
        });
        Ok(event)
    }

    pub fn complete_run(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent> {
        let completion = EffectCompletion {
            status: "completed",
            ..completion
        };
        let event = self.store.complete_effect(completion)?;
        self.emit(TraceEvent::EffectTerminal {
            run_id: completion.run_id.to_owned(),
            effect_id: completion.effect_id.to_owned(),
            status: EffectStatus::Completed,
        });
        Ok(event)
    }

    pub fn fail_run(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent> {
        self.fail_run_with_diagnostic(completion, None)
    }

    fn fail_run_with_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        let completion = EffectCompletion {
            status: "failed",
            ..completion
        };
        let event = self
            .store
            .complete_effect_with_terminal_diagnostic(completion, diagnostic)?;
        self.emit(TraceEvent::EffectTerminal {
            run_id: completion.run_id.to_owned(),
            effect_id: completion.effect_id.to_owned(),
            status: EffectStatus::Failed,
        });
        Ok(event)
    }

    /// Recovery resolution terminal: the effect becomes `failed` (a Failed
    /// subkind) but the run records the distinct `uncertain` status, so an
    /// operator can tell "we don't know if the side effect happened" apart from
    /// an ordinary provider failure. See admission-and-idempotency.md.
    fn resolve_run_uncertain_with_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        let completion = EffectCompletion {
            status: "failed",
            ..completion
        };
        let event = self
            .store
            .resolve_effect_uncertain(completion, diagnostic)?;
        // Uncertain resolution SETTLES the effect as failed, and settled
        // outcomes are facts: without one, a workflow handling
        // `after x fails` (which suppresses the auto-fail net) had nothing to
        // match after `whip recover` and idled forever.
        let value_json = json!({
            "effect_id": completion.effect_id,
            "run_id": completion.run_id,
            "status": "failed",
            "summary": completion.summary,
            "value": {
                "reason": completion.summary,
                "summary": completion.summary,
                "error_class": "uncertain",
            },
        })
        .to_string();
        self.derive_fact(
            completion.instance_id,
            "effect.failed",
            completion.effect_id,
            &value_json,
            Some(&event.event_id),
            Some(&idempotency_key(&[
                completion.instance_id,
                completion.effect_id,
                "uncertain-failed-fact",
            ])),
        )?;
        self.emit(TraceEvent::EffectTerminal {
            run_id: completion.run_id.to_owned(),
            effect_id: completion.effect_id.to_owned(),
            status: EffectStatus::Failed,
        });
        Ok(event)
    }

    pub fn timeout_run(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent> {
        self.timeout_run_with_diagnostic(completion, None)
    }

    pub fn cancel_run(&mut self, completion: EffectCompletion<'_>) -> StoreResult<StoredEvent> {
        let completion = EffectCompletion {
            status: "cancelled",
            ..completion
        };
        let event = self.store.complete_effect(completion)?;
        // A cancelled RUN settles its effect, and settled outcomes are facts
        // (the same invariant as cancel_effect): without this, the orphaned-run
        // cancellation acknowledgement left `after x cancelled`/`completes`
        // arms with nothing to match — and cancelled is auto-fail-exempt, so
        // the instance idled forever. Kind-specific cancel facts (e.g.
        // `agent.turn.cancelled`) may coexist; arm bindings prefer them by
        // fact-name order.
        let value_json = json!({
            "effect_id": completion.effect_id,
            "run_id": completion.run_id,
            "status": "cancelled",
            "reason": completion.summary,
            "summary": completion.summary,
        })
        .to_string();
        self.derive_fact(
            completion.instance_id,
            "effect.cancelled",
            completion.effect_id,
            &value_json,
            Some(&event.event_id),
            Some(&idempotency_key(&[
                completion.instance_id,
                completion.effect_id,
                "cancelled-fact",
            ])),
        )?;
        self.emit(TraceEvent::EffectTerminal {
            run_id: completion.run_id.to_owned(),
            effect_id: completion.effect_id.to_owned(),
            status: EffectStatus::Cancelled,
        });
        Ok(event)
    }

    fn timeout_run_with_diagnostic(
        &mut self,
        completion: EffectCompletion<'_>,
        diagnostic: Option<TerminalDiagnosticRecord>,
    ) -> StoreResult<StoredEvent> {
        let completion = EffectCompletion {
            status: "timed_out",
            ..completion
        };
        let event = self
            .store
            .complete_effect_with_terminal_diagnostic(completion, diagnostic)?;
        self.emit(TraceEvent::EffectTerminal {
            run_id: completion.run_id.to_owned(),
            effect_id: completion.effect_id.to_owned(),
            status: EffectStatus::TimedOut,
        });
        Ok(event)
    }

    pub fn cancel_effect(
        &mut self,
        cancellation: EffectCancellation<'_>,
    ) -> StoreResult<StoredEvent> {
        let event = self.store.cancel_effect(cancellation)?;
        // A cancellation SETTLES the effect, and settled outcomes are facts:
        // without this, `after x completes` / `after x cancelled` arms had
        // nothing to match when a sibling arm (or the operator) cancelled the
        // effect — the arm never fired and the instance idled forever.
        let value_json = json!({
            "effect_id": cancellation.effect_id,
            "status": "cancelled",
            "reason": cancellation.reason,
            "summary": cancellation.reason,
        })
        .to_string();
        self.derive_fact(
            cancellation.instance_id,
            "effect.cancelled",
            cancellation.effect_id,
            &value_json,
            Some(&event.event_id),
            Some(&idempotency_key(&[
                cancellation.instance_id,
                cancellation.effect_id,
                "cancelled-fact",
            ])),
        )?;
        self.emit(TraceEvent::EffectCancelled {
            effect_id: cancellation.effect_id.to_owned(),
        });
        Ok(event)
    }

    pub fn pause_instance(
        &mut self,
        instance_id: &str,
        reason: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let event = self.store.transition_instance(InstanceTransition {
            instance_id,
            status: "paused",
            reason,
            idempotency_key,
        })?;
        self.emit(TraceEvent::InstancePaused);
        Ok(event)
    }

    pub fn resume_instance(
        &mut self,
        instance_id: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let event = self.store.transition_instance(InstanceTransition {
            instance_id,
            status: "running",
            reason: None,
            idempotency_key,
        })?;
        self.emit(TraceEvent::InstanceResumed);
        Ok(event)
    }

    /// DR-0076 P2: the holder-lifetime bound is owed by REACHING a terminal,
    /// not by whoever transitioned the instance to one. The discharge happens
    /// here, and the `Coordination + WorkItems` bound is what makes forgetting
    /// it a compile error rather than a discipline — a caller holding a store
    /// that cannot release does not get to cancel. That refusal is the point:
    /// this same omission shipped twice (cancel leaving held state behind, and
    /// #236's `update_todo` reaching an unguarded release).
    ///
    /// What this does NOT fix is the atomicity hazard: the transition and the
    /// release are not one transaction, so a crash between them still leaves a
    /// holder holding. P5 cannot express that and does not license it; the TTL
    /// backstop remains the only answer there.
    pub fn cancel_instance(
        &mut self,
        instance_id: &str,
        reason: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent>
    where
        S: Coordination + WorkItems,
    {
        let event = self.store.transition_instance(InstanceTransition {
            instance_id,
            status: "cancelled",
            reason,
            idempotency_key,
        })?;
        // Cloned first: the reaper and the store are both behind `self`, and
        // the release needs the store mutably.
        let reaper = self.credential_reaper.clone();
        crate::rule_pass::release_holder_resources_on_terminal(
            &mut self.store,
            reaper.as_deref(),
            instance_id,
        );
        self.emit(TraceEvent::InstanceCancelled);
        Ok(event)
    }

    /// Generic internal workflow failure (auto-fail, R1 —
    /// models/maude/rule-autofail.maude): transitions the instance to `failed`
    /// with a plain reason and no typed `failure` payload — used when an
    /// unhandled effect failure in a self-terminating workflow would otherwise
    /// stall the instance forever. Distinct from an author `fail error { … }`
    /// (which produces the declared failure type); this is a runtime/system
    /// failure the author did not handle. Mirrors `cancel_instance`'s terminal
    /// cleanup (pending human asks are retired).
    pub fn fail_instance_internal(
        &mut self,
        instance_id: &str,
        reason: &str,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent>
    where
        S: Coordination + WorkItems,
    {
        let event = self.store.transition_instance(InstanceTransition {
            instance_id,
            status: "failed",
            reason: Some(reason),
            idempotency_key,
        })?;
        // Same bound, same reason as `cancel_instance` above.
        // Cloned first: the reaper and the store are both behind `self`, and
        // the release needs the store mutably.
        let reaper = self.credential_reaper.clone();
        crate::rule_pass::release_holder_resources_on_terminal(
            &mut self.store,
            reaper.as_deref(),
            instance_id,
        );
        self.emit(TraceEvent::InstanceFailed);
        Ok(event)
    }

    pub fn renew_lease(&mut self, renewal: LeaseRenewal<'_>) -> StoreResult<StoredEvent> {
        self.store.renew_lease(renewal)
    }

    pub fn expire_leases(
        &mut self,
        instance_id: &str,
        now: &str,
    ) -> StoreResult<Vec<ExpiredLease>> {
        let expired = self.store.expire_leases(instance_id, now)?;
        for lease in &expired {
            self.emit(TraceEvent::LeaseExpired {
                run_id: lease.run_id.clone(),
                effect_id: lease.effect_id.clone(),
            });
        }
        Ok(expired)
    }

    pub fn retry_effect(&mut self, retry: RetryEffect<'_>) -> StoreResult<StoredEvent> {
        let effect_id = retry.effect_id.to_owned();
        let event = self.store.retry_effect(retry)?;
        self.emit(TraceEvent::EffectRetried { effect_id });
        Ok(event)
    }

    pub fn run_agent_turn(
        &mut self,
        execution: AgentTurnExecution<'_>,
        harness: &dyn AgentHarness,
    ) -> StoreResult<StoredEvent> {
        self.run_agent_turn_with_metadata(execution, harness, "{}")
    }

    pub fn run_agent_turn_with_metadata(
        &mut self,
        execution: AgentTurnExecution<'_>,
        harness: &dyn AgentHarness,
        run_metadata_json: &str,
    ) -> StoreResult<StoredEvent> {
        self.start_run(RunStart {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            lease_id: execution.lease_id,
            lease_expires_at: execution.lease_expires_at,
            metadata_json: run_metadata_json,
        })?;
        self.store.record_skill_evidence(SkillEvidence {
            instance_id: execution.instance_id,
            run_id: execution.run_id,
            effect_id: execution.effect_id,
            skill_names: execution.skill_names,
            idempotency_key: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                "skills",
            ])),
        })?;

        let request = AgentTurnRequest {
            instance_id: execution.instance_id.to_owned(),
            effect_id: execution.effect_id.to_owned(),
            run_id: execution.run_id.to_owned(),
            agent: execution.agent.to_owned(),
            profile: execution.profile.map(str::to_owned),
            input_json: execution.input_json.to_owned(),
            skill_names: execution
                .skill_names
                .iter()
                .map(|skill| (*skill).to_owned())
                .collect(),
        };
        harness.before_launch(&request);
        if self
            .store
            .effect_has_open_cancellation_request(execution.instance_id, execution.effect_id)?
        {
            let metadata_json = merge_provider_run_metadata(
                json!({
                    "cancellation": "requested_before_provider_launch",
                    "provider": execution.provider,
                }),
                run_metadata_json,
            )
            .to_string();
            return self.cancel_run(EffectCompletion {
                instance_id: execution.instance_id,
                effect_id: execution.effect_id,
                run_id: execution.run_id,
                provider: execution.provider,
                worker_id: execution.worker_id,
                status: "cancelled",
                exit_code: None,
                summary: Some("provider launch skipped because cancellation was requested"),
                metadata_json: &metadata_json,
                idempotency_key: Some(&idempotency_key(&[
                    execution.instance_id,
                    execution.run_id,
                    "cancel-before-launch",
                ])),
            });
        }

        let mut result = harness.run(request);
        enforce_required_artifact_capture_failure(&mut result);
        self.settle_provider_run_result(execution, run_metadata_json, &result)
    }

    /// Settle an already-computed [`ProviderRunResult`] (an agent turn's outcome) to
    /// its terminal: record the provider evidence, emit the redacted diagnostics,
    /// complete/fail/timeout the run, and append the agent-turn event + fact. This
    /// is the store half of `run_agent_turn_with_metadata`, split out (like
    /// [`settle_coerce_result`](Self::settle_coerce_result)) so a host that drives
    /// the model turn itself can settle the outcome — the durable object's sans-IO
    /// agent turn drives its `BrokeredTurnMachine` over `fetch` and settles the
    /// `ProviderRunResult` here, reusing the exact evidence/diagnostic/fact path the
    /// native host uses. Pair with a prior [`start_run`](Self::start_run).
    pub fn settle_provider_run_result(
        &mut self,
        execution: AgentTurnExecution<'_>,
        run_metadata_json: &str,
        result: &ProviderRunResult,
    ) -> StoreResult<StoredEvent> {
        // Redacting the model's whole answer is byte-scaled work, so it happens
        // once here and the same bytes reach the evidence row, the diagnostics,
        // the completion, and the turn fact.
        let safe_summary = redacted_provider_summary(&result.summary);
        let evidence = self.record_provider_result(execution, result, &safe_summary)?;
        let (metadata_json, terminal_hash, provider_correlation_id) = provider_terminal_metadata(
            execution.instance_id,
            execution.run_id,
            result,
            run_metadata_json,
        );
        self.emit_provider_diagnostic(
            execution.run_id,
            execution.effect_id,
            execution.provider,
            provider_effect_status(&result.status),
            &safe_summary,
            &metadata_json,
        );
        let completion = EffectCompletion {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            status: provider_status(&result.status),
            exit_code: result.exit_code,
            summary: Some(&safe_summary),
            metadata_json: &metadata_json,
            idempotency_key: Some(&terminal_completion_idempotency_key(
                execution.instance_id,
                execution.run_id,
                &provider_correlation_id,
                &terminal_hash,
            )),
        };
        let diagnostic = self.provider_terminal_diagnostic(
            execution.instance_id,
            execution.effect_id,
            execution.run_id,
            execution.provider,
            provider_effect_status(&result.status),
            &safe_summary,
            Some(DurableDiagnosticCode::ProviderKind(provider_failure_code(
                result.failure.as_ref(),
                provider_status(&result.status),
            ))),
            &metadata_json,
            &evidence,
        );

        let event = match result.status {
            ProviderRunStatus::Completed => self.complete_run(completion)?,
            ProviderRunStatus::Failed => self.fail_run_with_diagnostic(completion, diagnostic)?,
            ProviderRunStatus::TimedOut => {
                self.timeout_run_with_diagnostic(completion, diagnostic)?
            }
            // A deliberate cancel is not a failure: no terminal diagnostic,
            // and cancel_run derives the effect.cancelled settling fact.
            ProviderRunStatus::Cancelled => self.cancel_run(completion)?,
        };
        self.append_agent_turn_event_and_fact(execution, result, &safe_summary)?;
        Ok(event)
    }

    pub fn run_native_agent_turn(
        &mut self,
        execution: AgentTurnExecution<'_>,
        request: NativeProviderTurnRequest,
        adapter: &mut dyn NativeProviderAdapter,
        max_events: usize,
    ) -> StoreResult<StoredEvent> {
        self.run_native_agent_turn_with_metadata(execution, request, adapter, max_events, "{}")
    }

    pub fn run_native_agent_turn_with_metadata(
        &mut self,
        execution: AgentTurnExecution<'_>,
        request: NativeProviderTurnRequest,
        adapter: &mut dyn NativeProviderAdapter,
        max_events: usize,
        run_metadata_json: &str,
    ) -> StoreResult<StoredEvent> {
        let run_metadata = merge_provider_run_metadata(
            json!({
                "native_provider": request.to_json_redacted(),
                "adapter_provider_id": adapter.provider_id(),
                "adapter_capability": {
                    "provider_kind": adapter.capability().provider_kind.as_str(),
                    "surface": adapter.capability().surface.as_str(),
                },
            }),
            run_metadata_json,
        )
        .to_string();
        self.start_run(RunStart {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            lease_id: execution.lease_id,
            lease_expires_at: execution.lease_expires_at,
            metadata_json: &run_metadata,
        })?;
        self.store.record_skill_evidence(SkillEvidence {
            instance_id: execution.instance_id,
            run_id: execution.run_id,
            effect_id: execution.effect_id,
            skill_names: execution.skill_names,
            idempotency_key: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                "skills",
            ])),
        })?;

        // Pre-start cancellation needs no branch here: `store.start_run`
        // (called above, before any provider work) transactionally refuses to
        // start a run while a cancellation request is open — the delegated
        // path shares the owned harness's pre-launch protection at the store
        // layer (DR-0035 Decision 5 residual, verified closed).
        // Captured before the request moves into the adapter: the depth the
        // program authorized for this turn, used for driver-initiated
        // cancellation (DR-0035 Decision 5).
        let cancellation_depth = request.cancellation_depth;
        let started = match adapter.start_turn(request) {
            Ok(event) => event,
            Err(error) => {
                let failed = native_boundary_error_event(execution, error);
                let evidence = self.record_native_provider_event(
                    execution,
                    &failed,
                    "native-provider-boundary-start",
                )?;
                return self.complete_native_agent_turn(
                    execution,
                    &failed,
                    &evidence,
                    run_metadata_json,
                );
            }
        };
        let mut latest_evidence =
            self.record_native_provider_event(execution, &started, "native-provider-started")?;
        if started.event_kind.is_terminal() {
            return self.complete_native_agent_turn(
                execution,
                &started,
                &latest_evidence,
                run_metadata_json,
            );
        }

        // Two-clock liveness (DR-0035 Decision 4): `max_events` bounds
        // DELIVERED frames only — an empty poll no longer consumes budget. The
        // wall-clock inactivity bound lives in the adapters (which synthesize
        // their own TimedOut terminal); the idle-poll ceiling here is only a
        // backstop against an adapter that spins on `Ok(None)` without ever
        // blocking, and it resets on every delivered frame.
        // The idle ceiling is deliberately generous: real adapters block on
        // their wall clock and synthesize their own TimedOut instead of
        // returning empty polls, so this only stops a non-blocking adapter
        // from spinning forever.
        let idle_poll_ceiling = max_events.max(1024);
        let mut delivered = 0usize;
        let mut idle_polls = 0usize;
        let mut cancel_attempted = false;
        while delivered < max_events && idle_polls < idle_poll_ceiling {
            // Cancellation plumb-through (DR-0035 Decision 5): an open durable
            // cancellation request reaches the running delegate. The ack is a
            // non-terminal Diagnostic; the run still ends with exactly one
            // terminal (normally `cancelled`, else the inactivity backstop).
            if !cancel_attempted
                && self.store.effect_has_open_cancellation_request(
                    execution.instance_id,
                    execution.effect_id,
                )?
            {
                cancel_attempted = true;
                match adapter.cancel_turn(NativeProviderCancellation {
                    run_id: execution.run_id.to_owned(),
                    provider_session_id: None,
                    provider_turn_id: None,
                    requested_depth: cancellation_depth,
                    reason: "effect_cancellation_requested".to_owned(),
                }) {
                    Ok(ack) => {
                        latest_evidence = self.record_native_provider_event(
                            execution,
                            &ack,
                            "native-provider-cancel-ack",
                        )?;
                        if ack.event_kind.is_terminal() {
                            return self.complete_native_agent_turn(
                                execution,
                                &ack,
                                &latest_evidence,
                                run_metadata_json,
                            );
                        }
                    }
                    Err(error) => {
                        // A refused cancel is evidence, not a turn failure —
                        // the run keeps draining toward its own terminal.
                        let refused = NativeProviderEvent {
                            provider_id: execution.provider.to_owned(),
                            run_id: execution.run_id.to_owned(),
                            event_kind: NativeProviderEventKind::Diagnostic,
                            provider_event_type: "whip.native.cancel_failed".to_owned(),
                            provider_session_id: None,
                            provider_turn_id: None,
                            sequence: None,
                            evidence: json!({ "boundary_error": error.to_json_redacted() }),
                            artifacts: Vec::new(),
                        };
                        self.record_native_provider_event(
                            execution,
                            &refused,
                            "native-provider-cancel-failed",
                        )?;
                    }
                }
            }
            let event = match adapter.next_event(execution.run_id) {
                Ok(Some(event)) => {
                    idle_polls = 0;
                    event
                }
                Ok(None) => {
                    idle_polls += 1;
                    continue;
                }
                Err(error) => {
                    let failed = native_boundary_error_event(execution, error);
                    latest_evidence = self.record_native_provider_event(
                        execution,
                        &failed,
                        &format!("native-provider-boundary-event-{delivered}"),
                    )?;
                    return self.complete_native_agent_turn(
                        execution,
                        &failed,
                        &latest_evidence,
                        run_metadata_json,
                    );
                }
            };
            latest_evidence = self.record_native_provider_event(
                execution,
                &event,
                &format!("native-provider-event-{delivered}"),
            )?;
            delivered += 1;
            if event.event_kind.is_terminal() {
                return self.complete_native_agent_turn(
                    execution,
                    &event,
                    &latest_evidence,
                    run_metadata_json,
                );
            }
        }

        let timed_out = NativeProviderEvent {
            provider_id: execution.provider.to_owned(),
            run_id: execution.run_id.to_owned(),
            event_kind: NativeProviderEventKind::TimedOut,
            provider_event_type: "whip.native.timeout".to_owned(),
            provider_session_id: None,
            provider_turn_id: None,
            sequence: None,
            evidence: json!({
                "max_events": max_events,
                "delivered": delivered,
                "idle_polls": idle_polls,
            }),
            artifacts: Vec::new(),
        };
        latest_evidence =
            self.record_native_provider_event(execution, &timed_out, "native-provider-timeout")?;
        self.complete_native_agent_turn(execution, &timed_out, &latest_evidence, run_metadata_json)
    }

    pub fn record_native_agent_turn_observation(
        &mut self,
        execution: AgentTurnExecution<'_>,
        observation: &NativeAgentTurnObservation,
        occurrence_key: &str,
    ) -> StoreResult<StoredEvent> {
        self.append_native_agent_turn_observation(execution, observation, occurrence_key)
    }

    pub fn record_artifact_capture_failure(
        &mut self,
        execution: AgentTurnExecution<'_>,
        failure: ArtifactCaptureFailure<'_>,
        idempotency_key: Option<&str>,
    ) -> StoreResult<StoredEvent> {
        let payload = artifact_capture_failed_payload(failure).map_err(StoreError::Conflict)?;
        let payload_json = payload.to_string();
        let event = self.store.append_event(NewEvent {
            instance_id: execution.instance_id,
            event_type: artifact_manifest::ARTIFACT_CAPTURE_FAILED_EVENT,
            payload_json: &payload_json,
            source: "kernel",
            causation_id: Some(execution.effect_id),
            correlation_id: Some(execution.run_id),
            idempotency_key,
        })?;
        let diagnostic_message = format!(
            "artifact capture failed for {}: {}",
            failure.artifact_ref, failure.error_kind
        );
        self.store.record_diagnostic(DiagnosticRecord {
            instance_id: Some(execution.instance_id),
            program_id: None,
            program_version_id: None,
            severity: Severity::Error,
            code: Some(DurableDiagnosticCode::Registered(
                artifact_manifest::ARTIFACT_CAPTURE_FAILED_CODE,
            )),
            message: &diagnostic_message,
            source_span_json: None,
            subject_type: Some("effect"),
            subject_id: Some(execution.effect_id),
            event_id: Some(&event.event_id),
            effect_id: Some(execution.effect_id),
            run_id: Some(execution.run_id),
            assertion_id: None,
            evidence_ids_json: "[]",
            artifact_ids_json: "[]",
            causation_id: Some(execution.effect_id),
            correlation_id: Some(execution.run_id),
            idempotency_key,
        })?;
        Ok(event)
    }

    pub fn recover_provider_terminal_from_evidence(
        &mut self,
        execution: AgentTurnExecution<'_>,
    ) -> StoreResult<Option<StoredEvent>> {
        let Some(run) = self
            .store
            .list_runs(execution.instance_id)?
            .into_iter()
            .find(|run| run.run_id == execution.run_id)
        else {
            return Ok(None);
        };
        if run.status != "running" {
            return Ok(None);
        }

        let evidence = self.store.list_evidence(execution.instance_id)?;
        if let Some(native_evidence) = evidence.iter().rev().find(|evidence| {
            evidence.kind == "agent.turn.native_provider"
                && evidence.subject_type == "run"
                && evidence.subject_id == execution.run_id
                && evidence
                    .metadata_json
                    .parse::<Value>()
                    .ok()
                    .and_then(|metadata| metadata.get("native_event").cloned())
                    .and_then(|event| event.get("terminal").and_then(Value::as_bool))
                    == Some(true)
        }) {
            let metadata = serde_json::from_str::<Value>(&native_evidence.metadata_json)?;
            let native_event = recover_native_provider_event(&metadata, execution)?;
            let artifact_ids = metadata
                .get("artifact_ids")
                .and_then(Value::as_array)
                .map(|ids| {
                    ids.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let provider_evidence = ProviderEvidence {
                evidence_id: Some(native_evidence.evidence_id.clone()),
                artifact_ids,
            };
            return self
                .complete_native_agent_turn(
                    execution,
                    &native_event,
                    &provider_evidence,
                    &run.metadata_json,
                )
                .map(Some);
        }

        let Some(evidence) = evidence.into_iter().rev().find(|evidence| {
            evidence.kind == "agent.turn.provider"
                && evidence.subject_type == "run"
                && evidence.subject_id == execution.run_id
        }) else {
            return Ok(None);
        };

        let metadata = serde_json::from_str::<Value>(&evidence.metadata_json)?;
        let status = recover_provider_status(&metadata);
        let failure = metadata.get("failure").and_then(provider_failure_from_json);
        let result = ProviderRunResult {
            status,
            summary: evidence
                .summary
                .clone()
                .unwrap_or_else(|| "recovered provider terminal outcome".to_owned()),
            stdout: String::new(),
            stderr: String::new(),
            transcript: String::new(),
            exit_code: metadata.get("exit_code").and_then(Value::as_i64),
            usage_json: "{}".to_owned(),
            artifacts: Vec::new(),
            failure,
        };
        let artifact_ids = metadata
            .get("artifact_ids")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let provider_evidence = ProviderEvidence {
            evidence_id: Some(evidence.evidence_id.clone()),
            artifact_ids,
        };
        let provider_correlation_id = evidence.correlation_id.clone().unwrap_or_else(|| {
            provider_terminal_correlation_id(execution.instance_id, execution.run_id)
        });
        let terminal_metadata_base = json!({
            "recovery": "provider_evidence_terminal",
            "evidence_id": evidence.evidence_id,
            "provider_metadata": metadata,
            "provider_correlation_id": provider_correlation_id,
        });
        let terminal_hash = terminal_payload_hash(
            provider_status(&result.status),
            result.exit_code,
            Some(&result.summary),
            &terminal_metadata_base.to_string(),
        );
        let terminal_metadata = add_terminal_payload_hash(terminal_metadata_base, &terminal_hash);
        let safe_summary = redacted_provider_summary(&result.summary);
        let completion = EffectCompletion {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            status: provider_status(&result.status),
            exit_code: result.exit_code,
            summary: Some(&safe_summary),
            metadata_json: &terminal_metadata,
            idempotency_key: Some(&terminal_completion_idempotency_key(
                execution.instance_id,
                execution.run_id,
                &provider_correlation_id,
                &terminal_hash,
            )),
        };
        let diagnostic = self.provider_terminal_diagnostic(
            execution.instance_id,
            execution.effect_id,
            execution.run_id,
            execution.provider,
            provider_effect_status(&result.status),
            &safe_summary,
            Some(DurableDiagnosticCode::ProviderKind(provider_failure_code(
                result.failure.as_ref(),
                provider_status(&result.status),
            ))),
            &terminal_metadata,
            &provider_evidence,
        );
        let event = match result.status {
            ProviderRunStatus::Completed => self.complete_run(completion)?,
            ProviderRunStatus::Failed => self.fail_run_with_diagnostic(completion, diagnostic)?,
            ProviderRunStatus::TimedOut => {
                self.timeout_run_with_diagnostic(completion, diagnostic)?
            }
            // A deliberate cancel is not a failure: no terminal diagnostic,
            // and cancel_run derives the effect.cancelled settling fact.
            ProviderRunStatus::Cancelled => self.cancel_run(completion)?,
        };
        self.append_agent_turn_event_and_fact(execution, &result, &safe_summary)?;
        Ok(Some(event))
    }

    pub fn recover_running_provider_runs(
        &mut self,
        instance_id: &str,
    ) -> StoreResult<Vec<StoredEvent>> {
        let runs = self.store.list_runs(instance_id)?;
        let effects = self.store.list_effects(instance_id)?;
        let mut recovered = Vec::new();
        for run in runs.into_iter().filter(|run| run.status == "running") {
            let Some(effect) = effects
                .iter()
                .find(|effect| effect.effect_id == run.effect_id)
            else {
                continue;
            };
            let execution = AgentTurnExecution {
                instance_id,
                effect_id: &run.effect_id,
                run_id: &run.run_id,
                provider: &run.provider,
                worker_id: &run.worker_id,
                lease_id: "",
                lease_expires_at: "",
                agent: effect.target.as_deref().unwrap_or("worker"),
                profile: effect.profile.as_deref(),
                input_json: &effect.input_json,
                skill_names: &[],
            };
            if let Some(event) = self.recover_provider_terminal_from_evidence(execution)? {
                recovered.push(event);
            } else {
                // No recoverable terminal evidence and no idempotent provider
                // re-query: resolve the started-without-terminal run to a single
                // `uncertain` terminal (a Failed subkind) rather than leaving it
                // stuck or silently re-executing the external side effect. This is
                // the admission-and-idempotency.md exactly-once recovery rule
                // (TLA+ ResolveUncertainRun).
                match self.resolve_uncertain_provider_run(execution) {
                    Ok(event) => recovered.push(event),
                    // A real terminal raced in between the run snapshot and this
                    // resolution; the store row guard already prevented a double
                    // terminal, so skip rather than aborting the whole sweep.
                    Err(StoreError::Conflict(_)) => {}
                    Err(err) => return Err(err),
                }
            }
        }
        Ok(recovered)
    }

    /// Recovery resolution for a run that started its external side effect but
    /// whose worker crashed before any terminal or evidence was recorded, where
    /// the provider offers no idempotent re-query. Resolves to a single
    /// `uncertain` terminal (a Failed subkind) under a deterministic idempotency
    /// key so re-running recovery cannot double-admit, and never re-executes the
    /// external side effect.
    fn resolve_uncertain_provider_run(
        &mut self,
        execution: AgentTurnExecution<'_>,
    ) -> StoreResult<StoredEvent> {
        let provider_correlation_id =
            provider_terminal_correlation_id(execution.instance_id, execution.run_id);
        let summary = "recovery could not determine the provider outcome; resolved as uncertain";
        let terminal_metadata_base = json!({
            "recovery": "uncertain",
            "provider_correlation_id": provider_correlation_id,
        });
        let terminal_hash = terminal_payload_hash(
            provider_status(&ProviderRunStatus::Failed),
            None,
            Some(summary),
            &terminal_metadata_base.to_string(),
        );
        let terminal_metadata = add_terminal_payload_hash(terminal_metadata_base, &terminal_hash);
        let completion = EffectCompletion {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            status: provider_status(&ProviderRunStatus::Failed),
            exit_code: None,
            summary: Some(summary),
            metadata_json: &terminal_metadata,
            idempotency_key: Some(&terminal_completion_idempotency_key(
                execution.instance_id,
                execution.run_id,
                &provider_correlation_id,
                &terminal_hash,
            )),
        };
        let provider_evidence = ProviderEvidence {
            evidence_id: None,
            artifact_ids: Vec::new(),
        };
        let diagnostic = self.provider_terminal_diagnostic(
            execution.instance_id,
            execution.effect_id,
            execution.run_id,
            execution.provider,
            provider_effect_status(&ProviderRunStatus::Failed),
            summary,
            Some(DurableDiagnosticCode::Registered(
                whipplescript_core::runtime_diagnostic_code!("runtime.recovery_uncertain"),
            )),
            &terminal_metadata,
            &provider_evidence,
        );
        self.resolve_run_uncertain_with_diagnostic(completion, diagnostic)
    }

    pub fn run_coerce(
        &mut self,
        execution: CoerceExecution<'_>,
        client: &dyn CoerceClient,
    ) -> StoreResult<StoredEvent> {
        let start_metadata = coerce_run_start_metadata(execution.model);
        self.start_run(RunStart {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            lease_id: execution.lease_id,
            lease_expires_at: execution.lease_expires_at,
            metadata_json: &start_metadata,
        })?;

        let result = client.coerce(execution.request);
        self.settle_coerce_result(execution, &result)
    }

    /// Settle an already-computed [`CoerceResult`] to its terminal: record the
    /// evidence, emit the redacted provider diagnostics, complete/fail/timeout the
    /// run, and append the coerce fact. This is the store half of `run_coerce`,
    /// split out so a host that performs the provider HTTP itself can settle the
    /// parsed result — the durable object's sans-IO coerce (build_request →
    /// `NeedsHttp` via `fetch` → `parse_response` → here) reuses it byte-for-byte,
    /// as the native `run_coerce` does after its synchronous client call. Pair with
    /// a prior [`start_run`](Self::start_run) so the run row exists.
    pub fn settle_coerce_result(
        &mut self,
        execution: CoerceExecution<'_>,
        result: &CoerceResult,
    ) -> StoreResult<StoredEvent> {
        // One redaction pass over the model's whole answer, reused by the
        // evidence row, the diagnostics, the completion, and the coerce fact.
        let safe_summary = redacted_provider_summary(&result.summary);
        let evidence = self.record_coerce_result(execution, result, &safe_summary)?;
        let metadata_json = coerce_metadata(result);
        self.emit_provider_diagnostic(
            execution.run_id,
            execution.effect_id,
            execution.provider,
            coerce_effect_status(&result.status),
            &safe_summary,
            &metadata_json,
        );
        let completion = EffectCompletion {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            status: coerce_status(&result.status),
            exit_code: coerce_exit_code(&result.status),
            summary: Some(&safe_summary),
            metadata_json: &metadata_json,
            idempotency_key: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                "coerce-terminal",
            ])),
        };
        let diagnostic = self.provider_terminal_diagnostic(
            execution.instance_id,
            execution.effect_id,
            execution.run_id,
            execution.provider,
            coerce_effect_status(&result.status),
            &safe_summary,
            Some(DurableDiagnosticCode::Registered(match result.status {
                CoerceStatus::Succeeded => {
                    whipplescript_core::runtime_diagnostic_code!("schema.coerce.succeeded")
                }
                CoerceStatus::Failed => {
                    whipplescript_core::runtime_diagnostic_code!("schema.coerce.failed")
                }
                CoerceStatus::TimedOut => {
                    whipplescript_core::runtime_diagnostic_code!("schema.coerce.timed_out")
                }
            })),
            &metadata_json,
            &evidence,
        );

        let event = match result.status {
            CoerceStatus::Succeeded => self.complete_run(completion)?,
            CoerceStatus::Failed => self.fail_run_with_diagnostic(completion, diagnostic)?,
            CoerceStatus::TimedOut => self.timeout_run_with_diagnostic(completion, diagnostic)?,
        };
        self.append_coerce_fact(execution, result, &safe_summary)?;
        Ok(event)
    }

    /// `safe_summary` is the caller's already-redacted `result.summary` (see
    /// [`Self::append_coerce_fact`]).
    fn record_coerce_result(
        &self,
        execution: CoerceExecution<'_>,
        result: &CoerceResult,
        safe_summary: &str,
    ) -> StoreResult<ProviderEvidence> {
        let metadata = json!({
            "effect_id": execution.effect_id,
            "function_name": execution.request.function_name,
            "arguments": json_payload_summary(&execution.request.arguments_json),
            "output_type": execution.request.output_type,
            "generated_coerce_source_hash": execution.request.generated_coerce_source_hash,
            "input_schema_hash": execution.request.input_schema_hash,
            "output_schema_hash": execution.request.output_schema_hash,
            "value": result.value_json.as_deref().map(json_payload_summary),
            "error": result_error_payload(result.error_json.as_deref()),
            "transcript": redacted_text_metadata(&result.transcript),
            "usage": json_from_str(&result.usage_json),
        })
        .to_string();
        let evidence_id = self.store.record_evidence(EvidenceRecord {
            instance_id: execution.instance_id,
            kind: "schema.coerce.provider",
            subject_type: "run",
            subject_id: execution.run_id,
            causation_id: Some(execution.effect_id),
            correlation_id: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                "coerce-provider",
            ])),
            summary: Some(safe_summary),
            metadata_json: &metadata,
        })?;
        Ok(ProviderEvidence {
            evidence_id: Some(evidence_id),
            artifact_ids: Vec::new(),
        })
    }

    /// `summary` is the caller's already-redacted `result.summary`: the
    /// redaction walks the model's whole answer, so the settle path computes it
    /// once and hands the same bytes to every recorder.
    fn append_coerce_fact(
        &mut self,
        execution: CoerceExecution<'_>,
        result: &CoerceResult,
        summary: &str,
    ) -> StoreResult<()> {
        let status = coerce_status(&result.status);
        let fact_name = match result.status {
            CoerceStatus::Succeeded => "schema.coerce.succeeded",
            CoerceStatus::Failed => "schema.coerce.failed",
            CoerceStatus::TimedOut => "schema.coerce.timed_out",
        };
        let succeeded = matches!(result.status, CoerceStatus::Succeeded);
        // DR-0032: on failure, `value` is the EffectError base (what `after f fails
        // as e` binds); on success it is the coerced output. The prior `null` on
        // failure shadowed the error blob, so the bound value was unreadable.
        let value_field = if succeeded {
            result_value_payload(result.value_json.as_deref())
        } else {
            // DR-0032 + redaction (D4): coerce is provider-backed, so the raw
            // `error_json` is confidential model output. The base `reason` must be
            // the already-redacted summary, NOT the raw-error-derived text — echoing
            // the provider error here would leak it into the persisted fact value.
            // P3 per-kind extras: `error_class` (a coarse classification) and
            // `http_status` (a number) are redaction-safe and ride the bound value.
            Some({
                let mut base = effect_failure_base(
                    "schema.coerce",
                    summary,
                    summary,
                    execution.effect_id,
                    execution.run_id,
                );
                let error = result
                    .error_json
                    .as_deref()
                    .and_then(|raw| serde_json::from_str::<Value>(raw).ok())
                    .unwrap_or(Value::Null);
                if let Some(object) = base.as_object_mut() {
                    object.insert(
                        "error_class".to_owned(),
                        Value::String(
                            error
                                .get("error_class")
                                .and_then(Value::as_str)
                                .unwrap_or("provider_error")
                                .to_owned(),
                        ),
                    );
                    if let Some(status) = error.get("http_status").and_then(Value::as_u64) {
                        object.insert("http_status".to_owned(), Value::from(status));
                    }
                }
                base
            })
        };
        let value = json!({
            "effect_id": execution.effect_id,
            "run_id": execution.run_id,
            "function_name": execution.request.function_name,
            "status": status,
            "output_type": execution.request.output_type,
            "value": value_field,
            "error": result_error_payload(result.error_json.as_deref()),
            "summary": summary,
        })
        .to_string();
        self.store.append_event(NewEvent {
            instance_id: execution.instance_id,
            event_type: fact_name,
            payload_json: &value,
            source: "kernel",
            causation_id: Some(execution.run_id),
            correlation_id: Some(execution.effect_id),
            idempotency_key: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                "coerce-event",
            ])),
        })?;
        let fact_id = idempotency_key(&[execution.instance_id, "coerce", execution.run_id]);
        let fact_key = idempotency_key(&[execution.instance_id, execution.run_id, "coerce-fact"]);
        self.store.derive_fact(DerivedFact {
            instance_id: execution.instance_id,
            fact: NewFact {
                fact_id: &fact_id,
                name: fact_name,
                key: execution.run_id,
                value_json: &value,
                schema_id: Some(&execution.request.output_type),
                provenance_class: "effect",
                correlation_id: Some(execution.effect_id),
                source_span_json: None,
            },
            source: "kernel",
            causation_id: Some(execution.run_id),
            idempotency_key: Some(&fact_key),
        })?;
        Ok(())
    }

    fn record_native_provider_event(
        &mut self,
        execution: AgentTurnExecution<'_>,
        event: &NativeProviderEvent,
        occurrence_key: &str,
    ) -> StoreResult<ProviderEvidence> {
        // DR-0035 Decision 3 (T1/T3): protocol violations are recorded as
        // diagnostics, never as lifecycle events. Explicit violations are
        // adapter-surfaced `whip.protocol.*` frames (e.g. misrouted run ids);
        // implicit ones are frames arriving after this run's terminal was
        // admitted — exactly-one-terminal means they must never reopen the run
        // or add lifecycle observations.
        let violation_reason = if event.provider_event_type.starts_with("whip.protocol.") {
            Some("adapter_surfaced")
        } else if self
            .store
            .list_runs(execution.instance_id)?
            .iter()
            .any(|run| run.run_id == execution.run_id && run.status != "running")
        {
            Some("post_terminal")
        } else {
            None
        };
        if let Some(reason) = violation_reason {
            return self.record_protocol_violation(execution, event, occurrence_key, reason);
        }
        let artifact_ids = event
            .artifacts
            .iter()
            .map(|artifact| {
                let artifact = redacted_native_artifact_ref(artifact);
                self.store.record_artifact(ArtifactRecord {
                    run_id: execution.run_id,
                    kind: &artifact.kind,
                    path: &artifact.uri,
                    content_hash: artifact.content_hash.as_deref(),
                    mime_type: artifact.mime_type.as_deref(),
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        let metadata = json!({
            "effect_id": execution.effect_id,
            "agent": execution.agent,
            "profile": execution.profile,
            "provider": execution.provider,
            "native_event": event.to_json_redacted(),
            "artifact_ids": artifact_ids,
        })
        .to_string();
        let evidence_id = self.store.record_evidence(EvidenceRecord {
            instance_id: execution.instance_id,
            kind: "agent.turn.native_provider",
            subject_type: "run",
            subject_id: execution.run_id,
            causation_id: Some(execution.effect_id),
            correlation_id: Some(occurrence_key),
            summary: Some(&match event.redacted_provider_error() {
                Value::String(detail) => format!(
                    "{} native provider event from {}: {}",
                    event.event_kind.as_str(),
                    event.provider_event_type,
                    detail
                ),
                _ => format!(
                    "{} native provider event from {}",
                    event.event_kind.as_str(),
                    event.provider_event_type
                ),
            }),
            metadata_json: &metadata,
        })?;
        let observation = native_provider_event_observation(event);
        self.append_native_agent_turn_observation(execution, &observation, occurrence_key)?;
        Ok(ProviderEvidence {
            evidence_id: Some(evidence_id),
            artifact_ids,
        })
    }

    /// DR-0035 Decision 3: a protocol-violating frame lands as evidence only —
    /// no lifecycle observation, no artifacts, and the run's terminal state is
    /// untouched, so a violating peer can never reopen or double-terminate a
    /// run.
    fn record_protocol_violation(
        &mut self,
        execution: AgentTurnExecution<'_>,
        event: &NativeProviderEvent,
        occurrence_key: &str,
        reason: &str,
    ) -> StoreResult<ProviderEvidence> {
        let metadata = json!({
            "effect_id": execution.effect_id,
            "agent": execution.agent,
            "provider": execution.provider,
            "reason": reason,
            "native_event": event.to_json_redacted(),
            // The adapter-constructed violation detail (frame type + run id) is
            // identifiers-only by construction, so it may cross verbatim where
            // the generic evidence shape would erase it.
            "violation": event.evidence.get("violation").cloned().unwrap_or(Value::Null),
        })
        .to_string();
        let evidence_id = self.store.record_evidence(EvidenceRecord {
            instance_id: execution.instance_id,
            kind: "agent.turn.protocol_violation",
            subject_type: "run",
            subject_id: execution.run_id,
            causation_id: Some(execution.effect_id),
            correlation_id: Some(occurrence_key),
            summary: Some(&format!(
                "protocol violation ({reason}): {} frame from {}",
                event.event_kind.as_str(),
                event.provider_event_type
            )),
            metadata_json: &metadata,
        })?;
        Ok(ProviderEvidence {
            evidence_id: Some(evidence_id),
            artifact_ids: Vec::new(),
        })
    }

    fn complete_native_agent_turn(
        &mut self,
        execution: AgentTurnExecution<'_>,
        event: &NativeProviderEvent,
        evidence: &ProviderEvidence,
        run_metadata_json: &str,
    ) -> StoreResult<StoredEvent> {
        let status = native_terminal_status(event.event_kind);
        let summary = match event.redacted_provider_error() {
            Value::String(detail) => format!(
                "{} native provider event from {}: {}",
                event.event_kind.as_str(),
                event.provider_event_type,
                detail
            ),
            _ => format!(
                "{} native provider event from {}",
                event.event_kind.as_str(),
                event.provider_event_type
            ),
        };
        let provider_correlation_id =
            provider_terminal_correlation_id(execution.instance_id, execution.run_id);
        let metadata_base = add_provider_correlation_id(
            merge_provider_run_metadata(
                json!({
                    "native_provider": event.to_json_redacted(),
                    "artifact_ids": evidence.artifact_ids,
                }),
                run_metadata_json,
            ),
            &provider_correlation_id,
        );
        let terminal_hash =
            terminal_payload_hash(status, Some(0), Some(&summary), &metadata_base.to_string());
        let metadata = add_terminal_payload_hash(metadata_base, &terminal_hash);
        let completion = EffectCompletion {
            instance_id: execution.instance_id,
            effect_id: execution.effect_id,
            run_id: execution.run_id,
            provider: execution.provider,
            worker_id: execution.worker_id,
            status,
            exit_code: Some(0),
            summary: Some(&summary),
            metadata_json: &metadata,
            idempotency_key: Some(&terminal_completion_idempotency_key(
                execution.instance_id,
                execution.run_id,
                &provider_correlation_id,
                &terminal_hash,
            )),
        };
        match event.event_kind {
            NativeProviderEventKind::Completed => self.complete_run(completion),
            NativeProviderEventKind::Failed => {
                let diagnostic = self.provider_terminal_diagnostic(
                    execution.instance_id,
                    execution.effect_id,
                    execution.run_id,
                    execution.provider,
                    EffectStatus::Failed,
                    &summary,
                    Some(DurableDiagnosticCode::ProviderKind(
                        "native_provider_failed",
                    )),
                    &metadata,
                    evidence,
                );
                self.fail_run_with_diagnostic(completion, diagnostic)
            }
            NativeProviderEventKind::TimedOut => {
                let diagnostic = self.provider_terminal_diagnostic(
                    execution.instance_id,
                    execution.effect_id,
                    execution.run_id,
                    execution.provider,
                    EffectStatus::TimedOut,
                    &summary,
                    Some(DurableDiagnosticCode::ProviderKind(
                        "native_provider_timed_out",
                    )),
                    &metadata,
                    evidence,
                );
                self.timeout_run_with_diagnostic(completion, diagnostic)
            }
            NativeProviderEventKind::Cancelled => self.cancel_run(completion),
            _ => Err(StoreError::Conflict(format!(
                "native provider event `{}` is not terminal",
                event.event_kind.as_str()
            ))),
        }
    }

    /// `safe_summary` is the caller's already-redacted `result.summary` (see
    /// [`Self::append_agent_turn_event_and_fact`]).
    fn record_provider_result(
        &self,
        execution: AgentTurnExecution<'_>,
        result: &ProviderRunResult,
        safe_summary: &str,
    ) -> StoreResult<ProviderEvidence> {
        let artifacts = result
            .artifacts
            .iter()
            .map(sanitized_provider_artifact_metadata)
            .collect::<Vec<_>>();
        let artifact_ids = artifacts
            .iter()
            .map(|artifact| {
                self.store.record_artifact(ArtifactRecord {
                    run_id: execution.run_id,
                    kind: &artifact.kind,
                    path: &artifact.path,
                    content_hash: artifact.content_hash.as_deref(),
                    mime_type: artifact.mime_type.as_deref(),
                })
            })
            .collect::<StoreResult<Vec<_>>>()?;
        let artifact_manifest = provider_artifact_manifest(&artifact_ids, &artifacts);
        validate_artifact_manifest(&artifact_manifest).map_err(StoreError::Conflict)?;
        let metadata = json!({
            "effect_id": execution.effect_id,
            "agent": execution.agent,
            "profile": execution.profile,
            "status": provider_status(&result.status),
            "stdout": redacted_text_metadata(&result.stdout),
            "stderr": redacted_text_metadata(&result.stderr),
            "transcript": redacted_text_metadata(&result.transcript),
            "exit_code": result.exit_code,
            "usage": json_from_str(&result.usage_json),
            "artifact_ids": artifact_ids,
            "artifact_manifest": artifact_manifest,
            "failure": result.failure.as_ref().map(provider_failure_json),
        })
        .to_string();
        let evidence_id = self.store.record_evidence(EvidenceRecord {
            instance_id: execution.instance_id,
            kind: "agent.turn.provider",
            subject_type: "run",
            subject_id: execution.run_id,
            causation_id: Some(execution.effect_id),
            correlation_id: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                "provider",
            ])),
            summary: Some(safe_summary),
            metadata_json: &metadata,
        })?;
        Ok(ProviderEvidence {
            evidence_id: Some(evidence_id),
            artifact_ids,
        })
    }

    /// Record the delegated-harness context attestation (DR-0034 Decision 5, D8-2).
    /// The evidence path forks on the harness class. A **Delegated** turn's context is
    /// assembled by the foreign runtime (codex/claude/command sidecar), so
    /// WhippleScript does NOT fabricate `context.bundle` provenance rows for a context
    /// it did not build. Instead it records ONE `context.attestation` row explicitly
    /// tagged `context: provider-assembled` — provider identity + kind, the prompt
    /// hash, and a hash of the tool/permission policy the envelope imposed — so an
    /// auditor can tell from the record alone which guarantee the turn carries. The
    /// shared `agent.turn.<status>` terminal is still emitted by the dispatched
    /// executor (only the provenance depth differs). **Managed** turns never call this;
    /// they emit their full hermetic `context.bundle` provenance instead.
    pub fn record_delegated_context_attestation(
        &self,
        execution: AgentTurnExecution<'_>,
        kind: &str,
        policy_json: &str,
    ) -> StoreResult<()> {
        let metadata = json!({
            "context": "provider-assembled",
            "provider": execution.provider,
            "kind": kind,
            "prompt_hash": stable_hash_hex(execution.input_json),
            "profile": execution.profile,
            "policy_hash": stable_hash_hex(policy_json),
        })
        .to_string();
        self.store.record_evidence(EvidenceRecord {
            instance_id: execution.instance_id,
            kind: "context.attestation",
            subject_type: "run",
            subject_id: execution.run_id,
            causation_id: None,
            correlation_id: Some(execution.effect_id),
            summary: Some("provider-assembled context"),
            metadata_json: &metadata,
        })?;
        Ok(())
    }

    /// `safe_summary` is the caller's already-redacted `result.summary`: the
    /// redaction walks the model's whole answer, so the settle path computes it
    /// once and hands the same bytes to every recorder.
    fn append_agent_turn_event_and_fact(
        &mut self,
        execution: AgentTurnExecution<'_>,
        result: &ProviderRunResult,
        summary: &str,
    ) -> StoreResult<()> {
        let status = provider_status(&result.status);
        let fact_name = format!("agent.turn.{status}");
        let mut payload_value = json!({
            "id": execution.run_id,
            "effect_id": execution.effect_id,
            "run_id": execution.run_id,
            "agent": execution.agent,
            "provider": execution.provider,
            "status": status,
            "summary": summary,
            "exit_code": result.exit_code,
            "failure": result.failure.as_ref().map(provider_failure_json),
        });
        // DR-0032: a failed turn carries the EffectError base under `value` (what
        // `after turn fails as f` binds); the rich provider blob stays under
        // `failure`. Success has no `value` here (the turn output is read via the
        // whole payload), so we add `value` only on failure to avoid a null shadow.
        if let Some(failure) = result.failure.as_ref() {
            let reason = provider_failure_summary_message(&failure.message);
            if let Some(object) = payload_value.as_object_mut() {
                // P3 per-kind extras: the provider failure's `error_kind` is a
                // coarse classification (redaction-safe), exposed as
                // `error_class` on the bound value.
                let mut base = effect_failure_base(
                    "agent.tell",
                    &reason,
                    summary,
                    execution.effect_id,
                    execution.run_id,
                );
                if let Some(base_object) = base.as_object_mut() {
                    base_object.insert(
                        "error_class".to_owned(),
                        Value::String(failure.error_kind.clone()),
                    );
                }
                object.insert("value".to_owned(), base);
            }
        }
        let payload = payload_value.to_string();
        let fact_id = idempotency_key(&[execution.instance_id, "agent-turn", execution.run_id]);
        let fact_event_key =
            idempotency_key(&[execution.instance_id, execution.run_id, "agent-turn-fact"]);
        self.store.append_event(NewEvent {
            instance_id: execution.instance_id,
            event_type: &fact_name,
            payload_json: &payload,
            source: "kernel",
            causation_id: Some(execution.run_id),
            correlation_id: Some(execution.effect_id),
            idempotency_key: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                "agent-turn-event",
            ])),
        })?;
        self.store.derive_fact(DerivedFact {
            instance_id: execution.instance_id,
            fact: NewFact {
                fact_id: &fact_id,
                name: &fact_name,
                key: execution.run_id,
                value_json: &payload,
                schema_id: None,
                provenance_class: "effect",
                correlation_id: Some(execution.effect_id),
                source_span_json: None,
            },
            source: "kernel",
            causation_id: Some(execution.run_id),
            idempotency_key: Some(&fact_event_key),
        })?;
        Ok(())
    }

    fn append_native_agent_turn_observation(
        &mut self,
        execution: AgentTurnExecution<'_>,
        observation: &NativeAgentTurnObservation,
        occurrence_key: &str,
    ) -> StoreResult<StoredEvent> {
        let event_type = observation.kind.event_type();
        let evidence_metadata = json!({
            "effect_id": execution.effect_id,
            "run_id": execution.run_id,
            "provider": execution.provider,
            "status": observation.kind.status(),
            "terminal": observation.terminal,
            "provider_event_type": observation.provider_event_type,
            "provider_session_id": observation.provider_session_id,
            "provider_turn_id": observation.provider_turn_id,
            "provider_payload_shape": observation.provider_payload_shape,
        })
        .to_string();
        let evidence_summary = format!(
            "{} observation from {}",
            observation.kind.status(),
            observation.provider_event_type
        );
        let evidence_id = self.store.record_evidence(EvidenceRecord {
            instance_id: execution.instance_id,
            kind: "agent.turn.native_event",
            subject_type: "run",
            subject_id: execution.run_id,
            causation_id: Some(execution.effect_id),
            correlation_id: Some(occurrence_key),
            summary: Some(&evidence_summary),
            metadata_json: &evidence_metadata,
        })?;
        let mut payload_value = json!({
            "id": execution.run_id,
            "effect_id": execution.effect_id,
            "run_id": execution.run_id,
            "agent": execution.agent,
            "provider": execution.provider,
            "status": observation.kind.status(),
            "terminal": observation.terminal,
            "provider_event_type": observation.provider_event_type,
            "provider_session_id": observation.provider_session_id,
            "provider_turn_id": observation.provider_turn_id,
            "provider_payload_shape": observation.provider_payload_shape,
            "evidence_id": evidence_id,
        });
        // Contract parity with the delegated-path terminal fact: the binding
        // contracts promise `summary` on every terminal and the EffectError
        // base under `value` on failures (`after turn fails as f` reads
        // f.reason / f.error_class) — this native fact used to carry neither,
        // so those checker-approved reads were null at runtime.
        if observation.terminal {
            let summary = match &observation.provider_error {
                Some(detail) => format!(
                    "{} native provider event from {}: {detail}",
                    observation.kind.status(),
                    observation.provider_event_type
                ),
                None => format!(
                    "{} native provider event from {}",
                    observation.kind.status(),
                    observation.provider_event_type
                ),
            };
            if let Some(object) = payload_value.as_object_mut() {
                object.insert("summary".to_owned(), Value::String(summary.clone()));
                let status = observation.kind.status();
                if matches!(status, "failed" | "timed_out") {
                    let reason = observation.provider_error.as_deref().unwrap_or(&summary);
                    let mut base = effect_failure_base(
                        "agent.tell",
                        reason,
                        &summary,
                        execution.effect_id,
                        execution.run_id,
                    );
                    if let Some(base_object) = base.as_object_mut() {
                        base_object.insert(
                            "error_class".to_owned(),
                            Value::String(
                                if status == "timed_out" {
                                    "timeout"
                                } else {
                                    "provider_error"
                                }
                                .to_owned(),
                            ),
                        );
                    }
                    object.insert("value".to_owned(), base);
                }
            }
        }
        let payload = payload_value.to_string();
        let event = self.store.append_event(NewEvent {
            instance_id: execution.instance_id,
            event_type,
            payload_json: &payload,
            source: "kernel.native_provider",
            causation_id: Some(execution.run_id),
            correlation_id: Some(execution.effect_id),
            idempotency_key: Some(&idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                occurrence_key,
                "native-lifecycle-event",
            ])),
        })?;
        // In-turn observations (streamed/tool_requested/artifact_captured) are
        // EVIDENCE only (recorded above) — never rule-matchable facts
        // (spec/agent-harness.md). Only the durable lifecycle kinds
        // (started/completed/failed/timed_out/cancelled) derive a fact; deriving
        // a fact for the evidence kinds would inflate the fact set with values no
        // rule may match (the compiler already forbids matching them).
        if observation.kind.derives_rule_matchable_fact() {
            let fact_id = idempotency_key(&[
                execution.instance_id,
                "native-agent-turn",
                execution.run_id,
                occurrence_key,
            ]);
            let fact_key = idempotency_key(&[
                execution.instance_id,
                execution.run_id,
                occurrence_key,
                "native-lifecycle-fact",
            ]);
            self.store.derive_fact(DerivedFact {
                instance_id: execution.instance_id,
                fact: NewFact {
                    fact_id: &fact_id,
                    name: event_type,
                    key: &fact_key,
                    value_json: &payload,
                    schema_id: None,
                    provenance_class: "effect",
                    correlation_id: Some(execution.effect_id),
                    source_span_json: None,
                },
                source: "kernel.native_provider",
                causation_id: Some(execution.run_id),
                idempotency_key: Some(&fact_key),
            })?;
        }
        Ok(event)
    }

    fn emit(&mut self, event: TraceEvent) {
        self.trace.push(TraceRecord {
            sequence: self.trace.len() as u64 + 1,
            event,
        });
    }

    fn emit_provider_diagnostic(
        &mut self,
        run_id: &str,
        effect_id: &str,
        provider: &str,
        status: EffectStatus,
        summary: &str,
        diagnostics_json: &str,
    ) {
        if status == EffectStatus::Completed {
            return;
        }
        self.emit(TraceEvent::ProviderDiagnostic {
            run_id: run_id.to_owned(),
            effect_id: effect_id.to_owned(),
            provider: provider.to_owned(),
            status,
            summary: summary.to_owned(),
            diagnostics_json: diagnostics_json.to_owned(),
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn provider_terminal_diagnostic(
        &self,
        instance_id: &str,
        effect_id: &str,
        run_id: &str,
        provider: &str,
        status: EffectStatus,
        summary: &str,
        code: Option<DurableDiagnosticCode<&str>>,
        diagnostics_json: &str,
        evidence: &ProviderEvidence,
    ) -> Option<TerminalDiagnosticRecord> {
        if status == EffectStatus::Completed {
            return None;
        }
        let evidence_ids_json = evidence
            .evidence_id
            .as_ref()
            .map(|evidence_id| json!([evidence_id]).to_string())
            .unwrap_or_else(|| "[]".to_owned());
        let artifact_ids_json = json!(evidence.artifact_ids).to_string();
        let message = provider_diagnostic_message(provider, summary, diagnostics_json);
        let idempotency_key =
            idempotency_key(&[instance_id, run_id, "provider-diagnostic", diagnostics_json]);
        let source_span_json = self
            .store
            .effect_source_span_json(instance_id, effect_id)
            .ok()
            .flatten();
        Some(TerminalDiagnosticRecord {
            program_id: None,
            program_version_id: None,
            severity: Severity::Error,
            code: code.map(DurableDiagnosticCode::into_owned),
            message,
            source_span_json,
            subject_type: Some("effect".to_owned()),
            subject_id: Some(effect_id.to_owned()),
            assertion_id: None,
            evidence_ids_json,
            artifact_ids_json,
            causation_id: Some(run_id.to_owned()),
            correlation_id: Some(effect_id.to_owned()),
            idempotency_key: Some(idempotency_key),
        })
    }
}

fn effect_status(status: &str) -> EffectStatus {
    match status {
        "blocked"
        | "blocked_by_dependency"
        | "blocked_by_capability"
        | "blocked_by_profile"
        | "blocked_by_capacity" => EffectStatus::Blocked,
        "claimed" => EffectStatus::Claimed,
        "running" => EffectStatus::Running,
        "completed" => EffectStatus::Completed,
        "failed" => EffectStatus::Failed,
        "timed_out" => EffectStatus::TimedOut,
        "cancelled" => EffectStatus::Cancelled,
        _ => EffectStatus::Queued,
    }
}

fn declared_profiles_json(program: &IrProgram) -> String {
    let harnesses = program
        .harnesses
        .iter()
        .map(|harness| {
            json!({
                "name": harness.name,
                "kind": harness.kind,
            })
        })
        .collect::<Vec<_>>();
    let agents = program
        .agents
        .iter()
        .map(|agent| {
            json!({
                "name": agent.name,
                "harness": agent.harness,
                "provider": agent.provider,
                "profile": agent.profile,
                "capacity": agent.capacity,
                "skills": agent.skills,
                "capabilities": agent.capabilities,
            })
        })
        .collect::<Vec<_>>();
    json!({ "harnesses": harnesses, "agents": agents }).to_string()
}

fn declared_skills_json(program: &IrProgram) -> String {
    let mut skills = program
        .agents
        .iter()
        .flat_map(|agent| agent.skills.iter().cloned())
        .collect::<Vec<_>>();
    skills.sort();
    skills.dedup();
    json!(skills).to_string()
}

fn declared_schemas_json(program: &IrProgram) -> String {
    let schemas = program
        .schemas
        .iter()
        .map(|schema| {
            let (name, kind) = match schema {
                whipplescript_parser::IrSchema::Class(class) => (&class.name, "class"),
                whipplescript_parser::IrSchema::Enum(enum_decl) => (&enum_decl.name, "enum"),
            };
            json!({ "name": name, "kind": kind })
        })
        .collect::<Vec<_>>();
    json!(schemas).to_string()
}

pub fn program_analysis_summary_json(program: &IrProgram) -> String {
    let workflow_contracts = program
        .workflow_contracts
        .iter()
        .map(|contract| {
            json!({
                "kind": workflow_contract_kind_name(&contract.kind),
                "name": contract.name,
                "type": ir_type_signature(&contract.ty),
                "source_span": source_span_summary(contract.span, "workflow_contract"),
            })
        })
        .collect::<Vec<_>>();
    let include_closure = program
        .includes
        .iter()
        .map(|include| {
            json!({
                "path": include.path,
                "source_hash": include.source_hash,
            })
        })
        .collect::<Vec<_>>();
    // A single stable fingerprint of the whole include closure: the ordered
    // (path, source_hash) pairs. Changes iff any included file's path or content
    // changes, so it identifies the bundle as a unit (the per-file `source_hash`
    // values above identify each member individually). Deterministic and stable
    // for an include-free program (hashes the empty closure).
    let bundle_hash = {
        let canonical = program
            .includes
            .iter()
            .map(|include| {
                format!(
                    "{}\u{0}{}",
                    include.path,
                    include.source_hash.as_deref().unwrap_or("")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        stable_hash_hex(&canonical)
    };
    let pattern_applications = program
        .pattern_applications
        .iter()
        .map(|application| {
            json!({
                "pattern": application.pattern,
                "alias": application.alias,
                "type_args": application
                    .type_args
                    .iter()
                    .map(ir_type_signature)
                    .collect::<Vec<_>>(),
                "value_args": application
                    .value_args
                    .iter()
                    .map(|argument| json!({
                        "name": argument.name,
                        "value": argument.value,
                    }))
                    .collect::<Vec<_>>(),
                "generated": application.generated,
            })
        })
        .collect::<Vec<_>>();
    let mut generated_declarations = program
        .pattern_applications
        .iter()
        .flat_map(|application| application.generated.iter().cloned())
        .collect::<Vec<_>>();
    generated_declarations.sort();
    generated_declarations.dedup();
    let generated_declaration_hashes = generated_declaration_hashes(program);
    let schemas = program
        .schemas
        .iter()
        .map(|schema| schema_summary(schema, true))
        .collect::<Vec<_>>();
    let harnesses = program
        .harnesses
        .iter()
        .map(|harness| {
            json!({
                "name": harness.name,
                "kind": harness.kind,
                "source_span": source_span_summary(harness.span, "harness"),
            })
        })
        .collect::<Vec<_>>();

    json!({
        "workflow": program.workflow,
        "workflow_contracts": workflow_contracts,
        "include_closure": include_closure,
        "bundle_hash": bundle_hash,
        "pattern_applications": pattern_applications,
        "generated_declarations": generated_declarations,
        "generated_declaration_hashes": generated_declaration_hashes,
        "harnesses": harnesses,
        "schemas": schemas,
    })
    .to_string()
}

fn workflow_contract_kind_name(kind: &IrWorkflowContractKind) -> &'static str {
    match kind {
        IrWorkflowContractKind::Input => "input",
        IrWorkflowContractKind::Output => "output",
        IrWorkflowContractKind::Failure => "failure",
    }
}

fn source_span_summary(span: SourceSpan, construct: &str) -> Value {
    json!({
        "start": span.start,
        "end": span.end,
        "construct": construct,
    })
}

fn schema_summary(schema: &IrSchema, include_source_spans: bool) -> Value {
    match schema {
        IrSchema::Class(class) => {
            let mut value = json!({
            "kind": "class",
            "name": class.name,
            "fields": class
                .fields
                .iter()
                .map(|field| {
                    let mut value = json!({
                        "name": field.name,
                        "type": ir_type_signature(&field.ty),
                    });
                    if include_source_spans {
                        value["source_span"] = source_span_summary(field.span, "class_field");
                    }
                    value
                })
                .collect::<Vec<_>>(),
            });
            if include_source_spans {
                value["source_span"] = source_span_summary(class.span, "class");
            }
            value
        }
        IrSchema::Enum(enum_decl) => {
            let mut value = json!({
            "kind": "enum",
            "name": enum_decl.name,
            "variants": enum_decl.variants,
            });
            if include_source_spans {
                value["source_span"] = source_span_summary(enum_decl.span, "enum");
            }
            value
        }
    }
}

fn generated_declaration_hashes(program: &IrProgram) -> Vec<Value> {
    let mut generated_declarations = program
        .pattern_applications
        .iter()
        .flat_map(|application| application.generated.iter().cloned())
        .collect::<Vec<_>>();
    generated_declarations.sort();
    generated_declarations.dedup();

    generated_declarations
        .into_iter()
        .map(
            |declaration| match generated_declaration_payload(program, &declaration) {
                Some(payload) => json!({
                    "declaration": declaration,
                    "hash": stable_hash_hex(&payload.to_string()),
                }),
                None => json!({
                    "declaration": declaration,
                    "hash": stable_hash_hex("missing-generated-declaration"),
                    "missing": true,
                }),
            },
        )
        .collect()
}

fn generated_declaration_payload(program: &IrProgram, declaration: &str) -> Option<Value> {
    let (kind, name) = declaration.split_once(':')?;
    match kind {
        "agent" => program
            .agents
            .iter()
            .find(|agent| agent.name == name)
            .map(|agent| {
                json!({
                    "kind": "agent",
                    "name": agent.name,
                    "harness": agent.harness,
                    "profile": agent.profile,
                    "capacity": agent.capacity,
                    "skills": agent.skills,
                    "capabilities": agent.capabilities,
                })
            }),
        "harness" => program
            .harnesses
            .iter()
            .find(|harness| harness.name == name)
            .map(|harness| {
                json!({
                    "kind": "harness",
                    "name": harness.name,
                    "provider_kind": harness.kind,
                })
            }),
        "enum" => program.schemas.iter().find_map(|schema| match schema {
            IrSchema::Enum(enum_decl) if enum_decl.name == name => Some(json!({
                "kind": "enum",
                "name": enum_decl.name,
                "variants": enum_decl.variants,
            })),
            _ => None,
        }),
        "class" => program.schemas.iter().find_map(|schema| match schema {
            IrSchema::Class(class) if class.name == name => Some(schema_summary(schema, false)),
            _ => None,
        }),
        "coerce" => program
            .coerces
            .iter()
            .find(|coerce| coerce.name == name)
            .map(|coerce| {
                json!({
                    "kind": "coerce",
                    "name": coerce.name,
                    "params": coerce
                        .params
                        .iter()
                        .map(|param| json!({
                            "name": param.name,
                            "type": ir_type_signature(&param.ty),
                        }))
                        .collect::<Vec<_>>(),
                    "output": ir_type_signature(&coerce.output),
                    "body": coerce.body,
                })
            }),
        "rule" => program
            .rules
            .iter()
            .find(|rule| rule.name == name)
            .map(|rule| {
                json!({
                    "kind": "rule",
                    "name": rule.name,
                    "whens": rule
                        .whens
                        .iter()
                        .map(|when| json!({
                            "source": when.source,
                            "pattern": when.pattern,
                            "guard": when.guard.as_ref().map(|guard| guard.source.as_str()),
                        }))
                        .collect::<Vec<_>>(),
                    "body": rule.body,
                    "metadata": {
                        "fact_reads": rule.metadata.fact_reads,
                        "projection_reads": rule
                            .metadata
                            .projection_reads
                            .iter()
                            .map(|read| json!({
                                "kind": format!("{:?}", read.kind),
                                "head": read.head,
                                "guard": read.guard,
                            }))
                            .collect::<Vec<_>>(),
                        "fact_writes": rule.metadata.fact_writes,
                        "fact_consumes": rule.metadata.fact_consumes,
                        "effects": rule
                            .metadata
                            .effects
                            .iter()
                            .map(|effect| json!({
                                "id": effect.id,
                                "kind": effect.kind.as_str(),
                                "binding": effect.binding,
                                "required_capabilities": effect.required_capabilities,
                                "idempotency_key": effect.idempotency_key,
                            }))
                            .collect::<Vec<_>>(),
                        "dependencies": rule
                            .metadata
                            .dependencies
                            .iter()
                            .map(|dependency| json!({
                                "upstream": dependency.upstream,
                                "predicate": dependency_predicate_name(&dependency.predicate),
                                "downstream": dependency.downstream,
                            }))
                            .collect::<Vec<_>>(),
                        "terminal_outputs": rule
                            .metadata
                            .terminal_outputs
                            .iter()
                            .map(|terminal| json!({
                                "binding": terminal.binding,
                                "alternatives": terminal
                                    .alternatives
                                    .iter()
                                    .map(|alternative| json!({
                                        "tag": alternative.tag,
                                        "payload_type": ir_type_signature(&alternative.payload_type),
                                    }))
                                    .collect::<Vec<_>>(),
                            }))
                            .collect::<Vec<_>>(),
                    },
                })
            }),
        _ => None,
    }
}

fn ir_type_signature(ty: &IrType) -> String {
    match ty {
        IrType::Primitive(primitive) => primitive_type_name(primitive).to_owned(),
        IrType::LiteralString(value) => format!("literal<{value:?}>"),
        IrType::Ref(name) => format!("ref<{name}>"),
        IrType::AgentRef(agents) => format!("agentref<{}>", agents.join(" | ")),
        IrType::Object(fields) => {
            let fields = fields
                .iter()
                .map(|field| format!("{} {}", field.name, ir_type_signature(&field.ty)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("object<{{{fields}}}>")
        }
        IrType::Optional(inner) => format!("optional<{}>", ir_type_signature(inner)),
        IrType::Array(inner) => format!("array<{}>", ir_type_signature(inner)),
        IrType::Map(inner) => format!("map<{}>", ir_type_signature(inner)),
        IrType::Sealed(inner) => format!("sealed<{}>", ir_type_signature(inner)),
        IrType::Union(variants) => {
            let variants = variants
                .iter()
                .map(ir_type_signature)
                .collect::<Vec<_>>()
                .join(" | ");
            format!("union<{variants}>")
        }
    }
}

fn dependency_predicate_name(predicate: &DependencyPredicate) -> &'static str {
    match predicate {
        DependencyPredicate::Succeeds => "succeeds",
        DependencyPredicate::Fails => "fails",
        DependencyPredicate::TimedOut => "timed_out",
        DependencyPredicate::Cancelled => "cancelled",
        DependencyPredicate::Completes => "completes",
    }
}

fn primitive_type_name(primitive: &IrPrimitiveType) -> &'static str {
    primitive.as_str()
}

fn dependency_edge(dependency: &NewEffectDependency<'_>) -> DependencyEdge {
    DependencyEdge {
        upstream_effect_id: dependency.upstream_effect_id.to_owned(),
        predicate: match dependency.predicate {
            "fails" => trace::DependencyPredicate::Fails,
            "completes" => trace::DependencyPredicate::Completes,
            _ => trace::DependencyPredicate::Succeeds,
        },
        downstream_effect_id: dependency.downstream_effect_id.to_owned(),
    }
}

fn stable_hash_hex(value: &str) -> String {
    // Collision-resistant (see idempotency_key): these hex digests cover
    // user-reachable content (terminal payload hashes) that feeds key
    // derivation, so an offline-collidable inner hash would undermine the
    // outer one.
    use sha2::Digest;
    use std::fmt::Write;
    let digest = sha2::Sha256::digest(value.as_bytes());
    let mut hex = String::with_capacity(32);
    for byte in &digest[..16] {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn redacted_text_metadata(value: &str) -> Value {
    json!({
        "redacted": true,
        "bytes": value.len(),
        "chars": value.chars().count(),
    })
}

fn json_payload_summary(source: &str) -> Value {
    json!({
        "redacted": true,
        "bytes": source.len(),
        "shape": json_shape(&json_from_str(source)),
    })
}

fn json_shape(value: &Value) -> Value {
    match value {
        Value::Null => json!({ "type": "null" }),
        Value::Bool(_) => json!({ "type": "bool" }),
        Value::Number(_) => json!({ "type": "number" }),
        Value::String(value) => json!({
            "type": "string",
            "chars": value.chars().count(),
        }),
        Value::Array(items) => json!({
            "type": "array",
            "items": items.len(),
        }),
        Value::Object(object) => json!({
            "type": "object",
            "keys": object.len(),
        }),
    }
}

fn result_value_payload(source: Option<&str>) -> Option<Value> {
    source.map(json_from_str)
}

fn result_error_payload(source: Option<&str>) -> Option<Value> {
    source.map(json_payload_summary)
}

fn sanitized_provider_artifact_metadata(
    artifact: &harness::ProviderArtifact,
) -> harness::ProviderArtifact {
    harness::ProviderArtifact {
        kind: redact_log_text(&artifact.kind),
        path: redact_log_text(&artifact.path),
        content_hash: artifact
            .content_hash
            .as_ref()
            .map(|hash| redact_log_text(hash)),
        mime_type: artifact
            .mime_type
            .as_ref()
            .map(|mime_type| redact_log_text(mime_type)),
    }
}

/// One secret-redaction vocabulary for both planes: the CLI's artifact-metadata
/// scrubber shares this predicate so a needle cannot be added to one list and
/// left leaking on the other.
pub fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "authorization",
        "api_key",
        "apikey",
        "credential",
        "password",
        "secret",
        "token",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn redact_log_text(value: &str) -> String {
    // Assembled into one buffer rather than a `Vec<String>` joined at the end:
    // this walks whole provider outputs, so the per-token allocation was the
    // cost. `split_whitespace` collapses runs, so emitting one separator before
    // every token after the first reproduces the former `join(" ")` byte for
    // byte.
    let mut redacted = String::with_capacity(value.len());
    let mut redact_next = false;
    let mut first = true;
    for token in value.split_whitespace() {
        if !first {
            redacted.push(' ');
        }
        first = false;
        if redact_next {
            redacted.push_str("[REDACTED]");
            redact_next = false;
            continue;
        }
        if token.eq_ignore_ascii_case("bearer") {
            redacted.push_str(token);
            redact_next = true;
            continue;
        }
        if let Some((key, _)) = token.split_once('=') {
            if is_sensitive_key(key) {
                redacted.push_str(key);
                redacted.push_str("=[REDACTED]");
                continue;
            }
        }
        if looks_like_secret_token(token) || contains_secret_token_pattern(token) {
            redacted.push_str("[REDACTED]");
        } else {
            redacted.push_str(token);
        }
    }
    const MAX_MESSAGE_CHARS: usize = 512;
    if redacted.chars().count() <= MAX_MESSAGE_CHARS {
        return redacted;
    }
    let mut truncated = redacted.chars().take(MAX_MESSAGE_CHARS).collect::<String>();
    truncated.push_str("...");
    truncated
}

fn looks_like_secret_token(token: &str) -> bool {
    let token = token.trim_matches(|ch: char| {
        matches!(ch, '"' | '\'' | ',' | ';' | ':' | ')' | '(' | '[' | ']')
    });
    (token.starts_with("sk-") && token.len() >= 20)
        || (token.starts_with("ghp_") && token.len() >= 20)
        || token.starts_with("github_pat_")
        || (token.starts_with("AKIA") && token.len() >= 20)
}

/// Shared with the CLI's artifact-metadata scrubber for the same reason as
/// [`is_sensitive_key`]. The prefix-anchored `looks_like_secret_token` stays
/// private: only `redact_log_text` applies it.
pub fn contains_secret_token_pattern(token: &str) -> bool {
    let token = token.trim_matches(|ch: char| {
        matches!(ch, '"' | '\'' | ',' | ';' | ':' | ')' | '(' | '[' | ']')
    });
    token.contains("github_pat_")
        || token
            .find("sk-")
            .is_some_and(|start| token[start..].len() >= 20)
        || token
            .find("ghp_")
            .is_some_and(|start| token[start..].len() >= 20)
        || token
            .find("AKIA")
            .is_some_and(|start| token[start..].len() >= 20)
}

fn provider_status(status: &ProviderRunStatus) -> &'static str {
    match status {
        ProviderRunStatus::Completed => "completed",
        ProviderRunStatus::Failed => "failed",
        ProviderRunStatus::TimedOut => "timed_out",
        ProviderRunStatus::Cancelled => "cancelled",
    }
}

fn native_terminal_status(kind: NativeProviderEventKind) -> &'static str {
    match kind {
        NativeProviderEventKind::Completed => "completed",
        NativeProviderEventKind::Failed => "failed",
        NativeProviderEventKind::TimedOut => "timed_out",
        NativeProviderEventKind::Cancelled => "cancelled",
        _ => "running",
    }
}

fn native_event_kind_from_str(value: &str) -> Option<NativeProviderEventKind> {
    match value {
        "started" => Some(NativeProviderEventKind::Started),
        "streamed" => Some(NativeProviderEventKind::Streamed),
        "tool_requested" => Some(NativeProviderEventKind::ToolRequested),
        "artifact_captured" => Some(NativeProviderEventKind::ArtifactCaptured),
        "completed" => Some(NativeProviderEventKind::Completed),
        "failed" => Some(NativeProviderEventKind::Failed),
        "timed_out" => Some(NativeProviderEventKind::TimedOut),
        "cancelled" => Some(NativeProviderEventKind::Cancelled),
        "diagnostic" => Some(NativeProviderEventKind::Diagnostic),
        _ => None,
    }
}

fn recover_native_provider_event(
    metadata: &Value,
    execution: AgentTurnExecution<'_>,
) -> StoreResult<NativeProviderEvent> {
    let event = metadata.get("native_event").ok_or_else(|| {
        StoreError::Conflict("native provider evidence is missing event".to_owned())
    })?;
    let kind = event
        .get("event_kind")
        .and_then(Value::as_str)
        .and_then(native_event_kind_from_str)
        .ok_or_else(|| {
            StoreError::Conflict("native provider evidence has invalid event kind".to_owned())
        })?;
    if !kind.is_terminal() {
        return Err(StoreError::Conflict(
            "native provider recovery requires terminal evidence".to_owned(),
        ));
    }
    Ok(NativeProviderEvent {
        provider_id: event
            .get("provider_id")
            .and_then(Value::as_str)
            .unwrap_or(execution.provider)
            .to_owned(),
        run_id: event
            .get("run_id")
            .and_then(Value::as_str)
            .unwrap_or(execution.run_id)
            .to_owned(),
        event_kind: kind,
        provider_event_type: event
            .get("provider_event_type")
            .and_then(Value::as_str)
            .unwrap_or("whip.native.recovered")
            .to_owned(),
        provider_session_id: event
            .get("provider_session_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        provider_turn_id: event
            .get("provider_turn_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        sequence: event.get("sequence").and_then(Value::as_u64),
        evidence: json!({
            "recovery": "native_provider_terminal_evidence",
            "provider_payload_shape": event.get("evidence_shape").cloned().unwrap_or(Value::Null),
        }),
        artifacts: Vec::new(),
    })
}

fn native_boundary_error_event(
    execution: AgentTurnExecution<'_>,
    error: provider::NativeProviderBoundaryError,
) -> NativeProviderEvent {
    let redacted = error.to_json_redacted();
    NativeProviderEvent {
        provider_id: error.provider_id,
        run_id: execution.run_id.to_owned(),
        event_kind: NativeProviderEventKind::Failed,
        provider_event_type: format!("whip.native.boundary_error.{}", error.code),
        provider_session_id: None,
        provider_turn_id: None,
        sequence: None,
        evidence: json!({
            "boundary_error": redacted,
            "recoverable": error.recoverable,
        }),
        artifacts: Vec::new(),
    }
}

fn redacted_native_artifact_ref(artifact: &NativeProviderArtifactRef) -> NativeProviderArtifactRef {
    let redacted = artifact.to_json_redacted();
    NativeProviderArtifactRef {
        artifact_id: redacted
            .get("artifact_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        kind: redacted
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("artifact")
            .to_owned(),
        uri: redacted
            .get("uri")
            .and_then(Value::as_str)
            .unwrap_or("provider://redacted/artifact")
            .to_owned(),
        content_hash: redacted
            .get("content_hash")
            .and_then(Value::as_str)
            .map(str::to_owned),
        mime_type: redacted
            .get("mime_type")
            .and_then(Value::as_str)
            .map(str::to_owned),
        required: redacted
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    }
}

fn native_provider_event_observation(event: &NativeProviderEvent) -> NativeAgentTurnObservation {
    let kind = match event.event_kind {
        NativeProviderEventKind::Started => AgentTurnLifecycleKind::Started,
        NativeProviderEventKind::Streamed | NativeProviderEventKind::Diagnostic => {
            AgentTurnLifecycleKind::Streamed
        }
        NativeProviderEventKind::ToolRequested => AgentTurnLifecycleKind::ToolRequested,
        NativeProviderEventKind::ArtifactCaptured => AgentTurnLifecycleKind::ArtifactCaptured,
        NativeProviderEventKind::Completed => AgentTurnLifecycleKind::Completed,
        NativeProviderEventKind::Failed => AgentTurnLifecycleKind::Failed,
        NativeProviderEventKind::TimedOut => AgentTurnLifecycleKind::TimedOut,
        NativeProviderEventKind::Cancelled => AgentTurnLifecycleKind::Cancelled,
    };
    NativeAgentTurnObservation::fixture(
        kind,
        event.provider_event_type.clone(),
        event.provider_session_id.clone(),
        event.provider_turn_id.clone(),
        json!({
            "type": "object",
            "keys": event
                .evidence
                .as_object()
                .map(serde_json::Map::len)
                .unwrap_or(0),
        }),
    )
}

fn enforce_required_artifact_capture_failure(result: &mut ProviderRunResult) {
    let required_artifact_capture_failed = result
        .failure
        .as_ref()
        .is_some_and(|failure| failure.phase == artifact_manifest::ARTIFACT_CAPTURE_FAILED_EVENT);
    if result.status == ProviderRunStatus::Completed && required_artifact_capture_failed {
        result.status = ProviderRunStatus::Failed;
        if !result.summary.contains("artifact capture failed") {
            result.summary = format!("artifact capture failed: {}", result.summary);
        }
    }
}

fn recover_provider_status(metadata: &Value) -> ProviderRunStatus {
    match metadata.get("status").and_then(Value::as_str) {
        Some("completed") => ProviderRunStatus::Completed,
        Some("timed_out") => ProviderRunStatus::TimedOut,
        Some("failed") => ProviderRunStatus::Failed,
        _ => {
            let failure_phase = metadata
                .pointer("/failure/phase")
                .and_then(Value::as_str)
                .unwrap_or("");
            if failure_phase == "provider.timeout" {
                ProviderRunStatus::TimedOut
            } else if metadata
                .get("failure")
                .is_some_and(|failure| !failure.is_null())
            {
                ProviderRunStatus::Failed
            } else {
                ProviderRunStatus::Completed
            }
        }
    }
}

fn provider_failure_from_json(value: &Value) -> Option<ProviderFailure> {
    if value.is_null() {
        return None;
    }
    Some(ProviderFailure {
        provider: value
            .get("provider")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        adapter: value
            .get("adapter")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        phase: value
            .get("phase")
            .and_then(Value::as_str)
            .unwrap_or("provider.recovered.failed")
            .to_owned(),
        error_kind: value
            .get("error_kind")
            .and_then(Value::as_str)
            .unwrap_or("recovered_failure")
            .to_owned(),
        message: value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("recovered provider failure")
            .to_owned(),
        recoverable: value
            .get("recoverable")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        retry_after: value
            .get("retry_after")
            .and_then(Value::as_str)
            .map(str::to_owned),
        workspace_id: value
            .get("workspace_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        provider_session_id: value
            .get("provider_session_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        provider_thread_id: value
            .get("provider_thread_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        missing_config_keys: value
            .get("missing_config_keys")
            .and_then(Value::as_array)
            .map(|keys| {
                keys.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        raw_json: None,
    })
}

fn provider_failure_code<'a>(
    failure: Option<&'a ProviderFailure>,
    fallback_status: &'static str,
) -> &'a str {
    failure
        .map(|failure| failure.error_kind.as_str())
        .unwrap_or(fallback_status)
}

fn provider_effect_status(status: &ProviderRunStatus) -> EffectStatus {
    match status {
        ProviderRunStatus::Completed => EffectStatus::Completed,
        ProviderRunStatus::Failed => EffectStatus::Failed,
        ProviderRunStatus::TimedOut => EffectStatus::TimedOut,
        ProviderRunStatus::Cancelled => EffectStatus::Cancelled,
    }
}

fn provider_metadata(result: &ProviderRunResult) -> Value {
    json!({
        "stdout": redacted_text_metadata(&result.stdout),
        "stderr": redacted_text_metadata(&result.stderr),
        "transcript": redacted_text_metadata(&result.transcript),
        "usage": json_from_str(&result.usage_json),
        "failure": result.failure.as_ref().map(provider_failure_json),
    })
}

fn provider_terminal_metadata(
    instance_id: &str,
    run_id: &str,
    result: &ProviderRunResult,
    run_metadata_json: &str,
) -> (String, String, String) {
    let provider_correlation_id = provider_terminal_correlation_id(instance_id, run_id);
    let metadata = add_provider_correlation_id(
        merge_provider_run_metadata(provider_metadata(result), run_metadata_json),
        &provider_correlation_id,
    );
    let terminal_hash = terminal_payload_hash(
        provider_status(&result.status),
        result.exit_code,
        Some(&result.summary),
        &metadata.to_string(),
    );
    (
        add_terminal_payload_hash(metadata, &terminal_hash),
        terminal_hash,
        provider_correlation_id,
    )
}

fn merge_provider_run_metadata(mut metadata: Value, run_metadata_json: &str) -> Value {
    let Value::Object(run_metadata) = json_from_str(run_metadata_json) else {
        return metadata;
    };
    if let Value::Object(object) = &mut metadata {
        for (key, value) in run_metadata {
            object.entry(key).or_insert(value);
        }
    }
    metadata
}

fn provider_terminal_correlation_id(instance_id: &str, run_id: &str) -> String {
    idempotency_key(&[instance_id, run_id, "provider"])
}

fn terminal_completion_idempotency_key(
    instance_id: &str,
    run_id: &str,
    provider_correlation_id: &str,
    terminal_hash: &str,
) -> String {
    idempotency_key(&[
        instance_id,
        run_id,
        provider_correlation_id,
        terminal_hash,
        "terminal",
    ])
}

fn terminal_payload_hash(
    status: &str,
    exit_code: Option<i64>,
    summary: Option<&str>,
    metadata_json: &str,
) -> String {
    stable_hash_hex(
        &json!({
            "status": status,
            "exit_code": exit_code,
            "summary": summary,
            "metadata": json_from_str(metadata_json),
        })
        .to_string(),
    )
}

fn add_provider_correlation_id(mut metadata: Value, provider_correlation_id: &str) -> Value {
    if let Value::Object(ref mut object) = metadata {
        object.insert(
            "provider_correlation_id".to_owned(),
            Value::String(provider_correlation_id.to_owned()),
        );
    }
    metadata
}

fn add_terminal_payload_hash(mut metadata: Value, terminal_hash: &str) -> String {
    if let Value::Object(ref mut object) = metadata {
        object.insert(
            "terminal_payload_hash".to_owned(),
            Value::String(terminal_hash.to_owned()),
        );
    }
    metadata.to_string()
}

fn redacted_provider_summary(summary: &str) -> String {
    redact_log_text(summary)
}

fn provider_failure_json(failure: &ProviderFailure) -> serde_json::Value {
    json!({
        "provider": failure.provider,
        "adapter": failure.adapter,
        "phase": failure.phase,
        "error_kind": failure.error_kind,
        "message": provider_failure_summary_message(&failure.message),
        "recoverable": failure.recoverable,
        "retry_after": failure.retry_after,
        "workspace_id": failure.workspace_id,
        "provider_session_id": failure.provider_session_id,
        "provider_thread_id": failure.provider_thread_id,
        "missing_config_keys": failure.missing_config_keys,
        "raw": failure.raw_json.as_deref().map(json_payload_summary),
    })
}

fn provider_failure_summary_message(message: &str) -> String {
    let summary = message
        .split_once(':')
        .map_or(message, |(summary, _)| summary);
    redact_log_text(summary.trim())
}

fn provider_diagnostic_message(provider: &str, summary: &str, diagnostics_json: &str) -> String {
    let diagnostics = serde_json::from_str::<Value>(diagnostics_json).unwrap_or(Value::Null);
    let primary_detail = diagnostics
        .get("failure")
        .and_then(|failure| failure.get("message"))
        .and_then(Value::as_str)
        .or_else(|| {
            diagnostics
                .get("error")
                .and_then(|error| {
                    error
                        .get("message")
                        .or_else(|| error.get("reason"))
                        .or(Some(error))
                })
                .and_then(Value::as_str)
        })
        .map(str::trim)
        .filter(|detail| !detail.is_empty());
    let stderr_detail = diagnostics
        .get("stderr")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|detail| !detail.is_empty());
    let mut message = format!("{provider} provider diagnostic: {summary}");
    if let Some(detail) = primary_detail {
        if !message.contains(detail) {
            message.push_str(": ");
            message.push_str(detail);
        }
    }
    if let Some(stderr) = stderr_detail {
        if !message.contains(stderr) {
            message.push_str(": ");
            message.push_str(stderr);
        }
    }
    redact_log_text(&message)
}

fn coerce_status(status: &CoerceStatus) -> &'static str {
    match status {
        CoerceStatus::Succeeded => "completed",
        CoerceStatus::Failed => "failed",
        CoerceStatus::TimedOut => "timed_out",
    }
}

fn coerce_effect_status(status: &CoerceStatus) -> EffectStatus {
    match status {
        CoerceStatus::Succeeded => EffectStatus::Completed,
        CoerceStatus::Failed => EffectStatus::Failed,
        CoerceStatus::TimedOut => EffectStatus::TimedOut,
    }
}

fn coerce_exit_code(status: &CoerceStatus) -> Option<i64> {
    match status {
        CoerceStatus::Succeeded => Some(0),
        CoerceStatus::Failed => Some(1),
        CoerceStatus::TimedOut => None,
    }
}

/// Build a coerce run's start metadata, carrying the runtime-resolved model
/// under the store's fingerprint-model key so `start_run` folds it into the
/// execution fingerprint (DR-0014). No model (or empty) yields `{}`, leaving the
/// fingerprint model-insensitive exactly as before.
fn coerce_run_start_metadata(model: Option<&str>) -> String {
    match model.filter(|model| !model.is_empty()) {
        Some(model) => {
            let mut map = serde_json::Map::new();
            map.insert(
                whipplescript_store::FINGERPRINT_MODEL_METADATA_KEY.to_owned(),
                serde_json::Value::String(model.to_owned()),
            );
            serde_json::Value::Object(map).to_string()
        }
        None => "{}".to_owned(),
    }
}

fn coerce_metadata(result: &CoerceResult) -> String {
    json!({
        "value": result.value_json.as_deref().map(json_payload_summary),
        "error": result_error_payload(result.error_json.as_deref()),
        "transcript": redacted_text_metadata(&result.transcript),
        "usage": json_from_str(&result.usage_json),
    })
    .to_string()
}

fn string_array_field(value: &Value, field: &str) -> Option<Vec<String>> {
    value.get(field)?.as_array().map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

/// Placeholder kernel entry point.
///
/// The real kernel will own rule commits, effect graph enqueueing, dependency
/// release, leases, retries, and trace emission.
pub fn kernel_stage() -> &'static str {
    whipplescript_store::store_stage()
}

#[cfg(test)]
mod tests {
    use super::*;
    use coerce::{CoerceRequest, FakeCoerceClient};
    use harness::{ClaudeCodeAgentHarness, CodexAgentHarness, CommandLaunchPlan, MockAgentHarness};
    use native_lifecycle::AgentTurnLifecycleKind;
    use provider::{
        builtin_provider_capabilities, CancellationDepth, NativeProviderBoundaryError,
        NativeProviderCancellation, ProviderCapability,
    };
    use std::{fs, path::PathBuf, process::Command};
    use trace::check_trace;
    use whipplescript_parser::compile_program;
    use whipplescript_store::{
        EffectCancellation, EffectCancellationRequest, EffectCompletion, LeaseRenewal, NewEffect,
        NewFact, RetryEffect, RevisionActivation, RuleCommit, RunStart, SkillRegistration,
    };

    #[test]
    fn every_new_model_visible_plane_maps_to_hash_or_derivative_evidence() {
        let (world_kind, world) =
            brokered_observation_evidence(&crate::harness_loop::LoopObservation::WorldProjected {
                epoch: 2,
                projection: "update".to_owned(),
                content_hash: "world-hash".to_owned(),
            });
        assert_eq!(world_kind, "context.world");
        assert_eq!(world["content_hash"], "world-hash");

        let (media_kind, media) =
            brokered_observation_evidence(&crate::harness_loop::LoopObservation::MediaNormalized {
                artifact_ref: "artifact:image".to_owned(),
                media_type: "image/png".to_owned(),
                normalization: "provider_image".to_owned(),
                derivative_hash: Some("derivative-hash".to_owned()),
            });
        assert_eq!(media_kind, "context.media_normalized");
        assert_eq!(media["artifact_ref"], "artifact:image");
        assert_eq!(media["derivative_hash"], "derivative-hash");
    }

    #[test]
    fn kernel_scaffold_links_to_store() {
        assert_eq!(kernel_stage(), whipplescript_core::IMPLEMENTATION_STAGE);
    }

    #[test]
    fn derives_deterministic_idempotency_keys() {
        let first = idempotency_key(&["instance-a", "rule", "start"]);
        let second = idempotency_key(&["instance-a", "rule", "start"]);
        let different = idempotency_key(&["instance-a", "rule", "again"]);

        assert_eq!(first, second);
        assert_ne!(first, different);
        assert!(first.starts_with("key_"));
    }

    #[test]
    fn analysis_summary_hashes_generated_declarations() {
        let compiled = compile_program(
            r#"
pattern Review<Input> {
  class Result {
    item Input
  }

  rule dispatch
    when Input as item
  => {
  }
}

workflow Root {
  class Task {
    title string
  }

  apply Review<Task> as taskReview {
  }
}
"#,
        );
        assert_eq!(compiled.diagnostics, Vec::new());
        let program = compiled.ir.expect("program compiles");

        let summary = serde_json::from_str::<Value>(&program_analysis_summary_json(&program))
            .expect("analysis summary is valid JSON");
        assert!(summary
            .get("schemas")
            .and_then(Value::as_array)
            .expect("schemas")
            .iter()
            .any(|schema| {
                schema.get("name").and_then(Value::as_str) == Some("Task")
                    && schema
                        .pointer("/source_span/construct")
                        .and_then(Value::as_str)
                        == Some("class")
            }));
        let hashes = summary
            .get("generated_declaration_hashes")
            .and_then(Value::as_array)
            .expect("generated declaration hashes are present");
        let class_hash = hashes
            .iter()
            .find(|entry| {
                entry.get("declaration").and_then(Value::as_str) == Some("class:taskReview_Result")
            })
            .expect("generated class hash is present");
        let rule_hash = hashes
            .iter()
            .find(|entry| {
                entry.get("declaration").and_then(Value::as_str) == Some("rule:taskReview_dispatch")
            })
            .expect("generated rule hash is present");

        for entry in [class_hash, rule_hash] {
            let hash = entry
                .get("hash")
                .and_then(Value::as_str)
                .expect("hash is a string");
            assert_eq!(hash.len(), 32);
            assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
            assert_ne!(entry.get("missing").and_then(Value::as_bool), Some(true));
        }
    }

    #[test]
    fn analysis_summary_reports_a_stable_whole_closure_bundle_hash() {
        // The compiled-IR report carries a single `bundle_hash` fingerprinting the
        // whole include closure (in addition to per-include `source_hash`). It is
        // deterministic, present for an include-free program, and changes iff the
        // closure changes (a member added, or a member's content changed).
        let compiled = compile_program(
            r#"
workflow Root {
  output result Done
  class Done { note string }

  rule finish
    when Done as d
  => {
    complete result { note d.note }
  }
}
"#,
        );
        assert_eq!(compiled.diagnostics, Vec::new());
        let base = compiled.ir.expect("program compiles");

        let bundle_hash = |program: &IrProgram| {
            serde_json::from_str::<Value>(&program_analysis_summary_json(program))
                .expect("valid JSON")
                .get("bundle_hash")
                .and_then(Value::as_str)
                .expect("bundle_hash present")
                .to_owned()
        };

        // Include-free closure: deterministic 32-hex fingerprint.
        let empty = bundle_hash(&base);
        assert_eq!(empty.len(), 32);
        assert!(empty.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert_eq!(empty, bundle_hash(&base), "same closure -> same hash");

        // Adding a closure member changes the bundle hash.
        let mut with_one = base.clone();
        with_one.includes.push(whipplescript_parser::IrInclude {
            path: "lib.whip".to_owned(),
            source_hash: Some("aaaa".to_owned()),
        });
        let one = bundle_hash(&with_one);
        assert_ne!(one, empty, "adding an include changes the bundle hash");

        // Changing a member's content changes the bundle hash.
        let mut changed = base.clone();
        changed.includes.push(whipplescript_parser::IrInclude {
            path: "lib.whip".to_owned(),
            source_hash: Some("bbbb".to_owned()),
        });
        assert_ne!(
            bundle_hash(&changed),
            one,
            "changed include content changes the bundle hash"
        );
    }

    #[test]
    fn idempotent_revision_activation_emits_trace_once_from_stored_event() {
        let compiled = compile_program(
            r#"
workflow RevisionTrace

rule noop
  when started
=> {
}
"#,
        );
        assert_eq!(compiled.diagnostics, Vec::new());
        let program = compiled.ir.expect("program compiles");
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version1 = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "source-1",
                    ir_hash: "ir-1",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("first version creates");
        let version2 = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "source-2",
                    ir_hash: "ir-2",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("second version creates");
        let instance_id = kernel
            .create_instance(&version1, "{}")
            .expect("instance creates");

        let first = kernel
            .activate_revision(RevisionActivation {
                instance_id: &instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                rule_carries_json: "[]",
                rule_correspondence_json: "null",
                idempotency_key: Some("revise-once"),
            })
            .expect("revision activates");
        let retry = kernel
            .activate_revision(RevisionActivation {
                instance_id: &instance_id,
                from_version_id: &version1.version_id,
                to_version_id: &version2.version_id,
                activation_policy_json: "{}",
                cancellation_policy: "keep",
                rule_carries_json: "[]",
                rule_correspondence_json: "null",
                idempotency_key: Some("revise-once"),
            })
            .expect("idempotent retry returns existing revision");

        assert_eq!(retry.revision_id, first.revision_id);
        let activation_records = kernel
            .trace()
            .iter()
            .filter(|record| matches!(record.event, TraceEvent::RevisionActivated { .. }))
            .count();
        assert_eq!(activation_records, 1);
        check_trace(kernel.trace()).expect("revision trace remains conformant");
    }

    #[test]
    fn load_brokered_transcript_at_addresses_a_non_latest_checkpoint() {
        // RC-2 Delta B: given a cut coordinate N (an event-log sequence), the
        // transcript loads at the checkpoint that was CURRENT at N — the latest
        // `agent.turn.brokered.transcript` with sequence <= N — not the newest.
        // The unbounded latest-load is unchanged.
        let compiled = compile_program(
            r#"
workflow TranscriptCut

rule noop
  when started
=> {
}
"#,
        );
        assert_eq!(compiled.diagnostics, Vec::new());
        let program = compiled.ir.expect("program compiles");
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "source-1",
                    ir_hash: "ir-1",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("version creates");
        let instance_id = kernel.create_instance(&version, "{}").expect("instance");

        let effect_id = "eff-transcript";
        // Append three transcript checkpoints (steps 0..2) at increasing
        // sequences, each carrying a distinct user message so the loaded
        // checkpoint is identifiable.
        let mut step_sequences = Vec::new();
        for step in 0..3 {
            let messages = vec![crate::harness_loop::ChatMessage::user_text(format!(
                "step-{step}"
            ))];
            let payload = json!({
                "effect_id": effect_id,
                "messages": crate::harness_loop::chat_messages_to_json(&messages),
            })
            .to_string();
            let key = idempotency_key(&[&instance_id, effect_id, "transcript", &step.to_string()]);
            let stored = kernel
                .store
                .append_event(whipplescript_store::NewEvent {
                    instance_id: &instance_id,
                    event_type: "agent.turn.brokered.transcript",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: None,
                    correlation_id: Some(effect_id),
                    idempotency_key: Some(&key),
                })
                .expect("transcript event appends");
            step_sequences.push(stored.sequence);
        }

        let text_of = |messages: &[crate::harness_loop::ChatMessage]| -> String {
            match messages.first().expect("one message") {
                crate::harness_loop::ChatMessage::User { text, .. } => text.clone(),
                other => panic!("expected user message, got {other:?}"),
            }
        };

        // Cut AT step 1's sequence: load the step-1 checkpoint, not step-2.
        let at_mid = kernel.load_brokered_transcript_at(&instance_id, effect_id, step_sequences[1]);
        assert_eq!(text_of(&at_mid), "step-1", "cut at N loads the step <= N");

        // A cut BETWEEN step 1 and step 2 still resolves to step 1.
        let between =
            kernel.load_brokered_transcript_at(&instance_id, effect_id, step_sequences[2] - 1);
        assert_eq!(
            text_of(&between),
            "step-1",
            "cut below step-2 stays at step-1"
        );

        // The unbounded latest-load is unchanged — it returns the newest (step 2).
        let latest = kernel.load_brokered_transcript(&instance_id, effect_id);
        assert_eq!(
            text_of(&latest),
            "step-2",
            "unbounded load returns the latest"
        );

        // A cut before any checkpoint yields an empty transcript.
        let before =
            kernel.load_brokered_transcript_at(&instance_id, effect_id, step_sequences[0] - 1);
        assert!(
            before.is_empty(),
            "cut before the first checkpoint is empty"
        );
    }

    #[test]
    fn load_brokered_transcript_rewinds_past_a_restore_marker() {
        // RC-4c: the transcript plane rewinds with the other planes. After a
        // `context.restored` marker to step-1's sequence, the unbounded latest
        // load returns step-1 (step-2 is abandoned), and a post-restore
        // checkpoint (step-3) becomes the new latest.
        let compiled = compile_program(
            r#"
workflow TranscriptRestore

rule noop
  when started
=> {
}
"#,
        );
        assert_eq!(compiled.diagnostics, Vec::new());
        let program = compiled.ir.expect("program compiles");
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "source-1",
                    ir_hash: "ir-1",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("version creates");
        let instance_id = kernel.create_instance(&version, "{}").expect("instance");
        let effect_id = "eff-transcript";

        let append_transcript = |kernel: &mut RuntimeKernel<SqliteStore>, step: i64| -> i64 {
            let messages = vec![crate::harness_loop::ChatMessage::user_text(format!(
                "step-{step}"
            ))];
            let payload = json!({
                "effect_id": effect_id,
                "messages": crate::harness_loop::chat_messages_to_json(&messages),
            })
            .to_string();
            let key = idempotency_key(&[&instance_id, effect_id, "transcript", &step.to_string()]);
            kernel
                .store
                .append_event(whipplescript_store::NewEvent {
                    instance_id: &instance_id,
                    event_type: "agent.turn.brokered.transcript",
                    payload_json: &payload,
                    source: "kernel",
                    causation_id: None,
                    correlation_id: Some(effect_id),
                    idempotency_key: Some(&key),
                })
                .expect("transcript appends")
                .sequence
        };
        let text_of = |messages: &[crate::harness_loop::ChatMessage]| -> String {
            match messages.first().expect("one message") {
                crate::harness_loop::ChatMessage::User { text, .. } => text.clone(),
                other => panic!("expected user message, got {other:?}"),
            }
        };

        let step0 = append_transcript(&mut kernel, 0);
        append_transcript(&mut kernel, 1);
        // Before any restore, the latest is step-1.
        assert_eq!(
            text_of(&kernel.load_brokered_transcript(&instance_id, effect_id)),
            "step-1"
        );

        // Restore to step-0's sequence: step-1 is abandoned.
        let marker_payload = json!({ "restored_to_sequence": step0 }).to_string();
        kernel
            .store
            .append_event(whipplescript_store::NewEvent {
                instance_id: &instance_id,
                event_type: "context.restored",
                payload_json: &marker_payload,
                source: "restorable-context",
                causation_id: None,
                correlation_id: None,
                idempotency_key: Some("restore-marker-1"),
            })
            .expect("marker appends");
        assert_eq!(
            text_of(&kernel.load_brokered_transcript(&instance_id, effect_id)),
            "step-0",
            "the latest live transcript rewinds past the abandoned step-1"
        );

        // Post-restore work (step-3) is live and becomes the new latest.
        append_transcript(&mut kernel, 3);
        assert_eq!(
            text_of(&kernel.load_brokered_transcript(&instance_id, effect_id)),
            "step-3",
            "post-restore transcript is live"
        );
    }

    #[test]
    fn delegated_context_attestation_is_tagged_provider_assembled() {
        // DR-0034 Decision 5 (D8-2): the kernel-owned attestation contract. A
        // Delegated turn records ONE `context.attestation` row tagged
        // `context: provider-assembled`, carrying provider identity/kind plus the
        // prompt and policy hashes — never the hermetic `context.bundle` provenance.
        let compiled = compile_program(
            r#"
workflow AttestationContract

agent worker {
  provider native-fixture
  profile "repo-writer"
  capacity 1
}

rule noop
  when started
=> {
}
"#,
        );
        let program = compiled.ir.expect("program compiles");
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "source-1",
                    ir_hash: "ir-1",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");

        let execution = AgentTurnExecution {
            instance_id: &instance_id,
            effect_id: "eff-1",
            run_id: "run-1",
            provider: "native-fixture",
            worker_id: "whip-worker",
            lease_id: "lease-1",
            lease_expires_at: "2030-01-01T00:00:00Z",
            agent: "worker",
            profile: Some("repo-writer"),
            input_json: r#"{"message":"delegated context is provider-assembled"}"#,
            skill_names: &[],
        };
        kernel
            .record_delegated_context_attestation(execution, "native-fixture", r#"["agent.tell"]"#)
            .expect("attestation records");

        let evidence = kernel
            .store()
            .list_evidence(&instance_id)
            .expect("evidence lists");
        let attestations = evidence
            .iter()
            .filter(|row| row.kind == "context.attestation")
            .collect::<Vec<_>>();
        assert_eq!(attestations.len(), 1, "exactly one attestation row");
        assert!(
            !evidence.iter().any(|row| row.kind == "context.bundle"),
            "a delegated turn fabricates no context.bundle provenance"
        );
        let metadata: Value =
            serde_json::from_str(&attestations[0].metadata_json).expect("attestation metadata");
        assert_eq!(
            metadata.get("context").and_then(Value::as_str),
            Some("provider-assembled")
        );
        assert_eq!(
            metadata.get("kind").and_then(Value::as_str),
            Some("native-fixture")
        );
        assert_eq!(
            metadata.get("profile").and_then(Value::as_str),
            Some("repo-writer")
        );
        // The prompt and policy hashes are present, non-empty, and distinct.
        let prompt_hash = metadata
            .get("prompt_hash")
            .and_then(Value::as_str)
            .expect("prompt hash");
        let policy_hash = metadata
            .get("policy_hash")
            .and_then(Value::as_str)
            .expect("policy hash");
        assert!(!prompt_hash.is_empty() && !policy_hash.is_empty());
        assert_ne!(prompt_hash, policy_hash);
    }

    #[test]
    fn program_agent_declarations_drive_capacity_blocks() {
        let compiled = compile_program(
            r#"
workflow CapacityFromSource

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
  capabilities ["agent.tell"]
}

rule start
  when started
=> {
  tell worker "one"
  tell worker "two"
}
"#,
        );
        let program = compiled.ir.expect("program compiles");
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "source",
                    ir_hash: "ir",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [
            NewEffect {
                timeout_seconds: None,
                effect_id: "tell-one",
                kind: "agent.tell",
                target: Some("worker"),
                input_json: r#"{"prompt":"one"}"#,
                status: "queued",
                idempotency_key: "rule=start;effect=tell-one",
                required_capabilities_json: "[]",
                profile: Some("repo-writer"),
                correlation_id: None,
                source_span_json: None,
            },
            NewEffect {
                timeout_seconds: None,
                effect_id: "tell-two",
                kind: "agent.tell",
                target: Some("worker"),
                input_json: r#"{"prompt":"two"}"#,
                status: "queued",
                idempotency_key: "rule=start;effect=tell-two",
                required_capabilities_json: "[]",
                profile: Some("repo-writer"),
                correlation_id: None,
                source_span_json: None,
            },
        ];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        kernel
            .start_run(RunStart {
                instance_id: &instance_id,
                effect_id: "tell-one",
                run_id: "run-one",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-one",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("first run starts");

        let blocked = kernel.start_run(RunStart {
            instance_id: &instance_id,
            effect_id: "tell-two",
            run_id: "run-two",
            provider: "test",
            worker_id: "worker-1",
            lease_id: "lease-two",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        });

        assert!(
            matches!(blocked, Err(StoreError::PolicyBlocked { reason, .. }) if reason.contains("capacity exhausted"))
        );
        assert!(kernel.trace().iter().any(|record| matches!(
            &record.event,
            TraceEvent::EffectBlocked {
                effect_id, reason, ..
            }
                if effect_id == "tell-two" && reason.contains("capacity exhausted")
        )));
        let store = kernel.into_store();
        let effects = store.list_effects(&instance_id).expect("effects load");
        let second = effects
            .iter()
            .find(|effect| effect.effect_id == "tell-two")
            .expect("second effect exists");
        assert_eq!(second.status, "blocked_by_capacity");
        assert!(second
            .policy_block_reason
            .as_deref()
            .expect("capacity reason")
            .contains("capacity exhausted"));
    }

    #[test]
    fn program_agent_capabilities_block_mismatched_effects() {
        let compiled = compile_program(
            r#"
workflow CapabilityFromSource

agent worker {
  provider fixture
  profile "repo-writer"
  capacity 1
  capabilities ["agent.tell"]
}

rule start
  when started
=> {
  tell worker "write"
}
"#,
        );
        let program = compiled.ir.expect("program compiles");
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "source",
                    ir_hash: "ir",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell-write",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"write"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell-write",
            required_capabilities_json: r#"["repo.write"]"#,
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let blocked = kernel.start_run(RunStart {
            instance_id: &instance_id,
            effect_id: "tell-write",
            run_id: "run-write",
            provider: "test",
            worker_id: "worker-1",
            lease_id: "lease-write",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        });

        assert!(
            matches!(blocked, Err(StoreError::PolicyBlocked { reason, .. }) if reason.contains("does not declare required capability `repo.write`"))
        );
    }

    #[test]
    fn kernel_creates_program_instance_and_ingests_external_event() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "Ralph",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let event = kernel
            .ingest_external_event(&instance_id, "external.started", "{}", Some("start"))
            .expect("event ingests");

        // Sequence 1 is `instance.created` (DR-0094); this is the event after it.
        assert_eq!(event.sequence, 2);
        assert!(instance_id.starts_with("ins_"));
    }

    #[test]
    fn kernel_derives_facts_and_evaluates_ready_rules() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let compiled = compile_program(
            r#"
workflow Ready

rule begin
  when started
=> {
}

rule wait
  when missing
=> {
}
"#,
        );
        let program = compiled.ir.expect("program compiles");

        let before = kernel
            .evaluate_rules("instance-a", &program)
            .expect("rules evaluate");
        assert!(before.is_empty());

        kernel
            .derive_fact(
                "instance-a",
                "pattern:started",
                "started",
                "{}",
                None,
                Some("derive-started"),
            )
            .expect("fact derives");
        let after = kernel
            .evaluate_rules("instance-a", &program)
            .expect("rules evaluate after fact");

        assert_eq!(after, vec!["begin".to_owned()]);
    }

    #[test]
    fn kernel_commits_rule_rewrite_with_effect_graph() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let facts = [NewFact {
            fact_id: "fact-1",
            name: "WorkItem",
            key: "issue-1",
            value_json: r#"{"title":"Implement"}"#,
            schema_id: Some("WorkItem"),
            provenance_class: "derived",
            correlation_id: None,
            source_span_json: None,
        }];
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        let event = kernel
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &facts,
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        assert_eq!(event.sequence, 1);
    }

    #[test]
    fn kernel_claims_and_completes_effect_run() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let claimable = kernel
            .claimable_effects("instance-a")
            .expect("claimable effects load");
        assert_eq!(claimable[0].effect_id, "tell");
        let started = kernel
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let completed = kernel
            .complete_run(EffectCompletion {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                status: "ignored",
                exit_code: Some(0),
                summary: Some("done"),
                metadata_json: "{}",
                idempotency_key: Some("complete-tell"),
            })
            .expect("run completes");

        assert_eq!(started.sequence, 2);
        assert_eq!(completed.sequence, 3);
        check_trace(kernel.trace()).expect("kernel trace conforms");
    }

    #[test]
    fn run_native_agent_turn_records_lifecycle_artifacts_and_terminal() {
        struct FakeAdapter {
            capability: provider::ProviderCapability,
            events: Vec<NativeProviderEvent>,
        }

        impl NativeProviderAdapter for FakeAdapter {
            fn provider_id(&self) -> &str {
                "native-fixture"
            }

            fn capability(&self) -> &provider::ProviderCapability {
                &self.capability
            }

            fn start_turn(
                &mut self,
                request: NativeProviderTurnRequest,
            ) -> Result<NativeProviderEvent, provider::NativeProviderBoundaryError> {
                Ok(NativeProviderEvent {
                    provider_id: "native-fixture".to_owned(),
                    run_id: request.run_id,
                    event_kind: NativeProviderEventKind::Started,
                    provider_event_type: "fixture.turn.started".to_owned(),
                    provider_session_id: Some("session-1".to_owned()),
                    provider_turn_id: Some("turn-1".to_owned()),
                    sequence: Some(1),
                    evidence: json!({"started": true}),
                    artifacts: Vec::new(),
                })
            }

            fn next_event(
                &mut self,
                _run_id: &str,
            ) -> Result<Option<NativeProviderEvent>, provider::NativeProviderBoundaryError>
            {
                Ok((!self.events.is_empty()).then(|| self.events.remove(0)))
            }

            fn cancel_turn(
                &mut self,
                _cancellation: provider::NativeProviderCancellation,
            ) -> Result<NativeProviderEvent, provider::NativeProviderBoundaryError> {
                unreachable!("cancel not used in this regression")
            }
        }

        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let capability = provider::ProviderCapability {
            provider_kind: "fixture".to_owned(),
            surface: "fixture".to_owned(),
            protocol_version: Some("fixture.v1".to_owned()),
            session_identity_fields: vec!["session".to_owned()],
            stream_event_kinds: vec!["fixture.turn.started".to_owned()],
            tool_policy: "fixture".to_owned(),
            cancellation_depths: vec![provider::CancellationDepth::CooperativeRequest],
            artifact_manifest: true,
            health_checks: Vec::new(),
            auth_requirements: Vec::new(),
        };
        let mut adapter = FakeAdapter {
            capability,
            events: vec![
                NativeProviderEvent {
                    provider_id: "native-fixture".to_owned(),
                    run_id: "run-tell".to_owned(),
                    event_kind: NativeProviderEventKind::Streamed,
                    provider_event_type: "fixture.turn.delta".to_owned(),
                    provider_session_id: Some("session-1".to_owned()),
                    provider_turn_id: Some("turn-1".to_owned()),
                    sequence: Some(2),
                    evidence: json!({"delta": 1}),
                    artifacts: Vec::new(),
                },
                NativeProviderEvent {
                    provider_id: "native-fixture".to_owned(),
                    run_id: "run-tell".to_owned(),
                    event_kind: NativeProviderEventKind::Streamed,
                    provider_event_type: "fixture.turn.delta".to_owned(),
                    provider_session_id: Some("session-1".to_owned()),
                    provider_turn_id: Some("turn-1".to_owned()),
                    sequence: Some(3),
                    evidence: json!({"delta": 2}),
                    artifacts: Vec::new(),
                },
                NativeProviderEvent {
                    provider_id: "native-fixture".to_owned(),
                    run_id: "run-tell".to_owned(),
                    event_kind: NativeProviderEventKind::ArtifactCaptured,
                    provider_event_type: "fixture.artifact.captured".to_owned(),
                    provider_session_id: Some("session-1".to_owned()),
                    provider_turn_id: Some("turn-1".to_owned()),
                    sequence: Some(4),
                    evidence: json!({"artifact": true}),
                    artifacts: vec![NativeProviderArtifactRef {
                        artifact_id: Some("artifact-1".to_owned()),
                        kind: "diff".to_owned(),
                        uri: "provider://native-fixture/runs/run-tell/diff".to_owned(),
                        content_hash: Some("sha256:abc".to_owned()),
                        mime_type: Some("text/x-diff".to_owned()),
                        required: true,
                    }],
                },
                NativeProviderEvent {
                    provider_id: "native-fixture".to_owned(),
                    run_id: "run-tell".to_owned(),
                    event_kind: NativeProviderEventKind::Completed,
                    provider_event_type: "fixture.turn.completed".to_owned(),
                    provider_session_id: Some("session-1".to_owned()),
                    provider_turn_id: Some("turn-1".to_owned()),
                    sequence: Some(5),
                    evidence: json!({"completed": true}),
                    artifacts: Vec::new(),
                },
            ],
        };

        let request = NativeProviderTurnRequest {
            provider_id: "native-fixture".to_owned(),
            provider_kind: "fixture".to_owned(),
            surface: "fixture".to_owned(),
            run_id: "run-tell".to_owned(),
            effect_id: "tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            prompt_json: json!({"prompt": "go"}),
            workspace_policy: provider::WorkspacePolicy::ReadOnly,
            required_capabilities: Vec::new(),
            cancellation_depth: provider::CancellationDepth::CooperativeRequest,
            artifact_policy: provider::ArtifactPolicy::Metadata,
            credential_ref: None,
            provider_options: std::collections::BTreeMap::new(),
        };

        let terminal = kernel
            .run_native_agent_turn_with_metadata(
                AgentTurnExecution {
                    instance_id: "instance-a",
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "native-fixture",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-writer"),
                    input_json: r#"{"prompt":"go"}"#,
                    skill_names: &[],
                },
                request,
                &mut adapter,
                8,
                r#"{"provider_selection":{"provider_id":"native-fixture","provider_kind":"native-fixture","source_harness_id":"fixtureHarness","surface":"fixture"}}"#,
            )
            .expect("native turn completes");
        assert!(terminal.sequence > 1);

        let runs = kernel.store.list_runs("instance-a").expect("runs list");
        assert_eq!(runs[0].status, "completed");
        let run_metadata = json_from_str(&runs[0].metadata_json);
        assert_eq!(
            run_metadata
                .pointer("/provider_selection/source_harness_id")
                .and_then(Value::as_str),
            Some("fixtureHarness")
        );
        assert_eq!(
            run_metadata
                .pointer("/native_provider/provider_id")
                .and_then(Value::as_str),
            Some("native-fixture")
        );
        let artifacts = kernel
            .store
            .list_artifacts_for_run("run-tell")
            .expect("artifacts list");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].kind, "diff");
        let facts = kernel.store.list_facts("instance-a").expect("facts list");
        // Only the durable lifecycle kinds are rule-matchable facts
        // (spec/agent-harness.md): started + completed here.
        assert!(facts.iter().any(|fact| fact.name == "agent.turn.started"));
        assert!(facts.iter().any(|fact| fact.name == "agent.turn.completed"));
        // In-turn observations are EVIDENCE, never facts — they must not appear
        // in the fact set (where they would inflate `facts=N` with values no
        // rule can match).
        assert_eq!(
            facts
                .iter()
                .filter(|fact| fact.name == "agent.turn.streamed")
                .count(),
            0,
            "streamed observations must not be derived as facts"
        );
        assert!(
            !facts
                .iter()
                .any(|fact| fact.name == "agent.turn.artifact_captured"),
            "artifact_captured observations must not be derived as facts"
        );
        // They are recorded as evidence instead: every native lifecycle
        // observation (terminal and in-turn) is durable evidence.
        let evidence = kernel.store.list_evidence("instance-a").expect("evidence");
        let streamed_evidence = evidence
            .iter()
            .filter(|record| {
                record.kind == "agent.turn.native_event"
                    && json_from_str(&record.metadata_json)
                        .pointer("/status")
                        .and_then(Value::as_str)
                        == Some("streamed")
            })
            .count();
        assert_eq!(
            streamed_evidence, 2,
            "streamed observations must be recorded as evidence"
        );
        assert!(
            evidence.iter().any(|record| {
                record.kind == "agent.turn.native_event"
                    && json_from_str(&record.metadata_json)
                        .pointer("/status")
                        .and_then(Value::as_str)
                        == Some("artifact_captured")
            }),
            "artifact_captured observation must be recorded as evidence"
        );
    }

    #[test]
    fn kernel_times_out_effect_run() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        kernel
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let timed_out = kernel
            .timeout_run(EffectCompletion {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                status: "ignored",
                exit_code: None,
                summary: Some("timeout"),
                metadata_json: "{}",
                idempotency_key: Some("timeout-tell"),
            })
            .expect("run times out");

        assert_eq!(timed_out.sequence, 3);
        check_trace(kernel.trace()).expect("kernel trace conforms");
    }

    #[test]
    fn kernel_expires_leases_and_retries_failed_effects() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: "instance-a",
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        kernel
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        kernel
            .renew_lease(LeaseRenewal {
                instance_id: "instance-a",
                lease_id: "lease-tell",
                run_id: "run-tell",
                new_expires_at: "2030-01-02T00:00:00Z",
                idempotency_key: Some("renew-tell"),
            })
            .expect("lease renews");
        let expired = kernel
            .expire_leases("instance-a", "2030-01-03T00:00:00Z")
            .expect("lease expires");
        assert_eq!(expired.len(), 1);
        let stale_completion = kernel.complete_run(EffectCompletion {
            instance_id: "instance-a",
            effect_id: "tell",
            run_id: "run-tell",
            provider: "test",
            worker_id: "worker-1",
            status: "ignored",
            exit_code: Some(0),
            summary: Some("late"),
            metadata_json: "{}",
            idempotency_key: Some("late-complete"),
        });
        assert!(stale_completion.is_err());

        kernel
            .start_run(RunStart {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell-2",
                provider: "test",
                worker_id: "worker-1",
                lease_id: "lease-tell-2",
                lease_expires_at: "2030-01-04T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("retry run starts after lease expiry");
        kernel
            .fail_run(EffectCompletion {
                instance_id: "instance-a",
                effect_id: "tell",
                run_id: "run-tell-2",
                provider: "test",
                worker_id: "worker-1",
                status: "ignored",
                exit_code: Some(1),
                summary: Some("failed"),
                metadata_json: "{}",
                idempotency_key: Some("fail-tell"),
            })
            .expect("run fails");
        kernel
            .retry_effect(RetryEffect {
                instance_id: "instance-a",
                effect_id: "tell",
                retry_after: Some("2030-01-05T00:00:00Z"),
                idempotency_key: Some("retry-tell"),
            })
            .expect("effect retries");

        check_trace(kernel.trace()).expect("kernel trace conforms");
    }

    /// DR-0076 P2: reaching a terminal discharges the holder's acquisitions,
    /// and `cancel_instance` is a way of reaching one. Before P2 the release
    /// lived in the CLI, bolted onto the call with `.inspect(...)`, so a caller
    /// that forgot left the lease held — the defect that shipped once already.
    /// The `Coordination + WorkItems` bound now makes forgetting a compile
    /// error; this asserts the release actually happens.
    #[test]
    fn cancel_instance_releases_the_holders_leases() {
        use whipplescript_store::coordination::{AcquireOutcome, Coordination};

        let store = whipplescript_store::native_stores::NativeStores::open_in_memory()
            .expect("stores open");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "Holder",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("version records");
        let instance_id = kernel.create_instance(&version, "{}").expect("instance");

        assert_eq!(
            Coordination::try_acquire(kernel.store_mut(), "env", "staging", 1, 60, &instance_id)
                .expect("lease acquires"),
            AcquireOutcome::Held,
        );
        assert_eq!(
            Coordination::list_leases(kernel.store(), Some("env"))
                .expect("leases list")
                .len(),
            1,
            "precondition: the instance holds the lease it is about to lose",
        );

        kernel
            .cancel_instance(&instance_id, Some("operator"), Some("cancel-instance"))
            .expect("instance cancels");

        assert!(
            Coordination::list_leases(kernel.store(), Some("env"))
                .expect("leases list")
                .is_empty(),
            "cancelling the holder released its lease without the caller asking",
        );
    }

    #[test]
    fn kernel_cancels_effect_and_instance() {
        let store = whipplescript_store::native_stores::NativeStores::open_in_memory()
            .expect("stores open");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "Lifecycle",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let cancelled_effect = kernel
            .cancel_effect(EffectCancellation {
                instance_id: &instance_id,
                effect_id: "tell",
                reason: Some("operator"),
                idempotency_key: Some("cancel-effect"),
            })
            .expect("effect cancels");
        let paused = kernel
            .pause_instance(&instance_id, Some("maintenance"), Some("pause"))
            .expect("instance pauses");
        let resumed = kernel
            .resume_instance(&instance_id, Some("resume"))
            .expect("instance resumes");
        let cancelled_instance = kernel
            .cancel_instance(&instance_id, Some("operator"), Some("cancel-instance"))
            .expect("instance cancels");

        // Shifted by `instance.created` at sequence 1 (DR-0094).
        assert_eq!(cancelled_effect.sequence, 3);
        // cancel_effect also derives the effect.cancelled settling fact, now at
        // sequence 4 -- every sequence here is one later than it was, because
        // `instance.created` takes sequence 1 (DR-0094).
        assert_eq!(paused.sequence, 5);
        assert_eq!(resumed.sequence, 6);
        assert_eq!(cancelled_instance.sequence, 7);
        check_trace(kernel.trace()).expect("kernel trace conforms");
    }

    #[test]
    fn kernel_fail_instance_internal_marks_failed_terminal() {
        let store = whipplescript_store::native_stores::NativeStores::open_in_memory()
            .expect("stores open");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "AutoFail",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        // Generic internal failure (flow auto-fail): no typed `failure` payload.
        kernel
            .fail_instance_internal(
                &instance_id,
                "unhandled effect failure in flow review",
                Some("autofail-1"),
            )
            .expect("instance fails internally");
        let instance = kernel
            .store
            .get_instance(&instance_id)
            .expect("instance loads")
            .expect("instance exists");
        assert_eq!(instance.status, "failed");
        check_trace(kernel.trace()).expect("kernel trace conforms");
    }

    #[test]
    fn kernel_emits_trace_for_profile_policy_blocks() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "Policy",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "write",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"write"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=write",
            required_capabilities_json: r#"["agent.tell","repo.write"]"#,
            profile: Some("repo-reader"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let blocked = kernel.start_run(RunStart {
            instance_id: &instance_id,
            effect_id: "write",
            run_id: "run-write",
            provider: "test",
            worker_id: "worker-1",
            lease_id: "lease-write",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        });

        assert!(matches!(blocked, Err(StoreError::PolicyBlocked { .. })));
        assert!(kernel.trace().iter().any(|record| matches!(
            &record.event,
            TraceEvent::EffectBlocked {
                effect_id, reason, ..
            }
                if effect_id == "write" && reason.contains("repo.write")
        )));
        check_trace(kernel.trace()).expect("kernel trace conforms");
    }

    #[test]
    fn mock_agent_harness_records_artifacts_evidence_and_turn_fact() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        store
            .register_skill(SkillRegistration {
                skill_id: "skill-repo-user",
                name: "repo-user",
                version: "1.0.0",
                source: "# Repo User\n",
                source_path: "skills/repo-user/SKILL.md",
                body: "# Repo User\nUse the repo carefully.\n",
                description: "Repo instructions",
                required_capabilities_json: r#"["repo.write"]"#,
                metadata_json: "{}",
            })
            .expect("skill registers");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "Harness",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let run_metadata_json = json!({
            "provider_selection": {
                "provider_id": "mock",
                "provider_kind": "fixture",
                "source_harness_id": "mock",
                "surface": Value::Null,
            }
        })
        .to_string();
        let terminal = kernel
            .run_agent_turn_with_metadata(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "mock",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-writer"),
                    input_json: r#"{"prompt":"go"}"#,
                    skill_names: &["repo-user"],
                },
                &MockAgentHarness::completed("done"),
                &run_metadata_json,
            )
            .expect("mock turn runs");

        // Shifted by `instance.created` at sequence 1 (DR-0094).
        assert_eq!(terminal.sequence, 4);
        check_trace(kernel.trace()).expect("kernel trace conforms");
        let mut store = kernel.into_store();
        let artifacts = store
            .list_artifacts_for_run("run-tell")
            .expect("artifacts list");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].kind, "transcript");

        let evidence = store.list_evidence(&instance_id).expect("evidence lists");
        assert_eq!(evidence.len(), 3);
        assert!(evidence
            .iter()
            .any(|evidence| evidence.kind == "rule.committed"
                && evidence.metadata_json.contains("tell")));
        assert!(evidence
            .iter()
            .any(|evidence| evidence.kind == "skills.injected"
                && evidence.metadata_json.contains("repo-user")));
        let provider_evidence = evidence
            .iter()
            .find(|evidence| evidence.kind == "agent.turn.provider")
            .expect("provider evidence recorded");
        let provider_metadata = serde_json::from_str::<Value>(&provider_evidence.metadata_json)
            .expect("provider metadata json");
        assert_eq!(
            provider_metadata
                .pointer("/stdout/redacted")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            provider_metadata
                .pointer("/transcript/redacted")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(provider_metadata.get("artifact_ids").is_some());
        assert_eq!(
            provider_metadata
                .pointer("/artifact_manifest/schema_version")
                .and_then(Value::as_str),
            Some(artifact_manifest::ARTIFACT_MANIFEST_SCHEMA_VERSION)
        );
        artifact_manifest::validate_artifact_manifest(
            provider_metadata
                .get("artifact_manifest")
                .expect("artifact manifest"),
        )
        .expect("artifact manifest validates");
        assert_eq!(
            provider_metadata
                .pointer("/artifact_manifest/entries/0/artifact_id")
                .and_then(Value::as_str),
            Some(artifacts[0].artifact_id.as_str())
        );
        assert_eq!(
            provider_metadata
                .pointer("/artifact_manifest/entries/0/retention_policy")
                .and_then(Value::as_str),
            Some("provider_default")
        );
        assert!(!provider_evidence.metadata_json.contains("mock stdout"));
        assert!(!provider_evidence.metadata_json.contains("mock transcript"));
        let links = store
            .list_evidence_links(&instance_id)
            .expect("evidence links list");
        assert!(links
            .iter()
            .any(|link| link.target_type == "effect" && link.target_id == "tell"));

        let facts = store.list_facts(&instance_id).expect("facts list");
        assert!(facts.iter().any(|fact| fact.name == "agent.turn.completed"
            && fact.value_json.contains("\"provider\":\"mock\"")));
        let events = store.list_events(&instance_id).expect("events list");
        let terminal_event = events
            .iter()
            .find(|event| event.event_type == "effect.terminal")
            .expect("terminal event exists");
        let terminal_payload =
            serde_json::from_str::<Value>(&terminal_event.payload_json).expect("terminal payload");
        assert!(terminal_payload
            .pointer("/metadata/provider_correlation_id")
            .and_then(Value::as_str)
            .is_some());
        assert!(terminal_payload
            .pointer("/metadata/terminal_payload_hash")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(
            terminal_payload
                .pointer("/metadata/provider_selection/source_harness_id")
                .and_then(Value::as_str),
            Some("mock")
        );
        let runs = store.list_runs(&instance_id).expect("runs list");
        assert_eq!(
            serde_json::from_str::<Value>(&runs[0].metadata_json)
                .expect("run metadata json")
                .pointer("/provider_selection/provider_kind")
                .and_then(Value::as_str),
            Some("fixture")
        );
        assert!(events
            .iter()
            .any(|event| event.event_type == "agent.turn.completed"));

        store
            .rebuild_projections(&instance_id)
            .expect("projections rebuild");
        let replayed_artifacts = store
            .list_artifacts_for_run("run-tell")
            .expect("replayed artifacts list");
        assert_eq!(replayed_artifacts.len(), 1);
        assert_eq!(replayed_artifacts[0].artifact_id, artifacts[0].artifact_id);
    }

    #[test]
    fn native_provider_lifecycle_observation_records_event_and_fact() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "NativeLifecycle",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        // Provider-agnostic: build the observation via the kernel's own
        // shape-only `fixture` constructor rather than reaching into a provider
        // crate's normalizer (that redaction is tested where the normalizer now
        // lives, whipplescript-provider-codex). This test owns the kernel's
        // record path: event + fact + evidence, no content leak.
        let observation = native_lifecycle::NativeAgentTurnObservation::fixture(
            AgentTurnLifecycleKind::Cancelled,
            "turn/completed",
            Some("session-1".to_owned()),
            Some("turn-1".to_owned()),
            json!({"type": "object", "keys": 4}),
        );
        assert_eq!(observation.kind, AgentTurnLifecycleKind::Cancelled);

        kernel
            .record_native_agent_turn_observation(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "codex-main",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-reader"),
                    input_json: r#"{"prompt":"go"}"#,
                    skill_names: &[],
                },
                &observation,
                "codex-turn-completed-1",
            )
            .expect("native lifecycle records");

        let store = kernel.into_store();
        let events = store.list_events(&instance_id).expect("events list");
        let event = events
            .iter()
            .find(|event| event.event_type == "agent.turn.cancelled")
            .expect("cancelled event recorded");
        let payload = serde_json::from_str::<Value>(&event.payload_json).expect("payload json");
        assert_eq!(
            payload.get("provider_event_type").and_then(Value::as_str),
            Some("turn/completed")
        );
        assert_eq!(payload.get("terminal").and_then(Value::as_bool), Some(true));
        let evidence_id = payload
            .get("evidence_id")
            .and_then(Value::as_str)
            .expect("event links evidence");
        assert!(!event.payload_json.contains("secret"));

        let facts = store.list_facts(&instance_id).expect("facts list");
        assert!(facts.iter().any(|fact| {
            fact.name == "agent.turn.cancelled"
                && fact.key != "run-tell"
                && fact.value_json.contains(r#""run_id":"run-tell""#)
                && !fact.value_json.contains("secret")
        }));
        let evidence = store.list_evidence(&instance_id).expect("evidence lists");
        let native_evidence = evidence
            .iter()
            .find(|evidence| evidence.evidence_id == evidence_id)
            .expect("native lifecycle evidence recorded");
        assert_eq!(native_evidence.kind, "agent.turn.native_event");
        assert_eq!(native_evidence.subject_type, "run");
        assert_eq!(native_evidence.subject_id, "run-tell");
        assert!(!native_evidence.metadata_json.contains("secret"));
    }

    #[test]
    fn artifact_capture_failure_records_redacted_event_and_diagnostic() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "ArtifactFailure",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");

        let event = kernel
            .record_artifact_capture_failure(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "codex",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-writer"),
                    input_json: "{}",
                    skill_names: &[],
                },
                ArtifactCaptureFailure {
                    provider: "codex",
                    adapter: "app_server",
                    run_id: "run-tell",
                    artifact_ref: "provider://codex/runs/run-tell/diff",
                    error_kind: "hash_mismatch",
                    recoverable: false,
                    message: "secret hash mismatch details",
                    transcript_ref: Some("provider://codex/runs/run-tell/transcript_ref"),
                    stderr_ref: None,
                },
                Some("artifact-capture-failed-run-tell"),
            )
            .expect("artifact capture failure records");

        let store = kernel.into_store();
        let events = store.list_events(&instance_id).expect("events list");
        let capture_event = events
            .iter()
            .find(|stored| stored.event_id == event.event_id)
            .expect("capture failure event exists");
        assert_eq!(
            capture_event.event_type,
            artifact_manifest::ARTIFACT_CAPTURE_FAILED_EVENT
        );
        assert!(capture_event
            .payload_json
            .contains("\"error_kind\":\"hash_mismatch\""));
        assert!(!capture_event
            .payload_json
            .contains("secret hash mismatch details"));
        let diagnostics = store
            .list_diagnostics(Some(&instance_id))
            .expect("diagnostics list");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].code.as_deref(),
            Some(artifact_manifest::ARTIFACT_CAPTURE_FAILED_EVENT)
        );
        assert_eq!(
            diagnostics[0].event_id.as_deref(),
            Some(event.event_id.as_str())
        );
        assert_eq!(diagnostics[0].effect_id.as_deref(), Some("tell"));
        assert_eq!(diagnostics[0].run_id.as_deref(), Some("run-tell"));
    }

    #[test]
    fn provider_secret_seed_never_reaches_durable_records() {
        struct SecretSeedHarness;

        impl AgentHarness for SecretSeedHarness {
            fn run(&self, _request: AgentTurnRequest) -> ProviderRunResult {
                let secret = "sk-test-secret-token-1234567890";
                ProviderRunResult {
                    status: ProviderRunStatus::Failed,
                    summary: format!("provider failed with token={secret}"),
                    stdout: format!("stdout {secret}\n"),
                    stderr: format!("stderr Bearer {secret}\n"),
                    transcript: format!("transcript api_key={secret}\n"),
                    exit_code: Some(1),
                    usage_json: r#"{"input_tokens":1,"output_tokens":0}"#.to_owned(),
                    artifacts: vec![harness::ProviderArtifact {
                        kind: "transcript".to_owned(),
                        path: format!("provider://codex/runs/run-tell/{secret}/transcript_ref"),
                        content_hash: Some(format!("sha256:{secret}")),
                        mime_type: Some("text/plain".to_owned()),
                    }],
                    failure: Some(
                        ProviderFailure::new(
                            "provider.fixture.failed",
                            "fixture_failure",
                            format!("failure token={secret}: stderr {secret}"),
                        )
                        .provider("codex")
                        .adapter("fixture")
                        .raw_json(format!(r#"{{"api_key":"{secret}","shape":"object"}}"#)),
                    ),
                }
            }
        }

        let secret = "sk-test-secret-token-1234567890";
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "SecretSeed",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: "{}",
            status: "queued",
            idempotency_key: "effect-tell",
            required_capabilities_json: "[]",
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start-secret-seed"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        kernel
            .run_agent_turn(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "codex",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-writer"),
                    input_json: r#"{"prompt":"go"}"#,
                    skill_names: &[],
                },
                &SecretSeedHarness,
            )
            .expect("secret-seeded turn runs");

        let store = kernel.into_store();
        let events = store.list_events(&instance_id).expect("events list");
        for event in &events {
            assert!(
                !event.payload_json.contains(secret),
                "event {} leaked secret: {}",
                event.event_type,
                event.payload_json
            );
        }
        let terminal_event = events
            .iter()
            .find(|event| event.event_type == "effect.terminal")
            .expect("terminal event exists");
        let terminal_payload =
            serde_json::from_str::<Value>(&terminal_event.payload_json).expect("terminal payload");
        assert_eq!(
            terminal_payload.pointer("/summary").and_then(Value::as_str),
            Some("provider failed with token=[REDACTED]")
        );
        assert_eq!(
            terminal_payload
                .pointer("/metadata/stderr/redacted")
                .and_then(Value::as_bool),
            Some(true)
        );

        for fact in store.list_facts(&instance_id).expect("facts list") {
            assert!(
                !fact.value_json.contains(secret),
                "fact {} leaked secret: {}",
                fact.name,
                fact.value_json
            );
        }
        for evidence in store.list_evidence(&instance_id).expect("evidence list") {
            assert!(
                !evidence
                    .summary
                    .as_deref()
                    .unwrap_or_default()
                    .contains(secret),
                "evidence {} summary leaked secret",
                evidence.kind
            );
            assert!(
                !evidence.metadata_json.contains(secret),
                "evidence {} metadata leaked secret: {}",
                evidence.kind,
                evidence.metadata_json
            );
        }
        for artifact in store
            .list_artifacts_for_run("run-tell")
            .expect("artifacts list")
        {
            assert!(
                !artifact.path.contains(secret),
                "artifact path leaked secret: {}",
                artifact.path
            );
            assert_eq!(artifact.path, "[REDACTED]");
            assert!(
                !artifact
                    .content_hash
                    .as_deref()
                    .unwrap_or_default()
                    .contains(secret),
                "artifact content hash leaked secret: {:?}",
                artifact.content_hash
            );
        }
        for diagnostic in store
            .list_diagnostics(Some(&instance_id))
            .expect("diagnostics list")
        {
            assert!(
                !diagnostic.message.contains(secret),
                "diagnostic leaked secret: {}",
                diagnostic.message
            );
        }
    }

    #[test]
    fn agent_harness_skips_provider_launch_when_cancel_requested_before_launch() {
        struct CancelBeforeLaunchHarness {
            store_path: PathBuf,
        }

        impl AgentHarness for CancelBeforeLaunchHarness {
            fn before_launch(&self, request: &AgentTurnRequest) {
                let mut store = SqliteStore::open(&self.store_path).expect("store reopens");
                store
                    .request_effect_cancellation(EffectCancellationRequest {
                        instance_id: &request.instance_id,
                        effect_id: &request.effect_id,
                        revision_id: None,
                        reason: Some("test pre-launch cancellation"),
                        requested_by: "test",
                        causation_event_id: None,
                        idempotency_key: Some("test-pre-launch-cancel"),
                    })
                    .expect("cancellation request records");
            }

            fn run(&self, _request: AgentTurnRequest) -> ProviderRunResult {
                panic!("provider should not launch after pre-launch cancellation request");
            }
        }

        let store_path = std::env::temp_dir().join(format!(
            "whip-kernel-pre-launch-cancel-{}.sqlite",
            idempotency_key(&["pre-launch-cancel", "store"])
        ));
        let _ = fs::remove_file(&store_path);
        let store = SqliteStore::open(&store_path).expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "HarnessPreLaunchCancel",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    timeout_seconds: None,
                    effect_id: "tell",
                    kind: "agent.tell",
                    target: Some("worker"),
                    input_json: r#"{"prompt":"go"}"#,
                    status: "queued",
                    idempotency_key: "rule=start;effect=tell",
                    required_capabilities_json: "[]",
                    profile: Some("repo-reader"),
                    correlation_id: None,
                    source_span_json: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        kernel
            .run_agent_turn(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "mock",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-reader"),
                    input_json: r#"{"prompt":"go"}"#,
                    skill_names: &[],
                },
                &CancelBeforeLaunchHarness {
                    store_path: store_path.clone(),
                },
            )
            .expect("turn cancels before provider launch");

        check_trace(kernel.trace()).expect("kernel trace conforms");
        let store = kernel.into_store();
        let effect = store
            .list_effects(&instance_id)
            .expect("effects list")
            .pop()
            .expect("effect exists");
        assert_eq!(effect.status, "cancelled");
        let requests = store
            .list_effect_cancellation_requests(&instance_id)
            .expect("cancellation requests list");
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].status, "terminal");
        let events = store.list_events(&instance_id).expect("events list");
        // cancel_run settles the effect AND derives the effect.cancelled
        // settling fact, so the log ends terminal-then-fact.
        assert_eq!(
            events.last().map(|event| event.event_type.as_str()),
            Some("fact.derived")
        );
        assert!(events
            .iter()
            .any(|event| event.event_type == "effect.terminal"));
        assert!(!events
            .iter()
            .any(|event| event.event_type == "agent.turn.completed"));

        let _ = fs::remove_file(store_path);
    }

    #[test]
    fn failed_agent_harness_records_structured_failure_event_and_evidence() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "HarnessFailure",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"go"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-reader"),
            correlation_id: None,
            source_span_json: Some(
                r#"{"path":"workflow.whip","start":10,"end":42,"construct":"effect"}"#,
            ),
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        kernel
            .run_agent_turn(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "mock",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-reader"),
                    input_json: r#"{"prompt":"go"}"#,
                    skill_names: &[],
                },
                &MockAgentHarness::failed("fixture exploded"),
            )
            .expect("mock turn records failure");

        assert!(kernel.trace().iter().any(|record| matches!(
            &record.event,
            TraceEvent::ProviderDiagnostic {
                run_id,
                effect_id,
                provider,
                status,
                diagnostics_json,
                ..
            } if run_id == "run-tell"
                && effect_id == "tell"
                && provider == "mock"
                && *status == EffectStatus::Failed
                && diagnostics_json.contains("\"phase\":\"provider.fixture.failed\"")
        )));
        check_trace(kernel.trace()).expect("kernel trace conforms");
        let store = kernel.into_store();
        let events = store.list_events(&instance_id).expect("events list");
        assert!(events
            .iter()
            .any(|event| event.event_type == "effect.terminal"
                && event.payload_json.contains("\"status\":\"failed\"")
                && event
                    .payload_json
                    .contains("\"phase\":\"provider.fixture.failed\"")));
        assert!(events
            .iter()
            .any(|event| event.event_type == "agent.turn.failed"
                && event
                    .payload_json
                    .contains("\"error_kind\":\"fixture_failure\"")));
        let failed_turn: Value = events
            .iter()
            .find(|event| event.event_type == "agent.turn.failed")
            .map(|event| serde_json::from_str(&event.payload_json).expect("payload parses"))
            .expect("failed turn event exists");
        assert_eq!(
            failed_turn
                .pointer("/failure/provider")
                .and_then(Value::as_str),
            Some("mock")
        );
        assert_eq!(
            failed_turn
                .pointer("/failure/adapter")
                .and_then(Value::as_str),
            Some("mock")
        );
        assert_eq!(
            failed_turn
                .pointer("/failure/missing_config_keys")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(0)
        );

        let evidence = store.list_evidence(&instance_id).expect("evidence lists");
        assert!(evidence
            .iter()
            .any(|evidence| evidence.kind == "agent.turn.provider"
                && evidence
                    .metadata_json
                    .contains("\"phase\":\"provider.fixture.failed\"")));

        let diagnostics = store
            .list_diagnostics(Some(&instance_id))
            .expect("diagnostics list");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code.as_deref(), Some("fixture_failure"));
        assert_eq!(diagnostics[0].subject_type.as_deref(), Some("effect"));
        assert_eq!(diagnostics[0].subject_id.as_deref(), Some("tell"));
        assert_eq!(diagnostics[0].effect_id.as_deref(), Some("tell"));
        assert_eq!(diagnostics[0].run_id.as_deref(), Some("run-tell"));
        assert!(diagnostics[0].event_id.is_some());
        assert!(diagnostics[0].message.contains("fixture exploded"));
        assert_ne!(diagnostics[0].evidence_ids_json, "[]");
        assert_eq!(
            diagnostics[0].source_span_json.as_deref(),
            Some(r#"{"construct":"effect","end":42,"path":"workflow.whip","start":10}"#)
        );
        let replayed = store
            .list_diagnostics_from_events(&instance_id)
            .expect("event diagnostics replay");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].code.as_deref(), Some("fixture_failure"));
        assert_eq!(
            replayed[0].source_span_json.as_deref(),
            diagnostics[0].source_span_json.as_deref()
        );

        let facts = store.list_facts(&instance_id).expect("facts list");
        assert!(facts.iter().any(|fact| fact.name == "agent.turn.failed"
            && fact.value_json.contains("\"recoverable\":false")));
    }

    #[test]
    fn required_artifact_capture_failure_prevents_successful_terminal_completion() {
        struct CompletedWithArtifactFailureHarness;

        impl AgentHarness for CompletedWithArtifactFailureHarness {
            fn run(&self, _request: AgentTurnRequest) -> ProviderRunResult {
                ProviderRunResult {
                    status: ProviderRunStatus::Completed,
                    summary: "provider completed before required artifact capture failed"
                        .to_owned(),
                    stdout: String::new(),
                    stderr: "artifact capture stderr".to_owned(),
                    transcript: "artifact capture transcript".to_owned(),
                    exit_code: Some(0),
                    usage_json: "{}".to_owned(),
                    artifacts: Vec::new(),
                    failure: Some(
                        ProviderFailure::new(
                            artifact_manifest::ARTIFACT_CAPTURE_FAILED_EVENT,
                            "missing",
                            "required artifact was missing",
                        )
                        .provider("codex")
                        .adapter("app_server"),
                    ),
                }
            }
        }

        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "RequiredArtifactFailure",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    timeout_seconds: None,
                    effect_id: "tell",
                    kind: "agent.tell",
                    target: Some("worker"),
                    input_json: r#"{"prompt":"go"}"#,
                    status: "queued",
                    idempotency_key: "rule=start;effect=tell",
                    required_capabilities_json: "[]",
                    profile: Some("repo-writer"),
                    correlation_id: None,
                    source_span_json: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start-artifact-failure"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        kernel
            .run_agent_turn(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider: "codex",
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-writer"),
                    input_json: r#"{"prompt":"go"}"#,
                    skill_names: &[],
                },
                &CompletedWithArtifactFailureHarness,
            )
            .expect("turn records artifact capture failure");

        check_trace(kernel.trace()).expect("kernel trace conforms");
        let store = kernel.into_store();
        let effect = store
            .list_effects(&instance_id)
            .expect("effects list")
            .pop()
            .expect("effect exists");
        assert_eq!(effect.status, "failed");
        let events = store.list_events(&instance_id).expect("events list");
        assert!(events
            .iter()
            .any(|event| event.event_type == "effect.terminal"
                && event.payload_json.contains("\"status\":\"failed\"")
                && event
                    .payload_json
                    .contains("\"phase\":\"artifact.capture.failed\"")));
        assert!(events
            .iter()
            .any(|event| event.event_type == "agent.turn.failed"
                && event.payload_json.contains("\"error_kind\":\"missing\"")));
        assert!(!events
            .iter()
            .any(|event| event.event_type == "agent.turn.completed"));
    }

    #[test]
    fn recovery_appends_terminal_from_provider_evidence_once_after_append_gap() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "ProviderTerminalRecovery",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    timeout_seconds: None,
                    effect_id: "tell",
                    kind: "agent.tell",
                    target: Some("worker"),
                    input_json: r#"{"prompt":"go"}"#,
                    status: "queued",
                    idempotency_key: "rule=start;effect=tell",
                    required_capabilities_json: "[]",
                    profile: Some("repo-writer"),
                    correlation_id: None,
                    source_span_json: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start-recovery"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        kernel
            .start_run(RunStart {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let provider_metadata = json!({
            "effect_id": "tell",
            "agent": "worker",
            "profile": "repo-writer",
            "status": "completed",
            "stdout": {"redacted": true, "bytes": 0, "chars": 0},
            "stderr": {"redacted": true, "bytes": 0, "chars": 0},
            "transcript": {"redacted": true, "bytes": 0, "chars": 0},
            "exit_code": 0,
            "usage": {},
            "artifact_ids": [],
            "failure": null,
        })
        .to_string();
        let evidence_id = kernel
            .store
            .record_evidence(EvidenceRecord {
                instance_id: &instance_id,
                kind: "agent.turn.provider",
                subject_type: "run",
                subject_id: "run-tell",
                causation_id: Some("tell"),
                correlation_id: Some("provider-terminal-gap"),
                summary: Some("provider completed before terminal append gap"),
                metadata_json: &provider_metadata,
            })
            .expect("provider evidence records");

        let recovered = kernel
            .recover_provider_terminal_from_evidence(AgentTurnExecution {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                agent: "worker",
                profile: Some("repo-writer"),
                input_json: r#"{"prompt":"go"}"#,
                skill_names: &[],
            })
            .expect("terminal recovery succeeds");
        assert!(recovered.is_some());
        let duplicate = kernel
            .recover_provider_terminal_from_evidence(AgentTurnExecution {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                agent: "worker",
                profile: Some("repo-writer"),
                input_json: r#"{"prompt":"go"}"#,
                skill_names: &[],
            })
            .expect("duplicate recovery is idempotent");
        assert!(duplicate.is_none());

        check_trace(kernel.trace()).expect("kernel trace conforms");
        let store = kernel.into_store();
        let effects = store.list_effects(&instance_id).expect("effects list");
        assert_eq!(effects[0].status, "completed");
        let events = store.list_events(&instance_id).expect("events list");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.terminal"
                    && event.payload_json.contains("\"run_id\":\"run-tell\""))
                .count(),
            1
        );
        let terminal = events
            .iter()
            .find(|event| event.event_type == "effect.terminal")
            .expect("terminal event exists");
        assert!(terminal
            .payload_json
            .contains("\"recovery\":\"provider_evidence_terminal\""));
        assert!(terminal.payload_json.contains(&evidence_id));
        let terminal_payload =
            serde_json::from_str::<Value>(&terminal.payload_json).expect("terminal payload");
        assert_eq!(
            terminal_payload
                .pointer("/metadata/provider_correlation_id")
                .and_then(Value::as_str),
            Some("provider-terminal-gap")
        );
        assert!(terminal_payload
            .pointer("/metadata/terminal_payload_hash")
            .and_then(Value::as_str)
            .is_some());
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "agent.turn.completed")
                .count(),
            1
        );
    }

    fn kernel_with_queued_agent_tell() -> (RuntimeKernel, String) {
        kernel_with_queued_agent_tell_on(SqliteStore::open_in_memory().expect("store opens"))
    }

    fn kernel_with_queued_agent_tell_on(store: SqliteStore) -> (RuntimeKernel, String) {
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "UncertainRecovery",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    timeout_seconds: None,
                    effect_id: "tell",
                    kind: "agent.tell",
                    target: Some("worker"),
                    input_json: r#"{"prompt":"go"}"#,
                    status: "queued",
                    idempotency_key: "rule=start;effect=tell",
                    required_capabilities_json: "[]",
                    profile: Some("repo-writer"),
                    correlation_id: None,
                    source_span_json: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start-uncertain"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        (kernel, instance_id)
    }

    fn start_running_agent_turn_without_evidence() -> (RuntimeKernel, String) {
        let (mut kernel, instance_id) = kernel_with_queued_agent_tell();
        kernel
            .start_run(RunStart {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        (kernel, instance_id)
    }

    /// A scripted native adapter for driver-loop tests: `None` entries are
    /// empty polls, `Some` entries are delivered frames. `on_start` fires
    /// inside `start_turn` (after the kernel's own run start); `with_cancel`
    /// arms an ack event plus the terminal the delegate emits afterwards.
    struct ScriptedAdapter {
        capability: ProviderCapability,
        script: std::collections::VecDeque<Option<NativeProviderEvent>>,
        on_start: Option<Box<dyn FnMut()>>,
        cancel_ack: Option<NativeProviderEvent>,
        cancel_follow_up: Option<NativeProviderEvent>,
        cancellations: Vec<CancellationDepth>,
    }

    impl ScriptedAdapter {
        fn new(script: Vec<Option<NativeProviderEvent>>) -> Self {
            Self {
                capability: builtin_provider_capabilities()
                    .into_iter()
                    .find(|capability| capability.provider_kind == "fixture")
                    .expect("fixture capability"),
                script: script.into(),
                on_start: None,
                cancel_ack: None,
                cancel_follow_up: None,
                cancellations: Vec::new(),
            }
        }

        fn with_on_start(mut self, hook: Box<dyn FnMut()>) -> Self {
            self.on_start = Some(hook);
            self
        }

        fn with_cancel(mut self, ack: NativeProviderEvent, terminal: NativeProviderEvent) -> Self {
            self.cancel_ack = Some(ack);
            self.cancel_follow_up = Some(terminal);
            self
        }
    }

    impl NativeProviderAdapter for ScriptedAdapter {
        fn provider_id(&self) -> &str {
            "scripted"
        }

        fn capability(&self) -> &ProviderCapability {
            &self.capability
        }

        fn start_turn(
            &mut self,
            _request: NativeProviderTurnRequest,
        ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
            if let Some(hook) = self.on_start.as_mut() {
                hook();
            }
            Ok(self
                .script
                .pop_front()
                .flatten()
                .expect("scripted start event"))
        }

        fn next_event(
            &mut self,
            _run_id: &str,
        ) -> Result<Option<NativeProviderEvent>, NativeProviderBoundaryError> {
            Ok(self.script.pop_front().unwrap_or(None))
        }

        fn cancel_turn(
            &mut self,
            cancellation: NativeProviderCancellation,
        ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
            self.cancellations.push(cancellation.requested_depth);
            let ack = self.cancel_ack.take().expect("scripted cancel ack");
            if let Some(terminal) = self.cancel_follow_up.take() {
                self.script.push_front(Some(terminal));
            }
            Ok(ack)
        }
    }

    fn scripted_event(kind: NativeProviderEventKind, event_type: &str) -> NativeProviderEvent {
        NativeProviderEvent {
            provider_id: "scripted".to_owned(),
            run_id: "run-tell".to_owned(),
            event_kind: kind,
            provider_event_type: event_type.to_owned(),
            provider_session_id: None,
            provider_turn_id: None,
            sequence: None,
            evidence: json!({}),
            artifacts: Vec::new(),
        }
    }

    #[test]
    fn empty_polls_do_not_consume_the_event_budget() {
        // DR-0035 Decision 4: `max_events` bounds DELIVERED frames only. With a
        // budget of 2, three empty polls before the terminal must not push the
        // turn into the synthetic timeout (pre-B2 they consumed the budget).
        let (mut kernel, instance_id) = kernel_with_queued_agent_tell();
        let execution = AgentTurnExecution {
            instance_id: &instance_id,
            effect_id: "tell",
            run_id: "run-tell",
            provider: "scripted",
            worker_id: "worker-1",
            lease_id: "lease-tell",
            lease_expires_at: "2030-01-01T00:00:00Z",
            agent: "worker",
            profile: Some("repo-writer"),
            input_json: r#"{"prompt":"go"}"#,
            skill_names: &[],
        };
        let mut adapter = ScriptedAdapter::new(vec![
            Some(scripted_event(
                NativeProviderEventKind::Started,
                "scripted.started",
            )),
            None,
            None,
            None,
            Some(scripted_event(
                NativeProviderEventKind::Completed,
                "scripted.completed",
            )),
        ]);
        let request = NativeProviderTurnRequest {
            provider_id: "scripted".to_owned(),
            provider_kind: "fixture".to_owned(),
            surface: "fixture".to_owned(),
            run_id: "run-tell".to_owned(),
            effect_id: "tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            prompt_json: json!("go"),
            workspace_policy: crate::provider::WorkspacePolicy::ReadOnly,
            required_capabilities: Vec::new(),
            cancellation_depth: CancellationDepth::None,
            artifact_policy: crate::provider::ArtifactPolicy::Metadata,
            credential_ref: None,
            provider_options: std::collections::BTreeMap::new(),
        };

        kernel
            .run_native_agent_turn(execution, request, &mut adapter, 2)
            .expect("turn completes");

        let runs = kernel.store().list_runs(&instance_id).expect("runs list");
        let run = runs.iter().find(|r| r.run_id == "run-tell").expect("run");
        assert_eq!(
            run.status, "completed",
            "the turn completed instead of timing out on empty polls"
        );
    }

    #[test]
    fn driver_never_launches_provider_when_cancel_requested_before_start() {
        // DR-0035 Decision 5 (B3 residual, verified closed at the store
        // layer): `store.start_run` transactionally refuses to start a run
        // while a cancellation request is open, so a delegated turn with a
        // pre-start request never invokes the provider — the same pre-launch
        // protection the owned harness has.
        let (mut kernel, instance_id) = start_running_agent_turn_without_evidence();
        kernel
            .store_mut()
            .request_effect_cancellation(EffectCancellationRequest {
                instance_id: &instance_id,
                effect_id: "tell",
                revision_id: None,
                reason: Some("pre-start cancellation"),
                requested_by: "test",
                causation_event_id: None,
                idempotency_key: Some("test-pre-start-cancel"),
            })
            .expect("cancellation request records");
        let execution = AgentTurnExecution {
            instance_id: &instance_id,
            effect_id: "tell",
            run_id: "run-tell",
            provider: "scripted",
            worker_id: "worker-1",
            lease_id: "lease-tell",
            lease_expires_at: "2030-01-01T00:00:00Z",
            agent: "worker",
            profile: Some("repo-writer"),
            input_json: r#"{"prompt":"go"}"#,
            skill_names: &[],
        };
        // An adapter whose start would panic proves the provider never launches.
        struct NeverLaunchAdapter {
            capability: ProviderCapability,
        }
        impl NativeProviderAdapter for NeverLaunchAdapter {
            fn provider_id(&self) -> &str {
                "scripted"
            }
            fn capability(&self) -> &ProviderCapability {
                &self.capability
            }
            fn start_turn(
                &mut self,
                _request: NativeProviderTurnRequest,
            ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
                panic!("provider must not launch after a pre-start cancellation request");
            }
            fn next_event(
                &mut self,
                _run_id: &str,
            ) -> Result<Option<NativeProviderEvent>, NativeProviderBoundaryError> {
                panic!("provider must not stream after a pre-start cancellation request");
            }
            fn cancel_turn(
                &mut self,
                _cancellation: NativeProviderCancellation,
            ) -> Result<NativeProviderEvent, NativeProviderBoundaryError> {
                panic!("pre-start skip needs no provider cancel");
            }
        }
        let mut adapter = NeverLaunchAdapter {
            capability: builtin_provider_capabilities()
                .into_iter()
                .find(|capability| capability.provider_kind == "fixture")
                .expect("fixture capability"),
        };
        let request = NativeProviderTurnRequest {
            provider_id: "scripted".to_owned(),
            provider_kind: "fixture".to_owned(),
            surface: "fixture".to_owned(),
            run_id: "run-tell".to_owned(),
            effect_id: "tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            prompt_json: json!("go"),
            workspace_policy: crate::provider::WorkspacePolicy::ReadOnly,
            required_capabilities: Vec::new(),
            cancellation_depth: CancellationDepth::None,
            artifact_policy: crate::provider::ArtifactPolicy::Metadata,
            credential_ref: None,
            provider_options: std::collections::BTreeMap::new(),
        };

        // The store-level guard fires before any provider work; the
        // NeverLaunchAdapter proves start_turn/next_event were never reached.
        let error = kernel
            .run_native_agent_turn(execution, request, &mut adapter, 8)
            .expect_err("run start is refused while a cancellation request is open");
        assert!(
            matches!(&error, StoreError::Conflict(message) if message.contains("cancellation")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn driver_cancels_running_delegate_on_open_cancellation_request() {
        // DR-0035 Decision 5: an open durable cancellation request reaches the
        // running delegate through the driver loop — cancel_turn is no longer
        // dead code. The ack is a non-terminal Diagnostic; the delegate's own
        // `cancelled` terminal ends the run (exactly one terminal).
        let store_path = std::env::temp_dir().join(format!(
            "whip-kernel-delegate-cancel-{}.sqlite",
            idempotency_key(&["delegate-cancel", "store"])
        ));
        let _ = fs::remove_file(&store_path);
        let store = SqliteStore::open(&store_path).expect("store opens");
        let (mut kernel, instance_id) = kernel_with_queued_agent_tell_on(store);
        let execution = AgentTurnExecution {
            instance_id: &instance_id,
            effect_id: "tell",
            run_id: "run-tell",
            provider: "scripted",
            worker_id: "worker-1",
            lease_id: "lease-tell",
            lease_expires_at: "2030-01-01T00:00:00Z",
            agent: "worker",
            profile: Some("repo-writer"),
            input_json: r#"{"prompt":"go"}"#,
            skill_names: &[],
        };
        // The cancellation request lands from a second store connection while
        // the turn is starting — the effect is `running` by then.
        let request_path = store_path.clone();
        let request_instance = instance_id.clone();
        let mut adapter = ScriptedAdapter::new(vec![Some(scripted_event(
            NativeProviderEventKind::Started,
            "scripted.started",
        ))])
        .with_on_start(Box::new(move || {
            let mut store = SqliteStore::open(&request_path).expect("store reopens");
            store
                .request_effect_cancellation(EffectCancellationRequest {
                    instance_id: &request_instance,
                    effect_id: "tell",
                    revision_id: None,
                    reason: Some("test delegate cancellation"),
                    requested_by: "test",
                    causation_event_id: None,
                    idempotency_key: Some("test-delegate-cancel"),
                })
                .expect("cancellation request records");
        }))
        .with_cancel(
            scripted_event(NativeProviderEventKind::Diagnostic, "scripted.cancel_ack"),
            scripted_event(NativeProviderEventKind::Cancelled, "scripted.cancelled"),
        );
        let request = NativeProviderTurnRequest {
            provider_id: "scripted".to_owned(),
            provider_kind: "fixture".to_owned(),
            surface: "fixture".to_owned(),
            run_id: "run-tell".to_owned(),
            effect_id: "tell".to_owned(),
            agent: "worker".to_owned(),
            profile: Some("repo-writer".to_owned()),
            prompt_json: json!("go"),
            workspace_policy: crate::provider::WorkspacePolicy::ReadOnly,
            required_capabilities: Vec::new(),
            cancellation_depth: CancellationDepth::NativeStop,
            artifact_policy: crate::provider::ArtifactPolicy::Metadata,
            credential_ref: None,
            provider_options: std::collections::BTreeMap::new(),
        };

        kernel
            .run_native_agent_turn(execution, request, &mut adapter, 8)
            .expect("turn cancels");

        // The delegate saw exactly one cancel at the authorized depth.
        assert_eq!(adapter.cancellations, vec![CancellationDepth::NativeStop]);
        let runs = kernel.store().list_runs(&instance_id).expect("runs list");
        let run = runs.iter().find(|r| r.run_id == "run-tell").expect("run");
        assert_eq!(run.status, "cancelled");
        // The ack was recorded as a non-terminal diagnostic before the terminal.
        let evidence = kernel
            .store()
            .list_evidence(&instance_id)
            .expect("evidence lists");
        assert!(
            evidence
                .iter()
                .any(|row| row.metadata_json.contains("scripted.cancel_ack")),
            "cancel ack recorded"
        );
        // Exactly one terminal lifecycle fact for the run.
        let events = kernel
            .store()
            .list_events(&instance_id)
            .expect("events list");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "agent.turn.cancelled")
                .count(),
            1
        );
        let _ = fs::remove_file(&store_path);
    }

    #[test]
    fn protocol_violations_record_as_evidence_not_lifecycle_events() {
        // DR-0035 Decision 3 (T1/T3): adapter-surfaced `whip.protocol.*` frames
        // and frames arriving after the run's terminal both land as
        // `agent.turn.protocol_violation` evidence — never as lifecycle events,
        // and they never reopen the run.
        let (mut kernel, instance_id) = start_running_agent_turn_without_evidence();
        let execution = AgentTurnExecution {
            instance_id: &instance_id,
            effect_id: "tell",
            run_id: "run-tell",
            provider: "codex",
            worker_id: "worker-1",
            lease_id: "lease-tell",
            lease_expires_at: "2030-01-01T00:00:00Z",
            agent: "worker",
            profile: Some("repo-writer"),
            input_json: r#"{"prompt":"go"}"#,
            skill_names: &[],
        };
        let frame = |event_type: &str, kind: NativeProviderEventKind| NativeProviderEvent {
            provider_id: "codex".to_owned(),
            run_id: "run-tell".to_owned(),
            event_kind: kind,
            provider_event_type: event_type.to_owned(),
            provider_session_id: None,
            provider_turn_id: None,
            sequence: None,
            evidence: json!({"violation": {"frame_type": "item/started", "frame_run_id": "run-other"}}),
            artifacts: Vec::new(),
        };

        // While running: an adapter-surfaced misrouted frame is a violation.
        kernel
            .record_native_provider_event(
                execution,
                &frame(
                    "whip.protocol.misrouted_frame",
                    NativeProviderEventKind::Diagnostic,
                ),
                "violation-0",
            )
            .expect("adapter-surfaced violation records");

        // Terminate the run (recovery resolves it to the uncertain terminal).
        kernel
            .recover_running_provider_runs(&instance_id)
            .expect("recovery resolves the run");
        let events_at_terminal = kernel
            .store()
            .list_events(&instance_id)
            .expect("events list")
            .len();

        // Post-terminal: even an ordinary stream frame is a violation now.
        kernel
            .record_native_provider_event(
                execution,
                &frame("item/started", NativeProviderEventKind::Streamed),
                "violation-1",
            )
            .expect("post-terminal violation records");

        let evidence = kernel
            .store()
            .list_evidence(&instance_id)
            .expect("evidence lists");
        let violations = evidence
            .iter()
            .filter(|row| row.kind == "agent.turn.protocol_violation")
            .collect::<Vec<_>>();
        assert_eq!(violations.len(), 2, "both frames land as violations");
        let reasons = violations
            .iter()
            .map(|row| {
                serde_json::from_str::<Value>(&row.metadata_json)
                    .expect("violation metadata")
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .expect("reason present")
            })
            .collect::<Vec<_>>();
        assert!(
            reasons.contains(&"adapter_surfaced".to_owned()),
            "{reasons:?}"
        );
        assert!(reasons.contains(&"post_terminal".to_owned()), "{reasons:?}");
        // The adapter-constructed identifiers survive into the evidence.
        assert!(
            violations
                .iter()
                .any(|row| row.metadata_json.contains("run-other")),
            "violation detail carries the stray frame's run id"
        );
        // Violations add no lifecycle events and the run stays terminal.
        assert!(
            !evidence
                .iter()
                .any(|row| row.kind == "agent.turn.native_event"),
            "no lifecycle observation was appended for a violation"
        );
        let events_after = kernel
            .store()
            .list_events(&instance_id)
            .expect("events list")
            .len();
        assert_eq!(
            events_after, events_at_terminal,
            "a post-terminal frame appends no events"
        );
        let runs = kernel.store().list_runs(&instance_id).expect("runs list");
        let run = runs.iter().find(|r| r.run_id == "run-tell").expect("run");
        assert_eq!(
            run.status, "uncertain",
            "the violation never reopens the run"
        );
    }

    #[test]
    fn recovery_resolves_running_run_without_evidence_to_uncertain() {
        let (mut kernel, instance_id) = start_running_agent_turn_without_evidence();

        let recovered = kernel
            .recover_running_provider_runs(&instance_id)
            .expect("recovery sweep succeeds");
        assert_eq!(
            recovered.len(),
            1,
            "the started run resolves to one terminal"
        );

        check_trace(kernel.trace()).expect("kernel trace conforms");

        let store = kernel.into_store();
        // The effect is a Failed subkind...
        let effects = store.list_effects(&instance_id).expect("effects list");
        assert_eq!(effects[0].status, "failed");
        // ...but the run records the distinct `uncertain` status (TLA+ ResolveUncertainRun).
        let runs = store.list_runs(&instance_id).expect("runs list");
        let run = runs.iter().find(|r| r.run_id == "run-tell").expect("run");
        assert_eq!(run.status, "uncertain");
        // Exactly one terminal for the run, marked as an uncertain recovery.
        let events = store.list_events(&instance_id).expect("events list");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.terminal"
                    && event.payload_json.contains("\"run_id\":\"run-tell\""))
                .count(),
            1
        );
        let terminal = events
            .iter()
            .find(|event| event.event_type == "effect.terminal")
            .expect("terminal event exists");
        assert!(terminal.payload_json.contains("\"recovery\":\"uncertain\""));
        // No success was fabricated.
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "agent.turn.completed")
                .count(),
            0
        );
    }

    #[test]
    fn recovery_resolving_uncertain_run_is_idempotent_on_rerun() {
        let (mut kernel, instance_id) = start_running_agent_turn_without_evidence();

        let first = kernel
            .recover_running_provider_runs(&instance_id)
            .expect("first recovery sweep succeeds");
        assert_eq!(first.len(), 1);
        // The run is now `uncertain` (terminal), so a re-run is a clean no-op,
        // not a swallowed unique-index error.
        let second = kernel
            .recover_running_provider_runs(&instance_id)
            .expect("rerun is idempotent");
        assert!(second.is_empty());

        let store = kernel.into_store();
        let events = store.list_events(&instance_id).expect("events list");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.terminal"
                    && event.payload_json.contains("\"run_id\":\"run-tell\""))
                .count(),
            1,
            "rerun must not double-admit a terminal"
        );
    }

    #[test]
    fn uncertain_terminal_idempotency_key_is_deterministic() {
        let correlation_a = provider_terminal_correlation_id("inst", "run-tell");
        let correlation_b = provider_terminal_correlation_id("inst", "run-tell");
        assert_eq!(correlation_a, correlation_b);
        let hash_a = terminal_payload_hash("failed", None, Some("uncertain"), "{}");
        let hash_b = terminal_payload_hash("failed", None, Some("uncertain"), "{}");
        assert_eq!(hash_a, hash_b);
        let key_a =
            terminal_completion_idempotency_key("inst", "run-tell", &correlation_a, &hash_a);
        let key_b =
            terminal_completion_idempotency_key("inst", "run-tell", &correlation_b, &hash_b);
        assert_eq!(
            key_a, key_b,
            "uncertain terminal idempotency key must be deterministic"
        );
    }

    #[test]
    fn recovery_preserves_artifact_evidence_after_capture_before_terminal_gap() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "ArtifactRecovery",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    timeout_seconds: None,
                    effect_id: "tell",
                    kind: "agent.tell",
                    target: Some("worker"),
                    input_json: r#"{"prompt":"go"}"#,
                    status: "queued",
                    idempotency_key: "rule=start;effect=tell",
                    required_capabilities_json: "[]",
                    profile: Some("repo-writer"),
                    correlation_id: None,
                    source_span_json: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start-artifact-recovery"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        kernel
            .start_run(RunStart {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let artifact_id = kernel
            .store
            .record_artifact(ArtifactRecord {
                run_id: "run-tell",
                kind: "transcript_ref",
                path: "provider://codex/runs/run-tell/transcript_ref",
                content_hash: None,
                mime_type: Some("text/plain"),
            })
            .expect("artifact records before terminal gap");
        let provider_metadata = json!({
            "effect_id": "tell",
            "agent": "worker",
            "profile": "repo-writer",
            "status": "completed",
            "stdout": {"redacted": true, "bytes": 0, "chars": 0},
            "stderr": {"redacted": true, "bytes": 0, "chars": 0},
            "transcript": {"redacted": true, "bytes": 0, "chars": 0},
            "exit_code": 0,
            "usage": {},
            "artifact_ids": [artifact_id],
            "artifact_manifest": {
                "schema_version": artifact_manifest::ARTIFACT_MANIFEST_SCHEMA_VERSION,
                "entry_count": 1,
                "entries": [{
                    "artifact_id": artifact_id,
                    "kind": "transcript_ref",
                    "uri": {
                        "type": "ref",
                        "value": "provider://codex/runs/run-tell/transcript_ref"
                    },
                    "content_hash": null,
                    "mime_type": "text/plain",
                    "size_bytes": null,
                    "redaction_status": "unredacted_metadata_only",
                    "retention_policy": "provider_default",
                    "required": false,
                    "source_provider_event": null
                }]
            },
            "failure": null,
        })
        .to_string();
        kernel
            .store
            .record_evidence(EvidenceRecord {
                instance_id: &instance_id,
                kind: "agent.turn.provider",
                subject_type: "run",
                subject_id: "run-tell",
                causation_id: Some("tell"),
                correlation_id: Some("provider-artifact-terminal-gap"),
                summary: Some("provider completed with artifact before terminal append gap"),
                metadata_json: &provider_metadata,
            })
            .expect("provider evidence records");

        let recovered = kernel
            .recover_provider_terminal_from_evidence(AgentTurnExecution {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                agent: "worker",
                profile: Some("repo-writer"),
                input_json: r#"{"prompt":"go"}"#,
                skill_names: &[],
            })
            .expect("terminal recovery succeeds");
        assert!(recovered.is_some());

        let store = kernel.into_store();
        let artifacts = store
            .list_artifacts_for_run("run-tell")
            .expect("artifacts list");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].artifact_id, artifact_id);
        let terminal = store
            .list_events(&instance_id)
            .expect("events list")
            .into_iter()
            .find(|event| event.event_type == "effect.terminal")
            .expect("terminal exists");
        assert!(terminal.payload_json.contains(&artifact_id));
    }

    #[test]
    fn restart_reconciles_running_provider_run_with_persisted_terminal_evidence() {
        let store_path = std::env::temp_dir().join(format!(
            "whip-kernel-provider-recovery-{}.sqlite",
            idempotency_key(&["provider-recovery", "store"])
        ));
        let _ = fs::remove_file(&store_path);
        let store = SqliteStore::open(&store_path).expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "RestartProviderRecovery",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    timeout_seconds: None,
                    effect_id: "tell",
                    kind: "agent.tell",
                    target: Some("worker"),
                    input_json: r#"{"prompt":"go"}"#,
                    status: "queued",
                    idempotency_key: "rule=start;effect=tell",
                    required_capabilities_json: "[]",
                    profile: Some("repo-writer"),
                    correlation_id: None,
                    source_span_json: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start-restart-provider-recovery"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        kernel
            .start_run(RunStart {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let provider_metadata = json!({
            "effect_id": "tell",
            "agent": "worker",
            "profile": "repo-writer",
            "status": "completed",
            "stdout": {"redacted": true, "bytes": 0, "chars": 0},
            "stderr": {"redacted": true, "bytes": 0, "chars": 0},
            "transcript": {"redacted": true, "bytes": 0, "chars": 0},
            "exit_code": 0,
            "usage": {},
            "artifact_ids": [],
            "failure": null,
        })
        .to_string();
        kernel
            .store
            .record_evidence(EvidenceRecord {
                instance_id: &instance_id,
                kind: "agent.turn.provider",
                subject_type: "run",
                subject_id: "run-tell",
                causation_id: Some("tell"),
                correlation_id: Some("provider-restart-terminal-gap"),
                summary: Some("provider completed before worker restart"),
                metadata_json: &provider_metadata,
            })
            .expect("provider evidence records");
        drop(kernel);

        let store = SqliteStore::open(&store_path).expect("store reopens after restart");
        let mut restarted = RuntimeKernel::new(store);
        let recovered = restarted
            .recover_running_provider_runs(&instance_id)
            .expect("running provider runs recover");
        assert_eq!(recovered.len(), 1);
        let duplicate = restarted
            .recover_running_provider_runs(&instance_id)
            .expect("duplicate restart recovery is idempotent");
        assert!(duplicate.is_empty());

        let store = restarted.into_store();
        let effects = store.list_effects(&instance_id).expect("effects list");
        assert_eq!(effects[0].status, "completed");
        let events = store.list_events(&instance_id).expect("events list");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.terminal"
                    && event.payload_json.contains("\"run_id\":\"run-tell\""))
                .count(),
            1
        );
        assert!(events
            .iter()
            .any(|event| event.event_type == "agent.turn.completed"));

        let _ = fs::remove_file(store_path);
    }

    #[test]
    fn restart_recovers_running_codex_native_run_from_terminal_evidence() {
        let store_path = std::env::temp_dir().join(format!(
            "whip-kernel-codex-native-recovery-{}.sqlite",
            idempotency_key(&["codex-native-provider-recovery", "store"])
        ));
        let _ = fs::remove_file(&store_path);
        let store = SqliteStore::open(&store_path).expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "RestartCodexNativeRecovery",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &[NewEffect {
                    timeout_seconds: None,
                    effect_id: "tell",
                    kind: "agent.tell",
                    target: Some("codex"),
                    input_json: r#"{"prompt":"go"}"#,
                    status: "queued",
                    idempotency_key: "rule=start;effect=tell",
                    required_capabilities_json: "[]",
                    profile: Some("repo-reader"),
                    correlation_id: None,
                    source_span_json: None,
                }],
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start-codex-native-recovery"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        kernel
            .start_run(RunStart {
                instance_id: &instance_id,
                effect_id: "tell",
                run_id: "run-tell",
                provider: "codex",
                worker_id: "worker-1",
                lease_id: "lease-tell",
                lease_expires_at: "2030-01-01T00:00:00Z",
                metadata_json: "{}",
            })
            .expect("run starts");
        let native_metadata = json!({
            "effect_id": "tell",
            "agent": "codex",
            "profile": "repo-reader",
            "provider": "codex",
            "native_event": {
                "provider_id": "codex",
                "run_id": "run-tell",
                "event_kind": "completed",
                "terminal": true,
                "provider_event_type": "turn/completed",
                "provider_session_id": "codex-session-1",
                "provider_turn_id": "codex-turn-1",
                "sequence": 4,
                "evidence_shape": {"type": "object", "keys": 2},
                "artifacts": []
            },
            "artifact_ids": []
        })
        .to_string();
        kernel
            .store
            .record_evidence(EvidenceRecord {
                instance_id: &instance_id,
                kind: "agent.turn.native_provider",
                subject_type: "run",
                subject_id: "run-tell",
                causation_id: Some("tell"),
                correlation_id: Some("native-codex-terminal-gap"),
                summary: Some("completed native provider event from turn/completed"),
                metadata_json: &native_metadata,
            })
            .expect("native provider evidence records");
        drop(kernel);

        let store = SqliteStore::open(&store_path).expect("store reopens after restart");
        let mut restarted = RuntimeKernel::new(store);
        let recovered = restarted
            .recover_running_provider_runs(&instance_id)
            .expect("running native provider runs recover");
        assert_eq!(recovered.len(), 1);
        let duplicate = restarted
            .recover_running_provider_runs(&instance_id)
            .expect("duplicate native provider recovery is idempotent");
        assert!(duplicate.is_empty());

        let store = restarted.into_store();
        let effects = store.list_effects(&instance_id).expect("effects list");
        assert_eq!(effects[0].status, "completed");
        let events = store.list_events(&instance_id).expect("events list");
        assert_eq!(
            events
                .iter()
                .filter(|event| event.event_type == "effect.terminal"
                    && event.payload_json.contains("\"run_id\":\"run-tell\""))
                .count(),
            1
        );
        let terminal = events
            .iter()
            .find(|event| event.event_type == "effect.terminal")
            .expect("terminal event exists");
        assert!(terminal
            .payload_json
            .contains("\"provider_event_type\":\"turn/completed\""));
        assert!(terminal.payload_json.contains("codex-session-1"));

        let _ = fs::remove_file(store_path);
    }

    #[test]
    fn real_codex_failure_reaches_event_stream() {
        if !command_exists("codex") {
            eprintln!("skipping real Codex failure smoke: codex not found on PATH");
            return;
        }
        let harness = CodexAgentHarness::new(
            CommandLaunchPlan::new("codex", "codex")
                .arg("app-server")
                .arg("--listen")
                .arg("not-a-url://"),
        );
        assert_real_provider_failure_reaches_event_stream(
            "RealCodexFailure",
            "codex",
            &harness,
            "unsupported --listen URL",
        );
    }

    #[test]
    fn real_claude_failure_reaches_event_stream() {
        if !command_exists("claude") {
            eprintln!("skipping real Claude failure smoke: claude not found on PATH");
            return;
        }
        let harness = ClaudeCodeAgentHarness::new(
            CommandLaunchPlan::new("claude", "claude").arg("--definitely-not-a-real-flag"),
        );
        assert_real_provider_failure_reaches_event_stream(
            "RealClaudeFailure",
            "claude",
            &harness,
            "unknown option",
        );
    }

    #[test]
    fn fake_coerce_records_evidence_and_success_fact() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "Coerce",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "review",
            kind: "schema.coerce",
            target: None,
            input_json: r#"{"function_name":"reviewWork"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=review",
            required_capabilities_json: r#"["schema.coerce"]"#,
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        let request = CoerceRequest {
            function_name: "reviewWork".to_owned(),
            arguments_json: r#"{"summary":"done"}"#.to_owned(),
            output_type: "WorkReview".to_owned(),
            generated_coerce_source_hash: "coerce-source".to_owned(),
            input_schema_hash: "input-schema".to_owned(),
            output_schema_hash: "output-schema".to_owned(),
        };
        let terminal = kernel
            .run_coerce(
                CoerceExecution {
                    instance_id: &instance_id,
                    effect_id: "review",
                    run_id: "run-review",
                    provider: "fake-coerce",
                    worker_id: "worker-1",
                    lease_id: "lease-review",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    request: &request,
                    model: None,
                },
                &FakeCoerceClient::succeeds(r#"{"status":"Accept","reason":"ok"}"#),
            )
            .expect("coerce runs");

        // Shifted by `instance.created` at sequence 1 (DR-0094).
        assert_eq!(terminal.sequence, 4);
        check_trace(kernel.trace()).expect("kernel trace conforms");
        let store = kernel.into_store();
        let evidence = store.list_evidence(&instance_id).expect("evidence lists");
        assert_eq!(evidence.len(), 2);
        let coerce_evidence = evidence
            .iter()
            .find(|evidence| evidence.kind == "schema.coerce.provider")
            .expect("coerce provider evidence recorded");
        assert!(coerce_evidence.metadata_json.contains("reviewWork"));
        assert!(coerce_evidence.metadata_json.contains("coerce-source"));
        let coerce_metadata = serde_json::from_str::<Value>(&coerce_evidence.metadata_json)
            .expect("coerce metadata json");
        assert_eq!(
            coerce_metadata
                .pointer("/arguments/redacted")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            coerce_metadata
                .pointer("/arguments/shape/type")
                .and_then(Value::as_str),
            Some("object")
        );
        assert!(!coerce_evidence
            .metadata_json
            .contains(r#""summary":"done""#));
        let facts = store.list_facts(&instance_id).expect("facts list");
        assert!(facts
            .iter()
            .any(|fact| fact.name == "schema.coerce.succeeded"
                && fact.value_json.contains("\"status\":\"Accept\"")));
    }

    #[test]
    fn fake_coerce_failure_records_failed_fact() {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name: "CoerceFail",
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "review",
            kind: "schema.coerce",
            target: None,
            input_json: r#"{"function_name":"reviewWork"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=review",
            required_capabilities_json: r#"["schema.coerce"]"#,
            profile: Some("repo-writer"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");
        let request = CoerceRequest {
            function_name: "reviewWork".to_owned(),
            arguments_json: r#"{"summary":"done"}"#.to_owned(),
            output_type: "WorkReview".to_owned(),
            generated_coerce_source_hash: "coerce-source".to_owned(),
            input_schema_hash: "input-schema".to_owned(),
            output_schema_hash: "output-schema".to_owned(),
        };

        kernel
            .run_coerce(
                CoerceExecution {
                    instance_id: &instance_id,
                    effect_id: "review",
                    run_id: "run-review",
                    provider: "fake-coerce",
                    worker_id: "worker-1",
                    lease_id: "lease-review",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    request: &request,
                    model: None,
                },
                &FakeCoerceClient::fails("invalid output"),
            )
            .expect("failed coerce records terminal event");

        assert!(kernel.trace().iter().any(|record| matches!(
            &record.event,
            TraceEvent::ProviderDiagnostic {
                run_id,
                effect_id,
                provider,
                status,
                diagnostics_json,
                ..
            } if run_id == "run-review"
                && effect_id == "review"
                && provider == "fake-coerce"
                && *status == EffectStatus::Failed
                && diagnostics_json.contains("\"redacted\":true")
                && !diagnostics_json.contains("invalid output")
        )));
        check_trace(kernel.trace()).expect("kernel trace conforms");
        let store = kernel.into_store();
        let diagnostics = store
            .list_diagnostics(Some(&instance_id))
            .expect("diagnostics list");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code.as_deref(), Some("schema.coerce.failed"));
        assert_eq!(diagnostics[0].subject_id.as_deref(), Some("review"));
        assert_eq!(diagnostics[0].run_id.as_deref(), Some("run-review"));
        assert!(!diagnostics[0].message.contains("invalid output"));

        let facts = store.list_facts(&instance_id).expect("facts list");
        let failed_fact = facts
            .iter()
            .find(|fact| fact.name == "schema.coerce.failed")
            .expect("failed coerce fact");
        assert!(failed_fact.value_json.contains("\"redacted\":true"));
        assert!(!failed_fact.value_json.contains("invalid output"));
    }

    fn command_exists(binary: &str) -> bool {
        Command::new(binary).arg("--version").output().is_ok()
    }

    fn assert_real_provider_failure_reaches_event_stream(
        program_name: &str,
        provider: &str,
        harness: &dyn AgentHarness,
        expected_stderr: &str,
    ) {
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version(ProgramVersionInput {
                program_name,
                source_hash: "source",
                ir_hash: "ir",
                compiler_version: "test",
                ir_snapshot: None,
            })
            .expect("program version creates");
        let instance_id = kernel
            .create_instance(&version, "{}")
            .expect("instance creates");
        let effects = [NewEffect {
            timeout_seconds: None,
            effect_id: "tell",
            kind: "agent.tell",
            target: Some("worker"),
            input_json: r#"{"prompt":"this should fail before a model turn"}"#,
            status: "queued",
            idempotency_key: "rule=start;effect=tell",
            required_capabilities_json: "[]",
            profile: Some("repo-reader"),
            correlation_id: None,
            source_span_json: None,
        }];
        kernel
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "start",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-start"),
                marks: &[],
                context_json: None,
            })
            .expect("rule commits");

        kernel
            .run_agent_turn(
                AgentTurnExecution {
                    instance_id: &instance_id,
                    effect_id: "tell",
                    run_id: "run-tell",
                    provider,
                    worker_id: "worker-1",
                    lease_id: "lease-tell",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    agent: "worker",
                    profile: Some("repo-reader"),
                    input_json: r#"{"prompt":"this should fail before a model turn"}"#,
                    skill_names: &[],
                },
                harness,
            )
            .expect("real provider failure records terminal event");

        let store = kernel.into_store();
        let events = store.list_events(&instance_id).expect("events list");
        let terminal_event = events
            .iter()
            .find(|event| event.event_type == "effect.terminal")
            .expect("failed terminal event");
        let terminal_payload = serde_json::from_str::<Value>(&terminal_event.payload_json)
            .expect("terminal payload json");
        assert_eq!(
            terminal_payload.get("status").and_then(Value::as_str),
            Some("failed")
        );
        assert_eq!(
            terminal_payload
                .pointer("/metadata/failure/phase")
                .and_then(Value::as_str),
            Some("provider.exit.failed")
        );
        assert_eq!(
            terminal_payload
                .pointer("/metadata/failure/error_kind")
                .and_then(Value::as_str),
            Some("nonzero_exit")
        );
        assert_eq!(
            terminal_payload
                .pointer("/metadata/stderr/redacted")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(!terminal_event.payload_json.contains(expected_stderr));
        assert!(
            events
                .iter()
                .any(|event| event.event_type == "agent.turn.failed"
                    && event
                        .payload_json
                        .contains("\"phase\":\"provider.exit.failed\"")
                    && event.payload_json.contains("\"recoverable\":true")),
            "missing failed agent turn event for {provider}: {events:#?}"
        );

        let facts = store.list_facts(&instance_id).expect("facts list");
        assert!(facts.iter().any(|fact| fact.name == "agent.turn.failed"
            && fact.value_json.contains("\"error_kind\":\"nonzero_exit\"")));

        let evidence = store.list_evidence(&instance_id).expect("evidence lists");
        let provider_evidence = evidence
            .iter()
            .find(|evidence| evidence.kind == "agent.turn.provider")
            .expect("provider evidence recorded");
        let provider_metadata = serde_json::from_str::<Value>(&provider_evidence.metadata_json)
            .expect("provider metadata json");
        assert_eq!(
            provider_metadata
                .pointer("/failure/phase")
                .and_then(Value::as_str),
            Some("provider.exit.failed")
        );
        assert_eq!(
            provider_metadata
                .pointer("/stderr/redacted")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(!provider_evidence.metadata_json.contains(expected_stderr));
        let diagnostics = store
            .list_diagnostics(Some(&instance_id))
            .expect("diagnostics list");
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code.as_deref() == Some("nonzero_exit")
                && diagnostic.message.contains(provider)
                && !diagnostic.message.contains(expected_stderr)
                && diagnostic.event_id.is_some()
                && diagnostic.run_id.as_deref() == Some("run-tell")
        }));
    }

    /// Thread continuation (pi-conformance §4): the agent's latest completed
    /// turn — including the final assistant reply the machine now persists —
    /// seeds the next tell, with the new user message appended.
    #[test]
    fn thread_transcript_loads_latest_completed_turn_for_the_agent() {
        use crate::harness_loop::ChatMessage;
        let store = SqliteStore::open_in_memory().expect("store opens");
        let mut kernel = RuntimeKernel::new(store);
        let compiled = whipplescript_parser::compile_program(
            "workflow ThreadDemo\n\noutput result Done\n\nclass Done {\n  ok int\n}\n\n\
             rule go\n  when started\n=> {\n  complete result { ok 1 }\n}\n",
        );
        let program = compiled.ir.expect("compiles");
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &program.workflow,
                    source_hash: "s",
                    ir_hash: "i",
                    compiler_version: "test",
                    ir_snapshot: None,
                },
                &program,
            )
            .expect("version");
        let instance_id = kernel
            .create_instance_with_authority(
                &version,
                "{}",
                NewInstanceAuthority {
                    workflow_principal: "local/ThreadDemo",
                    effective_authority_json: "{}",
                },
            )
            .expect("instance");

        // Synthesize a completed turn: the transcript checkpoints + the
        // completed fact event, exactly the shapes the runner records.
        let transcript = crate::harness_loop::chat_messages_to_json(&[
            ChatMessage::System("sys".to_owned()),
            ChatMessage::user_text("first question"),
            ChatMessage::Assistant {
                text: "first answer".to_owned(),
                tool_calls: Vec::new(),
            },
        ]);
        kernel
            .store()
            .append_event(NewEvent {
                instance_id: &instance_id,
                event_type: "agent.turn.brokered.transcript",
                payload_json: &json!({ "effect_id": "effect-1", "messages": transcript })
                    .to_string(),
                source: "kernel",
                causation_id: None,
                correlation_id: Some("effect-1"),
                idempotency_key: Some("t1"),
            })
            .expect("transcript event");
        kernel
            .store()
            .append_event(NewEvent {
                instance_id: &instance_id,
                event_type: "agent.turn.completed",
                payload_json: &json!({
                    "effect_id": "effect-1",
                    "agent": "helper",
                    "status": "completed",
                })
                .to_string(),
                source: "kernel",
                causation_id: None,
                correlation_id: Some("effect-1"),
                idempotency_key: Some("f1"),
            })
            .expect("completed fact event");

        let thread = kernel.load_agent_thread_transcript(&instance_id, "helper");
        assert_eq!(thread.len(), 3, "system + user + final assistant");
        assert!(
            matches!(&thread[2], ChatMessage::Assistant { text, .. } if text == "first answer")
        );
        // A different agent has no thread.
        assert!(kernel
            .load_agent_thread_transcript(&instance_id, "other")
            .is_empty());
    }
}
