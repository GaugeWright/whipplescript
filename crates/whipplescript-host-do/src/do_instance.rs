//! The durable-object binding of the instance step machine (DR-0033 chunk 5c).
//!
//! `DoInstanceDriver` is the DO counterpart to the native `NativeInstanceDriver`:
//! it implements the kernel's [`InstanceDriver`] seam over one held
//! `RuntimeKernel<DoSqliteStore<Sql>>`, so the same [`InstanceStepMachine`] drives
//! a workflow instance on the durable object. Because `DoSqliteStore` now
//! implements all three store traits (chunk 5a), the whole rule pass
//! (`step_instance_generic`) runs over the DO's one SQLite.
//!
//! What is wired: the rule pass (`advance_rules`), ready-effect discovery
//! (`next_ready_effect`), and `run_effect` dispatch of the lifted store-only
//! handler cores over the DO store — `event.emit`, the
//! `queue.*` family (via `WorkItems`), the lease/ledger/counter coordination family
//! (via `Coordination`), and the `file.*` family (via the `FileStore` seam). The
//! HTTP effects (coerce/agent) will suspend with `EffectStep::NeedsHttp` and be
//! fulfilled through the isolate's `fetch`; that + the remaining coupled cores
//! (notify/capability) are the rest of chunk 5b, so an unlifted kind still errors
//! clearly rather than silently skipping.

use whipplescript_kernel::coerce::{CoerceRequest, CoerceResult, CoerceStatus};
#[cfg(test)]
use whipplescript_kernel::coerce_native::CoerceProvider;
use whipplescript_kernel::coerce_native::{
    build_coerce_call_parts, build_request, parse_response, CoerceCall,
};
use whipplescript_kernel::context_assembly::{
    render_project_context, BundleKind, BundleProvenance, ProjectInstruction,
};
use whipplescript_kernel::effect_config::EffectConfig;
use whipplescript_kernel::effect_handlers::{
    run_capability_effect_generic, run_coordination_effect_generic, run_event_effect_generic,
    run_file_effect_generic, run_file_export_effect_generic, run_file_import_effect_generic,
    run_file_write_effect_generic, run_notify_effect_generic, run_queue_effect_generic,
    CapabilityContract, DeliveryGovernance, FixtureCapabilityProvider,
};
use whipplescript_kernel::exec_http::{
    build_executor_exec_request, decode_cached_exec_result, exec_content_key, ingest_exec_stdout,
    parse_executor_exec_response, settle_exec_http_result, ExecSettleContext,
};
use whipplescript_kernel::harness_loop::{
    provider_result_from_brokered_turn, BrokeredTurnInput, BrokeredTurnMachine,
    BrokeredTurnOutcome, BrokeredTurnSnapshot, ChatMessage, HttpModelClient, ImageBlock,
    NoopCompactor, ToolExecutor, TurnStatus,
};
use whipplescript_kernel::instance_machine::{EffectStep, InstanceDriver};
use whipplescript_kernel::rule_lowering::json_from_str;
use whipplescript_kernel::rule_pass::step_instance_generic;
use whipplescript_kernel::sansio::{
    HttpResponse, IoRequest, IoResult, Outcome, StepMachine, TransportError,
};
use whipplescript_kernel::AgentTurnExecution;
use whipplescript_kernel::{idempotency_key, CoerceExecution, RuntimeKernel};
use whipplescript_parser::IrProgram;
use whipplescript_store::files::FileStore;
use whipplescript_store::{ClaimableEffect, EvidenceRecord, RunStart, RuntimeStore, StoreError};

/// Projected coerce provider credentials (the DO secrets plane supplies these; a
/// live worker reads them from its bindings). This is the ONE canonical resolved
/// coerce config record (spec/std-coercion.md "Config-plane reconciliation"),
/// shared with the native door — the DO builds it from `coerce_config_json`
/// (`do_wasm::parse_coerce_config`). Everything else the coerce HTTP effect
/// needs is host-neutral in the kernel — `build_coerce_call_parts` +
/// `build_request` + `parse_response` + `settle_coerce_result` — so this config
/// is the whole of what the DO adds.
pub use whipplescript_kernel::coerce_native::ResolvedCoercionConfig;

/// The coercion-config fingerprint this DO's kernel folds into `schema.coerce`
/// effect admission keys (DR-0014 amendment) — derived from `coerce_config_json`
/// exactly as the native host derives it from its resolved config (same
/// combinator, same "fixture" literal when coerce is unconfigured), so an
/// identical config yields the identical fingerprint on either host.
pub fn do_coercion_config_fingerprint(coerce: Option<&ResolvedCoercionConfig>) -> String {
    coerce
        .map(|cfg| {
            whipplescript_kernel::coerce::coercion_config_fingerprint(
                "schema_coercer",
                &cfg.provider_id,
                &cfg.provider_id,
                &cfg.model,
            )
        })
        .unwrap_or_else(|| "fixture".to_owned())
}

use crate::do_store::{do_load_agent_snapshot, do_save_agent_snapshot, DoSql, DoSqliteStore};

/// Projected executor-sidecar wiring (compute plane P8): where Class-A exec
/// effects go (the DO cannot spawn processes — exec is HTTP to the sidecar,
/// DR-0033 Decision 7). `env_values` backs the script manifests' `env:`
/// references (the DO secrets plane supplies them); `environment_epoch` is
/// the delta-kernel cache's environment component (the workspace image
/// digest once the container tier wires it).
pub struct ExecutorSidecarConfig {
    pub base_url: String,
    pub env_values: std::collections::BTreeMap<String, String>,
    pub environment_epoch: String,
    pub timeout_ms: Option<u64>,
    pub auth_token: Option<String>,
}

/// Projected Class-B turn-container wiring (compute plane P8): when present,
/// agent turns run WHOLE inside a per-turn container over `whip-turn/1`
/// (v1 = the blocking `POST /turn` form; the shell routes the sentinel host
/// to a per-turn container instance). `provider` is the provider-config JSON
/// forwarded verbatim to the container ({"provider":"fixture"} runs
/// credential-free).
pub struct TurnContainerConfig {
    pub base_url: String,
    pub provider: serde_json::Value,
    pub max_steps: u64,
    pub auth_token: Option<String>,
}

/// `agent.tell` effects have two admitted producers. Authored workflow effects
/// carry the historical `{ "prompt": ... }` shape; the governed host facade
/// stores the complete `StartTurnCommand`, whose user text is nested at
/// `{ "input": { "text": ... } }`. Decode both explicitly at this adapter
/// edge and never turn an absent field into a valid empty model request.
fn agent_prompt(input: &serde_json::Value) -> Result<String, StoreError> {
    input
        .pointer("/input/text")
        .or_else(|| input.get("prompt"))
        .and_then(serde_json::Value::as_str)
        .filter(|prompt| !prompt.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            StoreError::Conflict(
                "agent.tell input omitted both host input.text and workflow prompt".to_owned(),
            )
        })
}

/// Refuse a turn whose grants name a resource this placement cannot serve.
///
/// Neither durable-object agent path can honor an external MCP server
/// (`spec/mcp-support-design-note.md` §12 slice 3). The in-isolate path would
/// need tool calls to suspend on `NeedsHttp` the way model calls already do,
/// and that stepped-tool-executor seam is shared with the still-unported web
/// tools, so it rides the DO tracker. The Class-B container path runs a real
/// process and could host MCP, but its turn server does not build those tools
/// today either (its selector is `tools: "file"|"none"`).
///
/// Until then the honest behavior is a REFUSAL, not a quieter turn. The DO
/// assembles its tool list from `do_tool_specs()` without ever reading
/// `access_grants`, so without this guard a program that grants
/// `github { create_issue }` runs here with that tool simply absent — the model
/// routes around the gap and returns a plausible wrong answer.
///
/// The DO cannot consult the operator's MCP registry, so it cannot tell an MCP
/// server from a file store by NAME. It does not have to: the lowering already
/// distinguishes them. A grant naming a declared `file store` carries a
/// `store_policy` snapshot (`rule_lowering::effect_access_grants_json`); no
/// other grant kind does. So the placement decides structurally:
///
///   * `store_policy` present -> a declared file store; the DO serves it.
///   * `tracker` / `command`  -> the DO has the todo tools and Bashkit.
///   * only memory verbs      -> a memory pool; the DO serves it.
///   * anything else          -> not honorable here. Refuse.
///
/// The last line is what a verb-only check would miss: the MCP role vocabulary
/// is deliberately `read`/`write`, so a rung-2/3 grant (`github { read }`)
/// reads exactly like a file-store grant on its verbs alone. It also refuses
/// `web { … }`, which the isolate cannot serve either.
fn refuse_mcp_grants_on_this_placement(input: &serde_json::Value) -> Result<(), StoreError> {
    const MEMORY_OPERATIONS: &[&str] = &["recall", "learn", "curate"];
    // Both admitted `agent.tell` input shapes carry grants: the workflow shape
    // at the top level and the governed-host shape nested under `input`.
    let grant_lists = [
        input.pointer("/access_grants"),
        input.pointer("/input/access_grants"),
    ];
    let mut unsupported = Vec::new();
    for grants in grant_lists.into_iter().flatten() {
        let Some(grants) = grants.as_array() else {
            continue;
        };
        for grant in grants {
            let resource = grant
                .get("resource")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            // A grant whose shape we cannot read is refused, not skipped: the
            // stated posture is fail-closed, and an unreadable grant is exactly
            // when guessing is least safe.
            let Some(operations) = grant.get("operations").and_then(|o| o.as_array()) else {
                unsupported.push(format!("{resource} (unreadable grant)"));
                continue;
            };
            let names: Vec<&str> = operations
                .iter()
                .filter_map(|operation| {
                    operation
                        .get("operation")
                        .and_then(serde_json::Value::as_str)
                })
                .filter(|name| !name.is_empty())
                .collect();
            if names.is_empty() {
                continue;
            }
            let is_file_store = grant.get("store_policy").is_some();
            let is_builtin_resource = matches!(resource, "tracker" | "command");
            let is_memory_pool = names.iter().all(|name| MEMORY_OPERATIONS.contains(name));
            if is_file_store || is_builtin_resource || is_memory_pool {
                continue;
            }
            unsupported.push(format!("{resource} {{ {} }}", names.join(" ")));
        }
    }
    unsupported.sort();
    unsupported.dedup();
    if unsupported.is_empty() {
        return Ok(());
    }
    Err(StoreError::Conflict(format!(
        "this turn grants {}, which this placement cannot honor: external MCP tool \
         servers are native-only for now (spec/mcp-support-design-note.md slice 3). \
         Run this workflow natively, or drop the grant.",
        unsupported.join(", ")
    )))
}

fn resolve_host_images<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    command_id: &str,
    command: &serde_json::Value,
) -> Result<Vec<ImageBlock>, StoreError> {
    let refs = command
        .get("input")
        .and_then(|input| input.get("images"))
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    refs.iter()
        .enumerate()
        .map(|(index, image)| {
            let selector = image
                .get("selector")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| StoreError::Conflict("host image ref has no selector".to_owned()))?;
            if image.get("handle").and_then(serde_json::Value::as_str) != Some("turn_images")
                || image.get("kind").and_then(serde_json::Value::as_str) != Some("image")
                || selector != index.to_string()
            {
                return Err(StoreError::Conflict(
                    "host image ref is outside the admitted turn-image capability".to_owned(),
                ));
            }
            let rows = sql
                .query(
                    "SELECT media_type, data_base64 FROM host_turn_images \
                     WHERE instance_id = ?1 AND command_id = ?2 AND selector = ?3",
                    &[
                        crate::do_store::SqlValue::Text(instance_id.to_owned()),
                        crate::do_store::SqlValue::Text(command_id.to_owned()),
                        crate::do_store::SqlValue::Text(selector.to_owned()),
                    ],
                )
                .map_err(StoreError::Conflict)?;
            let row = rows.first().ok_or_else(|| {
                StoreError::Conflict("admitted host image body is unavailable".to_owned())
            })?;
            let text = |value: &crate::do_store::SqlValue| match value {
                crate::do_store::SqlValue::Text(value) => Ok(value.clone()),
                _ => Err(StoreError::Conflict(
                    "admitted host image body has an invalid SQL shape".to_owned(),
                )),
            };
            Ok(ImageBlock {
                media_type: text(&row[0])?,
                data_base64: text(&row[1])?,
            })
        })
        .collect()
}

/// Drives a workflow instance's rule pass + effect discovery on the durable object.
pub struct DoInstanceDriver<'a, Sql: DoSql> {
    /// One held kernel over the DO's SQLite (backs runtime + coordination +
    /// work-items surfaces).
    pub kernel: RuntimeKernel<DoSqliteStore<Sql>>,
    /// The DO's file byte store (small files inline in DO SQLite, large spilled) —
    /// the `FileStore` seam the file effects cross. `DoFileStore` / `TieredFileStore`.
    pub files: &'a dyn FileStore,
    /// Projected coerce provider credentials, or `None` if coerce is not configured
    /// on this DO (a `coerce.call` then errors rather than degrading silently).
    pub coerce: Option<&'a ResolvedCoercionConfig>,
    /// The DO agent model client (builds the messages request + parses the reply);
    /// `None` if agent turns are not configured. A live worker's impl reads creds
    /// from its bindings; tests inject a fake.
    pub agent_model: Option<&'a dyn HttpModelClient>,
    /// Executes tool calls the model requests within a turn (nested effects). A live
    /// DO brokers these as HTTP to a sidecar; tests inject a fake.
    pub agent_tools: &'a dyn ToolExecutor,
    pub agent_tool_specs: Option<&'a [whipplescript_kernel::harness_loop::ToolSpec]>,
    /// Executor-sidecar wiring for Class-A exec effects (compute plane P8), or
    /// `None` if no sidecar is configured (an `exec.command` then errors).
    pub exec: Option<&'a ExecutorSidecarConfig>,
    /// Class-B turn-container wiring: when present, agent turns run whole in
    /// a per-turn container instead of the in-DO brokered machine.
    pub turn: Option<&'a TurnContainerConfig>,
    pub ir: &'a IrProgram,
    pub instance_id: &'a str,
}

/// Durable-object delivery governance. The mock DO is ungoverned (no envelope in
/// env), so no cross-package internal-workflow delivery is forbidden; a live DO
/// answers this from its bindings/secrets — the governance plane plugged in with
/// the infra (mirrors the native `IfcDeliveryGovernance`).
struct DoDeliveryGovernance;
impl DeliveryGovernance for DoDeliveryGovernance {
    fn any_internal_workflow(&self, _resources: &[String]) -> Result<bool, String> {
        Ok(false)
    }
}

/// Durable-object capability contract. The mock DO carries no package-lock, so no
/// output-validation constraint applies; a live DO validates against the contract
/// in its program metadata (plugged in with the infra; mirrors the native
/// `PackageLockCapabilityContract`).
struct DoCapabilityContract;
impl CapabilityContract for DoCapabilityContract {
    fn validate_output(
        &self,
        _effect: &ClaimableEffect,
        _value: &serde_json::Value,
    ) -> Option<String> {
        None
    }
}

impl<Sql: DoSql + Clone> InstanceDriver for DoInstanceDriver<'_, Sql> {
    fn advance_rules(&mut self) -> Result<bool, StoreError> {
        step_instance_generic(&mut self.kernel, self.instance_id, self.ir, None, None)?;
        let terminal = self
            .kernel
            .store()
            .status(self.instance_id)?
            .map(|status| status.instance.status != "running")
            .unwrap_or(true);
        Ok(terminal)
    }

    fn next_ready_effect(&mut self) -> Result<Option<ClaimableEffect>, StoreError> {
        Ok(self
            .kernel
            .claimable_effects(self.instance_id)?
            .into_iter()
            .next())
    }

    fn advance_time(&mut self, now: &str) -> Result<(), StoreError> {
        // The lifted due-time passes (DR-0033 Phase 6): complete due timers,
        // expire deadline-passed effects, and fire due clock-source
        // occurrences as durable signal facts — the same passes the native
        // dev loop runs, over the DO's threaded store. `now` is injected.
        whipplescript_kernel::time_pass::resolve_due_time_effects(
            &mut self.kernel,
            self.instance_id,
            now,
        )?;
        whipplescript_kernel::time_pass::resolve_due_clock_sources(
            &mut self.kernel,
            self.instance_id,
            now,
            self.ir,
        )?;
        Ok(())
    }

    fn next_due_unix_ms(&mut self, now: &str) -> Result<Option<i64>, StoreError> {
        // The earliest of: pending timed effects (creation-anchored timeouts
        // + explicit deadlines) and the next clock-source occurrence.
        let effect_due = self
            .kernel
            .store()
            .next_effect_due_epoch_ms(self.instance_id)?;
        let clock_due = whipplescript_kernel::time_pass::next_clock_due_unix_ms(
            &mut self.kernel,
            self.instance_id,
            now,
            self.ir,
        )?;
        Ok(match (effect_due, clock_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        })
    }

    fn run_effect(
        &mut self,
        effect: &ClaimableEffect,
        incoming: Option<Result<HttpResponse, TransportError>>,
    ) -> Result<EffectStep, StoreError> {
        // The store-only handler cores are host-agnostic (`kernel::effect_handlers`),
        // so the DO runs them over its `RuntimeKernel<DoSqliteStore>`. Fixture
        // outcomes do not apply on the DO (real execution), so `outcome_failed` is
        // false. The rest of the store-only cores + the HTTP effects land as they
        // are lifted (chunk 5b); an unlifted kind errors clearly rather than skips.
        let config = EffectConfig {
            provider: "do".to_owned(),
            outcome_failed: false,
        };
        let event = match effect.kind.as_str() {
            "event.emit" => {
                run_event_effect_generic(&mut self.kernel, self.instance_id, effect, &config)?
            }
            "signal.emit" => run_notify_effect_generic(
                &mut self.kernel,
                self.instance_id,
                effect,
                &DoDeliveryGovernance,
            )?,
            "capability.call" => {
                // Binding-driven provider selection (spec/std-memory.md; the DO
                // package bootstrap seeds the std.memory binding): a
                // `memory-provider`-bound capability routes to the real
                // DoMemoryStore-backed provider, everything else to the fixture.
                let bound = effect
                    .target
                    .as_deref()
                    .filter(|target| !target.is_empty())
                    .map(|target| {
                        self.kernel
                            .store()
                            .capability_bound_provider(self.instance_id, target)
                    })
                    .transpose()?
                    .flatten();
                if bound.as_deref() == Some("memory-provider") {
                    let provider = crate::do_memory::DoMemoryCapabilityProvider {
                        sql: self.kernel.store().sql.clone(),
                    };
                    run_capability_effect_generic(
                        &mut self.kernel,
                        self.instance_id,
                        effect,
                        &config,
                        &DoCapabilityContract,
                        &provider,
                    )?
                } else {
                    run_capability_effect_generic(
                        &mut self.kernel,
                        self.instance_id,
                        effect,
                        &config,
                        &DoCapabilityContract,
                        &FixtureCapabilityProvider,
                    )?
                }
            }
            // The agent turn: multi-round sans-IO. Each round drives the
            // BrokeredTurnMachine one provider call, persisting its snapshot so an
            // eviction between fetches loses nothing (snapshot/restore); on the final
            // reply the outcome settles through the shared kernel seam.
            // Class-B (compute plane P8): with a turn container configured,
            // the WHOLE agent turn runs in a per-turn container — one
            // blocking whip-turn/1 round; dispatch is idempotent (a re-sent
            // start re-attaches to the same turn in the container registry),
            // so an eviction mid-await recovers by re-entering this arm.
            "agent.tell" if self.turn.is_some() => {
                let cfg = self.turn.expect("guarded by arm pattern");
                let input = json_from_str(&effect.input_json);
                let prompt = agent_prompt(&input)?;
                // Fail closed before any provider work: a grant this placement
                // cannot honor must stop the turn, not shrink it silently.
                refuse_mcp_grants_on_this_placement(&input)?;
                let user_images = resolve_host_images(
                    &self.kernel.store().sql,
                    self.instance_id,
                    &effect.effect_id,
                    &input,
                )?;
                let run_id = idempotency_key(&[self.instance_id, &effect.effect_id, "agent-run"]);
                let lease_id =
                    idempotency_key(&[self.instance_id, &effect.effect_id, "agent-lease"]);
                match incoming {
                    None => {
                        self.kernel.start_run(RunStart {
                            instance_id: self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: "agent",
                            worker_id: "whip-turn-container",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            metadata_json: r#"{"class":"B"}"#,
                        })?;
                        let mut headers =
                            vec![("content-type".to_owned(), "application/json".to_owned())];
                        if let Some(token) = &cfg.auth_token {
                            headers.push(("authorization".to_owned(), format!("Bearer {token}")));
                        }
                        let request = whipplescript_kernel::sansio::HttpRequest {
                            url: format!("{}/turn", cfg.base_url.trim_end_matches('/')),
                            headers,
                            body: serde_json::json!({
                                "protocol": "whip-turn/1",
                                "turn_id": effect.effect_id,
                                "provider": cfg.provider,
                                "user": prompt,
                                "images": user_images,
                                "tools": "file",
                                "max_steps": cfg.max_steps,
                            }),
                        };
                        return Ok(EffectStep::NeedsHttp(request));
                    }
                    Some(resumed) => {
                        let outcome = match resumed {
                            Ok(response) if response.status == 200 => {
                                let outcome = response
                                    .body
                                    .get("outcome")
                                    .cloned()
                                    .unwrap_or(serde_json::Value::Null);
                                let status = match outcome
                                    .get("status")
                                    .and_then(|value| value.as_str())
                                    .unwrap_or("failed")
                                {
                                    "completed" => TurnStatus::Completed,
                                    "timed_out" => TurnStatus::TimedOut,
                                    "cancelled" => TurnStatus::Cancelled,
                                    _ => TurnStatus::Failed,
                                };
                                BrokeredTurnOutcome {
                                    status,
                                    summary: outcome
                                        .get("summary")
                                        .and_then(|value| value.as_str())
                                        .unwrap_or_default()
                                        .to_owned(),
                                    steps: outcome
                                        .get("steps")
                                        .and_then(|value| value.as_u64())
                                        .unwrap_or(0)
                                        as usize,
                                    observations: Vec::new(),
                                    usage: outcome
                                        .get("usage")
                                        .cloned()
                                        .unwrap_or_else(|| serde_json::json!({})),
                                }
                            }
                            Ok(response) => BrokeredTurnOutcome {
                                status: TurnStatus::Failed,
                                summary: format!(
                                    "turn container returned status {}: {}",
                                    response.status,
                                    response
                                        .body
                                        .get("error")
                                        .and_then(|value| value.as_str())
                                        .unwrap_or("no detail")
                                ),
                                steps: 0,
                                observations: Vec::new(),
                                usage: serde_json::json!({}),
                            },
                            Err(transport) => BrokeredTurnOutcome {
                                status: TurnStatus::Failed,
                                summary: format!("turn container transport error: {transport:?}"),
                                steps: 0,
                                observations: Vec::new(),
                                usage: serde_json::json!({}),
                            },
                        };
                        let result = provider_result_from_brokered_turn(&outcome);
                        let execution = AgentTurnExecution {
                            instance_id: self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: "agent",
                            worker_id: "whip-turn-container",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            agent: "agent",
                            profile: None,
                            input_json: &effect.input_json,
                            skill_names: &[],
                        };
                        self.kernel.settle_provider_run_result(
                            execution,
                            r#"{"class":"B"}"#,
                            &result,
                        )?
                    }
                }
            }
            "agent.tell" => {
                let model = self.agent_model.ok_or_else(|| {
                    StoreError::Conflict(
                        "no agent model is configured on this durable object".to_owned(),
                    )
                })?;
                let input = json_from_str(&effect.input_json);
                let prompt = agent_prompt(&input)?;
                // Fail closed before any provider work: a grant this placement
                // cannot honor must stop the turn, not shrink it silently.
                refuse_mcp_grants_on_this_placement(&input)?;
                let agent = effect.target.as_deref().unwrap_or("agent");
                let loaded = do_load_agent_snapshot(&self.kernel.store().sql, &effect.effect_id)?;
                // Image bodies are message-scoped. A restored machine already
                // contains the exact first-round input in its snapshot, so
                // resumption must not retain or replay the broker cache.
                let resolved_images = if loaded.is_some() {
                    Vec::new()
                } else {
                    resolve_host_images(
                        &self.kernel.store().sql,
                        self.instance_id,
                        &effect.effect_id,
                        &input,
                    )?
                };
                let mut resume_from = if loaded.is_none() {
                    self.kernel
                        .snapshot_agent_thread(self.instance_id, agent, None)?
                } else {
                    Vec::new()
                };
                if loaded.is_none() && !resume_from.is_empty() {
                    resume_from.push(ChatMessage::User {
                        text: prompt.clone(),
                        images: resolved_images.clone(),
                    });
                }
                let user_images = if resume_from.is_empty() {
                    resolved_images
                } else {
                    Vec::new()
                };
                // Store-backed project instructions (context-assembly Phase 3
                // item 4): the DO has no filesystem, so AGENTS.md/CLAUDE.md
                // content registered at deploy resolves from the store — the
                // same wrapper bytes the native fs path injects.
                let docs = self.kernel.store().list_project_context_docs()?;
                let (system, context_bundles) = if docs.is_empty() {
                    ("You are a WhippleScript agent.".to_owned(), Vec::new())
                } else {
                    let instructions: Vec<ProjectInstruction> = docs
                        .iter()
                        .map(|doc| ProjectInstruction {
                            path: doc.path.clone(),
                            content: doc.body.clone(),
                        })
                        .collect();
                    let block = render_project_context(&instructions);
                    let bundles = docs
                        .iter()
                        .map(|doc| BundleProvenance {
                            kind: BundleKind::ProjectContext,
                            source: doc.path.clone(),
                            version: String::new(),
                            content_hash: doc.content_hash.clone(),
                        })
                        .collect();
                    (
                        format!("You are a WhippleScript agent.\n\n{block}"),
                        bundles,
                    )
                };
                let turn_input = BrokeredTurnInput {
                    system,
                    user: prompt,
                    // P4: the DO agent turn advertises the in-isolate tool set
                    // (read/write/edit/ls/find/grep/recall + the tracker todos),
                    // brokered by the `DoToolExecutor` over the DO file plane.
                    tools: self
                        .agent_tool_specs
                        .map(<[_]>::to_vec)
                        .unwrap_or_else(crate::do_tools::do_tool_specs),
                    max_steps: 8,
                    resume_from,
                    user_images,
                    context_bundles,
                    pinned_skills: Vec::new(),
                };
                let run_id = idempotency_key(&[self.instance_id, &effect.effect_id, "agent-run"]);
                let lease_id =
                    idempotency_key(&[self.instance_id, &effect.effect_id, "agent-lease"]);
                if loaded.is_none() {
                    self.kernel.start_run(RunStart {
                        instance_id: self.instance_id,
                        effect_id: &effect.effect_id,
                        run_id: &run_id,
                        provider: "agent",
                        worker_id: "whip-worker",
                        lease_id: &lease_id,
                        lease_expires_at: "2030-01-01T00:00:00Z",
                        metadata_json: "{}",
                    })?;
                    // Context-assembly Phase 1 seam: one context.bundle row per
                    // assembled bundle, fresh starts only (resume must not
                    // duplicate) — same discipline as the native owned turn.
                    for bundle in &turn_input.context_bundles {
                        let metadata = serde_json::json!({
                            "kind": bundle.kind.tag(),
                            "source": bundle.source,
                            "version": bundle.version,
                            "content_hash": bundle.content_hash,
                        })
                        .to_string();
                        self.kernel.store_mut().record_evidence(EvidenceRecord {
                            instance_id: self.instance_id,
                            kind: "context.bundle",
                            subject_type: "run",
                            subject_id: &run_id,
                            causation_id: None,
                            correlation_id: Some(&effect.effect_id),
                            summary: Some(bundle.kind.tag()),
                            metadata_json: &metadata,
                        })?;
                    }
                }
                let mut discard = |_: &[ChatMessage]| {};
                // The DO agent turn now brokers a real in-isolate tool set (P4);
                // conversation compaction (context-assembly Phase 4 Layer B) is a
                // separate lift, so drive the machine with the no-op compactor for now.
                let compactor = NoopCompactor;
                let mut machine = match loaded {
                    None => BrokeredTurnMachine::new(
                        model,
                        self.agent_tools,
                        &turn_input,
                        &mut discard,
                        &compactor,
                    ),
                    Some(json) => {
                        let snapshot: BrokeredTurnSnapshot = serde_json::from_str(&json)
                            .map_err(|error| StoreError::Conflict(error.to_string()))?;
                        BrokeredTurnMachine::restore(
                            model,
                            self.agent_tools,
                            &turn_input,
                            &mut discard,
                            &compactor,
                            snapshot,
                        )
                    }
                };
                let step = machine.step(incoming.map(IoResult::Http));
                match step {
                    Outcome::NeedsIo(IoRequest::Http(request)) => {
                        let json = serde_json::to_string(&machine.snapshot())
                            .map_err(|error| StoreError::Conflict(error.to_string()))?;
                        do_save_agent_snapshot(&self.kernel.store().sql, &effect.effect_id, &json)?;
                        return Ok(EffectStep::NeedsHttp(request));
                    }
                    Outcome::Settle(outcome) => {
                        let result = provider_result_from_brokered_turn(&outcome);
                        let execution = AgentTurnExecution {
                            instance_id: self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: "agent",
                            worker_id: "whip-worker",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            agent,
                            profile: None,
                            input_json: &effect.input_json,
                            skill_names: &[],
                        };
                        self.kernel
                            .settle_provider_run_result(execution, "{}", &result)?
                    }
                }
            }
            // The coerce HTTP effect: the sans-IO suspend/resume DR-0033 exists for.
            // First pass builds the provider request (pure kernel: parts + request)
            // and yields `NeedsHttp`; the host awaits `fetch` and re-enters with the
            // response, which `parse_response` + `settle_coerce_result` turn into the
            // terminal — every piece host-neutral in the kernel but the creds.
            "schema.coerce" => {
                let cfg = self.coerce.ok_or_else(|| {
                    StoreError::Conflict(
                        "coerce provider is not configured on this durable object".to_owned(),
                    )
                })?;
                let input = json_from_str(&effect.input_json);
                let function_name = input
                    .get("function_name")
                    .and_then(|value| value.as_str())
                    .unwrap_or("coerce")
                    .to_owned();
                let arguments = input
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let output_type = input
                    .get("output_type")
                    .and_then(|value| value.as_str())
                    .unwrap_or("json")
                    .to_owned();
                let (prompt, output_schema, wrapped, schema_name) =
                    build_coerce_call_parts(self.ir, &function_name, &arguments)
                        .map_err(StoreError::Conflict)?;
                let run_id = idempotency_key(&[self.instance_id, &effect.effect_id, "coerce-run"]);
                let lease_id =
                    idempotency_key(&[self.instance_id, &effect.effect_id, "coerce-lease"]);
                // Stable per-effect `Idempotency-Key` (DR-0033): identical across a
                // resume of this coerce effect so OpenAI/codex dedupe the resumed
                // provider call after a worker eviction. Derived here where the
                // effect identity (instance_id + effect_id) is in scope.
                let idem_key = idempotency_key(&[self.instance_id, &effect.effect_id, "coerce"]);
                let request = CoerceRequest::with_evidence_hashes(
                    function_name,
                    arguments.to_string(),
                    output_type,
                );
                match incoming {
                    // Prepare: build the provider request and suspend on `fetch`.
                    None => {
                        self.kernel.start_run(RunStart {
                            instance_id: self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: &cfg.provider_id,
                            worker_id: "whip-worker",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            metadata_json: "{}",
                        })?;
                        let call = CoerceCall {
                            provider: cfg.backend,
                            base_url: &cfg.base_url,
                            api_key: &cfg.api_key,
                            model: &cfg.model,
                            prompt: &prompt,
                            output_schema: &output_schema,
                            schema_name: &schema_name,
                            max_tokens: cfg.max_tokens,
                            codex: None,
                            idempotency_key: &idem_key,
                        };
                        return Ok(EffectStep::NeedsHttp(build_request(&call)));
                    }
                    // Finish: decode the fetched response (or a transport failure)
                    // and settle it through the shared kernel seam.
                    resumed => {
                        let result = match resumed {
                            Some(Ok(response)) => parse_response(cfg.backend, &response, wrapped),
                            other => CoerceResult {
                                status: CoerceStatus::Failed,
                                value_json: None,
                                error_json: Some(
                                    serde_json::json!({
                                        "transport": format!("{other:?}"),
                                    })
                                    .to_string(),
                                ),
                                summary: "coerce transport error".to_owned(),
                                transcript: String::new(),
                                usage_json: r#"{"input_tokens":0,"output_tokens":0}"#.to_owned(),
                            },
                        };
                        let execution = CoerceExecution {
                            instance_id: self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: &cfg.provider_id,
                            worker_id: "whip-worker",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            request: &request,
                            model: None,
                        };
                        self.kernel.settle_coerce_result(execution, &result)?
                    }
                }
            }
            // Class-A exec (compute plane P8): the DO cannot spawn processes,
            // so a script-capability exec is one `whip-executor/1` HTTP round
            // to the sidecar — with the delta-kernel result cache consulted
            // first (a hit settles without any HTTP at all).
            "exec.command" => {
                let cfg = self.exec.ok_or_else(|| {
                    StoreError::Conflict(
                        "executor sidecar is not configured on this durable object".to_owned(),
                    )
                })?;
                let input = json_from_str(&effect.input_json);
                let mode = input
                    .get("mode")
                    .and_then(|value| value.as_str())
                    .unwrap_or("raw");
                if mode != "capability" {
                    return Err(StoreError::Conflict(
                        "raw exec is not allowed on the durable object; declare a script \
                         capability"
                            .to_owned(),
                    ));
                }
                let capability = input
                    .get("capability")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default()
                    .to_owned();
                let parse_contract = input.get("parse").cloned();
                let stdin = input
                    .get("stdin")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);
                let stdin_json = stdin.to_string();
                let script = self
                    .kernel
                    .store()
                    .get_script_capability(&capability)?
                    .ok_or_else(|| {
                        StoreError::Conflict(format!(
                            "script capability `{capability}` is not registered in the store"
                        ))
                    })?;
                let argv: Vec<String> =
                    serde_json::from_str(&script.argv_json).map_err(|error| {
                        StoreError::Conflict(format!(
                            "script capability `{capability}` argv is invalid: {error}"
                        ))
                    })?;
                let env_refs: std::collections::BTreeMap<String, String> =
                    serde_json::from_str(&script.env_json).map_err(|error| {
                        StoreError::Conflict(format!(
                            "script capability `{capability}` env is invalid: {error}"
                        ))
                    })?;
                let mut resolved_env = Vec::new();
                for (name, reference) in env_refs {
                    let Some(env_name) = reference.strip_prefix("env:") else {
                        return Err(StoreError::Conflict(format!(
                            "script capability `{capability}` env `{name}` must use an env: \
                             reference"
                        )));
                    };
                    let value = cfg.env_values.get(env_name).ok_or_else(|| {
                        StoreError::Conflict(format!(
                            "script capability `{capability}` requires `{env_name}`, which the \
                             executor config does not supply"
                        ))
                    })?;
                    resolved_env.push((name, value.clone()));
                }
                let run_id = idempotency_key(&[self.instance_id, &effect.effect_id, "exec-run"]);
                let lease_id =
                    idempotency_key(&[self.instance_id, &effect.effect_id, "exec-lease"]);
                let content_key = script.hermetic.then(|| {
                    exec_content_key(
                        &script.sha256,
                        &argv,
                        &resolved_env,
                        &cfg.environment_epoch,
                        &stdin_json,
                        &parse_contract,
                    )
                });
                let ingest_schema = parse_contract
                    .as_ref()
                    .and_then(|contract| contract.get("schema"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("json")
                    .to_owned();
                match incoming {
                    None => {
                        self.kernel.start_run(RunStart {
                            instance_id: self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            provider: "exec",
                            worker_id: "whip-exec",
                            lease_id: &lease_id,
                            lease_expires_at: "2030-01-01T00:00:00Z",
                            metadata_json: &serde_json::json!({
                                "mode": "capability", "capability": capability,
                            })
                            .to_string(),
                        })?;
                        // Delta-kernel cache: a hit settles right here — no
                        // container wakes, no HTTP round.
                        if let Some(key) = &content_key {
                            if let Some(hit) = self
                                .kernel
                                .store()
                                .lookup_compute_result(key)?
                                .and_then(|entry| decode_cached_exec_result(&entry.result_json))
                            {
                                let ctx = ExecSettleContext {
                                    instance_id: self.instance_id,
                                    effect_id: &effect.effect_id,
                                    run_id: &run_id,
                                    capability: &capability,
                                    script_sha256: &script.sha256,
                                    cache: Some((key, true)),
                                    ingest_schema: &ingest_schema,
                                };
                                let event =
                                    settle_exec_http_result(&mut self.kernel, &ctx, Ok(hit))?;
                                return Ok(EffectStep::Done(event));
                            }
                        }
                        let mut request = build_executor_exec_request(
                            &cfg.base_url,
                            &effect.effect_id,
                            &script.sha256,
                            &script.body,
                            &argv,
                            &resolved_env,
                            &stdin,
                            cfg.timeout_ms,
                        )
                        .map_err(StoreError::Conflict)?;
                        if let Some(token) = &cfg.auth_token {
                            request
                                .headers
                                .push(("authorization".to_owned(), format!("Bearer {token}")));
                        }
                        return Ok(EffectStep::NeedsHttp(request));
                    }
                    resumed => {
                        let outcome = match resumed {
                            Some(Ok(response)) => match parse_executor_exec_response(&response) {
                                Ok(result) if result.timed_out => Err((
                                    Some((result.exit_code, result.stdout, result.stderr)),
                                    "exec command timed out on the executor sidecar".to_owned(),
                                )),
                                Ok(result) if result.exit_code != 0 => Err((
                                    Some((result.exit_code, result.stdout.clone(), result.stderr)),
                                    format!("exec command exited with status {}", result.exit_code),
                                )),
                                Ok(result) => match &parse_contract {
                                    Some(contract) => {
                                        match ingest_exec_stdout(contract, &result.stdout) {
                                            Ok(ingested) => Ok((
                                                result.exit_code,
                                                result.stdout,
                                                result.stderr,
                                                Some(ingested),
                                            )),
                                            Err(reason) => Err((
                                                Some((
                                                    result.exit_code,
                                                    result.stdout,
                                                    result.stderr,
                                                )),
                                                reason,
                                            )),
                                        }
                                    }
                                    None => {
                                        Ok((result.exit_code, result.stdout, result.stderr, None))
                                    }
                                },
                                Err(reason) => Err((None, reason)),
                            },
                            other => Err((None, format!("executor transport error: {other:?}"))),
                        };
                        let ctx = ExecSettleContext {
                            instance_id: self.instance_id,
                            effect_id: &effect.effect_id,
                            run_id: &run_id,
                            capability: &capability,
                            script_sha256: &script.sha256,
                            cache: content_key.as_deref().map(|key| (key, false)),
                            ingest_schema: &ingest_schema,
                        };
                        settle_exec_http_result(&mut self.kernel, &ctx, outcome)?
                    }
                }
            }
            "tracker.file" | "tracker.claim" | "tracker.renew" | "tracker.release"
            | "tracker.finish" => {
                // The DO worker uses "now" as its clock stub (like coordination
                // below); deterministic/real-clock injection — hence a live claim
                // `ttl` deadline — is a native/scenario concern for now. The renew
                // heartbeat and untimed claims are unaffected.
                run_queue_effect_generic(
                    &mut self.kernel,
                    self.instance_id,
                    effect,
                    "now",
                    &config,
                )?
            }
            "lease.acquire" | "lease.release" | "lease.renew" | "ledger.append"
            | "counter.consume" => {
                // The DO worker uses wall-clock time for the bounded-wait deadline;
                // deterministic-clock injection is a native/scenario concern.
                run_coordination_effect_generic(&mut self.kernel, self.instance_id, effect, "now")?
            }
            "file.read" => {
                run_file_effect_generic(&mut self.kernel, self.files, self.instance_id, effect)?
            }
            "file.write" => run_file_write_effect_generic(
                &mut self.kernel,
                self.files,
                self.instance_id,
                effect,
            )?,
            "file.import" => run_file_import_effect_generic(
                &mut self.kernel,
                self.files,
                self.instance_id,
                effect,
            )?,
            // std.files slice F4: the export core moved from the CLI into
            // kernel::effect_handlers (it was already generic over the
            // FileStore seam), so exports now run on the DO plane like their
            // three siblings — closing the export exception to DO parity.
            "file.export" => run_file_export_effect_generic(
                &mut self.kernel,
                self.files,
                self.instance_id,
                effect,
            )?,
            other => {
                // No DO handler for this kind (e.g. `workflow.invoke` — its
                // handler core is not lifted; HTTP wiring pending, chunk 5b).
                // FAIL the effect with its settling fact instead of erroring
                // the step: an error here re-poisons every subsequent pass,
                // wedging the instance with no terminal, while a failed effect
                // routes through `after x fails` or the auto-fail net.
                let run_id =
                    idempotency_key(&[self.instance_id, &effect.effect_id, "do-unsupported-run"]);
                let summary = format!(
                    "effect kind `{other}` is not executable on the durable object placement"
                );
                self.kernel.start_run(RunStart {
                    instance_id: self.instance_id,
                    effect_id: &effect.effect_id,
                    run_id: &run_id,
                    provider: "durable-object",
                    worker_id: "do-worker",
                    lease_id: &idempotency_key(&[
                        self.instance_id,
                        &effect.effect_id,
                        "do-unsupported-lease",
                    ]),
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    metadata_json: "{}",
                })?;
                let event = self
                    .kernel
                    .fail_run(whipplescript_store::EffectCompletion {
                        instance_id: self.instance_id,
                        effect_id: &effect.effect_id,
                        run_id: &run_id,
                        provider: "durable-object",
                        worker_id: "do-worker",
                        status: "failed",
                        exit_code: None,
                        summary: Some(&summary),
                        metadata_json: "{}",
                        idempotency_key: Some(&idempotency_key(&[
                            self.instance_id,
                            &effect.effect_id,
                            "terminal",
                        ])),
                    })?;
                let value_json = serde_json::json!({
                    "effect_id": effect.effect_id,
                    "run_id": run_id,
                    "status": "failed",
                    "summary": summary,
                    "value": {
                        "reason": summary,
                        "summary": summary,
                        "error_class": "unsupported_placement",
                    },
                })
                .to_string();
                self.kernel.derive_fact(
                    self.instance_id,
                    "effect.failed",
                    &effect.effect_id,
                    &value_json,
                    Some(&event.event_id),
                    Some(&idempotency_key(&[
                        self.instance_id,
                        &effect.effect_id,
                        "unsupported-failed-fact",
                    ])),
                )?;
                event
            }
        };
        Ok(EffectStep::Done(event))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whipplescript_kernel::instance_machine::{InstanceOutcome, InstanceStepMachine};
    use whipplescript_kernel::sansio::{run_to_completion, HostDriver, IoRequest, IoResult};
    use whipplescript_kernel::ProgramVersionInput;
    use whipplescript_store::NewInstanceAuthority;

    use crate::do_store::test_support::store;

    /// Refuses I/O — a store-only / effect-free run never asks for it.
    struct RefuseIoHost;
    impl HostDriver for RefuseIoHost {
        fn fulfill(&self, _request: &IoRequest) -> IoResult {
            IoResult::Http(Err(TransportError::Transport(
                "no DO I/O expected".to_owned(),
            )))
        }
    }

    /// A no-op `ToolExecutor` for turns that request no tools.
    struct NoTools;
    impl ToolExecutor for NoTools {
        fn execute(
            &self,
            call: &whipplescript_kernel::harness_loop::ToolCall,
        ) -> whipplescript_kernel::harness_loop::ToolOutcome {
            whipplescript_kernel::harness_loop::ToolOutcome {
                status: whipplescript_kernel::harness_loop::ToolStatus::Error,
                content: format!("no tool executor on this test DO: {}", call.name),
            }
        }
    }

    /// A `FileStore` stub for effect-free runs (no file effect touches it).
    struct NoFiles;
    impl FileStore for NoFiles {
        fn read_to_string(&self, _path: &std::path::Path) -> std::io::Result<String> {
            Err(std::io::Error::other("no files in this test"))
        }
        fn exists(&self, _path: &std::path::Path) -> bool {
            false
        }
        fn create_dir_all(&self, _path: &std::path::Path) -> std::io::Result<()> {
            Ok(())
        }
        fn write(&self, _path: &std::path::Path, _bytes: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("no files in this test"))
        }
        fn append(&self, _path: &std::path::Path, _bytes: &[u8]) -> std::io::Result<()> {
            Err(std::io::Error::other("no files in this test"))
        }
        fn remove(&self, _path: &std::path::Path) -> std::io::Result<()> {
            Err(std::io::Error::other("no files in this test"))
        }
    }

    #[test]
    fn a_placement_refuses_an_mcp_grant_instead_of_dropping_it() {
        // An MCP grant reaches the DO as an ordinary access grant whose
        // operations are tool names. The placement has no MCP client and never
        // reads access_grants when building its tool list, so without this
        // guard the turn would run with `create_issue` simply missing.
        let granted = serde_json::json!({
            "input": { "text": "File the bug." },
            "access_grants": [
                { "resource": "github",
                  "operations": [ { "operation": "create_issue" } ] }
            ]
        });
        let error = match refuse_mcp_grants_on_this_placement(&granted) {
            Err(StoreError::Conflict(message)) => message,
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert!(error.contains("github { create_issue }"), "{error}");
        assert!(error.contains("native-only"), "{error}");

        // The sharp case: the MCP role vocabulary is deliberately `read`/`write`,
        // so on verbs alone a role grant is indistinguishable from a file-store
        // grant. It is caught because a real file-store grant carries a
        // `store_policy` snapshot and this one does not.
        let role_granted = serde_json::json!({
            "input": { "text": "Read the issues." },
            "access_grants": [
                { "resource": "github", "operations": [ { "operation": "read" } ] }
            ]
        });
        assert!(refuse_mcp_grants_on_this_placement(&role_granted).is_err());

        // The governed-host shape nests grants under `input`; that path is
        // guarded too, not only the workflow shape.
        let nested = serde_json::json!({
            "input": {
                "text": "File the bug.",
                "access_grants": [
                    { "resource": "github",
                      "operations": [ { "operation": "create_issue" } ] }
                ]
            }
        });
        assert!(refuse_mcp_grants_on_this_placement(&nested).is_err());

        // The resources this placement DOES honor still pass: a declared file
        // store (carrying its policy snapshot), the tracker, Bashkit, a memory
        // pool — and a tracker verb this guard does not enumerate.
        let builtin = serde_json::json!({
            "input": { "text": "Work." },
            "access_grants": [
                { "resource": "project",
                  "store_policy": { "root": ".", "allow_read": ["**"], "allow_write": ["**"] },
                  "operations": [ { "operation": "read" }, { "operation": "write" } ] },
                { "resource": "tracker", "operations": [ { "operation": "list" } ] },
                { "resource": "command", "operations": [ { "operation": "run" } ] },
                { "resource": "notes", "operations": [ { "operation": "recall" } ] }
            ]
        });
        assert!(
            refuse_mcp_grants_on_this_placement(&builtin).is_ok(),
            "a placement-honored grant set must not be refused"
        );

        // `web` is refused: the isolate has no web tools either.
        let web = serde_json::json!({
            "input": { "text": "Research." },
            "access_grants": [
                { "resource": "web", "operations": [
                    { "operation": "search" }, { "operation": "fetch" } ] }
            ]
        });
        assert!(refuse_mcp_grants_on_this_placement(&web).is_err());

        // An unreadable grant shape fails CLOSED, matching the stated posture.
        let malformed = serde_json::json!({
            "input": { "text": "Work." },
            "access_grants": [ { "resource": "github" } ]
        });
        assert!(refuse_mcp_grants_on_this_placement(&malformed).is_err());

        // A turn with no grants at all is unaffected.
        let plain = serde_json::json!({ "input": { "text": "Work." } });
        assert!(refuse_mcp_grants_on_this_placement(&plain).is_ok());
    }

    #[test]
    fn agent_prompt_reads_the_governed_host_turn_shape() {
        let input = serde_json::json!({
            "protocol": "whipplescript.host.v1",
            "command_id": "command-1",
            "input": {
                "text": "the exact GaugeDesk user turn",
                "images": [],
            },
        });
        assert_eq!(
            agent_prompt(&input).expect("host text"),
            "the exact GaugeDesk user turn"
        );
    }

    #[test]
    fn agent_prompt_keeps_authored_effects_and_refuses_missing_text() {
        assert_eq!(
            agent_prompt(&serde_json::json!({"prompt": "authored turn"})).expect("authored prompt"),
            "authored turn"
        );
        assert!(agent_prompt(&serde_json::json!({"input": {}})).is_err());
        assert!(agent_prompt(&serde_json::json!({"prompt": "  "})).is_err());
    }

    #[test]
    fn governed_host_images_resolve_only_from_the_admitted_broker_cache() {
        let store = store();
        store
            .sql
            .execute(
                "CREATE TABLE host_turn_images (instance_id TEXT, command_id TEXT, \
                 selector TEXT, media_type TEXT, data_base64 TEXT)",
                &[],
            )
            .expect("image table");
        store
            .sql
            .execute(
                "INSERT INTO host_turn_images VALUES (?1, ?2, ?3, ?4, ?5)",
                &[
                    crate::do_store::SqlValue::Text("instance-1".into()),
                    crate::do_store::SqlValue::Text("turn-1".into()),
                    crate::do_store::SqlValue::Text("0".into()),
                    crate::do_store::SqlValue::Text("image/png".into()),
                    crate::do_store::SqlValue::Text("aGVsbG8=".into()),
                ],
            )
            .expect("image body");
        let command = serde_json::json!({
            "input": { "images": [{
                "handle": "turn_images", "kind": "image", "selector": "0"
            }] }
        });
        assert_eq!(
            resolve_host_images(&store.sql, "instance-1", "turn-1", &command)
                .expect("resolved image"),
            vec![ImageBlock {
                media_type: "image/png".into(),
                data_base64: "aGVsbG8=".into(),
            }]
        );
        let wrong = serde_json::json!({
            "input": { "images": [{
                "handle": "other", "kind": "image", "selector": "0"
            }] }
        });
        assert!(resolve_host_images(&store.sql, "instance-1", "turn-1", &wrong).is_err());
    }

    // The DO drives an effect-free workflow's rule pass to its terminal through the
    // InstanceStepMachine, over `RuntimeKernel<DoSqliteStore>` — proving the whole
    // instance scheduler runs on the durable-object store.
    #[test]
    fn do_instance_driver_drives_rule_pass_to_terminal() {
        // The smallest complete workflow (examples/minimal-noop.whip): observe
        // start, record a fact, finish. Effect-free, so it drives to a terminal
        // purely through the rule pass. Compile it, then create + start an instance
        // directly in the DO SQLite via the kernel.
        let source = "workflow MinimalNoop\n\noutput result StartupSeen\n\n\
             class StartupSeen {\n  source string\n  state \"observed\"\n}\n\n\
             rule observe_start\n  when started\n=> {\n\
             \x20 record StartupSeen {\n    source \"external.started\"\n    state \"observed\"\n  }\n\n\
             \x20 complete result {\n    source \"external.started\"\n    state \"observed\"\n  }\n}\n";
        let compiled = whipplescript_parser::compile_program(source);
        let ir = compiled.ir.expect("program compiles");

        let mut kernel = RuntimeKernel::new(store());
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "src",
                    ir_hash: "ir",
                    compiler_version: "test",
                },
                &ir,
            )
            .expect("program version");
        let instance_id = kernel
            .create_instance_with_authority(
                &version,
                "{}",
                NewInstanceAuthority {
                    workflow_principal: "local/MinimalNoop",
                    effective_authority_json: "{}",
                },
            )
            .expect("instance");
        // Seed the `when started` trigger (the `external.started` event; the
        // rule fires on it directly, no input fact needed).
        kernel
            .ingest_external_event(&instance_id, "external.started", "{}", Some("started"))
            .expect("start event");

        let driver = DoInstanceDriver {
            kernel,
            files: &NoFiles,
            coerce: None,
            agent_model: None,
            agent_tools: &NoTools,
            agent_tool_specs: None,
            exec: None,
            turn: None,
            ir: &ir,
            instance_id: &instance_id,
        };
        let mut machine = InstanceStepMachine::new(driver);
        let outcome = run_to_completion(&mut machine, &RefuseIoHost);
        assert!(
            matches!(outcome, InstanceOutcome::Terminal),
            "the DO drives the instance to a terminal: {outcome:?}"
        );

        let driver = machine.into_driver();
        let status = driver
            .kernel
            .store()
            .status(&instance_id)
            .expect("status")
            .expect("instance row");
        assert_eq!(status.instance.status, "completed");
    }

    /// A host that answers the coerce `fetch` with a canned Anthropic structured
    /// output (mirrors `coerce_native`'s parse fixtures).
    struct CoerceHost;
    impl HostDriver for CoerceHost {
        fn fulfill(&self, request: &IoRequest) -> IoResult {
            let IoRequest::Http(_) = request;
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: serde_json::json!({
                    "content": [
                        { "type": "tool_use", "name": "Decision", "input": { "score": 0.9 } }
                    ],
                    "usage": { "input_tokens": 1, "output_tokens": 1 }
                }),
            }))
        }
    }

    // Class-A exec over the sidecar (compute plane P8): the first exec builds a
    // `whip-executor/1` request and suspends on HTTP; settling records the
    // delta-kernel cache entry; an identical second exec settles from the cache
    // with NO HTTP round at all.
    #[test]
    fn do_instance_driver_execs_over_the_sidecar_and_serves_the_second_from_cache() {
        use whipplescript_kernel::exec_http;
        use whipplescript_store::{NewEffect, RuleCommit, ScriptCapabilityRegistration};

        let source = "workflow ExecJudge\n\noutput result Verdict\n\n\
             class Verdict {\n  ok int\n}\n";
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("exec program compiles");
        let store = store();
        for stmt in [
            "INSERT INTO capability_schemas (capability, description, schema_json) \
             VALUES ('script.judge', 'Run an operator-pinned script capability.', '{}')",
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES ('binding_script_judge', NULL, 'script.judge', 'builtin-script', '{}')",
        ] {
            store.sql.execute(stmt, &[]).expect("seed script capability");
        }
        let script_body = "read line\necho '{\"verdict\":\"pass\"}'\n";
        let script_sha = exec_http::sha256_hex(script_body.as_bytes());
        store
            .register_script_capability(ScriptCapabilityRegistration {
                name: "judge",
                argv_json: r#"["sh", "{script}"]"#,
                sha256: &script_sha,
                env_json: "{}",
                hermetic: true,
                body: script_body,
            })
            .expect("register script");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "src-exec",
                    ir_hash: "ir-exec",
                    compiler_version: "test",
                },
                &ir,
            )
            .expect("program version");
        let instance_id = kernel
            .create_instance_with_authority(
                &version,
                "{}",
                NewInstanceAuthority {
                    workflow_principal: "local/ExecJudge",
                    effective_authority_json: "{}",
                },
            )
            .expect("instance");
        let effect_input = serde_json::json!({
            "mode": "capability",
            "capability": "judge",
            "stdin": {"n": 1},
        })
        .to_string();
        let effects = [
            NewEffect {
                effect_id: "exec-1",
                kind: "exec.command",
                target: None,
                input_json: &effect_input,
                status: "queued",
                idempotency_key: "rule=go;effect=exec-1",
                required_capabilities_json: r#"["script.judge"]"#,
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            },
            NewEffect {
                effect_id: "exec-2",
                kind: "exec.command",
                target: None,
                input_json: &effect_input,
                status: "queued",
                idempotency_key: "rule=go;effect=exec-2",
                required_capabilities_json: r#"["script.judge"]"#,
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            },
        ];
        kernel
            .store_mut()
            .commit_rule(RuleCommit {
                instance_id: &instance_id,
                rule: "go",
                trigger_event_id: None,
                facts: &[],
                consumed_fact_ids: &[],
                effects: &effects,
                dependencies: &[],
                terminal: None,
                idempotency_key: Some("commit-go"),
                marks: &[],
                context_json: None,
            })
            .expect("commit exec effects");

        let exec_cfg = ExecutorSidecarConfig {
            base_url: "http://executor:8080".to_owned(),
            env_values: std::collections::BTreeMap::new(),
            environment_epoch: "test-epoch".to_owned(),
            timeout_ms: Some(10_000),
            auth_token: None,
        };
        let mut driver = DoInstanceDriver {
            kernel,
            files: &NoFiles,
            coerce: None,
            agent_model: None,
            agent_tools: &NoTools,
            agent_tool_specs: None,
            exec: Some(&exec_cfg),
            turn: None,
            ir: &ir,
            instance_id: &instance_id,
        };
        let claimable = |effect_id: &str| ClaimableEffect {
            effect_id: effect_id.to_owned(),
            kind: "exec.command".to_owned(),
            target: None,
            profile: None,
            input_json: effect_input.clone(),
            required_capabilities_json: r#"["script.judge"]"#.to_owned(),
            declared_profiles_json: "[]".to_owned(),
        };

        // First exec: builds the whip-executor/1 request and suspends on HTTP.
        let step = driver
            .run_effect(&claimable("exec-1"), None)
            .expect("first exec prepares");
        let request = match step {
            EffectStep::NeedsHttp(request) => request,
            other => panic!("expected NeedsHttp, got {other:?}"),
        };
        assert_eq!(request.url, "http://executor:8080/exec");
        assert_eq!(
            request.body["protocol"],
            serde_json::json!(exec_http::EXECUTOR_PROTOCOL)
        );
        assert_eq!(request.body["script_sha256"], serde_json::json!(script_sha));
        assert_eq!(request.body["script_index"], serde_json::json!(1));
        assert_eq!(
            exec_http::base64_decode(request.body["script_b64"].as_str().expect("b64"))
                .expect("decodes"),
            script_body.as_bytes()
        );

        // Resume with the sidecar's canned response: the effect settles.
        let response = HttpResponse {
            status: 200,
            body: serde_json::json!({
                "protocol": exec_http::EXECUTOR_PROTOCOL,
                "effect_id": "exec-1",
                "exit_code": 0,
                "timed_out": false,
                "stdout": "{\"verdict\":\"pass\"}\n",
                "stderr": "",
            }),
        };
        let step = driver
            .run_effect(&claimable("exec-1"), Some(Ok(response)))
            .expect("first exec settles");
        assert!(matches!(step, EffectStep::Done(_)), "{step:?}");

        // Second identical exec: served from the delta-kernel cache — DONE
        // immediately on prepare, no HTTP round.
        let step = driver
            .run_effect(&claimable("exec-2"), None)
            .expect("second exec settles from cache");
        assert!(
            matches!(step, EffectStep::Done(_)),
            "expected a cache-hit settle with no HTTP, got {step:?}"
        );

        let runs = driver.kernel.store().list_runs(&instance_id).expect("runs");
        let meta_for = |effect_id: &str| {
            serde_json::from_str::<serde_json::Value>(
                &runs
                    .iter()
                    .find(|run| run.effect_id == effect_id)
                    .unwrap_or_else(|| panic!("run for {effect_id}"))
                    .metadata_json,
            )
            .expect("metadata json")
        };
        let first = meta_for("exec-1");
        let second = meta_for("exec-2");
        assert_eq!(first["cache"]["hit"], serde_json::json!(false), "{first}");
        assert_eq!(second["cache"]["hit"], serde_json::json!(true), "{second}");
        assert_eq!(
            first["cache"]["content_key"],
            second["cache"]["content_key"]
        );
        assert_eq!(first["stdout"], second["stdout"]);
        assert_eq!(first["sha256"], serde_json::json!(script_sha));

        let content_key = first["cache"]["content_key"]
            .as_str()
            .expect("content key")
            .to_owned();
        let entry = driver
            .kernel
            .store()
            .lookup_compute_result(&content_key)
            .expect("cache lookup")
            .expect("cache entry");
        assert_eq!(entry.source_effect_id, "exec-1");
    }

    // The architectural crux (DR-0033): a coerce HTTP effect SUSPENDS the instance
    // on `fetch` (EffectStep::NeedsHttp -> Outcome::NeedsIo) and RESUMES to its
    // terminal when the host supplies the response — all on the durable-object store.
    #[test]
    fn do_instance_driver_suspends_and_settles_a_coerce_effect() {
        let source = "workflow CoerceScore\n\noutput result Decision\n\n\
             class Decision {\n  score float\n}\n\n\
             coerce scoreIt() -> Decision {\n  prompt \"\"\"\n  Score it.\n  {{ ctx.output_format }}\n  \"\"\"\n}\n\n\
             rule go\n  when started\n=> {\n  coerce scoreIt() as review\n\
             \x20 after review succeeds as decision {\n    complete result { score decision.score }\n  }\n\
             \x20 after review fails {\n    complete result { score 0.0 }\n  }\n}\n";
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("coerce program compiles");
        // Register the builtin coerce provider + capability (migration-0001 seeds a
        // live store carries; the minimal test store does not).
        let store = store();
        for stmt in [
            "INSERT INTO capability_schemas (capability, description, schema_json) \
             VALUES ('schema.coerce', 'Coerce unstructured data into a typed value.', '{}')",
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES ('provider_coerce_builtin', 'schema.coerce', 'builtin-coerce', 'schema.coerce', '{}')",
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES ('binding_coerce_builtin', NULL, 'schema.coerce', 'builtin-coerce', '{}')",
        ] {
            store.sql.execute(stmt, &[]).expect("seed coerce provider");
        }
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "src",
                    ir_hash: "ir",
                    compiler_version: "test",
                },
                &ir,
            )
            .expect("program version");
        let instance_id = kernel
            .create_instance_with_authority(
                &version,
                "{}",
                NewInstanceAuthority {
                    workflow_principal: "local/CoerceScore",
                    effective_authority_json: "{}",
                },
            )
            .expect("instance");
        kernel
            .ingest_external_event(&instance_id, "external.started", "{}", Some("started"))
            .expect("start event");

        let cfg = ResolvedCoercionConfig {
            provider_id: "anthropic".to_owned(),
            backend: CoerceProvider::Anthropic,
            base_url: "https://api.anthropic.com".to_owned(),
            api_key: "test-key".to_owned(),
            model: "claude-test".to_owned(),
            max_tokens: whipplescript_kernel::coerce_native::DEFAULT_COERCE_MAX_TOKENS,
            timeout_secs: whipplescript_kernel::coerce_native::DEFAULT_COERCE_TIMEOUT_SECS,
            codex_account_id: None,
        };
        let driver = DoInstanceDriver {
            kernel,
            files: &NoFiles,
            coerce: Some(&cfg),
            agent_model: None,
            agent_tools: &NoTools,
            agent_tool_specs: None,
            exec: None,
            turn: None,
            ir: &ir,
            instance_id: &instance_id,
        };
        let mut machine = InstanceStepMachine::new(driver);
        let outcome = run_to_completion(&mut machine, &CoerceHost);
        let driver = machine.into_driver();
        assert!(
            matches!(outcome, InstanceOutcome::Terminal),
            "the DO suspends on fetch and settles the coerce to a terminal: {outcome:?}"
        );

        let status = driver
            .kernel
            .store()
            .status(&instance_id)
            .expect("status")
            .expect("instance row");
        assert_eq!(status.instance.status, "completed");
    }

    /// A fake HTTP agent model: one round, a final reply with no tool calls.
    struct FinalReplyModel;
    impl HttpModelClient for FinalReplyModel {
        fn build_request(
            &self,
            _messages: &[ChatMessage],
            _tools: &[whipplescript_kernel::harness_loop::ToolSpec],
        ) -> whipplescript_kernel::sansio::HttpRequest {
            whipplescript_kernel::sansio::HttpRequest {
                url: "https://provider/agent".to_owned(),
                headers: Vec::new(),
                body: serde_json::json!({}),
            }
        }
        fn parse_response(
            &self,
            _response: Result<HttpResponse, TransportError>,
        ) -> Result<
            whipplescript_kernel::harness_loop::ModelReply,
            whipplescript_kernel::harness_loop::HarnessModelError,
        > {
            Ok(whipplescript_kernel::harness_loop::ModelReply {
                text: "done".to_owned(),
                tool_calls: Vec::new(),
                usage: serde_json::json!({ "input_tokens": 1, "output_tokens": 1 }),
            })
        }
    }

    // The DO agent turn end-to-end: a `when started -> tell agent -> complete`
    // workflow drives the BrokeredTurnMachine over `fetch` (suspend on NeedsHttp,
    // resume via the snapshot table) and settles the ProviderRunResult, reaching a
    // terminal over the DO store.
    #[test]
    fn do_instance_driver_runs_an_agent_turn_over_fetch() {
        let source = "workflow AgentDemo\n\noutput result Done\n\n\
             class Done {\n  ok int\n}\n\n\
             agent helper {\n  provider owned\n  profile \"repo-reader\"\n  capacity 1\n}\n\n\
             rule go\n  when started\n=> {\n  tell helper as reply \"\"\"\n  Do the thing.\n  \"\"\"\n\n\
             \x20 after reply succeeds {\n    complete result { ok 1 }\n  }\n\n\
             \x20 after reply fails {\n    complete result { ok 0 }\n  }\n}\n";
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("agent program compiles");
        let store = store();
        for stmt in [
            "INSERT INTO capability_schemas (capability, description, schema_json) \
             VALUES ('agent.tell', 'Run an agent turn.', '{}')",
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
            "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) \
             VALUES ('profile_repo_reader', 'repo-reader', 'reads', 'enforce', '[\"agent.tell\"]', '{}')",
        ] {
            store.sql.execute(stmt, &[]).expect("seed agent provider");
        }
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "src",
                    ir_hash: "ir",
                    compiler_version: "test",
                },
                &ir,
            )
            .expect("program version");
        let instance_id = kernel
            .create_instance_with_authority(
                &version,
                "{}",
                NewInstanceAuthority {
                    workflow_principal: "local/AgentDemo",
                    effective_authority_json: "{}",
                },
            )
            .expect("instance");
        kernel
            .ingest_external_event(&instance_id, "external.started", "{}", Some("started"))
            .expect("start event");

        let model = FinalReplyModel;
        let driver = DoInstanceDriver {
            kernel,
            files: &NoFiles,
            coerce: None,
            agent_model: Some(&model),
            agent_tools: &NoTools,
            agent_tool_specs: None,
            exec: None,
            turn: None,
            ir: &ir,
            instance_id: &instance_id,
        };
        let mut machine = InstanceStepMachine::new(driver);
        let outcome = run_to_completion(&mut machine, &OkHost);
        assert!(
            matches!(outcome, InstanceOutcome::Terminal),
            "the DO drives the agent turn over fetch to a terminal: {outcome:?}"
        );
        let driver = machine.into_driver();
        let status = driver
            .kernel
            .store()
            .status(&instance_id)
            .expect("status")
            .expect("instance row");
        assert_eq!(status.instance.status, "completed");
    }

    /// Store-backed project instructions (context-assembly Phase 3 item 4):
    /// docs registered in the DO store ride into the agent turn's system prompt
    /// with pi's exact wrapper, and each doc records a `context.bundle`
    /// provenance row through the Phase 1 seam.
    #[test]
    fn do_agent_turn_injects_store_backed_project_context() {
        use std::cell::RefCell;

        /// A fake model that captures the system prompt it was asked to send.
        struct CapturingModel {
            systems: RefCell<Vec<String>>,
        }
        impl HttpModelClient for CapturingModel {
            fn build_request(
                &self,
                messages: &[ChatMessage],
                _tools: &[whipplescript_kernel::harness_loop::ToolSpec],
            ) -> whipplescript_kernel::sansio::HttpRequest {
                for message in messages {
                    if let ChatMessage::System(system) = message {
                        self.systems.borrow_mut().push(system.clone());
                    }
                }
                whipplescript_kernel::sansio::HttpRequest {
                    url: "https://provider/agent".to_owned(),
                    headers: Vec::new(),
                    body: serde_json::json!({}),
                }
            }
            fn parse_response(
                &self,
                _response: Result<HttpResponse, TransportError>,
            ) -> Result<
                whipplescript_kernel::harness_loop::ModelReply,
                whipplescript_kernel::harness_loop::HarnessModelError,
            > {
                Ok(whipplescript_kernel::harness_loop::ModelReply {
                    text: "done".to_owned(),
                    tool_calls: Vec::new(),
                    usage: Default::default(),
                })
            }
        }

        let source = "workflow AgentDemo\n\noutput result Done\n\n\
             class Done {\n  ok int\n}\n\n\
             agent helper {\n  provider owned\n  profile \"repo-reader\"\n  capacity 1\n}\n\n\
             rule go\n  when started\n=> {\n  tell helper as reply \"\"\"\n  Do the thing.\n  \"\"\"\n\n\
             \x20 after reply succeeds {\n    complete result { ok 1 }\n  }\n\n\
             \x20 after reply fails {\n    complete result { ok 0 }\n  }\n}\n";
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("agent program compiles");
        let store = store();
        for stmt in [
            "INSERT INTO capability_schemas (capability, description, schema_json) \
             VALUES ('agent.tell', 'Run an agent turn.', '{}')",
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
            "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) \
             VALUES ('profile_repo_reader', 'repo-reader', 'reads', 'enforce', '[\"agent.tell\"]', '{}')",
        ] {
            store.sql.execute(stmt, &[]).expect("seed agent provider");
        }
        store
            .register_project_context_doc(0, "repo/AGENTS.md", "Always be excellent.")
            .expect("doc registers");
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "src",
                    ir_hash: "ir",
                    compiler_version: "test",
                },
                &ir,
            )
            .expect("program version");
        let instance_id = kernel
            .create_instance_with_authority(
                &version,
                "{}",
                NewInstanceAuthority {
                    workflow_principal: "local/AgentDemo",
                    effective_authority_json: "{}",
                },
            )
            .expect("instance");
        kernel
            .ingest_external_event(&instance_id, "external.started", "{}", Some("started"))
            .expect("start event");

        let model = CapturingModel {
            systems: RefCell::new(Vec::new()),
        };
        let driver = DoInstanceDriver {
            kernel,
            files: &NoFiles,
            coerce: None,
            agent_model: Some(&model),
            agent_tools: &NoTools,
            agent_tool_specs: None,
            exec: None,
            turn: None,
            ir: &ir,
            instance_id: &instance_id,
        };
        let mut machine = InstanceStepMachine::new(driver);
        let outcome = run_to_completion(&mut machine, &OkHost);
        assert!(
            matches!(outcome, InstanceOutcome::Terminal),
            "turn completes: {outcome:?}"
        );

        // The system prompt carried the store-resolved project context in pi's
        // exact wrapper.
        let systems = model.systems.borrow();
        let system = systems.first().expect("a model round ran");
        assert!(
            system.contains("<project_instructions path=\"repo/AGENTS.md\">"),
            "{system}"
        );
        assert!(system.contains("Always be excellent."), "{system}");

        // One context.bundle provenance row rode the Phase 1 seam.
        let driver = machine.into_driver();
        let evidence = driver
            .kernel
            .store()
            .list_evidence(&instance_id)
            .expect("evidence");
        let bundles: Vec<_> = evidence
            .iter()
            .filter(|row| row.kind == "context.bundle")
            .collect();
        assert_eq!(bundles.len(), 1, "one project-context bundle row");
        assert!(
            bundles[0].metadata_json.contains("project_context")
                && bundles[0].metadata_json.contains("repo/AGENTS.md"),
            "{}",
            bundles[0].metadata_json
        );
    }

    /// A host that answers any request with a 200 (the fake model ignores the body).
    struct OkHost;
    impl HostDriver for OkHost {
        fn fulfill(&self, _request: &IoRequest) -> IoResult {
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: serde_json::json!({}),
            }))
        }
    }

    /// A canned Class-B turn container: asserts the whip-turn/1 start
    /// request shape and answers the blocking form's final outcome.
    struct TurnContainerHost;
    impl HostDriver for TurnContainerHost {
        fn fulfill(&self, request: &IoRequest) -> IoResult {
            let IoRequest::Http(request) = request;
            assert!(request.url.ends_with("/turn"), "{}", request.url);
            assert_eq!(request.body["protocol"], serde_json::json!("whip-turn/1"));
            assert_eq!(request.body["tools"], serde_json::json!("file"));
            assert_eq!(
                request.body["provider"]["provider"],
                serde_json::json!("fixture")
            );
            let turn_id = request.body["turn_id"]
                .as_str()
                .expect("turn_id")
                .to_owned();
            IoResult::Http(Ok(HttpResponse {
                status: 200,
                body: serde_json::json!({
                    "protocol": "whip-turn/1",
                    "turn_id": turn_id,
                    "resumed": false,
                    "outcome": {
                        "status": "completed",
                        "summary": "container turn complete",
                        "steps": 2,
                        "usage": {"input_tokens": 5, "output_tokens": 7},
                    },
                }),
            }))
        }
    }

    // Class-B (compute plane P8): with a turn container configured, the agent
    // turn dispatches WHOLE to the per-turn container over whip-turn/1 and the
    // delivered outcome settles through settle_provider_run_result.
    #[test]
    fn do_instance_driver_runs_an_agent_turn_in_a_turn_container() {
        let source = "workflow AgentDemo\n\noutput result Done\n\n\
             class Done {\n  ok int\n}\n\n\
             agent helper {\n  provider owned\n  profile \"repo-reader\"\n  capacity 1\n}\n\n\
             rule go\n  when started\n=> {\n  tell helper as reply \"\"\"\n  Do the thing.\n  \"\"\"\n\n\
             \x20 after reply succeeds {\n    complete result { ok 1 }\n  }\n\n\
             \x20 after reply fails {\n    complete result { ok 0 }\n  }\n}\n";
        let ir = whipplescript_parser::compile_program(source)
            .ir
            .expect("agent program compiles");
        let store = store();
        for stmt in [
            "INSERT INTO capability_schemas (capability, description, schema_json) \
             VALUES ('agent.tell', 'Run an agent turn.', '{}')",
            "INSERT INTO effect_providers (provider_id, effect_kind, provider, capability, config_json) \
             VALUES ('provider_agent_tell_builtin', 'agent.tell', 'builtin-agent-harness', 'agent.tell', '{}')",
            "INSERT INTO capability_bindings (binding_id, program_id, capability, provider, config_json) \
             VALUES ('binding_agent_tell_builtin', NULL, 'agent.tell', 'builtin-agent-harness', '{}')",
            "INSERT INTO profiles (profile_id, name, description, enforcement_mode, allowed_capabilities, config_json) \
             VALUES ('profile_repo_reader', 'repo-reader', 'reads', 'enforce', '[\"agent.tell\"]', '{}')",
        ] {
            store.sql.execute(stmt, &[]).expect("seed agent provider");
        }
        let mut kernel = RuntimeKernel::new(store);
        let version = kernel
            .create_program_version_for_program(
                ProgramVersionInput {
                    program_name: &ir.workflow,
                    source_hash: "src-turn",
                    ir_hash: "ir-turn",
                    compiler_version: "test",
                },
                &ir,
            )
            .expect("program version");
        let instance_id = kernel
            .create_instance_with_authority(
                &version,
                "{}",
                NewInstanceAuthority {
                    workflow_principal: "local/AgentDemo",
                    effective_authority_json: "{}",
                },
            )
            .expect("instance");
        kernel
            .ingest_external_event(&instance_id, "external.started", "{}", Some("started"))
            .expect("start event");

        let turn_cfg = TurnContainerConfig {
            base_url: "http://turn".to_owned(),
            provider: serde_json::json!({"provider": "fixture"}),
            max_steps: 8,
            auth_token: None,
        };
        let driver = DoInstanceDriver {
            kernel,
            files: &NoFiles,
            coerce: None,
            // No in-DO model configured: the container owns the turn.
            agent_model: None,
            agent_tools: &NoTools,
            agent_tool_specs: None,
            exec: None,
            turn: Some(&turn_cfg),
            ir: &ir,
            instance_id: &instance_id,
        };
        let mut machine = InstanceStepMachine::new(driver);
        let outcome = run_to_completion(&mut machine, &TurnContainerHost);
        assert!(
            matches!(outcome, InstanceOutcome::Terminal),
            "the container turn settles to a terminal: {outcome:?}"
        );
        let driver = machine.into_driver();
        let status = driver
            .kernel
            .store()
            .status(&instance_id)
            .expect("status")
            .expect("instance row");
        assert_eq!(status.instance.status, "completed");

        // The settle carries the container's outcome (summary + usage) on the
        // run, and the worker id marks the Class-B path.
        let runs = driver.kernel.store().list_runs(&instance_id).expect("runs");
        let run = runs
            .iter()
            .find(|run| run.worker_id == "whip-turn-container")
            .expect("class-B run row");
        assert_eq!(run.status, "completed");
    }
}
