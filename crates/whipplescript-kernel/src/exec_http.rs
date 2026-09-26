//! Exec-over-HTTP pure halves (compute plane P8): everything about a
//! `whip-executor/1` exec round that is not the process spawn itself, shared
//! by every host. The native CLI uses the content-key builder (its exec runs
//! in-process); the DO host uses all of it — build the sidecar request, raise
//! `NeedsHttp`, parse the response, and settle. Wasm-clean: serde_json +
//! sha2 only.
//!
//! The content key MUST be byte-identical across hosts — the delta-kernel
//! result cache is workspace-wide, and a native-recorded result should serve
//! a DO request for the same content key once the stores converge.

use std::fmt::Write;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use whipplescript_store::{EffectCompletion, RuntimeStore, StoreResult, StoredEvent};

use crate::effect_handlers::{effect_failure_base, validate_ingest_value};
use crate::sansio::{HttpRequest, HttpResponse};
use crate::RuntimeKernel;

/// Wire protocol marker for the executor sidecar.
pub const EXECUTOR_PROTOCOL: &str = "whip-executor/1";

/// The argv element that stands for "the staged script path" in store-backed
/// script capabilities (hosts with no filesystem cannot probe argv for a
/// readable file the way the native manifest loader does).
pub const SCRIPT_ARGV_PLACEHOLDER: &str = "{script}";

/// sha256 as lowercase hex — the script-pin digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Delta-kernel content key for a hermetic exec (compute plane P8-1):
/// sha256 over script hash + argv + resolved env + host environment epoch +
/// effect input (stdin + parse contract). `resolved_env` must be sorted by
/// name (BTreeMap iteration order natively; sort before calling otherwise).
pub fn exec_content_key(
    script_sha256: &str,
    argv: &[String],
    resolved_env: &[(String, String)],
    environment_epoch: &str,
    stdin_json: &str,
    parse_contract: &Option<Value>,
) -> String {
    let mut material = String::new();
    material.push_str("exec.command\x00");
    material.push_str(script_sha256);
    material.push('\x00');
    for arg in argv {
        material.push_str(arg);
        material.push('\x1f');
    }
    material.push('\x00');
    for (name, value) in resolved_env {
        material.push_str(name);
        material.push('=');
        material.push_str(value);
        material.push('\x1f');
    }
    material.push('\x00');
    material.push_str(environment_epoch);
    material.push('\x00');
    material.push_str(stdin_json);
    material.push('\x00');
    if let Some(contract) = parse_contract {
        material.push_str(&contract.to_string());
    }
    sha256_hex(material.as_bytes())
}

/// Build the `POST /exec` request for one script run. `argv` must contain
/// the [`SCRIPT_ARGV_PLACEHOLDER`] element naming where the staged script
/// path goes; the executor substitutes it after verifying the pin.
#[allow(clippy::too_many_arguments)]
pub fn build_executor_exec_request(
    executor_base_url: &str,
    effect_id: &str,
    script_sha256: &str,
    script_body: &str,
    argv: &[String],
    resolved_env: &[(String, String)],
    stdin: &Value,
    timeout_ms: Option<u64>,
) -> Result<HttpRequest, String> {
    let script_index = argv
        .iter()
        .position(|arg| arg == SCRIPT_ARGV_PLACEHOLDER)
        .ok_or_else(|| {
            format!("script argv must contain the `{SCRIPT_ARGV_PLACEHOLDER}` placeholder")
        })?;
    let env: serde_json::Map<String, Value> = resolved_env
        .iter()
        .map(|(name, value)| (name.clone(), Value::String(value.clone())))
        .collect();
    let mut body = json!({
        "protocol": EXECUTOR_PROTOCOL,
        "effect_id": effect_id,
        "script_sha256": script_sha256,
        "script_b64": base64_encode(script_body.as_bytes()),
        "script_ext": "sh",
        "argv": argv,
        "script_index": script_index,
        "env": Value::Object(env),
        "stdin": stdin,
    });
    if let Some(timeout_ms) = timeout_ms {
        body["timeout_ms"] = json!(timeout_ms);
    }
    Ok(HttpRequest {
        model_provenance: None,
        url: format!("{}/exec", executor_base_url.trim_end_matches('/')),
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body,
    })
}

/// A decoded executor exec response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutorExecResult {
    pub exit_code: i64,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Decode + validate the sidecar's `POST /exec` response.
pub fn parse_executor_exec_response(response: &HttpResponse) -> Result<ExecutorExecResult, String> {
    if response.status != 200 {
        let detail = response
            .body
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("no detail");
        return Err(format!(
            "executor returned status {}: {detail}",
            response.status
        ));
    }
    let protocol = response
        .body
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if protocol != EXECUTOR_PROTOCOL {
        return Err(format!(
            "executor answered protocol `{protocol}`; expected `{EXECUTOR_PROTOCOL}`"
        ));
    }
    let exit_code = response
        .body
        .get("exit_code")
        .and_then(Value::as_i64)
        .ok_or("executor response is missing exit_code")?;
    Ok(ExecutorExecResult {
        exit_code,
        timed_out: response
            .body
            .get("timed_out")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stdout: response
            .body
            .get("stdout")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        stderr: response
            .body
            .get("stderr")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
    })
}

/// A typed-ingest outcome for `exec ... -> Schema` / `-> each Schema`.
#[derive(Clone, Debug)]
pub enum ExecIngest {
    Single(Value),
    Stream(Vec<Value>),
}

/// Parses and validates exec stdout against the effect's embedded parse
/// contract (`{schema, shape, each}`). Pure JSON work — shared by the native
/// in-process exec and the DO's exec-over-HTTP settle.
pub fn ingest_exec_stdout(contract: &Value, stdout: &str) -> Result<ExecIngest, String> {
    let schema = contract
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or("json");
    let shape = contract.get("shape").cloned().unwrap_or(Value::Null);
    let each = contract
        .get("each")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = stdout.trim();
    if !each {
        let value: Value = serde_json::from_str(text)
            .map_err(|error| format!("stdout is not valid JSON for `{schema}`: {error}"))?;
        if !value.is_object() {
            return Err(format!(
                "stdout must be a single JSON object conforming to `{schema}`"
            ));
        }
        let mut errors = Vec::new();
        validate_ingest_value(&value, &shape, "$", &mut errors);
        if !errors.is_empty() {
            return Err(format!(
                "stdout does not conform to `{schema}`: {}",
                errors.join("; ")
            ));
        }
        return Ok(ExecIngest::Single(value));
    }
    let mut elements = Vec::new();
    let mut errors = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(element) => {
                validate_ingest_value(&element, &shape, &format!("[{index}]"), &mut errors);
                elements.push(element);
            }
            Err(error) => {
                errors.push(format!("line {index} is not valid JSON: {error}"));
            }
        }
    }
    if !errors.is_empty() {
        return Err(format!(
            "stream does not conform to `{schema}`: {}",
            errors.join("; ")
        ));
    }
    Ok(ExecIngest::Stream(elements))
}

/// Host-selected dispatch inputs persisted before yielding HTTP. Digests retain
/// identity without copying authorization headers or resolved environment values.
/// Deserialization is not authority: load only from the host-owned run journal.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecDispatchPlan {
    pub protocol: String,
    pub capability: String,
    pub script_sha256: String,
    pub input_sha256: String,
    pub request_sha256: String,
    pub request_body_sha256: String,
    pub environment_epoch: String,
    pub content_key: Option<String>,
    pub parse_contract: Option<Value>,
}
impl ExecDispatchPlan {
    pub fn prepare(
        capability: &str,
        script_sha256: &str,
        input: &Value,
        request: &HttpRequest,
        environment_epoch: &str,
        content_key: Option<String>,
        parse_contract: Option<Value>,
    ) -> Self {
        Self {
            protocol: "whipplescript.exec.dispatch/v1".into(),
            capability: capability.into(),
            script_sha256: script_sha256.into(),
            input_sha256: sha256_hex(input.to_string().as_bytes()),
            request_sha256: sha256_hex(json!([request.url, request.body]).to_string().as_bytes()),
            request_body_sha256: sha256_hex(request.body.to_string().as_bytes()),
            environment_epoch: environment_epoch.into(),
            content_key,
            parse_contract,
        }
    }

    pub fn load<S: RuntimeStore>(
        store: &S,
        instance_id: &str,
        effect_id: &str,
        run_id: &str,
        input: &Value,
    ) -> StoreResult<Self> {
        let runs = store.list_runs(instance_id)?;
        let run = runs
            .iter()
            .find(|run| run.run_id == run_id)
            .ok_or_else(|| {
                whipplescript_store::StoreError::Conflict("executor dispatch run is missing".into())
            })?;
        if run.effect_id != effect_id || run.provider != "exec" || run.status != "running" {
            return Err(whipplescript_store::StoreError::Conflict(
                "executor dispatch run differs from its invocation".into(),
            ));
        }
        let metadata: Value = serde_json::from_str(&run.metadata_json)?;
        let plan: Self = serde_json::from_value(
            metadata.get("executor_dispatch").cloned().ok_or_else(|| {
                whipplescript_store::StoreError::Conflict(
                    "executor dispatch plan is missing; recover the original run".into(),
                )
            })?,
        )?;
        if plan.protocol != "whipplescript.exec.dispatch/v1"
            || plan.input_sha256 != sha256_hex(input.to_string().as_bytes())
        {
            return Err(whipplescript_store::StoreError::Conflict(
                "executor dispatch plan differs from its original input or protocol".into(),
            ));
        }
        Ok(plan)
    }
}

/// A receipt for a different effect cannot populate this invocation's cache.
/// Ordinary parsing failures still settle as failures with the original receipt.
pub fn parse_executor_response_for_effect(
    response: &HttpResponse,
    effect_id: &str,
) -> Result<ExecutorExecResult, String> {
    if response.status == 200
        && response.body.get("effect_id").and_then(Value::as_str) != Some(effect_id)
    {
        return Err("executor response differs from its dispatched effect".into());
    }
    parse_executor_exec_response(response)
}

/// Identity of one exec-over-HTTP settle: which effect/run this outcome
/// belongs to, plus the cache posture (`(content_key, served_from_cache)`
/// when the capability is hermetic).
pub struct ExecSettleContext<'a> {
    pub input_json: &'a str,
    pub instance_id: &'a str,
    pub effect_id: &'a str,
    pub run_id: &'a str,
    pub capability: &'a str,
    pub script_sha256: &'a str,
    pub cache: Option<(&'a str, bool)>,
    /// The parse contract's schema name — the fact name streamed elements
    /// ingest under (`-> each Schema`); `"json"` when untyped.
    pub ingest_schema: &'a str,
    /// Executor-protocol response from this invocation, retained verbatim.
    /// Cache hits and direct process execution without that protocol supply None.
    pub executor_response: Option<&'a HttpResponse>,
    /// Physical delivery: `http` or the native bounded handler's `in-process`.
    /// This records provenance; it is not independent authentication evidence.
    pub executor_transport: &'a str,
    pub dispatch_plan: Option<&'a ExecDispatchPlan>,
    /// Original broker outcome journal identity, when settling retained evidence.
    pub resolution_event_id: Option<&'a str>,
}

/// The shaped outcome of an exec round, mirroring the native `ExecOutcome`:
/// `Ok((exit_code, stdout, stderr, ingested))` on success, `Err((detail,
/// reason))` where detail carries the streams when the process ran.
pub type ExecSettleOutcome =
    Result<(i64, String, String, Option<ExecIngest>), (Option<(i64, String, String)>, String)>;

pub fn decode_exec_http_outcome(
    plan: &ExecDispatchPlan,
    response: &HttpResponse,
    effect: &str,
) -> ExecSettleOutcome {
    let result =
        parse_executor_response_for_effect(response, effect).map_err(|reason| (None, reason))?;
    let detail = Some((
        result.exit_code,
        result.stdout.clone(),
        result.stderr.clone(),
    ));
    if result.timed_out {
        return Err((
            detail,
            "exec command timed out on the executor sidecar".into(),
        ));
    }
    if result.exit_code != 0 {
        return Err((
            detail,
            format!("exec command exited with status {}", result.exit_code),
        ));
    }
    let ingested = plan
        .parse_contract
        .as_ref()
        .map(|contract| ingest_exec_stdout(contract, &result.stdout))
        .transpose()
        .map_err(|reason| (detail, reason))?;
    Ok((result.exit_code, result.stdout, result.stderr, ingested))
}

/// Settle one exec-over-HTTP outcome through the effect ledger — the store
/// half of the native `run_exec_effect`, generic over the runtime store so
/// the DO host settles with the same terminal, metadata, and fact shapes the
/// native host writes. Also populates the delta-kernel result cache on a
/// fresh hermetic success (first-writer-wins).
pub fn settle_exec_http_result<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    ctx: &ExecSettleContext<'_>,
    outcome: ExecSettleOutcome,
) -> StoreResult<StoredEvent> {
    let mut projections = Vec::new();
    match outcome {
        Ok((exit_code, stdout, stderr, ingested)) => {
            let mut value = json!({
                "mode": "capability",
                "command": "",
                "capability": ctx.capability,
                "exit_code": exit_code,
                "stdout": stdout,
                "stderr": stderr,
                "sha256": ctx.script_sha256,
            });
            if let Some(event) = ctx.resolution_event_id {
                value["executor_outcome_event_id"] = json!(event);
            }
            if let Some(plan) = ctx.dispatch_plan {
                value["executor_dispatch"] = json!(plan);
            }
            if let Some(response) = ctx.executor_response {
                value["executor_transport"] = json!(ctx.executor_transport);
                value["executor_response"] =
                    json!({"status": response.status, "body": response.body});
            }
            let cache_json = ctx
                .cache
                .filter(|(_, hit)| !hit)
                .map(|_| encode_cached_exec_result(exit_code, &stdout, &stderr, &ingested));
            if let Some((content_key, hit)) = ctx.cache {
                value["cache"] = json!({"content_key": content_key, "hit": hit});
            }
            let mut fact = json!({
                "effect_id": ctx.effect_id,
                "run_id": ctx.run_id,
                "status": "completed",
                "mode": "capability",
                "capability": ctx.capability,
                "exit_code": exit_code,
                "stdout": value.get("stdout").cloned().unwrap_or(Value::Null),
            });
            match ingested {
                Some(ExecIngest::Single(parsed)) => {
                    fact["value"] = parsed;
                }
                Some(ExecIngest::Stream(elements)) => {
                    for (index, element) in elements.iter().enumerate() {
                        projections.push(ExecSettlementProjection {
                            name: ctx.ingest_schema.to_owned(),
                            key: format!("{}:{index}", ctx.effect_id),
                            value: element.to_string(),
                            ingest: true,
                            event_key: crate::execution_run_key(
                                ctx.instance_id,
                                ctx.effect_id,
                                ctx.run_id,
                                &["ingest", &index.to_string()],
                            ),
                        });
                    }
                    fact["ingested_count"] = json!(elements.len());
                }
                None => {}
            }
            projections.push(ExecSettlementProjection {
                name: "exec.command.completed".into(),
                key: ctx.effect_id.into(),
                value: fact.to_string(),
                ingest: false,
                event_key: crate::execution_run_key(
                    ctx.instance_id,
                    ctx.effect_id,
                    ctx.run_id,
                    &["exec-fact"],
                ),
            });
            commit_exec_settlement(
                kernel,
                ctx.input_json,
                EffectCompletion {
                    instance_id: ctx.instance_id,
                    effect_id: ctx.effect_id,
                    run_id: ctx.run_id,
                    provider: "exec",
                    worker_id: "whip-exec",
                    status: "completed",
                    exit_code: Some(exit_code),
                    summary: Some("exec completed"),
                    metadata_json: &value.to_string(),
                    idempotency_key: Some(&crate::execution_run_key(
                        ctx.instance_id,
                        ctx.effect_id,
                        ctx.run_id,
                        &["terminal"],
                    )),
                },
                &projections,
                ctx.cache
                    .zip(cache_json.as_deref())
                    .map(
                        |((content_key, _), result_json)| whipplescript_store::SettlementCache {
                            content_key,
                            result_json,
                        },
                    ),
            )
        }
        Err((detail, reason)) => {
            // Both arms name the same failure: the exec boundary was crossed and
            // the far side did not succeed. The detail arm carries the process's
            // own output as well, which is evidence, not a different kind.
            let failure = json!({"error_kind": "exec_failed", "message": reason});
            let mut metadata = match &detail {
                Some((exit_code, stdout, stderr)) => json!({
                    "failure": failure,
                    "exit_code": exit_code,
                    "stdout": stdout,
                    "stderr": stderr,
                }),
                None => json!({"failure": failure}),
            };
            metadata["mode"] = json!("capability");
            metadata["capability"] = json!(ctx.capability);
            metadata["sha256"] = json!(ctx.script_sha256);
            if let Some(event) = ctx.resolution_event_id {
                metadata["executor_outcome_event_id"] = json!(event);
            }
            if let Some(plan) = ctx.dispatch_plan {
                metadata["executor_dispatch"] = json!(plan);
            }
            if let Some(response) = ctx.executor_response {
                metadata["executor_transport"] = json!(ctx.executor_transport);
                metadata["executor_response"] =
                    json!({"status": response.status, "body": response.body});
            }
            // P3 per-kind extras: the command's exit code (when the process
            // actually ran) rides the bound failure value.
            let mut failure_value =
                effect_failure_base("exec", &reason, &reason, ctx.effect_id, ctx.run_id);
            if let (Some((exit_code, _, _)), Some(object)) =
                (&detail, failure_value.as_object_mut())
            {
                object.insert("exit_code".to_owned(), Value::from(*exit_code));
            }
            let fact = json!({
                "effect_id": ctx.effect_id,
                "run_id": ctx.run_id,
                "status": "failed",
                "mode": "capability",
                "capability": ctx.capability,
                "value": failure_value,
                "error": {"message": reason},
            })
            .to_string();
            projections.push(ExecSettlementProjection {
                name: "exec.command.failed".into(),
                key: ctx.effect_id.into(),
                value: fact,
                ingest: false,
                event_key: crate::execution_run_key(
                    ctx.instance_id,
                    ctx.effect_id,
                    ctx.run_id,
                    &["exec-fact"],
                ),
            });
            commit_exec_settlement(
                kernel,
                ctx.input_json,
                EffectCompletion {
                    instance_id: ctx.instance_id,
                    effect_id: ctx.effect_id,
                    run_id: ctx.run_id,
                    provider: "exec",
                    worker_id: "whip-exec",
                    status: "failed",
                    exit_code: detail.as_ref().map(|(code, _, _)| *code),
                    summary: Some(&reason),
                    metadata_json: &metadata.to_string(),
                    idempotency_key: Some(&crate::execution_run_key(
                        ctx.instance_id,
                        ctx.effect_id,
                        ctx.run_id,
                        &["terminal"],
                    )),
                },
                &projections,
                None,
            )
        }
    }
}

/// Owned fact material assembled before an exec settlement transaction.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSettlementProjection {
    pub name: String,
    pub key: String,
    pub value: String,
    pub ingest: bool,
    pub event_key: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedExecMaterial {
    status: String,
    exit_code: Option<i64>,
    summary: Option<String>,
    metadata: Value,
    projections: Vec<ExecSettlementProjection>,
    cache: Option<(String, String)>,
}

/// Retain the returned material before the atomic projection transaction.
/// If projection fails, the next process can finish without external execution.
pub fn commit_exec_settlement<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    input_json: &str,
    completion: EffectCompletion<'_>,
    projections: &[ExecSettlementProjection],
    cache: Option<whipplescript_store::SettlementCache<'_>>,
) -> StoreResult<StoredEvent> {
    let material = RetainedExecMaterial {
        status: completion.status.into(),
        exit_code: completion.exit_code,
        summary: completion.summary.map(str::to_owned),
        metadata: serde_json::from_str(completion.metadata_json)?,
        projections: projections.to_vec(),
        cache: cache.map(|cache| (cache.content_key.into(), cache.result_json.into())),
    };
    kernel
        .store_mut()
        .retain_exec_settlement(whipplescript_store::exec_settlement::Retention {
            instance_id: completion.instance_id,
            effect_id: completion.effect_id,
            run_id: completion.run_id,
            input_json,
            settlement_json: &serde_json::to_string(&material)?,
        })?;
    commit_exec_projection_batch(kernel, completion, projections, cache)
}

/// Finish retained running outcomes before cancellation, time, or new dispatch.
pub fn recover_pending_exec_settlements<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance: &str,
) -> StoreResult<Vec<StoredEvent>> {
    let mut recovered = Vec::new();
    let effects = kernel.store().list_effects(instance)?;
    for run in kernel.store().list_runs(instance)? {
        // Receipt identity selects recovery; mutable provider metadata is
        // checked by recovery and must not hide a retained outcome.
        if run.status != "running" {
            continue;
        }
        if kernel
            .store()
            .event_by_idempotency_key(
                instance,
                &whipplescript_store::exec_settlement::retention_key(&run.run_id),
            )?
            .is_none()
        {
            continue;
        }
        let effect = effects
            .iter()
            .find(|effect| effect.effect_id == run.effect_id)
            .ok_or_else(|| {
                whipplescript_store::StoreError::Conflict("retained exec effect is missing".into())
            })?;
        let selected = whipplescript_store::ClaimableEffect {
            attempt_admission_event_id: kernel
                .store()
                .effect_attempt_admission(instance, &effect.effect_id)?,
            effect_id: effect.effect_id.clone(),
            kind: effect.kind.clone(),
            target: effect.target.clone(),
            profile: effect.profile.clone(),
            input_json: effect.input_json.clone(),
            required_capabilities_json: effect.required_capabilities_json.clone(),
            declared_profiles_json: effect.declared_profiles_json.clone(),
        };
        let event = recover_exec_settlement(kernel, instance, &selected)?.ok_or_else(|| {
            whipplescript_store::StoreError::Conflict(
                "retained exec differs from the selected attempt".into(),
            )
        })?;
        recovered.push(event);
    }
    Ok(recovered)
}

/// Recover only the selected attempt's retained outcome, before host dispatch.
pub fn recover_exec_settlement<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    instance: &str,
    effect: &whipplescript_store::ClaimableEffect,
) -> StoreResult<Option<StoredEvent>> {
    use whipplescript_store::{exec_settlement, StoreError};
    if kernel
        .store()
        .effect_attempt_admission(instance, &effect.effect_id)?
        != effect.attempt_admission_event_id
    {
        return Err(StoreError::Conflict(
            "exec recovery differs from the admitted attempt".into(),
        ));
    }
    let run_id = crate::execution_attempt_key(
        instance,
        &effect.effect_id,
        effect.attempt_admission_event_id.as_deref(),
        "exec-run",
    );
    let Some(stored) = kernel
        .store()
        .event_by_idempotency_key(instance, &exec_settlement::retention_key(&run_id))?
    else {
        return Ok(None);
    };
    let events = kernel.store().list_events(instance)?;
    let event = events
        .iter()
        .find(|event| event.event_id == stored.event_id)
        .ok_or_else(|| StoreError::Conflict("exec recovery receipt event is missing".into()))?;
    let receipt: Value = serde_json::from_str(&event.payload_json)?;
    if event.event_type != exec_settlement::EVENT_TYPE
        || event.source != "kernel"
        || receipt["protocol"] != "whipplescript.exec.settlement-retention/v1"
        || receipt["instance_id"] != instance
        || receipt["effect_id"] != effect.effect_id
        || receipt["run_id"] != run_id
        || receipt["input"] != serde_json::from_str::<Value>(&effect.input_json)?
    {
        return Err(StoreError::Conflict(
            "exec recovery receipt differs from its invocation".into(),
        ));
    }
    let material: RetainedExecMaterial = serde_json::from_value(receipt["settlement"].clone())?;
    if !(matches!(material.status.as_str(), "completed" | "failed")
        || (matches!(material.status.as_str(), "cancelled" | "timed_out")
            && material.metadata.get("executor_outcome_event_id").is_some()))
    {
        return Err(StoreError::Conflict(
            "exec recovery has an unsupported terminal status".into(),
        ));
    }
    let runs = kernel.store().list_runs(instance)?;
    let run = runs
        .iter()
        .find(|run| run.run_id == run_id)
        .ok_or_else(|| StoreError::Conflict("exec recovery run is missing".into()))?;
    if run.effect_id != effect.effect_id || run.provider != "exec" || run.worker_id != "whip-exec" {
        return Err(StoreError::Conflict(
            "exec recovery run differs from its receipt".into(),
        ));
    }
    let metadata_json = material.metadata.to_string();
    let expected_run_status = whipplescript_store::exec_outcome::projection_run_status(
        EffectCompletion {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &run_id,
            provider: "exec",
            worker_id: "whip-exec",
            status: &material.status,
            exit_code: material.exit_code,
            summary: material.summary.as_deref(),
            metadata_json: &metadata_json,
            idempotency_key: None,
        },
        &material.status,
        material.cache.is_some(),
        |key| {
            let Some(ack) = kernel.store().event_by_idempotency_key(instance, key)? else {
                return Ok(None);
            };
            let e = events
                .iter()
                .find(|e| e.event_id == ack.event_id)
                .ok_or_else(|| {
                    StoreError::Conflict("exec projection evidence journal is missing".into())
                })?;
            Ok(Some((
                e.event_id.clone(),
                e.event_type.clone(),
                e.source.clone(),
                e.payload_json.clone(),
            )))
        },
    )?;
    if run.status != "running" {
        if run.status != expected_run_status
            || serde_json::from_str::<Value>(&run.metadata_json)? != material.metadata
        {
            return Err(StoreError::Conflict(
                "exec recovery terminal differs from its receipt".into(),
            ));
        }
        let terminal = kernel
            .store()
            .event_by_idempotency_key(
                instance,
                &crate::execution_run_key(instance, &effect.effect_id, &run_id, &["terminal"]),
            )?
            .ok_or_else(|| {
                StoreError::Conflict("exec recovery terminal event is missing".into())
            })?;
        let matching = events.iter().any(|event| {
            event.event_id == terminal.event_id
                && event.event_type == "effect.terminal"
                && event.source == "kernel"
                && serde_json::from_str::<Value>(&event.payload_json).is_ok_and(|body| {
                    body["run_id"] == run_id && body["effect_id"] == effect.effect_id
                })
        });
        if !matching {
            return Err(StoreError::Conflict(
                "exec recovery terminal event differs from its invocation".into(),
            ));
        }
        return Ok(Some(terminal));
    }
    let current = kernel
        .store()
        .list_effects(instance)?
        .into_iter()
        .find(|row| row.effect_id == effect.effect_id)
        .ok_or_else(|| StoreError::Conflict("exec recovery effect is missing".into()))?;
    if current.kind != "exec.command"
        || serde_json::from_str::<Value>(&current.input_json)? != receipt["input"]
    {
        return Err(StoreError::Conflict(
            "exec recovery effect differs from its retained input".into(),
        ));
    }
    let cache = material.cache.as_ref().map(|(content_key, result_json)| {
        whipplescript_store::SettlementCache {
            content_key,
            result_json,
        }
    });
    commit_exec_projection_batch(
        kernel,
        EffectCompletion {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &run_id,
            provider: "exec",
            worker_id: "whip-exec",
            status: &material.status,
            exit_code: material.exit_code,
            summary: material.summary.as_deref(),
            metadata_json: &material.metadata.to_string(),
            idempotency_key: Some(&crate::execution_run_key(
                instance,
                &effect.effect_id,
                &run_id,
                &["terminal"],
            )),
        },
        &material.projections,
        cache,
    )
    .map(Some)
}

/// Commit host-specific exec metadata and projections through the shared batch.
fn commit_exec_projection_batch<S: RuntimeStore>(
    kernel: &mut RuntimeKernel<S>,
    completion: EffectCompletion<'_>,
    projections: &[ExecSettlementProjection],
    cache: Option<whipplescript_store::SettlementCache<'_>>,
) -> StoreResult<StoredEvent> {
    let ids: Vec<_> = projections
        .iter()
        .map(|p| crate::idempotency_key(&[completion.instance_id, "fact", &p.name, &p.key]))
        .collect();
    let facts: Vec<_> = projections
        .iter()
        .zip(&ids)
        .map(|(p, id)| whipplescript_store::SettlementFact {
            fact: whipplescript_store::NewFact {
                fact_id: id,
                name: &p.name,
                key: &p.key,
                value_json: &p.value,
                schema_id: p.ingest.then_some(p.name.as_str()),
                provenance_class: if p.ingest { "ingest" } else { "external" },
                correlation_id: None,
                source_span_json: None,
                // An exec settlement projection carries no declared validity:
                // its premises are the run's, recorded on the settlement.
                validity_json: None,
            },
            idempotency_key: &p.event_key,
        })
        .collect();
    kernel.complete_exec_settlement(completion, &facts, cache)
}

/// Encode a successful exec outcome for the delta-kernel result cache.
pub fn encode_cached_exec_result(
    exit_code: i64,
    stdout: &str,
    stderr: &str,
    ingested: &Option<ExecIngest>,
) -> String {
    let ingested_value = match ingested {
        None => Value::Null,
        Some(ExecIngest::Single(value)) => json!({"single": value}),
        Some(ExecIngest::Stream(elements)) => json!({"stream": elements}),
    };
    json!({
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "ingested": ingested_value,
    })
    .to_string()
}

/// Decode a cached exec result back into the success-outcome shape. `None`
/// (treated as a miss) if the recorded JSON does not decode, so a malformed
/// entry degrades to a real run instead of an error.
pub fn decode_cached_exec_result(
    result_json: &str,
) -> Option<(i64, String, String, Option<ExecIngest>)> {
    let value = serde_json::from_str::<Value>(result_json).ok()?;
    let exit_code = value.get("exit_code")?.as_i64()?;
    let stdout = value.get("stdout")?.as_str()?.to_owned();
    let stderr = value.get("stderr")?.as_str()?.to_owned();
    let ingested = match value.get("ingested") {
        None | Some(Value::Null) => None,
        Some(ingested) => {
            if let Some(single) = ingested.get("single") {
                Some(ExecIngest::Single(single.clone()))
            } else {
                let stream = ingested.get("stream").and_then(Value::as_array)?;
                Some(ExecIngest::Stream(stream.clone()))
            }
        }
    };
    Some((exit_code, stdout, stderr, ingested))
}

/// Minimal standard-alphabet base64 encode (no dependency; the executor wire
/// carries script bytes inline).
pub fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let mut accumulator = 0u32;
        for (index, byte) in chunk.iter().enumerate() {
            accumulator |= u32::from(*byte) << (16 - 8 * index);
        }
        for position in 0..4 {
            if position <= chunk.len() {
                let index = ((accumulator >> (18 - 6 * position)) & 0x3f) as usize;
                output.push(ALPHABET[index] as char);
            } else {
                output.push('=');
            }
        }
    }
    output
}

/// Minimal standard-alphabet base64 decode (`=` padding tolerated).
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn value(ch: u8) -> Option<u32> {
        match ch {
            b'A'..=b'Z' => Some(u32::from(ch - b'A')),
            b'a'..=b'z' => Some(u32::from(ch - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(ch - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for byte in input.bytes() {
        let chunk = value(byte)?;
        accumulator = (accumulator << 6) | chunk;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((accumulator >> bits) as u8);
        }
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_body_identity_binds_execution_independently_of_endpoint() {
        let input = json!({"capability": "observer"});
        let request = HttpRequest {
            model_provenance: None,
            url: "https://executor-one/exec".into(),
            headers: vec![],
            body: json!({"argv": ["python", "-I", "{script}"], "stdin": "captured"}),
        };
        let plan = |request: &HttpRequest| {
            ExecDispatchPlan::prepare("observer", "script", &input, request, "epoch", None, None)
        };
        let original = plan(&request);
        assert_eq!(
            original.request_body_sha256,
            sha256_hex(request.body.to_string().as_bytes())
        );
        let mut relocated = request.clone();
        relocated.url = "https://executor-two/exec".into();
        assert_eq!(
            original.request_body_sha256,
            plan(&relocated).request_body_sha256
        );
        assert_ne!(original.request_sha256, plan(&relocated).request_sha256);
        for (field, value) in [
            ("argv", json!(["python", "{script}"])),
            ("stdin", json!("different capture")),
            ("env", json!({"PYTHONPATH": "/foreign"})),
        ] {
            let mut changed = request.clone();
            changed.body[field] = value;
            assert_ne!(
                original.request_body_sha256,
                plan(&changed).request_body_sha256,
                "{field}"
            );
        }
    }

    #[test]
    fn executor_receipt_survives_settlement_reopen_and_projection_rebuild() {
        use whipplescript_store::{NewEffect, RuleCommit, RunStart, SqliteStore};
        for case in 0..4 {
            let path = std::env::temp_dir().join(format!(
                "whip-executor-receipt-{}-{}-{case}.sqlite",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock after epoch")
                    .as_nanos(),
            ));
            let mut kernel = RuntimeKernel::new(SqliteStore::open(&path).expect("open store"));
            let effects = [NewEffect {
                effect_id: "observe",
                kind: "exec.command",
                target: None,
                input_json: r#"{"mode":"capability","capability":"observer"}"#,
                status: "queued",
                idempotency_key: "observe",
                required_capabilities_json: "[]",
                profile: None,
                correlation_id: None,
                source_span_json: None,
                timeout_seconds: None,
            }];
            kernel
                .store_mut()
                .commit_rule(RuleCommit {
                    instance_id: "instance",
                    rule: "check",
                    trigger_event_id: None,
                    facts: &[],
                    consumed_fact_ids: &[],
                    effects: &effects,
                    dependencies: &[],
                    terminal: None,
                    idempotency_key: Some("check"),
                    marks: &[],
                    context_json: None,
                })
                .expect("commit execution input");
            let input: Value = serde_json::from_str(effects[0].input_json).expect("effect input");
            let request = build_executor_exec_request(
                "http://executor",
                "observe",
                "script",
                "body",
                &["sh".into(), SCRIPT_ARGV_PLACEHOLDER.into()],
                &[],
                &Value::Null,
                None,
            )
            .expect("dispatch request");
            let plan = ExecDispatchPlan::prepare(
                "observer", "script", &input, &request, "fixture", None, None,
            );
            let prepared_metadata = json!({"executor_dispatch":plan}).to_string();
            kernel
                .start_run(RunStart {
                    instance_id: "instance",
                    effect_id: "observe",
                    run_id: "run",
                    provider: "exec",
                    worker_id: "whip-exec",
                    lease_id: "lease",
                    lease_expires_at: "2030-01-01T00:00:00Z",
                    metadata_json: &prepared_metadata,
                })
                .expect("start run");
            assert_eq!(
                ExecDispatchPlan::load(kernel.store(), "instance", "observe", "run", &input)
                    .expect("load dispatched plan")
                    .request_sha256,
                plan.request_sha256
            );
            if case == 0 {
                for (effect, run, expected) in [
                    (
                        "other",
                        "run",
                        "executor dispatch run differs from its invocation",
                    ),
                    ("observe", "missing", "executor dispatch run is missing"),
                ] {
                    let error =
                        ExecDispatchPlan::load(kernel.store(), "instance", effect, run, &input)
                            .expect_err("invalid invocation");
                    assert!(format!("{error:?}").contains(expected));
                }
                let error = ExecDispatchPlan::load(
                    kernel.store(),
                    "instance",
                    "observe",
                    "run",
                    &json!({"changed":true}),
                )
                .expect_err("changed input");
                assert!(format!("{error:?}").contains("original input or protocol"));
                let sql = rusqlite::Connection::open(&path).expect("fixture connection");
                let mut wrong_protocol = json!({"executor_dispatch":plan});
                wrong_protocol["executor_dispatch"]["protocol"] = json!("future");
                for (metadata, expected) in [
                    (json!({}), "executor dispatch plan is missing"),
                    (wrong_protocol, "original input or protocol"),
                ] {
                    sql.execute(
                        "UPDATE runs SET metadata_json = ?1 WHERE run_id = 'run'",
                        [metadata.to_string()],
                    )
                    .expect("inject invalid plan");
                    let error = ExecDispatchPlan::load(
                        kernel.store(),
                        "instance",
                        "observe",
                        "run",
                        &input,
                    )
                    .expect_err("invalid plan");
                    assert!(format!("{error:?}").contains(expected));
                }
                sql.execute(
                    "UPDATE runs SET metadata_json = ?1 WHERE run_id = 'run'",
                    [&prepared_metadata],
                )
                .expect("restore original plan");
            }
            let response = HttpResponse {
                status: 200,
                body: json!({"protocol": EXECUTOR_PROTOCOL, "effect_id":"observe",
                    "exit_code": if case == 0 {0} else {2}, "timed_out":case == 1,
                    "stdout_truncated":case == 1, "stderr_truncated":case == 1,
                    "stdout":"earlier counterexample\n", "stderr":"later failure",
                    "extension":{"future_receipt_field":17}}),
            };
            let response = if case == 3 {
                HttpResponse {
                    status: 503,
                    body: json!({"error":"executor unavailable"}),
                }
            } else {
                response
            };
            let context = ExecSettleContext {
                resolution_event_id: None,
                input_json: r#"{"mode":"capability","capability":"observer"}"#,
                instance_id: "instance",
                effect_id: "observe",
                run_id: "run",
                capability: "observer",
                script_sha256: "script",
                cache: (case == 0).then_some(("settlement-cache", false)),
                ingest_schema: "json",
                executor_response: if case == 2 { None } else { Some(&response) },
                executor_transport: "http",
                dispatch_plan: Some(&plan),
            };
            let outcome = if case == 1 {
                Err((
                    Some((2, "earlier counterexample\n".into(), "later failure".into())),
                    "timed out".into(),
                ))
            } else if case == 3 {
                Err((None, "executor unavailable".into()))
            } else {
                Ok((
                    0,
                    "earlier counterexample\n".into(),
                    "later failure".into(),
                    (case == 0).then(|| ExecIngest::Stream(vec![json!({"n":1}), json!({"n":2})])),
                ))
            };
            let db = rusqlite::Connection::open(&path).expect("fault connection");
            for key in if case == 0 {
                vec!["observe:0", "observe:1", "observe"]
            } else {
                vec!["observe"]
            } {
                db.execute_batch(&format!("CREATE TRIGGER fail_settlement_fact AFTER INSERT ON facts WHEN NEW.key = '{key}' BEGIN SELECT RAISE(ABORT, 'injected settlement fact failure'); END;")).unwrap();
                let events_before: Vec<_> = kernel
                    .store()
                    .list_events("instance")
                    .unwrap()
                    .into_iter()
                    .filter(|e| e.event_type != whipplescript_store::exec_settlement::EVENT_TYPE)
                    .collect();
                let trace_before = kernel.trace().len();
                assert!(settle_exec_http_result(&mut kernel, &context, outcome.clone()).is_err());
                assert_eq!(
                    kernel.store().list_events("instance").unwrap().into_iter().filter(|e| e.event_type != whipplescript_store::exec_settlement::EVENT_TYPE).collect::<Vec<_>>(),
                    events_before
                );
                assert_eq!(
                    kernel.trace().len(),
                    trace_before,
                    "rolled-back terminal must not emit trace"
                );
                assert_eq!(
                    kernel.store().list_runs("instance").unwrap()[0].status,
                    "running"
                );
                assert!(kernel
                    .store()
                    .lookup_compute_result("settlement-cache")
                    .unwrap()
                    .is_none());
                db.execute_batch("DROP TRIGGER fail_settlement_fact")
                    .unwrap();
            }
            drop(db);
            settle_exec_http_result(&mut kernel, &context, outcome)
                .expect("settle execution after rollback");
            drop(kernel);
            let mut store = SqliteStore::open(&path).expect("reopen after worker exit");
            for replay in [false, true] {
                if replay {
                    store
                        .rebuild_projections("instance")
                        .expect("replay journal");
                }
                let runs = store.list_runs("instance").expect("read durable runs");
                assert_eq!(runs.len(), 1);
                let metadata: Value =
                    serde_json::from_str(&runs[0].metadata_json).expect("metadata JSON");
                assert_eq!(metadata["executor_dispatch"], json!(plan));
                assert_eq!(metadata["sha256"], json!("script"));
                assert_eq!(metadata["capability"], json!("observer"));
                if case == 2 {
                    assert!(
                        metadata.get("executor_response").is_none(),
                        "execution without HTTP minted a receipt"
                    );
                } else {
                    assert_eq!(
                        metadata["executor_response"],
                        json!({"status":response.status,"body":response.body})
                    );
                }
                assert_eq!(
                    runs[0].status,
                    if case == 1 || case == 3 {
                        "failed"
                    } else {
                        "completed"
                    }
                );
            }
            drop(store);
            std::fs::remove_file(path).expect("remove test store");
        }
    }

    #[test]
    fn exec_dispatch_reply_requires_its_original_effect() {
        let response = HttpResponse {
            status: 200,
            body: json!({"protocol":EXECUTOR_PROTOCOL,"effect_id":"original","exit_code":0}),
        };
        assert!(parse_executor_response_for_effect(&response, "original").is_ok());
        assert_eq!(
            parse_executor_response_for_effect(&response, "other").expect_err("foreign reply"),
            "executor response differs from its dispatched effect"
        );
        let mut missing = response.clone();
        missing
            .body
            .as_object_mut()
            .expect("object")
            .remove("effect_id");
        assert_eq!(
            parse_executor_response_for_effect(&missing, "original")
                .expect_err("missing invocation"),
            "executor response differs from its dispatched effect"
        );
    }

    #[test]
    fn sha256_hex_matches_the_known_vector() {
        // This digest feeds persisted script pins, exec content keys, and
        // package identity, so the rendering is pinned against a fixed vector
        // rather than against whatever the helper currently emits.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn content_key_is_stable_and_component_sensitive() {
        let argv = vec!["sh".to_owned(), "{script}".to_owned()];
        let env = vec![("MODEL".to_owned(), "m1".to_owned())];
        let key = exec_content_key("a1", &argv, &env, "native-v0", r#"{"n":1}"#, &None);
        assert_eq!(
            key,
            exec_content_key("a1", &argv, &env, "native-v0", r#"{"n":1}"#, &None)
        );
        for other in [
            exec_content_key("a2", &argv, &env, "native-v0", r#"{"n":1}"#, &None),
            exec_content_key("a1", &argv, &env, "epoch-2", r#"{"n":1}"#, &None),
            exec_content_key("a1", &argv, &env, "native-v0", r#"{"n":2}"#, &None),
            exec_content_key(
                "a1",
                &argv,
                &env,
                "native-v0",
                r#"{"n":1}"#,
                &Some(json!({"schema": "S"})),
            ),
        ] {
            assert_ne!(key, other);
        }
    }

    #[test]
    fn request_builder_places_script_and_env() {
        let request = build_executor_exec_request(
            "http://executor:8080/",
            "effect-1",
            "a".repeat(64).as_str(),
            "echo hi\n",
            &["sh".to_owned(), "{script}".to_owned()],
            &[("MODE".to_owned(), "strict".to_owned())],
            &json!({"n": 1}),
            Some(15_000),
        )
        .expect("builds");
        assert_eq!(request.url, "http://executor:8080/exec");
        assert_eq!(request.body["script_index"], json!(1));
        assert_eq!(request.body["env"]["MODE"], json!("strict"));
        assert_eq!(request.body["timeout_ms"], json!(15_000));
        assert_eq!(
            base64_decode(request.body["script_b64"].as_str().expect("b64")).expect("decodes"),
            b"echo hi\n"
        );

        let error = build_executor_exec_request(
            "http://executor:8080",
            "effect-1",
            "aa",
            "echo hi\n",
            &["sh".to_owned(), "judge.sh".to_owned()],
            &[],
            &Value::Null,
            None,
        )
        .expect_err("missing placeholder rejected");
        assert!(error.contains("{script}"), "{error}");
    }

    #[test]
    fn response_parser_validates_protocol_and_shape() {
        let ok = parse_executor_exec_response(&HttpResponse {
            status: 200,
            body: json!({
                "protocol": EXECUTOR_PROTOCOL,
                "exit_code": 0,
                "timed_out": false,
                "stdout": "out",
                "stderr": "",
            }),
        })
        .expect("parses");
        assert_eq!(ok.exit_code, 0);
        assert_eq!(ok.stdout, "out");

        let error = parse_executor_exec_response(&HttpResponse {
            status: 500,
            body: json!({"error": "boom"}),
        })
        .expect_err("status surfaced");
        assert!(error.contains("500") && error.contains("boom"), "{error}");

        let error = parse_executor_exec_response(&HttpResponse {
            status: 200,
            body: json!({"protocol": "bogus/1", "exit_code": 0}),
        })
        .expect_err("protocol mismatch");
        assert!(error.contains("bogus/1"), "{error}");
    }

    #[test]
    fn ingest_single_and_stream() {
        let single =
            ingest_exec_stdout(&json!({"schema": "S"}), r#"{"ok": true}"#).expect("single ingests");
        assert!(matches!(single, ExecIngest::Single(_)));
        let stream = ingest_exec_stdout(
            &json!({"schema": "S", "each": true}),
            "{\"n\":1}\n{\"n\":2}\n",
        )
        .expect("stream ingests");
        match stream {
            ExecIngest::Stream(elements) => assert_eq!(elements.len(), 2),
            other => panic!("expected stream, got {other:?}"),
        }
        assert!(ingest_exec_stdout(&json!({"schema": "S"}), "not json").is_err());
    }

    #[test]
    fn base64_roundtrip() {
        for sample in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"\xff\x00!"[..],
        ] {
            assert_eq!(
                base64_decode(&base64_encode(sample)).expect("decodes"),
                sample
            );
        }
    }
}
