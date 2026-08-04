//! The `#[wasm_bindgen]` boundary the Cloudflare Worker shell imports (DR-0033
//! chunk 5c). wasm32-only — a thin JS↔Rust wrapper over
//! [`DurableInstance`](crate::do_worker::DurableInstance)`::create`/`step`/`status`,
//! carrying no orchestration of its own:
//!
//! - a [`DoSql`] backed by the isolate's `state.storage.sql` (via the JS
//!   `DoSqlBridge` object the shell passes in),
//! - JSON marshalling of the step protocol (`fetch` request out, response in), and
//! - error surfacing across the boundary.
//!
//! The TS shell drives it: `WasmDurableInstance.create(bridge, program, input,
//! principal)`, then loop `step(responseJson)` — on `{"kind":"needs_http", …}` do the
//! `fetch` and pass the result back, on `{"kind":"terminal"|"parked"|"failed"}` stop.
//! Provider creds flow in via `create`'s `coerce_config_json` / `agent_config_json`
//! (from DO secrets), so the store-only, effect-free, coerce, AND agent-turn paths
//! run on the deployed surface. The remaining agent seam is tools: a live turn that
//! requests tools needs a tool-executor sidecar (the async-tool boundary).

use wasm_bindgen::prelude::*;

use crate::do_store::{do_load_agent_snapshot, do_save_agent_snapshot, SqlValue};
use whipplescript_kernel::coerce_native::CoerceProvider;
use whipplescript_kernel::harness_model::MessagesApiClient;
use whipplescript_kernel::sansio::{HttpResponse, TransportError};

use crate::do_instance::{ExecutorSidecarConfig, ResolvedCoercionConfig, TurnContainerConfig};
use crate::do_store::DoSql;
use crate::do_worker::{
    DurableEffectPorts, DurableInstance, DurableStepOutcome, ScriptCapabilityInput,
};
use crate::governance::GaugeDeskGovernanceRoot;
use whipplescript_kernel::host_facade::{GovernedHostFacade, ProviderRealization};
use whipplescript_kernel::host_package::{AuthoredAgentPackage, PackageResolver};
use whipplescript_kernel::host_protocol::{
    EventPosition, ForkInstanceCommand, ForkedInstance, OpenInstanceCommand, PolicyEpochRef,
    StartTurnCommand, HOST_PROTOCOL,
};
use whipplescript_kernel::AgentThreadSeed;
use whipplescript_store::{EffectCancellationRequest, NewEvent, RuntimeStore};

/// Verify and normalize one GaugeDesk-signed hosted policy epoch. This is a
/// direct wasm export so the Worker shell can fail closed before persisting a
/// placement bootstrap. The signer and key come from Worker bindings, never
/// from the request body.
#[wasm_bindgen]
pub fn verify_host_policy(
    epoch: u64,
    signed_envelope: &str,
    expected_signer: &str,
    public_key_hex: &str,
) -> Result<String, JsValue> {
    let verified = GaugeDeskGovernanceRoot::new(expected_signer, public_key_hex)
        .verify_epoch(epoch, signed_envelope)
        .map_err(|error| JsValue::from_str(&error))?;
    serde_json::to_string(&verified.policy).map_err(|error| JsValue::from_str(&error.to_string()))
}

fn hosted_facade(
    bridge: DoSqlBridge,
    epoch: u64,
    signed_envelope: &str,
    expected_signer: &str,
    public_key_hex: &str,
) -> Result<GovernedHostFacade<crate::do_store::DoSqliteStore<JsDoSql>>, JsValue> {
    let verified = GaugeDeskGovernanceRoot::new(expected_signer, public_key_hex)
        .verify_epoch(epoch, signed_envelope)
        .map_err(|error| JsValue::from_str(&error))?;
    GovernedHostFacade::from_verified_store(
        crate::do_store::DoSqliteStore::new(JsDoSql { bridge }),
        epoch,
        verified.envelope,
    )
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

fn authored_package(
    manifest: &str,
    source: &str,
    system_prompt: &str,
) -> Result<AuthoredAgentPackage, JsValue> {
    AuthoredAgentPackage::from_documents(manifest, source, system_prompt)
        .map_err(|error| JsValue::from_str(&error))
}

/// Execute `OpenInstanceCommand` against the DO store through the common
/// governed facade and placement-neutral authored package implementation.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn host_open_instance(
    bridge: DoSqlBridge,
    epoch: u64,
    signed_envelope: &str,
    expected_signer: &str,
    public_key_hex: &str,
    command_json: &str,
    package_manifest: &str,
    package_source: &str,
    system_prompt: &str,
) -> Result<String, JsValue> {
    let mut facade = hosted_facade(
        bridge,
        epoch,
        signed_envelope,
        expected_signer,
        public_key_hex,
    )?;
    let command: OpenInstanceCommand = serde_json::from_str(command_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let package = authored_package(package_manifest, package_source, system_prompt)?;
    let opened = facade
        .open_instance(&command, &package)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_json::to_string(&opened).map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Phase one of a hosted turn: validate the signed epoch, instance, package,
/// IFC, actor, and opaque references. The Worker may resolve only the returned
/// capability ids after this function succeeds.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn host_validate_turn(
    bridge: DoSqlBridge,
    epoch: u64,
    signed_envelope: &str,
    expected_signer: &str,
    public_key_hex: &str,
    command_json: &str,
    package_manifest: &str,
    package_source: &str,
    system_prompt: &str,
) -> Result<String, JsValue> {
    let facade = hosted_facade(
        bridge,
        epoch,
        signed_envelope,
        expected_signer,
        public_key_hex,
    )?;
    let command: StartTurnCommand = serde_json::from_str(command_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let package = authored_package(package_manifest, package_source, system_prompt)?;
    let admission = facade
        .validate_turn(&command, &package)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_json::to_string(&admission).map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Phase two of a hosted turn: after the Worker resolves the admitted opaque
/// capability, verify its credential-free provider identity and enqueue the
/// exact command idempotently.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn host_begin_turn(
    bridge: DoSqlBridge,
    epoch: u64,
    signed_envelope: &str,
    expected_signer: &str,
    public_key_hex: &str,
    command_json: &str,
    package_manifest: &str,
    package_source: &str,
    system_prompt: &str,
    provider: &str,
    model: &str,
    base_url: &str,
) -> Result<bool, JsValue> {
    let mut facade = hosted_facade(
        bridge,
        epoch,
        signed_envelope,
        expected_signer,
        public_key_hex,
    )?;
    let command: StartTurnCommand = serde_json::from_str(command_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let package = authored_package(package_manifest, package_source, system_prompt)?;
    facade
        .begin_turn(
            &command,
            &package,
            ProviderRealization {
                provider,
                model,
                base_url,
            },
        )
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Request cooperative cancellation of one admitted hosted turn. The public
/// Worker fixes `requested_by`; callers cannot forge runtime evidence fields.
#[wasm_bindgen]
pub fn host_cancel_turn(
    bridge: DoSqlBridge,
    instance_id: &str,
    command_id: &str,
    requested_by: &str,
) -> Result<String, JsValue> {
    let mut store = crate::do_store::DoSqliteStore::new(std::rc::Rc::new(JsDoSql { bridge }));
    let idempotency = whipplescript_kernel::idempotency_key(&[
        instance_id,
        command_id,
        "host-cancellation-request",
    ]);
    let request = store
        .request_effect_cancellation(EffectCancellationRequest {
            instance_id,
            effect_id: command_id,
            revision_id: None,
            reason: Some("GaugeDesk requested cancellation"),
            requested_by,
            causation_event_id: None,
            idempotency_key: Some(&idempotency),
        })
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    Ok(serde_json::json!({
        "request_id": request.request_id,
        "instance_ref": request.instance_id,
        "command_id": request.effect_id,
        "status": request.status,
    })
    .to_string())
}

/// Fold one admitted hosted turn through WhippleScript's runtime-owned pointer
/// and receipt schema. The Worker shell merges this body-free projection with
/// its transcript transport; it does not reinterpret runtime SQL itself.
#[wasm_bindgen]
pub fn host_project_turn(
    bridge: DoSqlBridge,
    instance_id: &str,
    command_id: &str,
) -> Result<String, JsValue> {
    let mut store = crate::do_store::DoSqliteStore::new(std::rc::Rc::new(JsDoSql { bridge }));
    let projection = crate::host_projection::project_host_turn(&mut store, instance_id, command_id)
        .map_err(|error| JsValue::from_str(&error))?;
    serde_json::to_string(&projection).map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Current durable event coordinate for exact turn/fork cuts.
#[wasm_bindgen]
pub fn host_current_position(bridge: DoSqlBridge, instance_id: &str) -> Result<String, JsValue> {
    let store = crate::do_store::DoSqliteStore::new(std::rc::Rc::new(JsDoSql { bridge }));
    let position = crate::host_projection::current_position(&store, instance_id)
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    serde_json::to_string(&position).map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Export the source agent's live thread at one exact event coordinate. The
/// source package/policy binding and quiescence are revalidated before any
/// transcript projection leaves its placement.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn host_export_thread(
    bridge: DoSqlBridge,
    epoch: u64,
    signed_envelope: &str,
    expected_signer: &str,
    public_key_hex: &str,
    source_position_json: &str,
    package_manifest: &str,
    package_source: &str,
    system_prompt: &str,
) -> Result<String, JsValue> {
    let facade = hosted_facade(
        bridge,
        epoch,
        signed_envelope,
        expected_signer,
        public_key_hex,
    )?;
    let source: EventPosition = serde_json::from_str(source_position_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    if source.sequence == 0 {
        return Err(JsValue::from_str("fork source position must be nonzero"));
    }
    let package = authored_package(package_manifest, package_source, system_prompt)?;
    let resolved = package
        .resolve_package(package.version_ref())
        .map_err(|error| JsValue::from_str(&error))?;
    let instance = facade
        .kernel()
        .store()
        .get_instance(&source.instance_ref)
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?
        .ok_or_else(|| JsValue::from_str("fork source instance was not found"))?;
    let metadata: serde_json::Value = serde_json::from_str(&instance.input_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let source_policy: PolicyEpochRef = serde_json::from_value(metadata["policy"].clone())
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    if source_policy != *facade.policy_ref()
        || metadata
            .get("package_version_ref")
            .and_then(serde_json::Value::as_str)
            != Some(package.version_ref())
    {
        return Err(JsValue::from_str(
            "fork source package/policy binding does not match the admitted export",
        ));
    }
    let current =
        crate::host_projection::current_position(facade.kernel().store(), &source.instance_ref)
            .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    if source.sequence > current.sequence {
        return Err(JsValue::from_str(
            "fork source position is beyond the runtime head",
        ));
    }
    let running = facade
        .kernel()
        .store()
        .list_effects(&source.instance_ref)
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?
        .into_iter()
        .any(|effect| effect.status == "running");
    if running {
        return Err(JsValue::from_str("fork source instance is not quiescent"));
    }
    let source_sequence = i64::try_from(source.sequence)
        .map_err(|_| JsValue::from_str("fork source position exceeds runtime range"))?;
    let messages = facade
        .kernel()
        .snapshot_agent_thread(&source.instance_ref, &resolved.agent, Some(source_sequence))
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    Ok(serde_json::json!({
        "protocol": HOST_PROTOCOL,
        "source": source,
        "package_version_ref": package.version_ref(),
        "policy": facade.policy_ref(),
        "messages": whipplescript_kernel::harness_loop::chat_messages_to_json(&messages),
    })
    .to_string())
}

/// Import a validated source-thread projection into a distinct target instance.
/// This records one idempotent seed plus the public fork receipt; it never
/// pretends the target executed the source effects.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn host_import_fork(
    bridge: DoSqlBridge,
    epoch: u64,
    signed_envelope: &str,
    expected_signer: &str,
    public_key_hex: &str,
    command_json: &str,
    export_json: &str,
    package_manifest: &str,
    package_source: &str,
    system_prompt: &str,
) -> Result<String, JsValue> {
    let mut facade = hosted_facade(
        bridge,
        epoch,
        signed_envelope,
        expected_signer,
        public_key_hex,
    )?;
    let command: ForkInstanceCommand = serde_json::from_str(command_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    command
        .validate()
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    if command.policy != *facade.policy_ref() {
        return Err(JsValue::from_str(
            "fork target policy epoch does not match runtime",
        ));
    }
    let export: serde_json::Value =
        serde_json::from_str(export_json).map_err(|error| JsValue::from_str(&error.to_string()))?;
    let exported_source: EventPosition = serde_json::from_value(export["source"].clone())
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let exported_policy: PolicyEpochRef = serde_json::from_value(export["policy"].clone())
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    if export.get("protocol").and_then(serde_json::Value::as_str) != Some(HOST_PROTOCOL)
        || exported_source != command.source
        || exported_policy != command.policy
    {
        return Err(JsValue::from_str(
            "fork export does not match its admitted command",
        ));
    }
    let package = authored_package(package_manifest, package_source, system_prompt)?;
    let target_package = package
        .resolve_package(&command.package_version_ref)
        .map_err(|error| JsValue::from_str(&error))?;
    if export
        .get("package_version_ref")
        .and_then(serde_json::Value::as_str)
        != Some(command.package_version_ref.as_str())
    {
        return Err(JsValue::from_str(
            "fork export package does not match its admitted command",
        ));
    }
    let source_instance = facade
        .kernel()
        .store()
        .get_instance(&command.source.instance_ref)
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?
        .ok_or_else(|| JsValue::from_str("fork source instance was not found"))?;
    let source_metadata: serde_json::Value = serde_json::from_str(&source_instance.input_json)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let source_policy: PolicyEpochRef = serde_json::from_value(source_metadata["policy"].clone())
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    if source_policy != command.policy
        || source_metadata
            .get("package_version_ref")
            .and_then(serde_json::Value::as_str)
            != Some(command.package_version_ref.as_str())
    {
        return Err(JsValue::from_str(
            "fork source package/policy binding does not match the admitted import",
        ));
    }
    let source_head = crate::host_projection::current_position(
        facade.kernel().store(),
        &command.source.instance_ref,
    )
    .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    if command.source.sequence > source_head.sequence {
        return Err(JsValue::from_str(
            "fork source position is beyond the runtime head",
        ));
    }
    let source_running = facade
        .kernel()
        .store()
        .list_effects(&command.source.instance_ref)
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?
        .into_iter()
        .any(|effect| effect.status == "running");
    if source_running {
        return Err(JsValue::from_str("fork source instance is not quiescent"));
    }
    let source_sequence = i64::try_from(command.source.sequence)
        .map_err(|_| JsValue::from_str("fork source position exceeds runtime range"))?;
    // The export document is an admission token, not transcript authority. Both
    // instances are pinned to this placement, so import re-reads the exact cut
    // from the source DO store and ignores caller-echoed message bytes.
    let messages = facade
        .kernel()
        .snapshot_agent_thread(
            &command.source.instance_ref,
            &target_package.agent,
            Some(source_sequence),
        )
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    let target = facade
        .open_instance(&command.target_open_command(), &package)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    if target.instance_ref == command.source.instance_ref {
        return Err(JsValue::from_str("fork target identity must be distinct"));
    }
    if let Some(event) = facade
        .kernel()
        .store()
        .list_events(&target.instance_ref)
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?
        .into_iter()
        .find(|event| {
            event.event_type == "host.instance.forked"
                && serde_json::from_str::<serde_json::Value>(&event.payload_json)
                    .ok()
                    .and_then(|payload| {
                        payload
                            .get("request_id")
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_owned)
                    })
                    .as_deref()
                    == Some(command.request_id.as_str())
        })
    {
        let target_instance_ref = target.instance_ref.clone();
        let replay = ForkedInstance {
            protocol: HOST_PROTOCOL.to_owned(),
            request_id: command.request_id.clone(),
            source: command.source.clone(),
            target,
            forked_at: EventPosition {
                instance_ref: target_instance_ref,
                sequence: u64::try_from(event.sequence)
                    .ok()
                    .filter(|sequence| *sequence > 0)
                    .ok_or_else(|| {
                        JsValue::from_str("fork receipt event position must be positive")
                    })?,
            },
        };
        return serde_json::to_string(&replay)
            .map_err(|error| JsValue::from_str(&error.to_string()));
    }
    facade
        .kernel_mut()
        .seed_agent_thread(AgentThreadSeed {
            instance_id: &target.instance_ref,
            agent: &target_package.agent,
            messages: &messages,
            source_instance_id: &command.source.instance_ref,
            source_sequence,
            idempotency_key: &whipplescript_kernel::idempotency_key(&[
                &target.instance_ref,
                &command.request_id,
                "host-instance-thread-seed",
            ]),
        })
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    let payload = serde_json::json!({
        "request_id": command.request_id,
        "source": command.source,
        "target_request_id": command.target_request_id,
        "package_version_ref": command.package_version_ref,
        "policy": command.policy,
        "target_instance_ref": target.instance_ref,
    })
    .to_string();
    let event = facade
        .kernel()
        .store()
        .append_event(NewEvent {
            instance_id: &target.instance_ref,
            event_type: "host.instance.forked",
            payload_json: &payload,
            source: "host-do",
            causation_id: None,
            correlation_id: Some(&command.request_id),
            idempotency_key: Some(&whipplescript_kernel::idempotency_key(&[
                &target.instance_ref,
                &command.request_id,
                "host-instance-forked",
            ])),
        })
        .map_err(|error| JsValue::from_str(&format!("{error:?}")))?;
    let result = ForkedInstance {
        protocol: HOST_PROTOCOL.to_owned(),
        request_id: command.request_id.clone(),
        source: command.source.clone(),
        target: target.clone(),
        forked_at: EventPosition {
            instance_ref: target.instance_ref,
            sequence: u64::try_from(event.sequence)
                .ok()
                .filter(|sequence| *sequence > 0)
                .ok_or_else(|| JsValue::from_str("fork receipt event position must be positive"))?,
        },
    };
    result
        .validate_for(&command)
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    serde_json::to_string(&result).map_err(|error| JsValue::from_str(&error.to_string()))
}

#[wasm_bindgen]
extern "C" {
    /// The JS object the shell implements over `state.storage.sql`: run a statement
    /// (returns the changed-row count) or a query (returns rows as a JSON string).
    /// Params arrive as a JSON array of `null | number | string`.
    pub type DoSqlBridge;

    #[wasm_bindgen(method, catch)]
    fn exec(this: &DoSqlBridge, sql: &str, params_json: &str) -> Result<f64, JsValue>;

    #[wasm_bindgen(method, catch)]
    fn query(this: &DoSqlBridge, sql: &str, params_json: &str) -> Result<String, JsValue>;
}

/// [`DoSql`] over the JS `DoSqlBridge`. `SqlValue` marshals as JSON scalars.
struct JsDoSql {
    bridge: DoSqlBridge,
}

fn params_to_json(params: &[SqlValue]) -> String {
    let values: Vec<serde_json::Value> = params
        .iter()
        .map(|value| match value {
            SqlValue::Null => serde_json::Value::Null,
            SqlValue::Int(number) => serde_json::Value::from(*number),
            SqlValue::Text(text) => serde_json::Value::from(text.clone()),
        })
        .collect();
    serde_json::Value::from(values).to_string()
}

fn parse_rows(rows_json: &str) -> Result<Vec<Vec<SqlValue>>, String> {
    let rows: serde_json::Value =
        serde_json::from_str(rows_json).map_err(|error| error.to_string())?;
    let rows = rows
        .as_array()
        .ok_or("DoSqlBridge.query must return a JSON array of rows")?;
    rows.iter()
        .map(|row| {
            let cells = row
                .as_array()
                .ok_or("each row must be a JSON array".to_owned())?;
            Ok(cells
                .iter()
                .map(|cell| {
                    if cell.is_null() {
                        SqlValue::Null
                    } else if let Some(number) = cell.as_i64() {
                        SqlValue::Int(number)
                    } else if let Some(number) = cell.as_f64() {
                        SqlValue::Int(number as i64)
                    } else {
                        SqlValue::Text(cell.as_str().map(str::to_owned).unwrap_or_default())
                    }
                })
                .collect())
        })
        .collect()
}

impl DoSql for JsDoSql {
    fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
        let count = self
            .bridge
            .exec(sql, &params_to_json(params))
            .map_err(|error| format!("{error:?}"))?;
        Ok(count as u64)
    }

    fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
        let rows_json = self
            .bridge
            .query(sql, &params_to_json(params))
            .map_err(|error| format!("{error:?}"))?;
        parse_rows(&rows_json)
    }
}

/// The step response the shell hands back: `{"body": <json>, "status": <n>}` for a
/// completed `fetch`, or `{"error": "timeout" | <message>}` for a transport failure.
fn parse_incoming(
    response_json: Option<String>,
) -> Result<Option<Result<HttpResponse, TransportError>>, JsValue> {
    let Some(json) = response_json else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_str(&json).map_err(|error| JsValue::from_str(&error.to_string()))?;
    if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
        let transport = if error == "timeout" {
            TransportError::Timeout
        } else {
            TransportError::Transport(error.to_owned())
        };
        return Ok(Some(Err(transport)));
    }
    let status = value
        .get("status")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(200) as u16;
    let mut body = value
        .get("body")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    if let Some(stream) = body.as_str().filter(|stream| stream.contains("data:")) {
        body = whipplescript_kernel::harness_model::assemble_codex_responses_sse(stream);
    }
    Ok(Some(Ok(HttpResponse { status, body })))
}

/// Marshal a [`DurableStepOutcome`] to the JSON the shell branches on.
fn outcome_to_json(outcome: &DurableStepOutcome) -> String {
    let value = match outcome {
        DurableStepOutcome::NeedsHttp(request) => serde_json::json!({
            "kind": "needs_http",
            "request": {
                "url": request.url,
                "headers": request.headers,
                "body": request.body,
            },
        }),
        DurableStepOutcome::Terminal => serde_json::json!({ "kind": "terminal" }),
        DurableStepOutcome::Parked { next_due_unix_ms } => serde_json::json!({
            "kind": "parked",
            "next_due_unix_ms": next_due_unix_ms,
        }),
        DurableStepOutcome::Failed(message) => {
            serde_json::json!({ "kind": "failed", "message": message })
        }
    };
    value.to_string()
}

/// Parse the DO-secret coerce config JSON into the ONE canonical
/// [`ResolvedCoercionConfig`] record (spec/std-coercion.md "Config-plane
/// reconciliation") — the same record the native door resolves from env +
/// `whip auth` + the registry default. Coercion retains its bounded structured-
/// output default; it is separate from the owned agent harness below.
/// Codex brokered turns carry only sentinel authentication. The authenticated
/// outbound local broker replaces both sentinel fields after admission; no
/// OAuth material enters the Durable Object.
fn parse_coerce_config(json: &str) -> Result<ResolvedCoercionConfig, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| error.to_string())?;
    let backend = match value.get("provider").and_then(serde_json::Value::as_str) {
        Some("anthropic") => CoerceProvider::Anthropic,
        Some("openai") => CoerceProvider::OpenAi,
        Some("openai-generic") => CoerceProvider::OpenAiCompat,
        Some("openai-codex") => CoerceProvider::OpenAi,
        // The metered Cloudflare AI Gateway exposes the OpenAI-compatible
        // `/compat` surface, so the wire protocol is `OpenAiCompat`. It is a
        // distinct provider *id* rather than an alias because the id carries who
        // pays — a gateway round spends GaugeWright's unified-billing credits,
        // not a customer key (ADR 0085 §1). Collapsing the two here would be
        // fine on the wire and wrong in the ledger.
        Some("cloudflare-ai-gateway") => CoerceProvider::OpenAiCompat,
        other => return Err(format!("unknown coerce provider: {other:?}")),
    };
    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    Ok(ResolvedCoercionConfig {
        backend,
        provider_id: field("provider").unwrap_or_else(|| "coerce".to_owned()),
        base_url: field("base_url").ok_or("coerce config needs base_url")?,
        api_key: field("api_key").ok_or("coerce config needs api_key")?,
        model: field("model").ok_or("coerce config needs model")?,
        max_tokens: value
            .get("max_tokens")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(u64::from(
                whipplescript_kernel::coerce_native::DEFAULT_COERCE_MAX_TOKENS,
            )) as u32,
        timeout_secs: value
            .get("timeout_secs")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(whipplescript_kernel::coerce_native::DEFAULT_COERCE_TIMEOUT_SECS),
        codex_account_id: (value.get("provider").and_then(serde_json::Value::as_str)
            == Some("openai-codex"))
        .then(|| field("account_id").unwrap_or_else(|| "whipplescript-model-broker".to_owned())),
    })
}

/// Parse the DO-secret agent-model config JSON into a `MessagesApiClient` — the
/// same `{provider, base_url, api_key, model, max_tokens?}` shape as the coerce
/// config (an agent turn is a multi-round messages/responses call). When omitted,
/// WhippleScript derives the provider-required finite request value from the
/// selected model's output capability; the host does not impose a product limit.
/// The client is transport-free: the shell performs each round's `fetch`.
fn parse_agent_config(json: &str) -> Result<MessagesApiClient, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| error.to_string())?;
    let provider_id = value.get("provider").and_then(serde_json::Value::as_str);
    let provider = match provider_id {
        Some("anthropic") => CoerceProvider::Anthropic,
        Some("openai") => CoerceProvider::OpenAi,
        Some("openai-generic") => CoerceProvider::OpenAiCompat,
        Some("openai-codex") => CoerceProvider::OpenAi,
        // Same reasoning as the coerce parser above: OpenAI-compatible on the
        // wire, distinct as an id because the id is what says who pays.
        Some("cloudflare-ai-gateway") => CoerceProvider::OpenAiCompat,
        other => return Err(format!("unknown agent provider: {other:?}")),
    };
    let field = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let api_key = field("api_key").ok_or("agent config needs api_key")?;
    let model = field("model").ok_or("agent config needs model")?;
    let base_url = field("base_url").ok_or("agent config needs base_url")?;
    let max_tokens = value
        .get("max_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_else(|| {
            whipplescript_kernel::harness_model::model_output_limit(provider, &model)
        });
    let cache_key = field("cache_key");
    if provider_id == Some("openai-codex") {
        return Ok(MessagesApiClient::new_codex(
            api_key,
            field("account_id").unwrap_or_else(|| "whipplescript-model-broker".to_owned()),
            field("session_id").ok_or("codex agent config needs session_id")?,
            model,
            base_url,
            max_tokens,
            cache_key,
        ));
    }
    Ok(MessagesApiClient::new(
        provider, api_key, model, base_url, max_tokens, cache_key,
    ))
}

/// Parse the executor-sidecar config JSON (compute plane P8).
fn parse_exec_config(json: &str) -> Result<ExecutorSidecarConfig, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| error.to_string())?;
    let base_url = value
        .get("base_url")
        .and_then(serde_json::Value::as_str)
        .ok_or("exec config needs base_url")?
        .to_owned();
    let env_values = match value.get("env") {
        None | Some(serde_json::Value::Null) => std::collections::BTreeMap::new(),
        Some(env) => serde_json::from_value(env.clone())
            .map_err(|error| format!("exec config env must map names to strings: {error}"))?,
    };
    Ok(ExecutorSidecarConfig {
        base_url,
        env_values,
        environment_epoch: value
            .get("environment_epoch")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("do-v0")
            .to_owned(),
        timeout_ms: value.get("timeout_ms").and_then(serde_json::Value::as_u64),
        auth_token: value
            .get("auth_token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

/// Parse the deploy-shipped script capabilities (compute plane P8).
fn parse_scripts(json: &str) -> Result<Vec<ScriptCapabilityInput>, String> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_str(json).map_err(|error| error.to_string())?;
    entries
        .into_iter()
        .map(|entry| {
            let field = |name: &str| {
                entry
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            let name = field("name").ok_or("script entry needs name")?;
            let argv: Vec<String> = serde_json::from_value(
                entry
                    .get("argv")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            )
            .map_err(|error| format!("script `{name}` argv must be a string array: {error}"))?;
            let env = match entry.get("env") {
                None | Some(serde_json::Value::Null) => std::collections::BTreeMap::new(),
                Some(env) => serde_json::from_value(env.clone())
                    .map_err(|error| format!("script `{name}` env: {error}"))?,
            };
            Ok(ScriptCapabilityInput {
                sha256: field("sha256").ok_or(format!("script `{name}` needs sha256"))?,
                body: field("body").ok_or(format!("script `{name}` needs body"))?,
                hermetic: entry
                    .get("hermetic")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                name,
                argv,
                env,
            })
        })
        .collect()
}

/// Parse the Class-B turn-container config JSON (compute plane P8).
fn parse_turn_config(json: &str) -> Result<TurnContainerConfig, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|error| error.to_string())?;
    Ok(TurnContainerConfig {
        base_url: value
            .get("base_url")
            .and_then(serde_json::Value::as_str)
            .ok_or("turn config needs base_url")?
            .to_owned(),
        provider: value
            .get("provider")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({"provider": "fixture"})),
        max_steps: value
            .get("max_steps")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(30),
        auth_token: value
            .get("auth_token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

/// The durable-object instance as the Worker shell sees it.
#[wasm_bindgen]
pub struct WasmDurableInstance {
    inner: DurableInstance<JsDoSql>,
}

#[wasm_bindgen]
impl WasmDurableInstance {
    /// Attach to an instance already opened through `host_open_instance` and
    /// drive its queued governed turns. Package bytes are resolved through the
    /// same placement-neutral package implementation used during admission.
    #[allow(clippy::too_many_arguments)]
    pub fn attach_host(
        bridge: DoSqlBridge,
        instance_id: &str,
        package_manifest: &str,
        package_source: &str,
        system_prompt: &str,
        agent_config_json: Option<String>,
    ) -> Result<WasmDurableInstance, JsValue> {
        let package = authored_package(package_manifest, package_source, system_prompt)?;
        let resolved = package
            .resolve(package.version_ref())
            .map_err(|error| JsValue::from_str(&error))?;
        let agent_model: Option<Box<dyn whipplescript_kernel::harness_loop::HttpModelClient>> =
            match agent_config_json {
                Some(config) => Some(Box::new(
                    parse_agent_config(&config).map_err(|error| JsValue::from_str(&error))?,
                )),
                None => None,
            };
        let inner = DurableInstance::attach(
            JsDoSql { bridge },
            resolved.program,
            instance_id,
            resolved.system_prompt,
            resolved.max_steps,
            DurableEffectPorts {
                agent_model,
                agent_tool_specs: Some(resolved.tools),
                ..DurableEffectPorts::default()
            },
        )
        .map_err(|error| JsValue::from_str(&error))?;
        Ok(Self { inner })
    }

    /// Compile `program` and create + start a fresh instance over the JS-backed DO
    /// SQLite. Called once when the object is first addressed. Both config args are
    /// optional and carry provider creds from DO secrets, same JSON shape
    /// `{"provider":"anthropic"|"openai","base_url","api_key","model","max_tokens"}`:
    /// `coerce_config_json` for `coerce` effects, `agent_config_json` for the
    /// (multi-round) `agent.tell` turn. A live agent turn with tools also needs a
    /// tool executor over an HTTP sidecar (the remaining async-tool seam).
    /// Two further optional args wire the Class-A compute plane (P8):
    /// `exec_config_json` = `{"base_url", "env"?: {NAME: value}, "environment_epoch"?,
    /// "timeout_ms"?}` pointing at the executor sidecar; `scripts_json` = an
    /// array of `{"name", "argv": [.., "{script}", ..], "sha256", "env"?,
    /// "hermetic"?, "body"}` script capabilities registered into the DO store
    /// (each body verified against its pin, fail-closed).
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        bridge: DoSqlBridge,
        program: &str,
        input: &str,
        principal: &str,
        coerce_config_json: Option<String>,
        agent_config_json: Option<String>,
        project_context_json: Option<String>,
        exec_config_json: Option<String>,
        scripts_json: Option<String>,
        turn_config_json: Option<String>,
    ) -> Result<WasmDurableInstance, JsValue> {
        // Deploy-shipped project instructions: `[{"path": ..., "content": ...}]`
        // in injection order (context-assembly Phase 3 item 4).
        let project_context: Vec<(String, String)> = match project_context_json {
            Some(json) => serde_json::from_str::<Vec<serde_json::Value>>(&json)
                .map_err(|error| JsValue::from_str(&error.to_string()))?
                .into_iter()
                .filter_map(|doc| {
                    let path = doc.get("path")?.as_str()?.to_owned();
                    let content = doc.get("content")?.as_str()?.to_owned();
                    Some((path, content))
                })
                .collect(),
            None => Vec::new(),
        };
        let coerce = match coerce_config_json {
            Some(json) => Some(parse_coerce_config(&json).map_err(|e| JsValue::from_str(&e))?),
            None => None,
        };
        let agent_model: Option<Box<dyn whipplescript_kernel::harness_loop::HttpModelClient>> =
            match agent_config_json {
                Some(json) => Some(Box::new(
                    parse_agent_config(&json).map_err(|e| JsValue::from_str(&e))?,
                )),
                None => None,
            };
        let exec = match exec_config_json {
            Some(json) => Some(parse_exec_config(&json).map_err(|e| JsValue::from_str(&e))?),
            None => None,
        };
        let scripts = match scripts_json {
            Some(json) => parse_scripts(&json).map_err(|e| JsValue::from_str(&e))?,
            None => Vec::new(),
        };
        let turn = match turn_config_json {
            Some(json) => Some(parse_turn_config(&json).map_err(|e| JsValue::from_str(&e))?),
            None => None,
        };
        let inner = DurableInstance::create(
            JsDoSql { bridge },
            program,
            input,
            principal,
            DurableEffectPorts {
                coerce,
                agent_model,
                exec,
                turn,
                ..DurableEffectPorts::default()
            },
            &project_context,
            &scripts,
        )
        .map_err(|error| JsValue::from_str(&error))?;
        Ok(Self { inner })
    }

    /// Advance the instance one HTTP round. Pass `undefined`/`null` on the first
    /// call, then the previous `needs_http` request's `fetch` result as JSON.
    /// `now_unix_ms` is the host's clock (`Date.now()`), injected so the core
    /// never reads wall time (DR-0033 Phase 6 — timers/deadlines resolve
    /// against it, and `parked.next_due_unix_ms` names the next wake-up).
    /// Returns the next `DurableStepOutcome` as JSON.
    pub fn step(
        &mut self,
        response_json: Option<String>,
        now_unix_ms: f64,
    ) -> Result<String, JsValue> {
        let incoming = parse_incoming(response_json)?;
        Ok(outcome_to_json(
            &self.inner.step(incoming, now_unix_ms as i64),
        ))
    }

    /// The instance's durable status (`"running"` / `"completed"` / …).
    pub fn status(&self) -> Result<String, JsValue> {
        self.inner
            .status()
            .map(|status| status.unwrap_or_default())
            .map_err(|error| JsValue::from_str(&format!("{error:?}")))
    }

    /// Capture a restorable checkpoint (P3 — the DO operator command). Returns
    /// the checkpoint report as JSON, or a JS error if the instance is not
    /// quiescent.
    pub fn checkpoint(&mut self, cut_id: &str) -> Result<String, JsValue> {
        let report = self
            .inner
            .checkpoint(cut_id)
            .map_err(|error| JsValue::from_str(&error))?;
        Ok(serde_json::json!({
            "cut_id": report.cut_id,
            "sequence": report.sequence,
            "manifest_hash": report.manifest_hash,
            "file_count": report.file_count,
        })
        .to_string())
    }

    /// Restore the three planes to a prior checkpoint (P3 — the DO operator
    /// command). Returns the restore report as JSON, or a JS error on refusal /
    /// failure (a refusal mutates nothing).
    pub fn restore(&mut self, cut_id: &str) -> Result<String, JsValue> {
        let report = self
            .inner
            .restore(cut_id)
            .map_err(|error| JsValue::from_str(&error))?;
        Ok(serde_json::json!({
            "cut_id": report.cut_id,
            "restored_to_sequence": report.restored_to_sequence,
            "marker_sequence": report.marker_sequence,
            "files_written": report.files_written,
            "files_removed": report.files_removed,
            "auto_checkpoint": report.auto_checkpoint,
        })
        .to_string())
    }
}
