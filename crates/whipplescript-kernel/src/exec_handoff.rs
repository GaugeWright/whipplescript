//! Host-selected executor requests; URLs and caller envelopes confer no authority.
use crate::exec_invocation::{Envelope, Invocation};
use crate::sansio::HttpRequest;
use serde_json::{json, Value};
use whipplescript_store::{ClaimableEffect, RuntimeStore, StoreError, StoreResult};

#[derive(Clone, Debug)]
pub struct Handoff {
    selected: Invocation,
    envelope: Envelope,
    request: HttpRequest,
}

impl Handoff {
    pub fn run_id(&self) -> String {
        self.selected.run_id()
    }

    pub fn command(&self) -> Value {
        json!({"selected": self.selected, "envelope": self.envelope})
    }

    pub fn request(&self) -> &HttpRequest {
        &self.request
    }
}

/// `instance` and `effect` are the host's in-flight selection, never fields
/// extracted from an HTTP body. Recheck durable state before crossing the door.
pub fn select<S: RuntimeStore>(
    store: &S,
    instance: &str,
    effect: &ClaimableEffect,
    request: HttpRequest,
) -> StoreResult<Handoff> {
    let admission = store.effect_attempt_admission(instance, &effect.effect_id)?;
    let current = store
        .list_effects(instance)?
        .into_iter()
        .find(|row| row.effect_id == effect.effect_id)
        .ok_or_else(|| StoreError::Conflict("executor handoff effect is missing".into()))?;
    if effect.kind != "exec.command"
        || current.kind != "exec.command"
        || current.status != "running"
        || admission != effect.attempt_admission_event_id
        || serde_json::from_str::<Value>(&current.input_json)?
            != serde_json::from_str::<Value>(&effect.input_json)?
    {
        return Err(StoreError::Conflict(
            "executor handoff differs from the current selection".into(),
        ));
    }
    let selected = Invocation {
        instance_id: instance.into(),
        effect_id: effect.effect_id.clone(),
        attempt_admission_event_id: admission,
    };
    let run = store
        .list_runs(instance)?
        .into_iter()
        .find(|run| run.run_id == selected.run_id())
        .ok_or_else(|| StoreError::Conflict("executor handoff run is missing".into()))?;
    if run.effect_id != effect.effect_id
        || run.status != "running"
        || run.provider != "exec"
        || run.worker_id != "whip-exec"
    {
        return Err(StoreError::Conflict(
            "executor handoff run binding changed".into(),
        ));
    }
    let metadata: Value = serde_json::from_str(&run.metadata_json)?;
    let envelope: Envelope = serde_json::from_value(metadata["executor_invocation"].clone())?;
    let dispatch = envelope.dispatch(&selected).map_err(StoreError::Conflict)?;
    let plan = crate::exec_http::ExecDispatchPlan::load(
        store,
        instance,
        &effect.effect_id,
        &run.run_id,
        &serde_json::from_str(&current.input_json)?,
    )?;
    if dispatch != &request.body
        || plan.request_body_sha256
            != whipplescript_store::items::sha256_hex(&request.body.to_string())
        || plan.request_sha256
            != whipplescript_store::items::sha256_hex(
                &json!([request.url, request.body]).to_string(),
            )
    {
        return Err(StoreError::Conflict(
            "executor handoff differs from its retained dispatch".into(),
        ));
    }
    Ok(Handoff {
        selected,
        envelope,
        request,
    })
}

/// Reconstruct a read/reattach request from retained material, not current
/// script registration. Credentials remain ephemeral host inputs.
pub fn retained<S: RuntimeStore>(
    store: &S,
    instance: &str,
    effect: &ClaimableEffect,
    headers: Vec<(String, String)>,
) -> StoreResult<Handoff> {
    let selected = Invocation {
        instance_id: instance.into(),
        effect_id: effect.effect_id.clone(),
        attempt_admission_event_id: effect.attempt_admission_event_id.clone(),
    };
    let run = store
        .list_runs(instance)?
        .into_iter()
        .find(|run| run.run_id == selected.run_id())
        .ok_or_else(|| StoreError::Conflict("executor retained invocation is missing".into()))?;
    let metadata: Value = serde_json::from_str(&run.metadata_json)?;
    let url = metadata["executor_url"]
        .as_str()
        .ok_or_else(|| StoreError::Conflict("executor retained target is missing".into()))?
        .to_owned();
    let envelope: Envelope = serde_json::from_value(metadata["executor_invocation"].clone())?;
    let body = envelope
        .dispatch(&selected)
        .map_err(StoreError::Conflict)?
        .clone();
    let mut headers = headers;
    headers.insert(0, ("content-type".into(), "application/json".into()));
    select(
        store,
        instance,
        effect,
        HttpRequest {
            model_provenance: None,
            url,
            headers,
            body,
        },
    )
}

/// Retain request custody before the host exposes external dispatch authority.
pub fn select_tracked<S: RuntimeStore>(
    store: &mut S,
    instance: &str,
    effect: &ClaimableEffect,
    request: HttpRequest,
) -> StoreResult<Handoff> {
    let handoff = select(store, instance, effect, request)?;
    store.track_exec_lifetime(whipplescript_store::exec_lifetime::Track {
        instance_id: instance,
        effect_id: &effect.effect_id,
        run_id: &handoff.selected.run_id(),
        input_json: &effect.input_json,
        invocation_json: &serde_json::to_string(&handoff.envelope)?,
        executor_url: &handoff.request.url,
    })?;
    Ok(handoff)
}
