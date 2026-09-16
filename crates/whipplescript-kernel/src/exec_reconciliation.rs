//! Reconstruct reconciliation wakes from host-owned operational history.
use crate::exec_invocation::{Envelope, Invocation};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use whipplescript_store::{
    exec_reconciliation::{Schedule, EVENT_TYPE},
    ClaimableEffect, RuntimeStore, StoreError, StoreResult,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wake {
    protocol: String,
    instance_id: String,
    pub effect_id: String,
    pub run_id: String,
    scheduled_at_epoch_ms: i64,
    pub due_epoch_ms: i64,
    input: Value,
    pub invocation: Value,
}

/// Closed attempts are historical; active attempts must still match the host's
/// admission and original run envelope. List order is not used as authority.
pub fn pending<S: RuntimeStore>(store: &S, instance: &str) -> StoreResult<BTreeMap<String, Wake>> {
    let runs = store.list_runs(instance)?;
    let effects = store.list_effects(instance)?;
    let mut events = store.list_events(instance)?;
    events.sort_by_key(|event| event.sequence);
    let mut wakes = BTreeMap::new();
    for event in events
        .into_iter()
        .filter(|event| event.event_type == EVENT_TYPE)
    {
        let wake: Wake = serde_json::from_str(&event.payload_json)?;
        if wake.protocol != "whipplescript.exec.reconciliation-wake/v1"
            || wake.instance_id != instance
            || event.source != "kernel"
        {
            return Err(StoreError::Conflict(
                "untrusted exec reconciliation wake".into(),
            ));
        }
        let run = runs
            .iter()
            .find(|run| run.run_id == wake.run_id)
            .ok_or_else(|| StoreError::Conflict("exec reconciliation run is missing".into()))?;
        if run.status != "running" {
            continue;
        }
        if run.effect_id != wake.effect_id || run.provider != "exec" || run.worker_id != "whip-exec"
        {
            return Err(StoreError::Conflict(
                "exec reconciliation run binding changed".into(),
            ));
        }
        let effect = effects
            .iter()
            .find(|effect| effect.effect_id == wake.effect_id)
            .ok_or_else(|| StoreError::Conflict("exec reconciliation effect is missing".into()))?;
        if effect.status != "running" || effect.kind != "exec.command" {
            return Err(StoreError::Conflict(
                "exec reconciliation effect is not running".into(),
            ));
        }
        let selected = Invocation {
            instance_id: instance.into(),
            effect_id: wake.effect_id.clone(),
            attempt_admission_event_id: store
                .effect_attempt_admission(instance, &wake.effect_id)?,
        };
        let envelope: Envelope = serde_json::from_value(wake.invocation.clone())?;
        envelope.validate(&selected).map_err(StoreError::Conflict)?;
        if selected.run_id() != wake.run_id {
            return Err(StoreError::Conflict(
                "exec reconciliation belongs to another attempt".into(),
            ));
        }
        let input = wake.input.to_string();
        let invocation = wake.invocation.to_string();
        let schedule = Schedule {
            instance_id: instance,
            effect_id: &wake.effect_id,
            run_id: &wake.run_id,
            input_json: &input,
            invocation_json: &invocation,
            now_epoch_ms: wake.scheduled_at_epoch_ms,
            due_epoch_ms: wake.due_epoch_ms,
        };
        schedule.payload()?;
        schedule.verify_binding(&effect.input_json, &run.metadata_json)?;
        let acknowledged = store.event_by_idempotency_key(instance, &schedule.key())?;
        if acknowledged.as_ref().map(|ack| ack.event_id.as_str()) != Some(event.event_id.as_str()) {
            return Err(StoreError::Conflict(
                "exec reconciliation wake identity changed".into(),
            ));
        }
        wakes.insert(wake.run_id.clone(), wake);
    }
    Ok(wakes)
}

pub fn is_ready(
    effect: &ClaimableEffect,
    instance: &str,
    wakes: &BTreeMap<String, Wake>,
    now_epoch_ms: i64,
) -> bool {
    let run = crate::execution_attempt_key(
        instance,
        &effect.effect_id,
        effect.attempt_admission_event_id.as_deref(),
        "exec-run",
    );
    wakes
        .get(&run)
        .is_none_or(|wake| wake.due_epoch_ms <= now_epoch_ms)
}
