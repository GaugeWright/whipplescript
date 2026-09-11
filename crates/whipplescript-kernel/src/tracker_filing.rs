//! Governed execution of ordinary tracker filing effects.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_store::{
    file_settlement::TRACKER_PROVIDER,
    tracker_filing::{TrackerFiling, TrackerFilings},
    ClaimableEffect, EffectCompletion, RunStart, RuntimeStore, StoreError, StoreResult,
    StoredEvent,
};

use crate::{host_protocol::action::ActionResource, idempotency_key, RuntimeKernel};

pub const FILING_FAILURE: &str = "tracker filing did not settle successfully";

/// The host binds its facade's actual tracker store to this workspace resource.
/// These coordinates carry no authority by themselves; the facade verifies
/// their exact original binding and requires the host's current authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerBinding {
    pub scope: String,
    pub queue: String,
    pub resource: ActionResource,
}

/// Retained before target I/O. The classified title is sufficient to reconstruct
/// the original result after a receipt-proved filing, even if the item is edited.
/// The task body is not duplicated in dispatch metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilingDispatch {
    pub binding: TrackerBinding,
    pub operation_id: String,
    pub fingerprint: String,
    pub queue: String,
    pub title: String,
}

pub fn filing_operation_id(instance: &str, effect: &str) -> String {
    idempotency_key(&[instance, effect, "tracker-filing"])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilingItem {
    #[serde(default)]
    title: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    labels: Vec<String>,
    #[serde(default = "empty_metadata")]
    metadata: Value,
    #[serde(default)]
    assigned_to: Option<String>,
}

fn empty_metadata() -> Value {
    json!({})
}

pub(crate) fn request(
    instance: &str,
    effect: &ClaimableEffect,
    actor: &str,
    input: &str,
) -> StoreResult<TrackerFiling> {
    let input: Value = serde_json::from_str(input)?;
    // Credential escalation needs an additional classified continuation. It
    // cannot silently become an ordinary filing through this execution door.
    if input.get("credential").is_some() {
        return Err(StoreError::Conflict(
            "tracker filing requires an ordinary issue".into(),
        ));
    }
    let item: FilingItem = serde_json::from_value(
        input.get("item").cloned().unwrap_or_else(empty_metadata),
    )
    .map_err(|_| StoreError::Conflict("tracker filing item does not match its schema".into()))?;
    Ok(TrackerFiling {
        operation_id: filing_operation_id(instance, &effect.effect_id),
        instance_id: instance.into(),
        effect_id: effect.effect_id.clone(),
        actor: actor.into(),
        queue: effect.target.clone().unwrap_or_default(),
        title: item.title,
        body: item.body,
        labels: item.labels,
        metadata: item.metadata,
        assigned_to: item
            .assigned_to
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty()),
    })
}

pub(crate) fn run<S: RuntimeStore + TrackerFilings>(
    kernel: &mut RuntimeKernel<S>,
    instance: &str,
    effect: &ClaimableEffect,
    filing: &TrackerFiling,
    binding: &TrackerBinding,
) -> StoreResult<StoredEvent> {
    let dispatch = FilingDispatch {
        binding: binding.clone(),
        operation_id: filing.operation_id.clone(),
        fingerprint: filing.fingerprint()?,
        queue: filing.queue.clone(),
        title: filing.title.clone(),
    };
    let keys = crate::effect_handlers::local_attempt_keys(
        kernel,
        instance,
        &effect.effect_id,
        ["queue-run", "queue-lease", "queue-fact"],
    )?;
    let lease = kernel.local_effect_lease_deadline()?;
    kernel.start_dispatch_observed(
        RunStart {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &keys.run_id,
            provider: TRACKER_PROVIDER,
            worker_id: "whip-queue",
            lease_id: &keys.lease_id,
            lease_expires_at: &lease,
            metadata_json: &json!({"tracker_filing": dispatch}).to_string(),
        },
        effect,
    )?;
    let receipt = kernel.store_mut().file_issue_once(filing);
    let (status, value, metadata) = match receipt {
        Ok(receipt)
            if receipt.operation_id == dispatch.operation_id
                && receipt.fingerprint == dispatch.fingerprint
                && !receipt.item_id.trim().is_empty()
                && !receipt.event_id.trim().is_empty() =>
        {
            let value =
                json!({"queue": filing.queue, "id": receipt.item_id, "title": filing.title});
            (
                "completed",
                value.clone(),
                json!({"value": value, "filing_receipt": receipt}),
            )
        }
        _ => {
            let value = json!({"reason": FILING_FAILURE});
            (
                "failed",
                value.clone(),
                json!({"value": value,
                "failure": {"error_kind": "tracker_filing_failed", "message": FILING_FAILURE}}),
            )
        }
    };
    kernel.settle_local_run(EffectCompletion {
        instance_id: instance,
        effect_id: &effect.effect_id,
        run_id: &keys.run_id,
        provider: TRACKER_PROVIDER,
        worker_id: "whip-queue",
        status,
        exit_code: None,
        summary: None,
        metadata_json: &metadata.to_string(),
        idempotency_key: Some(&keys.terminal_key),
    }, &format!("tracker.file.{status}"),
        &json!({"effect_id": effect.effect_id, "run_id": keys.run_id, "status": status, "value": value}).to_string(),
        &keys.fact_key)
}

#[cfg(all(test, feature = "native"))]
mod tests;
