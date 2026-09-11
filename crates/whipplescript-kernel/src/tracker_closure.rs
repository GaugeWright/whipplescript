//! Governed execution of the ordinary tracker.finish effect.
use crate::{idempotency_key, tracker_filing::TrackerBinding, RuntimeKernel};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_store::{
    tracker_closure::{TrackerClosure, TrackerClosures},
    ClaimableEffect, EffectCompletion, RunStart, RuntimeStore, StoreError, StoreResult,
    StoredEvent,
};

/// Trusted target coordinates, not an authority grant. The embedding binds the
/// actual tracker store and resolves the permanent subject under current access.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerClosureBinding {
    pub tracker: TrackerBinding,
    pub item_id: String,
    pub subject_id: String,
    /// None means the existing operator override, which the current verifier
    /// must explicitly authorize. A holder is not inferred from the executor.
    pub expected_holder: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureDispatch {
    pub binding: TrackerClosureBinding,
    pub operation_id: String,
    pub fingerprint: String,
    pub summary: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureInput {
    queue: String,
    id: String,
    #[serde(rename = "rule")]
    _rule: String,
    #[serde(default)]
    payload: ClosurePayload,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosurePayload {
    #[serde(default)]
    summary: Option<String>,
}

pub fn closing_operation_id(instance: &str, effect: &str) -> String {
    idempotency_key(&[instance, effect, "tracker-closing"])
}

pub(crate) fn request(
    instance: &str,
    effect: &ClaimableEffect,
    actor: &str,
    input: &str,
    binding: &TrackerClosureBinding,
) -> StoreResult<TrackerClosure> {
    let input: ClosureInput = serde_json::from_str(input).map_err(|_| {
        StoreError::Conflict("tracker closure input does not match its schema".into())
    })?;
    if input.queue != binding.tracker.queue || input.id != binding.item_id {
        return Err(StoreError::Conflict(
            "tracker closure input differs from its target binding".into(),
        ));
    }
    let request = TrackerClosure {
        operation_id: closing_operation_id(instance, &effect.effect_id),
        instance_id: instance.into(),
        effect_id: effect.effect_id.clone(),
        actor: actor.into(),
        queue: input.queue,
        item_id: input.id,
        subject_id: binding.subject_id.clone(),
        summary: input.payload.summary,
        expected_holder: binding.expected_holder.clone(),
    };
    request.fingerprint()?;
    Ok(request)
}

pub(crate) fn run<
    S: RuntimeStore
        + TrackerClosures
        + whipplescript_store::items::WorkItems
        + whipplescript_store::vcs::FrontierRead,
>(
    kernel: &mut RuntimeKernel<S>,
    instance: &str,
    effect: &ClaimableEffect,
    request: &TrackerClosure,
    binding: &TrackerClosureBinding,
) -> StoreResult<StoredEvent> {
    let dispatch = ClosureDispatch {
        binding: binding.clone(),
        operation_id: request.operation_id.clone(),
        fingerprint: request.fingerprint()?,
        summary: request.summary.clone(),
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
            provider: "queue",
            worker_id: "whip-queue",
            lease_id: &keys.lease_id,
            lease_expires_at: &lease,
            metadata_json: &json!({"tracker_closure": dispatch}).to_string(),
        },
        effect,
    )?;
    let outcome = kernel.store_mut().close_issue_once(request);
    let (status, value, metadata) = match outcome {
        Ok(receipt) if receipt.validate_for(request).is_ok() => {
            // Preserve the existing advisory cut-trail evidence for a claimed
            // issue, using the actual executor rather than its workflow id.
            kernel
                .store_mut()
                .set_event_effect_id(Some(&effect.effect_id));
            crate::effect_handlers::auto_attest_finish_generic(
                kernel.store_mut(),
                &request.item_id,
                Some(&request.actor),
            );
            kernel.store_mut().set_event_effect_id(None);
            let value =
                json!({"id": receipt.item_id, "status": "done", "summary": request.summary});
            (
                "completed",
                value.clone(),
                json!({"value": value, "closing_receipt": receipt}),
            )
        }
        _ => {
            let value = json!({"reason": "tracker closure did not settle successfully"});
            (
                "failed",
                value.clone(),
                json!({"value": value, "failure": {
                    "error_kind": "tracker_closure_failed", "message": "tracker closure did not settle successfully"
                }}),
            )
        }
    };
    let fact: Value = json!({"effect_id": effect.effect_id, "run_id": keys.run_id, "status": status, "value": value});
    kernel.settle_local_run(
        EffectCompletion {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &keys.run_id,
            provider: "queue",
            worker_id: "whip-queue",
            status,
            exit_code: None,
            summary: None,
            metadata_json: &metadata.to_string(),
            idempotency_key: Some(&keys.terminal_key),
        },
        &format!("tracker.finish.{status}"),
        &fact.to_string(),
        &keys.fact_key,
    )
}
