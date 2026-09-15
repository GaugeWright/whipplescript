//! Governed principal-owned tracker controls through ordinary package calls.
use crate::{idempotency_key, tracker_filing::TrackerBinding, RuntimeKernel};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_store::{
    tracker_control::{TrackerControl, TrackerControlAction, TrackerControls},
    tracker_result::{control_value, CONTROL_PROVIDER},
    ClaimableEffect, EffectCompletion, RunStart, RuntimeStore, StoreError, StoreResult,
    StoredEvent,
};

pub fn is_control_capability(capability: &str) -> bool {
    matches!(
        capability,
        "tracker.claim" | "tracker.renew" | "tracker.release" | "tracker.assign"
    )
}
pub fn is_tracker_control(effect: &ClaimableEffect) -> bool {
    effect.kind == "capability.call" && effect.target.as_deref().is_some_and(is_control_capability)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerControlBinding {
    pub tracker: TrackerBinding,
    pub item_id: String,
    pub subject_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDispatch {
    pub binding: TrackerControlBinding,
    pub request: TrackerControl,
    pub fingerprint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseInput {
    queue: String,
    id: String,
    expires_at: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseInput {
    queue: String,
    id: String,
    expected_holder: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignInput {
    queue: String,
    id: String,
    expected_assignee: Value,
    assigned_to: Value,
}

pub fn control_operation_id(instance: &str, effect: &str) -> String {
    idempotency_key(&[instance, effect, "tracker-control"])
}

fn input_error(_: serde_json::Error) -> StoreError {
    StoreError::Conflict("tracker control input does not match its schema".into())
}
pub(crate) fn request(
    instance: &str,
    effect: &ClaimableEffect,
    actor: &str,
    input: &str,
    binding: &TrackerControlBinding,
) -> StoreResult<TrackerControl> {
    let input: Value = serde_json::from_str(input).map_err(input_error)?;
    let argument = input["arguments"]["arg0"].clone();
    let (queue, id, action) = match effect.target.as_deref() {
        Some(capability @ ("tracker.claim" | "tracker.renew")) => {
            let args: LeaseInput = serde_json::from_value(argument).map_err(input_error)?;
            let action = if capability == "tracker.claim" {
                TrackerControlAction::Claim {
                    expires_at: args.expires_at,
                }
            } else {
                TrackerControlAction::Renew {
                    expires_at: args.expires_at,
                }
            };
            (args.queue, args.id, action)
        }
        Some("tracker.release") => {
            let args: ReleaseInput = serde_json::from_value(argument).map_err(input_error)?;
            (
                args.queue,
                args.id,
                TrackerControlAction::Release {
                    expected_holder: serde_json::from_value(args.expected_holder)
                        .map_err(input_error)?,
                },
            )
        }
        Some("tracker.assign") => {
            let args: AssignInput = serde_json::from_value(argument).map_err(input_error)?;
            (
                args.queue,
                args.id,
                TrackerControlAction::Assign {
                    expected_assignee: serde_json::from_value(args.expected_assignee)
                        .map_err(input_error)?,
                    assignee: serde_json::from_value(args.assigned_to).map_err(input_error)?,
                },
            )
        }
        _ => {
            return Err(StoreError::Conflict(
                "tracker control capability is invalid".into(),
            ))
        }
    };
    if queue != binding.tracker.queue || id != binding.item_id {
        return Err(StoreError::Conflict(
            "tracker control input differs from its target binding".into(),
        ));
    }
    let request = TrackerControl {
        operation_id: control_operation_id(instance, &effect.effect_id),
        instance_id: instance.into(),
        effect_id: effect.effect_id.clone(),
        actor: actor.into(),
        queue,
        item_id: id,
        subject_id: binding.subject_id.clone(),
        action,
    };
    request.fingerprint()?;
    Ok(request)
}

pub(crate) fn run<S: RuntimeStore + TrackerControls>(
    kernel: &mut RuntimeKernel<S>,
    instance: &str,
    effect: &ClaimableEffect,
    request: &TrackerControl,
    binding: &TrackerControlBinding,
) -> StoreResult<StoredEvent> {
    let dispatch = ControlDispatch {
        binding: binding.clone(),
        request: request.clone(),
        fingerprint: request.fingerprint()?,
    };
    let keys = crate::effect_handlers::local_attempt_keys(
        kernel,
        instance,
        &effect.effect_id,
        ["capability-run", "capability-lease", "tracker-control-fact"],
    )?;
    let lease = kernel.local_effect_lease_deadline()?;
    kernel.start_dispatch_observed(
        RunStart {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &keys.run_id,
            provider: CONTROL_PROVIDER,
            worker_id: "whip-tracker-control",
            lease_id: &keys.lease_id,
            lease_expires_at: &lease,
            metadata_json: &json!({"tracker_control": dispatch}).to_string(),
        },
        effect,
    )?;
    let (status, suffix, value, metadata) = match kernel.store_mut().control_issue_once(request) {
        Ok(receipt) if receipt.validate_for(request).is_ok() => {
            let value = control_value(request, &receipt);
            (
                "completed",
                "succeeded",
                value.clone(),
                json!({"target": effect.target, "value": value, "control_receipt": receipt}),
            )
        }
        _ => {
            let value = json!({"reason": "tracker control did not settle successfully"});
            (
                "failed",
                "failed",
                value.clone(),
                json!({"target": effect.target, "value": value,
                "failure": {"error_kind": "tracker_control_failed", "message": "tracker control did not settle successfully"}}),
            )
        }
    };
    kernel.settle_local_run(
        EffectCompletion {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &keys.run_id,
            provider: CONTROL_PROVIDER,
            worker_id: "whip-tracker-control",
            status,
            exit_code: None,
            summary: None,
            metadata_json: &metadata.to_string(),
            idempotency_key: Some(&keys.terminal_key),
        },
        &format!("capability.call.{suffix}"),
        &json!({"effect_id": effect.effect_id, "run_id": keys.run_id, "target": effect.target,
            "status": status, "value": value})
        .to_string(),
        &keys.fact_key,
    )
}
