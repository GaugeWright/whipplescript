//! The fixed governed recording workflow and its synchronous target handler.
use serde_json::json;
use whipplescript_store::{
    branches::Branches, content::ContentBlobs, file_settlement::RESOLUTION_RECORDING_PROVIDER,
    vcs_resolution_recording::BoundResolutionRecording, ClaimableEffect, EffectCompletion,
    RunStart, RuntimeStore, StoreResult, StoredEvent,
};

use crate::{host_action::CompiledHostAction, idempotency_key, RuntimeKernel};

pub const RECORDING_OPERATION: &str = "resolution.record";
pub const RECORDING_FAILURE: &str = "resolution recording did not settle successfully";

const SOURCE: &str = r#"use std.vcs
workflow RecordResolutions
input corrections CorrectionReference
output result RecordingReceipt
failure error RecordingFailed
class CorrectionReference { handle string version_ref string label_ref string }
class RecordingReceipt { operation_id string receipt_hash string }
class RecordingFailed { reason string }
rule record_corrections
  when CorrectionReference as reference
=> {
  call vcs.record_resolutions for reference as recorded
  after recorded succeeds as outcome {
    complete result { operation_id outcome.operation_id receipt_hash outcome.receipt_hash }
  }
  after recorded fails as problem { fail error { reason problem.reason } }
}
"#;

/// A compiler-checked profile with no caller-supplied source or mutable IR.
/// Construct once when registering the host's operation, then reuse it.
pub struct ResolutionRecordingAction(CompiledHostAction);
impl ResolutionRecordingAction {
    pub fn compile() -> Result<Self, String> {
        CompiledHostAction::compile(RECORDING_OPERATION, SOURCE, None).map(Self)
    }

    pub fn action(&self) -> &CompiledHostAction {
        &self.0
    }
}

/// One target operation across attempts. Possessing this identity grants nothing.
pub fn recording_operation_id(instance: &str, effect: &str) -> String {
    idempotency_key(&[instance, effect, "resolution-recording"])
}

pub(crate) fn run<S: RuntimeStore, B: Branches, C: ContentBlobs>(
    kernel: &mut RuntimeKernel<S>,
    instance: &str,
    effect: &ClaimableEffect,
    target: &mut BoundResolutionRecording<B, C>,
) -> StoreResult<StoredEvent> {
    let keys = crate::effect_handlers::local_attempt_keys(
        kernel,
        instance,
        &effect.effect_id,
        ["recording-run", "recording-lease", "recording-fact"],
    )?;
    let lease = kernel.local_effect_lease_deadline()?;
    let metadata = json!({"resolution_recording": target.binding()}).to_string();
    kernel.start_dispatch_observed(
        RunStart {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &keys.run_id,
            provider: RESOLUTION_RECORDING_PROVIDER,
            worker_id: "whip-resolution-recording",
            lease_id: &keys.lease_id,
            lease_expires_at: &lease,
            metadata_json: &metadata,
        },
        effect,
    )?;
    // Dispatch retains the original binding before the first target access.
    // Backend details may contain protected material and never enter history.
    let outcome = target.record().and_then(|receipt| {
        let (_, hash) = receipt.encode()?;
        Ok(json!({"operation_id": receipt.request.operation_id, "receipt_hash": hash}))
    });
    let (status, value, metadata) = match outcome {
        Ok(value) => ("completed", value.clone(), json!({"value": value})),
        Err(_) => {
            let value = json!({"reason": RECORDING_FAILURE});
            (
                "failed",
                value.clone(),
                json!({"value": value, "failure": {
                    "error_kind": "resolution_recording_failed", "message": RECORDING_FAILURE,
                }}),
            )
        }
    };
    kernel.settle_local_run(
        EffectCompletion {
            instance_id: instance,
            effect_id: &effect.effect_id,
            run_id: &keys.run_id,
            provider: RESOLUTION_RECORDING_PROVIDER,
            worker_id: "whip-resolution-recording",
            status,
            exit_code: None,
            summary: None,
            metadata_json: &metadata.to_string(),
            idempotency_key: Some(&keys.terminal_key),
        },
        &format!("capability.call.{status}"),
        &json!({"effect_id": effect.effect_id, "run_id": keys.run_id,
            "target": effect.target, "status": status, "value": value})
        .to_string(),
        &keys.fact_key,
    )
}
