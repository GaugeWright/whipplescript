//! Current authority and raw input-flow checks precede recording target I/O.
mod recovery;
pub use recovery::{ResolutionRecordingEvidenceSource, ResolutionRecordingReconciliationAuthority};
use serde_json::json;
use whipplescript_store::{
    branches::Branches,
    content::ContentBlobs,
    file_settlement::RESOLUTION_RECORDING_CAPABILITY,
    log_append::LogAppend,
    vcs::resolution_scope::ResolutionMemoryScope,
    vcs_resolution_recording::{BoundResolutionRecording, ResolutionRecordingBinding},
    ClaimableEffect, RuntimeStore, StoredEvent,
};

use super::{GovernedHostFacade, HostFacadeError};
use crate::{
    host_protocol::{
        action::{ActionBasis, HostActionCommand},
        execution::{ActionExecutionVerifier, ExecuteActionEffect},
        ProtocolError,
    },
    resolution_recording::{
        recording_operation_id, ResolutionRecordingAction, RECORDING_OPERATION,
    },
};

/// The host must resolve both original and current policy against the actual
/// input and workspace. This obligation cannot be met with a supplied label.
pub trait ResolutionRecordingAuthority: ActionExecutionVerifier {
    /// Verify the original opaque input version maps to `binding.input_hash()`
    /// and its label; bind the actual store, original/current path ceiling and
    /// knowledge compartment, and authorize this executor's recording. Called
    /// before target I/O. Existing receipts and broader current grants do not
    /// establish original authority. Secret proof bytes stay outside evidence.
    fn authorize_recording(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError>;
}

fn binding_resources<'a>(
    original: &'a HostActionCommand,
    request: &ExecuteActionEffect,
    binding: &ResolutionRecordingBinding,
) -> Result<(&'a str, &'a str), ProtocolError> {
    let (Some(input), Some(memory)) = (
        original.inputs.get("corrections"),
        original.resources.get("resolutions"),
    ) else {
        return Err(ProtocolError::Mismatch(
            "recording requires admitted corrections and resolutions",
        ));
    };
    let scope: Option<ResolutionMemoryScope> = memory
        .resource
        .selector
        .as_deref()
        .and_then(|value| serde_json::from_str(value).ok());
    if original.operation != RECORDING_OPERATION
        || original.inputs.len() != 1
        || original.resources.len() != 1
        || memory.resource.kind != "resolution_memory"
        || memory.resource.writable != Some(true)
        || memory.basis
            != (ActionBasis::Version {
                version_ref: binding.scope().version_ref(),
            })
        || scope.as_ref() != Some(binding.scope())
        || input.label_ref != binding.input_label()
        || input.handle == memory.resource.handle
        || binding.batch().actor != request.provenance.executor
        || binding.batch().intent != original.fingerprint()?
        || binding.batch().operation_id
            != recording_operation_id(&request.admission.instance_ref, &request.effect_id)
    {
        return Err(ProtocolError::Mismatch(
            "recording command does not bind the target adapter",
        ));
    }
    Ok((&input.handle, &memory.resource.handle))
}

fn resources<'a>(
    original: &'a HostActionCommand,
    request: &ExecuteActionEffect,
    effect: &ClaimableEffect,
    binding: &ResolutionRecordingBinding,
) -> Result<(&'a str, &'a str), ProtocolError> {
    let resources = binding_resources(original, request, binding)?;
    let input_value: serde_json::Value = serde_json::from_str(&effect.input_json)
        .map_err(|_| ProtocolError::Mismatch("recording effect reference payload"))?;
    let capabilities: Vec<String> = serde_json::from_str(&effect.required_capabilities_json)
        .map_err(|_| ProtocolError::Mismatch("recording effect capabilities"))?;
    if effect.kind != "capability.call"
        || effect.target.as_deref() != Some(RESOLUTION_RECORDING_CAPABILITY)
        || capabilities != [RESOLUTION_RECORDING_CAPABILITY]
        || input_value
            != json!({"target": RESOLUTION_RECORDING_CAPABILITY,
            "bindings": {"reference": original.inputs["corrections"]}, "rule": "record_corrections"})
    {
        return Err(ProtocolError::Mismatch(
            "recording effect differs from its admitted reference",
        ));
    }
    Ok(resources)
}

impl<S: RuntimeStore + LogAppend> GovernedHostFacade<S> {
    /// Execute the fixed recording profile with the ordinary observed-dispatch
    /// grant and atomic local settlement. The target descriptor is I/O-free.
    pub fn execute_resolution_recording<B: Branches, C: ContentBlobs>(
        &mut self,
        request: ExecuteActionEffect,
        action: &ResolutionRecordingAction,
        authority: &dyn ResolutionRecordingAuthority,
        proof: &[u8],
        target: &mut BoundResolutionRecording<B, C>,
    ) -> Result<StoredEvent, HostFacadeError> {
        let (verified, original) =
            self.prepare_action_execution(request, action.action(), authority, proof)?;
        let (input, memory) = resources(
            &original,
            verified.request(),
            verified.observed(),
            target.binding(),
        )?;
        authority.authorize_recording(
            verified.request(),
            &original,
            verified.observed(),
            target.binding(),
        )?;
        for source in [input, memory] {
            for sink in [memory, "result", "error"] {
                self.envelope
                    .check_resource_flow(source, sink)
                    .map_err(HostFacadeError::PolicyRejected)?;
            }
        }
        self.kernel
            .execute_verified_resolution_recording(verified, target)
            .map_err(HostFacadeError::Store)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests;
