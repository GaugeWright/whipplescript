//! Historical batch evidence uses the original dispatch binding, never a new
//! body, current memory lookup, or caller-supplied replacement coordinates.
use super::*;
use crate::host_protocol::{
    action::ActionAdmissionReceipt,
    recovery::{EffectEvidenceVerifier, ReconcileEffectCommand, ReconciliationReceipt},
};
use crate::ifc::VerifiedEnvelope;
use serde_json::Value;
use sha2::{Digest, Sha256};
use whipplescript_store::{
    effect_recovery::{DispatchMarker, EvidenceDisposition},
    event_chain::OwnedChainEntry,
    file_settlement::RESOLUTION_RECORDING_PROVIDER,
    vcs::WorkspaceVcs,
    vcs_resolution_recording::read_committed_resolution_recording,
};

/// Trusted host registration and store mapping. Deliberately contains neither
/// a recording binding nor an input: both belong to the original dispatch.
pub struct ResolutionRecordingEvidenceSource<'a, B: Branches, C: ContentBlobs> {
    pub action: &'a ResolutionRecordingAction,
    pub admission: &'a ActionAdmissionReceipt,
    pub workspace: &'a WorkspaceVcs<B, C>,
    pub authority_ref: &'a str,
}

/// Current access to historical recording evidence is a separate authority
/// from permission to execute the original recording.
pub trait ResolutionRecordingReconciliationAuthority {
    /// Authenticate current instance-metadata access and every claim in the
    /// complete signing bytes, including the current provenance/delegation.
    fn authenticate(
        &self,
        command: &ReconcileEffectCommand,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError>;

    /// Before target I/O, authorize current receipt access under its exact
    /// label, actual store, original/current scope and path ceiling. Resolve
    /// the original opaque input version to the retained binding's hash/label
    /// using authorized historical metadata; never reload an erased body.
    /// Broader current grants or a supplied receipt cannot define that mapping.
    fn authorize(
        &self,
        command: &ReconcileEffectCommand,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        binding: &ResolutionRecordingBinding,
    ) -> Result<(), ProtocolError>;
}

#[derive(Debug)]
pub(super) struct VerifiedRecordingEvidence {
    command: ReconcileEffectCommand,
    signing: Vec<u8>,
    authorization: Vec<u8>,
    target: String,
}
impl EffectEvidenceVerifier for VerifiedRecordingEvidence {
    fn verify(
        &self,
        command: &ReconcileEffectCommand,
        signing_bytes: &[u8],
        authorization_proof: &[u8],
        target_proof: &[u8],
    ) -> Result<(), ProtocolError> {
        if command != &self.command
            || signing_bytes != self.signing
            || authorization_proof != self.authorization
            || target_proof != self.target.as_bytes()
        {
            return Err(ProtocolError::Mismatch(
                "recording verified evidence context",
            ));
        }
        Ok(())
    }
}

pub(super) fn prepare<B: Branches, C: ContentBlobs>(
    command: &ReconcileEffectCommand,
    source: &ResolutionRecordingEvidenceSource<'_, B, C>,
    prefix: &[OwnedChainEntry],
    authority: &dyn ResolutionRecordingReconciliationAuthority,
    authorization: &[u8],
    envelope: &VerifiedEnvelope,
) -> Result<VerifiedRecordingEvidence, HostFacadeError> {
    let frame = &command.evidence.frame;
    let (original, admission_index) = crate::host_action::recorded_action_command(
        source.admission,
        &command.issuer,
        &command.scope,
        prefix,
    )?;
    source.action.action().validate_command(&original)?;
    let pin = whipplescript_store::host_actions::dispatch_admission_binding(
        &source.admission.instance_ref,
        &prefix[..=admission_index],
    )
    .map_err(HostFacadeError::Store)?;
    if frame.instance_id != source.admission.instance_ref
        || frame.action_admission != pin
        || frame.kind != "capability.call"
        || frame.target.as_deref() != Some(RESOLUTION_RECORDING_CAPABILITY)
        || frame.provider != RESOLUTION_RECORDING_PROVIDER
        || command.evidence.disposition != EvidenceDisposition::Applied
        || command.evidence.authority_ref != source.authority_ref
    {
        return Err(
            ProtocolError::Mismatch("recording reconciliation scope and disposition").into(),
        );
    }
    let mut started = None;
    for event in prefix.iter().skip(admission_index + 1).filter(|event| {
        event.source.as_deref() == Some("kernel") && event.event_type == "effect.run_started"
    }) {
        let payload: Value =
            serde_json::from_str(&event.payload_json).map_err(HostFacadeError::Json)?;
        if payload.get("run_id").and_then(Value::as_str) != Some(frame.run_id.as_str()) {
            continue;
        }
        let marker: DispatchMarker = serde_json::from_value(payload["external_dispatch"].clone())
            .map_err(HostFacadeError::Json)?;
        if marker.frame != *frame || started.is_some() {
            return Err(ProtocolError::Mismatch("recording exact recorded dispatch").into());
        }
        started = Some(payload);
    }
    let Some(payload) = started else {
        return Err(ProtocolError::Mismatch("recording dispatch is unavailable").into());
    };
    let execution: ExecuteActionEffect =
        serde_json::from_value(payload["metadata"]["action_execution"]["request"].clone())
            .map_err(HostFacadeError::Json)?;
    let fingerprint = Sha256::digest(execution.signing_bytes()?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if execution.admission != *source.admission
        || execution.effect_id != frame.effect_id
        || execution.issuer != original.issuer
        || execution.scope != original.scope
        || payload["metadata"]["action_execution"]["fingerprint"] != fingerprint
    {
        return Err(ProtocolError::Mismatch("recording original executing authority").into());
    }
    let binding: ResolutionRecordingBinding =
        serde_json::from_value(payload["metadata"]["resolution_recording"].clone())
            .map_err(HostFacadeError::Json)?;
    let (input, memory) = binding_resources(&original, &execution, &binding)?;
    if command.evidence.evidence_ref != memory
        || command.evidence_label_ref != original.resources["resolutions"].label_ref
    {
        return Err(
            ProtocolError::Mismatch("recording original evidence reference and label").into(),
        );
    }
    authority.authorize(command, &original, &execution, &binding)?;
    for source in [input, memory] {
        envelope
            .check_resource_flow(source, memory)
            .map_err(HostFacadeError::PolicyRejected)?;
    }
    let receipt =
        read_committed_resolution_recording(source.workspace, &binding).map_err(|_| {
            ProtocolError::Mismatch("recording retained target evidence is unavailable")
        })?;
    let Some(receipt) = receipt else {
        return Err(ProtocolError::Mismatch("recording target has no committed result").into());
    };
    // This is the exact proof JSON. Its ordinary SHA-256 is checked by the
    // reconciliation protocol; the batch receipt's domain hash is different.
    let (target, _) = receipt.encode().map_err(HostFacadeError::Store)?;
    Ok(VerifiedRecordingEvidence {
        command: command.clone(),
        signing: command.signing_bytes()?,
        authorization: authorization.to_vec(),
        target,
    })
}

impl<S: RuntimeStore + LogAppend> GovernedHostFacade<S> {
    /// Recover only historical target evidence. This neither dispatches an
    /// effect nor changes its terminal, continuation facts or workflow state.
    pub fn reconcile_resolution_recording<B: Branches, C: ContentBlobs>(
        &mut self,
        command: ReconcileEffectCommand,
        owner_epoch: i64,
        source: &ResolutionRecordingEvidenceSource<'_, B, C>,
        authority: &dyn ResolutionRecordingReconciliationAuthority,
        proof: &[u8],
    ) -> Result<ReconciliationReceipt, HostFacadeError> {
        self.require_policy(&command.policy)?;
        authority.authenticate(&command, &command.signing_bytes()?, proof)?;
        self.require_governed(&command.evidence.evidence_ref)?;
        let prefix = self
            .kernel
            .store()
            .chain_prefix(&command.evidence.frame.instance_id)
            .map_err(HostFacadeError::Store)?;
        let verified = prepare(&command, source, &prefix, authority, proof, &self.envelope)?;
        self.reconcile_effect(
            command,
            owner_epoch,
            &verified,
            proof,
            verified.target.as_bytes(),
        )
    }
}
