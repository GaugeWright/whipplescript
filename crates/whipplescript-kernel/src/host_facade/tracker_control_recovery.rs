use super::*;
use crate::{
    host_action::CompiledHostAction,
    host_protocol::{
        action::HostActionCommand, execution::ExecuteActionEffect,
        tracker_recovery::RecoverTrackerControl,
    },
    tracker_control::{ControlDispatch, TrackerControlBinding},
};
use sha2::{Digest, Sha256};
use whipplescript_store::{
    effect_recovery::{fold_attempts, DispatchMarker, ExternalDisposition},
    log_append::LogAppend,
    tracker_control::{TrackerControl, TrackerControls},
    tracker_result::{TrackerControlResultDelivery, TrackerResultPublications},
    EventView, StoredEvent,
};

pub trait TrackerControlRecoveryAuthority {
    fn authenticate(
        &self,
        request: &RecoverTrackerControl,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError>;
    /// Current read access to the full retained instance evidence and the actual
    /// store/workspace mapping; runs before reading history or target receipts.
    fn authorize_observation(
        &self,
        request: &RecoverTrackerControl,
        binding: &TrackerControlBinding,
    ) -> Result<(), ProtocolError>;
    /// Current recovery and receipt access, within the original resource and
    /// input ceilings, including the actual target store. Called before receipt
    /// lookup and again immediately before result publication.
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerControl,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &ControlDispatch,
        control: &TrackerControl,
    ) -> Result<(), ProtocolError>;
}

impl<S: RuntimeStore + LogAppend + TrackerControls + TrackerResultPublications>
    GovernedHostFacade<S>
{
    pub fn recover_tracker_control(
        &mut self,
        request: RecoverTrackerControl,
        action: &CompiledHostAction,
        owner_epoch: i64,
        authority: &dyn TrackerControlRecoveryAuthority,
        proof: &[u8],
        binding: &TrackerControlBinding,
    ) -> Result<StoredEvent, HostFacadeError> {
        self.require_policy(&request.policy)?;
        let bytes = request.signing_bytes()?;
        if !self.envelope.attestation().is_some_and(|attestation| {
            attestation.epoch == Some(request.policy.epoch)
                && attestation.authority.as_deref() == Some(request.issuer.as_str())
        }) {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery signed authority and epoch",
            )
            .into());
        }
        authority.authenticate(&request, &bytes, proof)?;
        authority.authorize_observation(&request, binding)?;
        let instance = &request.admission.instance_ref;
        let prefix = self
            .kernel
            .store()
            .chain_prefix(instance)
            .map_err(HostFacadeError::Store)?;
        let head = crate::effect_reconciliation::checked_prefix(instance, &prefix)?;
        let (original, admission_index) = crate::host_action::recorded_action_command(
            &request.admission,
            &request.issuer,
            &request.scope,
            &prefix,
        )?;
        action.validate_command(&original)?;
        self.check_materialized_action_inputs(action, &original, &request.provenance.executor)?;
        self.check_program_ifc(action.program())?;
        let tracker = &binding.tracker;
        if tracker.scope != original.scope
            || original.resources.get(&tracker.queue) != Some(&tracker.resource)
            || tracker.resource.resource.kind != "tracker"
            || tracker.resource.resource.writable != Some(true)
            || tracker.resource.resource.selector.as_deref() != Some(tracker.queue.as_str())
            || !action
                .program()
                .trackers
                .iter()
                .any(|declared| declared.name == tracker.queue && declared.provider == "builtin")
        {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery original resource binding",
            )
            .into());
        }
        self.envelope
            .check_resource_binding(&tracker.queue, &tracker.resource.resource.handle)
            .map_err(HostFacadeError::PolicyRejected)?;
        for source in original
            .inputs
            .values()
            .map(|input| input.handle.as_str())
            .chain(std::iter::once(tracker.resource.resource.handle.as_str()))
        {
            for sink in [tracker.resource.resource.handle.as_str(), "result", "error"] {
                self.envelope
                    .check_resource_flow(source, sink)
                    .map_err(HostFacadeError::PolicyRejected)?;
            }
        }
        let pin = whipplescript_store::host_actions::dispatch_admission_binding(
            instance,
            &prefix[..=admission_index],
        )
        .map_err(HostFacadeError::Store)?;
        let mut started = None;
        for event in prefix.iter().filter(|event| {
            event.event_type == "effect.run_started" && event.source.as_deref() == Some("kernel")
        }) {
            let payload: Value =
                serde_json::from_str(&event.payload_json).map_err(HostFacadeError::Json)?;
            if payload["run_id"].as_str() == Some(&request.run_id) {
                if started.is_some() {
                    return Err(ProtocolError::Mismatch(
                        "tracker control recovery duplicate dispatch",
                    )
                    .into());
                }
                started = Some(payload);
            }
        }
        let payload = started.ok_or(ProtocolError::Mismatch(
            "tracker control recovery dispatch is unavailable",
        ))?;
        let marker: DispatchMarker = serde_json::from_value(payload["external_dispatch"].clone())
            .map_err(HostFacadeError::Json)?;
        let execution: ExecuteActionEffect =
            serde_json::from_value(payload["metadata"]["action_execution"]["request"].clone())
                .map_err(HostFacadeError::Json)?;
        let dispatch: ControlDispatch =
            serde_json::from_value(payload["metadata"]["tracker_control"].clone())
                .map_err(HostFacadeError::Json)?;
        let execution_digest = Sha256::digest(execution.signing_bytes()?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if marker.frame.instance_id != *instance
            || marker.frame.effect_id != request.effect_id
            || marker.frame.run_id != request.run_id
            || marker.frame.action_admission != pin
            || marker.frame.kind != "capability.call"
            || marker.frame.provider != whipplescript_store::tracker_result::CONTROL_PROVIDER
            || marker.frame.target.as_deref() != Some(dispatch.request.capability())
            || execution.admission != request.admission
            || execution.effect_id != request.effect_id
            || execution.issuer != request.issuer
            || execution.scope != request.scope
            || payload["metadata"]["action_execution"]["fingerprint"] != execution_digest
            || dispatch.binding != *binding
            || dispatch.request.operation_id
                != crate::tracker_control::control_operation_id(instance, &request.effect_id)
        {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery exact original dispatch",
            )
            .into());
        }
        let control = dispatch.request.clone();
        if control.instance_id != *instance
            || control.effect_id != request.effect_id
            || control.actor != execution.provenance.executor
            || control.queue != binding.tracker.queue
            || control.item_id != binding.item_id
            || control.subject_id != binding.subject_id
        {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery original request coordinates",
            )
            .into());
        }
        if control.fingerprint().map_err(HostFacadeError::Store)? != dispatch.fingerprint {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery original request fingerprint",
            )
            .into());
        }
        let events: Vec<_> = prefix
            .iter()
            .map(|entry| EventView {
                event_id: entry.event_id.clone(),
                sequence: entry.sequence,
                event_type: entry.event_type.clone(),
                payload_json: entry.payload_json.clone(),
                source: entry.source.clone().unwrap_or_default(),
                occurred_at: entry.occurred_at.clone(),
            })
            .collect();
        let attempts =
            fold_attempts(instance, &request.effect_id, &events).map_err(HostFacadeError::Store)?;
        // A positive receipt cannot silently settle a prior contradictory
        // investigation. Preserve that evidence for explicit resolution.
        if attempts.iter().any(|attempt| {
            attempt.run_id == request.run_id
                && (attempt.disputed || attempt.disposition == ExternalDisposition::NotApplied)
        }) {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery disputed target evidence",
            )
            .into());
        }
        authority.authorize_recovery(&request, &original, &execution, &dispatch, &control)?;
        let receipt = self
            .kernel
            .store()
            .control_receipt(&dispatch.request.operation_id)
            .map_err(|_| {
                ProtocolError::Mismatch("tracker control recovery receipt is unavailable")
            })?
            .ok_or(ProtocolError::Mismatch(
                "tracker control recovery has no committed control receipt",
            ))?;
        if receipt.validate_for(&control).is_err() {
            return Err(ProtocolError::Mismatch(
                "tracker control recovery receipt differs from dispatch",
            )
            .into());
        }
        authority.authorize_recovery(&request, &original, &execution, &dispatch, &control)?;
        let delivery = TrackerControlResultDelivery {
            control,
            run_id: request.run_id.clone(),
            control_receipt: receipt,
            fact_id: crate::idempotency_key(&[
                instance,
                "fact",
                "capability.call.succeeded",
                &request.effect_id,
            ]),
            recovery: serde_json::to_value(&request).map_err(HostFacadeError::Json)?,
        };
        self.kernel
            .store_mut()
            .publish_tracker_control_result(owner_epoch, &head.digest, &delivery)
            .map_err(HostFacadeError::Store)
    }
}
