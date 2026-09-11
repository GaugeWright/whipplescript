use super::*;
use crate::{
    host_action::CompiledHostAction,
    host_protocol::{
        action::HostActionCommand, execution::ExecuteActionEffect,
        tracker_recovery::RecoverTrackerFiling,
    },
    tracker_filing::{FilingDispatch, TrackerBinding},
};
use sha2::{Digest, Sha256};
use whipplescript_store::{
    effect_recovery::{fold_attempts, DispatchMarker, ExternalDisposition},
    log_append::LogAppend,
    tracker_filing::TrackerFilings,
    tracker_result::{TrackerResultDelivery, TrackerResultPublications},
    EventView, StoredEvent,
};

pub trait TrackerRecoveryAuthority {
    fn authenticate(
        &self,
        request: &RecoverTrackerFiling,
        signing_bytes: &[u8],
        proof: &[u8],
    ) -> Result<(), ProtocolError>;
    /// Current read access to the full retained instance evidence and the actual
    /// store/workspace mapping; runs before reading history or target receipts.
    fn authorize_observation(
        &self,
        request: &RecoverTrackerFiling,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError>;
    /// Current recovery and receipt access, within the original resource and
    /// input ceilings, including the actual target store. Called before receipt
    /// lookup and again immediately before result publication.
    fn authorize_recovery(
        &self,
        request: &RecoverTrackerFiling,
        original: &HostActionCommand,
        execution: &ExecuteActionEffect,
        dispatch: &FilingDispatch,
    ) -> Result<(), ProtocolError>;
}

impl<S: RuntimeStore + LogAppend + TrackerFilings + TrackerResultPublications>
    GovernedHostFacade<S>
{
    pub fn recover_tracker_filing(
        &mut self,
        request: RecoverTrackerFiling,
        action: &CompiledHostAction,
        owner_epoch: i64,
        authority: &dyn TrackerRecoveryAuthority,
        proof: &[u8],
        binding: &TrackerBinding,
    ) -> Result<StoredEvent, HostFacadeError> {
        self.require_policy(&request.policy)?;
        let bytes = request.signing_bytes()?;
        if !self.envelope.attestation().is_some_and(|attestation| {
            attestation.epoch == Some(request.policy.epoch)
                && attestation.authority.as_deref() == Some(request.issuer.as_str())
        }) {
            return Err(
                ProtocolError::Mismatch("tracker recovery signed authority and epoch").into(),
            );
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
        if binding.scope != original.scope
            || original.resources.get(&binding.queue) != Some(&binding.resource)
            || binding.resource.resource.kind != "tracker"
            || binding.resource.resource.writable != Some(true)
            || binding.resource.resource.selector.as_deref() != Some(binding.queue.as_str())
            || !action
                .program()
                .trackers
                .iter()
                .any(|tracker| tracker.name == binding.queue && tracker.provider == "builtin")
        {
            return Err(
                ProtocolError::Mismatch("tracker recovery original resource binding").into(),
            );
        }
        self.envelope
            .check_resource_binding(&binding.queue, &binding.resource.resource.handle)
            .map_err(HostFacadeError::PolicyRejected)?;
        for source in original
            .inputs
            .values()
            .map(|input| input.handle.as_str())
            .chain(std::iter::once(binding.resource.resource.handle.as_str()))
        {
            for sink in [binding.resource.resource.handle.as_str(), "result", "error"] {
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
                    return Err(
                        ProtocolError::Mismatch("tracker recovery duplicate dispatch").into(),
                    );
                }
                started = Some(payload);
            }
        }
        let payload = started.ok_or(ProtocolError::Mismatch(
            "tracker recovery dispatch is unavailable",
        ))?;
        let marker: DispatchMarker = serde_json::from_value(payload["external_dispatch"].clone())
            .map_err(HostFacadeError::Json)?;
        let execution: ExecuteActionEffect =
            serde_json::from_value(payload["metadata"]["action_execution"]["request"].clone())
                .map_err(HostFacadeError::Json)?;
        let dispatch: FilingDispatch =
            serde_json::from_value(payload["metadata"]["tracker_filing"].clone())
                .map_err(HostFacadeError::Json)?;
        let execution_digest = Sha256::digest(execution.signing_bytes()?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        if marker.frame.instance_id != *instance
            || marker.frame.effect_id != request.effect_id
            || marker.frame.run_id != request.run_id
            || marker.frame.action_admission != pin
            || marker.frame.kind != "tracker.file"
            || marker.frame.provider != "queue"
            || marker.frame.target.as_deref() != Some(binding.queue.as_str())
            || execution.admission != request.admission
            || execution.effect_id != request.effect_id
            || execution.issuer != request.issuer
            || execution.scope != request.scope
            || payload["metadata"]["action_execution"]["fingerprint"] != execution_digest
            || dispatch.binding != *binding
            || dispatch.queue != binding.queue
            || dispatch.operation_id
                != crate::tracker_filing::filing_operation_id(instance, &request.effect_id)
        {
            return Err(ProtocolError::Mismatch("tracker recovery exact original dispatch").into());
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
            return Err(
                ProtocolError::Mismatch("tracker recovery disputed target evidence").into(),
            );
        }
        authority.authorize_recovery(&request, &original, &execution, &dispatch)?;
        let receipt = self
            .kernel
            .store()
            .filing_receipt(&dispatch.operation_id)
            .map_err(|_| ProtocolError::Mismatch("tracker recovery receipt is unavailable"))?
            .ok_or(ProtocolError::Mismatch(
                "tracker recovery has no committed filing receipt",
            ))?;
        if receipt.operation_id != dispatch.operation_id
            || receipt.fingerprint != dispatch.fingerprint
            || receipt.item_id.trim().is_empty()
            || receipt.event_id.trim().is_empty()
        {
            return Err(
                ProtocolError::Mismatch("tracker recovery receipt differs from dispatch").into(),
            );
        }
        authority.authorize_recovery(&request, &original, &execution, &dispatch)?;
        let delivery = TrackerResultDelivery {
            instance_id: instance.clone(),
            effect_id: request.effect_id.clone(),
            run_id: request.run_id.clone(),
            queue: dispatch.queue,
            title: dispatch.title,
            filing_receipt: receipt,
            fact_id: crate::idempotency_key(&[
                instance,
                "fact",
                "tracker.file.completed",
                &request.effect_id,
            ]),
            recovery: serde_json::to_value(&request).map_err(HostFacadeError::Json)?,
        };
        self.kernel
            .store_mut()
            .publish_tracker_result(owner_epoch, &head.digest, &delivery)
            .map_err(HostFacadeError::Store)
    }
}
