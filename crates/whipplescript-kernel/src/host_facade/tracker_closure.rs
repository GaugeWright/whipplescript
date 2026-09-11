use super::*;
use crate::{
    host_action::CompiledHostAction,
    host_protocol::{
        action::HostActionCommand,
        execution::{ActionExecutionVerifier, AuthenticatedActionExecution, ExecuteActionEffect},
    },
    tracker_closure::TrackerClosureBinding,
};
use whipplescript_store::{
    log_append::LogAppend,
    tracker_closure::{TrackerClosure, TrackerClosures},
    StoredEvent,
};

pub trait TrackerClosureAuthority: ActionExecutionVerifier {
    /// Current authority over the full retained instance evidence and the
    /// actual bound tracker, before reading history or resolving effect inputs.
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerClosureBinding,
    ) -> Result<(), ProtocolError>;
    /// Authorize the actual subject, authenticated actor and exact holder
    /// precondition inside the original resource ceiling, including the actual
    /// frontier/anchor reads and evidence append used by advisory finish attestation.
    /// Assignment is advisory
    /// and never supplies this authorization; None is an explicit override.
    fn authorize_closure(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerClosureBinding,
        closure: &TrackerClosure,
    ) -> Result<(), ProtocolError>;
}

impl<
        S: RuntimeStore
            + LogAppend
            + TrackerClosures
            + whipplescript_store::items::WorkItems
            + whipplescript_store::vcs::FrontierRead,
    > GovernedHostFacade<S>
{
    pub fn execute_tracker_closure(
        &mut self,
        request: ExecuteActionEffect,
        action: &CompiledHostAction,
        authority: &dyn TrackerClosureAuthority,
        proof: &[u8],
        binding: &TrackerClosureBinding,
    ) -> Result<StoredEvent, HostFacadeError> {
        self.require_policy(&request.policy)?;
        let authenticated =
            AuthenticatedActionExecution::verify(request, &self.envelope, authority, proof)?;
        authority.authorize_observation(authenticated.request(), binding)?;
        let (verified, original) =
            self.prepare_authenticated_action_execution(authenticated, action, authority)?;
        let effect = verified.observed();
        let tracker = &binding.tracker;
        if tracker.scope != original.scope
            || original.resources.get(&tracker.queue) != Some(&tracker.resource)
            || tracker.resource.resource.kind != "tracker"
            || tracker.resource.resource.writable != Some(true)
            || tracker.resource.resource.selector.as_deref() != Some(tracker.queue.as_str())
            || effect.kind != "tracker.finish"
            || effect.target.is_some()
            || !action
                .program()
                .trackers
                .iter()
                .any(|queue| queue.name == tracker.queue && queue.provider == "builtin")
        {
            return Err(
                ProtocolError::Mismatch("tracker closure original resource binding").into(),
            );
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
        let input = crate::effect_handlers::resolve_effect_input_after_bindings_generic(
            self.kernel.store(),
            &verified.request().admission.instance_ref,
            effect,
        )
        .map_err(|_| ProtocolError::Invalid("tracker closure input resolution failed"))?;
        let closure = crate::tracker_closure::request(
            &verified.request().admission.instance_ref,
            effect,
            &verified.request().provenance.executor,
            &input,
            binding,
        )
        .map_err(|_| ProtocolError::Invalid("tracker closure input is invalid"))?;
        authority.authorize_closure(verified.request(), &original, binding, &closure)?;
        self.kernel
            .execute_verified_tracker_closure(verified, &closure, binding)
            .map_err(HostFacadeError::Store)
    }
}
