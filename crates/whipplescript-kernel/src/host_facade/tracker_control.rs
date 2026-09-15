use super::*;
use crate::{
    host_action::CompiledHostAction,
    host_protocol::{
        action::HostActionCommand,
        execution::{ActionExecutionVerifier, AuthenticatedActionExecution, ExecuteActionEffect},
    },
    tracker_control::TrackerControlBinding,
};
use whipplescript_store::{
    log_append::LogAppend,
    tracker_control::{TrackerControl, TrackerControlAction, TrackerControls},
    StoredEvent,
};

pub trait TrackerControlAuthority: ActionExecutionVerifier {
    /// Current access to the complete classified instance and actual tracker
    /// store mapping, before reading history, resolving input or inspecting tasks.
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerControlBinding,
    ) -> Result<(), ProtocolError>;
    /// Current mutation rights, original resource/input ceilings, actual actor,
    /// expected holder (including any explicit override), and roster-resolved
    /// recipient readability. Assignment never grants recipient access.
    fn authorize_control(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerControlBinding,
        control: &TrackerControl,
    ) -> Result<(), ProtocolError>;
}
impl<S: RuntimeStore + LogAppend + TrackerControls> GovernedHostFacade<S> {
    pub fn execute_tracker_control(
        &mut self,
        request: ExecuteActionEffect,
        action: &CompiledHostAction,
        authority: &dyn TrackerControlAuthority,
        proof: &[u8],
        binding: &TrackerControlBinding,
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
            || !crate::tracker_control::is_tracker_control(effect)
            || !action
                .program()
                .trackers
                .iter()
                .any(|queue| queue.name == tracker.queue && queue.provider == "builtin")
        {
            return Err(
                ProtocolError::Mismatch("tracker control original resource binding").into(),
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
        .map_err(|_| ProtocolError::Invalid("tracker control input resolution failed"))?;
        let control = crate::tracker_control::request(
            &verified.request().admission.instance_ref,
            effect,
            &verified.request().provenance.executor,
            &input,
            binding,
        )
        .map_err(|_| ProtocolError::Invalid("tracker control input is invalid"))?;
        if let TrackerControlAction::Assign {
            assignee: Some(recipient),
            ..
        } = &control.action
        {
            self.envelope
                .check_resource_reader(&tracker.resource.resource.handle, recipient)
                .map_err(HostFacadeError::PolicyRejected)?;
        }
        authority.authorize_control(verified.request(), &original, binding, &control)?;
        self.kernel
            .execute_verified_tracker_control(verified, &control, binding)
            .map_err(HostFacadeError::Store)
    }
}
