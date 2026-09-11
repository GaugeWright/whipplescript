//! Current authority for the standard package's bounded closure observation.
use super::*;
use crate::{
    host_action::CompiledHostAction,
    host_protocol::{
        action::HostActionCommand,
        execution::{ActionExecutionVerifier, AuthenticatedActionExecution, ExecuteActionEffect},
    },
    tracker_filing::TrackerBinding,
};
use whipplescript_store::{log_append::LogAppend, StoredEvent};

pub trait TrackerWaitAuthority: ActionExecutionVerifier {
    /// Authorize the actual workspace/store and complete classified instance
    /// before reading history, queued inputs or closure readiness facts.
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError>;

    /// Authorize the exact resolved call within the original and current
    /// tracker/input ceilings. Malformed input may be authorized to settle as
    /// an ordinary failure; it grants no additional resource access.
    fn authorize_wait(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        input: &Value,
    ) -> Result<(), ProtocolError>;
}

impl<S: RuntimeStore + LogAppend> GovernedHostFacade<S> {
    pub fn execute_tracker_wait(
        &mut self,
        request: ExecuteActionEffect,
        action: &CompiledHostAction,
        authority: &dyn TrackerWaitAuthority,
        proof: &[u8],
        binding: &TrackerBinding,
    ) -> Result<StoredEvent, HostFacadeError> {
        self.require_policy(&request.policy)?;
        let authenticated =
            AuthenticatedActionExecution::verify(request, &self.envelope, authority, proof)?;
        authority.authorize_observation(authenticated.request(), binding)?;
        let (verified, original) =
            self.prepare_authenticated_action_execution(authenticated, action, authority)?;
        let effect = verified.observed();
        if binding.scope != original.scope
            || original.resources.get(&binding.queue) != Some(&binding.resource)
            || binding.resource.resource.kind != "tracker"
            || binding.resource.resource.selector.as_deref() != Some(binding.queue.as_str())
            || !crate::tracker_wait::is_tracker_wait(effect)
            || !action
                .program()
                .trackers
                .iter()
                .any(|tracker| tracker.name == binding.queue && tracker.provider == "builtin")
        {
            return Err(ProtocolError::Mismatch("tracker wait original resource binding").into());
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
            for sink in ["result", "error"] {
                self.envelope
                    .check_resource_flow(source, sink)
                    .map_err(HostFacadeError::PolicyRejected)?;
            }
        }
        let resolved = crate::effect_handlers::resolve_effect_input_after_bindings_generic(
            self.kernel.store(),
            &verified.request().admission.instance_ref,
            effect,
        )
        .map_err(|_| ProtocolError::Invalid("tracker wait input resolution failed"))?;
        let input: Value = serde_json::from_str(&resolved)
            .map_err(|_| ProtocolError::Invalid("tracker wait input is invalid"))?;
        if input
            .pointer("/arguments/arg0/queue")
            .and_then(Value::as_str)
            .is_some_and(|queue| queue != binding.queue)
        {
            return Err(
                ProtocolError::Mismatch("tracker wait reference names another tracker").into(),
            );
        }
        authority.authorize_wait(verified.request(), &original, binding, &input)?;
        self.kernel
            .execute_verified_tracker_wait(verified)
            .map_err(HostFacadeError::Store)
    }
}
