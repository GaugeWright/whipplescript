//! Current access precedes workflow observation and actual tracker mutation.
use super::*;
use crate::{
    host_action::CompiledHostAction,
    host_protocol::{
        action::HostActionCommand,
        execution::{ActionExecutionVerifier, AuthenticatedActionExecution, ExecuteActionEffect},
    },
    tracker_filing::TrackerBinding,
};
use whipplescript_store::{
    log_append::LogAppend,
    tracker_filing::{TrackerFiling, TrackerFilings},
    StoredEvent,
};

pub trait TrackerExecutionAuthority: ActionExecutionVerifier {
    /// Called after request authentication but BEFORE reading the instance log,
    /// queued effect bodies, or wait facts. Authorize current access to the whole
    /// instance evidence under its retained classifications and bind the actual
    /// facade store to this workspace/queue. A label or supplied scope is not
    /// that mapping. This does not authorize a target mutation.
    fn authorize_observation(
        &self,
        request: &ExecuteActionEffect,
        binding: &TrackerBinding,
    ) -> Result<(), ProtocolError>;

    /// Bind the original and current resource bases to the actual tracker store,
    /// and authorize the exact filing, actor and roster-resolved assignment.
    /// Called after IFC checks and before the dispatch or any target I/O.
    fn authorize_filing(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        binding: &TrackerBinding,
        filing: &TrackerFiling,
    ) -> Result<(), ProtocolError>;
}

impl<S: RuntimeStore + LogAppend + TrackerFilings> GovernedHostFacade<S> {
    pub fn execute_tracker_filing(
        &mut self,
        request: ExecuteActionEffect,
        action: &CompiledHostAction,
        authority: &dyn TrackerExecutionAuthority,
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
            || binding.resource.resource.writable != Some(true)
            || binding.resource.resource.selector.as_deref() != Some(binding.queue.as_str())
            || effect.kind != "tracker.file"
            || effect.target.as_deref() != Some(binding.queue.as_str())
            || !action
                .program()
                .trackers
                .iter()
                .any(|tracker| tracker.name == binding.queue && tracker.provider == "builtin")
        {
            return Err(ProtocolError::Mismatch("tracker filing original resource binding").into());
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
        let input = crate::effect_handlers::resolve_effect_input_after_bindings_generic(
            self.kernel.store(),
            &verified.request().admission.instance_ref,
            effect,
        )
        .map_err(|_| ProtocolError::Invalid("tracker filing input resolution failed"))?;
        let filing = crate::tracker_filing::request(
            &verified.request().admission.instance_ref,
            effect,
            &verified.request().provenance.executor,
            &input,
        )
        .map_err(|_| ProtocolError::Invalid("tracker filing input is invalid"))?;
        authority.authorize_filing(verified.request(), &original, binding, &filing)?;
        self.kernel
            .execute_verified_tracker_filing(verified, &filing, binding)
            .map_err(HostFacadeError::Store)
    }
}
