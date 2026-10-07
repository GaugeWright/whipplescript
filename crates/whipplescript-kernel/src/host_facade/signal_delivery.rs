//! Current authority for an admitted action's directed signal (HA-4).
//!
//! `emit signal <name> to <target>` appends a fact to ANOTHER instance, so it
//! is an external effect of the action, not a private step. The door verifies
//! the request and the exact observed effect the way the file door does, then
//! asks the host to authorize the actual delivery coordinates before the
//! handler's fresh dispatch consumes the single-use grant.
use super::*;
use crate::{
    effect_handlers::DeliveryGovernance,
    host_action::CompiledHostAction,
    host_protocol::{
        action::HostActionCommand,
        execution::{ActionExecutionVerifier, AuthenticatedActionExecution, ExecuteActionEffect},
    },
};
use whipplescript_store::{log_append::LogAppend, StoredEvent};

pub trait SignalDeliveryAuthority: ActionExecutionVerifier {
    /// Authorize delivering `signal` into `target_instance` for this exact
    /// request, within the original command's ceiling. The target and signal
    /// are read from the observed effect the grant binds, never supplied by
    /// the caller.
    fn authorize_delivery(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        target_instance: &str,
        signal: &str,
    ) -> Result<(), ProtocolError>;
}

impl<S: RuntimeStore + LogAppend> GovernedHostFacade<S> {
    /// Execute one admitted `signal.emit` under freshly verified authority.
    /// The run-start records the verified request, so the delivered fact
    /// carries the action's principal, delegation and exact observation.
    pub fn execute_action_signal_effect(
        &mut self,
        request: ExecuteActionEffect,
        action: &CompiledHostAction,
        authority: &dyn SignalDeliveryAuthority,
        proof: &[u8],
        governance: &dyn DeliveryGovernance,
    ) -> Result<StoredEvent, HostFacadeError> {
        self.require_policy(&request.policy)?;
        let authenticated =
            AuthenticatedActionExecution::verify(request, &self.envelope, authority, proof)?;
        let (verified, original) =
            self.prepare_authenticated_action_execution(authenticated, action, authority)?;
        // A non-signal effect names no delivery target and refuses here; the
        // kernel entry refuses any other kind again before dispatch.
        let input: Value =
            serde_json::from_str(&verified.observed().input_json).unwrap_or(Value::Null);
        let target = input
            .get("target_instance")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let signal = input
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if target.is_empty() || signal.is_empty() {
            return Err(ProtocolError::Invalid("signal effect names no target or signal").into());
        }
        authority.authorize_delivery(verified.request(), &original, target, signal)?;
        self.kernel
            .execute_verified_signal_effect(verified, governance)
            .map_err(HostFacadeError::Store)
    }
}
