//! Typed workflow inputs admitted through immutable, governed custody.
use super::*;
use crate::host_action::CompiledHostAction;
use crate::host_protocol::action::{
    ActionAdmissionReceipt, ActionAdmissionVerifier, HostActionCommand, VerifiedActionAdmission,
};
use crate::workflow_input::{validate_workflow_start_input, workflow_input_fact_name};
use std::collections::{BTreeMap, BTreeSet};
use whipplescript_parser::IrWorkflowContractKind;
use whipplescript_store::log_append::LogAppend;

/// Trusted input-storage realization, not a workflow callback. Authentication
/// authorizes every immutable version and label before this adapter is entered.
/// Hold collection/erasure exclusion through `consume`; resolve exactly the
/// verified references, never mutable latest values. No input bytes may escape
/// into later work outside the admitted, classified workflow facts/evidence.
/// The generic result and FnOnce callback keep publication inside this scope.
pub trait ActionInputResolver {
    fn with_inputs<T>(
        &self,
        admission: &VerifiedActionAdmission,
        consume: impl FnOnce(BTreeMap<String, Value>) -> T,
    ) -> Result<T, HostFacadeError>;
}

impl<S: RuntimeStore> GovernedHostFacade<S> {
    pub(super) fn check_materialized_action_inputs(
        &self,
        action: &CompiledHostAction,
        command: &HostActionCommand,
        executor: &str,
    ) -> Result<(), HostFacadeError> {
        if !action.has_materialized_inputs() {
            return Ok(());
        }
        let contracts: Vec<_> = action
            .program()
            .workflow_contracts
            .iter()
            .filter(|contract| contract.kind == IrWorkflowContractKind::Input)
            .collect();
        let declared: BTreeSet<_> = contracts
            .iter()
            .map(|contract| contract.name.as_str())
            .collect();
        let supplied: BTreeSet<_> = command.inputs.keys().map(String::as_str).collect();
        if declared != supplied {
            return Err(ProtocolError::Mismatch("materialized workflow input names").into());
        }
        for contract in contracts {
            let input = &command.inputs[&contract.name];
            self.envelope
                .check_materialized_input(
                    &input.handle,
                    &format!("fact:{}", workflow_input_fact_name(contract)),
                    executor,
                )
                .map_err(HostFacadeError::PolicyRejected)?;
        }
        Ok(())
    }

    /// Admit unchanged typed workflow source. No resolver read occurs before
    /// all names, current authority and information flows have been checked.
    pub fn admit_action_with_inputs<R: ActionInputResolver>(
        &mut self,
        command: HostActionCommand,
        action: &CompiledHostAction,
        verifier: &dyn ActionAdmissionVerifier,
        proof: &[u8],
        resolver: &R,
    ) -> Result<ActionAdmissionReceipt, HostFacadeError>
    where
        S: LogAppend,
    {
        self.require_policy(&command.policy)?;
        let admission = VerifiedActionAdmission::verify(command, &self.envelope, verifier, proof)?;
        action.validate_command(admission.command())?;
        if !action.has_materialized_inputs() {
            return Err(
                ProtocolError::Invalid("reference workflow does not materialize inputs").into(),
            );
        }
        for resource in admission.command().resources.values() {
            self.require_governed(&resource.resource.handle)?;
        }
        self.check_materialized_action_inputs(
            action,
            admission.command(),
            &admission.command().provenance.executor,
        )?;
        self.check_program_ifc(action.program())?;
        if let Some(receipt) = self.kernel.existing_action_admission(&admission)? {
            return Ok(receipt);
        }
        resolver
            .with_inputs(&admission, |values| {
                // Even an empty declaration is closed: the legacy untyped startup
                // validator intentionally accepts arbitrary JSON in that case.
                if values.keys().collect::<BTreeSet<_>>()
                    != admission.command().inputs.keys().collect()
                {
                    return Err(ProtocolError::Mismatch("resolved workflow input names").into());
                }
                let facts = validate_workflow_start_input(action.program(), &json!(values))
                    .map_err(|_| {
                        ProtocolError::Invalid("materialized input does not match workflow schema")
                    })?;
                self.kernel
                    .admit_host_action_inputs(action, &admission, facts)
            })
            .map_err(|_| {
                HostFacadeError::Resolver("workflow input custody is unavailable".into())
            })?
    }
}

#[cfg(all(test, feature = "native"))]
mod tests;
