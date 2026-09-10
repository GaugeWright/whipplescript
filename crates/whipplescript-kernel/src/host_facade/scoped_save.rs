//! Scope authority and raw input flows precede every scoped adapter invocation.
use std::collections::BTreeSet;

use whipplescript_parser::{IrEffectKind, IrWorkflowContractKind};
use whipplescript_store::files::FileStore;
use whipplescript_store::log_append::LogAppend;
use whipplescript_store::vcs::resolution_scope::ResolutionMemoryScope;
use whipplescript_store::vcs_file_save::VersionedSaveBinding;
use whipplescript_store::{ClaimableEffect, RuntimeStore, StoredEvent};

use super::{GovernedHostFacade, HostFacadeError};
use crate::host_action::CompiledHostAction;
use crate::host_protocol::action::{ActionBasis, HostActionCommand};
use crate::host_protocol::execution::{ActionExecutionVerifier, ExecuteActionEffect};
use crate::host_protocol::ProtocolError;

#[cfg(all(test, feature = "native"))]
mod tests;

/// Additional authority for the registered scoped replacement profile. Legacy
/// target permission cannot authorize remembered input access implicitly.
pub trait ScopedSaveExecutionAuthority: ActionExecutionVerifier {
    /// Verify the actual descriptor against the registered program, original
    /// policy and admitted references, and current executor, path grants and
    /// knowledge compartment. Resolve opaque label references under both
    /// policies. The adapter descriptor, a receipt or today's broader grant
    /// cannot supply the missing original authority. Called before adapter I/O.
    fn authorize_scoped_save(
        &self,
        request: &ExecuteActionEffect,
        original: &HostActionCommand,
        effect: &ClaimableEffect,
        binding: &VersionedSaveBinding,
        scope: &ResolutionMemoryScope,
    ) -> Result<(), ProtocolError>;
}

struct Resources<'a> {
    memory: &'a str,
    target: &'a str,
    sinks: BTreeSet<&'a str>,
}

fn resources<'a>(
    original: &'a HostActionCommand,
    action: &'a CompiledHostAction,
    request: &ExecuteActionEffect,
    binding: &VersionedSaveBinding,
    scope: &ResolutionMemoryScope,
) -> Result<Resources<'a>, ProtocolError> {
    let (Some(input), Some(target), Some(memory)) = (
        original.inputs.get("content"),
        original.resources.get("target"),
        original.resources.get("resolutions"),
    ) else {
        return Err(ProtocolError::Mismatch(
            "scoped save requires admitted draft, target and resolutions",
        ));
    };
    let admitted_scope: Option<ResolutionMemoryScope> = memory
        .resource
        .selector
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok());
    if original.operation != "file.save"
        || target.resource.kind != "file_store"
        || target.resource.writable != Some(true)
        || target.basis
            != (ActionBasis::Version {
                version_ref: binding.base_cut_id.clone(),
            })
        || target.label_ref != binding.evidence_label
        || input.label_ref != binding.input_label
        || request.provenance.executor != binding.executing_principal
        || memory.resource.kind != "resolution_memory"
        || memory.resource.writable != Some(false)
        || memory.basis
            != (ActionBasis::Version {
                version_ref: scope.version_ref(),
            })
        || admitted_scope.as_ref() != Some(scope)
        || memory.resource.handle == target.resource.handle
        || memory.resource.handle == input.handle
    {
        return Err(ProtocolError::Mismatch(
            "scoped save command does not bind the adapter",
        ));
    }

    // This door owns the confined replacement profile. No unexamined effect,
    // durable fact or milestone can become a new sink for its implicit inputs.
    let program = action.program();
    let unsupported = program.rules.iter().any(|rule| {
        !rule.metadata.fact_writes.is_empty()
            || !rule.metadata.milestone_field_reads.is_empty()
            || rule.metadata.effects.iter().any(|effect| {
                !effect.access_grants.is_empty()
                    || match effect.kind {
                        IrEffectKind::FileRead => {
                            effect.resource.as_deref() != Some(input.handle.as_str())
                        }
                        IrEffectKind::FileWrite => {
                            effect.resource.as_deref() != Some(target.resource.handle.as_str())
                        }
                        _ => true,
                    }
            })
    });
    if unsupported {
        return Err(ProtocolError::Mismatch(
            "scoped save requires the confined replacement profile",
        ));
    }
    let mut sinks = BTreeSet::from([target.resource.handle.as_str()]);
    sinks.extend(
        program
            .workflow_contracts
            .iter()
            .filter(|port| {
                matches!(
                    port.kind,
                    IrWorkflowContractKind::Output | IrWorkflowContractKind::Failure
                )
            })
            .map(|port| port.name.as_str()),
    );
    Ok(Resources {
        memory: &memory.resource.handle,
        target: &target.resource.handle,
        sinks,
    })
}

impl<S: RuntimeStore + LogAppend> GovernedHostFacade<S> {
    /// Enter a confined scoped-save adapter only after ordinary execution
    /// authority, original scope binding, current scope access and both-axis
    /// flows from remembered and existing target inputs have been checked.
    /// Uses the ordinary single-use dispatch grant and file settlement path.
    pub fn execute_scoped_save_file_effect(
        &mut self,
        request: ExecuteActionEffect,
        action: &CompiledHostAction,
        authority: &dyn ScopedSaveExecutionAuthority,
        proof: &[u8],
        files: &dyn FileStore,
    ) -> Result<StoredEvent, HostFacadeError> {
        let (verified, original) =
            self.prepare_action_execution(request, action, authority, proof)?;
        let (binding, scope) = files.scoped_save_binding().ok_or(ProtocolError::Mismatch(
            "scoped save execution requires a scoped adapter",
        ))?;
        let resources = resources(&original, action, verified.request(), binding, scope)?;
        authority.authorize_scoped_save(
            verified.request(),
            &original,
            verified.observed(),
            binding,
            scope,
        )?;
        for source in [resources.memory, resources.target] {
            for sink in &resources.sinks {
                self.envelope
                    .check_resource_flow(source, sink)
                    .map_err(HostFacadeError::PolicyRejected)?;
            }
        }
        self.kernel
            .execute_verified_file_effect(verified, files)
            .map_err(HostFacadeError::Store)
    }
}
