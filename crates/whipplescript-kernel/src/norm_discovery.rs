//! Read-only automatic method discovery from captured requirements and host
//! installation evidence. No workflow, execution, publication or ref authority.
use crate::norm_execution::PreparedNormExecution;
use crate::norm_runner::{PreparedNormRun, PythonRuntime};
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_store::norm_artifact::CapturedArtifact;
use whipplescript_store::norm_inventory::InventoryRequirement;
use whipplescript_store::ScriptCapabilityRecord;

/// `requirement` comes from the complete captured inventory. `installed` comes
/// from the host capability registry. The verifier must independently validate
/// the selected runtime against host-owned installation evidence (for example
/// the native runtime-image binding), never event-supplied permission flags.
/// It must perform read-only verification; startup remains an execution action.
pub fn discover(
    requirement: &InventoryRequirement,
    candidate: &CapturedArtifact,
    installed: &ScriptCapabilityRecord,
    verify_runtime: impl FnOnce(&PythonRuntime) -> Result<(), String>,
) -> Result<EvidenceVersion, String> {
    let (contract, method) = PreparedNormExecution::requirement_support(requirement, candidate)?;
    if contract.cases.is_empty() {
        return Err("automatic norm method requires a nonempty case contract".into());
    }
    // This local request identity is used only to validate the same runner
    // preparation as execution. No request or dispatchable value escapes.
    let runner = PreparedNormRun::prepare_from_artifact(
        contract,
        method,
        candidate,
        "method-discovery".into(),
    )?;
    runner.validate_installation(installed)?;
    verify_runtime(&runner.method().runtime)?;
    Ok(runner.method().reference())
}

#[cfg(all(test, feature = "native"))]
#[path = "norm_discovery_tests.rs"]
mod tests;
