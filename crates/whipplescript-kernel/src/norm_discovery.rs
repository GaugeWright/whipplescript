//! Read-only automatic method discovery from captured requirements and host
//! installation evidence. No workflow, execution, publication or ref authority.
use crate::norm_execution::PreparedNormExecution;
use crate::norm_runner::{PreparedNormRun, PythonRuntime};
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_store::norm_artifact::CapturedArtifact;
use whipplescript_store::norm_inventory::InventoryRequirement;
use whipplescript_store::RuntimeStore;
use whipplescript_store::ScriptCapabilityRecord;

type ObserverRead = (String, Result<Option<ScriptCapabilityRecord>, String>);
type RuntimeRead = (PythonRuntime, Result<(), String>);

/// Relevant installation reads retained privately for recapture. Only their
/// fingerprints escape in a judgment; adapter bodies and environment values do
/// not. This value cannot be deserialized into installation authority.
#[derive(Default, serde::Serialize)]
pub struct MethodInstallationCapture {
    reads: Vec<InstallationRead>,
    #[serde(skip)]
    observer: Option<ObserverRead>,
    #[serde(skip)]
    runtimes: Vec<RuntimeRead>,
}

#[derive(serde::Serialize)]
struct InstallationRead {
    kind: &'static str,
    subject: String,
    state: String,
    available: bool,
}

fn fingerprint(value: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| format!("sha256:{}", crate::exec_http::sha256_hex(&bytes)))
        .map_err(|error| error.to_string())
}

impl MethodInstallationCapture {
    pub(crate) fn revalidate<S: RuntimeStore>(
        &self,
        store: &S,
        verify_runtime: impl Fn(&PythonRuntime) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some((capability, captured)) = &self.observer {
            let current = store
                .get_script_capability(capability)
                .map_err(|error| format!("{error:?}"));
            if &current != captured {
                return Err("norm observer installation changed during derivation".into());
            }
        }
        for (runtime, captured) in &self.runtimes {
            if verify_runtime(runtime) != *captured {
                return Err("norm runtime installation changed during derivation".into());
            }
        }
        Ok(())
    }
}

/// A discovery read is captured only when selection actually needs it. Existing
/// historical support and Buck2 methods do not depend on today's Python adapter.
#[derive(Default)]
pub(crate) struct DiscoveryReads {
    observer: std::cell::RefCell<Option<ObserverRead>>,
    runtimes: std::cell::RefCell<Vec<RuntimeRead>>,
}

impl DiscoveryReads {
    pub(crate) fn discover<S: RuntimeStore>(
        &self,
        store: &S,
        capability: &str,
        requirement: &InventoryRequirement,
        candidate: &CapturedArtifact,
        verify_runtime: impl Fn(&PythonRuntime) -> Result<(), String>,
    ) -> Result<EvidenceVersion, String> {
        let mut observer = self.observer.borrow_mut();
        let (_, read) = observer.get_or_insert_with(|| {
            (
                capability.into(),
                store
                    .get_script_capability(capability)
                    .map_err(|error| format!("{error:?}")),
            )
        });
        let installed = read
            .as_ref()
            .map_err(Clone::clone)?
            .as_ref()
            .ok_or_else(|| "norm observer capability is not registered".to_owned())?;
        discover(requirement, candidate, installed, |runtime| {
            let mut reads = self.runtimes.borrow_mut();
            if let Some((_, result)) = reads.iter().find(|(profile, _)| profile == runtime) {
                return result.clone();
            }
            let result = verify_runtime(runtime);
            reads.push((runtime.clone(), result.clone()));
            result
        })
    }

    pub(crate) fn finish(self) -> Result<MethodInstallationCapture, String> {
        let observer = self.observer.into_inner();
        let runtimes = self.runtimes.into_inner();
        let mut reads = Vec::new();
        if let Some((capability, result)) = &observer {
            // Hash the complete registration, including fields whose contents
            // must remain private. Absence and read refusals are also premises.
            let state = result.as_ref().map(|record| {
                record.as_ref().map(|record| {
                    (
                        &record.name,
                        &record.argv_json,
                        &record.sha256,
                        &record.env_json,
                        record.hermetic,
                        &record.body,
                    )
                })
            });
            reads.push(InstallationRead {
                kind: "observer",
                subject: fingerprint(&("observer/1", capability))?,
                state: fingerprint(&("observer/1", state))?,
                available: matches!(result, Ok(Some(_))),
            });
        }
        for (runtime, result) in &runtimes {
            reads.push(InstallationRead {
                kind: "runtime",
                subject: fingerprint(&("runtime/1", runtime))?,
                state: fingerprint(&("runtime/1", result))?,
                available: result.is_ok(),
            });
        }
        reads
            .sort_by(|left, right| (&left.kind, &left.subject).cmp(&(&right.kind, &right.subject)));
        Ok(MethodInstallationCapture {
            reads,
            observer,
            runtimes,
        })
    }
}

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
    let (contract, method) =
        PreparedNormExecution::requirement_support(requirement, candidate.files())?;
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
