//! Installed evidence policy, distinct from runtime installation or admission.
use crate::exec_http::sha256_hex;
use crate::norm_execution::VerifiedNormExecution;
use crate::norm_projection::ExecutionSelectionPolicy;
use crate::norm_runner::{ObserverIntegrity, PythonRuntime, EMBEDDED_ADAPTER};
use whipplescript_core::norm_evidence::EvidenceVersion;
use whipplescript_core::norm_selection::SelectionQuery;

/// Constructed from host-owned configuration. No deserializer or caller-chosen
/// policy identity. This is not an executor attestation or an expiry policy.
pub struct ProtectedPythonPolicy {
    runtime: PythonRuntime,
    identity: EvidenceVersion,
    time_basis: String,
}
impl ProtectedPythonPolicy {
    pub fn new(configuration: &str, time_basis: &str) -> Result<Self, String> {
        let runtime = crate::norm_runtime::parse(configuration)?;
        if time_basis.trim().is_empty() {
            return Err("protected evidence policy requires an explicit time basis".into());
        }
        let name = "whipplescript.norm.protected-python-evidence";
        let version = "1";
        let identity = EvidenceVersion {
            name: name.into(),
            version: version.into(),
            digest: sha256_hex(
                serde_json::json!([
                    name,
                    version,
                    sha256_hex(EMBEDDED_ADAPTER.as_bytes()),
                    runtime
                ])
                .to_string()
                .as_bytes(),
            ),
        };
        Ok(Self {
            runtime,
            identity,
            time_basis: time_basis.into(),
        })
    }
    pub fn identity(&self) -> &EvidenceVersion {
        &self.identity
    }
    pub fn time_basis(&self) -> &str {
        &self.time_basis
    }
}
impl ExecutionSelectionPolicy for ProtectedPythonPolicy {
    fn accepts(&self, query: &SelectionQuery, execution: &VerifiedNormExecution) -> bool {
        query.policy == self.identity
            && query.time_basis == self.time_basis
            && execution.method().runtime == self.runtime
            && execution.observation().observation_integrity
                == ObserverIntegrity::ProtectedInterpreter {}
            && execution.contract().subject.requirement == query.requirement
            && execution.contract().subject.method == execution.method().reference()
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "norm_execution_policy_tests.rs"]
mod tests;
