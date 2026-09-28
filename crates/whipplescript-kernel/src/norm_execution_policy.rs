//! Installed evidence policy, distinct from runtime installation or admission.
use crate::exec_http::sha256_hex;
use crate::norm_buck2_execution::{VerifiedBuck2Execution, BUCK2_TESTS_ADAPTER};
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
impl ProtectedPythonPolicy {
    /// Everything but the query's policy identity, which a composed policy
    /// names for itself.
    fn admits(&self, query: &SelectionQuery, execution: &VerifiedNormExecution) -> bool {
        query.time_basis == self.time_basis
            && execution.method().runtime == self.runtime
            && execution.observation().observation_integrity
                == ObserverIntegrity::ProtectedInterpreter {}
            && execution.contract().subject.requirement == query.requirement
            && execution.contract().subject.method == execution.method().reference()
    }
}
impl ExecutionSelectionPolicy for ProtectedPythonPolicy {
    fn accepts(&self, query: &SelectionQuery, execution: &VerifiedNormExecution) -> bool {
        query.policy == self.identity && self.admits(query, execution)
    }
}

/// A host's installed evidence policy as the planner uses it: the identity a
/// query names, the host's time basis, and whether the host runs Buck2 tests
/// and so can recover and schedule them.
pub trait EvidencePolicy: ExecutionSelectionPolicy {
    fn identity(&self) -> &EvidenceVersion;
    fn time_basis(&self) -> &str;
    /// Only a native host runs Buck2. Elsewhere a Buck2 run is unavailable,
    /// an explicit gap, and never support.
    fn runs_buck2_tests(&self) -> bool {
        false
    }
}
impl EvidencePolicy for ProtectedPythonPolicy {
    fn identity(&self) -> &EvidenceVersion {
        &self.identity
    }
    fn time_basis(&self) -> &str {
        &self.time_basis
    }
}

/// Accepts Buck2 test runs, a named kind beside the protected interpreter's:
/// a run of the requirement's own template, judged against the contract
/// rebuilt from verified history. Constructed from host configuration only.
pub struct Buck2TestsPolicy {
    identity: EvidenceVersion,
    time_basis: String,
}
impl Buck2TestsPolicy {
    pub fn new(time_basis: &str) -> Result<Self, String> {
        if time_basis.trim().is_empty() {
            return Err("Buck2 evidence policy requires an explicit time basis".into());
        }
        let name = "whipplescript.norm.buck2-tests-evidence";
        let version = "1";
        Ok(Self {
            identity: EvidenceVersion {
                name: name.into(),
                version: version.into(),
                digest: sha256_hex(
                    serde_json::json!([name, version, BUCK2_TESTS_ADAPTER])
                        .to_string()
                        .as_bytes(),
                ),
            },
            time_basis: time_basis.into(),
        })
    }
    fn admits(&self, query: &SelectionQuery, execution: &VerifiedBuck2Execution) -> bool {
        query.time_basis == self.time_basis
            && execution.contract().subject.requirement == query.requirement
            && execution.contract().subject.method == execution.support().method()
    }
}
impl ExecutionSelectionPolicy for Buck2TestsPolicy {
    fn accepts(&self, _: &SelectionQuery, _: &VerifiedNormExecution) -> bool {
        false
    }
    fn accepts_buck2_tests(
        &self,
        query: &SelectionQuery,
        execution: &VerifiedBuck2Execution,
    ) -> bool {
        query.policy == self.identity && self.admits(query, execution)
    }
}
impl EvidencePolicy for Buck2TestsPolicy {
    fn identity(&self) -> &EvidenceVersion {
        &self.identity
    }
    fn time_basis(&self) -> &str {
        &self.time_basis
    }
    fn runs_buck2_tests(&self) -> bool {
        true
    }
}

/// The native host's policy: the protected interpreter's runs and Buck2
/// test runs, each accepted as its own kind, under one identity that names
/// both.
pub struct NativeEvidencePolicy {
    python: ProtectedPythonPolicy,
    buck2: Buck2TestsPolicy,
    identity: EvidenceVersion,
}
impl NativeEvidencePolicy {
    pub fn new(python: ProtectedPythonPolicy, buck2: Buck2TestsPolicy) -> Result<Self, String> {
        if python.time_basis != buck2.time_basis {
            return Err("a native evidence policy's kinds share one time basis".into());
        }
        let name = "whipplescript.norm.native-evidence";
        let version = "1";
        let identity = EvidenceVersion {
            name: name.into(),
            version: version.into(),
            digest: sha256_hex(
                serde_json::json!([name, version, python.identity, buck2.identity])
                    .to_string()
                    .as_bytes(),
            ),
        };
        Ok(Self {
            python,
            buck2,
            identity,
        })
    }
}
impl ExecutionSelectionPolicy for NativeEvidencePolicy {
    fn accepts(&self, query: &SelectionQuery, execution: &VerifiedNormExecution) -> bool {
        query.policy == self.identity && self.python.admits(query, execution)
    }
    fn accepts_buck2_tests(
        &self,
        query: &SelectionQuery,
        execution: &VerifiedBuck2Execution,
    ) -> bool {
        query.policy == self.identity && self.buck2.admits(query, execution)
    }
}
impl EvidencePolicy for NativeEvidencePolicy {
    fn identity(&self) -> &EvidenceVersion {
        &self.identity
    }
    fn time_basis(&self) -> &str {
        &self.python.time_basis
    }
    fn runs_buck2_tests(&self) -> bool {
        true
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "norm_execution_policy_tests.rs"]
mod tests;
