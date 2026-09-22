//! The Buck2 test executor's report (DR-0124 §14.5), protocol
//! `whipplescript.norm.buck2-test-support/v1`.
//!
//! Written by the executor that Buck2 calls, read by the kernel's adapter
//! that turns it into a `TestReport` for `norm_evidence`. It records what the
//! executor observed through Buck2's orchestrator — which suites Buck2 handed
//! it, what each listing found, and every execution with its status, exit
//! code, verdict line, timing, execution kind and output digests — and
//! nothing it decided: adequacy is the norm plane's judgment, not the
//! executor's. A suite whose test type has no listing adapter says so rather
//! than inventing an exercised count.

use serde::{Deserialize, Serialize};

pub const BUCK2_TEST_SUPPORT_PROTOCOL: &str = "whipplescript.norm.buck2-test-support/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Buck2TestReport {
    pub protocol: String,
    /// The workspace cut the wrapper named when it ran the tests, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cut: Option<String>,
    /// The user Buck2 reported as the invoker, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executor_user: Option<String>,
    /// Buck2's trace id for the invocation: the key into its event log,
    /// where every execution this report names is recorded by Buck2 itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// The `--config-entry` values Buck2 passed the executor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_entries: Vec<String>,
    pub suites: Vec<SuiteReport>,
    /// The exit code the executor returned to Buck2: a presentation, not
    /// evidence.
    pub exit_code: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteTarget {
    pub cell: String,
    pub package: String,
    pub target: String,
    pub configuration: String,
}

impl SuiteTarget {
    pub fn label(&self) -> String {
        format!("{}//{}:{}", self.cell, self.package, self.target)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteReport {
    pub target: SuiteTarget,
    pub test_type: String,
    pub labels: Vec<String>,
    pub listing: Listing,
    pub executions: Vec<CaseExecution>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Listing {
    /// The adapter listed the suite's cases through a listing execution.
    Listed { cases: Vec<String>, cacheable: bool },
    /// The listing execution did not produce a case list.
    ListingFailed { reason: String },
    /// No adapter knows this test type; the suite ran once as one command.
    MissingAdapter { test_type: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Pass,
    Fail,
    Timeout,
    /// The process ended without a verdict the adapter could read.
    Unknown,
    /// Buck2 cancelled the execution.
    Omitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionKind {
    Local,
    Remote,
    OmittedLocal,
    WorkerInit,
    Worker,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseExecution {
    /// The case name, or the suite's label when the suite ran as one command.
    pub case: String,
    pub status: CaseStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Whether the adapter read a verdict line for this case, as distinct
    /// from inferring a status from the exit code.
    pub verdict_line: bool,
    pub start_time_ms: u64,
    pub duration_ms: u64,
    pub execution_kind: ExecutionKind,
    /// SHA-256 of the captured streams, so a witness can name what was read.
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_used_bytes: Option<u64>,
}
