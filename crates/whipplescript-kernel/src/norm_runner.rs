//! N1's first real runner adapter over the existing executor boundary.
//!
//! Preparation pins the method and materialized candidate. Finish MUST receive
//! the response to that prepared request over the host's authenticated executor
//! connection, never an arbitrary caller's uploaded response. Runtime/environment
//! integrity is an observer assumption; this adapter establishes no reuse closure.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use whipplescript_core::norm_evidence::{
    evaluate_report, ArtifactProvenance, AssertionObservation, EvidenceVersion, ProcessTermination,
    ReportCompletion, ReportContract, ReportVerifier, TestJudgment, TestReport,
};

use crate::exec_http::{
    build_executor_exec_request, sha256_hex, EXECUTOR_PROTOCOL, SCRIPT_ARGV_PLACEHOLDER,
};
use crate::sansio::{HttpRequest, HttpResponse};

/// Part of the prepared request body, shared by hosted reconstruction.
pub const PYTHON_CALLS_TIMEOUT_MS: u64 = 30_000;

pub const PYTHON_CALLS_PROTOCOL: &str = "whipplescript.norm.python-calls/v1";
const ADAPTER: &str = include_str!("norm_python_calls.py");
pub const EMBEDDED_ADAPTER: &str = include_str!("norm_embedded_calls.py");
pub const EMBEDDED_CALLS_PROTOCOL: &str = "whipplescript.norm.python-calls/v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PythonEngine {
    Cpython {},
    Cpython3147Wasi {
        artifact_path: String,
        artifact_sha256: String,
    },
}
impl Default for PythonEngine {
    fn default() -> Self {
        Self::Cpython {}
    }
}
impl PythonEngine {
    fn is_cpython(&self) -> bool {
        matches!(self, Self::Cpython {})
    }
}

/// Host-owned immutable runtime profile. Environment identifies the executor
/// deployment, not an environment label the candidate may choose. Python's
/// reported version is also checked; this is not a full toolchain measurement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonRuntime {
    #[serde(default, skip_serializing_if = "PythonEngine::is_cpython")]
    pub engine: PythonEngine,
    pub executable: String,
    pub python_version: String,
    pub environment: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonCase {
    pub id: String,
    pub args: Vec<Value>,
    pub kwargs: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonCallMethod {
    pub runtime: PythonRuntime,
    pub module: String,
    pub function: String,
    pub cases: Vec<PythonCase>,
}

impl PythonCallMethod {
    pub fn protocol(&self) -> &'static str {
        match self.runtime.engine {
            PythonEngine::Cpython {} => PYTHON_CALLS_PROTOCOL,
            PythonEngine::Cpython3147Wasi { .. } => EMBEDDED_CALLS_PROTOCOL,
        }
    }
    pub fn adapter(&self) -> &'static str {
        match self.runtime.engine {
            PythonEngine::Cpython {} => ADAPTER,
            PythonEngine::Cpython3147Wasi { .. } => EMBEDDED_ADAPTER,
        }
    }

    /// Pins adapter bytes, runtime profile, entry point, and all case inputs.
    pub fn reference(&self) -> EvidenceVersion {
        EvidenceVersion {
            name: "python-calls".into(),
            version: if self.runtime.engine.is_cpython() {
                "1"
            } else {
                "2"
            }
            .into(),
            digest: sha256_hex(
                json!([self.protocol(), sha256_hex(self.adapter().as_bytes()), self])
                    .to_string()
                    .as_bytes(),
            ),
        }
    }
}

/// Identity of every UTF-8 file staged for this run, including membership.
/// This is the candidate boundary, not an assertion that external reads cannot
/// happen. Paths are validated separately before materialization.
pub fn candidate_identity(files: &BTreeMap<String, String>) -> String {
    sha256_hex(
        json!(["whipplescript.norm.candidate/v1", files])
            .to_string()
            .as_bytes(),
    )
}

#[derive(Clone, Debug)]
pub struct PreparedNormRun {
    contract: ReportContract,
    method: PythonCallMethod,
    files: BTreeMap<String, String>,
    run_id: String,
    source: Option<whipplescript_store::norm_artifact::ArtifactBasis>,
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}

impl PreparedNormRun {
    /// Production store composition: the candidate files come from a complete
    /// verified cut capture. This does not certify the execution observer.
    pub fn prepare_from_artifact(
        contract: ReportContract,
        method: PythonCallMethod,
        artifact: &whipplescript_store::norm_artifact::CapturedArtifact,
        run_id: String,
    ) -> Result<Self, String> {
        let mut prepared = Self::prepare(contract, method, artifact.files().clone(), run_id)?;
        prepared.source = Some(artifact.basis().clone());
        Ok(prepared)
    }

    /// Shared by enqueue preparation and read-only automatic method discovery.
    pub(crate) fn validate_installation(
        &self,
        installed: &whipplescript_store::ScriptCapabilityRecord,
    ) -> Result<(), String> {
        if installed.name.trim().is_empty() {
            return Err("norm installation requires a capability identity".into());
        }
        let request = self.executor_request("https://norm-installation.invalid")?;
        if installed.hermetic
            || request.body["script_b64"]
                != crate::exec_http::base64_encode(installed.body.as_bytes())
            || request.body["script_sha256"] != installed.sha256
        {
            return Err(
                "norm installed script must match the adapter and disable unverified reuse".into(),
            );
        }
        let argv: Vec<String> = serde_json::from_str(&installed.argv_json)
            .map_err(|e| format!("invalid norm script argv: {e}"))?;
        let env: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&installed.env_json)
                .map_err(|e| format!("invalid norm script environment: {e}"))?;
        if json!(argv) != request.body["argv"] || !env.is_empty() {
            return Err("norm installed invocation differs from the declared method".into());
        }
        Ok(())
    }

    pub(crate) fn method(&self) -> &PythonCallMethod {
        &self.method
    }

    pub(crate) fn contract(&self) -> &ReportContract {
        &self.contract
    }

    pub fn source(&self) -> Option<&whipplescript_store::norm_artifact::ArtifactBasis> {
        self.source.as_ref()
    }

    pub fn prepare(
        contract: ReportContract,
        method: PythonCallMethod,
        files: BTreeMap<String, String>,
        run_id: String,
    ) -> Result<Self, String> {
        if run_id.trim().is_empty() {
            return Err("norm run requires a nonempty invocation identity".into());
        }
        if contract.subject.method != method.reference() {
            return Err("norm run method differs from its installed contract".into());
        }
        if contract.subject.artifact != candidate_identity(&files) {
            return Err("norm run candidate differs from its installed contract".into());
        }
        let runtime = &method.runtime;
        let runtime_incomplete = [
            &runtime.executable,
            &runtime.python_version,
            &runtime.environment,
        ]
        .into_iter()
        .any(|v| v.trim().is_empty());
        if runtime_incomplete {
            return Err("norm run requires a complete trusted runtime profile".into());
        }
        if let PythonEngine::Cpython3147Wasi {
            artifact_path,
            artifact_sha256,
        } = &runtime.engine
        {
            if artifact_path.trim().is_empty()
                || artifact_path.contains('\0')
                || artifact_sha256.len() != 64
                || !artifact_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || runtime.python_version != "3.14.7"
            {
                return Err(
                    "norm WASI runtime requires an artifact path, SHA-256 and Python 3.14.7".into(),
                );
            }
        }
        if !method.module.split('.').all(identifier) || !identifier(&method.function) {
            return Err("norm Python entry point must name a module and function".into());
        }
        for path in files.keys() {
            if path.contains('\\')
                || path.contains(':')
                || path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return Err("norm candidate paths must stay within their materialization".into());
            }
        }
        let module_path = method.module.replace('.', "/");
        let module_files = [
            format!("{module_path}.py"),
            format!("{module_path}/__init__.py"),
        ];
        if module_files
            .iter()
            .filter(|path| files.contains_key(*path))
            .count()
            != 1
        {
            return Err(
                "norm Python entry point must identify exactly one candidate module".into(),
            );
        }
        let required: BTreeSet<_> = contract.cases.iter().map(|case| &case.id).collect();
        let supplied: BTreeSet<_> = method.cases.iter().map(|case| &case.id).collect();
        if required != supplied
            || required.len() != contract.cases.len()
            || supplied.len() != method.cases.len()
        {
            return Err(
                "norm runner cases must match the complete unique contract inventory".into(),
            );
        }
        if contract
            .cases
            .iter()
            .any(|case| case.id.trim().is_empty() || case.assertion.trim().is_empty())
        {
            return Err("norm runner cases require an identity and assertion".into());
        }
        Ok(Self {
            contract,
            method,
            files,
            run_id,
            source: None,
        })
    }

    /// The host attaches its existing executor authentication. No result cache
    /// is consulted: this adapter has not established sound dependency reuse.
    pub fn executor_request(&self, executor_url: &str) -> Result<HttpRequest, String> {
        let argv = match self.method.runtime.engine {
            PythonEngine::Cpython {} => vec![
                self.method.runtime.executable.clone(),
                "-I".into(),
                SCRIPT_ARGV_PLACEHOLDER.into(),
            ],
            PythonEngine::Cpython3147Wasi { .. } => vec![
                self.method.runtime.executable.clone(),
                "executor".into(),
                "observe-norm".into(),
                SCRIPT_ARGV_PLACEHOLDER.into(),
            ],
        };
        build_executor_exec_request(
            executor_url,
            &self.run_id,
            &sha256_hex(self.method.adapter().as_bytes()),
            self.method.adapter(),
            &argv,
            &[],
            &json!({
                "run_id": self.run_id,
                "method_definition_json": serde_json::to_value(&self.method).expect("serializable Python method").to_string(),
                "files": self.files,
                "contract_json": serde_json::to_value(&self.contract).expect("serializable report contract").to_string(),
            }),
            Some(PYTHON_CALLS_TIMEOUT_MS),
        )
    }

    fn contract_digest(&self) -> String {
        sha256_hex(
            serde_json::to_value(&self.contract)
                .expect("serializable report contract")
                .to_string()
                .as_bytes(),
        )
    }

    /// Normalize actual process evidence. Unlike generic exec decoding, every
    /// truncation/timeout field is required, and the invocation id must match.
    pub fn finish(&self, response: &HttpResponse) -> Result<RunnerObservation, String> {
        if response.status != 200 {
            return Err(format!("norm executor returned HTTP {}", response.status));
        }
        if response.body.get("protocol").and_then(Value::as_str) != Some(EXECUTOR_PROTOCOL)
            || response.body.get("effect_id").and_then(Value::as_str) != Some(self.run_id.as_str())
        {
            return Err("norm executor receipt differs from its prepared invocation".into());
        }
        let mut diagnostics = Vec::new();
        let stdout = response.body.get("stdout").and_then(Value::as_str);
        let stderr = response.body.get("stderr").and_then(Value::as_str);
        let stdout_truncated = response
            .body
            .get("stdout_truncated")
            .and_then(Value::as_bool);
        let stderr_truncated = response
            .body
            .get("stderr_truncated")
            .and_then(Value::as_bool);
        let timed_out = response.body.get("timed_out").and_then(Value::as_bool);
        let exit_code = response.body.get("exit_code").and_then(Value::as_i64);
        for (field, present) in [
            ("stdout", stdout.is_some()),
            ("stderr", stderr.is_some()),
            ("stdout_truncated", stdout_truncated.is_some()),
            ("stderr_truncated", stderr_truncated.is_some()),
            ("timed_out", timed_out.is_some()),
            ("exit_code", exit_code.is_some()),
        ] {
            if !present {
                diagnostics.push(format!("missing or invalid executor field {field}"));
            }
        }
        let stdout = stdout.unwrap_or_default();
        let mut observed_header = None;
        let mut bound = false;
        let mut started = false;
        let mut complete = false;
        let mut observations = Vec::new();
        for line in stdout.lines() {
            let event: AdapterEvent = match serde_json::from_str(line) {
                Ok(event) => event,
                Err(error) => {
                    diagnostics.push(format!("invalid adapter event: {error}"));
                    continue;
                }
            };
            match event {
                AdapterEvent::Started(header) => {
                    if started || complete {
                        diagnostics.push("repeated adapter header".to_owned());
                        continue;
                    }
                    started = true;
                    bound = header.protocol == self.method.protocol()
                        && header.run_id == self.run_id
                        && header.contract_digest == self.contract_digest()
                        && header.requirement == self.contract.subject.requirement
                        && header.artifact == self.contract.subject.artifact
                        && header.method == self.contract.subject.method
                        && header.environment == self.method.runtime.environment
                        && header.adapter_digest == sha256_hex(self.method.adapter().as_bytes())
                        && header.python_version == self.method.runtime.python_version;
                    if !bound {
                        diagnostics.push(
                            "adapter header differs from the prepared run or runtime".to_owned(),
                        );
                    }
                    observed_header = Some(*header);
                }
                AdapterEvent::Case {
                    case,
                    assertion,
                    actual,
                } => {
                    if !started || complete {
                        diagnostics.push("case observation outside the adapter run".to_owned());
                        continue;
                    }
                    let witness = sha256_hex(
                        json!([
                            self.method.protocol(),
                            &observed_header,
                            case,
                            assertion,
                            actual
                        ])
                        .to_string()
                        .as_bytes(),
                    );
                    observations.push(AssertionObservation {
                        case,
                        assertion,
                        actual,
                        witness,
                    });
                }
                AdapterEvent::Error { case, message } => {
                    diagnostics.push(format!("adapter case {case:?}: {message}"));
                }
                AdapterEvent::Complete {} => {
                    if !started || complete {
                        diagnostics.push("completion outside the adapter run".to_owned());
                    }
                    complete = true;
                }
            }
        }
        if !started {
            diagnostics.push("missing adapter header".to_owned());
        }
        if !complete {
            diagnostics.push("missing adapter completion".to_owned());
        }
        let truncated = stdout_truncated.unwrap_or(true) || stderr_truncated.unwrap_or(true);
        if truncated {
            diagnostics.push("executor stream truncated".to_owned());
        }
        let completion = if stdout.is_empty() {
            ReportCompletion::Missing
        } else if complete && diagnostics.is_empty() && !truncated {
            ReportCompletion::Complete
        } else {
            ReportCompletion::Truncated
        };
        let termination = match (timed_out, exit_code) {
            (Some(true), _) | (Some(false), Some(..=-1)) => ProcessTermination::Crashed,
            (Some(false), Some(0)) => ProcessTermination::Success,
            (Some(false), Some(_)) => ProcessTermination::Failure,
            _ => ProcessTermination::Unknown,
        };
        let mut subject = self.contract.subject.clone();
        if let Some(header) = &observed_header {
            subject.requirement = header.requirement.clone();
            subject.artifact = header.artifact.clone();
            subject.method = header.method.clone();
        }
        let report = TestReport {
            subject,
            provenance: bound.then(|| ArtifactProvenance::Interpreted {
                source_frontier: self.contract.subject.artifact.clone(),
                interpreter: format!(
                    "{}@{}",
                    self.method.runtime.executable, self.method.runtime.python_version
                ),
                environment: self.method.runtime.environment.clone(),
            }),
            completion,
            termination,
            observations,
        };
        let verifier = BoundAdapter {
            report: &report,
            bound,
        };
        let judgment = evaluate_report(&self.contract, &report, &verifier);
        Ok(RunnerObservation {
            observation_integrity: if !bound {
                ObserverIntegrity::Unbound {}
            } else {
                match self.method.runtime.engine {
                    PythonEngine::Cpython {} => ObserverIntegrity::Cooperative {},
                    PythonEngine::Cpython3147Wasi { .. } => {
                        ObserverIntegrity::ProtectedInterpreter {}
                    }
                }
            },
            source: self.source.clone(),
            report,
            judgment,
            diagnostics,
            stderr: stderr.unwrap_or_default().to_owned(),
            observed_header,
        })
    }
}

/// Derived under the host's authenticated executor/runtime binding. This is not
/// a caller-provided permission, external-read closure or admission certificate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ObserverIntegrity {
    Unbound {},
    Cooperative {},
    ProtectedInterpreter {},
}

#[derive(Clone, Debug, Serialize)]
pub struct RunnerObservation {
    pub observation_integrity: ObserverIntegrity,
    pub source: Option<whipplescript_store::norm_artifact::ArtifactBasis>,
    pub observed_header: Option<RunnerHeader>,
    pub report: TestReport,
    pub judgment: TestJudgment,
    pub diagnostics: Vec<String>,
    pub stderr: String,
}

struct BoundAdapter<'a> {
    report: &'a TestReport,
    bound: bool,
}
impl ReportVerifier for BoundAdapter<'_> {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        self.bound && report == self.report
    }
    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        self.bound && report == self.report && self.report.observations.contains(observation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerHeader {
    pub contract_digest: String,
    pub requirement: EvidenceVersion,
    pub protocol: String,
    pub run_id: String,
    pub artifact: String,
    pub method: EvidenceVersion,
    pub environment: String,
    pub adapter_digest: String,
    pub python_version: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum AdapterEvent {
    Started(Box<RunnerHeader>),
    Case {
        case: String,
        assertion: String,
        actual: Value,
    },
    Error {
        case: Option<String>,
        message: String,
    },
    Complete {},
}
