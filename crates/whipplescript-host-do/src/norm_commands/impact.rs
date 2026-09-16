//! Authenticated hosted query composition; deployment premises are separate.
use super::{HostedNormTrust, NormArtifactCapture, NormCommandStore};
use serde::Deserialize;
use whipplescript_kernel::norm_execution_policy::ProtectedPythonPolicy;
use whipplescript_kernel::norm_planning::{ImpactQuery, PlanningConfiguration};
use whipplescript_kernel::norm_runner::PythonRuntime;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::RuntimeStore;

const PROTOCOL: &str = "whipplescript.norm.impact/v1";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    command: Coordinates,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Coordinates {
    before_cut: String,
    after_cut: String,
    before_frontier: Option<Vec<String>>,
    after_frontier: Option<Vec<String>>,
}

/// Supplied by the deployment, never decoded from the command body.
pub struct HostedImpactConfiguration<'a> {
    pub trust: &'a str,
    pub planning: &'a str,
    pub runtime: &'a str,
    pub time_basis: &'a str,
}

/// The embedding authenticates full-ledger/workspace access and independently
/// verifies installed runtimes. No default verifier equates policy with installation.
pub fn execute_hosted_norm_impact<S: NormCommandStore + RuntimeStore>(
    store: &S,
    configuration: HostedImpactConfiguration<'_>,
    command: &str,
    artifacts: &NormArtifactCapture<'_>,
    verify_runtime: impl Fn(&PythonRuntime) -> Result<(), String>,
) -> Result<String, String> {
    let request: Request = serde_json::from_str(command).map_err(|e| e.to_string())?;
    if request.protocol != PROTOCOL {
        return Err("unsupported norm impact protocol".into());
    }
    let planning = PlanningConfiguration::parse(configuration.planning)?;
    let policy = ProtectedPythonPolicy::new(configuration.runtime, configuration.time_basis)?;
    let trust: HostedNormTrust =
        serde_json::from_str(configuration.trust).map_err(|e| e.to_string())?;
    trust.with_verifier(|verifier| {
        let current = store.norm_state(verifier).map_err(|e| format!("{e:?}"))?;
        let history = CapturedNormHistory::capture(
            &current,
            &store.tracker_history().map_err(|e| format!("{e:?}"))?,
            verifier,
            NormHistoryLimits::default(),
        )
        .map_err(|e| format!("{e:?}"))?;
        let result = whipplescript_kernel::norm_planning::execute(
            ImpactQuery {
                configuration: &planning,
                history: &history,
                verifier,
                runtime: store,
                artifacts,
                before_cut: &request.command.before_cut,
                after_cut: &request.command.after_cut,
                before_frontier: request.command.before_frontier.as_deref(),
                after_frontier: request.command.after_frontier.as_deref(),
                policy: &policy,
            },
            verify_runtime,
        )?;
        serde_json::to_string(&serde_json::json!({"protocol":PROTOCOL, "result":result}))
            .map_err(|e| e.to_string())
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Deployment {
    planning: String,
    runtime: String,
    image_binding: String,
    deployed_image: String,
    time_basis: String,
}
/// Install the concrete image verifier from deployment-owned inputs. Request
/// data never chooses the policy, image binding, image identity or query time.
pub fn execute_installed_hosted_norm_impact<S: NormCommandStore + RuntimeStore>(
    store: &S,
    trust: &str,
    command: &str,
    artifacts: &NormArtifactCapture<'_>,
    deployment: &str,
) -> Result<String, String> {
    if deployment.len() > 131_072 {
        return Err("hosted impact deployment exceeds 128 KiB".into());
    }
    let deployment: Deployment = serde_json::from_str(deployment).map_err(|e| e.to_string())?;
    let installed = whipplescript_kernel::norm_runtime_image::InstalledRuntimeImage::parse(
        &deployment.image_binding,
    )?;
    let runtime = whipplescript_kernel::norm_runtime::parse(&deployment.runtime)?;
    installed.validate_for(&deployment.deployed_image, &runtime)?;
    execute_hosted_norm_impact(
        store,
        HostedImpactConfiguration {
            trust,
            planning: &deployment.planning,
            runtime: &deployment.runtime,
            time_basis: &deployment.time_basis,
        },
        command,
        artifacts,
        |selected| installed.validate_for(&deployment.deployed_image, selected),
    )
}
