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

/// The deployment's installed planning premises, as the Worker supplies them.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Deployment {
    pub(super) planning: String,
    pub(super) runtime: String,
    image_binding: String,
    pub(super) deployed_image: String,
    pub(super) time_basis: String,
}

impl Deployment {
    pub(super) fn parse(deployment: &str) -> Result<Self, String> {
        if deployment.len() > 131_072 {
            return Err("hosted impact deployment exceeds 128 KiB".into());
        }
        serde_json::from_str(deployment).map_err(|e| e.to_string())
    }

    /// The installed image binding, validated against the deployed image and
    /// the deployment's runtime before anything reads history.
    pub(super) fn installed(
        &self,
    ) -> Result<whipplescript_kernel::norm_runtime_image::InstalledRuntimeImage, String> {
        let installed = whipplescript_kernel::norm_runtime_image::InstalledRuntimeImage::parse(
            &self.image_binding,
        )?;
        let runtime = whipplescript_kernel::norm_runtime::parse(&self.runtime)?;
        installed.validate_for(&self.deployed_image, &runtime)?;
        Ok(installed)
    }
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
    let deployment = Deployment::parse(deployment)?;
    let installed = deployment.installed()?;
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
