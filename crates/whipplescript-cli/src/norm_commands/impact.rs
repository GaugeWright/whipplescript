//! Native read-only planning through captured host-owned evidence.
use super::*;
use whipplescript_kernel::norm_execution_policy::ProtectedPythonPolicy;
use whipplescript_kernel::norm_planning::{ImpactQuery, PlanningConfiguration};
use whipplescript_store::norm_commands::NormArtifactCapture;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};

const CONFIGURATION: &str = "WHIPPLESCRIPT_NORM_PLANNING";
pub(super) fn execute(
    args: &Arguments<'_>,
    store: &WorkItemStore,
    verifier: &dyn NormVerifier,
    runtime_path: &std::path::Path,
    artifacts: &NormArtifactCapture<'_>,
) -> Result<Value, String> {
    let configured =
        std::env::var(CONFIGURATION).map_err(|_| format!("host must configure {CONFIGURATION}"))?;
    let configuration = PlanningConfiguration::parse(&configured)?;
    let host = super::super::norm_exec_managed::configuration().map_err(debug_error)?;
    let host = super::super::norm_exec_managed::require(host.as_ref()).map_err(debug_error)?;
    let time_basis = format!(
        "native-impact/{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    );
    let policy = ProtectedPythonPolicy::new(
        &serde_json::to_string(&host.installed.runtime).map_err(|error| error.to_string())?,
        &time_basis,
    )?;
    let current = store.norm_view(verifier).map_err(debug_error)?;
    let history = CapturedNormHistory::capture(
        &current,
        &store.export_events().map_err(debug_error)?,
        verifier,
        NormHistoryLimits::default(),
    )
    .map_err(debug_error)?;
    let before_frontier = args.frontier("--before-frontier")?;
    let after_frontier = args.frontier("--after-frontier")?;
    let runtime = super::super::open_store(runtime_path)?;
    whipplescript_kernel::norm_planning::execute(
        ImpactQuery {
            configuration: &configuration,
            history: &history,
            verifier,
            runtime: &runtime,
            artifacts,
            before_cut: args.positional[0],
            after_cut: args.positional[1],
            before_frontier: before_frontier.as_deref(),
            after_frontier: after_frontier.as_deref(),
            policy: &policy,
        },
        |selected| host.installed.validate_for(selected).map_err(debug_error),
    )
}
