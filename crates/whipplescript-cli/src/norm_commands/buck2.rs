//! A requirement declared by its Buck2 check, native only (norm-plane §3.4,
//! §14.5): `norm infer-support` lists a check's cases once, into the
//! requirement's template, and `norm run` runs the targets at a recorded cut,
//! records the executor's report in the runtime journal and publishes the
//! observation that rests on it. Both reach the Home's daemon only through
//! the build wrapper, as a principal (§14.1).
use std::path::Path;

use whipplescript_kernel::norm_buck2_execution::{
    parse_check_command, run_instance, Buck2RunSelection, Buck2TestsSupport, PreparedBuck2Run,
    VerifiedBuck2Execution,
};
use whipplescript_kernel::norm_buck2_tests::Buck2Build;
use whipplescript_kernel::norm_publication::{ObservationSigning, PreparedObservationPublication};
use whipplescript_store::norm::{NormStatement, NormVerifier};
use whipplescript_store::norm_artifact::CapturedArtifact;
use whipplescript_store::norm_history::CapturedNormHistory;

use crate::build_commands::{list_tests, run_tests, CutTree};

/// Infer a requirement's Buck2 template from its declared check: the
/// command names the targets, and their listings at the cut are its cases.
pub(crate) fn infer_support(
    tree: &CutTree,
    command: &str,
    executor: &Path,
    report: &Path,
    timeout_seconds: u64,
) -> Result<Buck2TestsSupport, String> {
    let targets = parse_check_command(command)?;
    let listing = list_tests(tree, &targets, executor, report, timeout_seconds)?;
    Buck2TestsSupport::infer(&targets, &listing)
}

/// The Buck2 a tree's daemon runs, as a run's provenance.
pub(crate) fn build_of(tree: &CutTree) -> Buck2Build {
    Buck2Build {
        buck2_version: tree
            .buck2_version
            .strip_prefix("buck2 ")
            .unwrap_or(&tree.buck2_version)
            .to_owned(),
        toolchain: tree
            .pin
            .as_deref()
            .map(|pin| format!("buck2-version {pin}"))
            .unwrap_or_else(|| "buck2-version unpinned".into()),
        environment: format!("whip-test-executor; isolation {}", tree.isolation_dir),
    }
}

/// Where a run happens and what it runs through.
pub(crate) struct Buck2RunHost<'a> {
    pub tree: &'a CutTree,
    pub artifact: &'a CapturedArtifact,
    pub executor: &'a Path,
    pub report: &'a Path,
    pub timeout_seconds: u64,
}

/// Prepare a run from verified history, run the targets unless this effect
/// already recorded its run, record the report durably, and publish the
/// observation that rests on the record. A retry publishes the recorded run
/// and recovers the retained envelope.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_and_publish(
    history: &CapturedNormHistory,
    verifier: &dyn NormVerifier,
    host: Buck2RunHost<'_>,
    journal: &whipplescript_store::SqliteStore,
    ledger: &mut whipplescript_store::items::WorkItemStore,
    selection: Buck2RunSelection<'_>,
    signing: ObservationSigning<'_>,
    sign: impl FnOnce(&NormStatement) -> Result<String, String>,
) -> Result<(VerifiedBuck2Execution, String), String> {
    let cut = host.artifact.basis().cut.clone();
    let run_id = match PreparedBuck2Run::retried(journal, &cut, &selection)? {
        Some(run_id) => run_id,
        None => {
            let prepared = PreparedBuck2Run::prepare(history, verifier, host.artifact, selection)?;
            let run = run_tests(
                host.tree,
                prepared.targets(),
                host.executor,
                host.report,
                host.timeout_seconds,
                false,
            )?;
            // A report the executor did not leave is recorded as missing: a
            // named harness failure, never an exercised count.
            prepared
                .record(journal, build_of(host.tree), run.report.ok())?
                .0
        }
    };
    let execution = VerifiedBuck2Execution::recover_captured(
        history,
        verifier,
        host.artifact,
        journal,
        &run_instance(&cut),
        &run_id,
    )?;
    let publication = PreparedObservationPublication::prepare(
        &execution, history, journal, verifier, signing, sign,
    )?;
    let receipt = publication.submit(ledger, verifier)?;
    receipt.acknowledge(journal)?;
    Ok((execution, receipt.event_id().to_owned()))
}

/// `norm infer-support` and `norm run`, over the native stores.
pub(super) fn execute(
    args: &super::Arguments<'_>,
    trust: &super::NormTrust<'_>,
    verifier: &dyn NormVerifier,
    store: &mut whipplescript_store::items::WorkItemStore,
    runtime_path: &Path,
    artifacts: &whipplescript_store::norm_commands::NormArtifactCapture<'_>,
) -> Result<serde_json::Value, String> {
    use crate::build_commands::{
        admit_trigger, buck2_binary, build_root, classification_of, executor_binary,
        materialize_cut,
    };
    let binding = args.required("--as")?;
    let principal = trust.principal(binding)?;
    let cut = args.required("--cut")?;
    let timeout = match args.flags.get("--timeout") {
        Some(value) => value
            .parse()
            .map_err(|_| "--timeout needs a whole number of seconds".to_owned())?,
        None => 600,
    };
    let vcs = crate::open_vcs().map_err(|_| "could not open the branch stores".to_owned())?;
    let root = build_root();
    let tree = materialize_cut(&vcs, cut, &root, &buck2_binary())?;
    // The gated tier: the principal triggers only what it may read (§14.2).
    let admit = |targets: &[String]| -> Result<(), String> {
        for target in targets {
            let classification = classification_of(&tree, target, &trust.policy)?;
            admit_trigger(principal, target, &classification)?;
        }
        Ok(())
    };
    let executor = executor_binary()?;
    let reports = root.join("reports").join(&tree.cut);
    std::fs::create_dir_all(&reports)
        .map_err(|error| format!("cannot create {}: {error}", reports.display()))?;
    let report = reports.join(format!(
        "{}-{}.json",
        args.verb,
        crate::now_stamp().replace(':', "-")
    ));
    if args.verb == "infer-support" {
        let command = args.required("--check")?;
        admit(&parse_check_command(command)?)?;
        let support = infer_support(&tree, command, &executor, &report, timeout)?;
        return Ok(serde_json::json!({
            "cut": tree.cut,
            "targets": support.targets(),
            "method": support.method(),
            "cases": support.cases(),
            "support_contract": serde_json::to_string(&support).map_err(|e| e.to_string())?,
        }));
    }
    let signer = trust.key(binding)?;
    let view = store.norm_view(verifier).map_err(super::debug_error)?;
    let vocabulary =
        super::super::build_commands::charter_vocabulary(&view, args.required("--vocabulary")?)?;
    let history = whipplescript_store::norm_history::CapturedNormHistory::capture(
        &view,
        &store.export_events().map_err(super::debug_error)?,
        verifier,
        whipplescript_store::norm_history::NormHistoryLimits::default(),
    )
    .map_err(super::debug_error)?;
    let artifact = artifacts(cut).map_err(super::debug_error)?;
    let frontier = args.frontier("--frontier")?;
    let selection = || Buck2RunSelection {
        ledger: &view.ledger,
        frontier: frontier.as_deref(),
        requirement: args.positional[0],
        effect_id: args.flags.get("--effect").copied().unwrap_or(""),
        publisher: &signer.actor().principal,
    };
    admit(PreparedBuck2Run::prepare(&history, verifier, &artifact, selection())?.targets())?;
    let journal = crate::open_store(runtime_path)?;
    let created_at = args
        .flags
        .get("--at")
        .map(|value| (*value).to_owned())
        .unwrap_or_else(crate::now_stamp);
    let (execution, event_id) = run_and_publish(
        &history,
        verifier,
        Buck2RunHost {
            tree: &tree,
            artifact: &artifact,
            executor: &executor,
            report: &report,
            timeout_seconds: timeout,
        },
        &journal,
        store,
        selection(),
        ObservationSigning {
            vocabulary: &vocabulary,
            authority: Some(&view.authority_head),
            actor: signer.actor(),
            created_at: &created_at,
        },
        |statement| signer.sign(statement),
    )?;
    Ok(serde_json::json!({
        "event_id": event_id,
        "instance": execution.instance_id(),
        "run": execution.run_id(),
        "judgment": execution.judgment(),
    }))
}
