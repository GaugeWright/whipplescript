//! Coordinate-only source queries. The host supplies trust, installation and
//! stores; a request cannot supply a policy or a successful coverage label.
use std::process::ExitCode;

use whipplescript_kernel::norm_admission::AdmissionHost;
use whipplescript_kernel::norm_execution_policy::{
    Buck2TestsPolicy, NativeEvidencePolicy, ProtectedPythonPolicy,
};
use whipplescript_kernel::norm_planning::PlanningConfiguration;
use whipplescript_kernel::source_admission::SourceAdmissionCapture;
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::source_review::ReviewStore;
use whipplescript_store::source_review_types::NativeReviewReader;
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::SqliteStore;

pub(crate) const USAGE: &str =
    "usage: whip [--json] review plan <candidate-witness-digest> <attempt-id>\n\
  Reads the retained native candidate and authenticated norm ledger.\n\
  Returns obligations, selected evidence, required work and coverage blockers.\n\
  Host configuration: WHIPPLESCRIPT_NORM_TRUST, WHIPPLESCRIPT_NORM_PLANNING,\n\
  WHIPPLESCRIPT_NATIVE_NORM_RUNTIME, optional WHIPPLESCRIPT_SOURCE_REVIEW_STORE,\n\
  and the host-selected store paths.\n\
  Does not run checks, create tracker work or admit a ref.";

pub(crate) fn command(options: &super::CliOptions) -> ExitCode {
    let [verb, witness, attempt] = options.args.as_slice() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    if verb != "plan" || witness.starts_with("--") || attempt.starts_with("--") {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    match execute(&options.store_path, witness, attempt) {
        Ok(plan) if options.json => super::emit_json(plan),
        Ok(plan) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&plan).expect("plan JSON")
            );
            ExitCode::SUCCESS
        }
        Err(reason) => {
            eprintln!("review plan: {reason}");
            ExitCode::FAILURE
        }
    }
}

fn execute(
    runtime_path: &std::path::Path,
    witness: &str,
    attempt: &str,
) -> Result<serde_json::Value, String> {
    // Every database is opened without create, migration, repair or writer
    // privilege, including on refusals and in an empty working directory.
    let mut vcs = NativeWorkspaceVcs::open_read_only(
        super::branch_store_path(),
        super::vcs_content_store_path(),
    )
    .map_err(debug)?;
    super::install_decl_canonicalizers(&mut vcs);
    let ledger = WorkItemStore::open_read_only(super::items_store_path()).map_err(debug)?;
    let runtime = SqliteStore::open_read_only(runtime_path).map_err(debug)?;
    let review = std::env::var_os("WHIPPLESCRIPT_SOURCE_REVIEW_STORE")
        .map(|path| ReviewStore::open_read_only(std::path::PathBuf::from(path)))
        .transpose()
        .map_err(|error| format!("{error:?}"))?;
    let document = super::norm_commands::trust_document()?;
    let transport = super::norm_commands::custody_transport_for(&document)?;
    let trust = super::norm_commands::NormTrust::from_document(document, transport.as_deref())?;
    let verifier = trust.verifier()?;
    let configured = std::env::var("WHIPPLESCRIPT_NORM_PLANNING")
        .map_err(|_| "host must configure WHIPPLESCRIPT_NORM_PLANNING".to_owned())?;
    let configuration = PlanningConfiguration::parse(&configured)?;
    let managed = super::norm_exec_managed::configuration().map_err(debug)?;
    let managed = super::norm_exec_managed::require(managed.as_ref()).map_err(debug)?;
    // This is a reproducible selection coordinate, not wall-clock freshness.
    // The installed policy currently interprets protected/Buck2 observations.
    let time_basis = format!("native-source-admission/{witness}");
    let policy = NativeEvidencePolicy::new(
        ProtectedPythonPolicy::new(
            &serde_json::to_string(&managed.installed.runtime)
                .map_err(|error| error.to_string())?,
            &time_basis,
        )?,
        Buck2TestsPolicy::new(&time_basis)?,
    )?;
    let verify = |selected: &whipplescript_kernel::norm_runner::PythonRuntime| {
        managed.installed.validate_for(selected).map_err(debug)
    };
    whipplescript_kernel::source_admission::plan_with_capture(
        &vcs,
        &ledger,
        AdmissionHost {
            now: None,
            verifier: &verifier,
            configuration: &configuration,
            runtime: &runtime,
            policy: &policy,
            verify_runtime: &verify,
        },
        witness,
        attempt,
        SourceAdmissionCapture {
            home: None,
            review: review
                .as_ref()
                .map(|reader| reader as &dyn NativeReviewReader),
        },
    )
    .map(|plan| plan.to_json())
}

fn debug(error: whipplescript_store::StoreError) -> String {
    format!("{error:?}")
}
