//! A requirement declared by its Buck2 check (norm-plane §3.4, §14.5).
//!
//! One declaration: `buck2 test <targets>` names what runs, and inference
//! lists those targets' cases once, at declaration time, into the
//! requirement's support template. The case inventory is therefore the
//! requirement's, fixed when it is written; no later run chooses its own
//! denominator (§3.6). A case the runner stops listing is a missing case,
//! and a case it starts listing is not required.
//!
//! A run is a second execution kind beside the Python-call runs of
//! `norm_execution`. The wrapper runs the targets at a recorded cut, records
//! the executor's report durably in the runtime journal, and publishes a
//! signed observation that rests on that record. Recovery re-derives the
//! contract from verified history and the captured cut and re-judges the
//! retained report; it never imports a judgment. Only a host that runs Buck2
//! recovers such a run. Nothing here executes Buck2, grants authority to run
//! it, or grants permission to publish.
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::json;
use whipplescript_core::norm_buck2_report::{
    Buck2TestReport, Listing, BUCK2_TEST_SUPPORT_PROTOCOL,
};
use whipplescript_core::norm_evidence::{
    AssertionObservation, EvidenceSubject, EvidenceVersion, ReportContract, ReportVerifier,
    RequiredCase, TestReport,
};
use whipplescript_store::norm::NormVerifier;
use whipplescript_store::norm_artifact::{ArtifactBasis, CapturedArtifact};
use whipplescript_store::norm_commands::NormArtifactCapture;
use whipplescript_store::norm_history::{CapturedNormHistory, NormReadAnchor};
use whipplescript_store::norm_inventory::InventoryRequirement;
use whipplescript_store::{NewEvent, RuntimeStore};

use crate::exec_http::sha256_hex;
use crate::norm_buck2_tests::{case_id, expected_pass, Buck2Build, VERDICT_ASSERTION};
use crate::norm_runner::candidate_identity;

/// The support template's protocol, stored in a requirement's
/// `support_contract` beside the Python-call template's.
pub const BUCK2_TESTS_SUPPORT_PROTOCOL: &str = "whipplescript.norm.buck2-tests-support/v1";
/// The method a Buck2 template names.
pub const BUCK2_TESTS_METHOD: &str = "whipplescript.norm.buck2-tests";
/// The adapter a run passes through: the executor's `whip` listing and
/// verdict protocol, its report, and this kernel's reading of it
/// (`norm_buck2_tests`). A change to any of them is a new method.
pub const BUCK2_TESTS_ADAPTER: &str = "whipplescript.norm.buck2-tests-adapter/1";
/// The durable record of one run.
pub const BUCK2_RUN_PROTOCOL: &str = "whipplescript.norm.buck2-tests-run/v1";
/// The journal event a run's record is, and the fact its publication rests on.
pub const BUCK2_TESTS_RECORDED: &str = "norm.buck2-tests.recorded";
/// The runtime-journal instance of the runs made at one cut.
pub const BUCK2_TESTS_INSTANCE_PREFIX: &str = "buck2-tests:";
/// Why a host that runs no Buck2 reads a Buck2 run as unavailable.
pub const BUCK2_UNAVAILABLE: &str =
    "a Buck2 test run is unavailable on this host: it runs no Buck2, so it cannot recover the run's retained report or re-judge it";

/// The journal instance a run at `cut` is recorded under.
pub fn run_instance(cut: &str) -> String {
    format!("{BUCK2_TESTS_INSTANCE_PREFIX}{cut}")
}

/// Whether published coordinates name a Buck2 run's journal instance.
pub fn is_run_instance(instance: &str) -> bool {
    instance.starts_with(BUCK2_TESTS_INSTANCE_PREFIX)
}

fn no_adapter(program: &str) -> String {
    format!(
        "no bundled adapter reports cases for `{program}`; only `buck2 test <targets>` is adapted"
    )
}

/// Whether `arg` is one Buck2 target label, `[cell]//package:name`. A
/// pattern (`...`, or a package without a name) lets the runner choose its
/// suites at run time, so it is not a label.
pub fn is_target_label(arg: &str) -> bool {
    let Some((package, name)) = arg.rsplit_once(':') else {
        return false;
    };
    package.contains("//")
        && !name.is_empty()
        && !name.contains('/')
        && !arg.contains("...")
        && !arg.starts_with('-')
}

/// Split a declared check command without a shell and accept exactly
/// `buck2 test <label>...`. The targets are returned in the order written.
pub fn parse_check_command(command: &str) -> Result<Vec<String>, String> {
    const METACHARACTERS: &[char] = &[
        '|', '&', ';', '<', '>', '(', ')', '$', '`', '\\', '"', '\'', '*', '?', '[', ']', '{', '}',
        '~', '#', '!', '\n', '\r',
    ];
    if let Some(found) = command.chars().find(|c| METACHARACTERS.contains(c)) {
        return Err(format!(
            "the check command contains the shell metacharacter `{}`; it is split without a shell",
            found.escape_default()
        ));
    }
    let mut words = command.split_whitespace();
    let program = words.next().ok_or("the check command is empty")?;
    if program != "buck2" {
        return Err(no_adapter(program));
    }
    match words.next() {
        Some("test") => {}
        Some(other) => return Err(no_adapter(&format!("buck2 {other}"))),
        None => return Err(no_adapter("buck2")),
    }
    let mut targets: Vec<String> = Vec::new();
    for word in words {
        if !is_target_label(word) {
            return Err(format!(
                "`{word}` is not a Buck2 target label; name each target, since a flag or a pattern lets the runner choose what runs"
            ));
        }
        if targets.iter().any(|target| target == word) {
            return Err(format!("the check command names `{word}` twice"));
        }
        targets.push(word.to_owned());
    }
    if targets.is_empty() {
        return Err("`buck2 test` names no targets".into());
    }
    Ok(targets)
}

/// A requirement's Buck2 support template: the targets `buck2 test` runs and
/// the case inventory inferred from their listings when it was declared.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", deny_unknown_fields)]
pub enum Buck2TestsSupport {
    #[serde(rename = "whipplescript.norm.buck2-tests-support/v1")]
    V1 {
        targets: Vec<String>,
        cases: Vec<RequiredCase>,
    },
}

impl Buck2TestsSupport {
    /// Infer the template from a listing of `targets`: every case each suite
    /// listed, required to pass its verdict. A suite whose listing failed, or
    /// whose test type no adapter lists, refuses inference by name.
    pub fn infer(targets: &[String], listing: &Buck2TestReport) -> Result<Self, String> {
        if listing.suites.is_empty() {
            return Err("`buck2 test` over those targets handed the executor no test suite".into());
        }
        let mut cases = Vec::new();
        for suite in &listing.suites {
            let label = suite.target.label();
            match &suite.listing {
                Listing::Listed { cases: listed, .. } => {
                    cases.extend(listed.iter().map(|case| RequiredCase {
                        id: case_id(suite, case),
                        assertion: VERDICT_ASSERTION.into(),
                        expected: expected_pass(),
                    }))
                }
                Listing::ListingFailed { reason } => {
                    return Err(format!(
                        "cannot infer the cases of `{label}`: its listing failed: {reason}"
                    ))
                }
                Listing::MissingAdapter { test_type } => {
                    return Err(format!(
                        "cannot infer the cases of `{label}`: no bundled adapter lists a test of type `{test_type}`"
                    ))
                }
            }
        }
        let support = Self::V1 {
            targets: targets.to_vec(),
            cases,
        };
        support.validate()?;
        Ok(support)
    }

    pub fn targets(&self) -> &[String] {
        let Self::V1 { targets, .. } = self;
        targets
    }

    pub fn cases(&self) -> &[RequiredCase] {
        let Self::V1 { cases, .. } = self;
        cases
    }

    /// What a stored template must be before anything runs or is judged
    /// against it.
    pub fn validate(&self) -> Result<(), String> {
        let targets = self.targets();
        if targets.is_empty() {
            return Err("a Buck2 support template names no targets".into());
        }
        if let Some(bad) = targets.iter().find(|target| !is_target_label(target)) {
            return Err(format!(
                "a Buck2 support template names `{bad}`, which is not a target label"
            ));
        }
        if self.cases().is_empty() {
            return Err("a Buck2 support template declares no cases".into());
        }
        if self
            .cases()
            .iter()
            .any(|case| case.assertion != VERDICT_ASSERTION || case.expected != expected_pass())
        {
            return Err(
                "a Buck2 test case asserts only its verdict, and expects it to pass".into(),
            );
        }
        Ok(())
    }

    /// The method's identity: the template protocol, the adapter and report
    /// protocol a run passes through, and the targets it runs.
    pub fn method(&self) -> EvidenceVersion {
        EvidenceVersion {
            name: BUCK2_TESTS_METHOD.into(),
            version: "1".into(),
            digest: sha256_hex(
                json!([
                    BUCK2_TESTS_SUPPORT_PROTOCOL,
                    BUCK2_TESTS_ADAPTER,
                    BUCK2_TEST_SUPPORT_PROTOCOL,
                    self.targets(),
                ])
                .to_string()
                .as_bytes(),
            ),
        }
    }

    /// The contract a run over `files` is judged against. The tested
    /// artifact is the whole cut: nothing encloses what a Buck2 test reads.
    pub fn contract(
        &self,
        requirement: EvidenceVersion,
        files: &BTreeMap<String, String>,
    ) -> ReportContract {
        ReportContract {
            subject: EvidenceSubject {
                requirement,
                method: self.method(),
                artifact: candidate_identity(files),
            },
            cases: self.cases().to_vec(),
        }
    }
}

/// The Buck2 template a requirement declares, validated.
pub fn requirement_support(selected: &InventoryRequirement) -> Result<Buck2TestsSupport, String> {
    match crate::norm_execution::support_template(selected)? {
        crate::norm_execution::SupportTemplate::Buck2Tests(support) => {
            support.validate()?;
            Ok(support)
        }
        crate::norm_execution::SupportTemplate::PythonCalls(_) => {
            Err("norm requirement's support template calls Python, not Buck2 tests".into())
        }
    }
}

/// Serializable coordinates of one run, never proof of verification or authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Buck2RunIntent {
    pub protocol: String,
    pub anchor: NormReadAnchor,
    pub requirement: EvidenceVersion,
    pub method: EvidenceVersion,
    pub targets: Vec<String>,
    pub artifact: ArtifactBasis,
    pub effect_id: String,
    pub publisher: String,
}

/// The journal record of one run: what was prepared, the Buck2 that ran it,
/// and the executor's report as it was written, or `None` when it wrote none.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Buck2RunRecord {
    pub intent: Buck2RunIntent,
    pub build: Buck2Build,
    pub report: Option<Buck2TestReport>,
}

pub struct Buck2RunSelection<'a> {
    pub ledger: &'a str,
    pub frontier: Option<&'a [String]>,
    pub requirement: &'a str,
    pub effect_id: &'a str,
    pub publisher: &'a str,
}

/// Only constructed from verified history and an independently captured cut.
/// It grants no authority to run Buck2 and attests that nothing has run.
#[derive(Clone, Debug)]
pub struct PreparedBuck2Run {
    intent: Buck2RunIntent,
    support: Buck2TestsSupport,
    contract: ReportContract,
}

impl PreparedBuck2Run {
    pub fn prepare(
        history: &CapturedNormHistory,
        verifier: &dyn NormVerifier,
        artifact: &CapturedArtifact,
        selection: Buck2RunSelection<'_>,
    ) -> Result<Self, String> {
        let view = history
            .project(selection.frontier, verifier)
            .map_err(|e| format!("{e:?}"))?;
        if view.ledger != selection.ledger {
            return Err("norm preparation selected a different ledger".into());
        }
        if selection.publisher.trim().is_empty() || selection.effect_id.trim().is_empty() {
            return Err("a Buck2 run requires a publisher and an effect identity".into());
        }
        let inventory = view.requirement_inventory().map_err(|e| format!("{e:?}"))?;
        let selected = inventory
            .requirements
            .get(selection.requirement)
            .ok_or("norm preparation requires an active requirement")?;
        let requirement = selected
            .requirement
            .clone()
            .ok_or("norm requirement has no usable identity")?;
        let support = requirement_support(selected)?;
        let contract = support.contract(requirement.clone(), artifact.files());
        Ok(Self {
            intent: Buck2RunIntent {
                protocol: BUCK2_RUN_PROTOCOL.into(),
                anchor: NormReadAnchor {
                    checkpoint: view.checkpoint(),
                    frontier: view.frontier,
                },
                requirement,
                method: support.method(),
                targets: support.targets().to_vec(),
                artifact: artifact.basis().clone(),
                effect_id: selection.effect_id.into(),
                publisher: selection.publisher.into(),
            },
            support,
            contract,
        })
    }

    pub fn intent(&self) -> &Buck2RunIntent {
        &self.intent
    }
    pub fn targets(&self) -> &[String] {
        self.support.targets()
    }
    pub fn contract(&self) -> &ReportContract {
        &self.contract
    }
    /// The journal instance this run is recorded under.
    pub fn instance(&self) -> String {
        run_instance(&self.intent.artifact.cut)
    }

    /// The run an effect already recorded at a cut, in a ledger, if any.
    fn recorded_at<S: RuntimeStore>(
        journal: &S,
        cut: &str,
        ledger: &str,
        effect_id: &str,
    ) -> Result<Option<(String, Buck2RunRecord)>, String> {
        for event in journal
            .list_events(&run_instance(cut))
            .map_err(|e| format!("{e:?}"))?
        {
            if event.event_type != BUCK2_TESTS_RECORDED {
                continue;
            }
            let record: Buck2RunRecord = serde_json::from_str(&event.payload_json)
                .map_err(|e| format!("invalid Buck2 run record: {e}"))?;
            if record.intent.effect_id == effect_id
                && record.intent.anchor.checkpoint.ledger == ledger
            {
                return Ok(Some((event.event_id, record)));
            }
        }
        Ok(None)
    }

    /// The run this preparation's effect already recorded, if any.
    pub fn recorded<S: RuntimeStore>(
        &self,
        journal: &S,
    ) -> Result<Option<(String, Buck2RunRecord)>, String> {
        let recorded = Self::recorded_at(
            journal,
            &self.intent.artifact.cut,
            &self.intent.anchor.checkpoint.ledger,
            &self.intent.effect_id,
        )?;
        if let Some((_, record)) = &recorded {
            if record.intent != self.intent {
                return Err(
                    "this effect already recorded a Buck2 run of another preparation".into(),
                );
            }
        }
        Ok(recorded)
    }

    /// A retry: the run an effect already recorded at `cut`, which is
    /// published rather than run again. It was prepared against the ledger
    /// as it stood then, so its anchor is its own; it must still be a run
    /// of the same requirement for the same publisher.
    pub fn retried<S: RuntimeStore>(
        journal: &S,
        cut: &str,
        selection: &Buck2RunSelection<'_>,
    ) -> Result<Option<String>, String> {
        let Some((run_id, record)) =
            Self::recorded_at(journal, cut, selection.ledger, selection.effect_id)?
        else {
            return Ok(None);
        };
        if record.intent.requirement.name != selection.requirement
            || record.intent.publisher != selection.publisher
        {
            return Err(
                "this effect already recorded a Buck2 run of another requirement or publisher"
                    .into(),
            );
        }
        Ok(Some(run_id))
    }

    /// Record the run durably before anything is published: the record its
    /// publication rests on. Recording the same run again returns it.
    pub fn record<S: RuntimeStore>(
        &self,
        journal: &S,
        build: Buck2Build,
        report: Option<Buck2TestReport>,
    ) -> Result<(String, Buck2RunRecord), String> {
        let record = Buck2RunRecord {
            intent: self.intent.clone(),
            build,
            report,
        };
        if let Some((event_id, existing)) = self.recorded(journal)? {
            if existing != record {
                return Err("this effect already recorded a different Buck2 run".into());
            }
            return Ok((event_id, existing));
        }
        let payload = serde_json::to_string(&record).map_err(|e| e.to_string())?;
        let key = format!(
            "{BUCK2_TESTS_RECORDED}:{}:{}",
            self.intent.anchor.checkpoint.ledger, self.intent.effect_id
        );
        let instance = self.instance();
        let stored = journal
            .append_event(NewEvent {
                instance_id: &instance,
                event_type: BUCK2_TESTS_RECORDED,
                payload_json: &payload,
                source: "kernel",
                causation_id: None,
                correlation_id: Some(&self.intent.effect_id),
                idempotency_key: Some(&key),
            })
            .map_err(|e| format!("cannot record the Buck2 run: {e:?}"))?;
        Ok((stored.event_id, record))
    }
}

/// A run re-judged from its durable record against a contract rebuilt from
/// verified history and the captured cut. Not a publication grant.
#[derive(Clone, Debug)]
pub struct VerifiedBuck2Execution {
    support: Buck2TestsSupport,
    contract: ReportContract,
    record: Buck2RunRecord,
    instance_id: String,
    run_id: String,
    report: TestReport,
}

impl VerifiedBuck2Execution {
    /// Capture the record's cut through a host-owned reader, then recover.
    pub fn recover<S: RuntimeStore>(
        history: &CapturedNormHistory,
        verifier: &dyn NormVerifier,
        artifacts: &NormArtifactCapture<'_>,
        store: &S,
        instance_id: &str,
        run_id: &str,
    ) -> Result<Self, String> {
        let record = Self::record_of(store, instance_id, run_id)?;
        let artifact = artifacts(&record.intent.artifact.cut).map_err(|e| format!("{e:?}"))?;
        Self::recover_captured(history, verifier, &artifact, store, instance_id, run_id)
    }

    fn record_of<S: RuntimeStore>(
        store: &S,
        instance_id: &str,
        run_id: &str,
    ) -> Result<Buck2RunRecord, String> {
        let event = store
            .list_events(instance_id)
            .map_err(|e| format!("{e:?}"))?
            .into_iter()
            .find(|event| event.event_id == run_id && event.event_type == BUCK2_TESTS_RECORDED)
            .ok_or("the Buck2 run's record is missing from the journal")?;
        serde_json::from_str(&event.payload_json)
            .map_err(|e| format!("invalid Buck2 run record: {e}"))
    }

    /// The journal's record supplies coordinates and the executor's report;
    /// the requirement, template, method and contract come from verified
    /// history and the captured cut, and the judgment from the adapter.
    pub fn recover_captured<S: RuntimeStore>(
        history: &CapturedNormHistory,
        verifier: &dyn NormVerifier,
        artifact: &CapturedArtifact,
        store: &S,
        instance_id: &str,
        run_id: &str,
    ) -> Result<Self, String> {
        let record = Self::record_of(store, instance_id, run_id)?;
        let intent = &record.intent;
        let frontier: Vec<String> = intent.anchor.frontier.iter().cloned().collect();
        let prepared = PreparedBuck2Run::prepare(
            history,
            verifier,
            artifact,
            Buck2RunSelection {
                ledger: &intent.anchor.checkpoint.ledger,
                frontier: Some(&frontier),
                requirement: &intent.requirement.name,
                effect_id: &intent.effect_id,
                publisher: &intent.publisher,
            },
        )?;
        if prepared.intent != *intent || prepared.instance() != instance_id {
            return Err(
                "the recorded Buck2 run differs from its reconstruction from verified history"
                    .into(),
            );
        }
        let report = crate::norm_buck2_tests::test_report(
            &prepared.contract,
            &record.build,
            &intent.artifact.cut,
            record.report.as_ref(),
        );
        Ok(Self {
            support: prepared.support,
            contract: prepared.contract,
            record,
            instance_id: instance_id.into(),
            run_id: run_id.into(),
            report,
        })
    }

    pub fn support(&self) -> &Buck2TestsSupport {
        &self.support
    }
    /// Rebuilt from the historically accepted requirement and the captured
    /// cut, never from the record.
    pub fn contract(&self) -> &ReportContract {
        &self.contract
    }
    pub fn intent(&self) -> &Buck2RunIntent {
        &self.record.intent
    }
    pub fn record(&self) -> &Buck2RunRecord {
        &self.record
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    /// The adapter's report of the retained executor report.
    pub fn report(&self) -> &TestReport {
        &self.report
    }
    /// The judgment of the retained report against the rebuilt contract.
    pub fn judgment(&self) -> whipplescript_core::norm_evidence::TestJudgment {
        whipplescript_core::norm_evidence::evaluate_report(&self.contract, &self.report, self)
    }
}

// The binding is the adapter's: the report is the one rebuilt from the
// retained record for this contract, and it is bound only to its own cut.
impl ReportVerifier for VerifiedBuck2Execution {
    fn verify_report_binding(&self, report: &TestReport) -> bool {
        report == &self.report && self.report.provenance.is_some()
    }
    fn verify_assertion_exercise(
        &self,
        report: &TestReport,
        observation: &AssertionObservation,
    ) -> bool {
        self.verify_report_binding(report) && self.report.observations.contains(observation)
    }
}

#[cfg(all(test, feature = "native"))]
#[path = "norm_buck2_execution_tests.rs"]
mod tests;
