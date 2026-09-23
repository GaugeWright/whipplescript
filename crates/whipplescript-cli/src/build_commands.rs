//! `whip build`: the Home's build-engine wrapper of DR-0124 §14.1, first half.
//!
//! The wrapper is a security and provenance boundary around a pinned,
//! unmodified Buck2. It materializes a recorded cut into a directory the Home
//! owns and evaluates it there with the Home's own daemon — its isolation
//! directory, its configuration, its environment — so what the daemon builds
//! is exactly the cut and nothing that moved since. A built target becomes an
//! artifact record (§14.6): the wrapper appends the durable `build.recorded`
//! event, publishes the record through the journal-retained path under the
//! `build.publish` scope, and names the cut, the configured label, the output
//! digests, the classification basis and the input-root encoding. Tests run
//! through `whip-test-executor` (§14.5), which the daemon reaches over the
//! TCP launch, and their report is written where the caller asked.
//!
//! What this half does not do: the labeled action graph's ceiling (§14.2) is
//! not yet chosen, so every result carries the organization-wide ceiling as
//! an explicit interim basis; scoped result interfaces for principals other
//! than the Home's operator, and the qualification experiment that chooses
//! the ceiling, are the second half.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use whipplescript_core::norm_buck2_report::Buck2TestReport;
use whipplescript_core::vocabulary::{Vocabulary, VocabularyRef};
use whipplescript_kernel::norm_artifact_publication::{
    ArtifactSigning, BuildArtifact, PreparedArtifactPublication, INPUT_ROOT_ENCODING_V1,
};
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::{NormActor, NormStatement, NormVerifier};
use whipplescript_store::norm_commands::NormCommandStore;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::{NewEvent, SqliteStore};

pub(crate) const USAGE: &str = "usage: whip [--json] build <command>\n\
  artifact <label> --cut <cut> --as <binding> [--classification <basis>]\n\
  test <target>... --cut <cut> [--report <file>] [--timeout <seconds>]\n\
  daemon status|stop --cut <cut>\n\
  The cut is materialized under .whipplescript/build/cuts/<cut> and evaluated there by the\n\
  Home's Buck2 daemon (isolation dir whip-home), which reaches whip-test-executor over the TCP launch.\n\
  Host configuration: WHIPPLESCRIPT_NORM_TRUST; WHIPPLESCRIPT_BUCK2 (the pinned buck2, default: buck2 on\n\
  the PATH); WHIPPLESCRIPT_TEST_EXECUTOR (default: whip-test-executor beside whip).";

/// The Home daemon's isolation directory: one daemon per materialized cut,
/// never the developer's own.
pub(crate) const HOME_ISOLATION_DIR: &str = "whip-home";

/// The interim classification basis every result carries until the
/// qualification experiment of §14.2 chooses a ceiling: the organization's.
pub(crate) const ORGANIZATION_CEILING: &str = "ceiling:organization";

/// The journal event the wrapper appends before it publishes: the durable
/// build record a retention rests on (§14.6).
pub(crate) const BUILD_RECORDED_SOURCE: &str = "whip build";

/// A cut materialized for the daemon.
#[derive(Clone, Debug)]
pub(crate) struct CutTree {
    pub cut: String,
    pub root: PathBuf,
    /// The pin the tree carries in `.buck2-version`, if any.
    pub pin: Option<String>,
    /// What the daemon's binary reports.
    pub buck2_version: String,
    /// The pinned Buck2 the host names.
    pub buck2: PathBuf,
}

pub(crate) fn buck2_binary() -> PathBuf {
    std::env::var_os("WHIPPLESCRIPT_BUCK2")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("buck2"))
}

/// The executor the daemon is configured to call: named by the host, or the
/// binary installed beside `whip`.
pub(crate) fn executor_binary() -> Result<PathBuf, String> {
    let whip =
        std::env::current_exe().map_err(|error| format!("cannot locate whip itself: {error}"))?;
    executor_binary_from(
        std::env::var_os("WHIPPLESCRIPT_TEST_EXECUTOR").map(PathBuf::from),
        &whip,
    )
}

fn executor_binary_from(named: Option<PathBuf>, whip: &Path) -> Result<PathBuf, String> {
    if let Some(path) = named {
        return Ok(path);
    }
    let beside = whip.with_file_name("whip-test-executor");
    if beside.is_file() {
        Ok(beside)
    } else {
        Err(format!(
            "no whip-test-executor beside whip at {}; set WHIPPLESCRIPT_TEST_EXECUTOR",
            beside.display()
        ))
    }
}

fn now_unix_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(0))
        .unwrap_or(0)
}

/// Materialize the cut under the build root and learn which Buck2 will
/// evaluate it.
pub(crate) fn materialize_cut(
    vcs: &NativeWorkspaceVcs,
    cut: &str,
    build_root: &Path,
    buck2: &Path,
) -> Result<CutTree, String> {
    let root = build_root.join("cuts").join(cut);
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    let materialized = vcs
        .materialize_cut(cut, &root, now_unix_nanos())
        .map_err(|error| format!("cannot materialize cut {cut}: {error:?}"))?;
    if materialized.is_none() {
        return Err(format!("no recorded cut {cut}"));
    }
    let pin = std::fs::read_to_string(root.join(".buck2-version"))
        .ok()
        .map(|pin| pin.trim().to_owned())
        .filter(|pin| !pin.is_empty());
    let version = Command::new(buck2)
        .arg("--version")
        .output()
        .map_err(|error| format!("cannot run {}: {error}", buck2.display()))?;
    if !version.status.success() {
        return Err(format!(
            "{} --version failed: {}",
            buck2.display(),
            String::from_utf8_lossy(&version.stderr).trim()
        ));
    }
    Ok(CutTree {
        cut: cut.to_owned(),
        root,
        pin,
        buck2_version: String::from_utf8_lossy(&version.stdout).trim().to_owned(),
        buck2: buck2.to_path_buf(),
    })
}

/// The Home's daemon over this tree: its isolation directory, and the
/// environment under which it launches the executor over TCP.
pub(crate) fn buck2(tree: &CutTree) -> Command {
    let mut command = Command::new(&tree.buck2);
    command
        .current_dir(&tree.root)
        .arg("--isolation-dir")
        .arg(HOME_ISOLATION_DIR)
        .env("BUCK2_TEST_TPX_USE_TCP", "1");
    command
}

fn run(mut command: Command, what: &str) -> Result<std::process::Output, String> {
    let output = command
        .output()
        .map_err(|error| format!("cannot run buck2 to {what}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "buck2 failed to {what} ({}):\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(output)
}

/// `cell//package:target (configuration)` as `buck2 cquery` prints it.
pub(crate) fn parse_configured_label(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let (label, rest) = line.split_once(" (")?;
    let configuration = rest.strip_suffix(')')?;
    if label.is_empty() || configuration.is_empty() {
        return None;
    }
    Some((label.to_owned(), configuration.to_owned()))
}

/// SHA-256 of a file's bytes, or of a directory as the sorted list of its
/// relative paths and their digests.
pub(crate) fn digest_path(path: &Path) -> Result<String, String> {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = Vec::new();
        collect(path, path, &mut entries)?;
        entries.sort();
        let mut hash = Sha256::new();
        for entry in entries {
            let digest = digest_path(&path.join(&entry))?;
            hash.update(entry.to_string_lossy().as_bytes());
            hash.update(b"\0");
            hash.update(digest.as_bytes());
            hash.update(b"\n");
        }
        return Ok(hex(&hash.finalize()));
    }
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(hex(&Sha256::digest(&bytes)))
}

fn collect(root: &Path, dir: &Path, into: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        std::fs::read_dir(dir).map_err(|error| format!("cannot list {}: {error}", dir.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect(root, &path, into)?;
        } else if let Ok(relative) = path.strip_prefix(root) {
            into.push(relative.to_path_buf());
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug)]
pub(crate) struct BuiltTarget {
    pub label: String,
    pub configuration: String,
    /// Output path and digest, in Buck2's order.
    pub outputs: Vec<(String, String)>,
}

/// Build one target in the cut through the Home's daemon and digest its
/// outputs.
pub(crate) fn build_target(tree: &CutTree, label: &str) -> Result<BuiltTarget, String> {
    let mut cquery = buck2(tree);
    cquery.arg("cquery").arg(label);
    let configured = run(cquery, &format!("configure {label}"))?;
    let (label, configuration) = String::from_utf8_lossy(&configured.stdout)
        .lines()
        .find_map(parse_configured_label)
        .ok_or_else(|| format!("buck2 cquery printed no configured label for {label}"))?;
    let mut build = buck2(tree);
    build
        .arg("build")
        .arg(&label)
        .arg("--show-full-json-output");
    let built = run(build, &format!("build {label}"))?;
    let outputs: BTreeMap<String, Value> = serde_json::from_slice(&built.stdout)
        .map_err(|error| format!("buck2 build printed no output map: {error}"))?;
    let mut digested = Vec::new();
    for (_, output) in outputs {
        let path = output
            .as_str()
            .ok_or("buck2 build printed an output that is not a path")?;
        digested.push((path.to_owned(), digest_path(Path::new(path))?));
    }
    Ok(BuiltTarget {
        label,
        configuration,
        outputs: digested,
    })
}

pub(crate) fn artifact(
    tree: &CutTree,
    built: &BuiltTarget,
    ledger: &str,
    classification: &str,
) -> BuildArtifact {
    BuildArtifact {
        ledger: ledger.to_owned(),
        cut: tree.cut.clone(),
        label: built.label.clone(),
        configuration: built.configuration.clone(),
        outputs: built
            .outputs
            .iter()
            .map(|(_, digest)| digest.clone())
            .collect(),
        classification: classification.to_owned(),
        encoding: INPUT_ROOT_ENCODING_V1.into(),
        action: None,
    }
}

/// The artifact's `artifact` vocabulary in the ledger's charter.
pub(crate) fn artifact_vocabulary(
    view: &whipplescript_store::norm::NormView,
) -> Result<VocabularyRef, String> {
    let entry = view
        .charter
        .vocabularies
        .iter()
        .find(|entry| entry.definition.name == "artifact")
        .ok_or("the ledger's charter declares no artifact vocabulary")?;
    Vocabulary::new(entry.definition.clone())
        .map(|vocabulary| vocabulary.reference().clone())
        .map_err(|error| error.to_string())
}

/// What a publication returned.
#[derive(Clone, Debug)]
pub(crate) struct Published {
    pub build_record: String,
    pub event_id: String,
}

/// Record the build durably, then publish the artifact record through the
/// retained path and acknowledge the receipt.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_and_publish(
    journal: &SqliteStore,
    ledger: &mut WorkItemStore,
    verifier: &dyn NormVerifier,
    artifact: &BuildArtifact,
    vocabulary: &VocabularyRef,
    authority: Option<&str>,
    actor: &NormActor,
    created_at: &str,
    sign: impl FnOnce(&NormStatement) -> Result<String, String>,
) -> Result<Published, String> {
    let payload = serde_json::to_string(artifact).map_err(|error| error.to_string())?;
    let instance = PreparedArtifactPublication::build_instance(artifact);
    // The same build recorded before is the same record: recover it rather
    // than commit a second one, as the publication path recovers its envelope.
    let existing = journal
        .list_events(&instance)
        .map_err(|error| format!("cannot read the build journal: {error:?}"))?
        .into_iter()
        .find(|event| {
            event.event_type == PreparedArtifactPublication::BUILD_RECORDED
                && event.payload_json == payload
        })
        .map(|event| event.event_id);
    let build_record = match existing {
        Some(event_id) => event_id,
        None => {
            let key = format!(
                "build.recorded:{}:{}:{}",
                artifact.cut, artifact.label, artifact.configuration
            );
            journal
                .append_event(NewEvent {
                    instance_id: &instance,
                    event_type: PreparedArtifactPublication::BUILD_RECORDED,
                    payload_json: &payload,
                    source: BUILD_RECORDED_SOURCE,
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: Some(&key),
                })
                .map_err(|error| format!("cannot record the build: {error:?}"))?
                .event_id
        }
    };
    let current = ledger
        .norm_state(verifier)
        .map_err(|error| format!("{error:?}"))?;
    let history = CapturedNormHistory::capture(
        &current,
        &ledger
            .tracker_history()
            .map_err(|error| format!("{error:?}"))?,
        verifier,
        NormHistoryLimits::default(),
    )
    .map_err(|error| format!("{error:?}"))?;
    let prepared = PreparedArtifactPublication::prepare(
        artifact,
        &build_record,
        &history,
        journal,
        verifier,
        ArtifactSigning {
            vocabulary,
            authority,
            actor,
            created_at,
        },
        sign,
    )?;
    let receipt = prepared.submit(ledger, verifier)?;
    receipt.acknowledge(journal)?;
    Ok(Published {
        build_record,
        event_id: receipt.event_id().to_owned(),
    })
}

/// Run the targets' tests through the executor and read its report.
pub(crate) fn test_targets(
    tree: &CutTree,
    targets: &[String],
    executor: &Path,
    report: &Path,
    timeout_seconds: u64,
) -> Result<(std::process::ExitStatus, Buck2TestReport), String> {
    let mut command = buck2(tree);
    command
        .arg("test")
        .args(targets)
        .arg("-c")
        .arg(format!("test.v2_test_executor={}", executor.display()))
        .arg("--")
        .arg("--report")
        .arg(report)
        .arg("--cut")
        .arg(&tree.cut)
        .arg("--timeout")
        .arg(timeout_seconds.to_string());
    let output = command
        .output()
        .map_err(|error| format!("cannot run buck2 test: {error}"))?;
    let bytes = std::fs::read(report).map_err(|error| {
        format!(
            "the executor left no report at {} ({}): {}",
            report.display(),
            error,
            String::from_utf8_lossy(&output.stderr).trim()
        )
    })?;
    let parsed: Buck2TestReport = serde_json::from_slice(&bytes)
        .map_err(|error| format!("the executor's report does not parse: {error}"))?;
    Ok((output.status, parsed))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verb {
    Artifact,
    Test,
    Daemon,
}

#[derive(Debug)]
struct Arguments<'a> {
    verb: Verb,
    name: &'a str,
    positional: Vec<&'a str>,
    flags: BTreeMap<&'a str, &'a str>,
}

/// The daemon subcommand a `build daemon` action maps to.
fn daemon_action(action: &str) -> Result<&'static str, String> {
    match action {
        "status" => Ok("status"),
        "stop" => Ok("kill"),
        other => Err(format!("unknown daemon action {other}")),
    }
}

impl<'a> Arguments<'a> {
    fn parse(args: &'a [String]) -> Result<Self, String> {
        let name = args.first().map(String::as_str).unwrap_or("");
        let (verb, allowed): (Verb, &[&str]) = match name {
            "artifact" => (Verb::Artifact, &["--cut", "--as", "--classification"]),
            "test" => (Verb::Test, &["--cut", "--report", "--timeout"]),
            "daemon" => (Verb::Daemon, &["--cut"]),
            _ => return Err(format!("unknown build command {name:?}\n{USAGE}")),
        };
        let mut parsed = Self {
            verb,
            name,
            positional: Vec::new(),
            flags: BTreeMap::new(),
        };
        let mut remaining = args.iter().skip(1);
        while let Some(arg) = remaining.next() {
            if arg.starts_with("--") {
                if !allowed.contains(&arg.as_str()) || parsed.flags.contains_key(arg.as_str()) {
                    return Err(format!("unknown or repeated build option {arg}"));
                }
                let value = remaining
                    .next()
                    .filter(|value| !value.starts_with("--"))
                    .ok_or_else(|| format!("build option {arg} needs a value"))?;
                parsed.flags.insert(arg, value);
            } else {
                parsed.positional.push(arg);
            }
        }
        if parsed.verb == Verb::Test && parsed.positional.is_empty() {
            return Err("build test needs at least one target".into());
        }
        Ok(parsed)
    }
    fn required(&self, name: &str) -> Result<&str, String> {
        self.flags
            .get(name)
            .copied()
            .ok_or_else(|| format!("build {} requires {name}", self.name))
    }
}

fn build_root() -> PathBuf {
    std::env::var_os("WHIPPLESCRIPT_BUILD_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".whipplescript/build"))
}

fn execute(options: &super::CliOptions) -> Result<Value, String> {
    let args = Arguments::parse(&options.args)?;
    let vcs = super::open_vcs().map_err(|_| "could not open the branch stores".to_owned())?;
    let cut = args.required("--cut")?;
    let tree = materialize_cut(&vcs, cut, &build_root(), &buck2_binary())?;
    match args.verb {
        Verb::Daemon => {
            let action = args
                .positional
                .first()
                .copied()
                .ok_or("build daemon needs status or stop")?;
            let mut command = buck2(&tree);
            command.arg(daemon_action(action)?);
            let output = run(command, &format!("{action} the daemon"))?;
            Ok(json!({
                "cut": tree.cut,
                "root": tree.root,
                "isolation_dir": HOME_ISOLATION_DIR,
                "buck2_version": tree.buck2_version,
                "pin": tree.pin,
                "output": String::from_utf8_lossy(&output.stdout).trim(),
            }))
        }
        Verb::Artifact => {
            let label = args
                .positional
                .first()
                .copied()
                .ok_or("build artifact needs a target label")?;
            let document = super::norm_commands::trust_document()?;
            let transport = super::norm_commands::custody_transport_for(&document)?;
            let trust =
                super::norm_commands::NormTrust::from_document(document, transport.as_deref())?;
            let verifier = trust.verifier()?;
            let signer = trust.key(args.required("--as")?)?;
            let mut items = WorkItemStore::open(super::items_store_path())
                .map_err(|error| format!("{error:?}"))?;
            let journal = super::open_store(&options.store_path)?;
            let view = items
                .norm_view(&verifier)
                .map_err(|error| format!("{error:?}"))?;
            let vocabulary = artifact_vocabulary(&view)?;
            let built = build_target(&tree, label)?;
            let classification = args
                .flags
                .get("--classification")
                .copied()
                .unwrap_or(ORGANIZATION_CEILING);
            let artifact = artifact(&tree, &built, &view.ledger, classification);
            let created_at = super::now_stamp();
            let published = record_and_publish(
                &journal,
                &mut items,
                &verifier,
                &artifact,
                &vocabulary,
                Some(&view.authority_head),
                signer.actor(),
                &created_at,
                |statement| signer.sign(statement),
            )?;
            Ok(json!({
                "record": published.event_id,
                "build_record": published.build_record,
                "artifact": artifact,
                "outputs": built.outputs.iter().map(|(path, digest)| json!({"path": path, "sha256": digest})).collect::<Vec<_>>(),
                "buck2_version": tree.buck2_version,
                "pin": tree.pin,
            }))
        }
        Verb::Test => {
            let targets: Vec<String> = args.positional.iter().map(|s| (*s).to_owned()).collect();
            let executor = executor_binary()?;
            let report = match args.flags.get("--report") {
                Some(path) => PathBuf::from(path),
                None => {
                    let dir = build_root().join("reports").join(&tree.cut);
                    std::fs::create_dir_all(&dir)
                        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
                    dir.join(format!("{}.json", super::now_stamp().replace(':', "-")))
                }
            };
            let timeout = match args.flags.get("--timeout") {
                Some(value) => value
                    .parse()
                    .map_err(|_| "--timeout needs a whole number of seconds".to_owned())?,
                None => 600,
            };
            let (status, parsed) = test_targets(&tree, &targets, &executor, &report, timeout)?;
            Ok(json!({
                "cut": tree.cut,
                "report": report,
                "buck2_status": status.code(),
                "executor_exit_code": parsed.exit_code,
                "trace_id": parsed.trace_id,
                "suites": parsed.suites.iter().map(|suite| json!({
                    "target": suite.target.label(),
                    "configuration": suite.target.configuration,
                    "listing": suite.listing,
                    "executions": suite.executions.iter().map(|execution| json!({
                        "case": execution.case, "status": execution.status, "verdict_line": execution.verdict_line,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            }))
        }
    }
}

pub(crate) fn command(options: &super::CliOptions) -> ExitCode {
    match execute(options) {
        Ok(value) => {
            if options.json {
                super::emit_json(value)
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).expect("JSON value")
                );
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("build: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_labels_and_output_digests_are_read_as_buck2_prints_them() {
        assert_eq!(
            parse_configured_label("root//:passing (<unspecified>)"),
            Some(("root//:passing".into(), "<unspecified>".into()))
        );
        assert_eq!(
            parse_configured_label("cell//pkg:t (prelude//platforms:default#abc123)"),
            Some((
                "cell//pkg:t".into(),
                "prelude//platforms:default#abc123".into()
            ))
        );
        assert_eq!(parse_configured_label("nonsense"), None);
        assert_eq!(parse_configured_label(" (cfg)"), None);
        let dir = tempfile::tempdir().expect("a temporary directory");
        std::fs::write(dir.path().join("b.txt"), b"bee").expect("write");
        std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
        std::fs::write(dir.path().join("sub").join("a.txt"), b"ay").expect("write");
        let file = digest_path(&dir.path().join("b.txt")).expect("a file digests");
        assert_eq!(file, hex(&Sha256::digest(b"bee")));
        let tree = digest_path(dir.path()).expect("a directory digests");
        assert_eq!(tree.len(), 64);
        std::fs::write(dir.path().join("sub").join("a.txt"), b"changed").expect("write");
        assert_ne!(digest_path(dir.path()).expect("digests again"), tree);
    }

    #[test]
    fn the_executor_is_named_by_the_host_or_found_beside_whip() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let whip = dir.path().join("whip");
        assert_eq!(
            executor_binary_from(Some(PathBuf::from("/named/executor")), &whip).unwrap(),
            PathBuf::from("/named/executor")
        );
        assert_eq!(
            executor_binary_from(None, &whip).unwrap_err(),
            format!(
                "no whip-test-executor beside whip at {}; set WHIPPLESCRIPT_TEST_EXECUTOR",
                dir.path().join("whip-test-executor").display()
            )
        );
        std::fs::write(dir.path().join("whip-test-executor"), b"").expect("write");
        assert_eq!(
            executor_binary_from(None, &whip).unwrap(),
            dir.path().join("whip-test-executor")
        );
    }

    /// A stand-in buck2: answers `--version`, and fails everything else with
    /// `boom` on stderr — or fails `--version` too when `broken` is set.
    fn fake_buck2(dir: &Path, broken: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(if broken { "broken-buck2" } else { "buck2" });
        let script = if broken {
            "#!/bin/sh\necho 'no buck2 here' >&2\nexit 3\n".to_owned()
        } else {
            "#!/bin/sh\nfor a in \"$@\"; do if [ \"$a\" = --version ]; then echo 'buck2 fake'; exit 0; fi; done\necho boom >&2\nexit 1\n".to_owned()
        };
        std::fs::write(&path, script).expect("write the stand-in");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[test]
    fn a_cut_is_materialized_only_when_recorded_and_only_for_a_buck2_that_answers() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let mut vcs = NativeWorkspaceVcs::open(
            dir.path().join("branches.sqlite"),
            dir.path().join("content.sqlite"),
        )
        .expect("a vcs");
        vcs.init("t0").expect("init");
        let build_root = dir.path().join("build");
        let buck2 = fake_buck2(dir.path(), false);
        assert_eq!(
            materialize_cut(&vcs, "nope", &build_root, &buck2).unwrap_err(),
            "no recorded cut nope"
        );
        vcs.write("main", "FIXTURE", Some("# empty\n"), "cut-1", "t1")
            .expect("record a cut");
        let broken = fake_buck2(dir.path(), true);
        assert_eq!(
            materialize_cut(&vcs, "cut-1", &build_root, &broken).unwrap_err(),
            format!("{} --version failed: no buck2 here", broken.display())
        );
        let tree = materialize_cut(&vcs, "cut-1", &build_root, &buck2).expect("materializes");
        assert_eq!(tree.buck2_version, "buck2 fake");
        assert!(tree.root.join("FIXTURE").is_file());
        assert_eq!(tree.pin, None);
        // Every daemon invocation reports buck2's own failure, never a guess.
        assert_eq!(
            build_target(&tree, "//:x").unwrap_err(),
            "buck2 failed to configure //:x (exit status: 1):\nboom"
        );
    }

    #[test]
    fn daemon_actions_are_the_two_named() {
        assert_eq!(daemon_action("status").unwrap(), "status");
        assert_eq!(daemon_action("stop").unwrap(), "kill");
        assert_eq!(
            daemon_action("restart").unwrap_err(),
            "unknown daemon action restart"
        );
    }

    fn owned(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn build_arguments_are_checked_by_name() {
        let list = owned(&["artifact", "//:x", "--cut", "c1", "--as", "owner"]);
        let args = Arguments::parse(&list).unwrap();
        assert_eq!(args.positional, vec!["//:x"]);
        assert_eq!(args.required("--cut").unwrap(), "c1");
        assert!(Arguments::parse(&owned(&["nope"]))
            .unwrap_err()
            .contains("unknown build command"));
        assert!(Arguments::parse(&owned(&["test", "--report"]))
            .unwrap_err()
            .contains("needs a value"));
        assert!(Arguments::parse(&owned(&["artifact", "--report", "x"]))
            .unwrap_err()
            .contains("unknown or repeated build option"));
        let daemon = owned(&["daemon", "status"]);
        assert!(Arguments::parse(&daemon)
            .unwrap()
            .required("--cut")
            .unwrap_err()
            .contains("requires --cut"));
        assert_eq!(
            Arguments::parse(&owned(&["test", "--cut", "c1"])).unwrap_err(),
            "build test needs at least one target"
        );
    }
}
