//! `whip build`: the Home's build-engine wrapper of DR-0124 §14.1.
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
//! Every command acts as a principal — a trust binding with the labels the
//! Home grants it — and reaches the daemon only through here (§14.1). Two
//! tiers: `artifact` and `test` are the Home's daemon over the full cut, the
//! gated tier, and a principal may trigger and read only what the package
//! ceiling (`build_scope`) classifies within their labels — a refusal is
//! reported as a refusal, and what their view cannot establish is
//! unobserved, never absent. `iterate` is the ungated tier: the principal's
//! own daemon over their projection of the cut, whose record claims only
//! that tree. `correspond` is how the ungated tier says something about the
//! cut: a checked correspondence, published only after the wrapper compared
//! the two records' outputs, that binds both revisions as premises.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use whipplescript_core::norm_buck2_report::Buck2TestReport;
use whipplescript_core::vocabulary::{Vocabulary, VocabularyRef};
use whipplescript_kernel::norm_artifact_publication::{
    ArtifactSigning, BuildArtifact, PreparedArtifactPublication, INPUT_ROOT_ENCODING_V1,
};
use whipplescript_store::items::WorkItemStore;
use whipplescript_store::norm::{
    NormAct, NormActor, NormPremises, NormRecord, NormStatement, NormVerifier, NormView,
    SignedNormEvent,
};
use whipplescript_store::norm_commands::NormCommandStore;
use whipplescript_store::norm_history::{CapturedNormHistory, NormHistoryLimits};
use whipplescript_store::vcs::NativeWorkspaceVcs;
use whipplescript_store::{NewEvent, SqliteStore};

use super::build_scope::{
    classify, project, ActionInfluences, Cells, Classification, LabelPolicy, Packages, Principal,
    Projection,
};

pub(crate) const USAGE: &str = "usage: whip [--json] build <command> --as <binding>\n\
  artifact <label> --cut <cut>      build one target with the Home's daemon over the full cut; publish its record\n\
  iterate <label> --cut <cut>       build one target over the binding's projection of the cut: ungated, claims that tree\n\
  correspond <label> --cut <cut>    publish the checked correspondence from the projected result to the cut's\n\
  result <label> --cut <cut>        read the cut's results for a label under the binding's view\n\
  test <target>... --cut <cut> [--report <file>] [--timeout <seconds>]\n\
  daemon status|stop --cut <cut>\n\
  endpoint --cut <cut> [--sidecar <http://host:port>]\n\
                                    serve the remote-execution endpoint to the cut's daemon until stdin closes;\n\
                                    with --sidecar its actions run at that `whip executor`\n\
  record <dir> [--cut <id>] [--branch <name>]   record a directory tree (a git workspace, its cells) as a cut\n\
  The cut is materialized under .whipplescript/build/cuts/<cut> and evaluated there by the\n\
  Home's Buck2 daemon (isolation dir whip-home), which reaches whip-test-executor over the TCP launch.\n\
  Host configuration: WHIPPLESCRIPT_NORM_TRUST (bindings with labels, and labeled regions);\n\
  WHIPPLESCRIPT_BUCK2 (the pinned buck2, default: buck2 on the PATH); WHIPPLESCRIPT_TEST_EXECUTOR\n\
  (default: whip-test-executor beside whip); WHIPPLESCRIPT_REMOTE_EXECUTION (default:\n\
  whip-remote-execution beside whip).";

/// The Home daemon's isolation directory: one daemon per materialized cut,
/// never the developer's own.
pub(crate) const HOME_ISOLATION_DIR: &str = "whip-home";

/// The interim classification basis every result carried before the
/// qualification experiment of §14.2 chose the package ceiling: the
/// organization's, which names every label the policy declares.
pub(crate) const ORGANIZATION_CEILING: &str = "ceiling:organization";

/// The journal event the wrapper appends before it publishes: the durable
/// build record a retention rests on (§14.6).
pub(crate) const BUILD_RECORDED_SOURCE: &str = "whip build";

/// A cut materialized for a daemon: the Home's over the whole cut, or a
/// principal's over their projection of it.
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
    /// The daemon that evaluates this tree.
    pub isolation_dir: String,
    /// The manifest that was projected: the cut's, or the projection's subset.
    pub manifest: BTreeMap<String, String>,
    /// The projection, when this is a principal's tree and not the cut.
    pub projection: Option<Projection>,
    /// The tree's cells: the explicit name-to-directory mapping every label
    /// is placed in the tree through (GaugeWright DR-0125).
    pub cells: Cells,
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
    beside_whip(
        named,
        whip,
        "whip-test-executor",
        "WHIPPLESCRIPT_TEST_EXECUTOR",
    )
}

/// The remote-execution endpoint the wrapper serves to a daemon (§14.4):
/// named by the host, or the binary installed beside `whip`.
pub(crate) fn endpoint_binary() -> Result<PathBuf, String> {
    let whip =
        std::env::current_exe().map_err(|error| format!("cannot locate whip itself: {error}"))?;
    beside_whip(
        std::env::var_os("WHIPPLESCRIPT_REMOTE_EXECUTION").map(PathBuf::from),
        &whip,
        "whip-remote-execution",
        "WHIPPLESCRIPT_REMOTE_EXECUTION",
    )
}

fn beside_whip(
    named: Option<PathBuf>,
    whip: &Path,
    binary: &str,
    variable: &str,
) -> Result<PathBuf, String> {
    if let Some(path) = named {
        return Ok(path);
    }
    let beside = whip.with_file_name(binary);
    if beside.is_file() {
        Ok(beside)
    } else {
        Err(format!(
            "no {binary} beside whip at {}; set {variable}",
            beside.display()
        ))
    }
}

/// The Buck2 client configuration that points a daemon at the endpoint:
/// written beside the tree's `.buckconfig`, never into it, as the cut's own
/// content stays exactly the cut.
pub(crate) fn endpoint_client_config(address: &str) -> String {
    format!(
        "# Written by `whip build endpoint` (DR-0124 §14.4): the wrapper's remote-execution\n\
# endpoint for this tree's daemon. Every action, cache lookup and blob goes through it.\n\
[buck2_re_client]\n\
engine_address = grpc://{address}\n\
action_cache_address = grpc://{address}\n\
cas_address = grpc://{address}\n\
tls = false\n\
instance_name = main\n\
\n\
[buck2]\n\
digest_algorithms = SHA256\n"
    )
}

/// What the endpoint process announced on its first line.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct EndpointAnnouncement {
    pub address: String,
    pub executor: String,
    #[serde(default)]
    pub handles: BTreeMap<String, String>,
}

pub(crate) fn parse_endpoint_announcement(line: &str) -> Result<EndpointAnnouncement, String> {
    serde_json::from_str(line.trim())
        .map_err(|error| format!("the endpoint announced nothing readable: {error}"))
}

fn now_unix_nanos() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(0))
        .unwrap_or(0)
}

/// A recorded cut's manifest; an unrecorded cut is refused by name.
pub(crate) fn cut_manifest_of(
    vcs: &NativeWorkspaceVcs,
    cut: &str,
) -> Result<BTreeMap<String, String>, String> {
    let manifest = vcs
        .cut_manifest(cut)
        .map_err(|error| format!("cannot read cut {cut}: {error:?}"))?;
    let Some(manifest) = manifest else {
        return Err(format!("no recorded cut {cut}"));
    };
    Ok(manifest)
}

/// Materialize the whole cut under the build root for the Home's daemon and
/// learn which Buck2 will evaluate it.
pub(crate) fn materialize_cut(
    vcs: &NativeWorkspaceVcs,
    cut: &str,
    build_root: &Path,
    buck2: &Path,
) -> Result<CutTree, String> {
    let manifest = cut_manifest_of(vcs, cut)?;
    let root = build_root.join("cuts").join(cut);
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    vcs.materialize_cut(cut, &root, now_unix_nanos())
        .map_err(|error| format!("cannot materialize cut {cut}: {error:?}"))?;
    finish_tree(
        cut,
        root,
        buck2,
        HOME_ISOLATION_DIR.to_owned(),
        manifest,
        None,
    )
}

/// Materialize a principal's projection of the cut — the regions their
/// labels permit — under its own directory, named by the projection's
/// digest so a changed label set never builds over a stale tree, for the
/// principal's own daemon.
pub(crate) fn materialize_projection(
    vcs: &NativeWorkspaceVcs,
    cut: &str,
    build_root: &Path,
    buck2: &Path,
    policy: &LabelPolicy,
    principal: &Principal,
) -> Result<CutTree, String> {
    let manifest = cut_manifest_of(vcs, cut)?;
    let projection = project(&manifest, policy, principal);
    let short = projection
        .id
        .rsplit(':')
        .next()
        .map(|digest| digest.chars().take(16).collect::<String>())
        .unwrap_or_default();
    let root = build_root
        .join("projections")
        .join(&principal.name)
        .join(cut)
        .join(short);
    std::fs::create_dir_all(&root)
        .map_err(|error| format!("cannot create {}: {error}", root.display()))?;
    vcs.materialize_cut_subset(cut, &projection.include, &root, now_unix_nanos())
        .map_err(|error| format!("cannot materialize the projection of cut {cut}: {error:?}"))?;
    let projected = manifest
        .into_iter()
        .filter(|(path, _)| projection.include.contains(path))
        .collect();
    finish_tree(
        cut,
        root,
        buck2,
        format!("whip-projection-{}", principal.name),
        projected,
        Some(projection),
    )
}

fn finish_tree(
    cut: &str,
    root: PathBuf,
    buck2: &Path,
    isolation_dir: String,
    manifest: BTreeMap<String, String>,
    projection: Option<Projection>,
) -> Result<CutTree, String> {
    // Buck2 prints canonical paths, so the tree's root is the canonical one.
    let root = root
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", root.display()))?;
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
    let cells = Cells::from_configs(
        std::fs::read_to_string(root.join(".buckconfig"))
            .ok()
            .as_deref(),
        |dir| std::fs::read_to_string(root.join(dir).join(".buckconfig")).ok(),
    );
    Ok(CutTree {
        cut: cut.to_owned(),
        root,
        pin,
        buck2_version: String::from_utf8_lossy(&version.stdout).trim().to_owned(),
        buck2: buck2.to_path_buf(),
        isolation_dir,
        manifest,
        projection,
        cells,
    })
}

/// What recording a tree produced.
#[derive(Clone, Debug, serde::Serialize)]
pub(crate) struct RecordedTree {
    pub cut: String,
    pub branch: String,
    pub files: usize,
    pub bytes: usize,
}

/// The files of a directory tree as a cut would hold them: a git
/// repository's tracked and unignored files, a plain directory's files, and
/// nested git repositories — the cells of a workspace — the same way, each
/// under its directory; never `.git` or `buck-out`.
pub(crate) fn tree_files(root: &Path) -> Result<Vec<(String, PathBuf)>, String> {
    let mut files = Vec::new();
    walk_tree(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_tree(root: &Path, dir: &Path, into: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    let relative = |path: &Path| {
        path.strip_prefix(root)
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .unwrap_or_default()
    };
    if dir.join(".git").exists() {
        let listed = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args([
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ])
            .output()
            .map_err(|error| format!("cannot run git in {}: {error}", dir.display()))?;
        if !listed.status.success() {
            return Err(format!(
                "git ls-files failed in {}: {}",
                dir.display(),
                String::from_utf8_lossy(&listed.stderr).trim()
            ));
        }
        for entry in listed.stdout.split(|b| *b == 0).filter(|e| !e.is_empty()) {
            let entry = String::from_utf8_lossy(entry).into_owned();
            let path = dir.join(&entry);
            if entry.ends_with('/') {
                // A nested repository: git lists its directory, not its files.
                walk_tree(root, &dir.join(entry.trim_end_matches('/')), into)?;
            } else if path.is_file() && !entry.starts_with("buck-out/") {
                into.push((relative(&path), path));
            }
        }
        return Ok(());
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name == ".git" || name == "buck-out" {
                continue;
            }
            walk_tree(root, &path, into)?;
        } else if path.is_file() {
            into.push((relative(&path), path));
        }
    }
    Ok(())
}

/// Record a directory tree as one cut on a branch of the Home's store: every
/// file's bytes into the content store, the whole tree as one import, keyed
/// by the tree's own digest unless a cut id is given, so recording the same
/// tree twice is the same cut. The branch is created off the mainline when
/// it does not exist, and never the mainline itself.
pub(crate) fn record_tree(
    vcs: &mut NativeWorkspaceVcs,
    root: &Path,
    branch: &str,
    cut: Option<&str>,
    at: &str,
) -> Result<RecordedTree, String> {
    if branch == NativeWorkspaceVcs::mainline() {
        return Err("a recorded tree never lands on the mainline; name a build branch".into());
    }
    let files = tree_files(root)?;
    if files.is_empty() {
        return Err(format!("nothing to record under {}", root.display()));
    }
    let mut changed = BTreeMap::new();
    let mut bytes = 0;
    let mut digest = Sha256::new();
    for (relative, path) in &files {
        let body = std::fs::read(path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        bytes += body.len();
        let id = vcs
            .content_store()
            .put(&body)
            .map_err(|error| format!("cannot store {}: {error:?}", path.display()))?;
        digest.update(relative.as_bytes());
        digest.update(b"\0");
        digest.update(id.as_bytes());
        digest.update(b"\n");
        changed.insert(relative.clone(), id);
    }
    let cut = match cut {
        Some(cut) => cut.to_owned(),
        None => format!("tree:{}", &hex(&digest.finalize())[..32]),
    };
    let branches = vcs
        .list_branches(None)
        .map_err(|error| format!("cannot list branches: {error:?}"))?;
    let existing = branches.iter().find(|row| row.branch_id == branch);
    let removed: Vec<String> = match existing.and_then(|row| row.head_cut_id.clone()) {
        Some(head) => cut_manifest_of(vcs, &head)?
            .keys()
            .filter(|path| !changed.contains_key(*path))
            .cloned()
            .collect(),
        None => Vec::new(),
    };
    if existing.is_none() {
        vcs.create_branch(branch, None, NativeWorkspaceVcs::mainline(), at)
            .map_err(|error| format!("cannot create branch {branch}: {error:?}"))?;
    }
    let outcome = vcs
        .import_diff(branch, &changed, &removed, &cut, at)
        .map_err(|error| format!("cannot record the tree: {error:?}"))?;
    recorded(outcome, branch, files.len(), bytes)
}

/// The recording the store reports, or the refusal it is.
fn recorded(
    outcome: whipplescript_store::vcs::VcsWriteOutcome,
    branch: &str,
    files: usize,
    bytes: usize,
) -> Result<RecordedTree, String> {
    match outcome {
        whipplescript_store::vcs::VcsWriteOutcome::Written { cut_id, .. } => Ok(RecordedTree {
            cut: cut_id,
            branch: branch.to_owned(),
            files,
            bytes,
        }),
        other => Err(format!("the tree was not recorded: {other:?}")),
    }
}

/// The tree's daemon: its isolation directory, and the environment under
/// which it launches the executor over TCP.
pub(crate) fn buck2(tree: &CutTree) -> Command {
    let mut command = Command::new(&tree.buck2);
    command
        .current_dir(&tree.root)
        .arg("--isolation-dir")
        .arg(&tree.isolation_dir)
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

/// The cell and package of `cell//package:target`.
pub(crate) fn package_of_label(label: &str) -> Option<(String, String)> {
    let (cell, rest) = label.split_once("//")?;
    let (package, name) = rest.split_once(':')?;
    if name.is_empty() || cell.is_empty() {
        return None;
    }
    Some((cell.to_owned(), package.to_owned()))
}

/// A path Buck2 printed, made relative to the tree: an absolute path under
/// the root, or a `cell//path` reference placed through the cell map.
fn tree_relative(root: &Path, cells: &Cells, printed: &str) -> String {
    let printed = printed.trim();
    if let Ok(relative) = Path::new(printed).strip_prefix(root) {
        return relative.to_string_lossy().into_owned();
    }
    match printed.split_once("//") {
        Some((cell, path)) if !cell.contains('/') => cells
            .tree_path(cell, path)
            .unwrap_or_else(|| path.to_owned()),
        _ => printed.to_owned(),
    }
}

/// What shaped the actions of every target a pattern resolves to, asked of
/// the tree's daemon: the package each build file evaluated in, the rule
/// files it loaded, and the sources the actions read.
pub(crate) fn influences_of(
    tree: &CutTree,
    pattern: &str,
) -> Result<Vec<ActionInfluences>, String> {
    let mut deps = buck2(tree);
    deps.arg("cquery").arg(format!("deps({pattern})"));
    let resolved = run(deps, &format!("resolve the dependencies of {pattern}"))?;
    let mut influences = Vec::new();
    for (label, _) in String::from_utf8_lossy(&resolved.stdout)
        .lines()
        .filter_map(parse_configured_label)
    {
        let (cell, package) = package_of_label(&label)
            .ok_or_else(|| format!("buck2 printed a label without a package: {label}"))?;
        let build_file = tree
            .cells
            .build_files(&cell)
            .iter()
            .filter_map(|name| {
                let relative = if package.is_empty() {
                    name.clone()
                } else {
                    format!("{package}/{name}")
                };
                tree.cells.tree_path(&cell, &relative)
            })
            .find(|path| tree.manifest.contains_key(path))
            .ok_or_else(|| format!("the tree holds no build file for package {cell}//{package}"))?;
        let mut audit = buck2(tree);
        audit.arg("audit").arg("includes").arg(&build_file);
        let listed = run(audit, &format!("list the includes of {build_file}"))?;
        let includes = String::from_utf8_lossy(&listed.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| tree_relative(&tree.root, &tree.cells, line))
            .collect();
        let mut inputs = buck2(tree);
        inputs.arg("cquery").arg(format!("inputs({label})"));
        let read = run(inputs, &format!("list the inputs of {label}"))?;
        let inputs = String::from_utf8_lossy(&read.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(|line| tree_relative(&tree.root, &tree.cells, line))
            .collect();
        influences.push(ActionInfluences {
            target: label,
            cell,
            package,
            includes,
            inputs,
        });
    }
    Ok(influences)
}

/// The package ceiling over everything a pattern resolves to in this tree.
pub(crate) fn classification_of(
    tree: &CutTree,
    pattern: &str,
    policy: &LabelPolicy,
) -> Result<Classification, String> {
    let packages = Packages::of_manifest(&tree.manifest, &tree.cells);
    Ok(classify(
        &tree.manifest,
        policy,
        &packages,
        &influences_of(tree, pattern)?,
    ))
}

/// The daemon itself — its status, its end — is the Home operator's: a
/// principal holding every declared label.
pub(crate) fn operator_only(principal: &Principal, policy: &LabelPolicy) -> Result<(), String> {
    if principal.holds(&policy.labels()) {
        Ok(())
    } else {
        Err(format!(
            "build daemon is the Home operator's: {} does not hold every label",
            principal.name
        ))
    }
}

/// A principal may trigger, and read, only actions whose classification they
/// hold (§14.2). The refusal names itself: it is not an absence.
pub(crate) fn admit_trigger(
    principal: &Principal,
    pattern: &str,
    classification: &Classification,
) -> Result<(), String> {
    if principal.holds(&classification.labels) {
        Ok(())
    } else {
        Err(format!(
            "{pattern} is classified {}, which {} does not hold: refused, not absent",
            classification.basis(),
            principal.name
        ))
    }
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

/// Build one target in the tree through its daemon and digest its outputs.
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

/// The artifact record a built target becomes: the cut's, or — when the tree
/// is a projection — the projection's, which claims only that tree.
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
        projection: tree
            .projection
            .as_ref()
            .map(|projection| projection.id.clone()),
    }
}

/// A named vocabulary in the ledger's charter.
pub(crate) fn charter_vocabulary(view: &NormView, name: &str) -> Result<VocabularyRef, String> {
    let entry = view
        .charter
        .vocabularies
        .iter()
        .find(|entry| entry.definition.name == name)
        .ok_or_else(|| format!("the ledger's charter declares no {name} vocabulary"))?;
    Vocabulary::new(entry.definition.clone())
        .map(|vocabulary| vocabulary.reference().clone())
        .map_err(|error| error.to_string())
}

/// The artifact's `artifact` vocabulary in the ledger's charter.
pub(crate) fn artifact_vocabulary(view: &NormView) -> Result<VocabularyRef, String> {
    charter_vocabulary(view, "artifact")
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
                "build.recorded:{}:{}:{}:{}",
                artifact.cut,
                artifact.label,
                artifact.configuration,
                artifact.projection.as_deref().unwrap_or("")
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

/// The artifact records of a cut and label: the cut's own (no projection),
/// or one projection's, in configuration order.
pub(crate) fn artifact_records<'v>(
    view: &'v NormView,
    cut: &str,
    label: &str,
    projection: Option<&str>,
) -> Vec<&'v NormRecord> {
    let mut records: Vec<&NormRecord> = view
        .records
        .values()
        .filter(|record| {
            record.vocabulary.name == "artifact"
                && record.fields["cut"] == cut
                && record.fields["label"] == label
                && record.fields.get("projection").and_then(Value::as_str) == projection
        })
        .collect();
    records.sort_by(|a, b| {
        a.fields["configuration"]
            .as_str()
            .cmp(&b.fields["configuration"].as_str())
            .then(a.id.cmp(&b.id))
    });
    records
}

/// An artifact record as a principal's result interface sees it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ArtifactSeen {
    pub record: String,
    pub revision: String,
    pub configuration: String,
    pub classification: String,
    pub outputs: Vec<String>,
}

/// The result interface (§14.1, §14.2): a record whose classification the
/// principal holds is read; one they do not hold is unobserved — the view
/// reports neither its fields nor its existence.
pub(crate) fn scoped_result(
    record: &NormRecord,
    policy: &LabelPolicy,
    principal: &Principal,
) -> Result<Option<ArtifactSeen>, String> {
    let basis = record.fields["classification"]
        .as_str()
        .ok_or("an artifact record carries no classification basis")?;
    let labels = Classification::labels_of_basis(basis, policy)?;
    if !principal.holds(&labels) {
        return Ok(None);
    }
    Ok(Some(ArtifactSeen {
        record: record.id.clone(),
        revision: record.content_head.clone(),
        configuration: record.fields["configuration"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        classification: basis.to_owned(),
        outputs: record.fields["outputs"]
            .as_array()
            .map(|outputs| {
                outputs
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    }))
}

/// The checked correspondence from a projected result to the cut's (§14.1):
/// admissible only when the wrapper compared the two and found the outputs
/// equal under the same configuration.
pub(crate) fn correspondence_fields(
    label: &str,
    projected: &ArtifactSeen,
    cut_result: &ArtifactSeen,
    projection: &Projection,
    cut: &str,
) -> Result<Value, String> {
    if projected.configuration != cut_result.configuration {
        return Err(format!(
            "the projected build of {label} and the cut's were configured differently: {} against {}",
            projected.configuration, cut_result.configuration
        ));
    }
    if projected.outputs != cut_result.outputs {
        return Err(format!(
            "the projected build's outputs differ from the cut's for {label}: no correspondence"
        ));
    }
    Ok(json!({
        "sources": [projected.revision],
        "targets": [cut_result.revision],
        "claim": "equivalence",
        "property": "outputs",
        "direction": "forward",
        "witness": format!(
            "whip build correspond: {} output digest(s) of {label} equal between {} and cut {cut}, with {} region(s) unobserved under the projection",
            projected.outputs.len(), projection.id, projection.unobserved.len()
        ),
        "mode": "checked",
        "reliance": "the projected build's outputs stand for the cut's under this configuration; the cut's classification, not the projection's, governs who reads them",
    }))
}

/// The principal's own iteration result over their projection, which must
/// exist before a correspondence can be checked.
pub(crate) fn projected_result(
    found: Option<ArtifactSeen>,
    label: &str,
    principal: &Principal,
    cut: &str,
) -> Result<ArtifactSeen, String> {
    found.ok_or_else(|| {
        format!(
            "no iteration result for {label} over {}'s projection of {cut}: run build iterate first",
            principal.name
        )
    })
}

/// The cut's result as the principal's view holds it. A result the view does
/// not hold and a result that was never published read the same: unobserved,
/// never absent.
pub(crate) fn cut_result_under_view(
    found: Option<ArtifactSeen>,
    label: &str,
    principal: &Principal,
) -> Result<ArtifactSeen, String> {
    if let Some(seen) = found {
        return Ok(seen);
    }
    Err(format!(
        "the cut's result for {label} is unobserved under {}'s view",
        principal.name
    ))
}

/// Publish a correspondence record binding both revisions as premises.
#[allow(clippy::too_many_arguments)]
pub(crate) fn publish_correspondence(
    ledger: &mut WorkItemStore,
    verifier: &dyn NormVerifier,
    view: &NormView,
    fields: &Value,
    references: Vec<String>,
    actor: &NormActor,
    created_at: &str,
    sign: impl FnOnce(&NormStatement) -> Result<String, String>,
) -> Result<String, String> {
    let vocabulary = charter_vocabulary(view, "correspondence")?;
    let parts: Vec<&str> = std::iter::once("norm-correspondence")
        .chain(std::iter::once(view.ledger.as_str()))
        .chain(references.iter().map(String::as_str))
        .collect();
    let statement = NormStatement {
        protocol: "whipplescript.norm/v1".into(),
        actor: actor.clone(),
        nonce: whipplescript_kernel::idempotency_key(&parts),
        created_at: created_at.into(),
        action: NormAct::Create {
            ledger: view.ledger.clone(),
            authority: Some(view.authority_head.clone()),
            vocabulary,
            fields_json: fields.to_string(),
        },
        premises: Some(NormPremises {
            family_basis: None,
            references,
            inventory_frontier: Vec::new(),
        }),
    };
    let signature = sign(&statement)?;
    ledger
        .append_norm_event(
            &SignedNormEvent {
                statement,
                signature,
                successor_signature: None,
            },
            verifier,
        )
        .map_err(|error| format!("{error:?}"))
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
    Iterate,
    Correspond,
    Result,
    Test,
    Daemon,
    Endpoint,
    Record,
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
            "artifact" => (Verb::Artifact, &["--cut", "--as"]),
            "iterate" => (Verb::Iterate, &["--cut", "--as"]),
            "correspond" => (Verb::Correspond, &["--cut", "--as"]),
            "result" => (Verb::Result, &["--cut", "--as"]),
            "test" => (Verb::Test, &["--cut", "--as", "--report", "--timeout"]),
            "daemon" => (Verb::Daemon, &["--cut", "--as"]),
            "endpoint" => (Verb::Endpoint, &["--cut", "--as", "--sidecar"]),
            "record" => (Verb::Record, &["--as", "--cut", "--branch"]),
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
    fn label(&self) -> Result<&str, String> {
        self.positional
            .first()
            .copied()
            .ok_or_else(|| format!("build {} needs a target label", self.name))
    }
}

fn build_root() -> PathBuf {
    std::env::var_os("WHIPPLESCRIPT_BUILD_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".whipplescript/build"))
}

/// The ledger, the journal and the ledger's current view.
struct Ledger {
    items: WorkItemStore,
    journal: SqliteStore,
    view: NormView,
}

fn open_ledger(options: &super::CliOptions, verifier: &dyn NormVerifier) -> Result<Ledger, String> {
    let items =
        WorkItemStore::open(super::items_store_path()).map_err(|error| format!("{error:?}"))?;
    let journal = super::open_store(&options.store_path)?;
    let view = items
        .norm_view(verifier)
        .map_err(|error| format!("{error:?}"))?;
    Ok(Ledger {
        items,
        journal,
        view,
    })
}

fn execute(options: &super::CliOptions) -> Result<Value, String> {
    let args = Arguments::parse(&options.args)?;
    let mut vcs = super::open_vcs().map_err(|_| "could not open the branch stores".to_owned())?;
    let binding = args.required("--as")?;
    let document = super::norm_commands::trust_document()?;
    let transport = super::norm_commands::custody_transport_for(&document)?;
    let trust = super::norm_commands::NormTrust::from_document(document, transport.as_deref())?;
    let verifier = trust.verifier()?;
    let signer = trust.key(binding)?;
    let principal = trust.principal(binding)?;
    let policy = &trust.policy;
    let buck2_binary = buck2_binary();
    let build_root = build_root();
    if args.verb == Verb::Record {
        // Recording a tree is the Home's act: what the daemon will evaluate.
        operator_only(principal, policy)?;
        let dir = args
            .positional
            .first()
            .copied()
            .ok_or("build record needs a directory")?;
        let recorded = record_tree(
            &mut vcs,
            Path::new(dir),
            args.flags.get("--branch").copied().unwrap_or("build"),
            args.flags.get("--cut").copied(),
            &super::now_stamp(),
        )?;
        return Ok(json!(recorded));
    }
    let cut = args.required("--cut")?;
    match args.verb {
        Verb::Record => unreachable!("answered above"),
        Verb::Daemon => {
            operator_only(principal, policy)?;
            let tree = materialize_cut(&vcs, cut, &build_root, &buck2_binary)?;
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
                "isolation_dir": tree.isolation_dir,
                "buck2_version": tree.buck2_version,
                "pin": tree.pin,
                "output": String::from_utf8_lossy(&output.stdout).trim(),
            }))
        }
        Verb::Endpoint => {
            // The endpoint the Home's daemon reaches is the operator's to
            // serve; it admits every binding, and the daemon acts as this one.
            operator_only(principal, policy)?;
            let tree = materialize_cut(&vcs, cut, &build_root, &buck2_binary)?;
            let binary = endpoint_binary()?;
            let mut command = Command::new(&binary);
            command
                .arg("--listen")
                .arg("127.0.0.1:0")
                .arg("--scratch")
                .arg(build_root.join("actions"))
                // The store and the action cache outlive this process: the
                // next endpoint over the same build root serves what this one
                // stored and executed.
                .arg("--state")
                .arg(build_root.join("endpoint.sqlite"))
                // Its bytes are the workspace's content store, stored once for
                // both planes and under the workspace's erasure (§14.3).
                .arg("--content")
                .arg(super::vcs_content_store_path())
                .args(
                    // Actions run at a Class-A executor rather than on this
                    // host when the operator names one (§14.4).
                    args.flags
                        .get("--sidecar")
                        .map(|url| vec!["--sidecar", *url])
                        .unwrap_or_default(),
                )
                .arg("--daemon")
                .arg(binding)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped());
            for admitted in trust.principals() {
                let mut spec = admitted.name.clone();
                if !admitted.labels.is_empty() {
                    spec.push('=');
                    spec.push_str(
                        &admitted
                            .labels
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                }
                command.arg("--principal").arg(spec);
            }
            let mut child = command
                .spawn()
                .map_err(|error| format!("cannot start {}: {error}", binary.display()))?;
            let mut first = String::new();
            {
                use std::io::BufRead;
                let stdout = child.stdout.take().ok_or("the endpoint has no stdout")?;
                std::io::BufReader::new(stdout)
                    .read_line(&mut first)
                    .map_err(|error| format!("cannot read the endpoint's announcement: {error}"))?;
            }
            let announced = parse_endpoint_announcement(&first)?;
            let config = tree.root.join(".buckconfig.local");
            std::fs::write(&config, endpoint_client_config(&announced.address))
                .map_err(|error| format!("cannot write {}: {error}", config.display()))?;
            println!(
                "{}",
                json!({
                    "cut": tree.cut,
                    "root": tree.root,
                    "address": announced.address,
                    "executor": announced.executor,
                    "daemon": binding,
                    "handles": announced.handles,
                    "state": build_root.join("endpoint.sqlite"),
                    "content": super::vcs_content_store_path(),
                    "config": config,
                })
            );
            // The endpoint lives as long as this command: its stdin is ours.
            let status = child
                .wait()
                .map_err(|error| format!("the endpoint did not finish: {error}"))?;
            Ok(json!({"endpoint_exit": status.code()}))
        }
        Verb::Artifact | Verb::Iterate => {
            let label = args.label()?;
            let tree = if args.verb == Verb::Artifact {
                materialize_cut(&vcs, cut, &build_root, &buck2_binary)?
            } else {
                materialize_projection(&vcs, cut, &build_root, &buck2_binary, policy, principal)?
            };
            let classification = classification_of(&tree, label, policy)?;
            admit_trigger(principal, label, &classification)?;
            let mut ledger = open_ledger(options, &verifier)?;
            let vocabulary = artifact_vocabulary(&ledger.view)?;
            let built = build_target(&tree, label)?;
            let record = artifact(&tree, &built, &ledger.view.ledger, &classification.basis());
            let created_at = super::now_stamp();
            let authority = ledger.view.authority_head.clone();
            let published = record_and_publish(
                &ledger.journal,
                &mut ledger.items,
                &verifier,
                &record,
                &vocabulary,
                Some(&authority),
                signer.actor(),
                &created_at,
                |statement| signer.sign(statement),
            )?;
            Ok(json!({
                "record": published.event_id,
                "build_record": published.build_record,
                "artifact": record,
                "classification": classification,
                "outputs": built.outputs.iter().map(|(path, digest)| json!({"path": path, "sha256": digest})).collect::<Vec<_>>(),
                "buck2_version": tree.buck2_version,
                "pin": tree.pin,
                "tier": if tree.projection.is_some() { "projection" } else { "cut" },
                "claims": tree.projection.as_ref().map(|p| p.id.clone()).unwrap_or_else(|| tree.cut.clone()),
                "unobserved": tree.projection.as_ref().map(|p| p.unobserved.clone()).unwrap_or_default(),
            }))
        }
        Verb::Result => {
            let label = args.label()?;
            let ledger = open_ledger(options, &verifier)?;
            let records = artifact_records(&ledger.view, cut, label, None);
            let mut observed = Vec::new();
            for record in &records {
                if let Some(seen) = scoped_result(record, policy, principal)? {
                    observed.push(seen);
                }
            }
            let unobserved = !principal.holds(&policy.labels()) || observed.len() < records.len();
            Ok(json!({
                "cut": cut,
                "label": label,
                "observed": observed,
                "unobserved": unobserved,
            }))
        }
        Verb::Correspond => {
            let label = args.label()?;
            let manifest = cut_manifest_of(&vcs, cut)?;
            let projection = project(&manifest, policy, principal);
            let mut ledger = open_ledger(options, &verifier)?;
            let projected = artifact_records(&ledger.view, cut, label, Some(&projection.id))
                .into_iter()
                .next()
                .map(|record| scoped_result(record, policy, principal))
                .transpose()?
                .flatten();
            let projected = projected_result(projected, label, principal, cut)?;
            let cut_result = artifact_records(&ledger.view, cut, label, None)
                .into_iter()
                .filter(|record| record.fields["configuration"] == projected.configuration.as_str())
                .map(|record| scoped_result(record, policy, principal))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .flatten()
                .next();
            let cut_result = cut_result_under_view(cut_result, label, principal)?;
            let fields = correspondence_fields(label, &projected, &cut_result, &projection, cut)?;
            let created_at = super::now_stamp();
            let view = ledger.view.clone();
            let id = publish_correspondence(
                &mut ledger.items,
                &verifier,
                &view,
                &fields,
                vec![projected.revision.clone(), cut_result.revision.clone()],
                signer.actor(),
                &created_at,
                |statement| signer.sign(statement),
            )?;
            Ok(json!({
                "correspondence": id,
                "fields": fields,
                "projection": projection.id,
                "unobserved": projection.unobserved,
            }))
        }
        Verb::Test => {
            let tree = materialize_cut(&vcs, cut, &build_root, &buck2_binary)?;
            let targets: Vec<String> = args.positional.iter().map(|s| (*s).to_owned()).collect();
            let mut classifications = Vec::new();
            for target in &targets {
                let classification = classification_of(&tree, target, policy)?;
                admit_trigger(principal, target, &classification)?;
                classifications.push(classification);
            }
            let executor = executor_binary()?;
            let report = match args.flags.get("--report") {
                Some(path) => PathBuf::from(path),
                None => {
                    let dir = build_root.join("reports").join(&tree.cut);
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
                "classification": classifications,
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
    use crate::build_scope::Region;
    use std::collections::BTreeSet;

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
        assert_eq!(
            package_of_label("root//secret-gate:gate"),
            Some(("root".into(), "secret-gate".into()))
        );
        assert_eq!(
            package_of_label("inner//:note"),
            Some(("inner".into(), "".into()))
        );
        assert_eq!(package_of_label("root//pkg:"), None);
        assert_eq!(package_of_label("//pkg:t"), None);
        assert_eq!(package_of_label("nonsense"), None);
        let root = Path::new("/tree");
        let cells = Cells::from_configs(Some("[cells]\nroot = .\ninner = inner\n"), |_| None);
        assert_eq!(tree_relative(root, &cells, "/tree/rules.bzl"), "rules.bzl");
        assert_eq!(
            tree_relative(root, &cells, "root//tests/passing.sh"),
            "tests/passing.sh"
        );
        assert_eq!(
            tree_relative(root, &cells, "inner//note.txt"),
            "inner/note.txt"
        );
        assert_eq!(tree_relative(root, &cells, "other//x"), "x");
        assert_eq!(
            tree_relative(root, &cells, "tests/passing.sh"),
            "tests/passing.sh"
        );
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

    fn policy() -> LabelPolicy {
        LabelPolicy::new(vec![Region {
            prefix: "secret-gate/protected/".into(),
            label: "protected".into(),
        }])
        .expect("a policy")
    }

    fn principal(name: &str, labels: &[&str]) -> Principal {
        Principal {
            name: name.into(),
            labels: labels.iter().map(|l| l.to_string()).collect(),
        }
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
        vcs.write("main", "FIXTURE", Some("# empty\n"), "cut-0", "t1")
            .expect("record a cut");
        vcs.write(
            "main",
            "secret-gate/protected/flag",
            Some("flag\n"),
            "cut-1",
            "t2",
        )
        .expect("record a cut");
        let broken = fake_buck2(dir.path(), true);
        assert_eq!(
            materialize_cut(&vcs, "cut-1", &build_root, &broken).unwrap_err(),
            format!("{} --version failed: no buck2 here", broken.display())
        );
        let tree = materialize_cut(&vcs, "cut-1", &build_root, &buck2).expect("materializes");
        assert_eq!(tree.buck2_version, "buck2 fake");
        assert!(tree.root.join("FIXTURE").is_file());
        assert!(tree.root.join("secret-gate/protected/flag").is_file());
        assert_eq!(tree.pin, None);
        assert_eq!(tree.isolation_dir, HOME_ISOLATION_DIR);
        assert_eq!(tree.manifest.len(), 2);
        assert!(tree.projection.is_none());
        // Every daemon invocation reports buck2's own failure, never a guess.
        assert_eq!(
            build_target(&tree, "//:x").unwrap_err(),
            "buck2 failed to configure //:x (exit status: 1):\nboom"
        );
        // A principal's projection holds only what their labels permit, under
        // their own daemon, in a directory named by the projection.
        let dev = principal("dev", &[]);
        let projected = materialize_projection(&vcs, "cut-1", &build_root, &buck2, &policy(), &dev)
            .expect("the projection materializes");
        assert!(projected.root.join("FIXTURE").is_file());
        assert!(!projected.root.join("secret-gate").exists());
        assert_eq!(projected.isolation_dir, "whip-projection-dev");
        assert_eq!(projected.manifest.len(), 1);
        let projection = projected.projection.as_ref().expect("a projection");
        assert_eq!(
            projection.unobserved,
            vec!["secret-gate/protected/".to_owned()]
        );
        assert!(projected.root.ends_with(
            Path::new("projections/dev/cut-1").join(&projection.id["projection:".len()..][..16])
        ));
        assert_eq!(
            materialize_projection(&vcs, "nope", &build_root, &buck2, &policy(), &dev).unwrap_err(),
            "no recorded cut nope"
        );
    }

    #[test]
    fn the_endpoint_is_found_beside_whip_and_its_announcement_configures_the_daemon() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let whip = dir.path().join("whip");
        assert_eq!(
            beside_whip(
                None,
                &whip,
                "whip-remote-execution",
                "WHIPPLESCRIPT_REMOTE_EXECUTION"
            )
            .unwrap_err(),
            format!(
                "no whip-remote-execution beside whip at {}; set WHIPPLESCRIPT_REMOTE_EXECUTION",
                dir.path().join("whip-remote-execution").display()
            )
        );
        let config = endpoint_client_config("127.0.0.1:4321");
        assert!(config.contains("engine_address = grpc://127.0.0.1:4321\n"));
        assert!(config.contains("cas_address = grpc://127.0.0.1:4321\n"));
        assert!(config.contains("digest_algorithms = SHA256\n"));
        let announced = parse_endpoint_announcement(
            "{\"address\":\"127.0.0.1:4321\",\"executor\":\"whip-remote-execution/local\",\"handles\":{\"owner\":\"ab\"}}\n",
        )
        .unwrap();
        assert_eq!(announced.address, "127.0.0.1:4321");
        assert_eq!(announced.handles["owner"], "ab");
        assert_eq!(
            parse_endpoint_announcement("not json").unwrap_err(),
            "the endpoint announced nothing readable: expected ident at line 1 column 2"
        );
    }

    #[test]
    fn a_tree_records_as_one_cut_with_its_nested_repositories_and_never_on_the_mainline() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let tree = dir.path().join("workspace");
        std::fs::create_dir_all(tree.join("cell/src")).expect("mkdir");
        std::fs::create_dir_all(tree.join("cell/buck-out")).expect("mkdir");
        std::fs::create_dir_all(tree.join("plain")).expect("mkdir");
        std::fs::write(tree.join(".buckconfig"), "[cells]\nroot = .\ncell = cell\n")
            .expect("write");
        std::fs::write(tree.join("cell/src/a.txt"), "alpha").expect("write");
        std::fs::write(tree.join("cell/buck-out/junk"), "junk").expect("write");
        std::fs::write(tree.join("cell/ignored.log"), "log").expect("write");
        std::fs::write(tree.join("cell/.gitignore"), "*.log\n").expect("write");
        std::fs::write(tree.join("plain/note"), "note").expect("write");
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(tree.join("cell"))
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("git");
            assert!(status.success(), "git {args:?}");
        };
        git(&["init", "-q"]);
        let files: Vec<String> = tree_files(&tree)
            .expect("the tree lists")
            .into_iter()
            .map(|(relative, _)| relative)
            .collect();
        assert_eq!(
            files,
            vec![
                ".buckconfig",
                "cell/.gitignore",
                "cell/src/a.txt",
                "plain/note"
            ]
        );
        let mut vcs = NativeWorkspaceVcs::open(
            dir.path().join("branches.sqlite"),
            dir.path().join("content.sqlite"),
        )
        .expect("a vcs");
        vcs.init("t0").expect("init");
        assert_eq!(
            record_tree(&mut vcs, &tree, "main", None, "t1").unwrap_err(),
            "a recorded tree never lands on the mainline; name a build branch"
        );
        let empty = dir.path().join("empty");
        std::fs::create_dir_all(&empty).expect("mkdir");
        assert_eq!(
            record_tree(&mut vcs, &empty, "build", None, "t1").unwrap_err(),
            format!("nothing to record under {}", empty.display())
        );
        let first = record_tree(&mut vcs, &tree, "build", None, "t1").expect("records");
        assert_eq!(first.files, 4);
        assert_eq!(
            first.bytes,
            5 + 6 + 4 + "[cells]\nroot = .\ncell = cell\n".len()
        );
        assert!(first.cut.starts_with("tree:"));
        let manifest = cut_manifest_of(&vcs, &first.cut).expect("the cut is recorded");
        assert_eq!(manifest.len(), 4);
        // The same tree is the same cut; a changed tree is a new cut that
        // drops what is gone.
        let again = record_tree(&mut vcs, &tree, "build", None, "t2").expect("records again");
        assert_eq!(again.cut, first.cut);
        std::fs::remove_file(tree.join("plain/note")).expect("remove");
        let changed = record_tree(&mut vcs, &tree, "build", Some("cut-named"), "t3")
            .expect("records the change");
        assert_eq!(changed.cut, "cut-named");
        assert_eq!(
            cut_manifest_of(&vcs, "cut-named").expect("recorded").len(),
            3
        );
        // The store's other answers are refusals, said as what they are.
        assert_eq!(
            recorded(
                whipplescript_store::vcs::VcsWriteOutcome::BranchMissing,
                "build",
                1,
                1
            )
            .unwrap_err(),
            "the tree was not recorded: BranchMissing"
        );
        // A directory that claims to be a repository and is not is refused
        // with git's own words.
        let broken = dir.path().join("broken");
        std::fs::create_dir_all(broken.join("inner/.git")).expect("mkdir");
        std::fs::write(broken.join("inner/x"), "x").expect("write");
        let refused = tree_files(&broken).unwrap_err();
        assert!(
            refused.starts_with(&format!(
                "git ls-files failed in {}: ",
                broken.join("inner").display()
            )),
            "{refused}"
        );
        // A tree materialized from the cut carries its cells.
        let materialized = materialize_cut(
            &vcs,
            "cut-named",
            &dir.path().join("build"),
            &fake_buck2(dir.path(), false),
        )
        .expect("materializes");
        assert_eq!(materialized.cells.dir("cell"), Some("cell"));
        assert!(materialized.root.join("cell/src/a.txt").is_file());
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

    #[test]
    fn the_daemon_is_the_operators_and_a_correspondence_needs_both_results_in_view() {
        assert!(operator_only(&principal("owner", &["protected"]), &policy()).is_ok());
        assert_eq!(
            operator_only(&principal("dev", &[]), &policy()).unwrap_err(),
            "build daemon is the Home operator's: dev does not hold every label"
        );
        let seen = ArtifactSeen {
            record: "r".into(),
            revision: "r-rev".into(),
            configuration: "<unspecified>".into(),
            classification: "package-ceiling/v1:".into(),
            outputs: vec!["aa".into()],
        };
        let dev = principal("dev", &[]);
        assert_eq!(
            projected_result(Some(seen.clone()), "root//:passing", &dev, "cut-1").unwrap(),
            seen
        );
        assert_eq!(
            projected_result(None, "root//:passing", &dev, "cut-1").unwrap_err(),
            "no iteration result for root//:passing over dev's projection of cut-1: run build iterate first"
        );
        assert_eq!(
            cut_result_under_view(Some(seen.clone()), "root//:passing", &dev).unwrap(),
            seen
        );
        assert_eq!(
            cut_result_under_view(None, "root//secret-gate:gate", &dev).unwrap_err(),
            "the cut's result for root//secret-gate:gate is unobserved under dev's view"
        );
    }

    #[test]
    fn a_trigger_is_admitted_only_to_a_principal_holding_the_classification() {
        let protected = Classification {
            labels: ["protected".to_owned()].into_iter().collect(),
            influences: Vec::new(),
        };
        assert!(admit_trigger(
            &principal("owner", &["protected"]),
            "//secret-gate:gate",
            &protected
        )
        .is_ok());
        assert_eq!(
            admit_trigger(&principal("dev", &[]), "//secret-gate:gate", &protected).unwrap_err(),
            "//secret-gate:gate is classified package-ceiling/v1:protected, which dev does not hold: refused, not absent"
        );
    }

    fn record(id: &str, fields: Value) -> NormRecord {
        NormRecord {
            id: id.into(),
            vocabulary: VocabularyRef {
                name: "artifact".into(),
                version: "1".into(),
                digest: "d".into(),
            },
            fields,
            content_head: format!("{id}-rev"),
            status: "recorded".into(),
            head: id.into(),
        }
    }

    #[test]
    fn the_result_interface_reads_what_the_principal_holds_and_nothing_else() {
        let public = record(
            "r1",
            json!({"cut": "c1", "label": "root//:passing", "configuration": "<unspecified>", "classification": "package-ceiling/v1:", "outputs": ["aa"]}),
        );
        let gated = record(
            "r2",
            json!({"cut": "c1", "label": "root//secret-gate:gate", "configuration": "<unspecified>", "classification": "package-ceiling/v1:protected", "outputs": ["bb"]}),
        );
        let interim = record(
            "r3",
            json!({"cut": "c1", "label": "root//:passing", "configuration": "<unspecified>", "classification": ORGANIZATION_CEILING, "outputs": ["aa"]}),
        );
        let dev = principal("dev", &[]);
        let owner = principal("owner", &["protected"]);
        let seen = scoped_result(&public, &policy(), &dev)
            .unwrap()
            .expect("public is read");
        assert_eq!(seen.revision, "r1-rev");
        assert_eq!(seen.outputs, vec!["aa".to_owned()]);
        assert_eq!(scoped_result(&gated, &policy(), &dev).unwrap(), None);
        assert!(scoped_result(&gated, &policy(), &owner).unwrap().is_some());
        // The interim organization ceiling names every label the policy declares.
        assert_eq!(scoped_result(&interim, &policy(), &dev).unwrap(), None);
        assert!(scoped_result(&interim, &policy(), &owner)
            .unwrap()
            .is_some());
        let bare = record("r4", json!({"cut": "c1", "label": "x", "outputs": []}));
        assert_eq!(
            scoped_result(&bare, &policy(), &owner).unwrap_err(),
            "an artifact record carries no classification basis"
        );
    }

    #[test]
    fn a_correspondence_is_checked_before_it_is_written() {
        let seen = |revision: &str, configuration: &str, outputs: &[&str]| ArtifactSeen {
            record: revision.into(),
            revision: revision.into(),
            configuration: configuration.into(),
            classification: "package-ceiling/v1:".into(),
            outputs: outputs.iter().map(|o| o.to_string()).collect(),
        };
        let projection = Projection {
            id: "projection:abc".into(),
            include: BTreeSet::new(),
            unobserved: vec!["secret-gate/protected/".into()],
        };
        let fields = correspondence_fields(
            "root//:passing",
            &seen("p", "<unspecified>", &["aa"]),
            &seen("c", "<unspecified>", &["aa"]),
            &projection,
            "cut-1",
        )
        .expect("equal outputs correspond");
        assert_eq!(fields["sources"], json!(["p"]));
        assert_eq!(fields["targets"], json!(["c"]));
        assert_eq!(fields["mode"], json!("checked"));
        assert_eq!(fields["claim"], json!("equivalence"));
        assert_eq!(
            fields["witness"],
            json!("whip build correspond: 1 output digest(s) of root//:passing equal between projection:abc and cut cut-1, with 1 region(s) unobserved under the projection")
        );
        assert_eq!(
            correspondence_fields(
                "root//:passing",
                &seen("p", "<unspecified>", &["aa"]),
                &seen("c", "<unspecified>", &["bb"]),
                &projection,
                "cut-1",
            )
            .unwrap_err(),
            "the projected build's outputs differ from the cut's for root//:passing: no correspondence"
        );
        assert_eq!(
            correspondence_fields(
                "root//:passing",
                &seen("p", "linux", &["aa"]),
                &seen("c", "mac", &["aa"]),
                &projection,
                "cut-1",
            )
            .unwrap_err(),
            "the projected build of root//:passing and the cut's were configured differently: linux against mac"
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
        assert_eq!(args.label().unwrap(), "//:x");
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
        let record = owned(&["record", "/tmp/tree", "--as", "owner", "--branch", "b"]);
        let parsed = Arguments::parse(&record).unwrap();
        assert_eq!(parsed.positional, vec!["/tmp/tree"]);
        assert_eq!(parsed.flags.get("--branch").copied(), Some("b"));
        for verb in ["iterate", "correspond", "result"] {
            let list = owned(&[verb, "--cut", "c1", "--as", "dev"]);
            let parsed = Arguments::parse(&list).unwrap();
            assert_eq!(
                parsed.label().unwrap_err(),
                format!("build {verb} needs a target label")
            );
        }
    }
}
