//! The compute plane's seam: how the endpoint runs an action (DR-0124 §14.4).
//!
//! An action is a confined computation. It holds no authority to settle
//! work, publish a release, change the charter or write externally: the
//! runner gives it a scratch directory holding exactly its input root, the
//! command's own environment and nothing of the endpoint's, and reads back
//! only the outputs it named.
//!
//! That confinement is one function, [`run_confined`], and it is
//! synchronous so that every place an action runs is the same code: the
//! endpoint's own runner calls it on a blocking thread, and the Class-A
//! executor sidecar of the compute-plane design note calls it from its
//! request thread when an endpoint's [`crate::sidecar`] runner hands it an
//! action. The two runners differ in where the process table is, never in
//! what an action is allowed to see.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::digest::Digest;

/// An action, resolved: its command and the files of its input root.
#[derive(Clone, Debug)]
pub struct PreparedAction {
    pub arguments: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub working_directory: String,
    /// Path → (bytes, executable).
    pub inputs: BTreeMap<String, (Vec<u8>, bool)>,
    pub output_paths: Vec<String>,
    pub timeout: Option<Duration>,
}

/// What running it produced.
#[derive(Clone, Debug, Default)]
pub struct ActionOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Output path → the bytes of a file, or the files of a directory.
    pub outputs: BTreeMap<String, Output>,
    pub timed_out: bool,
}

#[derive(Clone, Debug)]
pub enum Output {
    File {
        bytes: Vec<u8>,
        executable: bool,
    },
    Directory {
        files: BTreeMap<String, (Vec<u8>, bool)>,
    },
}

#[cfg(feature = "endpoint")]
#[async_trait::async_trait]
pub trait ActionRunner: Send + Sync {
    /// The executor's name, recorded as the origin of every result it
    /// produces.
    fn name(&self) -> &str;
    async fn run(&self, action: PreparedAction) -> Result<ActionOutcome, String>;
}

/// The host's own processes, one scratch directory per action.
#[cfg(feature = "endpoint")]
pub struct LocalRunner {
    scratch_root: PathBuf,
}

#[cfg(feature = "endpoint")]
impl LocalRunner {
    pub fn new(scratch_root: impl Into<PathBuf>) -> Self {
        Self {
            scratch_root: scratch_root.into(),
        }
    }
}

fn confine(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(format!("an action path may not leave its root: {relative}"));
        }
        path.push(part);
    }
    Ok(path)
}

fn collect_files(
    root: &Path,
    dir: &Path,
    into: &mut BTreeMap<String, (Vec<u8>, bool)>,
) -> Result<(), String> {
    for entry in
        std::fs::read_dir(dir).map_err(|error| format!("cannot list {}: {error}", dir.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot list {}: {error}", dir.display()))?;
        let path = entry.path();
        if path.is_dir() {
            collect_files(root, &path, into)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| format!("{} is outside {}", path.display(), root.display()))?
                .to_string_lossy()
                .into_owned();
            into.insert(relative, read_file(&path)?);
        }
    }
    Ok(())
}

fn read_file(path: &Path) -> Result<(Vec<u8>, bool), String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let executable = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(path)
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            false
        }
    };
    Ok((bytes, executable))
}

#[cfg(feature = "endpoint")]
#[async_trait::async_trait]
impl ActionRunner for LocalRunner {
    fn name(&self) -> &str {
        "whip-remote-execution/local"
    }

    async fn run(&self, action: PreparedAction) -> Result<ActionOutcome, String> {
        let scratch_root = self.scratch_root.clone();
        tokio::task::spawn_blocking(move || run_confined(&scratch_root, &action))
            .await
            .unwrap_or_else(|failed| std::panic::resume_unwind(failed.into_panic()))
    }
}

/// How long an action that names no timeout may run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// Run an action confined: a fresh scratch directory under `scratch_root`
/// holding exactly its inputs, the command's own environment and nothing of
/// the caller's, its standard input closed, a timeout, and only the outputs
/// it named read back. An action that names no timeout gets
/// [`DEFAULT_TIMEOUT`]. A timed-out action reports no output at all.
pub fn run_confined(scratch_root: &Path, action: &PreparedAction) -> Result<ActionOutcome, String> {
    std::fs::create_dir_all(scratch_root)
        .map_err(|error| format!("cannot create {}: {error}", scratch_root.display()))?;
    let scratch = tempfile::Builder::new()
        .prefix("action-")
        .tempdir_in(scratch_root)
        .map_err(|error| {
            format!(
                "cannot create a scratch directory under {}: {error}",
                scratch_root.display()
            )
        })?;
    let root = scratch.path();
    for (path, (bytes, executable)) in &action.inputs {
        let target = confine(root, path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        std::fs::write(&target, bytes)
            .map_err(|error| format!("cannot write {}: {error}", target.display()))?;
        #[cfg(unix)]
        if *executable {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
                .map_err(|error| format!("cannot mark {} executable: {error}", target.display()))?;
        }
        #[cfg(not(unix))]
        let _ = executable;
    }
    for output in &action.output_paths {
        if let Some(parent) = confine(root, output)?.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
    }
    let cwd = confine(root, &action.working_directory)?;
    std::fs::create_dir_all(&cwd)
        .map_err(|error| format!("cannot create {}: {error}", cwd.display()))?;
    let Some((program, arguments)) = action.arguments.split_first() else {
        return Err("an action names no command".into());
    };
    let mut child = std::process::Command::new(program)
        .args(arguments)
        .current_dir(&cwd)
        .env_clear()
        .envs(
            action
                .environment
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str())),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot start {program}: {error}"))?;
    // Both streams drain on their own threads, so a chatty action never
    // blocks on a full pipe while it is being waited for.
    let drain = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            if let Some(mut stream) = stream {
                let _ = stream.read_to_end(&mut bytes);
            }
            bytes
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    // Every run has a deadline, the action's own or the default; a process
    // table that cannot say whether the child has finished is waited on
    // until then and treated as a timeout, never as a finish.
    let deadline = Instant::now() + action.timeout.unwrap_or(DEFAULT_TIMEOUT);
    let status = loop {
        if let Some(status) = child.try_wait().ok().flatten() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let Some(status) = status else {
        // A child the action started may still hold the pipes; its drains
        // are left to finish on their own rather than waited for.
        return Ok(ActionOutcome {
            exit_code: -1,
            timed_out: true,
            ..Default::default()
        });
    };
    let joined = |handle: std::thread::JoinHandle<Vec<u8>>| {
        handle
            .join()
            .unwrap_or_else(|panicked| std::panic::resume_unwind(panicked))
    };
    let (stdout, stderr) = (joined(stdout), joined(stderr));
    let mut outputs = BTreeMap::new();
    for output in &action.output_paths {
        let path = confine(root, output)?;
        if path.is_dir() {
            let mut files = BTreeMap::new();
            collect_files(&path, &path, &mut files)?;
            outputs.insert(output.clone(), Output::Directory { files });
        } else if path.is_file() {
            let (bytes, executable) = read_file(&path)?;
            outputs.insert(output.clone(), Output::File { bytes, executable });
        }
    }
    Ok(ActionOutcome {
        exit_code: status.code().unwrap_or(-1),
        stdout,
        stderr,
        outputs,
        timed_out: false,
    })
}

/// A digest-addressed view of an outcome's outputs, for the services.
pub fn digest_outputs(outcome: &ActionOutcome) -> Vec<(String, Digest)> {
    outcome
        .outputs
        .iter()
        .filter_map(|(path, output)| match output {
            Output::File { bytes, .. } => Some((path.clone(), Digest::of(bytes))),
            Output::Directory { .. } => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_action_runs_confined_to_its_root_with_only_what_it_named() {
        let scratch = tempfile::tempdir().unwrap();
        let run = |action: PreparedAction| run_confined(scratch.path(), &action);
        let mut inputs = BTreeMap::new();
        inputs.insert("in/a.txt".to_owned(), (b"alpha".to_vec(), false));
        let outcome = run(PreparedAction {
            arguments: vec![
                "sh".into(),
                "-c".into(),
                "cat in/a.txt > out/b.txt; mkdir -p out/d; echo x > out/d/x; echo err >&2; exit 3"
                    .into(),
            ],
            environment: vec![("HOME".into(), "/nonexistent".into())],
            working_directory: String::new(),
            inputs,
            output_paths: vec!["out/b.txt".into(), "out/d".into(), "out/absent".into()],
            timeout: Some(Duration::from_secs(30)),
        })
        .unwrap();
        assert_eq!(outcome.exit_code, 3);
        assert_eq!(outcome.stderr, b"err\n");
        assert!(!outcome.timed_out);
        assert!(
            matches!(&outcome.outputs["out/b.txt"], Output::File { bytes, .. } if bytes == b"alpha")
        );
        assert!(
            matches!(&outcome.outputs["out/d"], Output::Directory { files } if files["x"].0 == b"x\n")
        );
        assert!(!outcome.outputs.contains_key("out/absent"));
        assert_eq!(
            digest_outputs(&outcome),
            vec![("out/b.txt".to_owned(), Digest::of(b"alpha"))]
        );
        assert!(
            run(PreparedAction {
                arguments: vec!["sh".into(), "-c".into(), "sleep 5".into()],
                environment: vec![],
                working_directory: String::new(),
                inputs: BTreeMap::new(),
                output_paths: vec![],
                timeout: Some(Duration::from_millis(200)),
            })
            .unwrap()
            .timed_out
        );
        assert_eq!(
            run(PreparedAction {
                arguments: vec![],
                environment: vec![],
                working_directory: String::new(),
                inputs: BTreeMap::new(),
                output_paths: vec![],
                timeout: None,
            })
            .unwrap_err(),
            "an action names no command"
        );
        assert_eq!(
            confine(Path::new("/r"), "../escape").unwrap_err(),
            "an action path may not leave its root: ../escape"
        );
    }
}
