//! Placement-neutral governed virtual bash.
//!
//! `WhipShell` is the only Bashkit boundary WhippleScript hosts use. A caller
//! supplies an already-authorized workspace snapshot and receives the complete
//! post-execution snapshot. Native and Durable Object adapters remain
//! responsible for loading and atomically validating/importing the delta.
//! Bashkit never sees an ambient filesystem, process table, or network client.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bashkit::{
    async_trait, Bash, DirEntry, ExecutionLimits, FileSystem, FileSystemExt, FsLimits, FsUsage,
    InMemoryFs, Metadata, SearchCapable, VfsSnapshot,
};

// `std::time::SystemTime` PANICS unconditionally on wasm32-unknown-unknown, so
// bashkit's filesystem trait speaks `web_time`'s there and `std`'s elsewhere,
// through a private `time_compat` module. Private means the delegating
// `set_modified_time` below cannot name the type without restating that split
// here, on the same cfg bashkit switches on (`target_arch`, not
// `target_family`). Inheriting the trait default instead is not an option that
// stays honest: `InMemoryFs` overrides it, so a decorator that did not would
// silently stop `touch` from setting a time.
#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;

#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;

const WORKSPACE: &str = "/workspace";

/// One file admitted into the governed virtual workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellFile {
    pub path: String,
    pub content: Vec<u8>,
    pub writable: bool,
}

/// A bounded, fresh-spawn virtual bash invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellRequest {
    pub command: String,
    pub files: Vec<ShellFile>,
    pub timeout: Duration,
}

/// One file the interpreter READ while running the command.
///
/// The write half of a bash invocation has always been recoverable — the
/// caller diffs the returned workspace against what it supplied. The read half
/// was not observable at all, and reads are what carry information INTO a
/// model's context: a value the model emits after `cat`ting a file came from
/// that file, and nothing recorded that it had been opened.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct ShellRead {
    /// Workspace-relative, matching `ShellFile::path` and `ShellOutput::files`.
    pub path: String,
    /// `chunking::content_hash_hex` of the bytes returned — the store's one
    /// content-id construction, and the same digest a `file.write.completed`
    /// fact records, so a read joins the write that produced what it read.
    pub content_hash: String,
    pub bytes: u64,
}

/// Bash output, the complete resulting governed workspace, and what was read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub files: BTreeMap<String, Vec<u8>>,
    /// Every file the command read, deduplicated by `(path, content_hash)` and
    /// ordered deterministically. A file read twice with the same contents is
    /// one entry; read, rewritten, and read again is two, which is the honest
    /// answer about what the command actually saw.
    pub reads: Vec<ShellRead>,
}

/// WhippleScript-owned adapter around the pinned Bashkit dependency.
#[derive(Clone, Debug)]
pub struct WhipShell {
    max_workspace_bytes: u64,
    max_file_bytes: u64,
    max_files: u64,
    max_output_bytes: usize,
}

impl Default for WhipShell {
    fn default() -> Self {
        Self {
            max_workspace_bytes: 32 * 1024 * 1024,
            max_file_bytes: 8 * 1024 * 1024,
            max_files: 5_000,
            max_output_bytes: 1024 * 1024,
        }
    }
}

impl WhipShell {
    pub fn execute(&self, request: ShellRequest) -> Result<ShellOutput, String> {
        if request.command.trim().is_empty() {
            return Err("bash command must not be empty".to_owned());
        }
        if request.timeout.is_zero() {
            return Err("bash timeout must be positive".to_owned());
        }

        let fs = Arc::new(InMemoryFs::with_limits(
            FsLimits::new()
                .max_total_bytes(self.max_workspace_bytes)
                .max_file_size(self.max_file_bytes)
                .max_file_count(self.max_files),
        ));
        fs.add_dir(WORKSPACE, 0o755);
        if request.files.len() as u64 > self.max_files {
            return Err(format!(
                "bash workspace has more than {} files",
                self.max_files
            ));
        }
        let mut total_bytes = 0u64;
        for file in &request.files {
            let relative = validated_relative_path(&file.path)?;
            let bytes = file.content.len() as u64;
            if bytes > self.max_file_bytes {
                return Err(format!(
                    "bash workspace file `{}` exceeds the {} byte limit",
                    file.path, self.max_file_bytes
                ));
            }
            total_bytes = total_bytes.saturating_add(bytes);
            if total_bytes > self.max_workspace_bytes {
                return Err(format!(
                    "bash workspace exceeds the {} byte limit",
                    self.max_workspace_bytes
                ));
            }
            fs.add_file(
                Path::new(WORKSPACE).join(relative),
                &file.content,
                if file.writable { 0o644 } else { 0o444 },
            );
        }

        let recorder = Arc::new(RecordingFs::new(fs));

        let limits = ExecutionLimits::new()
            .timeout(request.timeout)
            .max_input_bytes(1024 * 1024)
            .max_commands(10_000)
            .max_loop_iterations(10_000)
            .max_total_loop_iterations(100_000)
            .max_stdout_bytes(self.max_output_bytes)
            .max_stderr_bytes(self.max_output_bytes);
        let bash_fs: Arc<dyn FileSystem> = recorder.clone();
        let mut bash = Bash::builder()
            .fs(Arc::clone(&bash_fs))
            .cwd(WORKSPACE)
            .env("HOME", WORKSPACE)
            .username("agent")
            .hostname("whip")
            // Model-visible wall time is deterministic. Recorded host time is
            // available through governed effects, not ambient shell authority.
            .fixed_epoch(0)
            .limits(limits)
            .build();

        let execution = async {
            let result = bash
                .exec(&request.command)
                .await
                .map_err(|error| format!("bashkit execution failed: {error}"))?;
            // Taken BEFORE the snapshot: `collect_workspace` reads every file
            // through this same filesystem, so draining afterwards would report
            // the whole workspace as read by the command.
            let reads = recorder.take_reads();
            let files = collect_workspace(&bash_fs).await?;
            Ok::<_, String>((result, files, reads))
        };
        // Native Bashkit arms Tokio's wall-clock timeout. The Cloudflare build
        // intentionally uses Bashkit's WASM path, which relies on structural
        // command/loop/fuel limits and does not require a timer reactor.
        #[cfg(not(target_family = "wasm"))]
        let (result, files, reads) = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|error| format!("cannot start virtual bash runtime: {error}"))?
            .block_on(execution)?;
        #[cfg(target_family = "wasm")]
        let (result, files, reads) = futures::executor::block_on(execution)?;
        Ok(ShellOutput {
            stdout: result.stdout.text_lossy().into_owned(),
            stderr: result.stderr.text_lossy().into_owned(),
            exit_code: result.exit_code,
            files,
            reads,
        })
    }
}

/// The governed workspace, wrapped so that every read the interpreter performs
/// is recorded.
///
/// This is where a read set can be made COMPLETE BY CONSTRUCTION rather than by
/// diligence, and the reason is that Bashkit is not a shell. It is an
/// interpreter over a filesystem WhippleScript supplies, so `cat`, `grep`, and
/// every builtin reach file bytes through this trait and nowhere else. The same
/// instrumentation on a real subprocess could only ever be best-effort.
///
/// It records rather than governs: no read is refused here, and the wrapper is
/// transparent to Bashkit apart from the search fast path it declines below.
struct RecordingFs {
    inner: Arc<InMemoryFs>,
    /// Deduplicated by `(path, content_hash)` and kept sorted, so a command that
    /// reads one file in a loop records one entry and two runs of the same
    /// command record byte-identical sets.
    reads: Mutex<BTreeSet<ShellRead>>,
}

impl RecordingFs {
    fn new(inner: Arc<InMemoryFs>) -> Self {
        Self {
            inner,
            reads: Mutex::new(BTreeSet::new()),
        }
    }

    fn record(&self, path: &Path, content: &[u8]) {
        let path = path
            .strip_prefix(WORKSPACE)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        // Poison recovery rather than a panic: the only way this lock is
        // poisoned is a panic elsewhere in the interpreter, and dropping reads
        // on the floor at that point would make a PARTIAL read set look like a
        // complete one — the single failure this record exists to prevent.
        let mut reads = self
            .reads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reads.insert(ShellRead {
            path,
            content_hash: whipplescript_store::chunking::content_hash_hex(content),
            bytes: content.len() as u64,
        });
    }

    fn take_reads(&self) -> Vec<ShellRead> {
        let mut reads = self
            .reads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::mem::take(&mut *reads).into_iter().collect()
    }
}

#[async_trait]
impl FileSystemExt for RecordingFs {
    fn usage(&self) -> FsUsage {
        self.inner.usage()
    }

    async fn mkfifo(&self, path: &Path, mode: u32) -> bashkit::Result<()> {
        self.inner.mkfifo(path, mode).await
    }

    fn limits(&self) -> FsLimits {
        self.inner.limits()
    }

    fn vfs_snapshot(&self) -> Option<VfsSnapshot> {
        self.inner.vfs_snapshot()
    }

    fn vfs_restore(&self, snapshot: &VfsSnapshot) -> bashkit::Result<()> {
        self.inner.vfs_restore(snapshot)
    }

    fn backend_kind(&self) -> &'static str {
        self.inner.backend_kind()
    }
}

#[async_trait]
impl FileSystem for RecordingFs {
    async fn read_file(&self, path: &Path) -> bashkit::Result<Vec<u8>> {
        let content = self.inner.read_file(path).await?;
        self.record(path, &content);
        Ok(content)
    }

    /// Deliberately NOT delegated, and the one place this wrapper is not
    /// transparent. `grep`'s fast path reads file bodies through
    /// `SearchCapable` without passing `read_file`, so a search-capable inner
    /// filesystem would put those reads outside the record and leave a read set
    /// that is silently partial — worse than none, because it would be trusted.
    /// `None` keeps `grep` on its linear-scan fallback, where every read is
    /// visible here. It costs nothing today: `InMemoryFs` is not search-capable,
    /// so the fallback is already what runs, and this keeps that true if the
    /// pinned dependency ever changes.
    fn as_search_capable(&self) -> Option<&dyn SearchCapable> {
        None
    }

    async fn write_file(&self, path: &Path, content: &[u8]) -> bashkit::Result<()> {
        self.inner.write_file(path, content).await
    }

    async fn append_file(&self, path: &Path, content: &[u8]) -> bashkit::Result<()> {
        self.inner.append_file(path, content).await
    }

    async fn mkdir(&self, path: &Path, recursive: bool) -> bashkit::Result<()> {
        self.inner.mkdir(path, recursive).await
    }

    async fn remove(&self, path: &Path, recursive: bool) -> bashkit::Result<()> {
        self.inner.remove(path, recursive).await
    }

    async fn stat(&self, path: &Path) -> bashkit::Result<Metadata> {
        self.inner.stat(path).await
    }

    async fn read_dir(&self, path: &Path) -> bashkit::Result<Vec<DirEntry>> {
        self.inner.read_dir(path).await
    }

    async fn exists(&self, path: &Path) -> bashkit::Result<bool> {
        self.inner.exists(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> bashkit::Result<()> {
        self.inner.rename(from, to).await
    }

    async fn copy(&self, from: &Path, to: &Path) -> bashkit::Result<()> {
        self.inner.copy(from, to).await
    }

    async fn symlink(&self, target: &Path, link: &Path) -> bashkit::Result<()> {
        self.inner.symlink(target, link).await
    }

    async fn read_link(&self, path: &Path) -> bashkit::Result<PathBuf> {
        self.inner.read_link(path).await
    }

    async fn chmod(&self, path: &Path, mode: u32) -> bashkit::Result<()> {
        self.inner.chmod(path, mode).await
    }

    async fn set_modified_time(&self, path: &Path, time: SystemTime) -> bashkit::Result<()> {
        self.inner.set_modified_time(path, time).await
    }
}

fn validated_relative_path(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(format!(
            "bash workspace path `{}` is not relative",
            path.display()
        ));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(segment) => normalized.push(segment),
            Component::CurDir => {}
            _ => {
                return Err(format!(
                    "bash workspace path `{}` escapes its capability",
                    path.display()
                ))
            }
        }
    }
    if normalized.as_os_str().is_empty() {
        return Err("bash workspace path must name a file".to_owned());
    }
    Ok(normalized)
}

async fn collect_workspace(fs: &Arc<dyn FileSystem>) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let root = PathBuf::from(WORKSPACE);
    let mut pending = vec![root.clone()];
    let mut files = BTreeMap::new();
    while let Some(directory) = pending.pop() {
        let mut entries = fs
            .read_dir(&directory)
            .await
            .map_err(|error| format!("cannot enumerate bash workspace: {error}"))?;
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        for entry in entries {
            let path = directory.join(&entry.name);
            if entry.metadata.file_type.is_dir() {
                pending.push(path);
            } else if entry.metadata.file_type.is_file() {
                let relative = path
                    .strip_prefix(&root)
                    .map_err(|_| "bash workspace enumeration escaped its root".to_owned())?
                    .to_string_lossy()
                    .replace('\\', "/");
                let content = fs
                    .read_file(&path)
                    .await
                    .map_err(|error| format!("cannot read bash result `{relative}`: {error}"))?;
                files.insert(relative, content);
            } else {
                return Err(format!(
                    "bash created unsupported workspace entry `{}`",
                    path.display()
                ));
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_pipelines_and_returns_workspace_delta() {
        let output = WhipShell::default()
            .execute(ShellRequest {
                command: "cat input.txt | tr a-z A-Z > output.txt".to_owned(),
                files: vec![ShellFile {
                    path: "input.txt".to_owned(),
                    content: b"hello\n".to_vec(),
                    writable: true,
                }],
                timeout: Duration::from_secs(5),
            })
            .expect("virtual bash");
        assert_eq!(output.exit_code, 0);
        assert_eq!(output.files.get("output.txt"), Some(&b"HELLO\n".to_vec()));
    }

    #[test]
    fn has_no_ambient_native_process_surface() {
        let output = WhipShell::default()
            .execute(ShellRequest {
                command: "definitely-not-a-bashkit-command".to_owned(),
                files: vec![],
                timeout: Duration::from_secs(5),
            })
            .expect("honest shell result");
        assert_ne!(output.exit_code, 0);
        assert!(output.stderr.contains("command not found"));
    }

    fn file(path: &str, content: &str) -> ShellFile {
        ShellFile {
            path: path.to_owned(),
            content: content.as_bytes().to_vec(),
            writable: true,
        }
    }

    fn run(command: &str, files: Vec<ShellFile>) -> ShellOutput {
        WhipShell::default()
            .execute(ShellRequest {
                command: command.to_owned(),
                files,
                timeout: Duration::from_secs(5),
            })
            .expect("virtual bash")
    }

    #[test]
    fn a_read_is_recorded_with_the_digest_of_what_it_returned() {
        let output = run("cat input.txt", vec![file("input.txt", "hello\n")]);
        assert_eq!(output.exit_code, 0);
        assert_eq!(
            output.reads,
            vec![ShellRead {
                path: "input.txt".to_owned(),
                // The digest a `file.write.completed` fact would carry for these
                // bytes, which is what lets a read join the write that made them.
                content_hash: whipplescript_store::chunking::content_hash_hex(b"hello\n"),
                bytes: 6,
            }]
        );
    }

    #[test]
    fn a_file_the_command_never_opened_is_not_in_the_read_set() {
        let output = run(
            "cat wanted.txt",
            vec![file("wanted.txt", "a\n"), file("ignored.txt", "b\n")],
        );
        let paths = output
            .reads
            .iter()
            .map(|read| read.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["wanted.txt"]);
    }

    #[test]
    fn collecting_the_result_workspace_is_not_counted_as_a_read() {
        // The snapshot walks every file through the same filesystem, so a read
        // set drained after it would report the whole workspace as read by a
        // command that opened nothing. Pins the ordering inside `execute`.
        let output = run("echo hi", vec![file("untouched.txt", "a\n")]);
        assert_eq!(output.stdout, "hi\n");
        assert!(
            output.reads.is_empty(),
            "nothing was read, got: {:?}",
            output.reads
        );
    }

    #[test]
    fn a_scan_across_the_workspace_records_every_file_it_opened() {
        // `grep`'s fast path would read bodies through `SearchCapable` without
        // passing `read_file`; `RecordingFs::as_search_capable` returns `None`
        // to keep it on the linear scan, where each open is visible.
        let output = run(
            "grep -l needle *.txt",
            vec![
                file("one.txt", "needle\n"),
                file("two.txt", "haystack\n"),
                file("three.txt", "needle\n"),
            ],
        );
        let paths = output
            .reads
            .iter()
            .map(|read| read.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["one.txt", "three.txt", "two.txt"]);
    }

    #[test]
    fn reading_a_file_that_changed_records_both_contents() {
        let output = run(
            "cat log.txt; echo second > log.txt; cat log.txt",
            vec![file("log.txt", "first\n")],
        );
        let recorded = output
            .reads
            .iter()
            .map(|read| (read.path.as_str(), read.content_hash.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(recorded.len(), 2, "got: {:?}", output.reads);
        assert!(recorded.iter().all(|(path, _)| *path == "log.txt"));
        assert_ne!(
            recorded[0].1, recorded[1].1,
            "the two reads saw different bytes and must not collapse"
        );
    }

    #[test]
    fn one_file_read_repeatedly_records_one_entry() {
        let output = run(
            "for i in 1 2 3; do cat input.txt; done",
            vec![file("input.txt", "same\n")],
        );
        assert_eq!(output.reads.len(), 1, "got: {:?}", output.reads);
    }

    #[test]
    fn fixes_the_shell_clock_for_replay() {
        let output = WhipShell::default()
            .execute(ShellRequest {
                command: "date +%s".to_owned(),
                files: vec![],
                timeout: Duration::from_secs(5),
            })
            .expect("virtual bash");
        assert_eq!(output.stdout, "0\n");
    }
}
