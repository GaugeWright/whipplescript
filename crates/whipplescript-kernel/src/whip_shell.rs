//! Placement-neutral governed virtual bash.
//!
//! `WhipShell` is the only Bashkit boundary WhippleScript hosts use. A caller
//! supplies an already-authorized workspace snapshot and receives the complete
//! post-execution snapshot. Native and Durable Object adapters remain
//! responsible for loading and atomically validating/importing the delta.
//! Bashkit never sees an ambient filesystem, process table, or network client.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use bashkit::{Bash, ExecutionLimits, FileSystem, FsLimits, InMemoryFs};

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

/// Bash output and the complete resulting governed workspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShellOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub files: BTreeMap<String, Vec<u8>>,
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

        let limits = ExecutionLimits::new()
            .timeout(request.timeout)
            .max_input_bytes(1024 * 1024)
            .max_commands(10_000)
            .max_loop_iterations(10_000)
            .max_total_loop_iterations(100_000)
            .max_stdout_bytes(self.max_output_bytes)
            .max_stderr_bytes(self.max_output_bytes);
        let bash_fs: Arc<dyn FileSystem> = fs;
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
            let files = collect_workspace(&bash_fs).await?;
            Ok::<_, String>((result, files))
        };
        // Native Bashkit arms Tokio's wall-clock timeout. The Cloudflare build
        // intentionally uses Bashkit's WASM path, which relies on structural
        // command/loop/fuel limits and does not require a timer reactor.
        #[cfg(not(target_family = "wasm"))]
        let (result, files) = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|error| format!("cannot start virtual bash runtime: {error}"))?
            .block_on(execution)?;
        #[cfg(target_family = "wasm")]
        let (result, files) = futures::executor::block_on(execution)?;
        Ok(ShellOutput {
            stdout: result.stdout,
            stderr: result.stderr,
            exit_code: result.exit_code,
            files,
        })
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
