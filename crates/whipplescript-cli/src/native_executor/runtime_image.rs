//! Install a pinned protected observer without rewriting its runtime profile.
use super::*;
use serde_json::{json, Value};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use whipplescript_kernel::{
    exec_http::sha256_hex,
    norm_runner::{PythonEngine, PythonRuntime},
};

const SIDECAR: &str = "/usr/local/bin/whip";
const MAX_REACTOR: u64 = 64 * 1024 * 1024;
pub const MAX_NORM_RUNTIME_PROFILE_BYTES: u64 = 16 * 1024;
pub const NORM_RUNTIME_PROBE_PROTOCOL: &str = "whipplescript.norm.runtime-probe/v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRuntimeImage {
    pub protocol: String,
    pub daemon_id: String,
    pub base_image: String,
    pub image_id: String,
    pub runtime: PythonRuntime,
}
impl NativeRuntimeImage {
    /// The binding comes from host installation, never candidate-supplied data.
    pub fn validate_for(&self, runtime: &PythonRuntime) -> StoreResult<()> {
        recipe(&self.base_image, &self.runtime)?;
        if self.protocol != "whipplescript.exec.native-runtime-image/v1"
            || self.daemon_id.is_empty()
            || self.daemon_id.len() > 128
            || self.daemon_id.chars().any(char::is_control)
            || !self.image_id.strip_prefix("sha256:").is_some_and(digest)
            || &self.runtime != runtime
        {
            return Err(StoreError::Conflict(
                "native norm runtime binding differs from its installed profile".into(),
            ));
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeImageRequest {
    pub endpoint: String,
    pub daemon_id: String,
    pub base_image: String,
    pub build_root: PathBuf,
    pub artifact_source: PathBuf,
    pub runtime: PythonRuntime,
}
impl RuntimeImageRequest {
    pub fn install(&self) -> StoreResult<NativeRuntimeImage> {
        Docker::new(&self.endpoint)?.install_norm_runtime(
            &self.daemon_id,
            &self.base_image,
            &self.runtime,
            &self.artifact_source,
            &self.build_root,
        )
    }
}

fn image_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path[1..]
            .split('/')
            .all(|part| !matches!(part, "" | "." | ".."))
        && !["dev", "proc", "sys", "tmp", "authority"]
            .contains(&path[1..].split('/').next().unwrap_or(""))
}
fn base_alias(base: &str) -> String {
    format!(
        "whip-native-runtime-base:{}",
        base.trim_start_matches("sha256:")
    )
}
fn recipe(base: &str, runtime: &PythonRuntime) -> StoreResult<(String, String)> {
    if !base.strip_prefix("sha256:").is_some_and(digest) {
        return Err(StoreError::Conflict(
            "runtime installation requires an immutable base image".into(),
        ));
    }
    let (layers, pin) = installation_layers(runtime)?;
    Ok((format!("FROM {}@{base}\n{layers}", base_alias(base)), pin))
}
fn installation_layers(runtime: &PythonRuntime) -> StoreResult<(String, String)> {
    let PythonEngine::Cpython3147Wasi {
        artifact_path,
        artifact_sha256,
    } = &runtime.engine
    else {
        return Err(StoreError::Conflict(
            "runtime installation requires the protected WASI profile".into(),
        ));
    };
    if serde_json::to_vec(runtime)?.len() as u64 > MAX_NORM_RUNTIME_PROFILE_BYTES
        || runtime.python_version != "3.14.7"
        || runtime.environment.trim().is_empty()
        || !digest(artifact_sha256)
        || !image_path(&runtime.executable)
        || !image_path(artifact_path)
        || artifact_path == SIDECAR
        || artifact_path == &runtime.executable
        || artifact_path.starts_with(&format!("{}/", runtime.executable))
        || runtime.executable.starts_with(&format!("{artifact_path}/"))
    {
        return Err(StoreError::Conflict(
            "runtime installation profile or image paths are invalid".into(),
        ));
    }
    let mut dockerfile = String::new();
    dockerfile.push_str(&format!(
        "RUN {}\n",
        json!(["test", "!", "-e", artifact_path])
    ));
    dockerfile.push_str(&format!(
        "RUN {}\n",
        json!(["test", "!", "-L", artifact_path])
    ));
    // COPY performs Dockerfile variable substitution even in JSON form.
    // Keep its destination fixed; exec-form mv preserves the declared path.
    let stage = "/tmp/whip-norm-reactor";
    dockerfile.push_str(&format!("RUN {}\n", json!(["test", "!", "-e", stage])));
    dockerfile.push_str(&format!("RUN {}\n", json!(["test", "!", "-L", stage])));
    dockerfile.push_str(&format!("COPY {}\n", json!(["reactor.wasm", stage])));
    let parent = artifact_path
        .rsplit_once('/')
        .expect("validated absolute image path")
        .0;
    let parent = if parent.is_empty() { "/" } else { parent };
    dockerfile.push_str(&format!("RUN {}\n", json!(["mkdir", "-p", parent])));
    dockerfile.push_str(&format!(
        "RUN {}\n",
        json!(["mv", "-T", stage, artifact_path])
    ));
    if runtime.executable != SIDECAR {
        let parent = runtime
            .executable
            .rsplit_once('/')
            .expect("validated absolute image path")
            .0;
        let parent = if parent.is_empty() { "/" } else { parent };
        dockerfile.push_str(&format!("RUN {}\n", json!(["mkdir", "-p", parent])));
        dockerfile.push_str(&format!(
            "RUN {}\n",
            json!(["ln", "-sT", SIDECAR, runtime.executable])
        ));
    }
    Ok((dockerfile, artifact_sha256.clone()))
}
struct Context {
    path: PathBuf,
    keep: bool,
}
impl Drop for Context {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
impl Docker {
    pub fn install_norm_runtime(
        &mut self,
        daemon: &str,
        base: &str,
        runtime: &PythonRuntime,
        artifact_source: &Path,
        build_root: &Path,
    ) -> StoreResult<NativeRuntimeImage> {
        use ring::rand::{SecureRandom, SystemRandom};
        let (dockerfile, expected_digest) = recipe(base, runtime)?;
        let bytes = read_artifact(artifact_source, &expected_digest)?;
        if !build_root.is_absolute() {
            return Err(StoreError::Conflict(
                "runtime installation requires an absolute build root".into(),
            ));
        }
        if daemon.is_empty() || self.daemon_id()? != daemon {
            return Err(StoreError::Conflict(
                "runtime installation daemon differs from its retained binding".into(),
            ));
        }
        let expected_entrypoint = json!(["whip", "executor", "--bind", "0.0.0.0:8080"]);
        let entrypoint: Value = serde_json::from_str(&self.command(
            &[
                "image",
                "inspect",
                "--format",
                "{{json .Config.Entrypoint}}",
                base,
            ],
            None,
        )?)?;
        if entrypoint != expected_entrypoint {
            return Err(StoreError::Conflict(
                "runtime base has a different sidecar entrypoint".into(),
            ));
        }
        // BuildKit requires a repository-qualified reference. The alias is a
        // content-addressed local cache name; FROM still pins the original digest.
        // Retain it: removing a last tag could delete the caller's base image.
        let alias = base_alias(base);
        let held = self.command(
            &[
                "image",
                "ls",
                "--no-trunc",
                "--filter",
                &format!("reference={alias}"),
                "--format",
                "{{.ID}}",
            ],
            None,
        )?;
        if held.is_empty() {
            self.command(&["image", "tag", base, &alias], None)?;
        } else if held != base {
            return Err(StoreError::Conflict(
                "runtime base cache alias already names another image".into(),
            ));
        }
        if self.command(&["image", "inspect", "--format", "{{.Id}}", &alias], None)? != base {
            return Err(StoreError::Conflict(
                "runtime base cache alias differs from its digest".into(),
            ));
        }
        std::fs::create_dir_all(build_root)?;
        let mut nonce = [0u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| StoreError::Conflict("runtime installation nonce failed".into()))?;
        let name: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = build_root.join(format!("norm-runtime-{name}"));
        std::fs::create_dir(&directory)?;
        let context = Context {
            path: directory,
            keep: false,
        };
        std::fs::write(context.path.join("Dockerfile"), dockerfile)?;
        std::fs::write(
            context.path.join(".dockerignore"),
            "*\n!Dockerfile\n!reactor.wasm\n",
        )?;
        std::fs::write(context.path.join("reactor.wasm"), bytes)?;
        let iid = context.path.join("image-id");
        let text = |path: &Path| -> StoreResult<String> {
            path.to_str()
                .map(str::to_owned)
                .ok_or_else(|| StoreError::Conflict("runtime build path is not UTF-8".into()))
        };
        self.command_io(
            &[
                "build",
                "--network",
                "none",
                "--pull=false",
                "--quiet",
                "--iidfile",
                &text(&iid)?,
                &text(&context.path)?,
            ],
            None,
            None,
            65536,
            Duration::from_secs(360),
        )?;
        let image = std::fs::read_to_string(iid)?.trim().to_owned();
        if !image.strip_prefix("sha256:").is_some_and(digest)
            || self.daemon_id()? != daemon
            || self.command(&["image", "inspect", "--format", "{{.Id}}", &image], None)? != image
        {
            return Err(StoreError::Conflict(
                "runtime installation image or daemon identity changed".into(),
            ));
        }
        let probe = self.command_io(
            &[
                "run",
                "--rm",
                "-i",
                "--pull=never",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--entrypoint",
                &runtime.executable,
                &image,
                "executor",
                "verify-norm-runtime",
            ],
            None,
            Some(serde_json::to_vec(runtime)?),
            65536,
            Duration::from_secs(360),
        )?;
        if serde_json::from_str::<Value>(&probe)?
            != json!({"protocol":NORM_RUNTIME_PROBE_PROTOCOL,"runtime":runtime})
            || self.daemon_id()? != daemon
        {
            return Err(StoreError::Conflict(
                "runtime installation probe did not acknowledge the pinned profile".into(),
            ));
        }
        Ok(NativeRuntimeImage {
            protocol: "whipplescript.exec.native-runtime-image/v1".into(),
            daemon_id: daemon.into(),
            base_image: base.into(),
            image_id: image,
            runtime: runtime.clone(),
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(all(test, unix))]
mod worker_races;

fn read_artifact(artifact_source: &Path, expected_digest: &str) -> StoreResult<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(artifact_source)?
        .take(MAX_REACTOR + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REACTOR || sha256_hex(&bytes) != expected_digest {
        return Err(StoreError::Conflict(
            "runtime installation artifact differs from its pin".into(),
        ));
    }
    Ok(bytes)
}

mod hosted_context;
pub use hosted_context::{HostedRuntimeContextRequest, PreparedRuntimeContext};

mod verify_image;
pub use verify_image::RuntimeImageVerificationRequest;
