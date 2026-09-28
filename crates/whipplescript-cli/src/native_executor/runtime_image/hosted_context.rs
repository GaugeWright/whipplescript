//! A portable build context for the hosted executor, without deployment side effects.
use super::*;
use std::collections::BTreeMap;

// The hosted executor's recipe is owned by whipplescript-host-do, at
// worker/executor/Dockerfile. A published crate carries only its own files, so
// an include reaching into that crate compiled here and failed crates.io's
// verification build (0.6.0 shipped without this crate for it). The copy is
// held to the owner byte for byte by tests/native_runtime_context.rs.
const PRODUCTION_RECIPE: &str = include_str!("executor.Dockerfile");
const IGNORE: &str = "*\n!Dockerfile\n!whip\n!reactor.wasm\n!runtime.json\n";
const NOTICES_IGNORE: &str = "!notices\n!notices/**\n";
/// Where a released image carries the guest's upstream notices (DR-0140).
const NOTICES_DIRECTORY: &str = "/usr/share/doc/whipplescript-norm-guest";
/// A notice collection's manifest and every notice it names are small text.
const MAX_NOTICE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedRuntimeContextRequest {
    pub runtime: PythonRuntime,
    pub artifact_source: PathBuf,
    pub build_root: PathBuf,
    /// The guest's collected upstream notices (`experiments/norm-wasi/
    /// notices.py`), shipped in the image when given. The collection must
    /// name this exact artifact, and each notice must match its digest.
    #[serde(default)]
    pub notices: Option<PathBuf>,
}

/// The notices a collection names, verified against its manifest and the
/// artifact it was collected for, as (file name, bytes), manifest first.
fn collected_notices(directory: &Path, artifact: &str) -> StoreResult<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let read = |name: &str| -> StoreResult<Vec<u8>> {
        let mut bytes = Vec::new();
        std::fs::File::open(directory.join(name))?
            .take(MAX_NOTICE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_NOTICE_BYTES {
            return Err(StoreError::Conflict(format!(
                "notice {name} exceeds its bound"
            )));
        }
        Ok(bytes)
    };
    let manifest_bytes = read("manifest.json")?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    if manifest["artifact_sha256"].as_str() != Some(artifact) {
        return Err(StoreError::Conflict(
            "the notice collection names another artifact".into(),
        ));
    }
    let entries = manifest["entries"]
        .as_array()
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| StoreError::Conflict("the notice collection lists no notices".into()))?;
    let mut notices = vec![("manifest.json".to_owned(), manifest_bytes)];
    for entry in entries {
        let (Some(file), Some(expected)) = (entry["file"].as_str(), entry["sha256"].as_str())
        else {
            return Err(StoreError::Conflict("a notice entry is malformed".into()));
        };
        if file.is_empty()
            || file == "manifest.json"
            || file.starts_with('.')
            || !file
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        {
            return Err(StoreError::Conflict(format!(
                "notice name {file:?} is not a plain file name"
            )));
        }
        if notices.iter().any(|(name, _)| name == file) {
            return Err(StoreError::Conflict(format!(
                "notice {file} is listed twice"
            )));
        }
        let bytes = read(file)?;
        if sha256_hex(&bytes) != expected {
            return Err(StoreError::Conflict(format!(
                "notice {file} differs from the digest its collection recorded"
            )));
        }
        notices.push((file.to_owned(), bytes));
    }
    Ok(notices)
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRuntimeContext {
    pub protocol: String,
    pub directory: PathBuf,
    pub runtime: PythonRuntime,
    pub files: BTreeMap<String, String>,
}

impl HostedRuntimeContextRequest {
    pub fn prepare(&self) -> StoreResult<PreparedRuntimeContext> {
        use ring::rand::{SecureRandom, SystemRandom};
        let (layers, pin) = installation_layers(&self.runtime)?;
        let reactor = read_artifact(&self.artifact_source, &pin)?;
        let notices = self
            .notices
            .as_deref()
            .map(|directory| collected_notices(directory, &pin))
            .transpose()?;
        if !self.build_root.is_absolute() {
            return Err(StoreError::Conflict(
                "runtime context requires an absolute build root".into(),
            ));
        }
        let mut recipe = format!("{PRODUCTION_RECIPE}\n{layers}");
        if notices.is_some() {
            recipe.push_str(&format!("COPY [\"notices\",\"{NOTICES_DIRECTORY}\"]\n"));
        }
        recipe.push_str("RUN [\"test\",\"!\",\"-e\",\"/tmp/whip-norm-profile\"]\n");
        recipe.push_str("RUN [\"test\",\"!\",\"-L\",\"/tmp/whip-norm-profile\"]\n");
        recipe.push_str("COPY [\"runtime.json\",\"/tmp/whip-norm-profile\"]\n");
        // The shell program is fixed. The executable is a positional argument,
        // so spaces, dollar signs and quotes remain literal path bytes.
        recipe.push_str(&format!(
            "RUN --network=none {}\n",
            json!([
                "/bin/sh",
                "-c",
                "exec \"$1\" executor verify-norm-runtime < /tmp/whip-norm-profile",
                "whip-norm-probe",
                self.runtime.executable,
            ])
        ));
        recipe.push_str("RUN [\"rm\",\"/tmp/whip-norm-profile\"]\n");
        std::fs::create_dir_all(&self.build_root)?;
        let mut nonce = [0u8; 16];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| StoreError::Conflict("runtime context nonce failed".into()))?;
        let nonce: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let directory = self.build_root.join(format!("norm-runtime-{nonce}"));
        std::fs::create_dir(&directory)?;
        let mut context = Context {
            path: directory,
            keep: false,
        };
        std::fs::write(context.path.join("Dockerfile"), recipe)?;
        let ignore = if notices.is_some() {
            format!("{IGNORE}{NOTICES_IGNORE}")
        } else {
            IGNORE.to_owned()
        };
        std::fs::write(context.path.join(".dockerignore"), ignore)?;
        std::fs::write(
            context.path.join("runtime.json"),
            serde_json::to_vec(&self.runtime)?,
        )?;
        std::fs::write(context.path.join("reactor.wasm"), reactor)?;
        std::fs::copy(std::env::current_exe()?, context.path.join("whip"))?;
        let mut files = BTreeMap::new();
        if let Some(notices) = &notices {
            std::fs::create_dir(context.path.join("notices"))?;
            for (name, bytes) in notices {
                std::fs::write(context.path.join("notices").join(name), bytes)?;
                files.insert(format!("notices/{name}"), sha256_hex(bytes));
            }
        }
        for name in [
            "Dockerfile",
            ".dockerignore",
            "runtime.json",
            "reactor.wasm",
            "whip",
        ] {
            files.insert(
                name.into(),
                sha256_hex(&std::fs::read(context.path.join(name))?),
            );
        }
        let receipt = PreparedRuntimeContext {
            protocol: "whipplescript.exec.norm-runtime-context/v1".into(),
            directory: context.path.clone(),
            runtime: self.runtime.clone(),
            files,
        };
        std::fs::write(
            context.path.join("context.json"),
            serde_json::to_vec(&receipt)?,
        )?;
        context.keep = true;
        Ok(receipt)
    }
}
