//! A portable build context for the hosted executor, without deployment side effects.
use super::*;
use std::collections::BTreeMap;

const PRODUCTION_RECIPE: &str =
    include_str!("../../../../whipplescript-host-do/worker/executor/Dockerfile");
const IGNORE: &str = "*\n!Dockerfile\n!whip\n!reactor.wasm\n!runtime.json\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedRuntimeContextRequest {
    pub runtime: PythonRuntime,
    pub artifact_source: PathBuf,
    pub build_root: PathBuf,
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
        if !self.build_root.is_absolute() {
            return Err(StoreError::Conflict(
                "runtime context requires an absolute build root".into(),
            ));
        }
        let mut recipe = format!("{PRODUCTION_RECIPE}\n{layers}");
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
        std::fs::write(context.path.join(".dockerignore"), IGNORE)?;
        std::fs::write(
            context.path.join("runtime.json"),
            serde_json::to_vec(&self.runtime)?,
        )?;
        std::fs::write(context.path.join("reactor.wasm"), reactor)?;
        std::fs::copy(std::env::current_exe()?, context.path.join("whip"))?;
        let mut files = BTreeMap::new();
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
