//! Probe an existing immutable image and emit deployment installation evidence.
use super::*;
use whipplescript_kernel::norm_runtime_image::{image_identity, InstalledRuntimeImage};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeImageVerificationRequest {
    pub endpoint: String,
    pub image_id: String,
    pub runtime: PythonRuntime,
}
impl RuntimeImageVerificationRequest {
    pub fn verify(&self) -> StoreResult<InstalledRuntimeImage> {
        Docker::new(&self.endpoint)?.verify_norm_runtime_image(&self.image_id, &self.runtime)
    }
}
impl Docker {
    pub fn verify_norm_runtime_image(
        &mut self,
        image: &str,
        runtime: &PythonRuntime,
    ) -> StoreResult<InstalledRuntimeImage> {
        if !image_identity(image) {
            return Err(StoreError::Conflict(
                "runtime verification requires an immutable image".into(),
            ));
        }
        installation_layers(runtime)?;
        let daemon = self.daemon_id()?;
        if self.command(&["image", "inspect", "--format", "{{.Id}}", image], None)? != image {
            return Err(StoreError::Conflict(
                "runtime verification image identity differs".into(),
            ));
        }
        let entrypoint: Value = serde_json::from_str(&self.command(
            &[
                "image",
                "inspect",
                "--format",
                "{{json .Config.Entrypoint}}",
                image,
            ],
            None,
        )?)?;
        if entrypoint != json!(["whip", "executor", "--bind", "0.0.0.0:8080"]) {
            return Err(StoreError::Conflict(
                "runtime verification requires the production entrypoint".into(),
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
                image,
                "executor",
                "verify-norm-runtime",
            ],
            None,
            Some(serde_json::to_vec(runtime)?),
            32768,
            Duration::from_secs(360),
        )?;
        if self.daemon_id()? != daemon
            || self.command(&["image", "inspect", "--format", "{{.Id}}", image], None)? != image
        {
            return Err(StoreError::Conflict(
                "runtime verification image or daemon changed".into(),
            ));
        }
        InstalledRuntimeImage::from_probe(image, runtime, &probe).map_err(StoreError::Conflict)
    }
}
