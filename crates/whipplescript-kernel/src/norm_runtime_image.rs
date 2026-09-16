//! Deployment-owned immutable image evidence. Parsing is not authentication.
use crate::norm_runner::PythonRuntime;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    protocol: String,
    image_id: String,
    runtime: PythonRuntime,
}
/// Its source must be trusted installation output, never candidate input.
#[derive(Serialize)]
#[serde(transparent)]
pub struct InstalledRuntimeImage(Binding);
impl InstalledRuntimeImage {
    pub fn parse(configuration: &str) -> Result<Self, String> {
        if configuration.len() > 32_768 {
            return Err("runtime image binding exceeds 32 KiB".into());
        }
        let binding: Binding = serde_json::from_str(configuration).map_err(|e| e.to_string())?;
        if binding.protocol != "whipplescript.exec.runtime-image/v1"
            || !image_identity(&binding.image_id)
        {
            return Err(
                "runtime image binding requires its protocol and immutable image identity".into(),
            );
        }
        crate::norm_runtime::parse(
            &serde_json::to_string(&binding.runtime).map_err(|e| e.to_string())?,
        )?;
        Ok(Self(binding))
    }
    pub fn image_id(&self) -> &str {
        &self.0.image_id
    }
    pub fn validate_for(
        &self,
        deployed_image: &str,
        runtime: &PythonRuntime,
    ) -> Result<(), String> {
        if deployed_image != self.0.image_id || runtime != &self.0.runtime {
            return Err(
                "runtime image binding differs from deployment image or selected runtime".into(),
            );
        }
        Ok(())
    }
    /// The embedding must have executed this probe in the exact inspected image.
    /// Matching JSON alone does not prove that physical premise.
    pub fn from_probe(
        image_id: &str,
        runtime: &PythonRuntime,
        probe: &str,
    ) -> Result<Self, String> {
        if probe.len() > 32_768 {
            return Err("runtime image probe exceeds 32 KiB".into());
        }
        let probe: serde_json::Value = serde_json::from_str(probe).map_err(|e| e.to_string())?;
        if probe
            != serde_json::json!({"protocol":"whipplescript.norm.runtime-probe/v1", "runtime":runtime})
        {
            return Err("runtime image probe differs from selected profile".into());
        }
        Self::parse(&serde_json::json!({"protocol":"whipplescript.exec.runtime-image/v1", "image_id":image_id, "runtime":runtime}).to_string())
    }
}
pub fn image_identity(image: &str) -> bool {
    image.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
