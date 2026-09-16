//! Host configuration is a locator and a fresh-installation selection, never
//! authority to replace a running invocation's retained binding.
use super::*;
use std::{io::Read, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeNormHost {
    pub protocol: String,
    pub endpoint: String,
    pub installed: NativeRuntimeImage,
}
impl NativeNormHost {
    pub fn load(path: &Path) -> StoreResult<Self> {
        if !path.is_absolute() {
            return Err(StoreError::Conflict(
                "native norm host configuration requires an absolute path".into(),
            ));
        }
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(65_537)
            .read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(StoreError::Conflict(
                "native norm host configuration exceeds 64 KiB".into(),
            ));
        }
        let host: Self = serde_json::from_slice(&bytes)?;
        host.validate()?;
        Ok(host)
    }
    pub fn validate(&self) -> StoreResult<()> {
        if self.protocol != "whipplescript.exec.native-norm-host/v1" {
            return Err(StoreError::Conflict(
                "native norm host protocol is unsupported".into(),
            ));
        }
        Docker::new(&self.endpoint)?;
        self.installed.validate_for(&self.installed.runtime)
    }
    pub fn docker(&self) -> StoreResult<Docker> {
        self.validate()?;
        Docker::new(&self.endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_executor::norm_admission::tests::{binding, fixture_with_store};
    use whipplescript_kernel::norm_runner::PythonCallMethod;
    #[test]
    fn native_norm_host_configuration_is_bounded_and_closed() {
        let (_, _, effect, _) = fixture_with_store("exact", SqliteStore::open_in_memory().unwrap());
        let input: serde_json::Value = serde_json::from_str(&effect.input_json).unwrap();
        let method: PythonCallMethod =
            serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap())
                .unwrap();
        let host = NativeNormHost {
            protocol: "whipplescript.exec.native-norm-host/v1".into(),
            endpoint: "unix:///fixture".into(),
            installed: binding(method.runtime),
        };
        let path =
            std::env::temp_dir().join(format!("native-norm-host-{}.json", std::process::id()));
        let good = serde_json::to_value(&host).unwrap();
        for fault in [
            "valid",
            "protocol",
            "endpoint",
            "binding",
            "unknown",
            "oversized",
        ] {
            let mut input = good.clone();
            match fault {
                "protocol" => input["protocol"] = "foreign".into(),
                "endpoint" => input["endpoint"] = "".into(),
                "binding" => input["installed"]["image_id"] = "mutable:latest".into(),
                "unknown" => input["untrusted"] = true.into(),
                _ => {}
            }
            let mut encoded = input.to_string();
            encoded.extend(std::iter::repeat_n(
                ' ',
                (if fault == "oversized" { 65_537 } else { 65_536 }) - encoded.len(),
            ));
            std::fs::write(&path, encoded).unwrap();
            let result = NativeNormHost::load(&path);
            assert_eq!(result.is_ok(), fault == "valid", "{fault}");
            if let Ok(loaded) = result {
                assert_eq!(loaded.installed, host.installed);
            }
        }
        let relative = std::path::PathBuf::from("target")
            .join(format!("native-norm-relative-{}.json", std::process::id()));
        std::fs::create_dir_all(relative.parent().unwrap()).unwrap();
        std::fs::write(&relative, good.to_string()).unwrap();
        let result = NativeNormHost::load(&relative);
        std::fs::remove_file(relative).unwrap();
        assert!(result.is_err());
        std::fs::remove_file(path).unwrap();
    }
}
