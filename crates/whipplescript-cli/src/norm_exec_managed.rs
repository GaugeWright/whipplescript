//! The ordinary worker's host-owned protected-observer boundary.
use super::*;
use whipplescript::native_executor::{native_norm_runs, NativeNormHost, NativeNormRecovery};
use whipplescript_kernel::norm_runner::{PythonCallMethod, PythonEngine};

pub(super) fn configuration() -> Result<Option<NativeNormHost>, StoreError> {
    env::var_os("WHIPPLESCRIPT_NATIVE_NORM_RUNTIME")
        .map(|path| NativeNormHost::load(Path::new(&path)))
        .transpose()
}

pub(super) fn protected(input: &Value) -> Result<bool, StoreError> {
    if input.get("norm_intent").is_none() && input.get("norm_dispatch").is_none() {
        return Ok(false);
    }
    let method: PythonCallMethod = serde_json::from_str(
        input["stdin"]["method_definition_json"]
            .as_str()
            .unwrap_or_default(),
    )?;
    Ok(matches!(
        method.runtime.engine,
        PythonEngine::Cpython3147Wasi { .. }
    ))
}

pub(super) fn require(host: Option<&NativeNormHost>) -> Result<&NativeNormHost, StoreError> {
    host.ok_or_else(|| StoreError::Conflict(
        "protected norm execution requires WHIPPLESCRIPT_NATIVE_NORM_RUNTIME host configuration".into(),
    ))
}

pub(super) fn recover(
    kernel: &mut RuntimeKernel<SqliteStore>,
    instance: &str,
    host: Option<&NativeNormHost>,
    now: &str,
    fence: bool,
) -> Result<NativeNormRecovery, StoreError> {
    if native_norm_runs(kernel.store(), instance)?.is_empty() {
        return Ok(NativeNormRecovery::default());
    }
    require(host)?
        .docker()?
        .recover_norm_instance(kernel, instance, now, fence)
}

pub(super) fn validate_enqueue(
    input: &Value,
    host: Option<&NativeNormHost>,
) -> Result<(), StoreError> {
    if protected(input)? {
        let method: PythonCallMethod = serde_json::from_str(
            input["stdin"]["method_definition_json"]
                .as_str()
                .unwrap_or_default(),
        )?;
        require(host)?.installed.validate_for(&method.runtime)?;
    }
    Ok(())
}
