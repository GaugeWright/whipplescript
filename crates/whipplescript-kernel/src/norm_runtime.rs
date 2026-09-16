//! Deployment assertions for fresh hosted norm admissions. Image installation
//! and verification remain the deployment owner's responsibility.
use crate::norm_runner::{PythonCallMethod, PythonEngine, PythonRuntime};
use serde_json::Value;

pub fn parse(configuration: &str) -> Result<PythonRuntime, String> {
    if configuration.len() > 16_384 {
        return Err("hosted norm runtime exceeds 16 KiB".into());
    }
    let runtime: PythonRuntime = serde_json::from_str(configuration).map_err(|e| e.to_string())?;
    let PythonEngine::Cpython3147Wasi {
        artifact_sha256, ..
    } = &runtime.engine
    else {
        return Err("hosted norm runtime must select the protected engine".into());
    };
    if runtime.environment.trim().is_empty()
        || runtime.executable.trim().is_empty()
        || runtime.python_version != "3.14.7"
        || artifact_sha256.len() != 64
        || !artifact_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("hosted norm runtime profile is invalid".into());
    }
    Ok(runtime)
}

pub fn validate(input: &Value, installed: Option<&PythonRuntime>) -> Result<(), String> {
    if input.get("norm_intent").is_none() && input.get("norm_dispatch").is_none() {
        return Ok(());
    }
    let method: PythonCallMethod = serde_json::from_str(
        input["stdin"]["method_definition_json"]
            .as_str()
            .ok_or("hosted norm execution requires its method definition")?,
    )
    .map_err(|e| e.to_string())?;
    if matches!(method.runtime.engine, PythonEngine::Cpython3147Wasi { .. }) {
        let installed =
            installed.ok_or("protected hosted norm execution requires WHIP_NORM_RUNTIME")?;
        if installed != &method.runtime {
            return Err("hosted norm method differs from the installed runtime profile".into());
        }
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessReceipt {
    protocol: String,
    incarnation: String,
    runtime: PythonRuntime,
}

/// The caller must have verified the runtime inside this process before
/// issuing the receipt. The codec does not establish that physical premise.
pub fn process_receipt(incarnation: &str, runtime: &PythonRuntime) -> Result<String, String> {
    crate::exec_incarnation::handshake(incarnation)?;
    parse(&serde_json::to_string(runtime).map_err(|e| e.to_string())?)?;
    serde_json::to_string(&ProcessReceipt {
        protocol: "whipplescript.exec.norm-runtime/v1".into(),
        incarnation: incarnation.into(),
        runtime: runtime.clone(),
    })
    .map_err(|e| e.to_string())
}

pub fn verify_process_receipt(
    receipt: &str,
    incarnation: &str,
    configuration: &str,
) -> Result<(), String> {
    if receipt.len() > 32_768 {
        return Err("norm process receipt exceeds 32 KiB".into());
    }
    let expected = parse(configuration)?;
    crate::exec_incarnation::handshake(incarnation)?;
    let receipt: ProcessReceipt = serde_json::from_str(receipt).map_err(|e| e.to_string())?;
    if receipt.protocol != "whipplescript.exec.norm-runtime/v1"
        || receipt.incarnation != incarnation
        || receipt.runtime != expected
    {
        return Err("norm process receipt differs from the expected incarnation or runtime".into());
    }
    Ok(())
}

/// This is a preflight constraint, never admission authority. The controller
/// separately validates placement ownership and commits its admission atomically.
pub fn validate_placement_runtime(
    placement: &str,
    configuration: Option<&str>,
) -> Result<(), String> {
    use crate::exec_http::sha256_hex;
    use crate::norm_runner::EMBEDDED_ADAPTER;
    let placement: crate::exec_placement::Placement =
        serde_json::from_str(placement).map_err(|e| e.to_string())?;
    let dispatch = placement.dispatch()?;
    let loader = dispatch["script_sha256"].as_str()
        == Some(sha256_hex(EMBEDDED_ADAPTER.as_bytes()).as_str());
    let command = dispatch["argv"].as_array().is_some_and(|argv| {
        argv.get(1).and_then(Value::as_str) == Some("executor")
            && argv.get(2).and_then(Value::as_str) == Some("observe-norm")
    });
    if !loader && !command {
        return Ok(());
    }
    let method: PythonCallMethod = serde_json::from_str(
        dispatch["stdin"]["method_definition_json"]
            .as_str()
            .ok_or("protected invocation requires its retained method definition")?,
    )
    .map_err(|e| e.to_string())?;
    let configured =
        parse(configuration.ok_or("protected invocation requires a configured runtime")?)?;
    if method.runtime != configured {
        return Err(
            "protected invocation runtime differs from current container configuration".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn profile() -> Value {
        json!({"engine":{"kind":"cpython3147_wasi","artifact_path":"/opt/reactor.wasm","artifact_sha256":"a".repeat(64)},
            "executable":"/usr/local/bin/whip","python_version":"3.14.7","environment":"norm-epoch"})
    }
    #[test]
    fn hosted_norm_profile_is_bounded_closed_and_exact() {
        let good = profile();
        let mut padded = good.to_string();
        padded.extend(std::iter::repeat_n(' ', 16_384 - padded.len()));
        let installed = parse(&padded).unwrap();
        assert!(parse(&(padded + " ")).is_err());
        for field in [
            "unknown",
            "environment",
            "executable",
            "python_version",
            "engine",
        ] {
            let mut changed = good.clone();
            changed[field] = json!("");
            assert!(parse(&changed.to_string()).is_err(), "{field}");
        }
        let input = |runtime: Value| {
            json!({"norm_intent":{}, "stdin":{"method_definition_json":json!({
            "runtime":runtime,"module":"main","function":"check","cases":[]
        }).to_string()}})
        };
        assert!(validate(&input(good.clone()), Some(&installed)).is_ok());
        assert!(validate(&input(good.clone()), None).is_err());
        for field in [
            "executable",
            "python_version",
            "environment",
            "artifact_path",
            "artifact_sha256",
        ] {
            let mut changed = good.clone();
            if field.starts_with("artifact_") {
                changed["engine"][field] = json!("changed");
            } else {
                changed[field] = json!("changed");
            }
            assert!(
                validate(&input(changed), Some(&installed)).is_err(),
                "{field}"
            );
        }
        let mut cooperative = good;
        cooperative.as_object_mut().unwrap().remove("engine");
        assert!(parse(&cooperative.to_string()).is_err());
        assert!(validate(&input(cooperative), None).is_ok());
        assert!(validate(&json!({"stdin":{}}), None).is_ok());
        assert!(validate(&json!({"norm_intent":{},"stdin":{}}), Some(&installed)).is_err());
        assert!(validate(&json!({"norm_dispatch":{},"stdin":{}}), None).is_err());
    }

    #[test]
    fn norm_process_receipt_is_closed_bounded_and_bound_to_the_process() {
        let configuration = profile().to_string();
        let runtime = parse(&configuration).unwrap();
        let receipt = process_receipt("process-one", &runtime).unwrap();
        verify_process_receipt(&receipt, "process-one", &configuration).unwrap();
        let mut padded = receipt.clone();
        padded.extend(std::iter::repeat_n(' ', 32_768 - padded.len()));
        verify_process_receipt(&padded, "process-one", &configuration).unwrap();
        assert!(verify_process_receipt(&(padded + " "), "process-one", &configuration).is_err());
        for field in ["protocol", "incarnation", "runtime", "unknown"] {
            let mut changed: Value = serde_json::from_str(&receipt).unwrap();
            changed[field] = json!("changed");
            assert!(
                verify_process_receipt(&changed.to_string(), "process-one", &configuration)
                    .is_err(),
                "{field}"
            );
        }
        assert!(verify_process_receipt(&receipt, "process-two", &configuration).is_err());
        let mut changed = profile();
        changed["environment"] = json!("changed");
        assert!(verify_process_receipt(&receipt, "process-one", &changed.to_string()).is_err());
        for malformed in ["", "{}", "[]", "null", "{} {}"] {
            assert!(verify_process_receipt(malformed, "process-one", &configuration).is_err());
        }
        assert!(process_receipt("", &runtime).is_err());
    }
    #[test]
    fn protected_placement_requires_its_original_runtime_before_startup() {
        use crate::exec_http::sha256_hex;
        let runtime = profile();
        let configuration = runtime.to_string();
        let method = json!({"runtime":runtime,"module":"main","function":"check","cases":[]});
        let dispatch = json!({"protocol":"whip-executor/1", "effect_id":"effect",
            "script_sha256":sha256_hex(crate::norm_runner::EMBEDDED_ADAPTER.as_bytes()),
            "argv":[runtime["executable"], "executor", "observe-norm", "{script}"],
            "stdin":{"method_definition_json":method.to_string()}});
        let placement = |dispatch: Value| {
            let selected = crate::exec_invocation::Invocation {
                instance_id: "instance".into(),
                effect_id: "effect".into(),
                attempt_admission_event_id: None,
            };
            let envelope = serde_json::to_string(
                &crate::exec_invocation::Envelope::new(selected.clone(), dispatch).unwrap(),
            )
            .unwrap();
            let selected = serde_json::to_string(&selected).unwrap();
            let claim: Value = serde_json::from_str(
                &crate::exec_invocation::claim_json(&selected, &envelope, None).unwrap(),
            )
            .unwrap();
            crate::exec_placement::bind_controller_json(
                &selected,
                &envelope,
                &claim["decision"]["receipt"].to_string(),
                None,
                "container",
                "dispatch",
            )
            .unwrap()
        };
        for marker in ["both", "loader", "command"] {
            let mut request = dispatch.clone();
            if marker == "loader" {
                request.as_object_mut().unwrap().remove("argv");
            }
            if marker == "command" {
                request.as_object_mut().unwrap().remove("script_sha256");
            }
            let placed = placement(request);
            validate_placement_runtime(&placed, Some(&configuration)).unwrap();
            assert!(
                validate_placement_runtime(&placed, None).is_err(),
                "{marker}"
            );
        }
        for field in [
            "environment",
            "executable",
            "python_version",
            "artifact_path",
            "artifact_sha256",
        ] {
            let mut altered = method.clone();
            if field.starts_with("artifact_") {
                altered["runtime"]["engine"][field] = json!("changed");
            } else {
                altered["runtime"][field] = json!("changed");
            }
            let mut request = dispatch.clone();
            request["stdin"]["method_definition_json"] = json!(altered.to_string());
            assert!(
                validate_placement_runtime(&placement(request), Some(&configuration)).is_err(),
                "{field}"
            );
        }
        for malformed in [Value::Null, json!("{}"), json!("invalid")] {
            let mut request = dispatch.clone();
            request["stdin"]["method_definition_json"] = malformed;
            assert!(validate_placement_runtime(&placement(request), Some(&configuration)).is_err());
        }
        let mut ordinary = dispatch.clone();
        ordinary.as_object_mut().unwrap().remove("argv");
        ordinary.as_object_mut().unwrap().remove("script_sha256");
        validate_placement_runtime(&placement(ordinary), None).unwrap();
        let original = placement(dispatch);
        for fault in ["legacy", "identity", "unknown"] {
            let mut invalid: Value = serde_json::from_str(&original).unwrap();
            match fault {
                "legacy" => invalid["protocol"] = json!("whipplescript.exec.placement/v1"),
                "identity" => invalid["selected"]["effect_id"] = json!("changed"),
                _ => invalid["unknown"] = json!(true),
            }
            assert!(
                validate_placement_runtime(&invalid.to_string(), Some(&configuration)).is_err(),
                "{fault}"
            );
        }
    }
}
