//! Protected call observation in an executor-owned child process.
//! Candidate Python receives files and call arguments, never report authority.
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::{json, Value};
use whipplescript_core::norm_evidence::ReportContract;
use whipplescript_kernel::exec_http::sha256_hex;
use whipplescript_kernel::norm_runner::{
    candidate_identity, PreparedNormRun, PythonCallMethod, PythonEngine, PythonRuntime,
    EMBEDDED_ADAPTER,
};

const MAX_INPUT: u64 = 2 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    run_id: String,
    method_definition_json: String,
    files: BTreeMap<String, String>,
    contract_json: String,
}

pub(crate) fn command(args: &[String]) -> ExitCode {
    let result = (|| {
        validate_loader(args)?;
        let body = read_input(std::io::stdin())?;
        let mut output = std::io::stdout().lock();
        execute(&body, &mut |event| {
            serde_json::to_writer(&mut output, &event).map_err(|e| e.to_string())?;
            output
                .write_all(b"\n")
                .and_then(|()| output.flush())
                .map_err(|e| e.to_string())
        })
    })();
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("norm observer: {error}");
            ExitCode::from(2)
        }
    }
}

fn validate_loader(args: &[String]) -> Result<(), String> {
    let [path] = args else {
        // MUTATION-SUCCESS-EXPR: Ok(())
        return Err("observe-norm requires its pinned loader path".into());
    };
    if std::fs::read_to_string(path).map_err(|e| e.to_string())? != EMBEDDED_ADAPTER {
        return Err("norm observer loader differs from its installed profile".into());
    }
    Ok(())
}

fn read_input(input: impl Read) -> Result<String, String> {
    let mut body = String::new();
    input
        .take(MAX_INPUT + 1)
        .read_to_string(&mut body)
        .map_err(|e| e.to_string())?;
    if body.len() as u64 > MAX_INPUT {
        return Err("norm observer input exceeds its budget".into());
    }
    Ok(body)
}

pub(crate) fn execute(
    body: &str,
    emit: &mut dyn FnMut(Value) -> Result<(), String>,
) -> Result<u8, String> {
    let input: Input = serde_json::from_str(body).map_err(|e| e.to_string())?;
    let method: PythonCallMethod =
        serde_json::from_str(&input.method_definition_json).map_err(|e| e.to_string())?;
    let contract: ReportContract =
        serde_json::from_str(&input.contract_json).map_err(|e| e.to_string())?;
    execute_wasi(input, method, contract, emit)
}

fn load_runtime(profile: &PythonRuntime) -> Result<crate::norm_wasi::Runtime, String> {
    let PythonEngine::Cpython3147Wasi {
        artifact_path,
        artifact_sha256,
    } = &profile.engine
    else {
        return Err("norm WASI observer requires its explicit runtime profile".into());
    };
    if profile.python_version != "3.14.7"
        || profile.executable.trim().is_empty()
        || profile.environment.trim().is_empty()
    {
        return Err("norm runtime probe requires a complete CPython 3.14.7 profile".into());
    }
    const MAX_RUNTIME_BYTES: u64 = 64 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(artifact_path)
        .map_err(|error| error.to_string())?
        .take(MAX_RUNTIME_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_RUNTIME_BYTES {
        return Err("norm runtime artifact exceeds its byte budget".into());
    }
    let runtime = crate::norm_wasi::Runtime::new(&bytes, artifact_sha256)
        .map_err(|error| error.to_string())?;
    Ok(runtime)
}

pub(crate) fn verify_runtime_command(args: &[String]) -> ExitCode {
    let result = (|| -> Result<(), String> {
        if !args.is_empty() {
            return Err("verify-norm-runtime accepts only its runtime profile on stdin".into());
        }
        let mut bytes = Vec::new();
        std::io::stdin()
            .take(whipplescript::native_executor::MAX_NORM_RUNTIME_PROFILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > whipplescript::native_executor::MAX_NORM_RUNTIME_PROFILE_BYTES {
            return Err("norm runtime profile exceeds its input bound".into());
        }
        let profile: PythonRuntime = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        verify_runtime_profile(&profile)?;
        serde_json::to_writer(
            std::io::stdout(),
            &json!({
                "protocol":whipplescript::native_executor::NORM_RUNTIME_PROBE_PROTOCOL,
                "runtime":profile,
            }),
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("norm runtime verification failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn execute_wasi(
    input: Input,
    method: PythonCallMethod,
    contract: ReportContract,
    emit: &mut dyn FnMut(Value) -> Result<(), String>,
) -> Result<u8, String> {
    PreparedNormRun::prepare(
        contract.clone(),
        method.clone(),
        input.files.clone(),
        input.run_id.clone(),
    )?;
    let mut guest = load_runtime(&method.runtime)?
        .instantiate()
        .map_err(|error| error.to_string())?;
    emit(
        json!({"kind":"started", "protocol":method.protocol(), "run_id":input.run_id,
        "artifact":candidate_identity(&input.files), "contract_digest":sha256_hex(input.contract_json.as_bytes()),
        "requirement":contract.subject.requirement, "method":method.reference(),
        "environment":method.runtime.environment, "adapter_digest":sha256_hex(EMBEDDED_ADAPTER.as_bytes()),
        "python_version":"3.14.7"}),
    )?;
    let mut failed = false;
    let mut broken = false;
    let files = serde_json::to_value(&input.files).map_err(|error| error.to_string())?;
    match guest.load(&files, EMBEDDED_ADAPTER, &method.module, &method.function) {
        Err(error) => {
            broken = true;
            emit(json!({"kind":"error", "case":null, "message":error.to_string()}))?;
        }
        Ok(()) => {
            let required: BTreeMap<_, _> =
                contract.cases.iter().map(|case| (&case.id, case)).collect();
            for case in &method.cases {
                match guest.call(&json!(case.args), &json!(case.kwargs)) {
                    Ok(actual) => {
                        let expected = required[&case.id];
                        failed |= actual != expected.expected;
                        emit(
                            json!({"kind":"case", "case":case.id, "assertion":expected.assertion, "actual":actual}),
                        )?;
                    }
                    Err(error) => {
                        broken = true;
                        emit(json!({"kind":"error", "case":case.id, "message":error.to_string()}))?;
                        // The failed guest is unusable; do not synthesize observations
                        // for remaining calls. Earlier emitted cases remain intact.
                        break;
                    }
                }
            }
        }
    }
    std::io::stderr()
        .write_all(&guest.diagnostics())
        .map_err(|error| error.to_string())?;
    emit(json!({"kind":"complete"}))?;
    Ok(if broken {
        2
    } else if failed {
        1
    } else {
        0
    })
}

pub(crate) fn verify_runtime_profile(profile: &PythonRuntime) -> Result<(), String> {
    let declared = std::fs::canonicalize(&profile.executable).map_err(|e| e.to_string())?;
    let actual = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|e| e.to_string())?;
    if declared != actual {
        return Err("norm runtime probe executable differs from its declared profile".into());
    }

    load_runtime(profile)?
        .instantiate()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn norm_observer_loader_and_input_limits_are_checked_directly() {
        assert_eq!(
            validate_loader(&[]).unwrap_err(),
            "observe-norm requires its pinned loader path"
        );
        let path = std::env::temp_dir().join(format!(
            "norm-observer-loader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let args = [path.to_string_lossy().into_owned()];
        std::fs::write(&path, EMBEDDED_ADAPTER).unwrap();
        assert!(validate_loader(&args).is_ok());
        std::fs::write(&path, "different loader").unwrap();
        let error = validate_loader(&args).unwrap_err();
        std::fs::remove_file(path).unwrap();
        assert_eq!(
            error,
            "norm observer loader differs from its installed profile"
        );
        assert_eq!(read_input(&b"{}"[..]).unwrap(), "{}");
        assert!(read_input(&vec![b' '; MAX_INPUT as usize][..]).is_ok());
        assert_eq!(
            read_input(&vec![b' '; MAX_INPUT as usize + 1][..]).unwrap_err(),
            "norm observer input exceeds its budget"
        );
    }

    fn input(
        engine: PythonEngine,
        version: String,
        module: &str,
        function: &str,
        source: &str,
        expected: Value,
    ) -> String {
        use whipplescript_core::norm_evidence::{EvidenceSubject, EvidenceVersion, RequiredCase};
        use whipplescript_kernel::norm_runner::{PythonCase, PythonRuntime};
        let files = BTreeMap::from([(format!("{module}.py"), source.to_owned())]);
        let method = PythonCallMethod {
            runtime: PythonRuntime {
                engine,
                executable: "whip".into(),
                python_version: version,
                environment: "profile-fixture".into(),
            },
            module: module.into(),
            function: function.into(),
            cases: vec![PythonCase {
                id: "only".into(),
                args: Vec::new(),
                kwargs: BTreeMap::new(),
            }],
        };
        let contract = ReportContract {
            subject: EvidenceSubject {
                requirement: EvidenceVersion {
                    name: "observed".into(),
                    version: "1".into(),
                    digest: "fixture".into(),
                },
                method: method.reference(),
                artifact: candidate_identity(&files),
            },
            cases: vec![RequiredCase {
                id: "only".into(),
                assertion: "actual-return".into(),
                expected,
            }],
        };
        json!({"run_id":"observer-preflight", "method_definition_json":serde_json::to_value(method).unwrap().to_string(), "contract_json":serde_json::to_value(contract).unwrap().to_string(), "files":files}).to_string()
    }

    #[test]
    fn norm_observer_refuses_cooperative_profiles_before_events() {
        let request = input(
            PythonEngine::Cpython {},
            "3.14.7".into(),
            "candidate",
            "check",
            "def check(): return True",
            json!(true),
        );
        let mut emitted = false;
        assert_eq!(
            execute(&request, &mut |_| {
                emitted = true;
                Ok(())
            })
            .unwrap_err(),
            "norm WASI observer requires its explicit runtime profile"
        );
        assert!(!emitted);
    }
}
