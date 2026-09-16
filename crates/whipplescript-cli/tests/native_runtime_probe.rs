use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};
use whipplescript_kernel::exec_http::sha256_hex;

fn probe(body: &[u8], extra: bool) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_whip"));
    command.args(["executor", "verify-norm-runtime"]);
    if extra {
        command.arg("unexpected");
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start runtime probe");
    // Refusal may close input immediately.
    let _ = child
        .stdin
        .take()
        .expect("piped probe input")
        .write_all(body);
    child
        .wait_with_output()
        .expect("collect runtime probe output")
}
#[test]
fn native_runtime_probe_acknowledges_only_the_pinned_protected_profile() {
    if whipplescript::norm_reactor::prepared_reactor().is_none() {
        return;
    }
    let artifact = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/norm-cpython-observer.wasm")
        .canonicalize()
        .unwrap();
    let runtime = json!({
        "engine":{"kind":"cpython3147_wasi","artifact_path":artifact,
            "artifact_sha256":sha256_hex(&std::fs::read(&artifact).unwrap())},
        "executable":env!("CARGO_BIN_EXE_whip"),"python_version":"3.14.7","environment":"probe-fixture",
    });
    let output = probe(runtime.to_string().as_bytes(), false);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!({
            "protocol":whipplescript::native_executor::NORM_RUNTIME_PROBE_PROTOCOL,"runtime":runtime,
        })
    );
    let bad_abi = std::env::temp_dir().join(format!(
        "norm-bad-abi-{}-{}.wasm",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let empty_module = b"\0asm\x01\0\0\0";
    std::fs::write(&bad_abi, empty_module).unwrap();
    for mode in [
        "executable",
        "invalid-abi",
        "digest",
        "version",
        "cooperative",
        "extra-field",
        "environment",
        "extra-arg",
        "oversized",
    ] {
        let mut changed = runtime.clone();
        match mode {
            "executable" => changed["executable"] = json!(artifact),
            "invalid-abi" => {
                changed["engine"]["artifact_path"] = json!(bad_abi);
                changed["engine"]["artifact_sha256"] = json!(sha256_hex(empty_module));
            }
            "digest" => changed["engine"]["artifact_sha256"] = json!("0".repeat(64)),
            "version" => changed["python_version"] = json!("3.14.4"),
            "cooperative" => changed["engine"] = json!({"kind":"cpython"}),
            "extra-field" => changed["candidate"] = json!("not-profile"),
            "environment" => changed["environment"] = json!(""),
            _ => {}
        }
        let body = if mode == "oversized" {
            changed["environment"] = json!("x".repeat(16385));
            changed.to_string().into_bytes()
        } else {
            changed.to_string().into_bytes()
        };
        let output = probe(&body, mode == "extra-arg");
        assert!(!output.status.success(), "{mode}");
        assert!(output.stdout.is_empty(), "{mode} acknowledged a profile");
    }
    std::fs::remove_file(bad_abi).unwrap();
}
