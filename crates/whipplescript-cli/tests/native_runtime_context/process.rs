use super::*;
use std::time::{Duration, Instant};

pub(super) fn verify(endpoint: &str, tag: &str, runtime: &PythonRuntime, root: &std::path::Path) {
    struct Container<'a> {
        endpoint: &'a str,
        name: String,
    }
    impl Drop for Container<'_> {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args([
                    "--host",
                    self.endpoint,
                    "container",
                    "rm",
                    "--force",
                    &self.name,
                ])
                .output();
        }
    }
    let invalid = root.join("startup-invalid.wasm");
    fs::write(&invalid, b"\0asm\x01\0\0\0").expect("invalid startup reactor");
    for fault in ["exact", "pin", "executable", "abi", "unconfigured"] {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let container = Container {
            endpoint,
            name: format!("whip-norm-startup-{nonce}-{fault}"),
        };
        let mut selected = runtime.clone();
        if fault == "executable" {
            selected.executable = "/bin/sh".into();
        }
        let PythonEngine::Cpython3147Wasi {
            artifact_path,
            artifact_sha256,
        } = &mut selected.engine
        else {
            panic!("protected fixture");
        };
        if fault == "pin" {
            *artifact_sha256 = "b".repeat(64);
        }
        if fault == "abi" {
            *artifact_sha256 = sha256_hex(&fs::read(&invalid).expect("invalid bytes"));
        }
        let mount = format!(
            "type=bind,src={},dst={artifact_path},readonly",
            invalid.display()
        );
        let profile = serde_json::to_string(&selected).expect("startup profile");
        let mut command = Command::new("docker");
        command.args([
            "--host",
            endpoint,
            "run",
            "--detach",
            "--name",
            &container.name,
            "--publish",
            "127.0.0.1::8080",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--env",
            "WHIP_EXECUTOR_TOKEN=norm-process-fixture",
        ]);
        if fault != "unconfigured" {
            command.args(["--env", &format!("WHIP_NORM_RUNTIME={profile}")]);
        }
        if fault == "abi" {
            command.args(["--mount", &mount]);
        }
        let started = command
            .arg(tag)
            .output()
            .expect("start configured executor");
        assert!(
            started.status.success(),
            "{}",
            String::from_utf8_lossy(&started.stderr)
        );
        let port = Command::new("docker")
            .args(["--host", endpoint, "port", &container.name, "8080/tcp"])
            .output()
            .expect("published executor port");
        if !port.status.success() {
            let state = Command::new("docker")
                .args([
                    "--host",
                    endpoint,
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    &container.name,
                ])
                .output()
                .expect("early startup refusal state");
            assert!(state.status.success());
            assert_eq!(
                state.stdout, b"false\n",
                "port lookup failed for a running executor"
            );
        }
        let url = format!(
            "http://{}",
            String::from_utf8(port.stdout).expect("port text").trim()
        );
        let deadline = Instant::now() + Duration::from_secs(60);
        let healthy = loop {
            if !port.status.success() {
                break false;
            }
            if ureq::get(&format!("{url}/healthz"))
                .timeout(Duration::from_millis(300))
                .call()
                .is_ok()
            {
                break true;
            }
            let state = Command::new("docker")
                .args([
                    "--host",
                    endpoint,
                    "inspect",
                    "--format",
                    "{{.State.Running}}",
                    &container.name,
                ])
                .output()
                .expect("startup state");
            if state.stdout == b"false\n" {
                break false;
            }
            assert!(
                Instant::now() < deadline,
                "{fault}: executor startup timed out"
            );
            std::thread::sleep(Duration::from_millis(30));
        };
        let logs = Command::new("docker")
            .args(["--host", endpoint, "logs", &container.name])
            .output()
            .expect("startup diagnostic");
        assert_eq!(
            healthy,
            matches!(fault, "exact" | "unconfigured"),
            "{fault}: {}",
            String::from_utf8_lossy(&logs.stderr)
        );
        if !healthy {
            println!("hosted process startup refused {fault}");
            continue;
        }
        let get = |path: &str| {
            ureq::get(&format!("{url}{path}"))
                .timeout(Duration::from_secs(5))
                .set("Authorization", "Bearer norm-process-fixture")
                .call()
                .map_err(Box::new)
        };
        if fault == "unconfigured" {
            let refusal =
                get("/exec/norm-runtime").expect_err("unconfigured runtime refuses a receipt");
            assert!(matches!(*refusal, ureq::Error::Status(409, _)));
            continue;
        }
        assert!(matches!(
            ureq::get(&format!("{url}/exec/norm-runtime")).call(),
            Err(ureq::Error::Status(401, _))
        ));
        let handshake = get("/exec/incarnation")
            .expect("incarnation")
            .into_string()
            .expect("incarnation body");
        let incarnation = whipplescript_kernel::exec_incarnation::read_handshake(&handshake)
            .expect("incarnation identity");
        let receipt = get("/exec/norm-runtime")
            .expect("runtime proof")
            .into_string()
            .expect("runtime proof body");
        whipplescript_kernel::norm_runtime::verify_process_receipt(
            &receipt,
            &incarnation,
            &profile,
        )
        .expect("actual process profile");
        assert!(whipplescript_kernel::norm_runtime::verify_process_receipt(
            &receipt,
            "replacement",
            &profile
        )
        .is_err());
        println!(
            "hosted process runtime: authenticated exact profile bound to running incarnation"
        );
    }
}
