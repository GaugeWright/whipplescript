use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command};
use whipplescript_kernel::{
    exec_http::sha256_hex,
    norm_runner::{PythonEngine, PythonRuntime},
};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn native_runtime_context_prepares_exact_profile_and_refuses_bad_inputs() {
    let root = std::env::temp_dir().join(format!("norm-context-{}", std::process::id()));
    fs::create_dir(&root).expect("isolated context fixture");
    let fixture = Fixture(root);
    let source = fixture.0.join("reactor.wasm");
    let bytes = b"pinned artifact; ABI verification belongs to the image build";
    fs::write(&source, bytes).expect("reactor fixture");
    let runtime = PythonRuntime {
        engine: PythonEngine::Cpython3147Wasi {
            artifact_path: "/opt/norm $literal 'path/runtime.wasm".into(),
            artifact_sha256: sha256_hex(bytes),
        },
        executable: "/opt/norm $literal 'path/observer".into(),
        python_version: "3.14.7".into(),
        environment: "original-epoch".into(),
    };
    let request = json!({"runtime":runtime, "artifact_source":source, "build_root":fixture.0.join("contexts")});
    let request_path = fixture.0.join("request.json");
    let invoke = |text: &[u8]| {
        fs::write(&request_path, text).expect("write context request");
        Command::new(env!("CARGO_BIN_EXE_whip"))
            .current_dir(&fixture.0)
            .args(["executor", "prepare-norm-runtime-context", "--request"])
            .arg(&request_path)
            .output()
            .expect("prepare context CLI")
    };
    let mut bounded = serde_json::to_vec(&request).expect("request JSON");
    bounded.resize(65_536, b' ');
    let output = invoke(&bounded);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let prepared: Value = serde_json::from_slice(&output.stdout).expect("prepared receipt");
    assert_eq!(
        prepared["protocol"],
        "whipplescript.exec.norm-runtime-context/v1"
    );
    assert_eq!(prepared["runtime"], request["runtime"]);
    let directory = PathBuf::from(prepared["directory"].as_str().expect("context directory"));
    assert!(directory.is_absolute() && directory.starts_with(fixture.0.join("contexts")));
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(directory.join("context.json")).expect("stored receipt")
        )
        .expect("receipt JSON"),
        prepared
    );
    assert_eq!(
        prepared["files"].as_object().expect("file digests").len(),
        5
    );
    for name in [
        "Dockerfile",
        ".dockerignore",
        "whip",
        "runtime.json",
        "reactor.wasm",
    ] {
        assert_eq!(
            prepared["files"][name],
            sha256_hex(&fs::read(directory.join(name)).expect("prepared file"))
        );
    }
    assert_eq!(
        prepared["files"]["whip"],
        sha256_hex(&fs::read(env!("CARGO_BIN_EXE_whip")).expect("running CLI bytes"))
    );
    assert_eq!(
        fs::read(directory.join("reactor.wasm")).expect("prepared reactor"),
        bytes
    );
    assert_eq!(
        serde_json::from_slice::<Value>(
            &fs::read(directory.join("runtime.json")).expect("prepared profile")
        )
        .expect("profile JSON"),
        request["runtime"]
    );
    let recipe = fs::read_to_string(directory.join("Dockerfile")).expect("prepared recipe");
    let production = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../whipplescript-host-do/worker/executor/Dockerfile"),
    )
    .expect("owning production recipe");
    assert!(recipe.starts_with(&production));
    assert!(recipe.contains("RUN --network=none "));
    assert!(recipe.contains("executor verify-norm-runtime"));
    assert!(recipe.contains("/opt/norm $literal 'path/observer"));
    assert!(recipe.contains("/opt/norm $literal 'path/runtime.wasm"));
    assert!(!fs::read_to_string(directory.join(".dockerignore"))
        .expect("context allowlist")
        .contains("!context.json"));
    for case in [
        "oversized-request",
        "unknown-field",
        "relative-root",
        "wrong-pin",
        "overlapping-path",
    ] {
        let mut altered = request.clone();
        match case {
            "unknown-field" => altered["future"] = json!(true),
            "relative-root" => altered["build_root"] = json!("relative"),
            "wrong-pin" => altered["runtime"]["engine"]["artifact_sha256"] = json!("a".repeat(64)),
            "overlapping-path" => {
                altered["runtime"]["executable"] =
                    altered["runtime"]["engine"]["artifact_path"].clone()
            }
            _ => {}
        }
        let mut body = serde_json::to_vec(&altered).expect("altered JSON");
        if case == "oversized-request" {
            body.resize(65_537, b' ');
        }
        let before = fs::read_dir(fixture.0.join("contexts"))
            .expect("contexts")
            .count();
        let result = invoke(&body);
        assert!(!result.status.success(), "{case} accepted");
        assert_eq!(
            fs::read_dir(fixture.0.join("contexts"))
                .expect("unchanged contexts")
                .count(),
            before
        );
    }
    assert_eq!(fs::read(source).expect("original source"), bytes);
}

#[cfg(unix)]
#[test]
#[ignore = "requires Docker and the pinned CPython reactor"]
fn native_runtime_context_builds_and_probes_the_exact_image() {
    use std::io::Write;
    use std::process::Stdio;
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let fixture = Fixture(repo.join(format!("target/norm-hosted-context-{nonce}")));
    fs::create_dir(&fixture.0).expect("physical context fixture");
    let endpoint = std::env::var("WHIP_TEST_DOCKER_ENDPOINT")
        .unwrap_or_else(|_| "unix:///var/run/docker.sock".into());
    let executable = fixture.0.join("whip");
    assert!(Command::new("strip")
        .arg("-o")
        .arg(&executable)
        .arg(env!("CARGO_BIN_EXE_whip"))
        .status()
        .expect("strip test binary")
        .success());
    struct Images {
        endpoint: String,
        tags: Vec<String>,
    }
    impl Drop for Images {
        fn drop(&mut self) {
            for tag in &self.tags {
                let _ = Command::new("docker")
                    .args(["--host", &self.endpoint, "image", "rm", tag])
                    .output();
            }
        }
    }
    let mut images = Images {
        endpoint: endpoint.clone(),
        tags: vec![],
    };
    for valid in [true, false] {
        let source = if valid {
            repo.join("target/norm-cpython-observer.wasm")
        } else {
            let source = fixture.0.join("invalid.wasm");
            fs::write(&source, "pinned bytes with no reactor ABI").expect("invalid reactor");
            source
        };
        let runtime = PythonRuntime {
            engine: PythonEngine::Cpython3147Wasi {
                artifact_path: "/opt/hosted norm $literal 'path/runtime.wasm".into(),
                artifact_sha256: sha256_hex(&fs::read(&source).expect("reactor bytes")),
            },
            executable: "/opt/hosted norm $literal 'path/observer".into(),
            python_version: "3.14.7".into(),
            environment: "hosted-context-epoch".into(),
        };
        let request = json!({"runtime":runtime, "artifact_source":source, "build_root":fixture.0.join("contexts")});
        let request_path = fixture.0.join("request.json");
        fs::write(&request_path, request.to_string()).expect("physical request");
        let prepared = Command::new(&executable)
            .args(["executor", "prepare-norm-runtime-context", "--request"])
            .arg(&request_path)
            .output()
            .expect("prepare physical context");
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        let prepared: Value = serde_json::from_slice(&prepared.stdout).expect("physical receipt");
        assert_eq!(prepared["runtime"], request["runtime"]);
        let tag = format!("whip-hosted-context-{nonce}-{valid}:test");
        images.tags.push(tag.clone());
        let build = Command::new("docker")
            .args([
                "--host",
                &endpoint,
                "build",
                "--network",
                "none",
                "--tag",
                &tag,
            ])
            .arg(prepared["directory"].as_str().expect("build directory"))
            .output()
            .expect("build prepared context");
        if !valid {
            assert!(
                !build.status.success(),
                "invalid reactor passed the build probe"
            );
            assert!(
                String::from_utf8_lossy(&build.stderr).contains("norm runtime verification failed"),
                "{}",
                String::from_utf8_lossy(&build.stderr)
            );
            println!("hosted context build: pinned invalid ABI refused by the build probe");
            continue;
        }
        assert!(
            build.status.success(),
            "{}",
            String::from_utf8_lossy(&build.stderr)
        );
        let entry = Command::new("docker")
            .args([
                "--host",
                &endpoint,
                "image",
                "inspect",
                "--format",
                "{{json .Config.Entrypoint}}",
                &tag,
            ])
            .output()
            .expect("inspect built entrypoint");
        assert!(entry.status.success());
        assert_eq!(
            serde_json::from_slice::<Value>(&entry.stdout).expect("entrypoint JSON"),
            json!(["whip", "executor", "--bind", "0.0.0.0:8080"])
        );
        let mut probe = Command::new("docker")
            .args([
                "--host",
                &endpoint,
                "run",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                "--entrypoint",
                &runtime.executable,
                "-i",
                &tag,
                "executor",
                "verify-norm-runtime",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("probe built runtime");
        probe
            .stdin
            .take()
            .expect("probe stdin")
            .write_all(request["runtime"].to_string().as_bytes())
            .expect("send exact profile");
        let result = probe.wait_with_output().expect("reap runtime probe");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let result: Value = serde_json::from_slice(&result.stdout).expect("probe receipt");
        assert_eq!(result["protocol"], "whipplescript.norm.runtime-probe/v1");
        assert_eq!(result["runtime"], request["runtime"]);
        println!("hosted context build: production entrypoint, literal profile paths and isolated ABI probe passed");
        let inspected = Command::new("docker")
            .args([
                "--host", &endpoint, "image", "inspect", "--format", "{{.Id}}", &tag,
            ])
            .output()
            .expect("immutable image identity");
        assert!(inspected.status.success());
        let image_id = String::from_utf8(inspected.stdout)
            .expect("image ID text")
            .trim()
            .to_owned();
        let verification = json!({"endpoint":endpoint,"image_id":image_id,"runtime":runtime});
        let verify_path = fixture.0.join("verify-image.json");
        fs::write(&verify_path, verification.to_string()).expect("verification request");
        let invoke = || {
            Command::new(&executable)
                .args(["executor", "verify-norm-runtime-image", "--request"])
                .arg(&verify_path)
                .output()
                .expect("verify immutable image CLI")
        };
        let output = invoke();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let binding = whipplescript_kernel::norm_runtime_image::InstalledRuntimeImage::parse(
            &String::from_utf8(output.stdout).expect("binding JSON"),
        )
        .expect("validated image binding");
        binding
            .validate_for(&image_id, &runtime)
            .expect("deployment and method binding");
        for fault in ["mutable", "artifact", "executable", "extra"] {
            let mut changed = verification.clone();
            match fault {
                "mutable" => changed["image_id"] = json!(tag),
                "artifact" => {
                    changed["runtime"]["engine"]["artifact_sha256"] = json!("0".repeat(64))
                }
                "executable" => changed["runtime"]["executable"] = json!("/opt/missing-observer"),
                _ => changed["caller_receipt"] = json!({"verified":true}),
            }
            fs::write(&verify_path, changed.to_string()).expect("faulted verification request");
            let refused = invoke();
            assert!(
                !refused.status.success(),
                "{fault} emitted installation evidence"
            );
        }
        println!("immutable image verifier: exact image/profile binding and mutable, missing executable, changed reactor and caller-receipt refusals passed");
        process::verify(&endpoint, &tag, &runtime, &fixture.0);
    }
}

#[cfg(unix)]
#[path = "native_runtime_context/process.rs"]
mod process;
