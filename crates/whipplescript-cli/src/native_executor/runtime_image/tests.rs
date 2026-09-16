use super::*;

fn profile() -> PythonRuntime {
    PythonRuntime {
        engine: PythonEngine::Cpython3147Wasi {
            artifact_path: "/opt/norm/runtime.wasm".into(),
            artifact_sha256: "a".repeat(64),
        },
        executable: "/opt/norm/observer".into(),
        python_version: "3.14.7".into(),
        environment: "installed-epoch".into(),
    }
}
#[test]
fn native_runtime_recipe_preserves_profile_and_refuses_ambiguous_paths() {
    let base = format!("sha256:{}", "b".repeat(64));
    let runtime = profile();
    let original = runtime.clone();
    let (text, pin) = recipe(&base, &runtime).unwrap();
    assert_eq!(runtime, original);
    assert_eq!(pin, "a".repeat(64));
    assert!(text.contains(r#"RUN ["mv","-T","/tmp/whip-norm-reactor","/opt/norm/runtime.wasm"]"#));
    assert!(text.contains(r#"RUN ["ln","-sT","/usr/local/bin/whip","/opt/norm/observer"]"#));
    let mut direct = runtime.clone();
    direct.executable = SIDECAR.into();
    assert!(!recipe(&base, &direct).unwrap().0.contains("ln"));
    assert!(recipe("mutable:latest", &runtime).is_err());
    let mut oversized = runtime.clone();
    oversized.environment = "x".repeat(MAX_NORM_RUNTIME_PROFILE_BYTES as usize + 1);
    assert!(recipe(&base, &oversized).is_err());

    let mut cooperative = runtime.clone();
    cooperative.engine = PythonEngine::Cpython {};
    assert!(recipe(&base, &cooperative).is_err());
    for path in [
        "/",
        "relative",
        "/tmp/observer",
        "/proc/1/exe",
        "/sys/a",
        "/dev/a",
        "/authority/a",
        "/opt//a",
        "/opt/../a",
        "/opt/./a",
        "/opt/a/",
        "/opt/a\nb",
    ] {
        let mut changed = runtime.clone();
        changed.executable = path.into();
        assert!(recipe(&base, &changed).is_err(), "{path}");
    }
    for path in [
        "/usr/local/bin/whip",
        "/opt/norm/observer",
        "/opt/norm/observer/child",
        "/opt",
    ] {
        let mut changed = runtime.clone();
        let PythonEngine::Cpython3147Wasi { artifact_path, .. } = &mut changed.engine else {
            unreachable!()
        };
        *artifact_path = path.into();
        assert!(recipe(&base, &changed).is_err(), "{path}");
    }
}

#[cfg(unix)]
#[test]
fn native_runtime_installation_refuses_changed_artifacts_and_authority() {
    use std::{fs, os::unix::fs::PermissionsExt};
    let dir = std::env::temp_dir().join(format!(
        "runtime-image-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    let build = dir.join("build");
    fs::create_dir(&build).unwrap();
    let program = dir.join("docker");
    fs::write(&program, include_str!("docker.py")).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let source = dir.join("source.wasm");
    let bytes = b"pinned reactor fixture";
    fs::write(&source, bytes).unwrap();
    let mut runtime = profile();
    let PythonEngine::Cpython3147Wasi {
        artifact_sha256, ..
    } = &mut runtime.engine
    else {
        unreachable!()
    };
    *artifact_sha256 = sha256_hex(bytes);
    fs::write(dir.join("runtime"), serde_json::to_vec(&runtime).unwrap()).unwrap();
    let base = format!("sha256:{}", "b".repeat(64));
    for mode in [
        "exact",
        "cached",
        "alias-conflict",
        "alias-id",
        "artifact",
        "daemon-1",
        "entrypoint",
        "daemon-2",
        "image-id",
        "image-lookup",
        "probe",
        "daemon-3",
    ] {
        let _ = fs::remove_file(dir.join("calls"));
        let _ = fs::remove_file(dir.join("count"));
        fs::write(dir.join("mode"), mode).unwrap();
        fs::write(
            &source,
            if mode == "artifact" {
                b"changed reactor".as_slice()
            } else {
                bytes.as_slice()
            },
        )
        .unwrap();
        let mut docker = Docker::new("unix:///fixture").unwrap();
        docker.program = program.clone();
        let result = docker.install_norm_runtime("daemon", &base, &runtime, &source, &build);
        if matches!(mode, "exact" | "cached") {
            let installed = result.unwrap();
            assert_eq!(installed.runtime, runtime);
            assert_eq!(installed.daemon_id, "daemon");
            assert_eq!(installed.base_image, base);
            assert_eq!(installed.image_id, format!("sha256:{}", "c".repeat(64)));
        } else {
            assert!(result.is_err(), "{mode}");
        }
        if mode == "artifact" {
            assert!(!dir.join("calls").exists(), "unpinned bytes reached Docker");
        }
        assert_eq!(
            fs::read_dir(&build).unwrap().count(),
            0,
            "{mode} leaked its context"
        );
    }
    let oversized = vec![0u8; MAX_REACTOR as usize + 1];
    let PythonEngine::Cpython3147Wasi {
        artifact_sha256, ..
    } = &mut runtime.engine
    else {
        unreachable!()
    };
    *artifact_sha256 = sha256_hex(&oversized);
    fs::write(&source, oversized).unwrap();
    fs::write(dir.join("runtime"), serde_json::to_vec(&runtime).unwrap()).unwrap();
    fs::write(dir.join("mode"), "exact").unwrap();
    fs::remove_file(dir.join("calls")).unwrap();
    let mut docker = Docker::new("unix:///fixture").unwrap();
    docker.program = program;
    assert!(docker
        .install_norm_runtime("daemon", &base, &runtime, &source, &build)
        .is_err());
    assert!(
        !dir.join("calls").exists(),
        "oversized reactor reached Docker"
    );
    fs::remove_dir_all(dir).unwrap();
}

struct PhysicalRuntimeCleanup {
    endpoint: String,
    image: String,
    owner: Option<String>,
    volume: Option<String>,
    armed: bool,
}
impl Drop for PhysicalRuntimeCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Ok(docker) = Docker::new(&self.endpoint) {
            if let Some(owner) = &self.owner {
                let _ = docker.command(&["container", "rm", "--force", "--volumes", owner], None);
            }
            if let Some(volume) = &self.volume {
                let _ = docker.command(&["volume", "rm", volume], None);
            }
            let _ = docker.command(&["image", "rm", &self.image], None);
        }
    }
}

#[test]
#[ignore = "requires the production executor image and Docker"]
fn native_docker_physical_protected_runtime_image() {
    let base = std::env::var("WHIP_TEST_EXECUTOR_IMAGE").unwrap();
    let endpoint = std::env::var("WHIP_TEST_DOCKER_ENDPOINT").unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let source = root.join("target/norm-cpython-observer.wasm");
    let bytes = std::fs::read(&source).unwrap();
    let mut runtime = profile();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    runtime.executable = format!("/opt/whip norm $literal-{nonce}/observer");
    runtime.engine = PythonEngine::Cpython3147Wasi {
        artifact_path: format!("/opt/whip norm $literal-{nonce}/runtime.wasm"),
        artifact_sha256: sha256_hex(&bytes),
    };
    let mut docker = Docker::new(&endpoint).unwrap();
    let daemon = docker.daemon_id().unwrap();
    let installed = docker
        .install_norm_runtime(
            &daemon,
            &base,
            &runtime,
            &source,
            &root.join("target/norm-runtime-image-tests"),
        )
        .unwrap();
    let mut cleanup = PhysicalRuntimeCleanup {
        endpoint: endpoint.clone(),
        image: installed.image_id.clone(),
        owner: None,
        volume: None,
        armed: true,
    };
    assert_eq!(installed.runtime, runtime);
    assert_eq!(installed.daemon_id, daemon);
    assert_eq!(installed.base_image, base);
    assert_ne!(installed.image_id, base);
    let directory = root.join(format!("target/norm-worker-physical-{nonce}"));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("runtime.sqlite");
    let config = directory.join("host.json");
    let host = NativeNormHost {
        protocol: "whipplescript.exec.native-norm-host/v1".into(),
        endpoint: endpoint.clone(),
        installed: installed.clone(),
    };
    std::fs::write(&config, serde_json::to_vec(&host).unwrap()).unwrap();
    let worker = |path: &Path, instance: &str, configured: bool| {
        let mut command = std::process::Command::new(root.join("target/debug/whip"));
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("WHIPPLESCRIPT_STORE", path)
            .args(["--json", "worker", instance, "--once"]);
        if configured {
            command.env("WHIPPLESCRIPT_NATIVE_NORM_RUNTIME", &config);
        }
        command.output().unwrap()
    };
    let (kernel, instance, effect, _) =
        crate::native_executor::norm_admission::tests::fixture_with_runtime(
            "exact",
            SqliteStore::open(&path).unwrap(),
            Some(runtime.clone()),
        );
    let run = whipplescript_kernel::exec_invocation::Invocation {
        instance_id: instance.clone(),
        effect_id: effect.effect_id.clone(),
        attempt_admission_event_id: None,
    }
    .run_id();
    cleanup.volume = Some(format!("whip-controller-{run}"));
    let before = kernel.store().list_events(&instance).unwrap().len();
    let missing = worker(&path, &instance, false);
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("WHIPPLESCRIPT_NATIVE_NORM_RUNTIME"));
    assert_eq!(kernel.store().list_events(&instance).unwrap().len(), before);
    assert!(kernel.store().list_runs(&instance).unwrap().is_empty());
    let result = worker(&path, &instance, true);
    cleanup.owner = kernel
        .store()
        .native_executor_owner(&instance, &run)
        .unwrap()
        .map(|(_, owner)| owner.owner_id);
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ran_effects"], 1);
    assert_eq!(report["native_norm_pending"], 0);
    let rows = kernel.store().list_runs(&instance).unwrap();
    assert_eq!(rows[0].status, "completed");
    let metadata: Value = serde_json::from_str(&rows[0].metadata_json).unwrap();
    assert_eq!(metadata["executor_transport"], "native-managed");
    assert!(metadata["executor_response"]["body"]["stdout"]
        .as_str()
        .unwrap()
        .contains("\"actual\":false"));
    let count = kernel.store().list_events(&instance).unwrap().len();
    let mut changed = host;
    changed.installed.daemon_id = "replacement-daemon".into();
    changed.installed.image_id = format!("sha256:{}", "a".repeat(64));
    changed.installed.runtime.environment = "replacement-epoch".into();
    std::fs::write(&config, serde_json::to_vec(&changed).unwrap()).unwrap();
    let replay = worker(&path, &instance, true);
    assert!(
        replay.status.success(),
        "{}",
        String::from_utf8_lossy(&replay.stderr)
    );
    let replay: Value = serde_json::from_slice(&replay.stdout).unwrap();
    assert_eq!(replay["ran_effects"], 0);
    assert_eq!(replay["native_norm_pending"], 0);
    assert_eq!(kernel.store().list_events(&instance).unwrap().len(), count);
    docker
        .command(&["volume", "rm", &format!("whip-controller-{run}")], None)
        .unwrap();
    cleanup.owner = None;
    cleanup.volume = None;
    drop(kernel);

    // Simulate process loss between run start and tracking. Ordinary recovery
    // resumes the unexpired original admission, or proves non-admission after
    // expiry. Today's changed installation cannot replace either binding.
    for expired in [true, false] {
        let abandoned = directory.join(format!("abandoned-{expired}.sqlite"));
        let (mut kernel, instance, effect, _) =
            crate::native_executor::norm_admission::tests::fixture_with_runtime(
                "exact",
                SqliteStore::open(&abandoned).unwrap(),
                Some(runtime.clone()),
            );
        let connection = rusqlite::Connection::open(&abandoned).unwrap();
        connection.execute_batch("CREATE TRIGGER stop_tracking BEFORE INSERT ON events WHEN NEW.event_type='exec.lifetime.tracked' BEGIN SELECT RAISE(ABORT,'interrupted admission'); END;").unwrap();
        let admitted_at = if expired {
            "2000-01-01T00:00:00Z".into()
        } else {
            chrono::DateTime::<chrono::Utc>::from(std::time::SystemTime::now())
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        };
        assert!(NativeNormAdmission::admit_at(
            &mut kernel,
            &instance,
            &effect,
            &installed,
            &admitted_at
        )
        .is_err());
        connection
            .execute_batch("DROP TRIGGER stop_tracking")
            .unwrap();
        drop(connection);
        let run = kernel.store().list_runs(&instance).unwrap()[0]
            .run_id
            .clone();
        cleanup.volume = Some(format!("whip-controller-{run}"));
        drop(kernel);
        let recovered = worker(&abandoned, &instance, true);
        let store = SqliteStore::open(&abandoned).unwrap();
        cleanup.owner = store
            .native_executor_owner(&instance, &run)
            .unwrap()
            .map(|(_, owner)| owner.owner_id);
        assert!(
            recovered.status.success(),
            "{}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        let recovered: Value = serde_json::from_slice(&recovered.stdout).unwrap();
        assert_eq!(recovered["ran_effects"], 1);
        assert_eq!(recovered["native_norm_pending"], 0);
        assert_eq!(
            store.list_runs(&instance).unwrap()[0].status,
            if expired { "failed" } else { "completed" }
        );
        assert_eq!(
            store
                .native_executor_owner(&instance, &run)
                .unwrap()
                .is_none(),
            expired
        );
        assert!(
            whipplescript_kernel::exec_lifetime::tracked(&store, &instance)
                .unwrap()
                .contains_key(&run)
        );
        assert!(
            whipplescript_kernel::exec_lifetime::fences(&store, &instance)
                .unwrap()
                .contains_key(&run)
        );
        docker
            .command(&["volume", "rm", &format!("whip-controller-{run}")], None)
            .unwrap();
        cleanup.volume = None;
        cleanup.owner = None;
    }
    #[cfg(unix)]
    super::worker_races::check(&root, &endpoint, &installed, &directory);
    let image = installed.image_id;
    let result = std::process::Command::new("docker")
        .args(["--host", &endpoint, "image", "rm", &image])
        .output()
        .unwrap();
    assert!(result.status.success(), "test runtime image cleanup failed");
    cleanup.armed = false;
    println!("native runtime image: exact declared executable and pinned reactor verified in isolated derived image");
}

#[cfg(unix)]
#[test]
fn runtime_image_verification_binds_image_profile_and_probe() {
    use std::{fs, os::unix::fs::PermissionsExt};
    use whipplescript_kernel::norm_runtime_image::InstalledRuntimeImage;
    let dir = std::env::temp_dir().join(format!(
        "verify-image-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    let program = dir.join("docker");
    fs::write(&program, include_str!("verify_image_fixture.py")).unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let runtime = profile();
    fs::write(dir.join("runtime"), serde_json::to_vec(&runtime).unwrap()).unwrap();
    let image = format!("sha256:{}", "c".repeat(64));
    let mut docker = Docker::new("unix:///fixture").unwrap();
    docker.program = program;
    for mode in [
        "exact",
        "first-image",
        "entrypoint",
        "failed-probe",
        "bad-probe",
        "profile",
        "extra",
        "daemon",
        "last-image",
    ] {
        fs::write(dir.join("mode"), mode).unwrap();
        fs::write(dir.join("calls"), "[]").unwrap();
        let result = docker.verify_norm_runtime_image(&image, &runtime);
        if mode == "exact" {
            let binding = result.unwrap();
            assert_eq!(binding.image_id(), image);
            binding.validate_for(&image, &runtime).unwrap();
            assert!(binding.validate_for("mutable:tag", &runtime).is_err());
            let mut changed = runtime.clone();
            changed.environment.push('x');
            assert!(binding.validate_for(&image, &changed).is_err());
            let wire = serde_json::to_value(&binding).unwrap();
            InstalledRuntimeImage::parse(&wire.to_string())
                .unwrap()
                .validate_for(&image, &runtime)
                .unwrap();
            for (field, value) in [
                ("protocol", json!("wrong")),
                ("image_id", json!("mutable:tag")),
                ("extra", json!(true)),
            ] {
                let mut invalid = wire.clone();
                invalid[field] = value;
                assert!(
                    InstalledRuntimeImage::parse(&invalid.to_string()).is_err(),
                    "{field}"
                );
            }
            assert!(InstalledRuntimeImage::parse(&" ".repeat(32769)).is_err());
            assert!(
                InstalledRuntimeImage::from_probe(&image, &runtime, &" ".repeat(32769)).is_err()
            );
        } else {
            assert!(result.is_err(), "{mode}");
            if matches!(mode, "first-image" | "entrypoint") {
                let calls: Vec<Vec<String>> =
                    serde_json::from_slice(&fs::read(dir.join("calls")).unwrap()).unwrap();
                assert!(
                    !calls
                        .iter()
                        .any(|call| call.first().is_some_and(|arg| arg == "run")),
                    "{mode} started a probe before image verification"
                );
            }
        }
    }
    for image in [
        "latest",
        "sha256:abc",
        &format!("sha256:{}", "A".repeat(64)),
        &format!("sha256:{}", "g".repeat(64)),
    ] {
        assert!(docker.verify_norm_runtime_image(image, &runtime).is_err());
    }
    fs::remove_dir_all(dir).unwrap();
}
