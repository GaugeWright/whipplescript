//! Physical CLI interruption tests; only the first worker's Docker client is
//! paused. Recovery uses the real client and the original external authority.
use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::Instant,
};

struct Cleanup {
    directory: PathBuf,
    endpoint: String,
    owner: Option<String>,
    instance: String,
    run: String,
    volume: String,
    worker: Child,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::write(self.directory.join("release"), "");
        let _ = self.worker.kill();
        let _ = self.worker.wait();
        if self.owner.is_none() {
            self.owner = SqliteStore::open(self.directory.join("runtime.sqlite"))
                .ok()
                .and_then(|store| store.native_executor_owner(&self.instance, &self.run).ok())
                .flatten()
                .map(|(_, owner)| owner.owner_id);
        }
        // The orphaned client can finish a late create after its worker dies.
        // Let this fixture's client finish before removing its exact owner.
        let deadline = Instant::now() + Duration::from_secs(30);
        while fs::read_dir(&self.directory).is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                name.starts_with("client-") && name.ends_with(".active")
            })
        }) && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Ok(docker) = Docker::new(&self.endpoint) {
            if let Some(owner) = &self.owner {
                let _ = docker.command(&["container", "rm", "--force", "--volumes", owner], None);
            }
            let _ = docker.command(&["volume", "rm", &self.volume], None);
        }
    }
}
fn wait_for(guard: &mut Cleanup, name: &str, require_live_worker: bool) {
    // Startup includes several bounded Docker operations and reactor loading.
    // The intentional pause has its own shorter deadline in worker_pause.py.
    let deadline = Instant::now() + Duration::from_secs(if require_live_worker { 120 } else { 35 });
    while !guard.directory.join(name).exists() {
        if require_live_worker {
            assert!(
                guard
                    .worker
                    .try_wait()
                    .expect("poll original worker status")
                    .is_none(),
                "worker exited: {}",
                fs::read_to_string(guard.directory.join("worker.err"))
                    .expect("read original worker diagnostics")
            );
        }
        assert!(
            Instant::now() < deadline,
            "worker race did not reach {name}; Docker calls: {}; diagnostics: {}",
            fs::read_to_string(guard.directory.join("calls")).unwrap_or_default(),
            fs::read_to_string(guard.directory.join("worker.err")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(super) fn check(root: &Path, endpoint: &str, installed: &NativeRuntimeImage, parent: &Path) {
    let path_env = std::env::var_os("PATH").expect("physical suite PATH");
    let real_docker = std::env::split_paths(&path_env)
        .map(|path| path.join("docker"))
        .find(|path| path.is_file())
        .expect("find Docker CLI on PATH")
        .canonicalize()
        .expect("resolve Docker CLI path");
    for mode in ["create", "completion"] {
        let directory = parent.join(mode);
        fs::create_dir(&directory).expect("create worker race directory");
        let store_path = directory.join("runtime.sqlite");
        let (kernel, instance, effect, _) =
            crate::native_executor::norm_admission::tests::fixture_with_runtime(
                "exact",
                SqliteStore::open(&store_path).expect("open worker race runtime"),
                Some(installed.runtime.clone()),
            );
        let run = whipplescript_kernel::exec_invocation::Invocation {
            instance_id: instance.clone(),
            effect_id: effect.effect_id,
            attempt_admission_event_id: None,
        }
        .run_id();
        let config = directory.join("host.json");
        fs::write(
            &config,
            serde_json::to_vec(&NativeNormHost {
                protocol: "whipplescript.exec.native-norm-host/v1".into(),
                endpoint: endpoint.into(),
                installed: installed.clone(),
            })
            .expect("serialize worker host configuration"),
        )
        .expect("write worker host configuration");
        let wrapper = directory.join("docker");
        fs::write(&wrapper, include_str!("worker_pause.py")).expect("write paused Docker client");
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o700))
            .expect("make paused Docker client executable");
        fs::write(
            directory.join("fixture.json"),
            json!({"docker":real_docker,"mode":mode}).to_string(),
        )
        .expect("write Docker race fixture");
        let mut worker_path = vec![directory.clone()];
        worker_path.extend(std::env::split_paths(&path_env));
        let command = |verb: &str| {
            let mut command = Command::new(root.join("target/debug/whip"));
            command
                .env_clear()
                .env("PATH", &path_env)
                .env("WHIPPLESCRIPT_STORE", &store_path)
                .env("WHIPPLESCRIPT_NATIVE_NORM_RUNTIME", &config)
                .args(["--json", verb, &instance]);
            if verb == "worker" {
                command.arg("--once");
            }
            command
        };
        let worker = command("worker")
            .env(
                "PATH",
                std::env::join_paths(worker_path).expect("construct isolated worker PATH"),
            )
            .stdout(Stdio::from(
                fs::File::create(directory.join("worker.out")).expect("create worker stdout log"),
            ))
            .stderr(Stdio::from(
                fs::File::create(directory.join("worker.err")).expect("create worker stderr log"),
            ))
            .spawn()
            .expect("spawn original worker");
        let mut guard = Cleanup {
            directory: directory.clone(),
            endpoint: endpoint.into(),
            owner: None,
            instance: instance.clone(),
            run: run.clone(),
            volume: format!("whip-controller-{run}"),
            worker,
        };
        wait_for(&mut guard, "ready", true);
        guard.owner = kernel
            .store()
            .native_executor_owner(&instance, &run)
            .expect("read original executor owner")
            .map(|(_, owner)| owner.owner_id);
        assert!(guard.owner.is_some());
        guard.worker.kill().expect("stop original worker");
        guard.worker.wait().expect("reap original worker");
        let output = command(if mode == "create" {
            "recover"
        } else {
            "worker"
        })
        .output()
        .expect("run recovery command");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("decode recovery report");
        assert_eq!(
            report[if mode == "create" {
                "recovered_count"
            } else {
                "ran_effects"
            }],
            1
        );
        assert_eq!(report["native_norm_pending"], usize::from(mode == "create"));
        assert_eq!(
            kernel
                .store()
                .list_runs(&instance)
                .expect("read recovered run")[0]
                .status,
            if mode == "create" {
                "failed"
            } else {
                "completed"
            }
        );
        let count = kernel
            .store()
            .list_events(&instance)
            .expect("read recovered journal")
            .len();
        fs::write(directory.join("release"), "").expect("release original Docker client");
        wait_for(&mut guard, "done", false);
        if mode == "create" {
            let id = fs::read_to_string(directory.join("created"))
                .expect("read late container identity");
            assert_eq!(id.trim().len(), 64, "late create did not reach Docker");
        }
        let output = command("worker").output().expect("run cold cleanup worker");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: Value = serde_json::from_slice(&output.stdout).expect("decode cleanup report");
        assert_eq!(report["ran_effects"], 0);
        assert_eq!(report["native_norm_pending"], 0);
        assert_eq!(
            kernel
                .store()
                .list_events(&instance)
                .expect("read journal after cleanup")
                .len(),
            count
        );
        assert!(Docker::new(endpoint)
            .expect("open original Docker endpoint")
            .inspect(
                guard
                    .owner
                    .as_ref()
                    .expect("original executor owner was retained")
            )
            .expect("inspect original owner after cleanup")
            .is_none());
        println!("native worker physical {mode}: interrupted CLI, original custody, terminal recovery and cold cleanup passed");
    }
}
