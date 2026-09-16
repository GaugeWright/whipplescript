use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};
use whipplescript_kernel::{
    exec_http::{base64_encode, sha256_hex},
    exec_invocation::{Envelope, Invocation},
};

struct Cleanup {
    dir: PathBuf,
    endpoint: String,
    owner: String,
    volume: String,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::write(self.dir.join("release"), "");
        for args in [
            vec!["rm", "--force", "--volumes", &self.owner],
            vec!["volume", "rm", &self.volume],
        ] {
            let _ = std::process::Command::new("docker")
                .args(["--host", &self.endpoint])
                .args(args)
                .output();
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
#[ignore = "requires the production executor image and Docker"]
fn native_docker_physical_managed_startup_races() {
    let image = std::env::var("WHIP_TEST_EXECUTOR_IMAGE").unwrap();
    let endpoint = std::env::var("WHIP_TEST_DOCKER_ENDPOINT").unwrap();
    for mode in ["fence", "completion", "inflight-removal"] {
        let nonce = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("native-start-race-{nonce}"));
        fs::create_dir(&dir).unwrap();
        let selected = Invocation {
            instance_id: nonce,
            effect_id: "exec".into(),
            attempt_admission_event_id: None,
        };
        let script = if mode == "inflight-removal" {
            "printf x > /tmp/executed; sleep 240 & wait"
        } else {
            "printf x >> /tmp/executed; printf retained"
        };
        let dispatch = json!({
            "protocol":"whip-executor/1", "effect_id":"exec",
            "script_sha256":sha256_hex(script.as_bytes()), "script_b64":base64_encode(script.as_bytes()),
            "script_ext":"sh", "argv":["sh","{script}"], "script_index":1,
            "stdin":null, "timeout_ms":if mode == "inflight-removal" { 250000 } else { 10000 },
        });
        let identity = Identity {
            envelope: Envelope::new(selected.clone(), dispatch).unwrap(),
            selected,
        };
        let mut engine = Docker::new(&endpoint).unwrap();
        let daemon = engine.daemon_id().unwrap();
        let owner = Owner {
            protocol: whipplescript_store::exec_native_owner::PROTOCOL.into(),
            instance_id: identity.selected.instance_id.clone(),
            effect_id: "exec".into(),
            run_id: identity.selected.run_id(),
            tracking_event_id: "physical-track".into(),
            daemon_id: daemon.clone(),
            image_id: image.clone(),
            owner_id: format!(
                "whip-exec-{}",
                sha256_hex(identity.selected.instance_id.as_bytes())
            ),
        };
        let cleanup = Cleanup {
            dir: dir.clone(),
            endpoint: endpoint.clone(),
            owner: owner.owner_id.clone(),
            volume: identity.controller_id(),
        };
        let prepared = engine
            .prepare_managed(&daemon, &image, &identity, &owner)
            .unwrap();
        let container = prepared.state.container_id.unwrap();
        if mode == "inflight-removal" {
            inflight_removal(&dir, &endpoint, &image, &daemon, &identity, &container);
            drop(cleanup);
            println!("native physical removal race: destruction waited for paused helper custody; cold termination retained");
            continue;
        }
        let proxy = dir.join("docker-proxy");
        fs::write(&proxy, include_str!("startup-proxy.py")).unwrap();
        fs::set_permissions(&proxy, fs::Permissions::from_mode(0o700)).unwrap();
        let mut paused = Docker::new(&endpoint).unwrap();
        paused.program = proxy;
        std::thread::scope(|scope| {
            let identity_ref = &identity;
            let daemon_ref = &daemon;
            let image_ref = &image;
            let worker =
                scope.spawn(move || paused.deliver_managed(daemon_ref, image_ref, identity_ref));
            let until = Instant::now() + Duration::from_secs(120);
            while !dir.join("started").exists() && !worker.is_finished() && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(20));
            }
            // Release on assertion unwinding too, so the scoped worker cannot hang.
            struct Release<'a>(&'a std::path::Path);
            impl Drop for Release<'_> {
                fn drop(&mut self) {
                    let _ = fs::write(self.0.join("release"), "");
                }
            }
            let release = Release(&dir);
            assert!(
                dir.join("started").exists(),
                "adapter never reached physical startup"
            );
            let winner = if mode == "fence" {
                engine
                    .controller(
                        &daemon,
                        &image,
                        &identity,
                        Command::Fence {
                            fence_id: "race-fence".into(),
                        },
                    )
                    .unwrap()
            } else {
                engine.deliver_managed(&daemon, &image, &identity).unwrap()
            };
            drop(release);
            let late = worker.join().unwrap().unwrap();
            assert_eq!(late.response, winner.response, "{mode}");
            assert!(
                !dir.join("delivered").exists(),
                "paused adapter dispatched after losing admission"
            );
            let marker = std::process::Command::new("docker")
                .args([
                    "--host",
                    &endpoint,
                    "exec",
                    &container,
                    "sh",
                    "-c",
                    "if test -e /tmp/executed; then cat /tmp/executed; fi",
                ])
                .output()
                .unwrap();
            assert!(marker.status.success());
            if mode == "fence" {
                assert_eq!(late.response["action"]["action"], "not_admitted");
                assert!(marker.stdout.is_empty(), "fenced invocation executed");
            } else {
                assert_eq!(late.response["action"]["action"], "replay");
                assert_eq!(late.response["action"]["body"]["stdout"], "retained");
                assert_eq!(
                    marker.stdout, b"x",
                    "competing adapters executed more than once"
                );
            }
            let closed = engine
                .fence_managed(&daemon, &image, &identity, "race-fence")
                .unwrap();
            assert!(engine.inspect(&container).unwrap().is_none());
            assert_eq!(
                engine
                    .deliver_managed(&daemon, &image, &identity)
                    .unwrap()
                    .response,
                closed.response
            );
        });
        drop(cleanup);
        println!("native physical startup race: {mode} preserved the winning authority without late delivery");
    }
}

fn docker_output(endpoint: &str, args: &[&str]) -> std::process::Output {
    std::process::Command::new("docker")
        .args(["--host", endpoint])
        .args(args)
        .output()
        .unwrap()
}

fn inflight_removal(
    dir: &std::path::Path,
    endpoint: &str,
    image: &str,
    daemon: &str,
    identity: &Identity,
    container: &str,
) {
    let mut observer = Docker::new(endpoint).unwrap();
    std::thread::scope(|scope| {
        let mut delivery = Docker::new(endpoint).unwrap();
        let executing = scope.spawn(move || delivery.deliver_managed(daemon, image, identity));
        struct RemoveOnPanic<'a> {
            endpoint: &'a str,
            container: &'a str,
        }
        impl Drop for RemoveOnPanic<'_> {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    let _ = docker_output(self.endpoint, &["rm", "--force", self.container]);
                }
            }
        }
        let _remove = RemoveOnPanic {
            endpoint,
            container,
        };
        let until = Instant::now() + Duration::from_secs(120);
        loop {
            let held = observer
                .controller(daemon, image, identity, Command::Read)
                .unwrap();
            let marker = docker_output(
                endpoint,
                &["exec", container, "test", "-e", "/tmp/executed"],
            );
            if held.response["action"]["action"] == "pending" && marker.status.success() {
                break;
            }
            assert!(
                !executing.is_finished(),
                "delivery ended before the removal race"
            );
            assert!(
                Instant::now() < until,
                "executor never admitted and started the fixture"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // The only container sharing this exact network namespace and mounting
        // this invocation's authority is its isolated delivery helper.
        let candidates = docker_output(
            endpoint,
            &[
                "ps",
                "--no-trunc",
                "--filter",
                &format!("volume={}", identity.controller_id()),
                "--format",
                "{{.ID}}",
            ],
        );
        assert!(candidates.status.success());
        let helpers = String::from_utf8(candidates.stdout)
            .unwrap()
            .lines()
            .filter(|id| {
                let network = docker_output(
                    endpoint,
                    &["inspect", "--format", "{{.HostConfig.NetworkMode}}", id],
                );
                network.status.success()
                    && String::from_utf8_lossy(&network.stdout).trim()
                        == format!("container:{container}")
            })
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(helpers.len(), 1, "expected one admitted delivery custodian");
        let helper = &helpers[0];
        assert!(docker_output(endpoint, &["pause", helper]).status.success());
        struct Resume<'a> {
            endpoint: &'a str,
            helper: &'a str,
        }
        impl Drop for Resume<'_> {
            fn drop(&mut self) {
                let _ = docker_output(self.endpoint, &["unpause", self.helper]);
            }
        }
        let resume = Resume { endpoint, helper };
        let proxy = dir.join("finish-proxy");
        fs::write(&proxy, include_str!("finish-proxy.py")).unwrap();
        fs::set_permissions(&proxy, fs::Permissions::from_mode(0o700)).unwrap();
        let finish_name = format!("whip-finish-{}", identity.selected.run_id());
        fs::write(dir.join("finish-name"), &finish_name).unwrap();
        let mut fence = Docker::new(endpoint).unwrap();
        fence.program = proxy;
        let finishing =
            scope.spawn(move || fence.fence_managed(daemon, image, identity, "inflight-fence"));
        let until = Instant::now() + Duration::from_secs(120);
        loop {
            let running = docker_output(
                endpoint,
                &["inspect", "--format", "{{.State.Running}}", &finish_name],
            );
            if dir.join("finish-started").exists()
                && running.status.success()
                && String::from_utf8_lossy(&running.stdout).trim() == "true"
            {
                break;
            }
            assert!(
                !finishing.is_finished(),
                "barrier finished before completion custody drained"
            );
            assert!(
                Instant::now() < until,
                "fencer never reached the completion custodian"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            observer.inspect(container).unwrap().is_none(),
            "finish started before immutable removal"
        );
        let held = observer
            .controller(daemon, image, identity, Command::Read)
            .unwrap();
        assert_eq!(held.state.barrier.as_ref().unwrap()["closing"], true);
        assert_ne!(held.response["action"]["action"], "terminated");
        assert!(
            !finishing.is_finished(),
            "paused helper lost its completion lock"
        );
        assert!(
            !executing.is_finished(),
            "paused delivery unexpectedly returned"
        );
        drop(resume);
        let closed = finishing.join().unwrap().unwrap();
        assert!(
            executing.join().unwrap().is_err(),
            "destroyed in-flight response became a completion"
        );
        assert_eq!(closed.response["action"]["action"], "terminated");
        assert_eq!(closed.state.barrier.as_ref().unwrap()["closing"], false);
        assert!(observer.inspect(container).unwrap().is_none());
        assert_eq!(
            observer
                .deliver_managed(daemon, image, identity)
                .unwrap()
                .response,
            closed.response
        );
        assert_eq!(
            observer
                .fence_managed(daemon, image, identity, "inflight-fence")
                .unwrap()
                .response,
            closed.response
        );
    });
}
