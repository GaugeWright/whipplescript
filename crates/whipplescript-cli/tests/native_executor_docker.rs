//! Store-backed Docker lifecycle adapter, with deterministic lost-response races.
use std::{cell::RefCell, rc::Rc};
use whipplescript::native_executor::*;
use whipplescript_store::*;

#[path = "support/native_executor.rs"]
mod fixture;
use fixture::{setup, setup_with_dispatch};

#[derive(Default)]
struct State {
    daemon: String,
    held: Option<Inspection>,
    creates: usize,
    removes: usize,
    lose_create: bool,
    retain_on_remove: bool,
    changed_image: bool,
    changed_create_id: bool,
}
#[derive(Clone)]
struct Fake(Rc<RefCell<State>>);
impl Engine for Fake {
    fn daemon_id(&mut self) -> StoreResult<String> {
        Ok(self.0.borrow().daemon.clone())
    }
    fn create_inert(&mut self, owner: &exec_native_owner::Owner) -> StoreResult<String> {
        let mut s = self.0.borrow_mut();
        s.creates += 1;
        let id = "b".repeat(64);
        s.held = Some(Inspection {
            id: id.clone(),
            image: if s.changed_image {
                format!("sha256:{}", "c".repeat(64))
            } else {
                owner.image_id.clone()
            },
            name: format!("/{}", owner.owner_id),
            owner: owner.owner_id.clone(),
            tracking: owner.tracking_event_id.clone(),
        });
        if s.lose_create {
            return Err(StoreError::Conflict("lost create response".into()));
        }
        Ok(if s.changed_create_id {
            "c".repeat(64)
        } else {
            id
        })
    }
    fn inspect(&mut self, _: &str) -> StoreResult<Option<Inspection>> {
        Ok(self.0.borrow().held.clone())
    }
    fn remove(&mut self, _: &str) -> StoreResult<()> {
        let mut s = self.0.borrow_mut();
        s.removes += 1;
        if !s.retain_on_remove {
            s.held = None;
        }
        Ok(())
    }
}
#[test]
fn native_docker_retains_ownership_across_failures() {
    let image = format!("sha256:{}", "a".repeat(64));
    for case in [
        "exact",
        "lost-create",
        "lost-before-create",
        "bind-IGNORE",
        "image",
        "create-id",
        "owner-label",
        "tracking-label",
        "name",
        "daemon",
        "bound-id",
        "remove-pending",
        "removed",
        "fence-IGNORE",
    ] {
        let (mut store, instance, run, path) = setup();
        let state = Rc::new(RefCell::new(State {
            daemon: "daemon".into(),
            lose_create: case == "lost-create",
            changed_image: case == "image",
            changed_create_id: case == "create-id",
            ..State::default()
        }));
        let mut adapter = NativeExecutor::new(Fake(state.clone()));
        let sql = rusqlite::Connection::open(&path).unwrap();
        if case == "lost-before-create" {
            store
                .allocate_native_executor(exec_native_owner::Allocation {
                    instance_id: &instance,
                    run_id: &run,
                    daemon_id: "daemon",
                    image_id: &image,
                })
                .unwrap();
            assert!(matches!(
                adapter
                    .prepare(&mut store, &instance, &run, &image)
                    .unwrap(),
                Prepared::AwaitingCreation
            ));
            assert_eq!(state.borrow().creates, 0);
            continue;
        }
        if case == "bind-IGNORE" {
            sql.execute_batch("CREATE TRIGGER fail_binding BEFORE INSERT ON events WHEN NEW.event_type='exec.native.container.bound' BEGIN SELECT RAISE(IGNORE); END").unwrap();
        }
        let prepared = adapter.prepare(&mut store, &instance, &run, &image);
        if matches!(case, "lost-create" | "bind-IGNORE" | "image" | "create-id") {
            assert!(prepared.is_err(), "{case}");
            assert!(store
                .native_executor_container(&instance, &run)
                .unwrap()
                .is_none());
            if matches!(case, "image" | "create-id") {
                continue;
            }
            if case == "bind-IGNORE" {
                sql.execute_batch("DROP TRIGGER fail_binding").unwrap();
            }
            store
                .ensure_exec_fence(exec_lifetime::Fence {
                    instance_id: &instance,
                    run_id: &run,
                    reason: exec_lifetime::FenceReason::Recovery,
                })
                .unwrap();
        } else {
            assert!(matches!(prepared.unwrap(), Prepared::Bound(_)), "{case}");
        }
        drop(store);
        let mut store = SqliteStore::open(&path).unwrap();
        let mut adapter = NativeExecutor::new(Fake(state.clone()));
        assert!(matches!(
            adapter
                .prepare(&mut store, &instance, &run, &image)
                .unwrap(),
            Prepared::Bound(_)
        ));
        assert_eq!(state.borrow().creates, 1, "{case}");
        match case {
            "owner-label" => state.borrow_mut().held.as_mut().unwrap().owner = "other".into(),
            "tracking-label" => state.borrow_mut().held.as_mut().unwrap().tracking = "other".into(),
            "name" => state.borrow_mut().held.as_mut().unwrap().name = "/other".into(),
            "bound-id" => state.borrow_mut().held.as_mut().unwrap().id = "c".repeat(64),
            "daemon" => state.borrow_mut().daemon = "other".into(),
            "remove-pending" => state.borrow_mut().retain_on_remove = true,
            "removed" => Fake(state.clone()).remove(&"b".repeat(64)).unwrap(),
            "fence-IGNORE" => sql.execute_batch("CREATE TRIGGER fail_fence BEFORE INSERT ON events WHEN NEW.event_type='exec.fence.requested' BEGIN SELECT RAISE(IGNORE); END").unwrap(),
            _ => (),
        }
        if matches!(
            case,
            "owner-label" | "tracking-label" | "name" | "bound-id" | "daemon"
        ) {
            assert!(
                adapter
                    .prepare(&mut store, &instance, &run, &image)
                    .is_err(),
                "{case}"
            );
        }
        let removed = adapter.remove_bound(
            &mut store,
            &instance,
            &run,
            exec_lifetime::FenceReason::Recovery,
        );
        if matches!(
            case,
            "owner-label"
                | "tracking-label"
                | "name"
                | "bound-id"
                | "daemon"
                | "remove-pending"
                | "fence-IGNORE"
        ) {
            assert!(removed.is_err(), "{case}");
            assert_eq!(
                state.borrow().removes,
                usize::from(case == "remove-pending")
            );
        } else {
            let removed = removed.unwrap();
            assert_eq!(state.borrow().removes, 1);
            assert_eq!(
                adapter
                    .remove_bound(
                        &mut store,
                        &instance,
                        &run,
                        exec_lifetime::FenceReason::Recovery
                    )
                    .unwrap(),
                removed
            );
            assert_eq!(state.borrow().removes, 1);
            assert!(matches!(
                adapter
                    .prepare(&mut store, &instance, &run, &image)
                    .unwrap(),
                Prepared::Absent(_)
            ));
            assert_eq!(state.borrow().creates, 1);
        }
        assert!(store
            .list_events(&instance)
            .unwrap()
            .iter()
            .all(|e| !matches!(
                e.event_type.as_str(),
                "exec.fence.proved" | "exec.outcome.observed" | "effect.terminal"
            )));
        drop(sql);
        drop(store);
        std::fs::remove_file(path).unwrap();
    }
}

struct ObservedDocker {
    inner: Docker,
    created: Rc<RefCell<Vec<String>>>,
    lose_response: bool,
}
impl Engine for ObservedDocker {
    fn daemon_id(&mut self) -> StoreResult<String> {
        self.inner.daemon_id()
    }
    fn inspect(&mut self, id: &str) -> StoreResult<Option<Inspection>> {
        self.inner.inspect(id)
    }
    fn remove(&mut self, id: &str) -> StoreResult<()> {
        self.inner.remove(id)
    }
    fn create_inert(&mut self, owner: &exec_native_owner::Owner) -> StoreResult<String> {
        let id = self.inner.create_inert(owner)?;
        self.created.borrow_mut().push(id.clone());
        if self.lose_response {
            return Err(StoreError::Conflict("physical create response lost".into()));
        }
        Ok(id)
    }
}
struct Cleanup {
    endpoint: String,
    containers: Rc<RefCell<Vec<String>>>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        for id in self.containers.borrow().iter() {
            let _ = std::process::Command::new("docker")
                .args(["--host", &self.endpoint, "container", "rm", "--force", id])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
        }
    }
}
#[test]
#[ignore = "local Docker physical suite: scripts/check-executor-container.sh"]
fn native_docker_physical_owner_recovery_and_removal() {
    use std::{
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    let image = std::env::var("WHIP_TEST_EXECUTOR_IMAGE")
        .expect("physical suite supplies its built image ID");
    let endpoint = std::env::var("WHIP_TEST_DOCKER_ENDPOINT")
        .unwrap_or_else(|_| "unix:///var/run/docker.sock".into());
    assert!(
        endpoint.starts_with("unix://"),
        "physical PID inspection requires the local Docker daemon"
    );
    for lose_response in [false, true] {
        let (mut store, instance, run, path) = setup();
        let containers = Rc::new(RefCell::new(Vec::new()));
        let _cleanup = Cleanup {
            endpoint: endpoint.clone(),
            containers: containers.clone(),
        };
        let mut adapter = NativeExecutor::new(ObservedDocker {
            inner: Docker::new(&endpoint).unwrap(),
            created: containers.clone(),
            lose_response,
        });
        let prepared = adapter.prepare(&mut store, &instance, &run, &image);
        if lose_response {
            assert!(prepared.is_err());
            assert!(store
                .native_executor_container(&instance, &run)
                .unwrap()
                .is_none());
            store
                .ensure_exec_fence(exec_lifetime::Fence {
                    instance_id: &instance,
                    run_id: &run,
                    reason: exec_lifetime::FenceReason::Recovery,
                })
                .unwrap();
        } else {
            assert!(matches!(prepared.unwrap(), Prepared::Bound(_)));
        }
        drop(store);
        let mut store = SqliteStore::open(&path).unwrap();
        let mut adapter = NativeExecutor::new(Docker::new(&endpoint).unwrap());
        let Prepared::Bound(bound) = adapter
            .prepare(&mut store, &instance, &run, &image)
            .unwrap()
        else {
            panic!("cold owner not recovered");
        };
        assert_eq!(
            containers.borrow().as_slice(),
            std::slice::from_ref(&bound.container_id)
        );
        let inspect = Command::new("docker")
            .args([
                "--host",
                &endpoint,
                "inspect",
                "--format",
                "{{.State.Status}}",
                &bound.container_id,
            ])
            .output()
            .unwrap();
        assert!(inspect.status.success());
        assert_eq!(
            String::from_utf8(inspect.stdout).unwrap().trim(),
            "created",
            "preparation must remain inert"
        );
        let mut descendant = None;
        let mut pids = Vec::new();
        if !lose_response {
            assert!(Command::new("docker")
                .args(["--host", &endpoint, "start", &bound.container_id])
                .stdout(Stdio::null())
                .status()
                .unwrap()
                .success());
            descendant = Some(
                Command::new("docker")
                    .args([
                        "--host",
                        &endpoint,
                        "exec",
                        &bound.container_id,
                        "sh",
                        "-c",
                        "sleep 300 & wait",
                    ])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let output = Command::new("docker")
                    .args([
                        "--host",
                        &endpoint,
                        "top",
                        &bound.container_id,
                        "-eo",
                        "pid,comm",
                    ])
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let rows = String::from_utf8(output.stdout).unwrap();
                if rows
                    .lines()
                    .any(|line| line.split_whitespace().last() == Some("sleep"))
                {
                    pids = rows
                        .lines()
                        .skip(1)
                        .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
                        .map(|pid| {
                            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                                .expect("container PID must be visible on this physical test host");
                            let fields: Vec<_> = stat
                                .rsplit_once(") ")
                                .unwrap()
                                .1
                                .split_whitespace()
                                .collect();
                            assert!(
                                !matches!(fields[0], "Z" | "X"),
                                "owner process was already dead"
                            );
                            (pid, fields[19].to_owned())
                        })
                        .collect();
                    break;
                }
                assert!(Instant::now() < deadline, "descendant did not start");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        assert_eq!(
            adapter
                .remove_bound(
                    &mut store,
                    &instance,
                    &run,
                    exec_lifetime::FenceReason::Recovery
                )
                .unwrap(),
            bound
        );
        if let Some(mut child) = descendant {
            let deadline = Instant::now() + Duration::from_secs(10);
            while child.try_wait().unwrap().is_none() {
                assert!(
                    Instant::now() < deadline,
                    "Docker exec remained live after owner removal"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
            for (pid, started) in pids {
                if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                    let fields: Vec<_> = stat
                        .rsplit_once(") ")
                        .unwrap()
                        .1
                        .split_whitespace()
                        .collect();
                    assert!(
                        fields[19] != started || matches!(fields[0], "Z" | "X"),
                        "owner process {pid} survived: {stat}"
                    );
                }
            }
        }
        assert!(
            !Command::new("docker")
                .args(["--host", &endpoint, "start", &bound.container_id])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success(),
            "removed immutable ID restarted"
        );
        assert!(matches!(
            adapter
                .prepare(&mut store, &instance, &run, &image)
                .unwrap(),
            Prepared::Absent(_)
        ));
        assert_eq!(
            adapter
                .remove_bound(
                    &mut store,
                    &instance,
                    &run,
                    exec_lifetime::FenceReason::Recovery
                )
                .unwrap(),
            bound
        );
        assert!(store
            .list_events(&instance)
            .unwrap()
            .iter()
            .all(|e| !matches!(
                e.event_type.as_str(),
                "exec.fence.proved" | "exec.outcome.observed" | "effect.terminal"
            )));
        drop(store);
        std::fs::remove_file(path).unwrap();
        println!(
            "native physical owner: lost_response={lose_response}, removal and cold replay passed"
        );
    }
}

#[test]
#[ignore = "requires the production executor image and Docker"]
fn native_docker_physical_controller_authority() {
    use whipplescript::native_controller::{Command, Identity};
    use whipplescript_kernel::exec_invocation::{Envelope, Invocation};
    let image = std::env::var("WHIP_TEST_EXECUTOR_IMAGE").expect("physical image");
    let endpoint = std::env::var("WHIP_TEST_DOCKER_ENDPOINT").expect("physical endpoint");
    let mut engine = Docker::new(&endpoint).unwrap();
    let daemon = engine.daemon_id().unwrap();
    let (mut store, instance, run, path) = setup();
    let selected = Invocation {
        instance_id: instance.clone(),
        effect_id: "exec".into(),
        attempt_admission_event_id: None,
    };
    let identity = Identity {
        envelope: Envelope::new(
            selected.clone(),
            serde_json::json!({"protocol":"whip-executor/1","effect_id":"exec"}),
        )
        .unwrap(),
        selected,
    };
    let owner = store
        .allocate_native_executor(exec_native_owner::Allocation {
            instance_id: &instance,
            run_id: &run,
            daemon_id: &daemon,
            image_id: &image,
        })
        .unwrap()
        .owner;
    struct Volumes {
        endpoint: String,
        names: Vec<String>,
    }
    impl Drop for Volumes {
        fn drop(&mut self) {
            for name in &self.names {
                let _ = std::process::Command::new("docker")
                    .args(["--host", &self.endpoint, "volume", "rm", name])
                    .output();
            }
        }
    }
    let mut cleanup = Volumes {
        endpoint: endpoint.clone(),
        names: vec![identity.controller_id()],
    };
    let read = engine
        .controller(&daemon, &image, &identity, Command::Read)
        .unwrap();
    assert!(!read.create);
    assert!(read.state.owner.is_none());
    assert!(
        engine
            .controller(
                &daemon,
                &image,
                &identity,
                Command::Claim {
                    owner: owner.clone()
                }
            )
            .unwrap()
            .create
    );
    let mut cold = Docker::new(&endpoint).unwrap();
    assert!(
        !cold
            .controller(
                &daemon,
                &image,
                &identity,
                Command::Claim {
                    owner: owner.clone()
                }
            )
            .unwrap()
            .create
    );
    let mut replaced = owner.clone();
    replaced.tracking_event_id = "restored-workflow-tracking".into();
    assert!(cold
        .controller(
            &daemon,
            &image,
            &identity,
            Command::Claim { owner: replaced }
        )
        .is_err());
    assert_eq!(
        cold.controller(&daemon, &image, &identity, Command::Read)
            .unwrap()
            .state
            .owner,
        Some(owner)
    );
    let fence = cold
        .controller(
            &daemon,
            &image,
            &identity,
            Command::Fence {
                fence_id: "original-fence".into(),
            },
        )
        .unwrap();
    assert_eq!(fence.response["action"]["action"], "not_admitted");
    assert!(cold
        .controller("foreign-daemon", &image, &identity, Command::Read)
        .is_err());
    assert!(cold
        .controller(&daemon, "mutable-image:latest", &identity, Command::Read)
        .is_err());
    let other_selected = Invocation {
        instance_id: instance.clone(),
        effect_id: "foreign-volume".into(),
        attempt_admission_event_id: None,
    };
    let other = Identity {
        envelope: Envelope::new(
            other_selected.clone(),
            serde_json::json!({"protocol":"whip-executor/1","effect_id":"foreign-volume"}),
        )
        .unwrap(),
        selected: other_selected,
    };
    cleanup.names.push(other.controller_id());
    assert!(std::process::Command::new("docker")
        .args([
            "--host",
            &endpoint,
            "volume",
            "create",
            "--label",
            "whipplescript.executor.controller=foreign",
            &other.controller_id()
        ])
        .output()
        .unwrap()
        .status
        .success());
    assert!(cold
        .controller(&daemon, &image, &other, Command::Read)
        .is_err());
    drop(store);
    std::fs::remove_file(path).unwrap();
    println!("native physical controller: cold ownership retained, replacement and foreign volume refused");
}

#[test]
#[ignore = "requires the production executor image and Docker"]
fn native_docker_physical_managed_lifecycle() {
    use whipplescript::native_controller::{Command, Identity};
    use whipplescript_kernel::{
        exec_http::{base64_encode, sha256_hex},
        exec_invocation::{Envelope, Invocation},
    };
    let image = std::env::var("WHIP_TEST_EXECUTOR_IMAGE").unwrap();
    let endpoint = std::env::var("WHIP_TEST_DOCKER_ENDPOINT").unwrap();
    let script = "sleep 120 &\nwait\n";
    let dispatch = serde_json::json!({"protocol":"whip-executor/1", "effect_id":"exec", "script_sha256":sha256_hex(script.as_bytes()), "script_b64":base64_encode(script.as_bytes()), "script_ext":"sh", "argv":["sh","{script}"], "script_index":1, "stdin":null, "timeout_ms":100});
    let (mut store, instance, run, path) = setup_with_dispatch(dispatch.clone());
    let selected = Invocation {
        instance_id: instance.clone(),
        effect_id: "exec".into(),
        attempt_admission_event_id: None,
    };
    let identity = Identity {
        envelope: Envelope::new(selected.clone(), dispatch).unwrap(),
        selected,
    };
    let mut engine = Docker::new(&endpoint).unwrap();
    let daemon = engine.daemon_id().unwrap();
    let owner = store
        .allocate_native_executor(exec_native_owner::Allocation {
            instance_id: &instance,
            run_id: &run,
            daemon_id: &daemon,
            image_id: &image,
        })
        .unwrap()
        .owner;
    struct Cleanup {
        endpoint: String,
        owner: String,
        volume: String,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::process::Command::new("docker")
                .args([
                    "--host",
                    &self.endpoint,
                    "rm",
                    "--force",
                    "--volumes",
                    &self.owner,
                ])
                .output();
            let _ = std::process::Command::new("docker")
                .args(["--host", &self.endpoint, "volume", "rm", &self.volume])
                .output();
        }
    }
    let _cleanup = Cleanup {
        endpoint: endpoint.clone(),
        owner: owner.owner_id.clone(),
        volume: identity.controller_id(),
    };
    let prepared = engine
        .prepare_managed(&daemon, &image, &identity, &owner)
        .unwrap();
    let container = prepared
        .state
        .container_id
        .clone()
        .expect("bound inert container");
    assert_eq!(prepared.state.owner.as_ref(), Some(&owner));
    let status = std::process::Command::new("docker")
        .args([
            "--host",
            &endpoint,
            "inspect",
            "--format",
            "{{.State.Status}}",
            &container,
        ])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8(status.stdout).unwrap().trim(), "created");
    let mut restored_candidate = owner.clone();
    restored_candidate.tracking_event_id = "restored-tracking-event".into();
    restored_candidate.owner_id = format!("whip-exec-{}", "c".repeat(64));
    let restored = engine
        .prepare_managed(&daemon, &image, &identity, &restored_candidate)
        .unwrap();
    assert_eq!(restored.state.owner.as_ref(), Some(&owner));
    assert_eq!(restored.state.container_id.as_ref(), Some(&container));
    let delivered = engine.deliver_managed(&daemon, &image, &identity).unwrap();
    assert_eq!(delivered.response["action"]["action"], "replay");
    assert_eq!(delivered.response["action"]["body"]["timed_out"], true);
    let tree = std::process::Command::new("docker")
        .args(["--host", &endpoint, "top", &container, "-eo", "pid,args"])
        .output()
        .unwrap();
    assert!(
        String::from_utf8(tree.stdout)
            .unwrap()
            .contains("sleep 120"),
        "fixture did not retain a descendant"
    );
    store
        .ensure_exec_fence(exec_lifetime::Fence {
            instance_id: &instance,
            run_id: &run,
            reason: exec_lifetime::FenceReason::Recovery,
        })
        .unwrap();
    let reconciled = engine
        .reconcile_managed(&mut store, &daemon, &image, &instance, &run)
        .unwrap();
    assert!(reconciled.closed);
    assert!(!reconciled.cleanup_pending);
    let fenced = engine
        .controller(&daemon, &image, &identity, Command::Read)
        .unwrap();
    let proofs = whipplescript_kernel::exec_lifetime::proofs(&store, &instance).unwrap();
    assert!(matches!(
        proofs[&run].closure.lifetime,
        exec_lifetime::LifetimeEvidence::Terminated { .. }
    ));
    let outcomes = whipplescript_kernel::exec_lifetime::outcomes(&store, &instance).unwrap();
    assert_eq!(
        outcomes[&run].outcome,
        exec_outcome::Outcome::Completed {
            status: 200,
            body: delivered.response["action"]["body"].clone(),
        }
    );
    assert_eq!(store.list_runs(&instance).unwrap()[0].status, "running");
    assert_eq!(
        fenced.response["action"]["body"],
        delivered.response["action"]["body"]
    );
    assert!(fenced.response["action"]["termination"].is_object());
    assert!(engine.inspect(&container).unwrap().is_none());
    let mut cold = Docker::new(&endpoint).unwrap();
    assert_eq!(
        cold.deliver_managed(&daemon, &image, &identity)
            .unwrap()
            .response,
        fenced.response
    );
    assert_eq!(
        cold.prepare_managed(&daemon, &image, &identity, &restored_candidate)
            .unwrap()
            .state
            .owner
            .as_ref(),
        Some(&owner)
    );
    assert_eq!(
        cold.controller(&daemon, &image, &identity, Command::Read)
            .unwrap()
            .state
            .container_id
            .as_ref(),
        Some(&container)
    );
    assert!(cold
        .inspect(&restored_candidate.owner_id)
        .unwrap()
        .is_none());
    let events = store.list_events(&instance).unwrap().len();
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    assert!(
        cold.reconcile_managed(&mut store, &daemon, &image, &instance, &run)
            .unwrap()
            .closed
    );
    assert_eq!(store.list_events(&instance).unwrap().len(), events);
    drop(store);
    std::fs::remove_file(path).unwrap();
    println!("native managed lifecycle: inert creation, original-owner recovery, retained timeout, descendant removal, workflow proof/outcome custody and cold replay passed");
}
