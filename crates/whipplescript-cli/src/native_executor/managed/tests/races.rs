use super::*;
use crate::native_controller::Authority;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
use whipplescript_kernel::exec_invocation::{Envelope, Invocation};

/// Docker-boundary transcript with replies produced by the real authority.
/// Unscripted helper requests fail, so a retained result cannot silently deliver.
struct Fixture {
    dir: PathBuf,
    docker: Docker,
    identity: Identity,
    owner: Owner,
    container: String,
    steps: Vec<Value>,
}
impl Fixture {
    fn new() -> Self {
        let selected = Invocation {
            instance_id: "managed-race".into(),
            effect_id: "exec".into(),
            attempt_admission_event_id: None,
        };
        let identity = Identity {
            envelope: Envelope::new(
                selected.clone(),
                json!({"protocol":"whip-executor/1","effect_id":"exec"}),
            )
            .unwrap(),
            selected,
        };
        Self::with_identity(identity)
    }
    fn with_identity(identity: Identity) -> Self {
        Self::with_binding(identity, true)
    }
    fn with_binding(identity: Identity, bound: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "managed-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        let owner = Owner {
            protocol: whipplescript_store::exec_native_owner::PROTOCOL.into(),
            instance_id: identity.selected.instance_id.clone(),
            effect_id: identity.selected.effect_id.clone(),
            run_id: identity.selected.run_id(),
            tracking_event_id: "track".into(),
            daemon_id: "daemon".into(),
            image_id: format!("sha256:{}", "a".repeat(64)),
            owner_id: format!("whip-exec-{}", "b".repeat(64)),
        };
        let container = "c".repeat(64);
        let program = dir.join("docker");
        fs::write(&program, include_str!("docker.py")).unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        let mut docker = Docker::new("unix:///fixture").unwrap();
        docker.program = program;
        let f = Self {
            dir,
            docker,
            identity,
            owner,
            container,
            steps: Vec::new(),
        };
        f.write("volume", json!(f.identity.controller_id()));
        f.write(
            "labels",
            json!({
                "whipplescript.executor.controller": f.identity.controller_id(),
                "whipplescript.executor.controller.protocol": crate::native_controller::PROTOCOL,
            }),
        );
        f.write(
            "inspection",
            json!({
                "id": f.container, "image": f.owner.image_id,
                "name": format!("/{}",f.owner.owner_id), "owner": f.owner.owner_id,
                "tracking": f.owner.tracking_event_id,
            }),
        );
        let mut profile = super::profile();
        profile["id"] = json!(f.container);
        profile["env"][0] = json!(format!(
            "WHIP_EXECUTOR_DISPATCH_SHA256={}",
            dispatch_digest(&f.identity).unwrap()
        ));
        f.write("profile", profile);
        f.write("present", json!(true));
        f.write("mode", json!("normal"));
        f.apply(Command::Claim {
            owner: f.owner.clone(),
        });
        if bound {
            f.apply(Command::Bind {
                owner: f.owner.clone(),
                container_id: f.container.clone(),
            });
        }
        f
    }
    fn write(&self, name: &str, value: Value) {
        fs::write(self.dir.join(name), value.to_string()).unwrap();
    }
    fn apply(&self, command: Command) -> Reply {
        Authority::open(&self.dir.join("authority.sqlite"))
            .unwrap()
            .apply(&self.identity, command)
            .unwrap()
    }
    fn queue(&mut self, command: Command) -> Value {
        let reply = self.apply(command.clone());
        let response = reply.response.clone();
        self.steps.push(json!({
            "request": serde_json::to_value(Request::Control { identity: self.identity.clone(), command }).unwrap(),
            "reply": serde_json::to_value(reply).unwrap(),
        }));
        self.write("steps", json!(self.steps));
        response
    }
    fn admit(&self, complete: bool) {
        let result = Authority::open(&self.dir.join("authority.sqlite"))
            .unwrap()
            .execute(
                &self.identity,
                &self.owner.owner_id,
                &self.container,
                "incarnation",
                self.identity
                    .envelope
                    .dispatch(&self.identity.selected)
                    .unwrap(),
                || {
                    if complete {
                        Ok((200, json!({"retained":true})))
                    } else {
                        Err(StoreError::Conflict("lost transport".into()))
                    }
                },
            );
        assert_eq!(result.is_ok(), complete);
    }
    fn deliver(&mut self) -> StoreResult<Reply> {
        self.docker
            .deliver_managed("daemon", &self.owner.image_id, &self.identity)
    }
    fn fence(&mut self) -> StoreResult<Reply> {
        self.docker
            .fence_managed("daemon", &self.owner.image_id, &self.identity, "fence")
    }
    fn calls(&self, name: &str) -> usize {
        fs::read_to_string(self.dir.join("calls"))
            .unwrap_or_default()
            .lines()
            .filter(|line| *line == name)
            .count()
    }
    fn consumed(&self) {
        let count: usize =
            serde_json::from_str(&fs::read_to_string(self.dir.join("cursor")).unwrap()).unwrap();
        assert_eq!(count, self.steps.len());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "{}",
                fs::read_to_string(self.dir.join("error")).unwrap_or_default()
            );
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn managed_cold_results_never_start_or_contact_the_executor() {
    for mode in ["pending", "completed", "fenced"] {
        let mut f = Fixture::new();
        match mode {
            "pending" => f.admit(false),
            "completed" => f.admit(true),
            _ => {
                f.apply(Command::Fence {
                    fence_id: "fence".into(),
                });
            }
        }
        let expected = f.queue(Command::Read);
        assert_eq!(f.deliver().unwrap().response, expected);
        assert_eq!(f.calls("start"), 0, "{mode}");
        assert_eq!(f.calls("inspect"), 0, "{mode}");
        assert_eq!(f.calls("deliver"), 0, "{mode}");
        f.consumed();
    }
}

#[test]
fn managed_startup_races_preserve_the_winning_authority() {
    for mode in ["pending", "completed", "fenced"] {
        let mut f = Fixture::new();
        f.queue(Command::Read);
        match mode {
            "pending" => f.admit(false),
            "completed" => f.admit(true),
            _ => {
                f.apply(Command::Fence {
                    fence_id: "fence".into(),
                });
            }
        }
        let expected = f.queue(Command::Read);
        assert_eq!(f.deliver().unwrap().response, expected);
        assert_eq!(f.calls("start"), 1, "{mode}");
        assert_eq!(f.calls("profile"), 1, "{mode}");
        assert_eq!(f.calls("deliver"), 0, "{mode}");
        f.consumed();
    }
}

#[test]
fn managed_startup_revalidates_the_physical_profile_and_identity() {
    for mode in ["changed-profile", "changed-start-id", "lost-target"] {
        let mut f = Fixture::new();
        f.write("mode", json!(mode));
        f.queue(Command::Read);
        if mode != "changed-start-id" {
            f.queue(Command::Read);
        }
        assert!(f.deliver().is_err(), "{mode}");
        assert_eq!(f.calls("start"), 1);
        assert_eq!(
            f.calls("read"),
            if mode == "changed-start-id" { 1 } else { 2 }
        );
        assert_eq!(f.calls("deliver"), 0);
        f.consumed();
    }
}

#[test]
fn managed_failed_removal_never_finishes_the_barrier_and_retry_recovers() {
    for mode in ["remove-error", "remove-pending"] {
        let mut f = Fixture::new();
        f.admit(false);
        f.write("mode", json!(mode));
        f.queue(Command::Fence {
            fence_id: "fence".into(),
        });
        assert!(f.fence().is_err(), "{mode}");
        assert_eq!(f.calls("finish"), 0);
        assert_eq!(f.calls("remove"), 1);
        f.consumed();
        f.write("mode", json!("normal"));
        f.queue(Command::Fence {
            fence_id: "fence".into(),
        });
        let held = f.apply(Command::Read);
        let barrier = held.state.barrier.as_ref().unwrap()["barrier_id"]
            .as_str()
            .unwrap();
        let expected = f.queue(Command::Finish {
            container_id: f.container.clone(),
            barrier_id: barrier.into(),
        });
        assert_eq!(f.fence().unwrap().response, expected);
        assert_eq!(f.calls("remove"), 2);
        assert_eq!(f.calls("finish"), 1);
        assert_eq!(f.calls("deliver"), 0);
        f.consumed();
    }
}

mod workflow {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/native_executor.rs"
    ));
}
fn workflow_identity(store: &SqliteStore, instance: &str, run: &str) -> Identity {
    let tracked = whipplescript_kernel::exec_lifetime::tracked(store, instance).unwrap();
    let original = &tracked[run];
    Identity {
        selected: serde_json::from_value(original.invocation["invocation"].clone()).unwrap(),
        envelope: serde_json::from_value(original.invocation.clone()).unwrap(),
    }
}
impl Fixture {
    fn queue_fence(&mut self, fence_id: &str) {
        self.queue(Command::Fence {
            fence_id: fence_id.into(),
        });
        let held = self.apply(Command::Read);
        if let Some(barrier) = &held.state.barrier {
            if barrier["closing"] == true {
                self.queue(Command::Finish {
                    container_id: self.container.clone(),
                    barrier_id: barrier["barrier_id"].as_str().unwrap().into(),
                });
            }
        }
    }
    fn reconcile(
        &mut self,
        store: &mut SqliteStore,
        instance: &str,
        run: &str,
    ) -> StoreResult<ManagedReconciliation> {
        self.docker
            .reconcile_managed(store, "daemon", &self.owner.image_id, instance, run)
    }
}
fn fence_intent(store: &mut SqliteStore, instance: &str, run: &str) -> String {
    store
        .ensure_exec_fence(whipplescript_store::exec_lifetime::Fence {
            instance_id: instance,
            run_id: run,
            reason: FenceReason::Recovery,
        })
        .unwrap();
    whipplescript_kernel::exec_lifetime::fences(store, instance).unwrap()[run]
        .fence_id
        .clone()
}

#[test]
fn native_norm_driver_preserves_live_pending_and_settles_closed_completion() {
    use crate::native_executor::norm_admission::tests::{binding, fixture_with_store};
    use whipplescript_kernel::{norm_runner::PythonCallMethod, RuntimeKernel};
    for (operation, mode) in [
        ("execute", "pending"),
        ("execute", "completed"),
        ("poll", "absent"),
        ("poll", "pending"),
        ("poll", "completed"),
        ("poll", "expired"),
        ("poll", "late"),
        ("recover", "absent"),
        ("recover", "pending"),
        ("recover", "completed"),
        ("recover", "expired"),
        ("recover", "late"),
        ("recover", "forced"),
        ("recover", "startup"),
        ("recover", "superseded"),
    ] {
        let path = std::env::temp_dir().join(format!(
            "norm-driver-{}-{operation}-{mode}.sqlite",
            std::process::id()
        ));
        let (mut kernel, instance, effect, _) =
            fixture_with_store("exact", SqliteStore::open(&path).unwrap());
        let input: Value = serde_json::from_str(&effect.input_json).unwrap();
        let method: PythonCallMethod =
            serde_json::from_str(input["stdin"]["method_definition_json"].as_str().unwrap())
                .unwrap();
        let mut installed = binding(method.runtime);
        installed.daemon_id = "daemon".into();
        installed.image_id = format!("sha256:{}", "a".repeat(64));
        let admitted = NativeNormAdmission::admit_at(
            &mut kernel,
            &instance,
            &effect,
            &installed,
            "2030-01-01T00:00:00Z",
        )
        .unwrap();
        let run = admitted.handoff.run_id();
        let mut f = Fixture::with_binding(
            serde_json::from_value(admitted.handoff.command()).unwrap(),
            mode != "late" && !(operation == "recover" && mode == "absent"),
        );
        if mode == "late" || (operation == "recover" && mode == "absent") {
            f.write("present", json!(false));
        }
        let response = json!({"protocol":"whip-executor/1", "effect_id":effect.effect_id,"exit_code":0,"stdout":"retained","stderr":"","timed_out":false,"stdout_truncated":false,"stderr_truncated":false});
        if !matches!(mode, "absent" | "late" | "startup") {
            let result = Authority::open(&f.dir.join("authority.sqlite"))
                .unwrap()
                .execute(
                    &f.identity,
                    &f.owner.owner_id,
                    &f.container,
                    "incarnation",
                    f.identity.envelope.dispatch(&f.identity.selected).unwrap(),
                    || {
                        if mode == "completed" {
                            Ok((200, response.clone()))
                        } else {
                            Err(StoreError::Conflict("lost transport".into()))
                        }
                    },
                );
            assert_eq!(result.is_ok(), mode == "completed");
        }
        if mode == "superseded" {
            kernel.store().append_event(whipplescript_store::NewEvent {
                instance_id: &instance, event_type: "lease.expired", payload_json: &json!({"effect_id":effect.effect_id, "run_id":run, "lease_id":"old-expiry"}).to_string(), source:"kernel", causation_id:None, correlation_id:None, idempotency_key:Some("old-expiry"),
            }).unwrap();
            let connection = rusqlite::Connection::open(&path).unwrap();
            connection.execute_batch("UPDATE runs SET status='lease_expired'; UPDATE effects SET status='queued'; UPDATE leases SET status='expired';").unwrap();
        }
        if mode == "late" || (mode == "expired" && operation != "recover") {
            fence_intent(kernel.store_mut(), &instance, &run);
        }
        if !matches!(mode, "expired" | "late" | "forced" | "superseded") {
            f.queue(Command::Read);
        }
        if mode == "startup" {
            f.queue(Command::Read);
            f.queue(Command::Read);
            let reply = Authority::open(&f.dir.join("authority.sqlite"))
                .unwrap()
                .execute(
                    &f.identity,
                    &f.owner.owner_id,
                    &f.container,
                    "incarnation",
                    f.identity.envelope.dispatch(&f.identity.selected).unwrap(),
                    || Ok((200, response.clone())),
                )
                .unwrap();
            f.steps.push(json!({"request":serde_json::to_value(Request::Deliver {identity:f.identity.clone(), owner:f.owner.owner_id.clone(), container_id:f.container.clone()}).unwrap(), "reply":serde_json::to_value(reply).unwrap()}));
            f.write("steps", json!(f.steps));
        }
        if matches!(
            mode,
            "completed" | "expired" | "late" | "forced" | "startup" | "superseded"
        ) {
            let fence = Fence {
                instance_id: &instance,
                run_id: &run,
                reason: FenceReason::Recovery,
            }
            .key();
            f.queue_fence(&fence);
        }
        let before = kernel.store().list_events(&instance).unwrap().len();
        let (closed, terminal_events) = if operation == "recover" {
            let calls = fs::read(f.dir.join("calls")).ok();
            assert!(f
                .docker
                .recover_norm_instance(&mut kernel, &instance, "now", false)
                .is_err());
            assert_eq!(kernel.store().list_events(&instance).unwrap().len(), before);
            assert_eq!(fs::read(f.dir.join("calls")).ok(), calls);
            let result = f
                .docker
                .recover_norm_instance(
                    &mut kernel,
                    &instance,
                    if mode == "expired" {
                        "2030-01-01T00:10:00Z"
                    } else {
                        "2030-01-01T00:09:59Z"
                    },
                    mode == "forced",
                )
                .unwrap();
            assert_eq!(
                result.pending,
                usize::from(matches!(mode, "absent" | "pending" | "late"))
            );
            (
                kernel.store().list_runs(&instance).unwrap()[0].status != "running",
                result.terminal_events,
            )
        } else {
            let progress = if operation == "execute" {
                f.docker
                    .execute_norm(&mut kernel, &instance, &effect, &installed)
            } else {
                f.docker.poll_norm(&mut kernel, &instance, &run)
            }
            .unwrap();
            (progress.closed, progress.terminal_events)
        };
        let terminal = matches!(
            mode,
            "completed" | "expired" | "late" | "forced" | "startup"
        );
        assert_eq!(closed, terminal || mode == "superseded");
        assert_eq!(terminal_events.len(), usize::from(terminal));
        assert_eq!(f.calls("deliver"), usize::from(mode == "startup"));
        assert_eq!(f.calls("start"), usize::from(mode == "startup"));
        if matches!(mode, "absent" | "pending") {
            assert_eq!(kernel.store().list_events(&instance).unwrap().len(), before);
            assert!(
                whipplescript_kernel::exec_lifetime::fences(kernel.store(), &instance)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(f.calls("remove"), 0);
        } else {
            let metadata: Value = serde_json::from_str(
                &kernel.store().list_runs(&instance).unwrap()[0].metadata_json,
            )
            .unwrap();
            if matches!(mode, "completed" | "startup") {
                assert_eq!(metadata["executor_transport"], "native-managed");
                assert_eq!(metadata["executor_response"]["body"], response);
            }
            let count = kernel.store().list_events(&instance).unwrap().len();
            drop(kernel);
            kernel = RuntimeKernel::new(SqliteStore::open(&path).unwrap());
            let start = kernel
                .store()
                .event_by_idempotency_key(&instance, &run)
                .unwrap()
                .unwrap();
            let connection = rusqlite::Connection::open(&path).unwrap();
            let original: String = connection
                .query_row(
                    "SELECT payload_json FROM events WHERE event_id=?1",
                    [&start.event_id],
                    |row| row.get(0),
                )
                .unwrap();
            let tracking: String = connection.query_row(
                "SELECT payload_json FROM events WHERE event_type='exec.lifetime.tracked' AND instance_id=?1",
                [&instance], |row| row.get(0),
            ).unwrap();
            let calls = fs::read_to_string(f.dir.join("calls")).unwrap();
            for fault in ["source", "invocation", "transport", "runtime", "provider"] {
                if fault == "provider" {
                    // Exercise the unfenced polling door: otherwise the deeper
                    // reconciliation provider guard masks this refusal.
                    connection.execute("UPDATE events SET event_type='fixture.hidden-fence' WHERE event_type='exec.fence.requested' AND instance_id=?1", [&instance]).unwrap();
                    let mut changed: Value = serde_json::from_str(&tracking).unwrap();
                    changed["executor_url"] = json!("https://foreign.invalid/exec");
                    connection.execute("UPDATE events SET payload_json=?1 WHERE event_type='exec.lifetime.tracked' AND instance_id=?2", rusqlite::params![changed.to_string(), &instance]).unwrap();
                }
                let mut changed: Value = serde_json::from_str(&original).unwrap();
                match fault {
                    "invocation" => changed["metadata"]["executor_invocation"] = json!({}),
                    "transport" => changed["metadata"]["executor_transport"] = json!("in-process"),
                    "runtime" => {
                        changed["metadata"]["native_runtime"]["runtime"]["environment"] =
                            json!("foreign")
                    }
                    _ => {}
                }
                connection
                    .execute(
                        "UPDATE events SET payload_json=?1,source=?2 WHERE event_id=?3",
                        rusqlite::params![
                            changed.to_string(),
                            if fault == "source" {
                                "foreign"
                            } else {
                                "kernel"
                            },
                            &start.event_id
                        ],
                    )
                    .unwrap();
                assert!(
                    f.docker
                        .reconcile_norm(&mut kernel, &instance, &run)
                        .is_err(),
                    "{fault}"
                );
                assert!(
                    f.docker.poll_norm(&mut kernel, &instance, &run).is_err(),
                    "poll {fault}"
                );
                assert_eq!(
                    fs::read_to_string(f.dir.join("calls")).unwrap(),
                    calls,
                    "{fault} reached Docker"
                );
                connection
                    .execute(
                        "UPDATE events SET payload_json=?1,source='kernel' WHERE event_id=?2",
                        rusqlite::params![&original, &start.event_id],
                    )
                    .unwrap();
                connection.execute("UPDATE events SET payload_json=?1 WHERE event_type='exec.lifetime.tracked' AND instance_id=?2", rusqlite::params![&tracking, &instance]).unwrap();
                connection.execute("UPDATE events SET event_type='exec.fence.requested' WHERE event_type='fixture.hidden-fence' AND instance_id=?1", [&instance]).unwrap();
            }
            drop(connection);
            let fence = whipplescript_kernel::exec_lifetime::fences(kernel.store(), &instance)
                .unwrap()[&run]
                .fence_id
                .clone();
            f.queue_fence(&fence);
            let replay = f.docker.poll_norm(&mut kernel, &instance, &run).unwrap();
            assert!(replay.closed);
            assert!(replay.terminal_events.is_empty());
            assert_eq!(kernel.store().list_events(&instance).unwrap().len(), count);
            if mode == "late" {
                assert!(replay.cleanup_pending);
                f.write("present", json!(true));
                f.queue(Command::Fence { fence_id: fence });
                f.queue(Command::Bind {
                    owner: f.owner.clone(),
                    container_id: f.container.clone(),
                });
                let cleaned = f.docker.poll_norm(&mut kernel, &instance, &run).unwrap();
                assert!(cleaned.closed);
                assert!(!cleaned.cleanup_pending);
                assert!(cleaned.terminal_events.is_empty());
                assert_eq!(kernel.store().list_events(&instance).unwrap().len(), count);
                assert_eq!(f.calls("remove"), 1);
                assert_eq!(f.calls("start"), 0);
                assert_eq!(f.calls("deliver"), 0);
            }
        }
        f.consumed();
        if mode == "expired" {
            // An expired lease resolves to `uncertain`: the container was
            // fenced, and the runtime cannot tell whether it applied its effect
            // before the lease ran out. Retrying would resubmit a side effect
            // that may already have happened, so admission refuses until
            // absence is PROVED (spec/admission-and-idempotency.md).
            //
            // A run whose resolution says `not_executed` is the provable case,
            // and `exec_lifetime::observe` records that disposition when it
            // sees one; `uncertain` is deliberately not recorded, because
            // nothing about it is proof.
            let refused = kernel
                .retry_effect(whipplescript_store::RetryEffect {
                    instance_id: &instance,
                    effect_id: &effect.effect_id,
                    retry_after: None,
                    idempotency_key: Some("proved-retry"),
                })
                .unwrap_err();
            assert!(
                matches!(refused, StoreError::Conflict(ref e)
                    if e.contains("does not prove safe resubmission")),
                "{refused:?}"
            );
            assert!(
                kernel
                    .store()
                    .claimable_effects(&instance)
                    .unwrap()
                    .is_empty(),
                "a refused retry admits no new attempt"
            );
        }
        if mode == "superseded" {
            // Supersession leaves the SAME effect claimable, so admitting it is
            // a fresh dispatch of an effect whose previous attempt has no
            // proved disposition. The norm driver admits under
            // `RecoveryCeiling::Unverifiable` -- the legacy entry point, which
            // by construction cannot prove a target never applied -- so a
            // second dispatch is refused rather than risking a duplicate
            // external effect.
            //
            // Lifting this needs the driver to dispatch under a verified
            // recovery contract; recording a disposition cannot substitute,
            // because an unverifiable ceiling is not promotable by metadata.
            let next = kernel
                .store()
                .claimable_effects(&instance)
                .unwrap()
                .pop()
                .unwrap();
            assert_eq!(next.effect_id, effect.effect_id);
            let Err(refused) = NativeNormAdmission::admit_at(
                &mut kernel,
                &instance,
                &next,
                &installed,
                "2030-01-01T00:11:00Z",
            ) else {
                panic!("a superseded effect must not re-dispatch unproved");
            };
            assert!(
                matches!(refused, StoreError::Conflict(ref e)
                    if e.contains("does not prove safe resubmission")),
                "{refused:?}"
            );
        }
        drop(kernel);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn native_reconciliation_requires_original_native_tracking_and_intent() {
    let (mut store, instance, run, path) = workflow::setup();
    let mut f = Fixture::with_identity(workflow_identity(&store, &instance, &run));
    let error = f
        .reconcile(&mut store, &instance, "foreign-run")
        .unwrap_err();
    assert!(matches!(error, StoreError::Conflict(ref e) if e.contains("original tracking")));
    let error = f.reconcile(&mut store, &instance, &run).unwrap_err();
    assert!(matches!(error, StoreError::Conflict(ref e) if e.contains("retained fence intent")));
    assert!(!f.dir.join("calls").exists());
    drop(store);
    fs::remove_file(path).unwrap();

    let (mut store, instance, run, path) = workflow::setup_with_executor(
        json!({"protocol":"whip-executor/1","effect_id":"exec"}),
        "https://executor.invalid/exec",
    );
    fence_intent(&mut store, &instance, &run);
    let mut f = Fixture::with_identity(workflow_identity(&store, &instance, &run));
    let error = f.reconcile(&mut store, &instance, &run).unwrap_err();
    assert!(
        matches!(error, StoreError::Conflict(ref e) if e.contains("another executor provider"))
    );
    assert!(!f.dir.join("calls").exists());
    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn native_reconciliation_retains_all_outcomes_without_settling_or_reexecuting() {
    use whipplescript_kernel::exec_lifetime as journal;
    use whipplescript_store::{exec_lifetime::LifetimeEvidence, exec_outcome::Outcome};
    for mode in ["not-executed", "uncertain", "completed"] {
        let (mut store, instance, run, path) = workflow::setup();
        let mut f = Fixture::with_identity(workflow_identity(&store, &instance, &run));
        if mode != "not-executed" {
            f.admit(mode == "completed");
        }
        let fence = fence_intent(&mut store, &instance, &run);
        f.queue_fence(&fence);
        assert_eq!(
            f.reconcile(&mut store, &instance, &run).unwrap(),
            ManagedReconciliation {
                closed: true,
                cleanup_pending: false
            }
        );
        let proof = journal::proofs(&store, &instance)
            .unwrap()
            .remove(&run)
            .unwrap();
        let outcome = journal::outcomes(&store, &instance)
            .unwrap()
            .remove(&run)
            .unwrap();
        match mode {
            "not-executed" => {
                assert!(matches!(
                    proof.closure.lifetime,
                    LifetimeEvidence::NotAdmitted { .. }
                ));
                assert_eq!(outcome.outcome, Outcome::NotExecuted);
            }
            "uncertain" => {
                assert!(matches!(
                    proof.closure.lifetime,
                    LifetimeEvidence::Terminated { .. }
                ));
                assert_eq!(outcome.outcome, Outcome::Uncertain);
            }
            _ => {
                assert!(matches!(
                    proof.closure.lifetime,
                    LifetimeEvidence::Terminated { .. }
                ));
                assert_eq!(
                    outcome.outcome,
                    Outcome::Completed {
                        status: 200,
                        body: json!({"retained":true})
                    }
                );
            }
        }
        let events = store.list_events(&instance).unwrap().len();
        drop(store);
        let mut store = SqliteStore::open(&path).unwrap();
        f.queue_fence(&fence);
        assert!(f.reconcile(&mut store, &instance, &run).unwrap().closed);
        assert_eq!(store.list_events(&instance).unwrap().len(), events);
        assert_eq!(store.list_runs(&instance).unwrap()[0].status, "running");
        assert_eq!(f.calls("remove"), 1);
        assert_eq!(f.calls("start"), 0);
        assert_eq!(f.calls("deliver"), 0);
        f.consumed();
        drop(store);
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn native_reconciliation_recovers_a_failed_outcome_write_after_proof() {
    use whipplescript_kernel::exec_lifetime as journal;
    let (mut store, instance, run, path) = workflow::setup();
    let mut f = Fixture::with_identity(workflow_identity(&store, &instance, &run));
    f.admit(false);
    let fence = fence_intent(&mut store, &instance, &run);
    let fault = rusqlite::Connection::open(&path).unwrap();
    fault
        .execute_batch(
            "CREATE TRIGGER reject_native_outcome BEFORE INSERT ON events
        WHEN NEW.event_type = 'exec.outcome.observed'
        BEGIN SELECT RAISE(ABORT, 'injected native outcome failure'); END;",
        )
        .unwrap();
    f.queue_fence(&fence);
    assert!(f.reconcile(&mut store, &instance, &run).is_err());
    let proof = journal::proofs(&store, &instance)
        .unwrap()
        .remove(&run)
        .unwrap();
    assert!(journal::outcomes(&store, &instance).unwrap().is_empty());
    assert_eq!(f.calls("remove"), 1);
    fault
        .execute_batch("DROP TRIGGER reject_native_outcome;")
        .unwrap();
    drop(fault);
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    f.queue_fence(&fence);
    assert!(f.reconcile(&mut store, &instance, &run).unwrap().closed);
    let retained = journal::proofs(&store, &instance)
        .unwrap()
        .remove(&run)
        .unwrap();
    assert_eq!(
        serde_json::to_value(retained).unwrap(),
        serde_json::to_value(proof).unwrap()
    );
    assert_eq!(journal::outcomes(&store, &instance).unwrap().len(), 1);
    assert_eq!(store.list_runs(&instance).unwrap()[0].status, "running");
    assert_eq!(f.calls("remove"), 1);
    assert_eq!(f.calls("start"), 0);
    assert_eq!(f.calls("deliver"), 0);
    f.consumed();
    drop(store);
    fs::remove_file(path).unwrap();
}

#[test]
fn native_reconciliation_keeps_late_creation_cleanup_after_non_admission() {
    let (mut store, instance, run, path) = workflow::setup();
    let mut f = Fixture::with_binding(workflow_identity(&store, &instance, &run), false);
    f.write("present", json!(false));
    let fence = fence_intent(&mut store, &instance, &run);
    f.queue(Command::Fence {
        fence_id: fence.clone(),
    });
    assert_eq!(
        f.reconcile(&mut store, &instance, &run).unwrap(),
        ManagedReconciliation {
            closed: true,
            cleanup_pending: true
        }
    );
    let events = store.list_events(&instance).unwrap().len();
    f.write("present", json!(true));
    f.queue(Command::Fence { fence_id: fence });
    f.queue(Command::Bind {
        owner: f.owner.clone(),
        container_id: f.container.clone(),
    });
    assert_eq!(
        f.reconcile(&mut store, &instance, &run).unwrap(),
        ManagedReconciliation {
            closed: true,
            cleanup_pending: false
        }
    );
    assert_eq!(store.list_events(&instance).unwrap().len(), events);
    assert_eq!(f.calls("remove"), 1);
    assert_eq!(f.calls("start"), 0);
    assert_eq!(f.calls("deliver"), 0);
    f.consumed();
    drop(store);
    fs::remove_file(path).unwrap();
}
