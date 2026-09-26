//! Native physical-owner custody: immutable creation and container bindings.
use whipplescript_store::{exec_lifetime, exec_native_owner::*, RuntimeStore, SqliteStore};

#[test]
fn native_executor_owner_custody() {
    let dir = std::env::temp_dir().join(format!(
        "native-owner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let image = format!("sha256:{}", "a".repeat(64));
    let container = "b".repeat(64);
    for case in [
        "exact",
        "daemon",
        "image",
        "image-tag",
        "foreign-transport",
        "fenced",
        "closed",
        "stale-attempt",
        "allocation-ABORT",
        "allocation-IGNORE",
        "bind-ABORT",
        "bind-IGNORE",
        "late-bind",
        "replacement",
        "owner-source",
        "owner-key",
        "tracking-source",
        "tracking-key",
        "container-source",
        "container-key",
        "invalid-container",
        "container-reuse",
    ] {
        let path = dir.join(format!("{case}.sqlite"));
        let mut store = SqliteStore::open(&path).unwrap();
        let sql = rusqlite::Connection::open(&path).unwrap();
        let url = if case == "foreign-transport" {
            "http://executor/exec"
        } else {
            "whip-executor://native/exec"
        };
        let (instance, run, invocation) = crate::exec_reconciliation_tests::prepared_at(
            &mut store,
            |q| sql.execute_batch(q).unwrap(),
            url,
        );
        store
            .track_exec_lifetime(exec_lifetime::Track {
                instance_id: &instance,
                effect_id: "observe",
                run_id: &run,
                input_json: "{}",
                invocation_json: &invocation,
                executor_url: url,
            })
            .unwrap();
        let mut request = Allocation {
            instance_id: &instance,
            run_id: &run,
            daemon_id: "daemon",
            image_id: &image,
        };
        if case == "image-tag" {
            request.image_id = "ubuntu:latest";
        }
        if case == "fenced" {
            store
                .ensure_exec_fence(exec_lifetime::Fence {
                    instance_id: &instance,
                    run_id: &run,
                    reason: exec_lifetime::FenceReason::Cancellation,
                })
                .unwrap();
        }
        if case == "stale-attempt" {
            store
                .append_event(whipplescript_store::NewEvent {
                    instance_id: &instance,
                    event_type: "lease.expired",
                    payload_json: r#"{"effect_id":"observe"}"#,
                    source: "kernel",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                })
                .unwrap();
        }
        if case == "closed" {
            sql.execute_batch("UPDATE runs SET status='failed'")
                .unwrap();
        }
        if case == "tracking-source" {
            sql.execute_batch(
                "UPDATE events SET source='external' WHERE event_type='exec.lifetime.tracked'",
            )
            .unwrap();
        }
        if case == "tracking-key" {
            sql.execute_batch("UPDATE events SET idempotency_key='other' WHERE event_type='exec.lifetime.tracked'").unwrap();
        }
        let allocation_fault = case.starts_with("allocation-");
        if allocation_fault {
            let action = if case.ends_with("IGNORE") {
                "RAISE(IGNORE)"
            } else {
                "RAISE(ABORT,'allocation fault')"
            };
            sql.execute_batch(&format!("CREATE TRIGGER fail_owner BEFORE INSERT ON events WHEN NEW.event_type='exec.native.owner.allocated' BEGIN SELECT {action}; END")).unwrap();
        }
        let before = store.list_events(&instance).unwrap();
        let allocated = store.allocate_native_executor(request);
        if matches!(
            case,
            "image-tag"
                | "foreign-transport"
                | "fenced"
                | "closed"
                | "stale-attempt"
                | "tracking-source"
                | "tracking-key"
        ) || allocation_fault
        {
            assert!(allocated.is_err(), "{case}");
            assert_eq!(store.list_events(&instance).unwrap(), before, "{case}");
            if !allocation_fault {
                continue;
            }
            sql.execute_batch("DROP TRIGGER fail_owner").unwrap();
        }
        let allocated = if allocation_fault {
            store.allocate_native_executor(request).unwrap()
        } else {
            allocated.unwrap()
        };
        assert!(allocated.created);
        let changed_image = format!("sha256:{}", "c".repeat(64));
        if case == "daemon" {
            request.daemon_id = "replacement-daemon";
        }
        if case == "image" {
            request.image_id = &changed_image;
        }
        if case == "owner-source" {
            sql.execute_batch("UPDATE events SET source='external' WHERE event_type='exec.native.owner.allocated'").unwrap();
        }
        if case == "owner-key" {
            sql.execute_batch("UPDATE events SET idempotency_key='other' WHERE event_type='exec.native.owner.allocated'").unwrap();
        }
        if matches!(case, "daemon" | "image" | "owner-source" | "owner-key") {
            let before = store.list_events(&instance).unwrap();
            assert!(store.allocate_native_executor(request).is_err(), "{case}");
            assert_eq!(store.list_events(&instance).unwrap(), before);
            continue;
        }
        if case == "late-bind" {
            store
                .ensure_exec_fence(exec_lifetime::Fence {
                    instance_id: &instance,
                    run_id: &run,
                    reason: exec_lifetime::FenceReason::Recovery,
                })
                .unwrap();
            sql.execute_batch(
                "UPDATE runs SET status='failed'; UPDATE effects SET status='failed'",
            )
            .unwrap();
        }
        let bind_fault = case.starts_with("bind-");
        if bind_fault {
            let action = if case.ends_with("IGNORE") {
                "RAISE(IGNORE)"
            } else {
                "RAISE(ABORT,'binding fault')"
            };
            sql.execute_batch(&format!("CREATE TRIGGER fail_binding BEFORE INSERT ON events WHEN NEW.event_type='exec.native.container.bound' BEGIN SELECT {action}; END")).unwrap();
        }
        let before = store.list_events(&instance).unwrap();
        let bound = store.bind_native_executor_container(
            &instance,
            &run,
            if case == "invalid-container" {
                "name-not-id"
            } else {
                &container
            },
        );
        if bind_fault || case == "invalid-container" {
            assert!(bound.is_err(), "{case}");
            assert_eq!(store.list_events(&instance).unwrap(), before);
            if !bind_fault {
                continue;
            }
            sql.execute_batch("DROP TRIGGER fail_binding").unwrap();
        }
        let bound = if bind_fault {
            store
                .bind_native_executor_container(&instance, &run, &container)
                .unwrap()
        } else {
            bound.unwrap()
        };
        if case == "replacement" {
            let before = store.list_events(&instance).unwrap();
            assert!(store
                .bind_native_executor_container(&instance, &run, &"d".repeat(64))
                .is_err());
            assert_eq!(store.list_events(&instance).unwrap(), before);
        }
        if case == "container-source" {
            sql.execute_batch("UPDATE events SET source='external' WHERE event_type='exec.native.container.bound'").unwrap();
        }
        if case == "container-key" {
            sql.execute_batch("UPDATE events SET idempotency_key='other' WHERE event_type='exec.native.container.bound'").unwrap();
        }
        if matches!(case, "container-source" | "container-key") {
            assert!(
                store.native_executor_container(&instance, &run).is_err(),
                "{case}"
            );
            assert!(
                store
                    .bind_native_executor_container(&instance, &run, &container)
                    .is_err(),
                "{case}"
            );
            continue;
        }
        if case == "container-reuse" {
            let original_instance = store.get_instance(&instance).unwrap().unwrap();
            let second = store
                .create_instance(whipplescript_store::NewInstance {
                    program_id: &original_instance.program_id,
                    version_id: &original_instance.version_id,
                    input_json: "{}",
                })
                .unwrap()
                .instance_id;
            store
                .commit_rule(crate::rule_commit_recovery_tests::commit(
                    &second,
                    &[whipplescript_store::NewEffect {
                        effect_id: "second",
                        idempotency_key: "second",
                        ..crate::rule_commit_recovery_tests::effect(None)
                    }],
                ))
                .unwrap();
            let selected = whipplescript_kernel::exec_invocation::Invocation {
                instance_id: second.clone(),
                effect_id: "second".into(),
                attempt_admission_event_id: None,
            };
            let second_run = selected.run_id();
            let envelope = whipplescript_kernel::exec_invocation::Envelope::new(
                selected.clone(),
                serde_json::json!({"protocol":"whip-executor/1","effect_id":"second"}),
            )
            .unwrap();
            let dispatch = whipplescript_kernel::sansio::HttpRequest {
                model_provenance: None,
                url: url.into(),
                headers: vec![],
                body: envelope.dispatch(&selected).unwrap().clone(),
            };
            let plan = whipplescript_kernel::exec_http::ExecDispatchPlan::prepare(
                "script.observer",
                "hash",
                &serde_json::json!({}),
                &dispatch,
                "epoch",
                None,
                None,
            );
            let metadata=serde_json::json!({"executor_invocation":envelope,"executor_dispatch":plan,"executor_url":url}).to_string();
            store
                .start_run(whipplescript_store::RunStart {
                    effect_id: "second",
                    run_id: &second_run,
                    worker_id: "whip-exec",
                    lease_id: "second-lease",
                    metadata_json: &metadata,
                    ..crate::run_reattach_tests::request(&second)
                })
                .unwrap();
            let second_invocation = serde_json::to_string(&envelope).unwrap();
            store
                .track_exec_lifetime(exec_lifetime::Track {
                    instance_id: &second,
                    effect_id: "second",
                    run_id: &second_run,
                    input_json: "{}",
                    invocation_json: &second_invocation,
                    executor_url: url,
                })
                .unwrap();
            store
                .allocate_native_executor(Allocation {
                    instance_id: &second,
                    run_id: &second_run,
                    daemon_id: "daemon",
                    image_id: &image,
                })
                .unwrap();
            assert!(store
                .bind_native_executor_container(&second, &second_run, &container)
                .is_err());
        }
        drop(store);
        let mut cold = SqliteStore::open(&path).unwrap();
        let before = cold.list_events(&instance).unwrap();
        let replay = cold.allocate_native_executor(request).unwrap();
        assert!(!replay.created);
        assert_eq!(replay.owner, allocated.owner);
        assert_eq!(replay.event, allocated.event);
        assert_eq!(
            cold.bind_native_executor_container(&instance, &run, &container)
                .unwrap(),
            bound
        );
        assert_eq!(
            cold.native_executor_container(&instance, &run)
                .unwrap()
                .unwrap()
                .container_id,
            container
        );
        assert_eq!(cold.list_events(&instance).unwrap(), before);
    }
    std::fs::remove_dir_all(dir).unwrap();
}
