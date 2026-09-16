use crate::do_store::DoSql;
use whipplescript_store::*;

const CASES: &[&str] = &[
    "lease-expiry-tracked",
    "lease-expiry-legacy",
    "lease-expiry-existing",
    "lease-expiry-ABORT",
    "lease-expiry-IGNORE",
    "lease-expiry-update-IGNORE",
    "lease-expiry-orphan",
    "recovery-fence-new",
    "recovery-fence-existing",
    "recovery-fence-ABORT",
    "recovery-fence-IGNORE",
    "retry-proof-empty",
    "retry-foreign-effect",
    "retry-closure",
    "retry-pending",
    "retry-proof-source",
    "retry-proof-key",
    "retry-tracking-key",
    "retry-proof-binding",
    "retry-missing-intent",
    "outcome-settle-not-executed",
    "outcome-settle-ABORT",
    "outcome-settle-IGNORE",
    "outcome-settle-success-completed",
    "outcome-settle-deadline",
    "outcome-settle-uncertain",
    "outcome-settle-completed",
    "outcome-proof-source",
    "outcome-proof-placement",
    "outcome-proof-empty",
    "outcome-live-pending",
    "outcome-completed-placement",
    "outcome-empty-fence",
    "outcome-completed-pending",
    "outcome-not-executed",
    "outcome-uncertain",
    "outcome-ABORT",
    "outcome-IGNORE",
    "outcome-proof-only",
    "outcome-replacement",
    "outcome-missing-proof",
    "outcome-wrong-proof",
    "outcome-pending-refused",
    "outcome-read-source",
    "outcome-read-key",
    "outcome-read-placement",
    "cancel-fence-track-first",
    "cancel-fence-cancel-first",
    "cancel-fence-track-first-ABORT",
    "cancel-fence-track-first-IGNORE",
    "cancel-fence-cancel-first-ABORT",
    "cancel-fence-cancel-first-IGNORE",
    "cancel-fence-unbound",
    "cancel-fence-existing",
    "proof-exact",
    "proof-pending",
    "proof-placement",
    "proof-empty",
    "proof-fault",
    "proof-source",
    "proof-binding",
    "proof-read-key",
    "proof-read-source",
    "proof-read-binding",
    "proof-no-intent",
    "proof-no-track",
    "proof-terminal",
    "proof-retire",
    "fence-exact",
    "fence-join",
    "fence-completed",
    "fence-retry",
    "fence-late",
    "fence-missing",
    "fence-identity",
    "fence-tracking-source",
    "fence-tracking-kind",
    "fence-tracking-effect",
    "fence-tracking-url",
    "fence-replay-source",
    "fence-replay-binding",
    "fence-fault",
    "fence-read-source",
    "fence-read-binding",
    "fence-read-key",
    "fence-deadline",
    "fence-deadline-fault",
    "life-exact",
    "life-completed",
    "life-retry",
    "life-input",
    "life-url",
    "life-hash",
    "life-provider",
    "life-worker",
    "life-closed",
    "life-envelope",
    "life-identity",
    "life-replacement",
    "life-source",
    "life-key",
    "life-fault",
    "life-read-source",
    "life-read-key",
    "life-read-binding",
    "life-read-effect",
    "life-read-url",
    "life-read-envelope",
    "recover-pending",
    "recover-legacy",
    "recover-kind",
    "recover-provider",
    "handoff-exact",
    "handoff-forged",
    "handoff-bodyhash",
    "handoff-effect-status",
    "handoff-kind",
    "handoff-run-missing",
    "handoff-run-closed",
    "handoff-provider",
    "handoff-http",
    "handoff-instance",
    "handoff-stale",
    "handoff-input",
    "handoff-body",
    "handoff-url",
    "handoff-envelope",
    "handoff-worker",
    "exact",
    "read-due",
    "read-latest",
    "read-source",
    "read-input",
    "read-metadata",
    "read-protocol",
    "read-run",
    "read-retry",
    "past",
    "input",
    "changed-input-before-schedule",
    "changed-dispatch-plan",
    "replacement",
    "run",
    "provider",
    "closed",
    "missing-envelope",
    "foreign-source",
    "foreign-key",
    "fault",
];

pub(crate) fn prepared<S: RuntimeStore>(
    store: &mut S,
    mutate: impl Fn(&str),
) -> (String, String, String) {
    prepared_at(store, mutate, "http://executor/exec")
}

pub(crate) fn prepared_at<S: RuntimeStore>(
    store: &mut S,
    mutate: impl Fn(&str),
    executor_url: &str,
) -> (String, String, String) {
    let instance = crate::exec_settlement_retention_tests::setup_with_key(store, true);
    let selected = whipplescript_kernel::exec_invocation::Invocation {
        instance_id: instance.clone(),
        effect_id: "observe".into(),
        attempt_admission_event_id: None,
    };
    let run = selected.run_id();
    let envelope = whipplescript_kernel::exec_invocation::Envelope::new(
        selected.clone(),
        serde_json::json!({"protocol":"whip-executor/1", "effect_id":"observe"}),
    )
    .unwrap();
    let invocation = serde_json::to_string(&envelope).unwrap();
    let request = whipplescript_kernel::sansio::HttpRequest {
        url: executor_url.into(),
        headers: vec![],
        body: envelope.dispatch(&selected).unwrap().clone(),
    };
    let plan = whipplescript_kernel::exec_http::ExecDispatchPlan::prepare(
        "script.observer",
        "hash",
        &serde_json::json!({}),
        &request,
        "epoch",
        None,
        None,
    );
    let metadata = serde_json::json!({"executor_invocation":envelope, "executor_dispatch":plan, "executor_url":executor_url})
        .to_string()
        .replace('\'', "''");
    mutate(&format!("UPDATE runs SET metadata_json = '{metadata}'"));
    (instance, run, invocation)
}

fn close_tracked<S: RuntimeStore>(store: &mut S, instance: &str, run: &str) {
    store
        .ensure_exec_fence(exec_lifetime::Fence {
            instance_id: instance,
            run_id: run,
            reason: exec_lifetime::FenceReason::Retry,
        })
        .unwrap();
    let original = whipplescript_kernel::exec_lifetime::tracked(store, instance)
        .unwrap()
        .remove(run)
        .unwrap();
    let closure = serde_json::json!({"placement":{"protocol":"whipplescript.exec.placement/v2","selected":original.invocation["invocation"],"envelope":original.invocation,"container_id":"owner","dispatch_id":"dispatch"},"lifetime":{"state":"not_admitted","fence_id":"f"}});
    store
        .retain_exec_fence_proof(exec_lifetime::Proof {
            instance_id: instance,
            run_id: run,
            closure_json: &closure.to_string(),
        })
        .unwrap();
}

fn check<S: RuntimeStore>(mut store: S, reopen: impl Fn() -> S, mutate: impl Fn(&str), case: &str) {
    let (instance, run, invocation) = prepared(&mut store, &mutate);
    if case.starts_with("lease-expiry-") {
        mutate("UPDATE leases SET expires_at='2030-01-01T00:00:00Z'");
        if case != "lease-expiry-legacy" {
            store
                .track_exec_lifetime(exec_lifetime::Track {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: &run,
                    input_json: "{}",
                    invocation_json: &invocation,
                    executor_url: "http://executor/exec",
                })
                .unwrap();
        }
        if case == "lease-expiry-existing" {
            store
                .ensure_exec_fence(exec_lifetime::Fence {
                    instance_id: &instance,
                    run_id: &run,
                    reason: exec_lifetime::FenceReason::Cancellation,
                })
                .unwrap();
        }
        let fault = matches!(
            case,
            "lease-expiry-ABORT"
                | "lease-expiry-IGNORE"
                | "lease-expiry-update-IGNORE"
                | "lease-expiry-orphan"
        );
        if case == "lease-expiry-orphan" {
            mutate("UPDATE events SET idempotency_key='orphan-tracking' WHERE event_type='exec.lifetime.tracked'");
        } else if case == "lease-expiry-update-IGNORE" {
            mutate("CREATE TRIGGER fail_expiry BEFORE UPDATE ON leases BEGIN SELECT RAISE(IGNORE); END");
        } else if fault {
            let action = if case.ends_with("IGNORE") {
                "RAISE(IGNORE)"
            } else {
                "RAISE(ABORT,'expiry fence fault')"
            };
            mutate(&format!("CREATE TRIGGER fail_expiry BEFORE INSERT ON events WHEN NEW.event_type='exec.fence.requested' BEGIN SELECT {action}; END"));
        }
        let events = store.list_events(&instance).unwrap();
        let runs = store.list_runs(&instance).unwrap();
        let effects = store.list_effects(&instance).unwrap();
        let result = store.expire_leases(&instance, "2030-01-02T00:00:00Z");
        if fault {
            assert!(result.is_err(), "{case}");
            assert_eq!(store.list_events(&instance).unwrap(), events, "{case}");
            assert_eq!(store.list_runs(&instance).unwrap(), runs, "{case}");
            assert_eq!(store.list_effects(&instance).unwrap(), effects, "{case}");
            if case == "lease-expiry-orphan" {
                mutate("UPDATE events SET idempotency_key=json_array('exec.lifetime.tracked',json_extract(payload_json,'$.run_id')) WHERE event_type='exec.lifetime.tracked'");
            } else {
                mutate("DROP TRIGGER fail_expiry");
            }
            assert_eq!(
                store
                    .expire_leases(&instance, "2030-01-02T00:00:00Z")
                    .unwrap()
                    .len(),
                1,
                "{case} could not recover its original lease"
            );
            assert_eq!(store.list_runs(&instance).unwrap()[0].status, "running");
            return;
        }
        assert_eq!(result.unwrap().len(), 1);
        assert_eq!(store.list_runs(&instance).unwrap()[0].status, "running");
        assert_eq!(store.list_effects(&instance).unwrap()[0].status, "running");
        assert!(store
            .start_run_for_admission(
                RunStart {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: "replacement-after-expiry",
                    provider: "exec",
                    worker_id: "whip-exec",
                    lease_id: "replacement-after-expiry",
                    lease_expires_at: "2040-01-01T00:00:00Z",
                    metadata_json: "{}"
                },
                None
            )
            .is_err());
        assert_eq!(store.list_runs(&instance).unwrap().len(), 1);
        let fences = whipplescript_kernel::exec_lifetime::fences(&store, &instance).unwrap();
        if case == "lease-expiry-legacy" {
            assert!(fences.is_empty());
        } else {
            assert!(matches!(
                fences[&run].reason,
                exec_lifetime::FenceReason::Recovery | exec_lifetime::FenceReason::Cancellation
            ));
        }
        assert_eq!(
            store
                .effect_attempt_admission(&instance, "observe")
                .unwrap(),
            None
        );
        assert!(store
            .list_events(&instance)
            .unwrap()
            .iter()
            .any(|e| e.event_type == "exec.lease.expired"));
        let count = store.list_events(&instance).unwrap().len();
        assert!(store
            .expire_leases(&instance, "2030-01-03T00:00:00Z")
            .unwrap()
            .is_empty());
        drop(store);
        let mut cold = reopen();
        cold.rebuild_projections(&instance).unwrap();
        assert_eq!(
            cold.effect_attempt_admission(&instance, "observe").unwrap(),
            None
        );
        assert_eq!(cold.list_runs(&instance).unwrap()[0].status, "running");
        assert_eq!(cold.list_effects(&instance).unwrap()[0].status, "running");
        assert!(cold
            .start_run_for_admission(
                RunStart {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: "replacement-after-replay",
                    provider: "exec",
                    worker_id: "whip-exec",
                    lease_id: "replacement-after-replay",
                    lease_expires_at: "2040-01-01T00:00:00Z",
                    metadata_json: "{}"
                },
                None
            )
            .is_err());
        assert_eq!(cold.list_runs(&instance).unwrap().len(), 1);
        assert_eq!(cold.list_events(&instance).unwrap().len(), count);
        return;
    }
    if case.starts_with("recovery-fence-") {
        store
            .track_exec_lifetime(exec_lifetime::Track {
                instance_id: &instance,
                effect_id: "observe",
                run_id: &run,
                input_json: "{}",
                invocation_json: &invocation,
                executor_url: "http://executor/exec",
            })
            .unwrap();
        if case.ends_with("existing") {
            store
                .ensure_exec_fence(exec_lifetime::Fence {
                    instance_id: &instance,
                    run_id: &run,
                    reason: exec_lifetime::FenceReason::Cancellation,
                })
                .unwrap();
        }
        let before = store.list_events(&instance).unwrap();
        let runs = store.list_runs(&instance).unwrap();
        let effects = store.list_effects(&instance).unwrap();
        let fault = case.ends_with("ABORT") || case.ends_with("IGNORE");
        if fault {
            let action = if case.ends_with("IGNORE") {
                "RAISE(IGNORE)"
            } else {
                "RAISE(ABORT,'recovery fence fault')"
            };
            mutate(&format!("CREATE TRIGGER fail_recovery_fence BEFORE INSERT ON events WHEN NEW.event_type='exec.fence.requested' BEGIN SELECT {action}; END"));
            let mut kernel = whipplescript_kernel::RuntimeKernel::new(store);
            assert!(kernel.recover_running_provider_runs(&instance).is_err());
            assert_eq!(kernel.store().list_events(&instance).unwrap(), before);
            store = kernel.into_store();
            mutate("DROP TRIGGER fail_recovery_fence");
        }
        drop(store);
        let mut kernel = whipplescript_kernel::RuntimeKernel::new(reopen());
        assert!(kernel
            .recover_running_provider_runs(&instance)
            .unwrap()
            .is_empty());
        let intents =
            whipplescript_kernel::exec_lifetime::fences(kernel.store(), &instance).unwrap();
        assert_eq!(intents.len(), 1);
        if case.ends_with("existing") {
            assert!(matches!(
                intents[&run].reason,
                exec_lifetime::FenceReason::Cancellation
            ));
        } else {
            assert!(matches!(
                intents[&run].reason,
                exec_lifetime::FenceReason::Recovery
            ));
        }
        assert_eq!(
            whipplescript_kernel::exec_lifetime::commands(kernel.store())
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let retained = kernel.store().list_events(&instance).unwrap();
        drop(kernel);
        let mut kernel = whipplescript_kernel::RuntimeKernel::new(reopen());
        assert!(kernel
            .recover_running_provider_runs(&instance)
            .unwrap()
            .is_empty());
        assert_eq!(kernel.store().list_events(&instance).unwrap(), retained);
        assert_eq!(kernel.store().list_runs(&instance).unwrap(), runs);
        assert_eq!(kernel.store().list_effects(&instance).unwrap(), effects);
        return;
    }
    if case.starts_with("retry-") {
        store
            .track_exec_lifetime(exec_lifetime::Track {
                instance_id: &instance,
                effect_id: "observe",
                run_id: &run,
                input_json: "{}",
                invocation_json: &invocation,
                executor_url: "http://executor/exec",
            })
            .unwrap();
        store
            .complete_effect(EffectCompletion {
                instance_id: &instance,
                effect_id: "observe",
                run_id: &run,
                provider: "exec",
                worker_id: "whip-exec",
                status: "failed",
                exit_code: Some(1),
                summary: Some("original"),
                metadata_json: "{}",
                idempotency_key: Some("retry-terminal"),
            })
            .unwrap();
        let request = RetryEffect {
            instance_id: &instance,
            effect_id: "observe",
            retry_after: None,
            idempotency_key: Some("retry-command"),
        };
        if case == "retry-pending" {
            let mut kernel = whipplescript_kernel::RuntimeKernel::new(store);
            assert!(kernel.retry_effect(request).is_err());
            store = kernel.into_store();
            assert!(matches!(
                whipplescript_kernel::exec_lifetime::fences(&store, &instance).unwrap()[&run]
                    .reason,
                exec_lifetime::FenceReason::Retry
            ));
            assert_eq!(store.list_effects(&instance).unwrap()[0].status, "failed");
            assert!(store
                .event_by_idempotency_key(&instance, "retry-command")
                .unwrap()
                .is_none());
        }
        if case != "retry-missing-intent" {
            close_tracked(&mut store, &instance, &run);
        }
        match case {
            "retry-proof-empty" => mutate("UPDATE events SET event_id='' WHERE event_type='exec.fence.proved'"),
            "retry-foreign-effect" => mutate("UPDATE events SET payload_json=replace(payload_json,'observe','foreign') WHERE event_type IN ('exec.lifetime.tracked','exec.fence.requested','exec.fence.proved')"),
            "retry-proof-source" => mutate("UPDATE events SET source='external' WHERE event_type='exec.fence.proved'"),
            "retry-proof-key" => mutate("UPDATE events SET idempotency_key='other' WHERE event_type='exec.fence.proved'"),
            "retry-tracking-key" => mutate("UPDATE events SET idempotency_key='other' WHERE event_type='exec.lifetime.tracked'"),
            "retry-proof-binding" => mutate("UPDATE events SET payload_json=json_set(payload_json,'$.tracking_event_id','other') WHERE event_type='exec.fence.proved'"),
            _ => {}
        }
        drop(store);
        let mut cold = reopen();
        let before = cold.list_events(&instance).unwrap();
        let admitted = cold.retry_effect(request);
        if matches!(case, "retry-closure" | "retry-pending") {
            let admitted = admitted.unwrap();
            assert_eq!(cold.list_effects(&instance).unwrap()[0].status, "queued");
            assert_eq!(cold.retry_effect(request).unwrap(), admitted);
        } else {
            assert!(admitted.is_err(), "{case}");
            assert_eq!(cold.list_events(&instance).unwrap(), before);
            assert_eq!(cold.list_effects(&instance).unwrap()[0].status, "failed");
        }
        return;
    }
    if case.starts_with("outcome-") {
        use whipplescript_kernel::exec_lifetime as reader;
        store
            .track_exec_lifetime(exec_lifetime::Track {
                instance_id: &instance,
                effect_id: "observe",
                run_id: &run,
                input_json: "{}",
                invocation_json: &invocation,
                executor_url: "http://executor/exec",
            })
            .unwrap();
        store
            .ensure_exec_fence(exec_lifetime::Fence {
                instance_id: &instance,
                run_id: &run,
                reason: if case == "outcome-settle-deadline" {
                    exec_lifetime::FenceReason::Deadline
                } else {
                    exec_lifetime::FenceReason::Cancellation
                },
            })
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&invocation).unwrap();
        let placement = serde_json::json!({"protocol":"whipplescript.exec.placement/v2","selected":envelope["invocation"],"envelope":envelope,"container_id":"owner","dispatch_id":"dispatch"});
        let completed = case.contains("completed") || case.ends_with("replacement");
        let lifetime = if completed {
            serde_json::json!({"state":"pending"})
        } else if case.ends_with("uncertain") || case.ends_with("wrong-proof") {
            serde_json::json!({"state":"terminated","incarnation":"process","fence_id":"f","barrier_id":"b"})
        } else {
            serde_json::json!({"state":"not_admitted","fence_id":"f"})
        };
        let outcome = if completed {
            serde_json::json!({"state":"completed","status":200,"body":{"original":"result"}})
        } else if case.ends_with("uncertain") {
            serde_json::json!({"state":"uncertain"})
        } else {
            serde_json::json!({"state":"not_executed"})
        };
        let mut view = serde_json::json!({"protocol":"whipplescript.exec.resolution/v1","selected":envelope["invocation"],"placement":placement,"lifetime":lifetime,"outcome":outcome});
        if case == "outcome-settle-success-completed" {
            view["outcome"]["body"] = serde_json::json!({"protocol":"whip-executor/1","effect_id":"observe","exit_code":0,"stdout":"{}","stderr":""});
        }
        if case == "outcome-live-pending" {
            view["lifetime"] = serde_json::json!({"state":"pending"});
            view["outcome"] = serde_json::json!({"state":"pending"});
            let before = store.list_events(&instance).unwrap();
            assert!(!reader::observe(&mut store, &instance, &run, &view.to_string()).unwrap());
            assert_eq!(store.list_events(&instance).unwrap(), before);
            assert_eq!(
                reader::commands(&reopen())
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            return;
        }
        if matches!(case, "outcome-completed-placement" | "outcome-empty-fence") {
            let mut requested = placement.clone();
            if case.ends_with("placement") {
                requested["envelope"]["invocation"]["instance_id"] = serde_json::json!("foreign");
            } else {
                mutate("UPDATE events SET event_id='' WHERE event_type='exec.fence.requested'");
            }
            let before = store.list_events(&instance).unwrap();
            assert!(
                store
                    .retain_exec_outcome(exec_outcome::Retention {
                        instance_id: &instance,
                        run_id: &run,
                        placement_json: &requested.to_string(),
                        outcome_json:
                            &serde_json::json!({"state":"completed","status":200,"body":{}})
                                .to_string()
                    })
                    .is_err(),
                "{case}"
            );
            assert_eq!(store.list_events(&instance).unwrap(), before);
            return;
        }
        if matches!(
            case,
            "outcome-missing-proof"
                | "outcome-wrong-proof"
                | "outcome-pending-refused"
                | "outcome-proof-source"
                | "outcome-proof-placement"
                | "outcome-proof-empty"
        ) {
            if case.ends_with("wrong-proof") || case.starts_with("outcome-proof-") {
                let mut proof_placement = placement.clone();
                if case.ends_with("placement") {
                    proof_placement["container_id"] = serde_json::json!("other-owner");
                }
                store
                    .retain_exec_fence_proof(exec_lifetime::Proof {
                        instance_id: &instance,
                        run_id: &run,
                        closure_json:
                            &serde_json::json!({"placement":proof_placement,"lifetime":lifetime})
                                .to_string(),
                    })
                    .unwrap();
            }
            if case == "outcome-proof-source" {
                mutate("UPDATE events SET source='external' WHERE event_type='exec.fence.proved'");
            }
            if case == "outcome-proof-empty" {
                mutate("UPDATE events SET event_id='' WHERE event_type='exec.fence.proved'");
            }
            let before = store.list_events(&instance).unwrap();
            let requested = if case.ends_with("pending-refused") {
                serde_json::json!({"state":"pending"})
            } else {
                outcome
            };
            assert!(
                store
                    .retain_exec_outcome(exec_outcome::Retention {
                        instance_id: &instance,
                        run_id: &run,
                        placement_json: &placement.to_string(),
                        outcome_json: &requested.to_string()
                    })
                    .is_err(),
                "{case}"
            );
            assert_eq!(store.list_events(&instance).unwrap(), before);
            return;
        }
        if case.ends_with("proof-only") {
            store
                .retain_exec_fence_proof(exec_lifetime::Proof {
                    instance_id: &instance,
                    run_id: &run,
                    closure_json: &serde_json::json!({"placement":placement,"lifetime":lifetime})
                        .to_string(),
                })
                .unwrap();
            assert_eq!(
                reader::commands(&reopen())
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                1,
                "proof alone must keep outcome custody pending"
            );
        }
        let fault = case
            .rsplit('-')
            .next()
            .filter(|v| matches!(*v, "ABORT" | "IGNORE"));
        if let Some(fault) = fault {
            let action = if fault == "IGNORE" {
                "RAISE(IGNORE)"
            } else {
                "RAISE(ABORT, 'injected outcome failure')"
            };
            mutate(&format!("CREATE TRIGGER fail_outcome BEFORE INSERT ON events WHEN NEW.event_type='exec.outcome.observed' BEGIN SELECT {action}; END"));
            assert!(
                reader::observe(&mut store, &instance, &run, &view.to_string()).is_err(),
                "{case}"
            );
            assert_eq!(reader::proofs(&reopen(), &instance).unwrap().len(), 1);
            assert!(reader::outcomes(&reopen(), &instance).unwrap().is_empty());
            assert_eq!(
                reader::commands(&reopen())
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            mutate("DROP TRIGGER fail_outcome");
        }
        assert_eq!(
            reader::observe(&mut store, &instance, &run, &view.to_string()).unwrap(),
            !completed
        );
        if case.starts_with("outcome-settle-") {
            use whipplescript_kernel::{exec_outcome_settlement, RuntimeKernel};
            assert!(exec_outcome_settlement::pending(&store).unwrap());
            if matches!(case, "outcome-settle-ABORT" | "outcome-settle-IGNORE") {
                let action = if case.ends_with("IGNORE") {
                    "RAISE(IGNORE)"
                } else {
                    "RAISE(ABORT, 'injected settlement failure')"
                };
                mutate(&format!("CREATE TRIGGER fail_settlement BEFORE INSERT ON facts BEGIN SELECT {action}; END"));
                let mut kernel = RuntimeKernel::new(store);
                assert!(exec_outcome_settlement::settle_instance(&mut kernel, &instance).is_err());
                store = kernel.into_store();
                assert_eq!(store.list_runs(&instance).unwrap()[0].status, "running");
                assert!(exec_outcome_settlement::pending(&store).unwrap());
                assert!(reader::commands(&store)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .is_empty());
                mutate("DROP TRIGGER fail_settlement");
            }
            drop(store);
            let mut kernel = RuntimeKernel::new(reopen());
            assert_eq!(
                exec_outcome_settlement::settle_instance(&mut kernel, &instance)
                    .unwrap()
                    .len(),
                1
            );
            let cold = kernel.into_store();
            let expected = if case == "outcome-settle-success-completed" {
                "completed"
            } else if case == "outcome-settle-deadline" {
                "timed_out"
            } else if completed {
                "failed"
            } else if case.ends_with("uncertain") {
                "uncertain"
            } else {
                "cancelled"
            };
            assert_eq!(cold.list_runs(&instance).unwrap()[0].status, expected);
            assert!(!exec_outcome_settlement::pending(&cold).unwrap());
            let before = cold.list_events(&instance).unwrap();
            drop(cold);
            let mut kernel = RuntimeKernel::new(reopen());
            assert!(
                exec_outcome_settlement::settle_instance(&mut kernel, &instance)
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(kernel.store().list_events(&instance).unwrap(), before);
            assert_eq!(
                reader::commands(kernel.store())
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                usize::from(completed)
            );
            return;
        }
        let original =
            serde_json::to_value(&reader::outcomes(&store, &instance).unwrap()[&run]).unwrap();
        if completed {
            assert!(reader::proofs(&store, &instance).unwrap().is_empty());
            assert_eq!(
                reader::commands(&store).unwrap().as_array().unwrap().len(),
                1
            );
            if case.ends_with("replacement") {
                view["outcome"]["body"] = serde_json::json!({"changed":true});
                let before = store.list_events(&instance).unwrap();
                assert!(reader::observe(&mut store, &instance, &run, &view.to_string()).is_err());
                assert_eq!(store.list_events(&instance).unwrap(), before);
                return;
            }
            view["lifetime"] = serde_json::json!({"state":"terminated","incarnation":"process","fence_id":"f","barrier_id":"b"});
            assert!(reader::observe(&mut store, &instance, &run, &view.to_string()).unwrap());
            assert_eq!(
                serde_json::to_value(&reader::outcomes(&store, &instance).unwrap()[&run]).unwrap(),
                original
            );
        }
        if case.starts_with("outcome-read-") {
            match case {
                "outcome-read-source"=>mutate("UPDATE events SET source='external' WHERE event_type='exec.outcome.observed'"),
                "outcome-read-key"=>mutate("UPDATE events SET idempotency_key='other' WHERE event_type='exec.outcome.observed'"),
                _=>mutate("UPDATE events SET payload_json=json_set(payload_json,'$.placement.envelope.invocation.instance_id','other') WHERE event_type='exec.outcome.observed'"),
            }
            assert!(reader::commands(&reopen()).is_err(), "{case}");
            return;
        }
        drop(store);
        let mut cold = reopen();
        let before = cold.list_events(&instance).unwrap();
        assert!(reader::observe(&mut cold, &instance, &run, &view.to_string()).unwrap());
        assert_eq!(cold.list_events(&instance).unwrap(), before);
        assert!(reader::commands(&cold)
            .unwrap()
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(cold.list_runs(&instance).unwrap()[0].status, "running");
        return;
    }
    if case.starts_with("cancel-fence-") {
        let track = exec_lifetime::Track {
            instance_id: &instance,
            effect_id: "observe",
            run_id: &run,
            input_json: "{}",
            invocation_json: &invocation,
            executor_url: "http://executor/exec",
        };
        let request = EffectCancellationRequest {
            instance_id: &instance,
            effect_id: "observe",
            revision_id: None,
            reason: Some("stop"),
            requested_by: "operator",
            causation_event_id: None,
            idempotency_key: Some("original-cancel"),
        };
        let track_first = case.contains("track-first") || case.ends_with("existing");
        if track_first {
            store.track_exec_lifetime(track).unwrap();
            if case.ends_with("existing") {
                store
                    .ensure_exec_fence(exec_lifetime::Fence {
                        instance_id: &instance,
                        run_id: &run,
                        reason: exec_lifetime::FenceReason::Deadline,
                    })
                    .unwrap();
            }
        } else {
            if case.ends_with("unbound") {
                mutate("UPDATE runs SET status = 'completed'");
                mutate("INSERT INTO runs (run_id, instance_id, effect_id, provider, worker_id, status) SELECT 'unbound-cancellation-run', instance_id, effect_id, provider, worker_id, 'running' FROM runs LIMIT 1");
            }
            store.request_effect_cancellation(request).unwrap();
            if case.ends_with("unbound") {
                mutate("UPDATE runs SET status = 'running'");
            }
        }
        let before = store.list_events(&instance).unwrap();
        let fault = case
            .rsplit('-')
            .next()
            .filter(|value| matches!(*value, "ABORT" | "IGNORE"));
        if let Some(fault) = fault {
            let action = if fault == "IGNORE" {
                "RAISE(IGNORE)"
            } else {
                "RAISE(ABORT, 'injected fence failure')"
            };
            mutate(&format!("CREATE TRIGGER fail_cancel_fence BEFORE INSERT ON events WHEN NEW.event_type = 'exec.fence.requested' BEGIN SELECT {action}; END"));
        }
        let admitted = if track_first {
            store.request_effect_cancellation(request).map(|_| ())
        } else {
            store.track_exec_lifetime(track).map(|_| ())
        };
        if fault.is_some() {
            assert!(admitted.is_err(), "{case}: fence write failure was ignored");
            assert_eq!(
                store.list_events(&instance).unwrap(),
                before,
                "{case}: partial admission"
            );
            assert_eq!(
                store
                    .list_effect_cancellation_requests(&instance)
                    .unwrap()
                    .len(),
                usize::from(!track_first)
            );
            mutate("DROP TRIGGER fail_cancel_fence");
            if track_first {
                store.request_effect_cancellation(request).unwrap();
            } else {
                store.track_exec_lifetime(track).unwrap();
            }
        } else {
            admitted.unwrap();
        }
        assert_eq!(
            whipplescript_kernel::exec_lifetime::fences(&store, &instance)
                .unwrap()
                .len(),
            usize::from(!case.ends_with("unbound")),
            "{case}: admission omitted fence intent"
        );
        drop(store);
        let mut cold = reopen();
        let before = cold.list_events(&instance).unwrap();
        cold.request_effect_cancellation(request).unwrap();
        cold.track_exec_lifetime(track).unwrap();
        assert_eq!(
            cold.list_events(&instance).unwrap(),
            before,
            "{case}: replay appended new intent"
        );
        let fences = whipplescript_kernel::exec_lifetime::fences(&cold, &instance).unwrap();
        if case.ends_with("unbound") {
            assert!(fences.is_empty(), "unbound run inherited cancellation");
        } else {
            assert_eq!(fences.len(), 1);
            assert_eq!(
                serde_json::to_value(fences[&run].reason).unwrap(),
                serde_json::json!(if case.ends_with("existing") {
                    "deadline"
                } else {
                    "cancellation"
                })
            );
            assert_eq!(
                whipplescript_kernel::exec_lifetime::commands(&cold)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
        assert_eq!(cold.list_runs(&instance).unwrap()[0].status, "running");
        return;
    }
    let mut schedule = exec_reconciliation::Schedule {
        instance_id: &instance,
        effect_id: "observe",
        run_id: &run,
        input_json: "{}",
        invocation_json: &invocation,
        now_epoch_ms: 1000,
        due_epoch_ms: 2000,
    };
    if case.starts_with("proof-") {
        use whipplescript_kernel::{exec_invocation, exec_placement, exec_resolution};
        if case != "proof-no-track" {
            store
                .track_exec_lifetime(exec_lifetime::Track {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: &run,
                    input_json: "{}",
                    invocation_json: &invocation,
                    executor_url: "http://executor/exec",
                })
                .unwrap();
        }
        if !matches!(case, "proof-no-intent" | "proof-no-track" | "proof-retire") {
            store
                .ensure_exec_fence(exec_lifetime::Fence {
                    instance_id: &instance,
                    run_id: &run,
                    reason: exec_lifetime::FenceReason::Deadline,
                })
                .unwrap();
        }
        if case == "proof-retire" {
            whipplescript_kernel::exec_lifetime::retire(&mut store).unwrap();
            whipplescript_kernel::exec_lifetime::retire(&mut store).unwrap();
            assert_eq!(
                whipplescript_kernel::exec_lifetime::commands(&store)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        }
        let env: serde_json::Value = serde_json::from_str(&invocation).unwrap();
        let selected = env["invocation"].to_string();
        let claim: serde_json::Value = serde_json::from_str(
            &exec_invocation::claim_json(&selected, &invocation, None).unwrap(),
        )
        .unwrap();
        let receipt = claim["decision"]["receipt"].to_string();
        let placement = exec_placement::bind_controller_json(
            &selected,
            &invocation,
            &receipt,
            None,
            "container",
            "dispatch",
        )
        .unwrap();
        let response = serde_json::json!({"protocol":"whipplescript.exec.controller.response/v1", "placement":serde_json::from_str::<serde_json::Value>(&placement).unwrap(),
            "action":{"action":"terminated","incarnation":"process","fence_id":"actual-owner-fence","barrier_id":"barrier"}});
        let resolved: serde_json::Value = serde_json::from_str(
            &exec_resolution::transition_json(
                &selected,
                &invocation,
                &receipt,
                &placement,
                None,
                &serde_json::json!({"op":"observe","response":response}).to_string(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut closure: serde_json::Value = serde_json::from_str(
            &exec_resolution::closure_json(&selected, &invocation, &resolved["view"].to_string())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        match case {
            "proof-pending" => closure["lifetime"] = serde_json::json!({"state":"pending"}),
            "proof-placement" => closure["placement"]["envelope"]["invocation"]["effect_id"] = serde_json::json!("other"),
            "proof-empty" => closure["lifetime"]["barrier_id"] = serde_json::json!(""),
            "proof-fault" => mutate("CREATE TRIGGER fail_proof BEFORE INSERT ON events WHEN NEW.event_type='exec.fence.proved' BEGIN SELECT RAISE(ABORT,'proof fault'); END"),
            "proof-terminal" => { mutate("UPDATE instances SET status='completed'"); mutate("UPDATE runs SET status='completed', metadata_json='{}'"); },
            _ => {}
        }
        let closure = closure.to_string();
        let request = exec_lifetime::Proof {
            instance_id: &instance,
            run_id: &run,
            closure_json: &closure,
        };
        let replay =
            matches!(case, "proof-source" | "proof-binding") || case.starts_with("proof-read-");
        if replay {
            store.retain_exec_fence_proof(request).unwrap();
        }
        match case {
            "proof-source" | "proof-read-source" => mutate("UPDATE events SET source='external' WHERE event_type='exec.fence.proved'"),
            "proof-binding" | "proof-read-binding" => mutate("UPDATE events SET payload_json=json_set(payload_json,'$.fence_event_id','other') WHERE event_type='exec.fence.proved'"),
            "proof-read-key" => mutate("UPDATE events SET idempotency_key='other' WHERE event_type='exec.fence.proved'"),
            _ => {}
        }
        if case.starts_with("proof-read-") {
            assert!(
                whipplescript_kernel::exec_lifetime::commands(&reopen()).is_err(),
                "{case}"
            );
            return;
        }
        let before = store.list_events(&instance).unwrap();
        let outcome = store.retain_exec_fence_proof(request);
        if matches!(case, "proof-exact" | "proof-terminal" | "proof-retire") {
            let event = outcome.unwrap();
            assert_eq!(store.retain_exec_fence_proof(request).unwrap(), event);
            assert!(whipplescript_kernel::exec_lifetime::observe(
                &mut store,
                &instance,
                &run,
                &resolved["view"].to_string()
            )
            .unwrap());
            let cold = reopen();
            assert_eq!(
                whipplescript_kernel::exec_lifetime::proofs(&cold, &instance)
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                whipplescript_kernel::exec_lifetime::commands(&cold).unwrap(),
                serde_json::json!([])
            );
        } else {
            assert!(outcome.is_err(), "{case}");
            assert_eq!(store.list_events(&instance).unwrap(), before, "{case}");
            if case == "proof-fault" {
                assert!(whipplescript_kernel::exec_lifetime::observe(
                    &mut store,
                    &instance,
                    &run,
                    &resolved["view"].to_string()
                )
                .is_err());
            }
        }
        return;
    }
    if case.starts_with("fence-") {
        if case != "fence-missing" {
            store
                .track_exec_lifetime(exec_lifetime::Track {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: &run,
                    input_json: "{}",
                    invocation_json: &invocation,
                    executor_url: "http://executor/exec",
                })
                .unwrap();
        }
        let mut request = exec_lifetime::Fence {
            instance_id: &instance,
            run_id: &run,
            reason: exec_lifetime::FenceReason::Deadline,
        };
        if case.starts_with("fence-deadline") {
            mutate("UPDATE effects SET timeout_seconds = 1, created_at = '2020-01-01T00:00:00Z'");
            let before = store.list_events(&instance).unwrap();
            if case == "fence-deadline-fault" {
                mutate("CREATE TRIGGER fail_deadline_fence BEFORE INSERT ON events WHEN NEW.event_type = 'exec.fence.requested' BEGIN SELECT RAISE(ABORT,'deadline fence fault'); END");
            }
            let mut kernel = whipplescript_kernel::RuntimeKernel::new(store);
            let outcome = whipplescript_kernel::time_pass::resolve_due_time_effects(
                &mut kernel,
                &instance,
                "2020-01-01T00:00:02Z",
            );
            if case == "fence-deadline-fault" {
                assert!(outcome.is_err());
                assert_eq!(kernel.store().list_events(&instance).unwrap(), before);
                assert_eq!(
                    kernel.store().list_runs(&instance).unwrap()[0].status,
                    "running"
                );
                mutate("DROP TRIGGER fail_deadline_fence");
                whipplescript_kernel::time_pass::resolve_due_time_effects(
                    &mut kernel,
                    &instance,
                    "2020-01-01T00:00:02Z",
                )
                .unwrap();
            } else {
                assert_eq!(outcome.unwrap().deadlines_expired, 1);
            }
            let events = kernel.store().list_events(&instance).unwrap();
            let fence = events
                .iter()
                .find(|e| e.event_type == exec_lifetime::FENCE_EVENT)
                .unwrap();
            let terminal = events
                .iter()
                .find(|e| e.event_type == "effect.terminal")
                .unwrap();
            assert!(fence.sequence < terminal.sequence);
            assert_eq!(
                kernel.store().list_runs(&instance).unwrap()[0].status,
                "timed_out"
            );
            drop(kernel);
            let fences = whipplescript_kernel::exec_lifetime::fences(&reopen(), &instance).unwrap();
            assert_eq!(fences.len(), 1);
            assert_eq!(fences[&run].fence_id, request.key());
            return;
        }
        let retained = matches!(
            case,
            "fence-exact"
                | "fence-join"
                | "fence-completed"
                | "fence-retry"
                | "fence-replay-source"
                | "fence-replay-binding"
        ) || case.starts_with("fence-read-");
        let original = retained.then(|| store.ensure_exec_fence(request).unwrap());
        match case {
            "fence-identity" => request.run_id = "",
            "fence-join" => request.reason = exec_lifetime::FenceReason::Retry,
            "fence-tracking-source" => mutate("UPDATE events SET source='external' WHERE event_type='exec.lifetime.tracked'"),
            "fence-tracking-kind" => mutate("UPDATE events SET event_type='other' WHERE event_type='exec.lifetime.tracked'"),
            "fence-tracking-effect" => mutate("UPDATE events SET payload_json=json_set(payload_json,'$.effect_id',null) WHERE event_type='exec.lifetime.tracked'"),
            "fence-tracking-url" => mutate("UPDATE events SET payload_json=json_set(payload_json,'$.executor_url',null) WHERE event_type='exec.lifetime.tracked'"),
            "fence-replay-source" | "fence-read-source" => mutate("UPDATE events SET source='external' WHERE event_type='exec.fence.requested'"),
            "fence-replay-binding" | "fence-read-binding" => mutate("UPDATE events SET payload_json=json_set(payload_json,'$.tracking_event_id','other') WHERE event_type='exec.fence.requested'"),
            "fence-read-key" => mutate("UPDATE events SET idempotency_key='other' WHERE event_type='exec.fence.requested'"),
            "fence-fault" => mutate("CREATE TRIGGER fail_fence BEFORE INSERT ON events WHEN NEW.event_type = 'exec.fence.requested' BEGIN SELECT RAISE(ABORT,'fence fault'); END"),
            "fence-completed" | "fence-retry" | "fence-late" => {
                store.complete_effect(EffectCompletion { instance_id:&instance, effect_id:"observe", run_id:&run, provider:"exec", worker_id:"whip-exec",
                    status:"failed", exit_code:Some(1), summary:Some("retained result"), metadata_json:"{}", idempotency_key:Some("fence-terminal") }).unwrap();
                if case == "fence-retry" { close_tracked(&mut store,&instance,&run); store.retry_effect(RetryEffect { instance_id:&instance, effect_id:"observe", retry_after:None, idempotency_key:Some("fence-retry") }).unwrap(); }
            }
            _=>{}
        }
        if case.starts_with("fence-read-") {
            assert!(whipplescript_kernel::exec_lifetime::fences(&reopen(), &instance).is_err());
            return;
        }
        let before = store.list_events(&instance).unwrap();
        let outcome = store.ensure_exec_fence(request);
        if matches!(
            case,
            "fence-exact" | "fence-join" | "fence-completed" | "fence-retry" | "fence-late"
        ) {
            let outcome = outcome.unwrap();
            if case != "fence-late" {
                assert_eq!(Some(outcome), original);
                assert_eq!(store.list_events(&instance).unwrap(), before);
            }
            drop(store);
            let fences = whipplescript_kernel::exec_lifetime::fences(&reopen(), &instance).unwrap();
            assert_eq!(fences.len(), 1);
            assert_eq!(fences[&run].fence_id, request.key());
            assert!(matches!(
                fences[&run].reason,
                exec_lifetime::FenceReason::Deadline
            ));
        } else {
            assert!(outcome.is_err(), "{case}");
            assert_eq!(store.list_events(&instance).unwrap(), before, "{case}");
        }
        return;
    }
    if case.starts_with("life-") {
        let mut request = exec_lifetime::Track {
            instance_id: &instance,
            effect_id: "observe",
            run_id: &run,
            input_json: "{}",
            invocation_json: &invocation,
            executor_url: "http://executor/exec",
        };
        let retained = matches!(
            case,
            "life-exact"
                | "life-completed"
                | "life-retry"
                | "life-replacement"
                | "life-source"
                | "life-key"
        ) || case.starts_with("life-read-");
        let original = retained.then(|| store.track_exec_lifetime(request).unwrap());
        match case {
            "life-input" => request.input_json = "{\"different\":true}",
            "life-url" => request.executor_url = "http://other/exec",
            "life-identity" => request.run_id = "other",
            "life-envelope" => request.invocation_json = "{}",
            "life-replacement" => request.executor_url = "http://replacement/exec",
            "life-hash" => mutate("UPDATE runs SET metadata_json = json_set(metadata_json, '$.executor_dispatch.request_sha256', 'changed')"),
            "life-provider" => mutate("UPDATE runs SET provider = 'other'"),
            "life-worker" => mutate("UPDATE runs SET worker_id = 'other'"),
            "life-closed" => mutate("UPDATE runs SET status = 'completed'"),
            "life-source" | "life-read-source" => mutate("UPDATE events SET source = 'external' WHERE event_type = 'exec.lifetime.tracked'"),
            "life-key" => mutate("UPDATE events SET event_type = 'other' WHERE event_type = 'exec.lifetime.tracked'"),
            "life-read-key" => mutate("UPDATE events SET idempotency_key = 'other' WHERE event_type = 'exec.lifetime.tracked'"),
            "life-read-binding" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.run_id', 'changed') WHERE event_type = 'exec.lifetime.tracked'"),
            "life-read-effect" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.effect_id', 'changed') WHERE event_type = 'exec.lifetime.tracked'"),
            "life-read-url" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.executor_url', '') WHERE event_type = 'exec.lifetime.tracked'"),
            "life-read-envelope" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.invocation.dispatch.effect_id', 'changed') WHERE event_type = 'exec.lifetime.tracked'"),
            "life-fault" => mutate("CREATE TRIGGER fail_lifetime BEFORE INSERT ON events WHEN NEW.event_type = 'exec.lifetime.tracked' BEGIN SELECT RAISE(ABORT,'lifetime fault'); END"),
            "life-completed" | "life-retry" => {
                store.complete_effect(EffectCompletion {
                    instance_id: &instance, effect_id: "observe", run_id: &run, provider: "exec", worker_id: "whip-exec",
                    status: "failed", exit_code: Some(1), summary: Some("original output"), metadata_json: "{}", idempotency_key: Some("life-terminal"),
                }).unwrap();
                if case == "life-retry" {
                    close_tracked(&mut store,&instance,&run);
                    store.retry_effect(RetryEffect { instance_id: &instance, effect_id: "observe", retry_after: None, idempotency_key: Some("life-retry") }).unwrap();
                }
            }
            _ => {}
        }
        if case.starts_with("life-read-") {
            assert!(whipplescript_kernel::exec_lifetime::tracked(&reopen(), &instance).is_err());
            return;
        }
        let before = store.list_events(&instance).unwrap();
        let outcome = store.track_exec_lifetime(request);
        assert_eq!(
            store.list_events(&instance).unwrap(),
            before,
            "{case}: changed journal"
        );
        if matches!(case, "life-exact" | "life-completed" | "life-retry") {
            assert_eq!(Some(outcome.unwrap()), original);
            drop(store);
            let tracked =
                whipplescript_kernel::exec_lifetime::tracked(&reopen(), &instance).unwrap();
            assert_eq!(tracked.len(), 1);
            assert_eq!(
                tracked[&run].invocation,
                serde_json::from_str::<serde_json::Value>(&invocation).unwrap()
            );
            assert_eq!(tracked[&run].executor_url, "http://executor/exec");
        } else {
            assert!(outcome.is_err(), "{case}: invalid tracking accepted");
        }
        return;
    }
    if case.starts_with("recover-") {
        store.schedule_exec_reconciliation(schedule).unwrap();
        match case {
            "recover-legacy" => mutate("UPDATE runs SET metadata_json = '{}'"),
            "recover-kind" => mutate("UPDATE effects SET kind = 'other'"),
            "recover-provider" => mutate("UPDATE runs SET provider = 'other'"),
            _ => {}
        }
        let before = store.list_events(&instance).unwrap();
        let effects = store.list_effects(&instance).unwrap();
        let runs = store.list_runs(&instance).unwrap();
        drop(store);
        for _ in 0..2 {
            let mut kernel = whipplescript_kernel::RuntimeKernel::new(reopen());
            assert!(kernel
                .recover_running_provider_runs(&instance)
                .unwrap()
                .is_empty());
            assert_eq!(
                kernel.store().list_events(&instance).unwrap(),
                before,
                "{case}"
            );
            assert_eq!(
                kernel.store().list_effects(&instance).unwrap(),
                effects,
                "{case}"
            );
            assert_eq!(kernel.store().list_runs(&instance).unwrap(), runs, "{case}");
            if case == "recover-pending" {
                let wakes =
                    whipplescript_kernel::exec_reconciliation::pending(kernel.store(), &instance)
                        .unwrap();
                assert_eq!(wakes.get(&run).unwrap().due_epoch_ms, 2000);
            }
        }
        return;
    }
    if case.starts_with("handoff-") {
        let mut effect = ClaimableEffect {
            effect_id: "observe".into(),
            kind: "exec.command".into(),
            target: None,
            profile: None,
            input_json: "{}".into(),
            required_capabilities_json: "[\"script.observer\"]".into(),
            declared_profiles_json: "[]".into(),
            attempt_admission_event_id: store
                .effect_attempt_admission(&instance, "observe")
                .unwrap(),
        };
        let envelope: serde_json::Value = serde_json::from_str(&invocation).unwrap();
        let mut request = whipplescript_kernel::sansio::HttpRequest {
            url: "http://executor/exec".into(),
            headers: vec![],
            body: envelope["dispatch"].clone(),
        };
        match case {
            "handoff-http" | "handoff-forged" => effect.kind = "http.request".into(),
            "handoff-stale" => effect.attempt_admission_event_id = Some("old-admission".into()),
            "handoff-input" => effect.input_json = "{\"changed\":true}".into(),
            "handoff-body" => request.body["changed"] = true.into(),
            "handoff-url" => request.url = "http://other/exec".into(),
            "handoff-envelope" => mutate("UPDATE runs SET metadata_json = json_remove(metadata_json, '$.executor_invocation')"),
            "handoff-worker" => mutate("UPDATE runs SET worker_id = 'other'"),
            "handoff-bodyhash" => mutate("UPDATE runs SET metadata_json = json_set(metadata_json, '$.executor_dispatch.request_body_sha256', 'other')"),
            "handoff-effect-status" => mutate("UPDATE effects SET status = 'queued'"),
            "handoff-kind" => mutate("UPDATE effects SET kind = 'http.request'"),
            "handoff-run-missing" => {
                mutate("DELETE FROM leases");
                mutate("DELETE FROM runs");
            }
            "handoff-run-closed" => mutate("UPDATE runs SET status = 'completed'"),
            "handoff-provider" => mutate("UPDATE runs SET provider = 'other'"),
            _ => {}
        }
        // A forged but well-formed envelope in generic HTTP cannot grant access.
        if case == "handoff-forged" {
            request.body = envelope.clone();
        }
        let before = store.list_events(&instance).unwrap();
        let result = whipplescript_kernel::exec_handoff::select(
            &store,
            if case == "handoff-instance" {
                "foreign"
            } else {
                &instance
            },
            &effect,
            request,
        );
        if case == "handoff-exact" {
            let handoff = result.unwrap();
            assert_eq!(handoff.command()["envelope"], envelope);
            assert_eq!(handoff.command()["selected"]["instance_id"], instance);
            assert_eq!(handoff.request().url, "http://executor/exec");
        } else {
            assert!(result.is_err(), "{case}");
        }
        assert_eq!(store.list_events(&instance).unwrap(), before);
        return;
    }
    match case {
        "past" => schedule.due_epoch_ms = 1000,
        "input" => schedule.input_json = "{\"changed\":true}",
        "changed-input-before-schedule" => {
            mutate("UPDATE effects SET input_json = '{\"changed\":true}'");
            schedule.input_json = "{\"changed\":true}";
        }
        "changed-dispatch-plan" => mutate("UPDATE runs SET metadata_json = json_set(metadata_json, '$.executor_dispatch.request_body_sha256', 'other')"),
        "replacement" => schedule.invocation_json = "{\"replacement\":true}",
        "run" => schedule.run_id = "other",
        "provider" => mutate("UPDATE runs SET provider = 'other'"),
        "closed" => mutate("UPDATE runs SET status = 'completed'"),
        "missing-envelope" => mutate("UPDATE runs SET metadata_json = '{}'"),
        "foreign-source" | "foreign-key" => {
            store.append_event(NewEvent {
                instance_id: &instance,
                event_type: if case == "foreign-key" { "other" } else { exec_reconciliation::EVENT_TYPE },
                payload_json: &schedule.payload().unwrap(),
                source: if case == "foreign-source" { "other" } else { "kernel" },
                causation_id: Some(&run), correlation_id: None, idempotency_key: Some(&schedule.key()),
            }).unwrap();
        }
        "fault" => mutate("CREATE TRIGGER fail_wake AFTER INSERT ON events WHEN NEW.event_type = 'exec.reconciliation.scheduled' BEGIN SELECT RAISE(ABORT, 'injected wake failure'); END"),
        _ => {}
    }
    if case.starts_with("read-") {
        use whipplescript_kernel::exec_reconciliation::{is_ready, pending};
        store.schedule_exec_reconciliation(schedule).unwrap();
        if case == "read-latest" {
            store
                .schedule_exec_reconciliation(exec_reconciliation::Schedule {
                    now_epoch_ms: 2100,
                    due_epoch_ms: 3000,
                    ..schedule
                })
                .unwrap();
        }
        if case == "read-retry" {
            store
                .track_exec_lifetime(exec_lifetime::Track {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: &run,
                    input_json: "{}",
                    invocation_json: &invocation,
                    executor_url: "http://executor/exec",
                })
                .unwrap();
            store
                .complete_effect(EffectCompletion {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: &run,
                    provider: "exec",
                    worker_id: "whip-exec",
                    status: "failed",
                    exit_code: None,
                    summary: None,
                    metadata_json: "{}",
                    idempotency_key: Some("close-old"),
                })
                .unwrap();
            // A `failed` terminal is the worker's account of itself, never
            // knowledge of the target, so it does not license a second
            // dispatch. The closure is what does: `not_admitted` says the
            // provider never took the invocation, so the new attempt has
            // nothing to duplicate.
            close_tracked(&mut store, &instance, &run);
            store
                .retry_effect(RetryEffect {
                    instance_id: &instance,
                    effect_id: "observe",
                    retry_after: None,
                    idempotency_key: Some("explicit-retry"),
                })
                .unwrap();
        }
        drop(store);
        match case {
            "read-source" => mutate("UPDATE events SET source = 'other' WHERE event_type = 'exec.reconciliation.scheduled'"),
            "read-input" => mutate("UPDATE effects SET input_json = '{\"changed\":true}'"),
            "read-metadata" => mutate("UPDATE runs SET metadata_json = '{}'"),
            "read-protocol" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.protocol', 'other') WHERE event_type = 'exec.reconciliation.scheduled'"),
            "read-run" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.run_id', 'other') WHERE event_type = 'exec.reconciliation.scheduled'"),
            _ => {}
        }
        let cold = reopen();
        let before = cold.list_events(&instance).unwrap();
        let result = pending(&cold, &instance);
        if matches!(case, "read-due" | "read-latest") {
            let wakes = result.unwrap();
            let due = if case == "read-latest" { 3000 } else { 2000 };
            assert_eq!(wakes.len(), 1);
            assert_eq!(wakes[&run].due_epoch_ms, due);
            let effect = ClaimableEffect {
                effect_id: "observe".into(),
                kind: "exec.command".into(),
                target: None,
                profile: None,
                input_json: "{}".into(),
                required_capabilities_json: "[]".into(),
                declared_profiles_json: "[]".into(),
                attempt_admission_event_id: None,
            };
            assert!(!is_ready(&effect, &instance, &wakes, due - 1));
            assert!(is_ready(&effect, &instance, &wakes, due));
            let sibling = ClaimableEffect {
                effect_id: "sibling".into(),
                ..effect
            };
            assert!(is_ready(&sibling, &instance, &wakes, due - 1));
        } else if case == "read-retry" {
            assert!(
                result.unwrap().is_empty(),
                "prior wake leaked to a new attempt"
            );
            assert!(cold
                .effect_attempt_admission(&instance, "observe")
                .unwrap()
                .is_some());
        } else {
            assert!(result.is_err(), "{case}: invalid wake accepted");
        }
        assert_eq!(cold.list_events(&instance).unwrap(), before);
        return;
    }
    let before = store.list_events(&instance).unwrap();
    let result = store.schedule_exec_reconciliation(schedule);
    if case == "exact" {
        let event = result.unwrap();
        drop(store);
        let mut cold = reopen();
        assert_eq!(cold.schedule_exec_reconciliation(schedule).unwrap(), event);
        assert_eq!(cold.list_runs(&instance).unwrap()[0].status, "running");
        assert!(cold.list_facts(&instance).unwrap().is_empty());
        assert_eq!(cold.list_events(&instance).unwrap().len(), before.len() + 1);
        let changed = exec_reconciliation::Schedule {
            now_epoch_ms: 999,
            ..schedule
        };
        assert!(cold.schedule_exec_reconciliation(changed).is_err());
    } else {
        assert!(result.is_err(), "{case}: wake accepted");
        assert_eq!(store.list_events(&instance).unwrap(), before);
        if case == "fault" {
            mutate("DROP TRIGGER fail_wake");
            let event = store.schedule_exec_reconciliation(schedule).unwrap();
            assert_eq!(store.schedule_exec_reconciliation(schedule).unwrap(), event);
        }
    }
}

#[test]
fn hosted_exec_reconciliation_schedule() {
    for case in CASES {
        let store = crate::do_store::test_support::store();
        let sql = store.sql.clone();
        check(
            store,
            || crate::do_store::DoSqliteStore::new(sql.clone()),
            |statement| {
                sql.execute(statement, &[]).unwrap();
            },
            case,
        );
    }
}

#[test]
fn native_exec_reconciliation_schedule() {
    let dir = std::env::temp_dir().join(format!(
        "exec-wake-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    for case in CASES {
        let path = dir.join(format!("{case}.sqlite"));
        let store = SqliteStore::open(&path).unwrap();
        let sql = rusqlite::Connection::open(&path).unwrap();
        check(
            store,
            || SqliteStore::open(&path).unwrap(),
            |statement| sql.execute_batch(statement).unwrap(),
            case,
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
