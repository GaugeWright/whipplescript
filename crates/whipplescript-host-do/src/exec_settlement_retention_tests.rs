//! The same immutable returned-outcome contract on both SQLite ports.
use crate::do_store::DoSql;
use crate::rule_commit_recovery_tests::{commit, effect, version};
use whipplescript_store::*;

const CASES: &[&str] = &[
    "exact",
    "closed-replay",
    "replacement",
    "input",
    "run",
    "effect",
    "instance",
    "closed",
    "provider",
    "worker",
    "effect-status",
    "kind",
    "foreign-key",
    "foreign-source",
    "malformed",
];

pub(crate) fn setup<S: RuntimeStore>(store: &mut S) -> String {
    setup_with_key(store, false)
}

pub(crate) fn setup_with_key<S: RuntimeStore>(store: &mut S, keyed: bool) -> String {
    let v = store.create_program_version(version("retention")).unwrap();
    let instance = store
        .create_instance(NewInstance {
            program_id: &v.program_id,
            version_id: &v.version_id,
            input_json: "{}",
        })
        .unwrap()
        .instance_id;
    store
        .register_capability_schema(CapabilitySchemaRegistration {
            capability: "script.observer",
            description: "fixture",
            schema_json: "{}",
            registered_by_package_id: None,
        })
        .unwrap();
    store
        .bind_capability(CapabilityBinding {
            binding_id: "observer",
            program_id: Some(&v.program_id),
            capability: "script.observer",
            provider: "builtin-script",
            config_json: "{}",
        })
        .unwrap();
    store
        .commit_rule(commit(&instance, &[effect(None)]))
        .unwrap();
    let run_id = if keyed {
        whipplescript_kernel::execution_attempt_key(&instance, "observe", None, "exec-run")
    } else {
        "run".into()
    };
    store
        .start_run(RunStart {
            run_id: &run_id,
            worker_id: "whip-exec",
            ..crate::run_reattach_tests::request(&instance)
        })
        .unwrap();
    instance
}

fn check<S: RuntimeStore>(mut store: S, case: &str, mutate: impl Fn(&str)) {
    let instance = setup(&mut store);
    let request = exec_settlement::Retention {
        instance_id: &instance,
        effect_id: "observe",
        run_id: "run",
        input_json: "{}",
        settlement_json: r#"{"outcome":"original"}"#,
    };
    let mut altered = request;
    let mut original = None;
    if matches!(
        case,
        "exact" | "closed-replay" | "replacement" | "foreign-key" | "foreign-source"
    ) {
        original = Some(store.retain_exec_settlement(request).unwrap());
    }
    match case {
        "closed-replay" | "closed" => mutate("UPDATE runs SET status = 'completed'"),
        "replacement" => altered.settlement_json = r#"{"outcome":"replacement"}"#,
        "input" => altered.input_json = r#"{"other":1}"#,
        "run" => altered.run_id = "other",
        "effect" => altered.effect_id = "other",
        "instance" => altered.instance_id = "other",
        "provider" => mutate("UPDATE runs SET provider = 'other'"),
        "worker" => mutate("UPDATE runs SET worker_id = 'other'"),
        "effect-status" => mutate("UPDATE effects SET status = 'queued'"),
        "kind" => mutate("UPDATE effects SET kind = 'other'"),
        "foreign-source" => mutate(
            "UPDATE events SET source = 'external' WHERE event_type = 'exec.settlement.retained'",
        ),
        "foreign-key" => mutate(
            "UPDATE events SET event_type = 'other' WHERE event_type = 'exec.settlement.retained'",
        ),
        "malformed" => altered.settlement_json = "{",
        _ => {}
    }
    let before = store.list_events(&instance).unwrap();
    let result = store.retain_exec_settlement(altered);
    if matches!(case, "exact" | "closed-replay") {
        assert_eq!(Some(result.unwrap()), original);
    } else {
        assert!(result.is_err(), "{case}: invalid receipt admitted");
    }
    assert_eq!(
        store.list_events(&instance).unwrap(),
        before,
        "{case}: changed journal"
    );
}

#[test]
fn hosted_exec_settlement_retention_guards() {
    for case in CASES {
        let store = crate::do_store::test_support::store();
        let sql = store.sql.clone();
        check(store, case, |statement| {
            sql.execute(statement, &[]).unwrap();
        });
    }
}

#[test]
fn native_exec_settlement_retention_guards() {
    let dir = std::env::temp_dir().join(format!(
        "exec-retention-{}-{}",
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
        check(store, case, |statement| {
            sql.execute_batch(statement).unwrap();
        });
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn native_exec_settlement_retention_selects_one_concurrent_outcome() {
    let path = std::env::temp_dir().join(format!(
        "exec-retention-race-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut store = SqliteStore::open(&path).unwrap();
    let instance = setup(&mut store);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = ["{\"outcome\":1}", "{\"outcome\":2}"]
        .into_iter()
        .map(|payload| {
            let path = path.clone();
            let instance = instance.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut store = SqliteStore::open(&path).unwrap();
                barrier.wait();
                store.retain_exec_settlement(exec_settlement::Retention {
                    instance_id: &instance,
                    effect_id: "observe",
                    run_id: "run",
                    input_json: "{}",
                    settlement_json: payload,
                })
            })
        })
        .collect();
    let outcomes: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(outcomes.iter().filter(|r| r.is_err()).count(), 1);
    let events = store.list_events(&instance).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| e.event_type == exec_settlement::EVENT_TYPE)
            .count(),
        1
    );
    drop(store);
    let mut store = SqliteStore::open(&path).unwrap();
    let retained: serde_json::Value = serde_json::from_str(
        &events
            .iter()
            .find(|e| e.event_type == exec_settlement::EVENT_TYPE)
            .unwrap()
            .payload_json,
    )
    .unwrap();
    let payload = retained["settlement"].to_string();
    assert!(store
        .retain_exec_settlement(exec_settlement::Retention {
            instance_id: &instance,
            effect_id: "observe",
            run_id: "run",
            input_json: "{}",
            settlement_json: &payload
        })
        .is_ok());
    drop(store);
    std::fs::remove_file(path).unwrap();
}

const RECOVERY_CASES: &[&str] = &[
    "recover",
    "generic-recover",
    "generic-source",
    "generic-run-provider",
    "terminal-race",
    "closed-other",
    "terminal-missing",
    "terminal-kind",
    "receipt-kind",
    "effect-kind",
    "new-attempt",
    "batch-input",
    "batch-material",
    "batch-cache",
    "protocol",
    "source",
    "receipt-effect",
    "receipt-run",
    "receipt-input",
    "status",
    "missing-run",
    "run-provider",
    "run-worker",
    "effect-input",
];
fn cold_recovery<S: RuntimeStore>(
    mut store: S,
    reopen: impl Fn() -> S,
    mutate: impl Fn(&str),
    case: &str,
) {
    use whipplescript_kernel::exec_http::{
        commit_exec_settlement, recover_exec_settlement, ExecSettlementProjection,
    };
    use whipplescript_kernel::RuntimeKernel;
    let instance = setup_with_key(&mut store, true);
    let run_id =
        whipplescript_kernel::execution_attempt_key(&instance, "observe", None, "exec-run");
    let effect = ClaimableEffect {
        attempt_admission_event_id: None,
        effect_id: "observe".into(),
        kind: "exec.command".into(),
        target: None,
        profile: None,
        input_json: "{}".into(),
        required_capabilities_json: r#"["script.observer"]"#.into(),
        declared_profiles_json: "[]".into(),
    };
    let mut kernel = RuntimeKernel::new(store);
    let projections = [ExecSettlementProjection {
        name: "exec.command.completed".into(),
        key: "observe".into(),
        value: r#"{"value":"original"}"#.into(),
        ingest: false,
        event_key: "projection".into(),
    }];
    mutate("CREATE TRIGGER fail_cold_projection AFTER INSERT ON facts BEGIN SELECT RAISE(ABORT, 'injected projection failure'); END;");
    assert!(commit_exec_settlement(
        &mut kernel,
        "{}",
        EffectCompletion {
            instance_id: &instance,
            effect_id: "observe",
            run_id: &run_id,
            provider: "exec",
            worker_id: "whip-exec",
            status: if case == "new-attempt" {
                "failed"
            } else {
                "completed"
            },
            exit_code: Some(0),
            summary: Some("original"),
            metadata_json: r#"{"stdout":"original"}"#,
            idempotency_key: Some(&whipplescript_kernel::execution_run_key(
                &instance,
                "observe",
                &run_id,
                &["terminal"]
            ))
        },
        &projections,
        None
    )
    .is_err());
    assert_eq!(
        kernel.store().list_runs(&instance).unwrap()[0].status,
        "running"
    );
    drop(kernel);
    mutate("DROP TRIGGER fail_cold_projection");
    match case {
        "protocol" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.protocol', 'other') WHERE event_type = 'exec.settlement.retained'"),
        "receipt-kind" => mutate("UPDATE events SET event_type = 'other' WHERE event_type = 'exec.settlement.retained'"),
        "effect-kind" => mutate("UPDATE effects SET kind = 'other'"),
        "closed-other" => mutate("UPDATE runs SET status = 'failed'"),
        "source" | "generic-source" => mutate("UPDATE events SET source = 'other' WHERE event_type = 'exec.settlement.retained'"),
        "receipt-effect" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.effect_id', 'other') WHERE event_type = 'exec.settlement.retained'"),
        "receipt-run" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.run_id', 'other') WHERE event_type = 'exec.settlement.retained'"),
        "receipt-input" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.input.other', 1) WHERE event_type = 'exec.settlement.retained'"),
        "status" => mutate("UPDATE events SET payload_json = json_set(payload_json, '$.settlement.status', 'other') WHERE event_type = 'exec.settlement.retained'"),
        "missing-run" => { mutate("DELETE FROM leases"); mutate("DELETE FROM runs"); },
        "run-provider" | "generic-run-provider" => mutate("UPDATE runs SET provider = 'other'"),
        "run-worker" => mutate("UPDATE runs SET worker_id = 'other'"),
        "effect-input" | "batch-input" => mutate("UPDATE effects SET input_json = '{\"other\":1}'"),
        _ => {},
    }
    let mut kernel = RuntimeKernel::new(reopen());
    if case == "terminal-race" {
        // A generic recovery sweep may have read the run before retention.
        // Its eventual write must still refuse after the receipt commits.
        let before = kernel.store().list_events(&instance).unwrap();
        assert!(
            kernel
                .store_mut()
                .resolve_effect_uncertain(
                    EffectCompletion {
                        instance_id: &instance,
                        effect_id: "observe",
                        run_id: &run_id,
                        provider: "exec",
                        worker_id: "whip-exec",
                        status: "failed",
                        exit_code: None,
                        summary: Some("uncertain"),
                        metadata_json: "{}",
                        idempotency_key: Some("racing-uncertain"),
                    },
                    None
                )
                .is_err(),
            "uncertain terminal replaced retained outcome"
        );
        // The refused terminal leaves a `run.terminal_refused` record on
        // purpose; what must not change is the settled history itself.
        let after = kernel.store().list_events(&instance).unwrap();
        assert!(
            after
                .iter()
                .filter(|event| event.event_type != "run.terminal_refused")
                .eq(before.iter()),
            "a refused terminal must not alter the retained outcome"
        );
        assert_eq!(
            kernel.store().list_runs(&instance).unwrap()[0].status,
            "running"
        );
        return;
    }
    if matches!(case, "terminal-missing" | "terminal-kind") {
        recover_exec_settlement(&mut kernel, &instance, &effect)
            .unwrap()
            .unwrap();
        if case == "terminal-missing" {
            mutate(
                "UPDATE events SET idempotency_key = 'other' WHERE event_type = 'effect.terminal'",
            );
        } else {
            mutate("UPDATE events SET event_type = 'other' WHERE event_type = 'effect.terminal'");
        }
    }
    if case.starts_with("batch-") {
        let before = kernel.store().list_events(&instance).unwrap();
        let id = whipplescript_kernel::idempotency_key(&[
            &instance,
            "fact",
            "exec.command.completed",
            "observe",
        ]);
        let facts = [SettlementFact {
            fact: NewFact {
                validity_json: None,
                fact_id: &id,
                name: "exec.command.completed",
                key: "observe",
                value_json: if case == "batch-material" {
                    "{\"value\":\"replacement\"}"
                } else {
                    "{\"value\":\"original\"}"
                },
                schema_id: None,
                provenance_class: "external",
                correlation_id: None,
                source_span_json: None,
            },
            idempotency_key: "projection",
        }];
        assert!(
            kernel
                .store_mut()
                .complete_effect_settlement(
                    EffectCompletion {
                        instance_id: &instance,
                        effect_id: "observe",
                        run_id: &run_id,
                        provider: "exec",
                        worker_id: "whip-exec",
                        status: "completed",
                        exit_code: Some(0),
                        summary: Some("original"),
                        metadata_json: "{\"stdout\":\"original\"}",
                        idempotency_key: Some(&whipplescript_kernel::execution_run_key(
                            &instance,
                            "observe",
                            &run_id,
                            &["terminal"]
                        ))
                    },
                    None,
                    &facts,
                    (case == "batch-cache").then_some(SettlementCache {
                        content_key: "replacement",
                        result_json: "{}"
                    })
                )
                .is_err(),
            "{case}: final transaction accepted changed receipt binding"
        );
        // The refused terminal leaves a `run.terminal_refused` record on
        // purpose; what must not change is the settled history itself.
        let after = kernel.store().list_events(&instance).unwrap();
        assert!(
            after
                .iter()
                .filter(|event| event.event_type != "run.terminal_refused")
                .eq(before.iter()),
            "a refused terminal must not alter the retained outcome"
        );
        return;
    }
    if case == "new-attempt" {
        recover_exec_settlement(&mut kernel, &instance, &effect)
            .unwrap()
            .unwrap();
        kernel
            .store_mut()
            .retry_effect(RetryEffect {
                instance_id: &instance,
                effect_id: "observe",
                retry_after: None,
                idempotency_key: Some("next-attempt"),
            })
            .unwrap();
        let mut selected = effect.clone();
        selected.attempt_admission_event_id = kernel
            .store()
            .effect_attempt_admission(&instance, "observe")
            .unwrap();
        assert!(selected.attempt_admission_event_id.is_some());
        assert!(
            recover_exec_settlement(&mut kernel, &instance, &selected)
                .unwrap()
                .is_none(),
            "new attempt reused old receipt"
        );
    }
    let before = kernel.store().list_events(&instance).unwrap();
    let recovered = if case.starts_with("generic-") {
        kernel
            .recover_running_provider_runs(&instance)
            .map(|events| {
                assert_eq!(events.len(), 1);
                events.into_iter().next()
            })
    } else {
        recover_exec_settlement(&mut kernel, &instance, &effect)
    };
    if matches!(case, "recover" | "generic-recover") {
        let event = recovered.unwrap().expect("retained outcome recovered");
        assert_eq!(
            kernel.store().list_runs(&instance).unwrap()[0].status,
            "completed"
        );
        assert_eq!(
            kernel.store().list_facts(&instance).unwrap()[0].value_json,
            r#"{"value":"original"}"#
        );
        mutate("UPDATE facts SET consumed_at = CURRENT_TIMESTAMP");
        let count = kernel.store().list_events(&instance).unwrap().len();
        assert_eq!(
            recover_exec_settlement(&mut kernel, &instance, &effect).unwrap(),
            Some(event)
        );
        assert!(kernel.store().list_facts(&instance).unwrap().is_empty());
        assert_eq!(kernel.store().list_events(&instance).unwrap().len(), count);
    } else {
        assert!(recovered.is_err(), "{case}: altered recovery accepted");
        // The refused terminal leaves a `run.terminal_refused` record on
        // purpose; what must not change is the settled history itself.
        let after = kernel.store().list_events(&instance).unwrap();
        assert!(
            after
                .iter()
                .filter(|event| event.event_type != "run.terminal_refused")
                .eq(before.iter()),
            "a refused terminal must not alter the retained outcome"
        );
    }
}

#[test]
fn hosted_exec_settlement_cold_recovery() {
    for case in RECOVERY_CASES {
        let store = crate::do_store::test_support::store();
        let sql = store.sql.clone();
        cold_recovery(
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
fn native_exec_settlement_cold_recovery() {
    let dir = std::env::temp_dir().join(format!(
        "exec-cold-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    for case in RECOVERY_CASES {
        let path = dir.join(format!("{case}.sqlite"));
        let store = SqliteStore::open(&path).unwrap();
        let sql = rusqlite::Connection::open(&path).unwrap();
        cold_recovery(
            store,
            || SqliteStore::open(&path).unwrap(),
            |statement| sql.execute_batch(statement).unwrap(),
            case,
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
