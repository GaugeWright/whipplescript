//! Identical reattachment and refusal controls run against both SQLite hosts.
use crate::do_store::{DoSql, SqlValue};
use crate::rule_commit_recovery_tests::{commit, effect, version};
use whipplescript_store::*;

pub(crate) fn request(instance: &str) -> RunStart<'_> {
    RunStart {
        instance_id: instance,
        effect_id: "observe",
        run_id: "run",
        provider: "exec",
        worker_id: "worker",
        lease_id: "lease",
        lease_expires_at: "2099-01-01T00:00:00Z",
        metadata_json: r#"{"plan":"original"}"#,
    }
}
const CASES: &[&str] = &[
    "exact",
    "fresh-run",
    "capacity",
    "dependencies",
    "metadata",
    "provider",
    "worker",
    "lease",
    "expiry",
    "effect",
    "released",
    "terminal",
    "effect-terminal",
    "missing-event",
    "event-kind",
    "policy",
    "paused",
    "cancelled",
];
fn check<S: RuntimeStore>(mut store: S, case: &str, mutate: impl Fn(&str)) {
    let mut declaration = version("reattach");
    if case == "capacity" {
        declaration.declared_profiles_json =
            r#"[{"name":"worker","capacity":1,"capabilities":["agent.tell"]}]"#;
    }
    let v = store.create_program_version(declaration).unwrap();
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
    if case == "capacity" {
        store
            .register_capability_schema(CapabilitySchemaRegistration {
                capability: "agent.tell",
                description: "fixture agent",
                schema_json: "{}",
                registered_by_package_id: None,
            })
            .unwrap();
        store
            .bind_capability(CapabilityBinding {
                binding_id: "fixture-agent",
                program_id: Some(&v.program_id),
                capability: "agent.tell",
                provider: "fixture-agent",
                config_json: "{}",
            })
            .unwrap();
        store
            .register_effect_provider(EffectProviderRegistration {
                provider_id: "fixture-agent",
                effect_kind: "agent.tell",
                provider: "fixture-agent",
                capability: "agent.tell",
                config_json: "{}",
                registered_by_package_id: None,
            })
            .unwrap();
    }
    let mut observed = effect(None);
    if case == "capacity" {
        observed.kind = "agent.tell";
        observed.target = Some("worker");
        observed.profile = None;
        observed.required_capabilities_json = r#"["agent.tell"]"#;
    }
    let upstream = NewEffect {
        effect_id: "upstream",
        idempotency_key: "upstream",
        ..observed
    };
    store
        .commit_rule(commit(&instance, &[observed, upstream]))
        .unwrap();
    let original = store.start_run(request(&instance)).unwrap();
    if case == "capacity" {
        let mut competing = request(&instance);
        competing.effect_id = "upstream";
        competing.run_id = "competing";
        competing.lease_id = "competing";
        assert!(matches!(
            store.start_run(competing),
            Err(StoreError::CapacityBlocked { .. })
        ));
    }
    match case {
        "dependencies" => mutate("INSERT INTO effect_dependencies (dependency_id, instance_id, upstream_effect_id, downstream_effect_id, predicate, created_by_rule) SELECT 'later', instance_id, 'upstream', 'observe', 'succeeds', 'fixture' FROM effects WHERE effect_id='observe'"),
        "released" => mutate("UPDATE leases SET status='released'"),
        "terminal" => mutate("UPDATE runs SET status='completed'"),
        "effect-terminal" => mutate("UPDATE effects SET status='completed'"),
        "missing-event" => mutate("DELETE FROM events WHERE event_type='effect.run_started'"),
        "event-kind" => {
            mutate("UPDATE events SET event_type='other' WHERE event_type='effect.run_started'")
        }
        "policy" => mutate("DELETE FROM capability_bindings"),
        "paused" => mutate("UPDATE instances SET status='paused'"),
        "cancelled" => {
            store
                .request_effect_cancellation(EffectCancellationRequest {
                    instance_id: &instance,
                    effect_id: "observe",
                    revision_id: None,
                    reason: Some("stop"),
                    requested_by: "fixture",
                    causation_event_id: None,
                    idempotency_key: Some("cancel"),
                })
                .unwrap();
        }
        _ => {}
    }
    let before = store.list_events(&instance).unwrap();
    let runs = store.list_runs(&instance).unwrap();
    let mut replay = request(&instance);
    match case {
        "fresh-run" => {
            replay.run_id = "second-run";
            replay.lease_id = "second-lease";
        }
        "metadata" => replay.metadata_json = r#"{"plan":"changed"}"#,
        "provider" => replay.provider = "other",
        "worker" => replay.worker_id = "other",
        "lease" => replay.lease_id = "other",
        "expiry" => replay.lease_expires_at = "2099-02-01T00:00:00Z",
        "effect" => replay.effect_id = "other",
        _ => {}
    }
    let result = store.start_run(replay);
    if matches!(case, "exact" | "capacity") {
        assert_eq!(result.as_ref().unwrap(), &original);
    } else {
        assert!(result.is_err(), "{case}: {result:?}");
    }
    assert_eq!(
        store.list_runs(&instance).unwrap(),
        runs,
        "{case}: no second run or projection change"
    );
    if case == "policy" {
        assert!(matches!(result, Err(StoreError::PolicyBlocked { .. })));
        let events = store.list_events(&instance).unwrap();
        assert_eq!(events.len(), before.len() + 1);
        assert_eq!(events.last().unwrap().event_type, "effect.blocked");
        let again = store.start_run(request(&instance));
        assert!(
            matches!(again, Err(StoreError::PolicyBlocked { .. })),
            "repeated policy denial must preserve its typed outcome: {again:?}"
        );
        assert_eq!(store.list_events(&instance).unwrap(), events);
        assert_eq!(store.list_runs(&instance).unwrap(), runs);
        mutate("DELETE FROM capability_schemas WHERE capability='script.observer'");
        let changed = store.start_run(request(&instance));
        assert!(
            matches!(changed, Err(StoreError::PolicyBlocked { ref reason, .. })
            if reason.contains("not registered")),
            "changed denial: {changed:?}"
        );
        let changed_events = store.list_events(&instance).unwrap();
        assert_eq!(
            changed_events.len(),
            events.len() + 1,
            "changed reason is durable"
        );
        let payload: serde_json::Value =
            serde_json::from_str(&changed_events.last().unwrap().payload_json).unwrap();
        assert!(payload["reason"]
            .as_str()
            .unwrap()
            .contains("not registered"));
        assert!(matches!(
            store.start_run(request(&instance)),
            Err(StoreError::PolicyBlocked { .. })
        ));
        assert_eq!(store.list_events(&instance).unwrap(), changed_events);
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
        assert_eq!(store.start_run(request(&instance)).unwrap(), original);
        assert_eq!(store.list_events(&instance).unwrap(), changed_events);
        assert_eq!(store.list_runs(&instance).unwrap(), runs);
    } else {
        assert_eq!(store.list_events(&instance).unwrap(), before, "{case}");
    }
}

#[test]
fn hosted_run_reattach_preserves_identity_and_rechecks_admission() {
    for case in CASES {
        let store = crate::do_store::test_support::store();
        let sql = store.sql.clone();
        check(store, case, |statement| {
            sql.execute(statement, &[]).unwrap();
        });
        assert_eq!(
            sql.query("SELECT COUNT(*) FROM leases", &[]).unwrap(),
            vec![vec![SqlValue::Int(1)]],
            "{case}: retain exactly the original lease"
        );
    }
}
#[test]
fn native_run_reattach_preserves_identity_and_rechecks_admission() {
    let dir = std::env::temp_dir().join(format!(
        "run-reattach-{}-{}",
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
        assert_eq!(
            sql.query_row("SELECT COUNT(*) FROM leases", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1,
            "{case}: retain exactly the original lease"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
