use super::*;
use crate::{RuntimeStore, SqliteStore};

#[test]
fn native_file_settlement_and_replay() {
    for kind in ["file.read", "file.write", "file.import", "file.export"] {
        for status in ["completed", "failed"] {
            conformance::run_suite(
                &mut SqliteStore::open_in_memory().expect("settlement fixture operation"),
                kind,
                status,
            );
        }
    }
}

#[test]
fn file_settlement_requires_exact_terminal_and_fact_identity() {
    let mut store = SqliteStore::open_in_memory().expect("settlement fixture operation");
    let fixture = conformance::setup(&mut store, "file.write", "completed");
    let before = store
        .list_events(&fixture.instance)
        .expect("settlement fixture operation");
    for changed in [
        "provider",
        "status",
        "missing-terminal-key",
        "empty-terminal-key",
        "same-key",
        "fact-id",
        "fact-event-key",
        "effect",
        "run",
        "fact-status",
        "value",
        "missing-value",
    ] {
        let mut completion = fixture.completion();
        let mut fact = fixture.fact();
        let mut value: serde_json::Value =
            serde_json::from_str(&fixture.value).expect("settlement fixture operation");
        match changed {
            "provider" => completion.provider = "unverified",
            "status" => completion.status = "cancelled",
            "missing-terminal-key" => completion.idempotency_key = None,
            "empty-terminal-key" => completion.idempotency_key = Some(" "),
            "same-key" => completion.idempotency_key = Some(fact.event_key),
            "fact-id" => fact.fact_id = " ",
            "fact-event-key" => fact.event_key = " ",
            "effect" => value["effect_id"] = "other".into(),
            "run" => value["run_id"] = "other".into(),
            "fact-status" => value["status"] = "failed".into(),
            "value" => value["value"]["bytes"] = 42.into(),
            "missing-value" => {
                value
                    .as_object_mut()
                    .expect("settlement fixture operation")
                    .remove("value");
            }
            _ => unreachable!(),
        }
        let wire = value.to_string();
        fact.value_json = &wire;
        let error = store
            .settle_file_effect(completion, None, fact)
            .expect_err("invalid settlement must refuse");
        assert!(
            matches!(error, crate::StoreError::Conflict(ref detail)
            if detail == "file settlement fact does not bind its terminal"),
            "{changed}: {error:?}"
        );
        assert_eq!(
            store
                .list_events(&fixture.instance)
                .expect("settlement fixture operation"),
            before,
            "{changed}"
        );
    }
    assert!(fixture.fact().check_kind("completed", None).is_err());
}

fn snapshot(store: &SqliteStore) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    [
        "events",
        "instances",
        "effects",
        "runs",
        "leases",
        "facts",
        "diagnostics",
        "effect_dependencies",
    ]
    .iter()
    .map(|table| {
        let mut statement = store
            .connection
            .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
            .expect("settlement fixture operation");
        let columns = statement.column_count();
        statement
            .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
            .expect("settlement fixture operation")
            .collect::<Result<Vec<_>, _>>()
            .expect("settlement fixture operation")
    })
    .collect()
}

#[test]
fn native_file_settlement_rolls_back_every_write_boundary() {
    native_settlement_faults(false, "failed");
}

#[test]
fn native_recording_settlement_rolls_back_every_write_boundary() {
    for status in ["completed", "failed"] {
        native_settlement_faults(true, status);
    }
}

fn native_settlement_faults(recording: bool, status: &str) {
    for timing in ["BEFORE", "AFTER"] {
        for (table, action, predicate) in [
            ("events", "INSERT", "NEW.event_type = 'effect.terminal'"),
            ("runs", "UPDATE", "1"),
            ("leases", "UPDATE", "1"),
            ("effects", "UPDATE", "1"),
            ("diagnostics", "INSERT", "1"),
            ("events", "INSERT", "NEW.event_type = 'fact.derived'"),
            ("facts", "INSERT", "1"),
        ] {
            let mut store = SqliteStore::open_in_memory().expect("settlement fixture operation");
            let fixture = if recording {
                recording_conformance::setup(&mut store, status)
            } else {
                conformance::setup(&mut store, "file.write", status)
            };
            // A completed result has no diagnostic INSERT to interrupt.
            if table == "diagnostics" && status == "completed" {
                continue;
            }
            let metadata = if recording {
                recording_conformance::metadata(status)
            } else {
                fixture.completion().metadata_json.to_owned()
            };
            let completion = crate::EffectCompletion {
                metadata_json: &metadata,
                ..fixture.completion()
            };
            let before = snapshot(&store);
            store
                .connection
                .execute_batch(&format!(
                "CREATE TRIGGER settlement_fault {timing} {action} ON {table} WHEN {predicate} \
                 BEGIN SELECT RAISE(ABORT, 'injected settlement fault'); END"
            ))
                .expect("settlement fixture operation");
            let error = store
                .settle_local_effect(completion, fixture.diagnostic(), fixture.fact())
                .expect_err("invalid settlement must refuse");
            assert!(
                format!("{error:?}").contains("injected settlement fault"),
                "{timing} {table}: {error:?}"
            );
            assert_eq!(snapshot(&store), before, "{timing} {table}");
            store
                .connection
                .execute_batch("DROP TRIGGER settlement_fault")
                .expect("settlement fixture operation");
            store
                .settle_local_effect(completion, fixture.diagnostic(), fixture.fact())
                .expect("settlement fixture operation");
            assert_eq!(
                store
                    .list_facts(&fixture.instance)
                    .expect("settlement fixture operation")
                    .len(),
                1
            );
        }
    }
}

#[test]
fn native_recording_settlement_and_replay() {
    for status in ["completed", "failed"] {
        recording_conformance::run_suite(
            &mut SqliteStore::open_in_memory().expect("store"),
            status,
        );
    }
    for case in ["missing-target", "foreign-target", "foreign-provider"] {
        recording_conformance::refuse_foreign_profile(
            &mut SqliteStore::open_in_memory().expect("store"),
            case,
        );
    }
}
