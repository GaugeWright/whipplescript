use super::*;
use crate::SqliteStore;

#[test]
fn native_coerce_settlement_and_replay() {
    for status in ["completed", "failed", "timed_out"] {
        conformance::run_suite(
            &mut SqliteStore::open_in_memory().expect("coerce settlement fixture"),
            status,
        );
    }
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
fn native_coerce_settlement_rolls_back_every_write_boundary() {
    for timing in ["BEFORE", "AFTER"] {
        for (table, action, predicate) in [
            ("events", "INSERT", "NEW.event_type = 'effect.terminal'"),
            ("runs", "UPDATE", "1"),
            ("leases", "UPDATE", "1"),
            ("effects", "UPDATE", "1"),
            ("diagnostics", "INSERT", "1"),
            (
                "events",
                "INSERT",
                "NEW.event_type = 'schema.coerce.failed'",
            ),
            ("events", "INSERT", "NEW.event_type = 'fact.derived'"),
            ("effects", "UPDATE", "NEW.effect_id = 'settle-dependent'"),
            ("facts", "INSERT", "1"),
        ] {
            let mut store = SqliteStore::open_in_memory().expect("settlement fixture operation");
            let fixture = conformance::setup(&mut store, "schema.coerce", "failed");
            let before = snapshot(&store);
            store
                .connection
                .execute_batch(&format!(
                "CREATE TRIGGER settlement_fault {timing} {action} ON {table} WHEN {predicate} \
                 BEGIN SELECT RAISE(ABORT, 'injected settlement fault'); END"
            ))
                .expect("settlement fixture operation");
            let error = store
                .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
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
                .settle_coerce_effect(fixture.completion(), fixture.diagnostic(), fixture.fact())
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
fn native_coerce_settlement_refuses_wrong_kind_and_occupied_admission() {
    conformance::wrong_kind(&mut SqliteStore::open_in_memory().expect("coerce settlement fixture"));
    conformance::occupied_fact(
        &mut SqliteStore::open_in_memory().expect("coerce settlement fixture"),
    );
}
