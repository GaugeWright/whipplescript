// Explicit test-only items also keep standalone source scans from counting
// injected storage faults and assertion patterns as production refusals.
use super::*;
use crate::do_branches::DoBranches;
use crate::do_store::{test_support::RusqliteDoSql, tests::FaultySql};
use whipplescript_store::branches::{resolution_batch::conformance, Branches};
use whipplescript_store::StoreError;

#[cfg(test)]
#[test]
fn hosted_resolution_batch_conformance() {
    conformance::check(
        &mut DoBranches::new(RusqliteDoSql::with_runtime_schema()).expect("fixture"),
    );
}

#[cfg(test)]
#[test]
fn hosted_resolution_batch_rolls_back_every_sql_boundary() {
    let mut completed = false;
    let mut refused = 0;
    for fail_at in 1..16 {
        let store = DoBranches::new(RusqliteDoSql::with_runtime_schema()).expect("fixture");
        let mut injected = DoBranches {
            sql: FaultySql::new(store.sql, fail_at),
        };
        let request = conformance::request();
        let outcome = injected.record_resolution_batch(&request);
        injected.sql.disarm();
        if let Ok(receipt) = outcome {
            assert_eq!(
                injected
                    .resolution_batch(&request.operation_id)
                    .expect("fixture"),
                Some(receipt)
            );
            completed = true;
            break;
        }
        refused += 1;
        assert_eq!(
            injected
                .resolution_batch(&request.operation_id)
                .expect("fixture"),
            None,
            "{fail_at}"
        );
        for entry in &request.entries {
            assert_eq!(
                injected
                    .resolution_memory(&entry.triple_key)
                    .expect("fixture"),
                None,
                "{fail_at}"
            );
        }
        assert!(injected.record_resolution_batch(&request).is_ok());
    }
    assert!(completed);
    assert_eq!(
        refused, 10,
        "receipt read, three memory insert/read pairs, two origin inserts, receipt insert"
    );
}

#[cfg(test)]
#[test]
fn hosted_resolution_batch_recovers_a_lost_commit_response_without_writes() {
    use std::rc::Rc;
    struct LostResponse(Rc<RusqliteDoSql>);
    impl DoSql for LostResponse {
        fn atomic(&self, body: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            self.0.atomic(body)?;
            Err(StoreError::Conflict("response lost after commit".into()))
        }
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.0.execute(sql, params)
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            self.0.query(sql, params)
        }
    }
    let sql = Rc::new(RusqliteDoSql::with_runtime_schema());
    let mut recovered = DoBranches::new(sql.clone()).expect("fixture");
    let request = conformance::request();
    let mut interrupted = DoBranches {
        sql: LostResponse(sql.clone()),
    };
    assert!(interrupted.record_resolution_batch(&request).is_err());
    let receipt = recovered
        .resolution_batch(&request.operation_id)
        .expect("fixture")
        .expect("committed despite lost response");
    sql.execute("CREATE TRIGGER no_memory BEFORE INSERT ON resolution_memory BEGIN SELECT RAISE(ABORT, 'replayed mutation'); END", &[]).expect("fixture");
    assert_eq!(
        recovered
            .record_resolution_batch(&request)
            .expect("fixture"),
        receipt
    );
}

#[cfg(test)]
#[test]
fn hosted_contradictory_resolution_receipts_are_faults() {
    for (id, json, digest) in conformance::contradictions() {
        let mut store = DoBranches::new(RusqliteDoSql::with_runtime_schema()).expect("fixture");
        store
            .sql
            .execute(INSERT, &[text(&id), text(&json), text(&digest)])
            .expect("fixture");
        assert!(matches!(
            store.resolution_batch(&id),
            Err(StoreError::Fault { .. })
        ));
        let request = ResolutionMemoryBatch {
            operation_id: id,
            ..conformance::request()
        };
        assert!(matches!(
            store.record_resolution_batch(&request),
            Err(StoreError::Fault { .. })
        ));
        assert_eq!(store.resolution_memory("triple-a").expect("fixture"), None);
    }
}

#[cfg(test)]
#[test]
fn hosted_invalid_resolution_sql_rows_never_become_outcomes() {
    struct Malformed {
        inner: RusqliteDoSql,
        target: &'static str,
        rows: Vec<Vec<SqlValue>>,
    }
    impl DoSql for Malformed {
        fn atomic(&self, body: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            self.inner.atomic(body)
        }
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.inner.execute(sql, params)
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            if sql == self.target {
                Ok(self.rows.clone())
            } else {
                self.inner.query(sql, params)
            }
        }
    }
    for (target, rows, expected_detail) in [
        (
            SELECT,
            vec![vec![SqlValue::Null]],
            "invalid receipt SQL row",
        ),
        (SELECT, vec![vec![], vec![]], "duplicate receipt SQL rows"),
        (SELECT_MEMORY, vec![], "missing or duplicate memory"),
        (
            SELECT_MEMORY,
            vec![vec![], vec![]],
            "missing or duplicate memory",
        ),
        (
            SELECT_MEMORY,
            vec![vec![SqlValue::Null]],
            "invalid memory SQL row",
        ),
        (
            SELECT_MEMORY,
            vec![vec![text(" ")]],
            "invalid memory SQL row",
        ),
    ] {
        let inner = DoBranches::new(RusqliteDoSql::with_runtime_schema())
            .expect("fixture")
            .sql;
        let mut store = DoBranches {
            sql: Malformed {
                inner,
                target,
                rows,
            },
        };
        let error = store
            .record_resolution_batch(&conformance::request())
            .expect_err("invalid SQL must refuse");
        match error {
            StoreError::Fault { subject, detail } => {
                assert_eq!(subject, "resolution batch resolve-1");
                assert_eq!(detail, expected_detail);
            }
            other => panic!("store contradiction was misclassified: {other:?}"),
        }
        assert!(store
            .sql
            .inner
            .query(SELECT_MEMORY, &[text("triple-a")])
            .expect("fixture")
            .is_empty());
        assert!(store
            .sql
            .inner
            .query(SELECT, &[text("resolve-1")])
            .expect("fixture")
            .is_empty());
    }
}

#[cfg(test)]
#[test]
fn hosted_resolution_recording_conformance() {
    whipplescript_store::vcs::resolution_recording::conformance::check(
        &mut crate::do_branches::compose_vcs(&RusqliteDoSql::with_runtime_schema())
            .expect("hosted workspace"),
    );
}

#[cfg(test)]
#[test]
fn hosted_resolution_scope_conformance() {
    whipplescript_store::vcs::resolution_scope::conformance::check(
        &mut crate::do_branches::compose_vcs(&RusqliteDoSql::with_runtime_schema())
            .expect("hosted workspace"),
    );
}

#[cfg(test)]
#[test]
fn hosted_resolution_observation_conformance() {
    whipplescript_store::vcs::resolution_scope::conformance::check_observations(
        &mut crate::do_branches::compose_vcs(&RusqliteDoSql::with_runtime_schema())
            .expect("hosted workspace"),
    );
}

#[cfg(test)]
#[test]
fn hosted_resolution_observation_verifies_the_consumed_bytes() {
    let sql = RusqliteDoSql::with_runtime_schema();
    let mut vcs = crate::do_branches::compose_vcs(&sql).expect("hosted workspace");
    whipplescript_store::vcs::resolution_scope::conformance::check_content_identity(
        &mut vcs,
        |id| {
            sql.execute(
                "UPDATE content_blobs SET body = 'forged value', byte_len = 12 WHERE id = ?1",
                &[text(id)],
            )
            .expect("corrupt stored bytes");
        },
    );
}
