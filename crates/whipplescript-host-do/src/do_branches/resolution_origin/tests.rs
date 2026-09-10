use super::*;
use crate::do_branches::DoBranches;
use crate::do_store::test_support::RusqliteDoSql;
use whipplescript_store::branches::{
    resolution_batch::conformance::request, resolution_origin::conformance, Branches,
};
use whipplescript_store::StoreError;

#[cfg(test)]
#[test]
fn hosted_resolution_origin_conformance() {
    conformance::check(&mut DoBranches::new(RusqliteDoSql::with_runtime_schema()).expect("store"));
}

#[cfg(test)]
#[test]
fn hosted_resolution_origin_corruption_never_becomes_absence_or_attribution() {
    for (sql, expected) in conformance::corruptions() {
        let mut store = DoBranches::new(RusqliteDoSql::with_runtime_schema()).expect("store");
        store.record_resolution_batch(&request()).expect("receipt");
        store.sql.execute(sql, &[]).expect("corrupt fixture");
        let error = store.resolution_observation("triple-b").expect_err(sql);
        assert!(
            matches!(error, StoreError::Fault { ref detail, .. } if detail.starts_with(expected)),
            "{sql}: {error:?}"
        );
    }
}

#[cfg(test)]
#[test]
fn hosted_resolution_origin_refuses_malformed_snapshot_rows() {
    struct Rows(Vec<Vec<SqlValue>>);
    impl DoSql for Rows {
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            unreachable!("read must not write")
        }
        fn query(&self, statement: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            assert_eq!(statement, SELECT);
            Ok(self.0.clone())
        }
    }
    let nulls = vec![SqlValue::Null; 5];
    let mut cases = vec![vec![], vec![nulls.clone(), nulls.clone()], vec![vec![]]];
    for index in 0..5 {
        let mut row = nulls.clone();
        row[index] = if index == 2 {
            text("wrong index type")
        } else {
            SqlValue::Int(7)
        };
        cases.push(vec![row]);
    }
    for rows in cases {
        let error = read(&Rows(rows), "triple-b").expect_err("malformed snapshot");
        assert!(
            matches!(error, StoreError::Fault { ref detail, .. } if detail == "invalid resolution origin SQL row")
        );
    }
}

#[cfg(test)]
#[test]
fn hosted_resolution_origin_query_failure_is_not_a_contradictory_snapshot() {
    struct QueryFailure;
    impl DoSql for QueryFailure {
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            unreachable!("lookup must not write")
        }
        fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            Err("database unavailable".into())
        }
    }
    let error = read(&QueryFailure, "triple-b").expect_err("query cannot run");
    assert!(matches!(error, StoreError::Io(_)));
}
