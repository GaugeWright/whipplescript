use super::*;
use crate::branches::{resolution_batch::conformance::request, BranchStore, Branches};
use crate::StoreError;

#[cfg(test)]
#[test]
fn native_resolution_origin_conformance() {
    conformance::check(&mut BranchStore::open_in_memory().expect("store"));
}

#[cfg(test)]
#[test]
fn native_resolution_origin_corruption_never_becomes_absence_or_attribution() {
    for (sql, expected) in conformance::corruptions() {
        let mut store = BranchStore::open_in_memory().expect("store");
        store.record_resolution_batch(&request()).expect("receipt");
        store
            .connection
            .execute_batch(sql)
            .expect("corrupt fixture");
        let error = store.resolution_observation("triple-b").expect_err(sql);
        assert!(
            matches!(error, StoreError::Fault { ref detail, .. } if detail.starts_with(expected)),
            "{sql}: {error:?}"
        );
    }
    let mut store = BranchStore::open_in_memory().expect("store");
    store
        .record_resolution_memory("blank", " ", "t0")
        .expect("legacy corruption");
    assert!(store.resolution_observation("blank").is_err());
}

#[cfg(test)]
#[test]
fn resolution_origin_migration_never_invents_old_authorship() {
    let mut store = BranchStore::open_in_memory().expect("store");
    let receipt = store
        .record_resolution_batch(&request())
        .expect("old receipt");
    store
        .connection
        .execute_batch("DROP TABLE resolution_origins")
        .expect("older generation shape");
    // The old journal is inspectable, but does not imply the absent index.
    super::super::ensure_branch_schema(&store.connection).expect("add empty index");
    assert_eq!(
        store.resolution_observation("triple-b").expect("unindexed"),
        ResolutionObservation::OriginUnavailable {
            content_hash: "requested-b".into()
        }
    );
    assert_eq!(
        store
            .record_resolution_batch(&request())
            .expect("retry original receipt"),
        receipt
    );
    assert!(matches!(
        store
            .resolution_observation("triple-b")
            .expect("retry cannot invent origin"),
        ResolutionObservation::OriginUnavailable { .. }
    ));
    assert!(matches!(
        crate::stamp_satellite_schema(&store.connection, "branch", 3),
        Err(StoreError::UnsupportedVersion {
            found: 4,
            supported: 3,
            ..
        })
    ));
}

#[cfg(test)]
#[test]
fn resolution_origin_query_failure_is_not_a_contradictory_snapshot() {
    let store = BranchStore::open_in_memory().expect("store");
    store
        .connection
        .execute_batch("DROP TABLE resolution_origins")
        .expect("older schema shape");
    let error = store
        .resolution_observation("triple-b")
        .expect_err("query cannot run");
    assert!(matches!(error, StoreError::Sqlite(_)));
}
