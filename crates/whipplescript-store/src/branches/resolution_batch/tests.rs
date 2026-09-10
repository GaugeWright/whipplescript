// Explicit test-only items also keep standalone source scans from counting
// injected storage faults and assertion patterns as production refusals.
use super::*;
use crate::branches::{BranchStore, Branches};

#[cfg(test)]
#[test]
fn native_resolution_batch_conformance() {
    conformance::check(&mut BranchStore::open_in_memory().expect("fixture"));
}

#[cfg(test)]
#[test]
fn resolution_batch_rolls_back_every_mutation_and_retains_losing_inputs() {
    for table in [
        "resolution_memory",
        "resolution_origins",
        "resolution_batches",
    ] {
        for moment in ["BEFORE", "AFTER"] {
            // Fault both the first insert and a later insert, after earlier
            // entries have been tentatively written inside the transaction.
            for key in ["triple-a", "triple-b"] {
                let mut store = BranchStore::open_in_memory().expect("fixture");
                let condition = if table != "resolution_batches" {
                    format!("WHEN NEW.triple_key = '{key}'")
                } else {
                    String::new()
                };
                store.connection.execute_batch(&format!("CREATE TRIGGER fail_batch {moment} INSERT ON {table} {condition} BEGIN SELECT RAISE(ABORT, 'batch fault'); END")).expect("fixture");
                let request = conformance::request();
                assert!(store.record_resolution_batch(&request).is_err());
                assert_eq!(
                    store
                        .resolution_batch(&request.operation_id)
                        .expect("fixture"),
                    None
                );
                for entry in &request.entries {
                    assert_eq!(
                        store.resolution_memory(&entry.triple_key).expect("fixture"),
                        None
                    );
                }
                store
                    .connection
                    .execute_batch("DROP TRIGGER fail_batch")
                    .expect("fixture");
                store
                    .record_resolution_memory("triple-a", "legacy-a", "t0")
                    .expect("fixture");
                store.record_resolution_batch(&request).expect("fixture");
                let roots = store.reachability_roots().expect("fixture");
                for hash in ["requested-a", "legacy-a", "requested-b", "later-b"] {
                    assert!(roots.contains(hash), "{hash} must remain a collection root");
                }
            }
        }
    }
}

#[cfg(test)]
#[test]
fn resolution_batch_reopens_read_only_without_repeating_or_rewriting_memory() {
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let dir = Directory(std::env::temp_dir().join(format!(
            "whip-resolution-batch-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        )));
    std::fs::create_dir_all(&dir.0).expect("fixture directory");
    let path = dir.0.join("branches.sqlite");
    let request = conformance::request();
    let receipt = {
        let mut store = BranchStore::open(&path).expect("fixture");
        store.record_resolution_batch(&request).expect("fixture")
    };
    let reader = BranchStore::open_read_only(&path).expect("fixture");
    assert_eq!(
        reader
            .resolution_batch(&request.operation_id)
            .expect("fixture"),
        Some(receipt.clone())
    );
    assert_eq!(reader.resolution_batch("absent").expect("fixture"), None);
    assert!(
        matches!(reader.resolution_observation("triple-b").expect("read-only origin"),
        crate::branches::resolution_origin::ResolutionObservation::Recorded { ref origin, .. }
            if origin.operation_id == request.operation_id && origin.outcome_index == 1)
    );
    let mut writer = BranchStore::open(&path).expect("fixture");
    writer.connection.execute_batch("CREATE TRIGGER no_memory BEFORE INSERT ON resolution_memory BEGIN SELECT RAISE(ABORT, 'replayed mutation'); END").expect("fixture");
    assert_eq!(
        writer.record_resolution_batch(&request).expect("fixture"),
        receipt
    );
    assert!(matches!(
        crate::stamp_satellite_schema(&writer.connection, "branch", 2),
        Err(StoreError::UnsupportedVersion {
            found: 4,
            supported: 2,
            ..
        })
    ));
}

#[cfg(test)]
#[test]
fn contradictory_resolution_receipts_fault_on_read_retry_and_collection() {
    for (id, json, digest) in conformance::contradictions() {
        let mut store = BranchStore::open_in_memory().expect("fixture");
        store
            .connection
            .execute(INSERT, rusqlite::params![id, json, digest])
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
        assert!(matches!(
            store.reachability_roots(),
            Err(StoreError::Fault { .. })
        ));
        assert_eq!(store.resolution_memory("triple-a").expect("fixture"), None);
    }
}

#[cfg(test)]
#[test]
fn invalid_legacy_memory_cannot_publish_a_resolution_receipt() {
    let mut store = BranchStore::open_in_memory().expect("store");
    store
        .record_resolution_memory("triple-b", " ", "t0")
        .expect("legacy row");
    assert!(matches!(
        store.record_resolution_batch(&conformance::request()),
        Err(StoreError::Fault { .. })
    ));
    assert_eq!(
        store.resolution_memory("triple-a").expect("rolled back"),
        None
    );
    assert_eq!(
        store
            .resolution_batch("resolve-1")
            .expect("no false receipt"),
        None
    );
}
