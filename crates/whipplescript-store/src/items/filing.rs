use super::*;
use crate::tracker_filing::{TrackerFiling, TrackerFilingReceipt, TrackerFilings};

fn receipt(connection: &Connection, operation: &str) -> StoreResult<Option<TrackerFilingReceipt>> {
    connection.query_row(
        "SELECT operation_id, fingerprint, item_id, event_id FROM tracker_filing_receipts WHERE operation_id = ?1",
        [operation],
        |row| Ok(TrackerFilingReceipt {
            operation_id: row.get(0)?, fingerprint: row.get(1)?,
            item_id: row.get(2)?, event_id: row.get(3)?,
        }),
    ).optional().map_err(Into::into)
}

impl TrackerFilings for WorkItemStore {
    fn filing_receipt(&self, operation: &str) -> StoreResult<Option<TrackerFilingReceipt>> {
        receipt(&self.connection, operation)
    }

    fn file_issue_once(&mut self, filing: &TrackerFiling) -> StoreResult<TrackerFilingReceipt> {
        let fingerprint = filing.fingerprint()?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(existing) = receipt(&tx, &filing.operation_id)? {
            if existing.fingerprint != fingerprint {
                return Err(StoreError::Conflict(
                    "tracker filing identity already binds a different request".into(),
                ));
            }
            return Ok(existing);
        }
        let (item_id, event_id) = tx_file_item(
            &tx,
            &filing.queue,
            &filing.title,
            &filing.body,
            &filing.labels,
            &filing.metadata,
            Some(&filing.actor),
            filing.assigned_to.as_deref(),
            Some(&filing.effect_id),
            Some(&fingerprint),
        )?;
        let receipt = TrackerFilingReceipt {
            operation_id: filing.operation_id.clone(),
            fingerprint,
            item_id,
            event_id,
        };
        tx.execute(
            "INSERT INTO tracker_filing_receipts (operation_id, fingerprint, item_id, event_id) VALUES (?1, ?2, ?3, ?4)",
            params![receipt.operation_id, receipt.fingerprint, receipt.item_id, receipt.event_id],
        )?;
        tx.commit()?;
        Ok(receipt)
    }
}

impl TrackerFilings for crate::native_stores::NativeStores {
    fn filing_receipt(&self, operation: &str) -> StoreResult<Option<TrackerFilingReceipt>> {
        self.items.filing_receipt(operation)
    }
    fn file_issue_once(&mut self, filing: &TrackerFiling) -> StoreResult<TrackerFilingReceipt> {
        self.items.file_issue_once(filing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "whip-filing-{}-{}.sqlite",
            std::process::id(),
            crate::stable_hash_hex(&format!("{:?}", std::time::SystemTime::now()))
        ))
    }

    #[test]
    fn native_tracker_filing_conformance() {
        crate::tracker_filing::conformance::run(
            &mut WorkItemStore::open_in_memory().expect("filing fixture"),
        );
    }

    #[test]
    fn filing_receipt_failure_rolls_back_the_issue_event_and_counter() {
        let mut store = WorkItemStore::open_in_memory().expect("filing fixture");
        store.connection.execute_batch("CREATE TRIGGER fail_receipt BEFORE INSERT ON tracker_filing_receipts BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END;").expect("filing fixture");
        let filing = crate::tracker_filing::conformance::request();
        assert!(store.file_issue_once(&filing).is_err());
        assert!(store
            .list_items(None, None)
            .expect("filing fixture")
            .is_empty());
        assert_eq!(
            WorkItems::event_position(&store).expect("filing fixture"),
            0
        );
        assert_eq!(
            store
                .filing_receipt(&filing.operation_id)
                .expect("filing fixture"),
            None
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fail_receipt")
            .expect("filing fixture");
        assert_eq!(
            store
                .file_issue_once(&filing)
                .expect("filing fixture")
                .item_id,
            "WS-1"
        );
    }

    #[test]
    fn a_filing_survives_reopen_and_projection_rebuild() {
        let path = database_path();
        let filing = crate::tracker_filing::conformance::request();
        let receipt = {
            let mut store = WorkItemStore::open(&path).expect("filing fixture");
            store.file_issue_once(&filing).expect("filing fixture")
        };
        {
            let mut store = WorkItemStore::open(&path).expect("filing fixture");
            store.rebuild_projection().expect("filing fixture");
            assert_eq!(
                store
                    .filing_receipt(&filing.operation_id)
                    .expect("filing fixture"),
                Some(receipt.clone())
            );
            assert_eq!(
                store.file_issue_once(&filing).expect("filing fixture"),
                receipt
            );
            assert_eq!(
                store
                    .event_effect_id(&receipt.event_id)
                    .expect("filing fixture"),
                Some(filing.effect_id)
            );
            assert_eq!(
                store.list_items(None, None).expect("filing fixture").len(),
                1
            );
        }
        std::fs::remove_file(path).expect("filing fixture");
    }

    #[test]
    fn concurrent_deliveries_file_one_issue() {
        let path = database_path();
        let first = WorkItemStore::open(&path).expect("first connection");
        let second = WorkItemStore::open(&path).expect("second connection");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let threads: Vec<_> = [first, second]
            .into_iter()
            .map(|mut store| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .file_issue_once(&crate::tracker_filing::conformance::request())
                        .expect("concurrent filing")
                })
            })
            .collect();
        let receipts: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().expect("writer thread"))
            .collect();
        assert_eq!(receipts[0], receipts[1]);
        {
            let store = WorkItemStore::open(&path).expect("reopen");
            assert_eq!(store.list_items(None, None).expect("items").len(), 1);
            assert_eq!(WorkItems::event_position(&store).expect("events"), 1);
        }
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn legacy_tracker_upgrade_preserves_events_without_inventing_receipts() {
        let path = database_path();
        let original = {
            let mut store = WorkItemStore::open(&path).expect("store");
            let issue = store
                .file_item("legacy", "old issue", "", &[], &json!({}), None, None)
                .expect("legacy filing");
            store.connection.execute_batch("DROP TABLE tracker_filing_receipts; DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (1, 'work-item');").expect("old generation");
            issue
        };
        {
            let mut store = WorkItemStore::open(&path).expect("upgrade");
            assert_eq!(store.get_item(&original.id).expect("item"), Some(original));
            assert_eq!(WorkItems::event_position(&store).expect("events"), 1);
            let filing = crate::tracker_filing::conformance::request();
            assert_eq!(
                store.filing_receipt(&filing.operation_id).expect("receipt"),
                None
            );
            assert_eq!(
                store.file_issue_once(&filing).expect("new filing").item_id,
                "WS-2"
            );
        }
        std::fs::remove_file(path).expect("cleanup");
    }
}
