use super::*;
use crate::tracker_closure::{TrackerClosure, TrackerClosureReceipt, TrackerClosures};

fn receipt(connection: &Connection, operation: &str) -> StoreResult<Option<TrackerClosureReceipt>> {
    let value: Option<String> = connection
        .query_row(
            "SELECT receipt_json FROM tracker_closure_receipts WHERE operation_id = ?1",
            [operation],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .transpose()
}

impl TrackerClosures for WorkItemStore {
    fn closing_receipt(&self, operation: &str) -> StoreResult<Option<TrackerClosureReceipt>> {
        receipt(&self.connection, operation)
    }

    fn close_issue_once(&mut self, request: &TrackerClosure) -> StoreResult<TrackerClosureReceipt> {
        let fingerprint = request.fingerprint()?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(existing) = receipt(&tx, &request.operation_id)? {
            existing.validate_for(request)?;
            return Ok(existing);
        }
        let subject = content_id_of(&tx, &request.item_id)?;
        let item: Option<(String, String)> = tx
            .query_row(
                "SELECT queue, status FROM tracker_issues WHERE issue_id = ?1",
                [&request.item_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((queue, status)) = item else {
            return Err(StoreError::Conflict(
                "tracker closure issue is unavailable".into(),
            ));
        };
        if queue != request.queue || subject.as_deref() != Some(request.subject_id.as_str()) {
            return Err(StoreError::Conflict(
                "tracker closure subject differs from its binding".into(),
            ));
        }
        if status != "open" {
            return Err(StoreError::Conflict(
                "tracker closure issue is not open".into(),
            ));
        }
        let now = tx_now(&tx)?;
        if tx_holder_conflict(
            &tx,
            &request.item_id,
            &now,
            request.expected_holder.as_deref(),
        )?
        .is_some()
        {
            return Err(StoreError::Conflict(
                "tracker closure issue has another live holder".into(),
            ));
        }
        let event_id = tx_append_raw(
            &tx,
            Some(&request.subject_id),
            None,
            "issue.closed",
            &request.event_payload(&fingerprint).to_string(),
            Some(&request.actor),
            Some(&request.effect_id),
            &now,
        )?;
        tx.execute(
            "UPDATE tracker_issues SET status = 'closed', claim_summary = ?2, updated_at = ?3 WHERE issue_id = ?1",
            params![request.item_id, request.summary, now],
        )?;
        tx_release_active_lease_by(
            &tx,
            &request.item_id,
            Some(&request.effect_id),
            Some(&request.actor),
            &now,
        )?;
        let receipt = TrackerClosureReceipt {
            operation_id: request.operation_id.clone(),
            fingerprint,
            queue: request.queue.clone(),
            item_id: request.item_id.clone(),
            subject_id: request.subject_id.clone(),
            actor: request.actor.clone(),
            event_id,
            closed_at: now,
        };
        tx.execute(
            "INSERT INTO tracker_closure_receipts (operation_id, receipt_json) VALUES (?1, ?2)",
            params![request.operation_id, serde_json::to_string(&receipt)?],
        )?;
        tx.commit()?;
        Ok(receipt)
    }
}

impl TrackerClosures for crate::native_stores::NativeStores {
    fn closing_receipt(&self, operation: &str) -> StoreResult<Option<TrackerClosureReceipt>> {
        self.items.closing_receipt(operation)
    }
    fn close_issue_once(&mut self, request: &TrackerClosure) -> StoreResult<TrackerClosureReceipt> {
        self.items.close_issue_once(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn database_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "whip-closure-{}-{}.sqlite",
            std::process::id(),
            crate::stable_hash_hex(&format!("{:?}", std::time::SystemTime::now()))
        ))
    }

    #[test]
    fn concurrent_tracker_closures_survive_disk_restart_as_one_closing() {
        let path = database_path();
        let mut first = WorkItemStore::open(&path).unwrap();
        let request = crate::tracker_closure::conformance::setup(&mut first, "person:learner");
        let second = WorkItemStore::open(&path).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let writers: Vec<_> = [first, second]
            .into_iter()
            .map(|mut store| {
                let barrier = barrier.clone();
                let request = request.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .close_issue_once(&request)
                        .expect("concurrent closing")
                })
            })
            .collect();
        let receipts: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(receipts[0], receipts[1]);
        {
            let mut store = WorkItemStore::open(&path).unwrap();
            store.rebuild_projection().unwrap();
            assert_eq!(
                store.closing_receipt(&request.operation_id).unwrap(),
                Some(receipts[0].clone())
            );
            assert_eq!(store.close_issue_once(&request).unwrap(), receipts[0]);
            assert_eq!(WorkItems::event_position(&store).unwrap(), 2);
            assert_eq!(store.closings(&request.queue).unwrap().len(), 1);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_tracker_closure_upgrade_preserves_legacy_history_without_a_new_receipt() {
        let path = database_path();
        let request = {
            let mut store = WorkItemStore::open(&path).unwrap();
            let request = crate::tracker_closure::conformance::setup(&mut store, "person:learner");
            store.finish_item(&request.item_id, None, None).unwrap();
            store.connection.execute_batch("DROP TABLE tracker_closure_receipts; DELETE FROM schema_migrations; INSERT INTO schema_migrations VALUES (2, 'work-item')").unwrap();
            request
        };
        {
            let store = WorkItemStore::open(&path).unwrap();
            let version: i64 = store
                .connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(version, 3);
            assert_eq!(store.closing_receipt(&request.operation_id).unwrap(), None);
            assert_eq!(WorkItems::event_position(&store).unwrap(), 2);
            assert_eq!(
                store.get_item(&request.item_id).unwrap().unwrap().status,
                "closed"
            );
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn tracker_closure_upgrade_refuses_a_newer_store_before_creating_the_table() {
        let path = database_path();
        {
            let store = WorkItemStore::open(&path).unwrap();
            store.connection.execute_batch("DROP TABLE tracker_closure_receipts; INSERT INTO schema_migrations VALUES (999, 'future')").unwrap();
        }
        assert!(matches!(
            WorkItemStore::open(&path),
            Err(StoreError::UnsupportedVersion {
                found: 999,
                supported: 3,
                ..
            })
        ));
        {
            let connection = Connection::open(&path).unwrap();
            let created: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'tracker_closure_receipts')", [], |row| row.get(0)).unwrap();
            assert!(!created);
        }
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn native_tracker_closure_conformance() {
        for actor in ["person:learner", "agent:assistant"] {
            crate::tracker_closure::conformance::run(
                &mut WorkItemStore::open_in_memory().unwrap(),
                actor,
            );
        }
        for case in crate::tracker_closure::conformance::REFUSAL_CASES {
            crate::tracker_closure::conformance::refuse(
                &mut WorkItemStore::open_in_memory().unwrap(),
                case,
            );
        }
    }

    #[test]
    fn native_tracker_closure_rolls_back_each_mutation_boundary() {
        for trigger in [
            "AFTER INSERT ON tracker_events WHEN NEW.kind = 'issue.closed'",
            "AFTER UPDATE ON tracker_issues",
            "AFTER INSERT ON tracker_events WHEN NEW.kind = 'claim.released'",
            "AFTER UPDATE ON tracker_leases",
            "AFTER INSERT ON tracker_closure_receipts",
        ] {
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let request = crate::tracker_closure::conformance::setup(&mut store, "person:learner");
            store
                .claim_item(&request.item_id, "workflow:holder", None)
                .unwrap();
            let item = store.get_item(&request.item_id).unwrap();
            let before = WorkItems::event_position(&store).unwrap();
            store.connection.execute_batch(&format!("CREATE TRIGGER closure_fault {trigger} BEGIN SELECT RAISE(ABORT, 'closure fault'); END")).unwrap();
            assert!(store.close_issue_once(&request).is_err(), "{trigger}");
            assert_eq!(store.get_item(&request.item_id).unwrap(), item);
            assert_eq!(WorkItems::event_position(&store).unwrap(), before);
            assert_eq!(store.closing_receipt(&request.operation_id).unwrap(), None);
            store
                .connection
                .execute_batch("DROP TRIGGER closure_fault")
                .unwrap();
            store.close_issue_once(&request).unwrap();
        }
    }

    #[test]
    fn native_tracker_closing_records_the_actual_actor_and_retries_after_reopen() {
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let request = crate::tracker_closure::conformance::setup(&mut store, "person:learner");
        store
            .claim_item(&request.item_id, "workflow:holder", None)
            .unwrap();
        let receipt = store.close_issue_once(&request).unwrap();
        let release = store
            .export_events()
            .unwrap()
            .into_iter()
            .find(|event| event.kind == "claim.released")
            .unwrap();
        assert_eq!(release.actor.as_deref(), Some(request.actor.as_str()));
        assert_eq!(
            serde_json::from_str::<Value>(&release.payload_json).unwrap()["actor"],
            "workflow:holder"
        );
        assert_eq!(
            store.event_effect_id(&release.event_id).unwrap(),
            Some(request.effect_id.clone())
        );
        let (actor, effect, payload): (String, String, String) = store
            .connection
            .query_row(
                "SELECT actor, effect_id, payload_json FROM tracker_events WHERE event_id = ?1",
                [&receipt.event_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(actor, request.actor);
        assert_eq!(effect, request.effect_id);
        let payload: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(payload["operation"]["instance_id"], request.instance_id);
        assert_eq!(payload["operation"]["fingerprint"], receipt.fingerprint);
        store.set_field(&request.item_id, "status", "open").unwrap();
        store.rebuild_projection().unwrap();
        let before = WorkItems::event_position(&store).unwrap();
        assert_eq!(store.close_issue_once(&request).unwrap(), receipt);
        assert_eq!(
            store.get_item(&request.item_id).unwrap().unwrap().status,
            "open"
        );
        assert_eq!(WorkItems::event_position(&store).unwrap(), before);
    }
}
