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
        let protection = self.protection.clone();
        if let Some(protection) = protection {
            protection.retain(|| self.file_issue_once_retained(filing, &mut || Ok(())))
        } else {
            self.file_issue_once_retained(filing, &mut || Ok(()))
        }
    }
}

impl WorkItemStore {
    /// The check borrows the SAME original embedding writer; no renewed
    /// principal or separately captured permission may replace it. A native
    /// commit may survive an embedding failure; recover the original request.
    pub fn file_issue_once_guarded(
        &mut self,
        filing: &TrackerFiling,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<TrackerFilingReceipt> {
        check()?;
        let protection = self.protection.clone();
        let mut file = || self.file_issue_once_retained(filing, check);
        match protection {
            Some(protection) => protection.retain(file),
            None => file(),
        }
    }

    /// Retain exact original filing evidence through an embedding reference
    /// commit. The callback consumes the SAME original product writer and
    /// checks its authority at commit; it does no native or external work.
    pub fn publish_filing_receipt<T>(
        &self,
        filing: &TrackerFiling,
        expected: &TrackerFilingReceipt,
        publish: impl FnOnce(&TrackerFilingReceipt) -> StoreResult<T>,
    ) -> StoreResult<T> {
        let protection = self.protection.clone();
        let publish = || {
            let tx = Transaction::new_unchecked(
                &self.connection,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            require_original_filing(&tx, filing, expected)?;
            let result = publish(expected)?;
            // Closing failure cannot undo an already committed embedding.
            tx.commit()?;
            Ok(result)
        };
        match protection {
            Some(protection) => protection.retain(publish),
            None => publish(),
        }
    }

    fn file_issue_once_retained(
        &mut self,
        filing: &TrackerFiling,
        check: &mut dyn FnMut() -> StoreResult<()>,
    ) -> StoreResult<TrackerFilingReceipt> {
        let fingerprint = filing.fingerprint()?;
        let tx = self.discovery_transaction()?;
        check()?;
        if let Some(existing) = receipt(&tx, &filing.operation_id)? {
            if existing.fingerprint != fingerprint {
                return Err(StoreError::Conflict(
                    "tracker filing identity already binds a different request".into(),
                ));
            }
            require_original_filing(&tx, filing, &existing)?;
            check()?;
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
        tx.commit_guarded(check)?;
        Ok(receipt)
    }
}

fn require_original_filing(
    connection: &Connection,
    filing: &TrackerFiling,
    expected: &TrackerFilingReceipt,
) -> StoreResult<()> {
    if expected.operation_id != filing.operation_id
        || expected.fingerprint != filing.fingerprint()?
        || receipt(connection, &filing.operation_id)?.as_ref() != Some(expected)
    {
        return Err(StoreError::Conflict(
            "original tracker filing receipt differs".into(),
        ));
    }
    let event = connection.query_row(
        "SELECT parents_json, issue_id, kind, whip_tracker_event_open(event_id, kind, payload_json), actor, effect_id, created_at FROM tracker_events WHERE event_id=?1",
        [&expected.event_id],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?,
            row.get::<_, String>(2)?, row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?, row.get::<_, Option<String>>(5)?,
            row.get::<_, String>(6)?)),
    ).optional()?.ok_or_else(|| StoreError::Conflict(
        "original tracker filing creation event unavailable".into(),
    ))?;
    let parents: Vec<String> = serde_json::from_str(&event.0)?;
    let payload: Value = serde_json::from_str(&event.3)?;
    let wanted = json!({
        "queue": filing.queue, "title": filing.title, "body": filing.body,
        "labels": filing.labels, "metadata": filing.metadata,
        "filed_by": filing.actor, "assigned_to": filing.assigned_to,
        "filing_fingerprint": expected.fingerprint,
    });
    if !parents.is_empty()
        || event.1.as_deref() != Some(&expected.event_id)
        || event.2 != "issue.created"
        || payload != wanted
        || event.4.as_deref() != Some(&filing.actor)
        || event.5.as_deref() != Some(&filing.effect_id)
        || event_content_id(
            &event.2,
            None,
            &event.3,
            event.4.as_deref(),
            &parents,
            &event.6,
        ) != expected.event_id
        || content_id_of(connection, &expected.item_id)?.as_deref() != Some(&expected.event_id)
    {
        return Err(StoreError::Conflict(
            "original tracker filing creation meaning differs".into(),
        ));
    }
    Ok(())
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

    #[test]
    fn guarded_filing_original_denial_rolls_back_every_boundary() {
        for boundary in 1..=3 {
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let filing = crate::tracker_filing::conformance::request();
            let mut checks = 0;
            let error = store
                .file_issue_once_guarded(&filing, &mut || {
                    checks += 1;
                    if checks == boundary {
                        Err(StoreError::Conflict("original task ended".into()))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(format!("{error:?}").contains("original task ended"));
            assert_eq!(checks, boundary);
            assert!(store.list_items(None, None).unwrap().is_empty());
            assert!(store.export_events().unwrap().is_empty());
            assert!(store
                .filing_receipt(&filing.operation_id)
                .unwrap()
                .is_none());
            assert_eq!(
                store
                    .file_issue_once_guarded(&filing, &mut || Ok(()))
                    .unwrap()
                    .item_id,
                "WS-1"
            );
        }
    }

    #[test]
    fn guarded_filing_final_check_follows_discovery_preparation() {
        let root = database_path().with_extension("discovery");
        std::fs::create_dir_all(&root).unwrap();
        let mut store = WorkItemStore::open(root.join("items.sqlite")).unwrap();
        store.enroll_discovery(&root).unwrap();
        let filing = crate::tracker_filing::conformance::request();
        let mut checks = 0;
        let error = store
            .file_issue_once_guarded(&filing, &mut || {
                checks += 1;
                if checks == 3 {
                    // This actual prepared view proves the last check follows
                    // staging rather than standing in for the durable boundary.
                    let stages: Vec<_> = std::fs::read_dir(&root)
                        .unwrap()
                        .flatten()
                        .filter(|e| {
                            e.file_name()
                                .to_string_lossy()
                                .starts_with(".tracker-stage-")
                        })
                        .collect();
                    assert_eq!(stages.len(), 1);
                    assert!(stages[0].path().join("tasks/WS-1.hjson").is_file());
                    Err(StoreError::Conflict(
                        "original task expired during preparation".into(),
                    ))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(format!("{error:?}").contains("original task expired during preparation"));
        assert!(store.export_events().unwrap().is_empty());
        assert!(store
            .filing_receipt(&filing.operation_id)
            .unwrap()
            .is_none());
        assert!(!root.join("tracker/tasks/WS-1.hjson").exists());
        drop(store);
        let mut restored = WorkItemStore::open_existing(root.join("items.sqlite")).unwrap();
        assert_eq!(
            restored
                .file_issue_once_guarded(&filing, &mut || Ok(()))
                .unwrap()
                .item_id,
            "WS-1"
        );
        assert!(root.join("tracker/tasks/WS-1.hjson").is_file());
        drop(restored);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn guarded_filing_checks_and_publication_hold_the_actual_native_writer() {
        let path = database_path();
        let mut store = WorkItemStore::open(&path).unwrap();
        let other = Connection::open(&path).unwrap();
        other.busy_timeout(std::time::Duration::ZERO).unwrap();
        let filing = crate::tracker_filing::conformance::request();
        let mut checks = 0;
        let receipt = store
            .file_issue_once_guarded(&filing, &mut || {
                checks += 1;
                if checks == 1 {
                    other.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
                } else {
                    assert!(other.execute_batch("BEGIN IMMEDIATE").is_err());
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(checks, 3);
        store
            .publish_filing_receipt(&filing, &receipt, |original| {
                assert_eq!(original, &receipt);
                assert!(other.execute_batch("BEGIN IMMEDIATE").is_err());
                Ok(())
            })
            .unwrap();
        other.execute_batch("BEGIN IMMEDIATE; ROLLBACK").unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn guarded_filing_exact_recovery_never_reopens_or_renews_original_access() {
        let mut store = WorkItemStore::open_in_memory().unwrap();
        let filing = crate::tracker_filing::conformance::request();
        let receipt = store
            .file_issue_once_guarded(&filing, &mut || Ok(()))
            .unwrap();
        let error = store
            .publish_filing_receipt::<()>(&filing, &receipt, |_| {
                Err(StoreError::Conflict("embedding commit refused".into()))
            })
            .unwrap_err();
        assert!(format!("{error:?}").contains("embedding commit refused"));
        store
            .finish_item(&receipt.item_id, Some("completed later"), None)
            .unwrap();
        let events = store.export_events().unwrap();
        for boundary in 1..=3 {
            let mut checks = 0;
            let error = store
                .file_issue_once_guarded(&filing, &mut || {
                    checks += 1;
                    if checks == boundary {
                        Err(StoreError::Conflict("original task ended".into()))
                    } else {
                        Ok(())
                    }
                })
                .unwrap_err();
            assert!(format!("{error:?}").contains("original task ended"));
            assert_eq!(checks, boundary);
            assert_eq!(store.export_events().unwrap(), events);
        }
        assert_eq!(
            store
                .file_issue_once_guarded(&filing, &mut || Ok(()))
                .unwrap(),
            receipt
        );
        store
            .publish_filing_receipt(&filing, &receipt, |_| Ok(()))
            .unwrap();
        assert_eq!(store.export_events().unwrap(), events);
        assert_eq!(
            store.get_item(&receipt.item_id).unwrap().unwrap().status,
            "closed"
        );
        let mut changed = filing.clone();
        changed.actor = "another-person".into();
        let error = store
            .file_issue_once_guarded(&changed, &mut || Ok(()))
            .unwrap_err();
        assert!(format!("{error:?}")
            .contains("tracker filing identity already binds a different request"));
    }

    #[test]
    fn guarded_filing_publication_refuses_changed_or_missing_original_evidence() {
        for case in [
            "receipt",
            "request",
            "missing-event",
            "event-body",
            "event-actor",
            "event-effect",
            "event-time",
            "event-parents",
            "event-subject",
            "alias",
        ] {
            let mut store = WorkItemStore::open_in_memory().unwrap();
            let mut filing = crate::tracker_filing::conformance::request();
            let receipt = store
                .file_issue_once_guarded(&filing, &mut || Ok(()))
                .unwrap();
            match case {
                "receipt" => {
                    store
                        .connection
                        .execute(
                            "UPDATE tracker_filing_receipts SET fingerprint='changed'",
                            [],
                        )
                        .unwrap();
                }
                "request" => {
                    filing.body.push_str(" changed");
                }
                "missing-event" => {
                    store
                        .connection
                        .execute("DELETE FROM tracker_events", [])
                        .unwrap();
                }
                "event-body" => {
                    store
                        .connection
                        .execute("UPDATE tracker_events SET payload_json='{}'", [])
                        .unwrap();
                }
                "event-actor" => {
                    store
                        .connection
                        .execute("UPDATE tracker_events SET actor='other'", [])
                        .unwrap();
                }
                "event-effect" => {
                    store
                        .connection
                        .execute("UPDATE tracker_events SET effect_id='other'", [])
                        .unwrap();
                }
                "event-time" => {
                    store
                        .connection
                        .execute("UPDATE tracker_events SET created_at='other'", [])
                        .unwrap();
                }
                "event-parents" => {
                    store
                        .connection
                        .execute("UPDATE tracker_events SET parents_json='[\"other\"]'", [])
                        .unwrap();
                }
                "event-subject" => {
                    store
                        .connection
                        .execute("UPDATE tracker_events SET issue_id='other'", [])
                        .unwrap();
                }
                "alias" => {
                    store
                        .connection
                        .execute("DELETE FROM tracker_aliases", [])
                        .unwrap();
                }
                _ => unreachable!(),
            }
            let error = store
                .publish_filing_receipt::<()>(&filing, &receipt, |_| {
                    panic!("invalid filing published: {case}")
                })
                .unwrap_err();
            let reason = match case {
                "receipt" | "request" => "original tracker filing receipt differs",
                "missing-event" => "original tracker filing creation event unavailable",
                _ => "original tracker filing creation meaning differs",
            };
            assert!(format!("{error:?}").contains(reason), "{case}: {error:?}");
        }
    }

    fn database_path() -> std::path::PathBuf {
        crate::scratch::file("whip-filing", "sqlite")
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
