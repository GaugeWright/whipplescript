use super::*;
use whipplescript_store::tracker_filing::{TrackerFiling, TrackerFilingReceipt, TrackerFilings};

fn receipt(sql: &impl DoSql, operation: &str) -> StoreResult<Option<TrackerFilingReceipt>> {
    let rows = sql.query(
        "SELECT operation_id, fingerprint, item_id, event_id FROM tracker_filing_receipts WHERE operation_id = ?1",
        &[text(operation)],
    ).map_err(sql_err)?;
    Ok(rows.first().map(|row| TrackerFilingReceipt {
        operation_id: as_text(&row[0]),
        fingerprint: as_text(&row[1]),
        item_id: as_text(&row[2]),
        event_id: as_text(&row[3]),
    }))
}

impl<Sql: DoSql> TrackerFilings for DoSqliteStore<Sql> {
    fn filing_receipt(&self, operation: &str) -> StoreResult<Option<TrackerFilingReceipt>> {
        receipt(&self.sql, operation)
    }
    fn file_issue_once(&mut self, filing: &TrackerFiling) -> StoreResult<TrackerFilingReceipt> {
        let fingerprint = filing.fingerprint()?;
        let mut result = None;
        self.sql.atomic(&mut || {
            if let Some(existing) = receipt(&self.sql, &filing.operation_id)? {
                if existing.fingerprint != fingerprint {
                    return Err(StoreError::Conflict("tracker filing identity already binds a different request".into()));
                }
                result = Some(existing);
                return Ok(());
            }
            let (item_id, event_id) = do_file_item_on(
                &self.sql, &filing.queue, &filing.title, &filing.body, &filing.labels,
                &filing.metadata, Some(&filing.actor), filing.assigned_to.as_deref(),
                Some(&filing.effect_id), Some(&fingerprint),
            )?;
            let receipt = TrackerFilingReceipt {
                operation_id: filing.operation_id.clone(), fingerprint: fingerprint.clone(), item_id, event_id,
            };
            self.sql.execute(
                "INSERT INTO tracker_filing_receipts (operation_id, fingerprint, item_id, event_id) VALUES (?1, ?2, ?3, ?4)",
                &[text(&receipt.operation_id), text(&receipt.fingerprint), text(&receipt.item_id), text(&receipt.event_id)],
            ).map_err(sql_err)?;
            result = Some(receipt);
            Ok(())
        })?;
        result.ok_or_else(|| {
            StoreError::fault(
                "tracker filing transaction",
                "reported success without executing",
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::RusqliteDoSql;
    use super::*;

    #[test]
    fn hosted_tracker_filing_conformance() {
        let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        whipplescript_store::tracker_filing::conformance::run(&mut store);
    }

    #[test]
    fn hosted_receipt_failure_rolls_back_the_issue_event_and_counter() {
        let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        store.sql.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON tracker_filing_receipts BEGIN SELECT RAISE(ABORT, 'injected receipt failure'); END", &[]).expect("filing fixture");
        let filing = whipplescript_store::tracker_filing::conformance::request();
        assert!(store.file_issue_once(&filing).is_err());
        assert!(store
            .list_items(None, None)
            .expect("filing fixture")
            .is_empty());
        assert_eq!(store.event_position().expect("filing fixture"), 0);
        assert_eq!(
            store
                .filing_receipt(&filing.operation_id)
                .expect("filing fixture"),
            None
        );
        store
            .sql
            .execute("DROP TRIGGER fail_receipt", &[])
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
    fn every_hosted_filing_sql_failure_rolls_back_before_retry() {
        use super::super::tests::FaultySql;
        let filing = whipplescript_store::tracker_filing::conformance::request();
        let mut reached_success = false;
        for fail_at in 1..32 {
            let mut store = DoSqliteStore::new(FaultySql::new(
                RusqliteDoSql::with_runtime_schema(),
                fail_at,
            ));
            let outcome = store.file_issue_once(&filing);
            store.sql.disarm();
            if outcome.is_ok() {
                assert!(fail_at > 4, "must exercise the mutation's SQL boundaries");
                assert_eq!(store.list_items(None, None).expect("items").len(), 1);
                reached_success = true;
                break;
            }
            assert!(
                store.list_items(None, None).expect("items").is_empty(),
                "failure {fail_at}"
            );
            assert_eq!(
                store.event_position().expect("events"),
                0,
                "failure {fail_at}"
            );
            assert_eq!(
                store.filing_receipt(&filing.operation_id).expect("receipt"),
                None
            );
            assert_eq!(
                store.file_issue_once(&filing).expect("retry").item_id,
                "WS-1"
            );
        }
        assert!(reached_success);
    }

    #[test]
    fn a_bridge_cannot_report_a_filing_it_never_executed() {
        struct NoBody;
        impl DoSql for NoBody {
            fn atomic(&self, _body: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
                Ok(())
            }
            fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
                panic!("unexpected write")
            }
            fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
                panic!("unexpected read")
            }
        }
        assert!(matches!(DoSqliteStore::new(NoBody)
            .file_issue_once(&whipplescript_store::tracker_filing::conformance::request())
            , Err(StoreError::Fault { subject, detail })
            if subject == "tracker filing transaction" && detail == "reported success without executing"));
    }

    #[test]
    fn filing_readback_loss_is_a_store_fault() {
        struct MissingReadback {
            inner: RusqliteDoSql,
            hide: std::cell::Cell<bool>,
        }
        impl DoSql for MissingReadback {
            fn execute(&self, query: &str, values: &[SqlValue]) -> Result<u64, String> {
                self.inner.execute(query, values)
            }
            fn query(
                &self,
                query: &str,
                values: &[SqlValue],
            ) -> Result<Vec<Vec<SqlValue>>, String> {
                if self.hide.get() && query.contains("FROM tracker_issues WHERE issue_id = ?1") {
                    return Ok(vec![]);
                }
                self.inner.query(query, values)
            }
        }
        let mut store = DoSqliteStore::new(MissingReadback {
            inner: RusqliteDoSql::with_runtime_schema(),
            hide: std::cell::Cell::new(true),
        });
        let outcome = store.file_item(
            "tutorials",
            "Create a chat",
            "",
            &[],
            &serde_json::json!({}),
            Some("person:learner"),
            Some("person:learner"),
        );
        assert!(matches!(outcome, Err(StoreError::Fault { subject, detail })
            if subject == "filed tracker issue"
                && detail == "missing immediately after the write that should have created it"));
        // The write succeeded; the injected read fault must not be mistaken
        // for a retryable conflict. Removing the fault exposes the same issue.
        store.sql.hide.set(false);
        assert_eq!(
            store
                .get_item("WS-1")
                .expect("readback")
                .expect("issue")
                .title,
            "Create a chat"
        );
    }
}
