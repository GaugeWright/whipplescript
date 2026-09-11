use super::*;
use whipplescript_store::tracker_closure::{
    TrackerClosure, TrackerClosureReceipt, TrackerClosures,
};

fn receipt(sql: &impl DoSql, operation: &str) -> StoreResult<Option<TrackerClosureReceipt>> {
    let rows = sql
        .query(
            "SELECT receipt_json FROM tracker_closure_receipts WHERE operation_id = ?1",
            &[text(operation)],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|row| serde_json::from_str(&as_text(&row[0])).map_err(Into::into))
        .transpose()
}

impl<Sql: DoSql> TrackerClosures for DoSqliteStore<Sql> {
    fn closing_receipt(&self, operation: &str) -> StoreResult<Option<TrackerClosureReceipt>> {
        receipt(&self.sql, operation)
    }

    fn close_issue_once(&mut self, request: &TrackerClosure) -> StoreResult<TrackerClosureReceipt> {
        let fingerprint = request.fingerprint()?;
        recovery::atomic_result(&self.sql, false, &mut || {
            if let Some(existing) = receipt(&self.sql, &request.operation_id)? {
                existing.validate_for(request)?;
                return Ok(existing);
            }
            let subject = do_content_id(&self.sql, &request.item_id)?;
            let rows = self
                .sql
                .query(
                    "SELECT queue, status FROM tracker_issues WHERE issue_id = ?1",
                    &[text(&request.item_id)],
                )
                .map_err(sql_err)?;
            let Some(row) = rows.first() else {
                return Err(StoreError::Conflict(
                    "tracker closure issue is unavailable".into(),
                ));
            };
            if as_text(&row[0]) != request.queue
                || subject.as_deref() != Some(request.subject_id.as_str())
            {
                return Err(StoreError::Conflict(
                    "tracker closure subject differs from its binding".into(),
                ));
            }
            if as_text(&row[1]) != "open" {
                return Err(StoreError::Conflict(
                    "tracker closure issue is not open".into(),
                ));
            }
            let now = do_now(&self.sql)?;
            if do_holder_conflict(
                &self.sql,
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
            let event_id = do_tracker_append_raw(
                &self.sql,
                Some(&request.subject_id),
                None,
                "issue.closed",
                &request.event_payload(&fingerprint).to_string(),
                Some(&request.actor),
                Some(&request.effect_id),
                &now,
            )?;
            self.sql.execute(
                "UPDATE tracker_issues SET status = 'closed', claim_summary = ?2, updated_at = ?3 WHERE issue_id = ?1",
                &[text(&request.item_id), opt_text(request.summary.as_deref()), text(&now)],
            ).map_err(sql_err)?;
            do_release_active_lease_by(
                &self.sql,
                &request.item_id,
                Some(&request.effect_id),
                Some(&request.actor),
                &now,
            )?;
            let receipt = TrackerClosureReceipt {
                operation_id: request.operation_id.clone(),
                fingerprint: fingerprint.clone(),
                queue: request.queue.clone(),
                item_id: request.item_id.clone(),
                subject_id: request.subject_id.clone(),
                actor: request.actor.clone(),
                event_id,
                closed_at: now,
            };
            self.sql.execute(
                "INSERT INTO tracker_closure_receipts (operation_id, receipt_json) VALUES (?1, ?2)",
                &[text(&request.operation_id), text(&serde_json::to_string(&receipt)?)],
            ).map_err(sql_err)?;
            Ok(receipt)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::RusqliteDoSql;
    use super::*;

    #[test]
    fn hosted_tracker_closing_records_the_actor_and_retries_after_reopen() {
        let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        let request =
            whipplescript_store::tracker_closure::conformance::setup(&mut store, "agent:assistant");
        store
            .claim_item(&request.item_id, "workflow:holder", None)
            .unwrap();
        let receipt = store.close_issue_once(&request).unwrap();
        let release = store.sql.query("SELECT actor, effect_id, payload_json FROM tracker_events WHERE kind = 'claim.released'", &[]).unwrap();
        assert_eq!(release.len(), 1);
        assert_eq!(as_text(&release[0][0]), request.actor);
        assert_eq!(as_text(&release[0][1]), request.effect_id);
        assert_eq!(
            serde_json::from_str::<Value>(&as_text(&release[0][2])).unwrap()["actor"],
            "workflow:holder"
        );
        let rows = store
            .sql
            .query(
                "SELECT actor, effect_id, payload_json FROM tracker_events WHERE event_id = ?1",
                &[text(&receipt.event_id)],
            )
            .unwrap();
        assert_eq!(as_text(&rows[0][0]), request.actor);
        assert_eq!(as_text(&rows[0][1]), request.effect_id);
        let payload: Value = serde_json::from_str(&as_text(&rows[0][2])).unwrap();
        assert_eq!(payload["operation"]["instance_id"], request.instance_id);
        assert_eq!(payload["operation"]["fingerprint"], receipt.fingerprint);
        store.set_field(&request.item_id, "status", "open").unwrap();
        store.rebuild_tracker_projection().unwrap();
        let before = store.event_position().unwrap();
        assert_eq!(store.close_issue_once(&request).unwrap(), receipt);
        assert_eq!(
            store.get_item(&request.item_id).unwrap().unwrap().status,
            "open"
        );
        assert_eq!(store.event_position().unwrap(), before);
    }

    #[test]
    fn hosted_tracker_closure_conformance() {
        for actor in ["person:learner", "agent:assistant"] {
            let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
            whipplescript_store::tracker_closure::conformance::run(&mut store, actor);
        }
        for case in whipplescript_store::tracker_closure::conformance::REFUSAL_CASES {
            let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
            whipplescript_store::tracker_closure::conformance::refuse(&mut store, case);
        }
    }

    #[test]
    fn every_hosted_tracker_closure_sql_failure_rolls_back_before_retry() {
        use super::super::tests::FaultySql;
        let mut reached_success = false;
        for fail_at in 1..=80 {
            let mut base = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
            let request = whipplescript_store::tracker_closure::conformance::setup(
                &mut base,
                "person:learner",
            );
            base.claim_item(&request.item_id, "workflow:holder", None)
                .unwrap();
            let before = base.event_position().unwrap();
            let item = base.get_item(&request.item_id).unwrap();
            let mut store = DoSqliteStore::new(FaultySql::new(base.sql, fail_at));
            let outcome = store.close_issue_once(&request);
            store.sql.disarm();
            if outcome.is_ok() {
                assert!(fail_at > 8, "exercise all mutation boundaries");
                reached_success = true;
                break;
            }
            assert_eq!(store.event_position().unwrap(), before, "SQL {fail_at}");
            assert_eq!(
                store.get_item(&request.item_id).unwrap(),
                item,
                "SQL {fail_at}"
            );
            assert_eq!(store.closing_receipt(&request.operation_id).unwrap(), None);
            store.close_issue_once(&request).unwrap();
        }
        assert!(reached_success);
    }
}
