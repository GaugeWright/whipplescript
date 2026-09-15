use super::*;
use whipplescript_store::tracker_control::{
    TrackerControl, TrackerControlAction as Action, TrackerControlOutcome as Outcome,
    TrackerControlReceipt, TrackerControls,
};

fn receipt(sql: &impl DoSql, operation: &str) -> StoreResult<Option<TrackerControlReceipt>> {
    let rows = sql
        .query(
            "SELECT receipt_json FROM tracker_control_receipts WHERE operation_id = ?1",
            &[text(operation)],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|row| serde_json::from_str(&as_text(&row[0])).map_err(Into::into))
        .transpose()
}
fn future_deadline(sql: &impl DoSql, expires: &str, now: &str) -> StoreResult<bool> {
    let rows = sql
        .query("SELECT datetime(?1)", &[text(expires)])
        .map_err(sql_err)?;
    if as_opt_text(&rows[0][0]).as_deref() != Some(expires) {
        return Err(StoreError::Conflict(
            "tracker control deadline must use canonical UTC time".into(),
        ));
    }
    Ok(expires > now)
}
fn execute(
    sql: &impl DoSql,
    request: &TrackerControl,
    status: &str,
    now: &str,
) -> StoreResult<Outcome> {
    let id = request.item_id.as_str();
    let actor = request.actor.as_str();
    let effect = Some(request.effect_id.as_str());
    match &request.action {
        Action::Claim { expires_at } => {
            if status != "open" {
                return Ok(Outcome::NotOpen);
            }
            if !future_deadline(sql, expires_at, now)? {
                return Ok(Outcome::DeadlineElapsed);
            }
            Ok(
                match tracker_control_ops::claim_item(
                    sql,
                    id,
                    actor,
                    Some(expires_at),
                    effect,
                    now,
                )? {
                    ClaimOutcome::Claimed => Outcome::Claimed {
                        expires_at: expires_at.clone(),
                    },
                    ClaimOutcome::AlreadyClaimed { holder } => Outcome::AlreadyClaimed { holder },
                    ClaimOutcome::NotFound => Outcome::NotOpen,
                },
            )
        }
        Action::Renew { expires_at } => {
            if !future_deadline(sql, expires_at, now)? {
                return Ok(Outcome::DeadlineElapsed);
            }
            Ok(
                match tracker_control_ops::renew_claim(
                    sql,
                    id,
                    actor,
                    Some(expires_at),
                    effect,
                    now,
                )? {
                    RenewOutcome::Renewed { .. } => Outcome::Renewed {
                        expires_at: expires_at.clone(),
                    },
                    RenewOutcome::NotHeld => Outcome::NotHeld,
                    RenewOutcome::NotMonotonic => Outcome::NotMonotonic,
                },
            )
        }
        Action::Release { expected_holder } => {
            if let Some(holder) = do_holder_conflict(sql, id, now, expected_holder.as_deref())? {
                return Ok(Outcome::HeldByOther { holder });
            }
            Ok(
                if do_release_active_lease_by(sql, id, effect, Some(actor), now)? {
                    Outcome::Released
                } else {
                    Outcome::NotHeld
                },
            )
        }
        Action::Assign {
            expected_assignee,
            assignee,
        } => {
            if status != "open" {
                return Ok(Outcome::NotOpen);
            }
            let rows = sql
                .query(
                    "SELECT assigned_to FROM tracker_issues WHERE issue_id = ?1",
                    &[text(id)],
                )
                .map_err(sql_err)?;
            let current = as_opt_text(&rows[0][0]);
            if &current != expected_assignee {
                return Ok(Outcome::AssignmentChanged { assignee: current });
            }
            do_tracker_append(
                sql,
                Some(id),
                "issue.assigned",
                &serde_json::json!({"assigned_to": assignee}),
                Some(actor),
                effect,
                now,
            )?;
            sql.execute(
                "UPDATE tracker_issues SET assigned_to = ?2, updated_at = ?3 WHERE issue_id = ?1",
                &[text(id), opt_text(assignee.as_deref()), text(now)],
            )
            .map_err(sql_err)?;
            Ok(Outcome::Assigned)
        }
    }
}
impl<Sql: DoSql> TrackerControls for DoSqliteStore<Sql> {
    fn control_receipt(&self, operation: &str) -> StoreResult<Option<TrackerControlReceipt>> {
        receipt(&self.sql, operation)
    }
    fn control_issue_once(
        &mut self,
        request: &TrackerControl,
    ) -> StoreResult<TrackerControlReceipt> {
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
                    "tracker control issue is unavailable".into(),
                ));
            };
            if as_text(&row[0]) != request.queue
                || subject.as_deref() != Some(request.subject_id.as_str())
            {
                return Err(StoreError::Conflict(
                    "tracker control subject differs from its binding".into(),
                ));
            }
            let rows_before = self
                .sql
                .query(
                    "SELECT COALESCE(MAX(event_seq), 0) FROM tracker_events",
                    &[],
                )
                .map_err(sql_err)?;
            let before = as_i64(&rows_before[0][0]);
            let now = do_now(&self.sql)?;
            let outcome = execute(&self.sql, request, &as_text(&row[1]), &now)?;
            let rows = self
                .sql
                .query(
                    "SELECT event_id FROM tracker_events WHERE event_seq > ?1 ORDER BY event_seq",
                    &[SqlValue::Int(before)],
                )
                .map_err(sql_err)?;
            let receipt = TrackerControlReceipt {
                operation_id: request.operation_id.clone(),
                fingerprint: fingerprint.clone(),
                queue: request.queue.clone(),
                item_id: request.item_id.clone(),
                subject_id: request.subject_id.clone(),
                actor: request.actor.clone(),
                outcome,
                event_ids: rows.iter().map(|row| as_text(&row[0])).collect(),
                recorded_at: now,
            };
            receipt.validate_for(request)?;
            self.sql.execute("INSERT INTO tracker_control_receipts (operation_id, receipt_json) VALUES (?1, ?2)", &[text(&request.operation_id), text(&serde_json::to_string(&receipt)?)]).map_err(sql_err)?;
            Ok(receipt)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::RusqliteDoSql;
    use super::*;
    #[test]
    fn hosted_tracker_control_conformance() {
        whipplescript_store::tracker_control::conformance::run_suite(&mut DoSqliteStore::new(
            RusqliteDoSql::with_runtime_schema(),
        ));
    }

    #[test]
    fn hosted_tracker_control_refusals() {
        for case in whipplescript_store::tracker_control::conformance::REFUSAL_CASES {
            whipplescript_store::tracker_control::conformance::refuse(
                &mut DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
                case,
            );
        }
    }
    #[test]
    fn every_hosted_tracker_control_sql_failure_rolls_back_before_retry() {
        use super::super::tests::FaultySql;
        use whipplescript_store::tracker_control::conformance::{next, setup};
        for (number, action) in [
            (
                1,
                Action::Claim {
                    expires_at: "2090-01-01 00:00:00".into(),
                },
            ),
            (
                2,
                Action::Renew {
                    expires_at: "2091-01-01 00:00:00".into(),
                },
            ),
            (
                3,
                Action::Release {
                    expected_holder: Some("alice".into()),
                },
            ),
            (
                4,
                Action::Assign {
                    expected_assignee: Some("alice".into()),
                    assignee: Some("bob".into()),
                },
            ),
        ] {
            let mut reached_success = false;
            for fail_at in 1..=100 {
                let mut base = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
                let request = setup(&mut base);
                if number == 2 || number == 3 {
                    base.control_issue_once(&request).unwrap();
                }
                let request = next(&request, number + 10, "alice", action.clone());
                let before = base.event_position().unwrap();
                let item = base.get_item(&request.item_id).unwrap();
                let mut store = DoSqliteStore::new(FaultySql::new(base.sql, fail_at));
                let outcome = store.control_issue_once(&request);
                store.sql.disarm();
                if outcome.is_ok() {
                    assert!(fail_at > 8);
                    reached_success = true;
                    break;
                }
                assert_eq!(
                    store.event_position().unwrap(),
                    before,
                    "action {number} SQL {fail_at}"
                );
                assert_eq!(store.get_item(&request.item_id).unwrap(), item);
                assert!(store
                    .control_receipt(&request.operation_id)
                    .unwrap()
                    .is_none());
                store.control_issue_once(&request).unwrap();
            }
            assert!(reached_success);
        }
    }

    #[test]
    fn hosted_tracker_control_shared_claim_helper_refuses_missing_permanent_identity() {
        let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        let request = whipplescript_store::tracker_control::conformance::setup(&mut store);
        store
            .sql
            .execute(
                "DELETE FROM tracker_aliases WHERE alias = ?1",
                &[text(&request.item_id)],
            )
            .unwrap();
        assert!(
            matches!(store.claim_item(&request.item_id, "alice", None), Err(StoreError::Conflict(message)) if message == format!("unknown issue alias {}", request.item_id))
        );
    }
}
