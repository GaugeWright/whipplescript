use super::*;
use whipplescript_store::tracker_membership::{
    MembershipChange, MembershipOutcome, TrackerMembership, TrackerMembershipReceipt,
    TrackerMemberships,
};

fn receipt(sql: &impl DoSql, operation_id: &str) -> StoreResult<Option<TrackerMembershipReceipt>> {
    let rows = sql
        .query(
            "SELECT receipt_json FROM tracker_control_receipts WHERE operation_id = ?1",
            &[text(operation_id)],
        )
        .map_err(sql_err)?;
    rows.first()
        .map(|row| serde_json::from_str(&as_text(&row[0])).map_err(Into::into))
        .transpose()
}

impl<Sql: DoSql> TrackerMemberships for DoSqliteStore<Sql> {
    fn membership_receipt(
        &self,
        operation_id: &str,
    ) -> StoreResult<Option<TrackerMembershipReceipt>> {
        receipt(&self.sql, operation_id)
    }

    fn change_membership_once(
        &mut self,
        request: &TrackerMembership,
    ) -> StoreResult<TrackerMembershipReceipt> {
        let fingerprint = request.fingerprint()?;
        recovery::atomic_result(&self.sql, false, &mut || {
            if let Some(existing) = receipt(&self.sql, &request.operation_id)? {
                existing.validate_for(request)?;
                return Ok(existing);
            }
            for (id, queue, subject, expected_kind) in [
                (
                    request.task_id.as_str(),
                    request.task_queue.as_str(),
                    request.task_subject_id.as_str(),
                    "task",
                ),
                (
                    request.initiative_id.as_str(),
                    request.initiative_queue.as_str(),
                    request.initiative_subject_id.as_str(),
                    "initiative",
                ),
            ] {
                let rows = self
                    .sql
                    .query(
                        "SELECT queue FROM tracker_issues WHERE issue_id = ?1",
                        &[text(id)],
                    )
                    .map_err(sql_err)?;
                if rows.first().map(|row| as_text(&row[0])).as_deref() != Some(queue)
                    || do_content_id(&self.sql, id)?.as_deref() != Some(subject)
                    || readiness::issue_kind(&self.sql, id)? != Some(expected_kind)
                {
                    return Err(StoreError::Conflict(
                        "initiative membership endpoints differ from their binding".into(),
                    ));
                }
            }
            let present = !self
                .sql
                .query(
                    "SELECT 1 FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = 'belongs-to'",
                    &[text(&request.task_id), text(&request.initiative_id)],
                )
                .map_err(sql_err)?
                .is_empty();
            let now = do_now(&self.sql)?;
            let (outcome, event_ids) = match request.change {
                MembershipChange::Add if present => (MembershipOutcome::AlreadyMember, Vec::new()),
                MembershipChange::Add => {
                    let payload = serde_json::json!({
                        "from": request.task_subject_id,
                        "to": request.initiative_subject_id,
                        "kind": "belongs-to",
                        "dep_kind": null,
                    });
                    let event = do_tracker_append_raw(
                        &self.sql,
                        Some(&request.initiative_subject_id),
                        None,
                        "relation.added",
                        &payload.to_string(),
                        Some(&request.actor),
                        Some(&request.effect_id),
                        &now,
                    )?;
                    self.sql
                        .execute(
                            "INSERT INTO tracker_relations (from_issue, to_issue, kind, dep_kind) VALUES (?1, ?2, 'belongs-to', NULL)",
                            &[text(&request.task_id), text(&request.initiative_id)],
                        )
                        .map_err(sql_err)?;
                    (MembershipOutcome::Added, vec![event])
                }
                MembershipChange::Remove => {
                    let payload = serde_json::json!({
                        "from": request.task_subject_id,
                        "to": request.initiative_subject_id,
                        "kind": "belongs-to",
                    });
                    let event = do_tracker_append_raw(
                        &self.sql,
                        Some(&request.initiative_subject_id),
                        None,
                        "relation.removed",
                        &payload.to_string(),
                        Some(&request.actor),
                        Some(&request.effect_id),
                        &now,
                    )?;
                    self.sql
                        .execute(
                            "DELETE FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = 'belongs-to'",
                            &[text(&request.task_id), text(&request.initiative_id)],
                        )
                        .map_err(sql_err)?;
                    (
                        MembershipOutcome::Removed {
                            was_member: present,
                        },
                        vec![event],
                    )
                }
            };
            let receipt = TrackerMembershipReceipt {
                operation_id: request.operation_id.clone(),
                fingerprint: fingerprint.clone(),
                task_id: request.task_id.clone(),
                initiative_id: request.initiative_id.clone(),
                outcome,
                event_ids,
                recorded_at: now,
            };
            receipt.validate_for(request)?;
            self.sql
                .execute(
                    "INSERT INTO tracker_control_receipts (operation_id, receipt_json) VALUES (?1, ?2)",
                    &[text(&request.operation_id), text(&serde_json::to_string(&receipt)?)],
                )
                .map_err(sql_err)?;
            Ok(receipt)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::RusqliteDoSql;
    use super::super::tests::FaultySql;
    use super::*;

    #[test]
    fn hosted_membership_recovery_matches_native_contract() {
        whipplescript_store::tracker_membership::conformance::run_suite(
            &mut DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
            |store, task, initiative| {
                !store.sql.query(
                    "SELECT 1 FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = 'belongs-to'",
                    &[text(task), text(initiative)],
                ).expect("test operation").is_empty()
            },
        );
    }

    #[test]
    fn hosted_inspection_refuses_a_relation_to_an_unavailable_member() {
        let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        let initiative = store
            .file_item(
                "company",
                "group",
                "outcome",
                &[],
                &serde_json::json!({"kind":"initiative"}),
                None,
                None,
            )
            .expect("initiative");
        store
            .sql
            .execute(
                "INSERT INTO tracker_relations (from_issue, to_issue, kind) VALUES (?1, ?2, 'belongs-to')",
                &[text("WS-missing"), text(&initiative.id)],
            )
            .expect("corrupt projection");
        let error = store
            .inspect_initiative_at(&initiative.id, "2030-01-01T00:00:00Z")
            .expect_err("missing member must be refused");
        assert!(format!("{error:?}").contains("initiative member WS-missing is unavailable"));
    }

    #[test]
    fn hosted_membership_sql_failures_leave_no_partial_event_edge_or_receipt() {
        let mut reached_success = false;
        for fail_at in 1..=60 {
            let mut base = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
            let task = base
                .file_item(
                    "engineering",
                    "task",
                    "work",
                    &[],
                    &serde_json::json!({}),
                    None,
                    None,
                )
                .expect("test operation");
            let initiative = base
                .file_item(
                    "company",
                    "group",
                    "outcome",
                    &[],
                    &serde_json::json!({"kind":"initiative"}),
                    None,
                    None,
                )
                .expect("test operation");
            let request = TrackerMembership {
                operation_id: "membership-fault".into(),
                instance_id: "run".into(),
                effect_id: "effect".into(),
                actor: "agent".into(),
                task_id: task.id.clone(),
                task_queue: task.queue,
                task_subject_id: base
                    .subject_content_id(&task.id)
                    .expect("test operation")
                    .expect("test operation"),
                initiative_id: initiative.id.clone(),
                initiative_queue: initiative.queue,
                initiative_subject_id: base
                    .subject_content_id(&initiative.id)
                    .expect("test operation")
                    .expect("test operation"),
                change: MembershipChange::Add,
            };
            let before = base.event_position().expect("test operation");
            let mut store = DoSqliteStore::new(FaultySql::new(base.sql, fail_at));
            let outcome = store.change_membership_once(&request);
            store.sql.disarm();
            if outcome.is_ok() {
                reached_success = true;
                break;
            }
            assert_eq!(
                store.event_position().expect("test operation"),
                before,
                "SQL {fail_at}"
            );
            assert!(store
                .membership_receipt(&request.operation_id)
                .expect("test operation")
                .is_none());
            assert!(store.sql.query(
                "SELECT 1 FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = 'belongs-to'",
                &[text(&request.task_id), text(&request.initiative_id)],
            ).expect("test operation").is_empty());
            assert_eq!(
                store
                    .change_membership_once(&request)
                    .expect("test operation")
                    .outcome,
                MembershipOutcome::Added
            );
        }
        assert!(
            reached_success,
            "the sweep must reach a successful SQL boundary"
        );
    }
}
