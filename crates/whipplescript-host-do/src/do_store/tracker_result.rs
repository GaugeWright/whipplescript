use super::*;
use whipplescript_store::tracker_result::{
    DeliveredTrackerResult, RecordedTrackerResult, TrackerClosureResultDelivery,
    TrackerResultDelivery, TrackerResultPublications,
};

impl<Sql: DoSql> TrackerResultPublications for DoSqliteStore<Sql> {
    fn publish_tracker_result(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        delivery: &TrackerResultDelivery,
    ) -> StoreResult<StoredEvent> {
        self.publish_tracker_delivery(
            owner_epoch,
            expected_head,
            &DeliveredTrackerResult::from(delivery.clone()),
        )
    }
    fn publish_tracker_closure_result(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        delivery: &TrackerClosureResultDelivery,
    ) -> StoreResult<StoredEvent> {
        self.publish_tracker_delivery(
            owner_epoch,
            expected_head,
            &DeliveredTrackerResult::from(delivery.clone()),
        )
    }
}

impl<Sql: DoSql> DoSqliteStore<Sql> {
    fn publish_tracker_delivery(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        delivery: &DeliveredTrackerResult,
    ) -> StoreResult<StoredEvent> {
        delivery.validate()?;
        let mut result = None;
        self.sql.atomic(&mut || {
            result = Some(publish(&self.sql, owner_epoch, expected_head, delivery)?);
            Ok(())
        })?;
        result.ok_or_else(|| {
            StoreError::fault(
                "tracker result transaction",
                "reported success without executing",
            )
        })
    }
}

fn publish(
    sql: &impl DoSql,
    owner_epoch: i64,
    expected_head: &str,
    delivery: &DeliveredTrackerResult,
) -> StoreResult<StoredEvent> {
    if do_instance_owner_epoch(sql, delivery.instance_id())? != owner_epoch {
        return Err(StoreError::Conflict(
            "tracker result owner changed before publication".into(),
        ));
    }
    if do_chain_head(sql, delivery.instance_id())?.digest != expected_head {
        return Err(StoreError::Conflict(
            "tracker result history changed before publication".into(),
        ));
    }
    let key = delivery.event_key();
    let existing = sql.query("SELECT event_id, sequence, event_type, payload_json, source FROM events WHERE instance_id=?1 AND idempotency_key=?2",
        &[text(delivery.instance_id()), text(&key)]).map_err(sql_err)?;
    if let Some(row) = existing.first() {
        let recorded: RecordedTrackerResult<DeliveredTrackerResult> =
            serde_json::from_str(&as_text(&row[3]))?;
        if as_text(&row[2]) != delivery.delivery_event()
            || as_opt_text(&row[4]).as_deref() != Some("kernel")
            || recorded.delivery != *delivery
        {
            return Err(StoreError::Conflict(
                "tracker result identity already binds a different delivery".into(),
            ));
        }
        return Ok(StoredEvent {
            event_id: as_text(&row[0]),
            sequence: as_i64(&row[1]),
        });
    }
    let state = sql.query("SELECT i.status, e.kind, e.target, e.status, r.provider, r.status FROM instances i JOIN effects e ON e.instance_id=i.instance_id JOIN runs r ON r.instance_id=e.instance_id AND r.effect_id=e.effect_id WHERE i.instance_id=?1 AND e.effect_id=?2 AND r.run_id=?3",
        &[text(delivery.instance_id()), text(delivery.effect_id()), text(delivery.run_id())]).map_err(sql_err)?;
    let Some(row) = state.first() else {
        return Err(StoreError::Conflict(
            "tracker result original attempt is missing".into(),
        ));
    };
    let run = as_text(&row[5]);
    if as_text(&row[0]) != "running"
        || as_text(&row[1]) != delivery.kind()
        || as_opt_text(&row[2]).as_deref() != delivery.target()
        || as_text(&row[4]) != "queue"
        || !matches!(as_text(&row[3]).as_str(), "running" | "failed")
        || !matches!(
            run.as_str(),
            "running" | "failed" | "lease_expired" | "uncertain"
        )
    {
        return Err(StoreError::Conflict(
            "tracker result cannot advance this workflow or attempt".into(),
        ));
    }
    let starts = sql.query("SELECT sequence, payload_json FROM events WHERE instance_id=?1 AND source='kernel' AND event_type='effect.run_started' AND json_extract(payload_json,'$.run_id')=?2",
        &[text(delivery.instance_id()), text(delivery.run_id())]).map_err(sql_err)?;
    let start = starts.first().ok_or_else(|| {
        StoreError::Conflict("tracker result original dispatch is missing".into())
    })?;
    let evidence = delivery.application_evidence(&serde_json::from_str(&as_text(&start[1]))?)?;
    let later = sql.query("SELECT EXISTS(SELECT 1 FROM events WHERE instance_id=?1 AND source='kernel' AND event_type='effect.run_started' AND sequence>?2 AND json_extract(payload_json,'$.effect_id')=?3)",
        &[text(delivery.instance_id()), int(as_i64(&start[0])), text(delivery.effect_id())]).map_err(sql_err)?;
    if as_i64(&later[0][0]) != 0 {
        return Err(StoreError::Conflict(
            "tracker result has a later competing attempt".into(),
        ));
    }
    let handled = sql.query("SELECT EXISTS(SELECT 1 FROM events WHERE instance_id=?1 AND source='kernel' AND event_type='rule.committed' AND sequence > (SELECT MIN(sequence) FROM events WHERE instance_id=?1 AND source='kernel' AND event_type IN ('effect.terminal','lease.expired') AND json_extract(payload_json,'$.run_id')=?2))",
        &[text(delivery.instance_id()), text(delivery.run_id())]).map_err(sql_err)?;
    let settled = sql.query("SELECT EXISTS(SELECT 1 FROM facts WHERE instance_id=?1 AND key=?2 AND (name=?3 OR (name=?4 AND consumed_at IS NOT NULL)))",
        &[text(delivery.instance_id()), text(delivery.effect_id()), text(delivery.success_name()), text(delivery.failure_name())]).map_err(sql_err)?;
    if as_i64(&handled[0][0]) != 0 || as_i64(&settled[0][0]) != 0 {
        return Err(StoreError::Conflict(
            "tracker result failure may already have been handled".into(),
        ));
    }
    let failures = sql.query("SELECT fact_id FROM facts WHERE instance_id=?1 AND name=?3 AND key=?2 AND consumed_at IS NULL ORDER BY fact_id",
        &[text(delivery.instance_id()), text(delivery.effect_id()), text(delivery.failure_name())]).map_err(sql_err)?;
    let record = RecordedTrackerResult {
        delivery: delivery.clone(),
        consumed_failure_facts: failures.iter().map(|row| as_text(&row[0])).collect(),
        complete_running_attempt: run == "running",
    };
    let payload = serde_json::to_string(&record)?;
    let event = do_append_event_fenced(
        sql,
        owner_epoch,
        expected_head,
        NewEvent {
            instance_id: delivery.instance_id(),
            event_type: delivery.delivery_event(),
            payload_json: &payload,
            source: "kernel",
            causation_id: Some(delivery.run_id()),
            correlation_id: Some(delivery.operation_id()),
            idempotency_key: Some(&key),
        },
    )?;
    do_append_event(
        sql,
        NewEvent {
            instance_id: delivery.instance_id(),
            event_type: "effect.disposition.recorded",
            payload_json: &serde_json::to_string(&evidence)?,
            source: "kernel",
            causation_id: Some(&event.event_id),
            correlation_id: Some(delivery.operation_id()),
            idempotency_key: Some(&format!("{key}:applied")),
        },
    )?;
    apply_result(sql, delivery.instance_id(), &event.event_id, &record)?;
    if record.complete_running_attempt {
        let metadata = delivery.terminal_metadata(&event.event_id);
        let terminal_key = format!("{key}:terminal");
        let completion = EffectCompletion {
            instance_id: delivery.instance_id(),
            effect_id: delivery.effect_id(),
            run_id: delivery.run_id(),
            provider: "queue",
            worker_id: "tracker-recovery",
            status: "completed",
            exit_code: None,
            summary: None,
            metadata_json: &metadata,
            idempotency_key: Some(&terminal_key),
        };
        let payload = effect_completion_payload(&completion, None, "completed")?;
        let terminal = do_append_event(
            sql,
            NewEvent {
                instance_id: delivery.instance_id(),
                event_type: "effect.terminal",
                payload_json: &payload,
                source: "kernel",
                causation_id: Some(&event.event_id),
                correlation_id: None,
                idempotency_key: Some(&terminal_key),
            },
        )?;
        do_replay_effect_terminal(sql, delivery.instance_id(), &terminal.event_id, &payload)?;
    }
    Ok(event)
}

pub(super) fn apply_result(
    sql: &impl DoSql,
    instance: &str,
    event: &str,
    record: &RecordedTrackerResult<DeliveredTrackerResult>,
) -> StoreResult<()> {
    let delivery = &record.delivery;
    if delivery.instance_id() != instance {
        return Err(StoreError::Conflict(
            "tracker result replay instance differs".into(),
        ));
    }
    let failures: Vec<&str> = record
        .consumed_failure_facts
        .iter()
        .map(String::as_str)
        .collect();
    do_consume_facts(sql, instance, &failures)?;
    sql.execute("UPDATE effects SET status='completed', updated_at=(SELECT occurred_at FROM events WHERE event_id=?3) WHERE instance_id=?1 AND effect_id=?2",
        &[text(instance), text(delivery.effect_id()), text(event)]).map_err(sql_err)?;
    do_satisfy_dependencies(sql, instance)?;
    let value = delivery.fact_value().to_string();
    let fact = NewFact {
        fact_id: delivery.fact_id(),
        name: delivery.success_name(),
        key: delivery.effect_id(),
        value_json: &value,
        schema_id: None,
        provenance_class: "external",
        correlation_id: None,
        source_span_json: None,
    };
    let (version, epoch) = do_active_revision(sql, instance)?;
    do_insert_fact(
        sql,
        instance,
        "kernel",
        event,
        version.as_deref(),
        epoch,
        &fact,
    )
}

#[cfg(test)]
mod tests {
    use super::super::test_support::RusqliteDoSql;
    use super::*;

    #[test]
    fn hosted_tracker_result_delivery_preserves_terminal_history_and_replays() {
        for status in ["running", "lease_expired", "failed"] {
            let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
            whipplescript_store::tracker_result::conformance::run_suite(&mut store, status);
        }
    }

    #[test]
    fn hosted_tracker_result_refuses_an_external_redelivery_record() {
        let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        whipplescript_store::tracker_result::conformance::refuse_external_redelivery(&mut store);
    }

    #[test]
    fn hosted_tracker_result_eligibility_ignores_external_event_names() {
        for scenario in ["attempt", "rule", "terminal"] {
            let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
            whipplescript_store::tracker_result::conformance::external_names_do_not_change_eligibility(&mut store, scenario);
        }
    }

    #[test]
    fn every_hosted_tracker_result_sql_failure_rolls_back_before_retry() {
        use super::super::tests::FaultySql;
        for status in ["running", "lease_expired", "failed"] {
            let mut reached_success = false;
            for fail_at in 1..128 {
                let mut base = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
                let delivery =
                    whipplescript_store::tracker_result::conformance::setup(&mut base, status);
                let epoch = base
                    .claim_instance_ownership(&delivery.instance_id)
                    .unwrap();
                let head = base.chain_head(&delivery.instance_id).unwrap();
                let snapshot = |sql: &dyn DoSql| {
                    [
                        "events",
                        "instances",
                        "effects",
                        "runs",
                        "leases",
                        "facts",
                        "effect_dependencies",
                    ]
                    .map(|table| {
                        sql.query(&format!("SELECT * FROM {table} ORDER BY rowid"), &[])
                            .unwrap()
                    })
                };
                let before = snapshot(&base.sql);
                let mut store = DoSqliteStore::new(FaultySql::new(base.sql, fail_at));
                let outcome = store.publish_tracker_result(epoch, &head.digest, &delivery);
                let seen = store.sql.statements_seen();
                store.sql.disarm();
                if outcome.is_ok() {
                    assert!(fail_at > seen, "swallowed SQL failure {fail_at}");
                    assert!(seen > 15, "must exercise projection and history writes");
                    reached_success = true;
                    break;
                }
                assert_eq!(
                    snapshot(&store.sql),
                    before,
                    "{status}: SQL failure {fail_at}"
                );
                assert!(format!("{:?}", outcome.unwrap_err()).contains("injected fault"));
                store
                    .publish_tracker_result(epoch, &head.digest, &delivery)
                    .unwrap();
                assert_eq!(store.list_facts(&delivery.instance_id).unwrap().len(), 1);
            }
            assert!(
                reached_success,
                "did not exhaust {status} publication's SQL boundaries"
            );
        }
    }
    #[test]
    fn hosted_tracker_result_enforces_each_publication_eligibility_condition() {
        use whipplescript_store::tracker_result::conformance;
        for case in conformance::REFUSAL_CASES {
            conformance::refuse_ineligible(
                &mut DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
                case,
            );
        }
    }

    #[test]
    fn hosted_tracker_result_requires_original_dispatch_and_replay_instance() {
        let mut store = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        let delivery =
            whipplescript_store::tracker_result::conformance::setup(&mut store, "failed");
        let epoch = store
            .claim_instance_ownership(&delivery.instance_id)
            .unwrap();
        // Preserve the projection while removing kernel provenance from the
        // purported original start. An untrusted event cannot supply it.
        store
            .sql
            .execute(
                "UPDATE events SET source='external' WHERE event_type='effect.run_started'",
                &[],
            )
            .unwrap();
        let head = store.chain_head(&delivery.instance_id).unwrap();
        let error = store
            .publish_tracker_result(epoch, &head.digest, &delivery)
            .unwrap_err();
        assert!(
            matches!(error, StoreError::Conflict(reason) if reason == "tracker result original dispatch is missing")
        );
        assert_eq!(store.chain_head(&delivery.instance_id).unwrap(), head);
        let record = RecordedTrackerResult {
            delivery,
            consumed_failure_facts: vec![],
            complete_running_attempt: false,
        };
        let error = apply_result(
            &store.sql,
            "different-instance",
            "replay-event",
            &record.into_delivered(),
        )
        .unwrap_err();
        assert!(
            matches!(error, StoreError::Conflict(reason) if reason == "tracker result replay instance differs")
        );
    }

    struct NoCallback(RusqliteDoSql);
    impl DoSql for NoCallback {
        fn atomic(&self, _: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            Ok(())
        }
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.0.execute(sql, params)
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            self.0.query(sql, params)
        }
    }
    #[test]
    fn hosted_tracker_result_refuses_success_without_executing_the_transaction() {
        let mut base = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
        let delivery = whipplescript_store::tracker_result::conformance::setup(&mut base, "failed");
        let epoch = base
            .claim_instance_ownership(&delivery.instance_id)
            .unwrap();
        let head = base.chain_head(&delivery.instance_id).unwrap();
        let mut store = DoSqliteStore::new(NoCallback(base.sql));
        let error = store
            .publish_tracker_result(epoch, &head.digest, &delivery)
            .unwrap_err();
        assert!(
            matches!(error, StoreError::Fault { ref subject, ref detail }
            if subject == "tracker result transaction" && detail == "reported success without executing")
        );
        assert_eq!(store.chain_head(&delivery.instance_id).unwrap(), head);
    }
    #[test]
    fn hosted_tracker_closing_result_preserves_attempts_and_matches_original_dispatch() {
        use whipplescript_store::tracker_result::closing_conformance;
        for status in ["running", "lease_expired", "failed"] {
            closing_conformance::run_suite(
                &mut DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
                status,
            );
        }
        for field in [
            "operation",
            "actor",
            "queue",
            "item",
            "subject",
            "summary",
            "holder",
        ] {
            closing_conformance::refuse_changed_dispatch(
                &mut DoSqliteStore::new(RusqliteDoSql::with_runtime_schema()),
                field,
            );
        }
    }

    #[test]
    fn every_hosted_tracker_closing_result_sql_failure_rolls_back_before_retry() {
        use super::super::tests::FaultySql;
        use whipplescript_store::tracker_result::closing_conformance;
        for status in ["running", "lease_expired", "failed"] {
            let mut finished = false;
            for fail_at in 1..128 {
                let mut base = DoSqliteStore::new(RusqliteDoSql::with_runtime_schema());
                let delivery = closing_conformance::setup(&mut base, status);
                let instance = &delivery.closure.instance_id;
                let owner = base.claim_instance_ownership(instance).unwrap();
                let head = base.chain_head(instance).unwrap();
                let snapshot = |sql: &dyn DoSql| {
                    [
                        "events",
                        "instances",
                        "effects",
                        "runs",
                        "leases",
                        "facts",
                        "effect_dependencies",
                    ]
                    .map(|table| {
                        sql.query(&format!("SELECT * FROM {table} ORDER BY rowid"), &[])
                            .expect("fixture tables")
                    })
                };
                let before = snapshot(&base.sql);
                let mut store = DoSqliteStore::new(FaultySql::new(base.sql, fail_at));
                let outcome = store.publish_tracker_closure_result(owner, &head.digest, &delivery);
                let seen = store.sql.statements_seen();
                store.sql.disarm();
                if outcome.is_ok() {
                    assert!(
                        fail_at > seen,
                        "swallowed closing publication fault {fail_at}"
                    );
                    assert!(seen > 15);
                    finished = true;
                    break;
                }
                assert_eq!(snapshot(&store.sql), before, "{status}: SQL {fail_at}");
                assert!(format!("{:?}", outcome.unwrap_err()).contains("injected fault"));
                store
                    .publish_tracker_closure_result(owner, &head.digest, &delivery)
                    .unwrap();
            }
            assert!(finished, "must exhaust closing publication SQL boundaries");
        }
    }
}
