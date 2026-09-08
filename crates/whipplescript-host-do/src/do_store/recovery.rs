//! Storage realization of the runtime-owned dispatch coordinates.
use super::*;
use whipplescript_store::effect_recovery::{unverified_dispatch_marker, DispatchMarker};

/// An active NeedsIo continuation may recover its original start receipt only
/// with the same recorded execution. Matching run/lease ids alone cannot make
/// changed input, metadata or action admission the original attempt.
pub(super) fn reattach_run<Sql: DoSql>(sql: &Sql, run: RunStart<'_>) -> StoreResult<StoredEvent> {
    let rows = sql.query(
        "SELECT event_id, sequence, source, event_type, payload_json FROM events WHERE instance_id = ?1 AND idempotency_key = ?2",
        &[text(run.instance_id), text(run.run_id)],
    ).map_err(sql_err)?;
    let row = rows
        .first()
        .ok_or_else(|| StoreError::Conflict("active run has no durable run-start event".into()))?;
    let fingerprint = do_execution_fingerprint(sql, run.instance_id, run.effect_id)?;
    let metadata = inject_execution_fingerprint(&run, run.metadata_json, &fingerprint)?;
    let dispatch = dispatch_marker(sql, run, &fingerprint)?;
    let expected: Value = serde_json::from_str(&run_start_payload(&run, &metadata, &dispatch)?)?;
    let recorded: Value = serde_json::from_str(&as_text(&row[4]))?;
    if as_text(&row[2]) != "kernel"
        || as_text(&row[3]) != "effect.run_started"
        || recorded != expected
    {
        return Err(StoreError::Conflict(
            "active run reattachment changed recorded execution".into(),
        ));
    }
    Ok(StoredEvent {
        event_id: as_text(&row[0]),
        sequence: as_i64(&row[1]),
    })
}

pub(super) fn require_proved_absence<Sql: DoSql>(
    sql: &Sql,
    instance_id: &str,
    effect_id: &str,
) -> StoreResult<()> {
    let rows = sql
        .query(effect_recovery::RECOVERY_EVENTS_SQL, &[text(instance_id)])
        .map_err(sql_err)?;
    let events = rows
        .iter()
        .map(|row| event_view_from_row(row))
        .collect::<Vec<_>>();
    effect_recovery::require_proved_absence(&effect_recovery::fold_attempts(
        instance_id,
        effect_id,
        &events,
    )?)
}

pub(super) fn dispatch_marker<Sql: DoSql>(
    sql: &Sql,
    run: RunStart<'_>,
    fingerprint: &str,
) -> StoreResult<DispatchMarker> {
    let rows = sql.query(
        "SELECT kind, target, input_json, idempotency_key FROM effects WHERE instance_id = ?1 AND effect_id = ?2",
        &[text(run.instance_id), text(run.effect_id)],
    ).map_err(sql_err)?;
    let row = rows
        .first()
        .ok_or_else(|| StoreError::Conflict("external dispatch effect is missing".into()))?;
    let mut marker = unverified_dispatch_marker(
        run,
        &as_text(&row[0]),
        as_opt_text(&row[1]).as_deref(),
        &as_text(&row[2]),
        &as_text(&row[3]),
        fingerprint,
    )?;
    let rows = sql
        .query(
            whipplescript_store::host_actions::ACTION_ADMISSION_PREFIX_SQL,
            &[text(run.instance_id)],
        )
        .map_err(sql_err)?;
    let prefix = rows
        .iter()
        .map(|row| event_chain::OwnedChainEntry {
            event_id: as_text(&row[0]),
            sequence: as_i64(&row[1]),
            event_type: as_text(&row[2]),
            payload_json: as_text(&row[3]),
            occurred_at: as_text(&row[4]),
            source: as_opt_text(&row[5]),
            causation_id: as_opt_text(&row[6]),
            correlation_id: as_opt_text(&row[7]),
            idempotency_key: as_opt_text(&row[8]),
            format_version: as_opt_i64(&row[9]),
        })
        .collect::<Vec<_>>();
    marker.frame.action_admission =
        whipplescript_store::host_actions::dispatch_admission_binding(run.instance_id, &prefix)?;
    Ok(marker)
}

/// A callback's returned success is insufficient: it must have executed. Only
/// explicit policy/capacity denials may commit their denial evidence while
/// returning a refusal, matching the native transaction's commit points.
pub(crate) fn atomic_result<T>(
    sql: &impl DoSql,
    retain_denial: bool,
    body: &mut dyn FnMut() -> StoreResult<T>,
) -> StoreResult<T> {
    let mut outcome = None;
    sql.atomic(&mut || {
        match body() {
            Ok(value) => outcome = Some(Ok(value)),
            Err(error) => {
                let retain_this_denial = retain_denial
                    && matches!(
                        error,
                        StoreError::PolicyBlocked { .. } | StoreError::CapacityBlocked { .. }
                    );
                // REFUSAL: storage and non-denial errors must roll back their writes
                if !retain_this_denial {
                    return Err(error);
                }
                outcome = Some(Err(error));
            }
        }
        Ok(())
    })?;
    outcome.ok_or_else(|| StoreError::Conflict("recovery transaction did not execute".into()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SilentSql;
    impl DoSql for SilentSql {
        fn atomic(&self, _: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            Ok(())
        }
        fn execute(&self, _: &str, _: &[SqlValue]) -> Result<u64, String> {
            panic!("silent bridge")
        }
        fn query(&self, _: &str, _: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            panic!("silent bridge")
        }
    }

    #[test]
    fn external_recovery_cannot_acknowledge_an_unexecuted_transaction() {
        let mut called = false;
        let error = atomic_result(&SilentSql, false, &mut || {
            called = true;
            Ok(())
        })
        .unwrap_err();
        assert!(!called);
        assert!(format!("{error:?}").contains("recovery transaction did not execute"));
    }

    #[test]
    fn external_recovery_retains_only_explicit_denial_evidence() {
        for retain in [false, true] {
            for denial in [false, true] {
                let sql = super::super::test_support::RusqliteDoSql::in_memory();
                sql.execute("CREATE TABLE probe (value TEXT)", &[]).unwrap();
                let result: StoreResult<()> = atomic_result(&sql, retain, &mut || {
                    sql.execute("INSERT INTO probe VALUES ('evidence')", &[])
                        .map_err(sql_err)?;
                    if denial {
                        Err(StoreError::PolicyBlocked {
                            effect_id: "effect".into(),
                            reason: "policy".into(),
                        })
                    } else {
                        Err(StoreError::Conflict("storage failure".into()))
                    }
                });
                assert!(result.is_err());
                assert_eq!(
                    sql.query("SELECT value FROM probe", &[]).unwrap().len(),
                    usize::from(retain && denial)
                );
            }
        }
    }

    #[test]
    fn external_recovery_cannot_record_a_dispatch_for_a_missing_effect() {
        let sql = super::super::test_support::RusqliteDoSql::with_runtime_schema();
        let run = RunStart {
            instance_id: "missing-instance",
            effect_id: "missing-effect",
            run_id: "run",
            provider: "builtin",
            worker_id: "worker",
            lease_id: "lease",
            lease_expires_at: "2030-01-01T00:00:00Z",
            metadata_json: "{}",
        };
        let error = dispatch_marker(&sql, run, "fingerprint").unwrap_err();
        assert!(format!("{error:?}").contains("external dispatch effect is missing"));
    }

    #[test]
    fn external_recovery_do_conformance() {
        let sql = super::super::test_support::RusqliteDoSql::with_runtime_schema();
        whipplescript_store::effect_recovery::conformance::check(&mut DoSqliteStore::new(sql));
    }
}
