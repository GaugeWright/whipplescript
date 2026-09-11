//! A provider reattachment receipt is not permission to issue new sink I/O.
use super::*;

pub(super) fn start<S: DoSql>(
    store: &DoSqliteStore<S>,
    run: RunStart<'_>,
    expected: Option<&ClaimableEffect>,
) -> StoreResult<StoredEvent> {
    recovery::atomic_result(&store.sql, true, &mut || start_on(store, run, expected))
}

/// Caller owns the transaction, including ordinary policy/capacity denials.
pub(super) fn start_on<S: DoSql>(
    store: &DoSqliteStore<S>,
    run: RunStart<'_>,
    expected: Option<&ClaimableEffect>,
) -> StoreResult<StoredEvent> {
    if let Some(expected) = expected {
        let observed = observe(store, run)?;
        whipplescript_store::dispatch_definition::check(expected, observed.as_ref())?;
    }
    let existing = store
        .sql
        .query(
            "SELECT 1 FROM runs WHERE run_id = ?1 UNION ALL \
         SELECT 1 FROM events WHERE instance_id = ?2 AND idempotency_key = ?1 LIMIT 1",
            &[text(run.run_id), text(run.instance_id)],
        )
        .map_err(sql_err)?;
    if !existing.is_empty() {
        return Err(StoreError::Conflict(
            "run already dispatched; reattachment cannot authorize new I/O".into(),
        ));
    }
    store.start_run_on(run)
}

pub(super) fn observe<S: DoSql>(
    store: &DoSqliteStore<S>,
    run: RunStart<'_>,
) -> StoreResult<Option<ClaimableEffect>> {
    let rows = store
        .sql
        .query(
            whipplescript_store::dispatch_definition::SELECT,
            &[text(run.instance_id), text(run.effect_id)],
        )
        .map_err(sql_err)?;
    Ok(rows.first().map(|row| ClaimableEffect {
        effect_id: as_text(&row[0]),
        kind: as_text(&row[1]),
        target: as_opt_text(&row[2]),
        profile: as_opt_text(&row[3]),
        input_json: as_text(&row[4]),
        required_capabilities_json: as_text(&row[5]),
        declared_profiles_json: as_text(&row[6]),
    }))
}
