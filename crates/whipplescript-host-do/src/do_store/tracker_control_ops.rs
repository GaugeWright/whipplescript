use super::*;

pub(super) fn claim_item(
    sql: &impl DoSql,
    item_id: &str,
    claimed_by: &str,
    expires: Option<&str>,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<ClaimOutcome> {
    let exists = !sql
        .query(
            "SELECT 1 FROM tracker_issues WHERE issue_id = ?1",
            &[text(item_id)],
        )
        .map_err(sql_err)?
        .is_empty();
    if !exists {
        return Ok(ClaimOutcome::NotFound);
    }
    do_expire_stale_leases(sql, item_id, now)?;
    // Exclusivity (tracker-lease I1): grant only when no active lease. The
    // single-writer invocation serializes this check-then-insert.
    if let Some(holder) = do_active_holder(sql, item_id)? {
        return Ok(ClaimOutcome::AlreadyClaimed { holder });
    }
    // The lease's identity IS its `claim.acquired` event (content hash) —
    // merge-stable across clones, matching the native store.
    let content_id = do_content_id(sql, item_id)?
        .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {item_id}")))?;
    // `expires` is an absolute deadline (`None` = no TTL); it records a
    // claim-TTL lease that `ready`/`claim` lazily reclaim once past-due.
    let payload = serde_json::json!({"actor": claimed_by, "expires_at": expires});
    let lease_id = do_tracker_append_raw(
        sql,
        Some(&content_id),
        None,
        "claim.acquired",
        &payload.to_string(),
        Some(claimed_by),
        effect_id,
        now,
    )?;
    sql
            .execute(
                "INSERT INTO tracker_leases (lease_id, issue_id, actor, acquired_at, expires_at, released_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                &[
                    text(&lease_id),
                    text(item_id),
                    text(claimed_by),
                    text(now),
                    opt_text(expires),
                ],
            )
            .map_err(sql_err)?;
    Ok(ClaimOutcome::Claimed)
}

pub(super) fn renew_claim(
    sql: &impl DoSql,
    item_id: &str,
    actor: &str,
    expires: Option<&str>,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<RenewOutcome> {
    let rows = sql
        .query(
            "SELECT lease_id, expires_at FROM tracker_leases \
                 WHERE issue_id = ?1 AND actor = ?2 AND released_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > ?3)",
            &[text(item_id), text(actor), text(now)],
        )
        .map_err(sql_err)?;
    let Some(row) = rows.first() else {
        return Ok(RenewOutcome::NotHeld);
    };
    let lease_id = as_text(&row[0]);
    let current_expires = as_opt_text(&row[1]);
    // Monotonicity (tracker-lease I2): a finite deadline may not move back.
    if let (Some(want), Some(current)) = (expires, current_expires.as_deref()) {
        if want <= current {
            return Ok(RenewOutcome::NotMonotonic);
        }
    }
    let new_expires: Option<String> = match expires {
        Some(want) => Some(want.to_owned()),
        None => current_expires,
    };
    let payload =
        serde_json::json!({"lease_id": lease_id, "actor": actor, "expires_at": new_expires});
    do_tracker_append(
        sql,
        Some(item_id),
        "claim.renewed",
        &payload,
        Some(actor),
        effect_id,
        now,
    )?;
    if expires.is_some() {
        sql.execute(
            "UPDATE tracker_leases SET expires_at = ?2 WHERE lease_id = ?1",
            &[text(&lease_id), opt_text(new_expires.as_deref())],
        )
        .map_err(sql_err)?;
    }
    Ok(RenewOutcome::Renewed {
        expires_at: new_expires,
    })
}
