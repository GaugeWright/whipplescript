use super::*;

pub(super) fn claim_item(
    tx: &Transaction<'_>,
    item_id: &str,
    claimed_by: &str,
    expires: Option<&str>,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<ClaimOutcome> {
    let exists: bool = tx
        .query_row(
            "SELECT 1 FROM tracker_issues WHERE issue_id = ?1",
            [item_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if !exists {
        return Ok(ClaimOutcome::NotFound);
    }
    tx_expire_stale_leases(tx, item_id, now)?;
    if let Some(holder) = tx_active_holder(tx, item_id, now)? {
        return Ok(ClaimOutcome::AlreadyClaimed { holder });
    }
    // No active lease: grant. The lease's identity IS its `claim.acquired`
    // event (content hash) — like comments/evidence, so ids from different
    // clones can never collide on merge and rebuild re-derives the same id
    // from the log. (Alias-derived `L-{alias}-{n}` ids collided across
    // clones: both mint `L-WS-1-0`, and the import fold's INSERT OR IGNORE
    // silently destroyed one lease.) A plain claim writes NO durable
    // status — readiness changes through the lease overlay.
    let content_id = content_id_of(tx, item_id)?
        .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {item_id}")))?;
    let payload = json!({"actor": claimed_by, "expires_at": expires});
    let lease_id = tx_append_raw(
        tx,
        Some(&content_id),
        None,
        "claim.acquired",
        &payload.to_string(),
        Some(claimed_by),
        effect_id,
        now,
    )?;
    tx.execute(
        "INSERT INTO tracker_leases (lease_id, issue_id, actor, acquired_at, expires_at, released_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
        params![lease_id, item_id, claimed_by, now, expires],
    )?;
    Ok(ClaimOutcome::Claimed)
}

pub(super) fn renew_claim(
    tx: &Transaction<'_>,
    item_id: &str,
    actor: &str,
    expires: Option<&str>,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<RenewOutcome> {
    let lease: Option<(String, Option<String>)> = tx
        .query_row(
            &format!(
                "SELECT lease_id, expires_at FROM tracker_leases \
                 WHERE issue_id = ?1 AND actor = ?2 AND {ACTIVE_LEASE}"
            ),
            params![item_id, actor, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((lease_id, current_expires)) = lease else {
        return Ok(RenewOutcome::NotHeld);
    };
    // Monotonicity: a finite deadline may not move backward. NULL (no TTL)
    // accepts a first finite deadline — the holder is voluntarily timing
    // its own lease, which the Maude model (Nat-only expiry) does not cover.
    if let (Some(want), Some(current)) = (expires, current_expires.as_deref()) {
        if want <= current {
            return Ok(RenewOutcome::NotMonotonic);
        }
    }
    let new_expires: Option<String> = match expires {
        Some(want) => Some(want.to_owned()),
        None => current_expires,
    };
    let payload = json!({"lease_id": lease_id, "actor": actor, "expires_at": new_expires});
    tx_append_event(
        tx,
        Some(item_id),
        "claim.renewed",
        &payload,
        Some(actor),
        effect_id,
        now,
    )?;
    if expires.is_some() {
        tx.execute(
            "UPDATE tracker_leases SET expires_at = ?2 WHERE lease_id = ?1",
            params![lease_id, new_expires],
        )?;
    }
    Ok(RenewOutcome::Renewed {
        expires_at: new_expires,
    })
}

pub(super) fn assign_item(
    tx: &Transaction<'_>,
    item_id: &str,
    assignee: Option<&str>,
    event_actor: Option<&str>,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<bool> {
    let status: Option<String> = tx
        .query_row(
            "SELECT status FROM tracker_issues WHERE issue_id = ?1",
            [item_id],
            |row| row.get(0),
        )
        .optional()?;
    if status.as_deref() != Some("open") {
        return Ok(false);
    }
    let payload = json!({ "assigned_to": assignee });
    tx_append_event(
        tx,
        Some(item_id),
        "issue.assigned",
        &payload,
        event_actor,
        effect_id,
        now,
    )?;
    tx.execute(
        "UPDATE tracker_issues SET assigned_to = ?2, updated_at = ?3 WHERE issue_id = ?1",
        params![item_id, assignee, now],
    )?;
    Ok(true)
}
