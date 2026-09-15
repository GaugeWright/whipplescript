use super::*;
use crate::native_stores::NativeStores;
use crate::tracker_control::{
    TrackerControl, TrackerControlAction as Action, TrackerControlOutcome as Outcome,
    TrackerControlReceipt, TrackerControls,
};

fn receipt(connection: &Connection, operation: &str) -> StoreResult<Option<TrackerControlReceipt>> {
    let value: Option<String> = connection
        .query_row(
            "SELECT receipt_json FROM tracker_control_receipts WHERE operation_id = ?1",
            [operation],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .transpose()
}

fn future_deadline(tx: &Transaction<'_>, expires: &str, now: &str) -> StoreResult<bool> {
    let canonical: Option<String> =
        tx.query_row("SELECT datetime(?1)", [expires], |row| row.get(0))?;
    if canonical.as_deref() != Some(expires) {
        return Err(StoreError::Conflict(
            "tracker control deadline must use canonical UTC time".into(),
        ));
    }
    Ok(expires > now)
}

fn execute(
    tx: &Transaction<'_>,
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
            if !future_deadline(tx, expires_at, now)? {
                return Ok(Outcome::DeadlineElapsed);
            }
            Ok(
                match control_ops::claim_item(tx, id, actor, Some(expires_at), effect, now)? {
                    ClaimOutcome::Claimed => Outcome::Claimed {
                        expires_at: expires_at.clone(),
                    },
                    ClaimOutcome::AlreadyClaimed { holder } => Outcome::AlreadyClaimed { holder },
                    ClaimOutcome::NotFound => Outcome::NotOpen,
                },
            )
        }
        Action::Renew { expires_at } => {
            if !future_deadline(tx, expires_at, now)? {
                return Ok(Outcome::DeadlineElapsed);
            }
            Ok(
                match control_ops::renew_claim(tx, id, actor, Some(expires_at), effect, now)? {
                    RenewOutcome::Renewed { .. } => Outcome::Renewed {
                        expires_at: expires_at.clone(),
                    },
                    RenewOutcome::NotHeld => Outcome::NotHeld,
                    RenewOutcome::NotMonotonic => Outcome::NotMonotonic,
                },
            )
        }
        Action::Release { expected_holder } => {
            if let Some(holder) = tx_holder_conflict(tx, id, now, expected_holder.as_deref())? {
                return Ok(Outcome::HeldByOther { holder });
            }
            Ok(
                if tx_release_active_lease_by(tx, id, effect, Some(actor), now)? {
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
            let current: Option<String> = tx.query_row(
                "SELECT assigned_to FROM tracker_issues WHERE issue_id = ?1",
                [id],
                |row| row.get(0),
            )?;
            if &current != expected_assignee {
                return Ok(Outcome::AssignmentChanged { assignee: current });
            }
            Ok(
                if control_ops::assign_item(tx, id, assignee.as_deref(), Some(actor), effect, now)?
                {
                    Outcome::Assigned
                } else {
                    Outcome::NotOpen
                },
            )
        }
    }
}

impl TrackerControls for WorkItemStore {
    fn control_receipt(&self, operation: &str) -> StoreResult<Option<TrackerControlReceipt>> {
        receipt(&self.connection, operation)
    }
    fn control_issue_once(
        &mut self,
        request: &TrackerControl,
    ) -> StoreResult<TrackerControlReceipt> {
        match self.protection.clone() {
            Some(protection) => protection.retain(|| self.control_issue_once_retained(request)),
            None => self.control_issue_once_retained(request),
        }
    }
}

impl WorkItemStore {
    fn control_issue_once_retained(
        &mut self,
        request: &TrackerControl,
    ) -> StoreResult<TrackerControlReceipt> {
        let fingerprint = request.fingerprint()?;
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(existing) = receipt(&tx, &request.operation_id)? {
            existing.validate_for(request)?;
            return Ok(existing);
        }
        let subject = content_id_of(&tx, &request.item_id)?;
        let item: Option<(String, String)> = tx
            .query_row(
                "SELECT queue, status FROM tracker_issues WHERE issue_id = ?1",
                [&request.item_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((queue, status)) = item else {
            return Err(StoreError::Conflict(
                "tracker control issue is unavailable".into(),
            ));
        };
        if queue != request.queue || subject.as_deref() != Some(request.subject_id.as_str()) {
            return Err(StoreError::Conflict(
                "tracker control subject differs from its binding".into(),
            ));
        }
        let before: i64 = tx.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM tracker_events",
            [],
            |row| row.get(0),
        )?;
        let now = tx_now(&tx)?;
        let outcome = execute(&tx, request, &status, &now)?;
        let event_ids = tx
            .prepare("SELECT event_id FROM tracker_events WHERE event_seq > ?1 ORDER BY event_seq")?
            .query_map([before], |row| row.get(0))?
            .collect::<Result<Vec<String>, _>>()?;
        let receipt = TrackerControlReceipt {
            operation_id: request.operation_id.clone(),
            fingerprint,
            queue,
            item_id: request.item_id.clone(),
            subject_id: request.subject_id.clone(),
            actor: request.actor.clone(),
            outcome,
            event_ids,
            recorded_at: now,
        };
        receipt.validate_for(request)?;
        tx.execute(
            "INSERT INTO tracker_control_receipts (operation_id, receipt_json) VALUES (?1, ?2)",
            params![request.operation_id, serde_json::to_string(&receipt)?],
        )?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Explicitly add control receipts to a known generation-4 tracker. This is
    /// an admitted host maintenance operation, never a side effect of a read.
    /// Current stores are only validated, not repaired; missing or foreign
    /// stores and a mismatched protection domain are refused before any schema change.
    pub fn upgrade_existing_controls(
        path: impl AsRef<Path>,
        protection: Option<crate::payload_protection::PayloadProtection>,
    ) -> StoreResult<Self> {
        let current = match protection.clone() {
            Some(protection) => Self::open_existing_protected(path.as_ref(), protection),
            None => Self::open_existing(path.as_ref()),
        };
        match current {
            Ok(store) => {
                store.connection.prepare(
                    "SELECT operation_id, receipt_json FROM tracker_control_receipts LIMIT 0",
                )?;
                return Ok(store);
            }
            Err(StoreError::UnsupportedVersion { found: 4, .. }) => {}
            Err(error) => return Err(error),
        }
        let connection = crate::native_existing::open(path.as_ref(), "work-item", 4)?;
        let mut store = Self::from_existing_connection(connection, protection.clone())?;
        let mut upgrade = || -> StoreResult<()> {
            let tx = store
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            crate::native_existing::validate(&tx, "work-item", 4)?;
            tx.execute_batch(crate::tracker_control::SCHEMA)?;
            tx.prepare("SELECT operation_id, receipt_json FROM tracker_control_receipts LIMIT 0")?;
            crate::stamp_satellite_schema(&tx, "work-item", SATELLITE_SCHEMA_VERSION)?;
            tx.commit()?;
            Ok(())
        };
        match protection {
            Some(protection) => protection.retain(upgrade)?,
            None => upgrade()?,
        }
        Ok(store)
    }
}

impl TrackerControls for NativeStores {
    fn control_receipt(&self, operation: &str) -> StoreResult<Option<TrackerControlReceipt>> {
        self.items.control_receipt(operation)
    }
    fn control_issue_once(
        &mut self,
        request: &TrackerControl,
    ) -> StoreResult<TrackerControlReceipt> {
        self.items.control_issue_once(request)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[test]
fn tracker_control_store_and_composite_run_suite() {
    crate::tracker_control::conformance::run_suite(&mut WorkItemStore::open_in_memory().unwrap());
    crate::tracker_control::conformance::run_suite(&mut NativeStores::open_in_memory().unwrap());
}
