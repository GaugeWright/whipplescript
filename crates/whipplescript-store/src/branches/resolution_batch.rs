//! Independently receipted resolution knowledge. A later file-save conflict
//! does not undo this effect. These storage identities confer no authority;
//! the host must authorize the exact batch before invoking the branch seam.
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};

pub const CREATE: &str = "CREATE TABLE IF NOT EXISTS resolution_batches (\
    operation_id TEXT PRIMARY KEY, receipt_json TEXT NOT NULL, receipt_hash TEXT NOT NULL)";
pub const SELECT: &str =
    "SELECT receipt_json, receipt_hash FROM resolution_batches WHERE operation_id = ?1";
pub const INSERT: &str = "INSERT INTO resolution_batches \
    (operation_id, receipt_json, receipt_hash) VALUES (?1, ?2, ?3)";
pub const INSERT_MEMORY: &str = "INSERT OR IGNORE INTO resolution_memory \
    (triple_key, resolution, recorded_at) VALUES (?1, ?2, ?3)";
pub const SELECT_MEMORY: &str = "SELECT resolution FROM resolution_memory WHERE triple_key = ?1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionMemoryEntry {
    pub triple_key: String,
    /// Content identity, never the resolution body.
    pub resolution: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionMemoryBatch {
    pub operation_id: String,
    pub actor: String,
    pub intent: String,
    pub recorded_at: String,
    /// Ordered: duplicate keys retain their first winner, including within
    /// this batch. Retrying with a different order changes the meaning.
    pub entries: Vec<ResolutionMemoryEntry>,
}

impl ResolutionMemoryBatch {
    pub fn validate(&self) -> StoreResult<()> {
        let incomplete = [
            &self.operation_id,
            &self.actor,
            &self.intent,
            &self.recorded_at,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
            || self.entries.is_empty()
            || self.entries.iter().any(|entry| {
                entry.triple_key.trim().is_empty() || entry.resolution.trim().is_empty()
            });
        if incomplete {
            return Err(StoreError::Conflict(
                "resolution batch requires operation, actor, intent, time and nonempty entries"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionMemoryOutcome {
    pub triple_key: String,
    pub resolution: String,
    /// True only when this batch inserted this memory entry. Observing an
    /// existing winner does not attribute its original authorship to this actor.
    pub inserted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionMemoryReceipt {
    pub request: ResolutionMemoryBatch,
    /// Actual first-wins content identity for every requested entry, in order.
    pub outcomes: Vec<ResolutionMemoryOutcome>,
}

impl ResolutionMemoryReceipt {
    pub fn check_retry(self, request: &ResolutionMemoryBatch) -> StoreResult<Self> {
        if &self.request != request {
            return Err(StoreError::Conflict(
                "resolution operation already has a different meaning".into(),
            ));
        }
        Ok(self)
    }

    pub fn encode(&self) -> StoreResult<(String, String)> {
        let json = serde_json::to_string(self)?;
        let digest = receipt_hash(&json);
        Ok((json, digest))
    }

    /// Validate persisted evidence before returning it as an outcome. A
    /// contradictory receipt is a store fault, never ordinary contention.
    pub fn decode(operation_id: &str, json: &str, digest: &str) -> StoreResult<Self> {
        let receipt: Self = serde_json::from_str(json)
            .map_err(|error| fault(operation_id, &format!("invalid receipt: {error}")))?;
        let mut winners = std::collections::BTreeMap::new();
        if receipt.request.operation_id != operation_id
            || receipt_hash(json) != digest
            || receipt.request.validate().is_err()
            || receipt.outcomes.len() != receipt.request.entries.len()
            || receipt
                .outcomes
                .iter()
                .zip(&receipt.request.entries)
                .any(|(outcome, entry)| {
                    let previous =
                        winners.insert(outcome.triple_key.as_str(), outcome.resolution.as_str());
                    outcome.triple_key != entry.triple_key
                        || outcome.resolution.trim().is_empty()
                        || outcome.inserted && outcome.resolution != entry.resolution
                        || previous
                            .is_some_and(|winner| outcome.inserted || winner != outcome.resolution)
                })
        {
            return Err(fault(operation_id, "contradictory receipt"));
        }
        Ok(receipt)
    }
}

fn receipt_hash(json: &str) -> String {
    crate::items::sha256_hex(&format!(
        "whipplescript.resolution-memory-receipt.v1\n{json}"
    ))
}

pub fn fault(operation_id: &str, detail: &str) -> StoreError {
    StoreError::Fault {
        subject: format!("resolution batch {operation_id}"),
        detail: detail.into(),
    }
}

#[cfg(feature = "native")]
pub(super) fn native_read(
    connection: &rusqlite::Connection,
    operation_id: &str,
) -> StoreResult<Option<ResolutionMemoryReceipt>> {
    use rusqlite::OptionalExtension;
    let row: Option<(String, String)> = connection
        .query_row(SELECT, [operation_id], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    row.map(|(json, digest)| ResolutionMemoryReceipt::decode(operation_id, &json, &digest))
        .transpose()
}

#[cfg(feature = "native")]
pub(super) fn native_record(
    store: &mut super::BranchStore,
    request: &ResolutionMemoryBatch,
) -> StoreResult<ResolutionMemoryReceipt> {
    use rusqlite::{params, TransactionBehavior};
    request.validate()?;
    let transaction = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    if let Some(receipt) = native_read(&transaction, &request.operation_id)? {
        return receipt.check_retry(request);
    }
    let mut outcomes = Vec::with_capacity(request.entries.len());
    for (index, entry) in request.entries.iter().enumerate() {
        let inserted = transaction.execute(
            INSERT_MEMORY,
            params![entry.triple_key, entry.resolution, request.recorded_at],
        )?;
        let resolution: String =
            transaction.query_row(SELECT_MEMORY, [&entry.triple_key], |row| row.get(0))?;
        if resolution.trim().is_empty() {
            return Err(fault(
                &request.operation_id,
                "invalid remembered content identity",
            ));
        }
        if inserted != 0 {
            // A Vec of entries cannot exceed isize::MAX bytes, so this index
            // fits the SQL integer on every supported target.
            transaction.execute(
                super::resolution_origin::INSERT,
                params![entry.triple_key, request.operation_id, index as i64],
            )?;
        }
        outcomes.push(ResolutionMemoryOutcome {
            triple_key: entry.triple_key.clone(),
            resolution,
            inserted: inserted != 0,
        });
    }
    let receipt = ResolutionMemoryReceipt {
        request: request.clone(),
        outcomes,
    };
    let (json, digest) = receipt.encode()?;
    transaction.execute(INSERT, params![request.operation_id, json, digest])?;
    transaction.commit()?;
    Ok(receipt)
}

/// Shared native/hosted branch-authority conformance, not a mock algorithm.
pub mod conformance;

#[cfg(all(test, feature = "native"))]
mod tests;
