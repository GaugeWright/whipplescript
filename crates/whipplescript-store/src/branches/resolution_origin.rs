//! The inserting batch is a resolution's origin; later observers are not its
//! authors. A single keyed SQL snapshot binds memory, index and receipt.
use super::resolution_batch::{fault, ResolutionMemoryReceipt};
use crate::StoreResult;
use serde::{Deserialize, Serialize};

pub const CREATE: &str = "CREATE TABLE IF NOT EXISTS resolution_origins (\
    triple_key TEXT PRIMARY KEY, operation_id TEXT NOT NULL, outcome_index INTEGER NOT NULL)";
pub const INSERT: &str = "INSERT INTO resolution_origins \
    (triple_key, operation_id, outcome_index) VALUES (?1, ?2, ?3)";
pub const SELECT: &str = "SELECT m.resolution, o.operation_id, o.outcome_index, \
    b.receipt_json, b.receipt_hash FROM (SELECT ?1 AS triple_key) AS k \
    LEFT JOIN resolution_memory m ON m.triple_key = k.triple_key \
    LEFT JOIN resolution_origins o ON o.triple_key = k.triple_key \
    LEFT JOIN resolution_batches b ON b.operation_id = o.operation_id";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionOrigin {
    pub operation_id: String,
    pub receipt_hash: String,
    pub outcome_index: u64,
}

/// Evidence, not authority. Unindexed rows can have older receipts elsewhere;
/// absence of an origin link must not fabricate an attribution or a new grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "snake_case",
    deny_unknown_fields,
    from = "ResolutionObservationWire"
)]
pub enum ResolutionObservation {
    Missing,
    OriginUnavailable {
        content_hash: String,
    },
    Recorded {
        content_hash: String,
        origin: ResolutionOrigin,
    },
}

// Serde's internally tagged unit variant accepts extra members even with
// deny_unknown_fields. Use an empty struct variant at the wire boundary so a
// future constraint on a missing observation cannot silently disappear.
#[derive(Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ResolutionObservationWire {
    Missing {},
    OriginUnavailable {
        content_hash: String,
    },
    Recorded {
        content_hash: String,
        origin: ResolutionOrigin,
    },
}
impl From<ResolutionObservationWire> for ResolutionObservation {
    fn from(wire: ResolutionObservationWire) -> Self {
        match wire {
            ResolutionObservationWire::Missing {} => Self::Missing,
            ResolutionObservationWire::OriginUnavailable { content_hash } => {
                Self::OriginUnavailable { content_hash }
            }
            ResolutionObservationWire::Recorded {
                content_hash,
                origin,
            } => Self::Recorded {
                content_hash,
                origin,
            },
        }
    }
}

pub fn decode(
    key: &str,
    content: Option<&str>,
    operation: Option<&str>,
    index: Option<i64>,
    json: Option<&str>,
    digest: Option<&str>,
) -> StoreResult<ResolutionObservation> {
    match (content, operation, index, json, digest) {
        (None, None, None, None, None) => Ok(ResolutionObservation::Missing),
        (Some(content), None, None, None, None) if !content.trim().is_empty() => {
            Ok(ResolutionObservation::OriginUnavailable {
                content_hash: content.into(),
            })
        }
        (Some(content), Some(operation), Some(index), Some(json), Some(digest)) => {
            let receipt = ResolutionMemoryReceipt::decode(operation, json, digest)?;
            let entry = usize::try_from(index).ok().and_then(|index| {
                receipt
                    .outcomes
                    .get(index)
                    .zip(receipt.request.entries.get(index))
            });
            let matches_origin = entry.is_some_and(|(outcome, request)| {
                outcome.inserted
                    && outcome.triple_key == key
                    && outcome.resolution == content
                    && request.resolution == content
            });
            if !matches_origin {
                return Err(fault(
                    operation,
                    "resolution origin does not identify its inserted outcome",
                ));
            }
            Ok(ResolutionObservation::Recorded {
                content_hash: content.into(),
                origin: ResolutionOrigin {
                    operation_id: operation.into(),
                    receipt_hash: digest.into(),
                    outcome_index: index as u64,
                },
            })
        }
        _ => Err(fault(key, "incomplete resolution origin snapshot")),
    }
}

#[cfg(feature = "native")]
type OriginRow = (
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
);

#[cfg(feature = "native")]
pub(super) fn native_read(
    connection: &rusqlite::Connection,
    key: &str,
) -> StoreResult<ResolutionObservation> {
    // Only decoding a row establishes malformed stored evidence. A query that
    // could not execute (including an older schema) remains an operational SQL
    // error rather than falsely diagnosing contradictory attribution.
    let snapshot: StoreResult<OriginRow> = connection.query_row(SELECT, [key], |row| {
        let values = (|| -> rusqlite::Result<OriginRow> {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })();
        Ok(values.map_err(|_| fault(key, "invalid resolution origin SQL row")))
    })?;
    let (content, operation, index, json, digest) = snapshot?;
    decode(
        key,
        content.as_deref(),
        operation.as_deref(),
        index,
        json.as_deref(),
        digest.as_deref(),
    )
}

pub mod conformance;
#[cfg(all(test, feature = "native"))]
mod tests;
