//! DR-0290: shared validation of the original paired checkpoint command.
use crate::{
    CapturedCheckpoint, CapturedCheckpointWithPositions, CheckpointCapture, CheckpointPositions,
    EventView, StoreError, StoreResult,
};
use serde_json::{json, Value};

fn refusal(message: &str) -> StoreError {
    StoreError::Conflict(message.into())
}

/// Build the carrier with the owning cut identity, rather than trusting a
/// caller-provided cut field. The positions are observed data; explicit external
/// positions are part of the stable command and must agree on redelivery.
pub fn payload(
    capture: CheckpointCapture<'_>,
    positions: CheckpointPositions<'_>,
) -> StoreResult<String> {
    if capture.idempotency_key.is_none_or(str::is_empty)
        || positions.idempotency_key.is_empty()
        || positions.source.is_empty()
    {
        return Err(refusal(
            "paired checkpoint requires stable command identities",
        ));
    }
    let observed: Value = serde_json::from_str(positions.positions_json)?;
    if !observed.is_object() {
        return Err(refusal("checkpoint positions must be an object"));
    }
    let mut carrier = json!({"cut_id": capture.cut_id, "positions": observed});
    if let Some(external) = positions.external_json {
        carrier["external"] = serde_json::from_str(external)?;
    }
    Ok(carrier.to_string())
}

/// Resolve an exact retained pair inside the capture transaction. A carrier
/// without a cut (or a legacy unpaired cut) must not be silently completed.
pub fn retained(
    capture: CheckpointCapture<'_>,
    positions: CheckpointPositions<'_>,
    events: &[(EventView, Option<String>)],
) -> StoreResult<Option<CapturedCheckpointWithPositions>> {
    let expected: Value = serde_json::from_str(&payload(capture, positions)?)?;
    let mut checkpoint = None;
    let mut carrier = None;
    for (event, key) in events {
        let value: Value = serde_json::from_str(&event.payload_json)?;
        let same_cut = value["cut_id"].as_str() == Some(capture.cut_id);
        let same_key = if event.event_type == "context.checkpoint" {
            key.as_deref() == capture.idempotency_key
        } else {
            key.as_deref() == Some(positions.idempotency_key)
        };
        if !same_cut && !same_key {
            continue;
        }
        if !same_cut || !same_key {
            return Err(refusal(
                "checkpoint command identity differs from retained cut",
            ));
        }
        if event.event_type == "context.checkpoint" {
            if checkpoint.is_some()
                || event.source != "restorable-context"
                || value.get("transcript_ref") != Some(&json!(capture.transcript_ref))
            {
                return Err(refusal("retained checkpoint command does not match"));
            }
            checkpoint = Some((event, value));
        } else {
            if carrier.is_some()
                || event.source != positions.source
                || value.get("external") != expected.get("external")
                || !value["positions"].is_object()
            {
                return Err(refusal(
                    "retained checkpoint position command does not match",
                ));
            }
            carrier = Some(event);
        }
    }
    match (checkpoint, carrier) {
        (None, None) => Ok(None),
        (Some((cut, value)), Some(pair)) if pair.sequence.checked_add(1) == Some(cut.sequence) => {
            let manifest_hash = value["manifest_hash"]
                .as_str()
                .ok_or_else(|| refusal("retained checkpoint manifest is unavailable"))?;
            let file_count = value["file_count"]
                .as_u64()
                .and_then(|count| usize::try_from(count).ok())
                .ok_or_else(|| refusal("retained checkpoint count is unavailable"))?;
            let manifest = value["manifest"]
                .as_object()
                .ok_or_else(|| refusal("retained checkpoint manifest is malformed"))?;
            let manifest_json = serde_json::to_string(manifest)?;
            if crate::stable_hash_hex(&manifest_json) != manifest_hash {
                return Err(refusal("retained checkpoint manifest identity differs"));
            }
            if manifest.len() != file_count {
                return Err(refusal("retained checkpoint manifest count differs"));
            }
            Ok(Some(CapturedCheckpointWithPositions {
                checkpoint: CapturedCheckpoint {
                    cut_id: capture.cut_id.into(),
                    event_id: cut.event_id.clone(),
                    sequence: cut.sequence,
                    manifest_hash: manifest_hash.into(),
                    file_count,
                },
                positions_payload_json: pair.payload_json.clone(),
            }))
        }
        _ => Err(refusal(
            "retained checkpoint has no coherent atomic position pair",
        )),
    }
}

/// The latest completed position pair, without treating a historical orphan
/// carrier as a cut. This is a read projection and never repairs old records.
pub fn latest_completed_pair(events: &[EventView]) -> StoreResult<Option<Value>> {
    let mut cuts = std::collections::BTreeMap::new();
    for event in events
        .iter()
        .filter(|event| event.event_type == "context.checkpoint")
    {
        let cut: Value = serde_json::from_str(&event.payload_json)?;
        let id = cut["cut_id"]
            .as_str()
            .ok_or_else(|| refusal("checkpoint cut identity is unavailable"))?;
        if event.source != "restorable-context"
            || cuts.insert(id.to_owned(), event.sequence).is_some()
        {
            return Err(refusal("checkpoint cut identity is ambiguous"));
        }
    }
    for event in events
        .iter()
        .rev()
        .filter(|event| event.event_type == "plane.positions")
    {
        let pair: Value = serde_json::from_str(&event.payload_json)?;
        let id = pair["cut_id"]
            .as_str()
            .ok_or_else(|| refusal("position carrier cut identity is unavailable"))?;
        if cuts
            .get(id)
            .is_some_and(|sequence| event.sequence < *sequence)
        {
            if !pair["positions"].is_object() {
                return Err(refusal("completed position carrier is malformed"));
            }
            return Ok(Some(pair));
        }
    }
    Ok(None)
}
