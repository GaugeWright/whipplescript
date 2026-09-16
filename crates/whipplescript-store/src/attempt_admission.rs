//! Attempt selection from the live runtime journal; not a caller-minted nonce.
use crate::{restore_marker_target, EventView, StoreError, StoreResult};

/// Return the latest retry/lease-expiry admission in the restored live prefix.
/// `None` selects the initial attempt. Callers must perform the comparison
/// inside run admission's transaction, and retain the result across external I/O.
pub fn select(events: &[EventView], effect_id: &str) -> StoreResult<Option<String>> {
    Ok(selections(events)?.remove(effect_id))
}

/// Select every effect in one journal pass for a batch of claimable snapshots.
pub fn selections(events: &[EventView]) -> StoreResult<std::collections::BTreeMap<String, String>> {
    let live = live_events(events)?;
    let mut selected = std::collections::BTreeMap::new();
    for event in live {
        if matches!(
            event.event_type.as_str(),
            "effect.retried" | "lease.expired"
        ) {
            let payload: serde_json::Value = serde_json::from_str(&event.payload_json)?;
            if let Some(effect_id) = payload.get("effect_id").and_then(serde_json::Value::as_str) {
                selected.insert(effect_id.to_owned(), event.event_id.clone());
            }
        }
    }
    Ok(selected)
}

fn live_events(events: &[EventView]) -> StoreResult<Vec<&EventView>> {
    let mut live: Vec<&EventView> = Vec::new();
    let mut previous = None;
    for event in events {
        if previous.is_some_and(|sequence| event.sequence <= sequence) {
            return Err(StoreError::Conflict(
                "attempt journal is not ordered".into(),
            ));
        }
        previous = Some(event.sequence);
        if event.event_type == "context.restored" {
            if let Some(target) = restore_marker_target(&event.payload_json) {
                live.retain(|held| held.sequence <= target);
            }
        }
        live.push(event);
    }
    Ok(live)
}

/// Latest terminal in the live prefix, used to pin a retry request.
pub fn terminal(events: &[EventView], effect_id: &str) -> StoreResult<Option<String>> {
    for event in live_events(events)?.into_iter().rev() {
        if event.event_type == "effect.terminal" {
            let payload: serde_json::Value = serde_json::from_str(&event.payload_json)?;
            if payload.get("effect_id").and_then(serde_json::Value::as_str) == Some(effect_id) {
                return Ok(Some(event.event_id.clone()));
            }
        }
    }
    Ok(None)
}

pub fn retry_payload(retry: crate::RetryEffect<'_>, terminal: Option<&str>) -> String {
    let mut payload =
        serde_json::json!({"effect_id": retry.effect_id, "retry_after": retry.retry_after});
    if let Some(terminal) = terminal {
        payload["terminal_event_id"] = serde_json::json!(terminal);
    }
    payload.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event(sequence: i64, kind: &str, payload: serde_json::Value) -> EventView {
        EventView {
            event_id: format!("event-{sequence}"),
            sequence,
            event_type: kind.into(),
            payload_json: payload.to_string(),
            source: "kernel".into(),
            occurred_at: "fixture".into(),
        }
    }
    #[test]
    fn attempt_admission_tracks_retry_expiry_and_nested_restore_cuts() {
        use serde_json::json;
        let mut events = vec![event(1, "rule.committed", json!({}))];
        assert_eq!(select(&events, "effect").unwrap(), None);
        events.push(event(2, "effect.retried", json!({"effect_id":"effect"})));
        events.push(event(3, "effect.retried", json!({"effect_id":"other"})));
        events.push(event(4, "effect.retried", json!({"effect_id":"effect"})));
        assert_eq!(
            select(&events, "effect").unwrap().as_deref(),
            Some("event-4")
        );
        events.push(event(
            5,
            "context.restored",
            json!({"restored_to_sequence":2}),
        ));
        assert_eq!(
            select(&events, "effect").unwrap().as_deref(),
            Some("event-2")
        );
        assert_eq!(select(&events, "other").unwrap(), None);
        events.push(event(6, "lease.expired", json!({"effect_id":"effect"})));
        assert_eq!(
            select(&events, "effect").unwrap().as_deref(),
            Some("event-6")
        );
        events.push(event(
            7,
            "context.restored",
            json!({"restored_to_sequence":1}),
        ));
        assert_eq!(select(&events, "effect").unwrap(), None);
        events.push(event(8, "effect.retried", json!({"effect_id":"effect"})));
        assert_eq!(
            select(&events, "effect").unwrap().as_deref(),
            Some("event-8")
        );
    }
    #[test]
    fn attempt_admission_refuses_ambiguous_journal_order() {
        use serde_json::json;
        for second in [1, 2] {
            let events = [
                event(2, "effect.retried", json!({"effect_id":"effect"})),
                event(second, "effect.retried", json!({"effect_id":"effect"})),
            ];
            assert!(select(&events, "effect").is_err());
        }
    }
}
