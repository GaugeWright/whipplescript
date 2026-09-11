//! Attributable, retry-safe closure of an existing native tracker issue.
//! These storage types grant neither access nor permission to end a claim.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{StoreError, StoreResult};

pub const SCHEMA: &str = include_str!("tracker_closure.sql");

#[doc(hidden)]
pub mod conformance;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerClosure {
    pub operation_id: String,
    pub instance_id: String,
    pub effect_id: String,
    pub actor: String,
    pub queue: String,
    pub item_id: String,
    /// The immutable subject resolved under current observation authority.
    /// A recycled local alias cannot redirect an admitted closing.
    pub subject_id: String,
    pub summary: Option<String>,
    /// A claim holder and an action's authenticated actor are distinct.
    /// Some refuses another live holder; None is the existing operator override
    /// and requires explicit authority at the governed execution boundary.
    pub expected_holder: Option<String>,
}

impl TrackerClosure {
    pub fn fingerprint(&self) -> StoreResult<String> {
        if [
            &self.operation_id,
            &self.instance_id,
            &self.effect_id,
            &self.actor,
            &self.queue,
            &self.item_id,
            &self.subject_id,
        ]
        .iter()
        .any(|field| field.trim().is_empty())
            || self
                .expected_holder
                .as_ref()
                .is_some_and(|holder| holder.trim().is_empty())
        {
            return Err(StoreError::Conflict(
                "tracker closure coordinates are incomplete".into(),
            ));
        }
        let value = crate::effect_recovery::canonical_value(&json!([
            "whipplescript.tracker-closure.v1",
            self,
        ]));
        Ok(crate::items::sha256_hex(&value.to_string()))
    }

    /// Keep operation lineage in the immutable issue event as well as its
    /// runtime dispatch. Existing issue.closed readers use status and summary.
    pub fn event_payload(&self, fingerprint: &str) -> Value {
        json!({
            "status": "closed", "summary": self.summary,
            "operation": {
                "id": self.operation_id, "fingerprint": fingerprint,
                "instance_id": self.instance_id, "effect_id": self.effect_id,
            },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerClosureReceipt {
    pub operation_id: String,
    pub fingerprint: String,
    pub queue: String,
    pub item_id: String,
    pub subject_id: String,
    pub actor: String,
    pub event_id: String,
    pub closed_at: String,
}

impl TrackerClosureReceipt {
    pub fn validate_for(&self, request: &TrackerClosure) -> StoreResult<()> {
        if self.operation_id != request.operation_id
            || self.fingerprint != request.fingerprint()?
            || self.queue != request.queue
            || self.item_id != request.item_id
            || self.subject_id != request.subject_id
            || self.actor != request.actor
            || self.event_id.trim().is_empty()
            || self.closed_at.trim().is_empty()
        {
            return Err(StoreError::Conflict(
                "tracker closure identity already binds a different request".into(),
            ));
        }
        Ok(())
    }
}

pub trait TrackerClosures {
    /// Closing, lease release, their projections and the receipt commit
    /// together. Exact redelivery returns the original receipt even if the
    /// issue was subsequently reopened; it never closes it again.
    fn close_issue_once(&mut self, request: &TrackerClosure) -> StoreResult<TrackerClosureReceipt>;
    fn closing_receipt(&self, operation_id: &str) -> StoreResult<Option<TrackerClosureReceipt>>;
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    #[test]
    fn tracker_closure_wire_and_receipt_require_exact_complete_coordinates() {
        let mut store = crate::items::WorkItemStore::open_in_memory().unwrap();
        let request = conformance::setup(&mut store, "person:learner");
        let receipt = store.close_issue_once(&request).unwrap();
        for field in [
            "operation_id",
            "instance_id",
            "effect_id",
            "actor",
            "queue",
            "item_id",
            "subject_id",
            "expected_holder",
        ] {
            for blank in ["", "   "] {
                let mut value = serde_json::to_value(&request).unwrap();
                value[field] = blank.into();
                let invalid: TrackerClosure = serde_json::from_value(value).unwrap();
                assert!(
                    matches!(invalid.fingerprint(), Err(StoreError::Conflict(message))
                    if message == "tracker closure coordinates are incomplete"),
                    "{field}"
                );
            }
        }
        for field in [
            "operation_id",
            "fingerprint",
            "actor",
            "queue",
            "item_id",
            "subject_id",
            "event_id",
            "closed_at",
        ] {
            let mut value = serde_json::to_value(&receipt).unwrap();
            value[field] = if matches!(field, "event_id" | "closed_at") {
                "   "
            } else {
                "different"
            }
            .into();
            let invalid: TrackerClosureReceipt = serde_json::from_value(value).unwrap();
            assert!(
                matches!(invalid.validate_for(&request), Err(StoreError::Conflict(message))
                if message == "tracker closure identity already binds a different request"),
                "{field}"
            );
        }
        let mut value = serde_json::to_value(&request).unwrap();
        value["unexpected"] = true.into();
        assert!(serde_json::from_value::<TrackerClosure>(value).is_err());
        let mut value = serde_json::to_value(&receipt).unwrap();
        value["unexpected"] = true.into();
        assert!(serde_json::from_value::<TrackerClosureReceipt>(value).is_err());
    }
}
