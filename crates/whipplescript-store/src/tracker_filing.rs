//! Atomic tracker filing and its immutable recovery evidence.
//! This storage interface grants no execution or evidence-read authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerFiling {
    pub operation_id: String,
    pub instance_id: String,
    pub effect_id: String,
    pub actor: String,
    pub queue: String,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub metadata: Value,
    pub assigned_to: Option<String>,
}

impl TrackerFiling {
    pub fn fingerprint(&self) -> StoreResult<String> {
        if [
            &self.operation_id,
            &self.instance_id,
            &self.effect_id,
            &self.actor,
            &self.queue,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(StoreError::Conflict(
                "tracker filing requires operation, instance, effect, actor and queue".into(),
            ));
        }
        // Recursively sort objects even when a consumer enables serde_json's
        // preserve_order feature. Arrays (including labels) retain their order.
        fn ordered(value: &Value, out: &mut String) -> StoreResult<()> {
            match value {
                Value::Object(object) => {
                    out.push('{');
                    let entries: std::collections::BTreeMap<_, _> = object.iter().collect();
                    for (index, (key, value)) in entries.into_iter().enumerate() {
                        if index > 0 {
                            out.push(',');
                        }
                        out.push_str(&serde_json::to_string(key)?);
                        out.push(':');
                        ordered(value, out)?;
                    }
                    out.push('}');
                }
                Value::Array(values) => {
                    out.push('[');
                    for (index, value) in values.iter().enumerate() {
                        if index > 0 {
                            out.push(',');
                        }
                        ordered(value, out)?;
                    }
                    out.push(']');
                }
                value => out.push_str(&serde_json::to_string(value)?),
            }
            Ok(())
        }
        let mut bytes = String::from("whipplescript.tracker-filing.v1\n");
        ordered(&serde_json::to_value(self)?, &mut bytes)?;
        use sha2::Digest;
        Ok(sha2::Sha256::digest(bytes.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
}

/// Body-free coordinates; access still requires the owning workspace's grant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerFilingReceipt {
    pub operation_id: String,
    pub fingerprint: String,
    pub item_id: String,
    pub event_id: String,
}

pub trait TrackerFilings {
    /// Mutation and receipt must commit together, or neither may be visible.
    fn file_issue_once(&mut self, filing: &TrackerFiling) -> StoreResult<TrackerFilingReceipt>;
    fn filing_receipt(&self, operation_id: &str) -> StoreResult<Option<TrackerFilingReceipt>>;
}

pub const SCHEMA: &str = include_str!("tracker_filing.sql");

/// Shared executable storage contract, consumed by native and hosted tests.
pub mod conformance {
    use super::*;
    use crate::items::WorkItems;

    pub fn request() -> TrackerFiling {
        TrackerFiling {
            operation_id: "filing:one".into(),
            instance_id: "workflow:one".into(),
            effect_id: "effect:one".into(),
            actor: "person:learner".into(),
            queue: "tutorials".into(),
            title: "Create a chat".into(),
            body: "Self-reported completion".into(),
            labels: vec!["basics".into()],
            metadata: serde_json::json!({"nested": {"z": 1, "a": true}}),
            assigned_to: Some("person:learner".into()),
        }
    }

    pub fn run<S: TrackerFilings + WorkItems>(store: &mut S) {
        let filing = request();
        assert_eq!(
            store
                .filing_receipt(&filing.operation_id)
                .expect("filing fixture"),
            None
        );
        let receipt = store.file_issue_once(&filing).expect("filing fixture");
        assert_eq!(
            receipt.fingerprint,
            filing.fingerprint().expect("filing fixture")
        );
        assert_eq!(
            store.file_issue_once(&filing).expect("filing fixture"),
            receipt
        );
        assert_eq!(
            store.list_items(None, None).expect("filing fixture").len(),
            1
        );
        let item = store
            .get_item(&receipt.item_id)
            .expect("filing fixture")
            .expect("filing fixture");
        assert_eq!(item.filed_by.as_deref(), Some(filing.actor.as_str()));
        assert_eq!(item.assigned_to, filing.assigned_to);
        for field in [
            "instance_id",
            "effect_id",
            "actor",
            "queue",
            "title",
            "body",
            "labels",
            "metadata",
            "assigned_to",
        ] {
            let mut changed = serde_json::to_value(&filing).expect("filing fixture");
            changed[field] = match field {
                "labels" => serde_json::json!(["other"]),
                "metadata" => serde_json::json!({"changed": true}),
                "assigned_to" => Value::Null,
                _ => Value::String("other".into()),
            };
            let changed: TrackerFiling = serde_json::from_value(changed).expect("filing fixture");
            assert!(store.file_issue_once(&changed).is_err(), "changed {field}");
        }
        // Recovery is the original filing, not the issue's current state.
        store
            .finish_item(&receipt.item_id, Some("completed later"), None)
            .expect("filing fixture");
        assert_eq!(
            store.file_issue_once(&filing).expect("filing fixture"),
            receipt
        );
        assert_eq!(
            store
                .filing_receipt(&filing.operation_id)
                .expect("filing fixture"),
            Some(receipt.clone())
        );
        assert_eq!(
            store
                .get_item(&receipt.item_id)
                .expect("filing fixture")
                .expect("filing fixture")
                .status,
            "closed"
        );
        // Explicit independent invocations may file identical content in the
        // same clock tick. Their immutable creation events are distinct.
        let mut next = filing.clone();
        next.operation_id = "filing:two".into();
        let second = store.file_issue_once(&next).expect("filing fixture");
        assert_ne!(second.item_id, receipt.item_id);
        assert_ne!(second.event_id, receipt.event_id);
        assert_eq!(
            store.list_items(None, None).expect("filing fixture").len(),
            2
        );
        for field in ["operation_id", "instance_id", "effect_id", "actor", "queue"] {
            let mut invalid = serde_json::to_value(&filing).expect("filing fixture");
            // A fresh operation ensures receipt mismatch cannot mask a missing
            // identity check for any of the remaining fields.
            invalid["operation_id"] = Value::String(format!("invalid:{field}"));
            invalid[field] = Value::String(" ".into());
            let invalid: TrackerFiling = serde_json::from_value(invalid).expect("filing fixture");
            assert!(
                matches!(store.file_issue_once(&invalid), Err(StoreError::Conflict(message))
                if message == "tracker filing requires operation, instance, effect, actor and queue"),
                "empty {field}"
            );
        }
        assert_eq!(
            store.list_items(None, None).expect("filing fixture").len(),
            2
        );
    }
}
