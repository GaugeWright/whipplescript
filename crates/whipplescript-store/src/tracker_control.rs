//! Retry-stable tracker control outcomes. These types confer no authority.
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{StoreError, StoreResult};

pub const SCHEMA: &str = include_str!("tracker_control.sql");

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrackerControlAction {
    Claim {
        expires_at: String,
    },
    Renew {
        expires_at: String,
    },
    Release {
        expected_holder: Option<String>,
    },
    Assign {
        expected_assignee: Option<String>,
        assignee: Option<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerControl {
    pub operation_id: String,
    pub instance_id: String,
    pub effect_id: String,
    pub actor: String,
    pub queue: String,
    pub item_id: String,
    pub subject_id: String,
    pub action: TrackerControlAction,
}

impl TrackerControl {
    pub fn capability(&self) -> &'static str {
        match self.action {
            TrackerControlAction::Claim { .. } => "tracker.claim",
            TrackerControlAction::Renew { .. } => "tracker.renew",
            TrackerControlAction::Release { .. } => "tracker.release",
            TrackerControlAction::Assign { .. } => "tracker.assign",
        }
    }

    pub fn fingerprint(&self) -> StoreResult<String> {
        let mut fields = vec![
            self.operation_id.as_str(),
            self.instance_id.as_str(),
            self.effect_id.as_str(),
            self.actor.as_str(),
            self.queue.as_str(),
            self.item_id.as_str(),
            self.subject_id.as_str(),
        ];
        match &self.action {
            TrackerControlAction::Claim { expires_at }
            | TrackerControlAction::Renew { expires_at } => fields.push(expires_at),
            TrackerControlAction::Release { expected_holder } => {
                fields.extend(expected_holder.as_deref())
            }
            TrackerControlAction::Assign {
                expected_assignee,
                assignee,
            } => {
                fields.extend(expected_assignee.as_deref());
                fields.extend(assignee.as_deref());
            }
        }
        if fields.iter().any(|field| field.trim().is_empty()) {
            return Err(StoreError::Conflict(
                "tracker control coordinates are incomplete".into(),
            ));
        }
        let value = crate::effect_recovery::canonical_value(&json!([
            "whipplescript.tracker-control.v1",
            self
        ]));
        Ok(crate::items::sha256_hex(&value.to_string()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrackerControlOutcome {
    Claimed {
        expires_at: String,
    },
    AlreadyClaimed {
        holder: String,
    },
    Renewed {
        expires_at: String,
    },
    NotHeld,
    NotMonotonic,
    Released,
    HeldByOther {
        holder: String,
    },
    Assigned,
    AssignmentChanged {
        assignee: Option<String>,
    },
    NotOpen,
    DeadlineElapsed,
    /// Open, but the one readiness (DR-0126) refused it: blocked, conflicted,
    /// or deferred. Each reason as a sentence.
    NotReady {
        reasons: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerControlReceipt {
    pub operation_id: String,
    pub fingerprint: String,
    pub queue: String,
    pub item_id: String,
    pub subject_id: String,
    pub actor: String,
    pub outcome: TrackerControlOutcome,
    /// Actual issue/lease events, including any native expiry discovered while
    /// claiming. A refused control can have no mutation events.
    pub event_ids: Vec<String>,
    pub recorded_at: String,
}

impl TrackerControlReceipt {
    pub fn validate_for(&self, request: &TrackerControl) -> StoreResult<()> {
        use TrackerControlAction as A;
        use TrackerControlOutcome as O;
        let compatible = match (&request.action, &self.outcome) {
            (A::Claim { expires_at: want }, O::Claimed { expires_at: actual })
            | (A::Renew { expires_at: want }, O::Renewed { expires_at: actual }) => want == actual,
            (A::Claim { .. }, O::AlreadyClaimed { holder })
            | (A::Release { .. }, O::HeldByOther { holder }) => !holder.trim().is_empty(),
            (A::Assign { .. }, O::AssignmentChanged { assignee }) => assignee
                .as_ref()
                .is_none_or(|actor| !actor.trim().is_empty()),
            (A::Assign { .. }, O::Assigned | O::NotOpen)
            | (A::Claim { .. }, O::NotOpen | O::DeadlineElapsed)
            | (A::Renew { .. }, O::NotHeld | O::NotMonotonic | O::DeadlineElapsed)
            | (A::Release { .. }, O::Released | O::NotHeld) => true,
            _ => false,
        };
        let changed = matches!(
            self.outcome,
            O::Claimed { .. } | O::Renewed { .. } | O::Released | O::Assigned
        );
        if self.operation_id != request.operation_id
            || self.fingerprint != request.fingerprint()?
            || self.queue != request.queue
            || self.item_id != request.item_id
            || self.subject_id != request.subject_id
            || self.actor != request.actor
            || self.recorded_at.trim().is_empty()
            || !compatible
            || (changed && self.event_ids.is_empty())
            || self.event_ids.iter().any(|event| event.trim().is_empty())
            || self
                .event_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.event_ids.len()
        {
            return Err(StoreError::Conflict(
                "tracker control receipt differs from its request".into(),
            ));
        }
        Ok(())
    }
}

pub trait TrackerControls {
    /// Current mutation and its exact outcome receipt commit together. A retry
    /// returns even a negative original outcome without reevaluating the issue.
    fn control_issue_once(
        &mut self,
        request: &TrackerControl,
    ) -> StoreResult<TrackerControlReceipt>;
    fn control_receipt(&self, operation_id: &str) -> StoreResult<Option<TrackerControlReceipt>>;
}

#[doc(hidden)]
pub mod conformance;

#[cfg(test)]
mod tests;
