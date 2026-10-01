//! Retry-stable initiative membership events. Authority belongs to the host
//! binding, not to these request fields.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{StoreError, StoreResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipChange {
    Add,
    Remove,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerMembership {
    pub operation_id: String,
    pub instance_id: String,
    pub effect_id: String,
    pub actor: String,
    pub task_id: String,
    pub task_queue: String,
    pub task_subject_id: String,
    pub initiative_id: String,
    pub initiative_queue: String,
    pub initiative_subject_id: String,
    pub change: MembershipChange,
}

impl TrackerMembership {
    pub fn fingerprint(&self) -> StoreResult<String> {
        if [
            self.operation_id.as_str(),
            self.instance_id.as_str(),
            self.effect_id.as_str(),
            self.actor.as_str(),
            self.task_id.as_str(),
            self.task_queue.as_str(),
            self.task_subject_id.as_str(),
            self.initiative_id.as_str(),
            self.initiative_queue.as_str(),
            self.initiative_subject_id.as_str(),
        ]
        .iter()
        .any(|field| field.trim().is_empty())
        {
            return Err(StoreError::Conflict(
                "initiative membership coordinates are incomplete".into(),
            ));
        }
        let value = crate::effect_recovery::canonical_value(&json!([
            "whipplescript.tracker-membership.v1",
            self
        ]));
        Ok(crate::items::sha256_hex(&value.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipOutcome {
    Added,
    AlreadyMember,
    Removed { was_member: bool },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackerMembershipReceipt {
    pub operation_id: String,
    pub fingerprint: String,
    pub task_id: String,
    pub initiative_id: String,
    pub outcome: MembershipOutcome,
    pub event_ids: Vec<String>,
    pub recorded_at: String,
}

impl TrackerMembershipReceipt {
    pub fn validate_for(&self, request: &TrackerMembership) -> StoreResult<()> {
        let compatible = matches!(
            (&request.change, &self.outcome),
            (
                MembershipChange::Add,
                MembershipOutcome::Added | MembershipOutcome::AlreadyMember
            ) | (MembershipChange::Remove, MembershipOutcome::Removed { .. })
        );
        let changed = matches!(
            self.outcome,
            MembershipOutcome::Added | MembershipOutcome::Removed { .. }
        );
        if self.operation_id != request.operation_id
            || self.fingerprint != request.fingerprint()?
            || self.task_id != request.task_id
            || self.initiative_id != request.initiative_id
            || self.recorded_at.trim().is_empty()
            || !compatible
            || (changed && self.event_ids.is_empty())
            || self.event_ids.iter().any(|id| id.trim().is_empty())
            || self
                .event_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.event_ids.len()
        {
            return Err(StoreError::Conflict(
                "initiative membership receipt differs from its request".into(),
            ));
        }
        Ok(())
    }
}

pub trait TrackerMemberships {
    /// The event, projection and original outcome commit together. Replaying an
    /// operation ID returns its original receipt, even after another writer
    /// changes current membership.
    fn change_membership_once(
        &mut self,
        request: &TrackerMembership,
    ) -> StoreResult<TrackerMembershipReceipt>;
    fn membership_receipt(
        &self,
        operation_id: &str,
    ) -> StoreResult<Option<TrackerMembershipReceipt>>;
}

#[doc(hidden)]
pub mod conformance {
    use super::*;
    use crate::items::WorkItems;

    pub fn run_suite<S: WorkItems + TrackerMemberships>(
        store: &mut S,
        member: impl Fn(&S, &str, &str) -> bool,
    ) {
        let task = store
            .file_item(
                "engineering",
                "Ship the work",
                "task",
                &[],
                &json!({}),
                None,
                None,
            )
            .expect("task");
        let initiative = store
            .file_item(
                "company",
                "Launch",
                "outcome",
                &[],
                &json!({"kind":"initiative"}),
                None,
                None,
            )
            .expect("initiative");
        let blocker = store
            .file_item(
                "engineering",
                "Prerequisite",
                "blocker",
                &[],
                &json!({}),
                None,
                None,
            )
            .expect("blocker");
        let wrong_kind = store
            .inspect_initiative_at(&task.id, "2030-01-01T00:00:00Z")
            .expect_err("task is not a group");
        assert!(format!("{wrong_kind:?}").contains("is not an initiative"));
        let missing = store
            .inspect_initiative_at("WS-404", "2030-01-01T00:00:00Z")
            .expect_err("missing group");
        assert!(format!("{missing:?}").contains("unknown initiative"));
        let bad_clock = store
            .inspect_initiative_at(&initiative.id, "not-a-time")
            .expect_err("inspection needs a canonical instant");
        assert!(format!("{bad_clock:?}").contains("UTC instant"));
        store.add_blocks(&blocker.id, &task.id).expect("dependency");
        let mut request = TrackerMembership {
            operation_id: "membership-one".into(),
            instance_id: "run-one".into(),
            effect_id: "effect-one".into(),
            actor: "agent".into(),
            task_id: task.id.clone(),
            task_queue: task.queue.clone(),
            task_subject_id: store
                .subject_content_id(&task.id)
                .expect("subject")
                .expect("task subject"),
            initiative_id: initiative.id.clone(),
            initiative_queue: initiative.queue.clone(),
            initiative_subject_id: store
                .subject_content_id(&initiative.id)
                .expect("subject")
                .expect("initiative subject"),
            change: MembershipChange::Add,
        };
        let before = store.event_position().expect("position");
        let added = store.change_membership_once(&request).expect("add");
        assert_eq!(added.outcome, MembershipOutcome::Added);
        assert_eq!(added.event_ids.len(), 1);
        assert!(member(store, &task.id, &initiative.id));
        let snapshot = store
            .inspect_initiative_at(&initiative.id, "2030-01-01T00:00:00Z")
            .expect("consistent inspection");
        assert_eq!(snapshot.initiative.id, initiative.id);
        assert_eq!(snapshot.members.len(), 1);
        assert_eq!(snapshot.members[0].item.id, task.id);
        assert!(snapshot.members[0].unready_reasons.iter().any(|reason| {
            matches!(reason, crate::items::readiness::Unready::BlockedBy { issue, .. } if issue == &blocker.id)
        }));
        assert_eq!(snapshot.state_counts.get("open"), Some(&1));
        store
            .finish_item(&blocker.id, Some("prerequisite done"), None)
            .expect("finish blocker");
        let ready_snapshot = store
            .inspect_initiative_at(&initiative.id, "2030-01-01T00:00:00Z")
            .expect("fresh readiness");
        assert!(ready_snapshot.members[0].unready_reasons.is_empty());
        assert!(store.event_position().expect("test operation") > before);
        assert_eq!(
            store
                .membership_receipt(&request.operation_id)
                .expect("test operation"),
            Some(added.clone())
        );
        let after_add = store.event_position().expect("test operation");
        assert_eq!(
            store
                .change_membership_once(&request)
                .expect("test operation"),
            added
        );
        assert_eq!(store.event_position().expect("test operation"), after_add);

        let mut drift = request.clone();
        drift.actor = "another actor".into();
        assert!(store.change_membership_once(&drift).is_err());
        assert_eq!(store.event_position().expect("test operation"), after_add);

        request.operation_id = "membership-two".into();
        let already = store
            .change_membership_once(&request)
            .expect("duplicate add");
        assert_eq!(already.outcome, MembershipOutcome::AlreadyMember);
        assert!(already.event_ids.is_empty());
        assert_eq!(store.event_position().expect("test operation"), after_add);

        request.operation_id = "membership-three".into();
        request.change = MembershipChange::Remove;
        let removed = store.change_membership_once(&request).expect("remove");
        assert_eq!(
            removed.outcome,
            MembershipOutcome::Removed { was_member: true }
        );
        assert_eq!(removed.event_ids.len(), 1);
        assert!(!member(store, &task.id, &initiative.id));
        let snapshot = store
            .inspect_initiative_at(&initiative.id, "2030-01-01T00:00:00Z")
            .expect("empty group remains inspectable");
        assert!(snapshot.members.is_empty());
        assert!(snapshot.state_counts.is_empty());
        assert_eq!(
            store
                .change_membership_once(&request)
                .expect("test operation"),
            removed
        );
        let after_remove = store.event_position().expect("test operation");
        assert_eq!(
            store
                .change_membership_once(&request)
                .expect("test operation"),
            removed
        );
        assert_eq!(
            store.event_position().expect("test operation"),
            after_remove
        );

        request.operation_id = "membership-four".into();
        let absent = store
            .change_membership_once(&request)
            .expect("absent remove");
        assert_eq!(
            absent.outcome,
            MembershipOutcome::Removed { was_member: false }
        );
        assert_eq!(absent.event_ids.len(), 1, "absence needs a tombstone");
        assert_eq!(
            store
                .membership_receipt(&request.operation_id)
                .expect("test operation"),
            Some(absent)
        );

        request.operation_id = "membership-invalid".into();
        request.task_id = initiative.id;
        request.task_queue = initiative.queue;
        request.task_subject_id = request.initiative_subject_id.clone();
        let before_invalid = store.event_position().expect("test operation");
        let refusal = store
            .change_membership_once(&request)
            .expect_err("initiative cannot be a member");
        assert!(
            format!("{refusal:?}").contains("endpoints differ from their binding"),
            "{refusal:?}"
        );
        assert_eq!(
            store.event_position().expect("test operation"),
            before_invalid
        );
        assert!(store
            .membership_receipt(&request.operation_id)
            .expect("test operation")
            .is_none());
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    #[test]
    fn native_and_composite_membership_recovery_match() {
        super::conformance::run_suite(
            &mut crate::items::WorkItemStore::open_in_memory().expect("test operation"),
            |store, task, initiative| {
                store
                    .initiative_members(initiative)
                    .expect("test operation")
                    .iter()
                    .any(|item| item.id == task)
            },
        );
        super::conformance::run_suite(
            &mut crate::native_stores::NativeStores::open_in_memory().expect("test operation"),
            |store, task, initiative| {
                store
                    .items
                    .initiative_members(initiative)
                    .expect("test operation")
                    .iter()
                    .any(|item| item.id == task)
            },
        );
    }
}
