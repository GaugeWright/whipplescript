//! DR-0153: initiatives reuse issue metadata and relation events, but are sets,
//! not executable issues or a task hierarchy. Native/hosted share these guards.

use crate::{StoreError, StoreResult};
use serde_json::Value;
use std::collections::BTreeMap;

use super::{readiness::Unready, WorkItem};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiativeMember {
    pub item: WorkItem,
    pub unready_reasons: Vec<Unready>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InitiativeInspection {
    pub initiative: WorkItem,
    pub members: Vec<InitiativeMember>,
    pub state_counts: BTreeMap<String, usize>,
    pub at: String,
}

pub fn inspection(
    initiative: WorkItem,
    members: Vec<InitiativeMember>,
    at: String,
) -> InitiativeInspection {
    let mut state_counts = BTreeMap::new();
    for member in &members {
        *state_counts.entry(member.item.status.clone()).or_default() += 1;
    }
    InitiativeInspection {
        initiative,
        members,
        state_counts,
        at,
    }
}

/// Absent kind is the legacy task kind. A reserved kind cannot silently fall
/// back to task and acquire execution semantics.
pub fn issue_kind(metadata: &Value) -> StoreResult<&'static str> {
    match metadata.get("kind") {
        None => Ok("task"),
        Some(Value::String(kind)) if kind == "task" => Ok("task"),
        Some(Value::String(kind)) if kind == "initiative" => Ok("initiative"),
        Some(_) => Err(StoreError::Conflict(
            "issue kind must be task or initiative".into(),
        )),
    }
}

/// Initiatives coordinate several parties; assignment belongs to member tasks.
pub fn validate_assignment(kind: &str, assignee: Option<&str>) -> StoreResult<()> {
    if kind == "initiative" && assignee.is_some() {
        return Err(StoreError::Conflict(
            "initiatives have no assignee; assign their member tasks".into(),
        ));
    }
    Ok(())
}

/// Validate the grouping boundary, independently of backend and queue.
pub fn validate_relation(kind: &str, from: Option<&str>, to: Option<&str>) -> StoreResult<()> {
    if kind == "belongs-to" && (from != Some("task") || to != Some("initiative")) {
        return Err(StoreError::Conflict(
            "belongs-to requires a task source and an initiative target".into(),
        ));
    }
    if kind == "blocks" && (from == Some("initiative") || to == Some("initiative")) {
        return Err(StoreError::Conflict(
            "dependencies connect tasks, not initiatives".into(),
        ));
    }
    Ok(())
}

pub fn validate_closure(kind: &str, unfinished: usize, summary: Option<&str>) -> StoreResult<()> {
    if kind == "initiative" && unfinished > 0 && summary.is_none_or(|s| s.trim().is_empty()) {
        return Err(StoreError::Conflict(format!("initiative has {unfinished} unfinished member(s); finish with a summary explaining their disposition")));
    }
    Ok(())
}

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};

#[cfg(feature = "native")]
use crate::tracker_membership::{
    MembershipChange, MembershipOutcome, TrackerMembership, TrackerMembershipReceipt,
    TrackerMemberships,
};

#[cfg(feature = "native")]
fn native_membership_receipt(
    conn: &Connection,
    operation_id: &str,
) -> StoreResult<Option<TrackerMembershipReceipt>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT receipt_json FROM tracker_control_receipts WHERE operation_id = ?1",
            [operation_id],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|value| serde_json::from_str(&value).map_err(Into::into))
        .transpose()
}

#[cfg(feature = "native")]
impl TrackerMemberships for super::WorkItemStore {
    fn membership_receipt(
        &self,
        operation_id: &str,
    ) -> StoreResult<Option<TrackerMembershipReceipt>> {
        native_membership_receipt(&self.connection, operation_id)
    }

    fn change_membership_once(
        &mut self,
        request: &TrackerMembership,
    ) -> StoreResult<TrackerMembershipReceipt> {
        match self.protection.clone() {
            Some(protection) => protection.retain(|| self.change_membership_once_retained(request)),
            None => self.change_membership_once_retained(request),
        }
    }
}

#[cfg(feature = "native")]
impl super::WorkItemStore {
    fn change_membership_once_retained(
        &mut self,
        request: &TrackerMembership,
    ) -> StoreResult<TrackerMembershipReceipt> {
        let fingerprint = request.fingerprint()?;
        let tx = self.discovery_transaction()?;
        if let Some(existing) = native_membership_receipt(&tx, &request.operation_id)? {
            existing.validate_for(request)?;
            return Ok(existing);
        }
        for (id, queue, subject, expected_kind) in [
            (
                request.task_id.as_str(),
                request.task_queue.as_str(),
                request.task_subject_id.as_str(),
                "task",
            ),
            (
                request.initiative_id.as_str(),
                request.initiative_queue.as_str(),
                request.initiative_subject_id.as_str(),
                "initiative",
            ),
        ] {
            let actual_queue: Option<String> = tx
                .query_row(
                    "SELECT queue FROM tracker_issues WHERE issue_id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?;
            if actual_queue.as_deref() != Some(queue)
                || super::content_id_of(&tx, id)?.as_deref() != Some(subject)
                || native_kind(&tx, id)? != Some(expected_kind)
            {
                return Err(StoreError::Conflict(
                    "initiative membership endpoints differ from their binding".into(),
                ));
            }
        }
        let present = tx
            .query_row(
                "SELECT 1 FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = 'belongs-to'",
                params![request.task_id, request.initiative_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let now = super::tx_now(&tx)?;
        let (outcome, event_ids) = match request.change {
            MembershipChange::Add if present => (MembershipOutcome::AlreadyMember, Vec::new()),
            MembershipChange::Add => {
                let payload = serde_json::json!({
                    "from": request.task_subject_id,
                    "to": request.initiative_subject_id,
                    "kind": "belongs-to",
                    "dep_kind": null,
                });
                let event = super::tx_append_raw(
                    &tx,
                    Some(&request.initiative_subject_id),
                    None,
                    "relation.added",
                    &payload.to_string(),
                    Some(&request.actor),
                    Some(&request.effect_id),
                    &now,
                )?;
                tx.execute(
                    "INSERT INTO tracker_relations (from_issue, to_issue, kind, dep_kind) VALUES (?1, ?2, 'belongs-to', NULL)",
                    params![request.task_id, request.initiative_id],
                )?;
                (MembershipOutcome::Added, vec![event])
            }
            MembershipChange::Remove => {
                // The tombstone is necessary even when this clone currently
                // sees no edge: an imported concurrent add must still fold it.
                let payload = serde_json::json!({
                    "from": request.task_subject_id,
                    "to": request.initiative_subject_id,
                    "kind": "belongs-to",
                });
                let event = super::tx_append_raw(
                    &tx,
                    Some(&request.initiative_subject_id),
                    None,
                    "relation.removed",
                    &payload.to_string(),
                    Some(&request.actor),
                    Some(&request.effect_id),
                    &now,
                )?;
                tx.execute(
                    "DELETE FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = 'belongs-to'",
                    params![request.task_id, request.initiative_id],
                )?;
                (
                    MembershipOutcome::Removed {
                        was_member: present,
                    },
                    vec![event],
                )
            }
        };
        let receipt = TrackerMembershipReceipt {
            operation_id: request.operation_id.clone(),
            fingerprint,
            task_id: request.task_id.clone(),
            initiative_id: request.initiative_id.clone(),
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
}

#[cfg(feature = "native")]
pub(super) fn native_kind(conn: &Connection, id: &str) -> StoreResult<Option<&'static str>> {
    let metadata: Option<String> = conn.query_row(
        "SELECT whip_payload_open('tracker.issue.metadata_json', issue_id, metadata_json) FROM tracker_issues WHERE issue_id = ?1",
        [id], |row| row.get(0),
    ).optional()?;
    metadata
        .map(|raw| issue_kind(&serde_json::from_str(&raw)?))
        .transpose()
}

#[cfg(feature = "native")]
pub(super) fn native_validate_closure(
    conn: &Connection,
    id: &str,
    summary: Option<&str>,
) -> StoreResult<()> {
    if native_kind(conn, id)? != Some("initiative") {
        return Ok(());
    }
    let unfinished: i64 = conn.query_row(
        "SELECT count(*) FROM tracker_relations r JOIN tracker_issues i ON i.issue_id = r.from_issue WHERE r.to_issue = ?1 AND r.kind = 'belongs-to' AND i.status != 'closed'",
        [id], |row| row.get(0),
    )?;
    validate_closure("initiative", unfinished as usize, summary)
}

#[cfg(feature = "native")]
pub(super) fn native_validate_projection(conn: &Connection) -> StoreResult<()> {
    let edges = conn.prepare("SELECT from_issue, to_issue, kind FROM tracker_relations WHERE kind IN ('belongs-to', 'blocks')")?
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (from, to, kind) in edges {
        validate_relation(&kind, native_kind(conn, &from)?, native_kind(conn, &to)?)?;
    }
    Ok(())
}

#[cfg(feature = "native")]
impl super::WorkItemStore {
    /// Current members; no snapshots or status cascades. Queue ownership stays
    /// on each task. Shared tasks appear in every relevant initiative.
    pub fn initiative_members(&self, id: &str) -> StoreResult<Vec<super::WorkItem>> {
        if native_kind(&self.connection, id)? != Some("initiative") {
            return Err(StoreError::Conflict(format!("{id} is not an initiative")));
        }
        let ids = self
            .relations(id)?
            .into_iter()
            .filter(|r| r.kind == "belongs-to" && r.to == id)
            .map(|r| r.from)
            .collect::<std::collections::BTreeSet<_>>();
        self.list_items(None, None)
            .map(|items| items.into_iter().filter(|i| ids.contains(&i.id)).collect())
    }

    /// A read transaction pins the group, relation set, member overlays and
    /// readiness explanations to the same SQLite snapshot.
    pub fn inspect_initiative_at(&self, id: &str, at: &str) -> StoreResult<InitiativeInspection> {
        self.inspect_initiative_inner(id, at, None)
    }

    pub fn inspect_initiative_for_queues_at(
        &self,
        id: &str,
        at: &str,
        allowed_queues: &std::collections::BTreeSet<String>,
    ) -> StoreResult<InitiativeInspection> {
        self.inspect_initiative_inner(id, at, Some(allowed_queues))
    }

    fn inspect_initiative_inner(
        &self,
        id: &str,
        at: &str,
        allowed_queues: Option<&std::collections::BTreeSet<String>>,
    ) -> StoreResult<InitiativeInspection> {
        let at = super::readiness::canonical_instant(at).ok_or_else(|| {
            StoreError::Conflict("initiative inspection needs a UTC instant".into())
        })?;
        // A canonical query handle already owns its response snapshot. Keep
        // that snapshot alive; standalone inspection still takes its own cut.
        let owned_tx = if self.connection.is_autocommit() {
            Some(self.connection.unchecked_transaction()?)
        } else {
            None
        };
        if let Some(allowed) = allowed_queues {
            let queue: Option<String> = self
                .connection
                .query_row(
                    "SELECT queue FROM tracker_issues WHERE issue_id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?;
            if queue.as_ref().is_some_and(|queue| !allowed.contains(queue)) {
                return Err(StoreError::Conflict(format!(
                    "initiative {id} is outside the readable tracker set"
                )));
            }
        }
        let initiative = self
            .get_item(id)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown initiative {id}")))?;
        if issue_kind(&initiative.metadata)? != "initiative" {
            return Err(StoreError::Conflict(format!("{id} is not an initiative")));
        }
        let addresses = self
            .connection
            .prepare(
                "SELECT r.from_issue, i.queue FROM tracker_relations r \
                 LEFT JOIN tracker_issues i ON i.issue_id = r.from_issue \
                 WHERE r.to_issue = ?1 AND r.kind = 'belongs-to' ORDER BY r.from_issue",
            )?
            .query_map([id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut members = Vec::with_capacity(addresses.len());
        for (member_id, queue) in addresses {
            let queue = queue.ok_or_else(|| {
                StoreError::Conflict(format!("initiative member {member_id} is unavailable"))
            })?;
            if allowed_queues.is_some_and(|allowed| !allowed.contains(&queue)) {
                return Err(StoreError::Conflict(format!(
                    "initiative member {member_id} is outside the readable tracker set"
                )));
            }
            let item = self
                .get_item(&member_id)?
                .expect("member queue row exists in this transaction snapshot");
            let unready_reasons = self.unready_reasons_at(&item.id, &at)?;
            members.push(InitiativeMember {
                item,
                unready_reasons,
            });
        }
        if let Some(tx) = owned_tx {
            tx.commit()?;
        }
        Ok(inspection(initiative, members, at))
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::items::{ClaimOutcome, FinishOutcome, WorkItem, WorkItemStore};
    use serde_json::json;

    fn file(store: &mut WorkItemStore, queue: &str, title: &str, kind: &str) -> WorkItem {
        store
            .file_item(
                queue,
                title,
                "outcome and completion criteria",
                &[],
                &json!({"kind": kind}),
                None,
                None,
            )
            .expect("test operation succeeds")
    }

    #[test]
    fn initiatives_refuse_assignment_while_tasks_keep_it() {
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let metadata = json!({"kind":"initiative"});
        let refusal = store
            .file_item("q", "group", "outcome", &[], &metadata, None, Some("alice"))
            .expect_err("assigned initiative");
        assert!(format!("{refusal:?}").contains("initiatives have no assignee"));
        assert!(store.list_items(None, None).expect("list").is_empty());

        let initiative = file(&mut store, "q", "group", "initiative");
        let refusal = store
            .assign_item(&initiative.id, Some("alice"))
            .expect_err("initiative assignment");
        assert!(format!("{refusal:?}").contains("initiatives have no assignee"));
        assert_eq!(
            store
                .get_item(&initiative.id)
                .expect("read")
                .unwrap()
                .assigned_to,
            None
        );
        // An earlier writer could have recorded an assignee before this
        // contract. Keep its event, but never present a sole owner now.
        store
            .connection
            .execute(
                "UPDATE tracker_issues SET assigned_to = 'legacy' WHERE issue_id = ?1",
                [&initiative.id],
            )
            .expect("legacy projection");
        assert_eq!(
            store
                .get_item(&initiative.id)
                .expect("read")
                .unwrap()
                .assigned_to,
            None
        );

        let task = store
            .file_item(
                "q",
                "task",
                "work",
                &[],
                &json!({"kind":"task"}),
                None,
                Some("alice"),
            )
            .expect("assigned task");
        assert_eq!(task.assigned_to.as_deref(), Some("alice"));
        assert!(store
            .assign_item(&task.id, Some("bob"))
            .expect("reassign task"));
        assert_eq!(
            store
                .get_item(&task.id)
                .expect("read")
                .unwrap()
                .assigned_to
                .as_deref(),
            Some("bob")
        );
    }

    #[test]
    fn initiative_replay_refuses_hash_valid_but_invalid_membership() {
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let a = file(&mut store, "q", "A", "initiative");
        let t = file(&mut store, "q", "task", "task");
        let from = crate::items::content_id_of(&store.connection, &a.id)
            .expect("read")
            .expect("ID");
        let to = crate::items::content_id_of(&store.connection, &t.id)
            .expect("read")
            .expect("ID");
        let mut events = store.export_events().expect("export");
        let payload_json =
            json!({"from":from, "to":to, "kind":"belongs-to", "dep_kind":null}).to_string();
        let parents = vec![to.clone()];
        let created_at = "2030-01-01 00:00:00".to_owned();
        let event_id = crate::items::event_content_id(
            "relation.added",
            Some(&to),
            &payload_json,
            None,
            &parents,
            &created_at,
        );
        events.push(crate::items::TrackerEvent {
            event_id,
            parents,
            issue_id: Some(to),
            kind: "relation.added".into(),
            payload_json,
            actor: None,
            created_at,
        });
        let error = store
            .import_events(&events)
            .expect_err("invalid imported membership");
        assert!(format!("{error:?}")
            .contains("belongs-to requires a task source and an initiative target"));
        assert!(
            store.relations(&a.id).expect("relations").is_empty(),
            "invalid projection was rolled back"
        );
    }

    #[test]
    fn initiative_refusals_explain_the_grouping_contract() {
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let a = file(&mut store, "q", "A", "initiative");
        let t = file(&mut store, "q", "task", "task");
        assert!(format!(
            "{:?}",
            issue_kind(&json!({"kind":"epic"})).expect_err("invalid kind")
        )
        .contains("issue kind must be task or initiative"));
        assert!(format!(
            "{:?}",
            store
                .add_relation(&a.id, &t.id, "belongs-to", None)
                .expect_err("invalid endpoints")
        )
        .contains("belongs-to requires a task source and an initiative target"));
        assert!(format!(
            "{:?}",
            store
                .add_relation(&t.id, &a.id, "blocks", None)
                .expect_err("invalid dependency")
        )
        .contains("dependencies connect tasks, not initiatives"));
        assert!(format!(
            "{:?}",
            store
                .set_field(&a.id, "kind", "task")
                .expect_err("immutable")
        )
        .contains("issue kind is immutable"));
        assert!(format!(
            "{:?}",
            store.initiative_members(&t.id).expect_err("not a group")
        )
        .contains("is not an initiative"));
        store
            .add_relation(&t.id, &a.id, "belongs-to", None)
            .expect("membership");
        assert!(format!(
            "{:?}",
            store
                .finish_item(&a.id, None, None)
                .expect_err("unfinished")
        )
        .contains("finish with a summary explaining their disposition"));
        // An initiative with no members remains an explicit outcome judgment.
        let empty = file(&mut store, "q", "empty", "initiative");
        assert_eq!(
            store
                .get_item(&empty.id)
                .expect("read")
                .expect("group")
                .status,
            "open"
        );
        store
            .finish_item(&empty.id, None, None)
            .expect("explicit closure");
    }

    #[test]
    fn initiatives_are_sets_with_independent_task_execution_and_explicit_closure() {
        let mut store = WorkItemStore::open_in_memory().expect("test operation succeeds");
        let a = file(&mut store, "company", "A", "initiative");
        let b = file(&mut store, "company", "B", "initiative");
        let task = file(&mut store, "product", "shared task", "task");
        store
            .add_relation(&task.id, &a.id, "belongs-to", None)
            .expect("test operation succeeds");
        let events = store
            .export_events()
            .expect("test operation succeeds")
            .len();
        store
            .add_relation(&task.id, &a.id, "belongs-to", None)
            .expect("test operation succeeds");
        assert_eq!(
            store
                .export_events()
                .expect("test operation succeeds")
                .len(),
            events,
            "duplicate membership is a no-op"
        );
        store
            .add_relation(&task.id, &b.id, "belongs-to", None)
            .expect("test operation succeeds");
        assert_eq!(
            store
                .initiative_members(&a.id)
                .expect("test operation succeeds")[0]
                .id,
            task.id
        );
        assert_eq!(
            store
                .initiative_members(&b.id)
                .expect("test operation succeeds")[0]
                .queue,
            "product"
        );
        assert!(store
            .ready_items("company")
            .expect("test operation succeeds")
            .is_empty());
        assert_eq!(
            store
                .ready_items("product")
                .expect("test operation succeeds")[0]
                .id,
            task.id
        );
        assert!(matches!(
            store.claim_item_at(
                &a.id,
                "agent",
                None,
                "2030-01-01 00:00:00",
                Some("override")
            ),
            Ok(ClaimOutcome::NotReady { .. })
        ));
        assert!(matches!(
            store
                .claim_item(&task.id, "agent", None)
                .expect("test operation succeeds"),
            ClaimOutcome::Claimed
        ));
        assert!(store.finish_item(&a.id, None, None).is_err());
        assert!(store.finish_item(&a.id, Some("  "), None).is_err());
        assert!(store.set_field(&a.id, "status", "closed").is_err());
        let token = store
            .issue_conflicts(&a.id)
            .expect("test operation succeeds")
            .expect("test operation succeeds")
            .state_token;
        assert!(store
            .set_field_checked(&a.id, "status", "closed", &token)
            .is_err());
        assert_eq!(
            store
                .get_item(&a.id)
                .expect("test operation succeeds")
                .expect("test operation succeeds")
                .status,
            "open"
        );
        assert_eq!(
            store
                .finish_item(
                    &a.id,
                    Some("Shared task retained for initiative B; outcome A verified"),
                    None
                )
                .expect("test operation succeeds"),
            FinishOutcome::Finished
        );
        assert_eq!(
            store
                .get_item(&task.id)
                .expect("test operation succeeds")
                .expect("test operation succeeds")
                .status,
            "in_progress"
        );
        store
            .finish_item(&task.id, Some("done"), Some("agent"))
            .expect("test operation succeeds");
        assert_eq!(
            store
                .get_item(&b.id)
                .expect("test operation succeeds")
                .expect("test operation succeeds")
                .status,
            "open",
            "all members closed never auto-closes"
        );
        let later = file(&mut store, "other", "later task", "task");
        store
            .add_relation(&later.id, &a.id, "belongs-to", None)
            .expect("test operation succeeds");
        assert_eq!(
            store
                .get_item(&a.id)
                .expect("test operation succeeds")
                .expect("test operation succeeds")
                .status,
            "closed",
            "new members never auto-reopen"
        );
        store
            .remove_relation(&task.id, &a.id, "belongs-to")
            .expect("test operation succeeds");
        assert_eq!(
            store
                .initiative_members(&b.id)
                .expect("test operation succeeds")
                .len(),
            1,
            "removing one membership leaves the other"
        );
        store.rebuild_projection().expect("test operation succeeds");
        assert_eq!(
            store
                .initiative_members(&a.id)
                .expect("test operation succeeds")[0]
                .id,
            later.id
        );
        let mut recovered = WorkItemStore::open_in_memory().expect("test operation succeeds");
        let mut events = store.export_events().expect("test operation succeeds");
        events.reverse();
        recovered
            .import_events(&events)
            .expect("test operation succeeds");
        let recovered_a = recovered
            .list_items(None, None)
            .expect("test operation succeeds")
            .into_iter()
            .find(|i| i.title == "A")
            .expect("test operation succeeds");
        assert_eq!(
            issue_kind(&recovered_a.metadata).expect("test operation succeeds"),
            "initiative"
        );
        assert_eq!(recovered_a.status, "closed");
        assert_eq!(
            recovered
                .initiative_members(&recovered_a.id)
                .expect("test operation succeeds")[0]
                .title,
            "later task"
        );
    }

    #[test]
    fn inspection_reuses_query_snapshot_without_losing_read_set_checks() {
        let path = crate::scratch::path("whip-initiative-query-snapshot");
        let mut writer = WorkItemStore::open(&path).unwrap();
        let group = file(&mut writer, "company", "group", "initiative");
        let member = file(&mut writer, "product", "member", "task");
        writer
            .add_relation(&member.id, &group.id, "belongs-to", None)
            .unwrap();
        let reader = WorkItemStore::open_read_snapshot(&path).unwrap();
        let at = reader.store_now().unwrap();
        assert_eq!(
            reader
                .inspect_initiative_at(&group.id, &at)
                .unwrap()
                .members
                .len(),
            1
        );
        let allowed = std::collections::BTreeSet::from(["company".to_owned()]);
        let error = reader
            .inspect_initiative_for_queues_at(&group.id, &at, &allowed)
            .unwrap_err();
        assert!(format!("{error:?}").contains("outside the readable tracker set"));
        let later = file(&mut writer, "product", "later", "task");
        writer
            .add_relation(&later.id, &group.id, "belongs-to", None)
            .unwrap();
        assert_eq!(
            reader
                .inspect_initiative_at(&group.id, &at)
                .unwrap()
                .members
                .len(),
            1
        );
        assert!(!reader.connection.is_autocommit());
        let fresh = WorkItemStore::open_read_snapshot(&path).unwrap();
        assert_eq!(
            fresh
                .inspect_initiative_at(&group.id, &at)
                .unwrap()
                .members
                .len(),
            2
        );
        assert_eq!(
            writer
                .inspect_initiative_at(&group.id, &at)
                .unwrap()
                .members
                .len(),
            2
        );
        assert!(writer.connection.is_autocommit());
        drop(fresh);
        drop(reader);
        drop(writer);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn inspection_refuses_an_unreadable_member_before_loading_its_record() {
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let initiative = file(&mut store, "company", "A", "initiative");
        let task = file(&mut store, "product", "task", "task");
        store
            .add_relation(&task.id, &initiative.id, "belongs-to", None)
            .expect("membership");
        store
            .connection
            .execute(
                "UPDATE tracker_issues SET metadata_json = 'not-json' WHERE issue_id = ?1",
                [&task.id],
            )
            .expect("corrupt member record");
        let allowed = std::collections::BTreeSet::from(["company".to_owned()]);
        let error = store
            .inspect_initiative_for_queues_at(&initiative.id, "2030-01-01T00:00:00Z", &allowed)
            .expect_err("unreadable member");
        assert!(format!("{error:?}").contains("outside the readable tracker set"));
    }

    #[test]
    fn inspection_refuses_an_unreadable_initiative_before_loading_its_record() {
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let initiative = file(&mut store, "company", "A", "initiative");
        store
            .connection
            .execute(
                "UPDATE tracker_issues SET metadata_json = 'not-json' WHERE issue_id = ?1",
                [&initiative.id],
            )
            .expect("corrupt initiative record");
        let allowed = std::collections::BTreeSet::from(["product".to_owned()]);
        let error = store
            .inspect_initiative_for_queues_at(&initiative.id, "2030-01-01T00:00:00Z", &allowed)
            .expect_err("unreadable initiative");
        assert!(format!("{error:?}").contains("outside the readable tracker set"));
    }

    #[test]
    fn initiative_membership_and_kind_refuse_invalid_endpoints_and_reclassification() {
        let mut store = WorkItemStore::open_in_memory().expect("test operation succeeds");
        let initiative = file(&mut store, "q", "group", "initiative");
        let task = file(&mut store, "q", "task", "task");
        let legacy = store
            .file_item("q", "legacy", "", &[], &json!({}), None, None)
            .expect("test operation succeeds");
        assert_eq!(
            issue_kind(&legacy.metadata).expect("test operation succeeds"),
            "task"
        );
        for (from, to) in [
            (&initiative.id, &initiative.id),
            (&initiative.id, &task.id),
            (&task.id, &task.id),
            (&task.id, &"missing".to_owned()),
        ] {
            assert!(store.add_relation(from, to, "belongs-to", None).is_err());
        }
        for (from, to) in [(&initiative.id, &task.id), (&task.id, &initiative.id)] {
            assert!(store.add_relation(from, to, "blocks", None).is_err());
        }
        assert!(store.set_field(&task.id, "kind", "initiative").is_err());
        assert!(store
            .set_field(&initiative.id, "metadata.kind", "task")
            .is_err());
        assert!(store
            .file_item("q", "bad", "", &[], &json!({"kind":"epic"}), None, None)
            .is_err());
        assert!(store
            .file_item("q", "bad", "", &[], &json!({"kind":null}), None, None)
            .is_err());
        assert!(store.initiative_members(&task.id).is_err());
        store
            .add_relation(&legacy.id, &initiative.id, "belongs-to", None)
            .expect("test operation succeeds");
        store
            .finish_item(&legacy.id, None, None)
            .expect("test operation succeeds");
        store
            .finish_item(&initiative.id, None, None)
            .expect("test operation succeeds");
        assert!(store
            .ready_items("q")
            .expect("test operation succeeds")
            .iter()
            .all(|i| i.id != initiative.id));
    }
}
