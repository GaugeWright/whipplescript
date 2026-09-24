//! The native store's side of the one readiness (DR-0126): how it fetches the
//! facts [`super::readiness`] decides from, and the store operations built on
//! that decision — the ready set, the claim guard, the explanation, deferral,
//! the review view, the derived order, and the next instant time alone can
//! change any of it.
//!
//! Waits and ordering-statement writers are derived on read from the issue's
//! own events rather than kept in a projection table: the events are already
//! merge-stable and rebuild-stable, so a derivation over them is too, and there
//! is no second copy to fall out of step.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use super::readiness::{
    derive_positions, next_time_change, review_due, unready_reasons, Blocker, OrderingGraph,
    Positions, ReadinessSource, Unready, Wait, WaitCondition, ORDERING_DEPENDENCY_KINDS,
};
use super::{
    analyze_issue_dag, content_id_of, load_issue_events, row_to_item, tx_append_raw, tx_now,
    WorkItem, WorkItemStore, ACTIVE_LEASE, ISSUE_COLS,
};
use crate::{StoreError, StoreResult};

/// [`ReadinessSource`] over one native connection. A transaction derefs to its
/// connection, so the claim guard reads through the same transaction it writes
/// in and cannot race the facts it decided on.
pub(super) struct NativeReadiness<'c>(pub(super) &'c Connection);

impl ReadinessSource for NativeReadiness<'_> {
    fn durable_status(&self, issue: &str) -> StoreResult<Option<String>> {
        Ok(self
            .0
            .query_row(
                "SELECT status FROM tracker_issues WHERE issue_id = ?1",
                [issue],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn queue_of(&self, issue: &str) -> StoreResult<Option<String>> {
        Ok(self
            .0
            .query_row(
                "SELECT queue FROM tracker_issues WHERE issue_id = ?1",
                [issue],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn active_lease_at(
        &self,
        issue: &str,
        at: &str,
    ) -> StoreResult<Option<(String, Option<String>)>> {
        Ok(self
            .0
            .query_row(
                &format!(
                    "SELECT actor, expires_at FROM tracker_leases WHERE issue_id = ?1 AND {} \
                     ORDER BY acquired_at DESC LIMIT 1",
                    ACTIVE_LEASE.replace('?', "?2")
                ),
                params![issue, at],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    fn blockers(&self, issue: &str) -> StoreResult<Vec<Blocker>> {
        let mut statement = self.0.prepare(
            "SELECT r.from_issue, r.dep_kind, b.status FROM tracker_relations r \
             JOIN tracker_issues b ON b.issue_id = r.from_issue \
             WHERE r.to_issue = ?1 AND r.kind = 'blocks' ORDER BY r.from_issue",
        )?;
        let rows = statement
            .query_map([issue], |row| {
                Ok(Blocker {
                    issue: row.get(0)?,
                    dep_kind: row.get(1)?,
                    status: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn conflicted_fields(&self, issue: &str) -> StoreResult<Vec<String>> {
        let Some(content_id) = content_id_of(self.0, issue)? else {
            return Ok(Vec::new());
        };
        Ok(analyze_issue_dag(&load_issue_events(self.0, &content_id)?)
            .field_conflicts
            .into_iter()
            .map(|conflict| conflict.field)
            .collect())
    }

    fn waits(&self, issue: &str) -> StoreResult<Vec<Wait>> {
        let Some(content_id) = content_id_of(self.0, issue)? else {
            return Ok(Vec::new());
        };
        let mut statement = self.0.prepare(
            "SELECT event_id, kind, whip_tracker_event_open(event_id, kind, payload_json), actor, created_at \
             FROM tracker_events WHERE issue_id = ?1 AND kind IN ('wait.added', 'wait.removed') \
             ORDER BY event_seq",
        )?;
        let rows = statement
            .query_map([&content_id], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(super::readiness::live_waits(
            issue,
            rows.into_iter()
                .map(|(id, kind, payload, actor, created_at)| {
                    (id.unwrap_or_default(), kind, payload, actor, created_at)
                }),
        ))
    }

    fn status_by_content_id(&self, content_id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .0
            .query_row(
                "SELECT i.status FROM tracker_aliases a JOIN tracker_issues i ON i.issue_id = a.alias \
                 WHERE a.content_id = ?1",
                [content_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn alias_of(&self, content_id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .0
            .query_row(
                "SELECT alias FROM tracker_aliases WHERE content_id = ?1",
                [content_id],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn label_count(&self, queue: &str, label: &str) -> StoreResult<i64> {
        let mut statement = self.0.prepare(
            "SELECT whip_payload_open('tracker.issue.labels_json', issue_id, labels_json) \
             FROM tracker_issues WHERE queue = ?1 AND status != 'canceled'",
        )?;
        let labels = statement
            .query_map([queue], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(super::readiness::count_label(
            labels.iter().map(String::as_str),
            label,
        ))
    }

    fn norm_reached(&self, record: &str, status: &str) -> StoreResult<bool> {
        let mut statement = self.0.prepare(
            "SELECT payload_json FROM tracker_events WHERE issue_id = ?1 \
             AND kind IN ('norm.record.transitioned', 'norm.record.retired')",
        )?;
        let payloads = statement
            .query_map([record], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(payloads
            .iter()
            .any(|payload| super::readiness::norm_event_reaches(payload, record, status)))
    }

    fn norm_record_known(&self, record: &str) -> StoreResult<bool> {
        Ok(self
            .0
            .query_row(
                "SELECT 1 FROM tracker_events WHERE event_id = ?1 AND kind = 'norm.record.created'",
                [record],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}

impl WorkItemStore {
    /// The store's own clock, in the canonical instant shape. Used only as the
    /// CLI's boundary instant — the kernel always supplies its own.
    pub fn store_now(&self) -> StoreResult<String> {
        Ok(self
            .connection
            .query_row("SELECT datetime('now')", [], |row| row.get(0))?)
    }

    /// Every reason `issue` is not ready at `at` (DR-0126): the explanation.
    pub fn unready_reasons_at(&self, issue: &str, at: &str) -> StoreResult<Vec<Unready>> {
        unready_reasons(&NativeReadiness(&self.connection), issue, at)
    }

    /// The ready set of `queue` at `at`, in derived order: open issues for which
    /// the one readiness has no reason to refuse.
    pub fn ready_items_at(&self, queue: &str, at: &str) -> StoreResult<Vec<WorkItem>> {
        let candidates = {
            let mut statement = self.connection.prepare(&format!(
                "SELECT {ISSUE_COLS} FROM tracker_issues \
                 WHERE queue = ?1 AND status = 'open' ORDER BY created_at, issue_id"
            ))?;
            let rows = statement
                .query_map([queue], row_to_item)?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let source = NativeReadiness(&self.connection);
        let mut ready = Vec::with_capacity(candidates.len());
        for item in candidates {
            if unready_reasons(&source, &item.id, at)?.is_empty() {
                ready.push(item);
            }
        }
        if ready.len() > 1 {
            let positions = self.positions()?;
            let filing = self.filing_order()?;
            ready.sort_by(|a, b| positions.cmp(&a.id, &b.id, &filing));
        }
        Ok(ready)
    }

    /// Open issues in `queue` with a wait past its review date and still unmet
    /// at `at` — the owner's review view. `assignee` narrows it to one owner.
    pub fn review_items_at(
        &self,
        queue: Option<&str>,
        assignee: Option<&str>,
        at: &str,
    ) -> StoreResult<Vec<WorkItem>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ISSUE_COLS} FROM tracker_issues WHERE status = 'open' \
             AND (?1 IS NULL OR queue = ?1) AND (?2 IS NULL OR assigned_to = ?2) \
             ORDER BY created_at, issue_id"
        ))?;
        let candidates = statement
            .query_map(params![queue, assignee], row_to_item)?
            .collect::<Result<Vec<_>, _>>()?;
        let source = NativeReadiness(&self.connection);
        let mut due = Vec::new();
        for item in candidates {
            if review_due(&source, &item.id, at)? {
                due.push(item);
            }
        }
        Ok(due)
    }

    /// The earliest instant after `at` at which readiness of any issue in
    /// `queues` can change by time alone — what a parked instance must wake for.
    pub fn next_readiness_change_after(
        &self,
        queues: &[String],
        at: &str,
    ) -> StoreResult<Option<String>> {
        let source = NativeReadiness(&self.connection);
        let mut earliest: Option<String> = None;
        for queue in queues {
            let ids = {
                let mut statement = self.connection.prepare(
                    "SELECT issue_id FROM tracker_issues WHERE queue = ?1 AND status = 'open'",
                )?;
                let rows = statement
                    .query_map([queue], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                rows
            };
            for id in ids {
                if let Some(instant) = next_time_change(&source, &id, at)? {
                    if earliest.as_ref().is_none_or(|current| &instant < current) {
                        earliest = Some(instant);
                    }
                }
            }
        }
        Ok(earliest)
    }

    /// The live waits on an issue, in the order they were added.
    pub fn waits(&self, issue: &str) -> StoreResult<Vec<Wait>> {
        NativeReadiness(&self.connection).waits(issue)
    }

    /// Each live wait on `issue` with what it observed at `at`, and its
    /// condition rendered with local names — for `waits` and `show`.
    pub fn wait_verdicts(
        &self,
        issue: &str,
        at: &str,
    ) -> StoreResult<Vec<(Wait, super::readiness::WaitVerdict, String)>> {
        let source = NativeReadiness(&self.connection);
        let queue = source.queue_of(issue)?.unwrap_or_default();
        let alias = |content_id: &str| {
            source
                .alias_of(content_id)
                .ok()
                .flatten()
                .unwrap_or_else(|| content_id.to_owned())
        };
        let mut out = Vec::new();
        for wait in source.waits(issue)? {
            let verdict = super::readiness::evaluate_wait(&source, &queue, &wait.condition, at)?;
            let described = wait.condition.describe(&alias);
            out.push((wait, verdict, described));
        }
        Ok(out)
    }

    /// Defer `issue` until `condition` holds, to be reviewed at `review_at`
    /// (DR-0126 Decision 2). Returns the wait's id. A condition may read only
    /// what the issue's own queue can see: a `settled` target in another queue
    /// is refused, because that is a dependency (`dep add`), not a wait.
    pub fn add_wait(
        &mut self,
        issue: &str,
        condition: &WaitCondition,
        review_at: &str,
        actor: Option<&str>,
    ) -> StoreResult<String> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let source = NativeReadiness(&tx);
        let queue = source
            .queue_of(issue)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {issue}")))?;
        super::readiness::validate_wait(&source, issue, &queue, condition, review_at)?;
        let content_id = content_id_of(&tx, issue)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {issue}")))?;
        let payload = json!({"condition": condition, "review_at": review_at});
        let wait_id = tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "wait.added",
            &payload.to_string(),
            actor,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.commit()?;
        Ok(wait_id)
    }

    /// Lift waits on `issue` early: the one named, or all of them. Returns how
    /// many were lifted. Lifting early is an act by a person; a wait whose
    /// condition comes to hold needs none.
    pub fn remove_waits(
        &mut self,
        issue: &str,
        wait: Option<&str>,
        actor: Option<&str>,
    ) -> StoreResult<usize> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let content_id = content_id_of(&tx, issue)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {issue}")))?;
        let targets: Vec<String> = NativeReadiness(&tx)
            .waits(issue)?
            .into_iter()
            .map(|live| live.id)
            .filter(|id| wait.is_none_or(|wanted| id == wanted || id.starts_with(wanted)))
            .collect();
        if wait.is_some() && targets.len() > 1 {
            return Err(StoreError::Conflict(format!(
                "wait prefix `{}` names {} waits; give more of the id",
                wait.unwrap_or_default(),
                targets.len()
            )));
        }
        for target in &targets {
            tx_append_raw(
                &tx,
                Some(&content_id),
                None,
                "wait.removed",
                &json!({"wait": target}).to_string(),
                actor,
                self.event_effect_id.as_deref(),
                &now,
            )?;
        }
        tx.commit()?;
        Ok(targets.len())
    }

    /// Every issue's derived position (DR-0126 Decision 4).
    pub fn positions(&self) -> StoreResult<Positions> {
        Ok(derive_positions(&self.ordering_graph()?))
    }

    /// The issues whose ordering statements contradict each other.
    pub fn ordering_conflicts(&self) -> StoreResult<BTreeSet<String>> {
        Ok(self.positions()?.conflicted)
    }

    fn filing_order(&self) -> StoreResult<BTreeMap<String, usize>> {
        let mut statement = self
            .connection
            .prepare("SELECT issue_id FROM tracker_issues ORDER BY created_at, issue_id")?;
        let ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids
            .into_iter()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect())
    }

    /// The inputs to the derived position, read from the projection and, for
    /// who wrote each ordering statement, from the events behind it.
    pub fn ordering_graph(&self) -> StoreResult<OrderingGraph> {
        let conn = &self.connection;
        let mut graph = OrderingGraph::default();
        {
            let mut statement = conn.prepare(
                "SELECT issue_id, assigned_to FROM tracker_issues ORDER BY created_at, issue_id",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            for (id, assignee) in rows {
                if let Some(owner) = assignee {
                    graph.owners.insert(id.clone(), owner);
                }
                graph.issues.push(id);
            }
        }
        {
            let mut statement = conn.prepare(
                "SELECT from_issue, to_issue, kind, dep_kind FROM tracker_relations \
                 WHERE kind IN ('parent-of', 'blocks')",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let writers = self.ordering_writers()?;
            for (from, to, kind, dep_kind) in rows {
                if kind == "parent-of" {
                    graph.parents.entry(to).or_default().insert(from);
                } else if dep_kind
                    .as_deref()
                    .is_some_and(|dk| ORDERING_DEPENDENCY_KINDS.contains(&dk))
                {
                    let who = writers
                        .get(&(from.clone(), to.clone()))
                        .cloned()
                        .unwrap_or_default();
                    graph.statements.push((from, to, who));
                } else {
                    graph.gates.push((from, to));
                }
            }
        }
        Ok(graph)
    }

    /// Who wrote each live `blocks` edge, keyed `(from, to)` by alias: the
    /// actors of its `relation.added` events since the last `relation.removed`
    /// of the same edge, in log order — the order the projection folded them.
    fn ordering_writers(&self) -> StoreResult<BTreeMap<(String, String), BTreeSet<String>>> {
        let mut statement = self.connection.prepare(
            "SELECT kind, whip_tracker_event_open(event_id, kind, payload_json), actor FROM tracker_events \
             WHERE kind IN ('relation.added', 'relation.removed') ORDER BY event_seq",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        let mut aliases: BTreeMap<String, Option<String>> = BTreeMap::new();
        let mut alias = |content_id: &str| -> StoreResult<Option<String>> {
            if let Some(known) = aliases.get(content_id) {
                return Ok(known.clone());
            }
            let found = NativeReadiness(&self.connection).alias_of(content_id)?;
            aliases.insert(content_id.to_owned(), found.clone());
            Ok(found)
        };
        let mut writers: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for (kind, payload, actor) in rows {
            let payload: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
            if payload["kind"].as_str() != Some("blocks") {
                continue;
            }
            let (Some(from), Some(to)) = (payload["from"].as_str(), payload["to"].as_str()) else {
                continue;
            };
            let (Some(from), Some(to)) = (alias(from)?, alias(to)?) else {
                continue;
            };
            if kind == "relation.removed" {
                writers.remove(&(from, to));
            } else if let Some(actor) = actor {
                writers.entry((from, to)).or_default().insert(actor);
            }
        }
        Ok(writers)
    }
}

#[cfg(test)]
mod tests {
    use super::super::readiness::{Unready, WaitCondition};
    use super::super::{ClaimOutcome, WorkItemStore};
    use serde_json::json;

    fn store() -> WorkItemStore {
        WorkItemStore::open_in_memory().expect("opens")
    }

    fn file(store: &mut WorkItemStore, queue: &str, title: &str, labels: &[&str]) -> String {
        let labels: Vec<String> = labels.iter().map(|label| (*label).to_owned()).collect();
        store
            .file_item(queue, title, "", &labels, &json!({}), None, None)
            .expect("files")
            .id
    }

    const AT: &str = "2030-01-01 00:00:00";

    /// A refusal with this text. The mutation sweep checks a refusal by
    /// rewriting its message, so a test that only sees "some error" pins nothing.
    fn refused_with<T: std::fmt::Debug>(result: crate::StoreResult<T>, text: &str) {
        match result {
            Err(error) => assert!(
                format!("{error:?}").contains(text),
                "refused, but not with `{text}`: {error:?}"
            ),
            Ok(value) => panic!("not refused (wanted `{text}`): {value:?}"),
        }
    }

    fn ready(store: &WorkItemStore, queue: &str, at: &str) -> Vec<String> {
        store
            .ready_items_at(queue, at)
            .expect("ready")
            .into_iter()
            .map(|item| item.id)
            .collect()
    }

    /// DR-0126 RV-1: the claim guard is the ready set's own definition. Before
    /// it, a claim on a blocked issue succeeded (reproduced 2026-09-24).
    #[test]
    fn a_blocked_issue_is_neither_ready_nor_claimable_and_an_override_is_recorded() {
        let mut store = store();
        let blocker = file(&mut store, "q", "blocker", &[]);
        let blocked = file(&mut store, "q", "blocked", &[]);
        store
            .add_relation(&blocker, &blocked, "blocks", None)
            .expect("gates");
        assert_eq!(ready(&store, "q", AT), vec![blocker.clone()]);
        match store
            .claim_item_at(&blocked, "a", None, AT, None)
            .expect("claims")
        {
            ClaimOutcome::NotReady { reasons } => assert_eq!(
                reasons,
                vec![Unready::BlockedBy {
                    issue: blocker.clone(),
                    dep_kind: None
                }]
            ),
            other => panic!("a blocked issue was not refused: {other:?}"),
        }
        assert_eq!(
            store
                .claim_item_at(&blocked, "a", None, AT, Some("pairing on it"))
                .expect("claims"),
            ClaimOutcome::Claimed
        );
        let acquired = store
            .export_events()
            .expect("exports")
            .into_iter()
            .rfind(|event| event.kind == "claim.acquired")
            .expect("a claim event");
        let payload: serde_json::Value =
            serde_json::from_str(&acquired.payload_json).expect("json");
        assert_eq!(payload["override"]["reason"], "pairing on it");
        assert!(payload["override"]["unready"][0]
            .as_str()
            .unwrap_or_default()
            .contains(&blocker));
    }

    /// A closed issue is not work to claim, override or not (reproduced
    /// 2026-09-24: `WS-1 claimed [closed]`).
    #[test]
    fn a_closed_issue_is_refused_even_with_an_override() {
        let mut store = store();
        let id = file(&mut store, "q", "done", &[]);
        store.finish_item(&id, None, None).expect("finishes");
        assert_eq!(
            store
                .claim_item_at(&id, "a", None, AT, Some("because"))
                .expect("claims"),
            ClaimOutcome::NotOpen {
                status: "closed".to_owned()
            }
        );
    }

    /// DR-0126 Decision 3.
    #[test]
    fn ordering_kinds_do_not_gate_and_discovered_does() {
        let mut store = store();
        let first = file(&mut store, "q", "first", &[]);
        let ordered = file(&mut store, "q", "ordered", &[]);
        let soft = file(&mut store, "q", "soft", &[]);
        let found = file(&mut store, "q", "found", &[]);
        store
            .add_relation(&first, &ordered, "blocks", Some("order"))
            .expect("orders");
        store
            .add_relation(&first, &soft, "blocks", Some("soft"))
            .expect("orders");
        store
            .add_relation(&first, &found, "blocks", Some("discovered"))
            .expect("gates");
        let ready = ready(&store, "q", AT);
        assert!(ready.contains(&ordered) && ready.contains(&soft));
        assert!(!ready.contains(&found));
    }

    /// DR-0126 RV-3: a claim lapses at the caller's instant. Before it, the
    /// store compared a virtual-clock deadline against its own wall clock, so
    /// a claim timed in a `given clock at` scenario never lapsed there.
    #[test]
    fn claims_lapse_at_the_callers_instant_not_the_store_clock() {
        let mut store = store();
        let id = file(&mut store, "q", "timed", &[]);
        assert_eq!(
            store
                .claim_item_at(&id, "a", Some("2030-01-01 00:10:00"), AT, None)
                .expect("claims"),
            ClaimOutcome::Claimed
        );
        assert!(ready(&store, "q", "2030-01-01 00:05:00").is_empty());
        assert_eq!(ready(&store, "q", "2030-01-01 00:20:00"), vec![id.clone()]);
        assert_eq!(
            store
                .claim_item_at(&id, "b", None, "2030-01-01 00:20:00", None)
                .expect("claims"),
            ClaimOutcome::Claimed
        );
    }

    /// DR-0126 Decision 2: each bundled condition gates until it holds.
    #[test]
    fn waits_gate_until_their_condition_holds() {
        let mut store = store();
        let dated = file(&mut store, "q", "dated", &[]);
        let after = file(&mut store, "q", "after", &[]);
        let target = file(&mut store, "q", "target", &[]);
        let demand = file(&mut store, "q", "demand", &[]);
        let target_cid = store.subject_content_id(&target).unwrap().unwrap();
        let review = "2099-01-01 00:00:00";
        store
            .add_wait(
                &dated,
                &WaitCondition::At {
                    instant: "2030-06-01 00:00:00".into(),
                },
                review,
                Some("owner"),
            )
            .expect("defers");
        store
            .add_wait(
                &after,
                &WaitCondition::Settled { issue: target_cid },
                review,
                None,
            )
            .expect("defers");
        store
            .add_wait(
                &demand,
                &WaitCondition::Count {
                    label: "ask".into(),
                    at_least: 2,
                },
                review,
                None,
            )
            .expect("defers");
        let now = ready(&store, "q", AT);
        assert!(!now.contains(&dated) && !now.contains(&after) && !now.contains(&demand));
        assert!(ready(&store, "q", "2030-06-01 00:00:00").contains(&dated));
        // A withdrawn target settles the wait, as it unblocks a dependency.
        store.cancel_item(&target, None, None).expect("cancels");
        assert!(ready(&store, "q", AT).contains(&after));
        // A canceled request is not demand.
        let ask = file(&mut store, "q", "ask one", &["ask"]);
        let withdrawn = file(&mut store, "q", "ask two", &["ask"]);
        store.cancel_item(&withdrawn, None, None).expect("cancels");
        assert!(!ready(&store, "q", AT).contains(&demand));
        file(&mut store, "q", "ask three", &["ask"]);
        assert!(ready(&store, "q", AT).contains(&demand));
        assert!(ready(&store, "q", AT).contains(&ask));
    }

    #[test]
    fn review_is_due_only_for_an_unmet_wait_past_its_date() {
        let mut store = store();
        let id = file(&mut store, "q", "parked", &[]);
        store
            .add_wait(
                &id,
                &WaitCondition::At {
                    instant: "2031-01-01 00:00:00".into(),
                },
                "2030-02-01 00:00:00",
                None,
            )
            .expect("defers");
        let due = |at: &str| {
            store
                .review_items_at(Some("q"), None, at)
                .expect("reviews")
                .len()
        };
        assert_eq!(due("2030-01-15 00:00:00"), 0, "before its review date");
        assert_eq!(due("2030-02-15 00:00:00"), 1, "past it and unmet");
        assert_eq!(due("2031-01-02 00:00:00"), 0, "met: never due");
    }

    #[test]
    fn lifting_a_wait_early_restores_readiness() {
        let mut store = store();
        let id = file(&mut store, "q", "parked", &[]);
        let wait = store
            .add_wait(
                &id,
                &WaitCondition::At {
                    instant: "2031-01-01 00:00:00".into(),
                },
                "2031-01-01 00:00:00",
                Some("owner"),
            )
            .expect("defers");
        assert!(ready(&store, "q", AT).is_empty());
        assert_eq!(
            store
                .remove_waits(&id, Some(&wait[..10]), Some("owner"))
                .expect("lifts"),
            1
        );
        assert_eq!(ready(&store, "q", AT), vec![id]);
    }

    /// Waits are derived from events, so a rebuild and a merge carry them.
    #[test]
    fn waits_survive_a_rebuild_and_a_merge() {
        let mut store = store();
        let id = file(&mut store, "q", "parked", &[]);
        store
            .add_wait(
                &id,
                &WaitCondition::At {
                    instant: "2031-01-01 00:00:00".into(),
                },
                "2031-01-01 00:00:00",
                None,
            )
            .expect("defers");
        store.rebuild_projection().expect("rebuilds");
        assert!(ready(&store, "q", AT).is_empty());
        let mut clone = WorkItemStore::open_in_memory().expect("opens");
        clone
            .import_events(&store.export_events().expect("exports"))
            .expect("imports");
        assert!(ready(&clone, "q", AT).is_empty());
        assert_eq!(ready(&clone, "q", "2031-01-01 00:00:00").len(), 1);
    }

    #[test]
    fn a_wait_that_could_never_mean_what_it_says_is_refused() {
        let mut store = store();
        let id = file(&mut store, "q", "parked", &[]);
        let elsewhere = file(&mut store, "other", "elsewhere", &[]);
        let own = store.subject_content_id(&id).unwrap().unwrap();
        let other = store.subject_content_id(&elsewhere).unwrap().unwrap();
        let review = "2031-01-01 00:00:00";
        for (condition, text) in [
            (
                WaitCondition::Settled { issue: own },
                "cannot wait on itself",
            ),
            (
                WaitCondition::Settled { issue: other },
                "a wait reads only its own",
            ),
            (
                WaitCondition::Settled {
                    issue: "no-such-issue".into(),
                },
                "is not an issue held here",
            ),
            (
                WaitCondition::Reached {
                    record: "nope".into(),
                    status: "accepted".into(),
                },
                "is not a record in this workspace's norm ledger",
            ),
            (
                WaitCondition::Reached {
                    record: "nope".into(),
                    status: " ".into(),
                },
                "a status to reach is required",
            ),
            (
                WaitCondition::Count {
                    label: "ask".into(),
                    at_least: 0,
                },
                "a count must be at least 1",
            ),
            (
                WaitCondition::Count {
                    label: " ".into(),
                    at_least: 1,
                },
                "a label to count is required",
            ),
            (
                WaitCondition::At {
                    instant: "tomorrow".into(),
                },
                "`tomorrow` is not an instant",
            ),
        ] {
            refused_with(store.add_wait(&id, &condition, review, None), text);
        }
        refused_with(
            store.add_wait(
                &id,
                &WaitCondition::At {
                    instant: review.into(),
                },
                "someday",
                None,
            ),
            "review date `someday` is not an instant",
        );
    }

    /// `reached` reads the norm ledger's admitted events. The ledger's own
    /// admission is covered where it is built; here a stored transition is
    /// written directly, as admission leaves it.
    #[test]
    fn reached_holds_once_the_ledger_has_an_admitted_transition() {
        let mut store = store();
        let id = file(&mut store, "q", "waits on a decision", &[]);
        store
            .connection
            .execute(
                "INSERT INTO tracker_events (event_id, issue_id, kind, payload_json, created_at) \
                 VALUES ('rec-1', NULL, 'norm.record.created', '{}', '2030-01-01 00:00:00')",
                [],
            )
            .expect("creates");
        store
            .add_wait(
                &id,
                &WaitCondition::Reached {
                    record: "rec-1".into(),
                    status: "accepted".into(),
                },
                "2031-01-01 00:00:00",
                None,
            )
            .expect("defers");
        assert!(ready(&store, "q", AT).is_empty());
        let transition = json!({"statement": {"action": {
            "act": "transition", "record": "rec-1", "status": "accepted",
        }}});
        store
            .connection
            .execute(
                "INSERT INTO tracker_events (event_id, issue_id, kind, payload_json, created_at) \
                 VALUES ('tr-1', 'rec-1', 'norm.record.transitioned', ?1, '2030-01-01 00:00:00')",
                [transition.to_string()],
            )
            .expect("transitions");
        assert_eq!(ready(&store, "q", AT), vec![id]);
    }

    #[test]
    fn the_next_time_change_is_the_earliest_of_expiry_deferral_and_review() {
        let mut store = store();
        let claimed = file(&mut store, "q", "claimed", &[]);
        let deferred = file(&mut store, "q", "deferred", &[]);
        store
            .claim_item_at(&claimed, "a", Some("2030-03-01 00:00:00"), AT, None)
            .expect("claims");
        store
            .add_wait(
                &deferred,
                &WaitCondition::Count {
                    label: "ask".into(),
                    at_least: 1,
                },
                "2030-02-01 00:00:00",
                None,
            )
            .expect("defers");
        let queues = vec!["q".to_owned()];
        assert_eq!(
            store
                .next_readiness_change_after(&queues, AT)
                .expect("reads")
                .as_deref(),
            Some("2030-02-01 00:00:00")
        );
        assert_eq!(
            store
                .next_readiness_change_after(&queues, "2030-02-15 00:00:00")
                .expect("reads")
                .as_deref(),
            Some("2030-03-01 00:00:00")
        );
    }

    /// Nothing is decided at something that is not an instant: a clock stub or
    /// a typo is refused rather than read as "never" or "always".
    #[test]
    fn nothing_is_decided_at_something_that_is_not_an_instant() {
        use super::super::WorkItems;
        let mut store = store();
        let id = file(&mut store, "q", "work", &[]);
        for bad in ["now", "tomorrow", "2030-01-01T00:00:00+02:00"] {
            let wanted = format!("`{bad}` is not an instant");
            refused_with(store.claim_item_at(&id, "a", None, bad, None), &wanted);
            refused_with(WorkItems::ready_items_at(&store, "q", bad), &wanted);
            refused_with(
                WorkItems::next_readiness_change_after(&store, &["q".to_owned()], bad),
                &wanted,
            );
        }
    }

    #[test]
    fn deferring_or_lifting_an_unknown_issue_is_refused() {
        let mut store = store();
        let at = WaitCondition::At {
            instant: "2031-01-01 00:00:00".into(),
        };
        refused_with(
            store.add_wait("WS-99", &at, "2031-01-01 00:00:00", None),
            "unknown issue alias WS-99",
        );
        refused_with(
            store.remove_waits("WS-99", None, None),
            "unknown issue alias WS-99",
        );
        // A prefix that names two waits is refused rather than lifting both.
        let id = file(&mut store, "q", "parked", &[]);
        store
            .add_wait(&id, &at, "2031-01-01 00:00:00", None)
            .expect("defers");
        store
            .add_wait(
                &id,
                &WaitCondition::Count {
                    label: "ask".into(),
                    at_least: 1,
                },
                "2031-01-01 00:00:00",
                None,
            )
            .expect("defers");
        refused_with(store.remove_waits(&id, Some(""), None), "names 2 waits");
        assert_eq!(store.waits(&id).expect("waits").len(), 2);
    }

    /// A projection row with no content id behind it is a damaged store; the
    /// guard and deferral refuse it rather than writing an event about nothing.
    #[test]
    fn an_issue_row_without_an_identity_is_refused() {
        let mut store = store();
        store
            .connection
            .execute(
                "INSERT INTO tracker_issues (issue_id, queue, title) VALUES ('ORPHAN-1', 'q', 'orphan')",
                [],
            )
            .expect("inserts");
        refused_with(
            store.claim_item_at("ORPHAN-1", "a", None, AT, None),
            "unknown issue alias ORPHAN-1",
        );
        refused_with(
            store.add_wait(
                "ORPHAN-1",
                &WaitCondition::At {
                    instant: "2031-01-01 00:00:00".into(),
                },
                "2031-01-01 00:00:00",
                None,
            ),
            "unknown issue alias ORPHAN-1",
        );
    }

    /// DR-0126 Decision 4, end to end through the store.
    #[test]
    fn the_ready_set_follows_the_owners_ranking_and_ignores_proposals() {
        let mut store = store();
        let parent = file(&mut store, "q", "initiative", &[]);
        store.assign_item(&parent, Some("boss")).expect("assigns");
        let a = file(&mut store, "q", "a", &[]);
        let b = file(&mut store, "q", "b", &[]);
        for child in [&a, &b] {
            store
                .add_relation(&parent, child, "parent-of", None)
                .expect("links");
        }
        store
            .add_relation_by(&b, &a, "blocks", Some("order"), Some("intern"))
            .expect("proposes");
        let order = ready(&store, "q", AT);
        let (pa, pb) = (
            order.iter().position(|id| id == &a),
            order.iter().position(|id| id == &b),
        );
        assert!(pa < pb, "a proposal ranks nothing: {order:?}");
        store
            .add_relation_by(&b, &a, "blocks", Some("order"), Some("boss"))
            .expect("ranks");
        let order = ready(&store, "q", AT);
        let (pa, pb) = (
            order.iter().position(|id| id == &a),
            order.iter().position(|id| id == &b),
        );
        assert!(pb < pa, "the owner's ranking holds: {order:?}");
        assert!(store.ordering_conflicts().expect("reads").is_empty());
        store
            .add_relation_by(&a, &b, "blocks", Some("order"), Some("boss"))
            .expect("contradicts");
        let conflicted = store.ordering_conflicts().expect("reads");
        assert!(conflicted.contains(&a) && conflicted.contains(&b));
    }
}
