//! The hosted store's side of the one readiness (DR-0126): the same facts the
//! native store fetches, over `DoSql`, fed to the same shared decision in
//! `whipplescript_store::items::readiness`. Waits and ordering-statement writers
//! are derived from the events on read, as natively, so the two hosts differ
//! only in how a row is fetched.

use std::collections::{BTreeMap, BTreeSet};

use whipplescript_store::items::readiness::{
    count_label, derive_positions, live_waits, next_time_change, norm_event_reaches, Blocker,
    OrderingGraph, Positions, ReadinessSource, Wait, ORDERING_DEPENDENCY_KINDS,
};

use super::*;

/// [`ReadinessSource`] over the hosted store's SQL.
pub(super) struct DoReadiness<'a, S: DoSql>(pub(super) &'a S);

impl<S: DoSql> ReadinessSource for DoReadiness<'_, S> {
    fn durable_status(&self, issue: &str) -> StoreResult<Option<String>> {
        let rows = self
            .0
            .query(
                "SELECT status FROM tracker_issues WHERE issue_id = ?1",
                &[text(issue)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn queue_of(&self, issue: &str) -> StoreResult<Option<String>> {
        let rows = self
            .0
            .query(
                "SELECT queue FROM tracker_issues WHERE issue_id = ?1",
                &[text(issue)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn active_lease_at(
        &self,
        issue: &str,
        at: &str,
    ) -> StoreResult<Option<(String, Option<String>)>> {
        let rows = self
            .0
            .query(
                "SELECT actor, expires_at FROM tracker_leases WHERE issue_id = ?1 \
                 AND released_at IS NULL AND (expires_at IS NULL OR expires_at > ?2) \
                 ORDER BY acquired_at DESC LIMIT 1",
                &[text(issue), text(at)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .first()
            .map(|row| (as_text(&row[0]), as_opt_text(&row[1]))))
    }

    fn blockers(&self, issue: &str) -> StoreResult<Vec<Blocker>> {
        let rows = self
            .0
            .query(
                "SELECT r.from_issue, r.dep_kind, b.status FROM tracker_relations r \
                 JOIN tracker_issues b ON b.issue_id = r.from_issue \
                 WHERE r.to_issue = ?1 AND r.kind = 'blocks' ORDER BY r.from_issue",
                &[text(issue)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| Blocker {
                issue: as_text(&row[0]),
                dep_kind: as_opt_text(&row[1]),
                status: as_text(&row[2]),
            })
            .collect())
    }

    fn conflicted_fields(&self, issue: &str) -> StoreResult<Vec<String>> {
        let Some(content_id) = do_content_id(self.0, issue)? else {
            return Ok(Vec::new());
        };
        Ok(
            whipplescript_store::items::analyze_issue_dag(&do_load_issue_events(
                self.0,
                &content_id,
            )?)
            .field_conflicts
            .into_iter()
            .map(|conflict| conflict.field)
            .collect(),
        )
    }

    fn waits(&self, issue: &str) -> StoreResult<Vec<Wait>> {
        let Some(content_id) = do_content_id(self.0, issue)? else {
            return Ok(Vec::new());
        };
        let rows = self
            .0
            .query(
                "SELECT event_id, kind, payload_json, actor, created_at FROM tracker_events \
                 WHERE issue_id = ?1 AND kind IN ('wait.added', 'wait.removed') ORDER BY event_seq",
                &[text(&content_id)],
            )
            .map_err(sql_err)?;
        Ok(live_waits(
            issue,
            rows.iter().map(|row| {
                (
                    as_opt_text(&row[0]).unwrap_or_default(),
                    as_text(&row[1]),
                    as_text(&row[2]),
                    as_opt_text(&row[3]),
                    as_text(&row[4]),
                )
            }),
        ))
    }

    fn status_by_content_id(&self, content_id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .0
            .query(
                "SELECT i.status FROM tracker_aliases a JOIN tracker_issues i ON i.issue_id = a.alias \
                 WHERE a.content_id = ?1",
                &[text(content_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn alias_of(&self, content_id: &str) -> StoreResult<Option<String>> {
        let rows = self
            .0
            .query(
                "SELECT alias FROM tracker_aliases WHERE content_id = ?1",
                &[text(content_id)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }

    fn label_count(&self, queue: &str, label: &str) -> StoreResult<i64> {
        let rows = self
            .0
            .query(
                "SELECT labels_json FROM tracker_issues WHERE queue = ?1 AND status != 'canceled'",
                &[text(queue)],
            )
            .map_err(sql_err)?;
        let labels: Vec<String> = rows.iter().map(|row| as_text(&row[0])).collect();
        Ok(count_label(labels.iter().map(String::as_str), label))
    }

    fn norm_reached(&self, record: &str, status: &str) -> StoreResult<bool> {
        let rows = self
            .0
            .query(
                "SELECT payload_json FROM tracker_events WHERE issue_id = ?1 \
                 AND kind IN ('norm.record.transitioned', 'norm.record.retired')",
                &[text(record)],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .any(|row| norm_event_reaches(&as_text(&row[0]), record, status)))
    }

    fn norm_record_known(&self, record: &str) -> StoreResult<bool> {
        let rows = self
            .0
            .query(
                "SELECT 1 FROM tracker_events WHERE event_id = ?1 AND kind = 'norm.record.created'",
                &[text(record)],
            )
            .map_err(sql_err)?;
        Ok(!rows.is_empty())
    }
}

impl<Sql: DoSql> DoSqliteStore<Sql> {
    /// The ready set of `queue` at `at`, in derived order (DR-0126).
    pub(super) fn do_ready_items_at(&self, queue: &str, at: &str) -> StoreResult<Vec<WorkItem>> {
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT {DO_ISSUE_COLS} FROM tracker_issues \
                     WHERE queue = ?1 AND status = 'open' ORDER BY created_at, issue_id"
                ),
                &[text(queue)],
            )
            .map_err(sql_err)?;
        let source = DoReadiness(&self.sql);
        let mut ready = Vec::with_capacity(rows.len());
        for row in &rows {
            let item = do_issue_row(row);
            if whipplescript_store::items::readiness::unready_reasons(&source, &item.id, at)?
                .is_empty()
            {
                ready.push(item);
            }
        }
        if ready.len() > 1 {
            let positions = self.do_positions()?;
            let filing = self.do_filing_order()?;
            ready.sort_by(|a, b| positions.cmp(&a.id, &b.id, &filing));
        }
        Ok(ready)
    }

    /// The earliest instant after `at` at which readiness in `queues` can change
    /// by time alone (DR-0126 RV-3).
    pub(super) fn do_next_readiness_change_after(
        &self,
        queues: &[String],
        at: &str,
    ) -> StoreResult<Option<String>> {
        let source = DoReadiness(&self.sql);
        let mut earliest: Option<String> = None;
        for queue in queues {
            let rows = self
                .sql
                .query(
                    "SELECT issue_id FROM tracker_issues WHERE queue = ?1 AND status = 'open'",
                    &[text(queue)],
                )
                .map_err(sql_err)?;
            for row in &rows {
                if let Some(instant) = next_time_change(&source, &as_text(&row[0]), at)? {
                    if earliest.as_ref().is_none_or(|current| &instant < current) {
                        earliest = Some(instant);
                    }
                }
            }
        }
        Ok(earliest)
    }

    pub(super) fn do_positions(&self) -> StoreResult<Positions> {
        Ok(derive_positions(&self.do_ordering_graph()?))
    }

    fn do_filing_order(&self) -> StoreResult<BTreeMap<String, usize>> {
        let rows = self
            .sql
            .query(
                "SELECT issue_id FROM tracker_issues ORDER BY created_at, issue_id",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .enumerate()
            .map(|(index, row)| (as_text(&row[0]), index))
            .collect())
    }

    fn do_ordering_graph(&self) -> StoreResult<OrderingGraph> {
        let mut graph = OrderingGraph::default();
        for row in self
            .sql
            .query(
                "SELECT issue_id, assigned_to FROM tracker_issues ORDER BY created_at, issue_id",
                &[],
            )
            .map_err(sql_err)?
        {
            let id = as_text(&row[0]);
            if let Some(owner) = as_opt_text(&row[1]) {
                graph.owners.insert(id.clone(), owner);
            }
            graph.issues.push(id);
        }
        let writers = self.do_ordering_writers()?;
        for row in self
            .sql
            .query(
                "SELECT from_issue, to_issue, kind, dep_kind FROM tracker_relations \
                 WHERE kind IN ('parent-of', 'blocks')",
                &[],
            )
            .map_err(sql_err)?
        {
            let (from, to, kind, dep_kind) = (
                as_text(&row[0]),
                as_text(&row[1]),
                as_text(&row[2]),
                as_opt_text(&row[3]),
            );
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
        Ok(graph)
    }

    fn do_ordering_writers(&self) -> StoreResult<BTreeMap<(String, String), BTreeSet<String>>> {
        let rows = self
            .sql
            .query(
                "SELECT kind, payload_json, actor FROM tracker_events \
                 WHERE kind IN ('relation.added', 'relation.removed') ORDER BY event_seq",
                &[],
            )
            .map_err(sql_err)?;
        let source = DoReadiness(&self.sql);
        let mut writers: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for row in &rows {
            let payload: serde_json::Value =
                serde_json::from_str(&as_text(&row[1])).unwrap_or(serde_json::Value::Null);
            if payload["kind"].as_str() != Some("blocks") {
                continue;
            }
            let (Some(from), Some(to)) = (payload["from"].as_str(), payload["to"].as_str()) else {
                continue;
            };
            let (Some(from), Some(to)) = (source.alias_of(from)?, source.alias_of(to)?) else {
                continue;
            };
            if as_text(&row[0]) == "relation.removed" {
                writers.remove(&(from, to));
            } else if let Some(actor) = as_opt_text(&row[2]) {
                writers.entry((from, to)).or_default().insert(actor);
            }
        }
        Ok(writers)
    }
}

/// Parity with the native store (DR-0126): the same events, imported, give the
/// same ready set, the same refusals and the same order on the hosted store.
#[cfg(test)]
mod tests {
    use super::super::test_support::store;
    use serde_json::json;
    use whipplescript_store::items::readiness::WaitCondition;
    use whipplescript_store::items::{ClaimOutcome, WorkItemStore, WorkItems};

    const AT: &str = "2030-01-01 00:00:00";

    fn native_file(native: &mut WorkItemStore, title: &str) -> String {
        native
            .file_item("q", title, "", &[], &json!({}), None, None)
            .expect("files")
            .id
    }

    fn ids(items: Vec<whipplescript_store::items::WorkItem>) -> Vec<String> {
        items.into_iter().map(|item| item.id).collect()
    }

    #[test]
    fn the_hosted_store_answers_readiness_as_the_native_one_does() {
        let mut native = WorkItemStore::open_in_memory().expect("opens");
        let blocker = native_file(&mut native, "blocker");
        let blocked = native_file(&mut native, "blocked");
        let later = native_file(&mut native, "later");
        let deferred = native_file(&mut native, "deferred");
        native
            .add_relation(&blocker, &blocked, "blocks", None)
            .unwrap();
        native
            .add_relation_by(&blocker, &later, "blocks", Some("order"), Some("w"))
            .unwrap();
        native
            .add_wait(
                &deferred,
                &WaitCondition::At {
                    instant: "2030-06-01 00:00:00".into(),
                },
                "2030-06-01 00:00:00",
                None,
            )
            .unwrap();
        let mut hosted = store();
        hosted
            .import_events(&native.export_events().unwrap())
            .unwrap();
        let native_ready = ids(native.ready_items_at("q", AT).unwrap());
        let hosted_ready = ids(WorkItems::ready_items_at(&hosted, "q", AT).unwrap());
        assert_eq!(native_ready, vec![blocker.clone(), later.clone()]);
        assert_eq!(hosted_ready, native_ready, "same set, same order");
        assert_eq!(
            ids(WorkItems::ready_items_at(&hosted, "q", "2030-06-01 00:00:00").unwrap()),
            ids(native.ready_items_at("q", "2030-06-01 00:00:00").unwrap())
        );
        match WorkItems::claim_item_at(&mut hosted, &blocked, "a", None, AT).unwrap() {
            ClaimOutcome::NotReady { reasons } => assert_eq!(reasons.len(), 1),
            other => panic!("the hosted store claimed a blocked issue: {other:?}"),
        }
        assert_eq!(
            WorkItems::claim_item_at(&mut hosted, &blocker, "a", Some("2030-01-01 00:10:00"), AT)
                .unwrap(),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            WorkItems::next_readiness_change_after(&hosted, &["q".to_owned()], AT)
                .unwrap()
                .as_deref(),
            Some("2030-01-01 00:10:00"),
            "a parked instance wakes when the claim lapses"
        );
    }

    /// Nothing is decided at something that is not an instant: a clock stub
    /// or a typo is refused, not read as "never" or "always".
    #[test]
    fn the_hosted_store_refuses_to_decide_at_something_that_is_not_an_instant() {
        let mut hosted = store();
        let id = WorkItems::file_item(&mut hosted, "q", "work", "", &[], &json!({}), None, None)
            .unwrap()
            .id;
        // The mutation sweep checks these refusals by rewriting their message,
        // so the text is what is pinned.
        let refused = |error: String, bad: &str| {
            assert!(
                error.contains(&format!("`{bad}` is not an instant")),
                "{error}"
            );
        };
        for bad in ["now", "tomorrow", "2030-01-01T00:00:00+02:00"] {
            refused(
                format!(
                    "{:?}",
                    WorkItems::ready_items_at(&hosted, "q", bad).unwrap_err()
                ),
                bad,
            );
            refused(
                format!(
                    "{:?}",
                    WorkItems::next_readiness_change_after(&hosted, &["q".to_owned()], bad)
                        .unwrap_err()
                ),
                bad,
            );
            refused(
                format!(
                    "{:?}",
                    WorkItems::claim_item_at(&mut hosted, &id, "a", None, bad).unwrap_err()
                ),
                bad,
            );
        }
    }

    #[test]
    fn a_closed_issue_is_not_claimable_on_the_hosted_store() {
        let mut hosted = store();
        let id = WorkItems::file_item(&mut hosted, "q", "done", "", &[], &json!({}), None, None)
            .unwrap()
            .id;
        WorkItems::finish_item(&mut hosted, &id, None, None).unwrap();
        assert_eq!(
            WorkItems::claim_item_at(&mut hosted, &id, "a", None, AT).unwrap(),
            ClaimOutcome::NotOpen {
                status: "closed".to_owned()
            }
        );
    }
}
