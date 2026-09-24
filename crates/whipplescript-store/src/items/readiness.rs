//! The one definition of readiness (DR-0126), shared by every host.
//!
//! Readiness used to be decided in three places that disagreed: the store's
//! ready query excluded blocked and conflicted issues, the workflow projection
//! admitted any open unclaimed issue, and a claim checked only that nobody held
//! the issue. This module is now the only place it is decided. Each backend
//! implements [`ReadinessSource`] over its own SQL; [`unready_reasons`] reads
//! through it and answers, so the native store and the Durable Object store
//! cannot drift apart except in how they fetch a fact.
//!
//! Nothing here reads a clock. Every question is asked at an instant the caller
//! supplies — the worker pass's injected `now`, or the CLI's wall clock at its
//! own boundary — and that instant is part of the answer.
//!
//! The model is `models/maude/tracker-readiness.maude` for readiness and
//! `models/maude/tracker-ordering.maude` for the derived position.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::StoreResult;

/// The dependency kinds that are ordering statements rather than dependencies
/// (DR-0126 Decision 3): they rank, and never gate readiness.
pub const ORDERING_DEPENDENCY_KINDS: &[&str] = &["order", "soft"];

/// Does a `blocks` edge of this dependency kind gate readiness? Every kind but
/// the ordering ones does, including an edge with no kind, which is the
/// historical hard dependency, and `discovered`, which records how a real
/// dependency was found rather than how strong it is.
#[must_use]
pub fn dependency_gates(dep_kind: Option<&str>) -> bool {
    !dep_kind.is_some_and(|kind| ORDERING_DEPENDENCY_KINDS.contains(&kind))
}

/// An instant in the store's comparable shape, `YYYY-MM-DD HH:MM:SS` (UTC) —
/// the shape SQLite's `datetime('now')` produces and every stored deadline
/// already uses, so a lexical comparison is a temporal one.
///
/// Accepts that shape, and ISO-8601 with a `T` separator, an optional
/// fractional second, and an optional `Z` or `+00:00` — the shape the kernel's
/// injected clock uses. A date alone is midnight. Anything else, including a
/// non-UTC offset, is refused rather than guessed at.
#[must_use]
pub fn canonical_instant(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let (date, time) = match raw.split_once(['T', ' ']) {
        Some((date, time)) => (date, Some(time)),
        None => (raw, None),
    };
    let date_ok = date.len() == 10
        && date.as_bytes()[4] == b'-'
        && date.as_bytes()[7] == b'-'
        && date
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit());
    if !date_ok {
        return None;
    }
    let Some(time) = time else {
        return Some(format!("{date} 00:00:00"));
    };
    let time = time
        .strip_suffix('Z')
        .or_else(|| time.strip_suffix("+00:00"))
        .unwrap_or(time);
    let clock = time.split('.').next()?;
    let clock_ok = clock.len() == 8
        && clock.as_bytes()[2] == b':'
        && clock.as_bytes()[5] == b':'
        && clock
            .bytes()
            .enumerate()
            .all(|(index, byte)| index == 2 || index == 5 || byte.is_ascii_digit());
    if !clock_ok {
        return None;
    }
    if let Some(fraction) = time.split_once('.').map(|(_, fraction)| fraction) {
        if fraction.is_empty() || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
    }
    Some(format!("{date} {clock}"))
}

/// A wait condition (DR-0126 Decision 2): data on an issue that readiness
/// reads. It is never a status, so it is lifted by nothing but the facts it
/// reads coming to hold.
///
/// Every condition reads only what the issue's own queue can already see, the
/// clock, or the workspace's norm ledger. A wait on an issue in another queue
/// is a gating dependency (`dep add`), not a wait condition, so a wait cannot
/// carry another queue's state into this queue's readiness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WaitCondition {
    /// The evaluation instant has reached `instant`.
    At { instant: String },
    /// Issue `issue` (content id) is no longer open work: closed, canceled or
    /// archived. The condition a gating dependency is.
    Settled { issue: String },
    /// An admitted norm event has brought record `record` (content id) to
    /// `status`. Monotone: a later transition away does not unmake it.
    Reached { record: String, status: String },
    /// At least `at_least` issues in this issue's queue carry `label`, not
    /// counting withdrawn (canceled) ones — what "demand-gated" means.
    Count { label: String, at_least: i64 },
}

impl WaitCondition {
    /// A one-line rendering for listings and explanations. `alias` maps an
    /// issue's content id to its local display name.
    #[must_use]
    pub fn describe(&self, alias: &dyn Fn(&str) -> String) -> String {
        match self {
            Self::At { instant } => format!("until {instant}"),
            Self::Settled { issue } => format!("until {} is settled", alias(issue)),
            Self::Reached { record, status } => format!("until {record} reaches {status}"),
            Self::Count { label, at_least } => {
                format!("until {at_least} issue(s) carry label `{label}`")
            }
        }
    }
}

/// One wait on an issue: its condition and the instant it is due for review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wait {
    /// The `wait.added` event's content id.
    pub id: String,
    /// The waiting issue's local alias.
    pub issue: String,
    pub condition: WaitCondition,
    /// Canonical instant ([`canonical_instant`]) past which an unmet wait puts
    /// its issue in its owner's review view.
    pub review_at: String,
    pub added_by: Option<String>,
    pub created_at: String,
}

/// What a wait condition observed when it was evaluated — the evidence the
/// explanation names, including absence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WaitVerdict {
    pub holds: bool,
    /// What was read: "instant 2026-09-24 10:00:00", "WS-3 is open",
    /// "0 of 2 matching issues", "no admitted event reached accepted".
    pub observed: String,
}

/// One reason an issue is not ready. An empty list is readiness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum Unready {
    NotFound,
    NotOpen {
        status: String,
    },
    Claimed {
        holder: String,
        expires_at: Option<String>,
    },
    BlockedBy {
        issue: String,
        dep_kind: Option<String>,
    },
    Conflicted {
        fields: Vec<String>,
    },
    Waiting {
        wait: String,
        condition: String,
        review_at: String,
        due_for_review: bool,
        observed: String,
    },
}

impl Unready {
    /// A one-line reason for a CLI refusal or a failed claim effect.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::NotFound => "not found".to_owned(),
            Self::NotOpen { status } => format!("status is {status}"),
            Self::Claimed { holder, expires_at } => match expires_at {
                Some(at) => format!("claimed by {holder} until {at}"),
                None => format!("claimed by {holder}"),
            },
            Self::BlockedBy { issue, dep_kind } => match dep_kind {
                Some(kind) => format!("waits on {issue} ({kind} dependency), still open"),
                None => format!("waits on {issue}, still open"),
            },
            Self::Conflicted { fields } => {
                format!("fields in conflict: {}", fields.join(", "))
            }
            Self::Waiting {
                condition,
                observed,
                due_for_review,
                review_at,
                ..
            } => {
                let review = if *due_for_review {
                    format!("; review was due {review_at}")
                } else {
                    String::new()
                };
                format!("deferred {condition}: {observed}{review}")
            }
        }
    }
}

/// A `blocks` edge into an issue, as readiness sees it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Blocker {
    /// The blocking issue's local alias.
    pub issue: String,
    pub dep_kind: Option<String>,
    /// The blocking issue's durable status.
    pub status: String,
}

/// The facts readiness reads, fetched by a backend. Every lease question is
/// asked at the caller's instant `at`; nothing here reads a clock.
pub trait ReadinessSource {
    /// Durable status (no lease overlay), or `None` if the issue is absent.
    fn durable_status(&self, issue: &str) -> StoreResult<Option<String>>;
    /// The issue's queue.
    fn queue_of(&self, issue: &str) -> StoreResult<Option<String>>;
    /// The lease active at `at`, as `(holder, expires_at)`.
    fn active_lease_at(
        &self,
        issue: &str,
        at: &str,
    ) -> StoreResult<Option<(String, Option<String>)>>;
    /// Every `blocks` edge into `issue`, of every dependency kind.
    fn blockers(&self, issue: &str) -> StoreResult<Vec<Blocker>>;
    /// The fields in merge conflict, empty when there is none.
    fn conflicted_fields(&self, issue: &str) -> StoreResult<Vec<String>>;
    /// The issue's live waits.
    fn waits(&self, issue: &str) -> StoreResult<Vec<Wait>>;
    /// Durable status of the issue with this content id, if held here.
    fn status_by_content_id(&self, content_id: &str) -> StoreResult<Option<String>>;
    /// The local alias for a content id, for display.
    fn alias_of(&self, content_id: &str) -> StoreResult<Option<String>>;
    /// How many issues in `queue` carry `label` and are not canceled.
    fn label_count(&self, queue: &str, label: &str) -> StoreResult<i64>;
    /// Has an admitted norm event brought `record` to `status`?
    fn norm_reached(&self, record: &str, status: &str) -> StoreResult<bool>;
    /// Is `record` a norm record this workspace's ledger admitted?
    fn norm_record_known(&self, record: &str) -> StoreResult<bool>;
}

/// How many of these issues' label lists (each a JSON array, as the store keeps
/// it) contain `label`. Shared so both hosts count the same way.
pub fn count_label<'a>(labels_json: impl Iterator<Item = &'a str>, label: &str) -> i64 {
    labels_json
        .filter(|json| {
            serde_json::from_str::<Vec<String>>(json)
                .is_ok_and(|labels| labels.iter().any(|candidate| candidate == label))
        })
        .count() as i64
}

/// Does this stored norm event (the signed statement JSON the ledger keeps)
/// transition or retire `record` to `status`? The event was verified when the
/// ledger admitted it, so reading it is reading the ledger's own record.
#[must_use]
pub fn norm_event_reaches(payload_json: &str, record: &str, status: &str) -> bool {
    let Ok(payload) = serde_json::from_str::<serde_json::Value>(payload_json) else {
        return false;
    };
    let action = &payload["statement"]["action"];
    matches!(action["act"].as_str(), Some("transition" | "retire"))
        && action["record"].as_str() == Some(record)
        && action["status"].as_str() == Some(status)
}

/// Refuse a wait that could never mean what it says (DR-0126 Decision 2):
/// an instant that is not one, a review date that is not one, a settled
/// target that is this issue, is not held here, or sits in another queue, a
/// norm record the ledger never admitted, or a count that asks for nothing.
pub fn validate_wait(
    source: &dyn ReadinessSource,
    issue: &str,
    queue: &str,
    condition: &WaitCondition,
    review_at: &str,
) -> StoreResult<()> {
    let refuse = |message: String| Err(crate::StoreError::Conflict(message));
    if canonical_instant(review_at).as_deref() != Some(review_at) {
        return refuse(format!("review date `{review_at}` is not an instant"));
    }
    match condition {
        WaitCondition::At { instant } => {
            if canonical_instant(instant).as_deref() != Some(instant.as_str()) {
                return refuse(format!("`{instant}` is not an instant"));
            }
        }
        WaitCondition::Settled { issue: target } => {
            let Some(alias) = source.alias_of(target)? else {
                return refuse(format!("{target} is not an issue held here"));
            };
            if alias == issue {
                return refuse(format!("{issue} cannot wait on itself"));
            }
            let target_queue = source.queue_of(&alias)?.unwrap_or_default();
            if target_queue != queue {
                return refuse(format!(
                    "{alias} is in queue `{target_queue}`, not `{queue}`: a wait reads only its own \
                     queue, so wait on another queue's work with a dependency (`dep add`)"
                ));
            }
        }
        WaitCondition::Reached { record, status } => {
            if status.trim().is_empty() {
                return refuse("a status to reach is required".to_owned());
            }
            if !source.norm_record_known(record)? {
                return refuse(format!(
                    "{record} is not a record in this workspace's norm ledger"
                ));
            }
        }
        WaitCondition::Count { label, at_least } => {
            if label.trim().is_empty() {
                return refuse("a label to count is required".to_owned());
            }
            if *at_least < 1 {
                return refuse(format!("a count must be at least 1, not {at_least}"));
            }
        }
    }
    Ok(())
}

/// Fold an issue's `wait.added` / `wait.removed` events, in log order, into the
/// waits still live. Both hosts fold through this, so a wait means the same on each.
pub fn live_waits(
    issue: &str,
    events: impl Iterator<Item = (String, String, String, Option<String>, String)>,
) -> Vec<Wait> {
    let mut live: BTreeMap<String, Wait> = BTreeMap::new();
    let mut order = Vec::new();
    for (event_id, kind, payload, actor, created_at) in events {
        let payload: serde_json::Value =
            serde_json::from_str(&payload).unwrap_or(serde_json::Value::Null);
        match kind.as_str() {
            "wait.added" => {
                let Ok(condition) =
                    serde_json::from_value::<WaitCondition>(payload["condition"].clone())
                else {
                    continue;
                };
                let Some(review_at) = payload["review_at"].as_str() else {
                    continue;
                };
                order.push(event_id.clone());
                live.insert(
                    event_id.clone(),
                    Wait {
                        id: event_id,
                        issue: issue.to_owned(),
                        condition,
                        review_at: review_at.to_owned(),
                        added_by: actor,
                        created_at,
                    },
                );
            }
            "wait.removed" => {
                if let Some(target) = payload["wait"].as_str() {
                    live.remove(target);
                }
            }
            _ => {}
        }
    }
    order
        .into_iter()
        .filter_map(|id| live.remove(&id))
        .collect()
}

/// Evaluate one wait condition at instant `at` for an issue in `queue`.
pub fn evaluate_wait(
    source: &dyn ReadinessSource,
    queue: &str,
    condition: &WaitCondition,
    at: &str,
) -> StoreResult<WaitVerdict> {
    Ok(match condition {
        WaitCondition::At { instant } => WaitVerdict {
            holds: at >= instant.as_str(),
            observed: format!("evaluated at {at}"),
        },
        WaitCondition::Settled { issue } => {
            let name = source.alias_of(issue)?.unwrap_or_else(|| issue.clone());
            match source.status_by_content_id(issue)? {
                Some(status) => WaitVerdict {
                    holds: status != "open",
                    observed: format!("{name} is {status}"),
                },
                None => WaitVerdict {
                    holds: false,
                    observed: format!("{name} is not held here"),
                },
            }
        }
        WaitCondition::Reached { record, status } => {
            let holds = source.norm_reached(record, status)?;
            WaitVerdict {
                holds,
                observed: if holds {
                    format!("an admitted event reached {status}")
                } else {
                    format!("no admitted event has reached {status}")
                },
            }
        }
        WaitCondition::Count { label, at_least } => {
            let count = source.label_count(queue, label)?;
            WaitVerdict {
                holds: count >= *at_least,
                observed: format!("{count} of {at_least} matching issue(s)"),
            }
        }
    })
}

/// Every reason `issue` is not ready at instant `at`; empty means ready. This
/// is the one definition of readiness: `ready`, the ready projection, the
/// claim guard and `why` all ask it.
pub fn unready_reasons(
    source: &dyn ReadinessSource,
    issue: &str,
    at: &str,
) -> StoreResult<Vec<Unready>> {
    let Some(status) = source.durable_status(issue)? else {
        return Ok(vec![Unready::NotFound]);
    };
    let mut reasons = Vec::new();
    if status != "open" {
        reasons.push(Unready::NotOpen { status });
    }
    if let Some((holder, expires_at)) = source.active_lease_at(issue, at)? {
        reasons.push(Unready::Claimed { holder, expires_at });
    }
    for blocker in source.blockers(issue)? {
        if dependency_gates(blocker.dep_kind.as_deref()) && blocker.status == "open" {
            reasons.push(Unready::BlockedBy {
                issue: blocker.issue,
                dep_kind: blocker.dep_kind,
            });
        }
    }
    let fields = source.conflicted_fields(issue)?;
    if !fields.is_empty() {
        reasons.push(Unready::Conflicted { fields });
    }
    let queue = source.queue_of(issue)?.unwrap_or_default();
    for wait in source.waits(issue)? {
        let verdict = evaluate_wait(source, &queue, &wait.condition, at)?;
        if !verdict.holds {
            let alias = |content_id: &str| {
                source
                    .alias_of(content_id)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| content_id.to_owned())
            };
            reasons.push(Unready::Waiting {
                wait: wait.id,
                condition: wait.condition.describe(&alias),
                due_for_review: wait.review_at.as_str() <= at,
                review_at: wait.review_at,
                observed: verdict.observed,
            });
        }
    }
    Ok(reasons)
}

/// Is `issue` due for review at `at`: some wait on it unmet and past its
/// review instant? A wait that holds is never due, however old.
pub fn review_due(source: &dyn ReadinessSource, issue: &str, at: &str) -> StoreResult<bool> {
    if source.durable_status(issue)?.as_deref() != Some("open") {
        return Ok(false);
    }
    let queue = source.queue_of(issue)?.unwrap_or_default();
    for wait in source.waits(issue)? {
        if wait.review_at.as_str() <= at
            && !evaluate_wait(source, &queue, &wait.condition, at)?.holds
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The earliest instant strictly after `at` at which `issue`'s readiness can
/// change by the passage of time alone: a claim expiring, an `at` condition
/// coming due, a review date passing. `None` when nothing is time-bound.
pub fn next_time_change(
    source: &dyn ReadinessSource,
    issue: &str,
    at: &str,
) -> StoreResult<Option<String>> {
    if source.durable_status(issue)?.as_deref() != Some("open") {
        return Ok(None);
    }
    let mut instants = Vec::new();
    if let Some((_, Some(expires_at))) = source.active_lease_at(issue, at)? {
        instants.push(expires_at);
    }
    for wait in source.waits(issue)? {
        if let WaitCondition::At { instant } = &wait.condition {
            instants.push(instant.clone());
        }
        instants.push(wait.review_at);
    }
    Ok(instants
        .into_iter()
        .filter(|instant| instant.as_str() > at)
        .min())
}

/// The inputs to the derived position (DR-0126 Decision 4), fetched by a
/// backend. Everything is keyed by local alias.
#[derive(Clone, Debug, Default)]
pub struct OrderingGraph {
    /// Every issue, in filing order (the tie-break).
    pub issues: Vec<String>,
    /// `child -> parents` through `parent-of` edges.
    pub parents: BTreeMap<String, BTreeSet<String>>,
    /// `parent -> owner`: its assignee.
    pub owners: BTreeMap<String, String>,
    /// Ordering statements: `(before, after, writers)`, from `blocks` edges of
    /// an ordering dependency kind (`blocks(before, after, order)` reads
    /// "before first").
    pub statements: Vec<(String, String, BTreeSet<String>)>,
    /// Gating dependencies: `(dependency, dependent)`.
    pub gates: Vec<(String, String)>,
}

/// The derived position of every issue: a path of sibling ranks from the root,
/// compared lexicographically — shorter prefix first, so a parent sorts before
/// its children — then lowered by inheritance. Also the issues whose ordering
/// is contradicted.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Positions {
    pub keys: BTreeMap<String, Vec<u64>>,
    pub conflicted: BTreeSet<String>,
}

impl Positions {
    /// Compare two issues by effective position, then by filing order.
    #[must_use]
    pub fn cmp(&self, a: &str, b: &str, filing: &BTreeMap<String, usize>) -> std::cmp::Ordering {
        let empty = Vec::new();
        let ka = self.keys.get(a).unwrap_or(&empty);
        let kb = self.keys.get(b).unwrap_or(&empty);
        ka.cmp(kb).then_with(|| {
            filing
                .get(a)
                .unwrap_or(&usize::MAX)
                .cmp(filing.get(b).unwrap_or(&usize::MAX))
        })
    }
}

/// Derive every issue's position (`tracker-ordering.maude`).
///
/// 1. A statement counts only between siblings — the same set of parents, or
///    both roots — and only when its writers include the parent's owner, or
///    the parent has none.
/// 2. Within each sibling group the counted statements form a graph; each
///    strongly connected component of more than one issue is a contradiction,
///    marked on every member, and its members share one rank. An issue's rank
///    is the longest chain of statements ending at it.
/// 3. An issue's key is its parent's key followed by its rank; with several
///    parents, the least. Roots start from their own rank.
/// 4. Inheritance: an issue's key is lowered to the least key of anything that
///    depends on it through a gating edge, transitively. It overrides a stated
///    order and is never a conflict.
#[must_use]
pub fn derive_positions(graph: &OrderingGraph) -> Positions {
    let root = String::new();
    let group_of = |issue: &str| -> Vec<String> {
        graph
            .parents
            .get(issue)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_else(|| vec![root.clone()])
    };
    // 1. Counted statements, grouped by the parent they rank under.
    let mut edges: BTreeMap<String, BTreeSet<(String, String)>> = BTreeMap::new();
    for (before, after, writers) in &graph.statements {
        if before == after {
            continue;
        }
        let (gb, ga) = (group_of(before), group_of(after));
        for parent in gb.iter().filter(|parent| ga.contains(parent)) {
            let owner = graph.owners.get(parent);
            if owner.is_none_or(|owner| writers.contains(owner)) {
                edges
                    .entry(parent.clone())
                    .or_default()
                    .insert((before.clone(), after.clone()));
            }
        }
    }
    // Members of each group.
    let mut members: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for issue in &graph.issues {
        for parent in group_of(issue) {
            members.entry(parent).or_default().insert(issue.clone());
        }
    }
    // 2. Rank within each group.
    let mut rank: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut conflicted = BTreeSet::new();
    for (parent, group) in &members {
        let group_edges = edges.get(parent).cloned().unwrap_or_default();
        let (component_of, components) = strongly_connected(group, &group_edges);
        for component in &components {
            if component.len() > 1 {
                conflicted.extend(component.iter().cloned());
            }
        }
        // Longest path over the condensation, by repeated relaxation (groups
        // are small and the condensation is acyclic, so this terminates in at
        // most |components| rounds).
        let mut level = vec![0_u64; components.len()];
        for _ in 0..components.len() {
            let mut changed = false;
            for (before, after) in &group_edges {
                let (cb, ca) = (component_of[before], component_of[after]);
                if cb != ca && level[ca] < level[cb] + 1 {
                    level[ca] = level[cb] + 1;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        for issue in group {
            rank.insert((parent.clone(), issue.clone()), level[component_of[issue]]);
        }
    }
    // 3. Hierarchical keys, memoized; a parent cycle falls back to the rank.
    let mut keys: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for issue in &graph.issues {
        let mut visiting = BTreeSet::new();
        hierarchical_key(issue, graph, &rank, &root, &mut keys, &mut visiting);
    }
    // 4. Inheritance, to a fixed point: keys only decrease.
    loop {
        let mut changed = false;
        for (dependency, dependent) in &graph.gates {
            let Some(dependent_key) = keys.get(dependent).cloned() else {
                continue;
            };
            let entry = keys.entry(dependency.clone()).or_default();
            if dependent_key < *entry {
                *entry = dependent_key;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    Positions { keys, conflicted }
}

fn hierarchical_key(
    issue: &str,
    graph: &OrderingGraph,
    rank: &BTreeMap<(String, String), u64>,
    root: &str,
    keys: &mut BTreeMap<String, Vec<u64>>,
    visiting: &mut BTreeSet<String>,
) -> Vec<u64> {
    if let Some(key) = keys.get(issue) {
        return key.clone();
    }
    let own = |parent: &str| {
        rank.get(&(parent.to_owned(), issue.to_owned()))
            .copied()
            .unwrap_or(0)
    };
    let key = match graph.parents.get(issue) {
        Some(parents) if !parents.is_empty() && visiting.insert(issue.to_owned()) => {
            let key = parents
                .iter()
                .map(|parent| {
                    let mut key = hierarchical_key(parent, graph, rank, root, keys, visiting);
                    key.push(own(parent));
                    key
                })
                .min()
                .unwrap_or_default();
            visiting.remove(issue);
            key
        }
        Some(parents) if !parents.is_empty() => {
            // A parent cycle: rank against the first parent without recursing.
            vec![own(parents.iter().next().map_or(root, String::as_str))]
        }
        _ => vec![own(root)],
    };
    keys.insert(issue.to_owned(), key.clone());
    key
}

/// Tarjan's strongly connected components over `nodes` and `edges`. Returns
/// each node's component index and the components.
fn strongly_connected(
    nodes: &BTreeSet<String>,
    edges: &BTreeSet<(String, String)>,
) -> (BTreeMap<String, usize>, Vec<BTreeSet<String>>) {
    let mut adjacency: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (from, to) in edges {
        if nodes.contains(from) && nodes.contains(to) {
            adjacency
                .entry(from.as_str())
                .or_default()
                .push(to.as_str());
        }
    }
    struct State<'a> {
        index: usize,
        indices: BTreeMap<&'a str, usize>,
        low: BTreeMap<&'a str, usize>,
        stack: Vec<&'a str>,
        on_stack: BTreeSet<&'a str>,
        components: Vec<BTreeSet<String>>,
    }
    fn visit<'a>(
        node: &'a str,
        adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
        state: &mut State<'a>,
    ) {
        state.indices.insert(node, state.index);
        state.low.insert(node, state.index);
        state.index += 1;
        state.stack.push(node);
        state.on_stack.insert(node);
        for &next in adjacency.get(node).map(Vec::as_slice).unwrap_or(&[]) {
            if !state.indices.contains_key(next) {
                visit(next, adjacency, state);
                let low = state.low[node].min(state.low[next]);
                state.low.insert(node, low);
            } else if state.on_stack.contains(next) {
                let low = state.low[node].min(state.indices[next]);
                state.low.insert(node, low);
            }
        }
        if state.low[node] == state.indices[node] {
            let mut component = BTreeSet::new();
            while let Some(member) = state.stack.pop() {
                state.on_stack.remove(member);
                component.insert(member.to_owned());
                if member == node {
                    break;
                }
            }
            state.components.push(component);
        }
    }
    let mut state = State {
        index: 0,
        indices: BTreeMap::new(),
        low: BTreeMap::new(),
        stack: Vec::new(),
        on_stack: BTreeSet::new(),
        components: Vec::new(),
    };
    for node in nodes {
        if !state.indices.contains_key(node.as_str()) {
            visit(node.as_str(), &adjacency, &mut state);
        }
    }
    let mut component_of = BTreeMap::new();
    for (index, component) in state.components.iter().enumerate() {
        for member in component {
            component_of.insert(member.clone(), index);
        }
    }
    (component_of, state.components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instants_canonicalize_from_both_clock_shapes() {
        assert_eq!(
            canonical_instant("2026-09-24T10:11:12Z").as_deref(),
            Some("2026-09-24 10:11:12")
        );
        assert_eq!(
            canonical_instant("2026-09-24 10:11:12").as_deref(),
            Some("2026-09-24 10:11:12")
        );
        assert_eq!(
            canonical_instant("2026-09-24T10:11:12.345+00:00").as_deref(),
            Some("2026-09-24 10:11:12")
        );
        assert_eq!(
            canonical_instant("2026-10-01").as_deref(),
            Some("2026-10-01 00:00:00")
        );
        assert_eq!(canonical_instant("2026-09-24T10:11:12+02:00"), None);
        assert_eq!(canonical_instant("tomorrow"), None);
        assert_eq!(canonical_instant("2026-9-24"), None);
    }

    #[test]
    fn only_ordering_kinds_stop_gating() {
        assert!(dependency_gates(None));
        for kind in ["hard", "resource", "review", "contract", "discovered"] {
            assert!(dependency_gates(Some(kind)), "{kind}");
        }
        assert!(!dependency_gates(Some("order")));
        assert!(!dependency_gates(Some("soft")));
    }

    fn graph() -> OrderingGraph {
        OrderingGraph {
            issues: ["P", "Q", "a", "b", "c", "x", "y"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            ..OrderingGraph::default()
        }
    }

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    fn with_parent(graph: &mut OrderingGraph, parent: &str, children: &[&str]) {
        for child in children {
            graph
                .parents
                .entry((*child).to_owned())
                .or_default()
                .insert(parent.to_owned());
        }
    }

    fn before(positions: &Positions, a: &str, b: &str) -> bool {
        positions.keys[a] < positions.keys[b]
    }

    #[test]
    fn the_owner_ranks_siblings_and_a_proposal_ranks_nothing() {
        let mut g = graph();
        with_parent(&mut g, "P", &["a", "b"]);
        g.owners.insert("P".into(), "owner".into());
        g.statements
            .push(("b".into(), "a".into(), set(&["someone"])));
        let proposal = derive_positions(&g);
        assert_eq!(proposal.keys["a"], proposal.keys["b"]);
        g.statements.push(("b".into(), "a".into(), set(&["owner"])));
        let ranked = derive_positions(&g);
        assert!(before(&ranked, "b", "a"));
    }

    #[test]
    fn a_statement_across_parents_ranks_nothing_but_parents_order_children() {
        let mut g = graph();
        with_parent(&mut g, "P", &["a"]);
        with_parent(&mut g, "Q", &["b"]);
        g.statements.push(("b".into(), "a".into(), set(&["w"])));
        let across = derive_positions(&g);
        assert_eq!(
            across.keys["a"], across.keys["b"],
            "not siblings: no effect"
        );
        g.statements.clear();
        g.statements.push(("Q".into(), "P".into(), set(&["w"])));
        let parents = derive_positions(&g);
        assert!(before(&parents, "b", "a"), "children follow their parents");
        assert!(
            before(&parents, "Q", "b"),
            "a parent sorts before its children"
        );
    }

    #[test]
    fn a_contradiction_is_marked_on_both_and_neither_wins() {
        let mut g = graph();
        with_parent(&mut g, "P", &["a", "b"]);
        g.statements.push(("a".into(), "b".into(), set(&["w"])));
        g.statements.push(("b".into(), "a".into(), set(&["w"])));
        let positions = derive_positions(&g);
        assert_eq!(positions.conflicted, set(&["a", "b"]));
        assert_eq!(positions.keys["a"], positions.keys["b"]);
    }

    #[test]
    fn urgency_flows_backward_along_dependencies_and_never_forward() {
        let mut g = graph();
        with_parent(&mut g, "P", &["a", "b"]);
        with_parent(&mut g, "Q", &["x", "y"]);
        g.statements.push(("P".into(), "Q".into(), set(&["w"])));
        g.statements.push(("a".into(), "b".into(), set(&["w"])));
        // x (under the later parent) is a dependency of a: it inherits a's rank.
        g.gates.push(("x".into(), "a".into()));
        let without = derive_positions(&g);
        // b is a dependency of y: y must not inherit b's rank.
        g.gates.push(("b".into(), "y".into()));
        let positions = derive_positions(&g);
        assert!(before(&positions, "x", "b"), "x is urgent before b");
        assert_eq!(
            positions.keys["y"], without.keys["y"],
            "y gains nothing from b"
        );
        assert!(before(&positions, "b", "y"));
        assert!(
            positions.conflicted.is_empty(),
            "inheritance is not a conflict"
        );
    }
}
