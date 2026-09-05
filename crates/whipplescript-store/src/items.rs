//! The builtin work-item tracker: the reference implementation of the
//! work-queue interface (`spec/work-queues.md`), rebuilt as an event-sourced
//! provider (ADR-0002 v1, A+blockers scope).
//!
//! State model (the ADR cure for the old row-store): the source of truth is an
//! APPEND-ONLY transaction log (`tracker_events`) — every mutation is an
//! immutable event, never an in-place row update. Current issue state
//! (`tracker_issues`), blocker edges (`tracker_relations`), and runtime claim
//! leases (`tracker_leases`) are DISPOSABLE projections folded from that log; a
//! rebuild-from-events reproduces them exactly (`rebuild_projection`).
//!
//! Claims are LOCAL runtime leases, split from durable issue status (the
//! "combined claim/status write" cure): a plain `claim` appends only a
//! `claim.acquired` event and changes readiness through a lease OVERLAY, not a
//! durable `in_progress` write. Durable issue status is only `open` / `closed`
//! / `canceled`; `in_progress` is purely the active-lease overlay, and `ready`
//! is a derived predicate (open, unblocked, unleased).
//!
//! The three invariant models under `models/maude/` are the spec this storage
//! realizes: exclusivity + expiry + holder-only renew + terminal-release
//! (`tracker-lease`), the readiness fold (`tracker-readiness`), and projection
//! determinism (`tracker-projection`).
//!
//! Items live in a workspace-scoped SQLite file (default
//! `.whipplescript/items.sqlite`), deliberately separate from run stores:
//! run stores are disposable per experiment, the backlog is durable.

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension, Transaction};
#[cfg(feature = "native")]
use serde_json::json;
use serde_json::Value;

#[cfg(feature = "native")]
use crate::StoreError;
use crate::StoreResult;

/// The active-lease predicate, shared by every readiness/overlay query: a lease
/// is active while it has not been released and has not expired. A NULL
/// `expires_at` models a lease with no TTL (the old builtin "no TTL backstop"
/// behavior) — it never auto-expires. `?N` binds the clock (`datetime('now')`
/// or a captured now-timestamp).
#[cfg(feature = "native")]
const ACTIVE_LEASE: &str = "released_at IS NULL AND (expires_at IS NULL OR expires_at > ?)";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkItem {
    pub id: String,
    pub queue: String,
    pub title: String,
    pub body: String,
    pub status: String,
    pub labels: Vec<String>,
    /// How many times this item has been returned to ready (DR-0088).
    ///
    /// The tracker maintains it, which is the whole point: an author who wants
    /// a rework loop to stop cannot forget to advance a number the provider
    /// advances for them, and the compiler can read `issue.releases < 3` as a
    /// termination measure over a ring that carries no fact at all.
    ///
    /// Every path that stops an item being held counts, expiry included. A turn
    /// of the ring always goes through `release`, so extra counts can only make
    /// the loop stop sooner than the measure promises — never later.
    pub releases: i64,
    pub metadata: Value,
    pub claimed_by: Option<String>,
    /// Who the issue is *directed at*, if anyone (0.2.2).
    ///
    /// Distinct from `claimed_by`, and the distinction is the point: an
    /// assignment is a durable statement about who *should* act, which survives
    /// restarts and is visible before anyone responds; a claim is the transient
    /// CAS that decides who *is* acting. Unassigned means "whoever has access",
    /// which is a real and common answer — an issue anyone may claim.
    pub assigned_to: Option<String>,
    pub filed_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// The durable statuses this store can produce, asserted against the one set
/// the compiler refuses programs on behalf of.
///
/// The compiler declares `WorkItem.status` as a literal union of
/// `WORK_ITEM_STATUSES`, so a rule comparing against anything outside it does
/// not compile. If this store ever folded an issue into a status the union
/// omits, that item would be unmatchable by any rule — refused at the source
/// for a value the runtime had actually produced. The test below is what keeps
/// the two honest; the constant itself lives in `whipplescript-core` because
/// the parser cannot depend on this crate.
#[cfg(test)]
const STORE_PRODUCED_STATUSES: &[&str] = &[
    // `open` on file, `closed` on finish, `canceled` on cancel, `open` again on
    // reopen (items.rs fold), `archived` via `whip issue archive`.
    "open",
    "closed",
    "canceled",
    "archived",
    // Never written durably — the readiness overlay presents a leased `open`
    // item as this. A rule still matches on it, so the union must carry it.
    "in_progress",
];

/// The relation kinds the builtin provider supports (ADR-0002 "Relations And
/// Dependencies"). Only `blocks` gates readiness; the rest are graph metadata.
pub const RELATION_KINDS: &[&str] = &[
    "blocks",
    "parent-of",
    "related",
    "duplicates",
    "supersedes",
    "discovered-from",
];

/// The dependency-kind taxonomy a `blocks` relation may carry (small and
/// operational). Recorded metadata; every `blocks` edge gates readiness
/// regardless of `dep_kind` (providers may later refine).
pub const DEPENDENCY_KINDS: &[&str] = &[
    "hard",
    "soft",
    "order",
    "resource",
    "review",
    "contract",
    "discovered",
];

/// A directed relation edge between two issues (by alias). `dep_kind` is the
/// dependency flavor, only present on `blocks` edges.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Relation {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub dep_kind: Option<String>,
}

/// A comment on an issue (`comment.added`). `id` is the comment's content hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comment {
    pub id: String,
    pub author: Option<String>,
    pub body: String,
    pub created_at: String,
}

/// A piece of evidence attached to an issue (`evidence.added`) — a reference /
/// artifact / note supporting it. `id` is the evidence's content hash.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Evidence {
    pub id: String,
    pub kind: Option<String>,
    pub reference: Option<String>,
    pub note: Option<String>,
    pub added_by: Option<String>,
    pub created_at: String,
    /// The branch head cut when this evidence was attested (DR-0084):
    /// attribution anchor for witness scans. `None` = unkeyed evidence.
    pub at_cut: Option<String>,
    /// The world-denoting basis region, COPIED at attest time.
    pub basis: Option<String>,
    /// The resolved basis fingerprint (JSON map, `decl:`/`path:` keys →
    /// hashes) — the freshness evaluator's first argument.
    pub basis_fingerprint_json: Option<String>,
}

/// One anchor (DR-0084 Decision 3): a binding from a ledger object (issue or
/// assertion, by alias) to a world-denoting region. `role` is `subject`
/// (what the object is about — drives staleness) or `intent` (what it plans
/// to touch). Keyed by its own event hash, so a merge folds each exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Anchor {
    pub id: String,
    pub subject: String,
    pub region: String,
    pub role: String,
    pub added_by: Option<String>,
    pub created_at: String,
}

/// One knowledge-plane assertion (DR-0084 Decision 2): a durable statement
/// about the world, the ledger's second vocabulary beside `issue`. No
/// readiness, no claim, no finish — an assertion is knowledge, not work. Its
/// durable identity is the content hash of its `assertion.created` event;
/// `id` is the clone-local `AS-N` alias bridged through `tracker_aliases`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assertion {
    pub id: String,
    pub content_id: String,
    pub title: String,
    pub body: String,
    /// `active` | `retired`.
    pub status: String,
    pub created_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// One field whose value is disputed: its `bef`-maximal setters in the event
/// DAG disagree (ADR-0002 phase B1 slice ii; `tracker-merge.maude` `conflict`).
/// `values` are the distinct maximal-setter values, sorted for stable output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldConflict {
    pub field: String,
    pub values: Vec<String>,
}

/// The DAG view of one issue: its frontier (`heads`), a content-derived
/// `state_token` over that frontier (the optimistic-concurrency token, slice v),
/// and any per-field conflicts. An issue is `conflicted` iff `field_conflicts`
/// is non-empty — and a conflicted issue is not ready. Heads and token are
/// content-hashes (unit 1), so they are already merge-stable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueConflicts {
    pub heads: Vec<String>,
    pub state_token: String,
    pub field_conflicts: Vec<FieldConflict>,
}

#[cfg(feature = "native")]
/// This store's schema generation. Bumped when its `CREATE TABLE` set changes
/// in a way an older build cannot read.
const SATELLITE_SCHEMA_VERSION: i64 = 1;

impl IssueConflicts {
    #[must_use]
    pub fn conflicted(&self) -> bool {
        !self.field_conflicts.is_empty()
    }
}

/// The outcome of an optimistic field set (ADR-0002 phase B1 slice v): a set
/// guarded by the `state_token` the caller last observed. `StateChanged` means
/// the frontier moved under the caller — the set was NOT applied, and `actual`
/// is the current token to retry against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SetFieldOutcome {
    Applied { state_token: String },
    NotFound,
    StateChanged { actual: String },
}

/// One tracker event in transport form (ADR-0002 phase B1 slice iii): the
/// content-addressed unit that crosses between clones. `issue_id` is the opaque
/// content_id (never a WS-N alias), so a set-union of two clones' events is
/// well-defined and deduped by `event_id`.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TrackerEvent {
    pub event_id: String,
    #[serde(default)]
    pub parents: Vec<String>,
    pub issue_id: Option<String>,
    pub kind: String,
    pub payload_json: String,
    pub actor: Option<String>,
    pub created_at: String,
}

/// The result of importing another clone's events (ADR-0002 phase B1 slice iii).
/// `duplicate_submissions` names each newly-seen issue (by local alias) that
/// describes the same work (queue + title) as a DISTINCT issue already present —
/// two independent submissions of one issue, surfaced as a WARNING for a human
/// to reconcile (via a `duplicates` relation), never silently collapsed. A
/// byte-identical event re-arriving is an idempotent re-transmit, not a
/// duplicate, and is counted in `skipped`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
    pub new_issues: usize,
    /// Newly-seen assertions re-aliased on this clone (DR-0084 Decision 2).
    pub new_assertions: usize,
    pub duplicate_submissions: Vec<String>,
    /// Events refused because their `event_id` did not equal the SHA-256 of
    /// their own content (tamper / corruption), or a created event whose id did
    /// not match its issue identity. The content-addressed integrity check that
    /// makes tamper-evidence and suppression-resistance real on the (untrusted)
    /// shared-folder transport.
    pub rejected: usize,
}

#[cfg(feature = "native")]
pub struct WorkItemStore {
    connection: Connection,
    /// The effect currently writing, set by the queue-effect dispatch around the
    /// whole of its work and cleared after (G3). Scoped rather than passed
    /// through every mutation because the alternative is a parameter on a
    /// dozen public methods with well over a hundred call sites, almost all of
    /// them tests that have no effect to name.
    event_effect_id: Option<String>,
}

#[cfg(feature = "native")]
impl WorkItemStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let connection = Connection::open(path)?;
        crate::establish_wal(&connection)?;
        Self::from_connection(connection)
    }

    /// In-memory work-item store, for tests that need a handle satisfying
    /// `WorkItems` without a file. No WAL, for the reason `CoordinationStore`
    /// gives.
    pub fn open_in_memory() -> StoreResult<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> StoreResult<Self> {
        connection.execute_batch(TRACKER_SCHEMA_SQL)?;
        // DR-0054 Phase B parity: this store had no schema stamp and no
        // downgrade guard, so an older binary read a newer file as whatever
        // it parsed. `SqliteStore` has refused that since Phase B.
        crate::stamp_satellite_schema(&connection, "work-item", SATELLITE_SCHEMA_VERSION)?;
        // Self-heal a pre-phase-B `tracker_events` (the ADR-0002 v1 linear log
        // had neither column): `CREATE TABLE IF NOT EXISTS` never alters an
        // existing table, so add the Merkle-DAG columns before the unique index
        // over `event_id` (which would otherwise fail on the old shape).
        tx_ensure_column(&connection, "tracker_events", "event_id", "TEXT")?;
        tx_ensure_column(
            &connection,
            "tracker_events",
            "parents_json",
            "TEXT NOT NULL DEFAULT '[]'",
        )?;
        // Self-heal a pre-0.2.2 `tracker_issues`, which had no assignment.
        tx_ensure_column(&connection, "tracker_issues", "assigned_to", "TEXT")?;
        // Existing stores start every item at zero rather than replaying
        // `claim.released` out of the event log. A count that begins now is
        // still monotone, which is all the measure needs; a replay would be
        // reconstructing history the projection never claimed to hold.
        tx_ensure_column(
            &connection,
            "tracker_issues",
            "releases",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        // Self-heal a tracker written before write-attribution (G3).
        tx_ensure_column(&connection, "tracker_events", "effect_id", "TEXT")?;
        // Self-heal a tracker written before the knowledge plane's validity
        // keys (DR-0084 Decision 3): keyed evidence carries its at-cut, its
        // basis region text, and the resolved basis fingerprint. Absent on
        // old rows = unkeyed evidence, which makes no freshness claim.
        tx_ensure_column(&connection, "tracker_evidence", "at_cut", "TEXT")?;
        tx_ensure_column(&connection, "tracker_evidence", "basis", "TEXT")?;
        tx_ensure_column(
            &connection,
            "tracker_evidence",
            "basis_fingerprint_json",
            "TEXT",
        )?;
        connection.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_tracker_events_id ON tracker_events(event_id);",
        )?;
        Ok(Self {
            connection,
            event_effect_id: None,
        })
    }

    /// Files an item, minting a sequential human-speakable id (`WS-1`,
    /// `WS-2`, ...). Sequential beats content hashes: "take WS-7" is
    /// speakable to an agent, and byte-identical items get distinct ids.
    /// Appends `issue.created` and folds it into the issue projection in one
    /// transaction.
    pub fn file_item(
        &mut self,
        queue: &str,
        title: &str,
        body: &str,
        labels: &[String],
        metadata: &Value,
        filed_by: Option<&str>,
    ) -> StoreResult<WorkItem> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let next: i64 = tx.query_row(
            "UPDATE tracker_counter SET next_id = next_id + 1 WHERE singleton = 1 RETURNING next_id - 1",
            [],
            |row| row.get(0),
        )?;
        let item_id = format!("WS-{next}");
        let labels_json = serde_json::to_string(labels)?;
        let metadata_json = metadata.to_string();
        let payload = json!({
            "queue": queue,
            "title": title,
            "body": body,
            "labels": labels,
            "metadata": metadata,
            "filed_by": filed_by,
        });
        let payload_json = payload.to_string();
        // The issue's opaque MERGE identity = the content-hash of its creation
        // event (issue_id excluded — it derives FROM this). WS-N is only a local
        // alias for it; the event log is keyed by content_id.
        let content_id =
            event_content_id("issue.created", None, &payload_json, filed_by, &[], &now);
        tx.execute(
            "INSERT INTO tracker_aliases (content_id, alias) VALUES (?1, ?2)",
            params![content_id, item_id],
        )?;
        tx_append_raw(
            &tx,
            Some(&content_id),
            Some(&content_id),
            "issue.created",
            &payload_json,
            filed_by,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT INTO tracker_issues \
             (issue_id, queue, title, body, status, labels_json, metadata_json, filed_by, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?8)",
            params![item_id, queue, title, body, labels_json, metadata_json, filed_by, now],
        )?;
        tx.commit()?;
        self.get_item(&item_id)?
            .ok_or_else(|| StoreError::Conflict("filed item missing".to_owned()))
    }

    pub fn get_item(&self, item_id: &str) -> StoreResult<Option<WorkItem>> {
        let base = self
            .connection
            .query_row(
                &format!("SELECT {ISSUE_COLS} FROM tracker_issues WHERE issue_id = ?1"),
                [item_id],
                row_to_item,
            )
            .optional()?;
        match base {
            None => Ok(None),
            Some(item) => {
                let holder = self.active_holder(item_id)?;
                Ok(Some(apply_overlay(item, holder)))
            }
        }
    }

    pub fn list_items(
        &self,
        queue: Option<&str>,
        status: Option<&str>,
    ) -> StoreResult<Vec<WorkItem>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ISSUE_COLS} FROM tracker_issues \
             WHERE (?1 IS NULL OR queue = ?1) ORDER BY created_at, issue_id"
        ))?;
        let bases = statement
            .query_map(params![queue], row_to_item)?
            .collect::<Result<Vec<_>, _>>()?;
        let holders = self.active_holders()?;
        let items = bases
            .into_iter()
            .map(|item| {
                let holder = holders.get(&item.id).cloned();
                apply_overlay(item, holder)
            })
            // The overlay can turn a durable-`open` issue into effective
            // `in_progress`, so the caller's status filter must run over the
            // OVERLAID status, not the durable column.
            .filter(|item| status.is_none_or(|want| item.status == want))
            .collect();
        Ok(items)
    }

    /// Readiness is the tracker's promise (`tracker-readiness.maude`): ready
    /// iff durable status is `open`, no ACTIVE blocker (`blocks(B, id)` with `B`
    /// still open), and no ACTIVE lease. Expired/released leases do not block.
    pub fn ready_items(&self, queue: &str) -> StoreResult<Vec<WorkItem>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ISSUE_COLS} FROM tracker_issues i \
             WHERE i.queue = ?1 AND i.status = 'open' \
             AND NOT EXISTS ( \
               SELECT 1 FROM tracker_leases l \
               WHERE l.issue_id = i.issue_id \
                 AND l.released_at IS NULL \
                 AND (l.expires_at IS NULL OR l.expires_at > datetime('now'))) \
             AND NOT EXISTS ( \
               SELECT 1 FROM tracker_relations r JOIN tracker_issues b ON b.issue_id = r.from_issue \
               WHERE r.to_issue = i.issue_id AND r.kind = 'blocks' AND b.status = 'open') \
             ORDER BY i.created_at, i.issue_id"
        ))?;
        let rows = statement
            .query_map([queue], row_to_item)?
            .collect::<Result<Vec<_>, _>>()?;
        // A conflicted issue is not ready (ADR-0002 phase B1 slice ii): its
        // field values are in dispute, so handing it to a worker would race a
        // resolution. The DAG conflict test is not expressible in the SQL
        // predicate above, so filter it here (the candidate set is small).
        let mut ready = Vec::with_capacity(rows.len());
        for item in rows {
            let conflicted = match content_id_of(&self.connection, &item.id)? {
                Some(content_id) => {
                    analyze_issue_dag(&load_issue_events(&self.connection, &content_id)?)
                        .conflicted()
                }
                None => false,
            };
            if !conflicted {
                ready.push(item);
            }
        }
        // Ready items have no active lease by construction, so the overlay is a
        // no-op here; return them as the projection sees them (durable `open`,
        // unclaimed).
        Ok(ready)
    }

    /// Atomic claim (`tracker-lease.maude` I1, exclusivity): grants a lease ONLY
    /// when the issue carries no active lease. The `Immediate` transaction takes
    /// the write lock at `BEGIN`, so the "is there an active lease?" check and
    /// the lease insert are serialized against every concurrent claim — exactly
    /// one wins, the rest see `AlreadyClaimed`. "Already claimed" is a normal,
    /// branchable outcome, not an error.
    /// `expires` is an ABSOLUTE deadline (`None` = no TTL, the historical
    /// backstop behavior — the lease never auto-expires and terminal
    /// auto-release is the only recovery). A finite `expires` records a
    /// claim-TTL lease that `ready`/`claim` lazily reclaim once past-due
    /// (`tracker-lease.maude`: expired leases do not block). The T3 claim-TTL
    /// half of the renew mechanism.
    pub fn claim_item(
        &mut self,
        item_id: &str,
        claimed_by: &str,
        expires: Option<&str>,
    ) -> StoreResult<ClaimOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM tracker_issues WHERE issue_id = ?1",
                [item_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            tx.commit()?;
            return Ok(ClaimOutcome::NotFound);
        }
        tx_expire_stale_leases(&tx, item_id, &now)?;
        if let Some(holder) = tx_active_holder(&tx, item_id, &now)? {
            tx.commit()?;
            return Ok(ClaimOutcome::AlreadyClaimed { holder });
        }
        // No active lease: grant. The lease's identity IS its `claim.acquired`
        // event (content hash) — like comments/evidence, so ids from different
        // clones can never collide on merge and rebuild re-derives the same id
        // from the log. (Alias-derived `L-{alias}-{n}` ids collided across
        // clones: both mint `L-WS-1-0`, and the import fold's INSERT OR IGNORE
        // silently destroyed one lease.) A plain claim writes NO durable
        // status — readiness changes through the lease overlay.
        let content_id = content_id_of(&tx, item_id)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {item_id}")))?;
        let payload = json!({"actor": claimed_by, "expires_at": expires});
        let lease_id = tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "claim.acquired",
            &payload.to_string(),
            Some(claimed_by),
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT INTO tracker_leases (lease_id, issue_id, actor, acquired_at, expires_at, released_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
            params![lease_id, item_id, claimed_by, now, expires],
        )?;
        tx.commit()?;
        Ok(ClaimOutcome::Claimed)
    }

    /// Extend/heartbeat a held lease (`tracker-lease.maude` I2, holder-only +
    /// monotonic). Only the actor that holds the active lease may renew; a
    /// finite `expires` may only move FORWARD (a non-monotonic request is
    /// rejected). `expires = None` re-affirms the lease without changing its
    /// deadline. The T3 sanctioned extension.
    pub fn renew_claim(
        &mut self,
        item_id: &str,
        actor: &str,
        expires: Option<&str>,
    ) -> StoreResult<RenewOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let lease: Option<(String, Option<String>)> = tx
            .query_row(
                &format!(
                    "SELECT lease_id, expires_at FROM tracker_leases \
                     WHERE issue_id = ?1 AND actor = ?2 AND {ACTIVE_LEASE}"
                ),
                params![item_id, actor, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((lease_id, current_expires)) = lease else {
            tx.commit()?;
            return Ok(RenewOutcome::NotHeld);
        };
        // Monotonicity: a finite deadline may not move backward. NULL (no TTL)
        // accepts a first finite deadline — the holder is voluntarily timing
        // its own lease, which the Maude model (Nat-only expiry) does not cover.
        if let (Some(want), Some(current)) = (expires, current_expires.as_deref()) {
            if want <= current {
                tx.commit()?;
                return Ok(RenewOutcome::NotMonotonic);
            }
        }
        let new_expires: Option<String> = match expires {
            Some(want) => Some(want.to_owned()),
            None => current_expires,
        };
        let payload = json!({"lease_id": lease_id, "actor": actor, "expires_at": new_expires});
        tx_append_event(
            &tx,
            Some(item_id),
            "claim.renewed",
            &payload,
            Some(actor),
            self.event_effect_id.as_deref(),
            &now,
        )?;
        if expires.is_some() {
            tx.execute(
                "UPDATE tracker_leases SET expires_at = ?2 WHERE lease_id = ?1",
                params![lease_id, new_expires],
            )?;
        }
        tx.commit()?;
        Ok(RenewOutcome::Renewed {
            expires_at: new_expires,
        })
    }

    /// Release the active lease on an issue, optionally only if `expect_holder`
    /// holds it (`tracker-lease.maude` I4, holder-only release).
    ///
    /// `None` releases whatever is there — the operator escape hatch for a stuck
    /// lease, and the in-program `release` effect. `Some(actor)` refuses when a
    /// *different* actor holds it, which is what keeps a stale agent from
    /// releasing live work.
    pub fn release_item(
        &mut self,
        item_id: &str,
        expect_holder: Option<&str>,
    ) -> StoreResult<ReleaseOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        if let Some(holder) = tx_holder_conflict(&tx, item_id, &now, expect_holder)? {
            tx.commit()?;
            return Ok(ReleaseOutcome::HeldByOther { holder });
        }
        let released =
            tx_release_active_lease(&tx, item_id, self.event_effect_id.as_deref(), &now)?;
        tx.commit()?;
        Ok(if released {
            ReleaseOutcome::Released
        } else {
            ReleaseOutcome::NotHeld
        })
    }

    /// See `WorkItems::subscribe_events`.
    pub fn subscribe_events(&mut self, subscriber: &str, queue: &str) -> StoreResult<bool> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let head: i64 = tx.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM tracker_events",
            [],
            |row| row.get(0),
        )?;
        // INSERT OR IGNORE, not upsert: an existing subscription keeps its
        // cursor. Re-subscribing must not rewind and redeliver.
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO tracker_subscriptions (subscriber, queue, position) \
             VALUES (?1, ?2, ?3)",
            params![subscriber, queue, head],
        )?;
        tx.commit()?;
        Ok(inserted > 0)
    }

    /// See `WorkItems::unsubscribe_events`.
    pub fn unsubscribe_events(&mut self, subscriber: &str, queue: &str) -> StoreResult<bool> {
        let removed = self.connection.execute(
            "DELETE FROM tracker_subscriptions WHERE subscriber = ?1 AND queue = ?2",
            params![subscriber, queue],
        )?;
        Ok(removed > 0)
    }

    /// See `WorkItems::list_subscriptions`.
    pub fn list_subscriptions(&self, subscriber: &str) -> StoreResult<Vec<TrackerSubscription>> {
        let mut statement = self.connection.prepare(
            "SELECT subscriber, queue, position FROM tracker_subscriptions \
             WHERE subscriber = ?1 ORDER BY queue",
        )?;
        let rows = statement
            .query_map(params![subscriber], |row| {
                Ok(TrackerSubscription {
                    subscriber: row.get(0)?,
                    queue: row.get(1)?,
                    position: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// See `WorkItems::poll_subscribed_events`.
    pub fn poll_subscribed_events(
        &self,
        subscriber: &str,
        limit: usize,
    ) -> StoreResult<Vec<SubscribedEvent>> {
        // Joined rather than queried per subscription so the cap applies across
        // the whole feed: a noisy queue must not starve a quiet one of the
        // budget, and the model sees one ordered sequence either way.
        let mut statement = self.connection.prepare(
            // The two id spaces are NOT interchangeable: `tracker_events.issue_id`
            // is the opaque content id, `tracker_issues.issue_id` is the local
            // `WS-N` alias, and `tracker_aliases` is the only bridge. Joining
            // them directly silently matches nothing.
            //
            // The alias join is therefore INNER, not LEFT: without an alias
            // there is no way to learn the event's queue, and an event that
            // cannot be attributed to a subscribed queue must not be delivered.
            "SELECT e.event_seq, i.queue, a.alias, e.kind, e.actor, i.title \
             FROM tracker_events e \
             JOIN tracker_aliases a ON a.content_id = e.issue_id \
             JOIN tracker_issues i ON i.issue_id = a.alias \
             JOIN tracker_subscriptions s \
               ON s.subscriber = ?1 AND s.queue = i.queue AND e.event_seq > s.position \
             ORDER BY e.event_seq LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![subscriber, limit as i64], |row| {
                Ok(SubscribedEvent {
                    position: row.get(0)?,
                    queue: row.get(1)?,
                    issue: row.get(2)?,
                    kind: row.get(3)?,
                    actor: row.get(4)?,
                    title: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// See `WorkItems::advance_subscription`.
    pub fn advance_subscription(
        &mut self,
        subscriber: &str,
        queue: &str,
        position: i64,
    ) -> StoreResult<()> {
        // MAX(position, ?) so a stale advance is a no-op rather than a rewind.
        self.connection.execute(
            "UPDATE tracker_subscriptions SET position = MAX(position, ?3) \
             WHERE subscriber = ?1 AND queue = ?2",
            params![subscriber, queue, position],
        )?;
        Ok(())
    }

    /// Terminal-releases-all (`tracker-lease.maude` I3, E7 non-opt-out): every
    /// active lease the actor holds across ALL issues is released in one
    /// transaction, so no intermediate state keeps a held lease.
    pub fn release_claims_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let leases: Vec<(String, String)> = tx
            .prepare(&format!(
                "SELECT lease_id, issue_id FROM tracker_leases WHERE actor = ?1 AND {ACTIVE_LEASE}"
            ))?
            .query_map(params![holder, now], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        for (lease_id, issue_id) in &leases {
            tx_mark_lease_released(
                &tx,
                lease_id,
                issue_id,
                "claim.released",
                holder,
                self.event_effect_id.as_deref(),
                &now,
            )?;
        }
        tx.commit()?;
        Ok(leases.len())
    }

    /// Marks the item done (`issue.closed`), records the optional summary, and
    /// releases any active lease. Finishable only from durable `open`.
    ///
    /// Holder-scoped when `expect_holder` is `Some` (`tracker-lease.maude` I4).
    /// Closing releases the lease, so an unguarded close is the same clobber as
    /// an unguarded release, one step removed — it ends work another actor is
    /// still doing.
    pub fn finish_item(
        &mut self,
        item_id: &str,
        summary: Option<&str>,
        expect_holder: Option<&str>,
    ) -> StoreResult<FinishOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        if let Some(holder) = tx_holder_conflict(&tx, item_id, &now, expect_holder)? {
            tx.commit()?;
            return Ok(FinishOutcome::HeldByOther { holder });
        }
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM tracker_issues WHERE issue_id = ?1",
                [item_id],
                |row| row.get(0),
            )
            .optional()?;
        if status.as_deref() != Some("open") {
            tx.commit()?;
            return Ok(FinishOutcome::NotOpen);
        }
        let payload = json!({"status": "closed", "summary": summary});
        tx_append_event(
            &tx,
            Some(item_id),
            "issue.closed",
            &payload,
            None,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "UPDATE tracker_issues SET status = 'closed', claim_summary = ?2, updated_at = ?3 \
             WHERE issue_id = ?1",
            params![item_id, summary, now],
        )?;
        tx_release_active_lease(&tx, item_id, self.event_effect_id.as_deref(), &now)?;
        tx.commit()?;
        Ok(FinishOutcome::Finished)
    }

    /// Direct an open issue at `assignee`, or clear it with `None` (0.2.2).
    ///
    /// Assignment is advisory by design: it records who *should* act, and does
    /// not restrict who *may* claim. Enforcing it in the store would put an
    /// authority model here, and this crate deliberately has none — `assignee`
    /// is an opaque string the embedding host interprets. A host that wants
    /// "only the assignee may claim" enforces it where it knows what an
    /// identity is.
    ///
    /// Returns `false` if the issue is absent or no longer open, so reassigning
    /// a closed issue is a no-op rather than a silent rewrite of history.
    pub fn assign_item(&mut self, item_id: &str, assignee: Option<&str>) -> StoreResult<bool> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM tracker_issues WHERE issue_id = ?1",
                [item_id],
                |row| row.get(0),
            )
            .optional()?;
        if status.as_deref() != Some("open") {
            tx.commit()?;
            return Ok(false);
        }
        let payload = json!({ "assigned_to": assignee });
        tx_append_event(
            &tx,
            Some(item_id),
            "issue.assigned",
            &payload,
            None,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "UPDATE tracker_issues SET assigned_to = ?2, updated_at = ?3 WHERE issue_id = ?1",
            params![item_id, assignee, now],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Records a `blocks(from -> to)` edge: `from` blocks `to`, so `to` is not
    /// ready until `from` closes (`tracker-readiness.maude`). Appends a
    /// `relation.added` event and folds it into `tracker_relations` in one
    /// transaction; idempotent via `INSERT OR IGNORE`. The `whip issue dep add`
    /// door (blocked depends-on blocker => `add_blocks(blocker, blocked)`).
    pub fn add_blocks(&mut self, from: &str, to: &str) -> StoreResult<()> {
        self.add_relation(from, to, "blocks", None)
    }

    /// Records a directed relation `kind(from -> to)` (ADR-0002 "Relations And
    /// Dependencies"). `blocks` gates readiness (`from` blocks `to`); the other
    /// kinds are graph metadata. `dep_kind` (the dependency flavor) is only
    /// valid on a `blocks` edge. A pair may carry several kinds at once
    /// (the projection PK is `(from, to, kind)`). Merge-stable: the event
    /// payload references issues by opaque content_id; the projection keeps
    /// aliases (the readiness join is alias-keyed and clone-local).
    pub fn add_relation(
        &mut self,
        from: &str,
        to: &str,
        kind: &str,
        dep_kind: Option<&str>,
    ) -> StoreResult<()> {
        if !RELATION_KINDS.contains(&kind) {
            return Err(StoreError::Conflict(format!(
                "unknown relation kind `{kind}`"
            )));
        }
        if let Some(dk) = dep_kind {
            if kind != "blocks" {
                return Err(StoreError::Conflict(
                    "dep_kind only applies to `blocks` relations".to_owned(),
                ));
            }
            if !DEPENDENCY_KINDS.contains(&dk) {
                return Err(StoreError::Conflict(format!(
                    "unknown dependency kind `{dk}`"
                )));
            }
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let from_cid = content_id_of(&tx, from)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {from}")))?;
        let to_cid = content_id_of(&tx, to)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {to}")))?;
        let payload = json!({"from": from_cid, "to": to_cid, "kind": kind, "dep_kind": dep_kind});
        tx_append_event(
            &tx,
            Some(to),
            "relation.added",
            &payload,
            None,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO tracker_relations (from_issue, to_issue, kind, dep_kind) \
             VALUES (?1, ?2, ?3, ?4)",
            params![from, to, kind, dep_kind],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Removes a relation edge (`relation.removed`). Returns whether an edge was
    /// present. The event is appended even if the edge was already absent, so
    /// the removal is durable across a rebuild and a merge.
    pub fn remove_relation(&mut self, from: &str, to: &str, kind: &str) -> StoreResult<bool> {
        if !RELATION_KINDS.contains(&kind) {
            return Err(StoreError::Conflict(format!(
                "unknown relation kind `{kind}`"
            )));
        }
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let from_cid = content_id_of(&tx, from)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {from}")))?;
        let to_cid = content_id_of(&tx, to)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {to}")))?;
        let payload = json!({"from": from_cid, "to": to_cid, "kind": kind});
        tx_append_event(
            &tx,
            Some(to),
            "relation.removed",
            &payload,
            None,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        let removed = tx.execute(
            "DELETE FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2 AND kind = ?3",
            params![from, to, kind],
        )?;
        tx.commit()?;
        Ok(removed > 0)
    }

    /// Every relation edge touching an issue (as `from` or `to`), by alias.
    pub fn relations(&self, item_id: &str) -> StoreResult<Vec<Relation>> {
        let mut statement = self.connection.prepare(
            "SELECT from_issue, to_issue, kind, dep_kind FROM tracker_relations \
             WHERE from_issue = ?1 OR to_issue = ?1 ORDER BY kind, from_issue, to_issue",
        )?;
        let rows = statement
            .query_map([item_id], |row| {
                Ok(Relation {
                    from: row.get(0)?,
                    to: row.get(1)?,
                    kind: row.get(2)?,
                    dep_kind: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Adds a comment to an issue (`comment.added`, ADR-0002 phase B2). Returns
    /// the comment's content-hash id. Merge-stable: the event is keyed by the
    /// issue's content_id and deduped by its own hash, so a comment made in one
    /// clone folds exactly once after import. Returns `None` if the issue is
    /// unknown.
    pub fn add_comment(
        &mut self,
        item_id: &str,
        author: Option<&str>,
        body: &str,
    ) -> StoreResult<Option<String>> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let Some(content_id) = content_id_of(&tx, item_id)? else {
            tx.commit()?;
            return Ok(None);
        };
        let payload = json!({"author": author, "body": body});
        let comment_id = tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "comment.added",
            &payload.to_string(),
            author,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO tracker_comments (comment_id, issue_id, author, body, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![comment_id, item_id, author, body, now],
        )?;
        tx.commit()?;
        Ok(Some(comment_id))
    }

    /// An issue's comments in chronological order.
    pub fn comments(&self, item_id: &str) -> StoreResult<Vec<Comment>> {
        let mut statement = self.connection.prepare(
            "SELECT comment_id, author, body, created_at FROM tracker_comments \
             WHERE issue_id = ?1 ORDER BY created_at, comment_id",
        )?;
        let rows = statement
            .query_map([item_id], |row| {
                Ok(Comment {
                    id: row.get(0)?,
                    author: row.get(1)?,
                    body: row.get(2)?,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Attaches evidence to an issue (`evidence.added`, ADR-0002 phase B2) — a
    /// reference / artifact / note. Returns the evidence's content-hash id, or
    /// `None` if the issue is unknown. Merge-stable and deduped like comments.
    pub fn add_evidence(
        &mut self,
        item_id: &str,
        kind: Option<&str>,
        reference: Option<&str>,
        note: Option<&str>,
        added_by: Option<&str>,
    ) -> StoreResult<Option<String>> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let Some(content_id) = content_id_of(&tx, item_id)? else {
            tx.commit()?;
            return Ok(None);
        };
        let payload = json!({
            "kind": kind, "reference": reference, "note": note, "added_by": added_by,
        });
        let evidence_id = tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "evidence.added",
            &payload.to_string(),
            added_by,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO tracker_evidence \
             (evidence_id, issue_id, kind, reference, note, added_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![evidence_id, item_id, kind, reference, note, added_by, now],
        )?;
        tx.commit()?;
        Ok(Some(evidence_id))
    }

    /// The opaque content id an issue or assertion alias resolves to, if any.
    pub fn subject_content_id(&self, id: &str) -> StoreResult<Option<String>> {
        content_id_of(&self.connection, id)
    }

    /// The content ids of the subjects `actor` currently holds active claims
    /// on (DR-0084 I1: the intent stamp's lookup — exactly one active claim
    /// is an unambiguous intent; zero or several stamp nothing).
    pub fn active_claim_subjects(&self, actor: &str) -> StoreResult<Vec<String>> {
        let now: String = self
            .connection
            .query_row("SELECT datetime('now')", [], |row| row.get(0))?;
        let mut statement = self.connection.prepare(&format!(
            "SELECT a.content_id FROM tracker_leases l \
             JOIN tracker_aliases a ON a.alias = l.issue_id \
             WHERE l.actor = ?1 AND {ACTIVE_LEASE} \
             ORDER BY l.acquired_at, l.lease_id"
        ))?;
        let rows = statement
            .query_map(params![actor, now], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Whether any claim (active or released) was ever taken on this subject
    /// — the cheap "was this worked under a claim" gate the finish
    /// auto-attest uses (DR-0084 I1).
    pub fn was_ever_claimed(&self, id: &str) -> StoreResult<bool> {
        let claimed: bool = self
            .connection
            .query_row(
                "SELECT 1 FROM tracker_leases WHERE issue_id = ?1 LIMIT 1",
                [id],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        Ok(claimed)
    }

    /// Attach KEYED evidence (DR-0084 Decision 3): `add_evidence` plus the
    /// validity key — at-cut, copied basis, resolved fingerprint. The caller
    /// (CLI, mediator) resolves the fingerprint against a frontier; this
    /// store stays VCS-free. Works for issues and assertions alike (one
    /// alias bridge).
    #[allow(clippy::too_many_arguments)]
    pub fn attest(
        &mut self,
        item_id: &str,
        kind: Option<&str>,
        reference: Option<&str>,
        note: Option<&str>,
        added_by: Option<&str>,
        at_cut: Option<&str>,
        basis: Option<&str>,
        basis_fingerprint_json: Option<&str>,
    ) -> StoreResult<Option<String>> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let Some(content_id) = content_id_of(&tx, item_id)? else {
            tx.commit()?;
            return Ok(None);
        };
        let payload = json!({
            "kind": kind, "reference": reference, "note": note, "added_by": added_by,
            "at_cut": at_cut, "basis": basis,
            "basis_fingerprint": basis_fingerprint_json
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok()),
        });
        let evidence_id = tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "evidence.added",
            &payload.to_string(),
            added_by,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO tracker_evidence \
             (evidence_id, issue_id, kind, reference, note, added_by, created_at, \
              at_cut, basis, basis_fingerprint_json) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                evidence_id,
                item_id,
                kind,
                reference,
                note,
                added_by,
                now,
                at_cut,
                basis,
                basis_fingerprint_json,
            ],
        )?;
        tx.commit()?;
        Ok(Some(evidence_id))
    }

    /// Bind an anchor to an issue or assertion (DR-0084 Decision 3). The
    /// region text is data here — validation (world-denoting subtype, parse)
    /// happens at the doors; transported anchors from other clones fold as
    /// data exactly like every other event.
    pub fn add_anchor(
        &mut self,
        item_id: &str,
        region: &str,
        role: &str,
        added_by: Option<&str>,
    ) -> StoreResult<Option<String>> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let Some(content_id) = content_id_of(&tx, item_id)? else {
            tx.commit()?;
            return Ok(None);
        };
        let payload = json!({ "region": region, "role": role, "added_by": added_by });
        let anchor_id = tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "anchor.added",
            &payload.to_string(),
            added_by,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO tracker_anchors \
             (anchor_id, subject, region, role, added_by, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![anchor_id, item_id, region, role, added_by, now],
        )?;
        tx.commit()?;
        Ok(Some(anchor_id))
    }

    /// Remove an anchor by its id — a recorded act (an `anchor.removed`
    /// event), never a silent delete; the projection row goes, the history
    /// stays. `Ok(false)` = no such anchor on that subject.
    pub fn remove_anchor(
        &mut self,
        item_id: &str,
        anchor_id: &str,
        removed_by: Option<&str>,
    ) -> StoreResult<bool> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let Some(content_id) = content_id_of(&tx, item_id)? else {
            return Ok(false);
        };
        let known: bool = tx
            .query_row(
                "SELECT 1 FROM tracker_anchors WHERE anchor_id = ?1 AND subject = ?2",
                params![anchor_id, item_id],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !known {
            return Ok(false);
        }
        tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "anchor.removed",
            &json!({ "anchor_id": anchor_id, "removed_by": removed_by }).to_string(),
            removed_by,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "DELETE FROM tracker_anchors WHERE anchor_id = ?1",
            params![anchor_id],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// A subject's current anchors, in creation order.
    pub fn anchors(&self, item_id: &str) -> StoreResult<Vec<Anchor>> {
        let mut statement = self.connection.prepare(
            "SELECT anchor_id, subject, region, role, added_by, created_at \
             FROM tracker_anchors WHERE subject = ?1 ORDER BY created_at, anchor_id",
        )?;
        let rows = statement
            .query_map([item_id], |row| {
                Ok(Anchor {
                    id: row.get(0)?,
                    subject: row.get(1)?,
                    region: row.get(2)?,
                    role: row.get(3)?,
                    added_by: row.get(4)?,
                    created_at: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// An issue's attached evidence in chronological order.
    pub fn evidence(&self, item_id: &str) -> StoreResult<Vec<Evidence>> {
        let mut statement = self.connection.prepare(
            "SELECT evidence_id, kind, reference, note, added_by, created_at, \
                    at_cut, basis, basis_fingerprint_json \
             FROM tracker_evidence WHERE issue_id = ?1 ORDER BY created_at, evidence_id",
        )?;
        let rows = statement
            .query_map([item_id], |row| {
                Ok(Evidence {
                    id: row.get(0)?,
                    kind: row.get(1)?,
                    reference: row.get(2)?,
                    note: row.get(3)?,
                    added_by: row.get(4)?,
                    created_at: row.get(5)?,
                    at_cut: row.get(6)?,
                    basis: row.get(7)?,
                    basis_fingerprint_json: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Sets one field of an issue (`issue.field_set`) — the mutation whose
    /// events the conflict engine folds. Appends the event (chaining onto the
    /// issue's current heads, so two independent sets across a merge FORK the
    /// DAG) and updates the linear projection column for the known display
    /// fields. Returns `false` if the issue does not exist.
    pub fn set_field(&mut self, item_id: &str, field: &str, value: &str) -> StoreResult<bool> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM tracker_issues WHERE issue_id = ?1",
                [item_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            tx.commit()?;
            return Ok(false);
        }
        tx_apply_field_set(
            &tx,
            item_id,
            field,
            value,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// Optimistic field set (ADR-0002 phase B1 slice v): apply only if the
    /// issue's current `state_token` still equals `expect_token`. The check and
    /// the append share one `Immediate` transaction, so a concurrent writer
    /// cannot slip a change in between — a stale token is refused with the
    /// current `actual`, never silently overwriting the other change.
    pub fn set_field_checked(
        &mut self,
        item_id: &str,
        field: &str,
        value: &str,
        expect_token: &str,
    ) -> StoreResult<SetFieldOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let exists: bool = tx
            .query_row(
                "SELECT 1 FROM tracker_issues WHERE issue_id = ?1",
                [item_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            tx.commit()?;
            return Ok(SetFieldOutcome::NotFound);
        }
        let content_id = content_id_of(&tx, item_id)?
            .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {item_id}")))?;
        let current = analyze_issue_dag(&load_issue_events(&tx, &content_id)?).state_token;
        if current != expect_token {
            tx.commit()?;
            return Ok(SetFieldOutcome::StateChanged { actual: current });
        }
        tx_apply_field_set(
            &tx,
            item_id,
            field,
            value,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        let after = analyze_issue_dag(&load_issue_events(&tx, &content_id)?).state_token;
        tx.commit()?;
        Ok(SetFieldOutcome::Applied { state_token: after })
    }

    /// The DAG conflict view of one issue (ADR-0002 phase B1 slice ii): its
    /// `heads`, the `state_token` over that frontier, and any field whose
    /// `bef`-maximal setters disagree. `None` if the issue does not exist.
    pub fn issue_conflicts(&self, item_id: &str) -> StoreResult<Option<IssueConflicts>> {
        let exists: bool = self
            .connection
            .query_row(
                "SELECT 1 FROM tracker_issues WHERE issue_id = ?1",
                [item_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Ok(None);
        }
        let Some(content_id) = content_id_of(&self.connection, item_id)? else {
            return Ok(None);
        };
        let events = load_issue_events(&self.connection, &content_id)?;
        Ok(Some(analyze_issue_dag(&events)))
    }

    /// Rebuilds the disposable projections (`tracker_issues`,
    /// `tracker_relations`, `tracker_leases`) by folding the append-only event
    /// log from empty (`tracker-projection.maude` determinism). A rebuild
    /// reproduces the live projection exactly, because live writes and the fold
    /// derive every field — including timestamps — from the same event rows.
    /// Create a knowledge-plane assertion (DR-0084 Decision 2). Identity =
    /// the content hash of its `assertion.created` event; `AS-N` is minted as
    /// the clone-local alias, exactly the issue pattern.
    pub fn create_assertion(
        &mut self,
        title: &str,
        body: &str,
        created_by: Option<&str>,
    ) -> StoreResult<Assertion> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let next: i64 = tx.query_row(
            "UPDATE tracker_assertion_counter SET next_id = next_id + 1 WHERE singleton = 1 RETURNING next_id - 1",
            [],
            |row| row.get(0),
        )?;
        let alias = format!("AS-{next}");
        let payload = json!({
            "title": title,
            "body": body,
            "created_by": created_by,
        });
        let payload_json = payload.to_string();
        let content_id = event_content_id(
            "assertion.created",
            None,
            &payload_json,
            created_by,
            &[],
            &now,
        );
        tx.execute(
            "INSERT INTO tracker_aliases (content_id, alias) VALUES (?1, ?2)",
            params![content_id, alias],
        )?;
        tx_append_raw(
            &tx,
            Some(&content_id),
            Some(&content_id),
            "assertion.created",
            &payload_json,
            created_by,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "INSERT INTO tracker_assertions \
             (assertion_id, title, body, status, created_by, created_at, updated_at) \
             VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?5)",
            params![alias, title, body, created_by, now],
        )?;
        tx.commit()?;
        // Constructed from what was just written — no re-fetch, so there is
        // no unreachable "row missing" branch to defend.
        Ok(Assertion {
            id: alias,
            content_id,
            title: title.to_owned(),
            body: body.to_owned(),
            status: "active".to_owned(),
            created_by: created_by.map(str::to_owned),
            created_at: now.clone(),
            updated_at: now,
        })
    }

    /// Look an assertion up by `AS-N` alias or by its opaque content id.
    pub fn get_assertion(&self, id: &str) -> StoreResult<Option<Assertion>> {
        let alias = if id.starts_with("AS-") {
            Some(id.to_owned())
        } else {
            self.connection
                .query_row(
                    "SELECT alias FROM tracker_aliases WHERE content_id = ?1",
                    [id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
        };
        let Some(alias) = alias else {
            return Ok(None);
        };
        let row = self
            .connection
            .query_row(
                "SELECT a.assertion_id, l.content_id, a.title, a.body, a.status, \
                        a.created_by, a.created_at, a.updated_at \
                 FROM tracker_assertions a JOIN tracker_aliases l ON l.alias = a.assertion_id \
                 WHERE a.assertion_id = ?1",
                [&alias],
                |row| {
                    Ok(Assertion {
                        id: row.get(0)?,
                        content_id: row.get(1)?,
                        title: row.get(2)?,
                        body: row.get(3)?,
                        status: row.get(4)?,
                        created_by: row.get(5)?,
                        created_at: row.get(6)?,
                        updated_at: row.get(7)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Every assertion, newest first; retired ones only when asked for —
    /// retirement changes current visibility, never history (the events
    /// remain, replay reproduces the projection).
    pub fn list_assertions(&self, include_retired: bool) -> StoreResult<Vec<Assertion>> {
        let filter = if include_retired {
            ""
        } else {
            "WHERE a.status = 'active'"
        };
        let mut statement = self.connection.prepare(&format!(
            "SELECT a.assertion_id, l.content_id, a.title, a.body, a.status, \
                    a.created_by, a.created_at, a.updated_at \
             FROM tracker_assertions a JOIN tracker_aliases l ON l.alias = a.assertion_id \
             {filter} ORDER BY a.created_at DESC, a.assertion_id DESC"
        ))?;
        let rows = statement
            .query_map([], |row| {
                Ok(Assertion {
                    id: row.get(0)?,
                    content_id: row.get(1)?,
                    title: row.get(2)?,
                    body: row.get(3)?,
                    status: row.get(4)?,
                    created_by: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Retire an assertion: an append (parented on the assertion's current
    /// heads) plus the projection update. Retired, not deleted — staleness
    /// and audit read history; retirement only ends current standing.
    pub fn retire_assertion(&mut self, id: &str, actor: Option<&str>) -> StoreResult<bool> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let now = tx_now(&tx)?;
        let alias = if id.starts_with("AS-") {
            id.to_owned()
        } else {
            match tx
                .query_row(
                    "SELECT alias FROM tracker_aliases WHERE content_id = ?1",
                    [id],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
            {
                Some(alias) => alias,
                None => return Ok(false),
            }
        };
        let Some(content_id) = content_id_of(&tx, &alias)? else {
            return Ok(false);
        };
        let known: bool = tx
            .query_row(
                "SELECT 1 FROM tracker_assertions WHERE assertion_id = ?1",
                [&alias],
                |_| Ok(true),
            )
            .optional()?
            .unwrap_or(false);
        if !known {
            return Ok(false);
        }
        tx_append_raw(
            &tx,
            Some(&content_id),
            None,
            "assertion.retired",
            &json!({ "retired_by": actor }).to_string(),
            actor,
            self.event_effect_id.as_deref(),
            &now,
        )?;
        tx.execute(
            "UPDATE tracker_assertions SET status = 'retired', updated_at = ?2 \
             WHERE assertion_id = ?1",
            params![alias, now],
        )?;
        tx.commit()?;
        Ok(true)
    }

    pub fn rebuild_projection(&mut self) -> StoreResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "DELETE FROM tracker_issues; DELETE FROM tracker_relations; DELETE FROM tracker_leases; \
             DELETE FROM tracker_comments; DELETE FROM tracker_evidence; \
             DELETE FROM tracker_assertions; DELETE FROM tracker_anchors;",
        )?;
        // The event log is keyed by opaque content_id; the projections are
        // alias-keyed. `tracker_aliases` (durable, NOT wiped) is the bridge.
        let alias_of: std::collections::HashMap<String, String> = tx
            .prepare("SELECT content_id, alias FROM tracker_aliases")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<_, _>>()?;
        // (event_id, issue_id/content_id, kind, payload_json, created_at, parents)
        type ProjectionEventRow = (String, Option<String>, String, String, String, Vec<String>);
        let events: Vec<ProjectionEventRow> = tx
            .prepare(
                "SELECT event_id, issue_id, kind, payload_json, created_at, parents_json \
                 FROM tracker_events ORDER BY event_seq",
            )?
            .query_map([], |row| {
                let parents: Vec<String> =
                    serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default();
                Ok((
                    row.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    parents,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        // Fold in a deterministic TOPOLOGICAL order (parents strictly before
        // children; concurrent events by event_id). `event_seq` is insertion
        // order, which is NOT causal after a merge — folding by it can apply a
        // field_set before its own `issue.created` (lost UPDATE) or a superseded
        // value last, so two clones holding the same event set would project
        // different columns. Topological order is content-derived and identical
        // on every clone.
        for id in topological_event_order(&events, |e| e.0.as_str(), |e| e.5.as_slice()) {
            let (event_id, content_id, kind, payload_json, created_at, _parents) = &events[id];
            let payload: Value = serde_json::from_str(payload_json).unwrap_or_else(|_| json!({}));
            let issue_alias = content_id
                .as_deref()
                .and_then(|c| alias_of.get(c))
                .map(String::as_str);
            fold_event(
                &tx,
                Some(event_id.as_str()),
                issue_alias,
                kind,
                &payload,
                created_at,
                &alias_of,
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Export every event in transport form (ADR-0002 phase B1 slice iii) — the
    /// content-addressed log another clone unions in. Ordered by append seq.
    /// The effect that wrote one event, if an effect did (G3).
    ///
    /// This is the join that replaces a search. Without it, "which effect wrote
    /// this tracker value" is answered by scanning an instance's effects by
    /// kind and target and guessing; `actor` names the instance, never the
    /// effect within it. Local only, and absent for events that arrived by
    /// import: a foreign clone's effect id names an effect in a store this one
    /// cannot query, so claiming it here would be attribution dressed up as
    /// observation.
    pub fn event_effect_id(&self, event_id: &str) -> StoreResult<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT effect_id FROM tracker_events WHERE event_id = ?1",
                params![event_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn export_events(&self) -> StoreResult<Vec<TrackerEvent>> {
        let mut statement = self.connection.prepare(
            "SELECT event_id, parents_json, issue_id, kind, payload_json, actor, created_at \
             FROM tracker_events ORDER BY event_seq",
        )?;
        let rows = statement
            .query_map([], |row| {
                let event_id: Option<String> = row.get(0)?;
                let parents_json: String = row.get(1)?;
                Ok(TrackerEvent {
                    event_id: event_id.unwrap_or_default(),
                    parents: serde_json::from_str(&parents_json).unwrap_or_default(),
                    issue_id: row.get(2)?,
                    kind: row.get(3)?,
                    payload_json: row.get(4)?,
                    actor: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Merge another clone's events into this one (ADR-0002 phase B1 slice iii):
    /// a set-union of the content-addressed log, deduped by `event_id`. Two
    /// clones that edited the SAME issue (same content_id) from a shared parent
    /// FORK its DAG — the conflict engine then surfaces the disagreement. Newly
    /// seen issues are RE-ALIASED locally (this clone's WS-N, independent of the
    /// origin's). A re-transmitted event (same content id) is deduped silently as
    /// an idempotent re-sync; a newly-seen creation that duplicates an existing
    /// issue (same queue + title, distinct content id) is reported in
    /// `duplicate_submissions` — a warning, never a silent collapse. Projections
    /// are rebuilt from the unioned log.
    pub fn import_events(&mut self, events: &[TrackerEvent]) -> StoreResult<ImportReport> {
        let mut report = ImportReport::default();
        {
            let tx = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            for event in events {
                // Re-verify the content-addressed id before admitting an event
                // from an untrusted transport (shared folder / rsync / synced
                // drive). Without this, a tampered `<hash>.json` whose payload
                // does not match its `event_id` would be folded verbatim, and an
                // event carrying an honest event's id but different content would
                // SUPPRESS the honest one via `INSERT OR IGNORE`. A created
                // event is hashed with no issue_id and no parents, and its id IS
                // the issue identity.
                let expected_id = if is_creation_kind(&event.kind) {
                    event_content_id(
                        &event.kind,
                        None,
                        &event.payload_json,
                        event.actor.as_deref(),
                        &[],
                        &event.created_at,
                    )
                } else {
                    event_content_id(
                        &event.kind,
                        event.issue_id.as_deref(),
                        &event.payload_json,
                        event.actor.as_deref(),
                        &event.parents,
                        &event.created_at,
                    )
                };
                let created_identity_ok = !is_creation_kind(&event.kind)
                    || event.issue_id.as_deref() == Some(event.event_id.as_str());
                if expected_id != event.event_id || !created_identity_ok {
                    report.rejected += 1;
                    continue;
                }
                let parents_json = serde_json::to_string(&event.parents)?;
                let changes = tx.execute(
                    "INSERT OR IGNORE INTO tracker_events \
                     (event_id, parents_json, issue_id, kind, payload_json, actor, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        event.event_id,
                        parents_json,
                        event.issue_id,
                        event.kind,
                        event.payload_json,
                        event.actor,
                        event.created_at,
                    ],
                )?;
                if changes == 1 {
                    report.imported += 1;
                } else {
                    // Byte-identical event already held. Under content-addressing
                    // this is an IDEMPOTENT re-transmit (the normal cross-machine
                    // re-sync) — the same event arriving twice, NOT a duplicate
                    // submission. Count it and stay silent; genuine duplicates are
                    // caught below by their distinct content ids.
                    report.skipped += 1;
                }
            }
            // Re-alias every newly-seen issue (has a created event, no local
            // alias yet) in append order, minting this clone's own WS-N.
            let unaliased: Vec<String> = tx
                .prepare(
                    "SELECT issue_id FROM tracker_events \
                     WHERE kind = 'issue.created' AND issue_id IS NOT NULL \
                       AND issue_id NOT IN (SELECT content_id FROM tracker_aliases) \
                     GROUP BY issue_id ORDER BY MIN(event_seq)",
                )?
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            let mut new_alias: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            for content_id in &unaliased {
                let next: i64 = tx.query_row(
                    "UPDATE tracker_counter SET next_id = next_id + 1 WHERE singleton = 1 RETURNING next_id - 1",
                    [],
                    |row| row.get(0),
                )?;
                let alias = format!("WS-{next}");
                tx.execute(
                    "INSERT INTO tracker_aliases (content_id, alias) VALUES (?1, ?2)",
                    params![content_id, alias],
                )?;
                new_alias.insert(content_id.clone(), alias);
                report.new_issues += 1;
            }
            // Re-alias every newly-seen assertion the same way, minting AS-N
            // from the assertion counter. No duplicate-submission advisory for
            // assertions in v1 (that heuristic keys on queue+title, and
            // assertions have no queue).
            let unaliased_assertions: Vec<String> = tx
                .prepare(
                    "SELECT issue_id FROM tracker_events \
                     WHERE kind = 'assertion.created' AND issue_id IS NOT NULL \
                       AND issue_id NOT IN (SELECT content_id FROM tracker_aliases) \
                     GROUP BY issue_id ORDER BY MIN(event_seq)",
                )?
                .query_map([], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            for content_id in &unaliased_assertions {
                let next: i64 = tx.query_row(
                    "UPDATE tracker_assertion_counter SET next_id = next_id + 1 WHERE singleton = 1 RETURNING next_id - 1",
                    [],
                    |row| row.get(0),
                )?;
                tx.execute(
                    "INSERT INTO tracker_aliases (content_id, alias) VALUES (?1, ?2)",
                    params![content_id, format!("AS-{next}")],
                )?;
                report.new_assertions += 1;
            }
            // Genuine duplicate submission: a newly-seen creation that describes
            // the SAME issue (same queue + title) as a DISTINCT issue already in
            // the log. Content-addressing gives every independent submission its
            // own id, so a real duplicate is two distinct `issue.created` events —
            // unlike a re-transmit, which shares one id. Advisory only (resolved
            // by a `duplicates` relation), NEVER a silent collapse.
            if !unaliased.is_empty() {
                let created: Vec<(String, String)> = tx
                    .prepare(
                        "SELECT issue_id, payload_json FROM tracker_events \
                         WHERE kind = 'issue.created' AND issue_id IS NOT NULL",
                    )?
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .map(|row| {
                        let (cid, payload_json) = row?;
                        // DR-0054 Phase C: an unreadable `issue.created` payload
                        // surfaces with its content id instead of silently
                        // reading as a blank queue+title (which both hides the
                        // corruption and can mis-group distinct issues as
                        // duplicates of each other).
                        let payload: Value =
                            serde_json::from_str(&payload_json).map_err(|error| {
                                StoreError::Conflict(format!(
                                    "tracker event `{cid}` (issue.created) has an \
                                     unreadable payload: {error}"
                                ))
                            })?;
                        let queue = payload
                            .get("queue")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let title = payload
                            .get("title")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        Ok((cid, format!("{queue}\u{1e}{title}")))
                    })
                    .collect::<StoreResult<Vec<_>>>()?;
                let mut by_key: std::collections::HashMap<&str, Vec<&str>> =
                    std::collections::HashMap::new();
                let mut key_of: std::collections::HashMap<&str, &str> =
                    std::collections::HashMap::new();
                for (cid, key) in &created {
                    by_key.entry(key).or_default().push(cid);
                    // `or_insert`, not `insert`: the linear scan this replaces
                    // took the FIRST creation event carrying a content id.
                    key_of.entry(cid.as_str()).or_insert(key.as_str());
                }
                for content_id in &unaliased {
                    if let Some(key) = key_of.get(content_id.as_str()) {
                        // A distinct issue already carries this queue+title.
                        if by_key[key].iter().any(|c| *c != content_id) {
                            report.duplicate_submissions.push(
                                new_alias
                                    .get(content_id)
                                    .cloned()
                                    .unwrap_or_else(|| content_id.clone()),
                            );
                        }
                    }
                }
            }
            tx.commit()?;
        }
        // Materialize projections from the unioned log (folds forks in on read).
        self.rebuild_projection()?;
        Ok(report)
    }

    /// Export the event log as content-addressed files under `dir` — the
    /// portable cross-machine transport (ADR-0002 phase B2). Each event is one
    /// JSON file at `dir/<aa>/<event_id>.json` (git-object-style sharding by
    /// hash prefix), so a write is idempotent and two clones' directories union
    /// by the mere set of files (drop-a-folder / rsync / synced-drive sync).
    /// Returns the number of NEW files written.
    pub fn export_to_dir(&self, dir: &Path) -> StoreResult<usize> {
        let events = self.export_events()?;
        let mut written = 0;
        for event in &events {
            if event.event_id.len() < 2 {
                continue;
            }
            let shard = dir.join(&event.event_id[..2]);
            std::fs::create_dir_all(&shard)?;
            let path = shard.join(format!("{}.json", event.event_id));
            if path.exists() {
                continue; // content-addressed: same id ⇒ same bytes, already present
            }
            std::fs::write(&path, serde_json::to_string_pretty(event)?)?;
            written += 1;
        }
        Ok(written)
    }

    /// Import every event file under `dir` (set-union, deduped by content hash).
    /// Events are applied in a deterministic order (clock, then id) so local
    /// re-aliasing is stable. Returns the merge report.
    pub fn import_from_dir(&mut self, dir: &Path) -> StoreResult<ImportReport> {
        let mut events = Vec::new();
        if dir.exists() {
            for shard in std::fs::read_dir(dir)? {
                let shard = shard?.path();
                if !shard.is_dir() {
                    continue;
                }
                for entry in std::fs::read_dir(&shard)? {
                    let path = entry?.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    if let Ok(event) =
                        serde_json::from_str::<TrackerEvent>(&std::fs::read_to_string(&path)?)
                    {
                        events.push(event);
                    }
                }
            }
        }
        events.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.event_id.cmp(&b.event_id))
        });
        self.import_events(&events)
    }

    /// Bidirectional reconcile against a shared directory: export local events
    /// to it, then import everything it holds. Two clones that both `sync_dir`
    /// the same directory converge — the cross-machine multi-writer exchange.
    pub fn sync_dir(&mut self, dir: &Path) -> StoreResult<(usize, ImportReport)> {
        let written = self.export_to_dir(dir)?;
        let report = self.import_from_dir(dir)?;
        Ok((written, report))
    }

    fn active_holder(&self, item_id: &str) -> StoreResult<Option<String>> {
        self.connection
            .query_row(
                &format!(
                    "SELECT actor FROM tracker_leases WHERE issue_id = ?1 AND {} \
                     ORDER BY acquired_at DESC LIMIT 1",
                    ACTIVE_LEASE.replace('?', "datetime('now')")
                ),
                [item_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn active_holders(&self) -> StoreResult<std::collections::HashMap<String, String>> {
        let mut statement = self.connection.prepare(&format!(
            "SELECT issue_id, actor FROM tracker_leases WHERE {}",
            ACTIVE_LEASE.replace('?', "datetime('now')")
        ))?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<std::collections::HashMap<String, String>, _>>()?;
        Ok(rows)
    }
}

/// The append-only tracker schema (native file and the DO share this shape).
/// `tracker_events` is INSERT-only — the source of truth; `tracker_issues` /
/// `tracker_relations` / `tracker_leases` are disposable projections folded from
/// it. `tracker_aliases` is NOT a projection: it is durable clone-local naming
/// state (content-hash issue id ↔ human `WS-N`), survives a rebuild, and is
/// re-assigned locally on merge-import — the WS-N of clone A is not the WS-N of
/// clone B. `tracker_counter` mints the sequential `WS-N`.
///
/// Identity (ADR-0002 phase B1 slice i unit 2): an issue's MERGE identity is the
/// content-hash of its `issue.created` event (`content_id`), carried in every
/// event's `issue_id` and in relation payloads, so two clones' logs union
/// correctly. `WS-N` is only a local alias for a human; the projection tables
/// stay keyed by it (clone-local), the event log by the opaque `content_id`.
#[cfg(feature = "native")]
const TRACKER_SCHEMA_SQL: &str = r#"
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS tracker_events (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    parents_json TEXT NOT NULL DEFAULT '[]',
    issue_id TEXT,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    actor TEXT,
    -- G3 of spec/output-attribution-research-note.md: the EFFECT that wrote
    -- this event, when one did. `actor` answers "as whom" and is part of the
    -- event's content id; this answers "by which effect", is deliberately NOT
    -- in the content id (adding it would change every event id and break
    -- import verification), and is deliberately NOT exported (a foreign clone's
    -- effect id names an effect in a store you cannot query).
    effect_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tracker_issues (
    issue_id TEXT PRIMARY KEY,
    queue TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    labels_json TEXT NOT NULL DEFAULT '[]',
    releases INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    claim_summary TEXT,
    assigned_to TEXT,
    filed_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tracker_relations (
    from_issue TEXT NOT NULL,
    to_issue TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'blocks',
    dep_kind TEXT,
    PRIMARY KEY (from_issue, to_issue, kind)
);
CREATE TABLE IF NOT EXISTS tracker_leases (
    lease_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    released_at TEXT
);
CREATE TABLE IF NOT EXISTS tracker_counter (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_id INTEGER NOT NULL
);
INSERT OR IGNORE INTO tracker_counter (singleton, next_id) VALUES (1, 1);
CREATE TABLE IF NOT EXISTS tracker_aliases (
    content_id TEXT PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS tracker_comments (
    comment_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    author TEXT,
    body TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tracker_evidence (
    evidence_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    kind TEXT,
    reference TEXT,
    note TEXT,
    added_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tracker_anchors (
    anchor_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    region TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'subject',
    added_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tracker_assertions (
    assertion_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tracker_assertion_counter (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_id INTEGER NOT NULL
);
INSERT OR IGNORE INTO tracker_assertion_counter (singleton, next_id) VALUES (1, 1);
CREATE TABLE IF NOT EXISTS tracker_subscriptions (
    subscriber TEXT NOT NULL,
    queue TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subscriber, queue)
);
CREATE INDEX IF NOT EXISTS idx_tracker_issues_queue ON tracker_issues(queue, status);
CREATE INDEX IF NOT EXISTS idx_tracker_leases_issue ON tracker_leases(issue_id, released_at);
CREATE INDEX IF NOT EXISTS idx_tracker_events_issue ON tracker_events(issue_id, kind);
"#;

/// Add a column to a table if it is missing (`CREATE TABLE IF NOT EXISTS` never
/// alters an existing table). Idempotent — the schema self-heals across phase
/// upgrades without a migration file.
#[cfg(feature = "native")]
fn tx_ensure_column(conn: &Connection, table: &str, column: &str, decl: &str) -> StoreResult<()> {
    let present = conn
        .prepare(&format!("PRAGMA table_info({table})"))?
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name == column);
    if !present {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"),
            [],
        )?;
    }
    Ok(())
}

/// Projection columns in `WorkItem` order (see `row_to_item`).
#[cfg(feature = "native")]
const ISSUE_COLS: &str = "issue_id, queue, title, body, status, labels_json, releases, \
     metadata_json, assigned_to, filed_by, created_at, updated_at";

/// Capture a single now-timestamp for one mutating op; every event + projection
/// field derived from this op uses it, so a rebuild reproduces the same values.
#[cfg(feature = "native")]
fn tx_now(tx: &Transaction<'_>) -> StoreResult<String> {
    tx.query_row("SELECT datetime('now')", [], |row| row.get(0))
        .map_err(Into::into)
}

/// The SHA-256 content id of an event (ADR-0002 phase B1: the tracker event
/// Merkle-DAG). The id commits to the event's whole content INCLUDING its
/// sorted parent ids, so the log is a hash-chain: altering any past event
/// changes its id and breaks every downstream `parents` link — a tampered
/// issue is DETECTABLE, the adversarial-integrity property FNV content-addressing
/// cannot give. SHA-256 (not FNV) precisely because the threat is a deliberate
/// forger, who could otherwise compute a colliding event. Two byte-identical
/// events (same kind/issue/payload/actor/parents/clock) share an id and dedup on
/// merge; the distinguishing `created_at` keeps genuine re-submissions distinct.
///
/// Backend-agnostic (shared by the native rusqlite store and the durable-object
/// `DoSql` store — DO parity) so both mint identical ids for identical events.
/// The event kinds that ROOT a ledger object's history: their event id IS the
/// object's durable identity (hashed with no issue_id and no parents), and a
/// transported creation event must carry its own id as its object identity.
/// One predicate shared by the native and DO import paths, so the two
/// admission doors cannot drift on which kinds are roots (DR-0084 Decision 2:
/// `issue` and `assertion` are two vocabularies over one ledger substrate).
pub fn is_creation_kind(kind: &str) -> bool {
    matches!(kind, "issue.created" | "assertion.created")
}

pub fn event_content_id(
    kind: &str,
    issue_id: Option<&str>,
    payload_json: &str,
    actor: Option<&str>,
    parents: &[String],
    created_at: &str,
) -> String {
    let mut sorted = parents.to_vec();
    sorted.sort();
    // A field-separated canonical form; the fields cannot themselves contain the
    // record separator (0x1e), so the encoding is injective.
    let material = [
        kind,
        issue_id.unwrap_or(""),
        payload_json,
        actor.unwrap_or(""),
        &sorted.join(","),
        created_at,
    ]
    .join("\u{1e}");
    sha256_hex(&material)
}

/// The current head event id(s) of an issue — events with no child (nothing
/// lists them as a parent). A new event's parents. Under single-writer appends
/// (this store) there is exactly one head, the latest event; the DAG can only
/// FORK when a merge imports a divergent log (phase B1 slice iii), which is when
/// multiple heads arise. `None` (no prior event) roots the issue's history.
#[cfg(feature = "native")]
fn tx_issue_heads(tx: &Transaction<'_>, issue_id: &str) -> StoreResult<Vec<String>> {
    let heads: Vec<String> = tx
        .prepare(
            "SELECT e.event_id FROM tracker_events e \
             WHERE e.issue_id = ?1 AND e.event_id IS NOT NULL \
               AND NOT EXISTS ( \
                 SELECT 1 FROM tracker_events c \
                 WHERE c.issue_id = ?1 \
                   AND instr(c.parents_json, '\"' || e.event_id || '\"') > 0)",
        )?
        .query_map(params![issue_id], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(heads)
}

/// Resolve a human `WS-N` alias to its opaque `content_id` merge identity.
#[cfg(feature = "native")]
fn content_id_of(conn: &Connection, alias: &str) -> StoreResult<Option<String>> {
    conn.query_row(
        "SELECT content_id FROM tracker_aliases WHERE alias = ?1",
        [alias],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

/// Append one immutable event keyed by the issue's opaque `content_id` (INSERT
/// only). Its parents are the issue's current heads; its `event_id` is the
/// content hash over the whole event, so the log is a Merkle-DAG. Pass
/// `event_id_override` only for the `issue.created` root, whose id IS the issue's
/// `content_id` (identity = the creation event). Deduped by `event_id` on merge.
#[cfg(feature = "native")]
// Eight positional arguments, which is one past the lint's taste. Grouping them
// into a struct would put the same fields behind one more name for a private
// helper with nine call sites in this file and none outside it; the existing
// `#[allow]`s in host_runtime.rs and improve.rs take the same view.
#[allow(clippy::too_many_arguments)]
fn tx_append_raw(
    tx: &Transaction<'_>,
    issue_content_id: Option<&str>,
    event_id_override: Option<&str>,
    kind: &str,
    payload_json: &str,
    actor: Option<&str>,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<String> {
    let parents = match issue_content_id {
        Some(id) => tx_issue_heads(tx, id)?,
        None => Vec::new(),
    };
    let event_id = match event_id_override {
        Some(id) => id.to_owned(),
        None => event_content_id(kind, issue_content_id, payload_json, actor, &parents, now),
    };
    let parents_json = serde_json::to_string(&parents)?;
    tx.execute(
        "INSERT OR IGNORE INTO tracker_events \
         (event_id, parents_json, issue_id, kind, payload_json, actor, effect_id, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            event_id,
            parents_json,
            issue_content_id,
            kind,
            payload_json,
            actor,
            effect_id,
            now
        ],
    )?;
    Ok(event_id)
}

/// Append one event for an issue given by its `WS-N` alias — the door for every
/// mutation the CLI drives (which speaks WS-N). Resolves the alias to the opaque
/// `content_id` the event log is keyed by, so the log stays merge-stable while
/// callers keep using the human handle.
#[cfg(feature = "native")]
fn tx_append_event(
    tx: &Transaction<'_>,
    alias: Option<&str>,
    kind: &str,
    payload: &Value,
    actor: Option<&str>,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<()> {
    let content_id = match alias {
        Some(a) => Some(
            content_id_of(tx, a)?
                .ok_or_else(|| StoreError::Conflict(format!("unknown issue alias {a}")))?,
        ),
        None => None,
    };
    tx_append_raw(
        tx,
        content_id.as_deref(),
        None,
        kind,
        &payload.to_string(),
        actor,
        effect_id,
        now,
    )?;
    Ok(())
}

/// The holder of the active lease on an issue, if any.
#[cfg(feature = "native")]
fn tx_active_holder(tx: &Transaction<'_>, item_id: &str, now: &str) -> StoreResult<Option<String>> {
    tx.query_row(
        &format!(
            "SELECT actor FROM tracker_leases WHERE issue_id = ?1 AND {ACTIVE_LEASE} \
             ORDER BY acquired_at DESC LIMIT 1"
        ),
        params![item_id, now],
        |row| row.get(0),
    )
    .optional()
    .map_err(Into::into)
}

/// Lazily expire past-due, still-held leases on an issue (append `claim.expired`,
/// mark released), so an expired lease frees the issue for a fresh claim.
#[cfg(feature = "native")]
fn tx_expire_stale_leases(tx: &Transaction<'_>, item_id: &str, now: &str) -> StoreResult<()> {
    let stale: Vec<String> = tx
        .prepare(
            "SELECT lease_id FROM tracker_leases \
             WHERE issue_id = ?1 AND released_at IS NULL AND expires_at IS NOT NULL \
               AND expires_at <= ?2",
        )?
        .query_map(params![item_id, now], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for lease_id in &stale {
        tx_mark_lease_released(tx, lease_id, item_id, "claim.expired", "system", None, now)?;
    }
    Ok(())
}

/// The active lease on `item_id`, if any, as `(lease_id, actor)`.
#[cfg(feature = "native")]
fn tx_active_lease_holder(
    tx: &Transaction<'_>,
    item_id: &str,
    now: &str,
) -> StoreResult<Option<(String, String)>> {
    Ok(tx
        .query_row(
            &format!(
                "SELECT lease_id, actor FROM tracker_leases WHERE issue_id = ?1 AND {ACTIVE_LEASE} \
                 ORDER BY acquired_at DESC LIMIT 1"
            ),
            params![item_id, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?)
}

/// Holder precondition, evaluated INSIDE the caller's transaction.
///
/// `expect_holder` is `None` for the operator and in-program paths, which may
/// release a stuck lease deliberately. It is `Some(actor)` for an agent, where
/// the whole point is that a stale one must not act on a lease someone else
/// now holds. Checking outside the transaction would be a TOCTOU race against
/// the very CAS the lease exists to be, so this is not a caller-side check.
///
/// A lease that does not exist is not a conflict: the precondition guards
/// against clobbering *another* actor, not against acting on an unclaimed item.
#[cfg(feature = "native")]
fn tx_holder_conflict(
    tx: &Transaction<'_>,
    item_id: &str,
    now: &str,
    expect_holder: Option<&str>,
) -> StoreResult<Option<String>> {
    let Some(expected) = expect_holder else {
        return Ok(None);
    };
    match tx_active_lease_holder(tx, item_id, now)? {
        Some((_, actor)) if actor != expected => Ok(Some(actor)),
        _ => Ok(None),
    }
}

/// Release the (single) active lease on an issue, if present. Returns whether a
/// lease was released. Unconditional: the holder precondition is the caller's,
/// via `tx_holder_conflict`, so the terminal and expiry paths that legitimately
/// strip another actor's lease keep working.
#[cfg(feature = "native")]
fn tx_release_active_lease(
    tx: &Transaction<'_>,
    item_id: &str,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<bool> {
    let lease: Option<(String, String)> = tx
        .query_row(
            &format!(
                "SELECT lease_id, actor FROM tracker_leases WHERE issue_id = ?1 AND {ACTIVE_LEASE} \
                 ORDER BY acquired_at DESC LIMIT 1"
            ),
            params![item_id, now],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match lease {
        None => Ok(false),
        Some((lease_id, actor)) => {
            tx_mark_lease_released(
                tx,
                &lease_id,
                item_id,
                "claim.released",
                &actor,
                effect_id,
                now,
            )?;
            Ok(true)
        }
    }
}

/// Append a lease-terminal event and fold it into the lease projection.
#[cfg(feature = "native")]
fn tx_mark_lease_released(
    tx: &Transaction<'_>,
    lease_id: &str,
    item_id: &str,
    kind: &str,
    actor: &str,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<()> {
    let payload = json!({"lease_id": lease_id, "actor": actor, "released_at": now});
    tx_append_event(
        tx,
        Some(item_id),
        kind,
        &payload,
        Some(actor),
        effect_id,
        now,
    )?;
    tx.execute(
        "UPDATE tracker_leases SET released_at = ?2 WHERE lease_id = ?1",
        params![lease_id, now],
    )?;
    // The one choke point where an item stops being held, so the count cannot
    // miss a return the way a per-caller increment could.
    tx.execute(
        "UPDATE tracker_issues SET releases = releases + 1 WHERE issue_id = ?1",
        params![item_id],
    )?;
    Ok(())
}

/// Append one `issue.field_set` (chaining onto the issue's heads) and fold it
/// into the linear display column. Shared by the plain and token-checked sets.
#[cfg(feature = "native")]
fn tx_apply_field_set(
    tx: &Transaction<'_>,
    item_id: &str,
    field: &str,
    value: &str,
    effect_id: Option<&str>,
    now: &str,
) -> StoreResult<()> {
    let payload = json!({"field": field, "value": value});
    tx_append_event(
        tx,
        Some(item_id),
        "issue.field_set",
        &payload,
        None,
        effect_id,
        now,
    )?;
    // The conflict view is computed on read from the DAG; the column is only
    // the last-writer display value.
    if let Some(column) = projection_column(field) {
        tx.execute(
            &format!(
                "UPDATE tracker_issues SET {column} = ?2, updated_at = ?3 WHERE issue_id = ?1"
            ),
            params![item_id, value, now],
        )?;
    }
    Ok(())
}

/// The `tracker_issues` display column an `issue.field_set` writes, if any.
/// Unknown fields still record an event (so the conflict view sees them) but
/// touch no column. Backend-agnostic (native + DO share it).
pub fn projection_column(field: &str) -> Option<&'static str> {
    match field {
        "title" => Some("title"),
        "body" => Some("body"),
        "status" => Some("status"),
        _ => None,
    }
}

/// SHA-256 hex of a string (the `state_token` hasher). Backend-agnostic.
///
/// Written as an explicit byte loop rather than `format!("{:x}", digest)`,
/// matching `content_hash_hex` and `stable_hash_hex`. `sha2` 0.11 returns a
/// `hybrid_array::Array` where 0.10 returned a `GenericArray`, and `Array` does
/// not implement `LowerHex` — so the formatting shorthand stopped compiling.
/// The output is unchanged: 32 bytes as 64 lowercase hex digits, which
/// `sha256_hex_matches_the_known_empty_vector` holds to a published vector,
/// because these digests are durable content ids and a changed encoding would
/// silently re-identify every existing record.
pub fn sha256_hex(s: &str) -> String {
    sha256_hex_bytes(s.as_bytes())
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest.iter() {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// One event as the conflict engine reads it (id + DAG parents + kind/payload).
/// Backend-agnostic: both the native and DO stores load their rows into this
/// shape and call `analyze_issue_dag`, so the conflict logic lives in one place.
#[derive(Clone, Debug)]
pub struct IssueEvent {
    pub event_id: String,
    pub parents: Vec<String>,
    pub kind: String,
    pub payload: Value,
}

/// Load one issue's events in append order for DAG analysis.
#[cfg(feature = "native")]
fn load_issue_events(conn: &Connection, issue_id: &str) -> StoreResult<Vec<IssueEvent>> {
    let mut statement = conn.prepare(
        "SELECT event_id, parents_json, kind, payload_json FROM tracker_events \
         WHERE issue_id = ?1 ORDER BY event_seq",
    )?;
    let rows = statement
        .query_map([issue_id], |row| {
            let event_id: Option<String> = row.get(0)?;
            let parents_json: String = row.get(1)?;
            let kind: String = row.get(2)?;
            let payload_json: String = row.get(3)?;
            Ok((event_id, parents_json, kind, payload_json))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows
        .into_iter()
        .map(|(event_id, parents_json, kind, payload_json)| IssueEvent {
            event_id: event_id.unwrap_or_default(),
            parents: serde_json::from_str(&parents_json).unwrap_or_default(),
            kind,
            payload: serde_json::from_str(&payload_json).unwrap_or_else(|_| json!({})),
        })
        .collect())
}

/// The DAG conflict analysis (ADR-0002 phase B1 slice ii, realizing
/// `tracker-merge.maude`): compute the frontier (`heads`), a content `state_token`
/// over it, and any field whose `bef`-maximal `issue.field_set` setters disagree.
/// A setter is `bef`-maximal iff no OTHER setter of the same field has it as a
/// transitive ancestor — i.e. nothing supersedes it along the DAG. A field with
/// two or more distinct maximal values is conflicted; a linear history (one
/// maximal setter) never is, and agreeing forks converge. Backend-agnostic —
/// the native and DO stores share this exact analysis (DO parity).
pub fn analyze_issue_dag(events: &[IssueEvent]) -> IssueConflicts {
    use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

    // Frontier: an event that nothing else lists as a parent.
    let claimed: HashSet<&str> = events
        .iter()
        .flat_map(|e| e.parents.iter().map(String::as_str))
        .collect();
    let mut heads: Vec<String> = events
        .iter()
        .filter(|e| !e.event_id.is_empty() && !claimed.contains(e.event_id.as_str()))
        .map(|e| e.event_id.clone())
        .collect();
    heads.sort();
    heads.dedup();
    let state_token = sha256_hex(&heads.join("\n"));

    // Which event sets which field. Each event sets at most one, and the
    // lifecycle events are ALSO status setters — including them means a
    // `finish` (close) concurrent with a `set status open` on another clone is
    // detected as a conflict, instead of silently folding to an order-dependent
    // status and being handed to a worker.
    let index: HashMap<&str, usize> = events
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.event_id.is_empty())
        .map(|(i, e)| (e.event_id.as_str(), i))
        .collect();
    let sets: Vec<Option<(String, String)>> = events
        .iter()
        .map(|e| {
            if e.event_id.is_empty() {
                return None;
            }
            match e.kind.as_str() {
                "issue.field_set" => match (
                    e.payload.get("field").and_then(Value::as_str),
                    e.payload.get("value").and_then(Value::as_str),
                ) {
                    (Some(field), Some(value)) => Some((field.to_owned(), value.to_owned())),
                    _ => None,
                },
                "issue.closed" => Some(("status".to_owned(), "closed".to_owned())),
                "issue.canceled" => Some(("status".to_owned(), "canceled".to_owned())),
                "issue.reopened" => Some(("status".to_owned(), "open".to_owned())),
                _ => None,
            }
        })
        .collect();

    // A setter counts only if NO strict descendant sets the same field — the
    // bef-maximal test. Computed once by propagating "a descendant sets this
    // field" up the DAG in reverse topological order, rather than by asking
    // `is_ancestor` for every PAIR of a field's setters and re-walking the
    // ancestor set on each ask. That pairwise form was O(n^3) in an issue's
    // event count (measured at exponent 3.06 over four doublings, 944 ms for one
    // 400-event issue) on a path `set_field_checked` takes twice per guarded
    // set. This is linear in events times the handful of distinct fields, and
    // `topological_event_order` is content-derived, so the traversal order is
    // identical on every clone.
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); events.len()];
    for (i, event) in events.iter().enumerate() {
        for parent in &event.parents {
            if let Some(&pi) = index.get(parent.as_str()) {
                children[pi].push(i);
            }
        }
    }
    let mut covered: Vec<BTreeSet<&str>> = vec![BTreeSet::new(); events.len()];
    let mut order = topological_event_order(events, |e| e.event_id.as_str(), |e| &e.parents);
    order.reverse();
    for &node in &order {
        let mut below: BTreeSet<&str> = BTreeSet::new();
        for &child in &children[node] {
            below.extend(covered[child].iter().copied());
            if let Some((field, _)) = &sets[child] {
                below.insert(field.as_str());
            }
        }
        covered[node] = below;
    }

    let mut maximal: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for (i, set) in sets.iter().enumerate() {
        let Some((field, value)) = set else { continue };
        if covered[i].contains(field.as_str()) {
            continue;
        }
        maximal
            .entry(field.as_str())
            .or_default()
            .insert(value.clone());
    }
    let field_conflicts = maximal
        .into_iter()
        .filter(|(_, values)| values.len() > 1)
        .map(|(field, values)| FieldConflict {
            field: field.to_owned(),
            values: values.into_iter().collect(),
        })
        .collect::<Vec<_>>();

    IssueConflicts {
        heads,
        state_token,
        field_conflicts,
    }
}

/// Fold one event into the projection tables — the shared step of both live
/// application and `rebuild_projection`, so a rebuild is bit-identical. `issue_id`
/// is the alias of the event's subject issue (already resolved from the event's
/// Deterministic topological order over a content-addressed event DAG: every
/// event's in-set parents come strictly before it; concurrent events are broken
/// by `event_id`. Returns indices into `events`. Because both the parent edges
/// and the tiebreak are content-derived, the order is IDENTICAL on every clone,
/// independent of insertion / import order — so folding in this order makes the
/// projected columns converge. Cycle-safe: a Merkle DAG has no cycles, but any
/// leftover (e.g. a dangling parent from a partial import) is appended by
/// `event_id`. Shared by the native rebuild and (via the DO's own copy) the DO.
pub fn topological_event_order<T>(
    events: &[T],
    id_of: impl Fn(&T) -> &str,
    parents_of: impl Fn(&T) -> &[String],
) -> Vec<usize> {
    use std::collections::{BTreeSet, HashMap};
    let index: HashMap<&str, usize> = events
        .iter()
        .enumerate()
        .map(|(i, e)| (id_of(e), i))
        .collect();
    let mut indeg = vec![0usize; events.len()];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); events.len()];
    for (i, e) in events.iter().enumerate() {
        for parent in parents_of(e) {
            if let Some(&pi) = index.get(parent.as_str()) {
                children[pi].push(i);
                indeg[i] += 1;
            }
        }
    }
    let mut ready: BTreeSet<(&str, usize)> = (0..events.len())
        .filter(|&i| indeg[i] == 0)
        .map(|i| (id_of(&events[i]), i))
        .collect();
    let mut order = Vec::with_capacity(events.len());
    while let Some(&(_, i)) = ready.iter().next() {
        ready.remove(&(id_of(&events[i]), i));
        order.push(i);
        for &child in &children[i] {
            indeg[child] -= 1;
            if indeg[child] == 0 {
                ready.insert((id_of(&events[child]), child));
            }
        }
    }
    if order.len() < events.len() {
        let mut seen = vec![false; events.len()];
        for &i in &order {
            seen[i] = true;
        }
        let mut rest: Vec<usize> = (0..events.len()).filter(|&i| !seen[i]).collect();
        rest.sort_by(|&a, &b| id_of(&events[a]).cmp(id_of(&events[b])));
        order.extend(rest);
    }
    order
}

/// opaque `content_id`). `alias_of` maps content_id → alias so `relation.added`
/// payloads (which reference issues by opaque id) fold into the alias-keyed
/// projection.
#[cfg(feature = "native")]
fn fold_event(
    tx: &Transaction<'_>,
    event_id: Option<&str>,
    issue_id: Option<&str>,
    kind: &str,
    payload: &Value,
    created_at: &str,
    alias_of: &std::collections::HashMap<String, String>,
) -> StoreResult<()> {
    let str_of = |key: &str| payload.get(key).and_then(Value::as_str).map(str::to_owned);
    match kind {
        "issue.created" => {
            let labels_json = payload
                .get("labels")
                .map_or_else(|| "[]".to_owned(), std::string::ToString::to_string);
            let metadata_json = payload
                .get("metadata")
                .map_or_else(|| "{}".to_owned(), std::string::ToString::to_string);
            tx.execute(
                "INSERT INTO tracker_issues \
                 (issue_id, queue, title, body, status, labels_json, metadata_json, filed_by, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, 'open', ?5, ?6, ?7, ?8, ?8)",
                params![
                    issue_id,
                    payload.get("queue").and_then(Value::as_str).unwrap_or_default(),
                    payload.get("title").and_then(Value::as_str).unwrap_or_default(),
                    payload.get("body").and_then(Value::as_str).unwrap_or_default(),
                    labels_json,
                    metadata_json,
                    payload.get("filed_by").and_then(Value::as_str),
                    created_at,
                ],
            )?;
        }
        "issue.field_set" => {
            if let (Some(id), Some(field), Some(value)) =
                (issue_id, str_of("field"), str_of("value"))
            {
                // Only the columns v1 sets via field_set; unknown fields are ignored.
                let column = match field.as_str() {
                    "title" => "title",
                    "body" => "body",
                    "status" => "status",
                    _ => return Ok(()),
                };
                tx.execute(
                    &format!(
                        "UPDATE tracker_issues SET {column} = ?2, updated_at = ?3 WHERE issue_id = ?1"
                    ),
                    params![id, value, created_at],
                )?;
            }
        }
        "issue.closed" => fold_set_status(tx, issue_id, payload, "closed", created_at)?,
        "issue.canceled" => fold_set_status(tx, issue_id, payload, "canceled", created_at)?,
        "issue.reopened" => fold_set_status(tx, issue_id, payload, "open", created_at)?,
        "relation.added" => {
            // The payload references issues by opaque content_id; the projection
            // is alias-keyed. Skip the edge if either endpoint has no local alias
            // (an imported relation whose issue we do not yet hold).
            let (Some(from), Some(to)) = (
                str_of("from").and_then(|c| alias_of.get(&c).cloned()),
                str_of("to").and_then(|c| alias_of.get(&c).cloned()),
            ) else {
                return Ok(());
            };
            tx.execute(
                "INSERT OR IGNORE INTO tracker_relations (from_issue, to_issue, kind, dep_kind) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    from,
                    to,
                    str_of("kind").unwrap_or_else(|| "blocks".to_owned()),
                    str_of("dep_kind"),
                ],
            )?;
        }
        "relation.removed" => {
            let (Some(from), Some(to)) = (
                str_of("from").and_then(|c| alias_of.get(&c).cloned()),
                str_of("to").and_then(|c| alias_of.get(&c).cloned()),
            ) else {
                return Ok(());
            };
            tx.execute(
                "DELETE FROM tracker_relations \
                 WHERE from_issue = ?1 AND to_issue = ?2 AND kind = ?3",
                params![
                    from,
                    to,
                    str_of("kind").unwrap_or_else(|| "blocks".to_owned())
                ],
            )?;
        }
        "comment.added" => {
            // Keyed by the comment's own event_id (content hash) so a merge /
            // re-import folds each comment exactly once.
            if let (Some(comment_id), Some(issue)) = (event_id, issue_id) {
                tx.execute(
                    "INSERT OR IGNORE INTO tracker_comments \
                     (comment_id, issue_id, author, body, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        comment_id,
                        issue,
                        str_of("author"),
                        str_of("body").unwrap_or_default(),
                        created_at,
                    ],
                )?;
            }
        }
        "evidence.added" => {
            if let (Some(evidence_id), Some(issue)) = (event_id, issue_id) {
                // DR-0084: keyed evidence carries its validity key; the
                // fingerprint folds verbatim (it is data, evaluated later).
                let fingerprint_json = payload
                    .get("basis_fingerprint")
                    .filter(|value| !value.is_null())
                    .map(std::string::ToString::to_string);
                tx.execute(
                    "INSERT OR IGNORE INTO tracker_evidence \
                     (evidence_id, issue_id, kind, reference, note, added_by, created_at, \
                      at_cut, basis, basis_fingerprint_json) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        evidence_id,
                        issue,
                        str_of("kind"),
                        str_of("reference"),
                        str_of("note"),
                        str_of("added_by"),
                        created_at,
                        str_of("at_cut"),
                        str_of("basis"),
                        fingerprint_json,
                    ],
                )?;
            }
        }
        "anchor.added" => {
            if let (Some(anchor_id), Some(subject)) = (event_id, issue_id) {
                tx.execute(
                    "INSERT OR IGNORE INTO tracker_anchors \
                     (anchor_id, subject, region, role, added_by, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        anchor_id,
                        subject,
                        str_of("region").unwrap_or_default(),
                        str_of("role").unwrap_or_else(|| "subject".to_owned()),
                        str_of("added_by"),
                        created_at,
                    ],
                )?;
            }
        }
        "anchor.removed" => {
            if let Some(anchor_id) = str_of("anchor_id") {
                tx.execute(
                    "DELETE FROM tracker_anchors WHERE anchor_id = ?1",
                    params![anchor_id],
                )?;
            }
        }
        "assertion.created" => {
            // `issue_id` here is the assertion's resolved AS-N alias (the fold
            // resolves every subject through the shared alias bridge).
            if let Some(alias) = issue_id {
                tx.execute(
                    "INSERT OR IGNORE INTO tracker_assertions \
                     (assertion_id, title, body, status, created_by, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, 'active', ?4, ?5, ?5)",
                    params![
                        alias,
                        str_of("title").unwrap_or_default(),
                        str_of("body").unwrap_or_default(),
                        str_of("created_by"),
                        created_at,
                    ],
                )?;
            }
        }
        "assertion.retired" => {
            if let Some(alias) = issue_id {
                tx.execute(
                    "UPDATE tracker_assertions SET status = 'retired', updated_at = ?2 \
                     WHERE assertion_id = ?1",
                    params![alias, created_at],
                )?;
            }
        }
        "claim.acquired" => {
            // Keyed by the acquire event's own event_id (content hash), like
            // comments/evidence: clone-local payload ids collide across clones
            // and INSERT OR IGNORE would silently drop one of two concurrent
            // cross-clone claims.
            if let (Some(lease_id), Some(issue)) = (event_id, issue_id) {
                tx.execute(
                    "INSERT OR IGNORE INTO tracker_leases (lease_id, issue_id, actor, acquired_at, expires_at, released_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, NULL)",
                    params![
                        lease_id,
                        issue,
                        str_of("actor"),
                        created_at,
                        payload.get("expires_at").and_then(Value::as_str),
                    ],
                )?;
            }
        }
        "claim.renewed" => {
            tx.execute(
                "UPDATE tracker_leases SET expires_at = ?2 WHERE lease_id = ?1",
                params![
                    str_of("lease_id"),
                    payload.get("expires_at").and_then(Value::as_str)
                ],
            )?;
        }
        "claim.released" | "claim.expired" => {
            tx.execute(
                "UPDATE tracker_leases SET released_at = ?2 WHERE lease_id = ?1",
                params![
                    str_of("lease_id"),
                    str_of("released_at").unwrap_or_else(|| created_at.to_owned())
                ],
            )?;
            // The live path counts in `tx_mark_lease_released`; a rebuild
            // replays the same events into a fresh projection, so the count has
            // to be derivable from the log or it would come back as zero.
            if let Some(issue_id) = issue_id {
                tx.execute(
                    "UPDATE tracker_issues SET releases = releases + 1 WHERE issue_id = ?1",
                    params![issue_id],
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(feature = "native")]
fn fold_set_status(
    tx: &Transaction<'_>,
    issue_id: Option<&str>,
    payload: &Value,
    status: &str,
    created_at: &str,
) -> StoreResult<()> {
    if let Some(id) = issue_id {
        let summary = payload.get("summary").and_then(Value::as_str);
        tx.execute(
            "UPDATE tracker_issues SET status = ?2, claim_summary = COALESCE(?3, claim_summary), \
             updated_at = ?4 WHERE issue_id = ?1",
            params![id, status, summary, created_at],
        )?;
    }
    Ok(())
}

/// Apply the active-lease overlay to a projection row: an issue under an active
/// lease presents as `in_progress` claimed by the holder (readiness overlay),
/// never a durable status write. Only durable-`open` issues can be overlaid.
/// Shared by the native and durable-object backends so the overlay is identical.
pub fn apply_overlay(mut item: WorkItem, holder: Option<String>) -> WorkItem {
    if item.status == "open" {
        if let Some(holder) = holder {
            item.status = "in_progress".to_owned();
            item.claimed_by = Some(holder);
        }
    }
    item
}

/// The work-item tracker as a backend-agnostic trait — the sans-IO store seam
/// (DR-0033 Phase 3), so a durable-object SQLite backend can back the same queue
/// operations without the language changing (`spec/work-queues.md`). The native
/// `WorkItemStore` implements it by forwarding to its inherent methods, so
/// existing callers are unaffected.
pub trait WorkItems {
    /// The workspace-plane HIGH-WATER position of the tracker's monotone
    /// event log (max event_seq; 0 = empty). One half of the two-plane
    /// consistent cut (vw note §9.3).
    /// Scope subsequent tracker writes to the effect performing them, or clear
    /// it with `None` (G3 of spec/output-attribution-research-note.md).
    ///
    /// Scoped rather than a parameter on every mutation: the alternative is
    /// widening a dozen public methods with well over a hundred call sites,
    /// nearly all of them tests with no effect to name. The queue-effect
    /// dispatch sets it around the whole of its work and clears it after, which
    /// is the only window in which it is meaningful — a stale value would
    /// MISATTRIBUTE a later write, which is worse than recording nothing.
    fn set_event_effect_id(&mut self, _effect_id: Option<&str>) {}

    fn event_position(&self) -> StoreResult<i64>;

    /// Declare an interest in `queue`, starting from the CURRENT end of the log.
    ///
    /// Starting at the head rather than at zero is the whole point: a
    /// subscription is for what happens next, and replaying a queue's entire
    /// history into a model's context the moment it subscribes would bury the
    /// one line that matters. Re-subscribing is idempotent and does NOT rewind
    /// an existing cursor — that would redeliver what the subscriber has seen.
    fn subscribe_events(&mut self, subscriber: &str, queue: &str) -> StoreResult<bool>;

    /// Drop an interest. `false` when there was none.
    fn unsubscribe_events(&mut self, subscriber: &str, queue: &str) -> StoreResult<bool>;

    /// What `subscriber` is currently subscribed to.
    fn list_subscriptions(&self, subscriber: &str) -> StoreResult<Vec<TrackerSubscription>>;

    /// Events appended since this subscriber's cursor, across every queue it
    /// subscribes to, in local append order and capped at `limit`.
    ///
    /// The cursor is a local `event_seq` watermark, not a DAG frontier. The log
    /// IS a DAG, and that governs causality and conflict resolution — but a feed
    /// asks a different question: what has landed in THIS store since I last
    /// looked. Local append order answers exactly that, including for events
    /// merged in from another clone, which take local sequence numbers when
    /// `import_events` folds them and so are delivered on arrival. A frontier
    /// cursor would also have nothing to point at: `state_token` is computed per
    /// issue, so there is no global head to name.
    ///
    /// Reading does not advance; call `advance_subscription` once delivered.
    fn poll_subscribed_events(
        &self,
        subscriber: &str,
        limit: usize,
    ) -> StoreResult<Vec<SubscribedEvent>>;

    /// Move a subscription's cursor forward. Never moves it backward, so a
    /// late or duplicated advance cannot redeliver.
    fn advance_subscription(
        &mut self,
        subscriber: &str,
        queue: &str,
        position: i64,
    ) -> StoreResult<()>;
    fn file_item(
        &mut self,
        queue: &str,
        title: &str,
        body: &str,
        labels: &[String],
        metadata: &Value,
        filed_by: Option<&str>,
    ) -> StoreResult<WorkItem>;

    fn get_item(&self, item_id: &str) -> StoreResult<Option<WorkItem>>;

    /// Direct an open issue at `assignee`, or clear it with `None` (0.2.2).
    /// Advisory: it records who *should* act and never restricts who may claim.
    /// Default: no-op, for a store with no assignment plane.
    fn assign_item(&mut self, _item_id: &str, _assignee: Option<&str>) -> StoreResult<bool> {
        Ok(false)
    }

    fn list_items(&self, queue: Option<&str>, status: Option<&str>) -> StoreResult<Vec<WorkItem>>;

    fn ready_items(&self, queue: &str) -> StoreResult<Vec<WorkItem>>;

    /// Atomic claim with an optional absolute expiry (`None` = no TTL). The
    /// T3 claim-TTL half: the caller computes `now + ttl` and passes it here.
    fn claim_item(
        &mut self,
        item_id: &str,
        claimed_by: &str,
        expires: Option<&str>,
    ) -> StoreResult<ClaimOutcome>;

    /// Holder-only lease extension/heartbeat (the T3 sanctioned extension).
    fn renew_claim(
        &mut self,
        item_id: &str,
        actor: &str,
        expires: Option<&str>,
    ) -> StoreResult<RenewOutcome>;

    /// Holder-scoped when `expect_holder` is `Some` (`tracker-lease.maude` I4);
    /// `None` is the operator/in-program path that may clear a stuck lease.
    fn release_item(
        &mut self,
        item_id: &str,
        expect_holder: Option<&str>,
    ) -> StoreResult<ReleaseOutcome>;

    fn release_claims_for_holder(&mut self, holder: &str) -> StoreResult<usize>;

    fn finish_item(
        &mut self,
        item_id: &str,
        summary: Option<&str>,
        expect_holder: Option<&str>,
    ) -> StoreResult<FinishOutcome>;

    /// Records a `blocks(from -> to)` edge (`to` is gated until `from` closes).
    /// The relation source-verbs' A+blockers seam; `from` blocks `to`.
    fn add_blocks(&mut self, from: &str, to: &str) -> StoreResult<()>;

    // ------------------------------------------------------------------
    // The knowledge plane (DR-0084), joining the trait with its first
    // workflow consumer: the effect-door finish auto-attest (DR-0086 F3).
    // ------------------------------------------------------------------

    /// The opaque content id an issue or assertion alias resolves to.
    fn subject_content_id(&self, id: &str) -> StoreResult<Option<String>>;

    /// Whether any claim (active or released) was ever taken on the subject
    /// — the finish auto-attest's cheap "was this worked under a claim" gate.
    fn was_ever_claimed(&self, id: &str) -> StoreResult<bool>;

    /// The subject's current anchors, in creation order.
    fn anchors(&self, item_id: &str) -> StoreResult<Vec<Anchor>>;

    /// The content ids of the subjects `actor` currently holds active
    /// claims on — the intent stamp's lookup (DR-0084 I1, generic since
    /// DR-0086 F4 so both hosts stamp identically).
    fn active_claim_subjects(&self, actor: &str) -> StoreResult<Vec<String>>;

    /// A subject's attached evidence in chronological order.
    fn evidence(&self, item_id: &str) -> StoreResult<Vec<Evidence>>;

    /// Attach KEYED evidence: kind/reference/note/actor plus the DR-0084
    /// validity key (at-cut, copied basis, resolved fingerprint) — all key
    /// fields optional, so unkeyed evidence is the same door with `None`s.
    /// `Ok(None)` = unknown subject.
    #[allow(clippy::too_many_arguments)]
    fn attest(
        &mut self,
        item_id: &str,
        kind: Option<&str>,
        reference: Option<&str>,
        note: Option<&str>,
        added_by: Option<&str>,
        at_cut: Option<&str>,
        basis: Option<&str>,
        basis_fingerprint_json: Option<&str>,
    ) -> StoreResult<Option<String>>;
}

#[cfg(feature = "native")]
impl WorkItems for WorkItemStore {
    fn subject_content_id(&self, id: &str) -> StoreResult<Option<String>> {
        WorkItemStore::subject_content_id(self, id)
    }

    fn was_ever_claimed(&self, id: &str) -> StoreResult<bool> {
        WorkItemStore::was_ever_claimed(self, id)
    }

    fn anchors(&self, item_id: &str) -> StoreResult<Vec<Anchor>> {
        WorkItemStore::anchors(self, item_id)
    }

    fn active_claim_subjects(&self, actor: &str) -> StoreResult<Vec<String>> {
        WorkItemStore::active_claim_subjects(self, actor)
    }

    fn evidence(&self, item_id: &str) -> StoreResult<Vec<Evidence>> {
        WorkItemStore::evidence(self, item_id)
    }

    fn attest(
        &mut self,
        item_id: &str,
        kind: Option<&str>,
        reference: Option<&str>,
        note: Option<&str>,
        added_by: Option<&str>,
        at_cut: Option<&str>,
        basis: Option<&str>,
        basis_fingerprint_json: Option<&str>,
    ) -> StoreResult<Option<String>> {
        WorkItemStore::attest(
            self,
            item_id,
            kind,
            reference,
            note,
            added_by,
            at_cut,
            basis,
            basis_fingerprint_json,
        )
    }

    fn set_event_effect_id(&mut self, effect_id: Option<&str>) {
        self.event_effect_id = effect_id.map(str::to_owned);
    }

    // Forwards to the inherent methods of the same name; inherent methods win
    // `self.method()` resolution, so this delegates rather than recurses.
    fn event_position(&self) -> StoreResult<i64> {
        let position: i64 = self.connection.query_row(
            "SELECT COALESCE(MAX(event_seq), 0) FROM tracker_events",
            [],
            |row| row.get(0),
        )?;
        Ok(position)
    }

    fn file_item(
        &mut self,
        queue: &str,
        title: &str,
        body: &str,
        labels: &[String],
        metadata: &Value,
        filed_by: Option<&str>,
    ) -> StoreResult<WorkItem> {
        self.file_item(queue, title, body, labels, metadata, filed_by)
    }

    fn get_item(&self, item_id: &str) -> StoreResult<Option<WorkItem>> {
        self.get_item(item_id)
    }

    fn assign_item(&mut self, item_id: &str, assignee: Option<&str>) -> StoreResult<bool> {
        self.assign_item(item_id, assignee)
    }

    fn list_items(&self, queue: Option<&str>, status: Option<&str>) -> StoreResult<Vec<WorkItem>> {
        self.list_items(queue, status)
    }

    fn ready_items(&self, queue: &str) -> StoreResult<Vec<WorkItem>> {
        self.ready_items(queue)
    }

    fn claim_item(
        &mut self,
        item_id: &str,
        claimed_by: &str,
        expires: Option<&str>,
    ) -> StoreResult<ClaimOutcome> {
        self.claim_item(item_id, claimed_by, expires)
    }

    fn renew_claim(
        &mut self,
        item_id: &str,
        actor: &str,
        expires: Option<&str>,
    ) -> StoreResult<RenewOutcome> {
        self.renew_claim(item_id, actor, expires)
    }

    fn release_item(
        &mut self,
        item_id: &str,
        expect_holder: Option<&str>,
    ) -> StoreResult<ReleaseOutcome> {
        self.release_item(item_id, expect_holder)
    }

    fn subscribe_events(&mut self, subscriber: &str, queue: &str) -> StoreResult<bool> {
        self.subscribe_events(subscriber, queue)
    }

    fn unsubscribe_events(&mut self, subscriber: &str, queue: &str) -> StoreResult<bool> {
        self.unsubscribe_events(subscriber, queue)
    }

    fn list_subscriptions(&self, subscriber: &str) -> StoreResult<Vec<TrackerSubscription>> {
        self.list_subscriptions(subscriber)
    }

    fn poll_subscribed_events(
        &self,
        subscriber: &str,
        limit: usize,
    ) -> StoreResult<Vec<SubscribedEvent>> {
        self.poll_subscribed_events(subscriber, limit)
    }

    fn advance_subscription(
        &mut self,
        subscriber: &str,
        queue: &str,
        position: i64,
    ) -> StoreResult<()> {
        self.advance_subscription(subscriber, queue, position)
    }

    fn release_claims_for_holder(&mut self, holder: &str) -> StoreResult<usize> {
        self.release_claims_for_holder(holder)
    }

    fn finish_item(
        &mut self,
        item_id: &str,
        summary: Option<&str>,
        expect_holder: Option<&str>,
    ) -> StoreResult<FinishOutcome> {
        self.finish_item(item_id, summary, expect_holder)
    }

    fn add_blocks(&mut self, from: &str, to: &str) -> StoreResult<()> {
        self.add_blocks(from, to)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    Claimed,
    AlreadyClaimed { holder: String },
    NotFound,
}

/// Outcome of `renew_claim` (`tracker-lease.maude` I2). `NotHeld` = the actor
/// does not hold an active lease on the issue; `NotMonotonic` = the requested
/// finite deadline would move the lease backward.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RenewOutcome {
    Renewed { expires_at: Option<String> },
    NotHeld,
    NotMonotonic,
}

/// Render one subscribed event as the prose line delivered mid-turn.
///
/// Prose, not JSON, for the reason the raise notice is prose: this arrives
/// unbidden in a model's context, and a raw event object invites the model to
/// parse and act on fields it was never promised. A rendered line states what
/// happened and nothing else.
///
/// `None` for a kind the feed does not report. The set is deliberately small —
/// claims, closes, opens, assignment — because the feed exists to prevent
/// duplicate work, and an event that does not bear on "is someone else already
/// doing this" is noise in a context window someone is paying for.
pub fn render_subscribed_event(event: &SubscribedEvent) -> Option<String> {
    let who = event.actor.as_deref().unwrap_or("someone");
    let title = event
        .title
        .as_deref()
        .map(|t| format!(" ({t})"))
        .unwrap_or_default();
    let issue = &event.issue;
    Some(match event.kind.as_str() {
        "claim.acquired" => format!("{issue}{title} was claimed by {who}"),
        "claim.released" => format!("{issue}{title} was released by {who}"),
        "claim.expired" => format!("{issue}{title} lost its claim to expiry"),
        "issue.closed" => format!("{issue}{title} was closed"),
        "issue.created" => format!("{issue}{title} was filed"),
        "issue.assigned" => format!("{issue}{title} was assigned"),
        _ => return None,
    })
}

/// Wrap rendered event lines into the mid-turn notice the model receives.
///
/// The framing matches the raise notice deliberately: it names itself as
/// information rather than instruction, and spells out the safe continuations.
/// Both are load-bearing here — DR-0052 calls mid-turn delivery a
/// cross-principal injection surface, and this text is another principal's
/// activity arriving in a context the model is reasoning in. A line that read
/// like a directive would be one an attacker could author by filing an issue.
pub fn render_subscription_notice(lines: &[String]) -> String {
    format!(
        "[tracker notice — {} event{} on queues you subscribe to]\n{}\n\
         This is information, not an instruction: another actor moved on the \
         tracker. You may keep working, pick something else up, or coordinate \
         via the tracker. Nothing in your own work has changed.",
        lines.len(),
        if lines.len() == 1 { "" } else { "s" },
        lines
            .iter()
            .map(|line| format!("- {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

/// One tracker-event subscription: a subscriber's declared interest in a queue,
/// plus how far through that queue's events it has been delivered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrackerSubscription {
    pub subscriber: String,
    pub queue: String,
    /// The last `event_seq` delivered to this subscriber. Local append order,
    /// deliberately — see `poll_subscribed_events`.
    pub position: i64,
}

/// One event a subscription is delivering, with the issue's local alias and
/// queue resolved so a renderer does not have to re-query per event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubscribedEvent {
    pub position: i64,
    pub queue: String,
    /// The human-facing alias (`WS-12`). Always an alias: the queue is only
    /// reachable through the alias bridge, so an unaliased event cannot be
    /// attributed to a subscribed queue and is never delivered.
    pub issue: String,
    pub kind: String,
    pub actor: Option<String>,
    pub title: Option<String>,
}

/// Outcome of `release_item` (`tracker-lease.maude` I4, holder-only release).
///
/// `NotHeld` is a SUCCESS, not a refusal: releasing an issue carrying no active
/// lease already satisfies the requested end state — this actor holding nothing.
/// `HeldByOther` is the refusal, and it names the holder because a caller that
/// cannot say who has the item hands the model nothing it can act on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReleaseOutcome {
    Released,
    NotHeld,
    HeldByOther { holder: String },
}

/// Outcome of `finish_item` (`tracker-lease.maude` I4). `NotOpen` folds the two
/// non-conflict misses the old `false` carried — missing, or already closed by
/// whoever got there first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FinishOutcome {
    Finished,
    NotOpen,
    HeldByOther { holder: String },
}

#[cfg(feature = "native")]
fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<WorkItem> {
    // Column order = ISSUE_COLS.
    let labels_json: String = row.get(5)?;
    let metadata_json: String = row.get(7)?;
    Ok(WorkItem {
        id: row.get(0)?,
        queue: row.get(1)?,
        title: row.get(2)?,
        body: row.get(3)?,
        status: row.get(4)?,
        labels: serde_json::from_str(&labels_json).unwrap_or_default(),
        releases: row.get(6)?,
        metadata: serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({})),
        // Durable projection carries no holder; the overlay supplies it.
        claimed_by: None,
        assigned_to: row.get(8)?,
        filed_by: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DR-0084 Decision 2: an assertion's durable identity is the content
    /// hash of its `assertion.created` event; `AS-N` is only a clone-local
    /// alias, and no event is ever keyed by it.
    #[test]
    fn assertion_identity_is_the_creation_event_hash() {
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let assertion = store
            .create_assertion("custody core verified", "model + sweep", Some("s:sess-1"))
            .expect("create");
        assert_eq!(assertion.id, "AS-1");
        assert_eq!(assertion.content_id.len(), 64, "content id is a SHA-256");
        assert_eq!(assertion.status, "active");

        // No event keyed by the alias; the log speaks content ids only.
        let by_alias: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM tracker_events WHERE issue_id = 'AS-1'",
                [],
                |row| row.get(0),
            )
            .expect("count");
        assert_eq!(by_alias, 0);

        // Lookup resolves through either handle.
        let by_content = store
            .get_assertion(&assertion.content_id)
            .expect("get")
            .expect("found");
        assert_eq!(by_content.id, "AS-1");
    }

    /// Assertions ride the same content-addressed transport as issues: a
    /// second clone imports them (identity re-verified — `assertion.created`
    /// is a root kind), re-aliases locally, folds the retirement, stays
    /// quiet on re-import, and a projection rebuild reproduces the rows.
    #[test]
    fn assertions_merge_across_clones_and_rebuild() {
        let mut a = WorkItemStore::open_in_memory().expect("store a");
        let kept = a
            .create_assertion("kept", "", Some("s:a"))
            .expect("create kept");
        let retired = a
            .create_assertion("retired", "", Some("s:a"))
            .expect("create retired");
        assert!(a
            .retire_assertion(&retired.id, Some("s:a"))
            .expect("retire"));

        let mut b = WorkItemStore::open_in_memory().expect("store b");
        let report = b
            .import_events(&a.export_events().expect("export"))
            .expect("import");
        assert_eq!(report.new_assertions, 2);
        assert_eq!(report.rejected, 0);

        // B's aliases are its own; identity is shared.
        let b_kept = b
            .get_assertion(&kept.content_id)
            .expect("get")
            .expect("found");
        assert_eq!(b_kept.title, "kept");
        assert_eq!(b_kept.status, "active");
        let b_retired = b
            .get_assertion(&retired.content_id)
            .expect("get")
            .expect("found");
        assert_eq!(b_retired.status, "retired");

        // Re-import is an idempotent resync: nothing new, nothing rejected.
        let again = b
            .import_events(&a.export_events().expect("export"))
            .expect("reimport");
        assert_eq!(again.imported, 0);
        assert_eq!(again.new_assertions, 0);
        assert_eq!(again.rejected, 0);

        // Replay reproduces the projection.
        b.rebuild_projection().expect("rebuild");
        assert_eq!(
            b.get_assertion(&retired.content_id)
                .expect("get")
                .expect("found")
                .status,
            "retired"
        );
        // Default listing hides retired; --all shows both.
        assert_eq!(b.list_assertions(false).expect("list").len(), 1);
        assert_eq!(b.list_assertions(true).expect("list").len(), 2);
    }

    /// DR-0084 I1: the intent-stamp lookup — active claims by actor resolve
    /// to content ids; released and expired leases drop out; the
    /// ever-claimed gate sees history.
    #[test]
    fn active_claim_subjects_track_the_holder() {
        let mut store = WorkItemStore::open_in_memory().expect("store");
        let issue = store
            .file_item("q", "work", "", &[], &json!({}), Some("s:a"))
            .expect("file");
        assert!(!store.was_ever_claimed(&issue.id).expect("gate"));
        assert!(matches!(
            store.claim_item(&issue.id, "ins-7", None).expect("claim"),
            ClaimOutcome::Claimed
        ));
        let held = store.active_claim_subjects("ins-7").expect("held");
        assert_eq!(held.len(), 1);
        assert_eq!(
            Some(held[0].clone()),
            store.subject_content_id(&issue.id).expect("content id")
        );
        assert!(store.was_ever_claimed(&issue.id).expect("gate"));
        assert!(matches!(
            store
                .release_item(&issue.id, Some("ins-7"))
                .expect("release"),
            ReleaseOutcome::Released
        ));
        assert!(store
            .active_claim_subjects("ins-7")
            .expect("held")
            .is_empty());
        assert!(store.was_ever_claimed(&issue.id).expect("gate"));
    }

    /// DR-0084 Decision 3: anchors bind ledger objects (issues AND
    /// assertions, one alias bridge) to world-denoting regions; removal is
    /// a recorded act; both fold through merge and rebuild.
    #[test]
    fn anchors_bind_merge_and_remove_as_recorded_acts() {
        let mut a = WorkItemStore::open_in_memory().expect("store a");
        let issue = a
            .file_item("q", "close the loop", "", &[], &json!({}), Some("s:a"))
            .expect("file");
        let assertion = a
            .create_assertion("custody verified", "", Some("s:a"))
            .expect("assert");
        let kept = a
            .add_anchor(&issue.id, "decl(rule close)", "subject", Some("s:a"))
            .expect("anchor")
            .expect("issue known");
        let dropped = a
            .add_anchor(&issue.id, "path(scratch/**)", "intent", Some("s:a"))
            .expect("anchor")
            .expect("issue known");
        a.add_anchor(&assertion.id, "path(crates/**)", "subject", Some("s:a"))
            .expect("anchor")
            .expect("assertion known");
        assert!(a
            .remove_anchor(&issue.id, &dropped, Some("s:a"))
            .expect("remove"));
        let current = a.anchors(&issue.id).expect("anchors");
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].id, kept);
        assert_eq!(current[0].role, "subject");
        assert_eq!(a.anchors(&assertion.id).expect("anchors").len(), 1);

        // A second clone folds add + remove to the same current set, and a
        // rebuild reproduces it.
        let mut b = WorkItemStore::open_in_memory().expect("store b");
        b.import_events(&a.export_events().expect("export"))
            .expect("import");
        // B's issue alias is WS-1 (first re-aliased issue).
        let b_anchors = b.anchors("WS-1").expect("anchors");
        assert_eq!(b_anchors.len(), 1);
        assert_eq!(b_anchors[0].region, "decl(rule close)");
        b.rebuild_projection().expect("rebuild");
        assert_eq!(b.anchors("WS-1").expect("anchors").len(), 1);
    }

    /// DR-0084 Decision 3: `attest` records the validity key (at-cut, copied
    /// basis, resolved fingerprint) beside the evidence; unkeyed
    /// `add_evidence` rows stay unkeyed; both merge intact.
    #[test]
    fn attest_records_the_validity_key_and_merges() {
        let mut a = WorkItemStore::open_in_memory().expect("store a");
        let issue = a
            .file_item("q", "verify", "", &[], &json!({}), Some("s:a"))
            .expect("file");
        a.add_evidence(&issue.id, Some("note"), None, Some("unkeyed"), Some("s:a"))
            .expect("evidence");
        let fingerprint = r#"{"decl:rule close":"ab12"}"#;
        a.attest(
            &issue.id,
            Some("test-run"),
            Some("check.sh#123"),
            None,
            Some("s:a"),
            Some("cut_7"),
            Some("decl(rule close)"),
            Some(fingerprint),
        )
        .expect("attest")
        .expect("issue known");

        let rows = a.evidence(&issue.id).expect("evidence");
        assert_eq!(rows.len(), 2);
        let unkeyed = rows
            .iter()
            .find(|row| row.note.as_deref() == Some("unkeyed"))
            .expect("row");
        assert_eq!(unkeyed.at_cut, None);
        let keyed = rows
            .iter()
            .find(|row| row.kind.as_deref() == Some("test-run"))
            .expect("row");
        assert_eq!(keyed.at_cut.as_deref(), Some("cut_7"));
        assert_eq!(keyed.basis.as_deref(), Some("decl(rule close)"));
        assert_eq!(
            keyed
                .basis_fingerprint_json
                .as_deref()
                .and_then(|raw| serde_json::from_str::<Value>(raw).ok()),
            serde_json::from_str::<Value>(fingerprint).ok()
        );

        // The key survives transport and rebuild on a second clone.
        let mut b = WorkItemStore::open_in_memory().expect("store b");
        b.import_events(&a.export_events().expect("export"))
            .expect("import");
        b.rebuild_projection().expect("rebuild");
        let b_rows = b.evidence("WS-1").expect("evidence");
        let b_keyed = b_rows
            .iter()
            .find(|row| row.kind.as_deref() == Some("test-run"))
            .expect("row");
        assert_eq!(b_keyed.at_cut.as_deref(), Some("cut_7"));
        assert!(b_keyed.basis_fingerprint_json.is_some());
    }

    /// `sha256_hex` produces durable content ids: an issue's identity is the
    /// hash of its `issue.created` event, carried in every later event and in
    /// relation payloads, and two clones' logs only union because they agree on
    /// it. So the encoding is a wire format, not an implementation detail — a
    /// changed one would silently re-identify every existing record rather than
    /// fail. These are the published SHA-256 vectors, so the assertion is
    /// against the standard rather than against whatever this build happens to
    /// emit, and it holds across the `sha2` 0.10 to 0.11 move that took
    /// `LowerHex` away from the digest type.
    #[test]
    fn sha256_hex_matches_the_known_empty_vector() {
        assert_eq!(
            sha256_hex(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            sha256_hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_eq!(sha256_hex("abc").len(), 64, "32 bytes as 64 hex digits");
    }

    fn open_memory() -> WorkItemStore {
        WorkItemStore::open(":memory:").expect("opens")
    }

    #[test]
    fn files_items_with_sequential_speakable_ids() {
        let mut store = open_memory();
        let first = store
            .file_item("backlog", "Fix login", "repro...", &[], &json!({}), None)
            .expect("files");
        let second = store
            .file_item(
                "backlog",
                "Fix login",
                "repro...",
                &[],
                &json!({}),
                Some("turn-1"),
            )
            .expect("files");
        assert_eq!(first.id, "WS-1");
        assert_eq!(second.id, "WS-2");
        assert_eq!(second.filed_by.as_deref(), Some("turn-1"));
    }

    /// Reads the raw event log for one issue (given by alias) in append order.
    fn events_for(store: &WorkItemStore, alias: &str) -> Vec<(String, Vec<String>, String)> {
        let content_id = content_id_of(&store.connection, alias).unwrap().unwrap();
        store
            .connection
            .prepare(
                "SELECT event_id, parents_json, kind FROM tracker_events \
                 WHERE issue_id = ?1 ORDER BY event_seq",
            )
            .unwrap()
            .query_map([&content_id], |row| {
                let id: String = row.get(0)?;
                let parents_json: String = row.get(1)?;
                let kind: String = row.get(2)?;
                Ok((id, serde_json::from_str(&parents_json).unwrap(), kind))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// ADR-0002 phase B1 slice i: every tracker event carries a SHA-256
    /// content-hash id, and each new event's parents are the issue's prior
    /// heads — so the log is a hash-chained Merkle-DAG, not a flat list.
    #[test]
    fn events_form_a_content_hash_chain() {
        let mut store = open_memory();
        let filed = store
            .file_item("backlog", "Fix login", "repro", &[], &json!({}), None)
            .expect("files");
        // A second event on the same issue (claim), so we have a chain to check.
        assert_eq!(
            store
                .claim_item(&filed.id, "worker-1", None)
                .expect("claim"),
            ClaimOutcome::Claimed
        );

        let events = events_for(&store, &filed.id);
        assert_eq!(events.len(), 2, "created + claim");

        let (created_id, created_parents, created_kind) = &events[0];
        assert_eq!(created_kind, "issue.created");
        // Content-hash id: 64 lowercase hex chars (SHA-256), not "WS-N".
        assert_eq!(created_id.len(), 64);
        assert!(created_id.chars().all(|c| c.is_ascii_hexdigit()));
        // The issue's root event has no parents.
        assert!(created_parents.is_empty());

        let (claim_id, claim_parents, _) = &events[1];
        assert_eq!(claim_id.len(), 64);
        // The claim event chains onto the created event: it is a child.
        assert_eq!(claim_parents.as_slice(), std::slice::from_ref(created_id));
        assert_ne!(claim_id, created_id);
    }

    /// ADR-0002 phase B1 slice i unit 2: the event log is keyed by the opaque
    /// content_id (merge identity), NOT the clone-local WS-N alias; the alias
    /// table bridges the two. Identity = the creation event's id.
    #[test]
    fn events_are_keyed_by_opaque_content_id_not_alias() {
        let mut store = open_memory();
        let filed = store
            .file_item("backlog", "Fix login", "repro", &[], &json!({}), None)
            .expect("files");
        assert_eq!(filed.id, "WS-1");

        let content_id = content_id_of(&store.connection, "WS-1")
            .unwrap()
            .expect("alias resolves");
        assert_eq!(content_id.len(), 64, "content_id is a SHA-256");

        // No event row carries the WS-N alias; every event's issue_id is the id.
        let alias_rows: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM tracker_events WHERE issue_id = 'WS-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(alias_rows, 0, "no event is keyed by the alias");
        let id_rows: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM tracker_events WHERE issue_id = ?1",
                [&content_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(id_rows, 1, "the created event is keyed by content_id");
        // Identity = the creation event: the created event's id IS the content_id.
        let (created_id, _, _) = &events_for(&store, "WS-1")[0];
        assert_eq!(created_id, &content_id);
    }

    /// A pre-phase-B `tracker_events` (the ADR-0002 v1 linear log, no `event_id`
    /// / `parents_json`) opens without crashing: the schema self-heals the
    /// columns before the unique index, so an old store upgrades in place.
    #[test]
    fn open_self_heals_a_pre_phase_b_event_table() {
        // Own the whole directory so the sqlite file and its `-shm`/`-wal`
        // sidecars all go away when this test ends, panic or not. Removing
        // only the file, only at the start, left one behind on every run.
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let scratch =
            Scratch(std::env::temp_dir().join(format!("whip-tracker-heal-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&scratch.0);
        std::fs::create_dir_all(&scratch.0).unwrap();
        let path = scratch.0.join("items.sqlite");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE tracker_events ( \
                   event_seq INTEGER PRIMARY KEY AUTOINCREMENT, \
                   issue_id TEXT, kind TEXT NOT NULL, \
                   payload_json TEXT NOT NULL DEFAULT '{}', \
                   actor TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);",
            )
            .unwrap();
        }
        // Opening adds the Merkle-DAG columns + index rather than erroring.
        let mut store = WorkItemStore::open(&path).expect("open self-heals old schema");
        let filed = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .expect("files on the healed store");
        assert_eq!(filed.id, "WS-1");
        let _ = std::fs::remove_file(&path);
    }

    /// A rebuild reconstructs the alias-keyed projection from the content_id-keyed
    /// event log via the durable `tracker_aliases` bridge — bit-identical to the
    /// live projection, across issues / field sets / dependencies / claims.
    #[test]
    fn rebuild_reproduces_projection_through_the_alias_bridge() {
        let mut store = open_memory();
        let a = store
            .file_item("q", "A title", "", &[], &json!({}), None)
            .expect("files");
        let b = store
            .file_item("q", "B title", "", &[], &json!({}), None)
            .expect("files");
        store.set_field(&a.id, "title", "A retitled").expect("set");
        store.add_blocks(&b.id, &a.id).expect("dep"); // b blocks a
        store.claim_item(&b.id, "worker-1", None).expect("claim");

        let before = store.get_item(&a.id).unwrap().unwrap();
        let ready_before = store.ready_items("q").unwrap();

        store.rebuild_projection().expect("rebuild");

        let after = store.get_item(&a.id).unwrap().unwrap();
        assert_eq!(after.id, "WS-1");
        assert_eq!(after.title, "A retitled", "field_set folded through");
        assert_eq!(after, before, "projection is bit-identical after rebuild");
        // a is still blocked by open b; b is claimed → neither ready, same as before.
        assert_eq!(
            store.ready_items("q").unwrap().len(),
            ready_before.len(),
            "readiness (deps + leases) reproduced"
        );
        // The dependency edge survived the content_id→alias round-trip.
        let edges: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM tracker_relations WHERE from_issue = ?1 AND to_issue = ?2",
                params![b.id, a.id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(edges, 1, "relation folded back to aliases");
    }

    /// Inserts one event with EXPLICIT parents, bypassing the linear
    /// head-chaining of `tx_append_event`. This is how a test manufactures a
    /// DAG fork — two events sharing a parent — which single-writer appends
    /// never produce (only a merge does). Returns the event's content id.
    fn insert_event(
        store: &WorkItemStore,
        alias: &str,
        kind: &str,
        payload: &Value,
        parents: &[String],
        now: &str,
    ) -> String {
        let content_id = content_id_of(&store.connection, alias).unwrap().unwrap();
        let payload_json = payload.to_string();
        let event_id = event_content_id(kind, Some(&content_id), &payload_json, None, parents, now);
        let parents_json = serde_json::to_string(parents).unwrap();
        store
            .connection
            .execute(
                "INSERT INTO tracker_events \
                 (event_id, parents_json, issue_id, kind, payload_json, actor, created_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6)",
                params![event_id, parents_json, content_id, kind, payload_json, now],
            )
            .unwrap();
        event_id
    }

    fn heads_of(store: &WorkItemStore, id: &str) -> Vec<String> {
        store.issue_conflicts(id).unwrap().unwrap().heads
    }

    /// ADR-0002 phase B1 slice ii, realizing `tracker-merge.maude`. Single
    /// clone: a linear field history has one maximal setter, so it never
    /// conflicts and the issue stays ready.
    /// An alias that names no issue is refused rather than silently resolving to
    /// nothing. These refusals were unexercised until the sweep's widened site
    /// matching (#309) attributed them to a change that threaded a parameter
    /// past them — true of the refusals, not of the change, and pinning them is
    /// the honest response.
    fn conflict_message(error: StoreError) -> String {
        match error {
            StoreError::Conflict(message) => message,
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn a_relation_refuses_an_alias_that_names_no_issue() {
        let mut store = open_memory();
        let real = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .unwrap();

        let from_missing = conflict_message(
            store
                .add_relation("WS-404", &real.id, "blocks", None)
                .expect_err("an unknown `from` is refused"),
        );
        assert!(
            from_missing.contains("unknown issue alias"),
            "got: {from_missing}"
        );

        let to_missing = conflict_message(
            store
                .add_relation(&real.id, "WS-404", "blocks", None)
                .expect_err("an unknown `to` is refused"),
        );
        assert!(
            to_missing.contains("unknown issue alias"),
            "got: {to_missing}"
        );
    }

    #[test]
    fn removing_a_relation_refuses_an_alias_that_names_no_issue() {
        let mut store = open_memory();
        let real = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .unwrap();

        let from_missing = conflict_message(
            store
                .remove_relation("WS-404", &real.id, "blocks")
                .expect_err("an unknown `from` is refused"),
        );
        assert!(
            from_missing.contains("unknown issue alias"),
            "got: {from_missing}"
        );

        let to_missing = conflict_message(
            store
                .remove_relation(&real.id, "WS-404", "blocks")
                .expect_err("an unknown `to` is refused"),
        );
        assert!(
            to_missing.contains("unknown issue alias"),
            "got: {to_missing}"
        );
    }

    #[test]
    fn a_guarded_field_set_refuses_an_issue_whose_alias_does_not_resolve() {
        // Not the same as `NotFound`, which an absent issue returns from the
        // existence check ABOVE this refusal. What this guards is the
        // inconsistent state: a projection row whose alias resolves to nothing,
        // which no ordinary path produces — so the state is constructed here,
        // which is the only way a defensive refusal can be pinned at all.
        let mut store = open_memory();
        let filed = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .unwrap();
        assert_eq!(
            store
                .set_field_checked(&filed.id, "title", "x", "stale-token")
                .expect("a resolvable alias reaches the token check"),
            SetFieldOutcome::StateChanged {
                actual: store
                    .issue_conflicts(&filed.id)
                    .unwrap()
                    .unwrap()
                    .state_token,
            },
            "the guard below is unreachable until the alias mapping is gone"
        );

        store
            .connection
            .execute("DELETE FROM tracker_aliases WHERE alias = ?1", [&filed.id])
            .expect("drop the alias mapping");

        let message = conflict_message(
            store
                .set_field_checked(&filed.id, "title", "x", "stale-token")
                .expect_err("an alias that resolves to nothing is refused"),
        );
        assert!(message.contains("unknown issue alias"), "got: {message}");
    }

    #[test]
    fn a_scoped_effect_is_recorded_on_the_events_it_writes() {
        // G3: `actor` names the instance; this names the EFFECT within it, so
        // "which effect wrote this tracker value" is a join and not a search.
        let mut store = open_memory();
        let filed = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .unwrap();

        store.set_event_effect_id(Some("eff-claim"));
        store.claim_item(&filed.id, "instance-a", None).unwrap();
        store.set_event_effect_id(None);

        let events = store.export_events().unwrap();
        let claim = events
            .iter()
            .find(|event| event.kind == "claim.acquired")
            .expect("claim event");
        assert_eq!(
            store.event_effect_id(&claim.event_id).unwrap().as_deref(),
            Some("eff-claim"),
        );

        // The write BEFORE the scope was opened is not attributed to it. The
        // failure this pins is misattribution, which is worse than recording
        // nothing: a stale scope would name an effect that did not write.
        let created = events
            .iter()
            .find(|event| event.kind == "issue.created")
            .expect("created event");
        assert_eq!(store.event_effect_id(&created.event_id).unwrap(), None);
    }

    #[test]
    fn clearing_the_scope_stops_attributing_later_writes() {
        let mut store = open_memory();
        let filed = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .unwrap();
        store.set_event_effect_id(Some("eff-claim"));
        store.claim_item(&filed.id, "instance-a", None).unwrap();
        store.set_event_effect_id(None);
        store.assign_item(&filed.id, Some("someone")).unwrap();

        let events = store.export_events().unwrap();
        let assigned = events
            .iter()
            .find(|event| event.kind == "issue.assigned")
            .expect("assigned event");
        assert_eq!(
            store.event_effect_id(&assigned.event_id).unwrap(),
            None,
            "a write after the scope closed must not inherit the last effect"
        );
    }

    #[test]
    fn the_effect_id_is_not_part_of_the_event_identity() {
        // Adding it to `event_content_id` would change every event id, break
        // import verification, and retire existing stores. Two events identical
        // but for their writing effect must share an id.
        // `issue.created` overrides its id with the issue's content id, so the
        // check has to use an event that actually DERIVES one.
        let mut store = open_memory();
        store.set_event_effect_id(Some("eff-1"));
        let filed = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .unwrap();
        store.claim_item(&filed.id, "instance-a", None).unwrap();

        let events = store.export_events().unwrap();
        let claim = events
            .iter()
            .find(|event| event.kind == "claim.acquired")
            .expect("claim event");
        let content_id = content_id_of(&store.connection, &filed.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            claim.event_id,
            event_content_id(
                "claim.acquired",
                Some(&content_id),
                &claim.payload_json,
                claim.actor.as_deref(),
                &claim.parents,
                &claim.created_at,
            ),
            "the id is derived from content alone, with no effect in the material"
        );
        assert_eq!(
            store.event_effect_id(&claim.event_id).unwrap().as_deref(),
            Some("eff-1"),
            "recorded alongside the identity, not inside it"
        );
    }

    #[test]
    fn linear_field_history_never_conflicts() {
        let mut store = open_memory();
        let it = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .expect("files");
        assert!(store.set_field(&it.id, "title", "A").expect("set"));
        assert!(store.set_field(&it.id, "title", "B").expect("set"));
        let c = store.issue_conflicts(&it.id).expect("q").expect("exists");
        assert!(!c.conflicted());
        assert_eq!(c.heads.len(), 1, "linear frontier is a single head");
        // The linear last-writer projection column tracks the latest set.
        assert_eq!(store.get_item(&it.id).unwrap().unwrap().title, "B");
        assert_eq!(store.ready_items("q").unwrap().len(), 1);
    }

    /// A fork whose two maximal setters DISAGREE conflicts, is reported per
    /// field with both values, and is no longer ready.
    #[test]
    fn disagreeing_fork_conflicts_and_is_not_ready() {
        let mut store = open_memory();
        let it = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .expect("files");
        let base = heads_of(&store, &it.id);
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "A"}),
            &base,
            "2020-01-01 00:00:01",
        );
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "B"}),
            &base,
            "2020-01-01 00:00:02",
        );
        let c = store.issue_conflicts(&it.id).expect("q").expect("exists");
        assert!(c.conflicted());
        assert_eq!(c.field_conflicts.len(), 1);
        assert_eq!(c.field_conflicts[0].field, "title");
        assert_eq!(c.field_conflicts[0].values, vec!["A", "B"]);
        assert_eq!(c.heads.len(), 2, "the fork has two heads");
        assert!(
            store.ready_items("q").unwrap().is_empty(),
            "a conflicted issue is not ready"
        );
    }

    /// A fork whose two maximal setters AGREE converges: distinct events (they
    /// differ by clock) but one value, so no conflict — and still ready.
    #[test]
    fn agreeing_fork_converges() {
        let mut store = open_memory();
        let it = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .expect("files");
        let base = heads_of(&store, &it.id);
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "A"}),
            &base,
            "2020-01-01 00:00:01",
        );
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "A"}),
            &base,
            "2020-01-01 00:00:02",
        );
        let c = store.issue_conflicts(&it.id).expect("q").expect("exists");
        assert!(!c.conflicted());
        assert_eq!(c.heads.len(), 2);
        assert_eq!(store.ready_items("q").unwrap().len(), 1);
    }

    /// A fork that sets DIFFERENT fields is not a conflict (soundness bite):
    /// each field has a single maximal setter.
    #[test]
    fn different_fields_fork_does_not_conflict() {
        let mut store = open_memory();
        let it = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .expect("files");
        let base = heads_of(&store, &it.id);
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "A"}),
            &base,
            "2020-01-01 00:00:01",
        );
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "body", "value": "X"}),
            &base,
            "2020-01-01 00:00:02",
        );
        let c = store.issue_conflicts(&it.id).expect("q").expect("exists");
        assert!(!c.conflicted());
        assert_eq!(c.heads.len(), 2);
    }

    /// Resolution: an event parented on BOTH conflicting heads supersedes them,
    /// leaving one maximal setter — the conflict clears and the frontier
    /// collapses to the resolver. The `state_token` changes across the resolve.
    #[test]
    fn merge_resolution_clears_conflict() {
        let mut store = open_memory();
        let it = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .expect("files");
        let base = heads_of(&store, &it.id);
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "A"}),
            &base,
            "2020-01-01 00:00:01",
        );
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "B"}),
            &base,
            "2020-01-01 00:00:02",
        );
        let conflicted = store.issue_conflicts(&it.id).unwrap().unwrap();
        assert!(conflicted.conflicted());
        let token_before = conflicted.state_token.clone();

        // Resolve: a single setter descending from both heads.
        let heads = heads_of(&store, &it.id);
        assert_eq!(heads.len(), 2);
        insert_event(
            &store,
            &it.id,
            "issue.field_set",
            &json!({"field": "title", "value": "C"}),
            &heads,
            "2020-01-01 00:00:03",
        );
        let resolved = store.issue_conflicts(&it.id).unwrap().unwrap();
        assert!(!resolved.conflicted(), "resolver supersedes both forks");
        assert_eq!(resolved.heads.len(), 1);
        assert_ne!(resolved.state_token, token_before, "the frontier changed");
    }

    /// ADR-0002 phase B1 slice iii — the real multi-writer scenario (two clones,
    /// one shared workbench). Clone B imports clone A's issue, both edit the SAME
    /// field independently, and a cross-import FORKS the field: the merged clone
    /// sees a genuine conflict with both values. This is what gaugedesk needs.
    #[test]
    fn two_clones_editing_one_issue_merge_to_a_conflict() {
        let mut a = open_memory();
        let mut b = open_memory();

        // A creates the issue; B imports it and re-aliases it locally.
        let issue = a
            .file_item("q", "Shared", "", &[], &json!({}), None)
            .expect("files");
        let report = b.import_events(&a.export_events().unwrap()).unwrap();
        assert_eq!(report.new_issues, 1, "B re-aliased A's issue");
        assert_eq!(report.imported, 1, "just the created event");
        // Both clones happen to name it WS-1 — independent, clone-local aliases.
        let b_alias = "WS-1";
        assert_eq!(b.get_item(b_alias).unwrap().unwrap().title, "Shared");

        // Divergent edits to the SAME field from a shared parent.
        a.set_field(&issue.id, "title", "from-A").expect("set A");
        b.set_field(b_alias, "title", "from-B").expect("set B");

        // Cross-import A's edit into B → the title forks.
        b.import_events(&a.export_events().unwrap()).unwrap();
        let conflicts = b.issue_conflicts(b_alias).unwrap().unwrap();
        assert!(conflicts.conflicted(), "the two writers disagree on title");
        assert_eq!(conflicts.field_conflicts.len(), 1);
        assert_eq!(conflicts.field_conflicts[0].field, "title");
        assert_eq!(
            conflicts.field_conflicts[0].values,
            vec!["from-A", "from-B"]
        );
        assert!(
            b.ready_items("q").unwrap().is_empty(),
            "a conflicted issue is not handed to a worker"
        );
    }

    /// A lifecycle close on one clone concurrent with a `status` set on another
    /// is a real status conflict — `issue.closed` is a status setter, so the
    /// fork is flagged (and kept off the ready queue) rather than folding to an
    /// order-dependent status.
    #[test]
    fn close_vs_concurrent_status_set_is_a_conflict() {
        let mut a = open_memory();
        let mut b = open_memory();
        let issue = a
            .file_item("q", "Shared", "", &[], &json!({}), None)
            .expect("files");
        b.import_events(&a.export_events().unwrap()).unwrap();
        let b_alias = "WS-1";

        // A finishes (issue.closed → status "closed"); B sets status "open" —
        // both chaining off the shared created event.
        a.finish_item(&issue.id, Some("done"), None)
            .expect("finish");
        b.set_field(b_alias, "status", "open").expect("set");

        b.import_events(&a.export_events().unwrap()).unwrap();
        let conflicts = b.issue_conflicts(b_alias).unwrap().unwrap();
        assert!(conflicts.conflicted(), "close vs status-open must conflict");
        assert_eq!(conflicts.field_conflicts[0].field, "status");
        assert_eq!(conflicts.field_conflicts[0].values, vec!["closed", "open"]);
        assert!(
            b.ready_items("q").unwrap().is_empty(),
            "a status-conflicted issue is not handed to a worker"
        );
    }

    /// Agreeing writers converge: two clones set the same value, merge is clean.
    #[test]
    fn two_clones_agreeing_merge_cleanly() {
        let mut a = open_memory();
        let mut b = open_memory();
        let issue = a
            .file_item("q", "Shared", "", &[], &json!({}), None)
            .expect("files");
        b.import_events(&a.export_events().unwrap()).unwrap();
        a.set_field(&issue.id, "status", "closed").expect("set A");
        b.set_field("WS-1", "status", "closed").expect("set B");
        b.import_events(&a.export_events().unwrap()).unwrap();
        let conflicts = b.issue_conflicts("WS-1").unwrap().unwrap();
        assert!(!conflicts.conflicted(), "same value → convergence");
    }

    /// Cross-clone concurrent claims must BOTH survive a merge. Regression:
    /// lease ids were minted from the clone-LOCAL alias (`L-WS-1-0` on both
    /// clones), so the import fold's INSERT OR IGNORE on the `lease_id`
    /// PRIMARY KEY silently destroyed one of the two leases — the losing
    /// holder's own lease vanished from their store, `release` could release
    /// the OTHER actor's lease, and an actively-claimed issue could be handed
    /// out as ready. Lease identity is now the acquire event's content id.
    #[test]
    fn cross_clone_concurrent_claims_survive_merge() {
        let mut a = open_memory();
        let mut b = open_memory();
        let issue = a
            .file_item("q", "Shared", "", &[], &json!({}), None)
            .expect("files");
        b.import_events(&a.export_events().unwrap()).unwrap();

        // Each clone claims its local WS-1; per-store exclusivity cannot see
        // the other clone, so both grants succeed — the double-claim case.
        assert!(matches!(
            a.claim_item(&issue.id, "alice", None).unwrap(),
            ClaimOutcome::Claimed
        ));
        assert!(matches!(
            b.claim_item("WS-1", "bob", None).unwrap(),
            ClaimOutcome::Claimed
        ));

        // Cross-import both ways: the union must carry BOTH leases, live,
        // under distinct ids, on both clones.
        b.import_events(&a.export_events().unwrap()).unwrap();
        a.import_events(&b.export_events().unwrap()).unwrap();
        for (label, store) in [("A", &a), ("B", &b)] {
            let live: Vec<(String, String)> = store
                .connection
                .prepare(
                    "SELECT lease_id, actor FROM tracker_leases \
                     WHERE released_at IS NULL ORDER BY actor",
                )
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let actors: Vec<&str> = live.iter().map(|(_, actor)| actor.as_str()).collect();
            assert_eq!(
                actors,
                vec!["alice", "bob"],
                "clone {label}: both concurrent leases survive the merge"
            );
            assert_ne!(live[0].0, live[1].0, "clone {label}: lease ids distinct");
            assert!(
                store.ready_items("q").unwrap().is_empty(),
                "clone {label}: a claimed issue is never handed out as ready"
            );
            assert_leases_reconcile_with_log(store, label);
        }
    }

    /// DR-0044 formal-verification follow-on (the log-vs-projection
    /// reconciliation invariant): every unreleased `claim.acquired` in the
    /// event log folds to exactly one live lease row, and no `claim.released`/
    /// `claim.expired` lacks its lease. This is the invariant the alias-derived
    /// lease-id collision violated silently — a determinism/convergence sweep
    /// cannot see it (the buggy fold converged identically under every delivery
    /// order to a projection that had simply LOST a row), so it is checked
    /// directly against the log. Content-addressed acquire ids make the count
    /// exact: re-transmitted duplicates share an id (deduped), genuinely
    /// concurrent claims get distinct ids (both survive).
    fn assert_leases_reconcile_with_log(store: &WorkItemStore, label: &str) {
        use std::collections::{HashMap, HashSet};
        let events = store.export_events().expect("export");
        // Net unreleased acquires, keyed by the acquire event's id (= lease_id).
        let mut released: HashSet<String> = HashSet::new();
        for ev in &events {
            if ev.kind == "claim.released" || ev.kind == "claim.expired" {
                let payload: serde_json::Value =
                    serde_json::from_str(&ev.payload_json).unwrap_or_default();
                if let Some(id) = payload.get("lease_id").and_then(serde_json::Value::as_str) {
                    released.insert(id.to_owned());
                }
            }
        }
        let mut expected_live: HashMap<String, String> = HashMap::new();
        for ev in &events {
            if ev.kind == "claim.acquired" {
                let id = ev.event_id.clone();
                if released.contains(&id) {
                    continue;
                }
                let payload: serde_json::Value =
                    serde_json::from_str(&ev.payload_json).unwrap_or_default();
                let actor = payload
                    .get("actor")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                expected_live.insert(id, actor);
            }
        }
        let live: HashMap<String, String> = store
            .connection
            .prepare("SELECT lease_id, actor FROM tracker_leases WHERE released_at IS NULL")
            .unwrap()
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            live, expected_live,
            "clone {label}: live leases must reconcile 1:1 with unreleased \
             claim.acquired events in the log"
        );
    }

    /// ADR-0002 phase B2 (richer model): only `blocks` gates readiness; other
    /// relation kinds are graph metadata. `blocks` carries a dependency kind,
    /// and removal frees the blocked issue. Relations survive rebuild.
    #[test]
    fn relation_kinds_gate_readiness_only_for_blocks() {
        let mut store = open_memory();
        let a = store
            .file_item("q", "A", "", &[], &json!({}), None)
            .expect("files");
        let b = store
            .file_item("q", "B", "", &[], &json!({}), None)
            .expect("files");

        // A non-blocking relation does not affect readiness.
        store
            .add_relation(&a.id, &b.id, "related", None)
            .expect("related");
        assert_eq!(
            store.ready_items("q").unwrap().len(),
            2,
            "related does not block"
        );

        // A dependency (blocks, with a kind) gates the blocked issue.
        store
            .add_relation(&b.id, &a.id, "blocks", Some("resource"))
            .expect("blocks");
        let ready: Vec<String> = store
            .ready_items("q")
            .unwrap()
            .into_iter()
            .map(|i| i.id)
            .collect();
        assert_eq!(ready, vec![b.id.clone()], "a is blocked by b, b is ready");

        // The dep_kind is recorded on the edge.
        let rels = store.relations(&a.id).unwrap();
        let blocks = rels.iter().find(|r| r.kind == "blocks").unwrap();
        assert_eq!(blocks.dep_kind.as_deref(), Some("resource"));

        // Removing the blocks edge frees a; the related edge is untouched.
        assert!(store.remove_relation(&b.id, &a.id, "blocks").unwrap());
        assert_eq!(
            store.ready_items("q").unwrap().len(),
            2,
            "unblocked after removal"
        );
        assert!(
            store
                .relations(&a.id)
                .unwrap()
                .iter()
                .any(|r| r.kind == "related"),
            "the metadata relation survives"
        );

        // Rebuild reproduces the surviving relation set (added then removed nets out).
        store.rebuild_projection().unwrap();
        let after = store.relations(&a.id).unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].kind, "related");

        // Validation: unknown kinds and misplaced dep_kind are rejected.
        assert!(store.add_relation(&a.id, &b.id, "bogus", None).is_err());
        assert!(store
            .add_relation(&a.id, &b.id, "related", Some("hard"))
            .is_err());
    }

    /// ADR-0002 phase B2 cross-machine transport: two clones reconcile by
    /// sharing a directory of content-addressed event files. After both
    /// `sync_dir` the same dir, divergent field edits surface as a conflict in
    /// BOTH — the drop-a-folder multi-writer exchange.
    #[test]
    fn dir_sync_reconciles_two_clones() {
        let dir = std::env::temp_dir().join(format!("whip-tracker-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut a = open_memory();
        let mut b = open_memory();
        let issue = a
            .file_item("q", "Shared", "", &[], &json!({}), None)
            .expect("files");

        // Seed B with A's issue through the shared directory.
        a.export_to_dir(&dir).expect("export");
        let report = b.import_from_dir(&dir).expect("import");
        assert_eq!(report.new_issues, 1);
        assert_eq!(b.get_item("WS-1").unwrap().unwrap().title, "Shared");

        // Divergent edits, then both sync against the shared dir.
        a.set_field(&issue.id, "title", "A version").expect("set A");
        b.set_field("WS-1", "title", "B version").expect("set B");
        a.sync_dir(&dir).expect("sync a");
        b.sync_dir(&dir).expect("sync b"); // b now sees A's edit → forks
        a.sync_dir(&dir).expect("sync a2"); // a now sees B's edit → forks

        for (name, store) in [("a", &a), ("b", &b)] {
            let c = store.issue_conflicts("WS-1").unwrap().unwrap();
            assert!(c.conflicted(), "{name} sees the conflict after sync");
            assert_eq!(c.field_conflicts[0].values, vec!["A version", "B version"]);
            // Content-addressed heads: both clones agree on the frontier.
            assert_eq!(c.heads.len(), 2);
        }
        // Both frontiers are byte-identical — true convergence, not just "both
        // conflicted": the state_token is a content hash of the shared heads.
        assert_eq!(
            a.issue_conflicts("WS-1").unwrap().unwrap().state_token,
            b.issue_conflicts("WS-1").unwrap().unwrap().state_token
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-0002 phase B2: comments and evidence attach to an issue, survive a
    /// rebuild, and fold exactly once through a merge (keyed by content hash).
    #[test]
    fn comments_and_evidence_attach_and_merge_once() {
        let mut a = open_memory();
        let issue = a
            .file_item("q", "Task", "", &[], &json!({}), None)
            .expect("files");
        a.add_comment(&issue.id, Some("worker-1"), "looks done")
            .expect("comment");
        a.add_evidence(
            &issue.id,
            Some("log"),
            Some("s3://run/42.log"),
            Some("green"),
            Some("worker-1"),
        )
        .expect("evidence");

        let comments = a.comments(&issue.id).unwrap();
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0].body, "looks done");
        assert_eq!(comments[0].author.as_deref(), Some("worker-1"));
        let evidence = a.evidence(&issue.id).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].reference.as_deref(), Some("s3://run/42.log"));

        // Survive a rebuild.
        a.rebuild_projection().unwrap();
        assert_eq!(a.comments(&issue.id).unwrap().len(), 1);
        assert_eq!(a.evidence(&issue.id).unwrap().len(), 1);

        // Merge into a second clone: the comment + evidence fold exactly once,
        // and a re-import does not duplicate them.
        let mut b = open_memory();
        b.import_events(&a.export_events().unwrap()).unwrap();
        assert_eq!(b.comments("WS-1").unwrap().len(), 1, "comment merged once");
        assert_eq!(b.evidence("WS-1").unwrap().len(), 1, "evidence merged once");
        b.import_events(&a.export_events().unwrap()).unwrap();
        assert_eq!(
            b.comments("WS-1").unwrap().len(),
            1,
            "re-import does not dup"
        );
    }

    /// Re-importing the same log is idempotent and SILENT: byte-identical events
    /// are re-transmits (same content id), deduped without a duplicate warning —
    /// this is the normal cross-machine re-sync, and it must not spam.
    #[test]
    fn reimport_is_a_silent_idempotent_resync() {
        let mut a = open_memory();
        let mut b = open_memory();
        a.file_item("q", "One", "", &[], &json!({}), None)
            .expect("files");
        a.file_item("q", "Two", "", &[], &json!({}), None)
            .expect("files");
        let events = a.export_events().unwrap();

        let first = b.import_events(&events).unwrap();
        assert_eq!(first.imported, 2);
        assert_eq!(first.new_issues, 2);
        assert!(first.duplicate_submissions.is_empty());

        let second = b.import_events(&events).unwrap();
        assert_eq!(second.imported, 0, "nothing new on re-import");
        assert_eq!(second.new_issues, 0, "no re-aliasing");
        assert_eq!(second.skipped, 2, "both events deduped as re-transmits");
        assert!(
            second.duplicate_submissions.is_empty(),
            "a re-transmit is NOT a duplicate submission — re-sync stays quiet"
        );
        assert_eq!(b.list_items(Some("q"), None).unwrap().len(), 2);
    }

    /// Two clones holding the byte-identical event set must project the SAME
    /// field value regardless of import order. A linear title history
    /// orig→A→B is folded TOPOLOGICALLY, so a non-causal import order can no
    /// longer drop edits or leave clones disagreeing. (Pre-fix bug: folding by
    /// insertion order projected "orig" in one order and "B" in another.)
    #[test]
    fn projection_converges_across_import_orders() {
        let mut source = open_memory();
        let it = source
            .file_item("q", "orig", "", &[], &json!({}), None)
            .expect("file");
        source.set_field(&it.id, "title", "A").expect("set A");
        source.set_field(&it.id, "title", "B").expect("set B");
        let events = source.export_events().unwrap();
        assert_eq!(source.get_item(&it.id).unwrap().unwrap().title, "B");

        let title_after = |order: &[TrackerEvent]| {
            let mut clone = open_memory();
            clone.import_events(order).unwrap();
            let alias = clone.list_items(Some("q"), None).unwrap()[0].id.clone();
            clone.get_item(&alias).unwrap().unwrap().title
        };
        let mut asc = events.clone();
        asc.sort_by(|a, b| a.event_id.cmp(&b.event_id));
        let mut desc = events.clone();
        desc.sort_by(|a, b| b.event_id.cmp(&a.event_id));
        assert_eq!(title_after(&asc), "B", "ascending import must project B");
        assert_eq!(title_after(&desc), "B", "descending import must project B");
    }

    /// A genuine duplicate submission — two clones independently FILE the same
    /// issue (same queue + title) — mints two distinct content ids. Merging them
    /// surfaces the second as a duplicate_submission warning (advisory; a human
    /// reconciles via a `duplicates` relation), never a silent collapse.
    /// A tampered event (payload mutated but the id kept, or an id that collides
    /// with an honest event) is REJECTED on import, not folded — the content-
    /// addressed integrity the shared-folder transport claims. Also proves an
    /// id-collision cannot SUPPRESS the honest event.
    #[test]
    fn import_rejects_events_whose_id_does_not_match_their_content() {
        let mut a = open_memory();
        let it = a
            .file_item("q", "Original", "", &[], &json!({}), Some("ann"))
            .expect("files");
        a.set_field(&it.id, "title", "Legit").expect("set");
        let events = a.export_events().unwrap();

        // Tamper: keep a field_set event's id + parents, mutate its payload to a
        // hostile value (a forger rewriting the title under a valid-looking id).
        let mut tampered = events.clone();
        let victim = tampered
            .iter_mut()
            .find(|e| e.kind == "issue.field_set")
            .expect("a field_set event");
        victim.payload_json = victim.payload_json.replace("Legit", "Hijacked");

        let mut b = open_memory();
        let report = b.import_events(&tampered).unwrap();
        assert!(report.rejected >= 1, "the tampered event must be rejected");
        // The honest events still import; the hijacked value never lands.
        let alias = b.list_items(Some("q"), None).unwrap()[0].id.clone();
        assert_eq!(b.get_item(&alias).unwrap().unwrap().title, "Original");

        // A created event whose id does not equal its issue identity is rejected.
        let mut forged = a.export_events().unwrap();
        let created = forged
            .iter_mut()
            .find(|e| e.kind == "issue.created")
            .expect("created");
        created.issue_id = Some("WS-forged-identity".to_owned());
        let mut c = open_memory();
        let report = c.import_events(std::slice::from_ref(created)).unwrap();
        assert_eq!(report.rejected, 1);
        assert_eq!(report.imported, 0);
    }

    #[test]
    fn independent_same_issue_submissions_warn_as_duplicates() {
        let mut a = open_memory();
        let mut b = open_memory();
        // Two clones each file "Fix login" into queue q — same work, filed twice.
        a.file_item("q", "Fix login", "", &[], &json!({}), Some("ann"))
            .expect("files");
        b.file_item("q", "Fix login", "", &[], &json!({}), Some("bob"))
            .expect("files");
        let a_events = a.export_events().unwrap();
        let b_events = b.export_events().unwrap();
        // Distinct content ids — independent submissions are not the same event.
        assert_ne!(a_events[0].event_id, b_events[0].event_id);

        // A pulls in B's independent submission of the same issue.
        let report = a.import_events(&b_events).unwrap();
        assert_eq!(report.imported, 1);
        assert_eq!(report.new_issues, 1);
        assert_eq!(
            report.duplicate_submissions.len(),
            1,
            "B's independent submission duplicates the one A already had"
        );
        // Both issues survive — advisory warning, never a silent collapse.
        assert_eq!(a.list_items(Some("q"), None).unwrap().len(), 2);
        // A different title in the same queue is NOT flagged.
        let mut c = open_memory();
        c.file_item("q", "Other work", "", &[], &json!({}), None)
            .expect("files");
        let clean = c.import_events(&a_events).unwrap();
        assert!(clean.duplicate_submissions.is_empty());
    }

    /// ADR-0002 phase B1 slice v: an optimistic set applies against the current
    /// state token, moves the token, and refuses a stale token — reporting the
    /// actual one to retry against, without overwriting the intervening change.
    #[test]
    fn optimistic_set_guards_on_state_token() {
        let mut store = open_memory();
        let it = store
            .file_item("q", "t", "", &[], &json!({}), None)
            .expect("files");
        let token0 = store.issue_conflicts(&it.id).unwrap().unwrap().state_token;

        // A fresh token applies and returns the new frontier token.
        let token1 = match store
            .set_field_checked(&it.id, "title", "A", &token0)
            .expect("set")
        {
            SetFieldOutcome::Applied { state_token } => {
                assert_ne!(state_token, token0);
                state_token
            }
            other => panic!("expected Applied, got {other:?}"),
        };

        // Re-using the stale token0 is refused with the current actual token1.
        match store
            .set_field_checked(&it.id, "title", "B", &token0)
            .expect("set")
        {
            SetFieldOutcome::StateChanged { actual } => assert_eq!(actual, token1),
            other => panic!("expected StateChanged, got {other:?}"),
        }
        // The refused set did not apply: the linear column is still "A".
        assert_eq!(store.get_item(&it.id).unwrap().unwrap().title, "A");

        // A missing issue reports NotFound, not a false token mismatch.
        assert_eq!(
            store
                .set_field_checked("WS-999", "title", "Z", &token0)
                .unwrap(),
            SetFieldOutcome::NotFound
        );
    }

    /// Drive the store through the `WorkItems` trait as a `dyn` object: proves
    /// the seam is object-safe (a boxed durable-object backend is legal) and
    /// forwards faithfully to the inherent methods.
    #[test]
    fn work_items_trait_seam_is_faithful() {
        let mut store = open_memory();
        let items: &mut dyn WorkItems = &mut store;

        let filed = items
            .file_item(
                "backlog",
                "Fix login",
                "repro",
                &[],
                &json!({}),
                Some("turn-1"),
            )
            .expect("file");
        assert_eq!(filed.id, "WS-1");
        assert_eq!(items.ready_items("backlog").expect("ready").len(), 1);
        assert_eq!(
            items
                .claim_item(&filed.id, "worker-1", None)
                .expect("claim"),
            ClaimOutcome::Claimed
        );
        assert!(items.ready_items("backlog").expect("ready").is_empty());
        let fetched = items.get_item(&filed.id).expect("get").expect("present");
        // The lease overlay presents the claimed issue as in_progress by holder.
        assert_eq!(fetched.status, "in_progress");
        assert_eq!(fetched.claimed_by.as_deref(), Some("worker-1"));
        assert_eq!(
            items
                .release_claims_for_holder("worker-1")
                .expect("release"),
            1
        );
        assert_eq!(
            items
                .finish_item(&filed.id, Some("done"), None)
                .expect("finish"),
            FinishOutcome::Finished
        );
        assert_eq!(
            items
                .list_items(Some("backlog"), Some("closed"))
                .expect("list")
                .len(),
            1
        );
    }

    #[test]
    fn ready_means_open_and_unclaimed() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(store.ready_items("backlog").expect("ready").len(), 1);
        assert_eq!(
            store
                .claim_item(&item.id, "worker-1", None)
                .expect("claims"),
            ClaimOutcome::Claimed
        );
        assert!(store.ready_items("backlog").expect("ready").is_empty());
    }

    #[test]
    fn double_claim_is_branchable_not_an_error() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(
            store
                .claim_item(&item.id, "worker-1", None)
                .expect("claims"),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            store
                .claim_item(&item.id, "worker-2", None)
                .expect("claims"),
            ClaimOutcome::AlreadyClaimed {
                holder: "worker-1".to_owned()
            }
        );
    }

    /// An issue files unassigned, which is the "whoever has access" case and
    /// must stay expressible — assignment is optional, not a required field
    /// callers work around.
    #[test]
    fn an_issue_files_unassigned() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(item.assigned_to, None);
        assert_eq!(
            store.get_item(&item.id).expect("gets").unwrap().assigned_to,
            None
        );
    }

    #[test]
    fn assignment_round_trips_and_clears() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert!(store.assign_item(&item.id, Some("alice")).expect("assigns"));
        assert_eq!(
            store.get_item(&item.id).expect("gets").unwrap().assigned_to,
            Some("alice".to_owned())
        );
        // Reassignment is ordinary; so is clearing back to "anyone".
        assert!(store.assign_item(&item.id, Some("bob")).expect("reassigns"));
        assert_eq!(
            store.get_item(&item.id).expect("gets").unwrap().assigned_to,
            Some("bob".to_owned())
        );
        assert!(store.assign_item(&item.id, None).expect("clears"));
        assert_eq!(
            store.get_item(&item.id).expect("gets").unwrap().assigned_to,
            None
        );
    }

    /// Assignment is advisory: it says who *should* act and never restricts who
    /// *may* claim. Enforcing it here would require an authority model this
    /// crate deliberately does not have.
    #[test]
    fn assignment_does_not_restrict_who_may_claim() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store.assign_item(&item.id, Some("alice")).expect("assigns");
        assert!(matches!(
            store.claim_item(&item.id, "bob", None).expect("claims"),
            ClaimOutcome::Claimed
        ));
        let held = store.get_item(&item.id).expect("gets").unwrap();
        assert_eq!(held.assigned_to, Some("alice".to_owned()));
        assert_eq!(held.claimed_by, Some("bob".to_owned()));
    }

    /// Assignment and claim are different facts and must not collapse into one
    /// another: an assigned issue is still unclaimed until someone claims it.
    #[test]
    fn assigning_does_not_claim() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store.assign_item(&item.id, Some("alice")).expect("assigns");
        let held = store.get_item(&item.id).expect("gets").unwrap();
        assert_eq!(held.claimed_by, None);
        assert_eq!(held.status, "open");
        assert_eq!(store.ready_items("backlog").expect("ready").len(), 1);
    }

    #[test]
    fn a_closed_issue_is_not_reassigned() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store
            .finish_item(&item.id, Some("done"), None)
            .expect("finishes");
        assert!(
            !store.assign_item(&item.id, Some("alice")).expect("no-op"),
            "reassigning a closed issue must be a no-op, not a silent rewrite",
        );
        assert_eq!(
            store.get_item(&item.id).expect("gets").unwrap().assigned_to,
            None
        );
    }

    #[test]
    fn assigning_an_unknown_issue_is_a_no_op() {
        let mut store = open_memory();
        assert!(!store.assign_item("WS-404", Some("alice")).expect("no-op"));
    }

    /// The column self-heals onto a database written before 0.2.2, so an
    /// existing tracker keeps working rather than failing to open.
    #[test]
    fn a_pre_assignment_database_self_heals() {
        let path = std::env::temp_dir().join(format!(
            "whip-tracker-selfheal-{}-{:?}.sqlite",
            std::process::id(),
            std::thread::current().id(),
        ));
        let _ = std::fs::remove_file(&path);
        {
            // A pre-0.2.2 shape: the issues table without `assigned_to`.
            let conn = Connection::open(&path).expect("opens");
            conn.execute_batch(
                "CREATE TABLE tracker_issues (
                    issue_id TEXT PRIMARY KEY,
                    queue TEXT NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    labels_json TEXT NOT NULL DEFAULT '[]',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    claim_summary TEXT,
                    filed_by TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE tracker_aliases (
                    content_id TEXT PRIMARY KEY,
                    alias TEXT NOT NULL UNIQUE
                );
                INSERT INTO tracker_issues (issue_id, queue, title)
                VALUES ('WS-1', 'backlog', 'existing');
                INSERT INTO tracker_aliases (content_id, alias)
                VALUES ('content-ws-1', 'WS-1');",
            )
            .expect("seeds the old shape");
        }
        let mut store = WorkItemStore::open(&path).expect("opens and self-heals");
        let existing = store.get_item("WS-1").expect("gets").expect("present");
        assert_eq!(existing.assigned_to, None, "an old row reads as unassigned");
        assert!(store.assign_item("WS-1", Some("alice")).expect("assigns"));
        assert_eq!(
            store.get_item("WS-1").expect("gets").unwrap().assigned_to,
            Some("alice".to_owned())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn release_returns_item_to_ready() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store.claim_item(&item.id, "w", None).expect("claims");
        assert_eq!(
            store.release_item(&item.id, None).expect("releases"),
            ReleaseOutcome::Released
        );
        assert_eq!(store.ready_items("backlog").expect("ready").len(), 1);
    }

    /// The compiler refuses a `status` comparison outside `WORK_ITEM_STATUSES`,
    /// so a status this store can produce and that set omits would make a real
    /// item unmatchable by any rule. Compared as SETS: the order differs
    /// deliberately (the union reads as the lifecycle, this list as the events
    /// that write it) and order is not the property under test.
    #[test]
    fn every_status_this_store_produces_is_one_the_compiler_admits() {
        use std::collections::BTreeSet;
        let admitted: BTreeSet<&str> = whipplescript_core::WORK_ITEM_STATUSES
            .iter()
            .copied()
            .collect();
        let produced: BTreeSet<&str> = STORE_PRODUCED_STATUSES.iter().copied().collect();
        assert_eq!(
            produced.difference(&admitted).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "the store produces a status no program can compare against"
        );
        assert_eq!(
            admitted.difference(&produced).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "the union admits a status nothing produces; drop it or say why"
        );
    }

    /// DR-0088: the count a rework loop's termination measure rests on. The
    /// compiler reads `where issue.releases < 3` as a proof that the ring stops,
    /// so three properties are load-bearing rather than cosmetic: it starts at
    /// zero, it rises by exactly one per return, and it survives a rebuild —
    /// the projection is disposable, so a count only the projection knew would
    /// come back as zero and the loop would run again from the top.
    #[test]
    fn releases_counts_every_return_to_ready_and_survives_a_rebuild() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(
            store.get_item(&item.id).expect("gets").unwrap().releases,
            0,
            "a filed item has not been handed back"
        );

        for expected in 1..=3 {
            store.claim_item(&item.id, "w", None).expect("claims");
            store.release_item(&item.id, None).expect("releases");
            assert_eq!(
                store.get_item(&item.id).expect("gets").unwrap().releases,
                expected
            );
        }

        // A claim that is never released does not count: the measure advances on
        // the return, and an item still held has not come back.
        store.claim_item(&item.id, "w", None).expect("claims");
        assert_eq!(store.get_item(&item.id).expect("gets").unwrap().releases, 3);
        store.release_item(&item.id, None).expect("releases");

        store.rebuild_projection().expect("rebuilds");
        assert_eq!(
            store.get_item(&item.id).expect("gets").unwrap().releases,
            4,
            "the count is derived from the event log, not held only in the projection"
        );
    }

    /// Claim atomicity (`tracker-lease.maude` I1, exclusivity, deterministic
    /// form): across many items and many contenders, every item is claimed by
    /// exactly one worker and the rest see `AlreadyClaimed`.
    #[test]
    fn claim_atomicity_no_double_claim() {
        let mut store = open_memory();
        let mut ids = Vec::new();
        for index in 0..20 {
            let item = store
                .file_item(
                    "backlog",
                    &format!("item-{index}"),
                    "",
                    &[],
                    &json!({}),
                    None,
                )
                .expect("files");
            ids.push(item.id);
        }
        for id in &ids {
            let mut claimed = 0;
            let mut already = 0;
            for worker in 0..5 {
                match store
                    .claim_item(id, &format!("worker-{worker}"), None)
                    .expect("claims")
                {
                    ClaimOutcome::Claimed => claimed += 1,
                    ClaimOutcome::AlreadyClaimed { .. } => already += 1,
                    ClaimOutcome::NotFound => panic!("item vanished"),
                }
            }
            assert_eq!(claimed, 1, "exactly one worker claims {id}");
            assert_eq!(already, 4, "the rest see already-claimed for {id}");
        }
        // Every item is now leased; none remain ready.
        assert!(store.ready_items("backlog").expect("ready").is_empty());
    }

    /// Release/claim cycles preserve the invariant: a released item is
    /// re-claimable exactly once again.
    #[test]
    fn release_then_reclaim_preserves_single_holder() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(
            store.claim_item(&item.id, "w1", None).expect("claims"),
            ClaimOutcome::Claimed
        );
        assert_eq!(
            store.release_item(&item.id, None).expect("releases"),
            ReleaseOutcome::Released
        );
        let mut claimed = 0;
        for worker in 0..3 {
            if let ClaimOutcome::Claimed = store
                .claim_item(&item.id, &format!("w{worker}"), None)
                .expect("claims")
            {
                claimed += 1;
            }
        }
        assert_eq!(claimed, 1);
    }

    /// Terminal-releases-all (`tracker-lease.maude` I3): a terminal holder drops
    /// only its OWN active leases (issue returns to ready), leaving other
    /// holders' leases untouched.
    #[test]
    fn release_claims_for_holder_frees_only_that_holders_in_progress_items() {
        let mut store = open_memory();
        let mine = store
            .file_item("backlog", "mine", "", &[], &json!({}), None)
            .expect("files");
        let theirs = store
            .file_item("backlog", "theirs", "", &[], &json!({}), None)
            .expect("files");
        store.claim_item(&mine.id, "w1", None).expect("claims mine");
        store
            .claim_item(&theirs.id, "w2", None)
            .expect("claims theirs");

        assert_eq!(
            store.release_claims_for_holder("w1").expect("releases"),
            1,
            "exactly w1's one active lease is released"
        );

        let mine = store.get_item(&mine.id).expect("gets").expect("exists");
        assert_eq!(mine.status, "open");
        assert!(mine.claimed_by.is_none());
        let theirs = store.get_item(&theirs.id).expect("gets").expect("exists");
        assert_eq!(theirs.status, "in_progress", "w2's lease is untouched");
        assert_eq!(theirs.claimed_by.as_deref(), Some("w2"));

        // The released item is claimable again; a holder with nothing held is a
        // no-op (e.g. an instance that already `finish`ed everything).
        assert_eq!(
            store.claim_item(&mine.id, "w3", None).expect("reclaims"),
            ClaimOutcome::Claimed
        );
        assert_eq!(store.release_claims_for_holder("w1").expect("noop"), 0);
    }

    #[test]
    fn finish_records_summary_and_leaves_done() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store.claim_item(&item.id, "w", None).expect("claims");
        assert_eq!(
            store
                .finish_item(&item.id, Some("done by agent"), None)
                .expect("finishes"),
            FinishOutcome::Finished
        );
        let item = store.get_item(&item.id).expect("gets").expect("exists");
        assert_eq!(item.status, "closed");
        assert!(store.ready_items("backlog").expect("ready").is_empty());
    }

    /// Holder-only + monotonic renew (`tracker-lease.maude` I2). A non-holder
    /// cannot renew; a finite deadline may only move forward.
    #[test]
    fn renew_is_holder_only_and_monotonic() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store.claim_item(&item.id, "w1", None).expect("claims");

        // Non-holder cannot renew.
        assert_eq!(
            store.renew_claim(&item.id, "w2", None).expect("renew"),
            RenewOutcome::NotHeld
        );
        // Holder sets a first finite deadline (NULL -> finite is allowed).
        assert!(matches!(
            store
                .renew_claim(&item.id, "w1", Some("2099-01-01 00:00:00"))
                .expect("renew"),
            RenewOutcome::Renewed { .. }
        ));
        // Forward move is accepted.
        assert!(matches!(
            store
                .renew_claim(&item.id, "w1", Some("2099-06-01 00:00:00"))
                .expect("renew"),
            RenewOutcome::Renewed { .. }
        ));
        // Backward move is rejected (non-monotonic).
        assert_eq!(
            store
                .renew_claim(&item.id, "w1", Some("2099-03-01 00:00:00"))
                .expect("renew"),
            RenewOutcome::NotMonotonic
        );
    }

    /// Claim TTL (T3): a finite absolute `expires` records a timed lease that
    /// blocks readiness while in the future and stops blocking once past-due —
    /// `tracker-lease.maude` I4 (holder-only release). Before the precondition
    /// existed, both of these silently succeeded: `release_item` took no holder
    /// at all and `finish_item` released whatever lease it found, so a stale
    /// agent could unclaim or close live work and both agents would proceed
    /// believing they owned the item.
    #[test]
    fn a_non_holder_cannot_release_or_finish_a_held_item() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(
            store.claim_item(&item.id, "agent:a", None).expect("claims"),
            ClaimOutcome::Claimed
        );

        // The refusal names the holder: a caller that cannot say who has the
        // item hands the model nothing it can act on.
        assert_eq!(
            store
                .release_item(&item.id, Some("agent:b"))
                .expect("release refused"),
            ReleaseOutcome::HeldByOther {
                holder: "agent:a".to_string()
            }
        );
        assert_eq!(
            store
                .finish_item(&item.id, None, Some("agent:b"))
                .expect("finish refused"),
            FinishOutcome::HeldByOther {
                holder: "agent:a".to_string()
            }
        );

        // Refused means UNCHANGED, not merely reported: the lease still stands
        // and the issue is still open. A refusal that already did the damage is
        // not a refusal.
        let after = store.get_item(&item.id).expect("gets").expect("exists");
        assert_eq!(after.status, "in_progress");
        assert_eq!(after.claimed_by.as_deref(), Some("agent:a"));

        // The holder itself is unaffected by the precondition.
        assert_eq!(
            store
                .release_item(&item.id, Some("agent:a"))
                .expect("holder releases"),
            ReleaseOutcome::Released
        );
    }

    /// The precondition guards against clobbering ANOTHER actor, not against
    /// acting on an unclaimed item — so an item with no lease stays workable,
    /// and releasing nothing stays an idempotent success rather than an error.
    #[test]
    fn an_unheld_item_is_not_a_holder_conflict() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(
            store
                .release_item(&item.id, Some("agent:b"))
                .expect("release of an unheld item"),
            ReleaseOutcome::NotHeld
        );
        assert_eq!(
            store
                .finish_item(&item.id, None, Some("agent:b"))
                .expect("finish of an unheld item"),
            FinishOutcome::Finished
        );
    }

    /// `None` is the operator escape hatch (`whip issue release`, `fail`) and
    /// the in-program `release` effect. It must keep clearing a lease the
    /// caller does not hold, or a stuck lease becomes unrecoverable.
    #[test]
    fn an_unscoped_release_still_clears_another_actors_lease() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store.claim_item(&item.id, "agent:a", None).expect("claims");
        assert_eq!(
            store
                .release_item(&item.id, None)
                .expect("operator release"),
            ReleaseOutcome::Released
        );
    }

    /// A subscription starts at the CURRENT head, so subscribing does not
    /// replay a queue's history into the subscriber's context.
    #[test]
    fn subscribing_starts_at_the_head_and_delivers_only_what_follows() {
        let mut store = open_memory();
        let before = store
            .file_item("backlog", "already here", "", &[], &json!({}), None)
            .expect("files");
        assert!(store
            .subscribe_events("agent:a", "backlog")
            .expect("subscribes"));

        // Nothing yet: the pre-existing issue's events are behind the cursor.
        assert!(store
            .poll_subscribed_events("agent:a", 50)
            .expect("poll")
            .is_empty());

        store
            .claim_item(&before.id, "agent:b", None)
            .expect("claim");
        let events = store.poll_subscribed_events("agent:a", 50).expect("poll");
        assert!(
            events
                .iter()
                .any(|e| e.kind == "claim.acquired" && e.actor.as_deref() == Some("agent:b")),
            "{events:?}"
        );

        // Polling does not advance; the same events are still pending.
        let again = store.poll_subscribed_events("agent:a", 50).expect("poll");
        assert_eq!(again.len(), events.len());

        // Advancing consumes them.
        let last = events.iter().map(|e| e.position).max().expect("position");
        store
            .advance_subscription("agent:a", "backlog", last)
            .expect("advance");
        assert!(store
            .poll_subscribed_events("agent:a", 50)
            .expect("poll")
            .is_empty());
    }

    /// Re-subscribing must not rewind a live cursor, or every re-subscribe
    /// would redeliver everything the subscriber already saw.
    #[test]
    fn resubscribing_does_not_rewind_and_a_stale_advance_does_not_redeliver() {
        let mut store = open_memory();
        assert!(store
            .subscribe_events("agent:a", "backlog")
            .expect("subscribes"));
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        let events = store.poll_subscribed_events("agent:a", 50).expect("poll");
        let last = events.iter().map(|e| e.position).max().expect("position");
        store
            .advance_subscription("agent:a", "backlog", last)
            .expect("advance");

        // Re-subscribe: reports "already subscribed" and leaves the cursor put.
        assert!(!store
            .subscribe_events("agent:a", "backlog")
            .expect("resubscribes"));
        assert!(store
            .poll_subscribed_events("agent:a", 50)
            .expect("poll")
            .is_empty());

        // A stale advance is a no-op, never a rewind.
        store
            .advance_subscription("agent:a", "backlog", 0)
            .expect("stale advance");
        assert!(store
            .poll_subscribed_events("agent:a", 50)
            .expect("poll")
            .is_empty());

        // A queue nobody subscribed to delivers nothing.
        store
            .file_item("other", "elsewhere", "", &[], &json!({}), None)
            .expect("files");
        store.claim_item(&item.id, "agent:b", None).expect("claim");
        let events = store.poll_subscribed_events("agent:a", 50).expect("poll");
        assert!(events.iter().all(|e| e.queue == "backlog"), "{events:?}");

        assert!(store
            .unsubscribe_events("agent:a", "backlog")
            .expect("unsubscribes"));
        assert!(store
            .poll_subscribed_events("agent:a", 50)
            .expect("poll")
            .is_empty());
    }

    /// so a claim in the past is expired-on-arrival and never blocks.
    #[test]
    fn claim_with_ttl_records_a_finite_expiry() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        // A far-future TTL: the claim is held, so the issue is not ready.
        assert_eq!(
            store
                .claim_item(&item.id, "w1", Some("2099-01-01 00:00:00"))
                .expect("claims"),
            ClaimOutcome::Claimed
        );
        assert!(store.ready_items("backlog").expect("ready").is_empty());
        let held = store.get_item(&item.id).expect("gets").expect("exists");
        assert_eq!(held.status, "in_progress");
        assert_eq!(held.claimed_by.as_deref(), Some("w1"));
        // A different worker cannot claim the still-live timed lease.
        assert!(matches!(
            store
                .claim_item(&item.id, "w2", None)
                .expect("contended claim"),
            ClaimOutcome::AlreadyClaimed { .. }
        ));
        // A past TTL is expired-on-arrival: it never blocks readiness, and the
        // lazy expiry sweep lets a fresh claim win.
        let stale = store
            .file_item("backlog", "b", "", &[], &json!({}), None)
            .expect("files");
        assert_eq!(
            store
                .claim_item(&stale.id, "w1", Some("2000-01-01 00:00:00"))
                .expect("claims"),
            ClaimOutcome::Claimed
        );
        let ready: Vec<String> = store
            .ready_items("backlog")
            .expect("ready")
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert!(
            ready.contains(&stale.id),
            "expired claim does not block: {ready:?}"
        );
        assert_eq!(
            store.claim_item(&stale.id, "w2", None).expect("reclaims"),
            ClaimOutcome::Claimed
        );
    }

    /// An expired lease frees the issue for a fresh claim and lets it be ready
    /// again (`tracker-lease.maude`: expired leases do not block).
    #[test]
    fn expired_lease_frees_the_issue() {
        let mut store = open_memory();
        let item = store
            .file_item("backlog", "a", "", &[], &json!({}), None)
            .expect("files");
        store.claim_item(&item.id, "w1", None).expect("claims");
        // Set the holder's own lease to a past deadline (NULL -> finite is
        // allowed for the holder), so it is now expired.
        assert!(matches!(
            store
                .renew_claim(&item.id, "w1", Some("2000-01-01 00:00:00"))
                .expect("renew"),
            RenewOutcome::Renewed { .. }
        ));
        // Expired lease no longer blocks readiness.
        assert_eq!(store.ready_items("backlog").expect("ready").len(), 1);
        // And a different worker can claim it (the lazy expiry sweep frees it).
        assert_eq!(
            store.claim_item(&item.id, "w2", None).expect("claims"),
            ClaimOutcome::Claimed
        );
    }

    /// Blocker readiness (`tracker-readiness.maude`): an issue with an active
    /// `blocks` edge from an open issue is not ready; closing the blocker frees
    /// it.
    #[test]
    fn active_blocker_gates_readiness() {
        let mut store = open_memory();
        let blocker = store
            .file_item("backlog", "blocker", "", &[], &json!({}), None)
            .expect("files");
        let blocked = store
            .file_item("backlog", "blocked", "", &[], &json!({}), None)
            .expect("files");
        store
            .add_blocks(&blocker.id, &blocked.id)
            .expect("add blocks");
        let ready: Vec<String> = store
            .ready_items("backlog")
            .expect("ready")
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(ready, vec![blocker.id.clone()], "blocked issue is gated");
        // Closing the blocker frees the blocked issue.
        assert_eq!(
            store.finish_item(&blocker.id, None, None).expect("finish"),
            FinishOutcome::Finished
        );
        let ready: Vec<String> = store
            .ready_items("backlog")
            .expect("ready")
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(ready, vec![blocked.id]);
    }

    /// Projection determinism (`tracker-projection.maude`): a rebuild-from-events
    /// reproduces the live projection exactly.
    #[test]
    fn rebuild_from_events_equals_live_projection() {
        let mut store = open_memory();
        let a = store
            .file_item(
                "backlog",
                "a",
                "body-a",
                &["x".to_owned()],
                &json!({"k": 1}),
                Some("f"),
            )
            .expect("files a");
        let b = store
            .file_item("backlog", "b", "", &[], &json!({}), None)
            .expect("files b");
        let c = store
            .file_item("backlog", "c", "", &[], &json!({}), None)
            .expect("files c");
        store.add_blocks(&a.id, &b.id).expect("blocks");
        store.claim_item(&c.id, "w1", None).expect("claims c");
        store
            .renew_claim(&c.id, "w1", Some("2099-01-01 00:00:00"))
            .expect("renew");
        store.claim_item(&a.id, "w2", None).expect("claims a");
        store.release_item(&a.id, None).expect("release a");
        store
            .finish_item(&b.id, Some("done"), None)
            .expect("finish b");

        let before = store.dump_projection().expect("dump before");
        store.rebuild_projection().expect("rebuild");
        let after = store.dump_projection().expect("dump after");
        assert_eq!(before, after, "rebuild reproduces the live projection");
    }

    // -- test-only projection helpers -------------------------------------

    impl WorkItemStore {
        /// A stable string snapshot of the three projection tables, for the
        /// rebuild-determinism assertion.
        fn dump_projection(&self) -> StoreResult<String> {
            let mut out = String::new();
            let mut issues = self.connection.prepare(
                "SELECT issue_id, queue, title, body, status, labels_json, metadata_json, \
                 claim_summary, filed_by, created_at, updated_at FROM tracker_issues \
                 ORDER BY issue_id",
            )?;
            let rows = issues.query_map([], |row| {
                Ok(format!(
                    "I {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?} {:?}",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, String>(10)?,
                ))
            })?;
            for row in rows {
                out.push_str(&row?);
                out.push('\n');
            }
            let mut rels = self.connection.prepare(
                "SELECT from_issue, to_issue, kind, dep_kind FROM tracker_relations \
                 ORDER BY from_issue, to_issue, kind",
            )?;
            let rows = rels.query_map([], |row| {
                Ok(format!(
                    "R {:?} {:?} {:?} {:?}",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })?;
            for row in rows {
                out.push_str(&row?);
                out.push('\n');
            }
            let mut leases = self.connection.prepare(
                "SELECT lease_id, issue_id, actor, acquired_at, expires_at, released_at \
                 FROM tracker_leases ORDER BY lease_id",
            )?;
            let rows = leases.query_map([], |row| {
                Ok(format!(
                    "L {:?} {:?} {:?} {:?} {:?} {:?}",
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })?;
            for row in rows {
                out.push_str(&row?);
                out.push('\n');
            }
            Ok(out)
        }
    }
}
