//! Branch manifests: cuts with divergent children
//! (spec/versioned-workspace-research-note.md §4, §8.3; untie-substrate
//! readiness tracker Phase 1).
//!
//! A branch is a named head over the content-addressed cut/manifest
//! substrate the restorable-context build already pays for: creation copies
//! two pointers (a cut id and its manifest hash) off the parent's head —
//! O(1), no blob traffic — and divergence is parent pointers, not a linear
//! chain. Workspace-plane store like coordination/work-items: branch rows
//! serialize under the mediator and never merge. Every operation is one
//! atomic transaction with a branchable outcome (stale-head, invalid
//! transition, and name contention are normal outcomes, not errors); the
//! caller passes the current time so the clock stays at the worker
//! boundary. Statuses are fail-closed: `discarded` and `adopted` are
//! terminal — the record is immutable history, never rewritten (the
//! no-destructive-verbs surface).

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};

use crate::event_chain;
use crate::StoreError;
use crate::StoreResult;
use std::collections::BTreeSet;

/// The distinguished mainline branch id.
pub const MAINLINE_BRANCH_ID: &str = "main";

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BranchStatus {
    Active,
    Discarded,
    Adopted,
}

impl BranchStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            BranchStatus::Active => "active",
            BranchStatus::Discarded => "discarded",
            BranchStatus::Adopted => "adopted",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(BranchStatus::Active),
            "discarded" => Some(BranchStatus::Discarded),
            "adopted" => Some(BranchStatus::Adopted),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BranchRow {
    pub branch_id: String,
    pub name: Option<String>,
    pub parent_branch_id: Option<String>,
    /// The cut this branch diverged from — fixed at creation; a later
    /// parent-head advance never moves it.
    pub branch_point_cut_id: Option<String>,
    pub branch_point_manifest_hash: Option<String>,
    pub head_cut_id: Option<String>,
    pub head_manifest_hash: Option<String>,
    /// Set only on adopted branches: the mainline/parent cut the adoption
    /// produced.
    pub adopted_merge_cut_id: Option<String>,
    pub status: BranchStatus,
    pub created_at: String,
    pub updated_at: String,
}

/// Request to create a branch. When `at_cut` is `None` the branch point is
/// the parent's CURRENT head (the common case); `at_cut` targets an older
/// pinned cut (branch-from-pin).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateBranch<'a> {
    pub branch_id: &'a str,
    pub name: Option<&'a str>,
    pub parent_branch_id: &'a str,
    pub at_cut: Option<(&'a str, &'a str)>,
    pub created_at: &'a str,
    pub idempotency_key: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateBranchOutcome {
    Created(BranchRow),
    /// The same creation (by id or idempotency key) already happened.
    Existing(BranchRow),
    ParentMissing,
    ParentNotActive {
        status: BranchStatus,
    },
    /// Another ACTIVE branch already holds the name; names are optional
    /// labels, unique only among live branches.
    NameTaken {
        holder_branch_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdvanceOutcome {
    Advanced(Box<BranchRow>),
    /// Optimistic-concurrency refusal: the head moved since the caller
    /// read it. The mediator serializes writers; this guard makes a racing
    /// writer a normal outcome rather than a lost update.
    Stale {
        current_head_cut_id: Option<String>,
    },
    NotActive {
        status: BranchStatus,
    },
    NotFound,
}

/// Outcome of binding an instance to a branch. An instance is BORN on a
/// branch: the binding is write-once (re-binding to the same branch is
/// the idempotent retry; to a different one is refused).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindOutcome {
    Bound,
    AlreadyBound { branch_id: String },
    BranchMissing,
    BranchNotActive { status: BranchStatus },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StatusOutcome {
    Done(Box<BranchRow>),
    /// Terminal statuses are immutable history; transitioning out of them
    /// is refused, never applied.
    InvalidTransition {
        from: BranchStatus,
    },
    NotFound,
}

/// Outcome of retargeting a branch's lineage parent (a chat re-homed
/// onto a workstream). Pointer-only: the recorded branch point is NOT
/// touched — it still names where this branch's content diverged, so
/// three-way merges stay correct; the next reconcile against the new
/// parent folds its deltas down and advances the point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetargetOutcome {
    Retargeted(Box<BranchRow>),
    BranchMissing,
    BranchNotActive {
        status: BranchStatus,
    },
    ParentMissing,
    ParentNotActive {
        status: BranchStatus,
    },
    /// The new parent's lineage passes through the branch itself (or IS
    /// the branch): parent pointers must stay a tree.
    WouldCycle,
}

/// One recorded cut with its provenance — the archaeology substrate
/// (vw note §7.3: write-attribution supersedes blame; every cut knows
/// what produced it and which head it advanced from).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CutRow {
    pub cut_id: String,
    pub change_id: String,
    pub branch_id: String,
    pub manifest_hash: String,
    /// The head cut this cut advanced from (`None` = first cut on the
    /// line, or a row recorded before lineage existed).
    pub parent_cut_id: Option<String>,
    /// What produced the cut: `write:<path>`, `import:<scope>`,
    /// `rebase`, `merge:<branch>`, `sync:<branch>`, `restore:<cut>`.
    pub origin: Option<String>,
    /// WHO authored the cut (DR-0052 Decision 1) — the deepest observed
    /// principal: `s:<session>` (harness lease work-unit root),
    /// `instance:<id>` (a run whose session carriage hasn't landed),
    /// `human:<operator>` (CLI, OS-trust), `root` (the GaugeDesk seat),
    /// `git:<author>` (bridge import — a CLAIM, never an observation),
    /// `mediator` (daemon reconciliation). `None` = recorded before the
    /// actor tier existed.
    pub actor: Option<String>,
    /// The motivating work item / incident id, when the recording
    /// operation carried one (repair cuts always do).
    pub intent: Option<String>,
    pub recorded_at: String,
}

/// Request to record a cut's identity + provenance. Idempotent per
/// `cut_id` (first record wins; retries are no-ops).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CutRecord<'a> {
    pub cut_id: &'a str,
    pub change_id: &'a str,
    pub branch_id: &'a str,
    pub manifest_hash: &'a str,
    pub parent_cut_id: Option<&'a str>,
    pub origin: Option<&'a str>,
    pub actor: Option<&'a str>,
    pub intent: Option<&'a str>,
    pub recorded_at: &'a str,
}

/// One persisted change-unit row (DR-0052 L4): the per-path delta of
/// one cut, indexed once — cuts are immutable and a branch's recorded
/// cut list is append-only, so the index never invalidates. Cut-level
/// metadata (origin/actor/intent/time) stays on the cut row and joins
/// at read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeUnitRow {
    pub branch_id: String,
    /// Absolute position of the OWNING CUT in the branch's oldest-first
    /// cut order at index time (windowed reads re-base unit seqs).
    pub cut_seq: i64,
    pub cut_id: String,
    pub path: String,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    /// Declaration-level sub-rows (DR-0054), JSON `Vec<DeclUnit>`;
    /// `None`/empty = the path had no canonical form on some side —
    /// attribution stays path-level for this unit.
    pub decl_units: Option<String>,
}

/// The index cursor: how far a branch's cut list has been unit-indexed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeUnitCursor {
    pub indexed_cuts: i64,
    pub last_indexed_cut_id: Option<String>,
}

/// A branch's pointer state as one workspace operation saw it — the op
/// log's unit of record. Everything `undo-op` needs to re-point the
/// branch is here; nothing else is (content is immutable, so pointers
/// ARE the operation).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OpBranchState {
    pub head_cut_id: Option<String>,
    pub head_manifest_hash: Option<String>,
    pub branch_point_cut_id: Option<String>,
    pub branch_point_manifest_hash: Option<String>,
    pub status: String,
}

impl OpBranchState {
    pub fn of(row: &BranchRow) -> Self {
        Self {
            head_cut_id: row.head_cut_id.clone(),
            head_manifest_hash: row.head_manifest_hash.clone(),
            branch_point_cut_id: row.branch_point_cut_id.clone(),
            branch_point_manifest_hash: row.branch_point_manifest_hash.clone(),
            status: row.status.as_str().to_owned(),
        }
    }
}

/// One branch a workspace operation moved: its pointers before and
/// after. `before = None` means the operation created the branch.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OpBranchDelta {
    pub branch_id: String,
    pub before: Option<OpBranchState>,
    pub after: OpBranchState,
}

/// One workspace operation in the op log (jj's most-loved feature
/// imported as a first-class record): what kind of verb ran, which
/// branch pointers it moved, and from-where-to-where. Append-only —
/// `undo-op` appends a compensating op, never deletes.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OpRow {
    pub seq: i64,
    pub op_id: String,
    pub kind: String,
    pub deltas: Vec<OpBranchDelta>,
    pub origin: Option<String>,
    pub recorded_at: String,
}

/// One structured conflict object (vw note §7.3: base + both sides +
/// both sides' provenance, never `<<<<<<<` markers). A recorded open
/// conflict TAGS the branch: the state is legal — recordable,
/// buildable-upon — and never adoptable while any conflict is open
/// (resolution-memory.maude). The id is content-addressed from its
/// components, so an identical conflict recurs under the same identity.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConflictRow {
    pub conflict_id: String,
    pub branch_id: String,
    pub path: String,
    pub base: Option<String>,
    pub ours: Option<String>,
    pub theirs: Option<String>,
    /// Provenance labels for both sides (branch ids / head refs).
    pub ours_label: String,
    pub theirs_label: String,
    /// `open` | `resolved` | `superseded` (a later clean three-way
    /// dissolved it).
    pub state: String,
    /// The resolution's content hash, when resolved.
    pub resolution: Option<String>,
    pub recorded_at: String,
    pub updated_at: String,
}

impl ConflictRow {
    /// The content-addressed conflict identity: branch, path, and the
    /// exact triple. Components are already content hashes, so joining
    /// them IS the content addressing.
    pub fn identity(
        branch_id: &str,
        path: &str,
        base: Option<&str>,
        ours: Option<&str>,
        theirs: Option<&str>,
    ) -> String {
        format!(
            "cf|{branch_id}|{path}|{}|{}|{}",
            base.unwrap_or("-"),
            ours.unwrap_or("-"),
            theirs.unwrap_or("-")
        )
    }

    /// The resolution-memory key: the content triple alone (no branch,
    /// no path) — rerere without the fragile hidden cache, and the
    /// daemon's propagation key across descendants.
    pub fn triple_key(base: Option<&str>, ours: Option<&str>, theirs: Option<&str>) -> String {
        format!(
            "tk|{}|{}|{}",
            base.unwrap_or("-"),
            ours.unwrap_or("-"),
            theirs.unwrap_or("-")
        )
    }
}

/// Object-safe branch-tier seam, mirroring `Coordination`/`WorkItems`: the
/// DO host supplies its own implementation over `DoSql`.
pub trait Branches {
    fn ensure_mainline(&mut self, created_at: &str) -> StoreResult<BranchRow>;
    fn create_branch(&mut self, request: CreateBranch<'_>) -> StoreResult<CreateBranchOutcome>;
    fn get_branch(&self, branch_id: &str) -> StoreResult<Option<BranchRow>>;
    fn list_branches(&self, status: Option<BranchStatus>) -> StoreResult<Vec<BranchRow>>;
    fn list_children(&self, parent_branch_id: &str) -> StoreResult<Vec<BranchRow>>;
    /// Walk parent pointers from the branch to its root, inclusive.
    fn lineage(&self, branch_id: &str) -> StoreResult<Vec<BranchRow>>;
    fn advance_head(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        cut_id: &str,
        manifest_hash: &str,
        at: &str,
    ) -> StoreResult<AdvanceOutcome>;
    /// Rebase-down bookkeeping: move the branch POINT to the (new) parent
    /// head and the branch HEAD to the rebased manifest in one atomic
    /// step, optimistically guarded like `advance_head`. The caller (the
    /// reconciliation planner's executor) supplies the already-merged
    /// manifest; this store never merges.
    #[allow(clippy::too_many_arguments)]
    fn rebase_branch(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        point_cut_id: &str,
        point_manifest_hash: &str,
        head_cut_id: &str,
        head_manifest_hash: &str,
        at: &str,
    ) -> StoreResult<AdvanceOutcome>;
    fn discard_branch(&mut self, branch_id: &str, at: &str) -> StoreResult<StatusOutcome>;
    fn adopt_branch(
        &mut self,
        branch_id: &str,
        merge_cut_id: &str,
        at: &str,
    ) -> StoreResult<StatusOutcome>;
    /// Move the branch's lineage parent (its upstream) to another active
    /// branch. See `RetargetOutcome` for what deliberately does NOT move.
    fn retarget_branch(
        &mut self,
        branch_id: &str,
        new_parent_branch_id: &str,
        at: &str,
    ) -> StoreResult<RetargetOutcome>;
    /// Bind an instance to the branch it is born on (write-once; the
    /// dispatch seam selects the instance's file surface by this).
    fn bind_instance(
        &mut self,
        instance_id: &str,
        branch_id: &str,
        at: &str,
    ) -> StoreResult<BindOutcome>;
    /// The branch an instance was born on; `None` = mainline (unbound).
    fn instance_branch(&self, instance_id: &str) -> StoreResult<Option<String>>;
    /// Every instance born on the branch (quiescence detection: the
    /// daemon treats a branch as mid-run while any bound instance runs).
    fn list_bound_instances(&self, branch_id: &str) -> StoreResult<Vec<String>>;
    /// Record a cut's CHANGE identity (dual identity, jj import) plus its
    /// provenance: the intent id assigned at creation, inherited across
    /// rewrites (rebases) and carried by transport (sync/merge); the
    /// parent cut it advanced from; and what produced it. Idempotent per
    /// cut id.
    fn record_cut(&mut self, cut: CutRecord<'_>) -> StoreResult<()>;

    /// DR-0068 §5: hold a cut's closure against collection for a run.
    ///
    /// Taken at **dispatch**, in the same step that stamps the cut into the
    /// trigger — `models/tla/PinnedResolution.tla` found the window that opens
    /// if the runner pins when it starts instead (collect a cut, fire a trigger
    /// naming it, resolve; every runner agrees on a world already reclaimed).
    ///
    /// Idempotent per `(cut_id, holder)`: a re-dispatch of the same run renews
    /// rather than accumulating. Deliberately a FIFTH lease-shaped mechanism
    /// rather than a merge into one of the existing four — `std-coord.md`'s
    /// four-mechanisms resolution is a standing decision that they stay
    /// separate, sharing the *contract shape* and not an implementation. The
    /// shape is honoured here: atomic attempt, holder-lifetime bound, TTL
    /// expiry, and release-on-terminal through [`Branches::release_closure_pins`].
    ///
    /// # Errors
    /// Propagates store failures.
    fn pin_closure(&mut self, cut_id: &str, holder: &str, expires_at: &str) -> StoreResult<()>;

    /// DR-0068 §5: release every pin a holder owns — the terminal hook.
    ///
    /// Every terminal path must reach this. A pin that outlives its run blocks
    /// collection forever, which is the cancel-leak lesson the runtime already
    /// paid for once (`release_holder_resources_on_terminal`): a held resource
    /// that only *usually* gets released is a leak with extra steps.
    ///
    /// # Errors
    /// Propagates store failures.
    fn release_closure_pins(&mut self, holder: &str) -> StoreResult<usize>;

    /// DR-0068 §5: cut ids currently held, expiry applied at `now`.
    ///
    /// # Errors
    /// Propagates store failures.
    fn pinned_cuts(&self, now: &str) -> StoreResult<BTreeSet<String>>;

    /// DR-0068 §2: record the log half of a cut — every in-scope instance's
    /// `(sequence, head_digest)` at the moment it was taken.
    ///
    /// Separate from [`Branches::record_cut`] because the two halves live in
    /// different stores: manifests and cuts are the branch store's, event logs
    /// are the runtime store's. Only a caller holding both can capture this, so
    /// asking `record_cut` for it would put a field on every VCS-internal cut
    /// that no VCS-internal caller could ever fill.
    ///
    /// Attaching what a cut already carries is refused rather than silently
    /// overwritten: a cut is immutable, and a second, different pin would mean
    /// two answers to "what world is this".
    fn attach_cut_log_heads(
        &mut self,
        cut_id: &str,
        heads: &event_chain::LogHeads,
    ) -> StoreResult<()>;

    /// DR-0068 §2: the log heads this cut pinned.
    ///
    /// `Ok(None)` means the cut predates the capture — distinct from
    /// `Ok(Some(empty))`, which means the cut genuinely had no in-scope
    /// instances. A runner must treat the first as "cannot verify" rather than
    /// as "nothing to verify".
    fn cut_log_heads(&self, cut_id: &str) -> StoreResult<Option<event_chain::LogHeads>>;

    /// DR-0052 L4 — the change-unit index. `change_unit_cursor` reports
    /// how far the branch's oldest-first cut list is indexed;
    /// `append_change_unit_rows` extends the index (advancing the
    /// cursor); `list_change_unit_rows` returns the indexed rows for the
    /// named cuts, cut-order ascending; `reset_change_unit_index` drops
    /// a branch's index (defensive resync only — the append-only cut
    /// list makes it unreachable in normal operation).
    fn change_unit_cursor(&self, branch_id: &str) -> StoreResult<ChangeUnitCursor>;
    fn append_change_unit_rows(
        &mut self,
        branch_id: &str,
        rows: &[ChangeUnitRow],
        indexed_cuts: i64,
        last_indexed_cut_id: Option<&str>,
    ) -> StoreResult<()>;
    fn list_change_unit_rows(
        &self,
        branch_id: &str,
        from_cut_seq: i64,
    ) -> StoreResult<Vec<ChangeUnitRow>>;
    fn reset_change_unit_index(&mut self, branch_id: &str) -> StoreResult<()>;
    /// The change id a cut carries; `None` for pre-identity cuts.
    fn cut_change_id(&self, cut_id: &str) -> StoreResult<Option<String>>;

    /// The manifest root a cut names, if the cut is recorded.
    ///
    /// # Errors
    /// Propagates store failures.
    fn cut_manifest_hash(&self, cut_id: &str) -> StoreResult<Option<String>>;
    /// The full recorded cut; `None` for unrecorded ids.
    fn get_cut(&self, cut_id: &str) -> StoreResult<Option<CutRow>>;
    /// The branch's recorded cuts, newest first, up to `limit`.
    fn list_cuts(&self, branch_id: &str, limit: usize) -> StoreResult<Vec<CutRow>>;
    /// Pointer-level state restore — `undo-op`'s compensator, and ONLY
    /// its: re-point head, branch point, and status to a recorded
    /// `OpBranchState`, guarded on the current head like `advance_head`.
    /// This appends a transition (the caller records the compensating
    /// op); it never rewrites the log. Statuses move through here even
    /// out of terminal states — undoing an adopt re-opens the branch —
    /// which is exactly why this method is not part of the ordinary verb
    /// surface.
    fn restore_branch_state(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        state: &OpBranchState,
        at: &str,
    ) -> StoreResult<AdvanceOutcome>;
    /// Append one operation to the op log. Idempotent per op id.
    fn record_op(
        &mut self,
        op_id: &str,
        kind: &str,
        deltas: &[OpBranchDelta],
        origin: Option<&str>,
        at: &str,
    ) -> StoreResult<()>;
    /// The op log, newest first, up to `limit`.
    fn list_ops(&self, limit: usize) -> StoreResult<Vec<OpRow>>;
    fn get_op(&self, op_id: &str) -> StoreResult<Option<OpRow>>;
    /// Record an open conflict object. Idempotent per conflict id; a
    /// previously resolved/superseded identical conflict re-opens (the
    /// same divergence recurred).
    fn record_conflict(&mut self, row: &ConflictRow) -> StoreResult<()>;
    /// The branch's OPEN conflicts.
    fn open_conflicts(&self, branch_id: &str) -> StoreResult<Vec<ConflictRow>>;
    /// Move a conflict to `resolved` (with the resolution hash) or
    /// `superseded`. Returns false when the id is unknown.
    fn set_conflict_state(
        &mut self,
        conflict_id: &str,
        state: &str,
        resolution: Option<&str>,
        at: &str,
    ) -> StoreResult<bool>;
    /// The stored resolution for a content triple, if any.
    fn resolution_memory(&self, triple_key: &str) -> StoreResult<Option<String>>;
    /// Store a resolution keyed by its content triple (first one wins;
    /// re-recording the same key is a no-op).
    fn record_resolution_memory(
        &mut self,
        triple_key: &str,
        resolution: &str,
        at: &str,
    ) -> StoreResult<()>;
}

#[cfg(feature = "native")]
pub struct BranchStore {
    connection: Connection,
}

#[cfg(feature = "native")]
impl BranchStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let connection = Connection::open(path)?;
        crate::establish_wal(&connection)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        ensure_branch_schema(&connection)?;
        Ok(Self { connection })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory()?;
        ensure_branch_schema(&connection)?;
        Ok(Self { connection })
    }

    fn row_by_id(connection: &Connection, branch_id: &str) -> StoreResult<Option<BranchRow>> {
        let row = connection
            .query_row(
                "SELECT branch_id, name, parent_branch_id, branch_point_cut_id, \
                 branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
                 adopted_merge_cut_id, status, created_at, updated_at \
                 FROM branches WHERE branch_id = ?1",
                params![branch_id],
                map_branch_row,
            )
            .optional()?;
        Ok(row)
    }

    /// Every content id the branch plane can still name: cut manifests
    /// (permanent archaeology — cuts of discarded branches included),
    /// branch pointers, remembered resolutions (region AND path tiers),
    /// and recorded conflict sides. This is the GC root set: anything the
    /// content store holds beyond these (and what they transitively name)
    /// is orphaned working residue.
    pub fn reachability_roots(&self) -> StoreResult<std::collections::BTreeSet<String>> {
        fn collect(
            connection: &Connection,
            sql: &str,
            roots: &mut std::collections::BTreeSet<String>,
        ) -> StoreResult<()> {
            let mut statement = connection.prepare(sql)?;
            let rows = statement.query_map([], |row| row.get::<_, Option<String>>(0))?;
            for value in rows {
                if let Some(value) = value? {
                    if !value.is_empty() {
                        roots.insert(value);
                    }
                }
            }
            Ok(())
        }
        let mut roots = std::collections::BTreeSet::new();
        for sql in [
            "SELECT manifest_hash FROM cuts",
            "SELECT head_manifest_hash FROM branches",
            "SELECT branch_point_manifest_hash FROM branches",
            "SELECT resolution FROM resolution_memory",
            "SELECT base FROM conflicts",
            "SELECT ours FROM conflicts",
            "SELECT theirs FROM conflicts",
            "SELECT resolution FROM conflicts",
        ] {
            collect(&self.connection, sql, &mut roots)?;
        }
        Ok(roots)
    }
}

#[cfg(feature = "native")]
fn map_branch_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BranchRow> {
    let status_text: String = row.get(8)?;
    Ok(BranchRow {
        branch_id: row.get(0)?,
        name: row.get(1)?,
        parent_branch_id: row.get(2)?,
        branch_point_cut_id: row.get(3)?,
        branch_point_manifest_hash: row.get(4)?,
        head_cut_id: row.get(5)?,
        head_manifest_hash: row.get(6)?,
        adopted_merge_cut_id: row.get(7)?,
        status: BranchStatus::parse(&status_text).unwrap_or(BranchStatus::Active),
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
}

#[cfg(feature = "native")]
fn map_cut_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<CutRow> {
    Ok(CutRow {
        cut_id: row.get(0)?,
        change_id: row.get(1)?,
        branch_id: row.get(2)?,
        manifest_hash: row.get(3)?,
        parent_cut_id: row.get(4)?,
        origin: row.get(5)?,
        actor: row.get(6)?,
        intent: row.get(7)?,
        recorded_at: row.get(8)?,
    })
}

#[cfg(feature = "native")]
fn map_conflict_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ConflictRow> {
    Ok(ConflictRow {
        conflict_id: row.get(0)?,
        branch_id: row.get(1)?,
        path: row.get(2)?,
        base: row.get(3)?,
        ours: row.get(4)?,
        theirs: row.get(5)?,
        ours_label: row.get(6)?,
        theirs_label: row.get(7)?,
        state: row.get(8)?,
        resolution: row.get(9)?,
        recorded_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}

#[cfg(feature = "native")]
fn map_op_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoreResult<OpRow>> {
    let deltas_json: String = row.get(3)?;
    let deltas = serde_json::from_str(&deltas_json).map_err(crate::StoreError::from);
    Ok(deltas.map(|deltas| OpRow {
        seq: row.get(0).unwrap_or_default(),
        op_id: row.get(1).unwrap_or_default(),
        kind: row.get(2).unwrap_or_default(),
        deltas,
        origin: row.get(4).unwrap_or_default(),
        recorded_at: row.get(5).unwrap_or_default(),
    }))
}

#[cfg(feature = "native")]
fn ensure_branch_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS branches (
            branch_id TEXT PRIMARY KEY,
            name TEXT,
            parent_branch_id TEXT,
            branch_point_cut_id TEXT,
            branch_point_manifest_hash TEXT,
            head_cut_id TEXT,
            head_manifest_hash TEXT,
            adopted_merge_cut_id TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            idempotency_key TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS branches_idempotency_idx
            ON branches(idempotency_key)
            WHERE idempotency_key IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS branches_active_name_idx
            ON branches(name)
            WHERE name IS NOT NULL AND status = 'active';
        CREATE INDEX IF NOT EXISTS branches_parent_idx
            ON branches(parent_branch_id);
        CREATE TABLE IF NOT EXISTS branch_instances (
            instance_id TEXT PRIMARY KEY,
            branch_id TEXT NOT NULL,
            bound_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS branch_instances_branch_idx
            ON branch_instances(branch_id);
        CREATE TABLE IF NOT EXISTS cuts (
            cut_id TEXT PRIMARY KEY,
            change_id TEXT NOT NULL,
            branch_id TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS cuts_change_idx ON cuts(change_id);
        CREATE INDEX IF NOT EXISTS cuts_branch_idx ON cuts(branch_id);
        CREATE TABLE IF NOT EXISTS ops (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            op_id TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            deltas TEXT NOT NULL,
            origin TEXT,
            recorded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS conflicts (
            conflict_id TEXT PRIMARY KEY,
            branch_id TEXT NOT NULL,
            path TEXT NOT NULL,
            base TEXT,
            ours TEXT,
            theirs TEXT,
            ours_label TEXT NOT NULL,
            theirs_label TEXT NOT NULL,
            state TEXT NOT NULL,
            resolution TEXT,
            recorded_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS conflicts_branch_idx
            ON conflicts(branch_id, state);
        CREATE TABLE IF NOT EXISTS resolution_memory (
            triple_key TEXT PRIMARY KEY,
            resolution TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS change_units (
            branch_id TEXT NOT NULL,
            cut_seq INTEGER NOT NULL,
            cut_id TEXT NOT NULL,
            path TEXT NOT NULL,
            before_hash TEXT,
            after_hash TEXT,
            decl_units TEXT
        );
        CREATE INDEX IF NOT EXISTS change_units_branch_idx
            ON change_units(branch_id, cut_seq);
        CREATE TABLE IF NOT EXISTS change_unit_cursor (
            branch_id TEXT PRIMARY KEY,
            indexed_cuts INTEGER NOT NULL,
            last_indexed_cut_id TEXT
        );
        -- DR-0068 §5: run-scoped closure pins. Keyed by (cut, holder) so a
        -- re-dispatch of the same run renews rather than accumulating.
        CREATE TABLE IF NOT EXISTS closure_pins (
            cut_id     TEXT NOT NULL,
            holder     TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (cut_id, holder)
        );
        CREATE INDEX IF NOT EXISTS closure_pins_holder_idx
            ON closure_pins(holder);
        "#,
    )?;
    // Provenance columns arrived with Phase 2, the actor tier with
    // DR-0052; stores minted before either gain the columns in place
    // (pre-migration rows read as NULL — honest "recorded before this
    // provenance existed").
    // DR-0068 §2: `log_heads` carries the cut's log half — the pinned
    // `(sequence, head_digest)` per in-scope instance. NULL on a cut recorded
    // before it, which reads as "not captured", never as "no instances".
    for column in ["parent_cut_id", "origin", "actor", "intent", "log_heads"] {
        ensure_column(connection, "cuts", column)?;
    }
    // DR-0054: declaration-level sub-rows on the change-unit index.
    ensure_column(connection, "change_units", "decl_units")?;
    Ok(())
}

#[cfg(feature = "native")]
fn ensure_column(connection: &Connection, table: &str, column: &str) -> StoreResult<()> {
    let mut stmt = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let existing: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<_, _>>()?;
    if !existing.iter().any(|name| name == column) {
        connection.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} TEXT"), [])?;
    }
    Ok(())
}

#[cfg(feature = "native")]
impl Branches for BranchStore {
    fn ensure_mainline(&mut self, created_at: &str) -> StoreResult<BranchRow> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO branches \
             (branch_id, name, parent_branch_id, status, created_at, updated_at) \
             VALUES (?1, ?1, NULL, 'active', ?2, ?2)",
            params![MAINLINE_BRANCH_ID, created_at],
        )?;
        let row =
            Self::row_by_id(&tx, MAINLINE_BRANCH_ID)?.expect("mainline row exists after insert");
        tx.commit()?;
        Ok(row)
    }

    fn create_branch(&mut self, request: CreateBranch<'_>) -> StoreResult<CreateBranchOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if let Some(existing) = Self::row_by_id(&tx, request.branch_id)? {
            tx.commit()?;
            return Ok(CreateBranchOutcome::Existing(existing));
        }
        if let Some(key) = request.idempotency_key {
            let by_key: Option<String> = tx
                .query_row(
                    "SELECT branch_id FROM branches WHERE idempotency_key = ?1",
                    params![key],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(branch_id) = by_key {
                let row = Self::row_by_id(&tx, &branch_id)?.expect("row for key");
                tx.commit()?;
                return Ok(CreateBranchOutcome::Existing(row));
            }
        }
        let Some(parent) = Self::row_by_id(&tx, request.parent_branch_id)? else {
            return Ok(CreateBranchOutcome::ParentMissing);
        };
        if parent.status != BranchStatus::Active {
            return Ok(CreateBranchOutcome::ParentNotActive {
                status: parent.status,
            });
        }
        if let Some(name) = request.name {
            let holder: Option<String> = tx
                .query_row(
                    "SELECT branch_id FROM branches \
                     WHERE name = ?1 AND status = 'active'",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(holder_branch_id) = holder {
                return Ok(CreateBranchOutcome::NameTaken { holder_branch_id });
            }
        }
        // The branch point: an explicit pinned cut, or the parent's current
        // head. Two TEXT pointers — the O(1) creation the content-addressed
        // store buys; the manifest and every blob under it are shared, not
        // copied.
        let (point_cut, point_manifest) = match request.at_cut {
            Some((cut, manifest)) => (Some(cut.to_owned()), Some(manifest.to_owned())),
            None => (
                parent.head_cut_id.clone(),
                parent.head_manifest_hash.clone(),
            ),
        };
        tx.execute(
            "INSERT INTO branches \
             (branch_id, name, parent_branch_id, branch_point_cut_id, \
              branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
              status, created_at, updated_at, idempotency_key) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?4, ?5, 'active', ?6, ?6, ?7)",
            params![
                request.branch_id,
                request.name,
                request.parent_branch_id,
                point_cut,
                point_manifest,
                request.created_at,
                request.idempotency_key,
            ],
        )?;
        let row = Self::row_by_id(&tx, request.branch_id)?.expect("created row");
        tx.commit()?;
        Ok(CreateBranchOutcome::Created(row))
    }

    fn get_branch(&self, branch_id: &str) -> StoreResult<Option<BranchRow>> {
        Self::row_by_id(&self.connection, branch_id)
    }

    fn list_branches(&self, status: Option<BranchStatus>) -> StoreResult<Vec<BranchRow>> {
        let mut rows = Vec::new();
        match status {
            Some(status) => {
                let mut stmt = self.connection.prepare(
                    "SELECT branch_id, name, parent_branch_id, branch_point_cut_id, \
                     branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
                     adopted_merge_cut_id, status, created_at, updated_at \
                     FROM branches WHERE status = ?1 ORDER BY branch_id",
                )?;
                let mapped = stmt.query_map(params![status.as_str()], map_branch_row)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
            None => {
                let mut stmt = self.connection.prepare(
                    "SELECT branch_id, name, parent_branch_id, branch_point_cut_id, \
                     branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
                     adopted_merge_cut_id, status, created_at, updated_at \
                     FROM branches ORDER BY branch_id",
                )?;
                let mapped = stmt.query_map([], map_branch_row)?;
                for row in mapped {
                    rows.push(row?);
                }
            }
        }
        Ok(rows)
    }

    fn list_children(&self, parent_branch_id: &str) -> StoreResult<Vec<BranchRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT branch_id, name, parent_branch_id, branch_point_cut_id, \
             branch_point_manifest_hash, head_cut_id, head_manifest_hash, \
             adopted_merge_cut_id, status, created_at, updated_at \
             FROM branches WHERE parent_branch_id = ?1 ORDER BY branch_id",
        )?;
        let mapped = stmt.query_map(params![parent_branch_id], map_branch_row)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    fn lineage(&self, branch_id: &str) -> StoreResult<Vec<BranchRow>> {
        let mut rows = Vec::new();
        let mut cursor = Some(branch_id.to_owned());
        // Parent pointers form a tree by construction; the visited guard
        // bounds the walk even against a manually corrupted store.
        let mut visited = std::collections::BTreeSet::new();
        while let Some(current) = cursor {
            if !visited.insert(current.clone()) {
                break;
            }
            let Some(row) = Self::row_by_id(&self.connection, &current)? else {
                break;
            };
            cursor = row.parent_branch_id.clone();
            rows.push(row);
        }
        Ok(rows)
    }

    fn retarget_branch(
        &mut self,
        branch_id: &str,
        new_parent_branch_id: &str,
        at: &str,
    ) -> StoreResult<RetargetOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(row) = Self::row_by_id(&tx, branch_id)? else {
            return Ok(RetargetOutcome::BranchMissing);
        };
        if row.status != BranchStatus::Active {
            return Ok(RetargetOutcome::BranchNotActive { status: row.status });
        }
        let Some(parent) = Self::row_by_id(&tx, new_parent_branch_id)? else {
            return Ok(RetargetOutcome::ParentMissing);
        };
        if parent.status != BranchStatus::Active {
            return Ok(RetargetOutcome::ParentNotActive {
                status: parent.status,
            });
        }
        // Parent pointers must stay a tree: refuse if the new parent's
        // lineage passes through the branch itself (self-parent is the
        // one-step case). Visited guard bounds the walk even against a
        // manually corrupted store.
        let mut cursor = Some(new_parent_branch_id.to_owned());
        let mut visited = std::collections::BTreeSet::new();
        while let Some(current) = cursor {
            if current == branch_id {
                return Ok(RetargetOutcome::WouldCycle);
            }
            if !visited.insert(current.clone()) {
                break;
            }
            cursor = Self::row_by_id(&tx, &current)?.and_then(|row| row.parent_branch_id);
        }
        tx.execute(
            "UPDATE branches SET parent_branch_id = ?2, updated_at = ?3 WHERE branch_id = ?1",
            params![branch_id, new_parent_branch_id, at],
        )?;
        let row = Self::row_by_id(&tx, branch_id)?.expect("retargeted row");
        tx.commit()?;
        Ok(RetargetOutcome::Retargeted(Box::new(row)))
    }

    fn advance_head(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        cut_id: &str,
        manifest_hash: &str,
        at: &str,
    ) -> StoreResult<AdvanceOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(row) = Self::row_by_id(&tx, branch_id)? else {
            return Ok(AdvanceOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(AdvanceOutcome::NotActive { status: row.status });
        }
        if row.head_cut_id.as_deref() != expected_head_cut_id {
            return Ok(AdvanceOutcome::Stale {
                current_head_cut_id: row.head_cut_id,
            });
        }
        tx.execute(
            "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, \
             updated_at = ?4 WHERE branch_id = ?1",
            params![branch_id, cut_id, manifest_hash, at],
        )?;
        let row = Self::row_by_id(&tx, branch_id)?.expect("advanced row");
        tx.commit()?;
        Ok(AdvanceOutcome::Advanced(Box::new(row)))
    }

    fn rebase_branch(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        point_cut_id: &str,
        point_manifest_hash: &str,
        head_cut_id: &str,
        head_manifest_hash: &str,
        at: &str,
    ) -> StoreResult<AdvanceOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(row) = Self::row_by_id(&tx, branch_id)? else {
            return Ok(AdvanceOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(AdvanceOutcome::NotActive { status: row.status });
        }
        if row.head_cut_id.as_deref() != expected_head_cut_id {
            return Ok(AdvanceOutcome::Stale {
                current_head_cut_id: row.head_cut_id,
            });
        }
        tx.execute(
            "UPDATE branches SET branch_point_cut_id = ?2, \
             branch_point_manifest_hash = ?3, head_cut_id = ?4, \
             head_manifest_hash = ?5, updated_at = ?6 WHERE branch_id = ?1",
            params![
                branch_id,
                point_cut_id,
                point_manifest_hash,
                head_cut_id,
                head_manifest_hash,
                at
            ],
        )?;
        let row = Self::row_by_id(&tx, branch_id)?.expect("rebased row");
        tx.commit()?;
        Ok(AdvanceOutcome::Advanced(Box::new(row)))
    }

    fn bind_instance(
        &mut self,
        instance_id: &str,
        branch_id: &str,
        at: &str,
    ) -> StoreResult<BindOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT branch_id FROM branch_instances WHERE instance_id = ?1",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing_branch) = existing {
            tx.commit()?;
            return Ok(if existing_branch == branch_id {
                BindOutcome::Bound
            } else {
                BindOutcome::AlreadyBound {
                    branch_id: existing_branch,
                }
            });
        }
        let Some(row) = Self::row_by_id(&tx, branch_id)? else {
            return Ok(BindOutcome::BranchMissing);
        };
        if row.status != BranchStatus::Active {
            return Ok(BindOutcome::BranchNotActive { status: row.status });
        }
        tx.execute(
            "INSERT INTO branch_instances (instance_id, branch_id, bound_at) \
             VALUES (?1, ?2, ?3)",
            params![instance_id, branch_id, at],
        )?;
        tx.commit()?;
        Ok(BindOutcome::Bound)
    }

    fn record_cut(&mut self, cut: CutRecord<'_>) -> StoreResult<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO cuts \
             (cut_id, change_id, branch_id, manifest_hash, parent_cut_id, \
              origin, actor, intent, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                cut.cut_id,
                cut.change_id,
                cut.branch_id,
                cut.manifest_hash,
                cut.parent_cut_id,
                cut.origin,
                cut.actor,
                cut.intent,
                cut.recorded_at
            ],
        )?;
        Ok(())
    }

    fn pin_closure(&mut self, cut_id: &str, holder: &str, expires_at: &str) -> StoreResult<()> {
        self.connection.execute(
            "INSERT INTO closure_pins (cut_id, holder, expires_at) VALUES (?1, ?2, ?3) \
             ON CONFLICT(cut_id, holder) DO UPDATE SET expires_at = excluded.expires_at",
            params![cut_id, holder, expires_at],
        )?;
        Ok(())
    }

    fn release_closure_pins(&mut self, holder: &str) -> StoreResult<usize> {
        let released = self.connection.execute(
            "DELETE FROM closure_pins WHERE holder = ?1",
            params![holder],
        )?;
        Ok(released)
    }

    fn pinned_cuts(&self, now: &str) -> StoreResult<BTreeSet<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT cut_id FROM closure_pins WHERE expires_at > ?1")?;
        let cuts = statement
            .query_map(params![now], |row| row.get::<_, String>(0))?
            .collect::<Result<BTreeSet<_>, _>>()?;
        Ok(cuts)
    }

    fn attach_cut_log_heads(
        &mut self,
        cut_id: &str,
        heads: &event_chain::LogHeads,
    ) -> StoreResult<()> {
        let existing: Option<Option<String>> = self
            .connection
            .query_row(
                "SELECT log_heads FROM cuts WHERE cut_id = ?1",
                params![cut_id],
                |row| row.get(0),
            )
            .optional()?;
        match existing {
            None => {
                return Err(StoreError::Conflict(format!(
                    "cut `{cut_id}` does not exist, so its log heads cannot be attached"
                )))
            }
            Some(Some(_)) => {
                return Err(StoreError::Conflict(format!(
                    "cut `{cut_id}` already pinned its log heads; a cut is immutable and a \
                     second pin would be a second answer to what world it names"
                )))
            }
            Some(None) => {}
        }
        let encoded = event_chain::encode_log_heads(heads)?;
        // `AND log_heads IS NULL` is the guard, not the check above.
        //
        // The read-then-write shape leaves a window in which two callers both
        // see NULL and both write, and the second silently overwrites a pin the
        // record says is immutable — the same class of defect as the lost-append
        // race, found by auditing for the pattern rather than by waiting for a
        // stress test to notice. Making the condition part of the statement
        // closes it; the read above survives only to distinguish "no such cut"
        // from "already pinned" in the error.
        let updated = self.connection.execute(
            "UPDATE cuts SET log_heads = ?1 WHERE cut_id = ?2 AND log_heads IS NULL",
            params![encoded, cut_id],
        )?;
        if updated == 0 {
            return Err(StoreError::Conflict(format!(
                "cut `{cut_id}` was pinned concurrently; a cut is immutable and a second \
                 pin would be a second answer to what world it names"
            )));
        }
        Ok(())
    }

    fn cut_log_heads(&self, cut_id: &str) -> StoreResult<Option<event_chain::LogHeads>> {
        let encoded: Option<Option<String>> = self
            .connection
            .query_row(
                "SELECT log_heads FROM cuts WHERE cut_id = ?1",
                params![cut_id],
                |row| row.get(0),
            )
            .optional()?;
        match encoded.flatten() {
            None => Ok(None),
            Some(text) => Ok(Some(event_chain::decode_log_heads(&text)?)),
        }
    }

    fn cut_manifest_hash(&self, cut_id: &str) -> StoreResult<Option<String>> {
        self.connection
            .query_row(
                "SELECT manifest_hash FROM cuts WHERE cut_id = ?1",
                params![cut_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    fn cut_change_id(&self, cut_id: &str) -> StoreResult<Option<String>> {
        let change: Option<String> = self
            .connection
            .query_row(
                "SELECT change_id FROM cuts WHERE cut_id = ?1",
                params![cut_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(change)
    }

    fn change_unit_cursor(&self, branch_id: &str) -> StoreResult<ChangeUnitCursor> {
        let cursor = self
            .connection
            .query_row(
                "SELECT indexed_cuts, last_indexed_cut_id FROM change_unit_cursor                  WHERE branch_id = ?1",
                params![branch_id],
                |row| {
                    Ok(ChangeUnitCursor {
                        indexed_cuts: row.get(0)?,
                        last_indexed_cut_id: row.get(1)?,
                    })
                },
            )
            .optional()?;
        Ok(cursor.unwrap_or(ChangeUnitCursor {
            indexed_cuts: 0,
            last_indexed_cut_id: None,
        }))
    }

    fn append_change_unit_rows(
        &mut self,
        branch_id: &str,
        rows: &[ChangeUnitRow],
        indexed_cuts: i64,
        last_indexed_cut_id: Option<&str>,
    ) -> StoreResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for row in rows {
            tx.execute(
                "INSERT INTO change_units                  (branch_id, cut_seq, cut_id, path, before_hash, after_hash, decl_units)                  VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    row.branch_id,
                    row.cut_seq,
                    row.cut_id,
                    row.path,
                    row.before_hash,
                    row.after_hash,
                    row.decl_units
                ],
            )?;
        }
        tx.execute(
            "INSERT INTO change_unit_cursor (branch_id, indexed_cuts, last_indexed_cut_id)              VALUES (?1, ?2, ?3)              ON CONFLICT(branch_id) DO UPDATE SET indexed_cuts = ?2,              last_indexed_cut_id = ?3",
            params![branch_id, indexed_cuts, last_indexed_cut_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn list_change_unit_rows(
        &self,
        branch_id: &str,
        from_cut_seq: i64,
    ) -> StoreResult<Vec<ChangeUnitRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT branch_id, cut_seq, cut_id, path, before_hash, after_hash, decl_units              FROM change_units WHERE branch_id = ?1 AND cut_seq >= ?2              ORDER BY cut_seq ASC, rowid ASC",
        )?;
        let mapped = stmt.query_map(params![branch_id, from_cut_seq], |row| {
            Ok(ChangeUnitRow {
                branch_id: row.get(0)?,
                cut_seq: row.get(1)?,
                cut_id: row.get(2)?,
                path: row.get(3)?,
                before_hash: row.get(4)?,
                after_hash: row.get(5)?,
                decl_units: row.get(6)?,
            })
        })?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    fn reset_change_unit_index(&mut self, branch_id: &str) -> StoreResult<()> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        tx.execute(
            "DELETE FROM change_units WHERE branch_id = ?1",
            params![branch_id],
        )?;
        tx.execute(
            "DELETE FROM change_unit_cursor WHERE branch_id = ?1",
            params![branch_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn get_cut(&self, cut_id: &str) -> StoreResult<Option<CutRow>> {
        let row = self
            .connection
            .query_row(
                "SELECT cut_id, change_id, branch_id, manifest_hash, \
                 parent_cut_id, origin, actor, intent, recorded_at \
                 FROM cuts WHERE cut_id = ?1",
                params![cut_id],
                map_cut_row,
            )
            .optional()?;
        Ok(row)
    }

    fn list_cuts(&self, branch_id: &str, limit: usize) -> StoreResult<Vec<CutRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT cut_id, change_id, branch_id, manifest_hash, \
             parent_cut_id, origin, actor, intent, recorded_at \
             FROM cuts WHERE branch_id = ?1 ORDER BY rowid DESC LIMIT ?2",
        )?;
        let mapped = stmt.query_map(params![branch_id, limit as i64], map_cut_row)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    fn restore_branch_state(
        &mut self,
        branch_id: &str,
        expected_head_cut_id: Option<&str>,
        state: &OpBranchState,
        at: &str,
    ) -> StoreResult<AdvanceOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(row) = Self::row_by_id(&tx, branch_id)? else {
            return Ok(AdvanceOutcome::NotFound);
        };
        if row.head_cut_id.as_deref() != expected_head_cut_id {
            return Ok(AdvanceOutcome::Stale {
                current_head_cut_id: row.head_cut_id,
            });
        }
        tx.execute(
            "UPDATE branches SET head_cut_id = ?2, head_manifest_hash = ?3, \
             branch_point_cut_id = ?4, branch_point_manifest_hash = ?5, \
             status = ?6, updated_at = ?7 WHERE branch_id = ?1",
            params![
                branch_id,
                state.head_cut_id,
                state.head_manifest_hash,
                state.branch_point_cut_id,
                state.branch_point_manifest_hash,
                state.status,
                at
            ],
        )?;
        let row = Self::row_by_id(&tx, branch_id)?.expect("restored row");
        tx.commit()?;
        Ok(AdvanceOutcome::Advanced(Box::new(row)))
    }

    fn record_op(
        &mut self,
        op_id: &str,
        kind: &str,
        deltas: &[OpBranchDelta],
        origin: Option<&str>,
        at: &str,
    ) -> StoreResult<()> {
        let deltas_json = serde_json::to_string(deltas).map_err(crate::StoreError::from)?;
        self.connection.execute(
            "INSERT OR IGNORE INTO ops (op_id, kind, deltas, origin, recorded_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![op_id, kind, deltas_json, origin, at],
        )?;
        Ok(())
    }

    fn list_ops(&self, limit: usize) -> StoreResult<Vec<OpRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT seq, op_id, kind, deltas, origin, recorded_at FROM ops \
             ORDER BY seq DESC LIMIT ?1",
        )?;
        let mapped = stmt.query_map(params![limit as i64], map_op_row)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row??);
        }
        Ok(rows)
    }

    fn get_op(&self, op_id: &str) -> StoreResult<Option<OpRow>> {
        let row = self
            .connection
            .query_row(
                "SELECT seq, op_id, kind, deltas, origin, recorded_at FROM ops \
                 WHERE op_id = ?1",
                params![op_id],
                map_op_row,
            )
            .optional()?;
        row.transpose()
    }

    fn record_conflict(&mut self, row: &ConflictRow) -> StoreResult<()> {
        // Idempotent per id; a terminal identical conflict RE-OPENS —
        // the same divergence recurred and is once again the ask.
        self.connection.execute(
            "INSERT INTO conflicts (conflict_id, branch_id, path, base, ours, \
             theirs, ours_label, theirs_label, state, resolution, recorded_at, \
             updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'open', NULL, ?9, ?9) \
             ON CONFLICT(conflict_id) DO UPDATE SET state = 'open', \
             resolution = NULL, updated_at = ?9 WHERE state != 'open'",
            params![
                row.conflict_id,
                row.branch_id,
                row.path,
                row.base,
                row.ours,
                row.theirs,
                row.ours_label,
                row.theirs_label,
                row.recorded_at,
            ],
        )?;
        Ok(())
    }

    fn open_conflicts(&self, branch_id: &str) -> StoreResult<Vec<ConflictRow>> {
        let mut stmt = self.connection.prepare(
            "SELECT conflict_id, branch_id, path, base, ours, theirs, \
             ours_label, theirs_label, state, resolution, recorded_at, updated_at \
             FROM conflicts WHERE branch_id = ?1 AND state = 'open' ORDER BY path",
        )?;
        let mapped = stmt.query_map(params![branch_id], map_conflict_row)?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    fn set_conflict_state(
        &mut self,
        conflict_id: &str,
        state: &str,
        resolution: Option<&str>,
        at: &str,
    ) -> StoreResult<bool> {
        let changed = self.connection.execute(
            "UPDATE conflicts SET state = ?2, resolution = ?3, updated_at = ?4 \
             WHERE conflict_id = ?1",
            params![conflict_id, state, resolution, at],
        )?;
        Ok(changed > 0)
    }

    fn resolution_memory(&self, triple_key: &str) -> StoreResult<Option<String>> {
        let resolution: Option<String> = self
            .connection
            .query_row(
                "SELECT resolution FROM resolution_memory WHERE triple_key = ?1",
                params![triple_key],
                |row| row.get(0),
            )
            .optional()?;
        Ok(resolution)
    }

    fn record_resolution_memory(
        &mut self,
        triple_key: &str,
        resolution: &str,
        at: &str,
    ) -> StoreResult<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO resolution_memory (triple_key, resolution, recorded_at) \
             VALUES (?1, ?2, ?3)",
            params![triple_key, resolution, at],
        )?;
        Ok(())
    }

    fn instance_branch(&self, instance_id: &str) -> StoreResult<Option<String>> {
        let branch: Option<String> = self
            .connection
            .query_row(
                "SELECT branch_id FROM branch_instances WHERE instance_id = ?1",
                params![instance_id],
                |row| row.get(0),
            )
            .optional()?;
        Ok(branch)
    }

    fn list_bound_instances(&self, branch_id: &str) -> StoreResult<Vec<String>> {
        let mut stmt = self.connection.prepare(
            "SELECT instance_id FROM branch_instances              WHERE branch_id = ?1 ORDER BY instance_id",
        )?;
        let mapped = stmt.query_map(params![branch_id], |row| row.get(0))?;
        let mut rows = Vec::new();
        for row in mapped {
            rows.push(row?);
        }
        Ok(rows)
    }

    fn discard_branch(&mut self, branch_id: &str, at: &str) -> StoreResult<StatusOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(row) = Self::row_by_id(&tx, branch_id)? else {
            return Ok(StatusOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(StatusOutcome::InvalidTransition { from: row.status });
        }
        tx.execute(
            "UPDATE branches SET status = 'discarded', updated_at = ?2 \
             WHERE branch_id = ?1",
            params![branch_id, at],
        )?;
        let row = Self::row_by_id(&tx, branch_id)?.expect("discarded row");
        tx.commit()?;
        Ok(StatusOutcome::Done(Box::new(row)))
    }

    fn adopt_branch(
        &mut self,
        branch_id: &str,
        merge_cut_id: &str,
        at: &str,
    ) -> StoreResult<StatusOutcome> {
        let tx = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let Some(row) = Self::row_by_id(&tx, branch_id)? else {
            return Ok(StatusOutcome::NotFound);
        };
        if row.status != BranchStatus::Active {
            return Ok(StatusOutcome::InvalidTransition { from: row.status });
        }
        tx.execute(
            "UPDATE branches SET status = 'adopted', adopted_merge_cut_id = ?2, \
             updated_at = ?3 WHERE branch_id = ?1",
            params![branch_id, merge_cut_id, at],
        )?;
        let row = Self::row_by_id(&tx, branch_id)?.expect("adopted row");
        tx.commit()?;
        Ok(StatusOutcome::Done(Box::new(row)))
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn store() -> BranchStore {
        BranchStore::open_in_memory().expect("open store")
    }

    fn create<'a>(branch_id: &'a str, parent: &'a str) -> CreateBranch<'a> {
        CreateBranch {
            branch_id,
            name: None,
            parent_branch_id: parent,
            at_cut: None,
            created_at: "2026-07-10T00:00:00Z",
            idempotency_key: None,
        }
    }

    fn seed_cut(store: &mut BranchStore, cut_id: &str) {
        store.ensure_mainline("t0").expect("mainline");
        store
            .record_cut(CutRecord {
                cut_id,
                change_id: cut_id,
                branch_id: MAINLINE_BRANCH_ID,
                manifest_hash: "manifest_a",
                parent_cut_id: None,
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t1",
            })
            .expect("cut records");
    }

    fn one_head(instance: &str, sequence: i64, digest: &str) -> event_chain::LogHeads {
        let mut heads = event_chain::LogHeads::new();
        heads.insert(
            instance.to_owned(),
            event_chain::ChainHead {
                sequence: Some(sequence),
                digest: digest.to_owned(),
            },
        );
        heads
    }

    /// DR-0068 §2: a cut carries the log half, so pinning the cut pins the
    /// runtime history too.
    #[test]
    fn a_cut_pins_and_returns_its_log_heads() {
        let mut store = store();
        seed_cut(&mut store, "cut_1");
        let heads = one_head("inst_a", 3, "digest_a");

        store
            .attach_cut_log_heads("cut_1", &heads)
            .expect("heads attach");

        assert_eq!(
            store.cut_log_heads("cut_1").expect("heads read"),
            Some(heads)
        );
    }

    /// "Not captured" and "no instances" must not be the same answer: the first
    /// means a runner cannot verify, the second means there is nothing to.
    #[test]
    fn an_uncaptured_cut_is_distinct_from_an_empty_one() {
        let mut store = store();
        seed_cut(&mut store, "cut_1");
        assert_eq!(store.cut_log_heads("cut_1").expect("heads read"), None);

        seed_cut(&mut store, "cut_2");
        store
            .attach_cut_log_heads("cut_2", &event_chain::LogHeads::new())
            .expect("empty heads attach");
        assert_eq!(
            store.cut_log_heads("cut_2").expect("heads read"),
            Some(event_chain::LogHeads::new())
        );
    }

    /// A cut is immutable, so a second, different pin would be a second answer
    /// to what world it names.
    #[test]
    fn re_pinning_a_cut_is_refused() {
        let mut store = store();
        seed_cut(&mut store, "cut_1");
        store
            .attach_cut_log_heads("cut_1", &one_head("inst_a", 3, "digest_a"))
            .expect("first attach");

        let second = store.attach_cut_log_heads("cut_1", &one_head("inst_a", 4, "digest_b"));
        assert!(
            matches!(&second, Err(StoreError::Conflict(message)) if message.contains("already pinned")),
            "a re-pin must be refused *as a re-pin*, got {second:?}"
        );
        assert_eq!(
            store.cut_log_heads("cut_1").expect("heads read"),
            Some(one_head("inst_a", 3, "digest_a")),
            "the original pin must survive the refusal"
        );
    }

    /// **Concurrent pins of one cut: exactly one wins.**
    ///
    /// The read-then-write shape let both callers see NULL and both write, so
    /// the immutability the record promises held only when nobody raced. Found
    /// by auditing for the pattern after the lost-append race, not by a failing
    /// test — which is the only reason it is fixed before it mattered.
    #[test]
    fn a_concurrently_pinned_cut_keeps_exactly_one_pin() {
        let dir = std::env::temp_dir().join(format!(
            "whip-pin-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("branches.sqlite");
        {
            let mut store = BranchStore::open(&path).expect("store opens");
            seed_cut(&mut store, "cut_1");
        }

        const WRITERS: usize = 4;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
        let mut handles = Vec::new();
        for index in 0..WRITERS {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut store = BranchStore::open(&path).expect("writer opens");
                let heads = one_head("inst_a", index as i64, &format!("digest_{index}"));
                barrier.wait();
                store.attach_cut_log_heads("cut_1", &heads).is_ok()
            }));
        }
        let wins = handles
            .into_iter()
            .filter(|_| true)
            .map(|handle| handle.join().expect("writer finishes"))
            .filter(|won| *won)
            .count();

        assert_eq!(
            wins, 1,
            "exactly one concurrent pin may win; the rest must be refused"
        );
        let store = BranchStore::open(&path).expect("store reopens");
        assert!(
            store.cut_log_heads("cut_1").expect("heads read").is_some(),
            "and the winner's pin must be what survives"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `attach_cut_log_heads` has THREE Conflict refusals — unknown cut,
    /// already pinned, pinned concurrently — so `Err(Conflict(_))` does not say
    /// which one fired. It passes just as well when the refusal is right for
    /// the wrong reason, and a mutation sweep reads it as testing nothing.
    /// Assert the reason, not the variant.
    #[test]
    fn pinning_an_unknown_cut_is_refused() {
        let mut store = store();
        store.ensure_mainline("t0").expect("mainline");
        let refusal = store.attach_cut_log_heads("cut_nope", &one_head("inst_a", 1, "d"));
        let Err(StoreError::Conflict(message)) = refusal else {
            panic!("pinning an unknown cut must be refused, got {refusal:?}");
        };
        assert!(
            message.contains("cut_nope") && message.contains("does not exist"),
            "the refusal must name the cut and say it does not exist, \
             not merely be some conflict: {message}"
        );
    }

    /// DR-0068 §5: a pin holds until it expires, and expiry is applied at read
    /// time rather than by a sweeper — a pin nobody swept must not read as
    /// still held.
    #[test]
    fn a_pin_holds_until_it_expires() {
        let mut store = store();
        seed_cut(&mut store, "cut_1");
        store
            .pin_closure("cut_1", "run-a", "2026-08-24T12:00:00Z")
            .expect("pin taken");

        assert!(store
            .pinned_cuts("2026-08-24T11:59:59Z")
            .expect("read")
            .contains("cut_1"));
        assert!(
            !store
                .pinned_cuts("2026-08-24T12:00:01Z")
                .expect("read")
                .contains("cut_1"),
            "an expired pin must not read as held"
        );
    }

    /// Idempotent per (cut, holder): a re-dispatch renews rather than
    /// accumulating rows that each have to be released separately.
    #[test]
    fn re_pinning_the_same_run_renews_rather_than_accumulating() {
        let mut store = store();
        seed_cut(&mut store, "cut_1");
        store
            .pin_closure("cut_1", "run-a", "2026-08-24T12:00:00Z")
            .expect("pin taken");
        store
            .pin_closure("cut_1", "run-a", "2026-08-24T18:00:00Z")
            .expect("pin renewed");

        assert!(
            store
                .pinned_cuts("2026-08-24T13:00:00Z")
                .expect("read")
                .contains("cut_1"),
            "the renewal must have extended the hold"
        );
        assert_eq!(
            store.release_closure_pins("run-a").expect("release"),
            1,
            "a renewal must not have left a second row behind"
        );
    }

    /// The terminal hook, and the lesson this runtime already paid for once: a
    /// held resource released on only *some* terminal paths is a leak with
    /// extra steps. Releasing by holder is what lets every terminal path reach
    /// it without knowing which cuts the run touched.
    #[test]
    fn releasing_a_holder_frees_every_cut_it_held() {
        let mut store = store();
        seed_cut(&mut store, "cut_1");
        seed_cut(&mut store, "cut_2");
        store
            .pin_closure("cut_1", "run-a", "2126-01-01T00:00:00Z")
            .expect("pin one");
        store
            .pin_closure("cut_2", "run-a", "2126-01-01T00:00:00Z")
            .expect("pin two");
        store
            .pin_closure("cut_1", "run-b", "2126-01-01T00:00:00Z")
            .expect("another run pins the same cut");

        assert_eq!(store.release_closure_pins("run-a").expect("release"), 2);

        let held = store.pinned_cuts("2026-08-24T00:00:00Z").expect("read");
        assert!(
            held.contains("cut_1"),
            "another holder's pin on the same cut must survive"
        );
        assert!(!held.contains("cut_2"));
    }

    /// **Concurrent pins and releases of one cut, under real threads.**
    ///
    /// `pin_closure` is `INSERT ... ON CONFLICT DO UPDATE` and
    /// `release_closure_pins` is a single `DELETE`, so both are one atomic
    /// statement and neither has the read-then-write shape that produced three
    /// defects in this work. That is an argument, though, not a check — and
    /// after this session I would rather not leave a concurrency claim resting
    /// on one.
    ///
    /// The property: a holder that pinned and did not release still holds, and
    /// a holder that released holds nothing. No interleaving may leave a pin
    /// belonging to a released holder, which is the leak that blocks collection
    /// forever.
    #[test]
    fn concurrent_pins_and_releases_leave_no_orphaned_hold() {
        let dir = std::env::temp_dir().join(format!(
            "whip-pinrace-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("branches.sqlite");
        {
            let mut store = BranchStore::open(&path).expect("store opens");
            seed_cut(&mut store, "cut_1");
        }

        const HOLDERS: usize = 4;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(HOLDERS));
        let mut handles = Vec::new();
        for index in 0..HOLDERS {
            let path = path.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut store = BranchStore::open(&path).expect("holder opens");
                let holder = format!("run-{index}");
                barrier.wait();
                for _ in 0..8 {
                    store
                        .pin_closure("cut_1", &holder, "2126-01-01T00:00:00Z")
                        .expect("pin takes");
                }
                // Odd holders release; even holders keep holding.
                if index % 2 == 1 {
                    store
                        .release_closure_pins(&holder)
                        .expect("release succeeds");
                }
                index % 2 == 0
            }));
        }
        let still_holding: usize = handles
            .into_iter()
            .map(|handle| handle.join().expect("holder finishes"))
            .filter(|kept| *kept)
            .count();

        let store = BranchStore::open(&path).expect("store reopens");
        let held = store
            .pinned_cuts("2026-08-24T00:00:00Z")
            .expect("pins read");
        assert!(
            held.contains("cut_1"),
            "holders that did not release must still hold the cut"
        );
        assert!(still_holding > 0, "the fixture must leave someone holding");

        // Every remaining pin belongs to a holder that did not release: no
        // interleaving may strand one, and none may vanish either.
        let rows: Vec<(String, String)> = store
            .connection
            .prepare("SELECT cut_id, holder FROM closure_pins")
            .and_then(|mut s| {
                s.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect()
            })
            .expect("pins enumerate");
        assert_eq!(
            rows.len(),
            still_holding,
            "one row per non-releasing holder — no orphan, no duplicate"
        );
        for (_, holder) in &rows {
            let index: usize = holder
                .trim_start_matches("run-")
                .parse()
                .expect("holder id parses");
            assert_eq!(index % 2, 0, "a released holder must hold nothing");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn releasing_a_holder_with_no_pins_is_not_an_error() {
        let mut store = store();
        assert_eq!(store.release_closure_pins("run-never").expect("release"), 0);
    }

    #[test]
    fn mainline_bootstrap_is_idempotent() {
        let mut store = store();
        let first = store.ensure_mainline("2026-07-10T00:00:00Z").expect("op");
        let second = store.ensure_mainline("2026-07-10T01:00:00Z").expect("op");
        assert_eq!(first, second);
        assert_eq!(first.branch_id, MAINLINE_BRANCH_ID);
        assert_eq!(first.status, BranchStatus::Active);
        assert_eq!(first.parent_branch_id, None);
    }

    /// O(1) divergent children: two branches off one mainline head share the
    /// branch-point pointers (no copying), and the branch point stays fixed
    /// when mainline advances afterwards.
    #[test]
    fn branch_creation_shares_pointers_and_pins_the_branch_point() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        assert!(matches!(
            store
                .advance_head(MAINLINE_BRANCH_ID, None, "cut_1", "manifest_a", "t1")
                .expect("op"),
            AdvanceOutcome::Advanced(_)
        ));
        let CreateBranchOutcome::Created(draft_a) = store
            .create_branch(create("draft_a", MAINLINE_BRANCH_ID))
            .expect("op")
        else {
            panic!("expected creation");
        };
        let CreateBranchOutcome::Created(draft_b) = store
            .create_branch(create("draft_b", MAINLINE_BRANCH_ID))
            .expect("op")
        else {
            panic!("expected creation");
        };
        for child in [&draft_a, &draft_b] {
            assert_eq!(child.branch_point_cut_id.as_deref(), Some("cut_1"));
            assert_eq!(
                child.branch_point_manifest_hash.as_deref(),
                Some("manifest_a")
            );
            assert_eq!(child.head_cut_id.as_deref(), Some("cut_1"));
        }
        // Mainline advances; the children's branch points do not move.
        assert!(matches!(
            store
                .advance_head(
                    MAINLINE_BRANCH_ID,
                    Some("cut_1"),
                    "cut_2",
                    "manifest_b",
                    "t2"
                )
                .expect("op"),
            AdvanceOutcome::Advanced(_)
        ));
        let pinned = store.get_branch("draft_a").expect("op").expect("row");
        assert_eq!(pinned.branch_point_cut_id.as_deref(), Some("cut_1"));
        let children = store.list_children(MAINLINE_BRANCH_ID).expect("op");
        assert_eq!(
            children
                .iter()
                .map(|c| c.branch_id.as_str())
                .collect::<Vec<_>>(),
            vec!["draft_a", "draft_b"]
        );
    }

    #[test]
    fn create_is_idempotent_by_id_and_key() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        let mut request = create("draft_a", MAINLINE_BRANCH_ID);
        request.idempotency_key = Some("key_1");
        let CreateBranchOutcome::Created(created) =
            store.create_branch(request.clone()).expect("op")
        else {
            panic!("expected creation");
        };
        // Same id: existing row, no second branch.
        assert_eq!(
            store.create_branch(request).expect("op"),
            CreateBranchOutcome::Existing(created.clone())
        );
        // Same idempotency key under a NEW id: still the existing row.
        let mut retry = create("draft_a_retry", MAINLINE_BRANCH_ID);
        retry.idempotency_key = Some("key_1");
        assert_eq!(
            store.create_branch(retry).expect("op"),
            CreateBranchOutcome::Existing(created)
        );
    }

    #[test]
    fn names_are_unique_among_active_branches_only() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        let mut first = create("draft_a", MAINLINE_BRANCH_ID);
        first.name = Some("triage");
        assert!(matches!(
            store.create_branch(first).expect("op"),
            CreateBranchOutcome::Created(_)
        ));
        let mut second = create("draft_b", MAINLINE_BRANCH_ID);
        second.name = Some("triage");
        assert_eq!(
            store.create_branch(second.clone()).expect("op"),
            CreateBranchOutcome::NameTaken {
                holder_branch_id: "draft_a".to_owned()
            }
        );
        // Discarding the holder frees the name: unique among LIVE branches.
        assert!(matches!(
            store.discard_branch("draft_a", "t1").expect("op"),
            StatusOutcome::Done(_)
        ));
        assert!(matches!(
            store.create_branch(second).expect("op"),
            CreateBranchOutcome::Created(_)
        ));
    }

    #[test]
    fn advance_head_is_optimistically_guarded() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        assert!(matches!(
            store
                .advance_head(MAINLINE_BRANCH_ID, None, "cut_1", "m1", "t1")
                .expect("op"),
            AdvanceOutcome::Advanced(_)
        ));
        // A writer holding the old head loses as a normal outcome.
        assert_eq!(
            store
                .advance_head(MAINLINE_BRANCH_ID, None, "cut_2", "m2", "t2")
                .expect("op"),
            AdvanceOutcome::Stale {
                current_head_cut_id: Some("cut_1".to_owned())
            }
        );
        assert!(matches!(
            store
                .advance_head(MAINLINE_BRANCH_ID, Some("cut_1"), "cut_2", "m2", "t2")
                .expect("op"),
            AdvanceOutcome::Advanced(_)
        ));
    }

    #[test]
    fn terminal_statuses_are_immutable() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        assert!(matches!(
            store
                .create_branch(create("draft_a", MAINLINE_BRANCH_ID))
                .expect("op"),
            CreateBranchOutcome::Created(_)
        ));
        assert!(matches!(
            store.discard_branch("draft_a", "t1").expect("op"),
            StatusOutcome::Done(_)
        ));
        assert_eq!(
            store.adopt_branch("draft_a", "cut_9", "t2").expect("op"),
            StatusOutcome::InvalidTransition {
                from: BranchStatus::Discarded
            }
        );
        assert_eq!(
            store.discard_branch("draft_a", "t3").expect("op"),
            StatusOutcome::InvalidTransition {
                from: BranchStatus::Discarded
            }
        );
        // Advancing a discarded branch's head is refused too.
        assert_eq!(
            store
                .advance_head("draft_a", None, "cut_3", "m3", "t4")
                .expect("op"),
            AdvanceOutcome::NotActive {
                status: BranchStatus::Discarded
            }
        );
        // Branching off a dead line is refused.
        assert_eq!(
            store
                .create_branch(create("draft_c", "draft_a"))
                .expect("op"),
            CreateBranchOutcome::ParentNotActive {
                status: BranchStatus::Discarded
            }
        );
    }

    /// Instance binding is write-once: an instance is BORN on a branch;
    /// same-branch re-bind is the idempotent retry, cross-branch re-bind
    /// refuses, dead lines refuse new births.
    #[test]
    fn instance_binding_is_write_once() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        assert!(matches!(
            store
                .create_branch(create("draft_a", MAINLINE_BRANCH_ID))
                .expect("op"),
            CreateBranchOutcome::Created(_)
        ));
        assert_eq!(store.instance_branch("ins_1").expect("op"), None);
        assert_eq!(
            store.bind_instance("ins_1", "draft_a", "t1").expect("op"),
            BindOutcome::Bound
        );
        assert_eq!(
            store.instance_branch("ins_1").expect("op"),
            Some("draft_a".to_owned())
        );
        assert_eq!(
            store.bind_instance("ins_1", "draft_a", "t2").expect("op"),
            BindOutcome::Bound
        );
        assert_eq!(
            store
                .bind_instance("ins_1", MAINLINE_BRANCH_ID, "t3")
                .expect("op"),
            BindOutcome::AlreadyBound {
                branch_id: "draft_a".to_owned()
            }
        );
        assert_eq!(
            store.bind_instance("ins_2", "missing", "t4").expect("op"),
            BindOutcome::BranchMissing
        );
        assert!(matches!(
            store.discard_branch("draft_a", "t5").expect("op"),
            StatusOutcome::Done(_)
        ));
        assert_eq!(
            store.bind_instance("ins_3", "draft_a", "t6").expect("op"),
            BindOutcome::BranchNotActive {
                status: BranchStatus::Discarded
            }
        );
    }

    #[test]
    fn lineage_walks_to_the_root() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        assert!(matches!(
            store
                .create_branch(create("draft_a", MAINLINE_BRANCH_ID))
                .expect("op"),
            CreateBranchOutcome::Created(_)
        ));
        assert!(matches!(
            store
                .create_branch(create("draft_a_1", "draft_a"))
                .expect("op"),
            CreateBranchOutcome::Created(_)
        ));
        let lineage = store.lineage("draft_a_1").expect("op");
        assert_eq!(
            lineage
                .iter()
                .map(|b| b.branch_id.as_str())
                .collect::<Vec<_>>(),
            vec!["draft_a_1", "draft_a", MAINLINE_BRANCH_ID]
        );
    }

    #[test]
    fn adoption_records_the_merge_cut() {
        let mut store = store();
        store.ensure_mainline("t0").expect("op");
        assert!(matches!(
            store
                .create_branch(create("draft_a", MAINLINE_BRANCH_ID))
                .expect("op"),
            CreateBranchOutcome::Created(_)
        ));
        let StatusOutcome::Done(adopted) = store
            .adopt_branch("draft_a", "cut_merge_1", "t1")
            .expect("op")
        else {
            panic!("expected adoption");
        };
        assert_eq!(adopted.status, BranchStatus::Adopted);
        assert_eq!(adopted.adopted_merge_cut_id.as_deref(), Some("cut_merge_1"));
    }

    /// A temp directory removed when the binding drops, panic included. Owning
    /// the directory rather than the `.sqlite` file means the `-shm`/`-wal`
    /// sidecars go with it.
    struct TempBranchDir(std::path::PathBuf);

    impl TempBranchDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "whipplescript-branches-{}-{}-{}",
                label,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos(),
            ));
            std::fs::create_dir_all(&dir).expect("create branches temp dir");
            Self(dir)
        }

        fn store_path(&self) -> std::path::PathBuf {
            self.0.join("branches.sqlite")
        }
    }

    impl Drop for TempBranchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A branch write contended by another connection's held write lock must
    /// *wait* for it, not fail.
    ///
    /// This is the regression for the defect that surfaced downstream as an
    /// intermittent `DatabaseBusy` on a perfectly ordinary commit: every write
    /// here opened a *deferred* transaction, read a row, and only then wrote.
    /// SQLite refuses that SHARED→RESERVED upgrade immediately when another
    /// connection holds the write lock and does not run the busy handler for
    /// it, so the 5s `STORE_BUSY_TIMEOUT` these connections set never applied
    /// and the write failed in milliseconds. Raising the timeout would not have
    /// moved it; opening the transaction `Immediate` is what makes the timeout
    /// mean what it says.
    ///
    /// The elapsed-time assertion is load-bearing, not decoration: without it a
    /// holder thread that silently failed to take the lock would let this test
    /// pass while proving nothing.
    #[test]
    fn a_contended_write_waits_for_the_held_lock_instead_of_failing() {
        const HELD: std::time::Duration = std::time::Duration::from_millis(1_500);
        // Well inside STORE_BUSY_TIMEOUT, so a correct wait always completes.
        const SLACK: std::time::Duration = std::time::Duration::from_millis(250);

        let dir = TempBranchDir::new("contended-write");
        let path = dir.store_path();
        let mut store = BranchStore::open(&path).expect("open store");
        store.ensure_mainline("t0").expect("bootstrap mainline");

        // A second connection holds the write lock for a fixed span, the way a
        // concurrent worker's commit does.
        let holder_path = path.clone();
        let holding = std::sync::Arc::new(std::sync::Barrier::new(2));
        let held = std::sync::Arc::clone(&holding);
        let holder = std::thread::spawn(move || {
            let connection = Connection::open(&holder_path).expect("open holder");
            crate::establish_wal(&connection).expect("establish wal");
            // `BEGIN IMMEDIATE` takes RESERVED at once, which is what excludes
            // another writer; no row need actually change.
            connection
                .execute_batch("BEGIN IMMEDIATE")
                .expect("take the write lock");
            held.wait();
            std::thread::sleep(HELD);
            connection
                .execute_batch("ROLLBACK")
                .expect("release the lock");
        });

        holding.wait();
        let started = std::time::Instant::now();
        let outcome = store.advance_head(MAINLINE_BRANCH_ID, None, "cut_1", "manifest_a", "t1");
        let waited = started.elapsed();
        holder.join().expect("holder thread");

        assert!(
            matches!(outcome, Ok(AdvanceOutcome::Advanced(_))),
            "a contended write must wait for the lock, not fail: {outcome:?}"
        );
        assert!(
            waited + SLACK >= HELD,
            "the write returned after {waited:?}, so the holder never really held the lock \
             and this test proved nothing"
        );
    }
}
