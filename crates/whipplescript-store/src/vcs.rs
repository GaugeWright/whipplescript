//! The integrated versioned workspace: branches, content, working sets,
//! and merge composed into the user-facing VCS operations
//! (spec/versioned-workspace-research-note.md §4–§7; untie-substrate
//! readiness tracker Phases 1–2; `whip branch` is the CLI surface).
//!
//! `WorkspaceVcs` is the mediator's storage half: every verb is a
//! proposal over immutable content — a write mints a new cut, a merge
//! either adopts certified content or returns structured conflicts and
//! moves NOTHING, a discard closes a head without deleting history. No
//! destructive verb exists on this surface. Manifests are stored as
//! content-addressed JSON blobs; a branch row carries only pointers, so
//! branch creation stays O(1) and a hundred branches share every
//! unchanged blob.
//!
//! Merging runs the P1 pipeline end to end: rebase-down first when the
//! parent moved (silent when slice-disjoint, honest structured conflicts
//! when not — never a fake auto-merge), then the staleness-checked
//! merge-up that adopts the branch and advances the parent head. The CLI
//! process is the single writer per workspace (the mediator); optimistic
//! head guards make a racing writer a refused normal outcome rather
//! than a lost update.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

#[cfg(feature = "native")]
use crate::branches::BranchStore;
use crate::branches::{
    AdvanceOutcome, BranchRow, BranchStatus, Branches, CreateBranch, CreateBranchOutcome,
    CutRecord, CutRow, OpBranchDelta, OpBranchState, OpRow, RetargetOutcome, StatusOutcome,
    MAINLINE_BRANCH_ID,
};
use crate::content::ContentBlobs;
#[cfg(feature = "native")]
use crate::content::ContentStore;
use crate::files::FileStore;
use crate::merge::MergeSide;
use crate::merge::PathConflict;
use crate::reconcile::{plan_merge_up, plan_rebase_down, MergeUpPlan, RebaseDownPlan};
use crate::text_merge::{MergePiece, Provenance, RegionResolution, TextMergeOutcome};
use crate::working_set::VirtualWorkingSet;
use crate::{StoreError, StoreResult};

/// Outcome of a base-carrying editor save (spec/text-merge-spec.md §12.1).
/// `Conflicted` wrote NOTHING and is transient — never persisted as an
/// open-conflict row (the resolving human is present; branch-merge
/// conflicts keep their rows).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SaveWithBaseOutcome {
    /// The head hadn't moved (or the path's content hadn't): a plain
    /// mediated write.
    Written {
        cut_id: String,
    },
    /// The head had moved; draft and head composed cleanly (possibly via
    /// region memory) and the merged body is the new head. `pieces`
    /// carries provenance for the editor's review fold.
    Merged {
        cut_id: String,
        merged: String,
        pieces: Vec<MergePiece>,
    },
    /// Real divergence: nothing written; the regions are the fold payload.
    Conflicted {
        head_cut_id: Option<String>,
        pieces: Vec<MergePiece>,
    },
    BranchMissing,
    BranchNotActive,
    /// The claimed base cut is not a recorded cut — the client's read
    /// base is unverifiable, so nothing is merged or written.
    UnknownBaseCut,
}

/// A read-only merge preview (spec §12.1): exactly what `save_with_base`
/// would compute, without writing — the editor's live fold.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergePreview {
    pub head_cut_id: Option<String>,
    pub clean: bool,
    pub pieces: Vec<MergePiece>,
}

/// One VCS write/remove outcome: the new cut, or the refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VcsWriteOutcome {
    Written {
        cut_id: String,
        manifest_hash: String,
    },
    BranchMissing,
    BranchNotActive,
}

/// One merge outcome. `Conflicted` moves nothing; the conflicts are the
/// notification-and-ask payload (resolve by writing the merged content on
/// the branch, then merge again).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VcsMergeOutcome {
    Adopted {
        merge_cut_id: String,
        into_branch_id: String,
    },
    /// Keep-open merge landed (`merge_keeping`): the parent adopted the
    /// CONTENT and the branch rebased onto the merge cut — empty delta,
    /// still active. A long-lived member line promoting its work, not a
    /// proposal closing.
    Landed {
        merge_cut_id: String,
        into_branch_id: String,
    },
    Conflicted {
        conflicts: Vec<PathConflict>,
    },
    BranchMissing,
    BranchNotActive,
    /// Mainline has no parent to merge into.
    NoParent,
}

/// Verdict of a source-aware merge attempt on one conflicted path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceMergeVerdict {
    /// The edits' slices are provably disjoint: this is the certified
    /// merged source (the composition theorem's crossover).
    Certified { merged: String },
    /// No certificate — stays an honest conflict.
    Conflict,
}

/// The declaration-granularity source-merge seam (vw note §6.1): the
/// store crate owns WHERE source-aware refinement applies (conflicted
/// `.whip` paths); the host installs HOW (the kernel's parser-backed
/// merger). Absent merger = every source conflict escalates (fail
/// closed).
pub trait SourceMerger {
    fn merge_source(&self, base: Option<&str>, ours: &str, theirs: &str) -> SourceMergeVerdict;
}

/// One declaration's canonical identity + content hash as the store sees it
/// (DR-0054; the parser-side `DeclCanon` crosses the seam as plain strings).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonDecl {
    /// Normalized header line (`rule triage`, `class Report`).
    pub identity: String,
    /// SHA-256/128 over the canonical print.
    pub canon_hash: String,
    /// The rename-detection key: the canonical print with the header's
    /// name replaced by `_` (DR-0054 Decision 3).
    pub rename_hash: String,
}

/// The DR-0054 canonicalization seam, same inversion as [`SourceMerger`]:
/// the store owns WHERE declaration identity applies (change-unit index
/// sub-rows for `.whip` paths), the host installs HOW (the parser-backed
/// canonicalizer). `None` = the source has no canonical form; callers keep
/// path-level rows only — attribution never guesses (fail closed).
pub trait DeclCanonicalizer {
    fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>>;
}

/// One reconciliation-daemon tick over one branch (the executor of
/// reconcile.rs's plans; lifecycle in ReconciliationDaemonLifecycle.tla).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconcileOutcome {
    UpToDate,
    /// The parent's delta folded in (silently when blob-disjoint; via
    /// certified source merges at quiescence).
    Rebased {
        rebase_cut_id: String,
    },
    /// Mid-run and the delta intersects: nothing moves until quiescence.
    DeferredMidRun,
    /// At quiescence the residual conflicts are the notification-and-ask.
    Conflicts {
        conflicts: Vec<PathConflict>,
    },
    BranchMissing,
    BranchNotActive,
    NoParent,
}

/// One greedy in-stream sync (auto-admit) or boundary promotion: the
/// branch's divergence lands on the line and the branch re-points fully
/// in sync — it KEEPS WORKING (never adopted), per the workstream tier's
/// per-contribution model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SyncOutcome {
    /// Nothing to admit (already in sync with the line).
    UpToDate,
    Synced {
        sync_cut_id: String,
    },
    /// Per-contribution isolation: this member's sync failed honestly;
    /// the stream stays active, siblings proceed.
    Conflicts {
        conflicts: Vec<PathConflict>,
    },
    /// Dual identity's detection (jj import): both heads carry the SAME
    /// change id with DIFFERENT content — the same edit, evolved apart.
    /// Both versions surface; nothing merges silently.
    DivergentChange {
        change_id: String,
        ours_manifest_hash: Option<String>,
        theirs_manifest_hash: Option<String>,
    },
    BranchMissing,
    BranchNotActive,
    LineMissing,
    LineNotActive,
}

/// Merge-probe outcome (`git merge-tree`'s replacement): what `merge`
/// WOULD do, computed without moving any pointer. Certified-refined
/// content written during the probe is harmless — content-addressed and
/// unreferenced until a real merge lands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeProbeOutcome {
    /// Nothing to merge: the parent already has the branch's content.
    UpToDate,
    /// The merge would adopt cleanly, producing this manifest.
    Clean {
        merged_manifest_hash: String,
        changed_paths: Vec<String>,
    },
    Conflicted {
        conflicts: Vec<PathConflict>,
    },
    BranchMissing,
    BranchNotActive,
    NoParent,
}

/// DR-0078's exact-cut promotion commit. The workstream store owns the
/// reservation around this call; this method owns the one mutable-name CAS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundaryPromotionOutcome {
    Promoted {
        main_cut_id: String,
        manifest_hash: String,
        ref_position: u64,
        ref_receipt_handle: String,
    },
    Conflicted {
        conflicts: Vec<PathConflict>,
    },
    ExpectedCutsMoved {
        current_line_cut: Option<String>,
        current_main_cut: Option<String>,
    },
    StreamLineMissing,
    StreamLineNotActive,
    MainMissing,
    MainNotActive,
}

/// Restore (un-tie's `revert` mapping): re-point the branch head to a
/// recorded cut's state AS A NEW CUT — a proposal over the immutable
/// record, never a rewind of history.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestoreOutcome {
    Restored {
        cut_id: String,
        manifest_hash: String,
    },
    /// The head already carries that state.
    AlreadyThere,
    CutMissing,
    BranchMissing,
    BranchNotActive,
}

/// A named quiescence cut (un-tie's commit-per-turn-finalize mapping).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct QuiescentCut {
    pub cut_id: String,
    pub manifest_hash: String,
    pub change_id: String,
}

/// Status + hash plumbing for one branch, consumable by an external
/// host: where the head is, how far the branch diverged from its point
/// (ahead), and whether the parent moved past it (behind).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BranchStatusReport {
    pub branch: BranchRow,
    pub head_change_id: Option<String>,
    /// Paths the branch changed since its branch point.
    pub ahead_paths: Vec<String>,
    /// The parent's head moved past the branch point: a reconcile would
    /// fold new parent content down.
    pub behind: bool,
    pub bound_instances: Vec<String>,
}

/// One entry of `reconcile-list`: a branch with pending flow in either
/// direction.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ReconcileEntry {
    pub branch_id: String,
    pub target_branch_id: String,
    pub ahead_paths: usize,
    pub behind: bool,
}

/// One path's write-attribution: who last wrote it, as what change,
/// from what origin (blame-superseding — provenance, not line ranges).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PathAttribution {
    pub path: String,
    pub cut_id: Option<String>,
    pub change_id: Option<String>,
    pub origin: Option<String>,
    /// WHO last wrote it (DR-0052; `None` = pre-actor cut).
    pub actor: Option<String>,
    pub recorded_at: Option<String>,
}

/// A previewed `undo <selection>` (dry-run is the default interaction:
/// agents show before they do).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UndoSelectionPlan {
    pub selected: Vec<crate::selection::ChangeUnit>,
    /// Retained later units whose inputs the undo would remove — a
    /// non-empty list refuses the apply (selective-undo.maude).
    pub stranded: Vec<crate::selection::ChangeUnit>,
    /// Path → the content it reverts to (`None` = the path disappears).
    pub reverts: BTreeMap<String, Option<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UndoSelectionOutcome {
    Proposed {
        cut_id: String,
        manifest_hash: String,
        reverted_paths: Vec<String>,
    },
    WouldStrand {
        stranded: Vec<crate::selection::ChangeUnit>,
    },
    NothingSelected,
    BranchMissing,
    BranchNotActive,
}

/// Outcome of `transport <selection>` / `adopt --only <selection>`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportOutcome {
    Transported {
        cut_id: String,
        change_id: String,
        moved_paths: Vec<String>,
    },
    /// Every selected unit is already on the target.
    UpToDate,
    /// The selection overlaps the target's own divergence: honest
    /// conflicts, nothing moves.
    Conflicted {
        conflicts: Vec<PathConflict>,
    },
    NothingSelected,
    BranchMissing,
    TargetMissing,
    TargetNotActive,
}

/// How to resolve one conflict item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolutionChoice<'a> {
    TakeOurs,
    TakeTheirs,
    Body(&'a str),
}

/// Outcome of a per-item conflict resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolveOutcome {
    Resolved {
        cut_id: String,
        /// The resolution's content hash (`None` = resolved by deletion).
        resolution: Option<String>,
    },
    NoOpenConflict,
    /// The chosen side's payload is gone (erased) and cannot be
    /// re-materialized.
    ContentUnavailable,
    BranchMissing,
    BranchNotActive,
}

/// Outcome of `undo-op`.
/// Outcome of [`WorkspaceVcs::fork_binding_for_instance`] — the branch
/// half of a chat fork. Refusals are data, not errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstanceForkBinding {
    /// The fork branch was created at the source line's head and the
    /// target instance bound to it at birth.
    Forked {
        source_branch_id: String,
        fork_branch: Box<BranchRow>,
    },
    /// The source instance has no branch binding: the fork is thread-only.
    SourceUnbound,
    /// The source's recorded branch is missing or no longer active.
    SourceBranchUnavailable { branch_id: String },
    /// The requested fork branch id (or name) is held by an unrelated line.
    ForkBranchIdTaken { branch_id: String },
    /// The target instance is already bound elsewhere (bind is write-once).
    TargetAlreadyBound { branch_id: String },
}

/// Exact historical branch half of a host point-fork. Unlike
/// `InstanceForkBinding`, the caller supplies the immutable source cut; later
/// movement of either the source or destination line cannot replace it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactInstanceForkBinding {
    Forked {
        source_branch_id: String,
        source_cut_id: String,
        fork_branch: Box<BranchRow>,
        evidence_handle: String,
    },
    SourceUnbound,
    SourceBranchUnavailable {
        branch_id: String,
    },
    SourceCutMissing {
        cut_id: String,
    },
    SourceCutNotOnBranch {
        cut_id: String,
        recorded_branch_id: String,
    },
    ForkBranchIdTaken {
        branch_id: String,
    },
    TargetAlreadyBound {
        branch_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactInstanceForkPreflight {
    Ready,
    Refused(ExactInstanceForkBinding),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UndoOpOutcome {
    Undone {
        undo_op_id: String,
    },
    /// The moved-head refusal (op-undo.maude's bite): some touched
    /// branch is no longer where the op left it.
    HeadMoved {
        branch_id: String,
        current_head_cut_id: Option<String>,
        expected_head_cut_id: Option<String>,
    },
    OpMissing,
    /// The op moved no branch pointers (e.g. an erasure record).
    NothingToUndo,
}

/// DR-0086 Decision 1: the kernel's read-only view of the versioned
/// workspace — the FRONTIER. Deliberately narrow: the content maps
/// freshness evaluates against, the change-unit window the witness and
/// selection scans read, and file bodies at the head. Never a write
/// surface — "the kernel reads the world freely; it changes the world only
/// through the governed verbs" (DR-0086 Decision 2), and widening this
/// trait toward writes is that record's Decision 4 to make, not a rider.
///
/// The inert contract: an empty or untouched store answers `Ok(None)` /
/// empty, never an error — a workspace that has never used the VCS behaves
/// as if the world were empty, which preserves every zero-setup behavior
/// by content rather than by absence.
pub trait FrontierRead {
    /// The branch's head cut id and frontier content maps. `Ok(None)` = no
    /// such branch (including the untouched store).
    fn frontier_content(
        &self,
        branch_id: &str,
    ) -> StoreResult<Option<(Option<String>, crate::freshness::FrontierContent)>>;

    /// The branch's change-unit window, oldest first. Empty for an absent
    /// branch.
    fn frontier_change_units(
        &self,
        branch_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<crate::selection::ChangeUnit>>;

    /// A file body at the branch head. `Ok(None)` = no such file or branch.
    fn frontier_file(&self, branch_id: &str, path: &str) -> StoreResult<Option<String>>;
}

/// The frontier of a workspace with no versioned world at all: everything
/// inert. The facade's stand-in wherever no branch store participates, and
/// the fixture for kernel tests that need the bound satisfied and nothing
/// else.
#[derive(Clone, Copy, Debug, Default)]
pub struct InertFrontier;

impl FrontierRead for InertFrontier {
    fn frontier_content(
        &self,
        _branch_id: &str,
    ) -> StoreResult<Option<(Option<String>, crate::freshness::FrontierContent)>> {
        Ok(None)
    }

    fn frontier_change_units(
        &self,
        _branch_id: &str,
        _limit: usize,
    ) -> StoreResult<Vec<crate::selection::ChangeUnit>> {
        Ok(Vec::new())
    }

    fn frontier_file(&self, _branch_id: &str, _path: &str) -> StoreResult<Option<String>> {
        Ok(None)
    }
}

pub struct WorkspaceVcs<B: Branches, C: ContentBlobs> {
    branches: B,
    content: C,
    source_merger: Option<Box<dyn SourceMerger>>,
    decl_canonicalizer: Option<Box<dyn DeclCanonicalizer>>,
    /// The acting principal every cut this handle records is attributed
    /// to (DR-0052 Decision 1: authorship observed at the mediator, so
    /// the handle's constructor — CLI seam, harness, daemon — decides,
    /// never the content). `None` = an un-attributed legacy caller.
    actor: Option<String>,
    /// The motivating work item / incident the current operation carries
    /// (repair sets it per incident; ordinary writes leave it unset).
    intent: Option<String>,
    /// `workspace.*` facts queued by operations, drained by the caller
    /// (DR-0052 A5: the store observes, the mediator surface routes).
    pending_facts: Vec<(String, serde_json::Value)>,
}

/// The native workspace VCS: rusqlite-backed branch + content stores.
#[cfg(feature = "native")]
pub type NativeWorkspaceVcs = WorkspaceVcs<BranchStore, ContentStore>;

impl<B: Branches, C: ContentBlobs> FrontierRead for WorkspaceVcs<B, C> {
    fn frontier_content(
        &self,
        branch_id: &str,
    ) -> StoreResult<Option<(Option<String>, crate::freshness::FrontierContent)>> {
        WorkspaceVcs::frontier_content(self, branch_id)
    }

    fn frontier_change_units(
        &self,
        branch_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<crate::selection::ChangeUnit>> {
        self.change_units(branch_id, limit)
    }

    fn frontier_file(&self, branch_id: &str, path: &str) -> StoreResult<Option<String>> {
        self.read(branch_id, path)
    }
}

/// A stored manifest as it lies: a tree root to descend, or the flat map cuts
/// carried before DR-0070 §1.
///
/// Host-agnostic, like everything it serves — placed with the branch impl below
/// rather than beside `NativeWorkspaceVcs`, where an earlier edit put it BETWEEN
/// that alias's `#[cfg(feature = "native")]` and the item the attribute
/// annotates. Native builds were unaffected and every native test passed; the
/// wasm build lost the gate on `impl NativeWorkspaceVcs` and stopped compiling.
enum RawManifest {
    Tree(String),
    Flat(BTreeMap<String, String>),
}

/// Fold a change set into a flat manifest.
fn fold_changes(
    manifest: &mut BTreeMap<String, String>,
    changes: &BTreeMap<String, Option<String>>,
) {
    for (path, value) in changes {
        match value {
            Some(id) => {
                manifest.insert(path.clone(), id.clone());
            }
            None => {
                manifest.remove(path);
            }
        }
    }
}

#[cfg(feature = "native")]
impl NativeWorkspaceVcs {
    pub fn open(
        branches_path: impl AsRef<Path>,
        content_path: impl AsRef<Path>,
    ) -> StoreResult<Self> {
        Ok(Self {
            branches: BranchStore::open(branches_path)?,
            content: ContentStore::open(content_path)?,
            source_merger: None,
            decl_canonicalizer: None,
            actor: None,
            intent: None,
            pending_facts: Vec::new(),
        })
    }

    /// Reclaim orphaned content — the residue of superseded working sets,
    /// refused imports, and raced saves. Roots = everything the branch
    /// plane can still name (every recorded cut's manifest and its
    /// entries, branch pointers, remembered resolutions, conflict sides);
    /// the sweep is conservative by construction (chunk tier and erasure
    /// tombstones untouched), so archaeology keeps everything a recorded
    /// cut can reach and a wrong root set can only retain too much.
    ///
    /// DR-0068 §5: run-held cuts are added to the root set explicitly. Today
    /// that changes nothing — every recorded cut is already a root, so no
    /// cut's closure is collectable and the pin is not yet load-bearing. It is
    /// wired now precisely because that stops being true the moment retention
    /// (research note §15) begins pruning recorded cuts: the guard exists
    /// before the thing that needs it, rather than being remembered afterwards.
    pub fn purge_unreachable(&mut self, now: &str) -> StoreResult<crate::content::PurgeOutcome> {
        let mut roots = self.branches.reachability_roots()?;
        for cut_id in self.branches.pinned_cuts(now)? {
            if let Some(manifest_hash) = self.branches.cut_manifest_hash(&cut_id)? {
                roots.insert(manifest_hash);
            }
        }
        // A root that is a MANIFEST names content ids: expand it.
        //
        // A TREE manifest (DR-0070 §1) must be walked WHOLE, not one level:
        // interior nodes and the leaves under them would otherwise look
        // unreachable, and the sweep would delete content a recorded cut still
        // names. A flat manifest keeps the old one-level expansion.
        // (Non-manifest roots that happen to parse as a string map add only
        // phantom ids — retention noise, never a wrong delete.)
        for hash in roots.clone() {
            if let Some(body) = self.content.get(&hash)? {
                if crate::manifest_tree::is_node(&body) {
                    roots.extend(crate::manifest_tree::reachable_ids(&self.content, &hash)?);
                } else if let Ok(manifest) = serde_json::from_str::<BTreeMap<String, String>>(&body)
                {
                    roots.extend(manifest.into_values());
                }
            }
        }
        self.content.purge_unreachable(&roots)
    }
}

impl<B: Branches, C: ContentBlobs> WorkspaceVcs<B, C> {
    fn require_head_reservation(&self, branch_id: &str, reservation_id: &str) -> StoreResult<()> {
        if self.branches.head_reservation(branch_id)?.as_deref() != Some(reservation_id) {
            return Err(StoreError::Conflict(format!(
                "stream line `{branch_id}` is not frozen by reservation `{reservation_id}`"
            )));
        }
        Ok(())
    }

    fn verify_recorded_promotion_cut(
        recorded: Option<&CutRow>,
        proposed_main_cut: &str,
        expected_main_cut: Option<&str>,
        manifest_hash: &str,
        origin: &str,
    ) -> StoreResult<()> {
        let recorded = recorded.ok_or_else(|| {
            StoreError::Conflict("proposed promotion cut is unavailable".to_owned())
        })?;
        if recorded.change_id != proposed_main_cut
            || recorded.branch_id != MAINLINE_BRANCH_ID
            || recorded.manifest_hash != manifest_hash
            || recorded.parent_cut_id.as_deref() != expected_main_cut
            || recorded.origin.as_deref() != Some(origin)
        {
            return Err(StoreError::Conflict(format!(
                "cut `{proposed_main_cut}` already names different immutable content or provenance"
            )));
        }
        Ok(())
    }

    fn boundary_receipt_handle(
        &self,
        stream_line_id: &str,
        expected_main_cut: Option<&str>,
        proposed_main_cut: &str,
        manifest_hash: &str,
        ref_position: u64,
    ) -> String {
        format!(
            "sha256:{}",
            crate::chunking::content_hash_hex(
                format!(
                    "workstream-boundary-v1|{stream_line_id}|{}|{proposed_main_cut}|{manifest_hash}|{ref_position}",
                    expected_main_cut.unwrap_or("")
                )
                .as_bytes()
            )
        )
    }

    /// Recover the evidence for an already-landed DR-0078 Main cut without
    /// issuing another CAS. `None` means Main does not currently name that cut
    /// or the immutable cut record is unavailable.
    ///
    /// Governed write surface (DR-0091): every call site is pinned by
    /// `scripts/check-governed-doors.sh` — a new caller belongs behind a
    /// kernel door, never here directly.
    pub fn boundary_ref_evidence(
        &self,
        stream_line_id: &str,
        expected_main_cut: Option<&str>,
        proposed_main_cut: &str,
    ) -> StoreResult<Option<(u64, String)>> {
        let Some(main) = self.branches.get_branch(MAINLINE_BRANCH_ID)? else {
            return Ok(None);
        };
        if main.head_cut_id.as_deref() != Some(proposed_main_cut) {
            return Ok(None);
        }
        let Some(cut) = self.branches.get_cut(proposed_main_cut)? else {
            return Ok(None);
        };
        let ref_position = u64::try_from(
            self.branches
                .list_cuts(MAINLINE_BRANCH_ID, usize::MAX)?
                .len(),
        )
        .unwrap_or(u64::MAX);
        Ok(Some((
            ref_position,
            self.boundary_receipt_handle(
                stream_line_id,
                expected_main_cut,
                proposed_main_cut,
                &cut.manifest_hash,
                ref_position,
            ),
        )))
    }

    /// Compose a workspace VCS from any host's branch + content seams
    /// (the DO host passes its `DoSql`-backed implementations).
    pub fn from_parts(branches: B, content: C) -> Self {
        Self {
            branches,
            content,
            source_merger: None,
            decl_canonicalizer: None,
            actor: None,
            intent: None,
            pending_facts: Vec::new(),
        }
    }

    /// Install the host's declaration-granularity source merger (the
    /// kernel's parser-backed implementation). Fail-closed default: no
    /// merger, no source-aware refinement.
    pub fn set_source_merger(&mut self, merger: Box<dyn SourceMerger>) {
        self.source_merger = Some(merger);
    }

    pub fn set_decl_canonicalizer(&mut self, canonicalizer: Box<dyn DeclCanonicalizer>) {
        self.decl_canonicalizer = Some(canonicalizer);
    }

    /// Attribute every cut this handle records to `actor` (DR-0052:
    /// `s:<session>` / `instance:<id>` / `human:<op>` / `root` /
    /// `git:<author>` / `mediator`). Set at construction seams only —
    /// the acting principal is a property of who holds the handle.
    pub fn set_actor(&mut self, actor: Option<String>) {
        self.actor = actor;
    }

    /// Stamp subsequent cuts with the motivating work item / incident id
    /// (`intent(...)` atom's data source). Cleared the same way.
    pub fn set_intent(&mut self, intent: Option<String>) {
        self.intent = intent;
    }

    /// Queue a `workspace.*` fact (DR-0052 A5). The store never routes —
    /// the caller (CLI mediator surface, daemon) drains
    /// [`Self::take_pending_facts`] and delivers to bound running
    /// instances. Generated-only by construction: user `record` mints
    /// capitalized class facts, so dotted `workspace.*` names are
    /// unrecordable from source.
    fn note_fact(&mut self, name: &str, branch_id: &str, mut payload: serde_json::Value) {
        if let Some(map) = payload.as_object_mut() {
            map.insert("branch".to_owned(), serde_json::json!(branch_id));
        }
        self.pending_facts.push((name.to_owned(), payload));
    }

    /// Drain the facts queued since the last drain, oldest first.
    pub fn take_pending_facts(&mut self) -> Vec<(String, serde_json::Value)> {
        std::mem::take(&mut self.pending_facts)
    }

    /// The op-undo moved-head refusal, as a fact (op-undo.maude's bite
    /// made observable — a DR-0052 repair arming signal).
    fn note_head_moved(&mut self, op_id: &str, branch_id: &str, at: &str) {
        let payload = serde_json::json!({
            "op": "undo-op",
            "reason": "head-moved",
            "op_id": op_id,
            "by": self.actor,
            "at": at,
        });
        self.note_fact("vcs.op.refused", branch_id, payload);
    }

    /// Bootstrap the workspace: the mainline branch exists after this.
    pub fn init(&mut self, at: &str) -> StoreResult<BranchRow> {
        self.branches.ensure_mainline(at)
    }

    pub fn create_branch(
        &mut self,
        branch_id: &str,
        name: Option<&str>,
        parent_branch_id: &str,
        at: &str,
    ) -> StoreResult<CreateBranchOutcome> {
        self.fork_with_lineage(branch_id, name, parent_branch_id, None, at)
    }

    /// Fork with lineage (un-tie's `fork-with-shared-ancestry`): a new
    /// branch off `from_branch`, at its current head or at a pinned
    /// earlier cut. The lineage (parent pointer + branch-point cut) is
    /// recorded on the row; the fork is an op-log entry.
    pub fn fork_with_lineage(
        &mut self,
        branch_id: &str,
        name: Option<&str>,
        from_branch: &str,
        at_cut_id: Option<&str>,
        at: &str,
    ) -> StoreResult<CreateBranchOutcome> {
        self.branches.ensure_mainline(at)?;
        let pinned = match at_cut_id {
            None => None,
            Some(cut_id) => {
                let Some(cut) = self.branches.get_cut(cut_id)? else {
                    return Err(StoreError::Conflict(format!(
                        "unknown cut `{cut_id}`; fork-with-lineage needs a recorded cut"
                    )));
                };
                Some((cut_id.to_owned(), cut.manifest_hash))
            }
        };
        let outcome = self.branches.create_branch(CreateBranch {
            branch_id,
            name,
            parent_branch_id: from_branch,
            at_cut: pinned
                .as_ref()
                .map(|(cut, manifest)| (cut.as_str(), manifest.as_str())),
            created_at: at,
            idempotency_key: None,
        })?;
        if let CreateBranchOutcome::Created(row) = &outcome {
            self.log_op(
                &format!("op-create-{branch_id}"),
                "create",
                vec![Self::op_delta(None, row)],
                Some(&format!("from:{from_branch}")),
                at,
            )?;
        }
        Ok(outcome)
    }

    pub fn get_branch(&self, branch_id: &str) -> StoreResult<Option<BranchRow>> {
        self.branches.get_branch(branch_id)
    }

    pub fn list_branches(&self, status: Option<BranchStatus>) -> StoreResult<Vec<BranchRow>> {
        self.branches.list_branches(status)
    }

    /// Re-home a branch under a new lineage parent (a chat retargeted
    /// onto a workstream). Pointer-only: the branch point stays the
    /// recorded divergence base, so the NEXT `reconcile_branch` folds the
    /// new parent's deltas down three-ways against it; `merge` now adopts
    /// into the new parent. Op-logged like every lineage movement.
    pub fn retarget(
        &mut self,
        branch_id: &str,
        new_parent_branch_id: &str,
        at: &str,
    ) -> StoreResult<RetargetOutcome> {
        let before = self.branches.get_branch(branch_id)?;
        let outcome = self
            .branches
            .retarget_branch(branch_id, new_parent_branch_id, at)?;
        if let RetargetOutcome::Retargeted(row) = &outcome {
            let origin = format!("retarget:{new_parent_branch_id}");
            self.log_op(
                &format!("op-retarget-{branch_id}-{at}"),
                "retarget",
                vec![Self::op_delta(before.as_ref(), row)],
                Some(&origin),
                at,
            )?;
        }
        Ok(outcome)
    }

    pub fn discard_branch(&mut self, branch_id: &str, at: &str) -> StoreResult<StatusOutcome> {
        let before = self.branches.get_branch(branch_id)?;
        let outcome = self.branches.discard_branch(branch_id, at)?;
        if let StatusOutcome::Done(row) = &outcome {
            self.log_op(
                &format!("op-discard-{branch_id}"),
                "discard",
                vec![Self::op_delta(before.as_ref(), row)],
                None,
                at,
            )?;
        }
        Ok(outcome)
    }

    /// One branch's pointer movement for the op log.
    fn op_delta(before: Option<&BranchRow>, after: &BranchRow) -> OpBranchDelta {
        OpBranchDelta {
            branch_id: after.branch_id.clone(),
            before: before.map(OpBranchState::of),
            after: OpBranchState::of(after),
        }
    }

    fn log_op(
        &mut self,
        op_id: &str,
        kind: &str,
        deltas: Vec<OpBranchDelta>,
        origin: Option<&str>,
        at: &str,
    ) -> StoreResult<()> {
        self.branches.record_op(op_id, kind, &deltas, origin, at)
    }

    /// The op log, newest first (the record–narrative separation: this IS
    /// the reflog, first-class).
    pub fn list_ops(&self, limit: usize) -> StoreResult<Vec<OpRow>> {
        self.branches.list_ops(limit)
    }

    pub fn get_op(&self, op_id: &str) -> StoreResult<Option<OpRow>> {
        self.branches.get_op(op_id)
    }

    pub fn get_cut(&self, cut_id: &str) -> StoreResult<Option<CutRow>> {
        self.branches.get_cut(cut_id)
    }

    pub fn list_cuts(&self, branch_id: &str, limit: usize) -> StoreResult<Vec<CutRow>> {
        self.branches.list_cuts(branch_id, limit)
    }

    /// DR-0070 §1 migration: **a compatibility read path keyed by shape**, and
    /// no rewrite of existing cuts.
    ///
    /// A manifest root written after the tree landed is a `manifest_tree` node;
    /// one written before is a flat JSON map. The two are told apart by reading
    /// the blob and trying the node shape first — a cut is immutable, so
    /// rewriting old manifests would mean minting new cut identities for cuts
    /// that already exist and are already referenced.
    ///
    /// The flat path therefore stays forever, not as a deprecation window but
    /// as the honest way to read history written before the tree.
    fn load_manifest(&self, hash: Option<&str>) -> StoreResult<BTreeMap<String, String>> {
        let Some(hash) = hash else {
            return Ok(BTreeMap::new());
        };
        self.load_manifest_opt(hash)?.ok_or_else(|| {
            StoreError::Conflict(format!(
                "manifest blob {hash} is absent from the content store"
            ))
        })
    }

    /// The same read, answering an absent root blob with `Ok(None)` instead of
    /// a conflict — for callers that treat an unreadable manifest as a cut to
    /// skip, and would otherwise fetch the root once to test whether it is
    /// there and again to read it.
    ///
    /// The shape test IS the parse: recognizing the root as a tree node yields
    /// the node the walk continues from, and a body that is not one falls
    /// through to the flat path exactly as before — including a malformed body,
    /// which still surfaces as the flat parse's error.
    fn load_manifest_opt(&self, hash: &str) -> StoreResult<Option<BTreeMap<String, String>>> {
        let Some(body) = self.content.get(hash)? else {
            return Ok(None);
        };
        if let Some(root) = crate::manifest_tree::parse_node(&body) {
            return Ok(Some(crate::manifest_tree::load_from(&self.content, root)?));
        }
        Ok(Some(serde_json::from_str(&body).map_err(StoreError::from)?))
    }

    /// DR-0070 §1: manifests are written as prolly trees, so a cut writes new
    /// bytes proportional to the change rather than to the workspace.
    ///
    /// Takes the WHOLE manifest, so it costs the workspace whatever moved.
    /// Where the caller knows what changed, [`Self::advance_manifest`] is the
    /// one to use.
    fn store_manifest(&self, manifest: &BTreeMap<String, String>) -> StoreResult<String> {
        crate::manifest_tree::build(&self.content, manifest)
    }

    /// Write the next cut's manifest from a BASE and the paths that changed.
    ///
    /// DR-0066 §8 refusal 2: nothing O(workspace) where its effect is
    /// O(change). Every write here loaded the whole manifest, folded a handful
    /// of paths into it, and rebuilt every node — so editing one file in a
    /// ten-thousand-file workspace cost ten thousand entries twice.
    ///
    /// A base written before the tree shipped is a flat map and has no spine to
    /// descend, so it is folded and rebuilt once; the cut it produces is a tree,
    /// and the next write to that branch is incremental.
    fn advance_manifest(
        &self,
        base_hash: Option<&str>,
        changes: &BTreeMap<String, Option<String>>,
    ) -> StoreResult<String> {
        let base = match base_hash {
            Some(hash) => self.load_manifest_opt_raw(hash)?,
            None => None,
        };
        match base {
            Some(RawManifest::Tree(root)) => {
                crate::manifest_tree::apply(&self.content, &root, changes)
            }
            Some(RawManifest::Flat(mut manifest)) => {
                fold_changes(&mut manifest, changes);
                self.store_manifest(&manifest)
            }
            None => {
                let mut manifest = BTreeMap::new();
                fold_changes(&mut manifest, changes);
                self.store_manifest(&manifest)
            }
        }
    }

    /// One path's content id on a branch, WITHOUT materializing the manifest.
    ///
    /// A keyed descent through the tree is O(depth); folding the whole manifest
    /// to look up one entry is O(workspace), which is the read half of the same
    /// refusal.
    fn manifest_entry(&self, base_hash: Option<&str>, path: &str) -> StoreResult<Option<String>> {
        let Some(hash) = base_hash else {
            return Ok(None);
        };
        match self.load_manifest_opt_raw(hash)? {
            Some(RawManifest::Tree(root)) => crate::manifest_tree::get(&self.content, &root, path),
            Some(RawManifest::Flat(manifest)) => Ok(manifest.get(path).cloned()),
            None => Ok(None),
        }
    }

    /// Recognize a stored manifest without materializing a tree one.
    fn load_manifest_opt_raw(&self, hash: &str) -> StoreResult<Option<RawManifest>> {
        let Some(body) = self.content.get(hash)? else {
            return Ok(None);
        };
        if crate::manifest_tree::is_node(&body) {
            return Ok(Some(RawManifest::Tree(hash.to_owned())));
        }
        Ok(Some(RawManifest::Flat(serde_json::from_str(&body)?)))
    }

    /// The branch's current file listing (path → content id).
    pub fn manifest(&self, branch_id: &str) -> StoreResult<Option<BTreeMap<String, String>>> {
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        Ok(Some(self.load_manifest(row.head_manifest_hash.as_deref())?))
    }

    /// The frontier's content maps for freshness evaluation (DR-0084
    /// Decision 3): every manifest path with its content id, and — for
    /// `.whip` paths when the canonicalizer is installed and the source has
    /// a canonical form — every declaration identity with its canonical
    /// hash. Non-canonicalizable paths contribute path entries only (fail
    /// closed, the DR-0054 posture). Returns the branch's head cut id
    /// alongside — the at-cut an attest records for witness scans.
    /// `Ok(None)` = no such branch.
    pub fn frontier_content(
        &self,
        branch_id: &str,
    ) -> StoreResult<Option<(Option<String>, crate::freshness::FrontierContent)>> {
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        let manifest = self.load_manifest(row.head_manifest_hash.as_deref())?;
        let mut frontier = crate::freshness::FrontierContent::default();
        for (path, content_id) in &manifest {
            frontier.paths.insert(path.clone(), content_id.clone());
            if !path.ends_with(".whip") {
                continue;
            }
            let Some(canonicalizer) = self.decl_canonicalizer.as_deref() else {
                continue;
            };
            let Some(text) = self.content.get(content_id)? else {
                continue; // unreadable blob: path entry only, fail closed
            };
            let Some(decls) = canonicalizer.canonical_declarations(&text) else {
                continue; // no canonical form: path entry only, fail closed
            };
            for decl in decls {
                frontier
                    .decl_renames
                    .insert(decl.identity.clone(), decl.rename_hash);
                frontier.decls.insert(decl.identity, decl.canon_hash);
            }
        }
        Ok(Some((row.head_cut_id.clone(), frontier)))
    }

    /// Read a file's body on a branch. `Ok(None)` = no such file there.
    ///
    /// A keyed descent, not a fold: this materialized the branch's whole
    /// manifest to look up one path until 2026-08-26, so reading one file cost
    /// the workspace (DR-0066 §8 refusal 2).
    pub fn read(&self, branch_id: &str, path: &str) -> StoreResult<Option<String>> {
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        let Some(id) = self.manifest_entry(row.head_manifest_hash.as_deref(), path)? else {
            return Ok(None);
        };
        self.content.get(&id)
    }

    /// Cut references normalize the empty-string sentinel (a rebase onto
    /// a target with NO head records "") back to `None`, so staleness
    /// comparisons never mistake "no head yet" for divergence.
    fn cut_ref(cut_id: &Option<String>) -> Option<&str> {
        cut_id.as_deref().filter(|cut| !cut.is_empty())
    }

    /// The change id a cut carries (falling back to the cut id itself for
    /// pre-identity cuts, so every cut HAS an intent identity).
    fn change_of(&self, cut_id: Option<&str>) -> StoreResult<Option<String>> {
        let Some(cut_id) = cut_id else {
            return Ok(None);
        };
        Ok(Some(
            self.branches
                .cut_change_id(cut_id)?
                .unwrap_or_else(|| cut_id.to_owned()),
        ))
    }

    /// Write (or remove) one path on a branch through its virtual working
    /// set, minting the next cut. Copy-on-write: no other branch and no
    /// prior cut changes.
    pub fn write(
        &mut self,
        branch_id: &str,
        path: &str,
        body: Option<&str>,
        cut_id: &str,
        at: &str,
    ) -> StoreResult<VcsWriteOutcome> {
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(VcsWriteOutcome::BranchMissing);
        };
        if row.status != BranchStatus::Active {
            return Ok(VcsWriteOutcome::BranchNotActive);
        }
        // Detached: a write records ONE path, and neither `write` nor `remove`
        // consults the base. Materializing the branch's manifest here to change
        // one entry was the read half of refusal 2 — a one-file edit paid for
        // the whole workspace before it paid for the whole workspace again on
        // the way out.
        let working_set = VirtualWorkingSet::detached(&self.content);
        match body {
            Some(body) => working_set
                .write(Path::new(path), body.as_bytes())
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
            None => working_set
                .remove(Path::new(path))
                .map_err(|error| StoreError::Conflict(error.to_string()))?,
        }
        let manifest_hash =
            self.advance_manifest(row.head_manifest_hash.as_deref(), &working_set.changes())?;
        match self.branches.advance_head(
            branch_id,
            row.head_cut_id.as_deref(),
            cut_id,
            &manifest_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                // A write is a NEW intent: the change id is born equal to
                // the cut id and survives every later rewrite of the cut.
                let origin = format!("write:{path}");
                self.branches.record_cut(CutRecord {
                    cut_id,
                    change_id: cut_id,
                    branch_id,
                    manifest_hash: &manifest_hash,
                    parent_cut_id: row.head_cut_id.as_deref(),
                    origin: Some(&origin),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-{cut_id}"),
                    "write",
                    vec![Self::op_delta(Some(&row), &advanced)],
                    Some(&origin),
                    at,
                )?;
                self.note_fact(
                    "vcs.cut.recorded",
                    branch_id,
                    serde_json::json!({
                        "cut": cut_id,
                        "path": path,
                        "origin": origin,
                        "by": self.actor,
                        "intent": self.intent,
                        "at": at,
                    }),
                );
                // DR-0052 L4: keep the change-unit index warm at the
                // mutation point (best-effort; reads are correct either
                // way).
                let _ = self.maintain_change_unit_index(branch_id);
                Ok(VcsWriteOutcome::Written {
                    cut_id: cut_id.to_owned(),
                    manifest_hash,
                })
            }
            AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                "branch head moved during the write; retry".to_owned(),
            )),
            AdvanceOutcome::NotActive { .. } => Ok(VcsWriteOutcome::BranchNotActive),
            AdvanceOutcome::NotFound => Ok(VcsWriteOutcome::BranchMissing),
        }
    }

    /// Conflict refinement, three stages. First the RESOLUTION MEMORY
    /// (resolution-memory.maude): a conflict whose content-addressed
    /// triple was resolved before applies the stored resolution — the
    /// daemon's auto-propagation to descendants; rerere as ordinary
    /// workspace-plane knowledge, exact triple match only. Then
    /// source-aware refinement: for each conflicted `.whip` path with
    /// both sides present, ask the installed merger for a certified
    /// declaration-granularity merge. Last the token-level TEXT MERGE
    /// (spec/text-merge-spec.md; text-merge-compose.maude) for
    /// modify/modify on non-source text paths — word-atom composition
    /// under the certified never-fabricate/proximity rules; a clean
    /// composition folds, anything conflicted stays escalated (the
    /// region detail is deterministically recomputable from the
    /// content-addressed triple, so the conflict row needs no new
    /// fields). Remembered/certified/composed content is stored and
    /// folded, everything else stays an honest conflict (fail closed:
    /// delete-vs-modify, add/add, oversized, or erased bodies never
    /// refine; `.whip` sources never reach the text tier — the
    /// merge-slice bite is untouched).
    fn refine_source_conflicts(
        &self,
        conflicts: Vec<PathConflict>,
    ) -> StoreResult<(BTreeMap<String, String>, Vec<PathConflict>)> {
        let mut resolved = BTreeMap::new();
        let mut unremembered = Vec::new();
        for conflict in conflicts {
            let key = crate::branches::ConflictRow::triple_key(
                conflict.base.as_deref(),
                conflict.ours.as_deref(),
                conflict.theirs.as_deref(),
            );
            if let Some(resolution) = self.branches.resolution_memory(&key)? {
                // Apply only while the resolution's payload is live —
                // an erased resolution cannot re-materialize.
                if matches!(
                    self.content.status(&resolution)?,
                    crate::content::BlobStatus::Live { .. }
                ) {
                    resolved.insert(conflict.path.clone(), resolution);
                    continue;
                }
            }
            unremembered.push(conflict);
        }
        let mut remaining = Vec::new();
        if let Some(merger) = self.source_merger.as_deref() {
            for conflict in unremembered {
                let refinable = conflict.path.ends_with(".whip")
                    && conflict.ours.is_some()
                    && conflict.theirs.is_some();
                if !refinable {
                    remaining.push(conflict);
                    continue;
                }
                let base_body = match conflict.base.as_deref() {
                    Some(hash) => self.content.get(hash)?,
                    None => None,
                };
                let (Some(ours_body), Some(theirs_body)) = (
                    self.content
                        .get(conflict.ours.as_deref().expect("present"))?,
                    self.content
                        .get(conflict.theirs.as_deref().expect("present"))?,
                ) else {
                    remaining.push(conflict);
                    continue;
                };
                match merger.merge_source(base_body.as_deref(), &ours_body, &theirs_body) {
                    SourceMergeVerdict::Certified { merged } => {
                        let hash = self.content.put(&merged)?;
                        resolved.insert(conflict.path.clone(), hash);
                    }
                    SourceMergeVerdict::Conflict => remaining.push(conflict),
                }
            }
        } else {
            remaining = unremembered;
        }
        let text_config = crate::text_merge::TextMergeConfig::from_env();
        let mut still_conflicted = Vec::new();
        for conflict in remaining {
            // Eligibility (spec section 3): modify/modify with a present
            // base, non-source path; deletes and add/add stay escalated.
            let refinable = !conflict.path.ends_with(".whip")
                && conflict.base.is_some()
                && conflict.ours.is_some()
                && conflict.theirs.is_some();
            if !refinable {
                still_conflicted.push(conflict);
                continue;
            }
            let (Some(base_body), Some(ours_body), Some(theirs_body)) = (
                self.content
                    .get(conflict.base.as_deref().expect("present"))?,
                self.content
                    .get(conflict.ours.as_deref().expect("present"))?,
                self.content
                    .get(conflict.theirs.as_deref().expect("present"))?,
            ) else {
                still_conflicted.push(conflict);
                continue;
            };
            if !text_config.within_size(&base_body, &ours_body, &theirs_body) {
                still_conflicted.push(conflict);
                continue;
            }
            let outcome =
                crate::text_merge::text_merge(&base_body, &ours_body, &theirs_body, &text_config);
            match self.apply_region_memory(outcome)? {
                TextMergeOutcome::Clean { merged, .. } => {
                    let hash = self.content.put(&merged)?;
                    resolved.insert(conflict.path.clone(), hash);
                }
                TextMergeOutcome::Conflicted { .. } => still_conflicted.push(conflict),
            }
        }
        Ok((resolved, still_conflicted))
    }

    /// Region-level resolution memory key (spec §12.2): content hashes of
    /// the three region texts under a prefix distinct from the path-level
    /// triple key.
    fn region_key(base_text: &str, ours_text: &str, theirs_text: &str) -> String {
        format!(
            "rk|{}|{}|{}",
            crate::chunking::content_hash_hex(base_text.as_bytes()),
            crate::chunking::content_hash_hex(ours_text.as_bytes()),
            crate::chunking::content_hash_hex(theirs_text.as_bytes()),
        )
    }

    /// Record the region resolutions a resolved save carries (spec §12.2).
    /// Payloads land in the content store (erasure honesty applies for
    /// free); keys land in the shared resolution-memory table, first-wins,
    /// in BOTH side orientations — a conflict is symmetric in its sides,
    /// and the editor's (head, draft) orientation need not match a later
    /// branch merge's (branch, target).
    pub fn record_region_resolutions(
        &mut self,
        resolutions: &[RegionResolution],
        at: &str,
    ) -> StoreResult<()> {
        for resolution in resolutions {
            let payload = self.content.put(&resolution.resolution_text)?;
            self.branches.record_resolution_memory(
                &Self::region_key(
                    &resolution.base_text,
                    &resolution.ours_text,
                    &resolution.theirs_text,
                ),
                &payload,
                at,
            )?;
            self.branches.record_resolution_memory(
                &Self::region_key(
                    &resolution.base_text,
                    &resolution.theirs_text,
                    &resolution.ours_text,
                ),
                &payload,
                at,
            )?;
        }
        Ok(())
    }

    /// Refine a text-merge outcome through region memory (spec §12.3): a
    /// conflict region whose exact triple was resolved before — and whose
    /// payload is still live — becomes a `resolved` piece; partial memory
    /// stays honestly Conflicted (`TextMergeOutcome::from_pieces`, the
    /// invariant pinned in text-merge-compose.maude's memory tier).
    fn apply_region_memory(&self, outcome: TextMergeOutcome) -> StoreResult<TextMergeOutcome> {
        let TextMergeOutcome::Conflicted { pieces } = outcome else {
            return Ok(outcome);
        };
        let mut refined = Vec::with_capacity(pieces.len());
        for piece in pieces {
            match piece {
                MergePiece::Conflict {
                    base_text,
                    ours_text,
                    theirs_text,
                } => {
                    let key = Self::region_key(&base_text, &ours_text, &theirs_text);
                    let mut applied = None;
                    if let Some(payload) = self.branches.resolution_memory(&key)? {
                        if matches!(
                            self.content.status(&payload)?,
                            crate::content::BlobStatus::Live { .. }
                        ) {
                            applied = self.content.get(&payload)?;
                        }
                    }
                    refined.push(match applied {
                        Some(text) => MergePiece::Merged {
                            text,
                            provenance: Provenance::Resolved,
                        },
                        None => MergePiece::Conflict {
                            base_text,
                            ours_text,
                            theirs_text,
                        },
                    });
                }
                merged => refined.push(merged),
            }
        }
        Ok(TextMergeOutcome::from_pieces(refined))
    }

    /// A path's body at a specific recorded cut (the editor's read base).
    fn body_at_cut(&self, cut_id: &str, path: &str) -> StoreResult<Option<String>> {
        let Some(cut) = self.branches.get_cut(cut_id)? else {
            return Ok(None);
        };
        let manifest = self.load_manifest(Some(&cut.manifest_hash))?;
        let Some(id) = manifest.get(path) else {
            return Ok(None);
        };
        self.content.get(id)
    }

    /// The base-carrying editor save (spec §12.1). `resolutions` from a
    /// resolved fold are recorded FIRST — they are settled human knowledge
    /// regardless of this save's outcome. Head unmoved (by cut or by
    /// content) → plain write. Moved → three-way with ours = head (the
    /// line's content) and theirs = draft (the editor's proposal) through
    /// the same region-memory-aware merge as branch reconciliation: clean
    /// writes and returns provenance pieces; conflicted writes NOTHING and
    /// returns the regions as the fold payload. Bounded optimistic
    /// retries absorb a head advance racing the write.
    #[allow(clippy::too_many_arguments)]
    pub fn save_with_base(
        &mut self,
        branch_id: &str,
        path: &str,
        draft: &str,
        base_cut_id: &str,
        resolutions: &[RegionResolution],
        cut_id: &str,
        at: &str,
    ) -> StoreResult<SaveWithBaseOutcome> {
        self.record_region_resolutions(resolutions, at)?;
        if self.branches.get_cut(base_cut_id)?.is_none() {
            return Ok(SaveWithBaseOutcome::UnknownBaseCut);
        }
        for _ in 0..3 {
            let Some(branch) = self.branches.get_branch(branch_id)? else {
                return Ok(SaveWithBaseOutcome::BranchMissing);
            };
            let head_cut = branch.head_cut_id.clone();
            let base_body = self.body_at_cut(base_cut_id, path)?;
            let head_body = self.read(branch_id, path)?;
            if Self::cut_ref(&head_cut) == Some(base_cut_id) || head_body == base_body {
                return Ok(
                    match self.write(branch_id, path, Some(draft), cut_id, at)? {
                        VcsWriteOutcome::Written { cut_id, .. } => {
                            SaveWithBaseOutcome::Written { cut_id }
                        }
                        VcsWriteOutcome::BranchMissing => SaveWithBaseOutcome::BranchMissing,
                        VcsWriteOutcome::BranchNotActive => SaveWithBaseOutcome::BranchNotActive,
                    },
                );
            }
            let config = crate::text_merge::TextMergeConfig::from_env();
            let outcome = match (&base_body, &head_body) {
                (Some(base), Some(head)) if config.within_size(base, head, draft) => {
                    crate::text_merge::text_merge(base, head, draft, &config)
                }
                _ => {
                    // Concurrent create/delete, or oversized: one whole-
                    // file region — still eligible for exact-triple
                    // memory, never a silent winner.
                    TextMergeOutcome::from_pieces(vec![MergePiece::Conflict {
                        base_text: base_body.clone().unwrap_or_default(),
                        ours_text: head_body.clone().unwrap_or_default(),
                        theirs_text: draft.to_owned(),
                    }])
                }
            };
            match self.apply_region_memory(outcome)? {
                TextMergeOutcome::Clean { merged, pieces } => {
                    match self.write(branch_id, path, Some(&merged), cut_id, at) {
                        Ok(VcsWriteOutcome::Written { cut_id, .. }) => {
                            return Ok(SaveWithBaseOutcome::Merged {
                                cut_id,
                                merged,
                                pieces,
                            })
                        }
                        Ok(VcsWriteOutcome::BranchMissing) => {
                            return Ok(SaveWithBaseOutcome::BranchMissing)
                        }
                        Ok(VcsWriteOutcome::BranchNotActive) => {
                            return Ok(SaveWithBaseOutcome::BranchNotActive)
                        }
                        // The head advanced between merge and write:
                        // recompute against the new head.
                        Err(StoreError::Conflict(_)) => continue,
                        Err(other) => return Err(other),
                    }
                }
                TextMergeOutcome::Conflicted { pieces } => {
                    return Ok(SaveWithBaseOutcome::Conflicted {
                        head_cut_id: head_cut,
                        pieces,
                    })
                }
            }
        }
        Err(StoreError::Conflict(
            "branch head kept moving during save_with_base; retry".to_owned(),
        ))
    }

    /// Read-only twin of `save_with_base` (spec §12.1): what the save
    /// would compute, for the editor's live fold. `Ok(None)` = unknown
    /// base cut or branch.
    pub fn merge_preview(
        &self,
        branch_id: &str,
        path: &str,
        draft: &str,
        base_cut_id: &str,
    ) -> StoreResult<Option<MergePreview>> {
        if self.branches.get_cut(base_cut_id)?.is_none() {
            return Ok(None);
        }
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        let head_cut = branch.head_cut_id.clone();
        let base_body = self.body_at_cut(base_cut_id, path)?;
        let head_body = self.read(branch_id, path)?;
        if Self::cut_ref(&head_cut) == Some(base_cut_id) || head_body == base_body {
            return Ok(Some(MergePreview {
                head_cut_id: head_cut,
                clean: true,
                pieces: vec![MergePiece::Merged {
                    text: draft.to_owned(),
                    provenance: Provenance::Theirs,
                }],
            }));
        }
        let config = crate::text_merge::TextMergeConfig::from_env();
        let outcome = match (&base_body, &head_body) {
            (Some(base), Some(head)) if config.within_size(base, head, draft) => {
                crate::text_merge::text_merge(base, head, draft, &config)
            }
            _ => TextMergeOutcome::from_pieces(vec![MergePiece::Conflict {
                base_text: base_body.clone().unwrap_or_default(),
                ours_text: head_body.clone().unwrap_or_default(),
                theirs_text: draft.to_owned(),
            }]),
        };
        Ok(Some(match self.apply_region_memory(outcome)? {
            TextMergeOutcome::Clean { pieces, .. } => MergePreview {
                head_cut_id: head_cut,
                clean: true,
                pieces,
            },
            TextMergeOutcome::Conflicted { pieces } => MergePreview {
                head_cut_id: head_cut,
                clean: false,
                pieces,
            },
        }))
    }

    /// Record the CURRENT three-way's residue as the branch's open
    /// conflict set: new conflicts open (or re-open), open rows the
    /// latest three-way no longer produces are superseded — the table
    /// stays truthful to the latest reconciliation, never a stale block.
    fn sync_conflict_table(
        &mut self,
        branch_id: &str,
        current: &[PathConflict],
        at: &str,
    ) -> StoreResult<()> {
        let mut current_ids = std::collections::BTreeSet::new();
        for conflict in current {
            let conflict_id = crate::branches::ConflictRow::identity(
                branch_id,
                &conflict.path,
                conflict.base.as_deref(),
                conflict.ours.as_deref(),
                conflict.theirs.as_deref(),
            );
            current_ids.insert(conflict_id.clone());
            self.branches
                .record_conflict(&crate::branches::ConflictRow {
                    conflict_id,
                    branch_id: branch_id.to_owned(),
                    path: conflict.path.clone(),
                    base: conflict.base.clone(),
                    ours: conflict.ours.clone(),
                    theirs: conflict.theirs.clone(),
                    ours_label: conflict.ours_side.label.clone(),
                    theirs_label: conflict.theirs_side.label.clone(),
                    state: "open".to_owned(),
                    resolution: None,
                    recorded_at: at.to_owned(),
                    updated_at: at.to_owned(),
                })?;
        }
        for stale in self.branches.open_conflicts(branch_id)? {
            if !current_ids.contains(&stale.conflict_id) {
                self.branches
                    .set_conflict_state(&stale.conflict_id, "superseded", None, at)?;
            }
        }
        Ok(())
    }

    /// A clean three-way dissolves every open conflict on the branch.
    fn supersede_open_conflicts(&mut self, branch_id: &str, at: &str) -> StoreResult<()> {
        for stale in self.branches.open_conflicts(branch_id)? {
            self.branches
                .set_conflict_state(&stale.conflict_id, "superseded", None, at)?;
        }
        Ok(())
    }

    /// The branch's open conflict objects (the ask surface).
    pub fn open_conflicts(
        &self,
        branch_id: &str,
    ) -> StoreResult<Vec<crate::branches::ConflictRow>> {
        self.branches.open_conflicts(branch_id)
    }

    /// Resolve one open conflict per-item (vw note §7.3): take-ours /
    /// take-theirs / an authored body. The resolution is an ORDINARY
    /// provenance-carrying write on the branch (a cut with origin
    /// `resolve:<path>`), the conflict row closes, and the resolution
    /// enters the content-addressed memory — from where the daemon
    /// auto-propagates it to any descendant hitting the identical pair.
    pub fn resolve_conflict(
        &mut self,
        branch_id: &str,
        path: &str,
        choice: ResolutionChoice<'_>,
        cut_id: &str,
        at: &str,
    ) -> StoreResult<ResolveOutcome> {
        let open = self.branches.open_conflicts(branch_id)?;
        let Some(conflict) = open.into_iter().find(|row| row.path == path) else {
            return Ok(ResolveOutcome::NoOpenConflict);
        };
        let body = match choice {
            ResolutionChoice::TakeOurs => match conflict.ours.as_deref() {
                Some(hash) => self.content.get(hash)?,
                None => None,
            },
            ResolutionChoice::TakeTheirs => match conflict.theirs.as_deref() {
                Some(hash) => self.content.get(hash)?,
                None => None,
            },
            ResolutionChoice::Body(body) => Some(body.to_owned()),
        };
        let Some(body) = body else {
            // Take-side of a deletion or an erased payload: nothing to
            // materialize. Deleting IS a legal resolution when the side
            // is an absence.
            let deleting = matches!(
                (&choice, &conflict.ours, &conflict.theirs),
                (ResolutionChoice::TakeOurs, None, _) | (ResolutionChoice::TakeTheirs, _, None)
            );
            if !deleting {
                return Ok(ResolveOutcome::ContentUnavailable);
            }
            match self.write(branch_id, path, None, cut_id, at)? {
                VcsWriteOutcome::Written { .. } => {}
                VcsWriteOutcome::BranchMissing => return Ok(ResolveOutcome::BranchMissing),
                VcsWriteOutcome::BranchNotActive => return Ok(ResolveOutcome::BranchNotActive),
            }
            self.branches
                .set_conflict_state(&conflict.conflict_id, "resolved", None, at)?;
            return Ok(ResolveOutcome::Resolved {
                cut_id: cut_id.to_owned(),
                resolution: None,
            });
        };
        match self.write(branch_id, path, Some(&body), cut_id, at)? {
            VcsWriteOutcome::Written { .. } => {}
            VcsWriteOutcome::BranchMissing => return Ok(ResolveOutcome::BranchMissing),
            VcsWriteOutcome::BranchNotActive => return Ok(ResolveOutcome::BranchNotActive),
        }
        let resolution_hash = self.content.put(&body)?;
        self.branches.set_conflict_state(
            &conflict.conflict_id,
            "resolved",
            Some(&resolution_hash),
            at,
        )?;
        let key = crate::branches::ConflictRow::triple_key(
            conflict.base.as_deref(),
            conflict.ours.as_deref(),
            conflict.theirs.as_deref(),
        );
        self.branches
            .record_resolution_memory(&key, &resolution_hash, at)?;
        // The branch's own next three-way sees (base, RESOLUTION, theirs)
        // — the resolution was authored in full knowledge of theirs, so
        // it re-applies verbatim while theirs is unchanged; a moved
        // theirs changes the triple and is honestly a NEW conflict.
        let post_key = crate::branches::ConflictRow::triple_key(
            conflict.base.as_deref(),
            Some(&resolution_hash),
            conflict.theirs.as_deref(),
        );
        self.branches
            .record_resolution_memory(&post_key, &resolution_hash, at)?;
        Ok(ResolveOutcome::Resolved {
            cut_id: cut_id.to_owned(),
            resolution: Some(resolution_hash),
        })
    }

    /// One reconciliation-daemon tick for one branch: fold the parent's
    /// delta down. Blob-disjoint deltas fold in ANY phase (silent
    /// continuous rebase); everything that touches contested paths waits
    /// for quiescence, where certified source merges refine and the
    /// residue escalates as the ask. Executes reconcile.rs's plans
    /// against the branch store; lifecycle per
    /// ReconciliationDaemonLifecycle.tla.
    pub fn reconcile_branch(
        &mut self,
        branch_id: &str,
        quiescent: bool,
        rebase_cut_id: &str,
        at: &str,
    ) -> StoreResult<ReconcileOutcome> {
        self.reconcile_branch_against(branch_id, None, quiescent, rebase_cut_id, at)
    }

    /// `reconcile_branch` with an explicit sync target — a workstream
    /// member folds its STREAM LINE's deltas down (the caller resolves
    /// membership; store seams stay separate). `None` = the lineage
    /// parent.
    pub fn reconcile_branch_against(
        &mut self,
        branch_id: &str,
        target_id: Option<&str>,
        quiescent: bool,
        rebase_cut_id: &str,
        at: &str,
    ) -> StoreResult<ReconcileOutcome> {
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(ReconcileOutcome::BranchMissing);
        };
        if branch.status != BranchStatus::Active {
            return Ok(ReconcileOutcome::BranchNotActive);
        }
        let Some(parent_id) = target_id
            .map(str::to_owned)
            .or_else(|| branch.parent_branch_id.clone())
        else {
            return Ok(ReconcileOutcome::NoParent);
        };
        let Some(parent) = self.branches.get_branch(&parent_id)? else {
            return Ok(ReconcileOutcome::NoParent);
        };
        if Self::cut_ref(&branch.branch_point_cut_id) == Self::cut_ref(&parent.head_cut_id) {
            self.supersede_open_conflicts(branch_id, at)?;
            return Ok(ReconcileOutcome::UpToDate);
        }
        let branch_side = MergeSide {
            label: branch_id.to_owned(),
            cut_id: branch.head_cut_id.clone(),
        };
        let parent_side = MergeSide {
            label: parent_id.clone(),
            cut_id: parent.head_cut_id.clone(),
        };
        let point = self.load_manifest(branch.branch_point_manifest_hash.as_deref())?;
        let head = self.load_manifest(branch.head_manifest_hash.as_deref())?;
        let target = self.load_manifest(parent.head_manifest_hash.as_deref())?;
        let new_head = match plan_rebase_down(
            &point,
            &head,
            &target,
            &branch_side,
            &parent_side,
            quiescent,
        ) {
            RebaseDownPlan::UpToDate => {
                self.supersede_open_conflicts(branch_id, at)?;
                return Ok(ReconcileOutcome::UpToDate);
            }
            RebaseDownPlan::Silent { new_head_manifest } => new_head_manifest,
            RebaseDownPlan::DeferredMidRun => return Ok(ReconcileOutcome::DeferredMidRun),
            RebaseDownPlan::AskAtQuiescence {
                conflicts,
                merged_remainder,
            } => {
                // At quiescence, certified source merges refine the
                // contested paths; any residue is the honest ask. The
                // refined manifest = clean remainder + certified content,
                // both halves carried out of the plan's three-way.
                let (resolved, remaining) = self.refine_source_conflicts(conflicts)?;
                if !remaining.is_empty() {
                    // The residue is the ask AND the tag: record each as
                    // an open conflict object on the branch (conflict-
                    // bearing state — legal, buildable-upon, never
                    // adoptable), superseding open rows the new
                    // three-way no longer produces.
                    self.sync_conflict_table(branch_id, &remaining, at)?;
                    return Ok(ReconcileOutcome::Conflicts {
                        conflicts: remaining,
                    });
                }
                let mut manifest = merged_remainder;
                manifest.extend(resolved);
                manifest
            }
        };
        self.supersede_open_conflicts(branch_id, at)?;
        let rebased_hash = self.store_manifest(&new_head)?;
        let parent_head_cut = parent.head_cut_id.clone().unwrap_or_default();
        let parent_head_hash = parent
            .head_manifest_hash
            .clone()
            .unwrap_or_else(|| self.store_manifest(&BTreeMap::new()).unwrap_or_default());
        // Dual identity: the rebase REWRITES the cut but the work is the
        // same intent — the new head cut inherits the prior head's change.
        let inherited_change = self
            .change_of(branch.head_cut_id.as_deref())?
            .unwrap_or_else(|| rebase_cut_id.to_owned());
        match self.branches.rebase_branch(
            branch_id,
            branch.head_cut_id.as_deref(),
            &parent_head_cut,
            &parent_head_hash,
            rebase_cut_id,
            &rebased_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                let origin = format!("rebase:{parent_id}");
                self.branches.record_cut(CutRecord {
                    cut_id: rebase_cut_id,
                    change_id: &inherited_change,
                    branch_id,
                    manifest_hash: &rebased_hash,
                    parent_cut_id: branch.head_cut_id.as_deref(),
                    origin: Some(&origin),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-{rebase_cut_id}"),
                    "rebase",
                    vec![Self::op_delta(Some(&branch), &advanced)],
                    Some(&origin),
                    at,
                )?;
                Ok(ReconcileOutcome::Rebased {
                    rebase_cut_id: rebase_cut_id.to_owned(),
                })
            }
            AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                "branch head moved during the rebase; retry".to_owned(),
            )),
            AdvanceOutcome::NotActive { .. } => Ok(ReconcileOutcome::BranchNotActive),
            AdvanceOutcome::NotFound => Ok(ReconcileOutcome::BranchMissing),
        }
    }

    /// Merge a branch into its parent line, running the reconciliation
    /// pipeline: rebase-down first when the parent advanced (silent when
    /// clean, honest conflicts when not), then the staleness-checked
    /// merge-up. On adoption the parent head advances to the branch's
    /// content and the branch becomes immutable history.
    pub fn merge(
        &mut self,
        branch_id: &str,
        merge_cut_id: &str,
        at: &str,
    ) -> StoreResult<VcsMergeOutcome> {
        self.merge_with_mode(branch_id, merge_cut_id, at, false)
    }

    /// `merge` for a LONG-LIVED member line (a chat, a workstream): the
    /// parent adopts the content exactly as in `merge`, but instead of
    /// closing, the branch rebases onto the merge cut — branch point and
    /// head both at the parent's new head, an empty delta, still active.
    /// The next turn diverges from what just landed.
    pub fn merge_keeping(
        &mut self,
        branch_id: &str,
        merge_cut_id: &str,
        at: &str,
    ) -> StoreResult<VcsMergeOutcome> {
        self.merge_with_mode(branch_id, merge_cut_id, at, true)
    }

    fn merge_with_mode(
        &mut self,
        branch_id: &str,
        merge_cut_id: &str,
        at: &str,
        keep_open: bool,
    ) -> StoreResult<VcsMergeOutcome> {
        let Some(mut branch) = self.branches.get_branch(branch_id)? else {
            return Ok(VcsMergeOutcome::BranchMissing);
        };
        if branch.status != BranchStatus::Active {
            return Ok(VcsMergeOutcome::BranchNotActive);
        }
        let Some(parent_id) = branch.parent_branch_id.clone() else {
            return Ok(VcsMergeOutcome::NoParent);
        };
        let Some(parent) = self.branches.get_branch(&parent_id)? else {
            return Ok(VcsMergeOutcome::NoParent);
        };
        // Rebase-down when the parent moved past our branch point. The
        // CLI merge runs at a quiescence point by definition (no run in
        // flight inside this verb), so a conflicting delta escalates as
        // the ask instead of deferring; source-certified refinement
        // applies (quiescent).
        match self.reconcile_branch(branch_id, true, &format!("{merge_cut_id}-rebase"), at)? {
            ReconcileOutcome::UpToDate => {}
            ReconcileOutcome::Rebased { .. } => {
                branch = self
                    .branches
                    .get_branch(branch_id)?
                    .ok_or_else(|| StoreError::Conflict("branch vanished mid-merge".to_owned()))?;
            }
            ReconcileOutcome::DeferredMidRun => unreachable!("reconciled at quiescence"),
            ReconcileOutcome::Conflicts { conflicts } => {
                return Ok(VcsMergeOutcome::Conflicted { conflicts });
            }
            ReconcileOutcome::BranchMissing => return Ok(VcsMergeOutcome::BranchMissing),
            ReconcileOutcome::BranchNotActive => return Ok(VcsMergeOutcome::BranchNotActive),
            ReconcileOutcome::NoParent => return Ok(VcsMergeOutcome::NoParent),
        }
        // The tagged-state guard (resolution-memory.maude): a branch with
        // open conflict objects is never adoptable, whatever the current
        // three-way says.
        let open = self.branches.open_conflicts(branch_id)?;
        if !open.is_empty() {
            return Ok(VcsMergeOutcome::Conflicted {
                conflicts: open
                    .into_iter()
                    .map(|row| PathConflict {
                        path: row.path,
                        base: row.base,
                        ours: row.ours,
                        theirs: row.theirs,
                        ours_side: MergeSide {
                            label: row.ours_label,
                            cut_id: None,
                        },
                        theirs_side: MergeSide {
                            label: row.theirs_label,
                            cut_id: None,
                        },
                    })
                    .collect(),
            });
        }

        let head = self.load_manifest(branch.head_manifest_hash.as_deref())?;
        match plan_merge_up(
            &head,
            Self::cut_ref(&branch.branch_point_cut_id),
            Self::cut_ref(&parent.head_cut_id),
            true,
            true,
        ) {
            MergeUpPlan::Certified { merged_manifest } => {
                let merged_hash = self.store_manifest(&merged_manifest)?;
                let transported_change = self
                    .change_of(branch.head_cut_id.as_deref())?
                    .unwrap_or_else(|| merge_cut_id.to_owned());
                let origin = format!("merge:{branch_id}");
                let parent_advanced = match self.branches.advance_head(
                    &parent_id,
                    parent.head_cut_id.as_deref(),
                    merge_cut_id,
                    &merged_hash,
                    at,
                )? {
                    AdvanceOutcome::Advanced(advanced) => {
                        self.branches.record_cut(CutRecord {
                            cut_id: merge_cut_id,
                            change_id: &transported_change,
                            branch_id: &parent_id,
                            manifest_hash: &merged_hash,
                            parent_cut_id: parent.head_cut_id.as_deref(),
                            origin: Some(&origin),
                            actor: self.actor.as_deref(),
                            intent: self.intent.as_deref(),
                            recorded_at: at,
                        })?;
                        advanced
                    }
                    AdvanceOutcome::Stale { .. } => {
                        return Err(StoreError::Conflict(
                            "parent head moved during the merge; retry".to_owned(),
                        ))
                    }
                    AdvanceOutcome::NotActive { .. } | AdvanceOutcome::NotFound => {
                        return Ok(VcsMergeOutcome::NoParent)
                    }
                };
                if keep_open {
                    // The member line continues: rebase point AND head to
                    // the merge cut (the parent's new head) — an empty
                    // delta over what just landed, same shape a fresh
                    // fork at the merge cut would have.
                    return match self.branches.rebase_branch(
                        branch_id,
                        branch.head_cut_id.as_deref(),
                        merge_cut_id,
                        &merged_hash,
                        merge_cut_id,
                        &merged_hash,
                        at,
                    )? {
                        AdvanceOutcome::Advanced(rebased) => {
                            self.log_op(
                                &format!("op-{merge_cut_id}"),
                                "merge-keep",
                                vec![
                                    Self::op_delta(Some(&parent), &parent_advanced),
                                    Self::op_delta(Some(&branch), &rebased),
                                ],
                                Some(&origin),
                                at,
                            )?;
                            Ok(VcsMergeOutcome::Landed {
                                merge_cut_id: merge_cut_id.to_owned(),
                                into_branch_id: parent_id,
                            })
                        }
                        AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                            "branch head moved during the merge; retry".to_owned(),
                        )),
                        AdvanceOutcome::NotActive { .. } => Ok(VcsMergeOutcome::BranchNotActive),
                        AdvanceOutcome::NotFound => Ok(VcsMergeOutcome::BranchMissing),
                    };
                }
                match self.branches.adopt_branch(branch_id, merge_cut_id, at)? {
                    StatusOutcome::Done(adopted) => {
                        self.log_op(
                            &format!("op-{merge_cut_id}"),
                            "merge",
                            vec![
                                Self::op_delta(Some(&parent), &parent_advanced),
                                Self::op_delta(Some(&branch), &adopted),
                            ],
                            Some(&origin),
                            at,
                        )?;
                        Ok(VcsMergeOutcome::Adopted {
                            merge_cut_id: merge_cut_id.to_owned(),
                            into_branch_id: parent_id,
                        })
                    }
                    StatusOutcome::InvalidTransition { .. } => Ok(VcsMergeOutcome::BranchNotActive),
                    StatusOutcome::NotFound => Ok(VcsMergeOutcome::BranchMissing),
                }
            }
            MergeUpPlan::StaleBase { .. } => Err(StoreError::Conflict(
                "parent advanced mid-merge; retry".to_owned(),
            )),
            MergeUpPlan::NeedsLease | MergeUpPlan::NeedsQuiescence => {
                unreachable!("CLI merge holds the mediator role and runs quiescent")
            }
        }
    }

    /// Every path whose entry differs between two manifests (present in
    /// one, absent or different in the other).
    fn diff_paths(a: &BTreeMap<String, String>, b: &BTreeMap<String, String>) -> Vec<String> {
        let mut paths: Vec<String> = a
            .iter()
            .filter(|(path, hash)| b.get(*path) != Some(hash))
            .map(|(path, _)| path.clone())
            .collect();
        for path in b.keys() {
            if !a.contains_key(path) {
                paths.push(path.clone());
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// Merge-probe: compute EXACTLY what `merge` would do — rebase-down
    /// plan, certified source refinement, merge-up composition — while
    /// moving NOTHING. The un-tie `merge-tree` mapping; agents preview
    /// before they act (vw note §7.3: dry-run is the default
    /// interaction).
    pub fn merge_probe(&self, branch_id: &str) -> StoreResult<MergeProbeOutcome> {
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(MergeProbeOutcome::BranchMissing);
        };
        if branch.status != BranchStatus::Active {
            return Ok(MergeProbeOutcome::BranchNotActive);
        }
        let Some(parent_id) = branch.parent_branch_id.clone() else {
            return Ok(MergeProbeOutcome::NoParent);
        };
        let Some(parent) = self.branches.get_branch(&parent_id)? else {
            return Ok(MergeProbeOutcome::NoParent);
        };
        let point = self.load_manifest(branch.branch_point_manifest_hash.as_deref())?;
        let head = self.load_manifest(branch.head_manifest_hash.as_deref())?;
        let target = self.load_manifest(parent.head_manifest_hash.as_deref())?;
        let candidate =
            if Self::cut_ref(&branch.branch_point_cut_id) == Self::cut_ref(&parent.head_cut_id) {
                head
            } else {
                let branch_side = MergeSide {
                    label: branch_id.to_owned(),
                    cut_id: branch.head_cut_id.clone(),
                };
                let parent_side = MergeSide {
                    label: parent_id.clone(),
                    cut_id: parent.head_cut_id.clone(),
                };
                match plan_rebase_down(&point, &head, &target, &branch_side, &parent_side, true) {
                    RebaseDownPlan::UpToDate => head,
                    RebaseDownPlan::Silent { new_head_manifest } => new_head_manifest,
                    RebaseDownPlan::DeferredMidRun => unreachable!("probe plans quiescent"),
                    RebaseDownPlan::AskAtQuiescence {
                        conflicts,
                        merged_remainder,
                    } => {
                        let (resolved, remaining) = self.refine_source_conflicts(conflicts)?;
                        if !remaining.is_empty() {
                            return Ok(MergeProbeOutcome::Conflicted {
                                conflicts: remaining,
                            });
                        }
                        let mut manifest = merged_remainder;
                        manifest.extend(resolved);
                        manifest
                    }
                }
            };
        let changed_paths = Self::diff_paths(&target, &candidate);
        if changed_paths.is_empty() {
            return Ok(MergeProbeOutcome::UpToDate);
        }
        let merged_manifest_hash = self.store_manifest(&candidate)?;
        Ok(MergeProbeOutcome::Clean {
            merged_manifest_hash,
            changed_paths,
        })
    }

    /// Promote one reserved stream line to Main without first moving the
    /// stream line. The merge is probed against immutable manifests, exact
    /// line/Main heads are re-read immediately before commit, and Main advances
    /// through one `advance_head` compare-and-set. A conflict or stale cut moves
    /// no pointer; certified content written by the probe is unreferenced and
    /// collected normally if the operation refuses.
    ///
    /// Governed write surface (DR-0091): every call site is pinned by
    /// `scripts/check-governed-doors.sh` — a new caller belongs behind a
    /// kernel door, never here directly.
    #[allow(clippy::too_many_arguments)]
    pub fn promote_line_exact(
        &mut self,
        stream_line_id: &str,
        reservation_id: &str,
        expected_line_cut: Option<&str>,
        expected_main_cut: Option<&str>,
        proposed_main_cut: &str,
        at: &str,
    ) -> StoreResult<BoundaryPromotionOutcome> {
        self.require_head_reservation(stream_line_id, reservation_id)?;
        let Some(line) = self.branches.get_branch(stream_line_id)? else {
            return Ok(BoundaryPromotionOutcome::StreamLineMissing);
        };
        if line.status != BranchStatus::Active {
            return Ok(BoundaryPromotionOutcome::StreamLineNotActive);
        }
        let Some(main) = self.branches.get_branch(MAINLINE_BRANCH_ID)? else {
            return Ok(BoundaryPromotionOutcome::MainMissing);
        };
        if main.status != BranchStatus::Active {
            return Ok(BoundaryPromotionOutcome::MainNotActive);
        }
        if line.head_cut_id.as_deref() != expected_line_cut
            || main.head_cut_id.as_deref() != expected_main_cut
        {
            return Ok(BoundaryPromotionOutcome::ExpectedCutsMoved {
                current_line_cut: line.head_cut_id,
                current_main_cut: main.head_cut_id,
            });
        }

        let manifest_hash = match self.merge_probe(stream_line_id)? {
            MergeProbeOutcome::Clean {
                merged_manifest_hash,
                ..
            } => merged_manifest_hash,
            MergeProbeOutcome::UpToDate => main
                .head_manifest_hash
                .clone()
                .unwrap_or_else(|| self.store_manifest(&BTreeMap::new()).unwrap_or_default()),
            MergeProbeOutcome::Conflicted { conflicts } => {
                return Ok(BoundaryPromotionOutcome::Conflicted { conflicts })
            }
            MergeProbeOutcome::BranchMissing => {
                return Ok(BoundaryPromotionOutcome::StreamLineMissing)
            }
            MergeProbeOutcome::BranchNotActive => {
                return Ok(BoundaryPromotionOutcome::StreamLineNotActive)
            }
            MergeProbeOutcome::NoParent => return Ok(BoundaryPromotionOutcome::MainMissing),
        };

        // Re-read both names after the pure probe. The workstream reservation
        // excludes line movement; the exact check is still load-bearing against
        // an implementation path that forgot to consult it.
        let current_line = self.branches.get_branch(stream_line_id)?;
        let current_main = self.branches.get_branch(MAINLINE_BRANCH_ID)?;
        let current_line_cut = current_line
            .as_ref()
            .and_then(|row| row.head_cut_id.clone());
        let current_main_cut = current_main
            .as_ref()
            .and_then(|row| row.head_cut_id.clone());
        if current_line_cut.as_deref() != expected_line_cut
            || current_main_cut.as_deref() != expected_main_cut
        {
            return Ok(BoundaryPromotionOutcome::ExpectedCutsMoved {
                current_line_cut,
                current_main_cut,
            });
        }

        self.require_head_reservation(stream_line_id, reservation_id)?;

        // Persist the immutable proposed coordinate before publishing it.
        // A stale Main CAS can leave an unreferenced cut, which is safe and
        // collectible; publishing a head whose cut record can still fail is
        // not recoverable.
        let origin = format!("promote:{stream_line_id}");
        self.branches.record_cut(CutRecord {
            cut_id: proposed_main_cut,
            change_id: proposed_main_cut,
            branch_id: MAINLINE_BRANCH_ID,
            manifest_hash: &manifest_hash,
            parent_cut_id: expected_main_cut,
            origin: Some(&origin),
            actor: self.actor.as_deref(),
            intent: self.intent.as_deref(),
            recorded_at: at,
        })?;
        let recorded = self.branches.get_cut(proposed_main_cut)?;
        Self::verify_recorded_promotion_cut(
            recorded.as_ref(),
            proposed_main_cut,
            expected_main_cut,
            &manifest_hash,
            &origin,
        )?;

        let advanced = match self.branches.advance_head(
            MAINLINE_BRANCH_ID,
            expected_main_cut,
            proposed_main_cut,
            &manifest_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => advanced,
            AdvanceOutcome::Stale {
                current_head_cut_id,
            } => {
                return Ok(BoundaryPromotionOutcome::ExpectedCutsMoved {
                    current_line_cut,
                    current_main_cut: current_head_cut_id,
                })
            }
            AdvanceOutcome::NotActive { .. } => return Ok(BoundaryPromotionOutcome::MainNotActive),
            AdvanceOutcome::NotFound => return Ok(BoundaryPromotionOutcome::MainMissing),
        };
        self.log_op(
            &format!("op-{proposed_main_cut}"),
            "promote-boundary",
            vec![Self::op_delta(Some(&main), &advanced)],
            Some(&origin),
            at,
        )?;
        let ref_position = u64::try_from(
            self.branches
                .list_cuts(MAINLINE_BRANCH_ID, usize::MAX)?
                .len(),
        )
        .unwrap_or(u64::MAX);
        let ref_receipt_handle = self.boundary_receipt_handle(
            stream_line_id,
            expected_main_cut,
            proposed_main_cut,
            &manifest_hash,
            ref_position,
        );
        Ok(BoundaryPromotionOutcome::Promoted {
            main_cut_id: proposed_main_cut.to_owned(),
            manifest_hash,
            ref_position,
            ref_receipt_handle,
        })
    }

    /// Restore (un-tie's `revert` mapping): re-point the branch head to a
    /// recorded cut's state AS A NEW CUT. The record is untouched — undo
    /// of the restore is another restore (or `undo-op`).
    pub fn restore(
        &mut self,
        branch_id: &str,
        to_cut_id: &str,
        new_cut_id: &str,
        at: &str,
    ) -> StoreResult<RestoreOutcome> {
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(RestoreOutcome::BranchMissing);
        };
        if row.status != BranchStatus::Active {
            return Ok(RestoreOutcome::BranchNotActive);
        }
        let Some(cut) = self.branches.get_cut(to_cut_id)? else {
            return Ok(RestoreOutcome::CutMissing);
        };
        if row.head_manifest_hash.as_deref() == Some(cut.manifest_hash.as_str()) {
            return Ok(RestoreOutcome::AlreadyThere);
        }
        match self.branches.advance_head(
            branch_id,
            row.head_cut_id.as_deref(),
            new_cut_id,
            &cut.manifest_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                // A restore is a NEW intent (a counterfactual state the
                // branch proposes), not the old change re-materialized.
                let origin = format!("restore:{to_cut_id}");
                self.branches.record_cut(CutRecord {
                    cut_id: new_cut_id,
                    change_id: new_cut_id,
                    branch_id,
                    manifest_hash: &cut.manifest_hash,
                    parent_cut_id: row.head_cut_id.as_deref(),
                    origin: Some(&origin),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-{new_cut_id}"),
                    "restore",
                    vec![Self::op_delta(Some(&row), &advanced)],
                    Some(&origin),
                    at,
                )?;
                Ok(RestoreOutcome::Restored {
                    cut_id: new_cut_id.to_owned(),
                    manifest_hash: cut.manifest_hash,
                })
            }
            AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                "branch head moved during the restore; retry".to_owned(),
            )),
            AdvanceOutcome::NotActive { .. } => Ok(RestoreOutcome::BranchNotActive),
            AdvanceOutcome::NotFound => Ok(RestoreOutcome::BranchMissing),
        }
    }

    /// Name the branch's current state as a durable cut (un-tie's
    /// commit-per-turn-finalize mapping). The head cut IS the quiescent
    /// cut when one exists — this records it (idempotently) and returns
    /// it; a virgin head mints the named cut over the current manifest.
    /// `None` = no such branch.
    pub fn cut_at_quiescence(
        &mut self,
        branch_id: &str,
        cut_id: &str,
        at: &str,
    ) -> StoreResult<Option<QuiescentCut>> {
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        if let Some(head_cut) = Self::cut_ref(&row.head_cut_id) {
            let manifest_hash = row.head_manifest_hash.clone().unwrap_or_default();
            self.branches.record_cut(CutRecord {
                cut_id: head_cut,
                change_id: head_cut,
                branch_id,
                manifest_hash: &manifest_hash,
                parent_cut_id: None,
                origin: Some("cut"),
                actor: self.actor.as_deref(),
                intent: self.intent.as_deref(),
                recorded_at: at,
            })?;
            let change_id = self
                .change_of(Some(head_cut))?
                .unwrap_or_else(|| head_cut.to_owned());
            return Ok(Some(QuiescentCut {
                cut_id: head_cut.to_owned(),
                manifest_hash,
                change_id,
            }));
        }
        // Virgin head (no cut yet — a fresh mainline): mint the named cut
        // over the current (empty) manifest.
        let manifest = self.load_manifest(row.head_manifest_hash.as_deref())?;
        let manifest_hash = self.store_manifest(&manifest)?;
        match self
            .branches
            .advance_head(branch_id, None, cut_id, &manifest_hash, at)?
        {
            AdvanceOutcome::Advanced(advanced) => {
                self.branches.record_cut(CutRecord {
                    cut_id,
                    change_id: cut_id,
                    branch_id,
                    manifest_hash: &manifest_hash,
                    parent_cut_id: None,
                    origin: Some("cut"),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-{cut_id}"),
                    "cut",
                    vec![Self::op_delta(Some(&row), &advanced)],
                    Some("cut"),
                    at,
                )?;
                Ok(Some(QuiescentCut {
                    cut_id: cut_id.to_owned(),
                    manifest_hash,
                    change_id: cut_id.to_owned(),
                }))
            }
            AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                "branch head moved during the cut; retry".to_owned(),
            )),
            AdvanceOutcome::NotActive { .. } | AdvanceOutcome::NotFound => Ok(None),
        }
    }

    /// Review-grade diff of the branch's head against a target (diff.rs):
    /// the branch point by default ("what did this branch change" — the
    /// review question), or an explicit branch head / recorded cut.
    /// `None` = no such branch.
    pub fn diff_against(
        &self,
        branch_id: &str,
        target: Option<&str>,
        context: usize,
    ) -> StoreResult<Option<Vec<crate::diff::DiffEntry>>> {
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        let head = self.load_manifest(branch.head_manifest_hash.as_deref())?;
        let base = match target {
            None => self.load_manifest(branch.branch_point_manifest_hash.as_deref())?,
            Some(target_ref) => {
                if let Some(row) = self.branches.get_branch(target_ref)? {
                    self.load_manifest(row.head_manifest_hash.as_deref())?
                } else if let Some(cut) = self.branches.get_cut(target_ref)? {
                    self.load_manifest(Some(&cut.manifest_hash))?
                } else {
                    return Err(StoreError::Conflict(format!(
                        "no branch or recorded cut `{target_ref}` to diff against"
                    )));
                }
            }
        };
        Ok(Some(crate::diff::diff_manifests(
            &base,
            &head,
            &self.content,
            context,
        )?))
    }

    /// Export the branch as a self-contained handoff bundle
    /// (bundle.rs): lineage snapshot + head manifest + reachable blobs +
    /// recorded cuts. Erasure-respecting by construction — tombstoned
    /// payloads never travel. `None` = no such branch.
    pub fn export_bundle(
        &self,
        branch_id: &str,
    ) -> StoreResult<Option<crate::bundle::WorkspaceBundle>> {
        self.export_bundle_delta(branch_id, &std::collections::BTreeSet::new())
    }

    /// `export_bundle` with pull-missing (rsync-class incremental): units
    /// in `have` — the receiver's declared inventory, computed by
    /// `bundle::transferable_ids` over ITS store — travel as structure
    /// only. Blob AND chunk granular, so a hybrid desktop↔cloud sync
    /// moves only the chunks that actually changed.
    pub fn export_bundle_delta(
        &self,
        branch_id: &str,
        have: &std::collections::BTreeSet<String>,
    ) -> StoreResult<Option<crate::bundle::WorkspaceBundle>> {
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        let manifest = self.load_manifest(branch.head_manifest_hash.as_deref())?;
        let blobs = crate::bundle::collect_blobs_delta(&manifest, &self.content, have)?;
        let head_change_id = self.change_of(branch.head_cut_id.as_deref())?;
        let cuts = self.branches.list_cuts(branch_id, i64::MAX as usize)?;
        Ok(Some(crate::bundle::WorkspaceBundle {
            format: crate::bundle::BUNDLE_FORMAT.to_owned(),
            branch,
            head_change_id,
            manifest,
            blobs,
            cuts,
        }))
    }

    /// Undo one workspace operation (jj's most-loved feature as a
    /// front-and-center verb; op-undo.maude): re-point every branch the
    /// op touched back to its recorded before-state, as a NEW
    /// compensating op — the log is append-only, undo-of-undo is the
    /// same verb on the compensator. Guarded per the model's bite: any
    /// touched branch whose head moved since the op is an honest
    /// refusal, never a lost update. Undoing a creation closes the head
    /// (discard — the record survives; no destructive verbs).
    pub fn undo_op(
        &mut self,
        op_id: &str,
        undo_op_id: &str,
        at: &str,
    ) -> StoreResult<UndoOpOutcome> {
        let Some(op) = self.branches.get_op(op_id)? else {
            return Ok(UndoOpOutcome::OpMissing);
        };
        if op.deltas.is_empty() {
            return Ok(UndoOpOutcome::NothingToUndo);
        }
        // Guard pass: every touched branch must still be exactly where
        // the op left it (the model's moved-head bite).
        for delta in &op.deltas {
            let Some(row) = self.branches.get_branch(&delta.branch_id)? else {
                self.note_head_moved(op_id, &delta.branch_id, at);
                return Ok(UndoOpOutcome::HeadMoved {
                    branch_id: delta.branch_id.clone(),
                    current_head_cut_id: None,
                    expected_head_cut_id: delta.after.head_cut_id.clone(),
                });
            };
            if OpBranchState::of(&row) != delta.after {
                self.note_head_moved(op_id, &delta.branch_id, at);
                return Ok(UndoOpOutcome::HeadMoved {
                    branch_id: delta.branch_id.clone(),
                    current_head_cut_id: row.head_cut_id,
                    expected_head_cut_id: delta.after.head_cut_id.clone(),
                });
            }
        }
        // Apply pass: restore each branch to its before-state.
        let mut undo_deltas = Vec::new();
        for delta in &op.deltas {
            let row = self
                .branches
                .get_branch(&delta.branch_id)?
                .ok_or_else(|| StoreError::Conflict("branch vanished mid-undo".to_owned()))?;
            let restored = match &delta.before {
                Some(before) => {
                    match self.branches.restore_branch_state(
                        &delta.branch_id,
                        row.head_cut_id.as_deref(),
                        before,
                        at,
                    )? {
                        AdvanceOutcome::Advanced(restored) => restored,
                        other => {
                            return Err(StoreError::Conflict(format!(
                                "undo of `{op_id}` could not restore `{}`: {other:?}",
                                delta.branch_id
                            )))
                        }
                    }
                }
                None => {
                    // The op created this branch: the compensator closes
                    // the head. The record remains readable history.
                    match self.branches.discard_branch(&delta.branch_id, at)? {
                        StatusOutcome::Done(discarded) => discarded,
                        other => {
                            return Err(StoreError::Conflict(format!(
                                "undo of `{op_id}` could not close created branch `{}`: {other:?}",
                                delta.branch_id
                            )))
                        }
                    }
                }
            };
            undo_deltas.push(OpBranchDelta {
                branch_id: delta.branch_id.clone(),
                before: Some(delta.after.clone()),
                after: OpBranchState::of(&restored),
            });
        }
        self.log_op(
            undo_op_id,
            "undo",
            undo_deltas,
            Some(&format!("undo:{op_id}")),
            at,
        )?;
        Ok(UndoOpOutcome::Undone {
            undo_op_id: undo_op_id.to_owned(),
        })
    }

    /// The branch's recorded change-units, oldest first (the selection
    /// algebra's universe): each cut's manifest diffed against its
    /// lineage parent. Cuts without a readable manifest pair are
    /// skipped rather than fabricated.
    pub fn change_units(
        &self,
        branch_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<crate::selection::ChangeUnit>> {
        // DR-0052 L4: the change-unit INDEX serves the recorded prefix
        // (no manifest loads); only the unindexed tail — cuts recorded
        // since the last maintenance — is computed here, in memory. The
        // index is a pure cache: cuts are immutable and the branch's cut
        // list is append-only, so a consistent prefix can never go
        // stale, and an inconsistent cursor (defensive: a restored or
        // hand-edited store) just means full recompute until the next
        // maintenance pass resets it.
        let mut cuts = self.branches.list_cuts(branch_id, i64::MAX as usize)?;
        cuts.reverse(); // oldest first: the dependence direction
        let cursor = self.branches.change_unit_cursor(branch_id)?;
        let indexed = cursor.indexed_cuts.max(0) as usize;
        let consistent = indexed <= cuts.len()
            && (indexed == 0
                || cuts.get(indexed - 1).map(|cut| cut.cut_id.as_str())
                    == cursor.last_indexed_cut_id.as_deref());
        let prefix = if consistent { indexed } else { 0 };
        // The window is known here, so the work is confined to it rather than
        // done for the whole branch and thrown away by the `retain` below:
        // rows and recomputed cuts before `window_start` are exactly the ones
        // that retain drops. When the branch is shorter than the window this is
        // 0 and nothing changes.
        let window_start = cuts.len().saturating_sub(limit);
        let by_cut: BTreeMap<&str, &crate::branches::CutRow> =
            cuts.iter().map(|cut| (cut.cut_id.as_str(), cut)).collect();
        let mut units: Vec<crate::selection::ChangeUnit> = Vec::new();
        if prefix > 0 && window_start < prefix {
            for row in self
                .branches
                .list_change_unit_rows(branch_id, window_start as i64)?
            {
                if row.cut_seq as usize >= prefix {
                    continue; // beyond the verified prefix: recompute below
                }
                let Some(cut) = by_cut.get(row.cut_id.as_str()) else {
                    continue;
                };
                units.push(crate::selection::ChangeUnit {
                    seq: units.len(),
                    cut_id: row.cut_id.clone(),
                    change_id: cut.change_id.clone(),
                    branch_id: cut.branch_id.clone(),
                    path: row.path.clone(),
                    before: row.before_hash.clone(),
                    after: row.after_hash.clone(),
                    origin: cut.origin.clone(),
                    actor: cut.actor.clone(),
                    intent: cut.intent.clone(),
                    recorded_at: cut.recorded_at.clone(),
                    decls: row
                        .decl_units
                        .as_deref()
                        .and_then(|json| serde_json::from_str(json).ok())
                        .unwrap_or_default(),
                });
            }
        }
        for cut in &cuts[prefix.max(window_start)..] {
            self.push_units_for_cut(cut, &mut units)?;
        }
        // Window semantics are unchanged: callers get the units of the
        // LAST `limit` cuts, seq re-based within the window.
        if cuts.len() > limit {
            let window: std::collections::BTreeSet<&str> = cuts[cuts.len() - limit..]
                .iter()
                .map(|cut| cut.cut_id.as_str())
                .collect();
            units.retain(|unit| window.contains(unit.cut_id.as_str()));
            for (index, unit) in units.iter_mut().enumerate() {
                unit.seq = index;
            }
        }
        Ok(units)
    }

    /// Compute one cut's per-path units (manifest diff against its
    /// parent) and append them, seq-continuing.
    /// The paths a cut changed against its parent.
    ///
    /// Both sides are trees for every cut written since DR-0070 §1, so this is
    /// `manifest_tree::diff` — equal subtrees cost one id comparison and are
    /// never read. A cut whose parent predates the tree, or which has no parent,
    /// falls back to comparing the materialized maps, which is what the whole
    /// path did before.
    ///
    /// # Errors
    /// Propagates store failures.
    fn cut_changes(
        &self,
        cut: &crate::branches::CutRow,
    ) -> StoreResult<Vec<crate::manifest_tree::ManifestChange>> {
        let parent_hash = match cut.parent_cut_id.as_deref() {
            None => None,
            Some(parent_cut) => match self.branches.get_cut(parent_cut)? {
                None => None,
                Some(parent) => Some(parent.manifest_hash),
            },
        };

        if let Some(parent_hash) = parent_hash.as_deref() {
            let both_are_trees = matches!(
                self.load_manifest_opt_raw(&cut.manifest_hash)?,
                Some(RawManifest::Tree(_))
            ) && matches!(
                self.load_manifest_opt_raw(parent_hash)?,
                Some(RawManifest::Tree(_))
            );
            if both_are_trees {
                return crate::manifest_tree::diff(&self.content, parent_hash, &cut.manifest_hash);
            }
        }

        let Some(after) = self.load_manifest_opt(&cut.manifest_hash)? else {
            return Ok(Vec::new());
        };
        let before = match parent_hash.as_deref() {
            None => BTreeMap::new(),
            Some(hash) => match self.load_manifest_opt(hash)? {
                Some(manifest) => manifest,
                None => return Ok(Vec::new()),
            },
        };
        Ok(Self::diff_paths(&before, &after)
            .into_iter()
            .map(|path| crate::manifest_tree::ManifestChange {
                before: before.get(&path).cloned(),
                after: after.get(&path).cloned(),
                path,
            })
            .collect())
    }

    fn push_units_for_cut(
        &self,
        cut: &crate::branches::CutRow,
        units: &mut Vec<crate::selection::ChangeUnit>,
    ) -> StoreResult<()> {
        // DR-0070 §1's diff, on its first production caller. This materialized
        // BOTH manifests and compared them entry by entry, so listing a cut's
        // changed paths cost the workspace twice over however little the cut
        // touched — and a change-unit index walks every cut on a branch.
        let changes = self.cut_changes(cut)?;
        for change in changes {
            let path = change.path;
            let before_hash = change.before;
            let after_hash = change.after;
            let decls =
                self.decl_units_for(&path, before_hash.as_deref(), after_hash.as_deref())?;
            units.push(crate::selection::ChangeUnit {
                seq: units.len(),
                cut_id: cut.cut_id.clone(),
                change_id: cut.change_id.clone(),
                branch_id: cut.branch_id.clone(),
                path: path.clone(),
                before: before_hash,
                after: after_hash,
                origin: cut.origin.clone(),
                actor: cut.actor.clone(),
                intent: cut.intent.clone(),
                recorded_at: cut.recorded_at.clone(),
                decls,
            });
        }
        Ok(())
    }

    /// Declaration-level sub-rows for one changed path (DR-0054 Decision
    /// 6.3): diff the two sides' canonical declaration lists. Empty when
    /// no canonicalizer is installed, the path is not `.whip` source, or
    /// EITHER present side has no canonical form — attribution never
    /// guesses (a half-canonical diff would misattribute).
    fn decl_units_for(
        &self,
        path: &str,
        before_hash: Option<&str>,
        after_hash: Option<&str>,
    ) -> StoreResult<Vec<crate::selection::DeclUnit>> {
        let Some(canonicalizer) = self.decl_canonicalizer.as_deref() else {
            return Ok(Vec::new());
        };
        if !path.ends_with(".whip") {
            return Ok(Vec::new());
        }
        let canon_side = |hash: Option<&str>| -> StoreResult<Option<Vec<CanonDecl>>> {
            let Some(hash) = hash else {
                return Ok(Some(Vec::new())); // absent side: no declarations
            };
            let Some(text) = self.content.get(hash)? else {
                return Ok(None); // unreadable blob: fail closed
            };
            Ok(canonicalizer.canonical_declarations(&text))
        };
        let (Some(before), Some(after)) = (canon_side(before_hash)?, canon_side(after_hash)?)
        else {
            return Ok(Vec::new());
        };
        let before_map: BTreeMap<&str, &str> = before
            .iter()
            .map(|declaration| {
                (
                    declaration.identity.as_str(),
                    declaration.canon_hash.as_str(),
                )
            })
            .collect();
        let after_map: BTreeMap<&str, &str> = after
            .iter()
            .map(|declaration| {
                (
                    declaration.identity.as_str(),
                    declaration.canon_hash.as_str(),
                )
            })
            .collect();
        let mut identities: Vec<&str> = before_map.keys().copied().collect();
        for identity in after_map.keys() {
            if !before_map.contains_key(identity) {
                identities.push(identity);
            }
        }
        identities.sort_unstable();
        let mut decls = Vec::new();
        for identity in identities {
            let before_canon = before_map.get(identity).copied();
            let after_canon = after_map.get(identity).copied();
            if before_canon == after_canon {
                continue; // untouched (or formatting-only) declaration
            }
            decls.push(crate::selection::DeclUnit {
                identity: identity.to_owned(),
                before_canon: before_canon.map(str::to_owned),
                after_canon: after_canon.map(str::to_owned),
            });
        }
        Ok(decls)
    }

    /// Extend the change-unit index over any unindexed tail (DR-0052
    /// L4). Called from mutation points (each call indexes only what the
    /// last one left); an inconsistent cursor resets and reindexes from
    /// scratch. Best-effort by design — the read path is correct with or
    /// without it.
    pub fn maintain_change_unit_index(&mut self, branch_id: &str) -> StoreResult<usize> {
        let mut cuts = self.branches.list_cuts(branch_id, i64::MAX as usize)?;
        cuts.reverse();
        let cursor = self.branches.change_unit_cursor(branch_id)?;
        let indexed = cursor.indexed_cuts.max(0) as usize;
        let consistent = indexed <= cuts.len()
            && (indexed == 0
                || cuts.get(indexed - 1).map(|cut| cut.cut_id.as_str())
                    == cursor.last_indexed_cut_id.as_deref());
        let start = if consistent {
            indexed
        } else {
            self.branches.reset_change_unit_index(branch_id)?;
            0
        };
        if start >= cuts.len() {
            return Ok(0);
        }
        let mut rows = Vec::new();
        for (offset, cut) in cuts[start..].iter().enumerate() {
            let mut scratch = Vec::new();
            self.push_units_for_cut(cut, &mut scratch)?;
            for unit in scratch {
                rows.push(crate::branches::ChangeUnitRow {
                    branch_id: branch_id.to_owned(),
                    cut_seq: (start + offset) as i64,
                    cut_id: cut.cut_id.clone(),
                    path: unit.path,
                    before_hash: unit.before,
                    after_hash: unit.after,
                    decl_units: if unit.decls.is_empty() {
                        None
                    } else {
                        serde_json::to_string(&unit.decls).ok()
                    },
                });
            }
        }
        let appended = rows.len();
        let last = cuts.last().map(|cut| cut.cut_id.clone());
        self.branches.append_change_unit_rows(
            branch_id,
            &rows,
            cuts.len() as i64,
            last.as_deref(),
        )?;
        Ok(appended)
    }

    /// Plan `undo <selection>` (vw note §7.3; selective-undo.maude): the
    /// proposal = current head minus the selected writes; the stranding
    /// check refuses when a RETAINED later unit consumed an undone
    /// write's output. Pure preview — `None` = no such branch.
    pub fn plan_undo_selection(
        &self,
        branch_id: &str,
        expr: &crate::selection::SelExpr,
    ) -> StoreResult<Option<UndoSelectionPlan>> {
        if self.branches.get_branch(branch_id)?.is_none() {
            return Ok(None);
        }
        let universe = self.change_units(branch_id, 500)?;
        let selected = crate::selection::eval(expr, &universe);
        let stranded = crate::selection::stranded_by_undo(&selected, &universe);
        // Per affected path, revert to the OLDEST selected unit's before
        // (the net exclusion of every selected write on that path).
        let mut reverts: BTreeMap<String, Option<String>> = BTreeMap::new();
        for &index in &selected {
            let unit = &universe[index];
            reverts
                .entry(unit.path.clone())
                .or_insert_with(|| unit.before.clone());
        }
        Ok(Some(UndoSelectionPlan {
            selected: selected.iter().map(|&i| universe[i].clone()).collect(),
            stranded: stranded.iter().map(|&i| universe[i].clone()).collect(),
            reverts,
        }))
    }

    /// Apply an undo-selection plan: one proposal cut on the branch —
    /// honestly a counterfactual state (a state that never ran), tagged
    /// by its origin until gates revalidate. Refuses a stranding plan.
    ///
    /// Governed write surface (DR-0091): every call site is pinned by
    /// `scripts/check-governed-doors.sh` — a new caller belongs behind a
    /// kernel door, never here directly.
    pub fn apply_undo_selection(
        &mut self,
        branch_id: &str,
        expr: &crate::selection::SelExpr,
        cut_id: &str,
        at: &str,
    ) -> StoreResult<UndoSelectionOutcome> {
        let Some(plan) = self.plan_undo_selection(branch_id, expr)? else {
            return Ok(UndoSelectionOutcome::BranchMissing);
        };
        if !plan.stranded.is_empty() {
            self.note_fact(
                "vcs.op.refused",
                branch_id,
                serde_json::json!({
                    "op": "undo-selection",
                    "reason": "stranded",
                    "stranded_paths": plan
                        .stranded
                        .iter()
                        .map(|unit| unit.path.clone())
                        .collect::<Vec<_>>(),
                    "by": self.actor,
                    "at": at,
                }),
            );
            return Ok(UndoSelectionOutcome::WouldStrand {
                stranded: plan.stranded,
            });
        }
        if plan.reverts.is_empty() {
            return Ok(UndoSelectionOutcome::NothingSelected);
        }
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(UndoSelectionOutcome::BranchMissing);
        };
        if row.status != BranchStatus::Active {
            return Ok(UndoSelectionOutcome::BranchNotActive);
        }
        // A revert set is already a change set: `(path, what it was)`, with
        // `None` for a path that was not there. Folding it into a materialized
        // manifest to rebuild every node was O(workspace) for an effect the
        // plan already states the size of (DR-0066 §8 refusal 2).
        let manifest_hash =
            self.advance_manifest(row.head_manifest_hash.as_deref(), &plan.reverts)?;
        match self.branches.advance_head(
            branch_id,
            row.head_cut_id.as_deref(),
            cut_id,
            &manifest_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                // A counterfactual proposal is a NEW intent; the origin
                // is the synthetic tag until gates revalidate.
                self.branches.record_cut(CutRecord {
                    cut_id,
                    change_id: cut_id,
                    branch_id,
                    manifest_hash: &manifest_hash,
                    parent_cut_id: row.head_cut_id.as_deref(),
                    origin: Some("undo-selection"),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-{cut_id}"),
                    "undo-selection",
                    vec![Self::op_delta(Some(&row), &advanced)],
                    Some("undo-selection"),
                    at,
                )?;
                self.note_fact(
                    "vcs.cut.recorded",
                    branch_id,
                    serde_json::json!({
                        "cut": cut_id,
                        "origin": "undo-selection",
                        "paths": plan.reverts.keys().cloned().collect::<Vec<_>>(),
                        "by": self.actor,
                        "intent": self.intent,
                        "at": at,
                    }),
                );
                // Revert-war detection (DR-0052 Decision 8's thrash
                // signature): this undo reverts another actor's units on
                // paths a PRIOR undo-selection cut (by one of those
                // actors) already fought over — the A-undoes-B,
                // B-undoes-A path-level cycle.
                let cross_actors: BTreeSet<String> = plan
                    .selected
                    .iter()
                    .filter_map(|unit| unit.actor.clone())
                    .filter(|actor| Some(actor.as_str()) != self.actor.as_deref())
                    .collect();
                if !cross_actors.is_empty() {
                    let reverted: BTreeSet<&String> = plan.reverts.keys().collect();
                    let prior_war = plan.selected.iter().any(|unit| {
                        unit.origin.as_deref() == Some("undo-selection")
                            && unit
                                .actor
                                .as_deref()
                                .is_some_and(|actor| cross_actors.contains(actor))
                            && reverted.contains(&unit.path)
                    });
                    if prior_war {
                        self.note_fact(
                            "vcs.revert_war.detected",
                            branch_id,
                            serde_json::json!({
                                "undoer": self.actor,
                                "counterparties": cross_actors,
                                "paths": plan.reverts.keys().cloned().collect::<Vec<_>>(),
                                "at": at,
                            }),
                        );
                    }
                }
                let _ = self.maintain_change_unit_index(branch_id);
                Ok(UndoSelectionOutcome::Proposed {
                    cut_id: cut_id.to_owned(),
                    manifest_hash,
                    reverted_paths: plan.reverts.keys().cloned().collect(),
                })
            }
            AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                "branch head moved during the undo; retry".to_owned(),
            )),
            AdvanceOutcome::NotActive { .. } => Ok(UndoSelectionOutcome::BranchNotActive),
            AdvanceOutcome::NotFound => Ok(UndoSelectionOutcome::BranchMissing),
        }
    }

    /// `transport <selection> onto <target>` — cherry-pick done right:
    /// the selected units' net content lands on the target as one cut
    /// that PRESERVES IDENTITY when the whole selection is one change
    /// (the eventual full merge reunifies instead of duplicating).
    /// Certified precondition per path: the target currently holds the
    /// unit's recorded BEFORE (or already holds the after — idempotent
    /// skip); anything else is an honest conflict and nothing moves.
    ///
    /// Governed write surface (DR-0091): every call site is pinned by
    /// `scripts/check-governed-doors.sh` — a new caller belongs behind a
    /// kernel door, never here directly.
    pub fn transport_selection(
        &mut self,
        branch_id: &str,
        expr: &crate::selection::SelExpr,
        onto: &str,
        cut_id: &str,
        at: &str,
    ) -> StoreResult<TransportOutcome> {
        if self.branches.get_branch(branch_id)?.is_none() {
            return Ok(TransportOutcome::BranchMissing);
        }
        let Some(target) = self.branches.get_branch(onto)? else {
            return Ok(TransportOutcome::TargetMissing);
        };
        if target.status != BranchStatus::Active {
            return Ok(TransportOutcome::TargetNotActive);
        }
        let universe = self.change_units(branch_id, 500)?;
        let selected = crate::selection::eval(expr, &universe);
        if selected.is_empty() {
            return Ok(TransportOutcome::NothingSelected);
        }
        // Net effect per path folds the OLDEST and NEWEST selected writes to
        // that path: the certified precondition on the target is the oldest's
        // `before` (the state before this branch first touched the path), and
        // the result is the newest's `after`. Using the newest write's `before`
        // (an intermediate state the target never held) would falsely conflict a
        // valid multi-write cherry-pick — e.g. create p2 (before=None) then edit
        // p2 (before="v1"): the target lacks p2, so `current(None) !=
        // before("v1")` reports a phantom conflict.
        struct NetUnit<'a> {
            oldest: &'a crate::selection::ChangeUnit,
            newest: &'a crate::selection::ChangeUnit,
        }
        let mut net: BTreeMap<String, NetUnit> = BTreeMap::new();
        for &index in &selected {
            let unit = &universe[index];
            net.entry(unit.path.clone())
                .and_modify(|net_unit| {
                    if unit.seq < net_unit.oldest.seq {
                        net_unit.oldest = unit;
                    }
                    if unit.seq > net_unit.newest.seq {
                        net_unit.newest = unit;
                    }
                })
                .or_insert(NetUnit {
                    oldest: unit,
                    newest: unit,
                });
        }
        // Read per path rather than materializing the target's manifest: the
        // preconditions below ask about the paths being transported, and there
        // are as many of those as there are units, not as there are files.
        let target_manifest_hash = target.head_manifest_hash.as_deref();
        let mut conflicts = Vec::new();
        let mut moved = Vec::new();
        for (path, net_unit) in &net {
            let precondition = net_unit.oldest.before.as_ref();
            let result = net_unit.newest.after.as_ref();
            let current = self.manifest_entry(target_manifest_hash, path)?;
            let current = current.as_ref();
            if current == result {
                continue; // already there: the idempotent skip
            }
            if current != precondition {
                conflicts.push(PathConflict {
                    path: path.clone(),
                    base: net_unit.oldest.before.clone(),
                    ours: current.cloned(),
                    theirs: net_unit.newest.after.clone(),
                    ours_side: MergeSide {
                        label: onto.to_owned(),
                        cut_id: target.head_cut_id.clone(),
                    },
                    theirs_side: MergeSide {
                        label: branch_id.to_owned(),
                        cut_id: Some(net_unit.newest.cut_id.clone()),
                    },
                });
                continue;
            }
            moved.push((path.clone(), net_unit.newest.after.clone()));
        }
        if !conflicts.is_empty() {
            self.note_fact(
                "vcs.op.refused",
                onto,
                serde_json::json!({
                    "op": "transport",
                    "reason": "conflicted",
                    "paths": conflicts.iter().map(|c| c.path.clone()).collect::<Vec<_>>(),
                    "by": self.actor,
                    "at": at,
                }),
            );
            return Ok(TransportOutcome::Conflicted { conflicts });
        }
        if moved.is_empty() {
            return Ok(TransportOutcome::UpToDate);
        }

        // Identity preservation: a single-change selection carries its
        // change id; a mixed selection is honestly a new intent.
        let changes: std::collections::BTreeSet<&str> = selected
            .iter()
            .map(|&i| universe[i].change_id.as_str())
            .collect();
        let transported_change = if changes.len() == 1 {
            (*changes.iter().next().expect("one")).to_owned()
        } else {
            cut_id.to_owned()
        };
        let moved_changes: BTreeMap<String, Option<String>> = moved.iter().cloned().collect();
        let manifest_hash = self.advance_manifest(target_manifest_hash, &moved_changes)?;
        match self.branches.advance_head(
            onto,
            target.head_cut_id.as_deref(),
            cut_id,
            &manifest_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                let origin = format!("transport:{branch_id}");
                self.branches.record_cut(CutRecord {
                    cut_id,
                    change_id: &transported_change,
                    branch_id: onto,
                    manifest_hash: &manifest_hash,
                    parent_cut_id: target.head_cut_id.as_deref(),
                    origin: Some(&origin),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-{cut_id}"),
                    "transport",
                    vec![Self::op_delta(Some(&target), &advanced)],
                    Some(&origin),
                    at,
                )?;
                let moved_paths: Vec<String> = moved.into_iter().map(|(path, _)| path).collect();
                self.note_fact(
                    "vcs.cut.recorded",
                    onto,
                    serde_json::json!({
                        "cut": cut_id,
                        "origin": origin,
                        "paths": moved_paths,
                        "by": self.actor,
                        "intent": self.intent,
                        "at": at,
                    }),
                );
                let _ = self.maintain_change_unit_index(onto);
                Ok(TransportOutcome::Transported {
                    cut_id: cut_id.to_owned(),
                    change_id: transported_change,
                    moved_paths,
                })
            }
            AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                "target head moved during the transport; retry".to_owned(),
            )),
            AdvanceOutcome::NotActive { .. } => Ok(TransportOutcome::TargetNotActive),
            AdvanceOutcome::NotFound => Ok(TransportOutcome::TargetMissing),
        }
    }

    /// `adopt --only <selection>`: partial adoption — the selected
    /// fraction of the branch's delta lands on its parent line, the
    /// REMAINDER stays live on the branch (never festering as
    /// uncommitted state; the branch is not adopted).
    pub fn adopt_only(
        &mut self,
        branch_id: &str,
        expr: &crate::selection::SelExpr,
        cut_id: &str,
        at: &str,
    ) -> StoreResult<TransportOutcome> {
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(TransportOutcome::BranchMissing);
        };
        let Some(parent_id) = branch.parent_branch_id else {
            return Ok(TransportOutcome::TargetMissing);
        };
        self.transport_selection(branch_id, expr, &parent_id, cut_id, at)
    }

    /// Write-attribution (vw note §7.3: blame is a weak projection of
    /// "which cut/change/effect wrote this, under what intent"): the
    /// newest recorded unit per live path on the branch. `None` = no
    /// such branch.
    pub fn attribution(&self, branch_id: &str) -> StoreResult<Option<Vec<PathAttribution>>> {
        let Some(manifest) = self.manifest(branch_id)? else {
            return Ok(None);
        };
        let units = self.change_units(branch_id, 500)?;
        // Indexed once instead of scanned per path: units are oldest first, so
        // a forward pass leaves the newest unit for each path — the one a
        // reverse scan found — and the cost stops being paths × units.
        let mut newest: HashMap<&str, &crate::selection::ChangeUnit> = HashMap::new();
        for unit in &units {
            newest.insert(unit.path.as_str(), unit);
        }
        let mut attributions = Vec::new();
        for path in manifest.keys() {
            let last = newest.get(path.as_str()).copied();
            attributions.push(PathAttribution {
                path: path.clone(),
                cut_id: last.map(|unit| unit.cut_id.clone()),
                change_id: last.map(|unit| unit.change_id.clone()),
                origin: last.and_then(|unit| unit.origin.clone()),
                actor: last.and_then(|unit| unit.actor.clone()),
                recorded_at: last.map(|unit| unit.recorded_at.clone()),
            });
        }
        Ok(Some(attributions))
    }

    /// The cut chain from `descendant` back to `ancestor`, inclusive,
    /// via recorded parent pointers — checkout-free bisect's substrate.
    /// `None` = no recorded path between them.
    pub fn cut_chain(&self, descendant: &str, ancestor: &str) -> StoreResult<Option<Vec<CutRow>>> {
        let mut chain = Vec::new();
        let mut cursor = Some(descendant.to_owned());
        let mut guard = 0usize;
        while let Some(cut_id) = cursor {
            let Some(cut) = self.branches.get_cut(&cut_id)? else {
                return Ok(None);
            };
            cursor = cut.parent_cut_id.clone();
            let done = cut.cut_id == ancestor;
            chain.push(cut);
            if done {
                chain.reverse(); // ancestor first
                return Ok(Some(chain));
            }
            guard += 1;
            if guard > 10_000 {
                return Err(StoreError::Conflict(
                    "cut lineage exceeds the walk bound".to_owned(),
                ));
            }
        }
        Ok(None)
    }

    /// A recorded cut's manifest (bisect materializes these directly —
    /// no branch pointer ever moves). `None` = unrecorded cut.
    pub fn cut_manifest(&self, cut_id: &str) -> StoreResult<Option<BTreeMap<String, String>>> {
        let Some(cut) = self.branches.get_cut(cut_id)? else {
            return Ok(None);
        };
        Ok(Some(self.load_manifest(Some(&cut.manifest_hash))?))
    }

    /// The transferable-unit ids this store can serve for the branch's
    /// manifest (pull-missing negotiation: the RECEIVER computes this
    /// over its store and sends it as the sender's `have` set).
    pub fn transferable_ids(&self, branch_id: &str) -> StoreResult<Option<Vec<String>>> {
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        let manifest = self.load_manifest(branch.head_manifest_hash.as_deref())?;
        Ok(Some(crate::bundle::transferable_ids(
            &manifest,
            &self.content,
        )?))
    }

    /// Import a bundle: store its payloads (content-addressed, so
    /// re-import is free), re-create the branch, and advance it to the
    /// bundle's state as ONE cut carrying the TRANSPORTED change id.
    /// Idempotent — a branch already at the bundle's state is
    /// `AlreadyPresent`; a branch with different local content is
    /// refused, never clobbered.
    pub fn import_bundle(
        &mut self,
        bundle: &crate::bundle::WorkspaceBundle,
        at: &str,
    ) -> StoreResult<crate::bundle::BundleImportOutcome> {
        use crate::bundle::BundleImportOutcome;
        if bundle.format != crate::bundle::BUNDLE_FORMAT {
            return Err(StoreError::Conflict(format!(
                "unknown bundle format `{}`",
                bundle.format
            )));
        }
        // A bundle is a fully external, serde-deserialized document
        // (`whip branch import`). Before persisting ANY of its state,
        // reject manifest keys that would escape the workspace root when
        // later materialized, and verify that every blob's content id is
        // the true content-address of the bytes it carries — otherwise a
        // hostile bundle could bind a content id (a hash callers trust to
        // commit to its bytes) to attacker-chosen content, forging
        // content-addressed data or resurrecting an erased blob.
        for key in bundle.manifest.keys() {
            crate::materialize::validate_manifest_key(key)?;
        }
        let max_blob_bytes = crate::content::max_blob_bytes();
        for blob in &bundle.blobs {
            if let Some(chunk_ids) = &blob.chunk_ids {
                // Fail-fast on an honestly-declared oversize root before doing
                // any work; a lying (small) `byte_len` is still caught at read
                // time by the reassembly ceiling in `ContentStore::get`.
                if blob.byte_len > max_blob_bytes {
                    return Err(StoreError::Conflict(format!(
                        "bundle chunk-root `{}` declares {} bytes, over the {max_blob_bytes}-byte \
                         blob ceiling (WHIPPLESCRIPT_MAX_BLOB_BYTES)",
                        blob.id, blob.byte_len
                    )));
                }
                // A chunk ROOT id is the content hash over the ordered
                // child chunk ids (their hex bytes concatenated); verify
                // the claimed root id re-derives from the chunk list so an
                // import cannot bind an arbitrary id to a forged structure.
                let mut id_bytes: Vec<u8> = Vec::new();
                for chunk_id in chunk_ids {
                    id_bytes.extend_from_slice(chunk_id.as_bytes());
                }
                let derived = crate::chunking::content_hash_hex(&id_bytes);
                if derived != blob.id {
                    return Err(StoreError::Conflict(format!(
                        "bundle chunk-root id `{}` does not match its chunk list \
                         (derived `{derived}`); refusing forged content address",
                        blob.id
                    )));
                }
                // A chunk root must never resurrect an id the local store
                // has erased (tombstone honesty): the payload is gone by
                // decision and an import must not silently rebind it.
                if matches!(
                    self.content.status(&blob.id)?,
                    crate::content::BlobStatus::Erased { .. }
                ) {
                    return Err(StoreError::Conflict(format!(
                        "bundle re-binds erased content `{}`; refusing resurrection",
                        blob.id
                    )));
                }
                // A chunk root: re-link the structure without
                // re-chunking; an erased root lands as the tombstone it
                // is (identity, no payload).
                self.content
                    .put_chunk_root(&blob.id, chunk_ids, blob.byte_len)?;
                if blob.erased {
                    self.content.erase(&blob.id, at)?;
                }
                continue;
            }
            if let Some(body) = &blob.body {
                if matches!(
                    self.content.status(&blob.id)?,
                    crate::content::BlobStatus::Erased { .. }
                ) {
                    return Err(StoreError::Conflict(format!(
                        "bundle re-binds erased content `{}`; refusing resurrection",
                        blob.id
                    )));
                }
                // `put` stores under the true content hash of `body`;
                // assert the bundle's claimed id equals it so a mismatched
                // (forged) id is refused rather than silently ignored. NOTE
                // (v0.1 trust assumption): the id is a 64-bit non-cryptographic
                // hash (see chunking::content_hash_hex), so this check proves
                // body↔id CONSISTENCY, not authenticity — a determined attacker
                // can craft colliding bytes. Bundle import is only forgery-safe
                // from a mutually-trusted sender until the id primitive is
                // re-keyed to SHA-256 (tracked, deferred).
                let stored = self.content.put(body)?;
                if stored != blob.id {
                    return Err(StoreError::Conflict(format!(
                        "bundle blob id `{}` does not match its content (hashes to `{stored}`)",
                        blob.id
                    )));
                }
            } else if blob.omitted {
                // The sender skipped this unit because we declared we
                // have it — verify, fail honest if the negotiation lied.
                if !matches!(
                    self.content.status(&blob.id)?,
                    crate::content::BlobStatus::Live { .. }
                ) {
                    return Err(StoreError::Conflict(format!(
                        "delta bundle omitted `{}` but this store does not hold it",
                        blob.id
                    )));
                }
            }
        }
        let manifest_hash = self.store_manifest(&bundle.manifest)?;
        let branch_id = bundle.branch.branch_id.clone();
        self.branches.ensure_mainline(at)?;
        if let Some(existing) = self.branches.get_branch(&branch_id)? {
            // Compared by CONTENT, not by manifest root id. `AlreadyPresent`
            // means "the branch already carries this state", which is a claim
            // about what the branch holds — and comparing roots made it a claim
            // about tree LAYOUT as well, so any change to how manifests are
            // shaped would have made an identical branch import as divergent
            // and refused an idempotent import as a conflict. That is the one
            // place tree layout was a cross-machine agreement; it is not one
            // now, which is what lets the shape be corrected at all.
            let already_present = existing.head_manifest_hash.as_deref() == Some(&manifest_hash)
                || self.load_manifest(existing.head_manifest_hash.as_deref())? == bundle.manifest;
            return Ok(if already_present {
                BundleImportOutcome::AlreadyPresent { branch_id }
            } else {
                BundleImportOutcome::DivergentBranch {
                    branch_id,
                    local_head_manifest_hash: existing.head_manifest_hash,
                }
            });
        }
        let created = self.branches.create_branch(CreateBranch {
            branch_id: &branch_id,
            name: bundle.branch.name.as_deref(),
            parent_branch_id: MAINLINE_BRANCH_ID,
            at_cut: None,
            created_at: at,
            idempotency_key: None,
        })?;
        let CreateBranchOutcome::Created(created_row) = created else {
            return Err(StoreError::Conflict(format!(
                "bundle import could not create branch `{branch_id}`: {created:?}"
            )));
        };
        // Identity travels: the branch's recorded cuts land first, so the
        // imported head cut resolves to its ORIGINAL change id and a
        // later merge reunifies instead of duplicating.
        for cut in &bundle.cuts {
            self.branches.record_cut(CutRecord {
                cut_id: &cut.cut_id,
                change_id: &cut.change_id,
                branch_id: &cut.branch_id,
                manifest_hash: &cut.manifest_hash,
                parent_cut_id: cut.parent_cut_id.as_deref(),
                origin: cut.origin.as_deref(),
                actor: self.actor.as_deref(),
                intent: self.intent.as_deref(),
                recorded_at: &cut.recorded_at,
            })?;
        }
        let cut_id = bundle
            .branch
            .head_cut_id
            .clone()
            .unwrap_or_else(|| format!("bundle-{manifest_hash}"));
        let transported_change = bundle
            .head_change_id
            .clone()
            .unwrap_or_else(|| cut_id.clone());
        match self.branches.advance_head(
            &branch_id,
            created_row.head_cut_id.as_deref(),
            &cut_id,
            &manifest_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                self.branches.record_cut(CutRecord {
                    cut_id: &cut_id,
                    change_id: &transported_change,
                    branch_id: &branch_id,
                    manifest_hash: &manifest_hash,
                    parent_cut_id: None,
                    origin: Some("bundle-import"),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-import-bundle-{branch_id}-{manifest_hash}"),
                    "import-bundle",
                    vec![Self::op_delta(Some(&created_row), &advanced)],
                    Some("bundle-import"),
                    at,
                )?;
                Ok(BundleImportOutcome::Imported {
                    branch_id,
                    cut_id,
                    manifest_hash,
                })
            }
            other => Err(StoreError::Conflict(format!(
                "bundle import could not land on `{branch_id}`: {other:?}"
            ))),
        }
    }

    /// Erase one path's payload on a branch (the honesty downgrade over
    /// the substrate): the blob's bytes drop store-wide, its hash and
    /// size remain, every manifest stays coherent. `None` = no such
    /// branch or path. NOT a write — the manifest is untouched; only the
    /// content plane loses the payload.
    pub fn erase_path(
        &mut self,
        branch_id: &str,
        path: &str,
        at: &str,
    ) -> StoreResult<Option<(String, crate::content::EraseOutcome)>> {
        let Some(manifest) = self.manifest(branch_id)? else {
            return Ok(None);
        };
        let Some(hash) = manifest.get(path) else {
            return Ok(None);
        };
        let outcome = self.content.erase(hash, at)?;
        if matches!(outcome, crate::content::EraseOutcome::Erased { .. }) {
            self.log_op(
                &format!("op-erase-{hash}"),
                "erase",
                Vec::new(),
                Some(&format!("erase:{path}@{hash}")),
                at,
            )?;
        }
        Ok(Some((hash.clone(), outcome)))
    }

    /// Status + hash plumbing for one branch. `None` = no such branch.
    pub fn status_report(&self, branch_id: &str) -> StoreResult<Option<BranchStatusReport>> {
        let Some(branch) = self.branches.get_branch(branch_id)? else {
            return Ok(None);
        };
        let point = self.load_manifest(branch.branch_point_manifest_hash.as_deref())?;
        let head = self.load_manifest(branch.head_manifest_hash.as_deref())?;
        let ahead_paths = Self::diff_paths(&point, &head);
        let behind = match branch.parent_branch_id.as_deref() {
            None => false,
            Some(parent_id) => match self.branches.get_branch(parent_id)? {
                None => false,
                Some(parent) => {
                    Self::cut_ref(&branch.branch_point_cut_id) != Self::cut_ref(&parent.head_cut_id)
                }
            },
        };
        let head_change_id = self.change_of(branch.head_cut_id.as_deref())?;
        let bound_instances = self.branches.list_bound_instances(branch_id)?;
        Ok(Some(BranchStatusReport {
            branch,
            head_change_id,
            ahead_paths,
            behind,
            bound_instances,
        }))
    }

    /// Every active branch with pending flow in either direction — the
    /// daemon's work list and the host's "what needs attention" view.
    pub fn reconcile_list(&self) -> StoreResult<Vec<ReconcileEntry>> {
        let mut entries = Vec::new();
        for branch in self.branches.list_branches(Some(BranchStatus::Active))? {
            let Some(parent_id) = branch.parent_branch_id.clone() else {
                continue;
            };
            let Some(parent) = self.branches.get_branch(&parent_id)? else {
                continue;
            };
            let behind =
                Self::cut_ref(&branch.branch_point_cut_id) != Self::cut_ref(&parent.head_cut_id);
            let point = self.load_manifest(branch.branch_point_manifest_hash.as_deref())?;
            let head = self.load_manifest(branch.head_manifest_hash.as_deref())?;
            let ahead_paths = Self::diff_paths(&point, &head).len();
            if behind || ahead_paths > 0 {
                entries.push(ReconcileEntry {
                    branch_id: branch.branch_id,
                    target_branch_id: parent_id,
                    ahead_paths,
                    behind,
                });
            }
        }
        Ok(entries)
    }

    /// Commit an imported scratch diff (materialize.rs) as ONE cut on the
    /// branch: atomic (a single head advance carries the whole diff),
    /// recorded, complete (the caller stored every blob first), keyed by
    /// the effect-derived `cut_id`, and IDEMPOTENT — a crash-retry that
    /// finds the head already at this cut is a no-op success, so
    /// re-driving the effect never double-applies.
    pub fn import_diff(
        &mut self,
        branch_id: &str,
        changed: &BTreeMap<String, String>,
        removed: &[String],
        cut_id: &str,
        at: &str,
    ) -> StoreResult<VcsWriteOutcome> {
        let Some(row) = self.branches.get_branch(branch_id)? else {
            return Ok(VcsWriteOutcome::BranchMissing);
        };
        if row.head_cut_id.as_deref() == Some(cut_id) {
            // The idempotent retry: this effect's import already landed.
            return Ok(VcsWriteOutcome::Written {
                cut_id: cut_id.to_owned(),
                manifest_hash: row.head_manifest_hash.unwrap_or_default(),
            });
        }
        if row.status != BranchStatus::Active {
            return Ok(VcsWriteOutcome::BranchNotActive);
        }
        let mut manifest = self.load_manifest(row.head_manifest_hash.as_deref())?;
        for (path, hash) in changed {
            manifest.insert(path.clone(), hash.clone());
        }
        for path in removed {
            manifest.remove(path);
        }
        let manifest_hash = self.store_manifest(&manifest)?;
        match self.branches.advance_head(
            branch_id,
            row.head_cut_id.as_deref(),
            cut_id,
            &manifest_hash,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                self.branches.record_cut(CutRecord {
                    cut_id,
                    change_id: cut_id,
                    branch_id,
                    manifest_hash: &manifest_hash,
                    parent_cut_id: row.head_cut_id.as_deref(),
                    origin: Some("import"),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                self.log_op(
                    &format!("op-{cut_id}"),
                    "import",
                    vec![Self::op_delta(Some(&row), &advanced)],
                    Some("import"),
                    at,
                )?;
                Ok(VcsWriteOutcome::Written {
                    cut_id: cut_id.to_owned(),
                    manifest_hash,
                })
            }
            AdvanceOutcome::Stale {
                current_head_cut_id,
            } => {
                if current_head_cut_id.as_deref() == Some(cut_id) {
                    // Raced with our own retry: the import landed.
                    return Ok(VcsWriteOutcome::Written {
                        cut_id: cut_id.to_owned(),
                        manifest_hash,
                    });
                }
                Err(StoreError::Conflict(
                    "branch head moved during the import; retry".to_owned(),
                ))
            }
            AdvanceOutcome::NotActive { .. } => Ok(VcsWriteOutcome::BranchNotActive),
            AdvanceOutcome::NotFound => Ok(VcsWriteOutcome::BranchMissing),
        }
    }

    /// Greedy in-stream sync (workstream auto-admit) and boundary
    /// promotion share one mechanism: fold the LINE's deltas down
    /// (certified source merges refine; conflicts isolate this
    /// contribution), then advance the line to the branch's content and
    /// re-point the branch fully in sync — zero divergence, still
    /// active. The caller runs this at quiescence and under the adoption
    /// lease where the line is a promotion boundary.
    pub fn sync_to_line(
        &mut self,
        branch_id: &str,
        line_id: &str,
        sync_cut_id: &str,
        at: &str,
    ) -> StoreResult<SyncOutcome> {
        if branch_id == line_id {
            return Ok(SyncOutcome::UpToDate);
        }
        let line_row = match self.branches.get_branch(line_id)? {
            None => return Ok(SyncOutcome::LineMissing),
            Some(line) if line.status != BranchStatus::Active => {
                return Ok(SyncOutcome::LineNotActive)
            }
            Some(line) => line,
        };
        // Dual identity's detection: the SAME change on both heads with
        // DIFFERENT content is the transported-then-edited case — surface
        // both versions, never merge silently.
        if let Some(branch_row) = self.branches.get_branch(branch_id)? {
            let ours_change = self.change_of(branch_row.head_cut_id.as_deref())?;
            let theirs_change = self.change_of(line_row.head_cut_id.as_deref())?;
            if let (Some(ours), Some(theirs)) = (&ours_change, &theirs_change) {
                if ours == theirs && branch_row.head_manifest_hash != line_row.head_manifest_hash {
                    return Ok(SyncOutcome::DivergentChange {
                        change_id: ours.clone(),
                        ours_manifest_hash: branch_row.head_manifest_hash,
                        theirs_manifest_hash: line_row.head_manifest_hash,
                    });
                }
            }
        }
        match self.reconcile_branch_against(
            branch_id,
            Some(line_id),
            true,
            &format!("{sync_cut_id}-rebase"),
            at,
        )? {
            ReconcileOutcome::UpToDate | ReconcileOutcome::Rebased { .. } => {}
            ReconcileOutcome::DeferredMidRun => unreachable!("synced at quiescence"),
            ReconcileOutcome::Conflicts { conflicts } => {
                return Ok(SyncOutcome::Conflicts { conflicts });
            }
            ReconcileOutcome::BranchMissing => return Ok(SyncOutcome::BranchMissing),
            ReconcileOutcome::BranchNotActive => return Ok(SyncOutcome::BranchNotActive),
            ReconcileOutcome::NoParent => return Ok(SyncOutcome::LineMissing),
        }
        let branch = self
            .branches
            .get_branch(branch_id)?
            .ok_or_else(|| StoreError::Conflict("branch vanished mid-sync".to_owned()))?;
        let line = self
            .branches
            .get_branch(line_id)?
            .ok_or_else(|| StoreError::Conflict("line vanished mid-sync".to_owned()))?;
        if branch.head_manifest_hash == branch.branch_point_manifest_hash {
            return Ok(SyncOutcome::UpToDate);
        }
        if Self::cut_ref(&branch.branch_point_cut_id) != Self::cut_ref(&line.head_cut_id) {
            return Err(StoreError::Conflict(
                "line advanced mid-sync; retry".to_owned(),
            ));
        }
        let head_manifest = branch
            .head_manifest_hash
            .clone()
            .unwrap_or_else(|| self.store_manifest(&BTreeMap::new()).unwrap_or_default());
        // Transport preserves identity: the admitted cut carries the
        // member head's change id, so the eventual full merge recognizes
        // it as THE SAME change (no ancestry-less duplicates).
        let transported_change = self
            .change_of(branch.head_cut_id.as_deref())?
            .unwrap_or_else(|| sync_cut_id.to_owned());
        let origin = format!("sync:{branch_id}");
        let line_advanced = match self.branches.advance_head(
            line_id,
            line.head_cut_id.as_deref(),
            sync_cut_id,
            &head_manifest,
            at,
        )? {
            AdvanceOutcome::Advanced(advanced) => {
                self.branches.record_cut(CutRecord {
                    cut_id: sync_cut_id,
                    change_id: &transported_change,
                    branch_id: line_id,
                    manifest_hash: &head_manifest,
                    parent_cut_id: line.head_cut_id.as_deref(),
                    origin: Some(&origin),
                    actor: self.actor.as_deref(),
                    intent: self.intent.as_deref(),
                    recorded_at: at,
                })?;
                advanced
            }
            AdvanceOutcome::Stale { .. } => {
                return Err(StoreError::Conflict(
                    "line advanced mid-sync; retry".to_owned(),
                ))
            }
            AdvanceOutcome::NotActive { .. } => return Ok(SyncOutcome::LineNotActive),
            AdvanceOutcome::NotFound => return Ok(SyncOutcome::LineMissing),
        };
        // The member re-points fully in sync (point == head == the sync
        // cut) and keeps working.
        match self.branches.rebase_branch(
            branch_id,
            branch.head_cut_id.as_deref(),
            sync_cut_id,
            &head_manifest,
            sync_cut_id,
            &head_manifest,
            at,
        )? {
            AdvanceOutcome::Advanced(repointed) => {
                self.log_op(
                    &format!("op-{sync_cut_id}"),
                    "sync",
                    vec![
                        Self::op_delta(Some(&line), &line_advanced),
                        Self::op_delta(Some(&branch), &repointed),
                    ],
                    Some(&origin),
                    at,
                )?;
                Ok(SyncOutcome::Synced {
                    sync_cut_id: sync_cut_id.to_owned(),
                })
            }
            AdvanceOutcome::Stale { .. } => Err(StoreError::Conflict(
                "branch head moved mid-sync; retry".to_owned(),
            )),
            AdvanceOutcome::NotActive { .. } => Ok(SyncOutcome::BranchNotActive),
            AdvanceOutcome::NotFound => Ok(SyncOutcome::BranchMissing),
        }
    }

    /// Materialize-on-exec: project the branch's head manifest into a
    /// real scratch directory (materialize.rs). `None` = no such branch.
    #[cfg(feature = "native")]
    pub fn materialize_branch(
        &self,
        branch_id: &str,
        root: &Path,
        now_unix_nanos: i128,
    ) -> StoreResult<Option<crate::materialize::MaterializedScratch>> {
        let Some(manifest) = self.manifest(branch_id)? else {
            return Ok(None);
        };
        crate::materialize::materialize_manifest(&manifest, &self.content, root, now_unix_nanos)
            .map(Some)
    }

    /// Import-back: scan the scratch against its seeded cache, store every
    /// changed blob, and commit the whole diff as ONE effect-keyed,
    /// idempotent cut on the branch.
    #[cfg(feature = "native")]
    #[allow(clippy::too_many_arguments)]
    pub fn import_scratch(
        &mut self,
        branch_id: &str,
        root: &Path,
        scratch: &crate::materialize::MaterializedScratch,
        cut_id: &str,
        at: &str,
        now_unix_nanos: i128,
    ) -> StoreResult<(crate::materialize::ScratchImport, VcsWriteOutcome)> {
        let import =
            crate::materialize::import_scratch(root, scratch, &self.content, now_unix_nanos)?;
        let outcome = self.import_diff(branch_id, &import.changed, &import.removed, cut_id, at)?;
        Ok((import, outcome))
    }

    /// Bind an instance to the branch it is born on (write-once; see
    /// `Branches::bind_instance`).
    pub fn bind_instance(
        &mut self,
        instance_id: &str,
        branch_id: &str,
        at: &str,
    ) -> StoreResult<crate::branches::BindOutcome> {
        self.branches.ensure_mainline(at)?;
        self.branches.bind_instance(instance_id, branch_id, at)
    }

    pub fn instance_branch(&self, instance_id: &str) -> StoreResult<Option<String>> {
        self.branches.instance_branch(instance_id)
    }

    pub fn list_bound_instances_of(&self, branch_id: &str) -> StoreResult<Vec<String>> {
        self.branches.list_bound_instances(branch_id)
    }

    pub fn reserve_branch_head(
        &mut self,
        branch_id: &str,
        reservation_id: &str,
        at: &str,
    ) -> StoreResult<crate::branches::HeadReservationOutcome> {
        self.branches.reserve_head(branch_id, reservation_id, at)
    }

    pub fn release_branch_head_reservation(
        &mut self,
        branch_id: &str,
        reservation_id: &str,
    ) -> StoreResult<bool> {
        self.branches
            .release_head_reservation(branch_id, reservation_id)
    }

    /// The branch half of a chat fork (chat-fork.maude): give the forked
    /// instance its OWN line — a fresh branch forked at the source line's
    /// current head, bound to the target at birth. Never rebinds the fork
    /// to the source's branch (two instances stepping one line would be
    /// divergent histories of the same run) and never moves the source.
    /// An unbound source is an honest outcome, not an error: the fork is
    /// thread-only, like the source itself.
    pub fn fork_binding_for_instance(
        &mut self,
        source_instance: &str,
        target_instance: &str,
        fork_branch_id: &str,
        name: Option<&str>,
        at: &str,
    ) -> StoreResult<InstanceForkBinding> {
        let Some(source_branch_id) = self.instance_branch(source_instance)? else {
            return Ok(InstanceForkBinding::SourceUnbound);
        };
        let fork_branch =
            match self.fork_with_lineage(fork_branch_id, name, &source_branch_id, None, at)? {
                CreateBranchOutcome::Created(row) => row,
                // Replay tolerance: the same fork re-issued finds its branch;
                // an unrelated branch squatting on the id is a refusal.
                CreateBranchOutcome::Existing(row)
                    if row.parent_branch_id.as_deref() == Some(source_branch_id.as_str()) =>
                {
                    row
                }
                CreateBranchOutcome::Existing(row) => {
                    return Ok(InstanceForkBinding::ForkBranchIdTaken {
                        branch_id: row.branch_id,
                    });
                }
                CreateBranchOutcome::NameTaken { holder_branch_id } => {
                    return Ok(InstanceForkBinding::ForkBranchIdTaken {
                        branch_id: holder_branch_id,
                    });
                }
                CreateBranchOutcome::ParentMissing => {
                    return Ok(InstanceForkBinding::SourceBranchUnavailable {
                        branch_id: source_branch_id,
                    });
                }
                CreateBranchOutcome::ParentNotActive { .. } => {
                    return Ok(InstanceForkBinding::SourceBranchUnavailable {
                        branch_id: source_branch_id,
                    });
                }
            };
        match self.bind_instance(target_instance, &fork_branch.branch_id, at)? {
            crate::branches::BindOutcome::Bound => {}
            crate::branches::BindOutcome::AlreadyBound { branch_id }
                if branch_id == fork_branch.branch_id => {}
            crate::branches::BindOutcome::AlreadyBound { branch_id } => {
                return Ok(InstanceForkBinding::TargetAlreadyBound { branch_id });
            }
            crate::branches::BindOutcome::BranchMissing
            | crate::branches::BindOutcome::BranchNotActive { .. } => {
                return Err(StoreError::Conflict(format!(
                    "fork branch `{}` closed underneath its own creation",
                    fork_branch.branch_id
                )));
            }
        }
        Ok(InstanceForkBinding::Forked {
            source_branch_id,
            fork_branch: Box::new(fork_branch),
        })
    }

    /// Exact-cut variant for application fork snapshots. Content always comes
    /// from `source_cut_id`; destination workstream admission is deliberately
    /// a separate authority operation and must not replace the branch point.
    pub fn preflight_fork_binding_for_instance_at_cut(
        &self,
        source_instance: &str,
        source_cut_id: &str,
        target_instance: &str,
        fork_branch_id: &str,
        name: Option<&str>,
    ) -> StoreResult<ExactInstanceForkPreflight> {
        let Some(source_branch_id) = self.instance_branch(source_instance)? else {
            return Ok(ExactInstanceForkPreflight::Refused(
                ExactInstanceForkBinding::SourceUnbound,
            ));
        };
        let Some(source_branch) = self.get_branch(&source_branch_id)? else {
            return Ok(ExactInstanceForkPreflight::Refused(
                ExactInstanceForkBinding::SourceBranchUnavailable {
                    branch_id: source_branch_id,
                },
            ));
        };
        if source_branch.status != BranchStatus::Active {
            return Ok(ExactInstanceForkPreflight::Refused(
                ExactInstanceForkBinding::SourceBranchUnavailable {
                    branch_id: source_branch_id,
                },
            ));
        }
        let Some(source_cut) = self.get_cut(source_cut_id)? else {
            return Ok(ExactInstanceForkPreflight::Refused(
                ExactInstanceForkBinding::SourceCutMissing {
                    cut_id: source_cut_id.to_owned(),
                },
            ));
        };
        if source_cut.branch_id != source_branch_id {
            return Ok(ExactInstanceForkPreflight::Refused(
                ExactInstanceForkBinding::SourceCutNotOnBranch {
                    cut_id: source_cut_id.to_owned(),
                    recorded_branch_id: source_cut.branch_id,
                },
            ));
        }
        if let Some(branch_id) = self.instance_branch(target_instance)? {
            return Ok(ExactInstanceForkPreflight::Refused(
                ExactInstanceForkBinding::TargetAlreadyBound { branch_id },
            ));
        }
        if let Some(row) = self.get_branch(fork_branch_id)? {
            if row.status != BranchStatus::Active
                || row.parent_branch_id.as_deref() != Some(source_branch_id.as_str())
                || row.branch_point_cut_id.as_deref() != Some(source_cut_id)
            {
                return Ok(ExactInstanceForkPreflight::Refused(
                    ExactInstanceForkBinding::ForkBranchIdTaken {
                        branch_id: row.branch_id,
                    },
                ));
            }
        } else if let Some(name) = name {
            if let Some(holder) = self
                .list_branches(Some(BranchStatus::Active))?
                .into_iter()
                .find(|row| row.name.as_deref() == Some(name))
            {
                return Ok(ExactInstanceForkPreflight::Refused(
                    ExactInstanceForkBinding::ForkBranchIdTaken {
                        branch_id: holder.branch_id,
                    },
                ));
            }
        }
        Ok(ExactInstanceForkPreflight::Ready)
    }

    pub fn fork_binding_for_instance_at_cut(
        &mut self,
        source_instance: &str,
        source_cut_id: &str,
        target_instance: &str,
        fork_branch_id: &str,
        name: Option<&str>,
        at: &str,
    ) -> StoreResult<ExactInstanceForkBinding> {
        if let ExactInstanceForkPreflight::Refused(refusal) = self
            .preflight_fork_binding_for_instance_at_cut(
                source_instance,
                source_cut_id,
                target_instance,
                fork_branch_id,
                name,
            )?
        {
            return Ok(refusal);
        }
        let Some(source_branch_id) = self.instance_branch(source_instance)? else {
            return Ok(ExactInstanceForkBinding::SourceUnbound);
        };
        let Some(source_branch) = self.get_branch(&source_branch_id)? else {
            return Ok(ExactInstanceForkBinding::SourceBranchUnavailable {
                branch_id: source_branch_id,
            });
        };
        if source_branch.status != BranchStatus::Active {
            return Ok(ExactInstanceForkBinding::SourceBranchUnavailable {
                branch_id: source_branch_id,
            });
        }
        let Some(source_cut) = self.get_cut(source_cut_id)? else {
            return Ok(ExactInstanceForkBinding::SourceCutMissing {
                cut_id: source_cut_id.to_owned(),
            });
        };
        if source_cut.branch_id != source_branch_id {
            return Ok(ExactInstanceForkBinding::SourceCutNotOnBranch {
                cut_id: source_cut_id.to_owned(),
                recorded_branch_id: source_cut.branch_id,
            });
        }
        if let Some(branch_id) = self.instance_branch(target_instance)? {
            return Ok(ExactInstanceForkBinding::TargetAlreadyBound { branch_id });
        }
        let fork_branch = match self.fork_with_lineage(
            fork_branch_id,
            name,
            &source_branch_id,
            Some(source_cut_id),
            at,
        )? {
            CreateBranchOutcome::Created(row) => row,
            CreateBranchOutcome::Existing(row)
                if row.parent_branch_id.as_deref() == Some(source_branch_id.as_str())
                    && row.branch_point_cut_id.as_deref() == Some(source_cut_id) =>
            {
                row
            }
            CreateBranchOutcome::Existing(row) => {
                return Ok(ExactInstanceForkBinding::ForkBranchIdTaken {
                    branch_id: row.branch_id,
                })
            }
            CreateBranchOutcome::NameTaken { holder_branch_id } => {
                return Ok(ExactInstanceForkBinding::ForkBranchIdTaken {
                    branch_id: holder_branch_id,
                })
            }
            CreateBranchOutcome::ParentMissing | CreateBranchOutcome::ParentNotActive { .. } => {
                return Ok(ExactInstanceForkBinding::SourceBranchUnavailable {
                    branch_id: source_branch_id,
                })
            }
        };
        match self.bind_instance(target_instance, &fork_branch.branch_id, at)? {
            crate::branches::BindOutcome::Bound => {}
            crate::branches::BindOutcome::AlreadyBound { branch_id }
                if branch_id == fork_branch.branch_id => {}
            crate::branches::BindOutcome::AlreadyBound { branch_id } => {
                return Ok(ExactInstanceForkBinding::TargetAlreadyBound { branch_id })
            }
            crate::branches::BindOutcome::BranchMissing
            | crate::branches::BindOutcome::BranchNotActive { .. } => {
                return Err(StoreError::Conflict(format!(
                    "exact fork branch `{}` closed underneath its own creation",
                    fork_branch.branch_id
                )))
            }
        }
        let evidence_handle = format!(
            "sha256:{}",
            crate::chunking::content_hash_hex(
                format!(
                    "exact-fork-v1|{source_branch_id}|{source_cut_id}|{}|{}",
                    fork_branch.branch_id, source_cut.manifest_hash
                )
                .as_bytes()
            )
        );
        Ok(ExactInstanceForkBinding::Forked {
            source_branch_id,
            source_cut_id: source_cut_id.to_owned(),
            fork_branch: Box::new(fork_branch),
            evidence_handle,
        })
    }

    /// Mainline's id, for callers that don't hardcode it.
    pub fn mainline() -> &'static str {
        MAINLINE_BRANCH_ID
    }

    /// The content seam, for callers that need the concrete store's
    /// tier entry points (chunked puts, packing).
    pub fn content_store(&self) -> &C {
        &self.content
    }
}

/// A branch-bound instance's file surface: the `FileStore` the effect
/// handlers dispatch onto when the instance was born on a branch. Every
/// mutation write-throughs a cut on the branch (COW — nothing outside the
/// branch changes); reads resolve the branch's current head. Cut ids
/// derive from the effect id (`<effect>-f<n>`), so one effect's file
/// operations are attributable cuts. Interior mutability because the
/// `FileStore` seam takes `&self`.
pub struct BranchFileStore<B: Branches, C: ContentBlobs> {
    vcs: std::cell::RefCell<WorkspaceVcs<B, C>>,
    branch_id: String,
    cut_seed: String,
    at: String,
    counter: std::cell::Cell<u64>,
}

impl<B: Branches, C: ContentBlobs> BranchFileStore<B, C> {
    pub fn new(vcs: WorkspaceVcs<B, C>, branch_id: &str, cut_seed: &str, at: &str) -> Self {
        Self {
            vcs: std::cell::RefCell::new(vcs),
            branch_id: branch_id.to_owned(),
            cut_seed: cut_seed.to_owned(),
            at: at.to_owned(),
            counter: std::cell::Cell::new(0),
        }
    }

    fn next_cut_id(&self) -> String {
        let index = self.counter.get();
        self.counter.set(index + 1);
        format!("{}-f{index}", self.cut_seed)
    }

    fn io_error(error: StoreError) -> std::io::Error {
        std::io::Error::other(format!("branch file store: {error:?}"))
    }

    fn apply(&self, path: &Path, body: Option<&str>) -> std::io::Result<()> {
        let cut_id = self.next_cut_id();
        let path_key = path.to_string_lossy();
        match self
            .vcs
            .borrow_mut()
            .write(&self.branch_id, &path_key, body, &cut_id, &self.at)
            .map_err(Self::io_error)?
        {
            VcsWriteOutcome::Written { .. } => Ok(()),
            VcsWriteOutcome::BranchMissing => Err(std::io::Error::other(format!(
                "instance is bound to unknown branch `{}`",
                self.branch_id
            ))),
            VcsWriteOutcome::BranchNotActive => Err(std::io::Error::other(format!(
                "instance is bound to closed branch `{}`",
                self.branch_id
            ))),
        }
    }
}

impl<B: Branches, C: ContentBlobs> FileStore for BranchFileStore<B, C> {
    fn read_to_string(&self, path: &Path) -> std::io::Result<String> {
        let path_key = path.to_string_lossy();
        match self
            .vcs
            .borrow()
            .read(&self.branch_id, &path_key)
            .map_err(Self::io_error)?
        {
            Some(body) => Ok(body),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no file at {path_key} on branch `{}`", self.branch_id),
            )),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        let path_key = path.to_string_lossy();
        self.vcs
            .borrow()
            .read(&self.branch_id, &path_key)
            .map(|body| body.is_some())
            .unwrap_or(false)
    }

    fn create_dir_all(&self, _path: &Path) -> std::io::Result<()> {
        Ok(())
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let body = std::str::from_utf8(bytes).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("non-UTF-8 write to {}: {error}", path.display()),
            )
        })?;
        self.apply(path, Some(body))
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        let existing = match self.read_to_string(path) {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error),
        };
        let suffix = std::str::from_utf8(bytes).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("non-UTF-8 append to {}: {error}", path.display()),
            )
        })?;
        let mut body = existing;
        body.push_str(suffix);
        self.apply(path, Some(&body))
    }

    fn remove(&self, path: &Path) -> std::io::Result<()> {
        self.apply(path, None)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    /// A vcs bound to a temp directory that is removed when the binding drops,
    /// including on a panicking assertion. `Deref`/`DerefMut` keep the 21 call
    /// sites unchanged: `let mut vcs = vcs(); vcs.init("t0")` still works.
    ///
    /// Before this, every test left its directory behind — 200 of them had
    /// accumulated in the RAM-backed /tmp.
    struct TempVcs {
        dir: std::path::PathBuf,
        inner: NativeWorkspaceVcs,
    }

    impl std::ops::Deref for TempVcs {
        type Target = NativeWorkspaceVcs;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl std::ops::DerefMut for TempVcs {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    impl Drop for TempVcs {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn vcs() -> TempVcs {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-vcs-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        let inner = WorkspaceVcs::open(dir.join("branches.sqlite"), dir.join("content.sqlite"))
            .expect("open vcs");
        TempVcs { dir, inner }
    }

    /// DR-0052 A1: cuts carry the handle's acting principal; attribution
    /// and change-units surface it; an un-attributed handle records
    /// `None` (the honest pre-actor reading, same as migrated rows).
    #[test]
    fn cuts_carry_the_observed_actor() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.set_actor(Some("s:sess-7".to_owned()));
        assert!(matches!(
            vcs.write(MAINLINE_BRANCH_ID, "src/a.md", Some("one"), "cut_1", "t1")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        let rows = vcs
            .attribution(MAINLINE_BRANCH_ID)
            .expect("attribution")
            .expect("branch exists");
        assert_eq!(rows[0].actor.as_deref(), Some("s:sess-7"));
        // A later un-attributed handle: the newest unit wins attribution,
        // honestly None.
        vcs.set_actor(None);
        assert!(matches!(
            vcs.write(MAINLINE_BRANCH_ID, "src/a.md", Some("two"), "cut_2", "t2")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        let rows = vcs
            .attribution(MAINLINE_BRANCH_ID)
            .expect("attribution")
            .expect("branch exists");
        assert_eq!(rows[0].actor, None);
        // The unit stream keeps both, oldest first.
        let units = vcs.change_units(MAINLINE_BRANCH_ID, 10).expect("units");
        assert_eq!(units[0].actor.as_deref(), Some("s:sess-7"));
        assert_eq!(units[1].actor, None);
    }

    /// DR-0052 L4: the change-unit index is a pure cache — indexed reads
    /// equal fresh computes byte-for-byte, maintenance is incremental
    /// (only the unindexed tail), and window semantics are unchanged.
    #[test]
    fn change_unit_index_is_transparent_and_incremental() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.set_actor(Some("s:sess-7".to_owned()));
        // Three cuts before any maintenance (write() maintains, so use
        // the branches seam via ordinary writes and compare outputs).
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("one"), "cut_1", "t1")
            .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "b.md", Some("two"), "cut_2", "t2")
            .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("three"), "cut_3", "t3")
            .expect("write");
        let indexed = vcs.change_units(MAINLINE_BRANCH_ID, 500).expect("units");
        assert_eq!(indexed.len(), 3);
        // The cursor is warm (write() maintained): nothing left to index.
        assert_eq!(
            vcs.maintain_change_unit_index(MAINLINE_BRANCH_ID)
                .expect("maintain"),
            0
        );
        // A reset forces full recompute; output is identical.
        vcs.branches
            .reset_change_unit_index(MAINLINE_BRANCH_ID)
            .expect("reset");
        let fresh = vcs.change_units(MAINLINE_BRANCH_ID, 500).expect("units");
        assert_eq!(indexed, fresh);
        // Maintenance after reset reindexes everything; a second pass is
        // a no-op; a new cut indexes exactly its own units.
        assert_eq!(
            vcs.maintain_change_unit_index(MAINLINE_BRANCH_ID)
                .expect("maintain"),
            3
        );
        vcs.write(MAINLINE_BRANCH_ID, "c.md", Some("four"), "cut_4", "t4")
            .expect("write");
        assert_eq!(
            vcs.maintain_change_unit_index(MAINLINE_BRANCH_ID)
                .expect("maintain"),
            0,
            "write() already maintained"
        );
        let after = vcs.change_units(MAINLINE_BRANCH_ID, 500).expect("units");
        assert_eq!(after.len(), 4);
        // Window semantics: last 2 cuts, seq re-based.
        let windowed = vcs.change_units(MAINLINE_BRANCH_ID, 2).expect("units");
        assert_eq!(windowed.len(), 2);
        assert_eq!(windowed[0].seq, 0);
        assert_eq!(windowed[0].cut_id, "cut_3");
        assert_eq!(windowed[1].cut_id, "cut_4");
    }

    /// DR-0084 Decision 3: the frontier content map is the freshness
    /// evaluator's second argument — every manifest path with its content
    /// id, plus canonical decl hashes where the canonicalizer applies, and
    /// PATH-ONLY entries where it does not (fail closed). Together with the
    /// pure evaluator this is the end-to-end round-trip check: edit, undo
    /// by writing the original content back, and the attest-time
    /// fingerprint is fresh again.
    #[test]
    fn frontier_content_feeds_content_identity_freshness() {
        struct StubCanon2;
        impl DeclCanonicalizer for StubCanon2 {
            fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>> {
                let mut declarations = Vec::new();
                for line in source.lines() {
                    if line == "ERR" {
                        return None;
                    }
                    let (name, hash) = line.split_once('=')?;
                    declarations.push(CanonDecl {
                        identity: name.to_owned(),
                        canon_hash: hash.to_owned(),
                        rename_hash: hash.to_owned(),
                    });
                }
                Some(declarations)
            }
        }
        use whipplescript_core::freshness::{evaluate, resolve_basis, Freshness};
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.set_decl_canonicalizer(Box::new(StubCanon2));
        vcs.write(
            MAINLINE_BRANCH_ID,
            "main.whip",
            Some("rule a=k1\nrule b=k2"),
            "cut_1",
            "t1",
        )
        .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "bad.whip", Some("ERR"), "cut_2", "t2")
            .expect("write");

        let (at_cut, frontier) = vcs
            .frontier_content(MAINLINE_BRANCH_ID)
            .expect("frontier")
            .expect("branch exists");
        assert!(at_cut.is_some(), "head cut recorded as the at-cut");
        assert_eq!(frontier.decls.get("rule a"), Some(&"k1".to_owned()));
        assert_eq!(frontier.decls.get("rule b"), Some(&"k2".to_owned()));
        // Non-canonicalizable content: a path entry, no decl entries.
        assert!(frontier.paths.contains_key("bad.whip"));
        assert!(!frontier.decls.keys().any(|k| k.contains("ERR")));

        // Attest-time fingerprint over the rule-a declaration.
        let basis = crate::selection::parse("decl(rule a)").expect("parse");
        let fingerprint = resolve_basis(&basis, &frontier).expect("resolve");
        assert_eq!(evaluate(&fingerprint, &frontier), Freshness::Fresh);

        // Edit rule a -> stale; write the original back (the undo) -> fresh.
        vcs.write(
            MAINLINE_BRANCH_ID,
            "main.whip",
            Some("rule a=k9\nrule b=k2"),
            "cut_3",
            "t3",
        )
        .expect("write");
        let (_, edited) = vcs
            .frontier_content(MAINLINE_BRANCH_ID)
            .expect("frontier")
            .expect("branch");
        assert!(matches!(
            evaluate(&fingerprint, &edited),
            Freshness::Stale { .. }
        ));
        vcs.write(
            MAINLINE_BRANCH_ID,
            "main.whip",
            Some("rule a=k1\nrule b=k2"),
            "cut_4",
            "t4",
        )
        .expect("write");
        let (_, round_trip) = vcs
            .frontier_content(MAINLINE_BRANCH_ID)
            .expect("frontier")
            .expect("branch");
        assert_eq!(evaluate(&fingerprint, &round_trip), Freshness::Fresh);
    }

    /// DR-0086 Decision 1 (F1): the FrontierRead trait conforms to the
    /// inherent methods on a live store, answers INERT on an untouched
    /// one — Ok(None)/empty, never an error, so a workspace that has
    /// never used the VCS behaves as if the world were empty — and the
    /// InertFrontier stand-in is inert by construction.
    #[test]
    fn frontier_read_trait_conforms_and_is_inert_when_empty() {
        struct StubCanon3;
        impl DeclCanonicalizer for StubCanon3 {
            fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>> {
                let mut declarations = Vec::new();
                for line in source.lines() {
                    let (name, hash) = line.split_once('=')?;
                    declarations.push(CanonDecl {
                        identity: name.to_owned(),
                        canon_hash: hash.to_owned(),
                        rename_hash: hash.to_owned(),
                    });
                }
                Some(declarations)
            }
        }
        // Untouched store: inert, not an error.
        let empty = vcs();
        assert_eq!(
            FrontierRead::frontier_content(&*empty, MAINLINE_BRANCH_ID).expect("inert"),
            None
        );
        assert!(empty
            .frontier_change_units(MAINLINE_BRANCH_ID, 10)
            .expect("inert")
            .is_empty());
        assert_eq!(
            empty
                .frontier_file(MAINLINE_BRANCH_ID, "src/a.whip")
                .expect("inert"),
            None
        );

        // Live store: the trait IS the inherent surface.
        let mut live = vcs();
        live.init("t0").expect("init");
        live.set_decl_canonicalizer(Box::new(StubCanon3));
        live.write(
            MAINLINE_BRANCH_ID,
            "main.whip",
            Some("rule a=k1"),
            "cut_f1",
            "t1",
        )
        .expect("write");
        let (at_cut, frontier) = FrontierRead::frontier_content(&*live, MAINLINE_BRANCH_ID)
            .expect("frontier")
            .expect("branch exists");
        assert!(at_cut.is_some());
        assert_eq!(frontier.decls.get("rule a"), Some(&"k1".to_owned()));
        let inherent = live
            .frontier_content(MAINLINE_BRANCH_ID)
            .expect("frontier")
            .expect("branch");
        assert_eq!(inherent.1, frontier, "trait == inherent");
        assert_eq!(
            live.frontier_change_units(MAINLINE_BRANCH_ID, 10)
                .expect("units")
                .len(),
            live.change_units(MAINLINE_BRANCH_ID, 10)
                .expect("units")
                .len()
        );
        assert_eq!(
            live.frontier_file(MAINLINE_BRANCH_ID, "main.whip")
                .expect("read")
                .as_deref(),
            Some("rule a=k1")
        );

        // The no-world stand-in: inert everywhere.
        let inert = InertFrontier;
        assert_eq!(
            inert.frontier_content(MAINLINE_BRANCH_ID).expect("inert"),
            None
        );
        assert!(inert
            .frontier_change_units(MAINLINE_BRANCH_ID, 10)
            .expect("inert")
            .is_empty());
        assert_eq!(
            inert
                .frontier_file(MAINLINE_BRANCH_ID, "main.whip")
                .expect("inert"),
            None
        );
    }

    /// DR-0054: with a canonicalizer installed, `.whip` units carry
    /// declaration-level sub-rows (persisted through the index and
    /// identical on recompute); non-`.whip` paths and unparseable sides
    /// stay path-level, and the `decl()` atom selects over the sub-rows.
    #[test]
    fn decl_sub_rows_ride_the_index_and_the_decl_atom() {
        // A stub canonicalizer: each line `name=hash` is one declaration
        // (`ERR` = no canonical form) — the seam under test is the
        // store's, not the parser's.
        struct StubCanon;
        impl DeclCanonicalizer for StubCanon {
            fn canonical_declarations(&self, source: &str) -> Option<Vec<CanonDecl>> {
                let mut declarations = Vec::new();
                for line in source.lines() {
                    if line == "ERR" {
                        return None;
                    }
                    let (name, hash) = line.split_once('=')?;
                    declarations.push(CanonDecl {
                        identity: name.to_owned(),
                        canon_hash: hash.to_owned(),
                        rename_hash: hash.to_owned(),
                    });
                }
                Some(declarations)
            }
        }
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.set_decl_canonicalizer(Box::new(StubCanon));
        vcs.set_actor(Some("s:sess-7".to_owned()));
        vcs.write(
            MAINLINE_BRANCH_ID,
            "main.whip",
            Some("rule a=k1\nrule b=k2"),
            "cut_1",
            "t1",
        )
        .expect("write");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "main.whip",
            Some("rule a=k1\nrule b=k9\nclass C=k3"),
            "cut_2",
            "t2",
        )
        .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "notes.md", Some("prose"), "cut_3", "t3")
            .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "bad.whip", Some("ERR"), "cut_4", "t4")
            .expect("write");
        let units = vcs.change_units(MAINLINE_BRANCH_ID, 500).expect("units");
        assert_eq!(units.len(), 4);
        // cut_1: both declarations added.
        assert_eq!(units[0].decls.len(), 2);
        assert_eq!(units[0].decls[0].identity, "rule a");
        assert_eq!(units[0].decls[0].before_canon, None);
        // cut_2: `rule a` untouched, `rule b` changed, `class C` added.
        let changed: Vec<&str> = units[1]
            .decls
            .iter()
            .map(|decl| decl.identity.as_str())
            .collect();
        assert_eq!(changed, vec!["class C", "rule b"]);
        // Non-source and unparseable paths stay path-level.
        assert!(units[2].decls.is_empty());
        assert!(units[3].decls.is_empty());
        // The persisted index serves the SAME sub-rows (prefix path).
        assert_eq!(
            vcs.maintain_change_unit_index(MAINLINE_BRANCH_ID)
                .expect("maintain"),
            0
        );
        let from_index = vcs.change_units(MAINLINE_BRANCH_ID, 500).expect("units");
        assert_eq!(units, from_index);
        // decl() selects over the sub-rows.
        let expr = crate::selection::parse("decl(rule b)").expect("parse");
        let selected = crate::selection::eval(&expr, &units);
        assert_eq!(selected, std::collections::BTreeSet::from([0, 1]));
    }

    /// DR-0052 A5: operations queue `workspace.*` facts for the caller
    /// to route — a write queues `cut.recorded`; a stranding refusal
    /// queues `op.refused`; the drain empties the queue.
    #[test]
    fn operations_queue_workspace_facts() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.set_actor(Some("s:sess-7".to_owned()));
        vcs.write(MAINLINE_BRANCH_ID, "src/a.md", Some("one"), "cut_1", "t1")
            .expect("write");
        let facts = vcs.take_pending_facts();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].0, "vcs.cut.recorded");
        assert_eq!(facts[0].1["branch"], "main");
        assert_eq!(facts[0].1["by"], "s:sess-7");
        assert_eq!(facts[0].1["path"], "src/a.md");
        assert!(vcs.take_pending_facts().is_empty(), "drain empties");
        // A dependent later write makes undoing the first a stranding
        // refusal — which must queue `vcs.op.refused`.
        vcs.write(MAINLINE_BRANCH_ID, "src/a.md", Some("two"), "cut_2", "t2")
            .expect("write");
        let expr = crate::selection::parse("cut(cut_1)").expect("parse");
        let outcome = vcs
            .apply_undo_selection(MAINLINE_BRANCH_ID, &expr, "cut_3", "t3")
            .expect("undo");
        assert!(matches!(outcome, UndoSelectionOutcome::WouldStrand { .. }));
        let facts = vcs.take_pending_facts();
        let refused = facts
            .iter()
            .find(|(name, _)| name == "vcs.op.refused")
            .expect("refusal fact queued");
        assert_eq!(refused.1["reason"], "stranded");
    }

    /// The full integrated loop: init → branch → isolated writes → merge
    /// adopts into mainline → the branch is immutable history.
    #[test]
    fn branch_write_merge_roundtrip() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        // Seed mainline.
        assert!(matches!(
            vcs.write(
                MAINLINE_BRANCH_ID,
                "notes/a.md",
                Some("base A"),
                "cut_m1",
                "t1"
            )
            .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        // Branch and diverge.
        assert!(matches!(
            vcs.create_branch("draft_a", Some("triage"), MAINLINE_BRANCH_ID, "t2")
                .expect("create"),
            CreateBranchOutcome::Created(_)
        ));
        assert!(matches!(
            vcs.write("draft_a", "notes/a.md", Some("draft A"), "cut_d1", "t3")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        // Isolation both ways.
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "notes/a.md").expect("read"),
            Some("base A".to_owned())
        );
        assert_eq!(
            vcs.read("draft_a", "notes/a.md").expect("read"),
            Some("draft A".to_owned())
        );
        // Merge: adopted, mainline sees the branch content, branch is
        // terminal history.
        assert_eq!(
            vcs.merge("draft_a", "cut_merge_1", "t4").expect("merge"),
            VcsMergeOutcome::Adopted {
                merge_cut_id: "cut_merge_1".to_owned(),
                into_branch_id: MAINLINE_BRANCH_ID.to_owned(),
            }
        );
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "notes/a.md").expect("read"),
            Some("draft A".to_owned())
        );
        let adopted = vcs.get_branch("draft_a").expect("get").expect("row");
        assert_eq!(adopted.status, BranchStatus::Adopted);
        // Writes to adopted history are refused.
        assert_eq!(
            vcs.write("draft_a", "x.md", Some("nope"), "cut_x", "t5")
                .expect("write"),
            VcsWriteOutcome::BranchNotActive
        );
    }

    /// The GC sweep reclaims only true orphans: content no recorded cut,
    /// branch pointer, resolution memory, or conflict row can name.
    /// Historical cut bodies, current heads, and remembered region
    /// payloads all survive; a directly-stored stray blob does not.
    #[test]
    fn purge_unreachable_reclaims_orphans_and_spares_everything_nameable() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        assert!(matches!(
            vcs.write(
                MAINLINE_BRANCH_ID,
                "a.md",
                Some("first body"),
                "cut_1",
                "t1"
            )
            .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        assert!(matches!(
            vcs.write(
                MAINLINE_BRANCH_ID,
                "a.md",
                Some("second body"),
                "cut_2",
                "t2"
            )
            .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        // Remembered region resolution: its payload must survive the sweep.
        vcs.record_region_resolutions(
            &[RegionResolution {
                base_text: "dog".to_owned(),
                ours_text: "tiger".to_owned(),
                theirs_text: "lion".to_owned(),
                resolution_text: "liger".to_owned(),
            }],
            "t3",
        )
        .expect("record");
        // A stray blob nothing names — the one thing the sweep may take.
        let orphan = vcs.content_store().put("orphaned residue").expect("put");
        let outcome = vcs.purge_unreachable("t9").expect("purge");
        assert!(outcome.purged >= 1, "the orphan was reclaimed: {outcome:?}");
        assert_eq!(
            vcs.content_store().get(&orphan).expect("get"),
            None,
            "orphan gone"
        );
        // The head reads; the SUPERSEDED body still reads through its cut.
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md").expect("read"),
            Some("second body".to_owned())
        );
        let old_manifest = vcs
            .cut_manifest("cut_1")
            .expect("cut manifest")
            .expect("recorded");
        let old_id = old_manifest.get("a.md").expect("entry");
        assert_eq!(
            vcs.content_store().get(old_id).expect("get"),
            Some("first body".to_owned()),
            "archaeology intact"
        );
        // The remembered payload still applies: the same divergence folds
        // to the settled text instead of re-asking.
        assert!(matches!(
            vcs.write(
                MAINLINE_BRANCH_ID,
                "b.md",
                Some("the dog sleeps"),
                "cut_3",
                "t4"
            )
            .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        assert!(matches!(
            vcs.write(
                MAINLINE_BRANCH_ID,
                "b.md",
                Some("the tiger sleeps"),
                "cut_4",
                "t5"
            )
            .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        let saved = vcs
            .save_with_base(
                MAINLINE_BRANCH_ID,
                "b.md",
                "the lion sleeps",
                "cut_3",
                &[],
                "cut_5",
                "t6",
            )
            .expect("save");
        let SaveWithBaseOutcome::Merged { merged, .. } = saved else {
            panic!("memory should fold the remembered region, got {saved:?}");
        };
        assert_eq!(merged, "the liger sleeps");
    }

    /// A LONG-LIVED member line merges with `merge_keeping`: the parent
    /// adopts the content, the branch stays ACTIVE with an empty delta at
    /// the merge cut, and the next divergence merges again — repeatedly,
    /// which is the shape `merge`'s adopt-terminal refuses on the second
    /// round.
    #[test]
    fn merge_keeping_lands_content_and_line_lives_on() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        assert!(matches!(
            vcs.create_branch("chat", None, MAINLINE_BRANCH_ID, "t1")
                .expect("create"),
            CreateBranchOutcome::Created(_)
        ));
        assert!(matches!(
            vcs.write("chat", "a.md", Some("first turn"), "cut_c1", "t2")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        assert_eq!(
            vcs.merge_keeping("chat", "cut_keep1", "t3").expect("merge"),
            VcsMergeOutcome::Landed {
                merge_cut_id: "cut_keep1".to_owned(),
                into_branch_id: MAINLINE_BRANCH_ID.to_owned(),
            }
        );
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md").expect("read"),
            Some("first turn".to_owned())
        );
        // Still active, empty delta, based at the merge cut.
        let row = vcs.get_branch("chat").expect("get").expect("row");
        assert_eq!(row.status, BranchStatus::Active);
        assert_eq!(row.branch_point_cut_id.as_deref(), Some("cut_keep1"));
        assert_eq!(row.head_cut_id.as_deref(), Some("cut_keep1"));
        // A second round writes and lands again — including a rebase-down
        // past mainline movement in between.
        assert!(matches!(
            vcs.write(
                MAINLINE_BRANCH_ID,
                "b.md",
                Some("elsewhere"),
                "cut_m2",
                "t4"
            )
            .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        assert!(matches!(
            vcs.write("chat", "a.md", Some("second turn"), "cut_c2", "t5")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        assert_eq!(
            vcs.merge_keeping("chat", "cut_keep2", "t6").expect("merge"),
            VcsMergeOutcome::Landed {
                merge_cut_id: "cut_keep2".to_owned(),
                into_branch_id: MAINLINE_BRANCH_ID.to_owned(),
            }
        );
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md").expect("read"),
            Some("second turn".to_owned())
        );
        assert_eq!(
            vcs.read("chat", "b.md").expect("read"),
            Some("elsewhere".to_owned()),
            "the rebase-down folded mainline's move into the live line"
        );
    }

    /// Retarget moves ONLY the lineage pointer: a chat branch re-homed
    /// onto a workstream merges into the WORKSTREAM afterwards, a
    /// reconcile folds the new parent's deltas down, and any retarget
    /// that would bend parent pointers into a cycle (including
    /// self-parent) is refused.
    #[test]
    fn retarget_rehomes_merge_target_and_refuses_cycles() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        assert!(matches!(
            vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("base"), "cut_m1", "t1")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        assert!(matches!(
            vcs.create_branch("ws", Some("stream"), MAINLINE_BRANCH_ID, "t2")
                .expect("create"),
            CreateBranchOutcome::Created(_)
        ));
        assert!(matches!(
            vcs.create_branch("chat", Some("chat"), MAINLINE_BRANCH_ID, "t2")
                .expect("create"),
            CreateBranchOutcome::Created(_)
        ));
        // The workstream advances on its own file; the chat writes another.
        assert!(matches!(
            vcs.write("ws", "ws.md", Some("stream work"), "cut_w1", "t3")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        assert!(matches!(
            vcs.write("chat", "chat.md", Some("chat work"), "cut_c1", "t3")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        // Re-home the chat under the workstream.
        assert!(matches!(
            vcs.retarget("chat", "ws", "t4").expect("retarget"),
            RetargetOutcome::Retargeted(_)
        ));
        // The new parent's deltas fold DOWN on reconcile (disjoint paths
        // compose silently)…
        assert!(matches!(
            vcs.reconcile_branch("chat", false, "cut_reb1", "t5")
                .expect("reconcile"),
            ReconcileOutcome::Rebased { .. }
        ));
        assert_eq!(
            vcs.read("chat", "ws.md").expect("read"),
            Some("stream work".to_owned())
        );
        // …and merge now adopts into the workstream, not mainline.
        assert_eq!(
            vcs.merge("chat", "cut_merge_c", "t6").expect("merge"),
            VcsMergeOutcome::Adopted {
                merge_cut_id: "cut_merge_c".to_owned(),
                into_branch_id: "ws".to_owned(),
            }
        );
        assert_eq!(
            vcs.read("ws", "chat.md").expect("read"),
            Some("chat work".to_owned())
        );
        // Mainline never saw either line's work.
        assert_eq!(vcs.read(MAINLINE_BRANCH_ID, "chat.md").expect("read"), None);
        // Guards: a retarget that bends the tree into a cycle is refused —
        // "ws" under its (adopted) child is caught by the not-active guard
        // first, so build a live A→B chain to prove the cycle walk bites.
        assert!(matches!(
            vcs.create_branch("a", None, MAINLINE_BRANCH_ID, "t7")
                .expect("create"),
            CreateBranchOutcome::Created(_)
        ));
        assert!(matches!(
            vcs.create_branch("b", None, "a", "t7").expect("create"),
            CreateBranchOutcome::Created(_)
        ));
        assert_eq!(
            vcs.retarget("a", "b", "t8").expect("retarget"),
            RetargetOutcome::WouldCycle
        );
        assert_eq!(
            vcs.retarget("a", "a", "t8").expect("retarget"),
            RetargetOutcome::WouldCycle
        );
        assert_eq!(
            vcs.retarget("a", "ghost", "t8").expect("retarget"),
            RetargetOutcome::ParentMissing
        );
        assert_eq!(
            vcs.retarget("ghost", "a", "t8").expect("retarget"),
            RetargetOutcome::BranchMissing
        );
    }

    /// A parent that advanced DISJOINTLY rebases in silently during the
    /// merge; both lines' content lands on mainline.
    #[test]
    fn merge_auto_rebases_disjoint_parent_advance() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("A0"), "cut_m1", "t1")
            .expect("write");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t2")
            .expect("create");
        vcs.write("draft_a", "a.md", Some("A1"), "cut_d1", "t3")
            .expect("write");
        // Mainline advances on a DIFFERENT path after the branch point.
        vcs.write(MAINLINE_BRANCH_ID, "b.md", Some("B1"), "cut_m2", "t4")
            .expect("write");
        assert!(matches!(
            vcs.merge("draft_a", "cut_merge_1", "t5").expect("merge"),
            VcsMergeOutcome::Adopted { .. }
        ));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md").expect("read"),
            Some("A1".to_owned())
        );
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "b.md").expect("read"),
            Some("B1".to_owned())
        );
    }

    /// Token-level text merge (spec/text-merge-spec.md): disjoint word
    /// edits to the SAME file — even the same sentence — compose during
    /// the merge instead of escalating; both sides' words land on
    /// mainline. The case the path-level merge could never grant.
    #[test]
    fn disjoint_text_edits_to_one_file_compose_on_merge() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        let base = "The quick brown fox jumps over the lazy dog tonight.";
        vcs.write(MAINLINE_BRANCH_ID, "notes/a.md", Some(base), "cut_m1", "t1")
            .expect("write");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t2")
            .expect("create");
        vcs.write(
            "draft_a",
            "notes/a.md",
            Some("The swift brown fox jumps over the lazy dog tonight."),
            "cut_d1",
            "t3",
        )
        .expect("write");
        // Mainline advances on the SAME path after the branch point.
        vcs.write(
            MAINLINE_BRANCH_ID,
            "notes/a.md",
            Some("The quick brown fox jumps over the lazy cat tonight."),
            "cut_m2",
            "t4",
        )
        .expect("write");
        assert!(matches!(
            vcs.merge("draft_a", "cut_merge_1", "t5").expect("merge"),
            VcsMergeOutcome::Adopted { .. }
        ));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "notes/a.md").expect("read"),
            Some("The swift brown fox jumps over the lazy cat tonight.".to_owned())
        );
    }

    /// The text tier stays honest: overlapping rewrites of the same words
    /// still escalate, and `.whip` sources never reach it (fail closed
    /// without a source merger installed) — the merge-slice bite is
    /// untouched.
    #[test]
    fn overlapping_text_edits_and_whip_sources_still_escalate() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        let prose = "The quick brown fox jumps over the lazy dog.";
        // Would text-compose cleanly, but lives in a .whip source path.
        let source = "agent triage does classify tickets by urgency every hour.";
        vcs.write(
            MAINLINE_BRANCH_ID,
            "notes/a.md",
            Some(prose),
            "cut_m1",
            "t1",
        )
        .expect("write");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "prog.whip",
            Some(source),
            "cut_m2",
            "t2",
        )
        .expect("write");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t3")
            .expect("create");
        vcs.write(
            "draft_a",
            "notes/a.md",
            Some("The nimble crimson fox jumps over the lazy dog."),
            "cut_d1",
            "t4",
        )
        .expect("write");
        vcs.write(
            "draft_a",
            "prog.whip",
            Some("agent sorting does classify tickets by urgency every hour."),
            "cut_d2",
            "t5",
        )
        .expect("write");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "notes/a.md",
            Some("The slow grey fox jumps over the lazy dog."),
            "cut_m3",
            "t6",
        )
        .expect("write");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "prog.whip",
            Some("agent triage does classify tickets by severity every hour."),
            "cut_m4",
            "t7",
        )
        .expect("write");
        let outcome = vcs.merge("draft_a", "cut_merge_1", "t8").expect("merge");
        let VcsMergeOutcome::Conflicted { conflicts } = outcome else {
            panic!("expected escalation, got {outcome:?}");
        };
        let paths: Vec<&str> = conflicts
            .iter()
            .map(|conflict| conflict.path.as_str())
            .collect();
        assert!(
            paths.contains(&"notes/a.md"),
            "overlap escalates: {paths:?}"
        );
        assert!(
            paths.contains(&"prog.whip"),
            ".whip never text-merges: {paths:?}"
        );
    }

    /// DR-0070 §1, the measurement the tracker gated the content tier on —
    /// now **inverted**, because the tree landed.
    ///
    /// Its first version measured the wrong thing, and the flaw is worth
    /// recording: it serialized the materialized map and compared sizes, which
    /// says how big a manifest *is*, not how many bytes a cut *writes*. That
    /// number barely moves when the storage layout changes, so the test would
    /// have kept passing whether or not the tree delivered anything.
    ///
    /// What actually matters is the count of NEW nodes a one-entry change
    /// mints. Under the old flat layout it was one whole-workspace blob every
    /// time, deduplicating with nothing. Under the tree it is a spine: the leaf
    /// that changed and its ancestors, with every other subtree keeping its id
    /// and costing nothing.
    #[test]
    fn a_one_file_edit_mints_only_a_spine() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");

        const FILES: usize = 256;
        let mut last_manifest = String::new();
        for index in 0..FILES {
            let outcome = vcs
                .write(
                    MAINLINE_BRANCH_ID,
                    &format!("src/file_{index:04}.txt"),
                    Some("original body"),
                    &format!("cut_seed_{index}"),
                    "t1",
                )
                .expect("seed write");
            if let VcsWriteOutcome::Written { manifest_hash, .. } = outcome {
                last_manifest = manifest_hash;
            }
        }

        let before_ids = crate::manifest_tree::reachable_ids(&vcs.content, &last_manifest)
            .expect("the manifest is a tree and walks whole");

        // Change exactly one file out of FILES.
        let outcome = vcs
            .write(
                MAINLINE_BRANCH_ID,
                "src/file_0000.txt",
                Some("edited body"),
                "cut_edit",
                "t2",
            )
            .expect("edit write");
        let VcsWriteOutcome::Written { manifest_hash, .. } = outcome else {
            panic!("the edit should have written");
        };
        let after_ids =
            crate::manifest_tree::reachable_ids(&vcs.content, &manifest_hash).expect("walks whole");

        let minted = after_ids.difference(&before_ids).count();
        assert!(
            minted > 0 && minted <= 12,
            "a one-entry change in a {FILES}-entry manifest should mint a spine \
             (its leaf, its ancestors, and the new blob), got {minted} new ids. \
             If this grew, the tree stopped sharing unchanged subtrees and the \
             DR-0070 §1 win is gone."
        );

        // And the content still reads back whole through the compatibility seam.
        let materialized = vcs
            .manifest(MAINLINE_BRANCH_ID)
            .expect("manifest reads")
            .expect("branch exists");
        assert_eq!(materialized.len(), FILES);
    }

    /// DR-0070 §1's migration decision: a compatibility read path keyed by
    /// shape, and no rewrite of existing cuts. A manifest written flat before
    /// the tree must still read, because cuts are immutable and rewriting them
    /// would mint new identities for cuts that already exist.
    #[test]
    fn a_flat_manifest_written_before_the_tree_still_reads() {
        let vcs = vcs();
        let flat: BTreeMap<String, String> =
            BTreeMap::from([("legacy/a.txt".to_owned(), "hash-a".to_owned())]);
        let body = serde_json::to_string(&flat).expect("encodes");
        let hash = vcs.content.put(&body).expect("legacy manifest stores");

        assert!(
            !crate::manifest_tree::is_node(&body),
            "a flat manifest must not be mistaken for a tree node"
        );
        assert_eq!(
            vcs.load_manifest(Some(&hash))
                .expect("legacy manifest reads"),
            flat
        );
    }

    /// The editor save verb (spec §12.1): unmoved head writes plain; a
    /// disjoint concurrent head advance MERGES draft and head; an
    /// overlapping one returns Conflicted and writes NOTHING.
    #[test]
    fn save_with_base_fast_path_merge_and_conflict() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        let base = "The quick brown fox jumps over the lazy dog tonight.";
        vcs.write(MAINLINE_BRANCH_ID, "notes/a.md", Some(base), "cut_m1", "t1")
            .expect("write");
        // Fast path: head is exactly the editor's base.
        let draft1 = "The swift brown fox jumps over the lazy dog tonight.";
        assert_eq!(
            vcs.save_with_base(
                MAINLINE_BRANCH_ID,
                "notes/a.md",
                draft1,
                "cut_m1",
                &[],
                "cut_s1",
                "t2",
            )
            .expect("save"),
            SaveWithBaseOutcome::Written {
                cut_id: "cut_s1".to_owned()
            }
        );
        // Concurrent DISJOINT advance: an agent changes "brown" -> "grey"
        // while the editor (based at cut_s1) changes "tonight" -> "today"
        // — six words apart, well past the proximity dial.
        vcs.write(
            MAINLINE_BRANCH_ID,
            "notes/a.md",
            Some("The swift grey fox jumps over the lazy dog tonight."),
            "cut_m2",
            "t3",
        )
        .expect("write");
        let draft2 = "The swift brown fox jumps over the lazy dog today.";
        let outcome = vcs
            .save_with_base(
                MAINLINE_BRANCH_ID,
                "notes/a.md",
                draft2,
                "cut_s1",
                &[],
                "cut_s2",
                "t4",
            )
            .expect("save");
        let SaveWithBaseOutcome::Merged { merged, .. } = &outcome else {
            panic!("expected merged save, got {outcome:?}");
        };
        assert_eq!(merged, "The swift grey fox jumps over the lazy dog today.");
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "notes/a.md").expect("read"),
            Some("The swift grey fox jumps over the lazy dog today.".to_owned())
        );
        // Concurrent OVERLAPPING advance: both rewrite "today"; nothing
        // moves and the fold payload carries all three slices.
        vcs.write(
            MAINLINE_BRANCH_ID,
            "notes/a.md",
            Some("The swift grey fox jumps over the lazy dog tomorrow."),
            "cut_m3",
            "t5",
        )
        .expect("write");
        let outcome = vcs
            .save_with_base(
                MAINLINE_BRANCH_ID,
                "notes/a.md",
                "The swift grey fox jumps over the lazy dog tonight.",
                "cut_s2",
                &[],
                "cut_s3",
                "t6",
            )
            .expect("save");
        let SaveWithBaseOutcome::Conflicted { pieces, .. } = &outcome else {
            panic!("expected conflicted save, got {outcome:?}");
        };
        assert!(pieces
            .iter()
            .any(|piece| matches!(piece, crate::text_merge::MergePiece::Conflict { .. })));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "notes/a.md").expect("read"),
            Some("The swift grey fox jumps over the lazy dog tomorrow.".to_owned()),
            "a conflicted save writes NOTHING"
        );
    }

    /// merge_preview computes the fold without writing, and an unknown
    /// base cut is refused rather than guessed at.
    #[test]
    fn merge_preview_reads_only() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.md",
            Some("alpha beta gamma delta epsilon zeta eta"),
            "cut_m1",
            "t1",
        )
        .expect("write");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.md",
            Some("alpha BETA gamma delta epsilon zeta eta"),
            "cut_m2",
            "t2",
        )
        .expect("write");
        let preview = vcs
            .merge_preview(
                MAINLINE_BRANCH_ID,
                "a.md",
                "alpha beta gamma delta epsilon zeta ETA",
                "cut_m1",
            )
            .expect("preview")
            .expect("known base");
        assert!(preview.clean, "disjoint edits preview clean: {preview:?}");
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md").expect("read"),
            Some("alpha BETA gamma delta epsilon zeta eta".to_owned()),
            "preview never writes"
        );
        assert!(vcs
            .merge_preview(MAINLINE_BRANCH_ID, "a.md", "x", "no_such_cut")
            .expect("preview")
            .is_none());
    }

    /// The payforward loop (spec §12.2–12.3): a region resolved in the
    /// EDITOR (resolved save → region memory, both orientations) auto-
    /// applies when a BRANCH merge later hits the identical region triple
    /// — rerere for prose, minted at the save surface.
    #[test]
    fn region_resolution_pays_forward_to_branch_merge() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        let base = "alpha beta gamma delta epsilon";
        let head_edit = "alpha beta GAMMA delta epsilon";
        let draft_edit = "alpha beta gamma-two delta epsilon";
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some(base), "cut_m1", "t1")
            .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some(head_edit), "cut_m2", "t2")
            .expect("write");
        // The editor (based at cut_m1) collides with the head edit.
        let outcome = vcs
            .save_with_base(
                MAINLINE_BRANCH_ID,
                "a.md",
                draft_edit,
                "cut_m1",
                &[],
                "cut_s1",
                "t3",
            )
            .expect("save");
        let SaveWithBaseOutcome::Conflicted {
            pieces,
            head_cut_id,
        } = outcome
        else {
            panic!("expected conflict");
        };
        let (region_base, region_ours, region_theirs) = pieces
            .iter()
            .find_map(|piece| match piece {
                crate::text_merge::MergePiece::Conflict {
                    base_text,
                    ours_text,
                    theirs_text,
                } => Some((base_text.clone(), ours_text.clone(), theirs_text.clone())),
                _ => None,
            })
            .expect("one region");
        // The user settles the region and re-saves against the fresh head.
        let resolved_body = "alpha beta GAMMA-TWO delta epsilon";
        let resolutions = vec![crate::text_merge::RegionResolution {
            base_text: region_base,
            ours_text: region_ours.clone(),
            theirs_text: region_theirs,
            resolution_text: region_ours.replace("GAMMA", "GAMMA-TWO"),
        }];
        let outcome = vcs
            .save_with_base(
                MAINLINE_BRANCH_ID,
                "a.md",
                resolved_body,
                head_cut_id.as_deref().expect("head cut"),
                &resolutions,
                "cut_s2",
                "t4",
            )
            .expect("save");
        assert!(
            matches!(outcome, SaveWithBaseOutcome::Written { .. }),
            "resolved re-save against the fresh head writes plain: {outcome:?}"
        );
        // A BRANCH now reproduces the identical region triple on another
        // path: branch takes the draft-side edit, mainline the head-side
        // edit. The remembered resolution folds it — the merge adopts.
        vcs.write(MAINLINE_BRANCH_ID, "b.md", Some(base), "cut_m4", "t5")
            .expect("write");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t6")
            .expect("create");
        vcs.write("draft_a", "b.md", Some(head_edit), "cut_d1", "t7")
            .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "b.md", Some(draft_edit), "cut_m5", "t8")
            .expect("write");
        assert!(matches!(
            vcs.merge("draft_a", "cut_merge_1", "t9").expect("merge"),
            VcsMergeOutcome::Adopted { .. }
        ));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "b.md").expect("read"),
            Some("alpha beta GAMMA-TWO delta epsilon".to_owned()),
            "the editor's region resolution propagated to the branch merge"
        );
    }

    /// A conflicting parent advance escalates: structured conflicts,
    /// NOTHING moves, the branch stays active; resolving on the branch
    /// (writing the merged content) makes the next merge... still honest:
    /// the same path diverges again, so resolution IS the branch's own
    /// write and the second merge adopts it only after the conflict is
    /// gone from the three-way (base catches up via the resolve write).
    #[test]
    fn conflicting_merge_escalates_and_resolves_by_branch_write() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("A0"), "cut_m1", "t1")
            .expect("write");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t2")
            .expect("create");
        vcs.write("draft_a", "a.md", Some("draft A"), "cut_d1", "t3")
            .expect("write");
        // Mainline advances on the SAME path: a real conflict.
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("main A"), "cut_m2", "t4")
            .expect("write");
        let VcsMergeOutcome::Conflicted { conflicts } =
            vcs.merge("draft_a", "cut_merge_1", "t5").expect("merge")
        else {
            panic!("expected escalation");
        };
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "a.md");
        assert_eq!(conflicts[0].ours_side.label, "draft_a");
        // Nothing moved.
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md").expect("read"),
            Some("main A".to_owned())
        );
        assert_eq!(
            vcs.get_branch("draft_a").expect("get").expect("row").status,
            BranchStatus::Active
        );
        // Resolution is an ordinary provenance-carrying edit on the
        // branch: write the merged content, then merge again — but the
        // three-way still sees divergence vs the OLD base... resolve by
        // matching mainline's change is a take-theirs; an authored merge
        // needs the branch to agree with mainline for this path to stop
        // conflicting. Authored resolution:
        vcs.write("draft_a", "a.md", Some("main A + draft A"), "cut_d2", "t6")
            .expect("write");
        // Still conflicted (base didn't move): the honest outcome.
        assert!(matches!(
            vcs.merge("draft_a", "cut_merge_2", "t7").expect("merge"),
            VcsMergeOutcome::Conflicted { .. }
        ));
        // Take-ours-into-mainline path: mainline itself adopts the
        // resolution as an ordinary edit (manual override — plain editing
        // is complete over states), after which the branch merges clean.
        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.md",
            Some("main A + draft A"),
            "cut_m3",
            "t8",
        )
        .expect("write");
        vcs.write("draft_a", "a.md", Some("main A + draft A"), "cut_d3", "t9")
            .expect("write");
        assert!(matches!(
            vcs.merge("draft_a", "cut_merge_3", "t10").expect("merge"),
            VcsMergeOutcome::Adopted { .. }
        ));
    }

    /// import_diff commits a whole scratch diff as ONE effect-keyed cut,
    /// and the crash-retry (same cut id) is a no-op success — never a
    /// double-apply, never a spurious conflict.
    #[test]
    fn import_diff_is_atomic_and_idempotent() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("A0"), "cut_m1", "t1")
            .expect("write");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t2")
            .expect("create");
        let mut changed = BTreeMap::new();
        changed.insert(
            "out.md".to_owned(),
            vcs.content.put("produced").expect("put"),
        );
        changed.insert(
            "a.md".to_owned(),
            vcs.content.put("A modified").expect("put"),
        );
        let removed = Vec::new();
        let first = vcs
            .import_diff("draft_a", &changed, &removed, "cut_effect_1", "t3")
            .expect("import");
        let VcsWriteOutcome::Written { manifest_hash, .. } = first else {
            panic!("expected the import to land");
        };
        assert_eq!(
            vcs.read("draft_a", "out.md").expect("read").as_deref(),
            Some("produced")
        );
        assert_eq!(
            vcs.read("draft_a", "a.md").expect("read").as_deref(),
            Some("A modified"),
            "the whole diff landed in one cut"
        );
        // The idempotent retry: same effect-keyed cut id, no double-apply.
        let retry = vcs
            .import_diff("draft_a", &changed, &removed, "cut_effect_1", "t4")
            .expect("retry");
        assert_eq!(
            retry,
            VcsWriteOutcome::Written {
                cut_id: "cut_effect_1".to_owned(),
                manifest_hash,
            }
        );
        // Removals fold in the same atomic step.
        let mut second_changed = BTreeMap::new();
        second_changed.insert("b.md".to_owned(), vcs.content.put("B new").expect("put"));
        let outcome = vcs
            .import_diff(
                "draft_a",
                &second_changed,
                &["out.md".to_owned()],
                "cut_effect_2",
                "t5",
            )
            .expect("second import");
        assert!(matches!(outcome, VcsWriteOutcome::Written { .. }));
        assert_eq!(vcs.read("draft_a", "out.md").expect("read"), None);
        assert_eq!(
            vcs.read("draft_a", "b.md").expect("read").as_deref(),
            Some("B new")
        );
    }

    /// The workstream sync loop: members greedily admit into the shared
    /// line (rebasing each other's admitted work down first), stay
    /// active with zero divergence, and a colliding contribution
    /// isolates without moving the line or blocking siblings.
    #[test]
    fn stream_members_sync_greedily_and_conflicts_isolate() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        // The stream's shared line is an ordinary branch off mainline.
        vcs.create_branch("line_ws", None, MAINLINE_BRANCH_ID, "t1")
            .expect("line");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t1")
            .expect("member a");
        vcs.create_branch("draft_b", None, MAINLINE_BRANCH_ID, "t1")
            .expect("member b");
        vcs.write("draft_a", "a.md", Some("A work"), "cut_a1", "t2")
            .expect("write");
        assert_eq!(
            vcs.sync_to_line("draft_a", "line_ws", "sync_a1", "t3")
                .expect("sync"),
            SyncOutcome::Synced {
                sync_cut_id: "sync_a1".to_owned()
            }
        );
        assert_eq!(
            vcs.read("line_ws", "a.md").expect("read").as_deref(),
            Some("A work")
        );
        let member = vcs.get_branch("draft_a").expect("get").expect("row");
        assert_eq!(member.status, BranchStatus::Active, "never adopted");
        assert_eq!(
            member.branch_point_manifest_hash, member.head_manifest_hash,
            "fully in sync — zero divergence"
        );
        // Second member: the greedy sync folds a's admitted work down
        // first, then admits b's disjoint contribution.
        vcs.write("draft_b", "b.md", Some("B work"), "cut_b1", "t4")
            .expect("write");
        assert!(matches!(
            vcs.sync_to_line("draft_b", "line_ws", "sync_b1", "t5")
                .expect("sync"),
            SyncOutcome::Synced { .. }
        ));
        assert_eq!(
            vcs.read("line_ws", "a.md").expect("read").as_deref(),
            Some("A work")
        );
        assert_eq!(
            vcs.read("line_ws", "b.md").expect("read").as_deref(),
            Some("B work")
        );
        assert_eq!(
            vcs.read("draft_b", "a.md").expect("read").as_deref(),
            Some("A work"),
            "the member picked up its sibling's admitted work"
        );
        // A colliding contribution isolates: the line does not move and
        // the member stays live for repair.
        vcs.create_branch("draft_c", None, MAINLINE_BRANCH_ID, "t6")
            .expect("member c");
        vcs.write("draft_c", "a.md", Some("C collides"), "cut_c1", "t7")
            .expect("write");
        assert!(matches!(
            vcs.sync_to_line("draft_c", "line_ws", "sync_c1", "t8")
                .expect("sync"),
            SyncOutcome::Conflicts { .. }
        ));
        assert_eq!(
            vcs.read("line_ws", "a.md").expect("read").as_deref(),
            Some("A work"),
            "a failed contribution never moves the line"
        );
        assert_eq!(
            vcs.get_branch("draft_c").expect("get").expect("row").status,
            BranchStatus::Active
        );
        // Promotion is the same mechanism at the boundary: the line's
        // state lands on mainline and the line keeps going.
        assert!(matches!(
            vcs.sync_to_line("line_ws", MAINLINE_BRANCH_ID, "promote_1", "t9")
                .expect("promote"),
            SyncOutcome::Synced { .. }
        ));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "b.md")
                .expect("read")
                .as_deref(),
            Some("B work")
        );
        assert_eq!(
            vcs.get_branch("line_ws").expect("get").expect("row").status,
            BranchStatus::Active,
            "the stream line survives promotion"
        );
    }

    /// Dual identity end to end: a write mints a change id equal to its
    /// cut; a rebase REWRITES the cut but inherits the change (stable
    /// across rewrites); transport (sync) carries it to the line; and
    /// the same change with divergent content is DETECTED, never merged
    /// silently.
    #[test]
    fn change_identity_survives_rewrites_and_divergence_is_detected() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("line_ws", None, MAINLINE_BRANCH_ID, "t1")
            .expect("line");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t1")
            .expect("member");
        vcs.write("draft_a", "a.md", Some("A work"), "cut_a1", "t2")
            .expect("write");
        // Birth: change id == cut id.
        assert_eq!(
            vcs.branches.cut_change_id("cut_a1").expect("op"),
            Some("cut_a1".to_owned())
        );
        // Mainline advances disjointly; the rebase rewrites draft_a's cut
        // but the CHANGE survives the rewrite.
        vcs.write(MAINLINE_BRANCH_ID, "b.md", Some("B"), "cut_m1", "t3")
            .expect("write");
        assert!(matches!(
            vcs.reconcile_branch("draft_a", true, "cut_a1_rebased", "t4")
                .expect("reconcile"),
            ReconcileOutcome::Rebased { .. }
        ));
        assert_eq!(
            vcs.branches.cut_change_id("cut_a1_rebased").expect("op"),
            Some("cut_a1".to_owned()),
            "the rewrite inherits the intent identity"
        );
        // Transport: the sync-admitted cut on the line carries the change.
        assert!(matches!(
            vcs.sync_to_line("draft_a", "line_ws", "sync_a1", "t5")
                .expect("sync"),
            SyncOutcome::Synced { .. }
        ));
        assert_eq!(
            vcs.branches.cut_change_id("sync_a1").expect("op"),
            Some("cut_a1".to_owned()),
            "transport preserves identity — no ancestry-less duplicate"
        );
        // Divergence: force the transported-then-edited shape — the same
        // change id on both heads with different content — and the sync
        // DETECTS it instead of merging.
        let forged = vcs.content.put("forged divergent manifest").expect("put");
        vcs.branches
            .advance_head("draft_a", Some("sync_a1"), "cut_a2", &forged, "t6")
            .expect("advance");
        vcs.branches
            .record_cut(CutRecord {
                cut_id: "cut_a2",
                change_id: "cut_a1",
                branch_id: "draft_a",
                manifest_hash: &forged,
                parent_cut_id: Some("sync_a1"),
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t6",
            })
            .expect("record");
        let outcome = vcs
            .sync_to_line("draft_a", "line_ws", "sync_a2", "t7")
            .expect("sync");
        let SyncOutcome::DivergentChange {
            change_id,
            ours_manifest_hash,
            theirs_manifest_hash,
        } = outcome
        else {
            panic!("expected divergence detection, got {outcome:?}");
        };
        assert_eq!(change_id, "cut_a1");
        assert_ne!(ours_manifest_hash, theirs_manifest_hash);
    }

    /// Op-undo mirrors op-undo.maude: undo re-points to the recorded
    /// before-state as a NEW op (append-only; undo-of-undo returns);
    /// the moved-head bite refuses instead of losing the newer work;
    /// undoing a merge re-opens the adopted branch and re-points the
    /// parent; undoing a create closes the head.
    #[test]
    fn undo_op_repoints_appends_and_refuses_moved_heads() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t1")
            .expect("create");
        vcs.write("draft_a", "a.md", Some("v1"), "cut_a1", "t2")
            .expect("write");
        vcs.write("draft_a", "a.md", Some("v2"), "cut_a2", "t3")
            .expect("write");
        // Undo the second write: head returns to cut_a1, the log grew.
        assert_eq!(
            vcs.undo_op("op-cut_a2", "undo_1", "t4").expect("undo"),
            UndoOpOutcome::Undone {
                undo_op_id: "undo_1".to_owned()
            }
        );
        assert_eq!(
            vcs.read("draft_a", "a.md").expect("read").as_deref(),
            Some("v1")
        );
        // The moved-head bite: op-cut_a1's after-state is no longer
        // where the branch is (the undo moved it) — refused, honest.
        assert!(matches!(
            vcs.undo_op("op-cut_a2", "undo_dup", "t5").expect("undo"),
            UndoOpOutcome::HeadMoved { .. },
        ));
        // Undo-of-undo: the same verb on the compensator returns to v2.
        assert_eq!(
            vcs.undo_op("undo_1", "undo_2", "t6").expect("undo"),
            UndoOpOutcome::Undone {
                undo_op_id: "undo_2".to_owned()
            }
        );
        assert_eq!(
            vcs.read("draft_a", "a.md").expect("read").as_deref(),
            Some("v2")
        );
        // Undo the merge: mainline re-points AND the branch re-opens.
        vcs.merge("draft_a", "cut_merge_1", "t7").expect("merge");
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md")
                .expect("read")
                .as_deref(),
            Some("v2")
        );
        assert_eq!(
            vcs.undo_op("op-cut_merge_1", "undo_3", "t8").expect("undo"),
            UndoOpOutcome::Undone {
                undo_op_id: "undo_3".to_owned()
            }
        );
        assert_eq!(vcs.read(MAINLINE_BRANCH_ID, "a.md").expect("read"), None);
        assert_eq!(
            vcs.get_branch("draft_a").expect("get").expect("row").status,
            BranchStatus::Active,
            "undoing the adopt re-opens the branch"
        );
        // Undo a create: the compensator closes the head.
        vcs.create_branch("draft_b", None, MAINLINE_BRANCH_ID, "t9")
            .expect("create");
        assert_eq!(
            vcs.undo_op("op-create-draft_b", "undo_4", "t10")
                .expect("undo"),
            UndoOpOutcome::Undone {
                undo_op_id: "undo_4".to_owned()
            }
        );
        assert_eq!(
            vcs.get_branch("draft_b").expect("get").expect("row").status,
            BranchStatus::Discarded
        );
        // The log is append-only: every op is still there, plus the
        // compensators.
        let kinds: Vec<String> = vcs
            .list_ops(20)
            .expect("ops")
            .into_iter()
            .map(|op| op.kind)
            .collect();
        assert_eq!(kinds.iter().filter(|kind| *kind == "undo").count(), 4);
        assert!(kinds.iter().any(|kind| kind == "merge"));
    }

    /// The structured conflict surface mirrors resolution-memory.maude:
    /// a conflicted reconcile records open conflict objects (the tagged
    /// state — work proceeds atop it, adoption refuses); per-item
    /// resolution is an ordinary provenance-carrying write that stores
    /// content-addressed memory; the daemon auto-applies the memory to a
    /// descendant's IDENTICAL pair (and never to a different base).
    #[test]
    fn conflict_objects_gate_adoption_and_memory_propagates() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("A0"), "cut_m1", "t1")
            .expect("write");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t2")
            .expect("create");
        vcs.write("draft_a", "a.md", Some("ours A"), "cut_d1", "t3")
            .expect("write");
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("theirs A"), "cut_m2", "t4")
            .expect("write");
        // The conflicted reconcile records the open conflict object with
        // both sides' provenance.
        assert!(matches!(
            vcs.reconcile_branch("draft_a", true, "cut_r1", "t5")
                .expect("reconcile"),
            ReconcileOutcome::Conflicts { .. }
        ));
        let open = vcs.open_conflicts("draft_a").expect("open");
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].path, "a.md");
        assert_eq!(open[0].ours_label, "draft_a");
        assert_eq!(open[0].theirs_label, MAINLINE_BRANCH_ID);
        // Work proceeds atop the tagged state...
        assert!(matches!(
            vcs.write("draft_a", "other.md", Some("more work"), "cut_d2", "t6")
                .expect("write"),
            VcsWriteOutcome::Written { .. }
        ));
        // ...but adoption refuses while a conflict is open.
        assert!(matches!(
            vcs.merge("draft_a", "cut_merge_1", "t7").expect("merge"),
            VcsMergeOutcome::Conflicted { .. }
        ));
        // Per-item authored resolution: closes the row, stores memory,
        // and the branch then merges clean.
        let outcome = vcs
            .resolve_conflict(
                "draft_a",
                "a.md",
                ResolutionChoice::Body("ours A + theirs A"),
                "cut_res1",
                "t8",
            )
            .expect("resolve");
        let ResolveOutcome::Resolved {
            resolution: Some(resolution),
            ..
        } = outcome
        else {
            panic!("expected a stored resolution, got {outcome:?}");
        };
        assert!(vcs.open_conflicts("draft_a").expect("open").is_empty());
        assert!(matches!(
            vcs.merge("draft_a", "cut_merge_2", "t9").expect("merge"),
            VcsMergeOutcome::Adopted { .. }
        ));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "a.md")
                .expect("read")
                .as_deref(),
            Some("ours A + theirs A")
        );
        // Propagation: a sibling with the IDENTICAL triple (same base
        // A0, same ours, same theirs) auto-resolves from memory during
        // its reconcile — no ask, no authored input.
        // Rebuild the shape on a fresh pair of branches: mainline back
        // to A0, sibling writes "ours A", mainline moves to "theirs A".
        vcs.write(MAINLINE_BRANCH_ID, "a.md", Some("A0"), "cut_m3", "t10")
            .expect("write");
        vcs.create_branch("draft_b", None, MAINLINE_BRANCH_ID, "t11")
            .expect("create");
        vcs.write("draft_b", "a.md", Some("ours A"), "cut_b1", "t12")
            .expect("write");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.md",
            Some("theirs A"),
            "cut_m4",
            "t13",
        )
        .expect("write");
        assert!(matches!(
            vcs.reconcile_branch("draft_b", true, "cut_r2", "t14")
                .expect("reconcile"),
            ReconcileOutcome::Rebased { .. },
        ));
        assert_eq!(
            vcs.read("draft_b", "a.md").expect("read").as_deref(),
            Some("ours A + theirs A"),
            "the stored resolution auto-propagated to the identical pair"
        );
        assert_eq!(
            vcs.branches.cut_change_id("cut_res1").expect("cut"),
            Some("cut_res1".to_owned()),
            "the resolution was an ordinary provenance-carrying cut"
        );
        let _ = resolution;
        // The bite: a DIFFERENT base with the same sides does NOT
        // auto-apply — content addressing, not similarity.
        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.md",
            Some("B0 different base"),
            "cut_m5",
            "t15",
        )
        .expect("write");
        vcs.create_branch("draft_c", None, MAINLINE_BRANCH_ID, "t16")
            .expect("create");
        vcs.write("draft_c", "a.md", Some("ours A"), "cut_c1", "t17")
            .expect("write");
        vcs.write(
            MAINLINE_BRANCH_ID,
            "a.md",
            Some("theirs A"),
            "cut_m6",
            "t18",
        )
        .expect("write");
        assert!(matches!(
            vcs.reconcile_branch("draft_c", true, "cut_r3", "t19")
                .expect("reconcile"),
            ReconcileOutcome::Conflicts { .. },
        ));
    }

    /// The selective verbs over the recorded universe: undo <selection>
    /// refuses a stranding exclusion and proposes a counterfactual cut
    /// otherwise (selective-undo.maude); dependents-of repairs the
    /// selection; transport carries identity and refuses overlap;
    /// adopt --only moves a fraction while the remainder stays live.
    #[test]
    fn selective_verbs_undo_transport_and_partial_adopt() {
        use crate::selection::parse;
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t1")
            .expect("create");
        vcs.write("draft_a", "p1.md", Some("e1 out"), "e1", "t2")
            .expect("write");
        vcs.write("draft_a", "p2.md", Some("e2 out"), "e2", "t3")
            .expect("write");
        vcs.write("draft_a", "p2.md", Some("e3 out"), "e3", "t4")
            .expect("write");
        // The universe records three units with lineage.
        let units = vcs.change_units("draft_a", 100).expect("units");
        assert_eq!(units.len(), 3);
        assert_eq!(units[0].path, "p1.md");
        assert_eq!(units[2].before, units[1].after);
        // Undoing e2 alone strands e3 (the model's bite): refused, and
        // the dry-run plan names the stranded unit.
        let plan = vcs
            .plan_undo_selection("draft_a", &parse("cut(e2)").expect("parse"))
            .expect("plan")
            .expect("branch");
        assert_eq!(plan.stranded.len(), 1);
        assert_eq!(plan.stranded[0].cut_id, "e3");
        assert!(matches!(
            vcs.apply_undo_selection("draft_a", &parse("cut(e2)").expect("parse"), "u1", "t5")
                .expect("undo"),
            UndoSelectionOutcome::WouldStrand { .. }
        ));
        assert_eq!(
            vcs.read("draft_a", "p2.md").expect("read").as_deref(),
            Some("e3 out"),
            "a refused undo moves nothing"
        );
        // dependents-of(e2) closes the selection; the undo applies and
        // p2 returns to its pre-e2 state (absent).
        let outcome = vcs
            .apply_undo_selection(
                "draft_a",
                &parse("dependents-of(cut(e2))").expect("parse"),
                "u2",
                "t6",
            )
            .expect("undo");
        assert!(matches!(outcome, UndoSelectionOutcome::Proposed { .. }));
        assert_eq!(vcs.read("draft_a", "p2.md").expect("read"), None);
        assert_eq!(
            vcs.read("draft_a", "p1.md").expect("read").as_deref(),
            Some("e1 out"),
            "unselected work is untouched"
        );
        // Transport e1 onto mainline: identity-preserving (one change).
        let outcome = vcs
            .transport_selection(
                "draft_a",
                &parse("cut(e1)").expect("parse"),
                MAINLINE_BRANCH_ID,
                "tp1",
                "t7",
            )
            .expect("transport");
        let TransportOutcome::Transported { change_id, .. } = outcome else {
            panic!("expected a transport, got {outcome:?}");
        };
        assert_eq!(change_id, "e1", "cherry-pick preserves the change id");
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "p1.md")
                .expect("read")
                .as_deref(),
            Some("e1 out")
        );
        // A conflicting transport refuses honestly: mainline's p1 moved.
        vcs.write(MAINLINE_BRANCH_ID, "p1.md", Some("main p1"), "m1", "t8")
            .expect("write");
        vcs.write("draft_a", "p1.md", Some("e4 out"), "e4", "t9")
            .expect("write");
        assert!(matches!(
            vcs.transport_selection(
                "draft_a",
                &parse("cut(e4)").expect("parse"),
                MAINLINE_BRANCH_ID,
                "tp2",
                "t10",
            )
            .expect("transport"),
            TransportOutcome::Conflicted { .. }
        ));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "p1.md")
                .expect("read")
                .as_deref(),
            Some("main p1"),
            "a conflicted transport moves nothing"
        );
        // adopt --only: a fraction lands on the parent, the branch stays
        // active with its remainder.
        vcs.write("draft_a", "keep.md", Some("stays"), "e5", "t11")
            .expect("write");
        vcs.write("draft_a", "give.md", Some("goes"), "e6", "t12")
            .expect("write");
        assert!(matches!(
            vcs.adopt_only(
                "draft_a",
                &parse("path(give.md)").expect("parse"),
                "ao1",
                "t13"
            )
            .expect("adopt-only"),
            TransportOutcome::Transported { .. }
        ));
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "give.md")
                .expect("read")
                .as_deref(),
            Some("goes")
        );
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "keep.md").expect("read"),
            None,
            "the remainder did not adopt"
        );
        assert_eq!(
            vcs.get_branch("draft_a").expect("get").expect("row").status,
            BranchStatus::Active,
            "partial adoption never closes the branch"
        );
    }

    /// A multi-write cherry-pick onto a target that never held the intermediate
    /// state must transport cleanly, not phantom-conflict (ultracode #10): the
    /// precondition is the OLDEST selected write's `before`, not the newest's.
    #[test]
    fn transport_of_a_multi_write_path_uses_the_oldest_precondition() {
        use crate::selection::parse;
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t1")
            .expect("create");
        // Create p2 (before=None), then edit it (before="v1"). mainline has no p2.
        vcs.write("draft_a", "p2.md", Some("v1"), "e2", "t2")
            .expect("create");
        vcs.write("draft_a", "p2.md", Some("v2"), "e3", "t3")
            .expect("edit");
        // Transport the whole path — both writes are selected. The oldest
        // (e2) before=None matches mainline's absent p2, so it transports the
        // net result (v2) rather than conflicting on the intermediate "v1".
        let outcome = vcs
            .transport_selection(
                "draft_a",
                &parse("path(p2.md)").expect("parse"),
                MAINLINE_BRANCH_ID,
                "tp1",
                "t4",
            )
            .expect("transport");
        assert!(
            matches!(outcome, TransportOutcome::Transported { .. }),
            "a valid multi-write cherry-pick must not phantom-conflict: {outcome:?}"
        );
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "p2.md")
                .expect("read")
                .as_deref(),
            Some("v2"),
            "the net result (newest after) lands on the target"
        );
    }

    #[test]
    fn discard_closes_a_head_without_deleting_history() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("draft_a", None, MAINLINE_BRANCH_ID, "t1")
            .expect("create");
        vcs.write("draft_a", "x.md", Some("scratch"), "cut_d1", "t2")
            .expect("write");
        assert!(matches!(
            vcs.discard_branch("draft_a", "t3").expect("discard"),
            StatusOutcome::Done(_)
        ));
        // The row (and its cut pointers) remain readable history.
        let row = vcs.get_branch("draft_a").expect("get").expect("row");
        assert_eq!(row.status, BranchStatus::Discarded);
        assert_eq!(
            vcs.read("draft_a", "x.md").expect("read"),
            Some("scratch".to_owned()),
            "discard closes the head; the content remains addressable"
        );
    }

    /// The branch half of a chat fork (chat-fork.maude): the fork gets its
    /// OWN line forked at the source line's head, the source binding never
    /// moves, and the two lines diverge independently afterwards.
    #[test]
    fn instance_fork_binding_mints_own_line_and_refuses_rebinds() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("chat_main", None, MAINLINE_BRANCH_ID, "t1")
            .expect("create");
        vcs.write("chat_main", "note.md", Some("turn one"), "cut_c1", "t2")
            .expect("write");
        assert!(matches!(
            vcs.bind_instance("ins_source", "chat_main", "t3")
                .expect("bind"),
            crate::branches::BindOutcome::Bound
        ));

        // An unbound source forks thread-only.
        assert_eq!(
            vcs.fork_binding_for_instance("ins_stranger", "ins_target0", "fork_x", None, "t4")
                .expect("fork"),
            InstanceForkBinding::SourceUnbound
        );

        // The real fork: fresh branch at the source head, bound at birth.
        let outcome = vcs
            .fork_binding_for_instance("ins_source", "ins_target", "chat_fork", None, "t5")
            .expect("fork");
        let InstanceForkBinding::Forked {
            source_branch_id,
            fork_branch,
        } = outcome
        else {
            panic!("expected Forked, got {outcome:?}");
        };
        assert_eq!(source_branch_id, "chat_main");
        assert_eq!(fork_branch.parent_branch_id.as_deref(), Some("chat_main"));
        let source_row = vcs.get_branch("chat_main").expect("get").expect("row");
        assert_eq!(
            fork_branch.head_manifest_hash, source_row.head_manifest_hash,
            "the fork starts exactly at the source line's head"
        );
        assert_eq!(
            vcs.instance_branch("ins_source").expect("lookup"),
            Some("chat_main".to_owned()),
            "the source binding never moves"
        );
        assert_eq!(
            vcs.instance_branch("ins_target").expect("lookup"),
            Some("chat_fork".to_owned())
        );

        // Divergence is line-local both ways.
        vcs.write("chat_fork", "note.md", Some("fork turn"), "cut_f1", "t6")
            .expect("write");
        assert_eq!(
            vcs.read("chat_main", "note.md").expect("read"),
            Some("turn one".to_owned())
        );
        assert_eq!(
            vcs.read("chat_fork", "note.md").expect("read"),
            Some("fork turn".to_owned())
        );

        // Replay of the same fork is tolerated; a squatted id is refused.
        assert!(matches!(
            vcs.fork_binding_for_instance("ins_source", "ins_target", "chat_fork", None, "t7")
                .expect("replay"),
            InstanceForkBinding::Forked { .. }
        ));
        assert_eq!(
            vcs.fork_binding_for_instance("ins_source", "ins_target2", "chat_main", None, "t8")
                .expect("squat"),
            InstanceForkBinding::ForkBranchIdTaken {
                branch_id: "chat_main".to_owned()
            }
        );
        // A target already bound elsewhere is a write-once refusal.
        assert_eq!(
            vcs.fork_binding_for_instance("ins_source", "ins_target", "chat_fork2", None, "t9")
                .expect("rebind"),
            InstanceForkBinding::TargetAlreadyBound {
                branch_id: "chat_fork".to_owned()
            }
        );
        // A closed source line refuses honestly.
        vcs.discard_branch("chat_main", "t10").expect("discard");
        assert_eq!(
            vcs.fork_binding_for_instance("ins_source", "ins_target3", "chat_fork3", None, "t11")
                .expect("closed"),
            InstanceForkBinding::SourceBranchUnavailable {
                branch_id: "chat_main".to_owned()
            }
        );
    }

    #[test]
    fn exact_instance_fork_uses_historical_cut_not_source_tip() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("chat", None, MAINLINE_BRANCH_ID, "t1")
            .expect("chat");
        vcs.bind_instance("source", "chat", "t1")
            .expect("bind source");
        vcs.write("chat", "answer.md", Some("historical"), "chat-1", "t2")
            .expect("historical write");
        vcs.write("chat", "answer.md", Some("later tip"), "chat-2", "t3")
            .expect("later write");

        let outcome = vcs
            .fork_binding_for_instance_at_cut("source", "chat-1", "child", "chat-child", None, "t4")
            .expect("exact fork");
        let ExactInstanceForkBinding::Forked {
            fork_branch,
            evidence_handle,
            ..
        } = outcome
        else {
            panic!("expected exact fork");
        };
        assert_eq!(fork_branch.branch_point_cut_id.as_deref(), Some("chat-1"));
        assert_eq!(
            vcs.read("chat-child", "answer.md").expect("child read"),
            Some("historical".to_owned())
        );
        assert!(evidence_handle.starts_with("sha256:"));
    }

    #[test]
    fn reserved_boundary_promotes_with_one_exact_main_cas() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(MAINLINE_BRANCH_ID, "base.md", Some("base"), "main-1", "t1")
            .expect("seed main");
        vcs.create_branch("line-ws", None, MAINLINE_BRANCH_ID, "t2")
            .expect("line");
        vcs.write("line-ws", "work.md", Some("work"), "line-1", "t3")
            .expect("stream work");
        assert_eq!(
            vcs.reserve_branch_head("line-ws", "reservation-ws", "t4")
                .expect("reserve line"),
            crate::branches::HeadReservationOutcome::Reserved
        );

        let outcome = vcs
            .promote_line_exact(
                "line-ws",
                "reservation-ws",
                Some("line-1"),
                Some("main-1"),
                "main-2",
                "t4",
            )
            .expect("promote");
        let BoundaryPromotionOutcome::Promoted {
            main_cut_id,
            ref_position,
            ref_receipt_handle,
            ..
        } = outcome
        else {
            panic!("expected promotion");
        };
        assert_eq!(main_cut_id, "main-2");
        assert!(ref_position >= 2);
        assert!(ref_receipt_handle.starts_with("sha256:"));
        assert_eq!(
            vcs.boundary_ref_evidence("line-ws", Some("main-1"), "main-2")
                .expect("recover landed ref"),
            Some((ref_position, ref_receipt_handle.clone())),
            "a crash after the Main CAS recovers the same body-free receipt"
        );
        assert_eq!(
            vcs.read(MAINLINE_BRANCH_ID, "work.md").expect("main read"),
            Some("work".to_owned())
        );
        assert_eq!(
            vcs.get_branch("line-ws")
                .expect("line read")
                .expect("line")
                .head_cut_id
                .as_deref(),
            Some("line-1"),
            "promotion never advances the frozen stream line"
        );

        let stale = vcs
            .promote_line_exact(
                "line-ws",
                "reservation-ws",
                Some("line-1"),
                Some("main-1"),
                "main-3",
                "t5",
            )
            .expect("stale attempt");
        assert!(matches!(
            stale,
            BoundaryPromotionOutcome::ExpectedCutsMoved {
                current_main_cut: Some(ref cut),
                ..
            } if cut == "main-2"
        ));
        assert!(
            vcs.get_cut("main-3").expect("cut lookup").is_none(),
            "the stale cut is rejected before proposal persistence"
        );
    }

    #[test]
    fn exact_promotion_requires_its_durable_reservation() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("line-ws", None, MAINLINE_BRANCH_ID, "t1")
            .expect("line");

        let error = vcs
            .promote_line_exact("line-ws", "missing-reservation", None, None, "main-1", "t2")
            .expect_err("promotion without the matching reservation must refuse");
        assert!(format!("{error:?}").contains("not frozen by reservation"));
    }

    #[test]
    fn recorded_promotion_cut_verification_refuses_a_missing_row() {
        let error = NativeWorkspaceVcs::verify_recorded_promotion_cut(
            None,
            "main-2",
            Some("main-1"),
            "manifest",
            "promote:line-ws",
        )
        .expect_err("a missing immutable proposal cannot be published");
        assert!(format!("{error:?}").contains("proposed promotion cut is unavailable"));
    }

    #[test]
    fn boundary_conflict_moves_no_pointer() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(MAINLINE_BRANCH_ID, "same.md", Some("base"), "main-1", "t1")
            .expect("seed main");
        vcs.create_branch("line-ws", None, MAINLINE_BRANCH_ID, "t2")
            .expect("line");
        vcs.write("line-ws", "same.md", Some("stream"), "line-1", "t3")
            .expect("stream work");
        vcs.write(MAINLINE_BRANCH_ID, "same.md", Some("main"), "main-2", "t4")
            .expect("main work");
        vcs.reserve_branch_head("line-ws", "reservation-ws", "t5")
            .expect("reserve line");

        let outcome = vcs
            .promote_line_exact(
                "line-ws",
                "reservation-ws",
                Some("line-1"),
                Some("main-2"),
                "main-3",
                "t5",
            )
            .expect("probe");
        assert!(matches!(
            outcome,
            BoundaryPromotionOutcome::Conflicted { .. }
        ));
        assert_eq!(
            vcs.get_branch(MAINLINE_BRANCH_ID)
                .expect("main read")
                .expect("main")
                .head_cut_id
                .as_deref(),
            Some("main-2")
        );
        assert_eq!(
            vcs.get_branch("line-ws")
                .expect("line read")
                .expect("line")
                .head_cut_id
                .as_deref(),
            Some("line-1")
        );
    }

    #[test]
    fn reserved_stream_line_refuses_every_direct_head_advance() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("line-ws", None, MAINLINE_BRANCH_ID, "t1")
            .expect("line");
        vcs.write("line-ws", "work.md", Some("before"), "line-1", "t2")
            .expect("seed line");
        vcs.reserve_branch_head("line-ws", "reservation-ws", "t3")
            .expect("reserve line");

        let error = vcs
            .write("line-ws", "work.md", Some("after"), "line-2", "t4")
            .expect_err("a direct write cannot bypass the boundary reservation");
        assert!(format!("{error:?}").contains("reserved by `reservation-ws`"));
        assert_eq!(
            vcs.get_branch("line-ws")
                .expect("line read")
                .expect("line")
                .head_cut_id
                .as_deref(),
            Some("line-1")
        );
        assert_eq!(
            vcs.read("line-ws", "work.md").expect("body read"),
            Some("before".to_owned())
        );
    }

    #[test]
    fn promotion_cut_record_failure_cannot_publish_main() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.write(MAINLINE_BRANCH_ID, "base.md", Some("base"), "main-1", "t1")
            .expect("seed main");
        vcs.create_branch("line-ws", None, MAINLINE_BRANCH_ID, "t2")
            .expect("line");
        vcs.write("line-ws", "work.md", Some("work"), "line-1", "t3")
            .expect("stream work");
        vcs.create_branch("unrelated", None, MAINLINE_BRANCH_ID, "t3")
            .expect("unrelated branch");
        vcs.write("unrelated", "other.md", Some("other"), "main-2", "t3")
            .expect("squat proposed cut identity");
        vcs.reserve_branch_head("line-ws", "reservation-ws", "t4")
            .expect("reserve line");

        let error = vcs
            .promote_line_exact(
                "line-ws",
                "reservation-ws",
                Some("line-1"),
                Some("main-1"),
                "main-2",
                "t4",
            )
            .expect_err("conflicting immutable cut identity must fail before Main CAS");
        assert!(format!("{error:?}").contains("different immutable content"));
        assert_eq!(
            vcs.get_branch(MAINLINE_BRANCH_ID)
                .expect("main read")
                .expect("main")
                .head_cut_id
                .as_deref(),
            Some("main-1")
        );
    }

    #[test]
    fn concurrent_exact_promotions_have_one_main_cas_winner() {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-boundary-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let branches = dir.join("branches.sqlite");
        let content = dir.join("content.sqlite");
        let mut setup = NativeWorkspaceVcs::open(&branches, &content).expect("setup");
        setup.init("t0").expect("init");
        setup
            .write(MAINLINE_BRANCH_ID, "base.md", Some("base"), "main-1", "t1")
            .expect("main");
        setup
            .create_branch("line-ws", None, MAINLINE_BRANCH_ID, "t2")
            .expect("line");
        setup
            .write("line-ws", "work.md", Some("work"), "line-1", "t3")
            .expect("work");
        setup
            .reserve_branch_head("line-ws", "reservation-race", "t4")
            .expect("reserve line");
        drop(setup);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut joins = Vec::new();
        for proposed in ["main-race-a", "main-race-b"] {
            let branches = branches.clone();
            let content = content.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            joins.push(std::thread::spawn(move || {
                let mut vcs = NativeWorkspaceVcs::open(branches, content).expect("racing vcs");
                barrier.wait();
                vcs.promote_line_exact(
                    "line-ws",
                    "reservation-race",
                    Some("line-1"),
                    Some("main-1"),
                    proposed,
                    "race",
                )
                .expect("promotion outcome")
            }));
        }
        barrier.wait();
        let outcomes = joins
            .into_iter()
            .map(|join| join.join().expect("thread"))
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, BoundaryPromotionOutcome::Promoted { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(outcome, BoundaryPromotionOutcome::ExpectedCutsMoved { .. })
                })
                .count(),
            1
        );
        let final_vcs = NativeWorkspaceVcs::open(&branches, &content).expect("final vcs");
        let main = final_vcs
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("main read")
            .expect("main");
        assert!(matches!(
            main.head_cut_id.as_deref(),
            Some("main-race-a" | "main-race-b")
        ));
        let _ = std::fs::remove_dir_all(dir);
    }
}
