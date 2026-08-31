//! The mapped workspace-operation surface for external hosts — the
//! git-replacement API (untie-substrate readiness tracker Phase 2;
//! untie-substrate-replacement-research-note §3).
//!
//! Un-tie consumes 13 git capabilities through `crates/workspace`; this
//! module is their whip-side mapping as ONE serializable protocol:
//! `WorkspaceOp` in, `WorkspaceOpOutcome` out, JSON on both sides, so an
//! external host (gaugedesk, a sidecar, a test harness) drives the
//! versioned workspace without linking against the verb methods
//! individually. The mapping, per the tracker: repo init → `Init`;
//! worktrees/refs → `Branch`; fork-with-shared-ancestry →
//! `ForkWithLineage`; commit-per-turn-finalize → `CutAtQuiescence`;
//! merge-probe (`merge-tree`) → `MergeProbe`; merge/abort → `Merge`
//! (conflicts move nothing, so "abort" is not needing to exist); revert
//! → `Restore`; workstream promotion → `Promote`; status/hash plumbing →
//! `Status`; sync-from-main → `Reconcile` + `ReconcileList`; remove →
//! `Remove` (a discard — the record survives).
//!
//! Every mutating op takes caller-supplied ids and timestamps (the clock
//! stays at the worker boundary; ids make retries idempotent), and no op
//! here is destructive: outcomes are proposals over the immutable record.

use serde::{Deserialize, Serialize};

use crate::branches::{BranchRow, CreateBranchOutcome, StatusOutcome};
use crate::content::ContentBlobs;
use crate::merge::PathConflict;
use crate::vcs::{
    BranchStatusReport, MergeProbeOutcome, QuiescentCut, ReconcileEntry, ReconcileOutcome,
    RestoreOutcome, SyncOutcome, VcsMergeOutcome, WorkspaceVcs,
};
use crate::{branches::Branches, StoreResult};

/// One workspace operation, host-encodable as tagged JSON.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum WorkspaceOp {
    /// Bootstrap: mainline exists afterwards.
    Init,
    /// A new branch off a parent's current head.
    Branch {
        branch_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_branch_id: Option<String>,
    },
    /// A new branch pinned to a recorded cut of `from_branch` — shared
    /// ancestry, recorded lineage.
    ForkWithLineage {
        branch_id: String,
        from_branch: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_cut_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// Name the branch's current state as a durable cut.
    CutAtQuiescence { branch_id: String, cut_id: String },
    /// What would `Merge` do? Moves nothing.
    MergeProbe { branch_id: String },
    /// Merge the branch into its parent (rebase-down + certified
    /// merge-up). Conflicts move nothing — there is no abort because
    /// there is nothing to abort.
    Merge {
        branch_id: String,
        merge_cut_id: String,
    },
    /// Re-point the branch head to a recorded cut's state as a NEW cut.
    Restore {
        branch_id: String,
        to_cut_id: String,
        new_cut_id: String,
    },
    /// Workstream promotion / greedy admit: land the branch's divergence
    /// on `onto` and re-point the branch fully in sync (never adopted).
    Promote {
        branch_id: String,
        onto: String,
        sync_cut_id: String,
    },
    /// Status + hash plumbing for one branch.
    Status { branch_id: String },
    /// Fold the parent's (or explicit target's) delta down into the
    /// branch — sync-from-main.
    Reconcile {
        branch_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_branch_id: Option<String>,
        quiescent: bool,
        rebase_cut_id: String,
    },
    /// Every branch with pending flow in either direction.
    ReconcileList,
    /// Close the branch head. The record remains readable history.
    Remove { branch_id: String },
}

/// The outcome envelope. Refusals are data, not errors: a host branches
/// on them the way the CLI does.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum WorkspaceOpOutcome {
    Initialized {
        mainline: BranchRow,
    },
    Created {
        branch: BranchRow,
    },
    /// Idempotent retry of a creation.
    Existing {
        branch: BranchRow,
    },
    NameTaken {
        holder_branch_id: String,
    },
    Cut {
        cut: QuiescentCut,
    },
    Probe {
        up_to_date: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        merged_manifest_hash: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        changed_paths: Vec<String>,
    },
    Merged {
        merge_cut_id: String,
        into_branch_id: String,
    },
    Conflicted {
        conflicts: Vec<PathConflict>,
    },
    Restored {
        cut_id: String,
        manifest_hash: String,
    },
    /// Restore found the head already carrying that state.
    AlreadyThere,
    Promoted {
        sync_cut_id: String,
    },
    /// Promote found nothing to admit.
    UpToDate,
    /// Dual identity's divergence detection: both heads carry the same
    /// change with different content — surfaced, never silently merged.
    DivergentChange {
        change_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ours_manifest_hash: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        theirs_manifest_hash: Option<String>,
    },
    Status {
        report: BranchStatusReport,
    },
    Rebased {
        rebase_cut_id: String,
    },
    /// Reconcile deferred: the branch is mid-run and the delta
    /// intersects.
    DeferredMidRun,
    ReconcileList {
        entries: Vec<ReconcileEntry>,
    },
    Removed {
        branch: BranchRow,
    },
    /// The named branch/cut/parent does not exist (or is terminal) in
    /// the way the op requires.
    Refused {
        reason: String,
    },
}

/// Apply one operation. Errors are store-level failures (I/O,
/// serialization, optimistic-guard retry exhaustion); every domain
/// refusal comes back as a `WorkspaceOpOutcome`.
pub fn apply<B: Branches, C: ContentBlobs>(
    vcs: &mut WorkspaceVcs<B, C>,
    op: &WorkspaceOp,
    at: &str,
) -> StoreResult<WorkspaceOpOutcome> {
    Ok(match op {
        WorkspaceOp::Init => WorkspaceOpOutcome::Initialized {
            mainline: vcs.init(at)?,
        },
        WorkspaceOp::Branch {
            branch_id,
            name,
            parent_branch_id,
        } => {
            let parent = parent_branch_id
                .as_deref()
                .unwrap_or_else(|| WorkspaceVcs::<B, C>::mainline());
            create_outcome(vcs.create_branch(branch_id, name.as_deref(), parent, at)?)
        }
        WorkspaceOp::ForkWithLineage {
            branch_id,
            from_branch,
            at_cut_id,
            name,
        } => create_outcome(vcs.fork_with_lineage(
            branch_id,
            name.as_deref(),
            from_branch,
            at_cut_id.as_deref(),
            at,
        )?),
        WorkspaceOp::CutAtQuiescence { branch_id, cut_id } => {
            match vcs.cut_at_quiescence(branch_id, cut_id, at)? {
                Some(cut) => WorkspaceOpOutcome::Cut { cut },
                None => refused(format!("no active branch `{branch_id}`")),
            }
        }
        WorkspaceOp::MergeProbe { branch_id } => match vcs.merge_probe(branch_id)? {
            MergeProbeOutcome::UpToDate => WorkspaceOpOutcome::Probe {
                up_to_date: true,
                merged_manifest_hash: None,
                changed_paths: Vec::new(),
            },
            MergeProbeOutcome::Clean {
                merged_manifest_hash,
                changed_paths,
            } => WorkspaceOpOutcome::Probe {
                up_to_date: false,
                merged_manifest_hash: Some(merged_manifest_hash),
                changed_paths,
            },
            MergeProbeOutcome::Conflicted { conflicts } => {
                WorkspaceOpOutcome::Conflicted { conflicts }
            }
            MergeProbeOutcome::BranchMissing => refused(format!("no branch `{branch_id}`")),
            MergeProbeOutcome::BranchNotActive => {
                refused(format!("branch `{branch_id}` is not active"))
            }
            MergeProbeOutcome::NoParent => {
                refused(format!("branch `{branch_id}` has no parent line"))
            }
        },
        WorkspaceOp::Merge {
            branch_id,
            merge_cut_id,
        } => match vcs.merge(branch_id, merge_cut_id, at)? {
            VcsMergeOutcome::Adopted {
                merge_cut_id,
                into_branch_id,
            }
            | VcsMergeOutcome::Landed {
                merge_cut_id,
                into_branch_id,
            } => WorkspaceOpOutcome::Merged {
                merge_cut_id,
                into_branch_id,
            },
            VcsMergeOutcome::Conflicted { conflicts } => {
                WorkspaceOpOutcome::Conflicted { conflicts }
            }
            VcsMergeOutcome::BranchMissing => refused(format!("no branch `{branch_id}`")),
            VcsMergeOutcome::BranchNotActive => {
                refused(format!("branch `{branch_id}` is not active"))
            }
            VcsMergeOutcome::NoParent => refused(format!("branch `{branch_id}` has no parent")),
        },
        WorkspaceOp::Restore {
            branch_id,
            to_cut_id,
            new_cut_id,
        } => match vcs.restore(branch_id, to_cut_id, new_cut_id, at)? {
            RestoreOutcome::Restored {
                cut_id,
                manifest_hash,
            } => WorkspaceOpOutcome::Restored {
                cut_id,
                manifest_hash,
            },
            RestoreOutcome::AlreadyThere => WorkspaceOpOutcome::AlreadyThere,
            RestoreOutcome::CutMissing => refused(format!("no recorded cut `{to_cut_id}`")),
            RestoreOutcome::BranchMissing => refused(format!("no branch `{branch_id}`")),
            RestoreOutcome::BranchNotActive => {
                refused(format!("branch `{branch_id}` is not active"))
            }
        },
        WorkspaceOp::Promote {
            branch_id,
            onto,
            sync_cut_id,
        } => match vcs.sync_to_line(branch_id, onto, sync_cut_id, at)? {
            SyncOutcome::Synced { sync_cut_id } => WorkspaceOpOutcome::Promoted { sync_cut_id },
            SyncOutcome::UpToDate => WorkspaceOpOutcome::UpToDate,
            SyncOutcome::Conflicts { conflicts } => WorkspaceOpOutcome::Conflicted { conflicts },
            SyncOutcome::DivergentChange {
                change_id,
                ours_manifest_hash,
                theirs_manifest_hash,
            } => WorkspaceOpOutcome::DivergentChange {
                change_id,
                ours_manifest_hash,
                theirs_manifest_hash,
            },
            SyncOutcome::BranchMissing => refused(format!("no branch `{branch_id}`")),
            SyncOutcome::BranchNotActive => refused(format!("branch `{branch_id}` is not active")),
            SyncOutcome::LineMissing => refused(format!("no line `{onto}`")),
            SyncOutcome::LineNotActive => refused(format!("line `{onto}` is not active")),
        },
        WorkspaceOp::Status { branch_id } => match vcs.status_report(branch_id)? {
            Some(report) => WorkspaceOpOutcome::Status { report },
            None => refused(format!("no branch `{branch_id}`")),
        },
        WorkspaceOp::Reconcile {
            branch_id,
            target_branch_id,
            quiescent,
            rebase_cut_id,
        } => match vcs.reconcile_branch_against(
            branch_id,
            target_branch_id.as_deref(),
            *quiescent,
            rebase_cut_id,
            at,
        )? {
            ReconcileOutcome::UpToDate => WorkspaceOpOutcome::UpToDate,
            ReconcileOutcome::Rebased { rebase_cut_id } => {
                WorkspaceOpOutcome::Rebased { rebase_cut_id }
            }
            ReconcileOutcome::DeferredMidRun => WorkspaceOpOutcome::DeferredMidRun,
            ReconcileOutcome::Conflicts { conflicts } => {
                WorkspaceOpOutcome::Conflicted { conflicts }
            }
            ReconcileOutcome::BranchMissing => refused(format!("no branch `{branch_id}`")),
            ReconcileOutcome::BranchNotActive => {
                refused(format!("branch `{branch_id}` is not active"))
            }
            ReconcileOutcome::NoParent => refused(format!("branch `{branch_id}` has no parent")),
        },
        WorkspaceOp::ReconcileList => WorkspaceOpOutcome::ReconcileList {
            entries: vcs.reconcile_list()?,
        },
        WorkspaceOp::Remove { branch_id } => match vcs.discard_branch(branch_id, at)? {
            StatusOutcome::Done(row) => WorkspaceOpOutcome::Removed { branch: *row },
            StatusOutcome::InvalidTransition { from } => refused(format!(
                "branch `{branch_id}` is already terminal ({})",
                from.as_str()
            )),
            StatusOutcome::NotFound => refused(format!("no branch `{branch_id}`")),
        },
    })
}

fn create_outcome(outcome: CreateBranchOutcome) -> WorkspaceOpOutcome {
    match outcome {
        CreateBranchOutcome::Created(branch) => WorkspaceOpOutcome::Created { branch },
        CreateBranchOutcome::Existing(branch) => WorkspaceOpOutcome::Existing { branch },
        CreateBranchOutcome::ParentMissing => refused("parent branch missing".to_owned()),
        CreateBranchOutcome::ParentNotActive { status } => {
            refused(format!("parent branch is not active ({})", status.as_str()))
        }
        CreateBranchOutcome::NameTaken { holder_branch_id } => {
            WorkspaceOpOutcome::NameTaken { holder_branch_id }
        }
    }
}

fn refused(reason: String) -> WorkspaceOpOutcome {
    WorkspaceOpOutcome::Refused { reason }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::vcs::NativeWorkspaceVcs;

    fn vcs() -> NativeWorkspaceVcs {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-wsapi-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        NativeWorkspaceVcs::open(dir.join("branches.sqlite"), dir.join("content.sqlite"))
            .expect("open vcs")
    }

    fn apply_json(vcs: &mut NativeWorkspaceVcs, op_json: serde_json::Value, at: &str) -> String {
        // The external-host path: ops arrive as JSON, outcomes leave as
        // JSON — this test drives the protocol exactly as a host would.
        let op: WorkspaceOp = serde_json::from_value(op_json).expect("decode op");
        let outcome = apply(vcs, &op, at).expect("apply");
        serde_json::to_value(&outcome).expect("encode")["outcome"]
            .as_str()
            .expect("tagged")
            .to_owned()
    }

    /// The whole mapped surface, driven as JSON: init → branch → write →
    /// cut → probe → merge → fork-with-lineage → restore → status →
    /// reconcile-list → remove.
    #[test]
    fn the_mapped_operation_surface_round_trips_as_json() {
        use serde_json::json;
        let mut vcs = vcs();
        assert_eq!(
            apply_json(&mut vcs, json!({"op": "init"}), "t0"),
            "initialized"
        );
        assert_eq!(
            apply_json(
                &mut vcs,
                json!({"op": "branch", "branch_id": "draft_a"}),
                "t1"
            ),
            "created"
        );
        // Retry is idempotent, not an error.
        assert_eq!(
            apply_json(
                &mut vcs,
                json!({"op": "branch", "branch_id": "draft_a"}),
                "t1"
            ),
            "existing"
        );
        // Divergence via the verb surface (writes are effect-plane, not
        // protocol ops).
        assert!(matches!(
            vcs.write("draft_a", "a.md", Some("A"), "cut_a1", "t2")
                .expect("write"),
            crate::vcs::VcsWriteOutcome::Written { .. }
        ));
        // Turn-finalize: the head cut is the quiescent cut.
        let op: WorkspaceOp = serde_json::from_value(
            json!({"op": "cut_at_quiescence", "branch_id": "draft_a", "cut_id": "cut_named"}),
        )
        .expect("decode");
        let WorkspaceOpOutcome::Cut { cut } = apply(&mut vcs, &op, "t3").expect("apply") else {
            panic!("expected a cut");
        };
        assert_eq!(cut.cut_id, "cut_a1");
        // Probe: clean, one changed path, nothing moved.
        let op: WorkspaceOp =
            serde_json::from_value(json!({"op": "merge_probe", "branch_id": "draft_a"}))
                .expect("decode");
        let WorkspaceOpOutcome::Probe {
            up_to_date,
            changed_paths,
            ..
        } = apply(&mut vcs, &op, "t4").expect("apply")
        else {
            panic!("expected a probe report");
        };
        assert!(!up_to_date);
        assert_eq!(changed_paths, vec!["a.md".to_owned()]);
        assert_eq!(
            vcs.read("main", "a.md").expect("read"),
            None,
            "the probe moved nothing"
        );
        // Merge for real.
        assert_eq!(
            apply_json(
                &mut vcs,
                json!({"op": "merge", "branch_id": "draft_a", "merge_cut_id": "cut_merge_1"}),
                "t5"
            ),
            "merged"
        );
        // Fork with lineage at the recorded merge cut.
        assert_eq!(
            apply_json(
                &mut vcs,
                json!({"op": "fork_with_lineage", "branch_id": "fork_1",
                       "from_branch": "main", "at_cut_id": "cut_merge_1"}),
                "t6"
            ),
            "created"
        );
        // Advance the fork.
        vcs.write("fork_1", "a.md", Some("changed"), "cut_f1", "t7")
            .expect("write");
        // Status: the fork is ahead (its write) and not behind.
        let op: WorkspaceOp =
            serde_json::from_value(json!({"op": "status", "branch_id": "fork_1"})).expect("decode");
        let WorkspaceOpOutcome::Status { report } = apply(&mut vcs, &op, "t8").expect("apply")
        else {
            panic!("expected status");
        };
        assert_eq!(report.ahead_paths, vec!["a.md".to_owned()]);
        assert!(!report.behind);
        // Reconcile-list sees the fork's pending divergence.
        let op: WorkspaceOp =
            serde_json::from_value(json!({"op": "reconcile_list"})).expect("decode");
        let WorkspaceOpOutcome::ReconcileList { entries } =
            apply(&mut vcs, &op, "t9").expect("apply")
        else {
            panic!("expected entries");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].branch_id, "fork_1");
        assert_eq!(entries[0].ahead_paths, 1);
        // Restore re-points the head to the merge cut's state (a NEW
        // cut, no history rewind) — afterwards the fork is back in sync.
        let op: WorkspaceOp =
            serde_json::from_value(json!({"op": "restore", "branch_id": "fork_1",
                "to_cut_id": "cut_merge_1", "new_cut_id": "cut_f2"}))
            .expect("decode");
        assert!(matches!(
            apply(&mut vcs, &op, "t10").expect("apply"),
            WorkspaceOpOutcome::Restored { .. }
        ));
        assert_eq!(
            vcs.read("fork_1", "a.md").expect("read").as_deref(),
            Some("A"),
            "restore re-pointed the head to the cut's state"
        );
        // Remove closes the head; a second remove is a refusal, not an
        // error.
        assert_eq!(
            apply_json(
                &mut vcs,
                json!({"op": "remove", "branch_id": "fork_1"}),
                "t11"
            ),
            "removed"
        );
        assert_eq!(
            apply_json(
                &mut vcs,
                json!({"op": "remove", "branch_id": "fork_1"}),
                "t12"
            ),
            "refused"
        );
    }

    /// The op log records every pointer movement the surface makes, with
    /// before/after states — the reflog, first-class.
    #[test]
    fn every_mutating_op_lands_in_the_op_log() {
        let mut vcs = vcs();
        vcs.init("t0").expect("init");
        vcs.create_branch("draft_a", None, "main", "t1")
            .expect("create");
        vcs.write("draft_a", "a.md", Some("A"), "cut_a1", "t2")
            .expect("write");
        vcs.merge("draft_a", "cut_merge_1", "t3").expect("merge");
        vcs.create_branch("draft_b", None, "main", "t4")
            .expect("create");
        vcs.discard_branch("draft_b", "t5").expect("discard");
        let ops = vcs.list_ops(10).expect("ops");
        let kinds: Vec<&str> = ops.iter().rev().map(|op| op.kind.as_str()).collect();
        assert_eq!(kinds, vec!["create", "write", "merge", "create", "discard"]);
        // The merge op carries BOTH branches' movements: mainline's head
        // advance and the branch's adoption.
        let merge_op = ops.iter().find(|op| op.kind == "merge").expect("merge op");
        assert_eq!(merge_op.deltas.len(), 2);
        assert_eq!(merge_op.deltas[0].branch_id, "main");
        assert_eq!(merge_op.deltas[1].branch_id, "draft_a");
        assert_eq!(merge_op.deltas[1].after.status, "adopted");
        // The write op's before/after pin the exact head movement.
        let write_op = ops.iter().find(|op| op.kind == "write").expect("write op");
        let before = write_op.deltas[0].before.as_ref().expect("before");
        assert_eq!(before.head_cut_id, None);
        assert_eq!(
            write_op.deltas[0].after.head_cut_id.as_deref(),
            Some("cut_a1")
        );
        // Cut provenance: the write's cut knows its origin and parent.
        let cut = vcs.get_cut("cut_a1").expect("get").expect("cut");
        assert_eq!(cut.origin.as_deref(), Some("write:a.md"));
        assert_eq!(cut.parent_cut_id, None);
    }
}
