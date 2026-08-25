//! Reconciliation planner: the decision core of daemon v1
//! (spec/versioned-workspace-research-note.md §7.1; untie-substrate
//! readiness tracker Phase 1; lifecycle modeled in
//! ReconciliationDaemonLifecycle.tla, merge content in merge-slice /
//! merge-confluence.maude).
//!
//! Pure planning over manifests — no store handle, no feature gate. The
//! daemon loop (lease acquisition, head advancement, notification
//! delivery) executes these plans against the branch/workstream stores;
//! this module decides, the caller acts, and every refusal is a normal
//! outcome. The two directions carry different policies:
//!
//! * **Rebase-down** — "your nose is your branch's slice": a target delta
//!   that merges cleanly against the branch's divergence folds in
//!   silently AT ANY TIME, running included; a conflicting delta never
//!   touches a mid-run branch (per-run snapshot isolation is absolute)
//!   and surfaces at a quiescence point as the notification-and-ask
//!   payload — structured conflicts, both sides, provenance.
//! * **Merge-up** — only under the adoption lease, only quiescent, and
//!   only with the staleness bound discharged AT MERGE TIME: the branch
//!   must be fully rebased down (its branch point = the target's current
//!   head cut), so the certified content IS the branch head manifest and
//!   the advance is conflict-free by construction.
//!
//! v1 certificates are blob-plane (clean three-way = certificate); the
//! declaration-granularity slice certificate joins here when the
//! whip-source merge half lands.

use std::collections::BTreeMap;

use crate::merge::{merge_manifests, MergeOutcome, MergeSide, PathConflict};

/// One rebase-down decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RebaseDownPlan {
    /// Base already equals the target head — nothing to fold.
    UpToDate,
    /// The delta is disjoint from the branch's divergence: fold silently,
    /// in any phase. The caller records `new_head_manifest` as the
    /// branch's next cut and re-points its branch point at the target
    /// head.
    Silent {
        new_head_manifest: BTreeMap<String, String>,
    },
    /// The delta intersects a running branch's work: nothing moves —
    /// deferred to the next quiescence point.
    DeferredMidRun,
    /// At quiescence, the intersecting delta arrives as an ask: the
    /// structured conflicts are the notification payload. Nothing is
    /// auto-resolved.
    ///
    /// `merged_remainder` is the clean part of the SAME three-way, carried
    /// rather than dropped: the caller needs it to build the refined manifest
    /// once the contested paths resolve, and recovering it meant re-walking the
    /// union of three manifests for an answer already computed here.
    AskAtQuiescence {
        conflicts: Vec<PathConflict>,
        merged_remainder: BTreeMap<String, String>,
    },
}

/// One merge-up decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MergeUpPlan {
    /// Not holding the adoption lease: refused, acquire first.
    NeedsLease,
    /// A merge-up of a running branch is refused: quiesce first.
    NeedsQuiescence,
    /// The staleness bound bites AT MERGE TIME: the branch's base is not
    /// the target's current head (the target may have advanced since the
    /// lease was acquired) — rebase down first, then retry.
    StaleBase {
        branch_point_cut_id: Option<String>,
        target_head_cut_id: Option<String>,
    },
    /// Certified: the branch is fully rebased, so its head manifest IS
    /// the merged content; the caller advances the target head to it and
    /// adopts the branch.
    Certified {
        merged_manifest: BTreeMap<String, String>,
    },
}

/// Plan a rebase-down of `target_head` into a branch whose divergence is
/// (`branch_point` → `branch_head`). `quiescent` is the branch's phase at
/// planning time.
pub fn plan_rebase_down(
    branch_point: &BTreeMap<String, String>,
    branch_head: &BTreeMap<String, String>,
    target_head: &BTreeMap<String, String>,
    branch_side: &MergeSide,
    target_side: &MergeSide,
    quiescent: bool,
) -> RebaseDownPlan {
    if branch_point == target_head {
        return RebaseDownPlan::UpToDate;
    }
    match merge_manifests(
        branch_point,
        branch_head,
        target_head,
        branch_side,
        target_side,
    ) {
        MergeOutcome::Clean { manifest } => RebaseDownPlan::Silent {
            new_head_manifest: manifest,
        },
        MergeOutcome::Conflicted {
            conflicts,
            merged_remainder,
        } => {
            if quiescent {
                RebaseDownPlan::AskAtQuiescence {
                    conflicts,
                    merged_remainder,
                }
            } else {
                RebaseDownPlan::DeferredMidRun
            }
        }
    }
}

/// Plan a merge-up of a branch into its target line. `branch_point_cut_id`
/// and `target_head_cut_id` are compared for the staleness bound; the
/// caller passes the CURRENT target head (re-read under the lease), never
/// a cached one.
#[allow(clippy::too_many_arguments)]
pub fn plan_merge_up(
    branch_head: &BTreeMap<String, String>,
    branch_point_cut_id: Option<&str>,
    target_head_cut_id: Option<&str>,
    lease_held: bool,
    quiescent: bool,
) -> MergeUpPlan {
    if !lease_held {
        return MergeUpPlan::NeedsLease;
    }
    if !quiescent {
        return MergeUpPlan::NeedsQuiescence;
    }
    if branch_point_cut_id != target_head_cut_id {
        return MergeUpPlan::StaleBase {
            branch_point_cut_id: branch_point_cut_id.map(str::to_owned),
            target_head_cut_id: target_head_cut_id.map(str::to_owned),
        };
    }
    MergeUpPlan::Certified {
        merged_manifest: branch_head.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(path, hash)| ((*path).to_owned(), (*hash).to_owned()))
            .collect()
    }

    fn sides() -> (MergeSide, MergeSide) {
        (
            MergeSide {
                label: "draft_a".to_owned(),
                cut_id: Some("cut_a".to_owned()),
            },
            MergeSide {
                label: "main".to_owned(),
                cut_id: Some("cut_m".to_owned()),
            },
        )
    }

    /// A disjoint mainline delta folds silently even MID-RUN — divergence
    /// never accumulates where it doesn't matter.
    #[test]
    fn disjoint_delta_rebases_silently_mid_run() {
        let (ours, theirs) = sides();
        let base = manifest(&[("a.md", "h_a0"), ("b.md", "h_b0")]);
        let branch_head = manifest(&[("a.md", "h_a1"), ("b.md", "h_b0")]);
        let target_head = manifest(&[("a.md", "h_a0"), ("b.md", "h_b1")]);
        let plan = plan_rebase_down(&base, &branch_head, &target_head, &ours, &theirs, false);
        assert_eq!(
            plan,
            RebaseDownPlan::Silent {
                new_head_manifest: manifest(&[("a.md", "h_a1"), ("b.md", "h_b1")])
            }
        );
    }

    /// An intersecting delta NEVER moves a running branch
    /// (NoMidRunIntrusion), and at quiescence it arrives as the
    /// structured ask, not an auto-merge.
    #[test]
    fn intersecting_delta_defers_mid_run_and_asks_at_quiescence() {
        let (ours, theirs) = sides();
        let base = manifest(&[("a.md", "h_a0")]);
        let branch_head = manifest(&[("a.md", "h_a1")]);
        let target_head = manifest(&[("a.md", "h_a2")]);
        assert_eq!(
            plan_rebase_down(&base, &branch_head, &target_head, &ours, &theirs, false),
            RebaseDownPlan::DeferredMidRun
        );
        let RebaseDownPlan::AskAtQuiescence {
            conflicts,
            merged_remainder,
        } = plan_rebase_down(&base, &branch_head, &target_head, &ours, &theirs, true)
        else {
            panic!("expected the ask");
        };
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].path, "a.md");
        // The ask carries the clean half of the same three-way, so the caller
        // never has to recompute the merge to build the refined manifest.
        assert!(!merged_remainder.contains_key("a.md"));
    }

    #[test]
    fn up_to_date_branch_needs_nothing() {
        let (ours, theirs) = sides();
        let head = manifest(&[("a.md", "h_a0")]);
        assert_eq!(
            plan_rebase_down(&head.clone(), &head.clone(), &head, &ours, &theirs, true),
            RebaseDownPlan::UpToDate
        );
    }

    /// Merge-up guards, in refusal order: lease, quiescence, staleness —
    /// staleness checked against the CURRENT target head (NoStaleMerge:
    /// the guard re-checks at merge time).
    #[test]
    fn merge_up_guards_refuse_in_order() {
        let head = manifest(&[("a.md", "h_a1")]);
        assert_eq!(
            plan_merge_up(&head, Some("cut_1"), Some("cut_1"), false, true),
            MergeUpPlan::NeedsLease
        );
        assert_eq!(
            plan_merge_up(&head, Some("cut_1"), Some("cut_1"), true, false),
            MergeUpPlan::NeedsQuiescence
        );
        // The target advanced after the lease was acquired: stale.
        assert_eq!(
            plan_merge_up(&head, Some("cut_1"), Some("cut_2"), true, true),
            MergeUpPlan::StaleBase {
                branch_point_cut_id: Some("cut_1".to_owned()),
                target_head_cut_id: Some("cut_2".to_owned()),
            }
        );
        assert_eq!(
            plan_merge_up(&head, Some("cut_1"), Some("cut_1"), true, true),
            MergeUpPlan::Certified {
                merged_manifest: head
            }
        );
    }
}
