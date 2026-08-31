//! The effect-dependency graph's one structural invariant: it is acyclic.
//!
//! An edge `upstream -> downstream` means the downstream effect waits for the
//! upstream one to settle. `satisfy_dependencies` re-queues a
//! `blocked_by_dependency` effect once every edge into it is satisfied, so a
//! cycle is not a cosmetic defect: no effect on the cycle can ever satisfy
//! another, every one of them stays blocked forever, and the instance neither
//! completes nor fails. It is the deadlock a workflow language exists to
//! refuse, and it is silent — the store answers "blocked", which is also what a
//! healthy instance waiting on a slow provider says.
//!
//! Acyclicity was an EMERGENT property until this module: dependencies are
//! lowered from program order, so ordinary programs cannot express a loop, and
//! nothing enforced or tested that. Emergent is not the same as guaranteed —
//! rules fire reactively and the replay/import path
//! (`apply_recorded_effects_payload`) builds edges from a JSON payload — so the
//! invariant is checked at the write instead of assumed.
//!
//! The core is pure and shared by both hosts so the native store and the
//! Durable Object cannot disagree about which graphs exist.

use std::collections::{BTreeMap, BTreeSet};

/// Whether adding `upstream -> downstream` to `existing` would close a cycle.
///
/// `existing` is the instance's edges as `(upstream_effect_id,
/// downstream_effect_id)` pairs, in any order and with duplicates permitted.
///
/// The walk goes UP from the proposed upstream: if the proposed downstream is
/// already a transitive upstream of it, then that node must settle before this
/// edge's upstream can, and this edge asks for the reverse at the same time.
/// A self-edge is the degenerate case of the same thing.
///
/// Terminates on a graph that already contains a cycle — one written before
/// this guard existed, or by another implementation — because each node is
/// expanded at most once. That matters: the caller is a write path, and a guard
/// that hangs on the data it is meant to refuse is worse than no guard.
pub fn edge_closes_cycle(
    existing: &[(String, String)],
    upstream_effect_id: &str,
    downstream_effect_id: &str,
) -> bool {
    if upstream_effect_id == downstream_effect_id {
        return true;
    }
    let mut upstreams_of: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (upstream, downstream) in existing {
        upstreams_of
            .entry(downstream.as_str())
            .or_default()
            .push(upstream.as_str());
    }
    let mut expanded: BTreeSet<&str> = BTreeSet::new();
    let mut pending: Vec<&str> = vec![upstream_effect_id];
    while let Some(node) = pending.pop() {
        if node == downstream_effect_id {
            return true;
        }
        if !expanded.insert(node) {
            continue;
        }
        if let Some(upstreams) = upstreams_of.get(node) {
            pending.extend(upstreams.iter().copied());
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edges(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(upstream, downstream)| ((*upstream).to_owned(), (*downstream).to_owned()))
            .collect()
    }

    #[test]
    fn an_effect_may_not_depend_on_itself() {
        assert!(edge_closes_cycle(&[], "a", "a"));
    }

    #[test]
    fn a_back_edge_closes_a_cycle() {
        // b already waits for a; making a wait for b deadlocks both.
        assert!(edge_closes_cycle(&edges(&[("a", "b")]), "b", "a"));
    }

    #[test]
    fn a_transitive_back_edge_closes_a_cycle() {
        let existing = edges(&[("a", "b"), ("b", "c")]);
        assert!(edge_closes_cycle(&existing, "c", "a"));
    }

    #[test]
    fn a_diamond_is_not_a_cycle() {
        // The case a shared-ancestor check would wrongly refuse: b and c both
        // wait for a, and d waits for both. Nothing waits on d.
        let existing = edges(&[("a", "b"), ("a", "c"), ("b", "d")]);
        assert!(!edge_closes_cycle(&existing, "c", "d"));
    }

    #[test]
    fn a_forward_edge_over_an_existing_chain_is_not_a_cycle() {
        // c waits for a as well as, transitively, through b. Redundant, not circular.
        let existing = edges(&[("a", "b"), ("b", "c")]);
        assert!(!edge_closes_cycle(&existing, "a", "c"));
    }

    #[test]
    fn an_unrelated_edge_is_not_a_cycle() {
        let existing = edges(&[("a", "b")]);
        assert!(!edge_closes_cycle(&existing, "c", "d"));
    }

    #[test]
    fn a_graph_that_already_contains_a_cycle_still_answers() {
        // Written by an older binary or another implementation. The guard must
        // terminate on it rather than hang on the write path.
        let existing = edges(&[("a", "b"), ("b", "a")]);
        assert!(edge_closes_cycle(&existing, "b", "a"));
        assert!(!edge_closes_cycle(&existing, "z", "y"));
    }

    #[test]
    fn duplicate_recorded_edges_do_not_change_the_answer() {
        let existing = edges(&[("a", "b"), ("a", "b"), ("b", "c")]);
        assert!(edge_closes_cycle(&existing, "c", "a"));
        assert!(!edge_closes_cycle(&existing, "c", "d"));
    }
}
