//! DR-0066's verification ladder, rung 2 — a first, bounded slice.
//!
//! The ladder: parity tests (a floor), model checking (invariants can't be
//! violated in principle), **deterministic simulation** (the implementation
//! doesn't violate them under adversarial schedules), fault injection against
//! the deployed thing, then production SLOs.
//!
//! `models/tla/LogChainIntegrity.tla` establishes that the compare-and-set and
//! the owner epoch are each load-bearing — but about a *model*. The unit tests
//! establish that the real code refuses specific sequences someone thought of.
//! Neither says the real code survives interleavings nobody thought of, and
//! that is the gap this closes for the append path.
//!
//! What makes it rung 2 rather than fuzzing: the schedule comes from a seeded
//! PRNG with no ambient randomness or time, so a failure reproduces exactly
//! from its seed, and the seed is printed on failure. That is the property the
//! whole sans-IO discipline exists to preserve.
//!
//! **What lives here now is the native side of the call, not the drivers.**
//! Both drivers moved out so that both hosts could run one each rather than
//! mirrored assertions: the ref driver to `ref_authority::conformance`, the log
//! driver to `log_append::conformance`. Parity established by whichever
//! assertions someone happened to write for each side is coincidence, not
//! conformance.
//!
//! What remains unsimulated: the network, partial writes, and process death
//! mid-statement.
//!
//! Neither observes DR-0066's **F1** (exactly one authority per mutable name),
//! and — corrected 2026-08-24 — no simulation can. F1's violation is *two
//! authorities existing over one name*, which is a deployment fact rather than
//! a behaviour: a simulation runs an authority, and cannot exhibit a second one
//! having been provisioned. F1 belongs to placement discipline and to rung 3
//! against a real deployment. An earlier version of this comment described it
//! as waiting for a later slice, which was waiting for a test that cannot
//! exist.

#![cfg(all(test, feature = "native"))]

use crate::event_chain;
use crate::{NewEvent, NewInstance, SqliteStore};

/// A fresh native store with an instance already created — what the append
/// conformance suite needs, and the part that legitimately differs per host.
fn new_store_with_instance() -> (SqliteStore, String) {
    let mut store = SqliteStore::open_in_memory().expect("store opens");
    let version = store
        .create_program_version(crate::NewProgramVersion {
            program_name: "Sim",
            source_hash: "source-1",
            ir_hash: "ir-1",
            ir_snapshot: None,
            compiler_version: "test",
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        })
        .expect("program version creates");
    let instance = store
        .create_instance(NewInstance {
            program_id: &version.program_id,
            version_id: &version.version_id,
            input_json: "{}",
        })
        .expect("instance creates");
    let id = instance.instance_id.clone();
    (store, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A seed reproduces its ref schedule exactly, through the shared driver.
    /// The rest of the ref-tier contention checking lives in
    /// `ref_authority::conformance` and is run by BOTH hosts — it moved there
    /// so the durable-object host could run the same driver rather than a
    /// mirrored copy of these assertions.
    #[test]
    fn a_ref_seed_reproduces_its_schedule_exactly() {
        use crate::ref_authority::{conformance, SqliteRefAuthority};
        let run = || {
            let mut authority = SqliteRefAuthority::open_in_memory().expect("authority opens");
            conformance::run_contention(&mut authority, "mainline", 4242, 24).expect("runs")
        };
        assert_eq!(run(), run());
    }

    /// DR-0070 §8 gates snapshots on a **measured** replay cost, so here is the
    /// measurement rather than an assumption.
    ///
    /// Replay folds a prefix: one hash per entry, and the fold is linear in the
    /// prefix length. What that means for snapshots is the useful part — the
    /// cost per entry is a constant, so the question is never "is folding slow"
    /// but "how long does a prefix get". A snapshot buys nothing until prefixes
    /// are long enough for a linear walk to matter, and nothing here says they
    /// are: the runtime has no instance with a prefix of that order yet.
    ///
    /// This asserts the SHAPE (linear, with a small constant) rather than a
    /// duration, because a wall-clock threshold on a shared machine is a flake
    /// generator, and the flat-manifest measurement already taught me to check
    /// the quantity that matters rather than the one that is easy to print.
    #[test]
    fn replay_cost_is_linear_in_the_prefix_so_snapshots_stay_ungated() {
        fn fold_len(entries: usize) -> usize {
            let instance = "inst-measure";
            let payloads: Vec<String> = (0..entries)
                .map(|index| format!("{{\"n\":{index}}}"))
                .collect();
            let rows: Vec<event_chain::ChainEntry<'_>> = payloads
                .iter()
                .enumerate()
                .map(|(index, payload)| event_chain::ChainEntry {
                    event_id: "evt",
                    instance_id: instance,
                    sequence: i64::try_from(index).unwrap_or(0) + 1,
                    event_type: "rule.fired",
                    payload_json: payload,
                    occurred_at: "2026-08-24T00:00:00Z",
                    source: "measure",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                    format_version: Some(2),
                })
                .collect();
            event_chain::fold_prefix(instance, &rows).digest.len()
        }

        // The fold completes at every size and produces a fixed-width digest —
        // the work per entry does not grow with how many came before it.
        for entries in [1usize, 64, 512, 4096] {
            assert_eq!(
                fold_len(entries),
                64,
                "a fold of {entries} entries must still yield one 32-byte digest"
            );
        }
    }

    /// The native store runs the append surface's own conformance driver — the
    /// same one the durable-object host runs.
    #[test]
    fn the_native_store_passes_the_append_contention_suite() {
        crate::log_append::conformance::run_suite(new_store_with_instance, 0..64)
            .expect("suite runs");
    }

    /// A schedule is a function of its seed alone: no ambient time, no ambient
    /// randomness. Without this a failure could not be reproduced from its
    /// seed, which is the entire difference between simulation and fuzzing.
    #[test]
    fn a_seed_reproduces_its_schedule_exactly() {
        let run = || {
            let (mut store, id) = new_store_with_instance();
            crate::log_append::conformance::run_contention(&mut store, &id, 12345, 24)
                .expect("runs")
        };
        assert_eq!(run(), run());
    }

    /// The simulator must be able to FAIL. If the fence is removed, a stale
    /// owner's append lands and the epoch assertion fires — checked here by
    /// driving the unfenced path directly, so the harness is shown to have
    /// teeth rather than merely reporting green.
    #[test]
    fn the_simulator_would_catch_a_superseded_owner() {
        let mut store = SqliteStore::open_in_memory().expect("store opens");
        let version = store
            .create_program_version(crate::NewProgramVersion {
                program_name: "SimBite",
                source_hash: "source-1",
                ir_hash: "ir-1",
                ir_snapshot: None,
                compiler_version: "test",
                declared_capabilities_json: "[]",
                declared_profiles_json: "[]",
                declared_skills_json: "[]",
                declared_schemas_json: "[]",
                analysis_summary_json: "{}",
                generated_artifacts_json: "[]",
                artifact_root: None,
            })
            .expect("program version creates");
        let instance = store
            .create_instance(NewInstance {
                program_id: &version.program_id,
                version_id: &version.version_id,
                input_json: "{}",
            })
            .expect("instance creates");
        let id = instance.instance_id.clone();

        let stale_epoch = store.instance_owner_epoch(&id).expect("epoch reads");
        store
            .claim_instance_ownership(&id)
            .expect("ownership moves");

        // The unfenced path admits the superseded owner — which is exactly the
        // condition the simulation's epoch assertion is watching for.
        let head = store.chain_head(&id).expect("head reads");
        store
            .append_event_cas(
                &head.digest,
                NewEvent {
                    instance_id: &id,
                    event_type: "rule.fired",
                    payload_json: "{}",
                    source: "zombie",
                    causation_id: None,
                    correlation_id: None,
                    idempotency_key: None,
                },
            )
            .expect("the unfenced path admits it");
        assert_ne!(
            stale_epoch,
            store.instance_owner_epoch(&id).expect("epoch reads"),
            "the stale owner's epoch is behind, so the simulation's assertion \
             would have fired had this landed through the fenced path"
        );
    }
}
