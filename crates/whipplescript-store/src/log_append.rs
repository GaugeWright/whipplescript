//! DR-0067's append surface as a **shared trait**, with the conformance driver
//! that both hosts run against it.
//!
//! Until now the append surface was inherent to each store type, so the log's
//! simulation could only drive the native one and the durable-object host got
//! mirrored assertions instead. That is the shape the ref tier already grew out
//! of, and for the same reason: parity established by whichever assertions
//! someone happened to write for each side proves only that each side passes
//! its own test.
//!
//! The trait carries exactly the four operations the contract is about — read
//! the head, read the epoch, take ownership, append under both guards — plus a
//! prefix read so a checker can fold the log *independently* of whatever the
//! store recorded as its head. That last one is what makes the check meaningful
//! rather than self-confirming.

use crate::event_chain::{ChainHead, OwnedChainEntry};
use crate::{NewEvent, StoreResult, StoredEvent};

/// The append surface DR-0067 specifies, shared by every host that has one.
pub trait LogAppend {
    /// The instance's high-water mark, `(sequence, head_digest)`.
    ///
    /// # Errors
    /// Propagates store failures, and refuses an unchained log rather than
    /// silently restarting the chain from genesis.
    fn chain_head(&self, instance_id: &str) -> StoreResult<ChainHead>;

    /// The instance's current owner epoch.
    ///
    /// # Errors
    /// Propagates store failures.
    fn instance_owner_epoch(&self, instance_id: &str) -> StoreResult<i64>;

    /// Take ownership, evicting the previous owner. Returns the epoch every
    /// subsequent append must present.
    ///
    /// # Errors
    /// Propagates store failures; refuses an instance that does not exist.
    fn claim_instance_ownership(&mut self, instance_id: &str) -> StoreResult<i64>;

    /// Append under both guards: the ownership fence and the head
    /// compare-and-set.
    ///
    /// # Errors
    /// A refusal is a `Conflict`, not a fault — losing a race is an ordinary
    /// outcome the caller must handle.
    fn append_event_fenced(
        &mut self,
        owner_epoch: i64,
        expected_head: &str,
        event: NewEvent<'_>,
    ) -> StoreResult<StoredEvent>;

    /// The stored prefix, for folding independently of the recorded head.
    ///
    /// # Errors
    /// Propagates store failures.
    fn chain_prefix(&self, instance_id: &str) -> StoreResult<Vec<OwnedChainEntry>>;
}

/// The append surface's executable conformance driver, shipped with the trait
/// so every implementation runs the same one.
///
/// Not `#[cfg(test)]`, for the reason the ref tier's is not: a driver that only
/// exists in the defining crate's tests cannot be run by an implementation in
/// another crate, which is exactly the case it exists for.
pub mod conformance {
    use super::LogAppend;
    use crate::event_chain;
    use crate::{NewEvent, StoreError, StoreResult};

    fn next_random(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Drive two contending owners against one instance's log under a seeded
    /// schedule, checking H3 (a superseded owner cannot append) and H1 (the
    /// recorded head is what the stored prefix folds to).
    ///
    /// The instance must already exist — creating one differs by host, and the
    /// contract this checks does not.
    ///
    /// Returns how many appends landed, so a caller can assert the schedule
    /// exercised something rather than refusing everything and proving nothing.
    ///
    /// # Errors
    /// Propagates store failures. A *refused* append is not an error.
    pub fn run_contention<S: LogAppend>(
        store: &mut S,
        instance_id: &str,
        seed: u64,
        steps: usize,
    ) -> StoreResult<usize> {
        // Each owner's BELIEF. Stale beliefs are the entire point.
        let mut epochs = [0i64, 0i64];
        let mut heads = [
            event_chain::ChainHead::empty(instance_id),
            event_chain::ChainHead::empty(instance_id),
        ];
        let mut state = seed;
        let mut landed = 0usize;

        for _ in 0..steps {
            let roll = next_random(&mut state);
            let who = usize::try_from(roll >> 8 & 1).unwrap_or(0);
            match roll % 8 {
                0 | 1 => {
                    epochs[who] = store.claim_instance_ownership(instance_id)?;
                }
                2 | 3 => {
                    // Re-reading the head is how a zombie gets past
                    // compare-and-set, and why the epoch has to exist.
                    heads[who] = store.chain_head(instance_id)?;
                }
                _ => {
                    let outcome = store.append_event_fenced(
                        epochs[who],
                        &heads[who].digest,
                        NewEvent {
                            instance_id,
                            event_type: "rule.fired",
                            payload_json: "{}",
                            source: if who == 0 { "owner-a" } else { "owner-b" },
                            causation_id: None,
                            correlation_id: None,
                            idempotency_key: None,
                        },
                    );
                    match outcome {
                        Ok(_) => {
                            landed += 1;
                            let live = store.instance_owner_epoch(instance_id)?;
                            assert_eq!(
                                epochs[who], live,
                                "seed {seed}: an append landed under epoch {} while the \
                                 log was at {live} — a superseded owner wrote",
                                epochs[who]
                            );
                            heads[who] = store.chain_head(instance_id)?;
                        }
                        // A guard did its job. Which guard is asserted by the
                        // dedicated tests; here the point is only that the
                        // refused append left no trace, checked by the fold
                        // below.
                        Err(StoreError::GuardRefused { .. }) => {}
                        Err(other) => return Err(other),
                    }
                }
            }

            // Must hold after EVERY step, landed or refused: the recorded head
            // is exactly what the stored prefix folds to.
            let recorded = store.chain_head(instance_id)?;
            let independent =
                event_chain::fold_owned(instance_id, &store.chain_prefix(instance_id)?);
            assert_eq!(
                recorded, independent,
                "seed {seed}: the recorded head diverged from the stored prefix"
            );
        }
        Ok(landed)
    }

    /// The whole suite over a range of seeds, against a fresh instance per seed.
    ///
    /// `make` yields a store and an instance id that already exists in it.
    ///
    /// # Errors
    /// Propagates store failures.
    pub fn run_suite<S: LogAppend>(
        make: impl Fn() -> (S, String),
        seeds: std::ops::Range<u64>,
    ) -> StoreResult<usize> {
        let mut total = 0usize;
        for seed in seeds {
            let (mut store, instance_id) = make();
            total += run_contention(&mut store, &instance_id, seed, 24)?;
        }
        assert!(
            total > 0,
            "every append was refused, so the suite proved nothing about what a \
             successful append means"
        );
        Ok(total)
    }
}
