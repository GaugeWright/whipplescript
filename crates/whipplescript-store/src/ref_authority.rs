//! DR-0069: the ref-authority seam.
//!
//! DR-0066 §2 requires **exactly one authority per mutable name**. Where that
//! authority lives differs by host — a SQLite transaction natively, one Durable
//! Object per workspace on the cloud host, where single-instance-per-id is the
//! platform's own guarantee — so it is a trait with two implementations rather
//! than a fork, following the pattern the store already uses for coordination.
//!
//! What is deliberately *not* here: consensus. Refs advance at merge cadence,
//! not edit cadence (research note §7.1), and per-agent branch tips do not
//! belong in a shared authority at all. Owning a consensus implementation would
//! be the worst liability available at this stage; if Durable Objects are ever
//! outgrown, this trait makes FoundationDB or etcd a swap.
//!
//! Two things every implementation owes, and both are contract rather than
//! convention:
//!
//! - **Position disclosure** (DR-0066 §6). [`RefRead`] carries a position, so a
//!   cached or follower read can say where it is. A read that cannot state its
//!   position is not a valid implementation of this trait — that disclosure is
//!   what makes lag something a caller can reason about instead of a hazard,
//!   and what makes DR-0068's pinning enforceable rather than merely polite.
//! - **Compare-and-set** ([`RefAuthority::advance`]). A blind write would let
//!   two writers lose each other's updates, which is precisely the multi-master
//!   behaviour DR-0066 §2 refuses.

use crate::StoreResult;

/// A read of a mutable name, with the authority's position attached.
///
/// The position is monotonic within one authority. It is *not* a timestamp and
/// carries no meaning across authorities; comparing positions from two
/// different names or two different hosts is meaningless and callers must not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefRead {
    /// The name's current value, or `None` if it has never been set.
    pub value: Option<String>,
    /// How far this authority has advanced overall. Monotonic, never reused.
    pub position: u64,
}

/// The outcome of an attempted advance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdvanceOutcome {
    Advanced {
        position: u64,
    },
    /// The name did not hold `expected`. The caller is told what it *does*
    /// hold, so it can re-read and decide rather than retry blindly.
    Rejected {
        current: Option<String>,
        position: u64,
    },
}

impl AdvanceOutcome {
    #[must_use]
    pub fn advanced(&self) -> bool {
        matches!(self, Self::Advanced { .. })
    }
}

/// The single authority for a set of mutable names.
///
/// Lineage (DR-0068 §6 — `to_cut` must descend from `from_cut`) is deliberately
/// **not** enforced here. Descent is a branch-store question and this seam does
/// not know about branches; a cut-valued ref gets its lineage check from the
/// layer that holds both. Putting it here would either drag branch knowledge
/// into the ref tier or, worse, invite an implementation to answer the descent
/// question wrongly because it had no way to answer it at all.
pub trait RefAuthority {
    /// Read a name and the authority's position.
    ///
    /// # Errors
    /// Propagates store failures. An unset name is `Ok` with a `None` value,
    /// not an error — never having been set is a normal state.
    fn read(&self, name: &str) -> StoreResult<RefRead>;

    /// Compare-and-set. Succeeds only when the name currently holds `expected`
    /// (`None` meaning "must be unset", which is how a name is first claimed).
    ///
    /// # Errors
    /// Propagates store failures. A *rejection* is not an error — it is an
    /// [`AdvanceOutcome`], because losing a race is an ordinary outcome the
    /// caller must handle rather than an exceptional one.
    fn advance(
        &mut self,
        name: &str,
        expected: Option<&str>,
        next: &str,
    ) -> StoreResult<AdvanceOutcome>;

    /// Coalescing change feed: the name's current value if it has moved since
    /// `position`, otherwise `None`.
    ///
    /// Coalescing rather than at-least-once-per-change, and the reason is that
    /// a runner re-reads the authority anyway (DR-0068 §1) — so it needs "has
    /// this moved", not a replay of every intermediate value. That decision is
    /// open in DR-0069 until the first real consumer; this is the leaning it
    /// records, and it ships in v1 because retrofitting a change feed means
    /// unwinding a polling loop from every consumer that grew one.
    ///
    /// # Errors
    /// Propagates store failures.
    fn changes_since(&self, name: &str, position: u64) -> StoreResult<Option<RefRead>>;
}

/// The trait's **executable conformance driver**, shipped with the trait so
/// every implementation runs the same one.
///
/// DR-0066's gaps section asked for exactly this and explained why: parity
/// between two implementations established by whichever assertions someone
/// happened to write for each is not conformance, it is coincidence. A driver
/// that lives beside the contract and is called by both hosts makes "these two
/// agree" a checked claim rather than a hopeful one.
///
/// It is deliberately not `#[cfg(test)]`: a conformance driver that only exists
/// in the defining crate's tests cannot be run by an implementation in another
/// crate, which is precisely the case it exists for.
pub mod conformance {
    use super::{AdvanceOutcome, RefAuthority};
    use crate::StoreResult;

    /// splitmix64 — deterministic and seedless at runtime, so a schedule is a
    /// function of its seed alone and a failure reproduces exactly.
    fn next_random(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Drive two contending clients against one authority under a seeded
    /// schedule, checking F2 (position disclosure) and F3 (compare-and-set).
    ///
    /// Returns how many advances committed, so a caller can assert the schedule
    /// exercised something rather than rejecting everything and proving nothing.
    ///
    /// Panics on violation, naming the seed — the failure has to be
    /// reproducible to be worth reporting.
    ///
    /// # Errors
    /// Propagates store failures. A *rejected* advance is not an error; it is
    /// the outcome half the contract is about.
    pub fn run_contention<R: RefAuthority>(
        authority: &mut R,
        name: &str,
        seed: u64,
        steps: usize,
    ) -> StoreResult<usize> {
        let mut believed: [Option<String>; 2] = [None, None];
        let mut last_committed: Option<String> = None;
        let mut last_position = 0u64;
        let mut committed = 0usize;
        let mut state = seed;

        for step in 0..steps {
            let roll = next_random(&mut state);
            let who = usize::try_from(roll >> 8 & 1).unwrap_or(0);
            if roll.is_multiple_of(3) {
                believed[who] = authority.read(name)?.value;
                continue;
            }
            let next = format!("cut-{who}-{step}");
            let outcome = authority.advance(name, believed[who].as_deref(), &next)?;
            let read = authority.read(name)?;

            match outcome {
                AdvanceOutcome::Advanced { position } => {
                    assert_eq!(
                        believed[who], last_committed,
                        "seed {seed}: an advance committed over a value the client was \
                         not holding — a lost update"
                    );
                    assert!(
                        position > last_position,
                        "seed {seed}: a commit did not move the position forward"
                    );
                    last_position = position;
                    last_committed = Some(next.clone());
                    believed[who] = Some(next);
                    committed += 1;
                }
                AdvanceOutcome::Rejected { current, position } => {
                    assert_eq!(
                        current, last_committed,
                        "seed {seed}: a rejection reported a value that never committed"
                    );
                    assert_eq!(
                        position, last_position,
                        "seed {seed}: a rejected advance consumed a position"
                    );
                }
            }
            assert_eq!(
                read.value, last_committed,
                "seed {seed}: the authority's value diverged from the committed chain"
            );
        }
        Ok(committed)
    }

    /// The whole suite over a range of seeds. An implementation that passes this
    /// satisfies F2 and F3 under interleavings nobody enumerated.
    ///
    /// # Errors
    /// Propagates store failures.
    pub fn run_suite<R: RefAuthority>(
        make: impl Fn() -> R,
        seeds: std::ops::Range<u64>,
    ) -> StoreResult<usize> {
        let mut total = 0usize;
        for seed in seeds {
            let mut authority = make();
            total += run_contention(&mut authority, "mainline", seed, 24)?;
        }
        assert!(
            total > 0,
            "every advance was rejected, so the suite proved nothing about what a \
             successful advance means"
        );
        Ok(total)
    }
}

#[cfg(feature = "native")]
mod sqlite {
    use super::{AdvanceOutcome, RefAuthority, RefRead};
    use crate::StoreResult;
    use rusqlite::{params, Connection, OptionalExtension};

    /// The native authority: one SQLite transaction, so single-writer is a
    /// property of the database rather than something this code arranges.
    pub struct SqliteRefAuthority {
        connection: Connection,
    }

    impl SqliteRefAuthority {
        /// Open (and create) a ref authority at `path`.
        ///
        /// # Errors
        /// Propagates SQLite failures opening or migrating the file.
        pub fn open(path: impl AsRef<std::path::Path>) -> StoreResult<Self> {
            let connection = Connection::open(path)?;
            // WAL and a busy timeout, exactly as `SqliteStore::open` does, and
            // for a reason the concurrency test found the hard way: without
            // them a contended `advance` fails with SQLITE_BUSY, which is
            // neither `Advanced` nor `Rejected`. `Immediate` alone is not
            // enough — it takes the write lock up front, but still needs to be
            // willing to WAIT for it.
            //
            // DR-0069 §6 owns the contract this implements: contention is a
            // WAIT, the outcome space stays two, and exceeding the bound is a
            // fault rather than a third outcome, because `Advanced` and
            // `Rejected` describe COMPLETED advances. Until 2026-08-31 that
            // decision lived here and in a conformance-ledger entry and in no
            // record — which is why the record now says why a `Busy` variant
            // and an unbounded wait are both refused.
            crate::establish_wal(&connection)?;
            let store = Self { connection };
            store.ensure_schema()?;
            Ok(store)
        }

        /// An in-memory authority, for tests.
        ///
        /// # Errors
        /// Propagates SQLite failures.
        pub fn open_in_memory() -> StoreResult<Self> {
            let connection = Connection::open_in_memory()?;
            // WAL does not apply in memory, but the busy timeout is set anyway
            // so the two constructors behave the same under contention — the
            // same posture `SqliteStore::open_in_memory` takes.
            connection.busy_timeout(crate::STORE_BUSY_TIMEOUT)?;
            let store = Self { connection };
            store.ensure_schema()?;
            Ok(store)
        }

        fn ensure_schema(&self) -> StoreResult<()> {
            self.connection.execute_batch(
                "CREATE TABLE IF NOT EXISTS refs (
                     name TEXT PRIMARY KEY,
                     value TEXT NOT NULL,
                     position INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS ref_position (
                     id INTEGER PRIMARY KEY CHECK (id = 0),
                     position INTEGER NOT NULL
                 );
                 INSERT OR IGNORE INTO ref_position (id, position) VALUES (0, 0);",
            )?;
            Ok(())
        }

        fn position(&self) -> StoreResult<u64> {
            let position: i64 = self.connection.query_row(
                "SELECT position FROM ref_position WHERE id = 0",
                [],
                |row| row.get(0),
            )?;
            Ok(position as u64)
        }
    }

    impl RefAuthority for SqliteRefAuthority {
        fn read(&self, name: &str) -> StoreResult<RefRead> {
            let value: Option<String> = self
                .connection
                .query_row(
                    "SELECT value FROM refs WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(RefRead {
                value,
                position: self.position()?,
            })
        }

        fn advance(
            &mut self,
            name: &str,
            expected: Option<&str>,
            next: &str,
        ) -> StoreResult<AdvanceOutcome> {
            let tx = self
                .connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let current: Option<String> = tx
                .query_row(
                    "SELECT value FROM refs WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            if current.as_deref() != expected {
                let position: i64 = tx.query_row(
                    "SELECT position FROM ref_position WHERE id = 0",
                    [],
                    |row| row.get(0),
                )?;
                return Ok(AdvanceOutcome::Rejected {
                    current,
                    position: position as u64,
                });
            }
            tx.execute(
                "UPDATE ref_position SET position = position + 1 WHERE id = 0",
                [],
            )?;
            let position: i64 = tx.query_row(
                "SELECT position FROM ref_position WHERE id = 0",
                [],
                |row| row.get(0),
            )?;
            tx.execute(
                "INSERT INTO refs (name, value, position) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value, \
                 position = excluded.position",
                params![name, next, position],
            )?;
            tx.commit()?;
            Ok(AdvanceOutcome::Advanced {
                position: position as u64,
            })
        }

        fn changes_since(&self, name: &str, position: u64) -> StoreResult<Option<RefRead>> {
            let row: Option<(String, i64)> = self
                .connection
                .query_row(
                    "SELECT value, position FROM refs WHERE name = ?1",
                    params![name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let Some((value, moved_at)) = row else {
                return Ok(None);
            };
            if (moved_at as u64) <= position {
                return Ok(None);
            }
            Ok(Some(RefRead {
                value: Some(value),
                position: self.position()?,
            }))
        }
    }
}

#[cfg(feature = "native")]
pub use sqlite::SqliteRefAuthority;

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn authority() -> SqliteRefAuthority {
        SqliteRefAuthority::open_in_memory().expect("authority opens")
    }

    #[test]
    fn an_unset_name_reads_as_none_not_an_error() {
        let authority = authority();
        let read = authority.read("mainline").expect("read succeeds");
        assert_eq!(read.value, None);
    }

    #[test]
    fn a_name_is_claimed_by_advancing_from_unset() {
        let mut authority = authority();
        assert!(authority
            .advance("mainline", None, "cut_1")
            .expect("advance")
            .advanced());
        assert_eq!(
            authority.read("mainline").expect("read").value,
            Some("cut_1".to_owned())
        );
    }

    /// The multi-master refusal, at the smallest scale it can be shown: two
    /// writers both holding the same prior value, only one of which may win.
    #[test]
    fn a_stale_expectation_is_rejected_and_told_what_is_there() {
        let mut authority = authority();
        authority
            .advance("mainline", None, "cut_1")
            .expect("first claims");
        authority
            .advance("mainline", Some("cut_1"), "cut_2")
            .expect("owner advances");

        let loser = authority
            .advance("mainline", Some("cut_1"), "cut_other")
            .expect("advance returns an outcome, not an error");
        assert_eq!(
            loser,
            AdvanceOutcome::Rejected {
                current: Some("cut_2".to_owned()),
                position: authority.read("mainline").expect("read").position,
            },
            "a rejected advance must say what the name actually holds"
        );
        assert_eq!(
            authority.read("mainline").expect("read").value,
            Some("cut_2".to_owned()),
            "the loser must not have overwritten the winner"
        );
    }

    /// Claiming a name that already exists must not silently succeed: `None`
    /// means "must be unset", and treating it as "don't care" would be a blind
    /// write wearing a compare-and-set's clothes.
    #[test]
    fn claiming_an_already_set_name_is_rejected() {
        let mut authority = authority();
        authority
            .advance("mainline", None, "cut_1")
            .expect("first claims");
        assert!(!authority
            .advance("mainline", None, "cut_hostile")
            .expect("advance")
            .advanced());
    }

    #[test]
    fn positions_are_monotonic_across_names() {
        let mut authority = authority();
        let start = authority.read("a").expect("read").position;
        authority.advance("a", None, "x").expect("advance a");
        let after_a = authority.read("a").expect("read").position;
        authority.advance("b", None, "y").expect("advance b");
        let after_b = authority.read("b").expect("read").position;

        assert!(after_a > start);
        assert!(
            after_b > after_a,
            "the position is the authority's, not the name's"
        );
    }

    /// A rejected advance must not consume a position: positions exist so a
    /// reader can tell whether anything moved, and a failed write moved nothing.
    #[test]
    fn a_rejected_advance_does_not_move_the_position() {
        let mut authority = authority();
        authority.advance("a", None, "x").expect("advance");
        let before = authority.read("a").expect("read").position;
        authority
            .advance("a", Some("wrong"), "y")
            .expect("advance returns an outcome");
        assert_eq!(authority.read("a").expect("read").position, before);
    }

    #[test]
    fn changes_since_coalesces_and_reports_only_movement() {
        let mut authority = authority();
        authority.advance("a", None, "x").expect("advance");
        let seen = authority.read("a").expect("read").position;

        assert_eq!(
            authority.changes_since("a", seen).expect("watch"),
            None,
            "nothing has moved since the caller last looked"
        );

        // Two advances while the caller was away collapse into one report of
        // the latest value — that is what coalescing means here.
        authority.advance("a", Some("x"), "y").expect("advance");
        authority.advance("a", Some("y"), "z").expect("advance");
        let change = authority
            .changes_since("a", seen)
            .expect("watch")
            .expect("the name moved");
        assert_eq!(change.value, Some("z".to_owned()));
    }

    /// The native host runs the trait's own conformance driver — the same one
    /// the durable-object host runs, so "these two agree" is checked rather
    /// than asserted.
    #[test]
    fn the_native_authority_passes_the_contention_suite() {
        super::conformance::run_suite(
            || SqliteRefAuthority::open_in_memory().expect("authority opens"),
            0..64,
        )
        .expect("suite runs");
    }

    /// **Real threads, not simulated interleaving.**
    ///
    /// `conformance::run_contention` interleaves two clients in one thread,
    /// which checks the *logic* of compare-and-set and cannot check its
    /// *atomicity* — a read and a write that race across real threads against a
    /// shared file are a different question, and the one that produced three
    /// defects elsewhere in this work.
    ///
    /// The invariant is lost-update freedom stated structurally: every
    /// successful advance's `expected` must be the `next` of some earlier
    /// success (or `None` for the first), so the winners form one chain with no
    /// value overwritten unseen.
    #[test]
    fn concurrent_advances_form_one_chain_with_no_lost_update() {
        let dir = std::env::temp_dir().join(format!(
            "whip-ref-race-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path = dir.join("refs.sqlite");
        SqliteRefAuthority::open(&path).expect("authority initialises");

        const WRITERS: usize = 4;
        const ROUNDS: usize = 10;
        let wins = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
        let mut handles = Vec::new();
        for who in 0..WRITERS {
            let path = path.clone();
            let wins = std::sync::Arc::clone(&wins);
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut authority = SqliteRefAuthority::open(&path).expect("writer opens");
                barrier.wait();
                for round in 0..ROUNDS {
                    let seen = authority.read("mainline").expect("read").value;
                    let next = format!("cut-{who}-{round}");
                    if let AdvanceOutcome::Advanced { .. } = authority
                        .advance("mainline", seen.as_deref(), &next)
                        .expect("advance returns an outcome")
                    {
                        wins.lock().expect("lock").push((seen, next));
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().expect("writer finishes");
        }

        let wins = wins.lock().expect("lock").clone();
        assert!(
            !wins.is_empty(),
            "no advance committed, so nothing was checked"
        );

        // Every winner's expectation must be some earlier winner's product.
        // Order the wins by following that chain; if any link is missing, a
        // write was overwritten without its author being told.
        let mut current: Option<String> = None;
        let mut linked = 0usize;
        while let Some((_, next)) = wins
            .iter()
            .find(|(expected, _)| expected.as_deref() == current.as_deref())
        {
            current = Some(next.clone());
            linked += 1;
        }
        assert_eq!(
            linked,
            wins.len(),
            "the successful advances must form ONE chain; {} of {} linked, so a \
             committed value was overwritten by a writer that had not seen it",
            linked,
            wins.len()
        );
        assert_eq!(
            SqliteRefAuthority::open(&path)
                .expect("reopen")
                .read("mainline")
                .expect("read")
                .value,
            current,
            "the stored value must be the end of that chain"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changes_since_ignores_other_names() {
        let mut authority = authority();
        authority.advance("a", None, "x").expect("advance");
        let seen = authority.read("a").expect("read").position;
        authority.advance("b", None, "y").expect("advance b");
        assert_eq!(
            authority.changes_since("a", seen).expect("watch"),
            None,
            "another name moving is not this name moving"
        );
    }
}
