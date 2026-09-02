//! DR-0069 on the durable-object host: the cloud half of the ref-authority
//! seam (native counterpart `whipplescript-store/src/ref_authority.rs`).
//!
//! This is where the design's central claim gets its cheapest possible
//! implementation. DR-0066 §2 needs exactly one authority per mutable name, and
//! a Durable Object *is* that: Cloudflare guarantees one active instance per
//! id and handles failover, so single-writer is a platform property rather than
//! something this code arranges. The compare-and-set below is not what makes
//! the authority single — it is what keeps a caller honest about what it
//! believed when it wrote.
//!
//! Parity is by reuse of the *contract*, not of the SQL: the trait, its
//! position-disclosure obligation, and its semantics are shared, while each
//! host runs its own statements against its own engine — the same posture
//! `do_branches` takes.

use whipplescript_store::ref_authority::{AdvanceOutcome, RefAuthority, RefRead};
use whipplescript_store::StoreResult;

use crate::do_store::{as_i64, as_opt_text, as_text, sql_err, text, DoSql};

pub struct DoRefAuthority<S: DoSql> {
    sql: S,
}

impl<S: DoSql> DoRefAuthority<S> {
    /// # Errors
    /// Propagates a failure creating the ref tables.
    pub fn new(sql: S) -> StoreResult<Self> {
        let store = Self { sql };
        store.ensure_schema()?;
        Ok(store)
    }

    fn ensure_schema(&self) -> StoreResult<()> {
        for statement in [
            "CREATE TABLE IF NOT EXISTS refs (
                 name TEXT PRIMARY KEY,
                 value TEXT NOT NULL,
                 position INTEGER NOT NULL
             )",
            "CREATE TABLE IF NOT EXISTS ref_position (
                 id INTEGER PRIMARY KEY CHECK (id = 0),
                 position INTEGER NOT NULL
             )",
            "INSERT OR IGNORE INTO ref_position (id, position) VALUES (0, 0)",
        ] {
            self.sql.execute(statement, &[]).map_err(sql_err)?;
        }
        Ok(())
    }

    fn position(&self) -> StoreResult<u64> {
        let rows = self
            .sql
            .query("SELECT position FROM ref_position WHERE id = 0", &[])
            .map_err(sql_err)?;
        let row = rows
            .first()
            .ok_or_else(|| sql_err("ref position row is missing".to_string()))?;
        Ok(as_i64(&row[0]) as u64)
    }

    fn current(&self, name: &str) -> StoreResult<Option<String>> {
        let rows = self
            .sql
            .query("SELECT value FROM refs WHERE name = ?1", &[text(name)])
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_text(&row[0])))
    }
}

impl<S: DoSql> RefAuthority for DoRefAuthority<S> {
    fn read(&self, name: &str) -> StoreResult<RefRead> {
        Ok(RefRead {
            value: self.current(name)?,
            position: self.position()?,
        })
    }

    fn advance(
        &mut self,
        name: &str,
        expected: Option<&str>,
        next: &str,
    ) -> StoreResult<AdvanceOutcome> {
        // No transaction, and that is not an oversight: the DO is single-writer
        // by platform guarantee, so the native store's transactions collapse to
        // a statement sequence here — the same posture the coordination and
        // branch parity impls take.
        let current = self.current(name)?;
        if current.as_deref() != expected {
            return Ok(AdvanceOutcome::Rejected {
                current,
                position: self.position()?,
            });
        }
        self.sql
            .execute(
                "UPDATE ref_position SET position = position + 1 WHERE id = 0",
                &[],
            )
            .map_err(sql_err)?;
        let position = self.position()?;
        self.sql
            .execute(
                "INSERT INTO refs (name, value, position) VALUES (?1, ?2, ?3) \
                 ON CONFLICT(name) DO UPDATE SET value = excluded.value, \
                 position = excluded.position",
                &[
                    text(name),
                    text(next),
                    crate::do_store::int(position as i64),
                ],
            )
            .map_err(sql_err)?;
        Ok(AdvanceOutcome::Advanced { position })
    }

    fn changes_since(&self, name: &str, position: u64) -> StoreResult<Option<RefRead>> {
        let rows = self
            .sql
            .query(
                "SELECT value, position FROM refs WHERE name = ?1",
                &[text(name)],
            )
            .map_err(sql_err)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let moved_at = as_i64(&row[1]) as u64;
        if moved_at <= position {
            return Ok(None);
        }
        Ok(Some(RefRead {
            value: as_opt_text(&row[0]),
            position: self.position()?,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::do_store::test_support::RusqliteDoSql;

    fn authority() -> DoRefAuthority<RusqliteDoSql> {
        DoRefAuthority::new(RusqliteDoSql::in_memory()).expect("authority opens")
    }

    /// The durable-object content store runs the same content conformance
    /// suite the native one and the cache layer run.
    ///
    /// It lives beside the ref tests rather than in `do_branches` only because
    /// that module has no test harness of its own; the suite it runs is the
    /// shared one either way.
    #[test]
    fn do_content_blobs_passes_the_content_conformance_suite() {
        whipplescript_store::content::conformance::run_suite(|| {
            crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory())
                .expect("content blobs open")
        })
        .expect("suite runs");
    }

    /// **DR-0071 §5 across the seam.** Both hosts must record the same erasure
    /// as the same chained entry, or the ledger is two ledgers.
    ///
    /// The digests are computed by `whipplescript_store::erasure_ledger` on
    /// both sides, so this asserts the two hosts *use* it identically — same
    /// order, same fields, same genesis — rather than each having its own
    /// almost-compatible encoding, which is how parity claims usually fail.
    #[test]
    fn an_erasure_chains_identically_on_both_hosts() {
        use whipplescript_store::content::{ContentBlobs, EraseOutcome};

        let hosted = crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory())
            .expect("content blobs open");
        let id = hosted.put("bytes to drop").expect("stores");
        assert!(matches!(
            hosted.erase(&id, "2026-08-30T00:00:00Z").expect("erases"),
            EraseOutcome::Erased { .. }
        ));

        // What the shared chain says the ledger head must be after exactly this
        // one erasure.
        let expected = whipplescript_store::erasure_ledger::fold(&[
            whipplescript_store::erasure_ledger::LedgerEntry {
                sequence: 1,
                id: &id,
                kind: whipplescript_store::erasure_ledger::ErasedKind::Blob,
                byte_len: "bytes to drop".len() as i64,
                erased_at: "2026-08-30T00:00:00Z",
            },
        ]);

        let digests = hosted.erasure_ledger_digests().expect("ledger reads");
        assert_eq!(digests.len(), 1, "the erasure must be recorded once");
        assert_eq!(
            digests[0], expected,
            "the hosted ledger head must be the digest the shared chain computes"
        );
    }

    /// DR-0068 §5 parity: this host must distinguish a LAPSED pin from an
    /// absent one too, or the refusal-on-lapse the model requires exists on one
    /// host and not the other.
    #[test]
    fn a_lapsed_pin_is_distinguishable_from_an_absent_one_on_this_host_too() {
        use whipplescript_store::branches::{Branches, ClosurePinState};

        let mut branches =
            crate::do_branches::DoBranches::new(RusqliteDoSql::in_memory()).expect("branches open");
        branches
            .pin_closure("cut_1", "run-a", "2026-08-24T12:00:00Z")
            .expect("pin");

        assert_eq!(
            branches
                .closure_pin_state("cut_1", "run-a", "2026-08-24T11:59:59Z")
                .expect("state"),
            ClosurePinState::Held {
                expires_at: "2026-08-24T12:00:00Z".to_owned()
            }
        );
        assert_eq!(
            branches
                .closure_pin_state("cut_1", "run-a", "2026-08-24T12:00:01Z")
                .expect("state"),
            ClosurePinState::Lapsed {
                expired_at: "2026-08-24T12:00:00Z".to_owned()
            }
        );
        branches.release_closure_pins("run-a").expect("release");
        assert_eq!(
            branches
                .closure_pin_state("cut_1", "run-a", "2026-08-24T11:59:59Z")
                .expect("state"),
            ClosurePinState::Absent
        );
    }

    #[test]
    fn a_do_head_reservation_blocks_advance_and_rebase_until_its_holder_releases() {
        use whipplescript_store::branches::{AdvanceOutcome, Branches, HeadReservationOutcome};

        let mut branches =
            crate::do_branches::DoBranches::new(RusqliteDoSql::in_memory()).expect("branches open");
        branches.ensure_mainline("t0").expect("mainline");
        assert_eq!(
            branches
                .reserve_head("main", "reservation-a", "t1")
                .expect("reserve"),
            HeadReservationOutcome::Reserved
        );

        for refusal in [
            branches.advance_head("main", None, "cut-a", "manifest-a", "t2"),
            branches.rebase_branch(
                "main",
                None,
                "point-a",
                "point-manifest-a",
                "cut-a",
                "manifest-a",
                "t2",
            ),
        ] {
            let Err(whipplescript_store::StoreError::Conflict(message)) = refusal else {
                panic!("reserved head mutation must be refused, got {refusal:?}");
            };
            assert!(message.contains("reserved by `reservation-a`"));
        }
        assert_eq!(
            branches
                .get_branch("main")
                .expect("main read")
                .expect("main")
                .head_cut_id,
            None
        );
        assert!(!branches
            .release_head_reservation("main", "reservation-b")
            .expect("wrong holder release"));
        assert!(branches
            .release_head_reservation("main", "reservation-a")
            .expect("holder release"));
        assert!(matches!(
            branches
                .advance_head("main", None, "cut-a", "manifest-a", "t3")
                .expect("advance after release"),
            AdvanceOutcome::Advanced(_)
        ));
    }

    fn head(
        instance: &str,
        sequence: i64,
        digest: &str,
    ) -> whipplescript_store::event_chain::LogHeads {
        let mut heads = whipplescript_store::event_chain::LogHeads::new();
        heads.insert(
            instance.to_owned(),
            whipplescript_store::event_chain::ChainHead {
                sequence: Some(sequence),
                digest: digest.to_owned(),
            },
        );
        heads
    }

    fn seeded_branches() -> crate::do_branches::DoBranches<RusqliteDoSql> {
        use whipplescript_store::branches::Branches;

        let mut branches =
            crate::do_branches::DoBranches::new(RusqliteDoSql::in_memory()).expect("branches open");
        branches.ensure_mainline("t0").expect("mainline");
        branches
            .record_cut(whipplescript_store::branches::CutRecord {
                cut_id: "cut_1",
                change_id: "cut_1",
                branch_id: whipplescript_store::branches::MAINLINE_BRANCH_ID,
                manifest_hash: "manifest_a",
                parent_cut_id: None,
                origin: None,
                actor: None,
                intent: None,
                recorded_at: "t1",
            })
            .expect("cut records");
        branches
    }

    /// Native parity for the unknown-cut refusal, which had no DO-side test at
    /// all: a mutation sweep of `do_branches.rs` reported it unexercised, and
    /// it was. The native half refuses at `branches.rs`; parity is the property
    /// the substrate records exist to hold, so it has to be observed on both
    /// hosts rather than inferred from shared code — `attach_cut_log_heads` is
    /// written separately here, against a different SQL surface.
    #[test]
    fn do_pinning_an_unknown_cut_is_refused() {
        use whipplescript_store::branches::Branches;

        let mut branches = seeded_branches();
        let refusal = branches.attach_cut_log_heads("cut_nope", &head("inst_a", 1, "d"));
        let Err(whipplescript_store::StoreError::Conflict(message)) = refusal else {
            panic!("pinning an unknown cut must be refused, got {refusal:?}");
        };
        assert!(
            message.contains("cut_nope") && message.contains("does not exist"),
            "the refusal must name the cut and say it does not exist, not merely \
             be some conflict: {message}"
        );
    }

    /// Native parity for the re-pin refusal, and for the same reason: nothing
    /// on this host distinguished "refused as a re-pin" from "refused as a
    /// concurrent pin". Those are different answers — on the native host,
    /// deleting the re-pin branch falls through to the `log_heads IS NULL`
    /// update and returns the concurrency refusal instead, which a wildcard
    /// assertion accepted as coverage.
    #[test]
    fn do_re_pinning_a_cut_is_refused() {
        use whipplescript_store::branches::Branches;

        let mut branches = seeded_branches();
        branches
            .attach_cut_log_heads("cut_1", &head("inst_a", 3, "digest_a"))
            .expect("first attach");

        let second = branches.attach_cut_log_heads("cut_1", &head("inst_a", 4, "digest_b"));
        let Err(whipplescript_store::StoreError::Conflict(message)) = second else {
            panic!("a re-pin must be refused, got {second:?}");
        };
        assert!(
            message.contains("already pinned"),
            "a re-pin must be refused *as a re-pin*, not as a concurrent pin: {message}"
        );
        assert_eq!(
            branches.cut_log_heads("cut_1").expect("heads read"),
            Some(head("inst_a", 3, "digest_a")),
            "the original pin must survive the refusal"
        );
    }

    /// DR-0066 §5 on this host, which had no erasure at all until 2026-08-25.
    ///
    /// The shared content suite already ran here and passed — by way of its
    /// `EraseOutcome::Unsupported` arm, which accepts a store that declines the
    /// obligation. So the suite could not tell "this host cannot erase" from
    /// "this host erases and forgets", and the distinguished answer §5 exists
    /// for was unavailable on the shipped cloud host. This test asserts the
    /// obligation directly rather than through an arm that permits declining.
    #[test]
    fn do_erased_is_not_absent() {
        use whipplescript_store::content::{BlobStatus, ContentBlobs, EraseOutcome};

        let blobs = crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory())
            .expect("content blobs open");
        let id = blobs.put("bytes that will be erased").expect("put");

        assert!(
            matches!(blobs.status(&id).expect("status"), BlobStatus::Live { .. }),
            "stored content reads as live before erasure"
        );

        let outcome = blobs.erase(&id, "2026-08-25T00:00:00Z").expect("erase");
        assert!(
            matches!(outcome, EraseOutcome::Erased { .. }),
            "this host must erase rather than answer Unsupported, got {outcome:?}"
        );

        // The distinction itself: erased content is NOT absent content.
        let erased = blobs.status(&id).expect("status after erasure");
        assert!(
            matches!(erased, BlobStatus::Erased { .. }),
            "erased content must read as erased, not as unknown — a caller told \
             `absent` retries forever for bytes that are gone: {erased:?}"
        );
        assert_eq!(blobs.get(&id).expect("get after erasure"), None);

        // And absence stays absence, or the distinction is only half made.
        assert!(matches!(
            blobs.status("never_stored").expect("status"),
            BlobStatus::Unknown
        ));

        // Idempotent retry: erasing again is AlreadyErased, never Unknown.
        assert!(matches!(
            blobs.erase(&id, "2026-08-25T00:00:01Z").expect("re-erase"),
            EraseOutcome::AlreadyErased
        ));
    }

    #[test]
    fn do_a_name_is_claimed_then_advanced() {
        let mut authority = authority();
        assert!(authority
            .advance("mainline", None, "cut_1")
            .expect("claim")
            .advanced());
        assert!(authority
            .advance("mainline", Some("cut_1"), "cut_2")
            .expect("advance")
            .advanced());
        assert_eq!(
            authority.read("mainline").expect("read").value,
            Some("cut_2".to_owned())
        );
    }

    /// Native parity for the multi-master refusal: the loser is told what the
    /// name actually holds, and has overwritten nothing.
    #[test]
    fn do_a_stale_expectation_is_rejected_and_told_what_is_there() {
        let mut authority = authority();
        authority.advance("mainline", None, "cut_1").expect("claim");
        authority
            .advance("mainline", Some("cut_1"), "cut_2")
            .expect("advance");

        let loser = authority
            .advance("mainline", Some("cut_1"), "cut_other")
            .expect("advance returns an outcome, not an error");
        assert!(matches!(
            loser,
            AdvanceOutcome::Rejected { ref current, .. } if current.as_deref() == Some("cut_2")
        ));
        assert_eq!(
            authority.read("mainline").expect("read").value,
            Some("cut_2".to_owned())
        );
    }

    #[test]
    fn do_claiming_an_already_set_name_is_rejected() {
        let mut authority = authority();
        authority.advance("mainline", None, "cut_1").expect("claim");
        assert!(!authority
            .advance("mainline", None, "cut_hostile")
            .expect("advance")
            .advanced());
    }

    #[test]
    fn do_a_rejected_advance_does_not_move_the_position() {
        let mut authority = authority();
        authority.advance("a", None, "x").expect("claim");
        let before = authority.read("a").expect("read").position;
        authority
            .advance("a", Some("wrong"), "y")
            .expect("advance returns an outcome");
        assert_eq!(authority.read("a").expect("read").position, before);
    }

    /// The durable-object host runs the **same** conformance driver the native
    /// host does (`ref_authority::conformance`), rather than its own mirrored
    /// assertions.
    ///
    /// This is what DR-0066's gaps section asked for. Parity established by
    /// whichever assertions someone happened to write for each side is
    /// coincidence; one driver called by both makes it a checked claim. It is
    /// also the reason the driver is not `#[cfg(test)]` in the defining crate —
    /// a conformance suite that cannot be run by an implementation in another
    /// crate is not a conformance suite.
    #[test]
    fn do_authority_passes_the_same_contention_suite_as_native() {
        whipplescript_store::ref_authority::conformance::run_suite(
            || DoRefAuthority::new(RusqliteDoSql::in_memory()).expect("authority opens"),
            0..64,
        )
        .expect("suite runs");
    }

    #[test]
    fn do_changes_since_coalesces_and_ignores_other_names() {
        let mut authority = authority();
        authority.advance("a", None, "x").expect("claim");
        let seen = authority.read("a").expect("read").position;
        assert_eq!(authority.changes_since("a", seen).expect("watch"), None);

        authority.advance("a", Some("x"), "y").expect("advance");
        authority.advance("a", Some("y"), "z").expect("advance");
        let change = authority
            .changes_since("a", seen)
            .expect("watch")
            .expect("the name moved");
        assert_eq!(change.value, Some("z".to_owned()));

        let after = authority.read("a").expect("read").position;
        authority.advance("b", None, "other").expect("advance b");
        assert_eq!(
            authority.changes_since("a", after).expect("watch"),
            None,
            "another name moving is not this name moving"
        );
    }
}
