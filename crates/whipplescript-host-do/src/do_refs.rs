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
    /// An in-memory object store, standing in for the platform bucket the
    /// deployment binds. The tier's contract is put/get/delete by key; where
    /// those bytes actually live is not this seam's business.
    #[derive(Default)]
    struct MemObjects {
        blobs: std::cell::RefCell<std::collections::HashMap<String, Vec<u8>>>,
    }

    impl crate::ObjectStore for MemObjects {
        fn put(&self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
            self.blobs
                .borrow_mut()
                .insert(key.to_owned(), bytes.to_vec());
            Ok(())
        }
        fn get(&self, key: &str) -> std::io::Result<Option<Vec<u8>>> {
            Ok(self.blobs.borrow().get(key).cloned())
        }
        fn delete(&self, key: &str) -> std::io::Result<()> {
            self.blobs.borrow_mut().remove(key);
            Ok(())
        }
        fn exists(&self, key: &str) -> bool {
            self.blobs.borrow().contains_key(key)
        }
    }

    /// The synchronous-store path, run against the shared suite.
    ///
    /// Deliberately NOT the durable object's deployed shape: that host records
    /// handles and cannot move bytes, so it declines the suite's byte property
    /// as it always has. This covers the configuration where a host genuinely
    /// can drive a synchronous object store — natively, and here — and proves
    /// the tier's own logic under the property rather than under our reading
    /// of it.
    #[test]
    fn a_synchronous_object_store_carries_the_suite_holding_bytes() {
        whipplescript_store::content::conformance::run_suite(|| {
            crate::do_branches::DoContentBlobs::with_external_bytes(
                RusqliteDoSql::in_memory(),
                Box::new(MemObjects::default()),
            )
            .expect("content blobs open")
        })
        .expect("suite runs");
    }

    /// The round trip the parity gap was about, spelled out: a picture goes in,
    /// the same picture comes out, and the tier it used is invisible.
    #[test]
    fn a_picture_round_trips_through_the_external_tier() {
        use whipplescript_store::content::{BlobStatus, ContentBlobs};
        let blobs = crate::do_branches::DoContentBlobs::with_external_bytes(
            RusqliteDoSql::in_memory(),
            Box::new(MemObjects::default()),
        )
        .expect("open");

        let picture: [u8; 12] = [
            0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d,
        ];
        let id = blobs.put(&picture).expect("a picture is storable now");
        assert_eq!(
            blobs.get(&id).expect("read").as_deref(),
            Some(&picture[..]),
            "byte-identical, or the id is a lie"
        );
        assert!(
            matches!(blobs.status(&id).expect("status"), BlobStatus::Live { byte_len } if byte_len == 12),
            "status and get must agree about a spilled blob"
        );

        // Text beside it still takes the inline tier and is unaffected.
        let text_id = blobs.put_text("prose").expect("text");
        assert_eq!(
            blobs.get(&text_id).expect("read").as_deref(),
            Some(&b"prose"[..])
        );
        assert_ne!(id, text_id);
    }

    /// Text too large for a SQLite value spills as well, so the tier boundary
    /// is about what a value can hold, not only about what decodes.
    #[test]
    fn text_past_the_threshold_spills_and_still_reads_as_text() {
        use whipplescript_store::content::{ContentBlobs, TextBlob};
        let mut blobs = crate::do_branches::DoContentBlobs::with_external_bytes(
            RusqliteDoSql::in_memory(),
            Box::new(MemObjects::default()),
        )
        .expect("open");
        blobs.set_threshold_bytes(64);

        let big = "prose ".repeat(200); // 1200 bytes, all of it text
        let id = blobs.put_text(&big).expect("stores");
        assert!(
            matches!(
                blobs.get_text(&id).expect("read"),
                TextBlob::Text(ref body) if *body == big
            ),
            "spilled text is still text on the way back"
        );
    }

    /// Erasure spans the tiers. Without this, whether a blob could be erased
    /// would depend on which side of the threshold it landed — and an id whose
    /// bytes are gone would answer *absent*, the substitution DR-0066 §5
    /// exists to refuse.
    #[test]
    fn erasing_a_spilled_blob_removes_the_bytes_and_says_erased() {
        use whipplescript_store::content::{BlobStatus, ContentBlobs, EraseOutcome};
        let objects = MemObjects::default();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let _ = &seen;
        let blobs = crate::do_branches::DoContentBlobs::with_external_bytes(
            RusqliteDoSql::in_memory(),
            Box::new(objects),
        )
        .expect("open");

        let picture: [u8; 6] = [0x89, b'P', b'N', b'G', 0xff, 0xfe];
        let id = blobs.put(&picture).expect("store");
        assert!(matches!(
            blobs.erase(&id, "2026-09-09T00:00:00Z").expect("erase"),
            EraseOutcome::Erased { byte_len: 6 }
        ));
        assert_eq!(blobs.get(&id).expect("read"), None, "the bytes are gone");
        assert!(
            matches!(
                blobs.status(&id).expect("status"),
                BlobStatus::Erased { byte_len: 6 }
            ),
            "erased, not absent — a caller must not retry forever for bytes by decision gone"
        );
        assert!(matches!(
            blobs.erase(&id, "2026-09-09T00:01:00Z").expect("retry"),
            EraseOutcome::AlreadyErased
        ));
    }

    /// This host stores text only, and the way it says so is the point.
    ///
    /// The handle path: this host records that content exists on the object
    /// plane and never sees a byte of it.
    ///
    /// A durable object's Rust is synchronous throughout — DO SQLite is, and
    /// there is no await point anywhere in the surface — while R2 is async
    /// only. So the isolate cannot fetch spilled bytes, and the three answers
    /// it gives have to stay distinguishable: present-but-unreachable, erased,
    /// and never-seen are three different facts and a caller acts differently
    /// on each.
    #[test]
    fn a_registered_handle_is_live_unreadable_here_and_erasable() {
        use whipplescript_store::content::{BlobStatus, ContentBlobs, EraseOutcome};
        let blobs =
            crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory()).expect("open");
        // The plane placed and verified these bytes; only the fact reaches us.
        let id = "89504e470d0a1a0a0000000d0000000d";
        blobs
            .register_external(id, 4096)
            .expect("register the handle");

        assert!(
            matches!(blobs.status(id).expect("status"), BlobStatus::Live { byte_len } if byte_len == 4096),
            "the content exists, and status is where that is said"
        );
        let error = blobs
            .get(id)
            .expect_err("this isolate cannot materialize what it did not move");
        let message = format!("{error:?}");
        assert!(
            message.contains("object plane") && message.contains("cannot materialize"),
            "the refusal says why and where to read it instead: {message}"
        );

        // Erasure is durable here and collected there.
        assert!(matches!(
            blobs.erase(id, "2026-09-10T00:00:00Z").expect("erase"),
            EraseOutcome::Erased { byte_len: 4096 }
        ));
        assert!(
            matches!(
                blobs.status(id).expect("status"),
                BlobStatus::Erased { byte_len: 4096 }
            ),
            "erased, not absent — the decision is durable before the bytes are gone"
        );
        assert_eq!(
            blobs.pending_external_deletes(16).expect("queue"),
            vec![id.to_owned()],
            "and the bytes are queued for the plane to collect"
        );

        blobs.external_delete_collected(id).expect("collected");
        assert!(blobs
            .pending_external_deletes(16)
            .expect("queue")
            .is_empty());
        assert!(
            matches!(blobs.status(id).expect("status"), BlobStatus::Erased { .. }),
            "collection does not un-erase it"
        );
    }

    /// Every shape a JS number can arrive in that is not a length.
    ///
    /// The wasm boundary passes numbers as `f64`, so this is the only place
    /// "whole and non-negative" is enforced — and a length that slipped through
    /// would register a handle claiming a size the bytes do not have, which
    /// `status` would then report as fact.
    #[test]
    fn a_byte_length_must_be_a_non_negative_whole_number() {
        use crate::do_branches::checked_byte_len;
        assert_eq!(checked_byte_len(0.0), Ok(0));
        assert_eq!(checked_byte_len(4096.0), Ok(4096));
        for bad in [
            -1.0,
            -0.5,
            0.5,
            4096.5,
            f64::NAN,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ] {
            assert!(checked_byte_len(bad).is_err(), "{bad} is not a byte length");
        }
    }

    /// An id that is not a content id would be a row no object could answer.
    #[test]
    fn a_handle_must_name_a_content_id() {
        let blobs =
            crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory()).expect("open");
        for bad in [
            "",
            "not-a-hash",
            &"0".repeat(31),
            &"0".repeat(33),
            &"A".repeat(32),
        ] {
            assert!(
                blobs.register_external(bad, 1).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(blobs.register_external(&"a1".repeat(16), 1).is_ok());
    }

    /// Absence still reads as absence. The handle path adds a third answer; it
    /// must not blur the two that were already there.
    #[test]
    fn an_unregistered_id_is_still_simply_absent() {
        use whipplescript_store::content::{BlobStatus, ContentBlobs};
        let blobs =
            crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory()).expect("open");
        assert_eq!(blobs.get(&"f".repeat(32)).expect("read"), None);
        assert!(matches!(
            blobs.status(&"f".repeat(32)).expect("status"),
            BlobStatus::Unknown
        ));
    }

    /// A store built without an external tier still refuses, and that is the
    /// remaining honest case rather than a leftover: `SqlValue` carries Null,
    /// Int and Text, so a host with no object store bound has genuinely
    /// nowhere to put bytes. The alternative was a lossy transcription of a
    /// picture under a hash that no longer describes it, which every later
    /// reader would then verify as correct.
    ///
    /// The refusal now names the way out, because there is one — see
    /// `with_an_external_tier_the_do_store_passes_the_suite_holding_bytes`.
    #[test]
    fn content_that_is_not_text_is_refused_rather_than_transcribed() {
        use whipplescript_store::content::ContentBlobs;
        let blobs = crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory())
            .expect("content blobs open");

        let picture: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x00];
        let error = blobs
            .put(&picture)
            .expect_err("this host cannot hold bytes that are not text");
        let message = format!("{error:?}");
        assert!(
            message.contains("text only") && message.contains("external byte tier"),
            "the refusal names what is missing and how to supply it: {message}"
        );

        // Text is unaffected, and round-trips as bytes through the same seam.
        let id = blobs.put_text("prose").expect("text is fine here");
        assert_eq!(
            blobs.get(&id).expect("read").as_deref(),
            Some(&b"prose"[..])
        );
    }

    #[test]
    fn do_content_blobs_passes_the_content_conformance_suite() {
        whipplescript_store::content::conformance::run_suite(|| {
            crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory())
                .expect("content blobs open")
        })
        .expect("suite runs");
    }

    #[test]
    fn do_authority_erasure_overrides_a_retaining_cache() {
        whipplescript_store::read_through::conformance::check(
            crate::do_branches::DoContentBlobs::new(RusqliteDoSql::in_memory())
                .expect("content blobs open"),
        );
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
        let id = hosted.put_text("bytes to drop").expect("stores");
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
        let id = blobs.put_text("bytes that will be erased").expect("put");

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
