//! DR-0068 §4: closure preflight — verify a pinned cut's inputs resolve
//! *before* doing work.
//!
//! A partially materialized run is worse than no run, because it produces a
//! result that looks like evidence. So a runner checks its whole closure up
//! front and refuses loudly, naming what was missing and — per DR-0066 §5 —
//! whether it was **absent** (not replicated here yet, a retry) or **erased**
//! (dropped by policy, an honesty downgrade the caller must surface). A remote
//! that returns the same answer for both is non-conforming, and a preflight
//! that collapsed them would throw away the distinction the store already
//! records.
//!
//! Host-agnostic: written against the [`ContentBlobs`] seam, so native and the
//! durable-object host share it rather than each growing their own.

use crate::content::{BlobStatus, ContentBlobs};
use crate::StoreResult;

/// Why one input of a closure could not be served.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MissingReason {
    /// The store has never seen this id. A cold cache, a lagging replica, or a
    /// genuinely lost blob — the caller retries or escalates.
    Absent,
    /// The payload was dropped by policy; identity and size are retained. No
    /// amount of retrying will produce it, so the caller must degrade honestly
    /// rather than wait.
    Erased { byte_len: u64 },
}

/// One input a runner needs and cannot have.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissingInput {
    /// The path in the manifest, so the refusal names something a human knows.
    pub path: String,
    pub blob_id: String,
    pub reason: MissingReason,
}

/// What a preflight found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreflightOutcome {
    /// Every input resolves. `checked` is how many, so a suspiciously small
    /// closure is visible rather than reading as success.
    Ready { checked: usize },
    /// The manifest itself could not be read, so the closure is unknown. This
    /// is distinct from an empty closure and must never read as "nothing to
    /// check".
    ManifestUnavailable {
        manifest_hash: String,
        reason: MissingReason,
    },
    /// Inputs are missing. Reported as a list rather than the first failure,
    /// because an operator fixing one at a time learns the extent slowly.
    Incomplete {
        checked: usize,
        missing: Vec<MissingInput>,
    },
}

impl PreflightOutcome {
    /// Whether a runner may start.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Check that every blob a manifest names can actually be served.
///
/// # Errors
/// Propagates store failures. A *missing* input is not an error — it is a
/// reported outcome, because the caller needs the whole list rather than the
/// first thing that went wrong.
pub fn preflight_manifest<B: ContentBlobs + ?Sized>(
    blobs: &B,
    manifest_hash: &str,
) -> StoreResult<PreflightOutcome> {
    let manifest_body = match blobs.status(manifest_hash)? {
        BlobStatus::Live { .. } => blobs.get(manifest_hash)?,
        BlobStatus::Erased { byte_len } => {
            return Ok(PreflightOutcome::ManifestUnavailable {
                manifest_hash: manifest_hash.to_owned(),
                reason: MissingReason::Erased { byte_len },
            })
        }
        BlobStatus::Unknown => {
            return Ok(PreflightOutcome::ManifestUnavailable {
                manifest_hash: manifest_hash.to_owned(),
                reason: MissingReason::Absent,
            })
        }
    };
    // A status of Live with no body is a store contradicting itself; treat it
    // as absent rather than as an empty manifest, which would read as success.
    let Some(manifest_body) = manifest_body else {
        return Ok(PreflightOutcome::ManifestUnavailable {
            manifest_hash: manifest_hash.to_owned(),
            reason: MissingReason::Absent,
        });
    };
    // DR-0066 §3, before the bytes are given any meaning. A closure derived
    // from an unverified manifest is a closure over whatever the store felt
    // like returning: every id below comes out of this parse, so one wrong
    // manifest silently redefines the whole run's inputs, and every per-input
    // check that follows would then be checking the wrong things and passing.
    crate::content::verify_body(manifest_hash, &manifest_body, "manifest")?;
    let manifest: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&manifest_body)?;

    let mut missing = Vec::new();
    let checked = manifest.len();
    for (path, blob_id) in manifest {
        match blobs.status(&blob_id)? {
            BlobStatus::Live { .. } => {}
            BlobStatus::Erased { byte_len } => missing.push(MissingInput {
                path,
                blob_id,
                reason: MissingReason::Erased { byte_len },
            }),
            BlobStatus::Unknown => missing.push(MissingInput {
                path,
                blob_id,
                reason: MissingReason::Absent,
            }),
        }
    }
    if missing.is_empty() {
        Ok(PreflightOutcome::Ready { checked })
    } else {
        Ok(PreflightOutcome::Incomplete { checked, missing })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// A blob seam whose contents and tombstones the test controls directly.
    #[derive(Default)]
    struct FakeBlobs {
        live: RefCell<BTreeMap<String, String>>,
        erased: RefCell<BTreeMap<String, u64>>,
    }

    impl FakeBlobs {
        /// Store a manifest under its REAL content id and hand it back.
        ///
        /// Needed once `preflight_manifest` verifies the manifest against the
        /// hash it was asked for (DR-0066 §3). Before that these tests named
        /// the manifest `"m"`, which no store could ever mint — the fixture was
        /// asserting on a manifest that could not exist.
        fn put_manifest(&self, body: &str) -> String {
            let id = crate::stable_hash_hex(body);
            self.put_at(&id, body);
            id
        }
        fn put_at(&self, id: &str, body: &str) {
            self.live
                .borrow_mut()
                .insert(id.to_owned(), body.to_owned());
        }
        fn erase_at(&self, id: &str, byte_len: u64) {
            self.live.borrow_mut().remove(id);
            self.erased.borrow_mut().insert(id.to_owned(), byte_len);
        }
    }

    impl ContentBlobs for FakeBlobs {
        /// Content-addressed, like the store it stands in for.
        ///
        /// This minted `format!("blob_{}", body.len())` until 2026-08-25, so
        /// two distinct bodies of equal length shared an id — a double that
        /// contradicted the one property the content plane is built on.
        fn put(&self, body: &str) -> StoreResult<String> {
            let id = crate::stable_hash_hex(body);
            self.put_at(&id, body);
            Ok(id)
        }
        fn get(&self, id: &str) -> StoreResult<Option<String>> {
            Ok(self.live.borrow().get(id).cloned())
        }
        fn status(&self, id: &str) -> StoreResult<BlobStatus> {
            if let Some(body) = self.live.borrow().get(id) {
                return Ok(BlobStatus::Live {
                    byte_len: body.len() as u64,
                });
            }
            if let Some(byte_len) = self.erased.borrow().get(id) {
                return Ok(BlobStatus::Erased {
                    byte_len: *byte_len,
                });
            }
            Ok(BlobStatus::Unknown)
        }
    }

    fn manifest_of(pairs: &[(&str, &str)]) -> String {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(path, id)| ((*path).to_owned(), (*id).to_owned()))
            .collect();
        serde_json::to_string(&map).expect("manifest encodes")
    }

    #[test]
    fn a_complete_closure_is_ready() {
        let blobs = FakeBlobs::default();
        blobs.put_at("b1", "one");
        blobs.put_at("b2", "two");
        let m = blobs.put_manifest(&manifest_of(&[("a.txt", "b1"), ("b.txt", "b2")]));

        assert_eq!(
            preflight_manifest(&blobs, &m).expect("preflight runs"),
            PreflightOutcome::Ready { checked: 2 }
        );
    }

    /// The distinction DR-0066 §5 exists for: absent is a retry, erased is not.
    /// Collapsing them makes a caller wait forever for bytes that are gone.
    #[test]
    fn absent_and_erased_are_reported_apart() {
        let blobs = FakeBlobs::default();
        blobs.put_at("b1", "one");
        blobs.erase_at("b2", 3);
        let m = blobs.put_manifest(&manifest_of(&[
            ("a.txt", "b1"),
            ("b.txt", "b2"),
            ("c.txt", "b3"),
        ]));

        let outcome = preflight_manifest(&blobs, &m).expect("preflight runs");
        let PreflightOutcome::Incomplete { checked, missing } = outcome else {
            panic!("expected an incomplete closure, got {outcome:?}");
        };
        assert_eq!(checked, 3);
        assert_eq!(missing.len(), 2);
        assert_eq!(
            missing[0],
            MissingInput {
                path: "b.txt".to_owned(),
                blob_id: "b2".to_owned(),
                reason: MissingReason::Erased { byte_len: 3 },
            }
        );
        assert_eq!(
            missing[1],
            MissingInput {
                path: "c.txt".to_owned(),
                blob_id: "b3".to_owned(),
                reason: MissingReason::Absent,
            }
        );
    }

    /// Every missing input is reported, not just the first: an operator fixing
    /// them one at a time learns the extent one round trip at a time.
    #[test]
    fn every_missing_input_is_named_not_only_the_first() {
        let blobs = FakeBlobs::default();
        let m = blobs.put_manifest(&manifest_of(&[("a", "x"), ("b", "y"), ("c", "z")]));
        let outcome = preflight_manifest(&blobs, &m).expect("preflight runs");
        let PreflightOutcome::Incomplete { missing, .. } = outcome else {
            panic!("expected an incomplete closure");
        };
        assert_eq!(missing.len(), 3);
    }

    /// An unreadable manifest means the closure is *unknown*, which must never
    /// read as an empty closure that trivially succeeds.
    #[test]
    fn an_unreadable_manifest_is_not_an_empty_closure() {
        let blobs = FakeBlobs::default();
        assert_eq!(
            preflight_manifest(&blobs, "gone").expect("preflight runs"),
            PreflightOutcome::ManifestUnavailable {
                manifest_hash: "gone".to_owned(),
                reason: MissingReason::Absent,
            }
        );

        blobs.erase_at("tombstoned", 12);
        assert_eq!(
            preflight_manifest(&blobs, "tombstoned").expect("preflight runs"),
            PreflightOutcome::ManifestUnavailable {
                manifest_hash: "tombstoned".to_owned(),
                reason: MissingReason::Erased { byte_len: 12 },
            }
        );
        assert!(!preflight_manifest(&blobs, "gone")
            .expect("preflight runs")
            .is_ready());
    }

    /// The fake above is a fake. This runs the same preflight against the REAL
    /// content store, so the absent/erased distinction is shown to survive
    /// end to end rather than only where the test controls the answers.
    ///
    /// It matters because that distinction is not something preflight invents —
    /// it reads it out of the `content_erasures` tombstone the store already
    /// keeps. If the store ever stopped recording erasure durably, this test
    /// fails and the fake-based ones would not notice.
    #[cfg(feature = "native")]
    #[test]
    fn the_real_store_reports_absent_and_erased_apart() {
        use crate::content::ContentStore;

        let dir = std::env::temp_dir().join(format!(
            "whip-preflight-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let store = ContentStore::open(dir.join("content.sqlite")).expect("content store opens");

        let live = store.put("kept").expect("live blob stores");
        let doomed = store.put("erased later").expect("doomed blob stores");
        let manifest = serde_json::to_string(&BTreeMap::from([
            ("kept.txt".to_owned(), live),
            ("gone.txt".to_owned(), doomed.clone()),
            (
                "never.txt".to_owned(),
                "sha-that-was-never-stored".to_owned(),
            ),
        ]))
        .expect("manifest encodes");
        let manifest_id = store.put(&manifest).expect("manifest stores");

        assert_eq!(
            preflight_manifest(&store, &manifest_id).expect("preflight runs"),
            PreflightOutcome::Incomplete {
                checked: 3,
                missing: vec![MissingInput {
                    path: "never.txt".to_owned(),
                    blob_id: "sha-that-was-never-stored".to_owned(),
                    reason: MissingReason::Absent,
                }],
            },
            "before erasure only the never-stored id is missing"
        );

        store
            .erase(&doomed, "2026-08-24T00:00:00Z")
            .expect("erasure records");

        let outcome = preflight_manifest(&store, &manifest_id).expect("preflight runs");
        let PreflightOutcome::Incomplete { checked, missing } = outcome else {
            panic!("expected an incomplete closure, got {outcome:?}");
        };
        assert_eq!(checked, 3);
        assert_eq!(missing.len(), 2);
        assert_eq!(missing[0].path, "gone.txt");
        assert!(
            matches!(missing[0].reason, MissingReason::Erased { .. }),
            "the erased blob must read as erased, not absent — a caller told \
             'absent' would retry forever for bytes that are gone"
        );
        assert_eq!(missing[1].reason, MissingReason::Absent);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A genuinely empty manifest is ready — and distinguishable from the
    /// unreadable case above, which is the whole point of separating them.
    #[test]
    fn a_genuinely_empty_manifest_is_ready() {
        let blobs = FakeBlobs::default();
        let m = blobs.put_manifest(&manifest_of(&[]));
        assert_eq!(
            preflight_manifest(&blobs, &m).expect("preflight runs"),
            PreflightOutcome::Ready { checked: 0 }
        );
    }
}
