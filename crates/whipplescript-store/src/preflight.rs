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
    // A manifest is a `manifest_tree` root (DR-0070 §1) or, for cuts written
    // before it, a flat map. This read parsed ONLY the flat map until
    // 2026-08-26, so against every manifest production has written since the
    // tree shipped it returned a serde error rather than an outcome: `invalid
    // type: integer 0, expected a string`, from the node's `level` field. The
    // one function whose job is to distinguish absent from erased could not
    // report either. Nothing caught it because nothing calls preflight yet, and
    // its own tests built flat fixtures by hand — a shape production stopped
    // writing.
    let manifest = match crate::manifest_tree::parse_node(&manifest_body) {
        Some(root) => match resolve_tree(blobs, root)? {
            TreeResolution::Resolved(manifest) => manifest,
            TreeResolution::Unreadable { blob_id, reason } => {
                return Ok(PreflightOutcome::ManifestUnavailable {
                    manifest_hash: blob_id,
                    reason,
                })
            }
        },
        None => serde_json::from_str(&manifest_body)?,
    };

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

/// What resolving a manifest tree found.
///
/// A named outcome rather than a nested `Result`, for the reason this whole
/// module exists: a blob that cannot be served **is not an error here, it is
/// the answer**. Written as `Result<_, (String, MissingReason)>` it read as a
/// failure to every reader, human and mechanical alike —
/// `scripts/check-new-refusals.sh` classified the three reporting sites as
/// refusals it could not measure, which was a fair reading of what the type
/// said.
enum TreeResolution {
    Resolved(std::collections::BTreeMap<String, String>),
    /// The closure is UNKNOWN, and this is the blob that made it so.
    Unreadable {
        blob_id: String,
        reason: MissingReason,
    },
}

/// Resolve a manifest tree to the flat map preflight checks, reporting an
/// unreadable node rather than failing on one.
///
/// Deliberately not [`crate::manifest_tree::load_from`], for two reasons that
/// are the whole point of this module. It answers an absent node with an
/// error, and an unreadable interior node is not an error here — it is the
/// outcome, "the closure is unknown", and the caller needs to know whether the
/// node was absent (retry) or erased (degrade honestly). And it does not tell
/// the caller WHICH node it could not read, which is the one thing an operator
/// needs to act.
///
/// # Errors
/// Propagates store failures, and refuses a node whose bytes do not hash to the
/// id they were fetched by.
fn resolve_tree<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: crate::manifest_tree::Node,
) -> StoreResult<TreeResolution> {
    let mut out = std::collections::BTreeMap::new();
    let mut pending: Vec<String> = Vec::new();
    let mut node = root;
    loop {
        if node.level == 0 {
            out.extend(node.entries);
        } else {
            pending.extend(node.entries.into_iter().map(|(_, child)| child));
        }
        let Some(id) = pending.pop() else {
            return Ok(TreeResolution::Resolved(out));
        };
        let body = match blobs.status(&id)? {
            BlobStatus::Live { .. } => blobs.get(&id)?,
            BlobStatus::Erased { byte_len } => {
                return Ok(TreeResolution::Unreadable {
                    blob_id: id,
                    reason: MissingReason::Erased { byte_len },
                })
            }
            BlobStatus::Unknown => {
                return Ok(TreeResolution::Unreadable {
                    blob_id: id,
                    reason: MissingReason::Absent,
                })
            }
        };
        // Live with no body is a store contradicting itself, exactly as at the
        // root above: absent, not an empty node, which would read as a smaller
        // closure than the run actually has.
        let Some(body) = body else {
            return Ok(TreeResolution::Unreadable {
                blob_id: id,
                reason: MissingReason::Absent,
            });
        };
        // Every interior node is part of the manifest, so the argument the root
        // check makes applies to all of them: a substituted node redefines a
        // whole subtree of the run's inputs, and every per-input check below
        // would then check the wrong things and pass.
        crate::content::verify_body(&id, &body, "manifest tree node")?;
        node = crate::manifest_tree::parse_node(&body).ok_or_else(|| {
            crate::StoreError::Conflict(format!(
                "manifest tree node `{id}` is not a node; the manifest is not the shape its \
                 root says it is"
            ))
        })?;
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

    /// The double stands in for a real content store, so it has to satisfy the
    /// contract it stands in for. Added 2026-08-25 by
    /// `scripts/check-conformance-coverage.sh`, which found this implementation
    /// running no suite — and it was minting `blob_{len}` ids at the time, so
    /// two distinct bodies of equal length shared one. Every test in this module
    /// was checking preflight against a store that was not content-addressed.
    #[test]
    fn the_preflight_double_satisfies_the_content_contract() {
        crate::content::conformance::run_suite(FakeBlobs::default).expect("suite runs");
    }

    /// The LEGACY flat manifest body — the shape cuts written before DR-0070
    /// §1 carry. Kept because those cuts are still readable, and used only by
    /// the test that says so.
    fn manifest_of(pairs: &[(&str, &str)]) -> String {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(path, id)| ((*path).to_owned(), (*id).to_owned()))
            .collect();
        serde_json::to_string(&map).expect("manifest encodes")
    }

    /// Store a manifest in the shape production actually writes — a
    /// `manifest_tree` root — and hand back its id.
    ///
    /// Every fixture here built the flat body by hand until 2026-08-26, which
    /// is why nothing noticed that `preflight_manifest` could not parse a tree.
    /// A fixture that constructs a format by hand can outlive the writer's
    /// agreement with it; one that goes through the writer cannot.
    fn put_tree_manifest<B: ContentBlobs + ?Sized>(blobs: &B, pairs: &[(&str, &str)]) -> String {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(path, id)| ((*path).to_owned(), (*id).to_owned()))
            .collect();
        crate::manifest_tree::build(blobs, &map).expect("manifest tree builds")
    }

    #[test]
    fn a_complete_closure_is_ready() {
        let blobs = FakeBlobs::default();
        blobs.put_at("b1", "one");
        blobs.put_at("b2", "two");
        let m = put_tree_manifest(&blobs, &[("a.txt", "b1"), ("b.txt", "b2")]);

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
        let m = put_tree_manifest(&blobs, &[("a.txt", "b1"), ("b.txt", "b2"), ("c.txt", "b3")]);

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
        let m = put_tree_manifest(&blobs, &[("a", "x"), ("b", "y"), ("c", "z")]);
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
        let manifest_id = crate::manifest_tree::build(
            &store,
            &BTreeMap::from([
                ("kept.txt".to_owned(), live),
                ("gone.txt".to_owned(), doomed.clone()),
                (
                    "never.txt".to_owned(),
                    "sha-that-was-never-stored".to_owned(),
                ),
            ]),
        )
        .expect("manifest tree builds");

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
        let m = put_tree_manifest(&blobs, &[]);
        assert_eq!(
            preflight_manifest(&blobs, &m).expect("preflight runs"),
            PreflightOutcome::Ready { checked: 0 }
        );
    }

    /// The remaining refusal in the tree walk: a child that is honest bytes but
    /// is not a node at all.
    ///
    /// It has to be its own test rather than a corollary of the substitution
    /// one, because verification fires FIRST — a smuggled body is caught by its
    /// hash long before anything asks whether it parses. Reaching this branch
    /// means a node that legitimately hashes to the id its parent names and is
    /// still not a node, which is a store that has been written to by something
    /// that does not share this format.
    ///
    /// Asserts on the message, because the sweep mutates a refusal by its text
    /// and a test that only checked "some error" would not notice it going
    /// quiet.
    #[test]
    fn a_child_that_is_not_a_node_is_refused_by_name() {
        let blobs = FakeBlobs::default();
        blobs.put_at("b1", "one");
        let leaf_root = put_tree_manifest(&blobs, &[("a.txt", "b1")]);
        let leaf_body = blobs.get(&leaf_root).expect("reads").expect("live");
        let leaf = crate::manifest_tree::parse_node(&leaf_body).expect("parses");

        // Honest bytes at an honest id — and not a node.
        let impostor = blobs.put("plainly not a manifest node").expect("stores");
        let parent = crate::manifest_tree::Node {
            tag: leaf.tag,
            level: 1,
            entries: vec![("zzz".to_owned(), impostor.clone())],
        };
        let parent_id = blobs
            .put(&serde_json::to_string(&parent).expect("encodes"))
            .expect("stores");

        let error =
            preflight_manifest(&blobs, &parent_id).expect_err("a non-node child is refused");
        let rendered = format!("{error:?}");
        assert!(
            rendered.contains(&impostor) && rendered.contains("is not a node"),
            "the refusal must name the blob and say what is wrong with it, got {rendered}"
        );
    }

    /// Cuts written before DR-0070 §1 carry a flat manifest body, and they are
    /// still readable — so the compatibility path is a claim this module makes
    /// and therefore a claim it has to hold to.
    #[test]
    fn a_legacy_flat_manifest_still_preflights() {
        let blobs = FakeBlobs::default();
        blobs.put_at("b1", "one");
        let m = blobs.put_manifest(&manifest_of(&[("a.txt", "b1")]));
        assert_eq!(
            preflight_manifest(&blobs, &m).expect("preflight runs"),
            PreflightOutcome::Ready { checked: 1 }
        );
    }

    /// Build a manifest big enough that its root has children, and hand back
    /// the root's child ids alongside it.
    ///
    /// The assertion is load-bearing: with too few entries `build` returns a
    /// single level-0 node, every test below would walk nothing, and they would
    /// pass while checking the interior-node path not at all.
    fn tree_with_interior_nodes(blobs: &FakeBlobs) -> (String, Vec<String>) {
        let pairs: Vec<(String, String)> = (0..240)
            .map(|index| (format!("file-{index:04}.txt"), format!("blob-{index:04}")))
            .collect();
        for (_, blob) in &pairs {
            blobs.put_at(blob, "body");
        }
        let map: BTreeMap<String, String> = pairs.into_iter().collect();
        let root_id = crate::manifest_tree::build(blobs, &map).expect("manifest tree builds");
        let root_body = blobs
            .get(&root_id)
            .expect("root reads")
            .expect("root is live");
        let root = crate::manifest_tree::parse_node(&root_body).expect("root parses as a node");
        assert!(
            root.level > 0,
            "the fixture must produce a root ABOVE level 0, or these tests walk no interior node"
        );
        let children = root.entries.into_iter().map(|(_, id)| id).collect();
        (root_id, children)
    }

    /// An unreadable interior node means the closure is UNKNOWN, which is the
    /// distinction this module exists to keep. It must not read as a smaller
    /// closure that happens to check out.
    #[test]
    fn an_erased_interior_node_is_an_unavailable_manifest_naming_that_node() {
        let blobs = FakeBlobs::default();
        let (root_id, children) = tree_with_interior_nodes(&blobs);
        let victim = children.first().expect("the root has children").clone();
        blobs.erase_at(&victim, 4096);

        assert_eq!(
            preflight_manifest(&blobs, &root_id).expect("preflight runs"),
            PreflightOutcome::ManifestUnavailable {
                manifest_hash: victim,
                reason: MissingReason::Erased { byte_len: 4096 },
            },
            "the outcome must name the node that could not be served, not the root — an \
             operator cannot act on `the manifest is unavailable`"
        );
    }

    #[test]
    fn an_absent_interior_node_reads_as_absent_not_as_a_shorter_closure() {
        let blobs = FakeBlobs::default();
        let (root_id, children) = tree_with_interior_nodes(&blobs);
        let victim = children.first().expect("the root has children").clone();
        blobs.live.borrow_mut().remove(&victim);

        assert_eq!(
            preflight_manifest(&blobs, &root_id).expect("preflight runs"),
            PreflightOutcome::ManifestUnavailable {
                manifest_hash: victim,
                reason: MissingReason::Absent,
            }
        );
    }

    /// DR-0066 §3 at every node, not only at the root. A substituted interior
    /// node redefines a whole subtree of the run's inputs, and every per-input
    /// check that followed would then be checking the wrong things and passing.
    #[test]
    fn a_substituted_interior_node_is_refused() {
        let blobs = FakeBlobs::default();
        let (root_id, children) = tree_with_interior_nodes(&blobs);
        let victim = children.first().expect("the root has children").clone();
        let honest = crate::manifest_tree::build(
            &blobs,
            &BTreeMap::from([("smuggled.txt".to_owned(), "blob-0000".to_owned())]),
        )
        .expect("the substitute builds");
        let substitute = blobs.get(&honest).expect("reads").expect("is live");
        blobs.put_at(&victim, &substitute);

        let error = preflight_manifest(&blobs, &root_id).expect_err("a lying node is refused");
        assert!(
            matches!(error, crate::StoreError::ContentMismatch { .. }),
            "expected a content mismatch, got {error:?}"
        );
    }
}
