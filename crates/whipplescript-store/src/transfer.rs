//! DR-0070 §4: the transfer seam, shaped like REAPI's CAS subset.
//!
//! Bazel's Remote Execution API already specifies this seam and has several
//! interoperable implementations, so the call *shapes* are copied rather than
//! invented: `FindMissingBlobs` is the want/have negotiation, `BatchReadBlobs`
//! amortizes round trips over small objects, and a streaming form handles large
//! ones. What is deliberately not adopted is REAPI itself — running a REAPI
//! server drags in the action-execution model this project does not want, and
//! inventing a different shape would be pure cost.
//!
//! The point of `find_missing` in particular: DR-0066 §7 says the protocol
//! speaks logical identities and lets the *server* choose physical grouping. A
//! want/have exchange is exactly that shape — the caller names what it needs,
//! the store answers what it lacks, and how those bytes are packed or fetched
//! stays the store's business.
//!
//! Written over [`ContentBlobs`], so it composes with anything implementing the
//! seam rather than binding to one host.

use crate::content::{BlobStatus, ContentBlobs};
use crate::StoreResult;

/// What a store lacks, and why.
///
/// Split rather than one list, because DR-0066 §5's distinction survives here
/// too: a caller can fetch what is *absent* from a peer, and no fetch will ever
/// produce what has been *erased*. Merging them would send a transfer loop
/// chasing bytes that are gone by policy.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MissingBlobs {
    /// Never seen here. Fetch these.
    pub absent: Vec<String>,
    /// Tombstoned by policy. No fetch will produce them; surface, do not retry.
    pub erased: Vec<String>,
}

impl MissingBlobs {
    /// Nothing to fetch and nothing to report.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.absent.is_empty() && self.erased.is_empty()
    }
}

/// One entry of a batch read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobRead {
    pub id: String,
    /// `None` when the store does not hold it — the batch does not fail as a
    /// whole, because a caller reading fifty blobs wants the forty-nine it can
    /// have plus an honest account of the one it cannot.
    pub body: Option<String>,
}

/// The want/have half of the seam.
///
/// # Errors
/// Propagates store failures.
pub fn find_missing<B: ContentBlobs + ?Sized>(
    blobs: &B,
    ids: &[String],
) -> StoreResult<MissingBlobs> {
    let mut missing = MissingBlobs::default();
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            continue; // A caller may name a blob twice; answer once.
        }
        match blobs.status(id)? {
            BlobStatus::Live { .. } => {}
            BlobStatus::Erased { .. } => missing.erased.push(id.clone()),
            BlobStatus::Unknown => missing.absent.push(id.clone()),
        }
    }
    Ok(missing)
}

/// The batch-read half. Order follows `ids`, deduplicated.
///
/// # Errors
/// Propagates store failures. A blob the store does not hold is a `None` body,
/// not an error.
pub fn batch_read<B: ContentBlobs + ?Sized>(
    blobs: &B,
    ids: &[String],
) -> StoreResult<Vec<BlobRead>> {
    let mut out = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(id.as_str()) {
            continue;
        }
        out.push(BlobRead {
            id: id.clone(),
            body: blobs.get(id)?,
        });
    }
    Ok(out)
}

/// What a peer must send for a cut to be servable here: the manifest tree's own
/// nodes plus every blob its leaves name, minus what this store already holds.
///
/// This is the operation a warm-up or a handoff actually wants, and it is why
/// the manifest is walked rather than the caller enumerating paths: the tree's
/// interior nodes are content too, and a transfer that shipped only leaf blobs
/// would leave the receiver unable to read its own manifest.
///
/// # Errors
/// Propagates store failures. A manifest root this store cannot read at all is
/// reported as a single absent id rather than an error, because "I need this
/// before I can tell you what else I need" is the honest answer to a want/have
/// exchange with a cold store.
pub fn missing_for_manifest<B: ContentBlobs + ?Sized>(
    blobs: &B,
    manifest_root: &str,
) -> StoreResult<MissingBlobs> {
    match blobs.status(manifest_root)? {
        BlobStatus::Unknown => {
            return Ok(MissingBlobs {
                absent: vec![manifest_root.to_owned()],
                erased: Vec::new(),
            })
        }
        BlobStatus::Erased { .. } => {
            return Ok(MissingBlobs {
                absent: Vec::new(),
                erased: vec![manifest_root.to_owned()],
            })
        }
        BlobStatus::Live { .. } => {}
    }
    let Some(body) = blobs.get(manifest_root)? else {
        return Ok(MissingBlobs {
            absent: vec![manifest_root.to_owned()],
            erased: Vec::new(),
        });
    };
    let ids: Vec<String> = if crate::manifest_tree::is_node(&body) {
        // NOT `manifest_tree::reachable_ids`, and the difference matters.
        //
        // That walk REFUSES an absent node, because it serves collection, where
        // an under-reported subtree becomes a wrong delete. Here the absent
        // nodes are the whole point of the question — a cold receiver is
        // *supposed* to be missing them — so the walk is tolerant and reports
        // what it could not follow instead of failing. Same traversal, opposite
        // posture toward absence, which is why it is a separate function rather
        // than a flag on one.
        return walk_for_transfer(blobs, manifest_root);
    } else {
        // A flat manifest written before DR-0070 §1: its entries are the whole
        // closure, and the manifest blob itself is already present.
        serde_json::from_str::<std::collections::BTreeMap<String, String>>(&body)?
            .into_values()
            .collect()
    };
    find_missing(blobs, &ids)
}

/// Walk a manifest tree for transfer: descend what is present, and report what
/// is not instead of refusing it.
///
/// A node that cannot be read stops the descent *there* — its children's ids
/// are unknown until the node itself arrives. So a cold receiver's first answer
/// is necessarily partial, and a transfer converges over a few rounds as nodes
/// land and reveal the next level. That is the honest shape of want/have
/// against a tree, and pretending otherwise would mean claiming to know ids the
/// receiver has no way to name yet.
fn walk_for_transfer<B: ContentBlobs + ?Sized>(blobs: &B, root: &str) -> StoreResult<MissingBlobs> {
    let mut missing = MissingBlobs::default();
    let mut leaf_ids = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_owned()];
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        match blobs.status(&id)? {
            BlobStatus::Unknown => {
                missing.absent.push(id);
                continue;
            }
            BlobStatus::Erased { .. } => {
                missing.erased.push(id);
                continue;
            }
            BlobStatus::Live { .. } => {}
        }
        let Some(body) = blobs.get(&id)? else {
            missing.absent.push(id);
            continue;
        };
        let Some(node) = crate::manifest_tree::parse_node(&body) else {
            // Present but not a node: the root of a flat manifest reached
            // through a tree edge, or a corrupt one. Either way it is here, so
            // it is not missing.
            continue;
        };
        if node.level == 0 {
            leaf_ids.extend(node.entries.into_iter().map(|(_, blob)| blob));
        } else {
            stack.extend(node.entries.into_iter().map(|(_, child)| child));
        }
    }
    let leaves = find_missing(blobs, &leaf_ids)?;
    missing.absent.extend(leaves.absent);
    missing.erased.extend(leaves.erased);
    missing.absent.sort();
    missing.absent.dedup();
    missing.erased.sort();
    missing.erased.dedup();
    Ok(missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct FakeBlobs {
        live: RefCell<BTreeMap<String, String>>,
        erased: RefCell<BTreeMap<String, u64>>,
    }

    impl ContentBlobs for FakeBlobs {
        /// `stable_hash_hex`, matching `ContentStore::put`. Said `sha256_hex`
        /// until 2026-08-25 — a 256-bit id where the real store mints 128.
        fn put(&self, body: &str) -> StoreResult<String> {
            let id = crate::stable_hash_hex(body);
            self.live.borrow_mut().insert(id.clone(), body.to_owned());
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
            if let Some(len) = self.erased.borrow().get(id) {
                return Ok(BlobStatus::Erased { byte_len: *len });
            }
            Ok(BlobStatus::Unknown)
        }
    }

    /// Same reason as `preflight`'s double: a transfer test is only as good as
    /// the store it transfers between.
    #[test]
    fn the_transfer_double_satisfies_the_content_contract() {
        crate::content::conformance::run_suite(FakeBlobs::default).expect("suite runs");
    }

    impl FakeBlobs {
        fn erase(&self, id: &str) {
            let len = self.live.borrow_mut().remove(id).map_or(0, |b| b.len());
            self.erased.borrow_mut().insert(id.to_owned(), len as u64);
        }
    }

    #[test]
    fn find_missing_splits_absent_from_erased() {
        let blobs = FakeBlobs::default();
        let here = blobs.put("present").expect("put");
        let gone = blobs.put("doomed").expect("put");
        blobs.erase(&gone);

        let missing = find_missing(
            &blobs,
            &[here.clone(), gone.clone(), "never-stored".to_owned()],
        )
        .expect("find_missing");

        assert_eq!(missing.absent, vec!["never-stored".to_owned()]);
        assert_eq!(missing.erased, vec![gone]);
        assert!(
            !missing.absent.contains(&here),
            "a blob we hold is not missing"
        );
    }

    /// Merging absent and erased would send a transfer loop chasing bytes that
    /// are gone by policy — the same distinction DR-0066 §5 exists for.
    #[test]
    fn an_erased_blob_is_never_offered_as_fetchable() {
        let blobs = FakeBlobs::default();
        let gone = blobs.put("doomed").expect("put");
        blobs.erase(&gone);
        let missing = find_missing(&blobs, std::slice::from_ref(&gone)).expect("find_missing");
        assert!(missing.absent.is_empty());
        assert_eq!(missing.erased, vec![gone]);
    }

    #[test]
    fn a_repeated_id_is_answered_once() {
        let blobs = FakeBlobs::default();
        let missing = find_missing(&blobs, &["x".to_owned(), "x".to_owned()]).expect("find");
        assert_eq!(missing.absent, vec!["x".to_owned()]);
    }

    /// A batch does not fail as a whole: a caller reading fifty blobs wants the
    /// forty-nine it can have plus an honest account of the one it cannot.
    #[test]
    fn batch_read_returns_holes_rather_than_failing() {
        let blobs = FakeBlobs::default();
        let here = blobs.put("present").expect("put");
        let reads = batch_read(&blobs, &[here.clone(), "absent".to_owned()]).expect("batch");
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0].body.as_deref(), Some("present"));
        assert_eq!(reads[1].body, None);
    }

    /// Want/have against a tree **converges over rounds**, and this is the test
    /// that says so.
    ///
    /// A first draft of this asserted that one call names everything a cold
    /// receiver needs. It cannot, and the reason is structural rather than a
    /// limitation: a node's children are unknowable until the node itself
    /// arrives, so the first answer names the root's children and nothing
    /// deeper. Claiming otherwise would mean naming ids the receiver has no way
    /// to know exist.
    ///
    /// What the protocol actually owes is convergence: each round strictly
    /// reduces what is missing, and it terminates with the receiver able to
    /// read the whole manifest.
    #[test]
    fn want_have_converges_over_rounds_and_ships_the_nodes_too() {
        let source = FakeBlobs::default();
        let manifest: BTreeMap<String, String> = (0..200)
            .map(|i| {
                let body = format!("body_{i}");
                let id = source.put(&body).expect("put");
                (format!("src/f_{i:04}.txt"), id)
            })
            .collect();
        let root = crate::manifest_tree::build(&source, &manifest).expect("tree builds");

        // A cold receiver that has been handed only the root node.
        let receiver = FakeBlobs::default();
        let root_body = source.get(&root).expect("get").expect("root exists");
        receiver.put(&root_body).expect("receiver takes the root");

        let mut rounds = 0;
        let mut shipped = 0usize;
        loop {
            let missing = missing_for_manifest(&receiver, &root).expect("missing computed");
            assert!(
                missing.erased.is_empty(),
                "nothing in this fixture was erased"
            );
            if missing.absent.is_empty() {
                break;
            }
            rounds += 1;
            assert!(rounds < 12, "want/have should converge, not loop");
            for id in &missing.absent {
                let body = source
                    .get(id)
                    .expect("source read")
                    .expect("the source holds everything");
                receiver.put(&body).expect("receiver stores");
                shipped += 1;
            }
        }

        assert!(
            rounds >= 2,
            "a tree deeper than one level cannot be named in a single round"
        );
        assert!(
            shipped > manifest.len(),
            "the receiver needed every leaf blob AND the interior nodes; \
             shipped {shipped} for a {}-entry manifest",
            manifest.len()
        );
        // The point of shipping the nodes: the receiver can now read its own
        // manifest, not merely hold the bytes the files are made of.
        assert_eq!(
            crate::manifest_tree::load(&receiver, &root).expect("receiver reads the manifest"),
            manifest
        );
    }

    #[test]
    fn a_warm_store_needs_nothing_for_a_manifest_it_holds() {
        let blobs = FakeBlobs::default();
        let manifest: BTreeMap<String, String> = (0..50)
            .map(|i| {
                let id = blobs.put(&format!("body_{i}")).expect("put");
                (format!("src/f_{i:04}.txt"), id)
            })
            .collect();
        let root = crate::manifest_tree::build(&blobs, &manifest).expect("tree builds");
        assert!(missing_for_manifest(&blobs, &root)
            .expect("missing computed")
            .is_empty());
    }

    /// "I need this before I can tell you what else I need" is the honest answer
    /// to a want/have exchange with a store that has nothing.
    #[test]
    fn an_unknown_manifest_root_asks_for_itself() {
        let blobs = FakeBlobs::default();
        let missing = missing_for_manifest(&blobs, "cold-root").expect("missing computed");
        assert_eq!(missing.absent, vec!["cold-root".to_owned()]);
    }

    /// Flat manifests written before the tree still negotiate.
    #[test]
    fn a_flat_manifest_still_negotiates() {
        let blobs = FakeBlobs::default();
        let flat: BTreeMap<String, String> =
            BTreeMap::from([("a".to_owned(), "missing-blob".to_owned())]);
        let root = blobs
            .put(&serde_json::to_string(&flat).expect("encodes"))
            .expect("put");
        let missing = missing_for_manifest(&blobs, &root).expect("missing computed");
        assert_eq!(missing.absent, vec!["missing-blob".to_owned()]);
    }
}
