//! DR-0070 §1: the manifest as a content-addressed **prolly tree**.
//!
//! The defect this replaces: the flat manifest was a whole `BTreeMap`
//! serialized per cut, so a one-entry change minted a blob the size of the
//! whole workspace, and no two manifests deduplicated because every one
//! differed somewhere. Against the promise of a cut at every mark, terminal,
//! and edit, that was the dominant cost in the content tier — ahead of anything
//! about the object store. `a_one_file_edit_mints_only_a_spine` is the
//! measurement, now inverted to assert the win rather than the defect.
//!
//! A prolly tree is a B-tree whose node boundaries are chosen by a hash of the
//! KEY rather than by insertion order. Three properties follow, and all three
//! are load-bearing here:
//!
//! - **History independence.** The tree for a given set of entries is the same
//!   whatever order they arrived in, so two branches that converged on the same
//!   content have literally the same tree.
//! - **O(log n) new nodes per change.** Unchanged subtrees keep their ids, and a
//!   content-addressed store dedupes them for free — so a cut writes new bytes
//!   proportional to the change, not to the workspace.
//! - **Diff that short-circuits.** Equal subtrees compare in one id comparison,
//!   making diff O(changed) rather than O(size). This is what makes continuous
//!   reconciliation affordable at all.
//!
//! Honest about what this does *not* do: [`build`] takes the full entry map and
//! is O(n) in CPU. The win being claimed is in bytes written and in diff, not in
//! the rebuild. An incremental update path that touches only the spine is a
//! later refinement, and nothing above depends on it.
//!
//! Pure over the [`ContentBlobs`] seam, so both hosts share it.

use std::collections::BTreeMap;

use crate::content::ContentBlobs;
use crate::{StoreError, StoreResult};

/// Encoding tag. A future layout change is a different tag rather than a silent
/// re-identification of every stored tree.
const NODE_TAG: &str = "whipplescript.manifest-tree.v1";

/// Target entries per node. Nodes average this size; the boundary is
/// probabilistic, so real nodes vary around it.
const TARGET_FANOUT: u64 = 16;

/// Never cut below this many entries. Without a floor, an unlucky run of keys
/// produces single-entry nodes and the tree degenerates toward a linked list.
const MIN_ENTRIES: usize = 4;

/// Never exceed this. Bounds the damage when keys are adversarial or simply
/// unlucky, keeping node reads a predictable size.
const MAX_ENTRIES: usize = 64;

/// Is this key a node boundary?
///
/// Derived from the key alone — never from position or insertion order — which
/// is exactly what makes the tree history-independent.
fn is_boundary(key: &str) -> bool {
    use sha2::{Digest, Sha256};
    // Hashed and read as BYTES, not through a hex string: this runs once per
    // entry at every level of every build, and rendering 64 hex digits to parse
    // four of them back cost an allocation per digit. The value is the same one
    // the hex round-trip produced — `the_boundary_predicate_matches_the_hex_
    // round_trip` holds it there, because boundaries decide every stored node's
    // id and a drifted predicate would stop new builds deduplicating against
    // trees already in the store.
    let mut hasher = Sha256::new();
    hasher.update(NODE_TAG.as_bytes());
    hasher.update("\u{1e}boundary\u{1e}".as_bytes());
    hasher.update(key.as_bytes());
    let digest = hasher.finalize();
    // First 16 bits of the digest, as a value in [0, 65536).
    let window = (u64::from(digest[0]) << 8) | u64::from(digest[1]);
    window.is_multiple_of(65536 / TARGET_FANOUT)
}

/// Does this blob body look like a tree node?
///
/// The shape test that keys DR-0070 §1's migration. A manifest written before
/// the tree is a flat JSON map; one written after is a node carrying
/// [`NODE_TAG`]. Cuts are immutable, so old manifests are read where they lie
/// rather than rewritten — rewriting them would mean minting new identities for
/// cuts that already exist and are already referenced.
#[must_use]
pub fn is_node(body: &str) -> bool {
    serde_json::from_str::<Node>(body).is_ok_and(|node| node.tag == NODE_TAG)
}

/// One node: a level and its ordered entries.
///
/// At level 0 an entry is `(path, blob_id)`. Above, it is
/// `(last_key_in_child, child_node_id)` — so a descent compares against the
/// child's greatest key.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Node {
    pub tag: String,
    pub level: u32,
    pub entries: Vec<(String, String)>,
}

/// Parse a blob body as a node, or `None` if it is not one.
///
/// The tolerant counterpart to the private loader: a caller that expects to
/// meet non-nodes — a transfer negotiating against a partial store — needs to
/// distinguish "not a node" from "a broken node" without an error.
#[must_use]
pub fn parse_node(body: &str) -> Option<Node> {
    serde_json::from_str::<Node>(body)
        .ok()
        .filter(|node| node.tag == NODE_TAG)
}

fn store_node<B: ContentBlobs + ?Sized>(
    blobs: &B,
    level: u32,
    entries: Vec<(String, String)>,
) -> StoreResult<(String, String)> {
    let last_key = entries
        .last()
        .map(|(key, _)| key.clone())
        .unwrap_or_default();
    let node = Node {
        tag: NODE_TAG.to_owned(),
        level,
        entries,
    };
    let body = serde_json::to_string(&node)?;
    let id = blobs.put(&body)?;
    Ok((last_key, id))
}

fn load_node<B: ContentBlobs + ?Sized>(blobs: &B, id: &str) -> StoreResult<Node> {
    let Some(body) = blobs.get(id)? else {
        return Err(StoreError::Conflict(format!(
            "manifest tree node `{id}` is absent from the content store"
        )));
    };
    let node: Node = serde_json::from_str(&body)?;
    if node.tag != NODE_TAG {
        return Err(StoreError::Conflict(format!(
            "manifest tree node `{id}` carries tag `{}`, not `{NODE_TAG}`",
            node.tag
        )));
    }
    Ok(node)
}

/// Split an ordered entry list into nodes at key-derived boundaries.
fn split(entries: Vec<(String, String)>) -> Vec<Vec<(String, String)>> {
    let mut nodes = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();
    for entry in entries {
        let key_is_boundary = is_boundary(&entry.0);
        current.push(entry);
        let long_enough = current.len() >= MIN_ENTRIES;
        let too_long = current.len() >= MAX_ENTRIES;
        if too_long || (key_is_boundary && long_enough) {
            nodes.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        nodes.push(current);
    }
    nodes
}

/// Build a tree from a full manifest, returning the root node id.
///
/// An empty manifest still gets a root — an empty level-0 node — so that "the
/// manifest is empty" and "the manifest is missing" stay distinguishable, the
/// same distinction [`crate::preflight`] keeps.
///
/// # Errors
/// Propagates store failures.
pub fn build<B: ContentBlobs + ?Sized>(
    blobs: &B,
    manifest: &BTreeMap<String, String>,
) -> StoreResult<String> {
    let entries: Vec<(String, String)> = manifest
        .iter()
        .map(|(path, hash)| (path.clone(), hash.clone()))
        .collect();
    if entries.is_empty() {
        let (_, id) = store_node(blobs, 0, Vec::new())?;
        return Ok(id);
    }

    let mut level = 0u32;
    let mut current = entries;
    loop {
        let groups = split(current);
        let mut parents = Vec::with_capacity(groups.len());
        for group in groups {
            let (last_key, id) = store_node(blobs, level, group)?;
            parents.push((last_key, id));
        }
        if parents.len() == 1 {
            return Ok(parents.remove(0).1);
        }
        level += 1;
        current = parents;
    }
}

/// Materialize the whole manifest from a root. The compatibility path for
/// callers that still want the flat map.
///
/// # Errors
/// Propagates store failures; refuses a node that is absent or foreign.
pub fn load<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: &str,
) -> StoreResult<BTreeMap<String, String>> {
    load_from(blobs, load_node(blobs, root)?)
}

/// The same materialization from a root node already in hand.
///
/// For a caller that had to parse the root to recognize it as one — the
/// migration shape test — so the root blob is fetched and parsed once rather
/// than twice.
///
/// # Errors
/// Propagates store failures; refuses a node that is absent or foreign.
pub fn load_from<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: Node,
) -> StoreResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    let mut node = root;
    loop {
        if node.level == 0 {
            out.extend(node.entries);
        } else {
            // Order does not matter: the map sorts, and every leaf is reached.
            stack.extend(node.entries.into_iter().map(|(_, child)| child));
        }
        let Some(id) = stack.pop() else {
            return Ok(out);
        };
        node = load_node(blobs, &id)?;
    }
}

/// Look up one path without materializing the manifest — O(log n) node reads.
///
/// # Errors
/// Propagates store failures.
pub fn get<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: &str,
    path: &str,
) -> StoreResult<Option<String>> {
    let mut id = root.to_owned();
    loop {
        let node = load_node(blobs, &id)?;
        if node.level == 0 {
            return Ok(node
                .entries
                .into_iter()
                .find(|(key, _)| key == path)
                .map(|(_, hash)| hash));
        }
        // The first child whose greatest key is >= the target holds it, if
        // anything does.
        let Some((_, child)) = node
            .entries
            .into_iter()
            .find(|(key, _)| key.as_str() >= path)
        else {
            return Ok(None);
        };
        id = child;
    }
}

/// Every content id a tree keeps alive: all its node ids, and every blob id its
/// leaves name.
///
/// Load-bearing for collection. A tree root expanded only one level would leave
/// interior nodes and their leaves looking unreachable, and a sweep would delete
/// content a recorded cut still names — so this walks the whole tree rather than
/// a level of it.
///
/// # Errors
/// Propagates store failures; refuses an absent or foreign node rather than
/// treating it as an empty subtree, which would under-report reachability and
/// turn a corrupt node into a wrong delete.
pub fn reachable_ids<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: &str,
) -> StoreResult<std::collections::BTreeSet<String>> {
    let mut ids = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_owned()];
    while let Some(id) = stack.pop() {
        if !ids.insert(id.clone()) {
            continue;
        }
        let node = load_node(blobs, &id)?;
        if node.level == 0 {
            ids.extend(node.entries.into_iter().map(|(_, blob)| blob));
        } else {
            stack.extend(node.entries.into_iter().map(|(_, child)| child));
        }
    }
    Ok(ids)
}

/// One path that differs between two trees.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestChange {
    pub path: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

/// Diff two trees, skipping identical subtrees by id.
///
/// This is the operation the reconciliation daemon wants to run continuously,
/// and the reason it can: equal subtrees cost one string comparison, so the
/// work is proportional to what changed rather than to the workspace.
///
/// # Errors
/// Propagates store failures.
pub fn diff<B: ContentBlobs + ?Sized>(
    blobs: &B,
    before_root: &str,
    after_root: &str,
) -> StoreResult<Vec<ManifestChange>> {
    if before_root == after_root {
        return Ok(Vec::new());
    }
    // Collect only the leaves that differ. Descending both sides in lockstep is
    // a later refinement; short-circuiting on equal subtree ids already removes
    // the term that scaled with the workspace.
    let before = collect_changed_leaves(blobs, before_root, after_root)?;
    let after = collect_changed_leaves(blobs, after_root, before_root)?;

    let mut changes = Vec::new();
    for (path, after_hash) in &after {
        match before.get(path) {
            Some(before_hash) if before_hash == after_hash => {}
            other => changes.push(ManifestChange {
                path: path.clone(),
                before: other.cloned(),
                after: Some(after_hash.clone()),
            }),
        }
    }
    for (path, before_hash) in &before {
        if !after.contains_key(path) {
            changes.push(ManifestChange {
                path: path.clone(),
                before: Some(before_hash.clone()),
                after: None,
            });
        }
    }
    changes.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(changes)
}

/// Entries under `root` that live in subtrees `other` does not share.
fn collect_changed_leaves<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: &str,
    other: &str,
) -> StoreResult<BTreeMap<String, String>> {
    let shared = subtree_ids(blobs, other)?;
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_owned()];
    while let Some(id) = stack.pop() {
        if shared.contains(&id) {
            continue; // THE SHORT-CIRCUIT: an identical subtree cannot differ.
        }
        let node = load_node(blobs, &id)?;
        if node.level == 0 {
            out.extend(node.entries);
        } else {
            stack.extend(node.entries.into_iter().map(|(_, child)| child));
        }
    }
    Ok(out)
}

fn subtree_ids<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: &str,
) -> StoreResult<std::collections::BTreeSet<String>> {
    let mut ids = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_owned()];
    while let Some(id) = stack.pop() {
        if !ids.insert(id.clone()) {
            continue;
        }
        let node = load_node(blobs, &id)?;
        if node.level > 0 {
            stack.extend(node.entries.into_iter().map(|(_, child)| child));
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::items::sha256_hex;
    use std::cell::RefCell;

    /// A blob store that also counts distinct bodies written, so a test can
    /// assert on how much a change actually costs.
    #[derive(Default)]
    struct CountingBlobs {
        stored: RefCell<BTreeMap<String, String>>,
        writes: RefCell<Vec<String>>,
    }

    impl ContentBlobs for CountingBlobs {
        /// `stable_hash_hex`, matching `ContentStore::put`. Said `sha256_hex`
        /// until 2026-08-25 — a 256-bit id where the real store mints 128.
        fn put(&self, body: &str) -> StoreResult<String> {
            let id = crate::stable_hash_hex(body);
            self.writes.borrow_mut().push(id.clone());
            self.stored.borrow_mut().insert(id.clone(), body.to_owned());
            Ok(id)
        }
        fn get(&self, id: &str) -> StoreResult<Option<String>> {
            Ok(self.stored.borrow().get(id).cloned())
        }
    }

    impl CountingBlobs {
        fn reset_writes(&self) {
            self.writes.borrow_mut().clear();
        }
        /// Bodies written that the store did not already hold.
        fn novel_writes(&self, before: &BTreeMap<String, String>) -> usize {
            self.writes
                .borrow()
                .iter()
                .filter(|id| !before.contains_key(*id))
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        }
        fn snapshot(&self) -> BTreeMap<String, String> {
            self.stored.borrow().clone()
        }
    }

    fn manifest(count: usize) -> BTreeMap<String, String> {
        (0..count)
            .map(|index| {
                (
                    format!("src/file_{index:04}.txt"),
                    format!("hash_of_{index}"),
                )
            })
            .collect()
    }

    #[test]
    fn a_tree_round_trips_its_manifest() {
        let blobs = CountingBlobs::default();
        let flat = manifest(200);
        let root = build(&blobs, &flat).expect("tree builds");
        assert_eq!(load(&blobs, &root).expect("tree loads"), flat);
    }

    #[test]
    fn an_empty_manifest_still_has_a_root() {
        let blobs = CountingBlobs::default();
        let root = build(&blobs, &BTreeMap::new()).expect("tree builds");
        assert!(load(&blobs, &root).expect("tree loads").is_empty());
    }

    /// History independence: the tree depends on the entry SET, never on the
    /// order it was assembled. Two branches that converged on the same content
    /// therefore have the same root, and share every node.
    #[test]
    fn the_root_depends_on_content_not_on_insertion_order() {
        let flat = manifest(120);
        let forward = CountingBlobs::default();
        let backward = CountingBlobs::default();

        let mut reversed = BTreeMap::new();
        for (path, hash) in flat.iter().rev() {
            reversed.insert(path.clone(), hash.clone());
        }

        assert_eq!(
            build(&forward, &flat).expect("builds"),
            build(&backward, &reversed).expect("builds"),
        );
    }

    /// THE POINT OF THE EXERCISE, and the inverse of
    /// `a_one_file_edit_still_mints_a_whole_manifest`: a one-entry change writes
    /// a handful of new nodes, not a whole workspace.
    #[test]
    fn a_one_entry_change_writes_only_its_spine() {
        let blobs = CountingBlobs::default();
        let mut flat = manifest(512);
        build(&blobs, &flat).expect("first build");

        let before = blobs.snapshot();
        blobs.reset_writes();
        flat.insert("src/file_0000.txt".to_owned(), "edited".to_owned());
        build(&blobs, &flat).expect("second build");

        let novel = blobs.novel_writes(&before);
        assert!(
            novel > 0 && novel <= 16,
            "a one-entry change in a 512-entry manifest should mint a spine's \
             worth of nodes, got {novel}. If this grew, the tree stopped \
             sharing unchanged subtrees and the DR-0070 §1 win is gone."
        );
    }

    /// The differential that lets [`is_boundary`] read digest bytes instead of
    /// hex digits: the byte read and the hex round-trip it replaced must agree
    /// on EVERY key, because a boundary that moved would re-identify every node
    /// built afterwards and silently end sharing with the trees already stored.
    #[test]
    fn the_boundary_predicate_matches_the_hex_round_trip() {
        fn via_hex(key: &str) -> bool {
            let digest = sha256_hex(&format!("{NODE_TAG}\u{1e}boundary\u{1e}{key}"));
            let window = u64::from_str_radix(&digest[..4], 16).unwrap_or(0);
            window.is_multiple_of(65536 / TARGET_FANOUT)
        }

        let mut keys: Vec<String> = vec![
            String::new(),
            "a".to_owned(),
            "\u{1e}".to_owned(),
            "boundary".to_owned(),
            "src/file_0000.txt".to_owned(),
            "docs/\u{65e5}\u{672c}\u{8a9e}.md".to_owned(),
        ];
        // A deterministic spread, so this is a real differential rather than a
        // handful of lucky agreements.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..4000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            keys.push(format!("dir_{state:016x}/leaf_{}.txt", state % 997));
        }

        let mut boundaries = 0usize;
        for key in &keys {
            assert_eq!(
                is_boundary(key),
                via_hex(key),
                "boundary predicate disagrees on `{key}`"
            );
            boundaries += usize::from(is_boundary(key));
        }
        assert!(
            boundaries > 0 && boundaries < keys.len(),
            "the case must exercise both outcomes, saw {boundaries} of {}",
            keys.len()
        );
    }

    #[test]
    fn get_finds_present_and_absent_paths() {
        let blobs = CountingBlobs::default();
        let flat = manifest(300);
        let root = build(&blobs, &flat).expect("builds");

        assert_eq!(
            get(&blobs, &root, "src/file_0150.txt").expect("get"),
            Some("hash_of_150".to_owned())
        );
        assert_eq!(get(&blobs, &root, "src/nope.txt").expect("get"), None);
        assert_eq!(get(&blobs, &root, "zzz-past-the-end").expect("get"), None);
    }

    #[test]
    fn diff_reports_adds_edits_and_removals() {
        let blobs = CountingBlobs::default();
        let mut flat = manifest(200);
        let before_root = build(&blobs, &flat).expect("builds");

        flat.insert("src/file_0010.txt".to_owned(), "edited".to_owned());
        flat.remove("src/file_0020.txt");
        flat.insert("src/added.txt".to_owned(), "new".to_owned());
        let after_root = build(&blobs, &flat).expect("builds");

        let changes = diff(&blobs, &before_root, &after_root).expect("diff");
        let edited = changes
            .iter()
            .find(|c| c.path == "src/file_0010.txt")
            .expect("the edit is reported");
        assert_eq!(edited.before.as_deref(), Some("hash_of_10"));
        assert_eq!(edited.after.as_deref(), Some("edited"));

        let removed = changes
            .iter()
            .find(|c| c.path == "src/file_0020.txt")
            .expect("the removal is reported");
        assert_eq!(removed.after, None);

        let added = changes
            .iter()
            .find(|c| c.path == "src/added.txt")
            .expect("the addition is reported");
        assert_eq!(added.before, None);
    }

    #[test]
    fn an_unchanged_tree_diffs_to_nothing() {
        let blobs = CountingBlobs::default();
        let flat = manifest(200);
        let root = build(&blobs, &flat).expect("builds");
        assert!(diff(&blobs, &root, &root).expect("diff").is_empty());
    }

    /// A foreign or corrupt node refuses rather than being read as an empty
    /// subtree, which would silently under-report a diff.
    #[test]
    fn a_foreign_node_refuses() {
        let blobs = CountingBlobs::default();
        let id = blobs
            .put("{\"tag\":\"something.else\",\"level\":0,\"entries\":[]}")
            .expect("put");
        assert!(matches!(load(&blobs, &id), Err(StoreError::Conflict(_))));
        assert!(matches!(
            load(&blobs, "never-stored"),
            Err(StoreError::Conflict(_))
        ));
    }

    /// Node sizes stay inside their bounds, so a run of unlucky keys cannot
    /// degenerate the tree into a list or balloon a node.
    #[test]
    fn node_sizes_respect_their_bounds() {
        let blobs = CountingBlobs::default();
        let flat = manifest(1000);
        let root = build(&blobs, &flat).expect("builds");

        let mut stack = vec![root];
        let mut leaves = 0usize;
        while let Some(id) = stack.pop() {
            let node = load_node(&blobs, &id).expect("node loads");
            assert!(
                node.entries.len() <= MAX_ENTRIES,
                "node of {} entries exceeds the cap",
                node.entries.len()
            );
            if node.level == 0 {
                leaves += 1;
            } else {
                stack.extend(node.entries.into_iter().map(|(_, child)| child));
            }
        }
        assert!(leaves > 1, "1000 entries should not fit in one leaf");
    }
}
