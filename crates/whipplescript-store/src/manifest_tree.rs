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

/// Encoding tag. A layout change is a different tag rather than a silent
/// re-identification of every stored tree.
///
/// v2 (2026-08-26) corrects the boundary rate — see [`is_boundary`]. The node
/// ENCODING is unchanged, so v1 trees stay readable exactly as they are; what
/// differs is where a build cuts, and therefore what a rebuilt manifest is
/// called. A v1 tree that gets written through migrates to v2 by being rebuilt.
const NODE_TAG: &str = "whipplescript.manifest-tree.v2";

/// Tags this reader still accepts. Nothing rewrites a stored tree, so every
/// manifest written before the boundary correction is read where it lies.
const LEGACY_NODE_TAGS: [&str; 1] = ["whipplescript.manifest-tree.v1"];

/// Is this a manifest tree node of any version this reader understands?
fn is_known_tag(tag: &str) -> bool {
    tag == NODE_TAG || LEGACY_NODE_TAGS.contains(&tag)
}

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
    // One key in `TARGET_FANOUT` is a boundary.
    //
    // This read `is_multiple_of(65536 / TARGET_FANOUT)` until 2026-08-26, which
    // is the same arithmetic upside down: it made one key in 4096 a boundary,
    // not one in 16. Measured, the rate was 1 in 3,922 and the mean leaf held
    // 63.3 entries against a `MAX_ENTRIES` of 64 — so every cut in every stored
    // manifest was the SIZE CAP, and the content-defined boundary this
    // structure is chosen for decided nothing.
    //
    // What that cost, beyond node size: `MAX_ENTRIES` cuts at a running count,
    // so inserting or removing one path re-cut every node after it. The tree
    // was not incrementally updatable (DR-0066 §8 refusal 2) and two trees
    // differing by one added file shared almost no subtrees, which is the
    // short-circuit DR-0070 §1 calls "what makes continuous reconciliation
    // affordable at all".
    //
    // Both existing checks passed throughout: `node_sizes_respect_their_bounds`
    // asks only that sizes fall between the floor and the cap, and 64 does; and
    // `a_one_entry_change_writes_only_its_spine` edits a VALUE, which cannot
    // move a boundary under either rate.
    window.is_multiple_of(TARGET_FANOUT)
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
    serde_json::from_str::<Node>(body).is_ok_and(|node| is_known_tag(&node.tag))
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
        .filter(|node| is_known_tag(&node.tag))
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
    // DR-0066 §3, at every node rather than only at the root. An interior node
    // names a whole subtree, so a substituted one silently redefines that much
    // of the manifest — and this walker cannot know whether the `blobs` it was
    // handed verifies (the read-through cache does; a bare store does not).
    // Cheap relative to the parse that follows: a node holds ~16 entries.
    crate::content::verify_body(id, &body, "manifest tree node")?;
    let node: Node = serde_json::from_str(&body)?;
    if !is_known_tag(&node.tag) {
        return Err(StoreError::Conflict(format!(
            "manifest tree node `{id}` carries tag `{}`, not `{NODE_TAG}`",
            node.tag
        )));
    }
    Ok(node)
}

/// An ordered run of `(key, id)` entries: a node's contents, or a run of them
/// on its way to becoming one.
///
/// At level 0 a key is a path and an id is a blob; above, a key is a child's
/// greatest key and an id is that child.
type Group = Vec<(String, String)>;

/// Split an ordered entry list into nodes at key-derived boundaries, keeping
/// the trailing run that never reached a cut separate.
///
/// The separation is what makes an incremental update possible. Cutting is a
/// left-to-right scan whose state resets to empty at every cut, so a node's
/// range always *starts* from empty state — which means re-splitting one node's
/// entries in isolation reproduces exactly the cuts a whole-tree rebuild would
/// make, PROVIDED the range still ends at a cut. A non-empty carry says it does
/// not: the boundary moved past this node's end and the change ripples into its
/// right sibling. [`apply`] treats that as the signal to fall back.
fn split_with_carry(entries: Group) -> (Vec<Group>, Group) {
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
    (nodes, current)
}

/// Split an ordered entry list into nodes at key-derived boundaries.
///
/// Defined in terms of [`split_with_carry`] rather than beside it, so the two
/// cannot drift: a whole rebuild is exactly the incremental scan with its
/// trailing run kept as the final node.
fn split(entries: Group) -> Vec<Group> {
    let (mut nodes, carry) = split_with_carry(entries);
    if !carry.is_empty() {
        nodes.push(carry);
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

/// Apply a batch of path changes to a tree, re-minting only the spine they
/// touch. `Some(id)` sets a path, `None` removes it.
///
/// **DR-0066 §8 refusal 2**: nothing O(workspace) where its effect is O(change).
/// [`build`] takes the whole entry map, so every write through it cost the
/// workspace no matter how little moved — a one-file edit rebuilt every node.
/// This descends to the paths that changed and re-mints their nodes and the
/// spine above them.
///
/// **The result is byte-identical to [`build`] over the resulting entry set.**
/// That is not a nicety: the manifest root is what an import compares to decide
/// `AlreadyPresent` from `DivergentBranch`, so two stores that disagreed about
/// the tree for identical content would refuse each other's idempotent imports
/// as conflicts. `apply_agrees_with_a_full_rebuild` asserts the root ids match,
/// not merely the entries.
///
/// Why a fallback exists. Cut positions depend on a running count since the
/// last cut (`MIN_ENTRIES`), not on keys alone, so adding or removing a key can
/// push a boundary past the end of the node that holds it. Where that happens
/// the update is not local and this rebuilds instead — correct either way, and
/// the rare case rather than the common one, because a value-only edit cannot
/// move a boundary at all and an insert usually meets the same boundary key
/// with the count still above the floor.
///
/// # Errors
/// Propagates store failures; refuses a node that is absent or foreign.
pub fn apply<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: &str,
    changes: &BTreeMap<String, Option<String>>,
) -> StoreResult<String> {
    if changes.is_empty() {
        return Ok(root.to_owned());
    }
    let ordered: Vec<(String, Option<String>)> = changes
        .iter()
        .map(|(path, value)| (path.clone(), value.clone()))
        .collect();

    if let Some(id) = apply_locally(blobs, root, &ordered)? {
        return Ok(id);
    }

    // Not locally updatable here. Rebuilding is the same answer, paid for.
    let mut manifest = load(blobs, root)?;
    for (path, value) in changes {
        match value {
            Some(id) => {
                manifest.insert(path.clone(), id.clone());
            }
            None => {
                manifest.remove(path);
            }
        }
    }
    build(blobs, &manifest)
}

/// The incremental half of [`apply`], separated so a test can ask how often it
/// carries the work — a fallback that quietly took every call would leave the
/// refusal violated with every test still green.
///
/// `None` means the change ripples past a node's end and only a whole rebuild
/// is correct.
///
/// # Errors
/// Propagates store failures; refuses a node that is absent or foreign.
fn apply_locally<B: ContentBlobs + ?Sized>(
    blobs: &B,
    root: &str,
    ordered: &[(String, Option<String>)],
) -> StoreResult<Option<String>> {
    let root_node = load_node(blobs, root)?;
    let root_level = root_node.level;
    if let Some(entries) = rebuild_range(blobs, root_node, ordered, true)? {
        if entries.is_empty() {
            // Everything was removed. An empty manifest still gets a root, so
            // "empty" and "missing" stay distinguishable — same as `build`.
            let (_, id) = store_node(blobs, 0, Vec::new())?;
            return Ok(Some(id));
        }
        // Grow levels above exactly as `build` does: entries already stored at
        // `root_level` are the input to the level above it.
        let mut current = entries;
        let mut level = root_level;
        loop {
            if current.len() == 1 {
                return Ok(Some(current.remove(0).1));
            }
            level += 1;
            let groups = split(current);
            let mut parents = Vec::with_capacity(groups.len());
            for group in groups {
                parents.push(store_node(blobs, level, group)?);
            }
            current = parents;
        }
    }
    Ok(None)
}

/// Rebuild one node's key range under `changes`, returning the entries that
/// range now contributes to its parent — or `None` if the rebuild would ripple
/// past the range's end, where only a whole rebuild is correct.
///
/// `is_rightmost` marks the range that runs to the end of the manifest. Only
/// there may a trailing uncut run stand as a node, because only there does
/// `build` end without a cut.
fn rebuild_range<B: ContentBlobs + ?Sized>(
    blobs: &B,
    node: Node,
    changes: &[(String, Option<String>)],
    is_rightmost: bool,
) -> StoreResult<Option<Vec<(String, String)>>> {
    let level = node.level;
    let entries = if level == 0 {
        merge_into_leaf(node.entries, changes)
    } else {
        let child_count = node.entries.len();
        let mut merged = Vec::with_capacity(child_count);
        let mut rest = changes;
        for (index, (last_key, child_id)) in node.entries.into_iter().enumerate() {
            let is_last = index + 1 == child_count;
            // Each child holds the keys up to its greatest, and the last child
            // takes whatever remains — including keys beyond the current
            // greatest, which is where an appended path lands.
            let take = if is_last {
                rest.len()
            } else {
                rest.partition_point(|(path, _)| path.as_str() <= last_key.as_str())
            };
            let (mine, tail) = rest.split_at(take);
            rest = tail;
            if mine.is_empty() {
                merged.push((last_key, child_id));
                continue;
            }
            let child = load_node(blobs, &child_id)?;
            let Some(replacement) = rebuild_range(blobs, child, mine, is_rightmost && is_last)?
            else {
                return Ok(None);
            };
            merged.extend(replacement);
        }
        merged
    };

    let (mut groups, carry) = split_with_carry(entries);
    if !carry.is_empty() {
        if !is_rightmost {
            // The boundary moved past this range's end, so the entries after it
            // would re-cut differently and this is no longer a local update.
            return Ok(None);
        }
        groups.push(carry);
    }
    let mut out = Vec::with_capacity(groups.len());
    for group in groups {
        out.push(store_node(blobs, level, group)?);
    }
    Ok(Some(out))
}

/// Merge a sorted change list into a leaf's sorted entries.
fn merge_into_leaf(
    entries: Vec<(String, String)>,
    changes: &[(String, Option<String>)],
) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(entries.len() + changes.len());
    let mut entries = entries.into_iter().peekable();
    let mut changes = changes.iter().peekable();
    loop {
        match (entries.peek(), changes.peek()) {
            (Some((entry_key, _)), Some((change_key, _))) => {
                match entry_key.as_str().cmp(change_key.as_str()) {
                    std::cmp::Ordering::Less => out.push(entries.next().expect("peeked")),
                    std::cmp::Ordering::Greater => {
                        let (path, value) = changes.next().expect("peeked");
                        if let Some(id) = value {
                            out.push((path.clone(), id.clone()));
                        }
                    }
                    std::cmp::Ordering::Equal => {
                        entries.next();
                        let (path, value) = changes.next().expect("peeked");
                        if let Some(id) = value {
                            out.push((path.clone(), id.clone()));
                        }
                    }
                }
            }
            (Some(_), None) => out.push(entries.next().expect("peeked")),
            (None, Some(_)) => {
                let (path, value) = changes.next().expect("peeked");
                if let Some(id) = value {
                    out.push((path.clone(), id.clone()));
                }
            }
            (None, None) => return out,
        }
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
/// and the reason it can: equal subtrees cost one id comparison, so the work is
/// proportional to what changed rather than to the workspace.
///
/// **How it was O(size) until 2026-08-30.** The previous shape called
/// `collect_changed_leaves` twice, and each call began by walking and parsing
/// *every node of the other tree* to build the set of shared ids. The
/// short-circuit skipped descending shared subtrees on one side only after the
/// precomputation had already descended all of the other. Its own comment said
/// "short-circuiting on equal subtree ids already removes the term that scaled
/// with the workspace" — the precomputation WAS that term, twice.
///
/// The two sides descend together now. At each level the ids common to both
/// frontiers name subtrees that cannot differ and are dropped unread; the rest
/// expand one level. Note that correctness does not depend on the skipping: a
/// shared subtree that the frontiers meet at different depths is simply
/// descended on both sides, and its entries compare equal at the end. The
/// skipping is the cost property, not the answer.
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
    let mut before = BTreeMap::new();
    let mut after = BTreeMap::new();
    let mut before_frontier = vec![before_root.to_owned()];
    let mut after_frontier = vec![after_root.to_owned()];

    while !before_frontier.is_empty() || !after_frontier.is_empty() {
        // An id names its whole content, so an id on both sides is a subtree
        // that cannot differ. Dropped without a read — this is the whole
        // short-circuit, and it happens BEFORE either side is loaded.
        let shared: std::collections::BTreeSet<String> = {
            let on_the_other_side: std::collections::BTreeSet<&str> =
                after_frontier.iter().map(String::as_str).collect();
            before_frontier
                .iter()
                .filter(|id| on_the_other_side.contains(id.as_str()))
                .cloned()
                .collect()
        };
        before_frontier.retain(|id| !shared.contains(id));
        after_frontier.retain(|id| !shared.contains(id));

        before_frontier = expand_frontier(blobs, before_frontier, &mut before)?;
        after_frontier = expand_frontier(blobs, after_frontier, &mut after)?;
    }

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

/// Load one frontier's nodes, draining level-0 entries into `leaves` and
/// returning the children of everything above.
fn expand_frontier<B: ContentBlobs + ?Sized>(
    blobs: &B,
    frontier: Vec<String>,
    leaves: &mut BTreeMap<String, String>,
) -> StoreResult<Vec<String>> {
    let mut next = Vec::new();
    for id in frontier {
        let node = load_node(blobs, &id)?;
        if node.level == 0 {
            leaves.extend(node.entries);
        } else {
            next.extend(node.entries.into_iter().map(|(_, child)| child));
        }
    }
    Ok(next)
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

    /// The tree's write-counting double runs the contract too — it was minting
    /// `sha256_hex` ids where the real store mints `stable_hash_hex`, so the
    /// node ids these tests count were ids no backend produces.
    #[test]
    fn the_manifest_double_satisfies_the_content_contract() {
        crate::content::conformance::run_suite(CountingBlobs::default).expect("suite runs");
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

    /// Counts node READS, as `CountingBlobs` counts writes. A cost claim about
    /// diff is a claim about how much of the tree it had to look at.
    struct ReadCounting<'a> {
        inner: &'a CountingBlobs,
        reads: &'a std::cell::Cell<usize>,
    }

    impl ContentBlobs for ReadCounting<'_> {
        fn put(&self, body: &str) -> StoreResult<String> {
            self.inner.put(body)
        }
        fn get(&self, id: &str) -> StoreResult<Option<String>> {
            self.reads.set(self.reads.get() + 1);
            self.inner.get(id)
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
    /// A deterministic stream, so a failure is reproducible from the seed
    /// alone rather than "it went red once in CI".
    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }
        fn below(&mut self, bound: usize) -> usize {
            (self.next() as usize) % bound
        }
    }

    /// **The property the whole incremental path rests on.**
    ///
    /// `apply` must produce the same ROOT ID as a full rebuild, not merely the
    /// same entries. The manifest root is what bundle import compares to decide
    /// `AlreadyPresent` from `DivergentBranch`, so a tree that differed only in
    /// shape would make two stores holding identical content refuse each
    /// other's idempotent imports as conflicts. It is also what
    /// history-independence means: two branches that converged on the same
    /// content have literally the same tree.
    #[test]
    fn apply_agrees_with_a_full_rebuild() {
        let mut rng = Lcg(0x2026_0826);
        let mut local = 0usize;
        let mut fell_back = 0usize;

        for round in 0..300 {
            let size = 1 + rng.below(400);
            let base: BTreeMap<String, String> = (0..size)
                .map(|index| {
                    (
                        format!("dir{}/file-{index:05}.txt", index % 7),
                        format!("blob-{index:05}"),
                    )
                })
                .collect();
            let keys: Vec<String> = base.keys().cloned().collect();

            let mut changes: BTreeMap<String, Option<String>> = BTreeMap::new();
            for step in 0..(1 + rng.below(6)) {
                match rng.below(3) {
                    // Edit a path that is there: cannot move a boundary.
                    0 => {
                        let key = keys[rng.below(keys.len())].clone();
                        changes.insert(key, Some(format!("edited-{round}-{step}")));
                    }
                    // Add one that is not: can.
                    1 => {
                        let key = format!("dir{}/new-{round}-{step}.txt", rng.below(9));
                        changes.insert(key, Some(format!("added-{round}-{step}")));
                    }
                    // Take one away: can.
                    _ => {
                        let key = keys[rng.below(keys.len())].clone();
                        changes.insert(key, None);
                    }
                }
            }

            let blobs = CountingBlobs::default();
            let root = build(&blobs, &base).expect("base builds");

            let ordered: Vec<(String, Option<String>)> = changes
                .iter()
                .map(|(path, value)| (path.clone(), value.clone()))
                .collect();
            if apply_locally(&blobs, &root, &ordered)
                .expect("local path runs")
                .is_some()
            {
                local += 1;
            } else {
                fell_back += 1;
            }

            let incremental = apply(&blobs, &root, &changes).expect("apply runs");

            let mut expected_entries = base.clone();
            for (path, value) in &changes {
                match value {
                    Some(id) => {
                        expected_entries.insert(path.clone(), id.clone());
                    }
                    None => {
                        expected_entries.remove(path);
                    }
                }
            }
            let rebuilt = build(&blobs, &expected_entries).expect("rebuild runs");

            assert_eq!(
                incremental,
                rebuilt,
                "round {round}: incremental and rebuilt trees disagree for {} entries and {} \
                 changes — a tree that differs in shape breaks history independence, and makes \
                 an identical branch import as divergent",
                size,
                changes.len()
            );
            assert_eq!(
                load(&blobs, &incremental).expect("reads back"),
                expected_entries,
                "round {round}: the incremental tree does not hold the expected entries"
            );
        }

        // A fallback that quietly took every call would leave refusal 2
        // violated with this test still green, so the split is asserted rather
        // than assumed.
        assert!(
            local > fell_back * 2,
            "the incremental path must carry the work: {local} local, {fell_back} rebuilt"
        );
    }

    /// DR-0066 §8 refusal 2, measured rather than asserted: a one-path edit
    /// must cost the DEPTH of the tree, not its width.
    ///
    /// `build` writes every node; `apply` writes the spine. If this test starts
    /// failing upward, an operation whose effect is O(change) has gone back to
    /// costing O(workspace).
    #[test]
    fn a_one_path_edit_writes_only_its_depth() {
        let blobs = CountingBlobs::default();
        let base = manifest(2_000);
        let root = build(&blobs, &base).expect("base builds");
        let full_rebuild = blobs.novel_writes(&BTreeMap::new());
        assert!(
            full_rebuild > 100,
            "the fixture must be wide enough for depth and width to differ, got {full_rebuild} \
             nodes"
        );

        let before = blobs.snapshot();
        blobs.reset_writes();
        let path = base
            .keys()
            .nth(1_000)
            .expect("a path in the middle")
            .clone();
        let changes = BTreeMap::from([(path, Some("edited".to_owned()))]);
        apply(&blobs, &root, &changes).expect("apply runs");

        let spine = blobs.novel_writes(&before);
        assert!(
            spine <= 6,
            "a one-path edit wrote {spine} new nodes where the whole tree is {full_rebuild}; the \
             incremental path is not being taken"
        );
    }

    /// Reads are bounded too: resolving one path must not materialize the
    /// workspace. `vcs::read` loaded the whole manifest to fetch one file until
    /// 2026-08-26, which is the same refusal on the other side.
    #[test]
    fn a_one_path_read_costs_the_depth_not_the_width() {
        let blobs = CountingBlobs::default();
        let base = manifest(2_000);
        let root = build(&blobs, &base).expect("base builds");
        let path = base
            .keys()
            .nth(1_000)
            .expect("a path in the middle")
            .clone();

        let reads = std::cell::Cell::new(0usize);
        struct Counting<'a> {
            inner: &'a CountingBlobs,
            reads: &'a std::cell::Cell<usize>,
        }
        impl ContentBlobs for Counting<'_> {
            fn put(&self, body: &str) -> StoreResult<String> {
                self.inner.put(body)
            }
            fn get(&self, id: &str) -> StoreResult<Option<String>> {
                self.reads.set(self.reads.get() + 1);
                self.inner.get(id)
            }
        }
        let counting = Counting {
            inner: &blobs,
            reads: &reads,
        };

        let found = get(&counting, &root, &path).expect("get runs");
        assert_eq!(found.as_deref(), base.get(&path).map(String::as_str));
        assert!(
            reads.get() <= 6,
            "resolving one path read {} nodes; a keyed descent is O(depth)",
            reads.get()
        );
    }

    #[test]
    fn the_boundary_predicate_matches_the_hex_round_trip() {
        fn via_hex(key: &str) -> bool {
            let digest = sha256_hex(&format!("{NODE_TAG}\u{1e}boundary\u{1e}{key}"));
            let window = u64::from_str_radix(&digest[..4], 16).unwrap_or(0);
            window.is_multiple_of(TARGET_FANOUT)
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

        // **The rate, not just the agreement.**
        //
        // This test mirrored the implementation's arithmetic and therefore
        // agreed with it while it was wrong: both sides read
        // `is_multiple_of(65536 / TARGET_FANOUT)`, which makes one key in 4096
        // a boundary rather than one in 16, and a differential test cannot see
        // a defect it reproduces. Measured, every cut in every stored manifest
        // was `MAX_ENTRIES` instead. So the rate is asserted against the
        // CONSTANT that names it, which is a claim neither side can satisfy by
        // agreeing with the other.
        let expected = keys.len() / (TARGET_FANOUT as usize);
        assert!(
            boundaries * 2 > expected && boundaries < expected * 2,
            "one key in {TARGET_FANOUT} should be a boundary — expected about {expected} of {}, \
             saw {boundaries}",
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

    /// **DR-0070 §1's diff claim, measured.**
    ///
    /// "Equal subtrees compare in one comparison, so diff is O(changed) rather
    /// than O(size)" — the property the record calls "what makes continuous
    /// reconciliation affordable at all". It was never measured, and it was
    /// false: the implementation walked and parsed every node of the other tree
    /// to build a shared-id set, twice, before its short-circuit did anything.
    ///
    /// The two correctness tests could not have caught it.
    /// `diff_reports_adds_edits_and_removals` uses a handful of entries, and
    /// `an_unchanged_tree_diffs_to_nothing` returns at the `before_root ==
    /// after_root` early exit without entering the walk at all.
    #[test]
    fn a_one_path_diff_reads_the_depth_not_the_width() {
        let blobs = CountingBlobs::default();
        let base = manifest(2_000);
        let before = build(&blobs, &base).expect("base builds");
        let whole_tree = blobs.novel_writes(&BTreeMap::new());
        assert!(
            whole_tree > 100,
            "the fixture must be wide enough for depth and width to differ, got {whole_tree} nodes"
        );

        let path = base
            .keys()
            .nth(1_000)
            .expect("a path in the middle")
            .clone();
        let after = apply(
            &blobs,
            &before,
            &BTreeMap::from([(path.clone(), Some("edited".to_owned()))]),
        )
        .expect("apply runs");

        let reads = std::cell::Cell::new(0usize);
        let counting = ReadCounting {
            inner: &blobs,
            reads: &reads,
        };
        let changes = diff(&counting, &before, &after).expect("diff runs");

        assert_eq!(changes.len(), 1, "one path changed");
        assert_eq!(changes[0].path, path);
        assert!(
            reads.get() <= 16,
            "diffing a one-path change read {} of {whole_tree} nodes; equal subtrees are \
             supposed to cost one id comparison",
            reads.get()
        );
    }

    /// The answer has to be right whatever the skipping does. Randomised
    /// against the naive comparison of the two entry maps, because the tandem
    /// descent drops subtrees UNREAD and a bug there would silently report
    /// fewer changes than happened — which reads exactly like an efficient
    /// diff.
    #[test]
    fn diff_agrees_with_comparing_the_two_manifests() {
        let mut rng = Lcg(0x2026_0830);
        for round in 0..200 {
            let size = 1 + rng.below(300);
            let base: BTreeMap<String, String> = (0..size)
                .map(|index| {
                    (
                        format!("dir{}/file-{index:05}.txt", index % 5),
                        format!("blob-{index:05}"),
                    )
                })
                .collect();
            let mut changes: BTreeMap<String, Option<String>> = BTreeMap::new();
            let keys: Vec<String> = base.keys().cloned().collect();
            for step in 0..(1 + rng.below(8)) {
                match rng.below(3) {
                    0 => {
                        changes.insert(
                            keys[rng.below(keys.len())].clone(),
                            Some(format!("edited-{round}-{step}")),
                        );
                    }
                    1 => {
                        changes.insert(
                            format!("dir{}/new-{round}-{step}.txt", rng.below(7)),
                            Some(format!("added-{round}-{step}")),
                        );
                    }
                    _ => {
                        changes.insert(keys[rng.below(keys.len())].clone(), None);
                    }
                }
            }

            let blobs = CountingBlobs::default();
            let before_root = build(&blobs, &base).expect("base builds");
            let after_root = apply(&blobs, &before_root, &changes).expect("apply runs");

            let mut expected_entries = base.clone();
            for (path, value) in &changes {
                match value {
                    Some(id) => {
                        expected_entries.insert(path.clone(), id.clone());
                    }
                    None => {
                        expected_entries.remove(path);
                    }
                }
            }

            let mut expected: Vec<ManifestChange> = Vec::new();
            for (path, after_hash) in &expected_entries {
                if base.get(path) != Some(after_hash) {
                    expected.push(ManifestChange {
                        path: path.clone(),
                        before: base.get(path).cloned(),
                        after: Some(after_hash.clone()),
                    });
                }
            }
            for (path, before_hash) in &base {
                if !expected_entries.contains_key(path) {
                    expected.push(ManifestChange {
                        path: path.clone(),
                        before: Some(before_hash.clone()),
                        after: None,
                    });
                }
            }
            expected.sort_by(|a, b| a.path.cmp(&b.path));

            assert_eq!(
                diff(&blobs, &before_root, &after_root).expect("diff runs"),
                expected,
                "round {round}: the tree diff and the map comparison disagree"
            );
        }
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
    /// DR-0066 §3 inside the walk, not only at whatever the caller verified.
    ///
    /// `load_node` verifies every node it fetches, because an interior node
    /// names a whole subtree and this walker cannot know whether the `blobs` it
    /// was handed verifies — the read-through cache does, a bare store does
    /// not. Without this, a substituted node silently redefines that much of
    /// the manifest and every reader downstream believes it.
    #[test]
    fn a_node_whose_bytes_do_not_match_its_id_is_refused_on_load() {
        let blobs = CountingBlobs::default();
        let root = build(&blobs, &manifest(240)).expect("tree builds");
        let parsed =
            parse_node(&blobs.get(&root).expect("reads").expect("live")).expect("root parses");
        assert!(
            parsed.level > 0,
            "the fixture must produce interior nodes, or this substitutes nothing"
        );
        let victim = parsed.entries[0].1.clone();

        // Honest bytes, wrong place: a real node from a different tree, stored
        // under the id the root points at.
        let other = build(&blobs, &manifest(8)).expect("second tree builds");
        let smuggled = blobs.get(&other).expect("reads").expect("live");
        blobs
            .stored
            .borrow_mut()
            .insert(victim.clone(), smuggled.clone());

        let error = load(&blobs, &root).expect_err("a lying node is refused");
        assert!(
            matches!(error, StoreError::ContentMismatch { .. }),
            "expected a content mismatch, got {error:?}"
        );
    }

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
