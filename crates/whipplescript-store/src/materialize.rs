//! Materialize-on-exec + import-back: POSIX as projection
//! (spec/versioned-workspace-research-note.md §10–§11; untie-substrate
//! readiness tracker Phase 1).
//!
//! When a branch's run reaches a POSIX-needing effect, the runtime
//! projects the branch's manifest into a REAL scratch directory (genuine
//! inodes — subprocesses, mmap, watchers all work; no FUSE), runs the
//! tool there, and imports the diff back as content-addressed writes.
//! The import is **atomic** (the whole diff is one branch-head advance),
//! **recorded** (a cut), **complete** (every changed blob is stored
//! before the head moves; nothing escapes the diff), **keyed by effect
//! id** (the cut id), and **idempotent** (a crash-retry that finds the
//! head already at the effect's cut is a no-op success).
//!
//! The stat cache (stat_cache.rs, invariant stat-cache.maude) is seeded
//! at materialization: entries carry the manifest's known content ids,
//! and the seed stamp is the materialization instant — files written in
//! that same granule are inside the racy window, so the FIRST import
//! re-hashes them (sound; the tool may have written immediately). A
//! scratch that persists across effects gets O(touched) scans from the
//! second import on, exactly the modeled trust rule.
//!
//! Manifest keys may be absolute (file effects record resolved full
//! paths); a scratch directory needs relative entries, so
//! materialization records the key mapping and import-back restores the
//! original keys — a tool-created NEW file keys by its scratch-relative
//! path.

#[cfg(feature = "native")]
use std::collections::BTreeMap;
use std::path::{Component, Path};

#[cfg(feature = "native")]
use crate::content::{BlobStatus, ContentBlobs};
#[cfg(feature = "native")]
use crate::stat_cache::{scan_dir, CachedEntry, StatCache};
use crate::{StoreError, StoreResult};

/// A materialized scratch: the seeded stat cache and the scratch-relative
/// path → original manifest key mapping (identity for relative keys).
#[cfg(feature = "native")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MaterializedScratch {
    pub cache: StatCache,
    pub key_of: BTreeMap<String, String>,
}

/// The imported diff, in ORIGINAL manifest keys: changed (added or
/// modified) path → content id with every blob already stored, removed
/// paths, and the refreshed cache for the next scan over this scratch.
#[cfg(feature = "native")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScratchImport {
    pub changed: BTreeMap<String, String>,
    pub removed: Vec<String>,
    pub cache: StatCache,
    pub trusted: usize,
    pub rehashed: usize,
}

/// Reject any manifest key that would escape a scratch/workspace root
/// when used as a filesystem path. Manifest keys may legitimately be
/// absolute (file effects record resolved full paths), so a leading `/`
/// is re-rooted under the scratch; but a `..` (ParentDir) component — or
/// any embedded root/prefix component — is an escape attempt. Manifest
/// keys are attacker-controllable through an imported handoff bundle
/// (`whip branch import`), so this validation is the choke point that
/// keeps a hostile bundle from writing outside the scratch on
/// materialize-on-exec. Returns the re-rooted, scratch-relative form.
pub(crate) fn safe_scratch_relative(key: &str) -> StoreResult<String> {
    let trimmed = key.trim_start_matches('/');
    if trimmed.is_empty() {
        return Err(StoreError::Conflict(format!(
            "manifest key `{key}` is empty after normalization"
        )));
    }
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(StoreError::Conflict(format!(
                    "manifest key `{key}` escapes the scratch root: \
                     `..` / absolute / prefix path components are not allowed"
                )));
            }
        }
    }
    Ok(trimmed.to_owned())
}

/// Validate a manifest key without materializing it — the import-time
/// choke point (`import_bundle`) so a bundle carrying a traversal key is
/// refused before any of its state is persisted.
pub(crate) fn validate_manifest_key(key: &str) -> StoreResult<()> {
    safe_scratch_relative(key).map(|_| ())
}

#[cfg(feature = "native")]
fn scratch_relative(key: &str) -> StoreResult<String> {
    safe_scratch_relative(key)
}

/// Bounds for a partial materialization (Class-B sidecar disks are
/// finite): exceeding the byte budget refuses CLEARLY, before any write,
/// naming the need and the bound — never a mysterious mid-write failure.
#[cfg(feature = "native")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MaterializeLimits {
    pub max_bytes: Option<u64>,
}

/// Project `manifest` into `root` (created if needed). Coherence checked
/// up front: a manifest entry whose blob is absent refuses before any
/// write. `now_unix_nanos` seeds the cache stamp — the materialization
/// granule itself stays racy (re-hashed on first import), which is what
/// makes a tool's immediate same-granule write undroppable.
#[cfg(feature = "native")]
pub fn materialize_manifest(
    manifest: &BTreeMap<String, String>,
    content: &dyn ContentBlobs,
    root: &Path,
    now_unix_nanos: i128,
) -> StoreResult<MaterializedScratch> {
    materialize_manifest_subset(
        manifest,
        None,
        content,
        root,
        now_unix_nanos,
        &MaterializeLimits::default(),
    )
}

/// Partial materialization (vw note §10.1 item 3): project only the
/// `include` subset — the slicer-computed input closure the effect
/// actually touches — under a byte budget. Import-back over a subset
/// scratch is naturally partial too: un-materialized manifest paths are
/// absent from the seeded cache, so the scan neither reports them
/// removed nor lets the diff touch them. Fetch-on-demand for surprise
/// reads is the DO Class-B pull-missing protocol's seam, not this
/// function; on native, a subset miss surfaces as an ordinary
/// file-not-found to the tool.
#[cfg(feature = "native")]
pub fn materialize_manifest_subset(
    manifest: &BTreeMap<String, String>,
    include: Option<&std::collections::BTreeSet<String>>,
    content: &dyn ContentBlobs,
    root: &Path,
    now_unix_nanos: i128,
    limits: &MaterializeLimits,
) -> StoreResult<MaterializedScratch> {
    materialize_manifest_onto(
        manifest,
        include,
        content,
        root,
        now_unix_nanos,
        limits,
        None,
    )
}

/// Materialize onto a root whose current contents are already described by
/// `on_disk`, writing only the files that are not already right.
///
/// The projection's cost used to be the whole manifest, every time, and the
/// common case is that it had nothing to do. `commit_turn` imports the
/// worktree and then projects the branch back onto it, so at the moment the
/// projection runs, every observed path on disk already holds exactly the
/// bytes the manifest records — and the projection read and rewrote all of
/// them anyway. That is O(worktree) work, and O(worktree) memory, on every
/// turn.
///
/// `on_disk` is a scan's own cache: for each path, what was there and what it
/// hashed to. An entry may be believed only under the rule `scan_dir` already
/// uses for the same question — size and mtime unchanged since the scan, and
/// that mtime strictly older than the scan's stamp. Anything touched inside the
/// racy granule is written, which is what the projection did for everything
/// before this existed, so the conservative direction is the unchanged one.
///
/// Pass `None` to project unconditionally.
#[cfg(feature = "native")]
pub fn materialize_manifest_onto(
    manifest: &BTreeMap<String, String>,
    include: Option<&std::collections::BTreeSet<String>>,
    content: &dyn ContentBlobs,
    root: &Path,
    now_unix_nanos: i128,
    limits: &MaterializeLimits,
    on_disk: Option<&StatCache>,
) -> StoreResult<MaterializedScratch> {
    let selected: Vec<(&str, &str)> = manifest
        .iter()
        .filter(|(key, _)| include.is_none_or(|include| include.contains(*key)))
        .map(|(key, hash)| (key.as_str(), hash.as_str()))
        .collect();

    // DR-0068 §4: check the WHOLE closure before doing any work. This loop used
    // to check coherence itself, one blob at a time, and got both halves of
    // that wrong: it returned on the FIRST missing blob, so an operator fixing
    // them learned the extent one round trip at a time, and it reported every
    // failure as "the blob is absent" — including an ERASED one, which is the
    // absent-for-erased substitution DR-0066 §5 refuses. Being told "absent"
    // about bytes that are gone by policy means retrying forever.
    //
    // `preflight_manifest` answered both correctly and had no production
    // caller, which is how a hand-rolled second answer came to live here.
    if let Some(refusal) =
        crate::preflight::preflight_entries(content, selected.iter().copied())?.refusal()
    {
        return Err(StoreError::Conflict(format!(
            "materialization refuses before writing anything: {refusal}"
        )));
    }

    // The budget is answered from recorded sizes, not from loaded payloads.
    // Summing what `get` returned meant holding the whole closure in memory to
    // discover it did not fit — the one outcome for which reading it was
    // certainly wasted. `status` is a metadata read on the native store, and
    // the sum is only taken when a budget was actually set.
    if let Some(max_bytes) = limits.max_bytes {
        let mut total_bytes = 0u64;
        for (_, hash) in &selected {
            if let BlobStatus::Live { byte_len } = content.status(hash)? {
                total_bytes += byte_len;
            }
        }
        if total_bytes > max_bytes {
            return Err(StoreError::Conflict(format!(
                "materialization needs {total_bytes} bytes but the budget is                  {max_bytes}; narrow the input closure or raise the bound                  (nothing was written)"
            )));
        }
    }
    std::fs::create_dir_all(root)
        .map_err(|error| StoreError::Conflict(format!("scratch {}: {error}", root.display())))?;
    // Canonical root for the post-join containment assertion below: even
    // with `..` rejected lexically, a symlink already present in a
    // persistent scratch could redirect a write outside the root, so we
    // re-check the real resolved parent against it before every write.
    let canonical_root = std::fs::canonicalize(root).map_err(|error| {
        StoreError::Conflict(format!("canonicalize scratch {}: {error}", root.display()))
    })?;
    let mut cache = StatCache {
        stamp_unix_nanos: now_unix_nanos,
        entries: BTreeMap::new(),
    };
    let mut key_of = BTreeMap::new();
    for (key, hash) in selected {
        let relative = scratch_relative(key)?;
        let target = root.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                StoreError::Conflict(format!("scratch parent for {relative}: {error}"))
            })?;
            let canonical_parent = std::fs::canonicalize(parent).map_err(|error| {
                StoreError::Conflict(format!(
                    "canonicalize scratch parent for {relative}: {error}"
                ))
            })?;
            if !canonical_parent.starts_with(&canonical_root) {
                return Err(StoreError::Conflict(format!(
                    "manifest key `{key}` resolves outside the scratch root (symlink escape)"
                )));
            }
        }
        // Already right on disk: no read, no write, and the entry it would
        // have produced carried forward unchanged.
        let metadata = match already_materialized(on_disk, &relative, hash, &target) {
            Some(metadata) => metadata,
            None => {
                let Some(body) = content.get(hash)? else {
                    // Preflight said this resolves, so a miss here is the store
                    // contradicting itself between one call and the next, not a
                    // missing input. Reported as the disagreement it is.
                    return Err(StoreError::Conflict(format!(
                        "content {hash} for {key} preflighted as servable and then did not \
                         serve; the store disagrees with itself"
                    )));
                };
                // Read one, write one. Loading the whole closure before writing
                // any of it cost the sum of the manifest in resident memory,
                // which is what made a chat holding recordings expensive to
                // commit rather than expensive to upload.
                std::fs::write(&target, &body).map_err(|error| {
                    StoreError::Conflict(format!("materialize {relative}: {error}"))
                })?;
                std::fs::metadata(&target)
                    .map_err(|error| StoreError::Conflict(format!("stat {relative}: {error}")))?
            }
        };
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|instant| {
                instant
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|elapsed| elapsed.as_nanos() as i128)
                    .ok()
            })
            .unwrap_or(0);
        cache.entries.insert(
            relative.clone(),
            CachedEntry {
                size: metadata.len(),
                mtime_unix_nanos: mtime,
                content_hash: hash.to_owned(),
            },
        );
        key_of.insert(relative, key.to_owned());
    }
    Ok(MaterializedScratch { cache, key_of })
}

/// Whether `target` already holds the manifest's bytes, and its metadata if so.
///
/// The trust rule is `scan_dir`'s, deliberately the same one: the cache entry
/// must name this content, and the file on disk must still carry the size and
/// mtime the scan recorded, with that mtime strictly older than the scan's
/// stamp. A file written inside the scan's own mtime granule is a file whose
/// fingerprint cannot distinguish two contents, so it is not believed — the
/// same-size, same-mtime, different-bytes hazard that makes a naive importer
/// drop a change would here make a projection skip a write it owed.
///
/// Two notions of "unchanged" that could drift apart would be worse than the
/// cost this saves, so there is one.
#[cfg(feature = "native")]
fn already_materialized(
    on_disk: Option<&StatCache>,
    relative: &str,
    hash: &str,
    target: &Path,
) -> Option<std::fs::Metadata> {
    let on_disk = on_disk?;
    let recorded = on_disk.entries.get(relative)?;
    if recorded.content_hash != hash || recorded.mtime_unix_nanos >= on_disk.stamp_unix_nanos {
        return None;
    }
    let metadata = std::fs::metadata(target).ok()?;
    if !metadata.is_file() || metadata.len() != recorded.size {
        return None;
    }
    let mtime = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos() as i128;
    (mtime == recorded.mtime_unix_nanos).then_some(metadata)
}

/// Import the scratch's state back: scan against the previous cache
/// (O(touched) from the second scan on), store every changed blob, and
/// translate scratch-relative paths back to original manifest keys —
/// tool-created files key by their scratch-relative path.
#[cfg(feature = "native")]
pub fn import_scratch(
    root: &Path,
    scratch: &MaterializedScratch,
    content: &dyn ContentBlobs,
    now_unix_nanos: i128,
) -> StoreResult<ScratchImport> {
    let outcome = scan_dir(root, &scratch.cache, now_unix_nanos)?;
    let mut changed = BTreeMap::new();
    for (relative, hash) in &outcome.changed {
        // Bytes, not text. A worktree holds whatever the work put in it: a
        // screenshot a turn produced, a PDF a person dropped in, a compiled
        // artifact. Refusing to import those did not keep them out of the
        // worktree — it only made the branch unable to record them, and a
        // single non-UTF-8 file failed the whole import, taking the diff and
        // the cut with it. Text keeps its identity: the digest was always
        // taken over the bytes.
        // Never `read` + `put`: a worktree holds recordings now, and reading
        // one whole to hand it to a store that will write it whole made the
        // resident cost of finalizing a turn scale with the largest file in
        // the tree. `put_file` lets a store that can write incrementally do
        // so; the ones that cannot read the file themselves, which is what
        // this line used to do anyway.
        let stored = content.put_file(&root.join(relative))?;
        if &stored != hash {
            return Err(StoreError::Conflict(format!(
                "content moved under the import of {relative}; retry"
            )));
        }
        let key = scratch
            .key_of
            .get(relative)
            .cloned()
            .unwrap_or_else(|| relative.clone());
        changed.insert(key, hash.clone());
    }
    let removed = outcome
        .removed
        .iter()
        .map(|relative| {
            scratch
                .key_of
                .get(relative)
                .cloned()
                .unwrap_or_else(|| relative.clone())
        })
        .collect();
    Ok(ScratchImport {
        changed,
        removed,
        cache: outcome.cache,
        trusted: outcome.trusted,
        rehashed: outcome.rehashed,
    })
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::content::ContentStore;

    fn scratch_root(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-materialize-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).expect("scratch");
        dir
    }

    fn content(label: &str) -> ContentStore {
        ContentStore::open(scratch_root(label).join("content.sqlite")).expect("content store")
    }

    fn now_nanos() -> i128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos() as i128
    }

    /// A real store that also reports how many payloads were pulled out of it.
    ///
    /// It delegates rather than simulating, because a double that answers
    /// differently from the backend it stands for makes every test using it a
    /// check against a store that could not exist — and the count is the whole
    /// point here, so the rest must be true.
    struct CountingReads {
        inner: ContentStore,
        reads: std::cell::Cell<usize>,
    }

    impl Default for CountingReads {
        fn default() -> Self {
            Self {
                inner: content("counting-reads"),
                reads: std::cell::Cell::new(0),
            }
        }
    }

    impl ContentBlobs for CountingReads {
        fn put(&self, body: &[u8]) -> StoreResult<String> {
            self.inner.put(body)
        }
        fn put_unerased(&self, body: &[u8]) -> StoreResult<String> {
            self.inner.put_unerased(body)
        }
        fn put_file(&self, path: &Path) -> StoreResult<String> {
            self.inner.put_file(path)
        }
        fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
            self.reads.set(self.reads.get() + 1);
            self.inner.get(id)
        }
        fn status(&self, id: &str) -> StoreResult<BlobStatus> {
            self.inner.status(id)
        }
        fn erase(&self, id: &str, at: &str) -> StoreResult<crate::content::EraseOutcome> {
            self.inner.erase(id, at)
        }
        fn cached_read_available(&self, id: &str) -> StoreResult<bool> {
            self.inner.cached_read_available(id)
        }
        fn publish_retained<T>(
            &self,
            ids: &[String],
            publish: impl FnOnce() -> StoreResult<T>,
        ) -> StoreResult<T> {
            self.inner.publish_retained(ids, publish)
        }
        fn chunk_ids(&self, id: &str) -> StoreResult<Option<Vec<String>>> {
            self.inner.chunk_ids(id)
        }
        fn put_chunk_root(
            &self,
            root_id: &str,
            chunk_ids: &[String],
            byte_len: u64,
        ) -> StoreResult<()> {
            self.inner.put_chunk_root(root_id, chunk_ids, byte_len)
        }
    }

    /// A store whose `status` promises what its `get` will not deliver.
    ///
    /// The preflight asks one question and the read asks another, and between
    /// them the store may change its mind. That is not a missing input — it is
    /// the store contradicting itself, and it has to be reported as such rather
    /// than as "the blob is absent", which would send an operator to retry for
    /// bytes the store believes it has.
    struct DisagreesWithItself {
        inner: ContentStore,
    }

    impl ContentBlobs for DisagreesWithItself {
        fn put(&self, body: &[u8]) -> StoreResult<String> {
            self.inner.put(body)
        }
        fn get(&self, _id: &str) -> StoreResult<Option<Vec<u8>>> {
            Ok(None)
        }
        fn status(&self, id: &str) -> StoreResult<BlobStatus> {
            self.inner.status(id)
        }
    }

    /// A store that preflights a blob as servable and then does not serve it is
    /// refused as the disagreement it is, and named as that rather than as an
    /// absence.
    #[test]
    fn content_that_preflights_and_then_does_not_serve_is_named_a_disagreement() {
        let store = DisagreesWithItself {
            inner: content("disagrees"),
        };
        let mut manifest = BTreeMap::new();
        manifest.insert("/ws/a.md".to_owned(), store.put_text("alpha").expect("put"));
        let root = scratch_root("disagrees-dir");

        let refused = materialize_manifest(&manifest, &store, &root, now_nanos())
            .expect_err("a store that will not serve what it promised is refused");
        let rendered = format!("{refused:?}");
        assert!(
            rendered.contains("the store disagrees with itself"),
            "named as a disagreement, not an absence: {rendered}"
        );
        assert!(
            !root.join("ws/a.md").exists(),
            "and the file it could not serve was not invented"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The read-counting double runs the contract too: a count taken against a
    /// store that does not behave like the real one counts nothing anybody
    /// cares about.
    #[test]
    fn the_read_counting_double_satisfies_the_content_contract() {
        crate::content::conformance::run_suite(CountingReads::default).expect("suite runs");
    }

    /// The projection's whole cost, on the turn where it has nothing to do.
    ///
    /// `commit_turn` imports the worktree and then projects the branch back
    /// onto it, so every file it is about to write is already exactly right.
    /// It used to read and rewrite all of them anyway.
    #[test]
    fn a_projection_onto_what_is_already_there_reads_nothing() {
        let store = CountingReads::default();
        let mut manifest = BTreeMap::new();
        for (name, body) in [("a.md", "alpha"), ("deep/b.md", "beta"), ("c.md", "gamma")] {
            manifest.insert(format!("/ws/{name}"), store.put_text(body).expect("stores"));
        }
        let root = scratch_root("projection-noop-dir");
        let first =
            materialize_manifest(&manifest, &store, &root, now_nanos()).expect("materialize");

        // The scan that would precede a real projection: its stamp must be
        // after the writes, exactly as `commit_turn`'s import stamp is.
        let scanned = scan_dir(&root, &first.cache, now_nanos() + 2_000_000_000)
            .expect("scan")
            .cache;

        store.reads.set(0);
        let again = materialize_manifest_onto(
            &manifest,
            None,
            &store,
            &root,
            now_nanos() + 4_000_000_000,
            &MaterializeLimits::default(),
            Some(&scanned),
        )
        .expect("materialize");

        assert_eq!(store.reads.get(), 0, "no payload was pulled");
        assert_eq!(
            std::fs::read_to_string(root.join("ws/a.md")).expect("reads"),
            "alpha",
            "and the files are still what the manifest says"
        );
        // The scratch a skipped projection returns has to describe the tree as
        // completely as one that wrote it, or the next import reads every
        // skipped path as removed.
        assert_eq!(
            again.cache.entries.keys().collect::<Vec<_>>(),
            first.cache.entries.keys().collect::<Vec<_>>()
        );
        assert_eq!(again.key_of, first.key_of);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The three ways a file is not what the cache claims, each of which must
    /// be written rather than believed.
    #[test]
    fn a_projection_writes_what_the_cache_cannot_vouch_for() {
        let store = CountingReads::default();
        let mut manifest = BTreeMap::new();
        manifest.insert("/ws/a.md".to_owned(), store.put_text("alpha").expect("put"));
        let root = scratch_root("projection-untrusted-dir");
        let first =
            materialize_manifest(&manifest, &store, &root, now_nanos()).expect("materialize");
        let scanned = scan_dir(&root, &first.cache, now_nanos() + 2_000_000_000)
            .expect("scan")
            .cache;

        let reproject = |cache: &StatCache| -> usize {
            store.reads.set(0);
            materialize_manifest_onto(
                &manifest,
                None,
                &store,
                &root,
                now_nanos() + 4_000_000_000,
                &MaterializeLimits::default(),
                Some(cache),
            )
            .expect("materialize");
            store.reads.get()
        };

        // 1. The manifest moved on: the cache describes yesterday's content.
        let mut stale = scanned.clone();
        stale
            .entries
            .get_mut("ws/a.md")
            .expect("entry")
            .content_hash = "0000000000000000000000000000000f".to_owned();
        assert_eq!(reproject(&stale), 1, "a different hash is written");

        // 2. Inside the racy granule: same size, same mtime, and a fingerprint
        //    that cannot tell two contents apart. `scan_dir` refuses to trust
        //    this and so does the projection.
        let mut racy = scanned.clone();
        racy.stamp_unix_nanos = racy.entries["ws/a.md"].mtime_unix_nanos;
        assert_eq!(reproject(&racy), 1, "the racy granule is written");

        // 3. The file moved under us since the scan.
        std::fs::write(root.join("ws/a.md"), "edited by somebody else").expect("edit");
        assert_eq!(reproject(&scanned), 1, "a changed file is written");
        assert_eq!(
            std::fs::read_to_string(root.join("ws/a.md")).expect("reads"),
            "alpha",
            "and restored to what the manifest records"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A closure that does not fit is refused from recorded sizes, without
    /// loading the payloads that were never going to be written.
    #[test]
    fn a_budget_refusal_costs_no_reads() {
        let store = CountingReads::default();
        let mut manifest = BTreeMap::new();
        manifest.insert(
            "/ws/big.bin".to_owned(),
            store.put(&vec![7u8; 4096]).expect("stores"),
        );
        let root = scratch_root("projection-budget-dir");
        store.reads.set(0);
        let refused = materialize_manifest_onto(
            &manifest,
            None,
            &store,
            &root,
            now_nanos(),
            &MaterializeLimits {
                max_bytes: Some(1024),
            },
            None,
        )
        .expect_err("the budget refuses");
        assert!(
            format!("{refused:?}").contains("nothing was written"),
            "{refused:?}"
        );
        assert_eq!(store.reads.get(), 0, "and nothing was read either");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// **An erased input must not read as an absent one.**
    ///
    /// DR-0066 §5 distinguishes *absent* (not replicated here — retry) from
    /// *erased* (dropped by policy — degrade honestly), and this path collapsed
    /// them: every failure said "the blob is absent", so an operator was told to
    /// retry forever for bytes that are gone.
    #[test]
    fn an_erased_input_refuses_as_erased_not_as_absent() {
        let store = content("erased-input");
        let kept = store.put_text("kept").expect("stores");
        let doomed = store.put_text("dropped by policy").expect("stores");
        store
            .erase(&doomed, "2026-08-30T00:00:00Z")
            .expect("erasure records");

        let manifest = BTreeMap::from([
            ("/ws/kept.txt".to_owned(), kept),
            ("/ws/gone.txt".to_owned(), doomed.clone()),
        ]);
        let root = scratch_root("erased-input").join("scratch");
        let error = materialize_manifest(&manifest, &store, &root, now_nanos())
            .expect_err("an erased input refuses");
        let rendered = format!("{error:?}");
        assert!(
            rendered.contains("erased") && rendered.contains(&doomed),
            "the refusal must name the blob and say it was erased, got {rendered}"
        );
        assert!(
            !rendered.contains("is absent"),
            "erased bytes reported as absent send an operator into an endless retry: {rendered}"
        );
        assert!(
            !root.exists() || std::fs::read_dir(&root).into_iter().flatten().count() == 0,
            "nothing may be written when the closure does not resolve"
        );
        // The refusal SAYS what the line above checks. Asserted because it is
        // an operational claim — an operator deciding whether to clean up a
        // half-written scratch reads this sentence, not the source — and
        // because the sweep found the wrapper's own text pinned by nothing: the
        // assertions above all match the inner rendering, which a mutation of
        // this message leaves untouched.
        assert!(
            rendered.contains("before writing anything"),
            "the refusal must say that nothing was written, got {rendered}"
        );
    }

    /// Every missing input, not the first.
    ///
    /// The whole reason `preflight_manifest` reports a list: an operator fixing
    /// them one at a time learns the extent one round trip at a time. This path
    /// returned on the first miss.
    #[test]
    fn every_unservable_input_is_named_not_only_the_first() {
        let store = content("missing-inputs");
        let kept = store.put_text("kept").expect("stores");
        let manifest = BTreeMap::from([
            ("/ws/a.txt".to_owned(), "never-stored-a".to_owned()),
            ("/ws/b.txt".to_owned(), kept),
            ("/ws/c.txt".to_owned(), "never-stored-c".to_owned()),
        ]);
        let root = scratch_root("missing-inputs").join("scratch");
        let error = materialize_manifest(&manifest, &store, &root, now_nanos())
            .expect_err("missing inputs refuse");
        let rendered = format!("{error:?}");
        assert!(
            rendered.contains("never-stored-a") && rendered.contains("never-stored-c"),
            "both missing inputs must be named, got {rendered}"
        );
        assert!(
            rendered.contains("2 of 3"),
            "the refusal must say how much of the closure it checked, got {rendered}"
        );
    }

    /// A subset materialization preflights the SUBSET.
    ///
    /// Checking the whole manifest would refuse runs over inputs they never
    /// touch, which is how a correct check becomes one someone routes around.
    #[test]
    fn a_subset_preflights_only_what_it_will_project() {
        let store = content("subset-preflight");
        let kept = store.put_text("kept").expect("stores");
        let manifest = BTreeMap::from([
            ("/ws/needed.txt".to_owned(), kept),
            ("/ws/untouched.txt".to_owned(), "never-stored".to_owned()),
        ]);
        let root = scratch_root("subset-preflight").join("scratch");
        let include = std::collections::BTreeSet::from(["/ws/needed.txt".to_owned()]);
        materialize_manifest_subset(
            &manifest,
            Some(&include),
            &store,
            &root,
            now_nanos(),
            &MaterializeLimits::default(),
        )
        .expect("a subset whose own inputs resolve materializes");
    }

    /// The symlink escape. A manifest key is a path inside the scratch, and a
    /// symlinked parent directory is how one stops being that — materializing
    /// through it would write the run's inputs somewhere on the host that no
    /// caller named. Nothing exercised this refusal until now, which means it
    /// was free to stop refusing.
    #[test]
    fn a_manifest_key_reaching_outside_the_scratch_through_a_symlink_is_refused() {
        let content = content("symlink-escape");
        let root = scratch_root("symlink-escape-dir");
        let outside = scratch_root("symlink-escape-target");
        std::fs::create_dir_all(&outside).expect("the directory to escape into");
        std::fs::create_dir_all(&root).expect("scratch root");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, root.join("ws")).expect("symlink the parent");

        let mut manifest = BTreeMap::new();
        manifest.insert(
            "/ws/escaped.md".to_owned(),
            content.put_text("payload").expect("put"),
        );

        #[cfg(unix)]
        {
            let error = materialize_manifest(&manifest, &content, &root, now_nanos())
                .expect_err("a key that leaves the scratch is refused");
            assert!(
                format!("{error:?}").contains("symlink escape"),
                "the refusal names what happened: {error:?}"
            );
            assert!(
                !outside.join("escaped.md").exists(),
                "and nothing was written outside the scratch"
            );
        }
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// A recording in the worktree: bigger than the streaming threshold, not
    /// text, and it has to import under exactly the identity a whole read
    /// would have given it. The manifest records one hash per file and nothing
    /// upstream knows which path the store took, so if these diverged a
    /// workspace would report the file as changed on every scan forever.
    #[test]
    fn a_file_past_the_streaming_threshold_imports_under_the_same_identity() {
        let content = content("streamed-import");
        let root = scratch_root("streamed-import-dir");
        let scratch = materialize_manifest(&BTreeMap::new(), &content, &root, now_nanos())
            .expect("materialize");

        let body: Vec<u8> = (0..(6 * 1024 * 1024 + 13))
            .map(|index| (index as u8) ^ 0x80)
            .collect();
        std::fs::write(root.join("take.wav"), &body).expect("a person adds a recording");

        let import = import_scratch(&root, &scratch, &content, now_nanos() + 2_000_000_000)
            .expect("imports");
        let expected = crate::chunking::content_hash_hex(&body);
        assert_eq!(import.changed.get("take.wav"), Some(&expected));
        assert_eq!(content.get(&expected).expect("reads"), Some(body));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The import's identity check. `import_scratch` scans for changed files,
    /// then reads and stores each one; if the stored id is not the id the scan
    /// computed, the file moved in between and the import is describing a
    /// state that no longer exists. A store that returns a different id
    /// standing in for that race, since the race itself is not schedulable.
    #[test]
    fn content_that_moves_under_the_import_is_refused_rather_than_recorded() {
        struct MovedUnderUs<'a>(&'a ContentStore);
        impl ContentBlobs for MovedUnderUs<'_> {
            fn put(&self, body: &[u8]) -> StoreResult<String> {
                // Store honestly, then answer with someone else's id — the
                // shape of "the bytes changed between the scan and the read".
                self.0.put(body)?;
                Ok("an-id-from-a-different-body".to_owned())
            }
            fn get(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
                self.0.get(id)
            }
        }

        let content = content("moved-under-import");
        let root = scratch_root("moved-under-import-dir");
        let mut manifest = BTreeMap::new();
        manifest.insert(
            "/ws/in.md".to_owned(),
            content.put_text("input").expect("put"),
        );
        let scratch =
            materialize_manifest(&manifest, &content, &root, now_nanos()).expect("materialize");
        std::fs::write(root.join("ws/in.md"), "edited").expect("the tool edits it");

        let moved = MovedUnderUs(&content);
        let error = import_scratch(&root, &scratch, &moved, now_nanos() + 2_000_000_000)
            .expect_err("an id that does not match the scan is refused");
        assert!(
            format!("{error:?}").contains("content moved under the import"),
            "the refusal names the race and asks for a retry: {error:?}"
        );
    }

    /// A turn that produces a picture. This is the failure the byte seam
    /// exists for: `import_scratch` decoded every changed file as UTF-8, so a
    /// single PNG in a worktree failed the whole import — and because the diff
    /// and the cut both run through it, the branch could not be read at all
    /// while that file sat there. The bytes go in and come back byte-identical.
    #[test]
    fn a_scratch_holding_bytes_that_are_not_text_imports() {
        let content = content("binary-import");
        let root = scratch_root("binary-import-dir");
        let mut manifest = BTreeMap::new();
        manifest.insert(
            "/ws/notes.md".to_owned(),
            content.put_text("notes").expect("put"),
        );
        let scratch =
            materialize_manifest(&manifest, &content, &root, now_nanos()).expect("materialize");

        // A PNG header: a lone 0x89, a NUL, and a sequence no UTF-8 decoder
        // accepts.
        let picture: [u8; 12] = [
            0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d,
        ];
        std::fs::write(root.join("ws/shot.png"), picture).expect("write the picture");
        std::fs::write(root.join("ws/notes.md"), "notes v2").expect("and edit the text");

        let import =
            import_scratch(&root, &scratch, &content, now_nanos() + 2_000_000_000).expect("import");
        assert_eq!(import.changed.len(), 2, "both files import");
        let picture_id = import
            .changed
            .get("ws/shot.png")
            .expect("the picture is in the import");
        assert_eq!(
            content.get(picture_id).expect("read").as_deref(),
            Some(&picture[..]),
            "the picture reads back byte-identical"
        );
        // And the text beside it is untouched, still stored as text.
        let notes_id = import.changed.get("/ws/notes.md").expect("the text too");
        assert!(matches!(
            content.get_text(notes_id).expect("read"),
            crate::content::TextBlob::Text(ref body) if body == "notes v2"
        ));
        assert!(matches!(
            content.get_text(picture_id).expect("read"),
            crate::content::TextBlob::Binary { byte_len: 12 }
        ));
    }

    /// The projection round-trip: absolute-keyed manifest materializes to
    /// relative scratch entries with real bytes; a tool run (one modify,
    /// one add, one delete) imports back as a diff in ORIGINAL keys with
    /// every blob stored, and unchanged files never re-read on a later
    /// scan.
    #[test]
    fn materialize_run_import_roundtrip() {
        let content = content("roundtrip");
        let root = scratch_root("roundtrip-dir");
        let mut manifest = BTreeMap::new();
        manifest.insert(
            "/ws/in.md".to_owned(),
            content.put_text("input").expect("put"),
        );
        manifest.insert(
            "/ws/keep.md".to_owned(),
            content.put_text("kept").expect("put"),
        );
        let scratch =
            materialize_manifest(&manifest, &content, &root, now_nanos()).expect("materialize");
        assert_eq!(
            std::fs::read_to_string(root.join("ws/in.md")).expect("read"),
            "input",
            "the scratch holds real bytes at relative paths"
        );

        // The "tool": modifies one input, creates one output, deletes one.
        std::fs::write(root.join("ws/in.md"), "input v2").expect("modify");
        std::fs::write(root.join("ws/out.md"), "produced").expect("create");
        std::fs::remove_file(root.join("ws/keep.md")).expect("delete");

        let import =
            import_scratch(&root, &scratch, &content, now_nanos() + 2_000_000_000).expect("import");
        assert_eq!(import.changed.len(), 2);
        assert_eq!(
            content
                .get(
                    import
                        .changed
                        .get("/ws/in.md")
                        .expect("modified key restored")
                )
                .expect("get")
                .as_deref(),
            Some(&b"input v2"[..]),
            "modified content is stored and keyed by the ORIGINAL manifest key"
        );
        assert_eq!(
            content
                .get(
                    import
                        .changed
                        .get("ws/out.md")
                        .expect("new file keys relative")
                )
                .expect("get")
                .as_deref(),
            Some(&b"produced"[..])
        );
        assert_eq!(import.removed, vec!["/ws/keep.md".to_owned()]);

        // A second import over the untouched scratch is O(touched): both
        // survivors trusted, nothing re-hashed, empty diff.
        let rescratch = MaterializedScratch {
            cache: import.cache.clone(),
            key_of: scratch.key_of.clone(),
        };
        let second = import_scratch(&root, &rescratch, &content, now_nanos() + 4_000_000_000)
            .expect("second import");
        assert!(second.changed.is_empty());
        assert!(second.removed.is_empty());
        assert_eq!(second.trusted, 2);
        assert_eq!(second.rehashed, 0);

        let _ = std::fs::remove_dir_all(root);
    }

    /// Partial materialization: only the input closure lands on disk; a
    /// tool run over the subset imports back WITHOUT the un-materialized
    /// manifest entries being reported removed or touched; the byte
    /// budget refuses clearly before any write.
    #[test]
    fn subset_materialization_respects_closure_and_budget() {
        let content = content("subset");
        let root = scratch_root("subset-dir");
        let mut manifest = BTreeMap::new();
        manifest.insert(
            "/ws/in.md".to_owned(),
            content.put_text("input").expect("put"),
        );
        manifest.insert(
            "/ws/huge.md".to_owned(),
            content.put_text(&"X".repeat(4096)).expect("put"),
        );
        let mut closure = std::collections::BTreeSet::new();
        closure.insert("/ws/in.md".to_owned());

        // The budget wall: the FULL manifest exceeds 1KiB and refuses with
        // nothing written; the closure fits.
        let refused = materialize_manifest_subset(
            &manifest,
            None,
            &content,
            &root,
            now_nanos(),
            &MaterializeLimits {
                max_bytes: Some(1024),
            },
        );
        assert!(refused.is_err(), "over-budget refuses");
        assert!(!root.join("ws").exists(), "nothing written on refusal");
        let scratch = materialize_manifest_subset(
            &manifest,
            Some(&closure),
            &content,
            &root,
            now_nanos(),
            &MaterializeLimits {
                max_bytes: Some(1024),
            },
        )
        .expect("subset materializes under budget");
        assert!(root.join("ws/in.md").exists());
        assert!(
            !root.join("ws/huge.md").exists(),
            "outside the closure, not on disk"
        );

        // The tool touches the materialized file; import-back reports
        // exactly that — the un-materialized entry is neither removed nor
        // changed.
        std::fs::write(root.join("ws/in.md"), "input v2").expect("modify");
        let import =
            import_scratch(&root, &scratch, &content, now_nanos() + 2_000_000_000).expect("import");
        assert_eq!(import.changed.len(), 1);
        assert!(import.changed.contains_key("/ws/in.md"));
        assert!(
            import.removed.is_empty(),
            "un-materialized manifest paths are not phantom removals"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A manifest key with a `..` component escapes the scratch root:
    /// materialize refuses it before any write, so a hostile imported
    /// bundle cannot use materialize-on-exec as an arbitrary-file-write
    /// primitive. An absolute key stays re-rooted safely under the scratch.
    #[test]
    fn materialize_refuses_traversal_keys() {
        let content = content("traversal");
        let root = scratch_root("traversal-dir");
        let payload = content.put_text("pwned").expect("put");

        // `..` traversal is refused, nothing written outside the root.
        let mut evil = BTreeMap::new();
        evil.insert("../../escape.txt".to_owned(), payload.clone());
        let refused = materialize_manifest(&evil, &content, &root, now_nanos());
        assert!(refused.is_err(), "`..` traversal key must be refused");
        assert!(
            !root
                .parent()
                .expect("scratch has a parent")
                .join("escape.txt")
                .exists(),
            "nothing is written outside the scratch root"
        );

        // A leading-slash absolute key is re-rooted UNDER the scratch, not
        // at the filesystem root.
        let mut absolute = BTreeMap::new();
        absolute.insert("/etc/whip-test.conf".to_owned(), payload);
        materialize_manifest(&absolute, &content, &root, now_nanos())
            .expect("absolute key re-roots under the scratch");
        assert!(
            root.join("etc/whip-test.conf").exists(),
            "the absolute key lands under the scratch, not at /etc"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Coherence up front: a manifest naming an absent blob refuses before
    /// any write lands in the scratch.
    #[test]
    fn materialize_refuses_dangling_manifest_entries() {
        let content = content("dangling");
        let root = scratch_root("dangling-dir");
        let mut manifest = BTreeMap::new();
        manifest.insert("/ws/ghost.md".to_owned(), "no_such_blob".to_owned());
        assert!(materialize_manifest(&manifest, &content, &root, now_nanos()).is_err());
        assert!(!root.join("ws").exists(), "nothing materialized on refusal");
        let _ = std::fs::remove_dir_all(root);
    }
}
