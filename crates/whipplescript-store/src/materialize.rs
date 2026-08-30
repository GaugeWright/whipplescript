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
use crate::content::ContentBlobs;
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

    let mut bodies = Vec::with_capacity(selected.len());
    let mut total_bytes = 0u64;
    for (key, hash) in selected {
        let Some(body) = content.get(hash)? else {
            // Preflight said this resolves, so a miss here is the store
            // contradicting itself between one call and the next, not a missing
            // input. Reported as the disagreement it is.
            return Err(StoreError::Conflict(format!(
                "content {hash} for {key} preflighted as servable and then did not serve; \
                 the store disagrees with itself"
            )));
        };
        total_bytes += body.len() as u64;
        bodies.push((key.to_owned(), hash.to_owned(), body));
    }
    if let Some(max_bytes) = limits.max_bytes {
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
    for (key, hash, body) in bodies {
        let relative = scratch_relative(&key)?;
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
        std::fs::write(&target, body.as_bytes())
            .map_err(|error| StoreError::Conflict(format!("materialize {relative}: {error}")))?;
        let metadata = std::fs::metadata(&target)
            .map_err(|error| StoreError::Conflict(format!("stat {relative}: {error}")))?;
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
                content_hash: hash,
            },
        );
        key_of.insert(relative, key);
    }
    Ok(MaterializedScratch { cache, key_of })
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
        let bytes = std::fs::read(root.join(relative))
            .map_err(|error| StoreError::Conflict(format!("read back {relative}: {error}")))?;
        let body = String::from_utf8(bytes).map_err(|error| {
            StoreError::Conflict(format!("non-UTF-8 import of {relative}: {error}"))
        })?;
        let stored = content.put(&body)?;
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

    /// **An erased input must not read as an absent one.**
    ///
    /// DR-0066 §5 distinguishes *absent* (not replicated here — retry) from
    /// *erased* (dropped by policy — degrade honestly), and this path collapsed
    /// them: every failure said "the blob is absent", so an operator was told to
    /// retry forever for bytes that are gone.
    #[test]
    fn an_erased_input_refuses_as_erased_not_as_absent() {
        let store = content("erased-input");
        let kept = store.put("kept").expect("stores");
        let doomed = store.put("dropped by policy").expect("stores");
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
        let kept = store.put("kept").expect("stores");
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
        let kept = store.put("kept").expect("stores");
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
        manifest.insert("/ws/in.md".to_owned(), content.put("input").expect("put"));
        manifest.insert("/ws/keep.md".to_owned(), content.put("kept").expect("put"));
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
            Some("input v2"),
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
            Some("produced")
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
        manifest.insert("/ws/in.md".to_owned(), content.put("input").expect("put"));
        manifest.insert(
            "/ws/huge.md".to_owned(),
            content.put(&"X".repeat(4096)).expect("put"),
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
        let payload = content.put("pwned").expect("put");

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
