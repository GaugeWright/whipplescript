//! Stat cache for import-back: O(touched), never unsound
//! (spec/versioned-workspace-research-note.md §10.1 item 2; untie-substrate
//! readiness tracker Phase 1; invariant modeled in stat-cache.maude).
//!
//! Import-back walks a materialized directory and must find every content
//! change without re-hashing the whole tree. The cache keeps size+mtime
//! fingerprints from the previous scan; a matching fingerprint is trusted
//! ONLY when the entry's mtime is strictly older than the previous scan's
//! stamp — anything inside that racy granule is re-hashed regardless,
//! because a write landing in the same mtime granule the cache was
//! recorded in produces a same-size-same-mtime content change the
//! fingerprint cannot see (git's racy-timestamp hazard; the modeled naive
//! importer silently drops exactly that change). The trust path is what
//! makes turn-finalize import-back O(touched) instead of O(tree);
//! soundness is bought with the racy window only.
//!
//! The caller passes the scan instant (clock at the worker boundary) and
//! persists the returned cache however it likes (`to_json`/`from_json`).
//! Content ids use the house primitive, `chunking::content_hash_hex`
//! (SHA-256/128), so import-back diffs speak the same id space as manifests
//! and blobs.

#[cfg(feature = "native")]
use std::collections::BTreeMap;
#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use serde_json::{json, Value};

#[cfg(feature = "native")]
use crate::chunking::content_hash_hex;
#[cfg(feature = "native")]
use crate::{StoreError, StoreResult};

/// One cached file: the stat fingerprint from the previous scan and the
/// content id it hashed to.
#[cfg(feature = "native")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CachedEntry {
    pub size: u64,
    pub mtime_unix_nanos: i128,
    pub content_hash: String,
}

/// The persisted cache: per-path entries plus the STAMP of the scan that
/// recorded them — the boundary of the racy window.
#[cfg(feature = "native")]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StatCache {
    pub stamp_unix_nanos: i128,
    pub entries: BTreeMap<String, CachedEntry>,
}

/// One scan's outcome: the current full manifest (path → content id),
/// which paths changed relative to the previous cache (added or modified),
/// which disappeared, the refreshed cache to persist, and the trust/rehash
/// counts that make the O(touched) claim observable.
#[cfg(feature = "native")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanOutcome {
    pub manifest: BTreeMap<String, String>,
    pub changed: BTreeMap<String, String>,
    pub removed: Vec<String>,
    pub cache: StatCache,
    pub trusted: usize,
    pub rehashed: usize,
}

#[cfg(feature = "native")]
impl StatCache {
    pub fn to_json(&self) -> String {
        let entries: Value = self
            .entries
            .iter()
            .map(|(path, entry)| {
                (
                    path.clone(),
                    json!({
                        "size": entry.size,
                        "mtime_unix_nanos": entry.mtime_unix_nanos.to_string(),
                        "content_hash": entry.content_hash,
                    }),
                )
            })
            .collect::<serde_json::Map<String, Value>>()
            .into();
        json!({
            "stamp_unix_nanos": self.stamp_unix_nanos.to_string(),
            "entries": entries,
        })
        .to_string()
    }

    pub fn from_json(body: &str) -> StoreResult<Self> {
        let value: Value = serde_json::from_str(body)?;
        let stamp = value
            .get("stamp_unix_nanos")
            .and_then(Value::as_str)
            .and_then(|text| text.parse::<i128>().ok())
            .ok_or_else(|| StoreError::Conflict("stat cache missing stamp".to_owned()))?;
        let mut entries = BTreeMap::new();
        if let Some(map) = value.get("entries").and_then(Value::as_object) {
            for (path, entry) in map {
                let size = entry.get("size").and_then(Value::as_u64).unwrap_or(0);
                let mtime = entry
                    .get("mtime_unix_nanos")
                    .and_then(Value::as_str)
                    .and_then(|text| text.parse::<i128>().ok())
                    .unwrap_or(0);
                let content_hash = entry
                    .get("content_hash")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                entries.insert(
                    path.clone(),
                    CachedEntry {
                        size,
                        mtime_unix_nanos: mtime,
                        content_hash,
                    },
                );
            }
        }
        Ok(Self {
            stamp_unix_nanos: stamp,
            entries,
        })
    }
}

#[cfg(feature = "native")]
fn mtime_unix_nanos(metadata: &std::fs::Metadata) -> i128 {
    metadata
        .modified()
        .ok()
        .and_then(|instant| {
            instant
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos() as i128)
                .ok()
        })
        .unwrap_or(0)
}

#[cfg(feature = "native")]
fn walk_files(
    root: &Path,
    prefix: &Path,
    out: &mut Vec<(String, std::fs::Metadata)>,
) -> std::io::Result<()> {
    for entry in std::fs::read_dir(prefix)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = entry.metadata()?;
        if metadata.is_dir() {
            walk_files(root, &path, out)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            out.push((relative, metadata));
        }
    }
    Ok(())
}

/// Scan `root` against the previous cache. `now_unix_nanos` becomes the
/// new cache's stamp (the caller's clock — the worker boundary owns time).
///
/// Trust rule, exactly the modeled sound importer: a file is trusted
/// (not re-read) iff its size+mtime fingerprint matches the previous
/// entry AND that mtime is STRICTLY older than the previous stamp;
/// a fingerprint match inside the racy granule is re-hashed.
#[cfg(feature = "native")]
pub fn scan_dir(
    root: &Path,
    previous: &StatCache,
    now_unix_nanos: i128,
) -> StoreResult<ScanOutcome> {
    let mut files = Vec::new();
    walk_files(root, root, &mut files)
        .map_err(|error| StoreError::Conflict(format!("scan {}: {error}", root.display())))?;

    let mut manifest = BTreeMap::new();
    let mut changed = BTreeMap::new();
    let mut entries = BTreeMap::new();
    let mut trusted = 0usize;
    let mut rehashed = 0usize;
    for (path, metadata) in files {
        let size = metadata.len();
        let mtime = mtime_unix_nanos(&metadata);
        let cached = previous.entries.get(&path);
        let trustable = cached.is_some_and(|entry| {
            entry.size == size
                && entry.mtime_unix_nanos == mtime
                && entry.mtime_unix_nanos < previous.stamp_unix_nanos
        });
        let content_hash = if trustable {
            trusted += 1;
            cached
                .expect("trustable implies cached")
                .content_hash
                .clone()
        } else {
            rehashed += 1;
            let bytes = std::fs::read(root.join(&path))
                .map_err(|error| StoreError::Conflict(format!("read {path}: {error}")))?;
            content_hash_hex(&bytes)
        };
        if cached.map(|entry| entry.content_hash.as_str()) != Some(content_hash.as_str()) {
            changed.insert(path.clone(), content_hash.clone());
        }
        entries.insert(
            path.clone(),
            CachedEntry {
                size,
                mtime_unix_nanos: mtime,
                content_hash: content_hash.clone(),
            },
        );
        manifest.insert(path, content_hash);
    }
    let removed = previous
        .entries
        .keys()
        .filter(|path| !manifest.contains_key(*path))
        .cloned()
        .collect();
    Ok(ScanOutcome {
        manifest,
        changed,
        removed,
        cache: StatCache {
            stamp_unix_nanos: now_unix_nanos,
            entries,
        },
        trusted,
        rehashed,
    })
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-stat-cache-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn now_nanos() -> i128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos() as i128
    }

    /// The O(touched) claim: a second scan over an unchanged tree trusts
    /// every fingerprint (mtimes are strictly older than the stamp) and
    /// re-hashes nothing; a touched file is re-read and reported.
    #[test]
    fn second_scan_trusts_unchanged_and_detects_touched() {
        let root = scratch("trust");
        std::fs::write(root.join("a.md"), "A0").expect("seed");
        std::fs::write(root.join("b.md"), "B0").expect("seed");
        // First scan: everything is new (re-hashed); stamp safely AFTER
        // the writes' mtime granule.
        let first =
            scan_dir(&root, &StatCache::default(), now_nanos() + 1_000_000_000).expect("scan");
        assert_eq!(first.rehashed, 2);
        assert_eq!(first.changed.len(), 2);
        // Second scan: nothing moved — the trust path carries both.
        let second = scan_dir(&root, &first.cache, now_nanos() + 2_000_000_000).expect("scan");
        assert_eq!(second.trusted, 2);
        assert_eq!(second.rehashed, 0);
        assert!(second.changed.is_empty());
        assert!(second.removed.is_empty());
        // A modified file (different size ⇒ fingerprint miss) is caught.
        std::fs::write(root.join("a.md"), "A1 longer").expect("modify");
        let third = scan_dir(&root, &second.cache, now_nanos() + 3_000_000_000).expect("scan");
        assert_eq!(third.changed.len(), 1);
        assert!(third.changed.contains_key("a.md"));
        assert_eq!(third.trusted, 1, "the untouched file stays trusted");
        let _ = std::fs::remove_dir_all(root);
    }

    /// THE soundness bite (stat-cache.maude, rejected at runtime): a
    /// same-size content change whose mtime is forced back into the
    /// cache's racy granule fools the fingerprint — the naive importer
    /// would trust and silently drop it; the racy-window rule re-hashes
    /// and detects it.
    #[test]
    fn racy_granule_same_size_change_is_never_missed() {
        let root = scratch("racy");
        let target = root.join("racy.md");
        std::fs::write(&target, "AAAA").expect("seed");
        let seeded_mtime = std::fs::metadata(&target)
            .expect("meta")
            .modified()
            .expect("mtime");
        // The cache was recorded IN the same granule as the write: stamp
        // equals the file's mtime (the hazard window).
        let seeded_nanos = seeded_mtime
            .duration_since(std::time::UNIX_EPOCH)
            .expect("epoch")
            .as_nanos() as i128;
        let first = scan_dir(&root, &StatCache::default(), seeded_nanos).expect("scan");
        assert_eq!(first.manifest.len(), 1);
        // Same-size content change, mtime forced back to the recorded
        // instant: the fingerprint is identical although the bytes differ.
        std::fs::write(&target, "BBBB").expect("tamper");
        let file = std::fs::File::options()
            .write(true)
            .open(&target)
            .expect("open");
        file.set_modified(seeded_mtime).expect("reset mtime");
        drop(file);
        let entry = &first.cache.entries["racy.md"];
        let metadata = std::fs::metadata(&target).expect("meta");
        assert_eq!(metadata.len(), entry.size, "fingerprint size matches");
        assert_eq!(
            mtime_unix_nanos(&metadata),
            entry.mtime_unix_nanos,
            "fingerprint mtime matches — the naive cache would trust this"
        );
        // The sound scan re-hashes the racy-granule entry and reports the
        // change.
        let second = scan_dir(&root, &first.cache, now_nanos() + 1_000_000_000).expect("scan");
        assert!(
            second.changed.contains_key("racy.md"),
            "the same-size-same-mtime change is detected, never dropped"
        );
        assert_eq!(second.rehashed, 1);
        assert_eq!(second.trusted, 0);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Deletions are reported; nested directories walk; the cache
    /// round-trips through JSON.
    #[test]
    fn removals_nesting_and_json_roundtrip() {
        let root = scratch("shape");
        std::fs::create_dir_all(root.join("sub")).expect("subdir");
        std::fs::write(root.join("sub/keep.md"), "K").expect("seed");
        std::fs::write(root.join("gone.md"), "G").expect("seed");
        let first =
            scan_dir(&root, &StatCache::default(), now_nanos() + 1_000_000_000).expect("scan");
        assert!(first.manifest.contains_key("sub/keep.md"));
        std::fs::remove_file(root.join("gone.md")).expect("remove");
        let restored = StatCache::from_json(&first.cache.to_json()).expect("roundtrip");
        assert_eq!(restored, first.cache);
        let second = scan_dir(&root, &restored, now_nanos() + 2_000_000_000).expect("scan");
        assert_eq!(second.removed, vec!["gone.md".to_owned()]);
        assert!(!second.manifest.contains_key("gone.md"));
        let _ = std::fs::remove_dir_all(root);
    }
}
