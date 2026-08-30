//! Virtual working set: the sandbox-mediated per-branch file surface
//! (spec/versioned-workspace-research-note.md §4, §10; untie-substrate
//! readiness tracker Phase 1).
//!
//! A branch's file surface is a view: reads resolve through the branch's
//! head manifest into the content-addressed blob store; writes and
//! deletes land copy-on-write in a branch-local overlay without touching
//! any other branch, the base manifest, or a real directory. A hundred
//! concurrent branches cost a hundred manifests plus their actual
//! divergent writes — identical bodies dedupe to one blob. The folded
//! `manifest()` is what a cut records and `Branches::advance_head`
//! points at; two working sets' manifests plus their base feed
//! `merge::merge_manifests` directly.
//!
//! Implements the `FileStore` seam, so the existing `file.*` effect
//! handlers run against a branch surface unchanged (the effect handler
//! keeps owning path policy; `path_policy_error` stays the virtual
//! default — no host symlinks are traversed here). Deletes are recorded
//! outcomes (a tombstone in the overlay), not absences, so `manifest()`
//! reflects them and restore/merge see the delete.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

use crate::content::ContentBlobs;
use crate::files::FileStore;

pub struct VirtualWorkingSet<'a> {
    content: &'a dyn ContentBlobs,
    /// The branch head's manifest (path → content id), fixed at open.
    base: BTreeMap<String, String>,
    /// Branch-local divergence: `Some(id)` = written, `None` = deleted.
    overlay: RefCell<BTreeMap<String, Option<String>>>,
}

impl<'a> VirtualWorkingSet<'a> {
    pub fn new(content: &'a dyn ContentBlobs, base_manifest: BTreeMap<String, String>) -> Self {
        Self {
            content,
            base: base_manifest,
            overlay: RefCell::new(BTreeMap::new()),
        }
    }

    fn key(path: &Path) -> String {
        path.to_string_lossy().into_owned()
    }

    fn resolve(&self, path: &Path) -> Option<String> {
        let key = Self::key(path);
        match self.overlay.borrow().get(&key) {
            Some(Some(id)) => Some(id.clone()),
            Some(None) => None,
            None => self.base.get(&key).cloned(),
        }
    }

    /// The branch's current manifest: base + overlay folded. This is the
    /// content of the next cut.
    pub fn manifest(&self) -> BTreeMap<String, String> {
        let mut manifest = self.base.clone();
        for (path, entry) in self.overlay.borrow().iter() {
            match entry {
                Some(id) => {
                    manifest.insert(path.clone(), id.clone());
                }
                None => {
                    manifest.remove(path);
                }
            }
        }
        manifest
    }

    /// A working set with NO base, for a caller that only needs to record what
    /// it changed.
    ///
    /// `write` and `remove` never consult the base — they put a blob and record
    /// an overlay entry — so a caller producing a change set for
    /// `manifest_tree::apply` does not need the branch's manifest materialized,
    /// which is the whole point (DR-0066 §8 refusal 2). Reads DO consult it, so
    /// on a detached set every path resolves to nothing: `read_to_string` and
    /// `append` are not usable here, and that is deliberate rather than an
    /// oversight to be patched later.
    pub fn detached(content: &'a dyn ContentBlobs) -> Self {
        Self::new(content, BTreeMap::new())
    }

    /// The overlay itself: path to `Some(id)` written or `None` removed.
    ///
    /// What [`Self::manifest`] folds into the base. A caller that is about to
    /// write a manifest tree wants the CHANGES rather than the fold, because
    /// applying them costs the change and folding costs the workspace
    /// (DR-0066 §8 refusal 2).
    pub fn changes(&self) -> BTreeMap<String, Option<String>> {
        self.overlay.borrow().clone()
    }

    /// How many paths this branch has diverged on (writes + deletes) —
    /// the actual cost of the branch beyond its pointers.
    pub fn divergence(&self) -> usize {
        self.overlay.borrow().len()
    }
}

fn store_error(error: crate::StoreError) -> io::Error {
    io::Error::other(format!("content store: {error:?}"))
}

impl FileStore for VirtualWorkingSet<'_> {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        let Some(id) = self.resolve(path) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no file at {} on this branch", path.display()),
            ));
        };
        match self.content.get(&id).map_err(store_error)? {
            Some(body) => Ok(body),
            None => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "manifest names content {id} for {} but the blob is absent",
                    path.display()
                ),
            )),
        }
    }

    fn exists(&self, path: &Path) -> bool {
        self.resolve(path).is_some()
    }

    fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
        // The working set is a flat path→content namespace; directories
        // exist implicitly.
        Ok(())
    }

    fn write(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let body = std::str::from_utf8(bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-UTF-8 write to {}: {error}", path.display()),
            )
        })?;
        let id = self.content.put(body).map_err(store_error)?;
        self.overlay.borrow_mut().insert(Self::key(path), Some(id));
        Ok(())
    }

    fn append(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let existing = match self.read_to_string(path) {
            Ok(body) => body,
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error),
        };
        let suffix = std::str::from_utf8(bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-UTF-8 append to {}: {error}", path.display()),
            )
        })?;
        let mut body = existing;
        body.push_str(suffix);
        self.write(path, body.as_bytes())
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        // Idempotent tombstone; removing an absent path is a no-op at the
        // surface but still records nothing new (the manifest fold treats
        // a tombstone over an absent base entry as absent).
        self.overlay.borrow_mut().insert(Self::key(path), None);
        Ok(())
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::content::ContentStore;
    use crate::merge::{merge_manifests, MergeOutcome, MergeSide};

    /// A content store whose temp directory dies with it, panic included.
    /// `Deref`/`DerefMut` keep the call sites unchanged. Owning the directory
    /// rather than the `.sqlite` file also reclaims the `-shm`/`-wal`
    /// sidecars.
    struct TempContent {
        dir: std::path::PathBuf,
        inner: ContentStore,
    }

    impl std::ops::Deref for TempContent {
        type Target = ContentStore;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl std::ops::DerefMut for TempContent {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    impl Drop for TempContent {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn content() -> TempContent {
        let dir = std::env::temp_dir().join(format!(
            "whipplescript-working-set-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).expect("create working-set temp dir");
        let inner = ContentStore::open(dir.join("content.sqlite")).expect("open content store");
        TempContent { dir, inner }
    }

    fn seeded_base(content: &ContentStore) -> BTreeMap<String, String> {
        let mut base = BTreeMap::new();
        base.insert("notes/a.md".to_owned(), content.put("base A").expect("put"));
        base.insert("notes/b.md".to_owned(), content.put("base B").expect("put"));
        base
    }

    /// Reads resolve through the manifest; writes land copy-on-write:
    /// the branch sees its own write, a sibling over the same base does
    /// not, and the base manifest never changes.
    #[test]
    fn copy_on_write_isolation() {
        let content = content();
        let base = seeded_base(&content);
        let ours = VirtualWorkingSet::new(&*content, base.clone());
        let sibling = VirtualWorkingSet::new(&*content, base.clone());

        assert_eq!(
            ours.read_to_string(Path::new("notes/a.md")).expect("read"),
            "base A"
        );
        ours.write(Path::new("notes/a.md"), b"ours A")
            .expect("write");
        ours.write(Path::new("new.md"), b"ours new").expect("write");

        assert_eq!(
            ours.read_to_string(Path::new("notes/a.md")).expect("read"),
            "ours A"
        );
        assert_eq!(
            sibling
                .read_to_string(Path::new("notes/a.md"))
                .expect("read"),
            "base A",
            "a sibling branch never sees the divergent write"
        );
        assert!(!sibling.exists(Path::new("new.md")));
        assert_eq!(ours.divergence(), 2);
        assert_eq!(sibling.divergence(), 0);
        assert_eq!(
            ours.manifest().get("notes/b.md"),
            base.get("notes/b.md"),
            "untouched paths share the base blob pointer"
        );
    }

    /// Deletes are recorded outcomes: the surface loses the file and the
    /// folded manifest drops it, while the base stays intact.
    #[test]
    fn deletes_are_tombstoned_outcomes() {
        let content = content();
        let base = seeded_base(&content);
        let set = VirtualWorkingSet::new(&*content, base.clone());
        set.remove(Path::new("notes/a.md")).expect("remove");
        assert!(!set.exists(Path::new("notes/a.md")));
        assert!(set
            .read_to_string(Path::new("notes/a.md"))
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound));
        assert!(!set.manifest().contains_key("notes/a.md"));
        assert!(base.contains_key("notes/a.md"));
        // Idempotent.
        set.remove(Path::new("notes/a.md")).expect("remove again");
    }

    /// Append composes read + write; identical bodies on two branches
    /// dedupe to one content id.
    #[test]
    fn append_composes_and_identical_bodies_share_blobs() {
        let content = content();
        let base = seeded_base(&content);
        let ours = VirtualWorkingSet::new(&*content, base.clone());
        let theirs = VirtualWorkingSet::new(&*content, base);
        ours.append(Path::new("notes/a.md"), b" + more")
            .expect("append");
        assert_eq!(
            ours.read_to_string(Path::new("notes/a.md")).expect("read"),
            "base A + more"
        );
        ours.append(Path::new("log.txt"), b"line")
            .expect("append creates");
        theirs
            .write(Path::new("other.md"), b"same body")
            .expect("write");
        ours.write(Path::new("mine.md"), b"same body")
            .expect("write");
        assert_eq!(
            ours.manifest().get("mine.md"),
            theirs.manifest().get("other.md"),
            "identical bodies dedupe to one blob id"
        );
    }

    /// The integration payoff: two branches' folded manifests plus their
    /// shared base feed the merge engine — disjoint divergence certifies
    /// clean and both writes land; a divergent same-path pair escalates.
    #[test]
    fn working_set_manifests_feed_the_merge_engine() {
        let content = content();
        let base = seeded_base(&content);
        let ours = VirtualWorkingSet::new(&*content, base.clone());
        let theirs = VirtualWorkingSet::new(&*content, base.clone());
        ours.write(Path::new("notes/a.md"), b"ours A")
            .expect("write");
        theirs
            .write(Path::new("notes/b.md"), b"theirs B")
            .expect("write");
        let ours_side = MergeSide {
            label: "draft_a".to_owned(),
            cut_id: Some("cut_a1".to_owned()),
        };
        let theirs_side = MergeSide {
            label: "main".to_owned(),
            cut_id: Some("cut_m2".to_owned()),
        };
        let outcome = merge_manifests(
            &base,
            &ours.manifest(),
            &theirs.manifest(),
            &ours_side,
            &theirs_side,
        );
        let MergeOutcome::Clean { manifest } = outcome else {
            panic!("disjoint branch divergence merges clean");
        };
        assert_eq!(
            content
                .get(manifest.get("notes/a.md").expect("a"))
                .expect("get")
                .as_deref(),
            Some("ours A")
        );
        assert_eq!(
            content
                .get(manifest.get("notes/b.md").expect("b"))
                .expect("get")
                .as_deref(),
            Some("theirs B")
        );

        // Same-path divergence escalates instead.
        theirs
            .write(Path::new("notes/a.md"), b"theirs A")
            .expect("write");
        let outcome = merge_manifests(
            &base,
            &ours.manifest(),
            &theirs.manifest(),
            &ours_side,
            &theirs_side,
        );
        assert!(matches!(outcome, MergeOutcome::Conflicted { .. }));
    }
}
