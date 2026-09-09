//! Observation cannot initialize storage, become a writer, or ignore live WAL.
#![cfg(feature = "native")]

use std::path::PathBuf;
use whipplescript_store::{
    branches::{BranchStore, Branches, MAINLINE_BRANCH_ID},
    content::{ContentBlobs, ContentStore},
    vcs::NativeWorkspaceVcs,
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("whipple-read-only-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).expect("fixture directory");
        Self(root)
    }
    fn branches(&self) -> PathBuf {
        self.0.join("branches.sqlite")
    }
    fn content(&self) -> PathBuf {
        self.0.join("content.sqlite")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn observers_never_create_missing_stores_or_parent_directories() {
    let fixture = Fixture::new();
    for root in [fixture.0.clone(), fixture.0.join("missing-parent")] {
        let branches = root.join("branches.sqlite");
        let content = root.join("content.sqlite");
        assert!(BranchStore::open_read_only(&branches).is_err());
        assert!(ContentStore::open_read_only(&content).is_err());
        assert!(NativeWorkspaceVcs::open_read_only(&branches, &content).is_err());
        assert!(!branches.exists());
        assert!(!content.exists());
    }
    assert!(!fixture.0.join("missing-parent").exists());
}

#[test]
fn observers_do_not_initialize_an_existing_empty_schema() {
    let fixture = Fixture::new();
    for path in [fixture.branches(), fixture.content()] {
        rusqlite::Connection::open(&path).expect("empty database");
    }
    let branches =
        BranchStore::open_read_only(fixture.branches()).expect("read-only branch handle");
    let content =
        ContentStore::open_read_only(fixture.content()).expect("read-only content handle");
    assert!(branches.get_branch(MAINLINE_BRANCH_ID).is_err());
    assert!(content.get("unknown").is_err());
    for path in [fixture.branches(), fixture.content()] {
        let db =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .expect("inspect schema");
        let tables: i64 = db
            .query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| row.get(0))
            .expect("schema count");
        assert_eq!(tables, 0, "observation must not initialize or migrate");
    }
}

#[test]
fn observer_reads_committed_wal_and_exact_cuts_but_cannot_write_or_erase() {
    let fixture = Fixture::new();
    let mut writer =
        NativeWorkspaceVcs::open(fixture.branches(), fixture.content()).expect("writer");
    writer.init("t0").expect("initialize");
    writer
        .write(
            MAINLINE_BRANCH_ID,
            "note.txt",
            Some("original"),
            "base",
            "t1",
        )
        .expect("base");
    let mut observer = NativeWorkspaceVcs::open_read_only(fixture.branches(), fixture.content())
        .expect("observer");
    assert_eq!(
        observer
            .read_at_cut("base", "note.txt")
            .expect("base read")
            .as_deref(),
        Some("original")
    );
    writer
        .write(MAINLINE_BRANCH_ID, "note.txt", Some("newer"), "next", "t2")
        .expect("advance while observed");
    let head = observer
        .get_branch(MAINLINE_BRANCH_ID)
        .expect("live head")
        .expect("mainline");
    assert_eq!(head.head_cut_id.as_deref(), Some("next"));
    assert_eq!(
        observer
            .read_at_cut("next", "note.txt")
            .expect("new WAL content")
            .as_deref(),
        Some("newer")
    );
    assert_eq!(
        observer
            .read_at_cut("base", "note.txt")
            .expect("exact old cut")
            .as_deref(),
        Some("original")
    );
    assert!(observer
        .write(
            MAINLINE_BRANCH_ID,
            "note.txt",
            Some("forbidden"),
            "unlogged",
            "t3"
        )
        .is_err());
    assert!(observer
        .create_branch("unlogged-branch", None, MAINLINE_BRANCH_ID, "t3")
        .is_err());
    assert!(observer.content_store().put_text("forbidden").is_err());
    let original_hash = whipplescript_store::stable_hash_hex("original");
    assert!(observer
        .content_store()
        .erase(&original_hash, "t3")
        .is_err());
    assert_eq!(
        writer
            .get_branch(MAINLINE_BRANCH_ID)
            .expect("unchanged head"),
        Some(head)
    );
    assert!(writer
        .get_branch("unlogged-branch")
        .expect("no branch")
        .is_none());
    assert!(writer.get_cut("unlogged").expect("no cut").is_none());
    assert!(writer
        .content_store()
        .get(&whipplescript_store::stable_hash_hex("forbidden"))
        .expect("no body")
        .is_none());
    writer
        .content_store()
        .erase(&original_hash, "t4")
        .expect("authorized erasure");
    assert!(
        observer.read_at_cut("base", "note.txt").is_err(),
        "erasure cannot fall back to the newer head"
    );
}
