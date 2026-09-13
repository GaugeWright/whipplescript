use super::*;
use crate::vcs::tests::vcs;

#[test]
fn native_file_version_origin_preserves_immutable_history() {
    let mut roots = Vec::new();
    conformance::check(|| {
        let fixture = vcs();
        let workspace = crate::vcs::NativeWorkspaceVcs::open(
            fixture.dir.join("branches.sqlite"),
            fixture.dir.join("content.sqlite"),
        )
        .unwrap();
        roots.push(fixture);
        workspace
    });
}

#[test]
fn exact_version_reads_refuse_substituted_body_and_manifest_after_reopen() {
    for root_fault in [false, true] {
        let mut fixture = vcs();
        fixture.init("t0").unwrap();
        fixture
            .write("main", "note.txt", Some("original body"), "first", "t1")
            .unwrap();
        assert_eq!(
            fixture.read_at_cut("first", "note.txt").unwrap().as_deref(),
            Some("original body")
        );
        let id = if root_fault {
            fixture.get_cut("first").unwrap().unwrap().manifest_hash
        } else {
            crate::stable_hash_hex("original body")
        };
        let fault = rusqlite::Connection::open(fixture.dir.join("content.sqlite")).unwrap();
        let replacement = if root_fault { "{}" } else { "substituted body" };
        assert_eq!(
            fault
                .execute(
                    "UPDATE content_blobs SET body = ?1, byte_len = ?2 WHERE id = ?3",
                    rusqlite::params![replacement, i64::try_from(replacement.len()).unwrap(), id]
                )
                .unwrap(),
            1
        );
        drop(fault);
        let observer = crate::vcs::NativeWorkspaceVcs::open_read_only(
            fixture.dir.join("branches.sqlite"),
            fixture.dir.join("content.sqlite"),
        )
        .unwrap();
        assert!(observer.read_at_cut("first", "note.txt").is_err());
        if root_fault {
            assert!(observer
                .file_version_origin("first", "note.txt", NonZeroUsize::new(8).unwrap())
                .is_err());
        }
    }
}

#[test]
fn version_origin_refuses_missing_parent_and_stops_at_unexplained_entry_change() {
    for missing_parent in [false, true] {
        let mut fixture = vcs();
        fixture.init("t0").unwrap();
        fixture
            .write("main", "note.txt", Some("original"), "first", "t1")
            .unwrap();
        fixture
            .write("main", "note.txt", Some("changed"), "second", "t2")
            .unwrap();
        let fault = rusqlite::Connection::open(fixture.dir.join("branches.sqlite")).unwrap();
        assert_eq!(fault.execute("UPDATE cuts SET origin = 'write:other.txt', parent_cut_id = ?1 WHERE cut_id = 'second'",
            [if missing_parent { "missing" } else { "first" }]).unwrap(), 1);
        let observed =
            fixture.file_version_origin("second", "note.txt", NonZeroUsize::new(8).unwrap());
        if missing_parent {
            assert!(observed.is_err());
        } else {
            assert_eq!(
                observed.unwrap().source,
                FileVersionSource::Opaque {
                    cut_id: "second".into()
                }
            );
        }
    }
}

#[test]
fn version_origin_is_available_through_a_read_only_observer_without_body_access() {
    let mut fixture = vcs();
    fixture.init("t0").unwrap();
    fixture
        .write("main", "note.txt", Some("original"), "first", "t1")
        .unwrap();
    fixture
        .write("main", "other.txt", Some("other"), "second", "t2")
        .unwrap();
    fixture
        .content
        .erase(&crate::stable_hash_hex("original"), "t3")
        .unwrap();
    let observer = crate::vcs::NativeWorkspaceVcs::open_read_only(
        fixture.dir.join("branches.sqlite"),
        fixture.dir.join("content.sqlite"),
    )
    .unwrap();
    assert_eq!(
        observer
            .file_version_origin("second", "note.txt", NonZeroUsize::new(8).unwrap())
            .unwrap()
            .source,
        FileVersionSource::Write {
            cut_id: "first".into(),
            evidence: None
        }
    );
    assert!(observer.read_at_cut("second", "note.txt").is_err());
}
