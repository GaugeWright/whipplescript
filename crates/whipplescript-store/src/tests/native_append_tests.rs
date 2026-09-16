use super::*;
use std::cell::RefCell;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

#[derive(Debug, PartialEq)]
enum Notice {
    WaitingForWrite,
    Returned,
}

thread_local! {
    static BUSY_NOTICE: RefCell<Option<Sender<Notice>>> = const { RefCell::new(None) };
}

fn report_busy(_: i32) -> bool {
    BUSY_NOTICE.with(|slot| {
        if let Some(sender) = slot.borrow_mut().take() {
            let _ = sender.send(Notice::WaitingForWrite);
        }
    });
    std::thread::yield_now();
    true
}

#[test]
fn append_waits_for_writer_before_observing_head() {
    for commit_repair in [true, false] {
        let dir = std::env::temp_dir().join(format!(
            "whip-append-head-{}-{}-{commit_repair}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("store.sqlite");
        let owner = SqliteStore::open(&path).unwrap();
        let follower = SqliteStore::open(&path).unwrap();
        owner
            .append_event(new_event("instance-a", "first", None))
            .unwrap();
        let digest: String = owner
            .connection
            .query_row(
                "SELECT entry_digest FROM events WHERE instance_id = 'instance-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        owner
            .connection
            .execute("UPDATE events SET entry_digest = NULL", [])
            .unwrap();
        let repair = rusqlite::Transaction::new_unchecked(
            &owner.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        repair
            .execute("UPDATE events SET entry_digest = ?1", [&digest])
            .unwrap();

        let (sender, receiver) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            BUSY_NOTICE.with(|slot| *slot.borrow_mut() = Some(sender.clone()));
            follower.connection.busy_handler(Some(report_busy)).unwrap();
            let result = follower.append_event(new_event("instance-a", "second", None));
            let _ = sender.send(Notice::Returned);
            (result, follower.connection.is_autocommit())
        });
        let first_notice = receiver.recv_timeout(Duration::from_secs(10));
        // Always release the writer before assertions, including when a mutant
        // returns early or fails to signal. No scheduling delay chooses the race.
        if commit_repair {
            repair.commit().unwrap();
        } else {
            repair.rollback().unwrap();
        }
        let (result, autocommit) = worker.join().unwrap();
        assert_eq!(first_notice.unwrap(), Notice::WaitingForWrite);
        assert!(autocommit, "append must release its own transaction");
        if commit_repair {
            assert_eq!(result.unwrap().sequence, 2);
            let head = owner.chain_head("instance-a").unwrap();
            assert_eq!(
                owner.list_events_pinned("instance-a", &head).unwrap().len(),
                2
            );
        } else {
            assert!(
                matches!(result, Err(StoreError::Conflict(message)) if message.contains("unchained"))
            );
            assert_eq!(owner.list_events("instance-a").unwrap().len(), 1);
        }
        drop(owner);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn append_preserves_caller_transaction_ownership() {
    let store = SqliteStore::open_in_memory().unwrap();
    for commit in [false, true] {
        let outer = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        assert_eq!(
            store
                .append_event(new_event("instance-a", "first", None))
                .unwrap()
                .sequence,
            1
        );
        assert!(!store.connection.is_autocommit());
        if commit {
            outer.commit().unwrap();
        } else {
            outer.rollback().unwrap();
        }
        assert_eq!(
            store.list_events("instance-a").unwrap().len(),
            usize::from(commit)
        );
    }
}

#[test]
fn owned_append_commits_and_releases_failed_transaction() {
    let store = SqliteStore::open_in_memory().unwrap();
    store
        .append_event(new_event("instance-a", "first", Some("one")))
        .unwrap();
    assert!(store.connection.is_autocommit());
    assert_eq!(store.list_events("instance-a").unwrap().len(), 1);
    let error = store
        .append_event(new_event("instance-a", "duplicate", Some("one")))
        .expect_err("a duplicate key must refuse");
    assert!(matches!(error, StoreError::Conflict(_)));
    assert!(store.connection.is_autocommit());
    assert_eq!(
        store
            .append_event(new_event("instance-a", "second", Some("two")))
            .unwrap()
            .sequence,
        2
    );
    let head = store.chain_head("instance-a").unwrap();
    assert_eq!(
        store.list_events_pinned("instance-a", &head).unwrap().len(),
        2
    );
}
