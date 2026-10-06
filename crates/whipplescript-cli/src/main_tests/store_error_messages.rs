//! How a store failure reads to the person who ran whip. Contention and a
//! store a newer whip changed are not defects, so neither may say "whip bug".

use super::store_error;
use whipplescript_store::StoreError;

fn sqlite(code: i32) -> StoreError {
    StoreError::Sqlite(rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(code),
        None,
    ))
}

#[test]
fn a_busy_or_locked_store_is_reported_as_busy() {
    for code in [rusqlite::ffi::SQLITE_BUSY, rusqlite::ffi::SQLITE_LOCKED] {
        let StoreError::Sqlite(cause) = sqlite(code) else {
            unreachable!()
        };
        let sqlite_words = cause.to_string();
        let message = store_error(StoreError::Sqlite(cause));
        assert!(
            message.starts_with("the store is busy: another whip held its write lock"),
            "{message}"
        );
        assert!(message.contains("Run the command again"), "{message}");
        // SQLite's own words stay, beside the advice.
        assert!(message.contains(&sqlite_words), "{message}");
        assert!(!message.contains("whip bug"), "{message}");
    }
}

#[test]
fn any_other_sqlite_failure_is_still_a_whip_bug() {
    let message = store_error(sqlite(rusqlite::ffi::SQLITE_CORRUPT));
    assert!(message.contains("this is a whip bug"), "{message}");
}
