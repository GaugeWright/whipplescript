//! Durable identity of one runtime store incarnation (DR-0150, RC-2).
//!
//! A Home operation points at an exact target store as well as an operation
//! row. The path or Durable Object name can be reused after deletion, so it
//! cannot identify the same store across recovery. This random identity is
//! minted once in the target database and retained on reopen or full restore.
//! It is an identity, not a secret or proof of Home authority; the Home must
//! bind it and still verify the exact operation and witness before use.

use crate::{StoreError, StoreResult};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS runtime_store_incarnation (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    incarnation_id TEXT NOT NULL CHECK (length(incarnation_id) = 32)
);
INSERT OR IGNORE INTO runtime_store_incarnation (id, incarnation_id)
    VALUES (1, lower(hex(randomblob(16))));
CREATE TRIGGER IF NOT EXISTS runtime_store_incarnation_no_update
    BEFORE UPDATE ON runtime_store_incarnation
    BEGIN SELECT RAISE(ABORT, 'runtime store incarnation is immutable'); END;
CREATE TRIGGER IF NOT EXISTS runtime_store_incarnation_no_delete
    BEFORE DELETE ON runtime_store_incarnation
    BEGIN SELECT RAISE(ABORT, 'runtime store incarnation is immutable'); END;";

pub fn validate(value: &str) -> StoreResult<()> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(StoreError::Conflict(
            "malformed runtime store incarnation identity".into(),
        ));
    }
    Ok(())
}
