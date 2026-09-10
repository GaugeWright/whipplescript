//! Immutable labeled result references committed with a write, not attached
//! after it. Prepared payloads are content-store data; only a committed row
//! roots the payload and establishes which result belongs to this cut.
use crate::{StoreError, StoreResult};
use serde::{Deserialize, Serialize};

pub const CREATE: &str = "CREATE TABLE IF NOT EXISTS cut_evidence (\
    cut_id TEXT PRIMARY KEY, schema_ref TEXT NOT NULL, label_ref TEXT NOT NULL, \
    content_hash TEXT NOT NULL)";
pub const INSERT: &str = "INSERT INTO cut_evidence \
    (cut_id, schema_ref, label_ref, content_hash) VALUES (?1, ?2, ?3, ?4)";
pub const SELECT: &str =
    "SELECT schema_ref, label_ref, content_hash FROM cut_evidence WHERE cut_id = ?1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteEvidenceRef {
    pub schema_ref: String,
    pub label_ref: String,
    pub content_hash: String,
}
impl WriteEvidenceRef {
    pub fn validate(&self) -> StoreResult<()> {
        if [&self.schema_ref, &self.label_ref, &self.content_hash]
            .iter()
            .any(|s| s.trim().is_empty())
        {
            return Err(StoreError::Conflict(
                "write evidence requires schema, label and content identity".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "native")]
pub(super) fn native_read(
    store: &super::BranchStore,
    cut_id: &str,
) -> StoreResult<Option<WriteEvidenceRef>> {
    use rusqlite::OptionalExtension;
    store
        .connection
        .query_row(SELECT, [cut_id], |row| {
            Ok(WriteEvidenceRef {
                schema_ref: row.get(0)?,
                label_ref: row.get(1)?,
                content_hash: row.get(2)?,
            })
        })
        .optional()
        .map_err(Into::into)
}

/// Shared transaction conformance, with the actual host's branch backend.
pub mod conformance {
    use super::*;
    use crate::branches::{
        write_commit::conformance::cut, AdvanceOutcome, Branches, MAINLINE_BRANCH_ID,
    };

    pub fn reference() -> WriteEvidenceRef {
        WriteEvidenceRef {
            schema_ref: "operation.result.v1".into(),
            label_ref: "private".into(),
            content_hash: "retained-result".into(),
        }
    }
    pub fn check(store: &mut impl Branches) {
        let before = store.ensure_mainline("t0").expect("init");
        let reference = reference();
        for field in ["schema", "label", "content"] {
            let mut invalid = reference.clone();
            match field {
                "schema" => invalid.schema_ref.clear(),
                "label" => invalid.label_ref.clear(),
                _ => invalid.content_hash.clear(),
            }
            let error = store
                .commit_write_with_evidence(cut("bad", None), Some(&invalid))
                .expect_err("incomplete reference");
            assert!(format!("{error:?}")
                .contains("write evidence requires schema, label and content identity"));
            assert!(store.write_evidence("bad").expect("query").is_none());
            assert!(store.get_cut("bad").expect("query").is_none());
            assert!(store.get_op("op-bad").expect("query").is_none());
            assert_eq!(
                store.get_branch(MAINLINE_BRANCH_ID).expect("query"),
                Some(before.clone())
            );
        }
        assert!(matches!(
            store
                .commit_write_with_evidence(cut("first", None), Some(&reference))
                .expect("commit"),
            AdvanceOutcome::Advanced(_)
        ));
        assert_eq!(
            store.write_evidence("first").expect("query"),
            Some(reference.clone())
        );
        let changed = WriteEvidenceRef {
            content_hash: "different".into(),
            ..reference.clone()
        };
        assert!(store
            .commit_write_with_evidence(cut("first", Some("first")), Some(&changed))
            .is_err());
        assert_eq!(
            store.write_evidence("first").expect("immutable ref"),
            Some(reference)
        );
        assert!(matches!(
            store
                .commit_write(cut("legacy", Some("first")))
                .expect("legacy write"),
            AdvanceOutcome::Advanced(_)
        ));
        assert!(store
            .write_evidence("legacy")
            .expect("legacy has no claim")
            .is_none());
        assert!(store
            .write_evidence("missing")
            .expect("missing ref")
            .is_none());
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::branches::{
        write_commit::conformance::cut, AdvanceOutcome, BranchStore, Branches, MAINLINE_BRANCH_ID,
    };

    #[test]
    fn native_write_evidence_conformance() {
        conformance::check(&mut BranchStore::open_in_memory().expect("branches"));
    }
    #[test]
    fn write_evidence_is_atomic_at_every_mutation_and_is_a_retention_root() {
        for (table, verb) in [
            ("cuts", "INSERT"),
            ("branches", "UPDATE"),
            ("ops", "INSERT"),
            ("cut_evidence", "INSERT"),
        ] {
            for moment in ["BEFORE", "AFTER"] {
                let mut store = BranchStore::open_in_memory().expect("store");
                let before = store.ensure_mainline("t0").expect("init");
                store.connection.execute_batch(&format!("CREATE TRIGGER fail_evidence {moment} {verb} ON {table} BEGIN SELECT RAISE(ABORT, 'evidence fault'); END")).expect("inject");
                assert!(
                    store
                        .commit_write_with_evidence(
                            cut("first", None),
                            Some(&conformance::reference())
                        )
                        .is_err(),
                    "{moment} {table}"
                );
                assert_eq!(
                    store.get_branch(MAINLINE_BRANCH_ID).expect("branch"),
                    Some(before)
                );
                assert!(store.get_cut("first").expect("cut").is_none());
                assert!(store.get_op("op-first").expect("op").is_none());
                assert!(store.write_evidence("first").expect("evidence").is_none());
                store
                    .connection
                    .execute_batch("DROP TRIGGER fail_evidence")
                    .expect("disarm");
                assert!(matches!(
                    store
                        .commit_write_with_evidence(
                            cut("first", None),
                            Some(&conformance::reference())
                        )
                        .expect("commit"),
                    AdvanceOutcome::Advanced(_)
                ));
                assert!(store
                    .reachability_roots()
                    .expect("roots")
                    .contains("retained-result"));
            }
        }
    }
    #[test]
    fn a_writer_without_evidence_retention_cannot_reopen_the_new_branch_schema() {
        let store = BranchStore::open_in_memory().expect("current branch schema");
        assert!(matches!(
            crate::stamp_satellite_schema(&store.connection, "branch", 1),
            Err(StoreError::UnsupportedVersion {
                found: 4,
                supported: 1,
                ..
            })
        ));
    }
}
