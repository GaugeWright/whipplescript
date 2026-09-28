//! Exact, per-admission import evidence (DR-0131, RC-2).
//!
//! A program version can be reused under a changed package lock. Each
//! accepting operation therefore retains its own immutable witness basis;
//! absence of a row remains unknown, never an empty import set.

use serde::{Deserialize, Serialize};

use crate::{StoreError, StoreResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramImportEdge {
    pub import: String,
    pub package_id: String,
    pub version: String,
    pub source_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProgramImportWitness {
    pub program_source_digest: String,
    pub lock_digest: String,
    pub compiler_artifact_digest: String,
    pub examined: Vec<String>,
    pub edges: Vec<ProgramImportEdge>,
    pub edge_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramImportAdmissionRecord {
    pub program_id: String,
    pub version_id: String,
    pub witness_digest: String,
}

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS program_import_admissions (
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    witness_digest TEXT NOT NULL,
    witness_json TEXT NOT NULL,
    PRIMARY KEY (version_id, witness_digest)
)";

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Native program source ids are the first 128 bits of SHA-256 over the same
/// bytes; hosted versions already retain all 256 bits. The witness keeps the
/// full digest, so either stored form binds to those exact source bytes.
pub fn matches_source_id(witness: &ProgramImportWitness, source_id: &str) -> bool {
    matches!(source_id.len(), 32 | 64)
        && source_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && if source_id.len() == 32 {
            witness.program_source_digest.starts_with(source_id)
        } else {
            witness.program_source_digest == source_id
        }
}

/// Check the witness's internal structure before it is retained. The compiler
/// boundary is responsible for proving that `examined` really is every
/// applicable import in the checked IR.
pub fn encode(witness: &ProgramImportWitness) -> StoreResult<(String, String)> {
    for (label, digest) in [
        ("program source", witness.program_source_digest.as_str()),
        ("package lock", witness.lock_digest.as_str()),
        (
            "compiler artifact",
            witness.compiler_artifact_digest.as_str(),
        ),
        ("edge set", witness.edge_digest.as_str()),
    ] {
        if !is_digest(digest) {
            return Err(StoreError::Conflict(format!(
                "import witness {label} lacks an exact lowercase SHA-256 digest"
            )));
        }
    }
    if witness.examined.iter().any(|name| name.is_empty())
        || witness.examined.windows(2).any(|pair| pair[0] >= pair[1])
        || witness.examined.len() != witness.edges.len()
        || witness
            .examined
            .iter()
            .zip(&witness.edges)
            .any(|(name, edge)| {
                edge.import != *name
                    || edge.package_id.is_empty()
                    || edge.version.is_empty()
                    || !is_digest(&edge.source_digest)
            })
    {
        return Err(StoreError::Conflict(
            "import witness has incomplete or unordered edges".into(),
        ));
    }
    let edge_json = serde_json::to_string(&witness.edges)?;
    if crate::items::sha256_hex(&edge_json) != witness.edge_digest {
        return Err(StoreError::Conflict(
            "import witness edge digest differs from its edges".into(),
        ));
    }
    let json = serde_json::to_string(witness)?;
    let digest = crate::items::sha256_hex(&json);
    Ok((digest, json))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use crate::{NewProgramVersion, SqliteStore};

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SOURCE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEXT_LOCK: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const COMPILER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn version(name: &'static str) -> NewProgramVersion<'static> {
        NewProgramVersion {
            program_name: name,
            source_hash: SOURCE_ID,
            ir_hash: COMPILER,
            compiler_version: "test-compiler",
            ir_snapshot: None,
            declared_capabilities_json: "[]",
            declared_profiles_json: "[]",
            declared_skills_json: "[]",
            declared_schemas_json: "[]",
            analysis_summary_json: "{}",
            generated_artifacts_json: "[]",
            artifact_root: None,
        }
    }

    fn witness(lock: &str) -> ProgramImportWitness {
        let edges = vec![ProgramImportEdge {
            import: "local.paint".into(),
            package_id: "pkg-paint".into(),
            version: "1".into(),
            source_digest: SOURCE.into(),
        }];
        ProgramImportWitness {
            program_source_digest: SOURCE.into(),
            lock_digest: lock.into(),
            compiler_artifact_digest: COMPILER.into(),
            examined: vec!["local.paint".into()],
            edge_digest: crate::items::sha256_hex(
                &serde_json::to_string(&edges).expect("fixture edge JSON"),
            ),
            edges,
        }
    }

    #[test]
    fn full_source_digest_binds_the_runtime_content_id() {
        let source = "use local.paint\nworkflow Paint\n";
        let mut witness = witness(LOCK);
        witness.program_source_digest = crate::items::sha256_hex(source);
        assert!(matches_source_id(&witness, &crate::stable_hash_hex(source)));
        assert!(matches_source_id(&witness, &witness.program_source_digest));
        assert!(!matches_source_id(&witness, ""));
        assert!(!matches_source_id(&witness, SOURCE_ID));
        assert!(!matches_source_id(&witness, SOURCE));
        assert!(!matches_source_id(
            &witness,
            &witness.program_source_digest[..63]
        ));
    }

    #[test]
    fn malformed_digest_and_incomplete_edge_set_refuse_encoding() {
        let mut malformed = witness(LOCK);
        malformed.compiler_artifact_digest = "short".into();
        assert!(matches!(
            encode(&malformed),
            Err(StoreError::Conflict(message)) if message.contains("exact lowercase SHA-256 digest")
        ));
        let mut incomplete = witness(LOCK);
        incomplete.examined.push("local.unresolved".into());
        assert!(matches!(
            encode(&incomplete),
            Err(StoreError::Conflict(message)) if message.contains("incomplete or unordered edges")
        ));
    }

    #[test]
    fn exact_import_admissions_are_immutable_per_basis_even_when_version_is_reused() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let first_witness = witness(LOCK);
        let full_source = store
            .create_program_version_with_import_witness(
                NewProgramVersion {
                    source_hash: SOURCE,
                    ..version("hosted-full-source")
                },
                &first_witness,
            )
            .unwrap();
        assert_eq!(
            store
                .program_import_witness(&full_source.version_id, &full_source.witness_digest)
                .unwrap(),
            Some(first_witness.clone())
        );
        let first = store
            .create_program_version_with_import_witness(version("paint"), &first_witness)
            .unwrap();
        assert_eq!(
            store
                .program_import_witness(&first.version_id, &first.witness_digest)
                .unwrap(),
            Some(first_witness.clone())
        );
        let repeated = store
            .create_program_version_with_import_witness(version("paint"), &first_witness)
            .unwrap();
        assert_eq!(repeated, first);

        let changed_lock = witness(NEXT_LOCK);
        let second = store
            .create_program_version_with_import_witness(version("paint"), &changed_lock)
            .unwrap();
        assert_eq!(second.version_id, first.version_id);
        assert_ne!(second.witness_digest, first.witness_digest);
        assert_eq!(
            store
                .program_import_witness(&second.version_id, &second.witness_digest)
                .unwrap(),
            Some(changed_lock)
        );
        assert_eq!(
            store
                .program_import_witness(&first.version_id, &first.witness_digest)
                .unwrap(),
            Some(first_witness)
        );
        let rows: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM program_import_admissions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rows, 3);
        store
            .connection
            .execute(
                "UPDATE program_versions SET source_hash = ?1 WHERE version_id = ?2",
                rusqlite::params!["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", &first.version_id],
            )
            .unwrap();
        assert!(matches!(
            store.program_import_witness(&first.version_id, &first.witness_digest),
            Err(StoreError::Conflict(message)) if message.contains("differs from its version")
        ));
    }

    #[test]
    fn bad_import_witness_rolls_back_the_program_version() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let mut bad = witness(LOCK);
        bad.edge_digest = NEXT_LOCK.into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("bad"), &bad),
            Err(StoreError::Conflict(message)) if message.contains("edge digest differs")
        ));
        let mut wrong_source = witness(LOCK);
        wrong_source.program_source_digest = NEXT_LOCK.into();
        assert!(matches!(
            store.create_program_version_with_import_witness(version("wrong-source"), &wrong_source),
            Err(StoreError::Conflict(message)) if message.contains("program source differs")
        ));
        let rows: i64 = store
            .connection
            .query_row("SELECT COUNT(*) FROM program_versions", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 0);
    }
}
