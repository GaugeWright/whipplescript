//! Exact, per-admission import evidence (DR-0131, RC-2).
//!
//! A program version can be reused under a changed package lock. Checked
//! version creation retains an immutable witness basis, while each call to
//! the version-creation API records a separate operation. A changed-IR
//! re-attestation records an unwitnessed operation. Other accepting paths
//! still need coverage before this population can describe a Home.

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
    /// Present when a version's source id hashes a larger checked identity
    /// that contains the exact program source (for example an authored host
    /// package). Older and direct-source witnesses use program_source_digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_source_digest: Option<String>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProgramImportOperationKind {
    Checked,
    Unwitnessed,
    LegacyGap,
}

impl TryFrom<&str> for ProgramImportOperationKind {
    type Error = StoreError;

    fn try_from(value: &str) -> StoreResult<Self> {
        match value {
            "checked" => Ok(Self::Checked),
            "unwitnessed" => Ok(Self::Unwitnessed),
            "legacy-gap" => Ok(Self::LegacyGap),
            other => Err(StoreError::Conflict(format!(
                "unknown program import operation kind {other}"
            ))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramImportOperation {
    pub sequence: i64,
    pub operation_id: String,
    pub version_id: String,
    pub witness_digest: Option<String>,
    pub kind: ProgramImportOperationKind,
}

impl ProgramImportOperation {
    /// Decode persisted evidence without turning malformed rows into a
    /// checked operation. Both store backends use this read boundary.
    pub fn from_stored_row(
        sequence: i64,
        operation_id: String,
        version_id: String,
        witness_digest: Option<String>,
        kind: &str,
    ) -> StoreResult<Self> {
        let kind = kind.try_into()?;
        if sequence <= 0
            || operation_id.is_empty()
            || version_id.is_empty()
            || (kind == ProgramImportOperationKind::Checked) != witness_digest.is_some()
            || witness_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
        {
            return Err(StoreError::Conflict(
                "malformed program import operation row".into(),
            ));
        }
        Ok(Self {
            sequence,
            operation_id,
            version_id,
            witness_digest,
            kind,
        })
    }
}

/// One store's observed operation population at a monotone sequence frontier.
/// This read does not establish that every Home accepting path writes the
/// ledger, or that a checked witness still matches current source inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProgramImportOperationRoster {
    pub frontier: i64,
    pub operations: Vec<ProgramImportOperation>,
}

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS program_import_admissions (
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    witness_digest TEXT NOT NULL,
    witness_json TEXT NOT NULL,
    PRIMARY KEY (version_id, witness_digest)
)";

/// One row per version-creation call or changed-IR re-attestation, including
/// repeated calls returning the same version. Existing stores cannot reconstruct old calls;
/// their migration records a conservative unknown gap for every old version.
pub const OPERATIONS_SCHEMA: &str = "CREATE TABLE IF NOT EXISTS program_import_operations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    witness_digest TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('checked', 'unwitnessed', 'legacy-gap')),
    FOREIGN KEY (version_id, witness_digest)
        REFERENCES program_import_admissions(version_id, witness_digest),
    CHECK ((kind = 'checked') = (witness_digest IS NOT NULL))
)";

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Native direct-source ids may be the first 128 bits of SHA-256; hosted ones
/// retain all 256 bits. A host package may instead hash a checked composite
/// identity containing those source bytes. The witness retains both digests.
pub fn matches_source_id(witness: &ProgramImportWitness, source_id: &str) -> bool {
    let version_source = witness
        .version_source_digest
        .as_deref()
        .unwrap_or(&witness.program_source_digest);
    matches!(source_id.len(), 32 | 64)
        && source_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && if source_id.len() == 32 {
            version_source.starts_with(source_id)
        } else {
            version_source == source_id
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
    if witness
        .version_source_digest
        .as_deref()
        .is_some_and(|digest| !is_digest(digest))
    {
        return Err(StoreError::Conflict(
            "import witness version source lacks an exact lowercase SHA-256 digest".into(),
        ));
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
    use crate::{NewInstance, NewProgramVersion, SqliteStore};

    const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SOURCE_ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const LOCK: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEXT_LOCK: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const COMPILER: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    #[test]
    fn operation_roster_refuses_an_unknown_kind() {
        assert!(matches!(
            ProgramImportOperationKind::try_from("future-kind"),
            Err(StoreError::Conflict(message)) if message.contains("unknown program import operation kind future-kind")
        ));
    }

    #[test]
    fn operation_roster_refuses_malformed_persisted_evidence() {
        assert!(ProgramImportOperation::from_stored_row(
            0,
            "op".into(),
            "version".into(),
            None,
            "unwitnessed",
        )
        .is_err());
        assert!(ProgramImportOperation::from_stored_row(
            1,
            "op".into(),
            "version".into(),
            None,
            "checked",
        )
        .is_err());
        assert!(ProgramImportOperation::from_stored_row(
            1,
            "op".into(),
            "version".into(),
            Some(LOCK.into()),
            "unwitnessed",
        )
        .is_err());
        assert!(ProgramImportOperation::from_stored_row(
            1,
            "op".into(),
            "version".into(),
            Some("not-a-digest".into()),
            "checked",
        )
        .is_err());
    }

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
            version_source_digest: None,
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
    fn composite_version_source_retains_the_exact_program_source() {
        let mut checked = witness(LOCK);
        checked.version_source_digest = Some(NEXT_LOCK.into());
        assert!(matches_source_id(&checked, NEXT_LOCK));
        assert!(!matches_source_id(&checked, SOURCE));
        assert_eq!(checked.program_source_digest, SOURCE);
        assert!(encode(&checked).is_ok());
        checked.version_source_digest = Some("not-a-digest".into());
        assert!(encode(&checked).is_err());
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
        let unwitnessed = store.create_program_version(version("paint")).unwrap();
        assert_eq!(unwitnessed.version_id, first.version_id);

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
        let roster = store.program_import_operation_roster().unwrap();
        assert_eq!(roster.frontier, roster.operations.last().unwrap().sequence);
        let operations: Vec<_> = roster
            .operations
            .iter()
            .filter(|operation| operation.version_id == first.version_id)
            .collect();
        assert_eq!(operations.len(), 4);
        assert!(operations
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        assert_eq!(
            operations
                .iter()
                .filter(|operation| operation.kind == ProgramImportOperationKind::Checked)
                .count(),
            3
        );
        assert_eq!(
            operations
                .iter()
                .filter(|operation| {
                    operation.kind == ProgramImportOperationKind::Unwitnessed
                        && operation.witness_digest.is_none()
                })
                .count(),
            1
        );
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
        let operations: i64 = store
            .connection
            .query_row(
                "SELECT COUNT(*) FROM program_import_operations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(operations, 0);
    }

    #[test]
    fn checked_reattestation_moves_the_instance_with_its_import_witness() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let first = store
            .create_program_version_with_import_witness(version("rechecked"), &witness(LOCK))
            .unwrap();
        let instance = store
            .create_instance(NewInstance {
                program_id: &first.program_id,
                version_id: &first.version_id,
                input_json: "{}",
            })
            .unwrap();
        let before_checked_refusals = store.program_import_operation_roster().unwrap();
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                "missing-instance",
                NewProgramVersion {
                    ir_hash: NEXT_LOCK,
                    ..version("rechecked")
                },
                &witness(LOCK),
            ),
            Err(StoreError::Conflict(message)) if message.contains("unknown instance")
        ));
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                &instance.instance_id,
                NewProgramVersion {
                    source_hash: NEXT_LOCK,
                    ir_hash: NEXT_LOCK,
                    ..version("rechecked")
                },
                &witness(LOCK),
            ),
            Err(StoreError::Conflict(message)) if message.contains("same authored program")
        ));
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                &instance.instance_id,
                version("rechecked"),
                &witness(LOCK),
            ),
            Err(StoreError::Conflict(message)) if message.contains("changed compiler IR")
        ));
        let mut wrong_source = witness(LOCK);
        wrong_source.program_source_digest = NEXT_LOCK.into();
        assert!(matches!(
            store.reattest_instance_program_with_import_witness(
                &instance.instance_id,
                NewProgramVersion {
                    ir_hash: NEXT_LOCK,
                    ..version("rechecked")
                },
                &wrong_source,
            ),
            Err(StoreError::Conflict(message)) if message.contains("program source differs")
        ));
        assert_eq!(
            store.program_import_operation_roster().unwrap(),
            before_checked_refusals
        );
        assert_eq!(
            store
                .get_instance(&instance.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            first.version_id
        );
        let changed = NewProgramVersion {
            ir_hash: NEXT_LOCK,
            ..version("rechecked")
        };
        let checked = store
            .reattest_instance_program_with_import_witness(
                &instance.instance_id,
                changed,
                &witness(LOCK),
            )
            .unwrap();
        assert_ne!(checked.version_id, first.version_id);
        assert_eq!(
            store
                .get_instance(&instance.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            checked.version_id
        );
        assert_eq!(
            store
                .program_import_witness(&checked.version_id, &checked.witness_digest)
                .unwrap(),
            Some(witness(LOCK))
        );
        let roster = store.program_import_operation_roster().unwrap();
        assert_eq!(roster.operations.len(), 2);
        assert_eq!(
            roster.operations[1].kind,
            ProgramImportOperationKind::Checked
        );
        assert_eq!(
            roster.operations[1].witness_digest.as_deref(),
            Some(checked.witness_digest.as_str())
        );

        let mut bad = witness(LOCK);
        bad.edge_digest = NEXT_LOCK.into();
        let refused = store.reattest_instance_program_with_import_witness(
            &instance.instance_id,
            NewProgramVersion {
                ir_hash: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                ..version("rechecked")
            },
            &bad,
        );
        assert!(refused.is_err());
        assert_eq!(store.program_import_operation_roster().unwrap(), roster);
        assert_eq!(
            store
                .get_instance(&instance.instance_id)
                .unwrap()
                .unwrap()
                .version_id,
            checked.version_id
        );
    }

    #[test]
    fn migration_keeps_prior_acceptance_unknown_after_version_reuse() {
        let mut store = SqliteStore::open_in_memory().unwrap();
        let first = store
            .create_program_version_with_import_witness(version("old"), &witness(LOCK))
            .unwrap();
        // Model an existing store stamped before operation tracking. Its
        // earlier checked witness says nothing about each old accepting call.
        store
            .connection
            .execute_batch(
                "DROP TABLE program_import_operations;
                 DELETE FROM schema_migrations WHERE version = 6;",
            )
            .unwrap();
        crate::initialize_runtime_schema_on(&store.connection).unwrap();
        let prior = store.program_import_operation_roster().unwrap();
        assert_eq!(prior.operations.len(), 1);
        assert_eq!(
            prior.operations[0].kind,
            ProgramImportOperationKind::LegacyGap
        );
        store
            .create_program_version_with_import_witness(version("old"), &witness(LOCK))
            .unwrap();
        let current = store.program_import_operation_roster().unwrap();
        assert!(current.frontier > prior.frontier);
        let rows: Vec<_> = current
            .operations
            .into_iter()
            .map(|operation| (operation.version_id, operation.kind))
            .collect();
        assert_eq!(
            rows,
            [
                (
                    first.version_id.clone(),
                    ProgramImportOperationKind::LegacyGap
                ),
                (first.version_id, ProgramImportOperationKind::Checked)
            ]
        );
    }
}
