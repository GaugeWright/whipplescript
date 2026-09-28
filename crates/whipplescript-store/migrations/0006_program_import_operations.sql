CREATE TABLE program_import_operations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT NOT NULL UNIQUE,
    version_id TEXT NOT NULL REFERENCES program_versions(version_id),
    witness_digest TEXT,
    kind TEXT NOT NULL CHECK (kind IN ('checked', 'unwitnessed', 'legacy-gap')),
    FOREIGN KEY (version_id, witness_digest)
        REFERENCES program_import_admissions(version_id, witness_digest),
    CHECK ((kind = 'checked') = (witness_digest IS NOT NULL))
);

-- The migration runner backfills old versions only when a legacy store has a
-- program_versions table. Some valid v1 layouts predate that table entirely.
