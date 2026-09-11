//! Protected content authorities are explicitly created and reopened. The
//! persisted domain is not a key and cannot authorize the caller.
use super::*;
use crate::{payload_protection::PayloadProtection, StoreError};

impl ContentStore {
    fn recorded_protection(connection: &Connection) -> StoreResult<Option<String>> {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'content_payload_protection')",
            [],
            |row| row.get(0),
        )?;
        if exists {
            return Ok(connection.query_row(
                "SELECT domain FROM content_payload_protection WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?);
        }
        let stamped: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'schema_migrations')",
            [],
            |row| row.get(0),
        )?;
        if stamped {
            let version: i64 = connection.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )?;
            if version >= SATELLITE_SCHEMA_VERSION {
                return Err(StoreError::fault(
                    "content protection",
                    "missing durable protection binding",
                ));
            }
        }
        Ok(None)
    }

    pub(super) fn require_plain_before_initialize(connection: &Connection) -> StoreResult<()> {
        if Self::recorded_protection(connection)?.is_some() {
            return Err(StoreError::fault(
                "content protection",
                "protected store requires its host codec",
            ));
        }
        Ok(())
    }

    pub(super) fn from_connection(
        connection: Connection,
        protection: Option<PayloadProtection>,
    ) -> StoreResult<Self> {
        let recorded = Self::recorded_protection(&connection)?;
        if recorded.as_deref() != protection.as_ref().map(PayloadProtection::domain) {
            return Err(StoreError::fault(
                "content protection",
                "host codec domain does not match the store",
            ));
        }
        Ok(Self {
            connection,
            protection,
        })
    }

    fn initialize_protected(
        connection: Connection,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let transaction = rusqlite::Transaction::new_unchecked(
            &connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if count != 0 {
            return Err(StoreError::fault(
                "content protection",
                "protected initialization requires an empty new store",
            ));
        }
        ensure_content_schema(&connection)?;
        connection.execute(
            "UPDATE content_payload_protection SET domain = ?1 WHERE singleton = 1",
            params![protection.domain()],
        )?;
        transaction.commit()?;
        Self::from_connection(connection, Some(protection))
    }

    /// Create a new protected file. Existing paths are never converted or
    /// replaced; use `open_existing_protected` for restart. A failed creation
    /// can leave an empty file, which existing-store reopening refuses.
    pub fn create_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?,
        );
        let connection = Connection::open(&path)?;
        crate::establish_wal(&connection)?;
        Self::initialize_protected(connection, protection)
    }

    pub fn open_in_memory_protected(protection: PayloadProtection) -> StoreResult<Self> {
        Self::initialize_protected(Connection::open_in_memory()?, protection)
    }

    /// Reopen the exact existing authority without recreating its mode or
    /// binding. This writable handle also supports retained publication.
    pub fn open_existing_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let connection =
            crate::native_existing::open(path.as_ref(), "content", SATELLITE_SCHEMA_VERSION)?;
        Self::from_connection(connection, Some(protection))
    }

    pub fn open_read_only_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(crate::STORE_BUSY_TIMEOUT)?;
        crate::native_existing::validate(&connection, "content", SATELLITE_SCHEMA_VERSION)?;
        Self::from_connection(connection, Some(protection))
    }

    pub(super) fn read_loose(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        let retained = self
            .connection
            .prepare_cached("SELECT body FROM content_blobs WHERE id = ?1")?
            .query_row(params![id], |row| row.get::<_, rusqlite::types::Value>(0))
            .optional()?;
        let Some(retained) = retained else {
            return Ok(None);
        };
        let Some(body) = body_bytes(retained) else {
            return Err(StoreError::fault(
                "content protection",
                "invalid retained blob representation",
            ));
        };
        let body = if let Some(protection) = &self.protection {
            let plaintext = protection.open("content.blob", id, &body)?;
            verify_body(id, &plaintext, "protected native content")?;
            plaintext
        } else {
            body
        };
        Ok(Some(body))
    }
}

#[cfg(test)]
mod tests;
