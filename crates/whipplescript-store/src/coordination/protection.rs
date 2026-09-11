//! Native coordination payloads retain their logical keys across encryption.
use super::*;
use crate::payload_protection::PayloadProtection;
use rusqlite::types::Value as SqlValue;
use sha2::{Digest, Sha256};

impl CoordinationStore {
    fn recorded_protection(connection: &Connection) -> StoreResult<Option<String>> {
        if table_exists(connection, "coordination_payload_protection")? {
            return Ok(connection.query_row(
                "SELECT domain FROM coordination_payload_protection WHERE singleton = 1",
                [],
                |row| row.get(0),
            )?);
        }
        if table_exists(connection, "schema_migrations")? {
            let version: i64 = connection.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
                [],
                |row| row.get(0),
            )?;
            if version >= SATELLITE_SCHEMA_VERSION {
                return Err(StoreError::fault(
                    "coordination protection",
                    "missing durable protection binding",
                ));
            }
        }
        Ok(None)
    }

    pub(super) fn require_plain_before_initialize(connection: &Connection) -> StoreResult<()> {
        if Self::recorded_protection(connection)?.is_some() {
            return Err(StoreError::fault(
                "coordination protection",
                "protected store requires its host codec",
            ));
        }
        Ok(())
    }

    pub(super) fn from_existing_connection(
        connection: Connection,
        protection: Option<PayloadProtection>,
    ) -> StoreResult<Self> {
        if Self::recorded_protection(&connection)?.as_deref()
            != protection.as_ref().map(PayloadProtection::domain)
        {
            return Err(StoreError::fault(
                "coordination protection",
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
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let tx = rusqlite::Transaction::new_unchecked(
            &connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
        if count != 0 {
            return Err(StoreError::fault(
                "coordination protection",
                "protected initialization requires an empty new store",
            ));
        }
        ensure_partitioned_schema(&connection)?;
        connection.execute(
            "UPDATE coordination_payload_protection SET domain = ?1 WHERE singleton = 1",
            params![protection.domain()],
        )?;
        tx.commit()?;
        Self::from_existing_connection(connection, Some(protection))
    }

    /// Create a protected authority at a new path. No existing store is adopted,
    /// replaced, or silently converted to another payload mode.
    pub fn create_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        if let Some(parent) = path
            .as_ref()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        drop(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?,
        );
        crate::harden_store_file_permissions(path.as_ref())?;
        let connection = Connection::open(&path)?;
        crate::establish_wal(&connection)?;
        Self::initialize_protected(connection, protection)
    }

    pub fn open_in_memory_protected(protection: PayloadProtection) -> StoreResult<Self> {
        Self::initialize_protected(Connection::open_in_memory()?, protection)
    }

    /// Reopen only the recorded schema and domain, without repairing either.
    pub fn open_existing_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let connection =
            crate::native_existing::open(path.as_ref(), "coordination", SATELLITE_SCHEMA_VERSION)?;
        crate::harden_store_file_permissions(path.as_ref())?;
        Self::from_existing_connection(connection, Some(protection))
    }

    pub fn open_read_only_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(crate::STORE_BUSY_TIMEOUT)?;
        crate::native_existing::validate(&connection, "coordination", SATELLITE_SCHEMA_VERSION)?;
        Self::from_existing_connection(connection, Some(protection))
    }

    pub(super) fn retained<T>(
        &mut self,
        publish: impl FnOnce(&mut Self) -> StoreResult<T>,
    ) -> StoreResult<T> {
        match self.protection.clone() {
            Some(protection) => protection.retain(|| publish(self)),
            None => publish(self),
        }
    }
}

pub(super) fn initialize_payload_schema(connection: &Connection) -> StoreResult<()> {
    for (table, column, source) in [
        ("leases", "key_payload", "key"),
        ("counters", "key_payload", "key"),
        ("ledger_entries", "partition_payload", "partition"),
    ] {
        if !column_exists(connection, table, column)? {
            connection.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} BLOB"))?;
            // Only old plaintext stores arrive here with rows. A protected
            // existing opener never initializes or reconstructs a field.
            connection.execute_batch(&format!("UPDATE {table} SET {column} = {source}"))?;
        }
    }
    connection.execute_batch("CREATE TABLE IF NOT EXISTS coordination_payload_protection (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), domain TEXT); INSERT OR IGNORE INTO coordination_payload_protection (singleton, domain) VALUES (1, NULL);")?;
    Ok(())
}

pub(super) fn key_index(
    protection: Option<&PayloadProtection>,
    plane: &str,
    owner: &str,
    resource: &str,
    key: &str,
) -> StoreResult<String> {
    let Some(protection) = protection else {
        return Ok(key.to_owned());
    };
    Ok(format!(
        "coord-key:{}",
        Sha256::digest(serde_json::to_vec(&(
            "whipplescript.coordination-key.v1",
            protection.domain(),
            plane,
            owner,
            resource,
            key,
        ))?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
    ))
}

pub(super) fn seal(
    protection: Option<&PayloadProtection>,
    plane: &str,
    coordinate: &[&str],
    value: &str,
) -> StoreResult<SqlValue> {
    match protection {
        Some(protection) => Ok(SqlValue::Blob(protection.seal(
            plane,
            &serde_json::to_string(coordinate)?,
            value.as_bytes(),
        )?)),
        None => Ok(SqlValue::Text(value.to_owned())),
    }
}

pub(super) fn open(
    protection: Option<&PayloadProtection>,
    plane: &str,
    coordinate: &[&str],
    value: SqlValue,
) -> StoreResult<String> {
    match (protection, value) {
        (Some(protection), SqlValue::Blob(bytes)) => String::from_utf8(protection.open(
            plane,
            &serde_json::to_string(coordinate)?,
            &bytes,
        )?)
        .map_err(|_| StoreError::fault("coordination protection", "decoded payload is not UTF-8")),
        (None, SqlValue::Text(text)) => Ok(text),
        _ => Err(StoreError::fault(
            "coordination protection",
            "payload representation does not match protection mode",
        )),
    }
}

pub(super) fn open_key(
    protection: Option<&PayloadProtection>,
    plane: &str,
    owner: &str,
    resource: &str,
    index: &str,
    coordinate: &[&str],
    value: SqlValue,
) -> StoreResult<String> {
    let key = open(protection, plane, coordinate, value)?;
    if key_index(protection, plane, owner, resource, &key)? != index {
        return Err(StoreError::fault(
            "coordination protection",
            "decoded key does not match its index",
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests;
