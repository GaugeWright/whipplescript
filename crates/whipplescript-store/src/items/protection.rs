//! Protected tracker authorities are explicitly created and reopened. The
//! persisted domain is not a key and cannot authorize the caller.
use super::*;
use crate::{payload_protection::PayloadProtection, StoreError};

impl WorkItemStore {
    fn recorded_protection(connection: &Connection) -> StoreResult<Option<String>> {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'tracker_payload_protection')",
            [],
            |row| row.get(0),
        )?;
        if exists {
            return Ok(connection.query_row(
                "SELECT domain FROM tracker_payload_protection WHERE singleton = 1",
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
                    "tracker protection",
                    "missing durable protection binding",
                ));
            }
        }
        Ok(None)
    }

    pub(super) fn require_plain_before_initialize(connection: &Connection) -> StoreResult<()> {
        if Self::recorded_protection(connection)?.is_some() {
            return Err(StoreError::fault(
                "tracker protection",
                "protected store requires its host codec",
            ));
        }
        Ok(())
    }

    pub(super) fn from_existing_connection(
        connection: Connection,
        protection: Option<PayloadProtection>,
    ) -> StoreResult<Self> {
        let recorded = Self::recorded_protection(&connection)?;
        if recorded.as_deref() != protection.as_ref().map(PayloadProtection::domain) {
            return Err(StoreError::fault(
                "tracker protection",
                "host codec domain does not match the store",
            ));
        }
        crate::payload_protection::register_sql_functions(&connection, protection.clone())?;
        register_event_functions(&connection, protection.clone())?;
        Ok(Self {
            connection,
            protection,
            event_effect_id: None,
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
                "tracker protection",
                "protected initialization requires an empty new store",
            ));
        }
        Self::initialize_schema(&connection)?;
        connection.execute(
            "UPDATE tracker_payload_protection SET domain = ?1 WHERE singleton = 1",
            params![protection.domain()],
        )?;
        transaction.commit()?;
        Self::from_existing_connection(connection, Some(protection))
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
            crate::native_existing::open(path.as_ref(), "work-item", SATELLITE_SCHEMA_VERSION)?;
        Self::from_existing_connection(connection, Some(protection))
    }

    pub fn open_read_only_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(crate::STORE_BUSY_TIMEOUT)?;
        crate::native_existing::validate(&connection, "work-item", SATELLITE_SCHEMA_VERSION)?;
        Self::from_existing_connection(connection, Some(protection))
    }
}

/// An operational view, not a decoded `TrackerEvent`. After key erasure this
/// view cannot attest that the sealed content still matches its content hash.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TrackerEventMetadata {
    pub event_id: String,
    pub parents: Vec<String>,
    pub issue_id: Option<String>,
    pub kind: String,
    pub actor: Option<String>,
    pub effect_id: Option<String>,
    pub created_at: String,
    pub operational: Value,
}

// Only named operational fields escape the content envelope. Unknown events
// and unknown fields remain protected, including arbitrary field-set values.
fn operational(kind: &str, payload: &Value) -> Value {
    let keys: &[&str] = match kind {
        "issue.created" => &["queue", "filed_by", "assigned_to", "filing_fingerprint"],
        "issue.assigned" => &["assigned_to"],
        "issue.closed" | "issue.canceled" | "issue.reopened" => {
            &["actor", "operation_id", "fingerprint", "subject_id"]
        }
        "claim.acquired" | "claim.renewed" | "claim.released" | "claim.expired" => {
            &["lease_id", "actor", "expires_at", "released_at"]
        }
        "relation.added" | "relation.removed" => &["from", "to", "kind", "dep_kind"],
        "comment.added" => &["author"],
        "evidence.added" => &["added_by", "at_cut"],
        "anchor.added" => &["added_by", "role"],
        "anchor.removed" => &["anchor_id", "removed_by"],
        "assertion.created" => &["created_by"],
        "assertion.retired" => &["retired_by"],
        "issue.field_set"
            if payload.get("field").and_then(Value::as_str) == Some("status")
                && matches!(
                    payload.get("value").and_then(Value::as_str),
                    Some("open" | "closed" | "canceled")
                ) =>
        {
            &["field", "value"]
        }
        _ => &[],
    };
    let mut result = serde_json::Map::new();
    for key in keys {
        if let Some(value) = payload.get(*key).filter(|v| v.is_string() || v.is_null()) {
            result.insert((*key).to_owned(), value.clone());
        }
    }
    if matches!(kind, "issue.closed" | "issue.canceled" | "issue.reopened") {
        let mut operation = serde_json::Map::new();
        for key in ["id", "fingerprint", "instance_id", "effect_id"] {
            if let Some(value) = payload
                .get("operation")
                .and_then(|v| v.get(key))
                .filter(|v| v.is_string())
            {
                operation.insert(key.to_owned(), value.clone());
            }
        }
        if !operation.is_empty() {
            result.insert("operation".into(), Value::Object(operation));
        }
    }
    Value::Object(result)
}

#[cfg(test)]
fn event_coordinate(id: &str, kind: &str, summary: &Value) -> StoreResult<String> {
    crate::event_payload_protection::coordinate(id, kind, summary)
}
fn seal_event(
    protection: &PayloadProtection,
    id: &str,
    kind: &str,
    raw: &str,
) -> StoreResult<String> {
    crate::event_payload_protection::seal(protection, "tracker.event", id, kind, raw, operational)
}
fn envelope(raw: &str) -> StoreResult<crate::event_payload_protection::Envelope> {
    crate::event_payload_protection::envelope(raw, "tracker protection")
}
fn open_event(
    protection: &PayloadProtection,
    id: &str,
    kind: &str,
    raw: &str,
) -> StoreResult<String> {
    crate::event_payload_protection::open(
        protection,
        "tracker.event",
        "tracker protection",
        id,
        kind,
        raw,
        operational,
    )
}

fn register_event_functions(
    connection: &Connection,
    protection: Option<PayloadProtection>,
) -> StoreResult<()> {
    for (name, seal) in [
        ("whip_tracker_event_seal", true),
        ("whip_tracker_event_open", false),
    ] {
        let protection = protection.clone();
        connection.create_scalar_function(
            name,
            3,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DIRECTONLY,
            move |context| {
                let raw: String = context.get(2)?;
                let Some(protection) = &protection else {
                    return Ok(raw);
                };
                let id: String = context.get(0)?;
                let kind: String = context.get(1)?;
                let result = if seal {
                    seal_event(protection, &id, &kind, &raw)
                } else {
                    open_event(protection, &id, &kind, &raw)
                };
                result.map_err(|error| {
                    rusqlite::Error::UserFunctionError(Box::new(std::io::Error::other(format!(
                        "{error:?}"
                    ))))
                })
            },
        )?;
    }
    Ok(())
}

impl WorkItemStore {
    /// Inspect operational history without opening customer content. This is
    /// not the full event export or an integrity verification after erasure.
    pub fn event_metadata(&self) -> StoreResult<Vec<TrackerEventMetadata>> {
        let mut statement = self.connection.prepare(
            "SELECT event_id, parents_json, issue_id, kind, actor, effect_id, created_at, payload_json
             FROM tracker_events ORDER BY event_seq",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                TrackerEventMetadata {
                    event_id: row.get(0)?,
                    parents: Vec::new(),
                    issue_id: row.get(2)?,
                    kind: row.get(3)?,
                    actor: row.get(4)?,
                    effect_id: row.get(5)?,
                    created_at: row.get(6)?,
                    operational: Value::Null,
                },
                row.get::<_, String>(1)?,
                row.get::<_, String>(7)?,
            ))
        })?;
        rows.map(|row| {
            let (mut metadata, parents, raw) = row?;
            metadata.parents = serde_json::from_str(&parents)?;
            metadata.operational = if self.protection.is_some() {
                envelope(&raw)?.operational
            } else {
                operational(&metadata.kind, &serde_json::from_str(&raw)?)
            };
            Ok(metadata)
        })
        .collect()
    }
}

#[cfg(test)]
mod tests;
