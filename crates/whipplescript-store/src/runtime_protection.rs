//! Protected runtime authorities are explicitly created and reopened. The
//! persisted domain is not a key and cannot authorize the caller.
use crate::*;
use crate::{payload_protection::PayloadProtection, StoreError};

impl SqliteStore {
    fn recorded_protection(connection: &Connection) -> StoreResult<Option<String>> {
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name = 'runtime_payload_protection')",
            [],
            |row| row.get(0),
        )?;
        if exists {
            return Ok(connection.query_row(
                "SELECT domain FROM runtime_payload_protection WHERE singleton = 1",
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
            if version >= SUPPORTED_SCHEMA_VERSION {
                return Err(StoreError::fault(
                    "runtime protection",
                    "missing durable protection binding",
                ));
            }
        }
        Ok(None)
    }

    pub(super) fn require_plain_before_initialize(connection: &Connection) -> StoreResult<()> {
        if Self::recorded_protection(connection)?.is_some() {
            return Err(StoreError::fault(
                "runtime protection",
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
                "runtime protection",
                "host codec domain does not match the store",
            ));
        }
        register(&connection, protection.clone())?;
        Ok(Self {
            connection,
            protection,
            retention_active: Default::default(),
        })
    }

    fn initialize_protected(
        connection: Connection,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let transaction = rusqlite::Transaction::new_unchecked(
            &connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let count: i64 =
            connection.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if count != 0 {
            return Err(StoreError::fault(
                "runtime protection",
                "protected initialization requires an empty new store",
            ));
        }
        register(&connection, Some(protection.clone()))?;
        initialize_runtime_schema_on(&connection)?;
        connection.execute(
            "UPDATE runtime_payload_protection SET domain = ?1 WHERE singleton = 1",
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
        crate::harden_store_file_permissions(path.as_ref())?;
        let connection = Connection::open(&path)?;
        crate::establish_wal(&connection)?;
        Self::initialize_protected(connection, protection)
    }

    /// Create an ephemeral protected runtime with the same payload boundaries
    /// as a protected file. The embedding host owns the codec and key lifetime.
    pub fn open_in_memory_protected(protection: PayloadProtection) -> StoreResult<Self> {
        Self::initialize_protected(Connection::open_in_memory()?, protection)
    }

    /// Reopen the exact existing authority without recreating its mode or
    /// binding. This writable handle also supports retained publication.
    pub fn open_existing_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let connection = crate::native_existing::open(
            path.as_ref(),
            "native-payload-protection",
            SUPPORTED_SCHEMA_VERSION,
        )?;
        crate::harden_store_file_permissions(path.as_ref())?;
        Self::from_existing_connection(connection, Some(protection))
    }

    /// Open a coordinator-initialized protected runtime for a worker without
    /// migrations, journal changes, or reconstruction of its durable binding.
    pub fn open_initialized_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        Self::from_existing_connection(Self::initialized_connection(path)?, Some(protection))
    }

    /// Open an existing protected runtime for decoded inspection. This never
    /// creates a store or repairs schema; an unavailable codec fails on reads.
    pub fn open_read_only_protected(
        path: impl AsRef<Path>,
        protection: PayloadProtection,
    ) -> StoreResult<Self> {
        let connection =
            Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(crate::STORE_BUSY_TIMEOUT)?;
        crate::native_existing::validate(
            &connection,
            "native-payload-protection",
            SUPPORTED_SCHEMA_VERSION,
        )?;
        Self::from_existing_connection(connection, Some(protection))
    }
}

/// One native connection cannot be used concurrently. Its nested mutations
/// share the outer retention interval, avoiding a second call into a host
/// whose erasure lock need not be reentrant. Separate connections retain
/// independently through the host codec.
pub(crate) struct RetainedPublication {
    protection: Option<PayloadProtection>,
    active: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RetainedPublication {
    pub(crate) fn run<T>(self, publish: impl FnOnce() -> StoreResult<T>) -> StoreResult<T> {
        use std::sync::atomic::Ordering;
        let Some(protection) = self.protection else {
            return publish();
        };
        if self.active.load(Ordering::SeqCst) {
            return publish();
        }
        protection.retain(|| {
            struct Reset(std::sync::Arc<std::sync::atomic::AtomicBool>);
            impl Drop for Reset {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::SeqCst);
                }
            }
            self.active.store(true, Ordering::SeqCst);
            let _reset = Reset(self.active);
            publish()
        })
    }
}

impl SqliteStore {
    pub(crate) fn retained_publication(&self) -> RetainedPublication {
        RetainedPublication {
            protection: self.protection.clone(),
            active: self.retention_active.clone(),
        }
    }
}

pub(crate) fn register(
    connection: &Connection,
    protection: Option<payload_protection::PayloadProtection>,
) -> StoreResult<()> {
    crate::payload_protection::register_sql_functions(connection, protection.clone())?;
    for (function, namespace) in [
        ("whip_runtime_fact_key", "whipplescript.runtime.fact-key.v1"),
        (
            "whip_runtime_metadata_key",
            "whipplescript.runtime.metadata-key.v1",
        ),
    ] {
        let index_protection = protection.clone();
        connection.create_scalar_function(
            function,
            1,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DIRECTONLY
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            move |context| {
                let key: String = context.get(0)?;
                Ok(match &index_protection {
                    Some(protection) => stable_hash_hex(
                        &serde_json::json!([namespace, protection.domain(), key]).to_string(),
                    ),
                    None => key,
                })
            },
        )?;
    }
    for (name, seal) in [
        ("whip_runtime_event_seal", true),
        ("whip_runtime_event_open", false),
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
                    crate::event_payload_protection::seal(
                        protection,
                        "runtime.event",
                        &id,
                        &kind,
                        &raw,
                        operational,
                    )
                } else {
                    crate::event_payload_protection::open(
                        protection,
                        "runtime.event",
                        "runtime protection",
                        &id,
                        &kind,
                        &raw,
                        operational,
                    )
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

fn operational(kind: &str, payload: &Value) -> Value {
    let keys: &[&str] = match kind {
        "host.action.admitted" => &[
            "fingerprint",
            "program_id",
            "version_id",
            "workflow_principal",
        ],
        "instance.created" | "instance.transitioned" | "instance.program.reattested" => &[
            "instance_id",
            "program_id",
            "version_id",
            "workflow_principal",
            "status",
            "from_status",
            "to_status",
        ],
        "effect.run_started" | "effect.terminal" | "effect.cancelled" | "lease.expired" => &[
            "effect_id",
            "run_id",
            "provider",
            "worker_id",
            "status",
            "exit_code",
        ],
        "fact.derived" => &["fact_id", "name", "schema_id", "provenance_class"],
        "rule.committed" => &["rule_name", "revision_epoch"],
        _ => &[],
    };
    let mut result = serde_json::Map::new();
    for key in keys {
        if let Some(value) = payload
            .get(*key)
            .filter(|v| v.is_string() || v.is_number() || v.is_null())
        {
            result.insert((*key).to_owned(), value.clone());
        }
    }
    Value::Object(result)
}

#[cfg(test)]
mod tests;

// Shared native/hosted SQL stays portable. Native readers of those bounded
// result sets open their payload cell through the same connection authority.
pub(crate) fn read_event_payload(
    connection: &Connection,
    row: &rusqlite::Row<'_>,
    id: usize,
    kind: usize,
    payload: usize,
) -> rusqlite::Result<String> {
    connection.query_row(
        "SELECT whip_runtime_event_open(?1, ?2, ?3)",
        params![
            row.get::<_, String>(id)?,
            row.get::<_, String>(kind)?,
            row.get::<_, String>(payload)?
        ],
        |r| r.get(0),
    )
}

/// Metadata inspection is distinct from the complete event export and chain
/// verification. An erased payload cannot be re-hashed by this view.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeEventMetadata {
    pub event_id: String,
    pub instance_id: String,
    pub sequence: i64,
    pub event_type: String,
    pub occurred_at: String,
    pub source: String,
    pub causation_id: Option<String>,
    pub correlation_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub format_version: Option<i64>,
    pub prev_digest: Option<String>,
    pub entry_digest: Option<String>,
    pub operational: Value,
}

impl SqliteStore {
    pub fn event_metadata(&self, instance: &str) -> StoreResult<Vec<RuntimeEventMetadata>> {
        let mut statement = self.connection.prepare("SELECT event_id, instance_id, sequence, event_type, occurred_at, source, causation_id, correlation_id, idempotency_key, format_version, prev_digest, entry_digest, payload_json FROM events WHERE instance_id = ?1 ORDER BY sequence")?;
        let rows = statement.query_map([instance], |r| {
            Ok((
                RuntimeEventMetadata {
                    event_id: r.get(0)?,
                    instance_id: r.get(1)?,
                    sequence: r.get(2)?,
                    event_type: r.get(3)?,
                    occurred_at: r.get(4)?,
                    source: r.get(5)?,
                    causation_id: r.get(6)?,
                    correlation_id: r.get(7)?,
                    idempotency_key: r.get(8)?,
                    format_version: r.get(9)?,
                    prev_digest: r.get(10)?,
                    entry_digest: r.get(11)?,
                    operational: Value::Null,
                },
                r.get::<_, String>(12)?,
            ))
        })?;
        rows.map(|row| {
            let (mut meta, payload) = row?;
            meta.operational = if self.protection.is_some() {
                crate::event_payload_protection::envelope(&payload, "runtime protection")?
                    .operational
            } else {
                operational(&meta.event_type, &serde_json::from_str(&payload)?)
            };
            Ok(meta)
        })
        .collect()
    }
}

// Native-generated references must not copy free-form error text into clear
// event headers. Plain stores keep their established event-key representation.
pub(crate) fn metadata_key(connection: &Connection, key: &str) -> StoreResult<String> {
    connection
        .query_row("SELECT whip_runtime_metadata_key(?1)", [key], |row| {
            row.get(0)
        })
        .map_err(Into::into)
}
