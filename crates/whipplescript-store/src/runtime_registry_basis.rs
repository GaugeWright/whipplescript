//! Exact current basis of the runtime registration rows a package seed can
//! change. This is a local read, not a Home operation roster or coverage claim.

use crate::StoreResult;

pub struct RegistryQuery {
    pub native_sql: &'static str,
    pub hosted_sql: &'static str,
}

/// Fixed table and column order is part of the digest format. Include every
/// row, including stale rows left by an upsert, so a later receipt cannot hide
/// a provider still visible to the runtime.
pub const QUERIES: [RegistryQuery; 5] = [
    RegistryQuery {
        native_sql: "SELECT package_id, name, version, \
            whip_payload_open('runtime.package_registrations.manifest_json', package_id, manifest_json) \
            FROM package_registrations ORDER BY package_id",
        hosted_sql: "SELECT package_id, name, version, manifest_json \
            FROM package_registrations ORDER BY package_id",
    },
    RegistryQuery {
        native_sql: "SELECT capability, \
            whip_payload_open('runtime.capability_schemas.description', capability, description), \
            whip_payload_open('runtime.capability_schemas.schema_json', capability, schema_json), \
            registered_by_package_id FROM capability_schemas ORDER BY capability",
        hosted_sql: "SELECT capability, description, schema_json, registered_by_package_id \
            FROM capability_schemas ORDER BY capability",
    },
    RegistryQuery {
        native_sql: "SELECT provider_id, effect_kind, provider, capability, \
            whip_payload_open('runtime.effect_providers.config_json', json_array(effect_kind, provider), config_json), \
            registered_by_package_id FROM effect_providers ORDER BY effect_kind, provider",
        hosted_sql: "SELECT provider_id, effect_kind, provider, capability, config_json, \
            registered_by_package_id FROM effect_providers ORDER BY effect_kind, provider",
    },
    RegistryQuery {
        native_sql: "SELECT profile_id, name, \
            whip_payload_open('runtime.profiles.description', name, description), \
            enforcement_mode, allowed_capabilities, \
            whip_payload_open('runtime.profiles.config_json', name, config_json) \
            FROM profiles ORDER BY name",
        hosted_sql: "SELECT profile_id, name, description, enforcement_mode, \
            allowed_capabilities, config_json FROM profiles ORDER BY name",
    },
    RegistryQuery {
        native_sql: "SELECT binding_id, program_id, capability, provider, \
            whip_payload_open('runtime.capability_bindings.config_json', binding_id, config_json) \
            FROM capability_bindings ORDER BY binding_id",
        hosted_sql: "SELECT binding_id, program_id, capability, provider, config_json \
            FROM capability_bindings ORDER BY binding_id",
    },
];

pub type RegistryRows = Vec<Vec<Vec<Option<String>>>>;

pub fn digest(rows: &RegistryRows) -> StoreResult<String> {
    let encoded = serde_json::to_string(&("whip.runtime-registry-basis.v1", rows))?;
    Ok(crate::items::sha256_hex(&encoded))
}

#[cfg(feature = "native")]
impl crate::SqliteStore {
    pub fn runtime_registry_digest(&self) -> StoreResult<String> {
        use rusqlite::{Transaction, TransactionBehavior};

        let snapshot = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let mut tables = Vec::with_capacity(QUERIES.len());
        for query in QUERIES {
            let mut statement = snapshot.prepare(query.native_sql)?;
            let columns = statement.column_count();
            let rows = statement.query_map([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, Option<String>>(column))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })?;
            tables.push(rows.collect::<rusqlite::Result<Vec<_>>>()?);
        }
        snapshot.commit()?;
        digest(&tables)
    }
}
