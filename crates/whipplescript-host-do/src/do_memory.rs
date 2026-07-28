//! DO-plane memory store (spec/std-memory.md MEM-3;
//! spec/durable-object-runtime-tracker.md "DO-plane memory"): the std.memory
//! `local` provider's `MemoryStore` seam over `DoSql`, so memory pools work on
//! the durable object the same way they do natively.
//!
//! Same table shape as `whipplescript_store::memory::SqliteMemoryStore`, but the
//! lexical match is `LIKE`-based rather than FTS5: the DO's platform SQLite is
//! not guaranteed to bundle FTS5, and the native store's inverted index would
//! not port to the Worker's `state.storage.sql` anyway. Retrieval stays "boring"
//! (per std-memory.md): case-insensitive per-token substring match, pool
//! scoping, recency ordering, `context_limit` cap.

use whipplescript_store::memory::{
    CurateStrategy, CurationReport, MemoryEntryRow, MemoryPoolRow, MemoryStore, NewMemoryEntry,
    DEFAULT_CONTEXT_LIMIT,
};
use whipplescript_store::StoreResult;

use whipplescript_kernel::effect_config::EffectConfig;
use whipplescript_kernel::effect_handlers::{
    run_memory_capability, CapabilityOutcome, CapabilityProvider,
};
use whipplescript_store::ClaimableEffect;

use crate::do_store::{as_i64, as_opt_text, as_text, sql_err, text, DoSql, SqlValue};

/// `MemoryStore` over the DO's SQLite. Owns a `DoSql` handle (share via `Rc` if
/// the runtime store needs the same connection).
pub struct DoMemoryStore<Sql: DoSql> {
    sql: Sql,
}

const ENTRY_COLUMNS: &str = "memory_id, pool, text, created_at, source_instance_id, \
     source_effect_id, source_run_id, author_actor, source, note";

impl<Sql: DoSql> DoMemoryStore<Sql> {
    /// Create the `memory_entries` table if absent, then hand back the store.
    pub fn open(sql: Sql) -> StoreResult<Self> {
        sql.execute(
            "CREATE TABLE IF NOT EXISTS memory_entries (\
               memory_id INTEGER PRIMARY KEY AUTOINCREMENT, \
               pool TEXT NOT NULL, \
               text TEXT NOT NULL, \
               created_at TEXT NOT NULL, \
               source_instance_id TEXT, \
               source_effect_id TEXT, \
               source_run_id TEXT, \
               author_actor TEXT, \
               source TEXT, \
               note TEXT)",
            &[],
        )
        .map_err(sql_err)?;
        sql.execute(
            "CREATE INDEX IF NOT EXISTS idx_memory_pool_created \
             ON memory_entries(pool, created_at)",
            &[],
        )
        .map_err(sql_err)?;
        Ok(Self { sql })
    }

    fn kept_in_pool(&self, pool: &str) -> StoreResult<usize> {
        let rows = self
            .sql
            .query(
                "SELECT COUNT(*) FROM memory_entries WHERE pool = ?1",
                &[text(pool)],
            )
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_i64(&row[0])).unwrap_or(0) as usize)
    }
}

fn entry_from_row(row: &[SqlValue]) -> MemoryEntryRow {
    MemoryEntryRow {
        memory_id: as_i64(&row[0]),
        pool: as_text(&row[1]),
        text: as_text(&row[2]),
        created_at: as_text(&row[3]),
        source_instance_id: as_opt_text(&row[4]),
        source_effect_id: as_opt_text(&row[5]),
        source_run_id: as_opt_text(&row[6]),
        author_actor: as_opt_text(&row[7]),
        source: as_opt_text(&row[8]),
        note: as_opt_text(&row[9]),
    }
}

/// Alphanumeric tokens of the query text — the same tokenization the native
/// store feeds FTS, here turned into case-insensitive `LIKE` substrings.
/// `None` when the text has no indexable tokens (recall then falls back to
/// pure recency).
fn like_tokens(query_text: &str) -> Option<Vec<String>> {
    let tokens: Vec<String> = query_text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| format!("%{}%", token.to_lowercase()))
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens)
    }
}

impl<Sql: DoSql> MemoryStore for DoMemoryStore<Sql> {
    fn write(&mut self, entry: &NewMemoryEntry<'_>) -> StoreResult<i64> {
        let opt = |value: Option<&str>| value.map_or(SqlValue::Null, text);
        self.sql
            .execute(
                "INSERT INTO memory_entries (pool, text, created_at, source_instance_id, \
                 source_effect_id, source_run_id, author_actor, source, note) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                &[
                    text(entry.pool),
                    text(entry.text),
                    text(entry.created_at),
                    opt(entry.source_instance_id),
                    opt(entry.source_effect_id),
                    opt(entry.source_run_id),
                    opt(entry.author_actor),
                    opt(entry.source),
                    opt(entry.note),
                ],
            )
            .map_err(sql_err)?;
        let rows = self
            .sql
            .query("SELECT last_insert_rowid()", &[])
            .map_err(sql_err)?;
        Ok(rows.first().map(|row| as_i64(&row[0])).unwrap_or(0))
    }

    fn query(
        &self,
        pool: &str,
        query_text: &str,
        context_limit: Option<usize>,
    ) -> StoreResult<Vec<MemoryEntryRow>> {
        let limit = context_limit.unwrap_or(DEFAULT_CONTEXT_LIMIT);
        let Some(tokens) = like_tokens(query_text) else {
            return self.entries(pool, Some(limit));
        };
        // pool is ?1; each token binds ?2.. ; the limit binds last.
        let mut params: Vec<SqlValue> = vec![text(pool)];
        let ors: Vec<String> = tokens
            .iter()
            .enumerate()
            .map(|(index, token)| {
                params.push(text(token));
                format!("LOWER(text) LIKE ?{}", index + 2)
            })
            .collect();
        params.push(SqlValue::Int(limit as i64));
        let limit_placeholder = params.len();
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM memory_entries \
             WHERE pool = ?1 AND ({}) \
             ORDER BY created_at DESC, memory_id DESC LIMIT ?{limit_placeholder}",
            ors.join(" OR ")
        );
        let rows = self.sql.query(&sql, &params).map_err(sql_err)?;
        Ok(rows.iter().map(|row| entry_from_row(row)).collect())
    }

    fn curate(&mut self, pool: &str, strategy: CurateStrategy) -> StoreResult<CurationReport> {
        let removed = match strategy {
            CurateStrategy::DedupeByText => self
                .sql
                .execute(
                    "DELETE FROM memory_entries WHERE pool = ?1 AND memory_id NOT IN \
                     (SELECT MIN(memory_id) FROM memory_entries WHERE pool = ?1 GROUP BY text)",
                    &[text(pool)],
                )
                .map_err(sql_err)?,
            CurateStrategy::DedupeBySourceNote => self
                .sql
                .execute(
                    "DELETE FROM memory_entries WHERE pool = ?1 AND memory_id NOT IN \
                     (SELECT MIN(memory_id) FROM memory_entries WHERE pool = ?1 \
                      GROUP BY source, note)",
                    &[text(pool)],
                )
                .map_err(sql_err)?,
            CurateStrategy::Prune { capacity } => self
                .sql
                .execute(
                    "DELETE FROM memory_entries WHERE pool = ?1 AND memory_id NOT IN \
                     (SELECT memory_id FROM memory_entries WHERE pool = ?1 \
                      ORDER BY created_at DESC, memory_id DESC LIMIT ?2)",
                    &[text(pool), SqlValue::Int(capacity as i64)],
                )
                .map_err(sql_err)?,
        };
        Ok(CurationReport {
            removed: removed as usize,
            kept: self.kept_in_pool(pool)?,
        })
    }

    fn pools(&self) -> StoreResult<Vec<MemoryPoolRow>> {
        let rows = self
            .sql
            .query(
                "SELECT pool, COUNT(*), MAX(created_at) FROM memory_entries \
                 GROUP BY pool ORDER BY pool",
                &[],
            )
            .map_err(sql_err)?;
        Ok(rows
            .iter()
            .map(|row| MemoryPoolRow {
                pool: as_text(&row[0]),
                entries: as_i64(&row[1]),
                last_created_at: as_opt_text(&row[2]),
            })
            .collect())
    }

    fn entries(&self, pool: &str, limit: Option<usize>) -> StoreResult<Vec<MemoryEntryRow>> {
        // SQLite `LIMIT -1` means unlimited.
        let limit = limit.map_or(-1, |limit| limit as i64);
        let rows = self
            .sql
            .query(
                &format!(
                    "SELECT {ENTRY_COLUMNS} FROM memory_entries WHERE pool = ?1 \
                     ORDER BY created_at DESC, memory_id DESC LIMIT ?2"
                ),
                &[text(pool), SqlValue::Int(limit)],
            )
            .map_err(sql_err)?;
        Ok(rows.iter().map(|row| entry_from_row(row)).collect())
    }
}

/// The DO's `std.memory` capability provider: selected in the DO capability
/// dispatch when the effect's target capability binds to `memory-provider`
/// (seeded by the embedded std.memory manifest, DO package bootstrap). Opens a
/// `DoMemoryStore` over the shared DO SQLite and runs the host-agnostic
/// `run_memory_capability`, so DO recall/learn/curate behave like native.
pub struct DoMemoryCapabilityProvider<Sql: DoSql + Clone> {
    /// The shared DO SQLite handle (an `Rc<…>` in every real instantiation, so
    /// cloning it is a refcount bump, not a connection copy).
    pub sql: Sql,
}

impl<Sql: DoSql + Clone> CapabilityProvider for DoMemoryCapabilityProvider<Sql> {
    fn produce(&self, effect: &ClaimableEffect, _config: &EffectConfig) -> CapabilityOutcome {
        let mut store = match DoMemoryStore::open(self.sql.clone()) {
            Ok(store) => store,
            Err(error) => {
                return CapabilityOutcome::Failed {
                    error_kind: "memory".to_owned(),
                    message: format!("memory store: {error:?}"),
                };
            }
        };
        run_memory_capability(&mut store, effect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::types::{Value, ValueRef};
    use rusqlite::Connection;

    /// Minimal rusqlite-backed `DoSql` so the ported SQL runs against a real
    /// engine (mirrors the `RusqliteDoSql` in `do_store` tests).
    struct TestSql {
        conn: Connection,
    }
    fn to_value(v: &SqlValue) -> Value {
        match v {
            SqlValue::Null => Value::Null,
            SqlValue::Int(n) => Value::Integer(*n),
            SqlValue::Text(s) => Value::Text(s.clone()),
        }
    }
    fn from_ref(r: ValueRef<'_>) -> SqlValue {
        match r {
            ValueRef::Null => SqlValue::Null,
            ValueRef::Integer(n) => SqlValue::Int(n),
            ValueRef::Real(f) => SqlValue::Int(f as i64),
            ValueRef::Text(t) => SqlValue::Text(String::from_utf8_lossy(t).into_owned()),
            ValueRef::Blob(_) => SqlValue::Null,
        }
    }
    impl DoSql for TestSql {
        fn execute(&self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
            self.conn
                .execute(sql, rusqlite::params_from_iter(params.iter().map(to_value)))
                .map(|n| n as u64)
                .map_err(|e| e.to_string())
        }
        fn query(&self, sql: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            let mut stmt = self.conn.prepare(sql).map_err(|e| e.to_string())?;
            let cols = stmt.column_count();
            let rows = stmt
                .query_map(
                    rusqlite::params_from_iter(params.iter().map(to_value)),
                    |row| Ok((0..cols).map(|i| from_ref(row.get_ref_unwrap(i))).collect()),
                )
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<Vec<SqlValue>>, _>>()
                .map_err(|e| e.to_string())?;
            Ok(rows)
        }
    }

    fn store() -> DoMemoryStore<TestSql> {
        DoMemoryStore::open(TestSql {
            conn: Connection::open_in_memory().expect("sqlite"),
        })
        .expect("open")
    }

    fn learn<'a>(pool: &'a str, text: &'a str, effect: &'a str) -> NewMemoryEntry<'a> {
        NewMemoryEntry {
            pool,
            text,
            // Effect-plane determinism: empty created_at, recency rides memory_id.
            created_at: "",
            source_instance_id: None,
            source_effect_id: Some(effect),
            source_run_id: None,
            author_actor: None,
            source: None,
            note: None,
        }
    }

    #[test]
    fn write_query_round_trip_scopes_to_pool_and_matches_lexically() {
        let mut store = store();
        store
            .write(&learn("project", "deploy pipeline failed", "e1"))
            .unwrap();
        store
            .write(&learn("project", "login page latency", "e2"))
            .unwrap();
        store.write(&learn("other", "deploy notes", "e3")).unwrap();

        // Lexical LIKE match, scoped to the pool: only the deploy entry in
        // `project` qualifies (the `other`-pool deploy entry is out of scope).
        let hits = store.query("project", "deploy", None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "deploy pipeline failed");

        // A query with no indexable tokens falls back to recency.
        let recent = store.query("project", "!!!", None).unwrap();
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn query_orders_by_recency_and_respects_context_limit() {
        let mut store = store();
        for i in 0..5 {
            store
                .write(&learn("p", &format!("note {i} shared"), &format!("e{i}")))
                .unwrap();
        }
        let limited = store.query("p", "shared", Some(2)).unwrap();
        assert_eq!(limited.len(), 2);
        // Newest insertion first (memory_id DESC under empty created_at).
        assert_eq!(limited[0].text, "note 4 shared");
        assert_eq!(limited[1].text, "note 3 shared");
    }

    #[test]
    fn curate_dedupe_by_text_and_prune_report_counts_and_are_idempotent() {
        let mut store = store();
        store.write(&learn("p", "same", "e1")).unwrap();
        store.write(&learn("p", "same", "e2")).unwrap();
        store.write(&learn("p", "unique", "e3")).unwrap();

        let report = store.curate("p", CurateStrategy::DedupeByText).unwrap();
        assert_eq!(report.removed, 1);
        assert_eq!(report.kept, 2);
        // Idempotent: a re-run removes nothing further.
        let again = store.curate("p", CurateStrategy::DedupeByText).unwrap();
        assert_eq!(again.removed, 0);
        assert_eq!(again.kept, 2);

        // Prune keeps the newest `capacity` entries.
        store.write(&learn("p", "x", "e4")).unwrap();
        store.write(&learn("p", "y", "e5")).unwrap();
        let pruned = store
            .curate("p", CurateStrategy::Prune { capacity: 2 })
            .unwrap();
        assert_eq!(pruned.kept, 2);
    }

    #[test]
    fn pools_and_entries_list_state() {
        let mut store = store();
        store.write(&learn("a", "one", "e1")).unwrap();
        store.write(&learn("a", "two", "e2")).unwrap();
        store.write(&learn("b", "three", "e3")).unwrap();

        let pools = store.pools().unwrap();
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].pool, "a");
        assert_eq!(pools[0].entries, 2);
        assert_eq!(pools[1].pool, "b");

        let entries = store.entries("a", None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].text, "two"); // newest first
    }
}
