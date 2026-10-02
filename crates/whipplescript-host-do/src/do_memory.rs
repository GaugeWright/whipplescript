//! DO-plane memory store (spec/std-memory.md MEM-3;
//! spec/durable-object-runtime-tracker.md "DO-plane memory"): the std.memory
//! `local` provider's `MemoryStore` seam over `DoSql`, so memory pools work on
//! the durable object the same way they do natively.
//!
//! Same content table and FTS5 lexical contract as the native store. SQLite-backed
//! Durable Objects support FTS5; the derived index is initialized atomically and
//! backfilled once for an existing pool, without changing content or provenance.

use whipplescript_store::memory::{
    fts_match_expression, CurateStrategy, CurationReport, MemoryEntryRow, MemoryPoolRow,
    MemoryStore, NewMemoryEntry, DEFAULT_CONTEXT_LIMIT,
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
        // The table is the initialization marker: creation, triggers and legacy
        // backfill commit together. A failed first touch leaves no partial index
        // and may be retried. Backfill costs scale with existing entries once;
        // neither reopening a healthy store nor querying rebuilds the index.
        let indexed = sql
            .query(
                "SELECT name FROM sqlite_master WHERE name = 'memory_entries_fts'",
                &[],
            )
            .map_err(sql_err)?;
        if indexed.is_empty() {
            sql.atomic(&mut || {
                for statement in [
                    "CREATE VIRTUAL TABLE memory_entries_fts USING fts5(text, content='memory_entries', content_rowid='memory_id')",
                    "CREATE TRIGGER memory_entries_fts_insert AFTER INSERT ON memory_entries BEGIN INSERT INTO memory_entries_fts(rowid, text) VALUES (new.memory_id, new.text); END",
                    "CREATE TRIGGER memory_entries_fts_delete AFTER DELETE ON memory_entries BEGIN INSERT INTO memory_entries_fts(memory_entries_fts, rowid, text) VALUES ('delete', old.memory_id, old.text); END",
                    "INSERT INTO memory_entries_fts(memory_entries_fts) VALUES ('rebuild')",
                ] {
                    sql.execute(statement, &[]).map_err(sql_err)?;
                }
                Ok(())
            })?;
        }
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
        let Some(expression) = fts_match_expression(query_text) else {
            return self.entries(pool, Some(limit));
        };
        let sql = format!(
            "SELECT {ENTRY_COLUMNS} FROM memory_entries \
             WHERE pool = ?1 AND memory_id IN \
             (SELECT rowid FROM memory_entries_fts WHERE memory_entries_fts MATCH ?2) \
             ORDER BY created_at DESC, memory_id DESC LIMIT ?3"
        );
        let rows = self
            .sql
            .query(
                &sql,
                &[text(pool), text(&expression), SqlValue::Int(limit as i64)],
            )
            .map_err(sql_err)?;
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
    fn label(&self) -> &'static str {
        "memory-provider"
    }

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

    use crate::do_store::test_support::RusqliteDoSql as TestSql;

    fn store() -> DoMemoryStore<TestSql> {
        DoMemoryStore::open(TestSql::in_memory()).expect("open")
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
    fn native_and_hosted_lexical_retrieval_have_identical_results() {
        use whipplescript_store::memory::SqliteMemoryStore;
        let mut native = SqliteMemoryStore::open_in_memory().unwrap();
        let mut hosted = store();
        for (pool, value) in [
            ("p", "concatenate"),
            ("p", "CAT café running"),
            ("p", "cat dog"),
            ("p", "cat dog"),
            ("other", "cat café"),
            ("p", "punctuation hyphen-word"),
            ("p", "東京 café"),
        ] {
            let mut entry = learn(pool, value, "effect");
            entry.author_actor = Some("author");
            entry.source = Some("source");
            native.write(&entry).unwrap();
            hosted.write(&entry).unwrap();
        }
        for query in [
            "cat",
            "CAT",
            "cafe",
            "café",
            "東京",
            "run",
            "running",
            "cat OR dog",
            "hyphen-word",
            r#""cat" + dog"#,
            "!!!",
            "missing",
        ] {
            for limit in [None, Some(0), Some(1), Some(8)] {
                assert_eq!(
                    native.query("p", query, limit).unwrap(),
                    hosted.query("p", query, limit).unwrap(),
                    "query={query}, limit={limit:?}"
                );
            }
        }
        for strategy in [
            CurateStrategy::DedupeByText,
            CurateStrategy::Prune { capacity: 1 },
            CurateStrategy::Prune { capacity: 0 },
        ] {
            assert_eq!(
                native.curate("p", strategy).unwrap(),
                hosted.curate("p", strategy).unwrap()
            );
            assert_eq!(
                native.query("p", "cat café", None).unwrap(),
                hosted.query("p", "cat café", None).unwrap()
            );
            assert_eq!(
                native.query("other", "cat", None).unwrap(),
                hosted.query("other", "cat", None).unwrap()
            );
        }
    }

    struct InitializationSql {
        inner: TestSql,
        fail_rebuild: std::cell::Cell<bool>,
        rebuilds: std::cell::Cell<usize>,
    }

    impl DoSql for &InitializationSql {
        fn atomic(&self, body: &mut dyn FnMut() -> StoreResult<()>) -> StoreResult<()> {
            self.inner.atomic(body)
        }
        fn execute(&self, query: &str, params: &[SqlValue]) -> Result<u64, String> {
            if query.contains("VALUES ('rebuild')") {
                self.rebuilds.set(self.rebuilds.get() + 1);
                if self.fail_rebuild.get() {
                    return Err("injected backfill failure".into());
                }
            }
            self.inner.execute(query, params)
        }
        fn query(&self, query: &str, params: &[SqlValue]) -> Result<Vec<Vec<SqlValue>>, String> {
            self.inner.query(query, params)
        }
    }

    #[test]
    fn legacy_backfill_is_atomic_retryable_and_runs_once() {
        let sql = InitializationSql {
            inner: TestSql::in_memory(),
            fail_rebuild: std::cell::Cell::new(true),
            rebuilds: std::cell::Cell::new(0),
        };
        // Open's content schema remains readable even if index initialization fails.
        assert!(DoMemoryStore::open(&sql).is_err());
        sql.inner.execute("INSERT INTO memory_entries (pool, text, created_at, source_instance_id, source_effect_id, source_run_id, author_actor, source, note) VALUES ('p', 'legacy cat', '2026-10-02', 'instance', 'effect', 'run', 'owner', 'source', 'note')", &[]).unwrap();
        let original = sql
            .inner
            .query("SELECT * FROM memory_entries", &[])
            .unwrap();
        assert!(DoMemoryStore::open(&sql).is_err());
        assert_eq!(
            sql.inner
                .query("SELECT * FROM memory_entries", &[])
                .unwrap(),
            original
        );
        let artifacts = sql
            .inner
            .query(
                "SELECT name FROM sqlite_master WHERE name LIKE 'memory_entries_fts%'",
                &[],
            )
            .unwrap();
        assert!(
            artifacts.is_empty(),
            "failed initialization must roll back index and triggers"
        );
        assert_eq!(
            sql.inner
                .query("SELECT COUNT(*) FROM memory_entries", &[])
                .unwrap()[0][0],
            SqlValue::Int(1)
        );
        sql.fail_rebuild.set(false);
        let mut first = DoMemoryStore::open(&sql).unwrap();
        let hits = first.query("p", "cat", None).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].author_actor.as_deref(), Some("owner"));
        let mut native = whipplescript_store::memory::SqliteMemoryStore::open_in_memory().unwrap();
        let mut legacy = learn("p", "legacy cat", "unused");
        legacy.created_at = "2026-10-02";
        legacy.source_instance_id = Some("instance");
        legacy.source_effect_id = Some("effect");
        legacy.source_run_id = Some("run");
        legacy.author_actor = Some("owner");
        legacy.source = Some("source");
        legacy.note = Some("note");
        native.write(&legacy).unwrap();
        assert_eq!(hits, native.query("p", "cat", None).unwrap());
        let rebuilds = sql.rebuilds.get();
        let mut new = learn("p", "new cat", "e1");
        new.created_at = "2026-10-03";
        first.write(&new).unwrap();
        new.source_effect_id = Some("e2");
        first.write(&new).unwrap();
        first.curate("p", CurateStrategy::DedupeByText).unwrap();
        assert_eq!(first.query("p", "cat", None).unwrap().len(), 2);
        first
            .curate("p", CurateStrategy::Prune { capacity: 1 })
            .unwrap();
        let reopened = DoMemoryStore::open(&sql).unwrap();
        assert_eq!(reopened.query("p", "legacy", None).unwrap().len(), 0);
        assert_eq!(reopened.query("p", "new", None).unwrap().len(), 1);
        assert_eq!(
            sql.rebuilds.get(),
            rebuilds,
            "healthy reopen/query must not rebuild"
        );
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

        // Lexical FTS5 match, scoped to the pool: only the deploy entry in
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
