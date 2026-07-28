//! Memory-pool store seam (std.memory MEM-3, spec/std-memory.md "Providers").
//!
//! The `local` memory provider's storage layer: workspace-scoped SQLite behind
//! the backend-agnostic [`MemoryStore`] trait (the Coordination/FileStore seam
//! pattern), so a durable-object SQLite backend can implement the same
//! write/query/curate operations without the language changing. The trait is
//! ungated; only the rusqlite-backed [`SqliteMemoryStore`] is `native`.
//!
//! Retrieval v1 is deliberately boring: FTS5 lexical match + pool scoping +
//! recency ordering. Entries are append-only — a stored entry is never
//! updated; `curate` only deletes (dedupe/prune), so the external-content FTS
//! index needs insert/delete triggers only.
//!
//! Every entry carries provenance columns (source instance/effect/run, author
//! actor, `created_at`) plus the optional `source`/`note` material a
//! `learn from <source> [{ note <expr> }]` records. Timestamps are
//! caller-supplied TEXT — the store never reads a clock, so replay is stable.

use std::path::PathBuf;

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, Row};

#[cfg(feature = "native")]
use crate::StoreError;
use crate::StoreResult;

/// Environment override for the memory store path.
pub const MEMORY_STORE_ENV: &str = "WHIPPLESCRIPT_MEMORY_STORE";

/// Workspace-scoped default path, beside the improve/backlog stores.
pub const DEFAULT_MEMORY_STORE_PATH: &str = ".whipplescript/memory.sqlite";

/// Recall packing budget applied when the effect input carries no
/// `context limit` (the pool clause is optional, spec/std-memory.md "Pool
/// declaration").
pub const DEFAULT_CONTEXT_LIMIT: usize = 8;

/// The active memory store path: [`MEMORY_STORE_ENV`] when set and non-empty,
/// else [`DEFAULT_MEMORY_STORE_PATH`] under the current workspace.
pub fn memory_store_path() -> PathBuf {
    match std::env::var(MEMORY_STORE_ENV) {
        Ok(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => PathBuf::from(DEFAULT_MEMORY_STORE_PATH),
    }
}

/// Input for one learned entry. Provenance identifies where the material came
/// from: the writing instance/effect/run and the acting author; `source` is
/// the resolved `from <source>` value and `note` the optional `{ note <expr> }`
/// field (the same material the capability effect input carries).
#[derive(Clone, Copy, Debug, Default)]
pub struct NewMemoryEntry<'a> {
    pub pool: &'a str,
    pub text: &'a str,
    /// Caller-supplied timestamp (TEXT, lexicographically ordered — RFC 3339
    /// or `datetime('now')` shape). The store never reads a clock.
    pub created_at: &'a str,
    pub source_instance_id: Option<&'a str>,
    pub source_effect_id: Option<&'a str>,
    pub source_run_id: Option<&'a str>,
    pub author_actor: Option<&'a str>,
    pub source: Option<&'a str>,
    pub note: Option<&'a str>,
}

/// One stored entry with its identity and provenance — the material a
/// `MemoryContext` entry (`{memory_id, text, created_at, provenance}`) and the
/// `whip memory entries` listing are built from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryEntryRow {
    pub memory_id: i64,
    pub pool: String,
    pub text: String,
    pub created_at: String,
    pub source_instance_id: Option<String>,
    pub source_effect_id: Option<String>,
    pub source_run_id: Option<String>,
    pub author_actor: Option<String>,
    pub source: Option<String>,
    pub note: Option<String>,
}

/// One pool head-line for the `whip memory pools` listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryPoolRow {
    pub pool: String,
    pub entries: i64,
    pub last_created_at: Option<String>,
}

/// v1 curation strategies (provider defaults — the curation policy grammar is
/// deferred, spec/std-memory.md "Deferred with cause").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CurateStrategy {
    /// Drop entries whose text duplicates an earlier entry in the pool
    /// (first occurrence kept).
    DedupeByText,
    /// Drop entries duplicating an earlier entry's (source, note) pair —
    /// the JSONL fixture provider's dedupe key. Absent fields compare equal.
    DedupeBySourceNote,
    /// Keep only the newest `capacity` entries in the pool (the pool
    /// `context limit`/capacity budget).
    Prune { capacity: usize },
}

/// Applied-changes report for one curate pass (feeds the
/// `MemoryCurationResult` output and curate evidence).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CurationReport {
    pub removed: usize,
    pub kept: usize,
}

/// The memory-pool operations the `local` provider performs, abstracted over
/// the physical backing (sans-IO seam). Object-safe so a host can hold a
/// `&dyn MemoryStore`; a durable-object SQLite port implements the same
/// surface (the MEM-3 DO-tracker row).
pub trait MemoryStore {
    /// Store one entry into its pool; returns the assigned `memory_id`.
    fn write(&mut self, entry: &NewMemoryEntry<'_>) -> StoreResult<i64>;

    /// Lexical retrieval scoped to `pool`: entries matching any query token,
    /// newest first, capped at `context_limit` (default
    /// [`DEFAULT_CONTEXT_LIMIT`]). A query with no indexable tokens falls back
    /// to pure recency, so recall always returns a valid (possibly empty)
    /// context.
    fn query(
        &self,
        pool: &str,
        query_text: &str,
        context_limit: Option<usize>,
    ) -> StoreResult<Vec<MemoryEntryRow>>;

    /// Apply one curation strategy to `pool`; other pools are untouched.
    /// Idempotent: re-running the same strategy removes nothing further.
    fn curate(&mut self, pool: &str, strategy: CurateStrategy) -> StoreResult<CurationReport>;

    /// Every pool with at least one entry (`whip memory pools`).
    fn pools(&self) -> StoreResult<Vec<MemoryPoolRow>>;

    /// The pool's entries, newest first, capped at `limit` when given
    /// (`whip memory entries <pool>`).
    fn entries(&self, pool: &str, limit: Option<usize>) -> StoreResult<Vec<MemoryEntryRow>>;
}

/// Native backing: a workspace-scoped SQLite file (default
/// [`DEFAULT_MEMORY_STORE_PATH`], override [`MEMORY_STORE_ENV`]). FTS5 is
/// compiled into the bundled amalgamation unconditionally (libsqlite3-sys
/// passes `-DSQLITE_ENABLE_FTS5` for every bundled build), so lexical match
/// rides a real inverted index rather than `LIKE` scans.
#[cfg(feature = "native")]
pub struct SqliteMemoryStore {
    connection: Connection,
}

#[cfg(feature = "native")]
impl SqliteMemoryStore {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let connection = Connection::open(path).map_err(StoreError::from)?;
        Self::bootstrap(connection)
    }

    /// Open at the active path ([`memory_store_path`]).
    pub fn open_default() -> StoreResult<Self> {
        Self::open(memory_store_path())
    }

    pub fn open_in_memory() -> StoreResult<Self> {
        let connection = Connection::open_in_memory().map_err(StoreError::from)?;
        Self::bootstrap(connection)
    }

    fn bootstrap(connection: Connection) -> StoreResult<Self> {
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 CREATE TABLE IF NOT EXISTS memory_entries (
                   memory_id INTEGER PRIMARY KEY AUTOINCREMENT,
                   pool TEXT NOT NULL,
                   text TEXT NOT NULL,
                   created_at TEXT NOT NULL,
                   source_instance_id TEXT,
                   source_effect_id TEXT,
                   source_run_id TEXT,
                   author_actor TEXT,
                   source TEXT,
                   note TEXT
                 );
                 CREATE INDEX IF NOT EXISTS idx_memory_pool_created
                   ON memory_entries(pool, created_at);
                 CREATE VIRTUAL TABLE IF NOT EXISTS memory_entries_fts USING fts5(
                   text,
                   content='memory_entries',
                   content_rowid='memory_id'
                 );
                 CREATE TRIGGER IF NOT EXISTS memory_entries_fts_insert
                 AFTER INSERT ON memory_entries BEGIN
                   INSERT INTO memory_entries_fts(rowid, text)
                   VALUES (new.memory_id, new.text);
                 END;
                 CREATE TRIGGER IF NOT EXISTS memory_entries_fts_delete
                 AFTER DELETE ON memory_entries BEGIN
                   INSERT INTO memory_entries_fts(memory_entries_fts, rowid, text)
                   VALUES ('delete', old.memory_id, old.text);
                 END;",
            )
            .map_err(StoreError::from)?;
        Ok(Self { connection })
    }

    fn kept_in_pool(&self, pool: &str) -> StoreResult<usize> {
        let kept: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM memory_entries WHERE pool = ?1",
            params![pool],
            |row| row.get(0),
        )?;
        Ok(kept as usize)
    }
}

#[cfg(feature = "native")]
const ENTRY_COLUMNS: &str = "memory_id, pool, text, created_at, source_instance_id, \
     source_effect_id, source_run_id, author_actor, source, note";

#[cfg(feature = "native")]
fn entry_from_row(row: &Row<'_>) -> rusqlite::Result<MemoryEntryRow> {
    Ok(MemoryEntryRow {
        memory_id: row.get(0)?,
        pool: row.get(1)?,
        text: row.get(2)?,
        created_at: row.get(3)?,
        source_instance_id: row.get(4)?,
        source_effect_id: row.get(5)?,
        source_run_id: row.get(6)?,
        author_actor: row.get(7)?,
        source: row.get(8)?,
        note: row.get(9)?,
    })
}

/// Raw query text as a safe FTS5 expression: alphanumeric tokens, each quoted
/// (never parsed as FTS syntax), joined with OR so any-token match qualifies.
/// `None` when the text has no indexable tokens.
#[cfg(feature = "native")]
fn fts_match_expression(query_text: &str) -> Option<String> {
    let tokens: Vec<String> = query_text
        .split(|c: char| !c.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| format!("\"{token}\""))
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" OR "))
    }
}

#[cfg(feature = "native")]
impl MemoryStore for SqliteMemoryStore {
    fn write(&mut self, entry: &NewMemoryEntry<'_>) -> StoreResult<i64> {
        self.connection.execute(
            "INSERT INTO memory_entries (pool, text, created_at, source_instance_id, \
             source_effect_id, source_run_id, author_actor, source, note) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                entry.pool,
                entry.text,
                entry.created_at,
                entry.source_instance_id,
                entry.source_effect_id,
                entry.source_run_id,
                entry.author_actor,
                entry.source,
                entry.note,
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    fn query(
        &self,
        pool: &str,
        query_text: &str,
        context_limit: Option<usize>,
    ) -> StoreResult<Vec<MemoryEntryRow>> {
        let limit = context_limit.unwrap_or(DEFAULT_CONTEXT_LIMIT) as i64;
        let Some(match_expression) = fts_match_expression(query_text) else {
            return self.entries(pool, Some(limit as usize));
        };
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM memory_entries \
             WHERE pool = ?1 AND memory_id IN \
               (SELECT rowid FROM memory_entries_fts WHERE memory_entries_fts MATCH ?2) \
             ORDER BY created_at DESC, memory_id DESC LIMIT ?3",
        ))?;
        let rows = statement
            .query_map(params![pool, match_expression, limit], entry_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn curate(&mut self, pool: &str, strategy: CurateStrategy) -> StoreResult<CurationReport> {
        let removed = match strategy {
            CurateStrategy::DedupeByText => self.connection.execute(
                "DELETE FROM memory_entries WHERE pool = ?1 AND memory_id NOT IN \
                 (SELECT MIN(memory_id) FROM memory_entries WHERE pool = ?1 GROUP BY text)",
                params![pool],
            )?,
            CurateStrategy::DedupeBySourceNote => self.connection.execute(
                "DELETE FROM memory_entries WHERE pool = ?1 AND memory_id NOT IN \
                 (SELECT MIN(memory_id) FROM memory_entries WHERE pool = ?1 \
                  GROUP BY source, note)",
                params![pool],
            )?,
            CurateStrategy::Prune { capacity } => self.connection.execute(
                "DELETE FROM memory_entries WHERE pool = ?1 AND memory_id NOT IN \
                 (SELECT memory_id FROM memory_entries WHERE pool = ?1 \
                  ORDER BY created_at DESC, memory_id DESC LIMIT ?2)",
                params![pool, capacity as i64],
            )?,
        };
        Ok(CurationReport {
            removed,
            kept: self.kept_in_pool(pool)?,
        })
    }

    fn pools(&self) -> StoreResult<Vec<MemoryPoolRow>> {
        let mut statement = self.connection.prepare(
            "SELECT pool, COUNT(*), MAX(created_at) FROM memory_entries \
             GROUP BY pool ORDER BY pool",
        )?;
        let rows = statement
            .query_map([], |row| {
                Ok(MemoryPoolRow {
                    pool: row.get(0)?,
                    entries: row.get(1)?,
                    last_created_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    fn entries(&self, pool: &str, limit: Option<usize>) -> StoreResult<Vec<MemoryEntryRow>> {
        // SQLite `LIMIT -1` means unlimited.
        let limit = limit.map_or(-1, |limit| limit as i64);
        let mut statement = self.connection.prepare(&format!(
            "SELECT {ENTRY_COLUMNS} FROM memory_entries WHERE pool = ?1 \
             ORDER BY created_at DESC, memory_id DESC LIMIT ?2",
        ))?;
        let rows = statement
            .query_map(params![pool, limit], entry_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    fn store() -> SqliteMemoryStore {
        SqliteMemoryStore::open_in_memory().expect("open store")
    }

    fn entry<'a>(pool: &'a str, text: &'a str, created_at: &'a str) -> NewMemoryEntry<'a> {
        NewMemoryEntry {
            pool,
            text,
            created_at,
            ..NewMemoryEntry::default()
        }
    }

    #[test]
    fn write_query_round_trip_scopes_to_pool() {
        let mut store = store();
        store
            .write(&entry(
                "alpha",
                "quota exceeded on deploy",
                "2026-07-01T00:00:00Z",
            ))
            .expect("write");
        store
            .write(&entry(
                "beta",
                "quota exceeded on deploy",
                "2026-07-01T00:00:01Z",
            ))
            .expect("write");
        let hits = store.query("alpha", "quota", None).expect("query");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].pool, "alpha");
        assert_eq!(hits[0].text, "quota exceeded on deploy");
        let pools = store.pools().expect("pools");
        assert_eq!(
            pools.iter().map(|p| p.pool.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "beta"],
        );
        assert_eq!(pools[0].entries, 1);
    }

    #[test]
    fn query_orders_by_recency_and_respects_context_limit() {
        let mut store = store();
        store
            .write(&entry("p", "release note one", "2026-07-01T00:00:00Z"))
            .expect("write");
        store
            .write(&entry("p", "release note two", "2026-07-03T00:00:00Z"))
            .expect("write");
        store
            .write(&entry("p", "release note three", "2026-07-02T00:00:00Z"))
            .expect("write");
        let hits = store.query("p", "release", None).expect("query");
        assert_eq!(
            hits.iter().map(|h| h.text.as_str()).collect::<Vec<_>>(),
            vec!["release note two", "release note three", "release note one"],
        );
        let capped = store.query("p", "release", Some(1)).expect("query");
        assert_eq!(capped.len(), 1);
        assert_eq!(capped[0].text, "release note two");
    }

    #[test]
    fn query_matches_lexically_and_excludes_non_matching() {
        let mut store = store();
        store
            .write(&entry(
                "p",
                "deploy failed on quota",
                "2026-07-01T00:00:00Z",
            ))
            .expect("write");
        store
            .write(&entry("p", "unrelated musing", "2026-07-02T00:00:00Z"))
            .expect("write");
        let hits = store.query("p", "quota", None).expect("query");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text, "deploy failed on quota");
        // Punctuation-heavy query text never reaches FTS as syntax.
        let quoted = store
            .query("p", "\"quota\" AND (deploy)", None)
            .expect("query");
        assert!(quoted.iter().any(|h| h.text == "deploy failed on quota"));
        // No indexable tokens: recency fallback, never an error.
        let fallback = store.query("p", "???", None).expect("query");
        assert_eq!(fallback.len(), 2);
        assert_eq!(fallback[0].text, "unrelated musing");
    }

    #[test]
    fn curate_dedupe_removes_duplicates_and_reports_counts() {
        let mut store = store();
        store
            .write(&entry("p", "same lesson", "2026-07-01T00:00:00Z"))
            .expect("write");
        store
            .write(&entry("p", "same lesson", "2026-07-02T00:00:00Z"))
            .expect("write");
        store
            .write(&entry("p", "different lesson", "2026-07-03T00:00:00Z"))
            .expect("write");
        store
            .write(&entry("other", "same lesson", "2026-07-04T00:00:00Z"))
            .expect("write");
        let report = store
            .curate("p", CurateStrategy::DedupeByText)
            .expect("curate");
        assert_eq!(
            report,
            CurationReport {
                removed: 1,
                kept: 2
            }
        );
        // The first occurrence survives; other pools are untouched.
        let kept = store.entries("p", None).expect("entries");
        assert!(kept
            .iter()
            .any(|e| e.text == "same lesson" && e.created_at == "2026-07-01T00:00:00Z"));
        assert_eq!(store.entries("other", None).expect("entries").len(), 1);
    }

    #[test]
    fn curate_dedupe_by_source_note_uses_provenance_key() {
        let mut store = store();
        let mut first = entry("p", "text a", "2026-07-01T00:00:00Z");
        first.source = Some("run outcome");
        first.note = Some("flaky");
        let mut second = entry("p", "text b", "2026-07-02T00:00:00Z");
        second.source = Some("run outcome");
        second.note = Some("flaky");
        let mut third = entry("p", "text c", "2026-07-03T00:00:00Z");
        third.source = Some("run outcome");
        third.note = Some("stable");
        store.write(&first).expect("write");
        store.write(&second).expect("write");
        store.write(&third).expect("write");
        let report = store
            .curate("p", CurateStrategy::DedupeBySourceNote)
            .expect("curate");
        assert_eq!(
            report,
            CurationReport {
                removed: 1,
                kept: 2
            }
        );
    }

    #[test]
    fn curate_prune_keeps_newest_capacity_entries() {
        let mut store = store();
        for (text, at) in [
            ("oldest", "2026-07-01T00:00:00Z"),
            ("middle", "2026-07-02T00:00:00Z"),
            ("newest", "2026-07-03T00:00:00Z"),
        ] {
            store.write(&entry("p", text, at)).expect("write");
        }
        let report = store
            .curate("p", CurateStrategy::Prune { capacity: 2 })
            .expect("curate");
        assert_eq!(
            report,
            CurationReport {
                removed: 1,
                kept: 2
            }
        );
        let kept = store.entries("p", None).expect("entries");
        assert_eq!(
            kept.iter().map(|e| e.text.as_str()).collect::<Vec<_>>(),
            vec!["newest", "middle"],
        );
    }

    #[test]
    fn curate_is_idempotent_on_rerun() {
        let mut store = store();
        store
            .write(&entry("p", "same lesson", "2026-07-01T00:00:00Z"))
            .expect("write");
        store
            .write(&entry("p", "same lesson", "2026-07-02T00:00:00Z"))
            .expect("write");
        let first = store
            .curate("p", CurateStrategy::DedupeByText)
            .expect("curate");
        assert_eq!(
            first,
            CurationReport {
                removed: 1,
                kept: 1
            }
        );
        let second = store
            .curate("p", CurateStrategy::DedupeByText)
            .expect("curate");
        assert_eq!(
            second,
            CurationReport {
                removed: 0,
                kept: 1
            }
        );
        // The FTS index survives curation deletes: the kept entry still matches.
        assert_eq!(store.query("p", "lesson", None).expect("query").len(), 1);
    }

    #[test]
    fn provenance_survives_round_trip() {
        let mut store = store();
        let full = NewMemoryEntry {
            pool: "p",
            text: "the whole story",
            created_at: "2026-07-01T00:00:00Z",
            source_instance_id: Some("inst-1"),
            source_effect_id: Some("eff-1"),
            source_run_id: Some("run-1"),
            author_actor: Some("agent:triage"),
            source: Some("run outcome"),
            note: Some("keep an eye on this"),
        };
        let memory_id = store.write(&full).expect("write");
        let hits = store.query("p", "story", None).expect("query");
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!(hit.memory_id, memory_id);
        assert_eq!(hit.created_at, "2026-07-01T00:00:00Z");
        assert_eq!(hit.source_instance_id.as_deref(), Some("inst-1"));
        assert_eq!(hit.source_effect_id.as_deref(), Some("eff-1"));
        assert_eq!(hit.source_run_id.as_deref(), Some("run-1"));
        assert_eq!(hit.author_actor.as_deref(), Some("agent:triage"));
        assert_eq!(hit.source.as_deref(), Some("run outcome"));
        assert_eq!(hit.note.as_deref(), Some("keep an eye on this"));
    }

    #[test]
    fn env_override_path_is_respected() {
        // Single test owns MEMORY_STORE_ENV (parallel tests never read it).
        assert_eq!(
            memory_store_path(),
            PathBuf::from(DEFAULT_MEMORY_STORE_PATH),
        );
        let override_path = std::env::temp_dir().join(format!(
            "whipplescript-memory-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        std::env::set_var(MEMORY_STORE_ENV, &override_path);
        assert_eq!(memory_store_path(), override_path);
        let mut store = SqliteMemoryStore::open_default().expect("open store");
        store
            .write(&entry(
                "p",
                "landed at the override path",
                "2026-07-01T00:00:00Z",
            ))
            .expect("write");
        std::env::remove_var(MEMORY_STORE_ENV);
        assert!(override_path.exists());
        let _ = std::fs::remove_file(&override_path);
    }
}
