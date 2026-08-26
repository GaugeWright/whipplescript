//! Content-addressed blob store for large tool outputs (context-assembly Phase 5).
//!
//! When an owned-harness tool produces an output too large for the model context,
//! the executor middle-truncates what the model sees but stores the FULL bytes here,
//! keyed by a stable content hash, and hands the model a recall id. The `recall`
//! tool reads the full bytes back (paginated) — so truncation is lossless, not
//! lossy (the WhippleScript edge over Codex/pi). It is also what makes Layer A's
//! "full output kept as evidence" promise true, and what the `ToolResultCompactor`
//! elides old tool results down to.
//!
//! Workspace-scoped and disposable-friendly like the other auxiliary stores
//! (coordination, work items): one small table opened over a path. Identical bytes
//! dedupe to one id. The shape (put/get by hash) is durable-object portable; the
//! DO mirror lands with the DO agent-tool executor.

#[cfg(feature = "native")]
use std::path::Path;

#[cfg(feature = "native")]
use rusqlite::{params, Connection, OptionalExtension};

/// Upper bound on the buffer pre-allocated when reassembling a chunk root.
/// A root's stored `byte_len` is attacker-controlled through bundle import
/// and is not committed to by the verified root id, so it is never trusted
/// as an allocation size — the reassembled string still grows to fit the
/// real (stored, hence bounded) chunk bytes.
#[cfg(feature = "native")]
const MAX_REASSEMBLE_PREALLOC: usize = 8 * 1024 * 1024;

/// Default ceiling on a single content blob's reassembled size (256 MiB).
/// A chunk root's `chunk_ids` may repeat the same chunk id — legitimate for
/// deduped repetitive content, but also the lever for an amplification bomb
/// (a tiny bundle whose root reassembles to gigabytes from one shared chunk).
/// There is no structural way to tell the two apart, so an absolute size
/// ceiling is the only real defense. Content-store bodies are UTF-8 text, so
/// this is generous for real files. Override with `WHIPPLESCRIPT_MAX_BLOB_BYTES`.
const DEFAULT_MAX_BLOB_BYTES: u64 = 256 * 1024 * 1024;

/// The active per-blob size ceiling, read from `WHIPPLESCRIPT_MAX_BLOB_BYTES`
/// (bytes) or the 256 MiB default. A malformed/zero override falls back to the
/// default rather than disabling the guard. Un-gated: the bundle-import
/// choke point in vcs.rs is host-agnostic and consults it too.
pub(crate) fn max_blob_bytes() -> u64 {
    std::env::var("WHIPPLESCRIPT_MAX_BLOB_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|&bytes| bytes > 0)
        .unwrap_or(DEFAULT_MAX_BLOB_BYTES)
}

/// What the store knows about a content id: alive with payload, erased
/// under the honesty downgrade (identity + size retained, payload gone),
/// or never seen.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BlobStatus {
    Live { byte_len: u64 },
    Erased { byte_len: u64 },
    Unknown,
}

/// Outcome of a `purge_unreachable` sweep: how many orphaned plain blob
/// rows were reclaimed and how many rows remain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurgeOutcome {
    pub purged: usize,
    pub retained: usize,
}

/// Outcome of a per-blob erasure request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EraseOutcome {
    /// Payload dropped; hash and size retained.
    Erased {
        byte_len: u64,
    },
    /// The idempotent retry.
    AlreadyErased,
    Unknown,
    /// This host's blob seam has no erasure (fail-honest, never
    /// fail-silent: the caller learns nothing was dropped).
    Unsupported,
}

/// DR-0066 §3: check that `body` hashes to `id`, and refuse if it does not.
///
/// **Where this is and is not applied.** Verification costs a hash per read,
/// and the manifest tree reads one blob per node, so hashing every local read
/// would put a hash on the hot path that #240's work just cleared. The line
/// drawn here is *trust boundary*, not *every read*: bytes are verified where
/// the reader did not itself derive the id from those bytes — across a cache,
/// across an authority, and on a manifest body before it is parsed into a
/// closure. A store reading a row it hashed itself on the way in is not a
/// boundary, and `ContentStore::get` deliberately does not pay for one.
///
/// That is narrower than §3 reads, and `spec/remote-substrate-conformance.md`
/// records the narrowing rather than leaving it implied.
pub fn verify_body(id: &str, body: &str, source: &'static str) -> crate::StoreResult<()> {
    let actual = crate::stable_hash_hex(body);
    if actual == id {
        return Ok(());
    }
    Err(crate::StoreError::ContentMismatch {
        id: id.to_owned(),
        actual,
        source,
    })
}

/// The content-addressed put/get seam, object-safe so the versioned
/// workspace (working sets, manifests) runs over any host's blob table:
/// natively `ContentStore`, on the durable object a thin impl over the
/// shared `DoSql` handle. Identical bytes dedupe to one id.
pub trait ContentBlobs {
    /// Store `body`, returning its content id (a stable hash of the
    /// bytes). Idempotent.
    fn put(&self, body: &str) -> crate::StoreResult<String>;
    /// Read the full stored bytes for a content id, or `None` if unknown.
    fn get(&self, id: &str) -> crate::StoreResult<Option<String>>;
    /// What the store knows about an id. The default derives Live/Unknown
    /// from `get`; stores with erasure override to report tombstones.
    fn status(&self, id: &str) -> crate::StoreResult<BlobStatus> {
        Ok(match self.get(id)? {
            Some(body) => BlobStatus::Live {
                byte_len: body.len() as u64,
            },
            None => BlobStatus::Unknown,
        })
    }
    /// Per-blob erasure (the honesty downgrade): drop the payload, retain
    /// hash + size. Hosts without an erasure path report `Unsupported`
    /// rather than pretending.
    fn erase(&self, _id: &str, _at: &str) -> crate::StoreResult<EraseOutcome> {
        Ok(EraseOutcome::Unsupported)
    }
    /// The ordered chunk ids under a chunk root, or `None` when the id is
    /// not a root. Chunk-granular transfer's seam: a bundle carries the
    /// root's structure and only the missing chunks travel.
    fn chunk_ids(&self, _id: &str) -> crate::StoreResult<Option<Vec<String>>> {
        Ok(None)
    }
    /// Record a chunk root's structure (transport support: the receiving
    /// side re-links roots without re-chunking). Hosts without a chunk
    /// tier refuse rather than silently dropping structure.
    fn put_chunk_root(
        &self,
        _root_id: &str,
        _chunk_ids: &[String],
        _byte_len: u64,
    ) -> crate::StoreResult<()> {
        Err(crate::StoreError::Conflict(
            "this content store has no chunk tier".to_owned(),
        ))
    }
}

/// The content plane's executable conformance driver, shipped with the trait so
/// every implementation runs the same one — the third such suite, after
/// `ref_authority::conformance` and `log_append::conformance`.
///
/// Not `#[cfg(test)]`, for the reason the others are not: a driver that only
/// exists in the defining crate's tests cannot be run by an implementation in
/// another crate, which is exactly the case it exists for.
pub mod conformance {
    use super::{BlobStatus, ContentBlobs, EraseOutcome};
    use crate::StoreResult;

    /// Check the obligations DR-0066 places on any content store.
    ///
    /// Takes a factory rather than a store so each check starts clean, and so a
    /// caller cannot accidentally have one check depend on another's leftovers.
    ///
    /// # Errors
    /// Propagates store failures. A contract violation panics with what was
    /// expected, because a conformance failure is not a value the caller
    /// handles — it means the implementation is not one.
    pub fn run_suite<B: ContentBlobs>(make: impl Fn() -> B) -> StoreResult<()> {
        // Identical bytes dedupe to one id — the property every other
        // conclusion about content addressing rests on.
        let blobs = make();
        let first = blobs.put("the same bytes")?;
        let second = blobs.put("the same bytes")?;
        assert_eq!(first, second, "identical bytes must dedupe to one id");
        assert_ne!(
            first,
            blobs.put("different bytes")?,
            "different bytes must not share an id"
        );
        // ...and distinctness must not come from LENGTH. Added 2026-08-25,
        // because the pair above happens to differ in length (14 bytes against
        // 15), so a store keying on `body.len()` satisfied it — and one did.
        // `preflight::FakeBlobs` minted `blob_{len}` for months and passed this
        // suite by that coincidence, which made every preflight test a check
        // against a store where two equal-length bodies are the same content.
        //
        // This is the case that costs nothing and closes the coincidence: two
        // distinct bodies of EQUAL length must still differ.
        let same_length_a = blobs.put("aaaa")?;
        let same_length_b = blobs.put("bbbb")?;
        assert_ne!(
            same_length_a, same_length_b,
            "two distinct bodies of the same length must not share an id — an \
             id derived from length is not a content address"
        );

        // What was stored is what comes back.
        let blobs = make();
        let id = blobs.put("round trip")?;
        assert_eq!(
            blobs.get(&id)?.as_deref(),
            Some("round trip"),
            "a stored blob must read back byte-identical"
        );

        // status and get must agree. Two functions disagreeing about whether a
        // blob exists reads as a successful erasure to everything downstream —
        // the divergence that was live in `erase` before DR-0070's pack fix.
        assert!(
            matches!(blobs.status(&id)?, BlobStatus::Live { .. }),
            "status must report Live for a blob get returns"
        );
        assert!(
            matches!(blobs.status("never-stored")?, BlobStatus::Unknown),
            "status must report Unknown for an id the store has never seen"
        );
        assert_eq!(
            blobs.get("never-stored")?,
            None,
            "get must report nothing for an id the store has never seen"
        );

        // C1: erased is not absent. A store without an erasure path says so
        // rather than pretending, and the suite honours that instead of
        // failing it — fail-honest is the contract, not erasure itself.
        let blobs = make();
        let doomed = blobs.put("doomed")?;
        match blobs.erase(&doomed, "2026-08-24T00:00:00Z")? {
            EraseOutcome::Unsupported => {}
            EraseOutcome::Erased { .. } | EraseOutcome::AlreadyErased => {
                assert!(
                    matches!(blobs.status(&doomed)?, BlobStatus::Erased { .. }),
                    "an erased blob must read as Erased, never as Unknown — a caller \
                     told 'absent' retries forever for bytes that are gone"
                );
                assert_eq!(
                    blobs.get(&doomed)?,
                    None,
                    "erasure must remove the bytes, not merely the tombstone's absence"
                );
                // Idempotent retry.
                assert!(
                    matches!(
                        blobs.erase(&doomed, "2026-08-24T00:00:01Z")?,
                        EraseOutcome::AlreadyErased | EraseOutcome::Erased { .. }
                    ),
                    "re-erasing must be idempotent, not an error"
                );
            }
            EraseOutcome::Unknown => panic!(
                "erase reported Unknown for a blob the store just accepted — status \
                 and erase disagree about whether it exists"
            ),
        }

        // Erasing something never stored is Unknown, not a silent success.
        let blobs = make();
        assert!(
            matches!(
                blobs.erase("never-stored", "2026-08-24T00:00:00Z")?,
                EraseOutcome::Unknown | EraseOutcome::Unsupported
            ),
            "erasing an unknown id must say so"
        );
        Ok(())
    }
}

use crate::StoreResult;

#[cfg(feature = "native")]
pub struct ContentStore {
    connection: Connection,
}

#[cfg(feature = "native")]
impl ContentStore {
    /// Open (creating if needed) the content-addressed store at `path`.
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let connection = Connection::open(path)?;
        crate::establish_wal(&connection)?;
        ensure_content_schema(&connection)?;
        Ok(Self { connection })
    }

    /// Store `body`, returning its content id (a stable hash of the bytes).
    /// Idempotent: identical bytes dedupe to the same id and one row.
    pub fn put(&self, body: &str) -> StoreResult<String> {
        ContentBlobs::put(self, body)
    }

    /// Conservative orphan sweep: delete plain blob rows unreachable from
    /// `roots`. Deliberately narrow so a wrong root set can only RETAIN
    /// too much, never break a readable id: erasure tombstones are a
    /// different honesty plane (never touched), and the whole chunk tier
    /// — chunk payloads, roots, refs, pack payloads — is left to its own
    /// erasure discipline.
    pub fn purge_unreachable(
        &self,
        roots: &std::collections::BTreeSet<String>,
    ) -> StoreResult<PurgeOutcome> {
        self.connection.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS gc_roots (id TEXT PRIMARY KEY); \
             DELETE FROM gc_roots;",
        )?;
        {
            let mut insert = self
                .connection
                .prepare("INSERT OR IGNORE INTO gc_roots (id) VALUES (?1)")?;
            for id in roots {
                insert.execute(params![id])?;
            }
        }
        let purged = self.connection.execute(
            "DELETE FROM content_blobs WHERE id NOT IN (SELECT id FROM gc_roots) \
             AND id NOT IN (SELECT chunk_id FROM content_chunk_refs) \
             AND id NOT IN (SELECT pack_id FROM content_pack_entries)",
            [],
        )?;
        let retained: i64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM content_blobs", [], |row| row.get(0))?;
        self.connection
            .execute_batch("DROP TABLE IF EXISTS gc_roots;")?;
        Ok(PurgeOutcome {
            purged,
            retained: retained as usize,
        })
    }

    /// Read the full stored bytes for a content id, or `None` if unknown.
    pub fn get(&self, id: &str) -> StoreResult<Option<String>> {
        ContentBlobs::get(self, id)
    }
}

#[cfg(feature = "native")]
impl ContentBlobs for ContentStore {
    /// The per-blob statements here are `prepare_cached`: the manifest tree
    /// stores and reads one blob per NODE, so re-parsing the same one-line SQL
    /// per node was a real share of the cost of a cut. The SQL, the rows, and
    /// the error paths are unchanged — only where the compiled statement lives.
    fn put(&self, body: &str) -> StoreResult<String> {
        let id = crate::stable_hash_hex(body);
        let mut insert = self.connection.prepare_cached(
            "INSERT OR IGNORE INTO content_blobs (id, body, byte_len, created_at) \
             VALUES (?1, ?2, ?3, datetime('now'))",
        )?;
        insert.execute(params![id, body, body.len() as i64])?;
        Ok(id)
    }

    /// Reads are transparent over the whole tier: a plain blob row, a
    /// chunk packed into a pack object, or a chunk ROOT (reassembled) all
    /// answer to their id — callers (working sets, bundles, diff) never
    /// see the tiering.
    fn get(&self, id: &str) -> StoreResult<Option<String>> {
        // Each cached statement is scoped so it returns to the cache before the
        // next step — `get` recurses through `reassemble_root`.
        {
            let mut loose = self
                .connection
                .prepare_cached("SELECT body FROM content_blobs WHERE id = ?1")?;
            if let Some(body) = loose
                .query_row(params![id], |row| row.get::<_, String>(0))
                .optional()?
            {
                return Ok(Some(body));
            }
        }
        if let Some(body) = self.read_packed(id)? {
            return Ok(Some(body));
        }
        // Erasure honesty: an id tombstoned in `content_erasures` is gone
        // by decision. `status` short-circuits on this table, so `get`
        // must too — otherwise a (forged) chunk root sharing the id would
        // resurrect erased bytes here while `status` still reports Erased.
        let tombstoned: Option<i64> = {
            let mut erased = self
                .connection
                .prepare_cached("SELECT byte_len FROM content_erasures WHERE id = ?1")?;
            erased.query_row(params![id], |row| row.get(0)).optional()?
        };
        if tombstoned.is_some() {
            return Ok(None);
        }
        // Chunk-root reassembly (each piece resolves through rows or
        // packs; chunks are never themselves roots, so this is depth 1).
        let Some(info) = self.chunk_root_info(id)? else {
            return Ok(None);
        };
        if info.erased {
            return Ok(None);
        }
        self.reassemble_root(id, &info, max_blob_bytes())
    }

    fn status(&self, id: &str) -> StoreResult<BlobStatus> {
        let live: Option<i64> = self
            .connection
            .prepare_cached("SELECT byte_len FROM content_blobs WHERE id = ?1")?
            .query_row(params![id], |row| row.get(0))
            .optional()?;
        if let Some(byte_len) = live {
            return Ok(BlobStatus::Live {
                byte_len: byte_len as u64,
            });
        }
        let packed: Option<i64> = self
            .connection
            .prepare_cached("SELECT len FROM content_pack_entries WHERE chunk_id = ?1")?
            .query_row(params![id], |row| row.get(0))
            .optional()?;
        if let Some(byte_len) = packed {
            return Ok(BlobStatus::Live {
                byte_len: byte_len as u64,
            });
        }
        let erased: Option<i64> = self
            .connection
            .prepare_cached("SELECT byte_len FROM content_erasures WHERE id = ?1")?
            .query_row(params![id], |row| row.get(0))
            .optional()?;
        if let Some(byte_len) = erased {
            return Ok(BlobStatus::Erased {
                byte_len: byte_len as u64,
            });
        }
        if let Some(info) = self.chunk_root_info(id)? {
            return Ok(if info.erased {
                BlobStatus::Erased {
                    byte_len: info.byte_len,
                }
            } else {
                BlobStatus::Live {
                    byte_len: info.byte_len,
                }
            });
        }
        Ok(BlobStatus::Unknown)
    }

    /// Per-blob erasure over the substrate itself (un-tie's content-
    /// erasure invariants become dischargeable here): the payload row is
    /// dropped, a tombstone retains hash + size, and every manifest/cut
    /// that references the hash stays coherent — reads degrade to an
    /// honest absence (`HISTORY_PRESERVED`). Chunk roots delegate to the
    /// chunk tier's fail-closed shared-chunk erasure. Content-level:
    /// dedup means one erasure drops the payload for EVERY referencing
    /// manifest — that is what content erasure means.
    fn erase(&self, id: &str, at: &str) -> StoreResult<EraseOutcome> {
        if let Some(info) = self.chunk_root_info(id)? {
            if info.erased {
                return Ok(EraseOutcome::AlreadyErased);
            }
            self.erase_chunks(id, at)?;
            return Ok(EraseOutcome::Erased {
                byte_len: info.byte_len,
            });
        }
        // A packed id has no `content_blobs` row, so without this the lookup
        // below finds nothing and erasure reports `Unknown` — while `status`
        // still answers `Live` from the pack and the bytes stay put. Erasure
        // must remove the BYTES, and a pack is one blob, so the pack is
        // dissolved first and its survivors return to loose rows.
        //
        // Reachable today only by erasing a packed chunk id directly (erasing a
        // chunk ROOT goes through `unpack_for_erasure`). It becomes the ordinary
        // path the moment DR-0070 §5's co-access packing packs plain blobs.
        self.dissolve_pack_containing(id)?;
        let live: Option<i64> = self
            .connection
            .query_row(
                "SELECT byte_len FROM content_blobs WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(byte_len) = live else {
            let tombstoned: Option<i64> = self
                .connection
                .query_row(
                    "SELECT byte_len FROM content_erasures WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            return Ok(match tombstoned {
                Some(_) => EraseOutcome::AlreadyErased,
                None => EraseOutcome::Unknown,
            });
        };
        self.connection.execute(
            "INSERT OR IGNORE INTO content_erasures (id, byte_len, erased_at) \
             VALUES (?1, ?2, ?3)",
            params![id, byte_len, at],
        )?;
        self.connection
            .execute("DELETE FROM content_blobs WHERE id = ?1", params![id])?;
        Ok(EraseOutcome::Erased {
            byte_len: byte_len as u64,
        })
    }

    fn chunk_ids(&self, id: &str) -> StoreResult<Option<Vec<String>>> {
        Ok(self.chunk_root_info(id)?.map(|info| info.chunk_ids))
    }

    fn put_chunk_root(
        &self,
        root_id: &str,
        chunk_ids: &[String],
        byte_len: u64,
    ) -> StoreResult<()> {
        self.connection.execute(
            "INSERT OR IGNORE INTO content_chunk_roots (root_id, byte_len) VALUES (?1, ?2)",
            params![root_id, byte_len as i64],
        )?;
        for (seq, chunk_id) in chunk_ids.iter().enumerate() {
            self.connection.execute(
                "INSERT OR IGNORE INTO content_chunk_refs (root_id, seq, chunk_id) \
                 VALUES (?1, ?2, ?3)",
                params![root_id, seq as i64, chunk_id],
            )?;
        }
        Ok(())
    }
}

#[cfg(feature = "native")]
fn ensure_content_schema(connection: &Connection) -> StoreResult<()> {
    connection.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS content_blobs (
            id         TEXT PRIMARY KEY,
            body       TEXT NOT NULL,
            byte_len   INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS content_erasures (
            id        TEXT PRIMARY KEY,
            byte_len  INTEGER NOT NULL,
            erased_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS content_chunk_roots (
            root_id    TEXT PRIMARY KEY,
            byte_len   INTEGER NOT NULL,
            erased_at  TEXT
        );
        CREATE TABLE IF NOT EXISTS content_chunk_refs (
            root_id  TEXT NOT NULL,
            seq      INTEGER NOT NULL,
            chunk_id TEXT NOT NULL,
            PRIMARY KEY (root_id, seq)
        );
        CREATE INDEX IF NOT EXISTS content_chunk_refs_chunk_idx
            ON content_chunk_refs(chunk_id);
        CREATE TABLE IF NOT EXISTS content_pack_entries (
            chunk_id TEXT PRIMARY KEY,
            pack_id  TEXT NOT NULL,
            offset   INTEGER NOT NULL,
            len      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS content_pack_entries_pack_idx
            ON content_pack_entries(pack_id);
        "#,
    )?;
    Ok(())
}

/// A chunked root's surviving identity after erasure: the retained
/// hashes and size — the honesty-downgrade handle (identity and pooling
/// verdicts survive; payload and replay do not).
#[cfg(feature = "native")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChunkRootInfo {
    pub root_id: String,
    pub byte_len: u64,
    pub chunk_ids: Vec<String>,
    pub erased: bool,
}

#[cfg(feature = "native")]
impl ContentStore {
    /// Store a body through the chunk tier (vw note §10.1): below the
    /// config threshold this IS `put` (plain content hash, nothing
    /// upstream re-keys); above it, UTF-8-snapped FastCDC chunks land as
    /// ordinary blobs deduped across roots, and the returned root id is
    /// the file's stable identity.
    pub fn put_chunked(
        &self,
        body: &str,
        config: &crate::chunking::ChunkingConfig,
    ) -> StoreResult<String> {
        let tree = crate::chunking::chunk_str(body, config);
        if tree.is_whole_blob() {
            return self.put(body);
        }
        for chunk in &tree.chunks {
            let piece = &body[chunk.offset..chunk.offset + chunk.len];
            let stored = self.put(piece)?;
            debug_assert_eq!(stored, chunk.hash);
        }
        self.connection.execute(
            "INSERT OR IGNORE INTO content_chunk_roots (root_id, byte_len) VALUES (?1, ?2)",
            params![tree.root_hash, body.len() as i64],
        )?;
        for (seq, chunk) in tree.chunks.iter().enumerate() {
            self.connection.execute(
                "INSERT OR IGNORE INTO content_chunk_refs (root_id, seq, chunk_id)                  VALUES (?1, ?2, ?3)",
                params![tree.root_hash, seq as i64, chunk.hash],
            )?;
        }
        Ok(tree.root_hash)
    }

    /// Read through the chunk tier. `Ok(None)` = unknown id OR an erased
    /// root (consult `chunk_root_info` for the retained identity).
    /// Kept as the tier's named entry point; `get` itself is transparent
    /// over roots and packs, so this simply delegates.
    pub fn get_chunked(&self, id: &str) -> StoreResult<Option<String>> {
        self.get(id)
    }

    /// Reassemble a chunk root's bytes, refusing at `cap` bytes. `chunk_ids`
    /// may repeat a shared chunk, so the reassembled size is bounded only by
    /// the ref count, not the distinct stored bytes — a chunk-amplification
    /// bomb. Growth is checked after every piece so a hostile root is refused
    /// having buffered at most one chunk past the ceiling, never gigabytes.
    fn reassemble_root(
        &self,
        id: &str,
        info: &ChunkRootInfo,
        cap: u64,
    ) -> StoreResult<Option<String>> {
        // Never pre-allocate the claimed `byte_len` (attacker-controlled and
        // uncommitted by the verified root id); reserve a small window and let
        // the string grow to the real size under the running cap.
        let mut body = String::with_capacity((info.byte_len as usize).min(MAX_REASSEMBLE_PREALLOC));
        for chunk_id in &info.chunk_ids {
            let Some(piece) = self.get(chunk_id)? else {
                return Ok(None);
            };
            body.push_str(&piece);
            if body.len() as u64 > cap {
                return Err(crate::StoreError::Conflict(format!(
                    "content `{id}` reassembles beyond the {cap}-byte blob ceiling \
                     (raise WHIPPLESCRIPT_MAX_BLOB_BYTES if this is a genuine large file); \
                     refusing (possible chunk amplification)"
                )));
            }
        }
        Ok(Some(body))
    }

    /// The retained identity of a chunk root, before or after erasure.
    pub fn chunk_root_info(&self, root_id: &str) -> StoreResult<Option<ChunkRootInfo>> {
        let root: Option<(i64, Option<String>)> = self
            .connection
            .prepare_cached(
                "SELECT byte_len, erased_at FROM content_chunk_roots WHERE root_id = ?1",
            )?
            .query_row(params![root_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        let Some((byte_len, erased_at)) = root else {
            return Ok(None);
        };
        let mut stmt = self.connection.prepare_cached(
            "SELECT chunk_id FROM content_chunk_refs WHERE root_id = ?1 ORDER BY seq",
        )?;
        let mapped = stmt.query_map(params![root_id], |row| row.get::<_, String>(0))?;
        let mut chunk_ids = Vec::new();
        for row in mapped {
            chunk_ids.push(row?);
        }
        Ok(Some(ChunkRootInfo {
            root_id: root_id.to_owned(),
            byte_len: byte_len as u64,
            chunk_ids,
            erased: erased_at.is_some(),
        }))
    }

    /// Dissolve the pack holding `id`, returning its members to loose rows.
    ///
    /// A no-op when `id` is not packed. Idempotent, and safe to call before any
    /// operation that needs `id` to have a `content_blobs` row of its own — the
    /// pack is an internal storage optimization (DR-0070 §5) and must never
    /// change what an operation on a content id means.
    fn dissolve_pack_containing(&self, id: &str) -> StoreResult<bool> {
        let pack_id: Option<String> = self
            .connection
            .query_row(
                "SELECT pack_id FROM content_pack_entries WHERE chunk_id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(pack_id) = pack_id else {
            return Ok(false);
        };
        let mut statement = self
            .connection
            .prepare("SELECT chunk_id FROM content_pack_entries WHERE pack_id = ?1")?;
        let members = statement
            .query_map(params![pack_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        // Read every member THROUGH the pack before dismantling it; afterwards
        // the bytes are only in the loose rows this writes.
        let mut bodies = Vec::with_capacity(members.len());
        for member in &members {
            if let Some(body) = self.read_packed(member)? {
                bodies.push((member.clone(), body));
            }
        }
        for (member, body) in &bodies {
            self.connection.execute(
                // `created_at` is NOT NULL, and `INSERT OR IGNORE` swallows a
                // constraint violation — omitting it silently re-inlined
                // nothing while reporting success. Every column the schema
                // requires is named here for that reason.
                "INSERT OR IGNORE INTO content_blobs (id, body, byte_len, created_at) \
                 VALUES (?1, ?2, ?3, datetime('now'))",
                params![member, body, body.len() as i64],
            )?;
        }
        self.connection.execute(
            "DELETE FROM content_pack_entries WHERE pack_id = ?1",
            params![pack_id],
        )?;
        self.connection
            .execute("DELETE FROM content_blobs WHERE id = ?1", params![pack_id])?;
        Ok(true)
    }

    /// Read a chunk that lives inside a pack object. Offsets are byte
    /// positions at chunk boundaries (UTF-8-snapped by construction).
    fn read_packed(&self, chunk_id: &str) -> StoreResult<Option<String>> {
        let entry: Option<(String, i64, i64)> = self
            .connection
            .prepare_cached(
                "SELECT pack_id, offset, len FROM content_pack_entries WHERE chunk_id = ?1",
            )?
            .query_row(params![chunk_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .optional()?;
        let Some((pack_id, offset, len)) = entry else {
            return Ok(None);
        };
        let pack: Option<String> = self
            .connection
            .prepare_cached("SELECT body FROM content_blobs WHERE id = ?1")?
            .query_row(params![pack_id], |row| row.get(0))
            .optional()?;
        let Some(pack) = pack else {
            return Ok(None);
        };
        let (start, end) = (offset as usize, (offset + len) as usize);
        if end > pack.len() || !pack.is_char_boundary(start) || !pack.is_char_boundary(end) {
            return Err(crate::StoreError::Conflict(format!(
                "pack {pack_id} entry for {chunk_id} is out of bounds"
            )));
        }
        Ok(Some(pack[start..end].to_owned()))
    }

    /// Object-tier chunk packing (vw note §10.1; internal optimization,
    /// never user-visible): move a root's loose chunk bodies into ONE
    /// pack blob with an offset index. Reads stay transparent
    /// (`get` falls through to the pack); identity is untouched. Returns
    /// how many chunks were packed (0 = nothing loose to pack).
    pub fn pack_root(&self, root_id: &str) -> StoreResult<usize> {
        let Some(info) = self.chunk_root_info(root_id)? else {
            return Ok(0);
        };
        if info.erased {
            return Ok(0);
        }
        // Only chunks that still live as loose rows move; chunks already
        // packed (or shared and packed by a sibling) are left where they
        // are — reads resolve either way.
        let mut loose: Vec<(String, String)> = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for chunk_id in &info.chunk_ids {
            if !seen.insert(chunk_id.clone()) {
                continue;
            }
            let body: Option<String> = self
                .connection
                .query_row(
                    "SELECT body FROM content_blobs WHERE id = ?1",
                    params![chunk_id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(body) = body {
                loose.push((chunk_id.clone(), body));
            }
        }
        if loose.is_empty() {
            return Ok(0);
        }
        let mut pack_body = String::new();
        let mut entries = Vec::new();
        for (chunk_id, body) in &loose {
            entries.push((chunk_id.clone(), pack_body.len() as i64, body.len() as i64));
            pack_body.push_str(body);
        }
        let pack_id = self.put(&pack_body)?;
        for (chunk_id, offset, len) in &entries {
            self.connection.execute(
                "INSERT OR IGNORE INTO content_pack_entries (chunk_id, pack_id, offset, len) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![chunk_id, pack_id, offset, len],
            )?;
        }
        for (chunk_id, _, _) in &entries {
            self.connection.execute(
                "DELETE FROM content_blobs WHERE id = ?1 AND id != ?2",
                params![chunk_id, pack_id],
            )?;
        }
        Ok(entries.len())
    }

    /// Re-inline every surviving chunk of the packs that hold this
    /// root's chunks, then drop the pack blobs — erasure of packed
    /// content must remove the BYTES, and a pack is one blob, so the
    /// pack dissolves and survivors return to loose rows.
    fn unpack_for_erasure(&self, root_id: &str) -> StoreResult<()> {
        let mut stmt = self.connection.prepare(
            "SELECT DISTINCT entries.pack_id FROM content_pack_entries AS entries \
             JOIN content_chunk_refs AS refs ON refs.chunk_id = entries.chunk_id \
             WHERE refs.root_id = ?1",
        )?;
        let packs: Vec<String> = stmt
            .query_map(params![root_id], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        for pack_id in packs {
            let mut stmt = self.connection.prepare(
                "SELECT chunk_id, offset, len FROM content_pack_entries WHERE pack_id = ?1",
            )?;
            let entries: Vec<(String, i64, i64)> = stmt
                .query_map(params![pack_id], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .collect::<Result<_, _>>()?;
            for (chunk_id, _, _) in &entries {
                if let Some(body) = self.read_packed(chunk_id)? {
                    self.connection.execute(
                        "INSERT OR IGNORE INTO content_blobs (id, body, byte_len, created_at) \
                         VALUES (?1, ?2, ?3, datetime('now'))",
                        params![chunk_id, body, body.len() as i64],
                    )?;
                }
            }
            self.connection.execute(
                "DELETE FROM content_pack_entries WHERE pack_id = ?1",
                params![pack_id],
            )?;
            self.connection
                .execute("DELETE FROM content_blobs WHERE id = ?1", params![pack_id])?;
        }
        Ok(())
    }

    /// Chunk-level erasure with the retained root (vw note §10.1 item 1):
    /// drop this root's chunk BODIES — except chunks still referenced by
    /// another live root (dedup sharing survives, fail-closed) — and mark
    /// the root erased. Identity (root + chunk hashes + size) is kept;
    /// payload and replay are honestly gone. Returns how many chunk
    /// bodies were erased.
    pub fn erase_chunks(&self, root_id: &str, at: &str) -> StoreResult<usize> {
        // Packed chunks first: dissolve their packs back to loose rows so
        // the erasure below actually removes bytes (a pack is one blob —
        // deleting an index entry alone would leave the payload inside).
        self.unpack_for_erasure(root_id)?;
        let erased = self.connection.execute(
            "DELETE FROM content_blobs WHERE id IN (
                 SELECT refs.chunk_id FROM content_chunk_refs AS refs
                 WHERE refs.root_id = ?1
                   AND NOT EXISTS (
                     SELECT 1 FROM content_chunk_refs AS other
                     JOIN content_chunk_roots AS other_root
                       ON other_root.root_id = other.root_id
                     WHERE other.chunk_id = refs.chunk_id
                       AND other.root_id != ?1
                       AND other_root.erased_at IS NULL
                   )
             )",
            params![root_id],
        )?;
        self.connection.execute(
            "UPDATE content_chunk_roots SET erased_at = ?2              WHERE root_id = ?1 AND erased_at IS NULL",
            params![root_id, at],
        )?;
        Ok(erased)
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    #[test]
    fn chunk_root_reassembly_refuses_beyond_cap() {
        use crate::chunking::ChunkingConfig;
        let dir = std::env::temp_dir().join(format!("whip-content-cap-{}", std::process::id()));
        let path = dir.join("content.db");
        let _ = std::fs::remove_file(&path);
        let store = ContentStore::open(&path).expect("open");

        // A small-threshold config forces a multi-chunk root.
        let config = ChunkingConfig {
            whole_blob_threshold: 8,
            min_size: 4,
            avg_size: 8,
            max_size: 32,
        };
        let body = "the-quick-brown-fox-".repeat(16);
        let root = store.put_chunked(&body, &config).expect("put chunked");
        let info = store
            .chunk_root_info(&root)
            .expect("info")
            .expect("root exists");

        // A ceiling below the true size refuses reassembly (chunk-amplification
        // guard) rather than building the whole blob.
        assert!(
            store.reassemble_root(&root, &info, 16).is_err(),
            "reassembly past the cap must be refused"
        );
        // A generous ceiling reassembles the original bytes exactly.
        assert_eq!(
            store
                .reassemble_root(&root, &info, 1_000_000)
                .expect("ok")
                .as_deref(),
            Some(body.as_str())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_is_content_addressed_and_get_round_trips() {
        let dir = std::env::temp_dir().join(format!("whip-content-{}", std::process::id()));
        let path = dir.join("content.db");
        let _ = std::fs::remove_file(&path);
        let store = ContentStore::open(&path).expect("open");

        let id1 = store.put("hello world").expect("put");
        let id2 = store.put("hello world").expect("put again");
        assert_eq!(id1, id2, "identical bytes dedupe to one id");
        assert_eq!(
            store.get(&id1).expect("get").as_deref(),
            Some("hello world")
        );

        let other = store.put("different").expect("put other");
        assert_ne!(id1, other);
        assert_eq!(store.get("nonexistent").expect("get missing"), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The native content store runs the trait's own conformance suite.
    #[test]
    fn the_native_content_store_passes_the_conformance_suite() {
        let root = std::env::temp_dir().join(format!(
            "whip-content-conf-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let counter = std::cell::Cell::new(0usize);
        conformance::run_suite(|| {
            counter.set(counter.get() + 1);
            ContentStore::open(root.join(format!("{}.db", counter.get()))).expect("open")
        })
        .expect("suite runs");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Erasing a **packed** blob must remove the bytes, not silently no-op.
    ///
    /// A packed id has no `content_blobs` row, and `erase` looked only there —
    /// so it reported `Unknown` while `status` kept answering `Live` from the
    /// pack and the bytes stayed put. `status` and `erase` disagreeing about
    /// whether a blob exists is the kind of divergence that reads as a
    /// successful erasure to everything downstream.
    ///
    /// Reachable today only by erasing a packed chunk id directly (erasing a
    /// chunk ROOT goes through `unpack_for_erasure`), so nothing was relying on
    /// it. It becomes the ordinary path the moment DR-0070 §5's co-access
    /// packing packs plain blobs — which is why it is fixed before that lands
    /// rather than after.
    #[test]
    fn erasing_a_packed_blob_removes_the_bytes() {
        use crate::chunking::ChunkingConfig;
        let dir = std::env::temp_dir().join(format!(
            "whip-pack-erase-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        let store = ContentStore::open(dir.join("content.db")).expect("open");
        let config = ChunkingConfig {
            whole_blob_threshold: 64,
            min_size: 16,
            avg_size: 64,
            max_size: 256,
        };
        let body: String = "packed-body-".repeat(200);
        let root = store.put_chunked(&body, &config).expect("put chunked");
        let packed = store.pack_root(&root).expect("pack");
        assert!(packed > 0, "the fixture must actually pack something");

        let chunk_ids = store
            .chunk_root_info(&root)
            .expect("root info")
            .expect("root exists")
            .chunk_ids;
        let one_chunk = chunk_ids.first().expect("at least one chunk").clone();

        assert!(
            matches!(
                store.status(&one_chunk).expect("status"),
                BlobStatus::Live { .. }
            ),
            "a packed chunk still reads as Live, because status consults the pack"
        );
        assert!(
            matches!(
                store
                    .erase(&one_chunk, "2026-08-24T00:00:00Z")
                    .expect("erase"),
                EraseOutcome::Erased { .. }
            ),
            "a packed blob must actually erase, not report Unknown"
        );
        assert!(
            matches!(
                store.status(&one_chunk).expect("status"),
                BlobStatus::Erased { .. }
            ),
            "and status must agree with erase afterwards"
        );

        // The pack dissolved rather than being left holding erased bytes: its
        // surviving members are still readable, through loose rows now.
        let survivors: Vec<&String> = chunk_ids.iter().filter(|id| **id != one_chunk).collect();
        for survivor in survivors {
            assert!(
                store.get(survivor).expect("get").is_some(),
                "dissolving the pack must not lose the chunks that were not erased"
            );
        }
        assert_eq!(
            store.get_chunked(&root).expect("reassemble"),
            None,
            "the root reads as erased once one of its chunks is gone"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The chunk tier: large bodies round-trip through UTF-8-snapped
    /// chunks deduped across roots; small bodies keep plain identity;
    /// erasure drops payload but keeps the root's identity, and a chunk
    /// shared with a live sibling root survives (fail-closed sharing).
    #[test]
    fn chunk_tier_roundtrip_dedup_and_erasure_with_retained_root() {
        use crate::chunking::ChunkingConfig;
        let dir = std::env::temp_dir().join(format!(
            "whip-chunk-tier-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        let store = ContentStore::open(dir.join("content.db")).expect("open");
        let config = ChunkingConfig {
            whole_blob_threshold: 256,
            min_size: 64,
            avg_size: 256,
            max_size: 1024,
        };

        // Small bodies keep their plain content identity: put_chunked IS put.
        let small = store.put_chunked("tiny", &config).expect("put small");
        assert_eq!(small, store.put("tiny").expect("put"));
        assert_eq!(
            store.get_chunked(&small).expect("get").as_deref(),
            Some("tiny")
        );

        // A large body (with multi-byte chars to exercise the UTF-8
        // snap) round-trips through the chunk tier.
        let unit = "0123456789abcdefé漢字🚀-";
        let big: String = unit.repeat(600);
        let root = store.put_chunked(&big, &config).expect("put big");
        assert_ne!(
            root,
            store.put(&big).expect("plain put"),
            "chunked identity"
        );
        assert_eq!(
            store.get_chunked(&root).expect("get").as_deref(),
            Some(big.as_str())
        );
        let info = store.chunk_root_info(&root).expect("info").expect("root");
        assert!(info.chunk_ids.len() > 1);
        assert!(!info.erased);

        // A sibling body sharing a long prefix dedupes chunks.
        let sibling = format!("{big}TAIL");
        let sibling_root = store.put_chunked(&sibling, &config).expect("put sibling");
        let sibling_info = store
            .chunk_root_info(&sibling_root)
            .expect("info")
            .expect("root");
        let shared: std::collections::BTreeSet<_> = info
            .chunk_ids
            .iter()
            .filter(|id| sibling_info.chunk_ids.contains(id))
            .collect();
        assert!(!shared.is_empty(), "prefix chunks dedupe across roots");

        // Erase the first root: payload gone, identity retained, shared
        // chunks survive for the live sibling.
        let erased = store.erase_chunks(&root, "t1").expect("erase");
        assert!(erased >= 1, "unshared chunks were dropped");
        assert_eq!(store.get_chunked(&root).expect("get"), None);
        let info_after = store.chunk_root_info(&root).expect("info").expect("root");
        assert!(info_after.erased);
        assert_eq!(info_after.chunk_ids, info.chunk_ids, "hashes retained");
        assert_eq!(info_after.byte_len, big.len() as u64);
        assert_eq!(
            store.get_chunked(&sibling_root).expect("get").as_deref(),
            Some(sibling.as_str()),
            "the sibling sharing chunks still reads whole"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Chunk packing is invisible: after `pack_root` the loose chunk
    /// rows dissolve into one pack blob, every id still reads (chunks
    /// AND the reassembled root), status stays Live — and erasure of a
    /// packed root still removes the bytes (packs dissolve, survivors
    /// return to loose rows, shared chunks live on).
    #[test]
    fn pack_root_is_read_transparent_and_erasure_safe() {
        use crate::chunking::ChunkingConfig;
        let dir = std::env::temp_dir().join(format!(
            "whip-pack-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos(),
        ));
        let store = ContentStore::open(dir.join("content.db")).expect("open");
        let config = ChunkingConfig {
            whole_blob_threshold: 256,
            min_size: 64,
            avg_size: 256,
            max_size: 1024,
        };
        let big = "abcdefghij-0123456789=".repeat(500);
        let root = store.put_chunked(&big, &config).expect("put");
        let sibling = format!("{big}EXTRA");
        let sibling_root = store.put_chunked(&sibling, &config).expect("put sibling");
        let info = store.chunk_root_info(&root).expect("info").expect("root");

        let packed = store.pack_root(&root).expect("pack");
        assert!(packed > 1, "the loose chunks moved into the pack");
        // Reads stay transparent: individual chunks and the whole root.
        for chunk_id in &info.chunk_ids {
            assert!(
                store.get(chunk_id).expect("get").is_some(),
                "packed chunk {chunk_id} still reads"
            );
            assert!(matches!(
                store.status(chunk_id).expect("status"),
                BlobStatus::Live { .. }
            ));
        }
        assert_eq!(
            store.get(&root).expect("get").as_deref(),
            Some(big.as_str())
        );
        assert_eq!(
            store.get(&sibling_root).expect("get").as_deref(),
            Some(sibling.as_str()),
            "the sibling reads through the pack for shared chunks"
        );

        // Erasure of the packed root removes bytes; the sibling's shared
        // chunks survive (fail-closed sharing, now across the pack tier).
        store.erase_chunks(&root, "t1").expect("erase");
        assert_eq!(store.get(&root).expect("get"), None);
        assert_eq!(
            store.get(&sibling_root).expect("get").as_deref(),
            Some(sibling.as_str()),
            "the live sibling still reads whole after the pack dissolved"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
