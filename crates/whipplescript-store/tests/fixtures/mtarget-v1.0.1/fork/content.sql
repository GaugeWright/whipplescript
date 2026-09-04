PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE content_blobs (
            id         TEXT PRIMARY KEY,
            body       TEXT NOT NULL,
            byte_len   INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
INSERT INTO content_blobs VALUES('251fecd592e56e6c4a95121752f4a73b','point',5,'2026-09-04 16:57:25');
INSERT INTO content_blobs VALUES('e7e5f9f4929fdd3a9f731d7fe38471af','{"tag":"whipplescript.manifest-tree.v2","level":0,"entries":[["state.txt","251fecd592e56e6c4a95121752f4a73b"]]}',111,'2026-09-04 16:57:25');
INSERT INTO content_blobs VALUES('2284c38a5da6d48d9513ab59d6d3796b','new tip',7,'2026-09-04 16:57:25');
INSERT INTO content_blobs VALUES('fbaec0ac98ad7a3488f2164336fd841a','{"tag":"whipplescript.manifest-tree.v2","level":0,"entries":[["state.txt","2284c38a5da6d48d9513ab59d6d3796b"]]}',111,'2026-09-04 16:57:25');
CREATE TABLE content_erasures (
            id        TEXT PRIMARY KEY,
            byte_len  INTEGER NOT NULL,
            erased_at TEXT NOT NULL
        );
CREATE TABLE content_erasure_ledger (
            sequence     INTEGER PRIMARY KEY,
            id           TEXT NOT NULL,
            kind         TEXT NOT NULL,
            byte_len     INTEGER NOT NULL,
            erased_at    TEXT NOT NULL,
            prev_digest  TEXT NOT NULL,
            entry_digest TEXT NOT NULL
        );
CREATE TABLE content_chunk_roots (
            root_id    TEXT PRIMARY KEY,
            byte_len   INTEGER NOT NULL,
            erased_at  TEXT
        );
CREATE TABLE content_chunk_refs (
            root_id  TEXT NOT NULL,
            seq      INTEGER NOT NULL,
            chunk_id TEXT NOT NULL,
            PRIMARY KEY (root_id, seq)
        );
CREATE TABLE content_pack_entries (
            chunk_id TEXT PRIMARY KEY,
            pack_id  TEXT NOT NULL,
            offset   INTEGER NOT NULL,
            len      INTEGER NOT NULL
        );
CREATE INDEX content_erasure_ledger_id_idx
            ON content_erasure_ledger(id);
CREATE INDEX content_chunk_refs_chunk_idx
            ON content_chunk_refs(chunk_id);
CREATE INDEX content_pack_entries_pack_idx
            ON content_pack_entries(pack_id);
COMMIT;
