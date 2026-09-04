PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE content_blobs (
            id         TEXT PRIMARY KEY,
            body       TEXT NOT NULL,
            byte_len   INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
INSERT INTO content_blobs VALUES('cae662172fd450bb0cd710a769079c05','base',4,'2026-09-04 16:57:26');
INSERT INTO content_blobs VALUES('d79a9287e605f4b4b46fe5d74e380d17','{"tag":"whipplescript.manifest-tree.v2","level":0,"entries":[["base","cae662172fd450bb0cd710a769079c05"]]}',106,'2026-09-04 16:57:26');
INSERT INTO content_blobs VALUES('00e13ed7af55b27622f1d6eab5bec014','work',4,'2026-09-04 16:57:26');
INSERT INTO content_blobs VALUES('f069964ec0b6d81287b5edf1523fa914','{"tag":"whipplescript.manifest-tree.v2","level":0,"entries":[["base","cae662172fd450bb0cd710a769079c05"],["work","00e13ed7af55b27622f1d6eab5bec014"]]}',150,'2026-09-04 16:57:26');
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
