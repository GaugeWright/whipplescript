PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE workstreams (
            stream_id TEXT PRIMARY KEY,
            name TEXT,
            line_branch_id TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            idempotency_key TEXT
        , staleness_seconds INTEGER, reservation_id TEXT, expected_line_cut TEXT, expected_main_cut TEXT, proposed_main_cut TEXT, ref_position INTEGER, ref_receipt_handle TEXT);
INSERT INTO workstreams VALUES('ws',NULL,'line','active','t4','t4',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL);
CREATE TABLE workstream_members (
            branch_id TEXT PRIMARY KEY,
            stream_id TEXT NOT NULL,
            joined_at TEXT NOT NULL
        );
INSERT INTO workstream_members VALUES('chat','ws','t4');
INSERT INTO workstream_members VALUES('chat-child','ws','t5');
CREATE TABLE workstream_home_positions (
            branch_id TEXT PRIMARY KEY,
            authority_position INTEGER NOT NULL,
            home_stream_id TEXT,
            recorded_at TEXT NOT NULL
        );
INSERT INTO workstream_home_positions VALUES('chat',1,'ws','t4');
INSERT INTO workstream_home_positions VALUES('chat-child',1,'ws','t5');
CREATE UNIQUE INDEX workstreams_idempotency_idx
            ON workstreams(idempotency_key)
            WHERE idempotency_key IS NOT NULL;
CREATE INDEX workstream_members_stream_idx
            ON workstream_members(stream_id);
CREATE UNIQUE INDEX workstreams_live_name_idx
           ON workstreams(name)
           WHERE name IS NOT NULL AND status != 'archived';
COMMIT;
