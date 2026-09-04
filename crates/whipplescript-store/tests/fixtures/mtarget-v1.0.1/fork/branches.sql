PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE branches (
            branch_id TEXT PRIMARY KEY,
            name TEXT,
            parent_branch_id TEXT,
            branch_point_cut_id TEXT,
            branch_point_manifest_hash TEXT,
            head_cut_id TEXT,
            head_manifest_hash TEXT,
            adopted_merge_cut_id TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            idempotency_key TEXT
        );
INSERT INTO branches VALUES('main','main',NULL,NULL,NULL,NULL,NULL,NULL,'active','t0','t0',NULL);
INSERT INTO branches VALUES('chat',NULL,'main',NULL,NULL,'chat-2','fbaec0ac98ad7a3488f2164336fd841a',NULL,'active','t1','t3',NULL);
INSERT INTO branches VALUES('line',NULL,'main',NULL,NULL,NULL,NULL,NULL,'active','t3','t3',NULL);
INSERT INTO branches VALUES('chat-child',NULL,'chat','chat-1','e7e5f9f4929fdd3a9f731d7fe38471af','chat-1','e7e5f9f4929fdd3a9f731d7fe38471af',NULL,'active','t5','t5',NULL);
CREATE TABLE branch_head_reservations (
            branch_id TEXT PRIMARY KEY,
            reservation_id TEXT NOT NULL,
            reserved_at TEXT NOT NULL
        );
CREATE TABLE branch_instances (
            instance_id TEXT PRIMARY KEY,
            branch_id TEXT NOT NULL,
            bound_at TEXT NOT NULL
        );
INSERT INTO branch_instances VALUES('parent','chat','t1');
INSERT INTO branch_instances VALUES('child','chat-child','t5');
CREATE TABLE cuts (
            cut_id TEXT PRIMARY KEY,
            change_id TEXT NOT NULL,
            branch_id TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        , parent_cut_id TEXT, origin TEXT, actor TEXT, intent TEXT, log_heads TEXT);
INSERT INTO cuts VALUES('chat-1','chat-1','chat','e7e5f9f4929fdd3a9f731d7fe38471af','t2',NULL,'write:state.txt',NULL,NULL,NULL);
INSERT INTO cuts VALUES('chat-2','chat-2','chat','fbaec0ac98ad7a3488f2164336fd841a','t3','chat-1','write:state.txt',NULL,NULL,NULL);
CREATE TABLE ops (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            op_id TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            deltas TEXT NOT NULL,
            origin TEXT,
            recorded_at TEXT NOT NULL
        );
INSERT INTO ops VALUES(1,'op-create-chat','create','[{"branch_id":"chat","before":null,"after":{"head_cut_id":null,"head_manifest_hash":null,"branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"}}]','from:main','t1');
INSERT INTO ops VALUES(2,'op-chat-1','write','[{"branch_id":"chat","before":{"head_cut_id":null,"head_manifest_hash":null,"branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"},"after":{"head_cut_id":"chat-1","head_manifest_hash":"e7e5f9f4929fdd3a9f731d7fe38471af","branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"}}]','write:state.txt','t2');
INSERT INTO ops VALUES(3,'op-chat-2','write','[{"branch_id":"chat","before":{"head_cut_id":"chat-1","head_manifest_hash":"e7e5f9f4929fdd3a9f731d7fe38471af","branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"},"after":{"head_cut_id":"chat-2","head_manifest_hash":"fbaec0ac98ad7a3488f2164336fd841a","branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"}}]','write:state.txt','t3');
INSERT INTO ops VALUES(4,'op-create-line','create','[{"branch_id":"line","before":null,"after":{"head_cut_id":null,"head_manifest_hash":null,"branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"}}]','from:main','t3');
INSERT INTO ops VALUES(5,'op-create-chat-child','create','[{"branch_id":"chat-child","before":null,"after":{"head_cut_id":"chat-1","head_manifest_hash":"e7e5f9f4929fdd3a9f731d7fe38471af","branch_point_cut_id":"chat-1","branch_point_manifest_hash":"e7e5f9f4929fdd3a9f731d7fe38471af","status":"active"}}]','from:chat','t5');
CREATE TABLE conflicts (
            conflict_id TEXT PRIMARY KEY,
            branch_id TEXT NOT NULL,
            path TEXT NOT NULL,
            base TEXT,
            ours TEXT,
            theirs TEXT,
            ours_label TEXT NOT NULL,
            theirs_label TEXT NOT NULL,
            state TEXT NOT NULL,
            resolution TEXT,
            recorded_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
CREATE TABLE resolution_memory (
            triple_key TEXT PRIMARY KEY,
            resolution TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        );
CREATE TABLE change_units (
            branch_id TEXT NOT NULL,
            cut_seq INTEGER NOT NULL,
            cut_id TEXT NOT NULL,
            path TEXT NOT NULL,
            before_hash TEXT,
            after_hash TEXT,
            decl_units TEXT
        );
INSERT INTO change_units VALUES('chat',0,'chat-1','state.txt',NULL,'251fecd592e56e6c4a95121752f4a73b',NULL);
INSERT INTO change_units VALUES('chat',1,'chat-2','state.txt','251fecd592e56e6c4a95121752f4a73b','2284c38a5da6d48d9513ab59d6d3796b',NULL);
CREATE TABLE change_unit_cursor (
            branch_id TEXT PRIMARY KEY,
            indexed_cuts INTEGER NOT NULL,
            last_indexed_cut_id TEXT
        );
INSERT INTO change_unit_cursor VALUES('chat',2,'chat-2');
CREATE TABLE closure_pins (
            cut_id     TEXT NOT NULL,
            holder     TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (cut_id, holder)
        );
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('ops',5);
CREATE UNIQUE INDEX branches_idempotency_idx
            ON branches(idempotency_key)
            WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX branches_active_name_idx
            ON branches(name)
            WHERE name IS NOT NULL AND status = 'active';
CREATE INDEX branches_parent_idx
            ON branches(parent_branch_id);
CREATE INDEX branch_instances_branch_idx
            ON branch_instances(branch_id);
CREATE INDEX cuts_change_idx ON cuts(change_id);
CREATE INDEX cuts_branch_idx ON cuts(branch_id);
CREATE INDEX conflicts_branch_idx
            ON conflicts(branch_id, state);
CREATE INDEX change_units_branch_idx
            ON change_units(branch_id, cut_seq);
CREATE INDEX closure_pins_holder_idx
            ON closure_pins(holder);
COMMIT;
