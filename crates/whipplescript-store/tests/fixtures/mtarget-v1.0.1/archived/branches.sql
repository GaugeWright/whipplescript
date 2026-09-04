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
INSERT INTO branches VALUES('main','main',NULL,NULL,NULL,'main-2','f069964ec0b6d81287b5edf1523fa914',NULL,'active','t0','t3',NULL);
INSERT INTO branches VALUES('line',NULL,'main','main-1','d79a9287e605f4b4b46fe5d74e380d17','line-1','f069964ec0b6d81287b5edf1523fa914',NULL,'active','t1','t2',NULL);
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
CREATE TABLE cuts (
            cut_id TEXT PRIMARY KEY,
            change_id TEXT NOT NULL,
            branch_id TEXT NOT NULL,
            manifest_hash TEXT NOT NULL,
            recorded_at TEXT NOT NULL
        , parent_cut_id TEXT, origin TEXT, actor TEXT, intent TEXT, log_heads TEXT);
INSERT INTO cuts VALUES('main-1','main-1','main','d79a9287e605f4b4b46fe5d74e380d17','t1',NULL,'write:base',NULL,NULL,NULL);
INSERT INTO cuts VALUES('line-1','line-1','line','f069964ec0b6d81287b5edf1523fa914','t2','main-1','write:work',NULL,NULL,NULL);
INSERT INTO cuts VALUES('main-2','main-2','main','f069964ec0b6d81287b5edf1523fa914','t3','main-1','promote:line',NULL,NULL,NULL);
CREATE TABLE ops (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            op_id TEXT NOT NULL UNIQUE,
            kind TEXT NOT NULL,
            deltas TEXT NOT NULL,
            origin TEXT,
            recorded_at TEXT NOT NULL
        );
INSERT INTO ops VALUES(1,'op-main-1','write','[{"branch_id":"main","before":{"head_cut_id":null,"head_manifest_hash":null,"branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"},"after":{"head_cut_id":"main-1","head_manifest_hash":"d79a9287e605f4b4b46fe5d74e380d17","branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"}}]','write:base','t1');
INSERT INTO ops VALUES(2,'op-create-line','create','[{"branch_id":"line","before":null,"after":{"head_cut_id":"main-1","head_manifest_hash":"d79a9287e605f4b4b46fe5d74e380d17","branch_point_cut_id":"main-1","branch_point_manifest_hash":"d79a9287e605f4b4b46fe5d74e380d17","status":"active"}}]','from:main','t1');
INSERT INTO ops VALUES(3,'op-line-1','write','[{"branch_id":"line","before":{"head_cut_id":"main-1","head_manifest_hash":"d79a9287e605f4b4b46fe5d74e380d17","branch_point_cut_id":"main-1","branch_point_manifest_hash":"d79a9287e605f4b4b46fe5d74e380d17","status":"active"},"after":{"head_cut_id":"line-1","head_manifest_hash":"f069964ec0b6d81287b5edf1523fa914","branch_point_cut_id":"main-1","branch_point_manifest_hash":"d79a9287e605f4b4b46fe5d74e380d17","status":"active"}}]','write:work','t2');
INSERT INTO ops VALUES(4,'op-main-2','promote-boundary','[{"branch_id":"main","before":{"head_cut_id":"main-1","head_manifest_hash":"d79a9287e605f4b4b46fe5d74e380d17","branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"},"after":{"head_cut_id":"main-2","head_manifest_hash":"f069964ec0b6d81287b5edf1523fa914","branch_point_cut_id":null,"branch_point_manifest_hash":null,"status":"active"}}]','promote:line','t3');
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
INSERT INTO change_units VALUES('main',0,'main-1','base',NULL,'cae662172fd450bb0cd710a769079c05',NULL);
INSERT INTO change_units VALUES('line',0,'line-1','work',NULL,'00e13ed7af55b27622f1d6eab5bec014',NULL);
CREATE TABLE change_unit_cursor (
            branch_id TEXT PRIMARY KEY,
            indexed_cuts INTEGER NOT NULL,
            last_indexed_cut_id TEXT
        );
INSERT INTO change_unit_cursor VALUES('main',1,'main-1');
INSERT INTO change_unit_cursor VALUES('line',1,'line-1');
CREATE TABLE closure_pins (
            cut_id     TEXT NOT NULL,
            holder     TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (cut_id, holder)
        );
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('ops',4);
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
