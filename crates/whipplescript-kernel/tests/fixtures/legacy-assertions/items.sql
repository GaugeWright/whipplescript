PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE tracker_events (
    event_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    parents_json TEXT NOT NULL DEFAULT '[]',
    issue_id TEXT,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    actor TEXT,
    -- G3 of spec/output-attribution-research-note.md: the EFFECT that wrote
    -- this event, when one did. `actor` answers "as whom" and is part of the
    -- event's content id; this answers "by which effect", is deliberately NOT
    -- in the content id (adding it would change every event id and break
    -- import verification), and is deliberately NOT exported (a foreign clone's
    -- effect id names an effect in a store you cannot query).
    effect_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE tracker_issues (
    issue_id TEXT PRIMARY KEY,
    queue TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open',
    labels_json TEXT NOT NULL DEFAULT '[]',
    releases INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    claim_summary TEXT,
    assigned_to TEXT,
    filed_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE tracker_relations (
    from_issue TEXT NOT NULL,
    to_issue TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'blocks',
    dep_kind TEXT,
    PRIMARY KEY (from_issue, to_issue, kind)
);
CREATE TABLE tracker_leases (
    lease_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT,
    released_at TEXT
);
CREATE TABLE tracker_counter (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_id INTEGER NOT NULL
);
INSERT INTO tracker_counter VALUES(1,1);
CREATE TABLE tracker_aliases (
    content_id TEXT PRIMARY KEY,
    alias TEXT NOT NULL UNIQUE
);
CREATE TABLE tracker_comments (
    comment_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    author TEXT,
    body TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE tracker_evidence (
    evidence_id TEXT PRIMARY KEY,
    issue_id TEXT NOT NULL,
    kind TEXT,
    reference TEXT,
    note TEXT,
    added_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
, at_cut TEXT, basis TEXT, basis_fingerprint_json TEXT);
CREATE TABLE tracker_anchors (
    anchor_id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    region TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'subject',
    added_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE tracker_assertions (
    assertion_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active',
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE tracker_assertion_counter (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    next_id INTEGER NOT NULL
);
INSERT INTO tracker_assertion_counter VALUES(1,1);
CREATE TABLE tracker_subscriptions (
    subscriber TEXT NOT NULL,
    queue TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (subscriber, queue)
);
DELETE FROM sqlite_sequence;
CREATE INDEX idx_tracker_issues_queue ON tracker_issues(queue, status);
CREATE INDEX idx_tracker_leases_issue ON tracker_leases(issue_id, released_at);
CREATE INDEX idx_tracker_events_issue ON tracker_events(issue_id, kind);
CREATE UNIQUE INDEX idx_tracker_events_id ON tracker_events(event_id);
COMMIT;
