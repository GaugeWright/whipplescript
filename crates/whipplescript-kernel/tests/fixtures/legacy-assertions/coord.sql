PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE leases (
            owner TEXT NOT NULL,
            resource TEXT NOT NULL,
            key TEXT NOT NULL,
            holder TEXT NOT NULL,
            acquired_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (owner, resource, key, holder)
        );
CREATE TABLE ledger_entries (
            owner TEXT NOT NULL,
            ledger TEXT NOT NULL,
            partition TEXT NOT NULL,
            seq INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            appended_by TEXT NOT NULL,
            appended_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (owner, ledger, seq)
        );
CREATE TABLE ledger_seq (
            owner TEXT NOT NULL,
            ledger TEXT NOT NULL,
            next_seq INTEGER NOT NULL,
            PRIMARY KEY (owner, ledger)
        );
CREATE TABLE counters (
            owner TEXT NOT NULL,
            counter TEXT NOT NULL,
            key TEXT NOT NULL,
            consumed INTEGER NOT NULL DEFAULT 0,
            period TEXT NOT NULL,
            PRIMARY KEY (owner, counter, key)
        );
CREATE TABLE coord_applied (
            owner TEXT NOT NULL,
            effect_id TEXT NOT NULL,
            outcome_json TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (owner, effect_id)
        );
CREATE INDEX idx_leases_holder ON leases(holder);
CREATE INDEX idx_ledger_partition ON ledger_entries(owner, ledger, partition, seq);
COMMIT;
