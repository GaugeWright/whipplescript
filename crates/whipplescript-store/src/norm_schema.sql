-- Owned by whipplescript-store, imported by native and hosted provisioning.
-- This pin is durable local trust state, never a replayable projection.
CREATE TABLE IF NOT EXISTS tracker_norm_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    genesis_id TEXT NOT NULL
);
-- One SQL statement appends a genesis AND pins its identity. In particular, a
-- failed append cannot leave a pin without its genesis on the synchronous DO.
CREATE TRIGGER IF NOT EXISTS tracker_norm_bootstrap_pin
AFTER INSERT ON tracker_events
WHEN NEW.kind = 'norm.governance.bootstrapped'
BEGIN
    INSERT OR IGNORE INTO tracker_norm_identity (singleton, genesis_id)
    VALUES (1, NEW.event_id);
END;
-- Authority event ids commit to the exact frontier closed by each rotation.
-- Keep both coordinates together when a fresh destination pins a checkpoint.
CREATE TABLE IF NOT EXISTS tracker_norm_checkpoint (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    genesis_id TEXT NOT NULL,
    authority_head TEXT NOT NULL
);
INSERT OR IGNORE INTO tracker_norm_checkpoint (singleton, genesis_id, authority_head)
SELECT singleton, genesis_id, genesis_id FROM tracker_norm_identity;
CREATE TRIGGER IF NOT EXISTS tracker_norm_identity_checkpoint
AFTER INSERT ON tracker_norm_identity
BEGIN
    INSERT OR IGNORE INTO tracker_norm_checkpoint (singleton, genesis_id, authority_head)
    VALUES (1, NEW.genesis_id, NEW.genesis_id);
END;
CREATE TRIGGER IF NOT EXISTS tracker_norm_checkpoint_identity
AFTER INSERT ON tracker_norm_checkpoint
BEGIN
    INSERT OR IGNORE INTO tracker_norm_identity (singleton, genesis_id)
    VALUES (1, NEW.genesis_id);
END;
-- Never roll a retained checkpoint back when recovering an older missing edge.
-- Imports insert validated events in causal order, inside one atomic statement.
CREATE TRIGGER IF NOT EXISTS tracker_norm_rotation_checkpoint
AFTER INSERT ON tracker_events
WHEN NEW.kind = 'norm.governance.rotated'
BEGIN
    UPDATE tracker_norm_checkpoint SET authority_head = NEW.event_id
    WHERE singleton = 1
      AND genesis_id = json_extract(NEW.payload_json, '$.statement.action.ledger')
      AND authority_head = json_extract(NEW.payload_json, '$.statement.action.previous');
END;
-- A pre-succession reader must not ignore this retained authority checkpoint
-- when rotation evidence is temporarily missing. Stamp after provisioning.
INSERT OR IGNORE INTO schema_migrations (version, name)
VALUES (3, 'norm-authority-checkpoint');
-- Like tracker_aliases, these are durable clone-local names, not projections.
-- A dedicated ordinal namespace prevents generic records from being mistaken
-- for legacy issue/assertion aliases by their existing command adapters.
CREATE TABLE IF NOT EXISTS tracker_norm_aliases (
    ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
    record_id TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS tracker_norm_creation_alias
AFTER INSERT ON tracker_events
WHEN NEW.kind = 'norm.record.created'
BEGIN
    INSERT INTO tracker_norm_aliases (record_id)
    SELECT NEW.event_id
    WHERE NOT EXISTS (
        SELECT 1 FROM tracker_norm_aliases WHERE record_id = NEW.event_id
    );
END;
-- Upgrade a C0/succession store, preserving names already minted here. Source
-- transport has no authority over this local ordinal allocation.
INSERT INTO tracker_norm_aliases (record_id)
SELECT event_id FROM tracker_events
WHERE kind = 'norm.record.created'
  AND event_id NOT IN (SELECT record_id FROM tracker_norm_aliases)
ORDER BY event_seq;
