CREATE TABLE runtime_payload_protection (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    domain TEXT
);
INSERT INTO runtime_payload_protection(singleton, domain) VALUES (1, NULL);

-- Plain stores retain their existing key representation. Protected stores use
-- key as a digest index and retain the original natural key in this sealed cell.
ALTER TABLE facts ADD COLUMN key_payload BLOB;
