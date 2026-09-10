CREATE TABLE IF NOT EXISTS tracker_filing_receipts (
    operation_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL,
    item_id TEXT NOT NULL, event_id TEXT NOT NULL
);
