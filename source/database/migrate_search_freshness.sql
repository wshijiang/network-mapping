-- Search-target freshness is derived work. The expensive freshness UPDATE runs
-- in a background worker instead of the upload confirm transaction, which must
-- release the scan_task_execution row lock quickly so scanner heartbeats can
-- renew task leases within their 1500ms lock_timeout.
CREATE TABLE IF NOT EXISTS search_freshness_outbox (
    task_id INTEGER PRIMARY KEY REFERENCES scan_task(id) ON DELETE CASCADE,
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS search_freshness_outbox_pending_idx
    ON search_freshness_outbox (available_at, task_id)
    WHERE processed_at IS NULL;