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
-- Freshness/admission aggregate child completion by parent_execution_id. The
-- composite (parent_task_id, parent_execution_id) index cannot serve that
-- filter, so deployments using a custom init_database_file (which skips the
-- index in init.sql) still need it created here.
CREATE INDEX IF NOT EXISTS idx_scan_task_lineage_parent_execution
    ON scan_task_lineage (parent_execution_id, child_task_id);