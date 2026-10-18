-- Derived work only; raw scan observations and upload receipts are unchanged.
CREATE TABLE IF NOT EXISTS web_detection_outbox (
    execution_id INTEGER NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
    ruleset_revision BIGINT NOT NULL CHECK (ruleset_revision > 0),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    lease_expires_at TIMESTAMPTZ,
    cursor JSONB,
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (execution_id, ruleset_revision)
);
CREATE INDEX IF NOT EXISTS web_detection_outbox_pending_idx
    ON web_detection_outbox (ruleset_revision, available_at, execution_id)
    WHERE processed_at IS NULL;

CREATE TABLE IF NOT EXISTS web_detection_backfill (
    ruleset_revision BIGINT PRIMARY KEY CHECK (ruleset_revision > 0),
    last_execution_id INTEGER NOT NULL DEFAULT 0 CHECK (last_execution_id >= 0)
);
