-- Additive, repeatable migration. Routing preferences never replace execution leases.
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS performance JSONB;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS routing_decision JSONB;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS task_group_id UUID;
CREATE INDEX IF NOT EXISTS idx_scan_task_group ON scan_task(task_group_id) WHERE task_group_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS scan_task_routing (
    task_id INT PRIMARY KEY REFERENCES scan_task(id) ON DELETE CASCADE,
    preferred_scanner_id TEXT,
    prefer_until BIGINT NOT NULL DEFAULT 0,
    decision JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_task_routing_preference ON scan_task_routing(preferred_scanner_id, prefer_until);

CREATE TABLE IF NOT EXISTS scanner_target_feedback (
    scanner_id TEXT NOT NULL,
    owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_key TEXT NOT NULL,
    successes INT NOT NULL DEFAULT 0,
    route_failures INT NOT NULL DEFAULT 0,
    elapsed_ms DOUBLE PRECISION,
    connect_ms DOUBLE PRECISION,
    connect_samples INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(scanner_id, owner_id, target_key)
);
CREATE INDEX IF NOT EXISTS idx_scanner_feedback_target ON scanner_target_feedback(owner_id, target_key, updated_at);
CREATE TABLE IF NOT EXISTS scan_routing_outcome (
    execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
    attempt_no INT NOT NULL,
    PRIMARY KEY(execution_id, attempt_no)
);

CREATE TABLE IF NOT EXISTS automatic_target_history (
    generation_key TEXT NOT NULL,
    plan_key TEXT NOT NULL,
    address_family TEXT NOT NULL,
    target TEXT NOT NULL,
    last_success_at BIGINT,
    last_attempt_at BIGINT,
    failure_count INT NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY(generation_key, plan_key)
);
CREATE INDEX IF NOT EXISTS idx_automatic_history_due ON automatic_target_history(address_family, next_attempt_at, last_success_at);

CREATE TABLE IF NOT EXISTS automatic_target_outcome (task_id INT PRIMARY KEY REFERENCES scan_task(id) ON DELETE CASCADE);

ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS asset_signature BIT(256);
ALTER TABLE automatic_target_history ADD COLUMN IF NOT EXISTS last_asset_signature TEXT;
ALTER TABLE automatic_target_history ADD COLUMN IF NOT EXISTS next_refresh_at BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_scanner_feedback_expiry ON scanner_target_feedback(updated_at);

ALTER TABLE automatic_target_history ADD COLUMN IF NOT EXISTS change_detected BOOLEAN NOT NULL DEFAULT FALSE;
