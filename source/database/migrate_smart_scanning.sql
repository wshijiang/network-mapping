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

-- Same set semantics as routing::target_key: order, duplicates, overlapping and
-- adjacent ranges do not change a plan. Skip invalid legacy port tokens safely.
CREATE OR REPLACE FUNCTION scan_port_set(ports TEXT) RETURNS INT4MULTIRANGE
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    token TEXT;
    parts TEXT[];
    low_port INT;
    high_port INT;
    result INT4MULTIRANGE := '{}';
BEGIN
    FOREACH token IN ARRAY string_to_array(ports, ',') LOOP
        parts := regexp_match(btrim(token), '^([0-9]+)(-([0-9]+))?$');
        IF parts IS NULL THEN CONTINUE; END IF;
        parts[1] := COALESCE(NULLIF(ltrim(parts[1], '0'), ''), '0');
        parts[3] := COALESCE(NULLIF(ltrim(COALESCE(parts[3], parts[1]), '0'), ''), '0');
        IF length(parts[1]) > 5 OR length(parts[3]) > 5 THEN CONTINUE; END IF;
        low_port := parts[1]::INT;
        high_port := parts[3]::INT;
        IF low_port > high_port OR high_port > 65535 THEN CONTINUE; END IF;
        result := result + int4multirange(int4range(low_port, high_port + 1, '[)'));
    END LOOP;
    RETURN result;
END;
$$;
CREATE INDEX IF NOT EXISTS idx_scan_task_active_plan
    ON scan_task(generation_key, scan_profile, scan_port_set(task_port))
    WHERE generation_key IS NOT NULL AND task_status IN ('pending', 'running');
