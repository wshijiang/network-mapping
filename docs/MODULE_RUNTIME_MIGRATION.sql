-- Review draft only: not included in application startup, not applied by this change.
-- Run via a versioned migration runner after reviewing permissions and schema ownership.
-- Existing report rows remain compatible; no renderer is activated by this script.
BEGIN;

CREATE TABLE IF NOT EXISTS module_release (
    release_id TEXT PRIMARY KEY,
    module_id TEXT NOT NULL,
    version TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    manifest JSONB NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (module_id, version),
    UNIQUE (module_id, release_id)
);

CREATE TABLE IF NOT EXISTS module_route_clock (
    singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
    revision BIGINT NOT NULL DEFAULT 0 CHECK (revision >= 0)
);
INSERT INTO module_route_clock(singleton, revision) VALUES (1, 0)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS module_route (
    module_id TEXT PRIMARY KEY,
    release_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    revision BIGINT NOT NULL CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (module_id, release_id) REFERENCES module_release(module_id, release_id)
);

CREATE TABLE IF NOT EXISTS module_deployment (
    id UUID PRIMARY KEY,
    module_id TEXT NOT NULL,
    target_release_id TEXT NOT NULL,
    expected_revision BIGINT NOT NULL CHECK (expected_revision >= 0),
    activated_revision BIGINT,
    state TEXT NOT NULL CHECK (state IN
        ('preparing', 'prepared', 'activating', 'draining', 'completed', 'failed', 'degraded')),
    requested_by INTEGER REFERENCES users(id),
    change_reason TEXT NOT NULL,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (module_id, target_release_id) REFERENCES module_release(module_id, release_id)
);
CREATE INDEX IF NOT EXISTS idx_module_deployment_active
ON module_deployment(module_id, created_at)
WHERE state IN ('preparing', 'prepared', 'activating', 'draining', 'degraded');

CREATE TABLE IF NOT EXISTS module_instance (
    instance_id UUID PRIMARY KEY,
    module_id TEXT NOT NULL,
    release_id TEXT NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL CHECK (state IN ('starting', 'ready', 'active', 'draining', 'stopped', 'failed')),
    inflight_count INTEGER NOT NULL DEFAULT 0 CHECK (inflight_count >= 0),
    last_heartbeat_at TIMESTAMPTZ NOT NULL,
    last_error TEXT,
    FOREIGN KEY (module_id, release_id) REFERENCES module_release(module_id, release_id)
);

CREATE TABLE IF NOT EXISTS module_host_state (
    host_instance_id UUID PRIMARY KEY,
    role TEXT NOT NULL,
    applied_route_revision BIGINT NOT NULL DEFAULT 0 CHECK (applied_route_revision >= 0),
    last_heartbeat_at TIMESTAMPTZ NOT NULL,
    last_error TEXT
);

-- Each host polls revisions after reconnecting and reports its applied revision.
-- Retain publication events; notification alone is not a durable publication record.
CREATE TABLE IF NOT EXISTS module_publication_event (
    revision BIGINT PRIMARY KEY CHECK (revision > 0),
    deployment_id UUID NOT NULL REFERENCES module_deployment(id),
    event_document JSONB NOT NULL CHECK (jsonb_typeof(event_document) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS report_render_input (
    report_id UUID PRIMARY KEY REFERENCES report_run(id) ON DELETE CASCADE,
    report_revision INTEGER NOT NULL CHECK (report_revision > 0),
    input_schema TEXT NOT NULL,
    input_bytes BYTEA NOT NULL CHECK (octet_length(input_bytes) BETWEEN 1 AND 1048576),
    input_checksum TEXT NOT NULL CHECK (input_checksum ~ '^[0-9a-f]{64}$'),
    statistics_payload JSONB NOT NULL,
    quality JSONB NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL,
    chart_png BYTEA CHECK (chart_png IS NULL OR octet_length(chart_png) <= 1048576),
    asset_descriptor JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE report_run ADD COLUMN IF NOT EXISTS renderer_release_id TEXT;
ALTER TABLE report_run ADD COLUMN IF NOT EXISTS renderer_generation BIGINT;
ALTER TABLE report_run ADD COLUMN IF NOT EXISTS render_input_checksum TEXT;
ALTER TABLE report_job ADD COLUMN IF NOT EXISTS assigned_generation BIGINT;
ALTER TABLE report_job ADD COLUMN IF NOT EXISTS claim_owner_instance UUID;

COMMIT;
