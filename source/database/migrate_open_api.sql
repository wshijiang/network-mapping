-- Open platform: identities are applications, never synthetic administrator users.
CREATE TABLE IF NOT EXISTS api_platform_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    revision BIGINT NOT NULL DEFAULT 1,
    document JSONB NOT NULL DEFAULT '{"enabled":false,"retention_days":30,"audit_retention_days":180}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO api_platform_settings(singleton) VALUES(TRUE) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS api_client (
    id SERIAL PRIMARY KEY,
    client_id UUID NOT NULL UNIQUE,
    owner_user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    kind TEXT NOT NULL CHECK (kind IN ('personal','partner')),
    environment TEXT NOT NULL DEFAULT 'production' CHECK (environment IN ('production','sandbox')),
    purpose TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','paused','archived')),
    policy JSONB NOT NULL,
    requested_policy JSONB NOT NULL,
    version BIGINT NOT NULL DEFAULT 1,
    revision BIGINT NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_client_owner ON api_client(owner_user_id,created_at DESC);
CREATE TABLE IF NOT EXISTS api_policy_revision (
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    revision BIGINT NOT NULL,
    policy JSONB NOT NULL,
    changed_by INTEGER REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(client_id,revision)
);
CREATE TABLE IF NOT EXISTS api_credential (
    id UUID PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    name TEXT NOT NULL,
    secret_hash TEXT NOT NULL UNIQUE,
    scopes TEXT[] NOT NULL,
    ip_allowlist TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_credential_client ON api_credential(client_id,created_at DESC);
CREATE TABLE IF NOT EXISTS api_approval_request (
    id UUID PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    requested_by INTEGER NOT NULL REFERENCES users(id),
    requested_policy JSONB NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
    reviewed_by INTEGER REFERENCES users(id),
    review_note TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_approval_pending ON api_approval_request(client_id) WHERE status='pending';
CREATE TABLE IF NOT EXISTS api_console_grant (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    role TEXT NOT NULL CHECK(role IN ('operator','auditor'))
);
CREATE TABLE IF NOT EXISTS api_console_verification (
    session_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS api_console_verification_attempt (
    user_id INTEGER NOT NULL REFERENCES users(id),
    bucket_start TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL,
    PRIMARY KEY(user_id,bucket_start)
);
CREATE TABLE IF NOT EXISTS api_usage_bucket (
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    category TEXT NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    units BIGINT NOT NULL DEFAULT 0 CHECK(units>=0),
    PRIMARY KEY(client_id,category,bucket_start)
);
CREATE TABLE IF NOT EXISTS api_call_log (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL,
    client_id INTEGER REFERENCES api_client(id),
    credential_id UUID,
    method TEXT NOT NULL,
    route TEXT NOT NULL,
    status SMALLINT NOT NULL,
    duration_ms BIGINT NOT NULL,
    reason_code TEXT,
    source_ip INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_call_client_time ON api_call_log(client_id,created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS api_audit (
    id BIGSERIAL PRIMARY KEY,
    client_id INTEGER REFERENCES api_client(id),
    actor_type TEXT NOT NULL CHECK(actor_type IN ('user','application','system')),
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_id TEXT,
    request_id UUID,
    changes JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_audit_time ON api_audit(created_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS api_idempotency_record (
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    operation TEXT NOT NULL,
    key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    response JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(client_id,operation,key)
);
CREATE TABLE IF NOT EXISTS api_cursor (
    id UUID PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    credential_id UUID NOT NULL REFERENCES api_credential(id),
    policy_revision BIGINT NOT NULL,
    query_hash TEXT NOT NULL,
    after_value JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW()+INTERVAL '10 minutes'
);
CREATE TABLE IF NOT EXISTS api_job (
    id UUID PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    credential_id UUID NOT NULL REFERENCES api_credential(id),
    policy_revision BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('export','report')),
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed','cancelled','deleted')),
    spec JSONB NOT NULL,
    result JSONB,
    artifact BYTEA,
    artifact_checksum TEXT,
    content_type TEXT,
    filename TEXT,
    last_error TEXT,
    claim_token UUID,
    lease_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW()+INTERVAL '7 days'
);
CREATE INDEX IF NOT EXISTS idx_api_job_queue ON api_job(status,created_at) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS idx_api_job_client ON api_job(client_id,created_at DESC);
CREATE TABLE IF NOT EXISTS api_saved_search (
    id UUID PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    document JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS api_asset_annotation (
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    ip_address INET NOT NULL,
    key TEXT NOT NULL CHECK(char_length(key) BETWEEN 1 AND 64),
    value TEXT NOT NULL CHECK(char_length(value)<=2048),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(client_id,ip_address,key)
);
CREATE TABLE IF NOT EXISTS api_event_outbox (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    event_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    dedup_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_event_client ON api_event_outbox(client_id,id);
CREATE TABLE IF NOT EXISTS api_webhook (
    id UUID PRIMARY KEY,
    client_id INTEGER NOT NULL REFERENCES api_client(id),
    credential_id UUID NOT NULL REFERENCES api_credential(id),
    url TEXT NOT NULL,
    event_types TEXT[] NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    signing_secret BYTEA NOT NULL,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS api_webhook_delivery (
    id UUID PRIMARY KEY,
    webhook_id UUID NOT NULL REFERENCES api_webhook(id),
    event_id BIGINT NOT NULL REFERENCES api_event_outbox(id),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','succeeded','failed','cancelled')),
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    lease_expires_at TIMESTAMPTZ,
    response_status INTEGER,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    UNIQUE(webhook_id,event_id)
);
CREATE INDEX IF NOT EXISTS idx_api_delivery_queue ON api_webhook_delivery(next_attempt_at) WHERE status IN ('pending','running');

ALTER TABLE users ADD COLUMN IF NOT EXISTS access_policy JSONB;
ALTER TABLE users ADD COLUMN IF NOT EXISTS access_version BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS user_access_version BIGINT;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS api_client_id INTEGER REFERENCES api_client(id);
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS api_credential_id UUID REFERENCES api_credential(id);
CREATE INDEX IF NOT EXISTS idx_scan_task_api_client ON scan_task(api_client_id,id DESC) WHERE api_client_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_api_events ON scan_task(task_end_time,id) WHERE api_client_id IS NOT NULL AND task_status IN ('succeeded','failed','partial','cancelled');
CREATE OR REPLACE FUNCTION api_scan_task_enabled(task scan_task) RETURNS BOOLEAN
LANGUAGE SQL STABLE AS $function$
    SELECT EXISTS (
        SELECT 1 FROM users owner
        WHERE owner.id=task.user_id AND owner.deleted_at IS NULL AND owner.disabled_at IS NULL
          AND (
            owner.role=0 AND task.api_client_id IS NULL AND task.user_access_version IS NULL
            OR (
              owner.role=1 AND task.user_access_version IS NULL
              OR owner.role=2 AND (
                owner.access_policy IS NULL AND task.user_access_version IS NULL
                OR task.api_client_id IS NULL AND owner.access_version=task.user_access_version
                   AND owner.access_policy->'permissions' ? 'create_scan'
                   AND ((owner.access_policy->>'expires_at') IS NULL OR
                        (owner.access_policy->>'expires_at')::TIMESTAMPTZ > NOW())
              )
            )
          )
    ) AND (task.api_client_id IS NULL OR EXISTS (
        SELECT 1 FROM api_client a JOIN api_credential k ON k.client_id=a.id
        JOIN users u ON u.id=a.owner_user_id CROSS JOIN api_platform_settings s
        WHERE a.id=task.api_client_id AND k.id=task.api_credential_id AND a.status='active'
          AND a.environment<>'sandbox' AND k.revoked_at IS NULL AND k.expires_at>NOW()
          AND (a.expires_at IS NULL OR a.expires_at>NOW()) AND u.disabled_at IS NULL
          AND u.deleted_at IS NULL AND NOT u.limit_login
          AND COALESCE((s.document->>'enabled')::BOOLEAN,FALSE)
          AND 'tasks:create'=ANY(k.scopes) AND a.policy->'scopes' ? 'tasks:create'
          AND task.generation_metadata->'open_api'->>'policy_revision'=a.revision::TEXT
    ));
$function$;

CREATE OR REPLACE FUNCTION user_scan_scanner_allowed(task scan_task, scanner TEXT) RETURNS BOOLEAN
LANGUAGE SQL STABLE AS $function$
    SELECT task.user_access_version IS NULL OR EXISTS (
        SELECT 1 FROM users owner WHERE owner.id=task.user_id
          AND owner.access_version=task.user_access_version
          AND owner.access_policy->'scanners' ? scanner
    );
$function$;
