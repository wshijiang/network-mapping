-- Feishu application-bot binding state. Binding codes are never stored in plaintext.
CREATE TABLE IF NOT EXISTS feishu_binding_request (
    id UUID PRIMARY KEY,
    channel_id UUID NOT NULL REFERENCES notification_channel(id),
    app_id TEXT NOT NULL,
    code_digest BYTEA NOT NULL,
    channel_revision BIGINT NOT NULL,
    created_by INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'bound', 'cancelled', 'expired')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS feishu_binding_one_pending_channel
    ON feishu_binding_request(channel_id) WHERE status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS feishu_binding_one_pending_code
    ON feishu_binding_request(app_id, code_digest) WHERE status = 'pending';

-- Fenced leases coordinate one connection per app across server replicas.
CREATE TABLE IF NOT EXISTS feishu_binding_connection (
    app_id TEXT PRIMARY KEY,
    owner UUID,
    generation BIGINT NOT NULL DEFAULT 0,
    lease_until TIMESTAMPTZ,
    state TEXT NOT NULL DEFAULT 'disconnected',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS feishu_binding_event (
    app_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(app_id, event_id)
);

CREATE TABLE IF NOT EXISTS feishu_binding_rate (
    app_id TEXT NOT NULL,
    subject BYTEA NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL,
    PRIMARY KEY(app_id, subject)
);

CREATE TABLE IF NOT EXISTS feishu_binding_reply (
    id UUID PRIMARY KEY,
    app_id TEXT NOT NULL,
    channel_id UUID NOT NULL REFERENCES notification_channel(id),
    target_open_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
