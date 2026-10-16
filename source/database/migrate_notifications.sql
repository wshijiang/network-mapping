-- Notification channels are separate from SMTP and external-application webhooks.
CREATE TABLE IF NOT EXISTS notification_channel (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('feishu')),
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    event_types TEXT[] NOT NULL,
    minimum_severity TEXT NOT NULL CHECK (minimum_severity IN ('warning', 'critical')),
    webhook_ciphertext BYTEA NOT NULL,
    secret_ciphertext BYTEA,
    revision BIGINT NOT NULL DEFAULT 1,
    destination_revision BIGINT NOT NULL DEFAULT 1,
    next_send_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_test_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS notification_event (
    id UUID PRIMARY KEY,
    dedup_key TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    outage_id BIGINT REFERENCES scanner_outage(id) ON DELETE CASCADE,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notification_delivery (
    id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES notification_event(id) ON DELETE CASCADE,
    channel_id UUID NOT NULL REFERENCES notification_channel(id),
    destination_revision BIGINT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT,
    response_status INTEGER,
    provider_code BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    UNIQUE(event_id, channel_id)
);
CREATE INDEX IF NOT EXISTS idx_notification_delivery_ready
    ON notification_delivery(available_at, id) WHERE status IN ('pending', 'sending');
CREATE INDEX IF NOT EXISTS idx_notification_delivery_channel
    ON notification_delivery(channel_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_notification_event_outage ON notification_event(outage_id);
CREATE INDEX IF NOT EXISTS idx_notification_event_time ON notification_event(occurred_at);

-- The database gate coordinates health-alert cooldown across processes/restarts.
CREATE TABLE IF NOT EXISTS notification_health_gate (
    alert_key TEXT PRIMARY KEY,
    severity TEXT NOT NULL,
    admitted_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE scanner_outage ADD COLUMN IF NOT EXISTS notification_recovery BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE scanner_outage ADD COLUMN IF NOT EXISTS notification_recovery_prepared BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_scanner_outage_notification_recovery ON scanner_outage(id)
    WHERE notification_recovery AND NOT notification_recovery_prepared AND recovered_at IS NOT NULL;
