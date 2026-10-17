-- Notification channels share subscriptions across email, Feishu and Telegram.
CREATE TABLE IF NOT EXISTS notification_channel (
    id UUID PRIMARY KEY,
    provider TEXT NOT NULL CHECK (provider IN ('email', 'feishu', 'telegram')),
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

ALTER TABLE notification_channel DROP CONSTRAINT IF EXISTS notification_channel_provider_check;
ALTER TABLE notification_channel ADD CONSTRAINT notification_channel_provider_check
    CHECK (provider IN ('email', 'feishu', 'telegram'));
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS settings JSONB NOT NULL DEFAULT '{}';
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS legacy_email BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_legacy_email ON notification_channel(legacy_email) WHERE legacy_email;

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
ALTER TABLE notification_event ADD COLUMN IF NOT EXISTS context JSONB NOT NULL DEFAULT '{}';

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

-- Import legacy SMTP exactly once. The test recipient is deliberately not a notification recipient.
CREATE TABLE IF NOT EXISTS notification_upgrade (
    name TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
DO $$
DECLARE
    smtp JSONB;
    prefs JSONB;
    events TEXT[];
BEGIN
    IF NOT EXISTS(SELECT 1 FROM notification_upgrade WHERE name='unified_channels_v1') THEN
        SELECT COALESCE(jsonb_object_agg(key,value),'{}') INTO smtp FROM setting WHERE item_type='smtp';
        SELECT COALESCE(jsonb_object_agg(key,value),'{}') INTO prefs FROM setting WHERE item_type='notification';
        events := array_remove(ARRAY[
            CASE WHEN COALESCE(prefs->>'health_alert_enabled','true')='true' THEN 'health.alert' END,
            CASE WHEN COALESCE(prefs->>'scanner_offline_enabled','false')='true' THEN 'scanner.offline' END,
            CASE WHEN COALESCE(prefs->>'scanner_recovery_enabled','true')='true' THEN 'scanner.recovered' END,
            CASE WHEN COALESCE(prefs->>'login_notify_enabled','true')='true' THEN 'user.login' END,
            CASE WHEN COALESCE(prefs->>'report_weekly','true')='true' THEN 'report.weekly' END,
            CASE WHEN COALESCE(prefs->>'report_monthly','false')='true' THEN 'report.monthly' END
        ],NULL);
        IF COALESCE(smtp->>'host','')<>'' OR COALESCE(smtp->>'sender','')<>'' THEN
            INSERT INTO notification_channel(id,provider,name,enabled,event_types,minimum_severity,webhook_ciphertext,secret_ciphertext,settings,legacy_email)
            VALUES(gen_random_uuid(),'email','邮件通知',cardinality(events)>0 AND COALESCE(smtp->>'host','')<>'' AND COALESCE(smtp->>'sender','')<>'' AND COALESCE(smtp->>'sender_key','')<>'',
                CASE WHEN cardinality(events)>0 THEN events ELSE ARRAY['health.alert'] END,'warning',''::BYTEA,
                CASE WHEN COALESCE(smtp->>'sender_key','')<>'' THEN decode(smtp->>'sender_key','base64') END,
                jsonb_build_object('smtp_host',COALESCE(smtp->>'host',''),'smtp_port',CASE WHEN smtp->>'port' ~ '^[0-9]{1,5}$' THEN (smtp->>'port')::INT ELSE 465 END,'smtp_sender',COALESCE(smtp->>'sender',''),'recipients','[]'::JSONB),TRUE);
        END IF;
        -- Old pending scanner mail must not duplicate the imported channel's deliveries.
        UPDATE scanner_outage_delivery SET status='cancelled',claimed_until=NULL WHERE status='pending';
        UPDATE report_delivery SET status='cancelled',claim_token=NULL,lease_until=NULL WHERE automatic AND status='pending';
        INSERT INTO notification_upgrade(name) VALUES('unified_channels_v1');
    END IF;
END $$;
