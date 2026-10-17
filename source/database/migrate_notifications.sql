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
        INSERT INTO notification_upgrade(name) VALUES('unified_channels_v1');
    END IF;
END $$;

-- Transfer each legacy recipient independently: a partial success must not be replayed.
-- Imported SMTP receipts stay on revision 1; a later first email setup uses its configured revision.
-- The same transaction-safe handoff runs after Web email configuration when SMTP was absent.
CREATE OR REPLACE FUNCTION notification_transfer_legacy_mail() RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE
    imported UUID;
    destination BIGINT := 1;
    job RECORD;
    event UUID;
BEGIN
    PERFORM pg_advisory_xact_lock(728104, 1);
    -- Repair the earlier completion marker if no channel ever took ownership of existing work.
    IF NOT EXISTS(SELECT 1 FROM notification_channel WHERE legacy_email) AND (
        EXISTS(SELECT 1 FROM scanner_outage_delivery WHERE status IN ('pending','sending') OR (kind='offline' AND status='sent'))
        OR EXISTS(SELECT 1 FROM report_delivery WHERE automatic AND status IN ('pending','sending'))
    ) THEN
        DELETE FROM notification_upgrade WHERE name='unified_mail_queue_v2';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM notification_upgrade WHERE name='unified_mail_queue_v2') THEN
        SELECT id INTO imported FROM notification_channel WHERE legacy_email;
        IF imported IS NULL THEN
            IF NOT EXISTS(SELECT 1 FROM scanner_outage_delivery WHERE status IN ('pending','sending') OR (kind='offline' AND status='sent'))
                AND NOT EXISTS(SELECT 1 FROM report_delivery WHERE automatic AND status IN ('pending','sending')) THEN
                INSERT INTO notification_upgrade(name) VALUES('unified_mail_queue_v2');
                RETURN;
            END IF;
            -- No imported SMTP: the first enabled, configured email channel takes ownership.
            -- This may be an existing channel whose destination was edited before activation.
            SELECT id,destination_revision INTO imported,destination FROM notification_channel
                WHERE provider='email' AND enabled AND deleted_at IS NULL AND secret_ciphertext IS NOT NULL
                AND COALESCE(settings->>'smtp_host','')<>'' AND COALESCE(settings->>'smtp_sender','')<>''
                ORDER BY created_at,id LIMIT 1 FOR UPDATE;
            IF imported IS NULL THEN
                RETURN; -- No consumer yet: leave source rows and the completion marker untouched.
            END IF;
            UPDATE notification_channel SET legacy_email=TRUE WHERE id=imported;
        END IF;
        IF imported IS NOT NULL THEN
            -- Recovery may occur while mail configuration is deferred, after bot recovery was
            -- already prepared. Transfer that email independently instead of reopening bot fanout.
            INSERT INTO scanner_outage_delivery(outage_id,kind,recipient)
                SELECT o.id,'recovered',d.recipient FROM scanner_outage o
                JOIN scanner_outage_delivery d ON d.outage_id=o.id AND d.kind='offline' AND d.status='sent'
                WHERE o.recovered_at IS NOT NULL AND (o.recovery_requested OR o.notification_recovery)
                    AND NOT o.recovery_delivery_prepared
                ON CONFLICT DO NOTHING;
            FOR job IN
                SELECT d.*,o.detected_at FROM scanner_outage_delivery d
                JOIN scanner_outage o ON o.id=d.outage_id
                WHERE d.status IN ('pending','sending') OR (d.kind='offline' AND d.status='sent')
            LOOP
                INSERT INTO notification_event(id,dedup_key,event_type,severity,title,body,outage_id,occurred_at,context)
                VALUES(gen_random_uuid(),'legacy:scanner:'||job.id,'scanner.'||job.kind,'warning',
                    CASE WHEN job.kind='offline' THEN 'Scanner 掉线' ELSE 'Scanner 恢复连接' END,
                    '升级前邮件队列；掉线事件：'||job.outage_id,job.outage_id,
                    CASE WHEN job.status='sent' THEN job.detected_at ELSE GREATEST(NOW(),job.available_at,CASE WHEN job.status='sending' THEN job.claimed_until END) END,
                    jsonb_build_object('legacy_recipient',job.recipient))
                ON CONFLICT(dedup_key) DO NOTHING;
                SELECT id INTO event FROM notification_event WHERE dedup_key='legacy:scanner:'||job.id;
                INSERT INTO notification_delivery(id,event_id,channel_id,destination_revision,status,attempts,available_at,finished_at)
                VALUES(gen_random_uuid(),event,imported,destination,CASE WHEN job.status='sent' THEN 'sent' ELSE 'pending' END,
                    job.attempts,GREATEST(job.available_at,CASE WHEN job.status='sending' THEN job.claimed_until END),
                    CASE WHEN job.status='sent' THEN COALESCE(job.sent_at,job.detected_at) END)
                ON CONFLICT(event_id,channel_id) DO NOTHING;
                -- The replacement is durable before relinquishing the old claim/queue entry.
                UPDATE scanner_outage_delivery SET status='cancelled',claimed_until=NULL
                    WHERE id=job.id AND status IN ('pending','sending');
            END LOOP;

            FOR job IN
                SELECT d.*,r.period_type,r.period_start,r.period_end,r.recipient_ids
                FROM report_delivery d JOIN report_run r ON r.id=d.report_id
                WHERE d.automatic AND d.status IN ('pending','sending') AND r.status='ready'
            LOOP
                -- Reserve the normal dedup key so reopening a ready report cannot broadcast it again.
                INSERT INTO notification_event(id,dedup_key,event_type,severity,title,body,context)
                VALUES(gen_random_uuid(),'report:'||job.report_id,'report.'||job.period_type,'warning','报告已生成',
                    '报告 ID：'||job.report_id,jsonb_build_object('report_id',job.report_id,'recipient_ids',job.recipient_ids))
                ON CONFLICT(dedup_key) DO NOTHING;
                INSERT INTO notification_event(id,dedup_key,event_type,severity,title,body,occurred_at,context)
                VALUES(gen_random_uuid(),'legacy:report:'||job.id,'report.'||job.period_type,'warning','报告已生成',
                    '升级前邮件队列；报告 ID：'||job.report_id,
                    GREATEST(NOW(),job.available_at,CASE WHEN job.status='sending' THEN job.lease_until END),
                    jsonb_build_object('report_id',job.report_id,'recipient_ids',job.recipient_ids,
                        'legacy_recipient',job.recipient,'legacy_recipient_user_id',job.recipient_user_id))
                ON CONFLICT(dedup_key) DO NOTHING;
                SELECT id INTO event FROM notification_event WHERE dedup_key='legacy:report:'||job.id;
                INSERT INTO notification_delivery(id,event_id,channel_id,destination_revision,attempts,available_at)
                VALUES(gen_random_uuid(),event,imported,destination,job.attempts,
                    GREATEST(job.available_at,CASE WHEN job.status='sending' THEN job.lease_until END))
                ON CONFLICT(event_id,channel_id) DO NOTHING;
                UPDATE report_delivery SET status='cancelled',claim_token=NULL,lease_until=NULL WHERE id=job.id;
            END LOOP;

            -- Leave incident flags independent: bot recovery may have already been prepared.
            -- Transferred per-recipient recovery deliveries also prevent duplicate email fanout.
        END IF;
        INSERT INTO notification_upgrade(name) VALUES('unified_mail_queue_v2');
    END IF;
END $$;
SELECT notification_transfer_legacy_mail();
