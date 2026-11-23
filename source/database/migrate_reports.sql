-- Administrator platform reports. Plans remain disabled on upgrades.
CREATE TABLE IF NOT EXISTS report_schedule (
    period_type TEXT PRIMARY KEY CHECK (period_type IN ('weekly', 'monthly')),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    send_hour SMALLINT NOT NULL DEFAULT 9 CHECK (send_hour BETWEEN 0 AND 23),
    send_minute SMALLINT NOT NULL DEFAULT 0 CHECK (send_minute BETWEEN 0 AND 59),
    recipient_ids INTEGER[] NOT NULL DEFAULT ARRAY[]::INTEGER[],
    enabled_at TIMESTAMPTZ,
    last_period_end TIMESTAMPTZ,
    revision BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (cardinality(recipient_ids) <= 100)
);
INSERT INTO report_schedule(period_type) VALUES ('weekly'), ('monthly') ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS report_run (
    id UUID PRIMARY KEY,
    period_type TEXT NOT NULL REFERENCES report_schedule(period_type),
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    source TEXT NOT NULL CHECK (source IN ('manual', 'automatic', 'revision')),
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'waiting_data', 'generating', 'ready', 'failed')),
    requested_by INTEGER,
    send_email BOOLEAN NOT NULL DEFAULT FALSE,
    recipient_ids INTEGER[] NOT NULL DEFAULT ARRAY[]::INTEGER[],
    cutoff_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    task_snapshot JSONB NOT NULL,
    payload JSONB,
    quality JSONB NOT NULL DEFAULT '{}'::JSONB,
    last_error TEXT,
    template_key TEXT,
    template_version INTEGER,
    rendered_mail JSONB,
    content_checksum TEXT,
    supersedes_report_id UUID REFERENCES report_run(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    generated_at TIMESTAMPTZ,
    UNIQUE(period_type, period_start, period_end, revision),
    CHECK (period_end > period_start)
);
CREATE INDEX IF NOT EXISTS idx_report_run_list ON report_run(period_start DESC, created_at DESC);
-- No cascading FK to scan executions: cleaning scan history must not delete reports.
CREATE TABLE IF NOT EXISTS report_input_execution (
    report_id UUID NOT NULL REFERENCES report_run(id) ON DELETE CASCADE,
    execution_id INTEGER NOT NULL,
    period_slot TEXT NOT NULL CHECK (period_slot IN ('current', 'previous')),
    expected_observations BIGINT NOT NULL,
    PRIMARY KEY(report_id, execution_id)
);
CREATE TABLE IF NOT EXISTS report_job (
    report_id UUID PRIMARY KEY REFERENCES report_run(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'retry_wait', 'succeeded', 'failed')),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0,
    wait_deadline TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '24 hours'),
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_report_job_ready ON report_job(available_at, report_id)
    WHERE status IN ('pending', 'retry_wait');
CREATE TABLE IF NOT EXISTS report_delivery (
    id UUID PRIMARY KEY,
    report_id UUID NOT NULL REFERENCES report_run(id) ON DELETE CASCADE,
    recipient_user_id INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    dispatch_seq INTEGER NOT NULL DEFAULT 1,
    automatic BOOLEAN NOT NULL DEFAULT FALSE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'cancelled')),
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    attempts INTEGER NOT NULL DEFAULT 0,
    claim_token UUID,
    lease_until TIMESTAMPTZ,
    sent_at TIMESTAMPTZ,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(report_id, recipient_user_id, dispatch_seq)
);
CREATE INDEX IF NOT EXISTS idx_report_delivery_ready ON report_delivery(available_at, id)
    WHERE status IN ('pending', 'sending');
CREATE INDEX IF NOT EXISTS idx_scan_execution_report_end ON scan_task_execution(task_end_time, id)
    WHERE execution_status = 'succeeded';
INSERT INTO mail_template(template_key, display_name) VALUES
    ('report_daily', '平台日报'), ('report_weekly', '平台周报'), ('report_monthly', '平台月报') ON CONFLICT DO NOTHING;

-- 日报周期：扩展约束并补齐计划行（幂等）。
ALTER TABLE report_schedule DROP CONSTRAINT IF EXISTS report_schedule_period_type_check;
ALTER TABLE report_schedule ADD CONSTRAINT report_schedule_period_type_check
    CHECK (period_type IN ('daily', 'weekly', 'monthly'));
INSERT INTO report_schedule(period_type) VALUES ('daily') ON CONFLICT DO NOTHING;

-- 用户报告订阅：站内通知收件人并授予对应周期报告的查看权限（幂等）。
CREATE TABLE IF NOT EXISTS report_subscription (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_type TEXT NOT NULL REFERENCES report_schedule(period_type) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, period_type)
);
