-- Independent bot templates. Existing mail templates and archived reports stay intact.
CREATE TABLE IF NOT EXISTS notification_template (
    provider TEXT NOT NULL CHECK (provider IN ('feishu','telegram')),
    event_type TEXT NOT NULL CHECK (event_type IN ('health.alert','scanner.offline','scanner.recovered','user.login','report.weekly','report.monthly')),
    revision BIGINT NOT NULL DEFAULT 0,
    active_version INTEGER,
    PRIMARY KEY(provider,event_type)
);
CREATE TABLE IF NOT EXISTS notification_template_version (
    provider TEXT NOT NULL,
    event_type TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('draft','published','archived')),
    source JSONB NOT NULL,
    created_by INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    published_at TIMESTAMPTZ,
    PRIMARY KEY(provider,event_type,version),
    FOREIGN KEY(provider,event_type) REFERENCES notification_template(provider,event_type)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_template_draft
    ON notification_template_version(provider,event_type) WHERE status='draft';
CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_template_published
    ON notification_template_version(provider,event_type) WHERE status='published';
