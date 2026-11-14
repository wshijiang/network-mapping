-- Syslog 历史日志回填任务：仅由用户手动下发，默认最近 7 天。

CREATE TABLE IF NOT EXISTS syslog_backfill_job (
	id UUID PRIMARY KEY,
	status TEXT NOT NULL DEFAULT 'queued'
		CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
	range_start TIMESTAMPTZ NOT NULL,
	range_end TIMESTAMPTZ NOT NULL,
	created_by_user_id INT REFERENCES users(id),
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	started_at TIMESTAMPTZ,
	finished_at TIMESTAMPTZ,
	cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
	processed_count BIGINT NOT NULL DEFAULT 0,
	sent_count BIGINT NOT NULL DEFAULT 0,
	failed_count BIGINT NOT NULL DEFAULT 0,
	last_error TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_syslog_backfill_job_created
	ON syslog_backfill_job (created_at DESC);