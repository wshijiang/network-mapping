-- Syslog 转发：目标状态快照与分钟级转发指标。
-- 配置本身存于 runtime_configuration（namespace = 'syslog'），由运行时配置机制播种。

CREATE TABLE IF NOT EXISTS syslog_target_status (
	target_id UUID PRIMARY KEY,
	state TEXT NOT NULL DEFAULT 'connecting',
	sent_count BIGINT NOT NULL DEFAULT 0,
	failed_count BIGINT NOT NULL DEFAULT 0,
	dropped_count BIGINT NOT NULL DEFAULT 0,
	last_success_at TIMESTAMPTZ,
	last_error_at TIMESTAMPTZ,
	last_error TEXT NOT NULL DEFAULT '',
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS syslog_metric_minute (
	target_id UUID NOT NULL,
	bucket_start TIMESTAMPTZ NOT NULL,
	sent BIGINT NOT NULL DEFAULT 0,
	failed BIGINT NOT NULL DEFAULT 0,
	dropped BIGINT NOT NULL DEFAULT 0,
	p50_ms REAL,
	p95_ms REAL,
	p99_ms REAL,
	max_ms REAL,
	by_source JSONB NOT NULL DEFAULT '{}'::JSONB,
	PRIMARY KEY (target_id, bucket_start)
);

CREATE INDEX IF NOT EXISTS idx_syslog_metric_minute_time
	ON syslog_metric_minute (bucket_start);