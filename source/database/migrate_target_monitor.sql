-- 目标监控：规则 + 运行 + 变化明细；审计分类 target_monitor。
CREATE TABLE IF NOT EXISTS target_monitor_rule (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    created_by INT NOT NULL REFERENCES users(id),
    recipient_ids INT[] NOT NULL DEFAULT '{}',
    target_type TEXT NOT NULL DEFAULT 'ip' CHECK (target_type IN ('ip', 'domain')),
    target_family TEXT CHECK (target_family IN ('ipv4', 'ipv6')),
    targets TEXT[] NOT NULL CHECK (cardinality(targets) BETWEEN 1 AND 64),
    ports TEXT NOT NULL DEFAULT '1-11000,11211,20000,27017,47808,11210,11300,11371,12174,13720,13721,16379,16992,16993,17185,19071,26379,27018,27019,28015,29015,34962-34964,37777,44818,50000,50090,51413,51820,60010,60030,61613,61616,62078,64738',
    scan_profile TEXT NOT NULL DEFAULT 'service_inventory',
    interval_seconds INT NOT NULL DEFAULT 86400 CHECK (interval_seconds BETWEEN 3600 AND 2592000),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    baseline JSONB,
    last_task_id VARCHAR(36),
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revision BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_target_monitor_due
    ON target_monitor_rule(next_run_at) WHERE enabled AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_target_monitor_owner
    ON target_monitor_rule(created_by) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS target_monitor_run (
    id UUID PRIMARY KEY,
    rule_id UUID NOT NULL REFERENCES target_monitor_rule(id) ON DELETE CASCADE,
    task_id VARCHAR(36),
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled', 'skipped')),
    skip_reason TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    snapshot JSONB,
    change_count INT NOT NULL DEFAULT 0,
    summary JSONB
);
CREATE INDEX IF NOT EXISTS idx_target_monitor_run_rule ON target_monitor_run(rule_id, id DESC);

-- 运行创建时冻结规则配置：收尾按派发时的目标类型与基线比对，
-- 运行期间编辑规则不会让旧任务的结果与新目标混用。
ALTER TABLE target_monitor_run ADD COLUMN IF NOT EXISTS target_type TEXT;
ALTER TABLE target_monitor_run ADD COLUMN IF NOT EXISTS targets TEXT[];
ALTER TABLE target_monitor_run ADD COLUMN IF NOT EXISTS baseline JSONB;

CREATE TABLE IF NOT EXISTS target_monitor_change (
    id UUID PRIMARY KEY,
    run_id UUID NOT NULL REFERENCES target_monitor_run(id) ON DELETE CASCADE,
    rule_id UUID NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN
        ('port_opened', 'port_closed', 'service_changed', 'title_changed', 'cert_changed', 'cert_expiring', 'target_down', 'target_up', 'dns_changed')),
    severity TEXT NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    target TEXT NOT NULL,
    port INT,
    detail JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_target_monitor_change_rule
    ON target_monitor_change(rule_id, occurred_at DESC, id);

-- 审计分类扩展（幂等 drop/re-add，兼容存量约束）。
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'audit_event'::regclass
          AND conname = 'audit_event_category_check'
          AND POSITION('target_monitor' IN pg_get_constraintdef(oid)) = 0
    ) THEN
        ALTER TABLE audit_event DROP CONSTRAINT audit_event_category_check;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'audit_event'::regclass AND conname = 'audit_event_category_check'
    ) THEN
        ALTER TABLE audit_event ADD CONSTRAINT audit_event_category_check CHECK (category IN (
            'authentication', 'authorization', 'user_security', 'task', 'scanner',
            'automatic_target', 'configuration', 'data_access', 'audit', 'backup',
            'data_import', 'federation', 'data_export', 'target_monitor'
        ));
    END IF;
END $$;
