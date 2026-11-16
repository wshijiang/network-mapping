-- 数据管理 · 联测（多源网络空间测绘联合查询）。
-- 数据源配置（凭据/代理加密）与联测 run 台账；联测观察经现有 result_ingest 管道写入 ES，
-- 扫描任务以 task_source='federation' 标记。设计见工作区 FEDERATION_PLAN.md 与 docs/FEDERATION.md。

CREATE TABLE IF NOT EXISTS federation_source (
    id               UUID PRIMARY KEY,
    kind             TEXT NOT NULL CHECK (kind IN ('hunter','quake','fofa','shodan')),
    name             TEXT NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT false,
    credential_ciphertext BYTEA,
    proxy_mode       TEXT NOT NULL DEFAULT 'system' CHECK (proxy_mode IN ('system','direct','custom')),
    proxy_ciphertext BYTEA,
    fields           JSONB NOT NULL DEFAULT '["ip","domain","port","service","tech"]'::JSONB,
    pagination_mode  TEXT NOT NULL DEFAULT 'follow_local' CHECK (pagination_mode IN ('follow_local','fixed')),
    page_size        INT NOT NULL DEFAULT 100 CHECK (page_size BETWEEN 1 AND 1000),
    max_pages        INT NOT NULL DEFAULT 5 CHECK (max_pages BETWEEN 1 AND 50),
    window_mode      TEXT NOT NULL DEFAULT 'follow' CHECK (window_mode IN ('follow','none','custom')),
    window_days      INT NOT NULL DEFAULT 30 CHECK (window_days BETWEEN 1 AND 60),
    timeout_seconds  INT NOT NULL DEFAULT 15 CHECK (timeout_seconds BETWEEN 3 AND 120),
    rate_limit_qps   DOUBLE PRECISION NOT NULL DEFAULT 1.0 CHECK (rate_limit_qps > 0 AND rate_limit_qps <= 10),
    detected_capabilities JSONB,
    revision         BIGINT NOT NULL DEFAULT 1,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_federation_source_name
    ON federation_source (name) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS federation_run (
    id               UUID PRIMARY KEY,
    query_text       TEXT NOT NULL,
    query_hash       TEXT NOT NULL,
    trigger          TEXT NOT NULL CHECK (trigger IN ('search','manual')),
    mode             TEXT NOT NULL CHECK (mode IN ('async','blocking')),
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','running','completed','partial','failed','cancelled','unsupported')),
    requested_by     INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    window_days      INT NOT NULL DEFAULT 30 CHECK (window_days BETWEEN 1 AND 60),
    local_state      TEXT NOT NULL DEFAULT 'unknown' CHECK (local_state IN ('empty','stale','fresh','unknown')),
    selected_sources JSONB,
    local_limit      INT NOT NULL DEFAULT 100 CHECK (local_limit BETWEEN 1 AND 100),
    local_offset     INT NOT NULL DEFAULT 0 CHECK (local_offset >= 0),
    persist_override TEXT NOT NULL DEFAULT 'auto' CHECK (persist_override IN ('auto','force','skip')),
    sources          JSONB NOT NULL DEFAULT '[]'::JSONB,
    total_fetched    INT NOT NULL DEFAULT 0,
    total_merged     INT NOT NULL DEFAULT 0,
    total_persisted  INT NOT NULL DEFAULT 0,
    result_cache     JSONB,
    persist_decision JSONB,
    error_message    TEXT,
    worker_id        UUID,
    lease_expires_at BIGINT,
    scan_task_id     INT REFERENCES scan_task(id) ON DELETE SET NULL,
    execution_id     INT REFERENCES scan_task_execution(id) ON DELETE SET NULL,
    upload_id        UUID,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_federation_run_status
    ON federation_run (status, created_at);
CREATE INDEX IF NOT EXISTS idx_federation_run_hash
    ON federation_run (query_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_federation_run_lease
    ON federation_run (lease_expires_at)
    WHERE status IN ('pending','running');

-- 预留系统扫描器身份：联测观察以该扫描器名义经 result_ingest 写入。
-- 由 worker 启动时确保存在（runtime_token_hash 由服务端密钥派生），扫描器管理列表排除此行。
INSERT INTO scanner_info (name, scanner_id, create_user, runtime_token_hash, is_enable, is_run, remark, create_time, register_time)
VALUES ('联测', '00000000-0000-7000-8000-00000000fed0', 0, '', true, false, '__system_federation__', NOW(), NOW())
ON CONFLICT (scanner_id) DO NOTHING;

-- run 状态：旧库的 federation_run_status_check 可能不含 unsupported（全部源不支持该语句），
-- 启动时幂等补齐，避免“未查询”run 被数据库约束拒绝。
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = to_regclass('federation_run')
          AND conname = 'federation_run_status_check'
          AND POSITION('unsupported' IN pg_get_constraintdef(oid)) = 0
    ) THEN
        ALTER TABLE federation_run DROP CONSTRAINT federation_run_status_check;
        ALTER TABLE federation_run ADD CONSTRAINT federation_run_status_check CHECK (status IN (
            'pending','running','completed','partial','failed','cancelled','unsupported'
        ));
    END IF;
END $$;

-- 联测审计事件分类：旧库的 audit_event_category_check 可能不含 federation，
-- 启动时幂等补齐，避免联测审计写入被数据库约束拒绝。
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = to_regclass('audit_event')
          AND conname = 'audit_event_category_check'
          AND POSITION('federation' IN pg_get_constraintdef(oid)) = 0
    ) THEN
        ALTER TABLE audit_event DROP CONSTRAINT audit_event_category_check;
        ALTER TABLE audit_event ADD CONSTRAINT audit_event_category_check CHECK (category IN (
            'authentication', 'authorization', 'user_security', 'task', 'scanner',
            'automatic_target', 'configuration', 'data_access', 'audit', 'backup', 'data_import', 'federation'
        ));
    END IF;
END $$;
