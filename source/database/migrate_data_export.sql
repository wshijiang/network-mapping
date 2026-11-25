-- 数据管理 · 后台导出（搜索语句匹配 → 后台写 CSV → Web 下载）。
-- 任务由运行中的服务器 worker 认领执行（租约模式，与 data_import_task 一致）。

CREATE TABLE IF NOT EXISTS data_export_task (
    id               UUID PRIMARY KEY,
    created_by       INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ,
    -- 创建时快照的数据范围，避免执行期间角色变化导致口径漂移。
    scope_type       TEXT NOT NULL CHECK (scope_type IN ('global','user')),
    scope_id         INT NOT NULL,
    query            TEXT NOT NULL,
    filter           JSONB NOT NULL,
    scope            TEXT NOT NULL CHECK (scope IN ('page','all')),
    page_offset      BIGINT,
    page_limit       BIGINT,
    sort_field       TEXT NOT NULL DEFAULT 'last_seen',
    sort_order       TEXT NOT NULL DEFAULT 'desc',
    fields           JSONB NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','running','completed','error','cancelled')),
    matched_total    BIGINT,
    exported_rows    BIGINT NOT NULL DEFAULT 0,
    file_path        TEXT,
    file_size        BIGINT,
    sha256           TEXT,
    error_message    TEXT,
    worker_id        UUID,
    lease_expires_at BIGINT
);

CREATE INDEX IF NOT EXISTS idx_data_export_task_owner
    ON data_export_task(created_by, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_data_export_task_claim
    ON data_export_task(status, lease_expires_at);

ALTER TABLE data_export_task
    ADD COLUMN IF NOT EXISTS storage_plan JSONB,
    ADD COLUMN IF NOT EXISTS s3_object JSONB,
    ADD COLUMN IF NOT EXISTS s3_failed BOOLEAN NOT NULL DEFAULT FALSE;

-- Keep cleanup details even if the parent task (or its owner) is deleted.
CREATE TABLE IF NOT EXISTS data_export_attempt (
    id UUID PRIMARY KEY,
    task_id UUID REFERENCES data_export_task(id) ON DELETE SET NULL,
    local_path TEXT,
    s3_object JSONB,
    multipart_upload_id TEXT,
    cleanup_after TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '10 minutes'
);
CREATE INDEX IF NOT EXISTS idx_data_export_attempt_task ON data_export_attempt(task_id);
CREATE INDEX IF NOT EXISTS idx_data_export_attempt_cleanup ON data_export_attempt(cleanup_after);

-- Files created before multi-location support also use the cleanup ledger.
INSERT INTO data_export_attempt (id, task_id, local_path)
    SELECT id, id, file_path FROM data_export_task WHERE storage_plan IS NULL AND file_path IS NOT NULL
    ON CONFLICT (id) DO NOTHING;

-- 导出审计事件分类：旧库的 audit_event_category_check 可能不含 data_export，
-- 启动时幂等补齐，避免导出审计写入被数据库约束拒绝。
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = to_regclass('audit_event')
          AND conname = 'audit_event_category_check'
          AND POSITION('data_export' IN pg_get_constraintdef(oid)) = 0
    ) THEN
        ALTER TABLE audit_event DROP CONSTRAINT audit_event_category_check;
        ALTER TABLE audit_event ADD CONSTRAINT audit_event_category_check CHECK (category IN (
            'authentication', 'authorization', 'user_security', 'task', 'scanner',
            'automatic_target', 'configuration', 'data_access', 'audit', 'backup', 'data_import', 'federation', 'data_export'
        ));
    END IF;
END $$;
