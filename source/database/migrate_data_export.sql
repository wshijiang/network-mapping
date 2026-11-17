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