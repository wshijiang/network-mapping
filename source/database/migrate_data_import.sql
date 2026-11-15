-- 数据管理 · 外部导入（CSV 资产端点导入）。
-- 任务与批次台账；导入观察经现有 result_ingest 管道写入 ES，扫描任务以 task_source='import' 标记。

CREATE TABLE IF NOT EXISTS data_import_task (
    id               UUID PRIMARY KEY,
    created_by       INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    file_name        TEXT NOT NULL,
    file_size        BIGINT NOT NULL,
    sha256           TEXT NOT NULL,
    storage_path     TEXT NOT NULL,
    file_headers     JSONB NOT NULL DEFAULT '[]'::JSONB,
    header_mapping   JSONB NOT NULL DEFAULT '{}'::JSONB,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','validating','type_checking',
                                       'importing','paused','completed','error','cancelled')),
    on_invalid       TEXT NOT NULL DEFAULT 'skip' CHECK (on_invalid IN ('skip','abort')),
    overwrite_policy TEXT NOT NULL DEFAULT 'fill' CHECK (overwrite_policy IN ('fill','overwrite')),
    dry_run          BOOLEAN NOT NULL DEFAULT false,
    fast_mode        BOOLEAN NOT NULL DEFAULT false,
    batch_size       INT NOT NULL DEFAULT 1000 CHECK (batch_size BETWEEN 1 AND 50000),
    concurrency      INT NOT NULL DEFAULT 2 CHECK (concurrency BETWEEN 1 AND 8),
    total_rows       BIGINT,
    processed_rows   BIGINT NOT NULL DEFAULT 0,
    imported_rows    BIGINT NOT NULL DEFAULT 0,
    invalid_rows     BIGINT NOT NULL DEFAULT 0,
    duplicate_rows   BIGINT NOT NULL DEFAULT 0,
    conflict_rows    BIGINT NOT NULL DEFAULT 0,
    error_samples    JSONB NOT NULL DEFAULT '[]'::JSONB,
    error_message    TEXT,
    scan_task_id     INT REFERENCES scan_task(id) ON DELETE SET NULL,
    execution_id     INT REFERENCES scan_task_execution(id) ON DELETE SET NULL,
    upload_id        UUID,
    next_batch_index INT NOT NULL DEFAULT 0,
    committed_rows   BIGINT NOT NULL DEFAULT 0,
    worker_id        UUID,
    lease_expires_at BIGINT,
    started_at       TIMESTAMPTZ,
    finished_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_data_import_task_status
    ON data_import_task (status, created_at);
CREATE INDEX IF NOT EXISTS idx_data_import_task_lease
    ON data_import_task (lease_expires_at)
    WHERE status IN ('validating','type_checking','importing');

CREATE TABLE IF NOT EXISTS data_import_batch (
    task_id          UUID NOT NULL REFERENCES data_import_task(id) ON DELETE CASCADE,
    batch_index      INT NOT NULL,
    row_start        BIGINT NOT NULL,
    row_end          BIGINT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','committed','failed')),
    observation_count INT NOT NULL DEFAULT 0,
    payload_checksum TEXT,
    committed_at     TIMESTAMPTZ,
    PRIMARY KEY (task_id, batch_index)
);

-- 预留系统扫描器身份：导入观察以该扫描器名义经 result_ingest 写入。
-- 由 worker 启动时确保存在（runtime_token_hash 由服务端密钥派生），扫描器管理列表排除此行。
INSERT INTO scanner_info (name, scanner_id, create_user, runtime_token_hash, is_enable, is_run, remark, create_time, register_time)
VALUES ('数据导入', '00000000-0000-7000-8000-00000000d1a0', 0, '', true, false, '__system_data_import__', NOW(), NOW())
ON CONFLICT (scanner_id) DO NOTHING;