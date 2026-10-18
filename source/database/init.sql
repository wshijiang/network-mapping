

-- 表 users 用于存储平台用户信息
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(200) NOT NULL UNIQUE,
    password TEXT NOT NULL,
	role INT,                                                                             -- 用户的权限级别，INT4 值，从 0-2 分别为系统、管理员、普通用户
	email TEXT,
    create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,    -- 用户的创建时间
	limit_login boolean DEFAULT false,                                                    -- 表示用户是否是被限制登录，既可以表示系统用户永远无法登录以及该账号是否因为密码错误而临时禁止登录
	limit_at BIGINT,                                                                      -- 限制登录操作产生的时间
	limit_time INT,                                                                       -- 限制登录时间，单位为 秒 
	enable_2fa boolean DEFAULT false,                                                     -- 表示用户是否启用了 2FA
	totp_secret TEXT,                                                                     -- TOTP 密钥
	last_login_at BIGINT,                                                                 -- 表示该用户最后一次登录的时间
	last_login_ip INET,                                                                   -- 最后一次登录的 IP 地址
	login_error_count INT,                                                                -- 登录错误的次数
	last_error_at BIGINT,                                                                 -- 最后一次登录出错的时间，以该时间为起点，判断是否将登录错误次数清零
	login_ip_allowlist CIDR[] NOT NULL DEFAULT ARRAY[]::CIDR[],                            -- 用户登录来源白名单；空数组表示不限制
	disabled_at TIMESTAMPTZ,                                                              -- 管理员主动禁用时间，与密码错误锁定分离
	deleted_at TIMESTAMPTZ,                                                               -- 软删除时间，保留任务与审计历史
	update_at TIMESTAMPTZ
);

ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS update_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS login_ip_allowlist CIDR[] NOT NULL DEFAULT ARRAY[]::CIDR[];
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'users_login_ip_allowlist_size_check'
    ) THEN
        ALTER TABLE users ADD CONSTRAINT users_login_ip_allowlist_size_check
            CHECK (cardinality(login_ip_allowlist) <= 64);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_users_management_status
ON users (role, disabled_at, deleted_at) WHERE role IN (1, 2);

-- 表 scan_task 用于存储扫描任务信息，配置了级联更新和删除
CREATE TABLE IF NOT EXISTS scan_task( 
	id SERIAL PRIMARY KEY,
	user_id INT NOT NULL,
	task_id VARCHAR(36) NOT NULL,                                                             -- 任务的 ID ，应该为 UUIDV7
	task_initiator VARCHAR(200) NOT NULL,
	task_target INET[] NOT NULL,                                                              -- 扫描的目标 IP/CIDR 数组
	task_port TEXT DEFAULT '1-65535',                                                         -- 扫描目标的 PORT
	task_create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT,   -- 表示扫描任务的创建时间
	task_level INT NOT NULL CHECK ( task_level >= 0 AND task_level <=4 ) DEFAULT 1,           -- 表示任务的优先级
	task_start_time BIGINT DEFAULT NULL,                                                      -- 扫描开始时间
	task_end_time BIGINT DEFAULT NULL,                                                        -- 扫描结束时间
	task_status TEXT NOT NULL DEFAULT 'pending',                                              -- pending/running/succeeded/failed
	assigned_scanner_id VARCHAR(36),                                                          -- 当前领取任务的扫描器 UUID
	lease_expires_at BIGINT,                                                                  -- 任务租约到期时间（毫秒时间戳）
	attempt_count INT NOT NULL DEFAULT 0,                                                     -- 任务领取次数
	failure_reason TEXT,                                                                      -- 最近一次扫描失败原因
	cancel_requested BOOLEAN NOT NULL DEFAULT false,                                          -- 控制端请求扫描器终止当前任务
	retry_of_task_id VARCHAR(36),                                                             -- 重试任务所引用的原任务
	dispatch_mode TEXT NOT NULL DEFAULT 'automatic',                                          -- automatic/selected/all
	task_source TEXT NOT NULL DEFAULT 'manual',                                               -- manual/automatic/search
	generation_strategy TEXT,
	generation_key TEXT,
	generation_metadata JSONB,
	address_family TEXT NOT NULL DEFAULT 'ipv4' CHECK (address_family IN ('ipv4', 'ipv6')),
	scan_profile TEXT NOT NULL DEFAULT 'legacy',
	scan_plan JSONB NOT NULL DEFAULT '{"version":1,"profile":"legacy","stages":[{"type":"port_discovery","required":true},{"type":"service_detection","required":false}]}'::jsonb,
	task_kind TEXT NOT NULL DEFAULT 'ip',
	dns_targets TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
	remarks TEXT DEFAULT NULL ,                                                               -- 扫描任务的备注
	CONSTRAINT fk_user
		FOREIGN KEY (user_id)
		REFERENCES users(id)
		ON DELETE CASCADE
		ON UPDATE CASCADE,
	CONSTRAINT uk_task_id UNIQUE (task_id)
);

-- 兼容已有数据库中的任务表。
ALTER TABLE scan_task ALTER COLUMN task_initiator TYPE VARCHAR(200);
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS task_source TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS generation_strategy TEXT;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS generation_key TEXT;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS generation_metadata JSONB;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS address_family TEXT NOT NULL DEFAULT 'ipv4';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS scan_profile TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS scan_plan JSONB NOT NULL
    DEFAULT '{"version":1,"profile":"legacy","stages":[{"type":"port_discovery","required":true},{"type":"service_detection","required":false}]}'::jsonb;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS task_kind TEXT NOT NULL DEFAULT 'ip';
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS dns_targets TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS dns_resolvers JSONB NOT NULL DEFAULT '[]'::JSONB;
UPDATE scan_task SET address_family = 'ipv6'
WHERE cardinality(task_target) > 0
  AND NOT EXISTS (SELECT 1 FROM unnest(task_target) AS target WHERE family(target) <> 6);
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'scan_task_address_family_check'
    ) THEN
        ALTER TABLE scan_task ADD CONSTRAINT scan_task_address_family_check
            CHECK (address_family IN ('ipv4', 'ipv6'));
    END IF;
END $$;
ALTER TABLE scan_task DROP CONSTRAINT IF EXISTS scan_task_profile_check;
ALTER TABLE scan_task ADD CONSTRAINT scan_task_profile_check
    CHECK (scan_profile IN (
        'legacy',
        'port_only',
        'service_inventory',
        'vulnerability_scan',
        'dns_records',
        'dns_ports',
        'dns_full'
    ));
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'scan_task_kind_check'
    ) THEN
        ALTER TABLE scan_task ADD CONSTRAINT scan_task_kind_check
            CHECK (task_kind IN ('ip', 'dns'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS scan_task_execution (
	id SERIAL PRIMARY KEY,
	execution_id VARCHAR(36) NOT NULL UNIQUE,
	task_id INT NOT NULL REFERENCES scan_task(id) ON DELETE CASCADE,
	requested_scanner_id VARCHAR(36),
	assigned_scanner_id VARCHAR(36),
	execution_status TEXT NOT NULL DEFAULT 'pending',
	attempt_count INT NOT NULL DEFAULT 0,
	task_start_time BIGINT,
	task_end_time BIGINT,
	lease_expires_at BIGINT,
	maintenance_hold BOOLEAN NOT NULL DEFAULT false,
	maintenance_hold_until TIMESTAMPTZ,
	failure_reason TEXT,
	cancel_requested BOOLEAN NOT NULL DEFAULT false,
	result_ip_count BIGINT,
	result_port_count BIGINT,
	result_observation_count BIGINT,
	CONSTRAINT uk_task_execution_scanner UNIQUE(task_id, requested_scanner_id)
);

ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS result_ip_count BIGINT;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS result_port_count BIGINT;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS result_observation_count BIGINT;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS maintenance_hold BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS maintenance_hold_until TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS automatic_target_state (
	strategy TEXT PRIMARY KEY,
	cursor JSONB NOT NULL DEFAULT '{"position": 0}'::JSONB,
	policy_hash TEXT NOT NULL,
	last_generated_at TIMESTAMPTZ,
	last_error TEXT,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 标签分类用于在 Web 端组织标签；风险语义仍由 asset_tag.kind 控制。
CREATE TABLE IF NOT EXISTS asset_tag_category (
	id BIGSERIAL PRIMARY KEY,
	name VARCHAR(32) NOT NULL,
	description VARCHAR(256),
	sort_order INT NOT NULL DEFAULT 0,
	is_active BOOLEAN NOT NULL DEFAULT TRUE,
	created_by INT REFERENCES users(id) ON DELETE SET NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_tag_category_active_name
	ON asset_tag_category (LOWER(name)) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_asset_tag_category_active_sort
	ON asset_tag_category (is_active, sort_order, id);

INSERT INTO asset_tag_category (name, description, sort_order)
SELECT '未分类', '系统升级时用于接收已有标签的默认分类', 0
WHERE NOT EXISTS (
	SELECT 1 FROM asset_tag_category WHERE is_active AND LOWER(name) = LOWER('未分类')
);

-- 资产标签独立于扫描执行保存。同一个 IP 的标签会应用到所有任务与历史结果。
CREATE TABLE IF NOT EXISTS asset_tag (
	id BIGSERIAL PRIMARY KEY,
	name VARCHAR(32) NOT NULL,
	kind TEXT NOT NULL CHECK (kind IN ('info', 'malicious', 'benign')),
	description VARCHAR(256),
	category_id BIGINT CONSTRAINT fk_asset_tag_category REFERENCES asset_tag_category(id),
	is_active BOOLEAN NOT NULL DEFAULT TRUE,
	created_by INT REFERENCES users(id) ON DELETE SET NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 兼容已有标签表：补列、回填默认分类，再收紧约束。
ALTER TABLE asset_tag ADD COLUMN IF NOT EXISTS category_id BIGINT;
UPDATE asset_tag
SET category_id = (
	SELECT id FROM asset_tag_category
	WHERE is_active AND LOWER(name) = LOWER('未分类')
	ORDER BY id LIMIT 1
)
WHERE category_id IS NULL;
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conname = 'fk_asset_tag_category' AND conrelid = 'asset_tag'::REGCLASS
	) THEN
		ALTER TABLE asset_tag
			ADD CONSTRAINT fk_asset_tag_category
			FOREIGN KEY (category_id) REFERENCES asset_tag_category(id);
	END IF;
END $$;
ALTER TABLE asset_tag ALTER COLUMN category_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_asset_tag_active_name
	ON asset_tag (LOWER(name)) WHERE is_active;
CREATE INDEX IF NOT EXISTS idx_asset_tag_kind_active
	ON asset_tag (kind, is_active);
CREATE INDEX IF NOT EXISTS idx_asset_tag_category_active
	ON asset_tag (category_id, is_active);

CREATE TABLE IF NOT EXISTS asset_ip_tag (
	ip_address INET NOT NULL,
	tag_id BIGINT NOT NULL REFERENCES asset_tag(id) ON DELETE CASCADE,
	assigned_by INT REFERENCES users(id) ON DELETE SET NULL,
	assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (ip_address, tag_id)
);

CREATE INDEX IF NOT EXISTS idx_asset_ip_tag_address
	ON asset_ip_tag (ip_address);
CREATE INDEX IF NOT EXISTS idx_asset_ip_tag_tag_address
	ON asset_ip_tag (tag_id, ip_address);

-- Versioned, idempotent scanner uploads. A retry with the same execution/upload/batch
-- identity is acknowledged without inserting observations again.
CREATE TABLE IF NOT EXISTS scan_result_batch (
	id BIGSERIAL PRIMARY KEY,
	execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	upload_id VARCHAR(36) NOT NULL,
	batch_index INT NOT NULL CHECK (batch_index >= 0),
	is_final BOOLEAN NOT NULL,
	observation_count INT NOT NULL CHECK (observation_count >= 0),
	protocol_version SMALLINT NOT NULL DEFAULT 2 CHECK (protocol_version IN (1, 2, 3)),
	payload_checksum VARCHAR(64),
	-- `pending` reserves an upload while its idempotent Elasticsearch write runs outside
	-- the PostgreSQL transaction. A retry resumes the same receipt after a crash/timeout.
	storage_backend TEXT NOT NULL DEFAULT 'pending',
	storage_references JSONB NOT NULL DEFAULT '[]'::JSONB,
	write_token UUID,
	write_lease_expires_at TIMESTAMPTZ,
	write_attempts INT NOT NULL DEFAULT 0,
	write_started_at TIMESTAMPTZ,
	last_write_error TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE(execution_id, upload_id, batch_index)
);

CREATE TABLE IF NOT EXISTS scan_storage_state (
	state_key TEXT PRIMARY KEY,
	state_value JSONB NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_projection_outbox (
	execution_id INT PRIMARY KEY REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	attempts INT NOT NULL DEFAULT 0,
	available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	last_error TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	processed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scan_projection_outbox_pending
	ON scan_projection_outbox(available_at, execution_id) WHERE processed_at IS NULL;

ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS claim_token UUID;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS cursor JSONB;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS phase TEXT NOT NULL DEFAULT 'promoting'
    CHECK (phase IN ('promoting', 'refreshing'));
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS processed_endpoints BIGINT NOT NULL DEFAULT 0;
ALTER TABLE scan_projection_outbox ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS protocol_version SMALLINT NOT NULL DEFAULT 2;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS payload_checksum VARCHAR(64);
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS storage_backend TEXT NOT NULL DEFAULT 'postgres';
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS storage_references JSONB NOT NULL DEFAULT '[]'::JSONB;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_token UUID;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_lease_expires_at TIMESTAMPTZ;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS write_started_at TIMESTAMPTZ;
ALTER TABLE scan_result_batch ADD COLUMN IF NOT EXISTS last_write_error TEXT;
ALTER TABLE scan_result_batch DROP CONSTRAINT IF EXISTS scan_result_batch_protocol_version_check;
ALTER TABLE scan_result_batch ADD CONSTRAINT scan_result_batch_protocol_version_check
	CHECK (protocol_version IN (1, 2, 3));

-- Analysis snapshots are deliberately independent from scan facts. Existing installations can
-- upgrade safely: the worker reconciles already succeeded executions into this outbox.
CREATE TABLE IF NOT EXISTS analytics_outbox (
	execution_id INT PRIMARY KEY REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed')),
	attempts INT NOT NULL DEFAULT 0,
	available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	locked_at TIMESTAMPTZ,
	completed_at TIMESTAMPTZ,
	last_error TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_analytics_outbox_pending
	ON analytics_outbox(available_at, execution_id) WHERE status <> 'completed';
CREATE INDEX IF NOT EXISTS idx_analytics_outbox_pending_ready
	ON analytics_outbox(available_at, execution_id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_analytics_outbox_running_locked
	ON analytics_outbox(locked_at, execution_id) WHERE status = 'running';

-- One compact, additive row per execution/window/dimension/label. It avoids repeatedly
-- aggregating the raw observation history on interactive requests.
CREATE TABLE IF NOT EXISTS analytics_distribution_30m (
	execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	bucket_start TIMESTAMPTZ NOT NULL,
	owner_id INT NOT NULL,
	scanner_id TEXT NOT NULL,
	task_source TEXT NOT NULL,
	dimension TEXT NOT NULL CHECK (dimension IN ('service', 'port')),
	label TEXT NOT NULL,
	endpoint_count BIGINT NOT NULL CHECK (endpoint_count >= 0),
	PRIMARY KEY (execution_id, bucket_start, dimension, label)
);
CREATE INDEX IF NOT EXISTS idx_analytics_distribution_query
	ON analytics_distribution_30m(bucket_start, owner_id, scanner_id, task_source, dimension);

-- IP facts are already deduplicated per execution/day. Queries only need to deduplicate this
-- much smaller set, never the full observation corpus.
CREATE TABLE IF NOT EXISTS analytics_discovery_fact (
	execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	day_start DATE NOT NULL,
	first_observed_at TIMESTAMPTZ,
	owner_id INT NOT NULL,
	scanner_id TEXT NOT NULL,
	task_source TEXT NOT NULL,
	ip_address INET NOT NULL,
	PRIMARY KEY (execution_id, day_start, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_analytics_discovery_query
	ON analytics_discovery_fact(day_start, owner_id, scanner_id, task_source);

CREATE TABLE IF NOT EXISTS analytics_watermark (
	watermark_key TEXT PRIMARY KEY,
	data_as_of TIMESTAMPTZ NOT NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A fixed set of executions, independent of arrivals during a backfill.
CREATE TABLE IF NOT EXISTS analytics_snapshot_build (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS analytics_snapshot_build_execution (
    execution_id INT PRIMARY KEY REFERENCES analytics_outbox(execution_id) ON DELETE CASCADE
);

-- 表 session 用于存储cookie，其中包括在有效期内的和有效期外的
CREATE TABLE IF NOT EXISTS session (
	user_id INT NOT NULL,
	id SERIAL PRIMARY KEY,
	token TEXT NOT NULL,
	csrf_token TEXT NOT NULL,
	ttl INT DEFAULT 2700,
	totp_verify_successful boolean DEFAULT false,
	pending_totp_secret TEXT,
	pending_totp_expires_at BIGINT,
	pending_totp_attempt_id UUID,
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) * 1000)::BIGINT, 
	is_enable boolean DEFAULT true,
	deleted_at TIMESTAMPTZ,
	deletion_reason TEXT,
	deleted_by_user_id INT
);

-- Session 使用软删除保留认证历史，便于安全事件回溯。旧库升级时只补充审计字段，
-- 不物理删除既有失效记录；历史记录的精确失效时间未知，因此明确标记为迁移时间。
ALTER TABLE session ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE session ADD COLUMN IF NOT EXISTS pending_totp_attempt_id UUID;
ALTER TABLE session ADD COLUMN IF NOT EXISTS deletion_reason TEXT;
ALTER TABLE session ADD COLUMN IF NOT EXISTS deleted_by_user_id INT;
DO $$
BEGIN
	IF NOT EXISTS (
		SELECT 1 FROM pg_constraint
		WHERE conrelid = 'session'::regclass AND conname = 'session_deleted_by_user_fk'
	) THEN
		ALTER TABLE session ADD CONSTRAINT session_deleted_by_user_fk
			FOREIGN KEY (deleted_by_user_id) REFERENCES users(id) ON DELETE SET NULL;
	END IF;
END $$;
UPDATE session
SET deleted_at = NOW(), deletion_reason = 'legacy_inactive_migrated'
WHERE is_enable = FALSE AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_session_unique ON session (token, is_enable);
CREATE UNIQUE INDEX IF NOT EXISTS idx_csrf_token_unique ON session (csrf_token, is_enable);
CREATE INDEX IF NOT EXISTS idx_session_user_status ON session (user_id, is_enable);
CREATE INDEX IF NOT EXISTS idx_session_active_expiration
	ON session ((create_time + ttl::BIGINT * 1000), id)
	WHERE is_enable = TRUE AND deleted_at IS NULL;

ALTER TABLE session ALTER COLUMN ttl SET DEFAULT 2700;


-- 表 system_status 用于存储系统状态数据
CREATE TABLE IF NOT EXISTS system_status (
	id SERIAL PRIMARY KEY,
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,   -- 为了便于筛选，使用秒级 UNIX 时间戳
	server_run_time BIGINT DEFAULT 0,
	cpu JSONB DEFAULT NULL,
	ram JSONB DEFAULT NULL,
	disk JSONB DEFAULT NULL,
	db_postgresql JSONB DEFAULT NULL,
	db_elasticsearch JSONB DEFAULT NULL,
	network JSONB DEFAULT NULL
);

ALTER TABLE system_status ADD COLUMN IF NOT EXISTS db_elasticsearch JSONB DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_system_status_create_time
	ON system_status(create_time);

-- 表 login_logs 用于存储用户登录日志，包括登陆成功和失败 
CREATE TABLE IF NOT EXISTS login_logs (
	id SERIAL PRIMARY KEY,
	event_at BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,       -- 触发登录事件的时间，该列通常由数据库自动生成，当然也可能由后端生产，需要在后面看
	event_ip INET,                                                                 -- 触发登录事件的 IP 地址
	event_usage_id INT,                                                            -- 登录日志中触发该事件的用户 ID ，该参数可有可无
	is_successful boolean NOT NULL                                                 -- 登录日志中表示成功登录，True 表示登录成功，False 表示登录失败
);

-- 表 scanner_info 用于存储扫描器的各种信息，可以存放扫描器的 ID (UUIDV4) ，扫描器的版本，所支持的网络环境 IPV4/IPV6/ALL ，当前状态（RUN/STOP）
CREATE TABLE IF NOT EXISTS scanner_info (
	id SERIAL PRIMARY KEY,
	name VARCHAR(50),                                                               -- 扫描器的名称
	scanner_id VARCHAR(36) NOT NULL UNIQUE,                                         -- 该字段为扫描器的 ID ，UUIDV7
	create_user INT NOT NULL,                                                       -- 由谁创建
	registration_token_hash TEXT UNIQUE,                                            -- 一次性注册 token 的 HMAC 哈希
	registration_token_expires_at TIMESTAMPTZ,                                      -- 注册 token 过期时间
	registration_consumed_at TIMESTAMPTZ,                                           -- 注册 token 消费时间
	runtime_token_hash TEXT UNIQUE,                                                 -- 扫描器运行 token 的 HMAC 哈希
	runtime_token_rotated_at TIMESTAMPTZ,                                           -- 运行 token 最近轮换时间
	location TEXT,                                                                  -- 扫描器的位置描述
	system_version TEXT,                                                            -- 扫描器所在的系统名称及版本
	scanner_version TEXT,                                                           -- 扫描器的版本
	cpu_model TEXT,                                                                 -- 扫描器 CPU 型号
	cpus INT,                                                                       -- 扫描器 CPU 数量
	ram INT,                                                                        -- 扫描器 RAM 大小
	uptime INT,                                                                     -- 扫描器总共运行的时间
	create_time TIMESTAMPTZ,                                                        -- 扫描器创建的时间
	register_time TIMESTAMPTZ,                                                      -- 扫描器注册时间
	update_time TIMESTAMPTZ,                                                        -- 更新时间
	last_seen_at TIMESTAMPTZ,                                                       -- 最近一次收到心跳的时间
	runtime_state TEXT NOT NULL DEFAULT 'offline',                                  -- offline/idle/scanning/stopping
	ip_address INET,                                                                -- 扫描器的IP地址
	is_run boolean,                                                                 -- 扫描器是否在运行
	is_enable boolean,                                                              -- 扫描器是否启用
	remark TEXT,                                                                    -- 扫描器的备注
	tag TEXT,                                                                       -- 扫描器的标签
	deleted_at TIMESTAMPTZ                                                          -- 软删除时间
);

-- 仅新版本服务成功处理过的心跳会启用掉线监控，避免升级时补发历史离线告警。
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS outage_monitored_at TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS scanner_outage (
	id BIGSERIAL PRIMARY KEY,
	scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id) ON DELETE CASCADE,
	last_seen_at TIMESTAMPTZ NOT NULL,
	detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	recovered_at TIMESTAMPTZ,
	recovery_requested BOOLEAN NOT NULL DEFAULT FALSE,
	recovery_delivery_prepared BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scanner_outage_active
	ON scanner_outage(scanner_id) WHERE recovered_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_scanner_outage_recovery_queue
	ON scanner_outage(id)
	WHERE recovered_at IS NOT NULL AND recovery_requested AND NOT recovery_delivery_prepared;

CREATE TABLE IF NOT EXISTS scanner_outage_delivery (
	id BIGSERIAL PRIMARY KEY,
	outage_id BIGINT NOT NULL REFERENCES scanner_outage(id) ON DELETE CASCADE,
	kind TEXT NOT NULL CHECK (kind IN ('offline', 'recovered')),
	recipient TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending'
		CHECK (status IN ('pending', 'sending', 'sent', 'cancelled', 'failed')),
	attempts INT NOT NULL DEFAULT 0,
	available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	claimed_until TIMESTAMPTZ,
	sent_at TIMESTAMPTZ,
	last_error TEXT,
	UNIQUE (outage_id, kind, recipient)
);
CREATE INDEX IF NOT EXISTS idx_scanner_outage_delivery_ready
	ON scanner_outage_delivery(available_at, id)
	WHERE status IN ('pending', 'sending');

-- 旧版扫描器没有网络能力心跳，安全地按仅支持 IPv4 处理。
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS supports_ipv4 BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS supports_ipv6 BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS ipv4_ready BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS ipv6_ready BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS public_ipv4 INET;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS public_ipv6 INET;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS network_status_reason JSONB;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS network_capabilities_updated_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS scan_capabilities JSONB NOT NULL
    DEFAULT '{"plan_versions":[],"profiles":["legacy"],"stages":["port_discovery"]}'::jsonb;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS scan_capabilities_updated_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_rtt_us BIGINT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_network_rtt_us BIGINT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_server_processing_us BIGINT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_measured_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS latency_probe_id UUID;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS applied_config_revision BIGINT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS config_status TEXT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS config_error TEXT;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS config_reported_at TIMESTAMPTZ;
ALTER TABLE scanner_info ADD COLUMN IF NOT EXISTS local_config_check JSONB;

CREATE TABLE IF NOT EXISTS scanner_runtime_configuration (
	scanner_id VARCHAR(36) PRIMARY KEY REFERENCES scanner_info(scanner_id) ON DELETE CASCADE,
	document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
	revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
	schema_version INT NOT NULL DEFAULT 1 CHECK (schema_version > 0),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_by_user_id INT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS scanner_runtime_configuration_revision (
	id BIGSERIAL PRIMARY KEY,
	scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id) ON DELETE CASCADE,
	revision BIGINT NOT NULL CHECK (revision > 0),
	schema_version INT NOT NULL CHECK (schema_version > 0),
	document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
	changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	changed_by_user_id INT REFERENCES users(id),
	change_reason TEXT NOT NULL DEFAULT '',
	UNIQUE(scanner_id, revision)
);

-- 扫描器到服务端的 HTTPS 心跳延迟历史。最新值同时冗余在 scanner_info，
-- 避免扫描器列表查询历史表。
CREATE TABLE IF NOT EXISTS scanner_latency_sample (
	id BIGSERIAL PRIMARY KEY,
	scanner_id VARCHAR(36) NOT NULL REFERENCES scanner_info(scanner_id) ON UPDATE CASCADE,
	probe_id UUID NOT NULL,
	measured_at TIMESTAMPTZ NOT NULL,
	reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	rtt_us BIGINT NOT NULL CHECK (rtt_us >= 0),
	server_processing_us BIGINT NOT NULL CHECK (server_processing_us >= 0),
	network_rtt_us BIGINT NOT NULL CHECK (network_rtt_us >= 0),
	UNIQUE(scanner_id, probe_id)
);

CREATE INDEX IF NOT EXISTS idx_scanner_latency_scanner_time
	ON scanner_latency_sample(scanner_id, measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_scanner_latency_time
	ON scanner_latency_sample(measured_at);

-- 系统维护状态。单行表用于跨进程重启恢复；预计结束时间仅用于提示，
-- enabled 只能由管理员通过 Web 控制接口显式关闭。
DO $$
BEGIN
	IF to_regclass('public.scanner_maintenance_state') IS NOT NULL
		AND to_regclass('public.system_maintenance_state') IS NULL THEN
		ALTER TABLE scanner_maintenance_state RENAME TO system_maintenance_state;
	END IF;
END $$;

CREATE TABLE IF NOT EXISTS system_maintenance_state (
	singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
	enabled BOOLEAN NOT NULL DEFAULT FALSE,
	phase TEXT NOT NULL DEFAULT 'off' CHECK (phase IN ('off', 'draining', 'active')),
	maintenance_id UUID,
	message TEXT NOT NULL DEFAULT '',
	expected_end_at TIMESTAMPTZ,
	retry_after_seconds INT NOT NULL DEFAULT 600 CHECK (retry_after_seconds BETWEEN 60 AND 86400),
	started_at TIMESTAMPTZ,
	started_by INT REFERENCES users(id),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	exited_at TIMESTAMPTZ,
	exited_by INT REFERENCES users(id),
	revision BIGINT NOT NULL DEFAULT 0
);

INSERT INTO system_maintenance_state (singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING;

-- 系统维护历史。每次进入维护即创建记录；退出维护时补齐结束信息，
-- 以便服务重启或操作者变更后仍可完整追溯维护窗口。
CREATE TABLE IF NOT EXISTS system_maintenance_history (
	id BIGSERIAL PRIMARY KEY,
	maintenance_id UUID NOT NULL UNIQUE,
	message TEXT NOT NULL DEFAULT '',
	expected_end_at TIMESTAMPTZ,
	started_at TIMESTAMPTZ NOT NULL,
	ended_at TIMESTAMPTZ,
	started_by_user_id INT REFERENCES users(id) ON DELETE SET NULL,
	started_by_username VARCHAR(200) NOT NULL,
	ended_by_user_id INT REFERENCES users(id) ON DELETE SET NULL,
	ended_by_username VARCHAR(200),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX IF NOT EXISTS idx_system_maintenance_history_started_at
	ON system_maintenance_history (started_at DESC, id DESC);

-- 升级期间若系统已处于维护模式，补建未完成的历史记录。
INSERT INTO system_maintenance_history (
	maintenance_id, message, expected_end_at, started_at, started_by_user_id,
	started_by_username, updated_at
)
SELECT s.maintenance_id, s.message, s.expected_end_at, s.started_at, s.started_by,
	COALESCE(u.username, '未知操作者'), s.updated_at
FROM system_maintenance_state s
LEFT JOIN users u ON u.id = s.started_by
WHERE s.enabled = TRUE AND s.maintenance_id IS NOT NULL AND s.started_at IS NOT NULL
ON CONFLICT (maintenance_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS operation_audit (
	id BIGSERIAL PRIMARY KEY,
	actor_user_id INT,
	action TEXT NOT NULL,
	resource_type TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	detail JSONB,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 统一安全审计事件。login_logs 与 operation_audit 暂时保留用于兼容旧数据，
-- 新代码只写入 audit_event。
CREATE TABLE IF NOT EXISTS audit_event (
	id BIGSERIAL PRIMARY KEY,
	event_id UUID NOT NULL UNIQUE,
	occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	category TEXT NOT NULL CONSTRAINT audit_event_category_check CHECK (category IN (
		'authentication', 'authorization', 'user_security', 'task', 'scanner',
		'automatic_target', 'configuration', 'data_access', 'audit', 'backup'
	)),
	action TEXT NOT NULL,
	outcome TEXT NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
	severity TEXT NOT NULL DEFAULT 'info' CHECK (severity IN ('info', 'warning', 'critical')),
	actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'scanner', 'system', 'anonymous')),
	actor_id TEXT,
	actor_name TEXT,
	resource_type TEXT,
	resource_id TEXT,
	request_id UUID,
	source_ip INET,
	user_agent TEXT,
	http_method TEXT,
	request_path TEXT,
	response_status SMALLINT,
	reason_code TEXT,
	changes JSONB,
	metadata JSONB NOT NULL DEFAULT '{}'::JSONB
);

-- 兼容尚未包含新审计分类的已有审计表。
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'audit_event'::regclass
          AND conname = 'audit_event_category_check'
          AND (
              POSITION('automatic_target' IN pg_get_constraintdef(oid)) = 0
              OR POSITION('backup' IN pg_get_constraintdef(oid)) = 0
          )
    ) THEN
        ALTER TABLE audit_event DROP CONSTRAINT audit_event_category_check;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'audit_event'::regclass
          AND conname = 'audit_event_category_check'
    ) THEN
        ALTER TABLE audit_event ADD CONSTRAINT audit_event_category_check CHECK (category IN (
            'authentication', 'authorization', 'user_security', 'task', 'scanner',
            'automatic_target', 'configuration', 'data_access', 'audit', 'backup'
        ));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_audit_event_time
	ON audit_event (occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_actor_time
	ON audit_event (actor_type, actor_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_resource_time
	ON audit_event (resource_type, resource_id, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_action_time
	ON audit_event (action, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_login_actor_time
	ON audit_event (actor_id, occurred_at DESC, id DESC)
	WHERE category = 'authentication' AND action = 'auth.login';
CREATE INDEX IF NOT EXISTS idx_audit_event_login_username_time
	ON audit_event ((COALESCE(actor_name, metadata->>'attempted_username')), occurred_at DESC, id DESC)
	WHERE category = 'authentication' AND action = 'auth.login' AND actor_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_audit_event_request
	ON audit_event (request_id) WHERE request_id IS NOT NULL;

-- 任务调度与结果索引。当前开发环境直接按上述定义创建全新表结构。

CREATE INDEX IF NOT EXISTS idx_scan_task_execution_dispatch
	ON scan_task_execution (execution_status, requested_scanner_id, lease_expires_at, task_id);

CREATE INDEX IF NOT EXISTS idx_scan_task_claim_priority
	ON scan_task (task_level DESC, task_create_time, id)
	WHERE task_status IN ('pending', 'running');
CREATE INDEX IF NOT EXISTS idx_scan_task_execution_selected_pending
	ON scan_task_execution (requested_scanner_id, task_id, id)
	WHERE execution_status = 'pending' AND requested_scanner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_execution_public_pending
	ON scan_task_execution (task_id, id)
	WHERE execution_status = 'pending' AND requested_scanner_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_execution_expired_running
	ON scan_task_execution (task_id, lease_expires_at, id)
	WHERE execution_status = 'running' AND maintenance_hold = FALSE AND cancel_requested = FALSE;
CREATE INDEX IF NOT EXISTS idx_scan_task_execution_cancel_reaper
	ON scan_task_execution (lease_expires_at, id)
	WHERE execution_status = 'running' AND cancel_requested = TRUE;

CREATE INDEX IF NOT EXISTS idx_scan_task_execution_maintenance_hold
	ON scan_task_execution (maintenance_hold_until)
	WHERE execution_status = 'running' AND maintenance_hold = TRUE;
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_task_execution_running_owner
	ON scan_task_execution (task_id, assigned_scanner_id)
	WHERE execution_status = 'running' AND assigned_scanner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_execution_running_scanner
	ON scan_task_execution (assigned_scanner_id)
	WHERE execution_status = 'running' AND assigned_scanner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_dispatch
	ON scan_task (task_status, lease_expires_at, task_level DESC, task_create_time);
CREATE INDEX IF NOT EXISTS idx_scan_task_user_list
	ON scan_task (user_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_task_status_list
	ON scan_task (task_status, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_task_scanner_list
	ON scan_task (assigned_scanner_id, id DESC)
	WHERE assigned_scanner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_scan_task_create_time_list
	ON scan_task (task_create_time DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_scan_task_manual_list
	ON scan_task (id DESC) WHERE task_source <> 'automatic';
CREATE INDEX IF NOT EXISTS idx_scan_task_automatic_queue
	ON scan_task (task_status, task_create_time) WHERE task_source = 'automatic';
CREATE INDEX IF NOT EXISTS idx_scan_task_automatic_family_queue
	ON scan_task (address_family, task_status, task_create_time) WHERE task_source = 'automatic';
CREATE INDEX IF NOT EXISTS idx_scan_task_generation_key
	ON scan_task (generation_key, task_create_time DESC) WHERE generation_key IS NOT NULL;

-- DNS 解析结果的可扫描地址及其派生端口任务。结果独立于 Elasticsearch，
-- 以便在多批上传、重试和服务重启后仍能保证子任务只生成一次。
CREATE TABLE IF NOT EXISTS dns_resolved_address (
	id SERIAL PRIMARY KEY,
	execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	task_id INT NOT NULL REFERENCES scan_task(id) ON DELETE CASCADE,
	ip_address INET NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	UNIQUE (execution_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_dns_resolved_address_execution
	ON dns_resolved_address (execution_id, ip_address);

CREATE TABLE IF NOT EXISTS dns_follow_up_generation (
	execution_id INT PRIMARY KEY REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	status TEXT NOT NULL CHECK (status IN ('succeeded', 'no_eligible_ip', 'blocked_policy')),
	eligible_ip_count INT NOT NULL DEFAULT 0,
	created_task_count INT NOT NULL DEFAULT 0,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_task_lineage (
	parent_task_id INT NOT NULL REFERENCES scan_task(id) ON DELETE CASCADE,
	parent_execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
	child_task_id INT NOT NULL UNIQUE REFERENCES scan_task(id) ON DELETE CASCADE,
	source_addresses INET[] NOT NULL,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_task_lineage_parent
	ON scan_task_lineage (parent_task_id, parent_execution_id);

-- 表 ip_list 用于存储 IP 名单信息，这个 IP 名单可用于多处，如：扫描白名单，访问白名单（黑名单）等···
CREATE TABLE IF NOT EXISTS ip_list (
	id SERIAL PRIMARY KEY,
	is_white boolean DEFAULT false,                                                 -- 该字段表示是否是白名单，默认为 false 
	ip INET NOT NULL,                                                               -- 该字段可以存储单个 IP 或 CIDR 地址段
	create_time BIGINT DEFAULT (EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::BIGINT,     -- 白名单 IP/CIDR 创建时间
	tag TEXT,                                                                       -- IP 列表的标签
	remark TEXT,                                                                    -- IP 列表的备注
	UNIQUE(ip, is_white)                                                            -- 限制了 ip 和 is_white 组合的唯一性
);


-- 国家简写表
CREATE TABLE IF NOT EXISTS country (
	id SERIAL PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	create_at TIMESTAMPTZ DEFAULT NOW(),
	remarks TEXT
);


-- 以下为 ASN 表所需要的组织信息表
CREATE TABLE IF NOT EXISTS org (
	id SERIAL PRIMARY KEY,
	org_name TEXT DEFAULT NULL,                                                    -- 组织名
	org_key TEXT,                                                                  -- 组织的唯一标识符
	org_type TEXT,                                                                 -- 组织类型
	descr TEXT DEFAULT NULL,                                                       -- 组织描述信息
	country TEXT,                                                                  -- 组织所属国家
	address TEXT,                                                                  -- 组织的物理地址
	phone TEXT,                                                                    -- 组织的电话
	email TEXT,                                                                    -- 组织的联系邮箱
	admin_c TEXT,                                                                  -- 管理联系人
	tech_c TEXT,                                                                   -- 组织技术联系人
	last_modified timestamptz,                                                     -- 该组织信息最后变动时间，该信息来自 RIR 数据
	create_at TEXT,                                                                -- 该条目创建的时间
	source TEXT,                                                                   -- 该条目数据来自哪一个 RIR
	unique_hash TEXT GENERATED ALWAYS AS (
		MD5(
			COALESCE(org_name, '') ||
			COALESCE(org_key, '') ||
			COALESCE(country, '') ||
			COALESCE(admin_c, '') ||
			COALESCE(source, '') 
		)
	) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_unique_hash ON org (unique_hash);

-- 以下为 ASN 表，其中描述了 IP/CIDR 当前宣告的 asn号，对应 RIR 数据中的 route/route6 路由宣告表
CREATE TABLE IF NOT EXISTS asn (
	id SERIAL PRIMARY KEY,
	ip INET,
	asnumber TEXT DEFAULT NULL,
	descr TEXT,
	status TEXT,                                                                    -- 当前段的状态 常见值包括：
	                                                                                --   • ASSIGNED NON-PORTABLE：已分配给特定组织，不可转移
																					--   • ALLOCATED PORTABLE：可携带的分配（常用于 ISP）
																					--   • SUB-ALLOCATED：子分配
	mnt_by TEXT,                                                                    -- 当前段的主维护者
	mnt_irt TEXT,
	mnt_lower TEXT,
	created timestamptz,                                                            -- 创建时间，该时间来自 RIR
	last_modified timestamptz,                                                      -- 最后修改时间
	create_at TIMESTAMPTZ DEFAULT NOW(),                                            -- 在本地数据库中创建的时间
	remarks TEXT,
	source TEXT,
	unique_hash TEXT GENERATED ALWAYS AS (
		MD5(
			COALESCE(ip::TEXT, '') ||
			COALESCE(asnumber, '') ||
			COALESCE(status, '') ||
			COALESCE(mnt_by, '') ||
			COALESCE(remarks, '') ||
			COALESCE(source, '')
		)
	) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_asn_unique_hash ON asn (unique_hash);



-- 该表描述了当前 IP/CIDR 对应的 ISP  ，对应 RIR 数据中的 inetnum/inet6num 所属表
CREATE TABLE IF NOT EXISTS isp (
	id SERIAL PRIMARY KEY,
	ip INET,
	netname TEXT,
	descr TEXT,
	country TEXT,
	admin_c TEXT,
	tech_c TEXT,
	notify TEXT,
	status TEXT,
	mnt_by TEXT,
	mnt_irt TEXT,
	remarks TEXT,
	last_modified timestamptz,
	source TEXT,

	create_at TIMESTAMPTZ DEFAULT NOW(),              -- 该条目在本地数据库创建的时间
	unique_hash TEXT GENERATED ALWAYS AS (
        MD5(
            COALESCE(ip::TEXT, '') ||
            COALESCE(netname, '') ||
            COALESCE(descr, '') ||
            COALESCE(country, '') ||
            COALESCE(admin_c, '') ||
            COALESCE(tech_c, '') ||
            COALESCE(notify, '') ||
            COALESCE(status, '') ||
            COALESCE(mnt_by, '') ||
            COALESCE(mnt_irt, '') ||
            COALESCE(remarks, '') ||
            COALESCE(source, '')
        )
    ) STORED
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_isp_unique_hash ON isp (unique_hash);

-- 存放配置
CREATE TABLE IF NOT EXISTS setting (
	id SERIAL PRIMARY KEY,
	item_type TEXT,
	key TEXT,
	value TEXT,
	create_at TIMESTAMPTZ DEFAULT NOW(),
	update_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_setting_item_type_key ON setting (item_type, key);

-- 可在线发布的服务运行策略。setting 保留给旧的简单键值配置；这里以完整 JSON
-- 文档、revision 与不可变历史确保校验、审计和并发更新可以原子完成。
CREATE TABLE IF NOT EXISTS runtime_configuration (
	namespace TEXT PRIMARY KEY,
	document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
	revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
	schema_version INT NOT NULL DEFAULT 1 CHECK (schema_version > 0),
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_by_user_id INT REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS runtime_configuration_revision (
	id BIGSERIAL PRIMARY KEY,
	namespace TEXT NOT NULL,
	revision BIGINT NOT NULL CHECK (revision > 0),
	schema_version INT NOT NULL CHECK (schema_version > 0),
	document JSONB NOT NULL CHECK (jsonb_typeof(document) = 'object'),
	changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	changed_by_user_id INT REFERENCES users(id),
	change_reason TEXT NOT NULL DEFAULT '',
	UNIQUE(namespace, revision)
);

INSERT INTO setting (item_type, key, value)
VALUES ('security', 'session_ttl_seconds', '2700')
ON CONFLICT (item_type, key) DO NOTHING;

INSERT INTO setting (item_type, key, value)
VALUES ('scan', 'default_profile', 'legacy')
ON CONFLICT (item_type, key) DO NOTHING;

INSERT INTO setting (item_type, key, value)
VALUES ('network', 'trusted_proxies', '{"trustedProxyCidrs":[],"clientIpHeader":"x-forwarded-for"}')
ON CONFLICT (item_type, key) DO NOTHING;

-- 邮件模板元数据与版本。草稿不会影响正在使用的已发布版本。
CREATE TABLE IF NOT EXISTS mail_template (
	template_key TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	active_version INT,
	enabled BOOLEAN NOT NULL DEFAULT TRUE,
	create_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	update_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS mail_template_version (
	id BIGSERIAL PRIMARY KEY,
	template_key TEXT NOT NULL REFERENCES mail_template(template_key) ON DELETE CASCADE,
	version INT NOT NULL,
	status TEXT NOT NULL CHECK (status IN ('draft', 'published', 'archived')),
	subject_template TEXT NOT NULL,
	html_template TEXT NOT NULL,
	text_template TEXT NOT NULL,
	created_by INT REFERENCES users(id) ON DELETE SET NULL,
	create_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	update_at TIMESTAMPTZ,
	published_at TIMESTAMPTZ,
	UNIQUE (template_key, version)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_template_single_draft
ON mail_template_version (template_key)
WHERE status = 'draft';

CREATE UNIQUE INDEX IF NOT EXISTS idx_mail_template_single_published
ON mail_template_version (template_key)
WHERE status = 'published';

INSERT INTO mail_template (template_key, display_name)
VALUES ('login_success', '登录成功')
ON CONFLICT (template_key) DO UPDATE SET display_name = EXCLUDED.display_name;

-- 请求日志（访问日志）：覆盖每一个业务请求，用于请求级分析与错误自动识别。
-- 与 audit_event（安全审计，只记录敏感操作）不同，本表不记录请求体、原始查询串、
-- Session、CSRF Token、Authorization 请求头、扫描器令牌。
CREATE TABLE IF NOT EXISTS request_log (
	id BIGSERIAL PRIMARY KEY,
	request_id UUID NOT NULL,
	occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	http_method TEXT NOT NULL,
	request_path TEXT NOT NULL,
	status_code SMALLINT NOT NULL,
	duration_ms INTEGER,
	duration_us BIGINT,
	route_pattern TEXT,
	client_ip INET,
	user_agent TEXT,
	actor_id INT,                        -- 已认证用户 id；匿名/扫描器请求为 NULL
	actor_name TEXT,                     -- 已认证用户名；匿名/扫描器请求为 NULL
	error_level TEXT NOT NULL DEFAULT 'ok'
		CHECK (error_level IN ('ok', 'client_error', 'server_error')),
	error_type TEXT,                     -- bad_request / unauthorized / not_found / ...
	reason_code TEXT                     -- 服务端判定的稳定原因代码，不存储请求体或凭据
);

-- 兼容已经创建 request_log 的部署：保留 duration_ms，新增微秒精度和标准化路由。
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS duration_us BIGINT;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS route_pattern TEXT;
ALTER TABLE request_log ADD COLUMN IF NOT EXISTS reason_code TEXT;

-- 只保留 2 个索引：分页/趋势/保留清理走 time 索引，错误查询与错误率趋势走 error 索引。
CREATE INDEX IF NOT EXISTS idx_request_log_time
	ON request_log (occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_request_log_error
	ON request_log (error_level, occurred_at DESC);

-- 健康告警历史：记录慢请求、5xx 错误、慢 SQL 的告警事件，供告警历史页与跨重启冷却去重使用。
-- detail 为 JSONB，存储告警详情键值列表（结构与 health_alert 邮件模板的 details 一致）。
CREATE TABLE IF NOT EXISTS health_alert (
	id BIGSERIAL PRIMARY KEY,
	alert_type TEXT NOT NULL,
	alert_key TEXT NOT NULL,
	severity TEXT NOT NULL DEFAULT 'warning',
	summary TEXT NOT NULL DEFAULT '',
	detail JSONB NOT NULL DEFAULT '{}',
	occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_health_alert_key_time
	ON health_alert (alert_type, alert_key, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_health_alert_time
	ON health_alert (occurred_at DESC, id DESC);

-- pgBackRest Web 管理任务。仓库中的 backup.info 仍是备份集的权威数据源；
-- 本表只保存手动操作的执行状态、日志和审计关联。
CREATE TABLE IF NOT EXISTS backup_job (
	id UUID PRIMARY KEY,
	operation TEXT NOT NULL CHECK (operation IN ('full', 'diff', 'incr', 'check')),
	source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'scheduled')),
	status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
	requested_by INT REFERENCES users(id) ON DELETE SET NULL,
	remark TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	started_at TIMESTAMPTZ,
	finished_at TIMESTAMPTZ,
	exit_code INT,
	stdout TEXT NOT NULL DEFAULT '',
	stderr TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_backup_job_created_at
	ON backup_job (created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_backup_job_single_active
	ON backup_job ((1)) WHERE status IN ('queued', 'running');

-- 搜索读模型：按用户权限范围和管理员全局范围预先维护每个 IP:port 的当前状态。
-- 历史 observation 仍是权威事实；此表和 Elasticsearch 索引均可重建。
CREATE TABLE IF NOT EXISTS search_index_outbox (
	id BIGSERIAL PRIMARY KEY,
	event_kind TEXT NOT NULL CHECK (event_kind IN ('execution', 'ip', 'full')),
	aggregate_key TEXT NOT NULL,
	payload JSONB NOT NULL DEFAULT '{}',
	attempts INT NOT NULL DEFAULT 0,
	available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	locked_at TIMESTAMPTZ,
	processed_at TIMESTAMPTZ,
	last_error TEXT,
	created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_search_index_outbox_pending
	ON search_index_outbox(available_at, id)
	WHERE processed_at IS NULL;


ALTER TABLE scan_result_batch ALTER COLUMN storage_backend SET DEFAULT 'pending';

-- Search-trigger state outlives task deletion so deleting tasks cannot bypass cooldown.
CREATE TABLE IF NOT EXISTS search_target_state (
    owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL CHECK (target_kind IN ('ip', 'domain')),
    target_key TEXT NOT NULL,
    last_success_at BIGINT,
    last_success_plan JSONB,
    last_search_generated_at BIGINT,
    last_search_task_id TEXT,
    PRIMARY KEY (owner_id, target_kind, target_key)
);
CREATE INDEX IF NOT EXISTS idx_search_target_recent ON search_target_state(owner_id, last_search_generated_at);
-- A durable rolling-hour admission log; independent from deletable tasks and targets.
CREATE TABLE IF NOT EXISTS search_generation_admission (
    owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    generated_at BIGINT NOT NULL,
    task_id TEXT NOT NULL PRIMARY KEY
);
CREATE INDEX IF NOT EXISTS idx_search_generation_admission_owner_time ON search_generation_admission(owner_id, generated_at);
CREATE INDEX IF NOT EXISTS idx_search_generation_admission_time ON search_generation_admission(generated_at);
CREATE INDEX IF NOT EXISTS idx_scan_task_search_source ON scan_task(id) WHERE task_source = 'search';

-- Persistent recovery count; safe to reapply on existing databases.
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS recovery_failure_count INTEGER NOT NULL DEFAULT 0 CHECK (recovery_failure_count >= 0);

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
    ('report_weekly', '平台周报'), ('report_monthly', '平台月报') ON CONFLICT DO NOTHING;

-- Preserve absolute observation instants and immutable report calendar rules.
ALTER TABLE analytics_discovery_fact ADD COLUMN IF NOT EXISTS first_observed_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_analytics_discovery_instant ON analytics_discovery_fact(first_observed_at, owner_id, scanner_id, task_source);
ALTER TABLE report_run ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai';
ALTER TABLE report_run ADD COLUMN IF NOT EXISTS settings_revision BIGINT NOT NULL DEFAULT 0;

ALTER TABLE report_run DROP CONSTRAINT IF EXISTS report_run_period_type_period_start_period_end_revision_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_report_run_calendar_revision ON report_run(period_type, period_start, period_end, timezone, revision);
INSERT INTO runtime_configuration(namespace, document) VALUES ('general', '{"timezone":"Asia/Shanghai","hourCycle":"24","dateFormat":"YYYY-MM-DD"}'::JSONB) ON CONFLICT(namespace) DO NOTHING;

-- Lightweight instance metadata; aggregation queries reuse existing indexes.
CREATE TABLE IF NOT EXISTS statistics_instance (
    instance_id TEXT PRIMARY KEY,
    status JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Derived receipt state. Receipt identities/checksums remain authoritative.
CREATE TABLE IF NOT EXISTS scan_upload_stream (
    execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
    upload_id VARCHAR(36) NOT NULL,
    batch_count BIGINT NOT NULL DEFAULT 0,
    confirmed_count BIGINT NOT NULL DEFAULT 0,
    pending_count BIGINT NOT NULL DEFAULT 0,
    first_batch INT,
    last_batch INT,
    final_count BIGINT NOT NULL DEFAULT 0,
    final_batch INT,
    confirmed_observations BIGINT NOT NULL DEFAULT 0,
    dirty BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (execution_id, upload_id)
);

-- Serialize installation/backfill with receipt writers, including older instances.
LOCK TABLE scan_result_batch IN SHARE ROW EXCLUSIVE MODE;
CREATE OR REPLACE FUNCTION maintain_scan_upload_stream() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- Administrative receipt removal is rare. Rebuild once on the next upload,
        -- instead of rescanning remaining receipts on every cascading deletion.
        UPDATE scan_upload_stream SET dirty = TRUE
        WHERE execution_id = OLD.execution_id AND upload_id = OLD.upload_id;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF (NEW.execution_id, NEW.upload_id, NEW.batch_index, NEW.is_final, NEW.observation_count)
            IS DISTINCT FROM
           (OLD.execution_id, OLD.upload_id, OLD.batch_index, OLD.is_final, OLD.observation_count) THEN
            RAISE EXCEPTION 'scan receipt identity and counts are immutable';
        END IF;
        IF NEW.storage_backend IS DISTINCT FROM OLD.storage_backend THEN
            UPDATE scan_upload_stream SET
                confirmed_count = confirmed_count + (NEW.storage_backend <> 'pending')::INT - (OLD.storage_backend <> 'pending')::INT,
                pending_count = pending_count + (NEW.storage_backend = 'pending')::INT - (OLD.storage_backend = 'pending')::INT,
                confirmed_observations = confirmed_observations +
                    ((NEW.storage_backend <> 'pending')::INT - (OLD.storage_backend <> 'pending')::INT)::BIGINT * NEW.observation_count
            WHERE execution_id = NEW.execution_id AND upload_id = NEW.upload_id;
        END IF;
        RETURN NEW;
    END IF;
    INSERT INTO scan_upload_stream AS s
        (execution_id, upload_id, batch_count, confirmed_count, pending_count,
         first_batch, last_batch, final_count, final_batch, confirmed_observations)
    VALUES (NEW.execution_id, NEW.upload_id, 1, (NEW.storage_backend <> 'pending')::INT,
            (NEW.storage_backend = 'pending')::INT, NEW.batch_index, NEW.batch_index,
            NEW.is_final::INT, CASE WHEN NEW.is_final THEN NEW.batch_index END,
            CASE WHEN NEW.storage_backend <> 'pending' THEN NEW.observation_count ELSE 0 END)
    ON CONFLICT (execution_id, upload_id) DO UPDATE SET
        batch_count = s.batch_count + 1,
        confirmed_count = s.confirmed_count + EXCLUDED.confirmed_count,
        pending_count = s.pending_count + EXCLUDED.pending_count,
        first_batch = LEAST(s.first_batch, EXCLUDED.first_batch),
        last_batch = GREATEST(s.last_batch, EXCLUDED.last_batch),
        final_count = s.final_count + EXCLUDED.final_count,
        final_batch = LEAST(s.final_batch, EXCLUDED.final_batch),
        confirmed_observations = s.confirmed_observations + EXCLUDED.confirmed_observations;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS scan_upload_stream_receipt ON scan_result_batch;
CREATE TRIGGER scan_upload_stream_receipt
AFTER INSERT OR DELETE OR UPDATE OF execution_id, upload_id, batch_index, is_final, observation_count, storage_backend
ON scan_result_batch FOR EACH ROW EXECUTE FUNCTION maintain_scan_upload_stream();

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM scan_storage_state WHERE state_key = 'upload_stream_schema_v1') THEN
        INSERT INTO scan_upload_stream
            (execution_id, upload_id, batch_count, confirmed_count, pending_count, first_batch,
             last_batch, final_count, final_batch, confirmed_observations)
        SELECT execution_id, upload_id, COUNT(*), COUNT(*) FILTER (WHERE storage_backend <> 'pending'),
               COUNT(*) FILTER (WHERE storage_backend = 'pending'), MIN(batch_index), MAX(batch_index),
               COUNT(*) FILTER (WHERE is_final), MIN(batch_index) FILTER (WHERE is_final),
               COALESCE(SUM(observation_count) FILTER (WHERE storage_backend <> 'pending'), 0)
        FROM scan_result_batch GROUP BY execution_id, upload_id
        ON CONFLICT (execution_id, upload_id) DO NOTHING;
        INSERT INTO scan_storage_state(state_key, state_value)
        VALUES ('upload_stream_schema_v1', '{"version":1}'::JSONB);
    END IF;
END $$;

-- Keep canonical search keys and expose a typed, indexable containment operand.
ALTER TABLE search_target_state ADD COLUMN IF NOT EXISTS target_ip INET
    GENERATED ALWAYS AS (CASE WHEN target_kind = 'ip' THEN target_key::INET ELSE NULL END) STORED;
CREATE INDEX IF NOT EXISTS idx_search_target_ip_gist
    ON search_target_state USING GIST (target_ip inet_ops) WHERE target_kind = 'ip';

-- Intelligent scan placement and refresh state.
-- Additive, repeatable migration. Routing preferences never replace execution leases.
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS performance JSONB;
ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS routing_decision JSONB;
ALTER TABLE scan_task ADD COLUMN IF NOT EXISTS task_group_id UUID;
CREATE INDEX IF NOT EXISTS idx_scan_task_group ON scan_task(task_group_id) WHERE task_group_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS scan_task_routing (
    task_id INT PRIMARY KEY REFERENCES scan_task(id) ON DELETE CASCADE,
    preferred_scanner_id TEXT,
    prefer_until BIGINT NOT NULL DEFAULT 0,
    decision JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scan_task_routing_preference ON scan_task_routing(preferred_scanner_id, prefer_until);

CREATE TABLE IF NOT EXISTS scanner_target_feedback (
    scanner_id TEXT NOT NULL,
    owner_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_key TEXT NOT NULL,
    successes INT NOT NULL DEFAULT 0,
    route_failures INT NOT NULL DEFAULT 0,
    elapsed_ms DOUBLE PRECISION,
    connect_ms DOUBLE PRECISION,
    connect_samples INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY(scanner_id, owner_id, target_key)
);
CREATE INDEX IF NOT EXISTS idx_scanner_feedback_target ON scanner_target_feedback(owner_id, target_key, updated_at);
CREATE TABLE IF NOT EXISTS scan_routing_outcome (
    execution_id INT NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
    attempt_no INT NOT NULL,
    PRIMARY KEY(execution_id, attempt_no)
);

CREATE TABLE IF NOT EXISTS automatic_target_history (
    generation_key TEXT NOT NULL,
    plan_key TEXT NOT NULL,
    address_family TEXT NOT NULL,
    target TEXT NOT NULL,
    last_success_at BIGINT,
    last_attempt_at BIGINT,
    failure_count INT NOT NULL DEFAULT 0,
    next_attempt_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY(generation_key, plan_key)
);
CREATE INDEX IF NOT EXISTS idx_automatic_history_due ON automatic_target_history(address_family, next_attempt_at, last_success_at);

CREATE TABLE IF NOT EXISTS automatic_target_outcome (task_id INT PRIMARY KEY REFERENCES scan_task(id) ON DELETE CASCADE);

ALTER TABLE scan_task_execution ADD COLUMN IF NOT EXISTS asset_signature BIT(256);
ALTER TABLE automatic_target_history ADD COLUMN IF NOT EXISTS last_asset_signature TEXT;
ALTER TABLE automatic_target_history ADD COLUMN IF NOT EXISTS next_refresh_at BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_scanner_feedback_expiry ON scanner_target_feedback(updated_at);

ALTER TABLE automatic_target_history ADD COLUMN IF NOT EXISTS change_detected BOOLEAN NOT NULL DEFAULT FALSE;

-- Same set semantics as routing::target_key: order, duplicates, overlapping and
-- adjacent ranges do not change a plan. Skip invalid legacy port tokens safely.
CREATE OR REPLACE FUNCTION scan_port_set(ports TEXT) RETURNS INT4MULTIRANGE
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    token TEXT;
    parts TEXT[];
    low_port INT;
    high_port INT;
    result INT4MULTIRANGE := '{}';
BEGIN
    FOREACH token IN ARRAY string_to_array(ports, ',') LOOP
        parts := regexp_match(btrim(token), '^([0-9]+)(-([0-9]+))?$');
        IF parts IS NULL THEN CONTINUE; END IF;
        parts[1] := COALESCE(NULLIF(ltrim(parts[1], '0'), ''), '0');
        parts[3] := COALESCE(NULLIF(ltrim(COALESCE(parts[3], parts[1]), '0'), ''), '0');
        IF length(parts[1]) > 5 OR length(parts[3]) > 5 THEN CONTINUE; END IF;
        low_port := parts[1]::INT;
        high_port := parts[3]::INT;
        IF low_port > high_port OR high_port > 65535 THEN CONTINUE; END IF;
        result := result + int4multirange(int4range(low_port, high_port + 1, '[)'));
    END LOOP;
    RETURN result;
END;
$$;
CREATE INDEX IF NOT EXISTS idx_scan_task_active_plan
    ON scan_task(generation_key, scan_profile, scan_port_set(task_port))
    WHERE generation_key IS NOT NULL AND task_status IN ('pending', 'running');

-- Administrator notification channels and durable delivery.
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

-- Derived work only; raw scan observations and upload receipts are unchanged.
CREATE TABLE IF NOT EXISTS os_detection_outbox (
    execution_id INTEGER NOT NULL REFERENCES scan_task_execution(id) ON DELETE CASCADE,
    ruleset_revision BIGINT NOT NULL CHECK (ruleset_revision > 0),
    attempts INTEGER NOT NULL DEFAULT 0,
    available_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    claim_token UUID,
    lease_expires_at TIMESTAMPTZ,
    cursor JSONB,
    processed_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (execution_id, ruleset_revision)
);
CREATE INDEX IF NOT EXISTS os_detection_outbox_pending_idx
    ON os_detection_outbox (ruleset_revision, available_at, execution_id)
    WHERE processed_at IS NULL;

CREATE TABLE IF NOT EXISTS os_detection_backfill (
    ruleset_revision BIGINT PRIMARY KEY CHECK (ruleset_revision > 0),
    last_execution_id INTEGER NOT NULL DEFAULT 0 CHECK (last_execution_id >= 0)
);

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
