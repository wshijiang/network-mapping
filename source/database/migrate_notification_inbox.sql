-- 站内通知收件箱：快照列独立于 notification_event 的 30 天清理，保留期由管理员配置。
CREATE TABLE IF NOT EXISTS notification_inbox (
    id UUID PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_id UUID REFERENCES notification_event(id) ON DELETE SET NULL,
    category TEXT NOT NULL CHECK (category IN ('task', 'monitor', 'alert', 'security', 'report')),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    link TEXT,
    read_at TIMESTAMPTZ,
    dismissed_at TIMESTAMPTZ,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, event_id)
);
CREATE INDEX IF NOT EXISTS idx_notification_inbox_list
    ON notification_inbox(user_id, id DESC) WHERE dismissed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_notification_inbox_unread
    ON notification_inbox(user_id, category) WHERE read_at IS NULL AND dismissed_at IS NULL;

-- 个人接收偏好：缺行 = 默认开启。
CREATE TABLE IF NOT EXISTS notification_user_preference (
    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (category IN ('task', 'monitor', 'alert', 'security', 'report')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, category)
);
