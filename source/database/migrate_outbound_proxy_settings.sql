-- Shared outbound proxy settings. Credentials never enter public JSON.
CREATE TABLE IF NOT EXISTS outbound_proxy_settings (
    scope TEXT PRIMARY KEY,
    proxy_mode TEXT NOT NULL DEFAULT 'system' CHECK(proxy_mode IN ('system','direct','custom')),
    proxy_endpoint TEXT NOT NULL DEFAULT '',
    proxy_ciphertext BYTEA,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO outbound_proxy_settings (scope) VALUES ('global'), ('domain_discovery')
ON CONFLICT (scope) DO NOTHING;
-- The unreleased per-module table is superseded by the shared scoped table.
DROP TABLE IF EXISTS domain_discovery_settings;