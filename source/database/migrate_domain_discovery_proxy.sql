-- Outbound transport for crt.sh. Proxy credentials never enter the public JSON.
CREATE TABLE IF NOT EXISTS domain_discovery_settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    proxy_mode TEXT NOT NULL DEFAULT 'system' CHECK(proxy_mode IN ('system','direct','custom')),
    proxy_endpoint TEXT NOT NULL DEFAULT '',
    proxy_ciphertext BYTEA,
    revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO domain_discovery_settings (singleton) VALUES (TRUE) ON CONFLICT (singleton) DO NOTHING;