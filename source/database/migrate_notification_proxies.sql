-- Proxy credentials never enter the public settings JSON.
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS proxy_mode TEXT NOT NULL DEFAULT 'system' CHECK(proxy_mode IN ('system','direct','custom'));
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS proxy_ciphertext BYTEA;
ALTER TABLE notification_channel ADD COLUMN IF NOT EXISTS proxy_endpoint TEXT NOT NULL DEFAULT '';
