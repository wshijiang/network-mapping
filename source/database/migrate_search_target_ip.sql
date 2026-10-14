-- Keep canonical search keys and expose a typed, indexable containment operand.
ALTER TABLE search_target_state ADD COLUMN IF NOT EXISTS target_ip INET
    GENERATED ALWAYS AS (CASE WHEN target_kind = 'ip' THEN target_key::INET ELSE NULL END) STORED;
CREATE INDEX IF NOT EXISTS idx_search_target_ip_gist
    ON search_target_state USING GIST (target_ip inet_ops) WHERE target_kind = 'ip';
