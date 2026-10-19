-- Shared domain task exclusions; literal rules are exact, *. rules cover descendants.
-- Match Rust str::trim Unicode White_Space, remove one root dot, fold ASCII case.
CREATE OR REPLACE FUNCTION dns_policy_name(value TEXT) RETURNS TEXT
LANGUAGE SQL IMMUTABLE AS $$
    SELECT lower(regexp_replace(btrim(value, E'\u0009\u000a\u000b\u000c\u000d \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000'), '\.$', ''));
$$;
CREATE OR REPLACE FUNCTION dns_domain_excluded(candidate TEXT) RETURNS BOOLEAN
LANGUAGE plpgsql STABLE AS $$
DECLARE
    rules JSONB;
    entry JSONB;
    pattern TEXT;
    base TEXT;
    name TEXT := dns_policy_name(candidate);
    matched BOOLEAN := FALSE;
BEGIN
    SELECT document->'excluded_domains' INTO rules FROM runtime_configuration WHERE namespace='dns_follow_up';
    IF rules IS NULL THEN RETURN FALSE; END IF;
    IF jsonb_typeof(rules)<>'array' OR jsonb_array_length(rules)>256 THEN RETURN TRUE; END IF;
    FOR entry IN SELECT value FROM jsonb_array_elements(rules) LOOP
        IF jsonb_typeof(entry)<>'string' THEN RETURN TRUE; END IF;
        pattern := dns_policy_name(entry #>> '{}');
        base := CASE WHEN left(pattern,2)='*.' THEN substr(pattern,3) ELSE pattern END;
        IF length(base)>253 OR base !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$' THEN RETURN TRUE; END IF;
        matched := matched OR name=pattern OR (left(pattern,2)='*.' AND right(name,length(base)+1)='.'||base);
    END LOOP;
    RETURN matched;
END;
$$;
CREATE OR REPLACE FUNCTION dns_scan_task_enabled(task scan_task) RETURNS BOOLEAN
LANGUAGE SQL STABLE AS $$
    SELECT NOT EXISTS (
        SELECT 1 FROM unnest(task.dns_targets) d WHERE dns_domain_excluded(d)
    ) AND NOT EXISTS (
        SELECT 1 FROM scan_task_lineage l JOIN scan_task p ON p.id=l.parent_task_id,
            LATERAL unnest(p.dns_targets) d
        WHERE l.child_task_id=task.id AND dns_domain_excluded(d)
    );
$$;

-- Preserve the old revision as evidence; an allowlist cannot be inverted safely.
WITH migrated AS (
    UPDATE runtime_configuration
    SET document=jsonb_set(document #- '{search_generation,authorized_domains}',
        '{search_generation,domain_enabled}', 'false'::jsonb), revision=revision+1, updated_at=NOW()
    WHERE namespace='automatic_target' AND document->'search_generation' ? 'authorized_domains'
    RETURNING namespace,revision,schema_version,document
)
INSERT INTO runtime_configuration_revision(namespace,revision,schema_version,document,change_reason)
SELECT namespace,revision,schema_version,document,'Domain allowlist retired; domain generation disabled' FROM migrated
ON CONFLICT DO NOTHING;
