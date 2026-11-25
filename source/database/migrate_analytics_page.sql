-- Page projections are switched together when the refresh transaction commits.
CREATE TABLE IF NOT EXISTS analytics_page_publication (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    revision BIGINT NOT NULL,
    timezone TEXT NOT NULL,
    calendar_day DATE NOT NULL,
    data_as_of TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS analytics_page_dirty (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_instant TIMESTAMPTZ,
    last_instant TIMESTAMPTZ,
    first_legacy_day DATE,
    last_legacy_day DATE,
    destructive BOOLEAN NOT NULL,
    rebuild BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_analytics_page_dirty_destructive
    ON analytics_page_dirty (id) WHERE destructive;

CREATE TABLE IF NOT EXISTS analytics_page_heat_day (
    day DATE NOT NULL,
    scope JSONB NOT NULL,
    count BIGINT NOT NULL,
    PRIMARY KEY (scope, day)
);
CREATE INDEX IF NOT EXISTS idx_analytics_page_heat_day ON analytics_page_heat_day (day);

CREATE TABLE IF NOT EXISTS analytics_page_legacy_day (
    day DATE NOT NULL,
    scope JSONB NOT NULL,
    PRIMARY KEY (scope, day)
);
CREATE INDEX IF NOT EXISTS idx_analytics_page_legacy_day ON analytics_page_legacy_day (day);

CREATE TABLE IF NOT EXISTS analytics_page_distribution_day (
    day DATE NOT NULL,
    scope JSONB NOT NULL,
    dimension TEXT NOT NULL,
    label TEXT NOT NULL,
    count BIGINT NOT NULL,
    PRIMARY KEY (day, scope, dimension, label)
);

CREATE TABLE IF NOT EXISTS analytics_page_distribution_window (
    window_start DATE NOT NULL,
    window_end DATE NOT NULL,
    scope JSONB NOT NULL,
    dimension TEXT NOT NULL,
    total BIGINT NOT NULL,
    items JSONB NOT NULL,
    PRIMARY KEY (window_start, window_end, scope, dimension)
);

-- Statement transition tables include cascaded deletes and avoid a trigger write per fact.
-- Use append-only events so a new fact transaction can commit during a projection rebuild.
CREATE OR REPLACE FUNCTION analytics_page_mark_facts() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE
    facts TEXT;
    instant TEXT;
    legacy TEXT;
    rollup_mode TEXT;
BEGIN
    -- Serialize an off-to-active change with facts committing at the same time.
    SELECT document->>'page_rollups' INTO rollup_mode
    FROM runtime_configuration WHERE namespace = 'analytics_snapshot' FOR SHARE;
    IF COALESCE(rollup_mode, 'off') NOT IN ('build', 'read') THEN
        RETURN NULL;
    END IF;
    IF TG_OP = 'TRUNCATE' THEN
        INSERT INTO analytics_page_dirty (destructive, rebuild) VALUES (TRUE, TRUE);
        RETURN NULL;
    END IF;
    facts := CASE TG_OP WHEN 'DELETE' THEN 'old_facts' ELSE 'new_facts' END;
    instant := CASE TG_ARGV[0] WHEN 'discovery' THEN 'first_observed_at' ELSE 'bucket_start' END;
    legacy := CASE TG_ARGV[0] WHEN 'discovery' THEN
        'min(day_start) FILTER (WHERE first_observed_at IS NULL), max(day_start) FILTER (WHERE first_observed_at IS NULL)'
        ELSE 'NULL::DATE, NULL::DATE' END;
    EXECUTE format(
        'INSERT INTO analytics_page_dirty(first_instant, last_instant, first_legacy_day, last_legacy_day, destructive)
          SELECT min(%1$s), max(%1$s), %2$s, $1 FROM %3$s HAVING count(*) > 0',
        instant, legacy, facts
    ) USING TG_OP <> 'INSERT';
    IF TG_OP = 'UPDATE' THEN
        EXECUTE format(
            'INSERT INTO analytics_page_dirty(first_instant, last_instant, first_legacy_day, last_legacy_day, destructive)
              SELECT min(%1$s), max(%1$s), %2$s, TRUE FROM old_facts HAVING count(*) > 0',
            instant, legacy
        );
    END IF;
    RETURN NULL;
END;
$$;

DO $$
DECLARE
    fact_table TEXT;
    kind TEXT;
BEGIN
    FOREACH fact_table IN ARRAY ARRAY['analytics_discovery_fact', 'analytics_distribution_30m'] LOOP
        kind := CASE fact_table WHEN 'analytics_discovery_fact' THEN 'discovery' ELSE 'distribution' END;
        EXECUTE format('CREATE OR REPLACE TRIGGER analytics_page_insert AFTER INSERT ON %I
            REFERENCING NEW TABLE AS new_facts FOR EACH STATEMENT EXECUTE FUNCTION analytics_page_mark_facts(%L)', fact_table, kind);
        EXECUTE format('CREATE OR REPLACE TRIGGER analytics_page_delete AFTER DELETE ON %I
            REFERENCING OLD TABLE AS old_facts FOR EACH STATEMENT EXECUTE FUNCTION analytics_page_mark_facts(%L)', fact_table, kind);
        EXECUTE format('CREATE OR REPLACE TRIGGER analytics_page_update AFTER UPDATE ON %I
            REFERENCING OLD TABLE AS old_facts NEW TABLE AS new_facts FOR EACH STATEMENT EXECUTE FUNCTION analytics_page_mark_facts(%L)', fact_table, kind);
        EXECUTE format('CREATE OR REPLACE TRIGGER analytics_page_truncate AFTER TRUNCATE ON %I
            FOR EACH STATEMENT EXECUTE FUNCTION analytics_page_mark_facts(%L)', fact_table, kind);
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION analytics_page_mark_enabled() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.document->>'page_rollups' IN ('build', 'read') THEN
        RETURN NULL;
    END IF;
    INSERT INTO analytics_page_dirty (destructive, rebuild) VALUES (TRUE, TRUE);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE TRIGGER analytics_page_enabled AFTER INSERT OR UPDATE ON runtime_configuration
    FOR EACH ROW WHEN (NEW.namespace = 'analytics_snapshot' AND NEW.document->>'page_rollups' IN ('build', 'read'))
    EXECUTE FUNCTION analytics_page_mark_enabled();

CREATE OR REPLACE FUNCTION analytics_page_refresh_day(
    local_day DATE, starts_at TIMESTAMPTZ, ends_at TIMESTAMPTZ, calendar_zone TEXT
) RETURNS VOID LANGUAGE SQL AS $$
    DELETE FROM analytics_page_heat_day WHERE day = local_day;
    INSERT INTO analytics_page_heat_day (day, scope, count)
    SELECT local_day, jsonb_build_array(owner_id, scanner_id, task_source), count(DISTINCT ip_address)
    FROM (
        SELECT owner_id, scanner_id, task_source, ip_address FROM analytics_discovery_fact
        WHERE first_observed_at >= starts_at AND first_observed_at < ends_at
        UNION ALL
        SELECT owner_id, scanner_id, task_source, ip_address FROM analytics_discovery_fact
        WHERE first_observed_at IS NULL AND day_start = local_day AND calendar_zone = 'Asia/Shanghai'
    ) facts
    GROUP BY CUBE(owner_id, scanner_id, task_source)
    HAVING count(*) > 0;

    DELETE FROM analytics_page_distribution_day WHERE day = local_day;
    INSERT INTO analytics_page_distribution_day (day, scope, dimension, label, count)
    SELECT local_day, jsonb_build_array(owner_id, scanner_id, task_source), dimension, label, sum(endpoint_count)::BIGINT
    FROM analytics_distribution_30m WHERE bucket_start >= starts_at AND bucket_start < ends_at
    GROUP BY dimension, label, CUBE(owner_id, scanner_id, task_source);
$$;

CREATE OR REPLACE FUNCTION analytics_page_refresh_legacy_day(local_day DATE)
RETURNS VOID LANGUAGE SQL AS $$
    DELETE FROM analytics_page_legacy_day WHERE day = local_day;
    INSERT INTO analytics_page_legacy_day (day, scope)
    SELECT local_day, jsonb_build_array(owner_id, scanner_id, task_source)
    FROM analytics_discovery_fact WHERE first_observed_at IS NULL AND day_start = local_day
    GROUP BY CUBE(owner_id, scanner_id, task_source)
    HAVING count(*) > 0;
$$;

CREATE OR REPLACE FUNCTION analytics_page_refresh_window(first_day DATE, end_day DATE)
RETURNS VOID LANGUAGE SQL AS $$
    DELETE FROM analytics_page_distribution_window WHERE window_start = first_day AND window_end = end_day;
    INSERT INTO analytics_page_distribution_window (window_start, window_end, scope, dimension, total, items)
    WITH labels AS (
        SELECT scope, dimension, label, sum(count)::BIGINT AS count
        FROM analytics_page_distribution_day WHERE day >= first_day AND day < end_day
        GROUP BY scope, dimension, label
    ), ranked AS (
        SELECT *, row_number() OVER (PARTITION BY scope, dimension ORDER BY count DESC, label) AS rank
        FROM labels
    )
    SELECT first_day, end_day, scope, dimension, sum(count)::BIGINT,
           jsonb_agg(jsonb_build_object('label', label, 'count', count) ORDER BY rank) FILTER (WHERE rank <= 10)
    FROM ranked GROUP BY scope, dimension;
$$;
