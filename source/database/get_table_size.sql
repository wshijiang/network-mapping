SELECT
    CASE
        WHEN stats.schemaname = current_schema() THEN stats.relname
        ELSE stats.schemaname || '.' || stats.relname
    END AS table_name,
    pg_total_relation_size(stats.relid) AS total_size,
    pg_relation_size(stats.relid) AS data_size,
    pg_indexes_size(stats.relid) AS index_size
FROM pg_catalog.pg_statio_user_tables AS stats
JOIN pg_catalog.pg_class AS relation ON relation.oid = stats.relid
WHERE relation.relpersistence <> 't'
ORDER BY stats.schemaname, stats.relname;
