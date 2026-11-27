#!/usr/bin/env python3
"""Compare the reported SQL shape, branch baseline and working tree in a disposable PG schema.

Requires psql and an explicitly supplied disposable database. No production data.
Each measured UPDATE runs in BEGIN/ROLLBACK. Creates/drops only its UUID schema.
"""
import argparse
import json
from pathlib import Path
import statistics
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'src/target_generated/search.rs'


def query_source(source):
    return source.split('const RECORD_SUCCESS_SQL: &str = r#"', 1)[1].split('"#;', 1)[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database-url', required=True)
    parser.add_argument('--baseline-ref', default='e722aae', help='immutable pre-change server commit')
    parser.add_argument('--rows', type=int, default=100000)
    parser.add_argument('--samples', type=int, default=9)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.rows < 65536 or args.samples < 3:
        parser.error('use at least 65536 rows and 3 samples')
    schema = 'freshness_bench_' + uuid.uuid4().hex

    def sql(statement, scoped=True):
        prefix = f'SET search_path TO {schema}, public; ' if scoped else ''
        result = subprocess.run(['psql', args.database_url, '-X', '-qAt', '-v', 'ON_ERROR_STOP=1'],
                                input=prefix + statement, text=True, capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return result.stdout.strip()

    head = subprocess.check_output(['git', 'show', f'{args.baseline_ref}:{SOURCE}'], cwd=ROOT, text=True)
    before = query_source(head)
    after = query_source((ROOT / SOURCE).read_text())
    # Reconstruct the supplied alert's old completed CTE; matched/candidates
    # remain identical, with literals instead of pg_stat_statements placeholders.
    legacy = '''WITH completed AS MATERIALIZED (
        SELECT t.user_id,t.task_kind,t.task_target,t.dns_targets,t.generation_metadata,
        GREATEST(e.task_end_time,(SELECT MAX(c.task_end_time) FROM scan_task_lineage l
          JOIN scan_task_execution c ON c.task_id=l.child_task_id WHERE l.parent_execution_id=e.id)) AS ended_at,
        jsonb_build_object('profile',CASE WHEN t.task_kind='dns'
          THEN t.generation_metadata->'dns_follow_up'->>'scan_profile' ELSE t.scan_profile END,
          'ports',t.task_port) AS plan
        FROM scan_task t JOIN scan_task_execution e ON e.task_id=t.id
        WHERE (t.id=$1 OR t.id IN (SELECT parent_task_id FROM scan_task_lineage WHERE child_task_id=$1))
          AND e.execution_status='succeeded' AND e.task_end_time IS NOT NULL
          AND NOT EXISTS(SELECT 1 FROM scan_task_lineage l JOIN scan_task_execution child ON child.task_id=l.child_task_id
            WHERE l.parent_execution_id=e.id AND child.execution_status<>'succeeded')
        ), matched AS (''' + before.split('), matched AS (', 1)[1]
    result = {'environment': {}, 'rows': args.rows, 'samples': args.samples,
              'baseline_commit': subprocess.check_output(['git', 'rev-parse', args.baseline_ref], cwd=ROOT, text=True).strip(),
              'limitations': ['Synthetic fixture, local PostgreSQL, no production traffic or concurrency.',
                              'First sample is not an OS cold-cache test; warm medians exclude it.',
                              'Rolled-back updates still generate WAL; VACUUM between samples removes aborted tuples.'], 'cases': {}}
    try:
        sql(f'CREATE SCHEMA {schema}', False)
        sql('BEGIN;\n' + (ROOT / 'source/database/init.sql').read_text() + '\nCOMMIT;')
        sql(f"""INSERT INTO users(id,username,password,role) VALUES(1,'benchmark','unused',2);
            INSERT INTO scan_task(id,user_id,task_id,task_initiator,task_target)
              SELECT n,1,'bench-'||n,'benchmark',ARRAY['198.51.100.1'::inet] FROM generate_series(1,{args.rows}) n;
            INSERT INTO scan_task_execution(execution_id,task_id,execution_status,task_end_time)
              SELECT 'execution-'||n,n,'succeeded',1000 FROM generate_series(1,{args.rows}) n;
            INSERT INTO search_target_state(owner_id,target_kind,target_key)
              SELECT 1,'ip',host('10.0.0.0'::inet+n) FROM generate_series(0,{args.rows-1}) n;
            ANALYZE;""")
        result['environment'] = {'postgresql': sql('SELECT version()'),
                                 'shared_buffers': sql('SHOW shared_buffers'), 'jit': sql('SHOW jit')}
        variants = {'alert_shape': legacy, 'branch_base': before, 'optimized': after}
        for case, target, replay in [('no_match', '198.51.100.1', False),
                                     ('cidr_24', '10.0.1.0/24', False),
                                     ('cidr_16_replay', '10.0.0.0/16', True)]:
            sql(f"UPDATE scan_task SET task_target=ARRAY['{target}'::inet] WHERE id=1;")
            sql('UPDATE search_target_state SET last_success_at=NULL,last_success_plan=NULL;')
            if replay:
                sql(after.replace('$1', '1'))
            sql('VACUUM ANALYZE search_target_state;')
            result['cases'][case] = {}
            for name, statement in variants.items():
                # Separate session per variant; one first sample, then warm samples.
                program = 'SET plan_cache_mode=force_custom_plan; PREPARE bench(int) AS ' + statement + ';\n'
                program += ('BEGIN; EXPLAIN (ANALYZE,BUFFERS,WAL,FORMAT JSON) EXECUTE bench(1); ROLLBACK; VACUUM search_target_state;\n' * (args.samples + 1))
                raw = sql(program)
                plans = []
                decoder = json.JSONDecoder()
                while raw.strip():
                    obj, end = decoder.raw_decode(raw.lstrip())
                    plans.append(obj[0])
                    raw = raw.lstrip()[end:]
                times = [p['Execution Time'] for p in plans]
                last = plans[-1]['Plan']
                result['cases'][case][name] = {
                    'first_ms': times[0], 'warm_median_ms': statistics.median(times[1:]),
                    'warm_min_ms': min(times[1:]), 'warm_max_ms': max(times[1:]),
                    'shared_hit_blocks': last.get('Shared Hit Blocks', 0),
                    'shared_read_blocks': last.get('Shared Read Blocks', 0),
                    'shared_dirtied_blocks': last.get('Shared Dirtied Blocks', 0),
                    'wal_bytes': last.get('WAL Bytes', 0), 'last_plan': plans[-1]}
                print(case, name, result['cases'][case][name]['warm_median_ms'], flush=True)
        args.output.write_text(json.dumps(result, indent=2) + '\n')
    finally:
        sql(f'DROP SCHEMA IF EXISTS {schema} CASCADE', False)


if __name__ == '__main__':
    main()
