#!/usr/bin/env python3
"""Smoke-test the image loaded from the verified OCI archive, using disposable containers."""
import base64
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

PG_IMAGE = 'postgres:18.6-bookworm@sha256:afc7e2d441324c0388fa80c3d24f733b4194a4eb7f47dd8ee2b08eb1a24a647c'
ES_IMAGE = 'docker.elastic.co/elasticsearch/elasticsearch:9.5.0@sha256:8818ab9af72d7482e38a9d6f0454d5ee667564a25bbdc42360c0f9b8f8f72fc5'


def command(*args, check=True, input=None):
    return subprocess.run(args, input=input, text=True, check=check, capture_output=True, timeout=120)


def docker(*args, **kwargs):
    return command('docker', *args, **kwargs)


def wait_until(probe, message, attempts=90):
    for _ in range(attempts):
        if probe():
            return
        time.sleep(2)
    raise RuntimeError(message)


def elasticsearch_ready(container):
    result = docker('exec', container, 'curl', '--fail', '--silent', '--show-error',
                    '--max-time', '5',
                    'http://localhost:9200/_cluster/health?wait_for_status=yellow&'
                    'wait_for_no_initializing_shards=true&timeout=1s', check=False)
    if result.returncode != 0:
        return False
    try:
        health = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return (isinstance(health, dict) and health.get('timed_out') is False
            and health.get('status') in ('green', 'yellow'))


def main():
    image, metadata_path = sys.argv[1:]
    metadata = json.loads(Path(metadata_path).read_text())
    config = json.loads(docker('image', 'inspect', image).stdout)[0]
    assert config['Id'] == metadata['config_digest'], 'Loaded image differs from tested OCI config'
    assert config['Architecture'] == metadata['architecture']
    version = docker('run', '--rm', image, '--version').stdout
    assert metadata['version'] in version
    namespace = 'nm-smoke-'+uuid.uuid4().hex[:12]
    containers = []
    network_created = False

    def start(name, image_name, *options):
        containers.append(name)
        docker('run', '-d', '--name', name, '--network', namespace, *options, image_name)

    try:
        docker('network', 'create', '--internal', namespace)
        network_created = True
        es_name = namespace+'-es'
        # Build caches and OCI exports can push the runner above ES disk watermarks.
        # Only disposable smoke-test data uses this bounded, separate filesystem.
        start(es_name, ES_IMAGE, '--network-alias', 'elasticsearch', '-e', 'discovery.type=single-node',
              '-e', 'xpack.security.enabled=false', '-e', 'ES_JAVA_OPTS=-Xms512m -Xmx512m',
              '--tmpfs', '/usr/share/elasticsearch/data:rw,uid=1000,gid=0,mode=0770,size=1g')
        wait_until(lambda: elasticsearch_ready(es_name), 'Elasticsearch did not become ready')

        if metadata['component'] == 'scanner':
            # Version/help validation does not require raw-network privileges.
            masscan = docker('run', '--rm', '--entrypoint', 'masscan', image, '--version', check=False)
            assert '1.3.2' in masscan.stdout+masscan.stderr
            nuclei = docker('run', '--rm', '--entrypoint', 'nuclei', image, '-version')
            assert '3.11.1' in nuclei.stdout+nuclei.stderr
            target_network = json.loads(docker('inspect', es_name).stdout)[0]['NetworkSettings']['Networks'][namespace]
            target = target_network['IPAddress']
            target_mac = target_network['MacAddress']
            # A single authorized container endpoint, never an external network.
            result = docker('run', '--rm', '--network', namespace, '--cap-drop', 'ALL', '--cap-add', 'NET_RAW',
                            '--entrypoint', 'masscan', image, target, '-p9200', '--rate', '10',
                            '--interface', 'eth0', '--router-mac', target_mac,
                            '--output-format', 'list', '--output-filename', '-', '--nointeractive',
                            '--open-only', '--wait', '2')
            assert f'open tcp 9200 {target} ' in result.stdout, 'Raw scan did not find the controlled endpoint'
            http = docker('run', '--rm', '-i', '--network', namespace, '--entrypoint', 'zgrab2', image,
                          '--blocklist-file', '/dev/null', '--senders', '1',
                          'http', '--port', '9200', '--connect-timeout', '5s', '--target-timeout', '10s', input=target+'\n')
            records = [json.loads(line) for line in http.stdout.splitlines() if line.strip()]
            assert any(r.get('data', {}).get('http', {}).get('status') == 'success' for r in records), 'zgrab2 HTTP handshake failed'
            print('Scanner tool versions, raw-socket scan and HTTP handshake passed on an isolated container endpoint.')
            return

        with tempfile.TemporaryDirectory(prefix='nm-docker-smoke-') as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            tls = directory/'tls'
            tls.mkdir(mode=0o755)
            command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                    '-keyout', str(tls/'key.pem'), '-out', str(tls/'cert.pem'))
            (tls/'ca.pem').write_bytes((tls/'cert.pem').read_bytes())
            for file in tls.iterdir():
                file.chmod(0o644)  # Only disposable CI certificates, removed on exit.
            password = secrets.token_hex(24)
            content = Path('docker/config.example.toml').read_text()
            content = content.replace('encrypt_key = ""', f'encrypt_key = "{base64.b64encode(secrets.token_bytes(32)).decode()}"')
            content = content.replace('scanner_token_pepper = ""', f'scanner_token_pepper = "{secrets.token_hex(32)}"')
            content = content.replace('password = ""', f'password = "{password}"')
            (directory/'config.toml').write_text(content)
            (directory/'config.toml').chmod(0o644)
            pg_name = namespace+'-pg'
            start(pg_name, PG_IMAGE, '--network-alias', 'postgres', '-e', 'POSTGRES_USER=network_mapping',
                  '-e', 'POSTGRES_DB=network_mapping', '-e', 'POSTGRES_PASSWORD='+password)
            wait_until(lambda: docker('exec', pg_name, 'pg_isready', '-U', 'network_mapping',
                                      '-d', 'network_mapping', check=False).returncode == 0, 'PostgreSQL did not become ready')
            server = namespace+'-server'
            start(server, image, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                  '-e', 'SERVER_TLS_NAME=localhost', '--mount', f'type=bind,src={directory},dst=/etc/network-mapping,readonly',
                  '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
                  '--tmpfs', '/var/lib/network-mapping:rw,uid=10001,gid=10001,mode=0700',
                  '--tmpfs', '/var/log/network-mapping:rw,uid=10001,gid=10001,mode=0700')

            def request(path):
                return docker('exec', server, 'curl', '--silent', '--show-error', '--cacert',
                              '/etc/network-mapping/tls/ca.pem', '--resolve', 'localhost:9999:127.0.0.1',
                              '--output', '/dev/null', '--write-out', '%{http_code}', 'https://localhost:9999'+path,
                              check=False)

            wait_until(lambda: request('/login').stdout == '200', 'HTTPS login did not become ready')
            assert request('/this-route-does-not-exist').stdout == '404'
            assert request('/assets/this-file-does-not-exist.js').stdout == '404'
            page = docker('exec', server, 'curl', '--fail', '--silent', '--cacert',
                          '/etc/network-mapping/tls/ca.pem', 'https://localhost:9999/login').stdout
            assets = re.findall(r'(?:src|href)="(/assets/[^"?#]+)', page)
            assert assets, 'Frontend assets were not referenced by the login page'
            for asset in assets:
                assert request(asset).stdout == '200', 'Missing frontend asset: '+asset
            docker('stop', '--time', '60', server)
            assert json.loads(docker('inspect', server).stdout)[0]['State']['ExitCode'] == 0
            docker('start', server)
            wait_until(lambda: request('/login').stdout == '200', 'Server did not recover after restart')
            print('Server initialization, verified HTTPS, frontend assets, 404s and database-preserving restart passed.')
    except Exception:
        for name in containers:
            logs = docker('logs', '--tail', '50', name, check=False)
            print(name, logs.stdout, logs.stderr, file=sys.stderr)
        raise
    finally:
        for name in reversed(containers):
            docker('rm', '--force', '--volumes', name, check=False)
        if network_created:
            docker('network', 'rm', namespace, check=False)


if __name__ == '__main__':
    main()
