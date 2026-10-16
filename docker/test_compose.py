"""Validate resolved deployment modes; never dump resolved deployment secrets."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('docker'), 'requires Docker Compose')
class ComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(['docker', 'compose', 'version'], capture_output=True)
        if result.returncode:
            raise unittest.SkipTest('Docker Compose unavailable')

    def config(self, host=False, extra=None, template=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            name = 'compose.host.example.yml' if host else 'compose.example.yml'
            env_name = '.env.host' if host else '.env'
            (directory / name).write_text((ROOT / 'docker' / name).read_text())
            values = dict(line.split('=', 1) for line in
                          (ROOT / 'docker' / (template or env_name + '.example')).read_text().splitlines()
                          if line and not line.startswith('#'))
            values.update(SERVER_IMAGE='example/server:test',
                          NM__SERVER__ENCRYPT_KEY='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
                          NM__SECURITY__SCANNER_TOKEN_PEPPER='fixture-pepper-at-least-32-characters',
                          NM__DATABASE__PASSWORD='fixture-password')
            values.update(extra or {})
            values.pop('SERVER_TLS_NAME', None)
            environment_file = directory / env_name
            environment_file.write_text(''.join(f'{k}={v}\n' for k, v in values.items()))
            environment_file.chmod(0o600)
            environment = {k: v for k, v in os.environ.items()
                           if not k.startswith(('NM__', 'SERVER_', 'COMPOSE_'))}
            result = subprocess.run(['docker', 'compose', '--env-file', str(environment_file),
                                     '-f', str(directory / name), 'config', '--format', 'json'],
                                    env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)['services']

    def test_standard_nat_defaults_keep_tls_and_map_host_gateway(self):
        services = self.config()
        server = services['server']
        self.assertEqual(server['environment']['NM__TLS__ENABLED'], 'true')
        self.assertEqual(server['environment']['SERVER_TLS_NAME'], 'localhost')
        self.assertIn('host.docker.internal=host-gateway', server['extra_hosts'])
        self.assertEqual(server['ports'][0]['host_ip'], '127.0.0.1')
        self.assertIn('postgres', services)

    def test_nat_host_postgres_keeps_only_the_requested_elasticsearch_profile(self):
        services = self.config(template='.env.host-db.example')
        self.assertNotIn('postgres', services)
        self.assertIn('elasticsearch', services)
        self.assertEqual(services['server']['environment']['NM__DATABASE__HOST'],
                         'host.docker.internal')

    def test_host_http_is_loopback_without_ports_certificates_or_local_databases(self):
        services = self.config(host=True)
        self.assertEqual(set(services), {'server'})
        server = services['server']
        self.assertEqual(server['network_mode'], 'host')
        self.assertNotIn('ports', server)
        self.assertNotIn('depends_on', server)
        self.assertEqual(server['environment']['NM__TLS__ENABLED'], 'false')
        self.assertEqual(server['environment']['NM__SERVER__HOST'], '127.0.0.1')
        self.assertEqual(server['environment']['NM__DATABASE__HOST'], '127.0.0.1')
        self.assertEqual(server['environment']['NM__ELASTICSEARCH__URL'], 'http://127.0.0.1:9200')
        self.assertNotIn('SERVER_TLS_NAME', server['environment'])
        self.assertFalse(any(v['target'].startswith('/etc/network-mapping/tls')
                             for v in server['volumes']))


if __name__ == '__main__':
    unittest.main()
