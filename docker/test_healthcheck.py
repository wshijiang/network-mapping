"""Probe behavior, real HTTP/TLS, and certificate failures without a database."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / 'docker/healthcheck.sh'


class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == '/login' else 404)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def log_message(self, *args):
        pass


@contextmanager
def page_server(host='127.0.0.1', context=None):
    class Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6 if ':' in host else socket.AF_INET
    server = Server((host, 0), Page)
    if context:
        server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class HealthcheckTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.environment = {k: v for k, v in os.environ.items()
                            if not k.startswith(('NM__', 'SERVER_TLS_'))}
        # Local probes must work even with inherited outbound proxy settings.
        self.environment.update(HTTP_PROXY='http://127.0.0.1:1',
                                HTTPS_PROXY='http://127.0.0.1:1',
                                ALL_PROXY='http://127.0.0.1:1', NO_PROXY='')
        self.fake = self.path / 'curl'
        self.fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\nexit "${CURL_EXIT_CODE:-0}"\n')
        self.fake.chmod(0o755)

    def probe(self, values=None, args=(), fake=True):
        environment = dict(self.environment, **(values or {}))
        if fake:
            environment['PATH'] = str(self.path) + os.pathsep + environment['PATH']
        return subprocess.run(['sh', str(PROBE), *args], env=environment,
                              capture_output=True, text=True, timeout=10)

    def test_default_https_verifies_ca_name_and_connects_locally(self):
        result = self.probe()
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = result.stdout.splitlines()
        self.assertIn('--cacert', arguments)
        self.assertIn('localhost:9999:127.0.0.1:9999', arguments)
        self.assertIn('https://localhost:9999/login', arguments)
        self.assertIn('--noproxy', arguments)
        self.assertNotIn('--insecure', arguments)

    def test_http_and_ipv6_use_configured_host_port_without_ca(self):
        for host in ['127.0.0.2', '::1']:
            with self.subTest(host=host):
                result = self.probe({'NM__TLS__ENABLED': 'false',
                                     'NM__SERVER__HOST': host, 'NM__SERVER__PORT': '12345'})
                address = f'[{host}]' if ':' in host else host
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f'http://{address}:12345/login', result.stdout.splitlines())
                self.assertNotIn('--cacert', result.stdout)

    def test_ipv6_wildcard_https_uses_ipv6_loopback(self):
        result = self.probe({'NM__SERVER__HOST': '::', 'SERVER_TLS_NAME': 'server.example.com'})
        self.assertIn('server.example.com:9999:[::1]:9999', result.stdout.splitlines())

    def test_file_mode_can_override_protocol_host_and_port(self):
        result = self.probe(args=('http', '::1', '12345'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('http://[::1]:12345/login', result.stdout)

    def test_file_inputs_and_conflicting_values(self):
        switch = self.path / 'enabled'
        switch.write_bytes(b'false\r\n')
        result = self.probe({'NM__TLS__ENABLED_FILE': str(switch)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('http://127.0.0.1:9999/login', result.stdout)
        self.assertNotEqual(self.probe({'NM__TLS__ENABLED': 'true',
                                       'NM__TLS__ENABLED_FILE': str(switch)}).returncode, 0)

    def test_bad_protocol_port_and_failed_requests_fail_the_probe(self):
        for values in [{'NM__TLS__ENABLED': 'invalid'}, {'NM__SERVER__PORT': 'bad'},
                       {'NM__SERVER__PORT': '0'}, {'NM__SERVER__PORT': '65536'},
                       {'CURL_EXIT_CODE': '22'}]:
            self.assertNotEqual(self.probe(values).returncode, 0)
        self.assertNotEqual(self.probe(args=('ftp',)).returncode, 0)

    @unittest.skipUnless(shutil.which('curl'), 'requires curl')
    def test_real_http_without_certificates_and_with_proxy_environment(self):
        with page_server() as port:
            result = self.probe({'NM__TLS__ENABLED': 'false',
                                 'NM__SERVER__PORT': str(port)}, fake=False)
            self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(shutil.which('curl') and shutil.which('openssl'), 'requires curl/openssl')
    def test_real_https_rejects_untrusted_ca_and_hostname_mismatch(self):
        cert, key = self.path / 'cert.pem', self.path / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-subj', '/CN=localhost', '-addext',
                        'subjectAltName=DNS:localhost', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True, timeout=20)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        with page_server(context=context) as port:
            values = {'NM__SERVER__PORT': str(port), 'SERVER_TLS_CA_FILE': str(cert)}
            result = self.probe(values, fake=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            values['SERVER_TLS_NAME'] = 'wrong.example.com'
            self.assertNotEqual(self.probe(values, fake=False).returncode, 0)
            values['SERVER_TLS_NAME'] = 'localhost'
            values['SERVER_TLS_CA_FILE'] = '/etc/ssl/certs/ca-certificates.crt'
            self.assertNotEqual(self.probe(values, fake=False).returncode, 0)

    @unittest.skipUnless(shutil.which('curl') and socket.has_ipv6, 'requires curl/IPv6')
    def test_real_ipv6_http(self):
        # IPv6 may be present in Python while disabled by the runner's kernel.
        try:
            listener = socket.socket(socket.AF_INET6)
            listener.bind(('::1', 0))
            listener.close()
        except OSError:
            self.skipTest('IPv6 loopback unavailable')
        with page_server('::1') as port:
            result = self.probe({'NM__TLS__ENABLED': 'false', 'NM__SERVER__HOST': '::1',
                                 'NM__SERVER__PORT': str(port)}, fake=False)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
