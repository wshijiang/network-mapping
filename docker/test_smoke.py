"""Readiness waits must reject partial startup and preserve the original failure."""
import json
import subprocess
import unittest
from unittest.mock import patch

import smoke


class ElasticsearchReadinessTests(unittest.TestCase):
    def ready(self, body, returncode=0):
        result = subprocess.CompletedProcess([], returncode, stdout=body, stderr='')
        with patch('smoke.docker', return_value=result):
            return smoke.elasticsearch_ready('disposable-es')

    def test_green_and_yellow_clusters_are_ready(self):
        for status in ('green', 'yellow'):
            with self.subTest(status=status):
                self.assertTrue(self.ready(json.dumps({'status': status, 'timed_out': False})))

    def test_http_success_with_red_health_is_not_ready(self):
        self.assertFalse(self.ready('{"status":"red","timed_out":false}'))

    def test_timed_out_wait_is_not_ready_even_with_yellow_health(self):
        self.assertFalse(self.ready('{"status":"yellow","timed_out":true}'))

    def test_failed_request_is_not_ready(self):
        self.assertFalse(self.ready('{"status":"green","timed_out":false}', returncode=28))

    def test_malformed_or_incomplete_health_is_not_ready(self):
        for body in ('', 'not json', 'null', '[]', '{}', '{"status":"green"}',
                     '{"timed_out":false}', '{"status":"green","timed_out":"false"}'):
            with self.subTest(body=body):
                self.assertFalse(self.ready(body))


class StartupTests(unittest.TestCase):
    def test_postgres_socket_only_initialization_is_not_ready(self):
        def postgres(*args, **kwargs):
            # Match the official image: the temporary init server has no TCP listener.
            tcp = '-h' in args and args[args.index('-h')+1] == '127.0.0.1'
            return subprocess.CompletedProcess(args, 2 if tcp else 0, stdout='', stderr='')
        with patch('smoke.docker', side_effect=postgres):
            self.assertFalse(smoke.postgres_ready('initializing-pg'))

    def test_http_200_from_an_incomplete_transfer_is_not_ready(self):
        result = subprocess.CompletedProcess([], 28, stdout='200', stderr='request timed out')
        with patch('smoke.https_request', return_value=result):
            self.assertFalse(smoke.https_ready('server'))
            self.assertIsNone(smoke.https_status('server', '/assets/partial.js'))

    def test_stopped_or_oom_killed_container_fails_without_waiting(self):
        for state in ({'Running': False, 'Status': 'exited', 'ExitCode': 1, 'OOMKilled': False},
                      {'Running': False, 'Status': 'exited', 'ExitCode': 137, 'OOMKilled': True}):
            with self.subTest(state=state):
                result = subprocess.CompletedProcess([], 0, stdout=json.dumps(state), stderr='')
                with patch('smoke.docker', return_value=result), patch('smoke.time.sleep') as sleep:
                    with self.assertRaisesRegex(RuntimeError, 'server stopped before readiness:.*exit_code='):
                        smoke.wait_until(lambda: False, 'ready timeout', containers=('server',))
                    sleep.assert_not_called()

    def test_wait_deadline_includes_probe_duration(self):
        clock = [0]
        def probe():
            clock[0] += 2
            return False
        def sleep(seconds):
            clock[0] += seconds
        with patch('smoke.time.monotonic', side_effect=lambda: clock[0]), \
             patch('smoke.time.sleep', side_effect=sleep):
            with self.assertRaisesRegex(RuntimeError, 'ready timeout'):
                smoke.wait_until(probe, 'ready timeout', timeout=3)
        self.assertEqual(clock[0], 3)

    def test_ready_probe_returns_without_sleeping(self):
        with patch('smoke.time.sleep') as sleep:
            smoke.wait_until(lambda: True, 'ready timeout')
            sleep.assert_not_called()


class FailureCleanupTests(unittest.TestCase):
    def test_diagnostic_and_cleanup_timeouts_preserve_original_error(self):
        metadata = {'config_digest': 'sha256:fixture', 'architecture': 'amd64', 'version': '1.2.3'}
        def docker(*args, **kwargs):
            if args[:2] == ('image', 'inspect'):
                body = json.dumps([{'Id': metadata['config_digest'], 'Architecture': 'amd64'}])
            elif args[0] == 'run' and '--rm' in args:
                body = 'server 1.2.3'
            elif args[0] in ('inspect', 'logs', 'rm'):
                raise subprocess.TimeoutExpired(['docker', *args], 10)
            else:
                body = ''
            return subprocess.CompletedProcess(args, 0, stdout=body, stderr='')
        with patch('smoke.sys.argv', ['smoke.py', 'fixture-image', 'fixture-metadata.json']), \
             patch('smoke.Path.read_text', return_value=json.dumps(metadata)), \
             patch('smoke.docker', side_effect=docker) as calls, \
             patch('smoke.wait_until', side_effect=RuntimeError('original readiness failure')), \
             patch('smoke.sys.stderr'):
            with self.assertRaisesRegex(RuntimeError, 'original readiness failure'):
                smoke.main()
        # Even after a timed-out container removal, the network cleanup is attempted.
        self.assertTrue(any(call.args[:2] == ('network', 'rm') for call in calls.call_args_list))


if __name__ == '__main__':
    unittest.main()
