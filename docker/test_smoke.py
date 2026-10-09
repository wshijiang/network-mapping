"""Elasticsearch must be ready for shard allocation before server initialization."""
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


if __name__ == '__main__':
    unittest.main()
