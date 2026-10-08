"""Existing tags and registry errors must abort before any remote write."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class PublishGuardTests(unittest.TestCase):
    def run_guard(self, case):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            marker = directory/'remote-write'
            commands = {
                'git': '#!/bin/sh\nexit 0\n',
                'skopeo': '''#!/bin/sh
if [ "$1" != inspect ]; then
  touch "$WRITE_MARKER"
  exit 0
fi
case "$REGISTRY_CASE" in
  existing) exit 0 ;;
  unauthorized) echo 'unauthorized: authentication required' >&2 ;;
  network) echo 'dial tcp: connection timed out' >&2 ;;
  rate_limit) echo 'too many requests' >&2 ;;
esac
exit 1
''',
                'docker': '#!/bin/sh\ntouch "$WRITE_MARKER"\nexit 0\n',
            }
            for name, text in commands.items():
                path = directory/name
                path.write_text(text)
                path.chmod(0o755)
            environment = dict(os.environ, PATH=str(directory)+os.pathsep+os.environ['PATH'],
                               IMAGE='ghcr.io/example/network-mapping-server', VERSION='1.2.3',
                               REVISION='a'*40, COMPONENT='server', GITHUB_REF='refs/tags/v1.2.3',
                               GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', REGISTRY_CASE=case,
                               WRITE_MARKER=str(marker))
            result = subprocess.run(['bash', str(Path(__file__).with_name('publish.sh'))],
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(marker.exists(), result.stderr)
            return result.stderr

    def test_existing_tag_is_never_overwritten(self):
        self.assertIn('Refusing to overwrite', self.run_guard('existing'))

    def test_authentication_error_is_not_treated_as_missing_tag(self):
        self.assertIn('unauthorized', self.run_guard('unauthorized'))

    def test_network_failure_is_not_treated_as_missing_tag(self):
        self.assertIn('timed out', self.run_guard('network'))

    def test_rate_limit_is_not_treated_as_missing_tag(self):
        self.assertIn('too many requests', self.run_guard('rate_limit'))


if __name__ == '__main__':
    unittest.main()
