"""Rust embedded inputs must survive the credential-safe Docker context."""
import fnmatch
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class EmbeddedInputsTests(unittest.TestCase):
    def test_every_tracked_sql_is_in_the_runtime_copy_inputs(self):
        paths = subprocess.check_output(['git', 'ls-files', '--', '*.sql'], cwd=ROOT, text=True).splitlines()
        self.assertIn('source/database/init.sql', paths)
        self.assertIn('docs/MODULE_RUNTIME_MIGRATION.sql', paths)
        rules = [line.strip() for line in (ROOT / '.dockerignore').read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        runtime = (ROOT / 'Dockerfile').read_text().split(' AS runtime\n', 1)[1]
        sources = []
        for line in runtime.splitlines():
            if line.startswith('COPY ') and '--from=' not in line:
                sources.extend(line.split()[1:-1])
        for path in paths:
            with self.subTest(path=path):
                included = False
                for rule in rules:
                    if fnmatch.fnmatch(path, rule.lstrip('!').rstrip('/')):
                        included = rule.startswith('!')
                self.assertTrue(included, f'{path} excluded from Docker context')
                self.assertTrue(any(fnmatch.fnmatch(path, source) or Path(source) in Path(path).parents
                                    for source in sources), f'{path} missing from runtime COPY')

    def test_open_api_embedded_inputs_are_allowed_and_copied(self):
        rules = [line.strip() for line in (ROOT / '.dockerignore').read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
        stage = (ROOT / 'Dockerfile').read_text().split(' AS rust-builder\n', 1)[1].split('\nFROM ', 1)[0]
        sources = []
        for line in stage.splitlines():
            if line.startswith('COPY ') and '--from=' not in line:
                sources.extend(line.split()[1:-1])

        def included(path):
            result = False
            for rule in rules:
                if fnmatch.fnmatch(path, rule.lstrip('!').rstrip('/')):
                    result = rule.startswith('!')
            return result

        inputs = set()
        for module in (ROOT / 'src/open_api').glob('*.rs'):
            for relative in re.findall(r'include_(?:str|bytes)!\(\s*"([^"]+)"', module.read_text()):
                inputs.add((module.parent / relative).resolve().relative_to(ROOT))
        self.assertTrue(inputs)
        for path in inputs:
            with self.subTest(path=str(path)):
                self.assertTrue((ROOT / path).is_file())
                self.assertTrue(included(path.as_posix()), f'{path} excluded from Docker context')
                self.assertTrue(any(path == Path(source) or Path(source) in path.parents for source in sources),
                                f'{path} missing from rust-builder COPY inputs')
        self.assertFalse(included('docs/credentials.md'))
        self.assertFalse(included('config.toml'))


if __name__ == '__main__':
    unittest.main()
