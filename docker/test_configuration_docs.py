"""Keep the public Docker configuration reference in sync without reading secrets."""
from pathlib import Path
import json
import re
import tomllib
import unittest

ROOT = Path(__file__).resolve().parents[1]


def leaf_fields(value, prefix='', atomic=()):
    for key, child in value.items():
        field = f'{prefix}.{key}' if prefix else key
        if isinstance(child, dict) and field not in atomic:
            yield from leaf_fields(child, field, atomic)
        else:
            yield field


class ConfigurationDocumentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = (ROOT / 'docs/DOCKER_CONFIGURATION.md').read_text()
        cls.defaults = tomllib.loads((ROOT / 'docker/config.example.toml').read_text())
        fields = set((ROOT / 'src/public_config_fields.txt').read_text().splitlines())
        fields.update(leaf_fields(cls.defaults))
        optional = (ROOT / 'src/config_env.rs').read_text().split(
            'const OPTIONAL_DEPLOYMENT_STRING_FIELDS', 1)[1].split('];', 1)[0]
        fields.update(re.findall(r'"([a-z_]+\.[a-z_]+)"', optional))
        cls.variables = {'NM__' + field.upper().replace('.', '__') for field in fields}
        cls.example = (ROOT / 'docker/.env.example').read_text()
        cls.assignments = re.findall(r'^(?:#\s*)?([A-Z][A-Z0-9_]*)=(.*)$',
                                     cls.example, re.MULTILINE)
        cls.rows = {}
        for line in cls.reference.splitlines():
            match = re.match(r'^\| `(NM__[A-Z0-9_]+)` \|', line)
            if match:
                cls.rows.setdefault(match[1], []).append(
                    [cell.strip() for cell in line.strip('|').split('|')])

    def test_every_accepted_base_variable_has_exactly_one_parameter_row(self):
        self.assertEqual(self.variables, set(self.rows),
                         'Document added fields and remove unsupported names from env tables')
        for variable, rows in self.rows.items():
            with self.subTest(variable=variable):
                self.assertEqual(len(rows), 1, 'A parameter must have one authoritative row')
                self.assertEqual(len(rows[0]), 4)
                self.assertTrue(all(rows[0]), 'Name, type, default and meaning are required')

    def test_embedded_non_secret_defaults_match_the_reference(self):
        for field in leaf_fields(self.defaults):
            value = self.defaults
            for part in field.split('.'):
                value = value[part]
            # The embedded empty secrets are deliberately unusable, not defaults.
            if value == '':
                continue
            variable = 'NM__' + field.upper().replace('.', '__')
            with self.subTest(variable=variable):
                rows = self.rows.get(variable, [])
                self.assertEqual(len(rows), 1)
                expected = (json.dumps(value, ensure_ascii=False) if isinstance(value, (list, dict))
                            else str(value).lower() if isinstance(value, bool) else str(value))
                self.assertEqual(rows[0][2], f'`{expected}`')

    def test_compose_and_example_variables_are_documented(self):
        variables = set()
        for filename in ('compose.example.yml', 'compose.sql.example.yml'):
            source = (ROOT / 'docker' / filename).read_text()
            variables.update(re.findall(r'(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)', source))
        variables.update(name for name, _ in self.assignments)
        for variable in variables:
            with self.subTest(variable=variable):
                if variable.startswith('NM__'):
                    base = variable if variable in self.variables else variable.removesuffix('_FILE')
                    self.assertIn(base, self.variables,
                                  'Example uses an unsupported environment variable')
                    self.assertIn(f'`{base}`', self.reference)
                else:
                    self.assertIn(f'`{variable}`', self.reference)

    def test_env_example_covers_every_base_variable_once(self):
        names = [name for name, _ in self.assignments]
        self.assertEqual(len(names), len(set(names)), 'Duplicate env example assignments')
        self.assertEqual(self.variables, {name for name in names if name in self.variables},
                         'Every accepted base variable needs an active or commented example')

    def test_env_example_default_values_match_the_reference(self):
        examples = dict(self.assignments)
        for variable, rows in self.rows.items():
            match = re.fullmatch(r'`([^`]+)`', rows[0][2])
            if not match:
                continue  # Required secrets and optional placeholders have no usable default.
            with self.subTest(variable=variable):
                self.assertIn(variable, examples)
                value = examples[variable]
                if value[:1] in ("'", '"') and value[-1:] == value[:1]:
                    value = value[1:-1]
                self.assertEqual(value, match[1])

    def test_toml_example_covers_env_and_file_only_configuration(self):
        source = (ROOT / 'docker/config.example.toml').read_text()
        expanded = []
        for line in source.splitlines():
            # Optional example sections and assignments use '# '; prose stays commented.
            match = re.match(r'^# (\[[a-z_][a-z0-9_.]*\]|[a-z_][a-z0-9_]*\s*=.*)$', line)
            expanded.append(match[1] if match else line)
        configuration = tomllib.loads('\n'.join(expanded))
        fields = {name.removeprefix('NM__').lower().replace('__', '.')
                  for name in self.variables}
        file_only = self.reference.split(
            '## 有文件配置或 Web 入口、暂不支持 env 的字段', 1)[1].split(
            '## 配置文档维护与覆盖检查', 1)[0]
        fields.update(re.findall(r'^\| `([a-z_]+\.[a-z_.]+)` \|', file_only, re.MULTILINE))
        actual = set(leaf_fields(configuration, atomic=('monitor.service_defaults',)))
        self.assertEqual(fields, actual,
                         'TOML examples must cover all fields, including file-only and legacy names')


if __name__ == '__main__':
    unittest.main()
