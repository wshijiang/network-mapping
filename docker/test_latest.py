"""Promotion preserves each architecture and refuses invalid or older releases."""
import copy
import json
import urllib.error
import unittest
from unittest.mock import patch

import latest


IMAGE = 'ghcr.io/example/network-mapping-server'
REVISION = 'a' * 40


class MemoryRegistry:
    def __init__(self):
        self.content = {}
        self.writes = []
        self.fail_tag = None

    def blob(self, value):
        raw = json.dumps(value).encode()
        key = latest.digest(raw)
        self.content[key] = raw
        return {'digest': key, 'size': len(raw), 'mediaType': latest.MANIFEST}

    def release(self, version='1.2.3', revision=REVISION):
        manifests = []
        for arch in ['amd64', 'arm64']:
            config = self.blob({'os': 'linux', 'architecture': arch, 'config': {'Labels': {
                'org.opencontainers.image.title': 'network-mapping-server',
                'org.opencontainers.image.version': version,
                'org.opencontainers.image.revision': revision}}})
            runtime = self.blob({'config': config, 'layers': []})
            runtime['platform'] = {'os': 'linux', 'architecture': arch}
            attestation = self.blob({'layers': []})
            attestation['annotations'] = {'vnd.docker.reference.type': 'attestation-manifest',
                                         'vnd.docker.reference.digest': runtime['digest']}
            attestation['platform'] = {'os': 'unknown', 'architecture': 'unknown'}
            manifests.extend([runtime, attestation])
        raw = json.dumps({'schemaVersion': 2, 'mediaType': latest.INDEX, 'manifests': manifests}).encode()
        self.content['v' + version] = raw
        return raw

    def request(self, kind, reference, data=None, missing_ok=False):
        if data is not None:
            if reference == self.fail_tag:
                raise RuntimeError('registry write failed')
            self.writes.append(reference)
            self.content[reference] = data
        elif reference not in self.content and not missing_ok:
            raise RuntimeError('missing source')
        return self.content.get(reference)


class PromotionTests(unittest.TestCase):
    def setUp(self):
        self.registry = MemoryRegistry()
        self.source = self.registry.release()
        self.destinations = {IMAGE + '-' + arch: MemoryRegistry() for arch in latest.ARCHES}
        self.copies = []

    def copy(self, source, target):
        image, tag = target.rsplit(':', 1)
        destination = self.destinations[image]
        if destination.fail_tag == tag:
            raise RuntimeError('registry write failed')
        self.copies.append(target)
        destination.content.update({k: v for k, v in self.registry.content.items() if k.startswith('sha256:')})
        destination.content[tag] = self.registry.content[source.split('@', 1)[1]]

    def promote(self, version='1.2.3', revision=REVISION, dry_run=False):
        latest.promote(self.registry, IMAGE, version, revision, dry_run,
                       registry_factory=lambda image, write: self.destinations[image], copier=self.copy)

    def mutate_source(self, change):
        index = json.loads(self.source)
        change(index)
        self.registry.content['v1.2.3'] = json.dumps(index).encode()

    def test_independent_image_names_preserve_exact_architecture_and_attestations(self):
        self.promote()
        self.assertEqual(self.copies, [IMAGE + '-amd64:latest', IMAGE + '-arm64:latest'])
        descriptors = json.loads(self.source)['manifests']
        for arch, offset in [('amd64', 0), ('arm64', 2)]:
            index = json.loads(self.destinations[IMAGE + '-' + arch].content['latest'])
            self.assertEqual(index['manifests'], descriptors[offset:offset + 2])
        self.assertEqual(self.registry.content['v1.2.3'], self.source)
        self.assertNotIn('latest', self.registry.content)

    def test_repeat_promotion_does_not_write(self):
        self.promote()
        self.registry.writes.clear()
        self.copies.clear()
        self.promote()
        self.assertEqual(self.registry.writes, [])
        self.assertEqual(self.copies, [])

    def test_dry_run_only_reads(self):
        self.promote(dry_run=True)
        self.assertEqual(self.registry.writes, [])

    def test_numeric_version_order_does_not_allow_downgrade(self):
        self.registry.release('1.10.0')
        self.promote('1.10.0')
        self.registry.writes.clear()
        self.copies.clear()
        self.promote()
        self.assertEqual(self.registry.writes, [])
        self.assertEqual(self.copies, [])

    def test_stable_upgrade(self):
        self.promote()
        self.registry.release('2.0.0')
        self.registry.writes.clear()
        self.copies.clear()
        self.promote('2.0.0')
        self.assertEqual(len(self.copies), 2)

    def test_wrong_release_revision_aborts_without_writes(self):
        with self.assertRaisesRegex(AssertionError, 'Git tag'):
            self.promote(revision='b' * 40)
        self.assertEqual(self.registry.writes, [])

    def test_missing_architecture_aborts_without_writes(self):
        self.mutate_source(lambda index: index['manifests'].__delitem__(slice(2, None)))
        with self.assertRaisesRegex(AssertionError, 'Missing runtime'):
            self.promote()
        self.assertEqual(self.registry.writes, [])

    def test_duplicate_architecture_is_rejected(self):
        self.mutate_source(lambda index: index['manifests'].append(copy.deepcopy(index['manifests'][0])))
        with self.assertRaisesRegex(AssertionError, 'duplicate runtime'):
            self.promote()

    def test_cross_architecture_attestation_is_rejected(self):
        def change(index):
            index['manifests'][3]['annotations']['vnd.docker.reference.digest'] = index['manifests'][0]['digest']
        self.mutate_source(change)
        with self.assertRaisesRegex(AssertionError, 'attestations'):
            self.promote()
        self.assertEqual(self.registry.writes, [])

    def test_config_architecture_mismatch_is_rejected(self):
        self.mutate_source(lambda index: index['manifests'][0]['platform'].update(architecture='arm64'))
        with self.assertRaisesRegex(AssertionError, 'architecture mismatch'):
            self.promote()

    def test_conflicting_same_version_revision_is_rejected(self):
        self.promote()
        self.registry.release(revision='b' * 40)
        self.registry.writes.clear()
        with self.assertRaisesRegex(AssertionError, 'conflicting revision'):
            self.promote(revision='b' * 40)
        self.assertEqual(self.registry.writes, [])

    def test_partial_failure_stops_and_retry_repairs_only_the_missing_architecture(self):
        destination = self.destinations[IMAGE + '-arm64']
        destination.fail_tag = 'latest'
        with self.assertRaisesRegex(RuntimeError, 'write failed'):
            self.promote()
        self.assertNotIn('latest', destination.content)
        destination.fail_tag = None
        self.copies.clear()
        self.promote()
        self.assertEqual(self.copies, [IMAGE + '-arm64:latest'])

    def test_skopeo_transfers_all_layers_and_proofs_without_credentials_in_arguments(self):
        with patch('latest.subprocess.run') as run:
            latest.copy_image(IMAGE + '@sha256:fixture', IMAGE + '-arm64:latest')
            run.assert_called_once_with(['skopeo', 'copy', '--all', '--preserve-digests',
                                         'docker://' + IMAGE + '@sha256:fixture',
                                         'docker://' + IMAGE + '-arm64:latest'], check=True, timeout=600)

    def test_prerelease_main_does_not_contact_registry(self):
        with patch('sys.argv', ['latest.py', '--component', 'server', '--version', '2.0.0-rc.1']), \
             patch('latest.Registry') as registry:
            latest.main()
            registry.assert_not_called()


class RegistryTests(unittest.TestCase):
    def registry(self):
        registry = object.__new__(latest.Registry)
        registry.repository = 'example/network-mapping-server'
        registry.token = 'test-only'
        return registry

    def test_only_not_found_is_treated_as_absent(self):
        for code in [401, 403, 404, 429, 500]:
            with self.subTest(code=code), patch('urllib.request.urlopen', side_effect=urllib.error.HTTPError(
                    'https://ghcr.io', code, 'fixture', {}, None)):
                if code == 404:
                    self.assertIsNone(self.registry().request('manifests', 'latest', missing_ok=True))
                else:
                    with self.assertRaises(urllib.error.HTTPError):
                        self.registry().request('manifests', 'latest', missing_ok=True)

    def test_readback_mismatch_fails(self):
        with patch('urllib.request.urlopen') as open_url:
            open_url.return_value.__enter__.return_value.read.return_value = b'corrupt'
            with self.assertRaisesRegex(AssertionError, 'digest mismatch'):
                self.registry().request('blobs', 'sha256:' + 'a' * 64)


if __name__ == '__main__':
    unittest.main()
