"""Release-contract tests: corrupted/wrong OCI artifacts must never reach GHCR."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

import ci


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)/'image-amd64.oci.tar'

    def fixture(self, architecture='amd64', attestations=True, corrupt=False, unsafe=False, component='server', sbom=True, extra_architecture=False):
        blobs = {}

        def blob(value):
            content = json.dumps(value).encode()
            digest = hashlib.sha256(content).hexdigest()
            blobs['blobs/sha256/'+digest] = content
            return {'digest': 'sha256:'+digest, 'size': len(content),
                    'mediaType': 'application/vnd.oci.image.manifest.v1+json'}

        config = blob({'architecture': architecture, 'os': 'linux', 'config': {
            'User': '10001:10001', 'Entrypoint': ['/opt/network-mapping/bin/network_mapping_server'],
            'Labels': {'org.opencontainers.image.title': 'network-mapping-'+component,
                       'org.opencontainers.image.version': '1.2.3',
                       'org.opencontainers.image.revision': 'a'*40,
                       'io.network-mapping.frontend.revision': 'b'*40}}})
        image = blob({'schemaVersion': 2, 'config': config, 'layers': []})
        image['platform'] = {'os': 'linux', 'architecture': architecture}
        manifests = [image]
        if extra_architecture:
            other_config = blob({'architecture': 'arm64', 'os': 'linux'})
            manifests.append(blob({'schemaVersion': 2, 'config': other_config, 'layers': []}))
        if attestations:
            layers = [blob({'predicateType': 'https://slsa.dev/provenance/v1'})]
            if sbom:
                layers.append(blob({'predicateType': 'https://spdx.dev/Document'}))
            attestation = blob({'schemaVersion': 2, 'config': blob({}), 'layers': layers})
            attestation['platform'] = {'os': 'unknown', 'architecture': 'unknown'}
            attestation['annotations'] = {'vnd.docker.reference.type': 'attestation-manifest'}
            manifests.append(attestation)
        blobs['index.json'] = json.dumps({'schemaVersion': 2, 'manifests': [
            blob({'schemaVersion': 2, 'manifests': manifests})]}).encode()
        if corrupt:
            blobs[next(iter(blobs))] += b'corrupted'
        if unsafe:
            blobs['../escaped'] = b'unsafe'
        with tarfile.open(self.path, 'w') as archive:
            for name, content in blobs.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))

    def verify(self, **changes):
        arguments = dict(archive=self.path, arch='amd64', component='server', version='1.2.3',
                         revision='a'*40, frontend='b'*40)
        arguments.update(changes)
        ci.verify_archive(**arguments)

    def test_valid_artifact_and_checksum(self):
        self.fixture()
        self.verify()
        self.verify()
        self.assertTrue(Path(str(self.path)+'.sha256').exists())

    def test_scanner_artifact(self):
        self.fixture(component='scanner')
        self.verify(component='scanner', frontend='')

    def test_attestation_without_sbom_is_rejected(self):
        self.fixture(sbom=False)
        with self.assertRaisesRegex(AssertionError, 'SPDX SBOM'):
            self.verify()

    def test_wrong_architecture_is_rejected(self):
        self.fixture(architecture='arm64')
        with self.assertRaisesRegex(AssertionError, 'runtime architecture'):
            self.verify()

    def test_mixed_architecture_archive_is_rejected(self):
        self.fixture(extra_architecture=True)
        with self.assertRaisesRegex(AssertionError, 'runtime architecture'):
            self.verify()

    def test_corrupt_blob_is_rejected(self):
        self.fixture(corrupt=True)
        with self.assertRaisesRegex(AssertionError, 'Corrupt OCI'):
            self.verify()

    def test_missing_attestations_are_rejected(self):
        self.fixture(attestations=False)
        with self.assertRaisesRegex(AssertionError, 'attestations'):
            self.verify()

    def test_wrong_revision_and_frontend_are_rejected(self):
        self.fixture()
        for changes in [{'revision': 'c'*40}, {'frontend': 'c'*40}, {'version': '1.2.4'}]:
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                self.verify(**changes)

    def test_checksum_tampering_is_rejected(self):
        self.fixture()
        Path(str(self.path)+'.sha256').write_text('0'*64+' image-amd64.oci.tar\n')
        with self.assertRaisesRegex(AssertionError, 'checksum mismatch'):
            self.verify()

    def test_unsafe_archive_entry_is_rejected(self):
        self.fixture(unsafe=True)
        with self.assertRaisesRegex(AssertionError, 'Unsafe OCI'):
            self.verify()




class MetadataTests(unittest.TestCase):
    def metadata(self, lock_version='1.2.3', tag='refs/tags/v1.2.3', ancestry_error=False):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory/'docker').mkdir()
            (directory/'docker/config.example.toml').write_text('[scanner]\nc_server="example.com"\n')
            (directory/'Cargo.toml').write_text('[package]\nname="scanner-rs"\nversion="1.2.3"\n')
            (directory/'Cargo.lock').write_text(f'[[package]]\nname="scanner-rs"\nversion="{lock_version}"\n')
            real_path = Path
            def fixture_path(value):
                return directory/value if value in ['Cargo.toml','Cargo.lock','docker/config.example.toml'] else real_path(value)
            with patch('ci.Path', side_effect=fixture_path), patch.dict('os.environ', {
                'GITHUB_REF': tag, 'GITHUB_REPOSITORY_OWNER': 'ExampleOwner', 'GITHUB_OUTPUT': ''}), \
                 patch('ci.subprocess.check_output', return_value='a'*40+'\n'), \
                 patch('ci.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'git') if ancestry_error else None) as ancestry, \
                 patch('sys.stdout', new_callable=io.StringIO) as output:
                ci.metadata('scanner')
                return output.getvalue(), ancestry

    def test_matching_version_and_main_ancestry(self):
        output, ancestry = self.metadata()
        self.assertIn('image=ghcr.io/exampleowner/network-mapping-scanner', output)
        ancestry.assert_called_once_with(['git','merge-base','--is-ancestor','a'*40,'origin/main'], check=True)

    def test_mismatched_lock_version_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'Cargo.lock'):
            self.metadata(lock_version='1.2.2')

    def test_wrong_component_version_tag_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'tag'):
            self.metadata(tag='refs/tags/v9.0.0')

    def test_commit_outside_main_is_rejected(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.metadata(ancestry_error=True)


if __name__ == '__main__':
    unittest.main()
