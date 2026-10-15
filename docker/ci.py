#!/usr/bin/env python3
"""Read-only metadata/OCI verification shared by this repository's Docker CI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib


def emit(values):
    text = ''.join(f'{key}={value}\n' for key, value in values.items())
    print(text, end='')
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            output.write(text)


def metadata(component):
    tomllib.loads(Path('docker/config.example.toml').read_text())
    package = tomllib.loads(Path('Cargo.toml').read_text())['package']
    version = package['version']
    assert re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', version), 'Invalid package version'
    lock = tomllib.loads(Path('Cargo.lock').read_text())
    assert any(p['name'] == package['name'] and p['version'] == version and 'source' not in p
               for p in lock['package']), 'Cargo.lock package version mismatch'
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    ref = os.environ.get('GITHUB_REF', '')
    if ref.startswith('refs/tags/'):
        assert ref == f'refs/tags/v{version}', 'Release tag must match Cargo.toml'
        subprocess.run(['git', 'merge-base', '--is-ancestor', revision, 'origin/main'], check=True)
    owner = os.environ.get('GITHUB_REPOSITORY_OWNER', 'wshijiang').lower()
    assert re.fullmatch(r'[a-z0-9-]+', owner), 'Invalid registry owner'
    result = {'version': version, 'revision': revision,
              'image': f'ghcr.io/{owner}/network-mapping-{component}'}
    if component == 'server':
        frontend = Path('.github/frontend-ref').read_text().strip()
        assert re.fullmatch(r'[a-f0-9]{40}', frontend), 'frontend-ref must be a full immutable commit'
        result['frontend_revision'] = frontend
    emit(result)


def verify_archive(archive, arch, component, version, revision, frontend):
    """Verify every OCI blob and the runtime config before testing/publishing it."""
    with tarfile.open(archive, 'r:') as bundle:
        members = {m.name.removeprefix('./'): m for m in bundle.getmembers()}
        for name, member in members.items():
            assert not name.startswith('/') and '..' not in Path(name).parts, 'Unsafe OCI entry'
            assert member.isfile() or member.isdir(), 'OCI links/devices are forbidden'
            if name.startswith('blobs/sha256/') and member.isfile():
                digest = hashlib.sha256()
                with bundle.extractfile(member) as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                assert digest.hexdigest() == name.rsplit('/', 1)[1], f'Corrupt OCI blob: {name}'

        def document(digest):
            algorithm, value = digest.split(':')
            assert algorithm == 'sha256'
            return json.load(bundle.extractfile(members[f'blobs/sha256/{value}']))

        root = json.load(bundle.extractfile(members['index.json']))
        pending = list(root['manifests'])
        runtime = []
        attestations = []
        predicate_types = set()
        while pending:
            descriptor = pending.pop()
            obj = document(descriptor['digest'])
            if 'manifests' in obj:
                pending.extend(obj['manifests'])
            elif descriptor.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest':
                attestations.append(descriptor)
                for layer in obj.get('layers', []):
                    statement = document(layer['digest'])
                    predicate_types.add(statement.get('predicateType', ''))
            elif 'config' in obj:
                config = document(obj['config']['digest'])
                assert config.get('os') == 'linux' and config.get('architecture') == arch, 'Unexpected runtime architecture in OCI archive'
                runtime.append((obj, config))
        assert len(runtime) == 1, 'Expected exactly one runtime image for the requested architecture'
        assert attestations, 'SBOM/provenance attestations are missing'
        assert 'https://spdx.dev/Document' in predicate_types, 'SPDX SBOM is missing'
        assert any(t.startswith('https://slsa.dev/provenance/') for t in predicate_types), 'Build provenance is missing'
        manifest, config = runtime[0]
        labels = config['config'].get('Labels', {})
        assert labels.get('org.opencontainers.image.title') == f'network-mapping-{component}'
        assert labels.get('org.opencontainers.image.version') == version
        assert labels.get('org.opencontainers.image.revision') == revision
        if component == 'server':
            assert labels.get('io.network-mapping.frontend.revision') == frontend
            assert config['config'].get('User') == '10001:10001'
        assert config['config'].get('Entrypoint'), 'Missing runtime entrypoint'
        summary = {'component': component, 'architecture': arch, 'version': version,
                   'revision': revision, 'config_digest': manifest['config']['digest'],
                   'frontend_revision': frontend, 'attestations': len(attestations),
                   'predicate_types': sorted(predicate_types)}
    sidecar = Path(str(archive) + '.sha256')
    with open(archive, 'rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if sidecar.exists():
        assert sidecar.read_text().split()[0] == digest, 'OCI archive checksum mismatch'
    else:
        sidecar.write_text(f'{digest}  {Path(archive).name}\n')
    Path(str(archive) + '.json').write_text(json.dumps(summary, indent=2)+'\n')
    print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['metadata', 'verify'])
    parser.add_argument('--component', required=True, choices=['server', 'scanner'])
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--arch', choices=['amd64', 'arm64'])
    parser.add_argument('--version')
    parser.add_argument('--revision')
    parser.add_argument('--frontend', default='')
    args = parser.parse_args()
    if args.operation == 'metadata':
        metadata(args.component)
    else:
        assert args.archive and args.arch and args.version and args.revision
        verify_archive(args.archive, args.arch, args.component, args.version, args.revision, args.frontend)


if __name__ == '__main__':
    main()
