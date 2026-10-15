#!/usr/bin/env python3
"""Promote a checked release to latest aliases without rebuilding any layers.

All callers must use the repository-wide docker-publish concurrency group.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request

INDEX = 'application/vnd.oci.image.index.v1+json'
MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
ARCHES = {'amd64', 'arm64'}


def digest(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def stable_version(version):
    assert re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)', version), 'Expected stable X.Y.Z version'
    return tuple(map(int, version.split('.')))


class Registry:
    def __init__(self, image, write=False):
        assert re.fullmatch(r'ghcr.io/[a-z0-9-]+/network-mapping-(server|scanner)(-amd64|-arm64)?', image)
        self.repository = image.removeprefix('ghcr.io/')
        scope = 'pull,push' if write else 'pull'
        query = urllib.parse.urlencode({'service': 'ghcr.io', 'scope': f'repository:{self.repository}:{scope}'})
        headers = {}
        if write:
            credentials = os.environ['REGISTRY_USERNAME'] + ':' + os.environ['REGISTRY_PASSWORD']
            headers['Authorization'] = 'Basic ' + base64.b64encode(credentials.encode()).decode()
        request = urllib.request.Request('https://ghcr.io/token?' + query, headers=headers)
        with urllib.request.urlopen(request, timeout=30) as response:
            self.token = json.load(response)['token']

    def request(self, kind, reference, data=None, missing_ok=False):
        assert kind in {'manifests', 'blobs'}
        assert re.fullmatch(r'[A-Za-z0-9_.:-]+', reference)
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': INDEX + ', ' + MANIFEST}
        if data is not None:
            headers['Content-Type'] = json.loads(data)['mediaType']
        request = urllib.request.Request(f'https://ghcr.io/v2/{self.repository}/{kind}/{reference}',
                                         data=data, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = response.read()
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok and data is None:
                return None
            raise
        if data is None and reference.startswith('sha256:'):
            assert digest(result) == reference, 'Registry content digest mismatch'
        return result


def inspect_index(registry, raw, image, expected_arches):
    """Check exact runtime architectures, labels and attestation associations."""
    index = json.loads(raw)
    assert index['mediaType'] == INDEX and index['schemaVersion'] == 2, 'Expected OCI index'
    runtimes, attestations, versions, revisions = {}, {}, set(), set()
    for descriptor in index['manifests']:
        annotations = descriptor.get('annotations', {})
        if annotations.get('vnd.docker.reference.type') == 'attestation-manifest':
            attestations.setdefault(annotations['vnd.docker.reference.digest'], []).append(descriptor)
            continue
        platform = descriptor['platform']
        arch = platform['architecture']
        assert platform['os'] == 'linux' and arch in expected_arches and arch not in runtimes, 'Unexpected or duplicate runtime architecture'
        manifest = json.loads(registry.request('manifests', descriptor['digest']))
        config = json.loads(registry.request('blobs', manifest['config']['digest']))
        assert config['os'] == 'linux' and config['architecture'] == arch, 'Config/platform architecture mismatch'
        labels = config['config']['Labels']
        assert labels['org.opencontainers.image.title'] == image.rsplit('/', 1)[1], 'Wrong component'
        versions.add(labels['org.opencontainers.image.version'])
        revisions.add(labels['org.opencontainers.image.revision'])
        runtimes[arch] = descriptor
    assert set(runtimes) == expected_arches, 'Missing runtime architecture'
    assert set(attestations) == {d['digest'] for d in runtimes.values()}, 'Missing or unrelated attestations'
    assert len(versions) == len(revisions) == 1, 'Mixed release versions or revisions'
    version, revision = versions.pop(), revisions.pop()
    stable_version(version)
    assert re.fullmatch(r'[a-f0-9]{40}', revision), 'Invalid source revision'
    return index, runtimes, attestations, version, revision


def copy_image(source, destination):
    # docker/login-action supplies credentials through ~/.docker/config.json,
    # which Skopeo also reads. Never pass credentials on the command line.
    subprocess.run(['skopeo', 'copy', '--all', '--preserve-digests',
                    'docker://' + source, 'docker://' + destination], check=True, timeout=600)


def promote(registry, image, version, revision, dry_run=False, registry_factory=Registry, copier=copy_image):
    wanted = stable_version(version)
    raw = registry.request('manifests', 'v' + version)
    index, runtimes, attestations, source_version, source_revision = inspect_index(registry, raw, image, ARCHES)
    assert (source_version, source_revision) == (version, revision), 'Release image does not match its Git tag'
    targets = {}
    for arch in sorted(ARCHES):
        subset = dict(index, manifests=[runtimes[arch], *attestations[runtimes[arch]['digest']]])
        targets[image + '-' + arch] = json.dumps(subset, separators=(',', ':')).encode()
    # Validate all existing aliases before the first write. Registry/auth failures
    # propagate; only an actual 404 means an alias does not exist yet.
    existing, destinations = {}, {}
    newer = False
    for target in targets:
        if dry_run:
            continue
        destination = registry_factory(target, write=True)
        destinations[target] = destination
        current = destination.request('manifests', 'latest', missing_ok=True)
        existing[target] = current
        if current is None:
            continue
        arches = {target.rsplit('-', 1)[1]}
        *_, old_version, old_revision = inspect_index(destination, current, image, arches)
        newer |= stable_version(old_version) > wanted
        if old_version == version:
            assert old_revision == revision, 'Existing alias has conflicting revision for this version'
    if newer:
        print(f'Skipped v{version}: a latest alias already points to a newer stable release')
        return
    lines = [f'{image}:v{version} -> {digest(raw)}']
    # Cross-repository copies must transfer the referenced layers as well as
    # manifests. Preserve each architecture's runtime and attestations together.
    # A failed copy stops promotion; retry repairs partial updates.
    for target, content in targets.items():
        if not dry_run and existing[target] != content:
            source_digest = digest(content)
            registry.request('manifests', source_digest, data=content)
            copier(image + '@' + source_digest, target + ':latest')
        if not dry_run:
            assert destinations[target].request('manifests', 'latest') == content, 'Alias read-back mismatch'
            inspect_index(destinations[target], content, image, {target.rsplit('-', 1)[1]})
        lines.append(f'{target}:latest -> {digest(content)}')
    report = ('Dry run: ' if dry_run else 'Published: ') + '\n'.join(lines) + '\n'
    print(report)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as output:
            output.write('```text\n' + report + '```\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--component', choices=['server', 'scanner'], required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    # Prereleases retain their immutable tags, without moving stable aliases.
    if re.fullmatch(r'\d+\.\d+\.\d+-[0-9A-Za-z.-]+', args.version):
        print('Prerelease: latest aliases are unchanged')
        return
    stable_version(args.version)
    owner = os.environ['GITHUB_REPOSITORY_OWNER'].lower()
    image = f'ghcr.io/{owner}/network-mapping-{args.component}'
    revision = subprocess.check_output(['git', 'rev-parse', f'refs/tags/v{args.version}^{{commit}}'], text=True).strip()
    subprocess.run(['git', 'merge-base', '--is-ancestor', revision, 'origin/main'], check=True)
    registry = Registry(image, write=not args.dry_run)
    promote(registry, image, args.version, revision, args.dry_run)


if __name__ == '__main__':
    main()
