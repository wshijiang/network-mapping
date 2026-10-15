#!/usr/bin/env bash
set -euo pipefail
# Called only by the protected publishing job, after all native builds pass.
: "${IMAGE:?}" "${VERSION:?}" "${REVISION:?}" "${COMPONENT:?}" "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}"
[[ "$GITHUB_REF" == "refs/tags/v$VERSION" ]]
[[ "$IMAGE" =~ ^ghcr.io/[a-z0-9-]+/network-mapping-(server|scanner)$ ]]
[[ "$REVISION" =~ ^[a-f0-9]{40}$ ]]
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]
git merge-base --is-ancestor "$REVISION" origin/main

require_absent() {
  local reference="$1" error_file
  error_file="$(mktemp)"
  if skopeo inspect --raw "docker://$reference" >/dev/null 2>"$error_file"; then
    echo "Refusing to overwrite existing image tag: $reference" >&2
    exit 1
  fi
  # Authentication, rate-limit and network errors must fail closed.
  if ! grep -Eqi 'manifest unknown|manifest_unknown|name unknown|name_unknown' "$error_file"; then
    cat "$error_file" >&2
    exit 1
  fi
}
require_absent "$IMAGE:v$VERSION"
require_absent "$IMAGE:sha-$REVISION"

references=()
for arch in amd64 arm64; do
  archive="docker/output/image-$arch.oci.tar"
  test -f "$archive.sha256"
  python3 docker/ci.py verify --component "$COMPONENT" --archive "$archive" --arch "$arch" \
    --version "$VERSION" --revision "$REVISION" --frontend "${FRONTEND_REVISION:-}"
done
# No registry writes occurred before both archives passed validation.
for arch in amd64 arm64; do
  staging="$IMAGE:build-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$arch"
  require_absent "$staging"
  skopeo copy --all --preserve-digests "oci-archive:docker/output/image-$arch.oci.tar" "docker://$staging"
  digest="$(docker buildx imagetools inspect "$staging" --format '{{.Manifest.Digest}}')"
  references+=("$IMAGE@$digest")
done
docker buildx imagetools create --tag "$IMAGE:v$VERSION" --tag "$IMAGE:sha-$REVISION" "${references[@]}"
docker buildx imagetools inspect "$IMAGE:v$VERSION"
skopeo inspect --raw "docker://$IMAGE:v$VERSION" > docker/output/published-manifest.json
python3 - <<'PY'
import json
from pathlib import Path
manifest = json.loads(Path('docker/output/published-manifest.json').read_text())
platforms = {(m.get('platform', {}).get('os'), m.get('platform', {}).get('architecture'))
             for m in manifest['manifests']}
assert ('linux', 'amd64') in platforms and ('linux', 'arm64') in platforms
assert sum(m.get('annotations', {}).get('vnd.docker.reference.type') == 'attestation-manifest'
           for m in manifest['manifests']) >= 2, 'Attestations were lost during publishing'
PY
version_digest="$(docker buildx imagetools inspect "$IMAGE:v$VERSION" --format '{{.Manifest.Digest}}')"
sha_digest="$(docker buildx imagetools inspect "$IMAGE:sha-$REVISION" --format '{{.Manifest.Digest}}')"
test "$version_digest" = "$sha_digest"
# shellcheck disable=SC2016 # Markdown code spans are literal printf text.
printf 'Published `%s:v%s`\n\nDigest: `%s`\n\nCommit: `%s`\n' "$IMAGE" "$VERSION" "$version_digest" "$REVISION" >> "$GITHUB_STEP_SUMMARY"
python3 docker/latest.py --component "$COMPONENT" --version "$VERSION"
