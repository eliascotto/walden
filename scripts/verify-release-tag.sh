#!/bin/sh
# Confirm a Git tag names the version Cargo.toml states.
#
# Version tags are the only release trigger. A tag that does not match the
# committed package version is refused, so a v1.2.3 tag cannot publish
# whatever happened to be in Cargo.toml at the time.
#
# Usage:
#   ./scripts/verify-release-tag.sh v0.1.0

set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/package-common.sh"

tag="${1:-}"
[ -n "$tag" ] || die "usage: $0 v<version>"

case "$tag" in
  v*) ;;
  *) die "release tags start with v, got ${tag}" ;;
esac

expected="v${VERSION}"
[ "$tag" = "$expected" ] ||
  die "tag ${tag} does not match Cargo.toml version ${VERSION} (expected ${expected})"

echo "tag ${tag} matches Cargo.toml version ${VERSION}"
