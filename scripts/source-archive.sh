#!/bin/sh
# Write a source archive of the committed tree.
#
# The archive contains only tracked files, so it is the same source a version
# tag names rather than a working tree with build output or a vendored catalog.
# gzip -n keeps the gzip header free of the wall clock, matching the rest of
# the packaging's SOURCE_DATE_EPOCH discipline.
#
# Usage:
#   ./scripts/source-archive.sh [--output FILE]

set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/package-common.sh"

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

output="${repo_root}/dist/walden-${VERSION}.tar.gz"

while [ $# -gt 0 ]; do
  case "$1" in
    --output)
      [ $# -ge 2 ] || die "--output needs a value"
      output="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

require_command git
require_command gzip

cd "$repo_root" || exit 1

if [ -n "$(git status --porcelain)" ]; then
  die "refusing to archive a dirty working tree; commit or stash first"
fi

mkdir -p "$(dirname "$output")"

echo "==> writing ${output}"
git archive --format=tar --prefix="walden-${VERSION}/" HEAD | gzip -9n >"$output"

[ -s "$output" ] || die "the source archive was not written"

echo "    prefix: walden-${VERSION}/"
echo "    sha256: $(sha256_of "$output")"
