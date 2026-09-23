#!/bin/sh
# Build and run Walden's checks in a reproducible Linux container.
#
# Usage:
#   ./scripts/test-linux.sh
#   CONTAINER_ENGINE=podman ./scripts/test-linux.sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
engine=${CONTAINER_ENGINE:-docker}
image=${WALDEN_TEST_IMAGE:-walden-linux-tests:local}

if ! command -v "$engine" >/dev/null 2>&1; then
  echo "walden: container engine not found: ${engine}" >&2
  echo "Install Docker, or set CONTAINER_ENGINE to another Docker-compatible engine." >&2
  exit 1
fi

if ! "$engine" info >/dev/null 2>&1; then
  echo "walden: ${engine} is installed, but its service is not running" >&2
  exit 1
fi

echo "==> building Linux test image"
"$engine" build \
  --file "${repo_root}/containers/test-linux.Dockerfile" \
  --tag "$image" \
  "$repo_root"

echo "==> running Linux verification"
"$engine" run --rm "$image"

