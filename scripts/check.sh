#!/bin/sh
# Run the complete non-privileged project verification suite.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)

echo "==> fetching the pinned walden-list snapshot"
"${repo_root}/scripts/fetch-catalog.sh"

# Tests and the CLI binary read the catalog from disk. Pointing them at the
# vendored snapshot is what lets a checkout verify without installing a package.
export WALDEN_CATALOG_DIR="${repo_root}/vendor/walden-list/v1"

echo "==> checking formatting"
cargo fmt --all -- --check

echo "==> linting all targets"
cargo clippy --locked --all-targets --all-features -- -D warnings

echo "==> running all tests"
cargo test --locked --all-targets --all-features

echo "==> building API documentation"
cargo doc --locked --no-deps --document-private-items

echo "==> checking required documentation"
for required in \
  README.md \
  LICENSE \
  docs/packaging.md \
  docs/service-ownership.md \
  docs/releasing.md \
  docs/usage.md \
  docs/testing.md
do
  if [ ! -f "${repo_root}/${required}" ]; then
    echo "walden: missing ${required}" >&2
    exit 1
  fi
done
