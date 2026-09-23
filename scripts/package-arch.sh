#!/bin/sh
# Generate the Walden Arch package recipe.
#
# This produces a PKGBUILD, not a package. An Arch package is built from its
# recipe by makepkg on an Arch machine, and published by putting the recipe in
# the Arch User Repository; what this script has to get right is that the
# recipe names one immutable release tarball and the checksum that proves it is
# that one. Pass --build to also run makepkg here, if this is such a machine.
#
# The checksum comes from the release tarball itself. By default the tarball is
# downloaded from the release the version in Cargo.toml names, which is what
# makes the recipe reproduce that release rather than the working tree.
#
# Usage:
#   ./scripts/package-arch.sh [--output DIR] [--build]
#   ./scripts/package-arch.sh --source-archive FILE
#   ./scripts/package-arch.sh --sha256 CHECKSUM

set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/package-common.sh"

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'
}

output="${repo_root}/dist/arch"
source_archive=""
checksum=""
build=no

while [ $# -gt 0 ]; do
  case "$1" in
    --output)
      [ $# -ge 2 ] || die "--output needs a value"
      output="$2"
      shift 2
      ;;
    --source-archive)
      [ $# -ge 2 ] || die "--source-archive needs a value"
      source_archive="$2"
      shift 2
      ;;
    --sha256)
      [ $# -ge 2 ] || die "--sha256 needs a value"
      checksum="$2"
      shift 2
      ;;
    --build)
      build=yes
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

# The same source archive the GitHub Release publishes, not GitHub's
# automatically generated tag tarball, so the checksum in the recipe is the
# checksum of a file that is itself on the release.
ARCH_SOURCE_URL="${HOMEPAGE}/releases/download/v${VERSION}/walden-${VERSION}.tar.gz"
ARCH_LICENSE="$LICENSE_ID"

if [ -n "$checksum" ] && [ -n "$source_archive" ]; then
  die "--sha256 and --source-archive both say what the source is; pass one"
fi

if [ -z "$checksum" ]; then
  if [ -z "$source_archive" ]; then
    require_command curl
    work=$(mktemp -d "${TMPDIR:-/tmp}/walden-arch-package.XXXXXX")
    trap 'rm -rf "$work"' EXIT INT TERM

    source_archive="${work}/walden-${VERSION}.tar.gz"
    echo "==> downloading ${ARCH_SOURCE_URL}"
    curl --fail --location --silent --show-error \
      --output "$source_archive" "$ARCH_SOURCE_URL" ||
      die "could not download the v${VERSION} release tarball; publish the release first, or pass --source-archive or --sha256"
  fi

  [ -f "$source_archive" ] || die "no such file: ${source_archive}"
  checksum=$(sha256_of "$source_archive")
fi

ARCH_SHA256="$checksum"
export ARCH_SOURCE_URL ARCH_LICENSE ARCH_SHA256

mkdir -p "$output"
render_template "${repo_root}/packaging/linux/arch/PKGBUILD.in" >"${output}/PKGBUILD"
cp "${repo_root}/packaging/linux/arch/walden.install" "${output}/walden.install"

echo "==> wrote ${output}/PKGBUILD"
echo "    source:   ${ARCH_SOURCE_URL}"
echo "    sha256:   ${ARCH_SHA256}"

# The Arch User Repository is served from .SRCINFO rather than from the
# PKGBUILD, so a recipe without one cannot be published.
if command -v makepkg >/dev/null 2>&1; then
  echo "==> writing ${output}/.SRCINFO"
  (cd "$output" && makepkg --printsrcinfo >.SRCINFO)
else
  echo "==> makepkg is not available; .SRCINFO must be generated on an Arch machine"
fi

if [ "$build" = "yes" ]; then
  require_command makepkg "run this on an Arch machine"
  echo "==> building the package"
  (cd "$output" && makepkg --clean --force)
fi
