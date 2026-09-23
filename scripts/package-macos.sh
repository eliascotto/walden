#!/bin/sh
# Build the Walden macOS installer package.
#
# One architecture per package: the two are built by separate release jobs on
# their own machines, and a user who downloads the wrong one is told so by the
# installer rather than by a daemon that will not launch.
#
# The package is unsigned. macOS will refuse to open it on the first attempt;
# docs/packaging.md explains the trust decision that gets past that. Signing
# later means adding `productsign` after this script and changes nothing about
# how the package is built.
#
# Usage:
#   ./scripts/package-macos.sh [--arch arm64|x86_64] [--output DIR] [--skip-build]
#                              [--skip-catalog-fetch]

set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/package-common.sh"

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
}

IDENTIFIER="org.scotto.walden"
LABEL="org.scotto.waldend"

# Walden is built with the current Rust toolchain's default deployment target
# and is tested no further back than this.
MINIMUM_MACOS="12.0"

arch=$(uname -m)
output="${repo_root}/dist"
skip_build=no

while [ $# -gt 0 ]; do
  case "$1" in
    --arch)
      [ $# -ge 2 ] || die "--arch needs a value"
      arch="$2"
      shift 2
      ;;
    --output)
      [ $# -ge 2 ] || die "--output needs a value"
      output="$2"
      shift 2
      ;;
    --skip-build)
      skip_build=yes
      shift
      ;;
    --skip-catalog-fetch)
      WALDEN_SKIP_CATALOG_FETCH=yes
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[ "$(uname -s)" = "Darwin" ] || die "the macOS package can only be built on macOS"
require_command pkgbuild
require_command productbuild

case "$arch" in
  arm64) target="aarch64-apple-darwin" ;;
  x86_64) target="x86_64-apple-darwin" ;;
  *) die "unsupported architecture: ${arch} (expected arm64 or x86_64)" ;;
esac

job="${repo_root}/packaging/macos/${LABEL}.plist"
uninstaller="${repo_root}/packaging/macos/walden-uninstall"

# The job says where the daemon runs. Taking the install path from it is what
# stops a package from putting the executable somewhere its own job, and the
# runtime that reads that job, do not look.
daemon_path=$(launchd_program "$job")
[ -n "$daemon_path" ] || die "${job} does not say what to run"

if [ "$skip_build" = "no" ]; then
  build_release_binaries "$target"
fi
release_dir="${repo_root}/target/${target}/release"
require_release_binaries_match_source "$release_dir"

echo "==> fetching the pinned walden-list snapshot"
ensure_catalog_snapshot

work=$(mktemp -d "${TMPDIR:-/tmp}/walden-macos-package.XXXXXX")
trap 'remove_work_tree "$work"' EXIT INT TERM

payload="${work}/payload"
scripts="${work}/scripts"

echo "==> staging the payload"
install -d -m 755 "${payload}/usr/local/bin"
install -d -m 755 "${payload}$(dirname "$daemon_path")"
install -d -m 755 "${payload}/Library/LaunchDaemons"

install -m 755 "${release_dir}/walden" "${payload}/usr/local/bin/walden"
install -m 755 "$uninstaller" "${payload}/usr/local/bin/walden-uninstall"
install -m 755 "${release_dir}/waldend" "${payload}${daemon_path}"
install -m 644 "$job" "${payload}/Library/LaunchDaemons/${LABEL}.plist"
install_shared_documentation "${payload}/usr/local/share/doc/walden" 644
install -m 644 "${repo_root}/LICENSE" "${payload}/usr/local/share/doc/walden/LICENSE"
# Copied writable so the payload timestamps can be rewritten; locked down after.
copy_catalog_snapshot "${payload}/usr/local/share/walden/catalog/v1"

install -d -m 755 "$scripts"
install -m 755 "${repo_root}/packaging/macos/scripts/preinstall" "${scripts}/preinstall"
install -m 755 "${repo_root}/packaging/macos/scripts/postinstall" "${scripts}/postinstall"

# A checkout carries extended attributes -- a quarantine flag on a downloaded
# release archive, above all -- and pkgbuild copies them into the payload,
# where the installer would restore them onto the installed files. macOS keeps
# its own provenance attribute on everything and does not allow it to be
# cleared; that one is harmless, and is why the payload listing still shows an
# AppleDouble entry beside every file.
xattr -rc "$payload"

# pkgbuild records the modification time of every file it packages, and a
# checkout hands out whatever time its files happened to be written. Taking
# them all from SOURCE_DATE_EPOCH is what makes the payload identical between
# two builds of one source.
find "$payload" -exec touch -t "$(source_date +%Y%m%d%H%M.%S)" {} +
harden_catalog_snapshot "${payload}/usr/local/share/walden/catalog/v1"

# `--ownership recommended` is what makes the installer write these as
# root-owned regardless of who built the package, so the staging tree above
# does not have to be, and the build does not have to run as root.
echo "==> building the component package"
pkgbuild \
  --root "$payload" \
  --scripts "$scripts" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --ownership recommended \
  --install-location / \
  "${work}/walden-component.pkg" >/dev/null

echo "==> building the product archive"
COMPONENT_PACKAGE="walden-component.pkg"
HOST_ARCHITECTURES="$arch"
export IDENTIFIER MINIMUM_MACOS COMPONENT_PACKAGE HOST_ARCHITECTURES
render_template "${repo_root}/packaging/macos/distribution.xml.in" >"${work}/distribution.xml"

mkdir -p "$output"
package="${output}/walden-${VERSION}-macos-${arch}.pkg"
productbuild \
  --distribution "${work}/distribution.xml" \
  --resources "${repo_root}/packaging/macos/resources" \
  --package-path "$work" \
  "$package" >/dev/null

echo "==> built ${package}"
echo
echo "Inspect it with:"
echo "  pkgutil --payload-files ${package}"
echo "  installer -pkginfo -pkg ${package}"
