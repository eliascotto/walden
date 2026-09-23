#!/bin/sh
# Build the Walden Debian package.
#
# The tree is staged and handed to dpkg-deb directly rather than built through
# debhelper, because there is nothing here debhelper would decide: two
# executables, one systemd unit, and four maintainer scripts that are the
# actual subject of this package and are written out by hand in
# packaging/linux/debian.
#
# Usage:
#   ./scripts/package-deb.sh [--arch amd64|arm64] [--output DIR] [--skip-build]
#                            [--revision N] [--skip-catalog-fetch]

set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/package-common.sh"

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

DEB_REVISION="1"
DEB_DISTRIBUTION="unstable"

arch="amd64"
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
    --revision)
      [ $# -ge 2 ] || die "--revision needs a value"
      DEB_REVISION="$2"
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

case "$arch" in
  amd64) target="x86_64-unknown-linux-gnu" ;;
  arm64) target="aarch64-unknown-linux-gnu" ;;
  *) die "unsupported architecture: ${arch} (expected amd64 or arm64)" ;;
esac

require_command dpkg-deb "install dpkg-dev on Debian, or 'brew install dpkg' on macOS"

debian="${repo_root}/packaging/linux/debian"
unit="${repo_root}/packaging/linux/distribution/waldend.service"

# The unit says where the daemon runs. Taking the install path from it is what
# stops the package from putting the executable somewhere its own unit, and the
# runtime that reads that unit, do not look.
daemon_path=$(systemd_exec_start "$unit")
[ -n "$daemon_path" ] || die "${unit} does not say what to run"

if [ "$skip_build" = "no" ]; then
  build_release_binaries "$target"
fi
release_dir="${repo_root}/target/${target}/release"
require_release_binaries_match_source "$release_dir"

echo "==> fetching the pinned walden-list snapshot"
ensure_catalog_snapshot

work=$(mktemp -d "${TMPDIR:-/tmp}/walden-deb-package.XXXXXX")
trap 'remove_work_tree "$work"' EXIT INT TERM
staging="${work}/staging"

echo "==> staging the package tree"
install -d -m 755 "${staging}/usr/bin"
install -d -m 755 "${staging}$(dirname "$daemon_path")"
install -d -m 755 "${staging}/usr/lib/systemd/system"
install -d -m 755 "${staging}/usr/share/doc/walden"
install_catalog_snapshot "${staging}/usr/share/walden/catalog/v1"

install -m 755 "${release_dir}/walden" "${staging}/usr/bin/walden"
install -m 755 "${release_dir}/waldend" "${staging}${daemon_path}"
install -m 644 "$unit" "${staging}/usr/lib/systemd/system/waldend.service"
install_shared_documentation "${staging}/usr/share/doc/walden" 644

DEB_ARCHITECTURE="$arch"
DEB_COPYRIGHT_YEAR=$(source_date +%Y)
DEB_DATE=$(source_date -R)
# A synopsis is a phrase rather than a sentence, and lintian says so.
DEB_SYNOPSIS=${SUMMARY%.}
export DEB_ARCHITECTURE DEB_COPYRIGHT_YEAR DEB_DATE DEB_DISTRIBUTION DEB_REVISION DEB_SYNOPSIS

render_template "${debian}/copyright.in" >"${staging}/usr/share/doc/walden/copyright"
render_template "${debian}/changelog.in" >"${work}/changelog.Debian"
# -n keeps the file name and timestamp out of the gzip header, which is one of
# the few things that would otherwise differ between two builds of one source.
gzip -9n <"${work}/changelog.Debian" >"${staging}/usr/share/doc/walden/changelog.Debian.gz"
chmod 644 "${staging}/usr/share/doc/walden/copyright" \
  "${staging}/usr/share/doc/walden/changelog.Debian.gz"

# Declared in kibibytes, and counted before the control files exist because
# they are not part of what gets installed.
DEB_INSTALLED_SIZE=$(du -sk "$staging" | cut -f1)
export DEB_INSTALLED_SIZE

install -d -m 755 "${staging}/DEBIAN"
render_template "${debian}/control.in" >"${staging}/DEBIAN/control"
chmod 644 "${staging}/DEBIAN/control"
for script in preinst postinst prerm postrm; do
  install -m 755 "${debian}/${script}" "${staging}/DEBIAN/${script}"
done

mkdir -p "$output"
package="${output}/walden_${VERSION}-${DEB_REVISION}_${arch}.deb"

echo "==> building the package"
# The staging tree belongs to whoever ran the build; --root-owner-group is what
# records every path as root:root without the build having to be root.
dpkg-deb --root-owner-group --build "$staging" "$package" >/dev/null

echo "==> inspecting the package"
dpkg-deb --info "$package"
dpkg-deb --contents "$package"

if command -v lintian >/dev/null 2>&1; then
  echo "==> running lintian"
  lintian --fail-on error --suppress-tags no-manual-page "$package" || die "lintian rejected the package"
else
  echo "==> lintian is not installed; skipping the Debian policy check"
fi

echo "==> built ${package}"
