#!/bin/sh
# Inspect a Walden package and fail if it is not a complete release artifact.
#
# The builders already refuse to package development output. This script is the
# independent check that the file they wrote contains the release binaries,
# the service definition that stays inactive on a fresh install, the catalog
# snapshot, and nothing else.
#
# Usage:
#   ./scripts/inspect-package.sh PACKAGE [--release-dir DIR]

set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/package-common.sh"

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
}

package=""
release_dir=""

while [ $# -gt 0 ]; do
  case "$1" in
    --release-dir)
      [ $# -ge 2 ] || die "--release-dir needs a value"
      release_dir="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    --*)
      die "unknown option: $1"
      ;;
    *)
      [ -z "$package" ] || die "unexpected argument: $1"
      package="$1"
      shift
      ;;
  esac
done

[ -n "$package" ] || die "usage: $0 PACKAGE [--release-dir DIR]"
[ -f "$package" ] || die "no such package: ${package}"

if [ -n "$release_dir" ]; then
  case "$release_dir" in
    */release | */release/) ;;
    *) die "--release-dir must be a Cargo release directory, not development output: ${release_dir}" ;;
  esac
fi

package=$(CDPATH= cd -- "$(dirname -- "$package")" && pwd)/$(basename "$package")
name=$(basename "$package")
work=$(mktemp -d "${TMPDIR:-/tmp}/walden-inspect.XXXXXX")
trap 'remove_work_tree "$work"' EXIT INT TERM
issues="${work}/issues"
: >"$issues"

issue() {
  printf '%s\n' "$*" >>"$issues"
}

require_file() {
  if [ ! -f "$1" ]; then
    issue "missing ${2:-$1}"
  fi
}

# Strip a leading ./ so Debian contents and find(1) paths compare the same way.
normalise_path() {
  path=$1
  case "$path" in
    ./) path="" ;;
    ./*) path=${path#./} ;;
  esac
  printf '%s\n' "$path"
}

kind=""
arch=""
case "$name" in
  walden-"${VERSION}"-macos-arm64.pkg)
    kind=macos
    arch=arm64
    ;;
  walden-"${VERSION}"-macos-x86_64.pkg)
    kind=macos
    arch=x86_64
    ;;
  walden_"${VERSION}"-1_amd64.deb)
    kind=debian
    arch=amd64
    ;;
  walden_"${VERSION}"-1_arm64.deb)
    kind=debian
    arch=arm64
    ;;
  *)
    die "unrecognised package name ${name}; expected walden-${VERSION}-macos-<arch>.pkg or walden_${VERSION}-1_<arch>.deb"
    ;;
esac

payload=""
control=""

extract_macos() {
  require_command pkgutil
  require_command installer

  installer -pkginfo -pkg "$package" >"${work}/pkginfo"
  grep -q "${VERSION}" "${work}/pkginfo" ||
    issue "installer metadata does not mention version ${VERSION}"

  pkgutil --expand-full "$package" "${work}/expanded" ||
    die "pkgutil --expand-full failed; inspect macOS packages on macOS 12 or later"

  walden_bin=$(find "${work}/expanded" -type f -path '*/usr/local/bin/walden' ! -name '._*' | head -n 1)
  [ -n "$walden_bin" ] || die "the package payload does not contain /usr/local/bin/walden"
  payload=$(CDPATH= cd -- "$(dirname -- "$walden_bin")/../../.." && pwd)

  scripts=$(find "${work}/expanded" -type d -name Scripts | head -n 1)
  [ -n "$scripts" ] || die "the package does not contain installer scripts"
  control=$scripts

  dist_found=no
  find "${work}/expanded" \( -name distribution.xml -o -name Distribution \) >"${work}/distributions"
  while IFS= read -r dist; do
    dist_found=yes
    grep -q "hostArchitectures=\"${arch}\"" "$dist" ||
      issue "${dist} does not restrict installation to ${arch}"
    grep -q "min=\"12.0\"" "$dist" ||
      issue "${dist} does not declare the macOS 12 minimum"
  done <"${work}/distributions"
  [ "$dist_found" = "yes" ] || issue "the product archive has no Distribution file"
}

extract_debian() {
  require_command dpkg-deb

  dpkg-deb --info "$package" >"${work}/info"
  grep -q "^ Package: walden$" "${work}/info" || issue "Debian package name is not walden"
  grep -q "^ Version: ${VERSION}-1$" "${work}/info" ||
    issue "Debian version is not ${VERSION}-1"
  grep -q "^ Architecture: ${arch}$" "${work}/info" ||
    issue "Debian architecture is not ${arch}"
  grep -q "systemd" "${work}/info" || issue "Debian Depends does not include systemd"
  grep -q "nftables" "${work}/info" || issue "Debian Depends does not include nftables"

  control="${work}/control"
  mkdir -p "$control"
  dpkg-deb --control "$package" "$control"

  payload="${work}/root"
  mkdir -p "$payload"
  dpkg-deb --fsys-tarfile "$package" | tar -C "$payload" -xf -

  dpkg-deb --contents "$package" >"${work}/contents"
  while IFS= read -r line; do
    case "$line" in
      -*)
        owner=$(printf '%s\n' "$line" | awk '{ print $2 }')
        [ "$owner" = "root/root" ] || issue "payload file is not root/root: ${line}"
        ;;
    esac
  done <"${work}/contents"
}

case "$kind" in
  macos) extract_macos ;;
  debian) extract_debian ;;
esac

[ -n "$payload" ] && [ -d "$payload" ] || die "failed to extract the package payload"

macos_allowed() {
  case "$1" in
    usr/local/bin/walden) return 0 ;;
    usr/local/bin/walden-uninstall) return 0 ;;
    usr/local/libexec/waldend) return 0 ;;
    Library/LaunchDaemons/org.scotto.waldend.plist) return 0 ;;
    usr/local/share/doc/walden/README.md) return 0 ;;
    usr/local/share/doc/walden/LICENSE) return 0 ;;
    usr/local/share/doc/walden/packaging.md) return 0 ;;
    usr/local/share/doc/walden/service-ownership.md) return 0 ;;
    usr/local/share/doc/walden/usage.md) return 0 ;;
    usr/local/share/walden/catalog/v1/manifest.json) return 0 ;;
    usr/local/share/walden/catalog/v1/checksums.txt) return 0 ;;
    usr/local/share/walden/catalog/v1/categories/*.txt) return 0 ;;
    */._* | ._* | *"/._"*) return 0 ;;
    *) return 1 ;;
  esac
}

debian_allowed() {
  case "$1" in
    usr/bin/walden) return 0 ;;
    usr/lib/walden/waldend) return 0 ;;
    usr/lib/systemd/system/waldend.service) return 0 ;;
    usr/share/doc/walden/README.md) return 0 ;;
    usr/share/doc/walden/packaging.md) return 0 ;;
    usr/share/doc/walden/service-ownership.md) return 0 ;;
    usr/share/doc/walden/usage.md) return 0 ;;
    usr/share/doc/walden/copyright) return 0 ;;
    usr/share/doc/walden/changelog.Debian.gz) return 0 ;;
    usr/share/walden/catalog/v1/manifest.json) return 0 ;;
    usr/share/walden/catalog/v1/checksums.txt) return 0 ;;
    usr/share/walden/catalog/v1/categories/*.txt) return 0 ;;
    *) return 1 ;;
  esac
}

path_allowed() {
  if [ "$kind" = "macos" ]; then
    macos_allowed "$1"
  else
    debian_allowed "$1"
  fi
}

# Every payload file must be on the allowlist, and every required file must
# exist. Extra development files fail the build; a missing catalog or daemon
# fails it the other way.
required=""
if [ "$kind" = "macos" ]; then
  required="
usr/local/bin/walden
usr/local/bin/walden-uninstall
usr/local/libexec/waldend
Library/LaunchDaemons/org.scotto.waldend.plist
usr/local/share/doc/walden/README.md
usr/local/share/doc/walden/LICENSE
usr/local/share/doc/walden/packaging.md
usr/local/share/doc/walden/service-ownership.md
usr/local/share/doc/walden/usage.md
usr/local/share/walden/catalog/v1/manifest.json
usr/local/share/walden/catalog/v1/checksums.txt
"
else
  required="
usr/bin/walden
usr/lib/walden/waldend
usr/lib/systemd/system/waldend.service
usr/share/doc/walden/README.md
usr/share/doc/walden/packaging.md
usr/share/doc/walden/service-ownership.md
usr/share/doc/walden/usage.md
usr/share/doc/walden/copyright
usr/share/doc/walden/changelog.Debian.gz
usr/share/walden/catalog/v1/manifest.json
usr/share/walden/catalog/v1/checksums.txt
"
fi

for rel in $required; do
  require_file "${payload}/${rel}" "$rel"
done

category_count=0
if [ "$kind" = "macos" ]; then
  category_dir="${payload}/usr/local/share/walden/catalog/v1/categories"
else
  category_dir="${payload}/usr/share/walden/catalog/v1/categories"
fi
if [ -d "$category_dir" ]; then
  # shellcheck disable=SC2045
  for category in "${category_dir}"/*.txt; do
    [ -f "$category" ] || continue
    category_count=$((category_count + 1))
  done
fi
[ "$category_count" -gt 0 ] || issue "the packaged catalog has no category files"

# Walk the payload as files only. Directories exist to hold them.
find "$payload" -type f ! -name '._*' >"${work}/payload-files"
while IFS= read -r file; do
  rel=$(normalise_path "${file#"$payload"/}")
  if ! path_allowed "$rel"; then
    issue "unexpected payload file: ${rel}"
  fi
done <"${work}/payload-files"

if [ "$kind" = "macos" ]; then
  require_file "${control}/preinstall" "installer preinstall script"
  require_file "${control}/postinstall" "installer postinstall script"
  if [ -f "${control}/preinstall" ]; then
    cmp -s "${control}/preinstall" "${repo_root}/packaging/macos/scripts/preinstall" ||
      issue "packaged preinstall does not match packaging/macos/scripts/preinstall"
  fi
  if [ -f "${control}/postinstall" ]; then
    cmp -s "${control}/postinstall" "${repo_root}/packaging/macos/scripts/postinstall" ||
      issue "packaged postinstall does not match packaging/macos/scripts/postinstall"
  fi

  plist="${payload}/Library/LaunchDaemons/org.scotto.waldend.plist"
  if [ -f "$plist" ]; then
    grep -q "<key>Disabled</key>" "$plist" || issue "launchd job does not declare Disabled"
    # Disabled is the next dict value after the key, and must be true so a
    # fresh installation does not start the daemon.
    awk '
      /<key>Disabled<\/key>/ { want = 1; next }
      want {
        if ($0 ~ /<true\/>/) found = 1
        exit
      }
      END { if (!found) exit 1 }
    ' "$plist" || issue "launchd job is not Disabled; a fresh install would start the daemon"
    cmp -s "$plist" "${repo_root}/packaging/macos/org.scotto.waldend.plist" ||
      issue "packaged launchd job does not match packaging/macos/org.scotto.waldend.plist"
  fi

  component=$(find "${work}/expanded" -name Bom | head -n 1)
  if [ -n "$component" ] && command -v lsbom >/dev/null 2>&1; then
    lsbom "${component}" >"${work}/bom"
    while IFS= read -r line; do
      owner=$(printf '%s\n' "$line" | awk '{ print $3 }')
      case "$owner" in
        0/0 | 0/80) ;;
        *)
          [ -n "$owner" ] || continue
          issue "BOM records a non-root owner: ${line}"
          ;;
      esac
    done <"${work}/bom"
  fi
else
  for script in preinst postinst prerm postrm; do
    require_file "${control}/${script}" "DEBIAN/${script}"
    if [ -f "${control}/${script}" ]; then
      cmp -s "${control}/${script}" "${repo_root}/packaging/linux/debian/${script}" ||
        issue "packaged ${script} does not match packaging/linux/debian/${script}"
    fi
  done
  if [ -f "${control}/postinst" ]; then
    grep -q "systemctl enable" "${control}/postinst" &&
      issue "postinst enables the service; a fresh installation must stay inactive"
    grep -q "systemctl start" "${control}/postinst" &&
      issue "postinst starts the service; a fresh installation must stay inactive"
  fi

  unit="${payload}/usr/lib/systemd/system/waldend.service"
  if [ -f "$unit" ]; then
    grep -q "^Restart=on-failure$" "$unit" ||
      issue "systemd unit does not use Restart=on-failure"
    grep -q "^ExecStart=/usr/lib/walden/waldend$" "$unit" ||
      issue "systemd unit does not run /usr/lib/walden/waldend"
    cmp -s "$unit" "${repo_root}/packaging/linux/distribution/waldend.service" ||
      issue "packaged unit does not match packaging/linux/distribution/waldend.service"
  fi
fi

if [ "$kind" = "macos" ]; then
  cli="${payload}/usr/local/bin/walden"
  daemon="${payload}/usr/local/libexec/waldend"
else
  cli="${payload}/usr/bin/walden"
  daemon="${payload}/usr/lib/walden/waldend"
fi

for binary in "$cli" "$daemon"; do
  [ -f "$binary" ] || continue
  [ -x "$binary" ] || issue "$(basename "$binary") is not executable"
  [ -s "$binary" ] || issue "$(basename "$binary") is empty"
done

expected_build=$(source_fingerprint)
expected_marker="WALDEN_BUILD_ID=${expected_build}"
expected_profile_marker="WALDEN_BUILD_PROFILE=release"
require_command strings
for binary in "$cli" "$daemon"; do
  [ -f "$binary" ] || continue
  strings "$binary" | grep -Fq "$expected_marker" ||
    issue "$(basename "$binary") was not built from this source (expected build ${expected_build})"
  strings "$binary" | grep -Fq "$expected_profile_marker" ||
    issue "$(basename "$binary") is not a release-profile binary"
done

if [ -n "$release_dir" ]; then
  [ -x "${release_dir}/walden" ] || issue "no release walden at ${release_dir}/walden"
  [ -x "${release_dir}/waldend" ] || issue "no release waldend at ${release_dir}/waldend"
  if [ -x "${release_dir}/walden" ] && [ -f "$cli" ]; then
    cmp -s "${release_dir}/walden" "$cli" ||
      issue "packaged walden is not the release binary at ${release_dir}/walden"
  fi
  if [ -x "${release_dir}/waldend" ] && [ -f "$daemon" ]; then
    cmp -s "${release_dir}/waldend" "$daemon" ||
      issue "packaged waldend is not the release binary at ${release_dir}/waldend"
  fi
fi

for candidate in \
  "${repo_root}/target/debug/walden" \
  "${repo_root}/target/debug/waldend"
do
  [ -f "$candidate" ] || continue
  for packaged in "$cli" "$daemon"; do
    [ -f "$packaged" ] || continue
    if cmp -s "$candidate" "$packaged"; then
      issue "packaged $(basename "$packaged") is identical to development output ${candidate}"
    fi
  done
done

matches_arch() {
  description=$1
  case "$kind-$arch" in
    macos-arm64)
      case "$description" in *arm64*) return 0 ;; esac
      ;;
    macos-x86_64)
      case "$description" in *x86_64*) return 0 ;; esac
      ;;
    debian-amd64)
      case "$description" in *x86-64* | *x86_64*) return 0 ;; esac
      ;;
    debian-arm64)
      case "$description" in *aarch64* | *ARM\ aarch64* | *arm64*) return 0 ;; esac
      ;;
  esac
  return 1
}

if command -v file >/dev/null 2>&1; then
  for binary in "$cli" "$daemon"; do
    [ -f "$binary" ] || continue
    description=$(file -b "$binary")
    matches_arch "$description" ||
      issue "$(basename "$binary") is not ${arch}: ${description}"
  done
fi

if [ -s "$issues" ]; then
  echo "walden: ${name} failed inspection:" >&2
  sed 's/^/  /' "$issues" >&2
  exit 1
fi

echo "==> ${name} is a complete ${kind} ${arch} release package"
