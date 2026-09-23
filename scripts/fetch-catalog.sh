#!/bin/sh
# Fetch the walden-list snapshot this checkout is pinned to.
#
# Walden ships category lists it does not curate. They come from walden-list,
# are pinned by assets/catalog.lock, and land in vendor/walden-list/v1 -- the
# tree the tests read through WALDEN_CATALOG_DIR and the packages install as
# read-only system files. Nothing here is committed: the lock file is the
# record of which snapshot this source belongs to, and this script is how that
# record is turned back into files.
#
# A download that does not match the lock file is a failure, not a newer
# snapshot. Adopting one is --update, which rewrites the lock file after
# printing what changed.
#
# Usage:
#   ./scripts/fetch-catalog.sh [--force] [--output DIR]
#   ./scripts/fetch-catalog.sh --update [--ref REF]

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
lock="${repo_root}/assets/catalog.lock"

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
  echo "walden: $*" >&2
  exit 1
}

output="${repo_root}/vendor/walden-list/v1"
force=no
update=no
requested_ref=""

while [ $# -gt 0 ]; do
  case "$1" in
    --output)
      [ $# -ge 2 ] || die "--output needs a value"
      output="$2"
      shift 2
      ;;
    --ref)
      [ $# -ge 2 ] || die "--ref needs a value"
      requested_ref="$2"
      shift 2
      ;;
    --force)
      force=yes
      shift
      ;;
    --update)
      update=yes
      force=yes
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

command -v curl >/dev/null 2>&1 || die "curl is required to fetch the category catalog"

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    die "neither sha256sum nor shasum is available to verify the catalog"
  fi
}

# One `key = "value"` out of the lock file. Deliberately not a TOML parser: the
# lock file is written by this script and read by it, and keeping the format
# this simple is what lets the packaging scripts read it too.
lock_field() {
  sed -n "s/^${1}[[:space:]]*=[[:space:]]*\"\\(.*\\)\"[[:space:]]*$/\\1/p" "$lock" | head -n 1
}

[ -f "$lock" ] || die "${lock} is missing; it says which walden-list snapshot this source uses"

repository=$(lock_field repository)
ref=$(lock_field ref)
dist_path=$(lock_field dist_path)
expected_manifest=$(lock_field manifest_sha256)
expected_checksums=$(lock_field checksums_sha256)

[ -n "$repository" ] || die "${lock} does not name a repository"
[ -n "$dist_path" ] || die "${lock} does not name a dist path"
if [ -n "$requested_ref" ]; then
  [ "$update" = "yes" ] || die "--ref only applies to --update"
  ref="$requested_ref"
fi
[ -n "$ref" ] || die "${lock} does not pin a walden-list revision"

# Raw file URLs, so a fetch downloads the six category files it needs rather
# than an archive of a repository whose build inputs and tests Walden does not
# use.
case "$repository" in
  https://github.com/*)
    slug=${repository#https://github.com/}
    slug=${slug%.git}
    base="https://raw.githubusercontent.com/${slug}/${ref}/${dist_path}"
    ;;
  *) die "unsupported repository host in ${lock}: ${repository}" ;;
esac

# A snapshot already on disk that matches the lock file is the snapshot the
# lock file asks for, and re-downloading it would only make the build depend on
# the network again.
if [ "$force" = "no" ] && [ -f "${output}/manifest.json" ] && [ -f "${output}/checksums.txt" ]; then
  if [ "$(sha256_of "${output}/manifest.json")" = "$expected_manifest" ] &&
    [ "$(sha256_of "${output}/checksums.txt")" = "$expected_checksums" ]; then
    echo "==> catalog snapshot is already at ${ref}"
    exit 0
  fi
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/walden-catalog-fetch.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM
staging="${work}/v1"
mkdir -p "${staging}/categories"

download() {
  echo "==> fetching ${1}"
  curl --fail --location --silent --show-error --proto '=https' \
    --max-redirs 3 --retry 2 --output "${staging}/${1}" "${base}/${1}" ||
    die "could not download ${base}/${1}"
}

verify() {
  actual=$(sha256_of "${staging}/${1}")
  if [ "$actual" != "$2" ]; then
    die "${1} does not match the expected checksum
  expected ${2}
  actual   ${actual}
Either the pinned snapshot was rewritten upstream, or the download was
tampered with. Adopt a reviewed snapshot with --update rather than editing
the lock file by hand."
  fi
}

download manifest.json
download checksums.txt

if [ "$update" = "no" ]; then
  [ -n "$expected_manifest" ] || die "${lock} does not record a manifest checksum"
  [ -n "$expected_checksums" ] || die "${lock} does not record a checksums checksum"
  verify manifest.json "$expected_manifest"
  verify checksums.txt "$expected_checksums"
fi

# checksums.txt is walden-list's own record of the distribution, so it decides
# which category files belong to this snapshot. The runtime cross-checks it
# against the manifest; a fetch only has to bring down what it lists.
while read -r digest path; do
  [ -n "${path:-}" ] || continue
  case "$path" in
    categories/*[!a-z0-9./-]* | *..*) die "checksums.txt names an unsafe path: ${path}" ;;
    categories/*.txt) ;;
    *) die "checksums.txt names an unexpected file: ${path}" ;;
  esac

  download "$path"
  verify "$path" "$digest"
done <"${staging}/checksums.txt"

if [ "$update" = "yes" ]; then
  manifest_sha=$(sha256_of "${staging}/manifest.json")
  checksums_sha=$(sha256_of "${staging}/checksums.txt")

  if [ "$manifest_sha" = "$expected_manifest" ] && [ "$checksums_sha" = "$expected_checksums" ]; then
    echo "==> ${ref} publishes the snapshot already pinned; nothing to update"
  else
    tmp_lock="${work}/catalog.lock"
    sed \
      -e "s|^ref = .*|ref = \"${ref}\"|" \
      -e "s|^manifest_sha256 = .*|manifest_sha256 = \"${manifest_sha}\"|" \
      -e "s|^checksums_sha256 = .*|checksums_sha256 = \"${checksums_sha}\"|" \
      "$lock" >"$tmp_lock"
    cp "$tmp_lock" "$lock"
    echo "==> pinned ${ref} in ${lock}"
  fi
fi

mkdir -p "$(dirname "$output")"
rm -rf "${output}.previous"
if [ -d "$output" ]; then
  mv "$output" "${output}.previous"
fi
mv "$staging" "$output"
rm -rf "${output}.previous"

echo "==> vendored the ${ref} catalog snapshot in ${output}"
awk '{ printf "    %-16s %s\n", $2, $1 }' "${output}/checksums.txt"
