#!/bin/sh
# Shared ground for the three package builders. Sourced, never run.
#
# Everything a package has to state about Walden -- its version, what it is,
# who maintains it, where it lives -- is already stated in Cargo.toml, so it is
# read from there rather than repeated in each recipe, where the copies would
# quietly disagree after the first release.

# Executable package scripts live in scripts/, so $0 locates their checkout.
# When a workflow sources this file directly, $0 is the runner's temporary
# shell script instead; GitHub Actions starts those steps in the checkout.
repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ ! -f "${repo_root}/Cargo.toml" ] &&
   [ -f "./Cargo.toml" ] && [ -f "./scripts/package-common.sh" ]; then
  repo_root=$(pwd)
fi

# A package built twice from one source should come out the same both times, so
# every timestamp a builder writes comes from here. Release automation sets it
# to the source's commit date; a local build gets the wall clock.
: "${SOURCE_DATE_EPOCH:=$(date +%s)}"
export SOURCE_DATE_EPOCH

die() {
  echo "walden: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required to build this package${2:+; $2}"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    die "neither sha256sum nor shasum is available to checksum ${1}"
  fi
}

source_fingerprint() {
  sh "${repo_root}/scripts/source-fingerprint.sh"
}

# A binary can exist at the expected target path and still have been built from
# an older checkout. The embedded source marker makes --skip-build safe: reuse
# is accepted only when both executables identify this exact source tree.
require_release_binaries_match_source() {
  release_dir="$1"
  expected=$(source_fingerprint)
  marker="WALDEN_BUILD_ID=${expected}"
  profile_marker="WALDEN_BUILD_PROFILE=release"

  require_command strings
  for binary in walden waldend; do
    path="${release_dir}/${binary}"
    [ -x "$path" ] || die "no release ${binary} at ${path}"
    if ! strings "$path" | grep -Fq "$marker"; then
      die "${path} was not built from the current source (expected build ${expected}); rebuild without --skip-build"
    fi
    if ! strings "$path" | grep -Fq "$profile_marker"; then
      die "${path} is not a release-profile binary; rebuild without --skip-build"
    fi
  done
}

# Catalog directories are mode 0555, so a plain rm -rf cannot delete them.
# Restoring the owner's write bit is what lets the staging tree go away after
# a successful build rather than turning that success into a failed cleanup.
remove_work_tree() {
  [ -n "${1:-}" ] && [ -d "$1" ] || return 0
  chmod -R u+w "$1" 2>/dev/null || true
  rm -rf "$1"
}

# One `key = "value"` from Cargo.toml's [package] table. Tables are bounded by
# the next header, so a key of the same name under [dependencies] is not
# mistaken for the package's own.
cargo_package_field() {
  awk -v key="$1" '
    /^\[/ { in_package = ($0 == "[package]"); next }
    !in_package { next }
    {
      line = $0
      sub(/^[ \t]+/, "", line)
      if (substr(line, 1, length(key)) != key) next
      rest = substr(line, length(key) + 1)
      sub(/^[ \t]+/, "", rest)
      if (substr(rest, 1, 1) != "=") next
      if (match(line, /"[^"]*"/)) {
        print substr(line, RSTART + 1, RLENGTH - 2)
        exit
      }
    }
  ' "${repo_root}/Cargo.toml"
}

# Replaces every @NAME@ in a template with the environment variable NAME. The
# replacement is literal, so a description containing a slash or an ampersand
# cannot rewrite the substitution the way it would in sed.
render_template() {
  awk '
    {
      out = ""
      rest = $0
      while (match(rest, /@[A-Z0-9_]+@/)) {
        name = substr(rest, RSTART + 1, RLENGTH - 2)
        out = out substr(rest, 1, RSTART - 1) ENVIRON[name]
        rest = substr(rest, RSTART + RLENGTH)
      }
      print out rest
    }
  ' "$1"
}

VERSION=$(cargo_package_field version)
SUMMARY=$(cargo_package_field description)
HOMEPAGE=$(cargo_package_field homepage)
LICENSE_ID=$(cargo_package_field license)
MAINTAINER=$(cargo_package_field authors)
RUST_VERSION=$(cargo_package_field rust-version)
export VERSION SUMMARY HOMEPAGE LICENSE_ID MAINTAINER RUST_VERSION

[ -n "$VERSION" ] || die "Cargo.toml does not state a version"
[ -n "$SUMMARY" ] || die "Cargo.toml does not state a description"
[ -n "$HOMEPAGE" ] || die "Cargo.toml does not state a homepage"
[ -n "$LICENSE_ID" ] || die "Cargo.toml does not state a license"
[ -n "$MAINTAINER" ] || die "Cargo.toml does not state an author to list as the maintainer"
[ -n "$RUST_VERSION" ] || die "Cargo.toml does not state a rust-version"

# The daemon goes wherever the service definition being shipped says it runs.
# Reading it out of the definition is what keeps a package from installing the
# executable somewhere its own unit or job does not look.
systemd_exec_start() {
  sed -n 's/^ExecStart=//p' "$1" | head -n 1
}

launchd_program() {
  awk '
    /<key>ProgramArguments<\/key>/ { in_program = 1; next }
    in_program && match($0, /<string>[^<]*<\/string>/) {
      print substr($0, RSTART + 8, RLENGTH - 17)
      exit
    }
  ' "$1"
}

# Release binaries for one target, which is the only build any package makes.
# Development output is never packaged: an installed daemon that was built
# without optimisations is indistinguishable from a slow one.
build_release_binaries() {
  target="$1"

  require_command cargo "install Rust from https://rustup.rs"
  if ! rustc --print target-list | grep -qx "$target"; then
    die "the Rust toolchain does not know the target ${target}"
  fi

  echo "==> building release binaries for ${target}"
  (
    cd "$repo_root" || exit 1
    cargo build --locked --release --target "$target" --bin walden --bin waldend
  ) || die "the release build for ${target} failed; run 'rustup target add ${target}' if the target is not installed"

  release_dir="${repo_root}/target/${target}/release"
  require_release_binaries_match_source "$release_dir"
}

# The documentation every package carries. The license is not here because
# each platform has its own place and format for it: a plain file on macOS, a
# Debian copyright record, an Arch licenses directory.
install_shared_documentation() {
  destination="$1"
  mode="$2"

  mkdir -p "$destination"
  for document in README.md docs/service-ownership.md docs/packaging.md docs/usage.md; do
    cp "${repo_root}/${document}" "${destination}/$(basename "$document")"
    chmod "$mode" "${destination}/$(basename "$document")"
  done
}

# A date derived from SOURCE_DATE_EPOCH rather than from now, so that two
# builds of one source write the same timestamps. BSD date reads the epoch with
# -r and GNU date with -d, and neither understands the other.
source_date() {
  date -u -r "$SOURCE_DATE_EPOCH" "$@" 2>/dev/null ||
    date -u -d "@${SOURCE_DATE_EPOCH}" "$@"
}

# The walden-list snapshot the packages install. Fetched unless the caller
# already has it or has asked not to hit the network.
: "${WALDEN_SKIP_CATALOG_FETCH:=no}"

ensure_catalog_snapshot() {
  if [ "$WALDEN_SKIP_CATALOG_FETCH" = "yes" ]; then
    [ -f "${repo_root}/vendor/walden-list/v1/manifest.json" ] ||
      die "the catalog snapshot is missing; run scripts/fetch-catalog.sh or drop --skip-catalog-fetch"
    return
  fi

  "${repo_root}/scripts/fetch-catalog.sh"
}

# Copies the vendored snapshot into DEST as ordinary files. macOS locks them
# down after the payload timestamps are rewritten; everyone else can harden
# immediately.
copy_catalog_snapshot() {
  dest="$1"
  src="${repo_root}/vendor/walden-list/v1"

  [ -f "${src}/manifest.json" ] ||
    die "no catalog snapshot at ${src}; run scripts/fetch-catalog.sh"
  [ -f "${src}/checksums.txt" ] ||
    die "no catalog snapshot at ${src}; run scripts/fetch-catalog.sh"

  mkdir -p "${dest}/categories"
  cp "${src}/manifest.json" "${src}/checksums.txt" "$dest"
  cp "${src}/categories/"*.txt "${dest}/categories/"
}

harden_catalog_snapshot() {
  dest="$1"
  [ -d "$dest" ] || die "no catalog snapshot at ${dest}"

  find "$dest" -type f -exec chmod 0444 {} +
  find "$dest" -type d -exec chmod 0555 {} +
}

install_catalog_snapshot() {
  copy_catalog_snapshot "$1"
  harden_catalog_snapshot "$1"
}
