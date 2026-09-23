#!/bin/sh
# Prints a deterministic digest of every input that can change Walden's Rust
# binaries. Both build.rs and the package builders use this exact calculation,
# so a package cannot mistake an older executable for one built from this tree.

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)

sha256_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | cut -d' ' -f1
  else
    echo "walden: neither sha256sum nor shasum is available" >&2
    exit 1
  fi
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

(
  cd "$repo_root"
  {
    find src -type f -name '*.rs' -print
    find src -type f -name '*.c' -print
    for path in Cargo.toml Cargo.lock rust-toolchain.toml build.rs scripts/source-fingerprint.sh; do
      [ -f "$path" ] && printf '%s\n' "$path"
    done
  } | LC_ALL=C sort | while IFS= read -r path; do
    printf '%s  %s\n' "$(sha256_file "$path")" "$path"
  done
) | sha256_stream
