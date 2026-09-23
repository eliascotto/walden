#!/bin/sh
# Locate Walden's persisted block-state file by the same name the daemon uses.
#
# Sourced, never run. The daemon names the file after this machine: a hidden
# SHA-256 of `waldend-settings-` plus the machine identifier. Uninstallers and
# development cleanup have to compute that name. A glob of hex-named dotfiles
# would also match files Walden does not own.
#
# The packaged macOS uninstaller and Debian postrm carry a copy of these
# functions, because they run on machines that do not have this checkout.
# Keep those copies in sync with this file.

walden_sha256_string() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | cut -d' ' -f1
  else
    echo "walden: neither sha256sum nor shasum is available" >&2
    return 1
  fi
}

walden_machine_id() {
  os=$(uname -s)
  id=""

  if [ "$os" = "Linux" ]; then
    for path in /etc/machine-id /var/lib/dbus/machine-id; do
      if [ -f "$path" ]; then
        id=$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' "$path")
        [ -n "$id" ] && break
      fi
    done
  elif [ "$os" = "Darwin" ]; then
    if command -v ioreg >/dev/null 2>&1; then
      id=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null |
        awk -F'"' '/IOPlatformSerialNumber/ && NF >= 4 { print $4; exit }')
    fi
    if [ -z "$id" ] && command -v sysctl >/dev/null 2>&1; then
      id=$(sysctl -n kern.hostuuid 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    fi
  fi

  if [ -z "$id" ]; then
    id="walden-unknown-machine"
  fi
  printf '%s\n' "$id"
}

walden_persisted_state_file_name() {
  digest=$(walden_sha256_string "waldend-settings-$1") || return 1
  printf '.%s\n' "$digest"
}

walden_persisted_state_dir() {
  if [ -n "${WALDEN_STATE_DIR:-}" ]; then
    printf '%s\n' "$WALDEN_STATE_DIR"
    return 0
  fi

  if [ "$(uname -s)" = "Darwin" ]; then
    printf '%s\n' "/usr/local/etc"
  else
    printf '%s\n' "/etc"
  fi
}

walden_persisted_state_path() {
  dir=$(walden_persisted_state_dir) || return 1
  name=$(walden_persisted_state_file_name "$(walden_machine_id)") || return 1
  printf '%s/%s\n' "$dir" "$name"
}

# Clear the immutable flag and delete this machine's state file only.
# Leaves every other file in the directory, including other 65-character
# hidden hex names, untouched.
walden_remove_persisted_state() {
  path=$(walden_persisted_state_path) || return 1
  [ -f "$path" ] || return 0

  echo "==> removing persisted block state at ${path}"
  if [ "$(uname -s)" = "Darwin" ]; then
    chflags nouchg "$path" 2>/dev/null || true
  else
    chattr -i "$path" 2>/dev/null || true
  fi
  rm -f "$path"
}
