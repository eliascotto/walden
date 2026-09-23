#!/bin/sh
# Stand in for the platform package on a development machine.
#
# Development-only. Walden manages an installed daemon but never installs one,
# so a checkout has to be put on the machine the way a package would before
# `walden start` will do anything. This installs exactly what a package owns
# -- the daemon, its service definition, and the bundled catalog -- and
# removes exactly that again.
#
# It refuses to run against a package-managed installation unless `--force` is
# passed, because the files it writes are the same ones a package owns.
#
# Build first (`cargo build` or `cargo build --release`).
#
# Usage:
#   ./scripts/dev-install.sh install [--release] [--force]
#   ./scripts/dev-install.sh remove [--purge] [--force]
#
# What each form takes off:
#   remove          package-owned files this script installed (binaries,
#                   service definition, catalog). Transient hosts and firewall
#                   rules are left as they are; use scripts/clean-rules.sh.
#   remove --purge  also the daemon's persisted block state, which a real
#                   package removal deliberately leaves alone.

set -eu

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
}

if [ $# -eq 0 ] || [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

action="$1"
shift

case "$action" in
  install | remove) ;;
  *)
    echo "walden: unknown action: ${action}" >&2
    usage >&2
    exit 1
    ;;
esac

os="$(uname -s)"
case "$os" in
  Darwin | Linux) ;;
  *)
    echo "walden: unsupported operating system: ${os}" >&2
    exit 1
    ;;
esac

profile=debug
purge=no
force=no
for option in "$@"; do
  case "$option" in
    --release) profile=release ;;
    --purge) purge=yes ;;
    --force) force=yes ;;
    *)
      echo "walden: unknown option: ${option}" >&2
      exit 1
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$action" "$@"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)

. "${script_dir}/package-common.sh"
. "${repo_root}/packaging/common/persisted-state.sh"
. "${repo_root}/packaging/common/package-presence.sh"

if [ "$force" = "no" ] && walden_package_is_installed; then
  walden_refuse_package_managed "./scripts/dev-install.sh ${action}"
fi

DAEMON_LABEL="org.scotto.waldend"
DAEMON_BINARY="/usr/local/libexec/waldend"
LAUNCHD_JOB="/Library/LaunchDaemons/${DAEMON_LABEL}.plist"
SYSTEMD_SERVICE="waldend.service"
SYSTEMD_UNIT="/etc/systemd/system/${SYSTEMD_SERVICE}"

if [ "$os" = "Darwin" ]; then
  BUNDLED_CATALOG="/usr/local/share/walden/catalog"
  UPDATED_CATALOG="/usr/local/var/walden/catalog"
  CATALOG_GROUP="wheel"
else
  BUNDLED_CATALOG="/usr/share/walden/catalog"
  UPDATED_CATALOG="/var/lib/walden/catalog"
  CATALOG_GROUP="root"
fi

# Stops the daemon and keeps the service manager from starting it again. Safe to
# run when nothing is installed or loaded. Does not delete the service
# definition: that is a package-owned file removed only below, and only by
# this script's own install layout.
deactivate_service() {
  if [ "$os" = "Darwin" ]; then
    launchctl bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
  elif command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now "$SYSTEMD_SERVICE" 2>/dev/null || true
  fi
}

if [ "$action" = "remove" ]; then
  echo "==> stopping the daemon service"
  deactivate_service

  echo "==> removing the files this script installed"
  rm -f "$DAEMON_BINARY"
  rm -rf "$BUNDLED_CATALOG" "$UPDATED_CATALOG"
  if [ "$os" = "Darwin" ]; then
    rm -f "$LAUNCHD_JOB"
    rmdir /usr/local/share/walden /usr/local/var/walden 2>/dev/null || true
  else
    rm -f "$SYSTEMD_UNIT"
    rmdir /usr/share/walden /var/lib/walden 2>/dev/null || true
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload
  fi

  if [ "$purge" = "yes" ]; then
    walden_remove_persisted_state
  fi

  echo "==> done"
  exit 0
fi

source_binary="${repo_root}/target/${profile}/waldend"
if [ ! -x "$source_binary" ]; then
  echo "walden: ${source_binary} is missing; build it first" >&2
  exit 1
fi

# An installed daemon that is still running would keep serving the old build.
echo "==> stopping any running daemon service"
deactivate_service

echo "==> fetching the pinned walden-list snapshot"
ensure_catalog_snapshot

echo "==> installing the category catalog at ${BUNDLED_CATALOG}/v1"
install_catalog_snapshot "${BUNDLED_CATALOG}/v1"
chown -R "root:${CATALOG_GROUP}" "$BUNDLED_CATALOG"

echo "==> installing the daemon at ${DAEMON_BINARY}"
if [ "$os" = "Darwin" ]; then
  install -o root -g wheel -m 755 -d "$(dirname "$DAEMON_BINARY")"
  install -o root -g wheel -m 755 "$source_binary" "$DAEMON_BINARY"

  echo "==> installing the launchd job at ${LAUNCHD_JOB}"
  install -o root -g wheel -m 644 \
    "${repo_root}/packaging/macos/${DAEMON_LABEL}.plist" "$LAUNCHD_JOB"
else
  install -D -o root -g root -m 755 "$source_binary" "$DAEMON_BINARY"

  echo "==> installing the systemd unit at ${SYSTEMD_UNIT}"
  install -D -o root -g root -m 644 \
    "${repo_root}/packaging/linux/${SYSTEMD_SERVICE}" "$SYSTEMD_UNIT"
  systemctl daemon-reload
fi

echo "==> installed and left inactive; run 'walden start' to begin a block"
