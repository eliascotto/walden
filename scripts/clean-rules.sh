#!/bin/sh
# Tear down a Walden block's transient enforcement.
#
# Development-only. Use this when the daemon has died or is stuck and has left
# hosts or firewall rules behind. It stops whatever is left of the daemon,
# strips the walden section from /etc/hosts, and removes the pf (macOS) or
# nftables (Linux) rules.
#
# It does not:
#   - delete the daemon binary or service definition (package-owned)
#   - delete the persisted block-state file (that outlives a block on purpose)
#   - uninstall a package
#
# For those, see:
#   transient rules        this script
#   persisted state        ./scripts/dev-install.sh remove --purge
#   service files/binaries ./scripts/dev-install.sh remove
#   a real package         walden-uninstall / apt remove / pacman -R
#
# A package-managed installation is refused unless `--force` is passed, because
# stopping the daemon by hand drops enforcement of an active block without
# going through Walden.
#
# Usage:
#   ./scripts/clean-rules.sh [--force]

set -eu

usage() {
  sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
}

force=no
for option in "$@"; do
  case "$option" in
    --force) force=yes ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "walden: unknown option: ${option}" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
. "${repo_root}/packaging/common/package-presence.sh"

if [ "$force" = "no" ] && walden_package_is_installed; then
  walden_refuse_package_managed "./scripts/clean-rules.sh"
fi

DAEMON_LABEL="org.scotto.waldend"

HOSTS_FILE="/etc/hosts"
WALDEN_START="#<walden>"
WALDEN_END="#</walden>"

PF_ANCHOR="org.scotto.walden"
PF_ANCHOR_FILE="/etc/pf.anchors/org.scotto.walden"
PF_CONF_FILE="/etc/pf.conf"
PF_TABLE_FILE="/var/run/waldend-blocked-ips.txt"
PF_TOKEN_FILE="/var/run/waldend-pf-token"
IPC_SOCKET="/var/run/waldend.sock"

NFT_FAMILY="inet"
NFT_TABLE="walden"
NFT_RULES_FILE="/etc/nftables.d/walden.nft"
NFT_CONF_FILE="/etc/nftables.conf"

os="$(uname -s)"

# Unloading alone would leave the service manager free to start the daemon
# again at the next boot, so it is also told not to. The installed job and unit
# are left alone: they belong to the package, and the next block needs them.
echo "==> stopping the daemon"
if [ "$os" = "Darwin" ]; then
  launchctl disable "system/${DAEMON_LABEL}" 2>/dev/null || true
  launchctl bootout "system/${DAEMON_LABEL}" 2>/dev/null || true
elif [ "$os" = "Linux" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl disable --now waldend.service 2>/dev/null || true
fi
pkill -9 -x waldend 2>/dev/null || true
rm -f "$IPC_SOCKET"

echo "==> removing the walden section from ${HOSTS_FILE}"
if [ -f "$HOSTS_FILE" ]; then
  awk -v start="$WALDEN_START" -v end="$WALDEN_END" '
    $0 == start { inside = 1; next }
    $0 == end   { inside = 0; next }
    !inside
  ' "$HOSTS_FILE" > "${HOSTS_FILE}.walden-clean"
  cat "${HOSTS_FILE}.walden-clean" > "$HOSTS_FILE"
  rm -f "${HOSTS_FILE}.walden-clean"
fi

if [ "$os" = "Darwin" ]; then
  echo "==> removing pf rules"

  if pfctl -s info >/dev/null 2>&1; then
    pfctl -a "$PF_ANCHOR" -F all 2>/dev/null || true
  fi

  if [ -f "$PF_CONF_FILE" ]; then
    sed -i '' "/^anchor \"${PF_ANCHOR}\"/d;/^load anchor \"${PF_ANCHOR}\"/d" "$PF_CONF_FILE"
    pfctl -f "$PF_CONF_FILE" 2>/dev/null || true
  fi

  rm -f "$PF_ANCHOR_FILE" "$PF_TABLE_FILE"

  if [ -f "$PF_TOKEN_FILE" ]; then
    token=$(tail -n 1 "$PF_TOKEN_FILE")
    [ -n "$token" ] && pfctl -X "$token" 2>/dev/null || true
    rm -f "$PF_TOKEN_FILE"
  fi
elif [ "$os" = "Linux" ]; then
  echo "==> removing nftables rules"

  if command -v nft >/dev/null 2>&1; then
    nft delete table "$NFT_FAMILY" "$NFT_TABLE" 2>/dev/null || true
  fi

  rm -f "$NFT_RULES_FILE"

  if [ -f "$NFT_CONF_FILE" ]; then
    sed -i "\#include \"${NFT_RULES_FILE}\"#d" "$NFT_CONF_FILE"
  fi
fi

echo "==> done"
