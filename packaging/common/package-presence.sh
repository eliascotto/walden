#!/bin/sh
# Detect a package-managed Walden installation.
#
# Sourced, never run. Development cleanup must not take apart files a package
# manager believes it owns unless the caller asked for that explicitly.

walden_package_is_installed() {
  os=$(uname -s)
  if [ "$os" = "Darwin" ]; then
    pkgutil --pkg-info org.scotto.walden >/dev/null 2>&1
    return $?
  fi

  if command -v dpkg-query >/dev/null 2>&1; then
    status=$(dpkg-query -W -f='${Status}' walden 2>/dev/null || true)
    case "$status" in
      *install\ ok\ installed*) return 0 ;;
    esac
  fi

  if command -v pacman >/dev/null 2>&1; then
    pacman -Q walden >/dev/null 2>&1 && return 0
  fi

  return 1
}

walden_refuse_package_managed() {
  action=$1
  cat >&2 <<EOF
walden: this machine has a package-managed Walden installation.

${action} is a development tool. It must not change files a package manager
owns unless you ask it to. Use the package's own uninstaller instead:

  macOS:  sudo walden-uninstall
  Debian: sudo apt remove walden
  Arch:   sudo pacman -R walden

Pass --force only if you intend to override the package on this machine.
EOF
  exit 1
}
