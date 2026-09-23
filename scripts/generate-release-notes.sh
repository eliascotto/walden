#!/bin/sh
# Write the GitHub Release notes for this version to stdout.
#
# The notes identify every supported package, say that the macOS packages are
# unsigned, and point at the same installation and upgrade guidance the
# packages themselves install. They are generated rather than hand-edited so a
# re-run of a release cannot pick up a stale draft.
#
# Usage:
#   ./scripts/generate-release-notes.sh [--prerelease]

set -eu

. "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/package-common.sh"

prerelease=no
while [ $# -gt 0 ]; do
  case "$1" in
    --prerelease)
      prerelease=yes
      shift
      ;;
    *) die "unknown option: $1" ;;
  esac
done

macos_arm64="walden-${VERSION}-macos-arm64.pkg"
macos_x86_64="walden-${VERSION}-macos-x86_64.pkg"
deb_amd64="walden_${VERSION}-1_amd64.deb"
deb_arm64="walden_${VERSION}-1_arm64.deb"
source_archive="walden-${VERSION}.tar.gz"
checksums="SHA256SUMS"
download="${HOMEPAGE}/releases/download/v${VERSION}"

if [ "$prerelease" = "yes" ]; then
  cat <<EOF
**This is a pre-release.** It is published for testing and is not a stable
Walden release. Do not use it as a production install unless you intend to.

EOF
fi

cat <<EOF
Walden ${VERSION} packages for every supported platform and architecture.

## Installation

Download the package for your system, then confirm it against \`SHA256SUMS\`.

| System | Architecture | Package |
| --- | --- | --- |
| macOS 12 and later | arm64 | [\`${macos_arm64}\`](${download}/${macos_arm64}) |
| macOS 12 and later | x86_64 | [\`${macos_x86_64}\`](${download}/${macos_x86_64}) |
| Debian-based Linux | amd64 | [\`${deb_amd64}\`](${download}/${deb_amd64}) |
| Debian-based Linux | arm64 | [\`${deb_arm64}\`](${download}/${deb_arm64}) |
| Source | — | [\`${source_archive}\`](${download}/${source_archive}) |

Checksums: [\`${checksums}\`](${download}/${checksums})

\`\`\`console
# Debian-based Linux
sudo apt install ./${deb_amd64}

# Arch Linux, from the recipe generated after this release
makepkg -si
\`\`\`

The macOS package is opened in Finder or installed with
\`sudo installer -pkg ${macos_arm64} -target /\`.

### Unsigned macOS packages

**The macOS packages are unsigned.** macOS refuses to open them on the first
attempt and offers only Move to Trash or Cancel. Opening one anyway is a
deliberate trust decision: after the refusal, go to System Settings → Privacy
& Security and choose Open Anyway. Alternatively, right-click the package in
Finder and choose Open. Checking the published checksum is what a signature
would otherwise be doing.

## Supported systems

- macOS 12 and later, \`arm64\` and \`x86_64\`. Each package is one architecture;
  the installer refuses the other.
- Linux with systemd and nftables, \`amd64\`/\`x86_64\` and \`arm64\`/\`aarch64\`.
  Other service managers and firewall backends are not supported.

A fresh installation is inactive. The daemon runs only while a block does.

## Using Walden

The [README](${HOMEPAGE}/blob/v${VERSION}/README.md) covers install, setup,
starting, stopping, status, categories, and removal.
[usage.md](${HOMEPAGE}/blob/v${VERSION}/docs/usage.md) covers troubleshooting,
persistence, upgrades, and catalog details.

## Upgrading

An upgrade replaces the package's files and puts back only what it interrupted.
An inactive installation stays inactive. An active daemon restarts on the new
version and resumes the same block: the same deadline, the same blocklist, the
same unlock delay. An upgrade cannot reset, shorten, or remove an active block.

Downgrading is not supported.

## Known limitations

- macOS packages are unsigned, as above.
- Linux other than systemd and nftables is not supported.
- There is no signed apt repository yet; Debian packages are installed from
  this release.
- A Homebrew tap is not part of this release.
- Removing Walden does not lift an active block. The hosts entries and
  firewall rules stay, and the daemon's persisted state is kept so an
  unfinished block resumes if Walden is installed again.

See [packaging.md](${HOMEPAGE}/blob/v${VERSION}/docs/packaging.md) for
ownership, purge behaviour, and how the packages are built, and
[testing.md](${HOMEPAGE}/blob/v${VERSION}/docs/testing.md) for privileged
smoke checks.
EOF
