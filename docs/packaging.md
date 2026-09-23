# Packaging

Walden's software is installed by a platform package. The package owns the
executables and the service definition; the runtime owns only when the daemon
runs. [service-ownership.md](service-ownership.md) is that boundary. This
document is the packages themselves: what they contain, how they are built, and
what installing, upgrading, and removing one does.

Supported platforms and install commands for end users are in the
[README](../README.md#installation). Linux packages declare systemd and
nftables as dependencies rather than failing later.

## What a package contains

| | macOS | Debian and Arch |
| --- | --- | --- |
| CLI | `/usr/local/bin/walden` | `/usr/bin/walden` |
| Daemon | `/usr/local/libexec/waldend` | `/usr/lib/walden/waldend` |
| Service definition | `/Library/LaunchDaemons/org.scotto.waldend.plist` | `/usr/lib/systemd/system/waldend.service` |
| Category catalog | `/usr/local/share/walden/catalog/v1/` | `/usr/share/walden/catalog/v1/` |
| Uninstaller | `/usr/local/bin/walden-uninstall` | (the package manager) |
| Documentation | `/usr/local/share/doc/walden/` | `/usr/share/doc/walden/` |
| License | `/usr/local/share/doc/walden/LICENSE` | `/usr/share/doc/walden/copyright`, `/usr/share/licenses/walden/LICENSE` |

Executables are installed mode 755 and service definitions mode 644, all owned
by root. The category catalog is a verified walden-list `dist/v1` snapshot:
directories mode 0555, files mode 0444, root-owned. Nothing else is installed:
no development scripts, no build output, no tests, and no user configuration.
The documentation directory includes `README.md`, `usage.md`, `packaging.md`,
and `service-ownership.md`. The user's configuration file is created and
updated by `walden setup`, and the daemon's state by the first block.

`walden catalog update` writes a newer snapshot beside the package's own, not
into the user configuration directory:

| | Updated catalog cache |
| --- | --- |
| Linux | `/var/lib/walden/catalog/v1/` |
| macOS | `/usr/local/var/walden/catalog/v1/` |

That cache is preferred only when it verifies in full. An absent cache is
normal; an incomplete or invalid one is ignored in favor of the verified
package snapshot and produces one concise repair notice. An ordinary package
removal deletes the cache so a later install does not keep serving lists the
new package did not ship. User configuration and daemon state follow the
existing retention rules.

Linux packages install the daemon under `/usr` rather than `/usr/local`, which
belongs to the machine's administrator and which a distribution package may not
write to. That is the only difference between `packaging/linux/waldend.service`
and `packaging/linux/distribution/waldend.service`, and each ships with the
layout it describes. Every build script reads the daemon's path out of the
service definition it is shipping, so the two cannot drift apart.

## Building the packages

### Quick build

Run these commands from the repository root. First verify the checkout:

```console
./scripts/check.sh
```

To build the two release binaries for the current host without making a
package:

```console
cargo build --locked --release --bin walden --bin waldend
```

To create a package, run the command for the target operating system and
architecture. The package scripts build both binaries themselves, so the
standalone Cargo command above is optional:

```console
# Apple Silicon macOS
./scripts/package-macos.sh --arch arm64

# Intel macOS
./scripts/package-macos.sh --arch x86_64

# Debian/Ubuntu x86-64
./scripts/package-deb.sh --arch amd64

# Debian/Ubuntu ARM64
./scripts/package-deb.sh --arch arm64

# Generate an Arch Linux recipe
./scripts/package-arch.sh

# Generate the recipe and build it on an Arch Linux machine
./scripts/package-arch.sh --build
```

macOS and Debian packages should be checked with the project inspector. Replace
`<version>` with the version in `Cargo.toml` and choose the paths matching the
package architecture:

```console
./scripts/inspect-package.sh \
  dist/walden-<version>-macos-arm64.pkg \
  --release-dir target/aarch64-apple-darwin/release

./scripts/inspect-package.sh \
  dist/walden_<version>-1_amd64.deb \
  --release-dir target/x86_64-unknown-linux-gnu/release
```

Each package script builds one platform and one architecture from the checkout
it lives in and writes to `dist/`.
They fetch the walden-list snapshot `assets/catalog.lock` pins, then build
release binaries for the requested target with locked dependencies.
`--skip-build` reuses an existing build only when both binaries' embedded
source fingerprints match the current tree; stale output is rejected with a
request to rebuild. `--skip-catalog-fetch` reuses an already-vendored snapshot,
and `--output DIR` writes elsewhere.
Cross-architecture builds need the Rust target installed
(`rustup target add aarch64-unknown-linux-gnu`) and, for Linux, a matching
linker.

Set `SOURCE_DATE_EPOCH` to build reproducibly. Every timestamp that goes into a
package is taken from it rather than from the clock — the modification time of
each packaged file, the Debian changelog date, the copyright year — so two
builds of one source install identical files. Release automation sets it to the
source's commit date.

Every binary embeds the package version, protocol version, target, profile,
reproducible source epoch, and a SHA-256 fingerprint of the Rust source inputs.
Run `walden version --verbose` to see the CLI identity and, when it is running,
the daemon identity. The CLI refuses to send commands to a daemon from a
different version or source build.

The macOS `.pkg` file itself still differs between two such builds, because the
installer archive format records build metadata of its own around a payload
that is identical. Release checksums therefore describe the artifact that was
published, and are not something a rebuild is expected to reproduce.

### macOS

`pkgbuild` stages the payload and `productbuild` wraps it in a distribution
product. Building does not require root: `--ownership recommended` is what
records the payload as root-owned, and `--root-owner-group` does the same for
Debian.

Inspect the result with:

```console
pkgutil --payload-files dist/walden-<version>-macos-<arch>.pkg
installer -pkginfo -pkg dist/walden-<version>-macos-<arch>.pkg
```

The package is unsigned; user-facing Gatekeeper steps are in the
[README](../README.md#unsigned-macos-packages). The package is a distribution
product with a stable identifier
(`org.scotto.walden`), which is the shape `productsign` and notarization
expect. Signing later adds a step after `package-macos.sh` and changes nothing
about how the package is built.

### Debian

`package-deb.sh` needs `dpkg-deb` (`apt-get install dpkg-dev`, or
`brew install dpkg` on macOS). It prints `dpkg-deb --info` and
`dpkg-deb --contents` for every build, and runs `lintian` when it is installed.

### Arch

`package-arch.sh` writes `dist/arch/PKGBUILD` and `dist/arch/walden.install`.
It does not build a package unless `--build` is passed and makepkg is
available; the recipe is the deliverable.

The recipe builds from a published release tarball with a fixed checksum, not
from a branch, so the Arch User Repository builds the same source the other
packages were built from. By default the script downloads the tarball for the
version in `Cargo.toml` and checksums it, which means the release has to exist
first. `--source-archive FILE` checksums a local copy and `--sha256 CHECKSUM`
takes the checksum directly.

`.SRCINFO` is generated when makepkg is available and is required to publish to
the AUR. AUR availability is not a release blocker: the recipe can be published
after a release, and a project-maintained repository is an alternative.

## Installing

End-user install commands are in the [README](../README.md#installation). A
fresh installation is inactive: the launchd job ships disabled and is not
loaded; the systemd unit ships installed and not enabled. `walden start` is
what activates the service, and the daemon stops again when the block ends.

## Upgrading

An upgrade replaces the package's files through the platform installer and puts
back exactly what it interrupted.

- The installation is asked, before anything is replaced, whether a daemon is
  running. That answer is the only thing that decides what happens next,
  because afterwards a daemon stopped by the upgrade and one that was never
  started look the same.
- An inactive installation stays inactive. Nothing is enabled or started.
- An active daemon is restarted on the new version and resumes the block from
  its persisted state: the same deadline, the same blocklist, the same unlock
  delay. An upgrade cannot reset, shorten, or remove an active block. Replacing
  the package-bundled catalog, or running `walden catalog update`, likewise
  cannot change a block that is already running.
- The block's `/etc/hosts` entries and firewall rules are never removed during
  an upgrade. Only the process maintaining them is briefly absent, so the
  machine is not unblocked in between.
- If the daemon cannot be restarted, the upgrade fails and says so. A machine
  left with a block's rules in place and no daemon to expire them is worse than
  an upgrade that stops.

### Persisted state across versions

The daemon's state file carries its own schema version, unrelated to the
application version and the category catalog. The daemon accepts only the
version it was built for, and a file it cannot read locks it rather than being
treated as an unblocked machine — so an incompatible schema change would strand
an active block behind an upgrade.

A release that changes the schema must therefore read the previous version and
migrate it, in the same release that introduces the new one. Removing support
for a schema is a separate, later change, and only after a release that
migrates it has been out long enough to have been installed. How that is
smoke-tested is in [testing.md](testing.md).

Downgrading is not supported. An older daemon rejects a newer state file and
locks, which is the fail-closed outcome but not a useful one.

## Removing

End-user removal commands are in the [README](../README.md#removal).

Removal stops the daemon, takes away the service manager's orders to start it
again, and removes every file the package installed, including the bundled
category catalog and the updated catalog cache. On macOS there is no
system uninstaller, so the package installs one; it removes the payload, checks
the installer's own receipt for anything it missed, and then forgets the
receipt and deletes itself.

Removing Walden does not lift a block: `/etc/hosts` entries and firewall rules
stay in place, and with the daemon gone nothing removes them when the block
ends. Every removal path warns about this while a block is active.

### Persistent state

Ordinary removal keeps the daemon's persisted block state, a root-owned
dotfile under `/etc` (`/usr/local/etc` on macOS) named for this machine: a
SHA-256 of `waldend-settings-` plus the machine identifier. Uninstallers
delete that file and no other, so a glob of hidden hex-named files in `/etc`
cannot take something Walden does not own. That state is the record of a
block someone deliberately chose not to be able to cancel, so uninstalling is
not the way around it: an unfinished block resumes if Walden is installed
again. Purge commands are in the [README](../README.md#removal).

## Distribution

macOS and Debian packages are published on GitHub Releases and installed by
direct download. Signed apt repository hosting is deferred until direct
releases are stable, and a Homebrew cask or tap that installs the macOS package
is worth having but is not a release requirement. The Arch recipe is prepared
for the AUR and can be published there or from a project-maintained repository.

How version tags publish these packages, checksums, and GitHub Releases is
documented in the repository at
[docs/releasing.md](https://github.com/eliascotto/walden/blob/main/docs/releasing.md).
