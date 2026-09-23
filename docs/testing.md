# Testing Walden

CI is the unprivileged half of a release. Privileged checks — install a
package, start a block, edit hosts or the firewall — belong on a disposable
virtual machine, not in GitHub Actions and not on a machine you still need.

[releasing.md](releasing.md) is how a version tag publishes packages.
[packaging.md](packaging.md) is what those packages contain.

## Local checks

Run the complete non-privileged verification suite:

```console
./scripts/check.sh
```

On Linux, the same suite also runs in a container:

```console
./scripts/test-linux.sh
```

The container image runs as an unprivileged user. These tests validate the
Linux build and the project's unit and CLI integration tests, but deliberately
do not start the daemon or alter the container's hosts file and firewall.

## What CI covers

Pull requests and the default branch run `.github/workflows/ci.yml`. Version
tags run that workflow and then `.github/workflows/release.yml`:

| Check | Where | Touches |
| --- | --- | --- |
| `scripts/check.sh` | Linux amd64, Linux arm64, macOS arm64 | source, tests, rustdoc |
| `scripts/test-linux.sh` | Debian container, non-root | the same, inside the container |
| package build and `scripts/inspect-package.sh` | each supported platform and architecture | the artifact only |
| Arch recipe renderer | Linux amd64 | a source archive of the current commit |

These tests do not start the daemon and do not edit `/etc/hosts`, pf, or
nftables.

The CLI integration suite also exercises catalog selection with an absent,
empty/incomplete, and invalid update cache. It verifies silent fallback for
absence, one concise repair notice for recoverable cache damage, no raw
manifest/parser errors, and continued use of the fully verified bundled
snapshot.

Package inspection fails if a required file is missing, an unexpected file is
present, a packaged binary is not the release build, ownership is not root, or
a fresh installation would start the service.

### Unsupported combinations

These are not in the matrix, and they are not skipped inside it:

- Windows
- 32-bit architectures
- Linux without systemd and nftables
- macOS 11 and earlier
- Privileged tests that install a package, start a block, or edit hosts and
  the firewall. Those belong on a disposable virtual machine; the smoke
  checklist below is for that.

## Privileged smoke checklist

Run this on a disposable VM before shipping a version, for each platform you
actually install and exercise. Architectures that are only cross-built and not
smoke-tested are build-only — note that when you cut the release. Use the
platform's package tooling, not `scripts/dev-install.sh`.

Every release:

1. Confirm the package inspects cleanly with `scripts/inspect-package.sh`, then
   install it.
2. `walden status` must read `installed but not running` / `not active`.
   Nothing may have started `waldend`.
3. `walden setup --categories social-media --unlock-delay "30 seconds"`, then
   `walden start`. Success means the daemon durably accepted the block. Poll
   `walden status` until it shows `running` / `active`; `/etc/hosts` then has
   the `#<walden>` section and the platform firewall has Walden's rules.
4. Rerun `walden setup` with a different category or delay while the block is
   active: the file updates, custom websites in it stay, and `walden status`
   still shows the original block.
5. `walden stop`, wait for expiry: hosts and firewall rules are gone, the
   daemon is retired, package files remain.
6. Remove while inactive: package-owned files disappear; persisted state
   remains. Attempt removal during an active block: the block is not lifted
   (on macOS the uninstaller refuses without `--force`).

When packaging, the daemon, or persisted state changed — or when you want a
deeper pass:

- Upgrade while inactive (stays inactive) and while a block is active
  (deadline, blocklist, and unlock delay survive; hosts/firewall stay).
- Restart the daemon and the machine during an active block; enforcement
  resumes from persisted state with the same deadline.
- Tamper with the `#<walden>` hosts section or firewall rules; the integrity
  check restores them within about 15 seconds.
- Downgrade is unsupported: an older daemon must reject a newer state file and
  lock, not read as idle-and-clear.
- If the state-file schema changes: this release must migrate the previous
  schema; run an active-block upgrade from a build that still writes the old
  schema. Unreadable or future schema must lock. See
  [packaging.md](packaging.md).

## Development install and cleanup

To put a checkout on a machine the way a package would:

```console
./scripts/dev-install.sh install
```

These scripts are development-only. They refuse to run against a
package-managed installation unless `--force` is passed. Do not use them to
uninstall a real package.

| What to reset | Command |
| --- | --- |
| Transient hosts/firewall rules, stuck daemon | `./scripts/clean-rules.sh` |
| Files `dev-install.sh` put on the machine | `./scripts/dev-install.sh remove` |
| Persisted block state | `./scripts/dev-install.sh remove --purge` |
| A real package | [README](../README.md#removal) |

Package build scripts are in [packaging.md](packaging.md).
