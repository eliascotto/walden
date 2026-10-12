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

Firewall query tests use harmless commands that emit separate stdout and stderr
streams. They verify that successful diagnostics cannot corrupt PF table entries
or nftables JSON, failures retain diagnostic messages, and PF enable tokens are
still read from stderr.

IPC tests use local socket pairs to cover frame-size boundaries, oversized
frames with and without a newline, slow-drip deadlines, incomplete frames,
and consecutive frames. A Start request containing every bundled category
also round-trips through the same size-limited reader and writer.

Atomic-write tests force a rename failure, repair the destination, and retry
in the same process. They also check temporary-file cleanup, stale files,
concurrent writes, and private-file permissions in temporary directories.

Lifecycle tests inject complete and partial DNS failures to check that existing
firewall coverage survives and resolution retries before the normal cache TTL.
They also cover resume without an address cache, the first apply with failed
lookups, failed persistence after installation, and firewall installation
failures that must not replace the cache.

Stop-persistence failures leave the current apply generation and progress intact.
Tests pause a worker during resolution and verify that it still completes after
a rejected stop, and that retrying a stop after persistence recovers cancels once.

Cleanup regression tests cover failure followed by recovery and a new start
after daemon restart, truthful status while `block_is_running` is false,
failed final-state persistence, worker cancellation, missing state with orphaned
rules, and retirement races. PF tests inject cleanup operations and query output;
they check scoped rule/table flushes, empty detached anchors, partial failure,
failed reload recovery after disk changes, and repeated cleanup of absent anchors.
The macOS parser test invokes `pfctl` with `-n` to parse native output without
loading rules. A local UDP blackhole tests the native resolver's timeout;
it does not change system DNS settings. CLI tests cover watch snapshots,
operation-specific waiting, apply failure, and sudo exit-status forwarding.

PF verification also covers normalization rules before the first filtering
anchor, genuine earlier filtering rules, and query errors. Apply regressions
cover validation before DNS, action-required errors, candidate reuse after a
firewall failure, separate current/previous stages, and consistent DNS units.
Resolver tests cover positive/negative caching, selective temporary retries,
backoff, retained address-family coverage, and draining cancelled workers.

The CLI integration suite also exercises catalog selection with an absent,
empty/incomplete, and invalid update cache. It verifies silent fallback for
absence, one concise repair notice for recoverable cache damage, no raw
manifest/parser errors, and continued use of the fully verified bundled
snapshot.

Every CLI subprocess in that suite has a ten-second execution limit. On timeout,
the test kills the subprocess and its process group and includes captured stdout
and stderr in the failure. Unlock-delay selection is tested in the CLI unit
tests before service inspection or elevation, so a valid configuration cannot
start an installed daemon or wait for a sudo password during that regression
test.

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

For the cleanup/output fixes:

- Run `walden start --wait` with a one-second unlock delay. It must show
  acceptance followed by `active`; it must not expire until `walden stop`.
- Run `walden status` repeatedly, or `walden status --verbose` for details. After `stop`,
  expect `ending`, then `cleaning up` when observable, then an inactive daemon
  and block. A very short phase may complete between one-second snapshots.
- Start a second block after cleanup; it must succeed without restarting or
  removing the package.
- On a disposable VM, inject a temporary failure during PF cleanup. Verbose status
  must show `cleanup failed` and the actual error, and a rejected start must
  not announce application or print a second sudo error. Repair the failure;
  cleanup must recover automatically and allow a subsequent start.
- Upgrade with cleanup pending; the saved retirement marker must resume cleanup.
- Confirm the system-log command printed by verbose status shows daemon errors
  on macOS. These privileged checks remain manual VM checks.

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

### Internal status monitoring

`walden status --watch --verbose` is an internal developer diagnostics option.
It polls once per second and prints changed snapshots until Ctrl+C. It remains
accepted by the parser but is hidden from normal help and user documentation.
User-facing guidance should recommend `walden status`, with `--verbose` when
technical details are needed.

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
