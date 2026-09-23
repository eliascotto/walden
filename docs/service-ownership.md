# Service ownership and lifecycle

Walden's software is installed by a platform package. Walden's runtime decides
only when the installed daemon runs. This document is the boundary between the
two, and what the runtime does on each side of it. The packages themselves —
what they contain, how they are built, and what installing, upgrading, and
removing one does — are in [packaging.md](packaging.md).

## Who owns what

### Owned by the platform package

These are read-only at runtime. Nothing in the CLI or the daemon creates,
replaces, or deletes them, on any code path, including cleanup and failure
recovery.

| File | macOS | Linux |
| --- | --- | --- |
| CLI | `/usr/local/bin/walden` | `/usr/local/bin/walden` or `/usr/bin/walden` |
| Daemon | `/usr/local/libexec/waldend` | `/usr/local/libexec/waldend`, `/usr/libexec/waldend`, or `/usr/lib/walden/waldend` |
| Service definition | `/Library/LaunchDaemons/org.scotto.waldend.plist` | any systemd unit directory, as `waldend.service` |
| Category catalog | `/usr/local/share/walden/catalog/v1/` | `/usr/share/walden/catalog/v1/` |
| Uninstaller | `/usr/local/bin/walden-uninstall` | (the package manager) |

These are what the runtime accepts. Which one each package actually uses, and
everything else a package installs, is in [packaging.md](packaging.md).

The canonical service definitions live in `packaging/`, and
`scripts/dev-install.sh` installs them the way a package will.

The daemon is looked for in several places on Linux because distributions
disagree over `/usr` and `/usr/local`. Walden reads whichever one holds the
executable rather than requiring a particular choice; the two systemd units in
`packaging/linux` differ only in the `ExecStart` that follows from that choice,
and each ships with the layout it describes. On Linux the unit is not looked
for by path at all: systemd is asked where it found it, so a distribution unit
directory and a locally installed one work the same way.

### Owned by `walden catalog update`

Created and replaced only by an explicit catalog update, never by a block.

- The updated catalog cache, under `/usr/local/var/walden/catalog/v1` on macOS
  and `/var/lib/walden/catalog/v1` on Linux. Root-owned and read-only once
  installed. Preferred over the package snapshot when it verifies. Removed
  with the package so a later install does not keep serving the previous
  update.

### Owned by the daemon

Created, maintained, and removed at runtime.

- Persisted block state, under `/usr/local/etc` on macOS and `/etc` on Linux.
  Written when a block starts, and deliberately outlives package removal.
- The IPC socket at `/var/run/waldend.sock`.
- The `#<walden>` section of `/etc/hosts`, and the pf or nftables rules for the
  active block.

### Owned by the service manager, at Walden's request

Whether the service is enabled is the one piece of installation-adjacent state
Walden changes: launchd's enable/disable override for the job, and systemd's
enablement symlinks for the unit. Both are the service manager's own records
about a package-owned definition, not the definition itself.

### Responsibilities

| Concern | Owner |
| --- | --- |
| Installation and upgrade of executables, service definitions, and the bundled catalog | Platform package |
| Refreshing the category catalog from walden-list | `walden catalog update` |
| Leaving a fresh installation inactive | Platform package |
| Activating the service for a block | Walden runtime |
| Keeping the service enabled while a block is active | Walden daemon |
| Persistent block state | Walden daemon |
| Removing block rules and retiring the service | Walden daemon |
| Removing executables and service definitions | Platform package |

## Service states

`walden status` reports the service separately from the block. State names and
example output are in the [README](../README.md#starting-stopping-and-status);
edge cases and troubleshooting are in [usage.md](usage.md).

## Starting a block

1. The configuration and the unlock delay are validated. The delay comes from
   the configuration file, or from `--unlock-delay` when that flag is passed.
2. Platform prerequisites are checked, and the installation is verified to be
   complete. Both are read-only and unprivileged, so a machine that cannot run
   a block says so before asking for a password and before anything changes.
3. The command re-runs itself under `sudo`.
4. The installed service is activated: enabled, then loaded or started.
5. Walden waits for the daemon to complete the build/protocol handshake and
   return a valid status response. Merely accepting a socket connection does
   not count as ready.
6. The block is sent with a unique operation ID. The daemon records both the
   ID and block, then replies before DNS lookups and
   rule writes finish, so the socket stays responsive.
7. `walden start` returns after durable acceptance. If the acknowledgement is
   lost, recovery succeeds only when status reports the same operation ID;
   matching counts or delays are not treated as proof. `walden status` shows
   `applying` until enforcement is active.

During apply, status reports writing hosts, hostname-resolution counts, or
firewall installation. Resolution uses a fixed pool of at most 64 workers and
does not hold the lifecycle lock while performing DNS, so status and stop
requests remain available. Cancelling an apply prevents any remaining queued
lookups from starting.

`walden status` uses the status response that established daemon readiness; it
does not probe and then issue the same request again. `walden stop` likewise
sends one direct request. Its response distinguishes an inactive block, a
cancelled apply, a newly scheduled ending, and an ending already in progress.
The socket server has a fixed worker pool and bounded pending queue, so stalled
local clients cannot create an unbounded number of daemon threads.

A missing or incomplete installation stops this at step 2. Nothing on the
machine has changed at that point, and no block has been accepted. The unlock
delay is locked in only once rules have been applied; `walden stop` during
`applying` cancels the start.

## Retiring the daemon

When a block ends, the daemon removes its rules, verifies that nothing is left,
tells the service manager not to start it again, removes its socket, and exits
cleanly.

Both service definitions are configured to treat that clean exit as the end of
the daemon and a crash as something to restart, so exiting is the second half of
retirement and not a separate stop command the daemon would have to issue
against itself.

- **macOS**: the job is disabled, which persists across reboots. It stays
  loaded and its property list stays installed.
- **Linux**: the unit is disabled, removing only the enablement symlinks. The
  unit file stays installed.

Every step can be repeated to no effect, so a retirement that fails part way
through is retried on the next tick rather than unwound. The daemon does not
retire while any part of the block is still installed, or while it cannot check.

## Restart and recovery

- The daemon reads its persisted state on startup and re-asserts a block that
  was running, before it serves any client.
- It then re-asserts that the service is enabled, so a block survives a reboot
  even if something disabled the service while it was running.
- An installation sitting inactive starts nothing. Only `walden start` activates
  the service.
- Persisted state that cannot be read locks the daemon rather than reading as an
  unblocked machine.
