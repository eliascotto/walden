# Using Walden

Troubleshooting, persistence, upgrades, and catalog details beyond the
[README](../README.md). [packaging.md](packaging.md) is what the package
itself contains and does. [service-ownership.md](service-ownership.md) is the
boundary between that package and the running daemon.

## Starting, stopping, and status

See the [README](../README.md) for the usual flow. This section covers edge
cases and example output.

A block is irreversible once it is active: the wait after `walden stop` cannot
be shortened or cancelled. Until rules have been applied, `walden stop`
cancels the start instead.

Large category lists can take minutes. `walden start` returns after the daemon
has durably accepted the block and continues applying rules in the background:

```text
Applying rules for 44971 websites. This can take a few minutes.
```

Use `walden status` to follow progress and confirm when enforcement is active:

```text
Daemon: running
Block: applying — resolving hostnames 27%
```

The reported phases are `writing hosts`, `resolving hostnames`, and
`installing firewall rules`. Resolution remains bounded to 64 workers even for
the largest catalog. Walden resolves eagerly because the firewall layer blocks
the addresses that hostnames resolve to in addition to writing `/etc/hosts`;
skipping this step would materially weaken the block. Progress is incremental,
and `walden stop` during apply stops new lookups from being taken from the
queue. The platform resolver cannot portably cancel lookups already in flight,
so at most the bounded worker set may finish before apply exits.

After `walden stop`:

```text
Stop requested. Run `walden status` to monitor the block.
```

If the same stop was already accepted, Walden reports the existing end time.
If no block is active, it says there is nothing to stop. These are daemon
outcomes from the stop request itself; the CLI does not issue a status request
first and guess which case occurred.

Example status output:

```text
Daemon: running
Block: active
Unblock delay: 3 days
```

```text
Daemon: running
Block: ending in 2d 4h
Ends at: 18:00:00 2026/08/26
```

```text
Daemon: installed but not running
Block: not active
```

Daemon state meanings are in the [README](../README.md#starting-stopping-and-status).
Two cases worth calling out:

- A service definition whose executable is missing, or the reverse, reads as
  `unhealthy`, not `not installed`.
- A daemon that is active but not answering on its socket reads as `starting`
  and the block reads as `unavailable`, never `not active`. `walden start`
  then reports it as running but unreachable when its readiness wait expires.

## Categories and catalog

Category lists are published by
[walden-list](https://github.com/eliascotto/walden-list). Catalog paths and
the update command are in the [README](../README.md#configuration).

`walden categories` shows the category IDs, descriptions, and the derived
catalog version of the snapshot that is currently active. The catalog version
comes from the snapshot (`generated_at` plus a short manifest digest). It is
independent of both the configuration schema and the Walden application
version.

When a block starts, the CLI expands the selected categories, merges the custom
websites, and sends a sorted, deduplicated snapshot to the root daemon. The
daemon persists that exact snapshot. Editing the configuration, updating the
catalog, or upgrading Walden therefore cannot change a running block.

`walden catalog update` downloads walden-list `dist/v1`, verifies the
manifest, checksums, and every category file, and replaces the cache only if
the whole snapshot passes. A failed download leaves the existing cache and
package snapshot untouched.

At read time the update cache has four states: absent, incomplete, invalid, or
valid. Absence is normal and silent. Incomplete and invalid caches fall back to
the fully verified package snapshot with one repair-oriented notice; the
underlying parser, manifest, and operating-system errors are kept out of the
normal CLI output. `walden start` makes this choice once before privilege
escalation and pins the verified snapshot path into the privileged invocation,
so the notice cannot be emitted a second time after `sudo`.

A Walden upgrade replaces the package-bundled snapshot. It does not write the
update cache, and it does not change an active block.

For tests and development checkouts, `WALDEN_CATALOG_DIR` points Walden at a
local snapshot, the same way `WALDEN_CONFIG_DIR` moves the configuration.
`./scripts/check.sh` uses that to read `vendor/walden-list/v1` after
`./scripts/fetch-catalog.sh` fetches the revision `assets/catalog.lock` pins.

[packaging.md](packaging.md) has more on what the package installs.

## Persistence, recovery, and upgrades

The block remains active after logout, restart, or ordinary app deletion. A
privileged system daemon enforces it, managed by launchd on macOS and systemd
on Linux.

The daemon:

- Applies entries to `/etc/hosts`.
- Installs firewall rules using pf on macOS or nftables on Linux.
- Persists the timed block so it survives the CLI closing or the machine
  restarting.
- Watches the hosts and firewall configuration and repairs removed rules.
- Removes expired rules and retires itself after the block ends.

When a block starts, the daemon writes a root-owned file under `/usr/local/etc`
on macOS and `/etc` on Linux. The filename is a hex digest of this machine's
identifier. The file is mode `0600` and marked immutable. It records whether a
block is running, its operation ID, when it ends, the blocklist, and the unlock delay. On
startup the daemon reads that file and re-asserts the block, including
repairing `/etc/hosts` and firewall rules that were removed, before it serves
any client. An unreadable or unsupported file locks the daemon rather than
being treated as an unblocked machine.

An installation sitting inactive starts nothing. Only `walden start` activates
the service. After a reboot during an active block, launchd or systemd starts
`waldend` because the service is enabled for the duration of the block and
disabled once it ends.

An upgrade replaces the package's files and puts back only what it interrupted.
An inactive installation stays inactive. An active daemon restarts on the new
version and resumes the same block: the same deadline, the same blocklist, the
same unlock delay. An upgrade cannot reset, shorten, or remove an active
block.

Downgrading is not supported. An older daemon rejects a newer state file and
locks.

[service-ownership.md](service-ownership.md) is the boundary between the
package and the running daemon.

## Removal

Removal commands and the warning that uninstall does not lift a block are in the
[README](../README.md#removal).

Purging deletes the daemon's persisted block state. It does not remove leftover
hosts or firewall rules by itself; the daemon does that when it retires a block
it still knows about.

## Troubleshooting

### Walden is not installed

```text
the Walden daemon is not installed on this system; install the Walden package for this system, then try again
```

`walden start` checks this before asking for a password. Install the package
for this system, then try again. A development checkout is not an
installation; `./scripts/dev-install.sh install` puts one on the machine the
way a package would.

### The installation is incomplete

```text
the Walden daemon service is not usable: ... reinstall the Walden package for this system
```

A service definition whose executable is missing, or an executable whose
service definition is missing, is unhealthy rather than uninstalled.
Reinstalling the package is the fix. `walden status` names the half that is
missing.

### Linux is missing nftables or systemd

```text
nftables is required for Linux support: ...
```

Linux support means systemd and nftables. Install both, or use a system that
has them. Other firewall backends are not supported.

### The daemon did not start

```text
the Walden daemon did not start; launchd reports it as not loaded
the Walden daemon did not start; systemd reports it as failed
```

The service manager was asked to start `waldend` and did not. Check the
launchd or systemd log for `waldend`. On a complete installation this is the
machine's problem to look into rather than the package's to reinstall.

### The daemon is running but unreachable

```text
the Walden daemon is running but is not answering on /var/run/waldend.sock; check the launchd log for waldend
```

The service is active and the socket is not. That is a different problem from
a daemon that never started. Check the service-manager log for `waldend`.
`walden status` reads this as `starting` until the wait for the socket runs
out.

### The configuration is rejected

Unknown category IDs, invalid website values, and an invalid or non-positive
`unlock_delay` in the configuration (or `--unlock-delay` on start) stop
startup with an error rather than being rewritten. A configuration missing
`unlock_delay` is rejected. `walden categories` is the list of IDs the
installed catalog has.

### A block survived uninstall

That is the documented behaviour. Ordinary removal keeps the daemon's
persisted state and does not lift hosts or firewall rules. Reinstall Walden to
let the daemon finish the block, or purge persisted state as described in the
[README](../README.md#removal) if you intend to discard that record.
