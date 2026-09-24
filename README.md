# Walden

A CLI tool designed to hard block websites that are known to be harmful or addictive. Created to help users be more productive and prevent brainrot.

The book *Walden* by [Henry David Thoreau](https://en.wikipedia.org/wiki/Henry_David_Thoreau) is the first use of the term ["brain-rot"](https://en.wikipedia.org/wiki/Brain_rot).

> While England endeavours to cure the potato rot, will not any endeavour to cure the brain-rot – which prevails so much more widely and fatally?
>
> — Henry David Thoreau, Walden (1854)

⚠️ A block is irreversible until the unblock-delay is expired. Use it at your own risk!

## Quick start

[Install the package for your system](#installation). Then choose what to block and start:

```console
walden setup
walden start
```

`setup` asks which categories to block and how long to wait before unlocking.

Check progress. If rules are still applying, run this again until it shows `Block: active`:

```console
walden status
```

When you’re ready to end the block:

```console
walden stop
```

Sites remain blocked for the unlock delay you chose during setup. Once the block is active, that delay cannot be shortened or cancelled.

### Available commands

| Command | What it does |
| --- | --- |
| `walden setup` | Create or update the config (wizard or flags) |
| `walden start` | Start a block; delay locks in once rules are applied |
| `walden status` | Daemon + block state |
| `walden stop` | Request end; sites stay blocked until the delay expires |
| `walden categories` | List catalog IDs |
| `walden catalog update` | Refresh the catalog snapshot |
| `walden version --verbose` | Show CLI and daemon build identities |

Plus `walden --help` as the source of truth for flags.

## How it works

Walden blocks websites selected in a small user-owned configuration file.

The configuration defines:

- Website categories to block
- The unlock delay served after `walden stop`
- Additional websites to block (optional; added by editing the file)

After starting Walden, the active block is locked. Editing the configuration file does not change it.

Start a block with `walden start`. The delay comes from the configuration; pass
`--unlock-delay` only to override it for that block. To end it, run `walden stop`.
**The websites remain blocked for the delay fixed at start**, after which access
is restored automatically. The waiting period cannot be shortened or cancelled
once the block is active.

The block remains active after logout, restart, or ordinary app deletion.

Walden supports macOS and Linux systems that use systemd and nftables. Other
Linux service managers and firewall backends are not currently supported.

## Installation

Download the package for your system from [Releases](https://github.com/eliascotto/walden/releases) and confirm it against `SHA256SUMS`.

Walden is installed by a platform package. Installing Walden blocks nothing and starts no background process.

| System | Architectures | Install |
| --- | --- | --- |
| macOS 12 and later | `arm64`, `x86_64` | Open `walden-<version>-macos-<arch>.pkg` |
| Debian-based Linux | `amd64`, `arm64` | `sudo apt install ./walden_<version>-1_<arch>.deb` |
| Arch Linux | `x86_64`, `aarch64` | `makepkg -si` from the recipe |

Each macOS package is one architecture. The installer refuses a package built for the other one.

### Unsigned macOS packages

The macOS package is unsigned. macOS refuses to open it on the first attempt and offers only Move to Trash or Cancel. To open it anyway:

1. After the refusal, go to *System Settings* → *Privacy & Security* and choose *Open Anyway*.
2. Alternatively, right-click the package in Finder and choose Open.

Downloading over HTTPS from the project's releases and checking the published checksum is what a signature would otherwise be doing.

### Removal

macOS packages do not uninstall themselves, so the macOS installer ships
`walden-uninstall`. On Linux, use the package manager:

| System | Remove | Also delete persisted block state |
| --- | --- | --- |
| macOS | `sudo walden-uninstall` | `sudo walden-uninstall --purge` |
| Debian | `sudo apt remove walden` | `sudo apt purge walden` |
| Arch | `sudo pacman -R walden` | clear the file's immutable flag with `chattr -i` and delete it |

**Removing Walden does not lift an active block.** The hosts entries and
firewall rules stay in place, and with the daemon gone nothing removes them
when the delay expires. The macOS uninstaller refuses to run during an active
block without `--force`. Reinstalling Walden lets the daemon resume from the
persisted state that ordinary removal keeps.

## Configuration

Walk through categories and an unlock delay, then write the configuration.
Run again anytime to change those choices. Custom websites already in the
file are kept. An active block is unchanged; the next `walden start` uses
the updated file.

```console
walden setup
```

The wizard does not ask for extra websites. Add those later by editing the
file. Without a terminal, pass the same choices as flags:

```console
walden setup --categories social-media --unlock-delay "1 hour"
```

`--categories` is repeatable. Both flags are required together when skipping
prompts.

Walden uses the native user configuration directory:

- macOS: `~/Library/Application Support/Walden/config.toml`
- Linux: `$XDG_CONFIG_HOME/walden/config.toml`, falling back to
  `~/.config/walden/config.toml`

Every configuration-aware command also accepts `--config PATH`.

```toml
schema_version = 1
unlock_delay = "1 hour"

categories = [
  "social-media",
]

websites = [
  "example.com",
  "https://news.example.org/a/path",
]
```

`unlock_delay` is a positive duration such as `"1 hour"` or `"3 days"`.
`walden start` uses it unless `--unlock-delay` is passed.

Use `walden categories` to list the category IDs in the installed catalog.
Setup pre-selects `social-media` and any catalog category marked
recommended; other categories are opt-in. Website values may be hostnames or
HTTP(S) URLs; paths and ports are stripped because Walden blocks hosts, not
pages. A bare hostname also blocks the corresponding `www.` entry; other
subdomains must be listed explicitly.

When a block starts, the selected categories and custom websites become a fixed
snapshot for the daemon. Later config or catalog edits do not change it.

Category lists are published by
[walden-list](https://github.com/eliascotto/walden-list). A package installs a
verified snapshot as read-only system files:

| | Bundled with the package | Written by `walden catalog update` |
| --- | --- | --- |
| Linux | `/usr/share/walden/catalog/v1/` | `/var/lib/walden/catalog/v1/` |
| macOS | `/usr/local/share/walden/catalog/v1/` | `/usr/local/var/walden/catalog/v1/` |

Walden classifies the optional update cache as absent, incomplete, invalid, or
valid. A valid update is preferred; an absent cache silently uses the verified
package snapshot. If an interrupted or damaged update leaves an incomplete or
invalid cache, Walden uses the package snapshot and prints one concise notice
with the repair command. Raw manifest and operating-system errors are not shown
for this recoverable fallback. To install a newer published snapshot without
waiting for a Walden package:

```console
sudo walden catalog update
```

An active block keeps the list it started with; the new catalog applies to the
next block.

## Starting, stopping, and status

```console
walden start
walden stop
walden status
```

The unlock delay comes from the configuration. Pass `--unlock-delay` to override
it for this block. The command checks that Walden is installed before asking
for a password. Large category lists can take a few minutes to apply;
`walden start` returns after the daemon has durably accepted the block. The
daemon keeps applying rules in the background; use `walden status` to follow
progress and confirm when enforcement is active.

Apply progress identifies the current phase: writing hosts, resolving
hostnames with a completion percentage, or installing firewall rules. DNS
resolution uses at most 64 workers regardless of catalog size, and a stop
during apply prevents remaining queued lookups from starting.

Until rules have been applied, `walden stop` cancels the start instead of
locking in the unlock delay. After they are applied, the wait cannot be
shortened or cancelled. A second `walden stop` cannot shorten it either.

`walden status` reports the service and the block separately:

| Daemon | Meaning |
| --- | --- |
| `not installed` | Neither the daemon nor its service definition is present. |
| `installed but not running` | Both are present, and nothing is enforcing a block. |
| `starting` | The service has been activated but has not completed a valid handshake and status response. |
| `running` | The service is active and the daemon has returned a valid status response. |
| `unhealthy (...)` | Something is installed, but not enough of it to run a block on. |

While a block is active, expect `Block: active` and an unblock delay. After
`walden stop`, expect `Block: ending in …` until the delay expires.
If an active service has not answered, block state is reported as `unavailable`
rather than incorrectly claiming that no block is active.

## Further reading

| Doc | Contents |
| --- | --- |
| [docs/usage.md](docs/usage.md) | Troubleshooting, persistence, upgrades, and catalog details |
| [docs/service-ownership.md](docs/service-ownership.md) | What the package owns vs what the daemon owns at runtime |
| [docs/packaging.md](docs/packaging.md) | Package contents, build scripts, install/upgrade/remove behaviour |
| [docs/testing.md](docs/testing.md) | CI coverage and privileged smoke checks before a release |
| [docs/releasing.md](docs/releasing.md) | Maintainer process for cutting a version-tag release |

## Development

See [docs/testing.md](docs/testing.md) for CI, local checks, and development
cleanup. See [docs/packaging.md](docs/packaging.md) for building binaries and
packages.

## License

GPL-3.0. See [LICENSE](LICENSE).

Category lists bundled with Walden come from
[walden-list](https://github.com/eliascotto/walden-list) and retain the licenses
of their upstream sources. See that project's
[LICENSE-DATA.md](https://github.com/eliascotto/walden-list/blob/main/LICENSE-DATA.md)
and the installed catalog manifest for attribution. There is no single license
covering every generated category file.
