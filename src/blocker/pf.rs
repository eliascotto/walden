// pf anchor/table blocking on macOS.

use anyhow::Context;
use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::Command;

use crate::blocker::common::{
    AddressRange, ConfigStatus, normalize_address_ranges, resolved_address_ranges,
};
use crate::common;
use crate::resolver::ResolvedAddr;

// pf anchor/table names and the files pfctl reads them from
const PF_ANCHOR: &str = "org.scotto.walden";
const PF_TABLE: &str = "walden_blocked";
const PF_ANCHOR_DIR: &str = "/etc/pf.anchors";
const PF_ANCHOR_FILE: &str = "/etc/pf.anchors/org.scotto.walden";
const PF_CONF_FILE: &str = "/etc/pf.conf";
const PF_TABLE_FILE: &str = "/var/run/waldend-blocked-ips.txt";
const PF_TOKEN_FILE: &str = "/var/run/waldend-pf-token";

#[derive(Debug)]
pub struct ConfigurationError(pub String);

impl std::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ConfigurationError {}

// An empty, persistent table plus a rule that blocks anything bound for it.
// `return` (rather than `drop`) sends an immediate RST/unreachable back to
// the blocked app instead of leaving it to hang until its own timeout, and
// `quick` stops evaluation here so a later `pass` cannot undo the block.
//
// The table is declared empty and filled by `sync_table`. Naming a `file` here
// instead would abort the whole ruleset load whenever that file is missing,
// taking the system's pf configuration down with it, not just this anchor.
fn pf_anchor_rules() -> String {
    format!(
        "table <{PF_TABLE}> persist\n\
block return out quick from any to <{PF_TABLE}>\n"
    )
}

fn to_table_entry(addr: &ResolvedAddr) -> String {
    match addr {
        ResolvedAddr::Host(ip) => ip.to_string(),
        ResolvedAddr::Network(ip, prefix) => format!("{ip}/{prefix}"),
    }
}

fn run_pfctl_output(args: &[&str], what: &str) -> anyhow::Result<std::process::Output> {
    run_pfctl_output_with(Command::new("pfctl").args(args), what)
}

fn run_pfctl_output_with(
    command: &mut Command,
    what: &str,
) -> anyhow::Result<std::process::Output> {
    let output = command
        .output()
        .with_context(|| format!("failed to run pfctl: {what}"))?;

    let diagnostic = String::from_utf8_lossy(&output.stderr);
    let lower = diagnostic.to_ascii_lowercase();
    if !output.status.success()
        && (lower.contains("permission denied") || lower.contains("operation not permitted"))
    {
        return Err(
            ConfigurationError(format!("pfctl {what} failed: {}", diagnostic.trim())).into(),
        );
    }

    anyhow::ensure!(
        output.status.success(),
        "pfctl {what} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );

    Ok(output)
}

// Keep successful-command notices out of table and status query output.
fn run_pfctl(args: &[&str], what: &str) -> anyhow::Result<String> {
    run_pfctl_with(Command::new("pfctl").args(args), what)
}

fn run_pfctl_with(command: &mut Command, what: &str) -> anyhow::Result<String> {
    let output = run_pfctl_output_with(command, what)?;

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// The pf enable reference count lives in the kernel and resets on reboot, so a
// token from an earlier boot is worthless. Recording the boot session next to
// the token makes that detectable without relying on /var/run being cleared.
fn boot_session_id() -> Option<String> {
    let output = Command::new("sysctl")
        .args(["-n", "kern.bootsessionuuid"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!id.is_empty()).then_some(id)
}

fn pf_is_enabled() -> bool {
    run_pfctl(&["-s", "info"], "query pf status")
        .map(|info| {
            info.lines()
                .any(|line| line.trim().starts_with("Status: Enabled"))
        })
        .unwrap_or(false)
}

// The token we currently hold, or None when there is nothing usable to release:
// no file, or a token left over from a previous boot. A boot session that
// cannot be determined proves nothing either way, so the token is kept.
fn current_token() -> Option<String> {
    let contents = fs::read_to_string(PF_TOKEN_FILE).ok()?;
    let (stored_boot_id, token) = contents.split_once('\n')?;
    let token = token.trim();

    if token.is_empty() {
        return None;
    }

    match (boot_session_id(), stored_boot_id.trim()) {
        (Some(current), stored) if !stored.is_empty() && current != stored => None,
        _ => Some(token.to_string()),
    }
}

fn parse_pf_reference_token(output: &std::process::Output) -> anyhow::Result<String> {
    // pfctl reports its enable token on stderr; accept stdout as well without
    // joining streams, which could merge an unterminated notice with the token.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stderr
        .lines()
        .chain(stdout.lines())
        .find_map(|line| {
            line.trim()
                .strip_prefix("Token :")
                .map(str::trim)
                .filter(|token| !token.is_empty())
        })
        .map(str::to_owned)
        .context("pfctl -E returned no token")
}

// `pfctl -E` enables pf and increments its reference count, handing back a
// token. The reference is held for the whole block, so this only records it.
fn acquire_pf_reference() -> anyhow::Result<()> {
    let output = run_pfctl_output(&["-E"], "acquire PF reference")?;
    let token = parse_pf_reference_token(&output)?;

    let boot_id = boot_session_id().unwrap_or_default();

    common::write_atomically(PF_TOKEN_FILE, format!("{boot_id}\n{token}\n").as_bytes())
        .with_context(|| format!("failed to write {PF_TOKEN_FILE}"))
}

// pf has to stay enabled for the whole block, so the reference is taken once
// and kept. Re-acquires when the recorded token is stale or when pf was turned
// off behind our back; the abandoned reference only keeps pf on, which is the
// safe direction to fail in.
fn ensure_pf_reference() -> anyhow::Result<()> {
    if current_token().is_some() && pf_is_enabled() {
        return Ok(());
    }

    acquire_pf_reference()
}

// Best effort: pfctl rejects a token it no longer knows about, and that must
// not leave the file behind, since a leftover token file would make every
// later release attempt fail the same way.
fn release_pf_reference() -> anyhow::Result<()> {
    if let Some(token) = current_token()
        && let Err(err) = run_pfctl(&["-X", &token], "release PF reference")
    {
        crate::daemon_log!("walden: {err}");
    }

    common::remove_file_if_present(PF_TOKEN_FILE)?;
    Ok(())
}

// The two lines /etc/pf.conf needs: one to evaluate the anchor, one to load its
// rules from disk at boot.
fn anchor_lines() -> (String, String) {
    let anchor_line = format!("anchor \"{PF_ANCHOR}\"");
    let load_line = format!("load anchor \"{PF_ANCHOR}\" from \"{PF_ANCHOR_FILE}\"");
    (anchor_line, load_line)
}

fn pf_conf_has_anchor() -> anyhow::Result<ConfigStatus> {
    let conf = fs::read_to_string(PF_CONF_FILE)
        .with_context(|| format!("failed to read {PF_CONF_FILE}"))?;

    let (anchor_line, load_line) = anchor_lines();

    let has_anchor_line = conf.lines().any(|line| line.trim() == anchor_line);
    let has_load_line = conf.lines().any(|line| line.trim() == load_line);

    if has_anchor_line && has_load_line {
        Ok(ConfigStatus::Present)
    } else if has_anchor_line || has_load_line || conf.lines().any(is_own_config_line) {
        Ok(ConfigStatus::Partial)
    } else {
        Ok(ConfigStatus::Absent)
    }
}

fn parse_parent_anchor_is_loaded(output: &str) -> bool {
    let expected = format!("anchor \"{PF_ANCHOR}\" all");

    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .find(|line| {
            !matches!(
                line.split_whitespace().next(),
                Some(
                    "scrub"
                        | "scrub-anchor"
                        | "nat"
                        | "nat-anchor"
                        | "rdr"
                        | "rdr-anchor"
                        | "binat"
                        | "binat-anchor"
                        | "dummynet"
                        | "dummynet-anchor"
                )
            )
        })
        .is_some_and(|line| line.split_whitespace().eq(expected.split_whitespace()))
}

// Whether the *running* ruleset evaluates our anchor. /etc/pf.conf can name the
// anchor while the loaded ruleset does not, if something flushed or replaced
// the ruleset after boot.
fn anchor_is_loaded() -> anyhow::Result<bool> {
    anchor_is_loaded_with(Command::new("pfctl").args(["-s", "rules"]))
}

fn anchor_is_loaded_with(command: &mut Command) -> anyhow::Result<bool> {
    let output = run_pfctl_output_with(command, "list parent filtering rules")?;
    Ok(parse_parent_anchor_is_loaded(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn pf_conf_with_anchor(conf: &str) -> String {
    let (anchor_line, load_line) = anchor_lines();
    let load_prefix = format!("load anchor \"{PF_ANCHOR}\"");

    // Remove our previous entries before inserting the pair again.
    let mut lines: Vec<&str> = conf
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.starts_with(anchor_line.as_str()) && !line.starts_with(load_prefix.as_str())
        })
        .collect();

    // Keep options and translation rules before filtering rules.
    let position = lines
        .iter()
        .position(|line| {
            matches!(
                line.split_whitespace().next(),
                Some("anchor" | "block" | "pass" | "antispoof")
            )
        })
        .unwrap_or(lines.len());

    lines.insert(position, &anchor_line);
    lines.push(&load_line);

    let mut updated = lines.join("\n");
    updated.push('\n');
    updated
}

fn ensure_pf_conf_anchor() -> anyhow::Result<bool> {
    let conf = fs::read_to_string(PF_CONF_FILE)
        .with_context(|| format!("failed to read {PF_CONF_FILE}"))?;

    let updated = pf_conf_with_anchor(&conf);

    if updated == conf {
        return Ok(false);
    }

    common::write_atomically(PF_CONF_FILE, updated.as_bytes())
        .with_context(|| format!("failed to update {PF_CONF_FILE}"))?;

    Ok(true)
}

// Drops our lines from /etc/pf.conf without touching the running ruleset.
// Matches on the anchor name alone so lines written by an older install, which
// may name a different path, are removed too.
fn is_own_config_line(line: &str) -> bool {
    let line = line.trim();
    line.starts_with(&format!("anchor \"{PF_ANCHOR}\""))
        || line.starts_with(&format!("load anchor \"{PF_ANCHOR}\""))
}

fn strip_anchor_from_pf_conf() -> anyhow::Result<bool> {
    let conf = fs::read_to_string(PF_CONF_FILE)
        .with_context(|| format!("failed to read {PF_CONF_FILE}"))?;

    let Some(updated) = configuration_without_own_anchor(&conf) else {
        return Ok(false);
    };
    common::write_atomically(PF_CONF_FILE, updated.as_bytes())
        .with_context(|| format!("failed to update {PF_CONF_FILE}"))?;
    Ok(true)
}

fn configuration_without_own_anchor(conf: &str) -> Option<String> {
    if !conf.lines().any(is_own_config_line) {
        return None;
    }
    let mut updated = conf
        .lines()
        .filter(|line| !is_own_config_line(line))
        .collect::<Vec<&str>>()
        .join("\n");
    updated.push('\n');

    Some(updated)
}

// Brings the ruleset back to the blocking state from whatever state it is in:
// rewrites the anchor file, makes sure /etc/pf.conf names the anchor, reloads
// the main ruleset when the anchor is not actually live, and reloads the
// anchor's own rules. Calling this repeatedly is what repairs a ruleset that
// has been flushed or edited.
fn ensure_anchor_wired() -> anyhow::Result<()> {
    fs::create_dir_all(PF_ANCHOR_DIR)
        .with_context(|| format!("failed to create {PF_ANCHOR_DIR}"))?;
    common::write_atomically(PF_ANCHOR_FILE, pf_anchor_rules().as_bytes())
        .with_context(|| format!("failed to write {PF_ANCHOR_FILE}"))?;

    let conf_changed = ensure_pf_conf_anchor()?;

    if conf_changed || !anchor_is_loaded()? {
        run_pfctl(&["-n", "-f", PF_CONF_FILE], "validate pf.conf")
            .map_err(|err| ConfigurationError(format!("invalid PF configuration: {err:#}")))?;
        run_pfctl(&["-f", PF_CONF_FILE], "load pf.conf")?;
    }

    if !anchor_is_loaded()? {
        return Err(ConfigurationError("Walden's unrestricted anchor must precede other live PF filtering rules; inspect the parent rules with `sudo pfctl -s rules`".into()).into());
    }

    // Recreates the table and the block rule inside the anchor.
    run_pfctl(
        &["-a", PF_ANCHOR, "-f", PF_ANCHOR_FILE],
        "load anchor rules",
    )?;

    Ok(())
}

// Replaces the table using a file instead of argv, avoiding argument limits
// for large blocklists. An empty list clears the table.
fn sync_table(entries: &[String]) -> anyhow::Result<()> {
    fs::write(PF_TABLE_FILE, entries.join("\n"))
        .with_context(|| format!("failed to write {PF_TABLE_FILE}"))?;

    run_pfctl(
        &[
            "-a",
            PF_ANCHOR,
            "-t",
            PF_TABLE,
            "-T",
            "replace",
            "-f",
            PF_TABLE_FILE,
        ],
        "table replace",
    )?;
    Ok(())
}

fn parse_table_entries(output: &str) -> anyhow::Result<Vec<AddressRange>> {
    let mut ranges = Vec::new();

    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let range = if let Some((addr, prefix)) = line.split_once('/') {
            let addr = addr
                .parse::<IpAddr>()
                .with_context(|| format!("invalid address in pf table: {line}"))?;
            let prefix = prefix
                .parse::<u8>()
                .with_context(|| format!("invalid prefix in pf table: {line}"))?;
            AddressRange::network(addr, prefix)
                .with_context(|| format!("invalid network in pf table: {line}"))?
        } else {
            AddressRange::host(
                line.parse::<IpAddr>()
                    .with_context(|| format!("invalid address in pf table: {line}"))?,
            )
        };
        ranges.push(range);
    }

    Ok(normalize_address_ranges(ranges))
}

// Reads back the table's effective coverage. pfctl normalizes network entries,
// so both sides are converted to ranges before they are compared.
fn table_matches(resolved_addrs: &BTreeSet<ResolvedAddr>) -> anyhow::Result<bool> {
    let output = run_pfctl(
        &["-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "show"],
        "table show",
    )?;
    let active = parse_table_entries(&output)?;
    let expected = resolved_address_ranges(resolved_addrs)
        .context("resolved block list contains an invalid network")?;

    Ok(active == expected)
}

fn parse_anchor_rules_match(output: &str) -> bool {
    let expected = format!("block return out quick from any to <{PF_TABLE}>");

    let actual_words = output.split_whitespace().collect::<Vec<_>>();
    let expected_words = expected.split_whitespace().collect::<Vec<_>>();

    actual_words == expected_words
}

fn anchor_rules_match() -> anyhow::Result<bool> {
    let output = run_pfctl_output(&["-a", PF_ANCHOR, "-s", "rules"], "list anchor rules")?;

    let rules = String::from_utf8_lossy(&output.stdout);

    Ok(parse_anchor_rules_match(&rules))
}

// Whether the block is still installed, checked from the outside in: pf turned
// on, the anchor named in /etc/pf.conf, its rules file on disk, the anchor live
// in the running ruleset, and addresses in its table. Partial means something
// survived, which `block` repairs the same way it repairs Absent -- the
// distinction is kept for the log, not for the decision.
pub fn status(resolved_addrs: &BTreeSet<ResolvedAddr>) -> ConfigStatus {
    if !pf_is_enabled() {
        return ConfigStatus::Absent;
    }

    match pf_conf_has_anchor() {
        Ok(ConfigStatus::Present) => {}
        Ok(ConfigStatus::Partial) => return ConfigStatus::Partial,
        Ok(ConfigStatus::Absent) | Err(_) => return ConfigStatus::Absent,
    }

    if !Path::new(PF_ANCHOR_FILE).exists() || !anchor_is_loaded().unwrap_or(false) {
        return ConfigStatus::Absent;
    }

    match anchor_rules_match() {
        Ok(true) => {}
        Ok(false) | Err(_) => return ConfigStatus::Partial,
    }

    match table_matches(resolved_addrs) {
        Ok(true) => ConfigStatus::Present,
        // A table that cannot be verified is repaired rather than trusted.
        Ok(false) | Err(_) => ConfigStatus::Partial,
    }
}

// Whether any trace of an earlier block is still installed. Unlike `status`
// this asks nothing about the block list, so it can be answered before one is
// known -- at startup, when the daemon has to tell an interrupted teardown
// from a clean machine.
pub fn has_leftovers() -> anyhow::Result<bool> {
    Ok(!cleanup_leftovers()?.is_empty())
}

fn parent_references_anchor() -> anyhow::Result<bool> {
    let rules = run_pfctl(&["-s", "rules"], "list parent rules")?;
    // Cleanup must find references in any position, including older installs.
    Ok(rules
        .lines()
        .any(|line| line.trim().starts_with(&format!("anchor \"{PF_ANCHOR}\""))))
}

pub fn cleanup_leftovers() -> anyhow::Result<Vec<String>> {
    let mut remaining = Vec::new();
    let mut errors = Vec::new();
    match pf_conf_has_anchor() {
        Ok(ConfigStatus::Absent) => {}
        Ok(_) => remaining.push(format!("Walden anchor in {PF_CONF_FILE}")),
        Err(err) => errors.push(format!("inspect {PF_CONF_FILE}: {err:#}")),
    }

    for file in [PF_ANCHOR_FILE, PF_TABLE_FILE, PF_TOKEN_FILE] {
        match Path::new(file).try_exists() {
            Ok(true) => remaining.push(file.into()),
            Ok(false) => {}
            Err(err) => errors.push(format!("inspect {file}: {err:#}")),
        }
    }

    match parent_references_anchor() {
        Ok(true) => remaining.push("live PF reference to Walden's anchor".into()),
        Ok(false) => {}
        Err(err) => errors.push(format!("inspect parent PF rules: {err:#}")),
    }
    match loaded_anchor_exists_with(Command::new("pfctl").args(["-s", "Anchors"])) {
        Ok(true) => match anchor_contents_leftovers(run_pfctl) {
            Ok(contents) => remaining.extend(contents),
            Err(err) => errors.push(format!("{err:#}")),
        },
        Ok(false) => {}
        Err(err) => errors.push(format!("inspect Walden PF anchor: {err:#}")),
        // A detached, empty anchor cannot block traffic. Merely listing its
        // name must not keep the daemon in retirement forever.
    }
    if !errors.is_empty() {
        if !remaining.is_empty() {
            errors.push(format!("remaining: {}", remaining.join(", ")));
        }
        anyhow::bail!(errors.join("; "));
    }
    Ok(remaining)
}

fn anchor_contents_leftovers(
    mut run: impl FnMut(&[&str], &str) -> anyhow::Result<String>,
) -> anyhow::Result<Vec<String>> {
    let mut remaining = Vec::new();
    let mut errors = Vec::new();
    for (modifier, description) in [
        ("rules", "PF rules in Walden's anchor"),
        ("Tables", "PF tables in Walden's anchor"),
    ] {
        match run(&["-a", PF_ANCHOR, "-s", modifier], description) {
            Ok(contents) if !contents.trim().is_empty() => remaining.push(description.into()),
            Ok(_) => {}
            Err(err) => errors.push(format!("{description}: {err:#}")),
        }
    }
    if !errors.is_empty() {
        if !remaining.is_empty() {
            errors.push(format!("remaining: {}", remaining.join(", ")));
        }
        anyhow::bail!(errors.join("; "));
    }
    Ok(remaining)
}

fn loaded_anchor_exists_with(command: &mut Command) -> anyhow::Result<bool> {
    let output = run_pfctl_output_with(command, "list anchors")?;
    let anchors = std::str::from_utf8(&output.stdout).context("invalid PF anchor-list encoding")?;

    Ok(anchors.lines().any(|line| line.trim() == PF_ANCHOR))
}

// Applies the blocking state, repairing it if it has drifted. The block list is
// fixed for the lifetime of a block, so calling this again -- on daemon
// restart, after a reboot, or on a timer -- re-asserts the same state rather
// than changing it. Only `unblock` takes the block down.
pub fn block(resolved_addrs: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
    let entries: Vec<String> = resolved_addrs.iter().map(to_table_entry).collect();

    ensure_pf_reference()?;
    ensure_anchor_wired()?;
    sync_table(&entries)?;

    Ok(())
}

// Initial startup validates wiring before DNS. Refreshes of active blocks use
// `block` directly so working table coverage remains until replacement.
pub fn prepare() -> anyhow::Result<()> {
    ensure_pf_reference()?;
    ensure_anchor_wired()
}

pub fn unblock() -> anyhow::Result<()> {
    unblock_with(
        strip_anchor_from_pf_conf,
        parent_references_anchor,
        || loaded_anchor_exists_with(Command::new("pfctl").args(["-s", "Anchors"])),
        run_pfctl,
        || {
            let mut errors = Vec::new();
            for path in [PF_ANCHOR_FILE, PF_TABLE_FILE] {
                if let Err(err) = common::remove_file_if_present(path) {
                    errors.push(format!("failed to remove {path}: {err:#}"));
                }
            }
            anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
            Ok(())
        },
        release_pf_reference,
    )
}

fn unblock_with(
    mut strip_config: impl FnMut() -> anyhow::Result<bool>,
    mut parent_reference: impl FnMut() -> anyhow::Result<bool>,
    mut anchor_exists: impl FnMut() -> anyhow::Result<bool>,
    mut run: impl FnMut(&[&str], &str) -> anyhow::Result<String>,
    mut remove_files: impl FnMut() -> anyhow::Result<()>,
    mut release_reference: impl FnMut() -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    let changed = match strip_config() {
        Ok(changed) => Some(changed),
        Err(err) => {
            errors.push(format!("remove PF configuration: {err:#}"));
            None
        }
    };
    let parent = match parent_reference() {
        Ok(present) => Some(present),
        Err(err) => {
            errors.push(format!("inspect parent PF rules: {err:#}"));
            None
        }
    };
    match anchor_exists() {
        Ok(true) => {
            // `all` also flushes global PF state/counters. Restrict teardown
            // to our filtering rules and tables, and attempt both independently.
            for (modifier, description) in [
                ("rules", "clear Walden filter rules"),
                ("Tables", "clear Walden tables"),
            ] {
                if let Err(err) = run(&["-a", PF_ANCHOR, "-F", modifier], description) {
                    errors.push(format!("{description}: {err:#}"));
                }
            }
        }
        Ok(false) => {}
        Err(err) => errors.push(format!("inspect Walden PF anchor: {err:#}")),
    }
    if changed.is_some()
        && (changed == Some(true) || parent == Some(true))
        && let Err(err) = run(
            &["-f", PF_CONF_FILE],
            "reload PF configuration without Walden",
        )
    {
        errors.push(format!("reload PF configuration: {err:#}"));
    }
    // Do not delete files still referenced by configuration after a failed
    // reload. Once rules/configuration are clear, file removal and reference
    // release are independent and both must be attempted.
    if errors.is_empty() {
        if let Err(err) = remove_files() {
            errors.push(format!("remove PF runtime files: {err:#}"));
        }
        if let Err(err) = release_reference() {
            errors.push(format!("release PF reference: {err:#}"));
        }
    }
    anyhow::ensure!(errors.is_empty(), "{}", errors.join("; "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_command(stdout: &str, stderr: &str, exit_code: &str) -> Command {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf '%s' \"$1\"; printf '%s' \"$2\" >&2; exit \"$3\"",
            "firewall-query-test",
            stdout,
            stderr,
            exit_code,
        ]);
        command
    }

    #[test]
    fn parses_and_normalizes_pf_table_entries() {
        let parsed = parse_table_entries("  192.0.2.99/24\n\t2001:db8::1\n192.0.3.0/24\n").unwrap();

        assert_eq!(
            parsed,
            [
                AddressRange::network("192.0.2.0".parse().unwrap(), 23).unwrap(),
                AddressRange::host("2001:db8::1".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn empty_pf_output_is_an_empty_address_set() {
        assert!(parse_table_entries("\n  \n").unwrap().is_empty());
    }

    #[test]
    fn successful_pf_table_query_keeps_diagnostics_out_of_addresses() {
        for (addresses, expected) in [
            (
                "  192.0.2.1\n  2001:db8::1\n",
                vec![
                    AddressRange::host("192.0.2.1".parse().unwrap()),
                    AddressRange::host("2001:db8::1".parse().unwrap()),
                ],
            ),
            ("", Vec::new()),
        ] {
            let output = run_pfctl_with(
                &mut query_command(addresses, "informational diagnostic\n", "0"),
                "table show",
            )
            .unwrap();

            assert_eq!(parse_table_entries(&output).unwrap(), expected);
        }
    }

    #[test]
    fn failed_pf_command_preserves_diagnostics_even_with_valid_addresses() {
        let error = run_pfctl_with(
            &mut query_command("192.0.2.1\n", "Permission denied", "1"),
            "table show",
        )
        .unwrap_err();

        assert!(error.to_string().contains("pfctl table show failed"));
        assert!(error.to_string().contains("Permission denied"));
    }

    #[test]
    fn pf_reference_token_survives_separate_output_streams() {
        for (stdout, stderr) in [
            ("", "informational diagnostic\n  Token : 12345\n"),
            ("notice without a newline", "Token : 12345\n"),
            ("Token : 12345\n", "informational diagnostic\n"),
        ] {
            let output = run_pfctl_output_with(
                &mut query_command(stdout, stderr, "0"),
                "acquire PF reference",
            )
            .unwrap();

            assert_eq!(parse_pf_reference_token(&output).unwrap(), "12345");
        }
    }

    #[test]
    fn pf_reference_requires_a_successful_command_and_a_nonempty_token() {
        for stderr in ["informational diagnostic\n", "Token : \n"] {
            let output =
                run_pfctl_output_with(&mut query_command("", stderr, "0"), "acquire PF reference")
                    .unwrap();

            assert!(
                parse_pf_reference_token(&output)
                    .unwrap_err()
                    .to_string()
                    .contains("returned no token")
            );
        }
        assert!(
            run_pfctl_output_with(
                &mut query_command("", "Token : 12345\nPermission denied\n", "1"),
                "acquire PF reference",
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_or_negated_pf_entries_are_rejected() {
        assert!(parse_table_entries("not-an-address\n").is_err());
        assert!(parse_table_entries("!192.0.2.1\n").is_err());
        assert!(parse_table_entries("192.0.2.1/33\n").is_err());
    }

    #[test]
    fn equal_counts_with_different_addresses_do_not_match() {
        let expected =
            normalize_address_ranges(vec![AddressRange::host("192.0.2.1".parse().unwrap())]);
        let active = parse_table_entries("192.0.2.2\n").unwrap();

        assert_ne!(active, expected);
    }

    #[test]
    fn extra_entries_do_not_match_an_empty_expected_set() {
        assert_ne!(
            parse_table_entries("192.0.2.1\n").unwrap(),
            Vec::<AddressRange>::new()
        );
    }

    #[test]
    fn expected_anchor_rule_matches() {
        assert!(parse_anchor_rules_match(
            "  block return out quick from any to <walden_blocked>\n"
        ));
    }

    #[test]
    fn changed_or_missing_anchor_rules_do_not_match() {
        for output in [
            "",
            "pass out quick from any to <walden_blocked>",
            "block return in quick from any to <walden_blocked>",
            "block return out from any to <walden_blocked>",
            "block return out quick from any to <another_table>",
            "block return out quick proto tcp from any to <walden_blocked>",
            "block return out quick from any to <walden_blocked>\npass out all",
        ] {
            assert!(
                !parse_anchor_rules_match(output),
                "unexpectedly accepted: {output}"
            );
        }
    }

    #[test]
    fn unrestricted_parent_anchor_is_loaded() {
        assert!(parse_parent_anchor_is_loaded(
            "\n  anchor \"org.scotto.walden\"   all\n\
             anchor \"another.anchor\" all\n"
        ));
    }

    #[test]
    fn normalization_rules_do_not_count_as_preceding_filter_rules() {
        assert!(parse_parent_anchor_is_loaded(
            "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"org.scotto.walden\" all\nanchor \"com.apple/*\" all\n"
        ));
        assert!(!parse_parent_anchor_is_loaded(
            "scrub-anchor \"com.apple/*\" all fragment reassemble\npass out quick all\nanchor \"org.scotto.walden\" all\n"
        ));
    }

    #[test]
    fn parent_query_errors_keep_the_real_diagnostic() {
        let error =
            anchor_is_loaded_with(&mut query_command("", "Permission denied", "1")).unwrap_err();
        assert!(error.to_string().contains("Permission denied"));
        assert!(!error.to_string().contains("first live"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_dry_run_output_is_accepted_without_loading_rules() {
        use std::io::Write;
        use std::process::Stdio;
        let mut child = Command::new("/sbin/pfctl")
            .args(["-n", "-v", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(b"scrub-anchor \"com.apple/*\"\nanchor \"org.scotto.walden\"\nanchor \"com.apple/*\"\n").unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            parse_parent_anchor_is_loaded(&String::from_utf8_lossy(&output.stdout)),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    #[test]
    fn missing_or_restricted_parent_anchor_is_not_loaded() {
        for output in [
            "",
            "anchor \"another.anchor\" all",
            "anchor \"org.scotto.walden\" in all",
            "anchor \"org.scotto.walden\" out all",
            "anchor \"org.scotto.walden\" on en0 all",
            "anchor \"org.scotto.walden\" proto tcp all",
        ] {
            assert!(
                !parse_parent_anchor_is_loaded(output),
                "unexpectedly accepted: {output}"
            );
        }
    }

    #[test]
    fn a_parent_anchor_after_other_rules_is_not_loaded() {
        for preceding_rule in [
            "pass out quick all flags S/SA keep state",
            "anchor \"another.anchor\" all",
        ] {
            let rules = format!("{preceding_rule}\nanchor \"{PF_ANCHOR}\" all\n");

            assert!(
                !parse_parent_anchor_is_loaded(&rules),
                "unexpectedly accepted rules:\n{rules}"
            );
        }
    }

    #[test]
    fn configuration_moves_anchor_before_filtering() {
        let (anchor, load) = anchor_lines();

        let conf = format!(
            "set block-policy drop\n\
             scrub-anchor \"com.apple/*\"\n\
             nat-anchor \"com.apple/*\"\n\
             rdr-anchor \"com.apple/*\"\n\
             dummynet-anchor \"com.apple/*\"\n\
             pass out quick all\n\
             {anchor}\n\
             {load}\n"
        );

        let expected = format!(
            "set block-policy drop\n\
             scrub-anchor \"com.apple/*\"\n\
             nat-anchor \"com.apple/*\"\n\
             rdr-anchor \"com.apple/*\"\n\
             dummynet-anchor \"com.apple/*\"\n\
             {anchor}\n\
             pass out quick all\n\
             {load}\n"
        );

        let updated = pf_conf_with_anchor(&conf);

        assert_eq!(updated, expected);

        // Repairing an already repaired configuration changes nothing.
        assert_eq!(pf_conf_with_anchor(&updated), updated);
    }

    #[test]
    fn an_empty_configuration_gets_the_anchor_pair() {
        let (anchor, load) = anchor_lines();

        assert_eq!(pf_conf_with_anchor(""), format!("{anchor}\n{load}\n"));
    }

    #[test]
    fn loaded_anchor_query_distinguishes_presence_from_absence() {
        for (output, expected) in [
            ("", false),
            ("  com.apple\n", false),
            ("  org.scotto.walden-other\n", false),
            ("  com.apple\n  org.scotto.walden\n", true),
        ] {
            assert_eq!(
                loaded_anchor_exists_with(&mut query_command(output, "", "0")).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn failed_loaded_anchor_queries_are_errors() {
        assert!(
            loaded_anchor_exists_with(&mut query_command("", "Permission denied", "1",)).is_err()
        );

        assert!(loaded_anchor_exists_with(&mut Command::new("/dev/null/walden-pf-test")).is_err());
    }

    #[test]
    fn anchor_query_checks_stdout_only() {
        assert!(
            !loaded_anchor_exists_with(&mut query_command("", "org.scotto.walden", "0",)).unwrap()
        );
    }

    #[test]
    fn a_detached_empty_anchor_does_not_prevent_cleanup_completion() {
        let remaining = anchor_contents_leftovers(|args, _| {
            assert_eq!(&args[..3], &["-a", PF_ANCHOR, "-s"]);
            Ok("\n  \n".into())
        })
        .unwrap();
        assert!(remaining.is_empty());
        let rules = anchor_contents_leftovers(|args, _| {
            Ok(if args[3] == "rules" {
                "block return out quick\n"
            } else {
                ""
            }
            .into())
        })
        .unwrap();
        assert_eq!(rules, ["PF rules in Walden's anchor"]);
        let tables = anchor_contents_leftovers(|args, _| {
            Ok(if args[3] == "Tables" {
                "walden_blocked\n"
            } else {
                ""
            }
            .into())
        })
        .unwrap();
        assert_eq!(tables, ["PF tables in Walden's anchor"]);
    }

    #[test]
    fn cleanup_preserves_other_configuration_and_skips_an_already_clean_file() {
        let conf = format!(
            "set skip on lo0\nanchor \"com.apple/*\"\n  anchor \"{PF_ANCHOR}\"\nload anchor \"{PF_ANCHOR}\" from \"/old/path\"\nanchor \"{PF_ANCHOR}-other\"\n"
        );
        let clean = configuration_without_own_anchor(&conf).unwrap();
        assert_eq!(
            clean,
            format!("set skip on lo0\nanchor \"com.apple/*\"\nanchor \"{PF_ANCHOR}-other\"\n")
        );
        assert!(configuration_without_own_anchor(&clean).is_none());
        assert!(configuration_without_own_anchor("set skip on lo0").is_none());
    }

    #[test]
    fn pf_cleanup_verification_does_not_treat_query_failure_as_absence() {
        let mut calls = 0;
        let error = anchor_contents_leftovers(|_, _| {
            calls += 1;
            anyhow::bail!("Permission denied")
        })
        .unwrap_err();
        assert_eq!(calls, 2);
        assert!(error.to_string().contains("Permission denied"));
    }

    #[test]
    fn pf_cleanup_is_scoped_and_repeated_cleanup_skips_an_absent_anchor() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        unblock_with(
            || Ok(true),
            || Ok(true),
            || Ok(true),
            |args, _| {
                calls.borrow_mut().push(args.join(" "));
                Ok(String::new())
            },
            || {
                calls.borrow_mut().push("remove files".into());
                Ok(())
            },
            || {
                calls.borrow_mut().push("release reference".into());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *calls.borrow(),
            [
                format!("-a {PF_ANCHOR} -F rules"),
                format!("-a {PF_ANCHOR} -F Tables"),
                format!("-f {PF_CONF_FILE}"),
                "remove files".into(),
                "release reference".into()
            ]
        );
        unblock_with(
            || Ok(false),
            || Ok(false),
            || Ok(false),
            |_, _| panic!("clean state must not reload or flush PF"),
            || Ok(()),
            || Ok(()),
        )
        .unwrap();
    }

    #[test]
    fn a_failed_pf_reload_is_retried_when_disk_configuration_is_already_clean() {
        use std::cell::RefCell;
        let state = RefCell::new((true, true, true)); // disk reference, live reference, first reload
        for attempt in 0..2 {
            let result = unblock_with(
                || {
                    let mut s = state.borrow_mut();
                    let changed = s.0;
                    s.0 = false;
                    Ok(changed)
                },
                || Ok(state.borrow().1),
                || Ok(true),
                |args, _| {
                    if args[0] == "-f" {
                        let mut s = state.borrow_mut();
                        if s.2 {
                            s.2 = false;
                            anyhow::bail!("injected reload failure");
                        }
                        s.1 = false;
                    }
                    Ok(String::new())
                },
                || {
                    assert!(
                        !state.borrow().1,
                        "files must remain while live references exist"
                    );
                    Ok(())
                },
                || Ok(()),
            );
            if attempt == 0 {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("injected reload failure")
                );
            } else {
                result.unwrap();
            }
        }
        assert!(!state.borrow().1);
    }

    #[test]
    fn partial_pf_cleanup_attempts_other_steps_and_preserves_referenced_files() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        let error = unblock_with(
            || anyhow::bail!("read-only pf.conf"),
            || Ok(true),
            || Ok(true),
            |args, _| {
                calls.borrow_mut().push(args.join(" "));
                if args[3] == "rules" {
                    anyhow::bail!("injected rule flush failure");
                }
                Ok(String::new())
            },
            || panic!("configuration still references files"),
            || panic!("cleanup is incomplete"),
        )
        .unwrap_err();
        assert_eq!(calls.borrow().len(), 2);
        assert!(calls.borrow()[1].ends_with("Tables"));
        assert!(error.to_string().contains("read-only pf.conf"));
        assert!(error.to_string().contains("rule flush failure"));
    }

    #[test]
    fn failed_pf_file_removal_does_not_skip_reference_release() {
        let mut released = false;
        let error = unblock_with(
            || Ok(false),
            || Ok(false),
            || Ok(false),
            |_, _| panic!("already clean"),
            || anyhow::bail!("file permission denied"),
            || {
                released = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(released);
        assert!(error.to_string().contains("file permission denied"));
    }
}
