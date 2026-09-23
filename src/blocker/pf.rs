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

// pfctl reports informational output on stderr, including the -E token.
fn run_pfctl(args: &[&str], what: &str) -> anyhow::Result<String> {
    let output = Command::new("pfctl")
        .args(args)
        .output()
        .with_context(|| format!("failed to run pfctl: {what}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    anyhow::ensure!(
        output.status.success(),
        "pfctl {what} failed: {}",
        stderr.trim()
    );

    Ok(format!("{stdout}{stderr}"))
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

// `pfctl -E` enables pf and increments its reference count, handing back a
// token. The reference is held for the whole block, so this only records it.
fn acquire_pf_reference() -> anyhow::Result<()> {
    let output = run_pfctl(&["-E"], "acquire PF reference")?;

    let token = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Token :"))
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .context("pfctl -E returned no token")?;

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
        eprintln!("walden: {err}");
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
    } else if has_anchor_line || has_load_line {
        Ok(ConfigStatus::Partial)
    } else {
        Ok(ConfigStatus::Absent)
    }
}

// Whether the *running* ruleset evaluates our anchor. /etc/pf.conf can name the
// anchor while the loaded ruleset does not, if something flushed or replaced
// the ruleset after boot.
fn anchor_is_loaded() -> bool {
    let (anchor_line, _) = anchor_lines();

    run_pfctl(&["-s", "rules"], "list rules")
        .map(|rules| {
            rules
                .lines()
                .any(|line| line.trim().starts_with(anchor_line.as_str()))
        })
        .unwrap_or(false)
}

fn append_anchor_to_pf_conf() -> anyhow::Result<()> {
    let mut conf = fs::read_to_string(PF_CONF_FILE)
        .with_context(|| format!("failed to read {PF_CONF_FILE}"))?;

    if !conf.ends_with('\n') {
        conf.push('\n');
    }

    let (anchor_line, load_line) = anchor_lines();
    conf.push_str(&format!("{anchor_line}\n{load_line}\n"));

    common::write_atomically(PF_CONF_FILE, conf.as_bytes())
        .with_context(|| format!("failed to update {PF_CONF_FILE}"))
}

// Drops our lines from /etc/pf.conf without touching the running ruleset.
// Matches on the anchor name alone so lines written by an older install, which
// may name a different path, are removed too.
fn strip_anchor_from_pf_conf() -> anyhow::Result<()> {
    let conf = fs::read_to_string(PF_CONF_FILE)
        .with_context(|| format!("failed to read {PF_CONF_FILE}"))?;

    let anchor_prefix = format!("anchor \"{PF_ANCHOR}\"");
    let load_prefix = format!("load anchor \"{PF_ANCHOR}\"");

    let mut updated = conf
        .lines()
        .filter(|line| {
            let line = line.trim();
            !line.starts_with(anchor_prefix.as_str()) && !line.starts_with(load_prefix.as_str())
        })
        .collect::<Vec<&str>>()
        .join("\n");
    updated.push('\n');

    common::write_atomically(PF_CONF_FILE, updated.as_bytes())
        .with_context(|| format!("failed to update {PF_CONF_FILE}"))
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

    let conf_changed = match pf_conf_has_anchor()? {
        ConfigStatus::Present => false,
        // Only one of the two lines survived: drop it and re-add the pair.
        ConfigStatus::Partial => {
            strip_anchor_from_pf_conf()?;
            append_anchor_to_pf_conf()?;
            true
        }
        ConfigStatus::Absent => {
            append_anchor_to_pf_conf()?;
            true
        }
    };

    if conf_changed || !anchor_is_loaded() {
        run_pfctl(&["-f", PF_CONF_FILE], "load pf.conf")?;
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

// Clears the active anchor and removes its runtime files.
fn clear_table() -> anyhow::Result<()> {
    run_pfctl(&["-a", PF_ANCHOR, "-F", "all"], "clear anchor")?;

    common::remove_file_if_present(PF_ANCHOR_FILE)?;
    common::remove_file_if_present(PF_TABLE_FILE)?;
    Ok(())
}

// Unwires the anchor from /etc/pf.conf and reloads the ruleset without it.
fn remove_anchor() -> anyhow::Result<()> {
    strip_anchor_from_pf_conf()?;
    run_pfctl(&["-f", PF_CONF_FILE], "load pf.conf")?;
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

    if !Path::new(PF_ANCHOR_FILE).exists() || !anchor_is_loaded() {
        return ConfigStatus::Absent;
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
pub fn has_leftovers() -> bool {
    let conf_wired = matches!(
        pf_conf_has_anchor(),
        Ok(ConfigStatus::Present | ConfigStatus::Partial)
    );

    conf_wired || Path::new(PF_ANCHOR_FILE).exists() || current_token().is_some()
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

pub fn unblock() -> anyhow::Result<()> {
    remove_anchor()?;
    clear_table()?;

    // Released last: pf stays enabled until the rules are gone.
    release_pf_reference()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
