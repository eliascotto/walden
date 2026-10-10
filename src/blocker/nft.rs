// nftables blocking on Linux.

use anyhow::{Context, anyhow, bail};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::blocker::common::{
    AddressRange, ConfigStatus, normalize_address_ranges, resolved_address_ranges,
};
use crate::common;
use crate::resolver::ResolvedAddr;

// nftables table/set names and the files nft reads them from. There is no
// counterpart to pf's enable reference here: nftables has no global on/off
// switch, so the table existing is the whole of the blocking state.
const NFT_FAMILY: &str = "inet";
const NFT_TABLE: &str = "walden";
const NFT_SET_V4: &str = "walden_blocked_v4";
const NFT_SET_V6: &str = "walden_blocked_v6";
const NFT_RULES_DIR: &str = "/etc/nftables.d";
const NFT_RULES_FILE: &str = "/etc/nftables.d/walden.nft";
const NFT_CONF_FILE: &str = "/etc/nftables.conf";

// A named set holding one address family. `interval` lets it hold CIDR blocks
// as well as single addresses, and `auto-merge` folds overlapping entries
// together instead of failing the load.
fn nft_set(name: &str, addr_type: &str, entries: &[String]) -> String {
    let mut set = String::new();

    set.push_str(&format!("    set {name} {{\n"));
    set.push_str(&format!("        type {addr_type}\n"));
    set.push_str("        flags interval\n");
    set.push_str("        auto-merge\n");

    // `elements = { }` is a syntax error, so an empty set just omits the line.
    if !entries.is_empty() {
        set.push_str(&format!(
            "        elements = {{ {} }}\n",
            entries.join(", ")
        ));
    }

    set.push_str("    }\n");
    set
}

// The entire blocking state as one nft script: a set per address family (a set
// is typed, so v4 and v6 cannot share one), the addresses they hold, and an
// output chain that rejects anything bound for them. `reject` (rather than
// `drop`) sends an immediate unreachable back to the blocked app instead of
// leaving it to hang until its own timeout.
//
// The leading `table`/`delete table` pair turns the script into a
// create-or-replace: the first line creates the table when it is missing so the
// delete cannot fail. nft applies a whole file as a single transaction, so
// re-running this swaps rules and addresses in together, with no instant where
// the table exists but blocks nothing.
fn nft_ruleset(v4: &[String], v6: &[String]) -> String {
    let mut ruleset = String::new();

    ruleset.push_str(&format!("table {NFT_FAMILY} {NFT_TABLE}\n"));
    ruleset.push_str(&format!("delete table {NFT_FAMILY} {NFT_TABLE}\n\n"));

    ruleset.push_str(&format!("table {NFT_FAMILY} {NFT_TABLE} {{\n"));
    ruleset.push_str(&nft_set(NFT_SET_V4, "ipv4_addr", v4));
    ruleset.push('\n');
    ruleset.push_str(&nft_set(NFT_SET_V6, "ipv6_addr", v6));
    ruleset.push('\n');
    ruleset.push_str("    chain output {\n");
    ruleset.push_str("        type filter hook output priority 0; policy accept;\n");
    ruleset.push_str(&format!("        ip daddr @{NFT_SET_V4} reject\n"));
    ruleset.push_str(&format!("        ip6 daddr @{NFT_SET_V6} reject\n"));
    ruleset.push_str("    }\n");
    ruleset.push_str("}\n");

    ruleset
}

// nft sets are typed (`ipv4_addr` / `ipv6_addr`), so unlike pf's mixed table
// the blocklist has to be split by family before load.
fn partition_by_family(addrs: &BTreeSet<ResolvedAddr>) -> (Vec<String>, Vec<String>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for addr in addrs {
        match addr {
            ResolvedAddr::Host(ip) if ip.is_ipv6() => v6.push(ip.to_string()),
            ResolvedAddr::Host(ip) => v4.push(ip.to_string()),
            ResolvedAddr::Network(ip, prefix) if ip.is_ipv6() => v6.push(format!("{ip}/{prefix}")),
            ResolvedAddr::Network(ip, prefix) => v4.push(format!("{ip}/{prefix}")),
        }
    }

    (v4, v6)
}

// Returns both streams joined, matching how the pf backend reports: nft writes
// its diagnostics to stderr.
fn run_nft(args: &[&str], what: &str) -> anyhow::Result<String> {
    let output = Command::new("nft")
        .args(args)
        .output()
        .with_context(|| format!("failed to run nft: {what}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    anyhow::ensure!(
        output.status.success(),
        "nft {what} failed: {}",
        stderr.trim()
    );

    Ok(format!("{stdout}{stderr}"))
}

fn table_exists() -> bool {
    Command::new("nft")
        .args(["list", "table", NFT_FAMILY, NFT_TABLE])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

// Adds an include line to the system nftables config so the table comes back on
// boot. Distros that do not ship /etc/nftables.conf are left alone; the daemon
// reloads the ruleset itself on start either way.
fn ensure_conf_include() -> anyhow::Result<()> {
    if !Path::new(NFT_CONF_FILE).exists() {
        return Ok(());
    }

    let conf = fs::read_to_string(NFT_CONF_FILE)
        .with_context(|| format!("failed to read {NFT_CONF_FILE}"))?;

    let include_line = format!("include \"{NFT_RULES_FILE}\"");
    if conf.lines().any(|line| line.trim() == include_line) {
        return Ok(()); // already wired
    }

    let mut updated = conf;
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push_str(&format!("{include_line}\n"));

    common::write_atomically(NFT_CONF_FILE, updated.as_bytes())
        .with_context(|| format!("failed to update {NFT_CONF_FILE}"))
}

// Removes the include line so the table does not come back on the next boot.
fn remove_conf_include() -> anyhow::Result<()> {
    if !Path::new(NFT_CONF_FILE).exists() {
        return Ok(());
    }

    let conf = fs::read_to_string(NFT_CONF_FILE)
        .with_context(|| format!("failed to read {NFT_CONF_FILE}"))?;

    let include_line = format!("include \"{NFT_RULES_FILE}\"");
    let mut updated = conf
        .lines()
        .filter(|line| line.trim() != include_line)
        .collect::<Vec<&str>>()
        .join("\n");
    updated.push('\n');

    common::write_atomically(NFT_CONF_FILE, updated.as_bytes())
        .with_context(|| format!("failed to update {NFT_CONF_FILE}"))
}

// Brings the ruleset back to the blocking state from whatever state it is in.
// The script is a create-or-replace applied as one transaction, so loading it
// unconditionally is also what repairs a table someone has flushed, edited a
// rule out of, or deleted outright.
fn ensure_ruleset_loaded(v4: &[String], v6: &[String]) -> anyhow::Result<()> {
    fs::create_dir_all(NFT_RULES_DIR)
        .with_context(|| format!("failed to create {NFT_RULES_DIR}"))?;

    common::write_atomically(NFT_RULES_FILE, nft_ruleset(v4, v6).as_bytes())
        .with_context(|| format!("failed to write {NFT_RULES_FILE}"))?;

    ensure_conf_include()?;

    run_nft(&["-f", NFT_RULES_FILE], "load ruleset")?;
    Ok(())
}

// Drops the whole table -- sets, chain, rules and addresses go with it -- and
// removes the file it was loaded from.
fn delete_table() -> anyhow::Result<()> {
    if table_exists() {
        run_nft(&["delete", "table", NFT_FAMILY, NFT_TABLE], "delete table")?;
    }

    common::remove_file_if_present(NFT_RULES_FILE)?;
    Ok(())
}

fn parse_nft_ip(value: &Value, what: &str) -> anyhow::Result<IpAddr> {
    value
        .as_str()
        .with_context(|| format!("{what} is not a string"))?
        .parse::<IpAddr>()
        .with_context(|| format!("invalid address in nftables {what}"))
}

fn parse_nft_element(value: &Value) -> anyhow::Result<AddressRange> {
    if value.is_string() {
        return Ok(AddressRange::host(parse_nft_ip(value, "set element")?));
    }

    let object = value
        .as_object()
        .context("nftables set element is not an address expression")?;

    if let Some(prefix) = object.get("prefix") {
        let prefix = prefix
            .as_object()
            .context("nftables prefix element is not an object")?;
        let addr = parse_nft_ip(
            prefix
                .get("addr")
                .context("nftables prefix has no address")?,
            "prefix",
        )?;
        let length = prefix
            .get("len")
            .and_then(Value::as_u64)
            .and_then(|length| u8::try_from(length).ok())
            .context("nftables prefix has an invalid length")?;

        return AddressRange::network(addr, length)
            .context("nftables prefix length does not match its address family");
    }

    if let Some(range) = object.get("range") {
        let range = range
            .as_array()
            .filter(|range| range.len() == 2)
            .context("nftables range does not have two endpoints")?;
        let start = parse_nft_ip(&range[0], "range start")?;
        let end = parse_nft_ip(&range[1], "range end")?;

        return AddressRange::between(start, end)
            .context("nftables range endpoints are invalid or from different families");
    }

    // Elements carrying optional metadata are wrapped as
    // { "elem": { "val": <expression>, ... } } by libnftables-json.
    if let Some(element) = object.get("elem") {
        let value = element
            .as_object()
            .and_then(|element| element.get("val"))
            .context("nftables element wrapper has no value")?;
        return parse_nft_element(value);
    }

    bail!("unsupported nftables set element: {value}")
}

fn parse_nft_set(
    output: &str,
    set_name: &str,
    expected_type: &str,
) -> anyhow::Result<Vec<AddressRange>> {
    let document: Value = serde_json::from_str(output).context("invalid nftables JSON output")?;
    let objects = document
        .get("nftables")
        .and_then(Value::as_array)
        .context("nftables JSON output has no object list")?;

    let mut matching_sets = objects
        .iter()
        .filter_map(|object| object.get("set"))
        .filter(|set| {
            set.get("family").and_then(Value::as_str) == Some(NFT_FAMILY)
                && set.get("table").and_then(Value::as_str) == Some(NFT_TABLE)
                && set.get("name").and_then(Value::as_str) == Some(set_name)
        });
    let set = matching_sets
        .next()
        .with_context(|| format!("nftables output does not contain set {set_name}"))?;
    if matching_sets.next().is_some() {
        bail!("nftables output contains set {set_name} more than once");
    }

    let actual_type = set
        .get("type")
        .and_then(Value::as_str)
        .with_context(|| format!("nftables set {set_name} has no address type"))?;
    if actual_type != expected_type {
        bail!("nftables set {set_name} has type {actual_type}, expected {expected_type}");
    }

    let elements = set.get("elem").or_else(|| set.get("elements"));
    let Some(elements) = elements else {
        return Ok(Vec::new());
    };

    // The schema permits either one expression or an array of expressions.
    let element_values: Vec<&Value> = match elements.as_array() {
        Some(elements) => elements.iter().collect(),
        None => vec![elements],
    };
    let mut ranges = Vec::with_capacity(element_values.len());
    for element in element_values {
        let range = parse_nft_element(element)?;
        let family_matches = match expected_type {
            "ipv4_addr" => !range.is_ipv6(),
            "ipv6_addr" => range.is_ipv6(),
            _ => return Err(anyhow!("unsupported nftables address type {expected_type}")),
        };
        if !family_matches {
            bail!("nftables set {set_name} contains an address from the wrong family");
        }
        ranges.push(range);
    }

    Ok(normalize_address_ranges(ranges))
}

fn active_set(set_name: &str, expected_type: &str) -> anyhow::Result<Vec<AddressRange>> {
    let output = run_nft(
        &["-j", "-n", "list", "set", NFT_FAMILY, NFT_TABLE, set_name],
        "list set",
    )?;

    parse_nft_set(&output, set_name, expected_type)
}

fn sets_match(resolved_addrs: &BTreeSet<ResolvedAddr>) -> anyhow::Result<bool> {
    let expected = resolved_address_ranges(resolved_addrs)
        .context("resolved block list contains an invalid network")?;
    let expected_v4: Vec<_> = expected
        .iter()
        .copied()
        .filter(|range| !range.is_ipv6())
        .collect();
    let expected_v6: Vec<_> = expected
        .iter()
        .copied()
        .filter(|range| range.is_ipv6())
        .collect();

    let active_v4 = active_set(NFT_SET_V4, "ipv4_addr")?;
    let active_v6 = active_set(NFT_SET_V6, "ipv6_addr")?;

    Ok(active_v4 == expected_v4 && active_v6 == expected_v6)
}

fn blocking_rule_matches(rule: &Value, protocol: &str, set_name: &str) -> bool {
    let Some(expr) = rule.get("expr").and_then(Value::as_array) else {
        return false;
    };

    if expr.len() != 2 {
        return false;
    }

    let expected_match = serde_json::json!({
        "match": {
            "op": "==",
            "left": {
                "payload": {
                    "protocol": protocol,
                    "field": "daddr"
                }
            },
            "right": format!("@{set_name}")
        }
    });

    let rejects = expr[1]
        .as_object()
        .is_some_and(|statement| statement.len() == 1 && statement.contains_key("reject"));

    expr[0] == expected_match && rejects
}

fn parse_rules_match(output: &str) -> anyhow::Result<bool> {
    let document: Value = serde_json::from_str(output).context("invalid nftables JSON output")?;
    let objects = document
        .get("nftables")
        .and_then(Value::as_array)
        .context("nftables JSON output has no object list")?;

    let table = objects
        .iter()
        .filter_map(|object| object.get("table"))
        .find(|table| {
            table.get("family").and_then(Value::as_str) == Some(NFT_FAMILY)
                && table.get("name").and_then(Value::as_str) == Some(NFT_TABLE)
        });

    let Some(table) = table else {
        return Ok(false);
    };

    let table_is_active = match table.get("flags") {
        None => true,
        Some(Value::String(flag)) => flag != "dormant",
        Some(Value::Array(flags)) => flags
            .iter()
            .all(|flag| flag.as_str().is_some_and(|name| name != "dormant")),

        Some(_) => false,
    };

    if !table_is_active {
        return Ok(false);
    }

    let chains = objects
        .iter()
        .filter_map(|object| object.get("chain"))
        .find(|chain| {
            chain.get("family").and_then(Value::as_str) == Some(NFT_FAMILY)
                && chain.get("table").and_then(Value::as_str) == Some(NFT_TABLE)
                && chain.get("name").and_then(Value::as_str) == Some("output")
        });

    let Some(chains) = chains else {
        return Ok(false);
    };

    if Some("filter") != chains.get("type").and_then(Value::as_str)
        || Some("output") != chains.get("hook").and_then(Value::as_str)
        || chains.get("prio").and_then(Value::as_i64) != Some(0)
        || chains.get("policy").and_then(Value::as_str) != Some("accept")
    {
        return Ok(false);
    }

    let rules = objects
        .iter()
        .filter_map(|object| object.get("rule"))
        .filter(|rule| {
            rule.get("family").and_then(Value::as_str) == Some(NFT_FAMILY)
                && rule.get("table").and_then(Value::as_str) == Some(NFT_TABLE)
                && rule.get("chain").and_then(Value::as_str) == Some("output")
        })
        .collect::<Vec<_>>();

    if rules.len() != 2 {
        return Ok(false);
    }

    Ok(blocking_rule_matches(rules[0], "ip", NFT_SET_V4)
        && blocking_rule_matches(rules[1], "ip6", NFT_SET_V6))
}

fn rules_match() -> anyhow::Result<bool> {
    let output = run_nft(
        &["-j", "-n", "list", "table", "inet", "walden"],
        "list table",
    )?;

    parse_rules_match(&output)
}

// Whether the block is still installed, read back from the running table: the
// rules file it is loaded from, the table itself, the two rules that send
// traffic at the sets, and addresses in those sets. Partial means something
// survived, which `block` repairs the same way it repairs Absent -- the
// distinction is kept for the log, not for the decision.
pub fn status(resolved_addrs: &BTreeSet<ResolvedAddr>) -> ConfigStatus {
    if !Path::new(NFT_RULES_FILE).exists() {
        return ConfigStatus::Absent;
    }

    match rules_match() {
        Ok(true) => {}
        Ok(false) | Err(_) => return ConfigStatus::Partial,
    }

    match sets_match(resolved_addrs) {
        Ok(true) => ConfigStatus::Present,
        // A set that cannot be verified is repaired rather than trusted.
        Ok(false) | Err(_) => ConfigStatus::Partial,
    }
}

// Whether any trace of an earlier block is still installed. Unlike `status`
// this asks nothing about the block list, so it can be answered before one is
// known -- at startup, when the daemon has to tell an interrupted teardown
// from a clean machine.
pub fn has_leftovers() -> bool {
    Path::new(NFT_RULES_FILE).exists() || table_exists()
}

// Applies the blocking state, repairing it if it has drifted. The block list is
// fixed for the lifetime of a block, so calling this again -- on daemon
// restart, after a reboot, or on a timer -- re-asserts the same state rather
// than changing it. Only `unblock` takes the block down.
pub fn block(resolved_addrs: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
    let (v4, v6) = partition_by_family(resolved_addrs);

    ensure_ruleset_loaded(&v4, &v6)
}

pub fn unblock() -> anyhow::Result<()> {
    // Unwired first: /etc/nftables.conf must never name a file that is gone, or
    // the next boot's ruleset load fails outright.
    remove_conf_include()?;
    delete_table()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_output(name: &str, address_type: &str, elements: &str) -> String {
        format!(
            r#"{{
                "nftables": [
                    {{ "metainfo": {{ "json_schema_version": 1 }} }},
                    {{ "set": {{
                        "family": "inet",
                        "name": "{name}",
                        "table": "walden",
                        "type": "{address_type}"{elements}
                    }} }}
                ]
            }}"#
        )
    }

    #[test]
    fn parses_hosts_prefixes_ranges_and_wrapped_elements() {
        let output = set_output(
            NFT_SET_V4,
            "ipv4_addr",
            r#", "elem": [
                "192.0.2.1",
                { "prefix": { "addr": "198.51.100.99", "len": 24 } },
                { "range": ["203.0.113.1", "203.0.113.9"] },
                { "elem": { "val": "203.0.113.10", "comment": "test" } }
            ]"#,
        );

        assert_eq!(
            parse_nft_set(&output, NFT_SET_V4, "ipv4_addr").unwrap(),
            [
                AddressRange::host("192.0.2.1".parse().unwrap()),
                AddressRange::network("198.51.100.0".parse().unwrap(), 24).unwrap(),
                AddressRange::between(
                    "203.0.113.1".parse().unwrap(),
                    "203.0.113.10".parse().unwrap()
                )
                .unwrap(),
            ]
        );
    }

    #[test]
    fn an_empty_nftables_set_is_parsed_as_empty() {
        let output = set_output(NFT_SET_V6, "ipv6_addr", "");

        assert!(
            parse_nft_set(&output, NFT_SET_V6, "ipv6_addr")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_single_non_array_set_element_is_supported() {
        let output = set_output(NFT_SET_V4, "ipv4_addr", r#", "elem": "192.0.2.1""#);

        assert_eq!(
            parse_nft_set(&output, NFT_SET_V4, "ipv4_addr").unwrap(),
            [AddressRange::host("192.0.2.1".parse().unwrap())]
        );
    }

    #[test]
    fn auto_merged_ranges_compare_by_effective_coverage() {
        let output = set_output(
            NFT_SET_V4,
            "ipv4_addr",
            r#", "elem": [{ "range": ["192.0.2.0", "192.0.2.255"] }]"#,
        );
        let active = parse_nft_set(&output, NFT_SET_V4, "ipv4_addr").unwrap();
        let expected = normalize_address_ranges(vec![
            AddressRange::network("192.0.2.99".parse().unwrap(), 25).unwrap(),
            AddressRange::network("192.0.2.128".parse().unwrap(), 25).unwrap(),
            AddressRange::host("192.0.2.7".parse().unwrap()),
        ]);

        assert_eq!(active, expected);
    }

    #[test]
    fn missing_extra_and_same_count_different_entries_do_not_match() {
        let output = set_output(NFT_SET_V4, "ipv4_addr", r#", "elem": ["192.0.2.2"]"#);
        let active = parse_nft_set(&output, NFT_SET_V4, "ipv4_addr").unwrap();
        let expected =
            normalize_address_ranges(vec![AddressRange::host("192.0.2.1".parse().unwrap())]);

        assert_ne!(active, expected);
        assert_ne!(active, Vec::<AddressRange>::new());
        assert_ne!(Vec::<AddressRange>::new(), expected);
    }

    #[test]
    fn malformed_wrong_family_or_wrong_type_sets_are_rejected() {
        assert!(parse_nft_set("not json", NFT_SET_V4, "ipv4_addr").is_err());

        let missing = set_output("another_set", "ipv4_addr", "");
        assert!(parse_nft_set(&missing, NFT_SET_V4, "ipv4_addr").is_err());

        let wrong_family = set_output(NFT_SET_V4, "ipv4_addr", r#", "elem": ["2001:db8::1"]"#);
        assert!(parse_nft_set(&wrong_family, NFT_SET_V4, "ipv4_addr").is_err());

        let wrong_type = set_output(NFT_SET_V4, "ipv6_addr", "");
        assert!(parse_nft_set(&wrong_type, NFT_SET_V4, "ipv4_addr").is_err());
    }

    fn valid_rules_document() -> Value {
        serde_json::json!({
            "nftables": [
                {
                    "chain": {
                        "family": "inet",
                        "table": "walden",
                        "name": "output",
                        "type": "filter",
                        "hook": "output",
                        "prio": 0,
                        "policy": "accept"
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "walden",
                        "chain": "output",
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {
                                            "protocol": "ip",
                                            "field": "daddr"
                                        }
                                    },
                                    "right": "@walden_blocked_v4"
                                }
                            },
                            {
                                "reject": {
                                    "type": "icmp",
                                    "expr": "port-unreachable"
                                }
                            }
                        ]
                    }
                },
                {
                    "rule": {
                        "family": "inet",
                        "table": "walden",
                        "chain": "output",
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {
                                        "payload": {
                                            "protocol": "ip6",
                                            "field": "daddr"
                                        }
                                    },
                                    "right": "@walden_blocked_v6"
                                }
                            },
                            {
                                "reject": {
                                    "type": "icmpv6",
                                    "expr": "port-unreachable"
                                }
                            }
                        ]
                    }
                },
                {
                    "table": {
                        "family": "inet",
                        "name": "walden"
                    }
                }
            ]
        })
    }

    #[test]
    fn expected_blocking_rules_match() {
        let document = valid_rules_document();

        assert!(parse_rules_match(&document.to_string()).unwrap());
    }

    #[test]
    fn rules_attached_to_the_wrong_hook_do_not_match() {
        let mut document = valid_rules_document();
        document["nftables"][0]["chain"]["hook"] = serde_json::json!("input");

        assert!(!parse_rules_match(&document.to_string()).unwrap());
    }

    #[test]
    fn a_missing_blocking_rule_does_not_match() {
        let mut document = valid_rules_document();
        document["nftables"].as_array_mut().unwrap().remove(2);

        assert!(!parse_rules_match(&document.to_string()).unwrap());
    }

    #[test]
    fn accepting_instead_of_rejecting_does_not_match() {
        let mut document = valid_rules_document();
        document["nftables"][1]["rule"]["expr"][1] = serde_json::json!({ "accept": null });

        assert!(!parse_rules_match(&document.to_string()).unwrap());
    }

    #[test]
    fn an_earlier_accept_rule_does_not_match() {
        let mut document = valid_rules_document();
        let accept_rule = serde_json::json!({
            "rule": {
                "family": "inet",
                "table": "walden",
                "chain": "output",
                "expr": [{ "accept": null }]
            }
        });

        document["nftables"]
            .as_array_mut()
            .unwrap()
            .insert(1, accept_rule);

        assert!(!parse_rules_match(&document.to_string()).unwrap());
    }

    #[test]
    fn a_rule_using_the_wrong_set_does_not_match() {
        let mut document = valid_rules_document();
        document["nftables"][1]["rule"]["expr"][0]["match"]["right"] =
            serde_json::json!("@another_set");

        assert!(!parse_rules_match(&document.to_string()).unwrap());
    }

    #[test]
    fn an_extra_condition_does_not_match() {
        let mut document = valid_rules_document();
        let port_condition = serde_json::json!({
            "match": {
                "op": "==",
                "left": {
                    "payload": {
                        "protocol": "tcp",
                        "field": "dport"
                    }
                },
                "right": 443
            }
        });

        document["nftables"][1]["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .insert(1, port_condition);

        assert!(!parse_rules_match(&document.to_string()).unwrap());
    }

    #[test]
    fn invalid_rules_output_returns_an_error() {
        assert!(parse_rules_match("not JSON").is_err());
        assert!(parse_rules_match(r#"{"nftables": {}}"#).is_err());
    }

    #[test]
    fn a_dormant_table_does_not_match() {
        for flags in [
            serde_json::json!("dormant"),
            serde_json::json!(["dormant"]),
            serde_json::json!(["owner", "dormant"]),
        ] {
            let mut document = valid_rules_document();
            document["nftables"][3]["table"]["flags"] = flags;

            assert!(!parse_rules_match(&document.to_string()).unwrap());
        }
    }

    #[test]
    fn a_missing_table_does_not_match() {
        let mut document = valid_rules_document();
        document["nftables"].as_array_mut().unwrap().pop();

        assert!(!parse_rules_match(&document.to_string()).unwrap());
    }
}
