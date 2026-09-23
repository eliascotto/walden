pub mod common;
pub mod hosts;
pub mod nft;
pub mod pf;

use std::collections::BTreeSet;

use anyhow::bail;

use crate::blocker::common::ConfigStatus;
use crate::common::{IS_LINUX, IS_MACOS};
use crate::resolver::ResolvedAddr;

fn firewall_status(resolved_addrs: &BTreeSet<ResolvedAddr>) -> ConfigStatus {
    if IS_MACOS {
        pf::status(resolved_addrs)
    } else if IS_LINUX {
        nft::status(resolved_addrs)
    } else {
        ConfigStatus::Present
    }
}

// Each backend replaces its own config; re-apply is the repair path on drift.
pub fn apply(block_list: &[String], resolved_addrs: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
    let mut failures = Vec::new();

    if let Err(err) = hosts::block(block_list) {
        failures.push(format!("failed to update hosts file: {err:#}"));
    }

    if IS_MACOS && let Err(err) = pf::block(resolved_addrs) {
        failures.push(format!("failed to apply pf rules: {err:#}"));
    }
    if IS_LINUX && let Err(err) = nft::block(resolved_addrs) {
        failures.push(format!("failed to apply nftables rules: {err:#}"));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

pub fn is_intact(block_list: &[String], resolved_addrs: &BTreeSet<ResolvedAddr>) -> bool {
    let hosts_intact = match hosts::hosts_status(block_list) {
        Ok(status) => status == ConfigStatus::Present,
        Err(err) => {
            eprintln!("walden: failed to check the hosts file: {err}");
            false
        }
    };

    hosts_intact && firewall_status(resolved_addrs) == ConfigStatus::Present
}

pub fn leftovers_present() -> Result<bool, anyhow::Error> {
    let hosts_leftovers = hosts::has_section()?;

    let firewall_leftovers = if IS_MACOS {
        pf::has_leftovers()
    } else if IS_LINUX {
        nft::has_leftovers()
    } else {
        return Err(anyhow::anyhow!("Unsupported platform"));
    };

    Ok(hosts_leftovers || firewall_leftovers)
}

pub fn stop_blocking() -> anyhow::Result<()> {
    let mut failures = Vec::new();

    if let Err(err) = hosts::unblock() {
        failures.push(format!("failed to update hosts file: {err:#}"));
    }

    if IS_MACOS && let Err(err) = pf::unblock() {
        failures.push(format!("failed to remove pf rules: {err:#}"));
    }
    if IS_LINUX && let Err(err) = nft::unblock() {
        failures.push(format!("failed to remove nftables rules: {err:#}"));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}
