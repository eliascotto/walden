pub mod common;
pub mod hosts;
pub mod nft;
pub mod pf;

use std::collections::BTreeSet;

use anyhow::{Context, bail};

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
    let mut needs_action = false;

    if let Err(err) = hosts::block(block_list) {
        failures.push(format!("failed to update hosts file: {err:#}"));
    }

    if IS_MACOS && let Err(err) = pf::block(resolved_addrs) {
        needs_action = requires_action(&err);
        failures.push(format!("failed to apply pf rules: {err:#}"));
    }
    if IS_LINUX && let Err(err) = nft::block(resolved_addrs) {
        failures.push(format!("failed to apply nftables rules: {err:#}"));
    }

    if failures.is_empty() {
        Ok(())
    } else if needs_action {
        Err(pf::ConfigurationError(failures.join("; ")).into())
    } else {
        bail!(failures.join("; "))
    }
}

pub fn prepare() -> anyhow::Result<()> {
    if IS_MACOS {
        pf::prepare().context("failed to prepare macOS firewall")?;
    }
    Ok(())
}

pub fn requires_action(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<pf::ConfigurationError>()
            || cause
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied)
    })
}

pub fn is_intact(block_list: &[String], resolved_addrs: &BTreeSet<ResolvedAddr>) -> bool {
    let hosts_intact = match hosts::hosts_status(block_list) {
        Ok(status) => status == ConfigStatus::Present,
        Err(err) => {
            crate::daemon_log!("walden: failed to check the hosts file: {err}");
            false
        }
    };

    hosts_intact && firewall_status(resolved_addrs) == ConfigStatus::Present
}

pub fn leftovers_present() -> Result<bool, anyhow::Error> {
    Ok(!cleanup_leftovers()?.is_empty())
}

pub fn cleanup_leftovers() -> anyhow::Result<Vec<String>> {
    let mut remaining = Vec::new();
    let mut errors = Vec::new();
    match hosts::has_section() {
        Ok(true) => remaining.push("Walden entries in /etc/hosts".into()),
        Ok(false) => {}
        Err(err) => errors.push(format!("hosts verification failed: {err:#}")),
    }
    let firewall = if IS_MACOS {
        pf::cleanup_leftovers()
    } else if IS_LINUX {
        nft::cleanup_leftovers()
    } else {
        bail!("unsupported platform");
    };
    match firewall {
        Ok(leftovers) => remaining.extend(leftovers),
        Err(err) => errors.push(format!("firewall verification failed: {err:#}")),
    }
    if !errors.is_empty() {
        if !remaining.is_empty() {
            errors.push(format!("remaining: {}", remaining.join(", ")));
        }
        bail!(errors.join("; "));
    }
    Ok(remaining)
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
