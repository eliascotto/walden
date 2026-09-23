// systemd integration: read-only use of the package-installed unit file.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, ensure};

use super::{Activity, ServiceRecord, run_command};

pub const SERVICE_MANAGER: &str = "systemd";

const SERVICE_NAME: &str = "waldend.service";

pub const SERVICE_DEFINITION_DESCRIPTION: &str = "waldend.service";

fn command_succeeds(command: &str, args: &[&str], description: &str) -> anyhow::Result<()> {
    let output = Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {description}"))?;
    ensure!(
        output.status.success(),
        "{description} is required for Linux support: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

pub fn preflight() -> anyhow::Result<()> {
    command_succeeds("nft", &["--version"], "nftables")
}

pub fn inspect() -> anyhow::Result<ServiceRecord> {
    command_succeeds(
        "systemctl",
        &["show", "--property=Version", "--value"],
        "systemd",
    )?;

    let output = Command::new("systemctl")
        .args([
            "show",
            SERVICE_NAME,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=FragmentPath",
        ])
        .output()
        .context("failed to ask systemd about the Walden daemon")?;
    ensure!(
        output.status.success(),
        "failed to read the state of {SERVICE_NAME}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );

    Ok(parse_record(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_record(shown: &str) -> ServiceRecord {
    let mut load_state = "";
    let mut active_state = "";
    let mut fragment_path = "";

    for line in shown.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        match key.trim() {
            "LoadState" => load_state = value.trim(),
            "ActiveState" => active_state = value.trim(),
            "FragmentPath" => fragment_path = value.trim(),
            _ => {}
        }
    }

    let definition =
        (load_state == "loaded" && !fragment_path.is_empty()).then(|| PathBuf::from(fragment_path));

    let activity = match active_state {
        "active" | "reloading" => Activity::Active,
        "activating" | "deactivating" => Activity::Activating,
        "failed" => Activity::Failed,
        _ if definition.is_none() => Activity::Unregistered,
        _ => Activity::Inactive,
    };

    ServiceRecord {
        definition,
        activity,
    }
}

pub fn enable_autostart() -> anyhow::Result<()> {
    run_command(
        Command::new("systemctl").args(["enable", SERVICE_NAME]),
        "enable the systemd service",
    )
}

pub fn activate() -> anyhow::Result<()> {
    run_command(
        Command::new("systemctl").args(["enable", "--now", SERVICE_NAME]),
        "enable and start the systemd service",
    )
}

pub fn disable_autostart() -> anyhow::Result<()> {
    run_command(
        Command::new("systemctl").args(["disable", SERVICE_NAME]),
        "disable the systemd service",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(load_state: &str, active_state: &str, fragment_path: &str) -> String {
        format!(
            "LoadState={load_state}\nActiveState={active_state}\nFragmentPath={fragment_path}\n"
        )
    }

    #[test]
    fn an_installed_unit_is_read_from_where_systemd_found_it() {
        let record = parse_record(&shown(
            "loaded",
            "active",
            "/usr/lib/systemd/system/waldend.service",
        ));

        assert_eq!(
            record.definition.as_deref(),
            Some(std::path::Path::new(
                "/usr/lib/systemd/system/waldend.service"
            ))
        );
        assert_eq!(record.activity, Activity::Active);
    }

    #[test]
    fn an_installed_unit_that_is_stopped_is_inactive_rather_than_missing() {
        let record = parse_record(&shown(
            "loaded",
            "inactive",
            "/etc/systemd/system/waldend.service",
        ));

        assert!(record.definition.is_some());
        assert_eq!(record.activity, Activity::Inactive);
    }

    #[test]
    fn a_unit_systemd_cannot_find_is_not_installed() {
        let record = parse_record(&shown("not-found", "inactive", ""));

        assert!(record.definition.is_none());
        assert_eq!(record.activity, Activity::Unregistered);
    }

    #[test]
    fn a_failed_start_is_kept_distinct_from_a_stopped_service() {
        let record = parse_record(&shown(
            "loaded",
            "failed",
            "/etc/systemd/system/waldend.service",
        ));

        assert_eq!(record.activity, Activity::Failed);
    }

    #[test]
    fn a_starting_service_is_not_yet_active() {
        let record = parse_record(&shown(
            "loaded",
            "activating",
            "/etc/systemd/system/waldend.service",
        ));

        assert_eq!(record.activity, Activity::Activating);
    }

    #[test]
    fn properties_are_read_by_name_rather_than_by_position() {
        let record = parse_record(
            "FragmentPath=/etc/systemd/system/waldend.service\n\
             Description=Walden website-blocking daemon\n\
             ActiveState=active\n\
             LoadState=loaded\n",
        );

        assert!(record.definition.is_some());
        assert_eq!(record.activity, Activity::Active);
    }
}
