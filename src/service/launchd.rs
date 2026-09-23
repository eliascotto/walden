// launchd integration: read-only use of the package-installed plist.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;

use super::{Activity, ServiceRecord, run_command};

pub const SERVICE_MANAGER: &str = "launchd";

const DAEMON_TARGET: &str = "system/org.scotto.waldend";

const SERVICE_DEFINITION_PATH: &str = "/Library/LaunchDaemons/org.scotto.waldend.plist";
pub const SERVICE_DEFINITION_DESCRIPTION: &str = SERVICE_DEFINITION_PATH;

pub fn preflight() -> anyhow::Result<()> {
    Ok(())
}

pub fn inspect() -> anyhow::Result<ServiceRecord> {
    let definition = Path::new(SERVICE_DEFINITION_PATH)
        .exists()
        .then(|| PathBuf::from(SERVICE_DEFINITION_PATH));

    Ok(ServiceRecord {
        definition,
        activity: activity()?,
    })
}

fn activity() -> anyhow::Result<Activity> {
    let output = Command::new("launchctl")
        .args(["print", DAEMON_TARGET])
        .output()
        .context("failed to ask launchd about the Walden daemon")?;

    if !output.status.success() {
        return Ok(Activity::Unregistered);
    }

    Ok(parse_activity(&String::from_utf8_lossy(&output.stdout)))
}

fn parse_activity(printed: &str) -> Activity {
    let state = printed
        .lines()
        .find_map(|line| line.trim().strip_prefix("state = "))
        .map(str::trim);

    match state {
        Some("running") => Activity::Active,
        Some("spawn scheduled") | Some("waiting") => Activity::Activating,
        _ => Activity::Inactive,
    }
}

pub fn enable_autostart() -> anyhow::Result<()> {
    run_command(
        Command::new("launchctl").args(["enable", DAEMON_TARGET]),
        "enable the launchd job",
    )
}

pub fn activate() -> anyhow::Result<()> {
    // Packaged job ships disabled; enable before bootstrap.
    enable_autostart()?;

    if matches!(activity()?, Activity::Unregistered) {
        run_command(
            Command::new("launchctl").args(["bootstrap", "system", SERVICE_DEFINITION_PATH]),
            "load the launchd job",
        )
    } else {
        run_command(
            Command::new("launchctl").args(["kickstart", DAEMON_TARGET]),
            "start the launchd job",
        )
    }
}

pub fn disable_autostart() -> anyhow::Result<()> {
    run_command(
        Command::new("launchctl").args(["disable", DAEMON_TARGET]),
        "disable the launchd job",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRINTED_JOB: &str = "\
system/org.scotto.waldend = {
	active count = 1
	path = /Library/LaunchDaemons/org.scotto.waldend.plist
	state = running
	program = /usr/local/libexec/waldend
}";

    #[test]
    fn a_running_job_is_read_from_its_state_line() {
        assert_eq!(parse_activity(PRINTED_JOB), Activity::Active);
    }

    #[test]
    fn a_loaded_job_that_is_not_running_is_inactive() {
        let printed = PRINTED_JOB.replace("state = running", "state = not running");
        assert_eq!(parse_activity(&printed), Activity::Inactive);
    }

    #[test]
    fn a_job_waiting_to_be_spawned_is_still_starting() {
        let printed = PRINTED_JOB.replace("state = running", "state = spawn scheduled");
        assert_eq!(parse_activity(&printed), Activity::Activating);
    }

    #[test]
    fn an_unreadable_dump_is_never_read_as_running() {
        assert_eq!(parse_activity(""), Activity::Inactive);
        assert_eq!(parse_activity("could not find service"), Activity::Inactive);
    }
}
