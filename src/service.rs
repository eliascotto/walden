// Daemon service management: Walden activates the package-installed waldend
// service for a block and hands it back when the block ends. The executable
// and unit/plist are package-owned and never written here.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};

use crate::common;
use crate::ipc;
use crate::protocol::{self, SOCKET_PATH};

#[cfg(target_os = "macos")]
mod launchd;
#[cfg(target_os = "linux")]
mod systemd;

#[cfg(target_os = "macos")]
use launchd as platform;
#[cfg(target_os = "linux")]
use systemd as platform;

// Both platform lists are kept so packaging can be checked cross-platform.
pub const MACOS_DAEMON_BINARY_CANDIDATES: &[&str] = &["/usr/local/libexec/waldend"];
pub const LINUX_DAEMON_BINARY_CANDIDATES: &[&str] = &[
    "/usr/local/libexec/waldend",
    "/usr/libexec/waldend",
    "/usr/lib/walden/waldend",
];

#[cfg(target_os = "macos")]
pub const DAEMON_BINARY_CANDIDATES: &[&str] = MACOS_DAEMON_BINARY_CANDIDATES;
#[cfg(target_os = "linux")]
pub const DAEMON_BINARY_CANDIDATES: &[&str] = LINUX_DAEMON_BINARY_CANDIDATES;

const REACHABLE_TIMEOUT: Duration = Duration::from_secs(5);
const REACHABLE_POLL: Duration = Duration::from_millis(200);
const RESPONSIVE_TIMEOUT: Duration = Duration::from_secs(1);

const MISSING_INSTALLATION_HINT: &str =
    "install the Walden package for this system, then try again";
const BROKEN_INSTALLATION_HINT: &str = "reinstall the Walden package for this system";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    // Not loaded since boot — ordinary idle, not a missing install.
    Unregistered,
    Inactive,
    Activating,
    Active,
    Failed,
}

pub struct ServiceRecord {
    pub definition: Option<PathBuf>,
    pub activity: Activity,
}

enum DaemonProbe {
    Responsive(protocol::StatusResponse),
    Unreachable,
    Incompatible(String),
}

pub struct ServiceInspection {
    pub state: ServiceState,
    pub status: Option<protocol::StatusResponse>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceState {
    NotInstalled,
    Inactive,
    Starting,
    Running,
    Unhealthy(String),
}

impl ServiceState {
    pub fn describe(&self) -> String {
        match self {
            ServiceState::NotInstalled => "not installed".to_string(),
            ServiceState::Inactive => "installed but not running".to_string(),
            ServiceState::Starting => "starting".to_string(),
            ServiceState::Running => "running".to_string(),
            ServiceState::Unhealthy(reason) => format!("unhealthy ({reason})"),
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, ServiceState::Running)
    }
}

fn run_command(cmd: &mut Command, action: &str) -> anyhow::Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("failed to {action}"))?;
    ensure!(status.success(), "failed to {action}: {status}");
    Ok(())
}

fn daemon_binary() -> Option<PathBuf> {
    DAEMON_BINARY_CANDIDATES
        .iter()
        .map(Path::new)
        .find(|candidate| candidate.exists())
        .map(Path::to_path_buf)
}

fn classify(
    daemon: Option<&Path>,
    record: &ServiceRecord,
    socket_is_reachable: bool,
) -> ServiceState {
    match (daemon, record.definition.as_deref()) {
        (None, None) => return ServiceState::NotInstalled,

        (None, Some(definition)) => {
            return ServiceState::Unhealthy(format!(
                "{} runs a waldend executable that is not installed; {BROKEN_INSTALLATION_HINT}",
                definition.display()
            ));
        }
        (Some(daemon), None) => {
            return ServiceState::Unhealthy(format!(
                "{} is installed, but its {} service definition ({}) is not; {BROKEN_INSTALLATION_HINT}",
                daemon.display(),
                platform::SERVICE_MANAGER,
                platform::SERVICE_DEFINITION_DESCRIPTION
            ));
        }

        (Some(_), Some(_)) => {}
    }

    match record.activity {
        Activity::Failed => ServiceState::Unhealthy(format!(
            "the {manager} service failed to start; check the {manager} log for waldend",
            manager = platform::SERVICE_MANAGER
        )),
        Activity::Activating => ServiceState::Starting,
        Activity::Active if socket_is_reachable => ServiceState::Running,
        Activity::Active => ServiceState::Starting,
        Activity::Unregistered | Activity::Inactive => ServiceState::Inactive,
    }
}

pub fn inspect() -> anyhow::Result<ServiceInspection> {
    let record = platform::inspect()?;
    let daemon = daemon_binary();
    let should_probe =
        daemon.is_some() && record.definition.is_some() && record.activity == Activity::Active;
    let probe = should_probe.then(daemon_probe);

    let (responsive, status, incompatibility) = match probe {
        Some(DaemonProbe::Responsive(status)) => (true, Some(status), None),
        Some(DaemonProbe::Incompatible(reason)) => (false, None, Some(reason)),
        Some(DaemonProbe::Unreachable) | None => (false, None, None),
    };

    let state = if let Some(reason) = incompatibility {
        ServiceState::Unhealthy(format!(
            "the CLI and running daemon are incompatible: {reason}"
        ))
    } else {
        classify(daemon.as_deref(), &record, responsive)
    };

    Ok(ServiceInspection { state, status })
}

pub fn state() -> anyhow::Result<ServiceState> {
    Ok(inspect()?.state)
}

// Service-manager state only. Used by `stop`, which must send its request
// directly instead of issuing a preliminary status RPC.
pub fn manager_state() -> anyhow::Result<ServiceState> {
    let record = platform::inspect()?;
    let daemon = daemon_binary();
    Ok(classify(daemon.as_deref(), &record, false))
}

// A successful Unix-socket connect only proves that a listener exists.  The
// old probe labelled that state "running", then the caller immediately timed
// out trying to read status.  Require one cheap application-level round trip
// before claiming the daemon is running.
fn daemon_probe() -> DaemonProbe {
    let Ok(mut stream) = ipc::connect_client_with_timeout(RESPONSIVE_TIMEOUT) else {
        return DaemonProbe::Unreachable;
    };
    if let Err(err) = protocol::client_handshake(&mut stream) {
        let ipc_error = err
            .chain()
            .find_map(|cause| cause.downcast_ref::<ipc::IpcError>());
        return match ipc_error {
            Some(ipc::IpcError::DeadlineExceeded)
            | Some(ipc::IpcError::Disconnected)
            | Some(ipc::IpcError::Io { .. }) => DaemonProbe::Unreachable,
            Some(ipc::IpcError::InvalidMessage(_)) | Some(ipc::IpcError::Serialize(_)) | None => {
                DaemonProbe::Incompatible(format!("{err:#}"))
            }
        };
    }
    if ipc::send_json(&mut stream, &protocol::ClientMessage::Status).is_err() {
        return DaemonProbe::Unreachable;
    }
    match ipc::receive_json::<protocol::StatusResponse>(&mut stream) {
        Ok(status) => DaemonProbe::Responsive(status),
        Err(ipc::IpcError::InvalidMessage(err)) => {
            DaemonProbe::Incompatible(format!("the daemon returned invalid status: {err}"))
        }
        Err(_) => DaemonProbe::Unreachable,
    }
}

fn usable_state() -> anyhow::Result<ServiceState> {
    let state = state()?;

    match &state {
        ServiceState::NotInstalled => {
            bail!("the Walden daemon is not installed on this system; {MISSING_INSTALLATION_HINT}")
        }
        ServiceState::Unhealthy(reason) => {
            bail!("the Walden daemon service is not usable: {reason}")
        }
        _ => Ok(state),
    }
}

// Run before elevation so a missing install fails without a password prompt.
pub fn verify_ready_to_start() -> anyhow::Result<()> {
    platform::preflight()?;
    usable_state().map(|_| ())
}

pub fn start_daemon() -> anyhow::Result<()> {
    platform::preflight()?;

    match usable_state()? {
        ServiceState::Running => return Ok(()),
        ServiceState::Starting => {}
        _ => platform::activate().context("failed to start the Walden daemon service")?,
    }

    wait_until_responsive()
}

fn wait_until_responsive() -> anyhow::Result<()> {
    let deadline = Instant::now() + REACHABLE_TIMEOUT;

    loop {
        match daemon_probe() {
            DaemonProbe::Responsive(_) => return Ok(()),
            DaemonProbe::Incompatible(reason) => {
                bail!("the running daemon is incompatible: {reason}")
            }
            DaemonProbe::Unreachable => {}
        }

        if Instant::now() >= deadline {
            break;
        }

        thread::sleep(REACHABLE_POLL);
    }

    let manager = platform::SERVICE_MANAGER;

    match platform::inspect()?.activity {
        Activity::Active => bail!(
            "the Walden daemon is running but is not answering on {SOCKET_PATH}; check the {manager} log for waldend"
        ),
        activity => bail!(
            "the Walden daemon did not start; {manager} reports it as {}",
            describe_activity(activity)
        ),
    }
}

fn describe_activity(activity: Activity) -> &'static str {
    match activity {
        Activity::Unregistered => "not loaded",
        Activity::Inactive => "inactive",
        Activity::Activating => "still starting",
        Activity::Active => "active",
        Activity::Failed => "failed",
    }
}

pub fn ensure_autostart_enabled() -> anyhow::Result<()> {
    platform::enable_autostart()
}

// Idempotent; safe to retry on partial failure.
pub fn retire_daemon() -> anyhow::Result<()> {
    platform::disable_autostart()
        .context("failed to stop the Walden daemon service from starting again")?;

    common::remove_file_if_present(SOCKET_PATH).context("failed to remove the daemon socket")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(definition: Option<&str>, activity: Activity) -> ServiceRecord {
        ServiceRecord {
            definition: definition.map(PathBuf::from),
            activity,
        }
    }

    fn classify_installed(activity: Activity, socket_is_reachable: bool) -> ServiceState {
        classify(
            Some(Path::new(DAEMON_BINARY_CANDIDATES[0])),
            &record(Some("/definition"), activity),
            socket_is_reachable,
        )
    }

    #[test]
    fn a_missing_installation_is_not_an_idle_one() {
        assert_eq!(
            classify(None, &record(None, Activity::Unregistered), false),
            ServiceState::NotInstalled
        );
        assert_eq!(
            classify_installed(Activity::Unregistered, false),
            ServiceState::Inactive
        );
        assert_eq!(
            classify_installed(Activity::Inactive, false),
            ServiceState::Inactive
        );
    }

    #[test]
    fn half_an_installation_names_the_missing_half() {
        let ServiceState::Unhealthy(no_daemon) = classify(
            None,
            &record(Some("/definition"), Activity::Inactive),
            false,
        ) else {
            panic!("a service definition without its executable should be unhealthy");
        };
        assert!(no_daemon.contains("/definition"));
        assert!(no_daemon.contains("waldend executable"));

        let ServiceState::Unhealthy(no_definition) = classify(
            Some(Path::new("/somewhere/waldend")),
            &record(None, Activity::Unregistered),
            false,
        ) else {
            panic!("an executable without its service definition should be unhealthy");
        };
        assert!(no_definition.contains("/somewhere/waldend"));
        assert!(no_definition.contains(platform::SERVICE_DEFINITION_DESCRIPTION));
    }

    #[test]
    fn a_service_is_running_only_once_it_answers() {
        assert_eq!(
            classify_installed(Activity::Active, true),
            ServiceState::Running
        );
        assert_eq!(
            classify_installed(Activity::Active, false),
            ServiceState::Starting
        );
        assert_eq!(
            classify_installed(Activity::Activating, false),
            ServiceState::Starting
        );
    }

    #[test]
    fn a_failed_service_is_reported_as_unhealthy_rather_than_idle() {
        let ServiceState::Unhealthy(reason) = classify_installed(Activity::Failed, false) else {
            panic!("a failed service should be unhealthy");
        };
        assert!(reason.contains(platform::SERVICE_MANAGER));
    }

    #[test]
    fn every_state_reads_differently_from_the_others() {
        let described: Vec<String> = [
            ServiceState::NotInstalled,
            ServiceState::Inactive,
            ServiceState::Starting,
            ServiceState::Running,
        ]
        .iter()
        .map(ServiceState::describe)
        .collect();

        for (position, description) in described.iter().enumerate() {
            assert!(!description.is_empty());
            assert!(
                !described[position + 1..].contains(description),
                "two service states both read as {description}"
            );
        }

        assert!(
            ServiceState::Unhealthy("half installed".to_string())
                .describe()
                .contains("half installed")
        );
    }

    #[test]
    fn nothing_short_of_a_running_service_counts_as_running() {
        assert!(ServiceState::Running.is_running());

        for state in [
            ServiceState::NotInstalled,
            ServiceState::Inactive,
            ServiceState::Starting,
            ServiceState::Unhealthy("half installed".to_string()),
        ] {
            assert!(!state.is_running(), "{state:?} should not count as running");
        }
    }
}
