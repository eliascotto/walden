// CLI ↔ waldend JSON protocol over a local Unix socket.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::os::unix::net::UnixStream;

use anyhow::{Context, bail, ensure};

use crate::build_info::BuildInfo;
use crate::ipc;

pub const SOCKET_PATH: &str = "/var/run/waldend.sock";
pub const PROTOCOL_VERSION: u32 = 3;

#[derive(Serialize, Deserialize)]
pub enum ClientMessage {
    Hello {
        protocol_version: u32,
        client: BuildInfo,
    },
    Start {
        operation_id: String,
        block_list: Vec<String>,
        unlock_delay_secs: u64,
    },
    Stop,
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HelloResponse {
    pub protocol_version: u32,
    pub daemon: BuildInfo,
    pub accepted: bool,
    pub message: Option<String>,
}

pub fn client_handshake(stream: &mut UnixStream) -> anyhow::Result<BuildInfo> {
    let client = BuildInfo::current();
    ipc::send_json(
        stream,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            client: client.clone(),
        },
    )
    .context("failed to send the compatibility handshake to the daemon")?;

    let response: HelloResponse = ipc::receive_json(stream).context(
        "the daemon did not complete the compatibility handshake; reinstall Walden so the CLI and daemon come from the same build",
    )?;
    ensure!(
        response.protocol_version == PROTOCOL_VERSION,
        "the installed daemon uses protocol {}, but this CLI uses protocol {}; reinstall Walden",
        response.protocol_version,
        PROTOCOL_VERSION
    );
    if !response.accepted {
        bail!(response.message.unwrap_or_else(|| {
            "the installed CLI and daemon are incompatible; reinstall Walden".to_string()
        }));
    }
    ensure!(
        client.is_same_release(&response.daemon),
        "the installed daemon is Walden {} build {}, but this CLI is Walden {} build {}; reinstall Walden so both executables come from the same package",
        response.daemon.version,
        response.daemon.short_build_id(),
        client.version,
        client.short_build_id()
    );
    Ok(response.daemon)
}

pub fn server_handshake(stream: &mut UnixStream) -> anyhow::Result<BuildInfo> {
    let request: ClientMessage = ipc::receive_json(stream).context(
        "the client did not begin with a compatibility handshake; reinstall Walden so the CLI and daemon come from the same build",
    )?;
    let ClientMessage::Hello {
        protocol_version,
        client,
    } = request
    else {
        bail!(
            "the client did not begin with a compatibility handshake; reinstall Walden so the CLI and daemon come from the same build"
        );
    };

    let daemon = BuildInfo::current();
    let compatible_protocol = protocol_version == PROTOCOL_VERSION;
    let compatible_build = client.is_same_release(&daemon);
    let accepted = compatible_protocol && compatible_build;
    let message = if !compatible_protocol {
        Some(format!(
            "the CLI uses protocol {protocol_version}, but the installed daemon uses protocol {PROTOCOL_VERSION}; reinstall Walden"
        ))
    } else if !compatible_build {
        Some(format!(
            "the CLI is Walden {} build {}, but the installed daemon is Walden {} build {}; reinstall Walden so both executables come from the same package",
            client.version,
            client.short_build_id(),
            daemon.version,
            daemon.short_build_id()
        ))
    } else {
        None
    };

    ipc::send_json(
        stream,
        &HelloResponse {
            protocol_version: PROTOCOL_VERSION,
            daemon: daemon.clone(),
            accepted,
            message: message.clone(),
        },
    )
    .context("failed to send the daemon identity")?;

    if !accepted {
        bail!(message.expect("a rejected handshake has a reason"));
    }
    Ok(client)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CommandResponse {
    StartAccepted { operation_id: String },
    StopCompleted { outcome: StopOutcome },
    Rejected { message: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopOutcome {
    AlreadyInactive,
    ApplyCancelled,
    Ending { block_end_at: DateTime<Utc> },
    AlreadyEnding { block_end_at: DateTime<Utc> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockPhase {
    Inactive,
    Applying,
    Active,
    Ending,
    ApplyFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyStage {
    WritingHosts,
    Resolving,
    InstallingFirewall,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ApplyProgress {
    pub stage: ApplyStage,
    pub completed: usize,
    pub total: usize,
    pub resolved_addresses: usize,
    pub failed_lookups: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatusResponse {
    pub operation_id: Option<String>,
    pub block_is_running: bool,
    pub unlock_delay_secs: Option<u64>,
    pub block_end_at: Option<DateTime<Utc>>,
    pub block_phase: BlockPhase,
    pub website_count: Option<usize>,
    pub apply_started_at: Option<DateTime<Utc>>,
    pub apply_error: Option<String>,
    pub apply_progress: Option<ApplyProgress>,
}

impl StatusResponse {
    pub fn inactive() -> Self {
        Self {
            operation_id: None,
            block_is_running: false,
            unlock_delay_secs: None,
            block_end_at: None,
            block_phase: BlockPhase::Inactive,
            website_count: None,
            apply_started_at: None,
            apply_error: None,
            apply_progress: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn matching_builds_complete_the_handshake() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = thread::spawn(move || server_handshake(&mut daemon).unwrap());

        let daemon_build = client_handshake(&mut client).unwrap();
        assert!(daemon_build.is_same_release(&BuildInfo::current()));
        assert!(
            daemon_thread
                .join()
                .unwrap()
                .is_same_release(&BuildInfo::current())
        );
    }

    #[test]
    fn daemon_rejects_a_different_source_build() {
        let (mut client_stream, mut daemon_stream) = UnixStream::pair().unwrap();
        let daemon_thread = thread::spawn(move || server_handshake(&mut daemon_stream));
        let mut client = BuildInfo::current();
        client.build_id = "0".repeat(64);

        ipc::send_json(
            &mut client_stream,
            &ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION,
                client,
            },
        )
        .unwrap();
        let response: HelloResponse = ipc::receive_json(&mut client_stream).unwrap();

        assert!(!response.accepted);
        assert!(response.message.unwrap().contains("same package"));
        assert!(daemon_thread.join().unwrap().is_err());
    }

    #[test]
    fn daemon_rejects_a_different_protocol() {
        let (mut client_stream, mut daemon_stream) = UnixStream::pair().unwrap();
        let daemon_thread = thread::spawn(move || server_handshake(&mut daemon_stream));

        ipc::send_json(
            &mut client_stream,
            &ClientMessage::Hello {
                protocol_version: PROTOCOL_VERSION + 1,
                client: BuildInfo::current(),
            },
        )
        .unwrap();
        let response: HelloResponse = ipc::receive_json(&mut client_stream).unwrap();

        assert!(!response.accepted);
        assert!(response.message.unwrap().contains("protocol"));
        assert!(daemon_thread.join().unwrap().is_err());
    }
}
