// The daemon binary: the privileged background process that keeps
// blocking active. It receives messages via socket from CLI.

use anyhow::{Result, bail};
use std::os::unix::net::UnixStream;
use std::thread;

use walden::build_info::{self, BuildInfo};
use walden::ipc;
use walden::lifecycle::{self, Lifecycle};
use walden::protocol;
use walden::service;

const ROOT_UID: u32 = 0;

// Clients only ever state an intent. Applying it, and everything that follows
// from it, belongs to the lifecycle.
fn handle_client(lifecycle: &Lifecycle, mut stream: UnixStream) -> Result<()> {
    protocol::server_handshake(&mut stream)?;
    let message: protocol::ClientMessage = ipc::receive_json(&mut stream)?;

    match message {
        protocol::ClientMessage::Hello { .. } => {
            bail!("the client sent a second compatibility handshake")
        }
        // The one request that puts rules on the machine and fixes the delay
        // they come down after, so it is the one kept to root. The socket is
        // reachable by every local user, and the uid comes from the kernel
        // rather than from anything the client claims about itself.
        protocol::ClientMessage::Start {
            operation_id,
            block_list,
            unlock_delay_secs,
        } => {
            let result = (|| {
                let uid = ipc::peer_uid(&stream)?;
                if uid != ROOT_UID {
                    bail!("only root can start a block, and this request came from uid {uid}");
                }

                lifecycle.start(operation_id, block_list, unlock_delay_secs)
            })();
            send_start_response(&mut stream, result)
        }
        protocol::ClientMessage::Stop => {
            let result = lifecycle.stop();
            send_stop_response(&mut stream, result)
        }
        protocol::ClientMessage::Status => {
            ipc::send_json(&mut stream, &lifecycle.status())?;
            Ok(())
        }
    }
}

fn print_version(verbose: bool) {
    let build = BuildInfo::current();
    if !verbose {
        println!("waldend {} ({})", build.version, build.short_build_id());
        return;
    }

    println!("Walden daemon {}", build.version);
    println!("Build ID       : {}", build.build_id);
    println!("Protocol       : {}", protocol::PROTOCOL_VERSION);
    println!("Target         : {}", build.target);
    println!("Profile        : {}", build.profile);
    println!(
        "Source epoch   : {}",
        build.source_date_epoch.as_deref().unwrap_or("not set")
    );
    println!("Binary marker  : {}", build_info::binary_marker());
    println!("Profile marker : {}", build_info::profile_marker());
}

fn version_requested() -> Option<bool> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [arg] if arg == "--version" || arg == "-V" => Some(false),
        [arg, verbose] if arg == "--version" && verbose == "--verbose" => Some(true),
        _ => None,
    }
}

fn send_start_response(stream: &mut UnixStream, result: Result<String>) -> Result<()> {
    let response = match result {
        Ok(operation_id) => protocol::CommandResponse::StartAccepted { operation_id },
        Err(err) => protocol::CommandResponse::Rejected {
            message: format!("{err:#}"),
        },
    };

    ipc::send_json(stream, &response)?;
    Ok(())
}

fn send_stop_response(
    stream: &mut UnixStream,
    result: Result<protocol::StopOutcome>,
) -> Result<()> {
    let response = match result {
        Ok(outcome) => protocol::CommandResponse::StopCompleted { outcome },
        Err(err) => protocol::CommandResponse::Rejected {
            message: format!("{err:#}"),
        },
    };

    ipc::send_json(stream, &response)?;
    Ok(())
}

fn main() {
    if let Some(verbose) = version_requested() {
        print_version(verbose);
        return;
    }

    let lifecycle = Lifecycle::from_disk();

    // Kick off restoration without waiting for DNS or rule writes, so the
    // socket can come up while a large block is still being applied.
    lifecycle.resume();

    // A block outlives a reboot only while the service manager still has orders
    // to bring the daemon back. Those orders are re-asserted rather than
    // assumed, because a daemon that is running now proves nothing about
    // whether anything would start it again.
    if lifecycle.status().block_is_running
        && let Err(err) = service::ensure_autostart_enabled()
    {
        eprintln!("walden: failed to keep the daemon enabled at startup: {err:#}");
    }

    // The socket server gets its own thread: the loop below owns the block and
    // has to keep ticking while a client is being served.
    let server_lifecycle = lifecycle.clone();
    thread::spawn(move || {
        // A daemon that can no longer be reached still enforces its block, so
        // losing the socket is reported rather than fatal.
        if let Err(err) = ipc::start_server(move |stream| handle_client(&server_lifecycle, stream))
        {
            eprintln!("walden: the IPC server stopped: {err}");
        }
    });

    lifecycle::run(&lifecycle);
}
