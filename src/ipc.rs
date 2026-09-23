// Local socket IPC between the walden CLI and waldend.

use crate::protocol::SOCKET_PATH;
use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt;
use std::fs::{self, Permissions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

// Long enough for a client that means to say something, short enough that one
// that never does cannot hold the accept loop.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const SERVER_WORKERS: usize = 8;
const PENDING_CLIENTS: usize = 16;

#[derive(Debug)]
pub enum IpcError {
    DeadlineExceeded,
    Disconnected,
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    Serialize(serde_json::Error),
    InvalidMessage(serde_json::Error),
}

impl IpcError {
    fn from_io(action: &'static str, source: std::io::Error) -> Self {
        if source.kind() == std::io::ErrorKind::TimedOut
            || source.kind() == std::io::ErrorKind::WouldBlock
            || source.raw_os_error() == Some(35)
        {
            Self::DeadlineExceeded
        } else if matches!(
            source.kind(),
            std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::UnexpectedEof
        ) {
            Self::Disconnected
        } else {
            Self::Io { action, source }
        }
    }

    pub fn is_deadline(&self) -> bool {
        matches!(self, Self::DeadlineExceeded)
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExceeded => {
                write!(
                    formatter,
                    "the daemon did not answer before the IPC deadline"
                )
            }
            Self::Disconnected => write!(formatter, "the daemon closed the IPC connection"),
            Self::Io { action, source } => write!(formatter, "{action}: {source}"),
            Self::Serialize(source) => {
                write!(formatter, "failed to serialize IPC message: {source}")
            }
            Self::InvalidMessage(source) => {
                write!(
                    formatter,
                    "the daemon sent an invalid IPC message: {source}"
                )
            }
        }
    }
}

impl std::error::Error for IpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Serialize(source) | Self::InvalidMessage(source) => Some(source),
            Self::DeadlineExceeded | Self::Disconnected => None,
        }
    }
}

pub type IpcResult<T> = std::result::Result<T, IpcError>;

pub fn start_server(
    handler: impl Fn(UnixStream) -> Result<()> + Send + Sync + 'static,
) -> Result<()> {
    // Remove existing socket file
    if fs::metadata(SOCKET_PATH).is_ok() {
        fs::remove_file(SOCKET_PATH)
            .with_context(|| format!("Could not delete previous socket at {:?}", SOCKET_PATH))?;
    }

    let listener = UnixListener::bind(SOCKET_PATH).context("Failed to bind socket")?;

    // Stop/Status are unprivileged; Start is checked via peer credentials.
    // 0o666 is safe here because only root can create a socket under /var/run.
    fs::set_permissions(SOCKET_PATH, Permissions::from_mode(0o666))
        .context("Failed to set the socket permissions")?;

    serve_connections(
        listener.incoming(),
        Arc::new(handler),
        SERVER_WORKERS,
        PENDING_CLIENTS,
    )
}

fn serve_connections<I>(
    incoming: I,
    handler: Arc<impl Fn(UnixStream) -> Result<()> + Send + Sync + 'static>,
    worker_count: usize,
    pending_clients: usize,
) -> Result<()>
where
    I: IntoIterator<Item = std::io::Result<UnixStream>>,
{
    let (sender, receiver) = mpsc::sync_channel::<UnixStream>(pending_clients);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let receiver = Arc::clone(&receiver);
        let handler = Arc::clone(&handler);
        workers.push(thread::spawn(move || {
            loop {
                let stream = receiver
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .recv();
                let Ok(stream) = stream else {
                    break;
                };
                if let Err(err) = serve_client(handler.as_ref(), stream) {
                    eprintln!("walden: failed to handle a client: {err:#}");
                }
            }
        }));
    }

    let result = (|| {
        for stream in incoming {
            let stream = stream?;
            match sender.try_send(stream) {
                Ok(()) => {}
                // Refuse excess peers promptly instead of allocating an
                // unbounded thread per connection.
                Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    anyhow::bail!("all IPC workers stopped")
                }
            }
        }
        Ok(())
    })();

    drop(sender);
    for worker in workers {
        let _ = worker.join();
    }
    result
}

fn serve_client(handler: &impl Fn(UnixStream) -> Result<()>, stream: UnixStream) -> Result<()> {
    stream
        .set_read_timeout(Some(CLIENT_TIMEOUT))
        .context("Failed to set the client read timeout")?;
    stream
        .set_write_timeout(Some(CLIENT_TIMEOUT))
        .context("Failed to set the client write timeout")?;

    handler(stream)
}

// Peer uid from the kernel; cannot be forged by the client.
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    peer_uid_raw(stream.as_raw_fd()).context("Failed to read the peer's credentials")
}

#[cfg(target_os = "linux")]
fn peer_uid_raw(fd: RawFd) -> std::io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;

    // SAFETY: `fd` is a connected socket borrowed from the caller's stream, and
    // `cred`/`len` are valid to write for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut cred).cast(),
            &mut len,
        )
    };

    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred.uid)
}

#[cfg(not(target_os = "linux"))]
fn peer_uid_raw(fd: RawFd) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;

    // SAFETY: `fd` is a connected socket borrowed from the caller's stream, and
    // both out-parameters are valid to write for the duration of the call.
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };

    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

// A stale socket file looks like a live one; connect to tell them apart.
pub fn connect_client() -> IpcResult<UnixStream> {
    connect_client_with_timeout(CLIENT_TIMEOUT)
}

pub fn connect_client_with_timeout(timeout: Duration) -> IpcResult<UnixStream> {
    let stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|err| IpcError::from_io("failed to connect to the daemon socket", err))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| IpcError::from_io("failed to set the daemon read timeout", err))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| IpcError::from_io("failed to set the daemon write timeout", err))?;
    Ok(stream)
}

pub fn send_json<T: Serialize>(stream: &mut UnixStream, value: &T) -> IpcResult<()> {
    let line = serde_json::to_string(value).map_err(IpcError::Serialize)?;
    writeln!(stream, "{}", line)
        .map_err(|err| IpcError::from_io("failed to write the IPC message", err))?;
    stream
        .flush()
        .map_err(|err| IpcError::from_io("failed to flush the IPC message", err))?;
    Ok(())
}

pub fn receive_json<T: DeserializeOwned>(stream: &mut UnixStream) -> IpcResult<T> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .map_err(|err| IpcError::from_io("failed to read the IPC message", err))?;
    if bytes == 0 {
        return Err(IpcError::Disconnected);
    }
    serde_json::from_str(line.trim_end()).map_err(IpcError::InvalidMessage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Start is root-only; peer_uid is the enforcement point.
    #[test]
    fn peer_uid_reports_the_calling_user() {
        let (stream, _other_end) = UnixStream::pair().expect("failed to create a socket pair");

        // SAFETY: `geteuid` reads process state and cannot fail.
        let expected = unsafe { libc::geteuid() };

        assert_eq!(
            peer_uid(&stream).expect("failed to read the peer uid"),
            expected
        );
    }

    #[test]
    fn macos_would_block_is_a_typed_deadline() {
        let error = IpcError::from_io("read", std::io::Error::from_raw_os_error(35));

        assert!(error.is_deadline());
        assert_eq!(
            error.to_string(),
            "the daemon did not answer before the IPC deadline"
        );
    }

    #[test]
    fn server_concurrency_is_bounded() {
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let handler_active = Arc::clone(&active);
        let handler_peak = Arc::clone(&peak);
        let handler = Arc::new(move |_stream: UnixStream| {
            let current = handler_active.fetch_add(1, Ordering::SeqCst) + 1;
            handler_peak.fetch_max(current, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(20));
            handler_active.fetch_sub(1, Ordering::SeqCst);
            Ok(())
        });

        let mut clients = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..12 {
            let (client, server) = UnixStream::pair().unwrap();
            clients.push(client);
            servers.push(Ok(server));
        }

        serve_connections(servers, handler, 2, 12).unwrap();
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert!(peak.load(Ordering::SeqCst) >= 2);
        drop(clients);
    }
}
