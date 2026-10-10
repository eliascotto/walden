// Local socket IPC between the walden CLI and waldend.

use crate::protocol::SOCKET_PATH;
use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};
use std::fmt;
use std::fs::{self, Permissions};
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{self, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

// Long enough for a client that means to say something, short enough that one
// that never finishes a frame cannot hold a worker indefinitely.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
// JSON payload bytes, excluding the newline. Fits the entire bundled catalog
// in one Start request, with room for custom websites.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const SERVER_WORKERS: usize = 8;
const PENDING_CLIENTS: usize = 16;

#[derive(Debug)]
pub enum IpcError {
    DeadlineExceeded,
    Disconnected,
    MessageTooLarge {
        limit: usize,
    },
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
            Self::MessageTooLarge { limit } => {
                write!(
                    formatter,
                    "the IPC message exceeds the {limit}-byte size limit"
                )
            }
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
            Self::DeadlineExceeded | Self::Disconnected | Self::MessageTooLarge { .. } => None,
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
    if line.len() > MAX_FRAME_BYTES {
        return Err(IpcError::MessageTooLarge {
            limit: MAX_FRAME_BYTES,
        });
    }
    writeln!(stream, "{}", line)
        .map_err(|err| IpcError::from_io("failed to write the IPC message", err))?;
    stream
        .flush()
        .map_err(|err| IpcError::from_io("failed to flush the IPC message", err))?;
    Ok(())
}

pub fn receive_json<T: DeserializeOwned>(stream: &mut UnixStream) -> IpcResult<T> {
    let timeout = stream
        .read_timeout()
        .map_err(|err| IpcError::from_io("failed to get the IPC read timeout", err))?;
    let deadline = Instant::now() + timeout.unwrap_or(CLIENT_TIMEOUT);
    let frame = read_frame(stream, deadline)?;
    serde_json::from_slice(&frame).map_err(IpcError::InvalidMessage)
}

fn read_frame(stream: &mut UnixStream, deadline: Instant) -> IpcResult<Vec<u8>> {
    let mut frame = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        // Peek to find the first newline without consuming the next frame.
        // A temporary BufReader would discard any bytes it read past it.
        let available = receive_bytes(stream, &mut chunk, libc::MSG_PEEK, deadline)?;
        let count = chunk[..available]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(available, |index| index + 1);

        let bytes = receive_bytes(stream, &mut chunk[..count], 0, deadline)?;
        let complete = chunk[bytes - 1] == b'\n';
        let payload_bytes = bytes - usize::from(complete);
        if payload_bytes > MAX_FRAME_BYTES - frame.len() {
            return Err(IpcError::MessageTooLarge {
                limit: MAX_FRAME_BYTES,
            });
        }
        frame.extend_from_slice(&chunk[..payload_bytes]);
        if complete {
            return Ok(frame);
        }
    }
}

// Poll with the remaining budget, then read without blocking. This keeps the
// socket's configured timeout intact and also works after the peer closes
// (macOS rejects changing SO_RCVTIMEO on that socket, even with unread data).
fn receive_bytes(
    stream: &UnixStream,
    buffer: &mut [u8],
    flags: libc::c_int,
    deadline: Instant,
) -> IpcResult<usize> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(IpcError::DeadlineExceeded);
        }
        // Round up to milliseconds so a sub-millisecond budget stays finite.
        let timeout_ms = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd: stream.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` is a valid pollfd borrowing a live socket, and
        // remains writable for the duration of this call.
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(IpcError::from_io("failed to wait for the IPC message", err));
        }
        if ready == 0 {
            continue;
        }
        // SAFETY: the socket is borrowed from `stream`, and `buffer` is
        // writable for the requested length throughout this call.
        let bytes = unsafe {
            libc::recv(
                stream.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                flags | libc::MSG_DONTWAIT,
            )
        };
        if bytes < 0 {
            let err = std::io::Error::last_os_error();
            if matches!(
                err.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(IpcError::from_io("failed to read the IPC message", err));
        }
        if Instant::now() >= deadline {
            return Err(IpcError::DeadlineExceeded);
        }
        if bytes == 0 {
            // Even valid JSON is incomplete until its newline arrives.
            return Err(IpcError::Disconnected);
        }
        return Ok(bytes as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
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
    fn a_frame_at_the_size_limit_round_trips() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let value = "x".repeat(MAX_FRAME_BYTES - 2); // JSON string quotes count too.
        let sender = thread::spawn(move || {
            writer.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
            send_json(&mut writer, &value).unwrap();
        });

        let received: String = receive_json(&mut reader).unwrap();
        assert_eq!(received.len(), MAX_FRAME_BYTES - 2);
        assert!(received.bytes().all(|byte| byte == b'x'));
        assert_eq!(reader.read_timeout().unwrap(), None);
        sender.join().unwrap();
    }

    // Keep the peer open after writing, so an unterminated frame cannot rely
    // on EOF to finish the read. The write timeout bounds a failed test too.
    fn send_frame(frame: Vec<u8>) -> (UnixStream, thread::JoinHandle<UnixStream>) {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_read_timeout(Some(CLIENT_TIMEOUT)).unwrap();
        let sender = thread::spawn(move || {
            writer.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
            writer.write_all(&frame).unwrap();
            writer
        });
        (reader, sender)
    }

    #[test]
    fn oversized_frames_are_rejected_with_or_without_a_newline() {
        for terminated in [false, true] {
            let mut frame = vec![b'x'; MAX_FRAME_BYTES + 1];
            frame[0] = b'"';
            frame[MAX_FRAME_BYTES] = b'"';
            if terminated {
                frame.push(b'\n');
            }
            let (mut reader, sender) = send_frame(frame);

            let result = receive_json::<String>(&mut reader);
            assert!(
                matches!(
                    result,
                    Err(IpcError::MessageTooLarge {
                        limit: MAX_FRAME_BYTES
                    })
                ),
                "{result:?}"
            );
            assert_eq!(reader.read_timeout().unwrap(), Some(CLIENT_TIMEOUT));
            sender.join().unwrap();
        }
    }

    #[test]
    fn an_oversized_outgoing_frame_writes_nothing() {
        let (mut writer, mut reader) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();

        let result = send_json(&mut writer, &"x".repeat(MAX_FRAME_BYTES - 1));
        assert!(matches!(result, Err(IpcError::MessageTooLarge { .. })));
        assert_eq!(
            reader.read(&mut [0_u8; 1]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn reading_one_frame_leaves_the_next_frame_on_the_socket() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let timeout = Duration::from_millis(200);
        reader.set_read_timeout(Some(timeout)).unwrap();
        writer.write_all(b"\"Status\"\n\"Stop\"\n").unwrap();

        assert_eq!(receive_json::<String>(&mut reader).unwrap(), "Status");
        assert_eq!(reader.read_timeout().unwrap(), Some(timeout));
        assert_eq!(receive_json::<String>(&mut reader).unwrap(), "Stop");
        assert_eq!(reader.read_timeout().unwrap(), Some(timeout));
    }

    #[test]
    fn eof_cannot_complete_an_unterminated_frame() {
        for frame in [b"null".as_slice(), b""] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(frame).unwrap();
            writer.shutdown(std::net::Shutdown::Write).unwrap();

            assert!(matches!(
                receive_json::<serde_json::Value>(&mut reader),
                Err(IpcError::Disconnected)
            ));
        }
    }

    #[test]
    fn a_complete_frame_from_a_closed_peer_is_accepted() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(b"null\n").unwrap();
        drop(writer);

        assert_eq!(
            receive_json::<serde_json::Value>(&mut reader).unwrap(),
            serde_json::Value::Null
        );
    }

    #[test]
    fn invalid_json_and_utf8_are_typed_invalid_messages() {
        for frame in [b"{]\n".as_slice(), b"\"\xff\"\n"] {
            let (mut reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(frame).unwrap();

            assert!(matches!(
                receive_json::<serde_json::Value>(&mut reader),
                Err(IpcError::InvalidMessage(_))
            ));
            assert_eq!(reader.read_timeout().unwrap(), None);
        }
    }

    #[test]
    fn fragmented_utf8_and_crlf_frames_are_accepted() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            writer.write_all(b"\"\xf0\x9f").unwrap();
            thread::sleep(Duration::from_millis(10));
            writer.write_all(b"\x8c\xb2\"\r\n").unwrap();
        });

        assert_eq!(receive_json::<String>(&mut reader).unwrap(), "🌲");
        sender.join().unwrap();
    }

    #[test]
    fn the_entire_bundled_catalog_fits_in_a_start_request() {
        let catalog = crate::catalog::Catalog::open(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor/walden-list/v1"),
        )
        .unwrap();
        let block_list = catalog
            .category_ids()
            .flat_map(|id| catalog.domains(id).unwrap().iter().cloned())
            .collect();
        let request = crate::protocol::ClientMessage::Start {
            operation_id: "catalog-round-trip".to_string(),
            block_list,
            unlock_delay_secs: 30,
        };
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let sender = thread::spawn(move || {
            writer.set_write_timeout(Some(CLIENT_TIMEOUT)).unwrap();
            send_json(&mut writer, &request).unwrap();
            request
        });

        let received = receive_json::<crate::protocol::ClientMessage>(&mut reader).unwrap();
        let expected = sender.join().unwrap();
        match (received, expected) {
            (
                crate::protocol::ClientMessage::Start {
                    operation_id,
                    block_list,
                    unlock_delay_secs,
                },
                crate::protocol::ClientMessage::Start {
                    operation_id: expected_id,
                    block_list: expected_list,
                    unlock_delay_secs: expected_delay,
                },
            ) => {
                assert_eq!(operation_id, expected_id);
                assert_eq!(block_list, expected_list);
                assert_eq!(unlock_delay_secs, expected_delay);
            }
            _ => panic!("expected a Start request"),
        }
    }

    #[test]
    fn slow_drip_input_cannot_extend_the_read_deadline() {
        let (mut reader, mut writer) = UnixStream::pair().unwrap();
        let timeout = Duration::from_millis(200);
        reader.set_read_timeout(Some(timeout)).unwrap();
        let sender = thread::spawn(move || {
            for _ in 0..60 {
                if writer.write_all(b" ").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let _ = writer.write_all(b"null\n");
        });

        let started = Instant::now();
        let result = receive_json::<serde_json::Value>(&mut reader);
        let elapsed = started.elapsed();
        assert_eq!(reader.read_timeout().unwrap(), Some(timeout));
        drop(reader);
        sender.join().unwrap();

        assert!(
            matches!(result, Err(IpcError::DeadlineExceeded)),
            "{result:?}"
        );
        assert!(elapsed < Duration::from_millis(600), "{elapsed:?}");
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
