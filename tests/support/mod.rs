use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
static CAPTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

pub trait CommandTimeout {
    fn output_with_timeout(&mut self) -> io::Result<Output>;
}

impl CommandTimeout for Command {
    fn output_with_timeout(&mut self) -> io::Result<Output> {
        output_with_timeout(self, COMMAND_TIMEOUT)
    }
}

struct ProcessGroup {
    child: Child,
    terminated: bool,
}

impl ProcessGroup {
    fn terminate(&mut self) {
        if self.terminated {
            return;
        }
        self.terminated = true;
        // SAFETY: the child was spawned in its own process group. A negative
        // PID signals that group, including children holding output handles.
        unsafe {
            libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn capture_file() -> io::Result<File> {
    loop {
        let sequence = CAPTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "walden-test-output-{}-{sequence}",
            std::process::id()
        ));
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            result => result?,
        };
        // An unlinked file remains usable until its handles close, even if
        // the test panics. Files also avoid waiting on inherited output pipes.
        fs::remove_file(path)?;
        return Ok(file);
    }
}

fn read_capture(file: &mut File) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn output_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    let description = format!("{command:?}");
    let mut stdout = capture_file()?;
    let mut stderr = capture_file()?;
    command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .process_group(0);
    let deadline = Instant::now() + timeout;
    let mut child = ProcessGroup {
        child: command.spawn()?,
        terminated: false,
    };

    loop {
        if let Some(status) = child.child.try_wait()? {
            child.terminate();
            return Ok(Output {
                status,
                stdout: read_capture(&mut stdout)?,
                stderr: read_capture(&mut stderr)?,
            });
        }
        if Instant::now() >= deadline {
            child.terminate();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "{description} exceeded {timeout:?}; killed its process group\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&read_capture(&mut stdout)?),
                    String::from_utf8_lossy(&read_capture(&mut stderr)?),
                ),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_both_streams_and_nonzero_status() {
        let output = Command::new("sh")
            .args(["-c", "printf out; printf err >&2; exit 7"])
            .output_with_timeout()
            .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
    }

    #[test]
    fn terminates_a_stalled_command_with_a_child_and_reports_output() {
        let started = Instant::now();
        let err = output_with_timeout(
            Command::new("sh").args([
                "-c",
                "printf waiting; printf diagnostic >&2; sleep 60 & wait",
            ]),
            Duration::from_millis(200),
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
        let message = err.to_string();
        assert!(message.contains("killed its process group"), "{message}");
        assert!(message.contains("waiting"), "{message}");
        assert!(message.contains("diagnostic"), "{message}");
    }

    #[test]
    fn a_child_inheriting_output_does_not_hold_up_a_completed_command() {
        let started = Instant::now();
        let output = output_with_timeout(
            Command::new("sh").args(["-c", "sleep 60 & printf done"]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"done");
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
