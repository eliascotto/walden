use std::fs::{self, OpenOptions};
use std::io::{Error, ErrorKind, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::Context;

pub const IS_LINUX: bool = cfg!(target_os = "linux");
pub const IS_MACOS: bool = cfg!(target_os = "macos");

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn write_atomically_impl<P: AsRef<Path>>(
    path: P,
    bytes: &[u8],
    mode: Option<u32>,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .context("atomic write path has no parent directory")?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    if let Some(mode) = mode {
        options.mode(mode);
    }

    // A sibling stays on the same filesystem. Each attempt gets its own name;
    // create_new also protects files left by a crashed process or a reused PID.
    let (temp_path, mut file) = loop {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = parent.join(format!(".walden-tmp-{}-{sequence}", std::process::id()));
        if temp_path == path {
            continue;
        }
        match options.open(&temp_path) {
            Ok(file) => break (temp_path, file),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("failed to open {}", temp_path.display()));
            }
        }
    };

    let result = (|| {
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync {}", temp_path.display()))?;
        drop(file);

        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "failed to move {} into {}",
                temp_path.display(),
                path.display()
            )
        })
    })();

    if result.is_err() {
        // Preserve the original error if cleanup fails. A retry uses a new name.
        let _ = fs::remove_file(&temp_path);
    }
    result
}

pub fn write_atomically<P: AsRef<Path>>(path: P, bytes: &[u8]) -> anyhow::Result<()> {
    write_atomically_impl(path, bytes, None)
}

pub fn write_atomically_with_mode<P: AsRef<Path>>(
    path: P,
    bytes: &[u8],
    mode: u32,
) -> anyhow::Result<()> {
    write_atomically_impl(path, bytes, Some(mode))
}

pub fn remove_file_if_present(path: &str) -> Result<(), Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Barrier;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "walden-atomic-write-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn entries(&self) -> Vec<PathBuf> {
            fs::read_dir(&self.0)
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .collect()
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_failed_rename_does_not_prevent_the_next_atomic_write() {
        for mode in [None, Some(0o600)] {
            let scratch = ScratchDirectory::new("rename-retry");
            let destination = scratch.0.join("state.bin");
            // A file cannot replace a directory, so the temporary file is
            // created and synced but the final rename fails.
            fs::create_dir(&destination).unwrap();
            let kept = destination.join("kept");
            fs::write(&kept, b"original").unwrap();
            let write = |bytes: &[u8]| match mode {
                Some(mode) => write_atomically_with_mode(&destination, bytes, mode),
                None => write_atomically(&destination, bytes),
            };

            let failure = write(b"failed replacement").unwrap_err();
            assert!(
                failure.to_string().contains("failed to move"),
                "{failure:#}"
            );
            assert_eq!(fs::read(&kept).unwrap(), b"original");

            fs::remove_file(kept).unwrap();
            fs::remove_dir(&destination).unwrap();
            write(b"retried replacement").unwrap();
            assert_eq!(fs::read(&destination).unwrap(), b"retried replacement");
            assert_eq!(scratch.entries(), [destination]);
        }
    }

    #[test]
    fn a_failed_atomic_write_removes_its_temporary_file() {
        let scratch = ScratchDirectory::new("failure-cleanup");
        let destination = scratch.0.join("state.bin");
        fs::create_dir(&destination).unwrap();

        assert!(write_atomically(&destination, b"replacement").is_err());
        assert_eq!(scratch.entries(), [destination]);
    }

    #[test]
    fn a_stale_temporary_file_does_not_prevent_atomic_writes() {
        let scratch = ScratchDirectory::new("stale-file");
        let destination = scratch.0.join("state.bin");
        // An earlier version or an interrupted process may have left this
        // deterministic name behind. The writer must leave it alone.
        let stale = destination.with_extension(format!(".tmp_{}", std::process::id()));
        fs::write(&stale, b"stale data").unwrap();

        write_atomically(&destination, b"new data").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new data");
        assert_eq!(fs::read(&stale).unwrap(), b"stale data");
        assert_eq!(scratch.entries().len(), 2);
    }

    #[test]
    fn long_destination_names_do_not_lengthen_temporary_names() {
        let scratch = ScratchDirectory::new("long-name");
        let destination = scratch.0.join(format!("state.{}", "x".repeat(240)));

        write_atomically(&destination, b"new data").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"new data");
        assert_eq!(scratch.entries(), [destination]);
    }

    #[test]
    fn concurrent_atomic_writes_use_separate_temporary_files() {
        let scratch = ScratchDirectory::new("concurrent");
        let destination = scratch.0.join("state.bin");
        let payloads: Vec<_> = (0..8).map(|byte| vec![byte; 128 * 1024]).collect();
        let barrier = Barrier::new(payloads.len());

        std::thread::scope(|scope| {
            let writers: Vec<_> = payloads
                .iter()
                .map(|bytes| {
                    scope.spawn(|| {
                        barrier.wait();
                        write_atomically(&destination, bytes)
                    })
                })
                .collect();
            for writer in writers {
                writer.join().unwrap().unwrap();
            }
        });

        assert!(payloads.contains(&fs::read(&destination).unwrap()));
        assert_eq!(scratch.entries(), [destination]);
    }

    #[cfg(unix)]
    #[test]
    fn private_atomic_replacements_remain_private() {
        use std::os::unix::fs::PermissionsExt;

        let scratch = ScratchDirectory::new("private");
        let destination = scratch.0.join("state.bin");
        fs::write(&destination, b"original").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).unwrap();

        for bytes in [b"first replacement".as_slice(), b"second replacement"] {
            write_atomically_with_mode(&destination, bytes, 0o600).unwrap();
            assert_eq!(fs::read(&destination).unwrap(), bytes);
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                scratch.entries().as_slice(),
                std::slice::from_ref(&destination)
            );
        }
    }
}
