use std::fs::{self, OpenOptions};
use std::io::{Error, ErrorKind, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::Context;

pub const IS_LINUX: bool = cfg!(target_os = "linux");
pub const IS_MACOS: bool = cfg!(target_os = "macos");

fn write_atomically_impl<P: AsRef<Path>>(
    path: P,
    bytes: &[u8],
    mode: Option<u32>,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let temp_path = path.with_extension(format!(".tmp_{}", std::process::id()));

    {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        #[cfg(unix)]
        if let Some(mode) = mode {
            options.mode(mode);
        }

        let mut file = options
            .open(&temp_path)
            .with_context(|| format!("failed to open {}", temp_path.display()))?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to move {} into {}",
            temp_path.display(),
            path.display()
        )
    })
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
