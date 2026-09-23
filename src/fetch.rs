// Catalog snapshot downloads via curl (HTTPS in production, file:// in tests).
// Walden's normal operation needs no network; curl keeps TLS validation maintained
// by the platform rather than bundling a second HTTP stack.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail, ensure};

const HTTPS_PREFIX: &str = "https://";
const FILE_PREFIX: &str = "file://";

// curl --proto wants `=https`, not a bare scheme name.
fn protocol_allowlist(url: &str) -> anyhow::Result<&'static str> {
    if url.starts_with(HTTPS_PREFIX) {
        Ok("=https")
    } else if url.starts_with(FILE_PREFIX) {
        Ok("=file")
    } else {
        bail!(
            "unsupported catalog URL {url:?}; it must begin with {HTTPS_PREFIX:?} or {FILE_PREFIX:?}"
        )
    }
}

/// Joins a catalog base URL and a path relative to its manifest.
pub fn join(base: &str, relative: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), relative)
}

/// Downloads one URL to `destination`, replacing whatever is there.
pub fn download(url: &str, destination: &Path) -> anyhow::Result<()> {
    let protocol = protocol_allowlist(url)?;

    let status = Command::new("curl")
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            protocol,
            "--proto-redir",
            protocol,
            "--max-redirs",
            "3",
            "--retry",
            "2",
            "--output",
        ])
        .arg(destination)
        .arg(url)
        .status()
        .context("failed to run curl, which Walden uses to download the category catalog")?;

    ensure!(status.success(), "failed to download {url} (curl {status})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_and_file_urls_are_accepted() {
        assert_eq!(
            protocol_allowlist("https://example.test/v1").unwrap(),
            "=https"
        );
        assert_eq!(protocol_allowlist("file:///tmp/v1").unwrap(), "=file");

        for rejected in [
            "http://example.test/v1",
            "ftp://example.test/v1",
            "example.test/v1",
            "--output",
        ] {
            assert!(
                protocol_allowlist(rejected).is_err(),
                "{rejected} was accepted"
            );
        }
    }

    #[test]
    fn joining_does_not_double_the_separator() {
        assert_eq!(
            join("file:///v1", "manifest.json"),
            "file:///v1/manifest.json"
        );
        assert_eq!(
            join("file:///v1/", "categories/social-media.txt"),
            "file:///v1/categories/social-media.txt"
        );
    }
}
