// Persisted daemon settings: root-owned binary block state for resume across restarts.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail, ensure};

use crate::common::{self, IS_LINUX, IS_MACOS};

pub const UNKNOWN_MACHINE_ID: &str = "walden-unknown-machine";
pub const SETTINGS_VERSION: i64 = 3;
pub const PREVIOUS_SETTINGS_VERSION: i64 = 2;
pub const LEGACY_SETTINGS_VERSION: i64 = 1;
const SETTINGS_NAME_PREFIX: &str = "waldend-settings-";

fn macos_serial_number() -> Option<String> {
    let output = Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()?;

    let stdout = String::from_utf8(output.stdout).ok()?;

    for line in stdout.lines() {
        if line.contains("IOPlatformSerialNumber") {
            let parts: Vec<&str> = line.split('"').collect();
            if parts.len() >= 4 {
                return Some(parts[3].to_string());
            }
        }
    }
    None
}

fn macos_host_uuid() -> Option<String> {
    let output = Command::new("sysctl")
        .args(["-n", "kern.hostuuid"])
        .output()
        .ok()?;

    let uuid = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if uuid.is_empty() { None } else { Some(uuid) }
}

fn linux_machine_id() -> Option<String> {
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(contents) = fs::read_to_string(path) {
            let id = contents.trim();
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}

// Locates the file; does not authenticate its contents.
pub fn machine_id() -> String {
    let id = if IS_LINUX {
        linux_machine_id()
    } else if IS_MACOS {
        macos_serial_number().or_else(macos_host_uuid)
    } else {
        None
    };
    id.unwrap_or_else(|| UNKNOWN_MACHINE_ID.to_string())
}

// Hashed hidden name avoids colliding with unrelated dotfiles.
pub fn persisted_state_file_name(machine_id: &str) -> String {
    let digest = Sha256::digest(format!("{SETTINGS_NAME_PREFIX}{machine_id}").as_bytes());
    format!(".{}", hex::encode(digest))
}

pub fn persisted_state_dir() -> &'static str {
    if IS_LINUX { "/etc" } else { "/usr/local/etc" }
}

// Toggles the filesystem immutable flag, so even root has to clear it
// deliberately before the file can be edited or removed.
fn set_immutable(path: &Path, immutable: bool) -> anyhow::Result<()> {
    let mut command = if IS_LINUX {
        let mut command = Command::new("chattr");
        command.arg(if immutable { "+i" } else { "-i" });
        command
    } else if IS_MACOS {
        let mut command = Command::new("chflags");
        command.arg(if immutable { "uchg" } else { "nouchg" });
        command
    } else {
        return Ok(());
    };

    let status = command
        .arg(path)
        .status()
        .with_context(|| format!("failed to run the immutable flag command: {path:?}"))?;

    if !status.success() {
        bail!("immutable flag command exited with {status}");
    }
    Ok(())
}

fn secure_settings_file_path() -> PathBuf {
    Path::new(persisted_state_dir()).join(persisted_state_file_name(&machine_id()))
}

pub fn secure_settings_file_exists() -> bool {
    secure_settings_file_path().exists()
}

fn decode_secure_settings(encoded: &[u8]) -> anyhow::Result<Settings> {
    if let Ok(mut settings) = postcard::from_bytes::<Settings>(encoded) {
        match settings.version {
            SETTINGS_VERSION => return Ok(settings),
            PREVIOUS_SETTINGS_VERSION => {
                settings.version = SETTINGS_VERSION;
                settings.operation_id = None;
                return Ok(settings);
            }
            LEGACY_SETTINGS_VERSION => {}
            version => bail!(
                "unsupported settings version {version}; expected {LEGACY_SETTINGS_VERSION}, {PREVIOUS_SETTINGS_VERSION}, or {SETTINGS_VERSION}"
            ),
        }
    }

    if let Ok(previous) = postcard::from_bytes::<SettingsV2>(encoded) {
        ensure!(
            previous.version == PREVIOUS_SETTINGS_VERSION,
            "unsupported settings version {}; expected {LEGACY_SETTINGS_VERSION}, {PREVIOUS_SETTINGS_VERSION}, or {SETTINGS_VERSION}",
            previous.version
        );
        return Ok(Settings::from_v2(previous));
    }

    if let Ok(legacy) = postcard::from_bytes::<SettingsV1>(encoded) {
        ensure!(
            legacy.version == LEGACY_SETTINGS_VERSION,
            "unsupported settings version {}; expected {LEGACY_SETTINGS_VERSION}, {PREVIOUS_SETTINGS_VERSION}, or {SETTINGS_VERSION}",
            legacy.version
        );
        return Ok(Settings::from_v1(legacy));
    }

    bail!("failed to decode settings file");
}

// Writes settings to a secure binary file and locks it down to root 0600
fn write_secure_settings_file(settings: &Settings) -> anyhow::Result<()> {
    let path = secure_settings_file_path();
    let encoded = postcard::to_allocvec(settings)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    common::write_atomically_with_mode(path, &encoded, 0o600)?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SettingsV1 {
    #[serde(default)]
    unlock_delay_secs: Option<u64>,

    #[serde(default)]
    block_end_at: Option<DateTime<Utc>>,

    #[serde(default)]
    blocklist: Option<Vec<String>>,

    block_is_running: bool,

    version: i64,

    last_update: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SettingsV2 {
    #[serde(default)]
    unlock_delay_secs: Option<u64>,
    #[serde(default)]
    block_end_at: Option<DateTime<Utc>>,
    #[serde(default)]
    blocklist: Option<Vec<String>>,
    block_is_running: bool,
    version: i64,
    last_update: DateTime<Utc>,
    #[serde(default)]
    rules_applied: bool,
    #[serde(default)]
    apply_started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    apply_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Settings {
    #[serde(default)]
    pub unlock_delay_secs: Option<u64>,

    #[serde(default)]
    pub block_end_at: Option<DateTime<Utc>>,

    #[serde(default)]
    pub blocklist: Option<Vec<String>>,

    pub block_is_running: bool,

    // Unrelated to user-config schema and catalog version.
    pub version: i64,

    pub last_update: DateTime<Utc>,

    // False until hosts and firewall rules have been applied at least once.
    // A v1 running block is treated as already applied so `walden stop` still
    // starts the recorded delay instead of cancelling a start that already
    // finished under the previous schema.
    #[serde(default)]
    pub rules_applied: bool,

    #[serde(default)]
    pub apply_started_at: Option<DateTime<Utc>>,

    #[serde(default)]
    pub apply_error: Option<String>,

    // Stable across acknowledgement loss and daemon restarts. Old persisted
    // blocks have no ID and can be observed/stopped, but cannot be mistaken
    // for a retry of a new start request.
    #[serde(default)]
    pub operation_id: Option<String>,
}

impl Settings {
    pub fn applying(operation_id: String, block_list: Vec<String>, unlock_delay_secs: u64) -> Self {
        let now = Utc::now();
        Self {
            operation_id: Some(operation_id),
            unlock_delay_secs: Some(unlock_delay_secs),
            block_end_at: None,
            blocklist: Some(block_list),
            block_is_running: true,
            version: SETTINGS_VERSION,
            last_update: now,
            rules_applied: false,
            apply_started_at: Some(now),
            apply_error: None,
        }
    }

    fn from_v1(previous: SettingsV1) -> Self {
        Self {
            operation_id: None,
            unlock_delay_secs: previous.unlock_delay_secs,
            block_end_at: previous.block_end_at,
            blocklist: previous.blocklist,
            block_is_running: previous.block_is_running,
            version: SETTINGS_VERSION,
            last_update: previous.last_update,
            rules_applied: previous.block_is_running,
            apply_started_at: previous.block_is_running.then_some(previous.last_update),
            apply_error: None,
        }
    }

    fn from_v2(previous: SettingsV2) -> Self {
        Self {
            operation_id: None,
            unlock_delay_secs: previous.unlock_delay_secs,
            block_end_at: previous.block_end_at,
            blocklist: previous.blocklist,
            block_is_running: previous.block_is_running,
            version: SETTINGS_VERSION,
            last_update: previous.last_update,
            rules_applied: previous.rules_applied,
            apply_started_at: previous.apply_started_at,
            apply_error: previous.apply_error,
        }
    }

    pub fn phase(&self) -> crate::protocol::BlockPhase {
        use crate::protocol::BlockPhase;

        if !self.block_is_running {
            return BlockPhase::Inactive;
        }
        if self.block_end_at.is_some() {
            return BlockPhase::Ending;
        }
        if !self.rules_applied {
            if self.apply_error.is_some() {
                return BlockPhase::ApplyFailed;
            }
            return BlockPhase::Applying;
        }
        BlockPhase::Active
    }

    pub fn website_count(&self) -> Option<usize> {
        self.blocklist.as_ref().map(Vec::len)
    }
}

// Ok(None) = no file; Ok(Some) = valid; Err = corrupt (lifecycle locks).
pub fn load_secure_settings_file() -> anyhow::Result<Option<Settings>> {
    let path = secure_settings_file_path();
    let encoded = match fs::read(&path) {
        Ok(encoded) => encoded,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", path.display()));
        }
    };

    decode_secure_settings(&encoded).map(Some)
}

// Immutable flag must be cleared before atomic rename; re-apply is best-effort.
pub fn save_secure_settings_file(settings: &Settings) -> anyhow::Result<()> {
    let path = secure_settings_file_path();

    let mut settings = settings.clone();
    settings.last_update = Utc::now();

    if path.exists()
        && let Err(err) = set_immutable(&path, false)
    {
        eprintln!("Warning: failed to clear the immutable flag: {err}");
    }

    write_secure_settings_file(&settings)?;
    // State is already committed; immutable-flag failure is not a write failure.
    if let Err(err) = set_immutable(&path, true) {
        eprintln!("Warning: failed to set the immutable flag: {err}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secure_settings_default() -> Settings {
        Settings {
            operation_id: Some("test-operation".to_string()),
            unlock_delay_secs: None,
            block_end_at: None,
            blocklist: None,
            block_is_running: true,
            version: SETTINGS_VERSION,
            last_update: Utc::now(),
            rules_applied: true,
            apply_started_at: None,
            apply_error: None,
        }
    }

    fn encoded_settings(version: i64) -> Vec<u8> {
        let mut settings = secure_settings_default();
        settings.version = version;
        postcard::to_allocvec(&settings).unwrap()
    }

    fn encoded_v1_settings(running: bool) -> Vec<u8> {
        let previous = SettingsV1 {
            unlock_delay_secs: Some(60),
            block_end_at: None,
            blocklist: Some(vec!["example.com".to_string()]),
            block_is_running: running,
            version: LEGACY_SETTINGS_VERSION,
            last_update: Utc::now(),
        };
        postcard::to_allocvec(&previous).unwrap()
    }

    fn encoded_v2_settings(running: bool) -> Vec<u8> {
        let previous = SettingsV2 {
            unlock_delay_secs: Some(60),
            block_end_at: None,
            blocklist: Some(vec!["example.com".to_string()]),
            block_is_running: running,
            version: PREVIOUS_SETTINGS_VERSION,
            last_update: Utc::now(),
            rules_applied: running,
            apply_started_at: running.then(Utc::now),
            apply_error: None,
        };
        postcard::to_allocvec(&previous).unwrap()
    }

    #[test]
    fn accepts_the_current_settings_version() {
        let settings = decode_secure_settings(&encoded_settings(SETTINGS_VERSION)).unwrap();

        assert_eq!(settings.version, SETTINGS_VERSION);
        assert!(settings.block_is_running);
        assert!(settings.rules_applied);
    }

    #[test]
    fn migrates_a_running_v1_block_as_already_applied() {
        let settings = decode_secure_settings(&encoded_v1_settings(true)).unwrap();

        assert_eq!(settings.version, SETTINGS_VERSION);
        assert!(settings.block_is_running);
        assert!(settings.rules_applied);
        assert_eq!(settings.operation_id, None);
        assert_eq!(settings.phase(), crate::protocol::BlockPhase::Active);
        assert_eq!(
            settings.blocklist.as_deref(),
            Some(vec!["example.com".to_string()].as_slice())
        );
    }

    #[test]
    fn migrates_v2_without_inventing_an_operation_id() {
        let settings = decode_secure_settings(&encoded_v2_settings(true)).unwrap();

        assert_eq!(settings.version, SETTINGS_VERSION);
        assert!(settings.block_is_running);
        assert!(settings.rules_applied);
        assert_eq!(settings.operation_id, None);
    }

    #[test]
    fn migrates_an_idle_v1_file_as_inactive() {
        let settings = decode_secure_settings(&encoded_v1_settings(false)).unwrap();

        assert!(!settings.block_is_running);
        assert!(!settings.rules_applied);
        assert_eq!(settings.phase(), crate::protocol::BlockPhase::Inactive);
    }

    #[test]
    fn rejects_unsupported_settings_versions() {
        let err = decode_secure_settings(&encoded_settings(SETTINGS_VERSION + 1)).unwrap_err();

        assert!(err.to_string().contains("unsupported settings version"));
    }

    #[test]
    fn rejects_corrupt_settings_bytes() {
        assert!(decode_secure_settings(b"not postcard settings").is_err());
    }

    #[test]
    fn persisted_state_file_name_is_a_hidden_hex_digest() {
        let name = persisted_state_file_name("test-machine");
        assert!(name.starts_with('.'));
        assert_eq!(name.len(), 65);
        assert!(
            name[1..]
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        );
        assert_ne!(
            persisted_state_file_name("test-machine"),
            persisted_state_file_name("other-machine")
        );
    }
}
