// User-owned configuration: category IDs, extra sites, unlock delay. The daemon
// gets a flattened snapshot when a block starts.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use anyhow::{Context, bail, ensure};
use serde::{Deserialize, Serialize};

use crate::catalog::Catalog;
use crate::{common, entry};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// The single category `walden setup` selects for a new configuration.
pub const DEFAULT_CATEGORY: &str = "social-media";

/// Unlock delay written by `walden setup` when the user accepts the default.
pub const DEFAULT_UNLOCK_DELAY: &str = "1 hour";

/// User-editable configuration: category IDs, extra websites, and the delay
/// served after `walden stop` before the block is lifted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    pub schema_version: u32,

    pub unlock_delay: String,

    #[serde(default)]
    pub categories: Vec<String>,

    #[serde(default)]
    pub websites: Vec<String>,
}

/// Resolved block list produced from a [`UserConfig`] and a category catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfig {
    pub catalog_version: String,
    pub category_ids: Vec<String>,
    pub block_list: Vec<String>,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            unlock_delay: DEFAULT_UNLOCK_DELAY.to_string(),
            categories: vec![DEFAULT_CATEGORY.to_string()],
            websites: Vec::new(),
        }
    }
}

impl UserConfig {
    pub fn parse(contents: &str) -> anyhow::Result<Self> {
        let config: Self = toml::from_str(contents).context("invalid configuration TOML")?;
        ensure!(
            config.schema_version == CONFIG_SCHEMA_VERSION,
            "unsupported configuration schema version {}; this Walden version supports version {}",
            config.schema_version,
            CONFIG_SCHEMA_VERSION
        );
        parse_unlock_delay_secs(&config.unlock_delay)?;
        Ok(config)
    }

    /// Validates category IDs against `catalog`: non-empty, unique, and known.
    pub fn validate_categories(&self, catalog: &Catalog) -> anyhow::Result<()> {
        let mut seen = BTreeSet::new();
        for id in &self.categories {
            ensure!(!id.trim().is_empty(), "category id is empty");
            ensure!(
                seen.insert(id.as_str()),
                "category {id:?} is selected more than once"
            );
            catalog.require(id)?;
        }
        Ok(())
    }

    /// Expands categories against `catalog` and merges personal websites.
    pub fn resolve(&self, catalog: &Catalog) -> anyhow::Result<EffectiveConfig> {
        self.validate_categories(catalog)?;

        let mut selected_categories = BTreeSet::new();
        let mut block_list = BTreeSet::new();

        for id in &self.categories {
            selected_categories.insert(id.as_str());
            block_list.extend(catalog.domains(id)?.iter().cloned());
        }

        for website in &self.websites {
            let normalized = entry::normalize_website(website)
                .with_context(|| format!("invalid website {website:?}"))?;
            block_list.insert(normalized);
        }

        ensure!(
            !block_list.is_empty(),
            "configuration selects no categories or websites"
        );

        Ok(EffectiveConfig {
            catalog_version: catalog.version().to_string(),
            category_ids: selected_categories
                .into_iter()
                .map(str::to_string)
                .collect(),
            block_list: block_list.into_iter().collect(),
        })
    }
}

/// Parses a positive duration such as `"1 hour"` or `"3 days"` into seconds.
pub fn parse_unlock_delay_secs(input: &str) -> anyhow::Result<u64> {
    let input = input.trim();
    let mut parts = input.split_whitespace();
    let count = parts
        .next()
        .context("invalid unlock delay")?
        .parse::<u64>()
        .context("invalid unlock delay")?;
    let unit = parts.next().context("invalid unlock delay")?;
    ensure!(
        parts.next().is_none(),
        "invalid unlock delay: expected `<count> <unit>`, got {input:?}"
    );
    ensure!(
        count > 0,
        "unlock delay must be a positive duration (got {input:?})"
    );

    let secs_per = unit_secs(unit)
        .with_context(|| format!("invalid unlock delay: unknown unit in {input:?}"))?;
    count
        .checked_mul(secs_per)
        .context("unlock delay is too large")
}

fn unit_secs(unit: &str) -> Option<u64> {
    let base = unit
        .strip_suffix('s')
        .or_else(|| unit.strip_suffix('S'))
        .unwrap_or(unit);

    match () {
        _ if base.eq_ignore_ascii_case("second") => Some(1),
        _ if base.eq_ignore_ascii_case("minute") => Some(60),
        _ if base.eq_ignore_ascii_case("hour") => Some(3_600),
        _ if base.eq_ignore_ascii_case("day") => Some(86_400),
        _ if base.eq_ignore_ascii_case("week") => Some(604_800),
        _ if base.eq_ignore_ascii_case("month") => Some(2_592_000), // 30 days
        _ if base.eq_ignore_ascii_case("year") => Some(31_536_000), // 365 days
        _ => None,
    }
}

pub fn default_path() -> anyhow::Result<PathBuf> {
    if let Some(path) = env::var_os("WALDEN_CONFIG_DIR") {
        return Ok(PathBuf::from(path).join(CONFIG_FILE_NAME));
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var_os("HOME").context("HOME is not set; pass --config explicitly")?;
        Ok(PathBuf::from(home)
            .join("Library/Application Support/Walden")
            .join(CONFIG_FILE_NAME))
    }

    #[cfg(not(target_os = "macos"))]
    {
        if let Some(path) = env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(path).join("walden").join(CONFIG_FILE_NAME));
        }

        let home = env::var_os("HOME").context("HOME is not set; pass --config explicitly")?;
        Ok(PathBuf::from(home)
            .join(".config/walden")
            .join(CONFIG_FILE_NAME))
    }
}

pub fn path(override_path: Option<&Path>) -> anyhow::Result<PathBuf> {
    override_path
        .map(Path::to_path_buf)
        .map_or_else(default_path, Ok)
}

/// Absolute path for printing, so a relative `--config` can still be opened.
pub fn absolute_display_path(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn load(override_path: Option<&Path>) -> anyhow::Result<(PathBuf, UserConfig)> {
    let (path, config) = load_optional(override_path)?;
    let Some(config) = config else {
        bail!(
            "failed to read {}; create it with `walden setup` or pass --config",
            absolute_display_path(&path).display()
        );
    };
    Ok((path, config))
}

/// Loads a configuration if the file exists.
///
/// A missing file is `Ok((path, None))`. A file that exists but cannot be
/// parsed is an error, so setup will not overwrite a broken file by accident.
pub fn load_optional(
    override_path: Option<&Path>,
) -> anyhow::Result<(PathBuf, Option<UserConfig>)> {
    let path = path(override_path)?;
    match fs::read_to_string(&path) {
        Ok(contents) => {
            let config = UserConfig::parse(&contents).with_context(|| {
                format!(
                    "failed to load {}; fix it manually or delete it and rerun `walden setup`",
                    absolute_display_path(&path).display()
                )
            })?;
            Ok((path, Some(config)))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok((path, None)),
        Err(err) => Err(err)
            .with_context(|| format!("failed to read {}", absolute_display_path(&path).display())),
    }
}

/// Replaces categories and unlock delay from a setup pass, keeping any
/// hand-edited websites from the existing file.
pub fn merge_setup(existing: Option<&UserConfig>, mut next: UserConfig) -> UserConfig {
    next.schema_version = CONFIG_SCHEMA_VERSION;
    next.websites = existing
        .map(|config| config.websites.clone())
        .unwrap_or_default();
    next
}

pub fn save(override_path: Option<&Path>, config: &UserConfig) -> anyhow::Result<PathBuf> {
    let path = path(override_path)?;

    let parent = path
        .parent()
        .context("configuration path has no parent directory")?;
    let parent_existed = parent.exists();
    fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;

    #[cfg(unix)]
    if !parent_existed {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure {}", parent.display()))?;
    }

    let contents =
        toml::to_string_pretty(config).context("failed to serialize the configuration")?;
    common::write_atomically_with_mode(&path, contents.as_bytes(), 0o600)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_config(categories: &[&str], websites: &[&str]) -> UserConfig {
        UserConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            unlock_delay: DEFAULT_UNLOCK_DELAY.to_string(),
            categories: categories.iter().map(|id| (*id).to_string()).collect(),
            websites: websites.iter().map(|site| (*site).to_string()).collect(),
        }
    }

    #[test]
    fn parses_and_resolves_a_configuration_deterministically() {
        let catalog = catalog::vendored();
        let config = UserConfig::parse(
            r#"
                schema_version = 1
                unlock_delay = "1 hour"
                categories = ["gambling", "social-media"]
                websites = ["HTTPS://Example.com/path", "facebook.com"]
            "#,
        )
        .unwrap();

        let effective = config.resolve(&catalog).unwrap();
        assert_eq!(effective.catalog_version, catalog.version());
        assert_eq!(effective.category_ids, ["gambling", "social-media"]);
        assert!(
            effective
                .block_list
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        // Already in social-media, so listing it personally must not repeat it.
        assert_eq!(
            effective
                .block_list
                .iter()
                .filter(|entry| entry.as_str() == "facebook.com")
                .count(),
            1
        );
        assert!(effective.block_list.contains(&"example.com".to_string()));
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        assert!(UserConfig::parse("schema_version = 1\nwebistes = []").is_err());
        assert!(UserConfig::parse("schema_version = 2").is_err());
    }

    #[test]
    fn rejects_a_missing_or_invalid_unlock_delay() {
        let missing =
            UserConfig::parse("schema_version = 1\ncategories = [\"social-media\"]").unwrap_err();
        assert!(
            format!("{missing:#}").contains("unlock_delay"),
            "{missing:#}"
        );

        let invalid = UserConfig::parse(
            "schema_version = 1\nunlock_delay = \"not-a-duration\"\ncategories = [\"social-media\"]\n",
        )
        .unwrap_err();
        assert!(
            format!("{invalid:#}").contains("invalid unlock delay"),
            "{invalid:#}"
        );

        assert!(
            UserConfig::parse(
                "schema_version = 1\nunlock_delay = \"0 seconds\"\ncategories = [\"social-media\"]\n"
            )
            .is_err()
        );
    }

    #[test]
    fn unlock_delay_must_be_a_positive_duration() {
        assert_eq!(parse_unlock_delay_secs("5 seconds").unwrap(), 5);
        assert_eq!(parse_unlock_delay_secs("1 second").unwrap(), 1);
        assert_eq!(parse_unlock_delay_secs("2 minutes").unwrap(), 120);
        assert_eq!(parse_unlock_delay_secs("1 minute").unwrap(), 60);
        assert_eq!(parse_unlock_delay_secs("1 hour").unwrap(), 3_600);
        assert_eq!(parse_unlock_delay_secs("3 hours").unwrap(), 10_800);
        assert_eq!(parse_unlock_delay_secs("1 day").unwrap(), 86_400);
        assert_eq!(parse_unlock_delay_secs("2 days").unwrap(), 172_800);
        assert_eq!(parse_unlock_delay_secs("1 week").unwrap(), 604_800);
        assert_eq!(parse_unlock_delay_secs("2 weeks").unwrap(), 1_209_600);
        assert_eq!(parse_unlock_delay_secs("1 month").unwrap(), 2_592_000);
        assert_eq!(parse_unlock_delay_secs("2 months").unwrap(), 5_184_000);
        assert_eq!(parse_unlock_delay_secs("1 year").unwrap(), 31_536_000);
        assert_eq!(parse_unlock_delay_secs("  1 Hour  ").unwrap(), 3_600);
        assert!(parse_unlock_delay_secs("0 seconds").is_err());
        assert!(parse_unlock_delay_secs("not-a-duration").is_err());
        assert!(parse_unlock_delay_secs("5").is_err());
        assert!(parse_unlock_delay_secs("5 seconds extra").is_err());
        assert!(parse_unlock_delay_secs("-5 seconds").is_err());
        assert!(parse_unlock_delay_secs("1.5 hours").is_err());
        assert!(parse_unlock_delay_secs("").is_err());
        assert!(parse_unlock_delay_secs(&format!("{} years", u64::MAX)).is_err());
    }

    #[test]
    fn rejects_unknown_and_duplicate_categories() {
        let catalog = catalog::vendored();

        let unknown = test_config(&["missing"], &[]);
        let err = unknown.resolve(&catalog).unwrap_err().to_string();
        assert!(err.contains("unknown category"), "{err}");
        assert!(err.contains("social-media"), "{err}");

        let duplicate = test_config(&["gambling", "gambling"], &[]);
        assert!(duplicate.resolve(&catalog).is_err());
    }

    #[test]
    fn requires_at_least_one_effective_entry() {
        let empty = test_config(&[], &[]);
        assert!(empty.resolve(&catalog::vendored()).is_err());
    }

    #[test]
    fn the_default_configuration_resolves_against_the_published_catalog() {
        let catalog = catalog::vendored();
        let effective = UserConfig::default().resolve(&catalog).unwrap();

        assert_eq!(effective.category_ids, [DEFAULT_CATEGORY]);
        assert_eq!(UserConfig::default().unlock_delay, DEFAULT_UNLOCK_DELAY);
        assert!(!effective.block_list.is_empty());
    }

    #[test]
    fn a_materialized_snapshot_does_not_follow_later_config_changes() {
        let catalog = catalog::vendored();
        let mut config = UserConfig::default();
        let snapshot = config.resolve(&catalog).unwrap();

        config.websites.push("later.example".to_string());
        let next_snapshot = config.resolve(&catalog).unwrap();

        assert!(!snapshot.block_list.contains(&"later.example".to_string()));
        assert!(
            next_snapshot
                .block_list
                .contains(&"later.example".to_string())
        );
    }

    fn unique_config_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir()
            .join(format!(
                "walden-config-test-{test_name}-{}-{unique}",
                std::process::id()
            ))
            .join(CONFIG_FILE_NAME)
    }

    #[test]
    fn merge_setup_replaces_categories_and_delay_and_keeps_websites() {
        let existing = test_config(&["social-media"], &["example.com"]);
        let next = UserConfig {
            schema_version: CONFIG_SCHEMA_VERSION,
            unlock_delay: "2 hours".to_string(),
            categories: vec!["gambling".to_string()],
            websites: Vec::new(),
        };

        let merged = merge_setup(Some(&existing), next);
        assert_eq!(merged.categories, ["gambling"]);
        assert_eq!(merged.unlock_delay, "2 hours");
        assert_eq!(merged.websites, ["example.com"]);

        let created = merge_setup(
            None,
            UserConfig {
                schema_version: CONFIG_SCHEMA_VERSION,
                unlock_delay: DEFAULT_UNLOCK_DELAY.to_string(),
                categories: vec![DEFAULT_CATEGORY.to_string()],
                websites: vec!["should-not-keep.example".to_string()],
            },
        );
        assert!(created.websites.is_empty());
    }

    #[test]
    fn load_optional_returns_none_when_missing_and_errors_on_invalid() {
        let path = unique_config_path("optional");
        let (resolved, missing) = load_optional(Some(&path)).unwrap();
        assert_eq!(resolved, path);
        assert!(missing.is_none());

        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "not toml").unwrap();
        let err = load_optional(Some(&path)).unwrap_err();
        assert!(format!("{err:#}").contains("fix it manually"), "{err:#}");
        assert!(
            format!("{err:#}").contains(&absolute_display_path(&path).display().to_string()),
            "{err:#}"
        );

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn saves_a_loadable_configuration_and_updates_it_in_place() {
        let path = unique_config_path("save");

        assert_eq!(save(Some(&path), &UserConfig::default()).unwrap(), path);
        let (_, loaded) = load(Some(&path)).unwrap();
        assert_eq!(loaded, UserConfig::default());

        let updated = test_config(&["gambling"], &["example.com"]);
        assert_eq!(save(Some(&path), &updated).unwrap(), path);
        let (_, loaded) = load(Some(&path)).unwrap();
        assert_eq!(loaded, updated);

        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn absolute_display_path_makes_a_relative_path_absolute() {
        let shown = absolute_display_path(Path::new("config.toml"));
        assert!(shown.is_absolute(), "{}", shown.display());
        assert_eq!(shown.file_name().unwrap(), "config.toml");
    }
}
