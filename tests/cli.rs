use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

fn walden_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_walden"));
    command.env(
        walden::catalog::CATALOG_DIR_ENV,
        walden::catalog::vendored_dir(),
    );
    command
}

fn walden_with_installed_catalog(cache: &Path) -> Command {
    let mut command = walden_command();
    command
        .env_remove(walden::catalog::CATALOG_DIR_ENV)
        .env(walden::catalog::CATALOG_CACHE_DIR_ENV, cache)
        .env(
            walden::catalog::BUNDLED_CATALOG_DIR_ENV,
            walden::catalog::vendored_dir(),
        );
    command
}

fn walden(args: &[&str]) -> Output {
    walden_command()
        .args(args)
        .output()
        .expect("failed to run walden")
}

fn temp_config_path(test_name: &str) -> std::path::PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();

    std::env::temp_dir()
        .join(format!(
            "walden-cli-{test_name}-{}-{unique}",
            std::process::id()
        ))
        .join("config.toml")
}

#[test]
fn setup_creates_and_updates_a_loadable_configuration() {
    let path = temp_config_path("setup");
    let path_arg = path.to_string_lossy();

    let created = walden(&[
        "--config",
        &path_arg,
        "setup",
        "--categories",
        "social-media",
        "--unlock-delay",
        "1 hour",
    ]);
    assert!(
        created.status.success(),
        "setup failed: {}",
        String::from_utf8_lossy(&created.stderr)
    );
    let stdout = String::from_utf8_lossy(&created.stdout);
    assert!(stdout.contains("Created configuration"));
    assert!(stdout.contains(path_arg.as_ref()));
    assert!(
        stdout.contains(&format!("Add extra websites by editing {path_arg}")),
        "{stdout}"
    );
    assert!(stdout.contains("walden start"));

    let contents = fs::read_to_string(&path).expect("setup did not create the configuration");
    let config = walden::user_config::UserConfig::parse(&contents)
        .expect("setup created an invalid configuration");
    assert_eq!(config.categories, ["social-media"]);
    assert_eq!(config.unlock_delay, "1 hour");
    assert!(config.websites.is_empty());
    config
        .resolve(&walden::catalog::vendored())
        .expect("setup created a configuration that cannot be used by start");

    let mut with_sites = config;
    with_sites.websites = vec!["example.com".to_string()];
    walden::user_config::save(Some(&path), &with_sites)
        .expect("failed to add a custom website to the configuration");

    let updated = walden(&[
        "--config",
        &path_arg,
        "setup",
        "--categories",
        "gambling",
        "--unlock-delay",
        "2 hours",
    ]);
    assert!(
        updated.status.success(),
        "setup rerun failed: {}",
        String::from_utf8_lossy(&updated.stderr)
    );
    let stdout = String::from_utf8_lossy(&updated.stdout);
    assert!(stdout.contains("Updated configuration"), "{stdout}");
    assert!(stdout.contains(path_arg.as_ref()), "{stdout}");
    assert!(
        stdout.contains(&format!("Add extra websites by editing {path_arg}")),
        "{stdout}"
    );

    let contents = fs::read_to_string(&path).expect("setup did not update the configuration");
    let config = walden::user_config::UserConfig::parse(&contents)
        .expect("setup updated to an invalid configuration");
    assert_eq!(config.categories, ["gambling"]);
    assert_eq!(config.unlock_delay, "2 hours");
    assert_eq!(config.websites, ["example.com"]);

    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn setup_refuses_to_overwrite_an_invalid_configuration() {
    let path = temp_config_path("setup-invalid");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "not a configuration\n").unwrap();
    let path_arg = path.to_string_lossy();

    let output = walden(&[
        "--config",
        &path_arg,
        "setup",
        "--categories",
        "social-media",
        "--unlock-delay",
        "1 hour",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("fix it manually"), "{stderr}");
    assert_eq!(fs::read_to_string(&path).unwrap(), "not a configuration\n");

    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn setup_without_flags_requires_a_terminal() {
    let path = temp_config_path("setup-tty");
    let path_arg = path.to_string_lossy();

    let output = walden(&["--config", &path_arg, "setup"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--categories") && stderr.contains("--unlock-delay"),
        "{stderr}"
    );
    assert!(!path.exists());
}

#[test]
fn categories_lists_the_installed_catalog() {
    let catalog = walden::catalog::vendored();
    let output = walden(&["categories"]);
    assert!(
        output.status.success(),
        "categories failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("Category catalog {}", catalog.version())),
        "{stdout}"
    );
    assert!(
        stdout.contains(&catalog.directory().display().to_string()),
        "{stdout}"
    );
    for category in catalog.categories() {
        assert!(stdout.contains(&category.id), "{stdout}");
        assert!(stdout.contains(&category.name), "{stdout}");
    }
}

#[test]
fn an_empty_download_cache_uses_the_bundle_with_one_repair_notice() {
    let cache = unique_dir("catalog-empty-cache");
    fs::create_dir_all(&cache).unwrap();

    let output = walden_with_installed_catalog(&cache)
        .arg("categories")
        .output()
        .expect("failed to run walden categories");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("Notice:").count(), 1, "{stderr}");
    assert!(stderr.contains("Using bundled catalog"), "{stderr}");
    assert!(stderr.contains("incomplete downloaded update"), "{stderr}");
    assert!(stderr.contains("sudo walden catalog update"), "{stderr}");
    assert!(!stderr.contains("manifest.json"), "{stderr}");
    assert!(!stderr.contains("os error"), "{stderr}");

    fs::remove_dir_all(cache).unwrap();
}

#[test]
fn an_absent_download_cache_uses_the_bundle_silently() {
    let cache = unique_dir("catalog-absent-cache");
    assert!(!cache.exists());

    let output = walden_with_installed_catalog(&cache)
        .arg("categories")
        .output()
        .expect("failed to run walden categories");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn an_invalid_download_cache_uses_the_bundle_without_raw_parser_errors() {
    let cache = unique_dir("catalog-invalid-cache");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("manifest.json"), "not json\n").unwrap();

    let output = walden_with_installed_catalog(&cache)
        .arg("categories")
        .output()
        .expect("failed to run walden categories");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(stderr.matches("Notice:").count(), 1, "{stderr}");
    assert!(stderr.contains("invalid downloaded update"), "{stderr}");
    assert!(!stderr.contains("expected ident"), "{stderr}");
    assert!(!stderr.contains("manifest.json"), "{stderr}");

    fs::remove_dir_all(cache).unwrap();
}

#[test]
fn start_validates_the_configuration_and_delay_before_elevation() {
    let path = temp_config_path("start");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "schema_version = 1\nunlock_delay = \"5 seconds\"\ncategories = [\"missing\"]\nwebsites = []\n",
    )
    .unwrap();
    let path_arg = path.to_string_lossy();

    let invalid_config = walden(&["--config", &path_arg, "start"]);
    assert!(!invalid_config.status.success());
    assert!(String::from_utf8_lossy(&invalid_config.stderr).contains("unknown category"));

    fs::write(
        &path,
        "schema_version = 1\nunlock_delay = \"not-a-duration\"\ncategories = []\nwebsites = [\"example.com\"]\n",
    )
    .unwrap();
    let invalid_delay = walden(&["--config", &path_arg, "start"]);
    assert!(!invalid_delay.status.success());
    assert!(String::from_utf8_lossy(&invalid_delay.stderr).contains("invalid unlock delay"));

    fs::write(
        &path,
        "schema_version = 1\nunlock_delay = \"5 seconds\"\ncategories = []\nwebsites = [\"example.com\"]\n",
    )
    .unwrap();
    let invalid_override = walden(&[
        "--config",
        &path_arg,
        "start",
        "--unlock-delay",
        "not-a-duration",
    ]);
    assert!(!invalid_override.status.success());
    assert!(String::from_utf8_lossy(&invalid_override.stderr).contains("invalid unlock delay"));

    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn start_uses_unlock_delay_from_the_configuration() {
    let path = temp_config_path("start-from-config");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "schema_version = 1\nunlock_delay = \"5 seconds\"\ncategories = []\nwebsites = [\"example.com\"]\n",
    )
    .unwrap();
    let path_arg = path.to_string_lossy();

    let output = walden(&["--config", &path_arg, "start"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        !stderr.contains("--unlock-delay"),
        "start should not require --unlock-delay when the configuration has one: {stderr}"
    );
    assert!(!stderr.contains("invalid unlock delay"), "{stderr}");

    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn start_rejects_a_configuration_without_unlock_delay() {
    let path = temp_config_path("start-missing-delay");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "schema_version = 1\ncategories = []\nwebsites = [\"example.com\"]\n",
    )
    .unwrap();
    let path_arg = path.to_string_lossy();

    let output = walden(&["--config", &path_arg, "start"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unlock_delay"));

    fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

fn file_url(path: &Path) -> String {
    format!("file://{}", path.display())
}

fn unique_dir(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "walden-cli-{test_name}-{}-{unique}",
        std::process::id()
    ))
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let destination = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).unwrap();
        }
    }
}

#[test]
fn catalog_update_installs_a_verified_snapshot_from_a_local_source() {
    let catalog = walden::catalog::vendored();
    let cache = unique_dir("catalog-update");

    let output = walden_command()
        .env_remove(walden::catalog::CATALOG_DIR_ENV)
        .env(walden::catalog::CATALOG_CACHE_DIR_ENV, &cache)
        .args([
            "catalog",
            "update",
            "--from",
            &file_url(&walden::catalog::vendored_dir()),
        ])
        .output()
        .expect("failed to run walden catalog update");

    assert!(
        output.status.success(),
        "catalog update failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("Updated category catalog {}", catalog.version())),
        "{stdout}"
    );
    assert!(stdout.contains("An active block is unchanged"), "{stdout}");
    for category in catalog.categories() {
        assert!(stdout.contains(&category.id), "{stdout}");
    }

    let listed = walden_command()
        .env_remove(walden::catalog::CATALOG_DIR_ENV)
        .env(walden::catalog::CATALOG_CACHE_DIR_ENV, &cache)
        .args(["categories"])
        .output()
        .expect("failed to run walden categories");
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed_out = String::from_utf8_lossy(&listed.stdout);
    assert!(listed_out.contains(catalog.version()), "{listed_out}");
    assert!(
        listed_out.contains(&cache.display().to_string()),
        "{listed_out}"
    );

    let _ = walden::catalog::set_tree_modes(&cache, 0o755, 0o644);
    let _ = fs::remove_dir_all(&cache);
}

#[test]
fn catalog_update_leaves_the_cache_alone_when_verification_fails() {
    let cache = unique_dir("catalog-update-keep");
    let installed = walden_command()
        .env_remove(walden::catalog::CATALOG_DIR_ENV)
        .env(walden::catalog::CATALOG_CACHE_DIR_ENV, &cache)
        .args([
            "catalog",
            "update",
            "--from",
            &file_url(&walden::catalog::vendored_dir()),
        ])
        .output()
        .expect("failed to seed the catalog cache");
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let previous = fs::read_to_string(cache.join("manifest.json")).unwrap();

    let tampered = unique_dir("catalog-update-tampered");
    copy_tree(&walden::catalog::vendored_dir(), &tampered);
    fs::write(tampered.join("categories/social-media.txt"), "evil.test\n").unwrap();

    let failed = walden_command()
        .env_remove(walden::catalog::CATALOG_DIR_ENV)
        .env(walden::catalog::CATALOG_CACHE_DIR_ENV, &cache)
        .args(["catalog", "update", "--from", &file_url(&tampered)])
        .output()
        .expect("failed to run walden catalog update");
    assert!(!failed.status.success());
    assert_eq!(
        fs::read_to_string(cache.join("manifest.json")).unwrap(),
        previous
    );

    let _ = walden::catalog::set_tree_modes(&cache, 0o755, 0o644);
    let _ = fs::remove_dir_all(&cache);
    let _ = fs::remove_dir_all(&tampered);
}

#[test]
fn help_lists_the_documented_commands() {
    let output = walden(&["--help"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "version",
        "start",
        "stop",
        "status",
        "setup",
        "categories",
        "catalog",
    ] {
        assert!(stdout.contains(command), "{stdout}");
    }
    assert!(stdout.contains("Blocks distracting websites"));
}

#[test]
fn verbose_version_identifies_the_cli_build() {
    let output = walden(&["version", "--verbose"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let build = walden::build_info::BuildInfo::current();
    assert!(stdout.contains(&format!("Walden CLI {}", build.version)));
    assert!(stdout.contains(&build.build_id));
    assert!(stdout.contains(&format!("Protocol: {}", walden::protocol::PROTOCOL_VERSION)));
    assert!(stdout.contains(&build.target));
}
