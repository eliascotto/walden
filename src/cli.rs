use std::collections::BTreeSet;
use std::env;
use std::io::IsTerminal;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use chrono::{Local, Utc};
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, MultiSelect, theme::ColorfulTheme};

use walden::{build_info, catalog, ipc, protocol, service, user_config};

static OPERATION_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub struct ForwardExit(pub i32);

impl std::fmt::Display for ForwardExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "privileged command exited with status {}", self.0)
    }
}
impl std::error::Error for ForwardExit {}

#[derive(Debug)]
struct StartRejected(String);
impl std::fmt::Display for StartRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for StartRejected {}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Use a configuration file at this path
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    // Internal handoff: the unprivileged process has already selected and
    // verified this exact snapshot. Pin it across sudo so selection and any
    // fallback notice happen only once.
    #[arg(long, global = true, value_name = "PATH", hide = true)]
    catalog_snapshot: Option<PathBuf>,

    #[command(subcommand)]
    command: CommandSet,
}

#[derive(Subcommand, Debug)]
enum CommandSet {
    /// Show the CLI and daemon build identities
    Version {
        /// Include source, protocol, target, and daemon details
        #[arg(long)]
        verbose: bool,
    },
    /// Start a block using the user configuration
    Start {
        /// Delay served after `walden stop` before the block is lifted
        ///
        /// Defaults to `unlock_delay` from the configuration file.
        #[arg(long, value_name = "DURATION")]
        unlock_delay: Option<String>,
        /// Follow progress until rules are active; Ctrl+C only stops waiting
        #[arg(long)]
        wait: bool,
    },
    /// Request that the active block end after its fixed delay
    Stop,
    /// Check the status of the system
    Status {
        /// Internal diagnostics: show changes every second until Ctrl+C
        #[arg(long, hide = true)]
        watch: bool,
        /// Include operation, timing, DNS, and daemon log details
        #[arg(long)]
        verbose: bool,
    },
    /// Create or update the configuration
    Setup {
        /// Category IDs to block (repeatable). Use with `--unlock-delay` to skip prompts.
        #[arg(long, value_name = "ID")]
        categories: Vec<String>,
        /// Delay served after `walden stop` before the block is lifted
        #[arg(long, value_name = "DURATION")]
        unlock_delay: Option<String>,
    },
    /// List the website categories in the installed catalog
    Categories,
    /// Manage the website category catalog
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
}

#[derive(Subcommand, Debug)]
enum CatalogCommand {
    /// Download and install a newer walden-list snapshot
    Update {
        /// Catalog distribution URL (a directory containing manifest.json)
        #[arg(long, value_name = "URL")]
        from: Option<String>,
    },
}

pub fn run() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = args.config.as_deref();
    let catalog_snapshot = args.catalog_snapshot.as_deref();

    match args.command {
        CommandSet::Version { verbose } => version(verbose),
        CommandSet::Start { unlock_delay, wait } => {
            start(config, catalog_snapshot, unlock_delay.as_deref(), wait)
        }
        CommandSet::Stop => stop(),
        CommandSet::Status { watch, verbose } => status(watch, verbose),
        CommandSet::Setup {
            categories,
            unlock_delay,
        } => setup(config, catalog_snapshot, categories, unlock_delay),
        CommandSet::Categories => categories(catalog_snapshot),
        CommandSet::Catalog { command } => match command {
            CatalogCommand::Update { from } => catalog_update(from.as_deref()),
        },
    }
}

fn version(verbose: bool) -> anyhow::Result<()> {
    let cli = build_info::BuildInfo::current();
    if !verbose {
        println!("walden {} ({})", cli.version, cli.short_build_id());
        return Ok(());
    }

    println!("Walden CLI {}", cli.version);
    print_field("Build ID", &cli.build_id);
    print_field("Protocol", &protocol::PROTOCOL_VERSION.to_string());
    print_field("Target", &cli.target);
    print_field("Profile", &cli.profile);
    print_field(
        "Source epoch",
        cli.source_date_epoch.as_deref().unwrap_or("not set"),
    );
    print_field("Binary marker", build_info::binary_marker());
    print_field("Profile marker", build_info::profile_marker());

    match ipc::connect_client() {
        Ok(mut stream) => match protocol::client_handshake(&mut stream) {
            Ok(daemon) => {
                println!();
                println!("Walden daemon {}", daemon.version);
                print_field("Build ID", &daemon.build_id);
                print_field("Target", &daemon.target);
                print_field("Profile", &daemon.profile);
                print_field(
                    "Source epoch",
                    daemon.source_date_epoch.as_deref().unwrap_or("not set"),
                );
            }
            Err(err) => {
                println!();
                print_field("Daemon", &format!("incompatible or unavailable ({err:#})"));
            }
        },
        Err(_) => {
            println!();
            print_field("Daemon", "not running");
        }
    }
    Ok(())
}

fn load_catalog(explicit_snapshot: Option<&Path>) -> anyhow::Result<catalog::Catalog> {
    let selection = catalog::select(explicit_snapshot)?;
    if let Some(notice) = selection.fallback_notice() {
        eprintln!("Notice: {notice}");
    }
    Ok(selection.into_catalog())
}

fn start(
    config_override: Option<&Path>,
    catalog_snapshot: Option<&Path>,
    unlock_delay: Option<&str>,
    wait: bool,
) -> anyhow::Result<()> {
    let (path, config) = user_config::load(config_override)?;
    let catalog = load_catalog(catalog_snapshot)?;
    let (effective, unlock_delay_secs) = prepare_start(&config, &catalog, unlock_delay)?;

    let website_count = effective.block_list.len();

    // Whether the daemon is installed can be read without privileges, so a
    // machine that cannot run a block says so before asking for a password and
    // long before anything on it changes.
    service::verify_ready_to_start()?;

    if !is_root() {
        let mut args = privileged_start_args(&path, &catalog, unlock_delay)?;
        if wait {
            args.push("--wait".into());
        }
        return rerun_with_sudo(&args);
    }

    let operation_id = start_block(effective.block_list, unlock_delay_secs)?;
    println!("{}", applying_rules_message(website_count));
    if wait {
        println!("Waiting for active rules. Ctrl+C stops waiting; the daemon continues.");
        monitor_status(
            service::inspect,
            |output| println!("{output}"),
            || std::thread::sleep(Duration::from_secs(1)),
            MonitorMode::WaitForActive(operation_id),
            false,
        )?;
    }
    Ok(())
}

// Keep configuration validation separate from service inspection and elevation.
// Tests can verify the actual block inputs without starting an installed daemon.
fn prepare_start(
    config: &user_config::UserConfig,
    catalog: &catalog::Catalog,
    unlock_delay: Option<&str>,
) -> anyhow::Result<(user_config::EffectiveConfig, u64)> {
    let effective = config.resolve(catalog)?;
    let delay = unlock_delay.unwrap_or(&config.unlock_delay);
    let unlock_delay_secs = user_config::parse_unlock_delay_secs(delay)?;
    Ok((effective, unlock_delay_secs))
}

fn applying_rules_message(website_count: usize) -> String {
    format!(
        "Start accepted for {website_count} websites.\nRun `walden status` to check whether rules are active."
    )
}

// Asking for the block to end is not privileged: the daemon owns the delay,
// and another request cannot shorten or cancel it.
fn stop() -> anyhow::Result<()> {
    let state = service::manager_state()?;
    if matches!(
        state,
        service::ServiceState::NotInstalled | service::ServiceState::Inactive
    ) {
        println!("Daemon is {}, nothing to stop", state.describe());
        return Ok(());
    }
    if let service::ServiceState::Unhealthy(reason) = state {
        bail!("the Walden daemon service is not usable: {reason}");
    }

    let mut stream = connect_daemon()?;
    match request_stop(&mut stream).context("failed to ask the daemon to stop")? {
        protocol::StopOutcome::AlreadyInactive => {
            println!("Daemon is running, but the block is not active, nothing to stop");
        }
        protocol::StopOutcome::CleanupPending => {
            println!(
                "The previous block is being cleaned up. Run `walden status` for progress and recovery details."
            );
        }
        protocol::StopOutcome::ApplyCancelled => {
            println!(
                "Start cancelled before the block was locked in. Rules may remain until cleanup finishes; run `walden status`."
            );
        }
        protocol::StopOutcome::Ending { block_end_at } => {
            let delay = format_duration(
                seconds_until(block_end_at, Utc::now()),
                DurationStyle::Compact,
            );
            println!(
                "Stop requested. Unlock delay remaining: {delay}. \
                 Run `walden status` to monitor the block."
            );
        }
        protocol::StopOutcome::AlreadyEnding { block_end_at } => {
            println!(
                "Stop was already requested; the block is ending at {}.",
                block_end_at
                    .with_timezone(&Local)
                    .format("%H:%M:%S %Y/%m/%d")
            );
        }
    }
    Ok(())
}

// Status is deliberately readable without a password prompt.
fn status(watch: bool, verbose: bool) -> anyhow::Result<()> {
    if watch {
        println!("Watching status; Ctrl+C stops watching.");
    }
    monitor_status(
        service::inspect,
        |output| println!("{output}"),
        || std::thread::sleep(Duration::from_secs(1)),
        if watch {
            MonitorMode::Watch
        } else {
            MonitorMode::Once
        },
        verbose,
    )
}

#[derive(Clone, Eq, PartialEq)]
enum MonitorMode {
    Once,
    Watch,
    WaitForActive(String),
}

fn monitor_status(
    mut inspect: impl FnMut() -> anyhow::Result<service::ServiceInspection>,
    mut emit: impl FnMut(&str),
    mut pause: impl FnMut(),
    mode: MonitorMode,
    verbose: bool,
) -> anyhow::Result<()> {
    let mut previous = None;
    loop {
        let inspection = inspect()?;
        let output = render_status(&inspection, verbose);
        if previous.as_ref() != Some(&output) {
            if previous.is_some() {
                emit("");
            }
            emit(&output);
            previous = Some(output);
        }
        if mode == MonitorMode::Once {
            return Ok(());
        }
        if let MonitorMode::WaitForActive(expected) = &mode {
            ensure!(
                inspection
                    .status
                    .as_ref()
                    .and_then(|status| status.operation_id.as_ref())
                    == Some(expected),
                "the accepted block is no longer the current operation; check `walden status --verbose`"
            );
            match inspection.status.as_ref().map(|status| status.block_phase) {
                Some(protocol::BlockPhase::Active) => return Ok(()),
                Some(protocol::BlockPhase::Applying) => {}
                Some(protocol::BlockPhase::ApplyFailed) => bail!(
                    "the daemon accepted the start, but applying rules failed. Check `walden status --verbose`; `walden stop` cancels before activation"
                ),
                _ => bail!(
                    "the accepted block did not become active; check `walden status --verbose` for its current state"
                ),
            }
        }
        pause();
    }
}

fn render_status(inspection: &service::ServiceInspection, verbose: bool) -> String {
    // Reported separately from the block, because a machine without Walden
    // installed and one sitting idle with it installed are both unblocked, and
    // only one of them is something the user has to act on.
    let daemon = if !verbose && matches!(inspection.state, service::ServiceState::Unhealthy(_)) {
        "unhealthy".into()
    } else {
        inspection.state.describe()
    };
    let mut lines = vec![format_field("Daemon", &daemon)];

    if !inspection.state.is_running() {
        let block = match &inspection.state {
            service::ServiceState::NotInstalled | service::ServiceState::Inactive => "not active",
            service::ServiceState::Starting => "unavailable (daemon has not answered yet)",
            service::ServiceState::Unhealthy(_) => "unavailable (daemon service is unhealthy)",
            service::ServiceState::Running => unreachable!(),
        };
        lines.push(format_field("Block", block));
    } else if let Some(status) = &inspection.status {
        lines.extend(
            describe_block(status, verbose)
                .into_iter()
                .map(|(label, value)| format_field(label, &value)),
        );
        if verbose {
            if let Some(operation) = &status.operation_id {
                lines.push(format_field("Operation", operation));
            }
            if let Some(started) = status.apply_started_at {
                lines.push(format_field("Apply started", &started.to_rfc3339()));
            }
            if let Some(progress) = &status.dns_progress {
                lines.push(format_field(
                    "DNS",
                    &format!(
                        "{}/{} hostnames checked; {} missing or incomplete; {} unique addresses",
                        progress.completed,
                        progress.total,
                        progress.failed_lookups,
                        progress.resolved_addresses
                    ),
                ));
            }
        }
    } else {
        lines.push(format_field(
            "Block",
            "unavailable (daemon returned no status)",
        ));
    }

    if verbose {
        let log = if cfg!(target_os = "macos") {
            "log show --last 1h --predicate 'process == \"waldend\"'"
        } else {
            "journalctl -u waldend.service --since '1 hour ago'"
        };
        lines.push(format_field("Daemon logs", log));
    }
    lines.join("\n")
}

fn setup(
    config_override: Option<&Path>,
    catalog_snapshot: Option<&Path>,
    categories: Vec<String>,
    unlock_delay: Option<String>,
) -> anyhow::Result<()> {
    let (path, existing) = user_config::load_optional(config_override)?;
    let is_update = existing.is_some();

    let is_terminal = std::io::stdin().is_terminal();
    let config = match (categories.is_empty(), unlock_delay.is_some()) {
        (false, true) => {
            let catalog = load_catalog(catalog_snapshot)?;
            setup_config_from_selection(
                categories,
                unlock_delay.unwrap(),
                existing.as_ref(),
                &catalog,
            )?
        }
        (true, false) if is_terminal => {
            let catalog = load_catalog(catalog_snapshot)?;
            setup_config_interactively(&path, existing.as_ref(), &catalog)?
        }
        (true, false) => {
            bail!("setup needs a terminal, or pass `--categories` and `--unlock-delay`");
        }
        (true, true) => {
            bail!("`--categories` is required when `--unlock-delay` is used");
        }
        (false, false) => {
            bail!("`--unlock-delay` is required when `--categories` is used");
        }
    };

    let path = user_config::save(config_override, &config)?;
    let shown = user_config::absolute_display_path(&path);
    if is_update {
        println!("Updated configuration at {}", shown.display());
    } else {
        println!("Created configuration at {}", shown.display());
    }
    println!("Add extra websites by editing {}", shown.display());
    if active_block_is_running() {
        println!("An active block is unchanged; the next block will use this configuration.");
    } else {
        println!("Run `walden start` to begin a block.");
    }
    Ok(())
}

fn setup_config_from_selection(
    categories: Vec<String>,
    unlock_delay: String,
    existing: Option<&user_config::UserConfig>,
    catalog: &catalog::Catalog,
) -> anyhow::Result<user_config::UserConfig> {
    ensure!(!categories.is_empty(), "select at least one category");
    user_config::parse_unlock_delay_secs(&unlock_delay)?;

    let config = user_config::merge_setup(
        existing,
        user_config::UserConfig {
            schema_version: user_config::CONFIG_SCHEMA_VERSION,
            unlock_delay,
            categories,
            websites: Vec::new(),
        },
    );
    config.validate_categories(catalog)?;
    Ok(config)
}

fn setup_config_interactively(
    path: &Path,
    existing: Option<&user_config::UserConfig>,
    catalog: &catalog::Catalog,
) -> anyhow::Result<user_config::UserConfig> {
    let theme = ColorfulTheme::default();

    println!("Walden setup");
    println!();
    if existing.is_some() {
        println!("This updates the configuration used by the next `walden start`.");
        println!("Custom websites already in the file are kept.");
    } else {
        println!("This writes a configuration used by `walden start`.");
    }
    println!("A block cannot be shortened once it is active.");
    println!();
    println!(
        "Category catalog {} from {}",
        catalog.version(),
        catalog.directory().display()
    );
    println!();

    let items: Vec<String> = catalog
        .categories()
        .iter()
        .map(|category| format_category_line(category, true))
        .collect();
    let existing_ids: BTreeSet<&str> = existing
        .map(|config| config.categories.iter().map(String::as_str).collect())
        .unwrap_or_default();
    let defaults: Vec<bool> = catalog
        .categories()
        .iter()
        .map(|category| {
            if existing.is_some() {
                existing_ids.contains(category.id.as_str())
            } else {
                category.id == user_config::DEFAULT_CATEGORY || category.recommended
            }
        })
        .collect();

    let selected = loop {
        let chosen = MultiSelect::with_theme(&theme)
            .with_prompt("Select categories to block")
            .items(&items)
            .defaults(&defaults)
            .interact()
            .context("failed to read category selection")?;
        if !chosen.is_empty() {
            break chosen;
        }
        println!("Select at least one category.");
    };

    let categories: Vec<String> = selected
        .into_iter()
        .map(|index| catalog.categories()[index].id.clone())
        .collect();

    let default_delay = existing
        .map(|config| config.unlock_delay.clone())
        .unwrap_or_else(|| user_config::DEFAULT_UNLOCK_DELAY.to_string());
    let unlock_delay = Input::with_theme(&theme)
        .with_prompt("Unlock delay after `walden stop`")
        .default(default_delay)
        .validate_with(|input: &String| -> Result<(), String> {
            user_config::parse_unlock_delay_secs(input)
                .map(|_| ())
                .map_err(|err| err.to_string())
        })
        .interact_text()
        .context("failed to read unlock delay")?;

    let shown = user_config::absolute_display_path(path);
    let websites = existing
        .map(|config| config.websites.as_slice())
        .unwrap_or(&[]);
    let custom_sites = if websites.is_empty() {
        format!("(none; add later by editing {})", shown.display())
    } else {
        format!("{} (kept; edit {})", websites.join(", "), shown.display())
    };

    println!();
    if existing.is_some() {
        println!("Update this configuration?");
    } else {
        println!("Write this configuration?");
    }
    println!("  Path:          {}", shown.display());
    println!("  Categories:    {}", categories.join(", "));
    println!("  Unlock delay:  {unlock_delay}");
    println!("  Custom sites:  {custom_sites}");
    if active_block_is_running() {
        println!();
        println!("An active block is unchanged; the next block will use this configuration.");
    }

    let proceed = Confirm::with_theme(&theme)
        .with_prompt("Proceed")
        .default(true)
        .interact()
        .context("failed to read confirmation")?;
    ensure!(proceed, "setup cancelled");

    setup_config_from_selection(categories, unlock_delay, existing, catalog)
}

fn active_block_is_running() -> bool {
    service::inspect().is_ok_and(|inspection| {
        inspection.state.is_running()
            && inspection
                .status
                .is_some_and(|status| status.block_is_running)
    })
}

fn category_detail(category: &catalog::Category) -> String {
    let mut detail = vec![format!("{} domains", category.domains)];
    if category.recommended {
        detail.push("recommended".to_string());
    }
    if let Some(confidence) = &category.confidence {
        detail.push(confidence.clone());
    }
    detail.join(", ")
}

fn format_category_line(category: &catalog::Category, include_warning: bool) -> String {
    let mut line = format!(
        "{}: {} ({})",
        category.id,
        category.name,
        category_detail(category)
    );
    if include_warning && let Some(warning) = &category.warning {
        line.push_str(&format!(" - warning: {warning}"));
    }
    line
}

fn categories(catalog_snapshot: Option<&Path>) -> anyhow::Result<()> {
    let catalog = load_catalog(catalog_snapshot)?;
    println!("Category catalog {}", catalog.version());
    println!("From {}", catalog.directory().display());
    println!();

    for category in catalog.categories() {
        println!("- {}", format_category_line(category, false));
        if !category.description.is_empty() {
            println!("    {}", category.description);
        }
        if let Some(warning) = &category.warning {
            println!("    Warning: {warning}");
        }
    }

    if !catalog.sources().is_empty() {
        println!();
        println!("Upstream sources:");
        for source in catalog.sources() {
            println!("    {}", format_source(source));
        }
    }

    Ok(())
}

fn catalog_update(from: Option<&str>) -> anyhow::Result<()> {
    if env::var_os(catalog::CATALOG_CACHE_DIR_ENV).is_none() && !is_root() {
        return match from {
            Some(source) => rerun_with_sudo(&[
                "catalog".to_string(),
                "update".to_string(),
                "--from".to_string(),
                source.to_string(),
            ]),
            None => rerun_with_sudo(&["catalog".to_string(), "update".to_string()]),
        };
    }

    let source = from.unwrap_or(catalog::DEFAULT_SOURCE_URL);
    println!("Downloading the category catalog from {source}");
    let catalog = catalog::update(source)?;

    println!("Updated category catalog {}", catalog.version());
    println!("Installed at {}", catalog.directory().display());
    println!();
    print_catalog_summary(&catalog);
    println!();
    println!("An active block is unchanged; the next block will use this catalog.");
    Ok(())
}

fn print_catalog_summary(catalog: &catalog::Catalog) {
    println!("Categories:");
    for category in catalog.categories() {
        println!("  {:<16} {:>8} domains", category.id, category.domains);
    }

    if catalog.sources().is_empty() {
        return;
    }

    println!();
    println!("Sources:");
    for source in catalog.sources() {
        println!("  {}", format_source(source));
    }
}

fn format_source(source: &catalog::Source) -> String {
    let commit = source.commit.as_deref().unwrap_or("unknown");
    let short = if commit.len() >= 8 {
        &commit[..8]
    } else {
        commit
    };

    match (&source.repository, &source.license) {
        (Some(repository), Some(license)) => {
            format!("{} {} {} ({license})", source.id, short, repository)
        }
        (Some(repository), None) => format!("{} {} {repository}", source.id, short),
        (None, Some(license)) => format!("{} {} ({license})", source.id, short),
        (None, None) => format!("{} {short}", source.id),
    }
}

fn privileged_start_args(
    config_path: &Path,
    catalog: &catalog::Catalog,
    unlock_delay: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let config_path = config_path
        .to_str()
        .context("config path is not valid UTF-8")?;
    let catalog_path = catalog
        .directory()
        .to_str()
        .context("catalog path is not valid UTF-8")?;
    let mut args = vec![
        "--config".to_string(),
        config_path.to_string(),
        "--catalog-snapshot".to_string(),
        catalog_path.to_string(),
        "start".to_string(),
    ];
    if let Some(delay) = unlock_delay {
        args.push("--unlock-delay".to_string());
        args.push(delay.to_string());
    }
    Ok(args)
}

fn rerun_with_sudo(args: &[String]) -> anyhow::Result<()> {
    let executable = env::current_exe().context("failed to find the walden executable")?;
    let mut command = Command::new("sudo");
    command.arg(executable);
    for arg in args {
        command.arg(arg);
    }

    let status = command.status().context("failed to execute sudo")?;
    forward_child_status(status)
}

fn forward_child_status(status: ExitStatus) -> anyhow::Result<()> {
    if status.success() {
        return Ok(());
    }
    Err(ForwardExit(
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)),
    )
    .into())
}

fn is_root() -> bool {
    // SAFETY: geteuid reads process state and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn start_block(block_list: Vec<String>, unlock_delay_secs: u64) -> anyhow::Result<String> {
    ensure!(is_root(), "starting a block requires root privileges");

    // Returns only once the installed daemon is up and answering, so the block
    // is either accepted by a daemon that will hold it or refused outright.
    service::start_daemon()?;

    let operation_id = new_operation_id();
    let message = protocol::ClientMessage::Start {
        operation_id: operation_id.clone(),
        block_list: block_list.clone(),
        unlock_delay_secs,
    };
    let mut stream = connect_daemon()?;
    match request_start(&mut stream, &message, &operation_id) {
        Ok(()) => Ok(operation_id),
        Err(err) => {
            // The daemon persists a start before it begins slow work.  A lost
            // acknowledgement is therefore recoverable only when the
            // responsive daemon reports the same durable operation ID as
            // active or applying. Retrying this Start message is idempotent.
            let persisted_matching_start = request_status().is_ok_and(|status| {
                status.block_is_running && status.operation_id.as_deref() == Some(&operation_id)
            });
            if persisted_matching_start {
                eprintln!(
                    "walden: the daemon did not confirm the request before the IPC deadline, but the matching block is persisted; continuing"
                );
                Ok(operation_id)
            } else {
                if let Some(rejection) = err.downcast_ref::<StartRejected>() {
                    bail!("Start refused: {rejection}. No new block was started.");
                }
                bail!(
                    "Start was not confirmed; run `walden status` to check whether it was accepted: {}",
                    daemon_request_detail(&err)
                )
            }
        }
    }
}

fn request_start(
    stream: &mut std::os::unix::net::UnixStream,
    message: &protocol::ClientMessage,
    expected_operation_id: &str,
) -> anyhow::Result<()> {
    ipc::send_json(stream, message).context("failed to send the request to the daemon")?;

    match ipc::receive_json(stream).context("failed to read the daemon response")? {
        protocol::CommandResponse::StartAccepted { operation_id }
            if operation_id == expected_operation_id =>
        {
            Ok(())
        }
        protocol::CommandResponse::StartAccepted { operation_id } => {
            bail!("the daemon acknowledged operation {operation_id}, not {expected_operation_id}")
        }
        protocol::CommandResponse::StopCompleted { .. } => {
            bail!("the daemon returned a stop response to a start request")
        }
        protocol::CommandResponse::Rejected { message } => Err(StartRejected(message).into()),
    }
}

fn request_stop(
    stream: &mut std::os::unix::net::UnixStream,
) -> anyhow::Result<protocol::StopOutcome> {
    ipc::send_json(stream, &protocol::ClientMessage::Stop)
        .context("failed to send the request to the daemon")?;

    match ipc::receive_json(stream).context("failed to read the daemon response")? {
        protocol::CommandResponse::StopCompleted { outcome } => Ok(outcome),
        protocol::CommandResponse::StartAccepted { .. } => {
            bail!("the daemon returned a start response to a stop request")
        }
        protocol::CommandResponse::Rejected { message } => {
            bail!("the daemon rejected the request: {message}")
        }
    }
}

fn request_status() -> anyhow::Result<protocol::StatusResponse> {
    let mut stream = connect_daemon()?;
    ipc::send_json(&mut stream, &protocol::ClientMessage::Status)?;
    Ok(ipc::receive_json(&mut stream)?)
}

fn connect_daemon() -> anyhow::Result<std::os::unix::net::UnixStream> {
    let mut stream = ipc::connect_client().context("failed to connect to the daemon")?;
    protocol::client_handshake(&mut stream)?;
    Ok(stream)
}

fn new_operation_id() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let counter = OPERATION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(
        "{:x}-{:x}-{:x}",
        elapsed.as_nanos(),
        std::process::id(),
        counter
    )
}

// macOS reports an expired Unix-socket read/write timeout as EAGAIN (error
// 35).  That wording suggests system-wide resource exhaustion even though the
// useful diagnosis is simply that the daemon did not answer before its IPC
// deadline.
fn daemon_request_detail(err: &anyhow::Error) -> String {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<ipc::IpcError>())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("{err:#}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DurationStyle {
    /// Exact units matching stored config values (e.g. `"1 hour"`, `"3 days"`).
    Exact,
    /// Compact countdown for live status (e.g. `"2h 15m"`, `"45s"`).
    Compact,
}

fn format_duration(secs: u64, style: DurationStyle) -> String {
    match style {
        DurationStyle::Exact => {
            const UNITS: [(u64, &str); 4] = [
                (24 * 60 * 60, "day"),
                (60 * 60, "hour"),
                (60, "minute"),
                (1, "second"),
            ];

            for (size, name) in UNITS {
                if secs >= size && secs.is_multiple_of(size) {
                    let count = secs / size;
                    return if count == 1 {
                        format!("1 {name}")
                    } else {
                        format!("{count} {name}s")
                    };
                }
            }

            format!("{secs} seconds")
        }
        DurationStyle::Compact => {
            let (days, hours) = (secs / 86_400, (secs % 86_400) / 3_600);
            let (minutes, seconds) = ((secs % 3_600) / 60, secs % 60);

            if days > 0 {
                format!("{days}d {hours}h")
            } else if hours > 0 {
                format!("{hours}h {minutes}m")
            } else if minutes > 0 {
                format!("{minutes}m {seconds}s")
            } else {
                format!("{seconds}s")
            }
        }
    }
}

fn seconds_until(deadline: chrono::DateTime<Utc>, now: chrono::DateTime<Utc>) -> u64 {
    let remaining = deadline - now;
    if remaining <= chrono::TimeDelta::zero() {
        return 0;
    }
    let seconds = remaining.num_seconds();
    seconds as u64 + u64::from(remaining > chrono::TimeDelta::seconds(seconds))
}

fn print_field(label: &str, value: &str) {
    println!("{}", format_field(label, value));
}

fn format_field(label: &str, value: &str) -> String {
    format!("{label}: {value}")
}

fn describe_block(status: &protocol::StatusResponse, verbose: bool) -> Vec<(&'static str, String)> {
    use protocol::BlockPhase;
    let block = match status.block_phase {
        BlockPhase::Inactive => "not active".into(),
        BlockPhase::Applying => format!("applying — {}", apply_progress_summary(status, verbose)),
        BlockPhase::ApplyFailed => {
            let reason = status
                .last_apply_failure
                .as_ref()
                .map(|failure| match failure.stage {
                    protocol::ApplyStage::PreparingFirewall
                    | protocol::ApplyStage::InstallingFirewall => "firewall setup",
                    protocol::ApplyStage::WritingHosts => "hosts setup",
                    protocol::ApplyStage::Resolving => "DNS setup",
                    protocol::ApplyStage::SavingState => "saving state",
                });
            reason.map_or_else(
                || "start failed".into(),
                |reason| format!("start failed ({reason})"),
            )
        }
        BlockPhase::CleaningUp => "cleaning up".into(),
        BlockPhase::CleanupFailed => "cleanup failed".into(),
        BlockPhase::Locked => "unavailable (saved state is unreadable)".into(),
        BlockPhase::Ending => status.block_end_at.map_or_else(
            || "ending".into(),
            |deadline| {
                format!(
                    "ending in {}",
                    format_duration(seconds_until(deadline, Utc::now()), DurationStyle::Compact)
                )
            },
        ),
        BlockPhase::Active if status.last_apply_failure.is_some() => {
            "active (rule repair failed)".into()
        }
        BlockPhase::Active => "active".into(),
    };
    let mut lines = vec![("Block", block)];
    let needs_details = matches!(
        status.block_phase,
        BlockPhase::ApplyFailed | BlockPhase::CleanupFailed | BlockPhase::Locked
    ) || (status.block_phase == BlockPhase::Active
        && status.last_apply_failure.is_some());
    if needs_details && !verbose {
        lines.push(("Details", "walden status --verbose".into()));
    }
    if status.block_phase == BlockPhase::Active {
        lines.push((
            "Unblock delay",
            status.unlock_delay_secs.map_or_else(
                || "not set".into(),
                |secs| format_duration(secs, DurationStyle::Exact),
            ),
        ));
    }
    if !verbose {
        return lines;
    }
    if let Some(count) = status.website_count {
        lines.push(("Websites", count.to_string()));
    }
    if status.apply_in_progress
        && let Some(progress) = &status.apply_progress
    {
        lines.push(("Current stage", apply_stage_name(progress.stage).into()));
        if progress.stage == protocol::ApplyStage::InstallingFirewall {
            lines.push((
                "Firewall addresses",
                progress.resolved_addresses.to_string(),
            ));
        }
    }
    if let Some(failure) = &status.last_apply_failure {
        lines.push(("Last failure", failure.message.clone()));
        lines.push(("Failed during", apply_stage_name(failure.stage).into()));
        lines.push(("Failure at", failure.failed_at.to_rfc3339()));
        lines.push(("Attempts", status.apply_attempts.to_string()));
        if failure.requires_action {
            lines.push(("Recovery", if status.block_phase == BlockPhase::Active { "configuration needs attention; existing block settings and unlock delay are preserved".into() } else { "configuration needs attention; fix the reported problem, then cancel the pending start with `walden stop` and start again".into() }));
        } else if let Some(retry) = status.apply_retry_at {
            lines.push((
                "Retry",
                format!(
                    "automatically in {}",
                    format_duration(seconds_until(retry, Utc::now()), DurationStyle::Compact)
                ),
            ));
        } else if status.apply_in_progress {
            lines.push(("Retry", "in progress".into()));
        }
    } else if let Some(error) = &status.apply_error {
        // The legacy saved-state format has only an error string. Never guess
        // its stage from a different attempt's current progress.
        lines.push(("Previous failure", error.clone()));
    }
    if let Some(cleanup) = &status.cleanup {
        lines.push(("Stage", cleanup_stage_name(cleanup.stage).into()));
        lines.push((
            "Cleanup elapsed",
            format_duration(
                (Utc::now() - cleanup.started_at).num_seconds().max(0) as u64,
                DurationStyle::Compact,
            ),
        ));
        lines.push(("Attempts", cleanup.attempts.to_string()));
        if let Some(error) = &cleanup.error {
            lines.push(("Error", error.clone()));
        }
        if !cleanup.remaining.is_empty() {
            lines.push(("Remaining", cleanup.remaining.join(", ")));
        }
        if let Some(retry) = cleanup.next_retry_at {
            lines.push((
                "Retry",
                format!(
                    "automatically in {}",
                    format_duration(seconds_until(retry, Utc::now()), DurationStyle::Compact)
                ),
            ));
        }
        lines.push((
            "New blocks",
            "unavailable until cleanup completes; rules may still be present".into(),
        ));
    }
    if let Some(error) = &status.state_error {
        lines.push(("Error", error.clone()));
    }
    if status.block_phase == BlockPhase::Ending
        && let Some(deadline) = status.block_end_at
    {
        lines.push((
            "Ends at",
            deadline
                .with_timezone(&Local)
                .format("%H:%M:%S %Y/%m/%d")
                .to_string(),
        ));
    }
    lines
}

fn cleanup_stage_name(stage: protocol::CleanupStage) -> &'static str {
    match stage {
        protocol::CleanupStage::WaitingForApply => "waiting for cancelled apply work to finish",
        protocol::CleanupStage::RemovingRules => "removing hosts and firewall rules",
        protocol::CleanupStage::VerifyingRules => "verifying hosts and firewall cleanup",
        protocol::CleanupStage::RetiringDaemon => "disabling daemon autostart",
        protocol::CleanupStage::SavingState => "saving completed cleanup",
    }
}

fn apply_stage_name(stage: protocol::ApplyStage) -> &'static str {
    match stage {
        protocol::ApplyStage::WritingHosts => "writing hosts",
        protocol::ApplyStage::PreparingFirewall => "preparing firewall rules",
        protocol::ApplyStage::Resolving => "resolving hostnames",
        protocol::ApplyStage::InstallingFirewall => "installing firewall rules",
        protocol::ApplyStage::SavingState => "saving activation state",
    }
}

fn apply_progress_summary(status: &protocol::StatusResponse, verbose: bool) -> String {
    let Some(progress) = &status.apply_progress else {
        return if verbose {
            format!("{} websites", status.website_count.unwrap_or(0))
        } else {
            "starting".into()
        };
    };

    match progress.stage {
        protocol::ApplyStage::WritingHosts if verbose => {
            format!("writing hosts for {} websites", progress.total)
        }
        protocol::ApplyStage::Resolving => {
            let percent = progress
                .completed
                .saturating_mul(100)
                .checked_div(progress.total)
                .unwrap_or(100);
            format!("resolving hostnames {percent}%")
        }
        protocol::ApplyStage::InstallingFirewall if verbose => {
            let unresolved = if progress.failed_lookups == 0 {
                String::new()
            } else {
                format!("; {} hostnames unresolved", progress.failed_lookups)
            };
            format!(
                "installing firewall rules for {} addresses{unresolved}",
                progress.resolved_addresses
            )
        }
        stage => apply_stage_name(stage).into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

    #[test]
    fn start_uses_unlock_delay_from_the_configuration() {
        let config = user_config::UserConfig::parse(
            "schema_version = 1\nunlock_delay = \"5 seconds\"\ncategories = []\nwebsites = [\"example.com\"]\n",
        )
        .unwrap();
        let args = Args::try_parse_from(["walden", "start"]).unwrap();
        let CommandSet::Start { unlock_delay, .. } = args.command else {
            panic!("expected a start command");
        };

        let (effective, delay_secs) =
            prepare_start(&config, &catalog::vendored(), unlock_delay.as_deref()).unwrap();
        assert_eq!(delay_secs, 5);
        assert_eq!(effective.block_list, ["example.com"]);
    }

    #[test]
    fn start_can_override_the_configured_unlock_delay() {
        let config = user_config::UserConfig::parse(
            "schema_version = 1\nunlock_delay = \"5 seconds\"\ncategories = []\nwebsites = [\"example.com\"]\n",
        )
        .unwrap();
        let args =
            Args::try_parse_from(["walden", "start", "--unlock-delay", "2 minutes"]).unwrap();
        let CommandSet::Start { unlock_delay, .. } = args.command else {
            panic!("expected a start command");
        };

        let (_, delay_secs) =
            prepare_start(&config, &catalog::vendored(), unlock_delay.as_deref()).unwrap();
        assert_eq!(delay_secs, 120);
    }

    #[test]
    fn privileged_start_pins_the_already_verified_catalog() {
        let catalog = catalog::vendored();
        let args = privileged_start_args(
            Path::new("/tmp/walden-config.toml"),
            &catalog,
            Some("2 hours"),
        )
        .unwrap();

        assert_eq!(
            args,
            [
                "--config",
                "/tmp/walden-config.toml",
                "--catalog-snapshot",
                catalog.directory().to_str().unwrap(),
                "start",
                "--unlock-delay",
                "2 hours",
            ]
        );
    }

    #[test]
    fn accepted_start_tells_the_user_to_follow_progress_separately() {
        assert_eq!(
            applying_rules_message(344_932),
            "Start accepted for 344932 websites.\nRun `walden status` to check whether rules are active."
        );
    }

    #[test]
    fn stop_succeeds_only_after_daemon_outcome() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = thread::spawn(move || {
            let _: protocol::ClientMessage = ipc::receive_json(&mut daemon).unwrap();
            ipc::send_json(
                &mut daemon,
                &protocol::CommandResponse::StopCompleted {
                    outcome: protocol::StopOutcome::AlreadyInactive,
                },
            )
            .unwrap();
        });

        assert_eq!(
            request_stop(&mut client).unwrap(),
            protocol::StopOutcome::AlreadyInactive
        );
        daemon_thread.join().unwrap();
    }

    #[test]
    fn start_acceptance_must_echo_the_operation_id() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = thread::spawn(move || {
            let _: protocol::ClientMessage = ipc::receive_json(&mut daemon).unwrap();
            ipc::send_json(
                &mut daemon,
                &protocol::CommandResponse::StartAccepted {
                    operation_id: "other-operation".to_string(),
                },
            )
            .unwrap();
        });
        let message = protocol::ClientMessage::Start {
            operation_id: "expected-operation".to_string(),
            block_list: vec!["example.com".to_string()],
            unlock_delay_secs: 60,
        };

        let err = request_start(&mut client, &message, "expected-operation").unwrap_err();
        assert!(err.to_string().contains("other-operation"));
        daemon_thread.join().unwrap();
    }

    #[test]
    fn command_surfaces_daemon_rejection() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = thread::spawn(move || {
            let _: protocol::ClientMessage = ipc::receive_json(&mut daemon).unwrap();
            ipc::send_json(
                &mut daemon,
                &protocol::CommandResponse::Rejected {
                    message: "a block is already running".into(),
                },
            )
            .unwrap();
        });

        let err = request_stop(&mut client).unwrap_err();
        assert!(err.to_string().contains("a block is already running"));
        daemon_thread.join().unwrap();
    }

    #[test]
    fn command_fails_without_daemon_confirmation() {
        let (mut client, mut daemon) = UnixStream::pair().unwrap();
        let daemon_thread = thread::spawn(move || {
            let _: protocol::ClientMessage = ipc::receive_json(&mut daemon).unwrap();
        });

        let err = request_stop(&mut client).unwrap_err();
        assert!(
            err.to_string()
                .contains("failed to read the daemon response")
        );
        daemon_thread.join().unwrap();
    }

    #[test]
    fn macos_socket_timeout_is_described_as_an_ipc_deadline() {
        let error = anyhow::Error::from(ipc::IpcError::DeadlineExceeded);

        assert_eq!(
            daemon_request_detail(&error),
            "the daemon did not answer before the IPC deadline"
        );
    }

    fn applying_status() -> protocol::StatusResponse {
        protocol::StatusResponse {
            operation_id: Some("operation-1".to_string()),
            block_is_running: true,
            unlock_delay_secs: Some(60),
            block_end_at: None,
            block_phase: protocol::BlockPhase::Applying,
            website_count: Some(44971),
            apply_started_at: Some(Utc::now() - chrono::TimeDelta::seconds(65)),
            apply_error: None,
            cleanup: None,
            state_error: None,
            last_apply_failure: None,
            apply_attempts: 0,
            apply_retry_at: None,
            apply_in_progress: true,
            dns_progress: None,
            apply_progress: Some(protocol::ApplyProgress {
                stage: protocol::ApplyStage::Resolving,
                completed: 12_400,
                total: 44_971,
                resolved_addresses: 8_120,
                failed_lookups: 17,
            }),
        }
    }

    #[test]
    fn status_describes_an_in_progress_apply() {
        let lines = describe_block(&applying_status(), true);
        assert!(lines.contains(&("Block", "applying — resolving hostnames 27%".into())));
        assert!(lines.contains(&("Current stage", "resolving hostnames".into())));
        assert_eq!(
            describe_block(&applying_status(), false),
            vec![("Block", "applying — resolving hostnames 27%".into())]
        );
    }

    #[test]
    fn normal_status_shows_apply_stages_without_diagnostic_counts() {
        let mut status = applying_status();
        for (stage, summary) in [
            (protocol::ApplyStage::WritingHosts, "writing hosts"),
            (
                protocol::ApplyStage::PreparingFirewall,
                "preparing firewall rules",
            ),
            (
                protocol::ApplyStage::InstallingFirewall,
                "installing firewall rules",
            ),
            (protocol::ApplyStage::SavingState, "saving activation state"),
        ] {
            status.apply_progress.as_mut().unwrap().stage = stage;
            let inspection = service::ServiceInspection {
                state: service::ServiceState::Running,
                status: Some(status.clone()),
            };
            assert_eq!(
                render_status(&inspection, false),
                format!("Daemon: running\nBlock: applying — {summary}")
            );
        }
    }

    #[test]
    fn normal_status_labels_dns_completion_without_claiming_activation() {
        let mut status = applying_status();
        for (completed, expected) in [(0, "0%"), (44_971, "100%")] {
            status.apply_progress.as_mut().unwrap().completed = completed;
            assert_eq!(
                describe_block(&status, false),
                vec![(
                    "Block",
                    format!("applying — resolving hostnames {expected}"),
                )]
            );
        }
        status.apply_progress = None;
        assert_eq!(
            describe_block(&status, false),
            vec![("Block", "applying — starting".into())]
        );
    }

    #[test]
    fn status_field_places_its_only_colon_after_the_label() {
        let line = format_field("Block", "applying — resolving hostnames 27%");

        assert_eq!(line, "Block: applying — resolving hostnames 27%");
        assert_eq!(line.matches(':').count(), 1);
    }

    #[test]
    fn status_describes_a_failed_apply() {
        let mut status = applying_status();
        status.block_phase = protocol::BlockPhase::ApplyFailed;
        status.apply_error = Some("injected backend failure".to_string());
        status.apply_in_progress = false;

        let lines = describe_block(&status, true);
        assert!(lines.contains(&("Block", "start failed".into())));
        assert!(lines.contains(&("Previous failure", "injected backend failure".into())));
        assert!(!lines.iter().any(|(label, _)| *label == "Failed during"));
    }

    #[test]
    fn status_describes_an_active_block() {
        let mut status = applying_status();
        status.block_phase = protocol::BlockPhase::Active;
        status.apply_started_at = None;

        assert_eq!(
            describe_block(&status, false),
            vec![
                ("Block", "active".to_string()),
                ("Unblock delay", "1 minute".to_string()),
            ]
        );
    }

    #[test]
    fn cleanup_is_rendered_even_when_the_block_is_no_longer_running() {
        let mut status = protocol::StatusResponse::inactive();
        status.block_phase = protocol::BlockPhase::CleanupFailed;
        status.cleanup = Some(protocol::CleanupProgress {
            stage: protocol::CleanupStage::VerifyingRules,
            started_at: Utc::now() - chrono::TimeDelta::seconds(60),
            attempts: 3,
            error: Some("PF query failed: Permission denied".into()),
            remaining: vec!["PF table walden_blocked".into()],
            next_retry_at: Some(Utc::now() + chrono::TimeDelta::seconds(5)),
        });
        let output = render_status(
            &service::ServiceInspection {
                state: service::ServiceState::Running,
                status: Some(status),
            },
            true,
        );
        assert!(output.contains("Block: cleanup failed"));
        assert!(output.contains("Stage: verifying hosts and firewall cleanup"));
        assert!(output.contains("Attempts: 3"));
        assert!(output.contains("Permission denied"));
        assert!(output.contains("Remaining: PF table walden_blocked"));
        assert!(output.contains("Retry: automatically"));
        assert!(output.contains("Daemon logs:"));
        assert!(!output.contains("Block: not active"));
    }

    #[test]
    fn waiting_follows_the_accepted_operation_until_active() {
        let mut snapshots = vec![applying_status(), applying_status()];
        snapshots[1].block_phase = protocol::BlockPhase::Active;
        let mut snapshots = snapshots.into_iter();
        let mut output = Vec::new();
        let mut pauses = 0;
        monitor_status(
            || {
                Ok(service::ServiceInspection {
                    state: service::ServiceState::Running,
                    status: Some(snapshots.next().unwrap()),
                })
            },
            |line| output.push(line.to_owned()),
            || pauses += 1,
            MonitorMode::WaitForActive("operation-1".into()),
            false,
        )
        .unwrap();
        assert_eq!(pauses, 1);
        assert!(output[0].contains("Block: applying"));
        assert!(output.last().unwrap().contains("Block: active"));
    }

    #[test]
    fn waiting_reports_apply_failure_without_claiming_the_start_was_rejected() {
        let mut failed = applying_status();
        failed.block_phase = protocol::BlockPhase::ApplyFailed;
        failed.apply_error = Some("firewall write failed".into());
        let mut output = String::new();
        let error = monitor_status(
            || {
                Ok(service::ServiceInspection {
                    state: service::ServiceState::Running,
                    status: Some(failed.clone()),
                })
            },
            |line| output.push_str(line),
            || panic!("should stop waiting on failure"),
            MonitorMode::WaitForActive("operation-1".into()),
            false,
        )
        .unwrap_err();
        assert!(error.to_string().contains("accepted the start"));
        assert!(output.contains("Block: start failed"));
        assert!(!output.contains("firewall write failed"));
    }

    #[test]
    fn waiting_cannot_report_a_different_block_as_success() {
        let mut replaced = applying_status();
        replaced.operation_id = Some("different-operation".into());
        replaced.block_phase = protocol::BlockPhase::Active;
        let error = monitor_status(
            || {
                Ok(service::ServiceInspection {
                    state: service::ServiceState::Running,
                    status: Some(replaced.clone()),
                })
            },
            |_| {},
            || {},
            MonitorMode::WaitForActive("operation-1".into()),
            false,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("no longer the current operation")
        );
    }

    #[test]
    fn watch_suppresses_unchanged_snapshots_and_shows_recovery() {
        let mut cleanup = protocol::StatusResponse::inactive();
        cleanup.block_phase = protocol::BlockPhase::CleaningUp;
        // Fixed snapshot has no elapsed clock so only a phase change prints.
        let mut snapshots = vec![
            cleanup.clone(),
            cleanup,
            protocol::StatusResponse::inactive(),
        ]
        .into_iter();
        let mut output = Vec::new();
        let result = monitor_status(
            || match snapshots.next() {
                Some(status) => Ok(service::ServiceInspection {
                    state: service::ServiceState::Running,
                    status: Some(status),
                }),
                None => bail!("end of test snapshots"),
            },
            |line| {
                if !line.is_empty() {
                    output.push(line.to_owned());
                }
            },
            || {},
            MonitorMode::Watch,
            false,
        );
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("end of test snapshots")
        );
        assert_eq!(output.len(), 2);
        assert!(output[0].contains("Block: cleaning up"));
        assert!(output[1].contains("Block: not active"));
    }

    #[test]
    fn privileged_exit_codes_are_forwarded_without_an_additional_diagnostic() {
        forward_child_status(ExitStatus::from_raw(0)).unwrap();
        let error = forward_child_status(ExitStatus::from_raw(7 << 8)).unwrap_err();
        assert_eq!(error.downcast_ref::<ForwardExit>().unwrap().0, 7);
        let interrupted = forward_child_status(ExitStatus::from_raw(libc::SIGINT)).unwrap_err();
        assert_eq!(
            interrupted.downcast_ref::<ForwardExit>().unwrap().0,
            128 + libc::SIGINT
        );
    }

    #[test]
    fn monitoring_options_are_accepted_by_the_cli_parser() {
        assert!(matches!(
            Args::try_parse_from(["walden", "start", "--wait"])
                .unwrap()
                .command,
            CommandSet::Start { wait: true, .. }
        ));
        assert!(matches!(
            Args::try_parse_from(["walden", "status", "--watch", "--verbose"])
                .unwrap()
                .command,
            CommandSet::Status {
                watch: true,
                verbose: true
            }
        ));
    }

    #[test]
    fn current_retry_and_previous_failure_have_independent_stages() {
        let mut status = applying_status();
        status.apply_error = Some("old PF error".into());
        status.last_apply_failure = Some(protocol::ApplyFailure {
            stage: protocol::ApplyStage::InstallingFirewall,
            message: "old PF error".into(),
            failed_at: Utc::now(),
            attempt: 1,
            requires_action: false,
        });
        status.apply_attempts = 2;
        let lines = describe_block(&status, true);
        assert!(lines.contains(&("Current stage", "resolving hostnames".into())));
        assert!(lines.contains(&("Failed during", "installing firewall rules".into())));
        assert!(lines.contains(&("Retry", "in progress".into())));
        let normal = describe_block(&status, false);
        assert_eq!(
            normal,
            vec![("Block", "applying — resolving hostnames 27%".into())]
        );
    }

    #[test]
    fn normal_failure_output_is_short_and_keeps_raw_diagnostics_verbose() {
        let mut status = applying_status();
        status.block_phase = protocol::BlockPhase::ApplyFailed;
        status.apply_in_progress = false;
        status.last_apply_failure = Some(protocol::ApplyFailure {
            stage: protocol::ApplyStage::PreparingFirewall,
            message: "native PF parser error".into(),
            failed_at: Utc::now(),
            attempt: 1,
            requires_action: true,
        });
        let inspection = service::ServiceInspection {
            state: service::ServiceState::Running,
            status: Some(status),
        };
        let normal = render_status(&inspection, false);
        assert_eq!(
            normal,
            "Daemon: running\nBlock: start failed (firewall setup)\nDetails: walden status --verbose"
        );
        let verbose = render_status(&inspection, true);
        assert!(verbose.contains("native PF parser error"));
        assert!(verbose.contains("Failed during: preparing firewall rules"));
        assert!(verbose.contains("configuration needs attention"));
        assert!(!verbose.contains("retrying automatically"));
    }

    #[test]
    fn firewall_address_progress_cannot_be_printed_as_dns_hostnames() {
        let mut status = applying_status();
        status.apply_progress.as_mut().unwrap().stage = protocol::ApplyStage::InstallingFirewall;
        status.apply_progress.as_mut().unwrap().resolved_addresses = 6584;
        status.dns_progress = Some(walden::resolver::ResolveProgress {
            completed: 2187,
            total: 2187,
            failed_lookups: 186,
            resolved_addresses: 6584,
        });
        let verbose = render_status(
            &service::ServiceInspection {
                state: service::ServiceState::Running,
                status: Some(status),
            },
            true,
        );
        assert!(verbose.contains("DNS: 2187/2187 hostnames checked"));
        assert!(verbose.contains("Firewall addresses: 6584"));
        assert!(!verbose.contains("6584/6584 hostnames"));
    }

    #[test]
    fn countdown_does_not_show_zero_before_a_one_second_delay_expires() {
        let now = Utc::now();
        assert_eq!(
            seconds_until(now + chrono::TimeDelta::milliseconds(999), now),
            1
        );
        assert_eq!(seconds_until(now + chrono::TimeDelta::seconds(1), now), 1);
        assert_eq!(
            seconds_until(now + chrono::TimeDelta::milliseconds(1001), now),
            2
        );
        assert_eq!(seconds_until(now, now), 0);
        assert_eq!(seconds_until(now - chrono::TimeDelta::seconds(1), now), 0);
    }
}
