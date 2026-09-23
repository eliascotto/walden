use std::collections::BTreeSet;
use std::env;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, bail, ensure};
use chrono::{Local, Utc};
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, MultiSelect, theme::ColorfulTheme};

use walden::{build_info, catalog, ipc, protocol, service, user_config};

const LARGE_BLOCK_NOTICE: usize = 1_000;
static OPERATION_COUNTER: AtomicU64 = AtomicU64::new(0);

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
    },
    /// Request that the active block end after its fixed delay
    Stop,
    /// Check the status of the system
    Status,
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
        CommandSet::Start { unlock_delay } => {
            start(config, catalog_snapshot, unlock_delay.as_deref())
        }
        CommandSet::Stop => stop(),
        CommandSet::Status => status(),
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
) -> anyhow::Result<()> {
    let (path, config) = user_config::load(config_override)?;
    let catalog = load_catalog(catalog_snapshot)?;
    let effective = config.resolve(&catalog)?;
    let delay = unlock_delay.unwrap_or(&config.unlock_delay);
    let unlock_delay_secs = user_config::parse_unlock_delay_secs(delay)?;

    let website_count = effective.block_list.len();
    if website_count >= LARGE_BLOCK_NOTICE && !is_root() {
        println!("Applying a block for {website_count} websites.");
        println!("This can take a few minutes; `walden status` shows progress.");
    }

    // Whether the daemon is installed can be read without privileges, so a
    // machine that cannot run a block says so before asking for a password and
    // long before anything on it changes.
    service::verify_ready_to_start()?;

    if !is_root() {
        return rerun_with_sudo(&privileged_start_args(&path, &catalog, unlock_delay)?);
    }

    start_block(effective.block_list, unlock_delay_secs)?;
    println!("{}", applying_rules_message(website_count));
    Ok(())
}

fn applying_rules_message(website_count: usize) -> String {
    format!("Applying rules for {website_count} websites. This can take a few minutes.")
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
        protocol::StopOutcome::ApplyCancelled => {
            println!("Apply cancelled. The block was not locked in.");
        }
        protocol::StopOutcome::Ending { .. } => {
            println!("Stop requested. Run `walden status` to monitor the block.");
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
fn status() -> anyhow::Result<()> {
    // Reported separately from the block, because a machine without Walden
    // installed and one sitting idle with it installed are both unblocked, and
    // only one of them is something the user has to act on.
    let inspection = service::inspect()?;
    print_field("Daemon", &inspection.state.describe());

    if !inspection.state.is_running() {
        match inspection.state {
            service::ServiceState::NotInstalled | service::ServiceState::Inactive => {
                print_status(None)
            }
            service::ServiceState::Starting => {
                print_field("Block", "unavailable (daemon has not answered yet)")
            }
            service::ServiceState::Unhealthy(_) => {
                print_field("Block", "unavailable (daemon service is unhealthy)")
            }
            service::ServiceState::Running => unreachable!(),
        }
        return Ok(());
    }

    let status = inspection
        .status
        .context("the daemon was responsive but returned no status")?;
    print_status(Some(&status));
    Ok(())
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
    ensure!(status.success(), "privileged command exited with {status}");
    Ok(())
}

fn is_root() -> bool {
    // SAFETY: geteuid reads process state and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

fn start_block(block_list: Vec<String>, unlock_delay_secs: u64) -> anyhow::Result<()> {
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
        Ok(()) => Ok(()),
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
                Ok(())
            } else {
                bail!("failed to start the block: {}", daemon_request_detail(&err))
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
        protocol::CommandResponse::Rejected { message } => {
            bail!("the daemon rejected the request: {message}")
        }
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

fn print_field(label: &str, value: &str) {
    println!("{}", format_field(label, value));
}

fn format_field(label: &str, value: &str) -> String {
    format!("{label}: {value}")
}

fn print_status(status: Option<&protocol::StatusResponse>) {
    let Some(status) = status.filter(|status| status.block_is_running) else {
        print_field("Block", "not active");
        return;
    };

    for (label, value) in describe_block(status) {
        print_field(label, &value);
    }
}

fn describe_block(status: &protocol::StatusResponse) -> Vec<(&'static str, String)> {
    match status.block_phase {
        protocol::BlockPhase::Inactive => vec![("Block", "not active".to_string())],
        protocol::BlockPhase::Applying => vec![(
            "Block",
            format!("applying — {}", apply_progress_summary(status)),
        )],
        protocol::BlockPhase::ApplyFailed => {
            let mut lines = vec![("Block", "apply failed".to_string())];
            if let Some(error) = &status.apply_error {
                lines.push(("Error", error.clone()));
            }
            if let Some(progress) = &status.apply_progress {
                lines.push((
                    "Failed during",
                    apply_stage_name(progress.stage).to_string(),
                ));
            }
            lines.push((
                "Websites",
                status
                    .website_count
                    .map(|count| count.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            ));
            lines.push((
                "Retry",
                "the daemon will keep retrying; `walden stop` cancels".to_string(),
            ));
            lines
        }
        protocol::BlockPhase::Ending => {
            let remaining = status.block_end_at.map(|block_end_at| {
                format_duration(
                    (block_end_at - Utc::now()).num_seconds().max(0) as u64,
                    DurationStyle::Compact,
                )
            });
            let mut lines = vec![(
                "Block",
                remaining
                    .map(|remaining| format!("ending in {remaining}"))
                    .unwrap_or_else(|| "ending".to_string()),
            )];
            if let Some(block_end_at) = status.block_end_at {
                lines.push((
                    "Ends at",
                    block_end_at
                        .with_timezone(&Local)
                        .format("%H:%M:%S %Y/%m/%d")
                        .to_string(),
                ));
            }
            lines
        }
        protocol::BlockPhase::Active => {
            let delay = match status.unlock_delay_secs {
                Some(secs) => format_duration(secs, DurationStyle::Exact),
                None => "not set".to_string(),
            };
            vec![("Block", "active".to_string()), ("Unblock delay", delay)]
        }
    }
}

fn apply_stage_name(stage: protocol::ApplyStage) -> &'static str {
    match stage {
        protocol::ApplyStage::WritingHosts => "writing hosts",
        protocol::ApplyStage::Resolving => "resolving hostnames",
        protocol::ApplyStage::InstallingFirewall => "installing firewall rules",
    }
}

fn apply_progress_summary(status: &protocol::StatusResponse) -> String {
    let Some(progress) = &status.apply_progress else {
        return format!("{} websites", status.website_count.unwrap_or(0));
    };

    match progress.stage {
        protocol::ApplyStage::WritingHosts => {
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
        protocol::ApplyStage::InstallingFirewall => {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::thread;

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
            "Applying rules for 344932 websites. This can take a few minutes."
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
        let lines = describe_block(&applying_status());
        assert_eq!(
            lines,
            vec![("Block", "applying — resolving hostnames 27%".to_string())]
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

        let lines = describe_block(&status);
        assert_eq!(
            lines,
            vec![
                ("Block", "apply failed".to_string()),
                ("Error", "injected backend failure".to_string()),
                ("Failed during", "resolving hostnames".to_string()),
                ("Websites", "44971".to_string()),
                (
                    "Retry",
                    "the daemon will keep retrying; `walden stop` cancels".to_string()
                ),
            ]
        );
    }

    #[test]
    fn status_describes_an_active_block() {
        let mut status = applying_status();
        status.block_phase = protocol::BlockPhase::Active;
        status.apply_started_at = None;

        assert_eq!(
            describe_block(&status),
            vec![
                ("Block", "active".to_string()),
                ("Unblock delay", "1 minute".to_string()),
            ]
        );
    }
}
