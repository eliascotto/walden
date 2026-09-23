// What the platform packages install, and what installing, upgrading, and
// removing one does.
//
// Two kinds of file are checked here. The service definitions are read by
// Walden at runtime and never written, so nothing in the daemon would notice
// if they drifted from what its lifecycle assumes: that the daemon runs where
// the runtime looks for it, that a fresh installation stays idle, and that the
// clean exit ending a block is not treated as a crash to recover from.
//
// The maintainer scripts are read by nothing at all until a package manager
// runs them as root on someone's machine, which is a poor first test of
// whether an upgrade restarts a daemon it interrupted or leaves a block
// unenforced. They are run here instead, against stub service managers in a
// temporary directory, where the decisions they make can be read out of what
// they asked the service manager to do.
//
// Everything is checked on both platforms, because the package for one
// platform is built and changed on the other.

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const LAUNCHD_JOB: &str = include_str!("../packaging/macos/org.scotto.waldend.plist");
const LOCAL_SYSTEMD_UNIT: &str = include_str!("../packaging/linux/waldend.service");
const DISTRIBUTION_SYSTEMD_UNIT: &str =
    include_str!("../packaging/linux/distribution/waldend.service");

// The unit an administrator installing Walden under /usr/local gets, and the
// one a distribution package installs under /usr. Both are shipped, so both
// have to hold up everything the runtime assumes of a unit.
fn systemd_units() -> [(&'static str, &'static str); 2] {
    [
        ("packaging/linux/waldend.service", LOCAL_SYSTEMD_UNIT),
        (
            "packaging/linux/distribution/waldend.service",
            DISTRIBUTION_SYSTEMD_UNIT,
        ),
    ]
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn launchd_job() -> plist::Dictionary {
    plist::Value::from_reader_xml(Cursor::new(LAUNCHD_JOB))
        .expect("the packaged launchd job is not a readable property list")
        .into_dictionary()
        .expect("the packaged launchd job is not a dictionary")
}

fn systemd_directive(unit: &'static str, name: &str) -> Option<&'static str> {
    unit.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
}

// The directives a unit actually sets, with the comments explaining them and
// the blank lines between them left out.
fn systemd_directives(unit: &'static str) -> Vec<&'static str> {
    unit.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

#[test]
fn every_packaged_service_definition_runs_a_daemon_the_runtime_looks_for() {
    let job = launchd_job();
    let program = job
        .get("ProgramArguments")
        .and_then(plist::Value::as_array)
        .and_then(|arguments| arguments.first())
        .and_then(plist::Value::as_string)
        .expect("the packaged launchd job does not say what to run");
    assert!(
        walden::service::MACOS_DAEMON_BINARY_CANDIDATES.contains(&program),
        "the launchd job runs {program}, which Walden does not look for on macOS"
    );
    assert!(Path::new(program).is_absolute());

    for (name, unit) in systemd_units() {
        let exec_start = systemd_directive(unit, "ExecStart")
            .unwrap_or_else(|| panic!("{name} does not say what to run"));
        assert!(
            walden::service::LINUX_DAEMON_BINARY_CANDIDATES.contains(&exec_start),
            "{name} runs {exec_start}, which Walden does not look for on Linux"
        );
        assert!(Path::new(exec_start).is_absolute());
    }
}

// The two units exist only because a distribution package may not install
// anything under /usr/local. Any second difference between them is a change
// that was made to one and forgotten in the other.
#[test]
fn the_two_systemd_units_differ_only_in_where_the_daemon_is() {
    let [(local_name, local), (distribution_name, distribution)] = systemd_units();

    assert_ne!(
        systemd_directive(local, "ExecStart"),
        systemd_directive(distribution, "ExecStart"),
        "{local_name} and {distribution_name} run the same daemon and one of them is redundant"
    );

    let without_exec_start = |unit| {
        systemd_directives(unit)
            .into_iter()
            .filter(|line| !line.starts_with("ExecStart="))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        without_exec_start(local),
        without_exec_start(distribution),
        "{local_name} and {distribution_name} disagree about something other than ExecStart"
    );
}

// The label is how Walden addresses the job, so the two have to agree or every
// launchctl call is aimed at nothing.
#[test]
fn the_launchd_job_is_labelled_the_way_walden_addresses_it() {
    let job = launchd_job();

    assert_eq!(
        job.get("Label").and_then(plist::Value::as_string),
        Some("org.scotto.waldend")
    );
}

// A package that installed an active daemon would put a machine under Walden's
// care before its owner asked for a block.
#[test]
fn a_fresh_installation_is_inactive_on_both_platforms() {
    let job = launchd_job();
    assert_eq!(
        job.get("Disabled").and_then(plist::Value::as_boolean),
        Some(true),
        "the packaged launchd job would run before a block is started"
    );

    // A systemd unit is inert until something enables it, which no package
    // does, so only the launchd job needs saying so explicitly.
    for (name, unit) in systemd_units() {
        assert_eq!(
            systemd_directive(unit, "WantedBy"),
            Some("multi-user.target"),
            "{name} would not come back after a restart once a block enabled it"
        );
    }
}

// Retirement ends with the daemon exiting cleanly, on the understanding that
// the service manager will read that as the end of the block rather than as a
// failure to recover from. Both definitions have to hold up that half of it,
// while still restarting a daemon that dies during a block.
#[test]
fn a_clean_exit_ends_the_daemon_and_a_crash_does_not() {
    let job = launchd_job();
    let keep_alive = job
        .get("KeepAlive")
        .and_then(plist::Value::as_dictionary)
        .expect("the packaged launchd job restarts the daemon unconditionally");
    assert_eq!(
        keep_alive
            .get("SuccessfulExit")
            .and_then(plist::Value::as_boolean),
        Some(false)
    );
    assert_eq!(
        job.get("RunAtLoad").and_then(plist::Value::as_boolean),
        Some(true),
        "the launchd job would not come back after a restart"
    );

    for (name, unit) in systemd_units() {
        assert_eq!(
            systemd_directive(unit, "Restart"),
            Some("on-failure"),
            "{name} would treat the daemon's clean exit as a crash"
        );
    }
}

// Every build recipe installs the daemon where the service definition it ships
// says the daemon runs, by reading the path out of that definition. A recipe
// that spelled the path out itself would be a second copy of a decision, free
// to disagree with the definition the runtime actually reads.
#[test]
fn no_build_recipe_decides_for_itself_where_the_daemon_goes() {
    for recipe in [
        "scripts/package-macos.sh",
        "scripts/package-deb.sh",
        "packaging/linux/arch/PKGBUILD.in",
    ] {
        let contents = fs::read_to_string(repo_root().join(recipe))
            .unwrap_or_else(|err| panic!("failed to read {recipe}: {err}"));

        for candidate in walden::service::MACOS_DAEMON_BINARY_CANDIDATES
            .iter()
            .chain(walden::service::LINUX_DAEMON_BINARY_CANDIDATES)
        {
            assert!(
                !contents.contains(candidate),
                "{recipe} names {candidate} itself instead of reading it from the \
                 service definition it ships"
            );
        }
    }
}

// A machine with stub service managers on its PATH, so that a maintainer
// script can be run for what it decides rather than for what it would do to
// the machine running the tests.
struct Sandbox {
    root: PathBuf,
}

// `is-active` and `launchctl print` answer with an exit status, so the stubs
// take one: zero is a daemon that is running.
const ACTIVE: &str = "0";
const INACTIVE: &str = "1";

const SYSTEMCTL_STUB: &str = r#"#!/bin/sh
echo "systemctl $*" >>"$STUB_LOG"
case "$1" in
  is-active) exit "${STUB_SERVICE_IS_ACTIVE:-1}" ;;
  restart) exit "${STUB_RESTART_EXIT:-0}" ;;
esac
exit 0
"#;

const LAUNCHCTL_STUB: &str = r#"#!/bin/sh
echo "launchctl $*" >>"$STUB_LOG"
case "$1" in
  print)
    if [ "${STUB_SERVICE_IS_ACTIVE:-1}" -eq 0 ]; then
      printf '\tstate = running\n'
      exit 0
    fi
    exit 113
    ;;
esac
exit 0
"#;

const CHATTR_STUB: &str = r#"#!/bin/sh
echo "chattr $*" >>"$STUB_LOG"
exit 0
"#;

impl Sandbox {
    fn new(name: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock is before the Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "walden-packaging-{name}-{}-{unique}",
            std::process::id()
        ));

        let sandbox = Sandbox { root };
        fs::create_dir_all(sandbox.root.join("bin")).unwrap();
        fs::create_dir_all(sandbox.state_dir()).unwrap();

        sandbox.stub("systemctl", SYSTEMCTL_STUB);
        sandbox.stub("launchctl", LAUNCHCTL_STUB);
        sandbox.stub("chattr", CHATTR_STUB);
        sandbox
    }

    fn stub(&self, name: &str, body: &str) {
        let path = self.root.join("bin").join(name);
        fs::write(&path, body).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    // The stubs come first, so that a script asking for systemctl or launchctl
    // reaches the recorder rather than the machine running the tests.
    fn search_path(&self) -> String {
        format!(
            "{}:/usr/bin:/bin:/usr/sbin:/sbin",
            self.root.join("bin").display()
        )
    }

    fn log(&self) -> PathBuf {
        self.root.join("commands.log")
    }

    fn marker(&self) -> PathBuf {
        self.root.join("run").join("upgrade-restart")
    }

    fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    // What the scripts asked the service managers to do, in order.
    fn commands(&self) -> String {
        fs::read_to_string(self.log()).unwrap_or_default()
    }

    fn command(&self, script: &str) -> Command {
        let mut command = Command::new("sh");
        command
            .env("PATH", self.search_path())
            .env("STUB_LOG", self.log())
            .env("WALDEN_UPGRADE_MARKER", self.marker())
            .env("WALDEN_STATE_DIR", self.state_dir())
            .env("STUB_SERVICE_IS_ACTIVE", INACTIVE)
            .current_dir(&self.root);
        command.arg(repo_root().join(script));
        command
    }

    fn run(&self, script: &str, args: &[&str], active: &str) -> Output {
        self.command(script)
            .args(args)
            .env("STUB_SERVICE_IS_ACTIVE", active)
            .output()
            .unwrap_or_else(|err| panic!("failed to run {script}: {err}"))
    }

    // pacman sources the scriptlet and calls one function out of it, which is
    // the only way its functions can be run.
    fn run_arch(&self, function: &str, active: &str) -> Output {
        let scriptlet = repo_root().join("packaging/linux/arch/walden.install");

        Command::new("sh")
            .arg("-c")
            .arg(format!(". \"{}\"; {function}", scriptlet.display()))
            .env("PATH", self.search_path())
            .env("STUB_LOG", self.log())
            .env("WALDEN_UPGRADE_MARKER", self.marker())
            .env("STUB_SERVICE_IS_ACTIVE", active)
            .current_dir(&self.root)
            .output()
            .unwrap_or_else(|err| panic!("failed to run {function}: {err}"))
    }

    // This machine's persisted state, named the way the daemon names it.
    fn write_persisted_state(&self) -> PathBuf {
        let name = walden::settings::persisted_state_file_name(&walden::settings::machine_id());
        let path = self.state_dir().join(name);
        fs::write(&path, b"persisted block").unwrap();
        path
    }

    // A hidden hex name of the same length the daemon uses, but not this
    // machine's file. A glob of `/etc/.*` would have deleted it.
    fn write_hex_named_decoy(&self) -> PathBuf {
        let path = self.state_dir().join(format!(".{}", "a1b2c3d4".repeat(8)));
        fs::write(&path, b"not walden's").unwrap();
        path
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn succeeded(output: &Output) -> bool {
    output.status.success()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

// Installing Walden is not asking it to block anything, so nothing a package
// does on a fresh machine may start or enable the service. Only `walden start`
// does that.
#[test]
fn installing_the_debian_package_starts_nothing() {
    let sandbox = Sandbox::new("deb-fresh-install");

    let output = sandbox.run("packaging/linux/debian/postinst", &["configure"], INACTIVE);
    assert!(succeeded(&output), "{}", stderr(&output));

    let commands = sandbox.commands();
    assert!(
        commands.contains("systemctl daemon-reload"),
        "the new unit was never made visible to systemd: {commands}"
    );
    for activation in ["enable", "start", "restart"] {
        assert!(
            !commands.contains(&format!("systemctl {activation}")),
            "a fresh installation ran 'systemctl {activation}': {commands}"
        );
    }
    assert!(stdout(&output).contains("inactive"));
}

// The whole point of the marker preinst writes: after dpkg has replaced the
// executable, a daemon the upgrade stopped and one that was never running look
// the same, and only one of them should come back.
#[test]
fn upgrading_the_debian_package_puts_back_only_a_daemon_that_was_running() {
    let interrupted = Sandbox::new("deb-upgrade-active");
    let preinst = interrupted.run(
        "packaging/linux/debian/preinst",
        &["upgrade", "0.0.9"],
        ACTIVE,
    );
    assert!(succeeded(&preinst), "{}", stderr(&preinst));
    assert!(
        interrupted.marker().exists(),
        "a running daemon was not noted before the upgrade replaced it"
    );

    let postinst = interrupted.run(
        "packaging/linux/debian/postinst",
        &["configure", "0.0.9"],
        INACTIVE,
    );
    assert!(succeeded(&postinst), "{}", stderr(&postinst));
    assert!(
        interrupted
            .commands()
            .contains("systemctl restart waldend.service"),
        "the daemon was not restarted onto the new version: {}",
        interrupted.commands()
    );
    assert!(
        !interrupted.marker().exists(),
        "the note survived the upgrade and would restart the daemon again next time"
    );

    let idle = Sandbox::new("deb-upgrade-inactive");
    let preinst = idle.run(
        "packaging/linux/debian/preinst",
        &["upgrade", "0.0.9"],
        INACTIVE,
    );
    assert!(succeeded(&preinst), "{}", stderr(&preinst));
    assert!(
        !idle.marker().exists(),
        "an idle installation was noted as one to restart"
    );

    let postinst = idle.run(
        "packaging/linux/debian/postinst",
        &["configure", "0.0.9"],
        INACTIVE,
    );
    assert!(succeeded(&postinst), "{}", stderr(&postinst));
    assert!(
        !idle.commands().contains("systemctl restart"),
        "an upgrade started a daemon nobody had asked to run: {}",
        idle.commands()
    );
}

// A machine left with a block's rules in place and no daemon to expire them is
// worse than an upgrade that stops and says so, so the restart is not allowed
// to fail quietly.
#[test]
fn an_upgrade_that_cannot_restart_the_daemon_fails() {
    let sandbox = Sandbox::new("deb-upgrade-restart-fails");
    sandbox.run(
        "packaging/linux/debian/preinst",
        &["upgrade", "0.0.9"],
        ACTIVE,
    );

    let output = sandbox
        .command("packaging/linux/debian/postinst")
        .args(["configure", "0.0.9"])
        .env("STUB_RESTART_EXIT", "1")
        .output()
        .unwrap();

    assert!(
        !succeeded(&output),
        "the upgrade reported success after failing to restart an interrupted daemon"
    );
}

// Removing Walden mid-block stops the daemon but leaves the hosts entries and
// firewall rules exactly where they are. A user who is not told that will
// reasonably assume uninstalling ended the block.
#[test]
fn removing_the_debian_package_stops_the_service_and_says_a_block_is_not_lifted() {
    let sandbox = Sandbox::new("deb-remove-active");

    let output = sandbox.run("packaging/linux/debian/prerm", &["remove"], ACTIVE);
    assert!(succeeded(&output), "{}", stderr(&output));

    assert!(
        sandbox
            .commands()
            .contains("systemctl disable --now waldend.service"),
        "removal left systemd willing to start the daemon again: {}",
        sandbox.commands()
    );

    let warning = stderr(&output);
    assert!(warning.contains("does not lift the block"), "{warning}");
    assert!(warning.contains("nftables"), "{warning}");
}

#[test]
fn removing_the_debian_package_while_idle_warns_about_nothing() {
    let sandbox = Sandbox::new("deb-remove-inactive");

    let output = sandbox.run("packaging/linux/debian/prerm", &["remove"], INACTIVE);
    assert!(succeeded(&output), "{}", stderr(&output));
    assert!(
        stderr(&output).is_empty(),
        "an idle removal warned about a block that was not running: {}",
        stderr(&output)
    );
}

// The persisted state is the record of a block someone chose not to be able to
// cancel, so uninstalling is deliberately not the way around it. Deleting it
// takes a second, explicit request.
#[test]
fn an_ordinary_removal_keeps_the_persisted_block_state_and_a_purge_deletes_it() {
    let sandbox = Sandbox::new("deb-purge");
    let state = sandbox.write_persisted_state();
    let unrelated = sandbox.state_dir().join(".hostname");
    fs::write(&unrelated, b"not walden's").unwrap();
    let decoy = sandbox.write_hex_named_decoy();
    assert_ne!(
        state, decoy,
        "the decoy collided with this machine's state file"
    );

    let removed = sandbox.run("packaging/linux/debian/postrm", &["remove"], INACTIVE);
    assert!(succeeded(&removed), "{}", stderr(&removed));
    assert!(
        state.exists(),
        "an ordinary removal deleted the block a user could not cancel"
    );
    assert!(stdout(&removed).contains("purge"));

    let purged = sandbox.run("packaging/linux/debian/postrm", &["purge"], INACTIVE);
    assert!(succeeded(&purged), "{}", stderr(&purged));
    assert!(!state.exists(), "a purge kept the persisted block state");
    assert!(
        unrelated.exists(),
        "a purge deleted a dotfile that was not Walden's"
    );
    assert!(
        decoy.exists(),
        "a purge deleted a hex-named dotfile that was not this machine's state"
    );
    assert!(
        sandbox.commands().contains("chattr -i"),
        "the immutable flag was never cleared, so a real state file would have survived: {}",
        sandbox.commands()
    );
}

// The macOS installer cannot tell a fresh install from an upgrade, so both run
// the same two scripts and the machine's own state is what separates them.
#[test]
fn installing_the_macos_package_loads_nothing() {
    let sandbox = Sandbox::new("macos-fresh-install");

    let preinstall = sandbox.run("packaging/macos/scripts/preinstall", &[], INACTIVE);
    assert!(succeeded(&preinstall), "{}", stderr(&preinstall));
    assert!(
        !sandbox.marker().exists(),
        "a machine with no daemon running was noted as one to restart"
    );

    let postinstall = sandbox.run("packaging/macos/scripts/postinstall", &[], INACTIVE);
    assert!(succeeded(&postinstall), "{}", stderr(&postinstall));

    let commands = sandbox.commands();
    for activation in ["bootstrap", "enable", "kickstart"] {
        assert!(
            !commands.contains(&format!("launchctl {activation}")),
            "a fresh installation ran 'launchctl {activation}': {commands}"
        );
    }
    assert!(stdout(&postinstall).contains("inactive"));
}

#[test]
fn upgrading_the_macos_package_puts_back_a_daemon_it_interrupted() {
    let sandbox = Sandbox::new("macos-upgrade-active");

    let preinstall = sandbox.run("packaging/macos/scripts/preinstall", &[], ACTIVE);
    assert!(succeeded(&preinstall), "{}", stderr(&preinstall));
    assert!(
        sandbox.marker().exists(),
        "a running daemon was not noted before the installer replaced it"
    );
    assert!(
        sandbox
            .commands()
            .contains("launchctl bootout system/org.scotto.waldend"),
        "the old daemon was left running on the replaced executable: {}",
        sandbox.commands()
    );

    // The daemon is not running by the time postinstall runs, which is exactly
    // why the note preinstall left is the only thing that can decide this.
    let postinstall = sandbox.run("packaging/macos/scripts/postinstall", &[], INACTIVE);
    assert!(succeeded(&postinstall), "{}", stderr(&postinstall));

    let commands = sandbox.commands();
    assert!(
        commands.contains("launchctl enable system/org.scotto.waldend"),
        "{commands}"
    );
    assert!(
        commands
            .contains("launchctl bootstrap system /Library/LaunchDaemons/org.scotto.waldend.plist"),
        "{commands}"
    );
    assert!(!sandbox.marker().exists());
}

// pacman's scriptlet is the Arch spelling of the Debian maintainer scripts and
// has to reach the same three answers.
#[test]
fn the_arch_scriptlet_matches_the_debian_maintainer_scripts() {
    let fresh = Sandbox::new("arch-fresh-install");
    let output = fresh.run_arch("post_install", INACTIVE);
    assert!(succeeded(&output), "{}", stderr(&output));
    assert!(stdout(&output).contains("inactive"));
    assert!(
        fresh.commands().is_empty(),
        "a fresh installation asked systemd for something: {}",
        fresh.commands()
    );

    let interrupted = Sandbox::new("arch-upgrade-active");
    assert!(succeeded(&interrupted.run_arch("pre_upgrade", ACTIVE)));
    assert!(interrupted.marker().exists());
    assert!(succeeded(&interrupted.run_arch("post_upgrade", INACTIVE)));
    assert!(
        interrupted
            .commands()
            .contains("systemctl restart waldend.service"),
        "{}",
        interrupted.commands()
    );

    let idle = Sandbox::new("arch-upgrade-inactive");
    assert!(succeeded(&idle.run_arch("pre_upgrade", INACTIVE)));
    assert!(!idle.marker().exists());
    assert!(succeeded(&idle.run_arch("post_upgrade", INACTIVE)));
    assert!(
        !idle.commands().contains("systemctl restart"),
        "{}",
        idle.commands()
    );

    let removed = Sandbox::new("arch-remove-active");
    let output = removed.run_arch("pre_remove", ACTIVE);
    assert!(succeeded(&output), "{}", stderr(&output));
    assert!(stderr(&output).contains("does not lift the block"));
    assert!(
        removed
            .commands()
            .contains("systemctl disable --now waldend.service"),
        "{}",
        removed.commands()
    );

    let kept = Sandbox::new("arch-post-remove");
    let output = kept.run_arch("post_remove", INACTIVE);
    assert!(succeeded(&output), "{}", stderr(&output));
    assert!(stdout(&output).contains("chattr -i"));
}

#[test]
fn every_package_builder_installs_the_vendored_catalog() {
    let debian = fs::read_to_string(repo_root().join("scripts/package-deb.sh")).unwrap();
    assert!(debian.contains("ensure_catalog_snapshot"));
    assert!(debian.contains("install_catalog_snapshot"));
    assert!(debian.contains("/usr/share/walden/catalog/v1"));

    let macos = fs::read_to_string(repo_root().join("scripts/package-macos.sh")).unwrap();
    assert!(macos.contains("ensure_catalog_snapshot"));
    assert!(macos.contains("copy_catalog_snapshot"));
    assert!(macos.contains("harden_catalog_snapshot"));
    assert!(macos.contains("/usr/local/share/walden/catalog/v1"));

    let arch = fs::read_to_string(repo_root().join("packaging/linux/arch/PKGBUILD.in")).unwrap();
    assert!(arch.contains("fetch-catalog.sh"));
    assert!(arch.contains("/usr/share/walden/catalog/v1"));
    assert!(arch.contains("WALDEN_CATALOG_DIR"));

    let dev = fs::read_to_string(repo_root().join("scripts/dev-install.sh")).unwrap();
    assert!(dev.contains("ensure_catalog_snapshot"));
    assert!(dev.contains("install_catalog_snapshot"));
}

#[test]
fn the_packaged_catalog_snapshot_is_complete_and_read_only() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_nanos();
    let dest = std::env::temp_dir().join(format!(
        "walden-packaging-catalog-{}-{unique}",
        std::process::id()
    ));

    let output = Command::new("sh")
        .args([
            "-c",
            ". ./scripts/package-common.sh && ensure_catalog_snapshot && install_catalog_snapshot \"$1\"",
            "scripts/package-deb.sh",
            dest.to_str().expect("temp path is utf-8"),
        ])
        .current_dir(repo_root())
        .output()
        .expect("failed to stage a catalog snapshot");
    assert!(
        succeeded(&output),
        "install_catalog_snapshot failed: {}",
        stderr(&output)
    );

    let vendor = walden::catalog::vendored_dir();
    for name in ["manifest.json", "checksums.txt"] {
        assert!(dest.join(name).is_file(), "missing {name}");
        assert_eq!(
            fs::read(dest.join(name)).unwrap(),
            fs::read(vendor.join(name)).unwrap()
        );
    }

    let vendor_categories = fs::read_dir(vendor.join("categories")).unwrap().count();
    let installed_categories = fs::read_dir(dest.join("categories")).unwrap().count();
    assert_eq!(installed_categories, vendor_categories);
    assert!(installed_categories > 0);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let file_mode = fs::metadata(dest.join("manifest.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, walden::catalog::FILE_MODE);
        assert_eq!(dir_mode, walden::catalog::DIRECTORY_MODE);
    }

    walden::catalog::Catalog::open(&dest)
        .unwrap()
        .verify()
        .unwrap();
    let _ = walden::catalog::set_tree_modes(&dest, 0o755, 0o644);
    let _ = fs::remove_dir_all(&dest);
}

#[test]
fn removing_a_package_takes_the_updated_catalog_cache_with_it() {
    let sandbox = Sandbox::new("deb-remove-catalog");
    let cache = sandbox.root.join("updated-catalog");
    fs::create_dir_all(&cache).unwrap();
    fs::write(cache.join("manifest.json"), "cached").unwrap();

    let output = sandbox
        .command("packaging/linux/debian/postrm")
        .args(["remove"])
        .env("WALDEN_UPDATED_CATALOG_DIR", &cache)
        .output()
        .unwrap();
    assert!(succeeded(&output), "{}", stderr(&output));
    assert!(
        !cache.exists(),
        "an ordinary removal left a catalog cache that would outrank the next package"
    );
}

#[test]
fn uninstallers_remove_catalog_directories() {
    let macos = fs::read_to_string(repo_root().join("packaging/macos/walden-uninstall")).unwrap();
    assert!(macos.contains("/usr/local/share/walden/catalog"));
    assert!(macos.contains("/usr/local/var/walden/catalog"));

    let debian = fs::read_to_string(repo_root().join("packaging/linux/debian/postrm")).unwrap();
    assert!(debian.contains("/var/lib/walden/catalog"));

    let arch = fs::read_to_string(repo_root().join("packaging/linux/arch/walden.install")).unwrap();
    assert!(arch.contains("/var/lib/walden/catalog"));

    let dev = fs::read_to_string(repo_root().join("scripts/dev-install.sh")).unwrap();
    assert!(dev.contains("BUNDLED_CATALOG"));
    assert!(dev.contains("UPDATED_CATALOG"));
}

fn cargo_package_version() -> String {
    let contents = fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    let mut in_package = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package && let Some(rest) = line.strip_prefix("version") {
            let value = rest.trim().trim_start_matches('=').trim();
            return value.trim_matches('"').to_string();
        }
    }
    panic!("Cargo.toml does not state a package version");
}

fn script_output(script: &str, args: &[&str]) -> Output {
    Command::new("sh")
        .arg(repo_root().join(script))
        .args(args)
        .current_dir(repo_root())
        .output()
        .unwrap_or_else(|err| panic!("failed to run {script}: {err}"))
}

#[test]
fn a_release_tag_must_match_the_cargo_version() {
    let version = cargo_package_version();
    let matched = script_output("scripts/verify-release-tag.sh", &[&format!("v{version}")]);
    assert!(succeeded(&matched), "{}", stderr(&matched));
    assert!(stdout(&matched).contains(&version));

    let mismatched = script_output(
        "scripts/verify-release-tag.sh",
        &["v0.0.0-not-this-release"],
    );
    assert!(
        !succeeded(&mismatched),
        "a tag that does not match Cargo.toml was accepted"
    );
    assert!(stderr(&mismatched).contains(&version));
}

#[test]
fn package_inspection_rejects_a_missing_artifact() {
    let output = script_output(
        "scripts/inspect-package.sh",
        &["/no/such/walden-package.pkg"],
    );
    assert!(
        !succeeded(&output),
        "inspecting a missing package succeeded"
    );
    assert!(stderr(&output).contains("no such package"));
}

#[test]
fn package_inspection_requires_release_binaries_and_an_inactive_service() {
    let inspect = fs::read_to_string(repo_root().join("scripts/inspect-package.sh")).unwrap();
    assert!(inspect.contains("--release-dir"));
    assert!(inspect.contains("unexpected payload file"));
    assert!(inspect.contains("Disabled"));
    assert!(inspect.contains("systemctl enable"));
    assert!(inspect.contains("systemctl start"));
    assert!(inspect.contains("/usr/local/share/walden/catalog/v1"));
    assert!(inspect.contains("/usr/share/walden/catalog/v1"));
    assert!(inspect.contains("usage.md"));
}

#[test]
fn release_notes_identify_unsigned_macos_packages_and_supported_architectures() {
    let output = script_output("scripts/generate-release-notes.sh", &[]);
    assert!(succeeded(&output), "{}", stderr(&output));
    let notes = stdout(&output);
    let version = cargo_package_version();
    assert!(notes.contains(&format!("Walden {version}")));
    assert!(notes.contains("unsigned"));
    assert!(notes.contains("macos-arm64"));
    assert!(notes.contains("macos-x86_64"));
    assert!(notes.contains("amd64.deb"));
    assert!(notes.contains("arm64.deb"));
    assert!(notes.contains("SHA256SUMS"));
    assert!(notes.contains("systemd"));
    assert!(notes.contains("nftables"));
    assert!(notes.contains("usage.md"));

    let prerelease = script_output("scripts/generate-release-notes.sh", &["--prerelease"]);
    assert!(succeeded(&prerelease), "{}", stderr(&prerelease));
    assert!(stdout(&prerelease).contains("pre-release"));
}

#[test]
fn the_arch_recipe_checksums_the_github_release_source_archive() {
    let script = fs::read_to_string(repo_root().join("scripts/package-arch.sh")).unwrap();
    assert!(script.contains("/releases/download/v${VERSION}/walden-${VERSION}.tar.gz"));
    assert!(
        !script.contains("/archive/refs/tags/"),
        "the Arch recipe must checksum the published source archive, not GitHub's tag tarball"
    );
}

#[test]
fn ci_cannot_publish_a_release() {
    let ci = fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    assert!(!ci.contains("gh release create"));
    assert!(!ci.contains("contents: write"));
    assert!(ci.contains("pull_request"));
    assert!(ci.contains("branches: [main]"));
    assert!(
        !ci.contains("tags:"),
        "CI must not run as a tag-triggered publisher"
    );
}

#[test]
fn version_tags_are_the_only_release_trigger() {
    let release = fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    assert!(release.contains("tags:"));
    assert!(release.contains("\"v*\""));
    assert!(release.contains("gh release create"));
    assert!(release.contains("contents: write"));
    assert!(release.contains("scripts/verify-release-tag.sh"));
    assert!(release.contains("Refusing to publish a partial release"));
    assert!(release.contains("--prerelease"));
}

fn pinned_action_specs(path: &str) -> Vec<(String, String)> {
    let contents = fs::read_to_string(repo_root().join(path))
        .unwrap_or_else(|err| panic!("failed to read {path}: {err}"));
    let mut specs = Vec::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix("uses:") else {
            continue;
        };
        let spec = rest.trim();
        if spec.starts_with("./") || spec.starts_with(".github/") {
            continue;
        }
        specs.push((
            path.to_string(),
            spec.split_whitespace().next().unwrap_or(spec).to_string(),
        ));
    }
    specs
}

#[test]
fn workflows_pin_third_party_actions_to_commit_shas() {
    let files = [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/actions/setup-rust/action.yml",
    ];
    let mut found = 0;
    for path in files {
        for (file, spec) in pinned_action_specs(path) {
            found += 1;
            let Some((_, pin)) = spec.split_once('@') else {
                panic!("{file} uses {spec} without a pin");
            };
            assert_eq!(
                pin.len(),
                40,
                "{file} pins {spec} to something other than a full commit SHA"
            );
            assert!(
                pin.chars().all(|c| c.is_ascii_hexdigit()),
                "{file} pins {spec} to a non-hex SHA"
            );
        }
    }
    assert!(found > 0, "no third-party actions were found to pin");
}

#[test]
fn package_builders_can_delete_a_read_only_catalog_staging_tree() {
    let common = fs::read_to_string(repo_root().join("scripts/package-common.sh")).unwrap();
    assert!(common.contains("remove_work_tree"));
    assert!(common.contains("chmod -R u+w"));

    for recipe in [
        "scripts/package-macos.sh",
        "scripts/package-deb.sh",
        "scripts/inspect-package.sh",
    ] {
        let contents = fs::read_to_string(repo_root().join(recipe)).unwrap();
        assert!(
            contents.contains("remove_work_tree"),
            "{recipe} still uses rm -rf on a tree that includes mode-0555 catalog directories"
        );
    }
}

#[test]
fn stale_release_binaries_cannot_be_reused_for_a_package() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new("stale-release-build");
    let release = sandbox.root.join("release");
    fs::create_dir_all(&release).unwrap();
    for binary in ["walden", "waldend"] {
        let path = release.join(binary);
        fs::write(&path, "#!/bin/sh\n# WALDEN_BUILD_ID=stale\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let output = Command::new("sh")
        .args([
            "-c",
            ". ./scripts/package-common.sh && require_release_binaries_match_source \"$1\"",
            "scripts/package-common.sh",
        ])
        .arg(&release)
        .current_dir(repo_root())
        .output()
        .unwrap();

    assert!(!succeeded(&output));
    assert!(
        stderr(&output).contains("was not built from the current source"),
        "stdout: {}\nstderr: {}",
        stdout(&output),
        stderr(&output)
    );
}

#[test]
fn the_source_fingerprint_is_deterministic_and_embedded_in_builds() {
    let first = script_output("scripts/source-fingerprint.sh", &[]);
    let second = script_output("scripts/source-fingerprint.sh", &[]);
    assert!(succeeded(&first), "{}", stderr(&first));
    assert_eq!(stdout(&first), stdout(&second));
    let fingerprint_output = stdout(&first);
    let fingerprint = fingerprint_output.trim();
    assert_eq!(fingerprint.len(), 64);
    assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(
        fingerprint,
        walden::build_info::BuildInfo::current().build_id
    );
}

#[test]
fn check_script_covers_formatting_linting_tests_and_documentation() {
    let check = fs::read_to_string(repo_root().join("scripts/check.sh")).unwrap();
    assert!(check.contains("cargo fmt"));
    assert!(check.contains("cargo clippy --locked"));
    assert!(check.contains("cargo test --locked"));
    assert!(check.contains("cargo doc --locked"));
    assert!(check.contains("docs/releasing.md"));
    assert!(check.contains("docs/usage.md"));
    assert!(check.contains("docs/testing.md"));
}

#[test]
fn cargo_package_metadata_is_complete() {
    let cargo = fs::read_to_string(repo_root().join("Cargo.toml")).unwrap();
    for field in ["description", "license", "repository", "rust-version"] {
        assert!(
            cargo.contains(&format!("{field} =")),
            "Cargo.toml does not state {field}"
        );
    }
    assert!(repo_root().join("LICENSE").is_file());

    let common = fs::read_to_string(repo_root().join("scripts/package-common.sh")).unwrap();
    assert!(
        common.contains("rust-version"),
        "package builds do not require Cargo.toml to state a rust-version"
    );

    let toolchain = fs::read_to_string(repo_root().join("rust-toolchain.toml")).unwrap();
    let rust_version = cargo
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("rust-version")
                .map(|rest| rest.trim().trim_start_matches('=').trim().trim_matches('"'))
        })
        .expect("Cargo.toml does not state rust-version");
    assert!(
        toolchain.contains(&format!("channel = \"{rust_version}")),
        "rust-toolchain.toml does not pin the rust-version {rust_version}"
    );
}

#[test]
fn shell_and_rust_agree_on_persisted_state_names() {
    let output = Command::new("sh")
        .args([
            "-c",
            r#". ./packaging/common/persisted-state.sh
walden_persisted_state_file_name "$1"
walden_machine_id"#,
            "sh",
            "test-machine",
        ])
        .current_dir(repo_root())
        .output()
        .expect("failed to source packaging/common/persisted-state.sh");
    assert!(
        succeeded(&output),
        "persisted-state.sh failed: {}",
        stderr(&output)
    );

    let printed = stdout(&output);
    let lines: Vec<&str> = printed.lines().collect();
    assert_eq!(
        lines.first().copied().unwrap_or(""),
        walden::settings::persisted_state_file_name("test-machine")
    );
    assert_eq!(
        lines.get(1).copied().unwrap_or(""),
        walden::settings::machine_id()
    );
}

#[test]
fn uninstallers_delete_this_machine_state_file_rather_than_globbing() {
    for path in [
        "packaging/linux/debian/postrm",
        "packaging/macos/walden-uninstall",
        "scripts/dev-install.sh",
        "packaging/common/persisted-state.sh",
    ] {
        let contents = fs::read_to_string(repo_root().join(path)).unwrap();
        assert!(
            contents.contains("waldend-settings-")
                || contents.contains("packaging/common/persisted-state.sh"),
            "{path} does not hash the daemon's settings-file prefix"
        );
        assert!(
            !contents.contains("\"$STATE_DIR\"/.*") && !contents.contains("\"$SETTINGS_DIR\"/.*"),
            "{path} still globs hidden files to find persisted state"
        );
    }
}

#[test]
fn development_cleanup_refuses_a_package_managed_installation() {
    for path in ["scripts/dev-install.sh", "scripts/clean-rules.sh"] {
        let contents = fs::read_to_string(repo_root().join(path)).unwrap();
        assert!(
            contents.contains("Development-only") || contents.contains("development-only"),
            "{path} is not marked as development-only"
        );
        assert!(
            contents.contains("walden_package_is_installed"),
            "{path} does not detect a package-managed installation"
        );
        assert!(
            contents.contains("--force"),
            "{path} has no explicit override for a package-managed installation"
        );
        assert!(
            !contents.contains("rm -f \"$DAEMON_BINARY\"") || path.contains("dev-install"),
            "{path} deletes the daemon binary without being the install stand-in"
        );
    }

    let clean = fs::read_to_string(repo_root().join("scripts/clean-rules.sh")).unwrap();
    assert!(
        !clean.contains("/usr/local/libexec/waldend") && !clean.contains("/usr/bin/walden"),
        "clean-rules.sh names package-owned binaries"
    );
    assert!(
        clean.contains("does not:") || clean.contains("It does not"),
        "clean-rules.sh does not say what it leaves alone"
    );
}

#[test]
fn packages_and_the_arch_recipe_ship_the_user_guide() {
    let common = fs::read_to_string(repo_root().join("scripts/package-common.sh")).unwrap();
    assert!(common.contains("docs/usage.md"));

    let arch = fs::read_to_string(repo_root().join("packaging/linux/arch/PKGBUILD.in")).unwrap();
    assert!(arch.contains("docs/usage.md"));
}
