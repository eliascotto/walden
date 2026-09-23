// Block lifecycle: persist settings, apply rules, rebuild on drift, tear down
// when the unlock delay expires. What is blocked follows persisted state, not
// whatever happens to be in /etc/hosts or the firewall.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use chrono::{TimeDelta, Utc};

use crate::blocker;
use crate::protocol;
use crate::resolver::{self, ResolvedAddr};
use crate::service;
use crate::settings::{self, Settings};

const TICK: Duration = Duration::from_secs(1);
const INTEGRITY_INTERVAL: Duration = Duration::from_secs(15);
const RESOLUTION_TTL: Duration = Duration::from_secs(15 * 60);

type ResolveAll =
    fn(&[String], &mut dyn FnMut(resolver::ResolveProgress) -> bool) -> BTreeSet<ResolvedAddr>;

fn unlock_delay(secs: u64) -> Option<TimeDelta> {
    TimeDelta::try_seconds(i64::try_from(secs).ok()?)
}

enum PersistedSettings {
    Missing,
    Valid(Settings),
    // Distinct from Missing so corrupt state never reads as unblocked.
    Invalid(String),
}

struct State {
    settings: PersistedSettings,
    resolved: BTreeSet<ResolvedAddr>,
    resolved_at: Option<Instant>,
    save_settings: fn(&Settings) -> anyhow::Result<()>,
    apply_generation: u64,
    apply_progress: Option<protocol::ApplyProgress>,
    retiring: bool,
}

impl State {
    fn valid_settings(&self) -> Option<&Settings> {
        match &self.settings {
            PersistedSettings::Valid(settings) => Some(settings),
            PersistedSettings::Missing | PersistedSettings::Invalid(_) => None,
        }
    }

    fn invalid_settings_reason(&self) -> Option<&str> {
        match &self.settings {
            PersistedSettings::Invalid(reason) => Some(reason),
            PersistedSettings::Missing | PersistedSettings::Valid(_) => None,
        }
    }

    fn running_blocklist(&self) -> Option<Vec<String>> {
        let settings = self.valid_settings()?;

        if !settings.block_is_running {
            return None;
        }

        settings
            .blocklist
            .clone()
            .filter(|block_list| !block_list.is_empty())
    }

    fn recorded_blocklist(&self) -> Option<Vec<String>> {
        let settings = self.valid_settings()?;
        if !settings.block_is_running {
            return None;
        }
        settings.blocklist.clone()
    }

    fn persist(&self) -> anyhow::Result<()> {
        if let Some(settings) = self.valid_settings() {
            (self.save_settings)(settings)?;
        }
        Ok(())
    }

    // Persist before updating memory so a failed write leaves disk and RAM aligned.
    fn persist_replacement(&mut self, settings: Settings) -> anyhow::Result<()> {
        (self.save_settings)(&settings)?;
        self.settings = PersistedSettings::Valid(settings);
        Ok(())
    }

    fn mark_block_finished(&mut self) -> anyhow::Result<()> {
        let Some(mut settings) = self.valid_settings().cloned() else {
            return Ok(());
        };

        settings.block_is_running = false;
        settings.unlock_delay_secs = None;
        // Keep the end time as a durable retirement marker until rules are
        // gone and autostart has been disabled. A restart can then retry.
        settings.blocklist = None;
        settings.rules_applied = false;
        settings.apply_started_at = None;
        settings.apply_error = None;
        settings.operation_id = None;
        self.persist_replacement(settings)?;
        self.apply_generation = self.apply_generation.wrapping_add(1);
        self.apply_progress = None;
        self.retiring = true;
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Teardown {
    stop_blocking: fn() -> anyhow::Result<()>,
    leftovers_present: fn() -> anyhow::Result<bool>,
    retire_daemon: fn() -> anyhow::Result<()>,
}

const SYSTEM_TEARDOWN: Teardown = Teardown {
    stop_blocking: blocker::stop_blocking,
    leftovers_present: blocker::leftovers_present,
    retire_daemon: service::retire_daemon,
};

#[derive(Clone)]
pub struct Lifecycle {
    state: Arc<Mutex<State>>,
    apply_hosts: fn(&[String]) -> anyhow::Result<()>,
    apply_block: fn(&[String], &BTreeSet<ResolvedAddr>) -> anyhow::Result<()>,
    resolve_all: ResolveAll,
    teardown: Teardown,
    apply_in_progress: Arc<AtomicBool>,
    apply_requested: Arc<AtomicBool>,
}

impl Lifecycle {
    pub fn from_disk() -> Self {
        let settings = match settings::load_secure_settings_file() {
            Ok(Some(settings)) => PersistedSettings::Valid(settings),
            Ok(None) => PersistedSettings::Missing,
            Err(err) => {
                let reason = format!("{err:#}");
                eprintln!("walden: persisted settings are invalid; the daemon is locked: {reason}");
                PersistedSettings::Invalid(reason)
            }
        };

        Lifecycle {
            state: Arc::new(Mutex::new(State {
                settings,
                resolved: BTreeSet::new(),
                resolved_at: None,
                save_settings: settings::save_secure_settings_file,
                apply_generation: 0,
                apply_progress: None,
                retiring: false,
            })),
            apply_hosts: blocker::hosts::block,
            apply_block: blocker::apply,
            resolve_all: resolver::resolve_all_with_progress,
            teardown: SYSTEM_TEARDOWN,
            apply_in_progress: Arc::new(AtomicBool::new(false)),
            apply_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    // After poison, keep enforcing rather than stop mid-block.
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn apply_busy(&self) -> bool {
        self.apply_in_progress.load(Ordering::SeqCst) || self.apply_requested.load(Ordering::SeqCst)
    }

    fn generation_cancelled(&self, generation: u64) -> bool {
        self.state().apply_generation != generation
    }

    fn set_apply_progress(&self, generation: u64, progress: protocol::ApplyProgress) -> bool {
        let mut state = self.state();
        if state.apply_generation != generation {
            return false;
        }
        state.apply_progress = Some(progress);
        true
    }

    fn spawn_apply(&self) {
        self.apply_requested.store(true, Ordering::SeqCst);
        if self.apply_in_progress.swap(true, Ordering::SeqCst) {
            return;
        }

        let this = self.clone();
        thread::spawn(move || {
            loop {
                this.apply_requested.store(false, Ordering::SeqCst);
                this.run_apply();
                if this.apply_requested.load(Ordering::SeqCst) {
                    continue;
                }
                this.apply_in_progress.store(false, Ordering::SeqCst);
                if this.apply_requested.load(Ordering::SeqCst)
                    && !this.apply_in_progress.swap(true, Ordering::SeqCst)
                {
                    continue;
                }
                break;
            }
        });
    }

    fn run_apply(&self) {
        let (generation, block_list, already_applied) = {
            let state = self.state();
            let Some(block_list) = state.recorded_blocklist() else {
                return;
            };
            let already_applied = state
                .valid_settings()
                .is_some_and(|settings| settings.rules_applied);
            (state.apply_generation, block_list, already_applied)
        };

        if !self.set_apply_progress(
            generation,
            protocol::ApplyProgress {
                stage: protocol::ApplyStage::WritingHosts,
                completed: 0,
                total: block_list.len(),
                resolved_addresses: 0,
                failed_lookups: 0,
            },
        ) {
            return;
        }

        if let Err(err) = (self.apply_hosts)(&block_list) {
            self.record_apply_error(generation, already_applied, &err);
            return;
        }
        if self.generation_cancelled(generation) {
            return;
        }

        let mut failed_lookups = 0;
        let resolved = (self.resolve_all)(&block_list, &mut |progress| {
            failed_lookups = progress.failed_lookups;
            self.set_apply_progress(
                generation,
                protocol::ApplyProgress {
                    stage: protocol::ApplyStage::Resolving,
                    completed: progress.completed,
                    total: progress.total,
                    resolved_addresses: progress.resolved_addresses,
                    failed_lookups: progress.failed_lookups,
                },
            )
        });
        if self.generation_cancelled(generation) {
            return;
        }

        {
            let mut state = self.state();
            state.resolved = resolved.clone();
            state.resolved_at = Some(Instant::now());
        }

        if !self.set_apply_progress(
            generation,
            protocol::ApplyProgress {
                stage: protocol::ApplyStage::InstallingFirewall,
                completed: resolved.len(),
                total: resolved.len(),
                resolved_addresses: resolved.len(),
                failed_lookups,
            },
        ) {
            return;
        }

        if let Err(err) = (self.apply_block)(&block_list, &resolved) {
            self.record_apply_error(generation, already_applied, &err);
            return;
        }
        if self.generation_cancelled(generation) {
            return;
        }

        self.mark_rules_applied(generation);
    }

    fn record_apply_error(&self, generation: u64, already_applied: bool, err: &anyhow::Error) {
        eprintln!("walden: failed to apply blocking rules: {err:#}");
        if already_applied {
            return;
        }

        let mut state = self.state();
        if state.apply_generation != generation {
            return;
        }
        let Some(mut settings) = state.valid_settings().cloned() else {
            return;
        };
        if !settings.block_is_running {
            return;
        }
        settings.apply_error = Some(format!("{err:#}"));
        if let Err(persist_err) = state.persist_replacement(settings) {
            eprintln!("walden: failed to record the apply error: {persist_err:#}");
        }
    }

    fn mark_rules_applied(&self, generation: u64) {
        let mut state = self.state();
        if state.apply_generation != generation {
            return;
        }
        let Some(mut settings) = state.valid_settings().cloned() else {
            return;
        };
        if !settings.block_is_running {
            return;
        }
        settings.rules_applied = true;
        settings.apply_error = None;
        if let Err(err) = state.persist_replacement(settings) {
            eprintln!("walden: failed to record that rules were applied: {err:#}");
        } else {
            state.apply_progress = None;
        }
    }

    pub fn resume(&self) {
        let state = self.state();

        if let Some(reason) = state.invalid_settings_reason() {
            eprintln!(
                "walden: cannot trust the persisted block state; leaving any installed rules in place: {reason}"
            );
            return;
        }

        let is_inactive = state
            .valid_settings()
            .is_some_and(|settings| !settings.block_is_running);
        let pending_retirement = state
            .valid_settings()
            .is_some_and(|settings| !settings.block_is_running && settings.block_end_at.is_some());
        let has_settings = state.valid_settings().is_some();
        let should_apply = state.running_blocklist().is_some()
            && !state.valid_settings().is_some_and(|settings| {
                settings
                    .block_end_at
                    .is_some_and(|block_end_at| Utc::now() >= block_end_at)
            });
        drop(state);

        if should_apply {
            self.spawn_apply();
            return;
        }

        // An expired block is handled by the main loop without first
        // re-applying rules. An inactive block may have interrupted cleanup.
        if is_inactive {
            if pending_retirement {
                self.state().retiring = true;
                return;
            }
            match (self.teardown.leftovers_present)() {
                Ok(false) => {}
                Ok(true) => self.state().retiring = true,
                Err(err) => {
                    eprintln!("walden: could not verify cleanup: {err:#}");
                    self.state().retiring = true;
                }
            }
            return;
        }

        if has_settings {
            return;
        }

        // No settings: leave installed rules alone; we cannot know what they were for.
        if blocker::leftovers_present().unwrap_or(false) {
            eprintln!(
                "walden: block rules are installed but the settings file is missing, leaving them in place"
            );
        }
    }

    pub fn start(
        &self,
        operation_id: String,
        block_list: Vec<String>,
        unlock_delay_secs: u64,
    ) -> anyhow::Result<String> {
        if operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("the start operation ID is invalid");
        }

        let mut state = self.state();

        if let Some(reason) = state.invalid_settings_reason() {
            bail!("persisted settings are invalid; refusing to overwrite locked state: {reason}");
        }

        if state.retiring {
            bail!("the previous block is still being cleaned up; retry start shortly");
        }

        if let Some(settings) = state.valid_settings()
            && settings.block_is_running
        {
            // The privileged CLI can lose its response after this state was
            // durably written.  Retrying the same request must report the
            // existing operation, never create a second immutable block or
            // turn a successful acceptance into a spurious failure.
            let same_operation = settings.operation_id.as_deref() == Some(&operation_id);
            if !same_operation {
                if !settings.rules_applied {
                    bail!("a different block is still being applied");
                }
                bail!("a different block is already running");
            }
            if settings.blocklist.as_ref() != Some(&block_list)
                || settings.unlock_delay_secs != Some(unlock_delay_secs)
            {
                bail!("the start operation ID was reused with different block settings");
            }

            let retry_failed_apply = !settings.rules_applied && settings.apply_error.is_some();
            drop(state);
            if retry_failed_apply {
                self.spawn_apply();
            }
            return Ok(operation_id);
        }

        // Reject out-of-range delays now; at stop time it would be unfixable.
        if unlock_delay(unlock_delay_secs).is_none() {
            bail!("an unlock delay of {unlock_delay_secs} seconds is out of range");
        }

        state.apply_generation = state.apply_generation.wrapping_add(1);
        let initial_progress = protocol::ApplyProgress {
            stage: protocol::ApplyStage::WritingHosts,
            completed: 0,
            total: block_list.len(),
            resolved_addresses: 0,
            failed_lookups: 0,
        };
        let settings = Settings::applying(operation_id.clone(), block_list, unlock_delay_secs);

        // Persist before applying rules so a crash mid-apply can resume and rebuild.
        // The unlock delay is not locked in until rules_applied becomes true.
        (state.save_settings)(&settings)?;
        state.settings = PersistedSettings::Valid(settings);
        state.apply_progress = Some(initial_progress);
        drop(state);

        self.spawn_apply();
        Ok(operation_id)
    }

    // Records an end time; the main loop tears down once that time is reached.
    // Repeated stops cannot shorten, cancel, or restart the wait once the block
    // is active. A stop while rules are still being applied cancels the start.
    pub fn stop(&self) -> anyhow::Result<protocol::StopOutcome> {
        let mut state = self.state();

        if let Some(reason) = state.invalid_settings_reason() {
            bail!("persisted settings are invalid; refusing to change locked state: {reason}");
        }

        let (is_running, rules_applied, unlock_delay_secs, block_end_at) =
            match state.valid_settings() {
                Some(settings) => (
                    settings.block_is_running,
                    settings.rules_applied,
                    settings.unlock_delay_secs,
                    settings.block_end_at,
                ),
                None => return Ok(protocol::StopOutcome::AlreadyInactive),
            };

        if !is_running {
            return Ok(protocol::StopOutcome::AlreadyInactive);
        }

        if let Some(block_end_at) = block_end_at {
            return Ok(protocol::StopOutcome::AlreadyEnding { block_end_at });
        }

        let apply_cancelled = !rules_applied;
        let block_end_at = if apply_cancelled {
            state.apply_generation = state.apply_generation.wrapping_add(1);
            state.apply_progress = None;
            eprintln!("walden: apply cancelled before the block was locked in");
            Utc::now()
        } else {
            match unlock_delay_secs {
                Some(unlock_delay_secs) => {
                    let Some(block_end_at) = unlock_delay(unlock_delay_secs)
                        .and_then(|delay| Utc::now().checked_add_signed(delay))
                    else {
                        bail!(
                            "the saved unlock delay cannot be counted from now; the block continues"
                        );
                    };

                    block_end_at
                }

                None => {
                    // Route through normal teardown rather than a special case.
                    eprintln!("walden: no unlock delay was recorded; ending immediately");
                    Utc::now()
                }
            }
        };

        // Persist before returning so a restart can still complete the same teardown.
        let mut updated = state
            .valid_settings()
            .cloned()
            .context("the running block state disappeared")?;
        updated.block_end_at = Some(block_end_at);
        state
            .persist_replacement(updated)
            .context("failed to durably save the stop request")?;

        eprintln!("walden: the block will end at {block_end_at}");
        if apply_cancelled {
            Ok(protocol::StopOutcome::ApplyCancelled)
        } else {
            Ok(protocol::StopOutcome::Ending { block_end_at })
        }
    }

    pub fn status(&self) -> protocol::StatusResponse {
        let state = self.state();

        match &state.settings {
            PersistedSettings::Valid(settings) => protocol::StatusResponse {
                operation_id: settings.operation_id.clone(),
                block_is_running: settings.block_is_running,
                unlock_delay_secs: settings.unlock_delay_secs,
                block_end_at: settings.block_end_at,
                block_phase: settings.phase(),
                website_count: settings.website_count(),
                apply_started_at: settings.apply_started_at,
                apply_error: settings.apply_error.clone(),
                apply_progress: state.apply_progress.clone(),
            },
            PersistedSettings::Invalid(_) => protocol::StatusResponse {
                operation_id: None,
                // Fail closed: never report a clean, unblocked machine.
                block_is_running: true,
                unlock_delay_secs: None,
                block_end_at: None,
                block_phase: protocol::BlockPhase::Active,
                website_count: None,
                apply_started_at: None,
                apply_error: None,
                apply_progress: None,
            },
            PersistedSettings::Missing => protocol::StatusResponse::inactive(),
        }
    }

    fn check_expiry(&self) -> bool {
        self.state().valid_settings().is_some_and(|settings| {
            settings.block_is_running
                && settings
                    .block_end_at
                    .is_some_and(|block_end_at| Utc::now() >= block_end_at)
        })
    }

    fn check_integrity(&self) {
        if self.apply_busy() {
            return;
        }

        let state = self.state();

        let Some(block_list) = state.running_blocklist() else {
            return;
        };

        // Deleting the settings file is another early-unblock route; write it back.
        if !settings::secure_settings_file_exists() {
            eprintln!("walden: the settings file is missing, writing it back");
            if let Err(err) = state.persist() {
                eprintln!("walden: failed to restore the settings file: {err:#}");
            }
        }

        let rules_applied = state
            .valid_settings()
            .is_some_and(|settings| settings.rules_applied);
        let cache_fresh = state
            .resolved_at
            .is_some_and(|resolved_at| resolved_at.elapsed() < RESOLUTION_TTL);
        let resolved = cache_fresh.then(|| state.resolved.clone());
        drop(state);

        if !rules_applied {
            self.spawn_apply();
            return;
        }

        match resolved {
            Some(resolved) if blocker::is_intact(&block_list, &resolved) => {}
            _ => {
                eprintln!(
                    "walden: block rules have drifted, rebuilding them from the saved block list"
                );
                self.spawn_apply();
            }
        }
    }

    // Retries on failure: a half-removed block with no daemon watching is worse than either alone.
    fn complete_teardown(&self) -> bool {
        if let Err(err) = (self.teardown.stop_blocking)() {
            eprintln!("walden: failed to remove blocking rules: {err:#}");
        }

        match (self.teardown.leftovers_present)() {
            Ok(false) => match (self.teardown.retire_daemon)() {
                Ok(()) => {
                    let mut state = self.state();
                    if let Some(mut settings) = state.valid_settings().cloned()
                        && !settings.block_is_running
                        && settings.block_end_at.is_some()
                    {
                        settings.block_end_at = None;
                        if let Err(err) = state.persist_replacement(settings) {
                            eprintln!("walden: failed to finish the retirement record: {err:#}");
                            return false;
                        }
                    }
                    true
                }
                Err(err) => {
                    eprintln!("walden: daemon retirement failed: {err:#}");
                    false
                }
            },
            Ok(true) => {
                eprintln!("walden: cleanup incomplete; retrying");
                false
            }
            Err(err) => {
                eprintln!("walden: could not verify cleanup: {err:#}");
                false
            }
        }
    }
}

pub fn run(lifecycle: &Lifecycle) -> ! {
    let mut next_integrity_check = Instant::now() + INTEGRITY_INTERVAL;

    loop {
        if lifecycle.check_expiry() {
            match lifecycle.state().mark_block_finished() {
                Ok(()) => {}
                Err(err) => {
                    eprintln!("walden: failed to persist the completed block: {err:#}");
                }
            }
        }

        if lifecycle.state().retiring {
            if lifecycle.apply_busy() {
                thread::sleep(TICK);
                continue;
            }

            if lifecycle.complete_teardown() {
                std::process::exit(0);
            }

            thread::sleep(TICK);
            continue;
        }

        if Instant::now() >= next_integrity_check {
            lifecycle.check_integrity();
            next_integrity_check = Instant::now() + INTEGRITY_INTERVAL;
        }

        thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn save_ok(_: &Settings) -> anyhow::Result<()> {
        Ok(())
    }

    fn save_fails(_: &Settings) -> anyhow::Result<()> {
        bail!("injected persistence failure")
    }

    fn hosts_ok(_: &[String]) -> anyhow::Result<()> {
        Ok(())
    }

    fn apply_ok(_: &[String], _: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
        Ok(())
    }

    fn resolve_all(
        hosts: &[String],
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
    ) -> BTreeSet<ResolvedAddr> {
        resolver::resolve_all_with_progress(hosts, progress)
    }

    fn apply_fails(_: &[String], _: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
        bail!("injected backend failure")
    }

    fn apply_sleeps(_: &[String], _: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
        thread::sleep(Duration::from_millis(300));
        Ok(())
    }

    fn resolve_slowly(
        hosts: &[String],
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
    ) -> BTreeSet<ResolvedAddr> {
        let total = hosts.len();
        if !progress(resolver::ResolveProgress {
            completed: 0,
            total,
            resolved_addresses: 0,
            failed_lookups: 0,
        }) {
            return BTreeSet::new();
        }
        for completed in 1..=total {
            thread::sleep(Duration::from_millis(5));
            if !progress(resolver::ResolveProgress {
                completed,
                total,
                resolved_addresses: completed,
                failed_lookups: 0,
            }) {
                break;
            }
        }
        BTreeSet::new()
    }

    fn unblock_ok() -> anyhow::Result<()> {
        Ok(())
    }

    fn nothing_left() -> anyhow::Result<bool> {
        Ok(false)
    }

    fn lifecycle_with_settings(settings: PersistedSettings) -> Lifecycle {
        lifecycle_with_dependencies(settings, save_ok, apply_ok)
    }

    fn lifecycle_with_dependencies(
        settings: PersistedSettings,
        save_settings: fn(&Settings) -> anyhow::Result<()>,
        apply_block: fn(&[String], &BTreeSet<ResolvedAddr>) -> anyhow::Result<()>,
    ) -> Lifecycle {
        lifecycle_with_teardown(
            settings,
            save_settings,
            apply_block,
            Teardown {
                stop_blocking: unblock_ok,
                leftovers_present: nothing_left,
                retire_daemon: || Ok(()),
            },
        )
    }

    fn lifecycle_with_teardown(
        settings: PersistedSettings,
        save_settings: fn(&Settings) -> anyhow::Result<()>,
        apply_block: fn(&[String], &BTreeSet<ResolvedAddr>) -> anyhow::Result<()>,
        teardown: Teardown,
    ) -> Lifecycle {
        Lifecycle {
            state: Arc::new(Mutex::new(State {
                settings,
                resolved: BTreeSet::new(),
                resolved_at: None,
                save_settings,
                apply_generation: 0,
                apply_progress: None,
                retiring: false,
            })),
            apply_hosts: hosts_ok,
            apply_block,
            resolve_all,
            teardown,
            apply_in_progress: Arc::new(AtomicBool::new(false)),
            apply_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    fn retiring_lifecycle(
        leftovers_present: fn() -> anyhow::Result<bool>,
        retire_daemon: fn() -> anyhow::Result<()>,
    ) -> Lifecycle {
        lifecycle_with_teardown(
            PersistedSettings::Valid(running_settings()),
            save_ok,
            apply_ok,
            Teardown {
                stop_blocking: unblock_ok,
                leftovers_present,
                retire_daemon,
            },
        )
    }

    fn running_settings() -> Settings {
        Settings {
            unlock_delay_secs: Some(60),
            block_end_at: None,
            blocklist: Some(vec!["example.com".to_string()]),
            block_is_running: true,
            version: settings::SETTINGS_VERSION,
            last_update: Utc::now(),
            rules_applied: true,
            apply_started_at: Some(Utc::now()),
            apply_error: None,
            operation_id: Some("running-operation".to_string()),
        }
    }

    fn wait_for_apply(lifecycle: &Lifecycle) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while lifecycle.apply_busy() {
            assert!(
                Instant::now() < deadline,
                "background apply did not finish in time"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn invalid_settings_are_locked_and_never_report_unblocked() {
        let lifecycle = lifecycle_with_settings(PersistedSettings::Invalid(
            "unsupported settings version".to_string(),
        ));

        let status = lifecycle.status();
        assert!(status.block_is_running);
        assert_eq!(status.block_phase, protocol::BlockPhase::Active);
        assert_eq!(status.unlock_delay_secs, None);
        assert_eq!(status.block_end_at, None);
        assert!(!lifecycle.check_expiry());

        assert!(
            lifecycle
                .start(
                    "operation-1".to_string(),
                    vec!["example.com".to_string()],
                    60
                )
                .unwrap_err()
                .to_string()
                .contains("refusing to overwrite locked state")
        );
        assert!(
            lifecycle
                .stop()
                .unwrap_err()
                .to_string()
                .contains("refusing to change locked state")
        );
    }

    #[test]
    fn missing_settings_remain_distinct_from_invalid_settings() {
        let lifecycle = lifecycle_with_settings(PersistedSettings::Missing);

        assert!(!lifecycle.status().block_is_running);
        assert_eq!(
            lifecycle.status().block_phase,
            protocol::BlockPhase::Inactive
        );
        assert!(lifecycle.stop().is_ok());
    }

    #[test]
    fn start_returns_before_rules_are_applied() {
        let lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, apply_sleeps);

        lifecycle
            .start("operation-1".to_string(), vec!["127.0.0.1".to_string()], 60)
            .unwrap();

        let status = lifecycle.status();
        assert!(status.block_is_running);
        assert_eq!(status.block_phase, protocol::BlockPhase::Applying);
        assert_eq!(status.website_count, Some(1));
        assert!(status.apply_started_at.is_some());
        assert!(status.apply_progress.is_some());

        wait_for_apply(&lifecycle);
        assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Active);
    }

    #[test]
    fn failed_initial_apply_is_recorded_for_repair() {
        let lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, apply_fails);

        lifecycle
            .start("operation-1".to_string(), Vec::new(), 60)
            .unwrap();
        wait_for_apply(&lifecycle);

        let status = lifecycle.status();
        assert!(status.block_is_running);
        assert_eq!(status.block_phase, protocol::BlockPhase::ApplyFailed);
        assert_eq!(status.unlock_delay_secs, Some(60));
        assert_eq!(status.block_end_at, None);
        assert!(
            status
                .apply_error
                .as_deref()
                .is_some_and(|err| err.contains("injected backend failure"))
        );
    }

    #[test]
    fn retrying_the_same_start_joins_the_existing_apply() {
        let lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, apply_sleeps);

        lifecycle
            .start("operation-1".to_string(), vec!["127.0.0.1".to_string()], 60)
            .unwrap();
        lifecycle
            .start("operation-1".to_string(), vec!["127.0.0.1".to_string()], 60)
            .unwrap();
        assert_eq!(
            lifecycle.status().block_phase,
            protocol::BlockPhase::Applying
        );

        let err = lifecycle
            .start("operation-2".to_string(), vec!["10.0.0.1".to_string()], 60)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("a different block is still being applied")
        );
        wait_for_apply(&lifecycle);
    }

    #[test]
    fn operation_id_not_payload_shape_defines_a_start_retry() {
        let lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, apply_sleeps);
        let blocklist = vec!["127.0.0.1".to_string()];

        lifecycle
            .start("operation-1".to_string(), blocklist.clone(), 60)
            .unwrap();
        let different_id = lifecycle
            .start("operation-2".to_string(), blocklist.clone(), 60)
            .unwrap_err();
        assert!(different_id.to_string().contains("different block"));

        let reused_id = lifecycle
            .start("operation-1".to_string(), blocklist, 120)
            .unwrap_err();
        assert!(reused_id.to_string().contains("reused with different"));
        assert_eq!(
            lifecycle.status().operation_id.as_deref(),
            Some("operation-1")
        );
        wait_for_apply(&lifecycle);
    }

    #[test]
    fn stop_reports_inactive_and_already_ending_without_guesswork() {
        let inactive = lifecycle_with_settings(PersistedSettings::Missing);
        assert_eq!(
            inactive.stop().unwrap(),
            protocol::StopOutcome::AlreadyInactive
        );

        let mut settings = running_settings();
        let end = Utc::now() + TimeDelta::seconds(60);
        settings.block_end_at = Some(end);
        let ending = lifecycle_with_settings(PersistedSettings::Valid(settings));
        assert_eq!(
            ending.stop().unwrap(),
            protocol::StopOutcome::AlreadyEnding { block_end_at: end }
        );
    }

    #[test]
    fn stop_during_apply_cancels_without_waiting_for_the_delay() {
        let lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, apply_sleeps);

        lifecycle
            .start("operation-1".to_string(), vec!["127.0.0.1".to_string()], 60)
            .unwrap();
        assert_eq!(
            lifecycle.stop().unwrap(),
            protocol::StopOutcome::ApplyCancelled
        );

        let end_at = lifecycle
            .status()
            .block_end_at
            .expect("stop should set an end time");
        let remaining = (end_at - Utc::now()).num_seconds();
        assert!(
            remaining <= 1,
            "cancelling an unapplied block should not start the unlock delay, remaining={remaining}"
        );
        assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Ending);

        wait_for_apply(&lifecycle);
    }

    #[test]
    fn status_and_stop_remain_responsive_during_large_resolution() {
        let mut lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, apply_ok);
        lifecycle.resolve_all = resolve_slowly;
        let blocklist = (0..50_000)
            .map(|index| format!("host-{index}.example"))
            .collect();

        lifecycle
            .start("operation-1".to_string(), blocklist, 60)
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let status = lifecycle.status();
            if status.apply_progress.as_ref().is_some_and(|progress| {
                progress.stage == protocol::ApplyStage::Resolving && progress.completed > 0
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "resolution never reported progress"
            );
            thread::sleep(Duration::from_millis(5));
        }

        let status_started = Instant::now();
        for _ in 0..100 {
            assert_eq!(
                lifecycle.status().block_phase,
                protocol::BlockPhase::Applying
            );
        }
        assert!(status_started.elapsed() < Duration::from_millis(500));

        let stop_started = Instant::now();
        assert_eq!(
            lifecycle.stop().unwrap(),
            protocol::StopOutcome::ApplyCancelled
        );
        assert!(stop_started.elapsed() < Duration::from_millis(500));
        wait_for_apply(&lifecycle);
    }

    #[test]
    fn failed_stop_persistence_is_rejected_without_changing_memory() {
        let lifecycle = lifecycle_with_dependencies(
            PersistedSettings::Valid(running_settings()),
            save_fails,
            apply_ok,
        );

        let err = lifecycle.stop().unwrap_err();

        assert!(format!("{err:#}").contains("failed to durably save the stop request"));
        assert!(format!("{err:#}").contains("injected persistence failure"));
        assert_eq!(lifecycle.status().block_end_at, None);
    }

    #[test]
    fn successful_stop_is_committed_to_memory_after_persistence() {
        let lifecycle = lifecycle_with_settings(PersistedSettings::Valid(running_settings()));

        assert!(matches!(
            lifecycle.stop().unwrap(),
            protocol::StopOutcome::Ending { .. }
        ));

        assert!(lifecycle.status().block_end_at.is_some());
        let remaining = (lifecycle.status().block_end_at.unwrap() - Utc::now()).num_seconds();
        assert!(
            remaining >= 50,
            "an active block must keep its unlock delay"
        );
    }

    #[test]
    fn failed_finished_state_persistence_keeps_the_block_running() {
        let mut settings = running_settings();
        settings.block_end_at = Some(Utc::now());
        let lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Valid(settings), save_fails, apply_ok);

        let err = lifecycle.state().mark_block_finished().unwrap_err();

        assert!(format!("{err:#}").contains("injected persistence failure"));
        assert!(lifecycle.status().block_is_running);
        assert!(lifecycle.status().block_end_at.is_some());
    }

    #[test]
    fn a_new_start_cannot_race_with_retirement() {
        let mut settings = running_settings();
        settings.block_end_at = Some(Utc::now());
        let lifecycle = lifecycle_with_settings(PersistedSettings::Valid(settings));

        lifecycle.state().mark_block_finished().unwrap();

        assert!(lifecycle.state().retiring);
        assert!(lifecycle.status().block_end_at.is_some());
        let err = lifecycle
            .start(
                "next-operation".to_string(),
                vec!["example.org".to_string()],
                60,
            )
            .unwrap_err();
        assert!(err.to_string().contains("still being cleaned up"));
        assert!(!lifecycle.status().block_is_running);
    }

    #[test]
    fn interrupted_retirement_is_retried_after_restart() {
        static CLEANUP_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

        fn cleanup() -> anyhow::Result<()> {
            if CLEANUP_ATTEMPTS.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("injected cleanup failure");
            }
            Ok(())
        }

        fn leftovers() -> anyhow::Result<bool> {
            Ok(CLEANUP_ATTEMPTS.load(Ordering::SeqCst) < 2)
        }

        CLEANUP_ATTEMPTS.store(0, Ordering::SeqCst);
        let mut settings = running_settings();
        settings.block_is_running = false;
        settings.block_end_at = Some(Utc::now());
        let lifecycle = lifecycle_with_teardown(
            PersistedSettings::Valid(settings),
            save_ok,
            apply_ok,
            Teardown {
                stop_blocking: cleanup,
                leftovers_present: leftovers,
                retire_daemon: || Ok(()),
            },
        );

        lifecycle.resume();
        assert!(lifecycle.state().retiring);
        assert!(!lifecycle.complete_teardown());
        assert!(lifecycle.complete_teardown());
        assert_eq!(CLEANUP_ATTEMPTS.load(Ordering::SeqCst), 2);
        assert_eq!(lifecycle.status().block_end_at, None);
    }

    #[test]
    fn retirement_marker_is_retried_even_after_rules_are_gone() {
        let mut settings = running_settings();
        settings.block_is_running = false;
        settings.block_end_at = Some(Utc::now());
        let lifecycle = lifecycle_with_settings(PersistedSettings::Valid(settings));

        lifecycle.resume();

        assert!(lifecycle.state().retiring);
        assert!(lifecycle.complete_teardown());
        assert_eq!(lifecycle.status().block_end_at, None);
    }

    #[test]
    fn a_completed_retirement_allows_the_next_start() {
        let mut settings = running_settings();
        settings.block_is_running = false;
        settings.block_end_at = None;
        let lifecycle = lifecycle_with_settings(PersistedSettings::Valid(settings));

        lifecycle.resume();

        assert!(!lifecycle.state().retiring);
        lifecycle
            .start("next-operation".to_string(), Vec::new(), 60)
            .unwrap();
        wait_for_apply(&lifecycle);
    }

    #[test]
    fn an_expired_block_is_not_reapplied_during_resume() {
        let mut settings = running_settings();
        settings.block_end_at = Some(Utc::now() - TimeDelta::seconds(1));
        let lifecycle = lifecycle_with_settings(PersistedSettings::Valid(settings));

        lifecycle.resume();

        assert!(!lifecycle.apply_busy());
    }

    #[test]
    fn a_daemon_is_not_retired_while_part_of_the_block_is_still_installed() {
        static RETIREMENTS: AtomicUsize = AtomicUsize::new(0);

        fn something_left() -> anyhow::Result<bool> {
            Ok(true)
        }

        fn retire() -> anyhow::Result<()> {
            RETIREMENTS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        let lifecycle = retiring_lifecycle(something_left, retire);

        assert!(!lifecycle.complete_teardown());
        assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_daemon_is_not_retired_when_the_cleanup_cannot_be_verified() {
        static RETIREMENTS: AtomicUsize = AtomicUsize::new(0);

        fn unverifiable() -> anyhow::Result<bool> {
            bail!("injected verification failure")
        }

        fn retire() -> anyhow::Result<()> {
            RETIREMENTS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        let lifecycle = retiring_lifecycle(unverifiable, retire);

        assert!(!lifecycle.complete_teardown());
        assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn teardown_is_complete_once_the_service_has_been_handed_back() {
        static RETIREMENTS: AtomicUsize = AtomicUsize::new(0);

        fn retire() -> anyhow::Result<()> {
            RETIREMENTS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        let lifecycle = retiring_lifecycle(nothing_left, retire);

        assert!(lifecycle.complete_teardown());
        assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_failed_retirement_is_safe_to_retry() {
        static RETIREMENTS: AtomicUsize = AtomicUsize::new(0);

        fn retire_fails() -> anyhow::Result<()> {
            RETIREMENTS.fetch_add(1, Ordering::SeqCst);
            bail!("injected retirement failure")
        }

        let lifecycle = retiring_lifecycle(nothing_left, retire_fails);

        assert!(!lifecycle.complete_teardown());
        assert!(!lifecycle.complete_teardown());
        assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 2);
    }
}
