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

type ResolveAll = fn(
    &[String],
    &mut resolver::ResolutionCache,
    &mut dyn FnMut(resolver::ResolveProgress) -> bool,
) -> BTreeSet<ResolvedAddr>;

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
    resolved: Option<BTreeSet<ResolvedAddr>>,
    resolved_at: Option<Instant>,
    save_settings: fn(&Settings) -> anyhow::Result<()>,
    apply_generation: u64,
    apply_progress: Option<protocol::ApplyProgress>,
    retiring: bool,
    cleanup: Option<protocol::CleanupProgress>,
    dns_cache: resolver::ResolutionCache,
    candidate: Option<DnsCandidate>,
    last_apply_failure: Option<protocol::ApplyFailure>,
    apply_attempts: u64,
    apply_retry_at: Option<chrono::DateTime<Utc>>,
    apply_retry_delay_secs: u64,
}

#[derive(Clone)]
struct DnsCandidate {
    addresses: BTreeSet<ResolvedAddr>,
    progress: protocol::ApplyProgress,
    expires: Instant,
}

impl State {
    fn begin_cleanup(&mut self) {
        self.retiring = true;
        self.cleanup
            .get_or_insert_with(protocol::CleanupProgress::new);
    }

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
        self.candidate = None;
        self.dns_cache = resolver::ResolutionCache::default();
        self.last_apply_failure = None;
        self.apply_retry_at = None;
        self.apply_retry_delay_secs = 5;
        self.begin_cleanup();
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Teardown {
    stop_blocking: fn() -> anyhow::Result<()>,
    leftovers_present: fn() -> anyhow::Result<Vec<String>>,
    retire_daemon: fn() -> anyhow::Result<()>,
}

const SYSTEM_TEARDOWN: Teardown = Teardown {
    stop_blocking: blocker::stop_blocking,
    leftovers_present: blocker::cleanup_leftovers,
    retire_daemon: service::retire_daemon,
};

#[derive(Clone)]
pub struct Lifecycle {
    state: Arc<Mutex<State>>,
    apply_hosts: fn(&[String]) -> anyhow::Result<()>,
    apply_block: fn(&[String], &BTreeSet<ResolvedAddr>) -> anyhow::Result<()>,
    prepare_firewall: fn() -> anyhow::Result<()>,
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
                crate::daemon_log!(
                    "walden: persisted settings are invalid; the daemon is locked: {reason}"
                );
                PersistedSettings::Invalid(reason)
            }
        };

        Lifecycle {
            state: Arc::new(Mutex::new(State {
                settings,
                resolved: None,
                resolved_at: None,
                save_settings: settings::save_secure_settings_file,
                apply_generation: 0,
                apply_progress: None,
                retiring: false,
                cleanup: None,
                dns_cache: resolver::ResolutionCache::default(),
                candidate: None,
                apply_retry_delay_secs: 5,
                last_apply_failure: None,
                apply_attempts: 0,
                apply_retry_at: None,
            })),
            apply_hosts: blocker::hosts::block,
            apply_block: blocker::apply,
            prepare_firewall: blocker::prepare,
            resolve_all: resolver::resolve_cached,
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

        {
            let mut state = self.state();
            if state.apply_generation != generation {
                return;
            }
            state.apply_attempts = state.apply_attempts.saturating_add(1);
            state.apply_retry_at = None;
        }

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

        if !already_applied {
            if !self.set_apply_progress(
                generation,
                protocol::ApplyProgress {
                    stage: protocol::ApplyStage::PreparingFirewall,
                    completed: 0,
                    total: block_list.len(),
                    resolved_addresses: 0,
                    failed_lookups: 0,
                },
            ) {
                return;
            }
            if let Err(err) = (self.prepare_firewall)() {
                self.record_apply_error(generation, already_applied, &err);
                return;
            }
        }

        let candidate = if already_applied {
            None
        } else {
            self.state()
                .candidate
                .clone()
                .filter(|candidate| candidate.expires > Instant::now())
        };

        let mut failed_lookups = 0;
        let resolved = if let Some(candidate) = candidate {
            failed_lookups = candidate.progress.failed_lookups;
            let mut progress = candidate.progress;
            progress.stage = protocol::ApplyStage::PreparingFirewall;
            if !self.set_apply_progress(generation, progress) {
                return;
            }
            candidate.addresses
        } else {
            let mut cache = std::mem::take(&mut self.state().dns_cache);
            let resolved = (self.resolve_all)(&block_list, &mut cache, &mut |progress| {
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
            let mut state = self.state();
            if state.apply_generation != generation {
                return;
            }
            let expires = cache.next_refresh().unwrap_or(
                Instant::now()
                    + if failed_lookups > 0 {
                        Duration::from_secs(30)
                    } else {
                        RESOLUTION_TTL
                    },
            );
            state.dns_cache = cache;
            if let Some(progress) = state.apply_progress.clone() {
                state.candidate = Some(DnsCandidate {
                    addresses: resolved.clone(),
                    progress,
                    expires,
                });
            }
            resolved
        };
        if self.generation_cancelled(generation) {
            return;
        }

        let resolved = {
            let mut state = self.state();
            if state.apply_generation != generation {
                return;
            }
            if failed_lookups > 0 && (already_applied || state.resolved.is_some()) {
                // Keep working coverage while adding any new DNS answers.
                // Leave the cache stale so the next integrity check retries DNS.
                state.resolved_at = None;
                crate::daemon_log!(
                    "walden: DNS refresh failed for {failed_lookups} hostnames; keeping previous firewall coverage and retrying at the next integrity check"
                );
                let Some(mut retained) = state.resolved.clone() else {
                    // Without cached addresses, leave installed rules untouched
                    // until DNS can provide a complete replacement.
                    state.apply_progress = None;
                    return;
                };
                retained.extend(resolved);
                retained
            } else {
                resolved
            }
        };

        let mut progress = self
            .state()
            .apply_progress
            .clone()
            .unwrap_or(protocol::ApplyProgress {
                stage: protocol::ApplyStage::Resolving,
                completed: 0,
                total: 0,
                resolved_addresses: 0,
                failed_lookups,
            });
        progress.stage = protocol::ApplyStage::InstallingFirewall;
        progress.resolved_addresses = resolved.len();
        if !self.set_apply_progress(generation, progress) {
            return;
        }

        if let Err(err) = (self.apply_block)(&block_list, &resolved) {
            self.record_apply_error(generation, already_applied, &err);
            return;
        }
        if self.generation_cancelled(generation) {
            return;
        }

        {
            let mut state = self.state();
            if state.apply_generation != generation {
                return;
            }
            // Only cache addresses that were successfully installed. A first
            // apply may use partial DNS results, but must retry them promptly.
            state.resolved = Some(resolved);
            state.resolved_at = (failed_lookups == 0).then(Instant::now);
        }

        self.mark_rules_applied(generation);
    }

    fn record_apply_error(&self, generation: u64, already_applied: bool, err: &anyhow::Error) {
        crate::daemon_log!("walden: failed to apply blocking rules: {err:#}");
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
        let requires_action = blocker::requires_action(err);
        state.last_apply_failure = Some(protocol::ApplyFailure {
            stage: state
                .apply_progress
                .as_ref()
                .map_or(protocol::ApplyStage::WritingHosts, |progress| {
                    progress.stage
                }),
            message: format!("{err:#}"),
            failed_at: Utc::now(),
            attempt: state.apply_attempts,
            requires_action,
        });
        let retry_delay = state.apply_retry_delay_secs;
        state.apply_retry_at =
            (!requires_action).then(|| Utc::now() + TimeDelta::seconds(retry_delay as i64));
        state.apply_retry_delay_secs = retry_delay.saturating_mul(2).min(300);
        if already_applied {
            return;
        }
        settings.apply_error = Some(format!("{err:#}"));
        if let Err(persist_err) = state.persist_replacement(settings) {
            crate::daemon_log!("walden: failed to record the apply error: {persist_err:#}");
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
        let already_applied = settings.rules_applied;
        if let Some(progress) = &mut state.apply_progress {
            progress.stage = protocol::ApplyStage::SavingState;
        }
        settings.rules_applied = true;
        settings.apply_error = None;
        let saved = state.persist_replacement(settings);
        if saved.is_ok() {
            state.apply_progress = None;
            state.last_apply_failure = None;
            state.apply_retry_at = None;
            state.apply_retry_delay_secs = 5;
        }
        drop(state);
        if let Err(err) = saved {
            self.record_apply_error(
                generation,
                already_applied,
                &err.context("failed to durably record activation"),
            );
        }
    }

    pub fn resume(&self) {
        let state = self.state();

        if let Some(reason) = state.invalid_settings_reason() {
            crate::daemon_log!(
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
                self.state().begin_cleanup();
                return;
            }
            match (self.teardown.leftovers_present)() {
                Ok(remaining) if remaining.is_empty() => {}
                Ok(remaining) => {
                    let mut state = self.state();
                    state.begin_cleanup();
                    state.cleanup.as_mut().unwrap().remaining = remaining;
                }
                Err(err) => {
                    self.state().begin_cleanup();
                    self.cleanup_failed(
                        protocol::CleanupStage::VerifyingRules,
                        format!("{err:#}"),
                        Vec::new(),
                    );
                }
            }
            return;
        }

        if has_settings {
            return;
        }

        // No settings: preserve orphaned rules rather than silently declaring
        // an unblocked machine or allowing a new block to overwrite them.
        let reason = match (self.teardown.leftovers_present)() {
            Ok(remaining) if remaining.is_empty() => return,
            Ok(remaining) => format!(
                "saved block state is missing, but rules or runtime files remain: {}",
                remaining.join(", ")
            ),
            Err(err) => {
                format!("saved block state is missing and rule cleanup cannot be verified: {err:#}")
            }
        };
        crate::daemon_log!("walden: {reason}; leaving existing rules in place");
        self.state().settings = PersistedSettings::Invalid(reason);
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
            let detail = state
                .cleanup
                .as_ref()
                .and_then(|cleanup| cleanup.error.as_deref());
            if detail.is_some() {
                bail!(
                    "previous block cleanup failed; run `walden status --verbose` for recovery details"
                );
            }
            bail!(
                "the previous block is still being cleaned up; run `walden status` to check progress"
            );
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
                    if settings.apply_error.is_some() {
                        bail!(
                            "the pending start has failed; check `walden status --verbose`, then cancel it with `walden stop` before starting again"
                        );
                    }
                    bail!("a different block is still being applied");
                }
                bail!("a different block is already running");
            }
            if settings.blocklist.as_ref() != Some(&block_list)
                || settings.unlock_delay_secs != Some(unlock_delay_secs)
            {
                bail!("the start operation ID was reused with different block settings");
            }

            let retry_failed_apply = !settings.rules_applied
                && settings.apply_error.is_some()
                && Self::retry_ready(&state);
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
        state.resolved = None;
        state.resolved_at = None;
        state.apply_progress = Some(initial_progress);
        state.dns_cache = resolver::ResolutionCache::default();
        state.candidate = None;
        state.last_apply_failure = None;
        state.apply_attempts = 0;
        state.apply_retry_at = None;
        state.apply_retry_delay_secs = 5;
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

        if state.retiring {
            return Ok(protocol::StopOutcome::CleanupPending);
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
                    crate::daemon_log!("walden: no unlock delay was recorded; ending immediately");
                    Utc::now()
                }
            }
        };

        // Persist before cancelling the apply so a rejected stop leaves it running.
        // A restart can still complete the same teardown after a successful save.
        let mut updated = state
            .valid_settings()
            .cloned()
            .context("the running block state disappeared")?;
        updated.block_end_at = Some(block_end_at);
        state
            .persist_replacement(updated)
            .context("failed to durably save the stop request")?;

        if apply_cancelled {
            state.apply_generation = state.apply_generation.wrapping_add(1);
            state.apply_progress = None;
            crate::daemon_log!("walden: apply cancelled before the block was locked in");
        }
        crate::daemon_log!("walden: the block will end at {block_end_at}");
        if apply_cancelled {
            Ok(protocol::StopOutcome::ApplyCancelled)
        } else {
            Ok(protocol::StopOutcome::Ending { block_end_at })
        }
    }

    pub fn status(&self) -> protocol::StatusResponse {
        let state = self.state();

        let mut status = match &state.settings {
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
                cleanup: None,
                last_apply_failure: state.last_apply_failure.clone(),
                apply_attempts: state.apply_attempts,
                apply_retry_at: state.apply_retry_at,
                apply_in_progress: self.apply_busy(),
                dns_progress: None,
                state_error: None,
            },
            PersistedSettings::Invalid(reason) => protocol::StatusResponse {
                operation_id: None,
                // Fail closed: never report a clean, unblocked machine.
                block_is_running: true,
                unlock_delay_secs: None,
                block_end_at: None,
                block_phase: protocol::BlockPhase::Locked,
                website_count: None,
                apply_started_at: None,
                apply_error: None,
                apply_progress: None,
                cleanup: None,
                last_apply_failure: None,
                apply_attempts: 0,
                apply_retry_at: None,
                apply_in_progress: false,
                dns_progress: None,
                state_error: Some(reason.clone()),
            },
            PersistedSettings::Missing => protocol::StatusResponse::inactive(),
        };
        let dns = state
            .apply_progress
            .as_ref()
            .filter(|progress| progress.stage == protocol::ApplyStage::Resolving)
            .or_else(|| {
                state
                    .candidate
                    .as_ref()
                    .map(|candidate| &candidate.progress)
            });
        status.dns_progress = dns.map(|progress| resolver::ResolveProgress {
            completed: progress.completed,
            total: progress.total,
            resolved_addresses: progress.resolved_addresses,
            failed_lookups: progress.failed_lookups,
        });
        if status.block_is_running
            && state.valid_settings().is_some()
            && status.block_end_at.is_none()
            && !state
                .valid_settings()
                .is_some_and(|settings| settings.rules_applied)
        {
            if self.apply_busy() {
                status.block_phase = protocol::BlockPhase::Applying;
            } else if state.last_apply_failure.is_some() {
                status.block_phase = protocol::BlockPhase::ApplyFailed;
            }
        }
        if state.retiring {
            status.cleanup = state.cleanup.clone();
            status.block_phase = if state
                .cleanup
                .as_ref()
                .is_some_and(|cleanup| cleanup.error.is_some())
            {
                protocol::BlockPhase::CleanupFailed
            } else {
                protocol::BlockPhase::CleaningUp
            };
        }
        status
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
            crate::daemon_log!("walden: the settings file is missing, writing it back");
            if let Err(err) = state.persist() {
                crate::daemon_log!("walden: failed to restore the settings file: {err:#}");
            }
        }

        let rules_applied = state
            .valid_settings()
            .is_some_and(|settings| settings.rules_applied);
        let cache_fresh = state
            .resolved_at
            .is_some_and(|resolved_at| resolved_at.elapsed() < RESOLUTION_TTL);
        let dns_fresh = state
            .dns_cache
            .next_refresh()
            .is_some_and(|expires| expires > Instant::now());
        let resolved = (cache_fresh || dns_fresh)
            .then(|| state.resolved.clone())
            .flatten();
        let retry_ready = Self::retry_ready(&state);
        drop(state);

        if !rules_applied {
            if retry_ready {
                self.spawn_apply();
            }
            return;
        }

        if !retry_ready {
            return;
        }

        match resolved {
            Some(resolved) if blocker::is_intact(&block_list, &resolved) => {}
            _ => {
                crate::daemon_log!(
                    "walden: block rules have drifted, rebuilding them from the saved block list"
                );
                self.spawn_apply();
            }
        }
    }

    fn retry_ready(state: &State) -> bool {
        !state
            .last_apply_failure
            .as_ref()
            .is_some_and(|failure| failure.requires_action)
            && state.apply_retry_at.is_none_or(|retry| Utc::now() >= retry)
    }

    fn retry_apply_if_due(&self) {
        if self.apply_busy() {
            return;
        }
        let state = self.state();
        let due = !state.retiring
            && state.running_blocklist().is_some()
            && state.last_apply_failure.is_some()
            && Self::retry_ready(&state);
        drop(state);
        if due {
            self.spawn_apply();
        }
    }

    fn cleanup_stage(&self, stage: protocol::CleanupStage) {
        let mut state = self.state();
        state.begin_cleanup();
        state.cleanup.as_mut().unwrap().stage = stage;
    }

    fn cleanup_failed(
        &self,
        stage: protocol::CleanupStage,
        error: String,
        remaining: Vec<String>,
    ) -> bool {
        let mut state = self.state();
        state.begin_cleanup();
        let cleanup = state.cleanup.as_mut().unwrap();
        cleanup.stage = stage;
        // Back off persistent errors, but continue automatic recovery.
        let retry_secs = cleanup.attempts.clamp(1, 30);
        cleanup.next_retry_at = Some(Utc::now() + TimeDelta::seconds(retry_secs as i64));
        if cleanup.error.as_deref() != Some(&error) {
            crate::daemon_log!(
                "walden: cleanup failed during {stage:?}: {error}; retrying automatically"
            );
        }
        cleanup.error = Some(error);
        cleanup.remaining = remaining;
        false
    }

    // The saved retirement marker survives every failure, including a restart.
    fn complete_teardown(&self) -> bool {
        if self.apply_busy() {
            self.cleanup_stage(protocol::CleanupStage::WaitingForApply);
            return false;
        }
        {
            let mut state = self.state();
            state.begin_cleanup();
            let cleanup = state.cleanup.as_mut().unwrap();
            cleanup.attempts = cleanup.attempts.saturating_add(1);
            cleanup.next_retry_at = None;
        }
        self.cleanup_stage(protocol::CleanupStage::RemovingRules);
        let removal_error = (self.teardown.stop_blocking)().err();
        self.cleanup_stage(protocol::CleanupStage::VerifyingRules);
        let remaining = match (self.teardown.leftovers_present)() {
            Ok(remaining) => remaining,
            Err(err) => {
                let detail = match removal_error {
                    Some(removal) => format!("{removal:#}; could not verify cleanup: {err:#}"),
                    None => format!("could not verify cleanup: {err:#}"),
                };
                return self.cleanup_failed(
                    protocol::CleanupStage::VerifyingRules,
                    detail,
                    Vec::new(),
                );
            }
        };
        if let Some(err) = removal_error {
            return self.cleanup_failed(
                protocol::CleanupStage::RemovingRules,
                format!("{err:#}"),
                remaining,
            );
        }
        if !remaining.is_empty() {
            return self.cleanup_failed(
                protocol::CleanupStage::VerifyingRules,
                "blocking rules or runtime files remain".into(),
                remaining,
            );
        }

        // Disable autostart before clearing the durable marker. Retirement
        // keeps IPC available until the final save succeeds, so failures remain
        // visible. Keep rejecting starts until this process actually exits.
        self.cleanup_stage(protocol::CleanupStage::RetiringDaemon);
        if let Err(err) = (self.teardown.retire_daemon)() {
            return self.cleanup_failed(
                protocol::CleanupStage::RetiringDaemon,
                format!("daemon retirement failed: {err:#}"),
                Vec::new(),
            );
        }
        self.cleanup_stage(protocol::CleanupStage::SavingState);
        let settings = self.state().valid_settings().cloned();
        if let Some(mut settings) = settings
            && !settings.block_is_running
            && settings.block_end_at.is_some()
        {
            settings.block_end_at = None;
            let saved = self.state().persist_replacement(settings);
            if let Err(err) = saved {
                return self.cleanup_failed(
                    protocol::CleanupStage::SavingState,
                    format!("failed to finish the retirement record: {err:#}"),
                    Vec::new(),
                );
            }
        }
        true
    }
}

pub fn run(lifecycle: &Lifecycle) -> ! {
    let mut next_integrity_check = Instant::now() + INTEGRITY_INTERVAL;

    loop {
        if lifecycle.check_expiry() {
            match lifecycle.state().mark_block_finished() {
                Ok(()) => {}
                Err(err) => {
                    crate::daemon_log!("walden: failed to persist the completed block: {err:#}");
                }
            }
        }

        if lifecycle.state().retiring {
            if lifecycle.apply_busy() {
                lifecycle.cleanup_stage(protocol::CleanupStage::WaitingForApply);
                thread::sleep(TICK);
                continue;
            }

            if lifecycle
                .state()
                .cleanup
                .as_ref()
                .and_then(|cleanup| cleanup.next_retry_at)
                .is_some_and(|retry| Utc::now() < retry)
            {
                thread::sleep(TICK);
                continue;
            }

            if lifecycle.complete_teardown() {
                if let Err(err) = crate::common::remove_file_if_present(protocol::SOCKET_PATH) {
                    crate::daemon_log!("walden: failed to remove the daemon socket: {err:#}");
                }
                std::process::exit(0);
            }

            thread::sleep(TICK);
            continue;
        }

        if Instant::now() >= next_integrity_check {
            lifecycle.check_integrity();
            next_integrity_check = Instant::now() + INTEGRITY_INTERVAL;
        }

        lifecycle.retry_apply_if_due();

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
        cache: &mut resolver::ResolutionCache,
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
    ) -> BTreeSet<ResolvedAddr> {
        resolver::resolve_cached(hosts, cache, progress)
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
        _cache: &mut resolver::ResolutionCache,
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

    fn nothing_left() -> anyhow::Result<Vec<String>> {
        Ok(Vec::new())
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
                resolved: None,
                resolved_at: None,
                save_settings,
                apply_generation: 0,
                apply_progress: None,
                retiring: false,
                cleanup: None,
                dns_cache: resolver::ResolutionCache::default(),
                candidate: None,
                apply_retry_delay_secs: 5,
                last_apply_failure: None,
                apply_attempts: 0,
                apply_retry_at: None,
            })),
            apply_hosts: hosts_ok,
            apply_block,
            prepare_firewall: || Ok(()),
            resolve_all,
            teardown,
            apply_in_progress: Arc::new(AtomicBool::new(false)),
            apply_requested: Arc::new(AtomicBool::new(false)),
        }
    }

    fn retiring_lifecycle(
        leftovers_present: fn() -> anyhow::Result<Vec<String>>,
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

    fn dns_addresses(addresses: &[&str]) -> BTreeSet<ResolvedAddr> {
        addresses
            .iter()
            .map(|address| ResolvedAddr::Host(address.parse().unwrap()))
            .collect()
    }

    fn dns_result(
        hosts: &[String],
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
        addresses: &[&str],
        failed_lookups: usize,
    ) -> BTreeSet<ResolvedAddr> {
        let resolved = dns_addresses(addresses);
        if progress(resolver::ResolveProgress {
            completed: hosts.len(),
            total: hosts.len(),
            resolved_addresses: resolved.len(),
            failed_lookups,
        }) {
            resolved
        } else {
            BTreeSet::new()
        }
    }

    fn resolve_old_addresses(
        hosts: &[String],
        _cache: &mut resolver::ResolutionCache,
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
    ) -> BTreeSet<ResolvedAddr> {
        dns_result(hosts, progress, &["203.0.113.1", "2001:db8::1"], 0)
    }

    fn resolve_new_addresses(
        hosts: &[String],
        _cache: &mut resolver::ResolutionCache,
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
    ) -> BTreeSet<ResolvedAddr> {
        dns_result(hosts, progress, &["203.0.113.2", "2001:db8::2"], 0)
    }

    fn resolve_partial_addresses(
        hosts: &[String],
        _cache: &mut resolver::ResolutionCache,
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
    ) -> BTreeSet<ResolvedAddr> {
        dns_result(hosts, progress, &["203.0.113.2"], 1)
    }

    fn resolve_no_addresses(
        hosts: &[String],
        _cache: &mut resolver::ResolutionCache,
        progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
    ) -> BTreeSet<ResolvedAddr> {
        dns_result(hosts, progress, &[], hosts.len())
    }

    fn dns_refresh_settings() -> Settings {
        let mut settings = running_settings();
        settings.blocklist = Some(vec!["one.test".to_string(), "two.test".to_string()]);
        settings
    }

    #[test]
    fn failed_dns_refresh_keeps_working_addresses_and_retries_before_the_normal_ttl() {
        static INSTALLED: Mutex<Vec<BTreeSet<ResolvedAddr>>> = Mutex::new(Vec::new());

        fn install(_: &[String], addresses: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
            INSTALLED.lock().unwrap().push(addresses.clone());
            Ok(())
        }

        for (resolve, retained) in [
            (
                resolve_no_addresses as ResolveAll,
                dns_addresses(&["203.0.113.1", "2001:db8::1"]),
            ),
            (
                resolve_partial_addresses,
                dns_addresses(&["203.0.113.1", "2001:db8::1", "203.0.113.2"]),
            ),
        ] {
            INSTALLED.lock().unwrap().clear();
            let mut lifecycle = lifecycle_with_dependencies(
                PersistedSettings::Valid(dns_refresh_settings()),
                save_ok,
                install,
            );
            lifecycle.resolve_all = resolve_old_addresses;
            lifecycle.run_apply();
            let previous = dns_addresses(&["203.0.113.1", "2001:db8::1"]);
            let expired = Instant::now() - RESOLUTION_TTL;
            lifecycle.state().resolved_at = Some(expired);

            lifecycle.resolve_all = resolve;
            lifecycle.run_apply();

            assert!(previous.is_subset(lifecycle.state().resolved.as_ref().unwrap()));
            assert_eq!(lifecycle.state().resolved.as_ref(), Some(&retained));
            assert_eq!(INSTALLED.lock().unwrap().last(), Some(&retained));
            assert_eq!(lifecycle.state().resolved_at, None);
            assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Active);
            assert_eq!(lifecycle.status().unlock_delay_secs, Some(60));
            assert_eq!(lifecycle.status().apply_progress, None);

            // An integrity check must retry now, rather than wait 15 minutes.
            // The expired cache also avoids querying the real firewall.
            lifecycle.resolve_all = resolve_new_addresses;
            lifecycle.check_integrity();
            wait_for_apply(&lifecycle);

            let replacement = dns_addresses(&["203.0.113.2", "2001:db8::2"]);
            assert_eq!(lifecycle.state().resolved.as_ref(), Some(&replacement));
            assert_eq!(INSTALLED.lock().unwrap().last(), Some(&replacement));
            assert!(lifecycle.state().resolved_at.unwrap().elapsed() < RESOLUTION_TTL);
            assert_eq!(lifecycle.status().apply_progress, None);
        }
    }

    #[test]
    fn failed_dns_during_resume_keeps_firewall_rules_without_an_in_memory_cache() {
        static INSTALLS: AtomicUsize = AtomicUsize::new(0);

        fn install(_: &[String], _: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
            INSTALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        for resolve in [
            resolve_no_addresses as ResolveAll,
            resolve_partial_addresses,
        ] {
            INSTALLS.store(0, Ordering::SeqCst);
            let mut lifecycle = lifecycle_with_dependencies(
                PersistedSettings::Valid(dns_refresh_settings()),
                save_ok,
                install,
            );
            lifecycle.resolve_all = resolve;
            lifecycle.resume();
            wait_for_apply(&lifecycle);

            assert_eq!(INSTALLS.load(Ordering::SeqCst), 0);
            assert_eq!(lifecycle.state().resolved, None);
            assert_eq!(lifecycle.state().resolved_at, None);
            assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Active);
            assert_eq!(lifecycle.status().apply_progress, None);

            lifecycle.resolve_all = resolve_new_addresses;
            lifecycle.check_integrity();
            wait_for_apply(&lifecycle);
            assert_eq!(INSTALLS.load(Ordering::SeqCst), 1);
            assert_eq!(
                lifecycle.state().resolved,
                Some(dns_addresses(&["203.0.113.2", "2001:db8::2"]))
            );
            assert!(lifecycle.state().resolved_at.is_some());
        }
    }

    #[test]
    fn initial_dns_failures_still_install_hosts_and_available_addresses_then_retry() {
        static HOST_WRITES: AtomicUsize = AtomicUsize::new(0);
        static INSTALLED: Mutex<Vec<BTreeSet<ResolvedAddr>>> = Mutex::new(Vec::new());

        fn hosts(_: &[String]) -> anyhow::Result<()> {
            HOST_WRITES.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn install(_: &[String], addresses: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
            INSTALLED.lock().unwrap().push(addresses.clone());
            Ok(())
        }

        for (resolve, expected) in [
            (resolve_no_addresses as ResolveAll, BTreeSet::new()),
            (resolve_partial_addresses, dns_addresses(&["203.0.113.2"])),
        ] {
            HOST_WRITES.store(0, Ordering::SeqCst);
            INSTALLED.lock().unwrap().clear();
            let mut lifecycle =
                lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, install);
            lifecycle.apply_hosts = hosts;
            lifecycle.resolve_all = resolve;
            // A new block must not reuse addresses from a previous block.
            lifecycle.state().resolved = Some(dns_addresses(&["203.0.113.1", "2001:db8::1"]));
            lifecycle.state().resolved_at = Some(Instant::now());
            lifecycle
                .start(
                    "initial-dns-failure".to_string(),
                    vec!["one.test".to_string(), "two.test".to_string()],
                    60,
                )
                .unwrap();
            wait_for_apply(&lifecycle);

            assert_eq!(HOST_WRITES.load(Ordering::SeqCst), 1);
            assert_eq!(
                INSTALLED.lock().unwrap().as_slice(),
                std::slice::from_ref(&expected)
            );
            assert_eq!(lifecycle.state().resolved.as_ref(), Some(&expected));
            assert_eq!(lifecycle.state().resolved_at, None);
            assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Active);

            // Even a hosts-only first apply must gain firewall coverage as
            // individual lookups recover, without waiting for every hostname.
            lifecycle.resolve_all = resolve_partial_addresses;
            lifecycle.check_integrity();
            wait_for_apply(&lifecycle);
            assert_eq!(
                INSTALLED.lock().unwrap().last(),
                Some(&dns_addresses(&["203.0.113.2"]))
            );
            assert_eq!(lifecycle.state().resolved_at, None);

            lifecycle.resolve_all = resolve_new_addresses;
            lifecycle.check_integrity();
            wait_for_apply(&lifecycle);
            assert_eq!(HOST_WRITES.load(Ordering::SeqCst), 3);
            assert_eq!(
                INSTALLED.lock().unwrap().last(),
                Some(&dns_addresses(&["203.0.113.2", "2001:db8::2"]))
            );
            assert!(lifecycle.state().resolved_at.is_some());
        }
    }

    #[test]
    fn failed_firewall_installation_does_not_publish_a_replacement_dns_cache() {
        let mut lifecycle =
            lifecycle_with_settings(PersistedSettings::Valid(dns_refresh_settings()));
        lifecycle.resolve_all = resolve_old_addresses;
        lifecycle.run_apply();
        let previous = lifecycle.state().resolved.clone();
        let previous_time = lifecycle.state().resolved_at;

        lifecycle.resolve_all = resolve_new_addresses;
        lifecycle.apply_block = apply_fails;
        lifecycle.run_apply();

        assert_eq!(lifecycle.state().resolved, previous);
        assert_eq!(lifecycle.state().resolved_at, previous_time);

        lifecycle.apply_block = apply_ok;
        lifecycle.resolve_all = resolve_partial_addresses;
        lifecycle.run_apply();
        assert_eq!(
            lifecycle.state().resolved,
            Some(dns_addresses(&[
                "203.0.113.1",
                "2001:db8::1",
                "203.0.113.2"
            ]))
        );
        assert_eq!(lifecycle.state().resolved_at, None);

        lifecycle.resolve_all = resolve_new_addresses;
        lifecycle.run_apply();
        assert_eq!(
            lifecycle.state().resolved,
            Some(dns_addresses(&["203.0.113.2", "2001:db8::2"]))
        );
        assert!(lifecycle.state().resolved_at.is_some());
    }

    #[test]
    fn failed_dns_after_applied_state_persistence_fails_keeps_installed_addresses() {
        fn install(_: &[String], addresses: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
            assert!(dns_addresses(&["203.0.113.1", "2001:db8::1"]).is_subset(addresses));
            Ok(())
        }

        let settings = Settings::applying(
            "unrecorded-apply".to_string(),
            vec!["one.test".to_string(), "two.test".to_string()],
            60,
        );
        let mut lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Valid(settings), save_fails, install);
        lifecycle.resolve_all = resolve_old_addresses;
        lifecycle.run_apply();
        assert!(!lifecycle.state().valid_settings().unwrap().rules_applied);

        lifecycle.resolve_all = resolve_partial_addresses;
        // Force a fresh DNS pass instead of reusing a firewall retry candidate.
        lifecycle.state().candidate.as_mut().unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        lifecycle.run_apply();
        assert_eq!(
            lifecycle.state().resolved,
            Some(dns_addresses(&[
                "203.0.113.1",
                "2001:db8::1",
                "203.0.113.2"
            ]))
        );
        assert_eq!(lifecycle.state().resolved_at, None);

        lifecycle.state().save_settings = save_ok;
        lifecycle.apply_block = apply_ok;
        lifecycle.resolve_all = resolve_new_addresses;
        // Force a fresh DNS pass instead of reusing a firewall retry candidate.
        lifecycle.state().candidate.as_mut().unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        lifecycle.run_apply();
        assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Active);
        assert_eq!(
            lifecycle.state().resolved,
            Some(dns_addresses(&["203.0.113.2", "2001:db8::2"]))
        );
    }

    #[test]
    fn invalid_settings_are_locked_and_never_report_unblocked() {
        let lifecycle = lifecycle_with_settings(PersistedSettings::Invalid(
            "unsupported settings version".to_string(),
        ));

        let status = lifecycle.status();
        assert!(status.block_is_running);
        assert_eq!(status.block_phase, protocol::BlockPhase::Locked);
        assert_eq!(
            status.state_error.as_deref(),
            Some("unsupported settings version")
        );
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
    fn failed_stop_during_apply_keeps_generation_and_progress_until_retry() {
        let lifecycle = lifecycle_with_dependencies(
            PersistedSettings::Valid(Settings::applying(
                "operation-1".to_string(),
                vec!["127.0.0.1".to_string()],
                60,
            )),
            save_fails,
            apply_ok,
        );
        {
            let mut state = lifecycle.state();
            state.apply_generation = 7;
            state.apply_progress = Some(protocol::ApplyProgress {
                stage: protocol::ApplyStage::Resolving,
                completed: 0,
                total: 1,
                resolved_addresses: 0,
                failed_lookups: 0,
            });
        }
        let before = lifecycle.status();

        let err = lifecycle.stop().unwrap_err();

        assert!(format!("{err:#}").contains("failed to durably save the stop request"));
        assert_eq!(lifecycle.status(), before);
        assert_eq!(lifecycle.state().apply_generation, 7);

        lifecycle.state().save_settings = save_ok;
        assert_eq!(
            lifecycle.stop().unwrap(),
            protocol::StopOutcome::ApplyCancelled
        );
        let after = lifecycle.status();
        assert_eq!(after.block_phase, protocol::BlockPhase::Ending);
        assert_eq!(after.apply_progress, None);
        assert_eq!(lifecycle.state().apply_generation, 8);
        let block_end_at = after.block_end_at.expect("stop should set an end time");
        assert_eq!(
            lifecycle.stop().unwrap(),
            protocol::StopOutcome::AlreadyEnding { block_end_at }
        );
        assert_eq!(lifecycle.state().apply_generation, 8);
    }

    #[test]
    fn failed_stop_during_resolution_allows_the_current_apply_to_finish() {
        use std::sync::mpsc::{self, Receiver, Sender};

        static RESOLVER_GATE: Mutex<Option<(Sender<()>, Receiver<()>)>> = Mutex::new(None);

        fn reject_stop(settings: &Settings) -> anyhow::Result<()> {
            if settings.block_end_at.is_some() {
                save_fails(settings)
            } else {
                save_ok(settings)
            }
        }

        fn paused_resolution(
            hosts: &[String],
            cache: &mut resolver::ResolutionCache,
            progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
        ) -> BTreeSet<ResolvedAddr> {
            if !progress(resolver::ResolveProgress {
                completed: 0,
                total: hosts.len(),
                resolved_addresses: 0,
                failed_lookups: 0,
            }) {
                return BTreeSet::new();
            }
            let (ready, resume) = RESOLVER_GATE.lock().unwrap().take().unwrap();
            ready.send(()).unwrap();
            resume.recv_timeout(Duration::from_secs(5)).unwrap();
            resolve_all(hosts, cache, progress)
        }

        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        *RESOLVER_GATE.lock().unwrap() = Some((ready_tx, resume_rx));
        let mut lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, reject_stop, apply_ok);
        lifecycle.resolve_all = paused_resolution;
        lifecycle
            .start("operation-1".to_string(), vec!["127.0.0.1".to_string()], 60)
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let before = lifecycle.status();
        let generation = lifecycle.state().apply_generation;

        let result = lifecycle.stop();
        let after = lifecycle.status();
        let generation_after = lifecycle.state().apply_generation;
        // Release the worker before asserting so failures cannot leave it blocked.
        resume_tx.send(()).unwrap();
        wait_for_apply(&lifecycle);

        let err = result.unwrap_err();
        assert!(format!("{err:#}").contains("failed to durably save the stop request"));
        assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Active);
        assert_eq!(lifecycle.status().block_end_at, None);
        assert_eq!(
            lifecycle.state().resolved,
            Some(dns_addresses(&["127.0.0.1"]))
        );
        assert_eq!(after, before);
        assert_eq!(generation_after, generation);
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
        assert_eq!(
            lifecycle.status().block_phase,
            protocol::BlockPhase::CleaningUp
        );
        assert_eq!(
            lifecycle.stop().unwrap(),
            protocol::StopOutcome::CleanupPending
        );
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

        fn leftovers() -> anyhow::Result<Vec<String>> {
            Ok(if CLEANUP_ATTEMPTS.load(Ordering::SeqCst) < 2 {
                vec!["injected leftover PF rules".into()]
            } else {
                Vec::new()
            })
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
        let status = lifecycle.status();
        assert_eq!(status.block_phase, protocol::BlockPhase::CleanupFailed);
        let progress = status.cleanup.unwrap();
        assert_eq!(progress.stage, protocol::CleanupStage::RemovingRules);
        assert!(
            progress
                .error
                .as_deref()
                .unwrap()
                .contains("injected cleanup failure")
        );
        assert_eq!(progress.remaining, ["injected leftover PF rules"]);
        assert_eq!(progress.attempts, 1);
        assert!(progress.next_retry_at.is_some());
        let refused = lifecycle
            .start("next-block".into(), vec!["example.org".into()], 1)
            .unwrap_err();
        assert!(refused.to_string().contains("cleanup failed"));
        assert!(refused.to_string().contains("status --verbose"));
        assert!(lifecycle.complete_teardown());
        assert_eq!(CLEANUP_ATTEMPTS.load(Ordering::SeqCst), 2);
        assert_eq!(lifecycle.status().block_end_at, None);
        // Until this process exits, a new start must not race its clean exit.
        assert!(
            lifecycle
                .start("next-block".into(), vec!["example.org".into()], 1)
                .is_err()
        );
        let persisted = lifecycle.state().valid_settings().unwrap().clone();
        let restarted = lifecycle_with_settings(PersistedSettings::Valid(persisted));
        restarted.resume();
        assert_eq!(
            restarted.status().block_phase,
            protocol::BlockPhase::Inactive
        );
        restarted
            .start("next-block".into(), vec!["127.0.0.1".into()], 1)
            .unwrap();
        wait_for_apply(&restarted);
        assert_eq!(restarted.status().block_phase, protocol::BlockPhase::Active);
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

        fn something_left() -> anyhow::Result<Vec<String>> {
            Ok(vec!["injected leftover PF rules".into()])
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

        fn unverifiable() -> anyhow::Result<Vec<String>> {
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

    #[test]
    fn failed_cleanup_verification_preserves_retirement_until_retry_succeeds() {
        static QUERIES: AtomicUsize = AtomicUsize::new(0);
        static RETIREMENTS: AtomicUsize = AtomicUsize::new(0);

        fn verify() -> anyhow::Result<Vec<String>> {
            if QUERIES.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("injected firewall query failure");
            }
            Ok(Vec::new())
        }

        fn retire() -> anyhow::Result<()> {
            RETIREMENTS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        QUERIES.store(0, Ordering::SeqCst);
        RETIREMENTS.store(0, Ordering::SeqCst);

        let mut settings = running_settings();
        settings.block_is_running = false;
        settings.block_end_at = Some(Utc::now());
        let retirement_marker = settings.block_end_at;

        let lifecycle = lifecycle_with_teardown(
            PersistedSettings::Valid(settings),
            save_ok,
            apply_ok,
            Teardown {
                stop_blocking: unblock_ok,
                leftovers_present: verify,
                retire_daemon: retire,
            },
        );

        lifecycle.resume();

        assert!(lifecycle.state().retiring);
        assert!(!lifecycle.complete_teardown());
        assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 0);
        assert_eq!(lifecycle.status().block_end_at, retirement_marker);

        assert!(lifecycle.complete_teardown());
        assert_eq!(QUERIES.load(Ordering::SeqCst), 2);
        assert_eq!(RETIREMENTS.load(Ordering::SeqCst), 1);
        assert_eq!(lifecycle.status().block_end_at, None);
    }

    #[test]
    fn failed_cleanup_save_preserves_marker_and_reports_the_failed_stage() {
        let mut settings = running_settings();
        settings.block_is_running = false;
        settings.block_end_at = Some(Utc::now());
        let marker = settings.block_end_at;
        let lifecycle = lifecycle_with_teardown(
            PersistedSettings::Valid(settings),
            save_fails,
            apply_ok,
            Teardown {
                stop_blocking: unblock_ok,
                leftovers_present: nothing_left,
                retire_daemon: || Ok(()),
            },
        );
        lifecycle.resume();
        assert!(!lifecycle.complete_teardown());
        let status = lifecycle.status();
        assert_eq!(status.block_phase, protocol::BlockPhase::CleanupFailed);
        assert_eq!(status.block_end_at, marker);
        let cleanup = status.cleanup.unwrap();
        assert_eq!(cleanup.stage, protocol::CleanupStage::SavingState);
        assert!(
            cleanup
                .error
                .unwrap()
                .contains("injected persistence failure")
        );
        lifecycle.state().save_settings = save_ok;
        assert!(lifecycle.complete_teardown());
        assert_eq!(lifecycle.status().block_end_at, None);
    }

    #[test]
    fn cleanup_waits_for_apply_workers_before_removing_rules() {
        let lifecycle = retiring_lifecycle(nothing_left, || Ok(()));
        lifecycle.apply_in_progress.store(true, Ordering::SeqCst);
        assert!(!lifecycle.complete_teardown());
        let status = lifecycle.status();
        assert_eq!(status.block_phase, protocol::BlockPhase::CleaningUp);
        assert_eq!(
            status.cleanup.unwrap().stage,
            protocol::CleanupStage::WaitingForApply
        );
        lifecycle.apply_in_progress.store(false, Ordering::SeqCst);
        assert!(lifecycle.complete_teardown());
    }

    #[test]
    fn missing_settings_with_orphaned_rules_are_locked() {
        let lifecycle = lifecycle_with_teardown(
            PersistedSettings::Missing,
            save_ok,
            apply_ok,
            Teardown {
                stop_blocking: unblock_ok,
                leftovers_present: || Ok(vec!["PF block rules".into()]),
                retire_daemon: || Ok(()),
            },
        );
        lifecycle.resume();
        let status = lifecycle.status();
        assert_eq!(status.block_phase, protocol::BlockPhase::Locked);
        assert!(status.state_error.unwrap().contains("PF block rules"));
        assert!(
            lifecycle
                .start("new-operation".into(), vec!["example.com".into()], 1)
                .is_err()
        );
    }

    #[test]
    fn permanent_pf_preparation_failure_skips_dns_and_requires_action() {
        let mut lifecycle = lifecycle_with_settings(PersistedSettings::Missing);
        lifecycle.prepare_firewall =
            || Err(blocker::pf::ConfigurationError("invalid parent filtering order".into()).into());
        lifecycle.resolve_all = |_, _, _| panic!("must validate PF before DNS");
        lifecycle
            .start("prepare-failure".into(), vec!["host.test".into()], 1)
            .unwrap();
        wait_for_apply(&lifecycle);
        let status = lifecycle.status();
        assert_eq!(status.block_phase, protocol::BlockPhase::ApplyFailed);
        let failure = status.last_apply_failure.unwrap();
        assert_eq!(failure.stage, protocol::ApplyStage::PreparingFirewall);
        assert!(failure.requires_action);
        assert!(status.apply_retry_at.is_none());
        lifecycle.retry_apply_if_due();
        assert_eq!(lifecycle.status().apply_attempts, 1);
        assert_eq!(
            lifecycle.stop().unwrap(),
            protocol::StopOutcome::ApplyCancelled
        );
    }

    #[test]
    fn apply_backoff_counts_failures_instead_of_successful_refreshes() {
        let lifecycle = lifecycle_with_settings(PersistedSettings::Valid(running_settings()));
        lifecycle.state().apply_attempts = 100;
        let error = anyhow::anyhow!("temporary command failure");
        lifecycle.record_apply_error(0, true, &error);
        assert_eq!(lifecycle.state().apply_retry_delay_secs, 10);
        assert!((lifecycle.status().apply_retry_at.unwrap() - Utc::now()).num_seconds() <= 5);
        lifecycle.record_apply_error(0, true, &error);
        assert_eq!(lifecycle.state().apply_retry_delay_secs, 20);
        lifecycle.mark_rules_applied(0);
        assert_eq!(lifecycle.state().apply_retry_delay_secs, 5);
    }

    #[test]
    fn firewall_retry_reuses_dns_candidates_without_publishing_failed_coverage() {
        static DNS_CALLS: AtomicUsize = AtomicUsize::new(0);
        static INSTALL_CALLS: AtomicUsize = AtomicUsize::new(0);
        fn resolve(
            hosts: &[String],
            _: &mut resolver::ResolutionCache,
            progress: &mut dyn FnMut(resolver::ResolveProgress) -> bool,
        ) -> BTreeSet<ResolvedAddr> {
            DNS_CALLS.fetch_add(1, Ordering::SeqCst);
            dns_result(hosts, progress, &["203.0.113.1", "2001:db8::1"], 0)
        }
        fn install(_: &[String], _: &BTreeSet<ResolvedAddr>) -> anyhow::Result<()> {
            if INSTALL_CALLS.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("temporary firewall command failure");
            }
            Ok(())
        }
        DNS_CALLS.store(0, Ordering::SeqCst);
        INSTALL_CALLS.store(0, Ordering::SeqCst);
        let mut lifecycle =
            lifecycle_with_dependencies(PersistedSettings::Missing, save_ok, install);
        lifecycle.resolve_all = resolve;
        lifecycle
            .start("cached-retry".into(), vec!["host.test".into()], 1)
            .unwrap();
        wait_for_apply(&lifecycle);
        let failed = lifecycle.status();
        assert_eq!(
            failed.last_apply_failure.unwrap().stage,
            protocol::ApplyStage::InstallingFirewall
        );
        assert_eq!(failed.dns_progress.unwrap().total, 1);
        assert_eq!(failed.apply_progress.unwrap().resolved_addresses, 2);
        assert!(lifecycle.state().resolved.is_none());
        assert!(lifecycle.state().candidate.is_some());
        lifecycle.retry_apply_if_due();
        assert_eq!(INSTALL_CALLS.load(Ordering::SeqCst), 1);
        lifecycle.state().apply_retry_at = Some(Utc::now() - TimeDelta::seconds(1));
        lifecycle.retry_apply_if_due();
        wait_for_apply(&lifecycle);
        assert_eq!(DNS_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(INSTALL_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(lifecycle.status().block_phase, protocol::BlockPhase::Active);
        assert!(lifecycle.status().last_apply_failure.is_none());
    }

    #[test]
    fn removal_errors_are_not_hidden_by_an_empty_leftover_query() {
        let lifecycle = lifecycle_with_teardown(
            PersistedSettings::Missing,
            save_ok,
            apply_ok,
            Teardown {
                stop_blocking: || bail!("PF access denied"),
                leftovers_present: nothing_left,
                retire_daemon: || panic!("must not retire"),
            },
        );
        assert!(!lifecycle.complete_teardown());
        let status = lifecycle.status();
        assert_eq!(status.block_phase, protocol::BlockPhase::CleanupFailed);
        assert!(
            status
                .cleanup
                .unwrap()
                .error
                .unwrap()
                .contains("PF access denied")
        );
    }
}
