//! Spec 029: which agent integrations this host has, as `workspace.snapshot.v3` tells the phone.
//!
//! A host learns that an attached Claude, Codex or Pi session exists only through Ciao's
//! integration for that agent. Without it the agent runs, the host lists no session, and the
//! phone has nothing to say about why. This module is the phone's view of the same answer
//! `ciao agent status` prints: the probe calls the very status functions that command calls, so
//! the two can never disagree about whether something is installed.
//!
//! Detection spawns `claude --version` and friends, and Codex's trust check asks `codex
//! app-server`, while the snapshot runs on every sweep. So a snapshot only ever reads a cached
//! answer; the probe runs in the background, once at start and then at most every
//! `REFRESH_INTERVAL`, and only when a v3 snapshot asks.

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use parking_lot::Mutex;
use tokio::time::Instant;

use crate::{
    agent_integration::AgentIntegration,
    claude_integration::{ClaudeIntegrationStatus, claude_integration_status},
    codex_integration::{CodexIntegrationStatus, codex_integration_status},
    host_protocol::{AgentIntegrationEntry, IntegrationAgent, IntegrationState},
    pi_integration::{PiIntegrationStatus, pi_integration_status},
    storage::CiaoPaths,
};

/// Integrations change when a person runs a command; `ciao setup` restarts the daemon, which
/// probes again at once. Five minutes stale is the cost of never making a sweep wait.
pub(crate) const REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// The attached hooks decide this, not the managed runtime: the hooks are what register a
/// session the person started in their own terminal. `None` when the status says Claude itself
/// is gone, which detection would not have reported a moment earlier.
pub(crate) fn claude_state(status: ClaudeIntegrationStatus) -> Option<IntegrationState> {
    Some(match status {
        ClaudeIntegrationStatus::NotInstalled => IntegrationState::Missing,
        ClaudeIntegrationStatus::Installed | ClaudeIntegrationStatus::AheadOfTested => {
            IntegrationState::Installed
        }
        ClaudeIntegrationStatus::UpdateAvailable => IntegrationState::Outdated,
        ClaudeIntegrationStatus::UnsupportedClaudeVersion => IntegrationState::UnsupportedVersion,
        ClaudeIntegrationStatus::ClaudeUnavailable => return None,
    })
}

pub(crate) fn codex_state(status: CodexIntegrationStatus) -> Option<IntegrationState> {
    Some(match status {
        CodexIntegrationStatus::NotInstalled => IntegrationState::Missing,
        CodexIntegrationStatus::Installed | CodexIntegrationStatus::CarriedVerified => {
            IntegrationState::Installed
        }
        CodexIntegrationStatus::AwaitingTrust => IntegrationState::NeedsApproval,
        CodexIntegrationStatus::UpdateAvailable => IntegrationState::Outdated,
        CodexIntegrationStatus::UnsupportedCodexVersion => IntegrationState::UnsupportedVersion,
        CodexIntegrationStatus::CodexUnavailable => return None,
    })
}

pub(crate) fn pi_state(status: PiIntegrationStatus) -> IntegrationState {
    match status {
        PiIntegrationStatus::NotInstalled => IntegrationState::Missing,
        PiIntegrationStatus::Installed => IntegrationState::Installed,
        PiIntegrationStatus::UpdateAvailable => IntegrationState::Outdated,
    }
}

fn entry(agent: AgentIntegration, state: IntegrationState) -> AgentIntegrationEntry {
    AgentIntegrationEntry {
        agent: match agent {
            // The hidden managed-only alias is the same agent.
            AgentIntegration::Claude | AgentIntegration::ClaudeManaged => IntegrationAgent::Claude,
            AgentIntegration::Codex => IntegrationAgent::Codex,
            AgentIntegration::Pi => IntegrationAgent::Pi,
        },
        state,
    }
}

/// One entry per agent `ciao setup` would detect, in a fixed order. An agent that is absent gets
/// no entry: there is nothing to fix on its behalf. A status that fails to read is left out
/// rather than guessed, and says so in the log.
pub(crate) async fn probe(paths: &CiaoPaths) -> Vec<AgentIntegrationEntry> {
    let blocking = paths.clone();
    let read = tokio::task::spawn_blocking(move || {
        let detected = crate::cli::detect_agents(&blocking);
        let claude = detected
            .contains(&AgentIntegration::Claude)
            .then(|| claude_integration_status(&blocking));
        let pi = detected
            .contains(&AgentIntegration::Pi)
            .then(|| pi_integration_status(&blocking));
        (detected, claude, pi)
    })
    .await;
    let Ok((detected, claude, pi)) = read else {
        tracing::warn!("agent integration probe stopped before it finished");
        return Vec::new();
    };
    let mut entries = Vec::new();
    match claude {
        Some(Ok(status)) => {
            if let Some(state) = claude_state(status) {
                entries.push(entry(AgentIntegration::Claude, state));
            }
        }
        Some(Err(error)) => tracing::debug!(%error, "claude integration status unreadable"),
        None => {}
    }
    if detected.contains(&AgentIntegration::Codex) {
        match codex_integration_status(paths).await {
            Ok(status) => {
                if let Some(state) = codex_state(status) {
                    entries.push(entry(AgentIntegration::Codex, state));
                }
            }
            Err(error) => tracing::debug!(%error, "codex integration status unreadable"),
        }
    }
    match pi {
        Some(Ok(status)) => entries.push(entry(AgentIntegration::Pi, pi_state(status))),
        Some(Err(error)) => tracing::debug!(%error, "pi integration status unreadable"),
        None => {}
    }
    tracing::debug!(entries = entries.len(), "agent integrations probed");
    entries
}

type ProbeFuture = Pin<Box<dyn Future<Output = Vec<AgentIntegrationEntry>> + Send>>;
type Probe = Arc<dyn Fn() -> ProbeFuture + Send + Sync>;

#[derive(Default)]
struct Cached {
    entries: Option<Vec<AgentIntegrationEntry>>,
    probed_at: Option<Instant>,
    probing: bool,
}

/// The daemon's one copy of the answer. `current` never waits: it returns what the last probe
/// found, nothing before the first probe lands, and starts a fresh probe in the background when
/// none has run within `REFRESH_INTERVAL` and none is running.
pub(crate) struct IntegrationStatusCache {
    probe: Option<Probe>,
    cached: Arc<Mutex<Cached>>,
}

impl std::fmt::Debug for IntegrationStatusCache {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cached = self.cached.lock();
        formatter
            .debug_struct("IntegrationStatusCache")
            .field("enabled", &self.probe.is_some())
            .field("entries", &cached.entries)
            .field("probing", &cached.probing)
            .finish()
    }
}

impl IntegrationStatusCache {
    pub(crate) fn for_host(paths: CiaoPaths) -> Self {
        Self::with_probe(Arc::new(move || {
            let paths = paths.clone();
            Box::pin(async move { probe(&paths).await })
        }))
    }

    pub(crate) fn with_probe(probe: Probe) -> Self {
        Self {
            probe: Some(probe),
            cached: Arc::new(Mutex::new(Cached::default())),
        }
    }

    /// A cache that never probes: fixtures and tests that must not run agent CLIs.
    #[cfg(test)]
    pub(crate) fn disabled() -> Self {
        Self {
            probe: None,
            cached: Arc::new(Mutex::new(Cached::default())),
        }
    }

    pub(crate) fn current(&self) -> Option<Vec<AgentIntegrationEntry>> {
        let mut cached = self.cached.lock();
        let stale = cached
            .probed_at
            .is_none_or(|at| at.elapsed() >= REFRESH_INTERVAL);
        if stale
            && !cached.probing
            && let Some(probe) = &self.probe
        {
            cached.probing = true;
            let slot = self.cached.clone();
            // The probe runs as its own task so a panic inside it becomes a join error here
            // rather than a `probing` flag stuck on forever.
            let running = tokio::spawn(probe());
            tokio::spawn(async move {
                let outcome = running.await;
                let mut cached = slot.lock();
                match outcome {
                    Ok(entries) => cached.entries = Some(entries),
                    Err(_) => {
                        tracing::warn!("agent integration probe failed; keeping the last answer")
                    }
                }
                // Stamped either way, so a probe that keeps failing is retried on the interval
                // rather than on every sweep.
                cached.probed_at = Some(Instant::now());
                cached.probing = false;
            });
        }
        cached.entries.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    fn sample() -> Vec<AgentIntegrationEntry> {
        vec![entry(AgentIntegration::Claude, IntegrationState::Missing)]
    }

    /// A probe that waits on `gate` and counts how often it was started.
    fn gated(gate: Arc<Notify>, calls: Arc<AtomicUsize>) -> Probe {
        Arc::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            let gate = gate.clone();
            Box::pin(async move {
                gate.notified().await;
                sample()
            })
        })
    }

    async fn settle() {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    /// Spec 029 §2: a snapshot never waits on the probe. Before it lands the field is absent;
    /// after it lands the answer is there, and asking again while it runs starts nothing new.
    #[tokio::test]
    async fn the_first_answer_is_absent_and_never_waits_for_the_probe() {
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let cache = IntegrationStatusCache::with_probe(gated(gate.clone(), calls.clone()));

        assert_eq!(cache.current(), None, "answered before any probe landed");
        assert_eq!(cache.current(), None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a running probe is not doubled"
        );

        gate.notify_one();
        settle().await;
        assert_eq!(cache.current(), Some(sample()));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a fresh answer is not re-probed"
        );
    }

    /// At most one probe per `REFRESH_INTERVAL`, however often the phone sweeps.
    #[tokio::test(start_paused = true)]
    async fn a_fresh_answer_is_reused_until_the_interval_passes() {
        let gate = Arc::new(Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let cache = IntegrationStatusCache::with_probe(gated(gate.clone(), calls.clone()));
        cache.current();
        gate.notify_one();
        settle().await;

        tokio::time::advance(REFRESH_INTERVAL - Duration::from_secs(1)).await;
        assert_eq!(cache.current(), Some(sample()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(
            cache.current(),
            Some(sample()),
            "the stale answer stands while the refresh runs"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A probe that panics keeps the last answer and is retried on the interval, not wedged.
    #[tokio::test(start_paused = true)]
    async fn a_panicking_probe_does_not_wedge_the_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let cache = IntegrationStatusCache::with_probe(Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { panic!("probe exploded") })
        }));
        cache.current();
        settle().await;
        assert_eq!(cache.current(), None);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "retried before the interval"
        );
        tokio::time::advance(REFRESH_INTERVAL).await;
        cache.current();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_disabled_cache_answers_nothing() {
        assert_eq!(IntegrationStatusCache::disabled().current(), None);
    }

    /// One owner for "is this installed": every status `ciao agent status` can print maps to
    /// exactly one wire state, and the attached hooks alone decide Claude's.
    #[test]
    fn every_cli_status_maps_to_one_wire_state() {
        use ClaudeIntegrationStatus as C;
        assert_eq!(
            claude_state(C::NotInstalled),
            Some(IntegrationState::Missing)
        );
        assert_eq!(
            claude_state(C::Installed),
            Some(IntegrationState::Installed)
        );
        assert_eq!(
            claude_state(C::AheadOfTested),
            Some(IntegrationState::Installed)
        );
        assert_eq!(
            claude_state(C::UpdateAvailable),
            Some(IntegrationState::Outdated)
        );
        assert_eq!(
            claude_state(C::UnsupportedClaudeVersion),
            Some(IntegrationState::UnsupportedVersion)
        );
        assert_eq!(claude_state(C::ClaudeUnavailable), None);

        use CodexIntegrationStatus as X;
        assert_eq!(
            codex_state(X::NotInstalled),
            Some(IntegrationState::Missing)
        );
        assert_eq!(codex_state(X::Installed), Some(IntegrationState::Installed));
        assert_eq!(
            codex_state(X::CarriedVerified),
            Some(IntegrationState::Installed)
        );
        assert_eq!(
            codex_state(X::AwaitingTrust),
            Some(IntegrationState::NeedsApproval)
        );
        assert_eq!(
            codex_state(X::UpdateAvailable),
            Some(IntegrationState::Outdated)
        );
        assert_eq!(
            codex_state(X::UnsupportedCodexVersion),
            Some(IntegrationState::UnsupportedVersion)
        );
        assert_eq!(codex_state(X::CodexUnavailable), None);

        use PiIntegrationStatus as P;
        assert_eq!(pi_state(P::NotInstalled), IntegrationState::Missing);
        assert_eq!(pi_state(P::Installed), IntegrationState::Installed);
        assert_eq!(pi_state(P::UpdateAvailable), IntegrationState::Outdated);
    }

    /// Every token the host can emit passes the wire validation the phone's copy is held to.
    #[test]
    fn every_emitted_token_is_a_valid_wire_token() {
        let result = crate::host_protocol::WorkspaceSnapshotResult {
            v: crate::host_protocol::HOST_PROTOCOL_VERSION,
            providers: crate::host_protocol::WorkspaceProviders {
                tmux: crate::host_protocol::TmuxProviderSnapshot {
                    state: "not_installed".into(),
                    version: None,
                    sessions: None,
                },
                herdr: crate::host_protocol::HerdrProviderSnapshot {
                    state: "not_installed".into(),
                    version: None,
                    sessions: None,
                },
                herdr_core: None,
            },
            omitted_sessions: 0,
            agent_integrations: Some(
                [
                    IntegrationState::Installed,
                    IntegrationState::Missing,
                    IntegrationState::NeedsApproval,
                    IntegrationState::Outdated,
                    IntegrationState::UnsupportedVersion,
                ]
                .into_iter()
                .map(|state| entry(AgentIntegration::Codex, state))
                .chain([
                    entry(AgentIntegration::Claude, IntegrationState::Installed),
                    entry(AgentIntegration::Pi, IntegrationState::Installed),
                ])
                .collect(),
            ),
        };
        result.validate().unwrap();
    }
}
