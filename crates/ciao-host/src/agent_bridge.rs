//! Same-user attached-agent bridge transport and adapter dispatch.
//!
//! The daemon owns only the Unix listener. This module authenticates each accepted peer, selects
//! one registered adapter codec, and drives the adapter-neutral session supervisor. Vendor frame
//! types never enter the daemon or the canonical host/iPhone protocol.

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{
    net::UnixStream,
    sync::{mpsc, watch},
    time::timeout,
};

use crate::{
    agent_adapter::{
        ADAPTER_COMMAND_CHANNEL_CAPACITY, AdapterConnectionKind, AttachedAgentAdapter,
        NormalizedAdapterEvent,
    },
    agent_protocol::{
        AgentProtocolError, TimelineBody, Truncation, TurnState, decode_agent_body,
        read_agent_frame, valid_token, write_agent_frame,
    },
    agent_route::{process_looks_like_tui, process_start_fingerprint},
    agent_session::{
        AgentSessionSupervisor, AttentionKind, NormalizedTimelineEntry, RegisteredAgentSession,
    },
    claude_adapter::ClaudeAttachedAdapter,
    claude_managed_adapter::ClaudeManagedAdapter,
    codex_adapter::CodexAttachedAdapter,
    host_protocol::HOST_OPERATION_TIMEOUT,
    managed_session::ManagedSessionDirectory,
    managed_worker::SharedWorkerTable,
    notify::Notifier,
    pi_adapter::PiAttachedAdapter,
    process::descends_from as process_descends_from,
};

const MAX_ADAPTER_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ADAPTER_SNAPSHOT_ENTRIES: usize = 4096;

static PI_ADAPTER: PiAttachedAdapter = PiAttachedAdapter;
static CLAUDE_ADAPTER: ClaudeAttachedAdapter = ClaudeAttachedAdapter;
static CLAUDE_MANAGED_ADAPTER: ClaudeManagedAdapter = ClaudeManagedAdapter;
static CODEX_ADAPTER: CodexAttachedAdapter = CodexAttachedAdapter;
pub(crate) static PRODUCTION_ADAPTERS: [&'static dyn AttachedAgentAdapter; 4] = [
    &PI_ADAPTER,
    &CLAUDE_ADAPTER,
    &CLAUDE_MANAGED_ADAPTER,
    &CODEX_ADAPTER,
];

#[derive(Clone, Copy)]
pub(crate) struct AgentAdapterRegistry<'a> {
    adapters: &'a [&'a dyn AttachedAgentAdapter],
}

impl AgentAdapterRegistry<'static> {
    pub(crate) const fn production() -> Self {
        Self {
            adapters: &PRODUCTION_ADAPTERS,
        }
    }
}

impl<'a> AgentAdapterRegistry<'a> {
    pub(crate) fn select(
        self,
        body: &[u8],
        peer_process_id: Option<u32>,
    ) -> Result<SelectedAdapter<'a>, AgentProtocolError> {
        let value: Value = decode_agent_body(body)?;
        let object = value.as_object().ok_or(AgentProtocolError::MalformedJson)?;
        if object.get("type").and_then(Value::as_str) != Some("register") {
            return Err(AgentProtocolError::UnexpectedMessage);
        }

        let adapter = match object.get("adapter") {
            Some(Value::String(id)) => {
                valid_token(id)?;
                self.adapters
                    .iter()
                    .copied()
                    .find(|adapter| adapter.id() == id)
                    .ok_or(AgentProtocolError::InvalidValue)?
            }
            Some(_) => return Err(AgentProtocolError::InvalidValue),
            None => {
                let mut legacy = self
                    .adapters
                    .iter()
                    .copied()
                    .filter(|adapter| adapter.accepts_legacy_registration());
                let selected = legacy.next().ok_or(AgentProtocolError::InvalidValue)?;
                if legacy.next().is_some() {
                    return Err(AgentProtocolError::InvalidValue);
                }
                selected
            }
        };
        let registration = adapter.decode_registration(body, peer_process_id)?;
        Ok(SelectedAdapter {
            codec: adapter,
            registration,
        })
    }
}

pub(crate) struct SelectedAdapter<'a> {
    pub(crate) codec: &'a dyn AttachedAgentAdapter,
    pub(crate) registration: crate::agent_session::NormalizedRegistration,
}

/// Everything applying one normalized adapter event needs, whichever connection topology
/// delivered it.
///
/// There used to be two hand-maintained event matches — one per topology — each treating the
/// other's vocabulary as a fatal protocol error. That split is how notifications became a
/// transient-only capability: the arm existed in one match and nobody noticed the other lacked
/// it. One dispatcher means an event kind gains handling for every dialect at once; which
/// dialects can actually *produce* an event stays governed by their decoders, and the
/// conformance ledger holds that vocabulary in both directions.
struct AdapterEventContext<'a> {
    sessions: &'a AgentSessionSupervisor,
    adoptions: &'a std::sync::Arc<crate::codex_adopted::AdoptionRegistry>,
    notifier: &'a Notifier,
    managed: &'a ManagedSessionDirectory,
    codec: &'a dyn AttachedAgentAdapter,
    registered: &'a RegisteredAgentSession,
    /// Vendor-side process identity, present only for transient hook connections. The Codex
    /// history read is the one consumer.
    agent: Option<&'a AgentProcessIdentity>,
    /// The Ciao session ID the managed directory keys on — the registration's upstream
    /// identity.
    managed_session_id: &'a str,
    snapshot_entries: Vec<NormalizedTimelineEntry>,
    snapshot_bytes: usize,
    snapshot_open: bool,
    unknown_sequence: u64,
}

enum EventOutcome {
    Continue,
    End { process_exited: bool },
}

fn apply_adapter_event(
    event: NormalizedAdapterEvent,
    ctx: &mut AdapterEventContext<'_>,
) -> Result<EventOutcome> {
    let session_id = &ctx.registered.session_id;
    match event {
        NormalizedAdapterEvent::Registration => bail!("agent bridge registered twice"),
        NormalizedAdapterEvent::SnapshotStart => {
            ctx.snapshot_entries.clear();
            ctx.snapshot_bytes = 0;
            ctx.snapshot_open = true;
        }
        NormalizedAdapterEvent::SnapshotEntry(entry) if ctx.snapshot_open => {
            ctx.snapshot_bytes = ctx
                .snapshot_bytes
                .saturating_add(entry.body.decoded_bytes());
            if ctx.snapshot_bytes > MAX_ADAPTER_SNAPSHOT_BYTES
                || ctx.snapshot_entries.len() >= MAX_ADAPTER_SNAPSHOT_ENTRIES
            {
                bail!("agent bridge snapshot exceeded its bound");
            }
            ctx.snapshot_entries.push(entry);
        }
        NormalizedAdapterEvent::SnapshotEnd if ctx.snapshot_open => {
            ctx.snapshot_open = false;
            ctx.sessions
                .replace_bridge_snapshot(session_id, std::mem::take(&mut ctx.snapshot_entries))?;
        }
        NormalizedAdapterEvent::UpsertEntry(entry) if !ctx.snapshot_open => {
            ctx.sessions.upsert_bridge_entry(session_id, entry)?;
        }
        NormalizedAdapterEvent::AppendText(delta) if !ctx.snapshot_open => {
            ctx.sessions.append_bridge_text(session_id, delta)?;
        }
        NormalizedAdapterEvent::Heartbeat if !ctx.snapshot_open => {}
        // Capability, turn, and receipt events are session-level and may interleave
        // with a paged snapshot burst; they are not ordered timeline content.
        NormalizedAdapterEvent::Turn(turn) => {
            // Categorical and adapter-neutral: the session, and the turn edge it
            // reported. No prompt, output, or vendor identifier. This is the only
            // place that answers "is this integration reporting turns at all",
            // which is otherwise indistinguishable from a quiet agent.
            tracing::info!(
                session = %session_id,
                turn = ?turn,
                "agent turn changed"
            );
            // Spec 012 §6. Codex's `sessionStart` does not fire until a session's first prompt,
            // so hooks alone show a resumed conversation as empty. The read is triggered here
            // rather than at registration because a turn is what names the part of the thread
            // the live tail already owns — without it, history and the live tail both deliver
            // the message the person just typed.
            if ctx.codec.id() == "codex"
                && let (Some(agent), TurnState::Running { run_id, .. }) = (ctx.agent, &turn)
            {
                crate::codex_history::spawn_history_read(
                    ctx.sessions.clone(),
                    ctx.adoptions.clone(),
                    session_id.clone(),
                    agent.thread_id.clone(),
                    run_id.clone(),
                    agent.process_id,
                    ctx.registered.process_generation,
                );
            }
            ctx.sessions.note_bridge_turn(session_id, turn)?;
        }
        NormalizedAdapterEvent::CommandCapabilities(commands) => {
            ctx.sessions.update_bridge_commands(session_id, commands);
        }
        NormalizedAdapterEvent::PermissionMode(mode) => {
            ctx.sessions.update_bridge_permission_mode(session_id, mode);
        }
        NormalizedAdapterEvent::Model(model) => {
            ctx.sessions.update_bridge_model(session_id, model);
        }
        NormalizedAdapterEvent::Effort(effort) => {
            ctx.sessions.update_bridge_effort(session_id, effort);
        }
        NormalizedAdapterEvent::ModelCatalogue(models) => {
            ctx.sessions
                .update_bridge_model_catalogue(session_id, models);
        }
        NormalizedAdapterEvent::CommandReceipt {
            command_id,
            state,
            evidence,
            reason_code,
        } => {
            let _ = ctx.sessions.record_bridge_receipt(
                session_id,
                &command_id,
                &state,
                evidence.as_deref(),
                reason_code.as_deref(),
            );
        }
        // Interactions are session-level like receipts: a worker may raise
        // or resolve one while a snapshot burst is in flight.
        NormalizedAdapterEvent::VendorSession(vendor_session_id) => {
            ctx.managed
                .record_vendor_session(ctx.managed_session_id, &vendor_session_id);
        }
        NormalizedAdapterEvent::UpsertInteraction(interaction) => {
            ctx.sessions
                .upsert_bridge_interaction(session_id, *interaction)?;
        }
        NormalizedAdapterEvent::ResolveInteraction {
            interaction_id,
            resolution,
        } => {
            ctx.sessions
                .resolve_bridge_interaction(session_id, &interaction_id, &resolution)?;
        }
        NormalizedAdapterEvent::SessionEnded => {
            return Ok(EventOutcome::End {
                process_exited: false,
            });
        }
        NormalizedAdapterEvent::Shutdown { process_exited } => {
            return Ok(EventOutcome::End { process_exited });
        }
        // ADR 005. The machine, the project, the conversation, and the reason all go out sealed
        // under the pairing key, so the relay and Apple forward a body only the paired phone can
        // read. A device with no key still gets the relay's generic alert, which names nothing.
        //
        // The turn moves too. This hook is the only signal an attached agent gives that it is
        // blocked on the person, and without it the alert and the session row disagreed about
        // the same moment: the phone buzzed while the row still read `Unknown`.
        NormalizedAdapterEvent::Notification(kind) => {
            // The kind decides what the turn may claim; the alert below goes out regardless.
            // Latching every kind made Claude's idle reminder the top-priority "needs input"
            // on the Lock Screen — see classify_attention_kind for the measured split.
            match AgentSessionSupervisor::classify_attention_kind(&kind) {
                AttentionKind::Latches => tracing::info!(
                    session = %session_id,
                    kind = %kind,
                    "agent session wants attention"
                ),
                AttentionKind::ReportsIdle | AttentionKind::Informational => tracing::debug!(
                    session = %session_id,
                    kind = %kind,
                    "agent notification forwarded without a turn claim"
                ),
                AttentionKind::Unrecognized => {
                    // Spec 017: tolerated vendor vocabulary is tallied, never just skipped. The
                    // kind is a validated token the vendor named, not content.
                    crate::drift::note(ctx.codec.id(), "notification", "unknown_kind", &kind, None);
                    tracing::debug!(
                        session = %session_id,
                        kind = %kind,
                        "agent notification kind is outside the pinned vocabulary"
                    );
                }
            }
            if let Err(error) = ctx.sessions.note_bridge_attention(session_id, &kind) {
                tracing::debug!(error = %error, "recording an attention turn failed");
            }
            let (workspace, title) = ctx
                .sessions
                .notification_facts(session_id)
                .unwrap_or_default();
            ctx.notifier
                .notify(session_id, &workspace, title.as_deref(), &kind, unix_now());
        }
        NormalizedAdapterEvent::Unknown if !ctx.snapshot_open => {
            // Spec 017 §4.2: the visible unsupported card is also tallied, so drift is a list
            // a release can be cut against, not only a moment in one session's timeline.
            crate::drift::note(ctx.codec.id(), "bridge_frame", "unknown_frame", "", None);
            ctx.unknown_sequence = ctx.unknown_sequence.saturating_add(1).max(1);
            ctx.sessions
                .upsert_bridge_entry(session_id, unsupported_entry(ctx.unknown_sequence))?;
        }
        _ => bail!("agent bridge frame order was invalid"),
    }
    Ok(EventOutcome::Continue)
}

pub(crate) async fn handle_agent_bridge(
    mut stream: UnixStream,
    sessions: AgentSessionSupervisor,
    workers: SharedWorkerTable,
    managed: ManagedSessionDirectory,
    adoptions: std::sync::Arc<crate::codex_adopted::AdoptionRegistry>,
    notifier: Notifier,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let credentials = stream.peer_cred().context("inspect agent bridge peer")?;
    if credentials.uid() != nix::unistd::Uid::effective().as_raw() {
        bail!("agent bridge peer has the wrong account");
    }
    let peer_pid = credentials.pid().and_then(|pid| u32::try_from(pid).ok());
    let first = timeout(HOST_OPERATION_TIMEOUT, read_agent_frame(&mut stream))
        .await
        .map_err(|_| anyhow!("agent bridge registration timed out"))??;
    let mut selected = AgentAdapterRegistry::production()
        .select(&first, peer_pid)
        .map_err(|_| anyhow!("agent bridge registration was invalid"))?;
    let peer_pid = peer_pid.ok_or_else(|| anyhow!("agent bridge peer process is unavailable"))?;
    if !process_descends_from(peer_pid, selected.registration.process_id).await {
        bail!("agent bridge peer is not descended from its claimed process");
    }
    if selected.codec.requires_tui_process()
        && !process_looks_like_tui(selected.registration.process_id, selected.codec.id()).await
    {
        // The refusal is still the foreign-hook watch's signal (Spec 013 §5): this event is
        // same-uid and descent-proven, and a non-TUI Codex process — an app-server, ours or
        // anyone's — writing an adopted thread is exactly the writer the descriptor check
        // cannot see. Ciao's own adopted child matches its recorded pid and does not yield.
        if selected.codec.id() == "codex" {
            adoptions.note_hook_event(
                &selected.registration.upstream_identity,
                selected.registration.process_id,
            );
        }
        bail!("agent bridge process is not an attached interactive TUI");
    }
    // A managed worker proves it is the process this daemon spawned by
    // presenting its one-time registration token; the token is consumed here so
    // a replayed or foreign registration cannot bind to a live worker.
    if let Some(token) = managed_spawn_token(&first)
        && !workers.consume_token(&selected.registration.upstream_identity, &token)
    {
        bail!("managed worker registration token was not accepted");
    }
    let process_start = process_start_fingerprint(selected.registration.process_id)
        .await
        .ok_or_else(|| anyhow!("agent bridge process identity is unavailable"))?;
    selected.registration.process_nonce = authenticated_process_nonce(
        &selected.registration.process_nonce,
        selected.registration.process_id,
        &process_start,
    );

    let adapter_family = selected.registration.adapter_family.clone();
    let adapter_version = selected.registration.adapter_version.clone();

    if selected.codec.connection_kind() == AdapterConnectionKind::TransientEvent {
        let thread_id = selected.registration.upstream_identity.clone();
        let agent_process_id = selected.registration.process_id;
        // The foreign-hook watch (Spec 013 §5): every Codex hook event names its thread and
        // its process, and an adopted thread hearing from a process that is not Ciao's own
        // child has a foreign writer — the registry yields the adoption. Our own child's
        // events match its pid and pass through.
        if selected.codec.id() == "codex" {
            adoptions.note_hook_event(&thread_id, agent_process_id);
        }
        let registered = sessions.register_observer(selected.registration).await?;
        log_registration("observer", &adapter_family, &adapter_version, &registered);
        let registered_frame = selected.codec.registered_frame(&registered)?;
        write_agent_frame(&mut stream, &registered_frame).await?;
        return handle_transient_agent_event(
            stream,
            sessions,
            adoptions,
            notifier,
            &managed,
            shutdown,
            selected.codec,
            registered,
            AgentProcessIdentity {
                thread_id,
                process_id: agent_process_id,
            },
        )
        .await;
    }

    let (command_sender, mut command_receiver) = mpsc::channel(ADAPTER_COMMAND_CHANNEL_CAPACITY);
    // The managed directory keys its records on the Ciao session ID the
    // launcher assigned, which is the registration's upstream identity.
    let managed_session_id = selected.registration.upstream_identity.clone();
    let registered = sessions
        .register(selected.registration, command_sender)
        .await?;
    log_registration("stream", &adapter_family, &adapter_version, &registered);
    let registered_frame = selected.codec.registered_frame(&registered)?;
    write_agent_frame(&mut stream, &registered_frame).await?;

    let mut context = AdapterEventContext {
        sessions: &sessions,
        adoptions: &adoptions,
        notifier: &notifier,
        managed: &managed,
        codec: selected.codec,
        registered: &registered,
        agent: None,
        managed_session_id: &managed_session_id,
        snapshot_entries: Vec::new(),
        snapshot_bytes: 0,
        snapshot_open: false,
        unknown_sequence: 0,
    };
    let mut process_exited = false;
    // Not `read_agent_frame`: a command or shutdown winning this select! drops the read future,
    // and that function loses consumed bytes on drop — a partial frame (big snapshots
    // especially) would desync the adapter stream.
    let mut frames = crate::agent_protocol::AgentFrameReader::default();
    let result = loop {
        tokio::select! {
            incoming = frames.next(&mut stream) => {
                let body = match incoming {
                    Ok(body) => body,
                    Err(error) => break Err(anyhow!(error)),
                };
                let event = match selected.codec.decode_event(&body) {
                    Ok(event) => event,
                    Err(error) => break Err(anyhow!(error)),
                };
                match apply_adapter_event(event, &mut context) {
                    Ok(EventOutcome::Continue) => {}
                    Ok(EventOutcome::End { process_exited: exited }) => {
                        process_exited = exited;
                        break Ok(());
                    }
                    Err(error) => break Err(error),
                }
            }
            command = command_receiver.recv() => {
                let Some(command) = command else { break Ok(()); };
                let outbound = selected.codec.command_frame(command.command)
                    .map_err(|_| anyhow!("agent command mapping failed"))?;
                if let Err(error) = write_agent_frame(&mut stream, &outbound).await {
                    break Err(anyhow!(error));
                }
            }
            changed = shutdown.changed() => {
                let _ = changed;
                if let Ok(frame) = selected.codec.shutdown_frame("daemon_shutdown") {
                    let _ = write_agent_frame(&mut stream, &frame).await;
                }
                break Ok(());
            }
        }
    };
    sessions.bridge_disconnected(
        &registered.session_id,
        &registered.disconnect_token,
        process_exited,
    );
    result
}

/// Extracts a managed worker's one-time spawn token without giving the daemon
/// any other view of an adapter's registration payload.
fn managed_spawn_token(body: &[u8]) -> Option<String> {
    let value: Value = decode_agent_body(body).ok()?;
    let object = value.as_object()?;
    if object.get("adapter").and_then(Value::as_str)? != "claude-managed" {
        return None;
    }
    object
        .get("spawn_token")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn authenticated_process_nonce(nonce: &str, process_id: u32, process_start: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"ciao-agent-process-v1\0");
    hasher.update((nonce.len() as u64).to_be_bytes());
    hasher.update(nonce.as_bytes());
    hasher.update(process_id.to_be_bytes());
    hasher.update((process_start.len() as u64).to_be_bytes());
    hasher.update(process_start.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The vendor-side identity of an observed process, kept together so the transient handler can
/// reach the agent itself rather than only the session Ciao gave it.
struct AgentProcessIdentity {
    thread_id: String,
    process_id: u32,
}

#[allow(clippy::too_many_arguments)] // one call site; a params struct would be ceremony
async fn handle_transient_agent_event(
    mut stream: UnixStream,
    sessions: AgentSessionSupervisor,
    adoptions: std::sync::Arc<crate::codex_adopted::AdoptionRegistry>,
    notifier: Notifier,
    managed: &ManagedSessionDirectory,
    mut shutdown: watch::Receiver<bool>,
    codec: &dyn AttachedAgentAdapter,
    registered: RegisteredAgentSession,
    agent: AgentProcessIdentity,
) -> Result<()> {
    let body = tokio::select! {
        incoming = timeout(HOST_OPERATION_TIMEOUT, read_agent_frame(&mut stream)) => {
            incoming
                .map_err(|_| anyhow!("agent event timed out"))??
        }
        changed = shutdown.changed() => {
            let _ = changed;
            return Ok(());
        }
    };
    let event = codec
        .decode_event(&body)
        .map_err(|_| anyhow!("agent event was invalid"))?;
    let mut context = AdapterEventContext {
        sessions: &sessions,
        adoptions: &adoptions,
        notifier: &notifier,
        managed,
        codec,
        registered: &registered,
        agent: Some(&agent),
        managed_session_id: &agent.thread_id,
        snapshot_entries: Vec::new(),
        snapshot_bytes: 0,
        snapshot_open: false,
        unknown_sequence: 0,
    };
    match apply_adapter_event(event, &mut context)? {
        EventOutcome::Continue => {}
        // An observed session has no bridge lifecycle to unwind; its end is recorded directly.
        EventOutcome::End { .. } => {
            sessions.end_observed_session(&registered.session_id, registered.process_generation);
        }
    }
    let acknowledgement = codec
        .event_applied_frame()
        .map_err(|_| anyhow!("agent event acknowledgement mapping failed"))?
        .ok_or_else(|| anyhow!("transient adapter has no event acknowledgement"))?;
    write_agent_frame(&mut stream, &acknowledgement).await?;
    Ok(())
}

/// Unknown structured adapter events become categorical canonical content. Adapter objects are
/// never stringified or forwarded to the phone.
fn unsupported_entry(sequence: u64) -> NormalizedTimelineEntry {
    NormalizedTimelineEntry {
        source_id: format!("unsupported:{sequence}"),
        source_revision: 1,
        timestamp: unix_now(),
        state: "complete".into(),
        kind: "unsupported".into(),
        body: TimelineBody::Unsupported {
            reason_code: "unknown_adapter_event".into(),
        },
        truncation: Truncation {
            truncated: false,
            reason_code: None,
            original_bytes: None,
        },
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs().max(1))
}

/// The one line that says an agent reached the host. Nothing recorded an accepted registration
/// before, so a session that never appeared on the phone and a session that appeared and was
/// immediately superseded looked identical from the host: silence either way. Diagnosing it
/// meant reading the metadata store by hand over SSH.
///
/// Session and process identifiers only — never a prompt, a path, or timeline content. The
/// session ID is what a client names when it opens, so it is the field that makes "the phone is
/// asking for a session this host already replaced" visible at a glance.
fn log_registration(kind: &str, family: &str, version: &str, registered: &RegisteredAgentSession) {
    tracing::info!(
        kind,
        family,
        version,
        session = %registered.session_id,
        generation = registered.process_generation,
        "agent session registered"
    );
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;
    use tokio::net::UnixStream;

    use crate::{
        agent_protocol::TimelineBody, claude_adapter::PINNED_CLAUDE_VERSION,
        workspace::WorkspaceConfig,
    };

    use super::*;

    fn pi_registration(adapter: Option<&str>) -> Vec<u8> {
        let mut value = serde_json::json!({
            "v": 1,
            "type": "register",
            "adapter_version": "0.81.1",
            "mode": "tui",
            "session_id": "fixture-upstream-session",
            "process_nonce": "0123456789abcdef0123456789abcdef",
            "process_id": std::process::id(),
            "workspace_display": "Fixture workspace",
            "commands": {
                "prompt": true,
                "steer": true,
                "follow_up": true,
                "interrupt": true
            }
        });
        if let Some(adapter) = adapter {
            value["adapter"] = adapter.into();
        }
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn registry_selects_explicit_pi_and_bounded_legacy_registration() {
        let registry = AgentAdapterRegistry::production();
        for body in [pi_registration(Some("pi")), pi_registration(None)] {
            let selected = registry.select(&body, Some(std::process::id())).unwrap();
            assert_eq!(selected.codec.id(), "pi");
            assert_eq!(selected.registration.adapter_family, "Pi");
            assert_eq!(selected.registration.observation.coverage, "partial");
            assert_eq!(selected.registration.capabilities.history, "full");
        }
    }

    #[test]
    fn registry_selects_transient_claude_hook_adapter() {
        let body = serde_json::to_vec(&serde_json::json!({
            "v": 1,
            "type": "register",
            "adapter": "claude",
            "adapter_version": PINNED_CLAUDE_VERSION,
            "mode": "tui_hook",
            "session_id": "fixture-claude-session",
            "process_nonce": "0123456789abcdef0123456789abcdef",
            "process_id": std::process::id(),
            "workspace_display": "Fixture workspace",
            "workspace_path": "/private/synthetic/Fixture workspace"
        }))
        .unwrap();
        let selected = AgentAdapterRegistry::production()
            .select(&body, Some(std::process::id()))
            .unwrap();
        assert_eq!(selected.codec.id(), "claude");
        assert_eq!(
            selected.codec.connection_kind(),
            AdapterConnectionKind::TransientEvent
        );
        assert_eq!(selected.registration.capabilities.history, "live_tail");
    }

    #[tokio::test]
    async fn transient_claude_connection_registers_applies_and_acknowledges_one_event() {
        let temporary = tempdir().unwrap();
        let sessions = AgentSessionSupervisor::load(
            &temporary.path().join("agent-metadata.json"),
            WorkspaceConfig::with_binary_dirs(Vec::new()),
        )
        .unwrap();
        let (server, mut client) = UnixStream::pair().unwrap();
        let (_shutdown_sender, shutdown) = watch::channel(false);
        let managed = crate::managed_session::ManagedSessionDirectory::load(
            &temporary.path().join("agent-managed.json"),
            temporary.path(),
            crate::managed_session::ManagedLauncher::Fake(Default::default()),
        )
        .unwrap();
        let task = tokio::spawn(handle_agent_bridge(
            server,
            sessions.clone(),
            std::sync::Arc::new(crate::managed_worker::WorkerTable::default()),
            managed,
            std::sync::Arc::new(crate::codex_adopted::AdoptionRegistry::default()),
            Notifier::new(
                std::sync::Arc::new(parking_lot::Mutex::new(
                    crate::storage::PairedDeviceStore::load(temporary.path().join("paired.json"))
                        .unwrap(),
                )),
                "fixture-host".into(),
            ),
            shutdown,
        ));

        write_agent_frame(
            &mut client,
            &serde_json::json!({
                "v": 1,
                "type": "register",
                "adapter": "claude",
                "adapter_version": PINNED_CLAUDE_VERSION,
                "mode": "tui_hook",
                "session_id": "fixture-claude-session",
                "process_nonce": "0123456789abcdef0123456789abcdef",
                "process_id": std::process::id(),
                "workspace_display": "Fixture workspace",
                "workspace_path": "/private/synthetic/Fixture workspace"
            }),
        )
        .await
        .unwrap();
        let registered_body = read_agent_frame(&mut client).await.unwrap();
        let registered: Value = decode_agent_body(&registered_body).unwrap();
        let session_id = registered["session_id"].as_str().unwrap().to_owned();
        assert_eq!(registered["type"], "registered");

        write_agent_frame(
            &mut client,
            &serde_json::json!({
                "v": 1,
                "type": "append_text",
                "delta": {
                    "source_id": "claude.message.fixture",
                    "source_revision": 1,
                    "timestamp": 1,
                    "kind": "assistant_message",
                    "delta": "Synthetic response.",
                    "final_chunk": true,
                    "truncation": {
                        "truncated": false,
                        "reason_code": null,
                        "original_bytes": null
                    }
                }
            }),
        )
        .await
        .unwrap();
        let applied_body = read_agent_frame(&mut client).await.unwrap();
        let applied: Value = decode_agent_body(&applied_body).unwrap();
        assert_eq!(
            applied,
            serde_json::json!({"type": "event_applied", "v": 1})
        );
        task.await.unwrap().unwrap();

        let snapshot = sessions.snapshot(&session_id).unwrap();
        assert_eq!(snapshot.adapter.family, "Claude");
        assert_eq!(snapshot.capabilities.history, "live_tail");
        assert_eq!(snapshot.timeline_window.entries.len(), 1);
        assert_eq!(
            snapshot.timeline_window.entries[0].body,
            TimelineBody::Text {
                text: "Synthetic response.".into()
            }
        );
    }

    #[test]
    fn registry_rejects_unknown_or_ambiguous_adapter_dispatch() {
        let registry = AgentAdapterRegistry::production();
        let unknown = serde_json::to_vec(&serde_json::json!({
            "v": 1,
            "type": "register",
            "adapter": "unknown"
        }))
        .unwrap();
        assert!(registry.select(&unknown, None).is_err());

        let malformed = serde_json::to_vec(&serde_json::json!({
            "v": 1,
            "type": "register",
            "adapter": 7
        }))
        .unwrap();
        assert!(registry.select(&malformed, None).is_err());
    }
}
