//! Adapter-neutral live Agent Session supervisor (Spec 005 §8).
//!
//! Canonical content is held in memory only. The accompanying metadata store contains only keyed
//! upstream identity digests, opaque Ciao IDs, generations/epochs/revision seeds, adapter tokens,
//! and bounded command receipts.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;
use rand::random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    sync::{Mutex as AsyncMutex, broadcast, mpsc},
    task::JoinSet,
};

use crate::{
    agent_protocol::{
        AGENT_PROTOCOL_VERSION, AgentAdapterMetadata, AgentCapabilities, AgentCommand,
        AgentDeltaChange, AgentModelOption, AgentProtocolError, AgentServerFrame,
        AgentSessionDelta, AgentSessionDescriptor, AgentSessionList, AgentSessionSnapshot,
        CommandCapabilities, CommandReceipt, DriftNote, MAX_AGENT_FRAME_BYTES,
        MAX_COMMAND_RECEIPTS, MAX_LIVE_TEXT_DELTA_BYTES, MAX_PENDING_INTERACTIONS,
        MAX_RECENT_PROMPT_BYTES, MAX_TIMELINE_PAGE_BYTES, MAX_TIMELINE_PAGE_ENTRIES,
        MAX_TIMELINE_TEXT_BYTES, Observation, PendingInteraction, TerminalFallback, TimelineBody,
        TimelineEntry, TimelinePage, TimelineWindow, Truncation, TurnState, bounded_session_list,
        valid_opaque_id, valid_token,
    },
    agent_route::{AgentRouteProof, AgentTerminalPlan, RouteContinuity, TerminalRouteResolver},
    host_protocol::AgentTabIndex,
    process::exists as process_exists,
    storage::{atomic_write_private, validate_private_file},
    workspace::WorkspaceConfig,
};

const METADATA_VERSION: u8 = 1;
const MAX_IDENTITY_MAPPINGS: usize = 256;
const RECEIPT_TTL_SECONDS: u64 = 24 * 60 * 60;
const SUBSCRIPTION_FRAME_CAPACITY: usize = 16; // 16 × 64 KiB = the 1 MiB queue bound.
const MAX_HOST_TIMELINE_BYTES: usize = 4 * 1024 * 1024;
const MAX_HOST_TIMELINE_ENTRIES: usize = 4096;
const MAX_AGENT_METADATA_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_UPSTREAM_SOURCE_ID_BYTES: usize = 128;
/// How long a hook-reported `Running` survives without a single further hook event before the
/// claim is withdrawn (Spec 019 §8).
///
/// Measured, not chosen: across 47,861 hook events in the owner's own trace the p99 gap between
/// consecutive events is ~254 s, including the idle stretches *between* turns. Fifteen minutes is
/// roughly 3.5× that tail, and sits under Spec 018's 20-minute Live Activity stale deadline so
/// the Agents tab is never the last surface still claiming. Erring long is deliberate: too tight
/// costs a withdrawn claim, which is only ever today's behavior, while too loose costs a false one.
const TURN_CLAIM_EXPIRY_SECONDS: u64 = 15 * 60;

/// Ended-session verdicts kept for Live Activity projection (Spec 018 §7, amended 2026-08-19).
/// In-memory on purpose: a verdict is something this daemon *observed* — a pid it watched die, a
/// SessionEnd it decoded — and a restarted daemon observed nothing, so it honestly reports
/// `unknown` until the adapters speak again. Capped because a long-lived daemon ends thousands of
/// sessions and only the handful still selected on someone's Lock Screen ever matter.
const MAX_ENDED_VERDICTS: usize = 256;

/// What a vendor notification kind is allowed to do to the turn. The alert is delivered for
/// every kind regardless; this only decides the state claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AttentionKind {
    /// A person is needed: latch `AwaitingInteraction`.
    Latches,
    /// The vendor announced it is idle and waiting: may correct a stranded `Running`, only.
    ReportsIdle,
    /// Recognized and deliberately stateless.
    Informational,
    /// Outside the pinned vocabulary: stateless, and the caller tallies it as drift.
    Unrecognized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedRegistration {
    /// `resume` when the adapter picked up a conversation whose earlier turns are not in its
    /// snapshot, so the timeline can say where the visible part begins. Silence where known
    /// history should be reads as a broken session rather than an explicitly bounded one.
    pub(crate) history_boundary: Option<String>,
    pub(crate) upstream_identity: String,
    pub(crate) process_nonce: String,
    pub(crate) process_id: u32,
    pub(crate) adapter_family: String,
    pub(crate) adapter_version: String,
    /// `attached` for user-owned TUI bridges; `managed` for daemon-owned workers; `adopted`
    /// for a user-owned persisted thread the daemon holds while the phone has it open
    /// (Spec 013).
    pub(crate) topology: String,
    pub(crate) compatible: bool,
    /// Spec 017 §3: `grounded`, `ahead`, or `unsupported` — where the sighted vendor version
    /// stands against this adapter's own admission rule. `unsupported` if and only if
    /// `!compatible`; `ahead` is what puts a drift note on the descriptor.
    pub(crate) version_state: String,
    /// The pin the state was computed against, carried so the drift note can say what
    /// "tested" meant without the session layer knowing any vendor's constant.
    pub(crate) tested_version: String,
    pub(crate) workspace_display: String,
    /// Absolute working directory when the adapter reports one. Host-only, and the reason
    /// promotion can launch a managed worker where the attached session actually lives.
    pub(crate) workspace_path: Option<String>,
    pub(crate) observation: Observation,
    pub(crate) turn: TurnState,
    pub(crate) capabilities: AgentCapabilities,
    pub(crate) control_owner: String,
}

impl NormalizedRegistration {
    pub(crate) fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_source_id(&self.upstream_identity)?;
        valid_opaque_id(&self.process_nonce)?;
        valid_token(&self.adapter_family)?;
        valid_token(&self.adapter_version)?;
        valid_token(&self.control_owner)?;
        self.observation.validate()?;
        self.turn.validate()?;
        self.capabilities.validate()?;
        valid_token(&self.tested_version)?;
        if self.process_id == 0
            || self.workspace_display.is_empty()
            || self.workspace_display.len() > 256
            || !matches!(self.topology.as_str(), "attached" | "managed" | "adopted")
            || !matches!(
                self.version_state.as_str(),
                "grounded" | "carried" | "ahead" | "unsupported"
            )
            || (self.version_state == "unsupported") == self.compatible
            || (matches!(self.topology.as_str(), "managed" | "adopted")
                && self.control_owner != "none")
            || self.capabilities.terminal_continuity != "unavailable"
            || (!self.observation.is_authoritative() && self.turn.is_authoritative_working())
            || (!self.compatible && self.capabilities.commands != CommandCapabilities::none())
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedTimelineEntry {
    pub(crate) source_id: String,
    pub(crate) source_revision: u64,
    pub(crate) timestamp: u64,
    pub(crate) state: String,
    pub(crate) kind: String,
    pub(crate) body: TimelineBody,
    pub(crate) truncation: Truncation,
}

impl NormalizedTimelineEntry {
    pub(crate) fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_source_id(&self.source_id)?;
        valid_token(&self.state)?;
        valid_token(&self.kind)?;
        self.body.validate()?;
        self.truncation.validate()?;
        if self.source_revision == 0 || self.timestamp == 0 {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NormalizedTextDelta {
    pub(crate) source_id: String,
    pub(crate) source_revision: u64,
    pub(crate) timestamp: u64,
    pub(crate) kind: String,
    pub(crate) delta: String,
    pub(crate) final_chunk: bool,
    pub(crate) truncation: Truncation,
}

impl NormalizedTextDelta {
    pub(crate) fn validate(&self) -> Result<(), AgentProtocolError> {
        valid_source_id(&self.source_id)?;
        valid_token(&self.kind)?;
        self.truncation.validate()?;
        if self.source_revision == 0
            || self.timestamp == 0
            || self.delta.len() > MAX_LIVE_TEXT_DELTA_BYTES
        {
            return Err(AgentProtocolError::InvalidValue);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BridgeCommandEnvelope {
    pub(crate) command: AgentCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisteredAgentSession {
    pub(crate) session_id: String,
    pub(crate) process_generation: u64,
    pub(crate) snapshot_epoch: u64,
    pub(crate) disconnect_token: String,
}

#[derive(Debug, Clone)]
pub(crate) struct AgentSessionSupervisor {
    inner: Arc<Mutex<SupervisorInner>>,
    metadata: Arc<Mutex<AgentMetadataStore>>,
    registration_gate: Arc<AsyncMutex<()>>,
    routes: TerminalRouteResolver,
}

#[derive(Debug)]
struct SupervisorInner {
    sessions: HashMap<String, LiveSession>,
    routes: HashMap<String, RouteRecord>,
    server_epoch: u64,
    /// Transcript held for a session that does not exist yet, keyed by the ID it will register
    /// under. Takeover mints a new session for a conversation Ciao was already observing, and
    /// without this the owner watches their own history disappear at the moment they adopt it.
    /// Consumed by the first bridge snapshot and never persisted.
    carried_history: HashMap<String, Vec<TimelineEntry>>,
    /// Sessions this daemon watched end, keyed to when. Removal alone erased the evidence: a
    /// Live Activity row whose session vanished read `unknown` ("Watching") forever, when the
    /// daemon had stood there and seen the process die. Any registration for the ID revokes the
    /// verdict — a resumed session is alive, whatever was observed before.
    ended: HashMap<String, u64>,
}

#[derive(Debug)]
struct LiveSession {
    snapshot: AgentSessionSnapshot,
    workspace_display: String,
    /// Host-only launch target, present only for adapters that report one. Promotion needs
    /// it to start the managed worker where the attached session actually lives.
    workspace_path: Option<String>,
    /// The adapter's own session identity, kept raw and in memory only. Everything else
    /// works from its digest; promotion is the one caller that needs the real value, because
    /// the SDK resumes Claude's session by Claude's ID, not by Ciao's.
    upstream_identity: String,
    bridge_disconnect_token: String,
    process_id: u32,
    compatible: bool,
    offered_commands: CommandCapabilities,
    bridge_sender: Option<mpsc::Sender<BridgeCommandEnvelope>>,
    adapter_active: bool,
    /// The last `Running` turn an adapter reported and has not yet closed (Spec 019).
    ///
    /// Kept beside the snapshot rather than read back out of it because a state that outranks a
    /// run — an attention latch, an expired claim — overwrites the turn field while the run
    /// itself is still open. This is what the session hands back afterwards, so a temporary
    /// override borrows the turn instead of ending it. Cleared by any other reported turn, by
    /// session end, and by every downgrade.
    open_run: Option<TurnState>,
    source_entries: HashMap<String, SourceEntryMapping>,
    history: Vec<TimelineEntry>,
    next_sequence: u64,
    updated_at: u64,
    route_id: Option<String>,
    in_flight_commands: HashSet<String>,
    updates: broadcast::Sender<AgentServerFrame>,
}

/// An attached session that can become a managed one, resolved before any worker is spawned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PromotionTarget {
    /// Claude's own session ID, which the SDK resumes. `None` when the attached session never
    /// prompted: there is no conversation in Claude's store to resume, so the takeover starts a
    /// fresh managed session in the same workspace instead of refusing. The two are the same
    /// outcome — an empty worker in that directory — and refusing only made the person do it
    /// themselves from the New agent sheet.
    pub(crate) vendor_session_id: Option<String>,
    pub(crate) workspace_path: String,
    /// The terminal Claude holding this session. Taking over means ending it: two processes
    /// appending to one session fork silently, so exactly one has to own it.
    pub(crate) process_id: u32,
}

#[derive(Debug, Clone)]
struct SourceEntryMapping {
    entry_id: String,
    sequence: u64,
}

#[derive(Debug, Clone)]
struct RouteRecord {
    session_id: String,
    process_generation: u64,
    proof: AgentRouteProof,
}

impl AgentSessionSupervisor {
    pub(crate) fn load(path: &Path, workspace: WorkspaceConfig) -> Result<Self> {
        let metadata = AgentMetadataStore::load(path)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(SupervisorInner {
                sessions: HashMap::new(),
                routes: HashMap::new(),
                server_epoch: nonzero_random_u64(),
                carried_history: HashMap::new(),
                ended: HashMap::new(),
            })),
            metadata: Arc::new(Mutex::new(metadata)),
            registration_gate: Arc::new(AsyncMutex::new(())),
            routes: TerminalRouteResolver::new(workspace),
        })
    }

    pub(crate) fn server_epoch(&self) -> u64 {
        self.inner.lock().server_epoch
    }

    pub(crate) fn active_count(&self) -> usize {
        self.inner
            .lock()
            .sessions
            .values()
            .filter(|session| session.adapter_active)
            .count()
    }

    pub(crate) async fn register(
        &self,
        registration: NormalizedRegistration,
        sender: mpsc::Sender<BridgeCommandEnvelope>,
    ) -> Result<RegisteredAgentSession> {
        let _registration_guard = self.registration_gate.lock().await;
        let registered = self.register_new(registration, Some(sender))?;
        self.refresh_route(&registered.session_id).await;
        Ok(registered)
    }

    /// Registers a process-scoped event source whose individual IPC connections are transient.
    /// Repeated events for the same live process retain canonical history and subscribers.
    pub(crate) async fn register_observer(
        &self,
        registration: NormalizedRegistration,
    ) -> Result<RegisteredAgentSession> {
        let _registration_guard = self.registration_gate.lock().await;
        registration
            .validate()
            .map_err(|_| anyhow!("normalized observer registration is invalid"))?;
        if registration.capabilities.commands != CommandCapabilities::none() {
            bail!("a transient observer cannot advertise native commands");
        }
        if let Some(registered) = self.refresh_observer_registration(&registration)? {
            return Ok(registered);
        }
        let registered = self.register_new(registration, None)?;
        let supervisor = self.clone();
        let session_id = registered.session_id.clone();
        tokio::spawn(async move {
            supervisor.refresh_route(&session_id).await;
        });
        Ok(registered)
    }

    fn refresh_observer_registration(
        &self,
        registration: &NormalizedRegistration,
    ) -> Result<Option<RegisteredAgentSession>> {
        let Some((session_id, process_generation, snapshot_epoch)) = self
            .metadata
            .lock()
            .mapping_for_process(&registration.upstream_identity, &registration.process_nonce)
        else {
            return Ok(None);
        };
        let now = unix_now();
        let mut revision_to_persist = None;
        let registered = {
            let mut inner = self.inner.lock();
            // An event arrived for this process: it is alive, so any observed end is stale.
            inner.ended.remove(&session_id);
            let Some(session) = inner.sessions.get_mut(&session_id) else {
                return Ok(None);
            };
            if session.snapshot.process_generation != process_generation
                || session.snapshot.snapshot_epoch != snapshot_epoch
            {
                return Ok(None);
            }

            let adapter = AgentAdapterMetadata {
                family: registration.adapter_family.clone(),
                version: registration.adapter_version.clone(),
                compatibility: if registration.compatible {
                    "compatible"
                } else {
                    "unsupported_version"
                }
                .into(),
            };
            let mut capabilities = registration.capabilities.clone();
            capabilities.commands = CommandCapabilities::none();
            capabilities.terminal_continuity =
                session.snapshot.capabilities.terminal_continuity.clone();
            // The turn is deliberately not compared or copied. A registration describes the
            // process, not what it is doing: an observer re-registers on every event, so
            // carrying the turn here would reset whatever the last `Turn` event established —
            // and `NormalizedRegistration::validate` refuses a working turn anyway, which is
            // what makes Spec 005 §1's "no registration path produces a `running` turn" true.
            // A genuinely new process gets a fresh session, and `register_new` sets the turn there.
            // The drift note's *identity* (state, versions, fix) is an adapter fact; its gap
            // count is not. Counting a new unrecognized shape must not fire ResyncRequired —
            // the note is refreshed below regardless, so the next natural delta carries the
            // newer number without forcing the phone to refetch anything.
            let drift = drift_note_for(registration);
            let drift_identity_changed = match (&session.snapshot.drift, &drift) {
                (Some(old), Some(new)) => {
                    old.state != new.state
                        || old.vendor_version != new.vendor_version
                        || old.tested != new.tested
                        || old.fix != new.fix
                }
                (None, None) => false,
                _ => true,
            };
            let facts_changed = session.snapshot.adapter != adapter
                || session.snapshot.control_owner != registration.control_owner
                || session.snapshot.observation != registration.observation
                || session.snapshot.capabilities != capabilities
                || session.workspace_display != registration.workspace_display
                || drift_identity_changed;

            session.process_id = registration.process_id;
            session.snapshot.drift = drift;
            session.compatible = registration.compatible;
            session.offered_commands = CommandCapabilities::none();
            session.adapter_active = true;
            session.updated_at = now;
            session.workspace_display = registration.workspace_display.clone();
            if facts_changed {
                session.snapshot.adapter = adapter;
                session.snapshot.control_owner = registration.control_owner.clone();
                session.snapshot.observation = registration.observation.clone();
                session.snapshot.capabilities = capabilities;
                bump_revision(session);
                revision_to_persist = Some(session.snapshot.revision);
                let _ = session.updates.send(AgentServerFrame::ResyncRequired {
                    v: AGENT_PROTOCOL_VERSION,
                    session_id: session_id.clone(),
                    reason_code: "adapter_facts_changed".into(),
                });
            }
            RegisteredAgentSession {
                session_id: session_id.clone(),
                process_generation,
                snapshot_epoch,
                disconnect_token: session.bridge_disconnect_token.clone(),
            }
        };
        if let Some(revision) = revision_to_persist {
            self.metadata
                .lock()
                .update_revision(&session_id, revision)?;
        }
        Ok(Some(registered))
    }

    fn register_new(
        &self,
        registration: NormalizedRegistration,
        sender: Option<mpsc::Sender<BridgeCommandEnvelope>>,
    ) -> Result<RegisteredAgentSession> {
        registration
            .validate()
            .map_err(|_| anyhow!("normalized adapter registration is invalid"))?;
        let now = unix_now();
        let process_nonce_digest = {
            let metadata = self.metadata.lock();
            metadata.digest(&registration.process_nonce)
        };
        let mapped_session_id = self
            .metadata
            .lock()
            .mapping_for(&registration.upstream_identity)
            .map(|mapping| mapping.session_id.clone());
        // Superseding a still-registered bridge is an ambiguity boundary. Fence every accepted
        // in-flight command before replacing its sender, and carry the highest in-memory
        // revision into metadata so a same-process reconnect cannot move backward in one epoch.
        let live_revision = if let Some(session_id) = mapped_session_id.as_ref() {
            let mut inner = self.inner.lock();
            if let Some(session) = inner.sessions.get_mut(session_id) {
                let in_flight: Vec<_> = session.in_flight_commands.iter().cloned().collect();
                for command_id in in_flight {
                    let receipt = CommandReceipt {
                        command_id,
                        session_id: session_id.clone(),
                        process_generation: session.snapshot.process_generation,
                        snapshot_epoch: session.snapshot.snapshot_epoch,
                        state: "outcome_unknown".into(),
                        updated_at: now,
                        reason_code: Some("bridge_superseded".into()),
                        application_evidence: None,
                    };
                    self.persist_and_publish_receipt(session, receipt)?;
                }
                session.in_flight_commands.clear();
                Some(session.snapshot.revision)
            } else {
                None
            }
        } else {
            None
        };
        // Attached upstream IDs are vendor identities and stay behind a random Ciao mapping.
        // A managed worker is different: its upstream identity is already the random Ciao ID
        // minted by ManagedSessionDirectory before launch. Preserving it keeps lifecycle and
        // live-stream operations on one stable session identity.
        let preferred_session_id = matches!(registration.topology.as_str(), "managed" | "adopted")
            .then_some(registration.upstream_identity.as_str());
        let (session_id, process_generation, snapshot_epoch, revision) =
            self.metadata.lock().register(
                &registration.upstream_identity,
                preferred_session_id,
                &process_nonce_digest,
                &registration.adapter_family,
                &registration.adapter_version,
                live_revision,
                now,
            )?;
        let bridge_disconnect_token = random_id();

        let fallback = if registration.topology == "adopted" {
            // Spec 013 §9: adopted continuity is structural — the conversation is resumable
            // by identity, not by a proven route — so the supervisor grants it atomically
            // with the registration, and the descriptor invariant that requires it never
            // sees an intermediate state. The route resolver learns this ID when Resume in
            // Terminal lands (§7).
            TerminalFallback {
                continuity: "resumable_session".into(),
                route_id: Some(random_id()),
                availability_reason: Some("adopted_resume".into()),
                handback_session: None,
                resume_command: None,
            }
        } else {
            TerminalFallback {
                continuity: "unavailable".into(),
                route_id: None,
                availability_reason: Some("route_resolving".into()),
                handback_session: None,
                resume_command: None,
            }
        };
        let mut capabilities = registration.capabilities.clone();
        capabilities.terminal_continuity = fallback.continuity.clone();
        let snapshot = AgentSessionSnapshot {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session_id.clone(),
            snapshot_epoch,
            revision,
            process_generation,
            adapter: AgentAdapterMetadata {
                family: registration.adapter_family.clone(),
                version: registration.adapter_version.clone(),
                compatibility: if registration.compatible {
                    "compatible"
                } else {
                    "unsupported_version"
                }
                .into(),
            },
            drift: drift_note_for(&registration),
            topology: registration.topology.clone(),
            presence: "live".into(),
            stored_reason: None,
            control_owner: registration.control_owner.clone(),
            observation: registration.observation.clone(),
            turn: registration.turn.clone(),
            // Reported by the adapter over the bridge once it is up, never assumed at
            // registration: an adapter that says nothing leaves this absent, and absent
            // means unknown rather than `default`.
            permission_mode: None,
            // Same rule, and it bites harder here: a managed worker has no model until its
            // first turn names one, so there is a real window where the honest answer is that
            // Ciao does not know. The catalogue arrives on the same bridge once the worker has
            // asked the SDK what this account can run.
            model: None,
            effort: None,
            models: None,
            capabilities,
            pending_interactions: Vec::new(),
            timeline_window: TimelineWindow {
                entries: Vec::new(),
                has_older: false,
                history_boundary: registration.history_boundary.clone(),
                oldest_sequence: None,
                newest_sequence: None,
                truncated: false,
            },
            terminal_fallback: fallback,
            latest_command_receipts: self.metadata.lock().receipts_for(
                &session_id,
                process_generation,
                snapshot_epoch,
            ),
        };
        let (updates, _) = broadcast::channel(SUBSCRIPTION_FRAME_CAPACITY);
        {
            let mut inner = self.inner.lock();
            // A re-registering process supersedes any other bridge-less session it left
            // behind: an identity change across reconnects would otherwise orphan the old
            // session forever, since its process never reports a clean exit for it.
            let superseded: Vec<String> = inner
                .sessions
                .iter()
                .filter(|(id, session)| {
                    session.bridge_sender.is_none()
                        && session.process_id == registration.process_id
                        && id.as_str() != session_id
                })
                .map(|(id, _)| id.clone())
                .collect();
            for id in superseded {
                if let Some(old) = inner.sessions.remove(&id) {
                    if let Some(route_id) = old.route_id {
                        inner.routes.remove(&route_id);
                    }
                    record_ended_verdict(&mut inner.ended, &id);
                }
            }
            // Migrate mappings written by builds that remapped an already-Ciao managed ID.
            // The daemon normally restarts into this code with an empty live directory, but
            // removing an in-memory predecessor too makes the invariant local and complete.
            if let Some(previous_id) = mapped_session_id.as_ref()
                && previous_id != &session_id
                && let Some(old) = inner.sessions.remove(previous_id)
            {
                if let Some(route_id) = old.route_id {
                    inner.routes.remove(&route_id);
                }
                record_ended_verdict(&mut inner.ended, previous_id);
            }
            let mut source_entries = HashMap::new();
            let mut history = Vec::new();
            let mut next_sequence = 1;
            if let Some(mut previous) = inner.sessions.remove(&session_id) {
                if let Some(route_id) = previous.route_id.take() {
                    inner.routes.remove(&route_id);
                }
                if previous.snapshot.process_generation == process_generation
                    && previous.snapshot.snapshot_epoch == snapshot_epoch
                {
                    // Same-process reconnect retains only in-memory canonical history and opaque
                    // source mappings. A new process/epoch starts clean and cannot inherit them.
                    source_entries = previous.source_entries;
                    history = previous.history;
                    next_sequence = previous.next_sequence;
                }
            }
            let mut session = LiveSession {
                snapshot,
                workspace_display: registration.workspace_display,
                workspace_path: registration.workspace_path,
                upstream_identity: registration.upstream_identity.clone(),
                bridge_disconnect_token: bridge_disconnect_token.clone(),
                process_id: registration.process_id,
                compatible: registration.compatible,
                offered_commands: registration.capabilities.commands,
                bridge_sender: sender,
                adapter_active: true,
                open_run: None,
                source_entries,
                history,
                next_sequence,
                updated_at: now,
                route_id: None,
                in_flight_commands: HashSet::new(),
                updates,
            };
            refresh_snapshot_window(&mut session);
            inner.sessions.insert(session_id.clone(), session);
            // A registration is life: whatever end this daemon once observed for the ID, the
            // session is back, and a stale `stopped` verdict must not outlive that fact.
            inner.ended.remove(&session_id);
        }

        Ok(RegisteredAgentSession {
            session_id,
            process_generation,
            snapshot_epoch,
            disconnect_token: bridge_disconnect_token,
        })
    }

    /// The adapter's own word on the mode it is now running under, which is the only truthful
    /// source: a mode can be changed at the vendor's end too, so Ciao never assumes the last
    /// thing it asked for took effect.
    pub(crate) fn update_bridge_permission_mode(&self, session_id: &str, mode: String) {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(session_id) else {
            return;
        };
        if session.snapshot.permission_mode.as_deref() == Some(mode.as_str()) {
            return;
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.permission_mode = Some(mode.clone());
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::PermissionMode {
                permission_mode: mode,
            }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
    }

    /// The model the adapter says is answering. Same contract as the mode above: reported, not
    /// requested, and idempotent so a worker restating it costs no revision.
    pub(crate) fn update_bridge_model(&self, session_id: &str, model: String) {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(session_id) else {
            return;
        };
        if session.snapshot.model.as_deref() == Some(model.as_str()) {
            return;
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.model = Some(model.clone());
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::Model { model }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
    }

    pub(crate) fn update_bridge_effort(&self, session_id: &str, effort: String) {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(session_id) else {
            return;
        };
        if session.snapshot.effort.as_deref() == Some(effort.as_str()) {
            return;
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.effort = Some(effort.clone());
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::Effort { effort }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
    }

    /// The whole catalogue, replaced rather than merged. An adapter reads it once per process,
    /// so this normally fires exactly once; restating an identical list changes no revision.
    pub(crate) fn update_bridge_model_catalogue(
        &self,
        session_id: &str,
        models: Vec<AgentModelOption>,
    ) {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(session_id) else {
            return;
        };
        if session.snapshot.models.as_deref() == Some(models.as_slice()) {
            return;
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.models = Some(models.clone());
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::ModelCatalogue { models }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
    }

    pub(crate) fn update_bridge_commands(&self, session_id: &str, commands: CommandCapabilities) {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(session_id) else {
            return;
        };
        session.offered_commands = commands.clone();
        // Native commands are bridge-gated, not route-gated: the authenticated bridge stream is
        // the mutation authority, while terminal continuity gates only "Continue in Terminal".
        let effective = if session.compatible && session.bridge_sender.is_some() {
            commands
        } else {
            CommandCapabilities::none()
        };
        if session.snapshot.capabilities.commands == effective {
            return;
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.capabilities.commands = effective;
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::Capabilities {
                capabilities: session.snapshot.capabilities.clone(),
            }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
    }

    /// A complete bridge snapshot reconciles source entries in one transaction. Existing
    /// subscribers resync instead of receiving a guessed delta assembled from a partial tail.
    /// The transcript Ciao is currently holding for a session, for handing to the session that
    /// replaces it. Bounded by whatever the live window already enforces, so this can never carry
    /// more than the host was already willing to hold.
    pub(crate) fn timeline_for_handover(&self, session_id: &str) -> Vec<TimelineEntry> {
        let inner = self.inner.lock();
        inner
            .sessions
            .get(session_id)
            .map(|session| session.history.clone())
            .unwrap_or_default()
    }

    /// Hold a transcript for a session that has not registered yet. Must be called before the
    /// worker is spawned: its first snapshot consumes this, and a snapshot that arrives first
    /// would leave the history behind for good.
    pub(crate) fn carry_history_into(&self, session_id: &str, history: Vec<TimelineEntry>) {
        if history.is_empty() {
            return;
        }
        self.inner
            .lock()
            .carried_history
            .insert(session_id.to_owned(), history);
    }

    pub(crate) fn replace_bridge_snapshot(
        &self,
        session_id: &str,
        entries: Vec<NormalizedTimelineEntry>,
    ) -> Result<()> {
        if entries.len() > 4096 {
            bail!("bridge snapshot entry count exceeds the host memory bound");
        }
        for entry in &entries {
            entry
                .validate()
                .map_err(|_| anyhow!("normalized bridge entry is invalid"))?;
        }
        let mut inner = self.inner.lock();
        let mut inner_carried = inner.carried_history.remove(session_id);
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        let mut source_ids = HashSet::new();
        let mut history = Vec::with_capacity(entries.len());
        for mut entry in entries {
            source_ids.insert(entry.source_id.clone());
            if let Some(previous_revision) = previous_source_revision(session, &entry.source_id)
                && entry.source_revision <= previous_revision
            {
                entry.source_revision = previous_revision.saturating_add(1).max(1);
            }
            history.push(normalize_entry(session, entry));
        }
        history.sort_by_key(|entry| entry.sequence);
        session
            .source_entries
            .retain(|source_id, _| source_ids.contains(source_id));
        // A promoted session inherits the transcript Ciao already had only when the worker could
        // not supply complete history itself. A current managed worker's full snapshot is the
        // authoritative copy of that same conversation; prepending the attached adapter's copy
        // would draw every turn twice under unrelated source IDs. A live-tail fallback still puts
        // the carried entries ahead of the worker's boundary, which is where they happened.
        //
        // Both sides of that fallback were numbered from their own session's counter, so both
        // start at 1. A client requires one strictly increasing order over the window, so the
        // worker's entries are shifted above the inherited ones — and the source mapping and the
        // counter move with them, or the next upsert would reuse a sequence behind the window.
        if session.snapshot.capabilities.history != "full"
            && let Some(carried) = inner_carried.take()
        {
            let carried_count = carried.len() as u64;
            for mapping in session.source_entries.values_mut() {
                mapping.sequence = mapping.sequence.saturating_add(carried_count);
            }
            for entry in &mut history {
                entry.sequence = entry.sequence.saturating_add(carried_count);
            }
            session.next_sequence = session.next_sequence.saturating_add(carried_count);
            let mut combined = Vec::with_capacity(carried.len() + history.len());
            for (index, mut entry) in carried.into_iter().enumerate() {
                entry.sequence = index as u64 + 1;
                combined.push(entry);
            }
            combined.extend(history);
            history = combined;
        }
        session.history = history;
        enforce_history_bound(session);
        bump_revision(session);
        refresh_snapshot_window(session);
        let _ = session.updates.send(AgentServerFrame::ResyncRequired {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            reason_code: "snapshot_reconciled".into(),
        });
        self.metadata
            .lock()
            .update_revision(session_id, session.snapshot.revision)?;
        Ok(())
    }

    /// Inserts already-happened history ahead of whatever the live adapter has sent so far.
    ///
    /// Spec 012 §6 reads a Codex thread's persisted history once, and that read races the live
    /// hook tail — a prompt event landed ~20ms after session start on the grounded machine,
    /// while the read takes about a second. `replace_bridge_snapshot` would drop the live
    /// entries it does not contain, so this shifts them up instead and numbers the read
    /// entries beneath them, which is where they happened.
    ///
    /// Entries whose source is already present are skipped rather than duplicated: the live
    /// tail's version of an event is the fresher one.
    pub(crate) fn prepend_bridge_history(
        &self,
        session_id: &str,
        entries: Vec<NormalizedTimelineEntry>,
    ) -> Result<()> {
        if entries.len() > MAX_HOST_TIMELINE_ENTRIES {
            bail!("bridge history entry count exceeds the host memory bound");
        }
        for entry in &entries {
            entry
                .validate()
                .map_err(|_| anyhow!("normalized bridge history entry is invalid"))?;
        }
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        let entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| !session.source_entries.contains_key(&entry.source_id))
            .collect();
        if entries.is_empty() {
            return Ok(());
        }
        let count = entries.len() as u64;
        for mapping in session.source_entries.values_mut() {
            mapping.sequence = mapping.sequence.saturating_add(count);
        }
        for entry in &mut session.history {
            entry.sequence = entry.sequence.saturating_add(count);
        }
        session.next_sequence = session.next_sequence.saturating_add(count);

        let mut history = Vec::with_capacity(entries.len() + session.history.len());
        for (index, entry) in entries.into_iter().enumerate() {
            let sequence = index as u64 + 1;
            session.source_entries.insert(
                entry.source_id.clone(),
                SourceEntryMapping {
                    entry_id: random_id(),
                    sequence,
                },
            );
            let entry_id = session.source_entries[&entry.source_id].entry_id.clone();
            history.push(TimelineEntry {
                entry_id,
                entry_revision: entry.source_revision,
                sequence,
                timestamp: entry.timestamp,
                state: entry.state,
                kind: entry.kind,
                body: entry.body,
                truncation: entry.truncation,
            });
        }
        history.append(&mut session.history);
        session.history = history;
        enforce_history_bound(session);
        bump_revision(session);
        refresh_snapshot_window(session);
        let _ = session.updates.send(AgentServerFrame::ResyncRequired {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            reason_code: "history_reconciled".into(),
        });
        self.metadata
            .lock()
            .update_revision(session_id, session.snapshot.revision)?;
        Ok(())
    }

    pub(crate) fn upsert_bridge_entry(
        &self,
        session_id: &str,
        entry: NormalizedTimelineEntry,
    ) -> Result<()> {
        entry
            .validate()
            .map_err(|_| anyhow!("normalized bridge entry is invalid"))?;
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        let canonical = normalize_entry(session, entry);
        if let Some(existing) = session
            .history
            .iter_mut()
            .find(|candidate| candidate.entry_id == canonical.entry_id)
        {
            if canonical.entry_revision <= existing.entry_revision {
                return Ok(());
            }
            *existing = canonical.clone();
        } else {
            session.history.push(canonical.clone());
            session.history.sort_by_key(|candidate| candidate.sequence);
        }
        enforce_history_bound(session);
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        refresh_snapshot_window(session);
        let mut changes = vec![AgentDeltaChange::UpsertEntry { entry: canonical }];
        changes.extend(clear_hook_attention(session));
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes,
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        Ok(())
    }

    /// Publishes a blocking interaction raised by a managed worker. The turn is
    /// gated by the canonical reducer invariant, never by the adapter.
    pub(crate) fn upsert_bridge_interaction(
        &self,
        session_id: &str,
        interaction: PendingInteraction,
    ) -> Result<()> {
        interaction
            .validate()
            .map_err(|_| anyhow!("normalized bridge interaction is invalid"))?;
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        if let Some(existing) = session
            .snapshot
            .pending_interactions
            .iter_mut()
            .find(|candidate| candidate.interaction_id == interaction.interaction_id)
        {
            if interaction.interaction_revision <= existing.interaction_revision {
                return Ok(());
            }
            *existing = interaction.clone();
        } else {
            if session.snapshot.pending_interactions.len() >= MAX_PENDING_INTERACTIONS {
                bail!("pending interactions exceeded their bound");
            }
            session
                .snapshot
                .pending_interactions
                .push(interaction.clone());
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.turn = TurnState::AwaitingInteraction { run_id: None };
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![
                AgentDeltaChange::UpsertInteraction { interaction },
                AgentDeltaChange::Turn {
                    turn: session.snapshot.turn.clone(),
                },
            ],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        Ok(())
    }

    /// Resolves an interaction exactly once. A resolution the worker reports for
    /// an already-removed interaction is dropped rather than re-published.
    pub(crate) fn resolve_bridge_interaction(
        &self,
        session_id: &str,
        interaction_id: &str,
        resolution: &str,
    ) -> Result<()> {
        valid_opaque_id(interaction_id)
            .and_then(|()| valid_token(resolution))
            .map_err(|_| anyhow!("normalized bridge resolution is invalid"))?;
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        if !session
            .snapshot
            .pending_interactions
            .iter()
            .any(|candidate| candidate.interaction_id == interaction_id)
        {
            return Ok(());
        }
        session
            .snapshot
            .pending_interactions
            .retain(|candidate| candidate.interaction_id != interaction_id);
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        // Resolution hands the turn back to whatever was running, exactly as `clear_hook_attention`
        // already does for the hook-side latch: the run the adapter opened is not erased by the
        // card it raised mid-way. Dropping to `Unknown` here made every answered permission show
        // "Watching" until the worker's next delta. Another still-pending card keeps the latch;
        // with nothing pending and no open run, unknown remains the honest answer.
        session.snapshot.turn = if !session.snapshot.pending_interactions.is_empty() {
            TurnState::AwaitingInteraction { run_id: None }
        } else {
            session.open_run.clone().unwrap_or(TurnState::Unknown {
                reason_code: "awaiting_worker_state".into(),
            })
        };
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![
                AgentDeltaChange::RemoveInteraction {
                    interaction_id: interaction_id.to_owned(),
                    resolution: resolution.to_owned(),
                },
                AgentDeltaChange::Turn {
                    turn: session.snapshot.turn.clone(),
                },
            ],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        Ok(())
    }

    pub(crate) fn append_bridge_text(
        &self,
        session_id: &str,
        delta: NormalizedTextDelta,
    ) -> Result<()> {
        delta
            .validate()
            .map_err(|_| anyhow!("normalized adapter text delta is invalid"))?;
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        if previous_source_revision(session, &delta.source_id)
            .is_some_and(|revision| delta.source_revision <= revision)
        {
            return Ok(());
        }

        let canonical = if let Some(mapping) = session.source_entries.get(&delta.source_id).cloned()
        {
            let existing = session
                .history
                .iter_mut()
                .find(|entry| entry.entry_id == mapping.entry_id)
                .ok_or_else(|| anyhow!("adapter source mapping has no timeline entry"))?;
            if existing.kind != delta.kind {
                bail!("adapter text delta changed entry kind");
            }
            let expected_revision = existing.entry_revision.saturating_add(1);
            let gap = delta.source_revision != expected_revision;
            let TimelineBody::Text { text } = &mut existing.body else {
                bail!("adapter text delta targeted a non-text entry");
            };
            let original_bytes = existing
                .truncation
                .original_bytes
                .and_then(|bytes| usize::try_from(bytes).ok())
                .unwrap_or(text.len())
                .saturating_add(delta.delta.len());
            text.push_str(&delta.delta);
            let overflowed = truncate_utf8(text, MAX_TIMELINE_TEXT_BYTES);
            if !existing.truncation.truncated {
                if gap {
                    existing.truncation = Truncation {
                        truncated: true,
                        reason_code: Some("adapter_delta_gap".into()),
                        original_bytes: Some(original_bytes as u64),
                    };
                } else if delta.truncation.truncated {
                    existing.truncation = delta.truncation.clone();
                }
            }
            if overflowed {
                existing.truncation = Truncation {
                    truncated: true,
                    reason_code: Some("adapter_bound".into()),
                    original_bytes: Some(original_bytes as u64),
                };
            }
            existing.entry_revision = delta.source_revision;
            existing.timestamp = delta.timestamp;
            existing.state = if delta.final_chunk {
                "complete"
            } else {
                "streaming"
            }
            .into();
            existing.clone()
        } else {
            let truncation = if delta.source_revision != 1 && !delta.truncation.truncated {
                Truncation {
                    truncated: true,
                    reason_code: Some("adapter_delta_gap".into()),
                    original_bytes: Some(delta.delta.len() as u64),
                }
            } else {
                delta.truncation
            };
            normalize_entry(
                session,
                NormalizedTimelineEntry {
                    source_id: delta.source_id,
                    source_revision: delta.source_revision,
                    timestamp: delta.timestamp,
                    state: if delta.final_chunk {
                        "complete"
                    } else {
                        "streaming"
                    }
                    .into(),
                    kind: delta.kind,
                    body: TimelineBody::Text { text: delta.delta },
                    truncation,
                },
            )
        };
        if !session
            .history
            .iter()
            .any(|entry| entry.entry_id == canonical.entry_id)
        {
            session.history.push(canonical.clone());
            session.history.sort_by_key(|entry| entry.sequence);
        }
        enforce_history_bound(session);
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        refresh_snapshot_window(session);
        let mut changes = vec![AgentDeltaChange::UpsertEntry { entry: canonical }];
        changes.extend(clear_hook_attention(session));
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes,
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        Ok(())
    }

    /// Where one registered session is working, for a caller that has only its ID.
    ///
    /// Spec 008's review screen is the reason this exists: a diff opened from the Agents tab
    /// names a session rather than a terminal, and the host resolves that to a directory the
    /// same way it resolves every other phone-supplied token — by looking up something it
    /// minted itself. `None` for a managed row, whose path lives in the managed record rather
    /// than in registration (`claude_managed_adapter.rs`), and for an adapter that reports no
    /// path at all.
    pub(crate) fn workspace_path(&self, session_id: &str) -> Option<String> {
        self.inner
            .lock()
            .sessions
            .get(session_id)?
            .workspace_path
            .clone()
    }

    /// What promotion needs from an attached session, or why it cannot have it.
    ///
    /// The vendor session ID is Claude's own, forwarded raw by the hook, so a managed worker
    /// resumes the real conversation rather than being told about it. Refuses while the TUI
    /// still holds the session: two operating-system processes appending to one Claude
    /// session have nothing arbitrating between them, and the result is a silent fork rather
    /// than an error, which is worse.
    pub(crate) fn promotion_target(&self, session_id: &str) -> Result<PromotionTarget, &str> {
        let inner = self.inner.lock();
        let session = inner.sessions.get(session_id).ok_or("unknown_session")?;
        if session.snapshot.topology != "attached" {
            return Err("not_attached");
        }
        if session.snapshot.adapter.family != "Claude" {
            // Pi already accepts native control in-process; there is nothing to promote.
            return Err("promotion_unsupported");
        }
        let workspace_path = session
            .workspace_path
            .clone()
            .ok_or("workspace_path_unknown")?;
        // A session that never prompted has nothing in Claude's store to resume, the same
        // condition release refuses on from the other direction.
        //
        // In-memory history alone is not evidence of that. Hook delivery is best-effort and is
        // dropped under load — a single IPC step blowing its deadline loses the frame, and a
        // lost `UserPromptSubmit` never comes back, so a conversation with turns behind it can
        // hold no `user_message` here at all. Refusing on that made a dropped hook cost the
        // whole takeover, permanently, for a session Claude still has on disk. Falling back to
        // the transcript is the same one Ciao already trusts to *name* these rows, so a row
        // showing a title can no longer refuse to be promoted.
        let observed_a_prompt = session
            .history
            .iter()
            .any(|entry| entry.kind == "user_message");
        let resumable = has_resumable_conversation(observed_a_prompt, || {
            crate::claude_transcript::recent_prompt(
                &session.upstream_identity,
                MAX_RECENT_PROMPT_BYTES,
            )
        });
        // A live terminal is no longer a refusal. Taking over means Ciao ends it, which the
        // caller does after this resolves — together with `promotion_preflight`, which settles
        // the reasons this cannot see. Only the launch itself can still fail after the terminal
        // is gone, because it cannot be attempted any earlier.
        Ok(PromotionTarget {
            // The adapter's identity, not Ciao's: resuming Ciao's opaque session ID would
            // ask Claude for a conversation that never existed. Absent entirely when the
            // conversation itself never existed, which starts one rather than refusing.
            vendor_session_id: resumable.then(|| session.upstream_identity.clone()),
            workspace_path,
            process_id: session.process_id,
        })
    }

    /// The live list, with attached rows told which managed session already owns their
    /// conversation.
    ///
    /// Only an attached session's `upstream_identity` is the vendor's own ID — a managed
    /// worker's is the Ciao ID minted before launch — so this match is one-directional by
    /// construction and cannot pair two managed rows with each other.
    pub(crate) fn list_with_managed_owners(
        &self,
        live_vendor_owners: &std::collections::HashMap<String, String>,
    ) -> AgentSessionList {
        let inner = self.inner.lock();
        let descriptors: Vec<_> = inner
            .sessions
            .values()
            .map(|session| {
                let mut descriptor = descriptor_for(session);
                if descriptor.topology == "attached" {
                    descriptor.managed_session_id =
                        live_vendor_owners.get(&session.upstream_identity).cloned();
                }
                descriptor
            })
            .collect();
        bounded_session_list(descriptors, 0)
    }

    pub(crate) fn list(&self) -> AgentSessionList {
        let inner = self.inner.lock();
        let descriptors: Vec<_> = inner.sessions.values().map(descriptor_for).collect();
        // One list frame remains below the 64 KiB wire bound. Oldest descriptors are omitted
        // categorically if long display labels would exceed it.
        bounded_session_list(descriptors, 0)
    }

    /// What an ADR 005 notification says about a session: its workspace and the conversation's
    /// current subject. Both are sealed under the pairing key, so neither reaches the relay.
    pub(crate) fn notification_facts(&self, session_id: &str) -> Option<(String, Option<String>)> {
        let inner = self.inner.lock();
        let session = inner.sessions.get(session_id)?;
        Some((
            session.workspace_display.clone(),
            recent_prompt_for(session),
        ))
    }

    /// Records that an attached agent is blocked on the person rather than working.
    ///
    /// The `Notification` hook is the only signal an attached session gives for this, so without
    /// it a session that stopped to ask permission still reads as `Unknown` on the phone — the
    /// alert and the session row disagreeing about the same moment. Managed workers report their
    /// own turn authoritatively and are untouched: this only ever moves the turn *into*
    /// `AwaitingInteraction`, and `clear_hook_attention` only ever moves it out when nothing is
    /// actually pending.
    /// An adapter reporting its own turn boundary. Unlike attention, this replaces whatever the
    /// turn was: the worker sees the edges and Ciao does not, so a stale local guess never wins.
    /// A repeat of the current state emits nothing, so a chatty adapter cannot churn revisions.
    pub(crate) fn note_bridge_turn(&self, session_id: &str, turn: TurnState) -> Result<()> {
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        // Recorded before the equality check: an adapter re-reporting the run it already reported
        // is a no-op for the wire and still the freshest proof that the run is open.
        session.open_run = matches!(turn, TurnState::Running { .. }).then(|| turn.clone());
        if session.snapshot.turn == turn {
            return Ok(());
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.turn = turn;
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::Turn {
                turn: session.snapshot.turn.clone(),
            }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        Ok(())
    }

    /// What a vendor notification kind means for the turn (Spec 019, amended 2026-08-19).
    ///
    /// Every kind used to latch `AwaitingInteraction`, so Claude's own 60-second idle reminder —
    /// 104 of the 117 latches in the owner's daemon log, 89 of them right after a `Completed` —
    /// pinned finished sessions at the Lock Screen's highest-priority "Needs input" until the
    /// next timeline entry, which for a walked-away session is never. The kind decides now, and
    /// only a kind that names a person being needed may claim one.
    pub(crate) fn classify_attention_kind(kind: &str) -> AttentionKind {
        match kind {
            "permission_prompt" | "agent_needs_input" => AttentionKind::Latches,
            "idle_prompt" => AttentionKind::ReportsIdle,
            "auth_success" | "agent_completed" | "unspecified" => AttentionKind::Informational,
            _ => AttentionKind::Unrecognized,
        }
    }

    pub(crate) fn note_bridge_attention(&self, session_id: &str, kind: &str) -> Result<()> {
        match Self::classify_attention_kind(kind) {
            AttentionKind::Latches => {}
            AttentionKind::ReportsIdle => return self.note_bridge_idle_report(session_id),
            // Delivered as an alert by the caller; deliberately stateless here. `auth_success`
            // and `agent_completed` latching "needs input" were semantic inversions, and an
            // unrecognized kind asserting one would resurrect them under a new name.
            AttentionKind::Informational | AttentionKind::Unrecognized => return Ok(()),
        }
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        if matches!(session.snapshot.turn, TurnState::AwaitingInteraction { .. }) {
            return Ok(());
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.turn = TurnState::AwaitingInteraction { run_id: None };
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::Turn {
                turn: session.snapshot.turn.clone(),
            }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        Ok(())
    }

    /// The vendor said it is waiting for input. That is an adapter-reported idle edge, and its
    /// one job is correcting a stranded `Running` claim — a lost `Stop` (6% of closes in the
    /// owner's trace) or an interrupt no hook announces. Measured before being trusted: across
    /// two days of the owner's daemon log, `idle_prompt` arrived 14 times while a turn claimed
    /// `Running`, and not one of those turns ever completed — the reminder only ever followed a
    /// close that was lost, never a turn still in flight. It corrects within ~60 s what the
    /// 15-minute expiry bounded in theory and fired once for in practice.
    ///
    /// It may never outrank `AwaitingInteraction`: a permission prompt left unanswered draws the
    /// same reminder, and "needs input" is the truth there. And it never touches `Completed` or
    /// `Idle` — a clean close stays "done"; this is a correction, not a new lifecycle.
    fn note_bridge_idle_report(&self, session_id: &str) -> Result<()> {
        let mut inner = self.inner.lock();
        let session = inner
            .sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("registered session is unavailable"))?;
        if !matches!(session.snapshot.turn, TurnState::Running { .. }) {
            return Ok(());
        }
        session.open_run = None;
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.turn = TurnState::Idle;
        tracing::info!(
            session = %session.snapshot.session_id,
            "agent stranded turn idled by vendor idle report"
        );
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::Turn {
                turn: session.snapshot.turn.clone(),
            }],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        Ok(())
    }

    pub(crate) fn snapshot(&self, session_id: &str) -> Option<AgentSessionSnapshot> {
        let inner = self.inner.lock();
        let session = inner.sessions.get(session_id)?;
        Some(snapshot_for_wire(session))
    }

    pub(crate) fn page(
        &self,
        session_id: &str,
        before_sequence: u64,
        limit: usize,
    ) -> Option<TimelinePage> {
        if limit == 0 || limit > MAX_TIMELINE_PAGE_ENTRIES {
            return None;
        }
        let inner = self.inner.lock();
        let session = inner.sessions.get(session_id)?;
        let candidates: Vec<_> = session
            .history
            .iter()
            .filter(|entry| entry.sequence < before_sequence)
            .rev()
            .take(limit)
            .cloned()
            .collect();
        let mut entries: Vec<_> = candidates.into_iter().rev().collect();
        while page_bytes(&entries) > MAX_TIMELINE_PAGE_BYTES {
            if !entries.is_empty() {
                entries.remove(0);
            } else {
                break;
            }
        }
        let has_older = entries.first().is_some_and(|first| {
            session
                .history
                .iter()
                .any(|entry| entry.sequence < first.sequence)
        });
        let next = has_older.then(|| {
            entries
                .first()
                .map_or(before_sequence, |entry| entry.sequence)
        });
        Some(TimelinePage {
            v: AGENT_PROTOCOL_VERSION,
            message_type: "agent_timeline_page".into(),
            session_id: session_id.to_owned(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            aggregate_bytes: u32::try_from(page_bytes(&entries)).unwrap_or(u32::MAX),
            entries,
            has_older,
            next_before_sequence: next,
        })
    }

    pub(crate) fn subscribe(
        &self,
        session_id: &str,
    ) -> Option<broadcast::Receiver<AgentServerFrame>> {
        self.inner
            .lock()
            .sessions
            .get(session_id)
            .map(|session| session.updates.subscribe())
    }

    pub(crate) async fn submit_command(&self, command: AgentCommand) -> CommandReceipt {
        let now = unix_now();
        if command.validate().is_err() {
            return rejected_receipt(&command, "rejected", "invalid_command", now);
        }
        if let Some(existing) = self.metadata.lock().receipt(&command.command_id) {
            if existing.session_id == command.session_id
                && existing.snapshot_epoch == command.snapshot_epoch
                && existing.process_generation == command.expected_generation
            {
                return existing;
            }
            return rejected_receipt(&command, "rejected", "duplicate_command_id", now);
        }

        let (sender, receipt) = {
            let mut inner = self.inner.lock();
            let Some(session) = inner.sessions.get_mut(&command.session_id) else {
                return rejected_receipt(&command, "unavailable", "session_unavailable", now);
            };
            let stale = command.snapshot_epoch != session.snapshot.snapshot_epoch
                || command.expected_generation != session.snapshot.process_generation
                || command
                    .expected_revision
                    .is_some_and(|revision| revision != session.snapshot.revision);
            if stale {
                let receipt = rejected_receipt(&command, "stale", "snapshot_stale", now);
                let _ = self.persist_and_publish_receipt(session, receipt.clone());
                return receipt;
            }
            // `AgentCapabilities::permits`, not the inner `commands.permits`. The outer one
            // exists precisely because an interaction response is gated by *interaction*
            // capabilities rather than command ones; the inner one answers `false` for it
            // unconditionally, so reaching past the wrapper refused every Allow and every Deny
            // with `command_not_advertised` and told the phone the message could not be
            // delivered. The distinction was already covered by a unit test on the type — which
            // passed throughout, because the only call site that matters never went through it.
            if !session.snapshot.capabilities.permits(&command.kind) {
                let receipt =
                    rejected_receipt(&command, "unavailable", "command_not_advertised", now);
                let _ = self.persist_and_publish_receipt(session, receipt.clone());
                return receipt;
            }
            let receipt = CommandReceipt {
                command_id: command.command_id.clone(),
                session_id: command.session_id.clone(),
                process_generation: command.expected_generation,
                snapshot_epoch: command.snapshot_epoch,
                state: "sending".into(),
                updated_at: now,
                reason_code: None,
                application_evidence: None,
            };
            if self
                .persist_and_publish_receipt(session, receipt.clone())
                .is_err()
            {
                return rejected_receipt(&command, "unavailable", "receipt_store_unavailable", now);
            }
            session
                .in_flight_commands
                .insert(command.command_id.clone());
            (session.bridge_sender.clone(), receipt)
        };

        let Some(sender) = sender else {
            return self.mark_outcome_unknown(&command, "bridge_disconnected");
        };
        if sender
            .try_send(BridgeCommandEnvelope {
                command: command.clone(),
            })
            .is_err()
        {
            return self.mark_outcome_unknown(&command, "bridge_backpressure");
        }
        receipt
    }

    pub(crate) fn record_bridge_receipt(
        &self,
        session_id: &str,
        command_id: &str,
        state: &str,
        evidence: Option<&str>,
        reason_code: Option<&str>,
    ) -> Option<CommandReceipt> {
        // `outcome_unknown` is in the union deliberately: it is the worker's honest word for a
        // command whose fate it cannot know (a slash-command prompt the SDK consumed without a
        // replay, a set-model the vendor never answered), and the daemon already publishes the
        // same state from `mark_outcome_unknown`. Dropping it pinned the phone on "accepted"
        // forever — the /status spinner (2026-08-09), and the 2026-08-04 Codex wall that got
        // papered over by calling its unknowns "rejected".
        if valid_opaque_id(command_id).is_err()
            || valid_token(state).is_err()
            || evidence.is_some_and(|value| valid_token(value).is_err())
            || reason_code.is_some_and(|value| valid_token(value).is_err())
            || !matches!(
                state,
                "accepted" | "applied" | "rejected" | "outcome_unknown"
            )
            || (state == "applied" && evidence.is_none())
        {
            return None;
        }
        let mut inner = self.inner.lock();
        let session = inner.sessions.get_mut(session_id)?;
        if !session.in_flight_commands.contains(command_id) {
            return session
                .snapshot
                .latest_command_receipts
                .iter()
                .find(|receipt| receipt.command_id == command_id)
                .cloned();
        }
        let receipt = CommandReceipt {
            command_id: command_id.to_owned(),
            session_id: session_id.to_owned(),
            process_generation: session.snapshot.process_generation,
            snapshot_epoch: session.snapshot.snapshot_epoch,
            state: state.into(),
            updated_at: unix_now(),
            reason_code: reason_code.map(str::to_owned),
            application_evidence: evidence.map(str::to_owned),
        };
        self.persist_and_publish_receipt(session, receipt.clone())
            .ok()?;
        // Unknown is as final as applied or rejected: the peer has said its last word about
        // this command, and an entry left in flight would leak until the session ends.
        if matches!(state, "applied" | "rejected" | "outcome_unknown") {
            session.in_flight_commands.remove(command_id);
        }
        Some(receipt)
    }

    pub(crate) fn bridge_disconnected(
        &self,
        session_id: &str,
        disconnect_token: &str,
        process_exited: bool,
    ) {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(session_id) else {
            return;
        };
        if session.bridge_disconnect_token != disconnect_token {
            return;
        }
        if process_exited {
            if let Some(route_id) = session.route_id.take() {
                inner.routes.remove(&route_id);
            }
            inner.sessions.remove(session_id);
            record_ended_verdict(&mut inner.ended, session_id);
            return;
        }
        session.bridge_sender = None;
        session.adapter_active = false;
        let in_flight: Vec<_> = session.in_flight_commands.drain().collect();
        for command_id in in_flight {
            let receipt = CommandReceipt {
                command_id,
                session_id: session_id.to_owned(),
                process_generation: session.snapshot.process_generation,
                snapshot_epoch: session.snapshot.snapshot_epoch,
                state: "outcome_unknown".into(),
                updated_at: unix_now(),
                reason_code: Some("bridge_disconnected".into()),
                application_evidence: None,
            };
            if self
                .persist_and_publish_receipt(session, receipt.clone())
                .is_err()
            {
                self.publish_receipt(session, receipt);
            }
        }
        if session.snapshot.topology == "adopted" {
            // An abrupt bridge loss ends the hold as surely as a clean release; the record
            // left behind takes the attached shape, mirroring end_adopted_session, so the
            // adopted-implies-resumable invariant never sees a downgraded row.
            session.snapshot.topology = "attached".into();
            session.snapshot.pending_interactions.clear();
        }
        downgrade_session(session, "bridge_disconnected");
    }

    pub(crate) fn end_observed_session(&self, session_id: &str, process_generation: u64) {
        let mut inner = self.inner.lock();
        let route_id = {
            let Some(session) = inner.sessions.get_mut(session_id) else {
                return;
            };
            if session.bridge_sender.is_some()
                || session.snapshot.process_generation != process_generation
            {
                return;
            }
            session.adapter_active = false;
            let route_id = session.route_id.take();
            downgrade_session(session, "session_ended");
            route_id
        };
        if let Some(route_id) = route_id {
            inner.routes.remove(&route_id);
        }
        // The row stays in the map for the Agents list, but its turn is now `Unknown` forever.
        // The verdict is what lets a Live Activity row say `stopped` instead — the vendor
        // announced this end; `/clear` keeps the process alive, so the pid sweep never would.
        record_ended_verdict(&mut inner.ended, session_id);
    }

    /// Ends an adopted session on release (Spec 013 §5). The session becomes the user's own
    /// unheld conversation again, which is the attached shape — the flip happens before the
    /// downgrade so the adopted live-and-resumable invariant never sees downgraded values.
    /// The raw Codex thread behind an attached session row, when that is what the row is.
    /// Pick-up resolves the row a person actually tapped — live tail, ended record, either —
    /// back to its conversation, instead of requiring them to find a twin row.
    pub(crate) fn codex_thread_for_session(&self, session_id: &str) -> Option<String> {
        let inner = self.inner.lock();
        let session = inner.sessions.get(session_id)?;
        (session.snapshot.adapter.family == "Codex" && session.snapshot.topology == "attached")
            .then(|| session.upstream_identity.clone())
    }

    /// Whether any session — live or record — speaks for this upstream identity. The discovery
    /// merge uses it so one conversation is one row: the attached row carries the pick-up
    /// verb, and a duplicate unheld row never appears beside it.
    pub(crate) fn has_upstream(&self, upstream_identity: &str) -> bool {
        let inner = self.inner.lock();
        inner
            .sessions
            .values()
            .any(|session| session.upstream_identity == upstream_identity)
    }

    pub(crate) fn end_adopted_session(
        &self,
        session_id: &str,
        process_generation: u64,
        reason: &str,
    ) {
        let mut inner = self.inner.lock();
        let route_id = {
            let Some(session) = inner.sessions.get_mut(session_id) else {
                return;
            };
            if session.snapshot.topology != "adopted"
                || session.snapshot.process_generation != process_generation
            {
                return;
            }
            session.bridge_sender = None;
            session.adapter_active = false;
            let route_id = session.route_id.take();
            session.snapshot.topology = "attached".into();
            session.snapshot.pending_interactions.clear();
            downgrade_session(session, reason);
            route_id
        };
        if let Some(route_id) = route_id {
            inner.routes.remove(&route_id);
        }
    }

    pub(crate) async fn terminal_plan(
        &self,
        route_id: &str,
        expected_session: &str,
        expected_generation: u64,
    ) -> Option<AgentTerminalPlan> {
        if valid_opaque_id(route_id).is_err() {
            return None;
        }
        let record = self.inner.lock().routes.get(route_id).cloned()?;
        if record.session_id != expected_session || record.process_generation != expected_generation
        {
            return None;
        }
        let plan = self.routes.terminal_plan(&record.proof).await;
        if plan.is_none() {
            self.downgrade_if_current(
                route_id,
                &record.session_id,
                record.process_generation,
                "route_invalidated",
            );
        }
        plan
    }

    /// Removes sessions whose registered process no longer exists. A killed persistent bridge
    /// and a killed process-scoped observer both need this bounded fallback because neither is
    /// guaranteed to deliver its explicit shutdown event.
    pub(crate) fn sweep_dead_sessions(&self) {
        let mut inner = self.inner.lock();
        let dead: Vec<String> = inner
            .sessions
            .iter()
            .filter(|(_, session)| !process_exists(session.process_id))
            .map(|(id, _)| id.clone())
            .collect();
        for id in dead {
            if let Some(old) = inner.sessions.remove(&id) {
                if let Some(route_id) = old.route_id {
                    inner.routes.remove(&route_id);
                }
                record_ended_verdict(&mut inner.ended, &id);
            }
        }
    }

    /// Session IDs this daemon watched end, for the Live Activity projection. A selected row
    /// whose session is simply absent stays `unknown` — absence proves nothing — but one the
    /// daemon saw die or heard end may honestly say `stopped`.
    pub(crate) fn ended_session_ids(&self) -> HashSet<String> {
        self.inner.lock().ended.keys().cloned().collect()
    }

    /// Withdraws a working claim whose evidence has aged out (Spec 019 §3).
    ///
    /// A turn edge from a hook adapter rides a transient, fire-and-forget connection: roughly one
    /// delivery in thirty-five is lost to the delivery deadline, and a lost close leaves a session
    /// claiming work it finished. This is the bound on that. It only ever *withdraws* — the sole
    /// state it can produce is `Unknown` — because deriving `Idle` from silence would be exactly
    /// the inference ADR 003 forbids, while admitting the evidence is stale is a fact about Ciao.
    ///
    /// Scoped by structure, not by vendor: only a session with no persistent bridge can strand a
    /// claim this way. A bridge that dies takes its session's turn down with it through
    /// `downgrade_session`, so Pi, managed, and adopted sessions are never candidates and a long
    /// authoritative turn is never demoted.
    pub(crate) fn expire_stale_turn_claims(&self) {
        let now = unix_now();
        let mut inner = self.inner.lock();
        for session in inner.sessions.values_mut() {
            if session.bridge_sender.is_some()
                || !matches!(session.snapshot.turn, TurnState::Running { .. })
                || now.saturating_sub(session.updated_at) < TURN_CLAIM_EXPIRY_SECONDS
            {
                continue;
            }
            session.open_run = None;
            let base_revision = session.snapshot.revision;
            bump_revision(session);
            session.snapshot.turn = TurnState::Unknown {
                reason_code: "turn_claim_expired".into(),
            };
            tracing::info!(
                session = %session.snapshot.session_id,
                "agent turn claim expired"
            );
            let delta = AgentSessionDelta {
                v: AGENT_PROTOCOL_VERSION,
                session_id: session.snapshot.session_id.clone(),
                snapshot_epoch: session.snapshot.snapshot_epoch,
                process_generation: session.snapshot.process_generation,
                base_revision,
                revision: session.snapshot.revision,
                changes: vec![AgentDeltaChange::Turn {
                    turn: session.snapshot.turn.clone(),
                }],
            };
            let _ = session.updates.send(AgentServerFrame::SessionDelta {
                v: AGENT_PROTOCOL_VERSION,
                delta,
            });
        }
    }

    /// Revalidates every live route without holding the supervisor lock across provider I/O.
    /// The daemon calls this periodically so a replaced pane removes native controls even when
    /// no command or terminal request happens to expose the loss first.
    pub(crate) async fn revalidate_live_routes(&self) {
        let records: Vec<_> = self
            .inner
            .lock()
            .routes
            .iter()
            .map(|(route_id, record)| (route_id.clone(), record.clone()))
            .collect();
        let mut checks = JoinSet::new();
        for (route_id, record) in records {
            let routes = self.routes.clone();
            checks.spawn(async move {
                let valid = routes.revalidate(&record.proof).await;
                (route_id, record, valid)
            });
        }
        while let Some(Ok((route_id, record, valid))) = checks.join_next().await {
            if !valid {
                self.downgrade_if_current(
                    &route_id,
                    &record.session_id,
                    record.process_generation,
                    "route_invalidated",
                );
            }
        }
    }

    /// Retries sessions that are live but hold no route. Resolution is attempted exactly once,
    /// at registration, and an observer re-registers into `refresh_observer_registration`, which
    /// returns before reaching it — so a single lost attempt left the session with no Continue in
    /// Terminal and no terminal-preferring notification for the rest of its life. Measured
    /// 2026-08-19: the same pid and pane resolved, failed, then resolved again across three
    /// daemon starts, and the failing one stuck.
    ///
    /// Bounded by the caller's interval rather than per-session state: a session with genuinely
    /// no pane costs one resolve per interval, against the per-second revalidation that every
    /// session holding a route already pays.
    pub(crate) async fn recover_missing_routes(&self) {
        let candidates: Vec<String> = {
            let inner = self.inner.lock();
            inner
                .sessions
                .iter()
                .filter(|(_, session)| {
                    session.adapter_active
                        && session.route_id.is_none()
                        && session.snapshot.topology != "adopted"
                })
                .map(|(session_id, _)| session_id.clone())
                .collect()
        };
        for session_id in candidates {
            self.refresh_route(&session_id).await;
        }
    }

    /// Which agent session each live pane holds, keyed the way a workspace tab row names itself.
    /// The snapshot builder uses this to say "this tab is that conversation", which is the only
    /// thing that lets a terminal attached from the Hosts tab offer the controls a terminal
    /// opened at an agent route already offers.
    ///
    /// Read off `routes`, which holds a record only while the route is live — `revalidate_live_
    /// routes` removes an invalidated one — so a stale pane cannot be advertised as an agent's.
    /// A pane the proof cannot name a tab for is simply absent; the tab lists unannotated.
    pub(crate) fn agent_tabs(&self) -> AgentTabIndex {
        self.inner
            .lock()
            .routes
            .values()
            .filter_map(|record| Some((record.proof.tab_key()?, record.session_id.clone())))
            .collect()
    }

    pub(crate) fn session_for_route(&self, route_id: &str) -> Option<(String, u64)> {
        let inner = self.inner.lock();
        let route = inner.routes.get(route_id)?;
        Some((route.session_id.clone(), route.process_generation))
    }

    async fn refresh_route(&self, session_id: &str) {
        let route_fence = {
            let inner = self.inner.lock();
            inner
                .sessions
                .get(session_id)
                // Adopted continuity is structural (Spec 013 §9): granted at registration,
                // revoked only by release. The resolver can never prove a pane behind the
                // daemon's own vendor child, and its None verdict must not rewrite the grant
                // — one adopted-and-unavailable row makes phones reject the whole list.
                .filter(|session| session.adapter_active && session.snapshot.topology != "adopted")
                .map(|session| {
                    (
                        session.process_id,
                        session.bridge_disconnect_token.clone(),
                        session.snapshot.process_generation,
                    )
                })
        };
        let Some((process_id, disconnect_token, process_generation)) = route_fence else {
            return;
        };
        let proof = self.routes.resolve(process_id).await;
        // Kept, at debug: resolution is the one step here that can fail transiently, and its
        // outcome is invisible from the phone — an unresolved route renders as the conversation
        // opening normally. `recover_missing_routes` retries, so a `none` followed by a
        // continuity is the recovery working rather than a fault.
        tracing::debug!(
            session = session_id,
            pid = process_id,
            route = match proof.as_ref() {
                Some(proof) => proof.continuity().wire(),
                None => "none",
            },
            "agent route resolve"
        );
        let mut inner = self.inner.lock();
        if !inner.sessions.get(session_id).is_some_and(|session| {
            session.adapter_active
                && session.process_id == process_id
                && session.bridge_disconnect_token == disconnect_token
                && session.snapshot.process_generation == process_generation
        }) {
            return;
        }
        let old_route = inner
            .sessions
            .get_mut(session_id)
            .and_then(|session| session.route_id.take());
        if let Some(old_route) = old_route {
            inner.routes.remove(&old_route);
        }
        let Some(session) = inner.sessions.get_mut(session_id) else {
            return;
        };
        // Commands follow the bridge, not the route: a session with no provable terminal
        // context still accepts native prompts over the authenticated bridge stream.
        let commands = if session.compatible && session.bridge_sender.is_some() {
            session.offered_commands.clone()
        } else {
            CommandCapabilities::none()
        };
        let (fallback, route_record) = match proof {
            Some(proof) => {
                let route_id = random_id();
                let continuity = proof.continuity();
                session.route_id = Some(route_id.clone());
                (
                    TerminalFallback {
                        continuity: continuity.wire().into(),
                        route_id: Some(route_id.clone()),
                        availability_reason: (continuity == RouteContinuity::WorkspaceOnly)
                            .then(|| "exact_context_unqualified".into()),
                        handback_session: None,
                        resume_command: None,
                    },
                    Some((
                        route_id,
                        RouteRecord {
                            session_id: session_id.to_owned(),
                            process_generation: session.snapshot.process_generation,
                            proof,
                        },
                    )),
                )
            }
            None => (
                TerminalFallback {
                    continuity: "unavailable".into(),
                    route_id: None,
                    availability_reason: Some("durable_context_unavailable".into()),
                    handback_session: None,
                    resume_command: None,
                },
                None,
            ),
        };
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        session.snapshot.terminal_fallback = fallback.clone();
        session.snapshot.capabilities.terminal_continuity = fallback.continuity.clone();
        session.snapshot.capabilities.commands = commands.clone();
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session_id.to_owned(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![
                AgentDeltaChange::TerminalFallback {
                    terminal_fallback: fallback,
                },
                AgentDeltaChange::Capabilities {
                    capabilities: session.snapshot.capabilities.clone(),
                },
            ],
        };
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
        if let Some((route_id, record)) = route_record {
            inner.routes.insert(route_id, record);
        }
    }

    fn downgrade_if_current(
        &self,
        route_id: &str,
        session_id: &str,
        process_generation: u64,
        reason: &str,
    ) {
        let mut inner = self.inner.lock();
        let current = inner.sessions.get(session_id).is_some_and(|session| {
            session.route_id.as_deref() == Some(route_id)
                && session.snapshot.process_generation == process_generation
        });
        if !current {
            return;
        }
        inner.routes.remove(route_id);
        if let Some(session) = inner.sessions.get_mut(session_id) {
            session.route_id = None;
            // Route loss removes only terminal continuity. Observation, turn, and native
            // commands stay bridge-owned; downgrading them is reserved for bridge loss.
            downgrade_route(session, reason);
        }
    }

    fn persist_and_publish_receipt(
        &self,
        session: &mut LiveSession,
        receipt: CommandReceipt,
    ) -> Result<()> {
        self.metadata.lock().upsert_receipt(receipt.clone())?;
        self.publish_receipt(session, receipt);
        Ok(())
    }

    fn publish_receipt(&self, session: &mut LiveSession, receipt: CommandReceipt) {
        if let Some(existing) = session
            .snapshot
            .latest_command_receipts
            .iter_mut()
            .find(|existing| existing.command_id == receipt.command_id)
        {
            *existing = receipt.clone();
        } else {
            session
                .snapshot
                .latest_command_receipts
                .push(receipt.clone());
            if session.snapshot.latest_command_receipts.len() > MAX_COMMAND_RECEIPTS {
                session.snapshot.latest_command_receipts.remove(0);
            }
        }
        let base_revision = session.snapshot.revision;
        bump_revision(session);
        let delta = AgentSessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            session_id: session.snapshot.session_id.clone(),
            snapshot_epoch: session.snapshot.snapshot_epoch,
            process_generation: session.snapshot.process_generation,
            base_revision,
            revision: session.snapshot.revision,
            changes: vec![AgentDeltaChange::CommandReceipt {
                receipt: receipt.clone(),
            }],
        };
        let _ = session.updates.send(AgentServerFrame::CommandReceipt {
            v: AGENT_PROTOCOL_VERSION,
            receipt,
        });
        let _ = session.updates.send(AgentServerFrame::SessionDelta {
            v: AGENT_PROTOCOL_VERSION,
            delta,
        });
    }

    fn mark_outcome_unknown(&self, command: &AgentCommand, reason: &str) -> CommandReceipt {
        let mut inner = self.inner.lock();
        let Some(session) = inner.sessions.get_mut(&command.session_id) else {
            return rejected_receipt(command, "outcome_unknown", reason, unix_now());
        };
        session.in_flight_commands.remove(&command.command_id);
        let receipt = rejected_receipt(command, "outcome_unknown", reason, unix_now());
        if self
            .persist_and_publish_receipt(session, receipt.clone())
            .is_err()
        {
            self.publish_receipt(session, receipt.clone());
        }
        receipt
    }
}

fn previous_source_revision(session: &LiveSession, source_id: &str) -> Option<u64> {
    let entry_id = &session.source_entries.get(source_id)?.entry_id;
    session
        .history
        .iter()
        .find(|entry| &entry.entry_id == entry_id)
        .map(|entry| entry.entry_revision)
}

fn normalize_entry(session: &mut LiveSession, entry: NormalizedTimelineEntry) -> TimelineEntry {
    let mapping = session
        .source_entries
        .entry(entry.source_id)
        .or_insert_with(|| {
            let mapping = SourceEntryMapping {
                entry_id: random_id(),
                sequence: session.next_sequence,
            };
            session.next_sequence = session.next_sequence.saturating_add(1).max(1);
            mapping
        })
        .clone();
    TimelineEntry {
        entry_id: mapping.entry_id,
        entry_revision: entry.source_revision,
        sequence: mapping.sequence,
        timestamp: entry.timestamp,
        state: entry.state,
        kind: entry.kind,
        body: entry.body,
        truncation: entry.truncation,
    }
}

fn truncate_utf8(value: &mut String, maximum_bytes: usize) -> bool {
    if value.len() <= maximum_bytes {
        return false;
    }
    let mut boundary = maximum_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value.truncate(boundary);
    true
}

fn enforce_history_bound(session: &mut LiveSession) {
    let mut bytes: usize = session
        .history
        .iter()
        .map(TimelineEntry::decoded_bytes)
        .sum();
    while bytes > MAX_HOST_TIMELINE_BYTES || session.history.len() > MAX_HOST_TIMELINE_ENTRIES {
        let index = session
            .history
            .iter()
            .position(|entry| entry.state != "streaming")
            // A hostile bridge cannot make process memory unbounded with thousands of streaming
            // records. If no complete item exists, evict the oldest item and force subscribers
            // through the normal bounded window/resync path rather than exceed the hard cap.
            .unwrap_or(0);
        let removed = session.history.remove(index);
        bytes = bytes.saturating_sub(removed.decoded_bytes());
        session
            .source_entries
            .retain(|_, mapping| mapping.entry_id != removed.entry_id);
    }
}

fn refresh_snapshot_window(session: &mut LiveSession) {
    let mut entries: Vec<_> = session
        .history
        .iter()
        .rev()
        .take(MAX_TIMELINE_PAGE_ENTRIES)
        .cloned()
        .collect();
    entries.reverse();
    session.snapshot.timeline_window = TimelineWindow {
        has_older: session.history.len() > entries.len(),
        history_boundary: session.snapshot.timeline_window.history_boundary.clone(),
        oldest_sequence: entries.first().map(|entry| entry.sequence),
        newest_sequence: entries.last().map(|entry| entry.sequence),
        truncated: session.history.len() > entries.len(),
        entries,
    };
}

fn snapshot_for_wire(session: &LiveSession) -> AgentSessionSnapshot {
    let mut snapshot = session.snapshot.clone();
    while serde_json::to_vec(&AgentServerFrame::SessionSnapshot {
        v: AGENT_PROTOCOL_VERSION,
        snapshot: Box::new(snapshot.clone()),
    })
    .map_or(usize::MAX, |bytes| bytes.len())
        > MAX_AGENT_FRAME_BYTES
    {
        if snapshot.timeline_window.entries.is_empty() {
            break;
        }
        snapshot.timeline_window.entries.remove(0);
        snapshot.timeline_window.has_older = true;
        snapshot.timeline_window.truncated = true;
        snapshot.timeline_window.oldest_sequence = snapshot
            .timeline_window
            .entries
            .first()
            .map(|entry| entry.sequence);
    }
    snapshot
}

/// The takeover verb an attached row offers, decided in the one place vendor knowledge
/// belongs. Claude promotes — a managed worker resumes the conversation by Claude's own
/// session ID. Codex is picked up — the daemon adopts the thread through the app-server. Pi
/// offers nothing: its bridge already accepts native control inside the Pi process, so there
/// is no second writer to resolve and nothing to take over. The phone renders exactly what
/// this advertises and infers nothing from the family name.
pub(crate) fn takeover_verb(topology: &str, family: &str) -> Option<&'static str> {
    if topology != "attached" {
        return None;
    }
    match family {
        "Claude" => Some("promote"),
        "Codex" => Some("pickup"),
        _ => None,
    }
}

/// The drift note a registration puts on its snapshot and descriptor (Spec 017 §4.5), and the
/// place every registration reports its sighting for release-meta resolution (§4.4). Grounded
/// and carried rows carry no note — nothing to say, or CLI-only news; `ahead` always carries
/// one; `unsupported` carries one exactly when a released Ciao is known to ground the sighted
/// version, because "Fixed in 0.1.X" is worth a line even where the legacy banner already
/// blocks. The gap count is read at registration time, which stays fresh for the sessions that
/// can be ahead — an attached observer re-registers on every event.
fn drift_note_for(registration: &NormalizedRegistration) -> Option<DriftNote> {
    let vendor = if registration.topology == "managed" {
        "claude-managed".to_owned()
    } else {
        registration.adapter_family.to_lowercase()
    };
    crate::release_meta::sighted(
        &vendor,
        &registration.adapter_version,
        &registration.version_state,
        &registration.tested_version,
    );
    let fix = crate::release_meta::fix_for(&vendor);
    match registration.version_state.as_str() {
        "ahead" => {}
        "unsupported" if fix.is_some() => {}
        _ => return None,
    }
    let gaps = crate::drift::live_distinct_for(&vendor).min(4096) as u32;
    Some(DriftNote {
        state: registration.version_state.clone(),
        vendor_version: registration.adapter_version.clone(),
        tested: registration.tested_version.clone(),
        gaps,
        fix,
    })
}

fn descriptor_for(session: &LiveSession) -> AgentSessionDescriptor {
    AgentSessionDescriptor {
        v: AGENT_PROTOCOL_VERSION,
        session_id: session.snapshot.session_id.clone(),
        adapter_family: session.snapshot.adapter.family.clone(),
        adapter_version: session.snapshot.adapter.version.clone(),
        topology: session.snapshot.topology.clone(),
        presence: session.snapshot.presence.clone(),
        stored_reason: session.snapshot.stored_reason.clone(),
        process_generation: session.snapshot.process_generation,
        observation: session.snapshot.observation.clone(),
        turn: session.snapshot.turn.clone(),
        capabilities: session.snapshot.capabilities.clone(),
        workspace_display: session.workspace_display.clone(),
        terminal_fallback: session.snapshot.terminal_fallback.clone(),
        recent_prompt: recent_prompt_for(session),
        // Filled in by the caller, which is the only place that can see both directories.
        managed_session_id: None,
        takeover: takeover_verb(&session.snapshot.topology, &session.snapshot.adapter.family)
            .map(str::to_owned),
        drift: session.snapshot.drift.clone(),
        revision: session.snapshot.revision,
        updated_at: session.updated_at,
    }
}

/// Undoes `note_bridge_attention` once the conversation actually moves again.
///
/// Claude Code has no "the prompt was answered" hook, so progress is the signal: an entry or a
/// text delta means it is working again. Guarded on there being no `pending_interactions`, which
/// is what keeps a managed worker's genuinely blocking question from being cleared by its own
/// streaming output.
///
/// Where a run is still open, the attention latch borrowed the turn rather than ended it, so the
/// session hands it back (Spec 019). That is not an inference about the agent: the adapter opened
/// that run, never closed it, and the permission prompt that outranked it is gone.
/// Records that a session ended, bounded. Eviction is oldest-first so a fresh verdict — the one
/// most likely to be on someone's Lock Screen — is never the casualty of the cap.
fn record_ended_verdict(ended: &mut HashMap<String, u64>, session_id: &str) {
    ended.insert(session_id.to_owned(), unix_now());
    while ended.len() > MAX_ENDED_VERDICTS {
        let Some(oldest) = ended
            .iter()
            .min_by_key(|(_, at)| **at)
            .map(|(id, _)| id.clone())
        else {
            break;
        };
        ended.remove(&oldest);
    }
}

fn clear_hook_attention(session: &mut LiveSession) -> Option<AgentDeltaChange> {
    if !matches!(session.snapshot.turn, TurnState::AwaitingInteraction { .. })
        || !session.snapshot.pending_interactions.is_empty()
    {
        return None;
    }
    session.snapshot.turn = session.open_run.clone().unwrap_or(TurnState::Unknown {
        reason_code: "awaiting_agent_state".into(),
    });
    Some(AgentDeltaChange::Turn {
        turn: session.snapshot.turn.clone(),
    })
}

/// The newest user message, first line only, bounded. History is already canonical and
/// sequence-sorted, so the last matching entry is the current subject of the conversation.
/// Prompt text is content the phone is already authorized to read in full over this same
/// stream; it never reaches the control service.
/// Whether there is a Claude conversation to resume. Taken as a lazily-read fallback rather than
/// a value so the transcript is only touched when Ciao has nothing observed — that read walks
/// Claude's project directories, and the common case must not pay for it.
fn has_resumable_conversation(
    observed_a_prompt: bool,
    transcript_prompt: impl FnOnce() -> Option<String>,
) -> bool {
    observed_a_prompt || transcript_prompt().is_some()
}

fn recent_prompt_for(session: &LiveSession) -> Option<String> {
    let text = session.history.iter().rev().find_map(|entry| {
        if entry.kind != "user_message" {
            return None;
        }
        match &entry.body {
            TimelineBody::Text { text } => Some(text.as_str()),
            _ => None,
        }
    });

    let Some(text) = text else {
        // Hooks report only what was submitted while Ciao was watching, so a registration that
        // outlived its last prompt — a daemon restart, a `--resume` — leaves the conversation
        // unnamed here while Claude still holds it on disk. Claude only: another adapter's
        // upstream identity names nothing in Claude's store, and searching for it is wasted.
        if session.snapshot.adapter.family != "Claude" {
            return None;
        }
        return crate::claude_transcript::recent_prompt(
            &session.upstream_identity,
            MAX_RECENT_PROMPT_BYTES,
        );
    };

    let line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    let bounded = truncate_on_char_boundary(line, MAX_RECENT_PROMPT_BYTES);
    // Validation rejects an empty string, so never advertise one.
    (!bounded.is_empty()).then_some(bounded)
}

/// Byte bounds cannot split a UTF-8 scalar, and prompts are arbitrary user text.
pub(crate) fn truncate_on_char_boundary(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_string();
    }
    let mut end = limit;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].trim_end().to_string()
}

fn bump_revision(session: &mut LiveSession) {
    session.snapshot.revision = session.snapshot.revision.saturating_add(1).max(1);
    session.updated_at = unix_now();
}

fn downgrade_session(session: &mut LiveSession, reason: &str) {
    let base_revision = session.snapshot.revision;
    bump_revision(session);
    // Whatever run was open belonged to the adapter that just went away. Nothing may hand it
    // back afterwards.
    session.open_run = None;
    session.snapshot.observation = Observation {
        coverage: "stale".into(),
        reason_code: reason.into(),
        last_authoritative_at: session.snapshot.observation.last_authoritative_at,
    };
    session.snapshot.turn = TurnState::Unknown {
        reason_code: reason.into(),
    };
    session.snapshot.capabilities.commands = CommandCapabilities::none();
    session.snapshot.capabilities.terminal_continuity = "unavailable".into();
    session.snapshot.terminal_fallback = TerminalFallback {
        continuity: "unavailable".into(),
        route_id: None,
        availability_reason: Some(reason.into()),
        handback_session: None,
        resume_command: None,
    };
    let delta = AgentSessionDelta {
        v: AGENT_PROTOCOL_VERSION,
        session_id: session.snapshot.session_id.clone(),
        snapshot_epoch: session.snapshot.snapshot_epoch,
        process_generation: session.snapshot.process_generation,
        base_revision,
        revision: session.snapshot.revision,
        changes: vec![
            AgentDeltaChange::Observation {
                observation: session.snapshot.observation.clone(),
            },
            AgentDeltaChange::TerminalFallback {
                terminal_fallback: session.snapshot.terminal_fallback.clone(),
            },
            AgentDeltaChange::Capabilities {
                capabilities: session.snapshot.capabilities.clone(),
            },
            AgentDeltaChange::Turn {
                turn: session.snapshot.turn.clone(),
            },
        ],
    };
    let _ = session.updates.send(AgentServerFrame::SessionDelta {
        v: AGENT_PROTOCOL_VERSION,
        delta,
    });
}

fn downgrade_route(session: &mut LiveSession, reason: &str) {
    let base_revision = session.snapshot.revision;
    bump_revision(session);
    session.snapshot.terminal_fallback = TerminalFallback {
        continuity: "unavailable".into(),
        route_id: None,
        availability_reason: Some(reason.into()),
        handback_session: None,
        resume_command: None,
    };
    session.snapshot.capabilities.terminal_continuity = "unavailable".into();
    let delta = AgentSessionDelta {
        v: AGENT_PROTOCOL_VERSION,
        session_id: session.snapshot.session_id.clone(),
        snapshot_epoch: session.snapshot.snapshot_epoch,
        process_generation: session.snapshot.process_generation,
        base_revision,
        revision: session.snapshot.revision,
        changes: vec![
            AgentDeltaChange::TerminalFallback {
                terminal_fallback: session.snapshot.terminal_fallback.clone(),
            },
            AgentDeltaChange::Capabilities {
                capabilities: session.snapshot.capabilities.clone(),
            },
        ],
    };
    let _ = session.updates.send(AgentServerFrame::SessionDelta {
        v: AGENT_PROTOCOL_VERSION,
        delta,
    });
}

fn rejected_receipt(command: &AgentCommand, state: &str, reason: &str, now: u64) -> CommandReceipt {
    CommandReceipt {
        command_id: command.command_id.clone(),
        session_id: command.session_id.clone(),
        process_generation: command.expected_generation,
        snapshot_epoch: command.snapshot_epoch,
        state: state.into(),
        updated_at: now,
        reason_code: Some(reason.into()),
        application_evidence: None,
    }
}

fn page_bytes(entries: &[TimelineEntry]) -> usize {
    serde_json::to_vec(entries).map_or(usize::MAX, |bytes| bytes.len())
}

fn valid_source_id(value: &str) -> Result<(), AgentProtocolError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_UPSTREAM_SOURCE_ID_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(AgentProtocolError::InvalidValue);
    }
    Ok(())
}

fn random_id() -> String {
    format!("{:032x}", random::<u128>())
}

fn nonzero_random_u64() -> u64 {
    random::<u64>().max(1)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs().max(1))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentMetadataFile {
    v: u8,
    key: String,
    mappings: Vec<IdentityMapping>,
    receipts: Vec<CommandReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityMapping {
    upstream_digest: String,
    session_id: String,
    process_nonce_digest: String,
    adapter_family: String,
    adapter_version: String,
    process_generation: u64,
    snapshot_epoch: u64,
    revision_seed: u64,
    updated_at: u64,
}

#[derive(Debug)]
struct AgentMetadataStore {
    path: PathBuf,
    key: [u8; 32],
    mappings: Vec<IdentityMapping>,
    receipts: Vec<CommandReceipt>,
}

impl AgentMetadataStore {
    fn load(path: &Path) -> Result<Self> {
        let file = match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    bail!("Agent metadata must be a regular file");
                }
                validate_private_file(path)?;
                if metadata.len() == 0 || metadata.len() > MAX_AGENT_METADATA_FILE_BYTES {
                    bail!("Agent metadata file violates its byte bound");
                }
                let bytes = fs::read(path).context("read Agent metadata")?;
                serde_json::from_slice::<AgentMetadataFile>(&bytes)
                    .context("Agent metadata is malformed")?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => AgentMetadataFile {
                v: METADATA_VERSION,
                key: hex(&random::<[u8; 32]>()),
                mappings: Vec::new(),
                receipts: Vec::new(),
            },
            Err(error) => return Err(error).context("inspect Agent metadata"),
        };
        if file.v != METADATA_VERSION
            || file.mappings.len() > MAX_IDENTITY_MAPPINGS
            || file.receipts.len() > MAX_IDENTITY_MAPPINGS * MAX_COMMAND_RECEIPTS
        {
            bail!("Agent metadata violates its bounds");
        }
        let key =
            decode_hex_32(&file.key).ok_or_else(|| anyhow!("Agent metadata key is invalid"))?;
        for mapping in &file.mappings {
            if decode_hex_32(&mapping.upstream_digest).is_none()
                || decode_hex_32(&mapping.process_nonce_digest).is_none()
                || valid_opaque_id(&mapping.session_id).is_err()
                || valid_token(&mapping.adapter_family).is_err()
                || valid_token(&mapping.adapter_version).is_err()
                || mapping.process_generation == 0
                || mapping.snapshot_epoch == 0
                || mapping.revision_seed == 0
            {
                bail!("Agent metadata mapping is invalid");
            }
        }
        let now = unix_now();
        let receipts = file
            .receipts
            .into_iter()
            .filter(|receipt| now.saturating_sub(receipt.updated_at) <= RECEIPT_TTL_SECONDS)
            .collect();
        let store = Self {
            path: path.to_owned(),
            key,
            mappings: file.mappings,
            receipts,
        };
        store.persist()?;
        Ok(store)
    }

    fn digest(&self, value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ciao-agent-identity-v1\0");
        hasher.update(self.key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
        hex(&hasher.finalize())
    }

    fn mapping_for(&self, upstream_identity: &str) -> Option<&IdentityMapping> {
        let digest = self.digest(upstream_identity);
        self.mappings
            .iter()
            .find(|mapping| mapping.upstream_digest == digest)
    }

    fn mapping_for_process(
        &self,
        upstream_identity: &str,
        process_nonce: &str,
    ) -> Option<(String, u64, u64)> {
        let process_nonce_digest = self.digest(process_nonce);
        let mapping = self.mapping_for(upstream_identity)?;
        (mapping.process_nonce_digest == process_nonce_digest).then(|| {
            (
                mapping.session_id.clone(),
                mapping.process_generation,
                mapping.snapshot_epoch,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn register(
        &mut self,
        upstream_identity: &str,
        preferred_session_id: Option<&str>,
        process_nonce_digest: &str,
        adapter_family: &str,
        adapter_version: &str,
        live_revision: Option<u64>,
        now: u64,
    ) -> Result<(String, u64, u64, u64)> {
        if let Some(preferred) = preferred_session_id {
            valid_opaque_id(preferred).map_err(|_| anyhow!("preferred session ID is invalid"))?;
        }
        let upstream_digest = self.digest(upstream_identity);
        let position = self
            .mappings
            .iter()
            .position(|mapping| mapping.upstream_digest == upstream_digest);
        if let Some(preferred) = preferred_session_id
            && self
                .mappings
                .iter()
                .enumerate()
                .any(|(index, mapping)| Some(index) != position && mapping.session_id == preferred)
        {
            bail!("preferred session ID is already mapped");
        }
        let values = if let Some(position) = position {
            let old_session_id = self.mappings[position].session_id.clone();
            if let Some(preferred) = preferred_session_id
                && old_session_id != preferred
            {
                self.receipts
                    .retain(|receipt| receipt.session_id != old_session_id);
                self.mappings[position].session_id = preferred.into();
            }
            let mapping = &mut self.mappings[position];
            let same_process = mapping.process_nonce_digest == process_nonce_digest;
            if !same_process {
                mapping.process_generation = mapping.process_generation.saturating_add(1).max(1);
            }
            // No in-memory state means daemon continuity was lost even if the same process
            // reconnects after restart; fence old cursors with a fresh epoch.
            if !same_process || live_revision.is_none() {
                mapping.snapshot_epoch = nonzero_random_u64();
            }
            mapping.revision_seed = mapping
                .revision_seed
                .max(live_revision.unwrap_or(0))
                .saturating_add(1)
                .max(1);
            mapping.process_nonce_digest = process_nonce_digest.into();
            mapping.adapter_family = adapter_family.into();
            mapping.adapter_version = adapter_version.into();
            mapping.updated_at = now;
            (
                mapping.session_id.clone(),
                mapping.process_generation,
                mapping.snapshot_epoch,
                mapping.revision_seed,
            )
        } else {
            if self.mappings.len() >= MAX_IDENTITY_MAPPINGS {
                self.mappings.sort_by_key(|mapping| mapping.updated_at);
                self.mappings.remove(0);
            }
            let mapping = IdentityMapping {
                upstream_digest,
                session_id: preferred_session_id
                    .map(str::to_owned)
                    .unwrap_or_else(random_id),
                process_nonce_digest: process_nonce_digest.into(),
                adapter_family: adapter_family.into(),
                adapter_version: adapter_version.into(),
                process_generation: 1,
                snapshot_epoch: nonzero_random_u64(),
                revision_seed: 1,
                updated_at: now,
            };
            let values = (
                mapping.session_id.clone(),
                mapping.process_generation,
                mapping.snapshot_epoch,
                mapping.revision_seed,
            );
            self.mappings.push(mapping);
            values
        };
        self.persist()?;
        Ok(values)
    }

    fn update_revision(&mut self, session_id: &str, revision: u64) -> Result<()> {
        if let Some(mapping) = self
            .mappings
            .iter_mut()
            .find(|mapping| mapping.session_id == session_id)
        {
            mapping.revision_seed = mapping.revision_seed.max(revision);
            mapping.updated_at = unix_now();
            self.persist()?;
        }
        Ok(())
    }

    fn receipt(&self, command_id: &str) -> Option<CommandReceipt> {
        self.receipts
            .iter()
            .find(|receipt| receipt.command_id == command_id)
            .cloned()
    }

    fn receipts_for(&self, session_id: &str, generation: u64, epoch: u64) -> Vec<CommandReceipt> {
        self.receipts
            .iter()
            .filter(|receipt| {
                receipt.session_id == session_id
                    && receipt.process_generation == generation
                    && receipt.snapshot_epoch == epoch
            })
            .rev()
            .take(MAX_COMMAND_RECEIPTS)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    fn upsert_receipt(&mut self, receipt: CommandReceipt) -> Result<()> {
        if let Some(existing) = self
            .receipts
            .iter_mut()
            .find(|existing| existing.command_id == receipt.command_id)
        {
            if receipt.updated_at >= existing.updated_at {
                *existing = receipt;
            }
        } else {
            self.receipts.push(receipt);
        }
        let now = unix_now();
        self.receipts
            .retain(|receipt| now.saturating_sub(receipt.updated_at) <= RECEIPT_TTL_SECONDS);
        self.receipts.sort_by_key(|receipt| receipt.updated_at);
        while self.receipts.len() > MAX_IDENTITY_MAPPINGS * MAX_COMMAND_RECEIPTS {
            self.receipts.remove(0);
        }
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        let encoded = serde_json::to_vec_pretty(&AgentMetadataFile {
            v: METADATA_VERSION,
            key: hex(&self.key),
            mappings: self.mappings.clone(),
            receipts: self.receipts.clone(),
        })?;
        if encoded.len() as u64 > MAX_AGENT_METADATA_FILE_BYTES {
            bail!("Agent metadata encoding exceeds its byte bound");
        }
        atomic_write_private(&self.path, &encoded)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut output = [0_u8; 32];
    let (pairs, _) = value.as_bytes().as_chunks::<2>();
    for (index, pair) in pairs.iter().enumerate() {
        output[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use tempfile::tempdir;

    use crate::agent_protocol::{AgentCommandKind, InteractionCapabilities, ResponseSchema};

    use super::*;

    fn registration(nonce: &str) -> NormalizedRegistration {
        registration_with(nonce, "fixture-upstream-a", std::process::id())
    }

    fn registration_with(nonce: &str, upstream: &str, process_id: u32) -> NormalizedRegistration {
        NormalizedRegistration {
            history_boundary: None,
            upstream_identity: upstream.into(),
            process_nonce: nonce.into(),
            process_id,
            adapter_family: "Fixture".into(),
            adapter_version: "1.0.0".into(),
            topology: "attached".into(),
            compatible: true,
            version_state: "grounded".into(),
            tested_version: "1.0.0".into(),
            workspace_display: "Fixture workspace".into(),
            workspace_path: None,
            observation: Observation {
                coverage: "partial".into(),
                reason_code: "partial_fixture".into(),
                last_authoritative_at: None,
            },
            turn: TurnState::Unknown {
                reason_code: "partial_observation".into(),
            },
            capabilities: AgentCapabilities {
                history: "full".into(),
                commands: CommandCapabilities {
                    prompt: true,
                    steer: true,
                    follow_up: true,
                    interrupt: true,
                    permission_mode: false,
                    model: false,
                    effort: false,
                },
                interactions: InteractionCapabilities::none(),
                pending_rehydration: "current_process".into(),
                terminal_continuity: "unavailable".into(),
            },
            control_owner: "shared".into(),
        }
    }

    #[tokio::test]
    async fn sweep_reaps_only_bridgeless_sessions_of_dead_processes() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender_a, _receiver_a) = mpsc::channel(4);
        let alive = supervisor
            .register(registration("nonce-a"), sender_a)
            .await
            .unwrap();
        let (sender_b, _receiver_b) = mpsc::channel(4);
        let dead = supervisor
            .register(
                registration_with("nonce-b", "fixture-upstream-b", 4_000_000_000),
                sender_b,
            )
            .await
            .unwrap();
        supervisor.bridge_disconnected(&alive.session_id, &alive.disconnect_token, false);
        supervisor.bridge_disconnected(&dead.session_id, &dead.disconnect_token, false);
        supervisor.sweep_dead_sessions();
        assert!(
            supervisor.snapshot(&alive.session_id).is_some(),
            "a live process with a broken bridge stays visible"
        );
        assert!(supervisor.snapshot(&dead.session_id).is_none());
    }

    #[tokio::test]
    async fn reregistering_process_supersedes_its_bridgeless_sessions() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender_a, _receiver_a) = mpsc::channel(4);
        let old = supervisor
            .register(registration("nonce-a"), sender_a)
            .await
            .unwrap();
        supervisor.bridge_disconnected(&old.session_id, &old.disconnect_token, false);
        let (sender_b, _receiver_b) = mpsc::channel(4);
        let new = supervisor
            .register(
                registration_with("nonce-b", "fixture-upstream-b", std::process::id()),
                sender_b,
            )
            .await
            .unwrap();
        assert_ne!(old.session_id, new.session_id);
        assert_eq!(supervisor.active_count(), 1);
        assert!(supervisor.snapshot(&old.session_id).is_none());
    }

    fn managed_registration(nonce: &str, session_id: &str) -> NormalizedRegistration {
        let mut registration = registration_with(nonce, session_id, std::process::id());
        registration.topology = "managed".into();
        registration.observation = Observation {
            coverage: "authoritative".into(),
            reason_code: "worker_stream".into(),
            last_authoritative_at: None,
        };
        registration.turn = TurnState::Idle;
        registration.capabilities.history = "live_tail".into();
        registration.capabilities.commands.steer = false;
        registration.capabilities.commands.follow_up = false;
        registration.control_owner = "none".into();
        registration
    }

    /// The worker's vocabulary for a command whose fate it genuinely cannot know —
    /// `outcome_unknown` — was silently dropped by `record_bridge_receipt`, so the phone
    /// waited on "accepted" forever: the /status spinner of 2026-08-09, and the same wall
    /// Codex hit on 2026-08-04 and papered over by calling its unknowns "rejected". The
    /// daemon already publishes this state from `mark_outcome_unknown`, so carrying it from
    /// a bridge peer widens nothing a phone can receive.
    #[tokio::test]
    async fn a_workers_outcome_unknown_receipt_reaches_the_phone_and_settles_the_command() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, mut receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(managed_registration("nonce-a", "fixture-managed-a"), sender)
            .await
            .unwrap();
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        let submitted = supervisor
            .submit_command(AgentCommand {
                v: AGENT_PROTOCOL_VERSION,
                command_id: "fixture-command-a".into(),
                session_id: registered.session_id.clone(),
                snapshot_epoch: snapshot.snapshot_epoch,
                expected_generation: snapshot.process_generation,
                expected_revision: None,
                kind: AgentCommandKind::Prompt {
                    text: "/status".into(),
                },
            })
            .await;
        assert_eq!(submitted.state, "sending");
        assert!(
            receiver.recv().await.is_some(),
            "the prompt reaches the bridge"
        );

        let recorded = supervisor.record_bridge_receipt(
            &registered.session_id,
            "fixture-command-a",
            "outcome_unknown",
            None,
            Some("turn_ended"),
        );
        let receipt = recorded.expect("an unknown outcome is a final answer, not a dropped frame");
        assert_eq!(receipt.state, "outcome_unknown");
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert!(
            snapshot
                .latest_command_receipts
                .iter()
                .any(|receipt| receipt.command_id == "fixture-command-a"
                    && receipt.state == "outcome_unknown"),
            "the settled receipt is what a re-subscribing phone recovers its composer from"
        );
    }

    fn adopted_registration(nonce: &str, upstream: &str) -> NormalizedRegistration {
        let mut registration = registration_with(nonce, upstream, std::process::id());
        registration.topology = "adopted".into();
        registration.observation = Observation {
            coverage: "authoritative".into(),
            reason_code: "adopted_stream".into(),
            last_authoritative_at: None,
        };
        registration.turn = TurnState::Idle;
        registration.capabilities.history = "live_tail".into();
        registration.capabilities.commands.follow_up = false;
        registration.control_owner = "none".into();
        registration
    }

    #[tokio::test]
    async fn adopted_session_keeps_resumable_continuity_when_no_route_resolves() {
        // Spec 013 §9: adopted continuity is structural — resumable by identity, not by a
        // proven route. The route resolver can never prove a pane behind the daemon's own
        // headless vendor child, and its verdict must not revoke the registration grant:
        // one adopted-and-unavailable row makes every phone reject the entire session list.
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(
                adopted_registration("nonce-adopt-route", "fixture-upstream-adopt-route"),
                sender,
            )
            .await
            .unwrap();
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert_eq!(snapshot.topology, "adopted");
        assert_eq!(
            snapshot.capabilities.terminal_continuity,
            "resumable_session"
        );
        assert_eq!(snapshot.terminal_fallback.continuity, "resumable_session");
    }

    #[tokio::test]
    async fn adopted_session_leaves_the_adopted_shape_before_any_downgrade() {
        // A supervisor crash is a bridge loss, not a release. Whatever record is left behind
        // must not be the adopted-and-unavailable shape (Spec 013 §9) — the clean release
        // path flips to attached before downgrading, and the crash path must match.
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(
                adopted_registration("nonce-adopt-drop", "fixture-upstream-adopt-drop"),
                sender,
            )
            .await
            .unwrap();
        supervisor.bridge_disconnected(&registered.session_id, &registered.disconnect_token, false);
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert!(
            snapshot.topology != "adopted"
                || snapshot.capabilities.terminal_continuity == "resumable_session",
            "adopted implies resumable_session; a downgraded record must leave the adopted shape"
        );
    }

    #[test]
    fn adopted_registration_is_accepted_only_with_no_control_owner() {
        // Spec 013 §9: the daemon itself is the vendor client for an adopted thread. Like a
        // managed worker it registers with no external control owner — a terminal claiming
        // one would contradict the adoption preconditions the supervisor just checked.
        adopted_registration("nonce-adopt-a", "fixture-upstream-adopt-a")
            .validate()
            .unwrap();
        let mut owned = adopted_registration("nonce-adopt-b", "fixture-upstream-adopt-b");
        owned.control_owner = "terminal".into();
        assert!(owned.validate().is_err());
    }

    #[tokio::test]
    async fn managed_registration_preserves_and_migrates_the_directory_session_id() {
        let temp = tempdir().unwrap();
        let metadata = temp.path().join("agent-metadata.json");
        let first = supervisor(&metadata);
        let managed_id = "managed-directory-session";

        // Reproduce metadata written by the old path: it treated the already-Ciao managed ID
        // as a vendor identity and minted a second random ID for the live row.
        let (old_sender, _old_receiver) = mpsc::channel(4);
        let old = first
            .register(
                registration_with("nonce-old", managed_id, std::process::id()),
                old_sender,
            )
            .await
            .unwrap();
        assert_ne!(old.session_id, managed_id);
        first.bridge_disconnected(&old.session_id, &old.disconnect_token, false);

        let (sender, _receiver) = mpsc::channel(4);
        let registered = first
            .register(managed_registration("nonce-managed", managed_id), sender)
            .await
            .unwrap();
        assert_eq!(registered.session_id, managed_id);
        assert!(first.snapshot(&old.session_id).is_none());
        assert_eq!(first.snapshot(managed_id).unwrap().session_id, managed_id);

        // The repaired identity is metadata, not an in-memory alias: a daemon reload keeps it.
        drop(first);
        let reloaded = supervisor(&metadata);
        let (sender, _receiver) = mpsc::channel(4);
        let registered = reloaded
            .register(managed_registration("nonce-next", managed_id), sender)
            .await
            .unwrap();
        assert_eq!(registered.session_id, managed_id);
    }

    fn observer_registration(nonce: &str) -> NormalizedRegistration {
        let mut registration = registration(nonce);
        registration.capabilities.history = "live_tail".into();
        registration.capabilities.commands = CommandCapabilities::none();
        registration.capabilities.pending_rehydration = "none".into();
        registration.control_owner = "terminal".into();
        registration
    }

    fn text_delta(
        source: &str,
        revision: u64,
        text: &str,
        final_chunk: bool,
    ) -> NormalizedTextDelta {
        NormalizedTextDelta {
            source_id: source.into(),
            source_revision: revision,
            timestamp: revision,
            kind: "assistant_message".into(),
            delta: text.into(),
            final_chunk,
            truncation: Truncation {
                truncated: false,
                reason_code: None,
                original_bytes: None,
            },
        }
    }

    fn entry(source: &str, revision: u64, text: &str) -> NormalizedTimelineEntry {
        NormalizedTimelineEntry {
            source_id: source.into(),
            source_revision: revision,
            timestamp: 1,
            state: if revision == 1 {
                "streaming"
            } else {
                "complete"
            }
            .into(),
            kind: "assistant_message".into(),
            body: TimelineBody::Text { text: text.into() },
            truncation: Truncation {
                truncated: false,
                reason_code: None,
                original_bytes: None,
            },
        }
    }

    fn prompt_entry(source: &str, revision: u64, text: &str) -> NormalizedTimelineEntry {
        NormalizedTimelineEntry {
            kind: "user_message".into(),
            ..entry(source, revision, text)
        }
    }

    fn supervisor(path: &Path) -> AgentSessionSupervisor {
        AgentSessionSupervisor::load(path, WorkspaceConfig::with_binary_dirs(Vec::new())).unwrap()
    }

    /// An attached row kept advertising the takeover that had already created a managed
    /// session, so tapping it could only come back `already_live`. The list has to name the
    /// session that owns the conversation instead.
    #[tokio::test]
    async fn an_attached_row_names_the_managed_session_already_running_its_conversation() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let vendor = "fixture-upstream-a";
        let (sender, _receiver) = mpsc::channel(4);
        let attached = supervisor
            .register(registration("nonce-attached"), sender)
            .await
            .unwrap();

        // Nothing is running this conversation yet, so the row stays promotable.
        let untouched = supervisor.list_with_managed_owners(&HashMap::new());
        assert_eq!(
            untouched
                .sessions
                .iter()
                .find(|row| row.session_id == attached.session_id)
                .and_then(|row| row.managed_session_id.as_deref()),
            None
        );

        let owners = HashMap::from([(vendor.to_string(), "managed-owner-1".to_string())]);
        let taken = supervisor.list_with_managed_owners(&owners);
        assert_eq!(
            taken
                .sessions
                .iter()
                .find(|row| row.session_id == attached.session_id)
                .and_then(|row| row.managed_session_id.as_deref()),
            Some("managed-owner-1"),
            "the attached row must point at the session that took its conversation over"
        );
    }

    /// The `Notification` hook has to move the row the phone shows, or the alert and the session
    /// disagree about the same moment — which is what shipped before this.
    #[tokio::test]
    async fn a_notification_hook_moves_the_turn_and_progress_moves_it_back() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-attention"), sender)
            .await
            .unwrap();
        let turn = |id: &str| supervisor.snapshot(id).unwrap().turn;

        assert!(!matches!(
            turn(&registered.session_id),
            TurnState::AwaitingInteraction { .. }
        ));
        supervisor
            .note_bridge_attention(&registered.session_id, "permission_prompt")
            .unwrap();
        assert!(matches!(
            turn(&registered.session_id),
            TurnState::AwaitingInteraction { .. }
        ));

        // Claude Code has no "the prompt was answered" hook, so progress is the signal.
        supervisor
            .upsert_bridge_entry(&registered.session_id, entry("source-a", 2, "back to work"))
            .unwrap();
        assert!(!matches!(
            turn(&registered.session_id),
            TurnState::AwaitingInteraction { .. }
        ));

        // Repeating the hook is idempotent rather than a second revision bump per prompt.
        supervisor
            .note_bridge_attention(&registered.session_id, "permission_prompt")
            .unwrap();
        let revision = supervisor
            .snapshot(&registered.session_id)
            .unwrap()
            .revision;
        supervisor
            .note_bridge_attention(&registered.session_id, "permission_prompt")
            .unwrap();
        assert_eq!(
            supervisor
                .snapshot(&registered.session_id)
                .unwrap()
                .revision,
            revision
        );
    }

    /// Spec 019 §6.2. A permission prompt outranks the run it interrupts, but it borrows the turn
    /// rather than ending it: the adapter opened that run and never closed it, so once the human
    /// answers the session hands it back instead of falling to `unknown` for the rest of the turn.
    #[tokio::test]
    async fn attention_borrows_a_running_turn_and_gives_it_back() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-borrow"), sender)
            .await
            .unwrap();
        let turn = |id: &str| supervisor.snapshot(id).unwrap().turn;
        let running = TurnState::Running {
            run_id: "fixture.turn.a".into(),
            activity: "responding".into(),
        };

        supervisor
            .note_bridge_turn(&registered.session_id, running.clone())
            .unwrap();
        supervisor
            .note_bridge_attention(&registered.session_id, "permission_prompt")
            .unwrap();
        assert!(matches!(
            turn(&registered.session_id),
            TurnState::AwaitingInteraction { .. }
        ));
        supervisor
            .upsert_bridge_entry(&registered.session_id, entry("source-a", 2, "granted"))
            .unwrap();
        assert_eq!(
            turn(&registered.session_id),
            running,
            "the run the adapter never closed comes back"
        );

        // A closed run is not handed back. After `Completed` the same sequence falls to unknown,
        // because there is nothing open to return to.
        supervisor
            .note_bridge_turn(
                &registered.session_id,
                TurnState::Completed { run_id: None },
            )
            .unwrap();
        supervisor
            .note_bridge_attention(&registered.session_id, "permission_prompt")
            .unwrap();
        supervisor
            .upsert_bridge_entry(&registered.session_id, entry("source-b", 2, "idle chatter"))
            .unwrap();
        assert_eq!(
            turn(&registered.session_id),
            TurnState::Unknown {
                reason_code: "awaiting_agent_state".into()
            }
        );
    }

    /// Spec 019 §3. A hook's turn edge rides a transient connection that loses roughly one
    /// delivery in thirty-five, so a lost close would leave a session claiming work it finished.
    /// The claim expires — and expiry may only ever *withdraw*. Deriving `idle` from silence
    /// would be the inference ADR 003 forbids; admitting the evidence is stale is a fact about
    /// Ciao, and `unknown` is the vocabulary's word for it.
    #[tokio::test]
    async fn a_stranded_working_claim_expires_to_unknown_and_never_to_anything_else() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let observer = supervisor
            .register_observer(observer_registration("nonce-expiry"))
            .await
            .unwrap();
        let running = TurnState::Running {
            run_id: "fixture.turn.a".into(),
            activity: "responding".into(),
        };
        supervisor
            .note_bridge_turn(&observer.session_id, running.clone())
            .unwrap();

        // Fresh evidence is not stale evidence.
        supervisor.expire_stale_turn_claims();
        assert_eq!(
            supervisor.snapshot(&observer.session_id).unwrap().turn,
            running
        );

        let age = |supervisor: &AgentSessionSupervisor, seconds: u64| {
            let mut inner = supervisor.inner.lock();
            let session = inner.sessions.get_mut(&observer.session_id).unwrap();
            session.updated_at = session.updated_at.saturating_sub(seconds);
        };
        age(&supervisor, TURN_CLAIM_EXPIRY_SECONDS - 1);
        supervisor.expire_stale_turn_claims();
        assert_eq!(
            supervisor.snapshot(&observer.session_id).unwrap().turn,
            running,
            "a turn inside the bound is still the adapter's own claim"
        );

        age(&supervisor, 2);
        supervisor.expire_stale_turn_claims();
        assert_eq!(
            supervisor.snapshot(&observer.session_id).unwrap().turn,
            TurnState::Unknown {
                reason_code: "turn_claim_expired".into()
            }
        );
        // Withdrawn, not reinterpreted. The open run is gone too, so nothing hands it back.
        supervisor
            .note_bridge_attention(&observer.session_id, "permission_prompt")
            .unwrap();
        supervisor
            .upsert_bridge_entry(&observer.session_id, entry("source-a", 2, "later"))
            .unwrap();
        assert_eq!(
            supervisor.snapshot(&observer.session_id).unwrap().turn,
            TurnState::Unknown {
                reason_code: "awaiting_agent_state".into()
            }
        );

        // Every other state is left alone at any age: only a working claim can be stranded, and
        // expiry is not a general-purpose aging of the turn field.
        for settled in [
            TurnState::Idle,
            TurnState::Completed { run_id: None },
            TurnState::Interrupted { run_id: None },
            TurnState::AwaitingInteraction { run_id: None },
            TurnState::Failed {
                run_id: None,
                category: "fixture".into(),
            },
        ] {
            supervisor
                .note_bridge_turn(&observer.session_id, settled.clone())
                .unwrap();
            age(&supervisor, TURN_CLAIM_EXPIRY_SECONDS * 4);
            supervisor.expire_stale_turn_claims();
            assert_eq!(
                supervisor.snapshot(&observer.session_id).unwrap().turn,
                settled
            );
        }
    }

    /// The expiry is scoped by structure rather than by vendor: only a session with no persistent
    /// bridge can strand a claim, because a bridge that dies takes its turn down with it. A
    /// managed worker thinking for an hour must never be demoted by this.
    #[tokio::test]
    async fn a_session_holding_a_live_bridge_is_never_expired() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(
                managed_registration("nonce-bridge", "fixture-upstream-managed"),
                sender,
            )
            .await
            .unwrap();
        let running = TurnState::Running {
            run_id: "fixture.turn.a".into(),
            activity: "thinking".into(),
        };
        supervisor
            .note_bridge_turn(&registered.session_id, running.clone())
            .unwrap();
        {
            let mut inner = supervisor.inner.lock();
            let session = inner.sessions.get_mut(&registered.session_id).unwrap();
            session.updated_at = session
                .updated_at
                .saturating_sub(TURN_CLAIM_EXPIRY_SECONDS * 10);
        }
        supervisor.expire_stale_turn_claims();
        assert_eq!(
            supervisor.snapshot(&registered.session_id).unwrap().turn,
            running
        );
    }

    /// A managed worker reports its own turn authoritatively. Its streaming output must not clear
    /// a question it is genuinely still blocked on.
    #[tokio::test]
    async fn a_managed_workers_pending_question_survives_its_own_output() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-managed-turn"), sender)
            .await
            .unwrap();
        supervisor
            .upsert_bridge_interaction(
                &registered.session_id,
                PendingInteraction {
                    interaction_id: "interaction-0001".into(),
                    interaction_revision: 1,
                    kind: "permission".into(),
                    blocking: true,
                    created_at: 1,
                    expires_at: None,
                    title: None,
                    body: "Allow writing to the file?".into(),
                    response_schema: ResponseSchema::FreeText {
                        maximum_bytes: 1024,
                    },
                    terminal_fallback: TerminalFallback {
                        continuity: "unavailable".into(),
                        route_id: None,
                        availability_reason: Some("managed_headless".into()),
                        handback_session: None,
                        resume_command: None,
                    },
                    state: "pending".into(),
                },
            )
            .unwrap();

        supervisor
            .upsert_bridge_entry(&registered.session_id, entry("source-a", 2, "thinking"))
            .unwrap();
        assert!(matches!(
            supervisor.snapshot(&registered.session_id).unwrap().turn,
            TurnState::AwaitingInteraction { .. }
        ));
    }

    /// Spec 019 amendment (2026-08-19): only a kind that names a person being needed may latch
    /// `needs_input`. Every kind used to, so Claude's idle reminder — 104 of the 117 latches in
    /// the owner's daemon log, 89 right after a completed turn — pinned finished sessions at the
    /// Lock Screen's top-priority word until the next timeline entry, which for a walked-away
    /// session never comes. `auth_success` and `agent_completed` latching it were inversions.
    #[tokio::test]
    async fn only_a_person_needed_kind_may_latch_needs_input() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let observer = supervisor
            .register_observer(observer_registration("nonce-kinds"))
            .await
            .unwrap();
        let turn = |supervisor: &AgentSessionSupervisor| {
            supervisor.snapshot(&observer.session_id).unwrap().turn
        };
        let completed = TurnState::Completed {
            run_id: Some("fixture.turn.a".into()),
        };
        supervisor
            .note_bridge_turn(&observer.session_id, completed.clone())
            .unwrap();

        // A finished session stays finished, whatever notice the vendor sends about it —
        // including vocabulary this pin has never seen.
        for kind in [
            "idle_prompt",
            "auth_success",
            "agent_completed",
            "unspecified",
            "elicitation_prompt_from_the_future",
        ] {
            supervisor
                .note_bridge_attention(&observer.session_id, kind)
                .unwrap();
            assert_eq!(turn(&supervisor), completed, "{kind}");
        }

        // The two kinds that name a person being needed still latch.
        for (index, kind) in ["permission_prompt", "agent_needs_input"]
            .iter()
            .enumerate()
        {
            supervisor
                .note_bridge_attention(&observer.session_id, kind)
                .unwrap();
            assert!(
                matches!(turn(&supervisor), TurnState::AwaitingInteraction { .. }),
                "{kind}"
            );
            supervisor
                .upsert_bridge_entry(
                    &observer.session_id,
                    entry("source-unlatch", index as u64 + 2, "answered"),
                )
                .unwrap();
            supervisor
                .note_bridge_turn(&observer.session_id, completed.clone())
                .unwrap();
        }
    }

    /// The vendor's idle reminder is an adapter-reported edge: it may correct a stranded
    /// `Running` claim — a lost `Stop`, an interrupt no hook announces — and nothing else.
    /// Measured before being trusted: across two days of the owner's log, 14 reminders arrived
    /// during claimed turns and not one of those turns ever completed. The correction also
    /// forgets the open run, so a later un-latch cannot resurrect the claim the vendor closed.
    #[tokio::test]
    async fn an_idle_report_closes_a_stranded_running_claim_and_forgets_the_run() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let observer = supervisor
            .register_observer(observer_registration("nonce-idle-report"))
            .await
            .unwrap();
        let turn = |supervisor: &AgentSessionSupervisor| {
            supervisor.snapshot(&observer.session_id).unwrap().turn
        };
        supervisor
            .note_bridge_turn(
                &observer.session_id,
                TurnState::Running {
                    run_id: "fixture.turn.stranded".into(),
                    activity: "responding".into(),
                },
            )
            .unwrap();

        supervisor
            .note_bridge_attention(&observer.session_id, "idle_prompt")
            .unwrap();
        assert_eq!(turn(&supervisor), TurnState::Idle);

        // The run is forgotten: a latch answered by progress falls back to unknown rather than
        // restoring the claim the vendor said was over.
        supervisor
            .note_bridge_attention(&observer.session_id, "permission_prompt")
            .unwrap();
        supervisor
            .upsert_bridge_entry(&observer.session_id, entry("source-progress", 2, "back"))
            .unwrap();
        assert_eq!(
            turn(&supervisor),
            TurnState::Unknown {
                reason_code: "awaiting_agent_state".into()
            }
        );

        // On anything but `Running` the report is a no-op, revision included: a clean close
        // stays "done" — this is a correction, not a second lifecycle.
        let completed = TurnState::Completed {
            run_id: Some("fixture.turn.closed".into()),
        };
        supervisor
            .note_bridge_turn(&observer.session_id, completed.clone())
            .unwrap();
        let revision = supervisor.snapshot(&observer.session_id).unwrap().revision;
        supervisor
            .note_bridge_attention(&observer.session_id, "idle_prompt")
            .unwrap();
        assert_eq!(turn(&supervisor), completed);
        assert_eq!(
            supervisor.snapshot(&observer.session_id).unwrap().revision,
            revision
        );
    }

    /// A permission prompt left unanswered draws the same idle reminder after sixty seconds —
    /// seven such sequences in the owner's log — and "needs input" is the truth there. The
    /// reminder never outranks the latch, and the eventual answer still restores the run.
    #[tokio::test]
    async fn an_idle_report_never_overrides_a_permission_latch() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let observer = supervisor
            .register_observer(observer_registration("nonce-idle-latch"))
            .await
            .unwrap();
        let running = TurnState::Running {
            run_id: "fixture.turn.blocked".into(),
            activity: "responding".into(),
        };
        supervisor
            .note_bridge_turn(&observer.session_id, running.clone())
            .unwrap();
        supervisor
            .note_bridge_attention(&observer.session_id, "permission_prompt")
            .unwrap();
        supervisor
            .note_bridge_attention(&observer.session_id, "idle_prompt")
            .unwrap();
        assert!(matches!(
            supervisor.snapshot(&observer.session_id).unwrap().turn,
            TurnState::AwaitingInteraction { .. }
        ));

        // Progress answers the prompt and hands back the run the latch borrowed (Spec 019 §6.2).
        supervisor
            .upsert_bridge_entry(&observer.session_id, entry("source-answer", 2, "approved"))
            .unwrap();
        assert_eq!(
            supervisor.snapshot(&observer.session_id).unwrap().turn,
            running
        );
    }

    /// The daemon watched this session die, so a Live Activity row may say `stopped` instead of
    /// "Watching" forever. Absence alone still proves nothing — a restarted daemon holds no
    /// verdicts — and any registration for the ID revokes one, because a resumed session is
    /// alive whatever was observed before. A vendor-announced end is a verdict too, even while
    /// the downgraded row remains listed: `/clear` keeps the process alive, so the pid sweep
    /// alone would never catch it.
    #[tokio::test]
    async fn a_watched_death_leaves_a_stopped_verdict_until_the_id_returns() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let mut dead = observer_registration("nonce-dead");
        dead.upstream_identity = "fixture-upstream-dead".into();
        // A pid above macOS's PID_MAX: guaranteed to fail the existence probe, never to signal
        // a real process.
        dead.process_id = 999_999;
        let observer = supervisor.register_observer(dead).await.unwrap();
        assert!(supervisor.ended_session_ids().is_empty());

        supervisor.sweep_dead_sessions();
        assert!(
            !supervisor
                .list()
                .sessions
                .iter()
                .any(|session| session.session_id == observer.session_id)
        );
        assert!(
            supervisor
                .ended_session_ids()
                .contains(&observer.session_id)
        );

        // The same conversation comes back under a live process: the verdict is revoked and the
        // identity mapping hands it the same session ID.
        let mut revived = observer_registration("nonce-dead-revived");
        revived.upstream_identity = "fixture-upstream-dead".into();
        let returned = supervisor.register_observer(revived).await.unwrap();
        assert_eq!(returned.session_id, observer.session_id);
        assert!(supervisor.ended_session_ids().is_empty());

        // The vendor announcing the end is a verdict as well, while the row stays listed.
        supervisor.end_observed_session(&returned.session_id, returned.process_generation);
        assert!(
            supervisor
                .ended_session_ids()
                .contains(&returned.session_id)
        );
        assert!(
            supervisor
                .list()
                .sessions
                .iter()
                .any(|session| session.session_id == returned.session_id)
        );
    }

    /// Verdicts are bounded and the oldest is the casualty, so the fresh one — the one most
    /// likely to be on someone's Lock Screen — survives the cap.
    #[test]
    fn ended_verdicts_evict_the_oldest_at_the_cap() {
        let mut ended = HashMap::new();
        for index in 0..MAX_ENDED_VERDICTS {
            ended.insert(format!("session-{index}"), index as u64);
        }
        record_ended_verdict(&mut ended, "session-fresh");
        assert_eq!(ended.len(), MAX_ENDED_VERDICTS);
        assert!(!ended.contains_key("session-0"));
        assert!(ended.contains_key("session-fresh"));
        assert!(ended.contains_key(&format!("session-{}", MAX_ENDED_VERDICTS - 1)));
    }

    /// Answering a worker's question hands the turn back to the run it interrupted, exactly as
    /// the hook-side latch already does. Dropping to `Unknown` here made every answered managed
    /// permission read "Watching" until the worker's next delta. A second still-pending card
    /// keeps the latch, and with no open run the unknown answer remains the honest one.
    #[tokio::test]
    async fn resolving_the_last_interaction_restores_the_open_run() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-resolve-restore"), sender)
            .await
            .unwrap();
        let turn = |supervisor: &AgentSessionSupervisor| {
            supervisor.snapshot(&registered.session_id).unwrap().turn
        };
        let interaction = |id: &str| PendingInteraction {
            interaction_id: id.into(),
            interaction_revision: 1,
            kind: "permission".into(),
            blocking: true,
            created_at: 1,
            expires_at: None,
            title: None,
            body: "Allow writing to the file?".into(),
            response_schema: ResponseSchema::FreeText {
                maximum_bytes: 1024,
            },
            terminal_fallback: TerminalFallback {
                continuity: "unavailable".into(),
                route_id: None,
                availability_reason: Some("managed_headless".into()),
                handback_session: None,
                resume_command: None,
            },
            state: "pending".into(),
        };
        let running = TurnState::Running {
            run_id: "run-1".into(),
            activity: "working".into(),
        };
        supervisor
            .note_bridge_turn(&registered.session_id, running.clone())
            .unwrap();
        supervisor
            .upsert_bridge_interaction(&registered.session_id, interaction("interaction-0001"))
            .unwrap();
        supervisor
            .upsert_bridge_interaction(&registered.session_id, interaction("interaction-0002"))
            .unwrap();

        // One card answered, one still up: the session is still waiting on a person.
        supervisor
            .resolve_bridge_interaction(&registered.session_id, "interaction-0001", "allow")
            .unwrap();
        assert!(matches!(
            turn(&supervisor),
            TurnState::AwaitingInteraction { .. }
        ));

        // The last answer returns the turn to the run the cards interrupted.
        supervisor
            .resolve_bridge_interaction(&registered.session_id, "interaction-0002", "allow")
            .unwrap();
        assert_eq!(turn(&supervisor), running);

        // With no open run there is nothing to hand back, and unknown stays the honest answer.
        supervisor
            .note_bridge_turn(
                &registered.session_id,
                TurnState::Completed {
                    run_id: Some("run-1".into()),
                },
            )
            .unwrap();
        supervisor
            .upsert_bridge_interaction(&registered.session_id, interaction("interaction-0003"))
            .unwrap();
        supervisor
            .resolve_bridge_interaction(&registered.session_id, "interaction-0003", "allow")
            .unwrap();
        assert_eq!(
            turn(&supervisor),
            TurnState::Unknown {
                reason_code: "awaiting_worker_state".into()
            }
        );
    }

    /// Hook delivery is best-effort: a single IPC step blowing its deadline drops the frame, and
    /// a dropped `UserPromptSubmit` never returns. Refusing promotion on observed history alone
    /// therefore cost the whole takeover, permanently, for a conversation Claude still held on
    /// disk — so an unobserved prompt must fall through to the transcript, and only a session
    /// neither source knows may refuse.
    #[test]
    fn a_conversation_is_resumable_when_either_source_knows_a_prompt() {
        assert!(
            has_resumable_conversation(true, || panic!(
                "the transcript must not be read when \
                Ciao already observed the prompt — that read walks Claude's project directories"
            )),
            "an observed prompt is enough on its own"
        );
        assert!(
            has_resumable_conversation(false, || Some("bonjour".into())),
            "a prompt Ciao missed but Claude still holds is still resumable"
        );
        assert!(
            !has_resumable_conversation(false, || None),
            "a session neither source knows has nothing to resume"
        );
    }

    #[tokio::test]
    async fn promotion_target_names_claudes_session_and_refuses_a_live_terminal() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let mut facts = registration("nonce-promote");
        facts.adapter_family = "Claude".into();
        facts.upstream_identity = "claude-vendor-session-0001".into();
        facts.workspace_path = Some(temp.path().to_string_lossy().into_owned());
        // A live process is the current one, so the terminal still owns the session.
        facts.process_id = std::process::id();
        let registered = supervisor.register(facts, sender).await.unwrap();

        // Nothing has been prompted, so there is no conversation in Claude's store to resume.
        // That is no longer a refusal: the takeover proceeds and starts a fresh managed session
        // in the same workspace, which is the identical outcome to refusing and making the
        // person open the New agent sheet themselves.
        let empty = supervisor
            .promotion_target(&registered.session_id)
            .expect("an empty conversation is started, not refused");
        assert_eq!(empty.vendor_session_id, None);
        assert_eq!(empty.workspace_path, temp.path().to_string_lossy());
        supervisor
            .replace_bridge_snapshot(
                &registered.session_id,
                vec![prompt_entry("source-a", 1, "Fix the login bug")],
            )
            .unwrap();

        // Now it has one. A live terminal no longer refuses: taking over means Ciao ends it,
        // so this reports the process to end rather than declining because it is running.
        let target = supervisor
            .promotion_target(&registered.session_id)
            .expect("a live terminal is a takeover, not a refusal");
        assert_eq!(
            target.vendor_session_id.as_deref(),
            Some("claude-vendor-session-0001")
        );
        assert_eq!(
            target.process_id,
            std::process::id(),
            "the caller ends this process before a worker resumes the conversation"
        );
        assert_eq!(
            supervisor.promotion_target("no-such-session"),
            Err("unknown_session")
        );
    }

    #[tokio::test]
    async fn registration_uses_adapter_facts_instead_of_pi_shaped_defaults() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let mut facts = registration("nonce-a");
        facts.observation = Observation {
            coverage: "authoritative".into(),
            reason_code: "fixture_authoritative".into(),
            last_authoritative_at: Some(1),
        };
        facts.turn = TurnState::Idle;
        facts.capabilities.history = "live_tail".into();
        facts.capabilities.commands = CommandCapabilities::none();
        facts.capabilities.pending_rehydration = "none".into();
        facts.control_owner = "terminal".into();
        let (sender, _) = mpsc::channel(4);
        let registered = supervisor.register(facts, sender).await.unwrap();
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert_eq!(snapshot.observation.coverage, "authoritative");
        assert!(matches!(snapshot.turn, TurnState::Idle));
        assert_eq!(snapshot.capabilities.history, "live_tail");
        assert_eq!(snapshot.capabilities.pending_rehydration, "none");
        assert_eq!(snapshot.control_owner, "terminal");

        let mut invalid = registration("nonce-b");
        invalid.turn = TurnState::Running {
            run_id: "fixture-run".into(),
            activity: "generation".into(),
        };
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn transient_observer_registration_retains_history_and_generation() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let first = supervisor
            .register_observer(observer_registration("nonce-a"))
            .await
            .unwrap();
        supervisor
            .append_bridge_text(
                &first.session_id,
                text_delta("message-a", 1, "Synthetic ", false),
            )
            .unwrap();
        let before = supervisor.snapshot(&first.session_id).unwrap();

        let second = supervisor
            .register_observer(observer_registration("nonce-a"))
            .await
            .unwrap();
        let after = supervisor.snapshot(&second.session_id).unwrap();
        assert_eq!(first.session_id, second.session_id);
        assert_eq!(first.process_generation, second.process_generation);
        assert_eq!(first.snapshot_epoch, second.snapshot_epoch);
        assert_eq!(before.revision, after.revision);
        assert_eq!(after.timeline_window.entries.len(), 1);
        assert_eq!(supervisor.active_count(), 1);

        supervisor.end_observed_session(&second.session_id, second.process_generation);
        assert_eq!(supervisor.active_count(), 0);
        let ended = supervisor.snapshot(&second.session_id).unwrap();
        assert_eq!(ended.observation.coverage, "stale");
        assert_eq!(ended.observation.reason_code, "session_ended");
    }

    #[tokio::test]
    async fn concurrent_observer_registrations_share_one_live_session() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let first_supervisor = supervisor.clone();
        let second_supervisor = supervisor.clone();
        let (first, second) = tokio::join!(
            first_supervisor.register_observer(observer_registration("nonce-a")),
            second_supervisor.register_observer(observer_registration("nonce-a")),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(first.session_id, second.session_id);
        assert_eq!(first.process_generation, second.process_generation);
        assert_eq!(first.snapshot_epoch, second.snapshot_epoch);
        assert_eq!(supervisor.active_count(), 1);
    }

    /// Spec 017 §4.5: an `ahead` registration labels its descriptor with the drift note —
    /// state, both versions, and the ledger's live gap count — while a grounded registration
    /// carries nothing, so an old app sees a plain compatible row either way.
    #[tokio::test]
    async fn an_ahead_registration_carries_a_drift_note_and_a_grounded_one_does_not() {
        let temp = tempdir().unwrap();
        let grounded = supervisor(&temp.path().join("grounded.json"));
        let registered = grounded
            .register_observer(observer_registration("nonce-grounded"))
            .await
            .unwrap();
        let list = grounded.list();
        let row = list
            .sessions
            .iter()
            .find(|row| row.session_id == registered.session_id)
            .unwrap();
        assert!(row.drift.is_none(), "grounded has nothing to say");

        crate::drift::note(
            "fixture",
            "hook_event",
            "unknown_event",
            "AgentSessionTestShape",
            None,
        );
        let ahead_supervisor = supervisor(&temp.path().join("ahead.json"));
        let mut ahead = observer_registration("nonce-ahead");
        ahead.version_state = "ahead".into();
        ahead.adapter_version = "1.1.0".into();
        ahead.tested_version = "1.0.0".into();
        let registered = ahead_supervisor.register_observer(ahead).await.unwrap();
        let list = ahead_supervisor.list();
        let row = list
            .sessions
            .iter()
            .find(|row| row.session_id == registered.session_id)
            .unwrap();
        let note = row.drift.as_ref().expect("ahead is labeled");
        assert_eq!(note.state, "ahead");
        assert_eq!(note.vendor_version, "1.1.0");
        assert_eq!(note.tested, "1.0.0");
        assert!(
            note.gaps >= 1,
            "the gap count is the ledger's live tally for family `Fixture` -> vendor `fixture`"
        );
        assert_eq!(note.fix, None, "no release can be promised until Phase 4");
        row.validate().expect("a labeled descriptor is still valid");
    }

    /// Spec 017 §4.4: once a release meta names a covering version, the note carries the fix —
    /// for an ahead row, and for a refused-but-newer row that otherwise says only the legacy
    /// banner. The line the phone renders from this is already pinned in the iOS suite.
    #[tokio::test]
    // Held across awaits deliberately: each #[tokio::test] runs its own current-thread
    // runtime on its own test thread, and blocking sibling tests is what the lock is for.
    #[allow(clippy::await_holding_lock)]
    async fn a_known_fix_rides_the_note_for_ahead_and_refused_rows_alike() {
        let _held = crate::release_meta::test_lock();
        let temp = tempdir().unwrap();
        crate::release_meta::apply_meta(
            crate::release_meta::parse_meta(
                serde_json::json!({
                    "v": 1,
                    "host": "0.1.44",
                    "vendors": {
                        "fixturefix": { "rule": "minor_floor", "pinned": "1.1.0" },
                    },
                })
                .to_string()
                .as_bytes(),
            )
            .unwrap(),
        );

        let ahead_supervisor = supervisor(&temp.path().join("ahead.json"));
        let mut ahead = observer_registration("nonce-fix-ahead");
        ahead.adapter_family = "FixtureFix".into();
        ahead.version_state = "ahead".into();
        ahead.adapter_version = "1.1.2".into();
        ahead.tested_version = "1.0.0".into();
        let registered = ahead_supervisor.register_observer(ahead).await.unwrap();
        let list = ahead_supervisor.list();
        let note = list
            .sessions
            .iter()
            .find(|row| row.session_id == registered.session_id)
            .unwrap()
            .drift
            .as_ref()
            .expect("ahead is labeled");
        assert_eq!(
            note.fix.as_deref(),
            Some("0.1.44"),
            "the promise names its release"
        );

        // A refused-but-newer row would normally carry no note; a known fix earns it one.
        let refused_supervisor = supervisor(&temp.path().join("refused.json"));
        let mut refused = observer_registration("nonce-fix-refused");
        refused.adapter_family = "FixtureFix".into();
        refused.version_state = "unsupported".into();
        refused.compatible = false;
        refused.capabilities.commands = CommandCapabilities::none();
        refused.adapter_version = "1.1.0".into();
        refused.tested_version = "1.0.0".into();
        let registered = refused_supervisor.register_observer(refused).await.unwrap();
        let list = refused_supervisor.list();
        let row = list
            .sessions
            .iter()
            .find(|row| row.session_id == registered.session_id)
            .unwrap();
        let note = row
            .drift
            .as_ref()
            .expect("a fix earns the refused row a note");
        assert_eq!(note.state, "unsupported");
        assert_eq!(note.fix.as_deref(), Some("0.1.44"));
        row.validate()
            .expect("the labeled refused row is still valid");
    }

    #[tokio::test]
    async fn transient_observer_rejects_native_commands() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        assert!(
            supervisor
                .register_observer(registration("nonce-a"))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn text_deltas_append_idempotently_and_mark_gaps() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let registered = supervisor
            .register_observer(observer_registration("nonce-a"))
            .await
            .unwrap();
        supervisor
            .append_bridge_text(
                &registered.session_id,
                text_delta("message-a", 1, "Synthetic ", false),
            )
            .unwrap();
        supervisor
            .append_bridge_text(
                &registered.session_id,
                text_delta("message-a", 2, "message.", true),
            )
            .unwrap();
        supervisor
            .append_bridge_text(
                &registered.session_id,
                text_delta("message-a", 2, "duplicate", true),
            )
            .unwrap();
        supervisor
            .append_bridge_text(
                &registered.session_id,
                text_delta("message-b", 3, "late batch", true),
            )
            .unwrap();

        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert_eq!(snapshot.timeline_window.entries.len(), 2);
        assert_eq!(
            snapshot.timeline_window.entries[0].body,
            TimelineBody::Text {
                text: "Synthetic message.".into()
            }
        );
        assert_eq!(snapshot.timeline_window.entries[0].entry_revision, 2);
        assert_eq!(
            snapshot.timeline_window.entries[1]
                .truncation
                .reason_code
                .as_deref(),
            Some("adapter_delta_gap")
        );
    }

    #[tokio::test]
    async fn fake_adapter_registers_reconciles_and_replaces_one_streaming_entry() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("agent-metadata.json");
        let supervisor = supervisor(&path);
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        supervisor
            .replace_bridge_snapshot(
                &registered.session_id,
                vec![entry("source-a", 1, "Synthetic fragment.")],
            )
            .unwrap();
        supervisor
            .upsert_bridge_entry(
                &registered.session_id,
                entry("source-a", 2, "Synthetic replacement."),
            )
            .unwrap();
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert_eq!(snapshot.timeline_window.entries.len(), 1);
        assert_eq!(snapshot.timeline_window.entries[0].entry_revision, 2);
        assert_eq!(snapshot.timeline_window.entries[0].state, "complete");
    }

    #[tokio::test]
    async fn a_backfilled_history_pages_from_the_snapshot_to_its_oldest_entry() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(
                managed_registration("nonce-history", "managed-history"),
                sender,
            )
            .await
            .unwrap();
        let history: Vec<_> = (0..130)
            .map(|index| {
                entry(
                    &format!("history-{index}"),
                    1,
                    &format!("Synthetic history entry {index}."),
                )
            })
            .collect();
        supervisor
            .replace_bridge_snapshot(&registered.session_id, history)
            .unwrap();

        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert_eq!(snapshot.timeline_window.entries.len(), 64);
        assert!(snapshot.timeline_window.has_older);
        assert_eq!(snapshot.timeline_window.oldest_sequence, Some(67));
        assert_eq!(snapshot.timeline_window.newest_sequence, Some(130));

        let middle = supervisor
            .page(&registered.session_id, 67, MAX_TIMELINE_PAGE_ENTRIES)
            .unwrap();
        assert_eq!(middle.entries.len(), 64);
        assert_eq!(middle.entries.first().map(|entry| entry.sequence), Some(3));
        assert_eq!(middle.entries.last().map(|entry| entry.sequence), Some(66));
        assert!(middle.has_older);
        assert_eq!(middle.next_before_sequence, Some(3));

        let oldest = supervisor
            .page(&registered.session_id, 3, MAX_TIMELINE_PAGE_ENTRIES)
            .unwrap();
        assert_eq!(oldest.entries.len(), 2);
        assert_eq!(oldest.entries.first().map(|entry| entry.sequence), Some(1));
        assert_eq!(oldest.entries.last().map(|entry| entry.sequence), Some(2));
        assert!(!oldest.has_older);
        assert_eq!(oldest.next_before_sequence, None);
    }

    #[tokio::test]
    async fn directory_advertises_the_newest_prompt_bounded_to_its_first_line() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();

        // Nothing has been asked yet, so there is nothing truthful to label the row with.
        assert_eq!(supervisor.list().sessions[0].recent_prompt, None);

        supervisor
            .replace_bridge_snapshot(
                &registered.session_id,
                vec![
                    prompt_entry("source-a", 1, "Fix the login bug"),
                    entry("source-b", 1, "Looking into it."),
                    prompt_entry(
                        "source-c",
                        1,
                        "Do the signup flow first\nand keep tests green",
                    ),
                ],
            )
            .unwrap();

        let listed = supervisor.list();
        let descriptor = &listed.sessions[0];
        assert_eq!(
            descriptor.recent_prompt.as_deref(),
            Some("Do the signup flow first"),
            "the newest prompt names the conversation; later lines are not the subject"
        );
        descriptor.validate().unwrap();
    }

    #[test]
    fn a_prompt_over_the_bound_is_cut_on_a_character_boundary() {
        // Two bytes per scalar, so a byte-indexed cut lands mid-character and would panic.
        let text = "é".repeat(MAX_RECENT_PROMPT_BYTES);
        let cut = truncate_on_char_boundary(&text, MAX_RECENT_PROMPT_BYTES);

        assert!(cut.len() <= MAX_RECENT_PROMPT_BYTES);
        assert_eq!(cut.chars().count(), MAX_RECENT_PROMPT_BYTES / 2);
        assert!(cut.chars().all(|scalar| scalar == 'é'));
    }

    #[tokio::test]
    async fn opaque_identity_generation_epoch_and_permissions_are_metadata_only() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("agent-metadata.json");
        let first_supervisor = supervisor(&path);
        let (sender, _) = mpsc::channel(4);
        let first = first_supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        drop(first_supervisor);
        let restarted = supervisor(&path);
        let (sender, _) = mpsc::channel(4);
        let same_process = restarted
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        assert_eq!(same_process.session_id, first.session_id);
        assert_eq!(same_process.process_generation, first.process_generation);
        assert_ne!(same_process.snapshot_epoch, first.snapshot_epoch);
        let (sender, _) = mpsc::channel(4);
        let new_process = restarted
            .register(registration("nonce-b"), sender)
            .await
            .unwrap();
        assert_eq!(new_process.session_id, first.session_id);
        assert_eq!(new_process.process_generation, first.process_generation + 1);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let persisted = fs::read_to_string(path).unwrap();
        assert!(!persisted.contains("fixture-upstream-a"));
        assert!(!persisted.contains("Fixture workspace"));
    }

    /// Takeover mints a new session for a conversation Ciao was already observing. When the
    /// worker cannot read that conversation, its first snapshot still has to inherit the carried
    /// transcript and put it before the boundary — the history happened before the worker did.
    #[tokio::test]
    async fn a_promoted_live_tail_session_inherits_the_transcript_it_was_observed_with() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("agent-metadata.json");
        let supervisor = supervisor(&path);

        // The attached session the owner was reading.
        let (sender, _) = mpsc::channel(4);
        let observed = supervisor
            .register(registration("nonce-observed"), sender)
            .await
            .unwrap();
        supervisor
            .replace_bridge_snapshot(
                &observed.session_id,
                vec![
                    entry("source-a", 1, "What did I say last?"),
                    entry("source-b", 1, "You asked about the terminal."),
                ],
            )
            .unwrap();
        let inherited = supervisor.timeline_for_handover(&observed.session_id);
        assert_eq!(inherited.len(), 2);

        // Promotion: the transcript is stashed against the ID the launcher minted, before the
        // worker exists. Only a managed registration keeps that ID, which is exactly what the
        // daemon's pre-spawn hook depends on.
        let promoted_id = "0123456789abcdef0123456789abcdef";
        supervisor.carry_history_into(promoted_id, inherited);
        let (sender, _) = mpsc::channel(4);
        let promoted = supervisor
            .register(managed_registration("nonce-promoted", promoted_id), sender)
            .await
            .unwrap();
        assert_eq!(promoted.session_id, promoted_id);
        supervisor
            .replace_bridge_snapshot(
                &promoted.session_id,
                vec![entry(
                    "history-boundary",
                    1,
                    "Earlier turns are in Claude history.",
                )],
            )
            .unwrap();

        let snapshot = supervisor.snapshot(&promoted.session_id).unwrap();
        let bodies: Vec<String> = snapshot
            .timeline_window
            .entries
            .iter()
            .map(|entry| format!("{:?}", entry.body))
            .collect();
        assert_eq!(
            bodies.len(),
            3,
            "carried transcript plus the worker boundary"
        );
        assert!(bodies[0].contains("What did I say last?"));
        assert!(bodies[1].contains("You asked about the terminal."));
        // The boundary reads as the join between what was observed and what the worker will say.
        assert!(bodies[2].contains("Earlier turns"));

        // The property a client actually enforces, and the one that matters more than the order
        // of the bodies: one strictly increasing sequence across both halves. Each side was
        // numbered from its own session's counter, so both arrive starting at 1 — a window that
        // merely reads correctly while repeating a sequence is rejected outright, which is what
        // being stuck on "could not be opened" looks like from the phone.
        let sequences: Vec<u64> = snapshot
            .timeline_window
            .entries
            .iter()
            .map(|entry| entry.sequence)
            .collect();
        assert!(
            sequences.windows(2).all(|pair| pair[0] < pair[1]),
            "timeline sequences must strictly increase, got {sequences:?}"
        );
        assert_eq!(
            snapshot.timeline_window.oldest_sequence,
            sequences.first().copied()
        );
        assert_eq!(
            snapshot.timeline_window.newest_sequence,
            sequences.last().copied()
        );

        // The counter moved with them, so the first live turn after the takeover extends the
        // order instead of colliding with a sequence the inherited transcript already used.
        supervisor
            .upsert_bridge_entry(
                &promoted.session_id,
                entry("source-live", 1, "First live turn after the takeover."),
            )
            .unwrap();
        let after = supervisor.snapshot(&promoted.session_id).unwrap();
        let tail: Vec<u64> = after
            .timeline_window
            .entries
            .iter()
            .map(|entry| entry.sequence)
            .collect();
        assert!(
            tail.windows(2).all(|pair| pair[0] < pair[1]),
            "a live entry must extend the order, got {tail:?}"
        );

        // Consumed once: a later reconciliation must not duplicate the history.
        supervisor
            .replace_bridge_snapshot(
                &promoted.session_id,
                vec![entry(
                    "history-boundary",
                    2,
                    "Earlier turns are in Claude history.",
                )],
            )
            .unwrap();
        let again = supervisor.snapshot(&promoted.session_id).unwrap();
        assert_eq!(again.timeline_window.entries.len(), 1);
    }

    /// The current managed worker reads the same persisted conversation the attached adapter was
    /// observing. Its complete snapshot must replace, not follow, that carried adapter-specific
    /// copy: their source IDs are intentionally unrelated, so combining them duplicates turns.
    #[tokio::test]
    async fn a_promoted_full_snapshot_supersedes_the_carried_attached_copy() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _) = mpsc::channel(4);
        let attached = supervisor
            .register(registration("nonce-attached-copy"), sender)
            .await
            .unwrap();
        supervisor
            .replace_bridge_snapshot(
                &attached.session_id,
                vec![
                    prompt_entry("attached-a", 1, "Carried attached question."),
                    entry("attached-b", 1, "Carried attached answer."),
                ],
            )
            .unwrap();
        let promoted_id = "0123456789abcdef0123456789abcdef";
        supervisor.carry_history_into(
            promoted_id,
            supervisor.timeline_for_handover(&attached.session_id),
        );
        let mut registration = managed_registration("nonce-promoted-full", promoted_id);
        registration.capabilities.history = "full".into();
        let (sender, _) = mpsc::channel(4);
        let promoted = supervisor.register(registration, sender).await.unwrap();

        supervisor
            .replace_bridge_snapshot(
                &promoted.session_id,
                vec![
                    entry("managed-user", 1, "Stored managed question."),
                    entry("managed-assistant", 1, "Stored managed answer."),
                ],
            )
            .unwrap();

        let snapshot = supervisor.snapshot(&promoted.session_id).unwrap();
        let bodies: Vec<_> = snapshot
            .timeline_window
            .entries
            .iter()
            .map(|entry| format!("{:?}", entry.body))
            .collect();
        assert_eq!(bodies.len(), 2);
        assert!(bodies[0].contains("Stored managed question"));
        assert!(bodies[1].contains("Stored managed answer"));
        assert!(bodies.iter().all(|body| !body.contains("Carried attached")));
        assert_eq!(snapshot.timeline_window.oldest_sequence, Some(1));
        assert_eq!(snapshot.timeline_window.newest_sequence, Some(2));
    }

    #[tokio::test]
    async fn same_process_reconnect_is_monotonic_and_old_disconnect_is_fenced() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("agent-metadata.json");
        let supervisor = supervisor(&path);
        let (sender, _) = mpsc::channel(4);
        let first = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        supervisor
            .replace_bridge_snapshot(
                &first.session_id,
                vec![entry("source-a", 5, "Synthetic first snapshot.")],
            )
            .unwrap();
        let before = supervisor.snapshot(&first.session_id).unwrap();

        let (sender, _) = mpsc::channel(4);
        let second = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        let reconnected = supervisor.snapshot(&second.session_id).unwrap();
        assert_eq!(second.process_generation, first.process_generation);
        assert_eq!(second.snapshot_epoch, first.snapshot_epoch);
        assert!(reconnected.revision > before.revision);

        supervisor
            .replace_bridge_snapshot(
                &second.session_id,
                vec![entry("source-a", 1, "Synthetic reconciled snapshot.")],
            )
            .unwrap();
        let reconciled = supervisor.snapshot(&second.session_id).unwrap();
        assert!(reconciled.timeline_window.entries[0].entry_revision > 5);

        supervisor.bridge_disconnected(&first.session_id, &first.disconnect_token, false);
        let after_old_disconnect = supervisor.snapshot(&second.session_id).unwrap();
        assert_eq!(after_old_disconnect.observation.coverage, "partial");
        assert_eq!(supervisor.active_count(), 1);
    }

    #[tokio::test]
    async fn privacy_canary_and_command_text_never_enter_metadata() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("agent-metadata.json");
        let supervisor = supervisor(&path);
        let (sender, mut receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        let canary = format!(
            "CIAO_PRIVATE_CANARY_{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        supervisor
            .replace_bridge_snapshot(&registered.session_id, vec![entry("source-a", 1, &canary)])
            .unwrap();
        let command = AgentCommand {
            v: 1,
            command_id: "command-a".into(),
            session_id: registered.session_id,
            snapshot_epoch: registered.snapshot_epoch,
            expected_generation: registered.process_generation,
            expected_revision: None,
            kind: AgentCommandKind::Prompt {
                text: canary.clone(),
            },
        };
        // Commands are bridge-gated: no exact route exists in this isolated test, yet the
        // prompt forwards over the bridge. The persisted receipt stays metadata-only.
        let receipt = supervisor.submit_command(command).await;
        assert_eq!(receipt.state, "sending");
        let persisted = fs::read_to_string(path).unwrap();
        assert!(!persisted.contains(&canary));
        assert!(!persisted.contains("source-a"));
        assert!(receiver.try_recv().is_ok());
    }

    /// Answering a permission card is gated by *interaction* capabilities, not command ones.
    ///
    /// The distinction was already asserted on `AgentCapabilities` in `agent_protocol`, and it
    /// held there the whole time: `submit_command` reached past the wrapper to
    /// `capabilities.commands`, which answers `false` for an interaction response by
    /// construction. Every Allow and every Deny came back `unavailable`/`command_not_advertised`
    /// and the phone said the message could not be delivered. This test drives the command path
    /// rather than the type, because the type was never the thing that was wrong.
    #[tokio::test]
    async fn answering_a_permission_is_gated_by_interaction_capabilities_not_command_ones() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _receiver) = mpsc::channel(4);
        let mut facts = registration("nonce-permission");
        // Exactly the managed-Claude shape: no command is advertised, one interaction is.
        facts.capabilities.commands = CommandCapabilities::none();
        facts.capabilities.interactions = InteractionCapabilities {
            permission: crate::agent_protocol::InteractionCapability {
                enabled: true,
                max_questions: 1,
                max_options_per_question: 4,
                allows_free_text: false,
            },
            ..InteractionCapabilities::none()
        };
        let registered = supervisor.register(facts, sender).await.unwrap();
        let command = AgentCommand {
            v: 1,
            command_id: "command-permission".into(),
            session_id: registered.session_id.clone(),
            snapshot_epoch: registered.snapshot_epoch,
            expected_generation: registered.process_generation,
            expected_revision: None,
            kind: AgentCommandKind::InteractionResponse {
                interaction_id: "interaction-a".into(),
                interaction_revision: 1,
                answer: crate::agent_protocol::InteractionAnswer::Choices {
                    choice_ids: vec!["allow-once".into()],
                },
            },
        };
        let receipt = supervisor.submit_command(command).await;
        assert_ne!(
            receipt.reason_code.as_deref(),
            Some("command_not_advertised"),
            "an advertised permission interaction must not be refused as an unadvertised command"
        );
        assert_eq!(receipt.state, "sending");

        // And the gate still bites where it should: a prompt really is unadvertised here.
        let prompt = AgentCommand {
            v: 1,
            command_id: "command-prompt".into(),
            session_id: registered.session_id,
            snapshot_epoch: registered.snapshot_epoch,
            expected_generation: registered.process_generation,
            expected_revision: None,
            kind: AgentCommandKind::Prompt {
                text: "should be refused".into(),
            },
        };
        let refused = supervisor.submit_command(prompt).await;
        assert_eq!(
            refused.reason_code.as_deref(),
            Some("command_not_advertised")
        );
    }

    #[tokio::test]
    async fn deterministic_large_live_workload_evicts_within_host_memory_bounds() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let (sender, _) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        for index in 0..(MAX_HOST_TIMELINE_ENTRIES + 32) {
            supervisor
                .upsert_bridge_entry(
                    &registered.session_id,
                    entry(
                        &format!("source-{index}"),
                        1,
                        &format!("Synthetic bounded entry {index}."),
                    ),
                )
                .unwrap();
        }
        let inner = supervisor.inner.lock();
        let session = inner.sessions.get(&registered.session_id).unwrap();
        assert_eq!(session.history.len(), MAX_HOST_TIMELINE_ENTRIES);
        assert!(
            session
                .history
                .iter()
                .map(TimelineEntry::decoded_bytes)
                .sum::<usize>()
                <= MAX_HOST_TIMELINE_BYTES
        );
        assert!(session.history.first().unwrap().sequence > 1);
    }

    #[tokio::test]
    async fn disconnect_marks_in_flight_ambiguous_and_duplicate_ids_never_forward_twice() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("agent-metadata.json");
        let supervisor = supervisor(&path);
        let (sender, mut receiver) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        let command = AgentCommand {
            v: 1,
            command_id: "command-duplicate".into(),
            session_id: registered.session_id.clone(),
            snapshot_epoch: registered.snapshot_epoch,
            expected_generation: registered.process_generation,
            expected_revision: None,
            kind: AgentCommandKind::Prompt {
                text: "Synthetic bounded command.".into(),
            },
        };
        let first = supervisor.submit_command(command.clone()).await;
        let duplicate = supervisor.submit_command(command).await;
        assert_eq!(first, duplicate);
        assert_eq!(first.state, "sending");
        assert!(receiver.try_recv().is_ok(), "the first submission forwards");
        assert!(
            receiver.try_recv().is_err(),
            "a duplicate command id never forwards twice"
        );

        {
            let mut inner = supervisor.inner.lock();
            inner
                .sessions
                .get_mut(&registered.session_id)
                .unwrap()
                .in_flight_commands
                .insert("command-ambiguous".into());
        }
        supervisor.bridge_disconnected(&registered.session_id, &registered.disconnect_token, false);
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        let receipt = snapshot
            .latest_command_receipts
            .iter()
            .find(|receipt| receipt.command_id == "command-ambiguous")
            .unwrap();
        assert_eq!(receipt.state, "outcome_unknown");
        assert_eq!(receipt.reason_code.as_deref(), Some("bridge_disconnected"));
    }

    /// An observer re-registers on every event it delivers. Until 2026-08-01 that registration
    /// also carried a turn, which meant each new event reset the turn the previous one had
    /// established — and a registration reporting `running` from a partially-observed session is
    /// refused outright, so the connection closed and the event was lost with it. That is what
    /// dropped every Codex prompt while its answers still arrived.
    #[tokio::test]
    async fn an_observer_refresh_leaves_the_turn_its_events_established() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let registered = supervisor
            .register_observer(observer_registration("nonce-a"))
            .await
            .unwrap();

        let working = TurnState::Running {
            run_id: "codex.turn.abc".into(),
            activity: "responding".into(),
        };
        supervisor
            .note_bridge_turn(&registered.session_id, working.clone())
            .unwrap();
        assert_eq!(
            supervisor.snapshot(&registered.session_id).unwrap().turn,
            working
        );

        // The next hook re-registers, exactly as the live tail does between events.
        supervisor
            .register_observer(observer_registration("nonce-a"))
            .await
            .unwrap();
        assert_eq!(
            supervisor.snapshot(&registered.session_id).unwrap().turn,
            working,
            "a registration describes the process, not what it is doing"
        );
    }

    /// The invariant the above exists to respect: Spec 005 §1's turn provenance is structural,
    /// so no registration path may produce a working turn from a partially-observed session.
    #[tokio::test]
    async fn a_registration_reporting_work_it_cannot_observe_is_refused() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let mut registration = observer_registration("nonce-a");
        registration.turn = TurnState::Running {
            run_id: "codex.turn.abc".into(),
            activity: "responding".into(),
        };
        assert!(!registration.observation.is_authoritative());
        assert!(supervisor.register_observer(registration).await.is_err());
    }

    /// Spec 012 §6. The Codex history read races the live hook tail, so what already arrived
    /// has to survive and end up *after* the history it belongs to — the failure this replaces
    /// is a snapshot replace that silently drops the first prompt of the session.
    #[tokio::test]
    async fn read_history_lands_beneath_the_live_tail_without_losing_it() {
        let temp = tempdir().unwrap();
        let supervisor = supervisor(&temp.path().join("agent-metadata.json"));
        let registered = supervisor
            .register_observer(observer_registration("nonce-a"))
            .await
            .unwrap();
        // The live tail arrives first, because it does.
        supervisor
            .upsert_bridge_entry(&registered.session_id, entry("live-prompt", 1, "live"))
            .unwrap();
        supervisor
            .prepend_bridge_history(
                &registered.session_id,
                vec![
                    entry("history-a", 1, "first"),
                    entry("history-b", 1, "second"),
                ],
            )
            .unwrap();

        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        let texts: Vec<_> = snapshot
            .timeline_window
            .entries
            .iter()
            .map(|entry| match &entry.body {
                TimelineBody::Text { text } => text.clone(),
                other => panic!("unexpected body {other:?}"),
            })
            .collect();
        assert_eq!(texts, vec!["first", "second", "live"]);
        let sequences: Vec<_> = snapshot
            .timeline_window
            .entries
            .iter()
            .map(|entry| entry.sequence)
            .collect();
        assert!(
            sequences.windows(2).all(|pair| pair[0] < pair[1]),
            "a client needs one strictly increasing order: {sequences:?}"
        );

        // The live entry's source mapping moved with it, so its completion still updates the
        // same card rather than creating a second one below the history.
        supervisor
            .upsert_bridge_entry(&registered.session_id, entry("live-prompt", 2, "live done"))
            .unwrap();
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert_eq!(snapshot.timeline_window.entries.len(), 3);

        // Reading twice must not duplicate what is already there.
        supervisor
            .prepend_bridge_history(&registered.session_id, vec![entry("history-a", 1, "first")])
            .unwrap();
        assert_eq!(
            supervisor
                .snapshot(&registered.session_id)
                .unwrap()
                .timeline_window
                .entries
                .len(),
            3
        );
    }

    #[tokio::test]
    async fn bridge_disconnect_removes_mutation_before_next_snapshot() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("agent-metadata.json");
        let supervisor = supervisor(&path);
        let (sender, _) = mpsc::channel(4);
        let registered = supervisor
            .register(registration("nonce-a"), sender)
            .await
            .unwrap();
        supervisor.bridge_disconnected(&registered.session_id, &registered.disconnect_token, false);
        let snapshot = supervisor.snapshot(&registered.session_id).unwrap();
        assert_eq!(snapshot.capabilities.commands, CommandCapabilities::none());
        assert_eq!(snapshot.terminal_fallback.continuity, "unavailable");
        assert_eq!(snapshot.observation.coverage, "stale");
    }

    #[test]
    fn metadata_rejects_symlinks_and_malformed_or_overbound_files() {
        let temp = tempdir().unwrap();
        let target = temp.path().join("target");
        atomic_write_private(&target, b"{}").unwrap();
        let link = temp.path().join("agent-metadata.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(AgentMetadataStore::load(&link).is_err());

        fs::remove_file(&link).unwrap();
        atomic_write_private(&link, b"not-json").unwrap();
        assert!(AgentMetadataStore::load(&link).is_err());

        fs::remove_file(&link).unwrap();
        let oversized = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&link)
            .unwrap();
        oversized
            .set_len(MAX_AGENT_METADATA_FILE_BYTES + 1)
            .unwrap();
        drop(oversized);
        assert!(AgentMetadataStore::load(&link).is_err());
    }
}
