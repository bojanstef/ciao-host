//! Adopted Codex sessions (Spec 013 §5–§7): pick up an unheld thread, write to it, yield.
//!
//! The daemon is the vendor client here. One supervised `codex app-server` child serves one
//! adopted thread for exactly as long as the phone holds the conversation; the thread's own
//! rollout file is the ground truth for who else might own it. Two watches keep answering the
//! ownership question while the hold lasts: the descriptor watch (a rollout holder is always a
//! terminal — grounded 2026-08-04, only TUIs hold the descriptor), and the foreign-hook watch
//! (an app-server writer is invisible to the descriptor but betrays itself through the hooks it
//! fires). On either signal Ciao yields, because the person is at the terminal (ADR 006 §4).

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Mutex,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::{process::Command, sync::mpsc, time};

use crate::{
    agent_protocol::{
        AgentCapabilities, AgentCommandKind, AgentModelOption, CommandCapabilities,
        InteractionAnswer, InteractionCapabilities, InteractionCapability,
        MAX_LIVE_TEXT_DELTA_BYTES, MAX_MODEL_CATALOGUE_ENTRIES, MAX_TIMELINE_TEXT_BYTES,
        MAX_TOOL_INPUT_PREVIEW_BYTES, MAX_TOOL_RESULT_PREVIEW_BYTES, Observation,
        PendingInteraction, ResponseChoice, ResponseSchema, TerminalFallback, TimelineBody,
        ToolTimelineBody, TurnState,
    },
    agent_session::{
        AgentSessionSupervisor, BridgeCommandEnvelope, NormalizedRegistration, NormalizedTextDelta,
        NormalizedTimelineEntry, RegisteredAgentSession,
    },
    codex_adapter::codex_run_id,
    codex_app_server,
    codex_app_server::{AppServerConnection, AppServerEvent},
    codex_history,
    hook_common::{bounded_preview, bounded_text, keyed_digest, no_truncation, unix_now},
};

const CODEX_ADOPTED_DOMAIN: &[u8] = b"ciao-codex-adopted-v1\0";
/// How often the descriptor watch re-asks the kernel while a thread is held. Before every
/// write it is asked again inline, so this bounds detection of a terminal that opened while
/// the phone was idle.
const DESCRIPTOR_WATCH_INTERVAL: Duration = Duration::from_secs(5);
/// The grace-completion cap (Spec 013 §5): a turn already streaming may finish before release,
/// because a phone lock must not cost a running answer — but not forever.
const GRACE_COMPLETION_CAP: Duration = Duration::from_secs(300);
/// The three decisions Ciao understands, in the order a card offers them. The vendor's
/// `availableDecisions` narrows this at runtime; a decision outside it is dropped, never
/// guessed at (Spec 013 §6).
const KNOWN_DECISIONS: [&str; 3] = ["accept", "acceptForSession", "decline"];

/// Why an adoption ended. Reported in logs and, where the supervisor keeps a reason, surfaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReleaseReason {
    ConversationClosed,
    ForeignTerminal,
    ForeignWriter,
    // Resume in Terminal releases first (Spec 013 §7): the phone's "Move to My Terminal"
    // drops the hold, then hands over `codex resume <id>`.
    ResumeInTerminal,
    ConnectionLost,
}

impl ReleaseReason {
    fn token(self) -> &'static str {
        match self {
            Self::ConversationClosed => "conversation_closed",
            Self::ForeignTerminal => "foreign_terminal",
            Self::ForeignWriter => "foreign_writer",
            Self::ResumeInTerminal => "resume_in_terminal",
            Self::ConnectionLost => "connection_lost",
        }
    }
}

/// A sustained rollout holder outside our own child's process tree — the refined foreign-
/// terminal signal. One sample is not enough: the app-server, ours included, opens the
/// rollout transiently while appending (the first grounded end-to-end yielded to its own
/// child mid-write), and only a terminal holds the descriptor continuously. So a holder
/// counts as foreign when it is not our child or its descendant, and it survives a second
/// sample three-quarters of a second later.
async fn foreign_rollout_holder(rollout: &Path, own_child: Option<u32>) -> bool {
    let Ok(first) = rollout_holders(rollout).await else {
        return false;
    };
    let mut suspects = Vec::new();
    for pid in first {
        if !is_own_process(pid, own_child).await {
            suspects.push(pid);
        }
    }
    if suspects.is_empty() {
        return false;
    }
    time::sleep(Duration::from_millis(750)).await;
    let Ok(second) = rollout_holders(rollout).await else {
        return false;
    };
    for pid in second {
        if suspects.contains(&pid) && !is_own_process(pid, own_child).await {
            return true;
        }
    }
    false
}

async fn is_own_process(pid: u32, own_child: Option<u32>) -> bool {
    match own_child {
        Some(child) => pid == child || crate::process::descends_from(pid, child).await,
        None => false,
    }
}

/// PIDs of live processes holding `rollout` open, from the kernel via lsof.
///
/// lsof exits nonzero for "nobody holds it", which is an answer here, not an error. A failure
/// to *ask* — lsof missing or unspawnable — is an error, and adoption fails closed on it:
/// writing to a thread whose ownership cannot be proven is the one mistake this module exists
/// to prevent.
pub(crate) async fn rollout_holders(rollout: &Path) -> Result<Vec<u32>> {
    let output = Command::new("lsof")
        .arg("-t")
        .arg("--")
        .arg(rollout)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .await
        .context("ask the kernel who holds the rollout (lsof)")?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect())
}

/// One adopter per thread, and a way to reach it — plus the two pieces of durable Codex
/// evidence the entry points need: the last binary a real registration proved (never `PATH`),
/// and a bounded cache of unheld threads for the directory.
///
/// Adoptions themselves are memory-only: a daemon restart clears them by design (Spec 013 §5) —
/// holding is deliberate, per-conversation, and bounded by use, so the phone re-adopts after a
/// restart rather than the daemon resurrecting holds. The binary evidence *is* persisted,
/// because discovery must work when no Codex process is alive to ask.
#[derive(Default, Debug)]
pub(crate) struct AdoptionRegistry {
    inner: Mutex<HashMap<String, AdoptionHandle>>,
    /// Where the binary evidence lives (`codex-runtime.json` beside the agent metadata).
    /// `None` in tests that never touch discovery.
    runtime_file: Option<PathBuf>,
    binary: Mutex<Option<PathBuf>>,
    discovery: tokio::sync::Mutex<DiscoveryCache>,
}

#[derive(Default, Debug)]
struct DiscoveryCache {
    rows: Vec<UnheldThread>,
    refreshed_at: Option<std::time::Instant>,
}

/// One unheld conversation the directory can offer for pick-up. Raw identifiers stay
/// host-side; the phone sees only the stable digested session ID and bounded metadata.
#[derive(Debug, Clone)]
pub(crate) struct UnheldThread {
    pub(crate) session_id: String,
    pub(crate) thread_id: String,
    pub(crate) rollout: Option<PathBuf>,
    pub(crate) cwd: Option<String>,
    pub(crate) preview: Option<String>,
    pub(crate) updated_at: u64,
    pub(crate) cli_version: String,
}

/// The stable Ciao identity for a Codex conversation across its unheld and adopted lives.
/// The row a person taps and the session that opens are the same identity, so the phone never
/// has to re-ask for a freshly minted ID — the lesson the Claude takeover path already paid
/// for.
pub(crate) fn codex_conversation_session_id(thread_id: &str) -> String {
    format!(
        "codex-adopted-{}",
        keyed_digest(CODEX_ADOPTED_DOMAIN, "conversation", thread_id)
    )
}

/// How stale the unheld cache may be before a list refreshes it. Spawning the vendor binary
/// costs about a second, and the Agents list polls every three; the cache keeps discovery off
/// that hot path.
const DISCOVERY_TTL: Duration = Duration::from_secs(30);
/// Newest-first ceiling on discovered threads. `log()`-free by design: the directory says how
/// many hosts contributed, not how many conversations exist on disk.
const DISCOVERY_LIMIT: usize = 20;

#[derive(Debug)]
struct AdoptionHandle {
    session_id: String,
    child_pid: Option<u32>,
    release: mpsc::Sender<ReleaseReason>,
}

impl AdoptionRegistry {
    /// Claims a thread for a new adoption. Refused while any other adoption holds it — the
    /// one-adopter invariant is Ciao's own, since the vendor refuses nothing (grounded:
    /// concurrent resume succeeds silently).
    fn claim(
        &self,
        thread_id: &str,
        session_id: &str,
        child_pid: Option<u32>,
        release: mpsc::Sender<ReleaseReason>,
    ) -> Result<()> {
        let mut inner = self.inner.lock().expect("adoption registry lock");
        if inner.contains_key(thread_id) {
            bail!("this conversation is already picked up");
        }
        inner.insert(
            thread_id.to_owned(),
            AdoptionHandle {
                session_id: session_id.to_owned(),
                child_pid,
                release,
            },
        );
        Ok(())
    }

    fn remove(&self, thread_id: &str) {
        self.inner
            .lock()
            .expect("adoption registry lock")
            .remove(thread_id);
    }

    /// The adopted session for a thread, if any. Raw thread IDs stay host-side.
    pub(crate) fn session_for(&self, thread_id: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("adoption registry lock")
            .get(thread_id)
            .map(|handle| handle.session_id.clone())
    }

    /// Asks the adoption holding `thread_id` to release for `reason`. Used by the
    /// conversation-close path and, later, by Resume in Terminal.
    /// The held thread behind a client-facing session ID, if this registry holds it.
    ///
    /// A scan rather than a second index: the conversation ID is a one-way keyed digest, so it
    /// cannot be inverted, and a registry holding more than a handful of live adoptions is not
    /// a shape this process reaches.
    pub(crate) fn held_thread_for_session(&self, session_id: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("adoption registry lock")
            .keys()
            .find(|thread_id| codex_conversation_session_id(thread_id) == session_id)
            .cloned()
    }

    pub(crate) fn request_release(&self, thread_id: &str, reason: ReleaseReason) {
        let sender = self
            .inner
            .lock()
            .expect("adoption registry lock")
            .get(thread_id)
            .map(|handle| handle.release.clone());
        if let Some(sender) = sender {
            let _ = sender.try_send(reason);
        }
    }

    /// A registry that persists binary evidence and serves discovery. `load` reads whatever a
    /// previous daemon recorded, so a machine that ran Codex once keeps its discovery across
    /// restarts.
    pub(crate) fn load(runtime_file: PathBuf) -> Self {
        let binary = std::fs::read(&runtime_file)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|value| value["binary"].as_str().map(PathBuf::from))
            .filter(|path| path.is_absolute());
        Self {
            inner: Mutex::new(HashMap::new()),
            runtime_file: Some(runtime_file),
            binary: Mutex::new(binary),
            discovery: tokio::sync::Mutex::new(DiscoveryCache::default()),
        }
    }

    /// Records the Codex binary behind a live, authenticated registration (Spec 013 §8) —
    /// resolved from the observed process, never from `PATH`, and refreshed whenever a real
    /// TUI runs. Cheap when nothing changed; the file write is atomic and rare.
    pub(crate) fn record_binary_evidence(&self, binary: PathBuf) {
        if !binary.is_absolute() {
            return;
        }
        {
            let mut recorded = self.binary.lock().expect("binary evidence lock");
            if recorded.as_ref() == Some(&binary) {
                return;
            }
            *recorded = Some(binary.clone());
        }
        if let Some(file) = &self.runtime_file {
            let payload = serde_json::json!({"binary": binary});
            let temporary = file.with_extension("json.tmp");
            let written = std::fs::write(&temporary, payload.to_string())
                .and_then(|()| std::fs::rename(&temporary, file));
            if let Err(error) = written {
                tracing::debug!(target: "codex_adopted", %error, "persisting binary evidence failed");
            }
        }
    }

    /// The last proven binary, if any machine history exists. A recorded path that no longer
    /// exists disables discovery truthfully rather than falling back to `PATH`.
    pub(crate) fn recorded_binary(&self) -> Option<PathBuf> {
        self.binary
            .lock()
            .expect("binary evidence lock")
            .clone()
            .filter(|path| path.exists())
    }

    /// The unheld conversations this machine can offer for pick-up, freshened when stale.
    /// Empty — and silent — when no binary evidence exists: a machine that never ran Codex has
    /// nothing to discover (Spec 013 §8).
    pub(crate) async fn unheld_threads(&self) -> Vec<UnheldThread> {
        let Some(binary) = self.recorded_binary() else {
            return Vec::new();
        };
        let mut cache = self.discovery.lock().await;
        let fresh = cache
            .refreshed_at
            .is_some_and(|instant| instant.elapsed() < DISCOVERY_TTL);
        if !fresh {
            match codex_app_server::request(
                &binary,
                "thread/list",
                json!({"limit": DISCOVERY_LIMIT, "archived": false}),
            )
            .await
            {
                Ok(listed) => {
                    cache.rows = unheld_rows(&listed);
                    cache.refreshed_at = Some(std::time::Instant::now());
                }
                Err(error) => {
                    tracing::debug!(target: "codex_adopted", %error, "unheld discovery failed");
                    // A failed refresh keeps the stale rows briefly rather than blanking the
                    // list; the next refresh retries.
                    cache.refreshed_at = Some(std::time::Instant::now());
                }
            }
        }
        let claimed: Vec<String> = {
            let inner = self.inner.lock().expect("adoption registry lock");
            inner.keys().cloned().collect()
        };
        cache
            .rows
            .iter()
            .filter(|row| !claimed.contains(&row.thread_id))
            .cloned()
            .collect()
    }

    /// The unheld row for a session ID, if discovery knows it. The pick-up operation resolves
    /// the tapped row back to its thread through this.
    pub(crate) async fn unheld_thread_for_session(&self, session_id: &str) -> Option<UnheldThread> {
        self.unheld_threads()
            .await
            .into_iter()
            .find(|row| row.session_id == session_id)
    }

    /// The thread an adopted session is holding, for the release-on-close path.
    pub(crate) fn thread_for_session(&self, session_id: &str) -> Option<String> {
        self.inner
            .lock()
            .expect("adoption registry lock")
            .iter()
            .find(|(_, handle)| handle.session_id == session_id)
            .map(|(thread, _)| thread.clone())
    }

    /// The unheld row for a raw thread ID, for pick-up resolved through an attached session
    /// row rather than a discovery row.
    pub(crate) async fn unheld_row_by_thread(&self, thread_id: &str) -> Option<UnheldThread> {
        self.unheld_threads()
            .await
            .into_iter()
            .find(|row| row.thread_id == thread_id)
    }

    /// The foreign-hook watch (Spec 013 §5): a hook event for an adopted thread from a process
    /// that is not Ciao's own child is a foreign app-server writer — invisible to the
    /// descriptor check — and Ciao yields. Called from the Codex hook ingest path.
    pub(crate) fn note_hook_event(&self, thread_id: &str, process_id: u32) {
        let sender = {
            let inner = self.inner.lock().expect("adoption registry lock");
            match inner.get(thread_id) {
                Some(handle) if handle.child_pid != Some(process_id) => {
                    Some(handle.release.clone())
                }
                _ => None,
            }
        };
        if let Some(sender) = sender {
            let _ = sender.try_send(ReleaseReason::ForeignWriter);
        }
    }
}

/// Maps one `thread/list` page onto unheld rows: non-archived threads that exist on disk,
/// newest first, bounded metadata only. A thread without a rollout path is skipped — it has no
/// content to pick up (grounded: a contentless thread cannot even be resumed).
fn unheld_rows(listed: &Value) -> Vec<UnheldThread> {
    let data = listed.get("data").and_then(Value::as_array);
    data.map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|row| {
            let thread_id = row["id"].as_str()?;
            let rollout = row["path"].as_str().map(PathBuf::from);
            rollout.as_deref()?;
            let preview = row
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .or_else(|| row.get("preview").and_then(Value::as_str))
                .map(|text| bounded_text(text.lines().next().unwrap_or_default(), 160).0);
            Some(UnheldThread {
                session_id: codex_conversation_session_id(thread_id),
                thread_id: thread_id.to_owned(),
                rollout,
                cwd: row["cwd"].as_str().map(str::to_owned),
                preview,
                // Grounded at this pin: thread/list timestamps are epoch SECONDS
                // (updatedAt 1785879799 on 2026-08-04). The first guess was milliseconds,
                // and dividing seconds by a thousand put every conversation twenty days
                // after 1970 — "2949w ago" on the phone. The guard absorbs a future switch
                // to milliseconds rather than re-inventing that row.
                updated_at: row["updatedAt"]
                    .as_u64()
                    .map(|value| {
                        if value > 100_000_000_000 {
                            value / 1000
                        } else {
                            value
                        }
                        .max(1)
                    })
                    .unwrap_or_else(unix_now),
                cli_version: row["cliVersion"].as_str().unwrap_or("unknown").to_owned(),
            })
        })
        .collect()
}

/// The directory row for one unheld conversation (Spec 013 §8): an ordinary attached
/// descriptor — old apps render it read-only with no verb — whose continuity is the resumable
/// conversation itself.
pub(crate) fn unheld_descriptor(
    row: &UnheldThread,
) -> crate::agent_protocol::AgentSessionDescriptor {
    let workspace_display = row
        .cwd
        .as_deref()
        .and_then(|cwd| Path::new(cwd).file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "Codex".to_owned());
    crate::agent_protocol::AgentSessionDescriptor {
        v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
        session_id: row.session_id.clone(),
        adapter_family: "Codex".into(),
        adapter_version: row.cli_version.clone(),
        topology: "attached".into(),
        presence: "live".into(),
        stored_reason: None,
        // Never `ahead`: the adopted admission rule is the major bound (see
        // `adopted_compatible`), so there is no tolerant band to label.
        drift: None,
        process_generation: 1,
        observation: Observation {
            coverage: "partial".into(),
            reason_code: "unheld_record".into(),
            last_authoritative_at: None,
        },
        turn: TurnState::Unknown {
            reason_code: "unheld_record".into(),
        },
        capabilities: AgentCapabilities {
            history: "live_tail".into(),
            commands: CommandCapabilities::none(),
            interactions: InteractionCapabilities::none(),
            pending_rehydration: "none".into(),
            terminal_continuity: "resumable_session".into(),
        },
        workspace_display,
        terminal_fallback: TerminalFallback {
            continuity: "resumable_session".into(),
            route_id: Some(format!(
                "codex-resume-{}",
                keyed_digest(CODEX_ADOPTED_DOMAIN, "route", &row.thread_id)
            )),
            availability_reason: Some("unheld_record".into()),
            handback_session: None,
            // Nobody holds this thread, so the way in is the same line the user would type
            // themselves.
            resume_command: codex_resume_command(&row.thread_id),
        },
        recent_prompt: row.preview.clone().filter(|preview| !preview.is_empty()),
        managed_session_id: None,
        // The whole point of the row: nobody holds this thread, so the daemon can.
        takeover: Some("pickup".into()),
        revision: 1,
        updated_at: row.updated_at,
    }
}

/// The one spelling of the way back into an unheld or released Codex thread. Formatted and
/// validated in one place: the descriptor and the release outcome must hand over the same
/// command, and a thread ID that does not round-trip yields no command rather than a mangled
/// one.
pub(crate) fn codex_resume_command(thread_id: &str) -> Option<String> {
    let command = format!("codex resume {thread_id}");
    crate::agent_protocol::valid_resume_command(&command)
        .is_ok()
        .then_some(command)
}

/// The read-only open of an unheld conversation (Spec 013 §7): the descriptor's facts plus a
/// timeline read once through the vendor's own protocol. No adoption is implied, no vendor
/// session is opened, and a failed read degrades to an empty timeline — the pick-up slot is
/// the point of the screen, and a short history is a degradation where a refused open was a
/// wall.
pub(crate) fn unheld_snapshot(
    row: &UnheldThread,
    entries: Vec<NormalizedTimelineEntry>,
) -> crate::agent_protocol::AgentSessionSnapshot {
    let descriptor = unheld_descriptor(row);
    let timeline: Vec<crate::agent_protocol::TimelineEntry> = entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| crate::agent_protocol::TimelineEntry {
            entry_id: entry.source_id,
            entry_revision: entry.source_revision,
            sequence: index as u64 + 1,
            timestamp: entry.timestamp,
            state: entry.state,
            kind: entry.kind,
            body: entry.body,
            truncation: entry.truncation,
        })
        .collect();
    let newest = timeline.last().map(|entry| entry.sequence);
    crate::agent_protocol::AgentSessionSnapshot {
        v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
        session_id: descriptor.session_id,
        snapshot_epoch: 1,
        revision: 1,
        process_generation: descriptor.process_generation,
        adapter: crate::agent_protocol::AgentAdapterMetadata {
            family: descriptor.adapter_family,
            version: descriptor.adapter_version,
            compatibility: "compatible".into(),
        },
        topology: descriptor.topology,
        presence: descriptor.presence,
        stored_reason: None,
        drift: None,
        control_owner: "terminal".into(),
        observation: descriptor.observation,
        turn: descriptor.turn,
        permission_mode: None,
        model: None,
        effort: None,
        models: None,
        capabilities: descriptor.capabilities,
        pending_interactions: Vec::new(),
        timeline_window: crate::agent_protocol::TimelineWindow {
            oldest_sequence: timeline.first().map(|entry| entry.sequence),
            newest_sequence: newest,
            entries: timeline,
            has_older: false,
            history_boundary: None,
            truncated: false,
        },
        terminal_fallback: descriptor.terminal_fallback,
        latest_command_receipts: Vec::new(),
    }
}

/// The model surface an adopted thread offers, read from the vendor at pickup: which model the
/// thread runs now, at what effort, and the catalogue `model/list` answers. All of it is the
/// vendor's — nothing here is compiled in — which is what lets the phone's picker stay
/// adapter-neutral. An empty catalogue leaves the picker hidden, the truthful degraded shape
/// when `model/list` fails, and exactly the pre-wiring behaviour.
pub(crate) struct ModelSurface {
    pub(crate) current: Option<String>,
    pub(crate) effort: Option<String>,
    pub(crate) catalogue: Vec<AgentModelOption>,
}

impl ModelSurface {
    /// The surface a vendor offering nothing leaves behind; the ledger pins what it produces.
    #[cfg(test)]
    pub(crate) fn none() -> Self {
        Self {
            current: None,
            effort: None,
            catalogue: Vec::new(),
        }
    }
}

/// `model/list` → the adapter-neutral catalogue. Hidden rows are the vendor's own "do not
/// offer" flag and are honoured. A row that fails the wire grammar is skipped rather than
/// poisoning the list — one bad descriptor once made a phone reject an entire session list
/// (2026-08-04), and a catalogue is the same all-or-nothing shape app-side.
fn catalogue_from_model_list(response: &Value) -> Vec<AgentModelOption> {
    let Some(data) = response["data"].as_array() else {
        return Vec::new();
    };
    data.iter()
        .filter(|row| !row["hidden"].as_bool().unwrap_or(false))
        .filter_map(|row| {
            let value = row["id"].as_str()?.to_owned();
            let display_name = row["displayName"].as_str().unwrap_or(&value).to_owned();
            let supported_effort_levels: Vec<String> = row["supportedReasoningEfforts"]
                .as_array()
                .map(|efforts| {
                    efforts
                        .iter()
                        .filter_map(|effort| effort["reasoningEffort"].as_str())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            let option = AgentModelOption {
                value,
                display_name,
                supports_effort: !supported_effort_levels.is_empty(),
                supported_effort_levels,
            };
            option.validate().ok().map(|()| option)
        })
        .take(MAX_MODEL_CATALOGUE_ENTRIES)
        .collect()
}

/// Reads the whole surface at pickup. The current model and effort ride the `thread/resume`
/// response the adapter already holds; only the catalogue costs a request. Every read is
/// tolerant: a vendor that answers strangely produces a smaller surface, never a failed adopt.
async fn model_surface(connection: &AppServerConnection, resumed: &Value) -> ModelSurface {
    let current = resumed["model"]
        .as_str()
        .filter(|model| crate::agent_protocol::valid_model_id(model).is_ok())
        .map(str::to_owned);
    let effort = resumed["reasoningEffort"]
        .as_str()
        .filter(|effort| crate::agent_protocol::valid_token(effort).is_ok())
        .map(str::to_owned);
    let catalogue = match connection.request("model/list", json!({})).await {
        Ok(response) => catalogue_from_model_list(&response),
        Err(error) => {
            tracing::debug!(target: "codex_adopted", %error, "model/list failed; no catalogue");
            Vec::new()
        }
    };
    ModelSurface {
        current,
        effort,
        catalogue,
    }
}

/// Everything adopt() needs to know, resolved by the caller: the binary comes from the
/// persisted registration evidence (never `PATH`), the rollout path from `thread/list`.
pub(crate) struct AdoptParams {
    pub(crate) binary: PathBuf,
    pub(crate) thread_id: String,
    pub(crate) rollout: Option<PathBuf>,
    pub(crate) workspace_display: String,
    pub(crate) workspace_path: Option<String>,
    pub(crate) adapter_version: String,
}

/// Why an adoption was refused, each with the categorical token the outcome frame carries.
#[derive(Debug)]
pub(crate) enum AdoptRefusal {
    AlreadyPickedUp,
    NoContent,
    TerminalHolds,
    // Held for the log line at the refusal site; the phone sees only the categorical token.
    Vendor(#[allow(dead_code)] anyhow::Error),
}

impl AdoptRefusal {
    pub(crate) fn reason_code(&self) -> &'static str {
        match self {
            Self::AlreadyPickedUp => "already_live",
            Self::NoContent => "no_content",
            Self::TerminalHolds => "terminal_holds_conversation",
            Self::Vendor(_) => "adoption_failed",
        }
    }
}

/// Adopts an unheld thread: preconditions, resume, registration, and the pump. Returns the
/// Ciao session ID the phone opens — the same stable ID the discovery row carried.
pub(crate) async fn adopt(
    supervisor: AgentSessionSupervisor,
    registry: std::sync::Arc<AdoptionRegistry>,
    notifier: crate::notify::Notifier,
    params: AdoptParams,
) -> std::result::Result<String, AdoptRefusal> {
    // Preconditions in spec order (§5). The registry is claimed last, once the child exists,
    // but a concurrent claim in the window is closed by claim() itself refusing.
    if registry.session_for(&params.thread_id).is_some() {
        return Err(AdoptRefusal::AlreadyPickedUp);
    }
    let rollout = params
        .rollout
        .as_deref()
        .filter(|path| path.exists())
        .ok_or(AdoptRefusal::NoContent)?;
    let holders = rollout_holders(rollout)
        .await
        .map_err(AdoptRefusal::Vendor)?;
    if !holders.is_empty() {
        return Err(AdoptRefusal::TerminalHolds);
    }

    let (mut connection, events) = AppServerConnection::connect(&params.binary)
        .await
        .map_err(AdoptRefusal::Vendor)?;
    let resumed = match connection
        .request("thread/resume", json!({"threadId": params.thread_id}))
        .await
    {
        Ok(resumed) => resumed,
        Err(error) => {
            connection.shutdown().await;
            return Err(AdoptRefusal::Vendor(error));
        }
    };
    // The resume response carries `thread.turns` in the same shape `thread/read` answers, so
    // the Spec 012 history mapper applies unchanged. There is no live tail to exclude: the
    // empty run ID matches no turn.
    let entries = codex_history::map_thread(&resumed, "");
    let models = model_surface(&connection, &resumed).await;

    let (command_sender, command_receiver) = mpsc::channel::<BridgeCommandEnvelope>(16);
    let registration = adopted_registration(&params, &models);
    let registered = match supervisor.register(registration, command_sender).await {
        Ok(registered) => registered,
        Err(error) => {
            connection.shutdown().await;
            return Err(AdoptRefusal::Vendor(error));
        }
    };
    if let Err(error) = supervisor.replace_bridge_snapshot(&registered.session_id, entries) {
        connection.shutdown().await;
        return Err(AdoptRefusal::Vendor(error));
    }
    // The surface the registration's capability bits promised, published as state. Registration
    // itself carries no model fields — the same update path the managed worker uses fills them,
    // so both integrations converge on one supervisor mechanism.
    if let Some(model) = models.current.clone() {
        supervisor.update_bridge_model(&registered.session_id, model);
    }
    if let Some(effort) = models.effort.clone() {
        supervisor.update_bridge_effort(&registered.session_id, effort);
    }
    if !models.catalogue.is_empty() {
        supervisor.update_bridge_model_catalogue(&registered.session_id, models.catalogue.clone());
    }

    let (release_sender, release_receiver) = mpsc::channel(4);
    if registry
        .claim(
            &params.thread_id,
            &registered.session_id,
            connection.pid(),
            release_sender,
        )
        .is_err()
    {
        connection.shutdown().await;
        return Err(AdoptRefusal::AlreadyPickedUp);
    }

    let session_id = registered.session_id.clone();
    tokio::spawn(run_adopted(AdoptedRuntime {
        supervisor,
        registry,
        notifier,
        connection,
        events,
        commands: command_receiver,
        release: release_receiver,
        registered,
        thread_id: params.thread_id,
        rollout: rollout.to_path_buf(),
        models,
    }));
    Ok(session_id)
}

/// Whether an adopted thread's recorded CLI version admits the write surface.
///
/// A version the vendor declared breaking closes the door; a version Ciao cannot read does not
/// invent a refusal — `thread/list` defaults `cliVersion` to `unknown` when absent, and turning
/// every such row read-only would refuse conversations this machine's own pinned Codex wrote.
/// GAP(parity): the tested-minor gate every other integration applies needs grounded evidence
/// that real rows carry `cliVersion` reliably; until then the major bound is what can be
/// promised honestly.
/// GAP(carry): once that evidence exists, the right tightening is carried-or-grounded, not
/// tested-minor — `codex_carry::state_for` already answers it, and its verdict names which
/// write-relevant lists (`steerRequiredParams`, `requiredClientMethods`, the decision sets)
/// moved, which is the per-method degradation Spec 017 Phase 3 sketches. Not wired here until
/// the cliVersion evidence lands: tightening a write gate on a field observed unreliable
/// would refuse threads this machine's own Codex wrote.
fn adopted_compatible(version: &str) -> bool {
    crate::agent_protocol::version_major_matches(
        version,
        crate::codex_adapter::PINNED_CODEX_VERSION,
    ) || crate::agent_protocol::parse_version(version).is_none()
}

pub(crate) fn adopted_registration(
    params: &AdoptParams,
    models: &ModelSurface,
) -> NormalizedRegistration {
    let compatible = adopted_compatible(&params.adapter_version);
    NormalizedRegistration {
        history_boundary: None,
        // The stable conversation identity, shared with the discovery row the person tapped:
        // the session that opens is the row they chose, not a freshly minted ID they must
        // re-ask for.
        upstream_identity: codex_conversation_session_id(&params.thread_id),
        process_nonce: keyed_digest(CODEX_ADOPTED_DOMAIN, "nonce", &params.thread_id),
        process_id: std::process::id(),
        adapter_family: "Codex".into(),
        adapter_version: params.adapter_version.clone(),
        topology: "adopted".into(),
        compatible,
        // `grounded` here means "inside this adapter's own admission rule", which for adopted
        // threads is deliberately the major bound (the GAP(parity) note on
        // `adopted_compatible`), not the attached tested-minor floor. Adopted rows never carry
        // an `ahead` label until that gate is tightened on evidence.
        version_state: if compatible {
            "grounded"
        } else {
            "unsupported"
        }
        .into(),
        tested_version: crate::codex_adapter::PINNED_CODEX_VERSION.into(),
        workspace_display: params.workspace_display.clone(),
        workspace_path: params.workspace_path.clone(),
        observation: Observation {
            coverage: "authoritative".into(),
            reason_code: if compatible {
                "adopted_stream"
            } else {
                "adapter_version_unsupported"
            }
            .into(),
            last_authoritative_at: Some(unix_now()),
        },
        turn: TurnState::Idle,
        capabilities: AgentCapabilities {
            history: "live_tail".into(),
            // A declared-breaking build advertises nothing, like every other integration:
            // the timeline stays readable, the write surface is withdrawn.
            commands: if compatible {
                CommandCapabilities {
                    prompt: true,
                    steer: true,
                    follow_up: false,
                    interrupt: true,
                    // GAP(parity): adopted Codex never restores or reports a permission mode,
                    // so a takeover lands in whatever default the app-server picks (managed
                    // Claude keeps the mode the conversation already had).
                    permission_mode: false,
                    // The 08-05 audit's "named next pass", now wired: the catalogue is what
                    // `model/list` answered at pickup and the write is `thread/settings/update`
                    // behind the experimentalApi handshake. Both bits stay honest to the
                    // vendor's actual answer — a failed or empty `model/list` advertises
                    // nothing, which is exactly the pre-wiring shape: no picker rather than a
                    // picker that does nothing.
                    model: !models.catalogue.is_empty(),
                    effort: models.catalogue.iter().any(|option| option.supports_effort),
                }
            } else {
                CommandCapabilities::none()
            },
            interactions: if compatible {
                InteractionCapabilities {
                    permission: InteractionCapability {
                        enabled: true,
                        max_questions: 1,
                        max_options_per_question: 4,
                        allows_free_text: false,
                    },
                    ..InteractionCapabilities::none()
                }
            } else {
                InteractionCapabilities::none()
            },
            pending_rehydration: if compatible {
                "current_process"
            } else {
                "none"
            }
            .into(),
            // Registration continuity is always unavailable — continuity is the supervisor's
            // to grant, and for adopted it grants resumable_session structurally at
            // registration (agent_session::register_new).
            terminal_continuity: "unavailable".into(),
        },
        control_owner: "none".into(),
    }
}

struct AdoptedRuntime {
    supervisor: AgentSessionSupervisor,
    registry: std::sync::Arc<AdoptionRegistry>,
    notifier: crate::notify::Notifier,
    connection: AppServerConnection,
    events: mpsc::Receiver<AppServerEvent>,
    commands: mpsc::Receiver<BridgeCommandEnvelope>,
    release: mpsc::Receiver<ReleaseReason>,
    registered: RegisteredAgentSession,
    thread_id: String,
    rollout: PathBuf,
    /// The pickup-time surface, kept current as settings commands succeed: `current` is what
    /// the effort closed-check validates against, and `catalogue` is the closed set itself.
    models: ModelSurface,
}

/// Live state the pump tracks between events.
#[derive(Default)]
struct TurnTracking {
    /// The vendor's active turn ID, from `turn/started` — the steer fence and interrupt target.
    vendor_turn_id: Option<String>,
    /// Monotonic revision per source entry, for streamed assistant text and tool updates.
    revisions: HashMap<String, u64>,
    /// Pending approvals: interaction ID → (vendor request id, decisions offered).
    approvals: HashMap<String, (Value, Vec<String>)>,
}

async fn run_adopted(mut runtime: AdoptedRuntime) {
    let session = runtime.registered.session_id.clone();
    let mut tracking = TurnTracking::default();
    let mut watch = time::interval(DESCRIPTOR_WATCH_INTERVAL);
    watch.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
    // Set once a release was requested while a turn is streaming: the turn may finish inside
    // the cap (§5 grace completion), after which the release goes through.
    let mut deferred_release: Option<(ReleaseReason, time::Instant)> = None;

    let reason = loop {
        if let Some((reason, since)) = deferred_release {
            let no_turn = tracking.vendor_turn_id.is_none();
            let blocked = !tracking.approvals.is_empty();
            if no_turn || blocked || since.elapsed() > GRACE_COMPLETION_CAP {
                // A waiting approval cannot complete on its own — nobody is left to answer
                // it — so it is interrupted rather than waited for.
                if blocked && let Some(turn) = tracking.vendor_turn_id.clone() {
                    let _ = runtime
                        .connection
                        .request(
                            "turn/interrupt",
                            json!({"threadId": runtime.thread_id, "turnId": turn}),
                        )
                        .await;
                }
                break reason;
            }
        }
        tokio::select! {
            event = runtime.events.recv() => match event {
                Some(AppServerEvent::Notification { method, params }) => {
                    on_notification(&runtime.supervisor, &session, &mut tracking, &method, &params);
                }
                Some(AppServerEvent::ServerRequest { id, method, params }) => {
                    on_server_request(&runtime, &session, &mut tracking, id, &method, &params).await;
                }
                Some(AppServerEvent::Closed { reason }) => {
                    tracing::warn!(target: "codex_adopted", %reason, "adopted app-server closed");
                    break ReleaseReason::ConnectionLost;
                }
                None => break ReleaseReason::ConnectionLost,
            },
            envelope = runtime.commands.recv() => match envelope {
                Some(envelope) => {
                    on_command(&mut runtime, &session, &mut tracking, envelope).await;
                }
                None => break ReleaseReason::ConversationClosed,
            },
            requested = runtime.release.recv() => {
                let requested = requested.unwrap_or(ReleaseReason::ConversationClosed);
                match requested {
                    // The person is at a terminal: yield now, mid-turn included (§5).
                    ReleaseReason::ForeignTerminal | ReleaseReason::ForeignWriter => break requested,
                    _ if tracking.vendor_turn_id.is_some() => {
                        deferred_release.get_or_insert((requested, time::Instant::now()));
                    }
                    _ => break requested,
                }
            },
            _ = watch.tick() => {
                // Filtered and confirmed: our own child appends transiently, and only a
                // sustained holder outside its tree is a terminal. A probe that cannot
                // answer is retried; releasing on a transient failure would drop a healthy
                // hold.
                if foreign_rollout_holder(&runtime.rollout, runtime.connection.pid()).await {
                    break ReleaseReason::ForeignTerminal;
                }
            },
        }
    };
    release(runtime, tracking, reason).await;
}

async fn release(mut runtime: AdoptedRuntime, tracking: TurnTracking, reason: ReleaseReason) {
    let session = runtime.registered.session_id.clone();
    // A turn interrupted by a yield is reported as interrupted, never left claiming to run.
    if matches!(
        reason,
        ReleaseReason::ForeignTerminal | ReleaseReason::ForeignWriter
    ) && let Some(turn) = tracking.vendor_turn_id.clone()
    {
        let _ = runtime
            .connection
            .request(
                "turn/interrupt",
                json!({"threadId": runtime.thread_id, "turnId": turn}),
            )
            .await;
    }
    runtime.registry.remove(&runtime.thread_id);
    runtime.connection.shutdown().await;
    tracing::info!(
        target: "codex_adopted",
        reason = reason.token(),
        dropped_deltas = runtime.connection.dropped_deltas(),
        "adopted Codex session released"
    );
    runtime.supervisor.end_adopted_session(
        &session,
        runtime.registered.process_generation,
        reason.token(),
    );
}

fn on_notification(
    supervisor: &AgentSessionSupervisor,
    session: &str,
    tracking: &mut TurnTracking,
    method: &str,
    params: &Value,
) {
    tracing::debug!(%method, "app-server notification");
    match method {
        "turn/started" => {
            let turn_id = params["turn"]["id"].as_str().unwrap_or_default().to_owned();
            let run_id = codex_run_id(&turn_id);
            tracking.vendor_turn_id = Some(turn_id);
            let _ = supervisor.note_bridge_turn(
                session,
                TurnState::Running {
                    run_id,
                    activity: "responding".into(),
                },
            );
        }
        "turn/completed" | "turn/failed" => {
            let turn = &params["turn"];
            let run_id = turn["id"].as_str().map(codex_run_id);
            let status = turn["status"].as_str().unwrap_or("completed");
            tracking.vendor_turn_id = None;
            let state = match status {
                "interrupted" => TurnState::Interrupted { run_id },
                "failed" => TurnState::Failed {
                    run_id,
                    category: "vendor_reported".into(),
                },
                _ => TurnState::Completed { run_id },
            };
            let _ = supervisor.note_bridge_turn(session, state);
        }
        "item/started" | "item/completed" => {
            let item = &params["item"];
            let complete = method == "item/completed";
            if let Some(entry) = live_item_entry(tracking, item, complete) {
                let _ = supervisor.upsert_bridge_entry(session, entry);
            }
        }
        "item/agentMessage/delta" => {
            let source_id = entry_source_id(params["itemId"].as_str().unwrap_or_default());
            let delta = params["delta"].as_str().unwrap_or_default();
            if delta.is_empty() {
                return;
            }
            let revision = tracking.next_revision(&source_id);
            let (text, truncation) = bounded_text(delta, MAX_LIVE_TEXT_DELTA_BYTES);
            let _ = supervisor.append_bridge_text(
                session,
                NormalizedTextDelta {
                    source_id,
                    source_revision: revision,
                    timestamp: unix_now(),
                    kind: "assistant_message".into(),
                    delta: text,
                    final_chunk: false,
                    truncation,
                },
            );
        }
        // GAP(drift): deliberately not tallied. The pin's distilled schema names only the
        // notifications this adapter handles, so a novel method is indistinguishable here from
        // one of the ~65 known methods it deliberately ignores — tallying would fill the ledger
        // at the pinned version and mean nothing. Spec 017 Phase 3's fuller extract carries the
        // complete list; the membership test lands then.
        _ => {}
    }
}

impl TurnTracking {
    fn next_revision(&mut self, source_id: &str) -> u64 {
        let revision = self.revisions.entry(source_id.to_owned()).or_insert(0);
        *revision += 1;
        *revision
    }
}

fn entry_source_id(item_id: &str) -> String {
    format!(
        "codex.item.{}",
        keyed_digest(CODEX_ADOPTED_DOMAIN, "item", item_id)
    )
}

/// Maps one live thread item event onto a canonical entry. The completed shapes intentionally
/// match the history mapper's vocabulary so a streamed conversation and a re-read one agree.
fn live_item_entry(
    tracking: &mut TurnTracking,
    item: &Value,
    complete: bool,
) -> Option<NormalizedTimelineEntry> {
    let item_id = item["id"].as_str()?;
    let source_id = entry_source_id(item_id);
    let revision = tracking.next_revision(&source_id);
    let item_kind = item["type"].as_str()?;
    if !crate::codex_adapter::known_thread_item(item_kind) {
        crate::drift::note("codex", "adopted_item", "unknown_item", item_kind, None);
    }
    let projection = (item_kind == "functionCallOutput")
        .then(|| crate::codex_history::function_output(item, complete))
        .flatten();
    let (kind, body, truncation) = match item_kind {
        "functionCallOutput" if projection.is_some() => {
            let (tool, truncation) = projection.unwrap();
            ("tool", TimelineBody::Tool { tool }, truncation)
        }
        "userMessage" => {
            // Same shape live as in the rollout: the text lives in `content` blocks, not a
            // top-level `text` (which is kept as a fallback against pin drift).
            let mut text = crate::codex_history::content_text(item);
            if text.is_empty() {
                text = item["text"].as_str().unwrap_or_default().to_owned();
            }
            let (text, truncation) = bounded_text(&text, MAX_TIMELINE_TEXT_BYTES);
            ("user_message", TimelineBody::Text { text }, truncation)
        }
        "agentMessage" => {
            // Deltas already streamed the text; the completed item carries it whole and
            // supersedes them. A started agentMessage with no text yet is skipped — the first
            // delta creates the entry.
            if !complete {
                return None;
            }
            let (text, truncation) = bounded_text(
                item["text"].as_str().unwrap_or_default(),
                MAX_TIMELINE_TEXT_BYTES,
            );
            ("assistant_message", TimelineBody::Text { text }, truncation)
        }
        "commandExecution"
        | "fileChange"
        | "mcpToolCall"
        | "dynamicToolCall"
        | "collabAgentToolCall"
        | "webSearch" => {
            let name = match item_kind {
                "commandExecution" => "shell",
                "fileChange" => "apply_patch",
                "webSearch" => "web_search",
                other => other,
            };
            let (input_preview, input_truncated) = bounded_preview(
                item.get("command").or_else(|| item.get("query")),
                MAX_TOOL_INPUT_PREVIEW_BYTES,
            );
            let (result_preview, result_truncated) = if complete {
                bounded_preview(item.get("aggregatedOutput"), MAX_TOOL_RESULT_PREVIEW_BYTES)
            } else {
                (None, false)
            };
            let mut truncation = no_truncation();
            if input_truncated || result_truncated {
                truncation.truncated = true;
                truncation.reason_code = Some("preview_bounded".into());
            }
            (
                "tool",
                TimelineBody::Tool {
                    tool: ToolTimelineBody {
                        name: name.into(),
                        status: if complete {
                            match item["status"].as_str() {
                                Some("failed") => "failed".into(),
                                _ => "completed".into(),
                            }
                        } else {
                            "running".into()
                        },
                        input_preview,
                        result_preview,
                    },
                },
                truncation,
            )
        }
        _ => {
            // Same split as the history reader: a card for the person, and a drift tally only
            // when the pin never listed the type (Spec 017 §4.2).
            (
                "unsupported",
                TimelineBody::Unsupported {
                    reason_code: "codex_item_unsupported".into(),
                },
                no_truncation(),
            )
        }
    };
    Some(NormalizedTimelineEntry {
        source_id,
        source_revision: revision,
        timestamp: unix_now(),
        state: if complete { "complete" } else { "streaming" }.into(),
        kind: kind.into(),
        body,
        truncation,
    })
}

async fn on_server_request(
    runtime: &AdoptedRuntime,
    session: &str,
    tracking: &mut TurnTracking,
    id: Value,
    method: &str,
    params: &Value,
) {
    match method {
        "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
            let offered: Vec<String> = match params["availableDecisions"].as_array() {
                // The card offers the intersection, in Ciao's canonical order; an unknown
                // decision is dropped, never guessed at.
                Some(available) => KNOWN_DECISIONS
                    .iter()
                    .filter(|known| available.iter().any(|value| value.as_str() == Some(known)))
                    .map(|known| (*known).to_owned())
                    .collect(),
                None => KNOWN_DECISIONS
                    .iter()
                    .map(|known| (*known).to_owned())
                    .collect(),
            };
            if offered.is_empty() {
                let _ = runtime
                    .connection
                    .refuse(id, "no decision Ciao understands is available")
                    .await;
                return;
            }
            let item_id = params["itemId"].as_str().unwrap_or_default();
            let interaction_id = format!(
                "codex.approval.{}",
                keyed_digest(CODEX_ADOPTED_DOMAIN, "approval", item_id)
            );
            let body = if method.starts_with("item/commandExecution") {
                bounded_preview(params.get("command"), MAX_TOOL_INPUT_PREVIEW_BYTES)
                    .0
                    .unwrap_or_else(|| "Run a command".into())
            } else {
                "Apply the proposed file changes".to_owned()
            };
            let interaction = PendingInteraction {
                interaction_id: interaction_id.clone(),
                interaction_revision: 1,
                kind: "permission".into(),
                blocking: true,
                created_at: unix_now(),
                expires_at: None,
                title: Some(
                    if method.starts_with("item/commandExecution") {
                        "Run command"
                    } else {
                        "Apply file changes"
                    }
                    .into(),
                ),
                body,
                response_schema: ResponseSchema::Choices {
                    minimum: 1,
                    maximum: 1,
                    choices: offered
                        .iter()
                        .map(|decision| ResponseChoice {
                            choice_id: decision.clone(),
                            label: decision_label(decision).into(),
                            description: None,
                            scope: None,
                        })
                        .collect(),
                },
                terminal_fallback: TerminalFallback {
                    continuity: "unavailable".into(),
                    route_id: None,
                    availability_reason: Some("adopted_session".into()),
                    handback_session: None,
                    resume_command: None,
                },
                state: "pending".into(),
            };
            if runtime
                .supervisor
                .upsert_bridge_interaction(session, interaction)
                .is_ok()
            {
                tracking.approvals.insert(interaction_id, (id, offered));
                let run_id = tracking.vendor_turn_id.as_deref().map(codex_run_id);
                let _ = runtime
                    .supervisor
                    .note_bridge_turn(session, TurnState::AwaitingInteraction { run_id });
                // ADR 005, same moment as every other integration: the card blocks the turn,
                // and this is the push that reaches a pocket. Managed and adopted were the two
                // paths that could raise a card and not say so — this closes the adopted half.
                let (workspace, title) = runtime
                    .supervisor
                    .notification_facts(session)
                    .unwrap_or_default();
                runtime.notifier.notify(
                    session,
                    &workspace,
                    title.as_deref(),
                    "permission_prompt",
                    unix_now(),
                );
            } else {
                // The card could not be raised; refusing beats a request nobody can see.
                let _ = runtime
                    .connection
                    .refuse(id, "the approval could not be surfaced")
                    .await;
            }
        }
        _ => {
            // Question, elicitation, and anything newer are not supported natively yet
            // (Spec 013 §3); refusing by error keeps the vendor's turn from waiting on an
            // answer that can never come.
            let _ = runtime
                .connection
                .refuse(id, "this request is not supported natively by Ciao yet")
                .await;
        }
    }
}

fn decision_label(decision: &str) -> &'static str {
    match decision {
        "accept" => "Allow once",
        "acceptForSession" => "Allow for this session",
        "decline" => "Deny",
        _ => "Answer",
    }
}

async fn on_command(
    runtime: &mut AdoptedRuntime,
    session: &str,
    tracking: &mut TurnTracking,
    envelope: BridgeCommandEnvelope,
) {
    let command = envelope.command;
    let command_id = command.command_id.clone();
    // The descriptor is re-asked before every write (§5): a terminal that appeared since the
    // last watch tick wins without racing it.
    if matches!(
        command.kind,
        AgentCommandKind::Prompt { .. } | AgentCommandKind::Steer { .. }
    ) && foreign_rollout_holder(&runtime.rollout, runtime.connection.pid()).await
    {
        // "rejected" is the receipt vocabulary's word for it — record_bridge_receipt accepts
        // only accepted/applied/rejected and silently records nothing for anything else,
        // which left the phone waiting on "accepted" forever (2026-08-04).
        let _ = runtime.supervisor.record_bridge_receipt(
            session,
            &command_id,
            "rejected",
            None,
            Some("foreign_terminal"),
        );
        runtime
            .registry
            .request_release(&runtime.thread_id, ReleaseReason::ForeignTerminal);
        return;
    }
    let outcome = match &command.kind {
        AgentCommandKind::Prompt { text } | AgentCommandKind::Steer { text } => {
            send_text(runtime, tracking, text).await
        }
        AgentCommandKind::Interrupt => match tracking.vendor_turn_id.clone() {
            Some(turn) => runtime
                .connection
                .request(
                    "turn/interrupt",
                    json!({"threadId": runtime.thread_id, "turnId": turn}),
                )
                .await
                .map(|_| ()),
            None => Err(anyhow!("no turn is running")),
        },
        AgentCommandKind::InteractionResponse {
            interaction_id,
            answer,
            ..
        } => answer_approval(runtime, session, tracking, interaction_id, answer).await,
        AgentCommandKind::SetModel { model } => set_model(runtime, session, model.clone()).await,
        AgentCommandKind::SetEffort { effort } => {
            set_effort(runtime, session, effort.clone()).await
        }
        _ => Err(anyhow!(
            "this command is not supported for an adopted session"
        )),
    };
    match outcome {
        Ok(()) => {
            // "applied" with evidence, per the receipt contract the phone frees its composer
            // on: the vendor's own RPC answer is the proof of application. "completed" was
            // outside record_bridge_receipt's vocabulary, so no final receipt was ever
            // published and the phone spun on "accepted" forever (2026-08-04).
            let _ = runtime.supervisor.record_bridge_receipt(
                session,
                &command_id,
                "applied",
                Some("vendor_rpc_answer"),
                None,
            );
        }
        Err(error) => {
            tracing::debug!(target: "codex_adopted", %error, "adopted command failed");
            let _ = runtime.supervisor.record_bridge_receipt(
                session,
                &command_id,
                "rejected",
                None,
                Some("vendor_refused"),
            );
        }
    }
}

/// The composer's one rule (§6): a running turn is steered behind its fence; no turn starts
/// one. A fence refusal — the turn ended between the phone's tap and the send — retries once
/// as a fresh turn rather than losing the words.
async fn send_text(
    runtime: &AdoptedRuntime,
    tracking: &mut TurnTracking,
    text: &str,
) -> Result<()> {
    let input = json!([{"type": "text", "text": text}]);
    if let Some(turn) = tracking.vendor_turn_id.clone() {
        let steered = runtime
            .connection
            .request(
                "turn/steer",
                json!({
                    "threadId": runtime.thread_id,
                    "expectedTurnId": turn,
                    "input": input,
                }),
            )
            .await;
        if steered.is_ok() {
            return Ok(());
        }
    }
    runtime
        .connection
        .request(
            "turn/start",
            json!({"threadId": runtime.thread_id, "input": input}),
        )
        .await
        .map(|_| ())
}

/// The closed check the protocol layer deliberately leaves to the adapter (`valid_model_id`
/// is grammar only): a model outside the catalogue this session advertised is refused before
/// the vendor sees it. `thread/settings/update` answers `{}` whatever it was fed — probed
/// against 0.147.0 — so an unchecked pass-through would confirm a change that never happened.
fn validate_model_choice(models: &ModelSurface, model: &str) -> Result<()> {
    if !models.catalogue.iter().any(|option| option.value == model) {
        bail!("that model is not in this session's catalogue");
    }
    Ok(())
}

/// Same closed check for effort, against the *active* model's own levels: the vendor accepts
/// a level the model does not support and silently runs another, and the phone would show
/// the lie — the exact silent downgrade the app-side picker refuses to offer.
fn validate_effort_choice(models: &ModelSurface, effort: &str) -> Result<()> {
    let active = models
        .current
        .as_deref()
        .and_then(|current| {
            models
                .catalogue
                .iter()
                .find(|option| option.value == current)
        })
        .ok_or_else(|| anyhow!("the active model offers no effort choice"))?;
    if !active
        .supported_effort_levels
        .iter()
        .any(|level| level == effort)
    {
        bail!("the active model does not offer that effort level");
    }
    Ok(())
}

/// Settings updates apply to subsequent turns (vendor semantics), so a change mid-turn is
/// legal and takes effect on the next send. State is updated only after the vendor's RPC
/// answer, which is the same evidence the receipt carries.
async fn set_model(runtime: &mut AdoptedRuntime, session: &str, model: String) -> Result<()> {
    validate_model_choice(&runtime.models, &model)?;
    runtime
        .connection
        .request(
            "thread/settings/update",
            json!({"threadId": runtime.thread_id, "model": model}),
        )
        .await?;
    runtime.models.current = Some(model.clone());
    runtime.supervisor.update_bridge_model(session, model);
    Ok(())
}

async fn set_effort(runtime: &mut AdoptedRuntime, session: &str, effort: String) -> Result<()> {
    validate_effort_choice(&runtime.models, &effort)?;
    runtime
        .connection
        .request(
            "thread/settings/update",
            json!({"threadId": runtime.thread_id, "effort": effort}),
        )
        .await?;
    runtime.models.effort = Some(effort.clone());
    runtime.supervisor.update_bridge_effort(session, effort);
    Ok(())
}

async fn answer_approval(
    runtime: &AdoptedRuntime,
    session: &str,
    tracking: &mut TurnTracking,
    interaction_id: &str,
    answer: &InteractionAnswer,
) -> Result<()> {
    let (vendor_id, offered) = tracking
        .approvals
        .remove(interaction_id)
        .ok_or_else(|| anyhow!("this approval is no longer pending"))?;
    let InteractionAnswer::Choices { choice_ids } = answer else {
        tracking
            .approvals
            .insert(interaction_id.to_owned(), (vendor_id, offered));
        bail!("an approval answer must be a choice");
    };
    let decision = choice_ids.first().cloned().unwrap_or_default();
    if !offered.contains(&decision) {
        tracking
            .approvals
            .insert(interaction_id.to_owned(), (vendor_id, offered));
        bail!("that decision was not offered");
    }
    runtime
        .connection
        .answer(vendor_id, json!({"decision": decision}))
        .await?;
    let _ = runtime
        .supervisor
        .resolve_bridge_interaction(session, interaction_id, "answered");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn function_output_live_history_parity() {
        let item = json!({"type":"functionCallOutput","id":"scope-live",
            "name":"CANARY invalid token", "status":"failed", "output":"line one\nline two"});
        let mut tracking = TurnTracking::default();
        let started = live_item_entry(&mut tracking, &item, false).unwrap();
        let completed = live_item_entry(&mut tracking, &item, true).unwrap();
        started.validate().unwrap();
        completed.validate().unwrap();
        assert_eq!(started.source_id, completed.source_id);
        assert_eq!(completed.source_revision, started.source_revision + 1);
        assert_eq!(started.state, "streaming");
        let TimelineBody::Tool { tool } = started.body else {
            panic!("tool")
        };
        assert_eq!(tool.status, "running");
        assert!(tool.result_preview.is_none());
        let history = crate::codex_history::map_thread(
            &json!({"thread":{
            "turns":[{"id":"turn","items":[item]}]}}),
            "",
        );
        assert_eq!(completed.body, history[0].body);
        assert_eq!(completed.truncation, history[0].truncation);
        assert_eq!(completed.state, "complete");
    }

    #[test]
    fn model_list_maps_to_the_neutral_catalogue() {
        // Grounded: the row shape `model/list` answered on 0.147.0 (probed 2026-08-18),
        // trimmed to the fields the mapper reads plus the ones it must ignore.
        let response = serde_json::json!({"data": [
            {"id": "gpt-5.6-sol", "displayName": "GPT-5.6-Sol", "hidden": false,
             "isDefault": true, "defaultReasoningEffort": "low",
             "supportedReasoningEfforts": [
                {"reasoningEffort": "low", "description": "Fast"},
                {"reasoningEffort": "high", "description": "Deep"},
                {"reasoningEffort": "ultra", "description": "Delegating"}]},
            {"id": "gpt-5.6-internal", "displayName": "Internal", "hidden": true,
             "supportedReasoningEfforts": []},
            {"id": "bad id with spaces", "displayName": "Broken",
             "supportedReasoningEfforts": []},
            {"id": "gpt-5.6-luna", "displayName": "GPT-5.6-Luna",
             "supportedReasoningEfforts": []},
        ]});
        let catalogue = super::catalogue_from_model_list(&response);
        // Hidden is the vendor's own "do not offer"; the malformed id is skipped rather
        // than poisoning the list (the 2026-08-04 failure shape).
        assert_eq!(
            catalogue
                .iter()
                .map(|option| option.value.as_str())
                .collect::<Vec<_>>(),
            vec!["gpt-5.6-sol", "gpt-5.6-luna"]
        );
        assert!(catalogue[0].supports_effort);
        assert_eq!(
            catalogue[0].supported_effort_levels,
            ["low", "high", "ultra"]
        );
        assert!(!catalogue[1].supports_effort);
        assert!(catalogue[1].supported_effort_levels.is_empty());
    }

    #[test]
    fn model_list_answering_nothing_is_an_empty_catalogue() {
        assert!(super::catalogue_from_model_list(&serde_json::json!({})).is_empty());
        assert!(super::catalogue_from_model_list(&serde_json::json!({"data": []})).is_empty());
    }

    #[test]
    fn choices_outside_the_surface_are_refused() {
        let surface = super::ModelSurface {
            current: Some("gpt-5.6-sol".into()),
            effort: Some("high".into()),
            catalogue: vec![
                crate::agent_protocol::AgentModelOption {
                    value: "gpt-5.6-sol".into(),
                    display_name: "GPT-5.6-Sol".into(),
                    supports_effort: true,
                    supported_effort_levels: vec!["low".into(), "high".into()],
                },
                crate::agent_protocol::AgentModelOption {
                    value: "gpt-5.6-luna".into(),
                    display_name: "GPT-5.6-Luna".into(),
                    supports_effort: false,
                    supported_effort_levels: Vec::new(),
                },
            ],
        };
        assert!(super::validate_model_choice(&surface, "gpt-5.6-luna").is_ok());
        assert!(super::validate_model_choice(&surface, "gpt-6-imagined").is_err());
        assert!(super::validate_effort_choice(&surface, "low").is_ok());
        // A level the active model does not list is the silent-downgrade case.
        assert!(super::validate_effort_choice(&surface, "ultra").is_err());

        // With the active model unknown to the catalogue there is no level list to check
        // against, so every effort is refused rather than guessed at.
        let unknown_active = super::ModelSurface {
            current: Some("gpt-something-new".into()),
            ..surface
        };
        assert!(super::validate_effort_choice(&unknown_active, "low").is_err());
    }

    #[test]
    fn live_user_message_reads_its_content_blocks() {
        // Grounded: a live `userMessage` item carries `content: [{type,text}]`, same as the
        // rollout shape — there is no top-level `text`. Reading the wrong field rendered
        // every sent message as a blank bubble on the phone (2026-08-04).
        let mut tracking = super::TurnTracking::default();
        let item = serde_json::json!({
            "id": "item-1",
            "type": "userMessage",
            "content": [{"type": "text", "text": "say exactly: pong"}],
        });
        let entry = super::live_item_entry(&mut tracking, &item, true).expect("entry");
        assert_eq!(entry.kind, "user_message");
        match &entry.body {
            crate::agent_protocol::TimelineBody::Text { text } => {
                assert_eq!(text, "say exactly: pong");
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }

    #[test]
    fn a_completed_tool_result_is_bounded_by_the_result_envelope_not_the_input_one() {
        // Regression: the result arm passed MAX_TOOL_INPUT_PREVIEW_BYTES (16 KiB) — copied from
        // the input arm — where the protocol admits results twice that size. A command whose
        // aggregated output serialized between the two envelopes lost its preview entirely.
        //
        // Many short lines rather than one long string, so the per-string cap inside
        // `bounded_preview` never engages and the envelope constant is the only thing under test.
        let mut tracking = super::TurnTracking::default();
        let output_lines: Vec<String> = (0..96)
            .map(|line| format!("line {line:03} {}", "x".repeat(240)))
            .collect();
        let item = serde_json::json!({
            "id": "item-2",
            "type": "commandExecution",
            "status": "completed",
            "command": "cargo test",
            "aggregatedOutput": output_lines,
        });
        let encoded = serde_json::to_string(&item["aggregatedOutput"])
            .unwrap()
            .len();
        assert!(
            encoded > crate::agent_protocol::MAX_TOOL_INPUT_PREVIEW_BYTES
                && encoded <= crate::agent_protocol::MAX_TOOL_RESULT_PREVIEW_BYTES,
            "fixture must sit between the two envelopes, got {encoded}"
        );
        let entry = super::live_item_entry(&mut tracking, &item, true).expect("entry");
        match &entry.body {
            crate::agent_protocol::TimelineBody::Tool { tool } => {
                let preview = tool
                    .result_preview
                    .as_deref()
                    .expect("a result within the protocol's result envelope is kept");
                assert!(preview.contains("line 095"));
                assert!(!entry.truncation.truncated);
            }
            other => panic!("unexpected body: {other:?}"),
        }
    }

    use super::*;

    #[tokio::test]
    async fn the_kernel_names_this_process_while_it_holds_a_file() {
        if !std::process::Command::new("sh")
            .args(["-c", "command -v lsof"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rollout-fixture.jsonl");
        std::fs::write(&path, b"{}\n").unwrap();
        // Not held: nobody has it open, and lsof's nonzero exit is an answer, not an error.
        assert_eq!(rollout_holders(&path).await.unwrap(), Vec::<u32>::new());
        // Held: this very process keeps it open, and the kernel says so.
        let held = std::fs::File::open(&path).unwrap();
        let holders = rollout_holders(&path).await.unwrap();
        assert!(
            holders.contains(&std::process::id()),
            "expected {} in {holders:?}",
            std::process::id()
        );
        drop(held);
    }

    #[test]
    fn one_adopter_per_thread_and_release_reaches_it() {
        let registry = AdoptionRegistry::default();
        let (sender, mut receiver) = mpsc::channel(2);
        registry
            .claim("thread-a", "session-a", Some(42), sender)
            .unwrap();
        assert_eq!(
            registry.session_for("thread-a").as_deref(),
            Some("session-a")
        );
        let (second, _second_receiver) = mpsc::channel(2);
        assert!(
            registry
                .claim("thread-a", "session-b", None, second)
                .is_err()
        );

        registry.request_release("thread-a", ReleaseReason::ConversationClosed);
        assert_eq!(
            receiver.try_recv().ok(),
            Some(ReleaseReason::ConversationClosed)
        );
        registry.remove("thread-a");
        assert!(registry.session_for("thread-a").is_none());
    }

    #[test]
    fn a_foreign_hook_process_triggers_the_yield_and_our_own_child_does_not() {
        let registry = AdoptionRegistry::default();
        let (sender, mut receiver) = mpsc::channel(2);
        registry
            .claim("thread-a", "session-a", Some(42), sender)
            .unwrap();
        // Our own adopted child's hooks fire for our own turns; that is not a foreign owner.
        registry.note_hook_event("thread-a", 42);
        assert!(receiver.try_recv().is_err());
        // A different process writing the same thread is.
        registry.note_hook_event("thread-a", 43);
        assert_eq!(receiver.try_recv().ok(), Some(ReleaseReason::ForeignWriter));
    }

    /// The whole adopted flow against the pinned binary: seed a conversation, adopt it, send
    /// a prompt through the real supervisor path, watch it stream, release, and leave nothing
    /// behind. Gated on its own variable — it spends **two model turns** on the signed-in
    /// account and creates (then archives) a real thread — so `CIAO_TEST_CODEX_CLI` runs stay
    /// free and this is opted into by name:
    ///
    ///   CIAO_TEST_CODEX_E2E=1 cargo test -p ciao-host --lib grounded_end_to_end -- --nocapture
    #[tokio::test(flavor = "multi_thread")]
    async fn grounded_end_to_end_pickup_prompt_release() {
        if std::env::var("CIAO_TEST_CODEX_E2E").as_deref() != Ok("1") {
            return;
        }
        use crate::workspace::WorkspaceConfig;
        let temp = tempfile::tempdir().unwrap();
        let supervisor = AgentSessionSupervisor::load(
            &temp.path().join("agent-metadata.json"),
            WorkspaceConfig::with_binary_dirs(Vec::new()),
        )
        .unwrap();
        let registry = std::sync::Arc::new(AdoptionRegistry::load(
            temp.path().join("codex-runtime.json"),
        ));
        let cwd = temp.path().join("workspace");
        std::fs::create_dir_all(&cwd).unwrap();

        // Seed: a conversation with one finished turn, then nobody holding it — the shape a
        // closed terminal leaves behind. Model turn one.
        let (mut seeder, mut seed_events) = AppServerConnection::connect(Path::new("codex"))
            .await
            .unwrap();
        let started = seeder
            .request("thread/start", json!({"cwd": cwd}))
            .await
            .unwrap();
        let thread_id = started["thread"]["id"].as_str().unwrap().to_owned();
        seeder
            .request(
                "turn/start",
                json!({"threadId": thread_id, "input": [{"type": "text", "text": "Reply with exactly: seeded"}]}),
            )
            .await
            .unwrap();
        // `turn/start` answers immediately (grounded); the rollout exists only once content
        // lands, so seeding means waiting for the turn to actually finish.
        let seed_deadline = std::time::Instant::now() + Duration::from_secs(120);
        loop {
            match tokio::time::timeout(Duration::from_secs(5), seed_events.recv()).await {
                Ok(Some(AppServerEvent::Notification { method, .. }))
                    if method == "turn/completed" || method == "turn/failed" =>
                {
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) => panic!("the seeder connection died mid-turn"),
                Err(_) => assert!(
                    std::time::Instant::now() < seed_deadline,
                    "the seed turn never completed"
                ),
            }
        }
        let rollout = {
            let mut found = None;
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while found.is_none() {
                let listed = seeder
                    .request("thread/list", json!({"limit": 30}))
                    .await
                    .unwrap();
                found = listed["data"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["id"].as_str() == Some(thread_id.as_str()))
                    .and_then(|row| row["path"].as_str())
                    .map(PathBuf::from);
                if found.is_none() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "the seeded thread never listed its rollout path"
                    );
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
            found.unwrap()
        };
        seeder.shutdown().await;
        poll_until_holders_gone(&rollout).await;

        let binary = which_codex();
        let params = |binary: PathBuf| AdoptParams {
            binary,
            thread_id: thread_id.clone(),
            rollout: Some(rollout.clone()),
            workspace_display: "e2e".into(),
            workspace_path: Some(cwd.to_string_lossy().into_owned()),
            adapter_version: "0.147.0".into(),
        };

        // A push with no paired devices is a no-op, which is exactly what a test wants.
        let notifier = crate::notify::Notifier::new(
            std::sync::Arc::new(parking_lot::Mutex::new(
                crate::storage::PairedDeviceStore::load(temp.path().join("paired-devices.json"))
                    .unwrap(),
            )),
            "fixture-host".into(),
        );

        // A held rollout refuses adoption by name — the terminal stand-in is this process.
        let held = std::fs::File::open(&rollout).unwrap();
        let refused = adopt(
            supervisor.clone(),
            registry.clone(),
            notifier.clone(),
            params(binary.clone()),
        )
        .await;
        assert!(
            matches!(refused, Err(AdoptRefusal::TerminalHolds)),
            "expected TerminalHolds, got {refused:?}"
        );
        drop(held);
        poll_until_holders_gone(&rollout).await;

        // Pick it up for real.
        let session_id = adopt(
            supervisor.clone(),
            registry.clone(),
            notifier,
            params(binary),
        )
        .await
        .expect("adoption succeeds on the unheld thread");
        assert_eq!(session_id, codex_conversation_session_id(&thread_id));
        let snapshot = supervisor.snapshot(&session_id).expect("adopted snapshot");
        assert_eq!(snapshot.topology, "adopted");
        assert!(
            snapshot
                .timeline_window
                .entries
                .iter()
                .any(|entry| entry.kind == "user_message"),
            "the resumed history carries the seeded prompt"
        );

        // Model turn two, through the real command path: submit → pump → turn/start → stream.
        let command = crate::agent_protocol::AgentCommand {
            v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
            command_id: "e2e-prompt-command-1".into(),
            session_id: session_id.clone(),
            snapshot_epoch: snapshot.snapshot_epoch,
            expected_generation: snapshot.process_generation,
            expected_revision: None,
            kind: AgentCommandKind::Prompt {
                text: "Reply with exactly: adopted".into(),
            },
        };
        let receipt = supervisor.submit_command(command).await;
        assert!(
            !matches!(receipt.state.as_str(), "rejected" | "unavailable" | "stale"),
            "the prompt was refused before reaching the pump: {receipt:?}"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        let mut saw_running = false;
        let final_turn = loop {
            let current = supervisor.snapshot(&session_id).expect("snapshot").turn;
            match &current {
                TurnState::Running { .. } => saw_running = true,
                TurnState::Completed { .. } => break current,
                _ => {}
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the adopted turn never completed; last state {current:?}"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        assert!(saw_running, "the turn was seen running before completing");
        assert!(matches!(final_turn, TurnState::Completed { .. }));
        let snapshot = supervisor.snapshot(&session_id).unwrap();
        let assistant = snapshot
            .timeline_window
            .entries
            .iter()
            .filter(|entry| entry.kind == "assistant_message")
            .count();
        assert!(assistant >= 1, "the streamed answer landed in the timeline");
        // The receipt must reach a final state the phone's vocabulary knows, or the composer
        // holds "working" forever: record_bridge_receipt records nothing for states outside
        // accepted/applied/rejected, which is exactly what happened with "completed".
        let final_receipt = snapshot
            .latest_command_receipts
            .iter()
            .find(|receipt| receipt.command_id == "e2e-prompt-command-1")
            .expect("the prompt's receipt is published");
        assert_eq!(
            final_receipt.state, "applied",
            "the prompt's receipt reached its final state: {final_receipt:?}"
        );
        assert!(
            final_receipt.application_evidence.is_some(),
            "an applied receipt carries its evidence"
        );

        // The model surface the pickup read. The catalogue is `model/list`'s answer and the
        // reported model is the thread's own — none of it compiled in.
        let snapshot = supervisor.snapshot(&session_id).unwrap();
        assert!(
            snapshot.capabilities.commands.model,
            "a live model/list advertises the picker"
        );
        let catalogue = snapshot.models.clone().expect("the catalogue is published");
        let reported = snapshot.model.clone().expect("the thread names its model");
        assert!(
            catalogue.iter().any(|option| option.value == reported),
            "the reported model {reported} is a catalogue row"
        );

        // Flip the model through the real command path, then prove the vendor took it — a
        // write that answers success unapplied is the npm-install no-op wearing JSON-RPC.
        let flipped = catalogue
            .iter()
            .map(|option| option.value.clone())
            .find(|value| value != &reported)
            .expect("the catalogue offers an alternative model");
        let set_model = crate::agent_protocol::AgentCommand {
            v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
            command_id: "e2e-set-model-1".into(),
            session_id: session_id.clone(),
            snapshot_epoch: snapshot.snapshot_epoch,
            expected_generation: snapshot.process_generation,
            expected_revision: None,
            kind: AgentCommandKind::SetModel {
                model: flipped.clone(),
            },
        };
        let receipt = supervisor.submit_command(set_model).await;
        assert!(
            !matches!(receipt.state.as_str(), "rejected" | "unavailable" | "stale"),
            "the model change was refused before reaching the pump: {receipt:?}"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let snapshot = supervisor.snapshot(&session_id).unwrap();
            if snapshot.model.as_deref() == Some(flipped.as_str()) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the confirmed model never reached the snapshot"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Same round trip for effort, against the flipped model's own levels.
        let flipped_levels = catalogue
            .iter()
            .find(|option| option.value == flipped)
            .map(|option| option.supported_effort_levels.clone())
            .unwrap_or_default();
        if let Some(level) = flipped_levels.first().cloned() {
            let set_effort = crate::agent_protocol::AgentCommand {
                v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
                command_id: "e2e-set-effort-1".into(),
                session_id: session_id.clone(),
                snapshot_epoch: snapshot.snapshot_epoch,
                expected_generation: snapshot.process_generation,
                expected_revision: None,
                kind: AgentCommandKind::SetEffort {
                    effort: level.clone(),
                },
            };
            let receipt = supervisor.submit_command(set_effort).await;
            assert!(
                !matches!(receipt.state.as_str(), "rejected" | "unavailable" | "stale"),
                "the effort change was refused before reaching the pump: {receipt:?}"
            );
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                let snapshot = supervisor.snapshot(&session_id).unwrap();
                if snapshot.effort.as_deref() == Some(level.as_str()) {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the confirmed effort never reached the snapshot"
                );
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }

        // Release on close: the hold clears, the session becomes an unheld attached record.
        registry.request_release(&thread_id, ReleaseReason::ConversationClosed);
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            let snapshot = supervisor.snapshot(&session_id).expect("snapshot survives");
            if snapshot.topology == "attached" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "release never flipped the session back to attached"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            registry.session_for(&thread_id).is_none(),
            "the claim cleared"
        );
        poll_until_holders_gone(&rollout).await;

        // The vendor's own read-back, from a fresh process: the settings write persisted on
        // the thread itself, not merely in the adapter's memory of it.
        let (mut cleaner, _cleaner_events) =
            AppServerConnection::connect(&which_codex()).await.unwrap();
        let resumed = cleaner
            .request("thread/resume", json!({"threadId": thread_id}))
            .await
            .unwrap();
        assert_eq!(
            resumed["model"].as_str(),
            Some(flipped.as_str()),
            "a fresh resume reports the flipped model"
        );

        // Leave the account tidy: archive the seeded thread.
        cleaner
            .request("thread/archive", json!({"threadId": thread_id}))
            .await
            .unwrap();
        cleaner.shutdown().await;
    }

    async fn poll_until_holders_gone(rollout: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !rollout_holders(rollout)
            .await
            .unwrap_or_default()
            .is_empty()
        {
            assert!(
                std::time::Instant::now() < deadline,
                "rollout holders never cleared"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn which_codex() -> PathBuf {
        let output = std::process::Command::new("sh")
            .args(["-c", "command -v codex"])
            .output()
            .expect("resolve codex");
        PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    #[test]
    fn binary_evidence_survives_a_registry_reload() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("codex-runtime.json");
        let binary = directory.path().join("codex");
        std::fs::write(&binary, b"#!/bin/sh\n").unwrap();

        let registry = AdoptionRegistry::load(file.clone());
        assert!(registry.recorded_binary().is_none());
        registry.record_binary_evidence(binary.clone());
        assert_eq!(registry.recorded_binary(), Some(binary.clone()));

        // A fresh daemon reads what the last one proved.
        let reloaded = AdoptionRegistry::load(file);
        assert_eq!(reloaded.recorded_binary(), Some(binary.clone()));

        // Evidence whose binary vanished disables discovery truthfully.
        std::fs::remove_file(&binary).unwrap();
        assert!(reloaded.recorded_binary().is_none());
    }

    #[test]
    fn unheld_rows_keep_only_threads_that_exist_on_disk() {
        let listed = json!({"data": [
            {"id": "thread-a", "path": "/tmp/rollout-a.jsonl", "cwd": "/home/user/project",
             "preview": "fix the parser\nsecond line", "updatedAt": 1_700_000_000_u64,
             "cliVersion": "0.146.0", "name": null},
            {"id": "thread-b", "path": null, "cwd": "/home/user/other"},
        ]});
        let rows = unheld_rows(&listed);
        assert_eq!(
            rows.len(),
            1,
            "a thread without a rollout has nothing to pick up"
        );
        let row = &rows[0];
        assert_eq!(row.thread_id, "thread-a");
        assert_eq!(row.session_id, codex_conversation_session_id("thread-a"));
        assert_eq!(row.preview.as_deref(), Some("fix the parser"));
        // Seconds pass through untouched; a millisecond-shaped value is scaled down
        // instead of rendering as 1970.
        assert_eq!(row.updated_at, 1_700_000_000);
        let millisecond_shaped = json!({"data": [
            {"id": "thread-ms", "path": "/tmp/rollout-ms.jsonl", "cwd": "/home/user/project",
             "updatedAt": 1_700_000_000_000_u64, "cliVersion": "0.146.0"},
        ]});
        assert_eq!(
            unheld_rows(&millisecond_shaped)[0].updated_at,
            1_700_000_000
        );

        // The directory row is a valid attached descriptor any app can render.
        let descriptor = unheld_descriptor(row);
        descriptor.validate().unwrap();
        assert_eq!(descriptor.workspace_display, "project");
        assert_eq!(
            descriptor.capabilities.terminal_continuity,
            "resumable_session"
        );
        assert_eq!(descriptor.observation.reason_code, "unheld_record");
    }

    #[test]
    fn an_unheld_snapshot_validates_and_keeps_the_pickup_surface() {
        let listed = json!({"data": [
            {"id": "thread-snap", "path": "/tmp/rollout-snap.jsonl", "cwd": "/home/user/project",
             "preview": "hello", "updatedAt": 1_700_000_000_u64, "cliVersion": "0.146.0"},
        ]});
        let row = unheld_rows(&listed).into_iter().next().unwrap();
        let entries = vec![
            NormalizedTimelineEntry {
                source_id: "codex.item.fixture-1".into(),
                source_revision: 1,
                timestamp: 1_700_000_000,
                state: "complete".into(),
                kind: "user_message".into(),
                body: TimelineBody::Text {
                    text: "hello".into(),
                },
                truncation: no_truncation(),
            },
            NormalizedTimelineEntry {
                source_id: "codex.item.fixture-2".into(),
                source_revision: 1,
                timestamp: 1_700_000_001,
                state: "complete".into(),
                kind: "assistant_message".into(),
                body: TimelineBody::Text {
                    text: "Ciao! How can I help?".into(),
                },
                truncation: no_truncation(),
            },
        ];
        let snapshot = unheld_snapshot(&row, entries);
        snapshot.validate().unwrap();
        assert_eq!(snapshot.session_id, row.session_id);
        assert_eq!(snapshot.timeline_window.entries.len(), 2);
        assert_eq!(snapshot.timeline_window.newest_sequence, Some(2));
        // The point of the screen: read-only facts that leave the pick-up slot offerable.
        assert_eq!(snapshot.capabilities.commands, CommandCapabilities::none());
        assert_eq!(snapshot.topology, "attached");
        // And an empty read still opens rather than refusing.
        let empty = unheld_snapshot(&row, Vec::new());
        empty.validate().unwrap();
        assert!(empty.timeline_window.entries.is_empty());
    }

    #[test]
    fn approval_decisions_intersect_with_the_vendor_and_keep_canonical_order() {
        let available = json!(["decline", "somethingNew", "accept"]);
        let offered: Vec<String> = KNOWN_DECISIONS
            .iter()
            .filter(|known| {
                available
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value.as_str() == Some(known))
            })
            .map(|known| (*known).to_owned())
            .collect();
        assert_eq!(offered, vec!["accept".to_owned(), "decline".to_owned()]);
    }

    #[test]
    fn live_items_map_to_the_history_vocabulary() {
        let mut tracking = TurnTracking::default();
        let user = live_item_entry(
            &mut tracking,
            &json!({"id": "item-1", "type": "userMessage", "text": "hello"}),
            true,
        )
        .unwrap();
        assert_eq!(user.kind, "user_message");
        assert_eq!(user.state, "complete");

        // A started agent message has nothing to say yet; the first delta creates the entry.
        assert!(
            live_item_entry(
                &mut tracking,
                &json!({"id": "item-2", "type": "agentMessage"}),
                false,
            )
            .is_none()
        );

        let command = live_item_entry(
            &mut tracking,
            &json!({
                "id": "item-3",
                "type": "commandExecution",
                "command": "echo hi",
                "status": "completed",
                "aggregatedOutput": "hi\n",
            }),
            true,
        )
        .unwrap();
        assert_eq!(command.kind, "tool");
        assert_eq!(command.state, "complete");

        let exotic = live_item_entry(
            &mut tracking,
            &json!({"id": "item-4", "type": "imageGeneration"}),
            true,
        )
        .unwrap();
        assert_eq!(exotic.kind, "unsupported");

        // Revisions stay monotonic per source: the same item completed after starting moves
        // forward, never backward.
        let started = live_item_entry(
            &mut tracking,
            &json!({"id": "item-5", "type": "commandExecution", "command": "ls"}),
            false,
        )
        .unwrap();
        let completed = live_item_entry(
            &mut tracking,
            &json!({"id": "item-5", "type": "commandExecution", "command": "ls", "status": "completed"}),
            true,
        )
        .unwrap();
        assert_eq!(started.source_id, completed.source_id);
        assert!(completed.source_revision > started.source_revision);
    }
}
