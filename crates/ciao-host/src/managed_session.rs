//! Spec 006 §8: the daemon-owned managed session directory.
//!
//! This module holds bounded lifecycle and ownership facts only: which managed
//! sessions exist, whether each is live or stored, why a stored session
//! stopped, and receipted lifecycle outcomes. The vendor wire terminates in
//! the worker; no timeline content, prompt text, or vendor payload enters this
//! store. Raw vendor session IDs and workspace paths stay in the restrictive
//! metadata file and never cross to iOS.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;
use rand::random;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::agent_protocol::{
    AGENT_PROTOCOL_VERSION, AgentAdapterMetadata, AgentCapabilities, AgentSessionDescriptor,
    AgentSessionSnapshot, AgentWorkspaceList, CommandCapabilities, InteractionCapabilities,
    LifecycleOutcome, MAX_LIFECYCLE_RECEIPTS, MAX_RECENT_PROMPT_BYTES, MAX_WORKSPACE_LABEL_BYTES,
    MAX_WORKSPACE_LIST_ENTRIES, Observation, TerminalFallback, TimelineWindow, TurnState,
    WorkspaceDescriptor, valid_opaque_id, valid_token,
};
use crate::agent_session::PromotionTarget;
use crate::managed_worker::{ManagedRuntime, SharedWorkerTable};
use crate::storage::{atomic_write_private, validate_private_file};

const MANAGED_METADATA_VERSION: u8 = 1;
const MAX_MANAGED_RECORDS: usize = 256;
const MAX_MANAGED_METADATA_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// How long the home scan gets before the daemon answers without it.
///
/// The walk has no timeout of its own, and on macOS a `read_dir` of Desktop, Documents or
/// Downloads blocks for as long as the consent dialog sits unanswered on that Mac's screen. The
/// request came from a phone, so nobody is there to answer it, and the wait is unbounded: the
/// sheet said "Checking…" until the app was killed. Well above a warm scan of a large home, well
/// below how long anyone stares at a spinner.
const WORKSPACE_SCAN_DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);

/// Facts a launcher must return for a worker it successfully started. The
/// launcher owns process supervision; the directory owns the session record.
#[derive(Debug, Clone)]
pub(crate) struct LaunchedWorker {
    /// `None` until the worker's first turn creates a vendor session.
    pub(crate) vendor_session_id: Option<String>,
    pub(crate) adapter_family: String,
    pub(crate) adapter_version: String,
}

/// What a release hands back. The vendor session ID stays host-side for the local CLI's
/// fallback line; only `route_session` is fit to cross to a client, and it is the same
/// non-secret provider session name the accepted durable-route path already carries.
#[derive(Debug, Clone)]
pub(crate) struct Handback {
    pub(crate) vendor_session_id: String,
    /// `None` when no terminal session could be created — tmux absent, or the conversation
    /// failed to start. Ownership is surrendered either way.
    pub(crate) route_session: Option<String>,
}

// Consumed by the fake launcher today; the real worker launcher wires every
// field in step 6.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct LaunchSpec {
    pub(crate) session_id: String,
    pub(crate) workspace_path: PathBuf,
    pub(crate) resume_vendor_session: Option<String>,
    /// The mode the conversation being resumed was last running under, when it can be read.
    /// `None` for a session started fresh, which has no conversation to inherit from, and the
    /// worker's own default stands.
    pub(crate) permission_mode: Option<String>,
    /// The model that conversation was last answered by, on the same terms. A resume that
    /// silently moved the conversation onto a different model would change the answers for a
    /// reason nobody chose.
    pub(crate) model: Option<String>,
}

/// The worker launcher behind the directory. A host without an installed
/// managed integration still uses `Worker`: pin resolution refuses every
/// start/resume categorically with `runtime_unavailable`, while stop and
/// listing keep their real semantics.
#[derive(Debug)]
pub(crate) enum ManagedLauncher {
    Worker(Box<WorkerLauncher>),
    #[cfg(test)]
    Fake(fake::FakeLauncher),
}

/// Owns the pinned-pair resolution and the supervised worker table.
#[derive(Debug)]
pub(crate) struct WorkerLauncher {
    sdk_prefix: PathBuf,
    worker_entrypoint: PathBuf,
    socket_path: PathBuf,
    workers: SharedWorkerTable,
}

impl WorkerLauncher {
    pub(crate) fn new(
        sdk_prefix: PathBuf,
        worker_entrypoint: PathBuf,
        socket_path: PathBuf,
        workers: SharedWorkerTable,
    ) -> Self {
        Self {
            sdk_prefix,
            worker_entrypoint,
            socket_path,
            workers,
        }
    }

    async fn launch(
        &self,
        spec: &LaunchSpec,
        workspace_label: &str,
    ) -> Result<LaunchedWorker, &'static str> {
        // The pin pair is verified before every spawn: an auto-updated or
        // tampered artifact must not silently change a worker's behavior.
        // Spec 017 §6: when the gate refuses a runtime a completed install once verified, the
        // daemon gets one bounded attempt to restore the pinned artifact — never to accept the
        // drifted one — before the refusal surfaces exactly as it always did. The person who
        // tapped Start waits a few seconds for a working session instead of reading an error.
        let runtime = match ManagedRuntime::resolve(&self.sdk_prefix, &self.worker_entrypoint) {
            Ok(runtime) => runtime,
            Err(reason) => {
                let sdk_prefix = self.sdk_prefix.clone();
                let worker_entrypoint = self.worker_entrypoint.clone();
                let restored = tokio::task::spawn_blocking(move || {
                    crate::claude_managed_integration::try_restore_managed_claude_once(
                        &sdk_prefix,
                        &worker_entrypoint,
                    )
                })
                .await
                .unwrap_or(false);
                if !restored {
                    return Err(reason);
                }
                ManagedRuntime::resolve(&self.sdk_prefix, &self.worker_entrypoint)
                    .map_err(|_| reason)?
            }
        };
        self.workers
            .spawn(
                &runtime,
                &spec.session_id,
                &spec.workspace_path,
                workspace_label,
                &self.socket_path,
                spec.resume_vendor_session.as_deref(),
                spec.permission_mode.as_deref(),
                spec.model.as_deref(),
            )
            .map_err(|_| "runtime_unavailable")?;
        Ok(LaunchedWorker {
            // A fresh worker has no vendor session until its first turn creates
            // one; the worker reports the real ID then. Grounded: the SDK is
            // lazy and emits no session identity before the first prompt.
            vendor_session_id: spec.resume_vendor_session.clone(),
            adapter_family: "Claude".into(),
            adapter_version: runtime.cli_version,
        })
    }

    /// Puts the released conversation into a detached terminal session and returns its name.
    ///
    /// The same pinned CLI the worker itself ran, launched through the recorded interpreter
    /// with the recorded PATH: the daemon cannot see a version-manager Node install, and a
    /// handback that resolves a different Claude than the one Ciao verified would defeat the
    /// pin the managed path exists to hold.
    async fn handback(
        &self,
        workspace: &str,
        session_name: &str,
        vendor_session: &str,
    ) -> Option<String> {
        let runtime = ManagedRuntime::resolve(&self.sdk_prefix, &self.worker_entrypoint).ok()?;
        let home = crate::pty::resolve_account().ok()?.home;
        let config = crate::workspace::WorkspaceConfig::for_home(&home);
        let request = crate::workspace::HandbackRequest {
            session: session_name,
            workspace,
            tool_path: &runtime.tool_path,
            cli: runtime.cli_path.to_str()?,
            vendor_session,
        };
        crate::workspace::create_handback_session(&config, &request)
            .await
            .then(|| session_name.to_owned())
    }

    /// Ends the handback terminal this launcher created, so its conversation can be taken back.
    async fn close_handback(&self, session_name: &str) -> bool {
        let Ok(account) = crate::pty::resolve_account() else {
            return false;
        };
        let config = crate::workspace::WorkspaceConfig::for_home(&account.home);
        crate::workspace::close_handback_session(&config, session_name).await
    }
}

impl ManagedLauncher {
    async fn launch(
        &self,
        spec: &LaunchSpec,
        workspace_label: &str,
    ) -> Result<LaunchedWorker, &'static str> {
        match self {
            Self::Worker(launcher) => launcher.launch(spec, workspace_label).await,
            #[cfg(test)]
            Self::Fake(fake) => fake.launch(spec),
        }
    }

    async fn stop(&self, session_id: &str) {
        match self {
            Self::Worker(launcher) => {
                launcher.workers.stop(session_id).await;
            }
            #[cfg(test)]
            Self::Fake(fake) => fake.stop(session_id),
        }
    }

    async fn foreign_owner_evidence(&self, vendor_session_id: &str, ignoring: Option<u32>) -> bool {
        match self {
            Self::Worker(_) => {
                crate::managed_worker::foreign_owner_evidence(vendor_session_id, ignoring).await
            }
            #[cfg(test)]
            Self::Fake(fake) => fake.foreign_owner_evidence(vendor_session_id, ignoring),
        }
    }

    async fn handback(
        &self,
        workspace: &str,
        session_name: &str,
        vendor_session: &str,
    ) -> Option<String> {
        match self {
            Self::Worker(launcher) => {
                launcher
                    .handback(workspace, session_name, vendor_session)
                    .await
            }
            #[cfg(test)]
            Self::Fake(fake) => fake.handback(session_name),
        }
    }

    async fn close_handback(&self, session_name: &str) -> bool {
        match self {
            Self::Worker(launcher) => launcher.close_handback(session_name).await,
            #[cfg(test)]
            Self::Fake(fake) => fake.close_handback(session_name),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ManagedSessionDirectory {
    store: Arc<Mutex<ManagedMetadataStore>>,
    launcher: Arc<ManagedLauncher>,
    /// Root of the workspace scan. Held here rather than passed per call because the list and
    /// the start that follows it must scan the same tree, or an ID the phone was just offered
    /// resolves to nothing.
    home: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct ManagedSessionSummary {
    pub(crate) session_id: String,
    pub(crate) presence: String,
    pub(crate) stored_reason: Option<String>,
    pub(crate) workspace_label: String,
    pub(crate) process_generation: u64,
    pub(crate) updated_at: u64,
}

impl ManagedSessionDirectory {
    pub(crate) fn load(path: &Path, home: &Path, launcher: ManagedLauncher) -> Result<Self> {
        let mut store = ManagedMetadataStore::load(path)?;
        // Daemon restart is a session fact: any record still marked live lost its
        // worker with the previous daemon and resumes only by explicit command.
        let mut transitioned = false;
        for record in &mut store.records {
            if record.presence == "live" {
                record.presence = "stored".into();
                record.stored_reason = Some("daemon_restart".into());
                record.updated_at = unix_now();
                transitioned = true;
            }
        }
        if transitioned {
            store.persist()?;
        }
        Ok(Self {
            store: Arc::new(Mutex::new(store)),
            launcher: Arc::new(launcher),
            home: home.to_owned(),
        })
    }

    /// Workspaces Ciao has run a session in, then every other git checkout under home.
    ///
    /// Spec 006 §7.3 listed records only, which meant the first session in any directory had to
    /// be started from the host CLI — the one step that sent someone back to their laptop.
    /// Discovery removes it without widening the wire: a found path is hashed into the same
    /// keyed opaque ID a record would have carried, so the two sources deduplicate by
    /// construction and no path crosses to iOS.
    ///
    /// Records lead because a workspace you have already used is the likelier answer than one
    /// merely present on disk, and its label is the one the phone has seen before.
    ///
    /// A scan that times out or is refused still produces a list — the records alone if that is
    /// all that is left. Partial results are results, and `scan_incomplete` is how the phone knows
    /// to say the list may be short rather than presenting it as the whole truth.
    pub(crate) async fn workspaces(&self) -> AgentWorkspaceList {
        // Scanned before the lock is taken: this is filesystem work on the daemon's runtime, and
        // holding the store across it would block every lifecycle command behind a syscall walk.
        let scan = self.scan_home().await;
        let scan_incomplete = scan.as_ref().is_none_or(|scan| scan.denied);
        let discovered = scan.map(|scan| scan.paths).unwrap_or_default();
        let store = self.store.lock();
        // Carried as paths and labelled at the end, because whether a name needs qualifying
        // depends on the rest of the list — and on the list as *sent*, so this happens after the
        // cap rather than before it.
        let mut seen = Vec::<(String, PathBuf)>::new();
        let mut records: Vec<_> = store.records.iter().collect();
        records.sort_by_key(|record| std::cmp::Reverse(record.updated_at));
        for record in records {
            if seen.iter().any(|(id, _)| *id == record.workspace_id) {
                continue;
            }
            seen.push((
                record.workspace_id.clone(),
                PathBuf::from(&record.workspace_path),
            ));
        }
        for path in discovered {
            let workspace_id = store.workspace_id(&path);
            if seen.iter().any(|(id, _)| *id == workspace_id) {
                continue;
            }
            seen.push((workspace_id, path));
        }
        let omitted = seen.len().saturating_sub(MAX_WORKSPACE_LIST_ENTRIES) as u32;
        seen.truncate(MAX_WORKSPACE_LIST_ENTRIES);
        AgentWorkspaceList {
            v: AGENT_PROTOCOL_VERSION,
            message_type: "agent_workspace_list".into(),
            workspaces: workspace_labels(&seen, &self.home),
            omitted_workspaces: omitted,
            scan_incomplete,
        }
    }

    /// One walk of home, off the runtime thread and on a deadline. `None` means it did not finish
    /// in time and the caller must answer without it.
    ///
    /// `spawn_blocking` because the walk is blocking syscalls: run inline, an unanswered macOS
    /// permission dialog does not merely delay this request, it parks a runtime thread that every
    /// other request on the connection is queued behind.
    ///
    /// ponytail: the thread that lost the race is left running rather than cancelled, because a
    /// `read_dir` blocked inside the kernel cannot be cancelled. It finishes the moment someone
    /// answers the dialog, and one tap on New agent starts at most one of them, so the leak is
    /// bounded by how many times a person will tap a button that is visibly not working.
    async fn scan_home(&self) -> Option<crate::workspace_scan::WorkspaceScan> {
        let home = self.home.clone();
        let scan = tokio::task::spawn_blocking(move || {
            crate::workspace_scan::discover_git_workspaces(&home)
        });
        tokio::time::timeout(WORKSPACE_SCAN_DEADLINE, scan)
            .await
            .ok()?
            .ok()
    }

    /// Every handback route this directory would advertise, so the caller can ask the provider
    /// which of them still exist before any of it reaches a client.
    pub(crate) fn handback_session_names(&self) -> Vec<String> {
        let store = self.store.lock();
        store
            .records
            .iter()
            .filter(|record| record.presence == "stored")
            .filter_map(|record| record.handback_session.clone())
            .collect()
    }

    /// Bounded descriptors for stored managed sessions; live managed sessions are
    /// presented by the supervisor while their worker is registered.
    ///
    /// `live_terminals` is the subset of `handback_session_names` the provider still has. A
    /// released record whose terminal the user has since closed keeps its record and its
    /// **Released** state, and loses only the route — the row stops offering a way back that
    /// would land on nothing.
    /// Live sessions whose conversation a terminal has also opened.
    ///
    /// ADR 004 §5 allows exactly one owner per vendor session, but the check ran only before a
    /// worker started. `claude --resume` *after* that was invisible, so both processes appended
    /// to one transcript and the conversation forked. Ownership is not a fact that can be
    /// established once; a live session has to keep answering for it.
    pub(crate) async fn foreign_owned_live_sessions(&self) -> Vec<String> {
        let live: Vec<(String, String)> = self
            .store
            .lock()
            .records
            .iter()
            .filter(|record| record.presence == "live" && !record.externally_owned)
            .filter_map(|record| {
                Some((record.session_id.clone(), record.vendor_session_id.clone()?))
            })
            .collect();
        let mut found = Vec::new();
        for (session_id, vendor) in live {
            if self.launcher.foreign_owner_evidence(&vendor, None).await {
                found.push(session_id);
            }
        }
        found
    }

    /// Drops a stored record so it stops appearing in the directory.
    ///
    /// A daemon restart stores every live session, which during development means they pile up
    /// with no way to remove them — the other five verbs all move a session between states and
    /// none of them ends one. Refuses while live, because forgetting a running worker would
    /// orphan the process rather than stop it.
    ///
    /// This deletes Ciao's mapping metadata only. Per ADR 004 §7 the vendor session store is
    /// the transcript of record, so the conversation itself survives and stays resumable in a
    /// terminal; what is given up is Ciao's ability to resume it.
    pub(crate) fn managed_forget(&self, session_id: &str, command_id: &str) -> LifecycleOutcome {
        if let Some(existing) = self.deduplicated(command_id) {
            return existing;
        }
        let outcome = {
            let mut store = self.store.lock();
            match store
                .records
                .iter()
                .position(|record| record.session_id == session_id)
            {
                None => store.refuse(command_id, "unknown_session"),
                Some(index) if store.records[index].presence == "live" => {
                    store.refuse(command_id, "already_live")
                }
                Some(index) => {
                    store.records.remove(index);
                    store.accept(command_id, Some(session_id.to_owned()), None)
                }
            }
        };
        self.persist();
        outcome
    }

    /// Vendor conversations Ciao is running right now, mapped to the managed session running
    /// them. The same condition `managed_promote` refuses on, read one step earlier so the
    /// phone can stop offering a takeover that is only going to come back `already_live`.
    pub(crate) fn live_vendor_owners(&self) -> HashMap<String, String> {
        self.store
            .lock()
            .records
            .iter()
            .filter(|record| record.presence == "live")
            .filter_map(|record| {
                Some((record.vendor_session_id.clone()?, record.session_id.clone()))
            })
            .collect()
    }

    /// The snapshot for a session whose worker is not running.
    ///
    /// A stored session has nothing to stream, so the live supervisor has no entry for it and
    /// refused both `snapshot` and `subscribe` with `session_unavailable`. The phone opening one
    /// therefore landed on a bare Retry that could only fail again, and stayed there: the
    /// "Stopped — Resume" affordance is gated on a snapshot saying `presence: stored`, which was
    /// exactly what could not arrive. Built from the same record the list is built from, so an
    /// opened row and its listed row cannot disagree.
    pub(crate) fn stored_snapshot(
        &self,
        session_id: &str,
        live_terminals: &HashSet<String>,
    ) -> Option<AgentSessionSnapshot> {
        let store = self.store.lock();
        let record = store
            .records
            .iter()
            .find(|record| record.session_id == session_id && record.presence == "stored")?;
        let descriptor = stored_descriptor(record, live_terminals);
        Some(AgentSessionSnapshot {
            v: AGENT_PROTOCOL_VERSION,
            session_id: descriptor.session_id,
            // A stored session has no worker and so no epoch of its own, but zero is refused and
            // the field is inert here: it exists to bind command receipts to a snapshot, and a
            // stopped session has none. The revision tracks the record and is never zero.
            snapshot_epoch: descriptor.revision,
            revision: descriptor.revision,
            process_generation: descriptor.process_generation,
            adapter: AgentAdapterMetadata {
                family: descriptor.adapter_family,
                version: descriptor.adapter_version,
                compatibility: "compatible".into(),
            },
            topology: descriptor.topology,
            // A stored managed session is never `ahead`; the exact pin has no tolerant band.
            drift: None,
            presence: descriptor.presence,
            stored_reason: descriptor.stored_reason,
            control_owner: "shared".into(),
            observation: descriptor.observation,
            turn: descriptor.turn,
            // A stored session has no worker to ask. The mode it will resume into is read
            // from the transcript at spawn, so nothing truthful can be said about it here.
            permission_mode: None,
            // Likewise: the model is read from the transcript at spawn, and the catalogue comes
            // from a running SDK. A stopped session has neither to offer.
            model: None,
            effort: None,
            models: None,
            capabilities: descriptor.capabilities,
            pending_interactions: Vec::new(),
            // Ciao keeps no transcript for a stored record — the managed store is metadata-only
            // — so an empty window is the truthful answer rather than a missing one.
            timeline_window: TimelineWindow {
                entries: Vec::new(),
                has_older: false,
                history_boundary: None,
                oldest_sequence: None,
                newest_sequence: None,
                truncated: false,
            },
            terminal_fallback: descriptor.terminal_fallback,
            latest_command_receipts: Vec::new(),
        })
    }

    pub(crate) fn stored_descriptors(
        &self,
        live_terminals: &HashSet<String>,
    ) -> Vec<AgentSessionDescriptor> {
        let store = self.store.lock();
        store
            .records
            .iter()
            .filter(|record| record.presence == "stored")
            .map(|record| stored_descriptor(record, live_terminals))
            .collect()
    }

    pub(crate) fn live_count(&self) -> usize {
        self.store
            .lock()
            .records
            .iter()
            .filter(|record| record.presence == "live")
            .count()
    }

    /// Where one managed conversation is working, for a caller that has only its session ID.
    ///
    /// Spec 008's counterpart to `AgentSessionSupervisor::workspace_path`, and the reason a
    /// diff opened on a managed row resolves at all: registration deliberately does not echo
    /// the path back, so the record is the only place it exists. Answers for stored rows too —
    /// a conversation whose worker has exited still has a worktree worth reading.
    pub(crate) fn workspace_path(&self, session_id: &str) -> Option<String> {
        self.store
            .lock()
            .records
            .iter()
            .find(|record| record.session_id == session_id)
            .map(|record| record.workspace_path.clone())
    }

    /// Bounded, privacy-safe rows for the local CLI: display labels only, no
    /// raw workspace paths or vendor session IDs.
    pub(crate) fn summaries(&self) -> Vec<ManagedSessionSummary> {
        let store = self.store.lock();
        let mut rows: Vec<_> = store
            .records
            .iter()
            .map(|record| ManagedSessionSummary {
                session_id: record.session_id.clone(),
                presence: record.presence.clone(),
                stored_reason: record.stored_reason.clone(),
                workspace_label: record.workspace_label.clone(),
                process_generation: record.process_generation,
                updated_at: record.updated_at,
            })
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.updated_at));
        rows.truncate(MAX_MANAGED_RECORDS);
        rows
    }

    pub(crate) async fn managed_start(
        &self,
        workspace_id: &str,
        command_id: &str,
    ) -> LifecycleOutcome {
        if let Some(existing) = self.deduplicated(command_id) {
            return existing;
        }
        let workspace = {
            let store = self.store.lock();
            store
                .records
                .iter()
                .find(|record| record.workspace_id == workspace_id)
                .map(|record| {
                    (
                        PathBuf::from(&record.workspace_path),
                        record.workspace_label.clone(),
                    )
                })
        };
        // No record means the ID came from discovery, and the hash is one-way: the only way back
        // to a path is to scan again and hash the candidates. Cheap next to launching a worker,
        // and it revalidates on the way — a checkout deleted since the list was drawn simply
        // stops matching and the start is refused rather than launching somewhere stale.
        let workspace = match workspace {
            Some(known) => Some(known),
            None => {
                // Scanned before the lock, same as the listing: no filesystem walk under the
                // mutex, and none of it on a runtime thread either. A start must not be the second
                // way a permission dialog on the Mac can hang the phone.
                //
                // A scan that times out resolves nothing and the refusal below calls that
                // `unknown_workspace`. Indistinguishable from a checkout deleted since the list
                // was drawn, and that is the right answer for both: the start cannot be placed.
                let candidates = self.scan_home().await.unwrap_or_default();
                let store = self.store.lock();
                candidates
                    .paths
                    .into_iter()
                    .find(|path| store.workspace_id(path) == workspace_id)
                    .map(|path| {
                        let label = workspace_label(&path);
                        (path, label)
                    })
            }
        };
        let Some((path, label)) = workspace else {
            return self.refuse(command_id, "unknown_workspace");
        };
        self.start_in_workspace(path, label, command_id).await
    }

    /// Host-CLI entry: an explicit local path may start the first session in a
    /// never-seen workspace. iOS never reaches this path; it selects from the
    /// bounded known-workspace list only.
    #[cfg_attr(not(test), allow(dead_code))] // CLI lifecycle verbs land in step 5
    pub(crate) async fn managed_start_at_path(
        &self,
        path: &Path,
        command_id: &str,
    ) -> LifecycleOutcome {
        if let Some(existing) = self.deduplicated(command_id) {
            return existing;
        }
        if !path.is_absolute() || !path.is_dir() {
            return self.refuse(command_id, "unknown_workspace");
        }
        let label = workspace_label(path);
        self.start_in_workspace(path.to_owned(), label, command_id)
            .await
    }

    /// Every reason promotion can refuse that is knowable before anything is destroyed.
    ///
    /// Taking over ends the owner's terminal, and the caller does that before calling
    /// `managed_promote` — so a refusal decided inside it arrives after the terminal is already
    /// gone, costing a live conversation for a promotion that was never going to happen. The
    /// comments here and in the caller both claimed that was impossible;
    /// `already_live`, `foreign_owner_live` and an unreadable workspace all disproved it.
    ///
    /// `managed_promote` still re-checks all of these. This does not replace those guards, it
    /// only moves the decision to a point where being wrong is free. What cannot be hoisted is
    /// the launch itself: it can only be tried once there is somewhere to launch into.
    pub(crate) async fn promotion_preflight(
        &self,
        target: &PromotionTarget,
    ) -> Option<&'static str> {
        let path = PathBuf::from(&target.workspace_path);
        if !path.is_absolute() || !path.is_dir() {
            return Some("unknown_workspace");
        }
        // Both remaining checks ask who else holds this conversation. A takeover with nothing to
        // resume has no conversation to contend over, so there is no one to collide with.
        if let Some(vendor_session_id) = target.vendor_session_id.as_deref() {
            if self.store.lock().records.iter().any(|record| {
                record.vendor_session_id.as_deref() == Some(vendor_session_id)
                    && record.presence == "live"
            }) {
                return Some("already_live");
            }
            if self
                .launcher
                .foreign_owner_evidence(vendor_session_id, Some(target.process_id))
                .await
            {
                return Some("foreign_owner_live");
            }
        }
        None
    }

    /// Adopts an attached Claude session as a managed one by resuming Claude's own session,
    /// not by retelling it. The caller resolves the target from the attached supervisor,
    /// which is where the TUI-still-running refusal lives.
    ///
    /// Deliberately not the inverse of release: release surrenders ownership and is one-way,
    /// while this claims a session the terminal has already let go of.
    pub(crate) async fn managed_promote(
        &self,
        target: &PromotionTarget,
        command_id: &str,
        // Runs once the new session ID exists and before its worker is spawned. Promotion is the
        // only lifecycle verb that inherits something from a session that already existed, and
        // the inheritance has to be in place before the worker's first frame arrives. Kept as a
        // callback so this module never learns about the transcript registry, whose content is
        // exactly what the managed metadata store is designed not to hold.
        before_spawn: &(dyn Fn(&str) + Sync),
    ) -> LifecycleOutcome {
        if let Some(existing) = self.deduplicated(command_id) {
            return existing;
        }
        let path = PathBuf::from(&target.workspace_path);
        if !path.is_absolute() || !path.is_dir() {
            return self.refuse(command_id, "unknown_workspace");
        }
        // Both ownership checks are about a conversation. A takeover with none to resume starts
        // one, and a conversation that does not exist yet cannot be held by anyone.
        if let Some(vendor_session_id) = target.vendor_session_id.as_deref() {
            // Ciao may already hold this vendor session from an earlier promotion; adopting it
            // twice would be the same silent fork the terminal check exists to prevent.
            if self.store.lock().records.iter().any(|record| {
                record.vendor_session_id.as_deref() == Some(vendor_session_id)
                    && record.presence == "live"
            }) {
                return self.refuse(command_id, "already_live");
            }
            // Same one-sided probe resume uses: evidence of a live foreign owner refuses,
            // absence of evidence never proves exclusivity.
            // The terminal named by the target is the one this takeover ends, so it cannot count
            // as a foreign owner of the conversation it is handing over. Any *other* Claude
            // holding it still refuses: two processes appending to one transcript fork it
            // silently.
            if self
                .launcher
                .foreign_owner_evidence(vendor_session_id, Some(target.process_id))
                .await
            {
                return self.refuse(command_id, "foreign_owner_live");
            }
        }
        let label = workspace_label(&path);
        self.start_in_workspace_resuming(
            path,
            label,
            target.vendor_session_id.clone(),
            command_id,
            Some(before_spawn),
        )
        .await
    }

    async fn start_in_workspace(
        &self,
        path: PathBuf,
        label: String,
        command_id: &str,
    ) -> LifecycleOutcome {
        self.start_in_workspace_resuming(path, label, None, command_id, None)
            .await
    }

    async fn start_in_workspace_resuming(
        &self,
        path: PathBuf,
        label: String,
        resume_vendor_session: Option<String>,
        command_id: &str,
        before_spawn: Option<&(dyn Fn(&str) + Sync)>,
    ) -> LifecycleOutcome {
        let session_id = random_opaque_id();
        if let Some(before_spawn) = before_spawn {
            before_spawn(&session_id);
        }
        // Derived here rather than threaded from each caller, because the rule is the same for
        // every route that reaches this point: a worker resuming somebody else's conversation
        // continues it in the mode that conversation was already in. A takeover of a terminal
        // running `bypassPermissions` used to hand the phone a session that stopped to ask about
        // every tool call — the same conversation, behaving differently for no visible reason.
        // A fresh start has nothing to inherit and keeps the worker's own default.
        let permission_mode = resume_vendor_session
            .as_deref()
            .and_then(crate::claude_transcript::recent_permission_mode);
        // Read from the same tail, for the same reason.
        let model = resume_vendor_session
            .as_deref()
            .and_then(crate::claude_transcript::recent_model);
        let spec = LaunchSpec {
            session_id: session_id.clone(),
            workspace_path: path.clone(),
            resume_vendor_session,
            permission_mode,
            model,
        };
        match self.launcher.launch(&spec, &label).await {
            Ok(worker) => {
                let outcome = {
                    let mut store = self.store.lock();
                    if store.records.len() >= MAX_MANAGED_RECORDS {
                        drop(store);
                        // A bound on the *store*, not on how many agents a person may run. It
                        // took the live workers' reason code until 2026-08-02 and therefore
                        // reported a limit that no longer exists.
                        return self.refuse(command_id, "record_limit");
                    }
                    let workspace_id = store.workspace_id(&path);
                    store.records.push(ManagedRecord {
                        session_id: session_id.clone(),
                        vendor_session_id: worker.vendor_session_id,
                        workspace_path: path.to_string_lossy().into_owned(),
                        workspace_id,
                        workspace_label: label,
                        adapter_family: worker.adapter_family,
                        adapter_version: worker.adapter_version,
                        process_generation: 1,
                        presence: "live".into(),
                        stored_reason: None,
                        externally_owned: false,
                        handback_session: None,
                        revision: 1,
                        updated_at: unix_now(),
                    });
                    store.accept(command_id, Some(session_id), None)
                };
                self.persist();
                outcome
            }
            Err(reason) => self.refuse(command_id, reason),
        }
    }

    /// Hands a session back to the user's own Claude (ADR 004 §5). Ciao stops the worker if it
    /// is live, gives up ownership permanently, and puts the conversation into a detached
    /// terminal session the user can attach whenever they reach a terminal.
    ///
    /// The terminal session is the point. Returning only the vendor session ID — which is all
    /// this used to do — means printing `claude --resume <id>` for someone to type at the Mac,
    /// which is exactly the machine they are not at when they want to hand a session back.
    /// The vendor ID is still returned to the host, and still never crosses to iOS; clients
    /// receive only the durable route.
    ///
    /// Release is deliberately one-way: re-adopting a released session needs the
    /// Spec 006 §20.3 conformance evidence Ciao does not have yet.
    pub(crate) async fn managed_release(
        &self,
        session_id: &str,
        command_id: &str,
    ) -> (LifecycleOutcome, Option<Handback>) {
        if let Some(existing) = self.deduplicated(command_id) {
            let handback = self.store.lock().record(session_id).and_then(|record| {
                record.vendor_session_id.clone().map(|vendor| Handback {
                    vendor_session_id: vendor,
                    route_session: record.handback_session.clone(),
                })
            });
            return (existing, handback);
        }
        let (vendor, workspace, label) = {
            let store = self.store.lock();
            let Some(record) = store.record(session_id) else {
                drop(store);
                return (self.refuse(command_id, "unknown_session"), None);
            };
            (
                record.vendor_session_id.clone(),
                record.workspace_path.clone(),
                record.workspace_label.clone(),
            )
        };
        // A session that never took a turn has nothing in Claude's store to hand
        // back; releasing it would promise a session that does not exist.
        let Some(vendor) = vendor else {
            return (self.refuse(command_id, "no_vendor_session"), None);
        };
        if !Path::new(&workspace).is_dir() {
            return (self.refuse(command_id, "unknown_workspace"), None);
        }
        self.launcher.stop(session_id).await;
        // Ownership is surrendered whether or not the terminal session could be created.
        // Refusing the release because tmux is absent would strand the conversation inside
        // Ciao, which is strictly worse than handing back an ID and saying so.
        let route_session = match crate::workspace::handback_session_name(&label, session_id) {
            Some(name) => self.launcher.handback(&workspace, &name, &vendor).await,
            None => None,
        };
        let outcome = {
            let mut store = self.store.lock();
            if let Some(record) = store.record_mut(session_id) {
                record.presence = "stored".into();
                record.stored_reason = Some("released".into());
                // Ownership is surrendered: the resume affordance is withdrawn
                // by the same flag foreign resumption uses.
                record.externally_owned = true;
                record.handback_session = route_session.clone();
                record.revision = record.revision.saturating_add(1);
                record.updated_at = unix_now();
            }
            store.accept(command_id, Some(session_id.to_owned()), None)
        };
        self.persist();
        (
            outcome,
            Some(Handback {
                vendor_session_id: vendor,
                route_session,
            }),
        )
    }

    pub(crate) async fn managed_stop(
        &self,
        session_id: &str,
        expected_generation: u64,
        command_id: &str,
    ) -> LifecycleOutcome {
        if let Some(existing) = self.deduplicated(command_id) {
            return existing;
        }
        {
            let store = self.store.lock();
            let Some(record) = store.record(session_id) else {
                drop(store);
                return self.refuse(command_id, "unknown_session");
            };
            if record.presence != "live" {
                drop(store);
                return self.refuse(command_id, "already_stored");
            }
            if record.process_generation != expected_generation {
                drop(store);
                return self.refuse(command_id, "stale_generation");
            }
        }
        self.launcher.stop(session_id).await;
        let outcome = {
            let mut store = self.store.lock();
            if let Some(record) = store.record_mut(session_id) {
                record.presence = "stored".into();
                record.stored_reason = Some("stopped".into());
                record.revision = record.revision.saturating_add(1);
                record.updated_at = unix_now();
            }
            store.accept(command_id, Some(session_id.to_owned()), None)
        };
        self.persist();
        outcome
    }

    pub(crate) async fn managed_resume(
        &self,
        session_id: &str,
        command_id: &str,
    ) -> LifecycleOutcome {
        if let Some(existing) = self.deduplicated(command_id) {
            return existing;
        }
        let (vendor_session, workspace_path, workspace_label, generation, handback) = {
            let store = self.store.lock();
            let Some(record) = store.record(session_id) else {
                drop(store);
                return self.refuse(command_id, "unknown_session");
            };
            if record.presence == "live" {
                drop(store);
                return self.refuse(command_id, "already_live");
            }
            // A release is Ciao handing the conversation to a terminal it created and recorded,
            // which is a move it knows how to undo — the same shape as the takeover that already
            // ships, and with a better starting position, since the holder is named rather than
            // resolved from process ancestry. Coming back is offered.
            //
            // `externally_owned` set by anything else is not that: a conversation a foreign
            // Claude resumed was never handed anywhere, nobody told Ciao where it went, and
            // taking it back would be a guess. Still refused.
            let handed_back = record.stored_reason.as_deref() == Some("released");
            if record.externally_owned && !handed_back {
                drop(store);
                return self.refuse(command_id, "externally_owned");
            }
            (
                record.vendor_session_id.clone(),
                PathBuf::from(&record.workspace_path),
                record.workspace_label.clone(),
                record.process_generation,
                handed_back
                    .then(|| record.handback_session.clone())
                    .flatten(),
            )
        };
        // Ends the terminal Ciao opened before the probe below looks for owners, or the Claude
        // inside it would be read as a foreign owner and refuse the take-back. Ordered this way
        // on purpose: evict the holder Ciao is responsible for, then let the probe rule on
        // everyone else, exactly as a takeover does.
        if let Some(session) = handback {
            self.launcher.close_handback(&session).await;
        }
        // Best-effort, one-sided-safe probe: evidence of a live foreign owner
        // refuses the resume; absence of evidence never proves exclusivity. A
        // session that never took a turn has no vendor session to contend over
        // and simply starts fresh in the same workspace.
        if let Some(vendor_session) = vendor_session.as_deref()
            && self
                .launcher
                .foreign_owner_evidence(vendor_session, None)
                .await
        {
            return self.refuse(command_id, "foreign_owner_live");
        }
        // Same rule as a takeover: a resumed conversation comes back in the mode it was left in
        // rather than reverting to `default` because the worker behind it restarted.
        let permission_mode = vendor_session
            .as_deref()
            .and_then(crate::claude_transcript::recent_permission_mode);
        let model = vendor_session
            .as_deref()
            .and_then(crate::claude_transcript::recent_model);
        let spec = LaunchSpec {
            session_id: session_id.to_owned(),
            workspace_path,
            resume_vendor_session: vendor_session,
            permission_mode,
            model,
        };
        match self.launcher.launch(&spec, &workspace_label).await {
            Ok(_) => {
                let next_generation = generation.saturating_add(1);
                let outcome = {
                    let mut store = self.store.lock();
                    if let Some(record) = store.record_mut(session_id) {
                        record.presence = "live".into();
                        record.stored_reason = None;
                        // Ciao runs this conversation again, so the flags describing the
                        // release are stale: leaving them would refuse the *next* resume and
                        // advertise a terminal route to a session that is live here now.
                        record.externally_owned = false;
                        record.handback_session = None;
                        record.process_generation = next_generation;
                        record.revision = record.revision.saturating_add(1);
                        record.updated_at = unix_now();
                    }
                    store.accept(
                        command_id,
                        Some(session_id.to_owned()),
                        Some(next_generation),
                    )
                };
                self.persist();
                outcome
            }
            Err(reason) => self.refuse(command_id, reason),
        }
    }

    /// Records the real vendor session ID once the worker's first turn creates
    /// one. This is what makes the session resumable and what the foreign-owner
    /// probe matches on; it is recorded exactly once per vendor session.
    pub(crate) fn record_vendor_session(&self, session_id: &str, vendor_session_id: &str) {
        {
            let mut store = self.store.lock();
            let Some(record) = store.record_mut(session_id) else {
                return;
            };
            if record.vendor_session_id.as_deref() == Some(vendor_session_id) {
                return;
            }
            record.vendor_session_id = Some(vendor_session_id.to_owned());
            record.updated_at = unix_now();
        }
        self.persist();
    }

    /// Worker exit reported by the supervising launcher. The vendor store is the
    /// transcript of record; the session is retained as stored and resumes only
    /// by explicit command.
    #[cfg_attr(not(test), allow(dead_code))] // the supervising launcher lands in step 6
    pub(crate) fn record_worker_exit(&self, session_id: &str, crashed: bool) {
        {
            let mut store = self.store.lock();
            if let Some(record) = store.record_mut(session_id)
                && record.presence == "live"
            {
                record.presence = "stored".into();
                record.stored_reason =
                    Some(if crashed { "worker_crash" } else { "stopped" }.into());
                record.revision = record.revision.saturating_add(1);
                record.updated_at = unix_now();
            }
        }
        self.persist();
    }

    /// Best-effort foreign-resumption marking: the session becomes externally
    /// owned and Ciao's resume affordance is withdrawn atomically.
    #[cfg_attr(not(test), allow(dead_code))] // foreign-owner detection lands in step 6
    pub(crate) fn mark_externally_owned(&self, session_id: &str) {
        {
            let mut store = self.store.lock();
            if let Some(record) = store.record_mut(session_id)
                && record.presence == "stored"
            {
                record.externally_owned = true;
                record.stored_reason = Some("externally_owned".into());
                record.revision = record.revision.saturating_add(1);
                record.updated_at = unix_now();
            }
        }
        self.persist();
    }

    fn deduplicated(&self, command_id: &str) -> Option<LifecycleOutcome> {
        let store = self.store.lock();
        store
            .lifecycle
            .iter()
            .find(|outcome| outcome.command_id == command_id)
            .map(|outcome| LifecycleOutcome {
                deduplicated: Some(true),
                ..outcome.clone()
            })
    }

    fn refuse(&self, command_id: &str, reason: &str) -> LifecycleOutcome {
        let outcome = self.store.lock().refuse(command_id, reason);
        self.persist();
        outcome
    }

    fn persist(&self) {
        // Persistence failure must not take live state down with it; the store
        // reloads from the last good file and the next mutation retries.
        let _ = self.store.lock().persist();
    }
}

/// The one spelling of the way back into a released Claude conversation. Formatted and
/// validated in one place: the stored descriptor and the release outcome must hand over the
/// same command, and an ID that does not round-trip yields no command rather than a mangled
/// one.
pub(crate) fn claude_resume_command(vendor_session_id: &str) -> Option<String> {
    let command = format!("claude --resume {vendor_session_id}");
    crate::agent_protocol::valid_resume_command(&command)
        .is_ok()
        .then_some(command)
}

fn stored_descriptor(
    record: &ManagedRecord,
    live_terminals: &HashSet<String>,
) -> AgentSessionDescriptor {
    // The recorded route is a claim about a terminal Ciao no longer owns; only a session the
    // provider still reports is a route worth putting in front of the user.
    let handback = record
        .handback_session
        .as_ref()
        .filter(|session| live_terminals.contains(*session));
    // The route that cannot go stale. A released conversation belongs to the user's own Claude
    // now, and `claude --resume <id>` reaches it from any shell on that machine whether or not
    // the terminal Ciao made for it still exists — which is exactly the case that used to
    // delete the row off the phone and leave the ID printed on a Mac nobody was sitting at.
    // ponytail: managed is Claude-only today; match on adapter_family when a second one lands
    let resume_command = match (record.stored_reason.as_deref(), &record.vendor_session_id) {
        (Some("released"), Some(vendor)) => claude_resume_command(vendor),
        _ => None,
    };
    let terminal_continuity = if handback.is_some() || resume_command.is_some() {
        "resumable_session"
    } else {
        "unavailable"
    };
    AgentSessionDescriptor {
        v: AGENT_PROTOCOL_VERSION,
        session_id: record.session_id.clone(),
        adapter_family: record.adapter_family.clone(),
        adapter_version: record.adapter_version.clone(),
        topology: "managed".into(),
        presence: "stored".into(),
        stored_reason: record.stored_reason.clone(),
        drift: None,
        process_generation: record.process_generation,
        observation: Observation {
            coverage: "unavailable".into(),
            reason_code: "worker_not_running".into(),
            last_authoritative_at: None,
        },
        turn: TurnState::Idle,
        capabilities: AgentCapabilities {
            history: "none".into(),
            commands: CommandCapabilities::none(),
            interactions: InteractionCapabilities::none(),
            pending_rehydration: "none".into(),
            terminal_continuity: terminal_continuity.into(),
        },
        takeover: None,
        workspace_display: record.workspace_label.clone(),
        // A managed session has no terminal — except a released one, which now has exactly
        // one. `resumable_session` and not `exact_live`: the terminal holds a Claude that
        // resumed this conversation, but it is a different process from the worker that was
        // stopped, and Ciao surrendered observation of it. Claiming the stronger continuity
        // would re-enable native controls over a session Ciao no longer owns.
        // A released record whose terminal is gone is distinguishable from one that never had a
        // terminal at all: the reason says which, so the phone is never left explaining a
        // headless session that was in fact handed back and then closed.
        terminal_fallback: match (handback, resume_command) {
            (None, None) => TerminalFallback {
                continuity: "unavailable".into(),
                route_id: None,
                availability_reason: Some(if record.handback_session.is_some() {
                    "terminal_closed".into()
                } else {
                    "managed_headless".to_string()
                }),
                handback_session: None,
                resume_command: None,
            },
            (handback, resume_command) => TerminalFallback {
                continuity: "resumable_session".into(),
                route_id: None,
                availability_reason: handback.is_none().then(|| "terminal_closed".to_owned()),
                handback_session: handback.cloned(),
                resume_command,
            },
        },
        // The managed store stays metadata-only: Ciao keeps no copy of the prompt, and this
        // reads Claude's own conversation store instead of reconstructing one. A stored record
        // is otherwise permanently unnamed, since its worker is gone and no hook will ever
        // report for it again. Absent stays truthful for a record whose transcript is missing.
        recent_prompt: record.vendor_session_id.as_deref().and_then(|vendor| {
            crate::claude_transcript::recent_prompt(vendor, MAX_RECENT_PROMPT_BYTES)
        }),
        // This row *is* the managed session; the field points attached rows at one.
        managed_session_id: None,
        revision: record.revision,
        updated_at: record.updated_at,
    }
}

#[cfg_attr(not(test), allow(dead_code))] // used by the step-5 CLI start path
/// Labels for one list, disambiguated only where they need it.
///
/// A bare directory name is what a person calls a project, and on a machine with dozens of
/// checkouts it is also ambiguous: `ciao` the checkout and `ciao` the worktree are the same word.
/// A name that repeats in the list gains its immediate parent — `Developer/ciao` beside
/// `worktrees/ciao` — and every other row stays one word. Qualifying all of them was the obvious
/// alternative and is worse: a prefix shared by forty rows distinguishes nothing while spending
/// the width the distinguishing part needs.
///
/// **One directory of context, never more.** Never an absolute path, and never the home
/// directory's own name — on macOS that is the account name, so a checkout sitting directly in
/// home keeps its bare label rather than announcing who owns it. This is the invariant that
/// replaces the old "a label contains no `/`", and it is the stronger of the two.
///
/// ponytail: two rows that still collide after one parent keep colliding. A second level is the
/// same trade again for a rarer case; add it when a real machine produces one.
fn workspace_labels(entries: &[(String, PathBuf)], home: &Path) -> Vec<WorkspaceDescriptor> {
    let bases: Vec<String> = entries
        .iter()
        .map(|(_, path)| workspace_label(path))
        .collect();
    entries
        .iter()
        .enumerate()
        .map(|(index, (workspace_id, path))| {
            let base = &bases[index];
            let collides = bases
                .iter()
                .enumerate()
                .any(|(other, name)| other != index && name == base);
            let display_label = match parent_label(path, home).filter(|_| collides) {
                // Over the bound the parent is dropped rather than the tail trimmed: trimming
                // eats the project name, which is the only part anyone was reading.
                Some(parent) if parent.len() + 1 + base.len() <= MAX_WORKSPACE_LABEL_BYTES => {
                    format!("{parent}/{base}")
                }
                _ => base.clone(),
            };
            WorkspaceDescriptor {
                workspace_id: workspace_id.clone(),
                display_label,
            }
        })
        .collect()
}

/// The immediate parent directory's own name, when naming it says something about the project
/// rather than about its owner.
fn parent_label(path: &Path, home: &Path) -> Option<String> {
    let parent = path.parent()?;
    if parent == home {
        return None;
    }
    let name = parent.file_name()?.to_string_lossy().into_owned();
    // A path outside home whose parent happens to be named like home's last component — the
    // account name — is refused on the name as well as on the path.
    if home
        .file_name()
        .is_some_and(|home_name| home_name == name.as_str())
    {
        return None;
    }
    Some(name).filter(|name| !name.is_empty())
}

fn workspace_label(path: &Path) -> String {
    let label = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "workspace".into());
    let mut bounded = label;
    while bounded.len() > MAX_WORKSPACE_LABEL_BYTES {
        bounded.pop();
    }
    if bounded.is_empty() {
        "workspace".into()
    } else {
        bounded
    }
}

fn random_opaque_id() -> String {
    format!("{:032x}", random::<u128>())
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(1)
        .max(1)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedRecord {
    session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vendor_session_id: Option<String>,
    workspace_path: String,
    workspace_id: String,
    workspace_label: String,
    adapter_family: String,
    adapter_version: String,
    process_generation: u64,
    presence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stored_reason: Option<String>,
    externally_owned: bool,
    /// The detached terminal session this conversation was handed back to, if one was
    /// created. Kept so a release that is asked about twice answers the same way, and so the
    /// route survives a daemon restart. A session name, not a path or a vendor identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    handback_session: Option<String>,
    revision: u64,
    updated_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedMetadataFile {
    v: u8,
    key: String,
    records: Vec<ManagedRecord>,
    lifecycle: Vec<LifecycleOutcome>,
}

#[derive(Debug)]
struct ManagedMetadataStore {
    path: PathBuf,
    key: [u8; 32],
    records: Vec<ManagedRecord>,
    lifecycle: Vec<LifecycleOutcome>,
}

impl ManagedMetadataStore {
    fn load(path: &Path) -> Result<Self> {
        let file = match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    bail!("Managed metadata must be a regular file");
                }
                validate_private_file(path)?;
                if metadata.len() == 0 || metadata.len() > MAX_MANAGED_METADATA_FILE_BYTES {
                    bail!("Managed metadata file violates its byte bound");
                }
                let bytes = fs::read(path).context("read managed metadata")?;
                serde_json::from_slice::<ManagedMetadataFile>(&bytes)
                    .context("managed metadata is malformed")?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => ManagedMetadataFile {
                v: MANAGED_METADATA_VERSION,
                key: hex(&random::<[u8; 32]>()),
                records: Vec::new(),
                lifecycle: Vec::new(),
            },
            Err(error) => return Err(error).context("inspect managed metadata"),
        };
        if file.v != MANAGED_METADATA_VERSION
            || file.records.len() > MAX_MANAGED_RECORDS
            || file.lifecycle.len() > MAX_MANAGED_RECORDS * MAX_LIFECYCLE_RECEIPTS
        {
            bail!("Managed metadata violates its bounds");
        }
        for record in &file.records {
            if valid_opaque_id(&record.session_id).is_err()
                || valid_opaque_id(&record.workspace_id).is_err()
                || valid_token(&record.adapter_family).is_err()
                || valid_token(&record.adapter_version).is_err()
                || record
                    .vendor_session_id
                    .as_ref()
                    .is_some_and(|value| value.is_empty() || value.len() > 128)
                || record.workspace_path.is_empty()
                || record.workspace_label.is_empty()
                || record.workspace_label.len() > MAX_WORKSPACE_LABEL_BYTES
                || record.process_generation == 0
                || record.revision == 0
                || !matches!(record.presence.as_str(), "live" | "stored")
                || record
                    .stored_reason
                    .as_deref()
                    .is_some_and(|reason| valid_token(reason).is_err())
            {
                bail!("Managed metadata record is invalid");
            }
        }
        let key =
            decode_hex_32(&file.key).ok_or_else(|| anyhow!("Managed metadata key is invalid"))?;
        let lifecycle = file
            .lifecycle
            .into_iter()
            .filter(|outcome| outcome.validate().is_ok())
            .take(MAX_MANAGED_RECORDS * MAX_LIFECYCLE_RECEIPTS)
            .collect::<Vec<_>>();
        let store = Self {
            path: path.to_owned(),
            key,
            records: file.records,
            lifecycle,
        };
        store.persist()?;
        Ok(store)
    }

    fn persist(&self) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).context("create managed metadata directory")?;
        }
        let file = ManagedMetadataFile {
            v: MANAGED_METADATA_VERSION,
            key: hex(&self.key),
            records: self.records.clone(),
            lifecycle: self.lifecycle.clone(),
        };
        let bytes = serde_json::to_vec(&file).context("encode managed metadata")?;
        atomic_write_private(&self.path, &bytes)
    }

    fn workspace_id(&self, path: &Path) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"ciao-managed-workspace-v1\0");
        hasher.update(self.key);
        let value = path.to_string_lossy();
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value.as_bytes());
        hex(&hasher.finalize())[..32].to_owned()
    }

    fn record(&self, session_id: &str) -> Option<&ManagedRecord> {
        self.records
            .iter()
            .find(|record| record.session_id == session_id)
    }

    fn record_mut(&mut self, session_id: &str) -> Option<&mut ManagedRecord> {
        self.records
            .iter_mut()
            .find(|record| record.session_id == session_id)
    }

    fn accept(
        &mut self,
        command_id: &str,
        session_id: Option<String>,
        process_generation: Option<u64>,
    ) -> LifecycleOutcome {
        self.push_outcome(LifecycleOutcome {
            resume_command: None,
            v: AGENT_PROTOCOL_VERSION,
            command_id: command_id.to_owned(),
            state: "accepted".into(),
            session_id,
            process_generation,
            reason_code: None,
            deduplicated: None,
        })
    }

    fn refuse(&mut self, command_id: &str, reason: &str) -> LifecycleOutcome {
        self.push_outcome(LifecycleOutcome {
            v: AGENT_PROTOCOL_VERSION,
            command_id: command_id.to_owned(),
            state: "refused".into(),
            session_id: None,
            process_generation: None,
            reason_code: Some(reason.to_owned()),
            deduplicated: None,
            resume_command: None,
        })
    }

    fn push_outcome(&mut self, outcome: LifecycleOutcome) -> LifecycleOutcome {
        self.lifecycle.push(outcome.clone());
        let bound = MAX_MANAGED_RECORDS * MAX_LIFECYCLE_RECEIPTS;
        if self.lifecycle.len() > bound {
            let excess = self.lifecycle.len() - bound;
            self.lifecycle.drain(0..excess);
        }
        outcome
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
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        output[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(output)
}

#[cfg(test)]
pub(crate) mod fake {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use super::{LaunchSpec, LaunchedWorker};

    /// Test launcher: spawns nothing, mints vendor session IDs, and lets tests
    /// script refusals and foreign-owner evidence.
    #[derive(Debug, Default)]
    pub(crate) struct FakeLauncher {
        pub(crate) refuse_with: Mutex<Option<&'static str>>,
        pub(crate) foreign_owned: Mutex<HashSet<String>>,
        pub(crate) stopped: Mutex<Vec<String>>,
        /// Set when the host has no tmux, or the handed-back conversation failed to start.
        /// Release must still surrender ownership in that case rather than strand it.
        pub(crate) handback_fails: Mutex<bool>,
        /// Handback terminals a take-back ended, in order.
        pub(crate) closed_handbacks: Mutex<Vec<String>>,
    }

    impl FakeLauncher {
        pub(crate) fn launch(&self, spec: &LaunchSpec) -> Result<LaunchedWorker, &'static str> {
            if let Some(reason) = *self.refuse_with.lock().unwrap() {
                return Err(reason);
            }
            Ok(LaunchedWorker {
                vendor_session_id: spec.resume_vendor_session.clone(),
                adapter_family: "claude".into(),
                adapter_version: crate::claude_managed_adapter::PINNED_MANAGED_CLI_VERSION.into(),
            })
        }

        pub(crate) fn stop(&self, session_id: &str) {
            self.stopped.lock().unwrap().push(session_id.to_owned());
        }

        pub(crate) fn foreign_owner_evidence(
            &self,
            vendor_session_id: &str,
            _ignoring: Option<u32>,
        ) -> bool {
            self.foreign_owned
                .lock()
                .unwrap()
                .contains(vendor_session_id)
        }

        pub(crate) fn handback(&self, session_name: &str) -> Option<String> {
            (!*self.handback_fails.lock().unwrap()).then(|| session_name.to_owned())
        }

        pub(crate) fn close_handback(&self, session_name: &str) -> bool {
            self.closed_handbacks
                .lock()
                .unwrap()
                .push(session_name.to_owned());
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    /// Home is the store's own directory, which is the tempdir every test already builds its
    /// workspaces under — so discovery has a real root to scan and finds nothing in it unless a
    /// test deliberately puts a checkout there.
    fn directory(path: &Path) -> ManagedSessionDirectory {
        ManagedSessionDirectory::load(
            path,
            path.parent().unwrap_or_else(|| Path::new(".")),
            ManagedLauncher::Fake(fake::FakeLauncher::default()),
        )
        .unwrap()
    }

    /// Terminal liveness is the provider's answer, and these tests have no tmux. Every test
    /// that is not about a *closed* terminal takes the recorded routes at face value; the one
    /// that is passes an empty set instead.
    fn all_recorded_handbacks(directory: &ManagedSessionDirectory) -> HashSet<String> {
        directory.handback_session_names().into_iter().collect()
    }

    fn fake(directory: &ManagedSessionDirectory) -> &fake::FakeLauncher {
        match directory.launcher.as_ref() {
            ManagedLauncher::Fake(fake) => fake,
            _ => unreachable!("tests always construct a fake launcher"),
        }
    }

    /// A name that repeats gains one parent; everything else stays one word. On a machine with
    /// dozens of checkouts a column of bare basenames is unusable exactly where it matters —
    /// `ciao` the checkout and `ciao` the worktree read identically — and qualifying every row
    /// instead would spend the width on a prefix that is the same for all of them.
    #[tokio::test]
    async fn only_a_repeated_project_name_is_qualified_by_its_parent() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        fs::create_dir_all(home.path().join("Developer/ciao/.git")).unwrap();
        fs::create_dir_all(home.path().join("worktrees/ciao/.git")).unwrap();
        fs::create_dir_all(home.path().join("Developer/umbra/.git")).unwrap();
        let directory = directory(&store);

        let labels: Vec<String> = directory
            .workspaces()
            .await
            .workspaces
            .into_iter()
            .map(|entry| entry.display_label)
            .collect();

        assert!(
            labels.contains(&"Developer/ciao".to_string())
                && labels.contains(&"worktrees/ciao".to_string()),
            "two projects of the same name must be told apart: {labels:?}"
        );
        assert!(
            labels.contains(&"umbra".to_string()),
            "a name nothing else shares stays one word: {labels:?}"
        );
        for label in &labels {
            assert!(!label.starts_with('/'), "never absolute: {label}");
            assert!(
                label.matches('/').count() <= 1,
                "at most one directory of context: {label}"
            );
        }
    }

    /// The home directory's own name is the account name on macOS, so a checkout sitting directly
    /// in home may not borrow it even when its name repeats. It keeps the bare label and stays
    /// ambiguous, which is the correct trade: the list is a convenience, the account name is not
    /// ours to broadcast.
    #[tokio::test]
    async fn a_checkout_in_home_never_takes_the_account_name_as_its_parent() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        fs::create_dir_all(home.path().join("ciao/.git")).unwrap();
        fs::create_dir_all(home.path().join("Developer/ciao/.git")).unwrap();
        let directory = directory(&store);

        let labels: Vec<String> = directory
            .workspaces()
            .await
            .workspaces
            .into_iter()
            .map(|entry| entry.display_label)
            .collect();

        let home_name = home
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert!(
            !labels.iter().any(|label| label.contains(&home_name)),
            "the home directory's own name must never ship: {labels:?} contains {home_name}"
        );
        assert!(
            labels.contains(&"ciao".to_string()),
            "the one in home keeps its bare name: {labels:?}"
        );
    }

    /// The whole point of discovery: a checkout Ciao has never run in is listed, and the opaque
    /// ID it was listed under is enough to start there. Before this the phone could only pick
    /// from records, so the first session in any directory needed the host CLI.
    #[tokio::test]
    async fn a_discovered_checkout_is_listed_and_startable_by_its_opaque_id() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        fs::create_dir_all(home.path().join("fresh-project/.git")).unwrap();
        let directory = directory(&store);

        let workspaces = directory.workspaces().await;
        workspaces.validate().unwrap();
        assert!(!workspaces.scan_incomplete, "nothing here blocked the walk");
        let listed = workspaces
            .workspaces
            .iter()
            .find(|entry| entry.display_label == "fresh-project")
            .expect("a git checkout under home is offered as a workspace");
        assert!(!listed.workspace_id.contains("fresh-project"));

        let started = directory
            .managed_start(&listed.workspace_id, "cmd-discovered")
            .await;
        assert_eq!(started.state, "accepted");

        // Now a record too. Both sources hash the same path, so it must not be listed twice.
        let after = directory.workspaces().await;
        assert_eq!(
            after
                .workspaces
                .iter()
                .filter(|entry| entry.workspace_id == listed.workspace_id)
                .count(),
            1
        );
    }

    /// Once someone has clicked Deny on a macOS folder prompt, that directory refuses to be read
    /// for good — silently, so the phone gets a list with their work missing and no reason why.
    /// The list still arrives, because partial results are results, and it carries the fact that
    /// it may be short so the phone can say so.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_refused_directory_still_answers_and_says_the_list_may_be_short() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        fs::create_dir_all(home.path().join("visible/.git")).unwrap();
        let refused = home.path().join("refused");
        fs::create_dir_all(&refused).unwrap();
        fs::set_permissions(&refused, fs::Permissions::from_mode(0o000)).unwrap();
        let directory = directory(&store);

        let workspaces = directory.workspaces().await;

        // Restored before any assertion can unwind past it, or the tempdir cannot be removed.
        fs::set_permissions(&refused, fs::Permissions::from_mode(0o755)).unwrap();
        workspaces.validate().unwrap();
        assert!(workspaces.scan_incomplete);
        assert!(
            workspaces
                .workspaces
                .iter()
                .any(|entry| entry.display_label == "visible"),
            "what could be read is still offered: {workspaces:?}"
        );
    }

    /// A path that hashes to nothing on disk is still refused, so discovery widened what can be
    /// started without widening it to anything a scan does not currently see.
    #[tokio::test]
    async fn an_unknown_workspace_id_is_still_refused() {
        let home = tempdir().unwrap();
        let directory = directory(&home.path().join("agent-managed.json"));

        let refused = directory
            .managed_start(&"a".repeat(32), "cmd-nowhere")
            .await;

        assert_eq!(refused.state, "refused");
        assert_eq!(refused.reason_code.as_deref(), Some("unknown_workspace"));
    }

    #[tokio::test]
    async fn start_stop_resume_round_trip_with_receipted_outcomes() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&store);

        let started = directory
            .managed_start_at_path(&workspace, "cmd-start")
            .await;
        started.validate().unwrap();
        assert_eq!(started.state, "accepted");
        let session_id = started.session_id.clone().unwrap();
        assert_eq!(directory.live_count(), 1);
        assert!(
            directory
                .stored_descriptors(&all_recorded_handbacks(&directory))
                .is_empty()
        );

        // The workspace becomes a known workspace with an opaque ID and a
        // bounded label; the raw path never appears.
        let workspaces = directory.workspaces().await;
        workspaces.validate().unwrap();
        assert_eq!(workspaces.workspaces.len(), 1);
        assert_eq!(workspaces.workspaces[0].display_label, "workspace");
        assert!(!workspaces.workspaces[0].workspace_id.contains("workspace"));

        // A duplicate command ID replays the persisted outcome.
        let duplicate = directory
            .managed_start_at_path(&workspace, "cmd-start")
            .await;
        assert_eq!(duplicate.deduplicated, Some(true));
        assert_eq!(duplicate.session_id.as_deref(), Some(session_id.as_str()));
        assert_eq!(directory.live_count(), 1);

        let stopped = directory.managed_stop(&session_id, 1, "cmd-stop").await;
        assert_eq!(stopped.state, "accepted");
        assert_eq!(
            fake(&directory).stopped.lock().unwrap().as_slice(),
            std::slice::from_ref(&session_id)
        );
        let stored = directory.stored_descriptors(&all_recorded_handbacks(&directory));
        assert_eq!(stored.len(), 1);
        stored[0].validate().unwrap();
        assert_eq!(stored[0].stored_reason.as_deref(), Some("stopped"));

        let resumed = directory.managed_resume(&session_id, "cmd-resume").await;
        assert_eq!(resumed.state, "accepted");
        assert_eq!(resumed.process_generation, Some(2));
        assert_eq!(directory.live_count(), 1);
    }

    #[tokio::test]
    async fn every_refusal_reason_is_categorical_and_receipted() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&store);

        let unknown_workspace = directory.managed_start("nope", "cmd-1").await;
        assert_eq!(
            unknown_workspace.reason_code.as_deref(),
            Some("unknown_workspace")
        );
        let unknown_session = directory.managed_stop("nope", 1, "cmd-2").await;
        assert_eq!(
            unknown_session.reason_code.as_deref(),
            Some("unknown_session")
        );
        let unknown_resume = directory.managed_resume("nope", "cmd-3").await;
        assert_eq!(
            unknown_resume.reason_code.as_deref(),
            Some("unknown_session")
        );

        let started = directory.managed_start_at_path(&workspace, "cmd-4").await;
        let session_id = started.session_id.clone().unwrap();
        let already_live = directory.managed_resume(&session_id, "cmd-5").await;
        assert_eq!(already_live.reason_code.as_deref(), Some("already_live"));
        let stale = directory.managed_stop(&session_id, 9, "cmd-6").await;
        assert_eq!(stale.reason_code.as_deref(), Some("stale_generation"));
        directory.managed_stop(&session_id, 1, "cmd-7").await;
        let already_stored = directory.managed_stop(&session_id, 1, "cmd-8").await;
        assert_eq!(
            already_stored.reason_code.as_deref(),
            Some("already_stored")
        );

        // A session that never took a turn has no vendor session to contend
        // over, so the probe cannot refuse it: it simply starts fresh.
        let never_prompted = directory.managed_resume(&session_id, "cmd-8b").await;
        assert_eq!(never_prompted.state, "accepted");
        directory.managed_stop(&session_id, 2, "cmd-8c").await;

        // Once the worker reports a real vendor session, foreign-owner evidence
        // refuses resume; marking externally owned withdraws it with its own
        // categorical reason.
        let vendor = format!("vendor-{session_id}");
        directory.record_vendor_session(&session_id, &vendor);
        fake(&directory)
            .foreign_owned
            .lock()
            .unwrap()
            .insert(vendor);
        let foreign = directory.managed_resume(&session_id, "cmd-9").await;
        assert_eq!(foreign.reason_code.as_deref(), Some("foreign_owner_live"));
        directory.mark_externally_owned(&session_id);
        let external = directory.managed_resume(&session_id, "cmd-10").await;
        assert_eq!(external.reason_code.as_deref(), Some("externally_owned"));
        let descriptor = &directory.stored_descriptors(&all_recorded_handbacks(&directory))[0];
        assert_eq!(
            descriptor.stored_reason.as_deref(),
            Some("externally_owned")
        );

        // Launcher refusals surface categorically.
        *fake(&directory).refuse_with.lock().unwrap() = Some("unsupported_version");
        let unsupported = directory.managed_start_at_path(&workspace, "cmd-11").await;
        assert_eq!(
            unsupported.reason_code.as_deref(),
            Some("unsupported_version")
        );
        for outcome in [
            &unknown_workspace,
            &unknown_session,
            &already_live,
            &stale,
            &unsupported,
        ] {
            outcome.validate().unwrap();
        }
    }

    /// The caller ends the owner's terminal before `managed_promote` runs, so any refusal left
    /// inside it is paid for with a live conversation. The preflight has to catch the same
    /// answers one step earlier, while being wrong is still free.
    /// A stopped session is reachable from the list but was not openable: the live supervisor
    /// has no entry, so both `snapshot` and `subscribe` refused, and the phone sat on a Retry
    /// that could only fail again. The Resume affordance is gated on a snapshot that says the
    /// session is stored, so the one state that could offer it was the one that never arrived.
    #[tokio::test]
    async fn a_stopped_session_still_has_a_snapshot_to_open() {
        let home = tempdir().unwrap();
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&home.path().join("agent-managed.json"));
        let started = directory
            .managed_start_at_path(&workspace, "cmd-stored-snapshot")
            .await;
        let session_id = started.session_id.clone().unwrap();
        assert!(
            directory
                .stored_snapshot(&session_id, &HashSet::new())
                .is_none(),
            "a live session is served by the supervisor, never from the record"
        );

        directory.managed_stop(&session_id, 1, "cmd-stop").await;

        let snapshot = directory
            .stored_snapshot(&session_id, &HashSet::new())
            .expect("a stopped session must still be openable");
        assert_eq!(snapshot.session_id, session_id);
        // The whole point: this is the field the phone gates its Resume button on.
        assert_eq!(snapshot.presence, "stored");
        assert_eq!(snapshot.topology, "managed");
        // Metadata-only store: an empty timeline is truthful, a missing one is not.
        assert!(snapshot.timeline_window.entries.is_empty());
        assert!(snapshot.pending_interactions.is_empty());
        assert_eq!(
            snapshot.validate().map_err(|e| format!("{e:?}")),
            Ok(()),
            "the phone rejects an invalid snapshot outright"
        );
    }

    #[tokio::test]
    async fn the_preflight_refuses_everything_promotion_would_have_refused_too_late() {
        let home = tempdir().unwrap();
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&home.path().join("agent-managed.json"));
        let target = PromotionTarget {
            vendor_session_id: Some("vendor-attached-0001".into()),
            workspace_path: workspace.to_string_lossy().into_owned(),
            process_id: 0,
        };
        assert_eq!(directory.promotion_preflight(&target).await, None);

        let missing = PromotionTarget {
            workspace_path: home.path().join("gone").to_string_lossy().into_owned(),
            ..target.clone()
        };
        assert_eq!(
            directory.promotion_preflight(&missing).await,
            Some("unknown_workspace")
        );

        // Adopting a conversation Ciao already runs is the silent fork the guards exist for,
        // and it must be refused without the terminal being closed for it.
        let promoted = directory
            .managed_promote(&target, "cmd-preflight", &|_| {})
            .await;
        assert_eq!(promoted.state, "accepted");
        assert_eq!(
            directory.promotion_preflight(&target).await,
            Some("already_live")
        );

        // However many are already running, another is allowed: how many agents a person runs at
        // once is theirs to decide (2026-08-02). No other harness imposes one.
        for index in 1..6 {
            let outcome = directory
                .managed_start_at_path(&workspace, &format!("cmd-fill-{index}"))
                .await;
            assert_eq!(outcome.state, "accepted");
        }
        let fresh = PromotionTarget {
            vendor_session_id: Some("vendor-attached-0002".into()),
            ..target.clone()
        };
        assert_eq!(directory.promotion_preflight(&fresh).await, None);
    }

    #[tokio::test]
    async fn promotion_resumes_the_real_conversation_and_refuses_a_contended_one() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&store);
        let target = PromotionTarget {
            vendor_session_id: Some("vendor-attached-0001".into()),
            workspace_path: workspace.to_string_lossy().into_owned(),
            process_id: 0,
        };

        let promoted = directory
            .managed_promote(&target, "cmd-promote", &|_| {})
            .await;
        assert_eq!(promoted.state, "accepted");
        let session_id = promoted.session_id.clone().unwrap();
        // The worker resumes Claude's own session rather than being told about it, so the
        // record owns the vendor ID from the first moment instead of after a first turn.
        assert_eq!(
            directory
                .store
                .lock()
                .record(&session_id)
                .and_then(|record| record.vendor_session_id.clone())
                .as_deref(),
            Some("vendor-attached-0001")
        );

        // Same command ID is the same promotion, not a second worker on one conversation.
        let replayed = directory
            .managed_promote(&target, "cmd-promote", &|_| {})
            .await;
        assert_eq!(replayed.session_id, promoted.session_id);
        assert_eq!(replayed.deduplicated, Some(true));

        // Ciao already holds it: adopting twice is the silent fork the guards exist for.
        let again = directory
            .managed_promote(&target, "cmd-promote-2", &|_| {})
            .await;
        assert_eq!(again.state, "refused");
        assert_eq!(again.reason_code.as_deref(), Some("already_live"));

        // Evidence of a foreign owner refuses even when Ciao holds nothing.
        let contended = PromotionTarget {
            vendor_session_id: Some("vendor-attached-0002".into()),
            workspace_path: workspace.to_string_lossy().into_owned(),
            process_id: 0,
        };
        if let ManagedLauncher::Fake(fake) = directory.launcher.as_ref() {
            fake.foreign_owned
                .lock()
                .unwrap()
                .insert("vendor-attached-0002".into());
        }
        let refused = directory
            .managed_promote(&contended, "cmd-promote-3", &|_| {})
            .await;
        assert_eq!(refused.state, "refused");
        assert_eq!(refused.reason_code.as_deref(), Some("foreign_owner_live"));

        // A directory that no longer exists is refused before a worker is considered.
        let gone = PromotionTarget {
            vendor_session_id: Some("vendor-attached-0003".into()),
            workspace_path: home.path().join("absent").to_string_lossy().into_owned(),
            process_id: 0,
        };
        let missing = directory
            .managed_promote(&gone, "cmd-promote-4", &|_| {})
            .await;
        assert_eq!(missing.reason_code.as_deref(), Some("unknown_workspace"));
    }

    /// Ownership is surrendered whether or not a terminal could be created, and a workspace
    /// that no longer exists is refused before anything is stopped. The first is the more
    /// important of the two: refusing the release because tmux is missing would strand the
    /// conversation inside Ciao, which is worse than handing back an ID and saying so.
    #[tokio::test]
    async fn release_surrenders_ownership_even_with_nowhere_to_hand_it_back_to() {
        let store = tempfile::tempdir().unwrap().keep().join("managed.json");
        let workspace = tempfile::tempdir().unwrap();
        let directory = directory(&store);
        let started = directory
            .managed_start_at_path(workspace.path(), "cmd-start")
            .await;
        let session_id = started.session_id.unwrap();
        directory.record_vendor_session(&session_id, "vendor-nowhere-0001");
        *fake(&directory).handback_fails.lock().unwrap() = true;

        let (released, handback) = directory.managed_release(&session_id, "cmd-release").await;
        assert_eq!(
            released.state, "accepted",
            "ownership is surrendered anyway"
        );
        let handback = handback.expect("the vendor ID is still the way back");
        assert_eq!(handback.vendor_session_id, "vendor-nowhere-0001");
        assert!(handback.route_session.is_none());
        let listed = directory
            .stored_descriptors(&all_recorded_handbacks(&directory))
            .into_iter()
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("a released session stays listed");
        assert_eq!(listed.stored_reason.as_deref(), Some("released"));
        // No terminal, so no terminal promised — but the conversation is still the user's, and
        // the command that reopens it is the route that does not depend on tmux having worked.
        // Withholding it is what used to make this row `isDeadRecord` and delete it off the
        // phone, leaving the ID printed only on the machine the user had walked away from.
        assert!(listed.terminal_fallback.handback_session.is_none());
        assert_eq!(listed.terminal_fallback.continuity, "resumable_session");
        assert_eq!(
            listed.terminal_fallback.resume_command.as_deref(),
            Some("claude --resume vendor-nowhere-0001")
        );
        assert_eq!(
            listed.terminal_fallback.availability_reason.as_deref(),
            Some("terminal_closed")
        );
        listed.validate().expect("a resume-only route is canonical");
    }

    /// A stopped session is not a released one: nothing was handed anywhere, Ciao still owns
    /// the conversation, and offering a command that starts a second writer on it would undo
    /// the single-owner rule the whole managed path is built on.
    #[tokio::test]
    async fn a_stopped_session_is_not_handed_a_resume_command() {
        let store = tempfile::tempdir().unwrap().keep().join("managed.json");
        let workspace = tempfile::tempdir().unwrap();
        let directory = directory(&store);
        let started = directory
            .managed_start_at_path(workspace.path(), "cmd-start")
            .await;
        let session_id = started.session_id.unwrap();
        directory.record_vendor_session(&session_id, "vendor-stopped-0001");
        directory.managed_stop(&session_id, 1, "cmd-stop").await;

        let listed = directory
            .stored_descriptors(&all_recorded_handbacks(&directory))
            .into_iter()
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("a stopped session stays listed");
        assert_eq!(listed.terminal_fallback.continuity, "unavailable");
        assert!(listed.terminal_fallback.resume_command.is_none());
        listed.validate().expect("unchanged and canonical");
    }

    /// A release is reversible; a conversation taken by a foreign Claude is not.
    ///
    /// Both set `externally_owned`, and treating them alike left a handed-back session with no
    /// way home — you could copy its command to a terminal but never bring it back into Ciao,
    /// while the Codex equivalent picks straight back up. The difference is knowledge: Ciao
    /// created the terminal a release went to and recorded its name, so it can end that holder
    /// precisely. Nobody tells Ciao where a foreign resume went, so that one stays refused.
    ///
    /// Order is the safety property. Ciao's own terminal is closed first, then the foreign-owner
    /// probe rules on everyone else — the takeover contract exactly. Skip the close and the
    /// probe sees the Claude that Ciao itself put there and refuses the take-back; skip the
    /// probe and two processes append to one transcript.
    #[tokio::test]
    async fn a_handed_back_session_comes_home_but_a_stolen_one_does_not() {
        let store = tempfile::tempdir().unwrap().keep().join("managed.json");
        let workspace = tempfile::tempdir().unwrap();
        let directory = directory(&store);
        let started = directory
            .managed_start_at_path(workspace.path(), "cmd-start")
            .await;
        let session_id = started.session_id.unwrap();
        directory.record_vendor_session(&session_id, "vendor-homecoming-0001");
        let (released, handback) = directory.managed_release(&session_id, "cmd-release").await;
        assert_eq!(released.state, "accepted");
        let handback_route = handback
            .and_then(|handback| handback.route_session)
            .expect("release created a terminal to take back from");

        let resumed = directory.managed_resume(&session_id, "cmd-resume").await;
        assert_eq!(
            resumed.state, "accepted",
            "a conversation Ciao handed to a terminal it made can be taken back"
        );
        assert_eq!(
            fake(&directory).closed_handbacks.lock().unwrap().as_slice(),
            std::slice::from_ref(&handback_route),
            "the terminal Ciao opened is ended before the owner probe runs"
        );
        {
            let store = directory.store.lock();
            let record = store.record(&session_id).expect("record");
            // Every trace of the release is cleared, or the next resume refuses itself and the
            // phone is offered a terminal route to a session that is live here.
            assert!(!record.externally_owned);
            assert_eq!(record.presence, "live");
            assert!(record.handback_session.is_none());
            assert_eq!(record.stored_reason, None);
        }

        // A foreign Claude that resumed a stored session is the other half of the rule. Nobody
        // told Ciao where that conversation went, so there is no holder it may end and no
        // take-back it can offer.
        let other = directory
            .managed_start_at_path(workspace.path(), "cmd-start-2")
            .await;
        let other_id = other.session_id.unwrap();
        directory.record_vendor_session(&other_id, "vendor-stolen-0001");
        directory.managed_stop(&other_id, 1, "cmd-stop-2").await;
        directory.mark_externally_owned(&other_id);
        let refused = directory.managed_resume(&other_id, "cmd-resume-2").await;
        assert_eq!(refused.reason_code.as_deref(), Some("externally_owned"));
    }

    /// A workspace that has been deleted cannot host the handback, and there is nothing
    /// truthful to return, so the release is refused before the worker is stopped.
    #[tokio::test]
    async fn release_refuses_a_workspace_that_is_gone() {
        let store = tempfile::tempdir().unwrap().keep().join("managed.json");
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().to_owned();
        let directory = directory(&store);
        let started = directory.managed_start_at_path(&path, "cmd-start").await;
        let session_id = started.session_id.unwrap();
        directory.record_vendor_session(&session_id, "vendor-gone-0001");
        drop(workspace);

        let (refused, handback) = directory.managed_release(&session_id, "cmd-release").await;
        assert_eq!(refused.state, "refused");
        assert_eq!(refused.reason_code.as_deref(), Some("unknown_workspace"));
        assert!(handback.is_none());
        assert!(
            fake(&directory).stopped.lock().unwrap().is_empty(),
            "nothing is stopped for a release that was going to fail"
        );
    }

    #[tokio::test]
    async fn release_hands_the_session_back_and_is_one_way() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&store);
        let started = directory
            .managed_start_at_path(&workspace, "cmd-start")
            .await;
        let session_id = started.session_id.unwrap();

        // A session that never took a turn has nothing to hand back.
        let (premature, vendor) = directory.managed_release(&session_id, "cmd-early").await;
        assert_eq!(premature.reason_code.as_deref(), Some("no_vendor_session"));
        assert!(vendor.is_none());

        directory.record_vendor_session(&session_id, "vendor-handback-0001");
        let (released, handback) = directory.managed_release(&session_id, "cmd-release").await;
        assert_eq!(released.state, "accepted");
        let handback = handback.expect("a released session reports where it went");
        // The caller gets the ID so the local CLI can print the resume command as a fallback.
        assert_eq!(handback.vendor_session_id, "vendor-handback-0001");
        // And a terminal session to attach, which is the whole point of handing one back.
        let route = handback
            .route_session
            .expect("release must leave a terminal to attach");
        assert!(
            crate::host_protocol::valid_session_name(&route),
            "the handback route is a provider session name: {route}"
        );
        // The descriptor carries it too, so a client that reconnects still finds the way back.
        let listed = directory
            .stored_descriptors(&all_recorded_handbacks(&directory))
            .into_iter()
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("a released session stays listed");
        assert_eq!(
            listed.terminal_fallback.handback_session.as_deref(),
            Some(route.as_str())
        );
        assert_eq!(listed.terminal_fallback.continuity, "resumable_session");
        assert_eq!(listed.capabilities.terminal_continuity, "resumable_session");
        listed
            .validate()
            .expect("the descriptor returned to a phone must pass the canonical validator");
        // The worker is stopped as part of releasing ownership.
        assert!(
            fake(&directory)
                .stopped
                .lock()
                .unwrap()
                .contains(&session_id)
        );

        // The user owns that terminal once it is handed back, so they may close it. The record
        // and its Released state survive; the tmux route does not, because a row offering to
        // reopen a terminal that is gone is a button that does nothing when tapped.
        //
        // What does survive is the command. The conversation belongs to the user's own Claude
        // and `claude --resume <id>` still reaches it from any shell, so this state is
        // `resumable_session` with the command as its whole route — not the dead end that used
        // to delete the row off the phone and leave the ID only on the Mac.
        let closed = directory.stored_descriptors(&HashSet::new());
        let closed = closed
            .iter()
            .find(|descriptor| descriptor.session_id == session_id)
            .expect("a released session stays listed after its terminal closes");
        assert!(closed.terminal_fallback.handback_session.is_none());
        assert_eq!(closed.terminal_fallback.continuity, "resumable_session");
        assert_eq!(closed.capabilities.terminal_continuity, "resumable_session");
        assert_eq!(
            closed.terminal_fallback.resume_command.as_deref(),
            Some("claude --resume vendor-handback-0001")
        );
        // Distinguishable from a managed session that never had a terminal at all.
        assert_eq!(
            closed.terminal_fallback.availability_reason.as_deref(),
            Some("terminal_closed")
        );
        assert_eq!(closed.stored_reason.as_deref(), Some("released"));
        closed
            .validate()
            .expect("withdrawing the route must still produce a valid descriptor");

        let stored = directory.stored_descriptors(&all_recorded_handbacks(&directory));
        assert_eq!(stored[0].stored_reason.as_deref(), Some("released"));
        assert_eq!(directory.live_count(), 0);

        // Release surrenders the conversation but is no longer a one-way door: Ciao made the
        // terminal it went to and knows its name, so it can end that holder and resume. The
        // rule that still holds is the one about conversations nobody told Ciao about, fenced
        // in `a_handed_back_session_comes_home_but_a_stolen_one_does_not`.

        // The vendor identifier now crosses to the client, in exactly one shape: the command
        // that reopens the conversation, on a session Ciao has already surrendered.
        //
        // This reverses the original rule, and the rule was wrong. It was written so a vendor
        // ID would not leak into a descriptor that had no use for one — but the released
        // descriptor is precisely the one that does, and withholding it meant the only copy
        // was a line `ciao agent release` printed on the Mac. Which is the machine the user is
        // not at; being elsewhere is why they handed the session back. The ID names a local
        // conversation on the user's own machine and travels their own paired channel to their
        // own phone: it is a name, not a credential.
        //
        // Still not carried anywhere else. A live managed session's descriptor has no use for
        // it, and `stored_descriptor` emits one only for `released`.
        let wire = serde_json::to_string(&stored).unwrap();
        assert!(wire.contains("claude --resume vendor-handback-0001"));
        let live = directory.stored_descriptors(&all_recorded_handbacks(&directory));
        assert!(
            live.iter()
                .filter(|descriptor| descriptor.stored_reason.as_deref() != Some("released"))
                .all(|descriptor| descriptor.terminal_fallback.resume_command.is_none())
        );

        let unknown = directory.managed_release("nope", "cmd-unknown").await;
        assert_eq!(unknown.0.reason_code.as_deref(), Some("unknown_session"));
    }

    /// How many agents run at once is the person's decision, not Ciao's (owner-directed
    /// 2026-08-02). Pi, Codex and Claude impose no such limit, and a host that refuses the fifth
    /// session is refusing work the machine may well have room for. The resource cost is real and
    /// is theirs to weigh: an idle worker is ~85 MiB.
    ///
    /// The bound that remains is on the *record store*, two orders of magnitude higher and about
    /// storage rather than permission.
    #[tokio::test]
    async fn no_limit_is_imposed_on_how_many_sessions_run_at_once() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let directory = directory(&store);
        for index in 0..12 {
            let workspace = home.path().join(format!("workspace-{index}"));
            fs::create_dir_all(&workspace).unwrap();
            let outcome = directory
                .managed_start_at_path(&workspace, &format!("cmd-{index}"))
                .await;
            assert_eq!(outcome.state, "accepted", "session {index} was refused");
        }
        assert_eq!(directory.live_count(), 12);
    }

    #[tokio::test]
    async fn daemon_restart_transitions_live_records_to_stored() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let session_id = {
            let directory = directory(&store);
            let started = directory
                .managed_start_at_path(&workspace, "cmd-start")
                .await;
            started.session_id.unwrap()
        };
        // A fresh load models the daemon restart: the worker is gone and the
        // session resumes only by explicit command.
        let directory = directory(&store);
        assert_eq!(directory.live_count(), 0);
        let stored = directory.stored_descriptors(&all_recorded_handbacks(&directory));
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].session_id, session_id);
        assert_eq!(stored[0].stored_reason.as_deref(), Some("daemon_restart"));
        let resumed = directory.managed_resume(&session_id, "cmd-resume").await;
        assert_eq!(resumed.state, "accepted");
    }

    /// The ownership check ran only before a worker started, so a terminal that resumed the
    /// conversation afterwards was invisible and both processes appended to one transcript.
    #[tokio::test]
    async fn a_live_session_notices_a_terminal_that_took_its_conversation() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&store);
        let session_id = directory
            .managed_start_at_path(&workspace, "cmd-start")
            .await
            .session_id
            .unwrap();
        let vendor = format!("vendor-{session_id}");
        directory.record_vendor_session(&session_id, &vendor);

        // Ciao's own worker is resuming this conversation, and that must never read as a
        // second owner or every live session would withdraw itself immediately.
        assert!(
            directory.foreign_owned_live_sessions().await.is_empty(),
            "the session's own worker is not a foreign owner"
        );

        fake(&directory)
            .foreign_owned
            .lock()
            .unwrap()
            .insert(vendor);
        assert_eq!(
            directory.foreign_owned_live_sessions().await,
            vec![session_id.clone()]
        );

        // What the daemon does with that answer: stop the worker, settle the record, then
        // mark it. The order matters — a record only takes the mark once it is stored, so
        // marking a live one is silently dropped and the reason is lost.
        directory.record_worker_exit(&session_id, false);
        directory.mark_externally_owned(&session_id);
        let stored = directory.stored_descriptors(&HashSet::new());
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].stored_reason.as_deref(), Some("externally_owned"));

        // Withdrawn sessions are not reported again; the sweep runs every tick.
        assert!(directory.foreign_owned_live_sessions().await.is_empty());
    }

    /// A daemon restart stores every live session, so during development they accumulate with
    /// nothing able to remove them: the other verbs all move a session between states and none
    /// ends one.
    #[tokio::test]
    async fn forget_drops_a_stored_record_and_refuses_a_live_one() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let running = directory(&store);
        let session_id = running
            .managed_start_at_path(&workspace, "cmd-start")
            .await
            .session_id
            .unwrap();

        // Forgetting a running worker would orphan the process rather than stop it.
        let live = running.managed_forget(&session_id, "cmd-forget-live");
        assert_eq!(live.reason_code.as_deref(), Some("already_live"));

        let missing = running.managed_forget("no-such-session", "cmd-forget-missing");
        assert_eq!(missing.reason_code.as_deref(), Some("unknown_session"));

        // A fresh load models the daemon restart that stored it.
        let restarted = directory(&store);
        assert_eq!(
            restarted.managed_forget(&session_id, "cmd-forget").state,
            "accepted"
        );
        assert!(
            restarted
                .stored_descriptors(&all_recorded_handbacks(&restarted))
                .is_empty(),
            "a forgotten session must stop appearing in the directory"
        );
        // Persisted, rather than coming back on the next load.
        assert!(
            directory(&store)
                .stored_descriptors(&HashSet::new())
                .is_empty()
        );
    }

    #[tokio::test]
    async fn crash_report_retains_the_session_as_stored() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&store);
        let started = directory
            .managed_start_at_path(&workspace, "cmd-start")
            .await;
        let session_id = started.session_id.unwrap();
        directory.record_worker_exit(&session_id, true);
        let stored = directory.stored_descriptors(&all_recorded_handbacks(&directory));
        assert_eq!(stored[0].stored_reason.as_deref(), Some("worker_crash"));
        assert_eq!(directory.live_count(), 0);
    }

    #[tokio::test]
    async fn an_uninstalled_managed_integration_refuses_start_categorically() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        // Nothing is installed under the Ciao-owned prefix, so pin resolution
        // refuses before any process is spawned.
        let directory = ManagedSessionDirectory::load(
            &store,
            home.path(),
            ManagedLauncher::Worker(Box::new(WorkerLauncher::new(
                home.path().join("managed/claude-sdk"),
                home.path().join("managed/worker.mjs"),
                home.path().join("agent.sock"),
                Arc::new(crate::managed_worker::WorkerTable::default()),
            ))),
        )
        .unwrap();
        let outcome = directory
            .managed_start_at_path(&workspace, "cmd-start")
            .await;
        assert_eq!(outcome.reason_code.as_deref(), Some("runtime_unavailable"));
        assert_eq!(directory.live_count(), 0);
    }

    #[tokio::test]
    async fn metadata_stays_private_bounded_and_content_free() {
        let home = tempdir().unwrap();
        let store = home.path().join("agent-managed.json");
        let workspace = home.path().join("canary-workspace");
        fs::create_dir_all(&workspace).unwrap();
        let directory = directory(&store);
        let started = directory
            .managed_start_at_path(&workspace, "cmd-start")
            .await;
        let session_id = started.session_id.unwrap();

        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&store).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // The wire-facing surfaces never carry the raw vendor session ID or the
        // raw workspace path; both stay confined to the restrictive store.
        directory.record_vendor_session(&session_id, "vendor-canary-0001");
        let raw = fs::read_to_string(&store).unwrap();
        assert!(raw.contains("vendor-canary-0001"));
        assert!(raw.contains("canary-workspace"));
        directory.managed_stop(&session_id, 1, "cmd-stop").await;
        let stored_wire = serde_json::to_string(
            &directory.stored_descriptors(&all_recorded_handbacks(&directory)),
        )
        .unwrap();
        let workspace_wire = serde_json::to_string(&directory.workspaces().await).unwrap();
        for wire in [&stored_wire, &workspace_wire] {
            assert!(!wire.contains("vendor-canary-0001"));
            assert!(!wire.contains(&workspace.to_string_lossy().into_owned()));
        }
    }
}
