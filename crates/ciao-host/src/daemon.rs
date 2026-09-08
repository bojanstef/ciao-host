use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, TransportAddr, Watcher,
    endpoint::{
        ConnectingError, Connection, ConnectionError, PathId, QuicTransportConfig, VarInt, presets,
    },
};
use iroh_tickets::endpoint::EndpointTicket;
use parking_lot::Mutex;
use serde_json::Value;
use tokio::{
    io::BufReader,
    net::{UnixListener, UnixStream},
    sync::watch,
    task::JoinSet,
    time::timeout,
};

use crate::{
    agent_protocol::{
        AGENT_PROTOCOL_VERSION, AgentClientFrame, AgentLimits, AgentServerFrame, AgentStreamOpen,
        CAPABILITY_AGENT_SESSION_MANAGED_V1, bounded_session_list, decode_agent_body,
        read_agent_frame, write_agent_frame,
    },
    agent_session::AgentSessionSupervisor,
    claude_integration::refresh_installed_claude_plugin,
    host_info,
    host_protocol::{
        CONNECTION_AUTHORIZATION_DENIED, CONNECTION_BUSY, CONNECTION_PROTOCOL_VIOLATION,
        CONNECTION_SUPERSEDED, HOST_ALPN, HOST_CONNECTION_RECEIVE_WINDOW, HOST_OPERATION_TIMEOUT,
        HOST_PROTOCOL_VERSION, HOST_SEND_WINDOW, HOST_STREAM_RECEIVE_WINDOW, HostHelloRequest,
        HostHelloResponse, HostInfoResponse, HostInfoResult, HostProtocolError, HostReceiveState,
        LiveActivityRegisterResponse, MAX_FORWARD_STREAMS, MAX_INCOMING_BIDI_STREAMS,
        MAX_INCOMING_UNI_STREAMS, MAX_NORMAL_CONNECTIONS, MAX_NORMAL_CONNECTIONS_PER_ENDPOINT,
        MAX_PENDING_HANDSHAKES, NotificationsRegisterResponse, RpcErrorResponse, RpcRequest,
        STREAM_BACKPRESSURE, STREAM_FORWARD_LIMIT, STREAM_INTERNAL, STREAM_MALFORMED,
        STREAM_PTY_FAILURE, STREAM_TERMINAL_LIMIT, STREAM_UNEXPECTED, StreamKind,
        TerminalCommandsResponse, TerminalError, TerminalExit, TerminalFrame, TerminalOpen,
        TerminalOpened, WorkspaceSnapshotResponse, decode_rpc_request,
        encode_snapshot_response_bounded, encode_terminal_commands_response_bounded, read_rpc_body,
        read_stream_preface_with_timeout, read_terminal_frame, write_rpc, write_terminal_frame,
    },
    identity::load_identity,
    ipc::{
        CreatePairingResult, DaemonStatus, IpcOperation, error_response, parse_request,
        read_bounded_line, success_response, write_response,
    },
    live_activity::LiveActivityOverview,
    managed_session::{ManagedLauncher, ManagedSessionDirectory, WorkerLauncher},
    managed_worker::{SharedWorkerTable, WorkerTable},
    notify::Notifier,
    pairing::{
        PairingClaim, PairingManager, PairingRateLimiter, PairingRejection, encoded_pairing_id,
    },
    protocol::{
        HEARTBEAT_INTERVAL_MS, HEARTBEAT_TIMEOUT_SECS, PAIRING_ALPN, PROTOCOL_VERSION,
        ProtocolError, WireMessage, base64url, kex_public, kex_shared, notification_key,
        notification_key_fingerprint, pairing_transcript_hash, read_frame, write_frame,
    },
    pty::{CleanupReason, PtyError, PtyExit, PtySession, resolve_account},
    qr::{decode_exact, encode_pairing_uri},
    storage::{
        CiaoPaths, LiveActivitySelection, LiveActivitySelectionChange, PairedDeviceStore,
        remove_socket_if_present,
    },
    workspace::{WorkspaceConfig, capture_snapshot, detach_tmux_client, target_command},
};

const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const AGENT_ROUTE_REVALIDATION_INTERVAL: Duration = Duration::from_secs(1);
/// Passes of the revalidation loop between attempts to recover a session that holds no route.
const AGENT_ROUTE_RECOVERY_TICKS: u32 = 15;
const MAX_PAIRING_CONNECTIONS: usize = 16;
const MAX_IPC_CONNECTIONS: usize = 32;
const RELAY_ONLY_ENV: &str = "CIAO_PHASE1_RELAY_ONLY";
/// A client that keeps sending RPC requests without ever completing `host.hello` is cut off
/// after this many pre-hello streams; the connection fails closed as a protocol violation.
const MAX_PRE_HELLO_STREAMS: usize = 8;

#[derive(Debug, Default)]
struct ActiveConnections {
    by_endpoint: HashMap<String, HashSet<u128>>,
}

impl ActiveConnections {
    fn add(&mut self, endpoint_id: EndpointId) -> (String, u128) {
        let endpoint = endpoint_id.to_string();
        let token = rand::random::<u128>();
        self.by_endpoint
            .entry(endpoint.clone())
            .or_default()
            .insert(token);
        (endpoint, token)
    }

    fn remove(&mut self, endpoint: &str, token: u128) {
        let Some(tokens) = self.by_endpoint.get_mut(endpoint) else {
            return;
        };
        tokens.remove(&token);
        if tokens.is_empty() {
            self.by_endpoint.remove(endpoint);
        }
    }

    fn device_count(&self) -> usize {
        self.by_endpoint.len()
    }
}

#[derive(Debug, Default)]
struct ConnectionAdmissions {
    by_endpoint: HashMap<String, HashSet<u128>>,
    total: usize,
}

impl ConnectionAdmissions {
    /// One short device ID per open lease, so a count can be traced back to the device holding
    /// it. An owner who closed the app on the phone in their hand and still read
    /// `Active terminals: 1` had no way to learn it belonged to another paired device.
    fn lease_devices(&self) -> Vec<String> {
        let mut devices: Vec<String> = self
            .by_endpoint
            .iter()
            .flat_map(|(endpoint, tokens)| {
                std::iter::repeat_n(short_endpoint_text(endpoint), tokens.len())
            })
            .collect();
        devices.sort();
        devices
    }

    fn try_add(&mut self, endpoint_id: EndpointId) -> Option<(String, u128)> {
        self.try_add_with_limits(
            endpoint_id,
            MAX_NORMAL_CONNECTIONS,
            MAX_NORMAL_CONNECTIONS_PER_ENDPOINT,
        )
    }

    fn try_add_with_limits(
        &mut self,
        endpoint_id: EndpointId,
        global_limit: usize,
        endpoint_limit: usize,
    ) -> Option<(String, u128)> {
        let endpoint = endpoint_id.to_string();
        let endpoint_count = self.by_endpoint.get(&endpoint).map_or(0, HashSet::len);
        if self.total >= global_limit || endpoint_count >= endpoint_limit {
            return None;
        }
        let token = rand::random::<u128>();
        self.by_endpoint
            .entry(endpoint.clone())
            .or_default()
            .insert(token);
        self.total += 1;
        Some((endpoint, token))
    }

    /// Grants a subscription slot, replacing whatever this endpoint already holds.
    ///
    /// The per-endpoint limit of one is right — Spec 005 gives iOS at most one live
    /// subscription — but refusing the *new* request enforces it backwards. iOS has no
    /// background networking (ADR 002), so a backgrounded or force-quit app cannot close its
    /// stream; the host keeps counting it until the QUIC idle timeout expires. Refusing meant
    /// the phone in someone's hand was turned away on behalf of a stream nobody was reading,
    /// and the only cure was waiting it out. Superseding keeps the bound exactly and always
    /// answers the live request.
    ///
    /// ponytail: the superseded stream is untracked, not cancelled — it ends on its own idle
    /// timeout. Cancelling it needs a handle per subscription; add that if a draining stream
    /// ever costs more than the bookkeeping does.
    fn try_add_superseding(
        &mut self,
        endpoint_id: EndpointId,
        global_limit: usize,
    ) -> Option<(String, u128)> {
        let endpoint = endpoint_id.to_string();
        if let Some(tokens) = self.by_endpoint.remove(&endpoint) {
            self.total = self.total.saturating_sub(tokens.len());
        }
        // The global cap still refuses: superseding frees this endpoint's own slots, never
        // another device's.
        if self.total >= global_limit {
            return None;
        }
        let token = rand::random::<u128>();
        self.by_endpoint
            .entry(endpoint.clone())
            .or_default()
            .insert(token);
        self.total += 1;
        Some((endpoint, token))
    }

    fn remove(&mut self, endpoint: &str, token: u128) {
        let Some(tokens) = self.by_endpoint.get_mut(endpoint) else {
            return;
        };
        if tokens.remove(&token) {
            self.total = self.total.saturating_sub(1);
        }
        if tokens.is_empty() {
            self.by_endpoint.remove(endpoint);
        }
    }

    /// Removes and returns every token this endpoint holds. The connection path uses it to
    /// supersede: the same installation dialing again at its own cap means the tracked
    /// connections are corpses a suspended app could never close (ADR 002), so the newest
    /// connection wins instead of being refused on their behalf. The evicted leases' `Drop`
    /// still runs later; `remove` is token-keyed and idempotent, so nothing double-frees.
    fn evict_endpoint(&mut self, endpoint: &str) -> Vec<u128> {
        let Some(tokens) = self.by_endpoint.remove(endpoint) else {
            return Vec::new();
        };
        self.total = self.total.saturating_sub(tokens.len());
        tokens.into_iter().collect()
    }
}

#[derive(Debug)]
struct RuntimeState {
    host_endpoint_id: EndpointId,
    online: AtomicBool,
    relay_known: AtomicBool,
    pairing: Mutex<PairingManager>,
    rate_limiter: Mutex<PairingRateLimiter>,
    // Shared rather than owned so the notifier can read tickets and drop dead ones without the
    // agent bridge having to reach back into the whole runtime.
    paired_devices: Arc<Mutex<PairedDeviceStore>>,
    notifier: Notifier,
    normal_connections: Mutex<ConnectionAdmissions>,
    host_connections: Mutex<HashMap<u128, Connection>>,
    active_ptys: Mutex<ConnectionAdmissions>,
    /// Which multiplexer session each live PTY lease attached to, keyed by the same
    /// `(endpoint, token)` pair `active_ptys` leases. Spec 015 §11.1: a preview arrives on its
    /// own stream carrying no session of its own, so this is the only way the download side can
    /// learn whose directory a relative token belongs to.
    attached_sessions: Mutex<HashMap<(String, u128), AttachedSession>>,
    resumable_ptys: AtomicUsize,
    active_agent_subscriptions: Mutex<ConnectionAdmissions>,
    pairing_connections: AtomicUsize,
    decoded_host_prefaces: AtomicUsize,
    shutdown: watch::Sender<bool>,
    active: Mutex<ActiveConnections>,
    workspace: WorkspaceConfig,
    /// The pinned managed pair's location. Held here rather than reached through
    /// `managed_sessions` because the slash-command probe needs the same verified runtime
    /// without going anywhere near a session: it reads a command list for a terminal the user
    /// runs, and starts nothing.
    managed_sdk_prefix: PathBuf,
    managed_worker_entrypoint: PathBuf,
    agent_sessions: AgentSessionSupervisor,
    managed_sessions: ManagedSessionDirectory,
    codex_adoptions: Arc<crate::codex_adopted::AdoptionRegistry>,
    managed_workers: SharedWorkerTable,
    host_info: HostInfoResult,
    /// Spec 007 upload storage under `state_dir/uploads/`; the daemon owns its TTL/quota
    /// sweeping, never the phone.
    uploads: crate::uploads::UploadStore,
}

impl RuntimeState {
    /// The one multiplexer session this device has a terminal on, or `None` when it has none or
    /// is attached to more than one.
    ///
    /// Ambiguity refuses on purpose. Resolving a relative token against the wrong session's
    /// directory could find a same-named file and present it as the right one, and Spec 015
    /// §11.1 names that as the single failure this feature cannot afford — a refusal says what
    /// is wrong, a wrong file says nothing. Two leases on the *same* session are not ambiguous:
    /// a reattach that has not finished unwinding still names one directory.
    fn sole_attached_session(&self, endpoint: &str) -> Option<AttachedSession> {
        let sessions = self.attached_sessions.lock();
        let mut found: Option<&AttachedSession> = None;
        for ((lease_endpoint, _), session) in sessions.iter() {
            if lease_endpoint != endpoint {
                continue;
            }
            match found {
                Some(existing) if existing == session => {}
                Some(_) => return None,
                None => found = Some(session),
            }
        }
        found.cloned()
    }

    fn status(&self) -> DaemonStatus {
        let online = self.online.load(Ordering::Relaxed);
        let relay_known = self.relay_known.load(Ordering::Relaxed);
        // Both terminal figures come from one guard. A second `self.active_ptys.lock()` further
        // down the struct literal deadlocks against this one: a temporary in a field initializer
        // lives until the whole expression ends, so the first guard is still held.
        let (active_terminals, active_terminal_devices) = {
            let ptys = self.active_ptys.lock();
            (ptys.total, ptys.lease_devices())
        };
        DaemonStatus {
            v: PROTOCOL_VERSION,
            daemon: "running".into(),
            iroh: if online {
                "online"
            } else if relay_known {
                "offline"
            } else {
                "starting"
            }
            .into(),
            host_endpoint_id: self.host_endpoint_id.to_string(),
            host_endpoint_id_short: short_endpoint_id(self.host_endpoint_id),
            paired_devices: self.paired_devices.lock().len(),
            active_connections: Some(self.active.lock().device_count()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            protocol: Some(HOST_PROTOCOL_VERSION),
            platform: Some(crate::host_info::platform_token().to_string()),
            active_terminals: Some(active_terminals),
            // Everything Ciao is observing or running, which is what the status line reports.
            active_agent_sessions: Some(
                self.agent_sessions.active_count() + self.managed_sessions.live_count(),
            ),
            // Spec 006 §14: a live managed worker is active work the installer must refuse on.
            // Reported separately from the sum above because an attached session is not — see
            // the amended Spec 005 §8.3.
            active_managed_workers: Some(self.managed_sessions.live_count()),
            // Spec 003: a multiplexer session outlives the client Ciao attaches to it, so these
            // terminals are the ones an update may take down and put back.
            resumable_terminals: Some(self.resumable_ptys.load(Ordering::Relaxed)),
            active_terminal_devices: Some(active_terminal_devices),
        }
    }
}

struct ActiveLease {
    state: Arc<RuntimeState>,
    endpoint: String,
    token: u128,
}

impl ActiveLease {
    fn new(state: Arc<RuntimeState>, endpoint_id: EndpointId) -> Self {
        let (endpoint, token) = state.active.lock().add(endpoint_id);
        Self {
            state,
            endpoint,
            token,
        }
    }
}

impl Drop for ActiveLease {
    fn drop(&mut self) {
        self.state.active.lock().remove(&self.endpoint, self.token);
    }
}

struct NormalConnectionLease {
    state: Arc<RuntimeState>,
    endpoint: String,
    token: u128,
}

impl NormalConnectionLease {
    fn try_new(
        state: Arc<RuntimeState>,
        endpoint_id: EndpointId,
        connection: &Connection,
    ) -> Option<Self> {
        // At this installation's own cap, supersede rather than refuse: iOS has no background
        // networking (ADR 002), so a backgrounded or force-quit app cannot close its
        // connections, and the host would otherwise count them against the phone in someone's
        // hand until the QUIC idle timeout — the exact trade already made for agent
        // subscriptions in `try_add_superseding`, now with the corpses actively closed so
        // their PTY leases and session tasks unwind instead of draining. A cap reached by
        // *other* devices (global exhaustion) still refuses.
        let (endpoint, token, evicted) = {
            let mut admissions = state.normal_connections.lock();
            match admissions.try_add(endpoint_id) {
                Some((endpoint, token)) => (endpoint, token, Vec::new()),
                None => {
                    let evicted = admissions.evict_endpoint(&endpoint_id.to_string());
                    if evicted.is_empty() {
                        return None;
                    }
                    let (endpoint, token) = admissions.try_add(endpoint_id)?;
                    (endpoint, token, evicted)
                }
            }
        };
        {
            let mut handles = state.host_connections.lock();
            for old in &evicted {
                if let Some(stale) = handles.remove(old) {
                    stale.close(
                        VarInt::from_u32(CONNECTION_SUPERSEDED),
                        b"superseded by a newer connection from this device",
                    );
                }
            }
            handles.insert(token, connection.clone());
        }
        if !evicted.is_empty() {
            tracing::info!(
                remote = %short_endpoint_id(endpoint_id),
                count = evicted.len(),
                "superseded stale connections"
            );
        }
        Some(Self {
            state,
            endpoint,
            token,
        })
    }
}

impl Drop for NormalConnectionLease {
    fn drop(&mut self) {
        self.state.host_connections.lock().remove(&self.token);
        self.state
            .normal_connections
            .lock()
            .remove(&self.endpoint, self.token);
    }
}

/// Whether what runs behind a PTY outlives it. A tmux or Herdr session keeps running when its
/// client goes away — including the one an Agent Session route lands in, which is always a
/// multiplexer session — so an update closes the view and the phone reattaches. Only a plain
/// login shell dies with the PTY, and only that is work an installer must refuse on.
fn target_is_resumable(
    target: Option<crate::host_protocol::TerminalTarget>,
    has_agent_plan: bool,
) -> bool {
    has_agent_plan
        || target
            .and_then(crate::host_protocol::TerminalTarget::provider)
            .is_some()
}

/// The multiplexer session a PTY lease attached to, remembered only so a later preview on a
/// separate stream can ask it where it is standing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AttachedSession {
    kind: crate::host_protocol::ProviderKind,
    name: String,
}

struct PtyLease {
    state: Arc<RuntimeState>,
    endpoint: String,
    token: u128,
    /// Whether what runs behind this PTY survives without it — a tmux or Herdr session keeps
    /// running when its client goes away, a plain login shell does not. The installer asks.
    resumable: bool,
}

impl PtyLease {
    fn try_new(
        state: Arc<RuntimeState>,
        endpoint_id: EndpointId,
        resumable: bool,
        session: Option<AttachedSession>,
    ) -> Option<Self> {
        let (endpoint, token) = state.active_ptys.lock().try_add_with_limits(
            endpoint_id,
            crate::host_protocol::MAX_ACTIVE_PTYS,
            crate::host_protocol::MAX_ACTIVE_PTYS_PER_ENDPOINT,
        )?;
        if resumable {
            state.resumable_ptys.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(session) = session {
            state
                .attached_sessions
                .lock()
                .insert((endpoint.clone(), token), session);
        }
        Some(Self {
            state,
            endpoint,
            token,
            resumable,
        })
    }
}

impl Drop for PtyLease {
    fn drop(&mut self) {
        if self.resumable {
            self.state.resumable_ptys.fetch_sub(1, Ordering::Relaxed);
        }
        self.state
            .attached_sessions
            .lock()
            .remove(&(self.endpoint.clone(), self.token));
        self.state
            .active_ptys
            .lock()
            .remove(&self.endpoint, self.token);
    }
}

struct AgentSubscriptionLease {
    state: Arc<RuntimeState>,
    endpoint: String,
    token: u128,
}

impl AgentSubscriptionLease {
    fn try_new(state: Arc<RuntimeState>, endpoint_id: EndpointId) -> Option<Self> {
        let (endpoint, token) = state
            .active_agent_subscriptions
            .lock()
            .try_add_superseding(
                endpoint_id,
                crate::host_protocol::MAX_ACTIVE_AGENT_SUBSCRIPTIONS,
            )?;
        Some(Self {
            state,
            endpoint,
            token,
        })
    }
}

impl Drop for AgentSubscriptionLease {
    fn drop(&mut self) {
        self.state
            .active_agent_subscriptions
            .lock()
            .remove(&self.endpoint, self.token);
    }
}

struct PairingConnectionLease {
    state: Arc<RuntimeState>,
}

impl PairingConnectionLease {
    fn try_new(state: Arc<RuntimeState>) -> Option<Self> {
        let result = state.pairing_connections.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |current| (current < MAX_PAIRING_CONNECTIONS).then_some(current + 1),
        );
        result.ok().map(|_| Self { state })
    }
}

impl Drop for PairingConnectionLease {
    fn drop(&mut self) {
        self.state
            .pairing_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointMode {
    Normal,
    RelayOnlyTest,
}

fn endpoint_mode(value: Option<&OsStr>) -> EndpointMode {
    if value == Some(OsStr::new("1")) {
        EndpointMode::RelayOnlyTest
    } else {
        EndpointMode::Normal
    }
}

fn host_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(VarInt::from_u32(u32::from(MAX_INCOMING_BIDI_STREAMS)))
        .max_concurrent_uni_streams(VarInt::from_u32(u32::from(MAX_INCOMING_UNI_STREAMS)))
        .stream_receive_window(VarInt::from_u32(HOST_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(HOST_CONNECTION_RECEIVE_WINDOW))
        .send_window(HOST_SEND_WINDOW)
        // RFC 9000 §10.1: the effective idle timeout is the min of both peers', and iroh-ffi
        // exposes no transport config to the app — so this one line bounds silent-death
        // detection, corpse-slot lifetime, and force-quit PTY cleanup (ADR 002 §9) for BOTH
        // ends: 15 s instead of the noq default 30 s. Not lower: iroh's 5 s keep-alives stop
        // during a brief suspension, and 15 s (3× keep-alive, the same margin iroh's own
        // 15 s path-idle uses) keeps a ~10 s app switch inside the survivable window that
        // makes foreground resume instant.
        .max_idle_timeout(Some(
            Duration::from_secs(15)
                .try_into()
                .expect("15s is a valid QUIC idle timeout"),
        ))
        // Keep-alives every 2 s instead of iroh's 5 s, on the connection and on every path
        // (the relay backup included). Two reasons, both host-side: `PathProbeWatch` reads a
        // dead path off QUIC's unanswered probes, and a ping every 2 s is what makes that
        // evidence accrue on an idle terminal too; and the phone hears this host at least
        // every 2 s on a healthy path, so its own silence marks stop straddling a 5 s
        // cadence. The phone's iroh-ffi has no such knob, so only this side changes. Cost:
        // ~50 B/2 s per path; the radio is already awake at the 5 s cadence.
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .default_path_keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .build()
}

/// See `host_transport_config`. `PathProbeWatch`'s two-second floor is one cadence of it.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(2);

/// Spec 014's Class B, healed where the knob is (2026-09-02, connection-quality lab). A
/// selected path whose sends have stopped being acknowledged while another path is open is
/// abandoned by this host, so iroh's selector moves to the backup path — the relay — within
/// seconds, instead of the phone noticing after its ~15 s path idle, convicting the whole
/// connection, and paying an endpoint recycle plus a redial for a path that was the only
/// thing wrong. Both directions of a one-way blackhole look the same from here: this
/// path's packets stop being acknowledged.
///
/// The evidence is QUIC's own: `PathStats::pto_count` (a one-field patch on noq-proto, see
/// `vendor/noq-proto/CIAO-PATCH.md`) counts consecutive probe timeouts on the path with
/// nothing acknowledged in between, and any acknowledgement of that path's packets resets
/// it. Nothing else in the per-path statistics can say this: with no acknowledgement to
/// compare against QUIC never declares a loss, so `lost_packets` and `cwnd` sit untouched
/// through a whole blackhole, and ACK-frame counts belong to the path a frame *arrived* on,
/// which under multipath is whichever path the phone prefers — a first draft of this watch
/// read those and convicted healthy paths in the lab's control run.
///
/// The bar: the counter at three or more — probe backoff has doubled twice, so the transport
/// itself has been asking for at least seven base timeouts — and the last acknowledgement
/// more than two seconds ago, which keeps a Wi-Fi burst inside QUIC's own recovery window
/// from moving a healthy path. And the one-way signature itself: the phone is still *heard*
/// on that same path — its datagrams keep arriving — *since* it stopped answering, with
/// `HEARD_SLACK` for the one-second sampling. That is the blackhole the daily phone recorded
/// on 2026-08-11 (reconnect profile §7: `rx+0` for 20 s while its own sends kept leaving),
/// and it is what a suspended phone, silent on every path, cannot produce; the idle timeout
/// owns that case. Three other clauses were tried and convicted by a lab first: none
/// (the simulator's SIGSTOP scenarios abandoned the direct path five times); "another path
/// whose probes are answered" (under multipath the phone acknowledges on the path *it*
/// prefers, so nothing this host sends anywhere is answered while its uplink is dead);
/// "heard on another path" (a mature connection carries nothing on its backup relay path,
/// so it never fired at all). The other direction — the phone's uplink dead while it still
/// hears this host — leaves nothing for this host to distinguish from suspension and stays
/// with the path idle timeout; the app convicts it itself 2.5 s after an unanswered
/// keystroke, and output keeps flowing meanwhile. A false conviction would cost a hop to the
/// relay until iroh's next holepunch upgrade, not a reconnect.
#[derive(Debug, Default)]
struct PathProbeWatch {
    path: Option<PathId>,
    answered_at: Option<std::time::Instant>,
}

impl PathProbeWatch {
    const PTO_COUNT: u32 = 3;
    const UNANSWERED: Duration = Duration::from_secs(2);
    /// A datagram already in flight when the phone stopped can be sampled up to a second
    /// after the baseline sample; two seconds keeps it out of "heard since".
    const HEARD_SLACK: Duration = Duration::from_secs(2);

    /// One sample of the selected path. Returns how long the path has gone unanswered, and
    /// the instant it was last answered, once the probe bar is met; `None` while it is
    /// healthy, idle, or too young to judge. Whether the phone is still heard on the path is
    /// the caller's question (`PathRxWatch::heard_on_since` the returned instant plus
    /// `HEARD_SLACK`), and so is whether another path exists to move to.
    fn observe(
        &mut self,
        now: std::time::Instant,
        path: PathId,
        pto_count: u32,
    ) -> Option<(Duration, std::time::Instant)> {
        if self.path != Some(path) || pto_count == 0 {
            // A new selection, or the transport heard back: the baseline moves here.
            *self = Self {
                path: Some(path),
                answered_at: Some(now),
            };
            return None;
        }
        let answered_at = self.answered_at?;
        let unanswered = now.saturating_duration_since(answered_at);
        (pto_count >= Self::PTO_COUNT && unanswered >= Self::UNANSWERED)
            .then_some((unanswered, answered_at))
    }
}

/// When the phone was last heard on each path: its inbound datagram counter moving is the
/// phone talking on that path, whatever this host's own sends there get back.
#[derive(Debug, Default)]
struct PathRxWatch {
    paths: std::collections::HashMap<PathId, (u64, std::time::Instant)>,
}

impl PathRxWatch {
    fn note(&mut self, now: std::time::Instant, path: PathId, rx_datagrams: u64) {
        match self.paths.get_mut(&path) {
            Some((seen, _)) if *seen == rx_datagrams => {}
            Some((seen, at)) => {
                *seen = rx_datagrams;
                *at = now;
            }
            // A path seen for the first time gets the benefit of the doubt for one window.
            None => {
                self.paths.insert(path, (rx_datagrams, now));
            }
        }
    }

    /// Whether the phone was heard on `path` strictly after `after`.
    fn heard_on_since(&self, path: PathId, after: std::time::Instant) -> bool {
        self.paths.get(&path).is_some_and(|(_, at)| *at > after)
    }
}

pub async fn run(paths: CiaoPaths) -> Result<()> {
    paths.ensure_layout()?;
    match refresh_installed_claude_plugin(&paths) {
        Ok(true) => tracing::info!("installed Claude hooks refreshed to this Ciao version"),
        Ok(false) => {}
        Err(error) => tracing::warn!("installed Claude hooks were left as they are: {error}"),
    }
    let identity = load_identity(&paths)?.ok_or_else(|| {
        anyhow!("Ciao is not configured. Run `ciao setup --yes` before `ciao daemon`.")
    })?;
    let paired_devices = PairedDeviceStore::load(&paths.paired_devices_file)?;

    let mode = endpoint_mode(std::env::var_os(RELAY_ONLY_ENV).as_deref());
    let mut endpoint_builder = Endpoint::builder(presets::N0)
        .secret_key(identity.secret_key)
        .alpns(vec![PAIRING_ALPN.to_vec(), HOST_ALPN.to_vec()])
        .transport_config(host_transport_config());
    // Ciao's own relays replace Number 0's for packet relaying. This errors rather than
    // returning `None` in a release build, so a shipped daemon can never quietly relay
    // through Number 0 while the paired app relays through us.
    if let Some(map) = crate::relay::configured_map()? {
        endpoint_builder = endpoint_builder.relay_mode(RelayMode::Custom(map));
    }
    if mode == EndpointMode::RelayOnlyTest {
        endpoint_builder = endpoint_builder.clear_ip_transports();
        tracing::info!("relay-only test mode is active");
    }
    let endpoint = endpoint_builder
        .bind()
        .await
        .context("bind the persistent Iroh endpoint with the Number 0 preset")?;
    if endpoint.id() != identity.endpoint_id {
        endpoint.close().await;
        bail!("bound Iroh endpoint does not match the persisted host identity");
    }

    let host_info = host_info::collect(identity.endpoint_id)?;
    let workspace = WorkspaceConfig::for_home(&paths.home);
    let agent_sessions =
        AgentSessionSupervisor::load(&paths.agent_metadata_file, workspace.clone())?;
    // The managed launcher is available only when the Ciao-owned SDK prefix and
    // worker entrypoint are installed; otherwise start/resume refuse
    // categorically while stored sessions stay listed.
    let managed_workers: SharedWorkerTable = Arc::new(WorkerTable::default());
    let codex_adoptions = Arc::new(crate::codex_adopted::AdoptionRegistry::load(
        paths
            .agent_metadata_file
            .with_file_name("codex-runtime.json"),
    ));
    let managed_sessions = ManagedSessionDirectory::load(
        &paths.agent_managed_file,
        &paths.home,
        ManagedLauncher::Worker(Box::new(WorkerLauncher::new(
            paths.managed_sdk_prefix.clone(),
            paths.managed_worker_entrypoint.clone(),
            paths.agent_socket_file.clone(),
            managed_workers.clone(),
        ))),
    )?;
    let paired_devices = Arc::new(Mutex::new(paired_devices));
    let state = Arc::new(RuntimeState {
        host_endpoint_id: identity.endpoint_id,
        online: AtomicBool::new(false),
        relay_known: AtomicBool::new(false),
        pairing: Mutex::new(PairingManager::default()),
        rate_limiter: Mutex::new(PairingRateLimiter::default()),
        notifier: Notifier::new(paired_devices.clone(), host_info.display_name.clone()),
        paired_devices,
        normal_connections: Mutex::new(ConnectionAdmissions::default()),
        host_connections: Mutex::new(HashMap::new()),
        active_ptys: Mutex::new(ConnectionAdmissions::default()),
        attached_sessions: Mutex::new(HashMap::new()),
        resumable_ptys: AtomicUsize::new(0),
        active_agent_subscriptions: Mutex::new(ConnectionAdmissions::default()),
        pairing_connections: AtomicUsize::new(0),
        decoded_host_prefaces: AtomicUsize::new(0),
        shutdown: watch::channel(false).0,
        active: Mutex::new(ActiveConnections::default()),
        workspace,
        agent_sessions,
        managed_sdk_prefix: paths.managed_sdk_prefix.clone(),
        managed_worker_entrypoint: paths.managed_worker_entrypoint.clone(),
        managed_sessions,
        codex_adoptions,
        managed_workers,
        host_info,
        uploads: crate::uploads::UploadStore::new(paths.state_dir.join("uploads")),
    });

    let listener = bind_control_socket(&paths).await?;
    let agent_listener = bind_agent_socket(&paths).await?;
    // Spec 017 §4.2: from here on, unrecognized vendor input is tallied durably. Before the
    // bind, notes land in memory and are merged in.
    crate::drift::bind(&paths.run_dir);
    // Spec 017 §4.3: the daemon both reads carry verdicts and runs first-contact checks.
    crate::codex_carry::bind(&paths, true);
    // Spec 007 §3.6: upload cleanup runs at daemon startup — catching partials orphaned by a
    // hard kill, which no connection teardown can clean — and then periodically.
    state.uploads.sweep();
    let monitor = tokio::spawn(monitor_home_relay(endpoint.clone(), state.clone()));
    let route_monitor = tokio::spawn(monitor_agent_routes(state.clone()));
    let upload_sweeper = tokio::spawn(sweep_uploads(state.clone()));
    let runtime_warmer = tokio::spawn(warm_managed_runtime(paths.clone()));
    // Spec 017 §4.4: while some vendor runs past this build's grounding, ask (at most daily)
    // whether a shipped release already grounds it. No drift, no fetch.
    let release_meta_poller = tokio::spawn(crate::release_meta::poll_loop(
        paths.clone(),
        crate::cli::DEFAULT_RELEASE_BASE.to_owned(),
    ));
    let mut iroh_task = tokio::spawn(serve_iroh(endpoint.clone(), state.clone()));
    let mut ipc_task = tokio::spawn(serve_ipc(listener, endpoint.clone(), state.clone()));
    let mut agent_ipc_task = tokio::spawn(serve_agent_ipc(agent_listener, state.clone()));

    tracing::info!(
        host = %short_endpoint_id(endpoint.id()),
        version = env!("CARGO_PKG_VERSION"),
        "Ciao daemon started"
    );
    // Presence/absence of this line answers "was RUST_LOG=debug set" for every future log
    // reader — the setenv is machine-local and reboot-losable, and the level is otherwise
    // undeterminable from the log itself.
    tracing::debug!("debug logging is on");
    let (result, iroh_finished, ipc_finished, agent_ipc_finished) = tokio::select! {
        result = &mut iroh_task => (
            result.unwrap_or_else(|_| Err(anyhow!("Iroh accept task stopped unexpectedly"))),
            true,
            false,
            false,
        ),
        result = &mut ipc_task => (
            result.unwrap_or_else(|_| Err(anyhow!("local IPC accept task stopped unexpectedly"))),
            false,
            true,
            false,
        ),
        result = &mut agent_ipc_task => (
            result.unwrap_or_else(|_| Err(anyhow!("agent bridge accept task stopped unexpectedly"))),
            false,
            false,
            true,
        ),
        () = shutdown_signal() => (Ok(()), false, false, false),
    };

    // Stop every normal connection with the stable shutdown code before closing the endpoint.
    // Terminal bridges observe either this connection close or the shutdown watch and run their
    // bounded process cleanup path before the accept task is joined.
    let _ = state.shutdown.send(true);
    let connections: Vec<_> = state.host_connections.lock().values().cloned().collect();
    for connection in connections {
        connection.close(
            VarInt::from_u32(crate::host_protocol::CONNECTION_SERVER_SHUTDOWN),
            b"daemon shutdown",
        );
    }

    endpoint.close().await;
    if !ipc_finished {
        ipc_task.abort();
        let _ = ipc_task.await;
    }
    if !agent_ipc_finished {
        agent_ipc_task.abort();
        let _ = agent_ipc_task.await;
    }
    if !iroh_finished
        && timeout(Duration::from_secs(6), &mut iroh_task)
            .await
            .is_err()
    {
        iroh_task.abort();
        let _ = iroh_task.await;
    }
    monitor.abort();
    let _ = monitor.await;
    route_monitor.abort();
    let _ = route_monitor.await;
    upload_sweeper.abort();
    let _ = upload_sweeper.await;
    runtime_warmer.abort();
    let _ = runtime_warmer.await;
    release_meta_poller.abort();
    let _ = release_meta_poller.await;
    remove_socket_if_present(&paths.socket_file)?;
    remove_socket_if_present(&paths.agent_socket_file)?;
    crate::drift::flush();
    tracing::info!("Ciao daemon stopped");
    result
}

async fn bind_control_socket(paths: &CiaoPaths) -> Result<UnixListener> {
    if paths.socket_file.exists() {
        if UnixStream::connect(&paths.socket_file).await.is_ok() {
            bail!(
                "another Ciao daemon is already listening at {}",
                paths.socket_file.display()
            );
        }
        remove_socket_if_present(&paths.socket_file)?;
    }
    let listener = UnixListener::bind(&paths.socket_file)
        .with_context(|| format!("bind Unix socket {}", paths.socket_file.display()))?;
    fs::set_permissions(&paths.socket_file, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("secure Unix socket {}", paths.socket_file.display()))?;
    Ok(listener)
}

async fn bind_agent_socket(paths: &CiaoPaths) -> Result<UnixListener> {
    if paths.agent_socket_file.exists() {
        if UnixStream::connect(&paths.agent_socket_file).await.is_ok() {
            bail!("another Ciao agent bridge listener is already active");
        }
        remove_socket_if_present(&paths.agent_socket_file)?;
    }
    let listener =
        UnixListener::bind(&paths.agent_socket_file).context("bind agent bridge socket")?;
    fs::set_permissions(&paths.agent_socket_file, fs::Permissions::from_mode(0o600))
        .context("secure agent bridge socket")?;
    Ok(listener)
}

async fn monitor_home_relay(endpoint: Endpoint, state: Arc<RuntimeState>) {
    let mut watcher = endpoint.home_relay_status();
    loop {
        let statuses = watcher.get();
        let online = statuses.iter().any(|status| status.is_connected());
        state.online.store(online, Ordering::Relaxed);
        if !statuses.is_empty() {
            state.relay_known.store(true, Ordering::Relaxed);
        }
        if watcher.updated().await.is_err() {
            state.online.store(false, Ordering::Relaxed);
            break;
        }
    }
}

async fn monitor_agent_routes(state: Arc<RuntimeState>) {
    let mut shutdown = state.shutdown.subscribe();
    // Route recovery runs on a multiple of this loop rather than every pass: a session with no
    // pane to find would otherwise shell out to a provider every second forever.
    let mut ticks: u32 = 0;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(AGENT_ROUTE_REVALIDATION_INTERVAL) => {
                state.agent_sessions.sweep_dead_sessions();
                state.agent_sessions.expire_stale_turn_claims();
                state.agent_sessions.revalidate_live_routes().await;
                ticks = ticks.wrapping_add(1);
                if ticks.is_multiple_of(AGENT_ROUTE_RECOVERY_TICKS) {
                    state.agent_sessions.recover_missing_routes().await;
                }
                // A worker that exited on its own becomes a truthful stored
                // session; a nonzero exit is reported as a crash.
                for (session_id, crashed) in state.managed_workers.reap() {
                    state.managed_sessions.record_worker_exit(&session_id, crashed);
                }
                // ADR 004 §5: exactly one owner per conversation. A terminal that resumed a
                // conversation Ciao is running is the second one, and the person is sitting at
                // it — so Ciao is the side that yields. Withdrawing here rather than at the
                // next command is the point: both processes append to one transcript, so every
                // turn taken while forked is damage already done.
                for session_id in state.managed_sessions.foreign_owned_live_sessions().await {
                    state.managed_workers.stop(&session_id).await;
                    // Recorded here rather than left to the next reap: the record has to
                    // reach `stored` before it can be marked, and a reap arriving first
                    // would settle it as an ordinary stop and lose the reason.
                    state.managed_sessions.record_worker_exit(&session_id, false);
                    state.managed_sessions.mark_externally_owned(&session_id);
                }
                refresh_live_activities(&state);
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

/// Snapshots both session owners and projects Spec 018's bounded facts, so notification delivery
/// receives one owned value rather than the owners themselves.
///
/// Composition belongs here because this is the layer that already holds both. `list()` and
/// `summaries()` each take and release their own lock and return owned rows, so nothing is held
/// while the notifier seals, posts, or backs off.
///
/// The interest check is what keeps a per-second sweep from projecting for nobody. It is a hint:
/// delivery re-reads the registrations itself, so losing the race in either direction costs at
/// most one sweep and never a wrong payload.
fn refresh_live_activities(state: &RuntimeState) {
    if !state.notifier.has_live_activity_interest() {
        return;
    }
    let overview = LiveActivityOverview::project(
        state.agent_sessions.list().sessions,
        state.managed_sessions.summaries(),
        &state.agent_sessions.ended_session_ids(),
    );
    state.notifier.refresh_live_activities(
        overview,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
}

/// The slash commands the agent in this pane would accept, or nothing.
///
/// Two gates, both of which have to pass before a CLI is spawned. The provider has to say a
/// Claude is in the pane — matched exactly, so a Codex or a Pi or a bare shell gets an empty
/// list rather than Claude's commands typed at something that cannot run them — and it has to
/// say where the pane is standing, because that directory decides which project and plugin
/// commands exist.
///
/// Empty covers every failure, and deliberately does not distinguish them. The phone's only
/// decision is whether to show a picker; "there is no agent here", "the runtime is not
/// installed", and "the probe timed out" all mean the same thing to that decision, and naming
/// which one would put the shape of the user's machine on the wire for no gain.
/// Every branch here returns the same empty list, so without a line naming which one ran, a
/// picker that never appears is indistinguishable from a request that never arrived. The
/// verdict is logged with the inputs that produced it; no path, prompt, or command name is ever
/// recorded — `has_cwd` and a count, never the directory or the list.
async fn terminal_slash_commands(
    state: &Arc<RuntimeState>,
    provider: crate::host_protocol::ProviderKind,
    session: &str,
) -> Vec<crate::slash_commands::SlashCommand> {
    let began = Instant::now();
    let facts = crate::workspace::pane_facts(&state.workspace, provider, session).await;
    let agent = facts.agent.clone();
    if agent.as_deref() != Some(crate::slash_commands::CLAUDE_AGENT) {
        tracing::info!(
            provider = provider.wire(),
            agent = agent.as_deref().unwrap_or("none"),
            "slash commands: pane holds no Claude"
        );
        return Vec::new();
    }
    let Some(cwd) = facts.cwd else {
        tracing::info!(
            provider = provider.wire(),
            "slash commands: the provider named no directory for this pane"
        );
        return Vec::new();
    };
    let commands = crate::slash_commands::commands_for(
        &state.managed_sdk_prefix,
        &state.managed_worker_entrypoint,
        std::path::Path::new(&cwd),
    )
    .await;
    tracing::info!(
        provider = provider.wire(),
        count = commands.len(),
        ms = began.elapsed().as_millis() as u64,
        "slash commands: answered"
    );
    commands
}

/// Verifies the pinned managed pair once, off the path of anything a user is waiting on.
///
/// `ManagedRuntime::resolve` hashes a ~257 MB binary and memoizes the verdict against the
/// file's identity for the life of the process. Whoever asks first pays it, and until now that
/// was always someone waiting: the first managed session start of a daemon's life, or
/// `ciao status`. Doing it here means the verdict is already cached before a phone can ask for
/// a slash-command list or a managed session, and a replaced binary still re-verifies because
/// the memo is keyed on its identity.
///
/// Budget for far worse than the idle number. Measured 14.1 s on an unloaded Mac and **150 s**
/// on the same Mac while a `cargo build --release` and an `xcodebuild` were running
/// (2026-08-20) — this is disk-bound and loses badly to whatever else is compiling. Callers
/// must treat a first answer as possibly minutes away rather than seconds; the phone's
/// slash-command fetch does, and retries instead of caching the timeout.
///
/// Silent by design. A machine without the runtime installed has nothing to warm, and this must
/// never be the thing that reports that.
async fn warm_managed_runtime(paths: CiaoPaths) {
    if !paths.managed_worker_entrypoint.is_file() {
        return;
    }
    // Blocking and long: hashing on a worker thread keeps it off the runtime's async threads,
    // where 14 s of CPU would stall the connections being accepted alongside it.
    let _ = tokio::task::spawn_blocking(move || {
        let began = std::time::Instant::now();
        let outcome = crate::managed_worker::ManagedRuntime::resolve(
            &paths.managed_sdk_prefix,
            &paths.managed_worker_entrypoint,
        );
        tracing::debug!(
            ms = began.elapsed().as_millis() as u64,
            verified = outcome.is_ok(),
            "managed runtime digest warmed"
        );
    })
    .await;
}

/// Periodic Spec 007 §3.6 upload cleanup, shaped like `monitor_agent_routes`: TTL for
/// partial/completed files and the global quota are host responsibilities the phone can never
/// be relied on to trigger.
async fn sweep_uploads(state: Arc<RuntimeState>) {
    let mut shutdown = state.shutdown.subscribe();
    loop {
        tokio::select! {
            _ = tokio::time::sleep(crate::uploads::UPLOAD_SWEEP_INTERVAL) => {
                state.uploads.sweep();
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

async fn serve_ipc(
    listener: UnixListener,
    endpoint: Endpoint,
    state: Arc<RuntimeState>,
) -> Result<()> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_IPC_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept local IPC connection")?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    continue;
                };
                let endpoint = endpoint.clone();
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_ipc(stream, endpoint, state).await {
                        tracing::warn!("local IPC request failed: {error}");
                    }
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!("local IPC task stopped unexpectedly: {error}");
                }
            }
        }
    }
}

async fn serve_agent_ipc(listener: UnixListener, state: Arc<RuntimeState>) -> Result<()> {
    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_IPC_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept agent bridge connection")?;
                let Ok(permit) = semaphore.clone().try_acquire_owned() else {
                    continue;
                };
                let state = state.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_agent_bridge(stream, state).await {
                        // Never include bridge frames or adapter errors in daemon logs. The
                        // reason is held back to DEBUG rather than dropped: discarding it left
                        // "a hook stopped being observed" and "a peer failed authentication"
                        // as the same line, which is not enough to act on. DEBUG is off unless
                        // RUST_LOG asks for it, so the default log is unchanged.
                        tracing::warn!(category = "bridge_protocol", "agent bridge connection ended");
                        tracing::debug!(
                            category = "bridge_protocol",
                            reason = %format!("{error:#}"),
                            "agent bridge failure detail"
                        );
                    }
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(_)) = completed {
                    tracing::warn!(category = "bridge_task", "agent bridge task stopped");
                }
            }
        }
    }
}

async fn handle_agent_bridge(stream: UnixStream, state: Arc<RuntimeState>) -> Result<()> {
    crate::agent_bridge::handle_agent_bridge(
        stream,
        state.agent_sessions.clone(),
        state.managed_workers.clone(),
        state.managed_sessions.clone(),
        state.codex_adoptions.clone(),
        state.notifier.clone(),
        state.shutdown.subscribe(),
    )
    .await
}

fn lifecycle_result(
    outcome: crate::agent_protocol::LifecycleOutcome,
) -> Result<Value, (&'static str, String)> {
    Ok(serde_json::json!({
        "state": outcome.state,
        "session_id": outcome.session_id,
        "process_generation": outcome.process_generation,
        "reason_code": outcome.reason_code,
    }))
}

async fn handle_ipc(
    mut stream: UnixStream,
    endpoint: Endpoint,
    state: Arc<RuntimeState>,
) -> Result<()> {
    let line = {
        let mut reader = BufReader::new(&mut stream);
        read_bounded_line(&mut reader).await
    };
    let line = match line {
        Ok(line) => line,
        Err(error) => {
            let response = error_response("unknown", error.code(), &error.safe_message());
            write_response(&mut stream, &response).await?;
            return Ok(());
        }
    };
    let request_id = extract_request_id(&line).unwrap_or_else(|| "unknown".into());
    let request = match parse_request(&line) {
        Ok(request) => request,
        Err(error) => {
            let response = error_response(&request_id, error.code(), &error.safe_message());
            write_response(&mut stream, &response).await?;
            return Ok(());
        }
    };

    let response = match process_ipc_operation(request.operation, &endpoint, &state).await {
        Ok(result) => success_response(&request.request_id, result),
        Err((code, message)) => error_response(&request.request_id, code, &message),
    };
    write_response(&mut stream, &response).await?;
    Ok(())
}

async fn process_ipc_operation(
    operation: IpcOperation,
    endpoint: &Endpoint,
    state: &Arc<RuntimeState>,
) -> Result<Value, (&'static str, String)> {
    match operation {
        IpcOperation::AgentSessions => {
            let rows: Vec<_> = state
                .managed_sessions
                .summaries()
                .into_iter()
                .map(|summary| {
                    serde_json::json!({
                        "session_id": summary.session_id,
                        "presence": summary.presence,
                        "stored_reason": summary.stored_reason,
                        "workspace_label": summary.workspace_label,
                        "process_generation": summary.process_generation,
                        "updated_at": summary.updated_at,
                        "topology": "managed",
                    })
                })
                .collect();
            // Attached sessions are listed alongside so `ciao agent promote` has something
            // to name. They are the operator's own terminals, not Ciao-owned workers, so
            // they carry no generation of ours and no stored reason.
            let mut rows = rows;
            rows.extend(state.agent_sessions.list().sessions.into_iter().filter_map(
                |descriptor| {
                    (descriptor.topology == "attached").then(|| {
                        serde_json::json!({
                            "session_id": descriptor.session_id,
                            "presence": descriptor.presence,
                            "stored_reason": Option::<String>::None,
                            "workspace_label": descriptor.workspace_display,
                            "process_generation": descriptor.process_generation,
                            "updated_at": descriptor.updated_at,
                            "topology": "attached",
                        })
                    })
                },
            ));
            Ok(Value::Array(rows))
        }
        IpcOperation::AgentStart { path } => {
            let command_id = format!("{:032x}", rand::random::<u128>());
            let outcome = state
                .managed_sessions
                .managed_start_at_path(std::path::Path::new(&path), &command_id)
                .await;
            lifecycle_result(outcome)
        }
        IpcOperation::AgentStop {
            session_id,
            expected_generation,
        } => {
            let command_id = format!("{:032x}", rand::random::<u128>());
            let outcome = state
                .managed_sessions
                .managed_stop(&session_id, expected_generation, &command_id)
                .await;
            lifecycle_result(outcome)
        }
        IpcOperation::AgentResume { session_id } => {
            let command_id = format!("{:032x}", rand::random::<u128>());
            let outcome = state
                .managed_sessions
                .managed_resume(&session_id, &command_id)
                .await;
            lifecycle_result(outcome)
        }
        IpcOperation::AgentPromote { session_id } => {
            // The attached supervisor owns the refusals that depend on the terminal:
            // whether the session exists, is Claude, ever prompted, and above all whether
            // its TUI is still running. Only then is a worker considered.
            let target = match state.agent_sessions.promotion_target(&session_id) {
                Ok(target) => target,
                Err(reason) => {
                    return lifecycle_result(crate::agent_protocol::LifecycleOutcome {
                        resume_command: None,
                        v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
                        command_id: format!("{:032x}", rand::random::<u128>()),
                        state: "refused".into(),
                        session_id: None,
                        process_generation: None,
                        reason_code: Some(reason.to_owned()),
                        deduplicated: None,
                    });
                }
            };
            let command_id = format!("{:032x}", rand::random::<u128>());
            // Taking over means the terminal lets go, and that is not reversible -- so every
            // refusal that can be decided without destroying anything is decided here, before
            // the exit request rather than inside `managed_promote` after it. Reaching a
            // `record_limit` or `already_live` from in there used to cost the owner a live
            // conversation for a promotion that never happened.
            if let Some(reason) = state.managed_sessions.promotion_preflight(&target).await {
                return lifecycle_result(crate::agent_protocol::LifecycleOutcome {
                    resume_command: None,
                    v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
                    command_id,
                    state: "refused".into(),
                    session_id: None,
                    process_generation: None,
                    reason_code: Some(reason.to_owned()),
                    deduplicated: None,
                });
            }
            // Read the transcript while the session it belongs to still exists. Closing the
            // terminal ends the observation, and the promoted session is a different session ID
            // with an empty timeline -- so without this the owner adopts a conversation and
            // watches its history vanish at the same moment.
            let inherited = state.agent_sessions.timeline_for_handover(&session_id);
            // What remains after the preflight is the launch, which can only be attempted once
            // there is somewhere to launch into.
            if !crate::process::request_exit(target.process_id).await {
                return lifecycle_result(crate::agent_protocol::LifecycleOutcome {
                    resume_command: None,
                    v: crate::agent_protocol::AGENT_PROTOCOL_VERSION,
                    command_id,
                    state: "refused".into(),
                    session_id: None,
                    process_generation: None,
                    reason_code: Some("terminal_owner_live".into()),
                    deduplicated: None,
                });
            }
            let sessions = state.agent_sessions.clone();
            let inherited = std::sync::Mutex::new(Some(inherited));
            let outcome = state
                .managed_sessions
                .managed_promote(&target, &command_id, &|promoted: &str| {
                    if let Some(history) = inherited.lock().ok().and_then(|mut h| h.take()) {
                        sessions.carry_history_into(promoted, history);
                    }
                })
                .await;
            lifecycle_result(outcome)
        }
        IpcOperation::AgentRelease { session_id } => {
            let command_id = format!("{:032x}", rand::random::<u128>());
            let (outcome, handback) = state
                .managed_sessions
                .managed_release(&session_id, &command_id)
                .await;
            // Same-user local socket only: the vendor session ID goes to the
            // host CLI so it can print the resume command, never to a device.
            let mut result = lifecycle_result(outcome)?;
            if let Some(object) = result.as_object_mut() {
                object.insert(
                    "vendor_session_id".into(),
                    serde_json::json!(handback.as_ref().map(|h| h.vendor_session_id.clone())),
                );
                object.insert(
                    "handback_session".into(),
                    serde_json::json!(handback.and_then(|h| h.route_session)),
                );
            }
            Ok(result)
        }
        IpcOperation::AgentForget { session_id } => {
            let command_id = format!("{:032x}", rand::random::<u128>());
            lifecycle_result(
                state
                    .managed_sessions
                    .managed_forget(&session_id, &command_id),
            )
        }
        IpcOperation::Unpair { endpoint_id } => {
            let removed = state
                .paired_devices
                .lock()
                .remove(&endpoint_id)
                .map_err(|error| ("unpair_failed", error.to_string()))?;
            if removed {
                // Every stream handler re-checks the allowlist, so nothing new can be started
                // over a surviving connection anyway. Closing is for the stream already running:
                // a live PTY would otherwise keep piping bytes to a device just revoked.
                let stale: Vec<_> = state
                    .host_connections
                    .lock()
                    .values()
                    .filter(|connection| connection.remote_id().to_string() == endpoint_id)
                    .cloned()
                    .collect();
                for connection in stale {
                    connection.close(
                        VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED),
                        b"device unpaired",
                    );
                }
                tracing::info!(remote = %&endpoint_id[..10], "unpaired a device");
            }
            Ok(serde_json::json!({ "removed": removed }))
        }
        IpcOperation::Status => serde_json::to_value(state.status()).map_err(|_| {
            (
                "internal_error",
                "Could not serialize daemon status.".into(),
            )
        }),
        IpcOperation::CreatePairing => {
            if !state.online.load(Ordering::Relaxed) {
                return Err((
                    "iroh_offline",
                    "Iroh is not online. Check the network and daemon log, then retry.".into(),
                ));
            }
            // Direct addresses are ephemeral, privacy-sensitive, and make the QR much larger.
            // A relay address is sufficient for Iroh to connect and negotiate a direct path.
            let ticket = relay_only_pairing_ticket(endpoint.addr()).ok_or_else(|| {
                (
                    "iroh_offline",
                    "Iroh has no connected Number 0 relay address yet. Retry shortly.".into(),
                )
            })?;
            let now = unix_now().map_err(|message| ("internal_error", message))?;
            let offer = state
                .pairing
                .lock()
                .create(now)
                .map_err(|error| (error.code(), error.safe_message().into()))?;
            let qr_uri = match encode_pairing_uri(
                &ticket,
                &offer.pairing_id,
                &offer.capability,
                offer.expires_at,
            ) {
                Ok(uri) => uri,
                Err(_) => {
                    state
                        .pairing
                        .lock()
                        .reject_current("Could not encode this pairing offer.");
                    return Err((
                        "internal_error",
                        "Could not create the pairing QR. Retry with `ciao pair`.".into(),
                    ));
                }
            };
            serde_json::to_value(CreatePairingResult {
                pairing_id: encoded_pairing_id(&offer.pairing_id),
                qr_uri,
                expires_at: offer.expires_at,
            })
            .map_err(|_| {
                (
                    "internal_error",
                    "Could not serialize pairing offer.".into(),
                )
            })
        }
        IpcOperation::PairingStatus { pairing_id } => {
            let now = unix_now().map_err(|message| ("internal_error", message))?;
            serde_json::to_value(state.pairing.lock().status(&pairing_id, now)).map_err(|_| {
                (
                    "internal_error",
                    "Could not serialize pairing status.".into(),
                )
            })
        }
    }
}

fn relay_only_pairing_ticket(endpoint_addr: EndpointAddr) -> Option<EndpointTicket> {
    let id = endpoint_addr.id;
    let relay_addrs = endpoint_addr
        .addrs
        .into_iter()
        .filter(TransportAddr::is_relay);
    let relay_only = EndpointAddr::from_parts(id, relay_addrs);
    (!relay_only.is_empty()).then(|| EndpointTicket::new(relay_only))
}

fn extract_request_id(line: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(line)
        .ok()?
        .get("request_id")?
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
}

async fn serve_iroh(endpoint: Endpoint, state: Arc<RuntimeState>) -> Result<()> {
    let pending_handshakes = Arc::new(tokio::sync::Semaphore::new(MAX_PENDING_HANDSHAKES));
    let mut tasks = JoinSet::new();
    'accept: loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break 'accept;
                };
                let Ok(permit) = pending_handshakes.clone().try_acquire_owned() else {
                    // Dropping an unaccepted handshake is the bounded overload behavior. No
                    // application bytes or endpoint addressing details are inspected or logged.
                    continue;
                };
                let state = state.clone();
                tasks.spawn(async move {
                    let began = std::time::Instant::now();
                    let handshake = timeout(HANDSHAKE_TIMEOUT, incoming).await;
                    drop(permit);
                    match handshake {
                        Ok(Ok(connection)) => handle_authenticated_connection(connection, state).await,
                        // Upstream handshake errors can include addressing diagnostics. Keep the
                        // log event categorical: the variant name never carries addressing or
                        // peer bytes, while Display strings can.
                        Ok(Err(error)) => {
                            let kind = match &error {
                                ConnectingError::ConnectionError { source, .. } => match source {
                                    ConnectionError::VersionMismatch => "version-mismatch",
                                    ConnectionError::TransportError(_) => "transport",
                                    ConnectionError::ConnectionClosed(_) => "connection-closed",
                                    ConnectionError::ApplicationClosed(_) => "application-closed",
                                    ConnectionError::Reset => "reset",
                                    ConnectionError::TimedOut => "timed-out",
                                    ConnectionError::LocallyClosed => "locally-closed",
                                    ConnectionError::CidsExhausted => "cids-exhausted",
                                },
                                ConnectingError::HandshakeFailure { .. } => "authentication",
                                ConnectingError::InternalConsistencyError { .. } => "internal",
                                ConnectingError::LocallyRejected { .. } => "locally-rejected",
                                _ => "other",
                            };
                            tracing::warn!(
                                kind,
                                ms = began.elapsed().as_millis() as u64,
                                "Iroh handshake failed"
                            );
                        }
                        Err(_) => tracing::warn!(
                            ms = began.elapsed().as_millis() as u64,
                            "Iroh handshake timed out"
                        ),
                    }
                });
            }
            completed = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(error)) = completed {
                    tracing::warn!("Iroh connection task stopped unexpectedly: {error}");
                }
            }
        }
    }
    while let Some(completed) = tasks.join_next().await {
        if let Err(error) = completed {
            tracing::warn!("Iroh connection task stopped unexpectedly: {error}");
        }
    }
    Ok(())
}

async fn handle_authenticated_connection(connection: Connection, state: Arc<RuntimeState>) {
    match connection.alpn() {
        PAIRING_ALPN => {
            let Some(_lease) = PairingConnectionLease::try_new(state.clone()) else {
                connection.close(VarInt::from_u32(CONNECTION_BUSY), b"host busy");
                return;
            };
            handle_pairing_connection(connection, state).await;
        }
        HOST_ALPN => handle_host_connection(connection, state).await,
        _ => connection.close(
            VarInt::from_u32(CONNECTION_PROTOCOL_VIOLATION),
            b"host protocol violation",
        ),
    }
}

/// The phone's ConnectTrace `flow` line, host-side (2026-08-11, Spec 014 rider): one DEBUG
/// line per five seconds per live connection with byte deltas, loss, rtt, and the selected
/// path class, plus an INFO line when the class changes. The phone half adjudicated every
/// stall to date alone; a blackhole's *direction* — downlink dead while this side still
/// transmits, or silent both ways — needs this half. Polled at the flow cadence, so a
/// sub-five-second flap can hide between lines; `path_events` would catch those, at the
/// price of a stream consumer per connection this diagnostic does not yet need.
async fn monitor_host_connection_flow(connection: Connection, remote_id: EndpointId) {
    // Sampled every second for `PathProbeWatch`; the DEBUG flow line keeps its 5 s cadence.
    const FLOW_LINE_EVERY: u32 = 5;
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_rx: u64 = 0;
    let mut last_tx: u64 = 0;
    let mut last_class = "";
    let mut watch = PathProbeWatch::default();
    let mut heard = PathRxWatch::default();
    let mut tick: u32 = 0;
    loop {
        ticker.tick().await;
        tick = tick.wrapping_add(1);
        let mut rx: u64 = 0;
        let mut tx: u64 = 0;
        let mut lost: u64 = 0;
        let mut rtt_ms = None;
        let mut class = "none";
        let mut selected = None;
        let now = std::time::Instant::now();
        let paths = connection.paths();
        for path in paths.iter() {
            let stats = path.stats();
            rx = rx.saturating_add(stats.udp_rx.bytes);
            tx = tx.saturating_add(stats.udp_tx.bytes);
            lost = lost.saturating_add(stats.lost_packets);
            if path.is_selected() {
                rtt_ms = Some(path.rtt().as_millis());
                class = if path.is_relay() {
                    "relayed"
                } else if path.is_ip() {
                    "direct"
                } else {
                    "unknown"
                };
                selected = Some((path.id(), stats.pto_count));
            }
            heard.note(now, path.id(), stats.udp_rx.datagrams);
        }
        // Somewhere to go, and the one-way signature: another path open, and the phone still
        // heard on this one since it stopped answering.
        if let Some((id, pto_count)) = selected
            && paths.len() >= 2
            && let Some((silent, answered_at)) = watch.observe(now, id, pto_count)
            && heard.heard_on_since(id, answered_at + PathProbeWatch::HEARD_SLACK)
        {
            let outcome = paths
                .get(id)
                .map(|path| path.close().map_err(|error| format!("{error:?}")));
            tracing::info!(
                remote = %short_endpoint_id(remote_id),
                path = class,
                unanswered_ms = silent.as_millis() as u64,
                closed = ?outcome,
                "path abandoned: probes unanswered while another path is open"
            );
            watch = PathProbeWatch::default();
        }
        if !last_class.is_empty() && class != last_class {
            tracing::info!(
                remote = %short_endpoint_id(remote_id),
                from = last_class,
                to = class,
                "path migrated"
            );
        }
        last_class = class;
        if !tick.is_multiple_of(FLOW_LINE_EVERY) {
            continue;
        }
        // Per-path sums go backwards when a path closes; a fresh baseline under-reports one
        // line rather than printing an astronomical wrapped delta (the app's flow line
        // learned this first).
        let rx_delta = if rx >= last_rx { rx - last_rx } else { rx };
        let tx_delta = if tx >= last_tx { tx - last_tx } else { tx };
        last_rx = rx;
        last_tx = tx;
        tracing::debug!(
            remote = %short_endpoint_id(remote_id),
            path = class,
            rtt_ms = %rtt_ms.map(|ms| ms.to_string()).unwrap_or_else(|| "-".into()),
            rx = rx_delta,
            tx = tx_delta,
            lost,
            "flow"
        );
    }
}

async fn handle_host_connection(connection: Connection, state: Arc<RuntimeState>) {
    let remote_id = connection.remote_id();
    // This is deliberately the first host-protocol operation after the authenticated Iroh
    // handshake. In particular, no stream is accepted and no preface/RPC/PTTY byte is decoded
    // before this local allowlist lookup succeeds.
    if !state.paired_devices.lock().contains(remote_id) {
        connection.close(
            VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED),
            b"authorization denied",
        );
        return;
    }
    let Some(_connection_lease) =
        NormalConnectionLease::try_new(state.clone(), remote_id, &connection)
    else {
        connection.close(VarInt::from_u32(CONNECTION_BUSY), b"host busy");
        return;
    };

    // Open/close are logged as a pair with duration and a categorical close reason — the
    // 2026-08-04 connection-resilience audit found reconnect behaviour unobservable host-side.
    let opened_at = Instant::now();
    tracing::info!(remote = %short_endpoint_id(remote_id), "host connection opened");
    let flow_monitor = tokio::spawn(monitor_host_connection_flow(connection.clone(), remote_id));
    let result = handle_host_session(&connection, remote_id, state).await;
    flow_monitor.abort();
    let reason = match &result {
        Ok(()) => close_reason_category(connection.close_reason()),
        Err(error) => host_error_category(error).to_string(),
    };
    if let Err(error) = result {
        tracing::warn!(
            remote = %short_endpoint_id(remote_id),
            category = host_error_category(&error),
            "host connection ended"
        );
    }
    tracing::info!(
        remote = %short_endpoint_id(remote_id),
        reason = %reason,
        seconds = opened_at.elapsed().as_secs(),
        "host connection closed"
    );
    connection.close(0_u32.into(), b"ciao host closed");
}

/// Categorical only — close reasons can carry peer-supplied bytes, and the default log posture
/// is redacted. Application close codes are Ciao's own protocol constants, so the number is safe.
fn close_reason_category(reason: Option<ConnectionError>) -> String {
    match reason {
        None => "host-closed".into(),
        Some(ConnectionError::TimedOut) => "idle-timeout".into(),
        Some(ConnectionError::ApplicationClosed(close)) => {
            format!("peer-code-{}", close.error_code)
        }
        Some(ConnectionError::ConnectionClosed(_)) => "transport-close".into(),
        Some(ConnectionError::LocallyClosed) => "locally-closed".into(),
        Some(ConnectionError::Reset) => "reset".into(),
        Some(ConnectionError::TransportError(_)) => "transport-error".into(),
        Some(ConnectionError::VersionMismatch) => "version-mismatch".into(),
        Some(ConnectionError::CidsExhausted) => "cids-exhausted".into(),
    }
}

async fn handle_host_session(
    connection: &Connection,
    remote_id: EndpointId,
    state: Arc<RuntimeState>,
) -> Result<()> {
    // Phase A — `host.hello` must be the first successful RPC on the connection. Known non-hello
    // methods before hello are answered with `not_ready`/`method_unknown` on their own stream
    // without closing the connection; malformed requests still fail the connection closed.
    let accepted_at = Instant::now();
    let mut pre_hello_streams = 0_usize;
    loop {
        if pre_hello_streams >= MAX_PRE_HELLO_STREAMS {
            connection.close(
                VarInt::from_u32(CONNECTION_PROTOCOL_VIOLATION),
                b"host protocol violation",
            );
            return Err(HostProtocolError::UnexpectedOrder.into());
        }
        pre_hello_streams += 1;
        let (mut send, mut recv) = timeout(HOST_OPERATION_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| anyhow!("host hello stream timed out"))??;
        state.decoded_host_prefaces.fetch_add(1, Ordering::Relaxed);
        let kind = match read_stream_preface_with_timeout(
            &mut recv,
            crate::host_protocol::STREAM_PREFACE_TIMEOUT,
        )
        .await
        {
            Ok(kind) => kind,
            Err(error) => {
                reset_stream(&mut send, &mut recv, host_stream_reset_code(&error));
                return Err(error.into());
            }
        };
        if kind != StreamKind::Rpc {
            // Any non-RPC stream (terminal, agent, upload) before a successful hello fails
            // the connection closed.
            reset_stream(&mut send, &mut recv, STREAM_UNEXPECTED);
            return Err(HostProtocolError::UnexpectedOrder.into());
        }
        match hello_phase_rpc(&mut send, &mut recv, remote_id, &state).await? {
            HelloPhaseOutcome::HelloDone => break,
            HelloPhaseOutcome::KeepWaiting => {}
        }
    }
    tracing::info!(
        remote = %short_endpoint_id(remote_id),
        ms = accepted_at.elapsed().as_millis() as u64,
        "host hello done"
    );

    // A normal connection becomes active only after a valid hello response is committed. The
    // shared active map deduplicates overlap with a still-draining pairing heartbeat connection.
    let _active_lease = ActiveLease::new(state.clone(), remote_id);

    // Phase B — RPC, Agent Session, and terminal streams have independent tasks/flow control.
    // The app owns at most one subscription; bounded one-shot Agent requests may coexist. One
    // terminal can be active per connection. The terminal
    // ending retains the accepted Phase 1 behavior of ending this disposable connection; an Agent
    // screen reconnects and starts from a complete snapshot.
    let snapshot_busy = Arc::new(tokio::sync::Mutex::new(()));
    let terminal_active = Arc::new(AtomicBool::new(false));
    let upload_gate = crate::uploads::UploadGate::default();
    let forward_gate = Arc::new(tokio::sync::Semaphore::new(MAX_FORWARD_STREAMS));
    let (terminal_done_sender, mut terminal_done_receiver) = tokio::sync::mpsc::unbounded_channel();
    let mut stream_tasks: JoinSet<()> = JoinSet::new();
    let mut shutdown = state.shutdown.subscribe();
    let result = loop {
        tokio::select! {
            accepted = connection.accept_bi() => {
                let Ok((mut send, mut recv)) = accepted else {
                    break Ok(());
                };
                state.decoded_host_prefaces.fetch_add(1, Ordering::Relaxed);
                let kind = match read_stream_preface_with_timeout(
                    &mut recv,
                    crate::host_protocol::STREAM_PREFACE_TIMEOUT,
                )
                .await
                {
                    Ok(kind) => kind,
                    Err(error) => {
                        reset_stream(&mut send, &mut recv, host_stream_reset_code(&error));
                        continue;
                    }
                };
                match kind {
                    StreamKind::Rpc => {
                        let state = state.clone();
                        let snapshot_busy = snapshot_busy.clone();
                        stream_tasks.spawn(async move {
                            let _ = ready_phase_rpc(
                                &mut send,
                                &mut recv,
                                remote_id,
                                &state,
                                &snapshot_busy,
                            )
                            .await;
                        });
                    }
                    StreamKind::Agent => {
                        let state = state.clone();
                        let connection = connection.clone();
                        stream_tasks.spawn(async move {
                            let _ = handle_agent_stream(
                                &connection,
                                &mut send,
                                &mut recv,
                                remote_id,
                                state,
                            )
                            .await;
                        });
                    }
                    StreamKind::Upload => {
                        // One active upload per connection (Spec 007 §3.5), gated with the
                        // same swap idiom as the terminal singleton below — but the loser is
                        // told `busy` in-protocol on its own stream rather than bare-reset,
                        // because the frozen upload format names that outcome.
                        let Some(lease) = upload_gate.try_acquire() else {
                            stream_tasks.spawn(async move {
                                let _ = crate::uploads::send_put_error(
                                    &mut send,
                                    crate::uploads::UploadErrorCode::Busy,
                                    "Another upload is already in progress.",
                                )
                                .await;
                                finish_upload_stream(&mut send, &mut recv).await;
                            });
                            continue;
                        };
                        let state = state.clone();
                        stream_tasks.spawn(async move {
                            let _lease = lease;
                            handle_upload_stream(&mut send, &mut recv, remote_id, state).await;
                        });
                    }
                    StreamKind::Download => {
                        // No gate and no lease: a preview is bounded at 16 MiB, streams from a
                        // 16 KiB buffer, and QUIC already caps this connection at 8 concurrent
                        // bidi streams. A counter on top of that limit would guard nothing.
                        let state = state.clone();
                        stream_tasks.spawn(async move {
                            handle_download_stream(&mut send, &mut recv, remote_id, state).await;
                        });
                    }
                    StreamKind::Forward => {
                        // Spec-less by design (see `crate::forward`): the pairing is the trust
                        // boundary, so the only thing enforced here is the stream count. The
                        // permit is held for the life of the copy, and a browser over quota is
                        // told so rather than left waiting on a QUIC credit the terminal needs.
                        let Ok(permit) = forward_gate.clone().try_acquire_owned() else {
                            reset_stream(&mut send, &mut recv, STREAM_FORWARD_LIMIT);
                            continue;
                        };
                        stream_tasks.spawn(async move {
                            let _permit = permit;
                            if let Err(error) = crate::forward::forward(&mut send, &mut recv).await
                            {
                                // Ordinary: the dev server was not running, or the browser hung
                                // up mid-response. The app turns a reset into a closed local
                                // socket, which is the browser's own error page.
                                tracing::debug!(%error, "forward stream ended");
                                reset_stream(&mut send, &mut recv, STREAM_INTERNAL);
                            }
                        });
                    }
                    StreamKind::Terminal => {
                        if terminal_active.swap(true, Ordering::AcqRel) {
                            reset_stream(&mut send, &mut recv, STREAM_TERMINAL_LIMIT);
                            continue;
                        }
                        let state = state.clone();
                        let connection = connection.clone();
                        let done = terminal_done_sender.clone();
                        let active = terminal_active.clone();
                        stream_tasks.spawn(async move {
                            let result = handle_terminal_stream(
                                &connection,
                                &mut send,
                                &mut recv,
                                remote_id,
                                state,
                            )
                            .await;
                            active.store(false, Ordering::Release);
                            let _ = done.send(result);
                        });
                    }
                }
            }
            Some(result) = terminal_done_receiver.recv() => break result,
            Some(_) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {}
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    connection.close(
                        VarInt::from_u32(crate::host_protocol::CONNECTION_SERVER_SHUTDOWN),
                        b"daemon shutdown",
                    );
                }
                break Ok(());
            }
        }
    };
    stream_tasks.abort_all();
    while stream_tasks.join_next().await.is_some() {}
    result
}

enum HelloPhaseOutcome {
    HelloDone,
    KeepWaiting,
}

async fn hello_phase_rpc(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    remote_id: EndpointId,
    state: &Arc<RuntimeState>,
) -> Result<HelloPhaseOutcome> {
    let body = match timeout(HOST_OPERATION_TIMEOUT, read_rpc_body(recv)).await {
        Err(_) => {
            reset_stream(send, recv, STREAM_MALFORMED);
            return Err(anyhow!("host hello body timed out"));
        }
        Ok(Err(error)) => {
            reset_stream(send, recv, host_stream_reset_code(&error));
            return Err(error.into());
        }
        Ok(Ok(body)) => body,
    };
    match decode_rpc_request(&body) {
        Ok(RpcRequest::Hello(request)) => {
            require_finished_request(send, recv, Some(request.request_id.clone())).await?;
            send_host_hello(send, &request, remote_id, state.host_endpoint_id).await?;
            let _ = send.finish();
            Ok(HelloPhaseOutcome::HelloDone)
        }
        Ok(RpcRequest::HostInfo(request)) => {
            send_rpc_error_code(
                send,
                Some(request.request_id),
                "not_ready",
                "The Ciao host connection is not ready for this request.",
            )
            .await;
            let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
            Ok(HelloPhaseOutcome::KeepWaiting)
        }
        Ok(RpcRequest::WorkspaceSnapshot(request)) => {
            send_rpc_error_code(
                send,
                Some(request.request_id),
                "not_ready",
                "The Ciao host connection is not ready for this request.",
            )
            .await;
            let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
            Ok(HelloPhaseOutcome::KeepWaiting)
        }
        Ok(RpcRequest::NotificationsRegister(request)) => {
            send_rpc_error_code(
                send,
                Some(request.request_id),
                "not_ready",
                "The Ciao host connection is not ready for this request.",
            )
            .await;
            let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
            Ok(HelloPhaseOutcome::KeepWaiting)
        }
        Ok(RpcRequest::TerminalCommands(request)) => {
            send_rpc_error_code(
                send,
                Some(request.request_id),
                "not_ready",
                "The Ciao host connection is not ready for this request.",
            )
            .await;
            let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
            Ok(HelloPhaseOutcome::KeepWaiting)
        }
        Ok(RpcRequest::LiveActivityRegister(request)) => {
            send_rpc_error_code(
                send,
                Some(request.request_id),
                "not_ready",
                "The Ciao host connection is not ready for this request.",
            )
            .await;
            let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
            Ok(HelloPhaseOutcome::KeepWaiting)
        }
        Err(HostProtocolError::UnsupportedMethod) => {
            send_rpc_error_code(
                send,
                valid_rpc_request_id(&body),
                "method_unknown",
                "This Ciao host method is not supported.",
            )
            .await;
            let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
            Ok(HelloPhaseOutcome::KeepWaiting)
        }
        Err(error) => {
            send_host_rpc_error(send, valid_rpc_request_id(&body), &error).await;
            let _ = recv.stop(VarInt::from_u32(host_stream_reset_code(&error)));
            Err(error.into())
        }
    }
}

/// Handles one post-hello RPC stream. Errors here are stream-scoped: the stream is answered or
/// reset, and the connection continues serving the picker and terminal.
async fn ready_phase_rpc(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    remote_id: EndpointId,
    state: &Arc<RuntimeState>,
    snapshot_busy: &Arc<tokio::sync::Mutex<()>>,
) -> Result<()> {
    let body = match timeout(HOST_OPERATION_TIMEOUT, read_rpc_body(recv)).await {
        Err(_) => {
            reset_stream(send, recv, STREAM_MALFORMED);
            return Ok(());
        }
        Ok(Err(error)) => {
            reset_stream(send, recv, host_stream_reset_code(&error));
            return Ok(());
        }
        Ok(Ok(body)) => body,
    };
    match decode_rpc_request(&body) {
        Ok(RpcRequest::Hello(request)) => {
            // A repeated hello after readiness is answered idempotently.
            if require_finished_request(send, recv, Some(request.request_id.clone()))
                .await
                .is_err()
            {
                return Ok(());
            }
            let response = HostHelloResponse::new(
                request.request_id.clone(),
                state.host_endpoint_id.to_string(),
                remote_id.to_string(),
            );
            let _ = write_rpc(send, &response).await;
            finish_rpc_send(send).await;
        }
        Ok(RpcRequest::HostInfo(request)) => {
            if require_finished_request(send, recv, Some(request.request_id.clone()))
                .await
                .is_err()
            {
                return Ok(());
            }
            // Display metadata is available only after hello and an immediate authoritative
            // allowlist recheck. It remains presentation data and never becomes authority.
            if !state.paired_devices.lock().contains(remote_id) {
                send_rpc_error_code(
                    send,
                    Some(request.request_id),
                    "authorization_denied",
                    "This installation is no longer authorized.",
                )
                .await;
                return Ok(());
            }
            let response = HostInfoResponse::new(request.request_id, state.host_info.clone());
            let _ = write_rpc(send, &response).await;
            finish_rpc_send(send).await;
        }
        Ok(RpcRequest::WorkspaceSnapshot(request)) => {
            if require_finished_request(send, recv, Some(request.request_id.clone()))
                .await
                .is_err()
            {
                return Ok(());
            }
            // Repeat the authoritative local authorization check immediately before executing
            // either provider. This mirrors the terminal pre-spawn check and closes the same
            // future revocation race without exposing any provider output.
            if !state.paired_devices.lock().contains(remote_id) {
                send_rpc_error_code(
                    send,
                    Some(request.request_id),
                    "authorization_denied",
                    "This installation is no longer authorized.",
                )
                .await;
                return Ok(());
            }
            // Snapshot execution is serialized per connection: a second request while one is
            // in flight is answered `busy` immediately rather than queued.
            match snapshot_busy.try_lock() {
                Err(_) => {
                    send_rpc_error_code(
                        send,
                        Some(request.request_id),
                        "busy",
                        "A workspace snapshot is already in progress.",
                    )
                    .await;
                }
                Ok(_guard) => {
                    let capture_began = Instant::now();
                    let result = capture_snapshot(
                        &state.workspace,
                        request
                            .params
                            .tabs
                            .then(|| state.agent_sessions.agent_tabs())
                            .as_ref(),
                    )
                    .await;
                    tracing::debug!(
                        remote = %short_endpoint_id(remote_id),
                        ms = capture_began.elapsed().as_millis() as u64,
                        "workspace snapshot captured"
                    );
                    let response =
                        WorkspaceSnapshotResponse::new(request.request_id.clone(), result);
                    match encode_snapshot_response_bounded(response) {
                        Ok((encoded, _)) => {
                            let _ = send.write_all(&encoded).await;
                            finish_rpc_send(send).await;
                        }
                        Err(_) => {
                            send_rpc_error_code(
                                send,
                                Some(request.request_id),
                                "internal_error",
                                "The Mac could not encode the workspace snapshot.",
                            )
                            .await;
                        }
                    }
                }
            }
        }
        Ok(RpcRequest::TerminalCommands(request)) => {
            if require_finished_request(send, recv, Some(request.request_id.clone()))
                .await
                .is_err()
            {
                return Ok(());
            }
            // The same authoritative recheck the snapshot does, for the same reason: this
            // executes a provider and then a vendor CLI, and a device revoked since hello must
            // reach neither.
            if !state.paired_devices.lock().contains(remote_id) {
                send_rpc_error_code(
                    send,
                    Some(request.request_id),
                    "authorization_denied",
                    "This installation is no longer authorized.",
                )
                .await;
                return Ok(());
            }
            let Ok(provider) = request.validated_provider() else {
                tracing::info!(
                    target = %request.params.target,
                    "slash commands: refused, that target names no multiplexer"
                );
                send_rpc_error_code(
                    send,
                    Some(request.request_id),
                    "unsupported_target",
                    "That terminal has no multiplexer to ask.",
                )
                .await;
                return Ok(());
            };
            let commands = terminal_slash_commands(state, provider, &request.params.session).await;
            let offered = commands.len();
            let response = TerminalCommandsResponse::new(request.request_id.clone(), commands);
            match encode_terminal_commands_response_bounded(response) {
                Ok((encoded, bounded)) => {
                    // What the phone will actually show, not what the probe found. The two
                    // differed silently until 2026-08-20: a full surface does not fit in one
                    // frame, `write_rpc`'s error was discarded here, and "answered count=138"
                    // above was the last thing anyone logged before the picker did not appear.
                    let sent = bounded.result.commands.len();
                    if sent != offered {
                        tracing::info!(offered, sent, "slash commands: trimmed to fit one frame");
                    }
                    let _ = send.write_all(&encoded).await;
                    finish_rpc_send(send).await;
                }
                Err(_) => {
                    send_rpc_error_code(
                        send,
                        Some(request.request_id),
                        "internal_error",
                        "The Mac could not encode the command list.",
                    )
                    .await;
                }
            }
        }
        Ok(RpcRequest::NotificationsRegister(request)) => {
            if require_finished_request(send, recv, Some(request.request_id.clone()))
                .await
                .is_err()
            {
                return Ok(());
            }
            // Same authoritative recheck as every other post-hello method: a device removed from
            // the allowlist must not be able to leave a ticket behind on its way out.
            let stored = {
                let mut devices = state.paired_devices.lock();
                if !devices.contains(remote_id) {
                    None
                } else {
                    Some(devices.set_push_ticket(remote_id, request.params.ticket.as_deref()))
                }
            };
            match stored {
                None => {
                    send_rpc_error_code(
                        send,
                        Some(request.request_id),
                        "authorization_denied",
                        "This installation is no longer authorized.",
                    )
                    .await;
                }
                Some(Err(error)) => {
                    // The ticket itself is never logged: it is a bearer credential for reaching
                    // that phone, and the daemon log is not the place for one.
                    tracing::warn!(error = %error, "storing a push ticket failed");
                    send_rpc_error_code(
                        send,
                        Some(request.request_id),
                        "internal_error",
                        "The Mac could not store the notification ticket.",
                    )
                    .await;
                }
                Some(Ok(())) => {
                    // The ticket itself never appears here — it is a bearer credential for
                    // reaching that phone. Whether one arrived is the diagnosable part.
                    tracing::info!(
                        remote = %short_endpoint_id(remote_id),
                        registered = request.params.ticket.is_some(),
                        "push ticket registration"
                    );
                    let response = NotificationsRegisterResponse::new(
                        request.request_id,
                        request.params.ticket.is_some(),
                    );
                    let _ = write_rpc(send, &response).await;
                    finish_rpc_send(send).await;
                }
            }
        }
        Ok(RpcRequest::LiveActivityRegister(request)) => {
            if require_finished_request(send, recv, Some(request.request_id.clone()))
                .await
                .is_err()
            {
                return Ok(());
            }
            // Recheck before even resolving an opaque ID: after revocation, whether a session
            // exists is no longer this endpoint's fact to probe. The store repeats the check
            // immediately before persistence to close a revocation race during resolution.
            if !state.paired_devices.lock().contains(remote_id) {
                send_rpc_error_code(
                    send,
                    Some(request.request_id),
                    "authorization_denied",
                    "This installation is no longer authorized.",
                )
                .await;
                return Ok(());
            }
            // An enabling phone sends only an opaque session ID. Labels remain host-authored:
            // accepting display text here would let a paired client smuggle arbitrary content
            // into ActivityKit under the host's encryption key.
            let change = match request.params.selection {
                Some(selection) if selection.enabled => {
                    let descriptor =
                        state
                            .agent_sessions
                            .list()
                            .sessions
                            .into_iter()
                            .find(|descriptor| {
                                descriptor.session_id == selection.session_id
                                    && descriptor.presence == "live"
                            });
                    let Some(descriptor) = descriptor else {
                        send_rpc_error_code(
                            send,
                            Some(request.request_id),
                            "session_unavailable",
                            "This Agent Session is no longer live.",
                        )
                        .await;
                        return Ok(());
                    };
                    Some(LiveActivitySelectionChange::Add(LiveActivitySelection {
                        session_id: descriptor.session_id,
                        // Adapter families are canonical ASCII tokens. Truncate without a
                        // Unicode marker so the persisted conservative-ASCII invariant remains
                        // true even for a future family at the 64-byte canonical bound.
                        adapter: descriptor.adapter_family.chars().take(32).collect(),
                        workspace: bounded_activity_label(&descriptor.workspace_display, 64),
                    }))
                }
                Some(selection) => Some(LiveActivitySelectionChange::Remove(selection.session_id)),
                None => None,
            };
            let stored = {
                let mut devices = state.paired_devices.lock();
                if !devices.contains(remote_id) {
                    None
                } else {
                    Some(devices.update_live_activity(
                        remote_id,
                        request.params.ticket.as_deref(),
                        change,
                    ))
                }
            };
            match stored {
                None => {
                    send_rpc_error_code(
                        send,
                        Some(request.request_id),
                        "authorization_denied",
                        "This installation is no longer authorized.",
                    )
                    .await;
                }
                Some(Err(error)) => {
                    tracing::warn!(error = %error, "storing a live activity registration failed");
                    send_rpc_error_code(
                        send,
                        Some(request.request_id),
                        "registration_failed",
                        "The Mac could not update this Live Activity.",
                    )
                    .await;
                }
                Some(Ok(selected)) => {
                    tracing::info!(
                        remote = %short_endpoint_id(remote_id),
                        registered = selected > 0,
                        selected,
                        "live activity registration"
                    );
                    refresh_live_activities(state);
                    let response = LiveActivityRegisterResponse::new(request.request_id, selected);
                    let _ = write_rpc(send, &response).await;
                    finish_rpc_send(send).await;
                }
            }
        }
        Err(HostProtocolError::UnsupportedMethod) => {
            send_rpc_error_code(
                send,
                valid_rpc_request_id(&body),
                "method_unknown",
                "This Ciao host method is not supported.",
            )
            .await;
            let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
        }
        Err(error) => {
            send_host_rpc_error(send, valid_rpc_request_id(&body), &error).await;
            let _ = recv.stop(VarInt::from_u32(host_stream_reset_code(&error)));
        }
    }
    Ok(())
}

/// Enforces the one-request-per-stream rule by requiring the client to have finished its send
/// side after exactly one request body.
async fn require_finished_request(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    request_id: Option<String>,
) -> Result<()> {
    let mut trailing = [0_u8; 1];
    match timeout(HOST_OPERATION_TIMEOUT, recv.read(&mut trailing)).await {
        Ok(Ok(None)) => Ok(()),
        Ok(Ok(Some(_))) => {
            let error = HostProtocolError::UnexpectedOrder;
            send_host_rpc_error(send, request_id, &error).await;
            let _ = recv.stop(VarInt::from_u32(STREAM_UNEXPECTED));
            Err(error.into())
        }
        Ok(Err(_)) => {
            reset_stream(send, recv, STREAM_INTERNAL);
            Err(anyhow!("host RPC request stream failed"))
        }
        Err(_) => {
            reset_stream(send, recv, STREAM_UNEXPECTED);
            Err(anyhow!("host RPC request did not finish"))
        }
    }
}

async fn send_host_hello(
    send: &mut iroh::endpoint::SendStream,
    request: &HostHelloRequest,
    installation_endpoint_id: EndpointId,
    host_endpoint_id: EndpointId,
) -> Result<()> {
    let response = HostHelloResponse::new(
        request.request_id.clone(),
        host_endpoint_id.to_string(),
        installation_endpoint_id.to_string(),
    );
    write_rpc(send, &response).await?;
    Ok(())
}

async fn send_rpc_error_code(
    send: &mut iroh::endpoint::SendStream,
    request_id: Option<String>,
    code: &str,
    message: &str,
) {
    let response = RpcErrorResponse::new(request_id, code, message);
    let _ = write_rpc(send, &response).await;
    finish_rpc_send(send).await;
}

async fn finish_rpc_send(send: &mut iroh::endpoint::SendStream) {
    if send.finish().is_ok() {
        let _ = timeout(Duration::from_secs(1), send.stopped()).await;
    }
}

async fn send_host_rpc_error(
    send: &mut iroh::endpoint::SendStream,
    request_id: Option<String>,
    error: &HostProtocolError,
) {
    let (code, message) = match error {
        HostProtocolError::UnsupportedVersion => (
            "unsupported_version",
            "This Ciao host protocol version is not supported.",
        ),
        HostProtocolError::UnsupportedMethod => (
            "unsupported_method",
            "This Ciao host method is not supported.",
        ),
        _ => ("malformed_request", "The Ciao host request was malformed."),
    };
    let response = RpcErrorResponse::new(request_id, code, message);
    let _ = write_rpc(send, &response).await;
    if send.finish().is_ok() {
        let _ = timeout(Duration::from_secs(1), send.stopped()).await;
    }
}

async fn handle_upload_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    remote_id: EndpointId,
    state: Arc<RuntimeState>,
) {
    // Repeat the authoritative local check immediately before allocation so a future revocation
    // path can close this race without changing the wire protocol. The frozen upload error
    // vocabulary has no authorization code, so the refusal rides `invalid` — a revoked device's
    // whole connection is torn down moments later anyway.
    if !state.paired_devices.lock().contains(remote_id) {
        let _ = crate::uploads::send_put_error(
            send,
            crate::uploads::UploadErrorCode::Invalid,
            "This installation is no longer authorized.",
        )
        .await;
        finish_upload_stream(send, recv).await;
        return;
    }
    match crate::uploads::run_upload_stream(
        recv,
        send,
        &state.uploads,
        crate::uploads::UPLOAD_IDLE_TIMEOUT,
    )
    .await
    {
        // The exchange concluded with a frame the phone can read (put_done or put_error);
        // exactly one upload runs per stream, so the stream now closes.
        Ok(()) => finish_upload_stream(send, recv).await,
        Err(error) => reset_stream(send, recv, host_stream_reset_code(&error)),
    }
}

/// Spec 015: one file, host to phone. Shaped like `handle_upload_stream` down to the
/// authorization recheck, and shorter because a preview owns no storage.
async fn handle_download_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    remote_id: EndpointId,
    state: Arc<RuntimeState>,
) {
    if !state.paired_devices.lock().contains(remote_id) {
        let _ = crate::downloads::send_get_error(
            send,
            crate::downloads::DownloadErrorCode::Invalid,
            "This installation is no longer authorized.",
        )
        .await;
        finish_upload_stream(send, recv).await;
        return;
    }
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    // Asked before the open frame is read, so an absolute token pays for an answer it will not
    // use. ponytail: one bounded provider call on a user-initiated preview, ~10 ms warm and
    // capped at PROVIDER_EXEC_TIMEOUT; make it lazy only if a wedged provider is ever observed
    // delaying previews of absolute paths.
    let session_cwd = match state.sole_attached_session(&remote_id.to_string()) {
        Some(session) => {
            crate::workspace::session_cwd(&state.workspace, session.kind, &session.name).await
        }
        None => None,
    };
    // Spec 008: a diff opened from the Agents tab names its session instead of relying on a
    // terminal lease. Attached rows carry the path through registration; managed rows
    // deliberately do not, so the managed record is the second half of the same question.
    let agent_workspace = |session_id: &str| {
        state
            .agent_sessions
            .workspace_path(session_id)
            .or_else(|| state.managed_sessions.workspace_path(session_id))
    };
    match crate::downloads::run_download_stream(
        recv,
        send,
        home.as_deref(),
        session_cwd.as_deref(),
        &agent_workspace,
        crate::downloads::DOWNLOAD_IDLE_TIMEOUT,
    )
    .await
    {
        Ok(()) => finish_upload_stream(send, recv).await,
        Err(error) => reset_stream(send, recv, host_stream_reset_code(&error)),
    }
}

async fn finish_upload_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
) {
    if send.finish().is_ok() {
        let _ = timeout(Duration::from_secs(1), send.stopped()).await;
    }
    let _ = recv.stop(VarInt::from_u32(0));
}

async fn handle_agent_stream(
    connection: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    remote_id: EndpointId,
    state: Arc<RuntimeState>,
) -> Result<()> {
    // Recheck local authorization before decoding the operation handshake.
    if !state.paired_devices.lock().contains(remote_id) {
        send_agent_error(send, "authorization_denied").await;
        return Ok(());
    }
    let open_body = match timeout(HOST_OPERATION_TIMEOUT, read_agent_frame(recv)).await {
        Ok(Ok(body)) => body,
        Ok(Err(error)) => {
            reset_stream(send, recv, agent_stream_reset_code(&error));
            return Ok(());
        }
        Err(_) => {
            reset_stream(send, recv, STREAM_MALFORMED);
            return Ok(());
        }
    };
    let open: AgentStreamOpen = match decode_agent_body(&open_body) {
        Ok(open) => open,
        Err(error) => {
            reset_stream(send, recv, agent_stream_reset_code(&error));
            return Ok(());
        }
    };
    if let Err(error) = open.validate() {
        // Name the operation: a handshake is rejected for the shape its operation declares,
        // so the operation is the whole answer. An op the table has no row for is refused
        // here as malformed, which is indistinguishable from a genuinely malformed frame
        // unless it says which one it was.
        tracing::warn!(
            operation = %open.operation,
            "agent stream handshake rejected before dispatch"
        );
        send_agent_error(
            send,
            if matches!(
                error,
                crate::agent_protocol::AgentProtocolError::UnsupportedVersion
            ) {
                "unsupported_version"
            } else {
                "malformed_handshake"
            },
        )
        .await;
        return Ok(());
    }
    let _subscription_lease = if open.operation == "agent.session.subscribe" {
        let Some(lease) = AgentSubscriptionLease::try_new(state.clone(), remote_id) else {
            send_agent_error(send, "subscription_limit").await;
            return Ok(());
        };
        Some(lease)
    } else {
        None
    };
    write_agent_frame(
        send,
        &AgentServerFrame::StreamAccepted {
            v: AGENT_PROTOCOL_VERSION,
            operation: open.operation.clone(),
            server_epoch: state.agent_sessions.server_epoch(),
            limits: AgentLimits::default(),
        },
    )
    .await?;

    match open.operation.as_str() {
        "agent.sessions.list" => {
            require_finished_agent_request(recv).await?;
            let list_began = Instant::now();
            // Managed sessions are withheld from peers that did not advertise the
            // managed capability; old apps never decode a managed descriptor.
            let list = if open
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_AGENT_SESSION_MANAGED_V1)
            {
                // An attached row whose conversation Ciao is already running must stop
                // offering a takeover: the host refuses it `already_live`, and the row the
                // user actually wants is the managed one sitting beside it.
                let list = state
                    .agent_sessions
                    .list_with_managed_owners(&state.managed_sessions.live_vendor_owners());
                let mut descriptors = list.sessions;
                // Released terminals belong to the user once handed back, so which of them
                // still exist is only knowable at list time, never from the record.
                let live_terminals = crate::workspace::existing_tmux_sessions(
                    &state.workspace,
                    &state.managed_sessions.handback_session_names(),
                )
                .await;
                descriptors.extend(state.managed_sessions.stored_descriptors(&live_terminals));
                bounded_session_list(descriptors, list.omitted_sessions)
            } else {
                state.agent_sessions.list()
            };
            // Unheld Codex conversations join as ordinary attached rows (Spec 013 §8): every
            // peer may render them; only the pick-up verb is capability-gated. A conversation
            // already spoken for — by a live attached session or a current adoption — is
            // withheld, because its live row is the one the person wants.
            let list = {
                let mut descriptors = list.sessions;
                let known: std::collections::HashSet<String> = descriptors
                    .iter()
                    .map(|descriptor| descriptor.session_id.clone())
                    .collect();
                for row in state.codex_adoptions.unheld_threads().await {
                    // One conversation, one row: any session speaking for this thread — a
                    // live tail or an ended record — is the row that carries the pick-up
                    // verb, so a twin unheld row never appears beside it.
                    if known.contains(&row.session_id)
                        || state.agent_sessions.has_upstream(&row.thread_id)
                    {
                        continue;
                    }
                    descriptors.push(crate::codex_adopted::unheld_descriptor(&row));
                }
                bounded_session_list(descriptors, list.omitted_sessions)
            };
            tracing::debug!(
                remote = %short_endpoint_id(remote_id),
                ms = list_began.elapsed().as_millis() as u64,
                "agent sessions listed"
            );
            write_agent_frame(
                send,
                &AgentServerFrame::SessionList {
                    v: AGENT_PROTOCOL_VERSION,
                    sessions: list.sessions,
                    omitted_sessions: list.omitted_sessions,
                },
            )
            .await?;
            finish_agent_send(send).await;
        }
        "agent.workspaces.list" => {
            require_finished_agent_request(recv).await?;
            let workspaces = state.managed_sessions.workspaces().await;
            write_agent_frame(
                send,
                &AgentServerFrame::WorkspaceList {
                    v: AGENT_PROTOCOL_VERSION,
                    workspaces: workspaces.workspaces,
                    omitted_workspaces: workspaces.omitted_workspaces,
                    scan_incomplete: workspaces.scan_incomplete,
                },
            )
            .await?;
            finish_agent_send(send).await;
        }
        "agent.managed.start"
        | "agent.managed.stop"
        | "agent.managed.resume"
        | "agent.managed.promote"
        | "agent.managed.release"
        | "agent.managed.forget"
        | "agent.adopted.pickup" => {
            require_finished_agent_request(recv).await?;
            // Lifecycle mutations recheck authorization immediately before acting.
            if !state.paired_devices.lock().contains(remote_id) {
                send_agent_error(send, "authorization_denied").await;
                return Ok(());
            }
            let (Some(command_id),) = (open.lifecycle_command_id.as_deref(),) else {
                send_agent_error(send, "malformed_handshake").await;
                return Ok(());
            };
            let outcome = match open.operation.as_str() {
                "agent.adopted.pickup" => {
                    let Some(session_id) = open.session_id.as_deref() else {
                        send_agent_error(send, "malformed_handshake").await;
                        return Ok(());
                    };
                    adopted_pickup(&state, session_id, command_id).await
                }
                "agent.managed.start" => {
                    let Some(workspace_id) = open.workspace_id.as_deref() else {
                        send_agent_error(send, "malformed_handshake").await;
                        return Ok(());
                    };
                    state
                        .managed_sessions
                        .managed_start(workspace_id, command_id)
                        .await
                }
                "agent.managed.promote" => {
                    let Some(session_id) = open.session_id.as_deref() else {
                        send_agent_error(send, "malformed_handshake").await;
                        return Ok(());
                    };
                    // Read the transcript before anything can end the session it belongs to.
                    // The promoted session is a new ID with an empty timeline, so this is the
                    // only moment the history Ciao already holds can be carried across.
                    let inherited = state.agent_sessions.timeline_for_handover(session_id);
                    let sessions = state.agent_sessions.clone();
                    let inherited = std::sync::Mutex::new(Some(inherited));
                    // Every refusal that depends on the terminal is resolved here, before a
                    // worker is considered, and is reported as an outcome rather than a
                    // stream error so the phone can explain it.
                    let refused = |reason: &str| crate::agent_protocol::LifecycleOutcome {
                        resume_command: None,
                        v: AGENT_PROTOCOL_VERSION,
                        command_id: command_id.to_owned(),
                        state: "refused".into(),
                        session_id: None,
                        process_generation: None,
                        reason_code: Some(reason.to_owned()),
                        deduplicated: None,
                    };
                    match state.agent_sessions.promotion_target(session_id) {
                        Ok(target) => {
                            // Decided before the terminal is asked to exit, not inside
                            // `managed_promote` after it: ending the terminal is not reversible,
                            // so a refusal that was knowable all along must not cost the owner a
                            // live conversation on its way to being reported.
                            if let Some(reason) =
                                state.managed_sessions.promotion_preflight(&target).await
                            {
                                refused(reason)
                            // Taking over means the terminal lets go. A terminal that will not
                            // exit refuses the takeover rather than becoming a second writer.
                            } else if !crate::process::request_exit(target.process_id).await {
                                refused("terminal_owner_live")
                            } else {
                                state
                                    .managed_sessions
                                    .managed_promote(&target, command_id, &|promoted: &str| {
                                        if let Some(history) =
                                            inherited.lock().ok().and_then(|mut h| h.take())
                                        {
                                            sessions.carry_history_into(promoted, history);
                                        }
                                    })
                                    .await
                            }
                        }
                        Err(reason) => refused(reason),
                    }
                }
                "agent.managed.release" => {
                    let Some(session_id) = open.session_id.as_deref() else {
                        send_agent_error(send, "malformed_handshake").await;
                        return Ok(());
                    };
                    // One verb, both topologies. A managed Claude and an adopted Codex differ in
                    // what Ciao has to let go of — a worker process versus a held rollout — but
                    // not in what the person is asking for, which is to continue the
                    // conversation somewhere Ciao does not run it. Routing Codex through its own
                    // command would have been a second name for one intention.
                    if let Some(thread_id) =
                        state.codex_adoptions.held_thread_for_session(session_id)
                    {
                        // Dropping the hold is what makes `codex resume` safe: Codex refuses
                        // nothing on contention (Spec 013 §5), so a command handed over while
                        // Ciao still held the thread would invite a second writer rather than
                        // a handover. Release first, then the command.
                        state.codex_adoptions.request_release(
                            &thread_id,
                            crate::codex_adopted::ReleaseReason::ResumeInTerminal,
                        );
                        crate::agent_protocol::LifecycleOutcome {
                            v: AGENT_PROTOCOL_VERSION,
                            command_id: command_id.to_owned(),
                            state: "accepted".into(),
                            session_id: Some(session_id.to_owned()),
                            process_generation: None,
                            reason_code: None,
                            deduplicated: None,
                            resume_command: crate::codex_adopted::codex_resume_command(&thread_id),
                        }
                    } else {
                        // The command travels with the outcome. Reading it off the refreshed
                        // descriptor instead meant the phone had to survive one more round trip
                        // through a connection the release had just disturbed — and it did not,
                        // so the one action whose point is handing over the command handed over
                        // an error. The descriptor still carries it too, for every later look.
                        let (mut outcome, handback) = state
                            .managed_sessions
                            .managed_release(session_id, command_id)
                            .await;
                        if outcome.state == "accepted" {
                            outcome.resume_command = handback.and_then(|handback| {
                                crate::managed_session::claude_resume_command(
                                    &handback.vendor_session_id,
                                )
                            });
                        }
                        outcome
                    }
                }
                "agent.managed.forget" => {
                    let Some(session_id) = open.session_id.as_deref() else {
                        send_agent_error(send, "malformed_handshake").await;
                        return Ok(());
                    };
                    // Drops Ciao's record only. The conversation stays in Claude's own store,
                    // which is why this is offered for a stopped session and refused for a live
                    // one: forgetting a running worker would strand the process, not the record.
                    state
                        .managed_sessions
                        .managed_forget(session_id, command_id)
                }
                "agent.managed.stop" => {
                    let (Some(session_id), Some(generation)) =
                        (open.session_id.as_deref(), open.expected_generation)
                    else {
                        send_agent_error(send, "malformed_handshake").await;
                        return Ok(());
                    };
                    state
                        .managed_sessions
                        .managed_stop(session_id, generation, command_id)
                        .await
                }
                _ => {
                    let Some(session_id) = open.session_id.as_deref() else {
                        send_agent_error(send, "malformed_handshake").await;
                        return Ok(());
                    };
                    state
                        .managed_sessions
                        .managed_resume(session_id, command_id)
                        .await
                }
            };
            // Categorical only — operation, verdict, reason. A lifecycle mutation that a
            // phone asked for used to leave no host-side trace at all, so a refusal and a
            // request that never arrived were indistinguishable from the Mac.
            tracing::info!(
                operation = %open.operation,
                state = %outcome.state,
                reason = outcome.reason_code.as_deref().unwrap_or("-"),
                "agent lifecycle request answered"
            );
            // The outcome is validated before it travels: the app validates on arrival, so a
            // non-compliant frame does not degrade gracefully there — it reads as the host
            // never answering. Better a generic, *valid* refusal and a loud log here.
            let outcome = if outcome.validate().is_ok() {
                outcome
            } else {
                tracing::error!(
                    operation = %open.operation,
                    "lifecycle outcome failed canonical validation; sending a generic refusal"
                );
                crate::agent_protocol::LifecycleOutcome {
                    resume_command: None,
                    v: AGENT_PROTOCOL_VERSION,
                    command_id: outcome.command_id.clone(),
                    state: "refused".into(),
                    session_id: None,
                    process_generation: None,
                    reason_code: Some("host_error".into()),
                    deduplicated: None,
                }
            };
            write_agent_frame(
                send,
                &AgentServerFrame::LifecycleOutcome {
                    v: AGENT_PROTOCOL_VERSION,
                    outcome,
                },
            )
            .await?;
            finish_agent_send(send).await;
        }
        "agent.session.snapshot" => {
            require_finished_agent_request(recv).await?;
            let Some(session_id) = open.session_id else {
                send_agent_error(send, "malformed_handshake").await;
                return Ok(());
            };
            // A stopped worker leaves no entry in the live supervisor, but its record is still
            // the one the list is built from -- so refusing here left the phone on a Retry that
            // could only fail again, with no way to reach the Resume the snapshot unlocks.
            let snapshot = match state.agent_sessions.snapshot(&session_id) {
                Some(snapshot) => snapshot,
                None => {
                    let live_terminals = crate::workspace::existing_tmux_sessions(
                        &state.workspace,
                        &state.managed_sessions.handback_session_names(),
                    )
                    .await;
                    match state
                        .managed_sessions
                        .stored_snapshot(&session_id, &live_terminals)
                    {
                        Some(snapshot) => snapshot,
                        // The third identity a session ID can have: an unheld Codex
                        // conversation from discovery, opened read-only through one
                        // thread/read (Spec 013 §7). No adoption implied; the pick-up slot
                        // is the way in.
                        None => match codex_unheld_snapshot(&state, &session_id).await {
                            Some(snapshot) => snapshot,
                            None => {
                                send_agent_error(send, "session_unavailable").await;
                                return Ok(());
                            }
                        },
                    }
                }
            };
            write_agent_frame(
                send,
                &AgentServerFrame::SessionSnapshot {
                    v: AGENT_PROTOCOL_VERSION,
                    snapshot: Box::new(snapshot),
                },
            )
            .await?;
            finish_agent_send(send).await;
        }
        "agent.timeline.page" => {
            require_finished_agent_request(recv).await?;
            let (Some(session_id), Some(before_sequence), Some(limit)) =
                (open.session_id, open.before_sequence, open.page_limit)
            else {
                send_agent_error(send, "malformed_handshake").await;
                return Ok(());
            };
            let Some(page) =
                state
                    .agent_sessions
                    .page(&session_id, before_sequence, usize::from(limit))
            else {
                send_agent_error(send, "page_unavailable").await;
                return Ok(());
            };
            let page_id = format!("{:032x}", rand::random::<u128>());
            write_agent_frame(
                send,
                &AgentServerFrame::TimelinePageStart {
                    v: AGENT_PROTOCOL_VERSION,
                    page_id: page_id.clone(),
                    session_id: page.session_id,
                    snapshot_epoch: page.snapshot_epoch,
                    process_generation: page.process_generation,
                    total_entries: u8::try_from(page.entries.len()).unwrap_or(u8::MAX),
                    aggregate_bytes: page.aggregate_bytes,
                    has_older: page.has_older,
                    next_before_sequence: page.next_before_sequence,
                },
            )
            .await?;
            for entry in page.entries {
                write_agent_frame(
                    send,
                    &AgentServerFrame::TimelinePageEntry {
                        v: AGENT_PROTOCOL_VERSION,
                        page_id: page_id.clone(),
                        entry,
                    },
                )
                .await?;
            }
            write_agent_frame(
                send,
                &AgentServerFrame::TimelinePageEnd {
                    v: AGENT_PROTOCOL_VERSION,
                    page_id,
                },
            )
            .await?;
            finish_agent_send(send).await;
        }
        "agent.command.submit" => {
            let Some(expected_session) = open.session_id else {
                send_agent_error(send, "malformed_handshake").await;
                return Ok(());
            };
            let body = timeout(HOST_OPERATION_TIMEOUT, read_agent_frame(recv))
                .await
                .map_err(|_| anyhow!("agent command timed out"))??;
            let frame: AgentClientFrame = decode_agent_body(&body)?;
            let AgentClientFrame::CommandSubmit { command } = frame else {
                send_agent_error(send, "unexpected_message").await;
                return Ok(());
            };
            require_finished_agent_request(recv).await?;
            // Authorization and route proof are both rechecked immediately before forwarding.
            if !state.paired_devices.lock().contains(remote_id) {
                send_agent_error(send, "authorization_denied").await;
                return Ok(());
            }
            if command.session_id != expected_session {
                send_agent_error(send, "session_mismatch").await;
                return Ok(());
            }
            let receipt = state.agent_sessions.submit_command(command).await;
            write_agent_frame(
                send,
                &AgentServerFrame::CommandReceipt {
                    v: AGENT_PROTOCOL_VERSION,
                    receipt,
                },
            )
            .await?;
            finish_agent_send(send).await;
        }
        "agent.session.subscribe" => {
            let Some(session_id) = open.session_id else {
                send_agent_error(send, "malformed_handshake").await;
                return Ok(());
            };
            // A stopped worker leaves no entry in the live supervisor, but its record is still
            // the one the list is built from -- so refusing here left the phone on a Retry that
            // could only fail again, with no way to reach the Resume the snapshot unlocks.
            let snapshot = match state.agent_sessions.snapshot(&session_id) {
                Some(snapshot) => snapshot,
                None => {
                    let live_terminals = crate::workspace::existing_tmux_sessions(
                        &state.workspace,
                        &state.managed_sessions.handback_session_names(),
                    )
                    .await;
                    match state
                        .managed_sessions
                        .stored_snapshot(&session_id, &live_terminals)
                    {
                        Some(snapshot) => snapshot,
                        // The third identity a session ID can have: an unheld Codex
                        // conversation from discovery, opened read-only through one
                        // thread/read (Spec 013 §7). No adoption implied; the pick-up slot
                        // is the way in.
                        None => match codex_unheld_snapshot(&state, &session_id).await {
                            Some(snapshot) => snapshot,
                            None => {
                                send_agent_error(send, "session_unavailable").await;
                                return Ok(());
                            }
                        },
                    }
                }
            };
            // Held for the life of the subscription so the receiver below never reports
            // `Closed`. A stored session has nothing to stream, and the stream staying open is
            // what lets the phone rest on the snapshot and offer Resume instead of falling
            // through to a stale state.
            let _idle_updates;
            let mut updates = match state.agent_sessions.subscribe(&session_id) {
                Some(updates) => updates,
                None => {
                    let (sender, receiver) = tokio::sync::broadcast::channel(1);
                    _idle_updates = sender;
                    receiver
                }
            };
            write_agent_frame(
                send,
                &AgentServerFrame::SessionSnapshot {
                    v: AGENT_PROTOCOL_VERSION,
                    snapshot: Box::new(snapshot),
                },
            )
            .await?;
            // Not `read_agent_frame`: every broadcast update winning this select! drops the read
            // future, and that function loses consumed bytes on drop — a phone command arriving
            // while a reply streams would desync the subscription.
            let mut frames = crate::agent_protocol::AgentFrameReader::default();
            loop {
                tokio::select! {
                    update = updates.recv() => {
                        match update {
                            Ok(frame) => write_agent_frame(send, &frame).await?,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                write_agent_frame(
                                    send,
                                    &AgentServerFrame::ResyncRequired {
                                        v: AGENT_PROTOCOL_VERSION,
                                        session_id: session_id.clone(),
                                        reason_code: "outbound_overflow".into(),
                                    },
                                )
                                .await?;
                                break;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                    incoming = frames.next(recv) => {
                        let body = match incoming {
                            Ok(body) => body,
                            Err(crate::agent_protocol::AgentProtocolError::Truncated) => break,
                            Err(error) => return Err(error.into()),
                        };
                        let frame: AgentClientFrame = decode_agent_body(&body)?;
                        match frame {
                            AgentClientFrame::CommandSubmit { command } => {
                                if !state.paired_devices.lock().contains(remote_id) {
                                    send_agent_error(send, "authorization_denied").await;
                                    break;
                                }
                                if command.session_id != session_id {
                                    send_agent_error(send, "session_mismatch").await;
                                    continue;
                                }
                                let receipt = state.agent_sessions.submit_command(command).await;
                                write_agent_frame(
                                    send,
                                    &AgentServerFrame::CommandReceipt {
                                        v: AGENT_PROTOCOL_VERSION,
                                        receipt,
                                    },
                                )
                                .await?;
                            }
                            AgentClientFrame::Close => break,
                            AgentClientFrame::Unknown => {
                                send_agent_error(send, "unexpected_message").await;
                                break;
                            }
                        }
                    }
                    _ = connection.closed() => break,
                }
            }
            finish_agent_send(send).await;
            // The phone closing the conversation is what ends an adopted hold (Spec 013 §5):
            // the subscription stream is the "open" the ADR bounds the hold by.
            if let Some(thread) = state.codex_adoptions.thread_for_session(&session_id) {
                state.codex_adoptions.request_release(
                    &thread,
                    crate::codex_adopted::ReleaseReason::ConversationClosed,
                );
            }
        }
        _ => send_agent_error(send, "unsupported_operation").await,
    }
    Ok(())
}

/// The read-only open of an unheld Codex conversation: descriptor facts plus one bounded
/// `thread/read`. A machine without binary evidence still opens — empty timeline, pick-up
/// slot intact — because the slot, not the history, is what the screen exists for.
async fn codex_unheld_snapshot(
    state: &Arc<RuntimeState>,
    session_id: &str,
) -> Option<crate::agent_protocol::AgentSessionSnapshot> {
    let row = state
        .codex_adoptions
        .unheld_thread_for_session(session_id)
        .await?;
    let entries = match state.codex_adoptions.recorded_binary() {
        Some(binary) => crate::codex_history::read_thread_once(&binary, &row.thread_id).await,
        None => Vec::new(),
    };
    Some(crate::codex_adopted::unheld_snapshot(&row, entries))
}

/// Picks up an unheld Codex conversation (Spec 013 §7): the tapped row resolves back to its
/// thread, the binary comes from persisted registration evidence, and every refusal is a
/// categorical token the phone can render.
async fn adopted_pickup(
    state: &Arc<RuntimeState>,
    session_id: &str,
    command_id: &str,
) -> crate::agent_protocol::LifecycleOutcome {
    // Refusals carry the reason and nothing else: the canonical rule — pinned by both
    // validators — is that a refused outcome names no session, and the phone already knows
    // what it tapped. The first phone run shipped a session_id here and every truthful
    // refusal rendered as a timeout, because the app's validator rightly threw it away.
    let refused = |reason: &str| crate::agent_protocol::LifecycleOutcome {
        resume_command: None,
        v: AGENT_PROTOCOL_VERSION,
        command_id: command_id.to_owned(),
        state: "refused".into(),
        session_id: None,
        process_generation: None,
        reason_code: Some(reason.into()),
        deduplicated: None,
    };
    // An adoption already holding this conversation answers accepted rather than refusing:
    // the row and the session share one identity, so the phone simply opens it.
    if state
        .codex_adoptions
        .thread_for_session(session_id)
        .is_some()
    {
        return crate::agent_protocol::LifecycleOutcome {
            resume_command: None,
            v: AGENT_PROTOCOL_VERSION,
            command_id: command_id.to_owned(),
            state: "accepted".into(),
            session_id: Some(session_id.to_owned()),
            process_generation: None,
            reason_code: None,
            deduplicated: Some(true),
        };
    }
    // The tapped row is either a discovery row (its ID is the conversation's stable identity)
    // or an attached session row — live tail or ended record — that resolves to its thread.
    // Ownership is not judged here: the adopt preconditions ask the kernel, and a live TUI
    // answers `terminal_holds_conversation` truthfully.
    let row = match state
        .codex_adoptions
        .unheld_thread_for_session(session_id)
        .await
    {
        Some(row) => row,
        None => {
            let Some(thread) = state.agent_sessions.codex_thread_for_session(session_id) else {
                return refused("unknown_session");
            };
            if let Some(adopted) = state.codex_adoptions.session_for(&thread) {
                // Already picked up under its stable identity; the phone opens that session.
                return crate::agent_protocol::LifecycleOutcome {
                    resume_command: None,
                    v: AGENT_PROTOCOL_VERSION,
                    command_id: command_id.to_owned(),
                    state: "accepted".into(),
                    session_id: Some(adopted),
                    process_generation: None,
                    reason_code: None,
                    deduplicated: Some(true),
                };
            }
            let Some(row) = state.codex_adoptions.unheld_row_by_thread(&thread).await else {
                return refused("unknown_session");
            };
            row
        }
    };
    let Some(binary) = state.codex_adoptions.recorded_binary() else {
        return refused("codex_unavailable");
    };
    let params = crate::codex_adopted::AdoptParams {
        binary,
        thread_id: row.thread_id.clone(),
        rollout: row.rollout.clone(),
        workspace_display: crate::codex_adopted::unheld_descriptor(&row).workspace_display,
        workspace_path: row.cwd.clone(),
        adapter_version: row.cli_version.clone(),
    };
    match crate::codex_adopted::adopt(
        state.agent_sessions.clone(),
        state.codex_adoptions.clone(),
        state.notifier.clone(),
        params,
    )
    .await
    {
        Ok(adopted_session) => crate::agent_protocol::LifecycleOutcome {
            resume_command: None,
            v: AGENT_PROTOCOL_VERSION,
            command_id: command_id.to_owned(),
            state: "accepted".into(),
            session_id: Some(adopted_session),
            process_generation: None,
            reason_code: None,
            deduplicated: None,
        },
        Err(refusal) => {
            tracing::info!(
                target: "codex_adopted",
                reason = refusal.reason_code(),
                "pick-up refused"
            );
            refused(refusal.reason_code())
        }
    }
}

async fn require_finished_agent_request(recv: &mut iroh::endpoint::RecvStream) -> Result<()> {
    let mut trailing = [0_u8; 1];
    match timeout(HOST_OPERATION_TIMEOUT, recv.read(&mut trailing)).await {
        Ok(Ok(None)) => Ok(()),
        _ => Err(crate::agent_protocol::AgentProtocolError::UnexpectedMessage.into()),
    }
}

async fn send_agent_error(send: &mut iroh::endpoint::SendStream, code: &str) {
    // Every refusal on this stream passes through here, so this is the one place that makes
    // a rejected request distinguishable from one that never arrived. The lifecycle log only
    // fires where an outcome exists, which is why a promote rejected during handshake
    // validation left no trace at all and cost most of a day to find.
    tracing::warn!(code, "agent stream request refused");
    let _ = write_agent_frame(
        send,
        &AgentServerFrame::Error {
            v: AGENT_PROTOCOL_VERSION,
            code: code.into(),
        },
    )
    .await;
    finish_agent_send(send).await;
}

async fn finish_agent_send(send: &mut iroh::endpoint::SendStream) {
    if send.finish().is_ok() {
        let _ = timeout(Duration::from_secs(1), send.stopped()).await;
    }
}

fn agent_stream_reset_code(error: &crate::agent_protocol::AgentProtocolError) -> u32 {
    match error {
        crate::agent_protocol::AgentProtocolError::FrameTooLarge => {
            crate::host_protocol::STREAM_FRAME_TOO_LARGE
        }
        crate::agent_protocol::AgentProtocolError::UnexpectedMessage => STREAM_UNEXPECTED,
        crate::agent_protocol::AgentProtocolError::Io(_) => STREAM_INTERNAL,
        _ => STREAM_MALFORMED,
    }
}

async fn handle_terminal_stream(
    connection: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    remote_id: EndpointId,
    state: Arc<RuntimeState>,
) -> Result<()> {
    let stream_began = Instant::now();
    let first = match timeout(HOST_OPERATION_TIMEOUT, read_terminal_frame(recv)).await {
        Err(_) => {
            reset_stream(send, recv, STREAM_MALFORMED);
            return Ok(());
        }
        Ok(Err(error)) => {
            let reset = host_stream_reset_code(&error);
            if matches!(
                error,
                HostProtocolError::Truncated | HostProtocolError::Io(_)
            ) {
                reset_stream(send, recv, reset);
            } else {
                send_terminal_protocol_error(send, None, &error).await;
                finish_terminal_error(send, recv, reset).await;
            }
            return Ok(());
        }
        Ok(Ok(frame)) => frame,
    };
    let receive_state = HostReceiveState::AwaitingOpen;
    if let Err(error) = receive_state.accept(&first) {
        send_terminal_protocol_error(send, None, &error).await;
        finish_terminal_error(send, recv, STREAM_UNEXPECTED).await;
        return Ok(());
    }
    let TerminalFrame::Open(open) = first else {
        reset_stream(send, recv, STREAM_UNEXPECTED);
        return Ok(());
    };

    // Repeat the authoritative local check immediately before allocation so a future revocation
    // path can close this race without changing the wire protocol.
    if !state.paired_devices.lock().contains(remote_id) {
        send_terminal_error(
            send,
            None,
            "authorization_denied",
            "This installation is no longer authorized.",
        )
        .await;
        finish_terminal_error(send, recv, STREAM_TERMINAL_LIMIT).await;
        return Ok(());
    }
    let agent_plan = match resolve_agent_terminal_plan(&open, &state).await {
        Ok(plan) => plan,
        Err((code, message)) => {
            send_terminal_error(send, None, code, message).await;
            finish_terminal_error(send, recv, STREAM_PTY_FAILURE).await;
            return Ok(());
        }
    };
    let resumable = target_is_resumable(open.validated_target().ok(), agent_plan.is_some());
    // Opened and finished are logged as a pair with the device that holds it, because the only
    // record of a terminal used to be a number in `ciao status`. An owner blocked by that number
    // could not tell a view they had left open on another device from a lease outliving a client
    // that was already gone, and neither could anyone reading the log afterwards.
    tracing::info!(
        device = %short_endpoint_id(remote_id),
        target = open.target.as_str(),
        resumable,
        "PTY terminal opened"
    );
    // Spec 015 §11.1: remember the multiplexer session so a preview arriving later on its own
    // stream can ask it where it is standing. `provider()` is exactly the right filter — it is
    // `None` for `shell` and for `agent_route`, and an agent route's `session` field is a route
    // id rather than a session name, so neither can be mistaken for one here.
    let attached_session = match (open.validated_target().ok(), open.session.as_deref()) {
        (Some(target), Some(name)) => target.provider().map(|kind| AttachedSession {
            kind,
            name: name.to_owned(),
        }),
        _ => None,
    };
    let Some(_pty_lease) = PtyLease::try_new(state.clone(), remote_id, resumable, attached_session)
    else {
        send_terminal_error(
            send,
            None,
            "terminal_limit",
            "The Mac terminal limit has been reached.",
        )
        .await;
        finish_terminal_error(send, recv, STREAM_TERMINAL_LIMIT).await;
        return Ok(());
    };

    // Spec 021 §5: land the attach on the requested tab before the viewer spawns. Best
    // effort — a stale or foreign tab focuses nothing and the attach proceeds to the
    // session's current tab. Focus is shared multiplexer state, so this also switches what
    // any attached desktop client of the same session is showing; that is the documented
    // §5 behaviour, not an accident.
    if let (Some(tab), Ok(target)) = (open.tab.as_deref(), open.validated_target())
        && agent_plan.is_none()
        && let (Some(kind), Some(session)) = (target.provider(), open.session.as_deref())
        && !crate::workspace::focus_tab(&state.workspace, kind, session, tab).await
    {
        tracing::debug!(
            target = open.target.as_str(),
            "tab pre-focus failed; attaching to the session's current tab"
        );
    }

    let tmux_detach_binary = tmux_detach_binary(&open, &state, agent_plan.as_ref());
    let mut spawn_task = match spawn_terminal_child(&open, &state, agent_plan.as_ref()) {
        Ok(task) => task,
        Err((code, message)) => {
            send_terminal_error(send, None, code, message).await;
            finish_terminal_error(send, recv, STREAM_PTY_FAILURE).await;
            return Ok(());
        }
    };
    let mut session = match timeout(HOST_OPERATION_TIMEOUT, &mut spawn_task).await {
        Err(_) => {
            // Keep ownership of a late successful spawn so a timed-out open cannot orphan its
            // shell. portable-pty's blocking spawn itself cannot be cancelled safely.
            tokio::spawn(async move {
                if let Ok(Ok(mut late_session)) = spawn_task.await {
                    let _ = late_session.cleanup(CleanupReason::BridgeFailure).await;
                }
            });
            send_terminal_error(
                send,
                None,
                "pty_open_failed",
                "The Mac could not open a login shell.",
            )
            .await;
            finish_terminal_error(send, recv, STREAM_PTY_FAILURE).await;
            return Ok(());
        }
        Ok(Ok(Err(error))) => {
            let (code, message) = pty_open_error(error);
            send_terminal_error(send, None, code, message).await;
            finish_terminal_error(send, recv, STREAM_PTY_FAILURE).await;
            return Ok(());
        }
        Ok(Err(_)) => {
            send_terminal_error(
                send,
                None,
                "internal_error",
                "The Mac could not open a login shell.",
            )
            .await;
            finish_terminal_error(send, recv, STREAM_INTERNAL).await;
            return Ok(());
        }
        Ok(Ok(Ok(session))) => session,
    };
    if herdr_viewer_child(&open, agent_plan.as_ref()) {
        session.mark_viewer_cleanup();
    }

    let terminal_id = session.terminal_id().to_owned();
    let opened = TerminalFrame::Opened(TerminalOpened {
        v: HOST_PROTOCOL_VERSION,
        terminal_id: terminal_id.clone(),
        dimensions: open.dimensions,
        term: "xterm-256color".into(),
    });
    if let Err(error) = write_terminal_frame(send, &opened).await {
        cleanup_terminal(
            &mut session,
            tmux_detach_binary.as_deref(),
            CleanupReason::BridgeFailure,
        )
        .await;
        return Err(error.into());
    }
    tracing::debug!(
        device = %short_endpoint_id(remote_id),
        ms = stream_began.elapsed().as_millis() as u64,
        "PTY terminal ready"
    );

    let result = bridge_terminal(
        connection,
        send,
        recv,
        &terminal_id,
        &mut session,
        tmux_detach_binary.as_deref(),
        state.shutdown.subscribe(),
    )
    .await;
    let high_water = session.queue_high_water_marks();
    tracing::info!(
        terminal = %terminal_id,
        device = %short_endpoint_id(remote_id),
        input_queue_high_water = high_water.input_bytes,
        output_queue_high_water = high_water.output_bytes,
        "PTY terminal finished"
    );
    result
}

async fn bridge_terminal(
    connection: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    terminal_id: &str,
    session: &mut PtySession,
    tmux_detach_binary: Option<&std::path::Path>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    enum Event {
        Incoming(Result<TerminalFrame, HostProtocolError>),
        Output(Option<crate::pty::PtyOutput>),
        Process(Result<PtyExit, PtyError>),
        ConnectionClosed,
        ServerShutdown,
    }

    let mut receive_state = HostReceiveState::Attached;
    // Not `read_terminal_frame`: this select! drops the losing read future on every PTY output
    // event, and that function loses consumed bytes on drop — the stream desynced whenever a
    // client frame arrived fragmented, which an LTE relay path does routinely.
    let mut frames = crate::host_protocol::TerminalFrameReader::default();
    let mut exit_watcher = session.exit_watcher();
    let mut process_exit = None;
    let mut output_finished = false;

    loop {
        if process_exit.is_some() && output_finished {
            let exit = session.finish_normal().await?;
            send_terminal_exit(send, terminal_id, exit).await;
            return Ok(());
        }

        let event = tokio::select! {
            frame = frames.next(recv), if process_exit.is_none() => Event::Incoming(frame),
            output = session.next_output(), if !output_finished => Event::Output(output),
            exit = exit_watcher.wait(), if process_exit.is_none() => Event::Process(exit),
            _ = connection.closed() => Event::ConnectionClosed,
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    Event::ServerShutdown
                } else {
                    Event::ConnectionClosed
                }
            }
        };

        match event {
            Event::Incoming(Ok(frame)) => {
                receive_state = match receive_state.accept(&frame) {
                    Ok(next) => next,
                    Err(error) => {
                        send_terminal_protocol_error(send, Some(terminal_id), &error).await;
                        finish_terminal_error(send, recv, STREAM_UNEXPECTED).await;
                        cleanup_terminal(session, tmux_detach_binary, CleanupReason::StreamEnded)
                            .await;
                        return Ok(());
                    }
                };
                match frame {
                    TerminalFrame::Input(bytes) => {
                        let input = tokio::select! {
                            result = session.send_input(bytes) => result,
                            _ = connection.closed() => {
                                cleanup_terminal(
                                    session,
                                    tmux_detach_binary,
                                    CleanupReason::ConnectionLost,
                                )
                                .await;
                                return Ok(());
                            }
                            changed = shutdown.changed() => {
                                if changed.is_ok() && *shutdown.borrow() {
                                    connection.close(
                                        VarInt::from_u32(crate::host_protocol::CONNECTION_SERVER_SHUTDOWN),
                                        b"daemon shutdown",
                                    );
                                    cleanup_terminal(
                                        session,
                                        tmux_detach_binary,
                                        CleanupReason::ServerShutdown,
                                    )
                                    .await;
                                    return Ok(());
                                }
                                Err(PtyError::InputClosed)
                            }
                        };
                        if input.is_err() {
                            send_terminal_error(
                                send,
                                Some(terminal_id),
                                "backpressure",
                                "The terminal input bridge could not keep up.",
                            )
                            .await;
                            finish_terminal_error(send, recv, STREAM_BACKPRESSURE).await;
                            cleanup_terminal(
                                session,
                                tmux_detach_binary,
                                CleanupReason::BridgeFailure,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                    TerminalFrame::Resize(dimensions) => {
                        if session.request_resize(dimensions).is_err() {
                            send_terminal_error(
                                send,
                                Some(terminal_id),
                                "internal_error",
                                "The Mac could not resize the terminal.",
                            )
                            .await;
                            finish_terminal_error(send, recv, STREAM_INTERNAL).await;
                            cleanup_terminal(
                                session,
                                tmux_detach_binary,
                                CleanupReason::BridgeFailure,
                            )
                            .await;
                            return Ok(());
                        }
                    }
                    TerminalFrame::Close => {
                        cleanup_terminal(session, tmux_detach_binary, CleanupReason::ExplicitClose)
                            .await;
                        send_closed_exit(send, terminal_id, "closed").await;
                        return Ok(());
                    }
                    _ => unreachable!("host receive state accepted only client frames"),
                }
            }
            Event::Incoming(Err(error)) => {
                let reset = host_stream_reset_code(&error);
                if matches!(
                    error,
                    HostProtocolError::Truncated | HostProtocolError::Io(_)
                ) {
                    reset_stream(send, recv, reset);
                } else {
                    send_terminal_protocol_error(send, Some(terminal_id), &error).await;
                    finish_terminal_error(send, recv, reset).await;
                }
                cleanup_terminal(session, tmux_detach_binary, CleanupReason::StreamEnded).await;
                return Ok(());
            }
            Event::Output(Some(output)) => {
                if write_terminal_frame(send, &TerminalFrame::Output(output.bytes().to_vec()))
                    .await
                    .is_err()
                {
                    cleanup_terminal(session, tmux_detach_binary, CleanupReason::BridgeFailure)
                        .await;
                    return Ok(());
                }
            }
            Event::Output(None) => output_finished = true,
            Event::Process(Ok(exit)) => {
                process_exit = Some(exit);
                let _ = recv.stop(VarInt::from_u32(crate::host_protocol::STREAM_CANCELLED));
            }
            Event::Process(Err(_)) => {
                send_terminal_error(
                    send,
                    Some(terminal_id),
                    "internal_error",
                    "The Mac could not observe the shell exit.",
                )
                .await;
                finish_terminal_error(send, recv, STREAM_INTERNAL).await;
                cleanup_terminal(session, tmux_detach_binary, CleanupReason::BridgeFailure).await;
                return Ok(());
            }
            Event::ConnectionClosed => {
                cleanup_terminal(session, tmux_detach_binary, CleanupReason::ConnectionLost).await;
                return Ok(());
            }
            Event::ServerShutdown => {
                connection.close(
                    VarInt::from_u32(crate::host_protocol::CONNECTION_SERVER_SHUTDOWN),
                    b"daemon shutdown",
                );
                cleanup_terminal(session, tmux_detach_binary, CleanupReason::ServerShutdown).await;
                return Ok(());
            }
        }
    }
}

async fn cleanup_terminal(
    session: &mut PtySession,
    tmux_binary: Option<&std::path::Path>,
    reason: CleanupReason,
) {
    // The one line that says WHY a PTY ended — "did the phone abandon the host, or the host the
    // phone" is the first fork in any halt forensics, and `reason` is computed at 13 call sites
    // and was never logged (2026-08-09 mid-session halt audit, gap G10a).
    tracing::info!(reason = ?reason, "PTY terminal cleanup");
    if let (Some(binary), Some(client_tty)) = (tmux_binary, session.client_tty()) {
        // The client may still be registering immediately after PTY spawn. Keep the whole retry
        // sequence well inside the terminal close deadline; dropping a timed-out bounded runner
        // kills and reaps its provider child.
        let mut detached = false;
        for attempt in 0..3 {
            if timeout(
                Duration::from_millis(500),
                detach_tmux_client(binary, client_tty),
            )
            .await
            .is_ok_and(|result| result)
            {
                detached = true;
                break;
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
        if !detached {
            tracing::warn!("tmux client detach failed; continuing bounded PTY cleanup");
        }
    }
    let _ = session.cleanup(reason).await;
}

fn tmux_detach_binary(
    open: &TerminalOpen,
    state: &RuntimeState,
    agent_plan: Option<&crate::agent_route::AgentTerminalPlan>,
) -> Option<std::path::PathBuf> {
    if let Some(plan) = agent_plan {
        return (plan.provider == crate::host_protocol::ProviderKind::Tmux)
            .then(|| plan.program.clone());
    }
    let target = open.validated_target().ok()?;
    matches!(
        target,
        crate::host_protocol::TerminalTarget::TmuxAttach
            | crate::host_protocol::TerminalTarget::TmuxCreate
    )
    .then(|| {
        state
            .workspace
            .resolve(crate::host_protocol::ProviderKind::Tmux)
    })
    .flatten()
}

async fn send_terminal_exit(
    send: &mut iroh::endpoint::SendStream,
    terminal_id: &str,
    exit: PtyExit,
) {
    let (kind, code, signal) = match exit {
        PtyExit::Exited(code) => ("exited", Some(code), None),
        PtyExit::Signaled(signal) => ("signaled", None, Some(signal)),
    };
    let frame = TerminalFrame::Exit(TerminalExit {
        v: HOST_PROTOCOL_VERSION,
        terminal_id: terminal_id.into(),
        kind: kind.into(),
        code,
        signal,
    });
    let _ = write_terminal_frame(send, &frame).await;
    finish_terminal_send(send).await;
}

async fn send_closed_exit(send: &mut iroh::endpoint::SendStream, terminal_id: &str, kind: &str) {
    let frame = TerminalFrame::Exit(TerminalExit {
        v: HOST_PROTOCOL_VERSION,
        terminal_id: terminal_id.into(),
        kind: kind.into(),
        code: None,
        signal: None,
    });
    let _ = write_terminal_frame(send, &frame).await;
    finish_terminal_send(send).await;
}

async fn send_terminal_protocol_error(
    send: &mut iroh::endpoint::SendStream,
    terminal_id: Option<&str>,
    error: &HostProtocolError,
) {
    let (code, message) = match error {
        HostProtocolError::UnsupportedVersion => (
            "unsupported_version",
            "This Ciao terminal protocol version is not supported.",
        ),
        HostProtocolError::InvalidDimensions => (
            "invalid_dimensions",
            "The requested terminal dimensions are invalid.",
        ),
        HostProtocolError::UnsupportedTarget => (
            "unsupported_target",
            "The requested terminal target is not supported.",
        ),
        HostProtocolError::InvalidTarget => {
            ("invalid_target", "The requested session target is invalid.")
        }
        HostProtocolError::FrameTooLarge => (
            "frame_too_large",
            "The terminal frame exceeds the allowed size.",
        ),
        HostProtocolError::UnexpectedDirection | HostProtocolError::UnexpectedOrder => (
            "unexpected_frame",
            "The terminal frame is not valid in this state.",
        ),
        _ => ("malformed_request", "The terminal frame was malformed."),
    };
    send_terminal_error(send, terminal_id, code, message).await;
}

async fn send_terminal_error(
    send: &mut iroh::endpoint::SendStream,
    terminal_id: Option<&str>,
    code: &str,
    message: &str,
) {
    let frame = TerminalFrame::Error(TerminalError {
        v: HOST_PROTOCOL_VERSION,
        terminal_id: terminal_id.map(str::to_owned),
        code: code.into(),
        message: message.into(),
    });
    let _ = write_terminal_frame(send, &frame).await;
}

async fn finish_terminal_send(send: &mut iroh::endpoint::SendStream) {
    if send.finish().is_ok() {
        let _ = timeout(Duration::from_secs(1), send.stopped()).await;
    }
}

async fn finish_terminal_error(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    reset_code: u32,
) {
    finish_terminal_send(send).await;
    let _ = recv.stop(VarInt::from_u32(reset_code));
}

fn pty_open_error(error: PtyError) -> (&'static str, &'static str) {
    match error {
        PtyError::ShellUnavailable => ("shell_unavailable", "The Mac login shell is unavailable."),
        _ => ("pty_open_failed", "The Mac could not open a login shell."),
    }
}

/// A herdr attach child is a pure viewer of server-side state and gets no graceful
/// teardown. Grace gave the dying client a window to misread teardown as keystrokes and
/// type them into the focused pane — the stray composer newline — so it is killed outright.
fn herdr_viewer_child(
    open: &TerminalOpen,
    agent_plan: Option<&crate::agent_route::AgentTerminalPlan>,
) -> bool {
    if let Some(plan) = agent_plan {
        return plan.provider == crate::host_protocol::ProviderKind::Herdr;
    }
    open.validated_target()
        .is_ok_and(|target| target.provider() == Some(crate::host_protocol::ProviderKind::Herdr))
}

/// Maps a fully validated `TerminalOpen` to its spawn task. Session targets resolve their
/// provider binary from the fixed directory list; a missing provider is rejected before any
/// process is spawned. The argv is always the fixed table from `workspace::target_command`.
fn spawn_terminal_child(
    open: &TerminalOpen,
    state: &Arc<RuntimeState>,
    agent_plan: Option<&crate::agent_route::AgentTerminalPlan>,
) -> Result<tokio::task::JoinHandle<Result<PtySession, PtyError>>, (&'static str, &'static str)> {
    let target = open
        .validated_target()
        .map_err(|_| invalid_target_error())?;
    if let Some(plan) = agent_plan {
        if target != crate::host_protocol::TerminalTarget::AgentRoute {
            return Err(invalid_target_error());
        }
        return Ok(tokio::spawn(PtySession::spawn_fixed_argv(
            open.dimensions,
            plan.program.clone(),
            plan.args.clone(),
        )));
    }
    if target == crate::host_protocol::TerminalTarget::AgentRoute {
        return Err((
            "stale_agent_route",
            "The Agent Session terminal route is no longer available.",
        ));
    }
    let Some(kind) = target.provider() else {
        return Ok(tokio::spawn(PtySession::spawn_login_shell(open.dimensions)));
    };
    let Some(binary) = state.workspace.resolve(kind) else {
        return Err((
            "provider_unavailable",
            "This session provider is not available on the Mac.",
        ));
    };
    let session = open.session.as_deref().ok_or_else(invalid_target_error)?;
    let account = resolve_account()
        .map_err(|_| ("pty_open_failed", "The Mac could not open the session."))?;
    let (program, args) = target_command(target, session, &binary, &account.home)
        .map_err(|_| invalid_target_error())?;
    Ok(tokio::spawn(PtySession::spawn_fixed_argv(
        open.dimensions,
        program,
        args,
    )))
}

async fn resolve_agent_terminal_plan(
    open: &TerminalOpen,
    state: &Arc<RuntimeState>,
) -> Result<Option<crate::agent_route::AgentTerminalPlan>, (&'static str, &'static str)> {
    let target = open
        .validated_target()
        .map_err(|_| invalid_target_error())?;
    if target != crate::host_protocol::TerminalTarget::AgentRoute {
        return Ok(None);
    }
    let route_id = open.session.as_deref().ok_or_else(invalid_target_error)?;
    let (session_id, generation) = state.agent_sessions.session_for_route(route_id).ok_or((
        "stale_agent_route",
        "The Agent Session terminal route is no longer available.",
    ))?;
    state
        .agent_sessions
        .terminal_plan(route_id, &session_id, generation)
        .await
        .map(Some)
        .ok_or((
            "stale_agent_route",
            "The Agent Session terminal route is no longer available.",
        ))
}

const fn invalid_target_error() -> (&'static str, &'static str) {
    ("invalid_target", "The requested session target is invalid.")
}

fn valid_rpc_request_id(body: &[u8]) -> Option<String> {
    let request_id = serde_json::from_slice::<Value>(body)
        .ok()?
        .as_object()?
        .get("request_id")?
        .as_str()?
        .to_owned();
    crate::host_protocol::validate_request_id(&request_id)
        .is_ok()
        .then_some(request_id)
}

fn reset_stream(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    code: u32,
) {
    let code = VarInt::from_u32(code);
    let _ = send.reset(code);
    let _ = recv.stop(code);
}

fn host_stream_reset_code(error: &HostProtocolError) -> u32 {
    match error {
        HostProtocolError::FrameTooLarge => crate::host_protocol::STREAM_FRAME_TOO_LARGE,
        HostProtocolError::InvalidDimensions
        | HostProtocolError::UnsupportedTarget
        | HostProtocolError::InvalidTarget => STREAM_TERMINAL_LIMIT,
        HostProtocolError::UnexpectedDirection | HostProtocolError::UnexpectedOrder => {
            STREAM_UNEXPECTED
        }
        HostProtocolError::Io(_) => STREAM_INTERNAL,
        _ => STREAM_MALFORMED,
    }
}

fn host_error_category(error: &anyhow::Error) -> &'static str {
    if error.downcast_ref::<HostProtocolError>().is_some() {
        "protocol"
    } else {
        "transport"
    }
}

async fn handle_pairing_connection(connection: Connection, state: Arc<RuntimeState>) {
    let remote_id = connection.remote_id();
    let result = handle_pairing_stream(&connection, remote_id, state).await;
    if result.is_err() {
        tracing::warn!(
            remote = %short_endpoint_id(remote_id),
            "pairing connection ended"
        );
    }
    connection.close(0_u32.into(), b"ciao pairing closed");
}

async fn handle_pairing_stream(
    connection: &Connection,
    remote_id: EndpointId,
    state: Arc<RuntimeState>,
) -> Result<()> {
    let (mut send, mut recv) = timeout(STREAM_OPEN_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| anyhow!("timed out waiting for pairing stream"))??;

    let first = match timeout(
        Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
        read_frame(&mut recv),
    )
    .await
    {
        Err(_) => return Err(anyhow!("timed out waiting for pair_request")),
        Ok(Err(error)) => {
            let (code, message) = protocol_rejection(&error);
            send_rejection(&mut send, code, message).await;
            return Err(error.into());
        }
        Ok(Ok(message)) => message,
    };

    let (pairing_id, capability, client_nonce, client_kex) = match first {
        WireMessage::PairRequest {
            v: PROTOCOL_VERSION,
            pairing_id,
            capability,
            client_nonce,
            client_kex,
        } => {
            let Some(pairing_id) = decode_exact::<16>(&pairing_id) else {
                send_rejection(
                    &mut send,
                    "malformed_request",
                    "Pairing request contains an invalid pairing ID.",
                )
                .await;
                return Ok(());
            };
            let Some(capability) = decode_exact::<32>(&capability) else {
                send_rejection(
                    &mut send,
                    "malformed_request",
                    "Pairing request contains an invalid capability.",
                )
                .await;
                return Ok(());
            };
            let Some(client_nonce) = decode_exact::<32>(&client_nonce) else {
                send_rejection(
                    &mut send,
                    "malformed_request",
                    "Pairing request contains an invalid nonce.",
                )
                .await;
                return Ok(());
            };
            let Some(client_kex) = decode_exact::<32>(&client_kex) else {
                send_rejection(
                    &mut send,
                    "malformed_request",
                    "Pairing request contains an invalid key share.",
                )
                .await;
                return Ok(());
            };
            (pairing_id, capability, client_nonce, client_kex)
        }
        _ => {
            send_rejection(
                &mut send,
                "malformed_request",
                "Expected pair_request as the first message.",
            )
            .await;
            return Ok(());
        }
    };

    let now = unix_now().map_err(anyhow::Error::msg)?;
    let rate_limit_result = { state.rate_limiter.lock().check(remote_id, now) };
    if let Err(error) = rate_limit_result {
        send_pairing_rejection(&mut send, error).await;
        return Ok(());
    }
    let claim_result = { state.pairing.lock().claim(&pairing_id, &capability, now) };
    let claim = match claim_result {
        Ok(claim) => claim,
        Err(error) => {
            send_pairing_rejection(&mut send, error).await;
            return Ok(());
        }
    };

    let server_nonce = rand::random::<[u8; 32]>();
    // Ephemeral per pairing attempt: the host's long-lived Iroh identity is never the key
    // agreement's secret, so a stolen host key cannot reconstruct any pairing's notification key.
    let server_kex_secret = rand::random::<[u8; 32]>();
    let host_bytes = endpoint_id_bytes(state.host_endpoint_id);
    let installation_bytes = endpoint_id_bytes(remote_id);
    let transcript_hash = pairing_transcript_hash(
        &claim.pairing_id,
        &claim.capability_hash,
        &host_bytes,
        &installation_bytes,
        &client_nonce,
        &server_nonce,
        claim.expires_at,
    );
    let commit_time = unix_now().map_err(anyhow::Error::msg)?;
    if commit_time >= claim.expires_at {
        state.pairing.lock().abort(&claim, commit_time);
        send_pairing_rejection(&mut send, PairingRejection::Expired).await;
        return Ok(());
    }

    // ADR 005: agree the notification key here, while the pair is face to face over the QR.
    // Only the two public shares cross the wire; the key itself never does.
    let Some(shared) = kex_shared(&server_kex_secret, &client_kex) else {
        state.pairing.lock().abort(&claim, commit_time);
        send_rejection(
            &mut send,
            "malformed_request",
            "Pairing request contains an unusable key share.",
        )
        .await;
        return Ok(());
    };
    let notification_key = notification_key(&shared, &transcript_hash);
    tracing::info!(
        remote = %short_endpoint_id(remote_id),
        fingerprint = %notification_key_fingerprint(&notification_key),
        "notification key agreed"
    );

    let persistence_result = {
        state.paired_devices.lock().upsert(
            remote_id,
            commit_time,
            &transcript_hash,
            &notification_key,
        )
    };
    if persistence_result.is_err() {
        state.pairing.lock().abort(&claim, commit_time);
        tracing::error!("paired-device persistence failed");
        send_rejection(
            &mut send,
            "persistence_failed",
            "Could not save paired-device authorization. Retry pairing.",
        )
        .await;
        return Ok(());
    }
    let completion_result = {
        state
            .pairing
            .lock()
            .complete(&claim, remote_id, commit_time)
    };
    if let Err(error) = completion_result {
        send_pairing_rejection(&mut send, error).await;
        return Ok(());
    }

    write_frame(
        &mut send,
        &WireMessage::PairAccepted {
            v: PROTOCOL_VERSION,
            host_endpoint_id: state.host_endpoint_id.to_string(),
            installation_endpoint_id: remote_id.to_string(),
            server_nonce: base64url(&server_nonce),
            expires_at: claim.expires_at,
            transcript_hash: base64url(&transcript_hash),
            heartbeat_interval_ms: HEARTBEAT_INTERVAL_MS,
            server_kex: base64url(&kex_public(&server_kex_secret)),
        },
    )
    .await?;

    process_heartbeats(&mut send, &mut recv, remote_id, &claim, state).await
}

async fn process_heartbeats(
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    remote_id: EndpointId,
    claim: &PairingClaim,
    state: Arc<RuntimeState>,
) -> Result<()> {
    let mut last_sequence = 0_u64;
    let mut active_lease = None;
    loop {
        let message = timeout(
            Duration::from_secs(HEARTBEAT_TIMEOUT_SECS),
            read_frame(recv),
        )
        .await
        .map_err(|_| anyhow!("heartbeat timed out"))??;
        let sequence = match message {
            WireMessage::Ping {
                v: PROTOCOL_VERSION,
                sequence,
            } if (last_sequence == 0 && sequence == 1)
                || (last_sequence != 0 && sequence > last_sequence) =>
            {
                sequence
            }
            _ => return Err(ProtocolError::UnexpectedMessageOrder.into()),
        };
        write_frame(
            send,
            &WireMessage::Pong {
                v: PROTOCOL_VERSION,
                sequence,
            },
        )
        .await?;
        last_sequence = sequence;
        if active_lease.is_none() {
            active_lease = Some(ActiveLease::new(state.clone(), remote_id));
            state
                .pairing
                .lock()
                .mark_connected(&claim.pairing_id, remote_id);
        }
    }
}

async fn send_pairing_rejection(
    send: &mut iroh::endpoint::SendStream,
    rejection: PairingRejection,
) {
    send_rejection(send, rejection.code(), rejection.safe_message()).await;
}

async fn send_rejection(send: &mut iroh::endpoint::SendStream, code: &str, message: &str) {
    let _ = write_frame(
        send,
        &WireMessage::PairRejected {
            v: PROTOCOL_VERSION,
            code: code.into(),
            message: message.into(),
        },
    )
    .await;
    if send.finish().is_ok() {
        // Avoid immediately closing the QUIC connection and discarding the rejection frame.
        let _ = timeout(Duration::from_secs(1), send.stopped()).await;
    }
}

fn protocol_rejection(error: &ProtocolError) -> (&'static str, &'static str) {
    match error {
        ProtocolError::UnsupportedVersion => (
            "unsupported_version",
            "This Ciao pairing protocol version is not supported.",
        ),
        _ => ("malformed_request", "Pairing request was malformed."),
    }
}

fn endpoint_id_bytes(endpoint_id: EndpointId) -> [u8; 32] {
    *endpoint_id.as_bytes()
}

fn unix_now() -> std::result::Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before the Unix epoch".into())
}

fn bounded_activity_label(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let marker = '…';
    let content_bytes = maximum_bytes.saturating_sub(marker.len_utf8());
    let mut result = String::new();
    for character in value.chars() {
        if result.len().saturating_add(character.len_utf8()) > content_bytes {
            break;
        }
        result.push(character);
    }
    result.push(marker);
    result
}

pub fn short_endpoint_id(endpoint_id: EndpointId) -> String {
    short_endpoint_text(&endpoint_id.to_string())
}

/// The same prefix taken from an endpoint ID already rendered as text, which is how the
/// admission tables hold it.
fn short_endpoint_text(endpoint: &str) -> String {
    endpoint.chars().take(10).collect()
}

async fn shutdown_signal() {
    let interrupt = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = interrupt => {},
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = interrupt.await;
    }
}

#[cfg(test)]
mod tests {
    /// The failure this replaced: a phone that backgrounded without closing its stream kept the
    /// endpoint's only slot, and every later open was refused with `subscription_limit` until
    /// the QUIC idle timeout expired. Superseding answers the live request and still never lets
    /// one device hold two slots.
    #[test]
    fn a_second_subscription_from_one_device_supersedes_rather_than_being_refused() {
        let mut admissions = ConnectionAdmissions::default();
        let phone = iroh::SecretKey::generate().public();

        let (endpoint, first) = admissions.try_add_superseding(phone, 16).unwrap();
        let (_, second) = admissions
            .try_add_superseding(phone, 16)
            .expect("the live request must be granted, not refused");
        assert_ne!(first, second);
        assert_eq!(admissions.total, 1, "one device must never hold two slots");

        // The superseded stream's own Drop still runs later; it must not free the slot the new
        // subscription is holding.
        admissions.remove(&endpoint, first);
        assert_eq!(admissions.total, 1);

        // A different device is unaffected by the eviction.
        let other = iroh::SecretKey::generate().public();
        admissions.try_add_superseding(other, 16).unwrap();
        assert_eq!(admissions.total, 2);

        // The global cap still refuses: superseding frees only this endpoint's own slots.
        let mut full = ConnectionAdmissions::default();
        for _ in 0..16 {
            full.try_add_superseding(iroh::SecretKey::generate().public(), 16)
                .unwrap();
        }
        assert!(
            full.try_add_superseding(iroh::SecretKey::generate().public(), 16)
                .is_none()
        );
    }

    use iroh::endpoint::ConnectionError;
    use tempfile::tempdir;

    use super::*;
    use crate::host_protocol::{
        Dimensions, MAX_ACTIVE_PTYS, MAX_ACTIVE_PTYS_PER_ENDPOINT, RpcResponse, TerminalOpen,
        decode_rpc_response, write_stream_preface,
    };
    use crate::uploads::{
        FRAME_PUT_ACCEPTED, FRAME_PUT_CANCEL, FRAME_PUT_CHUNK, FRAME_PUT_DONE, FRAME_PUT_ERROR,
        FRAME_PUT_FINISH, FRAME_PUT_OPEN, PutDone, PutError, PutOpen, encode_upload_control,
        encode_upload_frame,
    };

    fn test_state(
        host_endpoint_id: EndpointId,
        paired_path: &std::path::Path,
    ) -> Arc<RuntimeState> {
        test_state_with_workspace(
            host_endpoint_id,
            paired_path,
            WorkspaceConfig::for_home(std::path::Path::new("/nonexistent-test-home")),
        )
    }

    fn test_state_with_workspace(
        host_endpoint_id: EndpointId,
        paired_path: &std::path::Path,
        workspace: WorkspaceConfig,
    ) -> Arc<RuntimeState> {
        let agent_metadata = paired_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("agent-metadata.json");
        let agent_sessions =
            AgentSessionSupervisor::load(&agent_metadata, workspace.clone()).unwrap();
        let agent_managed = paired_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("agent-managed.json");
        let managed_sessions = ManagedSessionDirectory::load(
            &agent_managed,
            agent_managed
                .parent()
                .unwrap_or_else(|| std::path::Path::new(".")),
            ManagedLauncher::Fake(crate::managed_session::fake::FakeLauncher::default()),
        )
        .unwrap();
        let paired_devices = Arc::new(Mutex::new(PairedDeviceStore::load(paired_path).unwrap()));
        Arc::new(RuntimeState {
            codex_adoptions: Arc::new(crate::codex_adopted::AdoptionRegistry::default()),
            host_endpoint_id,
            online: AtomicBool::new(true),
            relay_known: AtomicBool::new(true),
            pairing: Mutex::new(PairingManager::default()),
            rate_limiter: Mutex::new(PairingRateLimiter::default()),
            paired_devices: paired_devices.clone(),
            notifier: Notifier::new(paired_devices, "fixture-host".into()),
            normal_connections: Mutex::new(ConnectionAdmissions::default()),
            host_connections: Mutex::new(HashMap::new()),
            active_ptys: Mutex::new(ConnectionAdmissions::default()),
            attached_sessions: Mutex::new(HashMap::new()),
            resumable_ptys: AtomicUsize::new(0),
            active_agent_subscriptions: Mutex::new(ConnectionAdmissions::default()),
            pairing_connections: AtomicUsize::new(0),
            decoded_host_prefaces: AtomicUsize::new(0),
            shutdown: watch::channel(false).0,
            active: Mutex::new(ActiveConnections::default()),
            workspace,
            // No pinned pair in a fixture, which is exactly the shape a machine that never ran
            // `ciao agent install claude` has: the probe resolves nothing and answers empty.
            managed_sdk_prefix: PathBuf::from("/nonexistent/ciao-fixture-sdk"),
            managed_worker_entrypoint: PathBuf::from("/nonexistent/ciao-fixture-worker.mjs"),
            agent_sessions,
            managed_sessions,
            managed_workers: Arc::new(WorkerTable::default()),
            host_info: HostInfoResult {
                v: HOST_PROTOCOL_VERSION,
                display_name: "fixture-host".into(),
                platform: "macos".into(),
                distribution: None,
                distribution_version: None,
                architecture: "aarch64".into(),
                machine_token: None,
                version: None,
            },
            uploads: crate::uploads::UploadStore::new(
                paired_path
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("uploads"),
            ),
        })
    }

    #[test]
    fn active_connections_count_distinct_endpoints() {
        let first = iroh::SecretKey::generate().public();
        let second = iroh::SecretKey::generate().public();
        let mut active = ActiveConnections::default();
        let (first_key, token_a) = active.add(first);
        let (_, token_b) = active.add(first);
        let (second_key, token_c) = active.add(second);
        assert_eq!(active.device_count(), 2);
        active.remove(&first_key, token_a);
        assert_eq!(active.device_count(), 2);
        active.remove(&first_key, token_b);
        assert_eq!(active.device_count(), 1);
        active.remove(&second_key, token_c);
        assert_eq!(active.device_count(), 0);
    }

    #[test]
    fn normal_connection_limits_are_global_and_per_endpoint() {
        let mut admissions = ConnectionAdmissions::default();
        let endpoint = iroh::SecretKey::generate().public();
        let first = admissions.try_add(endpoint).unwrap();
        let second = admissions.try_add(endpoint).unwrap();
        assert!(admissions.try_add(endpoint).is_none());

        let mut others = Vec::new();
        for _ in 0..(MAX_NORMAL_CONNECTIONS - 2) {
            let other = iroh::SecretKey::generate().public();
            others.push(admissions.try_add(other).unwrap());
        }
        assert_eq!(admissions.total, MAX_NORMAL_CONNECTIONS);
        assert!(
            admissions
                .try_add(iroh::SecretKey::generate().public())
                .is_none()
        );
        admissions.remove(&first.0, first.1);
        assert!(
            admissions
                .try_add(iroh::SecretKey::generate().public())
                .is_some()
        );
        admissions.remove(&second.0, second.1);
    }

    #[test]
    fn evicting_an_endpoint_supersedes_instead_of_refusing() {
        let mut admissions = ConnectionAdmissions::default();
        let endpoint = iroh::SecretKey::generate().public();
        let first = admissions.try_add(endpoint).unwrap();
        let second = admissions.try_add(endpoint).unwrap();
        assert!(admissions.try_add(endpoint).is_none());

        // The supersede path: evict frees exactly this endpoint's slots and returns their
        // tokens so the caller can close the stale connections they tracked.
        let evicted = admissions.evict_endpoint(&first.0);
        assert_eq!(evicted.len(), 2);
        assert!(evicted.contains(&first.1) && evicted.contains(&second.1));
        assert_eq!(admissions.total, 0);
        let third = admissions.try_add(endpoint).unwrap();

        // The evicted leases' Drop still runs later; token-keyed removal must not double-free
        // or touch the newcomer's slot.
        admissions.remove(&first.0, first.1);
        admissions.remove(&second.0, second.1);
        assert_eq!(admissions.total, 1);
        admissions.remove(&third.0, third.1);
        assert_eq!(admissions.total, 0);

        // A different device evicting nothing gains nothing: global exhaustion still refuses.
        assert!(admissions.evict_endpoint("unknown-endpoint").is_empty());
    }

    #[test]
    fn pty_limits_are_global_and_per_endpoint() {
        let mut admissions = ConnectionAdmissions::default();
        let endpoint = iroh::SecretKey::generate().public();
        assert!(
            admissions
                .try_add_with_limits(endpoint, MAX_ACTIVE_PTYS, MAX_ACTIVE_PTYS_PER_ENDPOINT)
                .is_some()
        );
        assert!(
            admissions
                .try_add_with_limits(endpoint, MAX_ACTIVE_PTYS, MAX_ACTIVE_PTYS_PER_ENDPOINT)
                .is_some()
        );
        assert!(
            admissions
                .try_add_with_limits(endpoint, MAX_ACTIVE_PTYS, MAX_ACTIVE_PTYS_PER_ENDPOINT)
                .is_none()
        );
        for _ in 0..(MAX_ACTIVE_PTYS - MAX_ACTIVE_PTYS_PER_ENDPOINT) {
            let other = iroh::SecretKey::generate().public();
            assert!(
                admissions
                    .try_add_with_limits(other, MAX_ACTIVE_PTYS, MAX_ACTIVE_PTYS_PER_ENDPOINT)
                    .is_some()
            );
        }
        assert_eq!(admissions.total, MAX_ACTIVE_PTYS);
        assert!(
            admissions
                .try_add_with_limits(
                    iroh::SecretKey::generate().public(),
                    MAX_ACTIVE_PTYS,
                    MAX_ACTIVE_PTYS_PER_ENDPOINT,
                )
                .is_none()
        );
    }

    #[test]
    fn relay_only_mode_is_exactly_opt_in_and_non_persistent() {
        assert_eq!(endpoint_mode(None), EndpointMode::Normal);
        assert_eq!(endpoint_mode(Some(OsStr::new(""))), EndpointMode::Normal);
        assert_eq!(
            endpoint_mode(Some(OsStr::new("true"))),
            EndpointMode::Normal
        );
        assert_eq!(
            endpoint_mode(Some(OsStr::new("1"))),
            EndpointMode::RelayOnlyTest
        );
        let plist = crate::service::launch_agent_plist(
            &CiaoPaths::for_home("/tmp/ciao-relay-mode-test"),
            std::path::Path::new("/tmp/ciao"),
        )
        .unwrap();
        assert!(!plist.contains(RELAY_ONLY_ENV));
    }

    #[test]
    fn pairing_ticket_keeps_relay_and_omits_direct_addresses() {
        let id = iroh::SecretKey::generate().public();
        let endpoint_addr = EndpointAddr::new(id)
            .with_relay_url("https://relay.example.invalid".parse().unwrap())
            .with_ip_addr("127.0.0.1:4242".parse().unwrap());
        let ticket = relay_only_pairing_ticket(endpoint_addr).unwrap();
        assert_eq!(ticket.endpoint_addr().id, id);
        assert_eq!(ticket.endpoint_addr().relay_urls().count(), 1);
        assert_eq!(ticket.endpoint_addr().ip_addrs().count(), 0);
    }

    #[test]
    fn endpoint_short_id_is_ten_characters() {
        let id = iroh::SecretKey::generate().public();
        let short = short_endpoint_id(id);
        assert_eq!(short.len(), 10);
        assert!(id.to_string().starts_with(&short));
    }

    /// Spec 015 §11.1: a preview arrives on its own stream, so the directory it resolves against
    /// is whichever session that device has a terminal on. Two different sessions is the case
    /// that must refuse — picking one could show a same-named file as if it were the right one.
    #[test]
    fn a_preview_borrows_a_directory_only_from_an_unambiguous_attachment() {
        let temp = tempdir().unwrap();
        let host_id = iroh::SecretKey::generate().public();
        let device = iroh::SecretKey::generate().public();
        let other_device = iroh::SecretKey::generate().public();
        let state = test_state(host_id, &temp.path().join("paired-devices.json"));
        let ciao = AttachedSession {
            kind: crate::host_protocol::ProviderKind::Herdr,
            name: "ciao".into(),
        };
        let boxes = AttachedSession {
            kind: crate::host_protocol::ProviderKind::Tmux,
            name: "boxes".into(),
        };

        assert_eq!(state.sole_attached_session(&device.to_string()), None);

        let one = PtyLease::try_new(state.clone(), device, true, Some(ciao.clone())).unwrap();
        assert_eq!(
            state.sole_attached_session(&device.to_string()),
            Some(ciao.clone())
        );

        // Another device's terminal is not this device's directory.
        let foreign =
            PtyLease::try_new(state.clone(), other_device, true, Some(boxes.clone())).unwrap();
        assert_eq!(
            state.sole_attached_session(&device.to_string()),
            Some(ciao.clone()),
            "one lease each, on different devices, is not ambiguous"
        );

        // A second lease on a *different* session is the ambiguity that refuses. Reachable, not
        // theoretical: MAX_ACTIVE_PTYS_PER_ENDPOINT is 2.
        let second = PtyLease::try_new(state.clone(), device, true, Some(boxes)).unwrap();
        assert_eq!(state.sole_attached_session(&device.to_string()), None);

        // Closing it restores an unambiguous answer.
        drop(second);
        assert_eq!(
            state.sole_attached_session(&device.to_string()),
            Some(ciao.clone())
        );

        // Two leases on the same session — a reattach whose predecessor has not finished
        // unwinding — still name one directory.
        let duplicate = PtyLease::try_new(state.clone(), device, true, Some(ciao.clone())).unwrap();
        assert_eq!(state.sole_attached_session(&device.to_string()), Some(ciao));

        // A shell terminal carries no session, and contributes no ambiguity either.
        drop((one, duplicate, foreign));
        let shell = PtyLease::try_new(state.clone(), device, false, None).unwrap();
        assert_eq!(state.sole_attached_session(&device.to_string()), None);
        drop(shell);
        assert!(
            state.attached_sessions.lock().is_empty(),
            "a dropped lease takes its session with it"
        );
    }

    /// `PathProbeWatch` table: host-side conviction of a one-way blackhole, so the rows are
    /// the shapes that must NOT convict — a healthy path, a loss burst QUIC recovers from on
    /// its own, a path that only just got selected — plus the dead path it exists for. The
    /// counter's own semantics (reset by any acknowledgement of the path) come from
    /// noq-proto; the lab blackhole is where those are proven, not here.
    #[test]
    fn path_probe_watch_convicts_only_a_path_the_transport_has_given_up_probing() {
        use std::time::{Duration, Instant};
        let t0 = Instant::now();
        let at = |secs: f64| t0 + Duration::from_secs_f64(secs);
        let direct = PathId::from(2u32);
        let relay = PathId::from(0u32);

        // Healthy: every sample answered.
        let mut watch = PathProbeWatch::default();
        assert_eq!(watch.observe(at(0.0), direct, 0).map(|(d, _)| d), None);
        assert_eq!(watch.observe(at(5.0), direct, 0).map(|(d, _)| d), None);
        assert_eq!(watch.observe(at(60.0), direct, 0).map(|(d, _)| d), None);

        // A burst inside QUIC's own recovery: the counter climbs and an ACK resets it.
        let mut watch = PathProbeWatch::default();
        assert_eq!(watch.observe(at(0.0), direct, 0).map(|(d, _)| d), None);
        assert_eq!(
            watch.observe(at(1.0), direct, 2).map(|(d, _)| d),
            None,
            "two probes is a burst"
        );
        assert_eq!(
            watch.observe(at(1.9), direct, 3).map(|(d, _)| d),
            None,
            "three, but under two seconds"
        );
        assert_eq!(
            watch.observe(at(2.5), direct, 0).map(|(d, _)| d),
            None,
            "answered: baseline moves here"
        );
        assert_eq!(
            watch.observe(at(4.4), direct, 3).map(|(d, _)| d),
            None,
            "1.9 s since that answer"
        );

        // Dead: three consecutive unanswered probes and more than two seconds since the last
        // answer — the transport has doubled its backoff twice and heard nothing.
        let mut watch = PathProbeWatch::default();
        assert_eq!(watch.observe(at(0.0), direct, 0).map(|(d, _)| d), None);
        assert_eq!(watch.observe(at(1.0), direct, 1).map(|(d, _)| d), None);
        assert_eq!(
            watch.observe(at(2.0), direct, 3).map(|(d, _)| d),
            Some(Duration::from_secs(2))
        );

        // The one-way signature is the caller's question, answered by `PathRxWatch`: a
        // suspended phone's last datagram, already in flight when it stopped, must not count,
        // and the phone still arriving on the path after it stopped answering (plus the
        // sampling slack) must.
        let mut heard = PathRxWatch::default();
        heard.note(at(0.0), direct, 10);
        heard.note(at(1.0), direct, 11); // the datagram in flight at the stop
        heard.note(at(2.0), direct, 11);
        heard.note(at(6.0), direct, 11);
        let stalled_at = at(0.5); // the path's last answered sample
        let slack = PathProbeWatch::HEARD_SLACK;
        assert!(
            !heard.heard_on_since(direct, stalled_at + slack),
            "suspended: not heard"
        );
        assert!(
            !heard.heard_on_since(relay, stalled_at + slack),
            "never seen at all"
        );
        heard.note(at(6.5), direct, 12); // the phone's next keep-alive still lands here
        assert!(
            heard.heard_on_since(direct, stalled_at + slack),
            "one-way: heard, unanswered"
        );

        // A low counter for a long time is not a conviction: something is being answered.
        let mut watch = PathProbeWatch::default();
        assert_eq!(watch.observe(at(0.0), direct, 0).map(|(d, _)| d), None);
        assert_eq!(
            watch.observe(at(9.0), direct, 2).map(|(d, _)| d),
            None,
            "never reached the bar"
        );

        // A selection change rebaselines rather than inheriting the old path's counter.
        let mut watch = PathProbeWatch::default();
        assert_eq!(watch.observe(at(0.0), direct, 0).map(|(d, _)| d), None);
        assert_eq!(watch.observe(at(1.0), direct, 3).map(|(d, _)| d), None);
        assert_eq!(
            watch.observe(at(1.5), relay, 5).map(|(d, _)| d),
            None,
            "new path, new baseline"
        );
        assert_eq!(
            watch.observe(at(3.4), relay, 5).map(|(d, _)| d),
            None,
            "1.9 s on the new path"
        );
        assert_eq!(
            watch.observe(at(3.5), relay, 5).map(|(d, _)| d),
            Some(Duration::from_secs(2))
        );
    }

    #[tokio::test]
    async fn unpaired_host_connection_is_rejected_before_stream_decoding() {
        let temp = tempdir().unwrap();
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(iroh::SecretKey::generate())
            .bind()
            .await
            .unwrap();
        let state = test_state(host_id, &temp.path().join("paired-devices.json"));
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });

        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
        let closed = timeout(Duration::from_secs(3), connection.closed())
            .await
            .unwrap();
        match closed {
            ConnectionError::ApplicationClosed(closed) => {
                assert_eq!(
                    closed.error_code,
                    VarInt::from_u32(CONNECTION_AUTHORIZATION_DENIED)
                );
            }
            other => panic!("unexpected close result: {other:?}"),
        }
        server.await.unwrap();
        assert_eq!(state.decoded_host_prefaces.load(Ordering::Relaxed), 0);
        assert_eq!(state.active.lock().device_count(), 0);
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn paired_host_hello_returns_both_authenticated_ids_and_tracks_active_state() {
        let temp = tempdir().unwrap();
        let paired_path = temp.path().join("paired-devices.json");
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state(host_id, &paired_path);
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[7; 32], &[0x5a; 32])
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });

        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
        assert_eq!(connection.remote_id(), host_id);
        assert_eq!(connection.alpn(), HOST_ALPN);
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut send, StreamKind::Rpc)
            .await
            .unwrap();
        let request = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        write_rpc(&mut send, &request).await.unwrap();
        send.finish().unwrap();
        let body = read_rpc_body(&mut recv).await.unwrap();
        let RpcResponse::Hello(response) = decode_rpc_response(&body).unwrap() else {
            panic!("expected hello response");
        };
        assert_eq!(response.result.host_endpoint_id, host_id.to_string());
        assert_eq!(
            response.result.installation_endpoint_id,
            installation_id.to_string()
        );
        assert_eq!(state.active.lock().device_count(), 1);

        let (mut terminal_send, mut terminal_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut terminal_send, StreamKind::Terminal)
            .await
            .unwrap();
        write_terminal_frame(
            &mut terminal_send,
            &TerminalFrame::Open(TerminalOpen {
                v: 1,
                target: "shell".into(),
                session: None,
                tab: None,
                dimensions: Dimensions {
                    cols: 80,
                    rows: 24,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            }),
        )
        .await
        .unwrap();
        let opened = read_terminal_frame(&mut terminal_recv).await.unwrap();
        assert!(matches!(opened, TerminalFrame::Opened(_)));
        write_terminal_frame(&mut terminal_send, &TerminalFrame::Close)
            .await
            .unwrap();
        terminal_send.finish().unwrap();
        loop {
            match read_terminal_frame(&mut terminal_recv).await.unwrap() {
                TerminalFrame::Output(_) => {}
                TerminalFrame::Exit(exit) => {
                    assert_eq!(exit.kind, "closed");
                    break;
                }
                other => panic!("unexpected terminal response: {other:?}"),
            }
        }

        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.active.lock().device_count(), 0);
        assert_eq!(state.decoded_host_prefaces.load(Ordering::Relaxed), 2);
        client.close().await;
        host.close().await;
    }

    async fn read_upload_host_frame(recv: &mut iroh::endpoint::RecvStream) -> (u8, Vec<u8>) {
        let mut header = [0_u8; 5];
        tokio::io::AsyncReadExt::read_exact(recv, &mut header)
            .await
            .unwrap();
        let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut payload = vec![0_u8; length];
        tokio::io::AsyncReadExt::read_exact(recv, &mut payload)
            .await
            .unwrap();
        (header[0], payload)
    }

    fn upload_open_frame(filename: &str, size: u64, sha256: &str) -> Vec<u8> {
        encode_upload_control(
            FRAME_PUT_OPEN,
            &PutOpen {
                v: 1,
                request_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into(),
                filename: filename.into(),
                source_kind: "file".into(),
                size,
                sha256: sha256.into(),
            },
        )
        .unwrap()
    }

    /// Drives the real accept path end to end: preface routing to the upload handler, the
    /// per-connection busy gate and its release, publication on disk, and the per-stream
    /// pairing re-check — everything the duplex-level tests in `uploads` cannot reach.
    #[tokio::test]
    async fn upload_stream_publishes_gates_concurrency_and_rechecks_pairing() {
        use sha2::{Digest, Sha256};

        let temp = tempdir().unwrap();
        let paired_path = temp.path().join("paired-devices.json");
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state(host_id, &paired_path);
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[7; 32], &[0x5a; 32])
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });

        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut send, StreamKind::Rpc)
            .await
            .unwrap();
        let request = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        write_rpc(&mut send, &request).await.unwrap();
        send.finish().unwrap();
        let body = read_rpc_body(&mut recv).await.unwrap();
        let RpcResponse::Hello(response) = decode_rpc_response(&body).unwrap() else {
            panic!("expected hello response");
        };
        assert!(
            response
                .result
                .capabilities
                .contains(&crate::host_protocol::CAPABILITY_FILE_PUT.to_string()),
            "hello must advertise file.put.v1"
        );

        // First upload holds the connection's one slot mid-transfer.
        let content = b"dispatch-level upload".to_vec();
        let sha256 = {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            hasher
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let (mut up_send, mut up_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut up_send, StreamKind::Upload)
            .await
            .unwrap();
        up_send
            .write_all(&upload_open_frame(
                "integration.bin",
                content.len() as u64,
                &sha256,
            ))
            .await
            .unwrap();
        let (frame_type, _) = read_upload_host_frame(&mut up_recv).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);

        // While it is active, a second upload stream is refused busy at dispatch — before the
        // host reads a single upload frame from it.
        let (mut busy_send, mut busy_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut busy_send, StreamKind::Upload)
            .await
            .unwrap();
        let (frame_type, payload) = read_upload_host_frame(&mut busy_recv).await;
        assert_eq!(frame_type, FRAME_PUT_ERROR);
        let error: PutError = serde_json::from_slice(&payload).unwrap();
        assert_eq!(error.code, "busy");
        drop(busy_send);
        drop(busy_recv);

        // The first transfer completes and publishes under the state directory.
        up_send
            .write_all(&encode_upload_frame(FRAME_PUT_CHUNK, &content).unwrap())
            .await
            .unwrap();
        up_send
            .write_all(&encode_upload_frame(FRAME_PUT_FINISH, b"").unwrap())
            .await
            .unwrap();
        up_send.finish().unwrap();
        let (frame_type, payload) = read_upload_host_frame(&mut up_recv).await;
        assert_eq!(frame_type, FRAME_PUT_DONE);
        let done: PutDone = serde_json::from_slice(&payload).unwrap();
        assert!(done.host_path.ends_with("-integration.bin"));
        assert!(
            done.host_path
                .starts_with(&temp.path().join("uploads").to_string_lossy().into_owned())
        );
        assert_eq!(fs::read(&done.host_path).unwrap(), content);
        assert_eq!(done.prompt_reference, format!("'{}'", done.host_path));
        drop(up_send);
        drop(up_recv);

        // The finished handler releases the gate; a fresh upload stream is accepted again.
        // Retried briefly because release happens when the handler task ends, a moment after
        // put_done is on the wire.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (mut next_send, mut next_recv) = connection.open_bi().await.unwrap();
            write_stream_preface(&mut next_send, StreamKind::Upload)
                .await
                .unwrap();
            next_send
                .write_all(&upload_open_frame("second.bin", 4, &"0".repeat(64)))
                .await
                .unwrap();
            let (frame_type, payload) = read_upload_host_frame(&mut next_recv).await;
            if frame_type == FRAME_PUT_ERROR {
                let error: PutError = serde_json::from_slice(&payload).unwrap();
                assert_eq!(error.code, "busy");
                assert!(
                    Instant::now() < deadline,
                    "the upload gate never released after put_done"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
            next_send
                .write_all(&encode_upload_frame(FRAME_PUT_CANCEL, b"").unwrap())
                .await
                .unwrap();
            let (frame_type, payload) = read_upload_host_frame(&mut next_recv).await;
            assert_eq!(frame_type, FRAME_PUT_ERROR);
            let error: PutError = serde_json::from_slice(&payload).unwrap();
            assert_eq!(error.code, "cancelled");
            break;
        }

        // Revoking the pairing mid-connection: the per-stream re-check refuses the next upload
        // in-protocol. Also retried, because the cancelled handler above releases its lease a
        // moment after replying and the gate check runs before the pairing re-check.
        state
            .paired_devices
            .lock()
            .remove(&installation_id.to_string())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let (mut revoked_send, mut revoked_recv) = connection.open_bi().await.unwrap();
            write_stream_preface(&mut revoked_send, StreamKind::Upload)
                .await
                .unwrap();
            let (frame_type, payload) = read_upload_host_frame(&mut revoked_recv).await;
            assert_eq!(frame_type, FRAME_PUT_ERROR);
            let error: PutError = serde_json::from_slice(&payload).unwrap();
            if error.code == "busy" {
                assert!(
                    Instant::now() < deadline,
                    "the upload gate never released after cancel"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
            assert_eq!(error.code, "invalid");
            assert_eq!(error.message, "This installation is no longer authorized.");
            break;
        }

        connection.close(0_u32.into(), b"test done");
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn coalesced_second_rpc_request_is_rejected_before_ready_state() {
        let temp = tempdir().unwrap();
        let paired_path = temp.path().join("paired-devices.json");
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state(host_id, &paired_path);
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[9; 32], &[0x5a; 32])
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });

        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut send, StreamKind::Rpc)
            .await
            .unwrap();
        let request = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        write_rpc(&mut send, &request).await.unwrap();
        write_rpc(&mut send, &request).await.unwrap();
        send.finish().unwrap();

        let body = read_rpc_body(&mut recv).await.unwrap();
        let RpcResponse::Error(response) = decode_rpc_response(&body).unwrap() else {
            panic!("expected malformed-request response");
        };
        assert_eq!(response.error.code, "malformed_request");
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.active.lock().device_count(), 0);
        assert_eq!(state.decoded_host_prefaces.load(Ordering::Relaxed), 1);
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn active_status_deduplicates_pairing_and_normal_overlap() {
        let temp = tempdir().unwrap();
        let endpoint = iroh::SecretKey::generate().public();
        let host = iroh::SecretKey::generate().public();
        let state = test_state(host, &temp.path().join("paired-devices.json"));
        let pairing = ActiveLease::new(state.clone(), endpoint);
        let normal = ActiveLease::new(state.clone(), endpoint);
        assert_eq!(state.status().active_connections, Some(1));
        drop(pairing);
        assert_eq!(state.status().active_connections, Some(1));
        drop(normal);
        assert_eq!(state.status().active_connections, Some(0));
    }

    #[tokio::test]
    async fn real_iroh_pairing_requires_receipt_and_ping_before_active() {
        let temp = tempdir().unwrap();
        let paired_path = temp.path().join("paired-devices.json");
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![PAIRING_ALPN.to_vec()])
            .bind()
            .await
            .unwrap();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state(host_id, &paired_path);
        let now = unix_now().unwrap();
        let offer = state.pairing.lock().create(now).unwrap();

        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_pairing_connection(connection, state).await;
            }
        });

        let connection = client.connect(host.addr(), PAIRING_ALPN).await.unwrap();
        assert_eq!(connection.remote_id(), host_id);
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let client_nonce = [7_u8; 32];
        let client_kex_secret = [11_u8; 32];
        write_frame(
            &mut send,
            &WireMessage::PairRequest {
                v: 1,
                pairing_id: base64url(&offer.pairing_id),
                capability: base64url(&offer.capability),
                client_nonce: base64url(&client_nonce),
                client_kex: base64url(&kex_public(&client_kex_secret)),
            },
        )
        .await
        .unwrap();
        let accepted = read_frame(&mut recv).await.unwrap();
        let (server_nonce, transcript, expires_at, server_kex) = match accepted {
            WireMessage::PairAccepted {
                host_endpoint_id,
                installation_endpoint_id,
                server_nonce,
                transcript_hash,
                expires_at,
                heartbeat_interval_ms,
                server_kex,
                ..
            } => {
                assert_eq!(host_endpoint_id, host_id.to_string());
                assert_eq!(installation_endpoint_id, installation_id.to_string());
                assert_eq!(heartbeat_interval_ms, HEARTBEAT_INTERVAL_MS);
                (
                    decode_exact::<32>(&server_nonce).unwrap(),
                    decode_exact::<32>(&transcript_hash).unwrap(),
                    expires_at,
                    decode_exact::<32>(&server_kex).unwrap(),
                )
            }
            other => panic!("expected pair_accepted, got {other:?}"),
        };
        let expected = pairing_transcript_hash(
            &offer.pairing_id,
            &crate::pairing::capability_hash(&offer.capability),
            &endpoint_id_bytes(host_id),
            &endpoint_id_bytes(installation_id),
            &client_nonce,
            &server_nonce,
            expires_at,
        );
        assert_eq!(transcript, expected);
        assert_eq!(state.paired_devices.lock().len(), 1);
        assert_eq!(state.active.lock().device_count(), 0);

        // The device derives the notification key from the host's share alone, and lands on the
        // bytes the host persisted (ADR 005 step 2).
        let derived = notification_key(
            &kex_shared(&client_kex_secret, &server_kex).unwrap(),
            &transcript,
        );
        assert_eq!(
            state.paired_devices.lock().devices()[0].notification_key,
            Some(base64url(&derived))
        );
        // The file that now holds it stays owner-only.
        crate::storage::validate_private_file(&paired_path).unwrap();

        write_frame(&mut send, &WireMessage::Ping { v: 1, sequence: 1 })
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut recv).await.unwrap(),
            WireMessage::Pong { v: 1, sequence: 1 }
        );
        assert_eq!(state.active.lock().device_count(), 1);
        let status = state
            .pairing
            .lock()
            .status(&encoded_pairing_id(&offer.pairing_id), now);
        assert_eq!(status.state, "connected");

        connection.close(0_u32.into(), b"test complete");
        timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.active.lock().device_count(), 0);
        client.close().await;
        host.close().await;
    }

    use crate::host_protocol::{
        CAPABILITY_NOTIFICATIONS_REGISTER, CAPABILITY_TERMINAL_HERDR, CAPABILITY_TERMINAL_TMUX,
        CAPABILITY_WORKSPACE_SNAPSHOT, CAPABILITY_WORKSPACE_TABS, SnapshotRpcResponse,
        WorkspaceSnapshotRequest, decode_snapshot_response, encode_rpc,
    };

    fn write_stub(directory: &std::path::Path, name: &str, script: &str) {
        let path = directory.join(name);
        fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    async fn open_rpc_stream(connection: &iroh::endpoint::Connection, body: &[u8]) -> Vec<u8> {
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut send, StreamKind::Rpc)
            .await
            .unwrap();
        send.write_all(body).await.unwrap();
        send.finish().unwrap();
        read_rpc_body(&mut recv).await.unwrap()
    }

    #[tokio::test]
    async fn snapshot_requires_hello_answers_unknown_methods_and_serializes_busy() {
        let temp = tempdir().unwrap();
        let stub_dir = tempdir().unwrap();
        // The tmux listing takes ~1 s so a concurrent second snapshot observes `busy`.
        write_stub(
            stub_dir.path(),
            "tmux",
            "if [ \"$1\" = \"-V\" ]; then echo 'tmux 3.6b'; else sleep 1; \
             printf 'api\\0371\\0373\\0371789000000\\n'; fi",
        );
        write_stub(
            stub_dir.path(),
            "herdr",
            "if [ \"$1\" = \"--version\" ]; then echo 'herdr 0.7.4'; else \
             echo '{\"sessions\":[{\"default\":true,\"name\":\"default\",\"running\":true}]}'; fi",
        );

        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state_with_workspace(
            host_id,
            &temp.path().join("paired-devices.json"),
            WorkspaceConfig::with_binary_dirs(vec![stub_dir.path().to_owned()]),
        );
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[3; 32], &[0x5a; 32])
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });
        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();

        // 1. workspace.snapshot before hello → not_ready, and the connection survives.
        let snapshot_request = encode_rpc(&WorkspaceSnapshotRequest::new(
            "AAECAwQFBgcICQoLDA0ODw".into(),
        ))
        .unwrap();
        let body = open_rpc_stream(&connection, &snapshot_request).await;
        let SnapshotRpcResponse::Error(error) = decode_snapshot_response(&body).unwrap() else {
            panic!("expected not_ready error before hello");
        };
        assert_eq!(error.error.code, "not_ready");

        // 2. An unknown method → method_unknown, still without closing the connection.
        let unknown = {
            let body = br#"{"v":1,"type":"request","request_id":"AAECAwQFBgcICQoLDA0ODw","method":"shell.exec","params":{}}"#;
            let mut encoded = Vec::new();
            encoded.extend_from_slice(&(body.len() as u32).to_be_bytes());
            encoded.extend_from_slice(body);
            encoded
        };
        let body = open_rpc_stream(&connection, &unknown).await;
        let SnapshotRpcResponse::Error(error) = decode_snapshot_response(&body).unwrap() else {
            panic!("expected method_unknown error");
        };
        assert_eq!(error.error.code, "method_unknown");

        // 3. hello succeeds and advertises the Phase 2 capabilities.
        let hello = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        let body = open_rpc_stream(&connection, &encode_rpc(&hello).unwrap()).await;
        let RpcResponse::Hello(response) = decode_rpc_response(&body).unwrap() else {
            panic!("expected hello response");
        };
        for capability in [
            CAPABILITY_WORKSPACE_SNAPSHOT,
            CAPABILITY_TERMINAL_TMUX,
            CAPABILITY_TERMINAL_HERDR,
            CAPABILITY_WORKSPACE_TABS,
        ] {
            assert!(response.result.capabilities.iter().any(|c| c == capability));
        }

        // 4. Two concurrent snapshots: exactly one succeeds, the other is busy.
        let first = tokio::spawn({
            let connection = connection.clone();
            let request = snapshot_request.clone();
            async move { open_rpc_stream(&connection, &request).await }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let second_body = open_rpc_stream(&connection, &snapshot_request).await;
        let second = decode_snapshot_response(&second_body).unwrap();
        let first_body = timeout(Duration::from_secs(10), first)
            .await
            .unwrap()
            .unwrap();
        let first = decode_snapshot_response(&first_body).unwrap();
        let (snapshot, busy) = match (first, second) {
            (SnapshotRpcResponse::Snapshot(snapshot), SnapshotRpcResponse::Error(busy)) => {
                (snapshot, busy)
            }
            (SnapshotRpcResponse::Error(busy), SnapshotRpcResponse::Snapshot(snapshot)) => {
                (snapshot, busy)
            }
            other => panic!("expected one snapshot and one busy, got {other:?}"),
        };
        assert_eq!(busy.error.code, "busy");
        assert_eq!(
            snapshot.result.providers.tmux.state,
            crate::host_protocol::PROVIDER_STATE_AVAILABLE
        );
        assert_eq!(
            snapshot
                .result
                .providers
                .tmux
                .sessions
                .as_ref()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            snapshot.result.providers.herdr.sessions.as_ref().unwrap()[0].name,
            "default"
        );

        // 5. Revocation after hello is re-checked immediately before provider execution.
        *state.paired_devices.lock() =
            PairedDeviceStore::load(temp.path().join("revoked-devices.json")).unwrap();
        let body = open_rpc_stream(&connection, &snapshot_request).await;
        let SnapshotRpcResponse::Error(error) = decode_snapshot_response(&body).unwrap() else {
            panic!("expected authorization error after revocation");
        };
        assert_eq!(error.error.code, "authorization_denied");

        connection.close(0_u32.into(), b"test complete");
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn a_push_ticket_is_stored_revoked_and_rechecked_against_the_allowlist() {
        use crate::host_protocol::{
            LiveActivityRegisterRequest, LiveActivityRpcResponse, LiveActivitySelectionMutation,
            NotificationsRegisterRequest, NotificationsRpcResponse, decode_live_activity_response,
            decode_notifications_response,
        };

        let temp = tempdir().unwrap();
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state(host_id, &temp.path().join("paired-devices.json"));
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[3; 32], &[0x5a; 32])
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });
        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();

        let ticket = "T".repeat(140);
        let register = |ticket: Option<&str>| {
            encode_rpc(&NotificationsRegisterRequest::new(
                "AAECAwQFBgcICQoLDA0ODw".into(),
                ticket.map(str::to_owned),
            ))
            .unwrap()
        };
        let register_activity = || {
            encode_rpc(&LiveActivityRegisterRequest::new(
                "AAECAwQFBgcICQoLDA0ODw".into(),
                Some(ticket.clone()),
                Some(LiveActivitySelectionMutation {
                    session_id: "session-probe".into(),
                    enabled: true,
                }),
            ))
            .unwrap()
        };

        // Registration before hello is refused like every other post-hello method.
        let body = open_rpc_stream(&connection, &register(Some(&ticket))).await;
        let NotificationsRpcResponse::Error(error) = decode_notifications_response(&body).unwrap()
        else {
            panic!("expected not_ready before hello");
        };
        assert_eq!(error.error.code, "not_ready");
        assert!(state.paired_devices.lock().push_targets().is_empty());
        let body = open_rpc_stream(&connection, &register_activity()).await;
        let LiveActivityRpcResponse::Error(error) = decode_live_activity_response(&body).unwrap()
        else {
            panic!("expected live activity not_ready before hello");
        };
        assert_eq!(error.error.code, "not_ready");

        let hello = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        let body = open_rpc_stream(&connection, &encode_rpc(&hello).unwrap()).await;
        let RpcResponse::Hello(response) = decode_rpc_response(&body).unwrap() else {
            panic!("expected hello response");
        };
        assert!(
            response
                .result
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_NOTIFICATIONS_REGISTER)
        );
        assert!(response.result.capabilities.iter().any(|capability| {
            capability == crate::host_protocol::CAPABILITY_LIVE_ACTIVITY_REGISTER
        }));

        let body = open_rpc_stream(&connection, &register(Some(&ticket))).await;
        let NotificationsRpcResponse::Registered(accepted) =
            decode_notifications_response(&body).unwrap()
        else {
            panic!("expected the ticket to be accepted");
        };
        assert!(accepted.result.registered);
        assert_eq!(
            state.paired_devices.lock().push_targets(),
            vec![(ticket.clone(), Some([0x5a; 32]))]
        );
        // It survives a reload: a daemon restart must not silently stop notifying.
        assert_eq!(
            PairedDeviceStore::load(temp.path().join("paired-devices.json"))
                .unwrap()
                .push_targets()
                .len(),
            1
        );

        // No ticket revokes, and the response says so without ever echoing a ticket back.
        let body = open_rpc_stream(&connection, &register(None)).await;
        let NotificationsRpcResponse::Registered(revoked) =
            decode_notifications_response(&body).unwrap()
        else {
            panic!("expected the revocation to be accepted");
        };
        assert!(!revoked.result.registered);
        assert!(state.paired_devices.lock().push_targets().is_empty());

        // A device dropped from the allowlist cannot leave a ticket behind on its way out.
        *state.paired_devices.lock() =
            PairedDeviceStore::load(temp.path().join("revoked-devices.json")).unwrap();
        let body = open_rpc_stream(&connection, &register(Some(&ticket))).await;
        let NotificationsRpcResponse::Error(error) = decode_notifications_response(&body).unwrap()
        else {
            panic!("expected authorization error after revocation");
        };
        assert_eq!(error.error.code, "authorization_denied");
        assert!(state.paired_devices.lock().push_targets().is_empty());
        // The revocation check precedes session resolution, so an old connection cannot probe
        // whether an opaque Agent Session ID exists.
        let body = open_rpc_stream(&connection, &register_activity()).await;
        let LiveActivityRpcResponse::Error(error) = decode_live_activity_response(&body).unwrap()
        else {
            panic!("expected live activity authorization error after revocation");
        };
        assert_eq!(error.error.code, "authorization_denied");

        connection.close(0_u32.into(), b"test complete");
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        client.close().await;
        host.close().await;
    }

    async fn read_agent_server(recv: &mut iroh::endpoint::RecvStream) -> AgentServerFrame {
        decode_agent_body(&read_agent_frame(recv).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn real_agent_bridge_lists_snapshots_streams_and_rechecks_authorization() {
        use crate::agent_protocol::{
            AgentCommand, AgentCommandKind, AgentStreamOpen, CAPABILITY_AGENT_SESSION_V1,
        };

        let temp = tempdir().unwrap();
        let paired_path = temp.path().join("paired-devices.json");
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state(host_id, &paired_path);
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[8; 32], &[0x5a; 32])
            .unwrap();

        // A real same-user full-duplex Unix stream exercises registration, peer PID validation,
        // snapshot order, and the adapter-neutral supervisor boundary.
        let (daemon_bridge, mut adapter_bridge) = UnixStream::pair().unwrap();
        let bridge_task = tokio::spawn({
            let state = state.clone();
            async move { handle_agent_bridge(daemon_bridge, state).await }
        });
        write_agent_frame(
            &mut adapter_bridge,
            &serde_json::json!({
                "v": 1,
                "type": "register",
                "adapter": "pi",
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
            }),
        )
        .await
        .unwrap();
        let registered_value: serde_json::Value =
            decode_agent_body(&read_agent_frame(&mut adapter_bridge).await.unwrap()).unwrap();
        assert_eq!(registered_value["type"], "registered");
        let session_id = registered_value["session_id"].as_str().unwrap().to_owned();
        write_agent_frame(
            &mut adapter_bridge,
            &serde_json::json!({"v": 1, "type": "snapshot_start"}),
        )
        .await
        .unwrap();
        write_agent_frame(
            &mut adapter_bridge,
            &serde_json::json!({
                "v": 1,
                "type": "snapshot_entry",
                "entry": {
                    "source_id": "fixture-entry",
                    "source_revision": 1,
                    "timestamp": 1,
                    "state": "complete",
                    "kind": "assistant_message",
                    "body": { "type": "text", "text": "Synthetic bridge text." },
                    "truncation": { "truncated": false }
                }
            }),
        )
        .await
        .unwrap();
        write_agent_frame(
            &mut adapter_bridge,
            &serde_json::json!({"v": 1, "type": "snapshot_end"}),
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(2), async {
            loop {
                if state
                    .agent_sessions
                    .snapshot(&session_id)
                    .is_some_and(|snapshot| !snapshot.timeline_window.entries.is_empty())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });
        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
        let hello = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        let body = open_rpc_stream(&connection, &encode_rpc(&hello).unwrap()).await;
        let RpcResponse::Hello(response) = decode_rpc_response(&body).unwrap() else {
            panic!("expected hello response");
        };
        assert!(
            response
                .result
                .capabilities
                .iter()
                .any(|capability| capability == CAPABILITY_AGENT_SESSION_V1)
        );

        let open = |operation: &str, session: Option<String>| AgentStreamOpen {
            v: 1,
            message_type: "agent_stream_open".into(),
            client_instance_id: "0123456789abcdef0123456789abcdef".into(),
            operation: operation.into(),
            capabilities: vec![CAPABILITY_AGENT_SESSION_V1.into()],
            session_id: session,
            before_sequence: None,
            page_limit: None,
            workspace_id: None,
            lifecycle_command_id: None,
            expected_generation: None,
        };

        let (mut list_send, mut list_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut list_send, StreamKind::Agent)
            .await
            .unwrap();
        write_agent_frame(&mut list_send, &open("agent.sessions.list", None))
            .await
            .unwrap();
        list_send.finish().unwrap();
        assert!(matches!(
            read_agent_server(&mut list_recv).await,
            AgentServerFrame::StreamAccepted { .. }
        ));
        let AgentServerFrame::SessionList { sessions, .. } =
            read_agent_server(&mut list_recv).await
        else {
            panic!("expected Agent Session list");
        };
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, session_id);
        assert_eq!(sessions[0].observation.coverage, "partial");

        let (mut subscription_send, mut subscription_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut subscription_send, StreamKind::Agent)
            .await
            .unwrap();
        write_agent_frame(
            &mut subscription_send,
            &open("agent.session.subscribe", Some(session_id.clone())),
        )
        .await
        .unwrap();
        assert!(matches!(
            read_agent_server(&mut subscription_recv).await,
            AgentServerFrame::StreamAccepted { .. }
        ));
        let AgentServerFrame::SessionSnapshot { snapshot, .. } =
            read_agent_server(&mut subscription_recv).await
        else {
            panic!("expected complete subscription snapshot");
        };
        assert_eq!(snapshot.timeline_window.entries.len(), 1);
        assert!(!snapshot.turn.is_authoritative_working());

        // The explicit grounded run executes this integration test inside a real tmux pane. It
        // proves the authenticated Iroh command is forwarded only after exact pane/TTY/ancestry
        // revalidation, then correlates the adapter's categorical application receipt.
        if std::env::var_os("CIAO_TEST_SYSTEM_TMUX").is_some() {
            assert_eq!(snapshot.terminal_fallback.continuity, "exact_live");
            let command_id = "11111111111111111111111111111111";
            write_agent_frame(
                &mut subscription_send,
                &AgentClientFrame::CommandSubmit {
                    command: AgentCommand {
                        v: 1,
                        command_id: command_id.into(),
                        session_id: session_id.clone(),
                        snapshot_epoch: snapshot.snapshot_epoch,
                        expected_generation: snapshot.process_generation,
                        expected_revision: Some(snapshot.revision),
                        kind: AgentCommandKind::Prompt {
                            text: "Synthetic correlated command.".into(),
                        },
                    },
                },
            )
            .await
            .unwrap();
            let forwarded: serde_json::Value = decode_agent_body(
                &timeout(
                    Duration::from_secs(2),
                    read_agent_frame(&mut adapter_bridge),
                )
                .await
                .unwrap()
                .unwrap(),
            )
            .unwrap();
            assert_eq!(forwarded["type"], "command");
            assert_eq!(forwarded["kind"], "prompt");
            assert_eq!(forwarded["command_id"], command_id);
            for (state_name, evidence) in [("accepted", None), ("applied", Some("pi_input_event"))]
            {
                write_agent_frame(
                    &mut adapter_bridge,
                    &serde_json::json!({
                        "v": 1,
                        "type": "command_receipt",
                        "command_id": command_id,
                        "state": state_name,
                        "evidence": evidence,
                    }),
                )
                .await
                .unwrap();
            }
            let mut saw_accepted = false;
            loop {
                let frame = timeout(
                    Duration::from_secs(2),
                    read_agent_server(&mut subscription_recv),
                )
                .await
                .unwrap();
                if let AgentServerFrame::CommandReceipt { receipt, .. } = frame {
                    if receipt.command_id != command_id {
                        continue;
                    }
                    saw_accepted |= receipt.state == "accepted";
                    if receipt.state == "applied" {
                        assert_eq!(
                            receipt.application_evidence.as_deref(),
                            Some("pi_input_event")
                        );
                        break;
                    }
                }
            }
            assert!(saw_accepted);
        }

        // A waiting Agent subscription has independent stream/task flow control and cannot block
        // an ordinary host RPC on the same authenticated connection.
        let rpc = encode_rpc(&WorkspaceSnapshotRequest::new(
            "AAECAwQFBgcICQoLDA0ODw".into(),
        ))
        .unwrap();
        let rpc_body = timeout(Duration::from_secs(2), open_rpc_stream(&connection, &rpc))
            .await
            .unwrap();
        assert!(matches!(
            decode_snapshot_response(&rpc_body).unwrap(),
            SnapshotRpcResponse::Snapshot(_)
        ));

        // One paired device owns at most one live subscription, keeping its queue at 1 MiB —
        // enforced by superseding, not by refusing. The device asking is the one in the user's
        // hand; the subscription it is replacing is its own, and on iOS it frequently cannot be
        // closed from the client side at all (ADR 002), so refusing here turned a backgrounded
        // app into a session that would not open until the QUIC idle timeout expired.
        let (mut second_send, mut second_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut second_send, StreamKind::Agent)
            .await
            .unwrap();
        write_agent_frame(
            &mut second_send,
            &open("agent.session.subscribe", Some(session_id.clone())),
        )
        .await
        .unwrap();
        assert!(
            matches!(
                read_agent_server(&mut second_recv).await,
                AgentServerFrame::StreamAccepted { .. }
            ),
            "a device re-subscribing must supersede its own stream, not be refused"
        );

        write_agent_frame(
            &mut adapter_bridge,
            &serde_json::json!({
                "v": 1,
                "type": "upsert_entry",
                "entry": {
                    "source_id": "fixture-entry",
                    "source_revision": 2,
                    "timestamp": 2,
                    "state": "complete",
                    "kind": "assistant_message",
                    "body": { "type": "text", "text": "Synthetic replacement." },
                    "truncation": { "truncated": false }
                }
            }),
        )
        .await
        .unwrap();
        let AgentServerFrame::SessionDelta { delta, .. } =
            read_agent_server(&mut subscription_recv).await
        else {
            panic!("expected live canonical delta");
        };
        assert_eq!(delta.session_id, session_id);

        // Managed lifecycle operations ride the same authorized agent stream; the
        // fake launcher stands in for the step-6 worker.
        let workspace_dir = temp.path().join("managed-workspace");
        std::fs::create_dir_all(&workspace_dir).unwrap();
        let started = state
            .managed_sessions
            .managed_start_at_path(&workspace_dir, "33333333333333333333333333333333")
            .await;
        assert_eq!(started.state, "accepted");
        let managed_id = started.session_id.clone().unwrap();
        let managed_open = |operation: &str| AgentStreamOpen {
            capabilities: vec![
                CAPABILITY_AGENT_SESSION_V1.into(),
                crate::agent_protocol::CAPABILITY_AGENT_SESSION_MANAGED_V1.into(),
            ],
            ..open(operation, None)
        };

        let (mut workspace_send, mut workspace_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut workspace_send, StreamKind::Agent)
            .await
            .unwrap();
        write_agent_frame(&mut workspace_send, &managed_open("agent.workspaces.list"))
            .await
            .unwrap();
        workspace_send.finish().unwrap();
        assert!(matches!(
            read_agent_server(&mut workspace_recv).await,
            AgentServerFrame::StreamAccepted { .. }
        ));
        let AgentServerFrame::WorkspaceList { workspaces, .. } =
            read_agent_server(&mut workspace_recv).await
        else {
            panic!("expected workspace list");
        };
        assert_eq!(workspaces.len(), 1);
        // The opaque workspace ID and bounded label carry no raw path. A label may now carry one
        // parent directory to tell two same-named projects apart, so the rule is no longer "no
        // separator" — it is that nothing absolute and nothing naming the account ever ships.
        assert!(!workspaces[0].workspace_id.contains("workspace"));
        assert!(!workspaces[0].display_label.starts_with('/'));
        assert!(workspaces[0].display_label.matches('/').count() <= 1);

        let (mut stop_send, mut stop_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut stop_send, StreamKind::Agent)
            .await
            .unwrap();
        let mut stop_open = managed_open("agent.managed.stop");
        stop_open.session_id = Some(managed_id.clone());
        stop_open.lifecycle_command_id = Some("44444444444444444444444444444444".into());
        stop_open.expected_generation = Some(1);
        write_agent_frame(&mut stop_send, &stop_open).await.unwrap();
        stop_send.finish().unwrap();
        assert!(matches!(
            read_agent_server(&mut stop_recv).await,
            AgentServerFrame::StreamAccepted { .. }
        ));
        let AgentServerFrame::LifecycleOutcome { outcome, .. } =
            read_agent_server(&mut stop_recv).await
        else {
            panic!("expected a lifecycle outcome");
        };
        assert_eq!(outcome.state, "accepted");

        // A managed-capability list shows the stored session; a legacy peer never
        // receives a managed descriptor.
        let (mut managed_list_send, mut managed_list_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut managed_list_send, StreamKind::Agent)
            .await
            .unwrap();
        write_agent_frame(&mut managed_list_send, &managed_open("agent.sessions.list"))
            .await
            .unwrap();
        managed_list_send.finish().unwrap();
        assert!(matches!(
            read_agent_server(&mut managed_list_recv).await,
            AgentServerFrame::StreamAccepted { .. }
        ));
        let AgentServerFrame::SessionList { sessions, .. } =
            read_agent_server(&mut managed_list_recv).await
        else {
            panic!("expected a managed-capability list");
        };
        assert!(sessions.iter().any(|descriptor| {
            descriptor.session_id == managed_id
                && descriptor.presence == "stored"
                && descriptor.stored_reason.as_deref() == Some("stopped")
        }));

        let (mut legacy_send, mut legacy_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut legacy_send, StreamKind::Agent)
            .await
            .unwrap();
        write_agent_frame(&mut legacy_send, &open("agent.sessions.list", None))
            .await
            .unwrap();
        legacy_send.finish().unwrap();
        assert!(matches!(
            read_agent_server(&mut legacy_recv).await,
            AgentServerFrame::StreamAccepted { .. }
        ));
        let AgentServerFrame::SessionList { sessions, .. } =
            read_agent_server(&mut legacy_recv).await
        else {
            panic!("expected a legacy list");
        };
        assert!(
            sessions
                .iter()
                .all(|descriptor| descriptor.session_id != managed_id)
        );

        // A refusal is receipted with its categorical reason, never silent.
        let (mut refuse_send, mut refuse_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut refuse_send, StreamKind::Agent)
            .await
            .unwrap();
        let mut refuse_open = managed_open("agent.managed.start");
        refuse_open.workspace_id = Some("0000000000000000".into());
        refuse_open.lifecycle_command_id = Some("55555555555555555555555555555555".into());
        write_agent_frame(&mut refuse_send, &refuse_open)
            .await
            .unwrap();
        refuse_send.finish().unwrap();
        assert!(matches!(
            read_agent_server(&mut refuse_recv).await,
            AgentServerFrame::StreamAccepted { .. }
        ));
        let AgentServerFrame::LifecycleOutcome { outcome, .. } =
            read_agent_server(&mut refuse_recv).await
        else {
            panic!("expected a refusal outcome");
        };
        assert_eq!(outcome.reason_code.as_deref(), Some("unknown_workspace"));

        // Revocation is authoritative at mutation time, before route or adapter forwarding.
        *state.paired_devices.lock() =
            PairedDeviceStore::load(temp.path().join("revoked-agent-devices.json")).unwrap();
        write_agent_frame(
            &mut subscription_send,
            &AgentClientFrame::CommandSubmit {
                command: AgentCommand {
                    v: 1,
                    command_id: "22222222222222222222222222222222".into(),
                    session_id: session_id.clone(),
                    snapshot_epoch: delta.snapshot_epoch,
                    expected_generation: delta.process_generation,
                    expected_revision: Some(delta.revision),
                    kind: AgentCommandKind::Prompt {
                        text: "Synthetic command.".into(),
                    },
                },
            },
        )
        .await
        .unwrap();
        let code = loop {
            if let AgentServerFrame::Error { code, .. } =
                read_agent_server(&mut subscription_recv).await
            {
                break code;
            }
            // A previously queued receipt/delta may legally precede the authorization response
            // on the long-lived subscription; it cannot authorize or apply this new command.
        };
        assert_eq!(code, "authorization_denied");

        // Revocation is also rechecked before decoding every new list/snapshot/page operation.
        let (mut revoked_send, mut revoked_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut revoked_send, StreamKind::Agent)
            .await
            .unwrap();
        write_agent_frame(&mut revoked_send, &open("agent.sessions.list", None))
            .await
            .unwrap();
        revoked_send.finish().unwrap();
        let AgentServerFrame::Error { code, .. } = read_agent_server(&mut revoked_recv).await
        else {
            panic!("expected operation authorization failure");
        };
        assert_eq!(code, "authorization_denied");

        write_agent_frame(
            &mut adapter_bridge,
            &serde_json::json!({"v": 1, "type": "shutdown", "reason": "process_exit"}),
        )
        .await
        .unwrap();
        timeout(Duration::from_secs(3), bridge_task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(state.agent_sessions.active_count(), 0);
        connection.close(0_u32.into(), b"test complete");
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        client.close().await;
        host.close().await;
    }

    #[tokio::test]
    async fn session_targets_are_validated_and_provider_gated_before_spawn() {
        let temp = tempdir().unwrap();
        let empty_dir = tempdir().unwrap();
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state_with_workspace(
            host_id,
            &temp.path().join("paired-devices.json"),
            WorkspaceConfig::with_binary_dirs(vec![empty_dir.path().to_owned()]),
        );
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[5; 32], &[0x5a; 32])
            .unwrap();

        for (payload, expected_code) in [
            (
                // Provider missing from the fixed directories → provider_unavailable.
                br#"{"v":1,"target":"tmux.attach","session":"api","cols":80,"rows":24,"pixel_width":0,"pixel_height":0}"#.as_slice(),
                "provider_unavailable",
            ),
            (
                // Hostile session name → rejected at decode, before any lease or spawn.
                br#"{"v":1,"target":"tmux.attach","session":"bad name","cols":80,"rows":24,"pixel_width":0,"pixel_height":0}"#.as_slice(),
                "invalid_target",
            ),
        ] {
            let server = tokio::spawn({
                let host = host.clone();
                let state = state.clone();
                async move {
                    let incoming = host.accept().await.unwrap();
                    let connection = incoming.await.unwrap();
                    handle_authenticated_connection(connection, state).await;
                }
            });
            let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
            let hello = HostHelloRequest {
                v: 1,
                message_type: "request".into(),
                request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
                method: "host.hello".into(),
                params: crate::host_protocol::HostHelloParams {
                    min_protocol: 1,
                    max_protocol: 1,
                },
            };
            let body = open_rpc_stream(&connection, &encode_rpc(&hello).unwrap()).await;
            assert!(matches!(
                decode_rpc_response(&body).unwrap(),
                RpcResponse::Hello(_)
            ));

            let (mut terminal_send, mut terminal_recv) = connection.open_bi().await.unwrap();
            write_stream_preface(&mut terminal_send, StreamKind::Terminal)
                .await
                .unwrap();
            let mut frame = vec![0x01_u8];
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(payload);
            terminal_send.write_all(&frame).await.unwrap();
            let response = read_terminal_frame(&mut terminal_recv).await.unwrap();
            let TerminalFrame::Error(error) = response else {
                panic!("expected terminal error, got {response:?}");
            };
            assert_eq!(error.code, expected_code);
            connection.close(0_u32.into(), b"test complete");
            timeout(Duration::from_secs(5), server).await.unwrap().unwrap();
            // The handler has fully unwound, releasing any transient PTY lease; no PTY child
            // was ever spawned for a rejected target.
            assert_eq!(state.active_ptys.lock().total, 0);
        }
        client.close().await;
        host.close().await;
    }

    /// The count alone sent an owner to close an app that was not holding anything: the terminal
    /// belonged to a second paired device, and nothing they could read said so. One entry per
    /// lease, so the list and the number can never tell different stories.
    #[test]
    fn a_terminal_count_names_every_device_holding_one() {
        let mut admissions = ConnectionAdmissions::default();
        let phone = iroh::SecretKey::generate().public();
        let tablet = iroh::SecretKey::generate().public();
        let (_, first) = admissions.try_add(phone).unwrap();
        admissions.try_add(phone).unwrap();
        admissions.try_add(tablet).unwrap();

        let devices = admissions.lease_devices();
        assert_eq!(devices.len(), admissions.total);
        assert_eq!(
            devices
                .iter()
                .filter(|device| **device == short_endpoint_id(phone))
                .count(),
            2
        );
        assert!(devices.contains(&short_endpoint_id(tablet)));

        admissions.remove(&phone.to_string(), first);
        let devices = admissions.lease_devices();
        assert_eq!(devices.len(), admissions.total);
        assert_eq!(
            devices
                .iter()
                .filter(|device| **device == short_endpoint_id(phone))
                .count(),
            1
        );
    }

    /// What the installer's refusal now turns on. Calling a plain shell resumable would let an
    /// update kill a login shell someone was working in; calling a multiplexer terminal
    /// unresumable is what made `ciao update` unreachable from the app, because the terminal in
    /// the way was the one the command was typed into.
    #[test]
    fn only_a_plain_shell_dies_with_its_pty() {
        use crate::host_protocol::TerminalTarget;
        for target in [
            TerminalTarget::TmuxAttach,
            TerminalTarget::TmuxCreate,
            TerminalTarget::HerdrAttach,
            TerminalTarget::HerdrCreate,
        ] {
            assert!(target_is_resumable(Some(target), false), "{target:?}");
        }
        assert!(!target_is_resumable(Some(TerminalTarget::Shell), false));
        // An agent route carries no provider of its own; the plan it resolved to does, and a
        // route that resolved to no plan never reaches the lease.
        assert!(target_is_resumable(Some(TerminalTarget::AgentRoute), true));
        assert!(!target_is_resumable(
            Some(TerminalTarget::AgentRoute),
            false
        ));
        // An unparseable target is refused before this, and unknown is not a promise to keep.
        assert!(!target_is_resumable(None, false));
    }

    #[tokio::test]
    async fn session_target_spawns_the_resolved_provider_binary_under_the_pty() {
        let temp = tempdir().unwrap();
        let stub_dir = tempdir().unwrap();
        write_stub(
            stub_dir.path(),
            "herdr",
            "printf 'stub-args:%s\\n' \"$*\"; exit 0",
        );
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state_with_workspace(
            host_id,
            &temp.path().join("paired-devices.json"),
            WorkspaceConfig::with_binary_dirs(vec![stub_dir.path().to_owned()]),
        );
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[6; 32], &[0x5a; 32])
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });
        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
        let hello = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        let body = open_rpc_stream(&connection, &encode_rpc(&hello).unwrap()).await;
        assert!(matches!(
            decode_rpc_response(&body).unwrap(),
            RpcResponse::Hello(_)
        ));

        let (mut terminal_send, mut terminal_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut terminal_send, StreamKind::Terminal)
            .await
            .unwrap();
        write_terminal_frame(
            &mut terminal_send,
            &TerminalFrame::Open(TerminalOpen {
                v: 1,
                target: "herdr.attach".into(),
                session: Some("default".into()),
                tab: None,
                dimensions: Dimensions {
                    cols: 80,
                    rows: 24,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            }),
        )
        .await
        .unwrap();
        let opened = read_terminal_frame(&mut terminal_recv).await.unwrap();
        assert!(matches!(opened, TerminalFrame::Opened(_)));
        let mut output = Vec::new();
        let exit = loop {
            match read_terminal_frame(&mut terminal_recv).await.unwrap() {
                TerminalFrame::Output(bytes) => output.extend_from_slice(&bytes),
                TerminalFrame::Exit(exit) => break exit,
                other => panic!("unexpected terminal frame: {other:?}"),
            }
        };
        // The stub provider client ran with the exact fixed argv and then exited normally.
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("stub-args:session attach default"),
            "output: {text}"
        );
        assert_eq!(exit.kind, "exited");
        assert_eq!(exit.code, Some(0));

        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        client.close().await;
        host.close().await;
    }

    /// Spec 021 §5: an open carrying a tab pre-focuses it with one bounded provider call and
    /// then spawns the exact same attach argv as an open without one. The stub records every
    /// invocation, so the order and the argv of both calls are pinned here.
    #[tokio::test]
    async fn attach_with_tab_prefocuses_before_the_same_attach_argv() {
        let temp = tempdir().unwrap();
        let stub_dir = tempdir().unwrap();
        let calls = stub_dir.path().join("calls.log");
        write_stub(
            stub_dir.path(),
            "herdr",
            &format!(
                "printf '%s\\n' \"$*\" >> {}; printf 'stub-args:%s\\n' \"$*\"; exit 0",
                calls.display()
            ),
        );
        let host_secret = iroh::SecretKey::generate();
        let host_id = host_secret.public();
        let installation_secret = iroh::SecretKey::generate();
        let installation_id = installation_secret.public();
        let host = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(host_secret)
            .alpns(vec![HOST_ALPN.to_vec()])
            .transport_config(host_transport_config())
            .bind()
            .await
            .unwrap();
        let client = Endpoint::builder(presets::N0DisableRelay)
            .secret_key(installation_secret)
            .bind()
            .await
            .unwrap();
        let state = test_state_with_workspace(
            host_id,
            &temp.path().join("paired-devices.json"),
            WorkspaceConfig::with_binary_dirs(vec![stub_dir.path().to_owned()]),
        );
        state
            .paired_devices
            .lock()
            .upsert(installation_id, 1, &[6; 32], &[0x5a; 32])
            .unwrap();
        let server = tokio::spawn({
            let host = host.clone();
            let state = state.clone();
            async move {
                let incoming = host.accept().await.unwrap();
                let connection = incoming.await.unwrap();
                handle_authenticated_connection(connection, state).await;
            }
        });
        let connection = client.connect(host.addr(), HOST_ALPN).await.unwrap();
        let hello = HostHelloRequest {
            v: 1,
            message_type: "request".into(),
            request_id: "AAECAwQFBgcICQoLDA0ODw".into(),
            method: "host.hello".into(),
            params: crate::host_protocol::HostHelloParams {
                min_protocol: 1,
                max_protocol: 1,
            },
        };
        let body = open_rpc_stream(&connection, &encode_rpc(&hello).unwrap()).await;
        assert!(matches!(
            decode_rpc_response(&body).unwrap(),
            RpcResponse::Hello(_)
        ));

        let (mut terminal_send, mut terminal_recv) = connection.open_bi().await.unwrap();
        write_stream_preface(&mut terminal_send, StreamKind::Terminal)
            .await
            .unwrap();
        write_terminal_frame(
            &mut terminal_send,
            &TerminalFrame::Open(TerminalOpen {
                v: 1,
                target: "herdr.attach".into(),
                session: Some("default".into()),
                tab: Some("w0:t1".into()),
                dimensions: Dimensions {
                    cols: 80,
                    rows: 24,
                    pixel_width: 0,
                    pixel_height: 0,
                },
            }),
        )
        .await
        .unwrap();
        let opened = read_terminal_frame(&mut terminal_recv).await.unwrap();
        assert!(matches!(opened, TerminalFrame::Opened(_)));
        let exit = loop {
            match read_terminal_frame(&mut terminal_recv).await.unwrap() {
                TerminalFrame::Output(_) => {}
                TerminalFrame::Exit(exit) => break exit,
                other => panic!("unexpected terminal frame: {other:?}"),
            }
        };
        assert_eq!(exit.kind, "exited");
        assert_eq!(exit.code, Some(0));
        let recorded = std::fs::read_to_string(&calls).unwrap();
        let lines: Vec<&str> = recorded.lines().collect();
        assert_eq!(
            lines,
            vec![
                "--session default tab focus w0:t1",
                "session attach default"
            ],
            "pre-focus must run first and neither argv may drift"
        );

        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        client.close().await;
        host.close().await;
    }
}
