//! ADR 005 push delivery. The host owns retry, coalescing, and rate limiting (ADR item 9),
//! because it is the always-on side of the pair and the relay stores nothing.
//!
//! What leaves this machine is a ticket and one sealed blob. The blob is ChaCha20-Poly1305
//! ciphertext under the key this host and that one phone agreed at pairing, so the relay and
//! Apple carry the session's name without ever being able to read it — the leak ADR 005 exists to
//! prevent. Everything outside the seal is the relay's own fixed generic alert, which is what
//! iOS shows when the Notification Service extension does not run.

use std::{
    collections::{HashMap, VecDeque},
    io::Write,
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::{
    live_activity::{
        LiveActivityOverview, MAX_LIVE_ACTIVITY_DISPLAY_BYTES, bounded_utf8, state_priority,
    },
    protocol::base64url,
    storage::{LiveActivityTarget, PairedDeviceStore, validate_endpoint_id},
};

pub const DEFAULT_RELAY_URL: &str = "https://ciaooo.app/notify";
pub const DEFAULT_LIVE_ACTIVITY_RELAY_URL: &str = "https://ciaooo.app/notify/activity";
/// Points delivery at another deployment without a rebuild. Same shape check as the release
/// downloader: a plain `https://` URL and nothing that could confuse an argv slot.
const RELAY_ENV: &str = "CIAO_NOTIFY_RELAY";
const LIVE_ACTIVITY_RELAY_ENV: &str = "CIAO_LIVE_ACTIVITY_RELAY";

/// One push per session per minute. A permission prompt that fires again while the first is still
/// unanswered is the same interruption, and Claude Code re-notifies on its own schedule.
const COALESCE_SECONDS: u64 = 60;
/// A ceiling across every session, so a host looping on prompts cannot empty a phone's battery.
const RATE_LIMIT_WINDOW_SECONDS: u64 = 600;
const RATE_LIMIT_PER_WINDOW: usize = 12;
/// Bounds the gate's memory on a host with a lot of short-lived sessions.
const MAX_TRACKED_SESSIONS: usize = 256;

const ATTEMPT_BACKOFF: [u64; 2] = [2, 8];
const CURL_MAX_SECONDS: u64 = 10;

/// Binds a sealed blob to this one use. A Live Activity's `content-state` will be sealed under
/// the same pairing key, and this is what stops one being replayed as the other.
const PAYLOAD_AAD: &[u8] = b"ciao-notify-payload-v1";
/// Purpose separation is part of the wire contract: an authentic alert blob replayed into an
/// activity is still unauthentic there, and vice versa.
const LIVE_ACTIVITY_AAD: &[u8] = b"ciao-notify-activity-v1";
/// Eight rows with every label at its bound seal to ~3.5 KB once prompts ride along. APNs caps
/// the whole Live Activity payload at 4 KB; the relay's envelope around `c` costs ~100 bytes,
/// so this leaves real margin. Changing it changes three places in the same release: this
/// constant, `maximumSealedCharacters` in `AgentLiveActivityModels.swift`, and
/// `LIVE_ACTIVITY_SEALED` in `site/_worker.js` — and the relay deploys first, because a host
/// ahead of the relay gets its oversized update refused as permanently as a bad token.
const MAX_LIVE_ACTIVITY_SEALED_CHARACTERS: usize = 3_584;
const LIVE_ACTIVITY_HEARTBEAT_SECONDS: u64 = 15 * 60;
const LIVE_ACTIVITY_STALE_SECONDS: u64 = 20 * 60;
const LIVE_ACTIVITY_RETRY_SECONDS: u64 = 60;
/// A failing update backs off instead of retrying every minute until morning.
///
/// Measured on the owner's daemon 2026-08-18: an activity iOS had already ended answered 502 for
/// roughly seven hours, ~390 requests an hour across two devices, ~2,900 in a night — every one of
/// them identical and none of them ever going to succeed. The ceiling is the heartbeat, because a
/// wait longer than that is indistinguishable from the ordinary unchanged-state cadence.
const LIVE_ACTIVITY_MAX_RETRY_SECONDS: u64 = LIVE_ACTIVITY_HEARTBEAT_SECONDS;
const MAX_LIVE_ACTIVITY_ROWS: usize = 8;
/// The name on a lock screen is a project directory, and a long one buys nothing readable. APNs
/// caps a whole payload at 4 KB, which this keeps a sealed push an order of magnitude inside.
const MAX_WORKSPACE_CHARACTERS: usize = 64;
/// The conversation's subject, which is a user prompt and therefore arbitrary text. The wire
/// bound is already 200 bytes; this is the shorter bound a notification body can actually show.
const MAX_TITLE_CHARACTERS: usize = 100;
/// Matches `MAX_HOST_DISPLAY_NAME_BYTES`, which the host protocol already enforces.
const MAX_HOST_CHARACTERS: usize = 64;
/// The relay's own failure text, logged and nothing else. Short because APNS's reasons are one
/// word and a relay that started returning prose should not be able to fill a log with it.
const MAX_RELAY_DETAIL_CHARACTERS: usize = 64;

/// Coalescing and rate limiting, kept pure so both are testable without a relay or a clock.
#[derive(Debug, Default)]
pub struct NotifyGate {
    recent: HashMap<String, u64>,
    window: VecDeque<u64>,
}

impl NotifyGate {
    pub fn allow(&mut self, session_id: &str, now: u64) -> bool {
        self.recent
            .retain(|_, last| now.saturating_sub(*last) < COALESCE_SECONDS);
        while self
            .window
            .front()
            .is_some_and(|sent| now.saturating_sub(*sent) >= RATE_LIMIT_WINDOW_SECONDS)
        {
            self.window.pop_front();
        }
        if self.recent.contains_key(session_id) || self.window.len() >= RATE_LIMIT_PER_WINDOW {
            return false;
        }
        // Retaining above already dropped everything stale, so a full map means genuinely that
        // many live sessions. Refusing is the honest answer: silently forgetting one session's
        // last push would turn the coalescing window off for it.
        if !self.recent.contains_key(session_id) && self.recent.len() >= MAX_TRACKED_SESSIONS {
            return false;
        }
        self.recent.insert(session_id.to_owned(), now);
        self.window.push_back(now);
        true
    }
}

#[derive(Debug)]
struct NotifierInner {
    devices: Arc<Mutex<PairedDeviceStore>>,
    relay: String,
    live_activity_relay: String,
    gate: Mutex<NotifyGate>,
    live_activities: Mutex<HashMap<String, LiveActivityDeliveryState>>,
    /// This machine's name, so an alert says which of them wants something. Safe to carry only
    /// because it is inside the seal — it is exactly the per-user metadata ADR 005 refuses to
    /// let the relay accumulate.
    host: String,
}

/// Delivers "a session wants attention" to every paired device that has handed over a ticket.
#[derive(Debug, Clone)]
pub struct Notifier {
    inner: Arc<NotifierInner>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LiveActivitySemanticRow {
    id: String,
    agent: String,
    workspace: String,
    /// The turn-opening prompt, when the descriptor names one. The workspace alone cannot tell
    /// two agents in one directory apart — the same reasoning as `recent_prompt` on the
    /// descriptor, carried to the Lock Screen.
    prompt: Option<String>,
    state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LiveActivityRow {
    id: String,
    agent: String,
    workspace: String,
    /// Absent rather than empty, so an old app's exact-shape check keeps rejecting only
    /// payloads that actually carry the new field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prompt: Option<String>,
    state: String,
    updated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct LiveActivityPayload {
    v: u8,
    host: String,
    updated_at: u64,
    sessions: Vec<LiveActivityRow>,
}

#[derive(Debug, Clone, Default)]
struct LiveActivityDeliveryState {
    /// What the phone last actually received — `None` until a post succeeds. Recording the new
    /// rows at queue time made the host believe a failed or unsendable update had landed, after
    /// which the semantic dedupe suppressed every retry and the card stayed wrong until the next
    /// state change (audit B2).
    delivered: Option<DeliveredLiveActivity>,
    /// Rounds that have failed back to back, which is what widens the retry. Carried across
    /// deliveries rather than rebuilt with the rest of the state: a run of failures is a property
    /// of the endpoint, not of the update that happened to be in flight when it started.
    consecutive_failures: u32,
    /// The earliest moment another send may be attempted; zero when healthy. It gates changed
    /// state and heartbeats alike — a busy agent used to bypass its own backoff by changing rows
    /// every second, re-posting each second into the same failing endpoint (audit B4).
    next_attempt_at: u64,
    /// The APNs ordering timestamp only ever moves forward per endpoint. Two updates prepared in
    /// the same wall-clock second tied and left ActivityKit's ordering undefined, and a stepped
    /// -back clock (sleep, NTP) stamped every later update older than one iOS already accepted,
    /// which discards them silently (audit B4/B6).
    last_timestamp: u64,
    /// The send currently allowed to act for this endpoint. A superseded task stops posting and
    /// writes nothing, so a slow retry can neither deliver an older state after a newer one nor
    /// rewind the newer delivery's bookkeeping (audit B4).
    generation: u64,
}

/// The payload a device is known to hold, kept to suppress unchanged re-sends and to carry each
/// row's `updated_at` across pushes.
#[derive(Debug, Clone)]
struct DeliveredLiveActivity {
    ticket_fingerprint: [u8; 32],
    semantic_rows: Vec<LiveActivitySemanticRow>,
    payload: LiveActivityPayload,
    at: u64,
}

struct PendingLiveActivityDelivery {
    endpoint_id: String,
    ticket: String,
    key: [u8; 32],
    payload: LiveActivityPayload,
}

/// One spawned send: everything the task needs, owned, plus the claim it may record on success.
struct LiveActivityJob {
    endpoint_id: String,
    ticket: String,
    sealed: String,
    timestamp: u64,
    stale_at: u64,
    generation: u64,
    delivered: DeliveredLiveActivity,
}

/// What a relay 400 meant. One status used to mean four unrelated things, and the host answered
/// all of them by deleting the device's registration — including "your payload was malformed",
/// which nuked a healthy Lock Screen for a host-side bug, and left the phone unable to re-register
/// because its reconcile only refreshes the ticket (audit B1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiveActivityRefusal {
    /// APNs said the ActivityKit token is gone — the activity ended on the device. The one
    /// refusal where clearing the registration is the truth.
    TokenDead,
    /// The relay could not open the ticket (expired, or sealed by another deployment). The
    /// selections are still the person's choices; keep them and wait for the phone to hand over
    /// a fresh ticket.
    TicketRefused,
    /// The relay refused the envelope shape — a version skew or host bug, never the user's state.
    ShapeRefused,
    /// A relay older than the classified bodies, or a word this host does not know. Refusing to
    /// guess means refusing to delete: keep the registration and back off.
    Ambiguous,
}

/// Keyed to the exact bodies `site/_worker.js` sends; anything else — including the previously
/// deployed relay's generic "bad request" — is ambiguous on purpose.
fn classify_live_activity_refusal(detail: &str) -> LiveActivityRefusal {
    match detail {
        "bad_token" => LiveActivityRefusal::TokenDead,
        "bad_ticket" => LiveActivityRefusal::TicketRefused,
        "bad_shape" => LiveActivityRefusal::ShapeRefused,
        _ => LiveActivityRefusal::Ambiguous,
    }
}

impl Notifier {
    pub fn new(devices: Arc<Mutex<PairedDeviceStore>>, host: String) -> Self {
        let relay = std::env::var(RELAY_ENV)
            .ok()
            .filter(|url| valid_relay_url(url))
            .unwrap_or_else(|| DEFAULT_RELAY_URL.to_string());
        let live_activity_relay = std::env::var(LIVE_ACTIVITY_RELAY_ENV)
            .ok()
            .filter(|url| valid_relay_url(url))
            .unwrap_or_else(|| DEFAULT_LIVE_ACTIVITY_RELAY_URL.to_string());
        Self {
            inner: Arc::new(NotifierInner {
                devices,
                relay,
                live_activity_relay,
                gate: Mutex::new(NotifyGate::default()),
                live_activities: Mutex::new(HashMap::new()),
                host,
            }),
        }
    }

    /// Fire and forget: the agent bridge acknowledges its event without waiting on a relay that
    /// may be slow, retrying, or unreachable.
    ///
    /// Nothing here leaves this process unsealed. A device paired before the notification key
    /// existed has no key to seal under and gets the relay's generic alert instead.
    pub fn notify(
        &self,
        session_id: &str,
        workspace: &str,
        title: Option<&str>,
        kind: &str,
        now: u64,
    ) {
        if !self.inner.gate.lock().allow(session_id, now) {
            return;
        }
        let targets = self.inner.devices.lock().push_targets();
        if targets.is_empty() {
            return;
        }
        let plaintext = payload(session_id, workspace, &self.inner.host, title, kind);
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            for (ticket, key) in targets {
                let sealed = key.and_then(|key| seal(&key, plaintext.as_bytes()).ok());
                inner.deliver(ticket, sealed).await;
            }
        });
    }

    /// Recomputes every opted-in, per-host overview from canonical session facts. Called from
    /// the daemon's existing one-second supervisor sweep, but sends only on semantic change or a
    /// fifteen-minute heartbeat — timeline streaming therefore cannot become an APNS firehose.
    ///
    /// Whether any device is currently listening, and the point at which delivery bookkeeping for
    /// an activity nobody watches is dropped.
    ///
    /// It exists so a caller can skip projecting: this sweep runs once a second on every host and
    /// almost none has an activity registered, so an unconditional projection would clone every
    /// descriptor and managed record, every second, for a feature nobody turned on.
    ///
    /// **Advisory, never authoritative.** `refresh_live_activities` re-reads the registrations
    /// under its own lock and keeps its own empty check, so nothing here decides delivery. A
    /// device that appears between the two calls simply receives its state on the following
    /// sweep — and does not wait even that long, because the registering RPC refreshes itself.
    /// A device that disappears between them is dropped by the authoritative check.
    pub(crate) fn has_live_activity_interest(&self) -> bool {
        if self.inner.devices.lock().live_activity_targets().is_empty() {
            // The same clear the empty-target path below performs, kept here so that skipping the
            // projection cannot leave a departed device's delivery state behind.
            self.inner.live_activities.lock().clear();
            return false;
        }
        true
    }

    /// The overview is a value the caller projected from the Agent and managed owners and handed
    /// over, so delivery reads no mutable state and holds no owner's lock while it seals, posts,
    /// or waits on a relay.
    pub(crate) fn refresh_live_activities(&self, overview: LiveActivityOverview, now: u64) {
        let targets = self.inner.devices.lock().live_activity_targets();
        if targets.is_empty() {
            self.inner.live_activities.lock().clear();
            return;
        }
        let active: std::collections::HashSet<_> = targets
            .iter()
            .map(|target| target.endpoint_id.clone())
            .collect();
        let mut jobs = Vec::new();
        {
            let mut deliveries = self.inner.live_activities.lock();
            deliveries.retain(|endpoint_id, _| active.contains(endpoint_id));
            for target in targets {
                let state = deliveries.entry(target.endpoint_id.clone()).or_default();
                if let Some(job) =
                    prepare_live_activity_job(&self.inner.host, target, &overview, state, now)
                {
                    jobs.push(job);
                }
            }
        }
        for job in jobs {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move { inner.deliver_live_activity(job).await });
        }
    }
}

/// Decides whether one endpoint gets a send this sweep, and prepares everything the task needs.
///
/// Bookkeeping is split by what it means: the generation and timestamp advance here, because they
/// describe the *attempt*; `delivered` moves only on a confirmed 204, because it describes the
/// *phone*. Sealing failures feed the same failure accounting as a refused post — the old shape
/// recorded the rows as delivered before sealing, so an unsendable payload was believed held by
/// the device and the fifteen-minute heartbeat re-failed on the same bytes forever (audit B2).
fn prepare_live_activity_job(
    host: &str,
    target: LiveActivityTarget,
    overview: &LiveActivityOverview,
    state: &mut LiveActivityDeliveryState,
    now: u64,
) -> Option<LiveActivityJob> {
    // The backoff gates every send, changed state included (audit B4).
    if now < state.next_attempt_at {
        return None;
    }
    let delivery = live_activity_delivery(host, target, overview, state.delivered.as_ref(), now)?;
    // Logged before the seal, because a payload that fails to prepare is itself an answer. The
    // sweep runs once a second, so the absence of this line says the host decided there was
    // nothing to send — which is indistinguishable from a successful push in a log that only
    // records failures.
    tracing::debug!(
        remote = %delivery.endpoint_id.chars().take(10).collect::<String>(),
        rows = delivery.payload.sessions.len(),
        "live activity update queued"
    );
    let sealed = serde_json::to_vec(&delivery.payload)
        .map_err(|_| "serialize")
        .and_then(|plaintext| {
            seal_for_context(&delivery.key, &plaintext, LIVE_ACTIVITY_AAD).map_err(|_| "seal")
        })
        .and_then(|sealed| {
            (sealed.len() <= MAX_LIVE_ACTIVITY_SEALED_CHARACTERS)
                .then_some(sealed)
                .ok_or("bound")
        });
    let sealed = match sealed {
        Ok(sealed) => sealed,
        Err(step) => {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.next_attempt_at =
                now.saturating_add(live_activity_retry_delay(state.consecutive_failures));
            tracing::warn!(
                step,
                failures = state.consecutive_failures,
                "live activity payload could not be prepared"
            );
            return None;
        }
    };
    state.generation = state.generation.wrapping_add(1);
    let timestamp = now.max(state.last_timestamp.saturating_add(1));
    state.last_timestamp = timestamp;
    Some(LiveActivityJob {
        endpoint_id: delivery.endpoint_id,
        ticket: delivery.ticket.clone(),
        sealed,
        timestamp,
        stale_at: timestamp.saturating_add(LIVE_ACTIVITY_STALE_SECONDS),
        generation: state.generation,
        delivered: DeliveredLiveActivity {
            ticket_fingerprint: live_activity_ticket_fingerprint(&delivery.ticket),
            semantic_rows: semantic_rows(&delivery.payload),
            payload: delivery.payload,
            at: now,
        },
    })
}

fn live_activity_delivery(
    host: &str,
    target: LiveActivityTarget,
    overview: &LiveActivityOverview,
    previous: Option<&DeliveredLiveActivity>,
    now: u64,
) -> Option<PendingLiveActivityDelivery> {
    let mut current: Vec<_> = target
        .selections
        .iter()
        .take(MAX_LIVE_ACTIVITY_ROWS)
        .map(|selection| {
            // Absence is not proof of completion or idleness, and neither is a persisted record.
            // Either way the labels captured at opt-in stand and only the state claim moves.
            let fact = overview.fact(&selection.session_id);
            let labels = fact.and_then(|fact| fact.labels.as_ref());
            LiveActivitySemanticRow {
                id: selection.session_id.clone(),
                agent: labels.map_or_else(|| selection.adapter.clone(), |it| it.agent.clone()),
                workspace: labels
                    .map_or_else(|| selection.workspace.clone(), |it| it.workspace.clone()),
                prompt: labels.and_then(|it| it.prompt.clone()),
                state: fact.map_or("unknown", |fact| fact.state).into(),
            }
        })
        .collect();
    current.sort_by(|left, right| {
        state_priority(&left.state)
            .cmp(&state_priority(&right.state))
            .then_with(|| left.workspace.cmp(&right.workspace))
            .then_with(|| left.id.cmp(&right.id))
    });

    let ticket_fingerprint = live_activity_ticket_fingerprint(&target.ticket);
    let changed = previous.is_none_or(|previous| {
        previous.ticket_fingerprint != ticket_fingerprint || previous.semantic_rows != current
    });
    let heartbeat_due = previous
        .is_some_and(|previous| now.saturating_sub(previous.at) >= LIVE_ACTIVITY_HEARTBEAT_SECONDS);
    if !changed && !heartbeat_due {
        return None;
    }
    let previous_rows = previous.map(|previous| &previous.payload.sessions);
    let rows = current
        .iter()
        .map(|row| {
            let unchanged_at = previous_rows.and_then(|rows| {
                rows.iter().find(|previous| {
                    previous.id == row.id
                        && previous.agent == row.agent
                        && previous.workspace == row.workspace
                        && previous.prompt == row.prompt
                        && previous.state == row.state
                })
            });
            LiveActivityRow {
                id: row.id.clone(),
                agent: row.agent.clone(),
                workspace: row.workspace.clone(),
                prompt: row.prompt.clone(),
                state: row.state.clone(),
                updated_at: unchanged_at.map_or(now, |row| row.updated_at),
            }
        })
        .collect();
    Some(PendingLiveActivityDelivery {
        endpoint_id: target.endpoint_id,
        ticket: target.ticket,
        key: target.key,
        payload: LiveActivityPayload {
            v: 1,
            host: bounded_utf8(host, MAX_LIVE_ACTIVITY_DISPLAY_BYTES),
            updated_at: now,
            sessions: rows,
        },
    })
}

fn live_activity_ticket_fingerprint(ticket: &str) -> [u8; 32] {
    Sha256::digest(ticket.as_bytes()).into()
}

fn semantic_rows(payload: &LiveActivityPayload) -> Vec<LiveActivitySemanticRow> {
    payload
        .sessions
        .iter()
        .map(|row| LiveActivitySemanticRow {
            id: row.id.clone(),
            agent: row.agent.clone(),
            workspace: row.workspace.clone(),
            prompt: row.prompt.clone(),
            state: row.state.clone(),
        })
        .collect()
}

/// 60s, then doubling, capped at the heartbeat. `failures` is the number that have already
/// happened, so the first failure waits a minute.
///
/// Pure, and the shift is guarded rather than trusted: `1 << 64` is undefined and a device that
/// somehow accumulated that many failures would be the least of it, but a panic in a delivery
/// task would take the sweep with it.
fn live_activity_retry_delay(failures: u32) -> u64 {
    let doublings = failures.saturating_sub(1).min(16);
    LIVE_ACTIVITY_RETRY_SECONDS
        .saturating_mul(1u64 << doublings)
        .min(LIVE_ACTIVITY_MAX_RETRY_SECONDS)
}

/// What the extension decrypts and shows: which machine, which project, which conversation, and
/// what it wants. Facts, not sentences — rendering is the device's job, and a host that shipped
/// lock-screen copy would have to be updated to reword it.
///
/// All of it is readable only by the paired phone, which is what makes it sayable at all. The
/// same four fields on the outside of the seal would hand the relay a per-user log of which
/// project on which machine needed attention and when.
fn payload(
    session_id: &str,
    workspace: &str,
    host: &str,
    title: Option<&str>,
    kind: &str,
) -> String {
    let mut payload = serde_json::json!({
        "v": 1,
        "session": session_id,
        "workspace": bounded(workspace, MAX_WORKSPACE_CHARACTERS),
        "host": bounded(host, MAX_HOST_CHARACTERS),
        "kind": kind,
    });
    // Omitted rather than empty: a conversation Ciao never saw a prompt for has no subject, and
    // the device renders one line instead of a trailing quotation mark around nothing.
    if let Some(title) = title.map(|title| bounded(title, MAX_TITLE_CHARACTERS))
        && !title.is_empty()
    {
        payload["title"] = title.into();
    }
    payload.to_string()
}

fn bounded(value: &str, characters: usize) -> String {
    if value.chars().count() <= characters {
        return value.to_owned();
    }
    value
        .chars()
        .take(characters.saturating_sub(1))
        .chain(std::iter::once('…'))
        .collect()
}

/// Seals one payload under a pairing's notification key, as `nonce ‖ ciphertext ‖ tag`.
///
/// ChaCha20-Poly1305 rather than AES-GCM: it is constant-time in software, and hosts include
/// headless Linux boxes whose CPU may have no AES instructions, where a table-driven AES is both
/// slower and a timing risk. CryptoKit's `ChaChaPoly` reads this exact framing on the device.
///
/// The nonce is random, not a counter. A counter would have to survive daemon restarts, and the
/// file it lived in can be restored from a backup or copied to another machine — either of which
/// repeats a nonce, which is catastrophic for this construction. Random 96-bit nonces have no
/// such state: at this host's own rate limit (12 per 10 minutes, ~1,700 a day) the birthday bound
/// for even a 2^-32 chance of a repeat is roughly 2^48 messages, which is millions of years.
fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    seal_for_context(key, plaintext, PAYLOAD_AAD)
}

fn seal_for_context(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<String> {
    seal_with_nonce(key, plaintext, aad, rand::random::<[u8; 12]>())
}

fn seal_with_nonce(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    nonce: [u8; 12],
) -> Result<String> {
    let sealed = ChaCha20Poly1305::new(&Key::from(*key))
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow!("sealing a notification payload failed"))?;
    Ok(base64url(&[nonce.as_slice(), sealed.as_slice()].concat()))
}

impl NotifierInner {
    async fn deliver(&self, ticket: String, sealed: Option<String>) {
        for attempt in 0..=ATTEMPT_BACKOFF.len() {
            let relay = self.relay.clone();
            let attempted = ticket.clone();
            let sealed = sealed.clone();
            let status = tokio::task::spawn_blocking(move || {
                post_ticket(&relay, &attempted, sealed.as_deref())
            })
            .await;
            match status {
                Ok(Ok((204, _))) => return,
                // The relay refuses a ticket it cannot open or that has expired. Retrying that is
                // pointless and keeping it is worse: it will never work again, and the phone
                // hands over a fresh one on its next connection.
                Ok(Ok((400, _))) => {
                    self.forget(&ticket);
                    return;
                }
                Ok(Ok((status, detail))) if !relay_attempt_is_retryable(status) => {
                    tracing::warn!(status, %detail, "notification relay refused a push");
                    return;
                }
                Ok(Ok((status, detail))) => {
                    tracing::warn!(status, %detail, "notification relay is unavailable")
                }
                Ok(Err(error)) => tracing::debug!(error = %error, "notification push failed"),
                Err(error) => tracing::debug!(error = %error, "notification push task failed"),
            }
            if let Some(backoff) = ATTEMPT_BACKOFF.get(attempt) {
                tokio::time::sleep(Duration::from_secs(*backoff)).await;
            }
        }
    }

    async fn deliver_live_activity(&self, job: LiveActivityJob) {
        for attempt in 0..=ATTEMPT_BACKOFF.len() {
            // A newer send supersedes this one entirely: it stops posting and writes nothing, so
            // a slow retry can neither hand APNs an older state after a newer one went out nor
            // rewind the newer delivery's bookkeeping (audit B4).
            if !self.live_activity_generation_is_current(&job.endpoint_id, job.generation) {
                return;
            }
            let relay = self.live_activity_relay.clone();
            let attempted = job.ticket.clone();
            let blob = job.sealed.clone();
            let (timestamp, stale_at) = (job.timestamp, job.stale_at);
            let status = tokio::task::spawn_blocking(move || {
                post_live_activity(&relay, &attempted, &blob, timestamp, stale_at)
            })
            .await;
            match status {
                Ok(Ok((204, _))) => {
                    tracing::debug!(attempt, "live activity update delivered");
                    self.record_live_activity_success(&job);
                    return;
                }
                Ok(Ok((400, detail))) => {
                    self.record_live_activity_refusal(&job, detail.trim());
                    return;
                }
                Ok(Ok((status, detail))) if !relay_attempt_is_retryable(status) => {
                    // Counted and rescheduled rather than dropped: a 403, 404, or an HTML 200
                    // from a misrouted relay URL used to vanish without a trace and without a
                    // retry, leaving the card wrong until the next state change (audit B3).
                    tracing::warn!(status, %detail, "live activity relay refused an update");
                    self.record_live_activity_failure(&job);
                    return;
                }
                Ok(Ok((status, detail))) => {
                    // `detail` is APNS's own word for it, forwarded by the relay. A bare 502
                    // could not tell an ended activity from a throttled one, and those want
                    // opposite responses.
                    tracing::warn!(status, %detail, "live activity relay is unavailable")
                }
                Ok(Err(error)) => {
                    tracing::debug!(error = %error, "live activity update failed")
                }
                Err(error) => {
                    tracing::debug!(error = %error, "live activity update task failed")
                }
            }
            if let Some(backoff) = ATTEMPT_BACKOFF.get(attempt) {
                tokio::time::sleep(Duration::from_secs(*backoff)).await;
            }
        }
        self.record_live_activity_failure(&job);
    }

    fn live_activity_generation_is_current(&self, endpoint_id: &str, generation: u64) -> bool {
        self.live_activities
            .lock()
            .get(endpoint_id)
            .is_some_and(|state| state.generation == generation)
    }

    /// Only a confirmed 204 moves `delivered`, and only the task that is still current may move
    /// anything — the claim describes the phone, not the attempt.
    fn record_live_activity_success(&self, job: &LiveActivityJob) {
        if let Some(state) = self.live_activities.lock().get_mut(&job.endpoint_id)
            && state.generation == job.generation
        {
            state.delivered = Some(job.delivered.clone());
            state.consecutive_failures = 0;
            state.next_attempt_at = 0;
        }
    }

    /// Widens the retry with the run of failures. A first failure is worth retrying in a minute;
    /// the four hundredth is the same dead activity answering the same way, and the only thing
    /// another minute buys is another failure.
    fn record_live_activity_failure(&self, job: &LiveActivityJob) {
        if let Some(state) = self.live_activities.lock().get_mut(&job.endpoint_id)
            && state.generation == job.generation
        {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            let delay = live_activity_retry_delay(state.consecutive_failures);
            state.next_attempt_at = job.timestamp.saturating_add(delay);
            tracing::debug!(
                failures = state.consecutive_failures,
                delay,
                "live activity delivery is backing off"
            );
        }
    }

    /// A 400 is permanent for *something*; the relay's one-word body says for what, and only a
    /// dead ActivityKit token may cost the person their selections. Everything else keeps the
    /// registration and waits at the ceiling — the phone repairs a stale ticket on its next
    /// registration, and a shape refusal is a bug to fix, not state to delete (audit B1).
    fn record_live_activity_refusal(&self, job: &LiveActivityJob, detail: &str) {
        match classify_live_activity_refusal(detail) {
            LiveActivityRefusal::TokenDead => {
                tracing::warn!("live activity token is dead; clearing the registration");
                if let Ok(endpoint) = validate_endpoint_id(&job.endpoint_id) {
                    let _ = self.devices.lock().clear_live_activity(endpoint);
                }
                self.live_activities.lock().remove(&job.endpoint_id);
            }
            refusal => {
                match refusal {
                    LiveActivityRefusal::TicketRefused => tracing::warn!(
                        "live activity ticket refused; keeping selections until the phone re-registers"
                    ),
                    _ => tracing::warn!(
                        %detail,
                        "live activity update refused without a recognized reason; backing off"
                    ),
                }
                if let Some(state) = self.live_activities.lock().get_mut(&job.endpoint_id)
                    && state.generation == job.generation
                {
                    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                    state.next_attempt_at = job
                        .timestamp
                        .saturating_add(LIVE_ACTIVITY_MAX_RETRY_SECONDS);
                }
            }
        }
    }

    fn forget(&self, ticket: &str) {
        let mut devices = self.devices.lock();
        let stale: Vec<String> = devices
            .devices()
            .iter()
            .filter(|device| device.push_ticket.as_deref() == Some(ticket))
            .map(|device| device.endpoint_id.clone())
            .collect();
        for endpoint_id in stale {
            match crate::storage::validate_endpoint_id(&endpoint_id)
                .and_then(|endpoint| devices.set_push_ticket(endpoint, None))
            {
                Ok(()) => tracing::info!("dropped a push ticket the relay no longer accepts"),
                Err(error) => tracing::warn!(error = %error, "dropping a push ticket failed"),
            }
        }
    }
}

/// Whether a relay attempt is worth repeating.
///
/// `post_json` reports curl's `%{http_code}`, which is **0** when the request never completed at
/// all — no route, no DNS, no TLS, no answer. That is the definition of transient, and it was
/// being treated as a refusal: the arm below returns for anything outside 5xx, so a single Wi-Fi
/// blip permanently abandoned the update and never reached the backoff written underneath it.
/// Observed doing exactly that — `live activity relay refused an update status=0` — after which
/// the Lock Screen sat on Apple's "Open Ciao to refresh this activity" until the next state
/// change or the fifteen-minute heartbeat, whichever came first.
fn relay_attempt_is_retryable(status: u16) -> bool {
    status == 0 || (500..=599).contains(&status)
}

fn valid_relay_url(url: &str) -> bool {
    url.starts_with("https://")
        && !url
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'\\'))
}

/// Posts one ticket and its sealed payload, and returns the relay's HTTP status.
///
/// `curl` rather than an HTTP crate, because the host already downloads its own releases this way
/// and a push is one bounded POST — a TLS stack and its dependency tree would be the largest
/// thing in the binary for the smallest request in the product.
///
/// The body goes over stdin, never argv: on a shared machine argv is world-readable, and a ticket
/// is a bearer credential for reaching someone's phone.
fn post_ticket(relay: &str, ticket: &str, sealed: Option<&str>) -> Result<(u16, String)> {
    post_json(
        relay,
        &match sealed {
            Some(sealed) => serde_json::json!({ "ticket": ticket, "sealed": sealed }),
            None => serde_json::json!({ "ticket": ticket }),
        }
        .to_string(),
    )
}

fn post_live_activity(
    relay: &str,
    ticket: &str,
    sealed: &str,
    timestamp: u64,
    stale_at: u64,
) -> Result<(u16, String)> {
    post_json(
        relay,
        &serde_json::json!({
            "ticket": ticket,
            "sealed": sealed,
            "event": "update",
            "timestamp": timestamp,
            "stale_at": stale_at,
        })
        .to_string(),
    )
}

/// The status, and whatever short text the relay sent with it.
///
/// The body is read because a bare 502 is not something anyone can act on — the whole reason this
/// branch spent a day guessing is that a failure that names itself is worth more than three
/// confident theories. It is bounded and only ever logged, never parsed or branched on here.
fn post_json(relay: &str, body: &str) -> Result<(u16, String)> {
    if !valid_relay_url(relay) {
        bail!("the notification relay must be a plain https:// URL");
    }
    let mut child = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--max-time",
            &CURL_MAX_SECONDS.to_string(),
            "--write-out",
            "\n%{http_code}",
            "--request",
            "POST",
            "--header",
            "content-type: application/json",
            "--data-binary",
            "@-",
        ])
        .arg(relay)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("execute curl")?;
    child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("curl stdin was not piped"))?
        .write_all(body.as_bytes())
        .context("write the push body")?;
    let output = child.wait_with_output().context("wait for curl")?;
    // `--write-out` appends the status after the body, on its own line.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let (body, status) = stdout
        .trim_end()
        .rsplit_once('\n')
        .unwrap_or(("", stdout.trim()));
    let status = status
        .trim()
        .parse()
        .map_err(|_| anyhow!("curl reported no HTTP status"))?;
    Ok((status, bounded(body.trim(), MAX_RELAY_DETAIL_CHARACTERS)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_protocol::{AgentSessionDescriptor, TurnState},
        live_activity::MAX_LIVE_ACTIVITY_ADAPTER_CHARACTERS,
        qr::decode_exact,
    };
    use std::collections::HashSet;

    #[test]
    fn one_session_is_coalesced_and_recovers_after_the_window() {
        let mut gate = NotifyGate::default();
        assert!(gate.allow("session-a", 100));
        assert!(!gate.allow("session-a", 100));
        assert!(!gate.allow("session-a", 100 + COALESCE_SECONDS - 1));
        assert!(gate.allow("session-a", 100 + COALESCE_SECONDS));

        // Coalescing is per session: another session needing attention is a different
        // interruption and is not swallowed by the first one's window.
        assert!(gate.allow("session-b", 100 + COALESCE_SECONDS));
    }

    #[test]
    fn the_global_rate_limit_bounds_every_session_together() {
        let mut gate = NotifyGate::default();
        for index in 0..RATE_LIMIT_PER_WINDOW {
            assert!(gate.allow(&format!("session-{index}"), 100), "{index}");
        }
        assert!(!gate.allow("session-over", 100));
        // The window slides rather than resetting: the first push ages out and one slot returns.
        assert!(gate.allow("session-over", 100 + RATE_LIMIT_WINDOW_SECONDS));
    }

    #[test]
    fn tracked_sessions_are_bounded_without_reopening_a_coalescing_window() {
        let mut gate = NotifyGate::default();
        // Fill the map inside one coalescing window, which the rate limit alone would not do.
        for index in 0..MAX_TRACKED_SESSIONS {
            gate.recent.insert(format!("session-{index}"), 100);
        }
        assert!(!gate.allow("session-new", 100));
        assert!(!gate.allow("session-0", 100));
        // Everything ages out together, so the bound never becomes permanent.
        assert!(gate.allow("session-new", 100 + COALESCE_SECONDS));
    }

    #[test]
    fn no_answer_from_the_relay_is_retried_rather_than_believed() {
        // curl writes 000 when the request never completed. Reading that as a verdict is how one
        // Wi-Fi outage left a Live Activity stale until the next heartbeat.
        assert!(relay_attempt_is_retryable(0));
        for status in [500, 502, 503, 599] {
            assert!(relay_attempt_is_retryable(status), "{status}");
        }
        // A real answer is an answer, including the two the callers act on by name.
        for status in [204, 400, 403, 404, 410] {
            assert!(!relay_attempt_is_retryable(status), "{status}");
        }
    }

    #[test]
    fn a_hostile_relay_url_is_refused_before_curl_runs() {
        for url in [
            "http://ciaooo.app/notify",
            "https://ciaooo.app/notify -o /etc/passwd",
            "https://ciaooo.app/\"notify",
            "file:///etc/passwd",
        ] {
            assert!(!valid_relay_url(url), "{url}");
            assert!(post_ticket(url, "ticket", None).is_err(), "{url}");
        }
        assert!(valid_relay_url(DEFAULT_RELAY_URL));
    }

    /// The one shared fixture that keeps Rust and Swift byte-identical. The Swift half is
    /// `SealedNotificationTests`; if only one of the two moves, this is what says so.
    #[test]
    fn a_sealed_payload_matches_the_shared_fixture() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            notification_key: String,
            nonce: String,
            aad: String,
            plaintext: String,
            sealed: String,
        }

        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase0/sealed-notification-v1.json"
        );
        let fixture: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let key = decode_exact::<32>(&fixture.notification_key).unwrap();
        let nonce = decode_exact::<12>(&fixture.nonce).unwrap();
        assert_eq!(fixture.aad.as_bytes(), PAYLOAD_AAD);

        // Sealing with the fixture's nonce reproduces the fixture byte for byte, which is what
        // pins the cipher, the AAD, and the nonce-first framing all at once.
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        let sealed = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: fixture.plaintext.as_bytes(),
                    aad: PAYLOAD_AAD,
                },
            )
            .unwrap();
        assert_eq!(
            base64url(&[nonce.as_slice(), sealed.as_slice()].concat()),
            fixture.sealed
        );

        // And the payload this host builds is the shape the fixture describes, so the fixture
        // cannot drift into pinning a plaintext nothing produces.
        assert_eq!(
            payload(
                "claude-9f2c1a7e",
                "ciao",
                "Alice\u{2019}s Example Mac",
                Some("seal the notification payload"),
                "permission_prompt",
            ),
            fixture.plaintext
        );
    }

    #[test]
    fn every_seal_uses_a_fresh_nonce_and_authenticates_its_payload() {
        let key = [7_u8; 32];
        let plaintext = payload("session-a", "ciao", "host", None, "idle_prompt");
        let first = decode(&seal(&key, plaintext.as_bytes()).unwrap());
        let second = decode(&seal(&key, plaintext.as_bytes()).unwrap());
        // Same key, same plaintext, different bytes: the nonce is not derived from either.
        assert_ne!(first[..12], second[..12]);
        assert_ne!(first, second);

        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        let opened = cipher
            .decrypt(
                &Nonce::try_from(&first[..12]).unwrap(),
                Payload {
                    msg: &first[12..],
                    aad: PAYLOAD_AAD,
                },
            )
            .unwrap();
        assert_eq!(opened, plaintext.as_bytes());

        // A flipped bit anywhere, the wrong key, and the wrong context all fail closed rather
        // than opening to something the device would then render.
        let mut tampered = first.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(
            cipher
                .decrypt(
                    &Nonce::try_from(&first[..12]).unwrap(),
                    Payload {
                        msg: &tampered[12..],
                        aad: PAYLOAD_AAD
                    }
                )
                .is_err()
        );
        assert!(
            cipher
                .decrypt(
                    &Nonce::try_from(&first[..12]).unwrap(),
                    Payload {
                        msg: &first[12..],
                        aad: b"ciao-notify-activity-v1"
                    }
                )
                .is_err()
        );
        assert!(
            ChaCha20Poly1305::new(&Key::from([8_u8; 32]))
                .decrypt(
                    &Nonce::try_from(&first[..12]).unwrap(),
                    Payload {
                        msg: &first[12..],
                        aad: PAYLOAD_AAD
                    }
                )
                .is_err()
        );
    }

    /// Every field in the payload is text a person chose — a directory name, a machine name, a
    /// prompt — so none of them may be trusted to be short.
    #[test]
    fn hostile_lengths_cannot_grow_the_payload_without_bound() {
        let plaintext = payload(
            "s",
            &"w".repeat(4096),
            &"h".repeat(4096),
            Some(&"t".repeat(4096)),
            "permission_prompt",
        );
        let sealed = seal(&[1; 32], plaintext.as_bytes()).unwrap();
        // Comfortably inside APNs' 4 KB, and inside the relay's own 1024-character blob bound.
        assert!(sealed.len() < 768, "{}", sealed.len());

        // Each field is cut to its own bound and says so, rather than ending mid-word as if the
        // payload had been corrupted. The marker replaces a character instead of extending it.
        let cut: serde_json::Value = serde_json::from_str(&plaintext).unwrap();
        for (field, bound) in [
            ("workspace", MAX_WORKSPACE_CHARACTERS),
            ("host", MAX_HOST_CHARACTERS),
            ("title", MAX_TITLE_CHARACTERS),
        ] {
            let value = cut[field].as_str().unwrap();
            assert_eq!(value.chars().count(), bound, "{field}");
            assert!(value.ends_with('…'), "{field}");
        }
        // A value that fits is left exactly alone.
        assert_eq!(bounded("ciao", MAX_WORKSPACE_CHARACTERS), "ciao");

        // A conversation Ciao never saw a prompt for carries no subject at all, rather than an
        // empty one the device would render as an empty pair of quotation marks.
        for absent in [None, Some("")] {
            assert!(!payload("s", "w", "h", absent, "idle_prompt").contains("title"));
        }
    }

    #[test]
    fn live_activity_fixture_pins_schema_cipher_and_purpose() {
        #[derive(serde::Deserialize)]
        struct Fixture {
            notification_key: String,
            nonce: String,
            aad: String,
            plaintext: String,
            sealed: String,
        }
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase7/live-activity-v1.json"
        );
        let fixture: Fixture = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let key = decode_exact::<32>(&fixture.notification_key).unwrap();
        let nonce = decode_exact::<12>(&fixture.nonce).unwrap();
        assert_eq!(fixture.aad.as_bytes(), LIVE_ACTIVITY_AAD);
        let payload: LiveActivityPayload = serde_json::from_str(&fixture.plaintext).unwrap();
        assert_eq!(payload.v, 1);
        assert_eq!(payload.host, "Studio Mac");
        assert_eq!(payload.sessions.len(), 2);
        assert_eq!(payload.sessions[0].state, "needs_input");
        // One row named by its prompt and one without pins both wire shapes at once: `prompt`
        // is present exactly when there is one, never an empty string.
        assert_eq!(
            payload.sessions[0].prompt.as_deref(),
            Some("Fix the reconnect wedge")
        );
        assert_eq!(payload.sessions[1].prompt, None);
        assert_eq!(serde_json::to_string(&payload).unwrap(), fixture.plaintext);
        assert_eq!(
            seal_with_nonce(&key, fixture.plaintext.as_bytes(), LIVE_ACTIVITY_AAD, nonce).unwrap(),
            fixture.sealed
        );

        // Purpose separation is cryptographic, not a decoder convention.
        let bytes = decode(&fixture.sealed);
        let cipher = ChaCha20Poly1305::new(&Key::from(key));
        assert!(
            cipher
                .decrypt(
                    &Nonce::try_from(&bytes[..12]).unwrap(),
                    Payload {
                        msg: &bytes[12..],
                        aad: PAYLOAD_AAD,
                    },
                )
                .is_err()
        );
    }

    #[test]
    fn unchanged_activity_state_waits_for_the_bounded_heartbeat() {
        let target = |ticket: char| LiveActivityTarget {
            endpoint_id: "a".repeat(64),
            ticket: ticket.to_string().repeat(140),
            key: [7; 32],
            selections: vec![crate::storage::LiveActivitySelection {
                session_id: "session-1".into(),
                adapter: "Pi".into(),
                workspace: "ciao".into(),
            }],
        };
        let overview = LiveActivityOverview::default();
        let first =
            live_activity_delivery("Studio Mac", target('T'), &overview, None, 100).unwrap();
        let state = DeliveredLiveActivity {
            ticket_fingerprint: live_activity_ticket_fingerprint(&first.ticket),
            semantic_rows: semantic_rows(&first.payload),
            payload: first.payload,
            at: 100,
        };
        assert!(
            live_activity_delivery(
                "Studio Mac",
                target('T'),
                &overview,
                Some(&state),
                100 + LIVE_ACTIVITY_HEARTBEAT_SECONDS - 1,
            )
            .is_none()
        );
        // A rotated ActivityKit token is a new destination and receives state immediately even
        // though its selected rows are unchanged.
        assert!(
            live_activity_delivery("Studio Mac", target('R'), &overview, Some(&state), 101)
                .is_some()
        );
        let heartbeat = live_activity_delivery(
            "Studio Mac",
            target('T'),
            &overview,
            Some(&state),
            100 + LIVE_ACTIVITY_HEARTBEAT_SECONDS,
        )
        .unwrap();
        // A heartbeat moves freshness, not the age of an unchanged status row.
        assert_eq!(
            heartbeat.payload.updated_at,
            100 + LIVE_ACTIVITY_HEARTBEAT_SECONDS
        );
        assert_eq!(heartbeat.payload.sessions[0].updated_at, 100);
    }

    /// Spec 018 named rows by directory alone, which cannot tell two agents in one workspace
    /// apart. The descriptor's `recent_prompt` is what names the conversation, so it rides into
    /// the activity row: bounded, absent when empty, and a change to it is a real update.
    #[test]
    fn a_prompt_names_the_row_and_its_change_alone_is_a_new_delivery() {
        let target = || LiveActivityTarget {
            endpoint_id: "a".repeat(64),
            ticket: "T".repeat(140),
            key: [7; 32],
            selections: vec![crate::storage::LiveActivitySelection {
                session_id: "session-1".into(),
                adapter: "Claude".into(),
                workspace: "ciao".into(),
            }],
        };
        let overview = |descriptor: &AgentSessionDescriptor| {
            LiveActivityOverview::project(vec![descriptor.clone()], Vec::new(), &HashSet::new())
        };
        let mut descriptor = fixture_descriptor();
        descriptor.session_id = "session-1".into();
        descriptor.recent_prompt = Some("Fix the reconnect wedge".into());

        let first =
            live_activity_delivery("Studio Mac", target(), &overview(&descriptor), None, 100)
                .unwrap();
        assert_eq!(
            first.payload.sessions[0].prompt.as_deref(),
            Some("Fix the reconnect wedge")
        );
        let state = DeliveredLiveActivity {
            ticket_fingerprint: live_activity_ticket_fingerprint(&first.ticket),
            semantic_rows: semantic_rows(&first.payload),
            payload: first.payload,
            at: 100,
        };
        // The same prompt is the same row: nothing to push before the heartbeat.
        assert!(
            live_activity_delivery(
                "Studio Mac",
                target(),
                &overview(&descriptor),
                Some(&state),
                101
            )
            .is_none()
        );

        // A new turn renames the row, and that alone is worth a push — with the wait clock
        // restarted, because the wait it measures is the new turn's.
        descriptor.recent_prompt = Some("Write the launch email".into());
        let renamed = live_activity_delivery(
            "Studio Mac",
            target(),
            &overview(&descriptor),
            Some(&state),
            102,
        )
        .unwrap();
        assert_eq!(
            renamed.payload.sessions[0].prompt.as_deref(),
            Some("Write the launch email")
        );
        assert_eq!(renamed.payload.sessions[0].updated_at, 102);

        // Arbitrary user text is bounded like every label, and an empty prompt is absence, not
        // an empty pair of quotation marks on a Lock Screen.
        descriptor.recent_prompt = Some("🧪".repeat(64));
        let bounded = live_activity_delivery(
            "Studio Mac",
            target(),
            &overview(&descriptor),
            Some(&state),
            103,
        )
        .unwrap();
        let prompt = bounded.payload.sessions[0].prompt.clone().unwrap();
        assert!(prompt.len() <= MAX_LIVE_ACTIVITY_DISPLAY_BYTES);
        assert!(prompt.ends_with('…'));
        descriptor.recent_prompt = Some(String::new());
        let empty = live_activity_delivery(
            "Studio Mac",
            target(),
            &overview(&descriptor),
            Some(&state),
            104,
        )
        .unwrap();
        assert_eq!(empty.payload.sessions[0].prompt, None);

        // A row rebuilt from the labels captured at opt-in has no conversation to name.
        let fallback = live_activity_delivery(
            "Studio Mac",
            target(),
            &LiveActivityOverview::default(),
            Some(&state),
            105,
        )
        .unwrap();
        assert_eq!(fallback.payload.sessions[0].prompt, None);
        assert_eq!(fallback.payload.sessions[0].state, "unknown");
    }

    /// The preflight that lets a per-second sweep skip projecting for nobody.
    ///
    /// It is only ever allowed to be a hint — delivery keeps its own empty check — but it carries
    /// one real obligation: the empty answer is also where a departed device's delivery state is
    /// dropped. Skipping the projection must not become a way of keeping bookkeeping alive for an
    /// activity that ended, because a stale `previous` is what suppresses a later update as
    /// unchanged.
    #[test]
    fn no_registered_device_means_no_projection_and_no_delivery_state_left_behind() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let endpoint = iroh::SecretKey::generate().public();
        let mut store = crate::storage::PairedDeviceStore::load(&path).unwrap();
        store.upsert(endpoint, 10, &[1; 32], &[2; 32]).unwrap();

        let ticket = "t".repeat(140);
        store
            .update_live_activity(
                endpoint,
                Some(&ticket),
                Some(crate::storage::LiveActivitySelectionChange::Add(
                    crate::storage::LiveActivitySelection {
                        session_id: "session-1".into(),
                        adapter: "Claude".into(),
                        workspace: "ciao".into(),
                    },
                )),
            )
            .unwrap();

        let devices = Arc::new(Mutex::new(store));
        let notifier = Notifier::new(Arc::clone(&devices), "Studio Mac".into());
        assert!(notifier.has_live_activity_interest());

        // Stand in for a round that was delivered, so the clear below has something to drop.
        notifier.inner.live_activities.lock().insert(
            endpoint.to_string(),
            LiveActivityDeliveryState {
                delivered: Some(DeliveredLiveActivity {
                    ticket_fingerprint: live_activity_ticket_fingerprint(&ticket),
                    semantic_rows: Vec::new(),
                    payload: LiveActivityPayload {
                        v: 1,
                        host: "Studio Mac".into(),
                        updated_at: 100,
                        sessions: Vec::new(),
                    },
                    at: 100,
                }),
                consecutive_failures: 3,
                next_attempt_at: 0,
                last_timestamp: 100,
                generation: 1,
            },
        );

        // The activity ends: the registration goes, and with it the reason to project at all.
        devices
            .lock()
            .update_live_activity(endpoint, None, None)
            .unwrap();
        assert!(!notifier.has_live_activity_interest());
        assert!(notifier.inner.live_activities.lock().is_empty());
    }

    /// The seam AQW-06 introduced, end to end: delivery is handed a projection rather than the
    /// two mutable owners, and the rows it builds are the ones those owners' facts describe —
    /// same labels, same states, same priority order, same opt-in fallback.
    ///
    /// A live descriptor names its own row; a persisted managed record contributes only a state
    /// and keeps the labels captured at opt-in; a session neither owner knows about is `unknown`.
    #[test]
    fn a_projection_builds_the_same_rows_the_two_owners_described() {
        let selection = |session_id: &str| crate::storage::LiveActivitySelection {
            session_id: session_id.into(),
            adapter: "Saved".into(),
            workspace: "saved-workspace".into(),
        };
        let target = LiveActivityTarget {
            endpoint_id: "a".repeat(64),
            ticket: "T".repeat(140),
            key: [7; 32],
            selections: vec![
                selection("session-idle"),
                selection("session-gone"),
                selection("session-crashed"),
                selection("session-needs-input"),
            ],
        };

        let descriptor = |session_id: &str, turn: TurnState| {
            let mut descriptor = fixture_descriptor();
            descriptor.session_id = session_id.into();
            descriptor.adapter_family = "claude".into();
            descriptor.workspace_display = "ciao".into();
            descriptor.recent_prompt = Some("Fix the reconnect wedge".into());
            descriptor.turn = turn;
            descriptor
        };
        let summary = |session_id: &str, reason: Option<&str>| {
            crate::managed_session::ManagedSessionSummary {
                session_id: session_id.into(),
                presence: "stored".into(),
                stored_reason: reason.map(str::to_owned),
                workspace_label: "ciao".into(),
                process_generation: 1,
                updated_at: 100,
            }
        };
        let overview = LiveActivityOverview::project(
            vec![
                descriptor("session-idle", TurnState::Idle),
                descriptor(
                    "session-needs-input",
                    TurnState::AwaitingInteraction { run_id: None },
                ),
            ],
            vec![summary("session-crashed", Some("worker_crash"))],
            &HashSet::new(),
        );

        let rows = live_activity_delivery("Studio Mac", target, &overview, None, 100)
            .unwrap()
            .payload
            .sessions;
        let seen: Vec<_> = rows
            .iter()
            .map(|row| {
                (
                    row.id.as_str(),
                    row.agent.as_str(),
                    row.workspace.as_str(),
                    row.prompt.as_deref(),
                    row.state.as_str(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            vec![
                // Spec 018 §3 priority, then workspace, then ID.
                (
                    "session-needs-input",
                    "claude",
                    "ciao",
                    Some("Fix the reconnect wedge"),
                    "needs_input",
                ),
                (
                    "session-crashed",
                    "Saved",
                    "saved-workspace",
                    None,
                    "failed"
                ),
                (
                    "session-idle",
                    "claude",
                    "ciao",
                    Some("Fix the reconnect wedge"),
                    "idle",
                ),
                ("session-gone", "Saved", "saved-workspace", None, "unknown"),
            ]
        );
    }

    #[test]
    fn activity_priority_and_payload_size_are_bounded() {
        let unicode = bounded_utf8(&"🧪".repeat(64), MAX_LIVE_ACTIVITY_DISPLAY_BYTES);
        assert!(unicode.len() <= MAX_LIVE_ACTIVITY_DISPLAY_BYTES);
        assert!(unicode.ends_with('…'));

        let states = [
            "unknown",
            "stopped",
            "idle",
            "done",
            "stopping",
            "active",
            "working",
            "failed",
            "needs_input",
        ];
        let priorities: Vec<_> = states.iter().map(|state| state_priority(state)).collect();
        assert_eq!(priorities, vec![8, 7, 6, 5, 4, 3, 2, 1, 0]);

        let payload = LiveActivityPayload {
            v: 1,
            host: "h".repeat(MAX_LIVE_ACTIVITY_DISPLAY_BYTES),
            updated_at: 100,
            sessions: (0..MAX_LIVE_ACTIVITY_ROWS)
                .map(|index| LiveActivityRow {
                    id: format!("{}{index}", "s".repeat(63)),
                    agent: "a".repeat(MAX_LIVE_ACTIVITY_ADAPTER_CHARACTERS),
                    workspace: "w".repeat(MAX_LIVE_ACTIVITY_DISPLAY_BYTES),
                    prompt: Some("p".repeat(MAX_LIVE_ACTIVITY_DISPLAY_BYTES)),
                    state: states[index].into(),
                    updated_at: 100,
                })
                .collect(),
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();
        let sealed = seal_for_context(&[9; 32], &plaintext, LIVE_ACTIVITY_AAD).unwrap();
        assert!(
            sealed.len() <= MAX_LIVE_ACTIVITY_SEALED_CHARACTERS,
            "{}",
            sealed.len()
        );
    }

    /// The measured waste this exists to stop: an activity iOS had ended answered 502 for about
    /// seven hours on the owner's daemon, ~390 requests an hour across two devices. At a flat
    /// minute that is ~480 rounds a night per device, every one of them the same dead activity
    /// giving the same answer.
    #[test]
    fn a_failing_activity_backs_off_instead_of_retrying_every_minute_all_night() {
        // The first failure is still worth a prompt retry — most failures are a blip.
        assert_eq!(live_activity_retry_delay(1), LIVE_ACTIVITY_RETRY_SECONDS);
        assert_eq!(live_activity_retry_delay(2), 120);
        assert_eq!(live_activity_retry_delay(3), 240);
        assert_eq!(live_activity_retry_delay(4), 480);
        // The ceiling is the heartbeat: waiting longer than the unchanged-state cadence would be
        // a distinction the sweep cannot act on.
        assert_eq!(
            live_activity_retry_delay(5),
            LIVE_ACTIVITY_MAX_RETRY_SECONDS
        );
        assert_eq!(
            live_activity_retry_delay(u32::MAX),
            LIVE_ACTIVITY_MAX_RETRY_SECONDS
        );
        // Zero cannot happen — the counter is incremented before it is read — but it must not
        // shift by -1 or wait longer than a first failure if it ever does.
        assert_eq!(live_activity_retry_delay(0), LIVE_ACTIVITY_RETRY_SECONDS);

        // Over eight hours, against the flat minute this replaces.
        let night = 8 * 60 * 60;
        let mut elapsed = 0;
        let mut rounds = 0;
        let mut failures = 0;
        while elapsed < night {
            failures += 1;
            rounds += 1;
            elapsed += live_activity_retry_delay(failures);
        }
        assert!(rounds < 40, "{rounds} rounds overnight");
        assert!(
            night / LIVE_ACTIVITY_RETRY_SECONDS > rounds * 10,
            "{rounds}"
        );
    }

    /// Audit B1: one relay 400 used to mean four unrelated things and all of them deleted the
    /// registration. Only the relay's own word for a dead ActivityKit token may do that now;
    /// everything else — including the previously deployed relay's generic "bad request" —
    /// refuses to guess.
    #[test]
    fn a_refusal_is_classified_by_the_relays_word() {
        assert_eq!(
            classify_live_activity_refusal("bad_token"),
            LiveActivityRefusal::TokenDead
        );
        assert_eq!(
            classify_live_activity_refusal("bad_ticket"),
            LiveActivityRefusal::TicketRefused
        );
        assert_eq!(
            classify_live_activity_refusal("bad_shape"),
            LiveActivityRefusal::ShapeRefused
        );
        for ambiguous in ["bad request", "", "BAD_TOKEN", "bad_token extra"] {
            assert_eq!(
                classify_live_activity_refusal(ambiguous),
                LiveActivityRefusal::Ambiguous,
                "{ambiguous:?}"
            );
        }
    }

    /// Audit B4: the failure backoff gates every send. A busy agent whose rows change every
    /// second used to bypass it entirely and re-post each second into the same failing endpoint.
    #[test]
    fn a_failing_endpoint_backs_off_even_when_state_keeps_changing() {
        let target = || LiveActivityTarget {
            endpoint_id: "a".repeat(64),
            ticket: "T".repeat(140),
            key: [7; 32],
            selections: vec![crate::storage::LiveActivitySelection {
                session_id: "session-1".into(),
                adapter: "Claude".into(),
                workspace: "ciao".into(),
            }],
        };
        let overview = LiveActivityOverview::default();
        let mut state = LiveActivityDeliveryState {
            consecutive_failures: 1,
            next_attempt_at: 200,
            ..Default::default()
        };
        // Never-delivered rows are as changed as state can be, and the gate still holds.
        assert!(
            prepare_live_activity_job("Studio Mac", target(), &overview, &mut state, 199).is_none()
        );
        assert!(
            prepare_live_activity_job("Studio Mac", target(), &overview, &mut state, 200).is_some()
        );
    }

    /// Audit B2: bookkeeping used to precede the send, so a failed or unsendable update was
    /// believed delivered and the semantic dedupe suppressed every retry. `delivered` now moves
    /// only on a confirmed 204, and only while the recording task is still the current one.
    #[test]
    fn delivery_is_recorded_only_on_success_and_only_by_the_current_generation() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint = iroh::SecretKey::generate().public();
        let mut store =
            crate::storage::PairedDeviceStore::load(temp.path().join("paired-devices.json"))
                .unwrap();
        store.upsert(endpoint, 10, &[1; 32], &[2; 32]).unwrap();
        let notifier = Notifier::new(Arc::new(Mutex::new(store)), "Studio Mac".into());

        let target = LiveActivityTarget {
            endpoint_id: endpoint.to_string(),
            ticket: "T".repeat(140),
            key: [7; 32],
            selections: vec![crate::storage::LiveActivitySelection {
                session_id: "session-1".into(),
                adapter: "Claude".into(),
                workspace: "ciao".into(),
            }],
        };
        let mut state = LiveActivityDeliveryState::default();
        let job = prepare_live_activity_job(
            "Studio Mac",
            target,
            &LiveActivityOverview::default(),
            &mut state,
            100,
        )
        .unwrap();
        // Preparing the job claims nothing about the phone.
        assert!(state.delivered.is_none());
        assert_eq!(state.generation, 1);

        notifier
            .inner
            .live_activities
            .lock()
            .insert(endpoint.to_string(), state);

        // A superseded task's success writes nothing.
        notifier
            .inner
            .live_activities
            .lock()
            .get_mut(&endpoint.to_string())
            .unwrap()
            .generation = 2;
        notifier.inner.record_live_activity_success(&job);
        assert!(
            notifier
                .inner
                .live_activities
                .lock()
                .get(&endpoint.to_string())
                .unwrap()
                .delivered
                .is_none()
        );

        // The current task's success is the one that records the claim and heals the counters.
        {
            let mut deliveries = notifier.inner.live_activities.lock();
            let state = deliveries.get_mut(&endpoint.to_string()).unwrap();
            state.generation = 1;
            state.consecutive_failures = 4;
            state.next_attempt_at = 999;
        }
        notifier.inner.record_live_activity_success(&job);
        let deliveries = notifier.inner.live_activities.lock();
        let state = deliveries.get(&endpoint.to_string()).unwrap();
        assert!(state.delivered.is_some());
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.next_attempt_at, 0);
    }

    /// Audit B4/B6: APNs ordering rides `aps.timestamp`, whose wall-clock source has one-second
    /// resolution and can step backwards across sleep. Per-endpoint monotonicity is what keeps
    /// a same-second successor and a post-sleep update from being discarded as stale.
    #[test]
    fn timestamps_only_move_forward_per_endpoint() {
        let target = |session: &str| LiveActivityTarget {
            endpoint_id: "a".repeat(64),
            ticket: "T".repeat(140),
            key: [7; 32],
            selections: vec![crate::storage::LiveActivitySelection {
                session_id: session.into(),
                adapter: "Claude".into(),
                workspace: "ciao".into(),
            }],
        };
        let overview = LiveActivityOverview::default();
        let mut state = LiveActivityDeliveryState::default();
        let first = prepare_live_activity_job(
            "Studio Mac",
            target("session-1"),
            &overview,
            &mut state,
            100,
        )
        .unwrap();
        assert_eq!(first.timestamp, 100);
        // A different selection in the same wall-clock second is a distinct, later update.
        let second = prepare_live_activity_job(
            "Studio Mac",
            target("session-2"),
            &overview,
            &mut state,
            100,
        )
        .unwrap();
        assert_eq!(second.timestamp, 101);
        assert!(second.stale_at > second.timestamp);
        // A clock that stepped backwards must not stamp an update older than one already sent.
        let after_sleep =
            prepare_live_activity_job("Studio Mac", target("session-3"), &overview, &mut state, 50)
                .unwrap();
        assert_eq!(after_sleep.timestamp, 102);
        assert_eq!(first.generation + 2, after_sleep.generation);
    }

    /// Audit B1, the whole chain: a refused ticket keeps the person's selections — the phone
    /// repairs the ticket on its next registration — while only a dead ActivityKit token clears
    /// them, because the activity it addressed no longer exists anywhere.
    #[test]
    fn a_refused_ticket_keeps_the_selections_and_a_dead_token_clears_them() {
        let temp = tempfile::tempdir().unwrap();
        let endpoint = iroh::SecretKey::generate().public();
        let mut store =
            crate::storage::PairedDeviceStore::load(temp.path().join("paired-devices.json"))
                .unwrap();
        store.upsert(endpoint, 10, &[1; 32], &[2; 32]).unwrap();
        let ticket = "t".repeat(140);
        store
            .update_live_activity(
                endpoint,
                Some(&ticket),
                Some(crate::storage::LiveActivitySelectionChange::Add(
                    crate::storage::LiveActivitySelection {
                        session_id: "session-1".into(),
                        adapter: "Claude".into(),
                        workspace: "ciao".into(),
                    },
                )),
            )
            .unwrap();
        let devices = Arc::new(Mutex::new(store));
        let notifier = Notifier::new(Arc::clone(&devices), "Studio Mac".into());
        let job = |generation: u64| LiveActivityJob {
            endpoint_id: endpoint.to_string(),
            ticket: ticket.clone(),
            sealed: "s".repeat(64),
            timestamp: 100,
            stale_at: 100 + LIVE_ACTIVITY_STALE_SECONDS,
            generation,
            delivered: DeliveredLiveActivity {
                ticket_fingerprint: live_activity_ticket_fingerprint(&ticket),
                semantic_rows: Vec::new(),
                payload: LiveActivityPayload {
                    v: 1,
                    host: "Studio Mac".into(),
                    updated_at: 100,
                    sessions: Vec::new(),
                },
                at: 100,
            },
        };
        notifier.inner.live_activities.lock().insert(
            endpoint.to_string(),
            LiveActivityDeliveryState {
                generation: 1,
                ..Default::default()
            },
        );

        // A stale ticket — or an old relay's unclassified refusal — waits at the ceiling.
        for detail in ["bad_ticket", "bad request", "bad_shape"] {
            notifier.inner.record_live_activity_refusal(&job(1), detail);
            assert!(
                !devices.lock().live_activity_targets().is_empty(),
                "{detail:?} must keep the registration"
            );
            let mut deliveries = notifier.inner.live_activities.lock();
            let state = deliveries.get_mut(&endpoint.to_string()).unwrap();
            assert_eq!(
                state.next_attempt_at,
                100 + LIVE_ACTIVITY_MAX_RETRY_SECONDS,
                "{detail:?}"
            );
            state.next_attempt_at = 0;
        }

        // The activity itself is gone: the registration goes with it, and the bookkeeping too.
        notifier
            .inner
            .record_live_activity_refusal(&job(1), "bad_token");
        assert!(devices.lock().live_activity_targets().is_empty());
        assert!(notifier.inner.live_activities.lock().is_empty());
    }

    /// The canonical Spec 005 descriptor, which is also the one the phone's own tests read.
    fn fixture_descriptor() -> AgentSessionDescriptor {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase4/agent-session-v1.json"
        );
        let fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        serde_json::from_value(fixture["list"]["sessions"][0].clone()).unwrap()
    }

    fn decode(sealed: &str) -> Vec<u8> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.decode(sealed).unwrap()
    }
}
