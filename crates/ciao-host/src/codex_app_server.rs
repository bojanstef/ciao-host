//! Clients for the Codex app-server protocol.
//!
//! Two shapes, deliberately distinct. The **one-shot** (Spec 012 §6, §8) spawns `codex
//! app-server`, asks exactly one question, and kills it — nothing held open, no vendor session,
//! no thread loaded. The **standing connection** (Spec 013 §6) exists for exactly one case: an
//! adopted thread, where the daemon *is* the vendor client and holds the thread for as long as
//! the phone holds the conversation. It dispatches responses, notifications, and
//! server-initiated requests, and dies with the adoption record (`kill_on_drop`).
//!
//! Vendor wire stops here. Callers get `serde_json::Value` and normalize it themselves; nothing
//! from this module reaches iOS unmapped (ADR 003 §2).

use std::{
    collections::HashMap,
    path::Path,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::{mpsc, oneshot},
    time::timeout,
};

/// Whole-exchange budget. Spawning the binary and completing `initialize` dominates it; the
/// grounded machine answers a `thread/read` inside two seconds.
const APP_SERVER_TIMEOUT: Duration = Duration::from_secs(12);
/// One JSON-RPC message. A large thread is bounded here rather than by the caller, so an
/// unbounded vendor response can never become an unbounded allocation in the daemon.
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Notifications arrive unbidden while a request is in flight; this caps how many are skipped
/// before the exchange is abandoned as unanswerable.
const MAX_SKIPPED_MESSAGES: usize = 512;

/// Runs `initialize` + one request against a fresh app-server and returns the request's result.
///
/// `binary` is an absolute path, never a `PATH` lookup. The daemon is started by a service
/// manager and inherits a minimal environment — on this machine `codex` lives under a mise-managed
/// node install that launchd's `PATH` knows nothing about, so a bare `codex` failed with
/// "start the Codex app-server" and history silently never loaded. The caller resolves the
/// binary from the session's own process, which also guarantees the app-server is the same build
/// as the TUI being observed.
pub(crate) async fn request(binary: &Path, method: &str, params: Value) -> Result<Value> {
    timeout(APP_SERVER_TIMEOUT, exchange(binary, method, params))
        .await
        .map_err(|_| anyhow!("the Codex app-server did not answer in time"))?
}

async fn exchange(binary: &Path, method: &str, params: Value) -> Result<Value> {
    let mut child = Command::new(binary)
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // The vendor's diagnostics are not Ciao's to relay, and a full pipe would wedge it.
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("start the Codex app-server")?;
    let result = drive(&mut child, method, params).await;
    let _ = child.start_kill();
    result
}

async fn drive(child: &mut Child, method: &str, params: Value) -> Result<Value> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("the Codex app-server has no input"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("the Codex app-server has no output"))?;
    let mut reader = BufReader::new(stdout);

    write_message(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "clientInfo": {"name": "ciao", "title": "Ciao", "version": env!("CARGO_PKG_VERSION")}
            }
        }),
    )
    .await?;
    read_result(&mut reader, 1).await?;
    write_message(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}),
    )
    .await?;

    write_message(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": method, "params": params}),
    )
    .await?;
    read_result(&mut reader, 2).await
}

async fn write_message(stdin: &mut tokio::process::ChildStdin, message: &Value) -> Result<()> {
    let mut line = serde_json::to_vec(message)?;
    line.push(b'\n');
    stdin
        .write_all(&line)
        .await
        .context("write to the Codex app-server")?;
    stdin.flush().await.context("flush the Codex app-server")
}

/// Reads until the response with `id` arrives, skipping the server-initiated notifications and
/// requests that share the stream. An error response is an error here, not an empty result.
async fn read_result(
    reader: &mut BufReader<tokio::process::ChildStdout>,
    id: u64,
) -> Result<Value> {
    for _ in 0..MAX_SKIPPED_MESSAGES {
        let line = read_bounded_line(reader).await?;
        let Ok(message) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        if message.get("id").and_then(Value::as_u64) != Some(id) {
            continue;
        }
        if let Some(error) = message.get("error") {
            bail!(
                "the Codex app-server refused the request: {}",
                error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("no reason given")
            );
        }
        return message
            .get("result")
            .cloned()
            .ok_or_else(|| anyhow!("the Codex app-server returned no result"));
    }
    bail!("the Codex app-server never answered the request")
}

/// One newline-delimited message, refusing rather than allocating past the bound. `read_line`
/// would grow without limit, and an unbounded vendor response must not become an unbounded
/// allocation in the daemon.
async fn read_bounded_line(reader: &mut BufReader<tokio::process::ChildStdout>) -> Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .context("read from the Codex app-server")?;
        if available.is_empty() {
            if line.is_empty() {
                bail!("the Codex app-server closed before answering");
            }
            return Ok(line);
        }
        let (chunk, consumed, complete) = match available.iter().position(|byte| *byte == b'\n') {
            Some(index) => (&available[..index], index + 1, true),
            None => (available, available.len(), false),
        };
        if line.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            bail!("a Codex app-server message exceeded its byte bound");
        }
        line.extend_from_slice(chunk);
        reader.consume(consumed);
        if complete {
            return Ok(line);
        }
    }
}

/// Everything a standing connection can hand the supervisor besides a direct answer.
///
/// A server request carries the vendor's own `id` back so the answer can name it; the id is a
/// `Value` because JSON-RPC allows numbers and strings and the vendor gets to choose.
#[derive(Debug)]
pub(crate) enum AppServerEvent {
    Notification {
        method: String,
        params: Value,
    },
    ServerRequest {
        id: Value,
        method: String,
        params: Value,
    },
    /// The child's stdout ended. The connection is dead; the adoption that owns it must
    /// release. Deliberately not automatic — the supervisor decides what the death means.
    Closed {
        reason: String,
    },
}

/// How long a standing request may wait for its answer. Turn responses arrive immediately —
/// grounded: `turn/start` answered with the turn object while the turn was still streaming —
/// so this bounds a wedged child, not a long turn.
const STANDING_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounded queue toward the supervisor. Lifecycle traffic is small; a runaway delta stream is
/// the only thing that can fill it, and deltas are the one kind that may be dropped (§11): the
/// completed item carries the whole text, so losing a delta degrades streaming to
/// whole-at-end rather than losing content.
const EVENT_QUEUE_CAPACITY: usize = 1024;

type PendingRequests = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

/// A held `codex app-server` speaking for one adopted thread.
///
/// Dropping this kills the child (`kill_on_drop`), which is the release path's backstop: an
/// adoption record that goes away takes its vendor client with it, and the kernel cleans up
/// whatever the daemon forgot.
pub(crate) struct AppServerConnection {
    child: Child,
    /// `None` after shutdown. Closing stdin is the load-bearing half of ending the child: the
    /// `codex` on PATH is routinely a package-manager shim whose real binary is a grandchild
    /// our SIGKILL never reaches, and that orphan holds the stdout pipe open forever — it
    /// exits on stdin EOF instead. Grounded the hard way: the first standing-connection test
    /// hung exactly there.
    stdin: Arc<tokio::sync::Mutex<Option<tokio::process::ChildStdin>>>,
    pending: PendingRequests,
    next_id: AtomicU64,
    dropped_deltas: Arc<AtomicU64>,
}

impl AppServerConnection {
    /// Spawns from an absolute binary path — never a `PATH` lookup, for the Spec 012 §2.8
    /// reason — completes the `initialize` handshake, and returns the connection plus the
    /// event stream the supervisor consumes.
    pub(crate) async fn connect(binary: &Path) -> Result<(Self, mpsc::Receiver<AppServerEvent>)> {
        let mut child = Command::new(binary)
            .arg("app-server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("start the Codex app-server")?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("the Codex app-server has no input"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("the Codex app-server has no output"))?;

        let stdin = Arc::new(tokio::sync::Mutex::new(Some(stdin)));
        let pending: PendingRequests = Arc::new(Mutex::new(HashMap::new()));
        let dropped_deltas = Arc::new(AtomicU64::new(0));
        let (events, event_receiver) = mpsc::channel(EVENT_QUEUE_CAPACITY);
        tokio::spawn(read_loop(
            BufReader::new(stdout),
            Arc::clone(&pending),
            events,
            Arc::clone(&dropped_deltas),
        ));

        let connection = Self {
            child,
            stdin,
            pending,
            next_id: AtomicU64::new(1),
            dropped_deltas,
        };
        timeout(
            STANDING_REQUEST_TIMEOUT,
            connection.request(
                "initialize",
                json!({
                    "clientInfo": {
                        "name": "ciao",
                        "title": "Ciao",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    // `thread/settings/update` — the model/effort write — answers only for a
                    // client that declared this at the handshake; without it the vendor
                    // refuses the whole method (probed against 0.147.0, 2026-08-18). The
                    // reads this connection already does are unchanged by declaring it:
                    // experimental *fields* stay absent unless individually requested.
                    "capabilities": {"experimentalApi": true}
                }),
            ),
        )
        .await
        .map_err(|_| anyhow!("the Codex app-server did not complete initialize in time"))??;
        connection
            .notify("initialized", json!({}))
            .await
            .context("finish the Codex app-server handshake")?;
        Ok((connection, event_receiver))
    }

    pub(crate) fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Deltas the reader had to drop because the supervisor fell behind. Zero in any healthy
    /// session; reported so a degraded stream is a number in a log rather than a mystery.
    pub(crate) fn dropped_deltas(&self) -> u64 {
        self.dropped_deltas.load(Ordering::Relaxed)
    }

    /// One request over the held connection. The timeout bounds a wedged child; an error
    /// response is an error here, with the vendor's message preserved for the refusal path.
    pub(crate) async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending-request lock")
            .insert(id, sender);
        let message = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        if let Err(error) = self.write(&message).await {
            self.pending
                .lock()
                .expect("pending-request lock")
                .remove(&id);
            return Err(error);
        }
        let answer = timeout(STANDING_REQUEST_TIMEOUT, receiver).await;
        match answer {
            Ok(Ok(Ok(result))) => Ok(result),
            Ok(Ok(Err(refusal))) => bail!("the Codex app-server refused {method}: {refusal}"),
            Ok(Err(_)) => bail!("the Codex app-server closed before answering {method}"),
            Err(_) => {
                self.pending
                    .lock()
                    .expect("pending-request lock")
                    .remove(&id);
                bail!("the Codex app-server did not answer {method} in time")
            }
        }
    }

    /// Answers a server-initiated request — an approval decision travelling back.
    pub(crate) async fn answer(&self, id: Value, result: Value) -> Result<()> {
        self.write(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
            .await
    }

    /// Refuses a server-initiated request Ciao cannot answer, by JSON-RPC error rather than by
    /// silence — an unanswered request would hold the vendor's turn open forever.
    pub(crate) async fn refuse(&self, id: Value, message: &str) -> Result<()> {
        self.write(
            &json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": message}}),
        )
        .await
    }

    async fn notify(&self, method: &str, params: Value) -> Result<()> {
        self.write(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
            .await
    }

    async fn write(&self, message: &Value) -> Result<()> {
        let mut stdin = self.stdin.lock().await;
        let stdin = stdin
            .as_mut()
            .ok_or_else(|| anyhow!("the Codex app-server connection is shut down"))?;
        write_message(stdin, message).await
    }

    /// Ends the child now rather than at drop: stdin closes first, because the shim's real
    /// binary is a grandchild the kill cannot reach and it exits on stdin EOF; the kill and
    /// the kill-on-drop backstop still take the direct child.
    pub(crate) async fn shutdown(&mut self) {
        self.stdin.lock().await.take();
        let _ = self.child.start_kill();
    }
}

/// Classification of one incoming line, factored out so the dispatch rules are testable
/// without a process: a message with `method` and `id` is a server request, `method` alone is
/// a notification, `id` alone answers a pending request, anything else is noise.
fn classify(message: Value) -> Option<AppServerEvent> {
    let method = message.get("method").and_then(Value::as_str);
    let id = message.get("id");
    match (method, id) {
        (Some(method), Some(id)) => Some(AppServerEvent::ServerRequest {
            id: id.clone(),
            method: method.to_owned(),
            params: message.get("params").cloned().unwrap_or(Value::Null),
        }),
        (Some(method), None) => Some(AppServerEvent::Notification {
            method: method.to_owned(),
            params: message.get("params").cloned().unwrap_or(Value::Null),
        }),
        _ => None,
    }
}

/// A delta is the one event class that may be dropped under backpressure (§11): its content
/// arrives again, whole, on the completed item.
fn is_droppable_delta(event: &AppServerEvent) -> bool {
    matches!(
        event,
        AppServerEvent::Notification { method, .. }
            if method.ends_with("Delta") || method.ends_with("/delta") || method.contains("Delta/")
    )
}

async fn read_loop(
    mut reader: BufReader<tokio::process::ChildStdout>,
    pending: PendingRequests,
    events: mpsc::Sender<AppServerEvent>,
    dropped_deltas: Arc<AtomicU64>,
) {
    let reason = loop {
        let line = match read_bounded_line(&mut reader).await {
            Ok(line) => line,
            Err(error) => break error.to_string(),
        };
        let Ok(message) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        // A response to one of our requests resolves its waiter and produces no event.
        if message.get("method").is_none()
            && let Some(id) = message.get("id").and_then(Value::as_u64)
        {
            let waiter = pending.lock().expect("pending-request lock").remove(&id);
            if let Some(waiter) = waiter {
                let outcome = match message.get("error") {
                    Some(error) => Err(error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("no reason given")
                        .to_owned()),
                    None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
                };
                let _ = waiter.send(outcome);
            }
            continue;
        }
        let Some(event) = classify(message) else {
            continue;
        };
        if is_droppable_delta(&event) {
            if events.try_send(event).is_err() {
                dropped_deltas.fetch_add(1, Ordering::Relaxed);
            }
        } else if events.send(event).await.is_err() {
            // The supervisor hung up; nothing left to deliver to.
            return;
        }
    };
    let _ = events.send(AppServerEvent::Closed { reason }).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification_separates_requests_notifications_and_answers() {
        // A server request carries both method and id; the answer must travel back under the
        // vendor's own id, whatever JSON type it chose.
        match classify(
            json!({"id": 7, "method": "item/commandExecution/requestApproval", "params": {"command": "touch x"}}),
        ) {
            Some(AppServerEvent::ServerRequest { id, method, params }) => {
                assert_eq!(id, json!(7));
                assert_eq!(method, "item/commandExecution/requestApproval");
                assert_eq!(params["command"], "touch x");
            }
            other => panic!("expected a server request, got {other:?}"),
        }
        match classify(
            json!({"method": "turn/completed", "params": {"turn": {"status": "completed"}}}),
        ) {
            Some(AppServerEvent::Notification { method, .. }) => {
                assert_eq!(method, "turn/completed");
            }
            other => panic!("expected a notification, got {other:?}"),
        }
        // A response resolves a pending request in the read loop and never becomes an event.
        assert!(classify(json!({"id": 3, "result": {"ok": true}})).is_none());
        assert!(classify(json!({"jsonrpc": "2.0"})).is_none());
    }

    #[test]
    fn only_deltas_are_droppable_under_backpressure() {
        let delta = |method: &str| {
            classify(json!({"method": method, "params": {}})).expect("notifications classify")
        };
        assert!(is_droppable_delta(&delta("item/agentMessage/delta")));
        assert!(is_droppable_delta(&delta(
            "item/reasoning/summaryTextDelta"
        )));
        assert!(is_droppable_delta(&delta(
            "item/commandExecution/outputDelta"
        )));
        // Lifecycle events are never dropped: losing one costs content or a turn boundary.
        assert!(!is_droppable_delta(&delta("turn/completed")));
        assert!(!is_droppable_delta(&delta("item/completed")));
        assert!(!is_droppable_delta(&delta("thread/status/changed")));
    }

    /// Grounded: the standing connection completes the handshake, answers a request, and dies
    /// with its handle. No thread is loaded and no model turn is spent.
    #[tokio::test]
    async fn a_standing_connection_answers_and_dies_with_its_handle() {
        if std::env::var("CIAO_TEST_CODEX_CLI").as_deref() != Ok("1") {
            return;
        }
        let (mut connection, mut events) = AppServerConnection::connect(Path::new("codex"))
            .await
            .unwrap();
        let listed = connection
            .request("thread/list", json!({"limit": 1}))
            .await
            .unwrap();
        assert!(
            listed.get("data").is_some(),
            "thread/list answers over the standing connection"
        );
        assert_eq!(connection.dropped_deltas(), 0);
        connection.shutdown().await;
        // The reader notices the death and says so, rather than going quiet — bounded, so a
        // regression here fails instead of hanging the suite.
        timeout(Duration::from_secs(10), async {
            loop {
                match events.recv().await {
                    Some(AppServerEvent::Closed { .. }) => break,
                    Some(_) => continue,
                    None => panic!("the event stream ended without a Closed event"),
                }
            }
        })
        .await
        .expect("the shutdown must surface as a Closed event");
    }

    /// Grounded against the pinned binary, and skipped everywhere it is absent. Proves the
    /// two facts the adapter rests on: the handshake works unattended, and `hooks/list` reports
    /// what a user-level install would need to know.
    #[tokio::test]
    async fn a_one_shot_exchange_answers_from_the_pinned_binary() {
        if std::env::var("CIAO_TEST_CODEX_CLI").as_deref() != Ok("1") {
            return;
        }
        let result = request(Path::new("codex"), "hooks/list", json!({}))
            .await
            .unwrap();
        assert!(
            result.get("data").is_some(),
            "hooks/list returns its results under `data`"
        );
    }
}
