//! Existing, same-user Herdr Core sessions. The API is the provider boundary: discovery and
//! attachment never launch `hc`, whose CLI would start a missing core as a side effect.

use std::{
    collections::BTreeMap,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use nix::unistd::Uid;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{
        UnixStream,
        unix::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, watch},
    task::JoinHandle,
    time::timeout,
};

use crate::{
    drift,
    host_protocol::{
        Dimensions, HOST_PENDING_INPUT_BYTES, HOST_PENDING_OUTPUT_BYTES, MAX_DATA_PAYLOAD,
        MAX_SESSIONS_PER_PROVIDER, MAX_TABS_PER_SESSION, valid_herdr_core_tab_id,
        valid_session_name,
    },
    pty::{CleanupReason, PtyError, PtyExit, QueueHighWaterMarks},
    workspace::{PaneFacts, sanitize_tab_label},
};

const VENDOR: &str = "herdr_core";
const RPC_BYTES: usize = 64 * 1024;
const JSON_DEPTH: usize = 12;
const QUERY_TIMEOUT: Duration = Duration::from_secs(1);
// Leave time for the common snapshot encoder within its five-second overall deadline.
const DISCOVERY_BUDGET: Duration = Duration::from_secs(4);
const DISCOVERY_ENTRIES: usize = 128;
const STREAM_FRAME_BYTES: usize = 16 * 1024 * 1024;
const STREAM_CHUNK_BYTES: usize = 16 * 1024;
const DATA: u8 = 0;
const CREDIT: u8 = 1;
const CLOSE: u8 = 2;
const RESIZE: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoreError {
    Unavailable,
    Invalid,
    Unsupported,
}

#[derive(Debug, Clone)]
pub(crate) struct CoreConfig {
    state: PathBuf,
    runtime: Option<PathBuf>,
}

impl CoreConfig {
    pub(crate) fn for_home(home: &Path) -> Self {
        Self {
            state: home.join(".local/state/herdr-core"),
            runtime: cfg!(target_os = "linux")
                .then(|| PathBuf::from(format!("/run/user/{}/herdr-core", Uid::effective()))),
        }
    }

    #[cfg(test)]
    pub(crate) fn at(state: PathBuf) -> Self {
        Self {
            state,
            runtime: None,
        }
    }

    fn sockets(&self, name: &str) -> Vec<PathBuf> {
        if !valid_session_name(name) {
            return Vec::new();
        }
        let mut paths = Vec::new();
        if let Some(runtime) = &self.runtime {
            paths.push(runtime.join(format!("{name}.sock")));
        }
        paths.push(self.state.join(name).join(format!("{name}.sock")));
        paths
    }

    fn sessions(&self) -> (Vec<String>, u32) {
        let mut names = BTreeMap::new();
        let mut omitted = 0_u32;
        for (root, runtime) in std::iter::once((&self.state, false))
            .chain(self.runtime.as_ref().map(|root| (root, true)))
        {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for (index, entry) in entries.enumerate() {
                if index >= DISCOVERY_ENTRIES {
                    omitted = omitted.saturating_add(1);
                    note("discovery", "omitted", "entry_bound", None);
                    break;
                }
                let Ok(entry) = entry else {
                    note("discovery", "invalid", "directory_entry", None);
                    continue;
                };
                let Ok(metadata) = entry.metadata() else {
                    continue;
                };
                if metadata.uid() != Uid::effective().as_raw() {
                    continue;
                }
                let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let name = if runtime {
                    if !metadata.file_type().is_socket() {
                        continue;
                    }
                    let Some(name) = file_name.strip_suffix(".sock") else {
                        continue;
                    };
                    if name.ends_with(".holder") || name.contains(".holder.") {
                        continue;
                    } // holder sockets are not Core APIs.
                    name.to_owned()
                } else {
                    if !metadata.is_dir() || entry.file_type().is_ok_and(|t| t.is_symlink()) {
                        continue;
                    }
                    file_name
                };
                if valid_session_name(&name) {
                    names.insert(name, ());
                } else {
                    omitted = omitted.saturating_add(1);
                    note("discovery", "omitted", "session_name", None);
                }
            }
        }
        let mut names: Vec<_> = names.into_keys().collect();
        if let Some(index) = names.iter().position(|name| name == "default") {
            names.swap(0, index);
        }
        omitted =
            omitted.saturating_add(names.len().saturating_sub(MAX_SESSIONS_PER_PROVIDER) as u32);
        names.truncate(MAX_SESSIONS_PER_PROVIDER);
        (names, omitted)
    }

    async fn connect(&self, session: &str) -> Result<UnixStream, CoreError> {
        for socket in self.sockets(session) {
            let Ok(metadata) = std::fs::symlink_metadata(&socket) else {
                continue;
            };
            if !metadata.file_type().is_socket() || metadata.uid() != Uid::effective().as_raw() {
                continue;
            }
            if let Ok(stream) = UnixStream::connect(socket).await
                && stream
                    .peer_cred()
                    .is_ok_and(|peer| peer.uid() == Uid::effective().as_raw())
            {
                return Ok(stream);
            }
        }
        Err(CoreError::Unavailable)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct CoreTerminal {
    pub(crate) tab: String,
    pub(crate) label: String,
    pub(crate) pid: Option<u32>,
    pub(crate) facts: PaneFacts,
    pub(crate) status: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct CoreListing {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) terminals: Vec<CoreTerminal>,
}

pub(crate) struct CoreDiscovery {
    pub(crate) present: bool,
    pub(crate) sessions: Vec<CoreListing>,
    pub(crate) omitted: u32,
    pub(crate) failed: bool,
    pub(crate) unsupported: bool,
}

pub(crate) async fn discover(config: &CoreConfig) -> CoreDiscovery {
    let (names, omitted) = config.sessions();
    let mut result = CoreDiscovery {
        present: !names.is_empty() || config.state.is_dir(),
        sessions: Vec::new(),
        omitted,
        failed: false,
        unsupported: false,
    };
    // A snapshot shares the outer five-second budget. Each existing core gets a bounded turn;
    // a silent socket cannot hold every later provider indefinitely.
    let deadline = tokio::time::Instant::now() + DISCOVERY_BUDGET;
    let mut names = names.into_iter();
    while let Some(name) = names.next() {
        let outcome = match tokio::time::timeout_at(deadline, listing(config, &name)).await {
            Ok(outcome) => outcome,
            Err(_) => {
                result.omitted = result.omitted.saturating_add(1 + names.len() as u32);
                result.failed = true;
                note("discovery", "omitted", "deadline", None);
                break;
            }
        };
        match outcome {
            Ok((session, _omitted_terminals)) => {
                // The phone's counter counts sessions, not terminal rows. Terminal losses
                // are already accounted individually in the drift ledger.
                result.sessions.push(session);
            }
            Err(CoreError::Unavailable) => {} // A saved, stopped session is not a live Core.
            Err(CoreError::Unsupported) => {
                result.unsupported = true;
                result.omitted = result.omitted.saturating_add(1);
            }
            Err(CoreError::Invalid) => {
                result.failed = true;
                result.omitted = result.omitted.saturating_add(1);
                note("discovery", "invalid", "response", None);
            }
        }
    }
    result
}

async fn listing(config: &CoreConfig, session: &str) -> Result<(CoreListing, u32), CoreError> {
    timeout(QUERY_TIMEOUT, async {
        let stream = config.connect(session).await?;
        let mut stream = BufReader::new(stream);
        let hello = plain_call(&mut stream, 1, "hello", json!({"generation":1})).await?;
        let (identity, version) = parse_hello(&hello)?;
        let list = plain_call(&mut stream, 2, "terminal.list", json!({})).await?;
        let (terminals, omitted) = parse_terminals(&list, &identity, &version)?;
        Ok((
            CoreListing {
                name: session.to_owned(),
                version,
                terminals,
            },
            omitted,
        ))
    })
    .await
    .map_err(|_| CoreError::Invalid)?
}

pub(crate) async fn terminal(
    config: &CoreConfig,
    session: &str,
    tab: &str,
) -> Option<CoreTerminal> {
    if !valid_herdr_core_tab_id(tab) {
        return None;
    }
    let (listing, _) = listing(config, session).await.ok()?;
    listing
        .terminals
        .into_iter()
        .find(|terminal| terminal.tab == tab)
}

fn parse_hello(value: &Value) -> Result<(String, String), CoreError> {
    unknown_fields(
        value,
        &[
            "generation",
            "version",
            "core",
            "framed",
            "methods",
            "features",
        ],
        "hello",
        None,
    );
    if let Some(core) = value.get("core") {
        unknown_fields(core, &["id", "name"], "core", None);
    }
    let version = value
        .get("version")
        .and_then(Value::as_str)
        .ok_or(CoreError::Invalid)?;
    let valid_version = version
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .is_ok_and(|parts| parts.len() == 3 && (parts[0], parts[1], parts[2]) >= (0, 1, 19));
    if value.get("generation").and_then(Value::as_u64) != Some(1)
        || !valid_version
        || version.len() > 32
    {
        return Err(CoreError::Unsupported);
    }
    let identity = value
        .get("core")
        .and_then(|core| core.get("id"))
        .and_then(Value::as_str)
        .ok_or(CoreError::Invalid)?;
    if !valid_herdr_core_tab_id(&format!("{identity}:t1")) {
        return Err(CoreError::Invalid);
    }
    Ok((identity.to_owned(), version.to_owned()))
}

fn parse_terminals(
    value: &Value,
    identity: &str,
    version: &str,
) -> Result<(Vec<CoreTerminal>, u32), CoreError> {
    unknown_fields(
        value,
        &["terminals", "hidden_finished", "machines"],
        "terminal_list",
        Some(version),
    );
    let rows = value
        .get("terminals")
        .and_then(Value::as_array)
        .ok_or(CoreError::Invalid)?;
    let mut terminals = Vec::new();
    let mut omitted = 0_u32;
    let mut seen = std::collections::HashSet::new();
    for row in rows {
        let parsed = parse_terminal(row, identity, version);
        match parsed {
            Some(terminal)
                if seen.insert(terminal.tab.clone()) && terminals.len() < MAX_TABS_PER_SESSION =>
            {
                terminals.push(terminal)
            }
            _ => {
                omitted = omitted.saturating_add(1);
                note("terminal_list", "omitted", "terminal", Some(version));
            }
        }
    }
    Ok((terminals, omitted))
}

fn parse_terminal(row: &Value, identity: &str, version: &str) -> Option<CoreTerminal> {
    // These are the pinned schema's fields, including vocabulary intentionally not consumed.
    unknown_fields(
        row,
        &[
            "address",
            "argv",
            "cols",
            "created_ms",
            "cwd",
            "die_with_parent",
            "exit_code",
            "finished_ms",
            "first_message",
            "foreground",
            "identity",
            "keep",
            "labels",
            "name",
            "notify",
            "parent",
            "paste_gap_ms",
            "pid",
            "reason",
            "records",
            "reported",
            "rm",
            "rows",
            "screen",
            "signal",
            "state",
            "status",
            "status_ms",
            "stop",
            "submit",
            "template",
            "title",
            "turn",
        ],
        "terminal",
        Some(version),
    );
    if row.get("state").and_then(Value::as_str) != Some("live") {
        return None;
    }
    let address = row.get("address")?.as_str()?;
    let tab = format!("{identity}:{address}");
    if !valid_herdr_core_tab_id(&tab) {
        return None;
    } // Never project a remote machine's PID locally.
    let label = row
        .get("name")
        .and_then(Value::as_str)
        .and_then(sanitize_tab_label)
        .or_else(|| {
            row.get("title")
                .and_then(Value::as_str)
                .and_then(sanitize_tab_label)
        })
        .unwrap_or_else(|| address.to_owned());
    let pid = |v: Option<&Value>| {
        v.and_then(Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
    };
    let foreground = row.get("foreground").filter(|value| value.is_object());
    if let Some(foreground) = foreground {
        unknown_fields(
            foreground,
            &["pid", "name", "argv", "cwd"],
            "foreground",
            Some(version),
        );
    }
    let cwd = foreground
        .and_then(|value| value.get("cwd"))
        .or_else(|| row.get("cwd"))
        .and_then(Value::as_str)
        .filter(|value| {
            value.len() <= 4096
                && Path::new(value).is_absolute()
                && !value.chars().any(char::is_control)
        })
        .map(str::to_owned);
    let report = row.get("status");
    if let Some(report) = report {
        unknown_fields(
            report,
            &["state", "kind", "progress", "app", "title", "msg"],
            "status",
            Some(version),
        );
    }
    let agent = report
        .and_then(|value| value.get("app"))
        .and_then(Value::as_str)
        .filter(|name| crate::host_protocol::valid_tab_agent(name))
        .map(|name| match name {
            "claude-code" => "claude".to_owned(),
            _ => name.to_owned(),
        });
    let status = report
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
        .and_then(|status| match status {
            "idle" | "working" | "blocked" | "error" | "done" => Some(status.to_owned()),
            _ => {
                note("status", "unknown_enum", status, Some(version));
                None
            }
        });
    Some(CoreTerminal {
        tab,
        label,
        pid: pid(row.get("pid")),
        facts: PaneFacts { cwd, agent },
        status,
    })
}

fn unknown_fields(value: &Value, known: &[&str], surface: &str, version: Option<&str>) {
    if let Some(object) = value.as_object() {
        for key in object.keys().filter(|key| !known.contains(&key.as_str())) {
            note(surface, "unknown_field", key, version);
        }
    }
}
fn note(surface: &str, kind: &str, name: &str, version: Option<&str>) {
    drift::note(VENDOR, surface, kind, name, version);
}

async fn plain_call(
    stream: &mut BufReader<UnixStream>,
    id: u32,
    method: &str,
    params: Value,
) -> Result<Value, CoreError> {
    let request = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
    let mut bytes = serde_json::to_vec(&request).map_err(|_| CoreError::Invalid)?;
    bytes.push(b'\n');
    stream
        .get_mut()
        .write_all(&bytes)
        .await
        .map_err(|_| CoreError::Unavailable)?;
    let mut line = Vec::new();
    loop {
        let available = stream.fill_buf().await.map_err(|_| CoreError::Invalid)?;
        if available.is_empty() {
            return Err(CoreError::Invalid);
        }
        let count = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(count) > RPC_BYTES {
            note("rpc", "invalid", "size_bound", None);
            return Err(CoreError::Invalid);
        }
        let finished = available[count - 1] == b'\n';
        line.extend_from_slice(&available[..count]);
        stream.consume(count);
        if finished {
            break;
        }
    }
    rpc_result(&line, id)
}

fn rpc_result(bytes: &[u8], id: u32) -> Result<Value, CoreError> {
    if bytes.len() > RPC_BYTES {
        return Err(CoreError::Invalid);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| {
        note("rpc", "invalid", "json", None);
        CoreError::Invalid
    })?;
    fn depth(value: &Value, left: usize) -> bool {
        if left == 0 {
            return false;
        }
        match value {
            Value::Array(values) => values.iter().all(|v| depth(v, left - 1)),
            Value::Object(values) => values.values().all(|v| depth(v, left - 1)),
            _ => true,
        }
    }
    if !depth(&value, JSON_DEPTH)
        || value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || value.get("id").and_then(Value::as_u64) != Some(u64::from(id))
    {
        note("rpc", "invalid", "response", None);
        return Err(CoreError::Invalid);
    }
    unknown_fields(&value, &["jsonrpc", "id", "result", "error"], "rpc", None);
    if let Some(error) = value.get("error") {
        unknown_fields(error, &["code", "message", "data"], "rpc_error", None);
        let kind = error
            .get("data")
            .and_then(|data| data.get("kind"))
            .and_then(Value::as_str);
        return match kind {
            Some("unsupported_generation") => Err(CoreError::Unsupported),
            Some("not_found" | "unavailable" | "finished") => Err(CoreError::Unavailable),
            Some("invalid_params" | "internal" | "method_not_found") => Err(CoreError::Invalid),
            _ => {
                note("rpc_error", "unknown_enum", "error_kind", None);
                Err(CoreError::Invalid)
            }
        };
    }
    value.get("result").cloned().ok_or(CoreError::Invalid)
}

struct CoreInput {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

#[derive(Default)]
struct ConsumedCredit {
    bytes: AtomicUsize,
    wake: Notify,
}

pub(crate) struct CoreOutput {
    bytes: Vec<u8>,
    credit: Arc<ConsumedCredit>,
    _permit: OwnedSemaphorePermit,
}
impl CoreOutput {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
impl Drop for CoreOutput {
    fn drop(&mut self) {
        // Coalescing a byte count also covers arbitrarily many tiny vendor frames without
        // an unbounded queue or a dropped credit that would silently stall the terminal.
        self.credit
            .bytes
            .fetch_add(self.bytes.len(), Ordering::Release);
        self.credit.wake.notify_one();
    }
}

pub(crate) struct CoreSession {
    terminal_id: String,
    input: Option<mpsc::Sender<CoreInput>>,
    input_bytes: Arc<Semaphore>,
    output: mpsc::Receiver<CoreOutput>,
    resize: watch::Sender<Dimensions>,
    exit: watch::Receiver<Option<Result<PtyExit, PtyError>>>,
    read_task: JoinHandle<()>,
    write_task: JoinHandle<()>,
    high_input: Arc<AtomicUsize>,
    high_output: Arc<AtomicUsize>,
}

#[derive(Clone)]
pub(crate) struct CoreExitWatcher(watch::Receiver<Option<Result<PtyExit, PtyError>>>);
impl CoreExitWatcher {
    pub(crate) async fn wait(&mut self) -> Result<PtyExit, PtyError> {
        loop {
            if let Some(exit) = self.0.borrow().clone() {
                return exit;
            }
            self.0.changed().await.map_err(|_| PtyError::WaitFailed)?;
        }
    }
}

impl CoreSession {
    pub(crate) async fn attach(
        config: CoreConfig,
        session: String,
        tab: String,
        dimensions: Dimensions,
    ) -> Result<Self, PtyError> {
        let result = timeout(
            Duration::from_secs(3),
            Self::open(config, session, tab, dimensions),
        )
        .await
        .map_err(|_| PtyError::SessionUnavailable)?;
        result.map_err(|_| PtyError::SessionUnavailable)
    }

    async fn open(
        config: CoreConfig,
        session: String,
        tab: String,
        dimensions: Dimensions,
    ) -> Result<Self, PtyError> {
        if !valid_session_name(&session) || !valid_herdr_core_tab_id(&tab) {
            return Err(PtyError::OpenFailed);
        }
        let (wanted_core, address) = tab.split_once(':').ok_or(PtyError::OpenFailed)?;
        let stream = config
            .connect(&session)
            .await
            .map_err(|_| PtyError::OpenFailed)?;
        let mut stream = BufReader::new(stream);
        let hello = plain_call(
            &mut stream,
            1,
            "hello",
            json!({"generation":1,"framed":true}),
        )
        .await
        .map_err(|_| PtyError::OpenFailed)?;
        let (core, version) = parse_hello(&hello).map_err(|_| PtyError::OpenFailed)?;
        if core != wanted_core || hello.get("framed").and_then(Value::as_bool) != Some(true) {
            return Err(PtyError::OpenFailed);
        }
        // The held connection is the identity fence: no second socket lookup may attach t1 on
        // a replacement core after the proof above. The typed address never uses a mutable name.
        let request = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":2,"method":"terminal.attach","params":{"terminal":address,"cols":dimensions.cols,"rows":dimensions.rows,"history":0}})).map_err(|_| PtyError::OpenFailed)?;
        write_frame(stream.get_mut(), 0, DATA, &request)
            .await
            .map_err(|_| PtyError::OpenFailed)?;
        let (channel, kind, len) = read_header(&mut stream)
            .await
            .map_err(|_| PtyError::OpenFailed)?;
        if channel != 0 || kind != DATA || len > RPC_BYTES {
            return Err(PtyError::OpenFailed);
        }
        let mut reply = vec![0; len];
        stream
            .read_exact(&mut reply)
            .await
            .map_err(|_| PtyError::OpenFailed)?;
        let result = rpc_result(&reply, 2).map_err(|_| PtyError::OpenFailed)?;
        unknown_fields(
            &result,
            &[
                "channel",
                "terminal",
                "resize_notifications",
                "automatic_input",
            ],
            "attach",
            Some(&version),
        );
        let attached = parse_terminal(
            result.get("terminal").ok_or(PtyError::OpenFailed)?,
            &core,
            &version,
        )
        .ok_or(PtyError::OpenFailed)?;
        if attached.tab != tab {
            return Err(PtyError::OpenFailed);
        }
        let channel = result
            .get("channel")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
            .filter(|channel| *channel != 0)
            .ok_or(PtyError::OpenFailed)?;
        let buffered = stream.buffer().to_vec();
        let (read, write) = stream.into_inner().into_split();
        let (input_tx, input_rx) = mpsc::channel(HOST_PENDING_INPUT_BYTES / MAX_DATA_PAYLOAD);
        let (output_tx, output_rx) = mpsc::channel(HOST_PENDING_OUTPUT_BYTES / STREAM_CHUNK_BYTES);
        let consumed = Arc::new(ConsumedCredit::default());
        let write_credit = consumed.clone();
        let input_bytes = Arc::new(Semaphore::new(HOST_PENDING_INPUT_BYTES));
        let (resize_tx, resize_rx) = watch::channel(dimensions);
        let (exit_tx, exit_rx) = watch::channel(None);
        let high_input = Arc::new(AtomicUsize::new(0));
        let high_output = Arc::new(AtomicUsize::new(0));
        let write_exit = exit_tx.clone();
        let write_task = tokio::spawn(async move {
            if write_loop(write, channel, input_rx, write_credit, resize_rx)
                .await
                .is_err()
            {
                let _ = write_exit.send(Some(Err(PtyError::InputClosed)));
            }
        });
        let high = high_output.clone();
        let read_task = tokio::spawn(async move {
            let outcome =
                read_loop(read, buffered, channel, output_tx, consumed, high, &version).await;
            let _ = exit_tx.send(Some(outcome));
        });
        Ok(Self {
            terminal_id: crate::protocol::base64url(&rand::random::<[u8; 16]>()),
            input: Some(input_tx),
            input_bytes,
            output: output_rx,
            resize: resize_tx,
            exit: exit_rx,
            read_task,
            write_task,
            high_input,
            high_output,
        })
    }

    pub(crate) fn terminal_id(&self) -> &str {
        &self.terminal_id
    }
    pub(crate) fn exit_watcher(&self) -> CoreExitWatcher {
        CoreExitWatcher(self.exit.clone())
    }
    pub(crate) async fn next_output(&mut self) -> Option<CoreOutput> {
        self.output.recv().await
    }
    pub(crate) async fn send_input(&self, bytes: Vec<u8>) -> Result<(), PtyError> {
        if bytes.is_empty() || bytes.len() > MAX_DATA_PAYLOAD {
            return Err(PtyError::InvalidInput);
        }
        let sender = self.input.as_ref().ok_or(PtyError::InputClosed)?;
        let permit = self
            .input_bytes
            .clone()
            .acquire_many_owned(bytes.len() as u32)
            .await
            .map_err(|_| PtyError::InputClosed)?;
        self.high_input.fetch_max(
            HOST_PENDING_INPUT_BYTES - self.input_bytes.available_permits(),
            Ordering::Relaxed,
        );
        sender
            .send(CoreInput {
                bytes,
                _permit: permit,
            })
            .await
            .map_err(|_| PtyError::InputClosed)
    }
    pub(crate) fn request_resize(&self, dimensions: Dimensions) -> Result<(), PtyError> {
        self.resize
            .send(dimensions)
            .map_err(|_| PtyError::ResizeFailed)
    }
    pub(crate) fn queue_high_water_marks(&self) -> QueueHighWaterMarks {
        QueueHighWaterMarks {
            input_bytes: self.high_input.load(Ordering::Relaxed),
            output_bytes: self.high_output.load(Ordering::Relaxed),
        }
    }
    pub(crate) async fn cleanup(&mut self, _reason: CleanupReason) -> Result<(), PtyError> {
        self.input.take();
        self.read_task.abort();
        self.write_task.abort();
        let _ = (&mut self.read_task).await;
        let _ = (&mut self.write_task).await;
        Ok(())
    }
    pub(crate) async fn finish_normal(&mut self) -> Result<PtyExit, PtyError> {
        let result = self.exit.borrow().clone().ok_or(PtyError::WaitFailed)?;
        self.cleanup(CleanupReason::StreamEnded).await?;
        result
    }
}
impl Drop for CoreSession {
    fn drop(&mut self) {
        self.read_task.abort();
        self.write_task.abort();
    }
}

async fn write_loop(
    mut write: OwnedWriteHalf,
    channel: u32,
    mut input: mpsc::Receiver<CoreInput>,
    credit: Arc<ConsumedCredit>,
    mut resize: watch::Receiver<Dimensions>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            command = input.recv() => match command {
                Some(chunk) => write_frame(&mut write, channel, DATA, &chunk.bytes).await?,
                None => return Ok(()),
            },
            _ = credit.wake.notified() => {
                let bytes = credit.bytes.swap(0, Ordering::AcqRel) as u32;
                if bytes != 0 { write_frame(&mut write, channel, CREDIT, &bytes.to_le_bytes()).await?; }
            },
            changed = resize.changed() => {
                if changed.is_err() { return Ok(()); }
                let size = *resize.borrow_and_update();
                let mut bytes = size.cols.to_le_bytes().to_vec(); bytes.extend_from_slice(&size.rows.to_le_bytes());
                write_frame(&mut write, channel, RESIZE, &bytes).await?;
            }
        }
    }
}

async fn read_loop(
    read: OwnedReadHalf,
    buffered: Vec<u8>,
    channel: u32,
    output: mpsc::Sender<CoreOutput>,
    credit: Arc<ConsumedCredit>,
    high: Arc<AtomicUsize>,
    version: &str,
) -> Result<PtyExit, PtyError> {
    let mut read = std::io::Cursor::new(buffered).chain(read);
    let output_bytes = Arc::new(Semaphore::new(HOST_PENDING_OUTPUT_BYTES));
    loop {
        let (incoming, kind, mut len) = read_header(&mut read)
            .await
            .map_err(|_| PtyError::WaitFailed)?;
        if incoming != channel {
            note("stream", "invalid", "channel", Some(version));
            return Err(PtyError::WaitFailed);
        }
        if kind == CLOSE {
            if len > RPC_BYTES {
                return Err(PtyError::WaitFailed);
            }
            let mut bytes = vec![0; len];
            read.read_exact(&mut bytes)
                .await
                .map_err(|_| PtyError::WaitFailed)?;
            let close: Value = serde_json::from_slice(&bytes).map_err(|_| PtyError::WaitFailed)?;
            unknown_fields(
                &close,
                &["reason", "exit_code", "signal", "finished_ms"],
                "close",
                Some(version),
            );
            return match close.get("reason").and_then(Value::as_str) {
                Some("exited") => close
                    .get("exit_code")
                    .and_then(Value::as_u64)
                    .and_then(|code| u32::try_from(code).ok())
                    .map(PtyExit::Exited)
                    .or_else(|| {
                        close
                            .get("signal")
                            .and_then(Value::as_i64)
                            .and_then(|number| i32::try_from(number).ok())
                            .and_then(|number| nix::sys::signal::Signal::try_from(number).ok())
                            .map(|signal| PtyExit::Signaled(signal.to_string()))
                    })
                    .ok_or(PtyError::WaitFailed),
                Some(
                    "killed" | "server_stop" | "holder_lost" | "stopped_by_restart"
                    | "host_shutdown" | "signaled",
                ) => Err(PtyError::WaitFailed),
                _ => {
                    note("stream", "unknown_enum", "close_reason", Some(version));
                    Err(PtyError::WaitFailed)
                }
            };
        }
        if kind != DATA {
            note("stream", "unknown_enum", "frame_kind", Some(version));
            return Err(PtyError::WaitFailed);
        }
        while len > 0 {
            let count = len.min(STREAM_CHUNK_BYTES);
            let permit = output_bytes
                .clone()
                .acquire_many_owned(count as u32)
                .await
                .map_err(|_| PtyError::InputClosed)?;
            let mut bytes = vec![0; count];
            read.read_exact(&mut bytes)
                .await
                .map_err(|_| PtyError::WaitFailed)?;
            high.fetch_max(
                HOST_PENDING_OUTPUT_BYTES - output_bytes.available_permits(),
                Ordering::Relaxed,
            );
            output
                .send(CoreOutput {
                    bytes,
                    credit: credit.clone(),
                    _permit: permit,
                })
                .await
                .map_err(|_| PtyError::InputClosed)?;
            len -= count;
        }
    }
}

async fn read_header(
    read: &mut (impl tokio::io::AsyncRead + Unpin),
) -> std::io::Result<(u32, u8, usize)> {
    let mut header = [0_u8; 9];
    read.read_exact(&mut header).await?;
    let channel = u32::from_le_bytes(header[..4].try_into().expect("four bytes"));
    let len = u32::from_le_bytes(header[5..].try_into().expect("four bytes")) as usize;
    if len > STREAM_FRAME_BYTES {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    Ok((channel, header[4], len))
}
async fn write_frame(
    write: &mut (impl tokio::io::AsyncWrite + Unpin),
    channel: u32,
    kind: u8,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut header = channel.to_le_bytes().to_vec();
    header.push(kind);
    header.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    write.write_all(&header).await?;
    write.write_all(bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    const ID: &str = "0123456789abcdef0123456789abcdef";
    fn hello(framed: bool) -> Value {
        json!({"generation":1,"version":"0.1.19","core":{"id":ID,"name":"fixture"},"framed":framed,"methods":[],"features":[]})
    }
    fn row(address: &str) -> Value {
        json!({"address":address,"state":"live","name":"Fixture","pid":123,"cwd":"/tmp/start","foreground":{"pid":124,"name":"sh","argv":["sh"],"cwd":"/tmp/current"},"status":{"app":"claude-code","state":"working"}})
    }
    fn size() -> Dimensions {
        Dimensions {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }
    fn fixture() -> (tempfile::TempDir, CoreConfig, UnixListener) {
        let temp = tempfile::Builder::new()
            .prefix("ciao-hc-")
            .tempdir_in("/tmp")
            .unwrap();
        let config = CoreConfig::at(temp.path().to_owned());
        std::fs::create_dir(temp.path().join("default")).unwrap();
        let listener = UnixListener::bind(config.sockets("default").pop().unwrap()).unwrap();
        (temp, config, listener)
    }
    async fn request(stream: &mut BufReader<UnixStream>) -> Value {
        let mut line = String::new();
        stream.read_line(&mut line).await.unwrap();
        serde_json::from_str(&line).unwrap()
    }
    async fn reply(stream: &mut UnixStream, id: u32, result: Value) {
        let bytes = format!("{}\n", json!({"jsonrpc":"2.0","id":id,"result":result}));
        stream.write_all(bytes.as_bytes()).await.unwrap();
    }
    async fn frame(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> (u32, u8, Vec<u8>) {
        let (channel, kind, len) = read_header(stream).await.unwrap();
        assert!(len <= RPC_BYTES);
        let mut bytes = vec![0; len];
        stream.read_exact(&mut bytes).await.unwrap();
        (channel, kind, bytes)
    }
    async fn accept_attach(listener: UnixListener) -> UnixStream {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let request = request(&mut stream).await;
        assert_eq!(request["method"], "hello");
        assert_eq!(request["params"]["generation"], 1);
        reply(stream.get_mut(), 1, hello(true)).await;
        let (_, kind, bytes) = frame(&mut stream).await;
        assert_eq!(kind, DATA);
        let request: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(request["method"], "terminal.attach");
        assert_eq!(request["params"]["terminal"], "t1");
        let reply=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":2,"result":{"channel":1,"terminal":row("t1"),"automatic_input":true,"resize_notifications":false}})).unwrap();
        write_frame(stream.get_mut(), 0, DATA, &reply)
            .await
            .unwrap();
        stream.into_inner()
    }

    #[test]
    fn future_shaped_input_core_is_tallied_without_repeating_values() {
        let mut terminal = row("t1b");
        terminal["future_terminal_field"] = json!("PRIVATE-CANARY-VALUE");
        let list = json!({"terminals":[terminal,row("remote/t1"),row("t1b"),{"state":"future"}],"hidden_finished":0,"machines":[]});
        let (rows, omitted) = parse_terminals(&list, ID, "0.1.19").unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(omitted, 3);
        assert_eq!(rows[0].tab, format!("{ID}:t1b"));
        assert_eq!(rows[0].facts.cwd.as_deref(), Some("/tmp/current"));
        assert_eq!(rows[0].facts.agent.as_deref(), Some("claude"));
        let ledger = serde_json::to_string(&drift::snapshot()).unwrap();
        assert!(ledger.contains("future_terminal_field"));
        assert!(!ledger.contains("PRIVATE-CANARY-VALUE"));
        assert!(!ledger.contains("/tmp/current"));
    }

    #[test]
    fn hello_gates_the_grounded_floor_and_protocol_generation() {
        for version in ["0.1.19", "0.1.20", "0.2.0", "1.0.0"] {
            let mut value = hello(false);
            value["version"] = json!(version);
            assert!(parse_hello(&value).is_ok());
        }
        for version in ["0.1.18", "0.1.11", "garbage", "0.1.19-extra"] {
            let mut value = hello(false);
            value["version"] = json!(version);
            assert_eq!(parse_hello(&value), Err(CoreError::Unsupported));
        }
        let mut value = hello(false);
        value["generation"] = json!(2);
        assert_eq!(parse_hello(&value), Err(CoreError::Unsupported));
    }

    #[tokio::test]
    async fn discovery_is_read_only_and_uses_live_core_identity() {
        let (_temp, config, listener) = fixture();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            assert_eq!(request(&mut stream).await["method"], "hello");
            reply(stream.get_mut(), 1, hello(false)).await;
            assert_eq!(request(&mut stream).await["method"], "terminal.list");
            reply(
                stream.get_mut(),
                2,
                json!({"terminals":[row("t1")],"hidden_finished":0,"machines":[]}),
            )
            .await;
        });
        let found = discover(&config).await;
        assert_eq!(found.sessions.len(), 1);
        assert_eq!(found.sessions[0].terminals[0].tab, format!("{ID}:t1"));
        assert_eq!(found.omitted, 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn discovery_keeps_healthy_default_when_other_sockets_are_silent() {
        let (_temp, config, listener) = fixture();
        let mut silent = Vec::new();
        for index in 0..6 {
            let name = format!("silent-{index}");
            std::fs::create_dir(config.state.join(&name)).unwrap();
            silent.push(UnixListener::bind(config.sockets(&name).pop().unwrap()).unwrap());
        }
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            request(&mut stream).await;
            reply(stream.get_mut(), 1, hello(false)).await;
            request(&mut stream).await;
            reply(stream.get_mut(), 2, json!({"terminals":[row("t1")]})).await;
        });
        let found = timeout(Duration::from_millis(4500), discover(&config))
            .await
            .unwrap();
        assert_eq!(found.sessions.len(), 1);
        assert_eq!(found.sessions[0].name, "default");
        assert!(found.failed);
        assert_eq!(found.omitted, 6);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn stopped_core_is_never_created_and_generation_refusal_is_unsupported() {
        let (temp, config, listener) = fixture();
        let socket = config.sockets("default").pop().unwrap();
        drop(listener);
        std::fs::remove_file(&socket).unwrap();
        assert!(discover(&config).await.sessions.is_empty());
        assert!(
            CoreSession::attach(config, "default".into(), format!("{ID}:t1"), size())
                .await
                .is_err()
        );
        assert!(!socket.exists());
        assert_eq!(
            std::fs::read_dir(temp.path().join("default"))
                .unwrap()
                .count(),
            0
        );
        let reply = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"private","data":{"kind":"unsupported_generation","hint":"private"}}})).unwrap();
        assert_eq!(rpc_result(&reply, 1), Err(CoreError::Unsupported));
    }

    #[tokio::test]
    async fn selected_terminal_facts_require_the_bound_tab_and_normalize_core_claude() {
        let (_temp, config, listener) = fixture();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                request(&mut stream).await;
                reply(stream.get_mut(), 1, hello(false)).await;
                request(&mut stream).await;
                let mut other = row("t2");
                other["foreground"]["cwd"] = json!("/tmp/other");
                other["status"]["app"] = json!("codex");
                reply(stream.get_mut(), 2, json!({"terminals":[other,row("t1")]})).await;
            }
        });
        let mut workspace = crate::workspace::WorkspaceConfig::with_binary_dirs(vec![]);
        workspace.core = config;
        let facts = crate::workspace::selected_pane_facts(
            &workspace,
            crate::host_protocol::ProviderKind::HerdrCore,
            "default",
            Some(&format!("{ID}:t1")),
        )
        .await;
        assert_eq!(facts.cwd.as_deref(), Some("/tmp/current"));
        assert_eq!(facts.agent.as_deref(), Some("claude"));
        assert!(
            crate::workspace::selected_pane_facts(
                &workspace,
                crate::host_protocol::ProviderKind::HerdrCore,
                "default",
                Some(&format!("{ID}:t3"))
            )
            .await
            .cwd
            .is_none()
        );
        assert!(
            crate::workspace::selected_pane_facts(
                &workspace,
                crate::host_protocol::ProviderKind::HerdrCore,
                "default",
                None
            )
            .await
            .cwd
            .is_none()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn changed_core_identity_refuses_before_attach_or_input() {
        let (_temp, config, listener) = fixture();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            request(&mut stream).await;
            let mut other = hello(true);
            other["core"]["id"] = json!("ffffffffffffffffffffffffffffffff");
            reply(stream.get_mut(), 1, other).await;
            let mut byte = [0];
            assert_eq!(
                timeout(Duration::from_secs(1), stream.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0,
                "no attach sent to the replacement core"
            );
        });
        assert!(
            CoreSession::attach(config, "default".into(), format!("{ID}:t1"), size())
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn native_stream_preserves_bytes_credit_resize_and_detaches() {
        let (_temp, config, listener) = fixture();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_attach(listener).await;
            // The split header makes a cancellation-unsafe reader lose framing; ours lives
            // in its own task while the daemon is free to process input and resizes.
            let payload = b"synthetic-screen";
            let mut bytes = 1_u32.to_le_bytes().to_vec();
            bytes.push(DATA);
            bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            bytes.extend_from_slice(payload);
            stream.write_all(&bytes[..3]).await.unwrap();
            tokio::task::yield_now().await;
            stream.write_all(&bytes[3..]).await.unwrap();
            let mut input = false;
            let mut resized = false;
            let mut credited = false;
            while !(input && resized && credited) {
                let (channel, kind, bytes) = frame(&mut stream).await;
                assert_eq!(channel, 1);
                match kind {
                    DATA => {
                        assert_eq!(bytes, b"typed\r");
                        input = true;
                    }
                    RESIZE => {
                        assert_eq!(bytes, [93, 0, 31, 0]);
                        resized = true;
                    }
                    CREDIT => {
                        assert_eq!(
                            u32::from_le_bytes(bytes.try_into().unwrap()),
                            payload.len() as u32
                        );
                        credited = true;
                    }
                    _ => panic!("unexpected frame"),
                }
            }
            ready_tx.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(
                stream.read(&mut byte).await.unwrap(),
                0,
                "cleanup closes only this viewer"
            );
        });
        let mut session = CoreSession::attach(config, "default".into(), format!("{ID}:t1"), size())
            .await
            .unwrap();
        let output = timeout(Duration::from_secs(1), session.next_output())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(output.bytes(), b"synthetic-screen");
        session.send_input(b"typed\r".to_vec()).await.unwrap();
        session
            .request_resize(Dimensions {
                cols: 93,
                rows: 31,
                ..size()
            })
            .unwrap();
        drop(output);
        timeout(Duration::from_secs(1), ready_rx)
            .await
            .unwrap()
            .unwrap();
        session.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn output_credit_waits_for_consumption_and_crosses_multiple_windows() {
        let (_temp, config, listener) = fixture();
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let (checked_tx, checked_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_attach(listener).await;
            let chunk = vec![b'x'; STREAM_CHUNK_BYTES];
            for _ in 0..HOST_PENDING_OUTPUT_BYTES / STREAM_CHUNK_BYTES {
                write_frame(&mut stream, 1, DATA, &chunk).await.unwrap();
            }
            held_rx.await.unwrap();
            let mut byte = [0];
            assert!(
                timeout(Duration::from_millis(100), stream.read(&mut byte))
                    .await
                    .is_err(),
                "retained output must not grant credit"
            );
            checked_tx.send(()).unwrap();
            let mut credited = 0;
            while credited < HOST_PENDING_OUTPUT_BYTES {
                let (channel, kind, bytes) = frame(&mut stream).await;
                assert_eq!((channel, kind), (1, CREDIT));
                credited += u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
            }
            assert_eq!(credited, HOST_PENDING_OUTPUT_BYTES);
            for _ in 0..HOST_PENDING_OUTPUT_BYTES / STREAM_CHUNK_BYTES {
                write_frame(&mut stream, 1, DATA, &chunk).await.unwrap();
            }
            while credited < 2 * HOST_PENDING_OUTPUT_BYTES {
                let (channel, kind, bytes) = frame(&mut stream).await;
                assert_eq!((channel, kind), (1, CREDIT));
                credited += u32::from_le_bytes(bytes.try_into().unwrap()) as usize;
            }
            assert_eq!(credited, 2 * HOST_PENDING_OUTPUT_BYTES);
            done_tx.send(()).unwrap();
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });
        let mut session = CoreSession::attach(config, "default".into(), format!("{ID}:t1"), size())
            .await
            .unwrap();
        let mut held = Vec::new();
        for _ in 0..HOST_PENDING_OUTPUT_BYTES / STREAM_CHUNK_BYTES {
            held.push(
                timeout(Duration::from_secs(2), session.next_output())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(
            held.iter().map(|chunk| chunk.bytes().len()).sum::<usize>(),
            HOST_PENDING_OUTPUT_BYTES
        );
        assert_eq!(
            session.queue_high_water_marks().output_bytes,
            HOST_PENDING_OUTPUT_BYTES
        );
        held_tx.send(()).unwrap();
        timeout(Duration::from_secs(2), checked_rx)
            .await
            .unwrap()
            .unwrap();
        drop(held);
        let mut consumed = 0;
        while consumed < HOST_PENDING_OUTPUT_BYTES {
            let chunk = timeout(Duration::from_secs(2), session.next_output())
                .await
                .unwrap()
                .unwrap();
            consumed += chunk.bytes().len();
            assert!(chunk.bytes().iter().all(|byte| *byte == b'x'));
        }
        timeout(Duration::from_secs(2), done_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(session.queue_high_water_marks().output_bytes <= HOST_PENDING_OUTPUT_BYTES);
        session.cleanup(CleanupReason::ExplicitClose).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn normal_exit_and_signal_drain_output_before_terminal_exit() {
        for (code, signal, expected) in [
            (Some(7), None, PtyExit::Exited(7)),
            (None, Some(15), PtyExit::Signaled("SIGTERM".into())),
        ] {
            let (_temp, config, listener) = fixture();
            let server = tokio::spawn(async move {
                let mut stream = accept_attach(listener).await;
                write_frame(&mut stream, 1, DATA, b"final output")
                    .await
                    .unwrap();
                let close = serde_json::to_vec(&json!({"reason":"exited","exit_code":code,"signal":signal,"finished_ms":12345})).unwrap();
                write_frame(&mut stream, 1, CLOSE, &close).await.unwrap();
            });
            let mut session =
                CoreSession::attach(config, "default".into(), format!("{ID}:t1"), size())
                    .await
                    .unwrap();
            let mut output = Vec::new();
            timeout(Duration::from_secs(1), async {
                while let Some(chunk) = session.next_output().await {
                    output.extend_from_slice(chunk.bytes());
                }
            })
            .await
            .unwrap();
            assert_eq!(output, b"final output");
            assert_eq!(session.finish_normal().await.unwrap(), expected);
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn oversized_rpc_and_stream_headers_are_refused_before_payload_allocation() {
        assert!(rpc_result(&vec![b'x'; RPC_BYTES + 1], 1).is_err());
        let mut bytes = 1_u32.to_le_bytes().to_vec();
        bytes.push(DATA);
        bytes.extend_from_slice(&((STREAM_FRAME_BYTES + 1) as u32).to_le_bytes());
        assert!(read_header(&mut std::io::Cursor::new(bytes)).await.is_err());
    }

    async fn live_call(config: &CoreConfig, method: &str, params: Value) -> Value {
        timeout(Duration::from_secs(5), async {
            let stream = config.connect("default").await.unwrap();
            plain_call(&mut BufReader::new(stream), 1, method, params)
                .await
                .unwrap()
        })
        .await
        .unwrap()
    }

    async fn live_output_contains(session: &mut CoreSession, expected: &[u8]) {
        timeout(Duration::from_secs(5), async {
            let mut seen = Vec::new();
            loop {
                let output = session.next_output().await.expect("Core stream ended");
                seen.extend_from_slice(output.bytes());
                assert!(
                    seen.len() <= 2 * HOST_PENDING_OUTPUT_BYTES,
                    "bounded synthetic output"
                );
                if seen
                    .windows(expected.len())
                    .any(|window| window == expected)
                {
                    break;
                }
            }
        })
        .await
        .expect("synthetic acknowledgement did not arrive");
    }

    /// Uses an explicitly supplied binary, a fresh state/config/home, and only synthetic shell
    /// processes. The outer task always stops its own server even if an assertion panics.
    #[tokio::test]
    async fn grounded_core_roundtrip_reconnect_and_route_when_explicitly_enabled() {
        let Some(binary) = std::env::var_os("CIAO_TEST_HERDR_CORE_BIN") else {
            return;
        };
        let binary = PathBuf::from(binary);
        assert!(binary.is_absolute());
        let temp = tempfile::Builder::new()
            .prefix("ciao-hc-live-")
            .tempdir_in("/tmp")
            .unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let config = CoreConfig::at(root.join("state/herdr-core"));
        let socket = config.sockets("default").pop().unwrap();
        let mut child = tokio::process::Command::new(binary)
            .arg("serve")
            .env_clear()
            .env("HOME", &root)
            .env("XDG_STATE_HOME", root.join("state"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("HC_SOCKET", &socket)
            .env("HC_SESSION", "default")
            .env("HC_LAUNCHD_DIRECT", std::process::id().to_string())
            .env("PATH", "/usr/bin:/bin")
            .env("SHELL", "/bin/sh")
            .env("TERM", "xterm-256color")
            .current_dir(&root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let test_config = config.clone();
        let mut exercise = tokio::spawn(async move {
            timeout(Duration::from_secs(5), async {
                while test_config.connect("default").await.is_err() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("isolated Core did not become ready");
            let first_cwd = root.join("first");
            let second_cwd = root.join("second");
            std::fs::create_dir(&first_cwd).unwrap();
            std::fs::create_dir(&second_cwd).unwrap();
            let program = [
                "/bin/sh",
                "-c",
                "printf 'READY\\n'; while IFS= read -r line; do printf 'ACK:%s\\n' \"$line\"; done",
            ];
            let created = live_call(&test_config, "terminal.run", json!({"argv":program,"cwd":first_cwd,"name":"ciao-first","no_parent":true,"no_notify":true})).await;
            let address = created["address"].as_str().unwrap().to_owned();
            let pid = created["pid"].as_u64().unwrap() as u32;
            live_call(&test_config, "terminal.run", json!({"argv":program,"cwd":second_cwd,"name":"ciao-second","no_parent":true,"no_notify":true})).await;
            let found = discover(&test_config).await;
            assert_eq!(found.sessions.len(), 1);
            assert_eq!(found.sessions[0].terminals.len(), 2);
            let first = found.sessions[0]
                .terminals
                .iter()
                .find(|terminal| terminal.pid == Some(pid))
                .unwrap();
            let tab = first.tab.clone();
            let mut workspace = crate::workspace::WorkspaceConfig::with_binary_dirs(vec![]);
            workspace.core = test_config.clone();
            let facts = crate::workspace::selected_pane_facts(
                &workspace,
                crate::host_protocol::ProviderKind::HerdrCore,
                "default",
                Some(&tab),
            )
            .await;
            assert_eq!(facts.cwd.as_deref(), first_cwd.to_str());
            let resolver = crate::agent_route::TerminalRouteResolver::new(workspace);
            let proof = resolver
                .resolve(pid)
                .await
                .expect("local Core process must produce a workspace route");
            assert_eq!(
                proof.continuity(),
                crate::agent_route::RouteContinuity::WorkspaceOnly
            );
            assert_eq!(
                proof.tab_key(),
                Some((
                    crate::host_protocol::ProviderKind::HerdrCore,
                    "default".into(),
                    tab.clone()
                ))
            );
            assert!(resolver.revalidate(&proof).await);
            assert!(matches!(
                resolver.terminal_plan(&proof).await,
                Some(crate::agent_route::AgentTerminalPlan::Core { .. })
            ));

            let mut first_viewer =
                CoreSession::attach(test_config.clone(), "default".into(), tab.clone(), size())
                    .await
                    .unwrap();
            first_viewer.send_input(b"first\n".to_vec()).await.unwrap();
            live_output_contains(&mut first_viewer, b"ACK:first").await;
            let mut second_viewer =
                CoreSession::attach(test_config.clone(), "default".into(), tab.clone(), size())
                    .await
                    .unwrap();
            second_viewer
                .request_resize(Dimensions {
                    cols: 93,
                    rows: 31,
                    ..size()
                })
                .unwrap();
            timeout(Duration::from_secs(3), async {
                loop {
                    let row =
                        live_call(&test_config, "terminal.get", json!({"terminal":address})).await;
                    if row["cols"] == 93 && row["rows"] == 31 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("viewer resize must reach the existing terminal");
            first_viewer
                .cleanup(CleanupReason::ExplicitClose)
                .await
                .unwrap();
            second_viewer
                .send_input(b"survived\n".to_vec())
                .await
                .unwrap();
            live_output_contains(&mut second_viewer, b"ACK:survived").await;
            second_viewer
                .cleanup(CleanupReason::StreamEnded)
                .await
                .unwrap();
            assert_eq!(
                terminal(&test_config, "default", &tab).await.unwrap().pid,
                Some(pid)
            );
            let mut reconnect =
                CoreSession::attach(test_config.clone(), "default".into(), tab.clone(), size())
                    .await
                    .unwrap();
            reconnect
                .send_input(b"reconnected\n".to_vec())
                .await
                .unwrap();
            live_output_contains(&mut reconnect, b"ACK:reconnected").await;
            reconnect
                .cleanup(CleanupReason::ExplicitClose)
                .await
                .unwrap();
            assert_eq!(
                terminal(&test_config, "default", &tab).await.unwrap().pid,
                Some(pid)
            );
            live_call(&test_config, "terminal.kill", json!({"terminal":address})).await;
            assert!(!resolver.revalidate(&proof).await);
            assert!(
                CoreSession::attach(test_config, "default".into(), tab, size())
                    .await
                    .is_err()
            );
            eprintln!(
                "Core live: selected_cwd=true input_output=true resize=true two_viewers=true reconnect_same_pid=true stale_refused=true continuity=workspace_only"
            );
        });
        let outcome = timeout(Duration::from_secs(35), &mut exercise).await;
        if outcome.is_err() {
            exercise.abort();
            let _ = exercise.await;
        }
        // This directly contacts only the owned fixture endpoint; it cannot autostart a core.
        let stopped = timeout(Duration::from_secs(15), async {
            let stream = config.connect("default").await?;
            plain_call(&mut BufReader::new(stream), 1, "server.stop", json!({})).await
        })
        .await;
        let exited = timeout(Duration::from_secs(5), child.wait()).await;
        assert!(
            matches!(stopped, Ok(Ok(_))),
            "isolated Core shutdown must succeed"
        );
        assert!(
            matches!(exited, Ok(Ok(status)) if status.success()),
            "isolated Core must exit"
        );
        assert!(!socket.exists(), "isolated endpoint must be removed");
        assert!(matches!(outcome, Ok(Ok(()))), "Core live exercise failed");
    }
}
