//! One viewer per Ciao terminal. Dropping the WebSocket releases Orca's viewer only.
use super::{
    OrcaConfig, Runtime,
    channel::{Channel, ChannelError, Pairing},
    uuid,
};
use crate::{
    host_protocol::{Dimensions, HOST_PENDING_OUTPUT_BYTES, MAX_DATA_PAYLOAD},
    pty::{PtyError, PtyExit, QueueHighWaterMarks},
    storage::CiaoPaths,
    terminal_input::{InputChunk, InputQueue},
};
use serde_json::{Value, json};
use std::{
    future::Future,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

pub(crate) fn valid_pane(key: &str) -> bool {
    key.split_once(':')
        .is_some_and(|(tab, leaf)| uuid(tab) && uuid(leaf))
}
fn viewport(size: Dimensions) -> Value {
    json!({"cols":size.cols,"rows":size.rows})
}

pub(super) async fn resolve(rt: &Runtime, workspace: &str, pane: &str) -> Option<Value> {
    if !uuid(workspace) || !valid_pane(pane) {
        return None;
    }
    let (worktrees, repos) = tokio::join!(
        rt.query("worktree.list", json!({"limit":super::MAX_ROWS})),
        rt.query("repo.list", json!({}))
    );
    let list = worktrees?;
    let repos = repos?;
    let mut matches = list["worktrees"].as_array()?.iter().filter(|w| {
        w["repoId"]
            .as_str()
            .and_then(|repo| super::project_folder(&repos, repo))
            .and_then(|folder| super::workspace_instance(w, folder))
            == Some(workspace)
    });
    let worktree = matches.next()?["id"].as_str()?;
    if matches.next().is_some() {
        return None;
    }
    // A recently closed tab can still resolve from Orca's layout cache. Require the
    // live PTY incarnation to appear in the fresh local listing as well.
    let (resolved, listing) = tokio::join!(rt.query(
            "terminal.resolvePane",
            json!({"worktreeId":worktree,"paneKey":pane}),
        ),rt.query("terminal.list",json!({"worktree":format!("id:{worktree}"),"limit":super::MAX_ROWS,"includePreview":false,"includeVisualLayouts":false,"requireFreshPtyLiveness":true})));
    let r = resolved?;
    let t = &r["terminal"];
    let list = listing?;
    let mut live = list["terminals"].as_array()?.iter().filter(|p| {
        p["executionHostId"] == "local"
            && p["connected"] == true
            && p["orphaned"] != true
            && p["worktreeId"] == worktree
            && p["tabId"] == t["tabId"]
            && p["leafId"] == t["leafId"]
            && p["ptyId"] == t["ptyId"]
            && p["incarnationId"] == t["incarnationId"]
    });
    live.next()?;
    if live.next().is_some() {
        return None;
    }
    let (tab, leaf) = pane.split_once(':')?;
    (t["connected"] == true
        && t["executionHostId"] == "local"
        && t["worktreeId"] == worktree
        && t["tabId"] == tab
        && t["leafId"] == leaf
        && t["handle"].is_string()
        && t["ptyId"].is_string())
    .then(|| t.clone())
}
pub(crate) async fn pair(paths: &CiaoPaths) -> anyhow::Result<()> {
    use std::io::{BufRead, Read};
    // Read from stdin so shell history and process listings never hold the offer.
    let mut text = String::new();
    std::io::stdin().lock().take(16_385).read_line(&mut text)?;
    anyhow::ensure!(text.len() <= 16_384, "Orca pairing link is too long");
    pair_link(paths, &text).await
}

pub(super) async fn pair_link(paths: &CiaoPaths, link: &str) -> anyhow::Result<()> {
    let pair = Pairing::decode(link)?;
    let candidates = Runtime::candidates(&OrcaConfig::for_home(&paths.home)).await;
    if candidates.is_empty() {
        anyhow::bail!("Orca is unavailable on this host");
    }
    crate::storage::ensure_private_directory(&paths.state_dir)?;
    let mut last_error = None;
    for rt in candidates {
        match timeout(Duration::from_secs(10), pair.clone().redeem(&rt)).await {
            Ok(Ok(redeemed)) => {
                // The offer is retired by the first sign-in with the new token. Persist it first.
                crate::storage::atomic_write_private(
                    &paths.orca_pairing_file(),
                    &serde_json::to_vec(&redeemed)?,
                )?;
                timeout(Duration::from_secs(6), Channel::connect(&rt, redeemed)).await??;
                println!("Paired this Ciao host with the local Orca runtime.");
                return Ok(());
            }
            Ok(Err(err)) => last_error = Some(anyhow::Error::from(err)),
            Err(err) => last_error = Some(anyhow::Error::from(err)),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Orca is unavailable on this host")))
}

#[derive(Default)]
struct QueueSize {
    bytes: AtomicUsize,
    peak: AtomicUsize,
}
struct QueuedBytes {
    data: Vec<u8>,
    size: Arc<QueueSize>,
    count: usize,
}
impl QueuedBytes {
    fn new(data: Vec<u8>, size: &Arc<QueueSize>) -> Self {
        let count = data.len();
        let bytes = size.bytes.fetch_add(count, Ordering::Relaxed) + count;
        size.peak.fetch_max(bytes, Ordering::Relaxed);
        Self {
            data,
            size: size.clone(),
            count,
        }
    }
    fn take(mut self) -> Vec<u8> {
        std::mem::take(&mut self.data)
    }
}
impl Drop for QueuedBytes {
    fn drop(&mut self) {
        self.size.bytes.fetch_sub(self.count, Ordering::Relaxed);
    }
}
#[derive(PartialEq)]
enum PendingOperation {
    Write,
    Resize,
}
pub(crate) struct OrcaSession {
    pub(crate) id: String,
    input: InputQueue,
    resize: watch::Sender<Dimensions>,
    output: mpsc::Receiver<QueuedBytes>,
    pub(crate) exit: watch::Receiver<Option<Result<PtyExit, PtyError>>>,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    high_output: Arc<QueueSize>,
}
/// What a viewer needs from Orca's encrypted channel. `next` must be cancel-safe: the viewer
/// polls it against input, resizes and its own deadline.
pub(super) trait ViewerChannel: Send {
    fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> impl Future<Output = Result<String, ChannelError>> + Send;
    fn next(&mut self) -> impl Future<Output = Result<Value, ChannelError>> + Send;
}
impl ViewerChannel for Channel {
    async fn request(&mut self, method: &str, params: Value) -> Result<String, ChannelError> {
        Channel::request(self, method, params).await
    }
    async fn next(&mut self) -> Result<Value, ChannelError> {
        Channel::next(self).await
    }
}

/// Why a viewer stopped. Each reason has one meaning for the phone: only a refusal of input by a
/// pane that is still there is `InputClosed`; everything else is a lost runtime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ViewerEnd {
    /// Orca refused a write. The pane is still there.
    WriteRefused,
    /// The phone sent bytes Orca cannot carry: Orca accepts UTF-8 text only.
    NotUtf8,
    /// Orca answered neither a write nor a viewport claim within five seconds.
    NoAnswer,
    SendFailed,
    ChannelFailed,
    RequestFailed,
    MalformedData,
    UnknownEvent,
    UnsolicitedAnswer,
    UnexpectedAnswer,
    ResizeRefused,
    OutputClosed,
    ResizeClosed,
}
impl ViewerEnd {
    fn error(self) -> PtyError {
        match self {
            Self::WriteRefused | Self::NotUtf8 => PtyError::InputClosed,
            Self::NoAnswer
            | Self::SendFailed
            | Self::ChannelFailed
            | Self::RequestFailed
            | Self::MalformedData
            | Self::UnknownEvent
            | Self::UnsolicitedAnswer
            | Self::UnexpectedAnswer
            | Self::ResizeRefused
            | Self::OutputClosed
            | Self::ResizeClosed => PtyError::WaitFailed,
        }
    }
}

/// The longest UTF-8 prefix of `text`, within one payload, that never splits a scalar.
fn sendable(text: &[u8]) -> Result<usize, ViewerEnd> {
    let window = &text[..text.len().min(MAX_DATA_PAYLOAD)];
    match std::str::from_utf8(window) {
        Ok(_) => Ok(window.len()),
        Err(e) if e.error_len().is_none() => Ok(e.valid_up_to()),
        Err(_) => Err(ViewerEnd::NotUtf8),
    }
}

struct Viewer<C = Channel> {
    channel: C,
    subscription: String,
    handle: String,
    client: Value,
    viewport: Value,
}
impl Viewer {
    async fn open(
        config: &OrcaConfig,
        credentials: &Path,
        workspace: &str,
        pane: &str,
        size: Dimensions,
        proof: Option<&super::route::Proof>,
    ) -> Option<(Self, String)> {
        let bytes = crate::orca::read_private_file(credentials).await?;
        let pairing: Pairing = serde_json::from_slice(&bytes).ok()?;
        let runtimes = match proof {
            Some(proof) => Runtime::discover_id(config, proof.runtime())
                .await
                .into_iter()
                .collect(),
            None => Runtime::candidates(config).await,
        };
        for rt in runtimes {
            if let Some(opened) = Self::open_in(&rt, &pairing, workspace, pane, size, proof).await {
                return Some(opened);
            }
        }
        None
    }

    async fn open_in(
        rt: &Runtime,
        pairing: &Pairing,
        workspace: &str,
        pane: &str,
        size: Dimensions,
        proof: Option<&super::route::Proof>,
    ) -> Option<(Self, String)> {
        let t = resolve(rt, workspace, pane).await?;
        if proof.is_some_and(|p| !p.matches(rt, &t)) {
            return None;
        }
        let mut channel = Channel::connect(rt, pairing.clone()).await.ok()?;
        let current = resolve(rt, workspace, pane).await?;
        if current["handle"] != t["handle"]
            || current["ptyId"] != t["ptyId"]
            || current["incarnationId"] != t["incarnationId"]
        {
            return None;
        }
        let client =
            json!({"id":crate::protocol::base64url(&rand::random::<[u8;16]>()),"type":"desktop"});
        let viewport = viewport(size);
        let handle = t["handle"].as_str()?.to_owned();
        let subscription = channel
            .request(
                "terminal.subscribe",
                json!({
                    "terminal": handle, "client": client, "viewport": viewport,
                    "capabilities": {"desktopViewportClaims": 1}, "snapshotByteBudget": 1024 * 1024
                }),
            )
            .await
            .ok()?;
        let frame = channel.next().await.ok()?;
        if frame["id"] != subscription
            || frame["ok"] != true
            || frame["result"]["type"] != "scrollback"
        {
            return None;
        }
        let snapshot = frame["result"]["serialized"].as_str()?.to_owned();
        Some((
            Self {
                channel,
                subscription,
                handle,
                client,
                viewport,
            },
            snapshot,
        ))
    }
}
impl<C: ViewerChannel> Viewer<C> {
    async fn forward(
        bytes: &str,
        tx: &mpsc::Sender<QueuedBytes>,
        peak: &Arc<QueueSize>,
    ) -> Result<(), ViewerEnd> {
        for bytes in bytes.as_bytes().chunks(MAX_DATA_PAYLOAD) {
            let permit = tx.reserve().await.map_err(|_| ViewerEnd::OutputClosed)?;
            permit.send(QueuedBytes::new(bytes.to_vec(), peak));
        }
        Ok(())
    }
    async fn run(
        &mut self,
        initial: String,
        tx: &mpsc::Sender<QueuedBytes>,
        input: &mut mpsc::Receiver<InputChunk>,
        dimensions: &mut watch::Receiver<Dimensions>,
        peak: &Arc<QueueSize>,
    ) -> Result<PtyExit, ViewerEnd> {
        Self::forward(&initial, tx, peak).await?;
        let mut pending: Option<(String, PendingOperation)> = None;
        // Accepted input not yet sent. Orca answers one write at a time, so everything queued
        // behind a write goes out together in the next one, up to one payload.
        let mut text = Vec::new();
        // The queue closes only when Ciao releases this viewer: send what was accepted, then end.
        let mut closing = false;
        let mut deadline = tokio::time::Instant::now();
        loop {
            if pending.is_none() {
                let n = sendable(&text)?;
                if n > 0 {
                    let chunk = std::str::from_utf8(&text[..n]).map_err(|_| ViewerEnd::NotUtf8)?;
                    self.viewport = viewport(*dimensions.borrow());
                    let params = json!({
                        "terminal": self.handle, "client": self.client, "viewport": self.viewport, "text": chunk
                    });
                    let id = self
                        .channel
                        .request("terminal.send", params)
                        .await
                        .map_err(|_| ViewerEnd::SendFailed)?;
                    text.drain(..n);
                    pending = Some((id, PendingOperation::Write));
                    deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                    continue;
                }
                if closing {
                    return Ok(PtyExit::Closed);
                }
            }
            tokio::select! {
                _ = tokio::time::sleep_until(deadline), if pending.is_some() => {
                    return Err(ViewerEnd::NoAnswer);
                }
                msg = input.recv(), if pending.is_none() && !closing => {
                    let Some(chunk) = msg else {
                        closing = true;
                        continue;
                    };
                    text.extend_from_slice(chunk.bytes());
                    while text.len() < MAX_DATA_PAYLOAD {
                        let Ok(chunk) = input.try_recv() else { break };
                        text.extend_from_slice(chunk.bytes());
                    }
                }
                changed = dimensions.changed(), if pending.is_none() && !closing => {
                    changed.map_err(|_| ViewerEnd::ResizeClosed)?;
                    self.viewport = viewport(*dimensions.borrow_and_update());
                    let params = json!({
                        "terminal": self.handle, "client": self.client, "viewport": self.viewport, "claim": true
                    });
                    let id = self.channel.request("terminal.updateViewport", params).await.map_err(|_| ViewerEnd::SendFailed)?;
                    pending = Some((id, PendingOperation::Resize));
                    deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                }
                frame = self.channel.next() => {
                    let frame = frame.map_err(|_| ViewerEnd::ChannelFailed)?;
                    if frame["ok"] != true { return Err(ViewerEnd::RequestFailed); }
                    let result = &frame["result"];
                    if frame["id"] == self.subscription {
                        match result["type"].as_str() {
                            Some("data") => {
                                let chunk = result["chunk"].as_str().ok_or(ViewerEnd::MalformedData)?;
                                Self::forward(chunk, tx, peak).await?;
                            }
                            Some("end") => return Ok(PtyExit::Closed),
                            Some("fit-override-changed") => {}
                            _ => return Err(ViewerEnd::UnknownEvent),
                        }
                    } else {
                        let (id, operation) = pending.take().ok_or(ViewerEnd::UnsolicitedAnswer)?;
                        if frame["id"] != id { return Err(ViewerEnd::UnexpectedAnswer); }
                        match operation {
                            PendingOperation::Write if result["send"]["accepted"] != true => return Err(ViewerEnd::WriteRefused),
                            PendingOperation::Resize if result["updated"] != true => return Err(ViewerEnd::ResizeRefused),
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)] // one viewer's whole lifetime; a params struct would be ceremony
async fn drive<C: ViewerChannel>(
    mut viewer: Viewer<C>,
    initial: String,
    outputs: mpsc::Sender<QueuedBytes>,
    mut input: mpsc::Receiver<InputChunk>,
    mut dimensions: watch::Receiver<Dimensions>,
    peak: Arc<QueueSize>,
    stop: oneshot::Receiver<()>,
    exit: watch::Sender<Option<Result<PtyExit, PtyError>>>,
) {
    let result = tokio::select! {
        result = viewer.run(initial, &outputs, &mut input, &mut dimensions, &peak) => {
            result.map_err(|end| {
                // A fixed reason, so a viewer that ends in the field names its cause in the
                // daemon log. No terminal content is logged.
                tracing::info!(reason = ?end, "Orca viewer ended");
                end.error()
            })
        }
        _ = stop => Ok(PtyExit::Closed),
    };
    // Publish the verdict before any queue closes, so a bridge that finds input or resizes
    // closed reads why instead of guessing from timing.
    let _ = exit.send(Some(result));
    let unsubscribe = json!({
        "requestId": viewer.subscription,
        "subscriptionId": format!("{}:{}", viewer.handle, viewer.client["id"].as_str().unwrap_or_default()),
        "client": viewer.client
    });
    let _ = timeout(
        Duration::from_millis(400),
        viewer.channel.request("terminal.unsubscribe", unsubscribe),
    )
    .await;
}

impl OrcaSession {
    pub(crate) async fn attach(
        config: OrcaConfig,
        credentials: PathBuf,
        workspace: String,
        pane: String,
        size: Dimensions,
    ) -> Result<Self, PtyError> {
        Self::open(&config, &credentials, &workspace, &pane, size, None).await
    }

    pub(crate) async fn attach_agent(
        config: OrcaConfig,
        credentials: PathBuf,
        proof: &super::route::Proof,
        size: Dimensions,
    ) -> Result<Self, PtyError> {
        Self::open(
            &config,
            &credentials,
            &proof.workspace,
            &proof.pane,
            size,
            Some(proof),
        )
        .await
    }

    async fn open(
        config: &OrcaConfig,
        credentials: &Path,
        workspace: &str,
        pane: &str,
        size: Dimensions,
        proof: Option<&super::route::Proof>,
    ) -> Result<Self, PtyError> {
        let (viewer, initial) = timeout(
            Duration::from_secs(6),
            Viewer::open(config, credentials, workspace, pane, size, proof),
        )
        .await
        .ok()
        .flatten()
        .ok_or(PtyError::SessionUnavailable)?;
        Ok(Self::start(viewer, initial, size))
    }

    fn start<C: ViewerChannel + 'static>(
        viewer: Viewer<C>,
        initial: String,
        size: Dimensions,
    ) -> Self {
        let (inputs, input) = InputQueue::new();
        let (outputs, output) = mpsc::channel(HOST_PENDING_OUTPUT_BYTES / MAX_DATA_PAYLOAD);
        let (resize, dimensions) = watch::channel(size);
        let (exit_tx, exit) = watch::channel(None);
        let (stop_tx, stop) = oneshot::channel();
        let high_output = Arc::new(QueueSize::default());
        let task = tokio::spawn(drive(
            viewer,
            initial,
            outputs,
            input,
            dimensions,
            high_output.clone(),
            stop,
            exit_tx,
        ));
        Self {
            id: crate::protocol::base64url(&rand::random::<[u8; 16]>()),
            input: inputs,
            resize,
            output,
            exit,
            stop: Some(stop_tx),
            task,
            high_output,
        }
    }
    #[cfg(test)]
    pub(crate) async fn send_input(&self, bytes: Vec<u8>) -> Result<(), PtyError> {
        self.input.send(bytes).await
    }
    pub(crate) fn input(&self) -> &InputQueue {
        &self.input
    }
    pub(crate) async fn next_output(&mut self) -> Option<Vec<u8>> {
        self.output.recv().await.map(QueuedBytes::take)
    }
    pub(crate) fn resize(&self, size: Dimensions) -> Result<(), PtyError> {
        self.resize.send(size).map_err(|_| PtyError::ResizeFailed)
    }
    pub(crate) fn high_water(&self) -> QueueHighWaterMarks {
        QueueHighWaterMarks {
            input_bytes: self.input.high_water(),
            output_bytes: self.high_output.peak.load(Ordering::Relaxed),
        }
    }
    pub(crate) async fn cleanup(&mut self) -> Result<(), PtyError> {
        // Complete accepted input before dropping this viewer: closing the queue lets the viewer
        // answer what it holds and then end. A failed or overloaded runtime must never keep a
        // closed Ciao connection alive indefinitely.
        self.input.close();
        if timeout(Duration::from_secs(1), &mut self.task)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if timeout(Duration::from_secs(1), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
        Ok(())
    }
}
impl Drop for OrcaSession {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
pub(crate) mod scripted {
    //! A scripted Orca runtime behind the real viewer, so tests drive `Viewer::run`, the
    //! task around it and `OrcaSession::cleanup` without a desktop app.
    use super::*;
    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

    pub(crate) const SUBSCRIPTION: &str = "subscription";

    #[derive(Debug)]
    pub(crate) struct Request {
        pub(crate) id: String,
        pub(crate) method: String,
        pub(crate) params: Value,
    }

    struct ScriptedChannel {
        requests: UnboundedSender<Request>,
        frames: UnboundedReceiver<Value>,
        sent: u64,
    }
    impl ViewerChannel for ScriptedChannel {
        async fn request(&mut self, method: &str, params: Value) -> Result<String, ChannelError> {
            self.sent += 1;
            let id = format!("request-{}", self.sent);
            self.requests
                .send(Request {
                    id: id.clone(),
                    method: method.into(),
                    params,
                })
                .map_err(|_| ChannelError)?;
            if method == "terminal.unsubscribe" {
                // A busy runtime: the viewer must not depend on this answer.
                std::future::pending::<()>().await;
            }
            Ok(id)
        }
        async fn next(&mut self) -> Result<Value, ChannelError> {
            self.frames.recv().await.ok_or(ChannelError)
        }
    }

    /// The runtime's side: what the viewer asked for, and what Orca sends back.
    pub(crate) struct Orca {
        requests: UnboundedReceiver<Request>,
        frames: Option<UnboundedSender<Value>>,
    }
    impl Orca {
        pub(crate) async fn request(&mut self) -> Request {
            timeout(Duration::from_secs(5), self.requests.recv())
                .await
                .expect("the viewer sent no request")
                .expect("the viewer is gone")
        }
        /// The next `terminal.send`, skipping nothing: any other request first is a failure.
        pub(crate) async fn write(&mut self) -> Request {
            let request = self.request().await;
            assert_eq!(request.method, "terminal.send");
            request
        }
        fn frame(&self, frame: Value) {
            if let Some(frames) = &self.frames {
                let _ = frames.send(frame);
            }
        }
        pub(crate) fn answer_write(&self, request: &Request, accepted: bool) {
            self.frame(
                json!({"id": request.id, "ok": true, "result": {"send": {"accepted": accepted}}}),
            );
        }
        pub(crate) fn data(&self, chunk: &str) {
            self.frame(
                json!({"id": SUBSCRIPTION, "ok": true, "result": {"type": "data", "chunk": chunk}}),
            );
        }
        pub(crate) fn end(&self) {
            self.frame(json!({"id": SUBSCRIPTION, "ok": true, "result": {"type": "end"}}));
        }
        /// The runtime's channel breaks.
        pub(crate) fn fail(&mut self) {
            self.frames = None;
        }
    }

    impl OrcaSession {
        pub(crate) fn scripted(size: Dimensions) -> (Self, Orca) {
            let (requests, requested) = unbounded_channel();
            let (frames, incoming) = unbounded_channel();
            let viewer = Viewer {
                channel: ScriptedChannel {
                    requests,
                    frames: incoming,
                    sent: 0,
                },
                subscription: SUBSCRIPTION.into(),
                handle: "term_scripted".into(),
                client: json!({"id": "scripted", "type": "desktop"}),
                viewport: viewport(size),
            };
            let session = Self::start(viewer, String::new(), size);
            let orca = Orca {
                requests: requested,
                frames: Some(frames),
            };
            (session, orca)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn setting(k: &str) -> String {
        std::env::var(k).expect("set disposable Orca test route")
    }
    async fn open(size: Dimensions) -> OrcaSession {
        OrcaSession::attach(
            OrcaConfig::at(setting("CIAO_TEST_ORCA_PROFILE").into()),
            setting("CIAO_TEST_ORCA_PAIRING").into(),
            setting("CIAO_TEST_ORCA_WORKSPACE"),
            setting("CIAO_TEST_ORCA_PANE"),
            size,
        )
        .await
        .expect("live attachment")
    }
    async fn until(view: &mut OrcaSession, needle: &str) {
        let mut output = Vec::new();
        timeout(Duration::from_secs(8), async {
            while let Some(chunk) = view.next_output().await {
                output.extend(chunk);
                if String::from_utf8_lossy(&output).contains(needle) {
                    return;
                }
                assert!(
                    output.len() < 1024 * 1024,
                    "unexpected terminal output volume"
                );
            }
            panic!("stream ended before expected output");
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {needle}"));
    }
    fn size() -> Dimensions {
        Dimensions {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        }
    }

    async fn verdict(session: &OrcaSession) -> Result<PtyExit, PtyError> {
        let mut exit = session.exit.clone();
        timeout(Duration::from_secs(5), exit.wait_for(Option::is_some))
            .await
            .expect("the viewer published no verdict")
            .expect("the viewer task is gone")
            .clone()
            .expect("checked above")
    }

    /// The phone sends one frame per scrolled line or key. A burst arriving within one
    /// Orca round trip is a few bytes, far below the input byte bound, and must queue.
    #[tokio::test]
    async fn burst_of_small_frames_queues_while_the_viewer_is_busy() {
        let (session, mut orca) = OrcaSession::scripted(size());
        session.send_input(b"x".to_vec()).await.unwrap();
        let _busy = orca.write().await;
        for frame in 0..8 {
            assert_eq!(
                session.send_input(b"\x1b[A".to_vec()).await,
                Ok(()),
                "frame {frame} was refused while 3-byte frames were pending"
            );
        }
        assert_eq!(session.high_water().input_bytes, 24);
    }

    /// Orca answers one write at a time. Everything queued behind a write goes out in the
    /// next write, up to one payload, instead of one round trip per frame.
    #[tokio::test]
    async fn queued_frames_go_out_together_in_the_next_write() {
        let (session, mut orca) = OrcaSession::scripted(size());
        session.send_input(b"x".to_vec()).await.unwrap();
        let first = orca.write().await;
        for _ in 0..100 {
            session.send_input(b"\x1b[A".to_vec()).await.unwrap();
        }
        orca.answer_write(&first, true);
        let next = orca.write().await;
        assert_eq!(next.params["text"], "\x1b[A".repeat(100));
    }

    #[tokio::test]
    async fn a_combined_write_stays_within_one_payload_and_never_splits_a_scalar() {
        let (session, mut orca) = OrcaSession::scripted(size());
        session.send_input(b"x".to_vec()).await.unwrap();
        let first = orca.write().await;
        let filler = "y".repeat(MAX_DATA_PAYLOAD - 1);
        session
            .send_input(filler.clone().into_bytes())
            .await
            .unwrap();
        // "é" is two bytes; the first lands on the payload boundary.
        session.send_input(vec![0xc3]).await.unwrap();
        session.send_input(vec![0xa9]).await.unwrap();
        orca.answer_write(&first, true);
        let second = orca.write().await;
        assert_eq!(second.params["text"], filler.as_str());
        orca.answer_write(&second, true);
        assert_eq!(orca.write().await.params["text"], "é");
    }

    /// Cleanup closes the queue: the viewer writes what it accepted, then ends normally.
    #[tokio::test]
    async fn cleanup_sends_accepted_input_and_ends_closed() {
        let (mut session, mut orca) = OrcaSession::scripted(size());
        session.send_input(b"abc".to_vec()).await.unwrap();
        let first = orca.write().await;
        session.send_input(b"def".to_vec()).await.unwrap();
        let runtime = async {
            orca.answer_write(&first, true);
            let second = orca.write().await;
            assert_eq!(second.params["text"], "def");
            orca.answer_write(&second, true);
        };
        let (cleaned, ()) = tokio::join!(session.cleanup(), runtime);
        cleaned.unwrap();
        assert_eq!(verdict(&session).await, Ok(PtyExit::Closed));
    }

    /// Whoever finds the viewer's queues closed must be able to read why, so the verdict is
    /// published before the viewer releases anything, even when Orca is slow to unsubscribe.
    #[tokio::test]
    async fn a_lost_runtime_is_published_before_the_viewer_lets_go() {
        let (session, mut orca) = OrcaSession::scripted(size());
        orca.fail();
        let unsubscribe = orca.request().await;
        assert_eq!(unsubscribe.method, "terminal.unsubscribe");
        assert_eq!(
            session.exit.borrow().clone(),
            Some(Err(PtyError::WaitFailed))
        );
    }

    #[tokio::test]
    async fn only_a_refusal_by_a_live_pane_is_input_closed() {
        let (session, mut orca) = OrcaSession::scripted(size());
        session.send_input(b"a".to_vec()).await.unwrap();
        let write = orca.write().await;
        orca.answer_write(&write, false);
        assert_eq!(verdict(&session).await, Err(PtyError::InputClosed));

        let (session, _orca) = OrcaSession::scripted(size());
        session.send_input(vec![0xff]).await.unwrap();
        assert_eq!(verdict(&session).await, Err(PtyError::InputClosed));
    }

    /// The phone sends one frame per scrolled line. Before the byte-bounded queue, the fifth
    /// frame of a burst failed while Orca answered the first, and the terminal was closed.
    #[tokio::test]
    #[ignore = "writes to an explicitly selected disposable Orca test pane"]
    async fn live_burst_of_small_frames_reaches_the_pane_in_order() {
        let size = Dimensions {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        };
        let mut view = open(size).await;
        let marker = format!("burst-{}", std::process::id());
        view.send_input(format!("printf '%s-ready\\n' {marker}; cat -v\r").into_bytes())
            .await
            .unwrap();
        until(&mut view, &format!("{marker}-ready")).await;
        for _ in 0..8 {
            view.send_input(b"\x1b[A".to_vec()).await.unwrap();
        }
        for letter in b'a'..=b'x' {
            view.send_input(vec![letter]).await.unwrap();
        }
        // A carriage return inside a combined write submits the line exactly once.
        for frame in [&b"\r"[..], b"1", b"2", b"\r"] {
            view.send_input(frame.to_vec()).await.unwrap();
        }
        // The tty echoes each line as typed and `cat -v` repeats it once submitted, so each
        // line appears exactly twice however the frames were combined into writes.
        let line = format!("{}abcdefghijklmnopqrstuvwx\r\n", "^[[A".repeat(8));
        let mut seen = String::new();
        timeout(Duration::from_secs(8), async {
            while seen.matches(&line).count() < 2 || seen.matches("12\r\n").count() < 2 {
                let chunk = view.next_output().await.expect("stream ended");
                seen.push_str(&String::from_utf8_lossy(&chunk));
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out; saw {seen:?}"));
        assert!(seen.find(&line) < seen.find("12\r\n"), "lines out of order");
        assert!(
            view.exit.borrow().is_none(),
            "the viewer ended during the burst"
        );
        view.send_input(vec![3]).await.unwrap();
        view.cleanup().await.unwrap();
    }

    #[tokio::test]
    #[ignore = "writes to an explicitly selected disposable Orca test pane"]
    async fn live_paired_stream() {
        let mut size = Dimensions {
            cols: 88,
            rows: 26,
            pixel_width: 0,
            pixel_height: 0,
        };
        let mut first = open(size).await;
        let mut observer = open(size).await;
        first.send_input(b"export CIAO_ORCA_TEST=survived; printf '\\033[?1049h\\033[2J\\033[Hci%s' ao-redraw; sleep 90\r".to_vec()).await.unwrap();
        until(&mut first, "ciao-redraw").await;
        until(&mut observer, "ciao-redraw").await;
        let mut repaint = open(size).await;
        until(&mut repaint, "ciao-redraw").await;
        repaint.cleanup().await.unwrap();
        first.send_input(vec![3]).await.unwrap();
        size.cols = 76;
        size.rows = 25;
        first.resize(size).unwrap();
        first
            .send_input(b"printf '\\033[?1049l'; stty size; sleep 90\r".to_vec())
            .await
            .unwrap();
        until(&mut observer, "25 76").await;
        first.send_input(vec![3]).await.unwrap();
        first.cleanup().await.unwrap();
        let mut next = open(size).await;
        next.send_input(b"printf 'pid-check-%s\\n' \"$CIAO_ORCA_TEST\"\r".to_vec())
            .await
            .unwrap();
        until(&mut next, "pid-check-survived").await;
        observer.cleanup().await.unwrap();
        next.cleanup().await.unwrap();
    }
}
