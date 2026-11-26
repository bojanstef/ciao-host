//! One viewer per Ciao terminal. Dropping the WebSocket releases Orca's viewer only.
use super::{
    Runtime,
    channel::{Channel, Pairing},
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
    let rt = Runtime::discover(&super::profile(&paths.home))
        .await
        .ok_or_else(|| anyhow::anyhow!("Orca is unavailable on this host"))?;
    crate::storage::ensure_private_directory(&paths.state_dir)?;
    let pair = timeout(Duration::from_secs(10), pair.redeem(&rt)).await??;
    // The offer is retired by the first sign-in with the new token. Persist it first.
    crate::storage::atomic_write_private(&paths.orca_pairing_file(), &serde_json::to_vec(&pair)?)?;
    timeout(Duration::from_secs(6), Channel::connect(&rt, pair)).await??;
    println!("Paired this Ciao host with the local Orca runtime.");
    Ok(())
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
struct Viewer {
    channel: Channel,
    subscription: String,
    handle: String,
    client: Value,
    viewport: Value,
}
impl Viewer {
    async fn open(
        profile: &Path,
        credentials: &Path,
        workspace: &str,
        pane: &str,
        size: Dimensions,
        proof: Option<&super::route::Proof>,
    ) -> Option<(Self, String)> {
        let rt = Runtime::discover(profile).await?;
        let t = resolve(&rt, workspace, pane).await?;
        if proof.is_some_and(|p| !p.matches(&rt, &t)) {
            return None;
        }
        let bytes = crate::orca::read_private_file(credentials).await?;
        let mut channel = Channel::connect(&rt, serde_json::from_slice(&bytes).ok()?)
            .await
            .ok()?;
        let current = resolve(&rt, workspace, pane).await?;
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
    async fn forward(
        bytes: &str,
        tx: &mpsc::Sender<QueuedBytes>,
        peak: &Arc<QueueSize>,
    ) -> Result<(), PtyError> {
        for bytes in bytes.as_bytes().chunks(MAX_DATA_PAYLOAD) {
            let permit = tx.reserve().await.map_err(|_| PtyError::InputClosed)?;
            permit.send(QueuedBytes::new(bytes.to_vec(), peak));
        }
        Ok(())
    }
    async fn run(
        &mut self,
        initial: String,
        tx: mpsc::Sender<QueuedBytes>,
        mut input: mpsc::Receiver<InputChunk>,
        mut dimensions: watch::Receiver<Dimensions>,
        peak: Arc<QueueSize>,
    ) -> Result<PtyExit, PtyError> {
        Self::forward(&initial, &tx, &peak).await?;
        let mut pending: Option<(String, PendingOperation)> = None;
        let mut utf8 = Vec::new();
        let mut deadline = tokio::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline), if pending.is_some() => {
                    return Err(PtyError::InputClosed);
                }
                msg = input.recv(), if pending.is_none() => {
                    // The queue closes only when Ciao releases this viewer, after every accepted
                    // write was answered.
                    let Some(chunk) = msg else { return Ok(PtyExit::Closed) };
                    utf8.extend_from_slice(chunk.bytes());
                    // A UTF-8 scalar may straddle Ciao data frames. Orca accepts UTF-8 text.
                    let n = match std::str::from_utf8(&utf8) {
                        Ok(_) => utf8.len(),
                        Err(e) if e.error_len().is_none() => e.valid_up_to(),
                        Err(_) => return Err(PtyError::InvalidInput),
                    };
                    if n == 0 { continue; }
                    let text = std::str::from_utf8(&utf8[..n]).map_err(|_| PtyError::InvalidInput)?;
                    self.viewport = viewport(*dimensions.borrow());
                    let params = json!({
                        "terminal": self.handle, "client": self.client, "viewport": self.viewport, "text": text
                    });
                    let id = self.channel.request("terminal.send", params).await.map_err(|_| PtyError::InputClosed)?;
                    utf8.drain(..n);
                    pending = Some((id, PendingOperation::Write));
                    deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                }
                changed = dimensions.changed(), if pending.is_none() => {
                    changed.map_err(|_| PtyError::ResizeFailed)?;
                    self.viewport = viewport(*dimensions.borrow_and_update());
                    let params = json!({
                        "terminal": self.handle, "client": self.client, "viewport": self.viewport, "claim": true
                    });
                    let id = self.channel.request("terminal.updateViewport", params).await.map_err(|_| PtyError::ResizeFailed)?;
                    pending = Some((id, PendingOperation::Resize));
                    deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                }
                frame = self.channel.next() => {
                    let frame = frame.map_err(|_| PtyError::WaitFailed)?;
                    if frame["ok"] != true { return Err(PtyError::WaitFailed); }
                    let result = &frame["result"];
                    if frame["id"] == self.subscription {
                        match result["type"].as_str() {
                            Some("data") => {
                                let chunk = result["chunk"].as_str().ok_or(PtyError::WaitFailed)?;
                                Self::forward(chunk, &tx, &peak).await?;
                            }
                            Some("end") => return Ok(PtyExit::Closed),
                            Some("fit-override-changed") => {}
                            _ => return Err(PtyError::WaitFailed),
                        }
                    } else {
                        let (id, operation) = pending.take().ok_or(PtyError::WaitFailed)?;
                        if frame["id"] != id { return Err(PtyError::WaitFailed); }
                        match operation {
                            PendingOperation::Write if result["send"]["accepted"] != true => return Err(PtyError::InputClosed),
                            PendingOperation::Resize if result["updated"] != true => return Err(PtyError::ResizeFailed),
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}
impl OrcaSession {
    pub(crate) async fn attach(
        profile: PathBuf,
        credentials: PathBuf,
        workspace: String,
        pane: String,
        size: Dimensions,
    ) -> Result<Self, PtyError> {
        Self::open(&profile, &credentials, &workspace, &pane, size, None).await
    }

    pub(crate) async fn attach_agent(
        profile: PathBuf,
        credentials: PathBuf,
        proof: &super::route::Proof,
        size: Dimensions,
    ) -> Result<Self, PtyError> {
        Self::open(
            &profile,
            &credentials,
            &proof.workspace,
            &proof.pane,
            size,
            Some(proof),
        )
        .await
    }

    async fn open(
        profile: &Path,
        credentials: &Path,
        workspace: &str,
        pane: &str,
        size: Dimensions,
        proof: Option<&super::route::Proof>,
    ) -> Result<Self, PtyError> {
        let (mut viewer, initial) = timeout(
            Duration::from_secs(6),
            Viewer::open(profile, credentials, workspace, pane, size, proof),
        )
        .await
        .ok()
        .flatten()
        .ok_or(PtyError::SessionUnavailable)?;
        let (inputs, input) = InputQueue::new();
        let (outputs, output) = mpsc::channel(HOST_PENDING_OUTPUT_BYTES / MAX_DATA_PAYLOAD);
        let (resize, dimensions) = watch::channel(size);
        let (exit_tx, exit) = watch::channel(None);
        let (stop_tx, stop) = oneshot::channel();
        let high_output = Arc::new(QueueSize::default());
        let high = high_output.clone();
        let task = tokio::spawn(async move {
            let result = tokio::select! {
                result = viewer.run(initial, outputs, input, dimensions, high) => result,
                _ = stop => Ok(PtyExit::Closed)
            };
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
            let _ = exit_tx.send(Some(result));
        });
        Ok(Self {
            id: crate::protocol::base64url(&rand::random::<[u8; 16]>()),
            input: inputs,
            resize,
            output,
            exit,
            stop: Some(stop_tx),
            task,
            high_output,
        })
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
impl OrcaSession {
    /// A session driven by a scripted viewer instead of an Orca runtime.
    fn scripted<F>(
        viewer: impl FnOnce(mpsc::Receiver<InputChunk>, mpsc::Sender<QueuedBytes>, Arc<QueueSize>) -> F,
    ) -> Self
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let (input, pending) = InputQueue::new();
        let (resize, _) = watch::channel(Dimensions {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        });
        let (outputs, output) = mpsc::channel(HOST_PENDING_OUTPUT_BYTES / MAX_DATA_PAYLOAD);
        let (_, exit) = watch::channel(None);
        let high_output = Arc::new(QueueSize::default());
        let task = tokio::spawn(viewer(pending, outputs, high_output.clone()));
        Self {
            id: String::new(),
            input,
            resize,
            output,
            exit,
            stop: None,
            task,
            high_output,
        }
    }

    /// A session whose viewer has not taken any input yet, as during one Orca round trip.
    fn stalled() -> (Self, ()) {
        let session = Self::scripted(|input, output, _| async move {
            let _held = (input, output);
            std::future::pending::<()>().await
        });
        (session, ())
    }

    /// A viewer that must forward `bytes` of output before it reads any input, as a real
    /// viewer does when output precedes the answer to a pending write.
    pub(crate) fn output_before_input(bytes: usize) -> Self {
        Self::scripted(move |mut input, output, peak| async move {
            if Viewer::forward(&"x".repeat(bytes), &output, &peak)
                .await
                .is_ok()
            {
                while input.recv().await.is_some() {}
            }
        })
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
            setting("CIAO_TEST_ORCA_PROFILE").into(),
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
    /// The phone sends one frame per scrolled line or key. A burst arriving within one
    /// Orca round trip is a few bytes, far below the input byte bound, and must queue.
    #[tokio::test]
    async fn burst_of_small_frames_queues_while_the_viewer_is_busy() {
        let (session, _viewer) = OrcaSession::stalled();
        for frame in 0..8 {
            assert_eq!(
                session.send_input(b"\x1b[A".to_vec()).await,
                Ok(()),
                "frame {frame} was refused while 3-byte frames were pending"
            );
        }
        assert_eq!(session.high_water().input_bytes, 24);
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
        until(
            &mut view,
            &format!("{}abcdefghijklmnopqrstuvwx", "^[[A".repeat(8)),
        )
        .await;
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
