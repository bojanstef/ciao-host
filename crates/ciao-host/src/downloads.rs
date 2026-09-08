//! Spec 015 — one file, host to phone, so a long-press in the terminal can preview it.
//!
//! The mirror of `uploads.rs` and deliberately smaller. Uploads must invent a destination,
//! guard a quota, survive resumption, and treat the phone's filename as hostile. A download
//! names a file that already exists, streams it once, and forgets it — there is no store, no
//! partial, no TTL, and no sweeper.
//!
//! **No containment check, on purpose.** The phone that can open this stream can already type
//! `cat` into the same terminal, so restricting previews to a subtree would deny nothing while
//! reading like protection. Spec 008's locator ceremony exists for the *agent* surface, which
//! has a boundary this one does not (Spec 015 §2).

use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::host_protocol::HostProtocolError;

/// Version tag inside every JSON control payload; independent of the stream preface version.
pub const DOWNLOAD_JSON_VERSION: u8 = 1;

pub const FRAME_GET_OPEN: u8 = 0x01;
pub const FRAME_GET_ACCEPTED: u8 = 0x02;
pub const FRAME_GET_CHUNK: u8 = 0x03;
pub const FRAME_GET_DONE: u8 = 0x04;
pub const FRAME_GET_ERROR: u8 = 0x05;
pub const FRAME_GET_CANCEL: u8 = 0x06;

pub const MAX_DOWNLOAD_CONTROL_PAYLOAD: usize = 4096;
pub const MAX_DOWNLOAD_CHUNK_PAYLOAD: usize = 16 * 1024;
/// Hard ceiling on what a preview will move. App Store screenshots run 1–6 MiB; past this the
/// phone is better served by the terminal it is already looking at.
pub const MAX_DOWNLOAD_BYTES: u64 = 16 * 1024 * 1024;
/// Longest path token accepted, matching the practical `PATH_MAX` on both host platforms.
pub const MAX_PATH_BYTES: usize = 4096;
pub const DOWNLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Categorical error codes of the `get_error` frame — the closed wire vocabulary both sides
/// implement; nothing else may appear in `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DownloadErrorCode {
    NotAFile,
    Denied,
    TooLarge,
    Invalid,
    Io,
    Timeout,
    Cancelled,
}

impl DownloadErrorCode {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::NotAFile => "not_a_file",
            Self::Denied => "denied",
            Self::TooLarge => "too_large",
            Self::Invalid => "invalid",
            Self::Io => "io",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A failure that maps directly onto one `get_error` frame. Messages are fixed short strings:
/// no path, no filename, and no distinction between "denied" and "absent" — a preview refusal
/// must never become a filesystem probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadFailure {
    pub code: DownloadErrorCode,
    pub message: &'static str,
}

impl DownloadFailure {
    const fn new(code: DownloadErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

/// What the phone long-pressed. `cwd` is the terminal's own present working directory, which
/// the app reads from the VT's OSC 7 state rather than from any process table — that is why it
/// stays correct inside tmux and herdr, where the PTY's child is a multiplexer client whose
/// directory has nothing to do with the shell the user is watching.
///
/// **Not** correct under ssh, and that one is a hazard rather than a miss: a remote shell would
/// report its own cwd, which this resolves against the *local* filesystem — usually not-found,
/// occasionally a same-named local file, which is the wrong file shown as if it were right. Moot
/// today because no shell in Ciao's terminal emits OSC 7 at all (§11), but it is the first thing
/// to guard if one ever does. Since 2026-08-20 that silence no longer costs the feature: when
/// this field is absent the host asks the multiplexer where the session is standing instead
/// (`workspace::session_cwd`), so the wire stays exactly as it was and relative tokens resolve
/// anyway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetOpen {
    pub v: u8,
    /// The selected token, exactly as it appeared on screen. Ignored when `kind` is
    /// `git_diff`, which names no file — the app sends `.` there because the field predates it.
    pub path: String,
    /// Absent when the shell never reported one; the host then falls back to the attached
    /// session's own directory, and only if that is unavailable too can just absolute tokens
    /// resolve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// What to send back. Absent means the Spec 015 file preview this stream was built for.
    ///
    /// Spec 008 reserves stream kind `0x04` for a structured diff snapshot, and that is still
    /// the right shape for the real feature. This rides the download stream instead because a
    /// spike that answers "does the renderer work on a phone" should not first have to build a
    /// manifest protocol — the bytes are bounded host→phone bytes either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// For `git_diff`: which range of history to show, as one of the tokens this host itself
    /// enumerated on a previous answer. Never a revision string — see `git_diff::DiffBase`.
    /// Absent means uncommitted, which is what every app before the base picker asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Which agent session this request is about, as the session ID this host minted and the
    /// phone read off a descriptor. The Agents tab has no terminal lease, so nothing in
    /// `attached_sessions` can say where its conversation is working — this is the only thing
    /// that can, and it is an opaque token rather than a path for the same reason `base` is a
    /// token rather than a revision.
    ///
    /// When present it *decides*: a session that does not resolve is refused, never answered
    /// from the attached terminal's directory. Showing one workspace's diff under another
    /// workspace's heading is the single failure this screen exists to avoid.
    ///
    /// Absent from every request the terminal makes, so that path is the exact bytes it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// The one non-file `kind` this stream understands.
pub const GET_KIND_GIT_DIFF: &str = "git_diff";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetAccepted {
    pub v: u8,
    /// Basename only. The phone writes it into its own temporary directory, and the extension
    /// is what lets QuickLook pick a renderer.
    pub name: String,
    pub size: u64,
    /// For `git_diff`: every base this workspace can be measured against, in the order the
    /// reader should see them. The picker is drawn from this rather than from anything the app
    /// knows statically, so an option that would always be empty here never appears there.
    /// Empty — and absent from the wire — for a file preview.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bases: Vec<GetDiffBase>,
    /// Which of them produced this patch. The reader is always told what they are looking at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
}

/// One selectable base: the token to ask for it by, and the words to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetDiffBase {
    pub token: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GetError {
    pub v: u8,
    pub code: String,
    pub message: String,
}

/// Frames the app is allowed to send. Host-to-app frame types arriving from the app are a
/// direction violation, not merely unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownloadClientFrame {
    Open(GetOpen),
    Cancel,
}

fn download_frame_payload_limit(frame_type: u8) -> Result<usize, HostProtocolError> {
    match frame_type {
        FRAME_GET_OPEN | FRAME_GET_ACCEPTED | FRAME_GET_ERROR => Ok(MAX_DOWNLOAD_CONTROL_PAYLOAD),
        FRAME_GET_CHUNK => Ok(MAX_DOWNLOAD_CHUNK_PAYLOAD),
        FRAME_GET_DONE | FRAME_GET_CANCEL => Ok(0),
        _ => Err(HostProtocolError::UnknownFrameType),
    }
}

pub fn encode_download_frame(frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, HostProtocolError> {
    if payload.len() > download_frame_payload_limit(frame_type)? {
        return Err(HostProtocolError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| HostProtocolError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(5 + payload.len());
    encoded.push(frame_type);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn encode_download_control<T: Serialize>(
    frame_type: u8,
    value: &T,
) -> Result<Vec<u8>, HostProtocolError> {
    let body = serde_json::to_vec(value).map_err(|_| HostProtocolError::MalformedJson)?;
    encode_download_frame(frame_type, &body)
}

pub fn decode_download_client_frame(
    frame_type: u8,
    payload: &[u8],
) -> Result<DownloadClientFrame, HostProtocolError> {
    match frame_type {
        FRAME_GET_OPEN => {
            let open: GetOpen =
                serde_json::from_slice(payload).map_err(|_| HostProtocolError::MalformedJson)?;
            Ok(DownloadClientFrame::Open(open))
        }
        FRAME_GET_CANCEL => {
            if !payload.is_empty() {
                return Err(HostProtocolError::InvalidControlValue);
            }
            Ok(DownloadClientFrame::Cancel)
        }
        FRAME_GET_ACCEPTED | FRAME_GET_CHUNK | FRAME_GET_DONE | FRAME_GET_ERROR => {
            Err(HostProtocolError::UnexpectedDirection)
        }
        _ => Err(HostProtocolError::UnknownFrameType),
    }
}

/// Frame reader that is safe to drop mid-read, modeled on `UploadFrameReader` for the same
/// reason: these reads sit under `tokio::time::timeout`, and a bare `read_exact` in that
/// position once lost already-consumed bytes over an LTE relay.
#[derive(Debug)]
pub struct DownloadFrameReader {
    buffered: Vec<u8>,
    chunk: Vec<u8>,
}

impl Default for DownloadFrameReader {
    fn default() -> Self {
        Self {
            buffered: Vec::new(),
            chunk: vec![0_u8; 16 * 1024],
        }
    }
}

impl DownloadFrameReader {
    /// Cancellation-safe: dropping the returned future never loses stream position.
    pub async fn next<R>(
        &mut self,
        reader: &mut R,
    ) -> Result<DownloadClientFrame, HostProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        loop {
            if let Some(frame) = self.take_frame()? {
                return Ok(frame);
            }
            let count = match reader.read(&mut self.chunk).await {
                Ok(0) => return Err(HostProtocolError::Truncated),
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(HostProtocolError::Truncated);
                }
                Err(error) => return Err(HostProtocolError::Io(error)),
            };
            self.buffered.extend_from_slice(&self.chunk[..count]);
        }
    }

    fn take_frame(&mut self) -> Result<Option<DownloadClientFrame>, HostProtocolError> {
        if self.buffered.len() < 5 {
            return Ok(None);
        }
        let frame_type = self.buffered[0];
        let length = u32::from_be_bytes(
            self.buffered[1..5]
                .try_into()
                .expect("four-byte download frame length"),
        ) as usize;
        if length > download_frame_payload_limit(frame_type)? {
            return Err(HostProtocolError::FrameTooLarge);
        }
        if self.buffered.len() < 5 + length {
            return Ok(None);
        }
        let frame = decode_download_client_frame(frame_type, &self.buffered[5..5 + length])?;
        self.buffered.drain(..5 + length);
        Ok(Some(frame))
    }
}

/// Turns what the user long-pressed into a file to stream, or one categorical refusal.
///
/// The whole delight of the feature lives here: the token on screen is rarely a clean absolute
/// path. It is `apps/ios/shot.png` under a shell, `~/Desktop/shot.png` in a prompt, or
/// `src/main.rs:42:5` in compiler output.
pub fn resolve_target(
    token: &str,
    cwd: Option<&str>,
    home: Option<&Path>,
) -> Result<PathBuf, DownloadFailure> {
    const INVALID: DownloadFailure = DownloadFailure::new(
        DownloadErrorCode::Invalid,
        "That selection is not a file path.",
    );
    const MISSING: DownloadFailure = DownloadFailure::new(
        DownloadErrorCode::NotAFile,
        "There is no file by that name here.",
    );
    const PROTECTED: DownloadFailure = DownloadFailure::new(
        DownloadErrorCode::Denied,
        "That folder is one macOS keeps private from Ciao.",
    );

    let token = token.trim();
    if token.is_empty() || token.len() > MAX_PATH_BYTES || token.contains('\0') {
        return Err(INVALID);
    }

    let expanded = if token == "~" || token.starts_with("~/") {
        let home = home.ok_or(INVALID)?;
        home.join(token.trim_start_matches('~').trim_start_matches('/'))
    } else if token.starts_with('/') {
        PathBuf::from(token)
    } else {
        // A relative token is meaningless without the terminal's own directory. `cwd` itself
        // must be absolute: a relative one would be canonicalized against the daemon's own
        // working directory, which is nowhere the user is looking.
        //
        // Deliberately unfenced. Every test written for it passed with the `filter` deleted —
        // the naive join fails for its own reasons — and a test that cannot go red is worse
        // than none. This is a nonsense guard, not a security one: an absolute path already
        // reaches anything this could.
        let base = cwd.filter(|value| value.starts_with('/')).ok_or(MISSING)?;
        Path::new(base).join(token)
    };

    // `src/main.rs:42:5` is what a compiler prints and what the user will long-press. Retrying
    // once without a numeric tail costs a stat and turns a dead end into the file they meant.
    // ponytail: numeric tails only. A file genuinely named `notes:42` loses to the file
    // `notes`, which is the right way round for a preview.
    match existing_file(&expanded) {
        Ok(file) => Ok(file),
        Err(first) => match strip_line_suffix(&expanded).as_deref().map(existing_file) {
            Some(Ok(file)) => Ok(file),
            // The first attempt's verdict is the honest one: the stripped retry failing tells
            // us nothing about the path the user actually pressed.
            _ if first.code == DownloadErrorCode::NotAFile && tcc_protected(&expanded, home) => {
                Err(PROTECTED)
            }
            _ => Err(first),
        },
    }
}

/// macOS reports a TCC refusal as absence, not as `PermissionDenied` — it hides existence
/// rather than admitting the block, so `existing_file`'s error-kind check can never catch it.
/// The daemon is a launchd agent with no grant, which makes exactly the folders screenshots
/// land in look permanently empty.
///
/// ponytail: a location test, not a permission test. It cannot tell a genuinely absent
/// `~/Desktop/nope.png` from a blocked one, which is why the message says "if it's really
/// there" rather than asserting. Both readings lead somewhere useful, and the alternative —
/// a probe that distinguishes them — is more code for a sentence nobody reads twice.
fn tcc_protected(path: &Path, home: Option<&Path>) -> bool {
    const GUARDED: [&str; 4] = [
        "Desktop",
        "Documents",
        "Downloads",
        "Library/Mobile Documents",
    ];
    if !cfg!(target_os = "macos") {
        return false;
    }
    let Some(home) = home else { return false };
    let Ok(relative) = path.strip_prefix(home) else {
        return false;
    };
    GUARDED
        .iter()
        .any(|folder| relative.starts_with(Path::new(folder)))
}

/// The canonical path when this resolves to a readable regular file, or the reason it does not.
///
/// Denial is reported separately from absence, against the usual instinct. On macOS the daemon
/// is a launchd agent with no TCC grant, so `~/Desktop`, `~/Documents`, and `~/Downloads` —
/// exactly where screenshots land — come back as permission errors. Calling that "there is no
/// file by that name" is false and leaves the user with nothing to do. Nothing is leaked by
/// admitting it either: this connection can already run `cat`, so it can distinguish these two
/// cases whenever it likes (Spec 015 §2). The anti-probe instinct is inherited from uploads,
/// where it belongs, and does not apply here.
fn existing_file(path: &Path) -> Result<PathBuf, DownloadFailure> {
    const MISSING: DownloadFailure = DownloadFailure::new(
        DownloadErrorCode::NotAFile,
        "There is no file by that name here.",
    );
    const DENIED: DownloadFailure = DownloadFailure::new(
        DownloadErrorCode::Denied,
        "This Mac will not let Ciao open that folder.",
    );

    fn classify(error: &io::Error) -> DownloadFailure {
        if error.kind() == io::ErrorKind::PermissionDenied {
            DENIED
        } else {
            MISSING
        }
    }

    let canonical = path.canonicalize().map_err(|error| classify(&error))?;
    let metadata = canonical.metadata().map_err(|error| classify(&error))?;
    if !metadata.is_file() {
        // Directories, devices, FIFOs, and sockets are all simply not a file; the phone learns
        // nothing more, because there is nothing more worth saying.
        return Err(MISSING);
    }
    Ok(canonical)
}

/// `…/main.rs:42:5` → `…/main.rs`. Returns `None` when there is no numeric tail to strip.
fn strip_line_suffix(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let mut trimmed = name;
    let mut stripped = false;
    while let Some((head, tail)) = trimmed.rsplit_once(':') {
        if head.is_empty() || tail.is_empty() || !tail.bytes().all(|byte| byte.is_ascii_digit()) {
            break;
        }
        trimmed = head;
        stripped = true;
    }
    stripped.then(|| path.with_file_name(trimmed))
}

async fn write_download_control<W, T>(
    send: &mut W,
    frame_type: u8,
    value: &T,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let encoded = encode_download_control(frame_type, value)?;
    send.write_all(&encoded)
        .await
        .map_err(HostProtocolError::Io)?;
    Ok(())
}

pub async fn send_get_error<W>(
    send: &mut W,
    code: DownloadErrorCode,
    message: &str,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
{
    // Categorical only, like the upload stream's refusal log: never a path, never a filename.
    tracing::warn!(code = code.wire(), "download stream refused");
    write_download_control(
        send,
        FRAME_GET_ERROR,
        &GetError {
            v: DOWNLOAD_JSON_VERSION,
            code: code.wire().into(),
            message: message.into(),
        },
    )
    .await
}

enum FrameOutcome {
    Frame(DownloadClientFrame),
    Timeout,
    /// A decodable-but-wrong frame: answered in-protocol with `get_error invalid`.
    Protocol,
    /// The peer is gone or the stream broke: nothing can be answered, the caller resets.
    Transport(HostProtocolError),
}

async fn next_frame<R>(
    reader: &mut DownloadFrameReader,
    recv: &mut R,
    idle_timeout: Duration,
) -> FrameOutcome
where
    R: AsyncRead + Unpin,
{
    match timeout(idle_timeout, reader.next(recv)).await {
        Err(_) => FrameOutcome::Timeout,
        Ok(Ok(frame)) => FrameOutcome::Frame(frame),
        Ok(Err(error)) => match error {
            HostProtocolError::Io(_) | HostProtocolError::Truncated => {
                FrameOutcome::Transport(error)
            }
            _ => FrameOutcome::Protocol,
        },
    }
}

/// The download state machine over one already-prefaced stream: open → resolve → accepted →
/// chunks → done, with every failure answered by exactly one `get_error`. Generic over the
/// stream halves so the whole exchange runs under tests on an in-memory duplex.
///
/// `session_cwd` is where the attached multiplexer session is standing, used only when the app
/// sent no `cwd` of its own. The app's report wins when present because it comes from the VT
/// the user is actually looking at; this is the floor beneath it, not a replacement.
///
/// `agent_workspace` answers where one registered agent session is working. It is consulted
/// only when the open frame names a session, and it is a closure rather than a resolved value
/// because the name arrives in that frame — there is nothing to look up before it is read. Both
/// lookups behind it are in-memory, so this stays synchronous.
pub async fn run_download_stream<R, W>(
    recv: &mut R,
    send: &mut W,
    home: Option<&Path>,
    session_cwd: Option<&str>,
    agent_workspace: &(dyn Fn(&str) -> Option<String> + Sync),
    idle_timeout: Duration,
) -> Result<(), HostProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = DownloadFrameReader::default();
    let open = match next_frame(&mut reader, recv, idle_timeout).await {
        FrameOutcome::Frame(DownloadClientFrame::Open(open)) => open,
        FrameOutcome::Frame(DownloadClientFrame::Cancel) => {
            return send_get_error(
                send,
                DownloadErrorCode::Cancelled,
                "The preview was cancelled.",
            )
            .await;
        }
        FrameOutcome::Timeout => {
            return send_get_error(send, DownloadErrorCode::Timeout, "The preview timed out.")
                .await;
        }
        FrameOutcome::Protocol => {
            return send_get_error(
                send,
                DownloadErrorCode::Invalid,
                "The preview request was malformed.",
            )
            .await;
        }
        FrameOutcome::Transport(error) => return Err(error),
    };
    if open.v != DOWNLOAD_JSON_VERSION {
        return send_get_error(
            send,
            DownloadErrorCode::Invalid,
            "This preview protocol version is not supported.",
        )
        .await;
    }

    // A named session outranks both the VT's report and the attached terminal, and a named
    // session that does not resolve ends the request. Falling back here would answer with
    // whatever directory happened to be nearby, which is the wrong-workspace failure rather
    // than a degraded one.
    let resolved_session = match open.session.as_deref() {
        Some(session) => match agent_workspace(session) {
            Some(path) => Some(path),
            None => {
                // The same code as "no directory at all", because to the reader it is the same
                // answer: there is nowhere to look. `not_a_file` would claim this folder is not
                // a repository, which is a statement about a directory nobody found.
                return send_get_error(
                    send,
                    DownloadErrorCode::Invalid,
                    "There's no directory to diff here.",
                )
                .await;
            }
        },
        None => None,
    };
    let cwd = resolved_session
        .as_deref()
        .or(open.cwd.as_deref())
        .or(session_cwd);

    if open.kind.as_deref() == Some(GET_KIND_GIT_DIFF) {
        return send_git_diff(send, cwd, open.base.as_deref()).await;
    }

    let path = match resolve_target(&open.path, cwd, home) {
        Ok(path) => path,
        Err(failure) => return send_get_error(send, failure.code, failure.message).await,
    };

    let mut file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(_) => {
            return send_get_error(
                send,
                DownloadErrorCode::NotAFile,
                "There is no file by that name here.",
            )
            .await;
        }
    };
    let size = match file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(_) => {
            return send_get_error(send, DownloadErrorCode::Io, "That file could not be read.")
                .await;
        }
    };
    if size > MAX_DOWNLOAD_BYTES {
        return send_get_error(
            send,
            DownloadErrorCode::TooLarge,
            "That file is too large to preview.",
        )
        .await;
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("file")
        .to_owned();

    write_download_control(
        send,
        FRAME_GET_ACCEPTED,
        &GetAccepted {
            v: DOWNLOAD_JSON_VERSION,
            name,
            size,
            // A file preview has no bases to choose between; both fields stay off the wire.
            bases: Vec::new(),
            base: None,
        },
    )
    .await?;

    // The declared size is the contract: a file being rewritten underneath us must not turn
    // into a stream the phone cannot end. Short reads end it early; extra bytes are dropped.
    let mut buffer = vec![0_u8; MAX_DOWNLOAD_CHUNK_PAYLOAD];
    let mut sent = 0_u64;
    while sent < size {
        let want = usize::try_from((size - sent).min(MAX_DOWNLOAD_CHUNK_PAYLOAD as u64))
            .unwrap_or(MAX_DOWNLOAD_CHUNK_PAYLOAD);
        let count = match file.read(&mut buffer[..want]).await {
            Ok(0) => break,
            Ok(count) => count,
            Err(_) => {
                return send_get_error(send, DownloadErrorCode::Io, "That file could not be read.")
                    .await;
            }
        };
        let encoded = encode_download_frame(FRAME_GET_CHUNK, &buffer[..count])?;
        send.write_all(&encoded)
            .await
            .map_err(HostProtocolError::Io)?;
        sent += count as u64;
    }

    let done = encode_download_frame(FRAME_GET_DONE, &[])?;
    send.write_all(&done).await.map_err(HostProtocolError::Io)?;
    Ok(())
}

/// The workspace's diff for one chosen base, as one `changes.diff` the phone renders.
///
/// The extension matters: it is what the app's renderer keys on, the same way `get_accepted`'s
/// name drives QuickLook for a file preview.
async fn send_git_diff<W>(
    send: &mut W,
    cwd: Option<&str>,
    base: Option<&str>,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
{
    let Some(cwd) = cwd else {
        // No directory to ask about: the shell reported none and the multiplexer had no answer.
        return send_get_error(
            send,
            DownloadErrorCode::Invalid,
            "There's no directory to diff here.",
        )
        .await;
    };

    // An absent base is the pre-picker request and means uncommitted. A base this host does not
    // know is refused rather than silently answered with a different one — the reader would be
    // shown changes they did not ask for under a label saying they did.
    let selected = match base {
        None => crate::git_diff::DiffBase::Uncommitted,
        Some(token) => match crate::git_diff::DiffBase::from_wire(token) {
            Some(base) => base,
            None => {
                return send_get_error(
                    send,
                    DownloadErrorCode::Invalid,
                    "That comparison isn't available on this host.",
                )
                .await;
            }
        },
    };

    let patch = match crate::git_diff::diff(Path::new(cwd), selected).await {
        Ok(patch) => patch,
        Err(error) => {
            let (code, message) = match error {
                crate::git_diff::GitDiffError::NotARepository => (
                    DownloadErrorCode::NotAFile,
                    "That folder isn't a Git repository.",
                ),
                crate::git_diff::GitDiffError::GitUnavailable => (
                    DownloadErrorCode::Denied,
                    "Git isn't available on this host.",
                ),
                crate::git_diff::GitDiffError::TooLarge => (
                    DownloadErrorCode::TooLarge,
                    "That diff is too large to review here.",
                ),
                crate::git_diff::GitDiffError::Timeout => {
                    (DownloadErrorCode::Timeout, "Git didn't answer in time.")
                }
                crate::git_diff::GitDiffError::Failed => {
                    (DownloadErrorCode::Io, "That diff couldn't be produced.")
                }
            };
            return send_get_error(send, code, message).await;
        }
    };

    // Enumerated after the patch is in hand, so the picker describes the same repository state
    // the reader is about to look at rather than one from before a slow diff.
    let bases = crate::git_diff::available_bases(Path::new(cwd))
        .await
        .into_iter()
        .map(|option| GetDiffBase {
            token: option.base.wire().to_owned(),
            label: option.label,
        })
        .collect();

    let bytes = patch.as_bytes();
    write_download_control(
        send,
        FRAME_GET_ACCEPTED,
        &GetAccepted {
            v: DOWNLOAD_JSON_VERSION,
            name: "changes.diff".to_owned(),
            size: bytes.len() as u64,
            bases,
            base: Some(selected.wire().to_owned()),
        },
    )
    .await?;

    for chunk in bytes.chunks(MAX_DOWNLOAD_CHUNK_PAYLOAD) {
        let encoded = encode_download_frame(FRAME_GET_CHUNK, chunk)?;
        send.write_all(&encoded)
            .await
            .map_err(HostProtocolError::Io)?;
    }
    let done = encode_download_frame(FRAME_GET_DONE, &[])?;
    send.write_all(&done).await.map_err(HostProtocolError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    fn write_file(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(bytes).expect("write");
        path
    }

    #[test]
    fn relative_token_resolves_against_the_terminal_cwd() {
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        write_file(&root, "apps/shot.png", b"png");

        let resolved = resolve_target("apps/shot.png", Some(root.to_str().unwrap()), None)
            .expect("resolves against cwd");
        assert_eq!(resolved, root.join("apps/shot.png"));
    }

    #[test]
    fn relative_token_without_cwd_is_refused() {
        let temp = temp_dir();
        write_file(temp.path(), "shot.png", b"png");

        let failure = resolve_target("shot.png", None, None).expect_err("no cwd, no resolution");
        assert_eq!(failure.code, DownloadErrorCode::NotAFile);
    }

    #[test]
    fn line_and_column_suffix_is_stripped() {
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        write_file(&root, "main.rs", b"fn main() {}");

        let cwd = root.to_str().unwrap();
        assert_eq!(
            resolve_target("main.rs:42:5", Some(cwd), None).expect("strips :line:col"),
            root.join("main.rs")
        );
        assert_eq!(
            resolve_target("main.rs:42", Some(cwd), None).expect("strips :line"),
            root.join("main.rs")
        );
    }

    #[test]
    fn tilde_expands_against_home() {
        let temp = temp_dir();
        let home = temp.path().canonicalize().expect("canonical home");
        write_file(&home, "Desktop/shot.png", b"png");

        let resolved =
            resolve_target("~/Desktop/shot.png", None, Some(&home)).expect("expands tilde");
        assert_eq!(resolved, home.join("Desktop/shot.png"));
    }

    /// The macOS TCC case in miniature: the file is there, the daemon may not look at it.
    /// Saying "there is no file by that name" would send the user hunting for a file that
    /// exists (Spec 015 §4).
    #[test]
    #[cfg(unix)]
    fn an_unreadable_folder_says_denied_not_missing() {
        use std::os::unix::fs::PermissionsExt;

        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        write_file(&root, "locked/shot.png", b"png");
        let locked = root.join("locked");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("lock the directory");

        let failure = resolve_target(locked.join("shot.png").to_str().unwrap(), None, None)
            .expect_err("an unreadable directory refuses");

        // Restore before the assert so a failure still cleans up after itself.
        let _ = std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755));
        assert_eq!(failure.code, DownloadErrorCode::Denied);
    }

    /// The owner's 2026-08-13 phone run: `~/Desktop/…` exists and is readable by an ordinary
    /// process, and the daemon is told it is simply absent. Reporting that as "no file by that
    /// name" sent the owner looking for a file that was sitting right there.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_macos_protected_folder_is_named_rather_than_called_empty() {
        let temp = temp_dir();
        let home = temp.path().canonicalize().expect("canonical home");

        let failure = resolve_target("~/Desktop/shot.png", None, Some(&home))
            .expect_err("an absent file under a guarded folder");
        assert_eq!(failure.code, DownloadErrorCode::Denied);

        // Anywhere else keeps the plain answer: this must not become the catch-all.
        let elsewhere = resolve_target("~/Developer/shot.png", None, Some(&home))
            .expect_err("an absent file outside the guarded folders");
        assert_eq!(elsewhere.code, DownloadErrorCode::NotAFile);
    }

    #[test]
    fn a_directory_is_not_a_file() {
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        std::fs::create_dir(root.join("apps")).expect("dir");

        let failure = resolve_target("apps", Some(root.to_str().unwrap()), None)
            .expect_err("directories refuse");
        assert_eq!(failure.code, DownloadErrorCode::NotAFile);
    }

    /// An absent file says so plainly, and its message never echoes the name back.
    #[test]
    fn an_absent_file_says_missing_without_naming_it() {
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");

        let failure = resolve_target("nope.png", Some(root.to_str().unwrap()), None)
            .expect_err("absent refuses");
        assert_eq!(failure.code, DownloadErrorCode::NotAFile);
        assert!(!failure.message.contains("nope"));
    }

    #[tokio::test]
    async fn a_preview_streams_open_accepted_chunks_done() {
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        // Two chunks plus a remainder, so reassembly is actually exercised.
        let bytes: Vec<u8> = (0..(MAX_DOWNLOAD_CHUNK_PAYLOAD * 2 + 17))
            .map(|index| (index % 251) as u8)
            .collect();
        write_file(&root, "shot.png", &bytes);

        let open = encode_download_control(
            FRAME_GET_OPEN,
            &GetOpen {
                v: DOWNLOAD_JSON_VERSION,
                path: "shot.png".into(),
                cwd: Some(root.to_str().unwrap().into()),
                kind: None,
                base: None,
                session: None,
            },
        )
        .expect("encode open");

        let mut recv = io::Cursor::new(open);
        let mut sent: Vec<u8> = Vec::new();
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            None,
            &no_agent_workspace,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        let (accepted, body) = decode_host_frames(&sent);
        assert_eq!(accepted.name, "shot.png");
        assert_eq!(accepted.size, bytes.len() as u64);
        assert_eq!(body, bytes);
    }

    #[tokio::test]
    async fn an_over_cap_file_is_refused_before_any_chunk() {
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        let path = write_file(&root, "big.bin", b"");
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open");
        file.set_len(MAX_DOWNLOAD_BYTES + 1).expect("grow");

        let open = encode_download_control(
            FRAME_GET_OPEN,
            &GetOpen {
                v: DOWNLOAD_JSON_VERSION,
                path: "big.bin".into(),
                cwd: Some(root.to_str().unwrap().into()),
                kind: None,
                base: None,
                session: None,
            },
        )
        .expect("encode open");

        let mut recv = io::Cursor::new(open);
        let mut sent: Vec<u8> = Vec::new();
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            None,
            &no_agent_workspace,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        assert_eq!(sent[0], FRAME_GET_ERROR);
        let error: GetError = serde_json::from_slice(&sent[5..]).expect("error frame");
        assert_eq!(error.code, "too_large");
    }

    #[test]
    fn host_frames_are_a_direction_violation_from_the_app() {
        assert!(matches!(
            decode_download_client_frame(FRAME_GET_ACCEPTED, b"{}"),
            Err(HostProtocolError::UnexpectedDirection)
        ));
        assert!(matches!(
            decode_download_client_frame(FRAME_GET_CHUNK, b"x"),
            Err(HostProtocolError::UnexpectedDirection)
        ));
    }

    /// Splits a recorded host-to-app byte stream into its accepted frame and reassembled body.
    /// Every host frame, including refusals — `decode_host_frames` panics on `get_error`
    /// because a preview test that reaches one has already failed.
    fn decode_error(bytes: &[u8]) -> Option<GetError> {
        let mut cursor = 0;
        while cursor + 5 <= bytes.len() {
            let frame_type = bytes[cursor];
            let length =
                u32::from_be_bytes(bytes[cursor + 1..cursor + 5].try_into().unwrap()) as usize;
            let payload = &bytes[cursor + 5..cursor + 5 + length];
            if frame_type == FRAME_GET_ERROR {
                return Some(serde_json::from_slice(payload).expect("error frame"));
            }
            cursor += 5 + length;
        }
        None
    }

    /// Nothing registered, which is also what every terminal-originated request means.
    fn no_agent_workspace(_session_id: &str) -> Option<String> {
        None
    }

    fn open_git_diff(cwd: Option<&str>) -> Vec<u8> {
        open_git_diff_base(cwd, None)
    }

    fn open_git_diff_base(cwd: Option<&str>, base: Option<&str>) -> Vec<u8> {
        open_git_diff_full(cwd, base, None)
    }

    fn open_git_diff_full(cwd: Option<&str>, base: Option<&str>, session: Option<&str>) -> Vec<u8> {
        encode_download_control(
            FRAME_GET_OPEN,
            &GetOpen {
                v: DOWNLOAD_JSON_VERSION,
                // The app sends a placeholder: `kind` decides, and this field names no file.
                path: ".".into(),
                cwd: cwd.map(str::to_owned),
                kind: Some(GET_KIND_GIT_DIFF.into()),
                base: base.map(str::to_owned),
                session: session.map(str::to_owned),
            },
        )
        .expect("encode open")
    }

    #[tokio::test]
    async fn a_git_diff_request_streams_the_worktree_patch_over_the_same_stream() {
        let Some(git) = crate::git_diff::resolve_git() else {
            return;
        };
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        let run = |args: Vec<&'static str>| {
            let mut command = std::process::Command::new(&git);
            command.arg("-C").arg(&root).args(args);
            command.output().expect("git");
        };
        run(vec!["init", "-q"]);
        run(vec!["config", "user.email", "spike@example.invalid"]);
        run(vec!["config", "user.name", "Spike"]);
        write_file(&root, "app.rs", b"fn main() {}\n");
        run(vec!["add", "app.rs"]);
        run(vec!["commit", "-q", "-m", "first"]);
        write_file(&root, "app.rs", b"fn main() {\n    println!(\"hi\");\n}\n");

        let mut recv = io::Cursor::new(open_git_diff(Some(root.to_str().unwrap())));
        let mut sent: Vec<u8> = Vec::new();
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            None,
            &no_agent_workspace,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        let (accepted, body) = decode_host_frames(&sent);
        // The extension is the contract with the app's renderer, exactly as it is with
        // QuickLook for a file preview.
        assert_eq!(accepted.name, "changes.diff");
        let patch = String::from_utf8(body).expect("utf-8 patch");
        assert_eq!(accepted.size as usize, patch.len());
        assert!(patch.contains("diff --git"), "a real patch: {patch}");
        assert!(patch.contains("+    println!"), "the edit: {patch}");
        // The answer says which base produced it and what else could be picked, so the screen
        // never has to guess at a label for what it is showing.
        assert_eq!(accepted.base.as_deref(), Some("uncommitted"));
        assert!(
            accepted
                .bases
                .iter()
                .any(|option| option.token == "uncommitted"),
            "the picker is drawn from this: {:?}",
            accepted.bases
        );
    }

    #[tokio::test]
    async fn a_git_diff_request_with_an_unknown_base_is_refused_rather_than_answered() {
        if crate::git_diff::resolve_git().is_none() {
            return;
        }
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");

        // The refusal has to come before the diff: answering a token this host does not know
        // with the uncommitted patch would put changes on screen under the wrong heading, and
        // the reader has no way to tell.
        let mut recv = io::Cursor::new(open_git_diff_base(
            Some(root.to_str().unwrap()),
            Some("HEAD~1"),
        ));
        let mut sent: Vec<u8> = Vec::new();
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            None,
            &no_agent_workspace,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        let error = decode_error(&sent).expect("a refusal");
        assert_eq!(error.code, DownloadErrorCode::Invalid.wire());
        assert!(
            !error.message.contains(root.to_str().unwrap()),
            "a refusal never names the path: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn a_git_diff_request_outside_a_repository_is_refused_without_naming_the_path() {
        if crate::git_diff::resolve_git().is_none() {
            return;
        }
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");

        let mut recv = io::Cursor::new(open_git_diff(Some(root.to_str().unwrap())));
        let mut sent: Vec<u8> = Vec::new();
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            None,
            &no_agent_workspace,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        let error = decode_error(&sent).expect("a refusal");
        assert_eq!(error.code, DownloadErrorCode::NotAFile.wire());
        // The refusal must not become a filesystem probe: no path, no git stderr.
        assert!(
            !error.message.contains(root.to_str().unwrap()),
            "message leaks the path: {}",
            error.message
        );
    }

    #[tokio::test]
    async fn a_git_diff_request_with_no_directory_at_all_is_refused() {
        let mut recv = io::Cursor::new(open_git_diff(None));
        let mut sent: Vec<u8> = Vec::new();
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            None,
            &no_agent_workspace,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        let error = decode_error(&sent).expect("a refusal");
        assert_eq!(error.code, DownloadErrorCode::Invalid.wire());
    }

    #[tokio::test]
    async fn a_named_session_is_diffed_where_that_session_works_not_where_the_terminal_is() {
        let Some(git) = crate::git_diff::resolve_git() else {
            return;
        };
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");
        let workspace = root.join("agent");
        let elsewhere = root.join("terminal");
        std::fs::create_dir_all(&workspace).expect("workspace");
        std::fs::create_dir_all(&elsewhere).expect("elsewhere");
        for dir in [&workspace, &elsewhere] {
            let run = |args: Vec<&str>| {
                let mut command = std::process::Command::new(&git);
                command.arg("-C").arg(dir).args(args);
                command.output().expect("git");
            };
            run(vec!["init", "--quiet"]);
            run(vec!["config", "user.email", "spike@example.invalid"]);
            run(vec!["config", "user.name", "Spike"]);
        }
        write_file(&workspace, "only-here.txt", b"agent work\n");
        write_file(&elsewhere, "not-this.txt", b"terminal work\n");

        // Both directories are repositories with untracked work, so a patch alone proves
        // nothing — only *which* filename comes back separates the two candidates.
        let mut recv = io::Cursor::new(open_git_diff_full(None, None, Some("sess-1")));
        let mut sent: Vec<u8> = Vec::new();
        let resolve = |session_id: &str| {
            (session_id == "sess-1").then(|| workspace.to_string_lossy().into_owned())
        };
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            // The device is attached to a terminal standing somewhere else entirely.
            Some(elsewhere.to_str().unwrap()),
            &resolve,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        let (accepted, body) = decode_host_frames(&sent);
        assert_eq!(accepted.name, "changes.diff");
        let patch = String::from_utf8(body).expect("utf-8 patch");
        assert!(patch.contains("only-here.txt"), "wrong workspace: {patch}");
        assert!(
            !patch.contains("not-this.txt"),
            "leaked the terminal's workspace: {patch}"
        );
    }

    #[tokio::test]
    async fn a_session_that_does_not_resolve_is_refused_rather_than_read_as_the_terminal() {
        let temp = temp_dir();
        let root = temp.path().canonicalize().expect("canonical root");

        // The terminal fallback is present and would answer. It must not: a session the host
        // cannot place is the wrong-workspace case, and the only safe answer is none.
        let mut recv = io::Cursor::new(open_git_diff_full(None, None, Some("gone")));
        let mut sent: Vec<u8> = Vec::new();
        run_download_stream(
            &mut recv,
            &mut sent,
            None,
            Some(root.to_str().unwrap()),
            &no_agent_workspace,
            DOWNLOAD_IDLE_TIMEOUT,
        )
        .await
        .expect("stream runs");

        let error = decode_error(&sent).expect("a refusal");
        assert_eq!(error.code, DownloadErrorCode::Invalid.wire());
        assert!(
            !error.message.contains(root.to_str().unwrap()),
            "a refusal never names the path: {}",
            error.message
        );
    }

    fn decode_host_frames(bytes: &[u8]) -> (GetAccepted, Vec<u8>) {
        let mut cursor = 0;
        let mut accepted = None;
        let mut body = Vec::new();
        while cursor + 5 <= bytes.len() {
            let frame_type = bytes[cursor];
            let length =
                u32::from_be_bytes(bytes[cursor + 1..cursor + 5].try_into().unwrap()) as usize;
            let payload = &bytes[cursor + 5..cursor + 5 + length];
            match frame_type {
                FRAME_GET_ACCEPTED => {
                    accepted = Some(serde_json::from_slice(payload).expect("accepted"));
                }
                FRAME_GET_CHUNK => body.extend_from_slice(payload),
                FRAME_GET_DONE => {}
                other => panic!("unexpected host frame {other:#x}"),
            }
            cursor += 5 + length;
        }
        (accepted.expect("an accepted frame"), body)
    }
}
