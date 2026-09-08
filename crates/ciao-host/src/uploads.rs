//! Spec 007 composer attachments, host side: the `file.put.v1` upload stream.
//!
//! One QUIC stream carries exactly one upload. After the shared two-byte preface
//! (`STREAM_KIND_UPLOAD`), frames are `1 type byte + 4-byte big-endian payload length +
//! payload`. The phone supplies only bounded metadata — a suggested filename (untrusted), a
//! coarse source kind, the final byte count, and the SHA-256 of the bytes it sends. The host
//! owns every destination component: it sanitizes the basename, generates the random file
//! names, resolves its own `uploads/` root under the Ciao state directory, verifies size and
//! hash, publishes atomically, and returns the completed absolute path plus a host-generated
//! POSIX single-quoted `prompt_reference`. No remotely supplied value is ever passed to a
//! shell (Spec 007 §3.1–§3.3).
//!
//! Cleanup is host-owned (Spec 007 §3.6): partial files older than 15 minutes and completed
//! files older than 24 hours are deleted, and a 256 MiB global quota evicts the oldest
//! completed uploads first. The sweeper runs at daemon startup and periodically; terminal
//! close never shortens a lifetime.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

use crate::{host_protocol::HostProtocolError, storage::ensure_private_directory};

/// Version tag inside every JSON control payload; independent of the stream preface version.
pub const UPLOAD_JSON_VERSION: u8 = 1;

pub const FRAME_PUT_OPEN: u8 = 0x01;
pub const FRAME_PUT_ACCEPTED: u8 = 0x02;
pub const FRAME_PUT_CHUNK: u8 = 0x03;
pub const FRAME_PUT_FINISH: u8 = 0x04;
pub const FRAME_PUT_DONE: u8 = 0x05;
pub const FRAME_PUT_ERROR: u8 = 0x06;
pub const FRAME_PUT_CANCEL: u8 = 0x07;

/// JSON control frames are bounded independently of chunk frames; either cap overrunning is a
/// protocol error that fails the stream closed.
pub const MAX_UPLOAD_CONTROL_PAYLOAD: usize = 4096;
pub const MAX_UPLOAD_CHUNK_PAYLOAD: usize = 16 * 1024;
/// Hard protocol limit on the declared and actual file size (Spec 007 §3.5), rejected at
/// `put_open` before any content is accepted and again if actual bytes overrun it.
pub const MAX_UPLOAD_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// A transfer that makes no progress for this long is failed with `timeout` and its partial
/// file removed; the phone retries from byte zero (Spec 007 §4).
pub const UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const UPLOAD_PARTIAL_TTL: Duration = Duration::from_secs(15 * 60);
pub const UPLOAD_COMPLETED_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub const UPLOAD_QUOTA_BYTES: u64 = 256 * 1024 * 1024;
pub const UPLOAD_SWEEP_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Longest sanitized basename the store keeps; a reasonable extension survives truncation.
const MAX_SANITIZED_FILENAME: usize = 64;
/// An extension is "reasonable" (worth preserving through truncation) when it is short and
/// purely alphanumeric — `.png`, `.tar`, not a 60-character tail that happens to follow a dot.
const MAX_PRESERVED_EXTENSION: usize = 16;

/// Categorical error codes of the `put_error` frame — the closed wire vocabulary both sides
/// implement; nothing else may appear in `code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadErrorCode {
    Busy,
    TooLarge,
    Invalid,
    HashMismatch,
    Io,
    Quota,
    Timeout,
    Cancelled,
}

impl UploadErrorCode {
    pub const fn wire(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::TooLarge => "too_large",
            Self::Invalid => "invalid",
            Self::HashMismatch => "hash_mismatch",
            Self::Io => "io",
            Self::Quota => "quota",
            Self::Timeout => "timeout",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A store/transfer failure that maps directly onto one `put_error` frame. Messages are fixed
/// short strings on purpose: no filename, path, or hash ever rides in one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UploadFailure {
    pub code: UploadErrorCode,
    pub message: &'static str,
}

impl UploadFailure {
    const fn new(code: UploadErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutOpen {
    pub v: u8,
    pub request_id: String,
    /// Suggested display name from the phone. Untrusted: it is sanitized to a safe ASCII
    /// basename and never used as a path component as-is.
    pub filename: String,
    pub source_kind: String,
    pub size: u64,
    pub sha256: String,
}

impl PutOpen {
    pub fn validate(&self) -> Result<(), UploadFailure> {
        if self.v != UPLOAD_JSON_VERSION {
            return Err(UploadFailure::new(
                UploadErrorCode::Invalid,
                "This upload protocol version is not supported.",
            ));
        }
        if !valid_upload_request_id(&self.request_id) {
            return Err(UploadFailure::new(
                UploadErrorCode::Invalid,
                "The upload request ID must be a UUID.",
            ));
        }
        if !matches!(self.source_kind.as_str(), "photo" | "file") {
            return Err(UploadFailure::new(
                UploadErrorCode::Invalid,
                "The upload source kind is not supported.",
            ));
        }
        if !valid_sha256_hex(&self.sha256) {
            return Err(UploadFailure::new(
                UploadErrorCode::Invalid,
                "The declared SHA-256 must be 64 lowercase hex characters.",
            ));
        }
        if self.size == 0 {
            return Err(UploadFailure::new(
                UploadErrorCode::Invalid,
                "An empty upload is not valid.",
            ));
        }
        if self.size > MAX_UPLOAD_FILE_BYTES {
            return Err(UploadFailure::new(
                UploadErrorCode::TooLarge,
                "The file exceeds the 8 MiB upload limit.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutAccepted {
    pub v: u8,
    pub transfer_id: String,
    pub chunk_bytes: u32,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutDone {
    pub v: u8,
    pub host_path: String,
    pub prompt_reference: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PutError {
    pub v: u8,
    pub code: String,
    pub message: String,
}

/// Frames the app is allowed to send. Host-to-app frame types arriving from the app are a
/// direction violation, not merely unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadClientFrame {
    Open(PutOpen),
    Chunk(Vec<u8>),
    Finish,
    Cancel,
}

/// Payload cap per frame type. Unknown types fail here, before any payload is buffered, so an
/// unrecognized frame can never smuggle bytes past the caps.
fn upload_frame_payload_limit(frame_type: u8) -> Result<usize, HostProtocolError> {
    match frame_type {
        FRAME_PUT_OPEN | FRAME_PUT_ACCEPTED | FRAME_PUT_DONE | FRAME_PUT_ERROR => {
            Ok(MAX_UPLOAD_CONTROL_PAYLOAD)
        }
        FRAME_PUT_CHUNK => Ok(MAX_UPLOAD_CHUNK_PAYLOAD),
        FRAME_PUT_FINISH | FRAME_PUT_CANCEL => Ok(0),
        _ => Err(HostProtocolError::UnknownFrameType),
    }
}

pub fn encode_upload_frame(frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, HostProtocolError> {
    if payload.len() > upload_frame_payload_limit(frame_type)? {
        return Err(HostProtocolError::FrameTooLarge);
    }
    let length = u32::try_from(payload.len()).map_err(|_| HostProtocolError::FrameTooLarge)?;
    let mut encoded = Vec::with_capacity(5 + payload.len());
    encoded.push(frame_type);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub fn encode_upload_control<T: Serialize>(
    frame_type: u8,
    value: &T,
) -> Result<Vec<u8>, HostProtocolError> {
    let body = serde_json::to_vec(value).map_err(|_| HostProtocolError::MalformedJson)?;
    encode_upload_frame(frame_type, &body)
}

pub fn decode_upload_client_frame(
    frame_type: u8,
    payload: &[u8],
) -> Result<UploadClientFrame, HostProtocolError> {
    match frame_type {
        FRAME_PUT_OPEN => {
            let open: PutOpen =
                serde_json::from_slice(payload).map_err(|_| HostProtocolError::MalformedJson)?;
            Ok(UploadClientFrame::Open(open))
        }
        FRAME_PUT_CHUNK => {
            if payload.is_empty() {
                return Err(HostProtocolError::ZeroLength);
            }
            Ok(UploadClientFrame::Chunk(payload.to_vec()))
        }
        FRAME_PUT_FINISH => {
            if !payload.is_empty() {
                return Err(HostProtocolError::InvalidControlValue);
            }
            Ok(UploadClientFrame::Finish)
        }
        FRAME_PUT_CANCEL => {
            if !payload.is_empty() {
                return Err(HostProtocolError::InvalidControlValue);
            }
            Ok(UploadClientFrame::Cancel)
        }
        FRAME_PUT_ACCEPTED | FRAME_PUT_DONE | FRAME_PUT_ERROR => {
            Err(HostProtocolError::UnexpectedDirection)
        }
        _ => Err(HostProtocolError::UnknownFrameType),
    }
}

/// Frame reader that is safe to drop mid-read, modeled on `AgentFrameReader`. The handler's
/// reads sit under `tokio::time::timeout`, which drops the read future when the deadline wins
/// — the same cancellation a `tokio::select!` branch performs, and the exact spot where a bare
/// `read_exact` once lost already-consumed bytes over an LTE relay and desynced the terminal
/// stream. Bytes here are consumed only by single completed `read` calls — cancellation-safe
/// by tokio's contract — and buffered in state that outlives the future.
#[derive(Debug)]
pub struct UploadFrameReader {
    buffered: Vec<u8>,
    chunk: Vec<u8>,
}

impl Default for UploadFrameReader {
    fn default() -> Self {
        Self {
            buffered: Vec::new(),
            chunk: vec![0_u8; 16 * 1024],
        }
    }
}

impl UploadFrameReader {
    /// Cancellation-safe: dropping the returned future never loses stream position.
    pub async fn next<R>(&mut self, reader: &mut R) -> Result<UploadClientFrame, HostProtocolError>
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

    fn take_frame(&mut self) -> Result<Option<UploadClientFrame>, HostProtocolError> {
        if self.buffered.len() < 5 {
            return Ok(None);
        }
        let frame_type = self.buffered[0];
        let length = u32::from_be_bytes(
            self.buffered[1..5]
                .try_into()
                .expect("four-byte upload frame length"),
        ) as usize;
        // The cap check runs on the header alone: an over-cap or unknown frame fails before its
        // payload is awaited, which also bounds this buffer at one frame plus one read chunk.
        if length > upload_frame_payload_limit(frame_type)? {
            return Err(HostProtocolError::FrameTooLarge);
        }
        if self.buffered.len() < 5 + length {
            return Ok(None);
        }
        let frame = decode_upload_client_frame(frame_type, &self.buffered[5..5 + length])?;
        self.buffered.drain(..5 + length);
        Ok(Some(frame))
    }
}

/// `request_id` must be a UUID string (8-4-4-4-12 hex groups, either case — Swift's
/// `UUID().uuidString` is uppercase).
fn valid_upload_request_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Reduces the phone's suggested filename to a safe ASCII basename (Spec 007 §3.2): only
/// `[A-Za-z0-9._-]` survive, every run of anything else collapses to one `_`, leading dots are
/// stripped (no hidden files, no `..`), and the result is capped at 64 characters while
/// preserving a reasonable extension. An empty result becomes `upload`. The sanitized name is
/// never used alone: the store prefixes it with a random hex token, so the final filename
/// never begins with `-` or collides by user choice.
pub fn sanitize_filename(name: &str) -> String {
    let mut reduced = String::new();
    let mut replacement_pending = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            reduced.push(ch);
            replacement_pending = false;
        } else if !replacement_pending {
            reduced.push('_');
            replacement_pending = true;
        }
    }
    let mut result = reduced.trim_start_matches('.').to_string();
    if result.is_empty() {
        return "upload".into();
    }
    if result.len() > MAX_SANITIZED_FILENAME {
        let preserved = result
            .rsplit_once('.')
            .map(|(_, extension)| extension)
            .filter(|extension| {
                !extension.is_empty()
                    && extension.len() <= MAX_PRESERVED_EXTENSION
                    && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
            })
            .map(str::to_owned);
        match preserved {
            Some(extension) => {
                // Everything is ASCII by construction, so byte truncation is char-safe.
                result.truncate(MAX_SANITIZED_FILENAME - extension.len() - 1);
                result.push('.');
                result.push_str(&extension);
            }
            None => result.truncate(MAX_SANITIZED_FILENAME),
        }
    }
    result
}

/// POSIX single-quote escaping, generated host-side only (Spec 007 §3.1): the whole path is
/// wrapped in `'…'` and each internal `'` becomes `'\''`, so spaces or shell metacharacters in
/// an ancestor directory can never become terminal input syntax. The phone inserts this string
/// verbatim and never constructs its own quoting.
pub fn posix_single_quote(text: &str) -> String {
    let mut quoted = String::with_capacity(text.len() + 2);
    quoted.push('\'');
    for ch in text.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

/// RFC 3339 UTC (`YYYY-MM-DDTHH:MM:SSZ`) without a date-time dependency; the civil-date
/// conversion is Howard Hinnant's `civil_from_days` algorithm.
pub fn format_rfc3339_utc(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = (z - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// One live upload per connection (Spec 007 §3.5). The daemon holds one gate per host
/// connection and acquires it with the same atomic-swap idiom as the terminal singleton; the
/// loser is told `busy` on its own stream while the active transfer is left alone. The lease
/// releases on drop, so an aborted handler task can never wedge the gate shut.
#[derive(Debug, Default, Clone)]
pub struct UploadGate(Arc<AtomicBool>);

#[derive(Debug)]
pub struct UploadGateLease(Arc<AtomicBool>);

impl UploadGate {
    pub fn try_acquire(&self) -> Option<UploadGateLease> {
        (!self.0.swap(true, Ordering::AcqRel)).then(|| UploadGateLease(self.0.clone()))
    }
}

impl Drop for UploadGateLease {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The host-owned upload directory: `state_dir/uploads/`, 0700, symlink-refusing, files 0600.
#[derive(Debug, Clone)]
pub struct UploadStore {
    root: PathBuf,
    quota_bytes: u64,
    partial_ttl: Duration,
    completed_ttl: Duration,
}

impl UploadStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            quota_bytes: UPLOAD_QUOTA_BYTES,
            partial_ttl: UPLOAD_PARTIAL_TTL,
            completed_ttl: UPLOAD_COMPLETED_TTL,
        }
    }

    #[cfg(test)]
    fn with_limits(
        root: PathBuf,
        quota_bytes: u64,
        partial_ttl: Duration,
        completed_ttl: Duration,
    ) -> Self {
        Self {
            root,
            quota_bytes,
            partial_ttl,
            completed_ttl,
        }
    }

    /// Opens a fresh partial file for one declared transfer. The destination is entirely
    /// host-chosen: a random 16-hex token names the partial (`{token}.partial`) and prefixes
    /// the sanitized basename in the final name (`{token}-{sanitized}`).
    pub fn begin(
        &self,
        suggested_filename: &str,
        declared_size: u64,
        expected_sha256: &str,
    ) -> Result<PartialUpload> {
        ensure_private_directory(&self.root)?;
        let token = format!("{:016x}", rand::random::<u64>());
        let sanitized = sanitize_filename(suggested_filename);
        let partial_path = self.root.join(format!("{token}.partial"));
        let final_path = self.root.join(format!("{token}-{sanitized}"));
        // `create_new` is O_CREAT|O_EXCL, which never follows a symlink and refuses an existing
        // file — that, plus the random unguessable name inside a 0700 directory, is the race
        // defense: a checked path cannot be swapped for a symlink between check and open,
        // because the check *is* the open.
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let file = options
            .open(&partial_path)
            .context("create the upload partial file")?;
        Ok(PartialUpload {
            store: self.clone(),
            file,
            hasher: Sha256::new(),
            written: 0,
            declared: declared_size,
            expected_sha256: expected_sha256.to_owned(),
            partial_path,
            final_path,
            published: false,
        })
    }

    /// Host-owned cleanup (Spec 007 §3.6): stale partials, expired completed files, then quota
    /// eviction oldest-completed-first. Runs at daemon startup and every sweep interval.
    pub fn sweep(&self) {
        self.sweep_at(SystemTime::now());
    }

    fn sweep_at(&self, now: SystemTime) {
        let entries = match self.scan() {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(error) => {
                tracing::warn!("upload sweep could not scan the uploads directory: {error}");
                return;
            }
        };
        let mut removed_partials = 0_usize;
        let mut removed_expired = 0_usize;
        let mut removed_for_quota = 0_usize;
        let mut completed = Vec::new();
        for entry in entries {
            let age = now.duration_since(entry.modified).unwrap_or(Duration::ZERO);
            if entry.partial {
                if age >= self.partial_ttl && fs::remove_file(&entry.path).is_ok() {
                    removed_partials += 1;
                }
            } else if age >= self.completed_ttl {
                if fs::remove_file(&entry.path).is_ok() {
                    removed_expired += 1;
                }
            } else {
                completed.push(entry);
            }
        }
        completed.sort_by_key(|entry| entry.modified);
        let mut total: u64 = completed.iter().map(|entry| entry.len).sum();
        for entry in &completed {
            if total <= self.quota_bytes {
                break;
            }
            if fs::remove_file(&entry.path).is_ok() {
                total = total.saturating_sub(entry.len);
                removed_for_quota += 1;
            }
        }
        if removed_partials + removed_expired + removed_for_quota > 0 {
            // Counts only — upload filenames stay out of logs exactly like file contents.
            tracing::info!(
                partials = removed_partials,
                expired = removed_expired,
                quota = removed_for_quota,
                "upload sweep removed files"
            );
        }
    }

    /// Evicts the oldest completed uploads until `incoming` more bytes fit inside the quota.
    fn make_room_for(&self, incoming: u64) -> Result<(), UploadFailure> {
        let entries = match self.scan() {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(_) => {
                return Err(UploadFailure::new(
                    UploadErrorCode::Io,
                    "The Mac could not inspect its upload storage.",
                ));
            }
        };
        let mut completed: Vec<SweepEntry> =
            entries.into_iter().filter(|entry| !entry.partial).collect();
        completed.sort_by_key(|entry| entry.modified);
        let mut total: u64 = completed.iter().map(|entry| entry.len).sum();
        let mut oldest_first = completed.into_iter();
        while total.saturating_add(incoming) > self.quota_bytes {
            let Some(entry) = oldest_first.next() else {
                return Err(UploadFailure::new(
                    UploadErrorCode::Quota,
                    "The Mac upload storage is full.",
                ));
            };
            if fs::remove_file(&entry.path).is_err() {
                return Err(UploadFailure::new(
                    UploadErrorCode::Io,
                    "The Mac could not make room in its upload storage.",
                ));
            }
            total = total.saturating_sub(entry.len);
        }
        Ok(())
    }

    /// Lists regular files directly inside the uploads root. Symlinks and directories are
    /// skipped entirely — the sweeper only ever touches the shapes the store itself creates.
    fn scan(&self) -> io::Result<Vec<SweepEntry>> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let Ok(entry) = entry else { continue };
            // `DirEntry::metadata` does not traverse symlinks, so a planted link is skipped
            // rather than followed.
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if !metadata.is_file() {
                continue;
            }
            let partial = entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".partial"));
            let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
            entries.push(SweepEntry {
                path: entry.path(),
                len: metadata.len(),
                modified,
                partial,
            });
        }
        Ok(entries)
    }
}

#[derive(Debug)]
struct SweepEntry {
    path: PathBuf,
    len: u64,
    modified: SystemTime,
    partial: bool,
}

/// An in-flight transfer streaming to `{token}.partial` with a running SHA-256; the whole file
/// is never buffered in memory. Dropping it unpublished removes the partial file, which is
/// what cleans up every error path — including an aborted handler task — without each caller
/// remembering to.
#[derive(Debug)]
pub struct PartialUpload {
    store: UploadStore,
    file: File,
    hasher: Sha256,
    written: u64,
    declared: u64,
    expected_sha256: String,
    partial_path: PathBuf,
    final_path: PathBuf,
    published: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedUpload {
    pub host_path: PathBuf,
    pub prompt_reference: String,
    pub expires_at: String,
}

impl PartialUpload {
    pub fn write_chunk(&mut self, chunk: &[u8]) -> Result<(), UploadFailure> {
        if self.written.saturating_add(chunk.len() as u64) > self.declared {
            return Err(UploadFailure::new(
                UploadErrorCode::Invalid,
                "More bytes arrived than the declared size.",
            ));
        }
        if self.file.write_all(chunk).is_err() {
            return Err(UploadFailure::new(
                UploadErrorCode::Io,
                "The Mac could not store the upload.",
            ));
        }
        self.hasher.update(chunk);
        self.written += chunk.len() as u64;
        Ok(())
    }

    /// Verifies exact size and hash, then atomically publishes. On any failure the partial is
    /// removed (via `Drop`) and nothing is published — the final name only ever appears after
    /// every check has passed.
    pub fn finish(mut self) -> Result<CompletedUpload, UploadFailure> {
        if self.written != self.declared {
            return Err(UploadFailure::new(
                UploadErrorCode::Invalid,
                "Fewer bytes arrived than the declared size.",
            ));
        }
        let digest = hex_lower(&self.hasher.finalize_reset());
        if digest != self.expected_sha256 {
            return Err(UploadFailure::new(
                UploadErrorCode::HashMismatch,
                "The uploaded bytes did not match the declared SHA-256.",
            ));
        }
        if self.file.sync_all().is_err() {
            return Err(UploadFailure::new(
                UploadErrorCode::Io,
                "The Mac could not store the upload.",
            ));
        }
        self.store.make_room_for(self.declared)?;
        if fs::rename(&self.partial_path, &self.final_path).is_err() {
            return Err(UploadFailure::new(
                UploadErrorCode::Io,
                "The Mac could not publish the upload.",
            ));
        }
        self.published = true;
        // Directory durability is best-effort: the publish is already complete, and failing
        // the transfer over a metadata sync would report an error for a file that exists.
        if let Ok(root) = File::open(&self.store.root) {
            let _ = root.sync_all();
        }
        let completed_at = SystemTime::now();
        let host_path = self.final_path.clone();
        Ok(CompletedUpload {
            prompt_reference: posix_single_quote(&host_path.to_string_lossy()),
            host_path,
            expires_at: format_rfc3339_utc(completed_at + self.store.completed_ttl),
        })
    }
}

impl Drop for PartialUpload {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.partial_path);
        }
    }
}

enum FrameOutcome {
    Frame(UploadClientFrame),
    Timeout,
    /// A decodable-but-wrong frame: answered in-protocol with `put_error invalid`.
    Protocol,
    /// The peer is gone or the stream broke: nothing can be answered, the caller resets.
    Transport(HostProtocolError),
}

async fn next_frame<R>(
    reader: &mut UploadFrameReader,
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

async fn write_upload_control<W, T>(
    send: &mut W,
    frame_type: u8,
    value: &T,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let encoded = encode_upload_control(frame_type, value)?;
    send.write_all(&encoded).await?;
    send.flush().await?;
    Ok(())
}

pub async fn send_put_error<W>(
    send: &mut W,
    code: UploadErrorCode,
    message: &str,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
{
    // Categorical only, modeled on the agent stream's refusal log: this is the one place that
    // makes a refused upload distinguishable from one that never arrived, and it never carries
    // a filename, path, or hash.
    tracing::warn!(code = code.wire(), "upload stream refused");
    write_upload_control(
        send,
        FRAME_PUT_ERROR,
        &PutError {
            v: UPLOAD_JSON_VERSION,
            code: code.wire().into(),
            message: message.into(),
        },
    )
    .await
}

async fn refuse<W>(
    send: &mut W,
    code: UploadErrorCode,
    message: &str,
) -> Result<(), HostProtocolError>
where
    W: AsyncWrite + Unpin,
{
    send_put_error(send, code, message).await?;
    Ok(())
}

/// The upload state machine over one already-prefaced stream: open → validate → accepted →
/// sequential chunks → finish → done, with every failure answered by exactly one `put_error`
/// and the partial removed. Returns `Ok(())` when the exchange concluded with a frame the
/// phone can read (done or error) and `Err` when the transport broke and the caller should
/// reset the stream. Generic over the stream halves so the whole state machine runs under
/// tests on an in-memory duplex; the daemon passes the QUIC halves.
pub async fn run_upload_stream<R, W>(
    recv: &mut R,
    send: &mut W,
    store: &UploadStore,
    idle_timeout: Duration,
) -> Result<(), HostProtocolError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = UploadFrameReader::default();
    let first = match next_frame(&mut reader, recv, idle_timeout).await {
        FrameOutcome::Frame(frame) => frame,
        FrameOutcome::Timeout => {
            return refuse(send, UploadErrorCode::Timeout, "The upload timed out.").await;
        }
        FrameOutcome::Protocol => {
            return refuse(
                send,
                UploadErrorCode::Invalid,
                "The upload frame was malformed.",
            )
            .await;
        }
        FrameOutcome::Transport(error) => return Err(error),
    };
    let open = match first {
        UploadClientFrame::Open(open) => open,
        UploadClientFrame::Cancel => {
            return refuse(
                send,
                UploadErrorCode::Cancelled,
                "The upload was cancelled.",
            )
            .await;
        }
        UploadClientFrame::Chunk(_) | UploadClientFrame::Finish => {
            return refuse(
                send,
                UploadErrorCode::Invalid,
                "The stream must begin with put_open.",
            )
            .await;
        }
    };
    if let Err(failure) = open.validate() {
        return refuse(send, failure.code, failure.message).await;
    }
    let mut partial = match store.begin(&open.filename, open.size, &open.sha256) {
        Ok(partial) => partial,
        Err(error) => {
            // The context names at most the host-owned uploads directory — never the phone's
            // suggested filename, which stays out of logs like file contents (Spec 007 §6).
            tracing::warn!("upload could not create its partial file: {error:#}");
            return refuse(
                send,
                UploadErrorCode::Io,
                "The Mac could not store the upload.",
            )
            .await;
        }
    };
    let accepted = PutAccepted {
        v: UPLOAD_JSON_VERSION,
        transfer_id: format!("{:032x}", rand::random::<u128>()),
        chunk_bytes: MAX_UPLOAD_CHUNK_PAYLOAD as u32,
        max_bytes: MAX_UPLOAD_FILE_BYTES,
    };
    write_upload_control(send, FRAME_PUT_ACCEPTED, &accepted).await?;
    loop {
        let frame = match next_frame(&mut reader, recv, idle_timeout).await {
            FrameOutcome::Frame(frame) => frame,
            FrameOutcome::Timeout => {
                return refuse(send, UploadErrorCode::Timeout, "The upload timed out.").await;
            }
            FrameOutcome::Protocol => {
                return refuse(
                    send,
                    UploadErrorCode::Invalid,
                    "The upload frame was malformed.",
                )
                .await;
            }
            FrameOutcome::Transport(error) => return Err(error),
        };
        match frame {
            UploadClientFrame::Chunk(bytes) => {
                if let Err(failure) = partial.write_chunk(&bytes) {
                    return refuse(send, failure.code, failure.message).await;
                }
            }
            UploadClientFrame::Finish => {
                return match partial.finish() {
                    Ok(completed) => {
                        tracing::info!(bytes = open.size, "upload published");
                        write_upload_control(
                            send,
                            FRAME_PUT_DONE,
                            &PutDone {
                                v: UPLOAD_JSON_VERSION,
                                host_path: completed.host_path.to_string_lossy().into_owned(),
                                prompt_reference: completed.prompt_reference,
                                expires_at: completed.expires_at,
                            },
                        )
                        .await
                    }
                    Err(failure) => refuse(send, failure.code, failure.message).await,
                };
            }
            UploadClientFrame::Cancel => {
                return refuse(
                    send,
                    UploadErrorCode::Cancelled,
                    "The upload was cancelled.",
                )
                .await;
            }
            UploadClientFrame::Open(_) => {
                return refuse(
                    send,
                    UploadErrorCode::Invalid,
                    "Exactly one upload runs per stream.",
                )
                .await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, path::Path};

    use tempfile::tempdir;

    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex_lower(&hasher.finalize())
    }

    fn open_frame(filename: &str, size: u64, sha256: &str) -> Vec<u8> {
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

    async fn read_host_frame<R>(reader: &mut R) -> (u8, Vec<u8>)
    where
        R: AsyncRead + Unpin,
    {
        let mut header = [0_u8; 5];
        reader.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes(header[1..5].try_into().unwrap()) as usize;
        let mut payload = vec![0_u8; length];
        reader.read_exact(&mut payload).await.unwrap();
        (header[0], payload)
    }

    async fn expect_put_error<R>(reader: &mut R, code: UploadErrorCode)
    where
        R: AsyncRead + Unpin,
    {
        let (frame_type, payload) = read_host_frame(reader).await;
        assert_eq!(frame_type, FRAME_PUT_ERROR);
        let error: PutError = serde_json::from_slice(&payload).unwrap();
        assert_eq!(error.v, 1);
        assert_eq!(error.code, code.wire());
    }

    fn store_in(temp: &tempfile::TempDir) -> UploadStore {
        UploadStore::new(temp.path().join("uploads"))
    }

    fn dir_names(root: &Path) -> Vec<String> {
        let Ok(entries) = fs::read_dir(root) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // --- Codec ---

    #[test]
    fn client_frames_round_trip_through_the_codec() {
        let open = PutOpen {
            v: 1,
            request_id: "6BA7B810-9DAD-11D1-80B4-00C04FD430C8".into(),
            filename: "photo.png".into(),
            source_kind: "photo".into(),
            size: 42,
            sha256: "a".repeat(64),
        };
        let encoded = encode_upload_control(FRAME_PUT_OPEN, &open).unwrap();
        assert_eq!(encoded[0], FRAME_PUT_OPEN);
        let decoded = decode_upload_client_frame(FRAME_PUT_OPEN, &encoded[5..]).unwrap();
        assert_eq!(decoded, UploadClientFrame::Open(open));

        let chunk = encode_upload_frame(FRAME_PUT_CHUNK, b"raw bytes").unwrap();
        assert_eq!(
            decode_upload_client_frame(FRAME_PUT_CHUNK, &chunk[5..]).unwrap(),
            UploadClientFrame::Chunk(b"raw bytes".to_vec())
        );

        let finish = encode_upload_frame(FRAME_PUT_FINISH, b"").unwrap();
        assert_eq!(finish, vec![FRAME_PUT_FINISH, 0, 0, 0, 0]);
        assert_eq!(
            decode_upload_client_frame(FRAME_PUT_FINISH, &finish[5..]).unwrap(),
            UploadClientFrame::Finish
        );

        let cancel = encode_upload_frame(FRAME_PUT_CANCEL, b"").unwrap();
        assert_eq!(
            decode_upload_client_frame(FRAME_PUT_CANCEL, &cancel[5..]).unwrap(),
            UploadClientFrame::Cancel
        );
    }

    #[test]
    fn host_frames_round_trip_through_serde() {
        let accepted = PutAccepted {
            v: 1,
            transfer_id: "abc123".into(),
            chunk_bytes: 16_384,
            max_bytes: 8_388_608,
        };
        let encoded = encode_upload_control(FRAME_PUT_ACCEPTED, &accepted).unwrap();
        assert_eq!(encoded[0], FRAME_PUT_ACCEPTED);
        let reparsed: PutAccepted = serde_json::from_slice(&encoded[5..]).unwrap();
        assert_eq!(reparsed, accepted);

        let done = PutDone {
            v: 1,
            host_path: "/tmp/u/abc-file.png".into(),
            prompt_reference: "'/tmp/u/abc-file.png'".into(),
            expires_at: "2026-08-11T00:00:00Z".into(),
        };
        let encoded = encode_upload_control(FRAME_PUT_DONE, &done).unwrap();
        let reparsed: PutDone = serde_json::from_slice(&encoded[5..]).unwrap();
        assert_eq!(reparsed, done);

        let error = PutError {
            v: 1,
            code: "busy".into(),
            message: "Another upload is already in progress.".into(),
        };
        let encoded = encode_upload_control(FRAME_PUT_ERROR, &error).unwrap();
        let reparsed: PutError = serde_json::from_slice(&encoded[5..]).unwrap();
        assert_eq!(reparsed, error);
    }

    #[test]
    fn payload_caps_are_enforced_per_frame_type() {
        // Control frames: 4096 is the cap, one byte over fails.
        assert!(encode_upload_frame(FRAME_PUT_OPEN, &vec![b'x'; 4096]).is_ok());
        assert!(matches!(
            encode_upload_frame(FRAME_PUT_OPEN, &vec![b'x'; 4097]),
            Err(HostProtocolError::FrameTooLarge)
        ));
        // Chunk frames: 16 KiB is the cap, one byte over fails.
        assert!(encode_upload_frame(FRAME_PUT_CHUNK, &vec![0_u8; 16_384]).is_ok());
        assert!(matches!(
            encode_upload_frame(FRAME_PUT_CHUNK, &vec![0_u8; 16_385]),
            Err(HostProtocolError::FrameTooLarge)
        ));
        // Empty-payload frames accept nothing else.
        assert!(matches!(
            encode_upload_frame(FRAME_PUT_FINISH, b"x"),
            Err(HostProtocolError::FrameTooLarge)
        ));
        assert!(matches!(
            decode_upload_client_frame(FRAME_PUT_FINISH, b"x"),
            Err(HostProtocolError::InvalidControlValue)
        ));
        // A zero-byte chunk carries nothing and is refused.
        assert!(matches!(
            decode_upload_client_frame(FRAME_PUT_CHUNK, b""),
            Err(HostProtocolError::ZeroLength)
        ));
    }

    #[tokio::test]
    async fn reader_enforces_caps_from_the_header_alone() {
        // The header claims an over-cap chunk; the reader must fail before any payload
        // arrives, not buffer 100 MiB waiting for it.
        let (mut client, mut server) = tokio::io::duplex(1024);
        let mut header = vec![FRAME_PUT_CHUNK];
        header.extend_from_slice(&(MAX_UPLOAD_CHUNK_PAYLOAD as u32 + 1).to_be_bytes());
        client.write_all(&header).await.unwrap();
        let mut reader = UploadFrameReader::default();
        assert!(matches!(
            reader.next(&mut server).await,
            Err(HostProtocolError::FrameTooLarge)
        ));
    }

    #[test]
    fn unknown_and_wrong_direction_frame_types_are_refused() {
        assert!(matches!(
            decode_upload_client_frame(0x08, b""),
            Err(HostProtocolError::UnknownFrameType)
        ));
        assert!(matches!(
            decode_upload_client_frame(0x00, b""),
            Err(HostProtocolError::UnknownFrameType)
        ));
        for host_only in [FRAME_PUT_ACCEPTED, FRAME_PUT_DONE, FRAME_PUT_ERROR] {
            assert!(matches!(
                decode_upload_client_frame(host_only, b"{}"),
                Err(HostProtocolError::UnexpectedDirection)
            ));
        }
        assert!(matches!(
            encode_upload_frame(0x08, b""),
            Err(HostProtocolError::UnknownFrameType)
        ));
    }

    #[test]
    fn unparseable_open_json_is_malformed() {
        assert!(matches!(
            decode_upload_client_frame(FRAME_PUT_OPEN, b"not json"),
            Err(HostProtocolError::MalformedJson)
        ));
        // Unknown fields are refused too — the frozen format is exact.
        assert!(matches!(
            decode_upload_client_frame(
                FRAME_PUT_OPEN,
                br#"{"v":1,"request_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","filename":"a","source_kind":"file","size":1,"sha256":"x","extra":true}"#,
            ),
            Err(HostProtocolError::MalformedJson)
        ));
    }

    #[tokio::test]
    async fn reader_assembles_frames_fed_one_byte_at_a_time() {
        let frame = open_frame("photo.png", 3, &"a".repeat(64));
        let chunk = encode_upload_frame(FRAME_PUT_CHUNK, b"abc").unwrap();
        let (mut client, mut server) = tokio::io::duplex(4096);
        let mut bytes = frame.clone();
        bytes.extend_from_slice(&chunk);
        let writer = tokio::spawn(async move {
            for byte in bytes {
                client.write_all(&[byte]).await.unwrap();
                client.flush().await.unwrap();
            }
            client
        });
        let mut reader = UploadFrameReader::default();
        let first = reader.next(&mut server).await.unwrap();
        assert!(matches!(first, UploadClientFrame::Open(_)));
        let second = reader.next(&mut server).await.unwrap();
        assert_eq!(second, UploadClientFrame::Chunk(b"abc".to_vec()));
        drop(writer.await.unwrap());
        // EOF mid-header is truncation, not a silent hang.
        assert!(matches!(
            reader.next(&mut server).await,
            Err(HostProtocolError::Truncated)
        ));
    }

    // --- Sanitization and quoting ---

    #[test]
    fn sanitize_filename_reduces_hostile_names() {
        let cases: &[(&str, &str)] = &[
            ("../../etc/passwd", "_.._etc_passwd"),
            ("/etc/passwd", "_etc_passwd"),
            ("..", "upload"),
            ("...", "upload"),
            (".hidden", "hidden"),
            ("", "upload"),
            ("   ", "_"),
            ("my file's.png", "my_file_s.png"),
            ("a\u{7}b\u{1b}[31m", "a_b_31m"),
            ("café🙂.png", "caf_.png"),
            ("раssword.txt", "_ssword.txt"),
            ("normal-name_1.2.jpg", "normal-name_1.2.jpg"),
            ("shell;rm -rf ~$(boom)`x`.png", "shell_rm_-rf_boom_x_.png"),
        ];
        for (input, expected) in cases {
            let sanitized = sanitize_filename(input);
            assert_eq!(&sanitized, expected, "input {input:?}");
            assert!(
                sanitized
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
                "input {input:?}"
            );
            assert!(!sanitized.starts_with('.'), "input {input:?}");
        }
    }

    #[test]
    fn sanitize_filename_caps_length_and_preserves_a_reasonable_extension() {
        let long = format!("{}.png", "a".repeat(300));
        let sanitized = sanitize_filename(&long);
        assert_eq!(sanitized.len(), MAX_SANITIZED_FILENAME);
        assert!(sanitized.ends_with(".png"));

        // An unreasonable "extension" (too long) is not preserved; the name is just cut.
        let weird = format!("{}.{}", "b".repeat(100), "c".repeat(40));
        let sanitized = sanitize_filename(&weird);
        assert_eq!(sanitized.len(), MAX_SANITIZED_FILENAME);
        assert!(!sanitized.contains('.'));

        // A 300-char name with no dot at all is also just cut.
        let plain = "d".repeat(300);
        assert_eq!(sanitize_filename(&plain).len(), MAX_SANITIZED_FILENAME);
    }

    #[test]
    fn prompt_reference_quotes_posix_single_quotes() {
        assert_eq!(posix_single_quote("/tmp/plain"), "'/tmp/plain'");
        assert_eq!(
            posix_single_quote("/Users/o'brien/Library/Application Support/Ciao/uploads/x.png"),
            "'/Users/o'\\''brien/Library/Application Support/Ciao/uploads/x.png'"
        );
        // The apostrophe escape is exact: close, escaped quote, reopen.
        assert_eq!(posix_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn rfc3339_formatting_is_correct() {
        assert_eq!(format_rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(
            format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_000_000_000)),
            "2001-09-09T01:46:40Z"
        );
        // A leap day and a date after it, both across the 400-year cycle math.
        assert_eq!(
            format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_709_164_800)),
            "2024-02-29T00:00:00Z"
        );
        assert_eq!(
            format_rfc3339_utc(UNIX_EPOCH + Duration::from_secs(1_776_038_399)),
            "2026-04-12T23:59:59Z"
        );
    }

    // --- Open validation ---

    #[test]
    fn put_open_validation_rejects_bad_metadata() {
        let valid = PutOpen {
            v: 1,
            request_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".into(),
            filename: "a.png".into(),
            source_kind: "photo".into(),
            size: 1,
            sha256: "a".repeat(64),
        };
        valid.validate().unwrap();

        let mut wrong_version = valid.clone();
        wrong_version.v = 2;
        assert_eq!(
            wrong_version.validate().unwrap_err().code,
            UploadErrorCode::Invalid
        );

        let mut bad_request = valid.clone();
        bad_request.request_id = "not-a-uuid".into();
        assert_eq!(
            bad_request.validate().unwrap_err().code,
            UploadErrorCode::Invalid
        );

        let mut bad_kind = valid.clone();
        bad_kind.source_kind = "clipboard".into();
        assert_eq!(
            bad_kind.validate().unwrap_err().code,
            UploadErrorCode::Invalid
        );

        let mut uppercase_hash = valid.clone();
        uppercase_hash.sha256 = "A".repeat(64);
        assert_eq!(
            uppercase_hash.validate().unwrap_err().code,
            UploadErrorCode::Invalid
        );

        let mut zero_size = valid.clone();
        zero_size.size = 0;
        assert_eq!(
            zero_size.validate().unwrap_err().code,
            UploadErrorCode::Invalid
        );

        let mut too_large = valid.clone();
        too_large.size = MAX_UPLOAD_FILE_BYTES + 1;
        assert_eq!(
            too_large.validate().unwrap_err().code,
            UploadErrorCode::TooLarge
        );
        let mut at_limit = valid;
        at_limit.size = MAX_UPLOAD_FILE_BYTES;
        at_limit.validate().unwrap();
    }

    // --- Store ---

    #[test]
    fn happy_path_publishes_atomically_with_owner_only_permissions() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let content = b"hello attachment".to_vec();
        let mut partial = store
            .begin("photo.png", content.len() as u64, &sha256_hex(&content))
            .unwrap();

        // Mid-transfer, only the partial exists — the final name must not appear early.
        let names = dir_names(store.root.as_path());
        assert_eq!(names.len(), 1);
        assert!(names[0].ends_with(".partial"));
        let partial_mode = fs::metadata(store.root.join(&names[0]))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(partial_mode, 0o600);
        let root_mode = fs::metadata(&store.root).unwrap().permissions().mode() & 0o777;
        assert_eq!(root_mode, 0o700);

        partial.write_chunk(&content[..5]).unwrap();
        partial.write_chunk(&content[5..]).unwrap();
        let completed = partial.finish().unwrap();

        let names = dir_names(store.root.as_path());
        assert_eq!(names.len(), 1, "partial must be gone after publish");
        assert!(names[0].ends_with("-photo.png"));
        assert_eq!(completed.host_path, store.root.join(&names[0]));
        assert_eq!(fs::read(&completed.host_path).unwrap(), content);
        let mode = fs::metadata(&completed.host_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            completed.prompt_reference,
            posix_single_quote(&completed.host_path.to_string_lossy())
        );
        // Expiry is RFC 3339 UTC, about 24 hours out.
        let expected_prefix =
            format_rfc3339_utc(SystemTime::now() + UPLOAD_COMPLETED_TTL - Duration::from_secs(2));
        assert_eq!(completed.expires_at.len(), 20);
        assert!(completed.expires_at.ends_with('Z'));
        assert!(completed.expires_at.as_str() >= expected_prefix.as_str());
    }

    #[test]
    fn wrong_hash_publishes_nothing_and_removes_the_partial() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut partial = store.begin("doc.pdf", 4, &"0".repeat(64)).unwrap();
        partial.write_chunk(b"1234").unwrap();
        let failure = partial.finish().unwrap_err();
        assert_eq!(failure.code, UploadErrorCode::HashMismatch);
        assert!(
            dir_names(store.root.as_path()).is_empty(),
            "nothing may be published and no partial may remain"
        );
    }

    #[test]
    fn bytes_beyond_the_declared_size_fail() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut partial = store.begin("doc.pdf", 4, &"0".repeat(64)).unwrap();
        partial.write_chunk(b"123").unwrap();
        let failure = partial.write_chunk(b"45").unwrap_err();
        assert_eq!(failure.code, UploadErrorCode::Invalid);
        drop(partial);
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[test]
    fn finishing_with_fewer_bytes_than_declared_fails() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut partial = store.begin("doc.pdf", 4, &sha256_hex(b"123")).unwrap();
        partial.write_chunk(b"123").unwrap();
        let failure = partial.finish().unwrap_err();
        assert_eq!(failure.code, UploadErrorCode::Invalid);
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[test]
    fn upload_gate_admits_one_transfer_at_a_time() {
        let gate = UploadGate::default();
        let lease = gate.try_acquire().expect("first acquire succeeds");
        assert!(
            gate.try_acquire().is_none(),
            "second concurrent open is busy"
        );
        drop(lease);
        assert!(
            gate.try_acquire().is_some(),
            "the gate reopens when the lease drops"
        );
    }

    #[test]
    fn sweep_removes_stale_partials_and_expired_completed_files() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        // A live upload writes a fresh partial; a completed file publishes alongside it.
        let content = b"keep me".to_vec();
        let mut partial = store
            .begin("keep.txt", content.len() as u64, &sha256_hex(&content))
            .unwrap();
        partial.write_chunk(&content).unwrap();
        let completed = partial.finish().unwrap();
        let _stale_partial = store.begin("stale.bin", 10, &"0".repeat(64)).unwrap();

        // Just after creation nothing is old enough to remove.
        store.sweep_at(SystemTime::now());
        assert_eq!(dir_names(store.root.as_path()).len(), 2);

        // Twenty minutes later the abandoned partial is gone, the completed file stays.
        store.sweep_at(SystemTime::now() + Duration::from_secs(20 * 60));
        let names = dir_names(store.root.as_path());
        assert_eq!(names.len(), 1);
        assert!(names[0].ends_with("-keep.txt"));
        assert!(completed.host_path.exists());

        // Twenty-five hours later the completed file has expired too.
        store.sweep_at(SystemTime::now() + Duration::from_secs(25 * 60 * 60));
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[test]
    fn quota_evicts_the_oldest_completed_uploads_first() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("uploads");
        let store = UploadStore::with_limits(
            root.clone(),
            10, // quota: ten bytes
            UPLOAD_PARTIAL_TTL,
            UPLOAD_COMPLETED_TTL,
        );
        ensure_private_directory(&root).unwrap();
        let base = SystemTime::now() - Duration::from_secs(600);
        for (name, age_rank) in [("aa-old.bin", 0_u64), ("bb-mid.bin", 1), ("cc-new.bin", 2)] {
            let path = root.join(name);
            fs::write(&path, b"12345").unwrap();
            let file = File::options().write(true).open(&path).unwrap();
            file.set_modified(base + Duration::from_secs(age_rank * 60))
                .unwrap();
        }

        // Fifteen bytes against a ten-byte quota: exactly the oldest file goes.
        store.sweep_at(SystemTime::now());
        assert_eq!(
            dir_names(&root),
            vec!["bb-mid.bin".to_string(), "cc-new.bin".to_string()]
        );

        // Publishing five more bytes evicts the next-oldest to make room.
        let content = b"67890".to_vec();
        let mut partial = store
            .begin("fresh.bin", content.len() as u64, &sha256_hex(&content))
            .unwrap();
        partial.write_chunk(&content).unwrap();
        let completed = partial.finish().unwrap();
        let names = dir_names(&root);
        assert_eq!(names.len(), 2);
        assert!(!names.contains(&"bb-mid.bin".to_string()));
        assert!(names.contains(&"cc-new.bin".to_string()));
        assert!(completed.host_path.exists());
    }

    #[test]
    fn symlinked_uploads_directory_is_refused() {
        let temp = tempdir().unwrap();
        let elsewhere = temp.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let root = temp.path().join("uploads");
        std::os::unix::fs::symlink(&elsewhere, &root).unwrap();
        let store = UploadStore::new(root);
        let error = store.begin("a.png", 1, &"0".repeat(64)).unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error:#}");
        assert!(
            dir_names(&elsewhere).is_empty(),
            "nothing may be written through the symlink"
        );
    }

    // --- Handler state machine (the daemon's QUIC accept path itself needs a live
    // endpoint, so these drive the full state machine one layer down over a duplex) ---

    async fn run_handler_with(
        store: UploadStore,
        idle_timeout: Duration,
        client_script: Vec<u8>,
    ) -> (Vec<u8>, Result<(), HostProtocolError>) {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let handler = tokio::spawn(async move {
            run_upload_stream(&mut server_read, &mut server_write, &store, idle_timeout).await
        });
        client.write_all(&client_script).await.unwrap();
        client.flush().await.unwrap();
        let result = handler.await.unwrap();
        let _ = client.shutdown().await;
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response).await;
        (response, result)
    }

    #[tokio::test]
    async fn upload_round_trip_publishes_and_reports_done() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let content: Vec<u8> = (0_u32..40_000).map(|value| value as u8).collect();
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let handler_store = store.clone();
        let handler = tokio::spawn(async move {
            run_upload_stream(
                &mut server_read,
                &mut server_write,
                &handler_store,
                UPLOAD_IDLE_TIMEOUT,
            )
            .await
        });

        client
            .write_all(&open_frame(
                "trip.bin",
                content.len() as u64,
                &sha256_hex(&content),
            ))
            .await
            .unwrap();
        let (frame_type, payload) = read_host_frame(&mut client).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        let accepted: PutAccepted = serde_json::from_slice(&payload).unwrap();
        assert_eq!(accepted.v, 1);
        assert_eq!(accepted.chunk_bytes, 16_384);
        assert_eq!(accepted.max_bytes, 8_388_608);
        assert!(!accepted.transfer_id.is_empty());

        for chunk in content.chunks(accepted.chunk_bytes as usize) {
            client
                .write_all(&encode_upload_frame(FRAME_PUT_CHUNK, chunk).unwrap())
                .await
                .unwrap();
        }
        client
            .write_all(&encode_upload_frame(FRAME_PUT_FINISH, b"").unwrap())
            .await
            .unwrap();

        let (frame_type, payload) = read_host_frame(&mut client).await;
        assert_eq!(frame_type, FRAME_PUT_DONE);
        let done: PutDone = serde_json::from_slice(&payload).unwrap();
        assert_eq!(done.v, 1);
        assert!(done.host_path.ends_with("-trip.bin"));
        assert_eq!(done.prompt_reference, posix_single_quote(&done.host_path));
        assert_eq!(fs::read(&done.host_path).unwrap(), content);
        assert_eq!(done.expires_at.len(), 20);
        handler.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn chunk_before_open_is_invalid_and_leaves_nothing_behind() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let script = encode_upload_frame(FRAME_PUT_CHUNK, b"sneaky").unwrap();
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        expect_put_error(&mut cursor, UploadErrorCode::Invalid).await;
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[tokio::test]
    async fn oversized_declaration_is_rejected_at_open_before_any_chunk() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let script = open_frame("big.bin", MAX_UPLOAD_FILE_BYTES + 1, &"0".repeat(64));
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        expect_put_error(&mut cursor, UploadErrorCode::TooLarge).await;
        assert!(
            dir_names(store.root.as_path()).is_empty(),
            "no partial may be created for a rejected declaration"
        );
    }

    #[tokio::test]
    async fn zero_size_declaration_is_invalid() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let script = open_frame("zero.bin", 0, &"0".repeat(64));
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        expect_put_error(&mut cursor, UploadErrorCode::Invalid).await;
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[tokio::test]
    async fn cancel_mid_transfer_removes_the_partial() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut script = open_frame("cancelled.bin", 100, &"0".repeat(64));
        script.extend_from_slice(&encode_upload_frame(FRAME_PUT_CHUNK, b"partial data").unwrap());
        script.extend_from_slice(&encode_upload_frame(FRAME_PUT_CANCEL, b"").unwrap());
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        let (frame_type, _) = read_host_frame(&mut cursor).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        expect_put_error(&mut cursor, UploadErrorCode::Cancelled).await;
        assert!(
            dir_names(store.root.as_path()).is_empty(),
            "cancel must remove the partial"
        );
    }

    #[tokio::test]
    async fn second_open_on_the_same_stream_is_invalid() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut script = open_frame("one.bin", 10, &"0".repeat(64));
        script.extend_from_slice(&open_frame("two.bin", 10, &"0".repeat(64)));
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        let (frame_type, _) = read_host_frame(&mut cursor).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        expect_put_error(&mut cursor, UploadErrorCode::Invalid).await;
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[tokio::test]
    async fn hash_mismatch_is_reported_and_nothing_is_published() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut script = open_frame("lied.bin", 4, &"0".repeat(64));
        script.extend_from_slice(&encode_upload_frame(FRAME_PUT_CHUNK, b"1234").unwrap());
        script.extend_from_slice(&encode_upload_frame(FRAME_PUT_FINISH, b"").unwrap());
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        let (frame_type, _) = read_host_frame(&mut cursor).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        expect_put_error(&mut cursor, UploadErrorCode::HashMismatch).await;
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[tokio::test]
    async fn overrun_beyond_declared_size_is_invalid_mid_stream() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut script = open_frame("small.bin", 4, &"0".repeat(64));
        script.extend_from_slice(&encode_upload_frame(FRAME_PUT_CHUNK, b"123456").unwrap());
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        let (frame_type, _) = read_host_frame(&mut cursor).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        expect_put_error(&mut cursor, UploadErrorCode::Invalid).await;
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[tokio::test]
    async fn idle_timeout_mid_transfer_fails_and_removes_the_partial() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let handler_store = store.clone();
        let handler = tokio::spawn(async move {
            run_upload_stream(
                &mut server_read,
                &mut server_write,
                &handler_store,
                Duration::from_millis(100),
            )
            .await
        });
        client
            .write_all(&open_frame("stalled.bin", 50, &"0".repeat(64)))
            .await
            .unwrap();
        let (frame_type, _) = read_host_frame(&mut client).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        // The client now stalls; the host must fail the transfer on its own.
        expect_put_error(&mut client, UploadErrorCode::Timeout).await;
        handler.await.unwrap().unwrap();
        assert!(
            dir_names(store.root.as_path()).is_empty(),
            "timeout must remove the partial"
        );
    }

    #[tokio::test]
    async fn malformed_frame_mid_transfer_is_invalid_and_removes_the_partial() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let mut script = open_frame("garbled.bin", 10, &"0".repeat(64));
        // Unknown frame type 0x09 after accept.
        script.extend_from_slice(&[0x09, 0, 0, 0, 0]);
        let (response, result) = run_handler_with(store.clone(), UPLOAD_IDLE_TIMEOUT, script).await;
        result.unwrap();
        let mut cursor = io::Cursor::new(response);
        let (frame_type, _) = read_host_frame(&mut cursor).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        expect_put_error(&mut cursor, UploadErrorCode::Invalid).await;
        assert!(dir_names(store.root.as_path()).is_empty());
    }

    #[tokio::test]
    async fn peer_disconnect_mid_transfer_removes_the_partial_without_an_error_frame() {
        let temp = tempdir().unwrap();
        let store = store_in(&temp);
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let (mut server_read, mut server_write) = tokio::io::split(server);
        let handler_store = store.clone();
        let handler = tokio::spawn(async move {
            run_upload_stream(
                &mut server_read,
                &mut server_write,
                &handler_store,
                UPLOAD_IDLE_TIMEOUT,
            )
            .await
        });
        client
            .write_all(&open_frame("dropped.bin", 50, &"0".repeat(64)))
            .await
            .unwrap();
        let (frame_type, _) = read_host_frame(&mut client).await;
        assert_eq!(frame_type, FRAME_PUT_ACCEPTED);
        drop(client);
        let result = handler.await.unwrap();
        assert!(matches!(
            result,
            Err(HostProtocolError::Truncated | HostProtocolError::Io(_))
        ));
        assert!(dir_names(store.root.as_path()).is_empty());
    }
}
