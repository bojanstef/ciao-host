//! Explicit versioned host installation, update, and rollback (Spec 004 §9).
//!
//! Everything here is bounded and fail-closed: archives are parsed by a strict ustar reader
//! with an entry allowlist, the declared SHA-256 is verified before any parsing, staging and
//! replacement happen in the destination filesystem, and exactly one rollback slot is kept.
//! Identity and pairing state are never read or written here.

use std::{
    fs,
    io::{IsTerminal, Read},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::storage::CiaoPaths;

pub const ARCHIVE_ENTRY_BINARY: &str = "ciao";
pub const ARCHIVE_ENTRY_METADATA: &str = "install.json";
pub const ARCHIVE_TEXT_ENTRIES: &[&str] =
    &["LICENSE-MIT", "LICENSE-APACHE", "THIRD-PARTY-NOTICES.md"];

/// Explicit finite caps (Spec 004 §11). Single-source; boundary-tested below.
pub const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_BINARY_BYTES: u64 = 200 * 1024 * 1024;
pub const MAX_TEXT_BYTES: u64 = 1024 * 1024;
pub const MAX_METADATA_BYTES: u64 = 4 * 1024;
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub const MAX_MANIFEST_ARTIFACTS: usize = 64;
pub const MAX_VERSION_BYTES: usize = 32;
/// Download bounds for the explicit owner-configured HTTPS release base.
pub const DOWNLOAD_MAX_SECONDS: u32 = 300;

const TAR_BLOCK: usize = 512;

pub fn stable_binary_dir(paths: &CiaoPaths) -> PathBuf {
    paths.home.join(".local/bin")
}

pub fn stable_binary_path(paths: &CiaoPaths) -> PathBuf {
    stable_binary_dir(paths).join("ciao")
}

pub fn rollback_binary_path(paths: &CiaoPaths) -> PathBuf {
    stable_binary_dir(paths).join("ciao.previous")
}

/// The only architectures with released artifacts (Spec 004 §9.1). Anything else is refused
/// for distribution rather than guessed.
pub fn current_release_target() -> Option<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-gnu")
    } else {
        None
    }
}

pub fn archive_file_name(version: &str, target: &str) -> String {
    format!("ciao-{version}-{target}.tar")
}

/// Bounded release version grammar: 1–32 ASCII bytes of `[0-9A-Za-z.-]`, starting with a digit.
pub fn valid_release_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_BYTES
        && version.as_bytes()[0].is_ascii_digit()
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

// ---------------------------------------------------------------------------
// Release manifest
// ---------------------------------------------------------------------------

// Deliberately not `deny_unknown_fields` since Spec 017 Phase 4: we are our own vendor, and a
// deployed `ciao update` refusing a manifest that grew a field is exactly the failure this
// whole spec exists to remove. Everything read is still validated below; what changed is only
// that a future field costs nothing. (Release metadata still rides the sibling `meta.json` —
// every binary in the field today runs the strict parser this comment replaces.)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReleaseManifest {
    pub v: u8,
    pub artifacts: Vec<ReleaseArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ReleaseArtifact {
    pub version: String,
    pub target: String,
    pub file: String,
    pub sha256: String,
    pub bytes: u64,
}

pub fn parse_manifest(bytes: &[u8]) -> Result<ReleaseManifest> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("release manifest exceeds {MAX_MANIFEST_BYTES} bytes");
    }
    let manifest: ReleaseManifest =
        serde_json::from_slice(bytes).context("release manifest is malformed")?;
    if manifest.v != 1 {
        bail!("release manifest has unsupported version {}", manifest.v);
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > MAX_MANIFEST_ARTIFACTS {
        bail!("release manifest artifact count is out of bounds");
    }
    for artifact in &manifest.artifacts {
        if !valid_release_version(&artifact.version)
            || artifact.target.len() > 64
            || artifact.file != archive_file_name(&artifact.version, &artifact.target)
            || decode_sha256_hex(&artifact.sha256).is_none()
            || artifact.bytes == 0
            || artifact.bytes > MAX_ARCHIVE_BYTES
        {
            bail!("release manifest contains an invalid artifact entry");
        }
    }
    Ok(manifest)
}

pub fn decode_sha256_hex(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk).ok()?;
        digest[index] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(digest)
}

// ---------------------------------------------------------------------------
// Bounded ustar archive validation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub name: String,
    pub executable: bool,
    pub data: Vec<u8>,
}

/// Parses an archive with a strict allowlist: exactly the `ciao` binary, the license/notice
/// texts, and `install.json`. Traversal, links, directories, unknown names, extra
/// executables, oversized entries, and malformed headers all fail closed (Spec 004 §9.2.4).
pub fn parse_release_archive(bytes: &[u8]) -> Result<Vec<ArchiveEntry>> {
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        bail!("archive exceeds {MAX_ARCHIVE_BYTES} bytes");
    }
    if !bytes.len().is_multiple_of(TAR_BLOCK) {
        bail!("archive is not block-aligned");
    }
    let mut entries: Vec<ArchiveEntry> = Vec::new();
    let mut offset = 0usize;
    loop {
        let Some(header) = bytes.get(offset..offset + TAR_BLOCK) else {
            bail!("archive ends without the terminating blocks");
        };
        if header.iter().all(|byte| *byte == 0) {
            // First zero block: require a second, then only zero padding to the end.
            let rest = &bytes[offset + TAR_BLOCK..];
            if rest.len() < TAR_BLOCK || !rest.iter().all(|byte| *byte == 0) {
                bail!("archive has malformed terminating blocks");
            }
            break;
        }
        verify_header_checksum(header)?;
        let magic = &header[257..263];
        if magic != b"ustar\0" && magic != b"ustar " {
            bail!("archive entry is not ustar");
        }
        let prefix = &header[345..500];
        if prefix.iter().any(|byte| *byte != 0) {
            bail!("archive entry uses a path prefix");
        }
        let name = read_header_string(&header[0..100])?;
        let type_flag = header[156];
        if !matches!(type_flag, b'0' | 0) {
            bail!("archive entry '{name}' is not a regular file");
        }
        if name.contains('/') || name.contains("..") || name.is_empty() {
            bail!("archive entry name is not a plain file name");
        }
        let mode = parse_octal(&header[100..108])?;
        let size = parse_octal(&header[124..136])?;
        let executable = mode & 0o111 != 0;
        let cap = entry_size_cap(&name)
            .ok_or_else(|| anyhow!("archive contains unexpected entry '{name}'"))?;
        if size > cap {
            bail!("archive entry '{name}' exceeds its size bound");
        }
        if (name == ARCHIVE_ENTRY_BINARY) != executable {
            bail!("archive entry '{name}' has unexpected executable permissions");
        }
        if entries.iter().any(|entry| entry.name == name) {
            bail!("archive entry '{name}' is duplicated");
        }
        let data_start = offset + TAR_BLOCK;
        let data_len = usize::try_from(size).context("entry size overflow")?;
        let padded = data_len.div_ceil(TAR_BLOCK) * TAR_BLOCK;
        let Some(data) = bytes.get(data_start..data_start + data_len) else {
            bail!("archive entry '{name}' is truncated");
        };
        entries.push(ArchiveEntry {
            name,
            executable,
            data: data.to_vec(),
        });
        offset = data_start + padded;
    }

    let mut expected: Vec<&str> = vec![ARCHIVE_ENTRY_BINARY, ARCHIVE_ENTRY_METADATA];
    expected.extend(ARCHIVE_TEXT_ENTRIES);
    if entries.len() != expected.len()
        || !expected
            .iter()
            .all(|name| entries.iter().any(|entry| entry.name == *name))
    {
        bail!("archive layout does not match the released layout");
    }
    Ok(entries)
}

fn entry_size_cap(name: &str) -> Option<u64> {
    if name == ARCHIVE_ENTRY_BINARY {
        Some(MAX_BINARY_BYTES)
    } else if name == ARCHIVE_ENTRY_METADATA {
        Some(MAX_METADATA_BYTES)
    } else if ARCHIVE_TEXT_ENTRIES.contains(&name) {
        Some(MAX_TEXT_BYTES)
    } else {
        None
    }
}

fn verify_header_checksum(header: &[u8]) -> Result<()> {
    let declared = parse_octal(&header[148..156])?;
    let mut sum: u64 = 0;
    for (index, byte) in header.iter().enumerate() {
        sum += if (148..156).contains(&index) {
            u64::from(b' ')
        } else {
            u64::from(*byte)
        };
    }
    if sum != declared {
        bail!("archive entry checksum mismatch");
    }
    Ok(())
}

fn read_header_string(field: &[u8]) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let text = std::str::from_utf8(&field[..end]).context("archive entry name is not UTF-8")?;
    Ok(text.to_string())
}

fn parse_octal(field: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(field)
        .context("archive header field is not ASCII")?
        .trim_end_matches(['\0', ' '])
        .trim_start_matches(' ');
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).context("archive header field is not octal")
}

// ---------------------------------------------------------------------------
// Install metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallMetadata {
    pub v: u8,
    pub version: String,
    pub target: String,
}

pub fn parse_install_metadata(bytes: &[u8]) -> Result<InstallMetadata> {
    let metadata: InstallMetadata =
        serde_json::from_slice(bytes).context("install.json is malformed")?;
    if metadata.v != 1 || !valid_release_version(&metadata.version) {
        bail!("install.json has unsupported contents");
    }
    Ok(metadata)
}

// ---------------------------------------------------------------------------
// Verified staging and atomic swap
// ---------------------------------------------------------------------------

/// Reads and fully verifies a local archive: size cap, declared digest, strict layout, and
/// install metadata matching the requested version and this machine's release target.
pub fn read_verified_archive(
    archive: &Path,
    expected_version: &str,
    expected_sha256: &[u8; 32],
) -> Result<Vec<ArchiveEntry>> {
    let target = current_release_target()
        .ok_or_else(|| anyhow!("this OS/architecture has no released Ciao artifact"))?;
    if !valid_release_version(expected_version) {
        bail!("the requested version is not a valid release version");
    }
    let metadata = fs::symlink_metadata(archive)
        .with_context(|| format!("inspect archive {}", archive.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("archive must be a regular file");
    }
    if metadata.len() > MAX_ARCHIVE_BYTES {
        bail!("archive exceeds {MAX_ARCHIVE_BYTES} bytes");
    }
    let mut bytes = Vec::new();
    fs::File::open(archive)?
        .take(MAX_ARCHIVE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        bail!("archive exceeds {MAX_ARCHIVE_BYTES} bytes");
    }

    // Spec 004 §9.2.3: the declared digest is verified before any extraction/parsing.
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if &digest != expected_sha256 {
        bail!("archive digest does not match the declared SHA-256");
    }

    let entries = parse_release_archive(&bytes)?;
    let metadata_entry = entries
        .iter()
        .find(|entry| entry.name == ARCHIVE_ENTRY_METADATA)
        .expect("layout validated");
    let install = parse_install_metadata(&metadata_entry.data)?;
    if install.version != expected_version {
        bail!(
            "archive is version {} but {} was requested",
            install.version,
            expected_version
        );
    }
    if install.target != target {
        bail!(
            "archive targets {} but this machine needs {target}",
            install.target
        );
    }
    Ok(entries)
}

/// Stages the verified binary beside the stable path, validates the staged binary's reported
/// version when requested, and atomically swaps it in, preserving exactly one previous binary
/// for rollback. Returns whether a previous binary now occupies the rollback slot.
pub fn stage_and_swap(
    paths: &CiaoPaths,
    entries: &[ArchiveEntry],
    expected_version: Option<&str>,
) -> Result<bool> {
    let directory = stable_binary_dir(paths);
    fs::create_dir_all(&directory).with_context(|| format!("create {}", directory.display()))?;
    let binary = entries
        .iter()
        .find(|entry| entry.name == ARCHIVE_ENTRY_BINARY)
        .ok_or_else(|| anyhow!("archive is missing the ciao binary"))?;

    let staged = directory.join(format!(".ciao.staged.{}", std::process::id()));
    let result = (|| -> Result<bool> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o700);
        {
            use std::io::Write as _;
            let mut file = options
                .open(&staged)
                .with_context(|| format!("stage binary in {}", directory.display()))?;
            file.write_all(&binary.data)?;
            file.sync_all()?;
        }
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))?;

        // Spec 004 §9.2.5: validate the staged binary before anything is replaced.
        if let Some(expected_version) = expected_version {
            verify_binary_version(&staged, expected_version)?;
        }

        let current = stable_binary_path(paths);
        let previous = rollback_binary_path(paths);
        let had_current = fs::symlink_metadata(&current).is_ok();
        if had_current {
            // One rollback slot: the outgoing binary replaces whatever was there before.
            let _ = fs::remove_file(&previous);
            fs::rename(&current, &previous)
                .with_context(|| format!("preserve previous binary at {}", previous.display()))?;
        }
        fs::rename(&staged, &current)
            .with_context(|| format!("install binary at {}", current.display()))?;
        fs::File::open(&directory)?.sync_all()?;
        Ok(had_current)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&staged);
    }
    result
}

/// Restores the rollback slot after a failed post-install health check (Spec 004 §9.2.8).
/// The failed binary is discarded; identity and pairing state are untouched.
pub fn restore_previous(paths: &CiaoPaths) -> Result<()> {
    let current = stable_binary_path(paths);
    let previous = rollback_binary_path(paths);
    if fs::symlink_metadata(&previous).is_err() {
        bail!("no previous Ciao binary is available to restore");
    }
    let _ = fs::remove_file(&current);
    fs::rename(&previous, &current)
        .with_context(|| format!("restore previous binary to {}", current.display()))?;
    Ok(())
}

/// Swaps the installed and rollback binaries for an explicit operator rollback (§9.3).
pub fn swap_with_previous(paths: &CiaoPaths) -> Result<()> {
    let current = stable_binary_path(paths);
    let previous = rollback_binary_path(paths);
    if fs::symlink_metadata(&previous).is_err() {
        bail!("no previous Ciao binary is available to roll back to");
    }
    if fs::symlink_metadata(&current).is_err() {
        bail!("no installed Ciao binary exists at the stable path");
    }
    let temporary = stable_binary_dir(paths).join(format!(".ciao.swap.{}", std::process::id()));
    fs::rename(&current, &temporary)?;
    fs::rename(&previous, &current)?;
    fs::rename(&temporary, &previous)?;
    Ok(())
}

/// Runs the staged/installed binary's `--version` with fixed argv and checks the exact
/// version token (Spec 004 §9.2.5). Output is bounded before parsing.
pub fn verify_binary_version(binary: &Path, expected_version: &str) -> Result<()> {
    let output = Command::new(binary)
        .arg("--version")
        .output()
        .with_context(|| format!("run {} --version", binary.display()))?;
    if !output.status.success() || output.stdout.len() > 256 {
        bail!("installed binary did not report a version");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let reported = text.trim().rsplit(' ').next().unwrap_or_default();
    if reported != expected_version {
        bail!("installed binary reports version {reported}, expected {expected_version}");
    }
    Ok(())
}

/// Refuses while a restart would destroy work, and only then (Spec 005 §8.3, amended
/// 2026-07-30).
///
/// A live terminal loses its PTY and a live managed worker is stopped, so both are refused. An
/// attached session is not: its agent runs in the operator's own terminal, Ciao has no code path
/// that signals it, and the restart drops only the observation, which re-registers on the next
/// event. Counting it refused nearly every update on a host that is being actively used —
/// including every update from the phone, where an attached session is the reason you are
/// there. A refusal that fires when nothing is at stake is one the operator learns to work
/// around, and then works around on the day a managed worker really is running.
pub fn refuse_if_active_work(
    active_terminals: Option<usize>,
    resumable_terminals: Option<usize>,
) -> Result<()> {
    // A terminal attached to tmux or Herdr is not work a restart ends: the session keeps running
    // without Ciao and the phone reattaches to it. Refusing on those made the installer
    // unreachable from the app that is the product — the terminal in the way was the one the
    // operator was typing the command into. What remains is the plain login shells, which do die.
    // A live managed session used to refuse here too. It no longer does: a restarting daemon
    // stores the conversation with its history and the installer resumes it afterwards, so the
    // remedy — stop each one by hand, update, start them again — was work the installer could
    // do itself. What is left is the plain login shells, which nothing can carry across.
    let terminals = active_terminals
        .unwrap_or(0)
        .saturating_sub(resumable_terminals.unwrap_or(0));
    if terminals == 0 {
        return Ok(());
    }
    bail!(
        "Ciao has {terminals} plain shell terminal(s). A restart would end that work, so the installer stopped. To continue, close the terminal(s), then retry."
    )
}

/// Backward-compatible policy helper retained for existing Phase 3 callers/tests.
pub fn refuse_if_terminal_active(active_terminals: Option<usize>) -> Result<()> {
    refuse_if_active_work(active_terminals, None)
}

/// Downloads `ciao-<version>-<target>.tar` from an explicitly supplied HTTPS release base
/// using fixed argv with size and time bounds. There is no default or hardcoded origin.
pub fn fetch_archive(
    release_base: &str,
    version: &str,
    target: &str,
    dest: &Path,
    expected_bytes: Option<u64>,
) -> Result<()> {
    fetch_release_file(
        release_base,
        &archive_file_name(version, target),
        dest,
        expected_bytes,
    )
}

/// Downloads one named file from an explicitly supplied HTTPS release base. Same bounds and
/// same fixed argv as an archive download, because a manifest arrives from the same untrusted
/// place and gets read before anything has been verified. The caller supplies the origin; this
/// still has none of its own.
pub fn fetch_release_file(
    release_base: &str,
    file_name: &str,
    dest: &Path,
    expected_bytes: Option<u64>,
) -> Result<()> {
    if !release_base.starts_with("https://")
        || release_base
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'\\'))
    {
        bail!("the release base must be a plain https:// URL");
    }
    let url = format!("{}/{}", release_base.trim_end_matches('/'), file_name);
    // curl stays silent and the progress is drawn here instead. Its own `--progress-bar` is a
    // 200-character wall of `#`, and its default meter is a table of seven columns nobody reads
    // — neither belongs next to output that otherwise says `Creating host identity… done`.
    //
    // ponytail: the growing file is the progress. curl is already writing to a path we chose and
    // the manifest already told us the exact byte count, so watching the size costs one `metadata`
    // call per tick and no protocol at all.
    let mut child = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            &DOWNLOAD_MAX_SECONDS.to_string(),
            "--max-filesize",
            &MAX_ARCHIVE_BYTES.to_string(),
            "--output",
        ])
        .arg(dest)
        .arg(&url)
        .stderr(Stdio::piped())
        .spawn()
        .context("execute curl")?;

    // Nothing is drawn without an expected size: the release manifest is half a kilobyte and
    // would flash a mark for one frame, and `install.sh` pipes this into a shell where a meter
    // is noise in a log.
    let mut line = ProgressLine::new(expected_bytes.is_some());
    loop {
        if let Some(status) = child.try_wait().context("wait for curl")? {
            line.clear();
            if !status.success() {
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    let _ = pipe.read_to_string(&mut stderr);
                }
                bail!("download failed: {}", stderr.trim());
            }
            return Ok(());
        }
        let read = fs::metadata(dest).map(|meta| meta.len()).unwrap_or(0);
        line.draw(&download_label(read, expected_bytes));
        std::thread::sleep(std::time::Duration::from_millis(90));
    }
}

/// `⠹  38%  8.1/21.4 MiB` — the share done first, because that is the only part anyone reads
/// while waiting, and the byte counts second for when a stalled transfer needs proving.
fn download_label(read: u64, total: Option<u64>) -> String {
    match total {
        // Both numbers carry the total's unit, and only the total prints it: `10.2/20.4 MiB`
        // rather than `10.2 MiB/20.4 MiB`, which says the same thing twice in a line that is
        // being redrawn ten times a second.
        Some(total) if total > 0 => {
            let read = read.min(total);
            format!(
                "{:>3}%  {}/{}",
                (read * 100) / total,
                scaled_to(read, total),
                human_bytes(total)
            )
        }
        _ => human_bytes(read),
    }
}

const MIB: u64 = 1024 * 1024;

/// `bytes` in whatever unit `reference` prints in, without the suffix.
fn scaled_to(bytes: u64, reference: u64) -> String {
    if reference >= MIB {
        format!("{:.1}", bytes as f64 / MIB as f64)
    } else {
        format!("{}", bytes / 1024)
    }
}

fn human_bytes(bytes: u64) -> String {
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{} KiB", bytes / 1024)
    }
}

/// One line of self-erasing terminal output, drawn after whatever label the caller already
/// printed.
///
/// ponytail: backspaces rather than a carriage return, so it appends to `Downloading Ciao
/// 0.1.20… ` instead of erasing it. That keeps every existing `print!("…")` / `println!("done")`
/// caller working untouched, which a line-rewriting renderer would have needed rewritten. Every
/// frame it draws is ASCII or a single-width braille cell, so counting chars counts columns.
pub(crate) struct ProgressLine {
    drawn: usize,
    frame: usize,
    watched: bool,
}

impl ProgressLine {
    const MARKS: [char; 10] = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

    pub(crate) fn new(wanted: bool) -> Self {
        Self {
            drawn: 0,
            frame: 0,
            watched: wanted && std::io::stdout().is_terminal(),
        }
    }

    /// Draws the next spinner mark followed by `text`, erasing whatever the previous call left.
    pub(crate) fn draw(&mut self, text: &str) {
        if !self.watched {
            return;
        }
        use std::io::Write as _;
        let mark = Self::MARKS[self.frame % Self::MARKS.len()];
        let rendered = if text.is_empty() {
            mark.to_string()
        } else {
            format!("{mark}  {text}")
        };
        let mut out = std::io::stdout();
        let _ = write!(
            out,
            "{}{}",
            "\u{8}".repeat(self.drawn) + &" ".repeat(self.drawn) + &"\u{8}".repeat(self.drawn),
            rendered
        );
        let _ = out.flush();
        self.drawn = rendered.chars().count();
        self.frame += 1;
    }

    /// Leaves the cursor exactly where the caller's label left it, so a following `done` lands
    /// where it always did whether or not anything was ever drawn.
    pub(crate) fn clear(&mut self) {
        if !self.watched || self.drawn == 0 {
            return;
        }
        use std::io::Write as _;
        let mut out = std::io::stdout();
        let blank =
            "\u{8}".repeat(self.drawn) + &" ".repeat(self.drawn) + &"\u{8}".repeat(self.drawn);
        let _ = write!(out, "{blank}");
        let _ = out.flush();
        self.drawn = 0;
    }
}

/// The same mark, for a stretch of work that blocks the caller and so cannot tick one itself:
/// verifying an archive, swapping a binary, bootstrapping the service. It owns the line from
/// `start` until it is dropped, so nothing else may print in between.
///
/// ponytail: the spinner moves to a thread rather than the work, which keeps wrapping a step to
/// two lines and works across `await` as well as a blocking call. Dropping erases the mark on
/// the `?` path out too, so no caller has to remember.
pub(crate) struct Spinner {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Spinner {
    pub(crate) fn start() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            let mut line = ProgressLine::new(true);
            while !flag.load(Ordering::Relaxed) {
                line.draw("");
                std::thread::sleep(std::time::Duration::from_millis(90));
            }
            line.clear();
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    pub(crate) fn tar_entry(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; TAR_BLOCK];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(format!("{mode:07o}").as_bytes());
        header[108..115].copy_from_slice(b"0000000");
        header[116..123].copy_from_slice(b"0000000");
        header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        header[136..147].copy_from_slice(b"00000000000");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let mut sum: u64 = 0;
        for (index, byte) in header.iter().enumerate() {
            sum += if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            };
        }
        header[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
        header[154] = 0;
        header[155] = b' ';
        let mut bytes = header.to_vec();
        bytes.extend_from_slice(data);
        bytes.resize(bytes.len().div_ceil(TAR_BLOCK) * TAR_BLOCK, 0);
        bytes
    }

    pub(crate) fn build_archive(entries: &[(&str, u32, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (name, mode, data) in entries {
            bytes.extend_from_slice(&tar_entry(name, *mode, data));
        }
        bytes.extend_from_slice(&[0u8; TAR_BLOCK * 2]);
        bytes
    }

    pub(crate) fn golden_entries(version: &str, target: &str) -> Vec<(&'static str, u32, Vec<u8>)> {
        vec![
            ("ciao", 0o755, b"#!/bin/sh\necho ciao-binary\n".to_vec()),
            ("LICENSE-MIT", 0o644, b"MIT".to_vec()),
            ("LICENSE-APACHE", 0o644, b"Apache-2.0".to_vec()),
            ("THIRD-PARTY-NOTICES.md", 0o644, b"# Notices".to_vec()),
            (
                "install.json",
                0o644,
                format!("{{\"v\":1,\"version\":\"{version}\",\"target\":\"{target}\"}}")
                    .into_bytes(),
            ),
        ]
    }

    fn write_archive(dir: &Path, entries: &[(&str, u32, Vec<u8>)]) -> (PathBuf, [u8; 32]) {
        let bytes = build_archive(entries);
        let path = dir.join("release.tar");
        fs::write(&path, &bytes).unwrap();
        (path, Sha256::digest(&bytes).into())
    }

    fn target() -> &'static str {
        current_release_target().expect("test host is a release target")
    }

    #[test]
    fn golden_archive_verifies_and_hostile_variants_fail_closed() {
        let temp = tempdir().unwrap();
        let golden = golden_entries("0.2.0", target());
        let (path, digest) = write_archive(temp.path(), &golden);
        let entries = read_verified_archive(&path, "0.2.0", &digest).unwrap();
        assert_eq!(entries.len(), 5);
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == "ciao" && entry.executable)
        );

        // Wrong digest fails before parsing.
        assert!(
            read_verified_archive(&path, "0.2.0", &[0u8; 32])
                .unwrap_err()
                .to_string()
                .contains("digest")
        );

        // Wrong requested version fails after metadata validation.
        assert!(read_verified_archive(&path, "0.3.0", &digest).is_err());

        // Traversal, links, extra entries, extra executables, and oversized entries fail.
        let traversal = build_archive(&[("../ciao", 0o755, b"x".to_vec())]);
        assert!(parse_release_archive(&traversal).is_err());
        let nested = build_archive(&[("bin/ciao", 0o755, b"x".to_vec())]);
        assert!(parse_release_archive(&nested).is_err());

        let mut link = tar_entry("ciao", 0o755, b"");
        link[156] = b'2';
        // Fix the checksum for the modified type flag.
        let mut sum: u64 = 0;
        for (index, byte) in link[..TAR_BLOCK].iter().enumerate() {
            sum += if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            };
        }
        link[148..154].copy_from_slice(format!("{sum:06o}").as_bytes());
        let mut link_archive = link;
        link_archive.extend_from_slice(&[0u8; TAR_BLOCK * 2]);
        assert!(parse_release_archive(&link_archive).is_err());

        let mut extra = golden.clone();
        extra.push(("evil.sh", 0o755, b"#!/bin/sh\n".to_vec()));
        assert!(parse_release_archive(&build_archive(&extra)).is_err());

        let mut nonexec_binary = golden.clone();
        nonexec_binary[0].1 = 0o644;
        assert!(parse_release_archive(&build_archive(&nonexec_binary)).is_err());

        let mut exec_license = golden.clone();
        exec_license[1].1 = 0o755;
        assert!(parse_release_archive(&build_archive(&exec_license)).is_err());

        let mut oversized = golden.clone();
        oversized[4].2 = vec![b'x'; MAX_METADATA_BYTES as usize + 1];
        assert!(parse_release_archive(&build_archive(&oversized)).is_err());

        let mut missing = golden.clone();
        missing.pop();
        assert!(parse_release_archive(&build_archive(&missing)).is_err());

        let mut duplicated = golden.clone();
        duplicated.push(("ciao", 0o755, b"again".to_vec()));
        assert!(parse_release_archive(&build_archive(&duplicated)).is_err());

        // A corrupted checksum is rejected.
        let mut corrupt = build_archive(&golden);
        corrupt[0] ^= 0x01;
        assert!(parse_release_archive(&corrupt).is_err());
    }

    #[test]
    fn stage_swap_preserves_one_rollback_slot_and_state_files() {
        let temp = tempdir().unwrap();
        let paths = CiaoPaths::for_home(temp.path());
        paths.ensure_layout().unwrap();
        // Identity/pairing stand-ins that the installer must never touch.
        crate::storage::atomic_write_private(&paths.credentials_file, b"{\"secret\":true}")
            .unwrap();
        crate::storage::atomic_write_private(&paths.paired_devices_file, b"{\"v\":1}").unwrap();

        let versions = ["one", "two", "three"];
        for (index, marker) in versions.iter().enumerate() {
            let entries = vec![ArchiveEntry {
                name: ARCHIVE_ENTRY_BINARY.into(),
                executable: true,
                data: marker.as_bytes().to_vec(),
            }];
            let had_previous = stage_and_swap(&paths, &entries, None).unwrap();
            assert_eq!(had_previous, index > 0);
        }
        assert_eq!(fs::read(stable_binary_path(&paths)).unwrap(), b"three");
        assert_eq!(fs::read(rollback_binary_path(&paths)).unwrap(), b"two");
        let mode = fs::metadata(stable_binary_path(&paths))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);

        // Explicit rollback swaps the two slots and allows roll-forward.
        swap_with_previous(&paths).unwrap();
        assert_eq!(fs::read(stable_binary_path(&paths)).unwrap(), b"two");
        assert_eq!(fs::read(rollback_binary_path(&paths)).unwrap(), b"three");

        // Health-failure restore discards the failed binary and recovers the previous one.
        restore_previous(&paths).unwrap();
        assert_eq!(fs::read(stable_binary_path(&paths)).unwrap(), b"three");
        assert!(fs::symlink_metadata(rollback_binary_path(&paths)).is_err());
        assert!(restore_previous(&paths).is_err());

        // Identity/pairing files were preserved byte for byte.
        assert_eq!(
            fs::read(&paths.credentials_file).unwrap(),
            b"{\"secret\":true}"
        );
        assert_eq!(fs::read(&paths.paired_devices_file).unwrap(), b"{\"v\":1}");
    }

    #[test]
    fn staged_binary_version_check_is_exact() {
        let temp = tempdir().unwrap();
        let script = temp.path().join("fake-ciao");
        fs::write(&script, "#!/bin/sh\necho \"ciao 0.2.0\"\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        verify_binary_version(&script, "0.2.0").unwrap();
        assert!(verify_binary_version(&script, "0.2.1").is_err());

        // A staged binary reporting the wrong version aborts before any replacement.
        let paths = CiaoPaths::for_home(temp.path().join("home"));
        let entries = vec![ArchiveEntry {
            name: ARCHIVE_ENTRY_BINARY.into(),
            executable: true,
            data: fs::read(&script).unwrap(),
        }];
        assert!(stage_and_swap(&paths, &entries, Some("9.9.9")).is_err());
        assert!(fs::symlink_metadata(stable_binary_path(&paths)).is_err());
        assert!(stage_and_swap(&paths, &entries, Some("0.2.0")).is_ok());
        assert!(fs::symlink_metadata(stable_binary_path(&paths)).is_ok());
    }

    #[test]
    fn active_work_refusal_and_version_grammar() {
        assert!(refuse_if_terminal_active(None).is_ok());
        assert!(refuse_if_active_work(Some(0), None).is_ok());
        assert!(refuse_if_active_work(Some(1), None).is_err());
        // Unknown counts are not evidence of work, and an unreachable daemon has none anyway.
        assert!(refuse_if_active_work(None, None).is_ok());

        // A terminal attached to tmux or Herdr survives the restart, so it is not in the way.
        // This is the case that made the installer unreachable from the app itself: the only
        // terminal open was the one the operator was typing `ciao update` into.
        assert!(refuse_if_active_work(Some(1), Some(1)).is_ok());
        assert!(refuse_if_active_work(Some(3), Some(3)).is_ok());
        // A plain shell alongside them still is.
        assert!(refuse_if_active_work(Some(2), Some(1)).is_err());
        // A daemon too old to report the subset refuses exactly as it did before.
        assert!(refuse_if_active_work(Some(1), None).is_err());
        // More resumable than active cannot happen, but must not underflow into a refusal.
        assert!(refuse_if_active_work(Some(1), Some(2)).is_ok());

        // The message names what is in the way; "active work" alone sent the operator looking.
        let terminal = refuse_if_active_work(Some(2), None)
            .unwrap_err()
            .to_string();
        assert!(terminal.contains("2 plain shell terminal(s)"), "{terminal}");
        assert!(terminal.contains("close the terminal(s)"), "{terminal}");
        // A live managed chat is no longer an obstacle — the installer resumes it — so no
        // refusal may send anyone to `ciao agent stop` before updating again.
        assert!(!terminal.contains("managed"), "{terminal}");
        assert!(!terminal.contains("ciao agent stop"), "{terminal}");

        assert!(valid_release_version("0.2.0"));
        assert!(valid_release_version("1.0.0-alpha.2"));
        assert!(!valid_release_version(""));
        assert!(!valid_release_version("v0.2.0"));
        assert!(!valid_release_version("0.2.0 "));
        assert!(!valid_release_version(&"9".repeat(33)));
    }

    #[test]
    fn python_packaged_golden_fixture_parses_with_the_strict_reader() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/fixtures/phase3/release-archive-golden.tar"
        );
        let bytes = fs::read(path).unwrap();
        let entries = parse_release_archive(&bytes).unwrap();
        assert_eq!(entries.len(), 5);
        assert!(
            entries
                .iter()
                .any(|entry| entry.name == "ciao" && entry.executable)
        );
        let metadata = entries
            .iter()
            .find(|entry| entry.name == ARCHIVE_ENTRY_METADATA)
            .unwrap();
        let install = parse_install_metadata(&metadata.data).unwrap();
        assert_eq!(install.version, "9.9.9-fixture");
        assert_eq!(install.target, "x86_64-unknown-linux-gnu");
    }

    #[test]
    fn manifest_parsing_is_bounded_and_tolerant_of_growth() {
        let target = target();
        let good = format!(
            "{{\"v\":1,\"artifacts\":[{{\"version\":\"0.2.0\",\"target\":\"{target}\",\"file\":\"ciao-0.2.0-{target}.tar\",\"sha256\":\"{}\",\"bytes\":42}}]}}",
            "ab".repeat(32)
        );
        let manifest = parse_manifest(good.as_bytes()).unwrap();
        assert_eq!(manifest.artifacts.len(), 1);

        // Spec 017 Phase 4: a manifest that grew a field parses — we are our own vendor, and a
        // deployed updater refusing tomorrow's metadata was this suite's must-refuse case
        // until it became the exact failure the spec removes. The flip is deliberate.
        let widened = good.replace("\"bytes\":42", "\"bytes\":42,\"field_from_the_future\":1");
        assert_eq!(parse_manifest(widened.as_bytes()).unwrap(), manifest);
        let widened_top = good.replace("{\"v\":1", "{\"v\":1,\"meta_from_the_future\":{}");
        assert_eq!(parse_manifest(widened_top.as_bytes()).unwrap(), manifest);

        for bad in [
            "{\"v\":2,\"artifacts\":[]}".to_string(),
            "{\"v\":1,\"artifacts\":[]}".to_string(),
            good.replace("ciao-0.2.0", "ciao-9.9.9"),
            good.replace(&"ab".repeat(32), "zz"),
        ] {
            assert!(parse_manifest(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn release_base_must_be_plain_https() {
        let temp = tempdir().unwrap();
        let dest = temp.path().join("out.tar");
        for bad in [
            "http://example.invalid",
            "https://example.invalid/\"x",
            "https://example.invalid/ space",
            "file:///etc",
        ] {
            assert!(fetch_archive(bad, "0.2.0", "aarch64-apple-darwin", &dest, None).is_err());
        }
    }

    /// The progress text is the whole feature, and it is the one part of it that can be checked
    /// without a terminal — the drawing itself is suppressed unless stdout is one.
    #[test]
    fn download_progress_reads_as_a_share_done_and_never_exceeds_the_total() {
        let total = Some(21_422_080);
        assert_eq!(download_label(0, total), "  0%  0.0/20.4 MiB");
        assert_eq!(download_label(10_711_040, total), " 50%  10.2/20.4 MiB");
        assert_eq!(download_label(21_422_080, total), "100%  20.4/20.4 MiB");
        // curl can write past the declared size if a manifest is stale. A percentage over 100
        // reads as a bug in Ciao rather than a stale manifest, so both halves are clamped.
        assert_eq!(download_label(99_999_999, total), "100%  20.4/20.4 MiB");
        // No declared total is the `--sha256` case: count bytes, claim no share.
        assert_eq!(download_label(2_097_152, None), "2.0 MiB");
        // A zero total would divide by zero rather than print anything useful.
        assert_eq!(download_label(1024, Some(0)), "1 KiB");
    }

    /// Nothing may reach a captured stdout: `install.sh` pipes this into a shell, and CI keeps
    /// the log. `new(false)` is the release-manifest case, which has no size to report.
    #[test]
    fn progress_draws_nothing_when_it_was_not_asked_for() {
        let mut line = ProgressLine::new(false);
        line.draw("50%");
        line.clear();
        assert!(!line.watched);
        assert_eq!(line.drawn, 0);
    }

    /// A spinner that outlived its step would scribble marks across whatever printed next, and
    /// one whose thread never joined would hang the install it was decorating. This test hangs
    /// rather than fails if the join stops working, which is the louder of the two.
    #[test]
    fn spinner_stops_and_joins_when_dropped() {
        let spinner = Spinner::start();
        let stop = Arc::clone(&spinner.stop);
        drop(spinner);
        assert!(stop.load(Ordering::Relaxed));
    }
}
