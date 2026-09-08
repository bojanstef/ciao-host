use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::{fs::MetadataExt, fs::OpenOptionsExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, anyhow, bail};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};

use crate::{
    host_protocol::{
        MAX_LIVE_ACTIVITY_SELECTIONS, valid_live_activity_session_id, valid_push_ticket,
    },
    protocol::base64url,
    qr::decode_exact,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Per-user filesystem layout behind the narrow host-platform boundary (Spec 004 §8.1).
///
/// macOS keeps the accepted Library layout and launchd plist untouched. Linux uses XDG config,
/// state, and runtime directories plus a per-user systemd unit. Everything above this struct is
/// platform-neutral and must not sprinkle `cfg(target_os)` checks of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiaoPaths {
    pub home: PathBuf,
    /// Configuration directory (`config.json`).
    pub support_dir: PathBuf,
    /// Secret/state directory (`credentials.json`, `paired-devices.json`). Same as
    /// `support_dir` on macOS.
    pub state_dir: PathBuf,
    pub config_file: PathBuf,
    pub credentials_file: PathBuf,
    pub paired_devices_file: PathBuf,
    /// Metadata-only Agent Session identity/receipt store. It never contains timeline content.
    pub agent_metadata_file: PathBuf,
    /// Metadata-only managed-session lifecycle/ownership store (Spec 006 §8.3). A separate file
    /// so a pre-006 host rolls back cleanly without ever reading it.
    pub agent_managed_file: PathBuf,
    /// Ciao-owned prefix holding the digest-verified pinned Agent SDK. Ciao never
    /// redistributes it; `ciao agent install claude` fetches it here.
    pub managed_sdk_prefix: PathBuf,
    /// Ciao-owned managed worker entrypoint installed alongside the SDK prefix.
    pub managed_worker_entrypoint: PathBuf,
    pub run_dir: PathBuf,
    pub socket_file: PathBuf,
    /// Same-user full-duplex socket used only by the attached agent bridge.
    pub agent_socket_file: PathBuf,
    pub logs_dir: PathBuf,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    /// launchd LaunchAgents directory on macOS; systemd user-unit directory on Linux.
    pub service_dir: PathBuf,
    pub service_file: PathBuf,
}

impl CiaoPaths {
    pub fn discover() -> Result<Self> {
        let home = env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("HOME is not set; cannot locate Ciao's per-user files"))?;
        #[cfg(target_os = "linux")]
        return Ok(Self::for_linux_home(
            home,
            env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
            env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from),
        ));
        #[cfg(not(target_os = "linux"))]
        Ok(Self::for_home(home))
    }

    /// The accepted macOS layout, unchanged for backward compatibility.
    pub fn for_home(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let support_dir = home.join("Library/Application Support/Ciao");
        let run_dir = support_dir.join("run");
        let logs_dir = home.join("Library/Logs/Ciao");
        let service_dir = home.join("Library/LaunchAgents");
        Self {
            config_file: support_dir.join("config.json"),
            credentials_file: support_dir.join("credentials.json"),
            paired_devices_file: support_dir.join("paired-devices.json"),
            agent_metadata_file: support_dir.join("agent-metadata.json"),
            agent_managed_file: support_dir.join("agent-managed.json"),
            managed_sdk_prefix: support_dir.join("managed/claude-sdk"),
            managed_worker_entrypoint: support_dir.join("managed/worker.mjs"),
            socket_file: run_dir.join("ciao.sock"),
            agent_socket_file: run_dir.join("agent.sock"),
            stdout_log: logs_dir.join("daemon.stdout.log"),
            stderr_log: logs_dir.join("daemon.stderr.log"),
            service_file: service_dir.join("app.ciaooo.ciao.daemon.plist"),
            state_dir: support_dir.clone(),
            home,
            support_dir,
            run_dir,
            logs_dir,
            service_dir,
        }
    }

    /// The Linux XDG layout (Spec 004 §8.1). An XDG variable is honored only when it is an
    /// absolute path; anything else falls back to the documented HOME default. There is never a
    /// current-directory or `/tmp` fallback.
    pub fn for_linux_home(
        home: impl Into<PathBuf>,
        xdg_config_home: Option<PathBuf>,
        xdg_state_home: Option<PathBuf>,
        xdg_runtime_dir: Option<PathBuf>,
    ) -> Self {
        let home = home.into();
        let config_base = valid_xdg(xdg_config_home).unwrap_or_else(|| home.join(".config"));
        let state_base = valid_xdg(xdg_state_home).unwrap_or_else(|| home.join(".local/state"));
        let support_dir = config_base.join("ciao");
        let state_dir = state_base.join("ciao");
        // The socket lives under the state directory, not XDG_RUNTIME_DIR (Spec 004 §8.1).
        // Its path has to be stable for the daemon's whole life and identical for every
        // client, and the runtime directory is neither: a cron-started daemon has no
        // XDG_RUNTIME_DIR while the operator's shell does, so they bound and looked up
        // different sockets and the CLI called a healthy daemon unreachable. Deriving it from
        // the uid instead does not help, because /run/user/<uid> appears and disappears with
        // the user manager. A stale socket after reboot is handled at bind time.
        let _ = xdg_runtime_dir;
        let run_dir = state_dir.join("run");
        let logs_dir = state_dir.join("logs");
        let service_dir = config_base.join("systemd/user");
        Self {
            config_file: support_dir.join("config.json"),
            credentials_file: state_dir.join("credentials.json"),
            paired_devices_file: state_dir.join("paired-devices.json"),
            agent_metadata_file: state_dir.join("agent-metadata.json"),
            agent_managed_file: state_dir.join("agent-managed.json"),
            managed_sdk_prefix: state_dir.join("managed/claude-sdk"),
            managed_worker_entrypoint: state_dir.join("managed/worker.mjs"),
            socket_file: run_dir.join("ciao.sock"),
            agent_socket_file: run_dir.join("agent.sock"),
            stdout_log: logs_dir.join("daemon.stdout.log"),
            stderr_log: logs_dir.join("daemon.stderr.log"),
            service_file: service_dir.join("ciao.service"),
            home,
            support_dir,
            state_dir,
            run_dir,
            logs_dir,
            service_dir,
        }
    }

    pub fn ensure_layout(&self) -> Result<()> {
        ensure_private_directory(&self.support_dir)?;
        ensure_private_directory(&self.state_dir)?;
        ensure_private_directory(&self.run_dir)?;
        ensure_private_directory(&self.logs_dir)?;
        fs::create_dir_all(&self.service_dir)
            .with_context(|| format!("create service directory {}", self.service_dir.display()))?;
        Ok(())
    }

    /// Where a person should look when the daemon misbehaves, phrased per platform.
    ///
    /// Names the stdout log, because that is where the daemon's tracing actually goes. This
    /// pointed at stderr for its whole life, and stderr only ever receives a panic — so every
    /// person sent here by a failure message opened an empty file and learned nothing.
    pub fn log_hint(&self) -> String {
        if cfg!(target_os = "linux") {
            "`journalctl --user -u ciao.service`".to_string()
        } else {
            format!("'{}'", self.stdout_log.display())
        }
    }
}

/// Spec 004 §8.1: XDG variables are honored only when absolute; a relative, empty, or otherwise
/// hostile value falls back to the HOME default.
fn valid_xdg(value: Option<PathBuf>) -> Option<PathBuf> {
    value.filter(|path| path.is_absolute())
}

pub fn ensure_private_directory(path: &Path) -> Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        bail!("refusing to use symlinked directory {}", path.display());
    }
    fs::create_dir_all(path).with_context(|| format!("create directory {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    if !metadata.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set permissions on {}", path.display()))?;
    Ok(())
}

pub fn validate_private_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect security of {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("{} must be a regular file, not a symlink", path.display());
    }
    let expected_uid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != expected_uid {
        bail!(
            "{} is owned by uid {}, expected {}; restore ownership before retrying",
            path.display(),
            metadata.uid(),
            expected_uid
        );
    }
    let mode = metadata.mode() & 0o777;
    if mode != 0o600 {
        bail!(
            "{} has insecure permissions {:03o}; run `chmod 600 '{}'` and retry",
            path.display(),
            mode,
            path.display()
        );
    }
    if metadata.nlink() != 1 {
        bail!("{} must not have hard links", path.display());
    }
    Ok(())
}

pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("{} has an invalid filename", path.display()))?;
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(".{name}.tmp.{}.{sequence}", std::process::id()));

    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create secure temporary file in {}", parent.display()))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)
            .with_context(|| format!("atomically replace {}", path.display()))?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveActivitySelection {
    pub session_id: String,
    pub adapter: String,
    pub workspace: String,
}

impl LiveActivitySelection {
    pub fn validate(&self) -> Result<()> {
        if !valid_live_activity_session_id(&self.session_id)
            || self.adapter.is_empty()
            || self.adapter.len() > 32
            || !self.adapter.bytes().all(|byte| byte.is_ascii_graphic())
            || !valid_live_activity_label(&self.workspace, 64)
        {
            bail!("live activity selection is malformed");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveActivityRegistration {
    pub ticket: String,
    pub selections: Vec<LiveActivitySelection>,
}

impl LiveActivityRegistration {
    fn validate(&self) -> Result<()> {
        if !valid_push_ticket(&self.ticket)
            || self.selections.is_empty()
            || self.selections.len() > MAX_LIVE_ACTIVITY_SELECTIONS
        {
            bail!("live activity registration is malformed");
        }
        let mut seen = std::collections::BTreeSet::new();
        for selection in &self.selections {
            selection.validate()?;
            if !seen.insert(&selection.session_id) {
                bail!("live activity registration contains a duplicate session");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveActivitySelectionChange {
    Add(LiveActivitySelection),
    Remove(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveActivityTarget {
    pub endpoint_id: String,
    pub ticket: String,
    pub key: [u8; 32],
    pub selections: Vec<LiveActivitySelection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedDevice {
    pub endpoint_id: String,
    pub paired_at: u64,
    pub transcript_hash: String,
    /// ADR 005 notification key, agreed at pairing. Secret — this is why the file is 0600 and
    /// `validate_private_file` refuses anything looser. `None` for devices paired before the
    /// key existed: they keep working for terminals and Agent Sessions, and are simply
    /// ineligible for notifications until they re-pair.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_key: Option<String>,
    /// ADR 005 push ticket: the relay's sealed handle on this device, handed over the
    /// authenticated Iroh channel after pairing. Opaque to the host, which only forwards it.
    ///
    /// Its presence here is also what makes unpairing revoke: `ciao reset` deletes this file, and
    /// nothing else on the host can reach the phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub push_ticket: Option<String>,
    /// Spec 018 per-host ActivityKit registration. Independent of the alert ticket: ending an
    /// activity must never turn permission alerts off, and APNS invalidates the two token kinds
    /// independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_activity: Option<LiveActivityRegistration>,
}

// Nothing on this file's read path denies unknown fields, deliberately, and re-adding it would be
// a regression rather than a tightening. `ciao update --rollback` is a shipped command, so the
// binary that wrote this file is routinely newer than the binary reading it — and a rejected parse
// here is not a degraded read, it is a daemon that will not start. Spec 018's `live_activity` field
// did precisely that to an older host. Every field this code depends on is checked by name in
// `load`; refusing the ones it has never heard of protects nothing.
// Fenced by `a_file_written_by_a_newer_host_still_loads`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PairedDevicesFile {
    v: u8,
    devices: Vec<PairedDevice>,
}

#[derive(Debug)]
pub struct PairedDeviceStore {
    path: PathBuf,
    devices: Vec<PairedDevice>,
}

impl PairedDeviceStore {
    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let encoded = serde_json::to_vec_pretty(&PairedDevicesFile {
                    v: 1,
                    devices: Vec::new(),
                })?;
                atomic_write_private(&path, &encoded)?;
                return Ok(Self {
                    path,
                    devices: Vec::new(),
                });
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", path.display()));
            }
            Ok(_) => {}
        }
        validate_private_file(&path)?;
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let file: PairedDevicesFile = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "{} is malformed; restore or remove it explicitly",
                path.display()
            )
        })?;
        if file.v != 1 {
            bail!("{} has unsupported version {}", path.display(), file.v);
        }
        let mut seen = std::collections::BTreeSet::new();
        for device in &file.devices {
            validate_endpoint_id(&device.endpoint_id)?;
            if decode_exact::<32>(&device.transcript_hash).is_none() {
                bail!("{} contains an invalid transcript hash", path.display());
            }
            if device
                .notification_key
                .as_deref()
                .is_some_and(|key| decode_exact::<32>(key).is_none())
            {
                bail!("{} contains an invalid notification key", path.display());
            }
            if device
                .push_ticket
                .as_deref()
                .is_some_and(|ticket| !valid_push_ticket(ticket))
            {
                bail!("{} contains an invalid push ticket", path.display());
            }
            if let Some(registration) = &device.live_activity
                && (device.notification_key.is_none() || registration.validate().is_err())
            {
                bail!("{} contains an invalid live activity", path.display());
            }
            if !seen.insert(&device.endpoint_id) {
                bail!("{} contains a duplicate endpoint ID", path.display());
            }
        }
        Ok(Self {
            path,
            devices: file.devices,
        })
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    pub fn devices(&self) -> &[PairedDevice] {
        &self.devices
    }

    pub fn contains(&self, endpoint_id: EndpointId) -> bool {
        let endpoint_id = endpoint_id.to_string();
        self.devices
            .iter()
            .any(|device| device.endpoint_id == endpoint_id)
    }

    pub fn upsert(
        &mut self,
        endpoint_id: EndpointId,
        paired_at: u64,
        transcript_hash: &[u8; 32],
        notification_key: &[u8; 32],
    ) -> Result<()> {
        let endpoint_id = endpoint_id.to_string();
        let record = PairedDevice {
            endpoint_id: endpoint_id.clone(),
            paired_at,
            transcript_hash: base64url(transcript_hash),
            notification_key: Some(base64url(notification_key)),
            // A re-pair starts with no ticket. The phone registers one on its next connection,
            // and carrying the previous pairing's ticket over would only widen the window in
            // which a ticket outlives the pairing it was handed to.
            push_ticket: None,
            live_activity: None,
        };
        let mut updated = self.devices.clone();
        if let Some(existing) = updated
            .iter_mut()
            .find(|device| device.endpoint_id == endpoint_id)
        {
            *existing = record;
        } else {
            updated.push(record);
            updated.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        }
        self.persist(updated)
    }

    /// Stores or clears one paired device's push ticket. `None` is the revocation: after it, the
    /// host holds nothing that can reach that phone.
    pub fn set_push_ticket(&mut self, endpoint_id: EndpointId, ticket: Option<&str>) -> Result<()> {
        if ticket.is_some_and(|ticket| !valid_push_ticket(ticket)) {
            bail!("push ticket is malformed");
        }
        let endpoint_id = endpoint_id.to_string();
        let mut updated = self.devices.clone();
        let device = updated
            .iter_mut()
            .find(|device| device.endpoint_id == endpoint_id)
            .ok_or_else(|| anyhow!("device is not paired"))?;
        if device.push_ticket.as_deref() == ticket {
            return Ok(());
        }
        device.push_ticket = ticket.map(str::to_owned);
        self.persist(updated)
    }

    /// Registers, rotates, adds to, removes from, or clears one host-scoped ActivityKit
    /// overview. The mutation is idempotent; the host derives labels before they enter this
    /// metadata file, so a phone can select an opaque ID but cannot author presentation text.
    pub fn update_live_activity(
        &mut self,
        endpoint_id: EndpointId,
        ticket: Option<&str>,
        change: Option<LiveActivitySelectionChange>,
    ) -> Result<usize> {
        if ticket.is_some_and(|ticket| !valid_push_ticket(ticket)) {
            bail!("live activity ticket is malformed");
        }
        let endpoint_id = endpoint_id.to_string();
        let mut updated = self.devices.clone();
        let device = updated
            .iter_mut()
            .find(|device| device.endpoint_id == endpoint_id)
            .ok_or_else(|| anyhow!("device is not paired"))?;
        if device.notification_key.is_none() {
            bail!("device has no notification key");
        }
        let Some(ticket) = ticket else {
            if change.is_some() {
                bail!("a selection mutation requires a live activity ticket");
            }
            if device.live_activity.is_none() {
                return Ok(0);
            }
            device.live_activity = None;
            self.persist(updated)?;
            return Ok(0);
        };

        let mut registration = device
            .live_activity
            .clone()
            .unwrap_or(LiveActivityRegistration {
                ticket: ticket.to_owned(),
                selections: Vec::new(),
            });
        registration.ticket = ticket.to_owned();
        match change {
            Some(LiveActivitySelectionChange::Add(selection)) => {
                selection.validate()?;
                if let Some(existing) = registration
                    .selections
                    .iter_mut()
                    .find(|existing| existing.session_id == selection.session_id)
                {
                    *existing = selection;
                } else {
                    if registration.selections.len() >= MAX_LIVE_ACTIVITY_SELECTIONS {
                        bail!("live activity selection limit reached");
                    }
                    registration.selections.push(selection);
                }
            }
            Some(LiveActivitySelectionChange::Remove(session_id)) => {
                if !valid_live_activity_session_id(&session_id) {
                    bail!("live activity session ID is malformed");
                }
                registration
                    .selections
                    .retain(|selection| selection.session_id != session_id);
            }
            // A bare ticket refresh against no registration is the phone reconciling after this
            // host cleared or never held one. Erroring here trapped the phone in a loop it could
            // not repair — its reconcile refreshes the ticket without restating selections, so
            // the answer it needs is "zero", which is what tells it to re-assert or end the
            // orphaned activity. Nothing is persisted: a registration with nothing selected is
            // not a registration.
            None if registration.selections.is_empty() => {
                return Ok(0);
            }
            None => {}
        }
        registration
            .selections
            .sort_by(|left, right| left.session_id.cmp(&right.session_id));
        let selected = registration.selections.len();
        device.live_activity = (selected > 0).then_some(registration);
        self.persist(updated)?;
        Ok(selected)
    }

    pub fn clear_live_activity(&mut self, endpoint_id: EndpointId) -> Result<()> {
        self.update_live_activity(endpoint_id, None, None)
            .map(|_| ())
    }

    /// Every current ActivityKit target with the pairing key needed to seal its state. A device
    /// paired before ADR 005 cannot create a registration in the first place.
    pub fn live_activity_targets(&self) -> Vec<LiveActivityTarget> {
        self.devices
            .iter()
            .filter_map(|device| {
                let registration = device.live_activity.as_ref()?;
                Some(LiveActivityTarget {
                    endpoint_id: device.endpoint_id.clone(),
                    ticket: registration.ticket.clone(),
                    key: device
                        .notification_key
                        .as_deref()
                        .and_then(decode_exact::<32>)?,
                    selections: registration.selections.clone(),
                })
            })
            .collect()
    }

    /// Drops one device from the allowlist, returning whether it was there to drop.
    ///
    /// This is the revocation ADR 001 promises. The notification key and push ticket leave with
    /// the entry, so after it nothing on this host can reach that phone or authorize it again.
    pub fn remove(&mut self, endpoint_id: &str) -> Result<bool> {
        let updated: Vec<PairedDevice> = self
            .devices
            .iter()
            .filter(|device| device.endpoint_id != endpoint_id)
            .cloned()
            .collect();
        if updated.len() == self.devices.len() {
            return Ok(false);
        }
        self.persist(updated)?;
        Ok(true)
    }

    /// Every paired device this host can currently push to.
    /// Every device that can be pushed to, with the key its payload is sealed under.
    ///
    /// The key is `None` for a device paired before ADR 005 step 2. Such a device still gets the
    /// push — it is the relay's generic alert, which names nothing — it just gets no decryptable
    /// body until it re-pairs.
    pub fn push_targets(&self) -> Vec<(String, Option<[u8; 32]>)> {
        self.devices
            .iter()
            .filter_map(|device| {
                let ticket = device.push_ticket.clone()?;
                Some((
                    ticket,
                    device
                        .notification_key
                        .as_deref()
                        .and_then(decode_exact::<32>),
                ))
            })
            .collect()
    }

    fn persist(&mut self, updated: Vec<PairedDevice>) -> Result<()> {
        let encoded = serde_json::to_vec_pretty(&PairedDevicesFile {
            v: 1,
            devices: updated.clone(),
        })?;
        atomic_write_private(&self.path, &encoded)?;
        self.devices = updated;
        Ok(())
    }
}

fn valid_live_activity_label(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && value.chars().all(|character| {
            let scalar = character as u32;
            !matches!(scalar, 0x0000..=0x001f | 0x007f..=0x009f | 0x2028 | 0x2029)
                && !matches!(scalar, 0x202a..=0x202e | 0x2066..=0x2069)
        })
}

pub fn validate_endpoint_id(value: &str) -> Result<EndpointId> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("endpoint ID must be 64 lowercase hexadecimal characters");
    }
    EndpointId::from_str(value).context("endpoint ID is not a valid Iroh public key")
}

pub fn remove_socket_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove stale socket {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn paired_devices_persist_atomically_and_repair_idempotently() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let first = iroh::SecretKey::generate().public();
        let second = iroh::SecretKey::generate().public();
        let mut store = PairedDeviceStore::load(&path).unwrap();
        store.upsert(first, 10, &[1; 32], &[4; 32]).unwrap();
        store.upsert(second, 20, &[2; 32], &[5; 32]).unwrap();
        store.upsert(first, 30, &[3; 32], &[6; 32]).unwrap();

        let loaded = PairedDeviceStore::load(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains(first));
        assert!(loaded.contains(second));
        assert!(!loaded.contains(iroh::SecretKey::generate().public()));
        let repaired = loaded
            .devices()
            .iter()
            .find(|device| device.endpoint_id == first.to_string())
            .unwrap();
        assert_eq!(repaired.paired_at, 30);
        assert_eq!(repaired.transcript_hash, base64url(&[3; 32]));
        assert_eq!(repaired.notification_key, Some(base64url(&[6; 32])));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn unpairing_removes_one_device_and_survives_a_reload() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let stale = iroh::SecretKey::generate().public();
        let live = iroh::SecretKey::generate().public();
        let mut store = PairedDeviceStore::load(&path).unwrap();
        store.upsert(stale, 10, &[1; 32], &[4; 32]).unwrap();
        store.upsert(live, 20, &[2; 32], &[5; 32]).unwrap();

        assert!(store.remove(&stale.to_string()).unwrap());
        // Removing what is already gone is not an error, so a retry after a crash is safe.
        assert!(!store.remove(&stale.to_string()).unwrap());

        // The allowlist is the authorization boundary, so the removal has to be on disk, not
        // just in the copy this process happens to hold.
        let loaded = PairedDeviceStore::load(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(!loaded.contains(stale));
        assert!(loaded.contains(live));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn devices_paired_before_the_notification_key_still_load() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let existing = iroh::SecretKey::generate().public();
        atomic_write_private(
            &path,
            format!(
                r#"{{"v":1,"devices":[{{"endpoint_id":"{existing}","paired_at":10,"transcript_hash":"{}"}}]}}"#,
                base64url(&[1; 32])
            )
            .as_bytes(),
        )
        .unwrap();

        // It authorizes terminals and Agent Sessions exactly as before, and carries no key.
        let mut store = PairedDeviceStore::load(&path).unwrap();
        assert!(store.contains(existing));
        assert_eq!(store.devices()[0].notification_key, None);

        // Re-pairing is what gives it one.
        store.upsert(existing, 20, &[2; 32], &[3; 32]).unwrap();
        assert_eq!(
            PairedDeviceStore::load(&path).unwrap().devices()[0].notification_key,
            Some(base64url(&[3; 32]))
        );
    }

    #[test]
    fn a_push_ticket_is_stored_revoked_and_cleared_by_re_pairing() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let first = iroh::SecretKey::generate().public();
        let second = iroh::SecretKey::generate().public();
        let ticket = "T".repeat(140);
        let mut store = PairedDeviceStore::load(&path).unwrap();
        store.upsert(first, 10, &[1; 32], &[4; 32]).unwrap();
        store.upsert(second, 20, &[2; 32], &[5; 32]).unwrap();

        // A device that has not registered is simply not notifiable, which is also the state
        // every device paired before ADR 005 is in.
        assert!(store.push_targets().is_empty());
        store.set_push_ticket(first, Some(&ticket)).unwrap();
        // The pairing key travels with the ticket: a push is sealed under the key agreed with
        // the device it is going to, so the two can never be read apart.
        assert_eq!(store.push_targets(), vec![(ticket.clone(), Some([4; 32]))]);
        assert_eq!(
            PairedDeviceStore::load(&path).unwrap().push_targets(),
            vec![(ticket.clone(), Some([4; 32]))]
        );

        // Re-pairing starts over: the phone registers again on its next connection rather than
        // the previous pairing's ticket outliving the pairing it was handed to.
        store.upsert(first, 30, &[3; 32], &[6; 32]).unwrap();
        assert!(store.push_targets().is_empty());

        store.set_push_ticket(second, Some(&ticket)).unwrap();
        store.set_push_ticket(second, None).unwrap();
        assert!(
            PairedDeviceStore::load(&path)
                .unwrap()
                .push_targets()
                .is_empty()
        );

        // Neither an unpaired device nor a malformed ticket can put one in the file.
        let stranger = iroh::SecretKey::generate().public();
        assert!(store.set_push_ticket(stranger, Some(&ticket)).is_err());
        for bad in ["short", &"T".repeat(513), &format!("{}=", "T".repeat(139))] {
            assert!(store.set_push_ticket(first, Some(bad)).is_err(), "{bad}");
        }
        assert!(store.push_targets().is_empty());
    }

    #[test]
    fn live_activity_selection_is_bounded_persistent_and_independent_of_alerts() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let endpoint = iroh::SecretKey::generate().public();
        let alert_ticket = "A".repeat(140);
        let first_ticket = "L".repeat(140);
        let rotated_ticket = "R".repeat(140);
        let mut store = PairedDeviceStore::load(&path).unwrap();
        store.upsert(endpoint, 10, &[1; 32], &[4; 32]).unwrap();
        store
            .set_push_ticket(endpoint, Some(&alert_ticket))
            .unwrap();

        let selection = |index: usize| LiveActivitySelection {
            session_id: format!("session-{index}"),
            adapter: "Claude".into(),
            workspace: format!("workspace-{index}"),
        };
        for index in 0..MAX_LIVE_ACTIVITY_SELECTIONS {
            assert_eq!(
                store
                    .update_live_activity(
                        endpoint,
                        Some(&first_ticket),
                        Some(LiveActivitySelectionChange::Add(selection(index))),
                    )
                    .unwrap(),
                index + 1
            );
        }
        assert!(
            store
                .update_live_activity(
                    endpoint,
                    Some(&first_ticket),
                    Some(LiveActivitySelectionChange::Add(selection(99))),
                )
                .is_err()
        );
        assert_eq!(store.live_activity_targets()[0].selections.len(), 8);
        // Rotating the activity token changes no selection and never touches ordinary alerts.
        assert_eq!(
            store
                .update_live_activity(endpoint, Some(&rotated_ticket), None)
                .unwrap(),
            8
        );
        assert_eq!(store.push_targets()[0].0, alert_ticket);
        assert_eq!(store.live_activity_targets()[0].ticket, rotated_ticket);
        assert_eq!(
            PairedDeviceStore::load(&path)
                .unwrap()
                .live_activity_targets()[0]
                .selections
                .len(),
            8
        );

        for index in 0..MAX_LIVE_ACTIVITY_SELECTIONS {
            let remaining = MAX_LIVE_ACTIVITY_SELECTIONS - index - 1;
            assert_eq!(
                store
                    .update_live_activity(
                        endpoint,
                        Some(&rotated_ticket),
                        Some(LiveActivitySelectionChange::Remove(format!(
                            "session-{index}"
                        ))),
                    )
                    .unwrap(),
                remaining
            );
        }
        assert!(store.live_activity_targets().is_empty());
        assert_eq!(store.push_targets()[0].0, alert_ticket);
    }

    #[test]
    fn re_pair_and_unpair_clear_activity_ticket_selection_and_key_together() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let endpoint = iroh::SecretKey::generate().public();
        let ticket = "L".repeat(140);
        let mut store = PairedDeviceStore::load(&path).unwrap();
        store.upsert(endpoint, 10, &[1; 32], &[4; 32]).unwrap();
        store
            .update_live_activity(
                endpoint,
                Some(&ticket),
                Some(LiveActivitySelectionChange::Add(LiveActivitySelection {
                    session_id: "session-1".into(),
                    adapter: "Pi".into(),
                    workspace: "ciao".into(),
                })),
            )
            .unwrap();
        store.upsert(endpoint, 20, &[2; 32], &[5; 32]).unwrap();
        assert!(store.live_activity_targets().is_empty());

        store
            .update_live_activity(
                endpoint,
                Some(&ticket),
                Some(LiveActivitySelectionChange::Add(LiveActivitySelection {
                    session_id: "session-1".into(),
                    adapter: "Pi".into(),
                    workspace: "ciao".into(),
                })),
            )
            .unwrap();
        assert!(store.remove(&endpoint.to_string()).unwrap());
        assert!(store.live_activity_targets().is_empty());
    }

    /// Audit B1's trap, host half: after this host cleared a registration, the phone's reconcile
    /// — a bare ticket refresh, no selection restated — was refused as "empty", so the phone
    /// could neither learn the loss nor repair it and its Lock Screen froze. A refresh against
    /// nothing answers zero: no error, nothing persisted, and the zero is the signal the phone
    /// re-asserts from.
    #[test]
    fn a_ticket_refresh_against_no_registration_answers_zero_instead_of_erroring() {
        let temp = tempdir().unwrap();
        let endpoint = iroh::SecretKey::generate().public();
        let mut store = PairedDeviceStore::load(temp.path().join("paired-devices.json")).unwrap();
        store.upsert(endpoint, 10, &[1; 32], &[4; 32]).unwrap();

        let ticket = "L".repeat(140);
        assert_eq!(
            store
                .update_live_activity(endpoint, Some(&ticket), None)
                .unwrap(),
            0
        );
        assert!(store.live_activity_targets().is_empty());

        // A refresh against a real registration still rotates the ticket and keeps selections.
        store
            .update_live_activity(
                endpoint,
                Some(&ticket),
                Some(LiveActivitySelectionChange::Add(LiveActivitySelection {
                    session_id: "session-1".into(),
                    adapter: "Pi".into(),
                    workspace: "ciao".into(),
                })),
            )
            .unwrap();
        let rotated = "M".repeat(140);
        assert_eq!(
            store
                .update_live_activity(endpoint, Some(&rotated), None)
                .unwrap(),
            1
        );
        assert_eq!(store.live_activity_targets()[0].ticket, rotated);
        // A selection mutation still requires a ticket, exactly as before.
        assert!(
            store
                .update_live_activity(
                    endpoint,
                    None,
                    Some(LiveActivitySelectionChange::Remove("session-1".into()))
                )
                .is_err()
        );
    }

    /// A field this build has never heard of has to be survivable, because the binary that wrote
    /// it is routinely newer than the binary reading it: `ciao update --rollback` is a shipped
    /// command. Refusing the file is not a degradation, it is the daemon failing to start — which
    /// is exactly what a Spec 018 host's `live_activity` field did to an older one, fifteen exits
    /// in a row. Everything this file actually depends on is validated by name below, so rejecting
    /// the *unknown* buys nothing and costs the whole process.
    #[test]
    fn a_file_written_by_a_newer_host_still_loads() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let endpoint = iroh::SecretKey::generate().public();
        atomic_write_private(
            &path,
            format!(
                r#"{{"v":1,"devices":[{{"endpoint_id":"{endpoint}","paired_at":10,"transcript_hash":"{}","notification_key":"{}","something_from_the_future":{{"nested":true}}}}],"also_from_the_future":7}}"#,
                base64url(&[1; 32]),
                base64url(&[2; 32]),
            )
            .as_bytes(),
        )
        .unwrap();
        let store = PairedDeviceStore::load(&path).expect("a newer file must not stop the daemon");
        assert_eq!(store.devices().len(), 1);
        assert_eq!(store.devices()[0].endpoint_id, endpoint.to_string());
    }

    #[test]
    fn a_malformed_live_activity_on_disk_is_refused() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let endpoint = iroh::SecretKey::generate().public();
        atomic_write_private(
            &path,
            format!(
                r#"{{"v":1,"devices":[{{"endpoint_id":"{endpoint}","paired_at":10,"transcript_hash":"{}","notification_key":"{}","live_activity":{{"ticket":"{}","selections":[{{"session_id":"../secret","adapter":"Pi","workspace":"ciao"}}]}}}}]}}"#,
                base64url(&[1; 32]),
                base64url(&[2; 32]),
                "L".repeat(140),
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(
            PairedDeviceStore::load(&path)
                .unwrap_err()
                .to_string()
                .contains("invalid live activity")
        );
    }

    #[test]
    fn a_malformed_push_ticket_on_disk_is_refused() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let endpoint = iroh::SecretKey::generate().public();
        atomic_write_private(
            &path,
            format!(
                r#"{{"v":1,"devices":[{{"endpoint_id":"{endpoint}","paired_at":10,"transcript_hash":"{}","push_ticket":"nope"}}]}}"#,
                base64url(&[1; 32])
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(
            PairedDeviceStore::load(&path)
                .unwrap_err()
                .to_string()
                .contains("invalid push ticket")
        );
    }

    #[test]
    fn a_malformed_notification_key_is_refused() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        let endpoint = iroh::SecretKey::generate().public();
        atomic_write_private(
            &path,
            format!(
                r#"{{"v":1,"devices":[{{"endpoint_id":"{endpoint}","paired_at":10,"transcript_hash":"{}","notification_key":"too-short"}}]}}"#,
                base64url(&[1; 32])
            )
            .as_bytes(),
        )
        .unwrap();
        assert!(
            PairedDeviceStore::load(&path)
                .unwrap_err()
                .to_string()
                .contains("invalid notification key")
        );
    }

    #[test]
    fn malformed_file_is_refused_without_replacement() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("paired-devices.json");
        atomic_write_private(&path, b"not-json").unwrap();
        assert!(PairedDeviceStore::load(&path).is_err());
        assert_eq!(fs::read(path).unwrap(), b"not-json");
    }

    #[test]
    fn macos_layout_is_unchanged_for_backward_compatibility() {
        let paths = CiaoPaths::for_home("/Users/alpha");
        assert_eq!(
            paths.credentials_file,
            Path::new("/Users/alpha/Library/Application Support/Ciao/credentials.json")
        );
        assert_eq!(
            paths.socket_file,
            Path::new("/Users/alpha/Library/Application Support/Ciao/run/ciao.sock")
        );
        assert_eq!(
            paths.service_file,
            Path::new("/Users/alpha/Library/LaunchAgents/app.ciaooo.ciao.daemon.plist")
        );
        assert_eq!(paths.state_dir, paths.support_dir);
    }

    #[test]
    fn linux_layout_honors_only_absolute_xdg_variables() {
        // All XDG variables valid and absolute.
        let custom = CiaoPaths::for_linux_home(
            "/home/alpha",
            Some("/custom/config".into()),
            Some("/custom/state".into()),
            Some("/run/user/1000".into()),
        );
        assert_eq!(
            custom.config_file,
            Path::new("/custom/config/ciao/config.json")
        );
        assert_eq!(
            custom.credentials_file,
            Path::new("/custom/state/ciao/credentials.json")
        );
        assert_eq!(
            custom.paired_devices_file,
            Path::new("/custom/state/ciao/paired-devices.json")
        );
        // The socket follows the state directory, never XDG_RUNTIME_DIR: a cron-started daemon
        // has no runtime directory and must still bind where every client looks.
        assert_eq!(
            custom.socket_file,
            Path::new("/custom/state/ciao/run/ciao.sock")
        );
        assert_eq!(
            custom.service_file,
            Path::new("/custom/config/systemd/user/ciao.service")
        );

        // Missing, empty, and relative (hostile) values all fall back to HOME defaults and
        // never to the current directory or /tmp.
        for hostile in [
            None,
            Some(PathBuf::from("")),
            Some(PathBuf::from("../evil")),
        ] {
            let fallback = CiaoPaths::for_linux_home(
                "/home/alpha",
                hostile.clone(),
                hostile.clone(),
                hostile.clone(),
            );
            assert_eq!(
                fallback.config_file,
                Path::new("/home/alpha/.config/ciao/config.json")
            );
            assert_eq!(
                fallback.credentials_file,
                Path::new("/home/alpha/.local/state/ciao/credentials.json")
            );
            assert_eq!(
                fallback.socket_file,
                Path::new("/home/alpha/.local/state/ciao/run/ciao.sock")
            );
            assert_eq!(
                fallback.service_file,
                Path::new("/home/alpha/.config/systemd/user/ciao.service")
            );
            assert!(!fallback.run_dir.starts_with("/tmp"));
        }
    }

    #[test]
    fn linux_layout_directories_are_created_private_and_refuse_symlinks() {
        let temp = tempdir().unwrap();
        let home = temp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let paths = CiaoPaths::for_linux_home(&home, None, None, None);
        paths.ensure_layout().unwrap();
        for directory in [&paths.support_dir, &paths.state_dir, &paths.run_dir] {
            let mode = fs::metadata(directory).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", directory.display());
        }

        // A symlinked state directory is refused rather than traversed.
        let other = temp.path().join("elsewhere");
        fs::create_dir_all(&other).unwrap();
        fs::remove_dir_all(&paths.state_dir).unwrap();
        std::os::unix::fs::symlink(&other, &paths.state_dir).unwrap();
        assert!(paths.ensure_layout().is_err());
    }

    #[test]
    fn insecure_file_permissions_are_refused() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("secret.json");
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = validate_private_file(&path).unwrap_err().to_string();
        assert!(error.contains("chmod 600"));
    }
}
