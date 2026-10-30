//! Read-only terminal identity for Codex's shared app-server topology.
//!
//! A hook's ancestry authenticates its backend, not the terminal currently displaying its
//! thread. The patched TUI endpoint supplies that second fact, authenticated independently
//! by Unix peer credentials and kernel process incarnation. Nothing here grants commands.

use std::{
    collections::{HashMap, HashSet},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    task::JoinSet,
    time::timeout,
};

use crate::process;

const QUERY_TIMEOUT: Duration = Duration::from_millis(500);
const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(1200);
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_THREADS: usize = 64;
const MAX_CANDIDATES: usize = 64;
const MAX_DIRECTORY_ENTRIES: usize = 256;
const QUERY_CONCURRENCY: usize = 4;
const MAX_STATUS_DIRECTORIES: usize = 8;
const MAX_DIRECTORY_STORE_BYTES: u64 = 16 * 1024;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryStore {
    v: u8,
    directories: Vec<PathBuf>,
}

/// Separate from strict agent metadata so a rollback can still read its original format.
fn directory_store_path(paths: &crate::storage::CiaoPaths) -> PathBuf {
    paths.state_dir.join("codex-terminal-directories.json")
}

fn read_directories(path: &Path) -> Result<Vec<PathBuf>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => bail!("Codex terminal directory record could not be inspected"),
    };
    if !metadata.is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_DIRECTORY_STORE_BYTES
    {
        bail!("Codex terminal directory record is invalid");
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| invalid_status())?;
    let opened = file.metadata().map_err(|_| invalid_status())?;
    if (opened.dev(), opened.ino()) != (metadata.dev(), metadata.ino())
        || !opened.is_file()
        || opened.uid() != nix::unistd::Uid::effective().as_raw()
        || opened.mode() & 0o077 != 0
        || opened.len() > MAX_DIRECTORY_STORE_BYTES
    {
        return Err(invalid_status());
    }
    file.take(MAX_DIRECTORY_STORE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_status())?;
    if bytes.len() as u64 > MAX_DIRECTORY_STORE_BYTES {
        return Err(invalid_status());
    }
    let store: DirectoryStore = serde_json::from_slice(&bytes).map_err(|_| invalid_status())?;
    if store.v != 1
        || store.directories.len() > MAX_STATUS_DIRECTORIES
        || store
            .directories
            .iter()
            .any(|directory| !directory.is_absolute() || directory.as_os_str().len() > 4096)
    {
        return Err(invalid_status());
    }
    Ok(store.directories)
}

fn remember_directory(path: &Path, directory: &Path) -> Result<()> {
    static WRITER: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = WRITER.lock().map_err(|_| invalid_status())?;
    if private_directory(directory)?.is_none() {
        return Err(invalid_status());
    }
    let mut directories = read_directories(path)?;
    if !directories.iter().any(|known| known == directory) {
        if directories.len() == MAX_STATUS_DIRECTORIES {
            bail!("Codex terminal directory record reached its bound");
        }
        directories.push(directory.to_owned());
        let bytes = serde_json::to_vec(&DirectoryStore { v: 1, directories })
            .map_err(|_| invalid_status())?;
        if bytes.len() as u64 > MAX_DIRECTORY_STORE_BYTES {
            return Err(invalid_status());
        }
        crate::storage::atomic_write_private(path, &bytes).map_err(|_| invalid_status())?;
    }
    Ok(())
}

/// Called only after a positive authenticated registration, never from an untrusted pathname.
pub(crate) fn remember_verified_directory(binding: &TerminalBinding) -> Result<()> {
    let paths = crate::storage::CiaoPaths::discover().map_err(|_| invalid_status())?;
    remember_directory(&directory_store_path(&paths), &binding.status_directory)
}

pub(crate) fn known_status_directories() -> Result<Vec<PathBuf>> {
    let paths = crate::storage::CiaoPaths::discover().map_err(|_| invalid_status())?;
    let default = std::env::var_os("CODEX_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.home.join(".codex"))
        .join("tui-status");
    let mut directories = vec![default];
    for directory in read_directories(&directory_store_path(&paths))? {
        if !directories.contains(&directory) {
            directories.push(directory);
        }
    }
    Ok(directories)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TerminalBinding {
    pub(crate) tui_pid: u32,
    pub(crate) tui_identity: String,
    pub(crate) server_pid: u32,
    pub(crate) server_identity: String,
    pub(crate) generation: u64,
    pub(crate) thread_id: String,
    pub(crate) status_directory: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Snapshot {
    v: u8,
    generation: u64,
    connection: Connection,
    displayed_thread_id: Option<String>,
    attached_thread_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Connection {
    kind: String,
    state: String,
    server: Option<Server>,
}

#[derive(Debug, Deserialize)]
struct Server {
    pid: u32,
    identity: String,
}

fn invalid_status() -> anyhow::Error {
    anyhow!("Codex terminal identity was invalid")
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}

fn kernel_identity(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() == 3
        && matches!(parts[0], "linux" | "macos")
        && uuid(parts[1])
        && parts[2]
            .parse::<u64>()
            .is_ok_and(|number| number > 0 && number.to_string() == parts[2])
}

fn note_unknown_fields(value: &Value, known: &[&str]) {
    if let Some(object) = value.as_object() {
        for field in object.keys().filter(|key| !known.contains(&key.as_str())) {
            crate::drift::note("codex", "terminal_status", "unknown_field", field, None);
        }
    }
}

fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        bail!("Codex terminal identity exceeded its bound");
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid_status())?;
    note_unknown_fields(
        &value,
        &[
            "v",
            "generation",
            "connection",
            "displayed_thread_id",
            "attached_thread_ids",
        ],
    );
    note_unknown_fields(&value["connection"], &["kind", "state", "server"]);
    note_unknown_fields(&value["connection"]["server"], &["pid", "identity"]);
    if value["v"].as_u64() != Some(1) {
        crate::drift::note("codex", "terminal_status", "unknown_version", "v", None);
        return Err(invalid_status());
    }
    for (field, known) in [
        ("kind", &["embedded", "local_daemon", "remote"][..]),
        ("state", &["connected", "disconnected"][..]),
    ] {
        if let Some(name) = value["connection"][field].as_str()
            && !known.contains(&name)
        {
            crate::drift::note(
                "codex",
                "terminal_status",
                "unknown_vocabulary",
                field,
                None,
            );
            return Err(invalid_status());
        }
    }
    let snapshot: Snapshot = serde_json::from_value(value).map_err(|_| invalid_status())?;
    let threads: HashSet<_> = snapshot.attached_thread_ids.iter().collect();
    if snapshot.v != 1
        || snapshot.generation == 0
        || snapshot.attached_thread_ids.len() > MAX_THREADS
        || threads.len() != snapshot.attached_thread_ids.len()
        || snapshot.attached_thread_ids.iter().any(|id| !uuid(id))
        || snapshot
            .displayed_thread_id
            .as_ref()
            .is_some_and(|id| !uuid(id))
        || !matches!(
            snapshot.connection.kind.as_str(),
            "embedded" | "local_daemon" | "remote"
        )
        || !matches!(
            snapshot.connection.state.as_str(),
            "connected" | "disconnected"
        )
    {
        return Err(invalid_status());
    }
    let connected_local =
        snapshot.connection.kind == "local_daemon" && snapshot.connection.state == "connected";
    if connected_local != snapshot.connection.server.is_some()
        || snapshot.connection.server.as_ref().is_some_and(|server| {
            server.pid == 0
                || i32::try_from(server.pid).is_err()
                || !kernel_identity(&server.identity)
        })
        || (snapshot.connection.state == "disconnected"
            && (snapshot.displayed_thread_id.is_some() || !threads.is_empty()))
        || (snapshot.connection.kind == "remote"
            && (snapshot.displayed_thread_id.is_some() || !threads.is_empty()))
    {
        return Err(invalid_status());
    }
    Ok(snapshot)
}

fn private_metadata(path: &Path, directory: bool) -> Result<Option<(u64, u64)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("Codex terminal identity endpoint could not be inspected"),
    };
    let valid_type = if directory {
        metadata.is_dir()
    } else {
        metadata.file_type().is_socket()
    };
    let expected_mode = if directory { 0o700 } else { 0o600 };
    if !valid_type
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.mode() & 0o777 != expected_mode
    {
        bail!("Codex terminal identity endpoint is not private");
    }
    Ok(Some((metadata.dev(), metadata.ino())))
}

fn private_directory(directory: &Path) -> Result<Option<(u64, u64)>> {
    if !directory.is_absolute() || directory.as_os_str().len() > 4096 {
        bail!("Codex terminal identity directory is invalid");
    }
    private_metadata(directory, true)
}

async fn query_authenticated(directory: &Path, pid: u32) -> Result<Option<TerminalBinding>> {
    timeout(QUERY_TIMEOUT, async {
        let Some(directory_identity) = private_directory(directory)? else {
            return Ok(None);
        };
        let socket = directory.join(format!("{pid}.sock"));
        let Some(socket_identity) = private_metadata(&socket, false)? else {
            return Ok(None);
        };
        let Some(tui_identity) = process::terminal_identity(pid).await else {
            return Ok(None); // A stale rendezvous file is not a live terminal.
        };
        let mut stream = UnixStream::connect(&socket)
            .await
            .map_err(|_| anyhow!("Codex terminal identity endpoint is unavailable"))?;
        let credentials = stream.peer_cred().map_err(|_| invalid_status())?;
        if credentials.uid() != nix::unistd::Uid::effective().as_raw()
            || credentials
                .pid()
                .and_then(|value| u32::try_from(value).ok())
                != Some(pid)
        {
            bail!("Codex terminal identity peer did not match its process");
        }
        stream
            .write_all(b"{\"v\":1,\"type\":\"status\"}\n")
            .await
            .map_err(|_| invalid_status())?;
        let mut bytes = Vec::new();
        let limit = (&mut stream).take((MAX_RESPONSE_BYTES + 1) as u64);
        BufReader::new(limit)
            .read_until(b'\n', &mut bytes)
            .await
            .map_err(|_| invalid_status())?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            bail!("Codex terminal identity response exceeded its bound");
        }
        if bytes.last() != Some(&b'\n') {
            bail!("Codex terminal identity response was incomplete");
        }
        let snapshot = decode_snapshot(&bytes)?;
        if private_directory(directory)? != Some(directory_identity)
            || private_metadata(&socket, false)? != Some(socket_identity)
            || process::terminal_identity(pid).await.as_ref() != Some(&tui_identity)
        {
            bail!("Codex terminal identity changed during inspection");
        }
        if snapshot.connection.kind != "local_daemon" || snapshot.connection.state != "connected" {
            return Ok(None);
        }
        let Some(thread_id) = snapshot.displayed_thread_id else {
            return Ok(None);
        };
        if !snapshot.attached_thread_ids.contains(&thread_id) {
            return Ok(None); // History/replay can display a thread without attaching to it.
        }
        let server = snapshot.connection.server.ok_or_else(invalid_status)?;
        if server.pid == pid {
            bail!("Codex terminal identity named itself as its shared backend");
        }
        if process::terminal_identity(server.pid).await.as_ref() != Some(&server.identity) {
            bail!("Codex terminal backend incarnation changed during inspection");
        }
        Ok(Some(TerminalBinding {
            tui_pid: pid,
            tui_identity,
            server_pid: server.pid,
            server_identity: server.identity,
            generation: snapshot.generation,
            thread_id,
            status_directory: directory.to_owned(),
        }))
    })
    .await
    .map_err(|_| anyhow!("Codex terminal identity query timed out"))?
}

async fn query(directory: &Path, pid: u32) -> Result<Option<TerminalBinding>> {
    timeout(QUERY_TIMEOUT, async {
        if !interactive_codex(pid).await {
            return Ok(None);
        }
        let binding = query_authenticated(directory, pid).await?;
        if let Some(binding) = &binding {
            if !interactive_codex(pid).await {
                return Err(invalid_status());
            }
            if !crate::codex_adapter::process_is_local_app_server(binding.server_pid).await {
                return Ok(None);
            }
        }
        Ok(binding)
    })
    .await
    .map_err(|_| anyhow!("Codex terminal identity query timed out"))?
}

async fn interactive_codex(pid: u32) -> bool {
    crate::codex_adapter::process_is_interactive(pid).await
}

fn candidate_pids(directory: &Path) -> Result<Vec<u32>> {
    if private_directory(directory)?.is_none() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(directory)
        .map_err(|_| anyhow!("Codex terminal identity directory could not be read"))?;
    let mut candidates = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_DIRECTORY_ENTRIES {
            bail!("Codex terminal identity directory exceeded its bound");
        }
        let entry = entry.map_err(|_| invalid_status())?;
        let file_name = entry.file_name();
        let Some(pid) = file_name
            .to_str()
            .and_then(|name| name.strip_suffix(".sock"))
        else {
            crate::drift::note(
                "codex",
                "terminal_status",
                "unexpected_directory_entry",
                "",
                None,
            );
            continue;
        };
        let Some(pid) = pid.parse::<u32>().ok().filter(|value| {
            *value != 0 && i32::try_from(*value).is_ok() && value.to_string() == pid
        }) else {
            crate::drift::note(
                "codex",
                "terminal_status",
                "unexpected_endpoint_name",
                "",
                None,
            );
            continue;
        };
        if candidates.len() == MAX_CANDIDATES {
            bail!("Codex terminal identity candidates exceeded their bound");
        }
        candidates.push(pid);
    }
    Ok(candidates)
}

fn unambiguous(bindings: Vec<TerminalBinding>) -> Vec<TerminalBinding> {
    let mut counts = HashMap::new();
    for binding in &bindings {
        *counts
            .entry((
                binding.server_identity.clone(),
                binding.server_pid,
                binding.thread_id.clone(),
            ))
            .or_insert(0usize) += 1;
    }
    bindings
        .into_iter()
        .filter(|binding| {
            counts.get(&(
                binding.server_identity.clone(),
                binding.server_pid,
                binding.thread_id.clone(),
            )) == Some(&1)
        })
        .collect()
}

/// Fresh, positive foreground bindings. Unsupported stock TUIs make no claim; two proven
/// TUIs displaying the same backend/thread are ambiguous to the current single-route model.
pub(crate) async fn live_bindings(directory: &Path) -> Result<Vec<TerminalBinding>> {
    timeout(DISCOVERY_TIMEOUT, async {
        let candidates = candidate_pids(directory)?;
        let mut tasks = JoinSet::new();
        let mut candidates = candidates.into_iter();
        let mut bindings = Vec::new();
        loop {
            while tasks.len() < QUERY_CONCURRENCY {
                let Some(pid) = candidates.next() else { break };
                let directory = directory.to_owned();
                tasks.spawn(async move { query(&directory, pid).await });
            }
            let Some(result) = tasks.join_next().await else {
                break;
            };
            if let Some(binding) = result.map_err(|_| invalid_status())?? {
                bindings.push(binding);
            }
        }
        Ok(unambiguous(bindings))
    })
    .await
    .map_err(|_| anyhow!("Codex terminal identity discovery timed out"))?
}

pub(crate) async fn resolve_shared(
    directory: &Path,
    server_pid: u32,
    thread_id: &str,
) -> Result<Option<TerminalBinding>> {
    timeout(DISCOVERY_TIMEOUT, async {
        if server_pid == 0 || !uuid(thread_id) {
            return Err(invalid_status());
        }
        let Some(server_identity) = process::terminal_identity(server_pid).await else {
            return Err(invalid_status());
        };
        let binding = live_bindings(directory).await?.into_iter().find(|binding| {
            binding.server_pid == server_pid
                && binding.server_identity == server_identity
                && binding.thread_id == thread_id
        });
        if process::terminal_identity(server_pid).await.as_ref() != Some(&server_identity) {
            return Err(invalid_status());
        }
        Ok(binding)
    })
    .await
    .map_err(|_| anyhow!("Codex terminal identity resolution timed out"))?
}

/// No cached verdict can authorize a route or an exit request after the TUI changed selection.
pub(crate) async fn revalidate(binding: &TerminalBinding) -> bool {
    matches!(resolve_shared(&binding.status_directory, binding.server_pid, &binding.thread_id).await,
        Ok(Some(current)) if current == *binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const THREAD: &str = "22222222-2222-4222-8222-222222222222";

    fn shared() -> Value {
        serde_json::from_str::<Value>(include_str!(
            "../../../integrations/codex/terminal-status/examples.json"
        ))
        .unwrap()["shared"]
            .clone()
    }

    fn decode(value: &Value) -> Result<Snapshot> {
        decode_snapshot(&serde_json::to_vec(value).unwrap())
    }

    fn binding(pid: u32, thread: &str) -> TerminalBinding {
        TerminalBinding {
            tui_pid: pid,
            tui_identity: format!("macos:12345678-1234-1234-1234-123456789abc:{pid}"),
            server_pid: 1234,
            server_identity: "linux:12345678-1234-1234-1234-123456789abc:5678".into(),
            generation: 2,
            thread_id: thread.into(),
            status_directory: PathBuf::from("/test/tui-status"),
        }
    }

    #[test]
    fn contract_examples_cover_embedded_shared_and_disconnected() {
        let examples: Value = serde_json::from_str(include_str!(
            "../../../integrations/codex/terminal-status/examples.json"
        ))
        .unwrap();
        assert_eq!(examples.as_object().unwrap().len(), 3);
        for value in examples.as_object().unwrap().values() {
            decode(value).unwrap();
        }
        assert_eq!(
            decode(&examples["shared"])
                .unwrap()
                .displayed_thread_id
                .as_deref(),
            Some(THREAD)
        );
    }

    #[test]
    fn malformed_stale_and_unbounded_claims_are_refused() {
        for field in ["v", "generation", "connection", "attached_thread_ids"] {
            let mut value = shared();
            value.as_object_mut().unwrap().remove(field);
            assert!(decode(&value).is_err(), "missing {field}");
        }
        for change in [
            json!({"generation":0}),
            json!({"generation":-1}),
            json!({"displayed_thread_id":"arbitrary/path"}),
            json!({"attached_thread_ids":[THREAD, THREAD]}),
            json!({"attached_thread_ids":vec![THREAD; MAX_THREADS+1]}),
        ] {
            let mut value = shared();
            value
                .as_object_mut()
                .unwrap()
                .extend(change.as_object().unwrap().clone());
            assert!(decode(&value).is_err());
        }
        for connection in [
            json!({"kind":"local_daemon","state":"connected","server":null}),
            json!({"kind":"local_daemon","state":"disconnected","server":null}),
            json!({"kind":"remote","state":"connected","server":null}),
            json!({"kind":"embedded","state":"connected","server":{"pid":1,"identity":"bad"}}),
        ] {
            let mut value = shared();
            value["connection"] = connection;
            assert!(decode(&value).is_err());
        }
        for identity in [
            "",
            "macos:boot:123",
            "linux:12345678-1234-1234-1234-123456789abc:00",
            "linux:12345678-1234-1234-1234-123456789abc:0",
        ] {
            let mut value = shared();
            value["connection"]["server"]["identity"] = json!(identity);
            assert!(decode(&value).is_err());
        }
        assert!(decode_snapshot(&vec![b' '; MAX_RESPONSE_BYTES + 1]).is_err());
    }

    #[test]
    fn future_shaped_input_terminal_status_is_accounted_without_values() {
        fn tally() -> u64 {
            crate::drift::snapshot()
                .vendors
                .get("codex")
                .map_or(0, |vendor| {
                    vendor.overflow
                        + vendor
                            .signatures
                            .iter()
                            .filter(|signature| signature.surface == "terminal_status")
                            .map(|signature| signature.count)
                            .sum::<u64>()
                })
        }
        let before = tally();
        let mut value = shared();
        value["future_terminal_field"] = json!({"private":"terminal-status-sensitive-value"});
        value["connection"]["future_connection_field"] = json!("private");
        assert!(decode(&value).is_ok());
        value["connection"]["kind"] = json!("future_local_backend");
        assert!(decode(&value).is_err());
        value = shared();
        value["v"] = json!(2);
        assert!(decode(&value).is_err());
        assert!(
            tally() >= before + 4,
            "every new vocabulary site must be accounted"
        );
        assert!(
            !serde_json::to_string(&crate::drift::snapshot())
                .unwrap()
                .contains("terminal-status-sensitive-value")
        );
    }

    #[test]
    fn two_tuis_for_one_backend_thread_never_choose_an_arbitrary_terminal() {
        let a = binding(10, THREAD);
        let b = binding(11, THREAD);
        let c = binding(12, "33333333-3333-4333-8333-333333333333");
        assert_eq!(unambiguous(vec![a.clone()]), vec![a.clone()]);
        assert_eq!(unambiguous(vec![a, b, c.clone()]), vec![c.clone()]);
        let mut different_backend = binding(13, &c.thread_id);
        different_backend.server_pid += 1;
        assert_eq!(unambiguous(vec![c, different_backend]).len(), 2);
    }

    #[tokio::test]
    async fn absent_and_insecure_endpoints_never_prove_a_binding() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("tui-status");
        assert!(live_bindings(&directory).await.unwrap().is_empty());
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(live_bindings(&directory).await.is_err());
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.join(format!("{}.sock", std::process::id()));
        std::fs::write(&socket, b"not a socket").unwrap();
        assert!(
            query_authenticated(&directory, std::process::id())
                .await
                .is_err()
        );
        std::fs::remove_file(&socket).unwrap();
        std::os::unix::fs::symlink(home.path().join("missing"), &socket).unwrap();
        assert!(
            query_authenticated(&directory, std::process::id())
                .await
                .is_err()
        );
    }

    #[test]
    fn custom_directories_are_bounded_private_and_survive_a_consumer_restart() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let store = home.path().join("directories.json");
        let directory = home.path().join("custom/tui-status");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        remember_directory(&store, &directory).unwrap();
        remember_directory(&store, &directory).unwrap();
        assert_eq!(read_directories(&store).unwrap(), vec![directory]);
        assert_eq!(std::fs::metadata(&store).unwrap().mode() & 0o777, 0o600);
        assert!(!std::fs::read_to_string(&store).unwrap().contains(THREAD));
        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_directories(&store).is_err());
    }

    #[tokio::test]
    async fn authenticated_endpoint_proves_its_real_peer_and_exact_process_incarnations() {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join("tui-status");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A separate executable process supplies the kernel-authenticated peer. The fixture
        // has no vendor/model behavior: its only job is to serve the agreed bounded status.
        let binary = home.path().join("codex");
        std::fs::hard_link(std::env::current_exe().unwrap(), &binary).unwrap();
        let backend = std::process::id();
        let identity = process::terminal_identity(backend).await.unwrap();
        let mut value = shared();
        value["connection"]["server"] = json!({"pid":backend,"identity":identity});
        let mut child = tokio::process::Command::new(binary)
            .args([
                "--ignored",
                "--exact",
                "codex_terminal_status::tests::status_socket_fixture",
                "--nocapture",
            ])
            .env_clear()
            .env("CIAO_TEST_STATUS_DIRECTORY", &directory)
            .env(
                "CIAO_TEST_STATUS_SNAPSHOT",
                serde_json::to_string(&value).unwrap(),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        timeout(Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                assert_ne!(
                    output.read_line(&mut line).await.unwrap(),
                    0,
                    "fixture exited before readiness"
                );
                if line.trim() == "STATUS_READY" {
                    break;
                }
            }
        })
        .await
        .unwrap();
        let found = query_authenticated(&directory, pid)
            .await
            .expect("first authenticated query")
            .expect("first binding");
        assert_eq!(found.tui_pid, pid);
        assert_eq!(found.server_pid, backend);
        assert_eq!(found.thread_id, THREAD);
        assert_eq!(
            query_authenticated(&directory, pid)
                .await
                .expect("steady authenticated query"),
            Some(found.clone())
        );
        let actual_path = directory.join(format!("{pid}.sock"));
        let forged_path = directory.join(format!("{backend}.sock"));
        std::fs::rename(&actual_path, &forged_path).unwrap();
        assert!(query_authenticated(&directory, backend).await.is_err());
        std::fs::rename(&forged_path, &actual_path).unwrap();
        assert_eq!(
            query_authenticated(&directory, pid)
                .await
                .expect("query after restoring renamed endpoint"),
            Some(found.clone())
        );
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        assert!(
            query_authenticated(&directory, pid)
                .await
                .unwrap()
                .is_none(),
            "a stale socket cannot keep a dead process live"
        );
    }

    #[tokio::test]
    #[ignore = "owned subprocess helper for real Unix credential tests"]
    async fn status_socket_fixture() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let directory = PathBuf::from(std::env::var_os("CIAO_TEST_STATUS_DIRECTORY").unwrap());
        let snapshot = std::env::var("CIAO_TEST_STATUS_SNAPSHOT").unwrap();
        let path = directory.join(format!("{}.sock", std::process::id()));
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        println!("STATUS_READY");
        std::io::stdout().flush().unwrap();
        // The child carries its own deadline even if a killed parent cannot run Drop.
        let _ = timeout(Duration::from_secs(10), async {
            for _ in 0..10 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let read = timeout(Duration::from_secs(1), async {
                    let limited = (&mut stream).take(257);
                    BufReader::new(limited).read_until(b'\n', &mut bytes).await
                })
                .await;
                let Ok(Ok(count)) = read else {
                    continue;
                };
                if count == 0 {
                    continue;
                } // A rejected peer closes before writing.
                assert_eq!(bytes, b"{\"v\":1,\"type\":\"status\"}\n");
                let response = format!("{snapshot}\n");
                let _ = timeout(
                    Duration::from_secs(1),
                    stream.write_all(response.as_bytes()),
                )
                .await;
            }
        })
        .await;
    }
}
