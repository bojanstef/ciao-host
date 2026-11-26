//! Orca's authenticated local catalog. Runtime handles, paths, and credentials stay on this host.
mod channel;
pub mod manage;
pub(crate) mod route;
pub(crate) mod session;

use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
    time::Duration,
};

use nix::{libc, unistd::Uid};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    fs::{self, OpenOptions},
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    time::timeout,
};

use crate::host_protocol::{HostProtocolError, valid_tab_label};
use crate::workspace::sanitize_tab_label;

const MAX_ROWS: usize = 128;
const METADATA_LIMIT: u64 = 16 * 1024;
const RESPONSE_LIMIT: u64 = 4 * 1024 * 1024;

/// Ordered, reviewed candidate directories for local Orca runtimes.
///
/// An explicit absolute `ORCA_USER_DATA_PATH` (or `ORCA_USER_DATA`, used by headless `orcad`)
/// pins discovery to that single directory for strict test and operator isolation. Otherwise,
/// discovery checks both the platform desktop user-data directory and headless `orcad`'s
/// `~/.orca` directory dynamically on each call, skipping missing or stale profiles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OrcaConfig {
    profiles: Vec<PathBuf>,
}

impl OrcaConfig {
    pub(crate) fn for_home(home: &Path) -> Self {
        Self::resolve_profiles(
            home,
            std::env::var_os("ORCA_USER_DATA_PATH").map(PathBuf::from),
            std::env::var_os("ORCA_USER_DATA").map(PathBuf::from),
            std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
        )
    }

    #[cfg(test)]
    pub(crate) fn at(profile: PathBuf) -> Self {
        Self {
            profiles: vec![profile],
        }
    }

    #[cfg(test)]
    pub(crate) fn from_profiles(profiles: Vec<PathBuf>) -> Self {
        Self { profiles }
    }

    fn resolve_profiles(
        home: &Path,
        user_data_path: Option<PathBuf>,
        user_data: Option<PathBuf>,
        xdg_config_home: Option<PathBuf>,
    ) -> Self {
        if let Some(explicit) = user_data_path
            .filter(|p| p.is_absolute())
            .or_else(|| user_data.filter(|p| p.is_absolute()))
        {
            return Self {
                profiles: vec![explicit],
            };
        }
        let mut profiles = Vec::with_capacity(2);
        let desktop = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/orca")
        } else {
            xdg_config_home
                .filter(|path| path.is_absolute())
                .unwrap_or_else(|| home.join(".config"))
                .join("orca")
        };
        profiles.push(desktop);
        let headless = home.join(".orca");
        if !profiles.contains(&headless) {
            profiles.push(headless);
        }
        Self { profiles }
    }

    fn profiles(&self) -> &[PathBuf] {
        &self.profiles
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OrcaSnapshot {
    Available {
        repositories: Vec<Repository>,
        truncated: bool,
        can_attach: bool,
        can_remove_worktrees: bool,
    },
    Unavailable,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub folder: bool,
    pub id: String,
    pub name: String,
    pub worktrees: Vec<Worktree>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Worktree {
    pub id: String,
    pub name: String,
    pub tabs: Vec<Tab>,
    pub removable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tab {
    pub id: String,
    pub name: String,
    pub panes: Vec<Pane>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Pane {
    pub key: String,
    pub name: String,
}

pub(crate) use valid_workspace_id as uuid;
pub(crate) fn valid_workspace_id(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}

impl OrcaSnapshot {
    pub(crate) fn validate(&self) -> Result<(), HostProtocolError> {
        let Self::Available { repositories, .. } = self else {
            return Ok(());
        };
        fn valid_rows<T>(rows: &[T], id: impl Fn(&T) -> &str) -> bool {
            let mut seen = BTreeSet::new();
            rows.len() <= MAX_ROWS && rows.iter().all(|row| seen.insert(id(row)))
        }
        let valid = valid_rows(repositories, |r| &r.id)
            && repositories.iter().all(|r| {
                uuid(&r.id)
                    && valid_tab_label(&r.name)
                    && valid_rows(&r.worktrees, |w| &w.id)
                    && r.worktrees.iter().all(|w| {
                        uuid(&w.id)
                            && valid_tab_label(&w.name)
                            && valid_rows(&w.tabs, |t| &t.id)
                            && w.tabs.iter().all(|t| {
                                uuid(&t.id)
                                    && valid_tab_label(&t.name)
                                    && !t.panes.is_empty()
                                    && valid_rows(&t.panes, |p| &p.key)
                                    && t.panes.iter().all(|p| {
                                        valid_tab_label(&p.name)
                                            && p.key.split_once(':').is_some_and(|(tab, leaf)| {
                                                tab == t.id && uuid(leaf)
                                            })
                                    })
                            })
                    })
            });
        valid
            .then_some(())
            .ok_or(HostProtocolError::InvalidControlValue)
    }

    pub(crate) fn shorten(&mut self) -> bool {
        let Self::Available {
            repositories,
            truncated,
            ..
        } = self
        else {
            return false;
        };
        let Some(repo) = repositories.last_mut() else {
            return false;
        };
        *truncated = true;
        if let Some(worktree) = repo.worktrees.last_mut() {
            if let Some(tab) = worktree.tabs.last_mut() {
                if tab.panes.len() > 1 {
                    tab.panes.pop();
                } else {
                    worktree.tabs.pop();
                }
            } else {
                repo.worktrees.pop();
            }
        } else {
            repositories.pop();
        }
        true
    }
}

// Neither this type nor the wire envelope implements Debug: both carry a credential.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    auth_token: String,
    runtime_id: String,
    transports: Vec<Transport>,
}

#[derive(Deserialize)]
struct Transport {
    kind: String,
    endpoint: PathBuf,
}

struct Runtime {
    profile: PathBuf,
    metadata: Metadata,
    endpoint: PathBuf,
}

impl Runtime {
    async fn discover_in(profile: &Path) -> Option<Self> {
        let uid = Uid::effective().as_raw();
        let dir = fs::symlink_metadata(profile).await.ok()?;
        if !dir.is_dir() || dir.uid() != uid || dir.mode() & 0o022 != 0 {
            return None;
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(profile.join("orca-runtime.json"))
            .await
            .ok()?;
        let info = file.metadata().await.ok()?;
        if !info.is_file() || info.uid() != uid || info.mode() & 0o077 != 0 {
            return None;
        }
        let mut buf = Vec::new();
        file.take(METADATA_LIMIT + 1)
            .read_to_end(&mut buf)
            .await
            .ok()?;
        if buf.len() as u64 > METADATA_LIMIT {
            return None;
        }
        let metadata: Metadata = serde_json::from_slice(&buf).ok()?;
        if metadata.auth_token.is_empty() || metadata.runtime_id.is_empty() {
            return None;
        }
        let endpoint = metadata
            .transports
            .iter()
            .find(|t| t.kind == "unix")?
            .endpoint
            .clone();
        if !endpoint.is_absolute() {
            return None;
        }
        let dir = fs::symlink_metadata(endpoint.parent()?).await.ok()?;
        let socket = fs::symlink_metadata(&endpoint).await.ok()?;
        if !dir.is_dir()
            || dir.uid() != uid
            || dir.mode() & 0o022 != 0
            || !socket.file_type().is_socket()
            || socket.uid() != uid
        {
            return None;
        }
        Some(Self {
            profile: profile.to_path_buf(),
            metadata,
            endpoint,
        })
    }

    async fn candidates(config: &OrcaConfig) -> Vec<Self> {
        let mut found = Vec::with_capacity(config.profiles().len());
        let mut seen = BTreeSet::new();
        for profile in config.profiles() {
            if let Some(rt) = Self::discover_in(profile).await
                && seen.insert(rt.metadata.runtime_id.clone())
            {
                found.push(rt);
            }
        }
        found
    }

    async fn discover_id(config: &OrcaConfig, runtime_id: &str) -> Option<Self> {
        for profile in config.profiles() {
            if let Some(rt) = Self::discover_in(profile).await
                && rt.metadata.runtime_id == runtime_id
            {
                return Some(rt);
            }
        }
        None
    }

    #[cfg(test)]
    async fn discover(config: &OrcaConfig) -> Option<Self> {
        Self::candidates(config).await.into_iter().next()
    }

    async fn query(&self, method: &str, params: Value) -> Option<Value> {
        let mut reply = self.exchange(method, params, None).await?;
        if reply["ok"] != true {
            return None;
        }
        Some(reply.get_mut("result")?.take())
    }

    async fn exchange(&self, method: &str, params: Value, source: Option<Value>) -> Option<Value> {
        let mut stream = UnixStream::connect(&self.endpoint).await.ok()?;
        if stream.peer_cred().ok()?.uid() != Uid::effective().as_raw() {
            return None;
        }
        let id = crate::protocol::base64url(&rand::random::<[u8; 16]>());
        let mut envelope =
            json!({"id":id, "authToken":self.metadata.auth_token,"method":method,"params":params});
        if let Some(source) = source {
            envelope["expectedRuntimeSource"] = source;
        }
        let mut request = serde_json::to_vec(&envelope).ok()?;
        request.push(b'\n');
        stream.write_all(&request).await.ok()?;
        let mut reader = BufReader::new(stream.take(RESPONSE_LIMIT + 1));
        let mut line = Vec::new();
        loop {
            line.clear();
            reader.read_until(b'\n', &mut line).await.ok()?;
            if line.last() != Some(&b'\n') || reader.get_ref().limit() == 0 {
                return None;
            }
            let reply: Value = serde_json::from_slice(&line).ok()?;
            if reply.get("_keepalive") == Some(&Value::Bool(true)) {
                continue;
            }
            if reply["id"] != id
                || reply["_meta"]["runtimeId"] != self.metadata.runtime_id
                || !reply["ok"].is_boolean()
            {
                return None;
            }
            return Some(reply);
        }
    }
}

async fn read_private_file(path: &Path) -> Option<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .await
        .ok()?;
    let meta = f.metadata().await.ok()?;
    if !meta.is_file() || meta.uid() != Uid::effective().as_raw() || meta.mode() & 0o077 != 0 {
        return None;
    }
    let mut data = Vec::new();
    f.take(METADATA_LIMIT + 1)
        .read_to_end(&mut data)
        .await
        .ok()?;
    (data.len() as u64 <= METADATA_LIMIT).then_some(data)
}

async fn paired(runtime: &Runtime, path: Option<&Path>) -> Option<()> {
    let bytes = read_private_file(path?).await?;
    let pairing = serde_json::from_slice(&bytes).ok()?;
    timeout(
        Duration::from_millis(900),
        channel::Channel::connect(runtime, pairing),
    )
    .await
    .ok()?
    .ok()?;
    Some(())
}

pub(crate) async fn snapshot(
    config: &OrcaConfig,
    tabs: bool,
    include_folders: bool,
    credentials: Option<&Path>,
) -> OrcaSnapshot {
    timeout(Duration::from_secs(3), async {
        let mut fallback = None;
        for rt in Runtime::candidates(config).await {
            let Some(snap) = snapshot_runtime(&rt, tabs, include_folders, credentials).await else {
                continue;
            };
            if matches!(
                snap,
                OrcaSnapshot::Available {
                    can_attach: true,
                    ..
                }
            ) {
                return Some(snap);
            }
            if fallback.is_none() {
                fallback = Some(snap);
            }
        }
        fallback
    })
    .await
    .ok()
    .flatten()
    .unwrap_or(OrcaSnapshot::Unavailable)
}

async fn snapshot_runtime(
    rt: &Runtime,
    tabs: bool,
    include_folders: bool,
    credentials: Option<&Path>,
) -> Option<OrcaSnapshot> {
    let terminals = async {
        if !tabs {
            return Some(json!({"terminals":[]}));
        }
        rt.query(
            "terminal.list",
            json!({
                "limit": MAX_ROWS, "includePreview": false,
                "includeVisualLayouts": false, "requireFreshPtyLiveness": true
            }),
        )
        .await
    };
    let (status, pairing, repos, worktrees, terminals) = tokio::join!(
        rt.query("status.get", json!({})),
        paired(rt, credentials),
        rt.query("repo.list", json!({})),
        rt.query("worktree.list", json!({"limit": MAX_ROWS})),
        terminals
    );
    let mut result = catalog(&repos?, &worktrees?, &terminals?, include_folders)?;
    if let OrcaSnapshot::Available {
        can_attach,
        can_remove_worktrees,
        ..
    } = &mut result
    {
        *can_attach = pairing.is_some();
        *can_remove_worktrees = status.as_ref().is_some_and(manage::can_retain);
    }
    Some(result)
}

fn name(row: &Value, key: &str, default: &str) -> String {
    row[key]
        .as_str()
        .and_then(sanitize_tab_label)
        .unwrap_or_else(|| default.into())
}

fn local_project(row: &Value) -> bool {
    (row["kind"] == "git" || row["kind"] == "folder")
        && row["connectionId"].is_null()
        && (row["hostId"].is_null() || row["hostId"] == "local")
        && (row["executionHostId"].is_null() || row["executionHostId"] == "local")
}
/// Orca 1.4.273 identifies a folder context directly on its local workspace row.
fn workspace_instance(row: &Value, folder: bool) -> Option<&str> {
    if row["hostId"] != "local"
        || !row["connectionId"].is_null()
        || !(row["executionHostId"].is_null() || row["executionHostId"] == "local")
    {
        return None;
    }
    let id = if row.get("identity").is_some() {
        if row["identity"]["executionHostId"] != "local" {
            return None;
        }
        let id = row["identity"]["instanceId"].as_str()?;
        if row["instanceId"].as_str().is_some_and(|flat| flat != id) {
            return None;
        }
        id
    } else if folder {
        row["instanceId"].as_str()?
    } else {
        return None;
    };
    uuid(id).then_some(id)
}

fn project_folder(repos: &Value, repo: &str) -> Option<bool> {
    let mut rows = repos["repos"]
        .as_array()?
        .iter()
        .filter(|r| r["id"] == repo);
    let row = rows.next()?;
    (rows.next().is_none() && local_project(row)).then(|| row["kind"] == "folder")
}

fn catalog(
    repos: &Value,
    worktrees: &Value,
    terminals: &Value,
    include_folders: bool,
) -> Option<OrcaSnapshot> {
    let repo_rows = repos["repos"].as_array()?;
    let wt_rows = worktrees["worktrees"].as_array()?;
    let pane_rows = terminals["terminals"].as_array()?;
    let truncated = worktrees["truncated"] == true
        || terminals["truncated"] == true
        || [repo_rows, wt_rows, pane_rows]
            .iter()
            .any(|rows| rows.len() > MAX_ROWS);
    let mut repositories = Vec::new();
    let mut index = BTreeMap::new();
    for row in repo_rows.iter().take(MAX_ROWS) {
        let Some(id) = row["id"].as_str().filter(|id| uuid(id)) else {
            continue;
        };
        let folder = row["kind"] == "folder";
        if !local_project(row) || (folder && !include_folders) {
            continue;
        }
        if index.insert(id, repositories.len()).is_some() {
            return None;
        }
        repositories.push(Repository {
            folder,
            id: id.into(),
            name: name(row, "displayName", "Repository"),
            worktrees: vec![],
        });
    }
    let mut paths = BTreeMap::new();
    for row in wt_rows.iter().take(MAX_ROWS) {
        let Some(&r) = row["repoId"].as_str().and_then(|k| index.get(k)) else {
            continue;
        };
        let folder = repositories[r].folder;
        let Some(id) = workspace_instance(row, folder) else {
            continue;
        };
        let Some(key) = row["id"].as_str() else {
            continue;
        };
        let entries = &mut repositories[r].worktrees;
        if paths.insert(key, (r, entries.len())).is_some() {
            return None;
        }
        entries.push(Worktree {
            id: id.into(),
            name: name(row, "displayName", "Worktree"),
            tabs: vec![],
            removable: !folder && row["isMainWorktree"] == false,
        });
    }
    for row in pane_rows.iter().take(MAX_ROWS) {
        if row["executionHostId"] != "local" || row["connected"] != true || row["orphaned"] == true
        {
            continue;
        }
        let Some(&(r, w)) = row["worktreeId"].as_str().and_then(|k| paths.get(k)) else {
            continue;
        };
        let Some(tab_id) = row["tabId"].as_str().filter(|id| uuid(id)) else {
            continue;
        };
        let Some(leaf) = row["leafId"].as_str().filter(|id| uuid(id)) else {
            continue;
        };
        let tabs = &mut repositories[r].worktrees[w].tabs;
        let slot = tabs.iter().position(|t| t.id == tab_id).unwrap_or_else(|| {
            tabs.push(Tab {
                id: tab_id.into(),
                name: name(row, "title", "Terminal"),
                panes: vec![],
            });
            tabs.len() - 1
        });
        let panes = &mut tabs[slot].panes;
        let fallback = format!("Pane {}", panes.len() + 1);
        panes.push(Pane {
            key: format!("{tab_id}:{leaf}"),
            name: name(row, "paneTitle", &fallback),
        });
    }
    let snapshot = OrcaSnapshot::Available {
        can_attach: false,
        can_remove_worktrees: false,
        repositories,
        truncated,
    };
    snapshot.validate().ok()?;
    Some(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_protocol::{
        RpcRequest, WorkspaceSnapshotResponse, decode_rpc_request, encode_snapshot_response_bounded,
    };

    const FIXTURE: &str = include_str!("../../../protocol/fixtures/phase9/orca-catalog-v1.json");

    #[test]
    fn shared_fixture_keeps_split_identity_and_legacy_wire() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        assert!(matches!(
            decode_rpc_request(&serde_json::to_vec(&fixture["request"]).unwrap()),
            Ok(RpcRequest::WorkspaceSnapshot(request)) if request.method == "workspace.snapshot.v4"
        ));
        let open: crate::host_protocol::TerminalOpen =
            serde_json::from_value(fixture["attach"].clone()).unwrap();
        assert_eq!(
            open.validated_target().unwrap(),
            crate::host_protocol::TerminalTarget::OrcaAttach
        );
        for envelope in fixture["management"].as_array().unwrap() {
            assert!(matches!(
                decode_rpc_request(&serde_json::to_vec(envelope).unwrap()),
                Ok(RpcRequest::OrcaManagement(_))
            ));
        }
        let mut response: WorkspaceSnapshotResponse =
            serde_json::from_value(fixture["response"].clone()).unwrap();
        response.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            fixture["response"]
        );
        let Some(OrcaSnapshot::Available { repositories, .. }) =
            response.result.providers.orca.as_deref_mut()
        else {
            panic!()
        };
        let panes = &mut repositories[0].worktrees[0].tabs[0].panes;
        assert_ne!(panes[0].key, panes[1].key);
        assert_eq!(panes[0].name, panes[1].name);
        panes[1].key = panes[0].key.clone();
        assert!(response.validate().is_err());
        response.result.providers.orca = None;
        assert!(
            serde_json::to_value(response).unwrap()["result"]["providers"]
                .get("orca")
                .is_none()
        );
    }

    #[test]
    fn oversized_orca_catalog_preserves_other_providers() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let mut response: WorkspaceSnapshotResponse =
            serde_json::from_value(fixture["response"].clone()).unwrap();
        let Some(OrcaSnapshot::Available { repositories, .. }) =
            response.result.providers.orca.as_deref_mut()
        else {
            panic!()
        };
        let first = repositories[0].clone();
        for i in 2..100 {
            let mut next = first.clone();
            next.id = format!("00000000-0000-4000-8000-{i:012x}");
            repositories.push(next);
        }
        let (_, bounded) = encode_snapshot_response_bounded(response).unwrap();
        assert!(matches!(
            bounded.result.providers.orca.as_deref(),
            Some(OrcaSnapshot::Available {
                truncated: true,
                ..
            })
        ));
        assert_eq!(
            serde_json::to_value(bounded.result.providers.tmux).unwrap(),
            fixture["response"]["result"]["providers"]["tmux"]
        );
    }

    #[test]
    fn folder_catalog_is_negotiated_and_keeps_git_operations_disabled() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase9/orca-folder-v5.json"
        ))
        .unwrap();
        let result = &fixture["response"]["result"]["providers"]["orca"];
        let expected = &result["repositories"][0];
        let workspace = &expected["worktrees"][0];
        let repos =
            json!({"repos":[{"id":expected["id"],"kind":"folder","displayName":expected["name"]}]});
        let worktrees = json!({"worktrees":[{"id":"folder:private","repoId":expected["id"],"hostId":"local","instanceId":workspace["id"],"displayName":workspace["name"],"isMainWorktree":false}]});
        let tab = &workspace["tabs"][0];
        let terminals: Vec<_> = tab["panes"].as_array().unwrap().iter().map(|p| json!({"worktreeId":"folder:private","tabId":tab["id"],"leafId":p["key"].as_str().unwrap().split_once(':').unwrap().1,"executionHostId":"local","connected":true,"title":tab["name"],"paneTitle":p["name"]})).collect();
        let panes = json!({"terminals":terminals});
        let snapshot = |w: &Value, folders| {
            serde_json::to_value(catalog(&repos, w, &panes, folders).unwrap()).unwrap()
        };
        assert_eq!(snapshot(&worktrees, true)["repositories"][0], *expected);
        assert_eq!(snapshot(&worktrees, false)["repositories"], json!([]));
        let mut foreign = worktrees.clone();
        foreign["worktrees"][0]["executionHostId"] = json!("ssh:other");
        assert_eq!(
            snapshot(&foreign, true)["repositories"][0]["worktrees"],
            json!([])
        );
        let mut conflicting = worktrees;
        conflicting["worktrees"][0]["identity"] =
            json!({"executionHostId":"remote","instanceId":workspace["id"]});
        assert_eq!(
            snapshot(&conflicting, true)["repositories"][0]["worktrees"],
            json!([])
        );
    }

    #[test]
    fn catalog_requires_local_identity_at_each_join() {
        let repo = "00000000-0000-4000-8000-000000000001";
        let id = "00000000-0000-4000-8000-000000000002";
        let tab = "00000000-0000-4000-8000-000000000003";
        let leaf = "00000000-0000-4000-8000-000000000004";
        let repos = json!({"repos":[{"id":repo,"kind":"git","displayName":"QA"}]});
        let worktrees = json!({"worktrees":[{"id":"opaque", "hostId":"local","identity":{"instanceId":id,"executionHostId":"local"},"repoId":repo}]});
        let entry = json!({"worktreeId":"opaque","tabId":tab,"leafId":leaf,"connected":true,"executionHostId":"local","title":"Shell","preview":"private","handle":"never-disclose"});
        let mut foreign = entry.clone();
        foreign["executionHostId"] = json!("ssh:other");
        let mut unknown = entry.clone();
        unknown.as_object_mut().unwrap().remove("executionHostId");
        let terminals = json!({"terminals":[foreign, unknown, entry]});
        let snap =
            serde_json::to_value(catalog(&repos, &worktrees, &terminals, false).unwrap()).unwrap();
        assert_eq!(
            snap["repositories"][0]["worktrees"][0]["tabs"][0]["panes"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let bytes = snap.to_string();
        assert!(
            !bytes.contains("private")
                && !bytes.contains("opaque")
                && !bytes.contains("never-disclose")
        );
        let mut remote = worktrees;
        remote["worktrees"][0]["identity"]["executionHostId"] = json!("ssh:other");
        let snap =
            serde_json::to_value(catalog(&repos, &remote, &terminals, false).unwrap()).unwrap();
        assert_eq!(snap["repositories"][0]["worktrees"], json!([]));
    }

    #[test]
    fn config_resolves_overrides_and_headless_fallback() {
        let home = Path::new("/home/tester");
        let explicit_path = PathBuf::from("/custom/orca-path");
        let explicit_data = PathBuf::from("/custom/orca-data");

        assert_eq!(
            OrcaConfig::resolve_profiles(
                home,
                Some(explicit_path.clone()),
                Some(explicit_data.clone()),
                None
            )
            .profiles(),
            &[explicit_path]
        );
        assert_eq!(
            OrcaConfig::resolve_profiles(home, None, Some(explicit_data.clone()), None).profiles(),
            &[explicit_data]
        );
        // Relative env overrides fail closed to the reviewed defaults.
        let defaults = OrcaConfig::resolve_profiles(
            home,
            Some(PathBuf::from("relative/path")),
            Some(PathBuf::from("relative/data")),
            Some(PathBuf::from("/xdg/config")),
        );
        if cfg!(target_os = "macos") {
            assert_eq!(
                defaults.profiles(),
                &[
                    home.join("Library/Application Support/orca"),
                    home.join(".orca")
                ]
            );
        } else {
            assert_eq!(
                defaults.profiles(),
                &[PathBuf::from("/xdg/config/orca"), home.join(".orca")]
            );
        }
        // When XDG_CONFIG_HOME/orca coincides with ~/.orca, keep one entry.
        if !cfg!(target_os = "macos") {
            let dedup =
                OrcaConfig::resolve_profiles(home, None, None, Some(PathBuf::from("/home/tester")));
            assert_eq!(dedup.profiles(), &[home.join("orca"), home.join(".orca")]);
        }
    }

    #[tokio::test]
    async fn snapshot_skips_dead_primary_profile_and_discovers_headless_runtime() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::net::UnixListener;

        let dir = tempfile::tempdir().unwrap();
        let desktop = dir.path().join("desktop");
        let headless = dir.path().join("headless");
        for p in [&desktop, &headless] {
            std::fs::create_dir(p).unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Stale desktop profile: valid metadata and socket file on disk, but nobody listening.
        let dead_sock = desktop.join("o-dead.sock");
        {
            let _dead_listener = UnixListener::bind(&dead_sock).unwrap();
            // Dropping the listener leaves the socket file behind with ECONNREFUSED.
        }
        let write_meta = |profile: &Path, runtime_id: &str, sock: &Path| {
            let meta = json!({
                "runtimeId": runtime_id,
                "authToken": "tok-test",
                "transports": [{"kind": "unix", "endpoint": sock}]
            });
            let path = profile.join("orca-runtime.json");
            std::fs::write(&path, serde_json::to_vec(&meta).unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        write_meta(&desktop, "11111111-1111-4111-8111-111111111111", &dead_sock);

        let live_sock = headless.join("o-live.sock");
        let listener = UnixListener::bind(&live_sock).unwrap();
        let runtime_id = "22222222-2222-4222-8222-222222222222";
        write_meta(&headless, runtime_id, &live_sock);

        let repo_id = "00000000-0000-4000-8000-000000000001";
        let instance_id = "00000000-0000-4000-8000-000000000002";
        let tab_id = "00000000-0000-4000-8000-000000000003";
        let leaf_id = "00000000-0000-4000-8000-000000000004";
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let (read_half, mut write_half) = stream.into_split();
                    let mut reader = BufReader::new(read_half);
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                        return;
                    }
                    let req: Value = serde_json::from_str(&line).unwrap();
                    let result = match req["method"].as_str().unwrap_or_default() {
                        "status.get" => json!({"capabilities": []}),
                        "repo.list" => json!({"repos": [{
                            "id": repo_id, "kind": "folder", "displayName": "remote://~"
                        }]}),
                        "worktree.list" => json!({"worktrees": [{
                            "id": "folder:home", "repoId": repo_id, "hostId": "local",
                            "instanceId": instance_id, "displayName": "tester",
                            "isMainWorktree": true
                        }]}),
                        "terminal.list" => json!({"terminals": [{
                            "worktreeId": "folder:home", "tabId": tab_id, "leafId": leaf_id,
                            "executionHostId": "local", "connected": true, "orphaned": false,
                            "title": "Claude", "paneTitle": "Pane 1"
                        }]}),
                        _ => json!({}),
                    };
                    let reply = json!({
                        "id": req["id"],
                        "ok": true,
                        "result": result,
                        "_meta": {"runtimeId": runtime_id}
                    });
                    let mut bytes = serde_json::to_vec(&reply).unwrap();
                    bytes.push(b'\n');
                    let _ = write_half.write_all(&bytes).await;
                });
            }
        });

        let config = OrcaConfig::from_profiles(vec![desktop, headless.clone()]);
        let snap = snapshot(&config, true, true, None).await;
        server.abort();
        let OrcaSnapshot::Available { repositories, .. } = snap else {
            panic!("expected headless fallback runtime to produce an available snapshot");
        };
        assert_eq!(repositories.len(), 1);
        assert_eq!(repositories[0].id, repo_id);
        assert_eq!(repositories[0].worktrees[0].id, instance_id);
        assert_eq!(
            repositories[0].worktrees[0].tabs[0].panes[0].key,
            format!("{tab_id}:{leaf_id}")
        );
        let matched = Runtime::discover_id(&config, runtime_id).await.unwrap();
        assert_eq!(matched.profile, headless);
    }

    /// Run only against a disposable profile containing at least one connected test terminal.
    #[tokio::test]
    #[ignore = "requires a running disposable Orca runtime"]
    async fn live_local_catalog_and_resolution() {
        let dir = PathBuf::from(
            std::env::var_os("CIAO_TEST_ORCA_PROFILE").expect("disposable Orca profile"),
        );
        let config = OrcaConfig::at(dir);
        let OrcaSnapshot::Available { repositories, .. } =
            snapshot(&config, true, true, None).await
        else {
            panic!("catalog unavailable")
        };
        let pane = repositories
            .iter()
            .flat_map(|r| &r.worktrees)
            .flat_map(|w| &w.tabs)
            .flat_map(|t| &t.panes)
            .next()
            .expect("disposable profile lacks a connected local pane");
        let rt = Runtime::discover(&config).await.unwrap();
        let terms = rt
            .query("terminal.list", json!({"includePreview":false}))
            .await
            .unwrap();
        let live = terms["terminals"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| {
                t["executionHostId"] == "local"
                    && Some(pane.key.as_str())
                        == t["tabId"]
                            .as_str()
                            .zip(t["leafId"].as_str())
                            .map(|(a, b)| format!("{a}:{b}"))
                            .as_deref()
            })
            .unwrap();
        let resolved = rt
            .query(
                "terminal.resolvePane",
                json!({"paneKey":pane.key,"worktreeId":live["worktreeId"]}),
            )
            .await
            .unwrap();
        assert_eq!(resolved["terminal"]["handle"], live["handle"]);
        assert_eq!(resolved["terminal"]["connected"], true);
    }
}
