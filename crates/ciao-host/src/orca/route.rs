//! Bind a Ciao agent process to its actual Orca PTY. The runtime identifies panes and
//! incarnations. Orca's local PTY daemon supplies their shell PIDs. All viewer traffic
//! still uses the separately paired runtime connection.
use super::{
    MAX_ROWS, OrcaConfig, RESPONSE_LIMIT, Runtime, project_folder, session, workspace_instance,
};
use crate::{agent_route::RouteCheck, process};
use nix::unistd::Uid;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::{Path, PathBuf},
};
use tokio::{
    fs,
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Proof {
    pub(super) workspace: String,
    pub(super) pane: String,
    runtime: String,
    handle: String,
    pty: String,
    incarnation: String,
    process: u32,
    process_generation: String,
    shell: u32,
    shell_generation: String,
}

impl Proof {
    pub(crate) async fn find(config: &OrcaConfig, pairing: &Path, pid: u32) -> Option<Self> {
        if !fs::try_exists(pairing).await.ok()? {
            return None;
        }
        let generation = process::terminal_identity(pid).await?;
        for rt in Runtime::candidates(config).await {
            if let Some(proof) = Self::find_in(&rt, pairing, pid, &generation).await {
                return Some(proof);
            }
        }
        None
    }

    async fn find_in(rt: &Runtime, pairing: &Path, pid: u32, generation: &str) -> Option<Self> {
        super::paired(rt, Some(pairing)).await?;
        let sessions = inventory(&rt.profile).await?;
        let owner = owner(&sessions, pid).await?;
        let (listed, projects) = tokio::join!(
            rt.query("worktree.list", json!({"limit": MAX_ROWS})),
            rt.query("repo.list", json!({}))
        );
        let listed = listed?;
        let projects = projects?;
        // Each daemon PTY is joined by both its opaque identifiers and its incarnation,
        // never by the directory encoded in some Orca PTY names.
        let live = rt.query("terminal.list", json!({"limit": MAX_ROWS, "includePreview": false, "includeVisualLayouts": false, "requireFreshPtyLiveness": true})).await?;
        let mut panes = live["terminals"]
            .as_array()?
            .iter()
            .filter(|t| owner.matches(t));
        let terminal = panes.next()?;
        if panes.next().is_some() {
            return None;
        }
        let mut worktrees = listed["worktrees"]
            .as_array()?
            .iter()
            .filter(|w| w["id"].is_string() && w["id"] == terminal["worktreeId"]);
        let w = worktrees.next()?;
        if worktrees.next().is_some() {
            return None;
        }
        let folder = project_folder(&projects, w["repoId"].as_str()?)?;
        let workspace = workspace_instance(w, folder)?.to_owned();
        let proof = Self {
            workspace,
            pane: owner.pane.clone()?,
            runtime: rt.metadata.runtime_id.clone(),
            handle: owner.handle.clone()?,
            pty: owner.id.clone(),
            incarnation: owner.incarnation.clone()?,
            process: pid,
            process_generation: generation.to_owned(),
            shell: owner.pid?,
            shell_generation: process::terminal_identity(owner.pid?).await?,
        };
        let verified = session::resolve(rt, &proof.workspace, &proof.pane).await?;
        (proof.matches(rt, &verified)
            && process::terminal_identity(pid).await.as_ref() == Some(&proof.process_generation))
        .then_some(proof)
    }

    /// `find` folds every miss into `None`, and most of its misses are Orca not answering:
    /// the runtime relaunching, the paired handshake or a query outrunning its deadline. Only
    /// facts that cannot change back disprove the route: the agent exiting, the pairing being
    /// removed, or Orca answering with a different pane or runtime.
    pub(crate) const fn process(&self) -> u32 {
        self.process
    }

    pub(super) fn runtime(&self) -> &str {
        &self.runtime
    }

    pub(crate) async fn check(&self, config: &OrcaConfig, pairing: &Path) -> RouteCheck {
        match fs::try_exists(pairing).await {
            Ok(true) => {}
            Ok(false) => return RouteCheck::Disproved,
            Err(_) => return RouteCheck::Unanswered,
        }
        match Self::find(config, pairing, self.process).await {
            Some(fresh) if fresh == *self => RouteCheck::Current,
            Some(_) => RouteCheck::Disproved,
            None if !process::exists(self.process) => RouteCheck::Disproved,
            None => RouteCheck::Unanswered,
        }
    }

    pub(super) fn matches(&self, rt: &Runtime, terminal: &Value) -> bool {
        self.runtime == rt.metadata.runtime_id
            && terminal["handle"] == self.handle
            && terminal["ptyId"] == self.pty
            && terminal["incarnationId"] == self.incarnation
    }

    pub(crate) async fn label(&self, config: &OrcaConfig) -> Option<String> {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let rt = Runtime::discover_id(config, &self.runtime).await?;
            let terminal = session::resolve(&rt, &self.workspace, &self.pane).await?;
            if !self.matches(&rt, &terminal) {
                return None;
            }
            crate::workspace::sanitize_tab_label(terminal["title"].as_str()?)
        })
        .await
        .ok()
        .flatten()
    }
}

#[derive(Deserialize)]
struct Pty {
    #[serde(rename = "sessionId")]
    id: String,
    #[serde(rename = "terminalHandle")]
    handle: Option<String>,
    #[serde(rename = "paneKey")]
    pane: Option<String>,
    #[serde(rename = "incarnationId")]
    incarnation: Option<String>,
    #[serde(rename = "isAlive")]
    alive: bool,
    state: String,
    pid: Option<u32>,
}
impl Pty {
    fn matches(&self, t: &Value) -> bool {
        let Some((tab, leaf)) = self.pane.as_deref().and_then(|p| p.split_once(':')) else {
            return false;
        };
        t["executionHostId"] == "local"
            && t["connected"] == true
            && t["orphaned"] != true
            && t["ptyId"] == self.id
            && self.handle.as_deref().is_some_and(|h| t["handle"] == h)
            && self
                .incarnation
                .as_deref()
                .is_some_and(|id| super::uuid(id) && t["incarnationId"] == id)
            && t["tabId"] == tab
            && t["leafId"] == leaf
    }
}

async fn owner(sessions: &[Pty], pid: u32) -> Option<&Pty> {
    // Walk once, regardless of how many other terminals this host is running.
    let tty = process::tty(pid).await?;
    if !(tty.starts_with("/dev/pts/") || tty.starts_with("/dev/tty")) || tty == "/dev/tty" {
        return None;
    }
    let mut ancestor = pid;
    for _ in 0..64 {
        let mut matches = sessions.iter().filter(|s| s.pid == Some(ancestor));
        if let Some(s) = matches.next() {
            return (matches.next().is_none()
                && s.alive
                && s.state == "running"
                && s.pane.as_deref().is_some_and(session::valid_pane)
                && process::tty(ancestor).await.as_ref() == Some(&tty))
            .then_some(s);
        }
        if ancestor <= 1 {
            return None;
        }
        ancestor = process::parent(ancestor).await?;
    }
    None
}

async fn private_dir(dir: &Path) -> Option<()> {
    let m = fs::symlink_metadata(dir).await.ok()?;
    (m.is_dir() && m.uid() == Uid::effective().as_raw() && m.mode() & 0o077 == 0).then_some(())
}

// Orca 1.4.273's PTY protocol 62. A random control-client identity with a single
// listSessions request reads metadata without taking over an existing viewer.
async fn inventory(profile: &Path) -> Option<Vec<Pty>> {
    let dir = profile.join("daemon");
    private_dir(&dir).await?;
    let name = "daemon-v62.sock";
    let mut socket = dir.join(name);
    let limit = if cfg!(target_os = "macos") { 103 } else { 107 };
    if socket.as_os_str().as_encoded_bytes().len() > limit {
        let hash = format!("{:x}", Sha256::digest(dir.as_os_str().as_encoded_bytes()));
        let base = PathBuf::from(format!("/tmp/.orca-daemon-{}", Uid::effective()));
        private_dir(&base).await?;
        let short = base.join(&hash[..12]);
        private_dir(&short).await?;
        socket = short.join(name);
    }
    let m = fs::symlink_metadata(&socket).await.ok()?;
    if !m.file_type().is_socket() || m.uid() != Uid::effective().as_raw() {
        return None;
    }
    let mut stream = UnixStream::connect(socket).await.ok()?;
    if stream.peer_cred().ok()?.uid() != Uid::effective().as_raw() {
        return None;
    }
    let token = super::read_private_file(&dir.join("daemon-v62.token")).await?;
    let id = crate::protocol::base64url(&rand::random::<[u8; 16]>());
    let hello = json!({"type":"hello","role":"control","version":62,"clientId":id,"token":std::str::from_utf8(&token).ok()?.trim()});
    let mut bytes = serde_json::to_vec(&hello).ok()?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await.ok()?;
    let mut reader = BufReader::new(stream.take(RESPONSE_LIMIT + 1));
    let mut line = Vec::new();
    reader.read_until(b'\n', &mut line).await.ok()?;
    if line.last() != Some(&b'\n') || line.len() > 16_384 {
        return None;
    }
    let hello: Value = serde_json::from_slice(&line).ok()?;
    if hello["type"] != "hello" || hello["ok"] != true {
        return None;
    }
    let request = format!("{{\"id\":\"{id}\",\"type\":\"listSessions\"}}\n");
    reader
        .get_mut()
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .ok()?;
    line.clear();
    reader.read_until(b'\n', &mut line).await.ok()?;
    if line.last() != Some(&b'\n') || reader.get_ref().limit() == 0 {
        return None;
    }
    let mut response: Value = serde_json::from_slice(&line).ok()?;
    if response["id"] != id || response["ok"] != true {
        return None;
    }
    let rows = response["payload"]["sessions"].take();
    if rows.as_array()?.len() > MAX_ROWS {
        return None;
    }
    serde_json::from_value(rows).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        agent_route::{AgentRouteProof, AgentTerminalPlan, RouteCheck, TerminalRouteResolver},
        host_protocol::Dimensions,
        storage::CiaoPaths,
        workspace::WorkspaceConfig,
    };
    use std::time::Duration;

    fn fixture_proof(process: u32) -> Proof {
        let id = "11111111-1111-4111-8111-111111111111";
        Proof {
            workspace: id.into(),
            pane: format!("{id}:{id}"),
            runtime: id.into(),
            handle: "term_fixture".into(),
            pty: "fixture-pty".into(),
            incarnation: id.into(),
            process,
            process_generation: "fixture".into(),
            shell: process,
            shell_generation: "fixture".into(),
        }
    }

    // A relaunching or starved Orca cannot answer for a pane that is still live. That is not
    // evidence the pane is gone; an exited agent or a removed pairing is.
    #[tokio::test]
    async fn orca_check_separates_no_answer_from_disproof() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let profile = dir.path().join("profile");
        std::fs::create_dir(&profile).unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pairing = dir.path().join("orca-pairing.json");
        std::fs::write(&pairing, "{}").unwrap();
        std::fs::set_permissions(&pairing, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut workspace = WorkspaceConfig::with_binary_dirs(vec![]);
        workspace.orca = OrcaConfig::at(profile);
        let resolver = TerminalRouteResolver::new(workspace).with_orca_pairing(pairing.clone());
        let live = AgentRouteProof::Orca(fixture_proof(std::process::id()));
        assert_eq!(resolver.check(&live).await, RouteCheck::Unanswered);
        assert!(
            !resolver.revalidate(&live).await,
            "an open still needs proof"
        );

        // Above every pid_max, so no process can hold it. Spawning a real child to reap would
        // briefly share this test process's descriptors and races the daemon-lock tests.
        let gone = u32::try_from(i32::MAX).unwrap();
        assert!(!process::exists(gone));
        let dead = AgentRouteProof::Orca(fixture_proof(gone));
        assert_eq!(resolver.check(&dead).await, RouteCheck::Disproved);

        std::fs::remove_file(&pairing).unwrap();
        assert_eq!(resolver.check(&live).await, RouteCheck::Disproved);
    }

    #[tokio::test]
    #[ignore = "requires an isolated paired Orca profile and two disposable folder terminals running cat"]
    async fn live_folder_agent_route() {
        let dir = PathBuf::from(std::env::var_os("CIAO_TEST_ORCA_FOLDER_LAB").unwrap());
        let profile = dir.join("profile");
        assert_eq!(std::env::var_os("ORCA_USER_DATA_PATH").unwrap(), profile);
        let paths = CiaoPaths::for_home(dir.join("ciao"));
        if !paths.orca_pairing_file().exists() {
            let link = fs::read_to_string(dir.join("offer")).await.unwrap();
            session::pair_link(&paths, &link).await.unwrap();
        }
        let mut workspace = WorkspaceConfig::with_binary_dirs(vec![dir.clone()]);
        workspace.orca = OrcaConfig::at(profile.clone());
        let resolver =
            TerminalRouteResolver::new(workspace).with_orca_pairing(paths.orca_pairing_file());
        let pid = |n: &str| {
            std::fs::read_to_string(dir.join(n))
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        };
        let a = resolver
            .resolve(pid("a.pid"))
            .await
            .expect("route to first folder process");
        let b = resolver
            .resolve(pid("b.pid"))
            .await
            .expect("route to second folder process");
        let (AgentRouteProof::Orca(a), AgentRouteProof::Orca(b)) = (&a, &b) else {
            panic!("wrong provider")
        };
        assert_eq!(a.workspace, b.workspace);
        assert_ne!(a.pane, b.pane);
        let mut stale = a.clone();
        stale.incarnation = b.incarnation.clone();
        assert!(
            !resolver
                .revalidate(&AgentRouteProof::Orca(stale.clone()))
                .await
        );
        let size = Dimensions {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        };
        assert!(
            session::OrcaSession::attach_agent(
                OrcaConfig::at(profile.clone()),
                paths.orca_pairing_file(),
                &stale,
                size
            )
            .await
            .is_err()
        );
        assert!(resolver.resolve(std::process::id()).await.is_none());
        let Ok(AgentTerminalPlan::Orca(plan)) = resolver
            .terminal_plan(&AgentRouteProof::Orca(a.clone()))
            .await
        else {
            panic!("exact route was lost")
        };
        let mut view = session::OrcaSession::attach_agent(
            OrcaConfig::at(profile),
            paths.orca_pairing_file(),
            &plan,
            size,
        )
        .await
        .unwrap();
        let marker = format!(
            "ciao-folder-{}",
            crate::protocol::base64url(&rand::random::<[u8; 12]>())
        );
        view.send_input(format!("{marker}\n").into_bytes())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(6), async {
            let mut bytes = Vec::new();
            while let Some(chunk) = view.next_output().await {
                bytes.extend(chunk);
                if String::from_utf8_lossy(&bytes).contains(&marker) {
                    return;
                }
                assert!(bytes.len() < 1024 * 1024);
            }
            panic!("terminal closed");
        })
        .await
        .unwrap();
        view.cleanup().await.unwrap();
        assert!(resolver.revalidate(&AgentRouteProof::Orca(b.clone())).await);
    }
}
