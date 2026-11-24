//! Fixed, local workspace operations. Resolve provider-owned identities immediately before dispatch.
use super::{
    Runtime,
    session::{resolve, valid_pane},
    uuid,
};
use crate::host_protocol::{
    HostProtocolError, valid_session_name, valid_tab_label, validate_request_id,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use tokio::time::timeout;

pub const METHOD: &str = "orca.manage.v1";
const RETAIN_BRANCH: &str = "worktree.remove-branch-policy.v1";
pub(super) fn can_retain(status: &Value) -> bool {
    status["capabilities"]
        .as_array()
        .is_some_and(|caps| caps.iter().any(|cap| cap == RETAIN_BRANCH))
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    v: u8,
    #[serde(rename = "type")]
    kind: String,
    pub request_id: String,
    method: String,
    pub params: Action,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    CreateWorktree {
        repo: String,
        name: String,
    },
    RemoveWorktree {
        repo: String,
        workspace: String,
    },
    CreateTab {
        repo: String,
        workspace: String,
    },
    RenameTab {
        repo: String,
        workspace: String,
        pane: String,
        name: String,
    },
    CloseTab {
        repo: String,
        workspace: String,
        pane: String,
    },
}
impl Request {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, HostProtocolError> {
        let req: Self =
            serde_json::from_slice(bytes).map_err(|_| HostProtocolError::MalformedJson)?;
        validate_request_id(&req.request_id)?;
        if req.v != 1 || req.kind != "request" || req.method != METHOD {
            return Err(HostProtocolError::InvalidControlValue);
        }
        let valid = match &req.params {
            Action::CreateWorktree { repo, name } => uuid(repo) && valid_session_name(name),
            Action::RemoveWorktree { repo, workspace } | Action::CreateTab { repo, workspace } => {
                uuid(repo) && uuid(workspace)
            }
            Action::CloseTab {
                repo,
                workspace,
                pane,
            } => uuid(repo) && uuid(workspace) && valid_pane(pane),
            Action::RenameTab {
                repo,
                workspace,
                pane,
                name,
            } => {
                uuid(repo)
                    && uuid(workspace)
                    && valid_pane(pane)
                    && valid_tab_label(name)
                    && name.trim() == name
            }
        };
        valid.then_some(req).ok_or(HostProtocolError::InvalidTarget)
    }
}
#[derive(Debug)]
pub(crate) enum Failure {
    Unavailable,
    Stale,
    Retain,
    Refused,
    Dirty,
    ArchiveHook,
    Unconfirmed,
}
impl Failure {
    pub(crate) fn wire(&self) -> (&'static str, &'static str) {
        match self {
            Self::Unavailable => (
                "provider_unavailable",
                "The local Orca runtime is unavailable.",
            ),
            Self::Stale => (
                "orca_stale",
                "Orca can no longer verify that selection. Refresh the workspaces.",
            ),
            Self::Retain => (
                "orca_branch_policy",
                "This Orca runtime cannot confirm branch retention.",
            ),
            Self::Dirty => (
                "orca_dirty",
                "The checkout has uncommitted or untracked changes.",
            ),
            Self::ArchiveHook => (
                "orca_archive_hook",
                "Orca’s archive hook refused removal. Check the hook output on the host.",
            ),
            Self::Refused => (
                "orca_refused",
                "Orca refused the operation. Check the checkout, running processes and archive hooks.",
            ),
            Self::Unconfirmed => (
                "orca_unconfirmed",
                "The operation may still be running. Refresh Orca before trying again.",
            ),
        }
    }
}

struct Prepared {
    method: &'static str,
    params: Value,
    source: Value,
    workspace: Option<String>,
}
async fn prepare(rt: &Runtime, request: &Request) -> Result<Prepared, Failure> {
    use Failure::*;
    let (status, repos) = tokio::join!(
        rt.query("status.get", json!({})),
        rt.query("repo.list", json!({}))
    );
    let status = status.ok_or(Unavailable)?;
    let source = json!({"sourceId":status["hostDescriptor"]["installationId"].as_str().ok_or(Unavailable)?,"runtimeId":rt.metadata.runtime_id});
    let (repo, workspace) = match &request.params {
        Action::CreateWorktree { repo, .. } => (repo, None),
        Action::CreateTab { repo, workspace }
        | Action::RemoveWorktree { repo, workspace }
        | Action::CloseTab {
            repo, workspace, ..
        }
        | Action::RenameTab {
            repo, workspace, ..
        } => (repo, Some(workspace)),
    };
    let repos = repos.ok_or(Unavailable)?;
    let mut candidates = repos["repos"]
        .as_array()
        .ok_or(Unavailable)?
        .iter()
        .filter(|row| row["id"] == repo.as_str() && super::local_git_repo(row));
    if candidates.next().is_none() || candidates.next().is_some() {
        return Err(Stale);
    }
    if let Action::CreateWorktree { name, .. } = &request.params {
        return Ok(Prepared {
            method: "worktree.create",
            params: json!({"repo":format!("id:{repo}"),"repoHostId":"local","hostId":"local","name":name,"clientMutationId":request.request_id}),
            source,
            workspace: None,
        });
    }
    let workspace = workspace.ok_or(Stale)?;
    let list = rt
        .query(
            "worktree.list",
            json!({"repo":format!("id:{repo}"),"limit":super::MAX_ROWS}),
        )
        .await
        .ok_or(Unavailable)?;
    let mut matches = list["worktrees"]
        .as_array()
        .ok_or(Unavailable)?
        .iter()
        .filter(|w| {
            super::local_workspace(w)
                && w["identity"]["instanceId"] == workspace.as_str()
                && w["repoId"] == repo.as_str()
        });
    let w = matches.next().ok_or(Stale)?;
    if matches.next().is_some() {
        return Err(Stale);
    }
    let worktree_id = w["id"].as_str().ok_or(Stale)?;
    let selector = format!("id:{worktree_id}");
    let (method, params) = match &request.params {
        Action::RemoveWorktree { .. } => {
            if !can_retain(&status) {
                return Err(Retain);
            }
            if w["isMainWorktree"] != false {
                return Err(Refused);
            }
            (
                "worktree.rm",
                json!({"worktree":selector,"hostId":"local","force":false,"deleteBranch":false,"runHooks":true,"allowFailedArchiveHook":false,"allowUnverifiedPtyStop":false,"waitForBackgroundRemoval":true}),
            )
        }
        Action::CreateTab { .. } => (
            "terminal.create",
            json!({"worktree":selector,"focus":false,"clientMutationId":request.request_id}),
        ),
        Action::RenameTab { pane, .. } | Action::CloseTab { pane, .. } => {
            let terminal = resolve(rt, workspace, pane).await.ok_or(Stale)?;
            if terminal["worktreeId"] != worktree_id {
                return Err(Stale);
            }
            if let Action::RenameTab { name, .. } = &request.params {
                (
                    "terminal.rename",
                    json!({"terminal":terminal["handle"],"title":name}),
                )
            } else {
                ("terminal.closeTab", json!({"terminal":terminal["handle"]}))
            }
        }
        Action::CreateWorktree { .. } => unreachable!(),
    };
    Ok(Prepared {
        method,
        params,
        source,
        workspace: Some(workspace.clone()),
    })
}

pub(crate) async fn execute(profile: &Path, request: &Request) -> Result<Value, Failure> {
    use Failure::*;
    let rt = timeout(Duration::from_secs(3), Runtime::discover(profile))
        .await
        .ok()
        .flatten()
        .ok_or(Unavailable)?;
    let p = timeout(Duration::from_secs(5), prepare(&rt, request))
        .await
        .map_err(|_| Unavailable)??;
    let removing = p.method == "worktree.rm";
    let budget = Duration::from_secs(if removing { 300 } else { 60 });
    let reply = timeout(budget, rt.exchange(p.method, p.params, Some(p.source)))
        .await
        .ok()
        .flatten();
    if let Some(frame) = reply {
        if frame["ok"] == false {
            let message = frame["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            let code = frame["error"]["code"].as_str().unwrap_or_default();
            let uncertain = removing
                && (code.contains("timeout")
                    || message.contains("timed out")
                    || message.contains("already removing")
                    || message.contains("in progress"));
            if !uncertain {
                if removing
                    && (message.contains("uncommitted")
                        || message.contains("untracked")
                        || message.contains("dirty"))
                {
                    return Err(Dirty);
                }
                if removing && message.contains("hook") {
                    return Err(ArchiveHook);
                }
                return Err(Refused);
            }
        }
        let r = &frame["result"];
        match p.method {
            "worktree.rm" if r["removed"] == true && r["removing"] != true => {
                return Ok(json!({"completed":true}));
            }
            "worktree.create" if r["worktree"].is_object() => return Ok(json!({"completed":true})),
            "terminal.create" if r["terminal"]["executionHostId"] == "local" => {
                let pane = r["terminal"]["paneKey"]
                    .as_str()
                    .filter(|key| valid_pane(key))
                    .ok_or(Unconfirmed)?;
                return Ok(json!({"completed":true,"workspace":p.workspace,"pane":pane}));
            }
            "terminal.rename" if r["rename"]["tabId"].is_string() => {
                return Ok(json!({"completed":true}));
            }
            "terminal.closeTab" if r["close"]["tabId"].is_string() => {
                return Ok(json!({"completed":true}));
            }
            _ => {}
        }
    }
    // The archive can outlive the reply. Only a complete local listing can establish disappearance.
    if removing
        && let Some(list) = timeout(
            Duration::from_secs(4),
            rt.query("worktree.list", json!({"limit":super::MAX_ROWS})),
        )
        .await
        .ok()
        .flatten()
        && list["truncated"] == false
        && list["hostScope"]["omittedHostIds"] == json!([])
        && list["hostScope"]["hostIds"]
            .as_array()
            .is_some_and(|ids| ids.iter().any(|id| id == "local"))
        && list["worktrees"].as_array().is_some_and(|rows| {
            rows.iter()
                .all(|w| w["identity"]["instanceId"].as_str() != p.workspace.as_deref())
        })
    {
        return Ok(json!({"completed":true}));
    }
    Err(Unconfirmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_protocol::Dimensions;
    use crate::orca::session::OrcaSession;
    use std::{env, path::PathBuf, process::Command};

    async fn apply(profile: &Path, params: Action) -> Result<Value, Failure> {
        execute(
            profile,
            &Request {
                v: 1,
                kind: "request".into(),
                method: METHOD.into(),
                request_id: crate::protocol::base64url(&rand::random::<[u8; 16]>()),
                params,
            },
        )
        .await
    }

    #[tokio::test]
    #[ignore = "creates and removes a checkout in an explicitly selected disposable Orca Git repository"]
    async fn live_worktree_lifecycle() {
        let profile = PathBuf::from(env::var_os("CIAO_TEST_ORCA_PROFILE").unwrap());
        let checkout = PathBuf::from(env::var_os("CIAO_TEST_ORCA_REPO").unwrap())
            .canonicalize()
            .unwrap();
        let credentials = PathBuf::from(env::var_os("CIAO_TEST_ORCA_PAIRING").unwrap());
        let rt = Runtime::discover(&profile).await.unwrap();
        let rows = rt.query("repo.list", json!({})).await.unwrap();
        let repo = rows["repos"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| {
                super::super::local_git_repo(r)
                    && r["path"].as_str().is_some_and(|path| {
                        Path::new(path).canonicalize().ok().as_ref() == Some(&checkout)
                    })
            })
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let name = format!("ciao-qa-{:08x}", rand::random::<u32>());
        apply(
            &profile,
            Action::CreateWorktree {
                repo: repo.clone(),
                name: name.clone(),
            },
        )
        .await
        .expect("create worktree");
        let trees = rt.query("worktree.list", json!({})).await.unwrap();
        let tree = trees["worktrees"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["repoId"] == repo && t["displayName"] == name)
            .unwrap();
        let workspace = tree["identity"]["instanceId"].as_str().unwrap().to_owned();
        let branch = tree["branch"].as_str().unwrap();
        let path = PathBuf::from(tree["path"].as_str().unwrap());
        let create = Action::CreateTab {
            repo: repo.clone(),
            workspace: workspace.clone(),
        };
        let first = apply(&profile, create.clone())
            .await
            .expect("create first tab");
        let second = apply(&profile, create).await.expect("create sibling");
        let pane = first["pane"].as_str().unwrap().to_owned();
        let sibling = second["pane"].as_str().unwrap().to_owned();
        assert_ne!(sibling, pane);
        let before = resolve(&rt, &workspace, &sibling).await.unwrap();
        let size = Dimensions {
            cols: 80,
            rows: 24,
            pixel_width: 0,
            pixel_height: 0,
        };
        let mut viewer = OrcaSession::attach(
            profile.clone(),
            credentials,
            workspace.clone(),
            pane.clone(),
            size,
        )
        .await
        .unwrap();
        viewer
            .send_input(b"printf 'work%s-test\\n' tree\r".to_vec())
            .await
            .unwrap();
        let mut observed = Vec::new();
        timeout(Duration::from_secs(8), async {
            while let Some(bytes) = viewer.next_output().await {
                observed.extend(bytes);
                if String::from_utf8_lossy(&observed).contains("worktree-test") {
                    return;
                }
            }
            panic!("viewer ended");
        })
        .await
        .expect("shell executed input");
        viewer.cleanup().await.unwrap();
        apply(
            &profile,
            Action::RenameTab {
                repo: repo.clone(),
                workspace: workspace.clone(),
                pane: pane.clone(),
                name: "Renamed QA tab".into(),
            },
        )
        .await
        .expect("rename");
        apply(
            &profile,
            Action::CloseTab {
                repo: repo.clone(),
                workspace: workspace.clone(),
                pane: pane.clone(),
            },
        )
        .await
        .expect("close");
        timeout(Duration::from_secs(5), async {
            while resolve(&rt, &workspace, &pane).await.is_some() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("closed pane disappears");
        assert_eq!(
            before["ptyId"],
            resolve(&rt, &workspace, &sibling).await.unwrap()["ptyId"]
        );
        apply(
            &profile,
            Action::CloseTab {
                repo: repo.clone(),
                workspace: workspace.clone(),
                pane: sibling,
            },
        )
        .await
        .unwrap();
        let dirty = path.join("ciao-test-uncommitted");
        std::fs::File::create_new(&dirty).unwrap();
        let remove = Action::RemoveWorktree { repo, workspace };
        assert!(matches!(
            apply(&profile, remove.clone()).await,
            Err(Failure::Dirty)
        ));
        assert!(dirty.is_file());
        std::fs::remove_file(dirty).unwrap();
        apply(&profile, remove)
            .await
            .expect("remove clean checkout");
        assert!(!path.exists());
        assert!(
            Command::new("git")
                .current_dir(checkout)
                .args(["rev-parse", "--verify", branch])
                .output()
                .unwrap()
                .status
                .success()
        );
    }
}
