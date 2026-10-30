//! Destination-owned delegation policy. Peers never enter the phone/shell allowlist.
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Result, bail};
use iroh::EndpointId;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::{
    agent_protocol::{AgentCommand, AgentCommandKind},
    storage::{atomic_write_private, validate_private_file},
};

pub(crate) const ALPN: &[u8] = b"ciao/peer/1";
pub(crate) const MAX_PEERS: usize = 16;
pub(crate) const MAX_WORKSPACES: usize = 32;
pub(crate) const MAX_STARTS: usize = 256;
pub(crate) const MAX_LIVE: usize = 2;
pub(crate) const MAX_REPLY_BYTES: usize = crate::agent_protocol::MAX_AGENT_FRAME_BYTES + 1024;
const MAX_STORE_BYTES: u64 = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Descriptor {
    pub endpoint_id: String,
    pub name: String,
}

impl Descriptor {
    pub fn validate(&self) -> Result<()> {
        let id = EndpointId::from_str(&self.endpoint_id)?;
        if id.to_string() != self.endpoint_id
            || self.name.is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
        {
            bail!("invalid_peer");
        }
        Ok(())
    }
}

pub(crate) fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Incoming {
    pub peer: Descriptor,
    pub grant_id: String,
    pub issuer: String,
    pub workspace_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Outgoing {
    pub peer: Descriptor,
    pub grant_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartRecord {
    pub grant_id: String,
    pub request_id: String,
    pub workspace_id: String,
    pub outcome: Option<crate::agent_protocol::LifecycleOutcome>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Store {
    pub incoming: Vec<Incoming>,
    pub outgoing: Vec<Outgoing>,
    pub starts: Vec<StartRecord>,
}

impl Store {
    fn validate(&self) -> Result<()> {
        if self.incoming.len() > MAX_PEERS
            || self.outgoing.len() > MAX_PEERS
            || self.starts.len() > MAX_STARTS
        {
            bail!("peer_limit");
        }
        let mut endpoints = HashSet::new();
        let mut grants = HashSet::new();
        for grant in &self.incoming {
            grant.peer.validate()?;
            EndpointId::from_str(&grant.issuer)?;
            if !valid_id(&grant.grant_id)
                || !endpoints.insert(&grant.peer.endpoint_id)
                || !grants.insert(&grant.grant_id)
                || grant.workspace_ids.is_empty()
                || grant.workspace_ids.len() > MAX_WORKSPACES
                || grant.workspace_ids.iter().any(|id| !valid_id(id))
                || grant.workspace_ids.iter().collect::<HashSet<_>>().len()
                    != grant.workspace_ids.len()
            {
                bail!("invalid_grant");
            }
        }
        endpoints.clear();
        for link in &self.outgoing {
            link.peer.validate()?;
            if !valid_id(&link.grant_id) || !endpoints.insert(&link.peer.endpoint_id) {
                bail!("invalid_link");
            }
        }
        let mut claims = HashSet::new();
        for claim in &self.starts {
            if !grants.contains(&claim.grant_id)
                || !valid_id(&claim.request_id)
                || !valid_id(&claim.workspace_id)
                || !claims.insert((&claim.grant_id, &claim.request_id))
            {
                bail!("invalid_claim");
            }
            if let Some(outcome) = &claim.outcome {
                outcome
                    .validate()
                    .map_err(|_| anyhow::anyhow!("invalid_outcome"))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(crate) struct Peers {
    path: PathBuf,
    store: Mutex<Store>,
    /// Serializes policy changes with async effects. A successful revoke fences all later effects.
    pub effects: tokio::sync::Mutex<()>,
    pub connections: Mutex<std::collections::HashMap<String, iroh::endpoint::Connection>>,
}

impl Peers {
    pub fn load(path: &Path) -> Result<Self> {
        let exists = match fs::symlink_metadata(path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let store = if exists {
            validate_private_file(path)?;
            if fs::metadata(path)?.len() > MAX_STORE_BYTES {
                bail!("peer_store_too_large");
            }
            let mut bytes = Vec::new();
            fs::File::open(path)?
                .take(MAX_STORE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_STORE_BYTES {
                bail!("peer_store_too_large");
            }
            let store: Store = serde_json::from_slice(&bytes)?;
            store.validate()?;
            store
        } else {
            Store::default()
        };
        Ok(Self {
            path: path.into(),
            store: Mutex::new(store),
            effects: tokio::sync::Mutex::new(()),
            connections: Mutex::new(Default::default()),
        })
    }

    pub fn snapshot(&self) -> Store {
        self.store.lock().clone()
    }

    pub fn change<T>(
        &self,
        change: impl FnOnce(&mut Store) -> Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        let mut guard = self.store.lock();
        let mut next = guard.clone();
        let value = change(&mut next)?;
        next.validate().map_err(|_| "invalid_peer_state")?;
        let bytes = serde_json::to_vec(&next).map_err(|_| "storage_failed")?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err("peer_limit");
        }
        atomic_write_private(&self.path, &bytes).map_err(|_| "storage_failed")?;
        *guard = next;
        Ok(value)
    }

    pub fn incoming(&self, endpoint: EndpointId, grant_id: Option<&str>) -> Option<Incoming> {
        self.store
            .lock()
            .incoming
            .iter()
            .find(|g| {
                g.peer.endpoint_id == endpoint.to_string()
                    && grant_id.is_none_or(|id| id == g.grant_id)
            })
            .cloned()
    }

    pub fn owns(&self, grant_id: &str, session: &str) -> bool {
        self.store.lock().starts.iter().any(|r| {
            r.grant_id == grant_id
                && r.outcome.as_ref().is_some_and(|o| {
                    o.state == "accepted" && o.session_id.as_deref() == Some(session)
                })
        })
    }

    pub fn close(&self, endpoint: &str) {
        if let Some(connection) = self.connections.lock().remove(endpoint) {
            connection.close(
                iroh::endpoint::VarInt::from_u32(
                    crate::host_protocol::CONNECTION_AUTHORIZATION_DENIED,
                ),
                b"peer access revoked",
            );
        }
    }

    pub fn revoke(&self, endpoint: &str) -> Result<(), &'static str> {
        self.change(|s| {
            let revoked: HashSet<_> = s
                .incoming
                .iter()
                .filter(|g| g.peer.endpoint_id == endpoint)
                .map(|g| g.grant_id.clone())
                .collect();
            s.incoming.retain(|g| g.peer.endpoint_id != endpoint);
            s.outgoing.retain(|g| g.peer.endpoint_id != endpoint);
            s.starts.retain(|r| !revoked.contains(&r.grant_id));
            Ok(())
        })?;
        self.close(endpoint);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Admin {
    Describe {},
    Grant {
        peer: Descriptor,
        workspace_ids: Vec<String>,
    },
    Remember {
        link: Outgoing,
    },
    Revoke {
        endpoint_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub v: u8,
    pub grant_id: String,
    pub action: Action,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Workspaces {},
    Start {
        request_id: String,
        workspace_id: String,
    },
    Snapshot {
        session_id: String,
    },
    Command {
        command: AgentCommand,
    },
    Stop {
        session_id: String,
        request_id: String,
        expected_generation: u64,
    },
}

impl Request {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.v != 1 || !valid_id(&self.grant_id) {
            return Err("invalid_request");
        }
        match &self.action {
            Action::Workspaces {} => {}
            Action::Start {
                request_id,
                workspace_id,
            } if valid_id(request_id) && valid_id(workspace_id) => {}
            Action::Snapshot { session_id } if valid_id(session_id) => {}
            Action::Stop {
                session_id,
                request_id,
                expected_generation,
            } if valid_id(session_id) && valid_id(request_id) && *expected_generation > 0 => {}
            Action::Command { command }
                if command.validate().is_ok()
                    && matches!(
                        command.kind,
                        AgentCommandKind::Prompt { .. } | AgentCommandKind::Interrupt
                    ) => {}
            _ => return Err("invalid_request"),
        }
        Ok(())
    }
}

/// Prevent a peer's chosen IDs colliding with phone or other peers' lifecycle/command receipts.
pub(crate) fn command_id(grant: &str, id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ciao-peer-command-v1\0");
    h.update(grant.as_bytes());
    h.update(b"\0");
    h.update(id.as_bytes());
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_shared_fixture_rejects_shell_paths_unknown_operations_and_invalid_ids() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/phase1/peer-admin-v1.json"
        ))
        .unwrap();
        assert_eq!(
            fixture["request"]["action"],
            serde_json::to_value(Admin::Describe {}).unwrap()
        );
        let descriptor: Descriptor =
            serde_json::from_value(fixture["response"]["result"]["peer"].clone()).unwrap();
        descriptor.validate().unwrap();
        assert_eq!(fixture["limits"]["peers"], MAX_PEERS);
        assert_eq!(fixture["limits"]["workspaces"], MAX_WORKSPACES);
        assert_eq!(fixture["limits"]["reply_bytes"], MAX_REPLY_BYTES);
        assert_eq!(
            fixture["limits"]["workspace_label_bytes"],
            crate::agent_protocol::MAX_WORKSPACE_LABEL_BYTES
        );
        for value in fixture["malformed_requests"].as_array().unwrap() {
            let result = serde_json::from_value::<Request>(value.clone());
            assert!(
                result.is_err() || result.unwrap().validate().is_err(),
                "must reject {value}"
            );
        }
    }

    #[test]
    fn peer_protocol_rejects_permission_mode_and_approval_controls() {
        for kind in [
            serde_json::json!({"type":"set_permission_mode","mode":"bypassPermissions"}),
            serde_json::json!({"type":"set_model","model":"other"}),
            serde_json::json!({"type":"interaction_response","interaction_id":"i","interaction_revision":1,"answer":{"type":"permission","decision":"allow"}}),
        ] {
            let request = serde_json::json!({"v":1,"grant_id":"grant","action":{"op":"command","command":{"v":1,"command_id":"cmd","session_id":"s","snapshot_epoch":1,"expected_generation":1,"kind":kind}}});
            let parsed = serde_json::from_value::<Request>(request);
            assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
        }
        let request = Request {
            v: 1,
            grant_id: "g".into(),
            action: Action::Command {
                command: AgentCommand {
                    v: 1,
                    command_id: "cmd".into(),
                    session_id: "s".into(),
                    snapshot_epoch: 1,
                    expected_generation: 1,
                    expected_revision: None,
                    kind: AgentCommandKind::Prompt {
                        text: "x".repeat(crate::agent_protocol::MAX_PROMPT_BYTES + 1),
                    },
                },
            },
        };
        assert_eq!(request.validate(), Err("invalid_request"));
    }

    #[test]
    fn peer_store_is_private_bounded_and_preserves_last_good_state() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("peers.json");
        let peers = Peers::load(&path).unwrap();
        let descriptor = Descriptor {
            endpoint_id: iroh::SecretKey::generate().public().to_string(),
            name: "Source".into(),
        };
        peers
            .change(|s| {
                s.outgoing.push(Outgoing {
                    peer: descriptor.clone(),
                    grant_id: "grant".into(),
                });
                Ok(())
            })
            .unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            peers
                .change(|s| {
                    s.outgoing.push(s.outgoing[0].clone());
                    Ok(())
                })
                .is_err()
        );
        assert_eq!(Peers::load(&path).unwrap().snapshot().outgoing.len(), 1);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Peers::load(&path).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(temp.path().join("missing"), &path).unwrap();
        assert!(
            Peers::load(&path).is_err(),
            "dangling symlinks must fail closed too"
        );
    }
}
